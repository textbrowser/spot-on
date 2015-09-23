/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Spot-On without specific prior written permission.
**
** SPOT-ON IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SPOT-ON, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSslKey>
#include <QSslSocket>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"

#if QT_VERSION >= 0x050000
void spoton_gui_server_tcp_server::incomingConnection(qintptr socketDescriptor)
#else
void spoton_gui_server_tcp_server::incomingConnection(int socketDescriptor)
#endif
{
  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  spoton_crypt::generateSslKeys
    (spoton_kernel::setting("gui/kernelKeySize", 2048).toInt(),
     certificate,
     privateKey,
     publicKey,
     serverAddress(),
     60L * 60L * 24L * static_cast<long> (spoton_common::
					  KERNEL_CERTIFICATE_DAYS_VALID),
     error);

  if(error.isEmpty())
    {
      QPointer<QSslSocket> socket = new (std::nothrow) QSslSocket(this);

      if(socket)
	{
	  try
	    {
	      socket->setSocketDescriptor(socketDescriptor);
	      socket->setSocketOption
		(QAbstractSocket::LowDelayOption,
		 spoton_kernel::setting("kernel/tcp_nodelay", 1).
		 toInt()); /*
			   ** Disable Nagle?
			   */
	      connect(socket,
		      SIGNAL(encrypted(void)),
		      this,
		      SLOT(slotEncrypted(void)));
	      connect(socket,
		      SIGNAL(modeChanged(QSslSocket::SslMode)),
		      this,
		      SIGNAL(modeChanged(QSslSocket::SslMode)));

	      QSslConfiguration configuration;
	      QString sslCS
		(spoton_kernel::
		 setting("gui/sslControlString",
			 "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH").
		 toString());

	      configuration.setLocalCertificate(QSslCertificate(certificate));
	      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));
#if QT_VERSION >= 0x040800
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
	      spoton_crypt::setSslCiphers
		(socket->supportedCiphers(), sslCS, configuration);
	      socket->setSslConfiguration(configuration);
	      socket->startServerEncryption();
	      m_queue.enqueue(socket);
	      emit newConnection();
	    }
	  catch(...)
	    {
	      m_queue.removeOne(socket);
	      socket->deleteLater();
	    }
	}
      else
	{
	  QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError("spoton_gui_server_tcp_server::"
				"incomingConnection(): memory failure.");
	}
    }
  else
    {
      QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

      socket.setSocketDescriptor(socketDescriptor);
      socket.abort();
      spoton_misc::logError
	(QString("spoton_gui_server_tcp_server::"
		 "incomingConnection(): "
		 "generateSslKeys() failure (%1).").arg(error));
    }
}

spoton_gui_server::spoton_gui_server(QObject *parent):
  spoton_gui_server_tcp_server(parent)
{
  m_uiAuthenticated = false;

  if(!listen(QHostAddress("127.0.0.1")))
    spoton_misc::logError("spoton_gui_server::spoton_gui_server(): "
			  "listen() failure. This is a serious problem!");

  connect(this,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
  connect(this,
	  SIGNAL(newConnection(void)),
	  this,
	  SLOT(slotClientConnected(void)));
  connect(&m_fileSystemWatcher,
	  SIGNAL(fileChanged(const QString &)),
	  this,
	  SLOT(slotFileChanged(const QString &)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_generalTimer.start(2500);

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "kernel.db");

  if(fileInfo.isReadable())
    m_fileSystemWatcher.addPath(fileInfo.absoluteFilePath());
  else
    spoton_misc::logError("spoton_gui_server::spoton_gui_server(): "
			  "could not locate kernel.db.");
}

spoton_gui_server::~spoton_gui_server()
{
  m_generalTimer.stop();
  m_guiSocketData.clear();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM kernel_gui_server");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_gui_server::slotClientConnected(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (nextPendingConnection());

  if(socket)
    {
      connect(socket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotClientDisconnected(void)));
      connect(socket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(socket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
}

void spoton_gui_server::slotClientDisconnected(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(socket)
    {
      m_guiSocketData.remove(socket->socketDescriptor());
      socket->deleteLater();
    }

  if(m_guiSocketData.isEmpty())
    spoton_kernel::clearBuzzKeysContainer();
}

void spoton_gui_server::slotReadyRead(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    {
      spoton_misc::logError("spoton_gui_server::"
			    "slotReadyRead(): empty socket object.");
      return;
    }

  if(!socket->isEncrypted())
    {
      socket->readAll();
      spoton_misc::logError
	(QString("spoton_gui_server::slotReadyRead(): "
		 "socket %1:%2 is not encrypted. Discarding data.").
	 arg(socket->localAddress().toString()).
	 arg(socket->localPort()));
      return;
    }

  /*
  ** What if socketDescriptor() equals negative one?
  */

  m_guiSocketData[socket->socketDescriptor()].append
    (socket->readAll());

  if(m_guiSocketData[socket->socketDescriptor()].endsWith('\n'))
    {
      QByteArray data(m_guiSocketData[socket->socketDescriptor()]);
      QList<QByteArray> messages(data.mid(0, data.lastIndexOf('\n')).
				 split('\n'));

      data.remove(0, data.lastIndexOf('\n'));

      if(data.isEmpty())
	m_guiSocketData.remove(socket->socketDescriptor());
      else
	m_guiSocketData.insert(socket->socketDescriptor(), data);

      while(!messages.isEmpty())
	{
	  QByteArray message(messages.takeFirst());

	  if(message.startsWith("addbuzz_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("addbuzz_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 4)
                spoton_kernel::addBuzzKey
                 (QByteArray::fromBase64(list.value(0)),
                  QByteArray::fromBase64(list.value(1)),
		  QByteArray::fromBase64(list.value(2)),
		  QByteArray::fromBase64(list.value(3)));
	    }
	  else if(message.startsWith("befriendparticipant_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("befriendparticipant_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 7)
		emit publicKeyReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   QByteArray::fromBase64(list.value(6)),
		   "0012");
	    }
	  else if(message.startsWith("buzz_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("buzz_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 6)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray(),
		   QByteArray(),
		   "0040a",
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)));
	      else if(list.size() == 8)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   "0040b",
		   QByteArray::fromBase64(list.value(6)),
		   QByteArray::fromBase64(list.value(7)));
	    }
	  else if(message.startsWith("call_participant_using_gemini_"))
	    {
	      message.remove
		(0,
		 static_cast<int> (qstrlen("call_participant_"
					   "using_gemini_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit callParticipantUsingGemini(list.value(0),
						list.value(1).toLongLong());
	    }
	  else if(message.startsWith("call_participant_using_public_key_"))
	    {
	      message.remove
		(0,
		 static_cast<int> (qstrlen("call_participant_"
					   "using_public_key_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit callParticipant(list.value(0),
				     list.value(1).toLongLong());
	    }
	  else if(message.startsWith("detach_listener_neighbors_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("detach_listener_neighbors_")));

	      if(!message.isEmpty())
		emit detachNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("disconnect_listener_neighbors_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("disconnect_listener_"
					      "neighbors_")));

	      if(!message.isEmpty())
		emit disconnectNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("echokeypair_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("echokeypair_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit echoKeyShare(list);
	    }
	  else if(message.startsWith("forward_secrecy_request_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("forward_secrecy_request_")));

	      QList<QByteArray> list(message.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(list.size() == 6)
		emit forwardSecrecyInformationReceivedFromUI(list);
	    }
	  else if(message.startsWith("forward_secrecy_response_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("forward_secrecy_response_")));

	      QList<QByteArray> list(message.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(list.size() == 7)
		emit forwardSecrecyResponseReceivedFromUI(list);
	    }
	  else if(message.startsWith("keys_"))
	    {
	      message.remove(0, static_cast<int> (qstrlen("keys_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		{
		  QStringList names;

		  names << "chat"
			<< "chat-signature"
			<< "email"
			<< "email-signature"
			<< "poptastic"
			<< "poptastic-signature"
			<< "rosetta"
			<< "rosetta-signature"
			<< "url"
			<< "url-signature";

		  for(int i = 0; i < names.size(); i++)
		    if(!spoton_kernel::s_crypts.contains(names.at(i)))
		      {
			spoton_crypt *crypt = 0;

			try
			  {
			    crypt = new (std::nothrow) spoton_crypt
			      (spoton_kernel::
			       setting("gui/cipherType",
				       "aes256").
			       toString(),
			       spoton_kernel::
			       setting("gui/hashType",
				       "sha512").
			       toString(),
			       QByteArray(),
			       QByteArray::
			       fromBase64(list.value(0)),
			       QByteArray::
			       fromBase64(list.value(1)),
			       spoton_kernel::
			       setting("gui/saltLength",
				       512).toInt(),
			       static_cast<unsigned
			       long> (spoton_kernel::
				      setting("gui/iterationCount",
					      10000).toInt()),
			       names.at(i));
			    spoton_kernel::s_crypts.insert
			      (names.at(i), crypt);
			  }
			catch(...)
			  {
			    if(crypt)
			      delete crypt;

			    spoton_kernel::s_crypts.remove(names.at(i));
			  }
		      }

		  for(int i = 0; i < names.size(); i++)
		    if(!spoton_kernel::s_crypts.value(names.at(i), 0))
		      spoton_misc::logError
			("spoton_gui_server::slotReadyRead(): potential "
			 "memory failure. Critical!");
		}
	    }
	  else if(message.startsWith("message_"))
	    {
	      message.remove(0, static_cast<int> (qstrlen("message_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 5)
		emit messageReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   "chat");
	    }
	  else if(message.startsWith("poptasticmessage_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("poptasticmessage_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 5)
		emit messageReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   "poptastic");
	    }
	  else if(message.startsWith("populate_starbeam_keys"))
	    emit populateStarBeamKeys();
	  else if(message.startsWith("publicizealllistenersplaintext"))
	    emit publicizeAllListenersPlaintext();
	  else if(message.startsWith("publicizelistenerplaintext"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("publicize"
					      "listenerplaintext_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 1)
		emit publicizeListenerPlaintext
		  (list.value(0).toLongLong());
	    }
	  else if(message.startsWith("purge_ephemeral_key_pair_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("purge_ephemeral_key_pair_")));

	      if(!message.isEmpty())
		emit purgeEphemeralKeyPair(QByteArray::fromBase64(message));
	    }
	  else if(message.startsWith("purge_ephemeral_keys"))
	    emit purgeEphemeralKeys();
	  else if(message.startsWith("removebuzz_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("removebuzz_")));
	      spoton_kernel::removeBuzzKey(QByteArray::fromBase64(message));
	    }
	  else if(message.startsWith("retrievemail"))
	    emit retrieveMail();
	  else if(message.startsWith("sharebuzzmagnet_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("sharebuzzmagnet_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit buzzMagnetReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)));
	    }
	  else if(message.startsWith("sharepublickey_"))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("sharepublickey_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 7)
		emit publicKeyReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   QByteArray::fromBase64(list.value(6)),
		   "0011");
	    }
	}
    }
}

void spoton_gui_server::slotTimeout(void)
{
  if(!isListening())
    if(!listen(QHostAddress("127.0.0.1")))
      spoton_misc::logError("spoton_gui_server::slotTimeout(): "
			    "listen() failure. This is a serious problem!");

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);
	quint16 port = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT port FROM kernel_gui_server"))
	  if(query.next())
	    port = query.value(0).toByteArray().toUShort();

	if(port == 0 || port != serverPort())
	  {
	    QSqlQuery updateQuery(db);

	    updateQuery.prepare("INSERT INTO kernel_gui_server (port) "
				"VALUES (?)");
	    updateQuery.bindValue(0, serverPort());

	    if(updateQuery.exec())
	      m_generalTimer.stop();
	  }
	else if(port == serverPort())
	  m_generalTimer.stop();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_gui_server::slotReceivedBuzzMessage
(const QByteArrayList &list,
 const QByteArrayList &keys)
{
  if(spoton_kernel::buzzKeyCount() == 0 || spoton_kernel::interfaces() == 0)
    return;

  /*
  ** keys[0]: Encryption Key
  ** keys[1]: Encryption Type
  ** keys[2]: Hash Key
  ** keys[3]: Hash Type
  ** list[0]: Data (Plaintext)
  ** list[1]: Hash
  */

  if(spoton_kernel::messagingCacheContains(list.value(1), true))
    return;
  else
    /*
    ** Add the message with an expiration date of 30 seconds into the future.
    */

    spoton_kernel::messagingCacheAdd(list.value(1), true, 30000);

  QByteArray message;

  message.append("buzz_");
  message.append(list.value(0).toBase64()); // Message
  message.append("_");
  message.append(keys.value(0).toBase64()); // Encryption Key
  message.append("\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotReceivedBuzzMessage(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotReceivedBuzzMessage(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotReceivedChatMessage(const QByteArray &message)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  /*
  ** The message array contains a unique message authentication code.
  */

  if(spoton_kernel::messagingCacheContains(message))
    return;
  else
    /*
    ** Add the message with an expiration date of 30 seconds into the future.
    */

    spoton_kernel::messagingCacheAdd(message, false, 30000);

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotReceivedChatMessage(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotReceivedChatMessage(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotNewEMailArrived(void)
{
  QByteArray message("newmail\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotNewEMailArrived(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotNewEMailArrived(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotModeChanged(QSslSocket::SslMode mode)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    {
      spoton_misc::logError
	(QString("spoton_gui_server::slotModeChanged(): "
		 "the connection mode has changed to %1 "
		 "for %2:%3.").
	 arg(mode).
	 arg(serverAddress().toString()).
	 arg(serverPort()));
      return;
    }

  spoton_misc::logError(QString("spoton_gui_server::slotModeChanged(): "
				"the connection mode has changed to %1 "
				"for %2:%3.").
			arg(mode).
			arg(socket->peerAddress().toString()).
			arg(socket->peerPort()));

  if(mode == QSslSocket::UnencryptedMode)
    {
      spoton_misc::logError
	(QString("spoton_gui_server::slotModeChanged(): "
		 "plaintext mode. Disconnecting kernel socket %1:%2.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
      socket->abort();
    }
}

void spoton_gui_server::slotEncrypted(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    {
      spoton_misc::logError("spoton_gui_server::"
			    "slotEncrypted(): empty socket object.");
      return;
    }

  QSslCipher cipher(socket->sessionCipher());

  spoton_misc::logError
    (QString("spoton_gui_server::slotEncrypted(): "
	     "using session cipher %1-%2-%3-%4-%5-%6-%7 for %8:%9.").
     arg(cipher.authenticationMethod()).
     arg(cipher.encryptionMethod()).
     arg(cipher.keyExchangeMethod()).
     arg(cipher.name()).
     arg(cipher.protocolString()).
     arg(cipher.supportedBits()).
     arg(cipher.usedBits()).
     arg(socket->peerAddress().toString()).
     arg(socket->peerPort()));
}

void spoton_gui_server::slotFileChanged(const QString &path)
{
  Q_UNUSED(path);

  if(!m_generalTimer.isActive())
    m_generalTimer.start(2500);
}

void spoton_gui_server::slotAuthenticationRequested
(const QString &peerInformation)
{
  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	QByteArray message;

	message.append("authentication_requested_");
	message.append(peerInformation);
	message.append("\n");

	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotAuthenticationRequested(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotAuthenticationRequested(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotStatusMessageReceived
(const QByteArray &publicKeyHash, const QString &status)
{
  QByteArray message("chat_status_");

  message.append(publicKeyHash.toBase64().constData());
  message.append("_");
  message.append(status);
  message.append("\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotStatusMessageReceived(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotStatusMessageReceived(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotForwardSecrecyRequest
(const QByteArrayList &list)
{
  QByteArray message("forward_secrecy_request_");

  message.append(list.value(0).toBase64()); // Key Type
  message.append("_");
  message.append(list.value(1).toBase64()); // Public Key Hash
  message.append("_");
  message.append(list.value(2).toBase64()); // Public Key
  message.append("\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotForwardSecrecyRequest(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotForwardSecrecyRequest(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotForwardSecrecyResponse
(const QByteArrayList &list)
{
  QByteArray message("forward_secrecy_response_");

  message.append(list.value(0).toBase64()); // Public Key Hash
  message.append("\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotForwardSecrecyResponse(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotForwardSecrecyResponse(): "
		 "socket %1:%2 is not encrypted. Ignoring write() response.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}
