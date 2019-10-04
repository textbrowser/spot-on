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

#if QT_VERSION < 0x050000
void spoton_gui_server_tcp_server::incomingConnection(int socketDescriptor)
#else
void spoton_gui_server_tcp_server::incomingConnection(qintptr socketDescriptor)
#endif
{
  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");
  int kernelKeySize = spoton_kernel::setting("gui/kernelKeySize", 2048).toInt();

  if(kernelKeySize > 0)
    spoton_crypt::generateSslKeys
      (kernelKeySize,
       certificate,
       privateKey,
       publicKey,
       serverAddress(),
       60L * 60L * 24L *
       static_cast<long int> (spoton_common::
			      KERNEL_CERTIFICATE_DAYS_VALID),
       error);

  if(error.isEmpty())
    {
      QPointer<QSslSocket> socket;

      try
	{
	  socket = new QSslSocket(this);
	  socket->setSocketDescriptor(socketDescriptor);
	  socket->setSocketOption
	    (QAbstractSocket::LowDelayOption,
	     spoton_kernel::setting("kernel/tcp_nodelay", 1).
	     toInt()); /*
		       ** Disable Nagle?
		       */

	  if(kernelKeySize > 0)
	    {
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
			 spoton_common::SSL_CONTROL_STRING).toString());

	      configuration.setLocalCertificate
		(QSslCertificate(certificate));
	      configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
	      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));
#if QT_VERSION >= 0x040806
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
#if QT_VERSION >= 0x050501
	      spoton_crypt::setSslCiphers
		(QSslConfiguration::supportedCiphers(),
		 sslCS,
		 configuration);
#else
	      spoton_crypt::setSslCiphers
		(socket->supportedCiphers(), sslCS, configuration);
#endif
	      socket->setSslConfiguration(configuration);
	      socket->startServerEncryption();
	    }

	  m_queue.enqueue(socket);
	  emit newConnection();
	}
      catch(...)
	{
	  m_queue.removeOne(socket);

	  if(socket)
	    socket->deleteLater();

	  spoton_misc::closeSocket(socketDescriptor);
	  spoton_misc::logError("spoton_gui_server_tcp_server::"
				"incomingConnection(): socket deleted.");
	}
    }
  else
    {
      QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

      if(socket.setSocketDescriptor(socketDescriptor))
	socket.abort();
      else
	spoton_misc::closeSocket(socketDescriptor);

      spoton_misc::logError
	(QString("spoton_gui_server_tcp_server::"
		 "incomingConnection(): "
		 "generateSslKeys() failure (%1).").arg(error));
    }
}

spoton_gui_server::spoton_gui_server(QObject *parent):
  spoton_gui_server_tcp_server(parent)
{
  if(!listen(QHostAddress("127.0.0.1")))
    spoton_misc::logError("spoton_gui_server::spoton_gui_server(): "
			  "listen() failure. This is a serious problem!");

  connect(&m_fileSystemWatcher,
	  SIGNAL(fileChanged(const QString &)),
	  this,
	  SLOT(slotFileChanged(const QString &)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(this,
	  SIGNAL(newConnection(void)),
	  this,
	  SLOT(slotClientConnected(void)));
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
  spoton_misc::logError("The UI server has been terminated.");
  m_generalTimer.stop();
  m_guiIsAuthenticated.clear();
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

void spoton_gui_server::slotAuthenticationRequested
(const QString &peerInformation)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  QByteArray message;

  message.append("authentication_requested_");
  message.append(peerInformation);
  message.append("\n");
  sendMessageToUIs(message);
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
      spoton_misc::logError
	(QString("spoton_gui_server::slotClientDisconnected(): "
		 "client %1:%2 disconnected.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
      m_guiIsAuthenticated.remove(socket->socketDescriptor());
      m_guiSocketData.remove(socket->socketDescriptor());
      socket->deleteLater();
    }

  if(m_guiSocketData.isEmpty())
    spoton_kernel::clearBuzzKeysContainer();
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

void spoton_gui_server::slotForwardSecrecyRequest
(const QByteArrayList &list)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  QByteArray message("forward_secrecy_request_");

  message.append(list.value(0).toBase64()); // Key Type
  message.append("_");
  message.append(list.value(1).toBase64()); // Public Key Hash
  message.append("_");
  message.append(list.value(2).toBase64()); // Public Key
  message.append("\n");
  sendMessageToUIs(message);
}

void spoton_gui_server::slotForwardSecrecyResponse
(const QByteArrayList &list)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  QByteArray message("forward_secrecy_response_");

  message.append(list.value(0).toBase64()); // Public Key Hash
  message.append("\n");
  sendMessageToUIs(message);
}

void spoton_gui_server::sendMessageToUIs(const QByteArray &message)
{
  int keySize = spoton_kernel::setting("gui/kernelKeySize", 2048).toInt();

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(m_guiIsAuthenticated.
       value(socket->socketDescriptor(), false) && (keySize == 0 ||
						    socket->isEncrypted()))
      {
	qint64 w = 0;

	if((w = socket->write(message.constData(),
			      message.length())) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::sendMessageToUIs(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));

	if(w > 0)
	  {
	    QWriteLocker locker
	      (&spoton_kernel::s_totalUiBytesReadWrittenMutex);

	    spoton_kernel::s_totalUiBytesReadWritten.second +=
	      static_cast<quint64> (w);
	  }
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::sendMessageToUIs(): "
		 "socket %1:%2 is not encrypted, if required, "
		 "or the user interface "
		 "has not been authenticated. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotModeChanged(QSslSocket::SslMode mode)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    {
      spoton_misc::logError("spoton_gui_server::slotModeChanged(): "
			    "empty socket object.");
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

void spoton_gui_server::slotNewEMailArrived(void)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  sendMessageToUIs("newmail\n");
}

void spoton_gui_server::slotNotification(const QString &text)
{
  if(spoton_kernel::interfaces() == 0 ||
     !spoton_kernel::setting("gui/monitorEvents", true).toBool())
    return;

  if(text.trimmed().isEmpty())
    return;

  QByteArray message("notification_");

  message.append(text);
  message.append("\n");
  sendMessageToUIs(message);
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

  if(!socket->isEncrypted() &&
     spoton_kernel::setting("gui/kernelKeySize", 2048).toInt() > 0)
    {
      while(socket->bytesAvailable() > 0)
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

  while(socket->bytesAvailable() > 0)
    {
      QByteArray data(socket->readAll());

      if(data.length() > 0)
	{
	  QWriteLocker locker(&spoton_kernel::s_totalUiBytesReadWrittenMutex);

	  spoton_kernel::s_totalUiBytesReadWritten.first +=
	    static_cast<quint64> (data.length());
	}

      m_guiSocketData[socket->socketDescriptor()].append(data);
    }

  if(m_guiSocketData.value(socket->socketDescriptor()).contains('\n'))
    {
      QByteArray data(m_guiSocketData.value(socket->socketDescriptor()));
      QList<QByteArray> messages
	(data.mid(0, data.lastIndexOf('\n')).split('\n'));

      data.remove(0, data.lastIndexOf('\n'));

      if(data.isEmpty())
	m_guiSocketData.remove(socket->socketDescriptor());
      else
	m_guiSocketData.insert(socket->socketDescriptor(), data);

      while(!messages.isEmpty())
	{
	  QByteArray message(messages.takeFirst());

	  if(message.startsWith("addbuzz_") &&
	     m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("befriendparticipant_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("buzz_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("buzz_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 7)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray(),
		   QByteArray(),
		   "0040a",
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   QByteArray::fromBase64(list.value(6)));
	      else if(list.size() == 9)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   "0040b",
		   QByteArray::fromBase64(list.value(6)),
		   QByteArray::fromBase64(list.value(7)),
		   QByteArray::fromBase64(list.value(8)));
	    }
	  else if(message.startsWith("call_participant_using_forward_"
				     "secrecy_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0,
		 static_cast<int> (qstrlen("call_participant_using_"
					   "forward_secrecy_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit callParticipantUsingForwardSecrecy
		  (list.value(0), list.value(1).toLongLong());
	    }
	  else if(message.startsWith("call_participant_using_gemini_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("call_participant_using_public_key_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("detach_listener_neighbors_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("detach_listener_neighbors_")));

	      if(!message.isEmpty())
		emit detachNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("disconnect_listener_neighbors_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("disconnect_listener_"
					      "neighbors_")));

	      if(!message.isEmpty())
		emit disconnectNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("echokeypair_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("echokeypair_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit echoKeyShare(list);
	    }
	  else if(message.startsWith("forward_secrecy_request_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("forward_secrecy_request_")));

	      QList<QByteArray> list(message.split('_'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      if(list.size() == 6)
		emit forwardSecrecyInformationReceivedFromUI(list);
	    }
	  else if(message.startsWith("forward_secrecy_response_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
		  QStringList names
		    (spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
		     spoton_common::SPOTON_SIGNATURE_KEY_NAMES);
		  int count = 0;

		  std::sort(names.begin(), names.end());

		  for(int i = 0; i < names.size(); i++)
		    {
		      spoton_crypt *crypt = spoton_kernel::s_crypts.value
			(names.at(i), 0);

		      if(crypt)
			{
			  if(crypt->isAuthenticated() &&
			     spoton_misc::isAuthenticatedHint(crypt))
			    count += 2;
			  else
			    spoton_misc::logError
			      (QString("spoton_gui_server::"
				       "slotReadyRead(): "
				       "spoton_crypt object %1 "
				       "could not be authenticated.").
			       arg(names.at(i)));

			  continue;
			}

		      try
			{
			  crypt = new spoton_crypt
			    (spoton_kernel::setting("gui/cipherType",
						    "aes256").toString(),
			     spoton_kernel::setting("gui/hashType",
						    "sha512").toString(),
			     QByteArray(),
			     QByteArray::fromBase64(list.value(0)),
			     QByteArray::fromBase64(list.value(1)),
			     spoton_kernel::setting("gui/saltLength",
						    512).toInt(),
			     static_cast<unsigned
			     long int> (spoton_kernel::
					setting("gui/iterationCount",
						10000).toInt()),
			     names.at(i));
			}
		      catch(...)
			{
			  delete crypt;
			  crypt = 0;
			}

		      if(Q_LIKELY(crypt))
			{
			  if(crypt->isAuthenticated() &&
			     spoton_misc::isAuthenticatedHint(crypt))
			    count += 2;
			  else
			    spoton_misc::logError
			      (QString("spoton_gui_server::"
				       "slotReadyRead(): "
				       "spoton_crypt object %1 "
				       "could not be authenticated.").
			       arg(names.at(i)));

			  spoton_kernel::s_crypts.insert(names.at(i), crypt);
			}
		    }

		  m_guiIsAuthenticated[socket->socketDescriptor()] =
		    count == 2 * names.size() && names.size() > 0 ?
		    true : false;

		  if(!m_guiIsAuthenticated.value(socket->socketDescriptor(),
						 false))
		    spoton_misc::logError
		      (QString("spoton_gui_server::slotReadyRead(): "
			       "UI at socket %1 is not authenticated "
			       "(count = %2, names.size() = %3).").
		       arg(socket->socketDescriptor()).
		       arg(count).
		       arg(names.size()));

		  for(int i = 0; i < names.size(); i++)
		    if(!spoton_kernel::s_crypts.value(names.at(i), 0))
		      spoton_misc::logError
			("spoton_gui_server::slotReadyRead(): potential "
			 "memory failure. Critical!");
		}
	    }
	  else if(message.startsWith("message_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("poptasticmessage_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("populate_starbeam_keys") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    emit populateStarBeamKeys();
	  else if(message.startsWith("publicizealllistenersplaintext") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    emit publicizeAllListenersPlaintext();
	  else if(message.startsWith("publicizelistenerplaintext") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("publicize"
					      "listenerplaintext_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 1)
		emit publicizeListenerPlaintext
		  (list.value(0).toLongLong());
	    }
	  else if(message.startsWith("purge_ephemeral_key_pair_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("purge_ephemeral_key_pair_")));

	      if(!message.isEmpty())
		emit purgeEphemeralKeyPair(QByteArray::fromBase64(message));
	    }
	  else if(message.startsWith("purge_ephemeral_keys") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    emit purgeEphemeralKeys();
	  else if(message.startsWith("removebuzz_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("removebuzz_")));
	      spoton_kernel::removeBuzzKey(QByteArray::fromBase64(message));
	    }
	  else if(message.startsWith("retrievemail") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    emit retrieveMail();
	  else if(message.startsWith("sharebuzzmagnet_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("sharebuzzmagnet_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		emit buzzMagnetReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)));
	    }
	  else if(message.startsWith("sharelink_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove
		(0, static_cast<int> (qstrlen("sharelink_")));

	      if(!message.isEmpty())
		emit shareLink(message);
	    }
	  else if(message.startsWith("sharepublickey_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
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
	  else if(message.startsWith("smp_") &&
		  m_guiIsAuthenticated.value(socket->socketDescriptor(), false))
	    {
	      message.remove(0, static_cast<int> (qstrlen("smp_")));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 5)
		emit smpMessageReceivedFromUI(list);
	    }
	}
    }

  if(m_guiSocketData.value(socket->socketDescriptor()).size() >
     spoton_common::MAXIMUM_KERNEL_GUI_SERVER_SINGLE_SOCKET_BUFFER_SIZE)
    {
      m_guiSocketData.remove(socket->socketDescriptor());
      spoton_misc::logError
	(QString("spoton_gui_server::slotReadyRead(): "
		 "container for socket %1:%2 contains too much data. "
		 "Discarding data.").
	 arg(socket->localAddress().toString()).
	 arg(socket->localPort()));
    }
}

void spoton_gui_server::slotReceivedBuzzMessage(const QByteArrayList &list,
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
  sendMessageToUIs(message);
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

  sendMessageToUIs(message);
}

void spoton_gui_server::slotSMPMessage(const QByteArrayList &list)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  QByteArray message("smp_");

  message.append(list.value(0).toBase64()); // Public Key Hash
  message.append("_");
  message.append(list.value(1).toBase64()); // Data
  message.append("\n");
  sendMessageToUIs(message);
}

void spoton_gui_server::slotStatusMessageReceived
(const QByteArray &publicKeyHash, const QString &status)
{
  if(spoton_kernel::interfaces() == 0)
    return;

  QByteArray message("chat_status_");

  message.append(publicKeyHash.toBase64());
  message.append("_");
  message.append(status);
  message.append("\n");
  sendMessageToUIs(message);
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
