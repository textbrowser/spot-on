/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

#include <QProgressDialog>
#include <QScopedPointer>

#include "spot-on.h"
#include "ui_forwardsecrecyalgorithmsselection.h"

void spoton::slotDuplicateTransmittedMagnet(void)
{
  QListWidgetItem *item = m_ui.transmittedMagnets->currentItem();

  if(!item)
    return;

  QString connectionName("");
  QString magnet(item->text());
  bool ok = false;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    goto done_label;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO "
		      "magnets (magnet, magnet_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, crypt->encryptedThenHashed(magnet.toLatin1(),
						      &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash(magnet.toLatin1(),
					      &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    askKernelToReadStarBeamKeys();
}

void spoton::addMessageToReplayQueue(const QString &message1,
				     const QByteArray &message2,
				     const QString &publicKeyHash)
{
  if(message1.isEmpty() || message2.isEmpty() || publicKeyHash.isEmpty())
    return;

  QPair<QQueue<QString>, QQueue<QByteArray> > pair
    (m_chatQueues.value(publicKeyHash));

  {
    QQueue<QString> queue(pair.first);

    if(queue.size() >= spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE)
      if(!queue.isEmpty())
	queue.dequeue();

    queue.enqueue(message1);
    pair.first = queue;
  }

  {
    QQueue<QByteArray> queue(pair.second);

    if(queue.size() >= spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE)
      if(!queue.isEmpty())
	queue.dequeue();

    queue.enqueue(message2);
    pair.second = queue;
  }

  m_chatQueues.insert(publicKeyHash, pair);
}

void spoton::slotReplayMessages(void)
{
  QTableWidgetItem *item = m_ui.participants->item
    (m_ui.participants->currentRow(), 3); // public_key_hash

  if(!item)
    return;

  if(!m_chatQueues.contains(item->text()))
    return;

  QDateTime now(QDateTime::currentDateTime());
  QQueue<QString> queue1(m_chatQueues.value(item->text()).first);
  QPointer<spoton_chatwindow> chat = m_chatWindows.value(item->text(), 0);
  QString msg("");

  msg.append
    (QString("[%1/%2/%3 %4:%5<font color=grey>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append(tr("<i>Replay activated.</i>"));
  m_ui.messages->append(msg);

  if(chat)
    chat->append(msg);

  for(int i = 0; i < queue1.size(); i++)
    {
      QString msg(queue1.at(i));

      m_ui.messages->append(msg);
      m_ui.messages->verticalScrollBar()->setValue
	(m_ui.messages->verticalScrollBar()->maximum());

      if(chat)
	chat->append(msg);
    }

  QQueue<QByteArray> queue2(m_chatQueues.value(item->text()).second);

  for(int i = 0; i < queue2.size(); i++)
    {
      QByteArray message(queue2.at(i));

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotReplayMessages(): write() failure for "
		   "%1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_chatInactivityTimer.start();
    }
}

void spoton::slotEstablishEmailForwardSecrecy(void)
{
  QModelIndexList names
    (m_ui.emailParticipants->selectionModel()->
     selectedRows(0)); // Participant
  QModelIndexList publicKeyHashes
    (m_ui.emailParticipants->selectionModel()->
     selectedRows(3)); // public_key_hash
  QProgressDialog progress(this);
  QString error("");
  spoton_crypt *s_crypt = m_crypts.value("email", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket.isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(publicKeyHashes.isEmpty())
    {
      error = tr("Please select at least one participant.");
      goto done_label;
    }

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Generating key pairs..."));
  progress.setMaximum(publicKeyHashes.size());
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Generating Key Pairs").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  for(int i = 0; i < publicKeyHashes.size() && !progress.wasCanceled(); i++)
    {
      if(i + 1 <= progress.maximum())
	progress.setValue(i + 1);

      progress.update();
#ifndef Q_OS_MAC
      QApplication::processEvents();
#endif

      bool temporary = publicKeyHashes.at(i).data(Qt::UserRole).toBool();

      if(temporary)
	/*
	** Ignore temporary participants.
	*/

	continue;

      QPair<QByteArray, QByteArray> keys;
      spoton_crypt crypt("aes256",
			 "sha512",
			 QByteArray(),
			 QByteArray(),
			 QByteArray(),
			 0,
			 0,
			 QString(""));

      keys = crypt.generatePrivatePublicKeys
	(s_crypt->publicKeySize(),
	 s_crypt->publicKeyAlgorithm(),
	 error,
	 false);

      if(!error.isEmpty())
	break;
      else
	{
	  QByteArray message;
	  QString keyType
	    (publicKeyHashes.at(i).data(Qt::ItemDataRole(Qt::UserRole + 1)).
	     toString());
	  QString name(names.at(i).data().toString());

	  message.append("forward_secrecy_request_");
	  message.append(name.toUtf8().toBase64());
	  message.append("_");
	  message.append(publicKeyHashes.at(i).data().toByteArray());
	  message.append("_");
	  message.append(keys.first.toBase64()); // Private Key
	  message.append("_");
	  message.append(keys.second.toBase64()); // Public Key
	  message.append("_");
	  message.append(keyType.toLatin1().toBase64());
	  message.append("_");
	  message.append(QByteArray("email").toBase64());
	  message.append("\n");

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    spoton_misc::logError
	      (QString("spoton::slotEstablishEmailForwardSecrecy(): "
		       "write() failure for "
		       "%1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	}
    }

  progress.close();

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical
      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
}

QList<QByteArray> spoton::retrieveForwardSecrecyInformation
(const QSqlDatabase &db, const QString &oid, bool *ok1) const
{
  if(ok1)
    *ok1 = false;

  QList<QByteArray> list;

  if(!db.isOpen())
    return list;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return list;

  QSqlQuery query(db);

  query.setForwardOnly(true);
  query.prepare("SELECT forward_secrecy_authentication_algorithm, "
		"forward_secrecy_authentication_key, "
		"forward_secrecy_encryption_algorithm, "
		"forward_secrecy_encryption_key FROM "
		"friends_public_keys WHERE OID = ?");
  query.bindValue(0, oid);

  if(query.exec())
    {
      if(query.next())
	{
	  QByteArray bytes;
	  bool ok2 = true;

	  if(!query.isNull(0))
	    {
	      bytes = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok2);

	      if(ok2)
		list << bytes;
	    }

	  if(ok2)
	    if(!query.isNull(1))
	      {
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()), &ok2);

		if(ok2)
		  list << bytes;
	      }

	  if(ok2)
	    if(!query.isNull(2))
	      {
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok2);

		if(ok2)
		  list << bytes;
	      }

	  if(ok2)
	    if(!query.isNull(3))
	      {
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()), &ok2);

		if(ok2)
		  list << bytes;
	      }

	  if(ok2)
	    if(ok1)
	      *ok1 = true;
	}
      else if(ok1)
	*ok1 = true;
    }

  return list;
}

void spoton::slotRespondToForwardSecrecy(void)
{
  QByteArray hashKey;
  QByteArray message;
  QByteArray publicKeyHash
    (m_sb.forward_secrecy_request->property("public_key_hash").toByteArray());
  QByteArray symmetricKey;
  QScopedPointer<QDialog> dialog;
  QString connectionName("");
  QString error("");
  QStringList aTypes;
  QStringList eTypes;
  Ui_forwardsecrecyalgorithmsselection ui;
  spoton_crypt *s_crypt = m_crypts.value("email", 0);
  spoton_forward_secrecy sfs = m_forwardSecrecyRequests.value(publicKeyHash);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket.isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }

  aTypes = spoton_crypt::hashTypes();

  if(aTypes.isEmpty())
    {
      error = tr("The method spoton_crypt::cipherTypes() has "
		 "failed. "
		 "This is a fatal flaw.");
      goto done_label;
    }

  eTypes = spoton_crypt::cipherTypes();

  if(eTypes.isEmpty())
    {
      error = tr("The method spoton_crypt::hashTypes() has "
		 "failed. "
		 "This is a fatal flaw.");
      goto done_label;
    }

  dialog.reset(new QDialog(this));
  dialog->setWindowTitle
    (tr("%1: Forward Secrecy Algorithms Selection").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(dialog.data());
#ifdef Q_OS_MAC
  dialog->setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.authentication_algorithm->addItems(aTypes);
  ui.encryption_algorithm->addItems(eTypes);

  if(dialog->exec() != QDialog::Accepted)
    {
      popForwardSecrecyRequest(publicKeyHash);
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;
	size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
	  (ui.encryption_algorithm->currentText().toLatin1());

	if(symmetricKeyLength <= 0)
	  {
	    db.close();
	    error = tr("Peculiar spoton_crypt error.");
	    goto remove_database_label;
	  }

	hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
	hashKey = spoton_crypt::strongRandomBytes
	  (static_cast<size_t> (hashKey.length())).toHex();
	symmetricKey.resize(static_cast<int> (symmetricKeyLength));
	symmetricKey = spoton_crypt::strongRandomBytes
	  (static_cast<size_t> (symmetricKey.length())).toHex();
	query.prepare
	  ("UPDATE friends_public_keys "
	   "SET forward_secrecy_authentication_algorithm = ?, "
	   "forward_secrecy_authentication_key = ?, "
	   "forward_secrecy_encryption_algorithm = ?, "
	   "forward_secrecy_encryption_key = ? WHERE "
	   "public_key_hash = ?");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(ui.authentication_algorithm->
					   currentText().toLatin1(), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->encryptedThenHashed(hashKey, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->encryptedThenHashed(ui.encryption_algorithm->
					     currentText().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->encryptedThenHashed(symmetricKey, &ok).toBase64());

	if(ok)
	  query.bindValue(4, publicKeyHash.toBase64());

	if(ok)
	  ok = query.exec();

	if(!ok)
	  error = tr("Error recording credentials.");
      }
    else
      error = tr("Unable to open a connection to friends_public_keys.db");

    db.close();
  }

 remove_database_label:
  QSqlDatabase::removeDatabase(connectionName);

  if(!error.isEmpty())
    goto done_label;

  message.append("forward_secrecy_response_");
  message.append(publicKeyHash.toBase64());
  message.append("_");
  message.append(sfs.public_key.toBase64());
  message.append("_");
  message.append(sfs.key_type.toLatin1().toBase64());
  message.append("_");
  message.append(ui.authentication_algorithm->currentText().toLatin1().
		 toBase64());
  message.append("_");
  message.append(hashKey.toBase64());
  message.append("_");
  message.append(ui.encryption_algorithm->currentText().toLatin1().
		 toBase64());
  message.append("_");
  message.append(symmetricKey.toBase64());
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotRespondToForwardSecrecy(): "
	       "write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    popForwardSecrecyRequest(publicKeyHash);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical
      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
}

void spoton::slotResetForwardSecrecyInformation(void)
{
  QModelIndexList publicKeyHashes
    (m_ui.emailParticipants->selectionModel()->
     selectedRows(3)); // public_key_hash

  if(publicKeyHashes.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	for(int i = 0; i < publicKeyHashes.size(); i++)
	  {
	    query.prepare
	      ("UPDATE friends_public_keys "
	       "SET forward_secrecy_authentication_algorithm = NULL, "
	       "forward_secrecy_authentication_key = NULL, "
	       "forward_secrecy_encryption_algorithm = NULL, "
	       "forward_secrecy_encryption_key = NULL WHERE "
	       "public_key_hash = ?");
	    query.bindValue(0, publicKeyHashes.at(i).data().toByteArray());
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::forwardSecrecyRequested(const QList<QByteArray> &list)
{
  QString keyType(QByteArray::fromBase64(list.value(0)).constData());

  if(!(keyType == "chat" || keyType == "email" ||
       keyType == "poptastic" || keyType == "url"))
    return;

  QByteArray publicKeyHash(QByteArray::fromBase64(list.value(1)));

  if(publicKeyHash.size() != spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES)
    return;

  if(m_forwardSecrecyRequests.contains(publicKeyHash))
    return;
  else
    {
      spoton_forward_secrecy s;

      s.key_type = keyType;
      s.public_key = list.value(2);
      s.public_key_hash = publicKeyHash;
      m_forwardSecrecyRequests.insert(publicKeyHash, s);
    }

  if(!m_sb.forward_secrecy_request->isVisible())
    {
      QString str(publicKeyHash.toBase64().constData());

      m_sb.forward_secrecy_request->setProperty
	("public_key_hash", publicKeyHash);
      m_sb.forward_secrecy_request->
	setToolTip(tr("Participant %1 is requesting forward secrecy "
		      "credentials.").arg(str.mid(0, 16) +
					  "..." +
					  str.right(16)));
      m_sb.forward_secrecy_request->setVisible(true);
    }
}

void spoton::popForwardSecrecyRequest(const QByteArray &publicKeyHash)
{
  m_forwardSecrecyRequests.remove(publicKeyHash);

  if(m_forwardSecrecyRequests.isEmpty())
    {
      m_sb.forward_secrecy_request->setProperty("public_key_hash", QVariant());
      m_sb.forward_secrecy_request->setToolTip("");
      m_sb.forward_secrecy_request->setVisible(false);
    }
  else
    {
      QByteArray publicKeyHash(m_forwardSecrecyRequests.keys().value(0));
      QString str(publicKeyHash.toBase64().constData());

      m_sb.forward_secrecy_request->setProperty
	("public_key_hash", publicKeyHash);
      m_sb.forward_secrecy_request->
	setToolTip(tr("Participant %1 is requesting forward secrecy "
		      "credentials.").arg(str.mid(0, 16) +
					  "..." +
					  str.right(16)));
    }
}
