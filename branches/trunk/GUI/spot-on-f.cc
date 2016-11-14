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

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-pacify.h"
#include "spot-on-pageviewer.h"
#if SPOTON_GOLDBUG == 0
#include "spot-on-neighborstatistics.h"
#endif
#include "spot-on-utilities.h"
#include "ui_spot-on-forward-secrecy-algorithms-selection.h"
#include "ui_spot-on-unlock.h"

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

  prepareDatabasesFromUI();

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
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

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
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
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

void spoton::slotEstablishForwardSecrecy(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString());

  if(!(type == "email" || type == "chat"))
    return;

  QModelIndexList names;
  QModelIndexList publicKeyHashes;
  QProgressDialog progress(this);
  QScopedPointer<QDialog> dialog;
  QString algorithm("");
  QString error("");
  QString keySize("");
  Ui_spoton_forwardsecrecyalgorithmsselection ui;
  int count = 0;
  int traditional = 0;

  if(type == "chat")
    {
      names =
	m_ui.participants->selectionModel()->
	selectedRows(0); // Participant
      publicKeyHashes =
	m_ui.participants->selectionModel()->
	selectedRows(3); // public_key_hash
    }
  else
    {
      names =
	m_ui.emailParticipants->selectionModel()->
	selectedRows(0); // Participant
      publicKeyHashes =
	m_ui.emailParticipants->selectionModel()->
	selectedRows(3); // public_key_hash
    }

  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
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

  for(int i = 0; i < publicKeyHashes.size(); i++)
    {
      if(names.value(i).data(Qt::ItemDataRole(Qt::UserRole + 2)).
	 toString() == "traditional e-mail")
	traditional += 1;

      if(publicKeyHashes.value(i).data(Qt::UserRole).toBool())
	/*
	** Ignore temporary participants.
	*/

	count += 1;
    }

  if(count == publicKeyHashes.size())
    {
      error = tr("All of the selected participants are temporary. "
		 "Please befriend some participants before attempting "
		 "to establish Forward Secrecy credentials.");
      goto done_label;
    }

  if(publicKeyHashes.size() == traditional)
    {
      error = tr("Traditional e-mail accounts do not support "
		 "Forward Secrecy.");
      goto done_label;
    }

  if(count > 0)
    QMessageBox::information
      (this, tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
       tr("Some of the selected participants are temporary. "
	  "Forward Secrecy credentials will not be established."));

  if(traditional > 0)
    QMessageBox::information
      (this, tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
       tr("Please note that traditional e-mail accounts do not "
	  "support Forward Secrecy."));

  dialog.reset(new QDialog(this));
  dialog->setWindowTitle
    (tr("%1: Forward Secrecy Algorithms Selection").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(dialog.data());
#ifdef Q_OS_MAC
  dialog->setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.encryptionKeySize->setObjectName("encryption_key_size");
#ifndef SPOTON_MCELIECE_ENABLED
  ui.encryptionKeyType->model()->setData
    (ui.encryptionKeyType->model()->index(1, 0), 0, Qt::UserRole - 1);
#endif
#ifndef SPOTON_LINKED_WITH_LIBNTRU
  ui.encryptionKeyType->model()->setData
    (ui.encryptionKeyType->model()->index(2, 0), 0, Qt::UserRole - 1);
#endif
  ui.tab->setCurrentIndex(0);
  ui.tab->setTabEnabled(1, false);
  ui.text_1->setText(tr("Please select."));
  connect(ui.encryptionKeyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotForwardSecrecyEncryptionKeyChanged(int)));

  if(dialog->exec() != QDialog::Accepted)
    goto done_label;

  dialog->close();
  repaint();
#ifndef Q_OS_MAC
  QApplication::processEvents();
#endif

  if(ui.encryptionKeyType->currentIndex() == 0)
    algorithm = "elg";
  else if(ui.encryptionKeyType->currentIndex() == 1)
    algorithm = "mceliece";
  else if(ui.encryptionKeyType->currentIndex() == 2)
    algorithm = "ntru";
  else
    algorithm = "rsa";

  keySize = ui.encryptionKeySize->currentText();

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Generating key pairs. Please be patient."));
  progress.setMaximum(publicKeyHashes.size());
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Generating Key Pairs").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  for(int i = 0; i < publicKeyHashes.size() && !progress.wasCanceled(); i++)
    {
      if(i + 1 <= progress.maximum())
	progress.setValue(i + 1);

#ifndef Q_OS_MAC
      progress.repaint();
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
			 "");

      keys = crypt.generatePrivatePublicKeys(keySize, algorithm, error, false);

      if(!error.isEmpty())
	break;
      else
	{
	  QByteArray message;
	  QString keyType
	    (publicKeyHashes.at(i).data(Qt::ItemDataRole(Qt::UserRole + 1)).
	     toString());
	  QString name(names.at(i).data().toString());

	  keys.first = qCompress(keys.first);
	  keys.second = qCompress(keys.second);
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
	  message.append(type.toLatin1().toBase64()); // Widget type.
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
  QApplication::restoreOverrideCursor();

 done_label:

  if(dialog)
    dialog->close();

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
  QDialog *dialog = 0;
  QString aKey("");
  QString connectionName("");
  QString error("");
  QString name("");
  QString keySize("");
  QString keyType("");
  QString str(publicKeyHash.toBase64().constData());
  QStringList aTypes;
  QStringList eTypes;
  Ui_spoton_forwardsecrecyalgorithmsselection ui;
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

  dialog = new QDialog(this);
  dialog->setWindowTitle
    (tr("%1: Forward Secrecy Algorithms Selection").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(dialog);
#ifdef Q_OS_MAC
  dialog->setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.authentication_algorithm->addItems(aTypes);
  ui.encryption_algorithm->addItems(eTypes);
  ui.tab->setCurrentIndex(1);
  ui.tab->setTabEnabled(0, false);
  name = spoton_misc::nameFromPublicKeyHash(publicKeyHash, s_crypt);
  keyType = spoton_misc::keyTypeFromPublicKeyHash(publicKeyHash, s_crypt);

  if(name.isEmpty())
    {
      if(keyType == "poptastic")
	name = "unknown@unknown.org";
      else
	name = "unknown";
    }

  sfs.public_key = qUncompress(sfs.public_key);
  aKey = spoton_crypt::publicKeyAlgorithm(sfs.public_key);

  if(aKey.isEmpty())
    aKey = "unknown";

  keySize = spoton_crypt::publicKeySize(sfs.public_key);

  if(keySize.isEmpty())
    keySize = "unknown";

  ui.text_2->setText
    (tr("<html>The participant <b>%1</b> (%2) is requesting "
	"forward secrecy credentials. The participant provided an "
	"<b>%3:%4</b> "
	"public session key. Please press the OK "
	"button if you would like to complete the exchange.</html>").
     arg(name).arg(str.mid(0, 16) + "..." + str.right(16)).
     arg(aKey).arg(keySize));

  if(dialog->exec() != QDialog::Accepted)
    {
      popForwardSecrecyRequest(publicKeyHash);
      goto done_label;
    }

  repaint();
#ifndef Q_OS_MAC
  QApplication::processEvents();
#endif

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

	hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
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

  sfs.public_key = qCompress(sfs.public_key);
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

  if(dialog)
    dialog->deleteLater();

  if(!error.isEmpty())
    QMessageBox::critical
      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
}

void spoton::slotResetForwardSecrecyInformation(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString());

  if(!(type == "email" || type == "chat"))
    return;

  QModelIndexList publicKeyHashes;

  if(type == "chat")
    publicKeyHashes =
      m_ui.participants->selectionModel()->
      selectedRows(3); // public_key_hash
  else
    publicKeyHashes =
      m_ui.emailParticipants->selectionModel()->
      selectedRows(3); // public_key_hash

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
       keyType == "open-library" || keyType == "poptastic" ||
       keyType == "url"))
    return;

  QByteArray publicKeyHash(QByteArray::fromBase64(list.value(1)));

  if(publicKeyHash.size() != spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES)
    return;

  if(m_forwardSecrecyRequests.contains(publicKeyHash))
    return;
  else
    {
      spoton_forward_secrecy s;

      s.key_type = keyType;
      s.public_key = QByteArray::fromBase64(list.value(2));
      s.public_key_hash = publicKeyHash;
      m_forwardSecrecyRequests.insert(publicKeyHash, s);
    }

  if(!m_sb.forward_secrecy_request->isVisible())
    {
      QString name = spoton_misc::nameFromPublicKeyHash
	(publicKeyHash, m_crypts.value("chat", 0));
      QString keyType = spoton_misc::keyTypeFromPublicKeyHash
	(publicKeyHash, m_crypts.value("chat", 0));

      if(name.isEmpty())
	{
	  if(keyType == "poptastic")
	    name = "unknown@unknown.org";
	  else
	    name = "unknown";
	}

      QString str(publicKeyHash.toBase64().constData());

      notify(QDateTime::currentDateTime().toString());
      notify
	(tr("Participant <i>%1</i> (%2) is "
	    "requesting forward secrecy "
	    "credentials.<br>").
	 arg(name).
	 arg(str.mid(0, 16) + "..." + str.right(16)));
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

void spoton::prepareTabIcons(void)
{
  QString iconSet
    (m_settings.value("gui/iconSet", "nouve").toString());
  QStringList list;

#if SPOTON_GOLDBUG == 0
  list << "buzz.png" << "chat.png" << "email.png"
       << "add-listener.png" << "neighbors.png" << "search.png"
       << "settings.png" << "starbeam.png" << "urls.png"
       << "spot-on-logo.png";
#else
  list << "buzz.png" << "chat.png" << "email.png"
       << "server.png" << "connect.png" << "search.png"
       << "settings.png" << "starbeam.png" << "urls.png"
       << "key.png" << "goldbug.png";
#endif

  for(int i = 0; i < list.size(); i++)
    {
      QPixmap pixmap;

      if(m_ui.tab->tabPosition() == QTabWidget::North ||
	 m_ui.tab->tabPosition() == QTabWidget::South)
	pixmap = QPixmap(QString(":/%1/%2").arg(iconSet).arg(list.at(i)));
      else
	{
	  QTransform transform;

	  pixmap = QPixmap(QString(":/%1/%2").arg(iconSet).arg(list.at(i)));

	  if(m_ui.tab->tabPosition() == QTabWidget::East)
	    transform.rotate(-90);
	  else
	    transform.rotate(90);

	  pixmap = pixmap.transformed(transform, Qt::SmoothTransformation);
	}

      QHash<QString, QVariant> hash(m_tabWidgetsProperties[i]);

      hash["icon"] = QIcon(pixmap);
      m_tabWidgetsProperties[i] = hash;
    }

  for(int i = 0; i < m_ui.tab->count(); i++)
    {
      /*
      ** May be slow... although we have a few pages.
      */

      int index = m_tabWidgets.key(m_ui.tab->widget(i));

      m_ui.tab->setTabIcon
	(i, m_tabWidgetsProperties[index].value("icon").value<QIcon> ());
    }
}

void spoton::slotEmailFsGb(int index)
{
  if(index == 1)
    m_ui.goldbug->setEnabled(true);
  else
    {
      m_ui.goldbug->clear();
      m_ui.goldbug->setEnabled(false);
    }
}

void spoton::slotForwardSecrecyEncryptionKeyChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QWidget *parent = comboBox->parentWidget();

  if(!parent)
    return;

  do
    {
      if(qobject_cast<QDialog *> (parent))
	break;

      if(parent)
	parent = parent->parentWidget();
    }
  while(parent != 0);

  if(!parent)
    return;

  comboBox = parent->findChild<QComboBox *> ("encryption_key_size");

  if(!comboBox)
    return;

  QStringList list;

  if(index == 0)
    list << s_publicKeySizes["elgamal"];
  else if(index == 1)
    list << s_publicKeySizes["mceliece"];
  else if(index == 2)
    list << s_publicKeySizes["ntru"];
  else
    list << s_publicKeySizes["rsa"];

  comboBox->clear();
  comboBox->addItems(list);
  comboBox->setCurrentIndex(0);
}

void spoton::slotAllowFSRequest(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(!checkBox)
    return;

  if(checkBox == m_optionsUi.chat_fs_request)
    {
      QSettings settings;

      m_settings["gui/allowChatFSRequest"] = state;
      settings.setValue("gui/allowChatFSRequest", state);
    }
  else if(checkBox == m_optionsUi.email_fs_request)
    {
      QSettings settings;

      m_settings["gui/allowEmailFSRequest"] = state;
      settings.setValue("gui/allowEmailFSRequest", state);
    }
}

void spoton::prepareTimeWidgets(void)
{
  if(!m_optionsWindow)
    return;

  foreach(QSlider *slider, m_optionsWindow->findChildren<QSlider *> ())
    connect(slider,
	    SIGNAL(valueChanged(int)),
	    this,
	    SLOT(slotTimeSliderValueChanged(int)),
	    Qt::UniqueConnection);

  m_optionsUi.chat_time_delta->setValue
    (spoton_common::CHAT_TIME_DELTA_MAXIMUM);
  m_optionsUi.forward_secrecy_time_delta->setValue
    (spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM);
  m_optionsUi.gemini_time_delta->setValue
    (spoton_common::GEMINI_TIME_DELTA_MAXIMUM);
  m_optionsUi.kernel_cache_object_lifetime->setValue
    (spoton_common::CACHE_TIME_DELTA_MAXIMUM);
  m_optionsUi.kernel_url_dispatcher->setValue
    (spoton_common::KERNEL_URL_DISPATCHER_INTERVAL);
  m_optionsUi.poptastic_forward_secrecy_time_delta->setValue
    (spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM);
  m_optionsUi.poptastic_gemini_time_delta->setValue
    (spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM);
  m_optionsUi.retrieve_mail_time_delta->setValue
    (spoton_common::MAIL_TIME_DELTA_MAXIMUM);

  foreach(QSlider *slider, m_optionsWindow->findChildren<QSlider *> ())
    {
      int value = slider->value();

      if(m_optionsUi.chat_time_delta == slider)
	m_optionsUi.chat_time_delta_current->setText(QString::number(value));
      else if(m_optionsUi.forward_secrecy_time_delta == slider)
	m_optionsUi.forward_secrecy_time_delta_current->setText
	  (QString::number(value));
      else if(m_optionsUi.gemini_time_delta == slider)
	m_optionsUi.gemini_time_delta_current->setText(QString::number(value));
      else if(m_optionsUi.kernel_cache_object_lifetime == slider)
	m_optionsUi.kernel_cache_object_lifetime_current->setText
	  (QString::number(value));
      else if(m_optionsUi.kernel_url_dispatcher == slider)
	m_optionsUi.kernel_url_dispatcher_current->setText
	  (QString::number(value));
      else if(m_optionsUi.poptastic_forward_secrecy_time_delta == slider)
	m_optionsUi.poptastic_forward_secrecy_time_delta_current->setText
	  (QString::number(value));
      else if(m_optionsUi.poptastic_gemini_time_delta == slider)
	m_optionsUi.poptastic_gemini_time_delta_current->setText
	  (QString::number(value));
      else if(m_optionsUi.retrieve_mail_time_delta == slider)
	m_optionsUi.retrieve_mail_time_delta_current->setText
	  (QString::number(value));
    }
}

void spoton::slotTimeSliderValueChanged(int value)
{
  QSlider *slider = qobject_cast<QSlider *> (sender());

  if(!slider)
    return;

  QString str("");

  if(m_optionsUi.chat_time_delta == slider)
    {
      m_optionsUi.chat_time_delta_current->setText(QString::number(value));
      str = "gui/chat_time_delta";
    }
  else if(m_optionsUi.forward_secrecy_time_delta == slider)
    {
      m_optionsUi.forward_secrecy_time_delta_current->setText
	(QString::number(value));
      str = "gui/forward_secrecy_time_delta";
    }
  else if(m_optionsUi.gemini_time_delta == slider)
    {
      m_optionsUi.gemini_time_delta_current->setText(QString::number(value));
      str = "gui/gemini_time_delta";
    }
  else if(m_optionsUi.kernel_cache_object_lifetime == slider)
    {
      m_optionsUi.kernel_cache_object_lifetime_current->setText
	(QString::number(value));
      str = "gui/kernel_cache_object_lifetime";
    }
  else if(m_optionsUi.kernel_url_dispatcher == slider)
    {
      m_optionsUi.kernel_url_dispatcher_current->setText
	(QString::number(value));
      str = "gui/kernel_url_dispatcher_interval";
    }
  else if(m_optionsUi.poptastic_forward_secrecy_time_delta == slider)
    {
      m_optionsUi.poptastic_forward_secrecy_time_delta_current->setText
	(QString::number(value));
      str = "gui/poptastic_forward_secrecy_time_delta";
    }
  else if(m_optionsUi.retrieve_mail_time_delta == slider)
    {
      m_optionsUi.retrieve_mail_time_delta_current->setText
	(QString::number(value));
      str = "gui/retrieve_mail_time_delta";
    }

  if(str.isEmpty())
    return;

  m_settings[str] = value;

  QSettings settings;

  settings.setValue(str, value);
}

void spoton::slotTimeSliderDefaults(void)
{
  QList<int> defaults;
  QStringList keys;

  defaults
    << spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC
    << spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
  keys << "gui/chat_time_delta"
       << "gui/forward_secrecy_time_delta"
       << "gui/gemini_time_delta"
       << "gui/kernel_cache_object_lifetime"
       << "gui/kernel_url_dispatcher_interval"
       << "gui/poptastic_forward_secrecy_time_delta"
       << "gui/poptastic_gemini_time_delta"
       << "gui/retrieve_mail_time_delta";

  QSettings settings;

  for(int i = 0; i < keys.size(); i++)
    {
      m_settings[keys.at(i)] = defaults.at(i);
      settings.setValue(keys.at(i), defaults.at(i));
    }

  spoton_common::CHAT_TIME_DELTA_MAXIMUM = defaults.value(0);
  spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM = defaults.value(1);
  spoton_common::GEMINI_TIME_DELTA_MAXIMUM = defaults.value(2);
  spoton_common::CACHE_TIME_DELTA_MAXIMUM = defaults.value(3);
  spoton_common::KERNEL_URL_DISPATCHER_INTERVAL = defaults.value(4);
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
    defaults.value(5);
  spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM = defaults.value(6);
  spoton_common::MAIL_TIME_DELTA_MAXIMUM = defaults.value(7);
  m_optionsUi.chat_time_delta->setValue
    (spoton_common::CHAT_TIME_DELTA_MAXIMUM);
  m_optionsUi.forward_secrecy_time_delta->setValue
    (spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM);
  m_optionsUi.gemini_time_delta->setValue
    (spoton_common::GEMINI_TIME_DELTA_MAXIMUM);
  m_optionsUi.kernel_cache_object_lifetime->setValue
    (spoton_common::CACHE_TIME_DELTA_MAXIMUM);
  m_optionsUi.kernel_url_dispatcher->setValue
    (spoton_common::KERNEL_URL_DISPATCHER_INTERVAL);
  m_optionsUi.poptastic_forward_secrecy_time_delta->setValue
    (spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM);
  m_optionsUi.poptastic_gemini_time_delta->setValue
    (spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM);
  m_optionsUi.retrieve_mail_time_delta->setValue
    (spoton_common::MAIL_TIME_DELTA_MAXIMUM);
}

void spoton::slotDeleteKey(void)
{
  QString keyType("chat");

  if(m_ui.keys->currentText() == "Chat")
    keyType = "chat";
  else if(m_ui.keys->currentText() == "E-Mail")
    keyType = "email";
  else if(m_ui.keys->currentText() == "Open Library")
    keyType = "open-library";
  else if(m_ui.keys->currentText() == "Poptastic")
    keyType = "poptastic";
  else if(m_ui.keys->currentText() == "Rosetta")
    keyType = "rosetta";
  else if(m_ui.keys->currentText() == "URL")
    keyType = "url";

  spoton_crypt *crypt1 = m_crypts.value(keyType, 0);
  spoton_crypt *crypt2 = m_crypts.value
    (QString("%1-signature").arg(keyType), 0);

  if(!(crypt1 && crypt2))
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt objects. This is "
			       "a fatal flaw."));
      return;
    }

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").
		    arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

  if(keyType == "chat")
    mb.setText(tr("Are you sure that you wish to delete the selected "
		  "key pair? StarBeam digest computations will be "
		  "interrupted. The kernel will also be deactivated."));
  else
    mb.setText(tr("Are you sure that you wish to delete the selected "
		  "key pair? The kernel will be deactivated."));

  if(mb.exec() != QMessageBox::Yes)
    return;

  repaint();
#ifndef Q_OS_MAC
  QApplication::processEvents();
#endif

  if(keyType == "chat")
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_starbeamDigestInterrupt.fetchAndStoreOrdered(1);

      while(!m_starbeamDigestFutures.isEmpty())
	{
	  QFuture<void> future(m_starbeamDigestFutures.takeFirst());

	  future.waitForFinished();
	}

      QApplication::restoreOverrideCursor();
    }

  slotDeactivateKernel();

  if(crypt1)
    crypt1->purgePrivatePublicKeys();

  if(crypt2)
    crypt2->purgePrivatePublicKeys();

  updatePublicKeysLabel();
}

void spoton::slotLock(void)
{
  if(!m_locked)
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setWindowTitle(tr("%1: Confirmation").
			arg(SPOTON_APPLICATION_NAME));
      mb.setWindowModality(Qt::WindowModal);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to lock the application? "
		    "All other windows will be closed. Buzz windows will be "
		    "united with the main window."));

      if(mb.exec() != QMessageBox::Yes)
	return;
      else
	m_locked = !m_locked;
    }
  else
    {
      /*
      ** Authenticate.
      */

      QDialog dialog(this);
      Ui_spoton_unlock ui;

      ui.setupUi(&dialog);
      dialog.setWindowTitle
	(tr("%1: Unlock").arg(SPOTON_APPLICATION_NAME));
      connect(ui.radio_1,
	      SIGNAL(toggled(bool)),
	      ui.passphrase,
	      SLOT(setEnabled(bool)));
      connect(ui.radio_2,
	      SIGNAL(toggled(bool)),
	      ui.answer,
	      SLOT(setEnabled(bool)));
      connect(ui.radio_2,
	      SIGNAL(toggled(bool)),
	      ui.question,
	      SLOT(setEnabled(bool)));
      ui.radio_2->setChecked(true);
      ui.radio_1->setChecked(true);
      ui.passphrase->setFocus();

      if(dialog.exec() != QDialog::Accepted)
	return;

      QByteArray computedHash;
      QByteArray hashType
	(m_settings.value("gui/hashType", "sha512").toByteArray());
      QByteArray salt(m_settings.value("gui/salt", "").toByteArray());
      QByteArray saltedPassphraseHash
	(m_settings.value("gui/saltedPassphraseHash", "").toByteArray());
      QString error("");
      bool authenticated = false;
      bool ok = true;

      if(ui.radio_1->isChecked())
	computedHash = spoton_crypt::saltedPassphraseHash
	  (hashType, ui.passphrase->text(), salt, error);
      else
	computedHash = spoton_crypt::keyedHash
	  (ui.question->text().toUtf8(),
	   ui.answer->text().toUtf8(),
	   hashType,
	   &ok);

      if(!ok)
	error = "keyed hash failure";

      if(!computedHash.isEmpty() && !saltedPassphraseHash.isEmpty() &&
	 spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
	if(error.isEmpty())
	  authenticated = true;

      if(!authenticated)
	return;

      m_locked = !m_locked;
    }

  if(m_locked)
    m_sb.lock->setText(tr("Unlock"));
  else
    m_sb.lock->setText(tr("Lock"));

  QHashIterator<QString, QPointer<spoton_chatwindow> > it
    (m_chatWindows);

  while(it.hasNext())
    {
      it.next();

      if(it.value())
	it.value()->close();
    }

  foreach(QToolButton *toolButton, m_sbWidget->findChildren<QToolButton *> ())
    if(m_sb.lock != toolButton)
      toolButton->setEnabled(!m_locked);

  foreach(QWidget *widget, QApplication::topLevelWidgets())
    {
#if SPOTON_GOLDBUG == 0
      spoton_neighborstatistics *neighborStatistics = qobject_cast
	<spoton_neighborstatistics *> (widget);

      if(neighborStatistics)
	neighborStatistics->close();
#endif

      spoton_pageviewer *pageViewer = qobject_cast<spoton_pageviewer *>
	(widget);

      if(pageViewer)
	pageViewer->deleteLater();
    }

  if(m_addParticipantWindow)
    m_addParticipantWindow->close();

  m_echoKeyShare->close();
  m_encryptFile.close();
  m_logViewer.close();
  m_notificationsWindow->close();
  m_optionsWindow->close();
  m_rosetta.close();
  m_rss->close();
  m_starbeamAnalyzer->close();
  m_statisticsWindow->close();
  m_ui.tab->setCurrentIndex(m_ui.tab->count() - 1);

  /*
  ** Lock everything!
  */

  m_sb.status->setEnabled(!m_locked);
  m_ui.menubar->setEnabled(!m_locked);
  m_ui.tab->setEnabled(!m_locked);

  /*
  ** Unite Buzz windows.
  */

  foreach(QWidget *widget, QApplication::topLevelWidgets())
    if(widget->isWindow())
      {
	QMainWindow *window = qobject_cast<QMainWindow *> (widget);

	if(!window)
	  continue;

	spoton_buzzpage *page = qobject_cast<spoton_buzzpage *>
	  (window->centralWidget());

	if(!page)
	  continue;

	page->unite();
      }
}

void spoton::slotCallParticipantViaForwardSecrecy(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString forwardSecrecyInformation("");
  QString keyType("");
  QString oid("");
  bool temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data(Qt::ItemDataRole(Qt::UserRole + 1)).toString();
	  oid = item->text();
	  temporary = item->data(Qt::UserRole).toBool();
	}

      item = m_ui.participants->item(row, 8); // Forward Secrecy Information

      if(item)
	forwardSecrecyInformation = item->text();
    }

  QList<QByteArray> values;

  if(!spoton_misc::isValidForwardSecrecyMagnet(forwardSecrecyInformation.
					       toLatin1(), values))
    return;
  else if(oid.isEmpty())
    return;
  else if(temporary) // Temporary friend?
    return; // Not allowed!

  /*
  ** Do we have forward secrecy keys?
  */

  slotGenerateGeminiInChat();

  QByteArray message;

  message.append("call_participant_using_forward_secrecy_");
  message.append(keyType);
  message.append("_");
  message.append(oid);
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotCallParticipantViaForwardSecrecy(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotPurgeEphemeralKeys(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QByteArray message("purge_ephemeral_keys\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotPurgeEphemeralKeys(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotPurgeEphemeralKeyPair(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString());

  if(!(type == "email" || type == "chat"))
    return;

  QModelIndexList publicKeyHashes;

  if(type == "chat")
    publicKeyHashes =
      m_ui.participants->selectionModel()->
      selectedRows(3); // public_key_hash
  else
    publicKeyHashes =
      m_ui.emailParticipants->selectionModel()->
      selectedRows(3); // public_key_hash

  if(publicKeyHashes.isEmpty())
    return;

  QByteArray message("purge_ephemeral_key_pair_");

  message.append(publicKeyHashes.value(0).data().toByteArray());
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotPurgeEphemeralKeyPair(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotDisableSynchronousUrlImport(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(!checkBox)
    return;

  QString str("");

  if(checkBox == m_optionsUi.disable_kernel_synchronous_download)
    str = "gui/disable_kernel_synchronous_sqlite_url_download";
  else
    str = "gui/disable_ui_synchronous_sqlite_url_import";

  m_settings[str] = state;

  QSettings settings;

  settings.setValue(str, state);
}

void spoton::slotLaneWidthChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    if(comboBox->property("table") == "listeners")
      db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			 "listeners.db");
    else
      db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			 "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(comboBox->property("table") == "listeners")
	  query.prepare("UPDATE listeners SET "
			"lane_width = ? "
			"WHERE OID = ?");
	else
	  query.prepare("UPDATE neighbors SET "
			"lane_width = ? "
			"WHERE OID = ?");

	query.bindValue(0, comboBox->itemText(index).toInt());
	query.bindValue(1, comboBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

QString spoton::saveCommonUrlCredentials
(const QPair<QByteArray, QByteArray> &keys,
 const QString &cipherType, const QString &hashType,
 spoton_crypt *crypt) const
{
  if(!crypt)
    return tr("Invalid spoton_crypt object. This is a fatal flaw.");

  prepareDatabasesFromUI();

  QString connectionName("");
  QString error("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO remote_key_information "
	   "(cipher_type, encryption_key, hash_key, hash_type) "
	   "VALUES (?, ?, ?, ?)");
	query.bindValue
	  (0,
	   crypt->encryptedThenHashed(cipherType.toLatin1(),
				      &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(keys.first, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed(keys.second, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->
	     encryptedThenHashed(hashType.toLatin1(),
				 &ok).toBase64());

	if(ok)
	  {
	    if(!query.exec())
	      error = tr
		("Database write error. Is urls_key_information.db "
		 "properly defined?");
	  }
	else
	  error = tr("An error occurred with "
		     "spoton_crypt::encryptedThenHashed().");
      }
    else
      error = tr("Unable to access urls_key_information.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return error;
}

void spoton::slotSaveCongestionAlgorithm(const QString &text)
{
  QString str("");

  if(text == "n/a")
    str = "sha224";
  else
    str = text;

  m_settings["kernel/messaging_cache_algorithm"] = str;

  QSettings settings;

  settings.setValue("kernel/messaging_cache_algorithm", str);
}

QByteArray spoton::copiedPublicKeyPairToMagnet(const QByteArray &data) const
{
  QByteArray magnet;
  QList<QByteArray> list(data.mid(1).split('@')); // Remove K.

  magnet.append("magnet:?kt=");
  magnet.append(list.value(0));
  magnet.append("&n=");
  magnet.append(list.value(1));
  magnet.append("&ek=");
  magnet.append(list.value(2));
  magnet.append("&eks=");
  magnet.append(list.value(3));
  magnet.append("&sk=");
  magnet.append(list.value(4));
  magnet.append("&sks=");
  magnet.append(list.value(5));
  return magnet;
}

void spoton::slotBluetoothSecurityChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE listeners SET "
		      "ssl_key_size = ? "
		      "WHERE OID = ?");
	query.bindValue(0, index);
	query.bindValue(1, comboBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotLinkClicked(const QUrl &url)
{
  QString scheme(url.scheme().toLower().trimmed());

  if(!(scheme == "ftp" || scheme == "http" || scheme == "https"))
    return;

  if(!m_settings.value("gui/openChatUrl", false).toBool())
    return;

  QMessageBox mb(this);
  QString str(spoton_misc::urlToEncoded(url).constData());

  if(str.length() > 64)
    str = str.mid(0, 24) + "..." + str.right(24);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").
		    arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to access the URL %1?").arg(str));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QDesktopServices::openUrl(url);
}

void spoton::slotOpenChatUrlChecked(bool state)
{
  m_settings["gui/openChatUrl"] = state;

  QSettings settings;

  settings.setValue("gui/openChatUrl", state);
}

void spoton::slotChatTimestamps(bool state)
{
  m_settings["gui/chatTimestamps"] = state;

  QSettings settings;

  settings.setValue("gui/chatTimestamps", state);
}

void spoton::slotPassphraseChanged(const QString &text)
{
  m_ui.passphrase_strength_indicator->setStyleSheet("");

  if(text.isEmpty())
    {
      m_ui.passphrase_strength_indicator->setVisible(false);
      return;
    }
  else
    m_ui.passphrase_strength_indicator->setVisible(true);

  double maximum = 500.00;
  double result = 0.0;
  spoton_pacify pacify(text.toStdString());

  result = 100.00 * pacify.evaluate() / maximum;
  m_ui.passphrase_strength_indicator->setMaximum(100);
  m_ui.passphrase_strength_indicator->setMinimum(0);
  m_ui.passphrase_strength_indicator->setValue(static_cast<int> (result));

  if(result >= 0.00 && result <= 25.00)
    m_ui.passphrase_strength_indicator->setStyleSheet
      ("QProgressBar::chunk"
       "{"
       "background: red; "
       "border-bottom-right-radius: 0px; "
       "border-bottom-left-radius: 0px; "
       "border: 1px solid black;"
       "}");
  else if(result > 25.00 && result <= 50.00)
    m_ui.passphrase_strength_indicator->setStyleSheet
      ("QProgressBar::chunk"
       "{"
       "background: yellow; "
       "border-bottom-right-radius: 0px; "
       "border-bottom-left-radius: 0px; "
       "border: 1px solid black;"
       "}");
  else if(result > 50.00 && result <= 75.00)
    m_ui.passphrase_strength_indicator->setStyleSheet
      ("QProgressBar::chunk"
       "{"
       "background: orange; "
       "border-bottom-right-radius: 0px; "
       "border-bottom-left-radius: 0px; "
       "border: 1px solid black;"
       "}");
  else
    m_ui.passphrase_strength_indicator->setStyleSheet
      ("QProgressBar::chunk"
       "{"
       "background: green; "
       "border-bottom-right-radius: 0px; "
       "border-bottom-left-radius: 0px; "
       "border: 1px solid black;"
       "}");
}

void spoton::slotShowStatisticsWindow(void)
{
  m_statisticsWindow->showNormal();
  m_statisticsWindow->activateWindow();
  m_statisticsWindow->raise();
  spoton_utilities::centerWidget(m_statisticsWindow, this);
}

void spoton::slotShowNeighborSummaryPanel(bool state)
{
  slotNeighborSelected();
  m_settings["gui/show_neighbor_summary_panel"] = state;
  m_ui.neighborSummary->setVisible(state);

  QSettings settings;

  settings.setValue("gui/show_neighbor_summary_panel", state);
}

void spoton::slotShowRss(void)
{
  m_rss->showNormal();
  m_rss->activateWindow();
  m_rss->raise();
  m_rss->center(this);
}

spoton_crypt *spoton::urlCommonCrypt(void) const
{
  return m_urlCommonCrypt;
}

QSqlDatabase spoton::urlDatabase(void) const
{
  return m_urlDatabase;
}

void spoton::slotMaximumUrlKeywordsChanged(int value)
{
  QSpinBox *spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  if(spinBox == m_optionsUi.maximum_url_keywords_interface)
    {
      QSettings settings;

      m_settings["gui/maximum_url_keywords_import_interface"] = value;
      settings.setValue("gui/maximum_url_keywords_import_interface", value);
    }
  else if(spinBox == m_optionsUi.maximum_url_keywords_kernel)
    {
      QSettings settings;

      m_settings["gui/maximum_url_keywords_import_kernel"] = value;
      settings.setValue("gui/maximum_url_keywords_import_kernel", value);
    }
}

void spoton::slotKernelUrlBatchSizeChanged(int value)
{
  QSettings settings;

  m_settings["gui/kernel_url_batch_size"] = value;
  settings.setValue("gui/kernel_url_batch_size", value);
}

void spoton::prepareDatabasesFromUI(void)
{
  QCursor *cursor = QApplication::overrideCursor();
  bool cursorIsBusy = false;

  if(cursor && (cursor->shape() == Qt::BusyCursor ||
		cursor->shape() == Qt::WaitCursor))
    cursorIsBusy = true;

  if(!cursorIsBusy)
    QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  spoton_misc::prepareDatabases();

  if(!cursorIsBusy)
    QApplication::restoreOverrideCursor();
}

void spoton::slotShowPage(bool state)
{
  QAction *action = qobject_cast<QAction *> (sender());
  QString str("");

  if(action == m_ui.action_Buzz)
    str = "gui/showBuzzPage";
  else if(action == m_ui.action_Listeners)
    str = "gui/showListenersPage";
  else if(action == m_ui.action_Neighbors)
    str = "gui/showNeighborsPage";
  else if(action == m_ui.action_Search)
    str = "gui/showSearchPage";
  else if(action == m_ui.action_StarBeam)
    str = "gui/showStarBeamPage";
  else if(action == m_ui.action_Urls)
    str = "gui/showUrlsPage";

  if(!str.isEmpty())
    {
      m_settings[str] = state;

      QSettings settings;

      settings.setValue(str, state);
      prepareVisiblePages();
    }
}

void spoton::prepareVisiblePages(void)
{
  QMap<QString, QAction *> actions;
  QMap<QString, int> pages;

  actions["buzz"] = m_ui.action_Buzz;
  actions["listeners"] = m_ui.action_Listeners;
  actions["neighbors"] = m_ui.action_Neighbors;
  actions["search"] = m_ui.action_Search;
  actions["starbeam"] = m_ui.action_StarBeam;
  actions["urls"] = m_ui.action_Urls;
  pages["buzz"] = 0;
  pages["chat"] = 1;
  pages["email"] = 2;
  pages["listeners"] = 3;
  pages["neighbors"] = 4;
  pages["search"] = 5;
  pages["settings"] = 6;
  pages["starbeam"] = 7;
  pages["urls"] = 8;
#if SPOTON_GOLDBUG == 1
  pages["x_add_friend"] = 9; // Sorted keys.
  pages["y_about"] = 10; // Sorted keys.
#else
  pages["x_about"] = 9; // Sorted keys.
#endif

  {
    QMapIterator<QString, QAction *> it(actions);

    while(it.hasNext())
      {
	it.next();

	if(!it.value()->isChecked())
	  pages.remove(it.key());
      }
  }

  int count = m_ui.tab->count();

  for(int i = 0; i < count; i++)
    m_ui.tab->removeTab(0);

  {
    QMapIterator<QString, int> it(pages);

    while(it.hasNext())
      {
	it.next();

	QWidget *widget = m_tabWidgets.value(it.value());

	if(!widget)
	  continue;

	QHash<QString, QVariant> hash
	  (m_tabWidgetsProperties.value(it.value()));
	QIcon icon(hash.value("icon").value<QIcon> ());

	m_ui.tab->addTab(widget, icon, hash.value("label").toString());
      }
  }
}

int spoton::tabIndexFromName(const QString &name) const
{
  /*
  ** Returns the index of the page having the given name.
  ** If the page is hidden, a negative one is returned.
  */

  QMapIterator<int, QHash<QString, QVariant> > it(m_tabWidgetsProperties);
  int index = -1;

  while(it.hasNext())
    {
      it.next();

      if(it.value().value("name").toString() == name)
	{
	  index = m_ui.tab->indexOf(m_tabWidgets[it.key()]);
	  break;
	}
    }

  return index;
}

void spoton::slotStarBeamFragmented(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(!checkBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE transmitted SET fragmented = ? "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, state ? 1 : 0);
	query.bindValue(1, checkBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSaveSecondaryStorage(bool state)
{
  m_settings["gui/secondary_storage_congestion_control"] = state;

  QSettings settings;

  settings.setValue("gui/secondary_storage_congestion_control", state);
}

void spoton::slotVacuumDatabases(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  spoton_misc::vacuumAllDatabases();
  QApplication::restoreOverrideCursor();
}

void spoton::slotNeighborWaitForBytesWrittenChanged(int value)
{
  QSpinBox *spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "waitforbyteswritten_msecs = ? "
		      "WHERE OID = ?");
	query.bindValue(0, value);
	query.bindValue(1, spinBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
