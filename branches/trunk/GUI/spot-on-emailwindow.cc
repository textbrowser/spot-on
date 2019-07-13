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

#include <QDesktopServices>
#include <QPrintPreviewDialog>
#include <QPrinter>

#include "spot-on-defines.h"
#include "spot-on-emailwindow.h"
#include "spot-on.h"

spoton_emailwindow::spoton_emailwindow
(const QString &message,
 const QString &subject,
 const QString &receiver_sender_hash,
 QWidget *parent):QMainWindow(parent)
{
  m_receiver_sender_hash = receiver_sender_hash;
  m_ui.setupUi(this);
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.emailParticipants->setColumnHidden(1, true); // OID
  m_ui.emailParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.emailParticipants->setColumnHidden(3, true); // public_key_hash
#if defined(Q_OS_WIN)
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
#endif
  m_ui.emailSecrets->setMenu(new QMenu(this));
  m_ui.emailSecrets->setVisible(false);
  m_ui.emailSecrets->menu()->setStyleSheet("QMenu {menu-scrollable: 1;}");
  m_ui.goldbug->setEnabled(false);
  m_ui.outgoingMessage->append(message);
  m_ui.outgoingSubject->setText(subject);

  if(spoton::instance())
    m_ui.sign_this_email->setChecked
      (spoton::instance()->m_settings.
       value("gui/emailSignMessages", true).toBool());

  connect(m_ui.attachment,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotRemoveAttachment(const QUrl &)));
  connect(m_ui.emailSecrets,
	  SIGNAL(clicked(void)),
	  m_ui.emailSecrets,
	  SLOT(showMenu(void)));
  connect(m_ui.emailSecrets->menu(),
	  SIGNAL(aboutToShow(void)),
	  this,
	  SLOT(slotAboutToShowEmailSecretsMenu(void)));
  connect(m_ui.email_fs_gb,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotEmailFsGb(int)));
  connect(m_ui.reloadEmailNames,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPopulateParticipants(void)));
  connect(m_ui.selectAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAttachment(void)));
  connect(m_ui.sendMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMail(void)));

  foreach(QAbstractButton *button,
	  m_ui.emailParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  setWindowTitle(tr("%1: E-Mail").arg(SPOTON_APPLICATION_NAME));
  slotPopulateParticipants();
  slotUpdate();
}

spoton_emailwindow::~spoton_emailwindow()
{
}

void spoton_emailwindow::closeEvent(QCloseEvent *event)
{
  Q_UNUSED(event);
  deleteLater();
}

void spoton_emailwindow::slotAboutToShowEmailSecretsMenu(void)
{
  if(!spoton::instance())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.emailSecrets->menu()->clear();

  QMapIterator<QString, QByteArray> it
    (spoton::instance()->
     SMPWindowStreams(QStringList() << "e-mail" << "poptastic"));

  while(it.hasNext())
    {
      it.next();

      QAction *action = m_ui.emailSecrets->menu()->addAction
	(it.key(),
	 this,
	 SLOT(slotEmailSecretsActionSelected(void)));

      action->setProperty("stream", it.value());
    }

  if(m_ui.emailSecrets->menu()->actions().isEmpty())
    {
      /*
      ** Please do not translate Empty.
      */

      QAction *action = m_ui.emailSecrets->menu()->addAction("Empty");

      action->setEnabled(false);
    }

  QApplication::restoreOverrideCursor();
}

void spoton_emailwindow::slotAddAttachment(void)
{
  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory(QDir::homePath());
  dialog.setFileMode(QFileDialog::ExistingFiles);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select Attachment").arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QStringList list(dialog.selectedFiles());

      std::sort(list.begin(), list.end());

      while(!list.isEmpty())
	{
	  QFileInfo fileInfo(list.takeFirst());

	  m_ui.attachment->append
	    (QString("<a href=\"%1 (%2)\">%1 (%2)</a>").
	     arg(fileInfo.absoluteFilePath()).
	     arg(spoton_misc::prettyFileSize(fileInfo.size())));
	}

      QApplication::restoreOverrideCursor();
    }
}

void spoton_emailwindow::slotEmailFsGb(int index)
{
  if(index == 1)
    {
      m_ui.emailSecrets->setVisible(true);
      m_ui.goldbug->setEnabled(true);
    }
  else
    {
      m_ui.emailSecrets->setVisible(false);
      m_ui.goldbug->clear();
      m_ui.goldbug->setEnabled(false);
    }
}

void spoton_emailwindow::slotEmailSecretsActionSelected(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  m_ui.goldbug->setText(action->property("stream").toString());
}

void spoton_emailwindow::slotNewGlobalName(const QString &text)
{
  Q_UNUSED(text);
  slotPopulateParticipants();
}

void spoton_emailwindow::slotPopulateParticipants(void)
{
  if(!spoton::instance())
    return;

  spoton_crypt *crypt = spoton::instance()->crypts().value("chat", 0);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.emailName->clear();
  m_ui.emailName->addItem
    (QString::fromUtf8(spoton::instance()->
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().constData(),
		       spoton::instance()->
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().length()).trimmed());
  m_ui.emailNameEditable->setText(m_ui.emailName->currentText());

  QList<QHash<QString, QVariant> > list
    (spoton_misc::poptasticSettings("", crypt, 0));

  for(int i = 0; i < list.size(); i++)
    {
      if(i == 0)
	m_ui.emailName->insertSeparator(1);

      m_ui.emailName->addItem(list.at(i).value("in_username").toString());
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	m_ui.emailParticipants->setSortingEnabled(false);
	m_ui.emailParticipants->setRowCount(0);

	QSqlQuery query(db);
	bool ok = true;
	int row = 0;
	int selectedRow = -1;

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "name, "               // 0
		      "OID, "                // 1
		      "neighbor_oid, "       // 2
		      "public_key_hash, "    // 3
		      "key_type, "           // 4
		      "public_key "          // 5
		      "FROM friends_public_keys "
		      "WHERE key_type_hash IN (?, ?)");
	query.addBindValue
	  (crypt->keyedHash(QByteArray("email"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("poptastic"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QString keyType("");
	      QString name("");
	      QString oid(query.value(1).toString());
	      bool ok = true;
	      bool publicKeyContainsPoptastic = false;
	      bool temporary = query.value(2).toLongLong() == -1 ? false : true;

	      keyType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(4).toByteArray()),
		 &ok).constData();

	      if(ok)
		{
		  QByteArray bytes
		    (crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.
							    value(0).
							    toByteArray()),
						 &ok));

		  if(ok)
		    name = QString::fromUtf8
		      (bytes.constData(), bytes.length());
		}

	      if(!ok)
		name = "";

	      if(query.value(5).toByteArray().length() < 1024 * 1024)
		/*
		** Avoid McEliece keys!
		*/

		publicKeyContainsPoptastic = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()), &ok).
		  contains("-poptastic");

	      for(int i = 0; i < query.record().count(); i++)
		{
		  if(i == query.record().count() - 1)
		    /*
		    ** Ignore public_key.
		    */

		    continue;

		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		      row += 1;
		      m_ui.emailParticipants->setRowCount(row);
		    }

		  if(i == 0)
		    {
		      if(name.isEmpty())
			{
			  if(keyType == "email")
			    name = "unknown";
			  else
			    name = "unknown@unknown.org";
			}

		      item = new QTableWidgetItem(name);

		      if(keyType == "email")
			item->setIcon
			  (QIcon(QString(":/%1/key.png").
				 arg(spoton::instance()->m_settings.
				     value("gui/iconSet",
					   "nouve").toString())));
		      else if(keyType == "poptastic")
			{
			  if(publicKeyContainsPoptastic)
			    {
			      item->setBackground
				(QBrush(QColor(255, 255, 224)));
			      item->setData
				(Qt::ItemDataRole(Qt::UserRole + 2),
				 "traditional e-mail");
			    }
			  else
			    {
			      item->setBackground
				(QBrush(QColor(137, 207, 240)));
			      item->setIcon
				(QIcon(QString(":/%1/key.png").
				       arg(spoton::instance()->m_settings.
					   value("gui/iconSet",
						 "nouve").toString())));
			    }
			}
		    }
		  else if(i == 1 || i == 2 || i == 3)
		    item = new QTableWidgetItem(query.value(i).toString());
		  else if(i == 4)
		    {
		      if(keyType == "poptastic" && publicKeyContainsPoptastic)
			item = new QTableWidgetItem("");
		      else
			{
			  QList<QByteArray> list;
			  bool ok = true;

			  list = spoton::instance()->
			    retrieveForwardSecrecyInformation(oid, &ok);

			  if(ok)
			    item = new QTableWidgetItem
			      (spoton_misc::forwardSecrecyMagnetFromList(list).
			       constData());
			  else
			    item = new QTableWidgetItem(tr("error"));
			}
		    }

		  if(i >= 0 && i <= 4)
		    {
		      if(i == 0)
			{
			  if(temporary)
			    item->setToolTip
			      (tr("User %1 is temporary.").arg(item->text()));
			  else
			    item->setToolTip
			      (query.value(3).toString().mid(0, 16) +
			       "..." +
			       query.value(3).toString().right(16));
			}

		      item->setData(Qt::UserRole, temporary);
		      item->setData
			(Qt::ItemDataRole(Qt::UserRole + 1), keyType);
		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.emailParticipants->setItem(row - 1, i, item);

		      if(i == 3 && !m_receiver_sender_hash.isEmpty())
			if(item->text() == m_receiver_sender_hash)
			  selectedRow = row - 1;
		    }

		  if(item)
		    if(!item->tableWidget())
		      {
			spoton_misc::logError
			  ("spoton_emailwindow::slotPopulateParticipants(): "
			   "QTableWidgetItem does not have a parent "
			   "table. Deleting.");
			delete item;
			item = 0;
		      }
		}
	    }


	if(selectedRow != -1)
	  m_ui.emailParticipants->selectRow(selectedRow);

	m_ui.emailParticipants->horizontalHeader()->setStretchLastSection(true);
	m_ui.emailParticipants->setSortingEnabled(true);
	m_ui.emailParticipants->resizeColumnToContents(0);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_emailwindow::slotRemoveAttachment(const QUrl &url)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QStringList list(m_ui.attachment->toPlainText().split('\n'));

  m_ui.attachment->clear();

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str != url.toString())
	m_ui.attachment->append(QString("<a href=\"%1\">%1</a>").arg(str));
    }

  QApplication::restoreOverrideCursor();
}

void spoton_emailwindow::slotSendMail(void)
{
  if(!spoton::instance())
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 *
    spoton::instance()->
    m_settings.value("gui/maximumEmailFileSize", 1024).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("The file email.db has exceeded the specified limit. Please "
	    "remove some entries and/or increase the limit "
	    "via the Permissions section in Options."));
      return;
    }

  QList<QPair<QByteArray, QByteArray> > attachments;

  if(!m_ui.attachment->toPlainText().isEmpty())
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QLocale locale;
      QStringList files(m_ui.attachment->toPlainText().split("\n"));

      while(!files.isEmpty())
	{
	  QString fileName(files.takeFirst());

	  fileName = fileName.mid(0, fileName.lastIndexOf(' '));
	  fileName = fileName.mid(0, fileName.lastIndexOf(' '));

	  QFileInfo fileInfo(fileName);

	  if(!fileInfo.exists() || !fileInfo.isReadable())
	    {
	      QApplication::restoreOverrideCursor();
	      QMessageBox::critical
		(this, tr("%1: Error").
		 arg(SPOTON_APPLICATION_NAME),
		 tr("The attachment %1 cannot be accessed.").
		 arg(fileName));
	      return;
	    }
	  else if(fileInfo.size() >
		  spoton_common::EMAIL_ATTACHMENT_MAXIMUM_SIZE)
	    {
	      QApplication::restoreOverrideCursor();
	      QMessageBox::critical
		(this, tr("%1: Error").
		 arg(SPOTON_APPLICATION_NAME),
		 tr("The attachment %1 is too large. The maximum size "
		    "of an attachment is %2 byte(s).").arg(fileName).
		 arg(locale.toString(spoton_common::
				     EMAIL_ATTACHMENT_MAXIMUM_SIZE)));
	      return;
	    }

	  QByteArray attachment;
	  QFile file(fileName);

	  if(file.open(QIODevice::ReadOnly))
	    attachment = file.readAll();

	  file.close();

	  if(attachment.isEmpty() ||
	     attachment.length() != static_cast<int> (fileInfo.size()))
	    {
	      QApplication::restoreOverrideCursor();
	      QMessageBox::critical
		(this, tr("%1: Error").
		 arg(SPOTON_APPLICATION_NAME),
		 tr("An error occurred while reading the attachment %1.").
		 arg(fileName));
	      return;
	    }

	  attachments << QPair<QByteArray, QByteArray>
	    (attachment, fileInfo.fileName().toUtf8());
	}

      QApplication::restoreOverrideCursor();
    }

  spoton_crypt *crypt = spoton::instance()->crypts().value("email", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  /*
  ** Why would you send an empty message?
  */

  if(!m_ui.emailParticipants->selectionModel()->hasSelection())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Please select at least one participant."));
      m_ui.emailParticipants->setFocus();
      return;
    }
  else if(m_ui.outgoingMessage->toPlainText().isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Please compose an actual letter."));
      m_ui.outgoingMessage->setFocus();
      return;
    }
  else if(m_ui.email_fs_gb->currentIndex() == 1)
    {
      if(m_ui.goldbug->text().size() < 96)
	{
	  QMessageBox::critical
	    (this, tr("%1: Error").
	     arg(SPOTON_APPLICATION_NAME),
	     tr("Please provide a Gold Bug that contains at least ninety-six "
		"characters."));
	  return;
	}
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QModelIndexList list
    (m_ui.emailParticipants->selectionModel()->selectedRows(0)); // Participant
  bool mixed = false;
  bool temporary = false;

  for(int i = 0; i < list.size(); i++)
    {
      if(list.at(i).data(Qt::UserRole).toBool())
	temporary = true;
      else
	{
	  QString keyType
	    (list.at(i).data(Qt::ItemDataRole(Qt::UserRole + 1)).toString());

	  if(m_ui.emailName->currentIndex() == 0)
	    {
	      if(keyType == "poptastic")
		mixed = true;
	    }
	  else
	    {
	      if(keyType != "poptastic")
		mixed = true;
	    }
	}

      if(mixed || temporary)
	break;
    }

  QApplication::restoreOverrideCursor();

  if(temporary)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("At least one of the selected e-mail recipients is temporary. "
	    "Please correct."));
      return;
    }

  if(mixed)
    {
      if(spoton::instance()->m_settings.value("gui/poptasticNameEmail").
	 isNull())
	{
	  QMessageBox::information
	    (this, tr("%1: Information").
	     arg(SPOTON_APPLICATION_NAME),
	     tr("The Poptastic & RetroPhone Settings window will be "
		"displayed. Please prepare at least one Poptastic account."));
	  emit configurePoptastic();
	}

      if(spoton::instance()->
	 m_settings.value("gui/poptasticNameEmail").isNull())
	return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  spoton_misc::prepareDatabases();

  /*
  ** Bundle the love letter and send it to the email.db file. The
  ** kernel shall do the rest.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QList<bool> isTraditionalEmailAccounts;
	QModelIndexList list;
	QStringList forwardSecrecyCredentials;
	QStringList keyTypes;
	QStringList names;
	QStringList oids;
	QStringList publicKeyHashes;

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(4); // Forward Secrecy Information

	while(!list.isEmpty())
	  forwardSecrecyCredentials.append
	    (list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(0); // Participant

	while(!list.isEmpty())
	  {
	    QModelIndex index(list.takeFirst());

	    isTraditionalEmailAccounts.append
	      (index.data(Qt::ItemDataRole(Qt::UserRole + 2)).
	       toString() == "traditional e-mail" ? true : false);
	    keyTypes.append(index.data(Qt::ItemDataRole(Qt::UserRole + 1)).
			    toString());
	    names.append(index.data().toString());
	  }

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(1); // OID

	while(!list.isEmpty())
	  oids.append(list.takeFirst().data().toString());

	list = m_ui.emailParticipants->selectionModel()->
	  selectedRows(3); // public_key_hash

	while(!list.isEmpty())
	  publicKeyHashes.append(list.takeFirst().data().toString());

	while(!forwardSecrecyCredentials.isEmpty() &&
	      !isTraditionalEmailAccounts.isEmpty() &&
	      !keyTypes.isEmpty() &&
	      !names.isEmpty() &&
	      !publicKeyHashes.isEmpty() &&
	      !oids.isEmpty())
	  {
	    QByteArray goldbug;
	    QByteArray name(names.takeFirst().toUtf8());
	    QByteArray mode;
	    QByteArray publicKeyHash(publicKeyHashes.takeFirst().toLatin1());
	    QByteArray subject
	      (m_ui.outgoingSubject->text().toUtf8());
	    QDateTime now(QDateTime::currentDateTime());
	    QSqlQuery query(db);
	    QString keyType(keyTypes.takeFirst());
	    QString oid(oids.takeFirst());
	    bool isTraditionalEmailAccount =
	      isTraditionalEmailAccounts.takeFirst();
	    bool ok = true;

	    if(m_ui.email_fs_gb->currentIndex() == 0 ||
	       m_ui.email_fs_gb->currentIndex() == 3)
	      {
		if(m_ui.email_fs_gb->currentIndex() == 0)
		  mode = "forward-secrecy";
		else
		  mode = "pure-forward-secrecy";

		goldbug = forwardSecrecyCredentials.first().toLatin1();
	      }
	    else if(m_ui.email_fs_gb->currentIndex() == 1)
	      {
		mode = "forward-secrecy";

		QByteArray bytes(m_ui.goldbug->text().toUtf8());
		int size = static_cast<int>
		  (spoton_crypt::cipherKeyLength("aes256"));

		goldbug.append("magnet:?aa=sha512&ak=");
		goldbug.append
		  (bytes.mid(size,
			     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));
		goldbug.append("&ea=aes256");
		goldbug.append("&ek=");
		goldbug.append(bytes.mid(0, size));
		goldbug.append("&xt=urn:forward-secrecy");
	      }
	    else
	      mode = "normal";

	    forwardSecrecyCredentials.removeFirst();

	    {
	      QList<QByteArray> list;

	      if(!spoton_misc::isValidForwardSecrecyMagnet(goldbug, list))
		{
		  goldbug.clear();
		  mode = "normal";
		}
	    }

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, from_account, goldbug, hash, "
			  "message, message_code, mode, "
			  "receiver_sender, receiver_sender_hash, "
			  "sign, signature, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, "
			  "?, ?, ?, ?, ?, ?, ?, ?)");
	    query.addBindValue
	      (crypt->
	       encryptedThenHashed(now.toString(Qt::ISODate).
				   toLatin1(), &ok).toBase64());
	    query.addBindValue(1); // Sent Folder

	    /*
	    ** If the destination account is a Spot-On account, let's
	    ** use the Spot-On e-mail name. Otherwise, we'll use
	    ** the primary Poptastic e-mail account.
	    */

	    if(keyType != "email")
	      {
		if(ok)
		  query.addBindValue
		    (crypt->
		     encryptedThenHashed(spoton::instance()->m_settings.
					 value("gui/poptasticNameEmail").
					 toByteArray(), &ok).toBase64());
	      }
	    else
	      {
		if(ok)
		  query.addBindValue
		    (crypt->encryptedThenHashed(m_ui.emailNameEditable->
						text().toUtf8(), &ok).
		     toBase64());
	      }

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(goldbug, &ok).toBase64());

	    QByteArray message;

	    if(m_ui.richtext->isChecked())
	      {
		if(isTraditionalEmailAccount)
		  message = m_ui.outgoingMessage->toPlainText().toUtf8();
		else
		  message = m_ui.outgoingMessage->toHtml().toUtf8();
	      }
	    else
	      message = m_ui.outgoingMessage->toPlainText().toUtf8();

	    if(ok)
	      query.addBindValue
		(crypt->
		 keyedHash(now.toString(Qt::ISODate).toLatin1() +
			   message + subject, &ok).toBase64());

	    if(ok)
	      query.addBindValue(crypt->
			      encryptedThenHashed(message, &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(mode, &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(name, &ok).toBase64());

	    query.addBindValue(publicKeyHash);

	    if(ok)
	      query.addBindValue
		(crypt->
		 encryptedThenHashed(QByteArray::
				     number(m_ui.sign_this_email->
					    isChecked()), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->
		 encryptedThenHashed(QByteArray("Queued"), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(subject, &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(oid.toLatin1(), &ok).toBase64());

	    if(ok)
	      if(query.exec())
		{
		  QVariant variant(query.lastInsertId());
		  qint64 id = query.lastInsertId().toLongLong();

		  for(int i = 0; i < attachments.size(); i++)
		    {
		      QByteArray attachment(attachments.at(i).first);
		      QByteArray fileName(attachments.at(i).second);

		      if(variant.isValid())
			{
			  QSqlQuery query(db);

			  query.prepare("INSERT INTO folders_attachment "
					"(data, folders_oid, name) "
					"VALUES (?, ?, ?)");
			  query.addBindValue
			    (crypt->encryptedThenHashed(attachment,
							&ok).toBase64());
			  query.addBindValue(id);

			  if(ok)
			    query.addBindValue
			      (crypt->encryptedThenHashed(fileName,
							  &ok).toBase64());

			  if(ok)
			    query.exec();
			}
		    }
		}
	  }

	m_ui.attachment->clear();
	m_ui.emailName->setCurrentIndex(0);
	m_ui.emailParticipants->selectionModel()->clear();
	m_ui.email_fs_gb->setCurrentIndex(2);
	m_ui.goldbug->clear();
	m_ui.outgoingMessage->clear();
	m_ui.outgoingMessage->setCurrentCharFormat(QTextCharFormat());
	m_ui.outgoingSubject->clear();
	m_ui.richtext->setChecked(true);
	m_ui.sign_this_email->setChecked
	  (spoton::instance()->m_settings.
	   value("gui/emailSignMessages", true).toBool());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  m_ui.outgoingSubject->setFocus();
}

void spoton_emailwindow::slotUpdate(void)
{
  if(!spoton::instance())
    return;

  m_ui.emailParticipants->setAlternatingRowColors
    (spoton::instance()->m_settings.
     value("gui/emailAlternatingRowColors", true).toBool());
  m_ui.sign_this_email->setChecked
    (spoton::instance()->m_settings.
     value("gui/emailSignMessages", true).toBool());
}
