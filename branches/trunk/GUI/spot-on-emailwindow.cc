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

#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-emailwindow.h"

spoton_emailwindow::spoton_emailwindow(QWidget *parent):QMainWindow(parent)
{
  m_ui.setupUi(this);
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.emailParticipants->setColumnHidden(1, true); // OID
  m_ui.emailParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.emailParticipants->setColumnHidden(3, true); // public_key_hash
#ifdef Q_OS_WIN32
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
#endif
  connect(m_ui.attachment,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotRemoveAttachment(const QUrl &)));
  connect(m_ui.reloadEmailNames,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPopulateParticipants(void)));
  connect(m_ui.selectAttachment,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAttachment(void)));
  
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

void spoton_emailwindow::slotAddAttachment(void)
{
  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  #ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
  dialog.setDirectory(QDir::homePath());
  dialog.setFileMode(QFileDialog::ExistingFiles);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select Attachment").arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QStringList list(dialog.selectedFiles());

      qSort(list);

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
	      QByteArray publicKey;
	      QString keyType("");
	      QString name("");
	      QString oid(query.value(1).toString());
	      bool ok = true;
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

	      publicKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(5).toByteArray()), &ok);

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
			  if(publicKey.contains("-poptastic"))
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
		      if(keyType == "poptastic" &&
			 publicKey.contains("-poptastic"))
			item = new QTableWidgetItem("");
		      else
			{
			  QList<QByteArray> list;
			  bool ok = true;

			  list = spoton::instance()->
			    retrieveForwardSecrecyInformation(db, oid, &ok);

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

void spoton_emailwindow::slotUpdate(void)
{
  if(!spoton::instance())
    return;

  m_ui.emailParticipants->setAlternatingRowColors
    (spoton::instance()->m_settings.
     value("gui/emailAlternatingRowColors", true).toBool());
}
