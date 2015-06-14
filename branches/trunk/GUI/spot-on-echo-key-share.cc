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
#include <QKeyEvent>
#include <QMessageBox>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-echo-key-share.h"

spoton_echo_key_share::spoton_echo_key_share(QSslSocket *kernelSocket):
  QMainWindow()
{
  m_kernelSocket = kernelSocket;
  ui.setupUi(this);
  setWindowTitle
    (tr("%1: Echo Public Key Share").arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#if QT_VERSION >= 0x050000
  setWindowFlags(windowFlags() & ~Qt::WindowFullscreenButtonHint);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  ui.cipher->addItems(spoton_crypt::cipherTypes());
  ui.hash->addItems(spoton_crypt::hashTypes());

  if(ui.cipher->count() == 0)
    ui.cipher->addItem("n/a");

  if(ui.hash->count() == 0)
    ui.hash->addItem("n/a");

  QMenu *menu = new QMenu(this);

  menu->addAction(tr("&Generate"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
  menu->addAction(tr("&Refresh Table"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
  menu->addAction(tr("Share &Chat Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addAction(tr("Share &E-Mail Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addAction(tr("Share &Poptastic Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addAction(tr("Share &Rosetta Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addAction(tr("Share &URL Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
  menu->addAction(tr("&Remove Selected"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
  menu->addAction(tr("&Reset Widgets"),
		  this,
		  SLOT(slotMenuAction(void)));
  ui.menu->setMenu(menu);
  connect(ui.menu,
	  SIGNAL(clicked(void)),
	  ui.menu,
	  SLOT(showMenu(void)));
}

spoton_echo_key_share::~spoton_echo_key_share()
{
}

void spoton_echo_key_share::slotClose(void)
{
  close();
}

void spoton_echo_key_share::show(QWidget *parent)
{
  populate();
  QMainWindow::show();
  raise();

  if(parent)
    {
      QPoint p(parent->pos());
      int X = 0;
      int Y = 0;

      if(parent->width() >= width())
	X = p.x() + (parent->width() - width()) / 2;
      else
	X = p.x() - (width() - parent->width()) / 2;

      if(parent->height() >= height())
	Y = p.y() + (parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - parent->height()) / 2;

      move(X, Y);
    }
}

void spoton_echo_key_share::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_echo_key_share::event(QEvent *event)
{
  if(event)
    if(event->type() == QEvent::WindowStateChange)
      if(windowState() == Qt::WindowNoState)
	{
	  /*
	  ** Minimizing the window on OS 10.6.8 and Qt 5.x will cause
	  ** the window to become stale once it has resurfaced.
	  */

	  hide();
	  show(0);
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

void spoton_echo_key_share::slotMenuAction(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  int index = ui.menu->menu()->actions().indexOf(action);

  if(index == 0) // Generate
    {
      QString name(ui.name->text().trimmed());

      if(name.length() < 16)
	{
	  showError(tr("Please provide a Community Name that contains "
		       "at least sixteen characters."));
	  return;
	}

      QPair<QByteArray, QByteArray> keys;
      QString error("");

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      keys = spoton_crypt::derivedKeys
	(ui.cipher->currentText(),
	 ui.hash->currentText(),
	 static_cast<unsigned long> (ui.iteration_count->value()),
	 name.mid(0, 16).toLatin1(),
	 ui.cipher->currentText().toLatin1().toHex() +
	 ui.hash->currentText().toLatin1().toHex() +
	 name.mid(16).toLatin1(),
	 spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES,
	 error);
      QApplication::restoreOverrideCursor();

      if(!error.isEmpty())
	{
	  showError
	    (tr("An error (%1) occurred with spoton_crypt::derivedKeys().").
	     arg(error));
	  return;
	}

      if(!save(keys,
	       ui.cipher->currentText(),
	       ui.hash->currentText(),
	       ui.iteration_count->value(),
	       name))
	showError(tr("An error occurred while attempting to save "
		     "the generated keys."));
      else
	{
	  ui.name->clear();
	  populate();
	}
    }
  else if(index == 2) // Refresh Table
    populate();
  else if(index == 4)
    shareSelected("chat");
  else if(index == 5)
    shareSelected("email");
  else if(index == 6)
    shareSelected("poptastic");
  else if(index == 7)
    shareSelected("rosetta");
  else if(index == 8)
    shareSelected("url");
  else if(index == 10) // Remove Selected
    deleteSelected();
  else if(index == 12) // Reset Widgets
    resetWidgets();
}

void spoton_echo_key_share::showError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  QMessageBox::critical(this, tr("%1: Error").
			arg(SPOTON_APPLICATION_NAME), error.trimmed());
}

bool spoton_echo_key_share::save(const QPair<QByteArray, QByteArray> &keys,
				 const QString &cipherType,
				 const QString &hashType,
				 const int iterationCount,
				 const QString &name)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return false;

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT INTO echo_key_sharing_secrets "
		      "(accept, "
		      "authentication_key, "
		      "cipher_type, "
		      "encryption_key, "
		      "hash_type, "
		      "iteration_count, "
		      "name, "
		      "name_hash, "
		      "share) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(keys.second, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->encryptedThenHashed(cipherType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->encryptedThenHashed(keys.first, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->encryptedThenHashed(hashType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed(QByteArray::number(iterationCount),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->encryptedThenHashed(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, crypt->keyedHash(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (8, crypt->encryptedThenHashed(QByteArray("false"),
					   &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

void spoton_echo_key_share::populate(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int row = 0;

	query.setForwardOnly(true);
	ui.table->clearContents();
	ui.table->setRowCount(0);

	if(query.exec("SELECT "
		      "accept, "
		      "share, "
		      "cipher_type, "
		      "hash_type, "
		      "iteration_count, "
		      "name, "
		      "OID FROM echo_key_sharing_secrets"))
	  while(query.next())
	    {
	      ui.table->setRowCount(row + 1);

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;
		  QCheckBox *box = 0;
		  QTableWidgetItem *item = 0;
		  bool ok = true;

		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(i).toByteArray()),
		     &ok);

		  if(i == 0 || i == 1)
		    {
		      box = new QCheckBox();

		      if(bytes == "true")
			box->setChecked(true);
		      else
			box->setChecked(false);

		      box->setProperty
			("oid", query.value(query.record().count() - 1));
		      box->setProperty
			("type", i == 0 ? "accept" : "share");
		      connect(box,
			      SIGNAL(toggled(bool)),
			      this,
			      SLOT(slotEnabled(bool)));
		      ui.table->setCellWidget(row, i, box);
		    }
		  else
		    {
		      if(ok)
			item = new QTableWidgetItem(bytes.constData());
		      else
			item = new QTableWidgetItem(tr("error"));

		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable);
		      ui.table->setItem(row, i, item);
		    }
		}

	      row += 1;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_echo_key_share::deleteSelected(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QModelIndexList list
	  (ui.table->selectionModel()->
	   selectedRows(ui.table->columnCount() - 1));
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	while(!list.isEmpty())
	  {
	    QString name(list.takeFirst().data().toString());

	    query.prepare("DELETE FROM echo_key_sharing_secrets "
			  "WHERE name_hash = ?");
	    query.bindValue
	      (0, crypt->keyedHash(name.toUtf8(), 0).toBase64());
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  populate();
}

void spoton_echo_key_share::resetWidgets(void)
{
  ui.cipher->setCurrentIndex(0);
  ui.hash->setCurrentIndex(0);
  ui.iteration_count->setValue(ui.iteration_count->minimum());
  ui.name->clear();
}

void spoton_echo_key_share::slotEnabled(bool state)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  QCheckBox *box = qobject_cast<QCheckBox *> (sender());

  if(!box)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	if(box->property("type").toString() == "accept")
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET accept = ? WHERE "
			"OID = ?");
	else
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET share = ? WHERE "
			"OID = ?");

	if(state)
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("true"), &ok).
	     toBase64());
	else
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).
	     toBase64());

	query.bindValue(1, box->property("oid"));

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_echo_key_share::shareSelected(const QString &keyType)
{
  spoton_crypt *eCrypt = spoton::instance() ?
    spoton::instance()->crypts().value(keyType, 0) : 0;
  spoton_crypt *sCrypt = spoton::instance() ?
    spoton::instance()->crypts().value(keyType + "-signature", 0) : 0;

  if(!eCrypt || !sCrypt)
    return;
  else if(!m_kernelSocket)
    return;

  if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket->isEncrypted())
    return;

  QStringList list;

  for(int i = 0; i < ui.table->rowCount(); i++)
    {
      QCheckBox *box = qobject_cast<QCheckBox *>
	(ui.table->cellWidget(i, 1));

      if(!box)
	continue;

      if(box->isChecked())
	{
	  QTableWidgetItem *item = ui.table->item
	    (i, ui.table->columnCount() - 1);

	  if(item)
	    list.append(item->text());
	}
    }

  if(list.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = eCrypt->publicKey(&ok);

  if(ok)
    signature = eCrypt->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = sCrypt->publicKey(&ok);

  if(ok)
    sSignature = sCrypt->digitalSignature(sPublicKey, &ok);

  if(!ok)
    return;

  QByteArray name;
  QSettings settings;

  if(keyType == "chat")
    name = settings.value("gui/nodeName", "unknown").toByteArray();
  else if(keyType == "email")
    name = settings.value("gui/emailName", "unknown").toByteArray();
  else if(keyType == "poptastic")
    {
      QHash<QString, QVariant> hash;
      bool ok = true;

      hash = spoton_misc::poptasticSettings(eCrypt, &ok);

      if(ok)
	name = hash["in_username"].toString().trimmed().toUtf8();
    }
  else if(keyType == "rosetta")
    name = settings.value("gui/rosettaName", "unknown").toByteArray();
  else if(keyType == "url")
    name = settings.value("gui/urlName", "unknown").toByteArray();

  if(name.isEmpty())
    {
      if(keyType == "poptastic")
	name = "unknown@unknown.org";
      else
	name = "unknown";
    }

  while(!list.isEmpty())
    {
      /*
      ** Now retrieve the given community's information.
      */

      QHash<QString, QByteArray> hash
	(spoton_misc::retrieveEchoShareInformation(list.takeFirst(),
						   eCrypt));

      if(!hash.isEmpty())
	{
	  QByteArray message;
	  QByteArray messageCode;
	  QDataStream stream(&message, QIODevice::WriteOnly);
	  bool ok = true;
	  spoton_crypt crypt(hash["cipher_type"].constData(),
			     hash["hash_type"].constData(),
			     QByteArray(),
			     hash["encryption_key"],
			     hash["authentication_key"],
			     0,
			     0,
			     QString(""));

	  stream << QByteArray("0090")
		 << keyType.toLatin1()
		 << name
		 << publicKey
		 << signature
		 << sPublicKey
		 << sSignature;

	  if(stream.status() != QDataStream::Ok)
	    ok = false;

	  if(ok)
	    message = crypt.encrypted(message, &ok);

	  if(ok)
	    messageCode = crypt.keyedHash(message, &ok);

	  if(ok)
	    {
	      message = "echokeypair_" + message.toBase64() + "_" +
		messageCode.toBase64() + "\n";

	      if(m_kernelSocket->write(message.constData(),
				       message.length()) != message.length())
		spoton_misc::logError
		  (QString("spoton_echo_key_share::shareSelected():"
			   "write() failure "
			   "for %1:%2.").
		   arg(m_kernelSocket->peerAddress().toString()).
		   arg(m_kernelSocket->peerPort()));
	    }
	}
    }
}
