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

  menu->addAction(tr("&New Category"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
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

  if(index == 0) // New Category
    addCategory();
  else if(index == 2) // Generate
    {
      QTreeWidgetItem *item = ui.tree->selectedItems().value(0);

      if(!item || item->parent())
	{
	  showError(tr("Please select a parent category."));
	  return;
	}

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
	       name,
	       item->data(0, Qt::UserRole)))
	showError(tr("An error occurred while attempting to save "
		     "the generated keys."));
      else
	{
	  resetWidgets();
	  populate();
	}
    }
  else if(index == 4) // Refresh Table
    populate();
  else if(index == 6)
    shareSelected("chat");
  else if(index == 7)
    shareSelected("email");
  else if(index == 8)
    shareSelected("poptastic");
  else if(index == 9)
    shareSelected("rosetta");
  else if(index == 10)
    shareSelected("url");
  else if(index == 12) // Remove Selected
    deleteSelected();
  else if(index == 14) // Reset Widgets
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
				 const QString &name,
				 const QVariant &category_oid)
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
		      "category_oid, "
		      "cipher_type, "
		      "encryption_key, "
		      "hash_type, "
		      "iteration_count, "
		      "name, "
		      "name_hash, "
		      "share) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(keys.second, &ok).toBase64());

	query.bindValue(2, category_oid);

	if(ok)
	  query.bindValue
	    (3, crypt->encryptedThenHashed(cipherType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->encryptedThenHashed(keys.first, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed(hashType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->encryptedThenHashed(QByteArray::number(iterationCount),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, crypt->encryptedThenHashed(name.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (8, crypt->keyedHash(name.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(QByteArray("false"),
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
  disconnect(ui.tree,
	     SIGNAL(itemChanged(QTreeWidgetItem *, int)),
	     this,
	     SLOT(slotItemChanged(QTreeWidgetItem *, int)));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	ui.tree->clear();

	if(query.exec("SELECT category, OID FROM categories"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QStringList strings;
	      QTreeWidgetItem *parent = 0;
	      bool ok = true;

	      bytes = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		strings << bytes;
	      else
		strings << tr("error");

	      parent = new QTreeWidgetItem(strings);
	      parent->setData(0, Qt::UserRole, query.value(1));
	      ui.tree->addTopLevelItem(parent);

	      QSqlQuery q(db);

	      q.setForwardOnly(true);
	      q.prepare("SELECT "
			"accept, "
			"share, "
			"name, "
			"cipher_type, "
			"hash_type, "
			"iteration_count, "
			"OID FROM echo_key_sharing_secrets "
			"WHERE category_oid = ?");
	      q.bindValue(0, query.value(query.record().count() - 1));

	      if(q.exec())
		while(q.next())
		  {
		    QList<bool> checked;
		    QStringList strings;

		    strings << ""; // Category

		    for(int i = 0; i < q.record().count() - 1; i++)
		      {
			QByteArray bytes;
			bool ok = true;

			bytes = crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(q.value(i).toByteArray()),
			   &ok);

			if(i == 0 || i == 1)
			  {
			    if(ok)
			      checked << QVariant(bytes).toBool();
			    else
			      checked << false;

			    strings << "";
			  }
			else
			  {
			    if(ok)
			      strings << bytes;
			    else
			      strings << tr("error");
			  }
		      }

		    QTreeWidgetItem *item = new QTreeWidgetItem
		      (parent, strings);

		    item->setData
		      (0, Qt::UserRole, q.value(q.record().count() - 1));
		    item->setFlags(Qt::ItemIsEnabled |
				   Qt::ItemIsSelectable |
				   Qt::ItemIsUserCheckable);
		    item->setCheckState
		      (1, checked.value(0) ? Qt::Checked : Qt::Unchecked);
		    item->setCheckState
		      (2, checked.value(1) ? Qt::Checked : Qt::Unchecked);
		    item->setToolTip(1, tr("If checked, public key pairs "
					   "originating from the specified "
					   "community will be saved in "
					   "friends_public_keys.db."));
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  ui.tree->resizeColumnToContents(1);
  ui.tree->resizeColumnToContents(2);
  ui.tree->resizeColumnToContents(4);
  ui.tree->resizeColumnToContents(5);
  ui.tree->resizeColumnToContents(6);
  ui.tree->sortItems(0, Qt::AscendingOrder);
  ui.tree->expandAll();
  connect(ui.tree,
	  SIGNAL(itemChanged(QTreeWidgetItem *, int)),
	  this,
	  SLOT(slotItemChanged(QTreeWidgetItem *, int)));
  QApplication::restoreOverrideCursor();
}

void spoton_echo_key_share::deleteSelected(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  QTreeWidgetItem *item = ui.tree->selectedItems().value(0);

  if(!item)
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

	query.exec("PRAGMA secure_delete = ON");

	if(!item->parent())
	  {
	    query.prepare("DELETE FROM categories "
			  "WHERE OID = ?");
	    query.bindValue(0, item->data(0, Qt::UserRole));
	    query.exec();
	  }
	else
	  {
	    QTreeWidgetItem *parent = item->parent();

	    if(parent)
	      {
		query.prepare("DELETE FROM echo_key_sharing_secrets "
			      "WHERE category_oid = ? AND name_hash = ?");
		query.bindValue
		  (0, parent->data(0, Qt::UserRole));
		query.bindValue
		  (1, crypt->keyedHash(item->text(3).toLatin1(), 0).
		   toBase64());
		query.exec();
	      }
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

void spoton_echo_key_share::slotItemChanged(QTreeWidgetItem *item,
					    int column)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  if(!(column == 1 || column == 2))
    return;
  else if(!item)
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

	if(column == 1)
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET accept = ? WHERE "
			"OID = ?");
	else
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET share = ? WHERE "
			"OID = ?");

	if(item->checkState(column) == Qt::Checked)
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("true"), &ok).
	     toBase64());
	else
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).
	     toBase64());

	query.bindValue(1, item->data(0, Qt::UserRole));

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
  int index = 0;

  while(true)
    {
      QTreeWidgetItem *item = ui.tree->topLevelItem(index);

      if(!item)
	break;
      else
	index += 1;

      for(int i = 0; i < item->childCount(); i++)
	{
	  QTreeWidgetItem *child = item->child(i);

	  if(!child)
	    continue;

	  if(child->checkState(2) == Qt::Checked)
	    list << child->text(3);
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

void spoton_echo_key_share::addCategory(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->crypts().
    value("chat", 0) : 0;

  if(!crypt)
    return;

  QString category;
  bool ok = true;

  category = QInputDialog::getText
    (this, tr("%1: New Category").arg(SPOTON_APPLICATION_NAME),
     tr("&Category"), QLineEdit::Normal, QString(""), &ok).trimmed();

  if(!ok)
    return;
  else if(category.isEmpty())
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

	query.prepare("INSERT INTO categories "
		      "(category, category_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, crypt->encryptedThenHashed(category.toUtf8(),
						      &ok).
			toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash(category.toUtf8(), &ok).
			  toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populate();
}
