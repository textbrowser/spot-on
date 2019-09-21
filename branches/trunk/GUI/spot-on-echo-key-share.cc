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
#include "spot-on-defines.h"
#include "spot-on-echo-key-share.h"
#include "spot-on.h"

spoton_echo_key_share::spoton_echo_key_share(QSslSocket *kernelSocket,
					     spoton *parent):
  QMainWindow(0)
{
  m_kernelSocket = kernelSocket;
  m_parent = parent;
  ui.setupUi(this);
  setWindowTitle
    (tr("%1: Echo Public Key Share").arg(SPOTON_APPLICATION_NAME));
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

  ui.tree->setContextMenuPolicy(Qt::CustomContextMenu);

  QMenu *menu = new QMenu(this);

  menu->addAction(tr("&New Category..."),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->addSeparator();
  menu->addAction(tr("&Generate Specified Community"),
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
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
  menu->addAction(tr("Share &Open Library Public Key Pair"),
		  this,
		  SLOT(slotMenuAction(void)));
#endif
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
  menu->addAction(tr("&Reset Input Widgets"),
		  this,
		  SLOT(slotMenuAction(void)));
  menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
  ui.menu->setMenu(menu);
  connect(ui.menu,
	  SIGNAL(clicked(void)),
	  ui.menu,
	  SLOT(showMenu(void)));
  connect(ui.tree,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
}

spoton_echo_key_share::~spoton_echo_key_share()
{
}

bool spoton_echo_key_share::save(const QPair<QByteArray, QByteArray> &keys,
				 const QString &cipherType,
				 const QString &hashType,
				 const int iterationCount,
				 const QString &name,
				 const QVariant &category_oid)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return false;

  spoton::prepareDatabasesFromUI();

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
		      "share, "
		      "signatures_required) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
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
	    (7, crypt->encryptedThenHashed(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (8, crypt->keyedHash(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(QByteArray("false"),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->encryptedThenHashed(QByteArray("true"),
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

void spoton_echo_key_share::addCategory(void)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString category;
  bool ok = true;

  category = QInputDialog::getText
    (this, tr("%1: New Category").arg(SPOTON_APPLICATION_NAME),
     tr("&Category"), QLineEdit::Normal, "", &ok).trimmed();

  if(!ok)
    return;
  else if(category.isEmpty())
    return;

  spoton::prepareDatabasesFromUI();

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

void spoton_echo_key_share::createDefaultUrlCommunity(void)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  spoton::prepareDatabasesFromUI();

  QString category("Public Communities");
  QString connectionName("");
  QVariant id;
  bool ok = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT OID FROM "
		      "categories WHERE category_hash = ?");
	query.bindValue(0, crypt->keyedHash(category.toUtf8(),
					    &ok).toBase64());

	if(query.exec())
	  if(query.next())
	    id = query.value(0);

	if(!id.isValid())
	  {
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
	      ok = query.exec();

	    if(ok)
	      id = query.lastInsertId();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    return;

  QString name("The Spot-On URL Community");
  bool exists = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 FROM "
		      "echo_key_sharing_secrets WHERE "
		      "category_oid = ? AND "
		      "name_hash = ?)");
	query.bindValue(0, id);
	query.bindValue
	  (1, crypt->keyedHash(name.toUtf8(), &ok).toBase64());

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toBool();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(exists)
    return;

  QPair<QByteArray, QByteArray> keys;
  QString error("");

  keys = spoton_crypt::derivedKeys
    ("aes256",
     "sha512",
     static_cast<unsigned long int> (15000),
     name.mid(0, 16).toUtf8(),
     QByteArray("aes256").toHex() + QByteArray("sha512").toHex() +
     name.mid(16).toUtf8(),
     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
     false,
     error);

  if(!error.isEmpty())
    return;

  save(keys, "aes256", "sha512", 15000, name, id);
}

void spoton_echo_key_share::deleteSelected(void)
{
  QTreeWidgetItem *item = ui.tree->selectedItems().value(0);

  if(!item)
    return;

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"item(s)?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

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
		bool ok = true;

		query.prepare("DELETE FROM echo_key_sharing_secrets "
			      "WHERE category_oid = ? AND name_hash = ?");
		query.bindValue
		  (0, parent->data(0, Qt::UserRole));
		query.bindValue
		  (1, crypt->keyedHash(item->text(3).toUtf8(), &ok).
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

void spoton_echo_key_share::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_echo_key_share::populate(void)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

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
		strings << QString::fromUtf8(bytes.constData(),
					     bytes.length());
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
			"signatures_required, "
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

			if(i == 0 || i == 1 || i == 6)
			  {
			    if(ok)
			      checked << QVariant(bytes).toBool();
			    else
			      {
				if(i == 0 || i == 1)
				  checked << false;
				else
				  checked << true;
			      }

			    strings << "";
			  }
			else
			  {
			    if(ok)
			      {
				if(i == 2)
				  strings << QString::fromUtf8
				    (bytes.constData(), bytes.length());
				else
				  strings << bytes;
			      }
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
		    item->setCheckState
		      (7, checked.value(2) ? Qt::Checked : Qt::Unchecked);
		    item->setToolTip(1, tr("<html>If checked, public key pairs "
					   "originating from the specified "
					   "community will be saved in "
					   "friends_public_keys.db.</html>"));
		    item->setToolTip(7, tr("<html>If checked, public key pairs "
					   "originating from the specified "
					   "community must contain valid "
					   "signatures in order to be saved "
					   "in friends_public_keys.db. Keys "
					   "that are not signed will be "
					   "temporarily accepted.</html>"));
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
  ui.tree->resizeColumnToContents(7);
  ui.tree->sortItems(0, Qt::AscendingOrder);
  ui.tree->expandAll();
  connect(ui.tree,
	  SIGNAL(itemChanged(QTreeWidgetItem *, int)),
	  this,
	  SLOT(slotItemChanged(QTreeWidgetItem *, int)));
  QApplication::restoreOverrideCursor();
}

void spoton_echo_key_share::resetWidgets(void)
{
  ui.cipher->setCurrentIndex(0);
  ui.hash->setCurrentIndex(0);
  ui.iteration_count->setValue(250000);
  ui.name->clear();
}

void spoton_echo_key_share::shareSelected(const QString &keyType)
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value(keyType, 0) : 0;
  spoton_crypt *sCrypt = m_parent ?
    m_parent->crypts().value(keyType + "-signature", 0) : 0;

  if(!eCrypt || !sCrypt)
    {
      showError(tr("Invalid eCrypt and/or sCrypt object(s). This is a "
		   "fatal error."));
      return;
    }
  else if(!m_kernelSocket)
    {
      showError(tr("Invalid m_kernelSocket object."));
      return;
    }

  if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      showError(tr("The interface is not connected to the kernel."));
      return;
    }
  else if(!m_kernelSocket->isEncrypted() &&
	  m_kernelSocket->property("key_size").toInt() > 0)
    {
      showError(tr("The connection to the kernel is not encrypted."));
      return;
    }

  QStringList list;

  for(int i = 0; i < ui.tree->topLevelItemCount(); i++)
    {
      QTreeWidgetItem *item = ui.tree->topLevelItem(i);

      if(!item)
	continue;

      for(int j = 0; j < item->childCount(); j++)
	{
	  QTreeWidgetItem *child = item->child(j);

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
  else if(keyType == "open-library")
    name = settings.value("gui/openLibraryName", "unknown").toByteArray();
  else if(keyType == "poptastic")
    name = m_parent ? m_parent->m_settings.value("gui/poptasticName",
						 "unknown@unknown.org").
      toByteArray() : "unknown@unknown.org";
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

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  while(!list.isEmpty())
    {
      /*
      ** Now retrieve the given community's information.
      */

      QHash<QString, QByteArray> hash
	(spoton_misc::retrieveEchoShareInformation(list.takeFirst(), eCrypt));

      if(!hash.isEmpty())
	{
	  QByteArray message;
	  QByteArray messageCode;
	  QDataStream stream(&message, QIODevice::WriteOnly);
	  bool ok = true;
	  spoton_crypt crypt(hash.value("cipher_type").constData(),
			     hash.value("hash_type").constData(),
			     QByteArray(),
			     hash.value("encryption_key"),
			     hash.value("authentication_key"),
			     0,
			     0,
			     "");

	  stream << QByteArray("0090")
		 << keyType.toLatin1()
		 << name
		 << qCompress(publicKey)
		 << signature
		 << sPublicKey
		 << sSignature
		 << QDateTime::currentDateTime().toUTC().
	            toString("MMddyyyyhhmmss").toLatin1();

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

  QApplication::restoreOverrideCursor();
}

void spoton_echo_key_share::show(QWidget *parent)
{
  populate();
  showNormal();
  activateWindow();
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

void spoton_echo_key_share::showError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  QMessageBox::critical(this, tr("%1: Error").
			arg(SPOTON_APPLICATION_NAME), error.trimmed());
  QApplication::processEvents();
}

void spoton_echo_key_share::slotClose(void)
{
  close();
}

void spoton_echo_key_share::slotItemChanged(QTreeWidgetItem *item,
					    int column)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  if(!(column == 1 || column == 2 || column == 7))
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
	else if(column == 2)
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET share = ? WHERE "
			"OID = ?");
	else
	  query.prepare("UPDATE echo_key_sharing_secrets "
			"SET signatures_required = ? WHERE "
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

      ui.menu->menu()->repaint();
      repaint();
      QApplication::processEvents();

      QPair<QByteArray, QByteArray> keys;
      QString error("");

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      keys = spoton_crypt::derivedKeys
	(ui.cipher->currentText(),
	 ui.hash->currentText(),
	 static_cast<unsigned long int> (ui.iteration_count->value()),
	 name.mid(0, 16).toUtf8(),
	 ui.cipher->currentText().toLatin1().toHex() +
	 ui.hash->currentText().toLatin1().toHex() +
	 name.mid(16).toUtf8(),
	 spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
	 false,
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
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
  else if(index == 8)
    shareSelected("open-library");
  else if(index == 9)
    shareSelected("poptastic");
  else if(index == 10)
    shareSelected("rosetta");
  else if(index == 11)
    shareSelected("url");
  else if(index == 13) // Remove Selected
    deleteSelected();
  else if(index == 15) // Reset Widgets
    resetWidgets();
#else
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
#endif
}

void spoton_echo_key_share::slotShowContextMenu(const QPoint &point)
{
  ui.menu->menu()->exec(ui.tree->mapToGlobal(point));
}
