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

#include <QClipboard>
#include <QDir>
#include <QKeyEvent>
#include <QInputDialog>
#include <QMessageBox>
#include <QSettings>
#include <QSqlQuery>
#include <QStandardPaths>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-rosetta-gpg-import.h"
#include "spot-on-rosetta.h"
#ifdef SPOTON_GPGME_ENABLED
#include "spot-on-utilities.h"
#endif
#include "spot-on.h"

#ifdef SPOTON_GPGME_ENABLED
QPointer<spoton_rosetta> spoton_rosetta::s_rosetta = 0;
#endif

spoton_rosetta::spoton_rosetta(void):QMainWindow()
{
  m_parent = 0;
  ui.setupUi(this);
  setWindowTitle(tr("%1: Rosetta").arg(SPOTON_APPLICATION_NAME));
#ifndef SPOTON_GPGME_ENABLED
  ui.action_Import_GPG_Keys->setEnabled(false);
  ui.action_Import_GPG_Keys->setToolTip
    (tr("The GnuPG Made Easy library is not available."));
  ui.action_Remove_GPG_Keys->setEnabled(false);
  ui.action_Remove_GPG_Keys->setToolTip(ui.action_Import_GPG_Keys->toolTip());
#endif
  ui.copy->setMenu(new QMenu(this));
#ifdef SPOTON_GPGME_ENABLED
  s_rosetta = this;
  ui.copy->menu()->addAction(tr("Copy My &GPG Public Keys"),
			     this,
			     SLOT(slotCopyMyGPGKeys(void)));
#else
  QAction *action = ui.copy->menu()->addAction
    (tr("Copy My &GPG Public Keys"));

  action->setEnabled(false);
  action->setToolTip(ui.action_Import_GPG_Keys->toolTip());
#endif
  ui.copy->menu()->addAction(tr("Copy My &Rosetta Public Keys"),
			     this,
			     SLOT(slotCopyMyRosettaPublicKeys(void)));
  ui.dump->setVisible(false);
  ui.from->setText(tr("Empty"));
  ui.inputDecrypt->setLineWrapColumnOrWidth(80);
  ui.inputDecrypt->setLineWrapMode(QTextEdit::FixedColumnWidth);
  ui.inputDecrypt->setWordWrapMode(QTextOption::WrapAnywhere);
  ui.name->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  ui.newContact->setLineWrapColumnOrWidth(80);
  ui.newContact->setLineWrapMode(QTextEdit::FixedColumnWidth);
  ui.newContact->setWordWrapMode(QTextOption::WrapAnywhere);
  ui.outputEncrypt->setLineWrapColumnOrWidth(80);
  ui.outputEncrypt->setLineWrapMode(QTextEdit::FixedColumnWidth);
  ui.outputEncrypt->setWordWrapMode(QTextOption::WrapAnywhere);
  connect(ui.action_Clear_Clipboard_Buffer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClearClipboardBuffer(void)));
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.action_Copy,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.action_Import_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportGPGKeys(void)));
  connect(ui.action_Paste,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.action_Remove_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveGPGKeys(void)));
  connect(ui.add,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddContact(void)));
  connect(ui.clearContact,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.clearInput,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.clearOutput,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.contacts,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotContactsChanged(int)));
  connect(ui.convertDecrypt,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotConvertDecrypt(void)));
  connect(ui.convertEncrypt,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotConvertEncrypt(void)));
  connect(ui.copy,
	  SIGNAL(clicked(void)),
	  ui.copy,
	  SLOT(showMenu(void)));
  connect(ui.copyDecrypt,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyDecrypted(void)));
  connect(ui.copyEncrypt,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyEncrypted(void)));
  connect(ui.decryptClear,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDecryptClear(void)));
  connect(ui.decryptPaste,
	  SIGNAL(clicked(void)),
	  ui.inputDecrypt,
	  SLOT(clear(void)));
  connect(ui.decryptPaste,
	  SIGNAL(clicked(void)),
	  ui.inputDecrypt,
	  SLOT(paste(void)));
  connect(ui.decryptReset,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDecryptReset(void)));
  connect(ui.decryptSplitter,
	  SIGNAL(splitterMoved(int, int)),
	  this,
	  SLOT(slotSplitterMoved(int, int)));
  connect(ui.deleteContact,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDelete(void)));
  connect(ui.encryptPaste,
	  SIGNAL(clicked(void)),
	  ui.inputEncrypt,
	  SLOT(clear(void)));
  connect(ui.encryptPaste,
	  SIGNAL(clicked(void)),
	  ui.inputEncrypt,
	  SLOT(paste(void)));
  connect(ui.encryptSplitter,
	  SIGNAL(splitterMoved(int, int)),
	  this,
	  SLOT(slotSplitterMoved(int, int)));
  connect(ui.mainHorizontalSplitter,
	  SIGNAL(splitterMoved(int, int)),
	  this,
	  SLOT(slotSplitterMoved(int, int)));
  connect(ui.name,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveName(void)));
  connect(ui.rename,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRename(void)));
  connect(ui.save,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveName(void)));
  slotSetIcons();
  ui.cipher->addItems(spoton_crypt::cipherTypes());
  ui.hash->addItems(spoton_crypt::hashTypes());

  QFont font(ui.newContact->font());

  font.setStyleHint(QFont::Monospace);
  ui.newContact->setFont(font);

  /*
  ** Please do not translate n/a.
  */

  if(ui.cipher->count() == 0)
    ui.cipher->addItem("n/a");

  if(ui.hash->count() == 0)
    ui.hash->addItem("n/a");

  populateContacts();

  QList<QSplitter *> splitters;
  QSettings settings;
  QStringList keys;

  keys << "gui/rosettaDecryptSplitter"
       << "gui/rosettaEncryptSplitter"
       << "gui/rosettaMainHorizontalSplitter";
  splitters << ui.decryptSplitter
	    << ui.encryptSplitter
	    << ui.mainHorizontalSplitter;

  for(int i = 0; i < keys.size(); i++)
    if(settings.contains(keys.at(i)))
      splitters.at(i)->restoreState(settings.value(keys.at(i)).toByteArray());

  slotDecryptClear();
#ifdef Q_OS_MAC
  foreach(QToolButton *toolButton, findChildren<QToolButton *> ())
#if (QT_VERSION < QT_VERSION_CHECK(5, 10, 0))
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 10px;}"
       "QToolButton::menu-button {border: none;}");
#else
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 15px;}"
       "QToolButton::menu-button {border: none; width: 15px;}");
#endif
#endif
}

QByteArray spoton_rosetta::copyMyRosettaPublicKey(void) const
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value("rosetta", 0) : 0;
  spoton_crypt *sCrypt = m_parent ? m_parent->crypts().
    value("rosetta-signature", 0) : 0;

  if(!eCrypt || !sCrypt)
    return QByteArray();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  QSettings settings;
  bool ok = true;

  name = settings.value("gui/rosettaName", "unknown").toByteArray();
  mPublicKey = eCrypt->publicKey(&ok);

  if(ok)
    mSignature = eCrypt->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = sCrypt->publicKey(&ok);

  if(ok)
    sSignature = sCrypt->digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray data("K" +
		      QByteArray("rosetta").toBase64() +
		      "@" +
		      name.toBase64() +
		      "@" +
		      qCompress(mPublicKey).toBase64() +
		      "@" +
		      mSignature.toBase64() +
		      "@" +
		      sPublicKey.toBase64() +
		      "@" +
		      sSignature.toBase64());

      data = spoton_misc::wrap(data);
      QApplication::restoreOverrideCursor();
      return data;
    }
  else
    {
      QApplication::restoreOverrideCursor();
      return QByteArray();
    }
}

QByteArray spoton_rosetta::gpgEncrypt(const QByteArray &receiver,
				      const QByteArray &sender) const
{
#ifdef SPOTON_GPGME_ENABLED
  Q_UNUSED(sender);
  gpgme_check_version(0);

  QByteArray output;
  gpgme_ctx_t ctx = 0;
  gpgme_error_t err = gpgme_new(&ctx);

  if(err == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t ciphertext = 0;
      gpgme_data_t plaintext = 0;

      gpgme_set_armor(ctx, 1);
      err = gpgme_data_new(&ciphertext);

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray data(ui.inputEncrypt->toPlainText().toUtf8());

	  err = gpgme_data_new_from_mem
	    (&plaintext,
	     data.constData(),
	     static_cast<size_t> (data.length()),
	     1);
	}

      if(err == GPG_ERR_NO_ERROR)
	{
	  gpgme_data_t keydata = 0;
	  gpgme_key_t keys[] = {0, 0};

	  err = gpgme_data_new_from_mem
	    // 1 = A private copy.
	    (&keydata,
	     receiver.constData(),
	     static_cast<size_t> (receiver.length()),
	     1);

	  if(err == GPG_ERR_NO_ERROR)
	    err = gpgme_op_keylist_from_data_start(ctx, keydata, 0);

	  if(err == GPG_ERR_NO_ERROR)
	    err = gpgme_op_keylist_next(ctx, &keys[0]);

	  if(err == GPG_ERR_NO_ERROR)
	    {
	      if(ui.sign->isChecked())
		{
		  err = gpgme_set_pinentry_mode
		    (ctx, GPGME_PINENTRY_MODE_LOOPBACK);

		  if(err == GPG_ERR_NO_ERROR)
		    {
		      gpgme_set_passphrase_cb(ctx, &gpgPassphrase, 0);
		      err = gpgme_op_encrypt_sign
			(ctx,
			 keys,
			 GPGME_ENCRYPT_ALWAYS_TRUST,
			 plaintext,
			 ciphertext);
		    }
		}
	      else
		{
		  gpgme_set_passphrase_cb(ctx, 0, 0);
		  err = gpgme_op_encrypt
		    (ctx,
		     keys,
		     GPGME_ENCRYPT_ALWAYS_TRUST,
		     plaintext,
		     ciphertext);
		}
	    }

	  gpgme_data_release(keydata);
	  gpgme_key_unref(keys[0]);
	}

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray bytes(1024, 0);
	  ssize_t rc = 0;

	  gpgme_data_seek(ciphertext, 0, SEEK_SET);

	  while
	    ((rc = gpgme_data_read(ciphertext,
				   bytes.data(),
				   static_cast<size_t> (bytes.length()))) > 0)
	    output.append(bytes.mid(0, static_cast<int> (rc)));
	}

      gpgme_data_release(ciphertext);
      gpgme_data_release(plaintext);
    }

  gpgme_release(ctx);

  if(err != GPG_ERR_NO_ERROR)
    {
      spoton_misc::logError
	(QString("spoton_rosetta::gpgEncrypt(): error (%1) raised.").
	 arg(gpgme_strerror(err)));
      ui.outputEncrypt->setText
	(tr("spoton_rosetta::gpgEncrypt(): error (%1) raised.").
	 arg(gpgme_strerror(err)));
    }

  return output;
#else
  Q_UNUSED(receiver);
  Q_UNUSED(sender);
  return QByteArray();
#endif
}

#ifdef SPOTON_GPGME_ENABLED
gpgme_error_t spoton_rosetta::gpgPassphrase(void *hook,
					    const char *uid_hint,
					    const char *passphrase_info,
					    int prev_was_bad,
					    int fd)
{
  Q_UNUSED(hook);
  Q_UNUSED(passphrase_info);
  Q_UNUSED(prev_was_bad);
  Q_UNUSED(uid_hint);

  QString passphrase("");
  bool ok = true;

  passphrase = QInputDialog::getText
    (s_rosetta,
     tr("%1: GPG Passphrase").arg(SPOTON_APPLICATION_NAME),
     tr("&GPG Passphrase"),
     QLineEdit::Password,
     "",
     &ok);

  if(!ok || passphrase.isEmpty())
    return GPG_ERR_NO_PASSPHRASE;

  gpgme_ssize_t rc = gpgme_io_writen
    (fd,
     passphrase.toUtf8().constData(),
     static_cast<size_t> (passphrase.toUtf8().length()));

  Q_UNUSED(rc);
  rc = gpgme_io_writen(fd, "\n", static_cast<size_t> (1));
  spoton_crypt::memzero(passphrase);
  return GPG_ERR_NO_ERROR;
}
#endif

void spoton_rosetta::keyPressEvent(QKeyEvent *event)
{
  QMainWindow::keyPressEvent(event);
}

void spoton_rosetta::populateContacts(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QMultiMap<QString, QPair<DestinationTypes, QByteArray> > names;
	QSqlQuery query(db);
	bool ok = true;
	spoton_crypt *eCrypt = m_parent ?
	  m_parent->crypts().value("rosetta", 0) : 0;

	ui.contacts->clear();
	query.setForwardOnly(true);
	query.prepare("SELECT name, public_key_hash FROM friends_public_keys "
		      "WHERE key_type_hash = ?");

	if(eCrypt)
	  query.addBindValue
	    (eCrypt->keyedHash(QByteArray("rosetta"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray name;
	      bool ok = true;

	      if(eCrypt)
		name = eCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      else
		ok = false;

	      if(ok)
		{
		  QPair<DestinationTypes, QByteArray> pair
		    (ROSETTA, query.value(1).toByteArray());

		  names.insert(name, pair);
		}
	    }

	query.prepare("SELECT email, public_keys_hash FROM gpg");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray name;
	      bool ok = true;

	      if(eCrypt)
		name = eCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      else
		ok = false;

	      if(ok)
		{
		  QPair<DestinationTypes, QByteArray> pair
		    (GPG, query.value(1).toByteArray());

		  names.insert(name, pair);
		}
	    }

	QMapIterator<QString, QPair<DestinationTypes, QByteArray> > it(names);

	while(it.hasNext())
	  {
	    it.next();

	    QString str(it.key().trimmed());

	    if(str.isEmpty())
	      ui.contacts->addItem("unknown", it.value().second);
	    else
	      ui.contacts->addItem(str, it.value().second);

	    /*
	    ** Record destination type.
	    */

	    ui.contacts->setItemData
	      (ui.contacts->count() - 1,
	       it.value().first,
	       Qt::ItemDataRole(Qt::UserRole + 1));
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ui.contacts->count() == 0)
    {
      ui.contacts->addItem("Empty"); // Please do not translate Empty.
      ui.contacts->setItemData(0, ZZZ, Qt::ItemDataRole(Qt::UserRole + 1));
    }

  QApplication::restoreOverrideCursor();
  slotContactsChanged(0);
}

void spoton_rosetta::resizeEvent(QResizeEvent *event)
{
  if(!isFullScreen())
    {
      QSettings settings;

      settings.setValue("gui/rosettaGeometry", saveGeometry());
    }

  QWidget::resizeEvent(event);
}

void spoton_rosetta::setName(const QString &text)
{
  ui.name->setText(text);
  slotSaveName();
}

void spoton_rosetta::show(spoton *parent)
{
  QSettings settings;

  if(!isVisible())
    if(settings.contains("gui/rosettaGeometry"))
      restoreGeometry(settings.value("gui/rosettaGeometry").toByteArray());

  m_parent = parent;
  showNormal();
  activateWindow();
  raise();

  if(m_parent)
    {
      QPoint p(m_parent->pos());
      int X = 0;
      int Y = 0;

      if(m_parent->width() >= width())
	X = p.x() + (m_parent->width() - width()) / 2;
      else
	X = p.x() - (width() - m_parent->width()) / 2;

      if(m_parent->height() >= height())
	Y = p.y() + (m_parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - m_parent->height()) / 2;

      move(X, Y);
    }

  ui.name->setText
    (QString::fromUtf8(settings.value("gui/rosettaName", "unknown").
		       toByteArray().constData(),
		       settings.value("gui/rosettaName", "unknown").
		       toByteArray().length()).trimmed());
  populateContacts();
}

void spoton_rosetta::slotAddContact(void)
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value("rosetta", 0) : 0;

  if(!eCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

#ifdef SPOTON_GPGME_ENABLED
  {
    QByteArray key(ui.newContact->toPlainText().trimmed().toUtf8());

    if(key.endsWith("-----END PGP PUBLIC KEY BLOCK-----") &&
       key.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
      {
	QByteArray fingerprint1(spoton_crypt::fingerprint(key));
	QByteArray fingerprint2
	  (spoton_crypt::fingerprint(spoton_crypt::publicGPG(eCrypt)));

	if(fingerprint1 == fingerprint2 &&
	   !fingerprint1.isEmpty() &&
	   !fingerprint2.isEmpty())
	  {
	    QMessageBox::critical
	      (this,
	       tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	       tr("Please do not add personal GPG keys."));
	    QApplication::processEvents();
	    return;
	  }

	gpgme_check_version(0);

	gpgme_ctx_t ctx = 0;
	gpgme_error_t err = gpgme_new(&ctx);

	if(err == GPG_ERR_NO_ERROR)
	  {
	    gpgme_data_t keydata = 0;

	    err = gpgme_data_new_from_mem
	      // 1 = A private copy.
	      (&keydata,
	       key.constData(),
	       static_cast<size_t> (key.length()),
	       1);

	    if(err == GPG_ERR_NO_ERROR)
	      err = gpgme_op_import(ctx, keydata);

	    gpgme_data_release(keydata);
	  }

	gpgme_release(ctx);

	if(err != GPG_ERR_NO_ERROR)
	  {
	    QMessageBox::critical
	      (this,
	       tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	       "GPGME error. Cannot add the key block to the keyring.");
	    QApplication::processEvents();
	    return;
	  }

	QString connectionName("");
	QString error("");

	{
	  QSqlDatabase db = spoton_misc::database(connectionName);

	  db.setDatabaseName(spoton_misc::homePath() +
			     QDir::separator() +
			     "friends_public_keys.db");

	  if(db.open())
	    {
	      QByteArray fingerprint(spoton_crypt::fingerprint(key));
	      QSqlQuery query(db);
	      bool ok = true;

	      /*
	      ** GPG public keys are not encrypted in the keyring.
	      */

	      query.exec("CREATE TABLE IF NOT EXISTS gpg ("
			 "email TEXT NOT NULL, "
			 "public_keys TEXT NOT NULL, "
			 "public_keys_hash TEXT NOT NULL PRIMARY KEY)");

	      if(fingerprint.isEmpty())
		{
		  error = tr("GPGME error.");
		  ok = false;
		}

	      query.prepare("INSERT OR REPLACE INTO gpg "
			    "(email, public_keys, public_keys_hash) "
			    "VALUES (?, ?, ?)");

	      if(ok)
		query.addBindValue
		  (eCrypt->encryptedThenHashed(spoton_rosetta_gpg_import::
					       email(key).toUtf8(), &ok).
		   toBase64());

	      if(ok)
		query.addBindValue
		  (eCrypt->encryptedThenHashed(key, &ok).toBase64());

	      if(ok)
		query.addBindValue
		  (eCrypt->keyedHash(fingerprint, &ok).toBase64());

	      if(ok)
		{
		  if(!query.exec())
		    error = tr("A database error occurred.");
		}
	      else if(error.isEmpty())
		error = tr("A cryptographic error occurred.");
	    }
	  else
	    error = tr("Unable to access the database friends_public_keys.db.");

	  db.close();
	}

	QSqlDatabase::removeDatabase(connectionName);

	if(!error.isEmpty())
	  {
	    QMessageBox::critical
	      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
	    QApplication::processEvents();
	  }
	else
	  {
	    populateContacts();
	    ui.newContact->selectAll();
	  }

	return;
      }
  }
#endif

  spoton_crypt *sCrypt = m_parent ? m_parent->crypts().
    value("rosetta-signature", 0) : 0;

  if(!sCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QByteArray key
    (ui.newContact->toPlainText().remove("\n").remove("\r\n").toLatin1());

  if(key.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Empty key(s). Really?"));
      QApplication::processEvents();
      return;
    }

  if(!(key.startsWith("K") || key.startsWith("k")))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid key(s). The provided text "
	    "must start with either the letter K or the letter k."));
      QApplication::processEvents();
      return;
    }

  QList<QByteArray> list(key.mid(1).split('@'));

  if(list.size() != 6)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Irregular data. Expecting 6 entries, received %1.").
	 arg(list.size()));
      QApplication::processEvents();
      return;
    }

  QByteArray keyType(list.value(0));

  keyType = QByteArray::fromBase64(keyType);

  if(keyType != "rosetta")
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid key type. Expecting 'rosetta'."));
      QApplication::processEvents();
      return;
    }

  QByteArray mPublicKey(list.value(2));
  QByteArray mSignature(list.value(3));
  QByteArray myPublicKey;
  QByteArray mySPublicKey;
  bool ok = true;

  mPublicKey = qUncompress(QByteArray::fromBase64(mPublicKey));
  myPublicKey = eCrypt->publicKey(&ok);

  if(!ok)
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Unable to retrieve your %1 "
		    "public key for comparison. Continue?").
		 arg(keyType.constData()));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").
			arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
    }

  mySPublicKey = sCrypt->publicKey(&ok);

  if(!ok)
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Unable to retrieve your %1 signature "
		    "public key for comparison. Continue?").
		 arg(keyType.constData()));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").
			arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
    }

  QByteArray sPublicKey(list.value(4));
  QByteArray sSignature(list.value(5));

  sPublicKey = QByteArray::fromBase64(sPublicKey);
  sSignature = QByteArray::fromBase64(sSignature);

  if((mPublicKey == myPublicKey && !myPublicKey.isEmpty()) ||
     (sPublicKey == mySPublicKey && !mySPublicKey.isEmpty()))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("You're attempting to add your own '%1' keys. "
	    "Please do not do this!").arg(keyType.constData()));
      QApplication::processEvents();
      return;
    }

  mSignature = QByteArray::fromBase64(mSignature);

  QString algorithm(spoton_crypt::publicKeyAlgorithm(mPublicKey).toLower());

  if(!(algorithm.startsWith("mceliece") || algorithm.startsWith("ntru")))
    if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey, mSignature))
      {
	QMessageBox::critical
	  (this, tr("%1: Error").
	   arg(SPOTON_APPLICATION_NAME),
	   tr("Invalid 'rosetta' public key signature."));
	QApplication::processEvents();
	return;
      }

  if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey, sSignature))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid signature public key signature."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QByteArray name(QByteArray::fromBase64(list.value(1)));

	if((ok = spoton_misc::saveFriendshipBundle(keyType,
						   name,
						   mPublicKey,
						   sPublicKey,
						   -1,
						   db,
						   eCrypt)))
	  if((ok = spoton_misc::saveFriendshipBundle(keyType + "-signature",
						     name,
						     sPublicKey,
						     QByteArray(),
						     -1,
						     db,
						     eCrypt)))
	    ui.newContact->selectAll();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("An error occurred while attempting to save the "
	    "friendship bundle."));
      QApplication::processEvents();
    }
  else
    {
      emit participantAdded("rosetta");
      populateContacts();
    }
}

void spoton_rosetta::slotClear(void)
{
  if(sender() == ui.clearContact)
    ui.newContact->clear();
  else if(sender() == ui.clearInput)
    {
      ui.cipher->setCurrentIndex(0);
      ui.desktop->setChecked(false);
      ui.hash->setCurrentIndex(0);
      ui.inputEncrypt->clear();
      ui.sign->setChecked(true);
    }
  else if(sender() == ui.clearOutput)
    ui.outputEncrypt->clear();
}

void spoton_rosetta::slotClearClipboardBuffer(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      menuBar()->repaint();
      repaint();
      QApplication::processEvents();
      clipboard->clear();
      QApplication::restoreOverrideCursor();
    }
}

void spoton_rosetta::slotClose(void)
{
#ifdef SPOTON_GPGME_ENABLED
  if(m_gpgImport)
    m_gpgImport->close();
#endif
  close();
}

void spoton_rosetta::slotContactsChanged(int index)
{
  if(index < 0)
    {
      slotClear();
      ui.convertEncrypt->setEnabled(false);
      ui.deleteContact->setEnabled(false);
      ui.dump->setVisible(false);
      ui.rename->setEnabled(false);
      ui.sign->setChecked(true);
      ui.sign->setEnabled(false);
      return;
    }

  DestinationTypes destinationType = DestinationTypes
    (ui.contacts->itemData(index, Qt::ItemDataRole(Qt::UserRole + 1)).toInt());

  ui.cipher->setCurrentIndex(0);
  ui.cipher->setEnabled(destinationType == ROSETTA);
  ui.convertEncrypt->setEnabled(destinationType != ZZZ);
  ui.deleteContact->setEnabled(destinationType != ZZZ);

  if(destinationType == GPG)
    {
      QByteArray publicKey;
      spoton_crypt *eCrypt = m_parent ?
	m_parent->crypts().value("rosetta", 0) : 0;

      publicKey = spoton_misc::publicKeyFromHash
	(QByteArray::fromBase64(ui.contacts->
				itemData(ui.contacts->
					 currentIndex()).toByteArray()),
	 true,
	 eCrypt);
      ui.dump->setText(spoton_rosetta_gpg_import::dump(publicKey));
      ui.dump->setVisible(!ui.dump->text().isEmpty());
    }
  else
    {
      ui.dump->setText("");
      ui.dump->setVisible(false);
    }

  ui.hash->setCurrentIndex(0);
  ui.hash->setEnabled(destinationType == ROSETTA);
  ui.rename->setEnabled(destinationType != ZZZ);
  ui.sign->setChecked(true);
  ui.sign->setEnabled(destinationType != ZZZ);
}

void spoton_rosetta::slotConvertDecrypt(void)
{
#ifdef SPOTON_GPGME_ENABLED
  {
    QByteArray data(ui.inputDecrypt->toPlainText().trimmed().toUtf8());

    if(data.endsWith("-----END PGP MESSAGE-----") &&
       data.startsWith("-----BEGIN PGP MESSAGE-----"))
      {
	gpgme_check_version(0);

	QColor signatureColor(240, 128, 128); // Light coral!
	QString signedMessage(tr("Invalid signature."));
	gpgme_ctx_t ctx = 0;
	gpgme_error_t err = gpgme_new(&ctx);

	if(err == GPG_ERR_NO_ERROR)
	  {
	    gpgme_data_t ciphertext = 0;
	    gpgme_data_t plaintext = 0;

	    gpgme_set_armor(ctx, 1);
	    err = gpgme_data_new(&plaintext);

	    if(err == GPG_ERR_NO_ERROR)
	      err = gpgme_data_new_from_mem
		(&ciphertext,
		 data.constData(),
		 static_cast<size_t> (data.length()),
		 1);

	    if(err == GPG_ERR_NO_ERROR)
	      {
		err = gpgme_set_pinentry_mode
		  (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
		gpgme_set_passphrase_cb(ctx, &gpgPassphrase, 0);
	      }

	    if(err == GPG_ERR_NO_ERROR)
	      err = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);

	    if(err == GPG_ERR_NO_ERROR)
	      {
		ui.outputDecrypt->clear();

		QByteArray bytes(1024, 0);
		ssize_t rc = 0;

		gpgme_data_seek(plaintext, 0, SEEK_SET);

		while
		  ((rc =
		    gpgme_data_read(plaintext,
				    bytes.data(),
				    static_cast<size_t> (bytes.length()))) > 0)
		  ui.outputDecrypt->append
		    (bytes.mid(0, static_cast<int> (rc)));

		ui.outputDecrypt->selectAll();

		QTextCursor textCursor = ui.outputDecrypt->textCursor();

		textCursor.setPosition(0);
		ui.outputDecrypt->setTextCursor(textCursor);

		gpgme_verify_result_t result = gpgme_op_verify_result(ctx);

		if(result)
		  {
		    gpgme_signature_t signature = result->signatures;

		    if(signature && signature->fpr)
		      {
			gpgme_key_t key = 0;

			if(gpgme_get_key(ctx, signature->fpr, &key, 0) ==
			   GPG_ERR_NO_ERROR)
			  {
			    if(key->uids && key->uids->email)
			      ui.from->setText(key->uids->email);
			    else
			      ui.from->setText(tr("Empty"));
			  }
			else
			  ui.from->setText(tr("Empty"));

			gpgme_key_unref(key);
		      }
		    else
		      ui.from->setText(tr("Empty"));

		    if((signature && (signature->summary &
				      GPGME_SIGSUM_GREEN)) ||
		       (signature && !signature->summary))
		      {
			signatureColor = QColor(144, 238, 144);
			signedMessage = tr("Message was signed.");
		      }
		  }
	      }

	    gpgme_data_release(ciphertext);
	    gpgme_data_release(plaintext);
	  }

	gpgme_release(ctx);

	if(err != GPG_ERR_NO_ERROR)
	  {
	    ui.from->setText(tr("Empty"));
	    ui.outputDecrypt->setText
	      (tr("spoton_rosetta::slotConvertDecrypt(): error (%1) raised.").
	       arg(gpgme_strerror(err)));
	  }

	ui.signedMessage->setStyleSheet
	  (QString("QLabel {background: %1;}").arg(signatureColor.name()));
	ui.signedMessage->setText(signedMessage);
	return;
      }
  }
#endif

  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().
    value("rosetta-signature", 0) : 0;

  if(!eCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray data
    (ui.inputDecrypt->toPlainText().remove("\n").remove("\r\n").toLatin1());
  QByteArray cipherType;
  QByteArray computedHash;
  QByteArray encryptionKey;
  QByteArray hashKey;
  QByteArray hashType;
  QByteArray keyInformation;
  QByteArray messageCode;
  QByteArray name;
  QByteArray publicKeyHash;
  QByteArray signature;
  QColor signatureColor;
  QDataStream stream(&keyInformation, QIODevice::ReadOnly);
  QList<QByteArray> list;
  QScopedPointer<spoton_crypt> crypt;
  QString error("");
  QString signedMessage("");
  bool ok = true;

  if(data.isEmpty())
    goto done_label;

  list = data.split('@');

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  data = list.value(1);
  keyInformation = eCrypt->publicKeyDecrypt(qUncompress(list.value(0)), &ok);

  if(!ok)
    {
      error = tr("The method spoton_crypt::publicKeyDecrypt() failed.");
      goto done_label;
    }

  messageCode = list.value(2);

  if(ok)
    {
      QDataStream stream(&keyInformation, QIODevice::ReadOnly);
      QList<QByteArray> list;

      for(int i = 0; i < 4; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;
	}

      if(list.size() == 4)
	{
	  encryptionKey = list.value(0);
	  hashKey = list.value(1);
	  cipherType = list.value(2);
	  hashType = list.value(3);
	}
      else
	{
	  error = tr("Stream error.");
	  goto done_label;
	}
    }

  if(ok)
    {
      computedHash = spoton_crypt::keyedHash(data, hashKey, hashType, &ok);

      if(!ok)
	{
	  error = tr("The method spoton_crypt::keyedHash() failed.");
	  goto done_label;
	}
    }

  if(ok)
    {
      if(computedHash.isEmpty() || messageCode.isEmpty() ||
	 !spoton_crypt::memcmp(computedHash, messageCode))
	{
	  error = tr("The computed hash does not match the provided hash.");
	  goto done_label;
	}
    }

  crypt.reset(new spoton_crypt(cipherType,
			       "",
			       QByteArray(),
			       encryptionKey,
			       0,
			       0,
			       ""));

  if(ok)
    data = crypt->decrypted(data, &ok);

  if(ok)
    {
      QDataStream stream(&data, QIODevice::ReadOnly);
      QList<QByteArray> list;

      for(int i = 0; i < 4; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;
	}

      if(list.size() == 4)
	{
	  publicKeyHash = list.value(0);
	  name = list.value(1);
	  data = list.value(2);
	  signature = list.value(3);
	}
      else
	{
	  error = tr("Stream error.");
	  ok = false;
	}
    }

  crypt.reset();

  if(ok)
    {
      if(signature.isEmpty())
	{
	  signatureColor = QColor(240, 128, 128); // Light coral!
	  signedMessage = tr("Empty signature.");
	}
      else if(!spoton_misc::isValidSignature(publicKeyHash + name + data,
					     publicKeyHash,
					     signature,
					     eCrypt))
	{
	  signatureColor = QColor(240, 128, 128); // Light coral!
	  signedMessage = tr
	    ("Invalid signature. Perhaps your contacts are not current.");
	}
      else
	{
	  signatureColor = QColor(144, 238, 144);
	  signedMessage = tr("Message was signed.");
	}
    }

  if(!ok)
    {
      if(error.isEmpty())
	error = tr("A serious cryptographic error occurred.");

      ui.outputDecrypt->clear();
    }
  else
    {
      ui.from->setText(QString::fromUtf8(name.constData(), name.length()));
      ui.outputDecrypt->setText
	(QString::fromUtf8(data.constData(), data.length()));

      QTextCursor textCursor = ui.outputDecrypt->textCursor();

      textCursor.setPosition(0);
      ui.outputDecrypt->setTextCursor(textCursor);
      ui.outputDecrypt->selectAll();
      ui.signedMessage->setStyleSheet
	(QString("QLabel {background: %1;}").arg(signatureColor.name()));
      ui.signedMessage->setText(signedMessage);
    }

  done_label:

  if(!error.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    error);
      QApplication::processEvents();
    }
  else
    QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotConvertEncrypt(void)
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value("rosetta", 0) : 0;

  if(!eCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  DestinationTypes destinationType = DestinationTypes
    (ui.contacts->itemData(ui.contacts->currentIndex(),
			   Qt::ItemDataRole(Qt::UserRole + 1)).toInt());

  if(destinationType == GPG)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QByteArray publicKeyHash
	(QByteArray::fromBase64(ui.contacts->
				itemData(ui.contacts->currentIndex()).
				toByteArray()));
      QByteArray receiver
	(spoton_misc::publicKeyFromHash(publicKeyHash, true, eCrypt));
      QByteArray sender;
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT public_keys FROM gpg");

	    if(query.exec() && query.next())
	      sender = eCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), 0);
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      ui.outputEncrypt->setText(gpgEncrypt(receiver, sender));
      ui.outputEncrypt->selectAll();
      toDesktop();
      QApplication::restoreOverrideCursor();
      return;
    }

  spoton_crypt *sCrypt = m_parent ? m_parent->crypts().
    value("rosetta-signature", 0) : 0;

  if(!sCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray data(ui.inputEncrypt->toPlainText().toUtf8());
  QByteArray encryptionKey;
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray messageCode;
  QByteArray myPublicKey;
  QByteArray myPublicKeyHash;
  QByteArray name;
  QByteArray publicKey;
  QByteArray signature;
  QDataStream stream(&keyInformation, QIODevice::WriteOnly);
  QScopedPointer<spoton_crypt> crypt;
  QSettings settings;
  QString error("");
  bool ok = true;
  size_t encryptionKeyLength = 0;

  if(data.isEmpty())
    goto done_label;

  if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      error = tr("Invalid item data. This is a serious flaw.");
      goto done_label;
    }

  if(ui.inputEncrypt->toPlainText().isEmpty())
    {
      error = tr("Please provide an actual message!");
      goto done_label;
    }

  encryptionKeyLength = spoton_crypt::cipherKeyLength
    (ui.cipher->currentText().toLatin1());

  if(encryptionKeyLength == 0)
    {
      error = tr("The method spoton_crypt::cipherKeyLength() failed.");
      goto done_label;
    }

  encryptionKey.resize(static_cast<int> (encryptionKeyLength));
  encryptionKey = spoton_crypt::veryStrongRandomBytes
    (static_cast<size_t> (encryptionKey.length()));
  hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
  hashKey = spoton_crypt::veryStrongRandomBytes
    (static_cast<size_t> (hashKey.length()));
  name = settings.value("gui/rosettaName", "unknown").toByteArray();
  publicKey = spoton_misc::publicKeyFromHash
    (QByteArray::fromBase64(ui.contacts->
			    itemData(ui.contacts->
				     currentIndex()).toByteArray()),
     false,
     eCrypt);
  stream << encryptionKey
	 << hashKey
	 << ui.cipher->currentText().toLatin1()
	 << ui.hash->currentText().toLatin1();

  if(stream.status() != QDataStream::Ok)
    ok = false;

  if(ok)
    keyInformation = spoton_crypt::publicKeyEncrypt
      (keyInformation, qCompress(publicKey), publicKey.mid(0, 25), &ok);

  if(!ok)
    {
      error = tr("The method spoton_crypt::publicKeyEncrypt() failed or "
		 "an error occurred with the QDataStream object.");
      goto done_label;
    }

  crypt.reset(new spoton_crypt(ui.cipher->currentText(),
			       ui.hash->currentText(),
			       QByteArray(),
			       encryptionKey,
			       hashKey,
			       0,
			       0,
			       ""));

  if(ui.sign->isChecked())
    {
      if(ok)
	myPublicKey = eCrypt->publicKey(&ok);

      if(ok)
	myPublicKeyHash = spoton_crypt::preferredHash(myPublicKey);

      if(ok)
	signature = sCrypt->digitalSignature
	  (myPublicKeyHash + name + ui.inputEncrypt->toPlainText().toUtf8(),
	   &ok);
    }

  if(ok)
    {
      QDataStream stream(&data, QIODevice::WriteOnly);
      QSettings settings;

      stream << myPublicKeyHash
	     << name
	     << ui.inputEncrypt->toPlainText().toUtf8()
	     << signature;

      if(stream.status() != QDataStream::Ok)
	ok = false;

      if(ok)
	data = crypt->encrypted(data, &ok);
    }

  if(ok)
    messageCode = crypt->keyedHash(data, &ok);

  if(ok)
    data = spoton_misc::wrap(qCompress(keyInformation).toBase64() +
			     "@" +
			     data.toBase64() +
			     "@" +
			     messageCode.toBase64());

  crypt.reset();

  if(!ok)
    if(error.isEmpty())
      error = tr("A serious cryptographic error occurred.");

  if(ok)
    {
      ui.outputEncrypt->setText(data);
      ui.outputEncrypt->selectAll();
      toDesktop();
    }
  else
    ui.outputEncrypt->clear();

  done_label:

  if(!error.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    error);
      QApplication::processEvents();
    }
  else
    QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotCopyDecrypted(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.outputDecrypt->toPlainText());
}

void spoton_rosetta::slotCopyEncrypted(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.outputEncrypt->toPlainText());
}

void spoton_rosetta::slotCopyMyGPGKeys(void)
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value("rosetta", 0) : 0;

  if(!eCrypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_keys FROM gpg");

	if(query.exec() && query.next())
	  {
	    QByteArray publicKey;

	    publicKey = eCrypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()), 0);

	    QClipboard *clipboard = QApplication::clipboard();

	    if(clipboard)
	      {
		repaint();
		QApplication::processEvents();
		clipboard->setText(publicKey);
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotCopyMyRosettaPublicKeys(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString text(copyMyRosettaPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The rosetta public key is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    {
      repaint();
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      clipboard->setText(text);
      QApplication::restoreOverrideCursor();
    }
}

void spoton_rosetta::slotCopyOrPaste(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QWidget *widget = QApplication::focusWidget();

  if(!widget)
    return;

  QString a("");

  if(action == ui.action_Copy)
    a = "copy";
  else
    a = "paste";

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  if(qobject_cast<QLineEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QLineEdit *> (widget)->copy();
      else
	{
	  qobject_cast<QLineEdit *> (widget)->clear();
	  qobject_cast<QLineEdit *> (widget)->paste();
	}
    }
  else if(qobject_cast<QTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QTextEdit *> (widget)->copy();
      else
	{
	  qobject_cast<QTextEdit *> (widget)->paste();
	  qobject_cast<QTextEdit *> (widget)->paste();
	}
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotDecryptClear(void)
{
  ui.from->setText(tr("Empty"));
  ui.outputDecrypt->clear();

  QColor color(240, 128, 128); // Light coral!

  ui.signedMessage->setStyleSheet
    (QString("QLabel {background: %1;}").arg(color.name()));
  ui.signedMessage->setText(tr("Message was not signed."));
}

void spoton_rosetta::slotDecryptReset(void)
{
  ui.inputDecrypt->clear();
}

void spoton_rosetta::slotDelete(void)
{
  if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid item data. This is a serious flaw."));
      QApplication::processEvents();
      return;
    }

  DestinationTypes destinationType = DestinationTypes
    (ui.contacts->itemData(ui.contacts->currentIndex(),
			   Qt::ItemDataRole(Qt::UserRole + 1)).toInt());
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

  if(destinationType == GPG)
    mb.setText
      (tr("Are you sure that you wish to remove the selected contact? "
	  "The contact will also be removed from the GPG keyring."));
  else
    mb.setText
      (tr("Are you sure that you wish to remove the selected contact?"));

  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  QByteArray publicKeyHash
    (ui.contacts->itemData(ui.contacts->currentIndex()).toByteArray());
  QString connectionName("");
  QString oid
    (QString::number(spoton_misc::oidFromPublicKeyHash(publicKeyHash)));
  bool ok = true;

#ifdef SPOTON_GPGME_ENABLED
  if(destinationType == GPG)
    {
      gpgme_check_version(0);

      gpgme_ctx_t ctx = 0;
      gpgme_error_t err = gpgme_new(&ctx);

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray publicKey;
	  gpgme_data_t keydata = 0;
	  gpgme_key_t key = 0;
	  spoton_crypt *eCrypt = m_parent ?
	    m_parent->crypts().value("rosetta", 0) : 0;

	  publicKey = spoton_misc::publicKeyFromHash
	    (QByteArray::fromBase64(publicKeyHash), true, eCrypt);
	  err = gpgme_data_new_from_mem
	    // 1 = A private copy.
	    (&keydata,
	     publicKey.constData(),
	     static_cast<size_t> (publicKey.length()),
	     1);

	  if(err == GPG_ERR_NO_ERROR)
	    err = gpgme_op_keylist_from_data_start(ctx, keydata, 0);

	  if(err == GPG_ERR_NO_ERROR)
	    err = gpgme_op_keylist_next(ctx, &key);

	  if(err == GPG_ERR_NO_ERROR)
	    err = gpgme_op_delete_ext(ctx, key, GPGME_DELETE_FORCE);

	  gpgme_data_release(keydata);
	  gpgme_key_unref(key);
	}

      gpgme_release(ctx);
    }
#endif

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(destinationType == GPG)
	  query.prepare("DELETE FROM gpg WHERE public_keys_hash = ?");
	else
	  query.prepare
	    ("DELETE FROM friends_public_keys WHERE public_key_hash = ?");

	query.addBindValue(publicKeyHash);
	ok = query.exec();

	if(destinationType == ROSETTA)
	  spoton_misc::purgeSignatureRelationships
	    (db, m_parent ? m_parent->crypts().value("rosetta", 0) : 0);
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("An error occurred while attempting to delete the specified "
	    "participant."));
      QApplication::processEvents();
    }
  else
    {
      emit participantDeleted(oid, "rosetta");
      ui.contacts->removeItem(ui.contacts->currentIndex());

      if(ui.contacts->count() == 0)
	{
	  ui.contacts->addItem("Empty"); // Please do not translate Empty.
	  ui.contacts->setItemData(0, ZZZ, Qt::ItemDataRole(Qt::UserRole + 1));
	}
      else
	sortContacts();

      slotContactsChanged(0);
    }
}

void spoton_rosetta::slotImportGPGKeys(void)
{
#ifdef SPOTON_GPGME_ENABLED
  if(!m_gpgImport)
    {
      m_gpgImport = new spoton_rosetta_gpg_import(m_parent);
      connect(this,
	      SIGNAL(gpgKeysRemoved(void)),
	      m_gpgImport,
	      SLOT(slotGPGKeysRemoved(void)));
    }

  m_gpgImport->showNormal();
  m_gpgImport->activateWindow();
  m_gpgImport->raise();
  spoton_utilities::centerWidget(m_gpgImport, this);
#endif
}

void spoton_rosetta::slotParticipantAdded(const QString &type)
{
  if(type == "rosetta")
    populateContacts();
}

void spoton_rosetta::slotRemoveGPGKeys(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove your GPG keys? "
		"The keys will not be removed from the GPG ring."));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(query.exec("DELETE FROM gpg"))
	  emit gpgKeysRemoved();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rosetta::slotRename(void)
{
  spoton_crypt *eCrypt = m_parent ? m_parent->crypts().value("rosetta", 0) : 0;

  if(!eCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }
  else if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid item data. This is a serious flaw."));
      QApplication::processEvents();
      return;
    }

  QString name("");
  bool ok = true;

  name = QInputDialog::getText
    (this, tr("%1: New Name").
     arg(SPOTON_APPLICATION_NAME), tr("&Name"),
     QLineEdit::Normal, ui.contacts->currentText(), &ok);
  name = name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH);

  if(name.isEmpty() || !ok)
    return;

  DestinationTypes destinationType = DestinationTypes
    (ui.contacts->itemData(ui.contacts->currentIndex(),
			   Qt::ItemDataRole(Qt::UserRole + 1)).toInt());
  QByteArray publicKeyHash
    (ui.contacts->itemData(ui.contacts->currentIndex()).toByteArray());
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(destinationType == GPG)
	  query.prepare("UPDATE gpg SET email = ? WHERE public_keys_hash = ?");
	else
	  query.prepare("UPDATE friends_public_keys "
			"SET name = ?, "
			"name_changed_by_user = 1 "
			"WHERE public_key_hash = ?");

	query.addBindValue
	  (eCrypt->encryptedThenHashed(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue(publicKeyHash);

	if(ok)
	  if((ok = query.exec()))
	    ui.contacts->setItemText(ui.contacts->currentIndex(), name);
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("An error occurred while attempting to rename the specified "
	    "participant."));
      QApplication::processEvents();
    }
  else
    {
      emit participantNameChanged(publicKeyHash, name);
      sortContacts();
    }
}

void spoton_rosetta::slotSaveName(void)
{
  QString str(ui.name->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      ui.name->setText(str);
    }
  else
    ui.name->setText(str.trimmed());

  QSettings settings;

  settings.setValue("gui/rosettaName", str.toUtf8());
  ui.name->selectAll();
}

void spoton_rosetta::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";

  ui.add->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  ui.clearContact->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearInput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearOutput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.copy->setIcon(QIcon(QString(":/%1/copy.png").arg(iconSet)));
  ui.decryptClear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.decryptReset->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.save->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

void spoton_rosetta::slotSplitterMoved(int pos, int index)
{
  Q_UNUSED(index);
  Q_UNUSED(pos);

  QSplitter *splitter = qobject_cast<QSplitter *> (sender());

  if(!splitter)
    return;

  QSettings settings;
  QString key("");

  if(splitter == ui.decryptSplitter)
    key = "gui/rosettaDecryptSplitter";
  else if(splitter == ui.encryptSplitter)
    key = "gui/rosettaEncryptSplitter";
  else
    key = "gui/rosettaMainHorizontalSplitter";

  settings.setValue(key, splitter->saveState());
}

void spoton_rosetta::sortContacts(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QMultiMap<QString, QPair<DestinationTypes, QVariant> > map;

  for(int i = 0; i < ui.contacts->count(); i++)
    {
      QPair<DestinationTypes, QVariant> pair
	(DestinationTypes(ui.contacts->
			  itemData(i, Qt::ItemDataRole(Qt::UserRole + 1)).
			  toInt()),
	 ui.contacts->itemData(i));

      map.insert(ui.contacts->itemText(i), pair);
    }

  ui.contacts->clear();

  QMapIterator<QString, QPair<DestinationTypes, QVariant> > it(map);

  while(it.hasNext())
    {
      it.next();

      QString str(it.key().trimmed());

      if(str.isEmpty())
	ui.contacts->addItem("unknown", it.value().second);
      else
	ui.contacts->addItem(str, it.value().second);

      /*
      ** Record destination type.
      */

      ui.contacts->setItemData
	(ui.contacts->count() - 1,
	 it.value().first,
	 Qt::ItemDataRole(Qt::UserRole + 1));
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::toDesktop(void) const
{
  if(!ui.desktop->isChecked())
    return;

  QFile file;
  QString fileName
    (QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) +
     QDir::separator() +
     "spot_on_" +
     QString::number(QDateTime::currentMSecsSinceEpoch())+
     ".asc");

  file.setFileName(fileName);
  file.open(QIODevice::WriteOnly);
  file.write(ui.outputEncrypt->toPlainText().toUtf8());
}
