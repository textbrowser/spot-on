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
#include <QCompleter>
#include <QDir>
#include <QFileSystemModel>
#include <QInputDialog>
#include <QKeyEvent>
#include <QMessageBox>
#include <QSettings>
#include <QSqlQuery>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QtConcurrent>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-rosetta-gpg-import.h"
#include "spot-on-rosetta.h"
#include "spot-on-utilities.h"
#include "spot-on.h"
#include "ui_spot-on-gpg-passphrase.h"

#ifdef SPOTON_GPGME_ENABLED
QPointer<spoton_rosetta> spoton_rosetta::s_rosetta = nullptr;
#endif

spoton_rosetta::spoton_rosetta(void):QMainWindow()
{
  QDir().mkpath(spoton_misc::homePath() + QDir::separator() + "Rosetta-GPG");
  m_gpgReadMessagesTimer.start(5000);
#ifdef SPOTON_GPGME_ENABLED
  m_prisonBluesTimer.start(spoton_common::PRISON_BLUES_PROCESS_INTERVAL);
#endif
  ui.setupUi(this);
  setWindowTitle(tr("%1: Rosetta").arg(SPOTON_APPLICATION_NAME));
#ifndef SPOTON_GPGME_ENABLED
  ui.action_Import_GPG_Keys->setEnabled(false);
  ui.action_Import_GPG_Keys->setToolTip
    (tr("The GnuPG Made Easy library is not available."));
  ui.action_Remove_GPG_Keys->setEnabled(false);
  ui.action_Remove_GPG_Keys->setToolTip(ui.action_Import_GPG_Keys->toolTip());
  ui.gpg_email_addresses->addItem("Empty"); // Please do not translate Empty.
  ui.gpg_email_addresses->setEnabled(false);
  ui.gpg_email_addresses->setToolTip
    (tr("The GnuPG Made Easy library is not available."));
  ui.publish->setEnabled(false);
  ui.publish->setToolTip(tr("The GnuPG Made Easy library is not available."));
  ui.tabWidget->setTabEnabled(1, false);
#endif
  ui.copy->setMenu(new QMenu(this));
#ifdef SPOTON_GPGME_ENABLED
  s_rosetta = this;
  ui.copy->menu()->addAction(tr("Copy My &GPG Public Keys"),
			     this,
			     SLOT(slotCopyMyGPGKeys(void)));
#else
  auto action = ui.copy->menu()->addAction
    (tr("Copy My &GPG Public Keys (Missing GPGME)"));

  action->setEnabled(false);
  action->setToolTip(ui.action_Import_GPG_Keys->toolTip());
#endif
  ui.attachments_label->setText
    (tr("An attachment larger than %1 bytes will be ignored.").
     arg(QLocale().toString(spoton_common::GPG_ATTACHMENT_MAXIMUM_SIZE)));
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
  ui.tool_bar->addAction(ui.action_Clear_Clipboard_Buffer);
  ui.tool_bar->addAction(ui.action_Copy);
  ui.tool_bar->addAction(ui.action_Import_GPG_Keys);
  ui.tool_bar->addAction(ui.action_New_GPG_Keys);
  ui.tool_bar->addAction(ui.action_Paste);
  ui.tool_bar->addAction(ui.action_Remove_GPG_Keys);
  ui.tool_bar->addAction(ui.action_Remove_Stored_INI_GPG_Passphrase);
  connect(&m_gpgReadMessagesTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGPGPMessagesReadTimer(void)));
  connect(&m_prisonBluesTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPrisonBluesTimeout(void)));
  connect(this,
	  SIGNAL(gpgFileProcessed(void)),
	  this,
	  SLOT(slotGPGFileProcessed(void)));
  connect(this,
	  SIGNAL(processGPGMessage(const QByteArray &)),
	  this,
	  SLOT(slotProcessGPGMessage(const QByteArray &)));
  connect(ui.action_Clear_Clipboard_Buffer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClearClipboardBuffer(void)));
  connect(ui.action_Copy,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.action_Import_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImportGPGKeys(void)));
  connect(ui.action_New_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotNewGPGKeys(void)));
  connect(ui.action_Paste,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.action_Remove_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveGPGKeys(void)));
  connect(ui.action_Remove_Stored_INI_GPG_Passphrase,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveStoredINIGPGPassphrase(void)));
  connect(ui.add,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddContact(void)));
  connect(ui.attach,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAttachForGPG(void)));
  connect(ui.attachments,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotRemoveGPGAttachment(const QUrl &)));
  connect(ui.chatHorizontalSplitter,
	  SIGNAL(splitterMoved(int, int)),
	  this,
	  SLOT(slotSplitterMoved(int, int)));
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
  connect(ui.clear_gpg,
	  SIGNAL(clicked(void)),
	  ui.gpg_messages,
	  SLOT(clear(void)));
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
  connect(ui.gpg,
	  SIGNAL(editingFinished(void)),
	  this,
	  SLOT(slotSaveGPGAttachmentProgram(void)));
  connect(ui.gpg_message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotWriteGPG(void)));
  connect(ui.gpg_send,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotWriteGPG(void)));
  connect(ui.mainHorizontalSplitter,
	  SIGNAL(splitterMoved(int, int)),
	  this,
	  SLOT(slotSplitterMoved(int, int)));
  connect(ui.name,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveName(void)));
  connect(ui.publish,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPublishGPG(void)));
  connect(ui.rename,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRename(void)));
  connect(ui.save,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveName(void)));
  prepareGPGAttachmentsProgramCompleter();
  slotSetIcons();
  ui.cipher->addItems(spoton_crypt::cipherTypes());
  ui.hash->addItems(spoton_crypt::hashTypes());

  auto font(ui.newContact->font());

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

  keys << "gui/rosettaChatHorizontalSplitter"
       << "gui/rosettaDecryptSplitter"
       << "gui/rosettaEncryptSplitter"
       << "gui/rosettaMainHorizontalSplitter";
  splitters << ui.chatHorizontalSplitter
	    << ui.decryptSplitter
	    << ui.encryptSplitter
	    << ui.mainHorizontalSplitter;

  for(int i = 0; i < keys.size(); i++)
    if(settings.contains(keys.at(i)))
      splitters.at(i)->restoreState(settings.value(keys.at(i)).toByteArray());

  slotDecryptClear();
  ui.gpg->setText(settings.value("gui/rosettaGPG", "").toString());

#if defined(Q_OS_MACOS)
  foreach(auto toolButton, findChildren<QToolButton *> ())
#if (QT_VERSION < QT_VERSION_CHECK(5, 10, 0))
    toolButton->setStyleSheet
    ("QToolButton {border: none; padding-right: 10px;}"
       "QToolButton::menu-arrow {image: none;}"
       "QToolButton::menu-button {border: none;}");
#else
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 15px;}"
       "QToolButton::menu-arrow {image: none;}"
       "QToolButton::menu-button {border: none; width: 15px;}");
#endif
#endif
#ifdef Q_OS_MACOS
  spoton_utilities::enableTabDocumentMode(this);
#endif
}

spoton_rosetta::~spoton_rosetta()
{
  m_gpgReadMessagesTimer.stop();
  m_prisonBluesTimer.stop();
  m_readPrisonBluesFuture.cancel();
  m_readPrisonBluesFuture.waitForFinished();
}

QByteArray spoton_rosetta::copyMyRosettaPublicKey(void) const
{
  auto eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;
  auto sCrypt = m_parent ? m_parent->crypts().
    value("rosetta-signature", nullptr) : nullptr;

  if(!eCrypt || !sCrypt)
    return QByteArray();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  auto ok = true;

  name = QSettings().value("gui/rosettaName", "unknown").toByteArray();
  mPublicKey = eCrypt->publicKey(&ok);

  if(ok)
    mSignature = eCrypt->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = sCrypt->publicKey(&ok);

  if(ok)
    sSignature = sCrypt->digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      auto data("K" +
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

QByteArray spoton_rosetta::gpgEncrypt
(bool &ok,
 const QByteArray &message,
 const QByteArray &receiver,
 const QByteArray &sender,
 const bool sign) const
{
#ifdef SPOTON_GPGME_ENABLED
  Q_UNUSED(sender);
  gpgme_check_version(nullptr);
  ok = false;

  QByteArray output;
  gpgme_ctx_t ctx = nullptr;
  auto err = gpgme_new(&ctx);

  if(err == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t ciphertext = nullptr;
      gpgme_data_t plaintext = nullptr;

      gpgme_set_armor(ctx, 1);
      err = gpgme_data_new(&ciphertext);

      if(err == GPG_ERR_NO_ERROR)
	err = gpgme_data_new_from_mem
	  (&plaintext,
	   message.constData(),
	   static_cast<size_t> (message.length()),
	   1);

      if(err == GPG_ERR_NO_ERROR)
	{
	  gpgme_data_t keydata = nullptr;
	  gpgme_key_t keys[] = {nullptr, nullptr};

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
	      auto const flags = static_cast<gpgme_encrypt_flags_t>
		(GPGME_ENCRYPT_ALWAYS_TRUST |
		 GPGME_ENCRYPT_NO_COMPRESS |
		 GPGME_ENCRYPT_THROW_KEYIDS);

	      if(sign)
		{
		  err = gpgme_set_pinentry_mode
		    (ctx, GPGME_PINENTRY_MODE_LOOPBACK);

		  if(err == GPG_ERR_NO_ERROR)
		    {
		      gpgme_set_passphrase_cb(ctx, &gpgPassphrase, nullptr);
		      err = gpgme_op_encrypt_sign
			(ctx, keys, flags, plaintext, ciphertext);
		    }
		}
	      else
		{
		  gpgme_set_passphrase_cb(ctx, nullptr, nullptr);
		  err = gpgme_op_encrypt
		    (ctx, keys, flags, plaintext, ciphertext);
		}
	    }

	  gpgme_data_release(keydata);
	  gpgme_key_unref(keys[0]);
	}

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray bytes(4096, 0);
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
      output = tr("spoton_rosetta::gpgEncrypt(): error (%1) raised.").
	arg(gpgme_strerror(err)).toUtf8();
      spoton_misc::logError
	(QString("spoton_rosetta::gpgEncrypt(): error (%1) raised.").
	 arg(gpgme_strerror(err)));
    }
  else
    ok = true;

  return output;
#else
  Q_UNUSED(message);
  Q_UNUSED(receiver);
  Q_UNUSED(sender);
  Q_UNUSED(sign);
  return QByteArray();
#endif
}

QMap<QString, QByteArray> spoton_rosetta::gpgEmailAddresses(void) const
{
  QMap<QString, QByteArray> map;
  auto crypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!crypt)
    return map;

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_keys FROM gpg"))
	  while(query.next())
	    {
	      QString email("");
	      auto publicKey
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      auto ok = true;

	      publicKey = crypt->decryptedAfterAuthenticated(publicKey, &ok);

	      if(!(email =
		   spoton_rosetta_gpg_import::email(publicKey)).isEmpty())
		map[email] = publicKey;

	      spoton_crypt::memzero(publicKey);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return map;
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
  Q_UNUSED(uid_hint);

  if(!s_rosetta || !s_rosetta->m_parent)
    return GPG_ERR_CANCELED;

  auto crypt = s_rosetta->m_parent->crypts().value("chat", nullptr);

  if(!crypt)
    return GPG_ERR_CANCELED;

  auto passphrase(QSettings().value("gui/gpgPassphrase").toByteArray());

  passphrase = crypt->decryptedAfterAuthenticated(passphrase, nullptr);

  if(passphrase.isEmpty() || prev_was_bad)
    {
      QDialog dialog(s_rosetta);
      Ui_spoton_gpg_passphrase ui;

      ui.setupUi(&dialog);

      if(dialog.exec() != QDialog::Accepted)
	{
	  QApplication::processEvents();
	  return GPG_ERR_CANCELED;
	}

      passphrase = ui.passphrase->text().toUtf8();

      if(ui.retain->isChecked())
	QSettings().setValue
	  ("gui/gpgPassphrase",
	   crypt->encryptedThenHashed(passphrase, nullptr));
    }

  Q_UNUSED
    (gpgme_io_writen(fd,
		     passphrase.constData(),
		     static_cast<size_t> (passphrase.length())));
  Q_UNUSED(gpgme_io_writen(fd, "\n", static_cast<size_t> (1)));
  spoton_crypt::memzero(passphrase);
  return GPG_ERR_NO_ERROR;
}
#endif

void spoton_rosetta::keyPressEvent(QKeyEvent *event)
{
  QMainWindow::keyPressEvent(event);
}

void spoton_rosetta::launchPrisonBluesProcessesIfNecessary(void)
{
#ifdef SPOTON_GPGME_ENABLED
  if(m_prisonBluesTimer.remainingTime() >= 5500)
    prisonBluesProcess();
#endif
}

void spoton_rosetta::populateContacts(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QMultiMap<QString, QPair<DestinationTypes, QByteArray> > names;
	QSqlQuery query(db);
	auto eCrypt = m_parent ?
	  m_parent->crypts().value("rosetta", nullptr) : nullptr;
	auto ok = true;

	ui.contacts->clear();
	query.setForwardOnly(true);
	query.prepare
	  ("SELECT name, public_key_hash FROM friends_public_keys "
	   "WHERE key_type_hash = ?");

	if(eCrypt)
	  query.addBindValue
	    (eCrypt->keyedHash(QByteArray("rosetta"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray name;
	      auto ok = true;

	      if(eCrypt)
		name = eCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      else
		ok = false;

	      if(ok)
		{
		  QPair<DestinationTypes, QByteArray> pair
		    (DestinationTypes::ROSETTA, query.value(1).toByteArray());

		  names.insert(name, pair);
		}
	    }

	QMap<QString, QString> fingerprints;
	QMap<QString, QString> gpgInformation;

	query.prepare("SELECT email, public_keys, public_keys_hash FROM gpg");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray name;
	      auto ok = true;

	      if(eCrypt)
		name = eCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      else
		ok = false;

	      if(ok)
		{
		  QPair<DestinationTypes, QByteArray> pair
		    (DestinationTypes::GPG, query.value(2).toByteArray());
		  auto publicKey
		    (QByteArray::fromBase64(query.value(1).toByteArray()));

		  publicKey = eCrypt->decryptedAfterAuthenticated
		    (publicKey, nullptr);
		  fingerprints.insert
		    (name, spoton_crypt::fingerprint(publicKey));
		  gpgInformation.insert
		    (name, spoton_crypt::gpgInformation(publicKey));
		  names.insert(name, pair);
		}
	    }

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	QMultiMapIterator<QString, QPair<DestinationTypes, QByteArray> >
	  it(names);
#else
	QMapIterator<QString, QPair<DestinationTypes, QByteArray> > it(names);
#endif
	int i = 0;

	ui.gpg_participants->setRowCount(names.size());

	while(it.hasNext())
	  {
	    it.next();

	    auto const str(it.key().trimmed());

	    if(str.isEmpty())
	      ui.contacts->addItem("unknown", it.value().second);
	    else
	      ui.contacts->addItem(str, it.value().second);

	    /*
	    ** Record destination type.
	    */

	    ui.contacts->setItemData
	      (ui.contacts->count() - 1,
	       static_cast<int> (it.value().first),
	       Qt::ItemDataRole(Qt::UserRole + 1));

	    auto item = new QTableWidgetItem(ui.contacts->itemText(i));

	    item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	    ui.gpg_participants->setItem(i, 0, item);
	    item = new QTableWidgetItem(fingerprints.value(str).trimmed());
	    item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	    item->setToolTip(item->text());
	    ui.gpg_participants->setItem(i, 1, item);
	    item = new QTableWidgetItem(it.value().second.constData());
	    item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	    item->setToolTip(item->text());
	    ui.gpg_participants->setItem(i, 2, item);
	    item = new QTableWidgetItem
	      (gpgInformation.value(str).simplified().trimmed());
	    item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	    item->setToolTip(item->text());
	    ui.gpg_participants->setItem(i, 3, item);
	    i += 1;
	  }

	ui.gpg_participants->resizeColumnsToContents();
	ui.gpg_participants->scrollToTop();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ui.contacts->count() == 0)
    {
      ui.contacts->addItem("Empty"); // Please do not translate Empty.
      ui.contacts->setItemData
	(0,
	 static_cast<int> (DestinationTypes::ZZZ),
	 Qt::ItemDataRole(Qt::UserRole + 1));
    }

  populateGPGEmailAddresses();
  QApplication::restoreOverrideCursor();
  slotContactsChanged(0);
}

void spoton_rosetta::populateGPGEmailAddresses(void)
{
  m_gpgFingerprints.clear();
  ui.gpg_address->clear();
  ui.gpg_email_addresses->clear();

  QMapIterator<QString, QByteArray> it(gpgEmailAddresses());

  while(it.hasNext())
    {
      it.next();
      m_gpgFingerprints.append(spoton_crypt::fingerprint(it.value()));
      ui.gpg_address->addItem(it.key(), it.value());
      ui.gpg_email_addresses->addItem(it.key(), it.value());
    }

  if(ui.gpg_address->count() > 0)
    ui.gpg_address->setCurrentIndex(0);
  else
    ui.gpg_address->addItem("Empty"); // Please do not translate Empty.

  if(ui.gpg_email_addresses->count() > 0)
    ui.gpg_email_addresses->setCurrentIndex(0);
  else
    ui.gpg_email_addresses->addItem("Empty"); // Please do not translate Empty.
}

void spoton_rosetta::prepareGPGAttachmentsProgramCompleter(void)
{
  if(ui.gpg->completer())
    return;

  auto completer = new QCompleter(this);
  auto model = new QFileSystemModel(this);

  completer->setCaseSensitivity(Qt::CaseInsensitive);
  completer->setCompletionRole(QFileSystemModel::FileNameRole);
  completer->setFilterMode(Qt::MatchContains);
  completer->setModel(model);
  model->setRootPath(QDir::rootPath());
  ui.gpg->setCompleter(completer);
}

void spoton_rosetta::prisonBluesProcess(void)
{
#ifdef SPOTON_GPGME_ENABLED
  if(m_parent == nullptr)
    showMessage
      (tr("Invalid parent object. Cannot launch Prison Blues process(es)."),
       5000);
  else
    m_parent->launchPrisonBluesProcesses(statusBar());
#endif
}

void spoton_rosetta::publishAttachments
(const QString &destination,
 const QString &participant,
 const QStringList &attachments)
{
  if(attachments.isEmpty() || destination.isEmpty() || participant.isEmpty())
    return;

  QFileInfo const fileInfo
    (QSettings().value("gui/rosettaGPG").toString().trimmed());

  if(!fileInfo.isExecutable())
    return;

  auto crypt = m_parent->crypts().value("chat", nullptr);

  if(!crypt)
    return;

  auto passphrase(QSettings().value("gui/gpgPassphrase").toByteArray());

  passphrase = crypt->decryptedAfterAuthenticated(passphrase, nullptr);

  for(int i = 0; i < attachments.size(); i++)
    {
      auto attachment(attachments.at(i));

      attachment = attachment.mid(0, attachment.lastIndexOf(' '));
      attachment = attachment.mid(0, attachment.lastIndexOf(' '));

      if(QFileInfo(attachment).isReadable() == false ||
	 QFileInfo(attachment).size() >
	 spoton_common::GPG_ATTACHMENT_MAXIMUM_SIZE)
	continue;

      QTemporaryFile file
	(destination + QDir::separator() + "PrisonBluesXXXXXXXXXX.gpg");

      if(!file.open())
	continue;

      QStringList parameters;

      parameters << "--armor"
		 << "--batch"
		 << "--encrypt"
		 << "--output"
		 << file.fileName()
		 << "--passphrase"
		 << passphrase.constData()
		 << "--pinentry-mode"
		 << "loopback"
		 << "--recipient"
		 << participant
		 << "--sign"
		 << "--trust-model"
		 << "always"
		 << attachment;
      QProcess::startDetached
	(fileInfo.absoluteFilePath(), parameters, spoton_misc::homePath());
    }
}

void spoton_rosetta::readPrisonBlues
(const QList<QFileInfo> &directories,
 const QString &gpgProgram,
 const QVector<QByteArray> &vector)
{
  for(int i = 0; i < directories.size(); i++)
    {
      if(m_readPrisonBluesFuture.isCanceled())
	return;

      QVectorIterator<QByteArray> it(vector);

      while(it.hasNext() && m_readPrisonBluesFuture.isCanceled() == false)
	{
	  QDir const dir
	    (directories[i].absoluteFilePath() +
	     QDir::separator() +
	     it.next());

	  if(dir.isReadable())
	    {
	      foreach(auto const &entry,
		      dir.entryInfoList(QDir::Files, QDir::Time))
		{
		  if(m_readPrisonBluesFuture.isCanceled())
		    return;

		  if(entry.suffix().toLower() == "gpg")
		    {
		      if(QFileInfo(gpgProgram).isExecutable())
			{
			  QProcess process;

			  process.setArguments
			    (QStringList() << "--batch"
					   << "--decrypt"
			                   << "--trust-model"
			                   << "always"
			                   << "--use-embedded-filename"
			                   << "--yes"
			                   << entry.absoluteFilePath());
			  process.setProgram(gpgProgram);
			  process.setWorkingDirectory
			    (spoton_misc::homePath() +
			     QDir::separator() +
			     "Rosetta-GPG");
			  process.start();
			  process.waitForFinished();

			  if(process.exitCode() == 0)
			    emit gpgFileProcessed();
			}

		      QFile::remove(entry.absoluteFilePath());
		      continue;
		    }

		  QFile file(entry.absoluteFilePath());

		  if(file.open(QIODevice::ReadOnly))
		    {
		      auto const bytes(file.readAll().trimmed());

		      emit processGPGMessage(bytes);

		      if(bytes.startsWith("-----BEGIN PGP MESSAGE-----"))
			file.remove();
		    }
		}
	    }
	}
    }
}

void spoton_rosetta::resizeEvent(QResizeEvent *event)
{
  QWidget::resizeEvent(event);
}

void spoton_rosetta::saveGPGMessage(const QMap<GPGMessage, QVariant> &map)
{
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "gpg.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS gpg_messages ("
		   "destination TEXT NOT NULL, "
		   "insert_date TEXT NOT NULL, "
		   "message TEXT NOT NULL PRIMARY KEY, "
		   "origin TEXT NOT NULL, "
		   "size TEXT NOT NULL)");
	query.prepare
	  ("INSERT INTO gpg_messages "
	   "(destination, insert_date, message, origin, size) "
	   "VALUES (?, ?, ?, ?, ?)");
	query.addBindValue
	  (map.value(GPGMessage::Destination).toString().trimmed());
	query.addBindValue
	  (QDateTime::currentDateTime().toString(Qt::ISODate));
	query.addBindValue
	  (map.value(GPGMessage::Message).toString().trimmed());
	query.addBindValue
	  (map.value(GPGMessage::Origin).toString().trimmed());
	query.addBindValue
	  (map.value(GPGMessage::Message).toString().trimmed().length());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rosetta::setName(const QString &text)
{
  ui.name->setText(text);
  ui.name->setCursorPosition(0);
  slotSaveName();
}

void spoton_rosetta::setParent(spoton *parent)
{
  m_parent = parent;
  populateContacts();
  ui.name->setText
    (QString::fromUtf8(QSettings().value("gui/rosettaName", "unknown").
		       toByteArray().constData(),
		       QSettings().value("gui/rosettaName", "unknown").
		       toByteArray().length()).trimmed());
  ui.name->setCursorPosition(0);
}

void spoton_rosetta::show(spoton *parent)
{
  setParent(parent);
}

void spoton_rosetta::showInformationMessage(const QString &m)
{
  if(m.trimmed().isEmpty())
    return;

  QString message("");
  auto const now(QDateTime::currentDateTime());

  message.append
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  message.append(QString("<i>%1</i>").arg(m.trimmed()));
  ui.gpg_messages->append(message);
  ui.gpg_messages->verticalScrollBar()->setValue
    (ui.gpg_messages->verticalScrollBar()->maximum());
}

void spoton_rosetta::showMessage
(const QString &message, const int milliseconds)
{
  if(message.trimmed().isEmpty())
    return;

  if(statusBar())
    statusBar()->showMessage
      (message.trimmed(), qBound(1000, milliseconds, 25000));
  else
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 message.trimmed());
      QApplication::processEvents();
    }
}

void spoton_rosetta::slotAddContact(void)
{
  spoton_crypt *eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!eCrypt)
    {
      showMessage
	(tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
      return;
    }

#ifdef SPOTON_GPGME_ENABLED
  {
    auto const key(ui.newContact->toPlainText().trimmed().toUtf8());

    if(key.endsWith("-----END PGP PUBLIC KEY BLOCK-----") &&
       key.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
      {
	auto const fingerprint1(spoton_crypt::fingerprint(key));
	auto const fingerprint2
	  (spoton_crypt::fingerprint(spoton_crypt::publicGPG(eCrypt)));

	if(fingerprint1 == fingerprint2 &&
	   fingerprint1.isEmpty() == false &&
	   fingerprint2.isEmpty() == false)
	  {
	    showMessage(tr("Please do not add personal GPG keys."), 5000);
	    return;
	  }

	gpgme_check_version(nullptr);

	gpgme_ctx_t ctx = nullptr;
	auto err = gpgme_new(&ctx);

	if(err == GPG_ERR_NO_ERROR)
	  {
	    gpgme_data_t keydata = nullptr;

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
	    showMessage
	      (tr("GPGME error. Cannot add the key block to the key ring."),
	       5000);
	    return;
	  }

	QString connectionName("");
	QString error("");

	{
	  auto db(spoton_misc::database(connectionName));

	  db.setDatabaseName
	    (spoton_misc::homePath() +
	     QDir::separator() +
	     "friends_public_keys.db");

	  if(db.open())
	    {
	      QSqlQuery query(db);
	      auto const fingerprint(spoton_crypt::fingerprint(key));
	      auto ok = true;

	      /*
	      ** GPG public keys are not encrypted in the key ring.
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
	  showMessage(error, 5000);
	else
	  {
	    populateContacts();
	    ui.newContact->selectAll();
	  }

	return;
      }
  }
#endif

  auto sCrypt = m_parent ?
    m_parent->crypts().value("rosetta-signature", nullptr) : nullptr;

  if(!sCrypt)
    {
      showMessage
	(tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
      return;
    }

  auto const key
    (ui.newContact->toPlainText().remove("\n").remove("\r\n").toLatin1());

  if(key.isEmpty())
    {
      showMessage(tr("Empty key(s). Really?"), 5000);
      return;
    }

  if(!(key.startsWith("K") || key.startsWith("k")))
    {
      showMessage(tr("Invalid key(s). The provided text "
		     "must start with either the letter K or the letter k."),
		  5000);
      return;
    }

  auto const list(key.mid(1).split('@'));

  if(list.size() != 6)
    {
      showMessage
	(tr("Irregular data. Expecting 6 entries, received %1.").
	 arg(list.size()),
	 5000);
      return;
    }

  auto keyType(list.value(0));

  keyType = QByteArray::fromBase64(keyType);

  if(keyType != "rosetta")
    {
      showMessage(tr("Invalid key type. Expecting 'rosetta'."), 5000);
      return;
    }

  QByteArray myPublicKey;
  QByteArray mySPublicKey;
  auto mPublicKey(list.value(2));
  auto mSignature(list.value(3));
  auto ok = true;

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
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

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
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
    }

  auto sPublicKey(list.value(4));
  auto sSignature(list.value(5));

  sPublicKey = QByteArray::fromBase64(sPublicKey);
  sSignature = QByteArray::fromBase64(sSignature);

  if((mPublicKey == myPublicKey && !myPublicKey.isEmpty()) ||
     (sPublicKey == mySPublicKey && !mySPublicKey.isEmpty()))
    {
      showMessage(tr("You're attempting to add your own '%1' keys. "
		     "Please do not do this!").arg(keyType.constData()),
		  5000);
      return;
    }

  mSignature = QByteArray::fromBase64(mSignature);

  auto const algorithm(spoton_crypt::publicKeyAlgorithm(mPublicKey).toLower());

  if(!(algorithm.startsWith("mceliece") || algorithm.startsWith("ntru")))
    if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey, mSignature))
      {
	showMessage(tr("Invalid 'rosetta' public key signature."), 5000);
	return;
      }

  if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey, sSignature))
    {
      showMessage(tr("Invalid signature public key signature."), 5000);
      return;
    }

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	auto const name(QByteArray::fromBase64(list.value(1)));

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
    showMessage
      (tr("An error occurred while attempting to save the friendship bundle."),
       5000);
  else
    {
      emit participantAdded("rosetta");
      populateContacts();
    }
}

void spoton_rosetta::slotAttachForGPG(void)
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
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      auto list(dialog.selectedFiles());

      std::sort(list.begin(), list.end());

      for(int i = 0; i < list.size(); i++)
	{
	  QFileInfo const fileInfo(list.at(i));

	  ui.attachments->append
	    (QString("<a href=\"%1 (%2)\">%1 (%2)</a>").
	     arg(fileInfo.absoluteFilePath()).
	     arg(spoton_misc::prettyFileSize(fileInfo.size())));
	}

      QApplication::restoreOverrideCursor();
    }

  QApplication::processEvents();
}

void spoton_rosetta::slotClear(void)
{
  if(sender() == ui.clearContact)
    ui.newContact->clear();
  else if(sender() == ui.clearInput)
    {
      if(!ui.inputEncrypt->toPlainText().trimmed().isEmpty())
	{
	  QMessageBox mb(this);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText
	    (tr("Are you sure that you wish to clear the text?"));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return;
	    }
	}

      ui.cipher->setCurrentIndex(0);
      ui.desktop->setChecked(false);
      ui.gpg_email_addresses->setCurrentIndex(0);
      ui.hash->setCurrentIndex(0);
      ui.inputEncrypt->clear();
      ui.sign->setChecked(true);
    }
  else if(sender() == ui.clearOutput)
    ui.outputEncrypt->clear();
}

void spoton_rosetta::slotClearClipboardBuffer(void)
{
  auto clipboard = QApplication::clipboard();

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

  auto const destinationType = DestinationTypes
    (ui.contacts->itemData(index, Qt::ItemDataRole(Qt::UserRole + 1)).toInt());

  ui.cipher->setCurrentIndex(0);
  ui.cipher->setEnabled(destinationType == DestinationTypes::ROSETTA);
  ui.convertEncrypt->setEnabled(destinationType != DestinationTypes::ZZZ);
  ui.deleteContact->setEnabled(destinationType != DestinationTypes::ZZZ);

  if(destinationType == DestinationTypes::GPG)
    {
      QByteArray publicKey;
      auto eCrypt = m_parent ?
	m_parent->crypts().value("rosetta", nullptr) : nullptr;

      publicKey = spoton_misc::publicKeyFromHash
	(QByteArray::fromBase64(ui.contacts->
				itemData(ui.contacts->
					 currentIndex()).toByteArray()),
	 true,
	 eCrypt);
      ui.dump->setText
	(spoton_rosetta_gpg_import::dump(publicKey).trimmed());

      if(tr("GPG Empty Data") == ui.dump->text() || ui.dump->text().isEmpty())
	ui.dump->setVisible(false);
      else
	ui.dump->setVisible(true);

      ui.gpg_email_addresses->setCurrentIndex(0);
#ifdef SPOTON_GPGME_ENABLED
      ui.gpg_email_addresses->setEnabled(true);
#endif
    }
  else
    {
      ui.dump->setText("");
      ui.dump->setVisible(false);
      ui.gpg_email_addresses->setCurrentIndex(0);
      ui.gpg_email_addresses->setEnabled(false);
    }

  ui.hash->setCurrentIndex(0);
  ui.hash->setEnabled(destinationType == DestinationTypes::ROSETTA);
  ui.rename->setEnabled(destinationType != DestinationTypes::ZZZ);
  ui.sign->setChecked(true);
  ui.sign->setEnabled(destinationType != DestinationTypes::ZZZ);
}

void spoton_rosetta::slotConvertDecrypt(void)
{
#ifdef SPOTON_GPGME_ENABLED
  {
    QByteArray const begin("-----BEGIN PGP MESSAGE-----");
    QByteArray const end("-----END PGP MESSAGE-----");
    auto data(ui.inputDecrypt->toPlainText().trimmed().toUtf8());
    auto const index1 = data.indexOf(begin);
    auto const index2 = data.indexOf(end);

    if(index1 >= 0 && index1 < index2)
      {
	data = data.mid
	  (index1, index2 - index1 + static_cast<int> (qstrlen(end)));
	gpgme_check_version(nullptr);

	QColor signatureColor(240, 128, 128); // Light coral!
	auto signedMessage(tr("Invalid signature."));
	gpgme_ctx_t ctx = nullptr;
	auto err = gpgme_new(&ctx);

	if(err == GPG_ERR_NO_ERROR)
	  {
	    gpgme_data_t ciphertext = nullptr;
	    gpgme_data_t plaintext = nullptr;

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
		gpgme_set_passphrase_cb(ctx, &gpgPassphrase, nullptr);
	      }

	    if(err == GPG_ERR_NO_ERROR)
	      err = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);

	    if(err == GPG_ERR_NO_ERROR)
	      {
		ui.outputDecrypt->clear();

		QByteArray bytes(4096, 0);
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

		auto textCursor = ui.outputDecrypt->textCursor();

		textCursor.setPosition(0);
		ui.outputDecrypt->setTextCursor(textCursor);

		auto result = gpgme_op_verify_result(ctx);

		if(result)
		  {
		    auto signature = result->signatures;

		    if(signature && signature->fpr)
		      {
			gpgme_key_t key = nullptr;

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

  auto eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!eCrypt)
    {
      showMessage
	(tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

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
  QList<QByteArray> list;
  QScopedPointer<spoton_crypt> crypt;
  QString error("");
  QString signedMessage("");
  auto data
    (ui.inputDecrypt->toPlainText().remove("\n").remove("\r\n").toLatin1());
  auto ok = true;

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
      if(computedHash.isEmpty() ||
	 messageCode.isEmpty() ||
	 spoton_crypt::memcmp(computedHash, messageCode) == false)
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
	  data = list.value(2);
	  name = list.value(1);
	  publicKeyHash = list.value(0);
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
      auto const myPublicKeyHash
	(spoton_crypt::preferredHash(eCrypt->publicKey(nullptr)));
      auto sCrypt = m_parent ?
	m_parent->crypts().value("rosetta-signature", nullptr) : nullptr;

      if(signature.isEmpty())
	{
	  signatureColor = QColor(240, 128, 128); // Light coral!
	  signedMessage = tr("Empty signature.");
	}
      else if(spoton_misc::isValidSignature(publicKeyHash +   // Sender
					    name +            // Sender's Name
					    myPublicKeyHash + // Recipient
					    data,             // Message
					    publicKeyHash,    // Sender
					    signature,        // Signature
					    sCrypt) == false)
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
      ui.from->setCursorPosition(0);
      ui.outputDecrypt->setText
	(QString::fromUtf8(data.constData(), data.length()));

      auto textCursor = ui.outputDecrypt->textCursor();

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
      showMessage(error, 5000);
    }
  else
    QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotConvertEncrypt(void)
{
  auto eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!eCrypt)
    {
      showMessage
	(tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
      return;
    }

  auto destinationType = DestinationTypes
    (ui.contacts->
     itemData(ui.contacts->currentIndex(),Qt::ItemDataRole(Qt::UserRole + 1)).
     toInt());

  if(destinationType == DestinationTypes::GPG)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      auto const publicKeyHash
	(QByteArray::fromBase64(ui.contacts->
				itemData(ui.contacts->currentIndex()).
				toByteArray()));
      auto const receiver
	(spoton_misc::publicKeyFromHash(publicKeyHash, true, eCrypt));
      auto const sender(ui.gpg_email_addresses->currentData().toByteArray());
      auto ok = true;

      ui.outputEncrypt->setText
	(gpgEncrypt(ok,
		    ui.inputEncrypt->toPlainText().trimmed().toUtf8(),
		    receiver,
		    sender,
		    ui.sign->isChecked()));
      ui.outputEncrypt->selectAll();
      toDesktop();
      QApplication::restoreOverrideCursor();
      return;
    }

  spoton_crypt *sCrypt = nullptr;

  if(ui.sign->isChecked())
    {
      sCrypt = m_parent ?
	m_parent->crypts().value("rosetta-signature", nullptr) : nullptr;

      if(!sCrypt)
	{
	  showMessage
	    (tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
	  return;
	}
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

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
  QString error("");
  auto data(ui.inputEncrypt->toPlainText().toUtf8());
  auto ok = true;
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
  name = QSettings().value("gui/rosettaName", "unknown").toByteArray();
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
	  (myPublicKeyHash +                        // Sender
	   name +                                   // Sender's Name
	   spoton_crypt::preferredHash(publicKey) + // Recipient
	   ui.inputEncrypt->toPlainText().toUtf8(), // Message
	   &ok);
    }

  if(ok)
    {
      QDataStream stream(&data, QIODevice::WriteOnly);

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
      showMessage(error, 5000);
    }
  else
    QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotCopyDecrypted(void)
{
  auto clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.outputDecrypt->toPlainText());
}

void spoton_rosetta::slotCopyEncrypted(void)
{
  auto clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.outputEncrypt->toPlainText());
}

void spoton_rosetta::slotCopyMyGPGKeys(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  repaint();
  QApplication::processEvents();

  auto eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!eCrypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray bytes;
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_keys FROM gpg");

	if(query.exec())
	  while(query.next())
	    {
	      auto ok = true;
	      auto const publicKey = eCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok && publicKey.isEmpty() == false)
		{
		  bytes.append(publicKey);
		  bytes.append("\r\n");
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  clipboard->setText(bytes.trimmed());
  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotCopyMyRosettaPublicKeys(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const text(copyMyRosettaPublicKey());

  QApplication::restoreOverrideCursor();

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      showMessage(tr("The rosetta public key is too long (%1 bytes).").
		  arg(QLocale().toString(text.length())),
		  5000);
      return;
    }

  auto clipboard = QApplication::clipboard();

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
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  auto widget = QApplication::focusWidget();

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
	  qobject_cast<QTextEdit *> (widget)->clear();
	  qobject_cast<QTextEdit *> (widget)->paste();
	}
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotDecryptClear(void)
{
  ui.from->setText(tr("Empty"));
  ui.outputDecrypt->clear();

  QColor const color(240, 128, 128); // Light coral!

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
      showMessage(tr("Invalid item data. This is a serious flaw."), 5000);
      return;
    }

  QMessageBox mb(this);
  auto const destinationType = DestinationTypes
    (ui.contacts->itemData(ui.contacts->currentIndex(),
			   Qt::ItemDataRole(Qt::UserRole + 1)).toInt());

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons
    (destinationType != DestinationTypes::GPG ?
     QMessageBox::No | QMessageBox::Yes :
     QMessageBox::No | QMessageBox::Yes | QMessageBox::YesAll);
  mb.setDefaultButton(QMessageBox::No);

  if(destinationType == DestinationTypes::GPG)
    mb.setText
      (tr("Are you sure that you wish to remove the selected contact? "
	  "The key will also be removed from the GPG key ring if Yes to All "
	  "is selected."));
  else
    mb.setText
      (tr("Are you sure that you wish to remove the selected contact?"));

  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  auto const rc = mb.exec();

  if(!(rc == QMessageBox::Yes || rc == QMessageBox::YesAll))
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  auto const publicKeyHash
    (ui.contacts->itemData(ui.contacts->currentIndex()).toByteArray());

#ifdef SPOTON_GPGME_ENABLED
  if(destinationType == DestinationTypes::GPG && rc == QMessageBox::YesAll)
    {
      gpgme_check_version(nullptr);

      gpgme_ctx_t ctx = nullptr;
      auto err = gpgme_new(&ctx);

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray publicKey;
	  gpgme_data_t keydata = nullptr;
	  gpgme_key_t key = nullptr;
	  auto eCrypt = m_parent ?
	    m_parent->crypts().value("rosetta", nullptr) : nullptr;

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
	    gpgme_op_delete_ext(ctx, key, GPGME_DELETE_FORCE);

	  gpgme_data_release(keydata);
	  gpgme_key_unref(key);
	}

      gpgme_release(ctx);
    }
#endif

  QString connectionName("");
  auto const oid
    (QString::number(spoton_misc::oidFromPublicKeyHash(publicKeyHash)));
  auto ok = true;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(destinationType == DestinationTypes::GPG)
	  query.prepare("DELETE FROM gpg WHERE public_keys_hash = ?");
	else
	  query.prepare
	    ("DELETE FROM friends_public_keys WHERE public_key_hash = ?");

	query.addBindValue(publicKeyHash);
	ok = query.exec();

	if(destinationType == DestinationTypes::ROSETTA)
	  spoton_misc::purgeSignatureRelationships
	    (db,
	     m_parent ? m_parent->crypts().value("rosetta", nullptr) : nullptr);
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    showMessage
      (tr("An error occurred while attempting to delete the specified "
	  "participant."),
       5000);
  else
    {
      emit participantDeleted(oid, "rosetta");
      ui.contacts->removeItem(ui.contacts->currentIndex());

      if(ui.contacts->count() == 0)
	{
	  ui.contacts->addItem("Empty"); // Please do not translate Empty.
	  ui.contacts->setItemData
	    (0,
	     static_cast<int> (DestinationTypes::ZZZ),
	     Qt::ItemDataRole(Qt::UserRole + 1));
	}
      else
	sortContacts();

      populateContacts();
    }
}

void spoton_rosetta::slotGPGFileProcessed(void)
{
  showInformationMessage
    (tr("A GPG file was processed. Please see <b>%1</b>.").
     arg(spoton_misc::homePath() + QDir::separator() + "Rosetta-GPG"));
}

void spoton_rosetta::slotGPGPMessagesReadTimer(void)
{
  QMutableMapIterator<QString, QString> it(m_gpgMessages);

  while(it.hasNext())
    {
      it.next();

      if(!QFileInfo::exists(it.key()))
	{
	  showInformationMessage
	    (tr("The message file <b>%1</b> was read by <b>%2</b>.").
	     arg(QFileInfo(it.key()).fileName()).arg(it.value()));
	  it.remove();
	}
    }
}

void spoton_rosetta::slotImportGPGKeys(void)
{
#ifdef SPOTON_GPGME_ENABLED
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  if(!m_gpgImport)
    {
      m_gpgImport = new spoton_rosetta_gpg_import(this, m_parent);
      connect(m_gpgImport,
	      SIGNAL(gpgKeysImported(void)),
	      this,
	      SLOT(slotPopulateGPGEmailAddresses(void)));
      connect(m_gpgImport,
	      SIGNAL(gpgKeysRemoved(void)),
	      this,
	      SLOT(slotPopulateGPGEmailAddresses(void)));
      connect(this,
	      SIGNAL(gpgKeysRemoved(void)),
	      m_gpgImport,
	      SLOT(slotGPGKeysRemoved(void)));
    }

  spoton_utilities::centerWidget(m_gpgImport, m_parent);
  m_gpgImport->showNormal();
  m_gpgImport->activateWindow();
  m_gpgImport->raise();
#endif
}

void spoton_rosetta::slotNewGPGKeys(void)
{
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  auto dialog = findChild<QDialog *> ("new-gpg-keys-dialog");

  if(!dialog)
    {
      auto completer = new QCompleter(this);
      auto model = new QFileSystemModel(this);

      completer->setCaseSensitivity(Qt::CaseInsensitive);
      completer->setCompletionRole(QFileSystemModel::FileNameRole);
      completer->setFilterMode(Qt::MatchContains);
      completer->setModel(model);
      dialog = new QDialog(this);
      dialog->setObjectName("new-gpg-keys-dialog");
      m_gpgNewKeysUi.setupUi(dialog);
      m_gpgNewKeysUi.gpg->setCompleter(completer);
      model->setRootPath(QDir::rootPath());
    }

  m_gpgNewKeysUi.gpg->setText
    (QSettings().value("gui/gpgPath", "").toString());
  m_gpgNewKeysUi.gpg->selectAll();
  m_gpgNewKeysUi.gpg_results->clear();

 repeat_label:

  if(dialog->exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      QSettings().setValue("gui/gpgPath", m_gpgNewKeysUi.gpg->text());
      dialog->open();

      QFileInfo const fileInfo(m_gpgNewKeysUi.gpg->text());

      if(fileInfo.isExecutable())
	{
	  QFile file;

	  file.setFileName
	    (spoton_misc::homePath() + QDir::separator() + "gpg.txt");

	  if(file.open(QIODevice::Text | QIODevice::WriteOnly))
	    {
	      file.write
		(m_gpgNewKeysUi.gpg_directives->toPlainText().toUtf8());
	      file.close();

	      QProcess process;
	      QStringList parameters;

	      parameters << "--batch"
			 << "--gen-key"
			 << file.fileName();
	      process.setWorkingDirectory(spoton_misc::homePath());
	      process.start(fileInfo.absoluteFilePath(), parameters);

	      do
		{
		  process.waitForFinished(150);
		  QApplication::processEvents();
		}
	      while(process.state() == QProcess::Running);

	      file.remove();
	      m_gpgNewKeysUi.gpg_results->append
		(process.readAllStandardError().trimmed());
	      m_gpgNewKeysUi.gpg_results->append
		(process.readAllStandardOutput().trimmed());
	      QApplication::restoreOverrideCursor();

	      if(process.exitCode() != 0)
		goto repeat_label;
	      else
		dialog->close();
	    }
	  else
	    {
	      m_gpgNewKeysUi.gpg_results->append
		(tr("Could not create %1.").arg(file.fileName()));
	      QApplication::restoreOverrideCursor();
	      goto repeat_label;
	    }
	}
      else
	{
	  m_gpgNewKeysUi.gpg_results->append
	    (tr("Please select an executable GPG program."));
	  QApplication::restoreOverrideCursor();
	  goto repeat_label;
	}
    }
}

void spoton_rosetta::slotParticipantAdded(const QString &type)
{
  if(type == "rosetta")
    populateContacts();
}

void spoton_rosetta::slotPopulateGPGEmailAddresses(void)
{
  populateGPGEmailAddresses();
}

void spoton_rosetta::slotPrisonBluesTimeout(void)
{
  if(!m_parent)
    return;

  if(m_readPrisonBluesFuture.isFinished())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    m_readPrisonBluesFuture = QtConcurrent::run
      (&spoton_rosetta::readPrisonBlues,
       this,
       m_parent->prisonBluesDirectories(),
       QSettings().value("gui/rosettaGPG").toString().trimmed(),
       m_gpgFingerprints);
#else
    m_readPrisonBluesFuture = QtConcurrent::run
      (this,
       &spoton_rosetta::readPrisonBlues,
       m_parent->prisonBluesDirectories(),
       QSettings().value("gui/rosettaGPG").toString().trimmed(),
       m_gpgFingerprints);
#endif

  prisonBluesProcess();
}

void spoton_rosetta::slotProcessGPGMessage(const QByteArray &message)
{
  if(message.trimmed().isEmpty())
    return;

#ifdef SPOTON_GPGME_ENABLED
  QByteArray const begin("-----BEGIN PGP MESSAGE-----");
  QByteArray const end("-----END PGP MESSAGE-----");
  auto const index1 = message.indexOf(begin);
  auto const index2 = message.indexOf(end);

  if(index1 < 0 || index2 < 0 || index1 >= index2)
    return;

  gpgme_check_version(nullptr);

  QByteArray msg("");
  auto from(tr("(Unknown)"));
  auto signedMessage(tr("(Invalid Signature)"));
  gpgme_ctx_t ctx = nullptr;
  gpgme_error_t err = gpgme_new(&ctx);

  if(err == GPG_ERR_NO_ERROR)
    {
      auto const data
	(message.
	 mid(index1, index2 - index1 + static_cast<int> (qstrlen(end))));
      gpgme_data_t ciphertext = nullptr;
      gpgme_data_t plaintext = nullptr;

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
	  gpgme_set_passphrase_cb(ctx, &gpgPassphrase, nullptr);
	}

      if(err == GPG_ERR_NO_ERROR)
	err = gpgme_op_decrypt_verify(ctx, ciphertext, plaintext);

      if(err == GPG_ERR_NO_ERROR)
	{
	  QByteArray bytes(4096, 0);
	  ssize_t rc = 0;

	  gpgme_data_seek(plaintext, 0, SEEK_SET);

	  while
	    ((rc = gpgme_data_read(plaintext,
				   bytes.data(),
				   static_cast<size_t> (bytes.length()))) > 0)
	    msg.append(bytes.mid(0, static_cast<int> (rc)));

	  msg = msg.trimmed();

	  auto result = gpgme_op_verify_result(ctx);

	  if(result)
	    {
	      auto signature = result->signatures;

	      if(signature && signature->fpr)
		{
		  gpgme_key_t key = nullptr;

		  if(gpgme_get_key(ctx, signature->fpr, &key, 0) ==
		     GPG_ERR_NO_ERROR)
		    {
		      if(key->uids && key->uids->email)
			{
			  QByteArray f(key->uids->email);

			  from = QString::fromUtf8(f.constData(), f.length());
			}
		      else
			from = tr("(Unknown)");
		    }
		  else
		    from = tr("(Unknown)");

		  gpgme_key_unref(key);
		}
	      else
		from = tr("(Unknown)");

	      if((signature && (signature->summary & GPGME_SIGSUM_GREEN)) ||
		 (signature && !signature->summary))
		signedMessage = tr("(Signed)");
	    }
	}

      gpgme_data_release(ciphertext);
      gpgme_data_release(plaintext);
    }

  gpgme_release(ctx);

  if(err == GPG_ERR_NO_ERROR && msg.length() > 0)
    {
      QString content("");
      auto const now(QDateTime::currentDateTime());

      content = QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>]: ").
	arg(now.toString("MM")).
	arg(now.toString("dd")).
	arg(now.toString("yyyy")).
	arg(now.toString("hh")).
	arg(now.toString("mm")).
	arg(now.toString("ss"));
      content.append
	(QString("<font color=blue>%1 <b>%2</b>: </font>").
	 arg(from).arg(signedMessage));
      content.append
	(qUtf8Printable(QString::fromUtf8(msg.constData(), msg.length())));
      content = m_parent &&
	m_parent->m_settings.value("gui/enableChatEmoticons", false).toBool() ?
	m_parent->mapIconToEmoticon(content) :
	content;
      ui.gpg_messages->append(content);
      ui.gpg_messages->verticalScrollBar()->setValue
	(ui.gpg_messages->verticalScrollBar()->maximum());
    }
#endif
}

void spoton_rosetta::slotPublishGPG(void)
{
  if(!m_parent)
    {
      showMessage(tr("Invalid parent object."), 5000);
      return;
    }

  auto const list(m_parent->prisonBluesDirectories());

  if(list.isEmpty())
    {
      showMessage(tr("Please configure GIT. Options -> GIT."), 5000);
      return;
    }

  auto const destinationType = DestinationTypes
    (ui.contacts->currentData(Qt::ItemDataRole(Qt::UserRole + 1)).toInt());

  if(destinationType != DestinationTypes::GPG)
    {
      showMessage(tr("GPG recipient only!"), 5000);
      return;
    }

  auto const fingerprint = spoton_crypt::fingerprint
    (spoton_misc::
     publicKeyFromHash(QByteArray::
		       fromBase64(ui.contacts->
				  itemData(ui.contacts->currentIndex()).
				  toByteArray()),
		       true,
		       m_parent->crypts().value("chat", nullptr)));

  if(fingerprint.trimmed().isEmpty())
    {
      showMessage(tr("Empty destination fingerprint."), 5000);
      return;
    }

  slotConvertEncrypt();

  auto state = false;

  foreach(auto const &directory, list)
    if(directory.isWritable())
      {
	QDir().mkpath
	  (directory.absoluteFilePath() + QDir::separator() + fingerprint);

	QTemporaryFile file
	  (directory.absoluteFilePath() +
	   QDir::separator() +
	   fingerprint +
	   QDir::separator() +
	   "PrisonBluesXXXXXXXXXX.txt");

	if(file.open())
	  {
	    Q_UNUSED(file.fileName()); // Prevents removal of file.
	    file.setAutoRemove(false);
	    file.write(ui.outputEncrypt->toPlainText().toUtf8());
	    state = true;
	  }
	else
	  showMessage(tr("Error creating a temporary file."), 5000);
      }
    else if(directory.absoluteFilePath().trimmed().isEmpty() == false)
      showMessage
	(tr("The directory %1 is not writable.").
	 arg(directory.absoluteFilePath()), 5000);

  state ? launchPrisonBluesProcessesIfNecessary() : (void) 0;
}

void spoton_rosetta::slotRemoveGPGAttachment(const QUrl &url)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
  auto const list
    (ui.attachments->toPlainText().split('\n', Qt::SkipEmptyParts));
#else
  auto const list
    (ui.attachments->toPlainText().split('\n', QString::SkipEmptyParts));
#endif

  ui.attachments->clear();

  for(int i = 0; i < list.size(); i++)
    {
      auto const str(list.at(i));

      if(str != url.toString() && str.length() > 0)
	ui.attachments->append(QString("<a href=\"%1\">%1</a>").arg(str));
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::slotRemoveGPGKeys(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setDefaultButton(QMessageBox::No);
  mb.setText(tr("Remove all of your local GPG keys? "
		"The keys will not be removed from the GPG key ring."));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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

  populateGPGEmailAddresses();
  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rosetta::slotRemoveStoredINIGPGPassphrase(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText
    (tr("Are you sure that you wish to remove the GPG passphrase from "
	"the INI file?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QSettings().remove("gui/gpgPassphrase");
}

void spoton_rosetta::slotRename(void)
{
  auto eCrypt = m_parent ?
    m_parent->crypts().value("rosetta", nullptr) : nullptr;

  if(!eCrypt)
    {
      showMessage
	(tr("Invalid spoton_crypt object. This is a fatal flaw."), 5000);
      return;
    }
  else if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      showMessage(tr("Invalid item data. This is a serious flaw."), 5000);
      return;
    }

  QString name("");
  auto ok = true;

  name = QInputDialog::getText
    (this,
     tr("%1: New Name").arg(SPOTON_APPLICATION_NAME),
     tr("&Name"),
     QLineEdit::Normal,
     ui.contacts->currentText(),
     &ok);
  name = name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH);

  if(name.isEmpty() || !ok)
    return;

  QString connectionName("");
  auto const destinationType = DestinationTypes
    (ui.contacts->itemData(ui.contacts->currentIndex(),
			   Qt::ItemDataRole(Qt::UserRole + 1)).toInt());
  auto const publicKeyHash
    (ui.contacts->itemData(ui.contacts->currentIndex()).toByteArray());

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(destinationType == DestinationTypes::GPG)
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
    showMessage
      (tr("An error occurred while attempting to rename the specified "
	  "participant."),
       5000);
  else
    {
      emit participantNameChanged(publicKeyHash, name);
      sortContacts();
    }
}

void spoton_rosetta::slotSaveGPGAttachmentProgram(void)
{
  QSettings().setValue("gui/rosettaGPG", ui.gpg->text().trimmed());
  ui.gpg->selectAll();
}

void spoton_rosetta::slotSaveName(void)
{
  auto str(ui.name->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      ui.name->setText(str);
    }
  else
    ui.name->setText(str.trimmed());

  QSettings().setValue("gui/rosettaName", str.toUtf8());
  ui.name->selectAll();
}

void spoton_rosetta::slotSetIcons(void)
{
  auto iconSet(QSettings().value("gui/iconSet", "nuove").toString().toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";

  ui.add->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  ui.clearContact->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearInput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearOutput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clear_gpg->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.copy->setIcon(QIcon(QString(":/%1/copy.png").arg(iconSet)));
  ui.decryptClear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.decryptReset->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.gpg_send->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
  ui.save->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

void spoton_rosetta::slotSplitterMoved(int pos, int index)
{
  Q_UNUSED(index);
  Q_UNUSED(pos);

  auto splitter = qobject_cast<QSplitter *> (sender());

  if(!splitter)
    return;

  QString key("");

  if(splitter == ui.chatHorizontalSplitter)
    key = "gui/rosettaChatHorizontalSplitter";
  else if(splitter == ui.decryptSplitter)
    key = "gui/rosettaDecryptSplitter";
  else if(splitter == ui.encryptSplitter)
    key = "gui/rosettaEncryptSplitter";
  else
    key = "gui/rosettaMainHorizontalSplitter";

  QSettings().setValue(key, splitter->saveState());
}

void spoton_rosetta::slotWriteGPG(void)
{
#ifdef SPOTON_GPGME_ENABLED
  if(!m_parent)
    {
      showMessage(tr("Invalid parent object."), 5000);
      return;
    }

  auto const list(m_parent->prisonBluesDirectories());

  if(list.isEmpty())
    {
      showMessage(tr("Please configure GIT. Options -> GIT."), 5000);
      return;
    }

  auto crypt = m_parent->crypts().value("chat", nullptr);

  if(!crypt)
    {
      showMessage(tr("Invalid spoton_crypt object."), 5000);
      return;
    }

  auto const message(ui.gpg_message->toPlainText().trimmed());

  if(message.isEmpty())
    {
      showMessage(tr("Please provide a message."), 5000);
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const names
    (ui.gpg_participants->selectionModel()->selectedRows(0));

  if(names.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      showMessage(tr("Please select a participant."), 5000);
      return;
    }

  QString msg("");
  QString to("");
  auto const now(QDateTime::currentDateTime());

  for(int i = 0; i < names.size(); i++)
    to.append(names.at(i).data().toString()).append(", ");

  msg.append
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append
    (tr("<b>%1</b> (<font color=gray>%2</font>)<b>:</b> ").
     arg(ui.gpg_email_addresses->currentText()).
     arg(to.mid(0, to.length() - 2)));

  if(m_parent->m_settings.value("gui/enableChatEmoticons", false).toBool())
    msg.append(m_parent->mapIconToEmoticon(message));
  else
    msg.append(message);

  ui.gpg_messages->append(msg);
  ui.gpg_messages->verticalScrollBar()->setValue
    (ui.gpg_messages->verticalScrollBar()->maximum());

  auto const fingerprints
    (ui.gpg_participants->selectionModel()->selectedRows(1));
  auto const participants
    (ui.gpg_participants->selectionModel()->selectedRows(0));
  auto const publicKeyHashes
    (ui.gpg_participants->selectionModel()->selectedRows(2));
  auto const sign = ui.gpg_sign_messages->isChecked();
  auto state = false;

  foreach(auto const &directory, list)
    for(int i = 0; i < fingerprints.size(); i++)
      {
	if(!(directory.isWritable()) ||
	   !(fingerprints.value(i).isValid() &&
	     publicKeyHashes.value(i).isValid()))
	  continue;

	auto const destination
	  (directory.absoluteFilePath() +
	   QDir::separator() +
	   fingerprints.value(i).data().toString());

	QDir().mkpath(destination);

	publishAttachments
	  (destination,
	   participants.value(i).data().toString(),
	   ui.attachments->toPlainText().split('\n'));

	QTemporaryFile file
	  (destination + QDir::separator() + "PrisonBluesXXXXXXXXXX.txt");

	if(file.open())
	  {
	    auto const publicKey = spoton_misc::publicKeyFromHash
	      (QByteArray::
	       fromBase64(publicKeyHashes.value(i).data().toByteArray()),
	       true,
	       crypt);
	    auto ok = true;
	    auto const output(gpgEncrypt(ok,
					 message.toUtf8(),
					 publicKey,
					 QByteArray(),
					 sign));

	    if(ok)
	      {
		Q_UNUSED(file.fileName()); // Prevents removal of file.
		file.setAutoRemove(false);

		if(file.write(output) ==
		   static_cast<qint64> (output.length()))
		  {
		    m_gpgMessages[file.fileName()] =
		      participants.value(i).data().toString();
		    showInformationMessage
		      (tr("The message file <b>%1</b> "
			  "was generated for <b>%2</b>.").
		       arg(QFileInfo(file.fileName()).fileName()).
		       arg(participants.value(i).data().toString()));
		    state = true;
		  }
		else
		  showMessage
		    (tr("Incorrect number of bytes written (%1).").
		     arg(file.fileName()),
		     5000);
	      }
	    else
	      showMessage(output, 5000);
	  }
	else
	  showMessage(tr("Could not create a temporary file."), 5000);
      }

  state ? launchPrisonBluesProcessesIfNecessary() : (void) 0;
  ui.gpg_message->clear();
  QApplication::restoreOverrideCursor();
#endif
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

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
  QMultiMapIterator<QString, QPair<DestinationTypes, QVariant> > it(map);
#else
  QMapIterator<QString, QPair<DestinationTypes, QVariant> > it(map);
#endif

  while(it.hasNext())
    {
      it.next();

      auto const str(it.key().trimmed());

      if(str.isEmpty())
	ui.contacts->addItem("unknown", it.value().second);
      else
	ui.contacts->addItem(str, it.value().second);

      /*
      ** Record destination type.
      */

      ui.contacts->setItemData
	(ui.contacts->count() - 1,
	 static_cast<int> (it.value().first),
	 Qt::ItemDataRole(Qt::UserRole + 1));
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rosetta::toDesktop(void)
{
  if(!ui.desktop->isChecked())
    return;

  QFile file;
  auto const fileName
    (QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) +
     QDir::separator() +
     "spot_on_" +
     QString::number(QDateTime::currentMSecsSinceEpoch())+
     ".asc");

  file.setFileName(fileName);

  if(file.open(QIODevice::Truncate | QIODevice::WriteOnly))
    file.write(ui.outputEncrypt->toPlainText().toUtf8());
  else
    showMessage(tr("Error creating the file %1.").arg(fileName), 5000);

  file.close();
}
