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

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-rosetta.h"

spoton_rosetta::spoton_rosetta(void):QMainWindow()
{
  m_eCrypt = 0;
  m_sCrypt = 0;
  ui.setupUi(this);
  setWindowTitle
    (tr("%1: Rosetta").
     arg(SPOTON_APPLICATION_NAME));
  ui.name->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
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
  connect(ui.action_Copy,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.action_Paste,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotCopyOrPaste(void)));
  connect(ui.add,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddContact(void)));
  connect(ui.clearContact,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));
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
  connect(ui.convert,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotConvert(void)));
  connect(ui.copy,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyMyRosettaPublicKey(void)));
  connect(ui.copyConverted,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyConverted(void)));
  connect(ui.decrypt,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotDecryptToggled(bool)));
  connect(ui.deleteContact,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDelete(void)));
  connect(ui.encrypt,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEncryptToggled(bool)));
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

  /*
  ** Please do not translate n/a.
  */

  if(ui.cipher->count() == 0)
    ui.cipher->addItem("n/a");

  if(ui.hash->count() == 0)
    ui.hash->addItem("n/a");

  populateContacts();
}

void spoton_rosetta::slotClose(void)
{
  close();
}

void spoton_rosetta::show(QWidget *parent)
{
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

  QSettings settings;

  ui.name->setText
    (QString::fromUtf8(settings.value("gui/rosettaName", "unknown").
		       toByteArray()).trimmed());
  QMainWindow::show();
  raise();
  populateContacts();
}

void spoton_rosetta::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_rosetta::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  toLower());

  if(!(iconSet == "everaldo" || iconSet == "nouve" || iconSet == "nuvola"))
    iconSet = "nouve";

  ui.add->setIcon(QIcon(QString(":/%1/add.png").arg(iconSet)));
  ui.clearContact->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearInput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.clearOutput->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.copy->setIcon(QIcon(QString(":/%1/copy.png").arg(iconSet)));
  ui.save->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_rosetta::event(QEvent *event)
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

void spoton_rosetta::slotClear(void)
{
  if(sender() == ui.clearContact)
    ui.newContact->clear();
  else if(sender() == ui.clearInput)
    {
      ui.cipher->setCurrentIndex(0);
      ui.hash->setCurrentIndex(0);
      ui.input->clear();
      ui.sign->setChecked(true);
    }
  else if(sender() == ui.clearOutput)
    ui.output->clear();
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

void spoton_rosetta::setCryptObjects(spoton_crypt *eCrypt,
				     spoton_crypt *sCrypt)
{
  m_eCrypt = eCrypt;
  m_sCrypt = sCrypt;
}

QByteArray spoton_rosetta::copyMyRosettaPublicKey(void) const
{
  if(!m_eCrypt || !m_sCrypt)
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  QSettings settings;
  bool ok = true;

  name = settings.value("gui/rosettaName", "unknown").toByteArray();
  mPublicKey = m_eCrypt->publicKey(&ok);

  if(ok)
    mSignature = m_eCrypt->digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_sCrypt->publicKey(&ok);

  if(ok)
    sSignature = m_sCrypt->digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("rosetta").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

void spoton_rosetta::slotCopyMyRosettaPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyRosettaPublicKey());
}

void spoton_rosetta::slotAddContact(void)
{
  if(!m_eCrypt || !m_sCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object(s). This is "
			       "a fatal flaw."));
      return;
    }

  QByteArray key
    (ui.newContact->toPlainText().toLatin1());

  if(key.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Empty key(s). Really?"));
      return;
    }

  if(!(key.startsWith("K") || key.startsWith("k")))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid key(s). The provided text "
	    "must start with either the letter K or the letter k."));
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
      return;
    }

  QByteArray mPublicKey(list.value(2));
  QByteArray mSignature(list.value(3));
  QByteArray myPublicKey;
  QByteArray mySPublicKey;
  bool ok = true;

  mPublicKey = QByteArray::fromBase64(mPublicKey);
  myPublicKey = m_eCrypt->publicKey(&ok);

  if(!ok)
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
      mb.setText(tr("Unable to retrieve your %1 "
		    "public key for comparison. Continue?").
		 arg(keyType.constData()));

      if(mb.exec() != QMessageBox::Yes)
	return;
    }

  mySPublicKey = m_sCrypt->publicKey(&ok);

  if(!ok)
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
      mb.setText(tr("Unable to retrieve your %1 signature "
		    "public key for comparison. Continue?").
		 arg(keyType.constData()));

      if(mb.exec() != QMessageBox::Yes)
	return;
    }

  if((mPublicKey == myPublicKey && !myPublicKey.isEmpty()) ||
     (mSignature == mySPublicKey && !mySPublicKey.isEmpty()))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("You're attempting to add your own '%1' keys. "
	    "Please do not do this!").arg(keyType.constData()));
      return;
    }

  mSignature = QByteArray::fromBase64(mSignature);

  if(!spoton_crypt::isValidSignature(mPublicKey, mPublicKey,
				     mSignature))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid 'rosetta' public key signature."));
      return;
    }

  QByteArray sPublicKey(list.value(4));
  QByteArray sSignature(list.value(5));

  sPublicKey = QByteArray::fromBase64(sPublicKey);
  sSignature = QByteArray::fromBase64(sSignature);

  if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey,
				     sSignature))
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid signature public key signature."));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QByteArray name(list.value(1));

	name = QByteArray::fromBase64(name);

	if((ok = spoton_misc::saveFriendshipBundle(keyType,
						   name,
						   mPublicKey,
						   sPublicKey,
						   -1,
						   db,
						   m_eCrypt)))
	  if((ok = spoton_misc::saveFriendshipBundle(keyType + "-signature",
						     name,
						     sPublicKey,
						     QByteArray(),
						     -1,
						     db,
						     m_eCrypt)))
	    ui.newContact->selectAll();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    QMessageBox::critical
      (this, tr("%1: Error").
       arg(SPOTON_APPLICATION_NAME),
       tr("An error occurred while attempting to save the friendship "
	  "bundle."));
  else
    populateContacts();
}

void spoton_rosetta::slotDecryptToggled(bool state)
{
  ui.cipher->setEnabled(!state);
  ui.hash->setEnabled(!state);
  ui.sign->setEnabled(!state);
}

void spoton_rosetta::slotEncryptToggled(bool state)
{
  ui.cipher->setEnabled(state);
  ui.hash->setEnabled(state);
  ui.sign->setEnabled(state);
}

void spoton_rosetta::populateContacts(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			"friends_public_keys.db");

    if(db.open())
      {
	QMultiMap<QString, QByteArray> names;
	QSqlQuery query(db);
	bool ok = true;

	ui.contacts->clear();
	query.setForwardOnly(true);
	query.prepare("SELECT name, public_key FROM friends_public_keys "
		      "WHERE key_type_hash = ?");

	if(m_eCrypt)
	  query.bindValue(0, m_eCrypt->keyedHash(QByteArray("rosetta"), &ok).
			  toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray name;
	      QByteArray publicKey;
	      bool ok = true;

	      if(m_eCrypt)
		name = m_eCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).
					  toByteArray()),
		   &ok);
	      else
		ok = false;

	      if(ok)
		{
		  if(m_eCrypt)
		    publicKey = m_eCrypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).
					      toByteArray()),
		       &ok);
		  else
		    ok = false;
		}

	      if(ok)
		names.insert(name, publicKey);
	    }

	QMapIterator<QString, QByteArray> it(names);

	while(it.hasNext())
	  {
	    it.next();

	    QString str(it.key().trimmed());

	    if(str.isEmpty())
	      ui.contacts->addItem("unknown", it.value());
	    else
	      ui.contacts->addItem(str, it.value());
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ui.contacts->count() == 0)
    ui.contacts->addItem("Empty");
}

void spoton_rosetta::slotConvert(void)
{
  if(ui.encrypt->isChecked())
    {
      QByteArray data;
      QByteArray encryptionKey;
      QByteArray hashKey;
      QByteArray keyInformation;
      QByteArray messageCode;
      QByteArray myPublicKey;
      QByteArray myPublicKeyHash;
      QByteArray publicKey;
      QByteArray signature;
      QString error("");
      bool ok = true;
      size_t encryptionKeyLength = 0;
      spoton_crypt *crypt = 0;

      if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
	{
	  error = tr("Invalid item data. This is a serious flaw.");
	  goto done_label1;
	}

      if(ui.input->toPlainText().isEmpty())
	{
	  error = tr("Please provide an actual message!");
	  goto done_label1;
	}

      encryptionKeyLength = spoton_crypt::cipherKeyLength
	(ui.cipher->currentText().toLatin1());

      if(encryptionKeyLength == 0)
	{
	  error = tr("The method spoton_crypt::cipherKeyLength() "
		     "failed.");
	  goto done_label1;
	}

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      encryptionKey.resize(static_cast<int> (encryptionKeyLength));
      encryptionKey = spoton_crypt::veryStrongRandomBytes
	(encryptionKey.length());
      hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
      hashKey = spoton_crypt::veryStrongRandomBytes(hashKey.length());
      publicKey = ui.contacts->itemData(ui.contacts->currentIndex()).
	toByteArray();
      keyInformation = spoton_crypt::publicKeyEncrypt
	(encryptionKey.toBase64() + "\n" +
	 hashKey.toBase64() + "\n" +
	 ui.cipher->currentText().toLatin1().toBase64() + "\n" +
	 ui.hash->currentText().toLatin1().toBase64(),
	 publicKey, &ok);

      if(!ok)
	{
	  QApplication::restoreOverrideCursor();
	  error = tr("The method spoton_crypt::publicKeyEncrypt() failed.");
	  goto done_label1;
	}

      crypt = new spoton_crypt(ui.cipher->currentText(),
			       ui.hash->currentText(),
			       QByteArray(),
			       encryptionKey,
			       hashKey,
			       0,
			       0,
			       QString(""));

      if(ui.sign->isChecked())
	{
	  if(ok)
	    myPublicKey = m_eCrypt->publicKey(&ok);

	  if(ok)
	    myPublicKeyHash = spoton_crypt::sha512Hash(myPublicKey, &ok);

	  if(ok)
	    signature = m_sCrypt->digitalSignature
	      (myPublicKeyHash + ui.input->toPlainText().toUtf8(),
	       &ok);
	}

      if(ok)
	data = crypt->encrypted
	  (myPublicKeyHash.toBase64() + "\n" +
	   ui.input->toPlainText().toUtf8().toBase64() + "\n" +
	   signature.toBase64(), &ok);

      if(ok)
	messageCode = crypt->keyedHash(data, &ok);

      if(ok)
	data = keyInformation.toBase64() + "@" +
	  data.toBase64() + "@" +
	  messageCode.toBase64();

      QApplication::restoreOverrideCursor();
      delete crypt;

      if(!ok)
	error = tr("A serious cryptographic error occurred.");

      if(ok)
	{
	  ui.output->setText(data);
	  ui.output->selectAll();
	}
      else
	ui.output->clear();

    done_label1:

      if(!error.isEmpty())
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      error);
    }
  else
    {
      QByteArray cipherType;
      QByteArray computedHash;
      QByteArray data(ui.input->toPlainText().toLatin1());
      QByteArray encryptionKey;
      QByteArray hashKey;
      QByteArray hashType;
      QByteArray keyInformation;
      QByteArray messageCode;
      QByteArray publicKeyHash;
      QByteArray signature;
      QList<QByteArray> list;
      QString error("");
      bool ok = true;
      spoton_crypt *crypt = 0;

      if(data.isEmpty())
	{
	  error = tr("Empty input data.");
	  goto done_label2;
	}

      list = data.split('@');

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      data = list.value(1);
      keyInformation = m_eCrypt->publicKeyDecrypt(list.value(0), &ok);

      if(!ok)
	{
	  error = tr("The method spoton_crypt::publicKeyDecrypt() "
		     "failed.");
	  goto done_label2;
	}

      messageCode = list.value(2);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  encryptionKey = QByteArray::fromBase64(list.value(0));
	  hashKey = QByteArray::fromBase64(list.value(1));
	  cipherType = QByteArray::fromBase64(list.value(2));
	  hashType = QByteArray::fromBase64(list.value(3));
	}

      if(ok)
	{
	  computedHash = spoton_crypt::keyedHash
	    (data, hashKey, hashType, &ok);

	  if(!ok)
	    {
	      error = tr("The method spoton_crypt::keyedHash() failed.");
	      goto done_label2;
	    }
	}

      if(ok)
	{
	  if(computedHash.isEmpty() || messageCode.isEmpty() ||
	     !spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      error = tr("The computed hash does not match the provided "
			 "hash.");
	      goto done_label2;
	    }
	}

      crypt = new spoton_crypt(cipherType,
			       QString(""),
			       QByteArray(),
			       encryptionKey,
			       0,
			       0,
			       QString(""));

      if(ok)
	data = crypt->decrypted(data, &ok);

      if(ok)
	{
	  QList<QByteArray> list(data.split('\n'));

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  publicKeyHash = list.value(0);
	  data = list.value(1);
	  signature = list.value(2);
	}

      delete crypt;

      if(ok)
	{
	  if(signature.isEmpty())
	    error = tr("The message was not signed.");
	  else if(!spoton_misc::isValidSignature(publicKeyHash + data,
						 publicKeyHash,
						 signature,
						 m_eCrypt))
	    error = tr("Invalid signature. Perhaps your contacts are "
		       "not current.");
	}

      if(!ok)
	{
	  error = tr("A serious cryptographic error occurred.");
	  ui.output->clear();
	}
      else
	{
	  ui.output->setText(QString::fromUtf8(data.constData()));
	  ui.output->selectAll();
	}

    done_label2:

      if(!error.isEmpty())
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      error);
    }
}

void spoton_rosetta::slotDelete(void)
{
  if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid item data. This is a serious flaw."));
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
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"contact?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QByteArray data(ui.contacts->itemData(ui.contacts->currentIndex()).
			toByteArray());
	QSqlQuery query(db);
	bool ok = true;

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, spoton_crypt::sha512Hash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();

	spoton_misc::purgeSignatureRelationships(db, m_eCrypt);
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    QMessageBox::critical
      (this, tr("%1: Error").
       arg(SPOTON_APPLICATION_NAME),
       tr("An error occurred while attempting to delete the specified "
	  "participant."));
  else
    populateContacts();
}

void spoton_rosetta::slotCopyConverted(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(ui.output->toPlainText());
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

  if(qobject_cast<QLineEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QLineEdit *> (widget)->copy();
      else
	qobject_cast<QLineEdit *> (widget)->paste();
    }
  else if(qobject_cast<QTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QTextEdit *> (widget)->copy();
      else
	qobject_cast<QTextEdit *> (widget)->paste();
    }
}

void spoton_rosetta::slotRename(void)
{
  if(!m_eCrypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }
  else if(ui.contacts->itemData(ui.contacts->currentIndex()).isNull())
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid item data. This is a serious flaw."));
      return;
    }

  QString name("");
  bool ok = true;

  name = QInputDialog::getText
    (this, tr("%1: New Name").
     arg(SPOTON_APPLICATION_NAME), tr("&Name"),
     QLineEdit::Normal, QString(""), &ok);
  name = name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH);

  if(name.isEmpty() || !ok)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QByteArray data(ui.contacts->itemData(ui.contacts->currentIndex()).
			toByteArray());
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys "
		      "SET name = ?, "
		      "name_changed_by_user = 1 "
		      "WHERE public_key_hash = ?");
	query.bindValue
	  (0, m_eCrypt->encryptedThenHashed(name.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue(1, spoton_crypt::sha512Hash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    QMessageBox::critical
      (this, tr("%1: Error").
       arg(SPOTON_APPLICATION_NAME),
       tr("An error occurred while attempting to rename the specified "
	  "participant."));
  else
    populateContacts();
}
