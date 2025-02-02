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

#ifdef SPOTON_GPGME_ENABLED
#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>

extern "C"
{
#include <gpgme.h>
}
#endif

#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-rosetta-gpg-import.h"

spoton_rosetta_gpg_import::spoton_rosetta_gpg_import
(QWidget *parent, spoton *spoton):QMainWindow(parent)
{
  m_spoton = spoton;
  m_ui.setupUi(this);
  m_ui.public_keys_dump->setText(tr("Empty GPG Data"));
  connect(m_ui.action_Clear,
	  SIGNAL(triggered(void)),
	  m_ui.public_keys,
	  SLOT(clear(void)));
  connect(m_ui.action_Remove_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveGPGKeys(void)));
  connect(m_ui.email_addresses,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotShowCurrentDump(int)));
  connect(m_ui.importButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotImport(void)));
  connect(m_ui.deleteContact,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRemoveGPGKey(void)));
  setWindowTitle(tr("%1: Rosetta GPG Import").arg(SPOTON_APPLICATION_NAME));
}

spoton_rosetta_gpg_import::~spoton_rosetta_gpg_import()
{
}

QString spoton_rosetta_gpg_import::dump(const QByteArray &data)
{
#ifdef SPOTON_GPGME_ENABLED
  if(data.trimmed().isEmpty())
    return tr("Empty GPG Data");

  gpgme_check_version(nullptr);

  auto dump(tr("Empty GPG Data"));
  gpgme_ctx_t ctx = nullptr;

  if(gpgme_new(&ctx) == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t keydata = nullptr;
      auto err = gpgme_data_new_from_mem
	// 1 = A private copy.
	(&keydata, data.constData(), static_cast<size_t> (data.length()), 1);

      if(err == GPG_ERR_NO_ERROR && keydata)
	{
	  err = gpgme_op_keylist_from_data_start(ctx, keydata, 0);

	  while(err == GPG_ERR_NO_ERROR)
	    {
	      gpgme_key_t key = nullptr;

	      if(gpgme_op_keylist_next(ctx, &key) != GPG_ERR_NO_ERROR)
		break;

	      QString email("");
	      QString fingerprint("");
	      QString keyid("");
	      QString name("");

	      if(key->uids && key->uids->email)
		email = key->uids->email;

	      if(key->fpr)
		fingerprint = key->fpr;

	      if(key->subkeys->keyid)
		keyid = key->subkeys->keyid;

	      if(key->uids && key->uids->name)
		name = key->uids->name;

	      dump = tr("E-Mail: %1<br>"
			"Key ID: %2<br>"
			"Name: %3<br>"
			"Fingerprint: %4").
		arg(email).
		arg(keyid).
		arg(name).
		arg(fingerprint);
	      gpgme_key_unref(key);
	      break;
	    }
	}

      gpgme_data_release(keydata);
    }

  gpgme_release(ctx);
  return dump;
#else
  Q_UNUSED(data);
  return tr("Empty GPG Data");
#endif
}

QString spoton_rosetta_gpg_import::email(const QByteArray &data)
{
#ifdef SPOTON_GPGME_ENABLED
  if(data.trimmed().isEmpty())
    return "";

  gpgme_check_version(nullptr);

  QString email("");
  gpgme_ctx_t ctx = nullptr;

  if(gpgme_new(&ctx) == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t keydata = nullptr;
      auto err = gpgme_data_new_from_mem
	// 1 = A private copy.
	(&keydata, data.constData(), static_cast<size_t> (data.length()), 1);

      if(err == GPG_ERR_NO_ERROR && keydata)
	{
	  err = gpgme_op_keylist_from_data_start(ctx, keydata, 0);

	  while(err == GPG_ERR_NO_ERROR)
	    {
	      gpgme_key_t key = nullptr;

	      if(gpgme_op_keylist_next(ctx, &key) != GPG_ERR_NO_ERROR)
		break;

	      if(key->uids && key->uids->email)
		email = QString(key->uids->email).trimmed();

	      gpgme_key_unref(key);
	      break;
	    }
	}

      gpgme_data_release(keydata);
    }

  gpgme_release(ctx);
  return email;
#else
  Q_UNUSED(data);
  return "";
#endif
}

void spoton_rosetta_gpg_import::showCurrentDump(void)
{
#ifdef SPOTON_GPGME_ENABLED
  m_ui.email_addresses->clear();
  m_ui.public_keys->clear();
  m_ui.public_keys_dump->setText(tr("Empty GPG Data"));

  auto crypt = m_spoton->crypts().value("rosetta", nullptr);

  if(!crypt)
    {
      m_ui.email_addresses->addItem("Empty"); // Please do not translate Empty.
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QMap<QString, QByteArray> map;
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
	      auto ok = true;
	      auto publicKey
		(QByteArray::fromBase64(query.value(0).toByteArray()));

	      publicKey = crypt->decryptedAfterAuthenticated(publicKey, &ok);

	      if(!(email = this->email(publicKey)).isEmpty())
		map[email] = publicKey;

	      spoton_crypt::memzero(publicKey);
	    }
	else
	  m_ui.public_keys_dump->setText(tr("Empty GPG Data"));
      }
    else
      m_ui.public_keys_dump->setText(tr("Empty GPG Data"));

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QMapIterator<QString, QByteArray> it(map);

  while(it.hasNext())
    {
      it.next();
      m_ui.email_addresses->addItem(it.key(), it.value());
    }

  if(m_ui.email_addresses->count() > 0)
    m_ui.email_addresses->setCurrentIndex(0);
  else
    m_ui.email_addresses->addItem("Empty"); // Please do not translate Empty.

  QApplication::restoreOverrideCursor();
#endif
}

void spoton_rosetta_gpg_import::showNormal(void)
{
  showCurrentDump();
  QMainWindow::showNormal();
}

void spoton_rosetta_gpg_import::slotGPGKeysRemoved(void)
{
  m_ui.email_addresses->clear();
  m_ui.email_addresses->addItem("Empty"); // Please do not translate Empty.
  m_ui.public_keys->clear();
  m_ui.public_keys_dump->setText(tr("Empty GPG Data"));
}

void spoton_rosetta_gpg_import::slotImport(void)
{
#ifdef SPOTON_GPGME_ENABLED
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  QString error("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS gpg ("
		   "public_keys TEXT NOT NULL, "
		   "public_keys_hash TEXT NOT NULL PRIMARY KEY)");

	auto crypt = m_spoton->crypts().value("rosetta", nullptr);

	if(crypt)
	  {
	    auto publicKey
	      (m_ui.public_keys->toPlainText().trimmed().toUtf8());
	    auto ok = true;

	    if(!publicKey.isEmpty())
	      {
		auto const fingerprint(spoton_crypt::fingerprint(publicKey));

		if(fingerprint.isEmpty())
		  {
		    error = tr("GPGME error. Please verify that the "
			       "provided keys are correct.");
		    ok = false;
		  }

		query.prepare("INSERT OR REPLACE INTO gpg "
			      "(public_keys, public_keys_hash) VALUES (?, ?)");

		if(ok)
		  query.addBindValue
		    (crypt->encryptedThenHashed(publicKey, &ok).toBase64());

		if(ok)
		  query.addBindValue
		    (crypt->keyedHash(fingerprint, &ok).toBase64());

		if(ok)
		  {
		    if(!query.exec())
		      error = tr("A database error occurred.");
		  }
		else if(error.isEmpty())
		  error = tr("A cryptographic error occurred.");
	      }
	    else
	      error = tr("Please provide non-empty keys.");

	    spoton_crypt::memzero(publicKey);
	  }
	else
	  error = tr("Invalid crypt object. Critical error.");
      }
    else
      error = tr("Unable to access the database idiotes.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    {
      m_ui.public_keys->selectAll();
      emit gpgKeysImported();
    }

  showCurrentDump();
#endif
}

void spoton_rosetta_gpg_import::slotRemoveGPGKey(void)
{
  auto const publicKey(m_ui.email_addresses->currentData().toByteArray());

  if(publicKey.isEmpty())
    return;

  auto crypt = m_spoton->crypts().value("rosetta", nullptr);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QMessageBox mb(this);
  auto const email(this->email(publicKey));

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

  if(!email.isEmpty())
    mb.setText
      (tr("Are you sure that you wish to remove the GPG keys "
	  "for %1? The keys will not be removed from the GPG ring.").
       arg(email));
  else
    mb.setText
      (tr("Are you sure that you wish to remove the GPG keys "
	  "for the selected e-mail address? The keys will not be removed "
	  "from the GPG ring."));

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
  auto ok = false;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM gpg WHERE public_keys_hash = ?");
	query.addBindValue
	  (crypt->keyedHash(spoton_crypt::fingerprint(publicKey), &ok).
	   toBase64());

	if(query.exec())
	  ok = true;
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      m_ui.email_addresses->removeItem(m_ui.email_addresses->currentIndex());

      if(m_ui.email_addresses->count() == 0)
	{
	  m_ui.email_addresses->addItem
	    ("Empty"); // Please do not translate Empty.
	  m_ui.public_keys->clear();
	  m_ui.public_keys_dump->setText(tr("Empty GPG Data"));
	}

      emit gpgKeysRemoved();
    }
}

void spoton_rosetta_gpg_import::slotRemoveGPGKeys(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove your GPG keys? "
		"The keys will not be removed from the GPG ring."));
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
  auto ok = false;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(query.exec("DELETE FROM gpg"))
	  ok = true;
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      m_ui.email_addresses->clear();
      m_ui.email_addresses->addItem("Empty"); // Please do not translate Empty.
      m_ui.public_keys->clear();
      m_ui.public_keys_dump->setText(tr("Empty GPG Data"));
      emit gpgKeysRemoved();
    }
}

void spoton_rosetta_gpg_import::slotShowCurrentDump(int index)
{
  Q_UNUSED(index);
  m_ui.public_keys->setPlainText
    (m_ui.email_addresses->currentData().toByteArray());
  m_ui.public_keys_dump->setText
    (dump(m_ui.email_addresses->currentData().toByteArray()));
}
