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

#include <gpgme.h>
#endif

#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-rosetta-gpg-import.h"

spoton_rosetta_gpg_import::spoton_rosetta_gpg_import(spoton *parent):
  QMainWindow(parent)
{
  m_parent = parent;
  m_ui.setupUi(this);
  connect(m_ui.action_Clear,
	  SIGNAL(triggered(void)),
	  m_ui.private_keys,
	  SLOT(clear(void)));
  connect(m_ui.action_Clear,
	  SIGNAL(triggered(void)),
	  m_ui.public_keys,
	  SLOT(clear(void)));
  connect(m_ui.action_Remove_GPG_Keys,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveGPGKeys(void)));
  connect(m_ui.importButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotImport(void)));
  setWindowTitle(tr("%1: Rosetta GPG Import").arg(SPOTON_APPLICATION_NAME));
}

spoton_rosetta_gpg_import::~spoton_rosetta_gpg_import()
{
}

QByteArray spoton_rosetta_gpg_import::fingerprint(const QByteArray &data)
{
#ifdef SPOTON_GPGME_ENABLED
  QByteArray fingerprint;

  if(data.trimmed().isEmpty())
    return fingerprint;

  gpgme_check_version(0);

  gpgme_ctx_t ctx = 0;

  if(gpgme_new(&ctx) == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t keydata = 0;
      gpgme_error_t err = gpgme_data_new_from_mem
	// 1 = A private copy.
	(&keydata, data.constData(), static_cast<size_t> (data.length()), 1);

      if(err == GPG_ERR_NO_ERROR &&
	 keydata &&
	 gpgme_op_import(ctx, keydata) == GPG_ERR_NO_ERROR)
	{
	  gpgme_import_result_t result = gpgme_op_import_result(ctx);

	  if(result)
	    {
	      gpgme_import_status_t imports = result->imports;

	      if(imports && imports->fpr)
		fingerprint = QByteArray(imports->fpr);
	    }
	}

      gpgme_data_release(keydata);
    }

  gpgme_release(ctx);
  return fingerprint;
#else
  Q_UNUSED(data);
  return QByteArray();
#endif
}

QString spoton_rosetta_gpg_import::dump(const QByteArray &data)
{
#ifdef SPOTON_GPGME_ENABLED
  QString dump("");

  if(data.trimmed().isEmpty())
    return dump;

  gpgme_check_version(0);

  gpgme_ctx_t ctx = 0;

  if(gpgme_new(&ctx) == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t keydata = 0;
      gpgme_error_t err = gpgme_data_new_from_mem
	// 1 = A private copy.
	(&keydata, data.constData(), static_cast<size_t> (data.length()), 1);

      if(err == GPG_ERR_NO_ERROR &&
	 keydata &&
	 gpgme_op_import(ctx, keydata) == GPG_ERR_NO_ERROR)
	{
	  err = gpgme_op_keylist_start(ctx, 0, 0);

	  while(err == GPG_ERR_NO_ERROR)
	    {
	      gpgme_key_t key = 0;

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
	      gpgme_key_release(key);
	      break;
	    }
	}

      gpgme_data_release(keydata);
    }

  gpgme_release(ctx);
  return dump;
#else
  Q_UNUSED(data);
  return "";
#endif
}

QString spoton_rosetta_gpg_import::email(const QByteArray &data)
{
#ifdef SPOTON_GPGME_ENABLED
  QString email("");

  if(data.trimmed().isEmpty())
    return email;

  gpgme_check_version(0);

  gpgme_ctx_t ctx = 0;

  if(gpgme_new(&ctx) == GPG_ERR_NO_ERROR)
    {
      gpgme_data_t keydata = 0;
      gpgme_error_t err = gpgme_data_new_from_mem
	// 1 = A private copy.
	(&keydata, data.constData(), static_cast<size_t> (data.length()), 1);

      if(err == GPG_ERR_NO_ERROR &&
	 keydata &&
	 gpgme_op_import(ctx, keydata) == GPG_ERR_NO_ERROR)
	{
	  err = gpgme_op_keylist_start(ctx, 0, 0);

	  while(err == GPG_ERR_NO_ERROR)
	    {
	      gpgme_key_t key = 0;

	      if(gpgme_op_keylist_next(ctx, &key) != GPG_ERR_NO_ERROR)
		break;

	      if(key->uids && key->uids->email)
		email = key->uids->email;

	      gpgme_key_release(key);
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
  spoton_crypt *crypt = m_parent->crypts().value("rosetta", 0);

  if(!crypt)
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

	if(query.exec("SELECT private_keys, public_keys FROM gpg") &&
	   query.next())
	  {
	    QByteArray privateKeys
	      (QByteArray::fromBase64(query.value(0).toByteArray()));
	    QByteArray publicKeys
	      (QByteArray::fromBase64(query.value(1).toByteArray()));
	    bool ok = true;

	    privateKeys = crypt->decryptedAfterAuthenticated(privateKeys, &ok);
	    publicKeys = crypt->decryptedAfterAuthenticated(publicKeys, &ok);
	    m_ui.private_keys_dump->setText(dump(privateKeys));
	    m_ui.public_keys_dump->setText(dump(publicKeys));
	    spoton_crypt::memzero(privateKeys);
	    spoton_crypt::memzero(publicKeys);
	  }
	else
	  {
	    m_ui.private_keys_dump->setText(tr("GPG Dump"));
	    m_ui.public_keys_dump->setText(tr("GPG Dump"));
	  }
      }
    else
      {
	m_ui.private_keys_dump->setText(tr("GPG Dump"));
	m_ui.public_keys_dump->setText(tr("GPG Dump"));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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
  m_ui.private_keys_dump->setText(tr("GPG Dump"));
  m_ui.public_keys_dump->setText(tr("GPG Dump"));
}

void spoton_rosetta_gpg_import::slotImport(void)
{
#ifdef SPOTON_GPGME_ENABLED
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  QString error("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS gpg ("
		   "private_keys TEXT NOT NULL, "
		   "private_keys_hash TEXT NOT NULL, "
		   "public_keys TEXT NOT NULL, "
		   "public_keys_hash TEXT NOT NULL, "
		   "PRIMARY KEY (private_keys_hash, public_keys_hash))");

	spoton_crypt *crypt = m_parent->crypts().value("rosetta", 0);

	if(crypt)
	  {
	    QByteArray privateKeys
	      (m_ui.private_keys->toPlainText().trimmed().toUtf8());
	    QByteArray publicKeys
	      (m_ui.public_keys->toPlainText().trimmed().toUtf8());
	    bool ok = true;

	    if(!privateKeys.isEmpty() && !publicKeys.isEmpty())
	      {
		QByteArray fingerprint1(fingerprint(privateKeys));
		QByteArray fingerprint2(fingerprint(publicKeys));

		if(fingerprint1.isEmpty() || fingerprint2.isEmpty())
		  {
		    error = tr("GPGME error. Please verify that the "
			       "provide keys are correct.");
		    ok = false;
		  }
		else
		  {
		    m_ui.private_keys_dump->setText(dump(privateKeys));
		    m_ui.public_keys_dump->setText(dump(publicKeys));
		  }

		if(ok)
		  {
		    /*
		    ** Remove all other entries.
		    */

		    query.exec("PRAGMA secure_delete = ON");
		    query.exec("DELETE FROM gpg");
		  }

		query.prepare("INSERT OR REPLACE INTO gpg "
			      "(private_keys, "
			      "private_keys_hash, "
			      "public_keys, "
			      "public_keys_hash) "
			      "VALUES (?, ?, ?, ?)");

		if(ok)
		  query.addBindValue
		    (crypt->encryptedThenHashed(privateKeys, &ok).toBase64());

		if(ok)
		  query.addBindValue
		    (crypt->keyedHash(fingerprint1, &ok).toBase64());

		if(ok)
		  query.addBindValue
		    (crypt->encryptedThenHashed(publicKeys, &ok).toBase64());

		if(ok)
		  query.addBindValue
		    (crypt->keyedHash(fingerprint2, &ok).toBase64());

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

	    spoton_crypt::memzero(privateKeys);
	    spoton_crypt::memzero(publicKeys);
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

  if(QApplication::clipboard())
    QApplication::clipboard()->clear();
#endif
}

void spoton_rosetta_gpg_import::slotRemoveGPGKeys(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove your GPG keys?"));
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
	  {
	    m_ui.private_keys_dump->setText(tr("GPG Dump"));
	    m_ui.public_keys_dump->setText(tr("GPG Dump"));
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
