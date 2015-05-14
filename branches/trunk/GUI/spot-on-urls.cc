/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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
#include <QFileInfo>
#include <QMessageBox>
#include <QProgressDialog>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "spot-on.h"
#include "spot-on-defines.h"
#include "ui_postgresqlconnect.h"

void spoton::prepareUrlLabels(void)
{
  QString connectionName("");
  int importCount = 0;
  int remoteCount = 0;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(crypt)
    {
      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "urls_key_information.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    QStringList queries;
	    bool ok = true;
	    int counts[2] = {0, 0};

	    query.setForwardOnly(true);
	    queries << "SELECT * FROM import_key_information"
		    << "SELECT * FROM remote_key_information";

	    for(int i = 0; i < queries.size(); i++)
	      if(query.exec(queries.at(i)) && query.next())
		for(int j = 0; j < query.record().count(); j++)
		  {
		    QByteArray bytes;

		    bytes = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(j).
					      toByteArray()),
		       &ok).constData();

		    if(ok)
		      counts[i] = 1;
		    else
		      {
			counts[i] = 0;
			break;
		      }
		  }

	    importCount = counts[0];
	    remoteCount = counts[1];
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  if(importCount > 0)
    m_ui.importCredentialsLabel->setText
      (tr("Import credentials have been prepared."));
  else
    m_ui.importCredentialsLabel->setText
      (tr("Import credentials have not been set."));

  if(remoteCount > 0)
    m_ui.commonCredentialsLabel->setText
      (tr("Common credentials have been prepared."));
  else
    m_ui.commonCredentialsLabel->setText
      (tr("Common credentials have not been set."));
}

void spoton::slotPrepareUrlDatabases(void)
{
  QProgressDialog progress(this);
  bool created = true;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Creating URL databases..."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Creating URL Databases").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

#if SPOTON_GOLDBUG == 0
  slotPostgreSQLDisconnect(m_ui.urls_db_type->currentIndex());
#endif
  created = spoton_misc::prepareUrlDistillersDatabase();

  if(created)
    created = spoton_misc::prepareUrlKeysDatabase();

  progress.update();

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;
	    QSqlQuery query(m_urlDatabase);

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    if(m_urlDatabase.driverName() == "QPSQL")
	      {
		if(!query.exec(QString("CREATE TABLE "
				       "spot_on_keywords_%1%2 ("
				       "keyword_hash TEXT NOT NULL, "
				       "url_hash TEXT NOT NULL, "
				       "PRIMARY KEY "
				       "(keyword_hash, url_hash))").
			       arg(c1).arg(c2)))
		  created = false;

		if(!query.exec(QString("GRANT INSERT, SELECT, UPDATE ON "
				       "spot_on_keywords_%1%2 TO "
				       "spot_on_user").
			       arg(c1).arg(c2)))
		  created = false;
	      }
	    else
	      if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				     "spot_on_keywords_%1%2 ("
				     "keyword_hash TEXT NOT NULL, "
				     "url_hash TEXT NOT NULL, "
				     "PRIMARY KEY (keyword_hash, url_hash))").
			     arg(c1).arg(c2)))
		created = false;

	    if(m_urlDatabase.driverName() == "QPSQL")
	      {
		if(!query.exec(QString("CREATE TABLE "
				       "spot_on_urls_%1%2 ("
				       "date_time_inserted TEXT NOT NULL, "
				       "description BYTEA, "
				       "title BYTEA NOT NULL, "
				       "url BYTEA NOT NULL, "
				       "url_hash TEXT PRIMARY KEY NOT NULL)").
			       arg(c1).arg(c2)))
		  created = false;

		if(!query.exec(QString("GRANT INSERT, SELECT, UPDATE ON "
				       "spot_on_urls_%1%2 TO "
				       "spot_on_user").
			       arg(c1).arg(c2)))
		  created = false;
	      }
	    else
	      if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				     "spot_on_urls_%1%2 ("
				     "date_time_inserted TEXT NOT NULL, "
				     "description BYTEA, "
				     "title BYTEA NOT NULL, "
				     "url BYTEA NOT NULL, "
				     "url_hash TEXT PRIMARY KEY NOT NULL)").
			     arg(c1).arg(c2)))
		created = false;
	  }
	else
	  created = false;

	processed += 1;
	progress.update();
#ifndef Q_OS_MAC
	QApplication::processEvents();
#endif
      }

  progress.hide();

  if(!created)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while attempting "
			     "to create the URL databases."));
}

void spoton::slotDeleteAllUrls(void)
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
  mb.setText(tr("Are you sure that you wish to vacuum all of the "
		"URL databases? Your credentials will also be removed."));

  if(mb.exec() != QMessageBox::Yes)
    return;

  bool deleted = deleteAllUrls();

  delete m_urlCommonCrypt;
  m_urlCommonCrypt = 0;
  prepareUrlLabels();

  if(!deleted)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while "
			     "attempting to vacuum the URL databases."));
}

bool spoton::deleteAllUrls(void)
{
  QProgressDialog progress(this);
  bool deleted = true;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Vacuuming URL databases..."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Vacuuming URL Databases").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;
	    QSqlQuery query(m_urlDatabase);

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    if(m_urlDatabase.driverName() != "QPSQL")
	      query.exec("PRAGMA secure_delete = ON");

	    if(!query.exec(QString("DELETE FROM "
				   "spot_on_keywords_%1%2").
			   arg(c1).arg(c2)))
	      deleted = false;

	    if(!query.exec(QString("DELETE FROM "
				   "spot_on_urls_%1%2").
			   arg(c1).arg(c2)))
	      deleted = false;
	  }
	else
	  deleted = false;

	  processed += 1;
	  progress.update();
#ifndef Q_OS_MAC
	  QApplication::processEvents();
#endif
      }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");

	if(!query.exec("DELETE FROM import_key_information"))
	  deleted = false;

	if(!query.exec("DELETE FROM remote_key_information"))
	  deleted = false;
      }
    else
      deleted = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return deleted;
}

void spoton::slotGatherUrlStatistics(void)
{
  QProgressDialog progress(this);
  int processed = 0;
  qint64 count = 0;
  quint64 size = 0;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Gathering URL statistics..."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Gathering URL Statistics").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  for(int i = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;
	    QSqlQuery query(m_urlDatabase);

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    query.setForwardOnly(true);

	    if(query.exec(QString("SELECT COUNT(*) FROM spot_on_urls_%1%2").
			  arg(c1).arg(c2)))
	      if(query.next())
		count += query.value(0).toLongLong();

	    if(query.exec(QString("SELECT pg_total_relation_size"
				  "('\"spot_on_urls_%1%2\"')").
			  arg(c1).arg(c2)))
	      if(query.next())
		size += query.value(0).toLongLong();
	  }

	processed += 1;
	progress.update();
#ifndef Q_OS_MAC
	QApplication::processEvents();
#endif
      }
}

void spoton::slotImportUrls(void)
{
  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  if(!m_urlCommonCrypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Did you prepare common credentials?"));
      return;
    }

  /*
  ** We need to determine the encryption key that was
  ** used to encrypt the URLs shared by another application.
  */

  QByteArray symmetricKey;
  QString cipherType("");
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, symmetric_key "
		      "FROM import_key_information") &&
	   query.next())
	  {
	    cipherType = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok).constData();

	    if(ok)
	      symmetricKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(1).
					toByteArray()),
		 &ok);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  int readEncrypted = 1;

  if(cipherType.isEmpty() || symmetricKey.isEmpty())
    readEncrypted = 0;

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Importing URLs..."));
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Importing URLs").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "shared.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) from urls"))
	  if(query.next())
	    progress.setMaximum(query.value(0).toInt());

	query.prepare("SELECT description, encrypted, title, url "
		      "FROM urls");

	if(query.exec())
	  {
	    int processed = 0;

	    while(query.next())
	      {
		if(progress.wasCanceled())
		  break;

		if(processed <= progress.maximum())
		  progress.setValue(processed);

		QByteArray description;
		QByteArray title;
		QByteArray url;
		bool encrypted = query.value(1).toBool();
		bool ok = true;

		if(encrypted)
		  {
		    if(!readEncrypted)
		      continue;

		    spoton_crypt crypt
		      (cipherType,
		       QString(""),
		       QByteArray(),
		       symmetricKey,
		       0,
		       0,
		       QString(""));

		    description = crypt.decrypted
		      (query.value(0).toByteArray(), &ok);

		    if(ok)
		      title = crypt.decrypted
			(query.value(2).toByteArray(), &ok);

		    if(ok)
		      url = crypt.decrypted
			(query.value(3).toByteArray(), &ok);
		  }
		else
		  {
		    description = query.value(0).toByteArray();
		    title = query.value(2).toByteArray();
		    url = query.value(3).toByteArray();
		  }

		if(ok)
		  importUrl(description, title, url);

		QSqlQuery deleteQuery(db);

		deleteQuery.exec("PRAGMA secure_delete = ON");
		deleteQuery.prepare("DELETE FROM urls WHERE url = ?");
		deleteQuery.bindValue(0, query.value(3));
		deleteQuery.exec();
		processed += 1;
		progress.update();
#ifndef Q_OS_MAC
		QApplication::processEvents();
#endif
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotShowUrlSettings(void)
{
  m_ui.urlSettings->setVisible(!m_ui.urlSettings->isVisible());
  m_ui.urlsBox->setVisible(!m_ui.urlSettings->isVisible());

#if SPOTON_GOLDBUG == 0
  if(m_ui.urlsBox->isVisible())
    m_ui.urls_settings_layout->addWidget(m_ui.importUrls);
  else
    m_ui.urls_import_layout->addWidget(m_ui.importUrls);
#endif
}

void spoton::slotSelectUrlIniPath(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select INI Path").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setFilter(QDir::AllEntries | QDir::Hidden);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveUrlIniPath(dialog.selectedFiles().value(0));
}

void spoton::saveUrlIniPath(const QString &path)
{
  m_settings["gui/urlIniPath"] = path;

  QSettings settings;

  settings.setValue("gui/urlIniPath", path);
  m_ui.urlIniPath->setText(path);
  m_ui.urlIniPath->setToolTip(path);
  m_ui.urlIniPath->selectAll();

  {
    QSettings settings(path, QSettings::IniFormat);

    for(int i = 0; i < settings.allKeys().size(); i++)
      {
	QString key(settings.allKeys().at(i));
	QVariant value(settings.value(key));

	if(key.toLower().contains("ciphertype"))
	  {
	    if(m_ui.urlCipher->findText(value.toString()) >= 0)
	      m_ui.urlCipher->setCurrentIndex
		(m_ui.urlCipher->findText(value.toString()));
	  }
	else if(key.toLower().contains("hash") &&
		value.toByteArray().length() >= 64)
	  m_ui.urlIniHash->setText(value.toByteArray().toHex());
	else if(key.toLower().contains("hashtype"))
	  {
	    if(m_ui.urlHash->findText(value.toString()) >= 0)
	      m_ui.urlHash->setCurrentIndex
		(m_ui.urlHash->findText(value.toString()));
	  }
	else if(key.toLower().contains("iteration"))
	  m_ui.urlIteration->setValue(value.toInt());
	else if(key.toLower().contains("salt") &&
		value.toByteArray().length() >= 100)
	  m_ui.urlSalt->setText(value.toByteArray().toHex());
      }
  }
}

void spoton::slotSetUrlIniPath(void)
{
  saveUrlIniPath(m_ui.urlIniPath->text());
}

void spoton::slotVerify(void)
{
  QByteArray computedHash;
  QByteArray salt
    (QByteArray::fromHex(m_ui.urlSalt->text().toLatin1()));
  QByteArray saltedPassphraseHash
    (QByteArray::fromHex(m_ui.urlIniHash->text().toLatin1()));
  QString error("");
  bool ok = false;

  computedHash = spoton_crypt::saltedPassphraseHash
    (m_ui.urlHash->currentText(), m_ui.urlPassphrase->text(), salt, error);

  if(!computedHash.isEmpty() && !saltedPassphraseHash.isEmpty() &&
     spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
    if(error.isEmpty())
      ok = true;

  if(ok)
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The provided credentials are correct. Please save the "
	  "information!"));
  else
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The provided credentials are incorrect."));
}

void spoton::slotSaveUrlCredentials(void)
{
  QByteArray salt
    (QByteArray::fromHex(m_ui.urlSalt->text().toLatin1()));
  QPair<QByteArray, QByteArray> keys;
  QString error("");
  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys(m_ui.urlCipher->currentText(),
				   m_ui.urlHash->currentText(),
				   m_ui.urlIteration->value(),
				   m_ui.urlPassphrase->text(),
				   salt,
				   64, // Dooble.
				   error);
  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "urls_key_information.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare
	      ("INSERT OR REPLACE INTO import_key_information "
	       "(cipher_type, symmetric_key) "
	       "VALUES (?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(m_ui.urlCipher->currentText().
					     toLatin1(),
					     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->
		 encryptedThenHashed(keys.first, &ok).toBase64());

	    if(ok)
	      {
		if(!query.exec())
		  error = tr
		    ("Database write error. "
		     "Is urls_key_information.db properly defined?");
	      }
	    else
	      error = tr("An error occurred with "
			 "spoton_crypt::encryptedThenHashed().");
	  }
	else
	  error = tr("Unable to access urls_key_information.db.");

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
  else
    error = tr("Key generation failure.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  error);
  else
    {
      m_ui.urlCipher->setCurrentIndex(0);
      m_ui.urlHash->setCurrentIndex(0);
      m_ui.urlIniHash->clear();
      m_ui.urlIteration->setValue(10000);
      m_ui.urlPassphrase->clear();
      m_ui.urlSalt->clear();
      prepareUrlLabels();
    }
}

void spoton::importUrl(const QByteArray &d, // Description
		       const QByteArray &t, // Title
		       const QByteArray &u) // URL
{
  /*
  ** We do not use explicit database transactions.
  */

  if(!m_urlCommonCrypt)
    return;

  if(!m_urlDatabase.isOpen())
    return;

  QUrl url(QUrl::fromUserInput(u));

  if(url.isEmpty() || !url.isValid())
    return;

  QByteArray all_keywords;
  QByteArray description(d.trimmed());
  QByteArray title(t.trimmed());
  bool separate = true;

  if(description.isEmpty())
    description = url.toString().toUtf8();
  else
    all_keywords = description;

  if(title.isEmpty())
    title = url.toString().toUtf8();
  else
    all_keywords.append(" ").append(title);

  QByteArray urlHash;
  bool ok = true;

  urlHash = m_urlCommonCrypt->keyedHash(url.toEncoded(), &ok).toHex();

  if(!ok)
    return;

  QSqlQuery query(m_urlDatabase);

  query.prepare
    (QString("INSERT INTO spot_on_urls_%1 ("
	     "date_time_inserted, "
	     "description, "
	     "title, "
	     "url, "
	     "url_hash) VALUES (?, ?, ?, ?, ?)").
     arg(urlHash.mid(0, 2).constData()));
  query.bindValue(0, QDateTime::currentDateTime().toString(Qt::ISODate));
  query.bindValue
    (1, m_urlCommonCrypt->encryptedThenHashed(description, &ok).
     toBase64());

  if(ok)
    query.bindValue
      (2, m_urlCommonCrypt->encryptedThenHashed(title, &ok).toBase64());

  if(ok)
    query.bindValue
      (3, m_urlCommonCrypt->encryptedThenHashed(url.toEncoded(), &ok).
       toBase64());

  if(ok)
    query.bindValue(4, urlHash.constData());

  if(ok)
    ok = query.exec();

  if(ok)
    if(all_keywords.isEmpty())
      separate = false;

  if(ok && separate)
    {
      QStringList keywords
	(QString::fromUtf8(all_keywords.toLower().constData()).
	 split(QRegExp("\\W+"), QString::SkipEmptyParts));

      for(int i = 0; i < keywords.size(); i++)
	{
	  QByteArray keywordHash;
	  QSqlQuery query(m_urlDatabase);

	  keywordHash = m_urlCommonCrypt->keyedHash
	    (keywords.at(i).toUtf8(), &ok).toHex();

	  if(!ok)
	    break;

	  query.prepare
	    (QString("INSERT INTO spot_on_keywords_%1 ("
		     "keyword_hash, "
		     "url_hash) "
		     "VALUES (?, ?)").arg(keywordHash.mid(0, 2).
					  constData()));
	  query.bindValue(0, keywordHash.constData());
	  query.bindValue(1, urlHash.constData());
	  query.exec();
	}
    }
}

void spoton::slotPostgreSQLConnect(void)
{
  if(m_ui.postgresqlConnect->
     property("user_text").toString() == "disconnect")
    {
      m_ui.postgresqlConnect->setProperty("user_text", "connect");
      m_ui.postgresqlConnect->setText(tr("PostgreSQL Connect"));
      m_urlDatabase.close();
      m_urlDatabase = QSqlDatabase();

      if(QSqlDatabase::contains("URLDatabase"))
	QSqlDatabase::removeDatabase("URLDatabase");

      return;
    }

  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QByteArray password;
  QDialog dialog(this);
  QSettings settings;
  Ui_postgresqlconnect ui;
  bool ok = true;

  password = crypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.value("gui/postgresql_password", "").
			    toByteArray()), &ok);
  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: PostgreSQL Connect").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.database->setText(settings.value("gui/postgresql_database", "").
		       toString().trimmed());
  ui.database->selectAll();
  ui.database->setFocus();
  ui.host->setText(settings.value("gui/postgresql_host", "localhost").
		   toString().trimmed());
  ui.name->setText(settings.value("gui/postgresql_name", "").toString().
		   trimmed());

  if(ok)
    ui.password->setText(password);

  ui.port->setValue(settings.value("gui/postgresql_port", 5432).
		    toInt());
  ui.ssltls->setChecked(settings.value("gui/postgresql_ssltls", false).
			toBool());

  if(dialog.exec() == QDialog::Accepted)
    {
      m_urlDatabase.close();
      m_urlDatabase = QSqlDatabase();

      if(QSqlDatabase::contains("URLDatabase"))
	QSqlDatabase::removeDatabase("URLDatabase");

      m_urlDatabase = QSqlDatabase::addDatabase("QPSQL", "URLDatabase");

      QString str("connect_timeout=10");

      if(ui.ssltls->isChecked())
	str.append(";requiressl=1");

      m_urlDatabase.setConnectOptions(str);
      m_urlDatabase.setHostName(ui.host->text());
      m_urlDatabase.setDatabaseName(ui.database->text());
      m_urlDatabase.setPort(ui.port->value());
      m_urlDatabase.open(ui.name->text(), ui.password->text());

      if(!m_urlDatabase.isOpen())
	{
	  QString str(m_urlDatabase.lastError().text().trimmed());

	  m_urlDatabase = QSqlDatabase();

	  if(QSqlDatabase::contains("URLDatabase"))
	    QSqlDatabase::removeDatabase("URLDatabase");

	  QMessageBox::critical
	    (this, tr("%1: Error").
	     arg(SPOTON_APPLICATION_NAME),
	     tr("Could not open (%1) a database connection.").
	     arg(str));
	}
      else
	{
	  m_ui.postgresqlConnect->setProperty("user_text", "disconnect");
	  m_ui.postgresqlConnect->setText(tr("PostgreSQL Disconnect"));
	  settings.setValue("gui/postgresql_database",
			    ui.database->text());
	  settings.setValue("gui/postgresql_host",
			    ui.host->text());
	  settings.setValue("gui/postgresql_name", ui.name->text());

	  bool ok = true;

	  settings.setValue
	    ("gui/postgresql_password",
	     crypt->encryptedThenHashed(ui.password->text().toUtf8(),
					&ok).toBase64());

	  if(!ok)
	    settings.remove("gui/postgresql_password");

	  settings.setValue("gui/postgresql_port", ui.port->value());
	  settings.setValue("gui/postgresql_ssltls", ui.ssltls->isChecked());
	}
    }
}

void spoton::slotSaveCommonUrlCredentials(void)
{
  QPair<QByteArray, QByteArray> keys;
  QString error("");
  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys(m_ui.commonUrlCipher->currentText(),
				   m_ui.commonUrlHash->currentText(),
				   m_ui.commonUrlIterationCount->value(),
				   m_ui.commonUrlPassphrase->text(),
				   m_ui.commonUrlPin->text().toUtf8(),
				   error);
  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "urls_key_information.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare
	      ("INSERT OR REPLACE INTO remote_key_information "
	       "(cipher_type, encryption_key, hash_key, hash_type) "
	       "VALUES (?, ?, ?, ?)");
	    query.bindValue
	      (0,
	       crypt->encryptedThenHashed(m_ui.commonUrlCipher->currentText().
					  toLatin1(),
					  &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->
		 encryptedThenHashed(keys.first, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->
		 encryptedThenHashed(keys.second, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->
		 encryptedThenHashed(m_ui.commonUrlHash->currentText().
				     toLatin1(),
				     &ok).toBase64());

	    if(ok)
	      {
		if(!query.exec())
		  error = tr
		    ("Database write error. Is urls_key_information.db "
		     "properly defined?");
	      }
	    else
	      error = tr("An error occurred with "
			 "spoton_crypt::encryptedThenHashed().");
	  }
	else
	  error = tr("Unable to access urls_key_information.db.");

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
  else
    error = tr("Key generation failure.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  error);
  else
    {
      m_ui.commonUrlCipher->setCurrentIndex(0);
      m_ui.commonUrlHash->setCurrentIndex(0);
      m_ui.commonUrlIterationCount->setValue(10000);
      m_ui.commonUrlPassphrase->clear();
      m_ui.commonUrlPin->clear();
      prepareUrlContainers();
      prepareUrlLabels();
    }
}

void spoton::slotAddDistiller(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QString connectionName("");
  QString error("");
  QUrl url(QUrl::fromUserInput(m_ui.domain->text().trimmed()));
  bool ok = true;

  if(url.isEmpty() || !url.isValid())
    {
      error = tr("Invalid domain.");
      ok = false;
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	QByteArray domain
	  (url.scheme().toLatin1() + "://" +
	   url.host().toUtf8() + url.path().toUtf8());
	QSqlQuery query(db);

	query.prepare("INSERT INTO distillers "
		      "(direction, "
		      "domain, "
		      "domain_hash) "
		      "VALUES "
		      "(?, ?, ?)");

	if(m_ui.downDist->isChecked())
	  query.bindValue(0, "download");
	else
	  query.bindValue(0, "upload");

	query.bindValue
	  (1,
	   crypt->encryptedThenHashed(domain, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(domain, &ok).toBase64());

	if(ok)
	  ok = query.exec();

	if(query.lastError().isValid())
	  error = query.lastError().text().trimmed();
      }
    else
      {
	ok = false;

	if(db.lastError().isValid())
	  error = db.lastError().text();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    {
      m_ui.domain->selectAll();
      populateUrlDistillers();
    }
  else if(error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to add the specified URL domain. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while attempting "
			     "to add the specified URL domain. "
			     "Please enable logging via the Log Viewer "
			     "and try again.").arg(error));
}

void spoton::populateUrlDistillers(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	m_ui.downDistillers->clear();
	m_ui.upDistillers->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT direction, domain FROM distillers");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray domain;
	      QString direction
		(query.value(0).toString().toLower().trimmed());
	      bool ok = true;

	      domain = crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(1).
						       toByteArray()),
					    &ok);

	      if(ok)
		{
		  if(direction == "download")
		    m_ui.downDistillers->addItem
		      (QString::fromUtf8(domain.constData()));
		  else
		    m_ui.upDistillers->addItem
		      (QString::fromUtf8(domain.constData()));
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshUrlDistillers(void)
{
  populateUrlDistillers();
}

void spoton::slotDeleteUrlDistillers(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QList<QListWidgetItem *> list;
  QString direction("");

  if(m_ui.urlTab->currentIndex() == 0)
    {
      direction = "download";
      list = m_ui.downDistillers->selectedItems();
    }
  else
    {
      direction = "upload";
      list = m_ui.upDistillers->selectedItems();
    }

  if(list.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      while(!list.isEmpty())
	{
	  QListWidgetItem *item = list.takeFirst();

	  if(!item)
	    continue;

	  QSqlQuery query(db);
	  bool ok = true;

	  query.exec("PRAGMA secure_delete = ON");
	  query.prepare("DELETE FROM distillers WHERE "
			"direction = ? AND domain_hash = ?");
	  query.bindValue(0, direction);
	  query.bindValue(1, crypt->keyedHash(item->text().toUtf8(),
					      &ok).toBase64());

	  if(ok)
	    query.exec();
	}

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  populateUrlDistillers();
}

void spoton::slotDeleteLink(const QUrl &u)
{
  QString scheme(u.scheme().toLower().trimmed());
  QUrl url(u);

  if(!scheme.startsWith("delete-"))
    {
      if(m_settings.value("gui/openLinks", false).toBool())
	QDesktopServices::openUrl(u);

      return;
    }
  else
    {
      scheme.remove("delete-");
      url.setScheme(scheme);
    }

  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }
  else if(!m_urlCommonCrypt)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid m_urlCommonCrypt object. This is a fatal flaw."));
      return;
    }
  else if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  QByteArray urlHash;
  bool ok = true;

  urlHash = m_urlCommonCrypt->keyedHash(url.toEncoded(), &ok).toHex();

  if(!ok)
    return;

  /*
  ** Let's first remove the URL from the correct URL table.
  */

  QSqlQuery query(m_urlDatabase);

  if(m_urlDatabase.driverName() != "QPSQL")
    query.exec("PRAGMA secure_delete = ON");

  query.prepare(QString("DELETE FROM spot_on_urls_%1 "
			"WHERE url_hash = ?").
		arg(urlHash.mid(0, 2).constData()));
  query.bindValue(0, urlHash.constData());

  if(!query.exec())
    if(query.lastError().text().toLower().contains("permission denied"))
      {
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("Invalid permissions."));
	return;
      }

  /*
  ** Now, we must remove the URL from all of the keywords tables.
  */

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Deleting URL keywords..."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setWindowModality(Qt::ApplicationModal);
  progress.setWindowTitle(tr("%1: Deleting URL Keywords").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

	QChar c1;
	QChar c2;
	QSqlQuery query(m_urlDatabase);

	if(i <= 9)
	  c1 = QChar(i + 48);
	else
	  c1 = QChar(i + 97 - 10);

	if(j <= 9)
	  c2 = QChar(j + 48);
	else
	  c2 = QChar(j + 97 - 10);

	if(m_urlDatabase.driverName() != "QPSQL")
	  query.exec("PRAGMA secure_delete = ON");

	query.prepare(QString("DELETE FROM "
			      "spot_on_keywords_%1%2 WHERE "
			      "url_hash = ?").
		      arg(c1).arg(c2));
	query.bindValue(0, urlHash.constData());
	query.exec();

	processed += 1;
	progress.update();
#ifndef Q_OS_MAC
	QApplication::processEvents();
#endif
      }

  /*
  ** Finally, let's discover!
  */

  discoverUrls();
}
