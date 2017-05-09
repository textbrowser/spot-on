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
#include <QFileInfo>
#include <QMessageBox>
#include <QPrinter>
#include <QProgressDialog>
#include <QSqlDriver>
#include <QtCore>

#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-pageviewer.h"
#include "spot-on-rss.h"
#include "spot-on-utilities.h"
#include "ui_spot-on-postgresql-connect.h"

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
		    crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(j).
					      toByteArray()),
		       &ok);

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
  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  if(!m_wizardHash.value("accepted", false))
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Please note that the database-preparation process may "
		    "require a considerable amount of time to complete. "
		    "The RSS mechanism and the kernel will be deactivated. "
		    "Proceed?"));
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	return;
      else
	{
	  m_rss->deactivate();
	  slotDeactivateKernel();
	}
    }

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QProgressDialog progress(this);
  bool created = true;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Creating URL databases. Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Creating URL Databases").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif
  created = spoton_misc::prepareUrlDistillersDatabase();

  if(created)
    created = spoton_misc::prepareUrlKeysDatabase();

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QSqlQuery query(m_urlDatabase);

  if(m_urlDatabase.driverName() == "QSQLITE")
    query.exec("PRAGMA journal_mode = OFF");

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    progress.setLabelText
	      (tr("Creating spot_on_keywords_%1%2. "
		  "Please be patient.").arg(c1).arg(c2));

	    if(m_urlDatabase.driverName() == "QPSQL")
	      {
		if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
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

	    progress.setLabelText
	      (tr("Creating spot_on_urls_%1%2. "
		  "Please be patient.").arg(c1).arg(c2));

	    if(m_urlDatabase.driverName() == "QPSQL")
	      {
		if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				       "spot_on_urls_%1%2 ("
				       "content BYTEA NOT NULL, "
				       "date_time_inserted TEXT NOT NULL, "
				       "description BYTEA, "
				       "title BYTEA NOT NULL, "
				       "unique_id BIGINT UNIQUE, "
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
				     "content BLOB NOT NULL, "
				     "date_time_inserted TEXT NOT NULL, "
				     "description BLOB, "
				     "title BLOB NOT NULL, "
				     "unique_id INTEGER NOT NULL, "
				     "url BLOB NOT NULL, "
				     "url_hash TEXT PRIMARY KEY NOT NULL)").
			     arg(c1).arg(c2)))
		created = false;

	    progress.setLabelText
	      (tr("Creating spot_on_urls_revisions_%1%2. "
		  "Please be patient.").arg(c1).arg(c2));

	    if(m_urlDatabase.driverName() == "QPSQL")
	      {
		if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				       "spot_on_urls_revisions_%1%2 ("
				       "content BYTEA NOT NULL, "
				       "content_hash TEXT NOT NULL, "
				       "date_time_inserted TEXT NOT NULL, "
				       "url_hash TEXT NOT NULL, "
				       "PRIMARY KEY (content_hash, url_hash), "
				       "FOREIGN KEY(url_hash) REFERENCES "
				       "spot_on_urls_%1%2(url_hash) ON "
				       "DELETE CASCADE)").
			       arg(c1).arg(c2)))
		  created = false;

		if(!query.exec(QString("GRANT INSERT, SELECT, UPDATE ON "
				       "spot_on_urls_revisions_%1%2 TO "
				       "spot_on_user").
			       arg(c1).arg(c2)))
		  created = false;
	      }
	    else
	      if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				     "spot_on_urls_revisions_%1%2 ("
				     "content BYTEA NOT NULL, "
				     "content_hash TEXT NOT NULL, "
				     "date_time_inserted TEXT NOT NULL, "
				     "url_hash TEXT NOT NULL, "
				     "PRIMARY KEY "
				     "(content_hash, url_hash))").
			     arg(c1).arg(c2)))
		created = false;
	  }
	else
	  created = false;

	processed += 1;
      }

  if(created)
    {
      if(m_urlDatabase.driverName() == "QPSQL")
	{
	  if(!query.exec("CREATE SEQUENCE IF NOT EXISTS serial START 1"))
	    created = false;

	  if(!query.exec("GRANT SELECT, UPDATE, USAGE ON serial "
			 "TO spot_on_user"))
	    created = false;
	}
      else
	{
	  if(!query.exec("CREATE TABLE IF NOT EXISTS sequence("
			 "value INTEGER NOT NULL PRIMARY KEY "
			 "AUTOINCREMENT)"))
	    created = false;
	}
    }

  if(m_urlDatabase.driverName() == "QSQLITE")
    query.exec("PRAGMA journal_mode = DELETE");

  progress.close();
#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  if(!created)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while attempting "
			     "to create the URL databases."));
}

void spoton::slotDeleteAllUrls(void)
{
  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to delete most of the "
		"URL databases? Your credentials will also be removed. "
		"The shared.db database will not be removed. Please "
		"note that the deletion process may require "
		"a considerable amount of time to complete. The "
		"RSS mechanism and the kernel will be deactivated. "
		"Please also verify that you have proper administrator "
		"privileges."));
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    return;
  else
    {
      m_rss->deactivate();
      slotDeactivateKernel();
    }

  bool deleted = deleteAllUrls();

  delete m_urlCommonCrypt;
  m_urlCommonCrypt = 0;
  prepareUrlLabels();

  if(!deleted)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while "
			     "attempting to delete the URL data. "
			     "Please verify that you have correct "
			     "administrator privileges."));
}

void spoton::slotDropUrlTables(void)
{
  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to drop most of the "
		"URL tables? Your credentials will not be removed. "
		"The shared.db database will not be removed. Please "
		"note that the process may require "
		"a considerable amount of time to complete. The "
		"RSS mechanism and the kernel will be deactivated."));
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    return;
  else
    {
      m_rss->deactivate();
      slotDeactivateKernel();
    }

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QProgressDialog progress(this);
  bool dropped = true;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Dropping URL tables. Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Dropping URL Tables").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif

  QSqlQuery query(m_urlDatabase);

  if(m_urlDatabase.driverName() == "QPSQL")
    {
      if(!query.exec("DROP SEQUENCE IF EXISTS serial"))
	dropped = false;
    }
  else
    {
      if(!query.exec("DROP TABLE IF EXISTS sequence"))
	dropped = false;
    }

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    if(!query.exec(QString("DROP TABLE IF EXISTS "
				   "spot_on_keywords_%1%2").
			   arg(c1).arg(c2)))
	      dropped = false;

	    if(!query.exec(QString("DROP TABLE IF EXISTS "
				   "spot_on_urls_%1%2").
			   arg(c1).arg(c2)))
	      dropped = false;

	    if(!query.exec(QString("DROP TABLE IF EXISTS "
				   "spot_on_urls_revisions_%1%2").
			   arg(c1).arg(c2)))
	      dropped = false;
	  }
	else
	  dropped = false;

	processed += 1;
      }

  if(!dropped)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while "
			     "attempting to destroy the URL tables."));
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
  progress.setLabelText(tr("Deleting URL data... Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Deleting URL Data").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif

  QSqlQuery query(m_urlDatabase);

  if(m_urlDatabase.driverName() != "QPSQL")
    query.exec("PRAGMA secure_delete = ON");

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;

	    if(i <= 9)
	      c1 = QChar(i + 48);
	    else
	      c1 = QChar(i + 97 - 10);

	    if(j <= 9)
	      c2 = QChar(j + 48);
	    else
	      c2 = QChar(j + 97 - 10);

	    if(!query.exec(QString("DELETE FROM "
				   "spot_on_keywords_%1%2").
			   arg(c1).arg(c2)))
	      deleted = false;

	    if(!query.exec(QString("DELETE FROM "
				   "spot_on_urls_%1%2").
			   arg(c1).arg(c2)))
	      deleted = false;

	    if(!query.exec(QString("DELETE FROM "
				   "spot_on_urls_revisions_%1%2").
			   arg(c1).arg(c2)))
	      deleted = false;
	  }
	else
	  deleted = false;

	processed += 1;
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
  progress.setLabelText(tr("Gathering URL statistics. Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Gathering URL Statistics").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif

  QSqlQuery query(m_urlDatabase);

  for(int i = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	if(m_urlDatabase.isOpen())
	  {
	    QChar c1;
	    QChar c2;

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
		size += static_cast<quint64> (query.value(0).toLongLong());
	  }

	processed += 1;
      }
}

void spoton::slotImportUrls(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
	 tr("Did you prepare URL common credentials?"));
      return;
    }

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Did you prepare your URL databases and URL distillers?"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QMessageBox::information
    (this, tr("%1: Information").
     arg(SPOTON_APPLICATION_NAME),
     tr("Please note that the URL-import process may "
	"require a considerable amount of time to complete."));

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

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QDateTime now(QDateTime::currentDateTime());
  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Importing URLs. Please be patient."));
  progress.setMaximum(0);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Importing URLs").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.raise();
  progress.activateWindow();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif
  populateUrlDistillers();

  quint64 declined = 0;
  quint64 imported = 0;
  quint64 not_imported = 0;

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

	query.prepare("SELECT content, description, encrypted, title, url "
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

#ifndef Q_OS_MAC
		progress.repaint();
		QApplication::processEvents();
#endif

		QByteArray content;
		QByteArray description;
		QByteArray title;
		QByteArray url;
		bool encrypted = query.value(2).toBool();
		bool ok = true;

		if(encrypted)
		  {
		    if(!readEncrypted)
		      {
			not_imported += 1;
			continue;
		      }

		    spoton_crypt crypt
		      (cipherType,
		       "",
		       QByteArray(),
		       symmetricKey,
		       0,
		       0,
		       "");

		    content = crypt.decrypted
		      (query.value(0).toByteArray(), &ok);

		    if(ok)
		      description = crypt.decrypted
			(query.value(1).toByteArray(), &ok);

		    if(ok)
		      title = crypt.decrypted
			(query.value(3).toByteArray(), &ok);

		    if(ok)
		      url = crypt.decrypted
			(query.value(4).toByteArray(), &ok);
		  }
		else
		  {
		    content = query.value(0).toByteArray();
		    description = query.value(1).toByteArray();
		    title = query.value(3).toByteArray();
		    url = query.value(4).toByteArray();
		  }

		if(ok)
		  {
		    ok = false;

		    for(int i = 0; i < m_ui.sharedDistillers->rowCount(); i++)
		      {
			QComboBox *box = qobject_cast<QComboBox *>
			  (m_ui.sharedDistillers->cellWidget(i, 1));
			QTableWidgetItem *item = m_ui.sharedDistillers->
			  item(i, 0);

			if(!box || !item)
			  continue;

			QString type("");
			QUrl u1(QUrl::fromUserInput(item->text()));
			QUrl u2(QUrl::fromUserInput(url));

			if(box->currentIndex() == 0)
			  type = "accept";
			else
			  type = "deny";

			if(type == "accept")
			  {
			    if(spoton_misc::urlToEncoded(u2).
			       startsWith(spoton_misc::urlToEncoded(u1)))
			      {
				ok = true;
				break;
			      }
			  }
			else
			  {
			    if(spoton_misc::urlToEncoded(u2).
			       startsWith(spoton_misc::urlToEncoded(u1)))
			      {
				ok = false;
				break;
			      }
			  }
		      }

		    if(!ok)
		      declined += 1;

		    if(ok)
		      {
			QString error("");

			ok = spoton_misc::importUrl
			  (content,
			   description,
			   title,
			   url,
			   m_urlDatabase,
			   m_optionsUi.maximum_url_keywords_interface->value(),
			   m_settings.value("gui/disable_ui_synchronous_"
					    "sqlite_url_import",
					    false).toBool(),
			   error,
			   m_urlCommonCrypt);
		      }
		  }

		if(ok)
		  imported += 1;
		else
		  not_imported += 1;

		if(ok)
		  {
		    QSqlQuery deleteQuery(db);

		    deleteQuery.exec("PRAGMA secure_delete = ON");
		    deleteQuery.prepare("DELETE FROM urls WHERE url = ?");
		    deleteQuery.bindValue(0, query.value(4));
		    deleteQuery.exec();
		  }

		processed += 1;
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  progress.close();
#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif
  displayUrlImportResults(now, imported, not_imported, declined);
}

void spoton::displayUrlImportResults(const QDateTime &then,
				     const quint64 imported,
				     const quint64 not_imported,
				     const quint64 declined)
{
  QLocale locale;

  QMessageBox::information
    (this, tr("%1: Information").
     arg(SPOTON_APPLICATION_NAME),
     tr("URLs imported: %1. URLs not imported: %2. "
	"Some URLs (%3) may have been declined because of distiller rules. "
	"URLs that were not imported will remain in shared.db. "
	"The process completed in %4 second(s).").
     arg(imported).arg(not_imported).arg(declined).
     arg(locale.toString(qAbs(QDateTime::currentDateTime().secsTo(then)))));
}

void spoton::slotShowUrlSettings(bool state)
{
  m_ui.urlSettings->setVisible(state);
  m_ui.urlsBox->setVisible(!state);

  if(!state)
    m_ui.urls_settings_layout->addWidget(m_ui.importUrls);
  else
    m_ui.urls_import_layout->addWidget(m_ui.importUrls);
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
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
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
    QMessageBox::critical
      (this, tr("%1: Error").
       arg(SPOTON_APPLICATION_NAME),
       tr("The provided credentials are incorrect."));
}

void spoton::slotSaveUrlCredentials(void)
{
  QByteArray salt
    (QByteArray::fromHex(m_ui.urlSalt->text().toLatin1()));
  QPair<QByteArray, QByteArray> keys;
  QString error("");
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys
    (m_ui.urlCipher->currentText(),
     m_ui.urlHash->currentText(),
     static_cast<unsigned long int> (m_ui.urlIteration->value()),
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

void spoton::slotPostgreSQLConnect(void)
{
  if(m_ui.postgresqlConnect->
     property("user_text").toString() == "disconnect")
    {
      m_ui.postgresqlConnect->setProperty("user_text", "connect");
      m_ui.postgresqlConnect->setText(tr("&PostgreSQL Connect..."));
      m_ui.url_database_connection_information->clear();
      m_urlDatabase.close();
      m_urlDatabase = QSqlDatabase();

      if(QSqlDatabase::contains("URLDatabase"))
	QSqlDatabase::removeDatabase("URLDatabase");

      return;
    }

  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
  Ui_spoton_postgresqlconnect ui;
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
  ui.connection_options->setText
    (settings.value("gui/postgresql_connection_options", "").
     toString().trimmed());
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
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_ui.url_database_connection_information->clear();
      m_urlDatabase.close();
      m_urlDatabase = QSqlDatabase();

      if(QSqlDatabase::contains("URLDatabase"))
	QSqlDatabase::removeDatabase("URLDatabase");

      m_urlDatabase = QSqlDatabase::addDatabase("QPSQL", "URLDatabase");

      QString str("connect_timeout=10");

      if(!ui.connection_options->text().trimmed().isEmpty())
	str.append(";").append(ui.connection_options->text().trimmed());

      if(ui.ssltls->isChecked())
	str.append(";requiressl=1");

      m_urlDatabase.setConnectOptions(str);
      m_urlDatabase.setHostName(ui.host->text());
      m_urlDatabase.setDatabaseName(ui.database->text());
      m_urlDatabase.setPort(ui.port->value());
      m_urlDatabase.open(ui.name->text(), ui.password->text());
      QApplication::restoreOverrideCursor();

      if(!m_urlDatabase.isOpen())
	{
	  m_ui.url_database_connection_information->clear();

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
	  m_ui.postgresqlConnect->setText(tr("&PostgreSQL Disconnect"));
	  m_ui.url_database_connection_information->setText
	    (QString("%1@%2/%3").
	     arg(ui.name->text()).
	     arg(ui.host->text()).
	     arg(ui.database->text()));
	  settings.setValue("gui/postgresql_connection_options",
			    ui.connection_options->text().trimmed());
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
  QScopedPointer<QMessageBox> mb;
  QString error("");
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  mb.reset(new QMessageBox(this));
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb->setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb->setIcon(QMessageBox::Question);
  mb->setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb->setText(tr("In order to save new Common Credentials, "
		 "the RSS mechanism and the kernel will be deactivated. "
		 "Proceed?"));
  mb->setWindowModality(Qt::WindowModal);
  mb->setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb->exec() != QMessageBox::Yes)
    return;
  else
    {
#ifndef Q_OS_MAC
      repaint();
      QApplication::processEvents();
#endif
      m_rss->deactivate();
      slotDeactivateKernel();
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys
    (m_ui.commonUrlCipher->currentText(),
     m_ui.commonUrlHash->currentText(),
     static_cast<unsigned long int> (m_ui.commonUrlIterationCount->value()),
     m_ui.commonUrlPassphrase->text(),
     m_ui.commonUrlPin->text().toUtf8(),
     error);
  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    error = saveCommonUrlCredentials
      (keys,
       m_ui.commonUrlCipher->currentText(),
       m_ui.commonUrlHash->currentText(),
       crypt);
  else
    error = tr("Key generation failure.");

 done_label:

  if(mb)
    mb->close();

  if(!error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  error);
  else
    {
      m_ui.commonUrlCipher->setCurrentIndex(0);
      m_ui.commonUrlHash->setCurrentIndex(0);
      m_ui.commonUrlIterationCount->setValue(250000);
      m_ui.commonUrlPassphrase->clear();
      m_ui.commonUrlPin->clear();
      prepareUrlContainers();
      prepareUrlLabels();
    }
}

void spoton::slotAddDistiller(void)
{
  spoton_misc::prepareUrlDistillersDatabase();

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
  QString scheme("");
  QUrl url(QUrl::fromUserInput(m_ui.domain->text().trimmed()));
  bool ok = true;

  if(!(m_ui.downDist->isChecked() ||
       m_ui.sharedDist->isChecked() ||
       m_ui.upDist->isChecked()))
    {
      error = tr("Please specify at least one direction.");
      ok = false;
      goto done_label;
    }
  else if(url.isEmpty() || !url.isValid())
    {
      error = tr("Invalid domain.");
      ok = false;
      goto done_label;
    }

  scheme = url.scheme().toLower().trimmed();
  url.setScheme(scheme);

  if(!spoton_common::ACCEPTABLE_URL_SCHEMES.contains(scheme))
    {
      error = tr("Only ftp, gopher, http, and https schemes are allowed.");
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
	QStringList list;

	if(m_ui.downDist->isChecked())
	  list << "download";

	if(m_ui.sharedDist->isChecked())
	  list << "shared";

	if(m_ui.upDist->isChecked())
	  list << "upload";

	for(int i = 0; i < list.size(); i++)
	  {
	    QByteArray permission("accept");
	    QString direction(list.at(i));
	    bool ok = true;

	    query.prepare("INSERT INTO distillers "
			  "(direction, "
			  "direction_hash, "
			  "domain, "
			  "domain_hash, "
			  "permission) "
			  "VALUES "
			  "(?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(direction.toLatin1(),
					     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(direction.toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->encryptedThenHashed(domain, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->keyedHash(domain, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->encryptedThenHashed(permission, &ok).toBase64());

	    if(ok)
	      ok = query.exec();

	    if(query.lastError().isValid())
	      {
		error = query.lastError().text().trimmed();
		break;
	      }
	  }
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
      m_ui.domain->clear();
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
			     "to add the specified URL domain.").arg(error));
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
	m_ui.downDistillers->setRowCount(0);
	m_ui.sharedDistillers->setRowCount(0);
	m_ui.upDistillers->setRowCount(0);

	QSqlQuery query(db);
	int dCount = 0;
	int sCount = 0;
	int uCount = 0;

	query.setForwardOnly(true);
	query.prepare
	  ("SELECT direction, domain, permission, OID FROM distillers");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray direction;
	      QByteArray domain;
	      QByteArray permission;
	      bool ok = true;

	      direction = crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.value(0).
						       toByteArray()),
					    &ok);

	      if(ok)
		domain = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(1).
							 toByteArray()),
					      &ok);

	      if(ok)
		permission = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.value(2).
							 toByteArray()),
					      &ok);

	      if(ok)
		{
		  QComboBox *box = new QComboBox();
		  QTableWidgetItem *item = new QTableWidgetItem
		    (QString::fromUtf8(domain.constData(), domain.length()));

		  box->addItem("accept");
		  box->addItem("deny");
		  box->setProperty
		    ("oid", query.value(query.record().count() - 1));

		  if(permission == "accept")
		    box->setCurrentIndex(0);
		  else
		    box->setCurrentIndex(1);

		  connect(box,
			  SIGNAL(currentIndexChanged(int)),
			  this,
			  SLOT(slotUrlPolarizerTypeChange(int)));
		  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

		  if(direction == "download")
		    {
		      m_ui.downDistillers->setRowCount(dCount + 1);
		      m_ui.downDistillers->setItem(dCount, 0, item);
		      m_ui.downDistillers->setCellWidget(dCount, 1, box);
		      dCount += 1;
		    }
		  else if(direction == "shared")
		    {
		      m_ui.sharedDistillers->setRowCount(sCount + 1);
		      m_ui.sharedDistillers->setItem(sCount, 0, item);
		      m_ui.sharedDistillers->setCellWidget(sCount, 1, box);
		      sCount += 1;
		    }
		  else
		    {
		      m_ui.upDistillers->setRowCount(uCount + 1);
		      m_ui.upDistillers->setItem(uCount, 0, item);
		      m_ui.upDistillers->setCellWidget(uCount, 1, box);
		      uCount += 1;
		    }
		}
	    }

	m_ui.downDistillers->sortItems(0);
	m_ui.downDistillers->resizeColumnToContents(1);
	m_ui.sharedDistillers->sortItems(0);
	m_ui.sharedDistillers->resizeColumnToContents(1);
	m_ui.upDistillers->sortItems(0);
	m_ui.upDistillers->resizeColumnToContents(1);
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

  QModelIndexList list;
  QString direction("");

  if(m_ui.urlTab->currentIndex() == 0)
    {
      direction = "download";
      list = m_ui.downDistillers->selectionModel()->selectedRows(0);
    }
  else if(m_ui.urlTab->currentIndex() == 1)
    {
      direction = "shared";
      list = m_ui.sharedDistillers->selectionModel()->selectedRows(0);
    }
  else
    {
      direction = "upload";
      list = m_ui.upDistillers->selectionModel()->selectedRows(0);
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
	  QSqlQuery query(db);
	  QString str(list.takeFirst().data().toString());
	  bool ok = true;

	  query.exec("PRAGMA secure_delete = ON");
	  query.prepare("DELETE FROM distillers WHERE "
			"direction_hash = ? AND domain_hash = ?");
	  query.bindValue
	    (0, crypt->keyedHash(direction.toLatin1(),
				 &ok).toBase64());

	  if(ok)
	    query.bindValue(1, crypt->keyedHash(str.toUtf8(),
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

void spoton::slotUrlLinkClicked(const QUrl &u)
{
  QString scheme(u.scheme().toLower().trimmed());
  QUrl url(u);

  if(scheme.startsWith("delete-"))
    {
      if(!m_urlDatabase.isOpen())
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please connect to a URL database."));
	  return;
	}

      scheme.remove("delete-");
      url.setScheme(scheme);

      QMessageBox mb(this);
      QString str(spoton_misc::urlToEncoded(url).constData());

      if(str.length() > 64)
	str = str.mid(0, 24) + "..." + str.right(24);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));
      mb.setWindowModality(Qt::WindowModal);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to remove the URL %1?").
		 arg(str));

      if(mb.exec() != QMessageBox::Yes)
	return;
    }
  else if(scheme.startsWith("export-"))
    {
      if(!m_urlDatabase.isOpen())
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please connect to a URL database."));
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

      QFileDialog dialog(this);

#ifdef Q_OS_MAC
      dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
      dialog.setAcceptMode(QFileDialog::AcceptSave);
#if QT_VERSION < 0x050000
      dialog.setDirectory(QDesktopServices::storageLocation(QDesktopServices::
							    DesktopLocation));
#else
      dialog.setDirectory(QStandardPaths::
			  standardLocations(QStandardPaths::DesktopLocation).
			  value(0));
#endif

      QString fileName("");

#if QT_VERSION >= 0x050200
      fileName = url.fileName().trimmed();
#else
      fileName = QFileInfo(url.path()).fileName().trimmed();
#endif

      if(fileName.isEmpty())
	fileName = QString("spot-on-exported-url-%1.pdf").
	  arg(spoton_crypt::weakRandomBytes(8).toHex().constData());
      else // What if the file's extension is PDF? That's fine.
	fileName += ".pdf";

      dialog.selectFile(fileName);
      dialog.setFileMode(QFileDialog::AnyFile);
      dialog.setLabelText(QFileDialog::Accept, tr("Save"));
      dialog.setWindowTitle
	(tr("%1: Export Link As PDF").arg(SPOTON_APPLICATION_NAME));

      if(dialog.exec() == QDialog::Accepted)
	{
	  QString hash(url.toString());

	  if(hash.startsWith("export-ftp:"))
	    hash.remove
	      (0, static_cast<int> (qstrlen("export-ftp:")));
	  else if(hash.startsWith("export-gopher:"))
	    hash.remove
	      (0, static_cast<int> (qstrlen("export-gopher:")));
	  else if(hash.startsWith("export-http:"))
	    hash.remove
	      (0, static_cast<int> (qstrlen("export-http:")));
	  else if(hash.startsWith("export-https:"))
	    hash.remove
	      (0, static_cast<int> (qstrlen("export-https:")));

	  hash = hash.mid(0, hash.indexOf("%"));

	  if(!hash.isEmpty())
	    {
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	      QSqlQuery query(m_urlDatabase);

	      query.setForwardOnly(true);
	      query.prepare
		(QString("SELECT content, url FROM spot_on_urls_%1 WHERE "
			 "url_hash = ?").
		 arg(hash.mid(0, 2)));
	      query.addBindValue(hash);

	      if(query.exec())
		if(query.next())
		  {
		    QByteArray content;
		    QUrl url;
		    bool ok = true;

		    content = m_urlCommonCrypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(0).toByteArray()),
		       &ok);

		    if(ok)
		      url = QUrl::fromUserInput
			(m_urlCommonCrypt->
			 decryptedAfterAuthenticated(QByteArray::
						     fromBase64(query.value(1).
								toByteArray()),
						     &ok));

		    if(ok)
		      {
			content = qUncompress(content);

			QPrinter printer;

			printer.setOutputFileName
			  (dialog.selectedFiles().value(0));
			printer.setOutputFormat(QPrinter::PdfFormat);

			spoton_textbrowser textbrowser(this);

			textbrowser.append(url.toString());
			textbrowser.append("<br>");
			textbrowser.append(content);
			textbrowser.print(&printer);
		      }
		  }

	      QApplication::restoreOverrideCursor();
	    }
	}

      return;
    }
  else if(scheme.startsWith("share-"))
    {
      /*
      ** Share the link!
      */

      QString error("");

      if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
	error = tr("The interface is not connected to the kernel.");
      else if(!m_kernelSocket.isEncrypted())
	error = tr("The connection to the kernel is not encrypted.");

      if(!error.isEmpty())
	{
	  QMessageBox::critical
	    (this, tr("%1: Error").
	     arg(SPOTON_APPLICATION_NAME),
	     error);
	  return;
	}

      QByteArray message("sharelink_");
      QString str(url.toString().mid(url.toString().indexOf("%") + 1));
      QUrl original;

      if(str.startsWith("253")) // Encoded "%3".
	str.remove(0, 3);
      else if(str.startsWith("3")) // %3.
	str.remove(0, 1);

      original = QUrl(str);
      message.append(url.toString().mid(0, url.toString().indexOf("%")));
      message.append("\n");

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
      mb.setText(tr("Are you sure that you wish to share the URL %1?").
		 arg(spoton_misc::urlToEncoded(original).constData()));

      if(mb.exec() != QMessageBox::Yes)
	return;

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotUrlLinkClicked(): write() failure for "
		   "%1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	{
	  m_sb.status->setText(tr("URL %1 shared with your friendly "
				  "participants.").
			       arg(spoton_misc::urlToEncoded(original).
				   constData()));
	  m_sb.status->repaint();
	}

      return;
    }
  else if(scheme.startsWith("view-"))
    {
      if(!m_urlDatabase.isOpen())
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please connect to a URL database."));
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

      QString hash(url.toString());

      if(hash.startsWith("view-ftp:"))
	hash.remove
	  (0, static_cast<int> (qstrlen("view-ftp:")));
      else if(hash.startsWith("view-gopher:"))
	hash.remove
	  (0, static_cast<int> (qstrlen("view-gopher:")));
      else if(hash.startsWith("view-http:"))
	hash.remove
	  (0, static_cast<int> (qstrlen("view-http:")));
      else if(hash.startsWith("view-https:"))
	hash.remove
	  (0, static_cast<int> (qstrlen("view-https:")));

      hash = hash.mid(0, hash.indexOf("%"));

      spoton_pageviewer *pageViewer = new spoton_pageviewer
	(&m_urlDatabase, hash, 0);

      pageViewer->setPage(QByteArray(), QUrl("http://127.0.0.1"), 0);

      if(!hash.isEmpty())
	{
	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	  QSqlQuery query(m_urlDatabase);

	  query.setForwardOnly(true);
	  query.prepare
	    (QString("SELECT content, url FROM spot_on_urls_%1 WHERE "
		     "url_hash = ?").
	     arg(hash.mid(0, 2)));
	  query.bindValue(0, hash);

	  if(query.exec())
	    if(query.next())
	      {
		QByteArray content;
		QUrl url;
		bool ok = true;

		content = m_urlCommonCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

		if(ok)
		  url = QUrl::fromUserInput
		    (m_urlCommonCrypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(1).
							    toByteArray()),
						 &ok));

		if(ok)
		  {
		    content = qUncompress(content);
		    pageViewer->setPage
		      (content, url, query.value(0).toByteArray().length());
		  }
	      }

	  QApplication::restoreOverrideCursor();
	}

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      pageViewer->showNormal();
      pageViewer->activateWindow();
      pageViewer->raise();
      spoton_utilities::centerWidget(pageViewer, this);
      QApplication::restoreOverrideCursor();
      return;
    }
  else if(!scheme.startsWith("delete-"))
    {
      if(m_settings.value("gui/openLinks", false).toBool())
	{
	  QMessageBox mb(this);
	  QString str(spoton_misc::urlToEncoded(url).constData());

	  if(str.length() > 64)
	    str = str.mid(0, 24) + "..." + str.right(24);

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
	  mb.setText(tr("Are you sure that you wish to access the URL %1?").
		     arg(str));

	  if(mb.exec() != QMessageBox::Yes)
	    return;

	  QDesktopServices::openUrl(url);
	}

      return;
    }

  spoton_crypt *crypt = m_crypts.value("chat", 0);

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

  urlHash = m_urlCommonCrypt->
    keyedHash(spoton_misc::urlToEncoded(url), &ok).toHex();

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

  query.prepare(QString("DELETE FROM spot_on_urls_revisions_%1 "
			"WHERE url_hash = ?").
		arg(urlHash.mid(0, 2).constData()));
  query.bindValue(0, urlHash.constData());
  query.exec();

  /*
  ** Now, we must remove the URL from all of the keywords tables.
  */

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Deleting URL keywords. Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Deleting URL Keywords").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	QChar c1;
	QChar c2;

	if(i <= 9)
	  c1 = QChar(i + 48);
	else
	  c1 = QChar(i + 97 - 10);

	if(j <= 9)
	  c2 = QChar(j + 48);
	else
	  c2 = QChar(j + 97 - 10);

	query.prepare(QString("DELETE FROM "
			      "spot_on_keywords_%1%2 WHERE "
			      "url_hash = ?").arg(c1).arg(c2));
	query.bindValue(0, urlHash.constData());
	query.exec();
	processed += 1;
      }

  /*
  ** Finally, let's discover!
  */

  discoverUrls();
}

void spoton::slotUrlPolarizerTypeChange(int index)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QComboBox *box = qobject_cast<QComboBox *> (sender());

  if(!box)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("UPDATE distillers SET "
		      "permission = ? WHERE OID = ?");

	if(index == 0)
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("accept"),
					   &ok).toBase64());
	else
	  query.bindValue
	    (0, crypt->encryptedThenHashed(QByteArray("deny"),
					   &ok).toBase64());

	query.bindValue(1, box->property("oid"));

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCorrectUrlDatabases(void)
{
  if(!m_urlDatabase.isOpen())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please connect to a URL database."));
      return;
    }

  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

  if(m_urlDatabase.driverName() == "QPSQL")
    mb.setText
      (tr("The database-correction process "
	  "may require a considerable amount of time to complete. "
	  "You may experience performance degradation upon completion. "
	  "The RSS mechanism and the kernel will be deactivated. "
	  "A brief report will be displayed after the process completes. "
	  "Proceed?"));
  else
    mb.setText
      (tr("The database-correction process "
	  "may require a considerable amount of time to complete. "
	  "The RSS mechanism and the kernel will be deactivated. "
	  "A brief report will be displayed after the process completes. "
	  "Proceed?"));

  if(mb.exec() != QMessageBox::Yes)
    return;
  else
    {
      m_rss->deactivate();
      slotDeactivateKernel();
    }

#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Deleting orphaned URL keywords. "
			   "Please be patient."));
  progress.setMaximum(10 * 10 + 6 * 6);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Deleting Orphaned URL Keywords").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif

  QSqlQuery query1(m_urlDatabase);
  QSqlQuery query2(m_urlDatabase);
  QSqlQuery query3(m_urlDatabase);
  qint64 deleted = 0;

  query1.setForwardOnly(true);
  query2.setForwardOnly(true);

  if(m_urlDatabase.driverName() != "QPSQL")
    {
      query2.exec("PRAGMA secure_delete = ON");
      query3.exec("PRAGMA secure_delete = ON");
    }

  for(int i = 0, processed = 0; i < 10 + 6 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 10 + 6 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

#ifndef Q_OS_MAC
	progress.repaint();
	QApplication::processEvents();
#endif

	QChar c1;
	QChar c2;

	if(i <= 9)
	  c1 = QChar(i + 48);
	else
	  c1 = QChar(i + 97 - 10);

	if(j <= 9)
	  c2 = QChar(j + 48);
	else
	  c2 = QChar(j + 97 - 10);

	progress.setLabelText
	  (tr("Reviewing spot_on_keywords_%1%2 for orphaned entries. "
	      "Please be patient.").arg(c1).arg(c2));
	query1.prepare
	  (QString("SELECT url_hash FROM "
		   "spot_on_keywords_%1%2").arg(c1).arg(c2));

	if(query1.exec())
	  {
	    while(query1.next())
	      if(!m_urlPrefixes.contains(query1.value(0).toString().mid(0, 2)))
		{
		  if(progress.wasCanceled())
		    break;

		  query2.prepare
		    (QString("DELETE FROM "
			     "spot_on_keywords_%1%2 WHERE "
			     "url_hash = ?").
		     arg(c1).arg(c2));
		  query2.bindValue(0, query1.value(0));

		  if(query2.exec())
		    deleted += 1;
		}
	      else
		{
		  if(progress.wasCanceled())
		    break;

		  query2.prepare
		    (QString("SELECT EXISTS(SELECT 1 FROM "
			     "spot_on_urls_%1 WHERE "
			     "url_hash = ?)").
		     arg(query1.value(0).toString().mid(0, 2)));
		  query2.bindValue(0, query1.value(0));

		  if(query2.exec())
		    if(query2.next())
		      if(!query2.value(0).toBool())
			{
			  query3.prepare
			    (QString("DELETE FROM "
				     "spot_on_keywords_%1%2 WHERE "
				     "url_hash = ?").
			     arg(c1).arg(c2));
			  query3.bindValue(0, query1.value(0));

			  if(query3.exec())
			    deleted += 1;
			}
		}
	  }

	processed += 1;
      }

  progress.close();
#ifndef Q_OS_MAC
  repaint();
  QApplication::processEvents();
#endif

  QLocale locale;

  QMessageBox::information
    (this, tr("%1: Information").
     arg(SPOTON_APPLICATION_NAME),
     tr("Approximate orphaned keyword entries deleted: %1.").
     arg(locale.toString(deleted)));
}
