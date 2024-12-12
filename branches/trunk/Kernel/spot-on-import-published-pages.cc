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
#include <QScopedPointer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QtConcurrent>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-import-published-pages.h"

spoton_import_published_pages::spoton_import_published_pages(QObject *parent):
  QObject(parent)
{
  connect(&m_importTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotImport(void)));
  connect(this,
	  SIGNAL(logError(const QString &)),
	  this,
	  SLOT(slotLogError(const QString &)));
  m_cancelImport = 0;
  m_importFutures.resize(qCeil(1.5 * qMax(1, QThread::idealThreadCount())));

  for(int i = 0; i < m_importFutures.size(); i++)
    m_importFutures.replace(i, QFuture<void> ());

  m_importTimer.setInterval(10000);
  m_importTimer.start();
  m_imported = 0;
}

spoton_import_published_pages::~spoton_import_published_pages()
{
  deactivate();
}

quint64 spoton_import_published_pages::imported(void) const
{
  return m_imported.loadAcquire();
}

spoton_crypt *spoton_import_published_pages::urlCommonCrypt(void) const
{
  return spoton_misc::retrieveUrlCommonCredentials
    (spoton_kernel::crypt("chat"));
}

void spoton_import_published_pages::deactivate(void)
{
  m_cancelImport.fetchAndStoreOrdered(1);
  m_importTimer.stop();

  for(int i = 0; i < m_importFutures.size(); i++)
    {
      m_importFutures[i].cancel();
      m_importFutures[i].waitForFinished();
    }
}

void spoton_import_published_pages::import(const QList<QVariant> &values)
{
  if(values.size() != 4)
    return;

  auto s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    {
      emit logError
	("Import failure. Invalid spoton_crypt object. This is a fatal flaw.");
      return;
    }

  QList<QPair<QUrl, QString> > polarizers;
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() +
		       QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT domain, " // 0
		      "permission "     // 1
		      "FROM distillers WHERE "
		      "direction_hash = ?");
	query.bindValue
	  (0, s_crypt->keyedHash(QByteArray("shared"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      if(m_cancelImport.fetchAndAddOrdered(0))
		break;

	      QByteArray domain;
	      QByteArray permission;
	      auto ok = true;

	      domain = s_crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(0).
						       toByteArray()),
					    &ok);

	      if(ok)
		permission = s_crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(1).
							 toByteArray()),
					      &ok);

	      if(ok)
		{
		  auto const url(QUrl::fromUserInput(domain));

		  if(!url.isEmpty())
		    if(url.isValid())
		      {
			QPair<QUrl, QString> pair;

			pair.first = url;
			pair.second = permission;
			polarizers.append(pair);
		      }
		}

	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_import_published_pages::slotImport(void)
{
  QString directory("");
  int titleLN = -1;
  int urlLN = -1;
  auto const list = spoton_kernel::setting
    ("PUBLISHED_PAGES", "").toString().trimmed().split(',');

  if(list.size() == 3)
    {
      directory = QFileInfo(list.at(0)).absoluteFilePath();
      titleLN = list.at(1).toInt();
      urlLN = list.at(2).toInt();
    }
  else
    return;

  QFileInfo const fileInfo(directory);

  if(fileInfo.isReadable() == false ||
     fileInfo.isWritable() == false ||
     titleLN <= 0 ||
     titleLN == urlLN ||
     urlLN <= 0)
    return;

  QList<QVariant> values;
  auto const maximumKeywords = spoton_kernel::setting
    ("gui/maximum_url_keywords_import_interface", 50).toInt();

  values << directory << maximumKeywords << titleLN << urlLN;

  for(int i = 0; i < m_importFutures.size(); i++)
    if(m_importFutures.at(i).isFinished())
      {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	m_importFutures.replace
	  (i,
	   QtConcurrent::run(&spoton_import_published_pages::import,
			     this,
			     values));
#else
	m_importFutures.replace
	  (i,
	   QtConcurrent::run(this,
			     &spoton_import_published_pages::import,
			     values));
#endif
	break;
      }
}

void spoton_import_published_pages::slotLogError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  spoton_misc::logError(error);
}
