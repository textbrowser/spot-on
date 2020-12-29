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
#include <QNetworkProxy>
#include <QScopedPointer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QXmlStreamReader>
#include <QtConcurrent>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-rss.h"

static char s_user_agent[] = "Spot-On";

spoton_rss::spoton_rss(QObject *parent):QObject(parent)
{
  m_cancelImport = 0;
  m_lastUniqueId = QPair<QByteArray, qint64> (QByteArray(), -1);
  connect(&m_downloadContentTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDownloadContent(void)));
  connect(&m_downloadTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDownloadTimeout(void)));
  connect(&m_importTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotImport(void)));
  connect(&m_populateTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateFeeds(void)));
  connect(this,
	  SIGNAL(logError(const QString &)),
	  this,
	  SLOT(slotLogError(const QString &)));

  double value = qBound
    (0.1,
     spoton_kernel::setting("gui/rss_download_interval", 1.50).toDouble(),
     120.0);

  m_downloadContentTimer.setInterval(1500);
  m_downloadContentTimer.start();
  m_downloadTimer.setInterval(static_cast<int> (60000.0 * value));
  m_downloadTimer.start();
  m_importFutures.resize
    (qCeil(1.5 * qMax(1, QThread::idealThreadCount())));

  for(int i = 0; i < m_importFutures.size(); i++)
    m_importFutures.replace(i, QFuture<void> ());

  m_importTimer.setInterval(2500);
  m_importTimer.start();
  m_populateTimer.setInterval(10000);
  m_populateTimer.start();
  prepareDatabases();
}

spoton_rss::~spoton_rss()
{
  deactivate();
}

bool spoton_rss::importUrl(const QList<QVariant> &list,
			   const int maximumKeywords)
{
  QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());

  if(!ucc)
    return false;

  QUrl url(list.value(4).toUrl());
  bool imported = false;

  if(url.isEmpty() || !url.isValid())
    url = list.value(3).toUrl();

  QSqlDatabase db(spoton_kernel::urlDatabase());
  QString connectionName(db.connectionName());
  QString error("");

  imported = spoton_misc::importUrl
    (list.value(0).toByteArray(),
     list.value(1).toString().toUtf8(), // Description
     list.value(2).toString().toUtf8(), // Title
     spoton_misc::urlToEncoded(url),    // URL
     db,
     maximumKeywords,
     spoton_kernel::
     setting("gui/disable_kernel_synchronous_sqlite_url_download",
	     false).toBool(),
     m_cancelImport,
     error,
     ucc.data());
  db.close();
  db = QSqlDatabase();
  QSqlDatabase::removeDatabase(connectionName);

  if(!error.isEmpty())
    emit logError(error);
  else
    emit logError
      (QString("The URL %1 has been imported.").
       arg(spoton_misc::urlToEncoded(url).constData()));

  return imported;
}

spoton_crypt *spoton_rss::urlCommonCrypt(void) const
{
  return spoton_misc::retrieveUrlCommonCredentials
    (spoton_kernel::crypt("chat"));
}

void spoton_rss::deactivate(void)
{
  m_cancelImport.fetchAndStoreOrdered(1);
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();

  for(int i = 0; i < m_importFutures.size(); i++)
    {
      m_importFutures[i].cancel();
      m_importFutures[i].waitForFinished();
    }

  m_parseXmlFuture.cancel();
  m_parseXmlFuture.waitForFinished();
  m_populateTimer.stop();
}

void spoton_rss::import(const int maximumKeywords)
{
  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    {
      emit logError
	("Import failure. Invalid spoton_crypt object. This is a fatal flaw.");
      return;
    }

  QString connectionName("");

  /*
  ** Now, retrieve polarizers.
  */

  QList<QPair<QUrl, QString> > polarizers;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() +
		       QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

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
	      bool ok = true;

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
		  QUrl url(QUrl::fromUserInput(domain));

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

  if(m_cancelImport.fetchAndAddOrdered(0))
    return;

  QList<QByteArray> urlHashes;
  QList<QList<QVariant> > lists;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int ct = 0;

	query.setForwardOnly(true);
	query.prepare
	  ("SELECT content, " // 0
	   "description, "    // 1
	   "title, "          // 2
	   "url, "            // 3
	   "url_hash, "       // 4
	   "url_redirected "  // 5
	   "FROM rss_feeds_links WHERE imported = 0 AND visited = 1");

	if(query.exec())
	  while(query.next())
	    {
	      ct += 1;

              QByteArray bytes;
	      QByteArray urlHash(query.value(4).toByteArray());
	      QList<QVariant> list;
	      bool ok = true;

	      bytes = qUncompress
		(s_crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		list << bytes;

	      if(ok)
		bytes = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		list << QUrl::fromEncoded(bytes);

	      if(ok)
		bytes = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

	      if(ok)
		{
		  /*
		  ** Apply polarizers.
		  */

		  ok = false;

		  for(int i = 0; i < polarizers.size(); i++)
		    {
		      if(m_cancelImport.fetchAndAddOrdered(0))
			break;

		      QString type(polarizers.at(i).second);
		      QUrl u1(polarizers.at(i).first);
		      QUrl u2(QUrl::fromEncoded(bytes));

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

		  if(m_cancelImport.fetchAndAddOrdered(0))
		    break;
		}

	      if(ok)
		{
		  QUrl url(QUrl::fromEncoded(bytes));

		  if(!url.isEmpty() && url.isValid())
		    list << url;
		}
	      else
		list.clear();

	      if(!list.isEmpty())
		{
		  lists << list;
		  urlHashes << urlHash;
		}

	      if(ct >= spoton_common::RSS_IMPORTS_PER_THREAD ||
		 m_cancelImport.fetchAndAddOrdered(0))
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_cancelImport.fetchAndAddOrdered(0))
    return;

  QList<bool> imported;

  for(int i = 0;
      i < lists.size() && !m_cancelImport.fetchAndAddOrdered(0);
      i++)
    imported << importUrl(lists.at(i), maximumKeywords);

  if(m_cancelImport.fetchAndAddOrdered(0))
    return;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	for(int i = 0;
	    i < imported.size() && !m_cancelImport.fetchAndAddOrdered(0);
	    i++)
	  {
	    query.prepare("UPDATE rss_feeds_links "
			  "SET imported = ? "
			  "WHERE url_hash = ?");

	    if(imported.at(i))
	      query.bindValue(0, 1);
	    else
	      query.bindValue(0, 2); // Import error.

	    query.bindValue(1, urlHashes.value(i));
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::parseXmlContent(const QByteArray &data, const QUrl &url)
{
  if(data.isEmpty())
    return;

  QString currentTag("");
  QString description("");
  QString link(url.toString());
  QString title("");
  QString type("");
  QXmlStreamReader reader(data);

  while(!reader.atEnd() && !reader.hasError())
    {
      if(m_parseXmlFuture.isCanceled())
	break;

      reader.readNext();

      if(reader.name().toString().toLower().trimmed() == "feed")
	{
	  type = "feed";
	  break;
	}
      else if(reader.name().toString().toLower().trimmed() == "rss")
	{
	  type = "rss";
	  break;
	}
    }

  /*
  ** Atom
  */

  if(type == "feed")
    {
      while(!reader.atEnd() && !reader.hasError())
	{
	  if(m_parseXmlFuture.isCanceled())
	    break;

	  reader.readNext();

	  if(reader.isStartElement())
	    currentTag = reader.name().toString().toLower().trimmed();

	  if(currentTag == "entry")
	    {
	      currentTag.clear();

	      QString description("");
	      QString link("");
	      QString publicationDate("");
	      QString tag("");
	      QString title("");
	      bool endDescription = false;

	      while(true)
		{
		  if(m_parseXmlFuture.isCanceled())
		    break;

		  reader.readNext();

		  if(reader.isEndElement())
		    {
		      if(reader.name().toString().toLower().trimmed() ==
			 "entry")
			break;

		      if(reader.name().toString().toLower().trimmed() ==
			 "summary")
			endDescription = true;
		    }
		  else if(reader.isStartElement())
		    tag = reader.name().toString().toLower().trimmed();

		  if(tag == "summary")
		    {
		      if(endDescription)
			tag.clear();
		      else if(reader.isCharacters())
			description.append(reader.text().toString());
		    }

		  if(tag == "link")
		    {
		      tag.clear();

		      QXmlStreamAttributes attributes = reader.attributes();

		      if(link.isEmpty())
			link = attributes.value("href").toString().trimmed();
		    }
		  else if(tag == "updated")
		    {
		      tag.clear();

		      if(publicationDate.isEmpty())
			{
			  reader.readNext();
			  publicationDate = reader.text().toString().trimmed();
			}
		    }
		  else if(tag == "title")
		    {
		      tag.clear();

		      if(title.isEmpty())
			{
			  reader.readNext();
			  title = reader.text().toString().trimmed();
			}
		    }

		  if(reader.atEnd() || reader.hasError())
		    break;
		}

	      if(!m_parseXmlFuture.isCanceled())
		saveFeedLink
		  (description.trimmed(), link, publicationDate, title, url);
	    }
	  else if(currentTag == "subtitle")
	    {
	      currentTag.clear();

	      if(description.isEmpty())
		{
		  reader.readNext();
		  description = reader.text().toString().trimmed();
		}
	    }
	  else if(currentTag == "title")
	    {
	      currentTag.clear();

	      if(title.isEmpty())
		{
		  reader.readNext();
		  title = reader.text().toString().trimmed();
		}
	    }
	}

      goto done_label;
    }

  /*
  ** RSS
  */

  while(!reader.atEnd() && !reader.hasError())
    {
      if(m_parseXmlFuture.isCanceled())
	break;

      reader.readNext();

      if(reader.isStartElement())
	currentTag = reader.name().toString().toLower().trimmed();

      if(currentTag == "description")
	{
	  currentTag.clear();

	  if(description.isEmpty())
	    {
	      reader.readNext();
	      description = reader.text().toString().trimmed();
	    }
	}
      else if(currentTag == "item")
	{
	  currentTag.clear();

	  QString description("");
	  QString link("");
	  QString publicationDate("");
	  QString tag("");
	  QString title("");
	  bool endDescription = false;

	  while(true)
	    {
	      if(m_parseXmlFuture.isCanceled())
		break;

	      reader.readNext();

	      if(reader.isEndElement())
		{
		  if(reader.name().toString().toLower().trimmed() ==
		     "description")
		    endDescription = true;

		  if(reader.name().toString().toLower().trimmed() == "item")
		    break;
		}
	      else if(reader.isStartElement())
		tag = reader.name().toString().toLower().trimmed();

	      if(tag == "description")
		{
		  if(endDescription)
		    tag.clear();
		  else if(reader.isCharacters())
		    description.append(reader.text().toString());
		}

	      if(tag == "link")
		{
		  tag.clear();

		  if(link.isEmpty())
		    {
		      reader.readNext();
		      link = reader.text().toString().trimmed();
		    }
		}
	      else if(tag == "pubdate")
		{
		  tag.clear();

		  if(publicationDate.isEmpty())
		    {
		      reader.readNext();
		      publicationDate = reader.text().toString().trimmed();
		    }
		}
	      else if(tag == "title")
		{
		  tag.clear();

		  if(title.isEmpty())
		    {
		      reader.readNext();
		      title = reader.text().toString().trimmed();
		    }
		}

	      if(reader.atEnd() || reader.hasError())
		break;
	    }

	  if(!m_parseXmlFuture.isCanceled())
	    saveFeedLink
	      (description.trimmed(), link, publicationDate, title, url);
	}
      else if(currentTag == "title")
	{
	  currentTag.clear();

	  if(title.isEmpty())
	    {
	      reader.readNext();
	      title = reader.text().toString().trimmed();
	    }
	}
    }

 done_label:

  if(m_parseXmlFuture.isCanceled())
    return;

  saveFeedData(description, link, title);

  QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());
  QSqlDatabase db(spoton_kernel::urlDatabase());
  QString connectionName(db.connectionName());
  QString error("");

  spoton_misc::importUrl
    (data,
     description.toUtf8(),
     title.toUtf8(),
     spoton_misc::urlToEncoded(url),
     db,
     spoton_kernel::setting("gui/rss_maximum_keywords", 50).toInt(),
     spoton_kernel::
     setting("gui/disable_kernel_synchronous_sqlite_url_download",
	     false).toBool(),
     m_cancelImport,
     error,
     ucc.data());
  db.close();
  db = QSqlDatabase();
  QSqlDatabase::removeDatabase(connectionName);

  if(!error.isEmpty())
    emit logError(error);
}

void spoton_rss::populateFeeds(void)
{
  int value = static_cast<int>
    (60000.0 *
     qBound(0.1,
	    spoton_kernel::
	    setting("gui/rss_download_interval", 1.50).toDouble(),
	    120.0));

  if(m_downloadTimer.interval() != value)
    {
      m_downloadTimer.setInterval(value);
      m_downloadTimer.start();
    }

  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT feed, " // 0
		      "OID "          // 1
		      "FROM rss_feeds "
		      "WHERE OID > ? ORDER BY 2");
	query.addBindValue(m_lastUniqueId.second);

	if(query.exec())
	  do
	    {
	      if(!query.next())
		{
		  m_lastUniqueId = QPair<QByteArray, qint64> (QByteArray(), -1);
		  break;
		}

	      QByteArray feed;
	      bool ok = true;

	      feed = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      if(ok)
		{
		  m_lastUniqueId = QPair<QByteArray, qint64>
		    (feed,
		     qMax(m_lastUniqueId.second,
			  query.value(query.record().count() - 1).
			  toLongLong()));
		  break;
		}
	    }
	  while(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT enabled, " // 0
		      "hostname, "       // 1
		      "password, "       // 2
		      "port, "           // 3
		      "type, "           // 4
		      "username "        // 5
		      "FROM rss_proxy");

	if(query.exec())
	  if(query.next())
	    {
	      QList<QByteArray> list;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QByteArray bytes;
		  bool ok = true;

		  bytes = s_crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(list.size() != query.record().count() ||
		 list.value(0) == "false")
		{
		}
	      else
		{
		  QNetworkProxy proxy;

		  if(list.value(4) == "HTTP")
		    proxy.setType(QNetworkProxy::HttpProxy);
		  else if(list.value(4) == "Socks5")
		    proxy.setType(QNetworkProxy::Socks5Proxy);
		  else if(list.value(4) == "System")
		    {
		      QNetworkProxyQuery proxyQuery;

		      proxyQuery.setQueryType(QNetworkProxyQuery::UrlRequest);

		      QList<QNetworkProxy> proxies
			(QNetworkProxyFactory::systemProxyForQuery(proxyQuery));

		      if(!proxies.isEmpty())
			proxy = proxies.at(0);
		      else
			proxy.setType(QNetworkProxy::NoProxy);
		    }
		  else
		    proxy.setType(QNetworkProxy::NoProxy);

		  if(proxy.type() != QNetworkProxy::NoProxy)
		    {
		      proxy.setHostName
			(QString::fromUtf8(list.value(1).constData(),
					   list.value(1).length()));
		      proxy.setPassword
			(QString::fromUtf8(list.value(2).constData(),
					   list.value(2).length()));
		      proxy.setPort(list.value(3).toUShort());
		      proxy.setUser
			(QString::fromUtf8(list.value(5).constData(),
					   list.value(5).length()));
		    }

		  m_contentNetworkAccessManager.setProxy(proxy);
		  m_feedNetworkAccessManager.setProxy(proxy);
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::prepareDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS rss_feeds ("
		   "feed TEXT NOT NULL, "
		   "feed_description TEXT NOT NULL, "
		   "feed_hash TEXT NOT NULL PRIMARY KEY, "
		   "feed_image BLOB NOT NULL, "
		   "feed_title TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS rss_feeds_links ("
		   "content TEXT NOT NULL, "
		   "description TEXT NOT NULL, "
		   "hidden INTEGER NOT NULL DEFAULT 0, "
		   "imported INTEGER NOT NULL DEFAULT 0, "
		   "insert_date TEXT NOT NULL, "
		   "publication_date TEXT NOT NULL, "
		   "title TEXT NOT NULL, "
		   "url TEXT NOT NULL, "
		   "url_hash TEXT NOT NULL PRIMARY KEY, "
		   "url_redirected TEXT NOT NULL, "
		   "visited INTEGER NOT NULL DEFAULT 0)");
	query.exec("CREATE TABLE IF NOT EXISTS rss_proxy ("
		   "enabled TEXT NOT NULL, "
		   "hostname TEXT NOT NULL, "
		   "password TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "type TEXT NOT NULL, "
		   "username TEXT NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS rss_proxy_trigger "
		   "BEFORE INSERT ON rss_proxy "
		   "BEGIN "
		   "DELETE FROM rss_proxy; "
		   "END");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::saveFeedData(const QString &d,
			      const QString &link,
			      const QString &t)
{
  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString description(d.trimmed());
	QString title(t.trimmed());
	bool ok = true;

	if(description.isEmpty())
	  description = link;

	if(title.isEmpty())
	  title = link;

	query.prepare("UPDATE rss_feeds "
		      "SET feed_description = ?, "
		      "feed_title = ? "
		      "WHERE feed_hash = ?");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(description.toUtf8(),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->encryptedThenHashed(title.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->keyedHash(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::saveFeedLink(const QString &d,
			      const QString &link,
			      const QString &p,
			      const QString &t,
			      const QUrl &url)
{
  Q_UNUSED(url);

  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    return;

  prepareDatabases();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString description(d.trimmed());
	QString publicationDate(p.trimmed());
	QString title(t.trimmed());
	bool ok = true;

	if(description.isEmpty())
	  description = link;

	if(publicationDate.isEmpty())
	  publicationDate = QDateTime::currentDateTime().toString(Qt::ISODate);

	if(title.isEmpty())
	  title = link;

	query.prepare
	  ("INSERT INTO rss_feeds_links ("
	   "content, description, insert_date, publication_date, "
	   "title, url, url_hash, url_redirected) "
	   "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(qCompress(QByteArray(), 9), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->encryptedThenHashed(description.toUtf8(), &ok).
	     toBase64());

	query.bindValue
	  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(3, publicationDate);

	if(ok)
	  query.bindValue
	    (4, s_crypt->encryptedThenHashed(title.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5,
	     s_crypt->encryptedThenHashed(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (6, s_crypt->keyedHash(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (7, s_crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::slotContentReplyFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      QUrl redirectUrl
	(reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 toUrl());

      if(!reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 isNull())
	if(redirectUrl.isRelative())
	  redirectUrl = reply->url().resolved(redirectUrl);

      if(!redirectUrl.isEmpty())
	if(redirectUrl.isValid())
	  {
	    QString error
	      (QString("The URL %1 is being redirected to %2.").
	       arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	       arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
	    QUrl originalUrl(reply->property("original-url").toUrl());

	    emit logError(error);
	    reply->deleteLater();

	    QNetworkRequest request(redirectUrl);

	    request.setRawHeader("Accept", "text/html");
	    request.setRawHeader("User-Agent", s_user_agent);
	    reply = m_contentNetworkAccessManager.get(request);

	    if(!reply)
	      {
		emit logError
		  (QString("QNetworkAccessManager::get() failure on %1.").
		   arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
		return;
	      }

	    reply->ignoreSslErrors();
	    reply->setProperty("original-url", originalUrl);
	    connect(reply,
		    SIGNAL(error(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
	    connect(reply,
		    SIGNAL(finished(void)),
		    this,
		    SLOT(slotContentReplyFinished(void)));
	    return;
	  }
    }

  if(reply)
    {
      spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

      if(!s_crypt)
	{
	  reply->deleteLater();
	  return;
	}

      QString error
	(QString("The content of URL %1 has been downloaded.").
	 arg(spoton_misc::urlToEncoded(reply->url()).constData()));

      emit logError(error);

      QByteArray data(reply->readAll());
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("UPDATE rss_feeds_links "
			  "SET content = ?, url_redirected = ?, visited = ? "
			  "WHERE url_hash = ?");
	    query.bindValue
	      (0, s_crypt->
	       encryptedThenHashed(qCompress(data, 9), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, s_crypt->
		 encryptedThenHashed(spoton_misc::
				     urlToEncoded(reply->url()),
				     &ok).toBase64());

	    if(data.isEmpty() || reply->error() != QNetworkReply::NoError)
	      {
		query.bindValue(2, 2); // Error.

		if(data.isEmpty())
		  {
		    QString error
		      (QString("The URL %1 does not have data.").
		       arg(spoton_misc::urlToEncoded(reply->url()).
			   constData()));

		    emit logError(error);
		  }
		else
		  {
		    QString error
		      (QString("The URL %1 cannot be indexed (%2).").
		       arg(spoton_misc::urlToEncoded(reply->url()).
			   constData()).
		       arg(reply->errorString()));

		    emit logError(error);
		  }
	      }
	    else
	      query.bindValue(2, 1);

	    if(ok)
	      query.bindValue
		(3, s_crypt->
		 keyedHash(spoton_misc::urlToEncoded(reply->
						     property("original-url").
						     toUrl()),
			   &ok).toBase64());

	    if(ok)
	      ok = query.exec();

	    if(!ok)
	      {
		QString error
		  (QString("The content of URL %1 was "
			   "not saved because of an error.").
		   arg(spoton_misc::urlToEncoded(reply->url()).constData()));

		emit logError(error);
	      }
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      reply->deleteLater();
    }
}

void spoton_rss::slotDownloadContent(void)
{
  if(!m_contentNetworkAccessManager.findChildren<QNetworkReply *> ().isEmpty())
    return;

  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    return;

  QString connectionName("");
  QUrl url;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT url, " // 0
		      "OID "         // 1
		      "FROM rss_feeds_links "
		      "WHERE visited = 0");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray bytes;
	      bool ok = true;

	      bytes = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		url = QUrl::fromEncoded(bytes);

	      if(!ok || url.isEmpty() || !url.isValid())
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM rss_feeds_links "
				      "WHERE OID = ?");
		  deleteQuery.addBindValue(query.value(1));
		  deleteQuery.exec();
		  url = QUrl();
		}
	      else
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!url.isEmpty() && url.isValid())
    {
      QString error
	(QString("Fetching the URL %1.").
	 arg(spoton_misc::urlToEncoded(url).constData()));

      emit logError(error);

      QNetworkRequest request(url);

      request.setRawHeader("Accept", "text/html");
      request.setRawHeader("User-Agent", s_user_agent);

      QNetworkReply *reply = m_contentNetworkAccessManager.get(request);

      if(!reply)
	{
	  emit logError
	    (QString("QNetworkAccessManager::get() failure on %1.").
	     arg(spoton_misc::urlToEncoded(url).constData()));
	  return;
	}

      reply->ignoreSslErrors();
      reply->setProperty("original-url", url);
      reply->setReadBufferSize(0);
      connect(reply,
	      SIGNAL(error(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
      connect(reply,
	      SIGNAL(finished(void)),
	      this,
	      SLOT(slotContentReplyFinished(void)));
    }
}

void spoton_rss::slotDownloadTimeout(void)
{
  if(!m_parseXmlFuture.isFinished())
    return;

  m_feedDownloadContent.clear();

  if(m_lastUniqueId.first.isEmpty())
    return;

  QNetworkRequest request
    (QUrl::fromUserInput(m_lastUniqueId.first.constData()));

  request.setRawHeader("Accept", "text/html");
  request.setRawHeader("User-Agent", s_user_agent);

  QNetworkReply *reply = m_feedNetworkAccessManager.get(request);

  if(!reply)
    {
      emit logError
	(QString("QNetworkAccessManager::get() failure on %1.").
	 arg(spoton_misc::urlToEncoded(request.url()).constData()));
      return;
    }

  reply->ignoreSslErrors();
  connect(reply,
	  SIGNAL(error(QNetworkReply::NetworkError)),
	  this,
	  SLOT(slotReplyError(QNetworkReply::NetworkError)));
  connect(reply,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotFeedReplyFinished(void)));
  connect(reply,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotFeedReplyReadyRead(void)));
  emit logError(QString("Downloading the feed %1.").
		arg(spoton_misc::urlToEncoded(reply->url()).constData()));
}

void spoton_rss::slotFeedReplyFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());
  QUrl url;

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      url = reply->url();

      QUrl redirectUrl
	(reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 toUrl());

      if(!reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 isNull())
	if(redirectUrl.isRelative())
	  redirectUrl = url.resolved(redirectUrl);

      reply->deleteLater();

      if(!redirectUrl.isEmpty())
	if(redirectUrl.isValid())
	  {
	    QString error
	      (QString("The feed URL %1 is being redirected to %2.").
	       arg(spoton_misc::urlToEncoded(url).constData()).
	       arg(spoton_misc::urlToEncoded(redirectUrl).constData()));

	    emit logError(error);

	    QNetworkRequest request(redirectUrl);

	    request.setRawHeader("Accept", "text/html");
	    request.setRawHeader("User-Agent", s_user_agent);
	    reply = m_feedNetworkAccessManager.get(request);

	    if(!reply)
	      {
		emit logError
		  (QString("QNetworkAccessManager::get() failure on %1.").
		   arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
		return;
	      }

	    reply->ignoreSslErrors();
	    connect(reply,
		    SIGNAL(error(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
	    connect(reply,
		    SIGNAL(finished(void)),
		    this,
		    SLOT(slotFeedReplyFinished(void)));
	    connect(reply,
		    SIGNAL(readyRead(void)),
		    this,
		    SLOT(slotFeedReplyReadyRead(void)));
	    url = QUrl();
	  }
    }
  else if(reply)
    {
      QString error
	(QString("The URL %1 could not be accessed correctly (%2).").
	 arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	 arg(reply->errorString()));

      emit logError(error);
      reply->deleteLater();
    }

  if(!m_feedDownloadContent.isEmpty())
    if(!url.isEmpty() && url.isValid())
      m_parseXmlFuture = QtConcurrent::run
	(this, &spoton_rss::parseXmlContent, m_feedDownloadContent, url);

  m_feedDownloadContent.clear();
}

void spoton_rss::slotFeedReplyReadyRead(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    m_feedDownloadContent.append(reply->readAll());
}

void spoton_rss::slotImport(void)
{
  for(int i = 0; i < m_importFutures.size(); i++)
    if(m_importFutures.at(i).isFinished())
      {
	m_importFutures.replace
	  (i,
	   QtConcurrent::run(this,
			     &spoton_rss::import,
			     spoton_kernel::
			     setting("gui/rss_maximum_keywords", 50).toInt()));
	break;
      }
}

void spoton_rss::slotLogError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  spoton_misc::logError(error);
}

void spoton_rss::slotPopulateFeeds(void)
{
  populateFeeds();
}

void spoton_rss::slotReplyError(QNetworkReply::NetworkError code)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());
  QString error("");

  if(reply)
    {
      error = QString("The URL %1 generated an error (%2).").
	arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	arg(reply->errorString());
      reply->deleteLater();
    }
  else
    error = QString("A QNetworkReply error (%1) occurred.").arg(code);

  emit logError(error);
}
