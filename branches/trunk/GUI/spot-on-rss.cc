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
#include <QMessageBox>
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QXmlStreamReader>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-pageviewer.h"
#include "spot-on-rss.h"

spoton_rss::spoton_rss(QWidget *parent):QMainWindow(parent)
{
  m_currentFeedRow = -1;
  m_ui.setupUi(this);
  m_ui.feeds->setColumnHidden(2, true); // OID
  m_ui.feeds->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.feeds->horizontalHeader()->setSortIndicator
    (1, Qt::AscendingOrder); // Feed
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
  connect(&m_statisticsTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatisticsTimeout(void)));
  connect(m_ui.action_Find,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotFindInitialize(void)));
  connect(m_ui.activate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActivate(bool)));
  connect(m_ui.add,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.download_interval,
	  SIGNAL(valueChanged(double)),
	  this,
	  SLOT(slotDownloadIntervalChanged(double)));
  connect(m_ui.feeds,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.find,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotFind(void)));
  connect(m_ui.find,
	  SIGNAL(textChanged(const QString &)),
	  this,
	  SLOT(slotFind(void)));
  connect(m_ui.new_feed,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.refresh_timeline,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshTimeline(void)));
  connect(m_ui.save_proxy_settings,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveProxy(void)));
  connect(m_ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));
  connect(m_ui.timeline,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotUrlLinkClicked(const QUrl &)));
  connect(this,
	  SIGNAL(downloadFeedImage(const QUrl &, const QUrl &)),
	  this,
	  SLOT(slotDownloadFeedImage(const QUrl &, const QUrl &)));
  m_originalFindPalette = m_ui.find->palette();
#if QT_VERSION >= 0x040700
  m_ui.find->setPlaceholderText(tr("Find Text"));
#endif
  QMenu *menu = new QMenu(this);

  menu->addAction(tr("Delete all feeds."),
		  this,
		  SLOT(slotDeleteAllFeeds(void)));
  menu->addAction(tr("Delete selected feed."),
		  this,
		  SLOT(slotDeleteFeed(void)));
  menu->addSeparator();
  menu->addAction(tr("Refresh table."),
		  this,
		  SLOT(slotPopulateFeeds(void)));
  m_ui.action_menu->setMenu(menu);
  connect(m_ui.action_menu,
	  SIGNAL(clicked(void)),
	  m_ui.action_menu,
	  SLOT(showMenu(void)));
  setWindowTitle(tr("%1: RSS").arg(SPOTON_APPLICATION_NAME));

  QSettings settings;
  bool state = false;
  double value = 1.50;

  state = settings.value("gui/rss_download_activate", false).toBool();
  value = qBound(m_ui.download_interval->minimum(),
		 settings.value("gui/rss_download_interval").toDouble(),
		 m_ui.download_interval->maximum());
  m_downloadContentTimer.setInterval(5 * 1000); // Every five seconds.
  m_downloadTimer.setInterval(static_cast<int> (60 * 1000 * value));
  m_importTimer.setInterval(2500);
  m_statisticsTimer.start(2500);

  if(state)
    {
      m_downloadContentTimer.start();
      m_downloadTimer.start();
      m_importTimer.start();
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();
  QApplication::restoreOverrideCursor();
}

spoton_rss::~spoton_rss()
{
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
  m_statisticsTimer.stop();
}

void spoton_rss::center(QWidget *parent)
{
  if(!parent)
    return;

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

void spoton_rss::closeEvent(QCloseEvent *event)
{
  QMainWindow::closeEvent(event);
}

void spoton_rss::deactivate(void)
{
  m_ui.activate->setChecked(false);
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_rss::event(QEvent *event)
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
	  show();
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

void spoton_rss::importUrl(const QList<QVariant> &list)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QSettings settings;
  bool ok = true;

  ok = spoton_misc::importUrl
    (list.value(0).toByteArray(),       // Content
     list.value(1).toString().toUtf8(), // Description
     list.value(2).toString().toUtf8(), // Title
     list.value(3).toUrl().toEncoded(), // URL
     spoton::instance() ? spoton::instance()->urlDatabase() : QSqlDatabase(),
     spoton_common::MAXIMUM_KEYWORDS_IN_URL_DESCRIPTION,
     settings.value("gui/disable_ui_synchronous_sqlite_url_import",
		    false).toBool(),
     spoton::instance() ? spoton::instance()->urlCommonCrypt() : 0);

  if(ok)
    {
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
			  "SET imported = 1 "
			  "WHERE url_hash = ?");
	    query.bindValue
	      (0, crypt->keyedHash(list.value(3).toUrl().toEncoded(), &ok).
	       toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton_rss::parseXmlContent(const QByteArray &data, const QUrl &url)
{
  /*
  ** Only thread-safe logic please!
  */

  if(data.isEmpty())
    return;

  QString currentTag("");
  QString description("");
  QString link(url.toString());
  QString title("");
  QUrl imageUrl;
  QXmlStreamReader reader(data);

  while(!reader.atEnd() && !reader.hasError())
    {
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
      else if(currentTag == "image")
	{
	  currentTag.clear();

	  if(imageUrl.isEmpty())
	    {
	      QString tag("");

	      while(true)
		{
		  reader.readNext();

		  if(reader.isEndElement())
		    {
		      if(reader.name().toString().toLower().
			 trimmed() == "image")
			break;
		    }
		  else if(reader.isStartElement())
		    tag = reader.name().toString().toLower().trimmed();

		  if(tag == "url")
		    {
		      reader.readNext();
		      imageUrl = QUrl::fromUserInput
			(reader.text().toString().trimmed());
		      break;
		    }

		  if(reader.atEnd() || reader.hasError())
		    break;
		}
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

	  while(true)
	    {
	      reader.readNext();

	      if(reader.isEndElement())
		{
		  if(reader.name().toString().toLower().trimmed() == "item")
		    break;
		}
	      else if(reader.isStartElement())
		tag = reader.name().toString().toLower().trimmed();

	      if(tag == "description")
		{
		  tag.clear();

		  if(description.isEmpty())
		    {
		      reader.readNext();
		      description = reader.text().toString().trimmed();
		    }
		}
	      else if(tag == "link")
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

	  saveFeedLink(description, link, publicationDate, title, url);
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

  saveFeedData(description, link, title);

  if(!imageUrl.isEmpty() && imageUrl.isValid())
    emit downloadFeedImage(imageUrl, url);

  QSettings settings;

  spoton_misc::importUrl
    (data, description.toUtf8(), title.toUtf8(), url.toEncoded(),
     spoton::instance() ? spoton::instance()->urlDatabase() : QSqlDatabase(),
     spoton_common::MAXIMUM_KEYWORDS_IN_URL_DESCRIPTION,
     settings.value("gui/disable_ui_synchronous_sqlite_url_import",
		    false).toBool(),
     spoton::instance() ? spoton::instance()->urlCommonCrypt() : 0);
}

void spoton_rss::populateFeeds(void)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int row = 0;

	m_ui.feeds->clearContents();
	m_ui.feeds->setRowCount(0);
	m_ui.feeds->setSortingEnabled(false);
	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM rss_feeds"))
	  if(query.next())
	    m_ui.feeds->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT echo, feed, feed_image, OID FROM rss_feeds"))
	  while(query.next())
	    {
	      QByteArray echo;
	      QByteArray feed;
	      QString oid(query.value(query.record().count() - 1).
			  toString());
	      QByteArray image;
	      QTableWidgetItem *item = 0;
	      bool ok = true;

	      echo = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      item = new QTableWidgetItem();
	      item->setFlags
		(Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 0, item);

	      if(!ok)
		item->setText(tr("error"));
	      else
		{
		  if(item->text() == "true")
		    item->setCheckState(Qt::Checked);
		  else
		    item->setCheckState(Qt::Unchecked);
		}

	      feed = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(1).toByteArray()), &ok);
	      item = new QTableWidgetItem();
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 1, item);

	      if(!ok)
		item->setText(tr("error"));
	      else
		item->setText(feed.constData());

	      if(ok)
		{
		  image = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(2).toByteArray()),
		     &ok);

		  if(ok)
		    {
		      QPixmap pixmap;

		      pixmap.loadFromData(image);
		      item->setIcon(pixmap);
		    }
		}

	      item = new QTableWidgetItem(oid);
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 2, item);
	      row += 1;
	    }

	m_ui.feeds->setRowCount(row);
	m_ui.feeds->setSortingEnabled(true);
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

	query.exec("CREATE TABLE IF NOT EXISTS rss_feeds ("
		   "echo TEXT NOT NULL, "
		   "feed TEXT NOT NULL, "
		   "feed_description TEXT NOT NULL, "
		   "feed_hash TEXT NOT NULL PRIMARY KEY, "
		   "feed_image BLOB NOT NULL, "
		   "feed_title TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS rss_feeds_links ("
		   "content TEXT NOT NULL, "
		   "description TEXT NOT NULL, "
		   "imported INTEGER NOT NULL DEFAULT 0, "
		   "insert_date TEXT NOT NULL, "
		   "publication_date TEXT NOT NULL, "
		   "title TEXT NOT NULL, "
		   "url TEXT NOT NULL, "
		   "url_hash TEXT NOT NULL PRIMARY KEY, "
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

void spoton_rss::restoreWidgets(void)
{
  QNetworkProxy proxy;

  proxy.setType(QNetworkProxy::NoProxy);
  m_networkAccessManager.setProxy(proxy);

  QSettings settings;
  double value = 1.50;
  int index = qBound(0,
		     settings.value("gui/rss_last_tab", 0).toInt(),
		     m_ui.tab->count());

  m_ui.activate->setChecked(settings.value("gui/rss_download_activate",
					   false).toBool());
  value = qBound(m_ui.download_interval->minimum(),
		 settings.value("gui/rss_download_interval", 1.50).toDouble(),
		 m_ui.download_interval->maximum());
  m_ui.download_interval->setValue(value);
  m_ui.tab->setCurrentIndex(index);

  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(crypt)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT enabled, hostname, password, port, type, "
			  "username FROM rss_proxy");

	    if(query.exec())
	      if(query.next())
		{
		  QList<QByteArray> list;

		  for(int i = 0; i < query.record().count(); i++)
		    {
		      QByteArray bytes;
		      bool ok = true;

		      bytes = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(i).
						toByteArray()), &ok);

		      if(ok)
			list << bytes;
		      else
			break;
		    }

		  if(list.size() != query.record().count() ||
		     list.value(0) == "false")
		    {
		      m_ui.proxy->setChecked(false);
		      m_ui.proxyHostname->clear();
		      m_ui.proxyPassword->clear();
		      m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
		      m_ui.proxyType->setCurrentIndex(0);
		      m_ui.proxyUsername->clear();
		    }
		  else
		    {
		      QNetworkProxy proxy;

		      m_ui.proxy->setChecked(true);
		      m_ui.proxyHostname->setText
			(QString::fromUtf8(list.value(1).constData()));
		      m_ui.proxyPassword->setText
			(QString::fromUtf8(list.value(2).constData()));
		      m_ui.proxyPort->setValue
			(list.value(3).toInt());

		      if(list.value(4) == "HTTP")
			{
			  m_ui.proxyType->setCurrentIndex(0);
			  proxy.setType(QNetworkProxy::HttpProxy);
			}
		      else if(list.value(4) == "Socks5")
			{
			  m_ui.proxyType->setCurrentIndex(1);
			  proxy.setType(QNetworkProxy::Socks5Proxy);
			}
		      else if(list.value(4) == "System")
			{
			  m_ui.proxyType->setCurrentIndex(2);

			  QNetworkProxyQuery proxyQuery;

			  proxyQuery.setQueryType
			    (QNetworkProxyQuery::UrlRequest);

			  QList<QNetworkProxy> proxies
			    (QNetworkProxyFactory::
			     systemProxyForQuery(proxyQuery));

			  if(!proxies.isEmpty())
			    proxy = proxies.at(0);
			  else
			    proxy.setType(QNetworkProxy::NoProxy);
			}
		      else
			{
			  m_ui.proxyType->setCurrentIndex(0);
			  proxy.setType(QNetworkProxy::NoProxy);
			}

		      m_ui.proxyUsername->setText
			(QString::fromUtf8(list.value(5).constData()));

		      if(proxy.type() != QNetworkProxy::NoProxy)
			{
			  proxy.setHostName
			    (m_ui.proxyHostname->text());
			  proxy.setPassword
			    (m_ui.proxyPassword->text());
			  proxy.setPort
			    (static_cast<quint16> (m_ui.proxyPort->value()));
			  proxy.setUser
			    (m_ui.proxyUsername->text());
			  m_networkAccessManager.setProxy(proxy);
			}
		    }
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton_rss::saveFeedData(const QString &description,
			      const QString &link,
			      const QString &title)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("UPDATE rss_feeds "
		      "SET feed_description = ?, "
		      "feed_title = ? "
		      "WHERE feed_hash = ?");
	query.bindValue
	  (0, crypt->encryptedThenHashed(description.toUtf8(),
					 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(title.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(link.toUtf8(), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::saveFeedImage(const QByteArray &data, const QString &link)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("UPDATE rss_feeds "
		      "SET feed_image = ? "
		      "WHERE feed_hash = ?");
	query.bindValue
	  (0, crypt->encryptedThenHashed(data, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(link.toUtf8(), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::saveFeedLink(const QString &description,
			      const QString &link,
			      const QString &publicationDate,
			      const QString &title,
			      const QUrl &url)
{
  Q_UNUSED(url);

  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("INSERT INTO rss_feeds_links ("
	   "content, description, insert_date, publication_date, "
	   "title, url, url_hash) VALUES (?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(qCompress(QByteArray(), 9), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(description.toUtf8(), &ok).
	     toBase64());

	query.bindValue
	  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(3, publicationDate);

	if(ok)
	  query.bindValue
	    (4, crypt->encryptedThenHashed(title.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed(link.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->keyedHash(link.toUtf8(), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::show(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();
  restoreWidgets();
  QApplication::restoreOverrideCursor();
  QMainWindow::show();
}

void spoton_rss::slotActivate(bool state)
{
  QSettings settings;

  settings.setValue("gui/rss_download_activate", state);

  if(state)
    {
      if(!m_downloadContentTimer.isActive()) // Signals.
	m_downloadContentTimer.start();

      if(!m_downloadTimer.isActive()) // Signals.
	m_downloadTimer.start();

      if(!m_importTimer.isActive()) // Signals.
	m_importTimer.start();
    }
  else
    {
      m_downloadContentTimer.stop();
      m_downloadTimer.stop();
      m_importTimer.stop();
    }
}

void spoton_rss::slotAddFeed(void)
{
  QString connectionName("");
  QString error("");
  QString new_feed(m_ui.new_feed->text().trimmed());
  QUrl url(QUrl::fromUserInput(new_feed));
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }
  else if(url.isEmpty() || !url.isValid())
    {
      error = tr("Please provide an RSS feed.");
      goto done_label;
    }
  else if(!(url.scheme().toLower() == "http" ||
	    url.scheme().toLower() == "https"))
    {
      error = tr("Invalid RSS feed scheme; HTTP or HTTPS.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("INSERT OR REPLACE INTO rss_feeds "
		      "(echo, feed, feed_description, feed_hash, "
		      "feed_image, feed_title) "
		      "VALUES (?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(new_feed.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue(2, crypt->encryptedThenHashed(QByteArray(),
							&ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->keyedHash(new_feed.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue(4, crypt->encryptedThenHashed(QByteArray(),
							&ok).toBase64());

	if(ok)
	  query.bindValue(5, crypt->encryptedThenHashed(QByteArray(),
							&ok).toBase64());

	if(ok)
	  ok = query.exec();

	if(!ok)
	  error = tr("Unable to insert the specified feed.");
      }
    else
      error = tr("Unable to access rss.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error.trimmed());
  else
    {
      m_ui.new_feed->clear();
      populateFeeds();
    }
}

void spoton_rss::slotContentReplyFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      spoton_crypt *crypt = spoton::instance() ?
	spoton::instance()->crypts().value("chat", 0) : 0;

      if(!crypt)
	{
	  reply->deleteLater();
	  return;
	}

      QByteArray data(reply->readAll());

      if(data.isEmpty())
	{
	  reply->deleteLater();
	  return;
	}

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
			  "SET content = ?, visited = 1 "
			  "WHERE url_hash = ?");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(qCompress(data, 9),
					     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(reply->url().toEncoded(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      reply->deleteLater();
    }
  else if(reply)
    reply->deleteLater();
}

void spoton_rss::slotDeleteAllFeeds(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to delete all of the RSS "
		"feeds?"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM rss_feeds");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateFeeds();
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotDeleteFeed(void)
{
  QString oid("");
  QTableWidgetItem *item = 0;
  int row = m_ui.feeds->currentRow();

  if((item = m_ui.feeds->item(row, 2)))
    oid = item->text();
  else
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM rss_feeds WHERE OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  m_ui.feeds->removeRow(row);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotDownloadContent(void)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  QUrl url;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT url FROM rss_feeds_links "
		      "WHERE visited = 0");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray bytes;
	      bool ok = true;

	      bytes = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		{
		  url = QUrl::fromEncoded(bytes);
		  break;
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(!url.isEmpty() && url.isValid())
    {
      QNetworkReply *reply = m_networkAccessManager.get(QNetworkRequest(url));

      reply->ignoreSslErrors();
      reply->setReadBufferSize(0);
      connect(reply,
	      SIGNAL(finished(void)),
	      this,
	      SLOT(slotContentReplyFinished(void)));
    }
}

void spoton_rss::slotDownloadFeedImage(const QUrl &imageUrl, const QUrl &url)
{
  if(!imageUrl.isEmpty() && imageUrl.isValid())
    {
      QNetworkReply *reply = m_networkAccessManager.get
	(QNetworkRequest(imageUrl));

      reply->ignoreSslErrors();
      reply->setProperty("url", url);
      connect(reply,
	      SIGNAL(finished(void)),
	      this,
	      SLOT(slotFeedImageReplyFinished(void)));
    }
}

void spoton_rss::slotDownloadIntervalChanged(double value)
{
  QSettings settings;

  settings.setValue("gui/rss_download_interval", value);
  m_downloadTimer.setInterval(static_cast<int> (60 * 1000 * value));
}

void spoton_rss::slotDownloadTimeout(void)
{
  m_feedDownloadContent.clear();

  QNetworkReply *reply = m_networkAccessManager.findChild
    <QNetworkReply *> ();

  if(reply)
    reply->deleteLater();

  if(m_ui.feeds->rowCount() == 0)
    return;

  m_currentFeedRow += 1;

  if(m_currentFeedRow >= m_ui.feeds->rowCount())
    m_currentFeedRow = 0;

  QTableWidgetItem *item = m_ui.feeds->item(m_currentFeedRow, 1);

  if(!item)
    {
      m_currentFeedRow = 0;
      return;
    }

  reply = m_networkAccessManager.get(QNetworkRequest(item->text()));
  reply->ignoreSslErrors();
  connect(reply,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotFeedReplyFinished(void)));
  connect(reply,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotFeedReplyReadyRead(void)));
}

void spoton_rss::slotFeedImageReplyFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      QByteArray data(reply->readAll());
      QPixmap pixmap;
      QUrl url(reply->property("url").toUrl());

      pixmap.loadFromData(data);
      reply->deleteLater();

      QList<QTableWidgetItem *> list(m_ui.feeds->findItems(url.toString(),
							   Qt::MatchExactly));

      if(!list.isEmpty())
	list.at(0)->setIcon(pixmap);

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      saveFeedImage(data, url.toString());
      QApplication::restoreOverrideCursor();
    }
  else if(reply)
    reply->deleteLater();
}

void spoton_rss::slotFeedReplyFinished(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());
  QUrl url;

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      url = reply->url();
      reply->deleteLater();
    }
  else if(reply)
    reply->deleteLater();

  if(!m_feedDownloadContent.isEmpty())
    if(!url.isEmpty() && url.isValid())
      parseXmlContent(m_feedDownloadContent, url);

  m_feedDownloadContent.clear();
}

void spoton_rss::slotFeedReplyReadyRead(void)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    m_feedDownloadContent.append(reply->readAll());
}

void spoton_rss::slotFind(void)
{
  if(m_ui.find->text().isEmpty())
    m_ui.find->setPalette(m_originalFindPalette);
  else if(!m_ui.timeline->find(m_ui.find->text()))
    {
      QColor color(240, 128, 128); // Light Coral
      QPalette palette(m_ui.find->palette());

      palette.setColor(m_ui.find->backgroundRole(), color);
      m_ui.find->setPalette(palette);
      m_ui.timeline->moveCursor(QTextCursor::Start);
    }
  else
    m_ui.find->setPalette(m_originalFindPalette);
}

void spoton_rss::slotFindInitialize(void)
{
  m_ui.find->selectAll();
  m_ui.find->setFocus();
}

void spoton_rss::slotImport(void)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QList<QVariant> list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT content, description, title, url "
		      "FROM rss_feeds_links WHERE "
		      "imported = 0 AND visited = 1");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray bytes;
	      bool ok = true;

	      bytes = qUncompress
		(crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		{
		  /*
		  ** Do not import empty content.
		  */

		  if(bytes.isEmpty())
		    ok = false;
		  else
		    list << bytes;
		}

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		list << QUrl::fromEncoded(bytes);

	      if(ok)
		break;
	      else
		list.clear();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(!list.isEmpty())
    importUrl(list);
}

void spoton_rss::slotPopulateFeeds(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotRefreshTimeline(void)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT content, description, publication_date, "
		      "title, url FROM rss_feeds_links ORDER BY "
		      "publication_date DESC");

	if(query.exec())
	  {
	    m_ui.timeline->clear();

	    while(query.next())
	      {
		QByteArray bytes;
		QList<QVariant> list;
		bool contentAvailable = false;
		bool ok = true;

		bytes = qUncompress
		  (crypt->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(0).
							  toByteArray()),
					       &ok));

		if(ok)
		  if(bytes.size() > 0)
		    contentAvailable = true;

		Q_UNUSED(contentAvailable);

		if(ok)
		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);

		if(ok)
		  list << QString::fromUtf8(bytes).trimmed();

		if(ok)
		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(3).toByteArray()),
		     &ok);

		if(ok)
		  list << QString::fromUtf8(bytes).trimmed();

		if(ok)
		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(4).toByteArray()),
		     &ok);

		if(ok)
		  list << QUrl::fromEncoded(bytes);

		if(list.size() == 3)
		  {
		    QString html("");

		    html.append("<a href=\"");
		    html.append(list.value(2).toUrl().toEncoded().constData());
		    html.append("\">");
		    html.append(list.value(1).toString());
		    html.append("</a>");
		    html.append("<br>");
		    html.append
		      (QString("<font color=\"green\" size=3>%1</font>").
		       arg(list.value(2).toUrl().toEncoded().constData()));
		    html.append("<br>");
		    html.append
		      (QString("<font color=\"gray\" size=3>%1</font>").
		       arg(list.value(0).toString()));
		    html.append("<br>");
		    html.append
		      (QString("<font color=\"gray\" size=3>%1</font>").
		       arg(query.value(2).toString().trimmed()));
		    html.append("<br>");
		    m_ui.timeline->append(html);

		    QTextCursor cursor = m_ui.timeline->textCursor();

		    cursor.setPosition(0);
		    m_ui.timeline->setTextCursor(cursor);
		  }
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotSaveProxy(void)
{
  QNetworkProxy proxy;

  proxy.setType(QNetworkProxy::NoProxy);
  m_networkAccessManager.setProxy(proxy);
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();

  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(crypt)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    QString enabled("false");
	    QString hostname(m_ui.proxyHostname->text().trimmed());
	    QString password(m_ui.proxyPassword->text());
	    QString port(QString::number(m_ui.proxyPort->value()));
	    QString type("");
	    QString username(m_ui.proxyUsername->text());
	    bool ok = true;

	    if(!m_ui.proxy->isChecked())
	      {
		m_ui.proxyHostname->clear();
		m_ui.proxyPassword->clear();
		m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
		m_ui.proxyType->setCurrentIndex(0);
		m_ui.proxyUsername->clear();
		hostname.clear();
		password.clear();
		port.clear();
		type.clear();
		username.clear();
	      }
	    else
	      {
		QNetworkProxy proxy;

		enabled = "true";

		if(m_ui.proxyType->currentIndex() == 0)
		  {
		    proxy.setType(QNetworkProxy::HttpProxy);
		    type = "HTTP";
		  }
		else if(m_ui.proxyType->currentIndex() == 1)
		  {
		    proxy.setType(QNetworkProxy::Socks5Proxy);
		    type = "Socks5";
		  }
		else
		  {
		    QNetworkProxyQuery proxyQuery;

		    proxyQuery.setQueryType
		      (QNetworkProxyQuery::UrlRequest);

		    QList<QNetworkProxy> proxies
		      (QNetworkProxyFactory::
		       systemProxyForQuery(proxyQuery));

		    if(!proxies.isEmpty())
		      proxy = proxies.at(0);
		    else
		      proxy.setType(QNetworkProxy::NoProxy);

		    type = "System";
		  }

		if(proxy.type() != QNetworkProxy::NoProxy)
		  {
		    proxy.setHostName
		      (m_ui.proxyHostname->text());
		    proxy.setPassword
		      (m_ui.proxyPassword->text());
		    proxy.setPort
		      (static_cast<quint16> (m_ui.proxyPort->value()));
		    proxy.setUser
		      (m_ui.proxyUsername->text());
		    m_networkAccessManager.setProxy(proxy);
		  }
	      }

	    query.prepare
	      ("INSERT OR REPLACE INTO rss_proxy ("
	       "enabled, hostname, password, port, type, username) "
	       "VALUES (?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(enabled.toLatin1(), &ok).
	       toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->encryptedThenHashed(hostname.toUtf8(),
					       &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->encryptedThenHashed(password.toUtf8(),
					       &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->encryptedThenHashed(port.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->encryptedThenHashed(type.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(5, crypt->encryptedThenHashed(username.toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  menu.addAction(tr("Delete all feeds."),
		 this, SLOT(slotDeleteAllFeeds(void)));
  menu.addAction(tr("Delete selected feed."),
		 this, SLOT(slotDeleteFeed(void)));
  menu.addSeparator();
  menu.addAction(tr("Refresh table."),
		 this, SLOT(slotPopulateFeeds(void)));
  menu.exec(m_ui.feeds->mapToGlobal(point));
}

void spoton_rss::slotStatisticsTimeout(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.statistics->setText(tr("0 <b>RSS Feeds</b> / "
			      "0 <b>Imported URLs</b> / "
			      "0 <b>Not Imported URLs</b> / "
			      "0 <b>Visited URLs</b> / "
			      "0 <b>Not Visited URLs</b> / "
			      "0 <b>Total URLs</b>"));

  QList<QVariant> list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QList<int> counts;
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*), 'a' FROM rss_feeds "
		      "UNION "
		      "SELECT COUNT(*), 'b' FROM rss_feeds_links "
		      "WHERE imported <> 0 "
		      "UNION "
		      "SELECT COUNT(*), 'c' FROM rss_feeds_links "
		      "WHERE imported = 0 "
		      "UNION "
		      "SELECT COUNT(*), 'd' FROM rss_feeds_links "
		      "WHERE visited <> 0 "
		      "UNION "
		      "SELECT COUNT(*), 'e' FROM rss_feeds_links "
		      "WHERE visited = 0 "
		      "UNION "
		      "SELECT COUNT(*), 'f' FROM rss_feeds_links "
		      "ORDER BY 2");

	if(query.exec())
	  while(query.next())
	    counts << query.value(0).toInt();

	QLocale locale;

	m_ui.statistics->setText
	  (tr("%1 <b>RSS Feeds</b> / "
	      "%2 <b>Imported URLs</b> / "
	      "%3 <b>Not Imported URLs</b> / "
	      "%4 <b>Visited URLs</b> / "
	      "%5 <b>Not Visited URLs</b> / "
	      "%6 <b>Total URLs</b>").
	   arg(locale.toString(counts.value(0))).
	   arg(locale.toString(counts.value(1))).
	   arg(locale.toString(counts.value(2))).
	   arg(locale.toString(counts.value(3))).
	   arg(locale.toString(counts.value(4))).
	   arg(locale.toString(counts.value(5))));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotTabChanged(int index)
{
  QSettings settings;

  settings.setValue("gui/rss_last_tab", index);
}

void spoton_rss::slotUrlLinkClicked(const QUrl &url)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  spoton_pageviewer *pageViewer = new spoton_pageviewer
    (QSqlDatabase(), QString(), this);

  pageViewer->setPage(0, QUrl("http://127.0.0.1"), 0);

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT content FROM rss_feeds_links WHERE "
		      "url_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(url.toEncoded(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray content;
	      bool ok = true;

	      content = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		pageViewer->setPage
		  (QString::fromUtf8(qUncompress(content).constData()),
		   url, query.value(0).toByteArray().length());
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  pageViewer->showNormal();
  pageViewer->activateWindow();
  pageViewer->raise();
  QApplication::restoreOverrideCursor();
  spoton::centerWidget(pageViewer, this);
}
