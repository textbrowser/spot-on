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
#include <QProgressDialog>
#include <QSettings>
#include <QScopedPointer>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QXmlStreamReader>

#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-pageviewer.h"
#include "spot-on-rss.h"

spoton_rss::spoton_rss(QWidget *parent):QMainWindow(parent)
{
  m_currentFeedRow = -1;
  m_ui.setupUi(this);
  m_ui.feeds->setColumnHidden(m_ui.feeds->columnCount() - 1, true); // OID
  m_ui.feeds->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.feeds->setIconSize(QSize(48, 48));
  m_ui.feeds->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder); // Feed
#if QT_VERSION >= 0x050000
  m_ui.feeds->verticalHeader()->setSectionResizeMode
    (QHeaderView::ResizeToContents);
#else
  m_ui.feeds->verticalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#endif
  m_ui.proxy_frame->setVisible(m_ui.proxy->isChecked());
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
  connect(m_ui.action_Descriptions_in_Timeline,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimelineShowOption(bool)));
  connect(m_ui.action_Find,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotFindInitialize(void)));
  connect(m_ui.action_Import,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotImport(void)));
  connect(m_ui.action_Insert_Date,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimeOrderBy(bool)));
  connect(m_ui.action_Publication_Date,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimeOrderBy(bool)));
  connect(m_ui.action_Publication_Dates_in_Timeline,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimelineShowOption(bool)));
  connect(m_ui.action_Toggle_Hidden,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_Toggle_Imported,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_Toggle_Indexed,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_Toggle_Malformed,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_Toggle_Not_Indexed,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_Toggle_Shown,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
  connect(m_ui.action_URL_Links_in_Timeline,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimelineShowOption(bool)));
  connect(m_ui.activate,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActivate(bool)));
  connect(m_ui.add,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.clear_errors,
	  SIGNAL(clicked(void)),
	  m_ui.errors,
	  SLOT(clear(void)));
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
  connect(m_ui.import_periodically,
	  SIGNAL(toggled(bool)),
	  m_ui.action_Import,
	  SLOT(setDisabled(bool)));
  connect(m_ui.import_periodically,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActivateImport(bool)));
  connect(m_ui.maximum_keywords,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumKeywordsChanged(int)));
  connect(m_ui.new_feed,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.proxy,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotProxyClicked(bool)));
  connect(m_ui.purge,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPurge(void)));
  connect(m_ui.purge_days,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotPurgeDaysChanged(int)));
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
	  SLOT(slotUrlClicked(const QUrl &)));
  connect(m_ui.timeline_filter,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotRefreshTimeline(void)));
  connect(this,
	  SIGNAL(downloadFeedImage(const QUrl &, const QUrl &)),
	  this,
	  SLOT(slotDownloadFeedImage(const QUrl &, const QUrl &)));
  m_originalFindPalette = m_ui.find->palette();
#if QT_VERSION >= 0x040700
  m_ui.find->setPlaceholderText(tr("Find Text"));
#endif
  QMenu *menu = new QMenu(this);

  menu->addAction(tr("Copy selected &link."),
		  this,
		  SLOT(slotCopyFeedLink(void)));
  menu->addSeparator();
  menu->addAction(tr("Delete &all feeds."),
		  this,
		  SLOT(slotDeleteAllFeeds(void)));
  menu->addAction(tr("Delete &selected feed."),
		  this,
		  SLOT(slotDeleteFeed(void)));
  menu->addSeparator();
  menu->addAction(tr("&Refresh table."),
		  this,
		  SLOT(slotPopulateFeeds(void)));
  menu->addSeparator();
  menu->addAction(tr("&Schedule selected feed for update."),
		  this, SLOT(slotScheduleFeedUpdate(void)));
  m_ui.action_menu->setMenu(menu);
  connect(m_ui.action_menu,
	  SIGNAL(clicked(void)),
	  m_ui.action_menu,
	  SLOT(showMenu(void)));
  setWindowTitle(tr("%1: RSS").arg(SPOTON_APPLICATION_NAME));

  QSettings settings;
  QString str("");
  double dvalue = 0.0;
  int index = 0;
  int ivalue = 0;

  m_ui.action_Descriptions_in_Timeline->setChecked
    (settings.value("gui/rss_descriptions_in_timeline", true).toBool());
  m_ui.action_Publication_Dates_in_Timeline->setChecked
    (settings.value("gui/rss_publication_dates_in_timeline", true).toBool());
  m_ui.action_URL_Links_in_Timeline->setChecked
    (settings.value("gui/rss_url_links_in_timeline", true).toBool());
  m_ui.activate->setChecked(settings.value("gui/rss_download_activate",
					   false).toBool());
  m_ui.import_periodically->setChecked
    (settings.value("gui/rss_import_activate", false).toBool());
  m_ui.action_Import->setEnabled(!m_ui.import_periodically->isChecked());
  ivalue = qBound(m_ui.maximum_keywords->minimum(),
		  settings.value("gui/rss_maximum_keywords", 50).toInt(),
		  m_ui.maximum_keywords->maximum());
  m_ui.maximum_keywords->setValue(ivalue);
  index = qBound(0,
		 settings.value("gui/rss_last_tab", 0).toInt(),
		 m_ui.tab->count());
  m_ui.tab->setCurrentIndex(index);
  m_downloadContentTimer.setInterval(2500);
  dvalue = qBound
    (m_ui.download_interval->minimum(),
     settings.value("gui/rss_download_interval", 1.50).toDouble(),
     m_ui.download_interval->maximum());
  m_downloadTimer.setInterval(static_cast<int> (60 * 1000 * dvalue));
  m_ui.download_interval->setValue(dvalue);
  ivalue = qBound
    (m_ui.purge_days->minimum(),
     settings.value("gui/rss_purge_days", 1).toInt(),
     m_ui.purge_days->maximum());
  m_ui.purge_days->setValue(ivalue);
  str = settings.value("gui/rss_time_order", "publication_date").toString().
    toLower().trimmed();

  if(str == "insert_date")
    m_ui.action_Insert_Date->setChecked(true);
  else
    m_ui.action_Publication_Date->setChecked(true);

  m_importTimer.setInterval(2500);
  m_statisticsTimer.start(2500);

  if(m_ui.activate->isChecked())
    {
      m_downloadContentTimer.start();
      m_downloadTimer.start();
    }

  if(m_ui.import_periodically->isChecked())
    m_importTimer.start();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();
  QApplication::restoreOverrideCursor();
  restoreGeometry(settings.value("gui/rss_window_geometry").toByteArray());
  restoreState(settings.value("gui/rss_window_state").toByteArray());
}

spoton_rss::~spoton_rss()
{
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
  m_statisticsTimer.stop();
  m_parseXmlFuture.cancel();
  m_parseXmlFuture.waitForFinished();
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

bool spoton_rss::importUrl(const QList<QVariant> &list, const bool batch)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return false;

  QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());

  if(!ucc)
    return false;

  if(!(spoton::instance() ? spoton::instance()->urlDatabase() :
       QSqlDatabase()).isOpen())
    return false;

  QSettings settings;
  QUrl url(list.value(4).toUrl());
  bool imported = true;

  if(url.isEmpty() || !url.isValid())
    url = list.value(3).toUrl();

  imported = spoton_misc::importUrl
    (list.value(0).toByteArray(),
     list.value(1).toString().toUtf8(), // Description
     list.value(2).toString().toUtf8(), // Title
     url.toEncoded(),                   // URL
     spoton::instance() ? spoton::instance()->urlDatabase() : QSqlDatabase(),
     m_ui.maximum_keywords->value(),
     settings.value("gui/disable_ui_synchronous_sqlite_url_import",
		    false).toBool(),
     ucc.data());

  if(batch)
    return imported;

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
			"SET imported = ? "
			"WHERE url_hash = ?");

	  if(imported)
	    query.bindValue(0, 1);
	  else
	    query.bindValue(0, 2); // Error.

	  query.bindValue
	    (1, crypt->keyedHash(list.value(3).toUrl().toEncoded(), &ok).
	     toBase64());

	  if(ok)
	    query.exec();
	}

      db.close();
    }

    QSqlDatabase::removeDatabase(connectionName);
  }

  return imported;
}

spoton_crypt *spoton_rss::urlCommonCrypt(void) const
{
  return spoton_misc::retrieveUrlCommonCredentials
    (spoton::instance() ? spoton::instance()->crypts().value("chat", 0) : 0);
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
  QSettings settings;

  settings.setValue("gui/rss_window_geometry", saveGeometry());
  settings.setValue("gui/rss_window_state", saveState());
  QMainWindow::closeEvent(event);
}

void spoton_rss::deactivate(void)
{
  m_ui.action_Import->setEnabled(true);
  m_ui.activate->setChecked(false);
  m_ui.import_periodically->setChecked(false);
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
  m_parseXmlFuture.cancel();
  m_parseXmlFuture.waitForFinished();
}

void spoton_rss::hideUrl(const QUrl &url, const bool state)
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
	QString scheme(url.scheme());
	QUrl u(url);
	bool ok = true;

	if(scheme.startsWith("hide-"))
	  scheme.remove(0, 5);

	if(scheme.startsWith("remove-"))
	  scheme.remove(0, 7);

	if(scheme.startsWith("visible-"))
	  scheme.remove(0, 8);

	u.setScheme(scheme);
	query.prepare("UPDATE rss_feeds_links SET hidden = ? "
		      "WHERE url_hash = ?");
	query.bindValue(0, state ? 1 : 0);
	query.bindValue
	  (1, crypt->keyedHash(u.toEncoded(), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  slotRefreshTimeline();
}

void spoton_rss::logError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  m_ui.errors->append(QDateTime::currentDateTime().toString(Qt::ISODate));
  m_ui.errors->append(QString(error).trimmed().append("<br>"));
  spoton_misc::logError(error);
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
  QUrl imageUrl;
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
      else if(currentTag == "image")
	{
	  currentTag.clear();

	  if(imageUrl.isEmpty())
	    {
	      QString tag("");

	      while(true)
		{
		  if(m_parseXmlFuture.isCanceled())
		    break;

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

  if(!imageUrl.isEmpty() && imageUrl.isValid())
    emit downloadFeedImage(imageUrl, url);

  QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());
  QSettings settings;

  spoton_misc::importUrl
    (data,
     description.toUtf8(),
     title.toUtf8(),
     url.toEncoded(),
     spoton::instance() ? spoton::instance()->urlDatabase() : QSqlDatabase(),
     m_ui.maximum_keywords->value(),
     settings.value("gui/disable_ui_synchronous_sqlite_url_import",
		    false).toBool(),
     ucc.data());
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

	if(query.exec("SELECT feed, feed_image, OID FROM rss_feeds"))
	  while(query.next())
	    {
	      QByteArray feed;
	      QString oid(query.value(query.record().count() - 1).
			  toString());
	      QByteArray image;
	      QTableWidgetItem *item = 0;
	      bool ok = true;

	      feed = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
	      item = new QTableWidgetItem();
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 0, item);

	      if(!ok)
		item->setText(tr("error"));
	      else
		item->setText(feed.constData());

	      if(ok)
		{
		  image = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);

		  if(ok)
		    {
		      QPixmap pixmap;

		      pixmap.loadFromData(image);

		      if(!pixmap.isNull())
			item->setIcon(pixmap);
		      else
			item->setIcon(QIcon(":/generic/rss.png"));
		    }
		  else
		    item->setIcon(QIcon(":/generic/rss.png"));
		}
	      else
		item->setIcon(QIcon(":/generic/rss.png"));

	      item = new QTableWidgetItem(oid);
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 1, item);
	      row += 1;
	    }

	m_ui.feeds->resizeColumnToContents(0);
	m_ui.feeds->setRowCount(row);
	m_ui.feeds->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::prepareAfterAuthentication(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();

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
		      m_ui.proxy_frame->setVisible(false);
		    }
		  else
		    {
		      QNetworkProxy proxy;

		      m_ui.proxy->setChecked(true);
		      m_ui.proxyHostname->setText
			(QString::fromUtf8(list.value(1).constData(),
					   list.value(1).length()));
		      m_ui.proxyPassword->setText
			(QString::fromUtf8(list.value(2).constData(),
					   list.value(2).length()));
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
			(QString::fromUtf8(list.value(5).constData(),
					   list.value(5).length()));
		      m_ui.proxy_frame->setVisible(true);

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

  QApplication::restoreOverrideCursor();
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

void spoton_rss::saveFeedLink(const QString &d,
			      const QString &link,
			      const QString &p,
			      const QString &t,
			      const QUrl &url)
{
  Q_UNUSED(url);

  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
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
	  query.bindValue
	    (7, crypt->encryptedThenHashed(QByteArray(), &ok).
	     toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::show(void)
{
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
    }
  else
    {
      m_downloadContentTimer.stop();
      m_downloadTimer.stop();
    }
}

void spoton_rss::slotActivateImport(bool state)
{
  QSettings settings;

  settings.setValue("gui/rss_import_activate", state);

  if(state)
    {
      if(!m_importTimer.isActive()) // Signals;
	m_importTimer.start();
    }
  else
    m_importTimer.stop();
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
      error = tr("Invalid RSS feed scheme; HTTP or HTTPS please.");
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
		      "(feed, feed_description, feed_hash, "
		      "feed_image, feed_title) "
		      "VALUES (?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(new_feed.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->encryptedThenHashed(QByteArray(),
							&ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(new_feed.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue(3, crypt->encryptedThenHashed(QByteArray(),
							&ok).toBase64());

	if(ok)
	  query.bindValue(4, crypt->encryptedThenHashed(QByteArray(),
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
	      (QString("The URL <a href=\"%1\">%1</a> is being "
		       "redirected to <a href=\"%2\">%2</a>.").
	       arg(reply->url().toEncoded().constData()).
	       arg(redirectUrl.toEncoded().constData()));
	    QUrl originalUrl(reply->property("original-url").toUrl());

	    logError(error);
	    reply->deleteLater();
	    reply = m_networkAccessManager.get(QNetworkRequest(redirectUrl));
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
      spoton_crypt *crypt = spoton::instance() ?
	spoton::instance()->crypts().value("chat", 0) : 0;

      if(!crypt)
	{
	  reply->deleteLater();
	  return;
	}

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
	      (0, crypt->
	       encryptedThenHashed(qCompress(data, 9), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->encryptedThenHashed(reply->url().toEncoded(),
					       &ok).toBase64());

	    if(data.isEmpty() || reply->error() != QNetworkReply::NoError)
	      {
		query.bindValue(2, 2); // Error.

		if(data.isEmpty())
		  {
		    QString error
		      (QString("The URL <a href=\"%1\">%1</a> "
			       "does not have data.").
		       arg(reply->url().toEncoded().constData()));

		    logError(error);
		  }
		else
		  {
		    QString error
		      (QString("The URL <a href=\"%1\">%1</a> "
			       "cannot be indexed "
			       "(%2).").
		       arg(reply->url().toEncoded().constData()).
		       arg(reply->errorString()));

		    logError(error);
		  }
	      }
	    else
	      query.bindValue(2, 1);

	    if(ok)
	      query.bindValue
		(3, crypt->
		 keyedHash(reply->property("original-url").toUrl().
			   toEncoded(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      reply->deleteLater();
    }
}

void spoton_rss::slotCopyFeedLink(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QTableWidgetItem *item = m_ui.feeds->item(m_ui.feeds->currentRow(), 0);

  if(!item)
    return;

  clipboard->setText(item->text());
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

  if((item = m_ui.feeds->item(row, m_ui.feeds->columnCount() - 1)))
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

void spoton_rss::slotDownloadFeedImage(const QUrl &imageUrl, const QUrl &url)
{
  if(!imageUrl.isEmpty() && imageUrl.isValid())
    {
      QNetworkReply *reply = m_networkAccessManager.get
	(QNetworkRequest(imageUrl));

      reply->ignoreSslErrors();
      reply->setProperty("url", url);
      connect(reply,
	      SIGNAL(error(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
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
  if(!m_parseXmlFuture.isFinished())
    return;

  m_feedDownloadContent.clear();

  if(m_ui.feeds->rowCount() == 0)
    return;

  m_currentFeedRow += 1;

  if(m_currentFeedRow >= m_ui.feeds->rowCount())
    m_currentFeedRow = 0;

  QTableWidgetItem *item = m_ui.feeds->item(m_currentFeedRow, 0);

  if(!item)
    {
      m_currentFeedRow = 0;
      return;
    }

  QNetworkReply *reply = m_networkAccessManager.get
    (QNetworkRequest(item->text()));

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
  logError(QString("Downloading feed <a href=\"%1\">%1</a>.").
	   arg(reply->url().toEncoded().constData()));
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
	      (QString("The feed URL <a href=\"%1\">%1</a> "
		       "is being redirected to <a href=\"%2\">%2</a>.").
	       arg(url.toEncoded().constData()).
	       arg(redirectUrl.toEncoded().constData()));

	    logError(error);
	    reply = m_networkAccessManager.get(QNetworkRequest(redirectUrl));
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
	(QString("The URL <a href=\"%1\">%1</a> "
		 "could not be accessed correctly (%2).").
	 arg(reply->url().toEncoded().constData()).arg(reply->errorString()));

      logError(error);
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
  QAction *action = qobject_cast<QAction *> (sender());
  bool batch = false;
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(action == m_ui.action_Import)
    {
      if(!crypt)
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Invalid spoton_crypt object. This is a fatal flaw."));
	  return;
	}

      if(!(spoton::instance() ? spoton::instance()->urlDatabase() :
	   QSqlDatabase()).isOpen())
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Please connect to a URL database."));
	  return;
	}

      QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());

      if(!ucc)
	{
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("Did you prepare common credentials?"));
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
      mb.setText(tr("Did you prepare your databases and distillers?"));
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	return;

      QMessageBox::information
		 (this, tr("%1: Information").
		  arg(SPOTON_APPLICATION_NAME),
		  tr("Please note that the URL-import process may "
		     "require a considerable amount of time to complete."));

      batch = true;
      m_downloadContentTimer.stop();
      m_downloadTimer.stop();
      m_importTimer.stop();
    }
  else
    {
      if(!crypt)
	return;
    }

  if(!batch)
    QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QList<QVariant> list;
  QProgressDialog *progress = 0;
  QString connectionName("");

  if(batch)
    {
      if(spoton::instance())
	spoton::instance()->populateUrlDistillers();

      progress = new QProgressDialog(this);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      progress->setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      progress->setLabelText(tr("Importing URLs. Please be patient."));
      progress->setMaximum(0);
      progress->setMinimum(0);
      progress->setModal(true);
      progress->setWindowTitle(tr("%1: Importing URLs").
			       arg(SPOTON_APPLICATION_NAME));
      progress->show();
      progress->raise();
      progress->activateWindow();
#ifndef Q_OS_MAC
      progress->repaint();
      QApplication::processEvents();
#endif
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare
	  ("SELECT content, description, title, url, url_hash, "
	   "url_redirected "
	   "FROM rss_feeds_links WHERE "
	   "imported = 0 AND visited = 1");

	if(query.exec())
	  while(query.next())
	    {
	      if(progress)
		{
		  if(progress->wasCanceled())
		    break;

#ifndef Q_OS_MAC
		  progress->repaint();
		  QApplication::processEvents();
#endif
		}

              QByteArray bytes;
	      QByteArray urlHash(query.value(4).toByteArray());
	      bool ok = true;

	      bytes = qUncompress
		(crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		list << bytes;

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		list << QUrl::fromEncoded(bytes);

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

	      if(ok)
		{
		  QUrl url(QUrl::fromEncoded(bytes));

		  if(!url.isEmpty() && url.isValid())
		    list << url;
		}

	      if(batch)
		{
		  bool imported = false;

		  if(!list.isEmpty())
		    imported = importUrl(list, true);

		  QSqlQuery query(db);

		  query.prepare("UPDATE rss_feeds_links "
				"SET imported = ? "
				"WHERE url_hash = ?");

		  if(imported)
		    query.bindValue(0, 1);
		  else
		    query.bindValue(0, 2); // Import error.

		  query.bindValue(1, urlHash);
		  query.exec();
		  list.clear();
		}
	      else
		{
		  if(ok)
		    break;
		  else
		    list.clear();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!batch)
    {
      if(!list.isEmpty())
	{
	  if(spoton::instance())
	    spoton::instance()->populateUrlDistillers();

	  importUrl(list, false);
	}

      QApplication::restoreOverrideCursor();
    }
  else
    {
      if(m_ui.activate->isChecked())
	{
          m_downloadContentTimer.start();
	  m_downloadTimer.start();
	}

      if(m_ui.import_periodically->isChecked())
	m_importTimer.start();
    }

  if(progress)
    {
      progress->close();
      progress->deleteLater();
    }
}

void spoton_rss::slotMaximumKeywordsChanged(int value)
{
  QSettings settings;

  settings.setValue("gui/rss_maximum_keywords", value);
}

void spoton_rss::slotPopulateFeeds(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotProxyClicked(bool state)
{
  m_ui.proxyHostname->clear();
  m_ui.proxyPassword->clear();
  m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
  m_ui.proxyType->setCurrentIndex(0);
  m_ui.proxyUsername->clear();
  m_ui.proxy_frame->setVisible(state);
}

void spoton_rss::slotPurge(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to purge obsolete links?"));
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
	query.prepare
	  ("DELETE FROM rss_feeds_links WHERE "
	   "ABS(strftime('%s', ?) - strftime('%s', insert_date)) > ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(1, 60 * 60 * 24 * m_ui.purge_days->value());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  slotRefreshTimeline();
}

void spoton_rss::slotPurgeDaysChanged(int value)
{
  QSettings settings;

  settings.setValue("gui/rss_purge_days", value);
}

void spoton_rss::slotRefreshTimeline(void)
{
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Populating..."));
  progress.setMaximum(0);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Populating").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.raise();
  progress.activateWindow();
#ifndef Q_OS_MAC
  progress.repaint();
  QApplication::processEvents();
#endif
  m_ui.timeline->clear();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString str1("");
	QString str2("");
	int i = 0;

	query.setForwardOnly(true);
	str2 = "SELECT content, description, hidden, publication_date, "
	  "title, url, url_redirected FROM rss_feeds_links ";

	if(m_ui.timeline_filter->currentIndex() == 1)
	  str1.append(" WHERE hidden = 1 ");
	else if(m_ui.timeline_filter->currentIndex() == 2)
	  str1.append(" WHERE hidden <> 1 AND imported = 1 ");
	else if(m_ui.timeline_filter->currentIndex() == 3)
	  str1.append(" WHERE hidden <> 1 AND visited = 1 ");
	else if(m_ui.timeline_filter->currentIndex() == 4)
	  str1.append(" WHERE hidden <> 1 AND (imported = 2 OR visited = 2) ");
	else if(m_ui.timeline_filter->currentIndex() == 5)
	  str1.append(" WHERE hidden <> 1 AND imported <> 1 ");
	else
	  str1.append(" WHERE hidden <> 1 ");

	str2.append(str1);
	str1.prepend("SELECT COUNT(*) FROM rss_feeds_links ");

	if(m_ui.action_Insert_Date->isChecked())
	  str2.append("ORDER BY insert_date DESC");
	else
	  str2.append("ORDER BY publication_date DESC");

	if(query.exec(str1))
	  if(query.next())
	    progress.setMaximum(query.value(0).toInt());

	if(query.exec(str2))
	  /*
	  ** 0 - content
	  ** 1 - description
	  ** 2 - hidden
	  ** 3 - publication_date
	  ** 4 - title
	  ** 5 - url
	  ** 6 - url_redirected
	  */

	  while(query.next())
	    {
	      if(progress.wasCanceled())
		break;

	      if(i <= progress.maximum())
		progress.setValue(i);

#ifndef Q_OS_MAC
	      progress.repaint();
	      QApplication::processEvents();
#endif

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

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok);

	      if(ok)
		list << QString::fromUtf8(bytes.constData(),
					  bytes.length()).trimmed();

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

	      if(ok)
		list << QUrl::fromEncoded(bytes);

	      if(ok)
		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(6).toByteArray()),
		   &ok);

	      if(ok)
		list << QUrl::fromEncoded(bytes);

	      if(list.size() == 4)
		{
		  /*
		  ** 0 - description
		  ** 1 - title
		  ** 2 - url
		  ** 3 - url_redirected
		  */

		  QString html("");
		  QUrl url(list.value(3).toUrl());

		  if(url.isEmpty() || !url.isValid())
		    url = list.value(2).toUrl();

		  if(contentAvailable)
		    {
		      html.append("<a href=\"");
		      html.append(list.value(2).toUrl().
				  toEncoded().constData());
		      html.append("\">");
		      html.append
			(spoton_misc::
			 removeSpecialHtmlTags(list.value(1).toString()));
		      html.append("</a>");
		    }
		  else
		    html.append
		      (spoton_misc::
		       removeSpecialHtmlTags(list.value(1).toString()));

		  if(query.value(2).toInt() != 1)
		    {
		      html.append(" | ");
		      html.append("<a href=\"hide-");
		      html.append(list.value(2).toUrl().
				  toEncoded().constData());
		      html.append("\">");
		      html.append("Hide URL");
		      html.append("</a>");
		      html.append(" | ");
		      html.append("<a href=\"remove-");
		      html.append(list.value(2).toUrl().
				  toEncoded().constData());
		      html.append("\">");
		      html.append("Remove URL");
		      html.append("</a>");
		    }
		  else
		    {
		      html.append(" | ");
		      html.append("<a href=\"remove-");
		      html.append(list.value(2).toUrl().
				  toEncoded().constData());
		      html.append("\">");
		      html.append("Remove URL");
		      html.append("</a>");
		      html.append(" | ");
		      html.append("<a href=\"visible-");
		      html.append(list.value(2).toUrl().
				  toEncoded().constData());
		      html.append("\">");
		      html.append("Show URL");
		      html.append("</a>");
		    }

		  html.append("<br>");

		  if(m_ui.action_URL_Links_in_Timeline->isChecked())
		    {
		      html.append
			(QString("<font color=\"green\" size=3>%1</font>").
			 arg(url.toEncoded().constData()));
		      html.append("<br>");
		    }

		  if(m_ui.action_Descriptions_in_Timeline->isChecked())
		    {
		      html.append
			(QString("<font color=\"gray\" size=3>%1</font>").
			 arg(spoton_misc::
			     removeSpecialHtmlTags(list.value(0).
						   toString())));
		      html.append("<br>");
		    }

		  if(m_ui.action_Publication_Dates_in_Timeline->isChecked())
		    {
		      html.append
			(QString("<font color=\"gray\" size=3>%1</font>").
			 arg(query.value(3).toString().trimmed()));
		      html.append("<br>");
		    }

		  m_ui.timeline->append(html);

		  QTextCursor cursor = m_ui.timeline->textCursor();

		  cursor.setPosition(0);
		  m_ui.timeline->setTextCursor(cursor);
		}

	      i += 1;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::slotReplyError(QNetworkReply::NetworkError code)
{
  QNetworkReply *reply = qobject_cast<QNetworkReply *> (sender());
  QString error("");

  if(reply)
    {
      error = QString("The URL <a href=\"%1\">%1</a> "
		      "generated an error (%2).").
	arg(reply->url().toEncoded().constData()).
	arg(reply->errorString());
      reply->deleteLater();
    }
  else
    error = QString("A QNetworkReply error (%1) occurred.").arg(code);

  logError(error);
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

void spoton_rss::slotScheduleFeedUpdate(void)
{
  m_currentFeedRow = m_ui.feeds->currentRow() - 1;
}

void spoton_rss::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  menu.addAction(tr("Copy selected &link."),
		 this, SLOT(slotCopyFeedLink(void)));
  menu.addSeparator();
  menu.addAction(tr("Delete &all feeds."),
		 this, SLOT(slotDeleteAllFeeds(void)));
  menu.addAction(tr("Delete &selected feed."),
		 this, SLOT(slotDeleteFeed(void)));
  menu.addSeparator();
  menu.addAction(tr("&Refresh table."),
		 this, SLOT(slotPopulateFeeds(void)));
  menu.addSeparator();
  menu.addAction(tr("&Schedule selected feed for update."),
		 this, SLOT(slotScheduleFeedUpdate(void)));
  menu.exec(m_ui.feeds->mapToGlobal(point));
}

void spoton_rss::slotStatisticsTimeout(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  statusBar()->showMessage(tr("0 RSS Feeds | "
			      "0 Hidden URLs | "
			      "0 Imported URLs | "
			      "0 Not Imported URLs | "
			      "0 Indexed URLs | "
			      "0 Not Indexed URLs | "
			      "0 Total URLs"));

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
		      "WHERE hidden = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'c' FROM rss_feeds_links "
		      "WHERE imported = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'd' FROM rss_feeds_links "
		      "WHERE imported <> 1 "
		      "UNION "
		      "SELECT COUNT(*), 'e' FROM rss_feeds_links "
		      "WHERE visited = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'f' FROM rss_feeds_links "
		      "WHERE visited <> 1 "
		      "UNION "
		      "SELECT COUNT(*), 'g' FROM rss_feeds_links "
		      "ORDER BY 2");

	if(query.exec())
	  while(query.next())
	    counts << query.value(0).toInt();

	QLocale locale;

	statusBar()->showMessage
	  (tr("%1 RSS Feeds | "
	      "%2 Hidden URLs | "
	      "%3 Imported URLs | "
	      "%4 Not Imported URLs | "
	      "%5 Indexed URLs | "
	      "%6 Not Indexed URLs | "
	      "%7 Total URLs").
	   arg(locale.toString(counts.value(0))).
	   arg(locale.toString(counts.value(1))).
	   arg(locale.toString(counts.value(2))).
	   arg(locale.toString(counts.value(3))).
	   arg(locale.toString(counts.value(4))).
	   arg(locale.toString(counts.value(5))).
	   arg(locale.toString(counts.value(6))));
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

void spoton_rss::slotTimeOrderBy(bool state)
{
  Q_UNUSED(state);

  QAction *action = qobject_cast<QAction *> (sender());

  if(action == m_ui.action_Insert_Date)
    {
      QSettings settings;

      settings.setValue("gui/rss_time_order", "insert_date");
      m_ui.action_Insert_Date->blockSignals(true);
      m_ui.action_Insert_Date->setChecked(true);
      m_ui.action_Insert_Date->blockSignals(false);
      m_ui.action_Publication_Date->blockSignals(true);
      m_ui.action_Publication_Date->setChecked(false);
      m_ui.action_Publication_Date->blockSignals(false);
      slotRefreshTimeline();
    }
  else if(action == m_ui.action_Publication_Date)
    {
      QSettings settings;

      settings.setValue("gui/rss_time_order", "publication_date");
      m_ui.action_Insert_Date->blockSignals(true);
      m_ui.action_Insert_Date->setChecked(false);
      m_ui.action_Insert_Date->blockSignals(false);
      m_ui.action_Publication_Date->blockSignals(true);
      m_ui.action_Publication_Date->setChecked(true);
      m_ui.action_Publication_Date->blockSignals(false);
      slotRefreshTimeline();
    }
}

void spoton_rss::slotTimelineShowOption(bool state)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(action == m_ui.action_Descriptions_in_Timeline)
    {
      QSettings settings;

      settings.setValue("gui/rss_descriptions_in_timeline", state);
      slotRefreshTimeline();
    }
  else if(action == m_ui.action_Publication_Dates_in_Timeline)
    {
      QSettings settings;

      settings.setValue("gui/rss_publication_dates_in_timeline", state);
      slotRefreshTimeline();
    }
  else if(action == m_ui.action_URL_Links_in_Timeline)
    {
      QSettings settings;

      settings.setValue("gui/rss_url_links_in_timeline", state);
      slotRefreshTimeline();
    }
}

void spoton_rss::slotToggleState(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString str("");

  if(action == m_ui.action_Toggle_Hidden)
    str = "UPDATE rss_feeds_links SET hidden = 0 WHERE hidden = 1";
  else if(action == m_ui.action_Toggle_Imported)
    str = "UPDATE rss_feeds_links SET imported = 0 WHERE imported = 1";
  else if(action == m_ui.action_Toggle_Indexed)
    str = "UPDATE rss_feeds_links SET visited = 0 WHERE visited = 1";
  else if(action == m_ui.action_Toggle_Malformed)
    str = "UPDATE rss_feeds_links SET imported = 0, "
      "visited = 0 WHERE imported = 2 OR visited = 2";
  else if(action == m_ui.action_Toggle_Not_Indexed)
    str = "UPDATE rss_feeds_links SET visited = 1 WHERE visited = 0";
  else if(action == m_ui.action_Toggle_Shown)
    str = "UPDATE rss_feeds_links SET hidden = 1 WHERE hidden = 0";

  if(str.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec(str);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  slotRefreshTimeline();
}

void spoton_rss::slotUrlClicked(const QUrl &url)
{
  if(url.scheme().toLower().trimmed().startsWith("hide-"))
    {
      hideUrl(url, true);
      return;
    }
  else if(url.scheme().toLower().trimmed().startsWith("remove-"))
    {
      spoton_crypt *crypt = spoton::instance() ?
	spoton::instance()->crypts().value("chat", 0) : 0;

      if(!crypt)
	return;

      QMessageBox mb(this);
      QUrl u(url);

      u.setScheme(u.scheme().remove(0, 7));
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to remove %1?").
		 arg(u.toEncoded().constData()));
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	return;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM rss_feeds_links WHERE url_hash = ?");
	    query.bindValue
	      (0, crypt->keyedHash(u.toEncoded(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      QApplication::restoreOverrideCursor();
      slotRefreshTimeline();
      return;
    }
  else if(url.scheme().toLower().trimmed().startsWith("visible-"))
    {
      hideUrl(url, false);
      return;
    }

  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  spoton_pageviewer *pageViewer = new spoton_pageviewer
    (QSqlDatabase(), QString(), 0);

  pageViewer->setPage(QByteArray(), QUrl("http://127.0.0.1"), 0);

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT content, url_redirected "
		      "FROM rss_feeds_links WHERE "
		      "url_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(url.toEncoded(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray content;
	      QUrl url;
	      bool ok = true;

	      content = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		{
		  QByteArray bytes
		    (crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(1).
							    toByteArray()),
						 &ok));

		  url = QUrl::fromEncoded(bytes);
		}

	      if(ok)
		{
		  content = qUncompress(content);
		  pageViewer->setPage
		    (content, url, query.value(0).toByteArray().length());
		}
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
