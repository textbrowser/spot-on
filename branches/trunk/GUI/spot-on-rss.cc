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

#include <QActionGroup>
#include <QDir>
#include <QMessageBox>
#include <QNetworkProxy>
#include <QProgressDialog>
#include <QScopedPointer>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QXmlStreamReader>
#include <QtConcurrent>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-pageviewer.h"
#include "spot-on-rss.h"
#include "spot-on-utilities.h"
#include "spot-on.h"

static char s_user_agent[] = "Spot-On";

spoton_rss::spoton_rss(spoton *parent):QMainWindow(parent)
{
  m_cancelImport = 0;
  m_currentFeedRow = -1;
  m_parent = parent;
  m_ui.setupUi(this);
  m_ui.feeds->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder); // Feed
  m_ui.feeds->setColumnHidden(m_ui.feeds->columnCount() - 1, true); // OID
  m_ui.feeds->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.feeds->setIconSize(QSize(16, 16));
  m_ui.feeds->verticalHeader()->setSectionResizeMode
    (QHeaderView::ResizeToContents);
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
  connect(&m_purgeTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotRemoveMalformed(void)));
  connect(m_ui.action_Descriptions_in_Timeline,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotTimelineShowOption(bool)));
  connect(m_ui.action_Find,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotFindInitialize(void)));
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
  connect(m_ui.action_Remove_Malformed,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotRemoveMalformed(void)));
  connect(m_ui.action_Toggle_Failed_Imports,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotToggleState(void)));
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
  connect(m_ui.clear,
	  SIGNAL(clicked(void)),
	  m_ui.timeline,
	  SLOT(clear(void)));
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
  connect(m_ui.maximum_keywords,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotMaximumKeywordsChanged(int)));
  connect(m_ui.new_feed,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.periodic_import,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotActivateImport(bool)));
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
  connect(m_ui.purge_malformed,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPurgeMalformed(bool)));
  connect(m_ui.record_notices,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotRecordNotices(bool)));
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
  connect(this,
	  SIGNAL(logError(const QString &)),
	  this,
	  SLOT(slotLogError(const QString &)));
  m_originalFindPalette = m_ui.find->palette();
  m_ui.find->setPlaceholderText(tr("Find Text"));

  auto actionGroup = new QActionGroup(this);

  actionGroup->addAction(m_ui.action_Insert_Date);
  actionGroup->addAction(m_ui.action_Publication_Date);
  actionGroup->setExclusive(true);

  auto menu = new QMenu(this);

  menu->addAction(tr("Copy All Links"),
		  this,
		  SLOT(slotCopyFeedLinks(void)));
  menu->addAction(tr("Copy Selected &Link"),
		  this,
		  SLOT(slotCopyFeedLink(void)));
  menu->addSeparator();
  menu->addAction(tr("Delete &All RSS Feeds"),
		  this,
		  SLOT(slotDeleteAllFeeds(void)));
  menu->addAction(tr("Delete &Selected RSS Feed"),
		  this,
		  SLOT(slotDeleteFeed(void)));
  menu->addSeparator();
  menu->addAction(tr("&Refresh Table"),
		  this,
		  SLOT(slotPopulateFeeds(void)));
  menu->addSeparator();
  m_scheduleAction = menu->addAction
    (tr("Schedule Selected RSS Feed For &Update (%1)").
     arg(m_ui.activate->isChecked() ? tr("Active") : tr("Not Active")),
     this,
     SLOT(slotScheduleFeedUpdate(void)));
  m_scheduleAction->setEnabled(m_ui.activate->isChecked());
  menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
  m_ui.action_menu->setMenu(menu);
  connect(m_ui.action_menu,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotShowMenu(void)));
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
  ivalue = qBound(m_ui.maximum_keywords->minimum(),
		  settings.value("gui/rss_maximum_keywords", 50).toInt(),
		  m_ui.maximum_keywords->maximum());
  m_ui.maximum_keywords->setValue(ivalue);
  index = qBound(0,
		 settings.value("gui/rss_last_tab", 0).toInt(),
		 m_ui.tab->count());
  m_ui.tab->setCurrentIndex(index);
  m_downloadContentTimer.setInterval(1500);
  dvalue = qBound
    (m_ui.download_interval->minimum(),
     settings.value("gui/rss_download_interval", 1.50).toDouble(),
     m_ui.download_interval->maximum());
  m_downloadTimer.setInterval(static_cast<int> (60000.0 * dvalue));
  m_ui.download_interval->setToolTip
    (tr("The kernel monitors this setting. [%1, %2]").
     arg(m_ui.download_interval->minimum()).
     arg(m_ui.download_interval->maximum()));
  m_ui.download_interval->setValue(dvalue);
  m_ui.maximum_keywords->setToolTip
    (tr("<html>A large value may impede the import process. "
	"Kernel monitors this setting. [%1, %2]</html>").
     arg(m_ui.maximum_keywords->minimum()).
     arg(m_ui.maximum_keywords->maximum()));
  m_ui.periodic_import->setChecked
    (settings.value("gui/rss_import_activate", false).toBool());
  m_ui.record_notices->setChecked
    (settings.value("gui/rss_record_notices", false).toBool());
  ivalue = qBound
    (m_ui.purge_days->minimum(),
     settings.value("gui/rss_purge_days", 1).toInt(),
     m_ui.purge_days->maximum());
  m_ui.purge_days->setValue(ivalue);
  m_ui.purge_malformed->setChecked
    (settings.value("gui/rss_purge_malformed", false).toBool());
  str = settings.value("gui/rss_time_order", "publication_date").toString().
    toLower().trimmed();

  if(str == "insert_date")
    m_ui.action_Insert_Date->setChecked(true);
  else
    m_ui.action_Publication_Date->setChecked(true);

  m_importTimer.setInterval(2500);
  m_purgeTimer.setInterval(2500);
  m_statisticsTimer.start(2500);

  if(m_ui.activate->isChecked())
    {
      m_downloadContentTimer.start();
      m_downloadTimer.start();
    }

  if(m_ui.periodic_import->isChecked())
    m_importTimer.start();

  if(m_ui.purge_malformed->isChecked())
    m_purgeTimer.start();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();
  QApplication::restoreOverrideCursor();
  restoreGeometry(settings.value("gui/rss_window_geometry").toByteArray());
  restoreState(settings.value("gui/rss_window_state").toByteArray());
#if defined(Q_OS_MACOS)
  foreach(auto toolButton, findChildren<QToolButton *> ())
#if (QT_VERSION < QT_VERSION_CHECK(5, 10, 0))
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 10px;}"
       "QToolButton::menu-button {border: none;}");
#else
    toolButton->setStyleSheet
      ("QToolButton {border: none; padding-right: 15px;}"
       "QToolButton::menu-button {border: none; width: 15px;}");
#endif
#endif
#ifdef Q_OS_MACOS
  spoton_utilities::enableTabDocumentMode(this);
#endif
}

spoton_rss::~spoton_rss()
{
  m_cancelImport.fetchAndStoreOrdered(1);
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
  m_purgeTimer.stop();
  m_statisticsTimer.stop();
  m_importFuture.cancel();
  m_importFuture.waitForFinished();
  m_parseXmlFuture.cancel();
  m_parseXmlFuture.waitForFinished();
}

bool spoton_rss::importUrl(const QList<QVariant> &list,
			   const int maximumKeywords)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return false;

  QScopedPointer<spoton_crypt> ucc(urlCommonCrypt());

  if(!ucc)
    return false;

  QSettings settings;
  auto imported = false;
  auto url(list.value(4).toUrl());

  if(url.isEmpty() || !url.isValid())
    url = list.value(3).toUrl();

  QString connectionName("");

  {
    connectionName = spoton_misc::databaseName();

    QSqlDatabase db;

    if(settings.value("gui/sqliteSearch", true).toBool())
      {
	db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "urls.db");
	db.open();
      }
    else
      {
	QByteArray name;
	QByteArray password;
	auto const database
	  (settings.value("gui/postgresql_database", "").
	   toString().trimmed());
	auto const host
	  (settings.value("gui/postgresql_host", "localhost").
	   toString().trimmed());
	auto const port = settings.value("gui/postgresql_port", 5432).toInt();
	auto const ssltls = settings.value("gui/postgresql_ssltls", true).
	  toBool();
	auto ok = true;
	auto options
	  (settings.value("gui/postgresql_connection_options",
			  spoton_common::POSTGRESQL_CONNECTION_OPTIONS).
	   toString().trimmed());

	if(!options.contains("connect_timeout="))
	  options.append(";connect_timeout=10");

	name = crypt->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(settings.value("gui/postgresql_name", "").
		      toByteArray()), &ok);

	if(ok)
	  password = crypt->decryptedAfterAuthenticated
	    (QByteArray::
	     fromBase64(settings.value("gui/postgresql_password", "").
			toByteArray()), &ok);

	if(ssltls)
	  options.append(";requiressl=1");

	db = QSqlDatabase::addDatabase("QPSQL", connectionName);
	db.setConnectOptions(spoton_misc::adjustPQConnectOptions(options));
	db.setDatabaseName(database);
	db.setHostName(host);
	db.setPort(port);

	if(ok)
	  db.open(name, password);
      }

    if(db.isOpen())
      {
	QString error("");

	imported = spoton_misc::importUrl
	  (list.value(0).toByteArray(),
	   list.value(1).toString().toUtf8(), // Description
	   list.value(2).toString().toUtf8(), // Title
	   spoton_misc::urlToEncoded(url),    // URL
	   db,
	   maximumKeywords,
	   settings.value("gui/disable_ui_synchronous_sqlite_url_import",
			  false).toBool(),
	   m_cancelImport,
	   error,
	   ucc.data());

	if(!error.isEmpty())
	  emit logError(error);
	else
	  emit logError
	    (QString("The URL <a href=\"%1\">%1</a> has been imported.").
	     arg(spoton_misc::urlToEncoded(url).constData()));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return imported;
}

spoton_crypt *spoton_rss::urlCommonCrypt(void) const
{
  return spoton_misc::retrieveUrlCommonCredentials
    (m_parent ? m_parent->crypts().value("chat", 0) : 0);
}

void spoton_rss::center(QWidget *parent)
{
  spoton_utilities::centerWidget(this, parent);
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
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.activate->setChecked(false);
  m_ui.periodic_import->setChecked(false);
  m_downloadContentTimer.stop();
  m_downloadTimer.stop();
  m_importTimer.stop();
  m_importFuture.cancel();
  m_importFuture.waitForFinished();
  m_parseXmlFuture.cancel();
  m_parseXmlFuture.waitForFinished();
  QApplication::restoreOverrideCursor();
}

void spoton_rss::hideUrl(const QUrl &url, const bool state)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto scheme(url.scheme());
	auto u(url);
	auto ok = true;

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
	  (1, crypt->keyedHash(spoton_misc::urlToEncoded(u), &ok).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
  slotRefreshTimeline();
}

void spoton_rss::import(const int maximumKeywords)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      emit logError("Import failure. Invalid spoton_crypt object. "
		    "This is a fatal flaw.");
      return;
    }

  QString connectionName("");

  /*
  ** Now, retrieve polarizers.
  */

  QList<QPair<QUrl, QString> > polarizers;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
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
	  (0, crypt->keyedHash(QByteArray("shared"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      if(m_importFuture.isCanceled())
		break;

	      QByteArray domain;
	      QByteArray permission;
	      auto ok = true;

	      domain = crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(0).
						       toByteArray()),
					    &ok);

	      if(ok)
		permission = crypt->
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

  if(m_importFuture.isCanceled())
    return;

  QList<QByteArray> urlHashes;
  QList<QList<QVariant> > lists;

  {
    auto db(spoton_misc::database(connectionName));

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

	      QList<QVariant> list;
	      auto const urlHash(query.value(4).toByteArray());
	      auto ok = true;
              QByteArray bytes;

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
		  /*
		  ** Apply polarizers.
		  */

		  ok = false;

		  for(int i = 0; i < polarizers.size(); i++)
		    {
		      if(m_importFuture.isCanceled())
			break;

		      auto const type(polarizers.at(i).second);
		      auto const u1(polarizers.at(i).first);
		      auto const u2(QUrl::fromEncoded(bytes));

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

		  if(m_importFuture.isCanceled())
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
		 m_importFuture.isCanceled())
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_importFuture.isCanceled())
    return;

  QList<bool> imported;

  for(int i = 0; i < lists.size() && !m_importFuture.isCanceled(); i++)
    imported << importUrl(lists.at(i), maximumKeywords);

  if(m_importFuture.isCanceled())
    return;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	for(int i = 0; i < imported.size() && !m_importFuture.isCanceled(); i++)
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
  QString title("");
  QString type("");
  QUrl imageUrl;
  QXmlStreamReader reader(data);
  auto const link(url.toString());

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
	      auto endDescription = false;

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

		      auto const attributes = reader.attributes();

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
	  auto endDescription = false;

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
  QString error("");

  spoton_misc::importUrl
    (data,
     description.toUtf8(),
     title.toUtf8(),
     spoton_misc::urlToEncoded(url),
     m_parent ? m_parent->urlDatabase() : QSqlDatabase(),
     m_ui.maximum_keywords->value(),
     settings.value("gui/disable_ui_synchronous_sqlite_url_import",
		    false).toBool(),
     m_cancelImport,
     error,
     ucc.data());

  if(!error.isEmpty())
    emit logError(error);
}

void spoton_rss::populateFeeds(void)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  disconnect(m_ui.feeds,
	     SIGNAL(itemChanged(QTableWidgetItem *)),
	     this,
	     SLOT(slotItemChanged(QTableWidgetItem *)));

  QString connectionName("");
  auto const hVal = m_ui.feeds->horizontalScrollBar()->value();
  auto const vVal = m_ui.feeds->verticalScrollBar()->value();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int row = 0;

	m_ui.feeds->setRowCount(0);
	m_ui.feeds->setSortingEnabled(false);
	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM rss_feeds"))
	  if(query.next())
	    m_ui.feeds->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT feed, " // 0
		      "feed_image, "  // 1
		      "OID "          // 2
		      "FROM rss_feeds"))
	  while(query.next())
	    {
	      QByteArray feed;
	      QByteArray image;
	      QTableWidgetItem *item = 0;
	      auto const oid
		(query.value(query.record().count() - 1).toString());
	      auto ok = true;

	      feed = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok).
		trimmed();
	      item = new QTableWidgetItem();
	      item->setFlags
		(Qt::ItemIsEditable |
		 Qt::ItemIsEnabled |
		 Qt::ItemIsSelectable);
	      m_ui.feeds->setItem(row, 0, item);

	      if(!ok)
		item->setText(tr("error"));
	      else
		{
		  item->setData(Qt::UserRole, feed);
		  item->setText(feed);
		  item->setToolTip(item->text());

		  if(feed == m_selectedFeed)
		    m_ui.feeds->setCurrentItem(item);
		}

	      if(ok)
		{
		  image = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);

		  if(ok)
		    {
		      QPixmap pixmap;

		      if(!pixmap.loadFromData(image))
			pixmap = QPixmap();

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

	if(m_selectedFeed.length() > 0)
	  {
	    m_ui.feeds->horizontalScrollBar()->setValue(hVal);
	    m_ui.feeds->verticalScrollBar()->setValue(vVal);
	  }

	m_ui.feeds->resizeColumnToContents(0);
	m_ui.feeds->setRowCount(row);
	m_ui.feeds->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  connect(m_ui.feeds,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotItemChanged(QTableWidgetItem *)));
  m_selectedFeed.clear();
}

void spoton_rss::prepareAfterAuthentication(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();

  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(crypt)
    {
      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

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
		      auto ok = true;

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
		      m_ui.proxyHostname->setCursorPosition(0);
		      m_ui.proxyPassword->setText
			(QString::fromUtf8(list.value(2).constData(),
					   list.value(2).length()));
		      m_ui.proxyPassword->setCursorPosition(0);
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

			  auto const proxies
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
		      m_ui.proxyUsername->setCursorPosition(0);
		      m_ui.proxy_frame->setVisible(true);

		      if(proxy.type() != QNetworkProxy::NoProxy)
			{
			  proxy.setHostName(m_ui.proxyHostname->text());
			  proxy.setPassword(m_ui.proxyPassword->text());
			  proxy.setPort
			    (static_cast<quint16> (m_ui.proxyPort->value()));
			  proxy.setUser(m_ui.proxyUsername->text());
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

  QApplication::restoreOverrideCursor();
}

void spoton_rss::prepareDatabases(void)
{
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto description(d.trimmed());
	auto ok = true;
	auto title(t.trimmed());

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
	    (2, crypt->keyedHash(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_rss::saveFeedImage(const QByteArray &data, const QString &link)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.prepare("UPDATE rss_feeds "
		      "SET feed_image = ? "
		      "WHERE feed_hash = ?");
	query.bindValue
	  (0, crypt->encryptedThenHashed(data, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(spoton_misc::urlToEncoded(link), &ok).
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

  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  prepareDatabases();

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto description(d.trimmed());
	auto ok = true;
	auto publicationDate(p.trimmed());
	auto title(t.trimmed());

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
	    (5,
	     crypt->encryptedThenHashed(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->keyedHash(spoton_misc::urlToEncoded(link), &ok).
	     toBase64());

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
      m_cancelImport.fetchAndStoreOrdered(0);

      if(!m_importTimer.isActive()) // Signals.
	m_importTimer.start();
    }
  else
    {
      m_cancelImport.fetchAndStoreOrdered(1);
      m_importTimer.stop();
      m_importFuture.cancel();
      m_importFuture.waitForFinished();
    }
}

void spoton_rss::slotAddFeed(void)
{
  QString connectionName("");
  QString error("");
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
  auto const list
    (m_ui.new_feed->text().trimmed().replace("\n", " ").
     split(' ', Qt::SkipEmptyParts));
#else
  auto const list
    (m_ui.new_feed->text().trimmed().replace("\n", " ").
     split(' ', QString::SkipEmptyParts));
#endif
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }
  else if(list.isEmpty())
    {
      error = tr("Please provide atleast one RSS feed.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	for(int i = 0; i < list.size(); i++)
	  {
	    auto const url(QUrl::fromUserInput(list.at(i).trimmed()));

	    if(url.isEmpty() || !url.isValid())
	      {
		if(error.isEmpty())
		  error = tr("Empty or invalid URL.");

		continue;
	      }
	    else if(!(url.scheme().toLower() == "http" ||
		      url.scheme().toLower() == "https"))
	      {
		if(error.isEmpty())
		  error = tr("URL scheme must be HTTP or HTTPS.");

		continue;
	      }

	    QSqlQuery query(db);
	    auto ok = true;

	    query.prepare("INSERT OR REPLACE INTO rss_feeds "
			  "(feed, feed_description, feed_hash, "
			  "feed_image, feed_title) "
			  "VALUES (?, ?, ?, ?, ?)");
	    query.bindValue
	      (0,
	       crypt->
	       encryptedThenHashed(spoton_misc::urlToEncoded(list.at(i)), &ok).
	       toBase64());

	    if(ok)
	      query.bindValue(1, crypt->encryptedThenHashed(QByteArray(),
							    &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->keyedHash(spoton_misc::urlToEncoded(list.at(i)),
				     &ok).toBase64());

	    if(ok)
	      query.bindValue(3, crypt->encryptedThenHashed(QByteArray(),
							    &ok).toBase64());

	    if(ok)
	      query.bindValue(4, crypt->encryptedThenHashed(QByteArray(),
							    &ok).toBase64());

	    if(ok)
	      ok = query.exec();

	    if(error.isEmpty() && !ok)
	      error = tr("Database or crypt-object error.");
	  }
      }
    else
      error = tr("Unable to access rss.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error.trimmed());
      QApplication::processEvents();
    }
  else
    {
      m_ui.new_feed->clear();
      populateFeeds();
    }
}

void spoton_rss::slotContentReplyFinished(void)
{
  auto reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      auto redirectUrl
	(reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 toUrl());

      if(!reply->attribute(QNetworkRequest::RedirectionTargetAttribute).
	 isNull())
	if(redirectUrl.isRelative())
	  redirectUrl = reply->url().resolved(redirectUrl);

      if(!redirectUrl.isEmpty())
	if(redirectUrl.isValid())
	  {
	    auto const error
	      (QString("The URL <a href=\"%1\">%1</a> is being "
		       "redirected to <a href=\"%2\">%2</a>.").
	       arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	       arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
	    auto const originalUrl(reply->property("original-url").toUrl());

	    emit logError(error);
	    reply->deleteLater();

	    QNetworkRequest request(redirectUrl);

	    request.setRawHeader("Accept", "text/html");
	    request.setRawHeader("User-Agent", s_user_agent);
	    reply = m_contentNetworkAccessManager.get(request);

	    if(!reply)
	      {
		emit logError
		  (QString("QNetworkAccessManager::get() failure on "
			   "<a href=\"%1\">%1</a>.").
		   arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
		return;
	      }

	    reply->ignoreSslErrors();
	    reply->setProperty("original-url", originalUrl);
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
	    connect(reply,
		    SIGNAL(error(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
#else
	    connect(reply,
		    SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
#endif
	    connect(reply,
		    SIGNAL(finished(void)),
		    this,
		    SLOT(slotContentReplyFinished(void)));
	    return;
	  }
    }

  if(reply)
    {
      auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

      if(!crypt)
	{
	  reply->deleteLater();
	  return;
	}

      auto const error
	(QString("The content of URL <a href=\"%1\">%1</a> has "
		 "been downloaded.").
	 arg(spoton_misc::urlToEncoded(reply->url()).constData()));

      emit logError(error);

      QString connectionName("");
      auto const data(reply->readAll());

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    auto ok = true;

	    query.prepare("UPDATE rss_feeds_links "
			  "SET content = ?, url_redirected = ?, visited = ? "
			  "WHERE url_hash = ?");
	    query.bindValue
	      (0, crypt->
	       encryptedThenHashed(qCompress(data, 9), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->
		 encryptedThenHashed(spoton_misc::
				     urlToEncoded(reply->url()),
				     &ok).toBase64());

	    if(data.isEmpty() || reply->error() != QNetworkReply::NoError)
	      {
		query.bindValue(2, 2); // Error.

		if(data.isEmpty())
		  {
		    auto const error
		      (QString("The URL <a href=\"%1\">%1</a> "
			       "does not have data.").
		       arg(spoton_misc::urlToEncoded(reply->url()).
			   constData()));

		    emit logError(error);
		  }
		else
		  {
		    auto const error
		      (QString("The URL <a href=\"%1\">%1</a> "
			       "cannot be indexed "
			       "(%2).").
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
		(3, crypt->
		 keyedHash(spoton_misc::urlToEncoded(reply->
						     property("original-url").
						     toUrl()),
			   &ok).toBase64());

	    if(ok)
	      ok = query.exec();

	    if(!ok)
	      {
		auto const error
		  (QString("The content of URL <a href=\"%1\">%1</a> was "
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

void spoton_rss::slotCopyFeedLink(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  auto item = m_ui.feeds->item(m_ui.feeds->currentRow(), 0);

  if(!item)
    return;

  clipboard->setText(item->text());
}

void spoton_rss::slotCopyFeedLinks(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString str("");

  for(int i = 0; i < m_ui.feeds->rowCount(); i++)
    {
      auto item = m_ui.feeds->item(i, 0);

      if(item)
	str.append(item->text() + "\n");
    }

  clipboard->setText(str.trimmed());
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotDeleteAllFeeds(void)
{
  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText
    (tr("Are you sure that you wish to delete all of the RSS feeds?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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
  if(qobject_cast<QAction *> (sender()))
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText
	(tr("Are you sure that you wish to delete the selected RSS feed?"));
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

  QString oid("");
  QTableWidgetItem *item = 0;
  auto const row = m_ui.feeds->currentRow();

  if((item = m_ui.feeds->item(row, m_ui.feeds->columnCount() - 1)))
    oid = item->text();
  else
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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
  if(!findChildren<QProgressDialog *> ().isEmpty())
    return;
  else if(!m_contentNetworkAccessManager.
	  findChildren<QNetworkReply *> ().isEmpty())
    return;

  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  QUrl url;

  {
    auto db(spoton_misc::database(connectionName));

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
	      auto ok = true;

	      bytes = crypt->decryptedAfterAuthenticated
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
  QApplication::restoreOverrideCursor();

  if(!url.isEmpty() && url.isValid())
    {
      auto const error
	(QString("Fetching the URL <a href=\"%1\">%1</a>.").
	 arg(spoton_misc::urlToEncoded(url).constData()));

      emit logError(error);

      QNetworkRequest request(url);

      request.setRawHeader("Accept", "text/html");
      request.setRawHeader("User-Agent", s_user_agent);

      auto reply = m_contentNetworkAccessManager.get(request);

      if(!reply)
	{
	  emit logError
	    (QString("QNetworkAccessManager::get() failure on "
		     "<a href=\"%1\">%1</a>.").
	     arg(spoton_misc::urlToEncoded(url).constData()));
	  return;
	}

      reply->ignoreSslErrors();
      reply->setProperty("original-url", url);
      reply->setReadBufferSize(0);
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(reply,
	      SIGNAL(error(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
#else
      connect(reply,
	      SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
#endif
      connect(reply,
	      SIGNAL(finished(void)),
	      this,
	      SLOT(slotContentReplyFinished(void)));
    }
}

void spoton_rss::slotDownloadFeedImage(const QUrl &imageUrl, const QUrl &url)
{
  if(!imageUrl.isEmpty() && imageUrl.isValid() &&
     !url.isEmpty() && url.isValid())
    {
      QNetworkRequest request(imageUrl);

      request.setRawHeader("Accept", "text/html");
      request.setRawHeader("User-Agent", s_user_agent);

      auto reply = m_feedNetworkAccessManager.get(request);

      if(!reply)
	{
	  emit logError
	    (QString("QNetworkAccessManager::get() failure on "
		     "<a href=\"%1\">%1</a>.").
	     arg(spoton_misc::urlToEncoded(imageUrl).constData()));
	  return;
	}

      reply->ignoreSslErrors();
      reply->setProperty("url", url);
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(reply,
	      SIGNAL(error(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
#else
      connect(reply,
	      SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
	      this,
	      SLOT(slotReplyError(QNetworkReply::NetworkError)));
#endif
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
  m_downloadTimer.setInterval(static_cast<int> (60000.0 * value));
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

  auto item = m_ui.feeds->item(m_currentFeedRow, 0);

  if(!item)
    {
      m_currentFeedRow = 0;
      return;
    }

  QNetworkRequest request(item->text());

  request.setRawHeader("Accept", "text/html");
  request.setRawHeader("User-Agent", s_user_agent);

  auto reply = m_feedNetworkAccessManager.get(request);

  if(!reply)
    {
      emit logError
	(QString("QNetworkAccessManager::get() failure on "
		 "<a href=\"%1\">%1</a>.").
	 arg(spoton_misc::urlToEncoded(QUrl::fromUserInput(item->text())).
	     constData()));
      return;
    }

  reply->ignoreSslErrors();
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
  connect(reply,
	  SIGNAL(error(QNetworkReply::NetworkError)),
	  this,
	  SLOT(slotReplyError(QNetworkReply::NetworkError)));
#else
  connect(reply,
	  SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
	  this,
	  SLOT(slotReplyError(QNetworkReply::NetworkError)));
#endif
  connect(reply,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotFeedReplyFinished(void)));
  connect(reply,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotFeedReplyReadyRead(void)));
  emit logError(QString("Downloading the feed <a href=\"%1\">%1</a>.").
		arg(spoton_misc::urlToEncoded(reply->url()).constData()));
}

void spoton_rss::slotFeedImageReplyFinished(void)
{
  auto reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      QPixmap pixmap;
      auto const data(reply->readAll());
      auto const url(reply->property("url").toUrl());

      if(!pixmap.loadFromData(data))
	pixmap = QPixmap();

      reply->deleteLater();

      auto const list(m_ui.feeds->findItems(url.toString(), Qt::MatchExactly));

      if(!list.isEmpty())
	{
	  if(!pixmap.isNull())
	    list.at(0)->setIcon(pixmap);
	  else
	    list.at(0)->setIcon(QIcon(":/generic/rss.png"));
	}

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      saveFeedImage(data, url.toString());
      QApplication::restoreOverrideCursor();
    }
  else if(reply)
    reply->deleteLater();
}

void spoton_rss::slotFeedReplyFinished(void)
{
  QUrl url;
  auto reply = qobject_cast<QNetworkReply *> (sender());

  if(reply && reply->error() == QNetworkReply::NoError)
    {
      url = reply->url();

      auto redirectUrl
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
	    auto const error
	      (QString("The feed URL <a href=\"%1\">%1</a> "
		       "is being redirected to <a href=\"%2\">%2</a>.").
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
		  (QString("QNetworkAccessManager::get() failure on "
			   "<a href=\"%1\">%1</a>.").
		   arg(spoton_misc::urlToEncoded(redirectUrl).constData()));
		return;
	      }

	    reply->ignoreSslErrors();
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
	    connect(reply,
		    SIGNAL(error(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
#else
	    connect(reply,
		    SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
		    this,
		    SLOT(slotReplyError(QNetworkReply::NetworkError)));
#endif
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
      auto const error
	(QString("The URL <a href=\"%1\">%1</a> "
		 "could not be accessed correctly (%2).").
	 arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	 arg(reply->errorString()));

      emit logError(error);
      reply->deleteLater();
    }

  if(!m_feedDownloadContent.isEmpty())
    if(!url.isEmpty() && url.isValid())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
      m_parseXmlFuture = QtConcurrent::run
	(&spoton_rss::parseXmlContent, this, m_feedDownloadContent, url);
#else
      m_parseXmlFuture = QtConcurrent::run
	(this, &spoton_rss::parseXmlContent, m_feedDownloadContent, url);
#endif

  m_feedDownloadContent.clear();
}

void spoton_rss::slotFeedReplyReadyRead(void)
{
  auto reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    m_feedDownloadContent.append(reply->readAll());
}

void spoton_rss::slotFind(void)
{
  if(m_ui.find->text().isEmpty())
    m_ui.find->setPalette(m_originalFindPalette);
  else if(!m_ui.timeline->find(m_ui.find->text()))
    {
      QColor const color(240, 128, 128); // Light Coral
      auto palette(m_ui.find->palette());

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
  m_ui.tab->setCurrentIndex(1);
}

void spoton_rss::slotImport(void)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  if(m_importFuture.isFinished())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    m_importFuture = QtConcurrent::run
      (&spoton_rss::import, this, m_ui.maximum_keywords->value());
#else
    m_importFuture = QtConcurrent::run
      (this, &spoton_rss::import, m_ui.maximum_keywords->value());
#endif
}

void spoton_rss::slotItemChanged(QTableWidgetItem *item)
{
  if(!item || item->text().trimmed().isEmpty())
    {
      m_ui.feeds->blockSignals(true);
      item->setText(item->data(Qt::UserRole).toString().trimmed());
      item->setToolTip(item->text());
      m_ui.feeds->blockSignals(false);
      return;
    }

  auto const before(m_ui.new_feed->text().trimmed());

  m_selectedFeed = item->text().trimmed();
  m_ui.new_feed->setText(item->text().trimmed());
  slotDeleteFeed();
  slotAddFeed();
  m_ui.new_feed->setText(before);
}

void spoton_rss::slotLogError(const QString &error)
{
  if(error.trimmed().isEmpty() || m_ui.record_notices->isChecked() == false)
    return;

  m_ui.errors->append(QDateTime::currentDateTime().toString(Qt::ISODate));
  m_ui.errors->append(error.trimmed().append("<br>"));
  spoton_misc::logError(error);
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

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to purge obsolete links?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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
	query.bindValue(1, 24 * 60 * 60 * m_ui.purge_days->value());
	query.exec();
	query.exec("VACUUM");
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

void spoton_rss::slotPurgeMalformed(bool state)
{
  QSettings settings;

  settings.setValue("gui/rss_purge_malformed", state);

  if(state)
    {
      if(!m_purgeTimer.isActive())
	m_purgeTimer.start();
    }
  else
    m_purgeTimer.stop();
}

void spoton_rss::slotRecordNotices(bool state)
{
  QSettings settings;

  settings.setValue("gui/rss_record_notices", state);
}

void spoton_rss::slotRefreshTimeline(void)
{
  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QProgressDialog progress(this);

  progress.setLabelText(tr("Populating..."));
  progress.setMaximum(0);
  progress.setMinimum(0);
  progress.setModal(true);
  progress.setWindowTitle(tr("%1: Populating").arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.raise();
  progress.activateWindow();
  progress.repaint();
  QApplication::processEvents();
  m_ui.timeline->clear();

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString str1("");
	QString str2("");
	auto const index = m_ui.timeline_filter->currentIndex();
	int i = 0;

	query.setForwardOnly(true);
	str2 = "SELECT content, " // 0
	  "description, "         // 1
	  "hidden, "              // 2
	  "publication_date, "    // 3
	  "title, "               // 4
	  "url, "                 // 5
	  "url_redirected "       // 6
	  "FROM rss_feeds_links ";

	if(index == 1) // Failed Imports
	  str1.append(" WHERE imported = 2 ");
	else if(index == 2) // Hidden
	  str1.append(" WHERE hidden = 1 ");
	else if(index == 3) // Imported
	  str1.append(" WHERE imported = 1 ");
	else if(index == 4) // Indexed
	  str1.append(" WHERE visited = 1 ");
	else if(index == 5) // Malformed
	  str1.append(" WHERE visited = 2 ");
	else if(index == 6) // Not Imported
	  str1.append(" WHERE imported <> 1 AND imported <> 2 ");
	else if(index == 7) // Not Indexed
	  str1.append(" WHERE visited <> 1 ");
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

	      progress.repaint();
	      QApplication::processEvents();

	      QByteArray bytes;
	      QList<QVariant> list;
	      auto contentAvailable = false;
	      auto ok = true;

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
		  auto url(list.value(3).toUrl());

		  if(url.isEmpty() || !url.isValid())
		    url = list.value(2).toUrl();

		  if(contentAvailable)
		    {
		      html.append("<a href=\"");
		      html.append(spoton_misc::urlToEncoded(list.value(2).
							    toUrl()));
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
		      html.append(spoton_misc::urlToEncoded(list.value(2).
							    toUrl()));
		      html.append("\">");
		      html.append("Hide URL");
		      html.append("</a>");
		      html.append(" | ");
		      html.append("<a href=\"remove-");
		      html.append(spoton_misc::urlToEncoded(list.value(2).
							    toUrl()));
		      html.append("\">");
		      html.append("Remove URL");
		      html.append("</a>");
		    }
		  else
		    {
		      html.append(" | ");
		      html.append("<a href=\"remove-");
		      html.append(spoton_misc::urlToEncoded(list.value(2).
							    toUrl()));
		      html.append("\">");
		      html.append("Remove URL");
		      html.append("</a>");
		      html.append(" | ");
		      html.append("<a href=\"visible-");
		      html.append(spoton_misc::urlToEncoded(list.value(2).
							    toUrl()));
		      html.append("\">");
		      html.append("Show URL");
		      html.append("</a>");
		    }

		  html.append("<br>");

		  if(m_ui.action_URL_Links_in_Timeline->isChecked())
		    {
		      html.append
			(QString("<font color=\"green\" size=3>%1</font>").
			 arg(spoton_misc::urlToEncoded(url).constData()));
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

		  auto cursor = m_ui.timeline->textCursor();

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

void spoton_rss::slotRemoveMalformed(void)
{
  if(qobject_cast<QAction *> (sender()))
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText
	(tr("Are you sure that you wish to remove all malformed links?"));
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

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM rss_feeds_links WHERE visited = 2");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(qobject_cast<QAction *> (sender()))
    slotRefreshTimeline();
}

void spoton_rss::slotReplyError(QNetworkReply::NetworkError code)
{
  QString error("");
  auto reply = qobject_cast<QNetworkReply *> (sender());

  if(reply)
    {
      error = QString("The URL <a href=\"%1\">%1</a> "
		      "generated an error (%2).").
	arg(spoton_misc::urlToEncoded(reply->url()).constData()).
	arg(reply->errorString());
      reply->deleteLater();
    }
  else
    error = QString("A QNetworkReply error (%1) occurred.").arg(code);

  emit logError(error);
}

void spoton_rss::slotSaveProxy(void)
{
  QNetworkProxy proxy;

  proxy.setType(QNetworkProxy::NoProxy);
  m_contentNetworkAccessManager.setProxy(proxy);
  m_feedNetworkAccessManager.setProxy(proxy);
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  prepareDatabases();

  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(crypt)
    {
      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    QString enabled("false");
	    QString type("");
	    auto hostname(m_ui.proxyHostname->text().trimmed());
	    auto ok = true;
	    auto password(m_ui.proxyPassword->text());
	    auto port(QString::number(m_ui.proxyPort->value()));
	    auto username(m_ui.proxyUsername->text());

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

		    auto const proxies
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
		    proxy.setHostName(m_ui.proxyHostname->text());
		    proxy.setPassword(m_ui.proxyPassword->text());
		    proxy.setPort
		      (static_cast<quint16> (m_ui.proxyPort->value()));
		    proxy.setUser(m_ui.proxyUsername->text());
		  }

		m_contentNetworkAccessManager.setProxy(proxy);
		m_feedNetworkAccessManager.setProxy(proxy);
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

  auto item = m_ui.feeds->item(m_currentFeedRow + 1, 0);

  if(item)
    emit logError
      (QString("The feed <a href=\"%1\">%1</a> has been scheduled "
	       "for an update.").arg(item->text()));
}

void spoton_rss::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  menu.addAction(tr("Copy All Links"),
		 this,
		 SLOT(slotCopyFeedLinks(void)));
  menu.addAction(tr("Copy Selected &Link"),
		 this,
		 SLOT(slotCopyFeedLink(void)));
  menu.addSeparator();
  menu.addAction(tr("Delete &All Feeds"),
		 this,
		 SLOT(slotDeleteAllFeeds(void)));
  menu.addAction(tr("Delete &Selected Feed"),
		 this,
		 SLOT(slotDeleteFeed(void)));
  menu.addSeparator();
  menu.addAction(tr("&Refresh Table"),
		 this,
		 SLOT(slotPopulateFeeds(void)));
  menu.addSeparator();
  menu.addAction
    (tr("Schedule Selected RSS Feed For &Update (%1)").
     arg(m_ui.activate->isChecked() ? tr("Active") : tr("Not Active")),
     this,
     SLOT(slotScheduleFeedUpdate(void)))->setEnabled
    (m_ui.activate->isChecked());
  menu.exec(m_ui.feeds->mapToGlobal(point));
}

void spoton_rss::slotShowMenu(void)
{
  if(m_scheduleAction)
    {
      m_scheduleAction->setEnabled(m_ui.activate->isChecked());
      m_scheduleAction->setText
	(tr("Schedule Selected RSS Feed For &Update (%1)").
	 arg(m_ui.activate->isChecked() ? tr("Active") : tr("Not Active")));
    }

  m_ui.action_menu->showMenu();
}

void spoton_rss::slotStatisticsTimeout(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QString str("");
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QList<qint64> counts;
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*), 'a' FROM rss_feeds "
		      "UNION "
		      "SELECT COUNT(*), 'b' FROM rss_feeds_links "
		      "WHERE imported = 2 "
		      "UNION "
		      "SELECT COUNT(*), 'c' FROM rss_feeds_links "
		      "WHERE hidden = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'd' FROM rss_feeds_links "
		      "WHERE imported = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'e' FROM rss_feeds_links "
		      "WHERE imported = 0 "
		      "UNION "
		      "SELECT COUNT(*), 'f' FROM rss_feeds_links "
		      "WHERE visited = 1 "
		      "UNION "
		      "SELECT COUNT(*), 'g' FROM rss_feeds_links "
		      "WHERE visited <> 1 "
		      "UNION "
		      "SELECT COUNT(*), 'h' FROM rss_feeds_links "
		      "WHERE visited = 2 "
		      "UNION "
		      "SELECT COUNT(*), 'i' FROM rss_feeds_links "
		      "ORDER BY 2");

	if(query.exec())
	  while(query.next())
	    counts << query.value(0).toLongLong();

	QLocale locale;

	str = tr("%1 RSS Feeds | "         // a
		 "%2 Failed Imports | "    // b
		 "%3 Hidden URLs | "       // c
		 "%4 Imported URLs | "     // d
		 "%5 Not Imported URLs | " // e
		 "%6 Indexed URLs | "      // f
		 "%7 Not Indexed URLs | "  // g
		 "%8 Malformed | "         // h
		 "%9 Total URLs").         // i
	  arg(locale.toString(counts.value(0))).
	  arg(locale.toString(counts.value(1))).
	  arg(locale.toString(counts.value(2))).
	  arg(locale.toString(counts.value(3))).
	  arg(locale.toString(counts.value(4))).
	  arg(locale.toString(counts.value(5))).
	  arg(locale.toString(counts.value(6))).
	  arg(locale.toString(counts.value(7))).
	  arg(locale.toString(counts.value(8)));
      }
    else
      str = tr("0 RSS Feeds | "
	       "0 Failed Imports | "
	       "0 Hidden URLs | "
	       "0 Imported URLs | "
	       "0 Not Imported URLs | "
	       "0 Indexed URLs | "
	       "0 Not Indexed URLs | "
	       "0 Malformed | "
	       "0 Total URLs");

    db.close();

    QFontMetrics const fm(statusBar()->fontMetrics());

    statusBar()->setToolTip
      ("<html>" + QString(str).replace(" | ", "<br>") + "</html>");
    statusBar()->showMessage
      (fm.elidedText(str.trimmed(), Qt::ElideRight, statusBar()->width() - 25));
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
  if(!state)
    return;

  auto action = qobject_cast<QAction *> (sender());

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
  auto action = qobject_cast<QAction *> (sender());

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
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString str("");

  if(action == m_ui.action_Toggle_Failed_Imports)
    str = "UPDATE rss_feeds_links SET imported = 0 WHERE imported = 2";
  else if(action == m_ui.action_Toggle_Hidden)
    str = "UPDATE rss_feeds_links SET hidden = 0 WHERE hidden = 1";
  else if(action == m_ui.action_Toggle_Imported)
    str = "UPDATE rss_feeds_links SET imported = 0 WHERE imported = 1";
  else if(action == m_ui.action_Toggle_Indexed)
    str = "UPDATE rss_feeds_links SET visited = 0 WHERE visited = 1";
  else if(action == m_ui.action_Toggle_Malformed)
    str = "UPDATE rss_feeds_links SET visited = 0 WHERE visited = 2";
  else if(action == m_ui.action_Toggle_Not_Indexed)
    str = "UPDATE rss_feeds_links SET visited = 1 WHERE visited = 0";
  else if(action == m_ui.action_Toggle_Shown)
    str = "UPDATE rss_feeds_links SET hidden = 1 WHERE hidden = 0";

  if(str.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

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
      auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

      if(!crypt)
	return;

      QMessageBox mb(this);
      auto u(url);

      u.setScheme(u.scheme().remove(0, 7));
      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to remove %1?").
		 arg(spoton_misc::urlToEncoded(u).constData()));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "rss.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    auto ok = true;

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM rss_feeds_links WHERE url_hash = ?");
	    query.bindValue
	      (0, crypt->keyedHash(spoton_misc::urlToEncoded(u),
				   &ok).toBase64());

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

  auto crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  auto pageViewer = new spoton_pageviewer(0, "", m_parent);

  pageViewer->setPage(QByteArray(), QUrl("http://127.0.0.1"), 0);

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() + "rss.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT content, " // 0
		      "url_redirected "  // 1
		      "FROM rss_feeds_links WHERE "
		      "url_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(spoton_misc::urlToEncoded(url),
			       &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    {
	      QByteArray content;
	      QUrl url;
	      auto ok = true;

	      content = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		{
		  auto const bytes
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
  spoton_utilities::centerWidget(pageViewer, this);
  pageViewer->showNormal();
  pageViewer->activateWindow();
  pageViewer->raise();
  QApplication::restoreOverrideCursor();
}
