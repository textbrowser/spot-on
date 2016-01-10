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
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on.h"
#include "spot-on-rss.h"

spoton_rss::spoton_rss(QWidget *parent):QMainWindow(parent)
{
  m_ui.setupUi(this);
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.feeds->setColumnHidden(2, true); // OID
  m_ui.feeds->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.feeds->horizontalHeader()->setSortIndicator
    (1, Qt::AscendingOrder); // Feed
  prepareDatabases();

  QSettings settings;
  bool state = false;
  double value = 1.50;

  state = settings.value("gui/rss_download_activate", false).toBool();
  value = qBound(m_ui.download_interval->minimum(),
		 settings.value("gui/rss_download_interval").toDouble(),
		 m_ui.download_interval->maximum());
  m_downloadTimer.setInterval(static_cast<int> (60 * 1000 * value));

  if(state)
    m_downloadTimer.start();

  QApplication::restoreOverrideCursor();
  connect(m_ui.action_Save_Settings,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotSaveSettings(void)));
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
  connect(m_ui.new_feed,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddFeed(void)));
  connect(m_ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));

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
}

spoton_rss::~spoton_rss()
{
  m_downloadTimer.stop();
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

	if(query.exec("SELECT echo, feed, OID FROM rss_feeds"))
	  while(query.next())
	    {
	      QByteArray echo;
	      QByteArray feed;
	      QString oid(query.value(2).toString());
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
		   "feed_hash TEXT NOT NULL PRIMARY KEY)");
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
  QSettings settings;
  double value = 1.50;
  int index = qBound(0,
		     settings.value("gui/rss_last_tab", 0).toInt(),
		     m_ui.tab->count());

  m_ui.activate->setChecked(settings.value("gui/rss_download_activate",
					   false).toBool());

#if 0
  if(m_ui.activate->isChecked())
    m_ui.activate->setStyleSheet
      ("QPushButton {background-color: #4d4dff;}");
  else
    m_ui.activate->setStyleSheet
      ("QPushButton {background-color: #fd5f00;}");
#endif

  value = qBound(m_ui.download_interval->minimum(),
		 settings.value("gui/rss_download_interval").toDouble(),
		 m_ui.download_interval->maximum());
  m_ui.download_interval->setValue(value);
  m_ui.scroll_automatically->setChecked
    (settings.value("gui/rss_scroll_automatically", true).toBool());
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
		      m_ui.proxyPort->setValue(1);
		      m_ui.proxyType->setCurrentIndex(0);
		      m_ui.proxyUsername->clear();
		    }
		  else
		    {
		      m_ui.proxy->setChecked(true);
		      m_ui.proxyHostname->setText
			(QString::fromUtf8(list.value(1).constData()));
		      m_ui.proxyPassword->setText
			(QString::fromUtf8(list.value(2).constData()));
		      m_ui.proxyPort->setValue
			(list.value(3).toInt());

		      if(list.value(4) == "HTTP")
			m_ui.proxyType->setCurrentIndex(0);
		      else if(list.value(4) == "Socks5")
			m_ui.proxyType->setCurrentIndex(1);
		      else if(list.value(4) == "System")
			m_ui.proxyType->setCurrentIndex(2);
		      else
			m_ui.proxyType->setCurrentIndex(0);

		      m_ui.proxyUsername->setText
			(QString::fromUtf8(list.value(5).constData()));
		    }
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
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
  if(state)
    {
      if(!m_downloadTimer.isActive()) // Signals.
	m_downloadTimer.start();

#if 0
      m_ui.activate->setStyleSheet
	("QPushButton {background-color: #4d4dff;}");
#endif
    }
  else
    {
      m_downloadTimer.stop();
#if 0
      m_ui.activate->setStyleSheet
	("QPushButton {background-color: #fd5f00;}");
#endif
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
      error = tr("Please provide a feed.");
      goto done_label;
    }
  else if(!(url.scheme().toLower() == "http" ||
	    url.scheme().toLower() == "https"))
    {
      error = tr("Invalid feed scheme; HTTP or HTTPS.");
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
		      "(echo, feed, feed_hash) VALUES (?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray("false"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->encryptedThenHashed(new_feed.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(new_feed.toUtf8(), &ok).toBase64());

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
      m_ui.new_feed->selectAll();
      populateFeeds();
    }
}

void spoton_rss::slotDeleteAllFeeds(void)
{
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

void spoton_rss::slotDownloadIntervalChanged(double value)
{
  m_downloadTimer.setInterval(static_cast<int> (60 * 1000 * value));
}

void spoton_rss::slotPopulateFeeds(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  populateFeeds();
  QApplication::restoreOverrideCursor();
}

void spoton_rss::slotSaveSettings(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QSettings settings;

  settings.setValue("gui/rss_download_activate",
		    m_ui.activate->isChecked());
  settings.setValue("gui/rss_download_interval",
		    m_ui.download_interval->value());
  settings.setValue("gui/rss_scroll_automatically",
		    m_ui.scroll_automatically->isChecked());
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
		hostname.clear();
		password.clear();
		port.clear();
		type.clear();
		username.clear();
	      }
	    else
	      {
		enabled = "true";

		if(m_ui.proxyType->currentIndex() == 0)
		  type = "HTTP";
		else if(m_ui.proxyType->currentIndex() == 1)
		  type = "Socks5";
		else
		  type = "System";
	      }

	    query.prepare("INSERT OR REPLACE INTO rss_proxy ("
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

void spoton_rss::slotTabChanged(int index)
{
  QSettings settings;

  settings.setValue("gui/rss_last_tab", index);
}
