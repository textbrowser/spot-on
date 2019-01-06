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

#include <QApplication>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include <limits>

#include "Common/spot-on-crypt.h"
#include "spot-on.h"
#include "spot-on-documentation.h"
#if SPOTON_GOLDBUG == 0
#include "spot-on-emailwindow.h"
#endif
#include "spot-on-utilities.h"
#include "ui_spot-on-socket-options.h"

void spoton::slotSetSocketOptions(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString());

  if(!(type == "listeners" || type == "neighbors"))
    return;

  QString oid("");
  QString socketOptions("");
  QString transport("");
  int row = -1;

  if(type == "listeners")
    {
      if((row = m_ui.listeners->currentRow()) >= 0)
	{
	  QTableWidgetItem *item = m_ui.listeners->item
	    (row, m_ui.listeners->columnCount() - 1); // OID

	  if(item)
	    oid = item->text();

	  item = m_ui.listeners->item(row, 24); // Socket Options

	  if(item)
	    socketOptions = item->text();

	  item = m_ui.listeners->item(row, 15); // Transport

	  if(item)
	    transport = item->text().toUpper();
	}
    }
  else
    {
      if((row = m_ui.neighbors->currentRow()) >= 0)
	{
	  QTableWidgetItem *item = m_ui.neighbors->item
	    (row, m_ui.neighbors->columnCount() - 1); // OID

	  if(item)
	    oid = item->text();

	  item = m_ui.neighbors->item(row, 41); // Socket Options

	  if(item)
	    socketOptions = item->text();

	  item = m_ui.neighbors->item(row, 27); // Transport

	  if(item)
	    transport = item->text().toUpper();
	}
    }

  if(row < 0)
    return;

  QDialog dialog(this);
  QStringList list(socketOptions.split(";", QString::SkipEmptyParts));
  Ui_spoton_socket_options ui;

  ui.setupUi(&dialog);
  ui.nodelay->setEnabled(transport != "BLUETOOTH" && transport != "UDP");
#ifndef SPOTON_SCTP_ENABLED
  ui.nodelay->setEnabled(!(transport == "SCTP"));
#endif

  if(!ui.nodelay->isEnabled())
    ui.nodelay->setToolTip(tr("SCTP, if available, and TCP only."));

  ui.so_keepalive->setEnabled(transport != "BLUETOOTH" && transport != "UDP");
#ifndef SPOTON_SCTP_ENABLED
  ui.so_keepalive->setEnabled(!(transport == "SCTP"));
#endif

  if(!ui.so_keepalive->isEnabled())
    ui.so_keepalive->setToolTip(tr("SCTP, if available, and TCP only."));

  ui.so_linger->setEnabled(transport != "BLUETOOTH" && transport != "UDP");
#ifndef SPOTON_SCTP_ENABLED
  ui.so_linger->setEnabled(!(transport == "SCTP"));
#endif

  if(!ui.so_linger->isEnabled())
    ui.so_linger->setToolTip(tr("SCTP, if available, and TCP only."));

  ui.so_rcvbuf->setMaximum(std::numeric_limits<int>::max());
  ui.so_sndbuf->setMaximum(std::numeric_limits<int>::max());

#if defined(SO_TIMESTAMPING)
  ui.so_timestamping->setEnabled(transport != "BLUETOOTH");

  if(!ui.so_timestamping->isEnabled())
    ui.so_timestamping->setToolTip
      (tr("TCP, SCTP, if available, and UDP only."));
#else
  ui.so_timestamping->setEnabled(false);
  ui.so_timestamping->setToolTip(tr("SO_TIMESTAMPING is not defined."));
#endif

  if(type == "listeners")
    {
      dialog.setWindowTitle
	(tr("%1: Listener Socket Options").arg(SPOTON_APPLICATION_NAME));
      ui.information->setText
	(tr("SCTP socket options will be applied to a listener's socket "
	    "after the socket is created. SCTP peers will also "
	    "inherit some options. "
	    "TCP and UDP socket options will be applied to "
	    "peer sockets after connections are established."));
    }
  else
    {
      dialog.setWindowTitle
	(tr("%1: Neighbor Socket Options").arg(SPOTON_APPLICATION_NAME));
      ui.information->setText
	(tr("SCTP socket options will be applied to a socket "
	    "after the socket is created and after the socket is connected. "
	    "TCP and UDP socket options will be applied after "
	    "connections are established."));
    }

  if(type == "listeners")
    {
      if(transport != "BLUETOOTH")
	{
	  ui.so_rcvbuf->setEnabled(true);
	  ui.so_sndbuf->setEnabled(true);
	}
      else
	{
	  ui.so_rcvbuf->setEnabled(false);
	  ui.so_rcvbuf->setToolTip(tr("SCTP, TCP, UDP listeners only."));
	  ui.so_sndbuf->setEnabled(false);
	  ui.so_sndbuf->setToolTip(tr("SCTP, TCP, UDP listeners only."));
	}
    }
  else
    {
#if QT_VERSION >= 0x050501
      if(transport == "BLUETOOTH")
	{
	  ui.so_rcvbuf->setEnabled(false);
	  ui.so_rcvbuf->setToolTip(tr("SCTP, TCP, UDP neighbors only."));
	  ui.so_sndbuf->setEnabled(false);
	  ui.so_sndbuf->setToolTip(tr("SCTP, TCP, UDP neighbors only."));
	}
#else
      ui.so_rcvbuf->setEnabled(false);
      ui.so_rcvbuf->setToolTip(tr("Qt version 5.5.1 or newer is required."));
      ui.so_sndbuf->setEnabled(false);
      ui.so_sndbuf->setToolTip(tr("Qt version 5.5.1 or newer is required."));
#endif
    }

#ifndef SPOTON_SCTP_ENABLED
  ui.so_rcvbuf->setEnabled(false);
  ui.so_rcvbuf->setToolTip(tr("SCTP is not available."));
  ui.so_sndbuf->setEnabled(false);
  ui.so_sndbuf->setToolTip(tr("SCTP is not available."));
#endif

  foreach(QString string, list)
    if(string.startsWith("nodelay="))
      {
	if(ui.nodelay->isEnabled())
	  ui.nodelay->setChecked
	    (string.mid(static_cast<int> (qstrlen("nodelay="))).toInt());
      }
    else if(string.startsWith("so_keepalive="))
      {
	if(ui.so_keepalive->isEnabled())
	  ui.so_keepalive->setChecked
	    (string.mid(static_cast<int> (qstrlen("so_keepalive="))).toInt());
      }
    else if(string.startsWith("so_linger="))
      {
	if(ui.so_linger->isEnabled())
	  ui.so_linger->setValue
	    (string.mid(static_cast<int> (qstrlen("so_linger="))).toInt());
      }
    else if(string.startsWith("so_rcvbuf="))
      {
	if(ui.so_rcvbuf->isEnabled())
	  ui.so_rcvbuf->setValue
	    (string.mid(static_cast<int> (qstrlen("so_rcvbuf="))).toInt());
      }
    else if(string.startsWith("so_sndbuf="))
      {
	if(ui.so_sndbuf->isEnabled())
	  ui.so_sndbuf->setValue
	    (string.mid(static_cast<int> (qstrlen("so_sndbuf="))).toInt());
      }
    else if(string.startsWith("so_timestamping="))
      {
	if(ui.so_timestamping->isEnabled())
	  ui.so_timestamping->setChecked
	    (string.
	     mid(static_cast<int> (qstrlen("so_timestamping="))).toInt());
      }

  if(dialog.exec() != QDialog::Accepted)
    return;

  socketOptions.clear();

  if(ui.nodelay->isEnabled())
    {
      socketOptions.append(QString("nodelay=%1").arg(ui.nodelay->isChecked()));
      socketOptions.append(";");
    }

  if(ui.so_keepalive->isEnabled())
    {
      socketOptions.append
	(QString("so_keepalive=%1").arg(ui.so_keepalive->isChecked()));
      socketOptions.append(";");
    }

  if(ui.so_linger->isEnabled())
    {
      socketOptions.append(QString("so_linger=%1").arg(ui.so_linger->value()));
      socketOptions.append(";");
    }

  if(ui.so_rcvbuf->isEnabled())
    {
      socketOptions.append(QString("so_rcvbuf=%1").arg(ui.so_rcvbuf->value()));
      socketOptions.append(";");
    }

  if(ui.so_sndbuf->isEnabled())
    {
      socketOptions.append(QString("so_sndbuf=%1").arg(ui.so_sndbuf->value()));
      socketOptions.append(";");
    }

  if(ui.so_timestamping->isEnabled())
    {
      socketOptions.append
	(QString("so_timestamping=%1").arg(ui.so_timestamping->isChecked()));
      socketOptions.append(";");
    }

  if(socketOptions.endsWith(";"))
    socketOptions = socketOptions.mid(0, socketOptions.length() - 1);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() +
		       QDir::separator() +
		       QString("%1.db").arg(type));

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  (QString("UPDATE %1 SET socket_options = ? WHERE OID = ?").arg(type));
	query.addBindValue(socketOptions);
	query.addBindValue(oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotPostgreSQLKernelUrlDistributionTimeout(int value)
{
  m_settings["gui/postgresql_kernel_url_distribution_timeout"] = value;

  QSettings settings;

  settings.setValue("gui/postgresql_kernel_url_distribution_timeout", value);
}

void spoton::slotShowReleaseNotes(void)
{
  m_releaseNotes->showNormal();
  m_releaseNotes->activateWindow();
  m_releaseNotes->raise();
  spoton_utilities::centerWidget(m_releaseNotes, this);
}

void spoton::slotNewEmailWindow(void)
{
#if SPOTON_GOLDBUG == 0
  QAction *action = qobject_cast<QAction *> (sender());
  spoton_emailwindow *window = 0;

  if(action)
    window = new spoton_emailwindow
      (action->property("message").toString(),
       action->property("subject").toString(),
       action->property("receiver_sender_hash").toString(),
       0);
  else
    window = new spoton_emailwindow("", "", "", 0);

  connect(this,
	  SIGNAL(updateEmailWindows(void)),
	  window,
	  SLOT(slotUpdate(void)));
  connect(window,
	  SIGNAL(configurePoptastic(void)),
	  this,
	  SLOT(slotConfigurePoptastic(void)));
  window->show();
  spoton_utilities::centerWidget(window, this);
#endif
}

QMap<QString, QByteArray> spoton::SMPWindowStreams
(const QStringList &keyTypes) const
{
  return m_smpWindow.streams(keyTypes);
}

void spoton::slotMailContextMenu(const QPoint &point)
{
#if SPOTON_GOLDBUG == 0
  QModelIndexList list
    (m_ui.mail->selectionModel()->selectedRows(5)); // Gold Bug
  bool enabled = false;

  if(!list.isEmpty())
    {
      if(list.at(0).data().toString() == "0")
	enabled = true;
      else
	enabled = false;
    }

  QAction *action = 0;
  QMenu menu(this);

  action = menu.addAction(tr("Read in new window..."),
			  this,
			  SLOT(slotNewEmailWindow(void)));
  action->setEnabled(enabled);

  if(enabled)
    {
      action->setProperty("message", m_ui.mailMessage->toHtml());
      list = m_ui.mail->selectionModel()->selectedRows(3); // Subject
      action->setProperty("subject", list.value(0).data().toString());
      list = m_ui.mail->selectionModel()->
	selectedRows(8); // receiver_sender_hash
      action->setProperty
	("receiver_sender_hash", list.value(0).data().toString());
    }

  menu.exec(m_ui.mail->mapToGlobal(point));
#else
  Q_UNUSED(point);
#endif
}

void spoton::slotTerminateKernelOnUIExit(bool state)
{
  m_settings["gui/terminate_kernel_on_ui_exit"] = state;

  QSettings settings;

  settings.setValue("gui/terminate_kernel_on_ui_exit", state);
}

void spoton::slotKeysIndexChanged(const QString &text)
{
#ifndef SPOTON_OPEN_LIBRARY_SUPPORTED
  if(text == "Open Library")
    m_ui.regenerate->setEnabled(false);
  else
    m_ui.regenerate->setEnabled(true);
#else
  Q_UNUSED(text);
#endif
}

void spoton::generalConcurrentMethod(const QHash<QString, QVariant> &settings)
{
  if(!settings.value("is_kernel_active").toBool())
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() +
			   QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    /*
	    ** OK, so the kernel is inactive. All participants are offline.
	    */

	    query.exec
	      ("UPDATE friends_public_keys SET status = 'offline' WHERE "
	       "status <> 'offline'");
	    spoton_misc::purgeSignatureRelationships
	      (db, m_crypts.value("chat", 0));
	  }
      }

      QSqlDatabase::removeDatabase(connectionName);

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "listeners.db");

	if(db.isOpen())
	  {
	    QSqlQuery query(db);

	    /*
	    ** OK, so the kernel is inactive. Discover the
	    ** listeners that have not been deleted and update some of their
	    ** information.
	    */

	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM listeners WHERE "
		       "status_control = 'deleted'");
	    query.exec("DELETE FROM listeners_accounts WHERE "
		       "listener_oid NOT IN "
		       "(SELECT OID FROM listeners)");
	    query.exec
	      ("DELETE FROM listeners_accounts_consumed_authentications "
	       "WHERE listener_oid >= 0");
	    query.exec("DELETE FROM listeners_allowed_ips WHERE "
		       "listener_oid NOT IN "
		       "(SELECT OID FROM listeners)");
	    query.exec("UPDATE listeners SET connections = 0, "
		       "external_ip_address = NULL, "
		       "status = 'offline' WHERE "
		       "connections > 0 OR status = 'online'");
	  }
      }

      QSqlDatabase::removeDatabase(connectionName);

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    /*
	    ** OK, so the kernel is inactive. Discover the
	    ** neighbors that have not been deleted and not disconnected
	    ** and update some of their information.
	    */

	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM neighbors WHERE "
		       "status_control = 'deleted'");
	    query.exec("UPDATE neighbors SET "
		       "account_authenticated = NULL, "
		       "bytes_discarded_on_write = 0, "
		       "bytes_read = 0, "
		       "bytes_written = 0, "
		       "external_ip_address = NULL, "
		       "is_encrypted = 0, "
		       "local_ip_address = NULL, "
		       "local_port = NULL, "
		       "ssl_session_cipher = NULL, "
		       "status = 'disconnected', "
		       "uptime = 0 WHERE "
		       "local_ip_address IS NOT NULL OR local_port IS NOT NULL "
		       "OR status <> 'disconnected'");
	  }
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  if(settings.value("keep_only_user_defined_neighbors").toBool())
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	if(db.open())
	  {
	    /*
	    ** Delete random, disconnected peers.
	    */

	    QSqlQuery query(db);

	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM neighbors WHERE "
		       "status <> 'connected' AND "
		       "status_control <> 'blocked' AND "
		       "user_defined = 0");
	  }
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::retrieveNeighbors(void)
{
  QFileInfo fileInfo
    (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_neighborsLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_neighborsLastModificationTime)
	    m_neighborsLastModificationTime = fileInfo.lastModified().
	      addMSecs(1);
	  else
	    m_neighborsLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_neighborsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase *db = new QSqlDatabase(spoton_misc::database(connectionName));

    db->setDatabaseName(fileInfo.absoluteFilePath());

    if(db->open())
      {
	QSqlQuery *query = new QSqlQuery(*db);
	int size = 0;

	query->setForwardOnly(true);

	if(query->exec("SELECT COUNT(*) FROM neighbors "
		       "WHERE status_control <> 'deleted'"))
	  if(query->next())
	    size = query->value(0).toInt();

	if(query->exec("SELECT sticky, "
		       "uuid, "
		       "status, "
		       "ssl_key_size, "
		       "status_control, "
		       "local_ip_address, "
		       "local_port, "
		       "external_ip_address, "
		       "external_port, "
		       "country, "
		       "remote_ip_address, "
		       "remote_port, "
		       "scope_id, "
		       "protocol, "
		       "proxy_hostname, "
		       "proxy_port, "
		       "maximum_buffer_size, "
		       "maximum_content_length, "
		       "echo_mode, "
		       "uptime, "
		       "allow_exceptions, "
		       "certificate, "
		       "bytes_read, "
		       "bytes_written, "
		       "ssl_session_cipher, "
		       "account_name, "
		       "account_authenticated, "
		       "transport, "
		       "orientation, "
		       "motd, "
		       "is_encrypted, "
		       "0, " // Certificate
		       "ae_token, "
		       "ae_token_type, "
		       "ssl_control_string, "
		       "priority, "
		       "lane_width, "
		       "passthrough, "
		       "waitforbyteswritten_msecs, "
		       "private_application_credentials, "
		       "silence_time, "
		       "socket_options, "
		       "OID "
		       "FROM neighbors WHERE status_control <> 'deleted'"))
	  {
	    emit neighborsQueryReady(db, query, connectionName, size);
	    return;
	  }

	db->close();
	delete db;
	delete query;
      }
    else
      delete db;
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::retrieveParticipants(spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QFileInfo fileInfo
    (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_participantsLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_participantsLastModificationTime)
	    m_participantsLastModificationTime = fileInfo.lastModified().
	      addMSecs(1);
	  else
	    m_participantsLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_participantsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase *db = new QSqlDatabase(spoton_misc::database(connectionName));

    db->setDatabaseName(fileInfo.absoluteFilePath());

    if(db->open())
      {
	QSqlQuery *query = new QSqlQuery(*db);
	bool ok = true;

	query->setForwardOnly(true);
	query->prepare("SELECT "
		       "name, "               // 0
		       "OID, "                // 1
		       "neighbor_oid, "       // 2
		       "public_key_hash, "    // 3
		       "status, "             // 4
		       "last_status_update, " // 5
		       "gemini, "             // 6
		       "gemini_hash_key, "    // 7
		       "key_type, "           // 8
		       "public_key "          // 9
		       "FROM friends_public_keys "
		       "WHERE key_type_hash IN (?, ?, ?, ?)");
	query->bindValue
	  (0, crypt->keyedHash(QByteArray("chat"), &ok).toBase64());

	if(ok)
	  query->bindValue
	    (1, crypt->keyedHash(QByteArray("email"), &ok).toBase64());

	if(ok)
	  query->bindValue
	    (2, crypt->keyedHash(QByteArray("poptastic"), &ok).toBase64());

	if(ok)
	  query->bindValue
	    (3, crypt->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query->exec())
	  {
	    emit participantsQueryReady(db, query, connectionName);
	    return;
	  }

	db->close();
	delete db;
	delete query;
      }
    else
      delete db;
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotPopulateNeighbors(void)
{
  if(currentTabName() != "neighbors")
    return;
  else if(m_ui.neighborsTemporarilyPause->isChecked())
    return;

  if(m_neighborsFuture.isFinished())
    m_neighborsFuture = QtConcurrent::run(this, &spoton::retrieveNeighbors);
}

void spoton::slotPopulateParticipants(void)
{
  if(m_participantsFuture.isFinished())
    m_participantsFuture = QtConcurrent::run
      (this, &spoton::retrieveParticipants, m_crypts.value("chat", 0));
}

QString spoton::participantKeyType(QTableWidget *table) const
{
  if(!table)
    return QString("");

  int row = -1;

  if((row = table->currentRow()) >= 0)
    {
      QTableWidgetItem *item = table->item(row, 1); // OID

      if(item)
	return item->data
	  (Qt::ItemDataRole(Qt::UserRole + 1)).toString().toLower();
    }

  return QString("");
}

bool spoton::listenerSupportsSslTls(void) const
{
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item1 = m_ui.listeners->item(row, 2);
      QTableWidgetItem *item2 = m_ui.listeners->item(row, 15);

      if(item1 && item2)
	return item1->text().toInt() > 0 &&
	  item2->text().toLower().trimmed() == "tcp";
    }

  return false;
}

QString spoton::listenerTransport(void) const
{
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item(row, 15);

      if(item)
	return item->text();
    }

  return QString("");
}

bool spoton::neighborSupportsSslTls(void) const
{
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item1 = m_ui.neighbors->item(row, 3);
      QTableWidgetItem *item2 = m_ui.neighbors->item(row, 27);

      if(item1 && item2)
	return item1->text().toInt() > 0 &&
	  item2->text().toLower().trimmed() == "tcp";
    }

  return false;
}

QString spoton::neighborTransport(void) const
{
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item(row, 27);

      if(item)
	return item->text();
    }

  return QString("");
}

void spoton::slotPrepareContextMenuMirrors(void)
{
  prepareContextMenuMirrors();
}

void spoton::slotShowErrorMessage(void)
{
  QTimer *timer = qobject_cast<QTimer *> (sender());

  if(!timer)
    return;

  QString str(timer->property("text").toString().trimmed());

  timer->deleteLater();
  QMessageBox::critical
    (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), str);
}

void spoton::slotMonitorEvents(bool state)
{
  m_settings["gui/monitorEvents"] = state;

  QSettings settings;

  settings.setValue("gui/monitorEvents", state);
}

void spoton::slotPQUrlDatabaseFaulty(void)
{
  slotPostgreSQLDisconnect(0);
}

void spoton::inspectPQUrlDatabase(const QByteArray &password)
{
  QSettings settings;
  QSqlDatabase db = QSqlDatabase::addDatabase
    ("QPSQL", "inspect_pq_url_database");
  QString options
    (settings.value("gui/postgresql_connection_options", "").
     toString().trimmed());
  QString str("connect_timeout=5");

  if(!options.isEmpty())
    {
      str.append(";");
      str.append(options);
    }

  if(settings.value("gui/postgresql_ssltls", false).toBool())
    str.append(";requiressl=1");

  db.setConnectOptions(str);
  db.setDatabaseName
    (settings.value("gui/postgresql_database", "").toString().trimmed());
  db.setHostName
    (settings.value("gui/postgresql_host", "localhost").toString().trimmed());
  db.setPort(settings.value("gui/postgresql_port", 5432).toInt());

  if(!db.open(settings.value("gui/postgresql_name", "").toString().trimmed(),
	      password))
    emit pqUrlDatabaseFaulty();

  db.close();
  db = QSqlDatabase();
  QSqlDatabase::removeDatabase("inspect_pq_url_database");
}
