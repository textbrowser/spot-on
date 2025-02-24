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

#include "spot-on-defines.h"
#include "spot-on.h"

#include <QActionGroup>
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QStandardItemModel>
#include <QStandardPaths>
#include <QTableWidgetItem>
#include <QtConcurrent>

QList<QPair<QString, QVariant> > spoton::gatherStatistics(void) const
{
  QList<QPair<QString, QVariant> > list;

  if(isKernelActive())
    {
      QFileInfo const fileInfo
	(spoton_misc::homePath() + QDir::separator() + "kernel.db");
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName(fileInfo.absoluteFilePath());

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);

	    if(query.exec("SELECT statistic, " // 0
			  "value "             // 1
			  "FROM kernel_statistics "
			  "ORDER BY statistic"))
	      while(query.next())
		list << QPair<QString, QVariant> (query.value(0).toString(),
						  query.value(1));
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  return list;
}

QList<QTableWidgetItem *> spoton::findItems(QTableWidget *table,
					    const QString &text,
					    const int column)
{
  if(column < 0 || !table || column >= table->columnCount())
    return QList<QTableWidgetItem *> ();

  QList<QTableWidgetItem *> list;

  for(int i = 0; i < table->rowCount(); i++)
    {
      auto item = table->item(i, column);

      if(!item)
	continue;

      if(item->text() == text)
	list.append(item);
    }

  return list;
}

void spoton::askKernelToReadStarBeamKeys(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  QByteArray message;

  message.append("populate_starbeam_keys\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::askKernelToReadStarBeamKeys(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::importNeighbors(const QString &filePath)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt || filePath.trimmed().isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QFile file;

	file.setFileName(filePath);

	if(file.open(QIODevice::ReadOnly | QIODevice::Text))
	  {
	    QByteArray bytes(2048, 0);
	    qint64 rc = 0;

	    while((rc = file.readLine(bytes.data(), bytes.length())) > -1)
	      {
		bytes = bytes.trimmed();

		if(bytes.isEmpty() || bytes.startsWith("#"))
		  /*
		  ** Comment, or an empty line, ignore!
		  */

		  continue;

		QHash<QString, QByteArray> hash;
		auto const list
		  (bytes.mid(0, static_cast<int> (rc)).trimmed().split('&'));
		auto fine = true;

		for(int i = 0; i < list.size(); i++)
		  {
		    auto token(list.at(i).trimmed());

		    if(token.startsWith("connect="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("connect=")));
			token = token.toLower().trimmed();

			if(!(token == "false" || token == "true"))
			  fine = false;
			else
			  hash["connect"] = token;
		      }
		    else if(token.startsWith("echo_mode="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("echo_mode=")));
			token = token.toLower().trimmed();

			if(!(token == "full" || token == "half"))
			  fine = false;
			else
			  hash["echo_mode"] = token;
		      }
		    else if(token.startsWith("ip_address="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("ip_address=")));
			token = token.toLower().trimmed();

			if(QHostAddress(token.constData()).isNull())
			  {
			    if(token.isEmpty())
			      fine = false;
			    else
			      hash["ip_address"] = token;
			  }
			else
			  hash["ip_address"] = token;
		      }
		    else if(token.startsWith("orientation="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("orientation=")));
			token = token.toLower().trimmed();

			if(!(token == "packet" || token == "stream"))
			  fine = false;
			else
			  hash["orientation"] = token;
		      }
		    else if(token.startsWith("port="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("port=")));
			token = token.trimmed();

			if(!(token.toInt() > 0 &&
			     token.toInt() <= 65535))
			  fine = false;
			else
			  hash["port"] = token;
		      }
		    else if(token.startsWith("protocol="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("protocol=")));
			token = token.toLower().trimmed();

			if(token == "dynamic dns")
			  hash["protocol"] = "Dynamic DNS";
			else if(token == "ipv4")
			  hash["protocol"] = "IPv4";
			else if(token == "ipv6")
			  hash["protocol"] = "IPv6";
			else if(token.isEmpty())
			  hash["protocol"] = "";
			else
			  fine = false;
		      }
		    else if(token.startsWith("scope_id="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("scope_id=")));
			token = token.trimmed();
			hash["scope_id"] = token;
		      }
		    else if(token.startsWith("ssl_key_size="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("ssl_key_size=")));
			token = token.trimmed();

			if(!(token == "0" ||
			     token == "256" ||
			     token == "384" ||
			     token == "521" ||
			     token == "2048" ||
			     token == "3072" ||
			     token == "4096"))
			  fine = false;
			else
			  hash["ssl_key_size"] = token;
		      }
		    else if(token.startsWith("transport="))
		      {
			token.remove
			  (0, static_cast<int> (qstrlen("transport=")));
			token = token.toLower().trimmed();

			if(!(token == "bluetooth" ||
			     token == "sctp" ||
			     token == "tcp" ||
			     token == "udp" ||
			     token == "websocket"))
			  fine = false;
			else
			  hash["transport"] = token;
		      }

		    if(!fine)
		      break;
		  }

		if(hash.count() != 9)
		  fine = false;

		if(fine)
		  {
		    QSqlQuery query(db);
		    auto ok = true;

		    query.prepare
		      ("INSERT INTO neighbors "
		       "(local_ip_address, "
		       "local_port, "
		       "protocol, "
		       "remote_ip_address, "
		       "remote_port, "
		       "sticky, "
		       "scope_id, "
		       "hash, "
		       "status_control, "
		       "country, "
		       "remote_ip_address_hash, "
		       "qt_country_hash, "
		       "proxy_hostname, "
		       "proxy_password, "
		       "proxy_port, "
		       "proxy_type, "
		       "proxy_username, "
		       "uuid, "
		       "echo_mode, "
		       "ssl_key_size, "
		       "allow_exceptions, "
		       "certificate, "
		       "ssl_required, "
		       "account_name, "
		       "account_password, "
		       "transport, "
		       "orientation) "
		       "VALUES "
		       "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		       "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		    query.bindValue(0, QVariant(QMetaType(QMetaType::QString)));
		    query.bindValue(1, QVariant(QMetaType(QMetaType::QString)));
#else
		    query.bindValue(0, QVariant(QVariant::String));
		    query.bindValue(1, QVariant(QVariant::String));
#endif
		    query.bindValue
		      (2, crypt->
		       encryptedThenHashed
		       (hash.value("protocol"), &ok).toBase64());

		    if(ok)
		      query.bindValue
			(3, crypt->
			 encryptedThenHashed
			 (hash.value("ip_address"), &ok).toBase64());

		    if(ok)
		      query.bindValue
			(4, crypt->
			 encryptedThenHashed
			 (hash.value("port"), &ok).toBase64());

		    query.bindValue(5, 1); // Sticky.

		    if(ok)
		      query.bindValue
			(6, crypt->
			 encryptedThenHashed
			 (hash.value("scope_id"), &ok).toBase64());

		    if(ok)
		      query.bindValue
			(7, crypt->
			 keyedHash(QByteArray() + // Proxy HostName
				   QByteArray() + // Proxy Port
				   hash.value("ip_address") +
				   hash.value("port") +
				   hash.value("scope_id") +
				   hash.value("transport"), &ok).
			 toBase64());

		    if(hash.value("connect") == "true")
		      query.bindValue(8, "connected");
		    else
		      query.bindValue(8, "disconnected");

		    auto country
		      (spoton_misc::
		       countryNameFromIPAddress(hash.value("ip_address")));

		    if(ok)
		      query.bindValue
			(9, crypt->
			 encryptedThenHashed
			 (country.toLatin1(), &ok).toBase64());

		    if(ok)
		      query.bindValue
			(10, crypt->
			 keyedHash(hash.value("ip_address"), &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(11, crypt->
			 keyedHash(country.remove(" ").toLatin1(), &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(12, crypt->
			 encryptedThenHashed(QByteArray(), &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(13, crypt->
			 encryptedThenHashed(QByteArray(), &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(14, crypt->encryptedThenHashed
			 (QByteArray(),
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(15, crypt->encryptedThenHashed
			 (QByteArray("NoProxy"),
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(16, crypt->encryptedThenHashed
			 (QByteArray(), &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(17, crypt->
			 encryptedThenHashed
			 ("{00000000-0000-0000-0000-"
			  "000000000000}", &ok).
			 toBase64());

		    if(ok)
		      query.bindValue
			(18, crypt->
			 encryptedThenHashed(hash.value("echo_mode"), &ok).
			 toBase64());

		    if(hash.value("transport") == "tcp")
		      query.bindValue(19, hash.value("ssl_key_size").toInt());
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
		    else if(hash.value("transport") == "udp")
		      query.bindValue(19, hash.value("ssl_key_size").toInt());
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
		    else if(hash.value("transport") == "websocket")
		      query.bindValue(19, hash.value("ssl_key_size").toInt());
#endif
		    else
		      query.bindValue(19, 0);

		    query.bindValue(20, 0);

		    if(ok)
		      query.bindValue
			(21, crypt->encryptedThenHashed
			 (QByteArray(),
			  &ok).toBase64());

		    if(hash.value("transport") == "tcp")
		      query.bindValue(22, 1);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
		    else if(hash.value("transport") == "udp")
		      query.bindValue(22, 1);
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
		    else if(hash.value("transport") == "websocket")
		      query.bindValue(22, 1);
#endif
		    else
		      query.bindValue(22, 0);

		    if(ok)
		      query.bindValue
			(23, crypt->encryptedThenHashed
			 (QByteArray(),
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(24, crypt->encryptedThenHashed
			 (QByteArray(),
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(25,
			 crypt->encryptedThenHashed
			 (hash.value("transport"),
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(26, crypt->encryptedThenHashed
			 (hash.value("orientation"),
			  &ok).toBase64());

		    if(ok)
		      query.exec();
		  }
	      }
	  }

	file.close();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::populateNovas(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	m_ui.novas->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT nova FROM received_novas");

	if(query.exec())
	  {
	    QStringList novas;

	    while(query.next())
	      {
		QString nova("");
		auto ok = true;

		nova = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok);

		if(!nova.isEmpty())
		  novas.append(nova);
	      }

	    std::sort(novas.begin(), novas.end());

	    if(!novas.isEmpty())
	      m_ui.novas->addItems(novas);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::populateStatistics(const QList<QPair<QString, QVariant> > &list)
{
  QString setting("");
  auto focusWidget = QApplication::focusWidget();
  auto totalRows = list.size();
  int activeListeners = 0;
  int activeNeighbors = 0;
  int row = 0;

  if(!m_statisticsUi.view->selectionModel()->selectedRows(0).isEmpty())
    setting = m_statisticsUi.view->selectionModel()->selectedRows(0).at(0).
      data().toString().trimmed();

  m_statisticsUi.view->setSortingEnabled(false);
  m_ui.statistics->setSortingEnabled(false);
  m_statisticsModel->removeRows(0, m_statisticsModel->rowCount());
  m_statisticsModel->setRowCount(totalRows);

  for(int i = 0; i < list.size(); i++)
    {
      auto item = new QStandardItem(list.at(i).first.trimmed());

      item->setEditable(false);
      m_statisticsModel->setItem(row, 0, item);
      item = new QStandardItem(list.at(i).second.toString().trimmed());
      item->setEditable(false);
      item->setToolTip(item->text());
      m_statisticsModel->setItem(row, 1, item);

      if(list.at(i).first.contains("percent consumed", Qt::CaseInsensitive))
	{
	  auto const percent = list.at(i).second.toString().remove('%').
	    toDouble();

	  if(percent <= 50.0)
	    item->setBackground(QBrush(QColor("lightgreen")));
	  else if(percent > 50.0 && percent <= 80.0)
	    item->setBackground(QBrush(QColor(232, 120, 0)));
	  else
	    item->setBackground(QBrush(QColor(240, 128, 128)));
	}
      else if(list.at(i).first.contains("live listeners", Qt::CaseInsensitive))
	activeListeners = list.at(i).second.toInt();
      else if(list.at(i).first.contains("live neighbors", Qt::CaseInsensitive))
	activeNeighbors = list.at(i).second.toInt();

      row += 1;
    }

  totalRows += 4; // Display statistics!
  m_statisticsModel->setRowCount(totalRows);

  QLocale locale;
  auto item = new QStandardItem("Display Forward Secrecy Requests");

  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem(locale.toString(m_forwardSecrecyRequests.size()));
  item->setEditable(false);
  item->setToolTip(item->text());
  m_statisticsModel->setItem(row, 1, item);
  row += 1;
  item = new QStandardItem("Display Open Database Connections");
  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem
    (locale.toString(QSqlDatabase::connectionNames().size()));
  item->setEditable(false);
  item->setToolTip(item->text());
  m_statisticsModel->setItem(row, 1, item);
  row += 1;
  item = new QStandardItem("Display PID");
  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem(QString::number(QApplication::applicationPid()));
  item->setEditable(false);
  item->setToolTip(item->text());
  m_statisticsModel->setItem(row, 1, item);
  row += 1;
  item = new QStandardItem("Display PostgreSQL Connection Faulty Counter");
  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem
    (locale.toString(m_pqUrlFaultyCounter.fetchAndAddOrdered(0)));
  item->setEditable(false);
  item->setToolTip(item->text());
  m_statisticsModel->setItem(row, 1, item);
  m_statisticsUi.view->resizeColumnToContents(0);
  m_statisticsUi.view->horizontalHeader()->setStretchLastSection(true);
  m_statisticsUi.view->sortByColumn(0, Qt::AscendingOrder);
  m_ui.statistics->resizeColumnToContents(0);
  m_ui.statistics->horizontalHeader()->setStretchLastSection(true);
  m_ui.statistics->sortByColumn(0, Qt::AscendingOrder);

  for(int i = 0; i < m_statisticsModel->rowCount(); i++)
    if(m_statisticsModel->item(i, 0) &&
       m_statisticsModel->item(i, 0)->text() == setting)
      {
	m_statisticsUi.view->selectRow(i);
	break;
      }

  if(focusWidget)
    focusWidget->setFocus();

  if(activeListeners > 0 && isKernelActive())
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.listeners->setToolTip
	(tr("There is (are) %1 active listener(s).").
	 arg(locale.toString(activeListeners)));
    }
  else
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.listeners->setToolTip(tr("Listeners are offline."));
    }

  if(activeNeighbors > 0 && isKernelActive())
    {
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.neighbors->setToolTip
	(tr("There is (are) %1 connected neighbor(s).").
	 arg(locale.toString(activeNeighbors)));
    }
  else
    {
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.neighbors->setToolTip(tr("Neighbors are offline."));
    }
}

void spoton::prepareContextMenuMirrors(void)
{
  if(true)
    {
      if(m_ui.chatActionMenu->menu())
	m_ui.chatActionMenu->menu()->clear();

      QAction *action = nullptr;
      QMenu *menu = nullptr;

      if(m_ui.chatActionMenu->menu())
	menu = m_ui.chatActionMenu->menu();
      else
	menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareChatPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(tr("Chat &Popup..."), this,
		      SLOT(slotChatPopup(void)));
      menu->addSeparator();
      menu->addAction(QIcon(":/generic/repleo-chat.png"),
		      tr("&Copy Repleo (Clipboard Buffer)"),
		      this,
		      SLOT(slotCopyFriendshipBundle(void)));
      menu->addSeparator();
#if SPOTON_GOLDBUG == 1
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA: &Call Friend (New "
				  "Gemini Pair)"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA: &Call Friend (New "
				  "Gemini Pair Using Existing "
				  "Gemini Pair)"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA Two-Way: &Call Friend (New "
				  "Gemini Pair)"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      action->setProperty("type", "calling_two_way");
#else
      action = menu->addAction(tr("&Call Participant"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu->addAction(tr("&Call Participant ("
				  "Existing Gemini Pair)"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu->addAction(tr("&Two-Way Calling"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      action->setProperty("type", "calling_two_way");
#endif
      action = menu->addAction(tr("&Terminate Call"),
			       this,
			       SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");
      menu->addSeparator();
#if SPOTON_GOLDBUG == 1
      menu->addAction
	(tr("&Generate Random Gemini Pair (Without Call)"),
	 this,
	 SLOT(slotGenerateGeminiInChat(void)));
#else
      menu->addAction(tr("&Generate Random Gemini Pair"),
		      this,
		      SLOT(slotGenerateGeminiInChat(void)));
#endif
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove Participant(s)"),
		      this,
		      SLOT(slotRemoveParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename Participant..."),
			       this,
			       SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "chat");
      menu->addSeparator();
      menu->addAction(tr("&Derive Gemini Pair From SMP Secret"),
		      this,
		      SLOT(slotDeriveGeminiPairViaSMP(void)));
      menu->addAction(tr("&Reset SMP Machine's Internal State (S0)"),
		      this,
		      SLOT(slotInitializeSMP(void)));
      menu->addAction(tr("&Set SMP Secret..."),
		      this,
		      SLOT(slotPrepareSMP(void)));
      menu->addAction(tr("&Verify SMP Secret"),
		      this,
		      SLOT(slotVerifySMPSecret(void)));
      menu->addSeparator();
      menu->addAction(tr("Replay &Last %1 Messages").
		      arg(spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE),
		      this,
		      SLOT(slotReplayMessages(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/starbeam.png").
			    arg(m_settings.value("gui/iconSet",
						 "nouve").
				toString().toLower())),
		      tr("Share &StarBeam With "
			 "Selected Participant(s)..."),
		      this,
		      SLOT(slotShareStarBeam(void)))->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      menu->addSeparator();
      menu->addAction
	(tr("Call Via Forward &Secrecy Credentials"),
	 this,
	 SLOT(slotCallParticipantViaForwardSecrecy(void)));
      action = menu->addAction(tr("Initiate Forward &Secrecy Exchange(s)..."),
			       this,
			       SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "chat");
      action = menu->addAction(tr("Purge Forward &Secrecy Key Pair"),
			       this,
			       SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "chat");
      action = menu->addAction
	(tr("Reset Forward &Secrecy Information of Selected Participant(s)"),
	 this,
	 SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "chat");
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/buzz.png").
			    arg(m_settings.value("gui/iconSet",
						 "nouve").
				toString().toLower())),
		      tr("Invite Selected Participant(s) "
			 "(Anonymous Buzz Channel)..."),
		      this,
		      SLOT(slotBuzzInvite(void)))->setEnabled
	("chat" == participantKeyType(m_ui.participants));
      m_ui.chatActionMenu->setMenu(menu);
      connect(m_ui.chatActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.chatActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
      connect(menu,
	      SIGNAL(aboutToShow(void)),
	      this,
	      SLOT(slotPrepareContextMenuMirrors(void)),
	      Qt::UniqueConnection);
    }

#if SPOTON_GOLDBUG == 0
  if(!m_ui.clearOutgoing->menu())
    {
      auto menu = new QMenu(this);

      menu->addAction(tr("New E-mail Window..."),
		      this,
		      SLOT(slotNewEmailWindow(void)));
      m_ui.clearOutgoing->setMenu(menu);
    }
#endif

  if(!m_ui.deleteAllUrls->menu())
    {
      auto menu = new QMenu(this);

      menu->addAction(tr("Delete URL Data"),
		      this,
		      SLOT(slotDeleteAllUrls(void)));
      menu->addAction(tr("Drop URL Tables"),
		      this,
		      SLOT(slotDropUrlTables(void)));
      menu->addSeparator();
      menu->addAction(tr("Gather Statistics"),
		      this,
		      SLOT(slotGatherUrlStatistics(void)));
      m_ui.deleteAllUrls->setMenu(menu);
      connect(m_ui.deleteAllUrls,
	      SIGNAL(clicked(void)),
	      m_ui.deleteAllUrls,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }

  if(!m_ui.emailWriteActionMenu->menu())
    {
      QAction *action = nullptr;
      auto menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Copy Keys (Clipboard Buffer)"),
		      this,
		      SLOT(slotCopyEmailKeys(void)));
      menu->addAction(QIcon(":/generic/repleo-email.png"),
		      tr("&Copy Repleo (Clipboard Buffer)"),
		      this,
		      SLOT(slotCopyEmailFriendshipBundle(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove Participant(s)"),
		      this,
		      SLOT(slotRemoveEmailParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename Participant..."),
			       this,
			       SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "email");
      menu->addSeparator();
      action = menu->addAction(tr("Initiate Forward &Secrecy Exchange(s)..."),
			       this,
			       SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "email");
      action = menu->addAction(tr("Purge Forward &Secrecy Key Pair"),
			       this,
			       SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "email");
      action = menu->addAction
	(tr("Reset Forward &Secrecy Information"),
	 this,
	 SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "email");
      m_ui.emailWriteActionMenu->setMenu(menu);
      connect(m_ui.emailWriteActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.emailWriteActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }

  if(true)
    {
      if(m_ui.listenersActionMenu->menu())
	m_ui.listenersActionMenu->menu()->clear();

      QAction *action = nullptr;
      QMenu *menu = nullptr;

      if(m_ui.listenersActionMenu->menu())
	menu = m_ui.listenersActionMenu->menu();
      else
	menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this,
		      SLOT(slotDeleteListener(void)));
      menu->addAction(tr("Delete &All"),
		      this,
		      SLOT(slotDeleteAllListeners(void)));
      menu->addSeparator();
      menu->addAction(tr("Detach &Neighbors"),
		      this,
		      SLOT(slotDetachListenerNeighbors(void)));
      menu->addAction(tr("Disconnect &Neighbors"),
		      this,
		      SLOT(slotDisconnectListenerNeighbors(void)));
      menu->addSeparator();
      menu->addAction(tr("&Publish Information (Plaintext)"),
		      this,
		      SLOT(slotPublicizeListenerPlaintext(void)));
      menu->addAction(tr("Publish &All (Plaintext)"),
		      this,
		      SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this,
		      SLOT(slotListenerFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this,
		      SLOT(slotListenerHalfEcho(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Copy Adaptive Echo Magnet"),
			       this,
			       SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "listeners");
      menu->addSeparator();
      action = menu->addAction
	(tr("&Copy Private Application Magnet"),
	 this,
	 SLOT(slotCopyPrivateApplicationMagnet(void)));
      action->setProperty("type", "listeners");
      action = menu->addAction
	(tr("&Set Private Application Information..."),
	 this,
	 SLOT(slotSetPrivateApplicationInformation(void)));
      action->setProperty("type", "listeners");
      action = menu->addAction
	(tr("&Reset Private Application Information"),
	 this,
	 SLOT(slotResetPrivateApplicationInformation(void)));
      action->setProperty("type", "listeners");
      menu->addSeparator();
      menu->addAction
	(tr("&Prepare New One-Year Certificate"),
	 this,
	 SLOT(slotGenerateOneYearListenerCertificate(void)))->setEnabled
	(listenerSupportsSslTls());
      menu->addAction(tr("Set &SSL Control String..."),
		      this,
		      SLOT(slotSetListenerSSLControlString(void)))->
	setEnabled(listenerSupportsSslTls());
      menu->addSeparator();
      action = menu->addAction(tr("Set Socket &Options..."),
			       this,
			       SLOT(slotSetSocketOptions(void)));
      action->setEnabled(listenerTransport() > "bluetooth");
      action->setProperty("type", "listeners");
      m_ui.listenersActionMenu->setMenu(menu);
      connect(m_ui.listenersActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.listenersActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
      connect(menu,
	      SIGNAL(aboutToShow(void)),
	      this,
	      SLOT(slotPrepareContextMenuMirrors(void)),
	      Qt::UniqueConnection);
    }

  if(!m_ui.magnetsActionMenu->menu())
    {
      auto menu = new QMenu(this);

      menu->addAction(tr("Copy &Magnet"),
		      this,
		      SLOT(slotCopyEtpMagnet(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this,
		      SLOT(slotDeleteEtpMagnet(void)));
      menu->addAction(tr("Delete &All"),
		      this,
		      SLOT(slotDeleteEtpAllMagnets(void)));
      m_ui.magnetsActionMenu->setMenu(menu);
      connect(m_ui.magnetsActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.magnetsActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }

  if(true)
    {
      if(m_ui.neighborsActionMenu->menu())
	m_ui.neighborsActionMenu->menu()->clear();

      QAction *action = nullptr;
      QMenu *menu = nullptr;
      auto const neighborSpecialClient = this->neighborSpecialClient();
      auto const neighborSupportsSslTls = this->neighborSupportsSslTls();

      if(m_ui.neighborsActionMenu->menu())
	menu = m_ui.neighborsActionMenu->menu();
      else
	menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &Chat Public Key Pair"),
		      this,
		      SLOT(slotShareChatPublicKey(void)));
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &E-Mail Public Key Pair"),
		      this,
		      SLOT(slotShareEmailPublicKey(void)));
#ifdef SPOTON_OPEN_LIBRARY_SUPPORTED
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &Open Library Public Key Pair"),
		      this,
		      SLOT(slotShareOpenLibraryPublicKey(void)));
#endif
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &Poptastic Public Key Pair"),
		      this,
		      SLOT(slotSharePoptasticPublicKey(void)));
      menu->addAction(QIcon(QString(":%1//share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &URL Public Key Pair"),
		      this,
		      SLOT(slotShareURLPublicKey(void)));
      menu->addSeparator();
      menu->addAction(tr("&Assign New Remote IP Information..."),
		      this,
		      SLOT(slotAssignNewIPToNeighbor(void)));
      menu->addAction(tr("&Connect"),
		      this,
		      SLOT(slotConnectNeighbor(void)));
      menu->addAction(tr("&Disconnect"),
		      this,
		      SLOT(slotDisconnectNeighbor(void)));
      menu->addSeparator();
      menu->addAction(tr("&Connect All"),
		      this,
		      SLOT(slotConnectAllNeighbors(void)));
      menu->addAction(tr("&Disconnect All"),
		      this,
		      SLOT(slotDisconnectAllNeighbors(void)));
      menu->addSeparator();
      menu->addAction
	(tr("&Authenticate Account..."),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu->addAction(tr("&Reset Account Information"),
		      this,
		      SLOT(slotResetAccountInformation(void)));
      menu->addSeparator();
      menu->addAction(tr("&Reset Certificate"),
		      this,
		      SLOT(slotResetCertificate(void)))->setEnabled
	(neighborSupportsSslTls);
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this,
		      SLOT(slotDeleteNeighbor(void)));
      menu->addAction(tr("Delete &All"),
		      this,
		      SLOT(slotDeleteAllNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &Blocked"),
		      this,
		      SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &UUIDs"),
		      this,
		      SLOT(slotDeleteAllUuids(void)));
      menu->addSeparator();
      menu->addAction(tr("B&lock"),
		      this,
		      SLOT(slotBlockNeighbor(void)));
      menu->addAction(tr("U&nblock"),
		      this,
		      SLOT(slotUnblockNeighbor(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this,
		      SLOT(slotNeighborFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this,
		      SLOT(slotNeighborHalfEcho(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Copy Adaptive Echo Magnet"),
			       this,
			       SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "neighbors");
      menu->addAction(tr("&Set Adaptive Echo Token Information..."),
		      this,
		      SLOT(slotSetAETokenInformation(void)));
      menu->addAction(tr("&Reset Adaptive Echo Token Information"),
		      this,
		      SLOT(slotResetAETokenInformation(void)));
      menu->addSeparator();
      action = menu->addAction
	(tr("&Copy Private Application Magnet"),
	 this,
	 SLOT(slotCopyPrivateApplicationMagnet(void)));
      action->setProperty("type", "neighbors");
      action = menu->addAction
	(tr("&Set Private Application Information..."),
	 this,
	 SLOT(slotSetPrivateApplicationInformation(void)));
      action->setProperty("type", "neighbors");
      action = menu->addAction
	(tr("&Reset Private Application Information"),
	 this,
	 SLOT(slotResetPrivateApplicationInformation(void)));
      action->setProperty("type", "neighbors");
      menu->addSeparator();
      menu->addAction(tr("Set &SSL Control String..."),
		      this,
		      SLOT(slotSetNeighborSSLControlString(void)))->
	setEnabled(neighborSupportsSslTls);
      menu->addSeparator();
      action = menu->addAction(tr("Set Socket &Options..."),
			       this,
			       SLOT(slotSetSocketOptions(void)));
      action->setEnabled(neighborTransport() > "bluetooth");
      action->setProperty("type", "neighbors");
      menu->addSeparator();

      QList<QPair<QString, QThread::Priority> > list;
      QPair<QString, QThread::Priority> pair;
      auto actionGroup = new QActionGroup(menu);
      auto subMenu = menu->addMenu(tr("Priority"));

      pair.first = tr("High Priority");
      pair.second = QThread::HighPriority;
      list << pair;
      pair.first = tr("Highest Priority");
      pair.second = QThread::HighestPriority;
      list << pair;
      pair.first = tr("Idle Priority");
      pair.second = QThread::IdlePriority;
      list << pair;
      pair.first = tr("Low Priority");
      pair.second = QThread::LowPriority;
      list << pair;
      pair.first = tr("Lowest Priority");
      pair.second = QThread::LowestPriority;
      list << pair;
      pair.first = tr("Normal Priority");
      pair.second = QThread::NormalPriority;
      list << pair;
      pair.first = tr("Time-Critical Priority");
      pair.second = QThread::TimeCriticalPriority;
      list << pair;

      auto const priority = neighborThreadPriority();

      for(int i = 0; i < list.size(); i++)
	{
	  action = subMenu->addAction
	    (list.at(i).first,
	     this,
	     SLOT(slotSetNeighborPriority(void)));
	  action->setCheckable(true);
	  action->setProperty("priority", list.at(i).second);
	  actionGroup->addAction(action);

	  if(list.at(i).second == priority)
	    action->setChecked(true);
	}

      if(actionGroup->actions().isEmpty())
	actionGroup->deleteLater();

#if SPOTON_GOLDBUG == 0
      menu->addSeparator();
      menu->addAction("&Statistics...",
		      this,
		      SLOT(slotShowNeighborStatistics(void)));
#endif
      menu->addSeparator();
      action = menu->addAction
	(tr("Initiate SSL/TLS Client Session"),
	 this,
	 SLOT(slotInitiateSSLTLSSession(void)));
      action->setEnabled(neighborSpecialClient && neighborSupportsSslTls);
      action->setProperty("mode", "client");
      action = menu->addAction
	(tr("Initiate SSL/TLS Server Session"),
	 this,
	 SLOT(slotInitiateSSLTLSSession(void)));
      action->setEnabled(neighborSpecialClient && neighborSupportsSslTls);
      action->setProperty("mode", "server");
      m_ui.neighborsActionMenu->setMenu(menu);
      connect(m_ui.neighborsActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.neighborsActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
      connect(menu,
	      SIGNAL(aboutToShow(void)),
	      this,
	      SLOT(slotPrepareContextMenuMirrors(void)),
	      Qt::UniqueConnection);
    }

  if(!m_ui.receivedActionMenu->menu())
    {
      QAction *action = nullptr;
      auto menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"), this,
		      SLOT(slotDeleteReceived(void)));
      menu->addAction(tr("Delete &All"), this,
		      SLOT(slotDeleteAllReceived(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Compute SHA-1 Hash"), this,
			       SLOT(slotComputeFileHash(void)));
      action->setProperty("hash", "sha-1");
      action->setProperty("widget_of", "received");
      action = menu->addAction(tr("&Compute SHA3-512  Hash"), this,
			       SLOT(slotComputeFileHash(void)));
#if QT_VERSION < 0x050100
      action->setEnabled(false);
#endif
      action->setProperty("hash", "sha3-512");
      action->setProperty("widget_of", "received");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy SHA-1 Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "received");
      m_ui.receivedActionMenu->setMenu(menu);
      connect(m_ui.receivedActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.receivedActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }

  if(!m_ui.transmittedActionMenu->menu())
    {
      QAction *action = nullptr;
      auto menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"), this,
		      SLOT(slotDeleteTransmitted(void)));
      menu->addAction(tr("Delete &All"), this,
		      SLOT(slotDeleteAllTransmitted(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Compute SHA-1 Hash"), this,
			       SLOT(slotComputeFileHash(void)));
      action->setProperty("hash", "sha-1");
      action->setProperty("widget_of", "transmitted");
      action = menu->addAction(tr("&Compute SHA3-512 Hash"), this,
			       SLOT(slotComputeFileHash(void)));
#if QT_VERSION < 0x050100
      action->setEnabled(false);
#endif
      action->setProperty("hash", "sha3-512");
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy SHA-1 Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      menu->addAction(tr("Copy &Magnet"),
		      this,
		      SLOT(slotCopyTransmittedMagnet(void)));
      menu->addAction(tr("&Duplicate Magnet"),
		      this,
		      SLOT(slotDuplicateTransmittedMagnet(void)));
      menu->addSeparator();
      menu->addAction(tr("Set &Pulse Size..."), this,
		      SLOT(slotSetSBPulseSize(void)));
      menu->addAction(tr("Set &Read Interval..."), this,
		      SLOT(slotSetSBReadInterval(void)));
      m_ui.transmittedActionMenu->setMenu(menu);
      connect(m_ui.transmittedActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.transmittedActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }

  if(!m_ui.urlActionMenu->menu())
    {
      QAction *action = nullptr;
      auto menu = new QMenu(this);

      menu->setStyleSheet("QMenu {menu-scrollable: 1;}");
      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add Participant As Friend"),
	 this,
	 SLOT(slotShareUrlPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Copy Keys (Clipboard Buffer)"),
		      this,
		      SLOT(slotCopyUrlKeys(void)));
      menu->addAction(QIcon(":/generic/repleo-url.png"),
		      tr("&Copy Repleo (Clipboard Buffer)"),
		      this,
		      SLOT(slotCopyUrlFriendshipBundle(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove Participant(s)"),
		      this,
		      SLOT(slotRemoveUrlParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename Participant..."),
			       this,
			       SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "url");
      m_ui.urlActionMenu->setMenu(menu);
      connect(m_ui.urlActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.urlActionMenu,
	      SLOT(showMenu(void)),
	      Qt::UniqueConnection);
    }
}

void spoton::saveDestination(const QString &path)
{
  m_settings["gui/etpDestinationPath"] = path;

  QSettings settings;

  settings.setValue("gui/etpDestinationPath", path);
  m_ui.destination->setText(path);
  m_ui.destination->setCursorPosition(0);
  m_ui.destination->setToolTip(path);
  m_ui.destination->selectAll();
}

void spoton::sharePublicKeyWithParticipant(const QString &keyType)
{
  if(!m_crypts.value(QString("%1-signature").arg(keyType), nullptr) ||
     !m_crypts.value(keyType, nullptr))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString oid("");
  QString publicKeyHash("");
  QTableWidget *table = nullptr;
  int row = -1;

  if(keyType == "chat" || keyType == "poptastic")
    if(currentTabName() == "chat")
      table = m_ui.participants;

  if(keyType == "email" || keyType == "poptastic")
    if(currentTabName() == "email")
      table = m_ui.emailParticipants;

  if(keyType == "url")
    table = m_ui.urlParticipants;

  if(!table)
    {
      QApplication::restoreOverrideCursor();
      return;
    }

  if((row = table->currentRow()) >= 0)
    {
      auto item = table->item(row, 2); // neighbor_oid

      if(item)
	oid = item->text();

      if((item = table->item(row, 3))) // public_key_hash
	publicKeyHash = item->text();
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }
  else if(oid == "0")
    {
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE "
			  "public_key_hash = ? AND "
			  "neighbor_oid = 0");
	    query.bindValue(0, publicKeyHash.toLatin1());
	    query.exec();
	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE "
			  "public_key_hash IN "
			  "(SELECT signature_public_key_hash FROM "
			  "relationships_with_signatures WHERE "
			  "public_key_hash = ?) "
			  "AND neighbor_oid = 0");
	    query.bindValue(0, publicKeyHash.toLatin1());
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  QByteArray publicKey;
  QByteArray signature;
  auto ok = true;

  publicKey = m_crypts.value(keyType)->publicKey(&ok);

  if(ok)
    signature = m_crypts.value(keyType)->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value(QString("%1-signature").arg(keyType))->
      publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value(QString("%1-signature").arg(keyType))->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name;

      if(keyType == "chat")
	name = m_settings.value("gui/nodeName", "unknown").
	  toByteArray();
      else if(keyType == "email")
	name = m_settings.value("gui/emailName", "unknown").
	  toByteArray();
      else if(keyType == "poptastic")
	name = poptasticName();
      else if(keyType == "url")
	name = name = m_settings.value("gui/urlName", "unknown").
	  toByteArray();

      if(name.isEmpty())
	{
	  if(keyType == "poptastic")
	    name = "unknown@unknown.org";
	  else
	    name = "unknown";
	}

      message.append("befriendparticipant_");
      message.append(oid.toUtf8());
      message.append("_");
      message.append(keyType.toLatin1().toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(qCompress(publicKey).toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(!writeKernelSocketData(message))
	spoton_misc::logError
	  (QString("spoton::sharePublicKeyWithParticipant(): "
		   "write() failure for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotAcceptBuzzMagnets(bool state)
{
  m_settings["gui/acceptBuzzMagnets"] = state;

  QSettings settings;

  settings.setValue("gui/acceptBuzzMagnets", state);
}

void spoton::slotAcceptChatKeys(bool state)
{
  m_settings["gui/acceptChatKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptChatKeys", state);
}

void spoton::slotAcceptEmailKeys(bool state)
{
  m_settings["gui/acceptEmailKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptEmailKeys", state);
}

void spoton::slotAcceptUrlKeys(bool state)
{
  m_settings["gui/acceptUrlKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptUrlKeys", state);
}

void spoton::slotAddEtpMagnet(const QString &text, const bool displayError)
{
  QString connectionName("");
  QString error("");
  QString magnet("");
  auto crypt = m_crypts.value("chat", nullptr);
  auto ok = true;
  auto origin(tr("StarBeam"));

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  prepareDatabasesFromUI();

  if(m_ui.magnetRadio->isChecked() || !text.isEmpty())
    {
      if(text.isEmpty())
	magnet = m_ui.etpMagnet->toPlainText();
      else
	{
	  magnet = text;
	  origin = tr("Buzz / Chat");
	}
    }
  else
    magnet = QString("magnet:?"
		     "ct=%1&"
		     "ek=%2&"
		     "ht=%3&"
		     "mk=%4&"
		     "xt=urn:starbeam").
      arg(m_ui.etpCipherType->currentText()).
      arg(m_ui.etpEncryptionKey->text()).
      arg(m_ui.etpHashType->currentText()).
      arg(m_ui.etpMacKey->text());

  /*
  ** Validate the magnet.
  */

  if(!spoton_misc::isValidStarBeamMagnet(magnet.toLatin1()))
    {
      error = tr("Invalid StarBeam magnet. Are you missing tokens?");
      goto done_label;
    }

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO magnets "
		      "(magnet, magnet_hash, origin) "
		      "VALUES (?, ?, ?)");
	query.addBindValue
	  (crypt->encryptedThenHashed(magnet.toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(magnet.toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->encryptedThenHashed(origin.toUtf8(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error occurred.");
  else
    {
      if(text.isEmpty())
	{
	  m_ui.etpCipherType->setCurrentIndex(0);
	  m_ui.etpEncryptionKey->clear();
	  m_ui.etpHashType->setCurrentIndex(0);
	  m_ui.etpMacKey->clear();
	  m_ui.etpMagnet->clear();
	}
    }

 done_label:

  if(!error.isEmpty())
    {
      if(displayError)
	{
	  QMessageBox::critical
	    (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
	  QApplication::processEvents();
	}
    }
  else
    askKernelToReadStarBeamKeys();
}

void spoton::slotAddReceiveNova(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  auto const nova(m_ui.receiveNova->text().trimmed());

  if(nova.length() < 48)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Please provide a nova that contains at least "
	    "forty-eight characters. Reach for the stars!"));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received_novas (nova, nova_hash) "
	   "VALUES (?, ?)");
	query.addBindValue
	  (crypt->encryptedThenHashed(nova.toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(nova.toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      m_ui.receiveNova->clear();
      populateNovas();
      askKernelToReadStarBeamKeys();
    }
  else
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Unable to store the nova."));
      QApplication::processEvents();
    }
}

void spoton::slotAutoRetrieveEmail(bool state)
{
  m_settings["gui/automaticallyRetrieveEmail"] = state;

  QSettings settings;

  settings.setValue("gui/automaticallyRetrieveEmail", state);

  if(state)
    m_emailRetrievalTimer.start();
  else
    m_emailRetrievalTimer.stop();
}

void spoton::slotBuzzActionsActivated(int index)
{
  if(index == 0)
    {
      m_ui.channel->clear();
      m_ui.buzzIterationCount->setValue(m_ui.buzzIterationCount->minimum());
      m_ui.channelSalt->clear();
      m_ui.channelType->setCurrentIndex(0);
      m_ui.buzzHashKey->clear();
      m_ui.buzzHashType->setCurrentIndex(0);
    }
  else if(index == 1)
    {
      m_ui.channel->setText
	(spoton_crypt::strongRandomBytes(static_cast<size_t> (m_ui.channel->
							      maxLength())).
	 toBase64());
      m_ui.channel->setCursorPosition(0);
      m_ui.channelSalt->setText
	(spoton_crypt::strongRandomBytes(512).toBase64());
      m_ui.channelSalt->setCursorPosition(0);
      m_ui.buzzHashKey->setText
	(spoton_crypt::
	 strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	 toBase64());
      m_ui.buzzHashKey->setCursorPosition(0);
    }

  disconnect(m_ui.buzzActions,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotBuzzActionsActivated(int)));
  m_ui.buzzActions->setCurrentIndex(0);
  connect(m_ui.buzzActions,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotBuzzActionsActivated(int)));
}

void spoton::slotComputeFileHash(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QTableWidget *table = nullptr;

  if(action->property("widget_of").toString().toLower() == "received")
    table = m_ui.received;
  else if(action->property("widget_of").toString().toLower() == "transmitted")
    table = m_ui.transmitted;

  if(!table)
    return;

  QString oid("");
  int row = -1;

  if((row = table->currentRow()) >= 0)
    {
      auto item = table->item(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QTableWidgetItem *item = nullptr;

  if(m_ui.received == table)
    item = table->item(table->currentRow(), 4); // File
  else
    item = table->item(table->currentRow(), 5); // File

  if(!item)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray hash;
  auto const fileName(item->text());
  auto const type(action->property("hash").toString());
  auto field("");

  if(type == "sha-1")
    {
      hash = spoton_crypt::sha1FileHash(fileName);
      field = "hash";
    }
  else
    {
      hash = spoton_crypt::sha3_512FileHash(fileName);
      field = "sha3_512_hash";
    }

  QApplication::restoreOverrideCursor();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	if(m_ui.received == table)
	  query.prepare
	    (QString("UPDATE received SET %1 = ? WHERE OID = ?").arg(field));
	else
	  query.prepare
	    (QString("UPDATE transmitted SET %1 = ? WHERE OID = ?").
	     arg(field));

	if(hash.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	  query.bindValue(0, QVariant(QMetaType(QMetaType::QString)));
#else
	  query.bindValue(0, QVariant::String);
#endif
	else
	  query.bindValue
	    (0, crypt->encryptedThenHashed(hash.toHex(), &ok).
	     toBase64());

	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCopyEmailKeys(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray name;
  QByteArray publicKeyHash;
  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      auto item = m_ui.emailParticipants->item(row, 0); // Name

      if(item)
	name.append(item->text().toUtf8());

      item = m_ui.emailParticipants->item(row, 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.emailParticipants->item(row, 3); // public_key_hash

      if(item)
	publicKeyHash.append(item->text().toUtf8());
    }

  if(oid.isEmpty() || publicKeyHash.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  if(name.isEmpty())
    name = "unknown";

  QByteArray publicKey;
  QByteArray signatureKey;
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  signatureKey = spoton_misc::signaturePublicKeyFromPublicKeyHash
    (QByteArray::fromBase64(publicKeyHash), crypt);

  if(!publicKey.isEmpty() && !signatureKey.isEmpty())
    {
      auto const text
	("K" + QByteArray("email").toBase64() + "@" + // 0
	 name.toBase64() + "@" +                      // 1
	 qCompress(publicKey.toBase64()) + "@" +      // 2
	 QByteArray().toBase64() + "@" +              // 3
	 signatureKey.toBase64() + "@" +              // 4
	 QByteArray().toBase64());                    // 5

      if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
	{
	  QApplication::restoreOverrideCursor();
	  QMessageBox::critical
	    (this,
	     tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	     tr("The e-mail keys are too long (%1 bytes).").
	     arg(QLocale().toString(text.length())));
	  QApplication::processEvents();
	  return;
	}

      clipboard->setText(spoton_misc::wrap(text));
    }
  else
    clipboard->clear();

  QApplication::restoreOverrideCursor();
}

void spoton::slotCopyEtpMagnet(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.etpMagnets->currentRow()) >= 0)
    {
      auto item = m_ui.etpMagnets->item(row, 2); // Magnet

      if(item)
	clipboard->setText(item->text());
    }
}

void spoton::slotCopyFileHash(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    {
      clipboard->clear();
      return;
    }

  QTableWidget *table = nullptr;

  if(action->property("widget_of").toString().toLower() == "received")
    table = m_ui.received;
  else if(action->property("widget_of").toString().toLower() == "transmitted")
    table = m_ui.transmitted;

  if(!table)
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = table->currentRow()) >= 0)
    {
      auto item = table->item(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      return;
    }

  QTableWidgetItem *item = nullptr;

  if(m_ui.received == table)
    item = table->item(table->currentRow(), 5); // Hash
  else
    item = table->item(table->currentRow(), 7); // Hash

  if(!item)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText(item->text());
}

void spoton::slotCopyOrPaste(void)
{
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  auto widget = QApplication::focusWidget();

  if(!widget)
    return;

  QString a("");

  if(action == m_ui.action_Copy)
    a = "copy";
  else
    a = "paste";

  if(qobject_cast<QLineEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QLineEdit *> (widget)->copy();
      else
	qobject_cast<QLineEdit *> (widget)->paste();
    }
  else if(qobject_cast<QPlainTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QPlainTextEdit *> (widget)->copy();
      else
	qobject_cast<QPlainTextEdit *> (widget)->paste();
    }
  else if(qobject_cast<QTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QTextEdit *> (widget)->copy();
      else
	qobject_cast<QTextEdit *> (widget)->paste();
    }
}

void spoton::slotCopyTransmittedMagnet(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  auto item = m_ui.transmittedMagnets->currentItem();

  if(item)
    clipboard->setText(item->text());
}

void spoton::slotCopyUrlFriendshipBundle(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypts.value("url", nullptr) ||
     !m_crypts.value("url-signature", nullptr))
    {
      clipboard->clear();
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString oid("");
  int row = -1;

  if((row = m_ui.urlParticipants->currentRow()) >= 0)
    {
      auto item = m_ui.urlParticipants->item(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  /*
  ** 1. Generate some symmetric information, S.
  ** 2. Encrypt S with the participant's public key.
  ** 3. Encrypt our information (name, public keys, signatures) with the
  **    symmetric key. Call our information T.
  ** 4. Compute a keyed hash of T.
  */

  QString neighborOid("");
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray startsWith;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  QString receiverName("");
  auto const cipherType(m_settings.value("gui/kernelCipherType", "aes256").
			toString().toLatin1());
  auto ok = true;

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     startsWith,
				     neighborOid,
				     receiverName,
				     cipherType,
				     oid,
				     m_crypts.value("url", nullptr),
				     &ok);

  if(!ok || hashKey.isEmpty() || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(),
     publicKey,
     startsWith,
     &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySPublicKey(m_crypts.value("url-signature")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySSignature
    (m_crypts.value("url-signature")->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const myPublicKey(m_crypts.value("url")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const mySignature
    (m_crypts.value("url")->digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto myName
    (m_settings.value("gui/urlName", "unknown").toByteArray());

  if(myName.isEmpty())
    myName = "unknown";

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     spoton_crypt::preferredHashAlgorithm(),
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  data = crypt.encrypted(QByteArray("url").toBase64() + "@" +
			 myName.toBase64() + "@" +
			 qCompress(myPublicKey).toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      QApplication::restoreOverrideCursor();
      return;
    }

  auto const text("R" +
		  keyInformation.toBase64() + "@" +
		  data.toBase64() + "@" +
		  hash.toBase64());

  if(text.length() >= spoton_common::MAXIMUM_COPY_KEY_SIZES)
    {
      QApplication::restoreOverrideCursor();
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("The URL bundle is too long (%1 bytes).").
	 arg(QLocale().toString(text.length())));
      QApplication::processEvents();
      return;
    }

  clipboard->setText(spoton_misc::wrap(text));
  QApplication::restoreOverrideCursor();
}

void spoton::slotDeleteAllReceived(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM received");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteAllTransmitted(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.exec("DELETE FROM transmitted");
	    query.exec("DELETE FROM transmitted_magnets");
	    query.exec("DELETE FROM transmitted_scheduled_pulses");
	  }
	else
	  query.exec("UPDATE transmitted SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteEtpAllMagnets(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM magnets");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  askKernelToReadStarBeamKeys();
}

void spoton::slotDeleteEtpMagnet(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.etpMagnets->currentRow()) >= 0)
    {
      auto item = m_ui.etpMagnets->item
	(row, m_ui.etpMagnets->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM magnets WHERE OID = ?");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  askKernelToReadStarBeamKeys();
}

void spoton::slotDeleteNova(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  auto const list(m_ui.novas->selectionModel()->selectedRows());

  if(list.isEmpty() || list.value(0).isValid() == false)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please select a nova to delete."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM received_novas WHERE nova_hash = ?");
	query.addBindValue
	  (crypt->keyedHash(list.at(0).data().toString().toLatin1(), &ok).
	   toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting "
			       "to delete the speficied nova."));
      QApplication::processEvents();
    }
  else
    {
      populateNovas();
      askKernelToReadStarBeamKeys();
    }
}

void spoton::slotDeleteReceived(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      auto item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM received WHERE OID = ?");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteTransmitted(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      auto item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM transmitted WHERE "
			  "OID = ?");
	    query.bindValue(0, oid);
	    query.exec();
	    query.exec("DELETE FROM transmitted_magnets WHERE "
		       "transmitted_oid NOT IN "
		       "(SELECT OID FROM transmitted)");
	    query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
		       "transmitted_oid NOT IN "
		       "(SELECT OID FROM transmitted)");
	  }
	else
	  {
	    query.prepare
	      ("UPDATE transmitted SET status_control = 'deleted' "
	       "WHERE OID = ? AND status_control <> 'deleted'");
	    query.bindValue(0, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotExportListeners(void)
{
  if(m_ui.listeners->rowCount() == 0)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Unable to export an empty listeners table."));
      QApplication::processEvents();
      return;
    }

  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptSave);
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
  dialog.setFileMode(QFileDialog::AnyFile);
  dialog.setLabelText(QFileDialog::Accept, tr("Save"));
  dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
  dialog.setWindowTitle
    (tr("%1: Select Listeners Export File").arg(SPOTON_APPLICATION_NAME));
  dialog.selectFile
    (QString("spot-on-listeners-export-%1.txt").
     arg(QDateTime::currentDateTime().toString("MM-dd-yyyy-hh-mm-ss")));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QFile file;

      file.setFileName(dialog.selectedFiles().value(0));

      if(file.fileName().trimmed().length() > 0 &&
	 file.open(QIODevice::Text |
		   QIODevice::Truncate |
		   QIODevice::WriteOnly))
	for(int i = 0; i < m_ui.listeners->rowCount(); i++)
	  {
	    QByteArray bytes;

	    bytes.append("echo_mode=");
	    bytes.append(m_ui.listeners->item(i, 11)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("ip_address=");
	    bytes.append(m_ui.listeners->item(i, 7)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("orientation=");
	    bytes.append(m_ui.listeners->item(i, 18)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("port=");
	    bytes.append(m_ui.listeners->item(i, 4)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("protocol=");
	    bytes.append(m_ui.listeners->item(i, 6)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("scope_id=");
	    bytes.append
	      (m_ui.listeners->item(i, 5)->text().remove("&").toUtf8());
	    bytes.append("&");
	    bytes.append("ssl_key_size=");
	    bytes.append(m_ui.listeners->item(i, 2)->text().toUtf8());
	    bytes.append("&");
	    bytes.append("transport=");
	    bytes.append(m_ui.listeners->item(i, 15)->text().toUtf8());
	    bytes.append("\n");
	    file.write(bytes);
	    file.flush();
	  }

      file.close();
      QApplication::restoreOverrideCursor();
    }

  QApplication::processEvents();
}

void spoton::slotExportPublicKeys(void)
{
  QApplication::restoreOverrideCursor();

  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptSave);
  dialog.setDirectory
    (QStandardPaths::
     standardLocations(QStandardPaths::DesktopLocation).value(0));
  dialog.setFileMode(QFileDialog::AnyFile);
  dialog.setLabelText(QFileDialog::Accept, tr("Save"));
  dialog.setOption(QFileDialog::DontConfirmOverwrite, false);
  dialog.setWindowTitle
    (tr("%1: Select Public Keys Export File").arg(SPOTON_APPLICATION_NAME));
  dialog.selectFile
    (QString("spot-on-public-keys-export-%1.txt").
     arg(QDateTime::currentDateTime().toString("MM-dd-yyyy-hh-mm-ss")));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QFile file;

      file.setFileName(dialog.selectedFiles().value(0));

      if(file.fileName().trimmed().length() > 0 &&
	 file.open(QIODevice::Text |
		   QIODevice::Truncate |
		   QIODevice::WriteOnly))
	{
	  for(int i = 1;; i++)
	    {
	      QByteArray bytes;

	      if(i == 1)
		bytes = copyMyChatPublicKey();
	      else if(i == 2)
		bytes = copyMyEmailPublicKey();
	      else if(i == 3)
		bytes = copyMyOpenLibraryPublicKey();
	      else if(i == 4)
		bytes = copyMyPoptasticPublicKey();
	      else if(i == 5)
		bytes = copyMyRosettaPublicKey();
	      else if(i == 6)
		bytes = copyMyUrlPublicKey();
	      else
		break;

	      if(!bytes.isEmpty())
		file.write(bytes + "\n");
	    }

	  file.flush();
	}

      file.close();
      QApplication::restoreOverrideCursor();
    }

  QApplication::processEvents();
}

void spoton::slotExternalIp(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QString str("");
  int v = 30;

  if(comboBox == m_optionsUi.guiExternalIpFetch)
    str = "gui";
  else
    str = "kernel";

  if(index == 0)
    v = 30;
  else if(index == 1)
    v = 60;
  else
    v = -1;

  m_settings[QString("gui/%1ExternalIpInterval").arg(str)] = v;

  QSettings settings;

  settings.setValue(QString("gui/%1ExternalIpInterval").arg(str), v);

  if(str == "gui")
    {
      if(index == 0)
	m_externalAddressDiscovererTimer.start(30000);
      else if(index == 1)
	m_externalAddressDiscovererTimer.start(60000);
      else
	{
	  m_externalAddress->clear();
	  m_externalAddressDiscovererTimer.stop();
	}
    }
}

void spoton::slotForceKernelRegistration(bool state)
{
  m_settings["gui/forceKernelRegistration"] = state;

  QSettings settings;

  settings.setValue("gui/forceKernelRegistration", state);
}

void spoton::slotGatherStatistics(void)
{
  if(!m_statisticsFuture.isFinished())
    return;

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
  m_statisticsFuture = QtConcurrent::run(&spoton::gatherStatistics, this);
#else
  m_statisticsFuture = QtConcurrent::run(this, &spoton::gatherStatistics);
#endif
  m_statisticsFutureWatcher.setFuture(m_statisticsFuture);
}

void spoton::slotGenerateEtpKeys(int index)
{
  /*
  ** StarBeam!
  */

  if(m_ui.pairRadio->isChecked())
    {
      if(index == 0)
	{
	  m_ui.etpCipherType->setCurrentIndex(0);
	  m_ui.etpEncryptionKey->clear();
	  m_ui.etpHashType->setCurrentIndex(0);
	  m_ui.etpMacKey->clear();
	}
      else if(index == 1)
	{
	  m_ui.etpEncryptionKey->setText
	    (spoton_crypt::
	     strongRandomBytes(static_cast<size_t> (m_ui.etpEncryptionKey->
						    maxLength())).
	     toBase64());
	  m_ui.etpEncryptionKey->setCursorPosition(0);
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	     toBase64());
	  m_ui.etpMacKey->setCursorPosition(0);
	}
      else if(index == 2)
	{
	  m_ui.etpEncryptionKey->setText
	    (spoton_crypt::
	     strongRandomBytes(static_cast<size_t> (m_ui.etpEncryptionKey->
						    maxLength())).
	     toBase64());
	  m_ui.etpEncryptionKey->setCursorPosition(0);
	}
      else if(index == 3)
	{
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	     toBase64());
	  m_ui.etpMacKey->setCursorPosition(0);
	}

      disconnect(m_ui.generate,
		 SIGNAL(activated(int)),
		 this,
		 SLOT(slotGenerateEtpKeys(int)));
      m_ui.generate->setCurrentIndex(0);
      connect(m_ui.generate,
	      SIGNAL(activated(int)),
	      this,
	      SLOT(slotGenerateEtpKeys(int)));
    }
}

void spoton::slotGenerateNova(void)
{
  auto const nova
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())) +
     spoton_crypt::
     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));

  m_ui.transmitNova->setText(nova.toBase64());
  m_ui.transmitNova->setCursorPosition(0);
}

void spoton::slotImpersonate(bool state)
{
  m_settings["gui/impersonate"] = state;

  QSettings settings;

  settings.setValue("gui/impersonate", state);
}

void spoton::slotImportNeighbors(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select Neighbors Import File").arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();

      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(),
		       dialog.selectedFiles().value(0));

      if(fileInfo.size() >= 32768)
	{
	  QMessageBox mb(this);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText
	    (tr("The import file %1 contains a lot (%2) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.absoluteFilePath()).
	     arg(fileInfo.size()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return;
	    }

	  QApplication::processEvents();
	}

      importNeighbors(fileInfo.filePath());
    }

  QApplication::processEvents();
}

void spoton::slotImportPublicKeys(void)
{
  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select Public Keys Import File").arg(SPOTON_APPLICATION_NAME));

  int imported = 0;
  int notimported = 0;

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();

      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(), dialog.selectedFiles().value(0));

      if(fileInfo.size() >= 32768)
	{
	  QMessageBox mb(this);

	  mb.setIcon(QMessageBox::Question);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText
	    (tr("The import file %1 contains a lot (%2) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.absoluteFilePath()).
	     arg(fileInfo.size()));
	  mb.setWindowIcon(windowIcon());
	  mb.setWindowModality(Qt::ApplicationModal);
	  mb.setWindowTitle
	    (tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

	  if(mb.exec() != QMessageBox::Yes)
	    {
	      QApplication::processEvents();
	      return;
	    }

	  QApplication::processEvents();
	}

      QByteArray bytes;
      QFile file;

      file.setFileName(fileInfo.filePath());

      if(file.open(QIODevice::ReadOnly | QIODevice::Text))
	bytes = file.readAll();

      file.close();

      auto const list(bytes.split('\n'));

      for(int i = 0; i < list.size(); i++)
	{
	  QByteArray bytes(list.at(i).trimmed());

	  if(bytes.isEmpty())
	    continue;

	  if(addFriendsKey(bytes, "K", this))
	    imported += 1;
	  else
	    notimported += 1;
	}

      QMessageBox::information
	(this,
	 tr("%1: Information").arg(SPOTON_APPLICATION_NAME),
	 tr("A total of %1 key pair(s) were imported and %2 key pair(s) "
	    "were not imported.").arg(imported).arg(notimported));
      QApplication::processEvents();
    }

  QApplication::processEvents();
}

void spoton::slotMailRetrievalIntervalChanged(int value)
{
  if(value < 5)
    value = 5;

  m_settings["gui/emailRetrievalInterval"] = value;

  QSettings settings;

  settings.setValue("gui/emailRetrievalInterval", value);
  m_emailRetrievalTimer.setInterval(60 * 1000 * value);
}

void spoton::slotMaxMosaicSize(int value)
{
  m_settings["gui/maxMosaicSize"] = value;

  QSettings settings;

  settings.setValue("gui/maxMosaicSize", value);
}

void spoton::slotPopulateEtpMagnets(void)
{
  if(currentTabName() != "starbeam")
    return;

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_magnetsLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_magnetsLastModificationTime)
	    m_magnetsLastModificationTime = fileInfo.lastModified().
	      addMSecs(1);
	  else
	    m_magnetsLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_magnetsLastModificationTime = QDateTime();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QStringList checked;
	auto focusWidget = QApplication::focusWidget();
	int totalRows = 0;

	for(int i = 0; i < m_ui.addTransmittedMagnets->rowCount(); i++)
	  {
	    auto checkBox = qobject_cast<QCheckBox *>
	      (m_ui.addTransmittedMagnets->cellWidget(i, 0));

	    if(checkBox && checkBox->isChecked())
	      checked.append(checkBox->text());
	  }

	m_ui.addTransmittedMagnets->setRowCount(0);
	m_ui.addTransmittedMagnets->setSortingEnabled(false);
	m_ui.addTransmittedMagnets->setUpdatesEnabled(false);
	m_ui.etpMagnets->setRowCount(0);
	m_ui.etpMagnets->setSortingEnabled(false);
	m_ui.etpMagnets->setUpdatesEnabled(false);
	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM magnets"))
	  if(query.next())
	    {
	      m_ui.addTransmittedMagnets->setRowCount(query.value(0).toInt());
	      m_ui.etpMagnets->setRowCount(query.value(0).toInt());
	    }

	if(query.exec("SELECT magnet, "   // 0
		      "one_time_magnet, " // 1
		      "origin, "          // 2
		      "OID "              // 3
		      "FROM magnets"))
	  {
	    int row = 0;

	    while(query.next() &&
		  totalRows < m_ui.addTransmittedMagnets->rowCount())
	      {
		totalRows += 1;

		QByteArray bytes;
		QByteArray origin;
		auto ok = true;

		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

		QTableWidgetItem *item = nullptr;
		auto checkBox = new QCheckBox();

		if(ok)
		  {
		    item = new QTableWidgetItem(QString(bytes));
		    item->setToolTip("<html>" + item->text() + "</html>");
		  }
		else
		  item = new QTableWidgetItem(tr("error"));

		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setItem(row, 2, item);
		origin = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()), &ok);

		if(ok)
		  {
		    item = new QTableWidgetItem(QString(origin));
		    item->setToolTip("<html>" + item->text() + "</html>");
		  }
		else
		  item = new QTableWidgetItem(tr("error"));

		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setItem(row, 1, item);
		checkBox->setChecked(query.value(1).toLongLong());
		checkBox->setProperty
		  ("oid", query.value(query.record().count() - 1));
		connect(checkBox,
			SIGNAL(toggled(bool)),
			this,
			SLOT(slotStarOTMCheckChange(bool)));
		m_ui.etpMagnets->setCellWidget(row, 0, checkBox);
		checkBox = new QCheckBox();

		if(ok)
		  checkBox->setText(bytes.replace("&", "&&"));
		else
		  checkBox->setText(tr("error"));

		if(checked.contains(checkBox->text()))
		  checkBox->setChecked(true);

		m_ui.addTransmittedMagnets->setCellWidget(row, 0, checkBox);
		item = new QTableWidgetItem
		  (query.value(query.record().count() - 1).toString());
		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setItem(row, 3, item);
		m_ui.addTransmittedMagnets->setItem(row, 1, item->clone());
		row += 1;
	      }
	  }

	m_ui.addTransmittedMagnets->setRowCount(totalRows);
	m_ui.addTransmittedMagnets->setSortingEnabled(true);
	m_ui.addTransmittedMagnets->setUpdatesEnabled(true);
	m_ui.etpMagnets->setRowCount(totalRows);
	m_ui.etpMagnets->setSortingEnabled(true);
	m_ui.etpMagnets->setUpdatesEnabled(true);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotPopulateStars(void)
{
  if(currentTabName() != "starbeam")
    if(m_chatWindows.size() == 0)
      return;

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_starsLastModificationTime)
	{
	  if(fileInfo.lastModified() == m_starsLastModificationTime)
	    m_starsLastModificationTime = fileInfo.lastModified().addMSecs(1);
	  else
	    m_starsLastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_starsLastModificationTime = QDateTime();

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QLocale locale;
	QModelIndexList list;
	QSqlQuery query(db);
	QString mosaic("");
	QString selectedFileName("");
	auto focusWidget = QApplication::focusWidget();
	int hval = 0;
	int rRow = -1;
	int row = -1;
	int tRow = -1;
	int totalRows = 0;
	int vval = 0;

	disconnect(m_ui.received,
		   SIGNAL(itemChanged(QTableWidgetItem *)),
		   this,
		   SLOT(slotReceiversChanged(QTableWidgetItem *)));
	m_starbeamReceivedModel->removeRows
	  (0, m_starbeamReceivedModel->rowCount());
	query.setForwardOnly(true);

	/*
	** First, received.
	*/

	list = m_ui.received->selectionModel()->selectedRows(4); // File

	if(!list.isEmpty())
	  selectedFileName = list.at(0).data().toString();

	hval = m_ui.received->horizontalScrollBar()->value();
	vval = m_ui.received->verticalScrollBar()->value();
	m_ui.received->setRowCount(0);
	m_ui.received->setSortingEnabled(false);
	m_ui.received->setUpdatesEnabled(false);
	row = 0;

	if(query.exec("SELECT COUNT(*) FROM received"))
	  if(query.next())
	    {
	      m_starbeamReceivedModel->setRowCount(query.value(0).toInt());
	      m_ui.received->setRowCount(query.value(0).toInt());
	    }

	query.prepare("SELECT locked, "          // 0
		      "pulse_size, "             // 1
		      "total_size, "             // 2
		      "file, "                   // 3
		      "hash, "                   // 4
		      "expected_file_hash, "     // 5
		      "sha3_512_hash, "          // 6
		      "expected_sha3_512_hash, " // 7
		      "estimated_time_arrival, " // 8
		      "OID "                     // 9
		      "FROM received");

	if(query.exec())
	  while(query.next() && totalRows < m_ui.received->rowCount())
	    {
	      totalRows += 1;

	      QByteArray expectedFileHash;
	      QByteArray expectedSha3512FileHash;
	      QByteArray hash;
	      QByteArray sha3512Hash;
	      QCheckBox *check = nullptr;
	      QString fileName("");
	      auto ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = nullptr;

		  if(i == 0)
		    {
		      item = new spoton_table_widget_item();
		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable |
				     Qt::ItemIsUserCheckable);

		      if(query.value(i).toBool())
			item->setCheckState(Qt::Checked);
		      else
			item->setCheckState(Qt::Unchecked);
		    }
		  else if(i >= 1 && i <= 8)
		    {
		      QByteArray bytes;

		      if(!query.isNull(i))
			bytes = crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(i).
						  toByteArray()),
			   &ok);

		      if(ok)
			{
			  switch(i)
			    {
			    case 1:
			    case 2:
			      {
				item = new spoton_table_widget_item
				  (QString(bytes));
				break;
			      }
			    case 3:
			      {
				item = new QTableWidgetItem
				  (QString::fromUtf8(bytes.constData(),
						     bytes.length()));
				break;
			      }
			    default:
			      {
				item = new QTableWidgetItem(QString(bytes));
				break;
			      }
			    }
			}
		      else
			item = new QTableWidgetItem(tr("error"));

		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

		      switch(i)
			{
			case 3:
			  {
			    fileName = item->text();

			    auto sItem = new QStandardItem(fileName);

			    sItem->setEditable(false);
			    m_starbeamReceivedModel->setItem(row, 1, sItem);
			    break;
			  }
			case 4:
			  {
			    hash = bytes;
			    break;
			  }
			case 5:
			  {
			    expectedFileHash = bytes;
			    break;
			  }
			case 6:
			  {
			    expectedSha3512FileHash = bytes;
			    break;
			  }
			case 7:
			  {
			    sha3512Hash = bytes;
			    break;
			  }
			default:
			  {
			    break;
			  }
			}
		    }
		  else
		    {
		      item = new QTableWidgetItem(query.value(i).toString());
		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		    }

		  if(item)
		    {
		      if(i == 0)
			m_ui.received->setItem(row, i, item);
		      else
			m_ui.received->setItem(row, i + 1, item);
		    }
		}

	      if(check)
		check->setProperty("filename", fileName);

	      auto item1 = m_ui.received->item(row, 3);
	      auto item2 = m_ui.received->item(row, 4);

	      if(item1 && item2)
		{
		  QFileInfo const fileInfo(item2->text());
		  auto const fileSize = item1->text().toLongLong();

		  if(fileInfo.size() < fileSize)
		    {
		      QLinearGradient linearGradient
			(0,
			 m_ui.received->rowHeight(row),
			 m_ui.received->columnWidth(1),
			 m_ui.received->rowHeight(row));
		      auto const percent = 100.0 *
			qAbs(static_cast<double> (fileInfo.size()) /
			     static_cast<double> (qMax(1LL, fileSize)));
		      auto i = new QTableWidgetItem();

		      linearGradient.setColorAt(percent / 100.0,
						QColor("lightgreen"));
		      linearGradient.setColorAt(percent / 100.0 + 0.05,
						QColor("white"));

		      QBrush brush(linearGradient);

		      i->setBackground(brush);
		      i->setText
			(tr("%1% - %2 of %3 Bytes").
			 arg(percent, 0, 'f', 2).
			 arg(locale.toString(fileInfo.size())).
			 arg(locale.toString(item1->text().toLongLong())));
		      i->setToolTip
			(tr("%1% - %2 (%3 Bytes)").
			 arg(percent, 0, 'f', 2).
			 arg(fileInfo.fileName()).
			 arg(locale.toString(fileInfo.size())));
		      m_ui.received->setItem(row, 1, i);

		      auto sItem = new QStandardItem
			(QString("%1%").arg(percent, 0, 'f', 2));

		      sItem->setEditable(false);
		      m_starbeamReceivedModel->setItem(row, 0, sItem);
		    }
		  else
		    {
		      auto sItem = new QStandardItem(tr("100.0%"));

		      sItem->setEditable(false);
		      m_starbeamReceivedModel->setItem(row, 0, sItem);

		      auto item = new QTableWidgetItem(tr("100.0%"));

		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.received->setItem(row, 1, item);

		      if(m_settings.value("gui/starbeamAutoVerify",
					  false).toBool())
			if(hash.isEmpty())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
			  m_starbeamDigestFutures.append
			    (QtConcurrent::run(&spoton::computeFileDigests,
					       this,
					       fileName,
					       query.
					       value(query.record().
						     count() - 1).toString(),
					       crypt));
#else
			  m_starbeamDigestFutures.append
			    (QtConcurrent::run(this,
					       &spoton::computeFileDigests,
					       fileName,
					       query.
					       value(query.record().
						     count() - 1).toString(),
					       crypt));
#endif
		    }
		}

	      auto item3 = m_starbeamReceivedModel->item(row, 0);
	      auto item4 = m_ui.received->item(row, 5);

	      if(item3 && item4)
		{
		  if(!hash.isEmpty() && spoton_crypt::memcmp(expectedFileHash,
							     hash))
		    {
		      item3->setBackground(QBrush(QColor("lightgreen")));
		      item3->setToolTip(tr("<html>The computed file digest "
					   "is identical to the expected "
					   "file digest.</html>"));
		      item4->setBackground(QBrush(QColor("lightgreen")));
		    }
		  else
		    {
		      item3->setBackground(QBrush(QColor(240, 128, 128)));
		      item3->setToolTip(tr("<html>The computed file digest "
					   "does not equal the expected "
					   "file digest.</html>"));
		      item4->setBackground(QBrush(QColor(240, 128, 128)));
		    }
		}

	      item4 = m_ui.received->item(row, 7);

	      if(item4)
		{
		  if(!sha3512Hash.isEmpty() &&
		     spoton_crypt::memcmp(expectedSha3512FileHash,
					  sha3512Hash))
		    item4->setBackground(QBrush(QColor("lightgreen")));
		  else
		    item4->setBackground(QBrush(QColor(240, 128, 128)));
		}

	      if(m_ui.received->item(row, 4) &&
		 m_ui.received->item(row, 4)->text() == selectedFileName &&
		 rRow == -1)
		rRow = row;

	      row += 1;
	    }

	m_starbeamReceivedModel->setRowCount(totalRows);
	m_ui.received->horizontalHeader()->setStretchLastSection(true);
	m_ui.received->horizontalScrollBar()->setValue(hval);
	m_ui.received->selectRow(rRow);
	m_ui.received->setRowCount(totalRows);
	m_ui.received->setSortingEnabled(true);
	m_ui.received->setUpdatesEnabled(true);
	m_ui.received->verticalScrollBar()->setValue(vval);
	connect(m_ui.received,
		SIGNAL(itemChanged(QTableWidgetItem *)),
		this,
		SLOT(slotReceiversChanged(QTableWidgetItem *)));

	for(int i = 0; i < m_ui.received->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.received->resizeColumnToContents(i);

	if(currentTabName() != "starbeam")
	  {
	    db.close();

	    if(focusWidget)
	      focusWidget->setFocus();

	    goto done_label;
	  }

	/*
	** Second, transmitted.
	*/

	list = m_ui.transmitted->selectionModel()->selectedRows
	  (6); // Mosaic

	if(!list.isEmpty())
	  mosaic = list.at(0).data().toString();

	disconnect(m_ui.transmitted,
		   SIGNAL(itemSelectionChanged(void)),
		   this,
		   SLOT(slotTransmittedSelected(void)));
	hval = m_ui.transmitted->horizontalScrollBar()->value();
	vval = m_ui.transmitted->verticalScrollBar()->value();
	m_ui.transmitted->setRowCount(0);
	m_ui.transmitted->setSortingEnabled(false);
	m_ui.transmitted->setUpdatesEnabled(false);
	row = 0;
	totalRows = 0;

	if(query.exec("SELECT COUNT(*) FROM transmitted "
		      "WHERE status_control <> 'deleted'"))
	  if(query.next())
	    m_ui.transmitted->setRowCount(query.value(0).toInt());

	query.prepare("SELECT 0, "               // 0
		      "position, "               // 1
		      "pulse_size, "             // 2
		      "total_size, "             // 3
		      "status_control, "         // 4
		      "file, "                   // 5
		      "mosaic, "                 // 6
		      "hash, "                   // 7
		      "read_interval, "          // 8
		      "fragmented, "             // 9
		      "sha3_512_hash, "          // 10
		      "estimated_time_arrival, " // 11
		      "OID "                     // 12
		      "FROM transmitted "
		      "WHERE status_control <> 'deleted'");

	if(query.exec())
	  while(query.next() && totalRows < m_ui.transmitted->rowCount())
	    {
	      totalRows += 1;

	      QString fileName("");
	      auto checkBox = new QCheckBox();
	      auto ok = true;
	      qint64 position = 0;

	      checkBox->setChecked(true);
	      checkBox->setProperty
		("oid", query.value(query.record().count() - 1));
	      m_ui.transmitted->setCellWidget(row, 0, checkBox);

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = nullptr;

		  if(i == 0)
		    {
		    }
		  else if(i == 1)
		    position = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(i).toByteArray()),
		       &ok).toLongLong();
		  else if(i == 2 ||
			  i == 3 ||
			  i == 5 ||
			  i == 7 ||
			  i == 10 ||
			  i == 11)
		    {
		      QByteArray bytes;

		      if(!query.isNull(i))
			bytes = crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(i).
						  toByteArray()), &ok);

		      if(ok)
			{
			  switch(i)
			    {
			    case 2:
			    case 3:
			      {
				item = new spoton_table_widget_item
				  (QString(bytes));
				break;
			      }
			    case 5:
			      {
				fileName = QString::fromUtf8
				  (bytes.constData(), bytes.length());
				item = new QTableWidgetItem(fileName);
				break;
			      }
			    default:
			      {
				item = new QTableWidgetItem(QString(bytes));
				break;
			      }
			    }
			}
		      else
			{
			  if(i == 5)
			    fileName = tr("error");

			  item = new QTableWidgetItem(tr("error"));
			}
		    }
		  else if(i == 4)
		    {
		      item = new QTableWidgetItem
			(query.value(i).toString().toLower());

		      if(item->text() != "paused")
			checkBox->setChecked(false);

		      if(item->text() == "transmitting")
			item->setBackground
			  (QBrush(QColor("lightgreen")));
		      else
			item->setBackground(QBrush());
		    }
		  else if(i == 6)
		    {
		      auto bytes(query.value(i).toByteArray());

		      bytes = bytes.mid(0, 16) + "..." + bytes.right(16);
		      item = new QTableWidgetItem(QString(bytes));
		    }
		  else if(i == 8 || i == query.record().count() - 1)
		    item = new QTableWidgetItem(query.value(i).toString());
		  else if(i == 9)
		    {
		      auto checkBox = new QCheckBox();

		      if(query.value(i).toBool())
			checkBox->setChecked(true);
		      else
			checkBox->setChecked(false);

		      checkBox->setProperty
			("oid", query.value(query.record().count() - 1));
		      connect(checkBox,
			      SIGNAL(toggled(bool)),
			      this,
			      SLOT(slotStarBeamFragmented(bool)));
		      m_ui.transmitted->setCellWidget(row, i, checkBox);
		    }

		  if(item)
		    {
		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.transmitted->setItem(row, i, item);
		    }
		}

	      auto item = m_ui.transmitted->item(row, 3);

	      if(item)
		{
		  auto const percent = 100.0 *
		    qAbs(static_cast<double> (position) /
			 static_cast<double> (qMax(static_cast<long long int>
						   (1),
						   item->text().
						   toLongLong())));

		  if(percent < 100.0)
		    {
		      QLinearGradient linearGradient
			(0,
			 m_ui.transmitted->rowHeight(row),
			 m_ui.transmitted->columnWidth(1),
			 m_ui.transmitted->rowHeight(row));
		      auto i = new QTableWidgetItem();

		      linearGradient.setColorAt(percent / 100.0,
						QColor("lightgreen"));
		      linearGradient.setColorAt(percent / 100.0 + 0.05,
						QColor("white"));

		      QBrush brush(linearGradient);

		      i->setBackground(brush);
		      i->setText
			(tr("%1% - %2 of %3 Bytes").
			 arg(percent, 0, 'f', 2).
			 arg(locale.toString(position)).
			 arg(locale.toString(item->text().toLongLong())));
		      i->setToolTip
			(tr("%1% - %2 (%3 Bytes)").
			 arg(percent, 0, 'f', 2).
			 arg(QFileInfo(fileName).fileName()).
			 arg(locale.toString(position)));
		      m_ui.transmitted->setItem(row, 1, i);
		    }
		  else
		    {
		      auto item = new QTableWidgetItem(tr("100.0%"));

		      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.transmitted->setItem(row, 1, item);
		    }
		}

	      connect(checkBox,
		      SIGNAL(toggled(bool)),
		      this,
		      SLOT(slotTransmittedPaused(bool)));

	      if(m_ui.transmitted->item(row, 6) &&
		 m_ui.transmitted->item(row, 6)->text() == mosaic &&
		 tRow == -1)
		tRow = row;

	      for(int i = 0; i < m_ui.transmitted->columnCount(); i++)
		if(i != 1 && m_ui.transmitted->item(row, i))
		  m_ui.transmitted->item(row, i)->setToolTip(fileName);

	      row += 1;
	    }

	m_ui.transmitted->horizontalHeader()->setStretchLastSection(true);
	m_ui.transmitted->horizontalScrollBar()->setValue(hval);
	m_ui.transmitted->selectRow(tRow);
	m_ui.transmitted->setRowCount(totalRows);
	m_ui.transmitted->setSortingEnabled(true);
	m_ui.transmitted->setUpdatesEnabled(true);
	m_ui.transmitted->verticalScrollBar()->setValue(vval);
	connect(m_ui.transmitted,
		SIGNAL(itemSelectionChanged(void)),
		this,
		SLOT(slotTransmittedSelected(void)));

	for(int i = 0; i < m_ui.transmitted->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.transmitted->resizeColumnToContents(i);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

 done_label:
  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotReceiversClicked(bool state)
{
  /*
  ** Obsolete!
  */

  Q_UNUSED(state);
}

void spoton::slotRegenerateKey(void)
{
  QString keyType("chat");

  if(m_ui.keys->currentText() == "Chat")
    keyType = "chat";
  else if(m_ui.keys->currentText() == "E-Mail")
    keyType = "email";
  else if(m_ui.keys->currentText() == "Open Library")
    keyType = "open-library";
  else if(m_ui.keys->currentText() == "Poptastic")
    keyType = "poptastic";
  else if(m_ui.keys->currentText() == "Rosetta")
    keyType = "rosetta";
  else if(m_ui.keys->currentText() == "URL")
    keyType = "url";

  auto crypt1 = m_crypts.value(keyType, nullptr);
  auto crypt2 = m_crypts.value(QString("%1-signature").arg(keyType), nullptr);

  if(!crypt1 || !crypt2)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object(s). This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);

  if(keyType == "chat")
    mb.setText(tr("Are you sure that you wish to generate the selected "
		  "key pair? StarBeam digest computations will be "
		  "interrupted. The kernel will also be deactivated."));
  else
    mb.setText(tr("Are you sure that you wish to generate the selected "
		  "key pair? The kernel will be deactivated."));

  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  if(m_ui.encryptionKeyType->currentIndex() == 1)
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("McEliece key pairs require a significant amount of "
		    "storage memory. As %1 prefers secure memory, "
		    "the gcrypt library may fail if it's unable to "
		    "reserve the required amount of memory. Some "
		    "operating systems require configuration in order "
		    "to support large amounts of locked memory. "
		    "You may disable secure memory by setting the "
		    "secure memory pools of the interface and the kernel "
		    "to zero. Continue with the key-generation process?").
		 arg(SPOTON_APPLICATION_NAME));
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

  repaint();
  QApplication::processEvents();

  if(keyType == "chat")
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_generalFuture.cancel();
      m_generalFuture.waitForFinished();
      m_starbeamDigestInterrupt.fetchAndStoreOrdered(1);

      for(int i = 0; i < m_starbeamDigestFutures.size(); i++)
	{
	  auto future(m_starbeamDigestFutures.at(i));

	  future.cancel();
	  future.waitForFinished();
	}

      m_starbeamDigestFutures.clear();
      QApplication::restoreOverrideCursor();
    }

  slotDeactivateKernel();

  QString encryptionKeyType("");
  QString signatureKeyType("");

  if(m_ui.encryptionKeyType->currentIndex() == 0)
    encryptionKeyType = "elg";
  else if(m_ui.encryptionKeyType->currentIndex() == 1)
    encryptionKeyType = "mceliece";
  else if(m_ui.encryptionKeyType->currentIndex() == 2)
    encryptionKeyType = "ntru";
  else
    encryptionKeyType = "rsa";

  if(m_ui.signatureKeyType->currentIndex() == 0)
    signatureKeyType = "dsa";
  else if(m_ui.signatureKeyType->currentIndex() == 1)
    signatureKeyType = "ecdsa";
  else if(m_ui.signatureKeyType->currentIndex() == 2)
    signatureKeyType = "eddsa";
  else if(m_ui.signatureKeyType->currentIndex() == 3)
    signatureKeyType = "elg";
  else
    signatureKeyType = "rsa";

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Generating public key pairs."));
  m_sb.status->repaint();

  QString error("");

  crypt1->generatePrivatePublicKeys
    (m_ui.encryptionKeySize->currentText(),
     encryptionKeyType,
     error);

  if(error.isEmpty())
    crypt2->generatePrivatePublicKeys
      (m_ui.signatureKeySize->currentText(),
       signatureKeyType,
       error);

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
  updatePublicKeysLabel();

  if(!error.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "generatePrivatePublicKeys().").
			    arg(error.trimmed()));
      QApplication::processEvents();
    }
}

void spoton::slotRemoveUrlParticipants(void)
{
  if(!m_ui.urlParticipants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"URLs participant(s)?"));
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
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto const list
	  (m_ui.urlParticipants->selectionModel()->
	   selectedRows(1)); // OID

	for(int i = 0; i < list.size(); i++)
	  {
	    auto const data(list.at(i).data());

	    if(!data.isNull() && data.isValid())
	      {
		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());

		if(query.exec())
		  emit participantDeleted(data.toString(), "url");
	      }
	  }

	spoton_misc::purgeSignatureRelationships
	  (db, m_crypts.value("chat", nullptr));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotRenameParticipant(void)
{
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  auto const type(action->property("type").toString().toLower());

  if(!(type == "chat" ||
       type == "email" ||
       type == "poptastic" ||
       type == "url"))
    return;

  QModelIndexList list;
  auto const tabName(currentTabName());

  if(tabName == "chat")
    if(type == "chat" || type == "poptastic")
      list = m_ui.participants->selectionModel()->selectedRows(1); // OID

  if(tabName == "email")
    if(type == "email" || type == "poptastic")
      list = m_ui.emailParticipants->selectionModel()->selectedRows(1); // OID

  if(type == "url")
    list = m_ui.urlParticipants->selectionModel()->selectedRows(1); // OID

  if(list.isEmpty())
    return;

  auto const data(list.value(0).data());

  if(tabName == "chat")
    if(type == "chat" || type == "poptastic")
      list = m_ui.participants->selectionModel()->selectedRows(0); // Name

  if(tabName == "email")
    if(type == "email" || type == "poptastic")
      list = m_ui.emailParticipants->selectionModel()->selectedRows(0); // Name

  if(type == "url")
    list = m_ui.urlParticipants->selectionModel()->selectedRows(0); // Name

  QString name("");
  auto ok = true;

  name = QInputDialog::getText
    (this,
     tr("%1: New Name").arg(SPOTON_APPLICATION_NAME),
     tr("&Name"),
     QLineEdit::Normal,
     list.value(0).data().toString(),
     &ok).mid(0, spoton_common::NAME_MAXIMUM_LENGTH);

  if(name.isEmpty() || ok == false)
    return;

  ok = false;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!data.isNull() && data.isValid())
	  {
	    query.prepare("UPDATE friends_public_keys "
			  "SET name = ?, "
			  "name_changed_by_user = 1 "
			  "WHERE OID = ?");
	    query.addBindValue
	      (crypt->encryptedThenHashed(name.toUtf8(), &ok).toBase64());
	    query.addBindValue(data.toString());

	    if(ok)
	      ok = query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(tabName == "chat")
	{
	  auto item = m_ui.participants->item
	    (list.value(0).row(), 3); // public_key_hash

	  if(item)
	    {
	      auto const publicKeyHash(item->text());

	      if(m_chatWindows.contains(publicKeyHash))
		{
		  auto chat = m_chatWindows.value(publicKeyHash, nullptr);

		  if(chat)
		    chat->setName(name);
		}

	      emit participantNameChanged(publicKeyHash.toLatin1(), name);
	    }
	}
      else if(tabName == "email")
	{
	  auto item = m_ui.emailParticipants->item
	    (list.value(0).row(), 3); // public_key_hash

	  if(item)
	    {
	      auto const publicKeyHash(item->text());

	      emit participantNameChanged(publicKeyHash.toLatin1(), name);
	    }
	}
      else if(tabName == "urls")
	{
	  auto item = m_ui.urlParticipants->item
	    (list.value(0).row(), 3); // public_key_hash

	  if(item)
	    {
	      auto const publicKeyHash(item->text());

	      emit participantNameChanged(publicKeyHash.toLatin1(), name);
	    }
	}
    }
}

void spoton::slotResetCertificate(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  auto const list
    (m_ui.neighbors->selectionModel()->
     selectedRows(m_ui.neighbors->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.prepare("UPDATE neighbors SET "
		      "certificate = ? "
		      "WHERE OID = ? AND "
		      "user_defined = 1");
	query.addBindValue
	  (crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());
	query.addBindValue(list.at(0).data());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotRewindFile(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      auto item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	for(int i = 1; i <= 10; i++)
	  {
	    query.prepare
	      ("UPDATE transmitted SET "
	       "estimated_time_arrival = NULL, "
	       "position = ?, "
	       "status_control = 'paused' "
	       "WHERE OID = ? AND status_control <> 'deleted'");
	    query.addBindValue
	      (crypt->
	       encryptedThenHashed(QByteArray::number(0), &ok).toBase64());
	    query.addBindValue(oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotSaveDestination(void)
{
  saveDestination(m_ui.destination->text());
}

void spoton::slotSaveUrlName(void)
{
  auto str(m_ui.urlName->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      m_ui.urlName->setText(str);
    }
  else
    m_ui.urlName->setText(str.trimmed());

  m_ui.urlName->setCursorPosition(0);
  m_settings["gui/urlName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/urlName", str.toUtf8());
  m_ui.urlName->selectAll();
}

void spoton::slotSecureMemoryPoolChanged(int value)
{
  QSettings settings;

  if(m_optionsUi.guiSecureMemoryPool == sender())
    {
      m_settings["gui/gcryctl_init_secmem"] = value;
      settings.setValue("gui/gcryctl_init_secmem", value);
    }
  else
    {
      m_settings["kernel/gcryctl_init_secmem"] = value;
      settings.setValue("kernel/gcryctl_init_secmem", value);
    }
}

void spoton::slotSelectDestination(void)
{
  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory(QDir::homePath());
  dialog.setFileMode(QFileDialog::Directory);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select StarBeam Destination Directory").
     arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      saveDestination(dialog.selectedFiles().value(0));
    }

  QApplication::processEvents();
}

void spoton::slotSelectTransmitFile(void)
{
  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory(QDir::homePath());
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Select StarBeam Transmit File").arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      m_ui.transmittedFile->setText(dialog.selectedFiles().value(0));
      m_ui.transmittedFile->setCursorPosition(0);
    }

  QApplication::processEvents();
}

void spoton::slotShareBuzzMagnet(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_kernelSocket.isEncrypted() == false &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString oid("");
  auto const data(action->data().toByteArray());
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray message;

  message.append("sharebuzzmagnet_");
  message.append(oid.toUtf8());
  message.append("_");
  message.append(data.toBase64());
  message.append("\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::slotShareBuzzMagnet(): write() failure "
	       "for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotShowEtpMagnetsMenu(const QPoint &point)
{
  if(m_ui.etpMagnets == sender())
    {
      QMenu menu(this);

      menu.addAction(tr("Copy &Magnet"),
		     this,
		     SLOT(slotCopyEtpMagnet(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this,
		     SLOT(slotDeleteEtpMagnet(void)));
      menu.addAction(tr("Delete &All"),
		     this,
		     SLOT(slotDeleteEtpAllMagnets(void)));
      menu.exec(m_ui.etpMagnets->mapToGlobal(point));
    }
}

void spoton::slotShowStatistics(void)
{
  m_ui.statisticsBox->setVisible(!m_ui.statisticsBox->isVisible());
}

void spoton::slotStarOTMCheckChange(bool state)
{
  auto checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE magnets SET "
			  "one_time_magnet = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, state ? 1 : 0);
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotStatisticsGathered(void)
{
  populateStatistics(m_statisticsFuture.result());
}

void spoton::slotTransmit(void)
{
  /*
  ** We must have at least one magnet selected.
  */

  QByteArray encryptedMosaic;
  QFileInfo fileInfo;
  QList<QByteArray> magnets;
  QString connectionName("");
  QString error("");
  auto crypt = m_crypts.value("chat", nullptr);
  auto ok = true;
  auto zero = true;

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(!m_ui.transmitNova->text().isEmpty())
    if(m_ui.transmitNova->text().length() < 48)
      {
	error = tr("Please provide a nova that contains at least "
		   "forty-eight characters.");
	goto done_label;
      }

  if(m_ui.transmittedFile->text().isEmpty())
    {
      error = tr("Please select a file to transfer.");
      goto done_label;
    }

  fileInfo.setFile(m_ui.transmittedFile->text());

  if(!fileInfo.exists() || !fileInfo.isReadable())
    {
      error = tr("The provided file cannot be accessed.");
      goto done_label;
    }

  for(int i = 0; i < m_ui.addTransmittedMagnets->rowCount(); i++)
    {
      auto checkBox = qobject_cast<QCheckBox *>
	(m_ui.addTransmittedMagnets->cellWidget(i, 0));

      if(checkBox)
	if(checkBox->isChecked())
	  {
	    zero = false;
	    magnets << checkBox->text().replace("&&", "&").toLatin1();
	  }
    }

  if(zero)
    {
      error = tr("Please select at least one magnet.");
      goto done_label;
    }

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	auto const nova(m_ui.transmitNova->text().toLatin1());

	if(!nova.isEmpty())
	  {
	    QSqlQuery query(db);

	    query.prepare
	      ("INSERT OR REPLACE INTO received_novas "
	       "(nova, nova_hash) VALUES (?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(nova, &ok).toBase64());

	    if(ok)
	      query.bindValue(1, crypt->keyedHash(nova, &ok).toBase64());

	    if(ok)
	      ok = query.exec();

	    if(query.lastError().isValid())
	      error = query.lastError().text();

	    if(!error.isEmpty() || !ok)
	      {
		db.close();
		QApplication::restoreOverrideCursor();
		goto done_label;
	      }
	  }

	QSqlQuery query(db);
	auto const mosaic
	  (spoton_crypt::strongRandomBytes(spoton_common::MOSAIC_SIZE).
	   toBase64());

	query.prepare("INSERT INTO transmitted "
		      "(file, fragmented, "
		      "hash, mosaic, nova, "
		      "position, pulse_size, "
		      "sha3_512_hash, "
		      "status_control, total_size, ultra) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.addBindValue
	  (crypt->encryptedThenHashed(m_ui.transmittedFile->text().toUtf8(),
				      &ok).toBase64());
	query.addBindValue
	  (m_ui.fragment_starbeam->isChecked() ? 1 : 0);

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(spoton_crypt::
				 sha1FileHash(m_ui.transmittedFile->text()).
				 toHex(), &ok).toBase64());

	if(ok)
	  {
	    encryptedMosaic = crypt->encryptedThenHashed(mosaic, &ok);

	    if(ok)
	      query.addBindValue(encryptedMosaic.toBase64());
	  }

	if(ok)
	  query.addBindValue
	    (crypt->encryptedThenHashed(nova, &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->encryptedThenHashed("0", &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::number(m_ui.pulseSize->value()),
				 &ok).toBase64());
	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(spoton_crypt::
				 sha3_512FileHash(m_ui.transmittedFile->
						  text()).
				 toHex(), &ok).toBase64());

	query.addBindValue("paused");

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::number(fileInfo.size()),
				 &ok).toBase64());

	query.addBindValue(1);

	if(ok)
	  ok = query.exec();

	if(query.lastError().isValid())
	  error = query.lastError().text();

	if(!error.isEmpty() || !ok)
	  {
	    db.close();
	    QApplication::restoreOverrideCursor();
	    goto done_label;
	  }

	for(int i = 0; i < magnets.size(); i++)
	  {
	    query.prepare("INSERT INTO transmitted_magnets "
			  "(magnet, magnet_hash, transmitted_oid) "
			  "VALUES (?, ?, (SELECT OID FROM transmitted WHERE "
			  "mosaic = ?))");

	    if(ok)
	      query.addBindValue
		(crypt->encryptedThenHashed(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(crypt->keyedHash(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.addBindValue(encryptedMosaic.toBase64());

	    if(ok)
	      ok = query.exec();

	    if(query.lastError().isValid())
	      error = query.lastError().text();

	    if(!error.isEmpty() || !ok)
	      break;

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM magnets WHERE "
			  "magnet_hash = ? and one_time_magnet = 1");
	    query.addBindValue
	      (crypt->keyedHash(magnets.at(i), nullptr).toBase64());

	    /*
	    ** It's fine if this query fails.
	    */

	    query.exec();
	  }

	QApplication::restoreOverrideCursor();
      }

    if(db.lastError().isValid())
      error = tr("A database error (%1) occurred.").arg(db.lastError().text());
    else if(!error.isEmpty())
      error = tr("A database error (%1) occurred.").arg(error);
    else if(!ok)
      error = tr("An error occurred within spoton_crypt.");

    db.close();
  }

 done_label:

  if(!connectionName.isEmpty())
    QSqlDatabase::removeDatabase(connectionName);

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    {
      m_ui.fragment_starbeam->setChecked(false);
      m_ui.pulseSize->setValue(15000);
      m_ui.transmitNova->clear();
      m_ui.transmittedFile->clear();
      populateNovas();
    }
}

void spoton::slotTransmittedPaused(bool state)
{
  auto checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE transmitted SET "
			  "estimated_time_arrival = NULL, "
			  "status_control = ? "
			  "WHERE OID = ? AND status_control <> 'deleted'");
	    query.bindValue(0, state ? "paused" : "transmitting");
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotTransmittedSelected(void)
{
  auto crypt = m_crypts.value("chat", nullptr);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      auto item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	m_ui.transmittedMagnets->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT magnet FROM transmitted_magnets "
		      "WHERE transmitted_oid = ? "
		      "AND transmitted_oid IN (SELECT OID FROM "
		      "transmitted WHERE status_control <> 'deleted' AND "
		      "OID = ?)");
	query.bindValue(0, oid);
	query.bindValue(1, oid);

	if(query.exec())
	  {
	    QStringList magnets;

	    while(query.next())
	      {
		QString magnet("");
		auto ok = true;

		magnet = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok);

		if(!magnet.isEmpty())
		  magnets.append(magnet);
	      }

	    std::sort(magnets.begin(), magnets.end());

	    for(int i = 0; i < magnets.size(); i++)
	      {
		auto item = new QListWidgetItem(magnets.at(i));

		item->setToolTip("<html>" + item->text() + "</html>");
		m_ui.transmittedMagnets->addItem(item);
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotTransportChanged(int index)
{
  /*
  ** 0 - Bluetooth
  ** 1 - SCTP
  ** 2 - TCP
  ** 3 - UDP
  ** 4 - WebSocket
  */

  if(m_ui.listenerTransport == sender())
    {
      if(index == 0)
	m_ui.ipv4Listener->setChecked(true);

      prepareListenerIPCombo();
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.days_valid->setEnabled(index == 2 || // TCP
				  index == 3);  // UDP
#else
      m_ui.days_valid->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.days_valid->setEnabled(true);
#else
        m_ui.days_valid->setEnabled(false);
#endif

      m_ui.ipv4Listener->setEnabled(index != 0);
      m_ui.ipv6Listener->setEnabled(index != 0);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.listenerKeySize->setEnabled(index == 2 || // TCP
				       index == 3);  // UDP
#else
      m_ui.listenerKeySize->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.listenerKeySize->setEnabled(true);
#else
        m_ui.listenerKeySize->setEnabled(false);
#endif

#if defined(Q_OS_WINDOWS)
      m_ui.listenerShareAddress->setEnabled(false);
#else
      m_ui.listenerShareAddress->setEnabled(index == 3);
#endif
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.listenersSslControlString->setEnabled(index == 2 || // TCP
						 index == 3);  // UDP
      m_ui.recordIPAddress->setEnabled(index == 2 || // TCP
				       index == 3);  // UDP
#else
      m_ui.listenersSslControlString->setEnabled(index == 2);
      m_ui.recordIPAddress->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	{
	  m_ui.listenersSslControlString->setEnabled(true);
	  m_ui.recordIPAddress->setEnabled(true);
	}
#else
        {
	  m_ui.listenersSslControlString->setEnabled(false);
	  m_ui.recordIPAddress->setEnabled(false);
	}
#endif

      if(m_ui.ipv6Listener->isChecked())
	m_ui.listenerScopeId->setEnabled(index != 0);
      else
	m_ui.listenerScopeId->setEnabled(false);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.sslListener->setEnabled(index == 2 || // TCP
				   index == 3);  // UDP
#else
      m_ui.sslListener->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.sslListener->setEnabled(true);
#else
        m_ui.sslListener->setEnabled(false);
#endif
    }
  else if(m_ui.neighborTransport == sender())
    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.addException->setEnabled(index == 2 || // TCP
				    index == 3);  // UDP
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.addException->setEnabled(true);
#else
        m_ui.addException->setEnabled(false);
#endif

      m_ui.dynamicdns->setEnabled(index != 0);

      if(index == 0)
	m_ui.ipv4Neighbor->setChecked(true);

      m_ui.ipv4Neighbor->setEnabled(index != 0);
      m_ui.ipv6Neighbor->setEnabled(index != 0);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.neighborKeySize->setEnabled(index == 2 || // TCP
				       index == 3);  // UDP
#else
      m_ui.neighborKeySize->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.neighborKeySize->setEnabled(true);
#else
        m_ui.neighborKeySize->setEnabled(false);
#endif

      if(m_ui.ipv6Neighbor->isChecked())
	m_ui.neighborScopeId->setEnabled(index != 0);
      else
	m_ui.neighborScopeId->setEnabled(false);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.neighborsSslControlString->setEnabled(index == 2 || // TCP
						 index == 3);  // UDP
#else
      m_ui.neighborsSslControlString->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	m_ui.neighborsSslControlString->setEnabled(true);
#else
        m_ui.neighborsSslControlString->setEnabled(false);
#endif

      if(index == 0 || index == 1)
	m_ui.proxy->setEnabled(false);
      else
	m_ui.proxy->setEnabled(true);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_ui.requireSsl->setEnabled(index == 2 || // TCP
				  index == 3);  // UDP
      m_ui.sslKeySizeLabel->setEnabled(index == 2 || // TCP
				       index == 3);  // UDP
#else
      m_ui.requireSsl->setEnabled(index == 2);
      m_ui.sslKeySizeLabel->setEnabled(index == 2);
#endif

      if(index == 4) // WebSocket
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	{
	  m_ui.requireSsl->setEnabled(true);
	  m_ui.sslKeySizeLabel->setEnabled(true);
	}
#else
        {
	  m_ui.requireSsl->setEnabled(false);
	  m_ui.sslKeySizeLabel->setEnabled(false);
	}
#endif
    }
}

void spoton::slotViewRosetta(void)
{
  menuBar()->repaint();
  repaint();
  QApplication::processEvents();
  m_rosetta.show(this);
}

void spoton::updatePublicKeysLabel(void)
{
  m_ui.personal_public_keys->setRowCount(0);

  auto list(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
	    spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

  std::sort(list.begin(), list.end());
  m_ui.personal_public_keys->setRowCount(list.size());

  for(int i = 0; i < list.size(); i++)
    {
      auto crypt = m_crypts.value(list.at(i), nullptr);

      if(!crypt)
	continue;

      QByteArray base64;
      QByteArray bytes;
      auto item = new QTableWidgetItem(list.at(i));
      auto ok = true;

      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      m_ui.personal_public_keys->setItem(i, 0, item);
      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      m_ui.personal_public_keys->setItem(i, 1, item);
      item->setText(crypt->publicKeyAlgorithm().trimmed());
      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      item->setText(crypt->publicKeySize());
      m_ui.personal_public_keys->setItem(i, 2, item);
      bytes = crypt->publicKey(&ok);
      bytes = spoton_crypt::preferredHash(bytes);
      base64 = bytes.toBase64();
      bytes = bytes.toHex();
      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

      if(ok)
	item->setText(bytes);

      m_ui.personal_public_keys->setItem(i, 3, item);
      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      item->setText(base64);

      if(!base64.isEmpty())
	item->setToolTip(base64.mid(0, 16) + "..." + base64.right(16));

      m_ui.personal_public_keys->setItem(i, 4, item);
    }

  m_ui.personal_public_keys->resizeColumnToContents(0);
}
