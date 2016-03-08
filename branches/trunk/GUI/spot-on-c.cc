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

#include "spot-on.h"
#include "spot-on-defines.h"

#include <QCheckBox>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#endif
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QStandardItemModel>
#if QT_VERSION >= 0x050000
#include <QStandardPaths>
#endif
#include <QTableWidgetItem>
#include <QThread>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

void spoton::slotGenerateEtpKeys(int index)
{
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
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	     toBase64());
	}
      else if(index == 2)
	m_ui.etpEncryptionKey->setText
	  (spoton_crypt::
	   strongRandomBytes(static_cast<size_t> (m_ui.etpEncryptionKey->
						  maxLength())).
	   toBase64());
      else if(index == 3)
	m_ui.etpMacKey->setText
	  (spoton_crypt::
	   strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	   toBase64());

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

void spoton::slotAddEtpMagnet(const QString &text,
			      const bool displayError)
{
  QString connectionName("");
  QString error("");
  QString magnet("");
  QStringList list;
  bool ok = true;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
	magnet = text;
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
      error = tr("Invalid magnet. Are you missing tokens?");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO "
		      "magnets (magnet, magnet_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, crypt->encryptedThenHashed(magnet.toLatin1(),
						      &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash(magnet.toLatin1(),
					      &ok).toBase64());

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
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME), error);
    }
  else
    askKernelToReadStarBeamKeys();
}

void spoton::slotPopulateEtpMagnets(void)
{
  if(currentTabName() != "starbeam")
    return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "starbeam.db");

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

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QStringList checked;
	QWidget *focusWidget = QApplication::focusWidget();
	int totalRows = 0;

	for(int i = 0; i < m_ui.addTransmittedMagnets->rowCount(); i++)
	  {
	    QCheckBox *checkBox = qobject_cast<QCheckBox *>
	      (m_ui.addTransmittedMagnets->cellWidget(i, 0));

	    if(checkBox && checkBox->isChecked())
	      checked.append(checkBox->text());
	  }

	m_ui.etpMagnet->setUpdatesEnabled(false);
	m_ui.etpMagnets->setSortingEnabled(false);
	m_ui.etpMagnets->clearContents();
	m_ui.etpMagnets->setRowCount(0);
	m_ui.addTransmittedMagnets->setUpdatesEnabled(false);
	m_ui.addTransmittedMagnets->setSortingEnabled(false);
	m_ui.addTransmittedMagnets->clearContents();
	m_ui.addTransmittedMagnets->setRowCount(0);
	query.setForwardOnly(true);
	query.exec("PRAGMA read_uncommitted = True");

	if(query.exec("SELECT COUNT(*) FROM magnets"))
	  if(query.next())
	    {
	      m_ui.addTransmittedMagnets->setRowCount
		(query.value(0).toInt());
	      m_ui.etpMagnets->setRowCount(query.value(0).toInt());
	    }

	if(query.exec("SELECT magnet, one_time_magnet, "
		      "OID FROM magnets"))
	  {
	    int row = 0;

	    while(query.next() &&
		  totalRows < m_ui.addTransmittedMagnets->rowCount())
	      {
		totalRows += 1;

		QByteArray bytes;
		bool ok = true;

		bytes = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

		QCheckBox *checkBox = new QCheckBox();
		QTableWidgetItem *item = 0;

		if(ok)
		  item = new QTableWidgetItem(bytes.constData());
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
		  checkBox->setText(bytes.replace("&", "&&").constData());
		else
		  checkBox->setText(tr("error"));

		if(checked.contains(checkBox->text()))
		  checkBox->setChecked(true);

		m_ui.addTransmittedMagnets->setCellWidget(row, 0, checkBox);
		item = new QTableWidgetItem
		  (query.value(query.record().count() - 1).toString());
		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setItem(row, 2, item);
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
}

void spoton::slotShowEtpMagnetsMenu(const QPoint &point)
{
  if(m_ui.etpMagnets == sender())
    {
      QMenu menu(this);

      menu.addAction(tr("Copy &Magnet"),
		     this, SLOT(slotCopyEtpMagnet(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString().toLower())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteEtpMagnet(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteEtpAllMagnets(void)));
      menu.exec(m_ui.etpMagnets->mapToGlobal(point));
    }
}

void spoton::slotDeleteEtpAllMagnets(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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
      QTableWidgetItem *item = m_ui.etpMagnets->item
	(row, m_ui.etpMagnets->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

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

void spoton::slotCopyEtpMagnet(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.etpMagnets->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.etpMagnets->item(row, 1); // Magnet

      if(item)
	clipboard->setText(item->text());
    }
}

void spoton::slotSaveDestination(void)
{
  saveDestination(m_ui.destination->text());
}

void spoton::saveDestination(const QString &path)
{
  m_settings["gui/etpDestinationPath"] = path;

  QSettings settings;

  settings.setValue("gui/etpDestinationPath", path);
  m_ui.destination->setText(path);
  m_ui.destination->setToolTip(path);
  m_ui.destination->selectAll();
}

void spoton::slotSelectDestination(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select StarBeam Destination Directory").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::Directory);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveDestination(dialog.selectedFiles().value(0));
}

void spoton::slotReceiversClicked(bool state)
{
  m_settings["gui/etpReceivers"] = state;

  QSettings settings;

  settings.setValue("gui/etpReceivers", state);
}

void spoton::slotMaxMosaicSize(int value)
{
  m_settings["gui/maxMosaicSize"] = value;

  QSettings settings;

  settings.setValue("gui/maxMosaicSize", value);
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
      m_ui.channelSalt->setText
	(spoton_crypt::strongRandomBytes(512).toBase64());
      m_ui.buzzHashKey->setText
	(spoton_crypt::
	 strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
	 toBase64());
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

void spoton::slotMailRetrievalIntervalChanged(int value)
{
  if(value < 5)
    value = 5;

  m_settings["gui/emailRetrievalInterval"] = value;

  QSettings settings;

  settings.setValue("gui/emailRetrievalInterval", value);
  m_emailRetrievalTimer.setInterval(60 * 1000 * value);
}

void spoton::slotResetCertificate(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("UPDATE neighbors SET "
		      "certificate = ? "
		      "WHERE OID = ? AND "
		      "user_defined = 1");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());
	query.bindValue(1, list.at(0).data());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotTransportChanged(int index)
{
  /*
  ** 0 - Bluetooth
  ** 1 - SCTP
  ** 2 - TCP
  ** 3 - UDP
  */

  if(m_ui.listenerTransport == sender())
    {
      if(index == 0)
	m_ui.ipv4Listener->setChecked(true);

      prepareListenerIPCombo();
      m_ui.days_valid->setEnabled(index == 2);
      m_ui.ipv4Listener->setEnabled(index != 0);
      m_ui.ipv6Listener->setEnabled(index != 0);
      m_ui.listenerKeySize->setEnabled(index == 2);
      m_ui.listenerShareAddress->setEnabled(index == 3);
      m_ui.listenersSslControlString->setEnabled(index == 2);
      m_ui.permanentCertificate->setEnabled(index == 2);
      m_ui.recordIPAddress->setEnabled(index == 2);

      if(m_ui.ipv6Listener->isChecked())
	m_ui.listenerScopeId->setEnabled(index != 0);
      else
	m_ui.listenerScopeId->setEnabled(false);

      m_ui.sslListener->setEnabled(index == 2);
    }
  else if(m_ui.neighborTransport == sender())
    {
      if(index == 0)
	m_ui.ipv4Neighbor->setChecked(true);

      m_ui.addException->setEnabled(index == 2);
      m_ui.dynamicdns->setEnabled(index != 0);
      m_ui.ipv4Neighbor->setEnabled(index != 0);
      m_ui.ipv6Neighbor->setEnabled(index != 0);
      m_ui.neighborKeySize->setEnabled(index == 2);

      if(m_ui.ipv6Neighbor->isChecked())
	m_ui.neighborScopeId->setEnabled(index != 0);
      else
	m_ui.neighborScopeId->setEnabled(false);

      m_ui.neighborsSslControlString->setEnabled(index == 2);

      if(index == 0 || index == 1)
	m_ui.proxy->setEnabled(false);
      else
	m_ui.proxy->setEnabled(true);

      m_ui.requireSsl->setEnabled(index == 2);
      m_ui.sslKeySizeLabel->setEnabled(index == 2);
    }
}

void spoton::slotStarOTMCheckChange(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

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

void spoton::slotGatherStatistics(void)
{
  if(!m_statisticsFuture.isFinished())
    return;

  m_statisticsFuture = QtConcurrent::run
    (this, &spoton::gatherStatistics);
  m_statisticsFutureWatcher.setFuture(m_statisticsFuture);
}

QList<QPair<QString, QVariant> > spoton::gatherStatistics(void) const
{
  QFileInfo fileInfo
    (spoton_misc::homePath() + QDir::separator() + "kernel.db");
  QList<QPair<QString, QVariant> > list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.exec("PRAGMA read_uncommitted = True");

	if(query.exec("SELECT statistic, value FROM kernel_statistics "
		      "ORDER BY statistic"))
	  while(query.next())
	    list << QPair<QString, QVariant> (query.value(0).toString(),
					      query.value(1));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return list;
}

void spoton::slotStatisticsGathered(void)
{
  populateStatistics(m_statisticsFuture.result());
}

void spoton::populateStatistics
(const QList<QPair<QString, QVariant> > &list)
{
  QWidget *focusWidget = QApplication::focusWidget();
  int activeListeners = 0;
  int activeNeighbors = 0;
  int row = 0;
  int totalRows = list.size();

  m_statisticsUi.view->setSortingEnabled(false);
  m_ui.statistics->setSortingEnabled(false);
  m_statisticsModel->removeRows(0, m_statisticsModel->rowCount());
  m_statisticsModel->setRowCount(totalRows);

  for(int i = 0; i < list.size(); i++)
    {
      QStandardItem *item = new QStandardItem(list.at(i).first);

      item->setEditable(false);
      m_statisticsModel->setItem(row, 0, item);
      item = new QStandardItem(list.at(i).second.toString());
      item->setEditable(false);
      m_statisticsModel->setItem(row, 1, item);

      if(list.at(i).first.toLower().contains("congestion container"))
	{
	  if(list.at(i).second.toLongLong() <= 50)
	    item->setBackground(QBrush(QColor("lightgreen")));
	  else
	    item->setBackground(QBrush(QColor(240, 128, 128)));
	}
      else if(list.at(i).first.toLower().contains("live listeners"))
	activeListeners = list.at(i).second.toInt();
      else if(list.at(i).first.toLower().contains("live neighbors"))
	activeNeighbors = list.at(i).second.toInt();

      row += 1;
    }

  totalRows += 2;
  m_statisticsModel->setRowCount(totalRows);

  QLocale locale;
  QStandardItem *item = new QStandardItem("Display Open Database Connections");

  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem(locale.toString(QSqlDatabase::connectionNames().
					   size()));
  item->setEditable(false);
  m_statisticsModel->setItem(row, 1, item);
  row += 1;
  item = new QStandardItem("Display PID");
  item->setEditable(false);
  m_statisticsModel->setItem(row, 0, item);
  item = new QStandardItem(QString::number(QApplication::applicationPid()));
  item->setEditable(false);
  m_statisticsModel->setItem(row, 1, item);
  m_statisticsUi.view->setSortingEnabled(true);
  m_statisticsUi.view->resizeColumnToContents(0);
  m_statisticsUi.view->horizontalHeader()->setStretchLastSection(true);
  m_ui.statistics->setSortingEnabled(true);
  m_ui.statistics->resizeColumnToContents(0);
  m_ui.statistics->horizontalHeader()->setStretchLastSection(true);

  if(focusWidget)
    focusWidget->setFocus();

  if(activeListeners > 0)
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.listeners->setToolTip
	(tr("There is (are) %1 active listener(s).").arg(activeListeners));
    }
  else
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.listeners->setToolTip(tr("Listeners are offline."));
    }

  if(activeNeighbors > 0)
    {
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())));
      m_sb.neighbors->setToolTip
	(tr("There is (are) %1 connected neighbor(s).").
	 arg(activeNeighbors));
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

void spoton::slotExternalIp(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QString str("");
  int v = 30;

  if(comboBox == m_ui.guiExternalIpFetch)
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
	  m_externalAddress.clear();
	  m_externalAddressDiscovererTimer.stop();
	}
    }
}

void spoton::slotSelectTransmitFile(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select StarBeam Transmit File").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    m_ui.transmittedFile->setText
      (dialog.selectedFiles().value(0));
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
  bool ok = true;
  bool zero = true;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
      QCheckBox *checkBox = qobject_cast<QCheckBox *>
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
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	QByteArray mosaic
	  (spoton_crypt::strongRandomBytes(spoton_common::MOSAIC_SIZE).
	   toBase64());
	QSqlQuery query(db);

	query.prepare("INSERT INTO transmitted "
		      "(file, fragmented, "
		      "hash, missing_links, mosaic, nova, "
		      "position, pulse_size, "
		      "status_control, total_size) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->
	   encryptedThenHashed(m_ui.transmittedFile->text().toUtf8(),
			       &ok).toBase64());
	query.bindValue
	  (1, m_ui.fragment_starbeam->isChecked() ? 1 : 0);

	if(ok)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed
	     (spoton_crypt::
	      sha1FileHash(m_ui.transmittedFile->text()).toHex(),
	      &ok).toBase64());

	if(ok)
	  {
	    QString missingLinks;
	    QStringList list(m_ui.missingLinks->text().
			     remove("magnet:?").split("&"));

	    while(!list.isEmpty())
	      {
		QString str(list.takeFirst());

		if(str.startsWith("ml="))
		  {
		    str.remove(0, 3);
		    missingLinks = str;
		    break;
		  }
	      }

	    query.bindValue
	      (3, crypt->
	       encryptedThenHashed(missingLinks.
				   toLatin1(), &ok).toBase64());
	  }

	if(ok)
	  {
	    encryptedMosaic = crypt->encryptedThenHashed(mosaic, &ok);

	    if(ok)
	      query.bindValue(4, encryptedMosaic.toBase64());
	  }

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed
	     (m_ui.transmitNova->text().
	      toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->encryptedThenHashed("0", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, crypt->
	     encryptedThenHashed(QByteArray::
				 number(qMin(m_ui.pulseSize->
					     value(),
					     spoton_misc::
					     minimumNeighborLaneWidth())),
				 &ok).toBase64());

	query.bindValue(8, "paused");

	if(ok)
	  query.bindValue
	    (9, crypt->
	     encryptedThenHashed(QByteArray::number(fileInfo.size()),
				 &ok).toBase64());

	if(ok)
	  query.exec();

	for(int i = 0; i < magnets.size(); i++)
	  {
	    query.prepare("INSERT INTO transmitted_magnets "
			  "(magnet, magnet_hash, transmitted_oid) "
			  "VALUES (?, ?, (SELECT OID FROM transmitted WHERE "
			  "mosaic = ?))");

	    if(ok)
	      query.bindValue
		(0, crypt->
		 encryptedThenHashed(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.bindValue(2, encryptedMosaic.toBase64());

	    if(ok)
	      query.exec();
	    else
	      break;

	    if(query.lastError().isValid())
	      {
		error = query.lastError().text();
		break;
	      }

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM magnets WHERE "
			  "magnet_hash = ? and one_time_magnet = 1");
	    query.bindValue(0, crypt->keyedHash(magnets.at(i), &ok).
			    toBase64());

	    if(ok)
	      query.exec();
	  }

	QApplication::restoreOverrideCursor();
      }

    if(db.lastError().isValid())
      error = tr("A database error (%1) occurred.").
	arg(db.lastError().text());
    else if(!error.isEmpty())
      error = tr("A database error (%1) occurred.").
	arg(error);
    else if(!ok)
      error = tr("An error occurred within spoton_crypt.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
  else
    {
      m_ui.fragment_starbeam->setChecked(false);
      m_ui.missingLinks->clear();
      m_ui.missingLinksCheckBox->setChecked(false);
      m_ui.pulseSize->setValue(15000);
      m_ui.transmitNova->clear();
      m_ui.transmittedFile->clear();
    }
}

void spoton::slotAcceptBuzzMagnets(bool state)
{
  m_settings["gui/acceptBuzzMagnets"] = state;

  QSettings settings;

  settings.setValue("gui/acceptBuzzMagnets", state);
}

void spoton::slotShareBuzzMagnet(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QByteArray data(action->data().toByteArray());
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray message;

  message.append("sharebuzzmagnet_");
  message.append(oid);
  message.append("_");
  message.append(data.toBase64());
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotShareBuzzMagnet(): write() failure "
	       "for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotPopulateStars(void)
{
  if(currentTabName() != "starbeam")
    if(m_chatWindows.size() == 0)
      return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "starbeam.db");

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

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QModelIndexList list;
	QSqlQuery query(db);
	QString mosaic("");
	QString selectedFileName("");
	QWidget *focusWidget = QApplication::focusWidget();
	int hval = 0;
	int row = -1;
	int totalRows = 0;
	int vval = 0;

	m_starbeamReceivedModel->removeRows
	  (0, m_starbeamReceivedModel->rowCount());
	query.setForwardOnly(true);

	/*
	** First, received.
	*/

	list = m_ui.received->selectionModel()->selectedRows
	  (4); // File

	if(!list.isEmpty())
	  selectedFileName = list.at(0).data().toString();

	hval = m_ui.received->horizontalScrollBar()->value();
	vval = m_ui.received->verticalScrollBar()->value();
	m_ui.received->setUpdatesEnabled(false);
	m_ui.received->setSortingEnabled(false);
	m_ui.received->clearContents();
	m_ui.received->setRowCount(0);
	row = 0;
	query.exec("PRAGMA read_uncommitted = True");

	if(query.exec("SELECT COUNT(*) FROM received"))
	  if(query.next())
	    {
	      m_starbeamReceivedModel->setRowCount(query.value(0).toInt());
	      m_ui.received->setRowCount(query.value(0).toInt());
	    }

	query.prepare("SELECT locked, pulse_size, total_size, file, hash, "
		      "expected_file_hash, OID FROM received");

	if(query.exec())
	  while(query.next() && totalRows < m_ui.received->rowCount())
	    {
	      totalRows += 1;

	      QByteArray expectedFileHash;
	      QByteArray hash;
	      QCheckBox *check = 0;
	      QString fileName("");
	      bool ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		      check = new QCheckBox();

		      if(query.value(i).toInt())
			check->setChecked(true);
		      else
			check->setChecked(false);

		      check->setProperty
			("oid", query.value(query.record().count() - 1));
		      connect(check,
			      SIGNAL(toggled(bool)),
			      this,
			      SLOT(slotMosaicLocked(bool)));
		      m_ui.received->setCellWidget(row, 0, check);
		    }
		  else if(i >= 1 && i <= 5)
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
			  if(i == 3)
			    item = new QTableWidgetItem
			      (QString::fromUtf8(bytes.constData(),
						 bytes.length()));
			  else
			    item = new QTableWidgetItem(bytes.constData());
			}
		      else
			item = new QTableWidgetItem(tr("error"));

		      if(i == 3)
			{
			  fileName = item->text();

			  QStandardItem *sItem = new QStandardItem(fileName);

			  sItem->setEditable(false);
			  m_starbeamReceivedModel->setItem(row, 1, sItem);
			}
		      else if(i == 4)
			hash = bytes;
		      else if(i == 5)
			expectedFileHash = bytes;
		    }
		  else if(i == query.record().count() - 1)
		    item = new QTableWidgetItem
		      (query.value(i).toString());

		  if(item)
		    {
		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable);
		      m_ui.received->setItem(row, i + 1, item);
		    }
		}

	      if(check)
		check->setProperty("filename", fileName);

	      QTableWidgetItem *item1 = m_ui.received->item(row, 3);
	      QTableWidgetItem *item2 = m_ui.received->item(row, 4);

	      if(item1 && item2)
		{
		  int percent = static_cast<int>
		    (100 *
       		     qAbs(static_cast<double> (QFileInfo(item2->text()).
					       size()) /
			  static_cast<double> (qMax(static_cast<long long>
						    (1),
						    item1->text().
						    toLongLong()))));

		  if(percent < 100)
		    {
		      QStandardItem *sItem = new QStandardItem
			(QString("%1%").arg(percent));

		      sItem->setEditable(false);
		      m_starbeamReceivedModel->setItem(row, 0, sItem);

		      QProgressBar *progressBar = new QProgressBar();

		      progressBar->setValue(percent);
		      progressBar->setTextVisible(true);
		      progressBar->setToolTip
			(QString("%1% - %2").
			 arg(percent).
			 arg(QFileInfo(fileName).fileName()));
		      m_ui.received->setCellWidget(row, 1, progressBar);
		    }
		  else
		    {
		      QStandardItem *sItem = new QStandardItem("100%");

		      sItem->setEditable(false);
		      m_starbeamReceivedModel->setItem(row, 0, sItem);

		      QTableWidgetItem *item = new QTableWidgetItem("100%");

		      item->setFlags
			(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.received->setItem(row, 1, item);

		      if(m_settings.value("gui/starbeamAutoVerify",
					  false).toBool())
			if(hash.isEmpty())
			  m_starbeamDigestFutures.append
			    (QtConcurrent::run(this,
					       &spoton::computeFileDigest,
					       expectedFileHash,
					       fileName,
					       query.
					       value(query.record().
						     count() - 1).toString(),
					       crypt));
		    }
		}

	      QStandardItem *item3 = m_starbeamReceivedModel->
		item(row, 0);
	      QTableWidgetItem *item4 = m_ui.received->item(row, 5);

	      if(item3 && item4)
		{
		  if(!hash.isEmpty() && spoton_crypt::memcmp(expectedFileHash,
							     hash))
		    {
		      item3->setBackground
			(QBrush(QColor("lightgreen")));
		      item3->setToolTip(tr("The computed file digest "
					   "is identical to the expected "
					   "file digest."));
		      item4->setBackground
			(QBrush(QColor("lightgreen")));
		    }
		  else
		    {
		      item3->setBackground
			(QBrush(QColor(240, 128, 128)));
		      item3->setToolTip(tr("The computed file digest "
					   "does not equal the expected "
					   "file digest."));
		      item4->setBackground
			(QBrush(QColor(240, 128, 128)));
		    }
		}

	      if(m_ui.received->item(row, 4) &&
		 selectedFileName == m_ui.received->item(row, 4)->text())
		m_ui.received->selectRow(row);

	      row += 1;
	    }

	m_starbeamReceivedModel->setRowCount(totalRows);
	m_ui.received->setRowCount(totalRows);
	m_ui.received->setSortingEnabled(true);

	for(int i = 0; i < m_ui.received->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.received->resizeColumnToContents(i);

	m_ui.received->horizontalHeader()->setStretchLastSection(true);
	m_ui.received->horizontalScrollBar()->setValue(hval);
	m_ui.received->verticalScrollBar()->setValue(vval);
	m_ui.received->setUpdatesEnabled(true);

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

	hval = m_ui.transmitted->horizontalScrollBar()->value();
	vval = m_ui.transmitted->verticalScrollBar()->value();
	m_ui.transmitted->setUpdatesEnabled(false);
	m_ui.transmitted->setSortingEnabled(false);
	m_ui.transmitted->clearContents();
	m_ui.transmitted->setRowCount(0);
	row = 0;
	totalRows = 0;

	if(query.exec("SELECT COUNT(*) FROM transmitted "
		      "WHERE status_control <> 'deleted'"))
	  if(query.next())
	    m_ui.transmitted->setRowCount(query.value(0).toInt());

	query.prepare("SELECT 0, position, pulse_size, total_size, "
		      "status_control, file, mosaic, hash, read_interval, "
		      "fragmented, OID FROM transmitted "
		      "WHERE status_control <> 'deleted'");

	if(query.exec())
	  while(query.next() && totalRows < m_ui.transmitted->rowCount())
	    {
	      totalRows += 1;

	      QCheckBox *checkBox = new QCheckBox();
	      QString fileName("");
	      bool ok = true;
	      qint64 position = 0;

	      checkBox->setChecked(true);
	      checkBox->setProperty
		("oid", query.value(query.record().count() - 1));
	      m_ui.transmitted->setCellWidget(row, 0, checkBox);

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		    }
		  else if(i == 1)
		    position = crypt->
		      decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(i).
					      toByteArray()),
		       &ok).toLongLong();
		  else if(i == 2 || i == 3 || i == 5 || i == 7)
		    {
		      QByteArray bytes
			(crypt->
			 decryptedAfterAuthenticated
			 (QByteArray::fromBase64(query.value(i).
						 toByteArray()),
			  &ok));

		      if(ok)
			{
			  if(i == 5)
			    {
			      fileName = QString::fromUtf8
				(bytes.constData(),
				 bytes.length());
			      item = new QTableWidgetItem(fileName);
			    }
			  else
			    item = new QTableWidgetItem(bytes.constData());
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
		      QByteArray bytes(query.value(i).toByteArray());

		      bytes = bytes.mid(0, 16) + "..." + bytes.right(16);
		      item = new QTableWidgetItem(bytes.constData());
		    }
		  else if(i == 8 || i == query.record().count() - 1)
		    item = new QTableWidgetItem
		      (query.value(i).toString());
		  else if(i == 9)
		    {
		      QCheckBox *checkBox = new QCheckBox();

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
		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable);
		      m_ui.transmitted->setItem(row, i, item);
		    }
		}

	      QTableWidgetItem *item = m_ui.transmitted->item(row, 3);

	      if(item)
		{
		  int percent = static_cast<int>
		    (100 *
		     qAbs(static_cast<double> (position) /
			  static_cast<double> (qMax(static_cast<long long>
						    (1),
						    item->text().
						    toLongLong()))));

		  if(percent < 100)
		    {
		      QProgressBar *progressBar = new QProgressBar();

		      progressBar->setValue(percent);
		      progressBar->setToolTip
			(QString("%1% - %2").
			 arg(percent).
			 arg(QFileInfo(fileName).fileName()));
		      progressBar->setTextVisible(true);
		      m_ui.transmitted->setCellWidget
			(row, 1, progressBar);
		    }
		  else
		    {
		      QTableWidgetItem *item = new QTableWidgetItem("100%");

		      item->setFlags
			(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		      m_ui.transmitted->setItem(row, 1, item);
		    }
		}

	      connect(checkBox,
		      SIGNAL(toggled(bool)),
		      this,
		      SLOT(slotTransmittedPaused(bool)));

	      for(int i = 0; i < m_ui.transmitted->columnCount(); i++)
		if(m_ui.transmitted->item(row, i))
		  m_ui.transmitted->item(row, i)->setToolTip(fileName);

	      if(m_ui.transmitted->item(row, 6) &&
		 mosaic == m_ui.transmitted->item(row, 6)->text())
		m_ui.transmitted->selectRow(row);

	      row += 1;
	    }

	m_ui.transmitted->setRowCount(totalRows);
	m_ui.transmitted->setSortingEnabled(true);

	for(int i = 0; i < m_ui.transmitted->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.transmitted->resizeColumnToContents(i);

	m_ui.transmitted->horizontalHeader()->setStretchLastSection(true);
	m_ui.transmitted->horizontalScrollBar()->setValue(hval);
	m_ui.transmitted->verticalScrollBar()->setValue(vval);
	m_ui.transmitted->setUpdatesEnabled(true);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

 done_label:
  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotTransmittedPaused(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE transmitted SET "
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

void spoton::slotDeleteAllTransmitted(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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

void spoton::slotDeleteTransmitted(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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

void spoton::slotSecureMemoryPoolChanged(int value)
{
  QSettings settings;

  if(m_ui.guiSecureMemoryPool == sender())
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

void spoton::slotAddReceiveNova(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QString nova(m_ui.receiveNova->text());

  if(nova.length() < 48)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Please provide a nova that contains at least "
	    "forty-eight characters. Reach for the "
	    "stars!"));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received_novas "
	   "(nova, nova_hash) VALUES (?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(nova.toLatin1(),
					 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(nova.toLatin1(), &ok).
	     toBase64());

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
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to store the nova."));
}

void spoton::populateNovas(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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
		bool ok = true;

		nova = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok).constData();

		if(!nova.isEmpty())
		  novas.append(nova);
	      }

	    qSort(novas);

	    if(!novas.isEmpty())
	      m_ui.novas->addItems(novas);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteNova(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QList<QListWidgetItem *> list(m_ui.novas->selectedItems());

  if(list.isEmpty() || !list.at(0))
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please select a nova to delete."));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM received_novas WHERE "
		      "nova_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(list.at(0)->text().toLatin1(), &ok).
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
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error occurred while attempting "
			     "to delete the speficied nova."));
  else
    {
      populateNovas();
      askKernelToReadStarBeamKeys();
    }
}

void spoton::slotGenerateNova(void)
{
  QByteArray nova
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::cipherKeyLength("aes256")) +
     spoton_crypt::
     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));

  m_ui.transmitNova->setText(nova.toBase64());
}

void spoton::slotTransmittedSelected(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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
		bool ok = true;

		magnet = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok).constData();

		if(!magnet.isEmpty())
		  magnets.append(magnet);
	      }

	    qSort(magnets);

	    if(!magnets.isEmpty())
	      m_ui.transmittedMagnets->addItems(magnets);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCopyTransmittedMagnet(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  QListWidgetItem *item = m_ui.transmittedMagnets->currentItem();

  if(item)
    clipboard->setText(item->text());
}

void spoton::slotDeleteAllReceived(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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

void spoton::slotDeleteReceived(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM received WHERE "
		      "OID = ?");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::askKernelToReadStarBeamKeys(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QByteArray message;

  message.append("populate_starbeam_keys\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::askKernelToReadStarBeamKeys(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::slotRewindFile(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("UPDATE transmitted SET position = ?, "
	   "status_control = 'paused' "
	   "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue
	  (0, crypt->encryptedThenHashed(QByteArray::number(0), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotComputeFileHash(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QTableWidget *table = 0;

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
      QTableWidgetItem *item = table->item
	(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QTableWidgetItem *item = 0;

  if(m_ui.received == table)
    item = table->item(table->currentRow(), 4); // File
  else
    item = table->item(table->currentRow(), 5); // File

  if(!item)
    return;

  QFile file;
  QString fileName(item->text());

  file.setFileName(fileName);

  if(!file.open(QIODevice::ReadOnly))
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray hash(spoton_crypt::sha1FileHash(fileName));

  QApplication::restoreOverrideCursor();

  file.close();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	if(m_ui.received == table)
	  query.prepare
	    ("UPDATE received SET hash = ? WHERE OID = ?");
	else
	  query.prepare
	    ("UPDATE transmitted SET hash = ? WHERE OID = ?");

	if(hash.isEmpty())
	  query.bindValue(0, QVariant::String);
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

void spoton::slotCopyFileHash(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    {
      clipboard->clear();
      return;
    }

  QTableWidget *table = 0;

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
      QTableWidgetItem *item = table->item
	(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      return;
    }

  QTableWidgetItem *item = 0;

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

void spoton::slotViewRosetta(void)
{
  m_rosetta.show(this);
}

void spoton::sharePublicKeyWithParticipant(const QString &keyType)
{
  if(!m_crypts.value(keyType, 0) ||
     !m_crypts.value(QString("%1-signature").arg(keyType), 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  QTableWidget *table = 0;
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
    return;

  if((row = table->currentRow()) >= 0)
    {
      QTableWidgetItem *item = table->item(row, 2); // neighbor_oid

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

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
      message.append(oid);
      message.append("_");
      message.append(keyType.toLatin1().toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::sharePublicKeyWithParticipant(): "
		   "write() failure for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }
}

void spoton::slotRegenerateKey(void)
{
  QString keyType("chat");

  if(m_ui.keys->currentText() == "Chat")
    keyType = "chat";
  else if(m_ui.keys->currentText() == "E-Mail")
    keyType = "email";
  else if(m_ui.keys->currentText() == "Poptastic")
    keyType = "poptastic";
  else if(m_ui.keys->currentText() == "Rosetta")
    keyType = "rosetta";
  else if(m_ui.keys->currentText() == "URL")
    keyType = "url";

  spoton_crypt *crypt1 = m_crypts.value(keyType, 0);
  spoton_crypt *crypt2 = m_crypts.value
    (QString("%1-signature").arg(keyType), 0);

  if(!crypt1 || !crypt2)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object(s). This is "
			       "a fatal flaw."));
      return;
    }

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
  mb.setText(tr("Are you sure that you wish to generate the selected "
		"key pair? The kernel will be deactivated."));

  if(mb.exec() != QMessageBox::Yes)
    return;
  else
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

  if(error.isEmpty())
    {
      if(m_ui.keys->currentText() != "Rosetta")
	sendKeysToKernel();
    }
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred with "
			     "spoton_crypt::"
			     "generatePrivatePublicKeys().").
			  arg(error.trimmed()));
}

void spoton::prepareContextMenuMirrors(void)
{
  if(!m_ui.chatActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareChatPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(tr("Chat &popup."), this,
		      SLOT(slotChatPopup(void)));
      menu->addSeparator();
      menu->addAction(QIcon(":/generic/repleo-chat.png"),
		      tr("&Copy Repleo to the clipboard buffer."),
		      this, SLOT(slotCopyFriendshipBundle(void)));
      menu->addSeparator();
#if SPOTON_GOLDBUG == 1
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA: &Call friend with new "
				  "Gemini pair."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA: &Call friend with new "
				  "Gemini pair using the existing "
				  "Gemini pair."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu->addAction(QIcon(QString(":/%1/melodica.png").
				     arg(m_settings.value("gui/iconSet",
							  "nouve").
					 toString().toLower())),
			       tr("MELODICA Two-Way: &Call friend with new "
				  "Gemini pair."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_two_way");
#else
      action = menu->addAction(tr("&Call participant."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu->addAction(tr("&Call participant using the "
				  "existing Gemini pair."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_using_gemini");
      action = menu->addAction(tr("&Two-way calling."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling_two_way");
#endif
      action = menu->addAction(tr("&Terminate call."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");
      menu->addSeparator();
#if SPOTON_GOLDBUG == 1
      menu->addAction
	(tr("&Generate random Gemini pair "
	    "(AES-256 Key, SHA-512 Key) (without a call)."),
	 this, SLOT(slotGenerateGeminiInChat(void)));
#else
      menu->addAction(tr("&Generate random Gemini pair "
			 "(AES-256 Key, SHA-512 Key)."),
		      this, SLOT(slotGenerateGeminiInChat(void)));
#endif
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove participant(s)."),
		      this, SLOT(slotRemoveParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename participant."),
			       this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "chat");
      menu->addSeparator();
      menu->addAction(tr("&Derive Gemini pair from SMP secret."),
		      this,
		      SLOT(slotDeriveGeminiPairViaSMP(void)));
      menu->addAction(tr("&Reset the SMP machine's internal state to s0."),
		      this,
		      SLOT(slotInitializeSMP(void)));
      menu->addAction(tr("&Set an SMP secret."),
		      this,
		      SLOT(slotPrepareSMP(void)));
      menu->addAction(tr("&Verify the SMP secret."),
		      this,
		      SLOT(slotVerifySMPSecret(void)));
      menu->addSeparator();
      menu->addAction(tr("Replay &last %1 messages.").
		      arg(spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE),
		      this,
		      SLOT(slotReplayMessages(void)));
      menu->addAction(tr("Share a &StarBeam."),
		     this,
		     SLOT(slotShareStarBeam(void)));
      menu->addSeparator();
      menu->addAction
	(tr("Call via Forward &Secrecy credentials."),
	 this, SLOT(slotCallParticipantViaForwardSecrecy(void)));
      action = menu->addAction(tr("Initiate Forward &Secrecy exchange(s)."),
			       this, SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "chat");
      action = menu->addAction(tr("Purge Forward &Secrecy key pair."),
			       this, SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "chat");
      action = menu->addAction
	(tr("Reset Forward &Secrecy information."),
	 this, SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "chat");
      m_ui.chatActionMenu->setMenu(menu);
      connect(m_ui.chatActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.chatActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.deleteAllUrls->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(tr("Drop Tables"),
		      this,
		      SLOT(slotDropUrlTables(void)));
      menu->addAction(tr("Vacuum Databases"),
		      this,
		      SLOT(slotDeleteAllUrls(void)));
      m_ui.deleteAllUrls->setMenu(menu);
      connect(m_ui.deleteAllUrls,
	      SIGNAL(clicked(void)),
	      m_ui.deleteAllUrls,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.emailWriteActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(QIcon(":/generic/repleo-email.png"),
		      tr("&Copy Repleo to the clipboard buffer."),
		      this, SLOT(slotCopyEmailFriendshipBundle(void)));
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Copy keys to the clipboard buffer."),
		      this, SLOT(slotCopyEmailKeys(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove participant(s)."),
		      this, SLOT(slotRemoveEmailParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename participant."),
			       this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "email");
      menu->addSeparator();
      action = menu->addAction(tr("Initiate Forward &Secrecy exchange(s)."),
			       this, SLOT(slotEstablishForwardSecrecy(void)));
      action->setProperty("type", "email");
      action = menu->addAction(tr("Purge Forward &Secrecy key pair."),
			       this, SLOT(slotPurgeEphemeralKeyPair(void)));
      action->setProperty("type", "email");
      action = menu->addAction
	(tr("Reset Forward &Secrecy information."),
	 this, SLOT(slotResetForwardSecrecyInformation(void)));
      action->setProperty("type", "email");
      m_ui.emailWriteActionMenu->setMenu(menu);
      connect(m_ui.emailWriteActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.emailWriteActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.listenersActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteListener(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteAllListeners(void)));
      menu->addSeparator();
      menu->addAction(tr("Detach &Neighbors"),
		      this, SLOT(slotDetachListenerNeighbors(void)));
      menu->addAction(tr("Disconnect &Neighbors"),
		      this, SLOT(slotDisconnectListenerNeighbors(void)));
      menu->addSeparator();
      menu->addAction(tr("&Publish Information (Plaintext)"),
		      this, SLOT(slotPublicizeListenerPlaintext(void)));
      menu->addAction(tr("Publish &All (Plaintext)"),
		      this, SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this, SLOT(slotListenerFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this, SLOT(slotListenerHalfEcho(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Copy Adaptive Echo Magnet"),
			       this, SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "listeners");
      menu->addSeparator();
      menu->addAction(tr("Set &SSL Control String"),
		      this, SLOT(slotSetListenerSSLControlString(void)));
      m_ui.listenersActionMenu->setMenu(menu);
      connect(m_ui.listenersActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.listenersActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.magnetsActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(tr("Copy &Magnet"),
		      this, SLOT(slotCopyEtpMagnet(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteEtpMagnet(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteEtpAllMagnets(void)));
      m_ui.magnetsActionMenu->setMenu(menu);
      connect(m_ui.magnetsActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.magnetsActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.neighborsActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &Chat Public Key Pair"),
		      this, SLOT(slotShareChatPublicKey(void)));
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &E-Mail Public Key Pair"),
		      this, SLOT(slotShareEmailPublicKey(void)));
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &Poptastic Public Key Pair"),
		      this, SLOT(slotSharePoptasticPublicKey(void)));
      menu->addAction(QIcon(QString(":%1//share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("Share &URL Public Key Pair"),
		      this, SLOT(slotShareURLPublicKey(void)));
      menu->addSeparator();
      menu->addAction(tr("&Assign New Remote IP Information"),
		      this, SLOT(slotAssignNewIPToNeighbor(void)));
      menu->addAction(tr("&Connect"),
		      this, SLOT(slotConnectNeighbor(void)));
      menu->addAction(tr("&Disconnect"),
		      this, SLOT(slotDisconnectNeighbor(void)));
      menu->addSeparator();
      menu->addAction(tr("&Connect All"),
		      this, SLOT(slotConnectAllNeighbors(void)));
      menu->addAction(tr("&Disconnect All"),
		      this, SLOT(slotDisconnectAllNeighbors(void)));
      menu->addSeparator();
      menu->addAction
	(tr("&Authenticate"),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu->addAction(tr("&Reset Account Information"),
		      this,
		      SLOT(slotResetAccountInformation(void)));
      menu->addSeparator();
      menu->addAction(tr("&Reset Certificate"),
		      this,
		      SLOT(slotResetCertificate(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteNeighbor(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteAllNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &Blocked"),
		      this, SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &UUIDs"),
		      this, SLOT(slotDeleteAllUuids(void)));
      menu->addSeparator();
      menu->addAction(tr("B&lock"),
		      this, SLOT(slotBlockNeighbor(void)));
      menu->addAction(tr("U&nblock"),
		      this, SLOT(slotUnblockNeighbor(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this, SLOT(slotNeighborFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this, SLOT(slotNeighborHalfEcho(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Copy Adaptive Echo Magnet"),
			       this, SLOT(slotCopyAEMagnet(void)));
      action->setProperty("from", "neighbors");
      menu->addAction(tr("&Set Adaptive Echo Token Information"),
		      this, SLOT(slotSetAETokenInformation(void)));
      menu->addAction(tr("&Reset Adaptive Echo Token Information"),
		      this, SLOT(slotResetAETokenInformation(void)));
      menu->addSeparator();
      menu->addAction(tr("Set &SSL Control String"),
		      this, SLOT(slotSetNeighborSSLControlString(void)));
      menu->addSeparator();

      QList<QPair<QString, QThread::Priority> > list;
      QMenu *subMenu = menu->addMenu(tr("Priority"));
      QPair<QString, QThread::Priority> pair;

      pair.first = tr("High Priority");
      pair.second = QThread::HighPriority;
      list << pair;
      pair.first = tr("Highest Priority");
      pair.second = QThread::HighestPriority;
      list << pair;
      pair.first = tr("Idle Priority");
      pair.second = QThread::IdlePriority;
      list << pair;
      pair.first = tr("Inherit Priority");
      pair.second = QThread::InheritPriority;
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

      for(int i = 0; i < list.size(); i++)
	{
	  action = subMenu->addAction
	    (list.at(i).first,
	     this,
	     SLOT(slotSetNeighborPriority(void)));
	  action->setProperty("priority", list.at(i).second);
	}

      m_ui.neighborsActionMenu->setMenu(menu);
      connect(m_ui.neighborsActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.neighborsActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.receivedActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

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
      action->setProperty("widget_of", "received");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy File Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "received");
      menu->addSeparator();
      menu->addAction(tr("Discover &Missing Links"), this,
		      SLOT(slotDiscoverMissingLinks(void)));
      m_ui.receivedActionMenu->setMenu(menu);
      connect(m_ui.receivedActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.receivedActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.transmittedActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

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
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy File Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      menu->addAction(tr("Copy &Magnet"),
		      this, SLOT(slotCopyTransmittedMagnet(void)));
      menu->addAction(tr("&Duplicate Magnet"),
		      this, SLOT(slotDuplicateTransmittedMagnet(void)));
      menu->addSeparator();
      menu->addAction(tr("Set &Pulse Size"), this,
		      SLOT(slotSetSBPulseSize(void)));
      menu->addAction(tr("Set &Read Interval"), this,
		      SLOT(slotSetSBReadInterval(void)));
      m_ui.transmittedActionMenu->setMenu(menu);
      connect(m_ui.transmittedActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.transmittedActionMenu,
	      SLOT(showMenu(void)));
    }

  if(!m_ui.urlActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString().
		   toLower())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareUrlPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(QIcon(":/generic/repleo-url.png"),
		      tr("&Copy Repleo to the clipboard buffer."),
		      this, SLOT(slotCopyUrlFriendshipBundle(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString().toLower())),
		      tr("&Remove participant(s)."),
		      this, SLOT(slotRemoveUrlParticipants(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Rename participant."),
			       this, SLOT(slotRenameParticipant(void)));
      action->setProperty("type", "url");
      m_ui.urlActionMenu->setMenu(menu);
      connect(m_ui.urlActionMenu,
	      SIGNAL(clicked(void)),
	      m_ui.urlActionMenu,
	      SLOT(showMenu(void)));
    }
}

void spoton::slotCopyEmailKeys(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QByteArray name;
  QByteArray publicKeyHash;
  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.emailParticipants->
	item(row, 0); // Name

      if(item)
	name.append(item->text());

      item = m_ui.emailParticipants->item(row, 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.emailParticipants->item(row, 3); // public_key_hash

      if(item)
	publicKeyHash.append(item->text());
    }

  if(oid.isEmpty() || publicKeyHash.isEmpty())
    {
      clipboard->clear();
      return;
    }

  if(name.isEmpty())
    name = "unknown";

  QByteArray publicKey;
  QByteArray signatureKey;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

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
    clipboard->setText
      ("K" + QByteArray("email").toBase64() + "@" +
       name.toBase64() + "@" +
       publicKey.toBase64() + "@" + QByteArray().toBase64() + "@" +
       signatureKey.toBase64() + "@" + QByteArray().toBase64());
  else
    clipboard->clear();
}

void spoton::slotImpersonate(bool state)
{
  m_settings["gui/impersonate"] = state;

  QSettings settings;

  settings.setValue("gui/impersonate", state);
}

void spoton::slotCopyOrPaste(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QWidget *widget = QApplication::focusWidget();

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

void spoton::updatePublicKeysLabel(void)
{
  m_ui.personal_public_keys->clearContents();
  m_ui.personal_public_keys->setRowCount(0);

  QStringList list(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES +
		   spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

  m_ui.personal_public_keys->setRowCount(list.size());

  for(int i = 0; i < list.size(); i++)
    {
      spoton_crypt *crypt = m_crypts.value(list.at(i), 0);

      if(!crypt)
	continue;

      QByteArray base64;
      QByteArray bytes;
      QTableWidgetItem *item = new QTableWidgetItem
	(list.at(i));
      bool ok = true;

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

      if(ok)
	{
	  bytes = spoton_crypt::sha512Hash(bytes, &ok);
	  base64 = bytes.toBase64();
	  bytes = bytes.toHex();
	}

      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

      if(ok)
	item->setText(bytes.constData());

      m_ui.personal_public_keys->setItem(i, 3, item);
      item = new QTableWidgetItem();
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      item->setText(base64.constData());

      if(!base64.isEmpty())
	item->setToolTip(base64.mid(0, 16) + "..." + base64.right(16));

      m_ui.personal_public_keys->setItem(i, 4, item);
    }

  m_ui.personal_public_keys->resizeColumnToContents(0);
}

void spoton::slotExportPublicKeys(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray keys(copyMyChatPublicKey() + "\n" +
		  copyMyEmailPublicKey() + "\n" +
		  copyMyPoptasticPublicKey() + "\n" +
		  copyMyRosettaPublicKey() + "\n" +
		  copyMyUrlPublicKey());

  QApplication::restoreOverrideCursor();

  if(keys.length() >= 30000)
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
      mb.setText(tr("The gathered public key pairs contain a lot (%1) "
		    "of data. "
		    "Are you sure that you wish to export the data?").
		 arg(keys.length()));

      if(mb.exec() != QMessageBox::Yes)
	return;
    }

  QFileDialog dialog(this);

  dialog.setConfirmOverwrite(true);
  dialog.setWindowTitle
    (tr("%1: Select Public Keys Export File").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::AnyFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory(QDesktopServices::storageLocation(QDesktopServices::
							DesktopLocation));
#else
  dialog.setDirectory(QStandardPaths::
		      standardLocations(QStandardPaths::DesktopLocation).
		      value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Save"));
  dialog.setAcceptMode(QFileDialog::AcceptSave);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
  dialog.selectFile(QString("spot-on-public-keys-export-%1.txt").
		    arg(QDateTime::currentDateTime().
			toString("MM-dd-yyyy-hh-mm-ss")));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QFile file;

      file.setFileName(dialog.selectedFiles().value(0));

      if(file.open(QIODevice::Truncate | QIODevice::WriteOnly))
	{
	  file.write(keys);
	  file.flush();
	}

      file.close();
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotImportPublicKeys(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Public Keys Import File").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory
    (QDesktopServices::storageLocation(QDesktopServices::
				       DesktopLocation));
#else
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(),
		       dialog.selectedFiles().value(0));

      if(fileInfo.size() >= 30000)
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
	  mb.setText
	    (tr("The import file contains a lot (%1) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.size()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QByteArray bytes;
      QFile file;

      file.setFileName(fileInfo.filePath());

      if(file.open(QIODevice::ReadOnly))
	bytes = file.readAll();

      file.close();

      QList<QByteArray> list(bytes.split('\n'));

      while(!list.isEmpty())
	{
	  QByteArray bytes("K");

	  bytes.append(list.takeFirst());
	  bytes.remove(0, 1);
	  addFriendsKey(bytes, "K");
	}
    }
}

void spoton::slotExportListeners(void)
{
  if(m_ui.listeners->rowCount() == 0)
    {
      QMessageBox::critical
	(this, tr("%1: Error").
	 arg(SPOTON_APPLICATION_NAME),
	 tr("Unable to export an empty listeners table."));
      return;
    }

  QFileDialog dialog(this);

  dialog.setConfirmOverwrite(true);
  dialog.setWindowTitle
    (tr("%1: Select Listeners Export File").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::AnyFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory(QDesktopServices::storageLocation(QDesktopServices::
							DesktopLocation));
#else
  dialog.setDirectory(QStandardPaths::
		      standardLocations(QStandardPaths::DesktopLocation).
		      value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Save"));
  dialog.setAcceptMode(QFileDialog::AcceptSave);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
  dialog.selectFile(QString("spot-on-listeners-export-%1.txt").
		    arg(QDateTime::currentDateTime().
			toString("MM-dd-yyyy-hh-mm-ss")));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QFile file;

      file.setFileName(dialog.selectedFiles().value(0));

      if(file.open(QIODevice::Text | QIODevice::Truncate |
		   QIODevice::WriteOnly))
	for(int i = 0; i < m_ui.listeners->rowCount(); i++)
	  {
	    QByteArray bytes;

	    bytes.append("echo_mode=");
	    bytes.append(m_ui.listeners->item(i, 11)->text());
	    bytes.append("&");
	    bytes.append("ip_address=");
	    bytes.append(m_ui.listeners->item(i, 7)->text());
	    bytes.append("&");
	    bytes.append("orientation=");
	    bytes.append(m_ui.listeners->item(i, 18)->text());
	    bytes.append("&");
	    bytes.append("port=");
	    bytes.append(m_ui.listeners->item(i, 4)->text());
	    bytes.append("&");
	    bytes.append("protocol=");
	    bytes.append(m_ui.listeners->item(i, 6)->text());
	    bytes.append("&");
	    bytes.append("scope_id=");
	    bytes.append(m_ui.listeners->item(i, 5)->text().remove("&"));
	    bytes.append("&");
	    bytes.append("ssl_key_size=");
	    bytes.append(m_ui.listeners->item(i, 2)->text());
	    bytes.append("&");
	    bytes.append("transport=");
	    bytes.append(m_ui.listeners->item(i, 15)->text());
	    bytes.append("\n");
	    file.write(bytes);
	    file.flush();
	  }

      file.close();
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotForceKernelRegistration(bool state)
{
  m_settings["gui/forceKernelRegistration"] = state;

  QSettings settings;

  settings.setValue("gui/forceKernelRegistration", state);
}

void spoton::slotImportNeighbors(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Neighbors Import File").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory
    (QDesktopServices::storageLocation(QDesktopServices::
				       DesktopLocation));
#else
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(),
		       dialog.selectedFiles().value(0));

      if(fileInfo.size() >= 30000)
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
	  mb.setText
	    (tr("The import file contains a lot (%1) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.size()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      importNeighbors(fileInfo.filePath());
    }
}

void spoton::importNeighbors(const QString &filePath)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QFile file;

	file.setFileName(filePath);

	if(file.open(QIODevice::ReadOnly))
	  {
	    QByteArray bytes(2048, 0);
	    qint64 rc = 0;

	    while((rc = file.readLine(bytes.data(),
				      bytes.length())) > -1)
	      {
		bytes = bytes.trimmed();

		if(bytes.isEmpty() || bytes.startsWith("#"))
		  /*
		  ** Comment, or an empty line, ignore!
		  */

		  continue;

		QHash<QString, QByteArray> hash;
		QList<QByteArray> list
		  (bytes.mid(0, static_cast<int> (rc)).trimmed().
		   split('&'));
		bool fine = true;

		while(!list.isEmpty())
		  {
		    QByteArray token(list.takeFirst().trimmed());

		    if(token.startsWith("echo_mode="))
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
			     token == "2048" || token == "3072" ||
			     token == "4096" || token == "8192"))
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
			     token == "udp"))
			  fine = false;
			else
			  hash["transport"] = token;
		      }

		    if(!fine)
		      break;
		  }

		if(hash.count() != 8)
		  fine = false;

		if(fine)
		  {
		    QSqlQuery query(db);
		    bool ok = true;

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
		    query.bindValue(0, QVariant(QVariant::String));
		    query.bindValue(1, QVariant(QVariant::String));
		    query.bindValue
		      (2, crypt->
		       encryptedThenHashed
		       (hash["protocol"], &ok).toBase64());

		    if(ok)
		      query.bindValue
			(3, crypt->
			 encryptedThenHashed
			 (hash["ip_address"], &ok).toBase64());

		    if(ok)
		      query.bindValue
			(4, crypt->
			 encryptedThenHashed
			 (hash["port"], &ok).toBase64());

		    query.bindValue(5, 1); // Sticky.

		    if(ok)
		      query.bindValue
			(6, crypt->
			 encryptedThenHashed
			 (hash["scope_id"], &ok).toBase64());

		    if(ok)
		      query.bindValue
			(7, crypt->
			 keyedHash(QByteArray() + // Proxy HostName
				   QByteArray() + // Proxy Port
				   hash["ip_address"] +
				   hash["port"] +
				   hash["scope_id"] +
				   hash["transport"], &ok).
			 toBase64());

		    query.bindValue(8, "disconnected");

		    QString country
		      (spoton_misc::
		       countryNameFromIPAddress(hash["ip_address"].
						constData()));

		    if(ok)
		      query.bindValue
			(9, crypt->
			 encryptedThenHashed
			 (country.toLatin1(), &ok).toBase64());

		    if(ok)
		      query.bindValue
			(10, crypt->
			 keyedHash(hash["ip_address"], &ok).
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
			 encryptedThenHashed
			 (hash["echo_mode"], &ok).toBase64());

		    if(hash["transport"] == "tcp")
		      query.bindValue
			(19, hash["ssl_key_size"].toInt());
		    else
		      query.bindValue(19, 0);

		    query.bindValue(20, 0);

		    if(ok)
		      query.bindValue
			(21, crypt->encryptedThenHashed
			 (QByteArray(),
			  &ok).toBase64());

		    if(hash["transport"] == "tcp")
		      query.bindValue(22, 1);
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
			 (hash["transport"],
			  &ok).toBase64());

		    if(ok)
		      query.bindValue
			(26, crypt->encryptedThenHashed
			 (hash["orientation"],
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

void spoton::slotSaveUrlName(void)
{
  QString str(m_ui.urlName->text());

  if(str.trimmed().isEmpty())
    {
      str = "unknown";
      m_ui.urlName->setText(str);
    }
  else
    m_ui.urlName->setText(str.trimmed());

  m_settings["gui/urlName"] = str.toUtf8();

  QSettings settings;

  settings.setValue("gui/urlName", str.toUtf8());
  m_ui.urlName->selectAll();
}

void spoton::slotCopyUrlFriendshipBundle(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypts.value("url", 0) ||
     !m_crypts.value("url-signature", 0))
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.urlParticipants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.urlParticipants->item
	(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
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
  QByteArray cipherType(m_settings.value("gui/kernelCipherType",
					 "aes256").toString().
			toLatin1());
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray symmetricKey;
  QPair<QByteArray, QByteArray> gemini;
  QString receiverName("");
  bool ok = true;

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     hashKey,
				     neighborOid,
				     receiverName,
				     cipherType,
				     oid,
				     m_crypts.value("url", 0),
				     &ok);

  if(!ok || publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      return;
    }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" +
     cipherType.toBase64() + "@" +
     hashKey.toBase64(), publicKey, &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySPublicKey(m_crypts.value("url-signature")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySSignature
    (m_crypts.value("url-signature")->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypts.value("url")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySignature(m_crypts.value("url")->
			 digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName
    (m_settings.value("gui/urlName", "unknown").toByteArray());

  if(myName.isEmpty())
    myName = "unknown";

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     "sha512",
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  data = crypt.encrypted(QByteArray("url").toBase64() + "@" +
			 myName.toBase64() + "@" +
			 myPublicKey.toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText("R" +
		     keyInformation.toBase64() + "@" +
		     data.toBase64() + "@" +
		     hash.toBase64());
}

void spoton::slotRemoveUrlParticipants(void)
{
  if(!m_ui.urlParticipants->selectionModel()->hasSelection())
    return;

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
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"participant(s)?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (m_ui.urlParticipants->selectionModel()->
	   selectedRows(1)); // OID
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      {
		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM friends_public_keys WHERE "
			      "OID = ?");
		query.bindValue(0, data.toString());
		query.exec();
	      }
	  }

	spoton_misc::purgeSignatureRelationships
	  (db, m_crypts.value("chat", 0));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotShowStatistics(void)
{
  m_ui.statisticsBox->setVisible(!m_ui.statisticsBox->isVisible());
}

void spoton::slotRenameParticipant(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString().toLower());

  if(!(type == "chat" || type == "email" ||
       type == "poptastic" || type == "url"))
    return;

  QModelIndexList list;

  if(currentTabName() == "chat")
    if(type == "chat" || type == "poptastic")
      list = m_ui.participants->selectionModel()->selectedRows(1); // OID

  if(currentTabName() == "email")
    if(type == "email" || type == "poptastic")
      list = m_ui.emailParticipants->selectionModel()->selectedRows(1); // OID

  if(type == "url")
    list = m_ui.urlParticipants->selectionModel()->selectedRows(1); // OID

  if(list.isEmpty())
    return;

  QVariant data(list.value(0).data());

  if(currentTabName() == "chat")
    if(type == "chat" || type == "poptastic")
      list = m_ui.participants->selectionModel()->selectedRows(0); // Name

  if(currentTabName() == "email")
    if(type == "email" || type == "poptastic")
      list = m_ui.emailParticipants->selectionModel()->selectedRows(0); // Name

  if(type == "url")
    list = m_ui.urlParticipants->selectionModel()->selectedRows(0); // Name

  QString name("");
  bool ok = true;

  name = QInputDialog::getText
    (this, tr("%1: New Name").arg(SPOTON_APPLICATION_NAME), tr("&Name"),
     QLineEdit::Normal, list.value(0).data().toString(), &ok);
  name = name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH);

  if(name.isEmpty() || !ok)
    return;

  ok = false;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!data.isNull() && data.isValid())
	  {
	    bool ok = true;

	    query.prepare("UPDATE friends_public_keys "
			  "SET name = ?, "
			  "name_changed_by_user = 1 "
			  "WHERE OID = ?");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(name.toUtf8(), &ok).
	       toBase64());
	    query.bindValue(1, data.toString());

	    if(ok)
	      ok = query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    if(currentTabName() == "chat")
      {
	QTableWidgetItem *item = m_ui.participants->item
	  (list.value(0).row(), 3); // public_key_hash

	if(item)
	  {
	    QString publicKeyHash(item->text());

	    if(m_chatWindows.contains(publicKeyHash))
	      {
		QPointer<spoton_chatwindow> chat =
		  m_chatWindows.value(publicKeyHash, 0);

		if(chat)
		  chat->setName(name);
	      }
	  }
      }
}

QList<QTableWidgetItem *> spoton::findItems(QTableWidget *table,
					    const QString &text,
					    const int column)
{
  if(column < 0 || !table)
    return QList<QTableWidgetItem *> ();

  QList<QTableWidgetItem *> list;

  for(int i = 0; i < table->rowCount(); i++)
    {
      QTableWidgetItem *item = table->item(i, column);

      if(!item)
	continue;

      if(item->text() == text)
	list.append(item);
    }

  return list;
}
