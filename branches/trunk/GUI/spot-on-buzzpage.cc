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

#include <QClipboard>
#include <QDateTime>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QtCore/qmath.h>
#include <QtCore>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-buzzpage.h"
#include "spot-on-defines.h"
#include "spot-on.h"

spoton_buzzpage::spoton_buzzpage(QSslSocket *kernelSocket,
				 const QByteArray &channel,
				 const QByteArray &channelSalt,
				 const QByteArray &channelType,
				 const QByteArray &id,
				 const unsigned long int iterationCount,
				 const QByteArray &hashKey,
				 const QByteArray &hashType,
				 const QByteArray &key,
				 spoton *parent):QWidget(parent)
{
  ui.setupUi(this);
  m_channel = channel;
  m_parent = parent;

  if(m_channel.isEmpty())
    m_channel = "unknown";

  m_channelSalt = channelSalt;

  if(m_channelSalt.isEmpty())
    m_channelSalt = "unknown";

  m_channelType = channelType;

  if(m_channelType.isEmpty())
    m_channelType = "aes256";

  m_hashKey = hashKey;

  if(m_hashKey.isEmpty())
    m_hashKey = "unknown";

  m_hashType = hashType;

  if(m_hashType.isEmpty())
    m_hashType = "sha512";

  m_id = id.trimmed();
  m_iterationCount = qMax(static_cast<unsigned long int> (10000),
			  iterationCount);

  if(m_id.isEmpty())
    m_id = spoton_crypt::strongRandomBytes
      (spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();

  m_kernelSocket = kernelSocket;
  m_key = key;

  if(m_key.isEmpty())
    m_key = "unknown";

  QString error("");

  m_hashKeyGenerated = spoton_crypt::derivedSha1Key
    (spoton_crypt::sha512Hash(m_hashKey + m_hashType, 0),
     m_hashKey,
     112,
     m_iterationCount);
  m_statusTimer.start(30000);
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimeout(void)));
  connect(ui.clearMessages,
	  SIGNAL(clicked(void)),
	  ui.messages,
	  SLOT(clear(void)));
  connect(ui.copy,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopy(void)));
  connect(ui.favorite,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSave(void)));
  connect(ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.remove,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRemove(void)));
  connect(ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.unify,
	  SIGNAL(clicked(void)),
	  this,
	  SIGNAL(unify(void)));
  ui.clients->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  ui.clients->setColumnHidden(1, true); // ID
  ui.clients->setColumnHidden(2, true); // Time
#if QT_VERSION >= 0x050501
  ui.message->setPlaceholderText(tr("Please type a message..."));
#endif
  ui.splitter->setStretchFactor(0, 1);
  ui.splitter->setStretchFactor(1, 0);
  ui.unify->setVisible(false);

  QByteArray data;

  data.append("magnet:?");
  data.append(QString("rn=%1&").arg(m_channel.constData()));
  data.append(QString("xf=%1&").arg(m_iterationCount));
  data.append(QString("xs=%1&").arg(m_channelSalt.constData()));
  data.append(QString("ct=%1&").arg(m_channelType.constData()));
  data.append(QString("hk=%1&").arg(m_hashKey.constData()));
  data.append(QString("ht=%1&").arg(m_hashType.constData()));
  data.append("xt=urn:buzz");
  ui.magnet->setText(data);
  slotSetIcons();

  QByteArray name;
  QSettings settings;

  name = settings.value("gui/buzzName", "unknown").toByteArray();

  if(name.isEmpty())
    name = "unknown";

  QList<QByteArray> list;

  list << name
       << m_id
       << ""; // Artificial date.
  userStatus(list);
}

spoton_buzzpage::~spoton_buzzpage()
{
  m_key.replace(0, m_key.length(), 0);
  m_key.clear();
  m_statusTimer.stop();

  if(m_kernelSocket &&
     m_kernelSocket->state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket->isEncrypted() ||
       m_kernelSocket->property("key_size").toInt() == 0)
      {
	QByteArray message("removebuzz_");

	message.append(key().toBase64());
	message.append("\n");

	if(m_kernelSocket->write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton_buzzpage::~spoton_buzzpage(): write() failure "
		     "for %1:%2.").
	     arg(m_kernelSocket->peerAddress().toString()).
	     arg(m_kernelSocket->peerPort()));
      }
}

QByteArray spoton_buzzpage::channel(void) const
{
  return m_channel;
}

QByteArray spoton_buzzpage::channelType(void) const
{
  return m_channelType;
}

QByteArray spoton_buzzpage::hashKey(void) const
{
  return m_hashKeyGenerated.mid(0, 48);
}

QByteArray spoton_buzzpage::hashType(void) const
{
  return m_hashType;
}

QByteArray spoton_buzzpage::key(void) const
{
  return m_key;
}

QString spoton_buzzpage::magnet(void) const
{
  return ui.magnet->text();
}

void spoton_buzzpage::appendMessage(const QList<QByteArray> &list)
{
  if(list.size() != 4)
    return;

  QByteArray id
    (list.value(1).mid(0, spoton_common::BUZZ_MAXIMUM_ID_LENGTH).trimmed());

  if(id.isEmpty())
    id = spoton_crypt::
      strongRandomBytes(spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();

  if(id == m_id)
    /*
    ** Ignore myself.
    */

    return;

  QByteArray name
    (list.value(0).mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
  QByteArray message(list.value(2));
  QDateTime now(QDateTime::currentDateTime());
  QDateTime dateTime
    (QDateTime::fromString(list.value(3).constData(), "MMddyyyyhhmmss"));
  QString msg("");

  if(name.isEmpty() || name == "unknown")
    name = id.mid(0, 16) + "-unknown";

  if(message.isEmpty())
    message = "unknown";

  msg.append
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>]:").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append
    (QString("[%1/%2/%3 %4:%5"
	     "<font color=gray>:%6</font>] ").
     arg(dateTime.toString("MM")).
     arg(dateTime.toString("dd")).
     arg(dateTime.toString("yyyy")).
     arg(dateTime.toString("hh")).
     arg(dateTime.toString("mm")).
     arg(dateTime.toString("ss")));
  msg.append
    (QString("<font color=blue>%1: </font>").
     arg(QString::fromUtf8(name.constData(), name.length())));
  msg.append(QString::fromUtf8(message.constData(), message.length()));
  ui.messages->append(msg);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
  emit changed();
}

void spoton_buzzpage::showUnify(const bool state)
{
  ui.unify->setVisible(state);
}

void spoton_buzzpage::slotBuzzNameChanged(const QByteArray &name)
{
  QList<QByteArray> list;

  list << name
       << m_id
       << ""; // Artificial date.
  userStatus(list);
}

void spoton_buzzpage::slotCopy(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->setText(ui.magnet->text());
}

void spoton_buzzpage::slotRemove(void)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is a "
			       "fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  QString error("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QByteArray data;
	QSqlQuery query(db);

	data.append(m_channel.toBase64());
	data.append("\n");
	data.append
	  (QByteArray::number(static_cast<qulonglong> (m_iterationCount)).
	   toBase64());
	data.append("\n");
	data.append(m_channelSalt.toBase64());
	data.append("\n");
	data.append(m_channelType.toBase64());
	data.append("\n");
	data.append(m_hashKey.toBase64());
	data.append("\n");
	data.append(m_hashType.toBase64());
	data.append("\n");
	data.append(QByteArray("urn:buzz").toBase64());
	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM buzz_channels WHERE "
		      "data_hash = ?");
	query.bindValue(0, crypt->keyedHash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();

	if(query.lastError().isValid())
	  error = query.lastError().text();
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

  if(!ok)
    {
      if(error.isEmpty())
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error occurred while attempting to "
				 "remove the channel data. Please enable "
				 "logging via the Log Viewer and try again."));
      else
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error (%1) occurred while attempting to "
				 "remove the channel data.").arg(error));

      QApplication::processEvents();
    }
  else
    emit channelSaved();
}

void spoton_buzzpage::slotSave(void)
{
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  spoton::prepareDatabasesFromUI();

  QString connectionName("");
  QString error("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QByteArray data;
	QSqlQuery query(db);

	data.append(m_channel.toBase64());
	data.append("\n");
	data.append
	  (QByteArray::number(static_cast<qulonglong> (m_iterationCount)).
	   toBase64());
	data.append("\n");
	data.append(m_channelSalt.toBase64());
	data.append("\n");
	data.append(m_channelType.toBase64());
	data.append("\n");
	data.append(m_hashKey.toBase64());
	data.append("\n");
	data.append(m_hashType.toBase64());
	data.append("\n");
	data.append(QByteArray("urn:buzz").toBase64());
	query.prepare("INSERT OR REPLACE INTO buzz_channels "
		      "(data, data_hash) "
		      "VALUES (?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(data, &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();

	if(query.lastError().isValid())
	  error = query.lastError().text();
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

  if(!ok)
    {
      if(error.isEmpty())
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error occurred while attempting to "
				 "save the channel data. Please enable "
				 "logging via the Log Viewer and try again."));
      else
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error (%1) occurred while attempting to "
				 "save the channel data.").arg(error));

      QApplication::processEvents();
    }
  else
    emit channelSaved();
}

void spoton_buzzpage::slotSendMessage(void)
{
  QByteArray name;
  QByteArray sendMethod;
  QDateTime now(QDateTime::currentDateTime());
  QSettings settings;
  QString error("");
  QString message("");

  if(!m_kernelSocket)
    {
      error = tr("Empty kernel socket.");
      goto done_label;
    }
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket->isEncrypted() &&
	  m_kernelSocket->property("key_size").toInt() > 0)
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(ui.message->toPlainText().isEmpty())
    {
      error = tr("Please provide a real message.");
      goto done_label;
    }

  message.append
    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());

#if SPOTON_GOLDBUG == 1
  sendMethod = "Normal_POST";
#else
  if(ui.sendMethod->currentIndex() == 0)
    sendMethod = "Normal_POST";
  else
    sendMethod = "Artificial_GET";
#endif

  name = settings.value("gui/buzzName", "unknown").toByteArray();

  if(name.isEmpty())
    name = "unknown";

  {
    QByteArray message;

    message.append("buzz_");
    message.append(m_key.toBase64());
    message.append("_");
    message.append(m_channelType.toBase64());
    message.append("_");
    message.append(name.toBase64());
    message.append("_");
    message.append(m_id.toBase64());
    message.append("_");
    message.append(ui.message->toPlainText().toUtf8().toBase64());
    message.append("_");
    message.append(sendMethod.toBase64());
    message.append("_");
    message.append(m_hashKeyGenerated.toBase64());
    message.append("_");
    message.append(m_hashType.toBase64());
    message.append("_");
    message.append(QDateTime::currentDateTime().toUTC().
		   toString("MMddyyyyhhmmss").toLatin1().toBase64());
    message.append("\n");

    if(m_kernelSocket->write(message.constData(),
			     message.length()) != message.length())
      {
	error = tr("An error occurred while writing to the "
		   "kernel socket.");
	spoton_misc::logError
	  (QString("spoton_buzzpage::slotSendMessage(): "
		   "write() failure for %1:%2.").
	   arg(m_kernelSocket->peerAddress().toString()).
	   arg(m_kernelSocket->peerPort()));
	goto done_label;
      }
  }

  ui.message->clear();

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
}

void spoton_buzzpage::slotSendStatus(void)
{
  if(!m_kernelSocket)
    return;
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket->isEncrypted() &&
	  m_kernelSocket->property("key_size").toInt() > 0)
    return;

  QByteArray name;
  QByteArray message;
  QSettings settings;

  name = settings.value("gui/buzzName", "unknown").toByteArray();

  if(name.isEmpty())
    name = "unknown";

  message.clear();
  message.append("buzz_");
  message.append(m_key.toBase64());
  message.append("_");
  message.append(m_channelType.toBase64());
  message.append("_");
  message.append(name.toBase64());
  message.append("_");
  message.append(m_id.toBase64());
  message.append("_");
  message.append(m_hashKeyGenerated.toBase64());
  message.append("_");
  message.append(m_hashType.toBase64());
  message.append("_");
  message.append(QDateTime::currentDateTime().toUTC().
		 toString("MMddyyyyhhmmss").toLatin1().toBase64());
  message.append("\n");

  if(m_kernelSocket->write(message.constData(),
			   message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_buzzpage::slotSendStatus(): write() failure "
	       "for %1:%2.").
       arg(m_kernelSocket->peerAddress().toString()).
       arg(m_kernelSocket->peerPort()));
}

void spoton_buzzpage::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nouve").toString().
		  toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";

  ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

void spoton_buzzpage::slotStatusTimeout(void)
{
  QDateTime now(QDateTime::currentDateTime());

  for(int i = ui.clients->rowCount() - 1; i >= 0; i--)
    {
      QTableWidgetItem *item = ui.clients->item(i, 1);

      if(item && item->text() == m_id)
	continue;

      item = ui.clients->item(i, 2);

      if(item)
	{
	  QDateTime dateTime
	    (QDateTime::fromString(item->text(), Qt::ISODate));

	  if(qAbs(dateTime.secsTo(now)) >= 60)
	    {
	      QTableWidgetItem *item = ui.clients->item(i, 0);

	      if(item)
		{
		  QDateTime now(QDateTime::currentDateTime());
		  QString msg("");

		  msg.append
		    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
		     arg(now.toString("MM")).
		     arg(now.toString("dd")).
		     arg(now.toString("yyyy")).
		     arg(now.toString("hh")).
		     arg(now.toString("mm")).
		     arg(now.toString("ss")));
		  msg.append(tr("<i>%1 has left %2.</i>").
			     arg(item->text()).
			     arg(QString::fromUtf8(m_channel.constData(),
						   m_channel.length())));
		  ui.messages->append(msg);
		  ui.messages->verticalScrollBar()->setValue
		    (ui.messages->verticalScrollBar()->maximum());
		  emit changed();
		}

	      ui.clients->removeRow(i);
	    }
	}
    }
}

void spoton_buzzpage::unite(void)
{
  emit unify();
}

void spoton_buzzpage::userStatus(const QList<QByteArray> &list)
{
  if(list.size() != 3)
    return;

  QByteArray id
    (list.value(1).mid(0, spoton_common::BUZZ_MAXIMUM_ID_LENGTH).trimmed());

  if(id.isEmpty())
    id = spoton_crypt::
      strongRandomBytes(spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();

  QByteArray name
    (list.value(0).mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
  QList<QTableWidgetItem *> items
    (spoton::findItems(ui.clients, id, 1));

  if(name.isEmpty() || name == "unknown")
    name = id.mid(0, 16) + "-unknown";

  ui.clients->setSortingEnabled(false);

  if(items.isEmpty())
    {
      ui.clients->setRowCount(ui.clients->rowCount() + 1);

      QTableWidgetItem *item = 0;

      item = new QTableWidgetItem(QString::fromUtf8(name.constData(),
						    name.length()));
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);

      if(id == m_id)
	item->setBackground(QBrush(QColor(254, 229, 172)));

      item->setToolTip(id.mid(0, 16) + "..." + id.right(16));
      ui.clients->setItem(ui.clients->rowCount() - 1, 0, item);
      item = new QTableWidgetItem(QString(id));
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      ui.clients->setItem(ui.clients->rowCount() - 1, 1, item);
      item = new QTableWidgetItem
	(QDateTime::currentDateTime().toString(Qt::ISODate));
      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
      ui.clients->setItem(ui.clients->rowCount() - 1, 2, item);

      QDateTime now(QDateTime::currentDateTime());
      QString msg("");

      msg.append
	(QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
	 arg(now.toString("MM")).
	 arg(now.toString("dd")).
	 arg(now.toString("yyyy")).
	 arg(now.toString("hh")).
	 arg(now.toString("mm")).
	 arg(now.toString("ss")));
      msg.append(tr("<i>%1 has joined %2.</i>").
		 arg(QString::fromUtf8(name.constData(), name.length())).
		 arg(QString::fromUtf8(m_channel.constData(),
				       m_channel.length())));
      ui.messages->append(msg);
      ui.messages->verticalScrollBar()->setValue
	(ui.messages->verticalScrollBar()->maximum());
      emit changed();
    }
  else
    {
      for(int i = 0; i < items.size(); i++) // Counterfeit IDs.
	{
	  if(!items.at(i))
	    continue;

	  QTableWidgetItem *item = ui.clients->item(items.at(i)->row(), 0);

	  if(item)
	    {
	      if(item->text().toUtf8() != name)
		{
		  /*
		  ** Someone's name changed.
		  */

		  QDateTime now(QDateTime::currentDateTime());
		  QString msg("");

		  msg.append
		    (QString("[%1/%2/%3 %4:%5<font color=gray>:%6</font>] ").
		     arg(now.toString("MM")).
		     arg(now.toString("dd")).
		     arg(now.toString("yyyy")).
		     arg(now.toString("hh")).
		     arg(now.toString("mm")).
		     arg(now.toString("ss")));
		  msg.append(tr("<i>%1 is now known as %2.</i>").
			     arg(item->text()).
			     arg(QString::fromUtf8(name.constData(),
						   name.length())));
		  ui.messages->append(msg);
		  ui.messages->verticalScrollBar()->setValue
		    (ui.messages->verticalScrollBar()->maximum());
		  item->setText(QString::fromUtf8(name.constData(),
						  name.length()));
		  emit changed();
		}

	      /*
	      ** Update the client's time.
	      */

	      item = ui.clients->item(item->row(), 2);

	      if(item) // Not a critical change. Do not notify the UI.
		item->setText
		  (QDateTime::currentDateTime().toString(Qt::ISODate));
	    }
	}
    }

  ui.clients->setSortingEnabled(true);
  ui.clients->resizeColumnToContents(0);
  ui.clients->horizontalHeader()->setStretchLastSection(true);
}
