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

#include <limits>

#include "spot-on.h"
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

  QDialog dialog(this);
  QStringList list(socketOptions.split(";", QString::SkipEmptyParts));
  Ui_spoton_socket_options ui;

  ui.setupUi(&dialog);
  ui.so_linger->setEnabled(transport != "BLUETOOTH" && transport != "UDP");
  ui.so_rcvbuf->setEnabled(transport != "BLUETOOTH");
  ui.so_rcvbuf->setMaximum(std::numeric_limits<int>::max());
  ui.so_sndbuf->setEnabled(transport != "BLUETOOTH");
  ui.so_sndbuf->setMaximum(std::numeric_limits<int>::max());

  if(type == "listeners")
    dialog.setWindowTitle
      (tr("%1: Listener Socket Options").arg(SPOTON_APPLICATION_NAME));
  else
    dialog.setWindowTitle
      (tr("%1: Neighbor Socket Options").arg(SPOTON_APPLICATION_NAME));

#if QT_VERSION >= 0x050300 && defined(SPOTON_BLUETOOTH_ENABLED)
  ui.so_rcvbuf->setEnabled(true);
  ui.so_sndbuf->setEnabled(true);

  foreach(QString string, list)
    if(string.startsWith("so_rcvbuf="))
      ui.so_rcvbuf->setValue
	(string.mid(static_cast<int> (qstrlen("so_rcvbuf="))).toInt());
    else if(string.startsWith("so_sndbuf="))
      ui.so_sndbuf->setValue
	(string.mid(static_cast<int> (qstrlen("so_sndbuf="))).toInt());
#else
  foreach(QString string, list)
    if(string.startsWith("so_linger="))
      {
	if(transport != "UDP")
	  ui.so_linger->setValue
	    (string.mid(static_cast<int> (qstrlen("so_linger="))).toInt());
      }
    else if(string.startsWith("so_rcvbuf="))
      {
	if(transport != "BLUETOOTH")
	  ui.so_rcvbuf->setValue
	    (string.mid(static_cast<int> (qstrlen("so_rcvbuf="))).toInt());
      }
    else if(string.startsWith("so_sndbuf="))
      {
	if(transport != "BLUETOOTH")
	  ui.so_sndbuf->setValue
	    (string.mid(static_cast<int> (qstrlen("so_sndbuf="))).toInt());
      }
#endif

  if(dialog.exec() != QDialog::Accepted)
    return;

  socketOptions = QString("so_linger=%1").arg(ui.so_linger->value());
  socketOptions.append(";");
  socketOptions.append(QString("so_rcvbuf=%1").arg(ui.so_rcvbuf->value()));
  socketOptions.append(";");
  socketOptions.append(QString("so_sndbuf=%1").arg(ui.so_sndbuf->value()));

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
