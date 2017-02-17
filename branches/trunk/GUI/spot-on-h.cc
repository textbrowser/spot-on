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
#include "ui_spot-on-socket-options.h"

void spoton::slotSetListenerSocketOptions(void)
{
  QString oid("");
  QString socketOptions("");
  QString transport("");
  int row = -1;

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

  if(!(transport == "SCTP" || transport == "TCP" || transport == "UDP"))
    return;

  QDialog dialog(this);
  QStringList list(socketOptions.split(";", QString::SkipEmptyParts));
  Ui_spoton_socket_options ui;

  ui.setupUi(&dialog);
  ui.so_linger->setEnabled(transport != "UDP");
  dialog.setWindowTitle
    (tr("%1: Listener Socket Options").arg(SPOTON_APPLICATION_NAME));

  foreach(QString string, list)
    if(string.startsWith("so_linger="))
      ui.so_linger->setValue
	(string.mid(static_cast<int> (qstrlen("so_linger="))).toInt());

  if(dialog.exec() != QDialog::Accepted)
    return;

  socketOptions = QString("so_linger=%1").arg(ui.so_linger->value());

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE listeners SET socket_options = ? WHERE OID = ?");
	query.addBindValue(socketOptions);
	query.addBindValue(oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
