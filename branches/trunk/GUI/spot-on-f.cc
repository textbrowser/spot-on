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

void spoton::slotDuplicateTransmittedMagnet(void)
{
  QListWidgetItem *item = m_ui.transmittedMagnets->currentItem();

  if(!item)
    return;

  QString connectionName("");
  QString magnet(item->text());
  bool ok = false;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    goto done_label;

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

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    askKernelToReadStarBeamKeys();
}

void spoton::addMessageToQueue(const QString &message1,
			       const QByteArray &message2,
			       const QString &publicKeyHash)
{
  if(message1.isEmpty() || message2.isEmpty() || publicKeyHash.isEmpty())
    return;

  QPair<QQueue<QString>, QQueue<QByteArray> > pair
    (m_chatQueues.value(publicKeyHash));

  {
    QQueue<QString> queue(pair.first);

    if(queue.size() >= spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE)
      if(!queue.isEmpty())
	queue.dequeue();

    queue.enqueue(message1);
    pair.first = queue;
  }

  {
    QQueue<QByteArray> queue(pair.second);

    if(queue.size() >= spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE)
      if(!queue.isEmpty())
	queue.dequeue();

    queue.enqueue(message2);
    pair.second = queue;
  }

  m_chatQueues.insert(publicKeyHash, pair);
}

void spoton::slotReplayMessages(void)
{
  QTableWidgetItem *item = m_ui.participants->item
    (m_ui.participants->currentRow(), 3); // public_key_hash

  if(!item)
    return;

  if(!m_chatQueues.contains(item->text()))
    return;

  QDateTime now(QDateTime::currentDateTime());
  QQueue<QString> queue1(m_chatQueues.value(item->text()).first);
  QPointer<spoton_chatwindow> chat = m_chatWindows.value(item->text(), 0);
  QString msg("");

  msg.append
    (QString("[%1/%2/%3 %4:%5<font color=grey>:%6</font>] ").
     arg(now.toString("MM")).
     arg(now.toString("dd")).
     arg(now.toString("yyyy")).
     arg(now.toString("hh")).
     arg(now.toString("mm")).
     arg(now.toString("ss")));
  msg.append(tr("<i>Replay activated.</i>"));
  m_ui.messages->append(msg);

  if(chat)
    chat->append(msg);

  while(!queue1.isEmpty())
    {
      QString msg(queue1.dequeue());

      m_ui.messages->append(msg);
      m_ui.messages->verticalScrollBar()->setValue
	(m_ui.messages->verticalScrollBar()->maximum());

      if(chat)
	chat->append(msg);
    }

  QQueue<QByteArray> queue2(m_chatQueues.value(item->text()).second);

  while(!queue2.isEmpty())
    {
      QByteArray message(queue2.dequeue());

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotReplayMessages(): write() failure for "
		   "%1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_chatInactivityTimer.start();
    }

  m_chatQueues.remove(item->text());
}
