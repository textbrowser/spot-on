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

#ifndef _spoton_buzzpage_h_
#define _spoton_buzzpage_h_

#include <QPointer>
#include <QSslSocket>
#include <QTimer>
#include <QWidget>

#include "ui_spot-on-buzzpage.h"

class spoton_crypt;

class spoton_buzzpage: public QWidget
{
  Q_OBJECT

 public:
  spoton_buzzpage(QSslSocket *kernelSocket,
		  const QByteArray &channel,
		  const QByteArray &channelSalt,
		  const QByteArray &channelType,
		  const QByteArray &id,
		  const unsigned long iterationCount,
		  const QByteArray &hashKey,
		  const QByteArray &hashType,
		  const QByteArray &key,
		  QWidget *parent);
  ~spoton_buzzpage();
  QByteArray channel(void) const;
  QByteArray channelType(void) const;
  QByteArray hashKey(void) const;
  QByteArray hashType(void) const;
  QByteArray key(void) const;
  QString magnet(void) const;
  void userStatus(const QList<QByteArray> &list);
  void appendMessage(const QList<QByteArray> &list);

 private:
  QByteArray m_channel;
  QByteArray m_channelSalt;
  QByteArray m_channelType;
  QByteArray m_hashKey;
  QByteArray m_hashType;
  QByteArray m_id;
  QByteArray m_key; // Not stored in secure memory.
  QPointer<QSslSocket> m_kernelSocket;
  QTimer m_statusTimer;
  Ui_buzzPage ui;
  unsigned long m_iterationCount;

 private slots:
  void slotBuzzNameChanged(const QByteArray &name);
  void slotCopy(void);
  void slotRemove(void);
  void slotSave(void);
  void slotSendMessage(void);
  void slotSendStatus(void);
  void slotSetIcons(void);
  void slotStatusTimeout(void);

 signals:
  void changed(void);
  void channelSaved(void);
};

#endif
