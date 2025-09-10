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

#ifndef _spoton_web_server_child_main_h_
#define _spoton_web_server_child_main_h_

#include <QObject>
#include <QSqlDatabase>

#include "Common/spot-on-crypt.h"

class spoton_web_server_child_main: public QObject
{
  Q_OBJECT

 public:
  spoton_web_server_child_main(QByteArray &settings);
  ~spoton_web_server_child_main();

 private:
  QByteArray m_search;
  QMap<QString, QVariant> m_settings;
  QScopedPointer<spoton_crypt> m_crypt;
  QSslSocket m_kernelSocket;
  QString m_emptyQuery;
  qint64 m_socketDescriptor;
  QSqlDatabase urlDatabase(QString &connectionName) const;
  void process(const QPair<QByteArray, QByteArray> &credentials);
  void process(QSslSocket *socket,
	       const QByteArray &data,
	       const QPair<QString, QString> &address);
  void processLocal(QSslSocket *socket, const QByteArray &data);
  void write(QSslSocket *socket, const QByteArray &data);
  void writeDefaultPage(QSslSocket *socket, const bool redirect = false);

 private slots:
  void slotKernelConnected(void);
  void slotKernelEncrypted(void);
  void slotKernelRead(void);
  void slotKeysReceived(void);

 signals:
  void keysReceived(void);
};

#endif
