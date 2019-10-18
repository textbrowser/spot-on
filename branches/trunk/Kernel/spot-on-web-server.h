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

#ifndef _spoton_web_server_h_
#define _spoton_web_server_h_

#include <QFuture>
#include <QPointer>
#include <QQueue>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QTcpServer>
#include <QTimer>

class spoton_web_server_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_web_server_tcp_server(QObject *parent):QTcpServer(parent)
  {
  }

  ~spoton_web_server_tcp_server()
  {
    while(!m_queue.isEmpty())
      {
	QPointer<QSslSocket> socket = m_queue.dequeue();

	if(socket)
	  socket->deleteLater();
      }
  }

  QSslSocket *nextPendingConnection(void)
  {
    if(m_queue.isEmpty())
      return 0;
    else
      return m_queue.dequeue();
  }

#if QT_VERSION < 0x050000
  void incomingConnection(int socketDescriptor);
#else
  void incomingConnection(qintptr socketDescriptor);
#endif

 private:
  QQueue<QPointer<QSslSocket> > m_queue;

 protected:
  QByteArray m_certificate;
  QByteArray m_privateKey;

 signals:
  void modeChanged(QSslSocket::SslMode mode);
  void newConnection(void);
};

class spoton_web_server: public spoton_web_server_tcp_server
{
  Q_OBJECT

 public:
  spoton_web_server(QObject *parent);
  ~spoton_web_server();
  int clientCount(void) const;

 private:
#if QT_VERSION < 0x050000
  QHash<int, QByteArray> m_webSocketData;
  QHash<int, QFuture<void> > m_futures;
#else
  QHash<qintptr, QByteArray> m_webSocketData;
  QHash<qintptr, QFuture<void> > m_futures;
#endif
  QTimer m_generalTimer;
  QSqlDatabase database(void) const;
  void process(QSslSocket *socket,
	       const QByteArray &data,
	       const QPair<QString, QString> &address);
  void processLocal(QSslSocket *socket, const QByteArray &data);

 private slots:
  void slotClientConnected(void);
  void slotClientDisconnected(void);
  void slotFinished(QSslSocket *socket, const QByteArray &data);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotReadyRead(void);
  void slotTimeout(void);

 signals:
  void finished(QSslSocket *socket, const QByteArray &data);
};

#endif
