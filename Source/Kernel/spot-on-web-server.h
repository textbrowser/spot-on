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

#include <QPointer>
#include <QTcpServer>
#include <QThread>
#include <QTimer>

class QSslSocket;

class spoton_web_server_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_web_server_tcp_server(QObject *parent):QTcpServer(parent)
  {
  }

  ~spoton_web_server_tcp_server()
  {
  }

  QByteArray certificate(void) const
  {
    return m_certificate;
  }

  QByteArray privateKey(void) const
  {
    return m_privateKey;
  }

  void clear(void)
  {
    m_certificate.clear();
    m_privateKey.clear();
  }

  void incomingConnection(qintptr socketDescriptor);

  void setCertificate(const QByteArray &certificate)
  {
    m_certificate = certificate;
  }

  void setPrivateKey(const QByteArray &privateKey)
  {
    m_privateKey = privateKey;
  }

 private:
  QByteArray m_certificate;
  QByteArray m_privateKey;

 signals:
  void newConnection(const qint64 socketDescriptor);
};

class spoton_web_server_tcp_server;

class spoton_web_server: public QObject
{
  Q_OBJECT

 public:
  spoton_web_server(QObject *parent);
  ~spoton_web_server();
  int httpClientCount(void) const;
  int httpsClientCount(void) const;

 private:
  QAtomicInt *m_abort;
  QAtomicInt *m_httpClientCount;
  QAtomicInt *m_httpsClientCount;
  QPointer<spoton_web_server_tcp_server> m_http;
  QPointer<spoton_web_server_tcp_server> m_https;
  QTimer m_generalTimer;

 private slots:
  void slotHttpClientConnected(const qint64 socketDescriptor);
  void slotHttpThreadFinished(void);
  void slotHttpsClientConnected(const qint64 socketDescriptor);
  void slotHttpsThreadFinished(void);
  void slotTimeout(void);
};

class spoton_web_server_thread: public QThread
{
  Q_OBJECT

 public:
  spoton_web_server_thread(QAtomicInt *atomicInt,
			   QObject *parent,
			   const QPair<QByteArray, QByteArray> &credentials,
			   const qint64 socketDescriptor):QThread(parent)
  {
    m_abort = atomicInt;
    m_credentials = credentials;
    m_socketDescriptor = socketDescriptor;
  }

 protected:
  void run(void);

 private:
  QAtomicInt *m_abort;
  QPair<QByteArray, QByteArray> m_credentials;
  qint64 m_socketDescriptor;
  void process(const QPair<QByteArray, QByteArray> &credentials,
	       const qint64 socketDescriptor);
  void process(QSslSocket *socket,
	       const QByteArray &data,
	       const QPair<QString, QString> &address);
  void processLocal(QSslSocket *socket, const QByteArray &data);
  void write(QSslSocket *socket, const QByteArray &data);
  void writeDefaultPage(QSslSocket *socket, const bool redirect = false);
};

#endif
