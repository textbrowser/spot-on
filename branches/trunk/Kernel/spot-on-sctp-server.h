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

#ifndef _spoton_sctp_server_h_
#define _spoton_sctp_server_h_

#include <QHostInfo>
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
#include <QSocketNotifier>
#else
#include <QTimer>
#endif

class spoton_sctp_server: public QObject
{
  Q_OBJECT

 public:
  spoton_sctp_server(const qint64 id, QObject *parent);
  ~spoton_sctp_server();
  QHostAddress serverAddress(void) const;
  QString errorString(void) const;
  bool isListening(void) const;
  bool listen(const QHostAddress &address,
	      const quint16 port,
	      const QString &socketOptions);
  int maxPendingConnections(void) const;
  int socketDescriptor(void) const;
  quint16 serverPort(void) const;
  void close(void);
  void setMaxPendingConnections(const int numConnections);

 private:
  QHostAddress m_serverAddress;
  QString m_errorString;
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  QSocketNotifier *m_socketNotifier;
#else
  QTimer m_timer;
#endif
  bool m_isListening;
  int m_backlog;
#if defined(Q_OS_WIN)
  SOCKET m_socketDescriptor;
#else
  int m_socketDescriptor;
#endif
  qint64 m_id;
  quint16 m_serverPort;

 private slots:
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  void slotActivated(int socketDescriptor);
#else
  void slotTimeout(void);
#endif

 signals:
#if QT_VERSION < 0x050000
  void newConnection(const int socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
#else
  void newConnection(const qintptr socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
#endif
};

#endif
