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

#ifndef _spoton_sctp_socket_h_
#define _spoton_sctp_socket_h_

#include <QAbstractSocket>
#include <QHostInfo>
#include <QObject>
#include <QTimer>

class spoton_sctp_socket: public QObject
{
  Q_OBJECT

 public:
  enum NetworkLayerProtocol
  {
    IPv4Protocol = QAbstractSocket::IPv4Protocol,
    IPv6Protocol = QAbstractSocket::IPv6Protocol
  };

  enum SocketError
  {
    ConnectionRefusedError = QAbstractSocket::ConnectionRefusedError,
    HostNotFoundError = QAbstractSocket::HostNotFoundError,
    NetworkError = QAbstractSocket::NetworkError,
    RemoteHostClosedError = QAbstractSocket::RemoteHostClosedError,
    SocketAccessError = QAbstractSocket::SocketAccessError,
    SocketResourceError = QAbstractSocket::SocketResourceError,
    SocketTimeoutError = QAbstractSocket::SocketTimeoutError,
    UnfinishedSocketOperationError =
    QAbstractSocket::UnfinishedSocketOperationError,
    UnknownSocketError = QAbstractSocket::UnknownSocketError,
    UnsupportedSocketOperationError =
    QAbstractSocket::UnsupportedSocketOperationError
  };

  enum SocketOption
  {
    LowDelayOption = QAbstractSocket::LowDelayOption
  };

  enum SocketState
  {
    ConnectedState = QAbstractSocket::ConnectedState,
    ConnectingState = QAbstractSocket::ConnectingState,
    HostLookupState = QAbstractSocket::HostLookupState,
    UnconnectedState = QAbstractSocket::UnconnectedState
  };

  spoton_sctp_socket(QObject *parent);
  ~spoton_sctp_socket();
  QByteArray readAll(void);
  QHostAddress localAddress(void) const;
  QHostAddress peerAddress(void) const;
  QString peerName(void) const;
  SocketState state(void) const;
  bool setSocketDescriptor(const int socketDescriptor);
  int socketDescriptor(void) const;
  qint64 write(const char *data, const qint64 maxSize);
  quint16 localPort(void) const;
  quint16 peerPort(void) const;
  void abort(void);
  void close(void);
  void connectToHost(const QString &hostName,
		     const quint16 port,
		     const QString &socketOptions);
  void setReadBufferSize(const qint64 size);
  void setSocketOption(const SocketOption option,
		       const QVariant &value);

 private:
  QByteArray m_readBuffer;
  QString m_connectToPeerName;
  QString m_ipAddress;
  QString m_socketOptions;
  QTimer m_timer;
  SocketState m_state;
  int m_hostLookupId;
  int m_socketDescriptor;
  qint64 m_readBufferSize;
  quint16 m_connectToPeerPort;
  QHostAddress localAddressAndPort(quint16 *port) const;
  QHostAddress peerAddressAndPort(quint16 *port) const;
  int inspectConnectResult(const int rc, const int errorcode);
  int setSocketBlockingOrNon(void);
  qint64 read(char *data, const qint64 maxSize);
  void connectToHostImplementation(void);

 private slots:
  void slotHostFound(const QHostInfo &hostInfo);
  void slotTimeout(void);

 signals:
  void connected(void);
  void disconnected(void);
  void error(const QString &method,
	     const spoton_sctp_socket::SocketError socketError);
  void readyRead(void);
};

#endif
