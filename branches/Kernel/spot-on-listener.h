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

#ifndef _spoton_listener_h_
#define _spoton_listener_h_

#include <QHash>
#include <QPointer>
#include <QSqlDatabase>
#include <QTcpServer>
#include <QTimer>
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
#include <QWebSocketServer>
#endif
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <qbluetoothserver.h>
#include <qbluetoothserviceinfo.h>
#include <qbluetoothsocket.h>
#endif

#include "spot-on-neighbor.h"

class QNetworkInterface;
class spoton_external_address;
class spoton_sctp_server;

class spoton_listener_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_listener_tcp_server(const qint64 id, QObject *parent):
    QTcpServer(parent)
  {
    m_id = id;
  }

  ~spoton_listener_tcp_server()
  {
  }

  void setMaxPendingConnections(const int maxPendingConnections)
  {
    QTcpServer::setMaxPendingConnections(qMax(1, maxPendingConnections));
  }

  void incomingConnection(qintptr socketDescriptor);

 private:
  qint64 m_id;

 signals:
  void newConnection(const qintptr socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
};

class spoton_listener_udp_server: public QUdpSocket
{
  Q_OBJECT

 public:
  spoton_listener_udp_server(const qint64 id, QObject *parent):
    QUdpSocket(parent)
  {
    m_id = id;
    m_maxPendingConnections = 5;
    connect(this,
	    SIGNAL(readyRead(void)),
	    this,
	    SLOT(slotReadyRead(void)));
  }

  ~spoton_listener_udp_server()
  {
  }

  bool clientExists(const QHostAddress &address, const quint16 port) const
  {
    return m_clients.contains(QString("%1:%2:%3").
			      arg(address.toString()).
			      arg(address.scopeId()).
			      arg(port));
  }

  int maxPendingConnections(void) const
  {
    return m_maxPendingConnections;
  }

  void addClientAddress(const QString &address)
  {
    m_clients.insert(address, 0);
  }

  void setMaxPendingConnections(const int maxPendingConnections)
  {
    m_maxPendingConnections = qMax(1, maxPendingConnections);
  }

 private:
  QHash<QString, char> m_clients;
  int m_maxPendingConnections;
  qint64 m_id;

 private slots:
  void slotClientDestroyed(QObject *object)
  {
    if(!object)
      return;

    QString client(object->property("address").toString());

    m_clients.remove(client);
  }

  void slotReadyRead(void);

 signals:
  void newConnection(const qintptr socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
  void newDatagram(const QByteArray &datagram,
		   const QHostAddress &address,
		   const quint16 port);
};

#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
class spoton_listener_websocket_server: public QWebSocketServer
{
 public:
  spoton_listener_websocket_server(const QWebSocketServer::SslMode sslMode,
				   const qint64 id,
				   QObject *parent):
    QWebSocketServer(QString::number(id), sslMode, parent)
  {
    m_id = id;
  }

  ~spoton_listener_websocket_server()
  {
  }

  void setMaxPendingConnections(const int maxPendingConnections)
  {
    QWebSocketServer::setMaxPendingConnections(qMax(1, maxPendingConnections));
  }

 private:
  qint64 m_id;
};
#endif

class spoton_listener: public QObject
{
  Q_OBJECT

 public:
  spoton_listener(const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const int maximumClients,
		  const qint64 id,
		  const QString &echoMode,
		  const unsigned int keySize,
		  const QByteArray &certificate,
		  const QByteArray &privateKey,
		  const QByteArray &publicKey,
		  const bool useAccounts,
		  const qint64 maximumBufferSize,
		  const qint64 maximumContentLength,
		  const QString &transport,
		  const bool shareAddress,
		  const QString &orientation,
		  const QString &motd,
		  const QString &sslControlString,
		  const int laneWidth,
		  const int passthrough,
		  const int sourceOfRandomness,
		  const QByteArray &privateApplicationCredentials,
		  const QString &socketOptions,
		  QObject *parent);
  ~spoton_listener();
  QHostAddress externalAddress(void) const;
  QHostAddress localAddress(void) const;
  QString orientation(void) const;
  QString serverAddress(void) const;
  QString transport(void) const;
  bool isListening(void) const;
  bool listen(const QString &address, const quint16 port);
  quint16 externalPort(void) const;
  quint16 serverPort(void) const;
  void close(void);
  void updateConnectionCount(void);

 private:
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  QBluetoothServiceInfo *m_bluetoothServiceInfo;
#endif
  QByteArray m_certificate;
  QByteArray m_privateApplicationCredentials;
  QByteArray m_privateKey;
  QByteArray m_publicKey;
  QNetworkInterface *m_networkInterface;
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  QPointer<QBluetoothServer> m_bluetoothServer;
#endif
  QPointer<spoton_external_address> m_externalAddress;
  QPointer<spoton_listener_tcp_server> m_tcpServer;
  QPointer<spoton_listener_udp_server> m_udpServer;
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  QPointer<spoton_listener_websocket_server> m_webSocketServer;
#endif
  QPointer<spoton_sctp_server> m_sctpServer;
  QString m_address;
  QString m_echoMode;
  QString m_motd;
  QString m_orientation;
  QString m_scopeId;
  QString m_socketOptions;
  QString m_sslControlString;
  QString m_transport;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_timer;
  bool m_shareAddress;
  bool m_useAccounts;
  int m_laneWidth;
  int m_maximumClients;
  int m_passthrough;
  int m_sourceOfRandomness;
  qint64 m_id;
  qint64 m_maximumBufferSize;
  qint64 m_maximumContentLength;
  quint16 m_externalPort;
  quint16 m_port;
  unsigned int m_keySize;
  QString errorString(void) const;
  int maxPendingConnections(void) const;
  qint64 id(void) const;
  void closeIfFull(void);
  void prepareNetworkInterface(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db);

 private slots:
  void slotDiscoverExternalAddress(void);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotNeighborDisconnected(void);
  void slotNewConnection(const qintptr socketDescriptor,
			 const QHostAddress &address,
			 const quint16 port);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  void slotNewConnection(void);
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  void slotNewWebSocketConnection(void);
#endif
  void slotTimeout(void);

 signals:
  void newNeighbor(const QPointer<spoton_neighbor> &neighbor);
};

#endif
