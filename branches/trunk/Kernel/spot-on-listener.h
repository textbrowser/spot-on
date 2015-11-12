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
#if QT_VERSION >= 0x050200
#include <qbluetoothlocaldevice.h>
#include <qbluetoothserver.h>
#include <qbluetoothserviceinfo.h>
#include <qbluetoothsocket.h>
#endif

#include "Common/spot-on-misc.h"
#include "spot-on-neighbor.h"

class QNetworkInterface;

class spoton_external_address;
class spoton_sctp_server;

class spoton_listener_bluetooth_server: public QObject
{
  Q_OBJECT

 public:
  spoton_listener_bluetooth_server(const qint64 id, QObject *parent);

  ~spoton_listener_bluetooth_server()
  {
  }

#if QT_VERSION >= 0x050200
  QBluetoothSocket *nextPendingConnection(void)
  {
    return m_server->nextPendingConnection();
  }
#endif

  QString errorString(void)
  {
#if QT_VERSION >= 0x050200
    return QString("%1").arg(m_server->error());
#else
    return "";
#endif
  }

  bool isListening(void) const
  {
#if QT_VERSION >= 0x050200
    return m_server->isListening() && m_serviceInfo.isRegistered();
#else
    return false;
#endif
  }

  bool listen(const QString &address, const quint16 port);

  int maxPendingConnections(void) const
  {
#if QT_VERSION >= 0x050200
    return m_server->maxPendingConnections();
#else
    return 0;
#endif
  }

  void close(void)
  {
#if QT_VERSION >= 0x050200
    m_serviceInfo.unregisterService();
    m_server->close();
#endif
  }

  void setMaxPendingConnections(const int maxPendingConnections)
  {
#if QT_VERSION >= 0x050200
    m_server->setMaxPendingConnections(qMax(1, maxPendingConnections));
#else
    Q_UNUSED(maxPendingConnections);
#endif
  }

 private:
#if QT_VERSION >= 0x050200
  QBluetoothServer *m_server;
  QBluetoothServiceInfo m_serviceInfo;
#endif
  qint64 m_id;

 signals:
  void newConnection(void);
};

class spoton_listener_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_listener_tcp_server(const qint64 id,
			     QObject *parent):QTcpServer(parent)
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

#if QT_VERSION >= 0x050000
  void incomingConnection(qintptr socketDescriptor);
#else
  void incomingConnection(int socketDescriptor);
#endif

 private:
  qint64 m_id;

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

class spoton_listener_udp_server: public QUdpSocket
{
  Q_OBJECT

 public:
  spoton_listener_udp_server(const qint64 id,
			     QObject *parent):QUdpSocket(parent)
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
#if QT_VERSION < 0x050000
  void newConnection(const int socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
#else
  void newConnection(const qintptr socketDescriptor,
		     const QHostAddress &address,
		     const quint16 port);
#endif
  void newDatagram(const QByteArray &datagram);
};

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
		  const int keySize,
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
		  QObject *parent);
  ~spoton_listener();
  QHostAddress externalAddress(void) const;
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
  QByteArray m_certificate;
  QByteArray m_privateKey;
  QByteArray m_publicKey;
  QNetworkInterface *m_networkInterface;
  QString m_address;
  QString m_echoMode;
  QString m_motd;
  QString m_orientation;
  QString m_scopeId;
  QString m_sslControlString;
  QString m_transport;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_timer;
  bool m_shareAddress;
  bool m_useAccounts;
  int m_keySize;
  int m_laneWidth;
  int m_maximumClients;
  qint64 m_id;
  qint64 m_maximumBufferSize;
  qint64 m_maximumContentLength;
  quint16 m_externalPort;
  quint16 m_port;
  spoton_external_address *m_externalAddress;
  spoton_listener_bluetooth_server *m_bluetoothServer;
  spoton_listener_tcp_server *m_tcpServer;
  spoton_listener_udp_server *m_udpServer;
  spoton_sctp_server *m_sctpServer;
  QString errorString(void) const;
  int maxPendingConnections(void) const;
  qint64 id(void) const;
  void prepareNetworkInterface(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db);

 private slots:
  void slotDiscoverExternalAddress(void);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotNeighborDisconnected(void);
#if QT_VERSION < 0x050000
  void slotNewConnection(const int socketDescriptor,
			 const QHostAddress &address,
			 const quint16 port);
#else
  void slotNewConnection(const qintptr socketDescriptor,
			 const QHostAddress &address,
			 const quint16 port);
#endif
#if QT_VERSION >= 0x050200
  void slotNewConnection(void);
#endif
  void slotTimeout(void);

 signals:
  void newNeighbor(QPointer<spoton_neighbor> neighbor);
};

#endif
