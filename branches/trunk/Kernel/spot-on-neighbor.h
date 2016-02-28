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

#ifndef _spoton_neighbor_h_
#define _spoton_neighbor_h_

#include <QAtomicInt>
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
#include <qbluetoothsocket.h>
#endif
#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkProxy>
#include <QPointer>
#include <QReadWriteLock>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QThread>
#include <QTimer>
#include <QUdpSocket>
#include <QUuid>

#include "Common/spot-on-common.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-sctp-socket.h"

class spoton_neighbor_tcp_socket: public QSslSocket
{
  Q_OBJECT

 public:
  spoton_neighbor_tcp_socket(QObject *parent = 0):QSslSocket(parent)
  {
  }

  void setLocalAddress(const QHostAddress &address)
  {
    QSslSocket::setLocalAddress(address);
  }
};

class spoton_neighbor_udp_socket: public QUdpSocket
{
  Q_OBJECT

 public:
  spoton_neighbor_udp_socket(QObject *parent = 0):QUdpSocket(parent)
  {
    m_multicastSocket = 0;
  }

  void initializeMulticast(const QHostAddress &address, const quint16 port)
  {
    if(address.protocol() == QAbstractSocket::IPv4Protocol)
      {
	quint32 a = address.toIPv4Address();

	if(!((a & 0xf0000000) == 0xe0000000))
	  return;
      }
    else if(address.protocol() == QAbstractSocket::IPv6Protocol)
      {
#ifdef Q_OS_OS2
	return;
#endif

	Q_IPV6ADDR a6 = address.toIPv6Address();

	if(a6.c[0] != 0xff)
	  return;
      }
    else
      return;

    if(m_multicastSocket)
      m_multicastSocket->deleteLater();

    m_multicastSocket = new (std::nothrow) QUdpSocket(this);

    if(m_multicastSocket)
      {
	if(!m_multicastSocket->bind(address, port,
				    QUdpSocket::ReuseAddressHint |
				    QUdpSocket::ShareAddress))
	  {
	    m_multicastSocket->deleteLater();
	    spoton_misc::logError
	      (QString("spoton_neighbor_udp_socket::initializeMulticast(): "
		       "bind() failure for %1:%2.").
	       arg(address.toString()).arg(port));
	    return;
	  }

#if QT_VERSION >= 0x040800
	if(!m_multicastSocket->joinMulticastGroup(address))
	  {
	    m_multicastSocket->deleteLater();
	    spoton_misc::logError
	      (QString("spoton_neighbor_udp_socket::initializeMulticast(): "
		       "joinMulticastGroup() failure for %1:%2.").
	       arg(address.toString()).arg(port));
	  }
	else
	  m_multicastSocket->setSocketOption
	    (QAbstractSocket::MulticastLoopbackOption, 0);
#else
	if(!spoton_misc::joinMulticastGroup(address,
					    0, // Disable loopback.
					    m_multicastSocket->
					    socketDescriptor(),
					    port))
	  m_multicastSocket->deleteLater();
#endif
      }
  }

  QPointer<QUdpSocket> multicastSocket(void) const
  {
    return m_multicastSocket;
  }

  void setLocalAddress(const QHostAddress &address)
  {
    QUdpSocket::setLocalAddress(address);
  }

  void setLocalPort(quint16 port)
  {
    QUdpSocket::setLocalPort(port);
  }

  void setPeerAddress(const QHostAddress &address)
  {
    QUdpSocket::setPeerAddress(address);
  }

  void setPeerPort(quint16 port)
  {
    QUdpSocket::setPeerPort(port);
  }

  void setSocketState(QAbstractSocket::SocketState state)
  {
    QUdpSocket::setSocketState(state);
  }

 private:
  QPointer<QUdpSocket> m_multicastSocket;
};

class spoton_neighbor: public QThread
{
  Q_OBJECT

 public:
  spoton_neighbor(void)
  {
  }

  spoton_neighbor(const QNetworkProxy &proxy,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const qint64 id,
		  const bool userDefined,
		  const int keySize,
		  const qint64 maximumBufferSize,
		  const qint64 maximumContentLength,
		  const QString &echoMode,
		  const QByteArray &peerCertificate,
		  const bool allowExceptions,
		  const QString &protocol,
		  const bool requireSsl,
		  const QByteArray &accountName,
		  const QByteArray &accountPassword,
		  const QString &transport,
		  const QString &orientation,
		  const QString &motd,
		  const QString &statusControl,
		  const QString &sslControlString,
		  const Priority priority,
		  const int laneWidth,
		  const int passthrough,
		  QObject *parent);
  spoton_neighbor(
#if QT_VERSION < 0x050000
		  const int socketDescriptor,
#else
		  const qintptr socketDescriptor,
#endif
		  const QByteArray &certificate,
		  const QByteArray &privateKey,
		  const QString &echoMode,
		  const bool useAccounts,
		  const qint64 listenerOid,
		  const qint64 maximumBufferSize,
		  const qint64 maximumContentLength,
		  const QString &transport,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &localIpAddress,
		  const QString &localPort,
		  const QString &orientation,
		  const QString &motd,
		  const QString &sslControlString,
		  const Priority priority,
		  const int laneWidth,
		  const int passthrough,
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
		  QBluetoothSocket *socket,
#endif
		  QObject *parent);
  ~spoton_neighbor();
  QAbstractSocket::SocketState state(void) const;
  QString localAddress(void) const;
  QString peerAddress(void) const;

  QString scopeId(void) const
  {
    return m_scopeId;
  }

  QString transport(void) const;
  QUuid receivedUuid(void);
  bool isEncrypted(void) const;
  bool writeMessage0060(const QByteArray &data);
  qint64 id(void) const;
  qint64 write(const char *data, qint64 size);
  quint16 peerPort(void) const;
  void abort(void);
  void close(void);
  void processData(void);
  void setId(const qint64 id);

 private:
  QAtomicInt m_abort;
  QAtomicInt m_accountAuthenticated;
  QAtomicInt m_kernelInterfaces;
  QAtomicInt m_passthrough;
  QAtomicInt m_useAccounts;
  QByteArray m_accountName;
  QByteArray m_accountPassword;
  QByteArray m_accountClientSentSalt;
  QByteArray m_data;
  QDateTime m_lastReadTime;
  QDateTime m_startTime;
  QList<QPair<QByteArray, QByteArray> > m_learnedAdaptiveEchoPairs;
  QPair<QByteArray, QByteArray> m_adaptiveEchoPair;
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
  QPointer<QBluetoothSocket> m_bluetoothSocket;
#else
  QPointer<QObject> m_bluetoothSocket;
#endif
  QReadWriteLock m_accountClientSentSaltMutex;
  QReadWriteLock m_accountNameMutex;
  QReadWriteLock m_accountPasswordMutex;
  QReadWriteLock m_bytesWrittenMutex;
  QReadWriteLock m_dataMutex;
  QReadWriteLock m_echoModeMutex;
  QReadWriteLock m_learnedAdaptiveEchoPairsMutex;
  QReadWriteLock m_maximumBufferSizeMutex;
  QReadWriteLock m_maximumContentLengthMutex;
  QReadWriteLock m_receivedUuidMutex;
  QSslCertificate m_peerCertificate;
  QString m_address;
  QString m_echoMode;
  QString m_ipAddress;
  QString m_motd;
  QString m_orientation;
  QString m_protocol;
  QString m_scopeId;
  QString m_sslControlString;
  QString m_statusControl;
  QString m_transport;
  QTimer m_accountTimer;
  QTimer m_authenticationTimer;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_keepAliveTimer;
  QTimer m_lifetime;
  QTimer m_timer;
  QUuid m_receivedUuid;
  bool m_allowExceptions;
  bool m_isUserDefined;
  bool m_requireSsl;
  bool m_useSsl;
  int m_keySize;
  int m_laneWidth;
  qint64 m_id;
  qint64 m_listenerOid;
  qint64 m_maximumBufferSize;
  qint64 m_maximumContentLength;
  quint64 m_bytesRead;
  quint64 m_bytesWritten;
  quint16 m_port;
  spoton_external_address *m_externalAddress;
  spoton_neighbor_tcp_socket *m_tcpSocket;
  spoton_neighbor_udp_socket *m_udpSocket;
  spoton_sctp_socket *m_sctpSocket;
  QString findMessageType
    (const QByteArray &data,
     QList<QByteArray> &symmetricKeys,
     QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  bool readyToWrite(void);
  void addToBytesWritten(const qint64 bytesWritten);
  void process0000(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0000a(int length, const QByteArray &data,
		    const QString &messageType);
  void process0000b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0000d(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0001a(int length, const QByteArray &data);
  void process0001b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0001c(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0002a(int length, const QByteArray &data,
		    const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  void process0002b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys,
		    const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  void process0011(int length, const QByteArray &data);
  void process0012(int length, const QByteArray &data);
  void process0013(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0014(int length, const QByteArray &data);
  void process0030(int length, const QByteArray &data);
  void process0040a(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0040b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0050(int length, const QByteArray &data);
  void process0051(int length, const QByteArray &data);
  void process0065(int length, const QByteArray &data);
  void process0070(int length, const QByteArray &data);
  void process0080(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0090(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0091a(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0091b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void recordCertificateOrAbort(void);
  void run(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveGemini(const QByteArray &publicKeyHash,
		  const QByteArray &gemini,
		  const QByteArray &geminiHashKey,
		  const QByteArray &timestamp,
		  const QByteArray &signature,
		  const QString &messageType);
  void saveParticipantStatus(const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash,
			     const QByteArray &status,
			     const QByteArray &timestamp);
  void savePublicKey(const QByteArray &keyType,
		     const QByteArray &name,
		     const QByteArray &publicKey,
		     const QByteArray &signature,
		     const QByteArray &sPublicKey,
		     const QByteArray &sSignature,
		     const qint64 neighborOid,
		     const bool ignore_key_permissions = false);
  void saveStatistics(const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db, const QString &status);
  void saveStatus(const QString &status);
  void saveUrlsToShared(const QList<QByteArray> &urls);
  void storeLetter(const QByteArray &symmetricKey,
		   const QByteArray &symmetricKeyAlgorithm,
		   const QByteArray &hashKey,
		   const QByteArray &hashKeyAlgorithm,
		   const QByteArray &senderPublicKeyHash,
		   const QByteArray &name,
		   const QByteArray &subject,
		   const QByteArray &message,
		   const QByteArray &attachment,
		   const QByteArray &attachmentName,
		   const QByteArray &signature,
		   const bool goldbugUsed);
  void storeLetter(const QList<QByteArray> &list,
		   const QByteArray &recipientHash);

 private slots:
  void slotAccountAuthenticated(const QByteArray &name,
				const QByteArray &password);
  void slotAuthenticationTimerTimeout(void);
  void slotCallParticipant(const QByteArray &data,
			   const QString &messageType);
  void slotConnected(void);
  void slotDisconnected(void);
  void slotDiscoverExternalAddress(void);
  void slotEchoKeyShare(const QByteArrayList &list);
  void slotEncrypted(void);
  void slotError(QAbstractSocket::SocketError error);
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
  void slotError(QBluetoothSocket::SocketError error);
#endif
  void slotError(const QString &method,
		 const spoton_sctp_socket::SocketError error);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotHostFound(const QHostInfo &hostInfo);
  void slotLifetimeExpired(void);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotNewDatagram(const QByteArray &datagram);
  void slotPeerVerifyError(const QSslError &error);
  void slotProxyAuthenticationRequired(const QNetworkProxy &proxy,
				       QAuthenticator *authenticator);
  void slotPublicizeListenerPlaintext(const QByteArray &data,
				      const qint64 id);
  void slotPublicizeListenerPlaintext(const QHostAddress &address,
				      const quint16 port,
				      const QString &transport,
				      const QString &orientation);
  void slotReadyRead(void);
  void slotResetKeepAlive(void);
  void slotRetrieveMail(const QByteArrayList &list,
			const QString &messageType);
  void slotSendAccountInformation(void);
  void slotSendAuthenticationRequest(void);
  void slotSendBuzz(const QByteArray &data);
  void slotSendCapabilities(void);
  void slotSendForwardSecrecyPublicKey(const QByteArray &data);
  void slotSendForwardSecrecySessionKeys(const QByteArray &data);
  void slotSendMOTD(void);
  void slotSendMail(const QPairByteArrayInt64List &list,
		    const QString &messageType);
  void slotSendMailFromPostOffice
    (const QByteArray &data,
     const QPairByteArrayByteArray &adaptiveEchoPair);
  void slotSendMessage(const QByteArray &data,
		       const spoton_send::spoton_send_method sendMethod);
  void slotSendStatus(const QByteArrayList &list);
  void slotSslErrors(const QList<QSslError> &errors);
  void slotStopTimer(QTimer *timer);
  void slotTimeout(void);
  void slotWrite(const QByteArray &data, const qint64 id,
		 const QPairByteArrayByteArray &adaptiveEchoPair);
  void slotWriteURLs(const QByteArray &data);

 public slots:
  void deleteLater(void);
  void slotSharePublicKey(const QByteArray &keyType,
			  const QByteArray &name,
			  const QByteArray &publicKey,
			  const QByteArray &signature,
			  const QByteArray &sPublicKey,
			  const QByteArray &sSignature);

 signals:
  void accountAuthenticated(const QByteArray &name,
			    const QByteArray &password);
  void authenticationRequested(const QString &peerInformation);
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
  void bluetooth(const QBluetoothServiceInfo &serviceInfo);
#endif
  void callParticipant(const QByteArray &publicKeyHash,
		       const QByteArray &gemini,
		       const QByteArray &geminiHashKey);
  void disconnected(void);
  void forwardSecrecyRequest(const QByteArrayList &list);
  void newData(void);
  void newEMailArrived(void);
  void publicizeListenerPlaintext(const QByteArray &data, const qint64 id);
  void receivedBuzzMessage(const QByteArrayList &list,
			   const QByteArrayList &symmetricKeys);
  void receivedChatMessage(const QByteArray &data);
  void receivedMessage
    (const QByteArray &data, const qint64 id,
     const QPairByteArrayByteArray &adaptiveEchoPair);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void resetKeepAlive(void);
  void retrieveMail(const QByteArray &data,
		    const QByteArray &publicKeyHash,
		    const QByteArray &timestamp,
		    const QByteArray &signature,
		    const QPairByteArrayByteArray &adaptiveEchoPair);
  void saveForwardSecrecySessionKeys(const QByteArrayList &list);
  void scrambleRequest(void);
  void sharePublicKey(const QByteArray &keyType,
		      const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &signature,
		      const QByteArray &sPublicKey,
		      const QByteArray &sSignature);
  void statusMessageReceived(const QByteArray &publicKeyHash,
			     const QString &status);
  void stopTimer(QTimer *timer);
};

class spoton_neighbor_worker: public QObject
{
  Q_OBJECT

 public:
  spoton_neighbor_worker(spoton_neighbor *neighbor):QObject(0)
  {
    m_neighbor = neighbor;
  }

  ~spoton_neighbor_worker()
  {
  }

 private:
  QPointer<spoton_neighbor> m_neighbor;

 private slots:
  void slotNewData(void)
  {
    if(m_neighbor)
      m_neighbor->processData();
  }
};
#endif
