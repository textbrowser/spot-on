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
#include <QDateTime>
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
#include <QDtls>
#include <QDtlsClientVerifier>
#endif
#include <QFuture>
#include <QHostAddress>
#include <QHostInfo>
#include <QMap>
#include <QNetworkProxy>
#include <QPointer>
#include <QReadWriteLock>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QThread>
#include <QTimer>
#include <QUdpSocket>
#include <QUuid>
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
#include <QWebSocket>
#endif
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#ifndef Q_OS_MACOS
#include <qbluetoothservicediscoveryagent.h>
#endif
#include <qbluetoothsocket.h>
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "Common/spot-on-socket-options.h"
#include "spot-on-sctp-socket.h"

class spoton_neighbor_tcp_socket: public QSslSocket
{
  Q_OBJECT

 public:
  spoton_neighbor_tcp_socket(QObject *parent = nullptr):QSslSocket(parent)
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
  spoton_neighbor_udp_socket(QObject *parent = nullptr):QUdpSocket(parent)
  {
    m_multicastSocket = nullptr;
  }

  void initializeMulticast(const QHostAddress &address,
			   const quint16 port,
			   const QString &socketOptions)
  {
    if(address.protocol() == QAbstractSocket::IPv4Protocol)
      {
	auto const a = address.toIPv4Address();

	if(!((a & 0xf0000000) == 0xe0000000))
	  return;
      }
    else if(address.protocol() == QAbstractSocket::IPv6Protocol)
      {
	auto const a6 = address.toIPv6Address();

	if(a6.c[0] != 0xff)
	  return;
      }
    else
      return;

    if(m_multicastSocket)
      m_multicastSocket->deleteLater();

    m_multicastSocket = new QUdpSocket(this);

    if(!m_multicastSocket->bind(address,
				port,
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

    spoton_socket_options::setSocketOptions
      (socketOptions,
       "udp",
       static_cast<qint64> (m_multicastSocket->socketDescriptor()),
       nullptr);

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
	(QAbstractSocket::MulticastLoopbackOption, 1);
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
		  const int waitforbyteswritten_msecs,
		  const QByteArray &privateApplicationCredentials,
		  const int silenceTime,
		  const QString &socketOptions,
		  const QString &bindIpAddress,
		  QObject *parent);

  /*
  ** We're a server. Let's represent a client connection.
  */

  spoton_neighbor(const qintptr socketDescriptor,
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
		  const int sourceOfRandomness,
		  const QByteArray &privateApplicationCredentials,
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
		  QBluetoothSocket *bluetooth_socket,
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
		  QWebSocket *web_socket,
#endif
		  const int keySize,
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
  bool readyToWrite(void) const;
  bool writeMessage006X(const QByteArray &data, const QString &messageType);
  int write(const char *data, const int size, const bool emitDropped = true);
  qint64 id(void) const;
  quint16 peerPort(void) const;
  void abort(void);
  void close(void);
  void processData(void);
  void setId(const qint64 id);

 private:
  QAtomicInt m_abort;
  QAtomicInt m_kernelInterfaces;
  QAtomicInt m_passthrough;
  QAtomicInt m_waitforbyteswritten_msecs;
  QByteArray m_accountClientSentSalt;
  QByteArray m_accountName;
  QByteArray m_accountPassword;
  QByteArray m_data;
  QByteArray m_privateApplicationCredentials;
  QDateTime m_lastReadTime;
  QDateTime m_startTime;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  QDtlsClientVerifier m_dtlsClientVerifier;
  QHash<QPair<QHostAddress, quint16>, char> m_verifiedUdpClients;
#endif
  QList<QFuture<void> > m_privateApplicationFutures;
  QList<QPair<QByteArray, QByteArray> > m_learnedAdaptiveEchoPairs;
  QMap<quint64, QByteArray> m_privateApplicationMap;
  QMutex m_privateApplicationMutex;
  QPair<QByteArray, QByteArray> m_adaptiveEchoPair;
  QPair<quint64, quint64> m_privateApplicationSequences;
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#ifndef Q_OS_MACOS
  QPointer<QBluetoothServiceDiscoveryAgent> m_bluetoothServiceDiscoveryAgent;
#endif
  QPointer<QBluetoothSocket> m_bluetoothSocket;
#else
  QPointer<QObject> m_bluetoothSocket;
#endif
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  QPointer<QDtls> m_dtls;
#endif
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  QPointer<QWebSocket> m_webSocket;
#else
  QPointer<QObject> m_webSocket;
#endif
  QPointer<spoton_external_address> m_externalAddress;
  QPointer<spoton_neighbor_tcp_socket> m_tcpSocket;
  QPointer<spoton_neighbor_udp_socket> m_udpSocket;
  QPointer<spoton_sctp_socket> m_sctpSocket;
  QReadWriteLock m_accountClientSentSaltMutex;
  QReadWriteLock m_accountNameMutex;
  QReadWriteLock m_accountPasswordMutex;
  QReadWriteLock m_bytesDiscardedOnWriteMutex;
  QReadWriteLock m_bytesWrittenMutex;
  QReadWriteLock m_dataMutex;
  QReadWriteLock m_echoModeMutex;
  QReadWriteLock m_learnedAdaptiveEchoPairsMutex;
  QReadWriteLock m_maximumBufferSizeMutex;
  QReadWriteLock m_maximumContentLengthMutex;
  QReadWriteLock m_receivedUuidMutex;
  QSslCertificate m_peerCertificate;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  QSslConfiguration m_udpSslConfiguration;
#endif
  QString m_address;
  QString m_bindIpAddress;
  QString m_echoMode;
  QString m_ipAddress;
  QString m_motd;
  QString m_orientation;
  QString m_protocol;
  QString m_scopeId;
  QString m_socketOptions;
  QString m_sslControlString;
  QString m_statusControl;
  QString m_transport;
  QTimer m_accountTimer;
  QTimer m_authenticationTimer;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_keepAliveTimer;
  QTimer m_lifetime;
  QTimer m_specialPeerTimer; // Server-less.
  QTimer m_timer;
  QUuid m_receivedUuid;
  bool m_allowExceptions;
  bool m_isUserDefined;
  bool m_requireSsl;
  bool m_useSsl;
  int m_keySize;
  int m_laneWidth;
  int m_silenceTime;
  int m_sourceOfRandomness;
  mutable QAtomicInt m_accountAuthenticated;
  mutable QAtomicInt m_useAccounts;
  qint64 m_id;
  qint64 m_listenerOid;
  qint64 m_maximumBufferSize;
  qint64 m_maximumContentLength;
  quint16 m_port;
  quint64 m_bytesDiscardedOnWrite;
  quint64 m_bytesRead;
  quint64 m_bytesWritten;
  QSslConfiguration sslConfiguration(void) const;
  QString findMessageType
    (const QByteArray &data,
     QList<QByteArray> &symmetricKeys,
     QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  void addToBytesWritten(const qint64 bytesWritten);
  void bundlePrivateApplicationData
    (const QByteArray &data,
     const QByteArray &privateApplicationCredentials,
     const qint64 id,
     const quint64 sequence);
  void parsePrivateApplicationData
    (const QByteArray &data,
     const QByteArray &privateApplicationCredentials,
     const qint64 maximumContentLength);
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  void prepareDtls(void);
#endif
  void prepareSslConfiguration(const QByteArray &certificate,
			       const QByteArray &privateKey,
			       const bool client,
			       const int keySize);
  void process0000(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0000a(int length,
		    const QByteArray &data,
		    const QString &messageType);
  void process0000b(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0000d(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0001a(int length, const QByteArray &data);
  void process0001b(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0001c(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0002a(int length,
		    const QByteArray &data,
		    const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  void process0002b(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys,
		    const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  void process0011(int length, const QByteArray &data);
  void process0012(int length, const QByteArray &data);
  void process0013(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0014(int length, const QByteArray &data);
  void process0030(int length, const QByteArray &data);
  void process0040a(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0040b(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0050(int length, const QByteArray &data);
  void process0051(int length, const QByteArray &data);
  void process0065(int length, const QByteArray &data);
  void process0070(int length, const QByteArray &data);
  void process0080(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0090(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0091a(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0091b(int length,
		    const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0092(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0095a(int length, const QByteArray &data);
  void process0095b(int length, const QByteArray &data);
  void process0100(int length,
		   const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void readyRead(const QByteArray &data);
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
		     const qint64 neighbor_oid,
		     const bool ignore_key_permissions,
		     const bool signatures_required,
		     const QString &messageType);
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
		   const QByteArray &date,
		   const QByteArray &attachmentData,
		   const QByteArray &signature,
		   const bool goldbugUsed);
  void storeLetter(const QList<QByteArray> &list,
		   const QByteArray &recipientHash);

 private slots:
  void slotAccountAuthenticated(const QByteArray &clientSalt,
				const QByteArray &name,
				const QByteArray &password);
  void slotAuthenticationTimerTimeout(void);
  void slotBinaryFrameReceived(const QByteArray &fame, bool isLastFrame);
  void slotBinaryMessageReceived(const QByteArray &message);
  void slotCallParticipant(const QByteArray &data, const QString &messageType);
  void slotConnected(void);
  void slotDisconnected(void);
  void slotDiscoverExternalAddress(void);
  void slotEchoKeyShare(const QByteArrayList &list);
  void slotEncrypted(void);
  void slotError(QAbstractSocket::SocketError error);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  void slotError(QBluetoothSocket::SocketError error);
#endif
  void slotError(const QString &method,
		 const spoton_sctp_socket::SocketError error);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotHandshakeTimeout(void);
  void slotHostFound(const QHostInfo &hostInfo);
  void slotInitiateSSLTLSSession(const bool client, const qint64 oid);
  void slotLifetimeExpired(void);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotNewDatagram(const QByteArray &datagram,
		       const QHostAddress &address,
		       const quint16 port);
  void slotPeerVerifyError(const QSslError &error);
  void slotProxyAuthenticationRequired(const QNetworkProxy &proxy,
				       QAuthenticator *authenticator);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  void slotPublicizeListenerPlaintext(const QBluetoothAddress &address,
				      const quint16 port,
				      const QString &orientation);
#endif
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
  void slotSMPMessageReceivedFromUI(const QByteArrayList &list);
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
    (const QByteArray &data, const QPairByteArrayByteArray &adaptiveEchoPair);
  void slotSendMessage
    (const QByteArray &data, const spoton_send::spoton_send_method sendMethod);
  void slotSendStatus(const QByteArrayList &list);
  void slotShareGit(const QByteArray &fingerprint, const QByteArray &message);
  void slotSpecialTimerTimeout(void);
  void slotSslErrors(const QList<QSslError> &errors);
  void slotStopTimer(QTimer *timer);
  void slotTimeout(void);
  void slotWrite(const QByteArray &data,
		 const qint64 id,
		 const QPairByteArrayByteArray &adaptiveEchoPair);
  void slotWriteParsedApplicationData(const QByteArray &data);
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
  void accountAuthenticated(const QByteArray &clientSalt,
			    const QByteArray &name,
			    const QByteArray &password);
  void authenticationRequested(const QString &peerInformation);
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  void bluetooth(const QBluetoothServiceInfo &serviceInfo);
#endif
  void bytesReceived(const qint64 size);
  void bytesSent(const qint64 size);
  void callParticipant(const QByteArray &publicKeyHash,
		       const QByteArray &gemini,
		       const QByteArray &geminiHashKey);
  void disconnected(void);
  void dropped(const QByteArray &data);
  void forwardSecrecyRequest(const QByteArrayList &list);
  void newData(void);
  void newEMailArrived(void);
  void notification(const QString &text);
  void publicizeListenerPlaintext(const QByteArray &data, const qint64 id);
  void receivedBuzzMessage(const QByteArrayList &list,
			   const QByteArrayList &symmetricKeys);
  void receivedChatMessage(const QByteArray &data);
  void receivedMessage
    (const QByteArray &data,
     const qint64 id,
     const QPairByteArrayByteArray &adaptiveEchoPair);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void resetKeepAlive(void);
  void retrieveMail(const QByteArray &data,
		    const QByteArray &publicKeyHash,
		    const QByteArray &timestamp,
		    const QByteArray &signature,
		    const QPairByteArrayByteArray &adaptiveEchoPair);
  void saveForwardSecrecySessionKeys(const QByteArrayList &list);
  void saveUrls(const QList<QByteArray> &urls);
  void scrambleRequest(void);
  void sendMessage
    (const QByteArray &data, const QPairByteArrayByteArray &adaptiveEchoPair);
  void sharePublicKey(const QByteArray &keyType,
		      const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &signature,
		      const QByteArray &sPublicKey,
		      const QByteArray &sSignature);
  void smpMessage(const QByteArrayList &list);
  void statusMessageReceived(const QByteArray &publicKeyHash,
			     const QString &status);
  void stopTimer(QTimer *timer);
  void writeParsedApplicationData(const QByteArray &data);
};

class spoton_neighbor_worker: public QObject
{
  Q_OBJECT

 public:
  spoton_neighbor_worker(spoton_neighbor *neighbor):QObject(nullptr)
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
