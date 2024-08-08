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

#include <QAuthenticator>
#include <QSqlError>
#include <QSqlQuery>
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#ifndef Q_OS_MACOS
#include <qbluetoothhostinfo.h>
#include <qbluetoothlocaldevice.h>
#endif
#endif

#include "spot-on-kernel.h"
#include "spot-on-mailer.h"
#include "spot-on-neighbor.h"

extern "C"
{
#if defined(Q_OS_WIN)
#include <io.h>
#else
#include <unistd.h>
#endif
}

#include <limits>

spoton_neighbor::spoton_neighbor
(const qintptr socketDescriptor,
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
 QObject *parent):QThread(parent)
{
  Q_UNUSED(priority);
  m_abort = 0;
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
  m_bluetoothSocket = bluetooth_socket;

  if(m_bluetoothSocket)
    m_bluetoothSocket->setParent(this);
#else
#endif
  m_kernelInterfaces = spoton_kernel::interfaces();
  m_keySize = qAbs(keySize);
  m_laneWidth = qBound(spoton_common::LANE_WIDTH_MINIMUM,
		       laneWidth,
		       spoton_common::LANE_WIDTH_MAXIMUM);
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
  m_passthrough = passthrough;
  m_privateApplicationCredentials = privateApplicationCredentials;
  m_privateApplicationSequences.first = m_privateApplicationSequences.second =
    1;
  m_sourceOfRandomness = qBound
    (0,
     sourceOfRandomness,
     static_cast<int> (std::numeric_limits<unsigned short>::max()));
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  m_webSocket = web_socket;

  if(m_webSocket)
    m_webSocket->setParent(this);
#else
#endif

  if(transport == "bluetooth")
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
      if(m_bluetoothSocket)
	{
	  connect(m_bluetoothSocket,
		  SIGNAL(disconnected(void)),
		  this,
		  SIGNAL(disconnected(void)));
	  connect(m_bluetoothSocket,
		  SIGNAL(disconnected(void)),
		  this,
		  SLOT(slotDisconnected(void)));
	  connect(m_bluetoothSocket,
		  SIGNAL(error(QBluetoothSocket::SocketError)),
		  this,
		  SLOT(slotError(QBluetoothSocket::SocketError)));
	  connect(m_bluetoothSocket,
		  SIGNAL(readyRead(void)),
		  this,
		  SLOT(slotReadyRead(void)));
	}
#endif
    }
  else if(transport == "sctp")
    m_sctpSocket = new spoton_sctp_socket(this);
  else if(transport == "tcp")
    m_tcpSocket = new spoton_neighbor_tcp_socket(this);
  else if(transport == "udp")
    m_udpSocket = new spoton_neighbor_udp_socket(this);
  else if(transport == "websocket")
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      if(m_webSocket)
	{
	  connect(m_webSocket,
		  SIGNAL(binaryFrameReceived(const QByteArray &, bool)),
		  this,
		  SLOT(slotBinaryFrameReceived(const QByteArray &, bool)));
	  connect(m_webSocket,
		  SIGNAL(binaryMessageReceived(const QByteArray &)),
		  this,
		  SLOT(slotBinaryMessageReceived(const QByteArray &)));
	  connect(m_webSocket,
		  SIGNAL(disconnected(void)),
		  this,
		  SIGNAL(disconnected(void)));
	  connect(m_webSocket,
		  SIGNAL(disconnected(void)),
		  this,
		  SLOT(slotDisconnected(void)));
	  connect(m_webSocket,
		  SIGNAL(error(QAbstractSocket::SocketError)),
		  this,
		  SLOT(slotError(QAbstractSocket::SocketError)));
	  connect(m_webSocket,
		  SIGNAL(sslErrors(const QList<QSslError> &)),
		  this,
		  SLOT(slotSslErrors(const QList<QSslError> &)));
	}
#endif
    }

  if(m_bluetoothSocket)
    {
    }
  else if(m_sctpSocket)
    {
      m_sctpSocket->setReadBufferSize(m_maximumBufferSize);
      m_sctpSocket->setSocketDescriptor(static_cast<int> (socketDescriptor));
    }
  else if(m_tcpSocket)
    {
      m_tcpSocket->setReadBufferSize(m_maximumBufferSize);

      if(!m_tcpSocket->setSocketDescriptor(socketDescriptor))
	spoton_misc::closeSocket(socketDescriptor);
    }
  else if(m_udpSocket)
    {
      int s = 0;

#if defined(Q_OS_WIN)
      s = _dup(static_cast<int> (socketDescriptor));

      if(s != -1)
	{
	  if(!m_udpSocket->setSocketDescriptor(s, QAbstractSocket::BoundState))
	    spoton_misc::closeSocket(s);
	}
      else
	spoton_misc::closeSocket(socketDescriptor);
#else
      s = dup(static_cast<int> (socketDescriptor));

      if(s != -1)
	{
	  if(!m_udpSocket->setSocketDescriptor(s, QAbstractSocket::BoundState))
	    spoton_misc::closeSocket(s);
	}
      else
	spoton_misc::closeSocket(socketDescriptor);
#endif
      m_udpSocket->setLocalAddress(QHostAddress(localIpAddress));
      m_udpSocket->setLocalPort(localPort.toUShort());
      m_udpSocket->setPeerAddress(QHostAddress(ipAddress));
      m_udpSocket->setPeerPort(port.toUShort());
    }
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_webSocket->setReadBufferSize(m_maximumBufferSize);
#endif
    }
  else if(socketDescriptor != -1)
    spoton_misc::closeSocket(socketDescriptor);

  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_address = m_bluetoothSocket->peerAddress().toString();
#endif
    }
  else if(m_sctpSocket)
    m_address = m_sctpSocket->peerAddress().toString();
  else if(m_tcpSocket)
    m_address = m_tcpSocket->peerAddress().toString();
  else if(m_udpSocket)
    m_address = ipAddress.trimmed();
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_address = m_webSocket->peerAddress().toString();
#endif
    }

  m_accountAuthenticated = 0;
  m_allowExceptions = false;
  m_bytesDiscardedOnWrite = 0;
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address
    (QUrl::fromUserInput(spoton_kernel::setting("gui/external_ip_url", "").
			 toString()),
     this);
  m_id = -1; /*
	     ** This neighbor was created by a listener. We must
	     ** obtain a valid id at some point (setId())!
	     */
  m_ipAddress = m_address.trimmed();
  m_isUserDefined = false;
  m_lastReadTime = QDateTime::currentDateTime();
  m_listenerOid = listenerOid;
  m_maximumContentLength =
    qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumContentLength,
	   spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
  m_motd = motd;
  m_orientation = orientation;

  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_port = m_bluetoothSocket->peerPort();
#endif
    }
  else if(m_sctpSocket)
    m_port = m_sctpSocket->peerPort();
  else if(m_tcpSocket)
    m_port = m_tcpSocket->peerPort();
  else if(m_udpSocket)
    m_port = port.toUShort();
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_port = m_webSocket->peerPort();
#endif
    }

  m_receivedUuid = QUuid("{00000000-0000-0000-0000-000000000000}");
  m_silenceTime = spoton_common::NEIGHBOR_SILENCE_TIME;
  m_sslControlString = sslControlString.trimmed();

  if(m_sslControlString.isEmpty())
    m_sslControlString = spoton_common::SSL_CONTROL_STRING;

  m_statusControl = "connected";
  m_startTime = QDateTime::currentDateTime();
  m_transport = transport;
  m_useAccounts = useAccounts ? 1 : 0;

  if(m_transport == "tcp")
    m_requireSsl = true;
  else if(m_transport == "udp")
    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_requireSsl = true;
#else
      m_requireSsl = false;
#endif
    }
  else if(m_transport == "websocket")
    m_requireSsl = true;
  else
    m_requireSsl = false;

  if(certificate.isEmpty() ||
     m_transport == "bluetooth" ||
     m_transport == "sctp" ||
     privateKey.isEmpty())
    m_useSsl = false;
  else if(m_transport == "tcp")
    m_useSsl = true;
  else if(m_transport == "udp")
    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      m_useSsl = true;
#else
      m_useSsl = false;
#endif
    }
  else if(m_transport == "websocket")
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_useSsl = true;
#else
      m_useSsl = false;
#endif
    }

  m_waitforbyteswritten_msecs = 0;

  if(m_useSsl)
    prepareSslConfiguration(certificate, privateKey, false);

  if(!m_useSsl)
    m_sslControlString = "N/A";

  connect(this,
	  SIGNAL(accountAuthenticated(const QByteArray &,
				      const QByteArray &,
				      const QByteArray &)),
	  this,
	  SLOT(slotAccountAuthenticated(const QByteArray &,
					const QByteArray &,
					const QByteArray &)));
  connect(this,
	  SIGNAL(resetKeepAlive(void)),
	  this,
	  SLOT(slotResetKeepAlive(void)));
  connect(this,
	  SIGNAL(sharePublicKey(const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &)),
	  this,
	  SLOT(slotSharePublicKey(const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &)));
  connect(this,
	  SIGNAL(stopTimer(QTimer *)),
	  this,
	  SLOT(slotStopTimer(QTimer *)));
  connect(this,
	  SIGNAL(writeParsedApplicationData(const QByteArray &)),
	  this,
	  SLOT(slotWriteParsedApplicationData(const QByteArray &)));

  if(m_bluetoothSocket)
    {
    }
  else if(m_sctpSocket)
    {
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(error(const QString &,
			   const spoton_sctp_socket::SocketError)),
	      this,
	      SLOT(slotError(const QString &,
			     const spoton_sctp_socket::SocketError)));
      connect(m_sctpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
  else if(m_tcpSocket)
    {
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotEncrypted(void)));
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#else
      connect(m_tcpSocket,
	      SIGNAL(errorOccurred(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#endif
      connect(m_tcpSocket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(m_tcpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
      connect(m_tcpSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      this,
	      SLOT(slotSslErrors(const QList<QSslError> &)));
    }
  else if(m_udpSocket)
    {
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#else
      connect(m_udpSocket,
	      SIGNAL(errorOccurred(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#endif
      connect(m_udpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }

  connect(&m_accountTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendAuthenticationRequest(void)));
  connect(&m_authenticationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotAuthenticationTimerTimeout(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendCapabilities(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));

  if(m_useSsl)
    {
      if(m_tcpSocket)
	m_tcpSocket->startServerEncryption();
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      else if(m_udpSocket)
	prepareDtls();
#endif
    }

  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs", 15000).toInt());

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() == 30)
    {
      m_externalAddress->discover();
      m_externalAddressDiscovererTimer.start(30000);
    }
  else if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
	  toInt() == 60)
    {
      m_externalAddress->discover();
      m_externalAddressDiscovererTimer.start(60000);
    }
  else
    m_externalAddressDiscovererTimer.setInterval(30000);

  if(m_useAccounts.fetchAndAddOrdered(0))
    if(!m_useSsl)
      {
	m_accountTimer.start();
	m_authenticationTimer.start();
      }

  QTimer::singleShot(30000, this, SLOT(slotSendMOTD(void)));
  m_keepAliveTimer.start(15000);
  m_lifetime.start(spoton_common::NEIGHBOR_LIFETIME_MS);
  m_timer.start(2500);
}

spoton_neighbor::spoton_neighbor
(const QNetworkProxy &proxy,
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
 QObject *parent):QThread(parent)
{
  Q_UNUSED(priority);
  m_abort = 0;
  m_accountAuthenticated = 0;
  m_accountName = accountName;
  m_accountPassword = accountPassword;
  m_address = ipAddress.trimmed();
  m_allowExceptions = allowExceptions;
  m_bindIpAddress = bindIpAddress.trimmed();
  m_bytesDiscardedOnWrite = 0;
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address
    (QUrl::fromUserInput(spoton_kernel::setting("gui/external_ip_url", "").
			 toString()),
     this);
  m_id = id;
  m_ipAddress = ipAddress;
  m_isUserDefined = userDefined;
  m_kernelInterfaces = spoton_kernel::interfaces();
  m_keySize = qAbs(keySize);

  if(transport == "tcp" || transport == "udp" || transport == "websocket")
    {
      if(m_keySize != 0)
	if(!(m_keySize == 256 ||
	     m_keySize == 384 ||
	     m_keySize == 521 ||
	     m_keySize == 2048 ||
	     m_keySize == 3072 ||
	     m_keySize == 4096))
	  m_keySize = 2048;

#if (QT_VERSION < QT_VERSION_CHECK(5, 12, 0))
      if(m_transport == "udp")
	m_keySize = 0;
#endif

#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
#else
      if(m_transport == "websocket")
	m_keySize = 0;
#endif
    }
  else
    m_keySize = 0;

  m_laneWidth = qBound(spoton_common::LANE_WIDTH_MINIMUM,
		       laneWidth,
		       spoton_common::LANE_WIDTH_MAXIMUM);
  m_lastReadTime = QDateTime::currentDateTime();
  m_listenerOid = -1;
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
  m_maximumContentLength =
    qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumContentLength,
	   spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
  m_motd = motd;
  m_orientation = orientation;
  m_passthrough = passthrough;
  m_peerCertificate = QSslCertificate(peerCertificate);
  m_port = port.toUShort();
  m_privateApplicationCredentials = privateApplicationCredentials;
  m_privateApplicationSequences.first = m_privateApplicationSequences.second =
    1;
  m_protocol = protocol;
  m_receivedUuid = QUuid("{00000000-0000-0000-0000-000000000000}");
  m_requireSsl = requireSsl;
  m_silenceTime = qBound(0, silenceTime, std::numeric_limits<int>::max());
  m_socketOptions = socketOptions;
  m_sourceOfRandomness = 0;
  m_sslControlString = sslControlString.trimmed();

  if(m_sslControlString.isEmpty())
    m_sslControlString = spoton_common::SSL_CONTROL_STRING;

  m_startTime = QDateTime::currentDateTime();
  m_statusControl = statusControl;
  m_transport = transport;
  m_waitforbyteswritten_msecs =
    qBound(0,
	   waitforbyteswritten_msecs,
	   spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM);

  auto s_crypt = spoton_kernel::crypt("chat");

  if(s_crypt)
    {
      auto name(m_accountName);
      auto ok = true;
      auto password(m_accountPassword);

      name = s_crypt->decryptedAfterAuthenticated(name, &ok);

      if(ok)
	password = s_crypt->decryptedAfterAuthenticated(password, &ok);

      if(ok)
	m_useAccounts = !name.isEmpty() && !password.isEmpty() ? 1 : 0;
      else
	m_useAccounts = 0;
    }
  else
    m_useAccounts = 0;

  if(m_transport == "tcp")
    {
      if(m_keySize != 0)
	m_useSsl = true;
      else
	m_useSsl = false;
    }
  else if(m_transport == "udp")
    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
      if(m_keySize != 0)
	m_useSsl = true;
      else
	m_useSsl = false;
#else
      m_useSsl = false;
#endif
    }
  else if(m_transport == "websocket")
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      if(m_keySize != 0)
	m_useSsl = true;
      else
	m_useSsl = false;
#else
      m_useSsl = false;
#endif
    }
  else
    m_useSsl = false;

  if(m_transport == "bluetooth")
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#ifndef Q_OS_MACOS
      auto const list(QBluetoothLocalDevice::allDevices());

      if(list.isEmpty())
	m_bluetoothServiceDiscoveryAgent =
	  new QBluetoothServiceDiscoveryAgent(this);
      else
	m_bluetoothServiceDiscoveryAgent =
	  new QBluetoothServiceDiscoveryAgent(list.at(0).address(), this);
#endif
#endif
    }
  else if(m_transport == "sctp")
    m_sctpSocket = new spoton_sctp_socket(this);
  else if(m_transport == "tcp")
    m_tcpSocket = new spoton_neighbor_tcp_socket(this);
  else if(m_transport == "udp")
    m_udpSocket = new spoton_neighbor_udp_socket(this);
  else if(m_transport == "websocket")
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_webSocket = new QWebSocket
	("", QWebSocketProtocol::VersionLatest, this);
#endif
    }

  if(m_sctpSocket)
    m_sctpSocket->setReadBufferSize(m_maximumBufferSize);
  else if(m_tcpSocket)
    {
      m_tcpSocket->setProxy(proxy);
      m_tcpSocket->setReadBufferSize(m_maximumBufferSize);
    }
  else if(m_udpSocket)
    m_udpSocket->setProxy(proxy);
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      m_webSocket->setProxy(proxy);
      m_webSocket->setReadBufferSize(m_maximumBufferSize);
#endif
    }

  if(m_bindIpAddress.isEmpty())
    prepareSslConfiguration(QByteArray(), QByteArray(), true);

  if(m_transport != "bluetooth")
    if(m_address.isEmpty())
      if(!m_ipAddress.isEmpty())
	QHostInfo::lookupHost
	  (m_ipAddress, this, SLOT(slotHostFound(const QHostInfo &)));

  if(m_transport != "bluetooth")
    m_scopeId = scopeId;

  if(!m_useSsl)
    m_sslControlString = "N/A";

  connect(this,
	  SIGNAL(resetKeepAlive(void)),
	  this,
	  SLOT(slotResetKeepAlive(void)));
  connect(this,
	  SIGNAL(sharePublicKey(const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &)),
	  this,
	  SLOT(slotSharePublicKey(const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &)));
  connect(this,
	  SIGNAL(stopTimer(QTimer *)),
	  this,
	  SLOT(slotStopTimer(QTimer *)));
  connect(this,
	  SIGNAL(writeParsedApplicationData(const QByteArray &)),
	  this,
	  SLOT(slotWriteParsedApplicationData(const QByteArray &)));

  if(m_sctpSocket)
    {
      connect(m_sctpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(error(const QString &,
			   const spoton_sctp_socket::SocketError)),
	      this,
	      SLOT(slotError(const QString &,
			     const spoton_sctp_socket::SocketError)));
      connect(m_sctpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
  else if(m_tcpSocket)
    {
      connect(m_tcpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotEncrypted(void)));
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#else
      connect(m_tcpSocket,
	      SIGNAL(errorOccurred(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#endif
      connect(m_tcpSocket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(m_tcpSocket,
	      SIGNAL(peerVerifyError(const QSslError &)),
	      this,
	      SLOT(slotPeerVerifyError(const QSslError &)));
      connect(m_tcpSocket,
	      SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
						 QAuthenticator *)),
	      this,
	      SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
						   QAuthenticator *)));
      connect(m_tcpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
      connect(m_tcpSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      this,
	      SLOT(slotSslErrors(const QList<QSslError> &)));
    }
  else if(m_udpSocket)
    {
      connect(m_udpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#else
      connect(m_udpSocket,
	      SIGNAL(errorOccurred(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
#endif
      connect(m_udpSocket,
	      SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
						 QAuthenticator *)),
	      this,
	      SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
						   QAuthenticator *)));
      connect(m_udpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      connect(m_webSocket,
	      SIGNAL(binaryFrameReceived(const QByteArray &, bool)),
	      this,
	      SLOT(slotBinaryFrameReceived(const QByteArray &, bool)));
      connect(m_webSocket,
	      SIGNAL(binaryMessageReceived(const QByteArray &)),
	      this,
	      SLOT(slotBinaryMessageReceived(const QByteArray &)));
      connect(m_webSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_webSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_webSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_webSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_webSocket,
	      SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
						 QAuthenticator *)),
	      this,
	      SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
						   QAuthenticator *)));
      connect(m_webSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      this,
	      SLOT(slotSslErrors(const QList<QSslError> &)));
#endif
    }

  connect(&m_accountTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendAccountInformation(void)));
  connect(&m_authenticationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotAuthenticationTimerTimeout(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendCapabilities(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_specialPeerTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSpecialTimerTimeout(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs",
	     15000).toInt());

  if(!m_bindIpAddress.isEmpty())
    if(m_tcpSocket)
      {
	m_tcpSocket->bind
	  (QHostAddress(m_bindIpAddress),
	   m_port,
	   QAbstractSocket::ReuseAddressHint | QAbstractSocket::ShareAddress);

	if(m_tcpSocket->state() & QAbstractSocket::BoundState)
	  m_specialPeerTimer.start
	    (qBound(0,
		    spoton_kernel::
		    setting("P2P_SERVERLESS_CONNECT_INTERVAL_MS", 1).toInt(),
		    1500));
      }

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).toInt() == 30)
    m_externalAddressDiscovererTimer.setInterval(30000);
  else if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
	  toInt() == 60)
    m_externalAddressDiscovererTimer.setInterval(60000);
  else
    m_externalAddressDiscovererTimer.setInterval(30000);

  m_keepAliveTimer.setInterval(15000);
  m_lifetime.start(spoton_common::NEIGHBOR_LIFETIME_MS);
  m_timer.start(2500);
}

spoton_neighbor::~spoton_neighbor()
{
  spoton_misc::logError(QString("Neighbor %1:%2 deallocated.").
			arg(m_address).
			arg(m_port));
  m_abort.fetchAndStoreOrdered(1);

  QWriteLocker locker(&m_dataMutex);

  m_data.clear();
  locker.unlock();
  m_accountTimer.stop();
  m_authenticationTimer.stop();
  m_externalAddressDiscovererTimer.stop();
  m_keepAliveTimer.stop();
  m_lifetime.stop();
  m_specialPeerTimer.stop();
  m_timer.stop();

  if(m_id != -1)
    {
      /*
      ** We must not delete accepted participants (neighbor_oid = -1).
      */

      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    /*
	    ** Remove asymmetric keys that were not completely shared.
	    */

	    QSqlQuery query(db);

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM friends_public_keys WHERE "
			  "neighbor_oid = ?");
	    query.bindValue(0, m_id);
	    query.exec();
	    spoton_misc::purgeSignatureRelationships
	      (db, spoton_kernel::crypt("chat"));
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM neighbors WHERE "
			  "OID = ? AND status_control = 'deleted'");
	    query.bindValue(0, m_id);
	    query.exec();

	    if(spoton_kernel::setting("gui/keepOnlyUserDefinedNeighbors",
				      true).toBool())
	      {
		query.prepare("DELETE FROM neighbors WHERE "
			      "OID = ? AND status_control <> 'blocked' AND "
			      "user_defined = 0");
		query.bindValue(0, m_id);
		query.exec();
	      }

	    query.prepare("UPDATE neighbors SET "
			  "account_authenticated = NULL, "
			  "buffered_content = 0, "
			  "bytes_discarded_on_write = 0, "
			  "bytes_read = 0, "
			  "bytes_written = 0, "
			  "external_ip_address = NULL, "
			  "external_port = NULL, "
			  "is_encrypted = 0, "
			  "local_ip_address = NULL, "
			  "local_port = NULL, "
			  "ssl_session_cipher = NULL, "
			  "status = 'disconnected', "
			  "uptime = 0 "
			  "WHERE OID = ?");
	    query.bindValue(0, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  for(int i = 0; i < m_privateApplicationFutures.size(); i++)
    {
      auto future(m_privateApplicationFutures.at(i));

      future.cancel();
      future.waitForFinished();
    }

  close();
  quit();
  wait();
}

void spoton_neighbor::readyRead(const QByteArray &data)
{
  if(!data.isEmpty())
    if(m_passthrough)
      {
	/*
	** A private application may not be able to authenticate.
	*/

	if(!m_privateApplicationCredentials.isEmpty())
	  {
	    if(m_isUserDefined)
	      {
		QMutexLocker locker(&m_privateApplicationMutex);
		auto const sequence = m_privateApplicationSequences.first;

		m_privateApplicationSequences.first += 1;
		locker.unlock();
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		m_privateApplicationFutures << QtConcurrent::run
		  (&spoton_neighbor::bundlePrivateApplicationData,
		   this,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
#else
		m_privateApplicationFutures << QtConcurrent::run
		  (this,
		   &spoton_neighbor::bundlePrivateApplicationData,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
#endif
	      }
	    else
	      {
		QMutexLocker locker(&m_privateApplicationMutex);
		auto const sequence = m_privateApplicationSequences.second;

		m_privateApplicationSequences.second += 1;
		locker.unlock();
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		m_privateApplicationFutures << QtConcurrent::run
		  (&spoton_neighbor::bundlePrivateApplicationData,
		   this,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
#else
		m_privateApplicationFutures << QtConcurrent::run
		  (this,
		   &spoton_neighbor::bundlePrivateApplicationData,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
#endif
	      }

	    return;
	  }

	auto ok = true;

	if(m_useAccounts.fetchAndAddOrdered(0))
	  if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	    ok = false;

	if(ok)
	  {
	    /*
	    ** We cannot safely inspect duplicate bytes.
	    ** For example, an 'a' followed by another 'a' may
	    ** be acceptable.
	    */

	    emit receivedMessage(data, m_id, QPair<QByteArray, QByteArray> ());
	    emit resetKeepAlive();
	    return;
	  }
      }

  if(!data.isEmpty() || m_udpSocket)
    {
      QReadLocker locker1(&m_maximumBufferSizeMutex);
      auto const maximumBufferSize = m_maximumBufferSize;

      locker1.unlock();

      QWriteLocker locker2(&m_dataMutex);
      auto const length = static_cast<int>
	(maximumBufferSize) - m_data.length();

      if(length > 0)
	m_data.append(data.mid(0, length));

      if(!m_data.isEmpty())
	{
	  locker2.unlock();
	  emit newData();
	}
    }
  else
    {
      emit notification
	(QString("The neighbor %1:%2 generated a fatal error (%3).").
	 arg(m_address).arg(m_port).
	 arg("zero data received on ready-read signal"));
      spoton_misc::logError
	(QString("spoton_neighbor::readyRead(): "
		 "Did not receive data. Closing connection for "
		 "%1:%2.").
	 arg(m_address).
	 arg(m_port));
      deleteLater();
    }
}

void spoton_neighbor::slotAccountAuthenticated(const QByteArray &clientSalt,
					       const QByteArray &name,
					       const QByteArray &password)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!(state() == QAbstractSocket::BoundState ||
       state() == QAbstractSocket::ConnectedState))
    return;
  else if(name.length() < 32 || password.length() < 32)
    return;

  QByteArray hash;
  QByteArray message;
  auto const salt(spoton_crypt::
		   strongRandomBytes(spoton_common::
				     ACCOUNTS_RANDOM_BUFFER_SIZE));
  auto ok = true;

  /*
  ** The server authenticated the client's credentials. We'll
  ** now create a similar response so that the client can
  ** verify the server. We are the server.
  */

  hash = spoton_crypt::keyedHash
    (QDateTime::currentDateTimeUtc().toString("MMddyyyyhhmm").
     toLatin1() + clientSalt + salt,
     name + password,
     spoton_crypt::preferredHashAlgorithm(),
     &ok);

  if(ok)
    message = spoton_send::message0051(hash, salt);

  if(ok)
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotAccountAuthenticated(): "
		   "write() error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
    }
}

void spoton_neighbor::slotCallParticipant(const QByteArray &data,
					  const QString &messageType)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QByteArray message;
  auto const ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::crypt("chat")));

  if(spoton_kernel::setting("gui/chatSendMethod", "Artificial_GET").
     toString().toLower() == "artificial_get")
    {
      if(messageType == "0000a" || messageType == "0000c")
	message = spoton_send::message0000a(data,
					    spoton_send::
					    ARTIFICIAL_GET,
					    ae);
      else if(messageType == "0000b")
	message = spoton_send::message0000b(data,
					    spoton_send::
					    ARTIFICIAL_GET,
					    ae);
      else if(messageType == "0000d")
	message = spoton_send::message0000d(data,
					    spoton_send::
					    ARTIFICIAL_GET,
					    ae);
    }
  else
    {
      if(messageType == "0000a" || messageType == "0000c")
	message = spoton_send::message0000a(data,
					    spoton_send::
					    NORMAL_POST,
					    ae);
      else if(messageType == "0000b")
	message = spoton_send::message0000b(data,
					    spoton_send::
					    NORMAL_POST,
					    ae);
      else if(messageType == "0000d")
	message = spoton_send::message0000d(data,
					    spoton_send::
					    NORMAL_POST,
					    ae);
    }

  if(!message.isEmpty() && readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotCallParticipant(): write() "
		   "error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::slotConnected(void)
{
  if(m_sctpSocket)
    spoton_socket_options::setSocketOptions
      (m_socketOptions,
       m_transport,
       static_cast<qint64> (m_sctpSocket->socketDescriptor()),
       0);
  else if(m_tcpSocket)
    spoton_socket_options::setSocketOptions
      (m_socketOptions,
       m_transport,
       static_cast<qint64> (m_tcpSocket->socketDescriptor()),
       0);
  else if(m_udpSocket)
    {
      if(m_isUserDefined)
	{
	  spoton_socket_options::setSocketOptions
	    (m_socketOptions,
	     m_transport,
	     static_cast<qint64> (m_udpSocket->socketDescriptor()),
	     0);

	  QHostAddress address(m_address);

	  address.setScopeId(m_scopeId);
	  m_udpSocket->initializeMulticast(address, m_port, m_socketOptions);

	  if(m_udpSocket->multicastSocket())
	    connect(m_udpSocket->multicastSocket(),
		    SIGNAL(readyRead(void)),
		    this,
		    SLOT(slotReadyRead(void)),
		    Qt::UniqueConnection);
	}
    }
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      recordCertificateOrAbort();
#endif
    }

  /*
  ** The local address is the address of the proxy. Unfortunately,
  ** we do not have a network interface that has such an address.
  ** Hence, m_networkInterface will always be zero. The object
  ** m_networkInterface was removed on 11/08/2013. The following
  ** logic remains.
  */

  if(m_tcpSocket)
    {
      if(m_tcpSocket->proxy().type() != QNetworkProxy::NoProxy)
	{
	  QHostAddress const address(m_ipAddress);

	  if(address.protocol() == QAbstractSocket::IPv4Protocol)
	    m_tcpSocket->setLocalAddress(QHostAddress("127.0.0.1"));
	  else
	    m_tcpSocket->setLocalAddress(QHostAddress("::1"));
	}
    }
  else if(m_udpSocket)
    {
      if(m_udpSocket->proxy().type() != QNetworkProxy::NoProxy)
	{
	  QHostAddress const address(m_ipAddress);

	  if(address.protocol() == QAbstractSocket::IPv4Protocol)
	    m_udpSocket->setLocalAddress(QHostAddress("127.0.0.1"));
	  else
	    m_udpSocket->setLocalAddress(QHostAddress("::1"));
	}
    }

  if(m_id != -1)
    {
      auto s_crypt = spoton_kernel::crypt("chat");

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    auto db(spoton_misc::database(connectionName));

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		QString country("Unknown");

		if(m_sctpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_sctpSocket->peerAddress().isNull() ?
		     m_sctpSocket->peerName() :
		     m_sctpSocket->peerAddress().toString());
		else if(m_tcpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_tcpSocket->peerAddress().isNull() ?
		     m_tcpSocket->peerName() :
		     m_tcpSocket->peerAddress().toString());
		else if(m_udpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_udpSocket->peerAddress().isNull() ?
		     m_udpSocket->peerName() :
		     m_udpSocket->peerAddress().toString());
		else if(m_webSocket)
		  {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
		    country = spoton_misc::countryNameFromIPAddress
		      (m_webSocket->peerAddress().isNull() ?
		       m_webSocket->peerName() :
		       m_webSocket->peerAddress().toString());
#endif
		  }

		auto ok = true;

		query.prepare("UPDATE neighbors SET country = ?, "
			      "is_encrypted = ?, "
			      "local_ip_address = ?, "
			      "local_port = ?, qt_country_hash = ?, "
			      "status = 'connected' "
			      "WHERE OID = ?");
		query.bindValue
		  (0, s_crypt->
		   encryptedThenHashed(country.toLatin1(), &ok).toBase64());
		query.bindValue(1, isEncrypted() ? 1 : 0);

		if(m_bluetoothSocket)
		  {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
		    query.bindValue
		      (2, m_bluetoothSocket->localAddress().toString());
		    query.bindValue
		      (3, m_bluetoothSocket->localPort());
#endif
		  }
		else if(m_sctpSocket)
		  {
		    query.bindValue
		      (2, m_sctpSocket->localAddress().toString());
		    query.bindValue(3, m_sctpSocket->localPort());
		  }
		else if(m_tcpSocket)
		  {
		    query.bindValue
		      (2, m_tcpSocket->localAddress().toString());
		    query.bindValue(3, m_tcpSocket->localPort());
		  }
		else if(m_udpSocket)
		  {
		    query.bindValue
		      (2, m_udpSocket->localAddress().toString());
		    query.bindValue(3, m_udpSocket->localPort());
		  }
		else if(m_webSocket)
		  {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
		    query.bindValue
		      (2, m_webSocket->localAddress().toString());
		    query.bindValue(3, m_webSocket->localPort());
#endif
		  }

		if(ok)
		  query.bindValue
		    (4, s_crypt->keyedHash(country.remove(" ").
					   toLatin1(), &ok).
		     toBase64());

		query.bindValue(5, m_id);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }

  /*
  ** Initial discovery of the external IP address.
  */

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).toInt() != -1)
    {
      if(m_externalAddress)
	{
	  m_externalAddress->discover();
	  m_externalAddressDiscovererTimer.start();
	}
      else
	m_externalAddressDiscovererTimer.stop();
    }
  else
    {
      if(m_externalAddress)
	m_externalAddress->clear();

      m_externalAddressDiscovererTimer.stop();
    }

  m_lastReadTime = QDateTime::currentDateTime();

  if(!m_keepAliveTimer.isActive())
    m_keepAliveTimer.start();

  if(m_useAccounts.fetchAndAddOrdered(0))
    if(!m_useSsl)
      {
	m_accountTimer.start();
	m_authenticationTimer.start();
      }

  if(!m_useSsl)
    QTimer::singleShot(250, this, SLOT(slotSendCapabilities(void)));

  QTimer::singleShot(30000, this, SLOT(slotSendMOTD(void)));
}

void spoton_neighbor::slotDisconnected(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotDisconnected(): "
	     "aborting socket for %1:%2!").
     arg(m_address).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotDiscoverExternalAddress(void)
{
  if(m_externalAddress)
    if(state() == QAbstractSocket::BoundState ||
       state() == QAbstractSocket::ConnectedState)
      m_externalAddress->discover();
}

void spoton_neighbor::slotEncrypted(void)
{
  recordCertificateOrAbort();
  QTimer::singleShot(250, this, SLOT(slotSendCapabilities(void)));
}

void spoton_neighbor::slotError(QAbstractSocket::SocketError error)
{
  if(error == QAbstractSocket::ConnectionRefusedError)
    {
      if(!m_bindIpAddress.isEmpty())
	/*
	** Server-less!
	*/

	return;
    }
  else if(error == QAbstractSocket::DatagramTooLargeError ||
	  error == QAbstractSocket::TemporaryError)
    return;
  else if(error == QAbstractSocket::SslHandshakeFailedError)
    {
      /*
      ** Do not use SSL.
      */

      if(!m_requireSsl)
	{
	  m_sslControlString = "N/A";
	  m_useSsl = false;

	  if(m_tcpSocket)
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotError(): socket error "
		       "(%1) for %2:%3. Disabling SSL.").
	       arg(m_tcpSocket->errorString()).arg(m_address).arg(m_port));
	  else if(m_webSocket)
	    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	      spoton_misc::logError
		(QString("spoton_neighbor::slotError(): socket error "
			 "(%1) for %2:%3. Disabling SSL.").
		 arg(m_webSocket->errorString()).arg(m_address).arg(m_port));
#endif
	    }

	  return;
	}
    }

  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): "
	     "fatal socket error (%1) for %2:%3.").
     arg(error).arg(m_address).arg(m_port));

  if(m_tcpSocket)
    {
      emit notification
	(QString("The neighbor %1:%2 generated a fatal error (%3).").
	 arg(m_address).arg(m_port).arg(m_tcpSocket->errorString()));
      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): "
		 "fatal socket error (%1) for %2:%3.").
	 arg(m_tcpSocket->errorString()).arg(m_address).arg(m_port));
    }
  else if(m_udpSocket)
    {
      emit notification
	(QString("The neighbor %1:%2 generated an error (%3).").
	 arg(m_address).arg(m_port).arg(m_udpSocket->errorString()));
      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): "
		 "fatal socket error (%1) for %2:%3.").
	 arg(m_udpSocket->errorString()).arg(m_address).arg(m_port));
    }
  else if(m_webSocket)
    {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
      emit notification
	(QString("The neighbor %1:%2 generated a fatal error (%3).").
	 arg(m_address).arg(m_port).arg(m_webSocket->errorString()));
      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): "
		 "fatal socket error (%1) for %2:%3.").
	 arg(m_webSocket->errorString()).arg(m_address).arg(m_port));
#endif
    }
  else
    emit notification
      (QString("The neighbor %1:%2 generated a fatal error (%3).").
       arg(m_address).arg(m_port).arg(error));

  deleteLater();
}

#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
void spoton_neighbor::slotError(QBluetoothSocket::SocketError error)
{
  if(error == QBluetoothSocket::SocketError::NoSocketError)
    return;

  if(m_bluetoothSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): socket error (%1) for %2:%3.").
       arg(m_bluetoothSocket->errorString()).arg(m_address).arg(m_port));

  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): socket error for %1:%2.").
     arg(m_address).arg(m_port));

  if(error != QBluetoothSocket::SocketError::UnknownSocketError)
    {
      if(m_bluetoothSocket)
	emit notification
	  (QString("The neighbor %1:%2 generated a fatal error (%3).").
	   arg(m_address).arg(m_port).arg(m_bluetoothSocket->errorString()));
      else
	emit notification
	  (QString("The neighbor %1:%2 generated a fatal error.").
	   arg(m_address).arg(m_port));

      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): "
		 "socket error for %1:%2. Aborting.").
	 arg(m_address).arg(m_port));
      deleteLater();
    }
}
#endif

void spoton_neighbor::slotError
(const QString &method, const spoton_sctp_socket::SocketError error)
{
  emit notification
    (QString("The neighbor %1:%2 generated a fatal error (%3).").
     arg(m_address).arg(m_port).arg(error));
  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): socket error (%1:%2) for %3:%4. "
	     "Aborting socket.").
     arg(method).arg(error).arg(m_address).arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotExternalAddressDiscovered
(const QHostAddress &address)
{
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      saveExternalAddress(address, db);

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotHostFound(const QHostInfo &hostInfo)
{
  foreach(auto const &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_address = address.toString();
	m_ipAddress = m_address;
	break;
      }
}

void spoton_neighbor::slotLifetimeExpired(void)
{
  emit notification
    (QString("The neighbor %1:%2 generated a fatal error (%3).").
     arg(m_address).arg(m_port).arg("lifetime expired"));
  spoton_misc::logError
    (QString("spoton_neighbor::slotLifetimeExpired(): "
	     "expiration time reached for %1:%2. Aborting socket.").
     arg(m_address).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotModeChanged(QSslSocket::SslMode mode)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotModeChanged(): "
	     "the connection mode has changed to %1 for %2:%3.").
     arg(mode).
     arg(m_address).
     arg(m_port));

  if(m_useSsl)
    {
      if(mode == QSslSocket::UnencryptedMode)
	{
	  emit notification
	    (QString("The neighbor %1:%2 generated a fatal error (%3).").
	     arg(m_address).arg(m_port).arg("unencrypted connection"));
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotModeChanged(): "
		     "unencrypted connection mode for %1:%2. Aborting.").
	     arg(m_address).
	     arg(m_port));
	  deleteLater();
	  return;
	}

      if(m_useAccounts.fetchAndAddOrdered(0))
	{
	  m_accountTimer.start();
	  m_authenticationTimer.start();
	}
    }
  else
    m_sslControlString = "N/A";
}

void spoton_neighbor::slotPeerVerifyError(const QSslError &error)
{
  /*
  ** This method may be called several times!
  */

  auto shouldDelete = true;

  if(error.error() == QSslError::CertificateUntrusted ||
     error.error() == QSslError::HostNameMismatch ||
     error.error() == QSslError::SelfSignedCertificate)
    shouldDelete = false;

  if(shouldDelete)
    {
      emit notification
	(QString("The neighbor %1:%2 generated a fatal error (%3).").
	 arg(m_address).arg(m_port).arg(error.errorString()));
      spoton_misc::logError
	(QString("spoton_neighbor::slotPeerVerifyError(): instructed "
		 "to delete neighbor for %1:%2.").
	 arg(m_address).
	 arg(m_port));
      deleteLater();
      return;
    }

  if(!m_bindIpAddress.isEmpty())
    return;

  if(!m_allowExceptions)
    if(m_isUserDefined)
      if(m_tcpSocket)
	if(!m_peerCertificate.isNull() &&
	   !m_tcpSocket->peerCertificate().isNull())
	  if(!m_peerCertificate.toPem().isEmpty() &&
	     !m_tcpSocket->peerCertificate().toPem().isEmpty())
	    if(!spoton_crypt::memcmp(m_peerCertificate.toPem(),
				     m_tcpSocket->peerCertificate().toPem()))
	      {
		emit notification
		  (QString("The neighbor %1:%2 generated a fatal error (%3).").
		   arg(m_address).arg(m_port).arg("certificate mismatch"));
		spoton_misc::logError
		  (QString("spoton_neighbor::slotPeerVerifyError(): "
			   "the stored certificate does not match "
			   "the peer's certificate for %1:%2. This is a "
			   "serious problem! Aborting.").
		   arg(m_address).
		   arg(m_port));
		deleteLater();
	      }
}

void spoton_neighbor::slotProxyAuthenticationRequired
(const QNetworkProxy &proxy, QAuthenticator *authenticator)
{
  Q_UNUSED(proxy);

  if(authenticator)
    {
      if(m_tcpSocket)
	{
	  authenticator->setPassword(m_tcpSocket->proxy().password());
	  authenticator->setUser(m_tcpSocket->proxy().user());
	}
      else if(m_udpSocket)
	{
	  authenticator->setPassword(m_udpSocket->proxy().password());
	  authenticator->setUser(m_udpSocket->proxy().user());
	}
      else if(m_webSocket)
	{
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	  authenticator->setPassword(m_webSocket->proxy().password());
	  authenticator->setUser(m_webSocket->proxy().user());
#endif
	}
      else
	*authenticator = QAuthenticator();
    }
}

#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
void spoton_neighbor::slotPublicizeListenerPlaintext
(const QBluetoothAddress &address,
 const quint16 port,
 const QString &orientation)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!address.isNull())
    if(readyToWrite())
      {
	auto const message
	  (spoton_send::message0030(address, port, orientation));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotPublicizeListenerPlaintext(): "
		     "write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  spoton_kernel::messagingCacheAdd(message);
      }
}
#endif

void spoton_neighbor::slotPublicizeListenerPlaintext(const QByteArray &data,
						     const qint64 id)
{
  if(id == m_id)
    return;

  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  /*
  ** A neighbor (id) received a request to publish listener information.
  ** This neighbor now needs to send the message to its peer.
  */

  QReadLocker locker(&m_echoModeMutex);
  auto const echoMode(m_echoMode);

  locker.unlock();

  if(echoMode == "full")
    if(readyToWrite())
      {
	auto const message(spoton_send::message0030(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::"
		     "slotPublicizeListenerPlaintext(): "
		     "write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  spoton_kernel::messagingCacheAdd(message);
      }
}

void spoton_neighbor::slotPublicizeListenerPlaintext
(const QHostAddress &address,
 const quint16 port,
 const QString &transport,
 const QString &orientation)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!address.isNull())
    if(readyToWrite())
      {
	auto const message
	  (spoton_send::message0030(address, port, transport, orientation));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotPublicizeListenerPlaintext(): "
		     "write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  spoton_kernel::messagingCacheAdd(message);
      }
}

void spoton_neighbor::slotReadyRead(void)
{
  if(m_abort.fetchAndAddOrdered(0))
    return;

  QByteArray data;

  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
      while(m_bluetoothSocket->bytesAvailable() > 0)
	data.append(m_bluetoothSocket->readAll());
#endif
    }
  else if(m_sctpSocket)
    data = m_sctpSocket->readAll();
  else if(m_tcpSocket)
    while(m_tcpSocket->bytesAvailable() > 0)
      data.append(m_tcpSocket->readAll());
  else if(m_udpSocket)
    {
      while(m_udpSocket->hasPendingDatagrams())
	{
	  QByteArray datagram;
	  QHostAddress peerAddress;
	  quint16 peerPort = 0;
	  auto size = qMax
	    (static_cast<qint64> (0), m_udpSocket->pendingDatagramSize());

	  datagram.resize(static_cast<int> (size));
	  size = m_udpSocket->readDatagram
	    (datagram.data(), size, &peerAddress, &peerPort);

	  if(size <= 0)
	    continue;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) &&	\
  !defined(SPOTON_DTLS_DISABLED)
	  if(m_dtls && m_isUserDefined)
	    {
	      m_bytesRead += static_cast<quint64> (datagram.length());

	      if(m_dtls->isConnectionEncrypted())
		{
		  datagram = m_dtls->decryptDatagram(m_udpSocket, datagram);

		  if(m_dtls->dtlsError() ==
		     QDtlsError::RemoteClosedConnectionError)
		    {
		      spoton_misc::logError
			(QString("spoton_neighbor::slotReadyRead(): "
				 "%1:%2 closed the connection. Aborting.").
			 arg(m_address).
			 arg(m_port));
		      deleteLater();
		      return;
		    }
		  else
		    {
		      data.append(datagram);
		      m_lastReadTime = QDateTime::currentDateTime();
		    }
		}
	      else
		{
		  if(!m_dtls->doHandshake(m_udpSocket, datagram))
		    {
		      if(!(m_dtls->dtlsError() == QDtlsError::NoError ||
			   m_dtls->dtlsError() == QDtlsError::TlsNonFatalError))
			{
			  m_dtls->abortHandshake(m_udpSocket);
			  spoton_misc::logError
			    (QString("spoton_neighbor::slotReadyRead(): "
				     "DTLS error (%1) for %2:%3. Aborting.").
			     arg(m_dtls->dtlsErrorString()).
			     arg(m_address).
			     arg(m_port));
			  deleteLater();
			}
		    }
		  else if(m_dtls->handshakeState() == QDtls::HandshakeComplete)
		    recordCertificateOrAbort();

		  return;
		}
	    }
	  else
	    data.append(datagram);
#else
	  data.append(datagram);
#endif
	}

      while(m_udpSocket->multicastSocket() &&
	    m_udpSocket->multicastSocket()->hasPendingDatagrams())
	{
	  QByteArray datagram;
	  auto size = qMax
	    (static_cast<qint64> (0),
	     m_udpSocket->multicastSocket()->pendingDatagramSize());

	  datagram.resize(static_cast<int> (size));
	  size = m_udpSocket->multicastSocket()->readDatagram
	    (datagram.data(), size);

	  if(size > 0)
	    data.append(datagram.mid(0, static_cast<int> (size)));
	}
    }

  if(!data.isEmpty())
    emit bytesReceived(static_cast<qint64> (data.length()));

  m_bytesRead += static_cast<quint64> (data.length());

  {
    QWriteLocker locker
      (&spoton_kernel::s_totalNeighborsBytesReadWrittenMutex);

    spoton_kernel::s_totalNeighborsBytesReadWritten.first +=
      static_cast<quint64> (data.length());
  }

  if(!data.isEmpty() && !isEncrypted() && m_useSsl)
    {
      data.clear();
      spoton_misc::logError
	(QString("spoton_neighbor::slotReadyRead(): "
		 "m_useSsl is true, however, isEncrypted() is false "
		 "for %1:%2. Purging read data.").
	 arg(m_address).
	 arg(m_port));
    }

  readyRead(data);
}

void spoton_neighbor::slotResetKeepAlive(void)
{
  m_lastReadTime = QDateTime::currentDateTime();
  spoton_kernel::s_sendInitialStatus.testAndSetOrdered(0, 1);
}

void spoton_neighbor::slotRetrieveMail(const QByteArrayList &list,
				       const QString &messageType)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	auto const ae
	  (spoton_misc::
	   decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
				     spoton_kernel::crypt("chat")));

	if(messageType == "0002a")
	  message = spoton_send::message0002a(list.at(i), ae);
	else
	  message = spoton_send::message0002b(list.at(i), ae);

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotRetrieveMail(): write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  spoton_kernel::messagingCacheAdd(message);
      }
}

void spoton_neighbor::slotSendAccountInformation(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!(state() == QAbstractSocket::BoundState ||
       state() == QAbstractSocket::ConnectedState))
    return;

  auto s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    return;

  QByteArray name;
  QByteArray password;
  auto ok = true;

  QReadLocker locker1(&m_accountNameMutex);

  name = m_accountName;
  locker1.unlock();

  QReadLocker locker2(&m_accountPasswordMutex);

  password = m_accountPassword;
  locker2.unlock();
  name = s_crypt->decryptedAfterAuthenticated(name, &ok);

  if(ok)
    password = s_crypt->decryptedAfterAuthenticated(password, &ok);

  if(ok)
    if(name.length() >= 32 && password.length() >= 32)
      {
	QByteArray hash;
	QByteArray message;
	auto const salt
	  (spoton_crypt::
	   strongRandomBytes(spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE));

	hash = spoton_crypt::keyedHash
	  (QDateTime::currentDateTimeUtc().toString("MMddyyyyhhmm").
	   toLatin1() + salt,
	   name + password,
	   spoton_crypt::preferredHashAlgorithm(),
	   &ok);

	if(ok)
	  message = spoton_send::message0050(hash, salt);

	if(ok)
	  {
	    if(write(message.constData(), message.length()) !=
	       message.length())
	      spoton_misc::logError
		(QString("spoton_neighbor::slotSendAccountInformation(): "
			 "write() error for %1:%2.").
		 arg(m_address).
		 arg(m_port));
	    else
	      {
		QWriteLocker locker(&m_accountClientSentSaltMutex);

		m_accountClientSentSalt = salt;
	      }
	  }
      }
}

void spoton_neighbor::slotSendAuthenticationRequest(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!(state() == QAbstractSocket::BoundState ||
       state() == QAbstractSocket::ConnectedState))
    return;

  auto const message(spoton_send::message0052());

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendAuthenticationRequest(): "
	       "write() error for %1:%2.").
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::slotSendBuzz(const QByteArray &data)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(readyToWrite())
    {
      if(write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendBuzz(): write() error for "
		   "%1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(data);
    }
}

void spoton_neighbor::slotSendCapabilities(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(m_passthrough)
    return;
  else if(!readyToWrite())
    return;

  QByteArray message;
  QReadLocker locker(&m_echoModeMutex);
  auto const echoMode(m_echoMode);

  locker.unlock();

  QUuid uuid
    (spoton_kernel::
     setting("gui/uuid", "{00000000-0000-0000-0000-000000000000}").toString());

  message = spoton_send::message0014(uuid.toString().toLatin1() + "\n" +
				     QByteArray::number(m_laneWidth) + "\n" +
				     echoMode.toLatin1());

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendCapabilities(): "
	       "write() error for %1:%2.").
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::slotSendMOTD(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(m_passthrough)
    return;
  else if(!readyToWrite())
    return;

  auto const message(spoton_send::message0070(m_motd.toUtf8()));

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendMOTD(): write() error for %1:%2.").
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::slotSendMail(const QPairByteArrayInt64List &list,
				   const QString &messageType)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QList<qint64> oids;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	auto const ae
	  (spoton_misc::
	   decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
				     spoton_kernel::crypt("chat")));
	auto const pair(list.at(i));

	if(messageType == "0001a")
	  message = spoton_send::message0001a(pair.first, ae);
	else if (messageType == "0001b")
	  message = spoton_send::message0001b(pair.first, ae);
	else
	  message = spoton_send::message0001c(pair.first, ae);

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotSendMail(): write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  {
	    /*
	    ** We may need to store the letter that this node sent if
	    ** the node is also a post office box.
	    ** Almost-anonymous e-mail shall not be archived.
	    */

	    if(messageType != "0001c")
	      if(spoton_kernel::setting("gui/postoffice_enabled",
					false).toBool())
		{
		  QWriteLocker locker(&m_dataMutex);

		  m_data.append(message);
		  locker.unlock();
		  processData();
		}

	    oids.append(pair.second);
	    spoton_kernel::messagingCacheAdd(message);
	  }
      }

  if(!oids.isEmpty())
    {
      auto s_crypt = spoton_kernel::crypt("email");

      spoton_mailer::moveSentMailToSentFolder(oids, s_crypt);
    }
}

void spoton_neighbor::slotSendMailFromPostOffice
(const QByteArray &data, const QPairByteArrayByteArray &adaptiveEchoPair)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QReadLocker locker(&m_learnedAdaptiveEchoPairsMutex);
  auto adaptiveEcho = false;

  if(adaptiveEchoPair == QPair<QByteArray, QByteArray> () ||
     m_learnedAdaptiveEchoPairs.contains(adaptiveEchoPair))
    adaptiveEcho = true;

  locker.unlock();

  if(adaptiveEcho && readyToWrite())
    {
      QByteArray message;
      auto const ae
	(spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						spoton_kernel::crypt("chat")));

      message = spoton_send::message0001b(data, ae);

      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendMailFromPostOffice(): write() "
		   "error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(data);
    }
}

void spoton_neighbor::slotSendMessage
(const QByteArray &data, const spoton_send::spoton_send_method sendMethod)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;
  else if(!readyToWrite())
    return;

  QByteArray message;
  auto const ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::crypt("chat")));

  message = spoton_send::message0000(data, sendMethod, ae);

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendMessage(): write() error "
	       "for %1:%2.").
       arg(m_address).
       arg(m_port));
  else
    spoton_kernel::messagingCacheAdd(message);
}

void spoton_neighbor::slotSendStatus(const QByteArrayList &list)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	auto const ae
	  (spoton_misc::
	   decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
				     spoton_kernel::crypt("chat")));

	message = spoton_send::message0013(list.at(i), ae);

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotSendStatus(): write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else
	  spoton_kernel::messagingCacheAdd(message);
      }
}

void spoton_neighbor::slotSharePublicKey(const QByteArray &keyType,
					 const QByteArray &name,
					 const QByteArray &publicKey,
					 const QByteArray &signature,
					 const QByteArray &sPublicKey,
					 const QByteArray &sSignature)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(m_id == -1)
    return;
  else if(!readyToWrite())
    return;

  QByteArray message;

  message.append(keyType.toBase64());
  message.append("\n");
  message.append(name.toBase64());
  message.append("\n");
  message.append(publicKey.toBase64());
  message.append("\n");
  message.append(signature.toBase64());
  message.append("\n");
  message.append(sPublicKey.toBase64());
  message.append("\n");
  message.append(sSignature.toBase64());
  message = spoton_send::message0012(message);

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSharePublicKey(): "
	       "write() failure for %1:%2.").
       arg(m_address).
       arg(m_port));
  else
    {
      auto s_crypt = spoton_kernel::crypt("chat");

      if(!s_crypt)
	return;

      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    auto ok = true;

	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE "
			  "key_type_hash = ? AND "
			  "neighbor_oid = ?");
	    query.bindValue(0, s_crypt->keyedHash(keyType, &ok).toBase64());
	    query.bindValue(1, m_id);

	    if(ok)
	      query.exec();

	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE "
			  "key_type_hash = ? AND "
			  "neighbor_oid = ?");

	    if(ok)
	      query.bindValue
		(0, s_crypt->keyedHash(keyType + "-signature", &ok).
		 toBase64());

	    query.bindValue(1, m_id);

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton_neighbor::slotSslErrors(const QList<QSslError> &errors)
{
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  if(m_webSocket)
    for(int i = 0; i < errors.size(); i++)
      if(errors.at(i).error() == QSslError::CertificateUntrusted ||
	 errors.at(i).error() == QSslError::HostNameMismatch ||
	 errors.at(i).error() == QSslError::SelfSignedCertificate)
	{
	  m_webSocket->ignoreSslErrors();
	  break;
	}
#endif

  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError(QString("spoton_neighbor::slotSslErrors(): "
				  "error (%1) occurred from %2:%3.").
			  arg(errors.at(i).errorString()).
			  arg(m_address).
			  arg(m_port));
}

void spoton_neighbor::slotTimeout(void)
{
  if(m_silenceTime > 0 &&
     qAbs(m_lastReadTime.secsTo(QDateTime::currentDateTime())) >= m_silenceTime)
    {
      emit notification
	(QString("The neighbor %1:%2 generated a fatal error (%3).").
	 arg(m_address).arg(m_port).
	 arg("aborting because of silent connection"));
      spoton_misc::logError
	(QString("spoton_neighbor::slotTimeout(): "
		 "aborting because of silent (%1) connection for %2:%3.").
	 arg(m_silenceTime).
	 arg(m_address).
	 arg(m_port));
      deleteLater();
      return;
    }

  /*
  ** We'll change socket states here.
  */

  QString connectionName("");
  QString status("");
  auto shouldDelete = false;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	saveStatistics(db);

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, "           // 0
		      "sticky, "                          // 1
		      "echo_mode, "                       // 2
		      "maximum_buffer_size, "             // 3
		      "maximum_content_length, "          // 4
		      "account_name, "                    // 5
		      "account_password, "                // 6
		      "ae_token, "                        // 7
		      "ae_token_type, "                   // 8
		      "ssl_control_string, "              // 9
		      "priority, "                        // 10
		      "lane_width, "                      // 11
		      "passthrough, "                     // 12
		      "waitforbyteswritten_msecs, "       // 13
		      "private_application_credentials, " // 14
		      "silence_time "                     // 15
		      "FROM neighbors WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		status = query.value(0).toString().toLower();

		if(status == "blocked" ||
		   status == "deleted" ||
		   status == "disconnected")
		  {
		    saveStatus(db, status);
		    shouldDelete = true;
		  }
		else
		  {
		    auto s_crypt = spoton_kernel::crypt("chat");

		    if(s_crypt)
		      {
			QWriteLocker locker(&m_echoModeMutex);
			auto ok = true;

			m_echoMode = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(2).
						  toByteArray()),
			   &ok);

			if(!ok)
			  m_echoMode = "full";

			locker.unlock();

			if(m_isUserDefined)
			  {
			    m_adaptiveEchoPair.first =
			      m_adaptiveEchoPair.second = QByteArray();

			    if(!query.isNull(7) && !query.isNull(8))
			      {
				QPair<QByteArray, QByteArray> pair
				  (QByteArray::fromBase64(query.value(7).
							  toByteArray()),
				   QByteArray::fromBase64(query.value(8).
							  toByteArray()));

				m_adaptiveEchoPair = pair;
			      }
			  }

			if(m_isUserDefined &&
			   !m_accountAuthenticated.fetchAndAddOrdered(0))
			  {
			    QByteArray aName;
			    QByteArray aPassword;
			    auto name
			      (QByteArray::fromBase64(query.value(5).
						      toByteArray()));
			    auto password
			      (QByteArray::fromBase64(query.value(6).
						      toByteArray()));

			    {
			      QReadLocker locker1(&m_accountNameMutex);

			      aName = m_accountName;
			      locker1.unlock();

			      QReadLocker locker2(&m_accountPasswordMutex);

			      aPassword = m_accountPassword;
			      locker2.unlock();
			    }

			    if(!spoton_crypt::memcmp(name, aName) ||
			       !spoton_crypt::memcmp(password, aPassword))
			      {
				auto ok = true;

				{
				  QWriteLocker locker1
				    (&m_accountNameMutex);

				  m_accountName = name;
				  locker1.unlock();

				  QWriteLocker locker2
				    (&m_accountPasswordMutex);

				  m_accountPassword = password;
				  locker2.unlock();
				}

				name = s_crypt->decryptedAfterAuthenticated
				  (name, &ok);

				if(ok)
				  password = s_crypt->
				    decryptedAfterAuthenticated
				    (password, &ok);

				if(ok)
				  {
				    if(!name.isEmpty() &&
				       !password.isEmpty())
				      m_useAccounts.fetchAndStoreOrdered(1);
				    else
				      m_useAccounts.fetchAndStoreOrdered(0);
				  }
				else
				  m_useAccounts.fetchAndStoreOrdered(0);

				if(m_useAccounts.fetchAndAddOrdered(0))
				  {
				    m_accountTimer.start();
				    m_authenticationTimer.start();
				  }
				else
				  {
				    m_accountTimer.stop();
				    m_authenticationTimer.stop();
				  }
			      }
			  }

			if(query.isNull(14))
			  m_privateApplicationCredentials.clear();
			else
			  m_privateApplicationCredentials = s_crypt->
			    decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(14).
						    toByteArray()),
			     &ok);
		      }

		    m_laneWidth = qBound
		      (spoton_common::LANE_WIDTH_MINIMUM,
		       query.value(11).toInt(),
		       spoton_common::LANE_WIDTH_MAXIMUM);

		    QWriteLocker locker1(&m_maximumBufferSizeMutex);

		    m_maximumBufferSize =
		      qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
			     query.value(3).toLongLong(),
			     spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
		    locker1.unlock();

		    QWriteLocker locker2(&m_maximumContentLengthMutex);

		    m_maximumContentLength =
		      qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
			     query.value(4).toLongLong(),
			     spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
		    locker2.unlock();

		    if(isRunning())
		      {
			Priority p = priority();
			Priority q = HighPriority;

			q = Priority(query.value(10).toInt());

			if(q < 0 || q > 6)
			  q = HighPriority;

			if(isRunning() && p != q)
			  setPriority(q);
		      }

		    m_passthrough = query.value(12).toInt();
		    m_silenceTime = qBound
		      (0,
		       query.value(15).toInt(),
		       std::numeric_limits<int>::max());
		    m_sslControlString = query.value(9).toString();

		    if(m_sslControlString.isEmpty())
		      {
			if(m_useSsl)
			  m_sslControlString =
			    spoton_common::SSL_CONTROL_STRING;
			else
			  m_sslControlString = "N/A";
		      }
		    else if(!m_useSsl)
		      m_sslControlString = "N/A";

		    m_waitforbyteswritten_msecs = qBound
		      (0,
		       query.value(13).toInt(),
		       spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM);
		  }

		if(query.value(1).toLongLong())
		  m_lifetime.stop();
		else if(!m_lifetime.isActive())
		  m_lifetime.start();
	      }
	    else if(m_id != -1)
	      {
		if(query.lastError().isValid())
		  shouldDelete = true;
	      }
	  }
	else if(m_id != -1 && query.lastError().isValid())
	  {
	    QFileInfo const fileInfo
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(!fileInfo.exists())
	      shouldDelete = true;
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(shouldDelete)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotTimeout(): instructed "
		 "to delete neighbor for %1:%2.").
	 arg(m_address).
	 arg(m_port));
      deleteLater();
      return;
    }

  m_kernelInterfaces.fetchAndStoreOrdered(spoton_kernel::interfaces());

  if(m_isUserDefined)
    if(status == "connected")
      {
	if(m_transport == "bluetooth")
	  {
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
#ifndef Q_OS_MACOS
	    QList<QBluetoothServiceInfo> list;

	    if(m_bluetoothServiceDiscoveryAgent && !m_bluetoothSocket)
	      {
		list = m_bluetoothServiceDiscoveryAgent->discoveredServices();

		if(!m_bluetoothServiceDiscoveryAgent->isActive())
		  m_bluetoothServiceDiscoveryAgent->start
		    (QBluetoothServiceDiscoveryAgent::FullDiscovery);
	      }
#endif

#ifdef Q_OS_MACOS
	    for(int i = 0; i < 1; i++)
#else
	    for(int i = 0; i < list.size(); i++)
#endif
	      {
		if(m_bluetoothSocket)
		  break;

		QByteArray bytes;
		QString serviceUuid;

		bytes.append(QByteArray::number(m_port).toHex());
		bytes = bytes.rightJustified(12, '0');
		serviceUuid.append(bytes.mid(0, 8));
		serviceUuid.append("-");
		serviceUuid.append(bytes.mid(8));
		serviceUuid.append("-0000-0000-");
		serviceUuid.append(QString(m_address).remove(":"));

#ifndef Q_OS_MACOS
		if(QBluetoothUuid(serviceUuid) == list.at(i).serviceUuid())
#endif
		  {
		    m_bluetoothSocket = new QBluetoothSocket
		      (QBluetoothServiceInfo::RfcommProtocol, this);
		    connect(m_bluetoothSocket,
			    SIGNAL(connected(void)),
			    this,
			    SLOT(slotConnected(void)));
		    connect(m_bluetoothSocket,
			    SIGNAL(disconnected(void)),
			    this,
			    SIGNAL(disconnected(void)));
		    connect(m_bluetoothSocket,
			    SIGNAL(disconnected(void)),
			    this,
			    SLOT(slotDisconnected(void)));
		    connect(m_bluetoothSocket,
			    SIGNAL(error(QBluetoothSocket::SocketError)),
			    this,
			    SLOT(slotError(QBluetoothSocket::SocketError)));
		    connect(m_bluetoothSocket,
			    SIGNAL(readyRead(void)),
			    this,
			    SLOT(slotReadyRead(void)));
		    m_bluetoothSocket->connectToService
		      (QBluetoothAddress(m_address),
		       QBluetoothUuid(serviceUuid));
		    saveStatus("connecting");
		    break;
		  }
	      }
#endif
	  }
	else if(m_sctpSocket)
	  {
	    if(m_sctpSocket->state() == spoton_sctp_socket::UnconnectedState)
	      {
		saveStatus("connecting");
		m_sctpSocket->connectToHost(m_address, m_port, m_socketOptions);
	      }
	  }
	else if(m_tcpSocket)
	  {
	    if(m_bindIpAddress.isEmpty())
	      {
		if(m_tcpSocket->state() == QAbstractSocket::UnconnectedState)
		  {
		    saveStatus("connecting");

		    if(m_useSsl)
		      m_tcpSocket->connectToHostEncrypted(m_address, m_port);
		    else
		      m_tcpSocket->connectToHost(m_address, m_port);
		  }
	      }
	  }
	else if(m_udpSocket)
	  {
	    if(m_udpSocket->state() == QAbstractSocket::UnconnectedState)
	      {
		saveStatus("connecting");
		m_udpSocket->connectToHost(m_address, m_port);

		int timeout = 2500;

		if(m_udpSocket->proxy().type() != QNetworkProxy::NoProxy)
		  timeout = 5000;

		if(!m_udpSocket->waitForConnected(timeout))
		  {
		    emit notification
		      (QString("The neighbor %1:%2 generated a fatal "
			       "error (%3).").
		       arg(m_address).arg(m_port).
		       arg("waitForConnected() failure"));
		    spoton_misc::logError
		      (QString("spoton_neighbor::slotTimeout(): "
			       "waitForConnected() failure for "
			       "%1:%2.").
		       arg(m_address).
		       arg(m_port));
		    deleteLater();
		    return;
		  }

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
		prepareDtls();

		if(m_dtls)
		  if(!m_dtls->doHandshake(m_udpSocket))
		    if(!(m_dtls->dtlsError() == QDtlsError::NoError ||
			 m_dtls->dtlsError() == QDtlsError::TlsNonFatalError))
		      {
			m_dtls->abortHandshake(m_udpSocket);
			spoton_misc::logError
			  (QString("spoton_neighbor::slotTimeout(): "
				   "DTLS error (%1) failure for "
				   "%2:%3. Aborting.").
			   arg(m_dtls->dtlsErrorString()).
			   arg(m_address).
			   arg(m_port));
			deleteLater();
			return;
		      }
#endif
	      }
	  }
	else if(m_webSocket)
	  {
#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	    if(m_webSocket->state() == QAbstractSocket::UnconnectedState)
	      {
		saveStatus("connecting");

		QUrl url;

		url.setHost(m_address);
		url.setPort(m_port);

		if(m_useSsl)
		  url.setScheme("wss");
		else
		  url.setScheme("ws");

		m_webSocket->open(url);
	      }
#endif
	  }
      }

  auto v = spoton_kernel::setting("gui/kernelExternalIpInterval", -1).toInt();

  if(v != -1)
    {
      v *= 1000;

      if(v == 30000)
	{
	  if(m_externalAddressDiscovererTimer.interval() != v)
	    m_externalAddressDiscovererTimer.start(30000);
	  else if(!m_externalAddressDiscovererTimer.isActive())
	    m_externalAddressDiscovererTimer.start(30000);
	}
      else
	{
	  if(m_externalAddressDiscovererTimer.interval() != v)
	    m_externalAddressDiscovererTimer.start(60000);
	  else if(!m_externalAddressDiscovererTimer.isActive())
	    m_externalAddressDiscovererTimer.start(60000);
	}
    }
  else
    {
      if(m_externalAddress)
	m_externalAddress->clear();

      m_externalAddressDiscovererTimer.stop();
    }

  for(int i = m_privateApplicationFutures.size() - 1; i >= 0; i--)
    if(m_privateApplicationFutures.at(i).isFinished())
      m_privateApplicationFutures.removeAt(i);

  /*
  ** Remove learned adaptive echo tokens that are not contained
  ** in the complete set of adaptive echo tokens.
  */

  QSet<QPair<QByteArray, QByteArray> > a;
  QWriteLocker locker2(&m_learnedAdaptiveEchoPairsMutex);

  for(int i = 0; i < m_learnedAdaptiveEchoPairs.size(); i++)
    a.insert(m_learnedAdaptiveEchoPairs.at(i));

  locker2.unlock();

  QSet<QPair<QByteArray, QByteArray> > b;
  auto const list(spoton_kernel::adaptiveEchoTokens());

  for(int i = 0; i < list.size(); i++)
    b.insert(list.at(i));

  a.intersect(b);
  locker2.relock();
  m_learnedAdaptiveEchoPairs.clear();

  QSetIterator<QPair<QByteArray, QByteArray> > it(a);

  while(it.hasNext())
    m_learnedAdaptiveEchoPairs.append(it.next());

  locker2.unlock();

  if(!m_isUserDefined &&
     !m_passthrough &&
     m_privateApplicationCredentials.isEmpty())
    if(m_sourceOfRandomness > 0)
      if(readyToWrite())
	write(spoton_crypt::
	      weakRandomBytes(static_cast<size_t> (m_sourceOfRandomness)).
	      constData(),
	      m_sourceOfRandomness);
}

void spoton_neighbor::slotWrite
(const QByteArray &data,
 const qint64 id,
 const QPairByteArrayByteArray &adaptiveEchoPair)
{
  /*
  ** A neighbor (id) received a message. The neighbor now needs
  ** to send the message to its peers.
  */

  if(id == m_id)
    return;

  if(data.length() > m_laneWidth)
    return;

  {
    QReadLocker locker(&m_echoModeMutex);

    if(m_echoMode != "full")
      return;
  }

  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
      m_privateApplicationFutures << QtConcurrent::run
	(&spoton_neighbor::parsePrivateApplicationData,
	 this,
	 data,
	 m_privateApplicationCredentials,
	 m_maximumContentLength);
#else
      m_privateApplicationFutures << QtConcurrent::run
	(this,
	 &spoton_neighbor::parsePrivateApplicationData,
	 data,
	 m_privateApplicationCredentials,
	 m_maximumContentLength);
#endif
      return;
    }

  {
    QReadLocker locker(&m_learnedAdaptiveEchoPairsMutex);

    if(!(adaptiveEchoPair == QPair<QByteArray, QByteArray> () ||
	 m_learnedAdaptiveEchoPairs.contains(adaptiveEchoPair)))
      return;
  }

  if(readyToWrite())
    {
      if(write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotWrite(): write() error for %1:%2.").
	   arg(m_address).arg(m_port));
      else if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
	spoton_kernel::messagingCacheAdd(data + QByteArray::number(id));
      else
	spoton_kernel::messagingCacheAdd(data);
    }
}

void spoton_neighbor::slotWriteURLs(const QByteArray &data)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;
  else if(!readyToWrite())
    return;

  QByteArray message;
  auto const ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::crypt("chat")));

  message = spoton_send::message0080(data, ae);

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotWriteURLs(): write() error "
	       "for %1:%2.").
       arg(m_address).
       arg(m_port));
  else
    spoton_kernel::messagingCacheAdd(message);
}
