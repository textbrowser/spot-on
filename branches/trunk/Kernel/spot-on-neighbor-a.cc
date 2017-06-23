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
#include <QDateTime>
#include <QDir>
#include <QSqlError>
#include <QSqlQuery>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslKey>
#include <QtCore/qmath.h>

#include <limits>

#include "Common/spot-on-common.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-receive.h"
#include "spot-on-kernel.h"
#include "spot-on-mailer.h"
#include "spot-on-neighbor.h"

extern "C"
{
#include "libSpotOn/libspoton.h"
}

extern "C"
{
#ifdef Q_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
}

spoton_neighbor::spoton_neighbor
(
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
 const int sourceOfRandomness,
 const QByteArray &privateApplicationCredentials,
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
 QBluetoothSocket *socket,
#endif
 QObject *parent):QThread(parent)
{
  m_abort = 0;
  m_kernelInterfaces = spoton_kernel::interfaces();
  m_laneWidth = qBound(spoton_common::LANE_WIDTH_MINIMUM,
		       laneWidth,
		       spoton_common::LANE_WIDTH_MAXIMUM);
  m_bluetoothSocket = 0;
  m_passthrough = passthrough;
  m_privateApplicationCredentials = privateApplicationCredentials;
  m_privateApplicationSequences.first = m_privateApplicationSequences.second =
    1;
  m_sctpSocket = 0;
  m_sourceOfRandomness = qBound
    (0,
     sourceOfRandomness,
     static_cast<int> (std::numeric_limits<unsigned short>::max()));
  m_tcpSocket = 0;
  m_udpSocket = 0;
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);

  if(transport == "bluetooth")
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_bluetoothSocket = socket;

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
	  socket->setParent(this);
	}
#endif
    }
  else if(transport == "sctp")
    m_sctpSocket = new spoton_sctp_socket(this);
  else if(transport == "tcp")
    m_tcpSocket = new spoton_neighbor_tcp_socket(this);
  else if(transport == "udp")
    m_udpSocket = new spoton_neighbor_udp_socket(this);

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
      m_tcpSocket->setSocketDescriptor(socketDescriptor);
    }
  else if(m_udpSocket)
    {
#ifdef Q_OS_WIN32
      m_udpSocket->setSocketDescriptor
	(_dup(static_cast<int> (socketDescriptor)));
#else
      m_udpSocket->setSocketDescriptor
	(dup(static_cast<int> (socketDescriptor)));
#endif
      m_udpSocket->setLocalAddress(QHostAddress(localIpAddress));
      m_udpSocket->setLocalPort(localPort.toUShort());
      m_udpSocket->setPeerAddress(QHostAddress(ipAddress));
      m_udpSocket->setPeerPort(port.toUShort());
    }

  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_address = m_bluetoothSocket->peerAddress().toString();
#endif
    }
  else if(m_sctpSocket)
    m_address = m_sctpSocket->peerAddress().toString();
  else if(m_tcpSocket)
    m_address = m_tcpSocket->peerAddress().toString();
  else if(m_udpSocket)
    m_address = ipAddress.trimmed();

  m_accountAuthenticated = 0;
  m_allowExceptions = false;
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address(this);
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
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_port = m_bluetoothSocket->peerPort();
#endif
    }
  else if(m_sctpSocket)
    m_port = m_sctpSocket->peerPort();
  else if(m_tcpSocket)
    m_port = m_tcpSocket->peerPort();
  else if(m_udpSocket)
    m_port = port.toUShort();

  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";
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
  else
    m_requireSsl = false;

  if(certificate.isEmpty() || m_transport != "tcp" || privateKey.isEmpty())
    m_useSsl = false;
  else
    m_useSsl = true;

  m_waitforbyteswritten_msecs = 0;

  if(m_useSsl)
    {
      if(m_tcpSocket)
	{
	  QSslConfiguration configuration;

	  configuration.setLocalCertificate(QSslCertificate(certificate));

	  if(
#if QT_VERSION < 0x050000
	     configuration.localCertificate().isValid()
#else
	     !configuration.localCertificate().isNull()
#endif
	     )
	    {
	      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	      if(!configuration.privateKey().isNull())
		{
#if QT_VERSION >= 0x040800
		  configuration.setSslOption
		    (QSsl::SslOptionDisableCompression, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableEmptyFragments, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableLegacyRenegotiation, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableSessionTickets, true);
#if QT_VERSION >= 0x050200
		  configuration.setSslOption
		    (QSsl::SslOptionDisableSessionPersistence, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableSessionSharing, true);
#endif
#endif
#if QT_VERSION >= 0x050000
		  spoton_crypt::setSslCiphers
		    (configuration.supportedCiphers(), m_sslControlString,
		     configuration);
#else
		  spoton_crypt::setSslCiphers
		    (m_tcpSocket->supportedCiphers(), m_sslControlString,
		     configuration);
#endif
		  m_tcpSocket->setSslConfiguration(configuration);
		}
	      else
		{
		  m_useSsl = false;
		  spoton_misc::logError
		    (QString("spoton_neighbor::spoton_neighbor(): "
			     "empty private key for %1:%2. SSL disabled.").
		     arg(m_address).
		     arg(m_port));
		}
	    }
	  else
	    {
	      m_useSsl = false;
	      spoton_misc::logError
		(QString("spoton_neighbor::spoton_neighbor(): "
			 "invalid local certificate for %1:%2. "
			 "SSL disabled.").
		 arg(m_address).
		 arg(m_port));
	    }
	}
    }

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
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
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
      /*
      ** UDP sockets are connection-less. However, most of the communications
      ** logic requires connected sockets.
      */

      m_udpSocket->setSocketState(QAbstractSocket::ConnectedState);
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_udpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }

  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  connect(&m_accountTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendAuthenticationRequest(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  connect(&m_authenticationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotAuthenticationTimerTimeout(void)));
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

  if(m_useSsl)
    {
      if(m_tcpSocket)
	m_tcpSocket->startServerEncryption();
    }

  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs",
	     15000).toInt());

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
  start(priority);
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
 QObject *parent):QThread(parent)
{
  m_abort = 0;
  m_accountAuthenticated = 0;
  m_accountName = accountName;
  m_accountPassword = accountPassword;
  m_address = ipAddress.trimmed();
  m_allowExceptions = allowExceptions;
  m_bluetoothSocket = 0;
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address(this);
  m_id = id;
  m_ipAddress = ipAddress;
  m_isUserDefined = userDefined;
  m_kernelInterfaces = spoton_kernel::interfaces();
  m_keySize = qAbs(keySize);

  if(transport == "tcp")
    if(m_keySize != 0)
      if(!(m_keySize == 2048 || m_keySize == 3072 ||
	   m_keySize == 4096))
	m_keySize = 2048;

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
  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";
  m_requireSsl = requireSsl;
  m_sctpSocket = 0;
  m_silenceTime = qBound(5, silenceTime, std::numeric_limits<int>::max());
  m_socketOptions = socketOptions;
  m_sourceOfRandomness = 0;
  m_sslControlString = sslControlString.trimmed();

  if(m_sslControlString.isEmpty())
    m_sslControlString = spoton_common::SSL_CONTROL_STRING;

  m_startTime = QDateTime::currentDateTime();
  m_statusControl = statusControl;
  m_tcpSocket = 0;
  m_transport = transport;
  m_udpSocket = 0;
  m_waitforbyteswritten_msecs =
    qBound(0,
	   waitforbyteswritten_msecs,
	   spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM);

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(s_crypt)
    {
      QByteArray name(m_accountName);
      QByteArray password(m_accountPassword);
      bool ok = true;

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
  else
    m_useSsl = false;

  if(m_transport == "bluetooth")
    {
    }
  else if(m_transport == "sctp")
    m_sctpSocket = new spoton_sctp_socket(this);
  else if(m_transport == "tcp")
    m_tcpSocket = new spoton_neighbor_tcp_socket(this);
  else if(m_transport == "udp")
    m_udpSocket = new spoton_neighbor_udp_socket(this);

  if(m_sctpSocket)
    m_sctpSocket->setReadBufferSize(m_maximumBufferSize);
  else if(m_tcpSocket)
    {
      m_tcpSocket->setProxy(proxy);
      m_tcpSocket->setReadBufferSize(m_maximumBufferSize);
    }
  else if(m_udpSocket)
    m_udpSocket->setProxy(proxy);

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  if(m_transport == "tcp" && m_useSsl)
    {
      spoton_crypt::generateSslKeys
	(m_keySize,
	 certificate,
	 privateKey,
	 publicKey,
	 QHostAddress(),
	 0, // Days are not used.
	 error);

      if(!error.isEmpty())
	spoton_misc::logError
	  (QString("spoton_neighbor:: "
		   "spoton_neighbor(): "
		   "generateSslKeys() failure (%1) for %2:%3.").
	   arg(error).
	   arg(ipAddress).
	   arg(port));
    }

  if(!privateKey.isEmpty())
    {
      if(m_tcpSocket)
	{
	  QSslConfiguration configuration;

	  configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	  if(!configuration.privateKey().isNull())
	    {
#if QT_VERSION >= 0x040800
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionTickets, true);
#if QT_VERSION >= 0x050200
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionPersistence, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionSharing, true);
#endif
#endif
	      configuration.setPeerVerifyMode(QSslSocket::QueryPeer);
#if QT_VERSION >= 0x050000
	      spoton_crypt::setSslCiphers
		(configuration.supportedCiphers(), m_sslControlString,
		 configuration);
#else
	      spoton_crypt::setSslCiphers
		(m_tcpSocket->supportedCiphers(), m_sslControlString,
		 configuration);
#endif
	      m_tcpSocket->setSslConfiguration(configuration);
	    }
	  else
	    {
	      m_useSsl = m_requireSsl;
	      spoton_misc::logError
		(QString("spoton_neighbor::spoton_neighbor(): "
			 "empty private key for %1:%2.").
		 arg(ipAddress).
		 arg(port));
	    }
	}
    }

  if(m_transport != "bluetooth")
    if(m_address.isEmpty())
      if(!m_ipAddress.isEmpty())
	QHostInfo::lookupHost(m_ipAddress,
			      this, SLOT(slotHostFound(const QHostInfo &)));

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
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
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
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
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

  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
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
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs",
	     15000).toInt());

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() == 30)
    m_externalAddressDiscovererTimer.setInterval(30000);
  else if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
	  toInt() == 60)
    m_externalAddressDiscovererTimer.setInterval(60000);
  else
    m_externalAddressDiscovererTimer.setInterval(30000);

  m_keepAliveTimer.setInterval(15000);
  m_lifetime.start(spoton_common::NEIGHBOR_LIFETIME_MS);
  m_timer.start(2500);
  start(priority);
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
  m_timer.stop();

  if(m_id != -1)
    {
      /*
      ** We must not delete accepted participants (neighbor_oid = -1).
      */

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
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
	      (db, spoton_kernel::s_crypts.value("chat", 0));
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

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
			  "bytes_read = 0, "
			  "bytes_written = 0, "
			  "external_ip_address = NULL, "
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

  while(!m_privateApplicationFutures.isEmpty())
    m_privateApplicationFutures.takeFirst().waitForFinished();

  close();
  quit();
  wait();
}

void spoton_neighbor::slotTimeout(void)
{
  if(qAbs(m_lastReadTime.secsTo(QDateTime::currentDateTime())) >= m_silenceTime)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotTimeout(): "
		 "aborting because of silent connection for %1:%2.").
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
  bool shouldDelete = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	saveStatistics(db);

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, "
		      "sticky, "
		      "echo_mode, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "account_name, "
		      "account_password, "
		      "ae_token, "
		      "ae_token_type, "
		      "ssl_control_string, "
		      "priority, "
		      "lane_width, "
		      "passthrough, "
		      "waitforbyteswritten_msecs, "
		      "private_application_credentials, "
		      "silence_time "
		      "FROM neighbors WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		status = query.value(0).toString().toLower();

		if(status == "blocked" || status == "disconnected")
		  {
		    saveStatus(db, status);
		    shouldDelete = true;
		  }
		else
		  {
		    spoton_crypt *s_crypt =
		      spoton_kernel::s_crypts.value("chat", 0);

		    if(s_crypt)
		      {
			bool ok = true;

			QWriteLocker locker(&m_echoModeMutex);

			m_echoMode = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(2).
						  toByteArray()),
			   &ok).constData();

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
			    QByteArray name
			      (QByteArray::fromBase64(query.value(5).
						      toByteArray()));
			    QByteArray password
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
				bool ok = true;

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

			if(q < 0 || q > 7)
			  q = HighPriority;

			if(isRunning() && p != q)
			  setPriority(q);
		      }

		    m_passthrough = query.value(12).toInt();
		    m_silenceTime = qBound
		      (5,
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
	      shouldDelete = true;
	  }
	else if(m_id != -1)
	  shouldDelete = true;
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
	    if(!m_bluetoothSocket)
	      {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
		m_bluetoothSocket = new (std::nothrow) QBluetoothSocket
		  (QBluetoothServiceInfo::RfcommProtocol, this);

		if(Q_LIKELY(m_bluetoothSocket))
		  {
		    QByteArray bytes;
		    QString serviceUuid;

		    bytes.append(QString("%1").arg(m_port).
				 toLatin1().toHex());
		    bytes = bytes.rightJustified(12, '0');
		    serviceUuid.append(bytes.mid(0, 8).constData());
		    serviceUuid.append("-");
		    serviceUuid.append(bytes.mid(8).constData());
		    serviceUuid.append("-0000-0000-");
		    serviceUuid.append(QString(m_address).remove(":"));
		    saveStatus("connecting");
		    m_bluetoothSocket->connectToService
		      (QBluetoothAddress(m_address),
		       QBluetoothUuid(serviceUuid));
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
		  }
#endif
	      }
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
	    if(m_tcpSocket->state() == QAbstractSocket::UnconnectedState)
	      {
		saveStatus("connecting");

		if(m_useSsl)
		  m_tcpSocket->connectToHostEncrypted(m_address, m_port);
		else
		  m_tcpSocket->connectToHost(m_address, m_port);
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
		    spoton_misc::logError
		      (QString("spoton_neighbor::slotTimeout(): "
			       "waitForConnected() failure for "
			       "%1:%2.").
		       arg(m_address).
		       arg(m_port));
		    deleteLater();
		    return;
		  }
	      }
	  }
      }

  int v = spoton_kernel::setting
    ("gui/kernelExternalIpInterval", -1).toInt();

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
  QSet<QPair<QByteArray, QByteArray> > b
    (spoton_kernel::adaptiveEchoTokens().toSet());
  QWriteLocker locker2(&m_learnedAdaptiveEchoPairsMutex);

  a = m_learnedAdaptiveEchoPairs.toSet();
  m_learnedAdaptiveEchoPairs =
    QList<QPair<QByteArray, QByteArray> >::fromSet(a.intersect(b));

  if(!m_isUserDefined &&
     !m_passthrough &&
     m_privateApplicationCredentials.isEmpty())
    if(m_sourceOfRandomness > 0)
      if(readyToWrite())
	write(spoton_crypt::weakRandomBytes(m_sourceOfRandomness).constData(),
	      m_sourceOfRandomness);
}

void spoton_neighbor::saveStatistics(const QSqlDatabase &db)
{
  if(!db.isOpen())
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatistics(): db is closed.");
      return;
    }
  else if(m_id == -1)
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatistics(): m_id is -1.");
      return;
    }

  QSqlQuery query(db);
  QSslCipher cipher;
  bool ok = true;

  if(m_tcpSocket)
    cipher = m_tcpSocket->sessionCipher();

  qint64 seconds = qAbs(m_startTime.secsTo(QDateTime::currentDateTime()));

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE neighbors SET "
		"bytes_read = ?, "
		"bytes_written = ?, "
		"is_encrypted = ?, "
		"ssl_session_cipher = ?, "
		"uptime = ? "
		"WHERE OID = ? AND "
		"status = 'connected' "
		"AND ABS(? - uptime) >= 10");
  query.bindValue(0, m_bytesRead);

  QReadLocker locker(&m_bytesWrittenMutex);

  query.bindValue(1, m_bytesWritten);
  locker.unlock();
  query.bindValue(2, isEncrypted() ? 1 : 0);

  if(cipher.isNull() || !spoton_kernel::s_crypts.value("chat", 0))
    query.bindValue(3, QVariant::String);
  else
    {
      query.bindValue
	(3, spoton_kernel::s_crypts.value("chat")->
	 encryptedThenHashed(QString("%1-%2-%3-%4-%5-%6-%7").
			     arg(cipher.name()).
			     arg(cipher.authenticationMethod()).
			     arg(cipher.encryptionMethod()).
			     arg(cipher.keyExchangeMethod()).
			     arg(cipher.protocolString()).
			     arg(cipher.supportedBits()).
			     arg(cipher.usedBits()).toUtf8(), &ok).
	 toBase64());

      if(!ok)
	query.bindValue(3, QVariant::String);
    }

  query.bindValue(4, seconds);
  query.bindValue(5, m_id);
  query.bindValue(6, seconds);

  if(ok)
    query.exec();
}

void spoton_neighbor::saveStatus(const QString &status)
{
  if(m_id == -1)
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatus(): m_id is -1.");
      return;
    }
  else if(status.trimmed().isEmpty())
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatus(): status is empty.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, isEncrypted() ? 1 : 0);
	query.bindValue(1, status.trimmed());
	query.bindValue(2, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::saveStatus(const QSqlDatabase &db,
				 const QString &status)
{
  if(!db.isOpen())
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatus(): db is closed.");
      return;
    }
  else if(m_id == -1)
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatus(): m_id is -1.");
      return;
    }
  else if(status.trimmed().isEmpty())
    {
      spoton_misc::logError
	("spoton_neighbor::saveStatus(): status is empty.");
      return;
    }

  QSqlQuery query(db);

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		"WHERE OID = ? AND status_control <> 'deleted'");
  query.bindValue(0, isEncrypted() ? 1 : 0);
  query.bindValue(1, status.trimmed());
  query.bindValue(2, m_id);
  query.exec();
}

void spoton_neighbor::run(void)
{
  spoton_neighbor_worker worker(this);

  connect(this,
	  SIGNAL(newData(void)),
	  &worker,
	  SLOT(slotNewData(void)));
  exec();
}

void spoton_neighbor::slotReadyRead(void)
{
  if(m_abort.fetchAndAddOrdered(0))
    return;

  QByteArray data;

  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      data = m_bluetoothSocket->readAll();
#endif
    }
  else if(m_sctpSocket)
    data = m_sctpSocket->readAll();
  else if(m_tcpSocket)
    data = m_tcpSocket->readAll();
  else if(m_udpSocket)
    {
      data = m_udpSocket->readAll();

      while(m_udpSocket->multicastSocket() &&
	    m_udpSocket->multicastSocket()->hasPendingDatagrams())
	{
	  QByteArray datagram;
	  qint64 size = 0;

	  datagram.resize
	    (static_cast<int> (qMax(static_cast<qint64> (0),
				    m_udpSocket->multicastSocket()->
				    pendingDatagramSize())));
	  size = m_udpSocket->multicastSocket()->readDatagram
	    (datagram.data(), datagram.size(), 0, 0);

	  if(size > 0)
	    data.append(datagram.mid(0, static_cast<int> (size)));
	}
    }

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
		 "m_useSsl is true, however, isEncrypted() "
		 "is false "
		 "for %1:%2. "
		 "Purging read data.").
	 arg(m_address).
	 arg(m_port));
    }

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
		quint64 sequence = m_privateApplicationSequences.first;

		m_privateApplicationSequences.first += 1;
		locker.unlock();
		m_privateApplicationFutures << QtConcurrent::run
		  (this,
		   &spoton_neighbor::bundlePrivateApplicationData,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
	      }
	    else
	      {
		QMutexLocker locker(&m_privateApplicationMutex);
		quint64 sequence = m_privateApplicationSequences.second;

		m_privateApplicationSequences.second += 1;
		locker.unlock();
		m_privateApplicationFutures << QtConcurrent::run
		  (this,
		   &spoton_neighbor::bundlePrivateApplicationData,
		   data,
		   m_privateApplicationCredentials,
		   m_id,
		   sequence);
	      }

	    return;
	  }

	bool ok = true;

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
      qint64 maximumBufferSize = m_maximumBufferSize;

      locker1.unlock();

      QWriteLocker locker2(&m_dataMutex);
      int length = static_cast<int> (maximumBufferSize) - m_data.length();

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
      spoton_misc::logError
	(QString("spoton_neighbor::slotReadyRead(): "
		 "Did not receive data. Closing connection for "
		 "%1:%2.").
	 arg(m_address).
	 arg(m_port));
      deleteLater();
    }
}

void spoton_neighbor::processData(void)
{
  if(m_abort.fetchAndAddOrdered(0))
    return;

  QByteArray data;

  {
    QReadLocker locker(&m_dataMutex);

    data = m_data;
  }

  QList<QByteArray> list;
  bool reset_keep_alive = false;
  int index = -1;
  int totalBytes = 0;

  while((index = data.indexOf(spoton_send::EOM)) >= 0)
    {
      if(m_abort.fetchAndAddOrdered(0))
	return;

      QByteArray bytes(data.mid(0, index + spoton_send::EOM.length()));

      data.remove(0, bytes.length());
      totalBytes += bytes.length();

      if(!bytes.isEmpty())
	{
	  if(!spoton_kernel::messagingCacheContains(bytes))
	    list.append(bytes);
	  else
	    reset_keep_alive = true;
	}
    }

  if(reset_keep_alive)
    emit resetKeepAlive();

  if(totalBytes > 0)
    {
      QWriteLocker locker(&m_dataMutex);

      m_data.remove(0, totalBytes);
    }

  data.clear();

  qint64 maximumBufferSize = 0;

  {
    QReadLocker locker(&m_maximumBufferSizeMutex);

    maximumBufferSize = m_maximumBufferSize;
  }

  {
    QWriteLocker locker(&m_dataMutex);

    if(m_data.length() >= maximumBufferSize)
      m_data.clear();
  }

  if(list.isEmpty())
    return;

  QByteArray accountClientSentSalt;
  QString echoMode("");
  bool useAccounts = false;
  qint64 maximumContentLength = 0;

  {
    QReadLocker locker(&m_accountClientSentSaltMutex);

    accountClientSentSalt = m_accountClientSentSalt;
  }

  {
    QReadLocker locker(&m_echoModeMutex);

    echoMode = m_echoMode;
  }

  {
    QReadLocker locker(&m_maximumContentLengthMutex);

    maximumContentLength = m_maximumContentLength;
  }

  useAccounts = m_useAccounts.fetchAndAddOrdered(0);

  while(!list.isEmpty())
    {
      if(m_abort.fetchAndAddOrdered(0))
	return;

      QByteArray data(list.takeFirst());
      QByteArray originalData(data);
      int index = -1;
      int length = 0;

      if((index = data.indexOf("Content-Length: ")) >= 0)
	{
	  QByteArray contentLength
	    (data.mid(index + static_cast<int> (qstrlen("Content-Length: "))));

	  if((index = contentLength.indexOf("\r\n")) >= 0)
	    /*
	    ** toInt() returns zero on failure.
	    */

	    length = contentLength.mid(0, index).toInt();
	}
      else
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::processData(): "
		     "data does not contain Content-Length "
		     "from node %1:%2.").
	     arg(m_address).
	     arg(m_port));
	  continue;
	}

      if(length <= 0)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::processData(): "
		     "negative or zero length from node %1:%2. "
		     "Ignoring.").
	     arg(m_address).
	     arg(m_port));
	  continue;
	}

      if(length > maximumContentLength)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::processData(): "
		     "the Content-Length header from node %1:%2 "
		     "contains a lot of data (%3). Ignoring.").
	     arg(m_address).
	     arg(m_port).
	     arg(length));
	  continue;
	}

      if(!m_isUserDefined)
	{
	  /*
	  ** We're a server!
	  */

	  if(useAccounts)
	    {
	      if(length > 0 && data.contains("type=0050&content="))
		if(!m_accountAuthenticated.fetchAndAddOrdered(0))
		  process0050(length, data);

	      if(!m_accountAuthenticated.fetchAndAddOrdered(0))
		continue;
	    }
	  else if(length > 0 && (data.contains("type=0050&content=") ||
				 data.contains("type=0051&content=") ||
				 data.contains("type=0052&content=")))
	    continue;
	}
      else if(useAccounts &&
	      length > 0 && data.contains("type=0051&content="))
	{
	  /*
	  ** The server responded. Let's determine if the server's
	  ** response is valid. What if the server solicits a response
	  ** without the client having requested the authentication?
	  */

	  if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	    if(accountClientSentSalt.length() >=
	       spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE)
	      process0051(length, data);

	  if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	    continue;
	}
      else if(length > 0 && data.contains("type=0052&content="))
	{
	  if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	    {
	      if(m_bluetoothSocket)
		{
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
		  emit authenticationRequested
		    (QString("%1:%2").
		     arg(m_bluetoothSocket->peerAddress().toString()).
		     arg(m_bluetoothSocket->peerPort()));
#endif
		}
	      else if(m_sctpSocket)
		{
		  if(m_sctpSocket->peerAddress().scopeId().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_sctpSocket->peerAddress().toString()).
		       arg(m_sctpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_sctpSocket->peerAddress().toString()).
		       arg(m_sctpSocket->peerPort()).
		       arg(m_sctpSocket->peerAddress().scopeId()));
		}
	      else if(m_tcpSocket)
		{
		  if(m_tcpSocket->peerAddress().scopeId().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_tcpSocket->peerAddress().toString()).
		       arg(m_tcpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_tcpSocket->peerAddress().toString()).
		       arg(m_tcpSocket->peerPort()).
		       arg(m_tcpSocket->peerAddress().scopeId()));
		}
	      else if(m_udpSocket)
		{
		  if(m_udpSocket->peerAddress().scopeId().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_udpSocket->peerAddress().toString()).
		       arg(m_udpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_udpSocket->peerAddress().toString()).
		       arg(m_udpSocket->peerPort()).
		   arg(m_udpSocket->peerAddress().scopeId()));
		}
	    }
	}

      if(m_isUserDefined)
	if(useAccounts)
	  {
	    if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	      continue;
	  }

      if(length > 0 && data.contains("type=0011&content="))
	process0011(length, data);
      else if(length > 0 && data.contains("type=0012&content="))
	process0012(length, data);
      else if(length > 0 && data.contains("type=0014&content="))
	process0014(length, data);
      else if(length > 0 && data.contains("type=0030&content="))
	process0030(length, data);
      else if(length > 0 && (data.contains("type=0050&content=") ||
			     data.contains("type=0051&content=") ||
			     data.contains("type=0052&content=")))
	/*
	** We shouldn't be here!
	*/

	continue;
      else if(length > 0 && data.contains("type=0065&content="))
	process0065(length, data);
      else if(length > 0 && data.contains("type=0070&content="))
	process0070(length, data);
      else if(length > 0 && data.contains("type=0095b&content="))
	process0095b(length, data);
      else if(length > 0 && data.contains("content="))
	{
	  /*
	  ** Remove some header data.
	  */

	  length -= static_cast<int> (qstrlen("content="));

	  int indexOf = data.lastIndexOf("\r\n");

	  if(indexOf > -1)
	    data = data.mid(0, indexOf + 2);

	  indexOf = data.indexOf("content=");

	  if(indexOf > -1)
	    data.remove(0, indexOf + static_cast<int> (qstrlen("content=")));

	  if(data.length() == length)
	    {
	      emit resetKeepAlive();
	      spoton_kernel::messagingCacheAdd(originalData);
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::processData(): "
			 "data length does not equal content length "
			 "from node %1:%2. Ignoring.").
		 arg(m_address).
		 arg(m_port));
	      continue;
	    }

	  if(spoton_kernel::setting("gui/superEcho", 1).toInt() != 1)
	    /*
	    ** Super Echo!
	    */

	    emit receivedMessage
	      (originalData, m_id, QPair<QByteArray, QByteArray> ());

	  /*
	  ** Please note that findMessageType() calls
	  ** participantCount(). Therefore, the process() methods
	  ** that would do not.
	  */

	  QList<QByteArray> symmetricKeys;
	  QPair<QByteArray, QByteArray> discoveredAdaptiveEchoPair;

	  /*
	  ** The findMessageType() method does not detect StarBeam
	  ** data.
	  */

	  QString messageType(findMessageType(data, symmetricKeys,
					      discoveredAdaptiveEchoPair));

	  if(messageType == "0000")
	    process0000(length, data, symmetricKeys);
	  else if(messageType == "0000a" || messageType == "0000c")
	    process0000a(length, data, messageType);
	  else if(messageType == "0000b")
	    process0000b(length, data, symmetricKeys);
	  else if(messageType == "0000d")
	    process0000d(length, data, symmetricKeys);
	  else if(messageType == "0001a")
	    process0001a(length, data);
	  else if(messageType == "0001b")
	    process0001b(length, data, symmetricKeys);
	  else if(messageType == "0001c")
	    process0001c(length, data, symmetricKeys);
	  else if(messageType == "0002a")
	    process0002a(length, data, discoveredAdaptiveEchoPair);
	  else if(messageType == "0002b")
	    process0002b
	      (length, data, symmetricKeys, discoveredAdaptiveEchoPair);
	  else if(messageType == "0013")
	    process0013(length, data, symmetricKeys);
	  else if(messageType == "0040a")
	    process0040a(length, data, symmetricKeys);
	  else if(messageType == "0040b")
	    process0040b(length, data, symmetricKeys);
	  else if(messageType == "0080")
	    process0080(length, data, symmetricKeys);
	  else if(messageType == "0090")
	    process0090(length, data, symmetricKeys);
	  else if(messageType == "0091a")
	    process0091a(length, data, symmetricKeys);
	  else if(messageType == "0091b")
	    process0091b(length, data, symmetricKeys);
	  else if(messageType == "0092")
	    process0092(length, data, symmetricKeys);
	  else
	    messageType.clear();

	  if(messageType.isEmpty() && data.trimmed().split('\n').size() == 3)
	    if(spoton_kernel::instance() &&
	       spoton_kernel::instance()->
	       processPotentialStarBeamData(data, discoveredAdaptiveEchoPair))
	      {
		if(!discoveredAdaptiveEchoPair.first.isEmpty() &&
		   !discoveredAdaptiveEchoPair.second.isEmpty())
		  {
		    QWriteLocker locker(&m_learnedAdaptiveEchoPairsMutex);

		    if(!m_learnedAdaptiveEchoPairs.
		       contains(discoveredAdaptiveEchoPair))
		      m_learnedAdaptiveEchoPairs.
			append(discoveredAdaptiveEchoPair);
		  }

		messageType = "0060";
	      }

	  if(spoton_kernel::setting("gui/scramblerEnabled", false).toBool())
	    emit scrambleRequest();

	  if(discoveredAdaptiveEchoPair == QPair<QByteArray, QByteArray> () &&
	     spoton_kernel::setting("gui/superEcho", 1).toInt() != 1)
	    {
	      /*
	      ** Super Echo!
	      */
	    }
	  else if(echoMode == "full")
	    {
	      if(messageType == "0001b" &&
		 data.trimmed().split('\n').size() == 7)
		emit receivedMessage
		  (originalData, m_id, discoveredAdaptiveEchoPair);
	      else if(messageType.isEmpty() ||
		      messageType == "0002b" ||
		      messageType == "0090")
		emit receivedMessage
		  (originalData, m_id, discoveredAdaptiveEchoPair);
	      else if(messageType == "0040a" || messageType == "0040b")
		/*
		** Buzz.
		*/

		emit receivedMessage
		  (originalData, m_id, QPair<QByteArray, QByteArray> ());
	      else if(messageType == "0060" &&
		      !discoveredAdaptiveEchoPair.first.isEmpty() &&
		      !discoveredAdaptiveEchoPair.second.isEmpty())
		emit receivedMessage
		  (originalData, m_id, discoveredAdaptiveEchoPair);
	    }
	}
    }
}

void spoton_neighbor::slotConnected(void)
{
  if(m_sctpSocket)
    {
      m_sctpSocket->setSocketOption
	(spoton_sctp_socket::KeepAliveOption,
	 QVariant(m_socketOptions.contains("so_keepalive=1")));
      m_sctpSocket->setSocketOption
 	(spoton_sctp_socket::LowDelayOption,
	 QVariant(m_socketOptions.contains("nodelay=1")));
    }
  else if(m_tcpSocket)
    spoton_socket_options::setSocketOptions(m_tcpSocket, m_socketOptions, 0);
  else if(m_udpSocket)
    if(m_isUserDefined)
      {
	spoton_socket_options::setSocketOptions
	  (m_udpSocket, m_socketOptions, 0);

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

  /*
  ** The local address is the address of the proxy. Unfortunately,
  ** we do not have network interfaces that have such an address.
  ** Hence, m_networkInterface will always be zero. The object
  ** m_networkInterface was removed on 11/08/2013. The following
  ** logic remains.
  */

  if(m_tcpSocket)
    {
      if(m_tcpSocket->proxy().type() != QNetworkProxy::NoProxy)
	{
	  QHostAddress address(m_ipAddress);

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
	  QHostAddress address(m_ipAddress);

	  if(address.protocol() == QAbstractSocket::IPv4Protocol)
	    m_udpSocket->setLocalAddress(QHostAddress("127.0.0.1"));
	  else
	    m_udpSocket->setLocalAddress(QHostAddress("::1"));
	}
    }

  if(m_id != -1)
    {
      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

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
		     m_sctpSocket->peerAddress().
		     toString());
		else if(m_tcpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_tcpSocket->peerAddress().isNull() ?
		     m_tcpSocket->peerName() :
		     m_tcpSocket->peerAddress().
		     toString());
		else if(m_udpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_udpSocket->peerAddress().isNull() ?
		     m_udpSocket->peerName() :
		     m_udpSocket->peerAddress().
		     toString());

		bool ok = true;

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
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
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

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() != -1)
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

void spoton_neighbor::savePublicKey(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const QByteArray &sPublicKey,
				    const QByteArray &sSignature,
				    const qint64 neighbor_oid,
				    const bool ignore_key_permissions,
				    const bool signatures_required,
				    const QString &messageType)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value(keyType, 0);

  if(spoton_crypt::exists(publicKey, s_crypt) ||
     spoton_crypt::exists(sPublicKey, s_crypt))
    {
      spoton_misc::logError("spoton_neighbor::savePublicKey(): "
			    "attempting to add my own public key(s).");
      return;
    }

  if(keyType == "chat" || keyType == "poptastic")
    {
      if(!ignore_key_permissions)
	if(!spoton_kernel::setting("gui/acceptChatKeys", false).toBool())
	  return;
    }
  else if(keyType == "email")
    {
      if(!ignore_key_permissions)
	if(!spoton_kernel::setting("gui/acceptEmailKeys", false).toBool())
	  return;
    }
  else if(keyType == "rosetta")
    {
      if(!ignore_key_permissions)
	/*
	** Only echo key-share allows sharing of Rosetta key pairs.
	*/

	return;
    }
  else if(keyType == "url")
    {
      if(!ignore_key_permissions)
	if(!spoton_kernel::setting("gui/acceptUrlKeys", false).toBool())
	  return;
    }
  else
    {
      spoton_misc::logError
	(QString("spoton_neighbor::savePublicKey(): unexpected key type "
		 "for %1:%2.").
	 arg(m_address).
	 arg(m_port));
      return;
    }

  int noid = neighbor_oid;

  /*
  ** Save a friendly key.
  */

  if(signatures_required)
    if(!spoton_crypt::isValidSignature(publicKey, publicKey, signature))
      if(messageType == "0090")
	noid = 0;

  if(signatures_required)
    if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey, sSignature))
      if(messageType == "0090")
	noid = 0;

  /*
  ** If noid (neighbor_oid) is -1, we have bonded two neighbors.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	if(noid != -1)
	  {
	    /*
	    ** We have received a request for friendship.
	    ** Do we already have the neighbor's public key?
	    */

	    QSqlQuery query(db);
	    bool exists = false;
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare("SELECT neighbor_oid "
			  "FROM friends_public_keys "
			  "WHERE public_key_hash = ?");
	    query.bindValue(0, spoton_crypt::sha512Hash(publicKey,
							&ok).toBase64());

	    if(ok)
	      if(query.exec())
		if(query.next())
		  if(query.value(0).toLongLong() == -1)
		    exists = true;

	    if(!exists)
	      {
		/*
		** An error occurred or we do not have the public key.
		*/

		spoton_misc::saveFriendshipBundle
		  (keyType, name, publicKey, sPublicKey,
		   noid, db, s_crypt);
		spoton_misc::saveFriendshipBundle
		  (keyType + "-signature", name, sPublicKey,
		   QByteArray(), noid, db, s_crypt);
	      }
	  }
	else
	  {
	    spoton_misc::saveFriendshipBundle
	      (keyType, name, publicKey, sPublicKey, -1, db, s_crypt);
	    spoton_misc::saveFriendshipBundle
	      (keyType + "-signature", name, sPublicKey, QByteArray(), -1,
	       db, s_crypt);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

qint64 spoton_neighbor::id(void) const
{
  return m_id;
}

void spoton_neighbor::setId(const qint64 id)
{
  m_id = id;
}

void spoton_neighbor::slotSendMessage
(const QByteArray &data,
 const spoton_send::spoton_send_method sendMethod)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

  message = spoton_send::message0000(data, sendMethod, ae);

  if(readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendMessage(): write() error "
		   "for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::slotWriteURLs(const QByteArray &data)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

  message = spoton_send::message0080(data, ae);

  if(readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotWriteURLs(): write() error "
		   "for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::slotWrite
(const QByteArray &data, const qint64 id,
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

  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    {
      m_privateApplicationFutures << QtConcurrent::run
	(this,
	 &spoton_neighbor::parsePrivateApplicationData,
	 data,
	 m_privateApplicationCredentials,
	 m_maximumContentLength);
      return;
    }

  QReadLocker locker1(&m_learnedAdaptiveEchoPairsMutex);

  if(!(adaptiveEchoPair == QPair<QByteArray, QByteArray> () ||
       m_learnedAdaptiveEchoPairs.contains(adaptiveEchoPair)))
    return;

  locker1.unlock();

  QReadLocker locker2(&m_echoModeMutex);
  QString echoMode(m_echoMode);

  locker2.unlock();

  if(echoMode == "full")
    if(readyToWrite())
      {
	if(write(data.constData(), data.length()) != data.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotWrite(): write() "
		     "error for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	else if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
	  spoton_kernel::messagingCacheAdd(data + QByteArray::number(id));
	else
	  spoton_kernel::messagingCacheAdd(data);
      }
}

void spoton_neighbor::slotLifetimeExpired(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotLifetimeExpired(): "
	     "expiration time reached for %1:%2. Aborting socket.").
     arg(m_address).
     arg(m_port));
  deleteLater();
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
      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(!s_crypt)
	return;

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

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

void spoton_neighbor::process0000(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0000(length, dataIn, symmetricKeys,
				 spoton_kernel::setting("gui/chatAccept"
							"SignedMessages"
							"Only",
							true).toBool(),
				 m_address, m_port,
				 spoton_kernel::s_crypts.value("chat", 0)));

  if(!list.isEmpty())
    {
      saveParticipantStatus
	(list.value(1),  // Name
	 list.value(0)); // Public Key Hash
      emit receivedChatMessage
	("message_" +
	 list.value(0).toBase64() + "_" +
	 list.value(1).toBase64() + "_" +
	 list.value(2).toBase64() + "_" +
	 list.value(3).toBase64() + "_" +
	 list.value(4).toBase64() + "_" +
	 list.value(5).toBase64() + "_" +
	 list.last().toBase64().append("\n"));
    }
}

void spoton_neighbor::process0000a(int length, const QByteArray &dataIn,
				   const QString &messageType)
{
  /*
  ** This method also processes 0000c.
  */

  QList<QByteArray> list
    (spoton_receive::process0000a(length, dataIn,
				  spoton_kernel::setting("gui/chatAccept"
							 "SignedMessages"
							 "Only",
							 true).toBool(),
				  m_address, m_port,
				  messageType,
				  spoton_kernel::s_crypts.value("chat", 0)));

  if(!list.isEmpty())
    saveGemini(list.value(0), list.value(1),
	       list.value(2), list.value(3),
	       list.value(4), messageType);
}

void spoton_neighbor::process0000b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0000b(length, dataIn, symmetricKeys,
				  spoton_kernel::setting("gui/chatAccept"
							 "SignedMessages"
							 "Only",
							 true).toBool(),
				  m_address, m_port,
				  spoton_kernel::s_crypts.value("chat", 0)));

  if(!list.isEmpty())
    saveGemini(list.value(1), list.value(2),
	       list.value(3), list.value(4),
	       list.value(5), "0000b");
}

void spoton_neighbor::process0000d(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0000d(length, dataIn, symmetricKeys,
				  m_address, m_port,
				  spoton_kernel::s_crypts.value("chat", 0)));

  if(!list.isEmpty())
    saveGemini(list.value(0), list.value(1),
	       list.value(2), list.value(3),
	       QByteArray(), "0000d");
}

void spoton_neighbor::process0001a(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 7)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001a(): "
		     "received irregular data. Expecting 7 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray computedHash;
      QByteArray data1(list.value(1));
      QByteArray data2(list.value(3));
      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation1(list.value(0));
      QByteArray keyInformation2(list.value(2));
      QByteArray originalKeyInformation1(keyInformation1);
      QByteArray originalKeyInformation2(keyInformation2);
      QByteArray messageCode1(list.value(5));
      QByteArray messageCode2(list.value(4));
      QByteArray recipientHash;
      QByteArray senderPublicKeyHash1;
      QByteArray signature;
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation1 = s_crypt->
	publicKeyDecrypt(keyInformation1, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation1.split('\n'));

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      hashKeyAlgorithm = QByteArray::fromBase64(list.value(3));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0001a(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation1 + data1 + keyInformation2 + data2,
	     hashKey, hashKeyAlgorithm, &ok);

	  if(computedHash.isEmpty() || messageCode1.isEmpty() || !ok ||
	     !spoton_crypt::memcmp(computedHash, messageCode1))
	    {
	      spoton_misc::logError
		("spoton_neighbor::"
		 "process0001a(): "
		 "computed message code 1 does "
		 "not match provided code.");
	      return;
	    }

	  QByteArray data;
	  QByteArray senderPublicKeyHash2;
	  spoton_crypt crypt(symmetricKeyAlgorithm,
			     hashKeyAlgorithm,
			     QByteArray(),
			     symmetricKey,
			     0,
			     0,
			     "");

	  data = crypt.decrypted(data1, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(data.split('\n'));

	      if(list.size() == 3)
		{
		  senderPublicKeyHash1 = QByteArray::fromBase64
		    (list.value(0));
		  recipientHash = QByteArray::fromBase64(list.value(1));
		  signature = QByteArray::fromBase64(list.value(2));

		  if(!spoton_misc::
		     isAcceptedParticipant(senderPublicKeyHash1, "email",
					   s_crypt))
		    return;

		  if(spoton_kernel::setting("gui/emailAcceptSigned"
					    "MessagesOnly",
					    true).toBool())
		    if(!spoton_misc::
		       isValidSignature("0001a" +
					symmetricKey +
					hashKey +
					symmetricKeyAlgorithm +
					hashKeyAlgorithm +
					senderPublicKeyHash1 +
					recipientHash,
					senderPublicKeyHash1,
					signature,
					s_crypt))
		      {
			spoton_misc::logError
			  ("spoton_neighbor::"
			   "process0001a(): invalid "
			   "signature.");
			return;
		      }
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::process0001a(): "
			     "received irregular data. "
			     "Expecting 3 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray publicKey = s_crypt->publicKey(&ok);
	      QByteArray publicKeyHash;

	      if(ok)
		publicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

	      if(ok &&
		 !publicKeyHash.isEmpty() && !recipientHash.isEmpty() &&
		 spoton_crypt::memcmp(publicKeyHash, recipientHash))
		{
		  keyInformation2 = s_crypt->
		    publicKeyDecrypt(keyInformation2, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(keyInformation2.split('\n'));

		      if(!list.isEmpty())
			list.removeAt(0); // Message Type

		      if(list.size() == 4)
			{
			  hashKey = QByteArray::fromBase64(list.value(1));
			  hashKeyAlgorithm = QByteArray::fromBase64
			    (list.value(3));
			  symmetricKey = QByteArray::fromBase64
			    (list.value(0));
			  symmetricKeyAlgorithm = QByteArray::fromBase64
			    (list.value(2));
			}
		      else
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0001a(): "
				     "received irregular data. "
				     "Expecting 4 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}

		      computedHash = spoton_crypt::keyedHash
			(originalKeyInformation2 + data2,
			 hashKey, hashKeyAlgorithm, &ok);

		      if(computedHash.isEmpty() || messageCode2.isEmpty() ||
			 !ok || !spoton_crypt::memcmp(computedHash,
						      messageCode2))
			{
			  spoton_misc::logError
			    ("spoton_neighbor::"
			     "process0001a(): "
			     "computed message code 2 does "
			     "not match provided code.");
			  return;
			}

		      QByteArray attachmentData;
		      QByteArray date;
		      QByteArray message;
		      QByteArray name;
		      QByteArray signature;
		      QByteArray subject;
		      bool goldbugUsed = false;
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 hashKeyAlgorithm,
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 "");

		      if(ok)
			data = crypt.decrypted(data2, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 8)
			    {
			      senderPublicKeyHash2 =
				QByteArray::fromBase64(list.value(0));
			      name =
				QByteArray::fromBase64(list.value(1));
			      subject =
				QByteArray::fromBase64(list.value(2));
			      message =
				QByteArray::fromBase64(list.value(3));
			      date =
				QByteArray::fromBase64(list.value(4));
			      attachmentData =
				QByteArray::fromBase64(list.value(5));
			      signature =
				QByteArray::fromBase64(list.value(6));
			      goldbugUsed = QVariant
				(QByteArray::fromBase64(list.value(7))).
				toBool();
			    }
			  else
			    {
			      spoton_misc::logError
				(QString("spoton_neighbor::process0001a(): "
					 "received irregular data. "
					 "Expecting 8 "
					 "entries, "
					 "received %1.").arg(list.size()));
			      return;
			    }
			}

		      if(ok)
			{
			  /*
			  ** This is our letter! Please remember that the
			  ** message may have been encrypted via a goldbug.
			  */

			  storeLetter(symmetricKey,
				      symmetricKeyAlgorithm,
				      hashKey,
				      hashKeyAlgorithm,
				      senderPublicKeyHash2,
				      name,
				      subject,
				      message,
				      date,
				      attachmentData,
				      signature,
				      goldbugUsed);
			  return;
			}
		    }
		}
	    }
	}

      if(ok)
	if(spoton_kernel::setting("gui/postoffice_enabled",
				  false).toBool())
	  if(spoton_misc::
	     isAcceptedParticipant(recipientHash, "email", s_crypt))
	    if(spoton_misc::
	       isAcceptedParticipant(senderPublicKeyHash1, "email", s_crypt))
	      {
		if(spoton_kernel::setting("gui/coAcceptSignedMessagesOnly",
					  true).toBool())
		  if(!spoton_misc::
		     isValidSignature("0001a" +
				      symmetricKey +
				      hashKey +
				      symmetricKeyAlgorithm +
				      hashKeyAlgorithm +
				      senderPublicKeyHash1 +
				      recipientHash,
				      senderPublicKeyHash1,
				      signature,
				      s_crypt))
		    {
		      spoton_misc::logError
			("spoton_neighbor::"
			 "process0001a(): invalid "
			 "signature.");
		      return;
		    }

		/*
		** Store the letter in the post office!
		*/

		saveParticipantStatus(senderPublicKeyHash1);
		storeLetter(list.mid(2, 3), recipientHash);
	      }
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001a(): 0001a "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0001b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(!(list.size() == 4 || list.size() == 7))
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001b(): "
		     "received irregular data. Expecting 4 or 7 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() == 4)
	{
	  QByteArray hashKey;
	  QByteArray hashKeyAlgorithm;
	  QByteArray keyInformation(list.value(0));
	  QByteArray originalKeyInformation(keyInformation);
	  QByteArray symmetricKey;
	  QByteArray symmetricKeyAlgorithm;
	  bool ok = true;

	  keyInformation = s_crypt->
	    publicKeyDecrypt(keyInformation, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(keyInformation.split('\n'));

	      if(!list.isEmpty())
		list.removeAt(0); // Message Type

	      if(list.size() == 4)
		{
		  hashKey = QByteArray::fromBase64(list.value(1));
		  hashKeyAlgorithm = QByteArray::fromBase64(list.value(3));
		  symmetricKey = QByteArray::fromBase64(list.value(0));
		  symmetricKeyAlgorithm = QByteArray::fromBase64
		    (list.value(2));
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::0001b(): "
			     "received irregular data. "
			     "Expecting 4 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray computedHash;
	      QByteArray data(list.value(1));

	      computedHash = spoton_crypt::keyedHash
		(originalKeyInformation + data, hashKey,
		 hashKeyAlgorithm, &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(2));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 hashKeyAlgorithm,
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 "");

		      data = crypt.decrypted(data, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 8)
			    {
			      for(int i = 0; i < list.size(); i++)
				list.replace
				  (i, QByteArray::fromBase64(list.at(i)));

			      storeLetter
				(symmetricKey,
				 symmetricKeyAlgorithm,
				 hashKey,
				 hashKeyAlgorithm,
				 list.value(0),  // Public Key Hash
				 list.value(1),  // Name
				 list.value(2),  // Subject
				 list.value(3),  // Message
				 list.value(4),  // Date
				 list.value(5),  // Attachment Data
				 list.value(6),  // Signature
				 QVariant(list.value(7)).
				 toBool());      // Gold Bug Used?
			    }
			  else
			    {
			      spoton_misc::logError
				(QString("spoton_neighbor::process0001b(): "
					 "received irregular data. "
					 "Expecting 8 "
					 "entries, "
					 "received %1.").arg(list.size()));
			      return;
			    }
			}
		    }
		  else
		    {
		      spoton_misc::logError
			("spoton_neighbor::process0001b(): "
			 "computed message code does "
			 "not match provided code.");
		      return;
		    }
		}
	    }
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      if(list.size() == 7)
	/*
	** This letter is destined for someone else.
	*/

	if(spoton_kernel::setting("gui/postoffice_enabled", false).toBool())
	  {
	    QByteArray publicKeyHash
	      (spoton_misc::findPublicKeyHashGivenHash(list.value(3),
						       list.value(4),
						       symmetricKeys.value(2),
						       symmetricKeys.value(3),
						       s_crypt));

	    if(!publicKeyHash.isEmpty())
	      if(spoton_misc::isAcceptedParticipant(publicKeyHash, "email",
						    s_crypt))
		storeLetter(list.mid(0, 3), publicKeyHash);
	  }
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001b(): 0001b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0001c
(int length, const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0001c(length, dataIn, symmetricKeys,
				  m_address, m_port, "email",
				  spoton_kernel::s_crypts.value("email", 0)));

  if(!list.isEmpty())
    emit newEMailArrived();
}

void spoton_neighbor::process0002a
(int length, const QByteArray &dataIn,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0002a(): "
		     "received irregular data. Expecting 4 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** We must do some sort of thinking.
      ** Remember, we may receive multiple mail requests. And we may
      ** have many letters for the requesting parties. How should
      ** we retrieve the letters in a timely, yet functional, manner?
      */

      QByteArray hashKey;
      QByteArray hashKeyAlgorithm;
      QByteArray keyInformation(list.value(0));
      QByteArray originalKeyInformation(keyInformation);
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  if(!list.isEmpty())
	    list.removeAt(0); // Message Type

	  if(list.size() == 4)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      hashKeyAlgorithm = QByteArray::fromBase64(list.value(3));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0002a(): "
			 "received irregular data. "
			 "Expecting 4 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (originalKeyInformation + data, hashKey, hashKeyAlgorithm, &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     hashKeyAlgorithm,
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     "");

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      for(int i = 0; i < list.size(); i++)
			list.replace
			  (i, QByteArray::fromBase64(list.at(i)));

		      if(list.size() == 4 &&
			 list.value(1).length() >= 64) // Message
			{
			  saveParticipantStatus
			    (list.value(0)); // Public Key Hash
			  emit retrieveMail
			    ("0002a" +
			     symmetricKey +
			     hashKey +
			     symmetricKeyAlgorithm +
			     hashKeyAlgorithm +
			     list.value(0) +
			     list.value(1) +
			     list.value(2), // Data
			     list.value(0), // Public Key Hash
			     list.value(2), // Timestamp
			     list.value(3), // Signature
			     adaptiveEchoPair);
			}
		      else
			{
			  if(list.size() != 4)
			    spoton_misc::logError
			      (QString("spoton_neighbor::process0002a(): "
				       "received irregular data. "
				       "Expecting 4 "
				       "entries, "
				       "received %1.").arg(list.size()));
			  else
			    spoton_misc::logError
			      ("spoton_neighbor::process0002a(): "
			       "received irregular data. "
			       "Expecting a larger message.");
			}
		    }
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0002a(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0002a(): 0002a "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0002b
(int length, const QByteArray &dataIn,
 const QList<QByteArray> &symmetricKeys,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0002b(): "
		     "received irregular data. Expecting 3 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** We must do some sort of thinking.
      ** Remember, we may receive multiple mail requests. And we may
      ** have many letters for the requesting parties. How should
      ** we retrieve the letters in a timely, yet functional, manner?
      */

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      QByteArray data(list.value(0));

      computedHash = spoton_crypt::keyedHash
	(data, symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 "");

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  QList<QByteArray> list(data.split('\n'));

		  for(int i = 0; i < list.size(); i++)
		    list.replace
		      (i, QByteArray::fromBase64(list.at(i)));

		  if(list.size() == 6 &&
		     list.value(1).size() >= 64 &&
		     list.value(3).size() >= 64)
		    {
		      if(list.value(0) == "0002b")
			{
			  QByteArray publicKeyHash
			    (spoton_misc::findPublicKeyHashGivenHash
			     (list.value(1), list.value(2),
			      symmetricKeys.value(2),
			      symmetricKeys.value(3), s_crypt));

			  if(!publicKeyHash.isEmpty())
			    {
			      saveParticipantStatus
				(publicKeyHash); // Public Key Hash
			      emit retrieveMail
				(list.value(0) +
				 list.value(1) +
				 list.value(2) +
				 list.value(3) +
				 list.value(4),  // Data
				 publicKeyHash,  // Public Key Hash
				 list.value(4),  // Timestamp
				 list.value(5),  // Signature
				 adaptiveEchoPair);
			    }
			}
		      else
			spoton_misc::logError
			  ("spoton_neighbor::process0002b(): "
			   "message type does not match 0002b.");
		    }
		  else
		    {
		      if(list.size() != 6)
			spoton_misc::logError
			  (QString("spoton_neighbor::process0002b(): "
				   "received irregular data. "
				   "Expecting 6 "
				   "entries, "
				   "received %1.").arg(list.size()));
		      else
			spoton_misc::logError
			  ("spoton_neighbor::process0002b(): "
			   "received irregular data. "
			   "Expecting larger messages.");
		    }
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::process0002b(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0002b(): 0002b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0011(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0011&content="));

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0011&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + static_cast<int> (qstrlen("type=0011&content=")));

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0011(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(m_id != -1)
	savePublicKey
	  (list.value(0), list.value(1), qUncompress(list.value(2)),
	   list.value(3), list.value(4), list.value(5), m_id, false, true,
	   "0011");
      else
	spoton_misc::logError("spoton_neighbor::process0011(): "
			      "m_id equals negative one. "
			      "Calling savePublicKey() would be "
			      "problematic. Ignoring request.");

      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0011(): 0011 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0012(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0012&content="));

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0012&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0012&content=")));

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0012(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      emit resetKeepAlive();
      savePublicKey
	(list.value(0), list.value(1), qUncompress(list.value(2)),
	 list.value(3), list.value(4), list.value(5), -1, false, true, "0012");
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0012(): 0012 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0013(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0013(length, dataIn, symmetricKeys,
				 spoton_kernel::setting("gui/chatAccept"
							"SignedMessages"
							"Only",
							true).toBool(),
				 m_address, m_port,
				 spoton_kernel::s_crypts.value("chat", 0)));

  if(!list.isEmpty())
    saveParticipantStatus
      (list.value(1),  // Name
       list.value(0),  // Public Key Hash
       list.value(2),  // Status
       list.value(3)); // Timestamp
}

void spoton_neighbor::process0014(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0014&content="));

  /*
  ** We may have received a uuid.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0014&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0014&content=")));

  if(length == data.length())
    {
      emit resetKeepAlive();
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));
#if QT_VERSION >= 0x040800
      QUuid uuid(list.value(0));
#else
      QUuid uuid(list.value(0).constData());
#endif
      QWriteLocker locker(&m_receivedUuidMutex);

      m_receivedUuid = uuid;

      if(m_receivedUuid.isNull())
	m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";

      locker.unlock();

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() +
	       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		if(!m_isUserDefined)
		  {
		    QList<int> laneWidths(spoton_common::LANE_WIDTHS);
		    QString echoMode(list.value(2));
		    int laneWidth = list.value(1).toInt();

		    if(!(echoMode == "full" || echoMode == "half"))
		      echoMode = "full";

		    QWriteLocker locker(&m_echoModeMutex);

		    m_echoMode = echoMode;
		    locker.unlock();
		    laneWidths << spoton_common::LANE_WIDTH_DEFAULT
			       << spoton_common::LANE_WIDTH_MAXIMUM
			       << spoton_common::LANE_WIDTH_MINIMUM;

		    if(!laneWidths.contains(laneWidth))
		      laneWidth = spoton_common::LANE_WIDTH_DEFAULT;

		    query.prepare("UPDATE neighbors SET "
				  "echo_mode = ?, "
				  "lane_width = ?, "
				  "uuid = ? "
				  "WHERE OID = ?");
		    query.bindValue
		      (0, s_crypt->
		       encryptedThenHashed(echoMode.toLatin1(),
					   &ok).toBase64());
		    query.bindValue(1, laneWidth);

		    if(ok)
		      query.bindValue
			(2, s_crypt->
			 encryptedThenHashed(uuid.toString().toLatin1(),
					     &ok).toBase64());

		    query.bindValue(3, m_id);
		  }
		else
		  {
		    query.prepare("UPDATE neighbors SET uuid = ? "
				  "WHERE OID = ?");
		    query.bindValue
		      (0, s_crypt->
		       encryptedThenHashed(uuid.toString().toLatin1(),
					   &ok).toBase64());
		    query.bindValue(1, m_id);
		  }

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0014(): 0014 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0030(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0030&content="));

  /*
  ** We may have received a listener's information.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0030&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0030&content=")));

  if(length == data.length())
    {
      data = data.trimmed();

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 5)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0030(): "
		     "received irregular data. Expecting 5 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}
      else
	{
	  QString statusControl
	    (spoton_kernel::setting("gui/acceptPublicizedListeners",
				    "localConnected").toString().
	     toLower());

	  if(statusControl == "connected" ||
	     statusControl == "disconnected")
	    {
	      QHostAddress address;

	      address.setAddress(list.value(0).constData());
	      address.setScopeId(list.value(2).constData());

	      if(!spoton_misc::isPrivateNetwork(address))
		{
		  QString orientation(list.value(4).constData());
		  QString transport(list.value(3).constData());
		  quint16 port = list.value(1).toUShort(); /*
							   ** toUShort()
							   ** returns zero
							   ** on failure.
							   */

		  spoton_misc::savePublishedNeighbor
		    (address, port, transport, statusControl, orientation,
		     s_crypt);
		}
	    }
	  else if(statusControl == "localconnected")
	    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
	      if(!QBluetoothAddress(list.value(0).constData()).isNull())
		{
		  QString orientation(list.value(4).constData());
		  quint16 port = list.value(1).toUShort(); /*
							   ** toUShort()
							   ** returns zero
							   ** on failure.
							   */

		  spoton_misc::savePublishedNeighbor
		    (QBluetoothAddress(list.value(0).constData()),
		     port,
		     "connected",
		     orientation,
		     s_crypt);
		  goto done_label;
		}
#endif
	      QHostAddress address;

	      address.setAddress(list.value(0).constData());
	      address.setScopeId(list.value(2).constData());

	      if(spoton_misc::isPrivateNetwork(address))
		{
		  QString orientation(list.value(4).constData());
		  QString transport(list.value(3).constData());
		  quint16 port = list.value(1).toUShort(); /*
							   ** toUShort()
							   ** returns zero
							   ** on failure.
							   */

		  spoton_misc::savePublishedNeighbor
		    (address, port, transport, "connected", orientation,
		     s_crypt);
		}

	      goto done_label;
	    }
	}

    done_label:
      emit publicizeListenerPlaintext(originalData, m_id);
      emit resetKeepAlive();
      spoton_kernel::messagingCacheAdd(dataIn);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0030(): 0030 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0040a(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040a(): "
		     "received irregular data. Expecting 2 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(list.value(0), symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      QByteArray data(list.value(0));
	      bool ok = true;
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 "");

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  list.replace(0, data);
		  emit receivedBuzzMessage(list, symmetricKeys);
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::"
				  "process0040a(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0040a(): 0040a "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0040b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040b(): "
		     "received irregular data. Expecting 2 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(list.value(0), symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      QByteArray data(list.value(0));
	      bool ok = true;
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 "");

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  list.replace(0, data);
		  emit receivedBuzzMessage(list, symmetricKeys);
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::"
				  "process0040b(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0040b(): 0040b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0050(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0050&content="));

  /*
  ** We may have received a name and a password from the client.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0050&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0050&content=")));

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0050(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray name;
      QByteArray password;

      if(spoton_misc::authenticateAccount(name,
					  password,
					  m_listenerOid,
					  list.at(0),
					  list.at(1),
					  spoton_kernel::
					  s_crypts.value("chat", 0)))
	{
	  m_accountAuthenticated.fetchAndStoreOrdered(1);
	  emit stopTimer(&m_accountTimer);
	  emit stopTimer(&m_authenticationTimer);
	  emit accountAuthenticated(list.at(1), name, password);
	}
      else
	{
	  /*
	  ** Respond with invalid information.
	  */

	  m_accountAuthenticated.fetchAndStoreOrdered(0);
	  emit accountAuthenticated
	    (spoton_crypt::weakRandomBytes(64),
	     spoton_crypt::weakRandomBytes(64),
	     spoton_crypt::weakRandomBytes(64));
	}

      if(m_accountAuthenticated.fetchAndAddOrdered(0))
	emit resetKeepAlive();

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() +
	       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "account_authenticated = ?, "
			      "account_name = ? "
			      "WHERE OID = ? AND "
			      "user_defined = 0");
		query.bindValue
		  (0,
		   m_accountAuthenticated.fetchAndAddOrdered(0) ?
		   s_crypt->encryptedThenHashed(QByteArray::number(1),
						&ok).toBase64() :
		   s_crypt->encryptedThenHashed(QByteArray::number(0),
						&ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encryptedThenHashed(name, &ok).toBase64());

		query.bindValue(2, m_id);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0050(): 0050 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0051(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0051&content="));

  /*
  ** We may have received a name and a password from the server.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0051&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0051&content=")));

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0051(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray accountClientSentSalt;
      QReadLocker locker(&m_accountClientSentSaltMutex);

      accountClientSentSalt = m_accountClientSentSalt;
      locker.unlock();

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(accountClientSentSalt.length() >=
	 spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE &&
	 list.at(1).trimmed().length() >=
	 spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE &&
	 !spoton_crypt::memcmp(list.at(1).trimmed(), accountClientSentSalt))
	{
	  if(s_crypt)
	    {
	      QByteArray hash(list.at(0));
	      QByteArray name;
	      QByteArray newHash;
	      QByteArray password;
	      QByteArray salt(list.at(1).trimmed());
	      bool ok = true;

	      QReadLocker locker1(&m_accountNameMutex);

	      name = m_accountName;
	      locker1.unlock();

	      QReadLocker locker2(&m_accountPasswordMutex);

	      password = m_accountPassword;
	      locker2.unlock();
	      name = s_crypt->decryptedAfterAuthenticated(name, &ok);

	      if(ok)
		password = s_crypt->decryptedAfterAuthenticated
		  (password, &ok);

	      if(ok)
		newHash = spoton_crypt::keyedHash
		  (QDateTime::currentDateTime().toUTC().
		   toString("MMddyyyyhhmm").
		   toLatin1() + accountClientSentSalt + salt,
		   name + password, "sha512", &ok);

	      if(ok)
		{
		  if(!hash.isEmpty() && !newHash.isEmpty() &&
		     spoton_crypt::memcmp(hash, newHash))
		    {
		      m_accountAuthenticated.fetchAndStoreOrdered(1);
		      emit stopTimer(&m_accountTimer);
		      emit stopTimer(&m_authenticationTimer);
		    }
		  else
		    {
		      newHash = spoton_crypt::keyedHash
			(QDateTime::currentDateTime().toUTC().addSecs(60).
			 toString("MMddyyyyhhmm").
			 toLatin1() + accountClientSentSalt + salt,
			 name + password, "sha512", &ok);

		      if(ok)
			{
			  if(!hash.isEmpty() && !newHash.isEmpty() &&
			     spoton_crypt::memcmp(hash, newHash))
			    {
			      m_accountAuthenticated.fetchAndStoreOrdered(1);
			      emit stopTimer(&m_accountTimer);
			      emit stopTimer(&m_authenticationTimer);
			    }
			}
		      else
			m_accountAuthenticated.fetchAndStoreOrdered(0);
		    }
		}
	      else
		m_accountAuthenticated.fetchAndStoreOrdered(0);
	    }
	  else
	    m_accountAuthenticated.fetchAndStoreOrdered(0);
	}
      else
	{
	  m_accountAuthenticated.fetchAndStoreOrdered(0);

	  if(accountClientSentSalt.length() <
	     spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE)
	    spoton_misc::logError
	      ("spoton_neighbor::process0051(): "
	       "the server replied to an authentication message, however, "
	       "my provided salt is short.");
	  else if(spoton_crypt::memcmp(list.at(1), accountClientSentSalt))
	    spoton_misc::logError
	      ("spoton_neighbor::process0051(): "
	       "the provided salt is identical to the generated salt. "
	       "The server may be devious.");
	}

      if(m_accountAuthenticated.fetchAndAddOrdered(0))
	emit resetKeepAlive();

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() +
	       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "account_authenticated = ? "
			      "WHERE OID = ? AND "
			      "user_defined = 1");
		query.bindValue
		  (0,
		   m_accountAuthenticated.fetchAndAddOrdered(0) ?
		   s_crypt->encryptedThenHashed(QByteArray::number(1),
						&ok).toBase64() :
		   s_crypt->encryptedThenHashed(QByteArray::number(0),
						&ok).toBase64());
		query.bindValue(1, m_id);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0051(): 0051 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0065(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  /*
  ** Shared Buzz Magnet?
  */

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0065&content="));

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0065&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0065&content=")));

  if(length == data.length())
    {
      emit resetKeepAlive();
      data = QByteArray::fromBase64(data);

      if(spoton_kernel::setting("gui/acceptBuzzMagnets", false).toBool())
	if(spoton_misc::isValidBuzzMagnetData(data))
	  {
	    QString connectionName("");

	    {
	      QSqlDatabase db = spoton_misc::database(connectionName);

	      db.setDatabaseName
		(spoton_misc::homePath() + QDir::separator() +
		 "buzz_channels.db");

	      if(db.open())
		{
		  QSqlQuery query(db);
		  bool ok = true;

		  query.prepare("INSERT OR REPLACE INTO buzz_channels "
				"(data, data_hash) "
				"VALUES (?, ?)");
		  query.bindValue
		    (0, s_crypt->encryptedThenHashed(data, &ok).toBase64());

		  if(ok)
		    query.bindValue
		      (1, s_crypt->keyedHash(data, &ok).toBase64());

		  if(ok)
		    query.exec();
		}

	      db.close();
	    }

	    QSqlDatabase::removeDatabase(connectionName);
	  }
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0065(): 0065 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0070(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0070&content="));

  /*
  ** We may have received a message of the day.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0070&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0070&content=")));

  if(length == data.length())
    {
      emit resetKeepAlive();
      data = QByteArray::fromBase64(data);

      QString motd(QString::fromUtf8(data.constData(),
				     data.length()).trimmed());

      if(motd.isEmpty())
	motd = "Welcome to Spot-On.";

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE neighbors SET motd = ? WHERE OID = ?");
	    query.bindValue(0, motd);
	    query.bindValue(1, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0070(): 0070 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0080(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0080(): "
		     "received irregular data. Expecting 4 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      QByteArray keyInformation(list.value(0));
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(list.value(0) + list.value(1),
	 symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(2));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      QByteArray data(list.value(1));
	      bool ok = true;
	      spoton_crypt crypt(symmetricKeys.value(1),
				 symmetricKeys.value(3),
				 QByteArray(),
				 symmetricKeys.value(0),
				 symmetricKeys.value(2),
				 0,
				 0,
				 "");

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  QList<QByteArray> list;

		  {
		    QByteArray a;
		    QDataStream stream(&data, QIODevice::ReadOnly);

		    while(true)
		      {
			stream >> a;

			if(stream.status() != QDataStream::Ok)
			  break;
			else
			  list << a;
		      }
		  }

		  QDateTime dateTime
		    (QDateTime::fromString(list.value(1).constData(),
					   "MMddyyyyhhmmss"));

		  dateTime.setTimeSpec(Qt::UTC);

		  if(!spoton_misc::
		     acceptableTimeSeconds(dateTime,
					   spoton_common::URL_TIME_DELTA))
		    return;

		  QByteArray dataForSignature
		    (keyInformation + list.value(0) + list.value(1));
		  QByteArray signature(list.value(2));

		  {
		    QByteArray a;
		    QByteArray data(qUncompress(list.value(0)));
		    QDataStream stream(&data, QIODevice::ReadOnly);

		    list.clear();

		    while(true)
		      {
			stream >> a;

			if(stream.status() != QDataStream::Ok)
			  break;
			else
			  {
			    list << a;

			    if(list.size() == 1)
			      {
				QByteArray publicKeyHash(list.value(0));

				if(!spoton_misc::
				   isAcceptedParticipant(publicKeyHash, "url",
							 spoton_kernel::
							 s_crypts.
							 value("url", 0)))
				  return;

				if(spoton_kernel::
				   setting("gui/urlAcceptSignedMessagesOnly",
					   true).toBool())
				  if(!spoton_misc::
				     isValidSignature(dataForSignature,
						      publicKeyHash,
						      signature,
						      spoton_kernel::s_crypts.
						      value("url", 0)))
				    {
				      spoton_misc::logError
					("spoton_neighbor::process0080(): "
					 "invalid signature.");
				      return;
				    }
			      }
			  }
		      }
		  }

		  if(!list.isEmpty())
		    /*
		    ** Remove the public-key digest.
		    */

		    list.removeAt(0);

		  saveUrlsToShared(list);
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::"
				  "process0080(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0080(): 0080 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0090(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0090(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      ** symmetricKeys[4]: Signatures Required
      */

      bool ok = true;
      spoton_crypt crypt(symmetricKeys.value(1).constData(),
			 symmetricKeys.value(3).constData(),
			 QByteArray(),
			 symmetricKeys.value(0),
			 symmetricKeys.value(2),
			 0,
			 0,
			 "");

      data = crypt.decrypted(list.value(0), &ok);

      if(ok)
	{
	  QDataStream stream(&data, QIODevice::ReadOnly);

	  list.clear();

	  for(int i = 0; i < 8; i++)
	    {
	      QByteArray a;

	      stream >> a;

	      if(stream.status() != QDataStream::Ok)
		{
		  list.clear();
		  break;
		}
	      else
		list << a;
	    }

	  if(list.size() != 8)
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0090(): "
			 "received irregular data. Expecting 8 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }

	  QDateTime dateTime
	    (QDateTime::fromString(list.value(list.size() - 1).
				   constData(), "MMddyyyyhhmmss"));

	  dateTime.setTimeSpec(Qt::UTC);

	  if(!spoton_misc::
	     acceptableTimeSeconds(dateTime, spoton_common::EPKS_TIME_DELTA))
	    return;

	  savePublicKey
	    (list.value(1),                    // Key Type
	     list.value(2),                    // Name
	     qUncompress(list.value(3)),       // Public Key
	     list.value(4),                    // Public Key Signature
	     list.value(5),                    // Signature Public Key
	     list.value(6),                    // Signature Public Key
	                                       // Signature
	     -1,                               // Neighbor OID
	     true,                             // Ignore Permissions
	                                       // (acceptChatKeys)
	     QVariant(symmetricKeys.value(4)). // Signatures Required
	     toBool(),
	     "0090");                          // Message Type
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0090(): 0090 "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::process0091a(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0091(length, dataIn, symmetricKeys,
				 m_address, m_port, "0091a"));

  if(!list.isEmpty())
    emit forwardSecrecyRequest(list);
}

void spoton_neighbor::process0091b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0091(length, dataIn, symmetricKeys,
				 m_address, m_port, "0091b"));

  if(!list.isEmpty())
    emit saveForwardSecrecySessionKeys(list);
}

void spoton_neighbor::process0092(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0092(length, dataIn, symmetricKeys,
				 m_address, m_port));

  if(!list.isEmpty())
    emit smpMessage(list);
}

void spoton_neighbor::process0095b(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0095b&content="));

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0095b&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0095b&content=")));

  if(length == data.length())
    {
      emit receivedMessage(dataIn, m_id, QPair<QByteArray, QByteArray> ());
      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0095b(): 0095b "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::slotSendStatus(const QByteArrayList &list)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	QPair<QByteArray, QByteArray> ae
	  (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						  spoton_kernel::s_crypts.
						  value("chat", 0)));

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

void spoton_neighbor::saveParticipantStatus(const QByteArray &publicKeyHash)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE friends_public_keys SET "
		      "last_status_update = ?, status = 'online' "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(1, publicKeyHash.toBase64());
     	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::saveParticipantStatus(const QByteArray &name,
					    const QByteArray &publicKeyHash)
{
  saveParticipantStatus
    (name, publicKeyHash, QByteArray(),
     QDateTime::currentDateTime().toUTC().
     toString("MMddyyyyhhmmss").toLatin1());
}

void spoton_neighbor::saveParticipantStatus(const QByteArray &name,
					    const QByteArray &publicKeyHash,
					    const QByteArray &status,
					    const QByteArray &timestamp)
{
  spoton_misc::saveParticipantStatus
    (name, publicKeyHash, status, timestamp,
     static_cast<int> (2.5 * spoton_common::STATUS_INTERVAL),
     spoton_kernel::s_crypts.value("chat", 0));
}

void spoton_neighbor::slotError(QAbstractSocket::SocketError error)
{
  if(error == QAbstractSocket::DatagramTooLargeError)
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
		       "(%1) for "
		       "%2:%3. "
		       "Disabling SSL.").arg(m_tcpSocket->errorString()).
	       arg(m_address).arg(m_port));

	  return;
	}
    }

  if(m_tcpSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): "
	       "socket error (%1) for %2:%3. "
	       "Aborting socket.").arg(m_tcpSocket->errorString()).
       arg(m_address).
       arg(m_port));
  else if(m_udpSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): "
	       "socket error (%1) for %2:%3. "
	       "Aborting socket.").arg(m_udpSocket->errorString()).
       arg(m_address).
       arg(m_port));

  deleteLater();
}

#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
void spoton_neighbor::slotError(QBluetoothSocket::SocketError error)
{
  if(m_bluetoothSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): "
	       "socket error (%1) for %2:%3.").
       arg(m_bluetoothSocket->errorString()).
       arg(m_address).
       arg(m_port));

  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): "
	     "socket error (%1) for %2:%3.").
     arg(error).
     arg(m_address).
     arg(m_port));

  if(error != QBluetoothSocket::UnknownSocketError)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): "
		 "socket error (%1) for %2:%3. Aborting.").
	 arg(error).
	 arg(m_address).
	 arg(m_port));
      deleteLater();
    }
}
#endif

void spoton_neighbor::slotError(const QString &method,
				const spoton_sctp_socket::SocketError error)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): "
	     "socket error (%1:%2) for %3:%4. "
	     "Aborting socket.").
     arg(method).
     arg(error).
     arg(m_address).
     arg(m_port));
  deleteLater();
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
  QString echoMode(m_echoMode);

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
  else if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message(spoton_send::message0070(m_motd.toUtf8()));

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendMOTD(): write() error for %1:%2.").
       arg(m_address).
       arg(m_port));
}

void spoton_neighbor::saveExternalAddress(const QHostAddress &address,
					  const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;
  else if(m_id == -1)
    return;

  QAbstractSocket::SocketState state = this->state();
  QSqlQuery query(db);
  bool ok = true;

  if(state == QAbstractSocket::ConnectedState)
    {
      if(address.isNull())
	{
	  query.prepare("UPDATE neighbors SET "
			"external_ip_address = NULL "
			"WHERE OID = ? AND external_ip_address IS "
			"NOT NULL");
	  query.bindValue(0, m_id);
	}
      else
	{
	  spoton_crypt *s_crypt =
	    spoton_kernel::s_crypts.value("chat", 0);

	  if(s_crypt)
	    {
	      query.prepare("UPDATE neighbors SET external_ip_address = ? "
			    "WHERE OID = ?");
	      query.bindValue
		(0, s_crypt->encryptedThenHashed(address.toString().
						 toLatin1(), &ok).
		 toBase64());
	      query.bindValue(1, m_id);
	    }
	  else
	    ok = false;
	}
    }
  else if(state == QAbstractSocket::UnconnectedState)
    {
      query.prepare("UPDATE neighbors SET external_ip_address = NULL "
		    "WHERE OID = ? AND external_ip_address IS NOT NULL");
      query.bindValue(0, m_id);
    }

  if(ok)
    query.exec();
}

void spoton_neighbor::slotExternalAddressDiscovered
(const QHostAddress &address)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      saveExternalAddress(address, db);

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotDiscoverExternalAddress(void)
{
  if(m_externalAddress)
    if(state() == QAbstractSocket::ConnectedState)
      m_externalAddress->discover();
}

QUuid spoton_neighbor::receivedUuid(void)
{
  QReadLocker locker(&m_receivedUuidMutex);

  return m_receivedUuid;
}

void spoton_neighbor::slotSendMail
(const QPairByteArrayInt64List &list, const QString &messageType)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QList<qint64> oids;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	QPair<QByteArray, QByteArray> ae
	  (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						  spoton_kernel::s_crypts.
						  value("chat", 0)));
	QPair<QByteArray, qint64> pair(list.at(i));

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
      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

      spoton_mailer::moveSentMailToSentFolder(oids, s_crypt);
    }
}

void spoton_neighbor::slotSendMailFromPostOffice
(const QByteArray &data,
 const QPairByteArrayByteArray &adaptiveEchoPair)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  bool adaptiveEcho = false;

  QReadLocker locker(&m_learnedAdaptiveEchoPairsMutex);

  if(adaptiveEchoPair == QPair<QByteArray, QByteArray> () ||
     m_learnedAdaptiveEchoPairs.contains(adaptiveEchoPair))
    adaptiveEcho = true;

  locker.unlock();

  if(adaptiveEcho && readyToWrite())
    {
      QByteArray message;
      QPair<QByteArray, QByteArray> ae
	(spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						spoton_kernel::s_crypts.
						value("chat", 0)));

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

void spoton_neighbor::storeLetter(const QByteArray &symmetricKey,
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
				  const bool goldbugUsed)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maximumEmailFileSize", 1024).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      spoton_misc::logError("spoton_neighbor::storeLetter(): "
			    "email.db has exceeded the specified limit.");
      return;
    }

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash, "email",
					 s_crypt))
    return;

  if(!goldbugUsed &&
     spoton_kernel::setting("gui/emailAcceptSignedMessagesOnly",
			    true).toBool())
    if(!spoton_misc::
       isValidSignature("0001b" +
			symmetricKey +
			hashKey +
			symmetricKeyAlgorithm +
			hashKeyAlgorithm +
			senderPublicKeyHash +
			name +
			subject +
			message +
			date +
			attachmentData,
			senderPublicKeyHash,
			signature, s_crypt))
      {
	spoton_misc::logError
	  ("spoton_neighbor::storeLetter(): invalid signature.");
	return;
      }

  /*
  ** We need to remember that the information here may have been
  ** encoded with a goldbug. The interface will prompt the user
  ** for the symmetric key.
  */

  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash, "email",
					 s_crypt))
    return;

  if(goldbugUsed)
    saveParticipantStatus(senderPublicKeyHash);
  else
    saveParticipantStatus(name, senderPublicKeyHash);

  QByteArray attachmentData_l(attachmentData);
  QByteArray date_l(date);
  QByteArray message_l(message);
  QByteArray name_l(name);
  QByteArray subject_l(subject);
  QString connectionName("");
  bool goldbugUsed_l = goldbugUsed;

  if(goldbugUsed_l)
    {
      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare
	      ("SELECT forward_secrecy_authentication_algorithm, "
	       "forward_secrecy_authentication_key, "
	       "forward_secrecy_encryption_algorithm, "
	       "forward_secrecy_encryption_key FROM "
	       "friends_public_keys WHERE "
	       "neighbor_oid = -1 AND "
	       "public_key_hash = ?");
	    query.bindValue(0, senderPublicKeyHash.toBase64());

	    if(query.exec() && query.next())
	      if(!query.isNull(0) && !query.isNull(1) &&
		 !query.isNull(2) && !query.isNull(3))
		{
		  QByteArray aa;
		  QByteArray ak;
		  QByteArray ea;
		  QByteArray ek;
		  QByteArray magnet;

		  if(ok)
		    aa = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(0).
					      toByteArray()),
		       &ok);

		  if(ok)
		    ak = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).
					      toByteArray()),
		       &ok);

		  if(ok)
		    ea = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(2).
					      toByteArray()),
		       &ok);

		  if(ok)
		    ek = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(3).
					      toByteArray()),
		       &ok);

		  if(ok)
		    {
		      magnet = spoton_misc::forwardSecrecyMagnetFromList
			(QList<QByteArray> () << aa << ak << ea << ek);

		      spoton_crypt *crypt =
			spoton_misc::cryptFromForwardSecrecyMagnet
			(magnet);

		      if(crypt)
			{
			  attachmentData_l = crypt->
			    decryptedAfterAuthenticated(attachmentData_l,
							&ok);

			  if(ok)
			    date_l = crypt->
			      decryptedAfterAuthenticated
			      (date_l, &ok);

			  if(ok)
			    message_l = crypt->
			      decryptedAfterAuthenticated
			      (message_l, &ok);

			  if(ok)
			    name_l = crypt->
			      decryptedAfterAuthenticated(name_l, &ok);

			  if(ok)
			    subject_l = crypt->
			      decryptedAfterAuthenticated
			      (subject_l, &ok);

			  if(ok)
			    goldbugUsed_l = false;
			  else
			    {
			      /*
			      ** Reset the local variables.
			      */

			      attachmentData_l = attachmentData;
			      date_l = date;
			      message_l = message;
			      name_l = name;
			      subject_l = subject;
			    }
			}

		      delete crypt;
		    }
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	bool ok = true;
	QSqlQuery query(db);

	query.prepare("INSERT INTO folders "
		      "(date, folder_index, from_account, goldbug, hash, "
		      "message, message_code, "
		      "receiver_sender, receiver_sender_hash, sign, "
		      "signature, "
		      "status, subject, participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->
	   encryptedThenHashed(date_l, &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue(2, s_crypt->encryptedThenHashed(QByteArray(), &ok).
			  toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->
	     encryptedThenHashed(QByteArray::number(goldbugUsed_l), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, s_crypt->keyedHash(date_l + message_l + subject_l,
				   &ok).toBase64());

	if(ok)
	  if(!message_l.isEmpty())
	    query.bindValue
	      (5, s_crypt->encryptedThenHashed(message_l, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, s_crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  if(!name.isEmpty())
	    query.bindValue
	      (7, s_crypt->encryptedThenHashed(name_l, &ok).toBase64());

	query.bindValue
	  (8, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (9, s_crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, s_crypt->encryptedThenHashed(signature, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (11, s_crypt->
	     encryptedThenHashed(QByteArray("Unread"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (12, s_crypt->encryptedThenHashed(subject_l, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (13, s_crypt->
	     encryptedThenHashed(QByteArray::number(-1), &ok).
	     toBase64());

	if(ok)
	  if(query.exec())
	    {
	      if(!attachmentData_l.isEmpty())
		{
		  QVariant variant(query.lastInsertId());
		  qint64 id = query.lastInsertId().toLongLong();

		  if(variant.isValid())
		    {
		      QByteArray data;

		      if(!goldbugUsed_l)
			data = qUncompress(attachmentData_l);
		      else
			data = attachmentData_l;

		      if(!data.isEmpty())
			{
			  QList<QPair<QByteArray, QByteArray> > attachments;

			  if(!goldbugUsed_l)
			    {
			      QDataStream stream(&data, QIODevice::ReadOnly);

			      stream >> attachments;

			      if(stream.status() != QDataStream::Ok)
				attachments.clear();
			    }
			  else
			    attachments << QPair<QByteArray, QByteArray>
			      (data, data);

			  while(!attachments.isEmpty())
			    {
			      QPair<QByteArray, QByteArray> pair
				(attachments.takeFirst());
			      QSqlQuery query(db);

			      query.prepare("INSERT INTO folders_attachment "
					    "(data, folders_oid, name) "
					    "VALUES (?, ?, ?)");
			      query.bindValue
				(0, s_crypt->encryptedThenHashed(pair.first,
								 &ok).
				 toBase64());
			      query.bindValue(1, id);

			      if(ok)
				query.bindValue
				  (2, s_crypt->
				   encryptedThenHashed(pair.second,
						       &ok).toBase64());

			      if(ok)
				query.exec();
			    }
			}
		    }
		}

	      emit newEMailArrived();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::storeLetter(const QList<QByteArray> &list,
				  const QByteArray &recipientHash)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maximumEmailFileSize", 1024).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      spoton_misc::logError("spoton_neighbor::storeLetter(): "
			    "email.db has exceeded the specified limit.");
      return;
    }

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("INSERT INTO post_office "
		      "(date_received, message_bundle, "
		      "message_bundle_hash, recipient_hash) "
		      "VALUES (?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->
	   encryptedThenHashed(QDateTime::currentDateTime().
			       toString(Qt::ISODate).
			       toLatin1(), &ok).toBase64());

	if(ok)
	  {
	    QByteArray data;

	    data =
	      list.value(0).toBase64() + "\n" + // Symmetric Key Bundle
	      list.value(1).toBase64() + "\n" + // Data
	      list.value(2).toBase64();         // Message Code
	    query.bindValue
	      (1, s_crypt->encryptedThenHashed(data, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, s_crypt->keyedHash(data, &ok).
		 toBase64());
	  }

	query.bindValue(3, recipientHash.toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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
	QPair<QByteArray, QByteArray> ae
	  (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						  spoton_kernel::s_crypts.
						  value("chat", 0)));

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

void spoton_neighbor::slotHostFound(const QHostInfo &hostInfo)
{
  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_address = address.toString();
	m_ipAddress = m_address;
	break;
      }
}

#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
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
	QByteArray message
	  (spoton_send::message0030(address, port, orientation));

	if(write(message.constData(), message.length()) !=
	   message.length())
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

void spoton_neighbor::slotPublicizeListenerPlaintext
(const QHostAddress &address, const quint16 port, const QString &transport,
 const QString &orientation)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(!address.isNull())
    if(readyToWrite())
      {
	QByteArray message
	  (spoton_send::message0030(address, port, transport, orientation));

	if(write(message.constData(), message.length()) !=
	   message.length())
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
  QString echoMode(m_echoMode);

  locker.unlock();

  if(echoMode == "full")
    if(readyToWrite())
      {
	QByteArray message(spoton_send::message0030(data));

	if(write(message.constData(), message.length()) !=
	   message.length())
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

void spoton_neighbor::slotSslErrors(const QList<QSslError> &errors)
{
  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError(QString("spoton_neighbor::slotSslErrors(): "
				  "error (%1) occurred from %2:%3.").
			  arg(errors.at(i).errorString()).
			  arg(m_address).
			  arg(m_port));
}

void spoton_neighbor::slotPeerVerifyError(const QSslError &error)
{
  /*
  ** This method may be called several times!
  */

  bool shouldDelete = true;

  if(error.error() == QSslError::CertificateUntrusted ||
     error.error() == QSslError::HostNameMismatch ||
     error.error() == QSslError::SelfSignedCertificate)
    shouldDelete = false;

  if(shouldDelete)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotPeerVerifyError(): instructed "
		 "to delete neighbor for %1:%2.").
	 arg(m_address).
	 arg(m_port));
      deleteLater();
      return;
    }

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

void spoton_neighbor::slotDisconnected(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotDisconnected(): "
	     "aborting socket for %1:%2!").
     arg(m_address).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotEncrypted(void)
{
  recordCertificateOrAbort();
  QTimer::singleShot(250, this, SLOT(slotSendCapabilities(void)));
}

void spoton_neighbor::recordCertificateOrAbort(void)
{
  QSslCertificate certificate;
  bool save = false;

  if(m_isUserDefined)
    {
      if(m_tcpSocket)
	{
	  if(m_peerCertificate.isNull() &&
	     !m_tcpSocket->peerCertificate().isNull())
	    {
	      certificate = m_peerCertificate = m_tcpSocket->peerCertificate();
	      save = true;
	    }
	  else if(!m_allowExceptions)
	    {
	      if(m_tcpSocket->peerCertificate().isNull())
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::recordCertificateOrAbort(): "
			     "null peer certificate for %1:%2. Aborting.").
		     arg(m_address).
		     arg(m_port));
		  deleteLater();
		  return;
		}
	      else if(!spoton_crypt::
		      memcmp(m_peerCertificate.toPem(),
			     m_tcpSocket->peerCertificate().toPem()))
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::recordCertificateOrAbort(): "
			     "the stored certificate does not match "
			     "the peer's certificate for %1:%2. This is a "
			     "serious problem! Aborting.").
		     arg(m_address).
		     arg(m_port));
		  deleteLater();
		  return;
		}
	    }
	}
    }
  else
    {
      if(m_tcpSocket)
	certificate = m_tcpSocket->sslConfiguration().localCertificate();

      save = true;
    }

  if(!save)
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("UPDATE neighbors SET certificate = ? WHERE OID = ?");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(certificate.toPem(),
					   &ok).toBase64());
	query.bindValue(1, m_id);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotProxyAuthenticationRequired
(const QNetworkProxy &proxy,
 QAuthenticator *authenticator)
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
    }
}

bool spoton_neighbor::readyToWrite(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return false;

  if(isEncrypted() && m_useSsl)
    {
      if(m_useAccounts.fetchAndAddOrdered(0))
	return m_accountAuthenticated.fetchAndAddOrdered(0);
      else
	return true;
    }
  else if(!isEncrypted() && !m_useSsl)
    {
      if(m_useAccounts.fetchAndAddOrdered(0))
	return m_accountAuthenticated.fetchAndAddOrdered(0);
      else
	return true;
    }
  else
    return false;
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

void spoton_neighbor::slotResetKeepAlive(void)
{
  m_lastReadTime = QDateTime::currentDateTime();
  spoton_kernel::s_sendInitialStatus.testAndSetOrdered(0, 1);
}

QString spoton_neighbor::findMessageType
(const QByteArray &data,
 QList<QByteArray> &symmetricKeys,
 QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair)
{
  QList<QByteArray> list(data.trimmed().split('\n'));
  QString type("");
  int interfaces = m_kernelInterfaces.fetchAndAddOrdered(0);
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  /*
  ** list[0]: Data
  ** ...
  ** list[list.size - 1]: Adaptive Echo Data
  ** symmetricKeys[0]: Encryption Key
  ** symmetricKeys[1]: Encryption Type
  ** symmetricKeys[2]: Hash Key
  ** symmetricKeys[3]: Hash Type
  */

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  /*
  ** Do not attempt to locate a Buzz key if an interface is not
  ** attached to the kernel.
  */

  if(interfaces > 0 && list.size() == 2)
    {
      symmetricKeys = spoton_kernel::findBuzzKey(list.value(0), list.value(1));

      if(!symmetricKeys.isEmpty())
	{
	  QByteArray data;
	  bool ok = true;
	  spoton_crypt crypt(symmetricKeys.value(1),
			     "sha512",
			     QByteArray(),
			     symmetricKeys.value(0),
			     0,
			     0,
			     "");

	  data = crypt.decrypted(list.value(0), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;
	    }

	  if(type == "0040a" || type == "0040b")
	    goto done_label;
	  else
	    {
	      symmetricKeys.clear();
	      type.clear();
	    }
	}
    }

  /*
  ** Do not attempt to locate a gemini if an interface is not
  ** attached to the kernel.
  */

  if(interfaces > 0 && list.size() == 3 && s_crypt &&
     spoton_misc::participantCount("chat", s_crypt) > 0)
    {
      QPair<QByteArray, QByteArray> gemini
	(spoton_misc::
	 findGeminiInCosmos(list.value(0), list.value(1), s_crypt));

      if(!gemini.first.isEmpty())
	{
	  QByteArray data;
	  bool ok = true;
	  spoton_crypt crypt("aes256",
			     "sha512",
			     QByteArray(),
			     gemini.first,
			     0,
			     0,
			     "");

	  data = crypt.decrypted(list.value(0), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;
	    }

	  if(type == "0000" || type == "0000b" || type == "0013")
	    {
	      symmetricKeys.append(gemini.first);
	      symmetricKeys.append("aes256");
	      symmetricKeys.append(gemini.second);
	      symmetricKeys.append("sha512");
	      goto done_label;
	    }
	  else
	    type.clear();
	}
    }

  if(list.size() == 3 && s_crypt)
    {
      symmetricKeys = spoton_misc::findEchoKeys
	(list.value(0), list.value(1), type, s_crypt);

      if(type == "0090")
	goto done_label;
      else
	{
	  symmetricKeys.clear();
	  type.clear();
	}
    }

  /*
  ** Attempt to decipher the message via our private key.
  ** We would like to determine the message type only if we have at least
  ** one interface attached to the kernel or if we're processing
  ** a letter.
  */

  if(interfaces > 0 && list.size() == 4 && s_crypt)
    if(!spoton_misc::allParticipantsHaveGeminis())
      if(spoton_misc::participantCount("chat", s_crypt) > 0)
	{
	  QByteArray data;
	  bool ok = true;

	  data = s_crypt->publicKeyDecrypt(list.value(0), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;
	    }

	  if(type == "0000" || type == "0000a" ||
	     type == "0000c" || type == "0013")
	    goto done_label;
	  else
	    type.clear();
	}

  if(list.size() == 3 || list.size() == 7)
    /*
    ** 0001b
    ** 0002b
    */

    if(spoton_misc::participantCount("email",
				     spoton_kernel::s_crypts.
				     value("email", 0)) > 0)
      {
	if(list.size() == 3)
	  symmetricKeys = spoton_kernel::findInstitutionKey
	    (list.value(0), list.value(1));
	else
	  symmetricKeys = spoton_kernel::findInstitutionKey
	    (list.value(0) +
	     list.value(1) +
	     list.value(2) +
	     list.value(3) +
	     list.value(4),
	     list.value(5));

	if(!symmetricKeys.isEmpty())
	  {
	    if(list.size() == 3)
	      type = "0002b";
	    else
	      type = "0001b";

	    goto done_label;
	  }
      }

  if(list.size() == 4 || list.size() == 7)
    if((s_crypt = spoton_kernel::s_crypts.value("email", 0)))
      if(spoton_misc::participantCount("email", s_crypt) > 0)
	{
	  QByteArray data;
	  bool ok = true;

	  data = s_crypt->publicKeyDecrypt(list.value(0), &ok);

	  if(ok)
	    type = QByteArray::fromBase64(data.split('\n').value(0));

	  if(type == "0001a" || type == "0001b" || type == "0002a")
	    {
	      QList<QByteArray> list(data.split('\n'));

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      symmetricKeys.append(list.value(1));
	      symmetricKeys.append(list.value(3));
	      symmetricKeys.append(list.value(2));
	      symmetricKeys.append(list.value(4));
	      goto done_label;
	    }
	  else
	    type.clear();
	}

  if(list.size() == 4)
    if((s_crypt = spoton_kernel::s_crypts.value("url", 0)))
      if(spoton_misc::participantCount("url", s_crypt) > 0)
	{
	  QByteArray data;
	  bool ok = true;

	  data = s_crypt->publicKeyDecrypt(list.value(0), &ok);

	  if(ok)
	    {
	      QByteArray a;
	      QDataStream stream(&data, QIODevice::ReadOnly);

	      stream >> a;

	      if(stream.status() == QDataStream::Ok)
		type = a;

	      if(type == "0080")
		{
		  QList<QByteArray> list;

		  for(int i = 0; i < 4; i++)
		    {
		      stream >> a;

		      if(stream.status() != QDataStream::Ok)
			{
			  list.clear();
			  type.clear();
			  break;
			}
		      else
			list.append(a);
		    }

		  if(!type.isEmpty())
		    {
		      symmetricKeys.append(list.value(0));
		      symmetricKeys.append(list.value(2));
		      symmetricKeys.append(list.value(1));
		      symmetricKeys.append(list.value(3));
		      goto done_label;
		    }
		}
	      else
		type.clear();
	    }
	}

  if(interfaces > 0 && list.size() == 4)
    for(int i = 0; i < spoton_common::SPOTON_ENCRYPTION_KEY_NAMES.size(); i++)
      {
	QString keyType(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES.at(i));

	s_crypt = spoton_kernel::s_crypts.value(keyType, 0);

	if(!s_crypt)
	  continue;

	if(spoton_misc::participantCount(keyType, s_crypt) <= 0)
	  continue;

	QByteArray data;
	bool ok = true;

	data = s_crypt->publicKeyDecrypt(list.value(0), &ok);

	if(ok)
	  {
	    QByteArray a;
	    QDataStream stream(&data, QIODevice::ReadOnly);

	    stream >> a;

	    if(stream.status() == QDataStream::Ok)
	      type = a;

	    if(type == "0091a" || type == "0091b" || type == "0092")
	      {
		QList<QByteArray> list;

		for(int i = 0; i < 4; i++)
		  {
		    stream >> a;

		    if(stream.status() != QDataStream::Ok)
		      {
			list.clear();
			type.clear();
			break;
		      }
		    else
		      list.append(a);
		  }

		if(!type.isEmpty())
		  {
		    symmetricKeys.append(list.value(0));
		    symmetricKeys.append(list.value(2));
		    symmetricKeys.append(list.value(1));
		    symmetricKeys.append(list.value(3));
		    goto done_label;
		  }
	      }
	    else
	      type.clear();
	  }
      }

  if(list.size() == 3 && (s_crypt = spoton_kernel::s_crypts.value("email", 0)))
    symmetricKeys = spoton_misc::findForwardSecrecyKeys
      (list.value(0),
       list.value(1),
       type,
       s_crypt);

 done_label:
  spoton_kernel::discoverAdaptiveEchoPair
    (data.trimmed(), discoveredAdaptiveEchoPair);

  if(!discoveredAdaptiveEchoPair.first.isEmpty() &&
     !discoveredAdaptiveEchoPair.second.isEmpty())
    {
      QWriteLocker locker(&m_learnedAdaptiveEchoPairsMutex);

      if(!m_learnedAdaptiveEchoPairs.contains(discoveredAdaptiveEchoPair))
	m_learnedAdaptiveEchoPairs.append(discoveredAdaptiveEchoPair);
    }

  return type;
}

void spoton_neighbor::slotCallParticipant(const QByteArray &data,
					  const QString &messageType)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

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
      if(write(message.constData(),
	       message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotCallParticipant(): write() "
		   "error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::saveGemini(const QByteArray &publicKeyHash,
				 const QByteArray &gemini,
				 const QByteArray &geminiHashKey,
				 const QByteArray &timestamp,
				 const QByteArray &signature,
				 const QString &messageType)
{
  /*
  ** Some of the following is similar to logic in
  ** spot-on-kernel-b.cc.
  */

  if(!spoton_kernel::setting("gui/acceptGeminis", true).toBool())
    return;

  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      spoton_misc::logError
	("spoton_neighbor::saveGemini(): invalid date-time object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  qint64 secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= static_cast<qint64> (spoton_common::
				      GEMINI_TIME_DELTA_MAXIMUM)))
    {
      spoton_misc::logError
	(QString("spoton_neighbor::saveGemini(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }
  else if(spoton_kernel::duplicateGeminis(publicKeyHash +
					  gemini +
					  geminiHashKey))
    {
      spoton_misc::logError
	(QString("spoton_neighbor::saveGemini(): duplicate keys, "
		 "message type %1.").arg(messageType));
      return;
    }

  spoton_kernel::geminisCacheAdd(publicKeyHash + gemini + geminiHashKey);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QByteArray bytes1;
	QByteArray bytes2;
	QPair<QByteArray, QByteArray> geminis;
	QSqlQuery query(db);
	bool ok = true;
	bool respond = false;

	geminis.first = gemini;
	geminis.second = geminiHashKey;

	if(messageType == "0000a")
	  if(!gemini.isEmpty() && !geminiHashKey.isEmpty())
	    if(static_cast<size_t> (gemini.length()) ==
	       spoton_crypt::cipherKeyLength("aes256") / 2 &&
	       geminiHashKey.length() ==
	       spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES / 2)
	      {
		bytes1 = spoton_crypt::strongRandomBytes
		  (spoton_crypt::cipherKeyLength("aes256") / 2);
		bytes2 = spoton_crypt::strongRandomBytes
		  (spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES / 2);
		geminis.first.append(bytes1);
		geminis.second.append(bytes2);
		respond = true;
	      }

	if(messageType == "0000c")
	  if(!gemini.isEmpty() && !geminiHashKey.isEmpty())
	    if(static_cast<size_t> (gemini.length()) ==
	       spoton_crypt::cipherKeyLength("aes256") / 2 &&
	       geminiHashKey.length() ==
	       spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES / 2)
	      {
		/*
		** We may be processing a two-way call.
		*/

		spoton_crypt *s_crypt =
		  spoton_kernel::s_crypts.value("chat", 0);

		if(s_crypt)
		  {
		    query.setForwardOnly(true);
		    query.prepare("SELECT gemini, gemini_hash_key "
				  "FROM friends_public_keys WHERE "
				  "neighbor_oid = -1 AND "
				  "public_key_hash = ?");
		    query.bindValue(0, publicKeyHash.toBase64());

		    if(query.exec() && query.next())
		      {
			if(!query.isNull(0))
			  bytes1 = s_crypt->decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(0).
						    toByteArray()),
			     &ok);

			if(ok)
			  if(!query.isNull(1))
			    bytes2 = s_crypt->decryptedAfterAuthenticated
			      (QByteArray::fromBase64(query.value(1).
						      toByteArray()),
			       &ok);

			if(ok)
			  {
			    /*
			    ** This is a response.
			    */

			    geminis.first.prepend
			      (bytes1.mid(0, gemini.length()));
			    geminis.second.prepend
			      (bytes2.mid(0, geminiHashKey.length()));
			  }
		      }
		  }
	      }

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ?, "
		      "last_status_update = ?, status = 'online' "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");

	if(geminis.first.isEmpty() || geminis.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    spoton_crypt *s_crypt =
	      spoton_kernel::s_crypts.value("chat", 0);

	    if(s_crypt)
	      {
		query.bindValue
		  (0, s_crypt->encryptedThenHashed(geminis.first, &ok).
		   toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encryptedThenHashed(geminis.second,
						     &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue
	  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(3, publicKeyHash.toBase64());

	if(ok)
	  if(query.exec())
	    {
	      QString notsigned("");

	      if(signature.isEmpty())
		notsigned = " (unsigned)";

	      if(geminis.first.isEmpty() ||
		 geminis.second.isEmpty())
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 terminated%3 the call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned));
	      else if(messageType == "0000a")
		{
		  if(respond)
		    emit statusMessageReceived
		      (publicKeyHash,
		       tr("The participant %1...%2 may have "
			  "initiated a two-way call%3. Response dispatched.").
		       arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		       arg(publicKeyHash.toBase64().right(16).constData()).
		       arg(notsigned));
		  else
		    emit statusMessageReceived
		      (publicKeyHash,
		       tr("The participant %1...%2 initiated a call%3.").
		       arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		       arg(publicKeyHash.toBase64().right(16).constData()).
		       arg(notsigned));
		}
	      else if(messageType == "0000b")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call%3 "
		      "within a call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned));
	      else if(messageType == "0000c")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("Received a two-way call response%1 from "
		      "participant %2...%3.").
		   arg(notsigned).
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	      else if(messageType == "0000d")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call via "
		      "Forward Secrecy.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));

	      /*
	      ** Respond to this call with a new pair of half keys.
	      */

	      if(respond)
		emit callParticipant(publicKeyHash, bytes1, bytes2);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::addToBytesWritten(const qint64 bytesWritten)
{
  QWriteLocker locker(&m_bytesWrittenMutex);

  m_bytesWritten += static_cast<quint64> (qAbs(bytesWritten));
  locker.unlock();

  {
    QWriteLocker locker
      (&spoton_kernel::s_totalNeighborsBytesReadWrittenMutex);

    spoton_kernel::s_totalNeighborsBytesReadWritten.second +=
      static_cast<quint64> (qAbs(bytesWritten));
  }
}

void spoton_neighbor::slotSendAccountInformation(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(state() != QAbstractSocket::ConnectedState)
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray name;
  QByteArray password;
  bool ok = true;

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
	QByteArray salt
	  (spoton_crypt::
	   strongRandomBytes(spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE));

	hash = spoton_crypt::keyedHash
	  (QDateTime::currentDateTime().toUTC().toString("MMddyyyyhhmm").
	   toLatin1() + salt, name + password, "sha512", &ok);

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

void spoton_neighbor::slotAccountAuthenticated(const QByteArray &clientSalt,
					       const QByteArray &name,
					       const QByteArray &password)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(state() != QAbstractSocket::ConnectedState)
    return;
  else if(name.length() < 32 || password.length() < 32)
    return;

  QByteArray hash;
  QByteArray message;
  QByteArray salt(spoton_crypt::
		  strongRandomBytes(spoton_common::
				    ACCOUNTS_RANDOM_BUFFER_SIZE));
  bool ok = true;

  /*
  ** The server authenticated the client's credentials. We'll
  ** now create a similar response so that the client can
  ** verify the server. We are the server.
  */

  hash = spoton_crypt::keyedHash
    (QDateTime::currentDateTime().toUTC().toString("MMddyyyyhhmm").
     toLatin1() + clientSalt + salt, name + password, "sha512", &ok);

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

void spoton_neighbor::slotSendAuthenticationRequest(void)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return;

  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message(spoton_send::message0052());

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendAuthenticationRequest(): "
	       "write() error for %1:%2.").
       arg(m_address).
       arg(m_port));
}

qint64 spoton_neighbor::write(const char *data, const qint64 size)
{
  if(!data || size < 0)
    return -1;
  else if(size == 0)
    return 0;

  qint64 udpMinimum = qMin
    (static_cast<qint64> (spoton_common::MAXIMUM_UDP_DATAGRAM_SIZE), size);
  qint64 remaining = size;
  qint64 sent = 0;

  while(remaining > 0)
    {
      if(m_bluetoothSocket)
	{
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
	  sent = m_bluetoothSocket->write
	    (data,
	     qMin(spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE, remaining));

	  if(sent > 0)
	    {
	      if(remaining - sent >
		 spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE)
		m_bluetoothSocket->waitForBytesWritten
		  (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
	      else if(m_waitforbyteswritten_msecs > 0)
		m_bluetoothSocket->waitForBytesWritten
		  (m_waitforbyteswritten_msecs);
	    }
#endif
	}
      else if(m_sctpSocket)
	sent = m_sctpSocket->write(data, remaining);
      else if(m_tcpSocket)
	{
	  sent = m_tcpSocket->write
	    (data, qMin(spoton_common::MAXIMUM_TCP_PACKET_SIZE, remaining));

	  if(sent > 0)
	    {
	      if(remaining - sent > spoton_common::MAXIMUM_TCP_PACKET_SIZE)
		m_tcpSocket->waitForBytesWritten
		  (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
	      else if(m_waitforbyteswritten_msecs > 0)
		m_tcpSocket->waitForBytesWritten(m_waitforbyteswritten_msecs);
	    }
	}
      else if(m_udpSocket)
	{
	  if(m_isUserDefined)
	    sent = m_udpSocket->write(data, qMin(udpMinimum, remaining));
	  else
	    {
	      QHostAddress address(m_address);

	      address.setScopeId(m_scopeId);
	      sent = m_udpSocket->writeDatagram
		(data, qMin(udpMinimum, remaining), address, m_port);
	    }

	  if(sent > 0)
	    {
	      if(remaining - sent > udpMinimum)
		m_udpSocket->waitForBytesWritten
		  (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
	      else if(m_waitforbyteswritten_msecs > 0)
		m_udpSocket->waitForBytesWritten(m_waitforbyteswritten_msecs);
	    }

	  if(sent == -1)
	    {
	      if(m_udpSocket->error() ==
		 QAbstractSocket::DatagramTooLargeError)
		{
		  udpMinimum = udpMinimum / 2;

		  if(udpMinimum > 0)
		    continue;
		}
	      else if(m_udpSocket->error() ==
		      QAbstractSocket::UnknownSocketError)
		{
		  /*
		  ** If the end-point is absent, QIODevice::write() may
		  ** return -1.
		  */

		  deleteLater();
		  break;
		}
	    }
	}
      else
	sent = 0;

      if(sent > 0)
	addToBytesWritten(sent);

      if(sent <= 0 || sent > size)
	break;

      data += sent;
      remaining -= sent;
    }

  return size - remaining;
}

bool spoton_neighbor::writeMessage0060(const QByteArray &data)
{
  if(m_passthrough && !m_privateApplicationCredentials.isEmpty())
    return false;

  bool ok = true;

  if((ok = readyToWrite()))
    {
      QByteArray message;
      QPair<QByteArray, QByteArray> ae
	(spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
						spoton_kernel::s_crypts.
						value("chat", 0)));

      message = spoton_send::message0060(data, ae);

      if(write(message.constData(), message.length()) != message.length())
	{
	  ok = false;
	  spoton_misc::logError
	    (QString("spoton_neighbor::writeMessage0060(): write() error "
		     "for %1:%2.").
	     arg(m_address).
	     arg(m_port));
	}
      else
	spoton_kernel::messagingCacheAdd(message);
    }

  return ok;
}
