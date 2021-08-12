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

#include <QSslConfiguration>
#include <QSslKey>

#include "spot-on-neighbor.h"

void spoton_neighbor::prepareSslConfiguration(const QByteArray &certificate,
					      const QByteArray &privateKey,
					      const bool client)
{
  if(!((m_tcpSocket || m_udpSocket || m_webSocket) && m_useSsl))
    return;

  if(client)
    {
      QSslConfiguration configuration;

      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

      if(!configuration.privateKey().isNull())
	{
	  configuration.setSslOption
	    (QSsl::SslOptionDisableCompression, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableEmptyFragments, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableLegacyRenegotiation, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionTickets, true);
#if QT_VERSION >= 0x050501
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionPersistence, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableSessionSharing, true);
#endif
	  configuration.setPeerVerifyMode(QSslSocket::QueryPeer);
	  spoton_crypt::setSslCiphers
	    (configuration.supportedCiphers(),
	     m_sslControlString,
	     configuration);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	  if(m_udpSocket)
	    {
	      m_udpSslConfiguration = configuration;
	      m_udpSslConfiguration.setProtocol(QSsl::DtlsV1_2OrLater);
	    }
#endif
	  if(m_tcpSocket)
	    m_tcpSocket->setSslConfiguration(configuration);

#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
	  if(m_webSocket)
	    m_webSocket->setSslConfiguration(configuration);
#endif
	}
      else
	{
	  m_useSsl = m_requireSsl;
	  spoton_misc::logError
	    (QString("spoton_neighbor::prepareSslConfiguration(): "
		     "empty private key for %1:%2.").
	     arg(m_ipAddress).
	     arg(m_port));
	}
    }
  else
    {
      QSslConfiguration configuration;

      configuration.setLocalCertificate(QSslCertificate(certificate));

      if(!configuration.localCertificate().isNull())
	{
	  configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	  if(!configuration.privateKey().isNull())
	    {
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionTickets, true);
#if QT_VERSION >= 0x050501
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionPersistence, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableSessionSharing, true);
#endif
	      spoton_crypt::setSslCiphers
		(configuration.supportedCiphers(),
		 m_sslControlString,
		 configuration);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
	      if(m_udpSocket)
		{
		  m_udpSslConfiguration = configuration;
		  m_udpSslConfiguration.
		    setDtlsCookieVerificationEnabled(true);
		  m_udpSslConfiguration.setPeerVerifyMode
		    (QSslSocket::QueryPeer);
		  m_udpSslConfiguration.setProtocol(QSsl::DtlsV1_2OrLater);
		}
#endif

	      if(m_tcpSocket)
		m_tcpSocket->setSslConfiguration(configuration);
	    }
	  else
	    {
	      m_useSsl = false;
	      spoton_misc::logError
		(QString("spoton_neighbor::prepareSslConfiguration(): "
			 "empty private key for %1:%2. SSL disabled.").
		 arg(m_address).
		 arg(m_port));
	    }
	}
      else
	{
	  m_useSsl = false;
	  spoton_misc::logError
	    (QString("spoton_neighbor::prepareSslConfiguration(): "
		     "invalid local certificate for %1:%2. SSL disabled.").
	     arg(m_address).
	     arg(m_port));
	}
    }
}

void spoton_neighbor::slotSpecialTimerTimeout(void)
{
  if(m_bindIpAddress.isEmpty() || !m_tcpSocket)
    {
      if(m_bindIpAddress.isEmpty())
	m_specialPeerTimer.stop();

      return;
    }

  if(m_tcpSocket->state() == QAbstractSocket::ConnectedState)
    m_specialPeerTimer.stop();
  else if(m_tcpSocket->state() == QAbstractSocket::BoundState ||
	  m_tcpSocket->state() == QAbstractSocket::UnconnectedState)
    m_tcpSocket->connectToHost(m_address, m_port);
}

void spoton_neighbor::slotInitiateSSLTLSSession(const bool client,
						const qint64 oid)
{
  if(m_bindIpAddress.isEmpty() ||
     m_id != oid ||
     m_tcpSocket == nullptr ||
     m_tcpSocket->isEncrypted() ||
     m_tcpSocket->state() != QAbstractSocket::ConnectedState ||
     m_useSsl != true)
    return;

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  spoton_crypt::generateSslKeys
    (m_keySize,
     certificate,
     privateKey,
     publicKey,
     QHostAddress(),
     31536000L,
     error);

  if(!error.isEmpty())
    return;

  prepareSslConfiguration(certificate, privateKey, client);

  if(client)
    m_tcpSocket->startClientEncryption();
  else
    m_tcpSocket->startServerEncryption();
}
