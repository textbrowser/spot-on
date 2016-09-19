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

#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"

QAbstractSocket::SocketState spoton_neighbor::state(void) const
{
  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      return QAbstractSocket::SocketState(m_bluetoothSocket->state());
#endif
      return QAbstractSocket::UnconnectedState;
    }
  else if(m_sctpSocket)
    return QAbstractSocket::SocketState(m_sctpSocket->state());
  else if(m_tcpSocket)
    return m_tcpSocket->state();
  else if(m_udpSocket)
    return m_udpSocket->state();
  else
    return QAbstractSocket::UnconnectedState;
}

QString spoton_neighbor::localAddress(void) const
{
  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      return m_bluetoothSocket->localAddress().toString();
#else
      return "";
#endif
    }
  else if(m_sctpSocket)
    return m_sctpSocket->localAddress().toString();
  else if(m_tcpSocket)
    return m_tcpSocket->localAddress().toString();
  else if(m_udpSocket)
    return m_udpSocket->localAddress().toString();
  else
    return "";
}

QString spoton_neighbor::peerAddress(void) const
{
  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      return m_bluetoothSocket->peerAddress().toString();
#else
      return "";
#endif
    }
  else if(m_sctpSocket)
    return m_sctpSocket->peerAddress().toString();
  else if(m_tcpSocket)
    return m_tcpSocket->peerAddress().toString();
  else if(m_udpSocket)
    return m_udpSocket->peerAddress().toString();
  else
    return "";
}

quint16 spoton_neighbor::peerPort(void) const
{
  if(m_sctpSocket)
    return m_sctpSocket->peerPort();
  else if(m_tcpSocket)
    return m_tcpSocket->peerPort();
  else if(m_udpSocket)
    return m_udpSocket->peerPort();
  else
    return 0;
}

bool spoton_neighbor::isEncrypted(void) const
{
  if(m_tcpSocket)
    return m_tcpSocket->isEncrypted();
  else
    return false;
}

QString spoton_neighbor::transport(void) const
{
  return m_transport;
}

void spoton_neighbor::slotAuthenticationTimerTimeout(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotAuthenticationTimerTimeout(): "
	     "authentication timer expired for %1:%2. Aborting!").
     arg(m_address).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::abort(void)
{
  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_bluetoothSocket->abort();
#endif
    }
  else if(m_sctpSocket)
    m_sctpSocket->abort();
  else if(m_tcpSocket)
    m_tcpSocket->abort();
  else if(m_udpSocket)
    m_udpSocket->abort();
}

void spoton_neighbor::close(void)
{
  if(m_bluetoothSocket)
    {
#if QT_VERSION >= 0x050200 && defined(SPOTON_BLUETOOTH_ENABLED)
      m_bluetoothSocket->disconnectFromService();
#endif
    }
  else if(m_sctpSocket)
    m_sctpSocket->close();
  else if(m_tcpSocket)
    {
      if(!m_isUserDefined)
	{
	  int socketDescriptor = static_cast<int>
	    (m_tcpSocket->socketDescriptor());

#ifdef Q_OS_WIN32
	  shutdown(socketDescriptor, SD_BOTH);
#else
	  shutdown(socketDescriptor, SHUT_RDWR);
#endif
	}

      m_tcpSocket->close();
    }
  else if(m_udpSocket)
    m_udpSocket->close();
}

void spoton_neighbor::slotStopTimer(QTimer *timer)
{
  if(timer)
    timer->stop();
}

void spoton_neighbor::slotNewDatagram(const QByteArray &datagram)
{
  if(datagram.isEmpty())
    return;

  if(m_passthrough)
    {
      /*
      ** A private application may not be able to authenticate.
      */

      if(!m_isUserDefined) // We're a server.
	if(m_privateApplicationCrypt)
	  {
	    QFuture<void> future = QtConcurrent::run
	      (this,
	       &spoton_neighbor::bundlePrivateApplicationData,
	       datagram,
	       m_id);

	    m_privateApplicationFutures << future;
	    return;
	  }

      bool ok = true;

      if(m_useAccounts.fetchAndAddOrdered(0))
	if(!m_accountAuthenticated.fetchAndAddOrdered(0))
	  ok = false;

      if(ok)
	{
	  if(!spoton_kernel::messagingCacheContains(datagram))
	    {
	      emit receivedMessage
		(datagram, m_id, QPair<QByteArray, QByteArray> ());
	      spoton_kernel::messagingCacheAdd(datagram);
	    }

	  emit resetKeepAlive();
	  return;
	}
    }

  QReadLocker locker1(&m_maximumBufferSizeMutex);
  qint64 maximumBufferSize = m_maximumBufferSize;

  locker1.unlock();

  QWriteLocker locker2(&m_dataMutex);
  int length = static_cast<int> (maximumBufferSize) - m_data.length();

  if(length > 0)
    m_data.append(datagram.mid(0, length));

  if(!m_data.isEmpty())
    {
      locker2.unlock();
      emit newData();
    }
}

void spoton_neighbor::saveUrlsToShared(const QList<QByteArray> &urls)
{
  if(urls.isEmpty())
    return;

  if(spoton_kernel::instance())
    spoton_kernel::instance()->saveUrls(urls);
}

void spoton_neighbor::slotEchoKeyShare(const QByteArrayList &list)
{
  if(!m_isUserDefined)
    if(m_passthrough && m_privateApplicationCrypt)
      return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

  message = spoton_send::message0090
    (list.value(0) + "\n" + list.value(1), ae);

  if(readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotEchoKeyShare(): write() error "
		   "for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::deleteLater(void)
{
#if QT_VERSION >= 0x050200 && defined(Q_OS_MAC) && \
  defined(SPOTON_BLUETOOTH_ENABLED)
  if(m_transport == "bluetooth")
    {
      /*
      ** Deferred deletion does not function correctly on
      ** OS X.
      */

      m_abort.fetchAndStoreOrdered(1);
      disconnect(m_bluetoothSocket,
		 SIGNAL(connected(void)),
		 this,
		 SLOT(slotConnected(void)));
      disconnect(m_bluetoothSocket,
		 SIGNAL(disconnected(void)),
		 this,
		 SIGNAL(disconnected(void)));
      disconnect(m_bluetoothSocket,
		 SIGNAL(disconnected(void)),
		 this,
		 SLOT(slotDisconnected(void)));
      disconnect(m_bluetoothSocket,
		 SIGNAL(error(QBluetoothSocket::SocketError)),
		 this,
		 SLOT(slotError(QBluetoothSocket::SocketError)));
      disconnect(m_bluetoothSocket,
		 SIGNAL(readyRead(void)),
		 this,
		 SLOT(slotReadyRead(void)));
      disconnect(this,
		 SIGNAL(accountAuthenticated(const QByteArray &,
					     const QByteArray &,
					     const QByteArray &)),
		 this,
		 SLOT(slotAccountAuthenticated(const QByteArray &,
					       const QByteArray &,
					       const QByteArray &)));
      disconnect(this,
		 SIGNAL(resetKeepAlive(void)),
		 this,
		 SLOT(slotResetKeepAlive(void)));
      disconnect(this,
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
      disconnect(this,
		 SIGNAL(stopTimer(QTimer *)),
		 this,
		 SLOT(slotStopTimer(QTimer *)));
      disconnect(this,
		 SIGNAL(writeParsedApplicationData(const QByteArray &)),
		 this,
		 SLOT(slotWriteParsedApplicationData(const QByteArray &)));
      close();
      m_accountTimer.stop();
      m_authenticationTimer.stop();
      m_externalAddressDiscovererTimer.stop();
      m_keepAliveTimer.stop();
      m_lifetime.stop();
      m_timer.stop();
      delete this;
    }
  else
    QThread::deleteLater();
#else
  QThread::deleteLater();
#endif
}

void spoton_neighbor::slotSendForwardSecrecyPublicKey(const QByteArray &data)
{
  if(!m_isUserDefined)
    if(m_passthrough && m_privateApplicationCrypt)
      return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

  message = spoton_send::message0091a(data, ae);

  if(readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendForwardSecrecyPublicKey(): "
		   "write() error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::slotSendForwardSecrecySessionKeys
(const QByteArray &data)
{
  if(!m_isUserDefined)
    if(m_passthrough && m_privateApplicationCrypt)
      return;

  QByteArray message;
  QPair<QByteArray, QByteArray> ae
    (spoton_misc::decryptedAdaptiveEchoPair(m_adaptiveEchoPair,
					    spoton_kernel::s_crypts.
					    value("chat", 0)));

  message = spoton_send::message0091b(data, ae);

  if(readyToWrite())
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendForwardSecrecySessionKeys(): "
		   "write() error for %1:%2.").
	   arg(m_address).
	   arg(m_port));
      else
	spoton_kernel::messagingCacheAdd(message);
    }
}

void spoton_neighbor::parsePrivateApplicationData
(const QByteArray &data,
 const qint64 id,
 const qint64 maximumContentLength)
{
  /*
  ** The container data contains Spot-On data, that is, data does
  ** not contain raw application data.
  */

  if(!m_privateApplicationCrypt)
    return;
  else if(spoton_kernel::messagingCacheContains(data + QByteArray::number(id)))
    return;

  int a = data.indexOf("Content-Length: ");

  if(a >= 0)
    {
      QByteArray contentLength;
      int b = data.indexOf("\r\n", a);
      int length = 0;

      if(b > 0)
	{
	  a += static_cast<int> (qstrlen("Content-Length: "));

	  if(a < b)
	    contentLength = data.mid(a, b - a);
	}

      /*
      ** toInt() returns zero on failure.
      */

      length = contentLength.toInt();

      if(length > 0 && length <= maximumContentLength)
	if((a = data.indexOf("content=", a)) > 0)
	  {
	    QByteArray bytes(data.mid(a));

	    if(bytes.length() == length)
	      {
		bytes = bytes.mid
		  (static_cast<int> (qstrlen("content="))).trimmed();

		if((a = bytes.lastIndexOf('\n')) > 0)
		  {
		    bool ok = true;

		    bytes = bytes.mid(0, a);
		    bytes = m_privateApplicationCrypt->
		      decryptedAfterAuthenticated(QByteArray::
						  fromBase64(bytes), &ok);

		    if(ok)
		      emit writeParsedApplicationData(bytes);
		  }
	      }
	  }
    }
}

void spoton_neighbor::slotWriteParsedApplicationData(const QByteArray &data)
{
  /*
  ** Let's write the raw data to the private application.
  */

  if(data.length() > m_laneWidth)
    return;

  if(readyToWrite())
    if(write(data.constData(), data.length()) != data.length())
      spoton_misc::logError
	(QString("spoton_neighbor::slotWriteParsedApplicationData(): "
		 "write() error for %1:%2.").
	 arg(m_address).
	 arg(m_port));
}

void spoton_neighbor::bundlePrivateApplicationData(const QByteArray &data,
						   const qint64 id)
{
  /*
  ** The private application (id) transmitted some raw data. We'll
  ** bundle it and internally echo the results to other neighbors. We shall
  ** pass id to those neighbors. One neighbor will store a digest
  ** of the bundled data that's specific to our id. That is, we need
  ** to tag the bundled data with the id of the neighbor that is
  ** connected to the private application.
  */

  /*
  ** The container data contains raw application data.
  ** We will not insert an entry into the congestion-control mechanism here.
  */

  if(!m_privateApplicationCrypt)
    return;

  QByteArray bytes;
  bool ok = true;

  bytes = m_privateApplicationCrypt->encryptedThenHashed(data, &ok);

  if(ok)
    emit receivedMessage
      (spoton_send::messageXYZ(bytes.toBase64(),
			       QPair<QByteArray, QByteArray> ()),
       id,
       QPair<QByteArray, QByteArray> ());

  emit resetKeepAlive();
}
