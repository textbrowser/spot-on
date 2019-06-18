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

#include <QSqlQuery>

#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"

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

  if(interfaces > 0 && (list.size() == 2 || list.size() == 3))
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
	    type = QByteArray::fromBase64(data.split('\n').value(0));

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

QUuid spoton_neighbor::receivedUuid(void)
{
  QReadLocker locker(&m_receivedUuidMutex);

  return m_receivedUuid;
}

bool spoton_neighbor::readyToWrite(void)
{
  if(!(state() == QAbstractSocket::BoundState ||
       state() == QAbstractSocket::ConnectedState))
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

qint64 spoton_neighbor::id(void) const
{
  return m_id;
}

qint64 spoton_neighbor::write(const char *data, const qint64 size)
{
  if(!data || size < 0)
    return -1;
  else if(size == 0)
    return 0;

  qint64 remaining = size;
  qint64 sent = 0;
  qint64 udpMinimum = qMin
    (static_cast<qint64> (spoton_common::MAXIMUM_UDP_DATAGRAM_SIZE), size);

  while(remaining > 0)
    {
      if(m_bluetoothSocket)
	{
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
	  sent = m_bluetoothSocket->write
	    (data,
	     qMin(spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE, remaining));

	  if(sent > 0)
	    {
	      if(remaining - sent >
		 spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE)
		{
		  if(m_waitforbyteswritten_msecs > 0)
		    m_bluetoothSocket->waitForBytesWritten
		      (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
		}
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
		{
		  if(m_waitforbyteswritten_msecs > 0)
		    m_tcpSocket->waitForBytesWritten
		      (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
		}
	      else if(m_waitforbyteswritten_msecs > 0)
		m_tcpSocket->waitForBytesWritten(m_waitforbyteswritten_msecs);
	    }
	}
      else if(m_udpSocket)
	{
	  if(m_isUserDefined)
	    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
	      if(m_dtls)
		sent = m_dtls->writeDatagramEncrypted
		  (m_udpSocket, QByteArray(data, qMin(remaining, udpMinimum)));
	      else
#endif
		sent = m_udpSocket->write(data, qMin(remaining, udpMinimum));
	    }
	  else
	    {
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
	      if(m_dtls)
		sent = m_dtls->writeDatagramEncrypted
		  (m_udpSocket, QByteArray(data, qMin(remaining, udpMinimum)));
	      else
#endif
		{
		  QHostAddress address(m_address);

		  address.setScopeId(m_scopeId);
		  sent = m_udpSocket->writeDatagram
		    (data, qMin(remaining, udpMinimum), address, m_port);
		}
	    }

	  if(sent > 0)
	    {
	      if(remaining - sent > udpMinimum)
		{
		  if(m_waitforbyteswritten_msecs > 0)
		    m_udpSocket->waitForBytesWritten
		      (spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED);
		}
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
	      else if(m_udpSocket->
		      error() == QAbstractSocket::UnknownSocketError)
		{
		  /*
		  ** If the end-point is absent, QIODevice::write() may
		  ** return -1.
		  */

		  emit notification
		    (QString("The neighbor %1:%2 generated "
			     "a fatal error (unknown socket error).").
		     arg(m_address).arg(m_port));
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

  if(remaining > 0)
    {
      QWriteLocker locker(&m_bytesDiscardedOnWriteMutex);

      m_bytesDiscardedOnWrite += remaining;
    }

  return size - remaining;
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
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
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
      else if(length > 0 && data.contains("type=0095a&content="))
	process0095a(length, data);
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

		messageType = "starbeam";
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
	      else if(!discoveredAdaptiveEchoPair.first.isEmpty() &&
		      !discoveredAdaptiveEchoPair.second.isEmpty() &&
		      messageType == "starbeam")
		emit receivedMessage
		  (originalData, m_id, discoveredAdaptiveEchoPair);
	    }
	}
    }
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

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
  if(m_dtls)
    cipher = m_dtls->sessionCipher();
  else
#endif
  if(m_tcpSocket)
    cipher = m_tcpSocket->sessionCipher();

  qint64 seconds = qAbs(m_startTime.secsTo(QDateTime::currentDateTime()));

  query.prepare("UPDATE neighbors SET "
		"buffered_content = ?, "
		"bytes_discarded_on_write = ?, "
		"bytes_read = ?, "
		"bytes_written = ?, "
		"is_encrypted = ?, "
		"ssl_session_cipher = ?, "
		"status = ?, "
		"uptime = ? "
		"WHERE OID = ?");

  {
    QReadLocker locker(&m_dataMutex);

    query.addBindValue(m_data.length());
  }

  {
    QReadLocker locker(&m_bytesDiscardedOnWriteMutex);

    query.addBindValue(m_bytesDiscardedOnWrite);
  }

  query.addBindValue(m_bytesRead);

  {
    QReadLocker locker(&m_bytesWrittenMutex);

    query.addBindValue(m_bytesWritten);
  }

  query.addBindValue(isEncrypted() ? 1 : 0);

  if(cipher.isNull() || !spoton_kernel::s_crypts.value("chat", 0))
    query.addBindValue(QVariant::String);
  else
    query.addBindValue
      (spoton_kernel::s_crypts.value("chat")->
       encryptedThenHashed(QString("%1-%2-%3-%4-%5-%6-%7").
			   arg(cipher.name()).
			   arg(cipher.authenticationMethod()).
			   arg(cipher.encryptionMethod()).
			   arg(cipher.keyExchangeMethod()).
			   arg(cipher.protocolString()).
			   arg(cipher.supportedBits()).
			   arg(cipher.usedBits()).toUtf8(), 0).toBase64());

  switch(state())
    {
    case QAbstractSocket::BoundState:
      {
	query.addBindValue("connected");
	break;
      }
    case QAbstractSocket::ClosingState:
      {
	query.addBindValue("closing");
	break;
      }
    case QAbstractSocket::ConnectedState:
      {
	query.addBindValue("connected");
	break;
      }
    case QAbstractSocket::ConnectingState:
      {
	query.addBindValue("connecting");
	break;
      }
    case QAbstractSocket::HostLookupState:
      {
	query.addBindValue("host-lookup");
	break;
      }
    default:
      {
	query.addBindValue("disconnected");
	break;
      }
    }

  query.addBindValue(seconds);
  query.addBindValue(m_id);
  query.exec();
}

void spoton_neighbor::saveStatus(const QSqlDatabase &db, const QString &status)
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

  query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		"WHERE OID = ? AND status_control <> 'deleted'");
  query.bindValue(0, isEncrypted() ? 1 : 0);
  query.bindValue(1, status.trimmed());
  query.bindValue(2, m_id);
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

void spoton_neighbor::setId(const qint64 id)
{
  m_id = id;
}
