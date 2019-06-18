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
