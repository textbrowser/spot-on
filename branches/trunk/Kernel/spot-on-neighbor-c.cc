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

#include "Common/spot-on-receive.h"
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

bool spoton_neighbor::writeMessage006X(const QByteArray &data,
				       const QString &messageType)
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

      if(messageType == "0060")
	message = spoton_send::message0060(data, ae);
      else
	message = spoton_send::message0061(data, ae);

      if(write(message.constData(), message.length()) != message.length())
	{
	  ok = false;
	  spoton_misc::logError
	    (QString("spoton_neighbor::writeMessage006X(): write() error "
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

void spoton_neighbor::process0000(int length,
				  const QByteArray &dataIn,
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

void spoton_neighbor::process0000a(int length,
				   const QByteArray &dataIn,
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

void spoton_neighbor::process0000b(int length,
				   const QByteArray &dataIn,
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

void spoton_neighbor::process0000d(int length,
				   const QByteArray &dataIn,
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

void spoton_neighbor::process0001b(int length,
				   const QByteArray &dataIn,
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

void spoton_neighbor::process0001c(int length,
				   const QByteArray &dataIn,
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
(int length,
 const QByteArray &dataIn,
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
(int length,
 const QByteArray &dataIn,
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

void spoton_neighbor::process0013(int length,
				  const QByteArray &dataIn,
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
#if QT_VERSION >= 0x040806
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
#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
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

void spoton_neighbor::process0040a(int length,
				   const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = data.trimmed();

      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(!(list.size() == 2 || list.size() == 3))
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040a(): "
		     "received irregular data. Expecting 2 or 3 "
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

void spoton_neighbor::process0040b(int length,
				   const QByteArray &dataIn,
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

      if(!(list.size() == 2 || list.size() == 3))
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040b(): "
		     "received irregular data. Expecting 2 or 3 "
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

void spoton_neighbor::process0080(int length,
				  const QByteArray &dataIn,
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
				  {
				    QByteArray recipientDigest;
				    bool ok = true;
				    spoton_crypt *s_crypt = spoton_kernel::
				      s_crypts.value("url", 0);

				    if(s_crypt)
				      recipientDigest = s_crypt->publicKey(&ok);
				    else
				      ok = false;

				    if(ok)
				      recipientDigest = spoton_crypt::
					sha512Hash(recipientDigest, &ok);

				    if(!ok ||
				       !spoton_misc::
				       isValidSignature(dataForSignature +
							recipientDigest,
							publicKeyHash,
							signature,
							s_crypt))
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

void spoton_neighbor::process0090(int length,
				  const QByteArray &dataIn,
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

void spoton_neighbor::process0091a(int length,
				   const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0091(length, dataIn, symmetricKeys,
				 m_address, m_port, "0091a"));

  if(!list.isEmpty())
    emit forwardSecrecyRequest(list);
}

void spoton_neighbor::process0091b(int length,
				   const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0091(length, dataIn, symmetricKeys,
				 m_address, m_port, "0091b"));

  if(!list.isEmpty())
    emit saveForwardSecrecySessionKeys(list);
}

void spoton_neighbor::process0092(int length,
				  const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list
    (spoton_receive::process0092(length, dataIn, symmetricKeys,
				 m_address, m_port));

  if(!list.isEmpty())
    emit smpMessage(list);
}

void spoton_neighbor::process0095a(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= static_cast<int> (qstrlen("type=0095a&content="));

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0095a&content=");

  if(indexOf < 0)
    return;

  data.remove
    (0, indexOf + static_cast<int> (qstrlen("type=0095a&content=")));

  if(length == data.length())
    {
      emit receivedMessage(dataIn, m_id, QPair<QByteArray, QByteArray> ());
      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0095a(): 0095a "
	       "Content-Length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address).
       arg(m_port));
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
		     "data (%1) does not contain Content-Length "
		     "from node %2:%3.").
	     arg(originalData.mid(0, 128).constData()).
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

	  int indexOf = data.lastIndexOf("\r\n");

	  if(indexOf > -1)
	    data = data.mid(0, indexOf + 2);

	  QRegExp rx("(type=[0-9][0-9][0-9][0-9][a-z]{0,1}&){0,1}content=");

	  indexOf = QString(data).indexOf(rx);

	  if(indexOf > -1)
	    {
	      data.remove(0, indexOf + rx.matchedLength());
	      length -= rx.matchedLength();
	    }

	  if(data.length() == length)
	    {
	      emit resetKeepAlive();
	      spoton_kernel::messagingCacheAdd(originalData);
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::processData(): "
			 "data length (%1) does not equal content length (%2) "
			 "from node %3:%4 (%5). Ignoring.").
		 arg(data.length()).
		 arg(length).
		 arg(m_address).
		 arg(m_port).
		 arg(originalData.mid(0, 128).constData()));
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

	  QString messageType
	    (findMessageType(data, symmetricKeys, discoveredAdaptiveEchoPair));

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
		  emit notification
		    (QString("The neighbor %1:%2 generated a fatal "
			     "error (%3).").
		     arg(m_address).arg(m_port).arg("empty peer certificate"));
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
		  emit notification
		    (QString("The neighbor %1:%2 generated a fatal "
			     "error (%3).").
		     arg(m_address).arg(m_port).arg("certificate mismatch"));
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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0))
      else if(m_udpSocket)
	certificate = m_udpSslConfiguration.localCertificate();
#endif

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

void spoton_neighbor::run(void)
{
  spoton_neighbor_worker worker(this);

  connect(this,
	  SIGNAL(newData(void)),
	  &worker,
	  SLOT(slotNewData(void)));
  exec();
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

  if(state == QAbstractSocket::BoundState ||
     state == QAbstractSocket::ConnectedState)
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
		   tr("The participant %1...%2 terminated%3 the call "
		      "via %4:%5.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned).
		   arg(m_address).
		   arg(m_port));
	      else if(messageType == "0000a")
		{
		  if(respond)
		    emit statusMessageReceived
		      (publicKeyHash,
		       tr("The participant %1...%2 may have "
			  "initiated a two-way call%3 via %4:%5. "
			  "Response dispatched.").
		       arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		       arg(publicKeyHash.toBase64().right(16).constData()).
		       arg(notsigned).
		       arg(m_address).
		       arg(m_port));
		  else
		    emit statusMessageReceived
		      (publicKeyHash,
		       tr("The participant %1...%2 initiated a call%3 "
			  "via %4:%5.").
		       arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		       arg(publicKeyHash.toBase64().right(16).constData()).
		       arg(notsigned).
		       arg(m_address).
		       arg(m_port));
		}
	      else if(messageType == "0000b")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call%3 "
		      "within a call via %4:%5.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned).
		   arg(m_address).
		   arg(m_port));
	      else if(messageType == "0000c")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("Received a two-way call response%1 from "
		      "participant %2...%3 via %4:%5.").
		   arg(notsigned).
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(m_address).
		   arg(m_port));
	      else if(messageType == "0000d")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call via "
		      "Forward Secrecy via %3:%4.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(m_address).
		   arg(m_port));

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
