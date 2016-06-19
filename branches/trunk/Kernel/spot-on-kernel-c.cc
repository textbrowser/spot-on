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
#include <QSqlRecord>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"

bool spoton_kernel::prepareAlmostAnonymousEmail
(const QByteArray &attachmentData,
 const QByteArray &fromAccount,
 const QByteArray &goldbug,
 const QByteArray &keyType,
 const QByteArray &message,
 const QByteArray &name,
 const QByteArray &receiverName,
 const QByteArray &subject,
 const QByteArray &date,
 const qint64 mailOid,
 QByteArray &data)
{
  data.clear();

  spoton_crypt *s_crypt = s_crypts.value(keyType, 0);

  if(!s_crypt)
    return false;

  spoton_crypt *crypt = spoton_misc::cryptFromForwardSecrecyMagnet(goldbug);

  if(!crypt)
    return false;

  QByteArray group1;
  QByteArray group2;
  QDataStream stream(&data, QIODevice::WriteOnly);
  bool ok = true;

  if(attachmentData.isEmpty())
    stream << QByteArray("0001c")
	   << name
	   << subject
	   << message
	   << date
	   << QByteArray();
  else
    stream << QByteArray("0001c")
	   << name
	   << subject
	   << message
	   << date
	   << qCompress(attachmentData, 9);

  if(stream.status() != QDataStream::Ok)
    {
      ok = false;
      goto done_label;
    }

  group1 = crypt->encrypted(data, &ok);

  if(!ok)
    goto done_label;

  group2 = crypt->keyedHash(group1, &ok);

  if(!ok)
    goto done_label;

  data = group1.toBase64() + "\n" + group2.toBase64();

  if(keyType == "poptastic")
    {
      QByteArray message(spoton_send::message0001c(data));

      postPoptasticMessage(receiverName, message, fromAccount, mailOid);
    }

 done_label:
  delete crypt;

  if(!ok)
    data.clear();

  return ok;
}

void spoton_kernel::slotPurgeEphemeralKeys(void)
{
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);

  m_forwardSecrecyKeys.clear();
}

void spoton_kernel::slotPurgeEphemeralKeyPair(const QByteArray &publicKeyHash)
{
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);

  m_forwardSecrecyKeys.remove(publicKeyHash);
}

void spoton_kernel::slotCallParticipantUsingForwardSecrecy
(const QByteArray &keyType, const qint64 oid)
{
  spoton_crypt *s_crypt = s_crypts.value(keyType, 0);

  if(!s_crypt)
    return;

  QByteArray data;
  QString connectionName("");
  QString receiverName("");
  bool ok = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "forward_secrecy_authentication_algorithm, " // 0
		      "forward_secrecy_authentication_key, "       // 1
		      "forward_secrecy_encryption_algorithm, "     // 2
		      "forward_secrecy_encryption_key, "           // 3
		      "gemini, "                                   // 4
		      "gemini_hash_key, "                          // 5
		      "name "                                      // 6
		      "FROM friends_public_keys WHERE "
		      "key_type_hash IN (?, ?) AND neighbor_oid = -1 AND "
		      "OID = ?");
	query.bindValue(0, s_crypt->keyedHash(QByteArray("chat"),
					      &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt->keyedHash(QByteArray("poptastic"),
						&ok).toBase64());

	query.bindValue(2, oid);

	if(ok && query.exec())
	  if(query.next())
	    {
	      QList<QByteArray> list;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QByteArray bytes
		    (s_crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.
							    value(i).
							    toByteArray()),
						 &ok));

		  if(!ok)
		    break;

		  list << bytes;

		  if(i == 6)
		    receiverName = bytes;
		}

	      QByteArray messageCode;
	      QDataStream stream(&data, QIODevice::WriteOnly);
	      QDateTime dateTime(QDateTime::currentDateTime());
	      spoton_crypt crypt(list.value(2).constData(),
				 list.value(0).constData(),
				 QByteArray(),
				 list.value(3),
				 list.value(1),
				 0,
				 0,
				 "");

	      stream << QByteArray("0000d")
		     << list.value(4)
		     << list.value(5)
		     << dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1();

	      if(stream.status() != QDataStream::Ok)
		ok = false;

	      if(ok)
		data = crypt.encrypted(data, &ok);

	      if(ok)
		messageCode = crypt.keyedHash(data, &ok);

	      if(ok)
		{
		  data = data.toBase64();
		  data.append("\n");
		  data.append(messageCode.toBase64());
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(keyType == "poptastic")
	{
	  QByteArray message(spoton_send::message0000d(data));

	  postPoptasticMessage(receiverName, message);
	}
      else
	emit callParticipant(data, "0000d");
    }
}

void spoton_kernel::slotPrepareObjects(void)
{
  spoton_misc::prepareDatabases();
  prepareListeners();
  prepareNeighbors();
  prepareStarbeamReaders();
}
