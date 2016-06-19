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

#include <QDateTime>
#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlRecord>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-mailer.h"

QMap<qint64, char> spoton_mailer::s_oids;

spoton_mailer::spoton_mailer(QObject *parent):QObject(parent)
{
  connect(&m_reaperTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotReap(void)));
  connect(&m_retrieveMailTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotRetrieveMailTimeout(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_reaperTimer.start
    (1000 * spoton_common::REAP_POST_OFFICE_LETTERS_INTERVAL);
  m_retrieveMailTimer.setInterval
    (1000 * spoton_common::HARVEST_POST_OFFICE_LETTERS_INTERVAL);
  m_timer.start(1000 * spoton_common::SEND_QUEUED_EMAIL_INTERVAL);
}

spoton_mailer::~spoton_mailer()
{
  m_reaperTimer.stop();
  m_retrieveMailTimer.stop();
  m_timer.stop();
}

void spoton_mailer::slotTimeout(void)
{
  /*
  ** Send mail.
  */

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    {
      spoton_misc::logError("spoton_mailer::slotTimeout(): "
			    "s_crypt is zero.");
      return;
    }

  QByteArray attachmentData;
  QList<QVector<QVariant> > list;
  QString connectionName1("");
  QString connectionName2("");

  {
    QSqlDatabase db1 = spoton_misc::database(connectionName1);
    QSqlDatabase db2 = spoton_misc::database(connectionName2);

    db1.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");
    db2.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db1.open() && db2.open())
      {
	QByteArray name
	  (spoton_kernel::setting("gui/emailName", "unknown").
	   toByteArray());
	QSqlQuery query(db1);

	/*
	** Send one message from the sent folder.
	*/

	query.setForwardOnly(true);

	if(query.exec("SELECT from_account, " // 0
		      "goldbug, "             // 1
		      "message, "             // 2
		      "mode, "                // 3
		      "participant_oid, "     // 4
		      "sign, "                // 5
		      "status, "              // 6
		      "subject, "             // 7
		      "date, "                // 8
		      "OID "                  // 9
		      "FROM folders WHERE folder_index = 1"))
	  while(query.next())
	    {
	      attachmentData.clear();
	      list.clear();

	      qint64 oid = query.value(query.record().count() - 1).
		toLongLong();

	      if(s_oids.contains(oid))
		{
		  s_oids.remove(oid);
		  continue;
		}

	      QString status("");
	      bool ok = true;

	      status = s_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(6).toByteArray()), &ok).
		constData();

	      if(status.toLower() != "queued")
		continue;

	      QByteArray date;
	      QByteArray fromAccount;
	      QByteArray goldbug;
	      QByteArray keyType;
	      QByteArray message;
	      QByteArray mode;
	      QByteArray publicKey;
	      QByteArray receiverName;
	      QByteArray subject;
	      bool sign = query.value(5).toBool();
	      qint64 participantOid = -1;

	      if(ok)
		fromAccount = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

	      if(ok)
		goldbug = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		message = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(3))
		  mode = s_crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(3).toByteArray()),
		     &ok);

	      if(ok)
		participantOid = s_crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok).toLongLong();

	      if(ok)
		{
		  QByteArray publicKeyHash;
		  QSqlQuery query(db2);

		  query.setForwardOnly(true);
		  query.prepare("SELECT key_type, name, public_key FROM "
				"friends_public_keys "
				"WHERE OID = ? AND neighbor_oid = -1");
		  query.bindValue(0, participantOid);

		  if((ok = query.exec()))
		    if((ok = query.next()))
		      {
			keyType = s_crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(0).
						  toByteArray()),
			   &ok);

			if(ok)
			  receiverName = s_crypt->
			    decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(1).
						    toByteArray()),
			     &ok);

			if(ok)
			  publicKey = s_crypt->
			    decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(2).
						    toByteArray()),
			     &ok);
		      }
		}

	      if(ok)
		subject = s_crypt->
		  decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(7).toByteArray()),
		   &ok);

	      if(ok)
		date = s_crypt->
		  decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(8).toByteArray()),
		   &ok);

	      if(ok)
		{
		  QList<QPair<QByteArray, QByteArray> > attachments;
		  QSqlQuery query(db1);

		  query.setForwardOnly(true);
		  query.prepare("SELECT data, name FROM folders_attachment "
				"WHERE folders_oid = ?");
		  query.bindValue(0, oid);

		  if(query.exec())
		    while(query.next())
		      {
			QByteArray attachment;
			QByteArray attachmentName;

			attachment = s_crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(0).
						  toByteArray()),
			   &ok);

			if(ok)
			  attachmentName = s_crypt->
			    decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(1).
						    toByteArray()),
			     &ok);

			if(ok)
			  attachments << QPair<QByteArray, QByteArray>
			    (attachment, attachmentName);
			else
			  break;
		      }

		  if(!attachments.isEmpty())
		    {
		      QDataStream stream
			(&attachmentData, QIODevice::WriteOnly);

		      stream << attachments;

		      if(stream.status() != QDataStream::Ok)
			ok = false;
		    }
		}

	      if(ok)
		{
		  QVector<QVariant> vector;

		  vector << goldbug
			 << message
			 << name
			 << publicKey
			 << subject
			 << attachmentData
			 << keyType
			 << receiverName
			 << mode
			 << fromAccount
			 << date
			 << sign
			 << oid;
		  list.append(vector);
		  s_oids[oid] = 0;
		  break;
		}
	    }
      }

    db1.close();
    db2.close();
  }

  QSqlDatabase::removeDatabase(connectionName1);
  QSqlDatabase::removeDatabase(connectionName2);

  for(int i = 0; i < list.size(); i++)
    {
      QVector<QVariant> vector(list.at(i));

      /*
      ** So many parameters.
      */

      emit sendMail(vector.value(0).toByteArray(),
		    vector.value(1).toByteArray(),
		    vector.value(2).toByteArray(),
		    vector.value(3).toByteArray(),
		    vector.value(4).toByteArray(),
		    vector.value(5).toByteArray(),
		    vector.value(6).toByteArray(),
		    vector.value(7).toByteArray(),
		    vector.value(8).toByteArray(),
		    vector.value(9).toByteArray(),
		    vector.value(10).toByteArray(),
		    vector.value(11).toBool(),
		    vector.value(12).toLongLong());
    }
}

void spoton_mailer::slotRetrieveMail
(const QByteArray &data,
 const QByteArray &publicKeyHash,
 const QByteArray &timestamp,
 const QByteArray &signature,
 const QPairByteArrayByteArray &adaptiveEchoPair)
{
  /*
  ** We must locate the public key that's associated with the provided
  ** public key hash. Remember, publicKeyHash is the hash of the signature
  ** public key.
  */

  QByteArray publicKey
    (spoton_misc::publicKeyFromHash(publicKeyHash,
				    spoton_kernel::s_crypts.value("email",
								  0)));

  if(publicKey.isEmpty())
    {
      spoton_misc::logError("spoton_mailer::slotRetrieveMail(): "
			    "empty public key from hash.");
      return;
    }

  if(!spoton_crypt::isValidSignature(data,
				     publicKey,
				     signature))
    {
      spoton_misc::logError("spoton_mailer::slotRetrieveMail(): "
			    "invalid signature.");
      return;
    }

  publicKey = spoton_misc::publicKeyFromSignaturePublicKeyHash
    (publicKeyHash, spoton_kernel::s_crypts.value("email", 0));

  if(publicKey.isEmpty())
    {
      spoton_misc::logError("spoton_mailer::slotRetrieveMail(): "
			    "empty public key from signature hash.");
      return;
    }

  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    {
      spoton_misc::logError
	("spoton_mailer::slotRetrieveMail(): "
	 "spoton_crypt::sha512Hash() failure.");
      return;
    }

  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      spoton_misc::logError
	("spoton_mailer::slotRetrieveMail(): "
	 "invalid dateTime object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  qint64 secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= static_cast<qint64> (spoton_common::
				      MAIL_TIME_DELTA_MAXIMUM)))
    {
      spoton_misc::logError
	(QString("spoton_mailer::slotRetrieveMail(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }
  else if(spoton_kernel::duplicateEmailRequests(data))
    {
      spoton_misc::logError
	("spoton_mailer::slotRetrieveMail(): duplicate requests.");
      return;
    }

  spoton_kernel::emailRequestCacheAdd(data);

  QList<QByteArray> list;

  list << hash << adaptiveEchoPair.first << adaptiveEchoPair.second;

  if(!m_publicKeyHashesAdaptiveEchoPairs.contains(list))
    m_publicKeyHashesAdaptiveEchoPairs.append(list);

  if(!m_retrieveMailTimer.isActive())
    m_retrieveMailTimer.start();
}

void spoton_mailer::slotRetrieveMailTimeout(void)
{
  if(m_publicKeyHashesAdaptiveEchoPairs.isEmpty())
    {
      m_retrieveMailTimer.stop();
      return;
    }

  /*
  ** We're assuming that only authenticated participants
  ** can request their e-mail. Let's hope our implementation
  ** of digital signatures is correct.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QByteArray publicKeyHash(m_publicKeyHashesAdaptiveEchoPairs.
				 first().value(0));
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT message_bundle, OID FROM post_office "
		      "WHERE recipient_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  {
	    if(query.next())
	      {
		spoton_crypt *s_crypt =
		  spoton_kernel::s_crypts.value("email", 0);

		if(s_crypt)
		  {
		    /*
		    ** Is this a letter?
		    */

		    QByteArray message;
		    bool ok = true;

		    message = s_crypt->
		      decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(0).toByteArray()),
		       &ok);

		    if(ok)
		      {
			QPair<QByteArray, QByteArray> pair;

			pair.first = m_publicKeyHashesAdaptiveEchoPairs.
			  first().value(1);
			pair.second = m_publicKeyHashesAdaptiveEchoPairs.
			  first().value(2);
			emit sendMailFromPostOffice(message, pair);
			
			QSqlQuery deleteQuery(db);

			deleteQuery.exec("PRAGMA secure_delete = ON");
			deleteQuery.prepare("DELETE FROM post_office "
					    "WHERE recipient_hash = ? AND "
					    "OID = ?");
			deleteQuery.bindValue(0, publicKeyHash.toBase64());
			deleteQuery.bindValue(1, query.value(1));
			deleteQuery.exec();
		      }
		  }
	      }
	    else
	      m_publicKeyHashesAdaptiveEchoPairs.takeFirst();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_publicKeyHashesAdaptiveEchoPairs.isEmpty())
    m_retrieveMailTimer.stop();
}

void spoton_mailer::slotReap(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    {
      spoton_misc::logError("spoton_mailer::slotReap(): "
			    "s_crypt is zero.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int days = spoton_kernel::setting
	  ("gui/postofficeDays", 1).toInt();

	query.setForwardOnly(true);

	if(query.exec("SELECT date_received, OID FROM post_office"))
	  while(query.next())
	    {
	      QDateTime dateTime;
	      QDateTime now(QDateTime::currentDateTime());
	      bool ok = true;

	      dateTime = QDateTime::fromString
		(s_crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.value(0).
							toByteArray()),
					     &ok).constData(),
		 Qt::ISODate);

	      if(!ok)
		dateTime = QDateTime();

	      if(dateTime.isNull() || !dateTime.isValid() ||
		 dateTime.daysTo(now) > days)
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.exec("PRAGMA secure_delete = ON");
		  deleteQuery.prepare("DELETE FROM post_office "
				      "WHERE OID = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_mailer::moveSentMailToSentFolder(const QList<qint64> &oids,
					     spoton_crypt *crypt)
{
  bool keep = spoton_kernel::setting("gui/saveCopy", true).toBool();

  if(keep)
    if(!crypt)
      {
	spoton_misc::logError
	  ("spoton_mailer::moveSentMailToSentFolder(): crypt is zero.");
	return;
      }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(keep)
	  query.prepare("UPDATE folders SET status = ? WHERE "
			"OID = ?");
	else
	  {
	    query.exec("PRAGMA secure_delete = ON");
	    query.prepare("DELETE FROM folders WHERE OID = ?");
	  }

	for(int i = 0; i < oids.size(); i++)
	  {
	    bool ok = true;

	    if(keep)
	      {
		query.bindValue
		  (0, crypt->encryptedThenHashed(QByteArray("Sent"),
						 &ok).toBase64());
		query.bindValue(1, oids.at(i));
	      }
	    else
	      query.bindValue(0, oids.at(i));

	    if(ok)
	      if(query.exec())
		{
		  s_oids.remove(oids.at(i));

		  if(!keep)
		    {
		      QSqlQuery query(db);

		      query.exec("PRAGMA secure_delete = ON");
		      query.prepare
			("DELETE FROM folders_attachment WHERE "
			 "folders_oid = ?");
		      query.bindValue(0, oids.at(i));
		      query.exec();
		    }
		}
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
