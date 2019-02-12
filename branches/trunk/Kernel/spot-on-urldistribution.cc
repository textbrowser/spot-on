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

#include <QSqlDatabase>
#include <QSqlQuery>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "../Common/spot-on-common.h"
#include "../Common/spot-on-crypt.h"
#include "../Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-urldistribution.h"

spoton_urldistribution::spoton_urldistribution(QObject *parent):QObject(parent)
{
  m_lastUniqueId = -1;
  m_timer.setInterval(1000 * spoton_common::KERNEL_URL_DISPATCHER_INTERVAL);
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
}

spoton_urldistribution::~spoton_urldistribution()
{
  quit();
}

bool spoton_urldistribution::isRunning(void) const
{
  return m_timer.isActive();
}

void spoton_urldistribution::quit(void)
{
  m_timer.stop();
  m_future.cancel();
  m_future.waitForFinished();
}

void spoton_urldistribution::run(void)
{
  spoton_crypt *s_crypt1 = spoton_kernel::s_crypts.value("url", 0);

  if(!s_crypt1)
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "s_crypt1 is zero.");
      return;
    }

  spoton_crypt *s_crypt2 = spoton_kernel::s_crypts.value("url-signature", 0);

  if(!s_crypt2)
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "s_crypt2 is zero.");
      return;
    }

  QString connectionName("");

  /*
  ** Now, retrieve polarizers.
  */

  QList<QPair<QUrl, QString> > polarizers;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT domain, permission FROM distillers WHERE "
		      "direction_hash = ?");
	query.bindValue(0, s_crypt1->keyedHash(QByteArray("upload"),
					       &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray domain;
	      QByteArray permission;
	      bool ok = true;

	      domain = s_crypt1->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(0).
						       toByteArray()),
					    &ok);

	      if(ok)
		permission = s_crypt1->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(1).
							 toByteArray()),
					      &ok);

	      if(ok)
		{
		  QUrl url(QUrl::fromUserInput(domain));

		  if(!url.isEmpty())
		    if(url.isValid())
		      {
			QPair<QUrl, QString> pair;

			pair.first = url;
			pair.second = permission.constData();
			polarizers.append(pair);
		      }
		}

	      if(m_future.isCanceled())
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_future.isCanceled())
    return;

  /*
  ** Let's retrieve the public keys.
  */

  QList<QByteArray> publicKeys;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue
	  (0, s_crypt1->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray publicKey;
	      bool ok = true;

	      publicKey = s_crypt1->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		publicKeys.append(publicKey);

	      if(m_future.isCanceled())
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_future.isCanceled())
    return;

  if(publicKeys.isEmpty())
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "publicKeys is empty.");
      return;
    }

  spoton_crypt *urlCommonCredentials =
    spoton_misc::retrieveUrlCommonCredentials(s_crypt1);

  if(!urlCommonCredentials)
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "urlCommonCredentials is zero.");
      return;
    }

  /*
  ** Next, retrieve some URL(s).
  */

  QByteArray data;

  {
    connectionName = spoton_misc::databaseName();

    QSqlDatabase db;

    if(spoton_kernel::setting("gui/sqliteSearch", true).toBool())
      {
	db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "urls.db");
	db.open();
      }
    else
      {
	QByteArray password;
	QString database
	  (spoton_kernel::setting("gui/postgresql_database", "").
	   toString().trimmed());
	QString host
	  (spoton_kernel::setting("gui/postgresql_host", "localhost").
	   toString().trimmed());
	QString name
	  (spoton_kernel::setting("gui/postgresql_name", "").toString().
	   trimmed());
	QString str("connect_timeout=10");
	bool ok = true;
	bool ssltls = spoton_kernel::setting
	  ("gui/postgresql_ssltls", false).toBool();
	int port = spoton_kernel::setting
	  ("gui/postgresql_port", 5432).toInt();

	password = s_crypt1->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(spoton_kernel::setting("gui/postgresql_password", "").
		      toByteArray()), &ok);

	if(ssltls)
	  str.append(";requiressl=1");

	db = QSqlDatabase::addDatabase("QPSQL", connectionName);
	db.setConnectOptions(str);
	db.setDatabaseName(database);
	db.setHostName(host);
	db.setPort(port);

	if(ok)
	  db.open(name, password);
      }

    if(db.isOpen())
      {
	QDataStream stream(&data, QIODevice::WriteOnly);
	QSqlQuery query(db);
	QString querystr("");
	quint64 limit = static_cast<quint64>
	  (spoton_kernel::setting("gui/kernel_url_batch_size", 5).toInt());

	query.setForwardOnly(true);

	if(db.driverName() == "QPSQL")
	  query.exec
	    (QString("SET SESSION statement_timeout TO %1").
	     arg(spoton_kernel::
		 setting("gui/postgresql_kernel_url_distribution_timeout",
			 45000).toInt()));

	for(int i = 0; i < 10 + 6; i++)
	  for(int j = 0; j < 10 + 6; j++)
	    {
	      QChar c1;
	      QChar c2;

	      if(i <= 9)
		c1 = QChar(i + 48);
	      else
		c1 = QChar(i + 97 - 10);

	      if(j <= 9)
		c2 = QChar(j + 48);
	      else
		c2 = QChar(j + 97 - 10);

	      if(i == 15 && j == 15)
		querystr.append
		  (QString("SELECT url, title, description, content, "
			   "date_time_inserted, unique_id "
			   "FROM spot_on_urls_%1%2 "
			   "WHERE LENGTH(content) <= %3 AND unique_id > %4 ").
		   arg(c1).arg(c2).
		   arg(spoton_common::URL_CONTENT_SHARE_MAXIMUM_SIZE).
		   arg(m_lastUniqueId));
	      else
		querystr.append
		  (QString("SELECT url, title, description, content, "
			   "date_time_inserted, unique_id "
			   "FROM spot_on_urls_%1%2 "
			   "WHERE LENGTH(content) <= %3 AND unique_id > %4 "
			   "UNION ").
		   arg(c1).arg(c2).
		   arg(spoton_common::URL_CONTENT_SHARE_MAXIMUM_SIZE).
		   arg(m_lastUniqueId));
	    }

	querystr.append(" ORDER BY 5 "); // date_time_inserted
	querystr.append(QString(" LIMIT %1 ").arg(limit));

	quint64 count = 0;

	if(query.exec(querystr))
	  do
	    {
	      if(!query.next())
		{
		  if(count != limit)
		    m_lastUniqueId = -1;

		  break;
		}

	      bool ok = true;

	      if(data.isEmpty())
		{
		  QByteArray myPublicKey(s_crypt1->publicKey(&ok));
		  QByteArray myPublicKeyHash;

		  if(ok)
		    myPublicKeyHash = spoton_crypt::sha512Hash
		      (myPublicKey, &ok);

		  if(ok)
		    {
		      stream << myPublicKeyHash;

		      if(stream.status() != QDataStream::Ok)
			{
			  data.clear();
			  ok = false;
			}
		    }
		}

	      QList<QByteArray> bytes;

	      if(ok)
		bytes.append
		  (urlCommonCredentials->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(0).
							  toByteArray()),
					       &ok));

	      if(ok)
		{
		  /*
		  ** Apply polarizers.
		  */

		  ok = false;

		  for(int i = 0; i < polarizers.size(); i++)
		    {
		      QString type(polarizers.at(i).second);
		      QUrl u1(polarizers.at(i).first);
		      QUrl u2(QUrl::fromUserInput(bytes.value(0)));

		      if(type == "accept")
			{
			  if(spoton_misc::urlToEncoded(u2).
			     startsWith(spoton_misc::urlToEncoded(u1)))
			    {
			      ok = true;
			      break;
			    }
			}
		      else
			{
			  if(spoton_misc::urlToEncoded(u2).
			     startsWith(spoton_misc::urlToEncoded(u1)))
			    {
			      ok = false;
			      break;
			    }
			}
		    }
		}

	      if(ok)
		bytes.append
		  (urlCommonCredentials->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(1).
							  toByteArray()),
					       &ok));

	      if(ok)
		bytes.append
		  (urlCommonCredentials->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(2).
							  toByteArray()),
					       &ok));

	      if(ok)
		bytes.append
		  (urlCommonCredentials->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(3).
							  toByteArray()),
					       &ok));

	      if(ok)
		m_lastUniqueId = qMax
		  (m_lastUniqueId, query.value(5).toLongLong());

	      if(ok)
		{
		  stream << bytes.value(0)  // URL
			 << bytes.value(1)  // Title
			 << bytes.value(2)  // Description
			 << bytes.value(3); // Content

		  if(stream.status() != QDataStream::Ok)
		    {
		      data.clear();
		      ok = false;
		    }
		}

	      count += 1;

	      if(m_future.isCanceled())
		break;
	    }
	  while(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete urlCommonCredentials;

  if(data.isEmpty())
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "data is empty.");
      return;
    }

  if(m_future.isCanceled())
    return;

  QByteArray cipherType
    (spoton_kernel::setting("gui/kernelCipherType",
			    "aes256").toString().toLatin1());
  QByteArray hashType
    (spoton_kernel::setting("gui/kernelHashType",
			    "sha512").toString().toLatin1());
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
    (cipherType);

  if(symmetricKeyLength == 0)
    {
      spoton_misc::logError("spoton_urldistribution::run(): "
			    "cipherKeyLength() failure.");
      return;
    }

  data = qCompress(data, 9);

  for(int i = 0; i < publicKeys.size(); i++)
    {
      QByteArray hashKey;
      QByteArray symmetricKey;

      hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
      hashKey = spoton_crypt::strongRandomBytes
	(static_cast<size_t> (hashKey.length()));
      symmetricKey.resize(static_cast<int> (symmetricKeyLength));
      symmetricKey = spoton_crypt::strongRandomBytes
	(static_cast<size_t> (symmetricKey.length()));

      QByteArray keyInformation;
      QByteArray message;
      QByteArray messageCode;
      QByteArray signature;
      QDataStream stream(&keyInformation, QIODevice::WriteOnly);
      QDateTime now(QDateTime::currentDateTime());
      bool ok = true;

      stream << QByteArray("0080")
	     << symmetricKey
	     << hashKey
	     << cipherType
	     << hashType;

      if(stream.status() != QDataStream::Ok)
	ok = false;

      if(ok)
	keyInformation = spoton_crypt::publicKeyEncrypt
	  (keyInformation,
	   qCompress(publicKeys.at(i)),
	   publicKeys.at(i).mid(0, 25),
	   &ok);

      if(ok)
	if(spoton_kernel::setting("gui/urlSignMessages", true).toBool())
	  {
	    QByteArray recipientDigest
	      (spoton_crypt::sha512Hash(publicKeys.at(i), &ok));

	    signature = s_crypt2->digitalSignature
	      (keyInformation +
	       data +
	       now.toUTC().toString("MMddyyyyhhmmss").toLatin1() +
	       recipientDigest,
	       &ok);
	  }

      if(ok)
	{
	  QByteArray bytes;
	  QDataStream stream(&bytes, QIODevice::WriteOnly);
	  spoton_crypt crypt(cipherType,
			     hashType,
			     QByteArray(),
			     symmetricKey,
			     hashKey,
			     0,
			     0,
			     "");

	  stream << data
		 << now.toUTC().toString("MMddyyyyhhmmss").toLatin1()
		 << signature;

	  if(stream.status() != QDataStream::Ok)
	    ok = false;

	  if(ok)
	    message = crypt.encrypted(bytes, &ok);

	  if(ok)
	    messageCode = crypt.keyedHash(keyInformation + message, &ok);
	}

      if(ok)
	message = keyInformation.toBase64() + "\n" +
	  message.toBase64() + "\n" +
	  messageCode.toBase64();

      if(ok)
	emit sendURLs(message);

      if(m_future.isCanceled())
	return;
    }
}

void spoton_urldistribution::slotTimeout(void)
{
  if(1000 * spoton_common::KERNEL_URL_DISPATCHER_INTERVAL != m_timer.interval())
    m_timer.setInterval(1000 * spoton_common::KERNEL_URL_DISPATCHER_INTERVAL);

  if(m_future.isFinished())
    m_future = QtConcurrent::run(this, &spoton_urldistribution::run);
}

void spoton_urldistribution::start(void)
{
  m_timer.setInterval(1000 * spoton_common::KERNEL_URL_DISPATCHER_INTERVAL);
  m_timer.start();
}
