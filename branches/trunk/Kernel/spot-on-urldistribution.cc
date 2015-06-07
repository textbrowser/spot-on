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
#include <QTimer>

#include "../Common/spot-on-common.h"
#include "../Common/spot-on-crypt.h"
#include "../Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-urldistribution.h"

spoton_urldistribution::spoton_urldistribution(QObject *parent):
  QThread(parent)
{
  m_limit = spoton_common::KERNEL_URLS_BATCH_SIZE;
  m_offset = 0;
  m_quit = false;
}

spoton_urldistribution::~spoton_urldistribution()
{
  quit();
  wait();
}

void spoton_urldistribution::quit(void)
{
  QWriteLocker locker(&m_quitLocker);

  m_quit = true;
  locker.unlock();
  QThread::quit();
}

void spoton_urldistribution::run(void)
{
  QWriteLocker locker(&m_quitLocker);

  m_quit = false;
  locker.unlock();

  QTimer timer;

  connect(&timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  timer.start(30000);
  exec();
}

void spoton_urldistribution::slotTimeout(void)
{
  spoton_crypt *s_crypt1 = spoton_kernel::s_crypts.value("url", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = spoton_kernel::s_crypts.value("url-signature", 0);

  if(!s_crypt2)
    return;

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

	      QReadLocker locker(&m_quitLocker);

	      if(m_quit)
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QReadLocker locker(&m_quitLocker);

    if(m_quit)
      return;
  }

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

	      QReadLocker locker(&m_quitLocker);

	      if(m_quit)
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QReadLocker locker(&m_quitLocker);

    if(m_quit)
      return;
  }

  if(publicKeys.isEmpty())
    return;

  spoton_crypt *urlCommonCredentials =
    spoton_misc::retrieveUrlCommonCredentials(s_crypt1);

  if(!urlCommonCredentials)
    return;

  /*
  ** Next, retrieve at most spoton_common::KERNEL_URLS_BATCH_SIZE URLs.
  */

  QByteArray data;

  {
    QSqlDatabase db;

    connectionName = spoton_misc::databaseName();

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
	db.setHostName(host);
	db.setDatabaseName(database);
	db.setPort(port);

	if(ok)
	  db.open(name, password);
      }

    if(db.isOpen())
      {
	QDataStream stream(&data, QIODevice::WriteOnly);
	QSqlQuery query(db);
	QString querystr("");

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
		  (QString("SELECT url, title, description, "
			   "date_time_inserted "
			   "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	      else
		querystr.append
		  (QString("SELECT url, title, description, "
			   "date_time_inserted "
			   "FROM spot_on_urls_%1%2 UNION ").arg(c1).arg(c2));
	    }

	querystr.append(" ORDER BY 4 DESC ");
	querystr.append(QString(" LIMIT %1 ").arg(m_limit));
	querystr.append(QString(" OFFSET %1 ").arg(m_offset));

	quint64 count = 0;

	if(query.exec(querystr))
	  do
	    {
	      if(!query.next())
		{
		  if(count != m_limit)
		    m_offset = 0;

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
		    stream << myPublicKeyHash;
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
			  if(u2.toEncoded().startsWith(u1.toEncoded()))
			    {
			      ok = true;
			      break;
			    }
			}
		      else
			{
			  if(u2.toEncoded().startsWith(u1.toEncoded()))
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
		stream << bytes.value(0)  // URL
		       << bytes.value(1)  // Title
		       << bytes.value(2); // Description

	      count += 1;
	      m_offset += 1;

	      QReadLocker locker(&m_quitLocker);

	      if(m_quit)
		break;
	    }
	  while(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete urlCommonCredentials;

  if(data.isEmpty())
    return;

  {
    QReadLocker locker(&m_quitLocker);

    if(m_quit)
      return;
  }

  QByteArray cipherType
    (spoton_kernel::setting("gui/kernelCipherType",
			    "aes256").toString().toLatin1());
  QByteArray hashType
    (spoton_kernel::setting("gui/kernelHashType",
			    "sha512").toString().toLatin1());
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
    (cipherType);

  if(symmetricKeyLength <= 0)
    {
      spoton_misc::logError
	("spoton_urldistribution::slotTimeout(): "
	 "cipherKeyLength() failure.");
      return;
    }

  data = qCompress(data, 9);

  for(int i = 0; i < publicKeys.size(); i++)
    {
      QByteArray hashKey;
      QByteArray symmetricKey;

      hashKey.resize(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
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
      bool ok = true;

      stream << QByteArray("0080")
	     << symmetricKey
	     << hashKey
	     << cipherType
	     << hashType;
      keyInformation = spoton_crypt::publicKeyEncrypt
	(keyInformation, publicKeys.at(i), &ok);

      if(ok)
	if(spoton_kernel::setting("gui/urlSignMessages", true).toBool())
	  signature = s_crypt2->digitalSignature(keyInformation + data, &ok);

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
			     QString(""));

	  stream << data
		 << signature;
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

      QReadLocker locker(&m_quitLocker);

      if(m_quit)
	return;
    }
}
