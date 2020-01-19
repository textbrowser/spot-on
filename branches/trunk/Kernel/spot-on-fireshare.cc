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
#include "spot-on-fireshare.h"
#include "spot-on-kernel.h"

spoton_fireshare::spoton_fireshare(QObject *parent):QThread(parent)
{
  m_quit = 0;
}

spoton_fireshare::~spoton_fireshare()
{
  quit();
  wait();
}

void spoton_fireshare::quit(void)
{
  m_quit.fetchAndStoreOrdered(1);
  QThread::quit();
}

void spoton_fireshare::run(void)
{
  m_quit.fetchAndStoreOrdered(0);

  QTimer timer;

  connect(&timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  timer.start(2500);
  exec();
}

void spoton_fireshare::slotShareLink(const QByteArray &link)
{
  QWriteLocker locker(&m_sharedLinksMutex);

  m_sharedLinks.enqueue(link);
}

void spoton_fireshare::slotTimeout(void)
{
  {
    QReadLocker locker(&m_sharedLinksMutex);

    if(m_sharedLinks.isEmpty())
      return;
  }

  spoton_crypt *s_crypt1 = spoton_kernel::s_crypts.value("url", 0);

  if(!s_crypt1)
    {
      spoton_misc::logError("spoton_fireshare::slotTimeout(): "
			    "s_crypt1 is zero.");
      return;
    }

  spoton_crypt *s_crypt2 = spoton_kernel::s_crypts.value("url-signature", 0);

  if(!s_crypt2)
    {
      spoton_misc::logError("spoton_fireshare::slotTimeout(): "
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
			pair.second = permission;
			polarizers.append(pair);
		      }
		}

	      if(m_quit.fetchAndAddOrdered(0))
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_quit.fetchAndAddOrdered(0))
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

	      if(m_quit.fetchAndAddOrdered(0))
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_quit.fetchAndAddOrdered(0))
    return;

  if(publicKeys.isEmpty())
    {
      spoton_misc::logError("spoton_fireshare::slotTimeout(): "
			    "publicKeys is empty.");
      return;
    }

  spoton_crypt *urlCommonCredentials =
    spoton_misc::retrieveUrlCommonCredentials(s_crypt1);

  if(!urlCommonCredentials)
    {
      spoton_misc::logError("spoton_fireshare::slotTimeout(): "
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
	QByteArray name;
	QByteArray password;
	QString database
	  (spoton_kernel::setting("gui/postgresql_database", "").
	   toString().trimmed());
	QString host
	  (spoton_kernel::setting("gui/postgresql_host", "localhost").
	   toString().trimmed());
	QString options
	  (spoton_kernel::setting("gui/postgresql_connection_options",
				  spoton_common::POSTGRESQL_CONNECTION_OPTIONS).
	   toString().trimmed());
	bool ok = true;
	bool ssltls = spoton_kernel::setting
	  ("gui/postgresql_ssltls", true).toBool();
	int port = spoton_kernel::setting("gui/postgresql_port", 5432).toInt();

	if(!options.contains("connect_timeout="))
	  options.append(";connect_timeout=10");

	name = s_crypt1->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(spoton_kernel::setting("gui/postgresql_name", "").
		      toByteArray()), &ok);

	if(ok)
	  password = s_crypt1->decryptedAfterAuthenticated
	    (QByteArray::
	     fromBase64(spoton_kernel::setting("gui/postgresql_password", "").
			toByteArray()), &ok);

	if(ssltls)
	  options.append(";requiressl=1");

	db = QSqlDatabase::addDatabase("QPSQL", connectionName);
	db.setConnectOptions(spoton_misc::adjustPQConnectOptions(options));
	db.setDatabaseName(database);
	db.setHostName(host);
	db.setPort(port);

	if(ok)
	  db.open(name, password);
      }

    if(db.isOpen())
      {
	QDataStream stream(&data, QIODevice::WriteOnly);
	int count = 0;

	while(true)
	  {
	    if(count > spoton_kernel::setting("gui/kernel_url_batch_size",
					      5).toInt())
	      break;

	    QByteArray shareHash;

	    {
	      QWriteLocker locker(&m_sharedLinksMutex);

	      if(!m_sharedLinks.isEmpty())
		{
		  shareHash = m_sharedLinks.dequeue();

		  if(shareHash.startsWith("share-ftp:"))
		    shareHash.remove
		      (0, static_cast<int> (qstrlen("share-ftp:")));
		  else if(shareHash.startsWith("share-gopher:"))
		    shareHash.remove
		      (0, static_cast<int> (qstrlen("share-gopher:")));
		  else if(shareHash.startsWith("share-http:"))
		    shareHash.remove
		      (0, static_cast<int> (qstrlen("share-http:")));
		  else if(shareHash.startsWith("share-https:"))
		    shareHash.remove
		      (0, static_cast<int> (qstrlen("share-https:")));
		}
	      else
		break;
	    }

	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare
	      (QString("SELECT url, title, description, content "
		       "FROM spot_on_urls_%1 "
		       "WHERE url_hash = ?").arg(shareHash.mid(0, 2).
						 constData()));
	    query.bindValue(0, shareHash.constData());

	    if(query.exec())
	      if(query.next())
		{
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
			  if(m_quit.fetchAndAddOrdered(0))
			    break;

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
		}

	    count += 1;

	    if(m_quit.fetchAndAddOrdered(0))
	      break;
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete urlCommonCredentials;

  if(data.isEmpty())
    {
      spoton_misc::logError("spoton_fireshare::slotTimeout(): "
			    "data is empty.");
      return;
    }

  if(m_quit.fetchAndAddOrdered(0))
    return;

  QByteArray cipherType
    (spoton_kernel::setting("gui/kernelCipherType",
			    "aes256").toString().toLatin1());
  QByteArray hashType
    (spoton_kernel::setting("gui/kernelHashType",
			    "sha512").toString().toLatin1());
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength == 0)
    {
      spoton_misc::logError
	("spoton_fireshare::slotTimeout(): cipherKeyLength() failure.");
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

      if(m_quit.fetchAndAddOrdered(0))
	return;
    }
}
