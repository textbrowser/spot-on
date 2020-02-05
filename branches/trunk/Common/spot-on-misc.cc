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

#include <QtGlobal>

#ifdef Q_OS_FREEBSD
extern "C"
{
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_LINUX)
extern "C"
{
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_OPENBSD)
extern "C"
{
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_WIN)
extern "C"
{
#include <winsock2.h>
}
#endif

#include <QDataStream>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QLocale>
#ifdef Q_OS_WIN
#include <qt_windows.h>
#include <QtNetwork>
#else
#include <QNetworkInterface>
#endif
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QString>
#include <QTcpSocket>
#include <QUrl>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include <limits>
#include <sstream>

#include "spot-on-common.h"
#include "spot-on-crypt.h"
#include "spot-on-misc.h"
#include "spot-on-send.h"

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
extern "C"
{
#include <GeoIP.h>
}
#endif

extern "C"
{
#include <signal.h>
}

static bool lengthGreaterThan(const QString &string1, const QString &string2)
{
  return string1.length() > string2.length();
}

QAtomicInt spoton_misc::s_enableLog = 0;
QReadWriteLock spoton_misc::s_dbMutex;
QReadWriteLock spoton_misc::s_logMutex;
quint64 spoton_misc::s_dbId = 0;

QByteArray spoton_misc::findPublicKeyHashGivenHash
(const QByteArray &randomBytes,
 const QByteArray &hash,
 const QByteArray &hashKey,
 const QByteArray &hashType,
 spoton_crypt *crypt)
{
  /*
  ** Locate the public key's hash of the public key whose
  ** hash is identical to the provided hash.
  */

  if(!crypt)
    {
      logError
	("spoton_misc::findPublicKeyHashGivenHash(): crypt "
	 "is zero.");
      return QByteArray();
    }

  QByteArray publicKeyHash;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT public_key, public_key_hash FROM "
		      "friends_public_keys WHERE "
		      "neighbor_oid = -1"))
	  while(query.next())
	    {
	      QByteArray publicKey;
	      bool ok = true;

	      publicKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		{
		  QByteArray computedHash;

		  computedHash = spoton_crypt::keyedHash
		    (randomBytes + publicKey, hashKey, hashType, &ok);

		  if(ok)
		    if(!computedHash.isEmpty() && !hash.isEmpty() &&
		       spoton_crypt::memcmp(computedHash, hash))
		      {
			publicKeyHash = QByteArray::fromBase64
			  (query.value(1).toByteArray());
			break;
		      }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKeyHash;
}

QByteArray spoton_misc::forwardSecrecyMagnetFromList
(const QList<QByteArray> &list)
{
  QByteArray magnet;

  magnet.append("magnet:?aa=");
  magnet.append(list.value(0));
  magnet.append("&ak=");
  magnet.append(list.value(1));
  magnet.append("&ea=");
  magnet.append(list.value(2));
  magnet.append("&ek=");
  magnet.append(list.value(3));
  magnet.append("&xt=urn:forward-secrecy");
  return magnet;
}

QByteArray spoton_misc::publicKeyFromHash(const QByteArray &publicKeyHash,
					  spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::publicKeyFromHash(): crypt is zero.");
      return QByteArray();
    }

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::publicKeyFromOID(const qint64 oid, spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::publicKeyFromHash(): crypt is zero.");
      return QByteArray();
    }

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::publicKeyFromSignaturePublicKeyHash
(const QByteArray &signaturePublicKeyHash, spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::publicKeyFromSignaturePublicKeyHash(): crypt "
	 "is zero.");
      return QByteArray();
    }

  /*
  ** Gather the public key that's associated with the provided
  ** signature public key hash.
  */

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = (SELECT public_key_hash FROM "
		      "relationships_with_signatures WHERE "
		      "signature_public_key_hash = ?)");
	query.bindValue(0, signaturePublicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::signaturePublicKeyFromPublicKeyHash
(const QByteArray &publicKeyHash, spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::signaturePublicKeyFromPublicKeyHash(): crypt "
	 "is zero.");
      return QByteArray();
    }

  /*
  ** Gather the signature public key that's associated with the
  ** provided public key hash.
  */

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = (SELECT signature_public_key_hash "
		      "FROM "
		      "relationships_with_signatures WHERE "
		      "public_key_hash = ?)");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    publicKey = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return publicKey;
}

QByteArray spoton_misc::urlToEncoded(const QUrl &url)
{
#if QT_VERSION < 0x050000
  QByteArray bytes(url.toEncoded());

  bytes.replace("(", "%28");
  bytes.replace(")", "%29");
  return bytes;
#else
  return url.toEncoded();
#endif
}

QByteArray spoton_misc::xor_arrays(const QByteArray &a, const QByteArray &b)
{
  int length = qMin(a.length(), b.length());

  if(length == 0)
    return QByteArray();

  QByteArray bytes(length, 0);

  for(int i = 0; i < length; i++)
    bytes[i] = static_cast<char> (a[i] ^ b[i]);

  return bytes;
}

QHash<QString, QByteArray> spoton_misc::retrieveEchoShareInformation
(const QString &communityName, spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::retrieveEchoShareInformation(): crypt "
	 "is zero.");
      return QHash<QString, QByteArray> ();
    }

  QHash<QString, QByteArray> hash;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "accept, "
		      "authentication_key, "
		      "cipher_type, "
		      "encryption_key, "
		      "hash_type, "
		      "share "
		      "FROM echo_key_sharing_secrets "
		      "WHERE name_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(communityName.toUtf8(), &ok).toBase64());

	if(ok)
	  if(query.exec() && query.next())
	    for(int i = 0; i < query.record().count(); i++)
	      {
		QByteArray bytes;
		bool ok = true;

		bytes = crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.value(i).
							 toByteArray()),
					      &ok);

		if(ok)
		  hash[query.record().fieldName(i)] = bytes;
		else
		  {
		    hash.clear();
		    break;
		  }
	      }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return hash;
}

QHostAddress spoton_misc::localAddressIPv4(void)
{
  QList<QNetworkInterface> interfaces(QNetworkInterface::allInterfaces());

  for(int i = 0; i < interfaces.size(); i++)
    {
      const QNetworkInterface &interface(interfaces.at(i));

      if(!interface.isValid() || !(interface.flags() & QNetworkInterface::IsUp))
	continue;

      QList<QNetworkAddressEntry> addresses(interface.addressEntries());

      for(int i = 0; i < addresses.size(); i++)
	{
	  const QNetworkAddressEntry &entry(addresses.at(i));

	  if(entry.ip() != QHostAddress::LocalHost &&
	     entry.ip().protocol() == QAbstractSocket::IPv4Protocol)
	    return entry.ip();
	}
    }

  return QHostAddress(QHostAddress::LocalHost);
}

QHostAddress spoton_misc::peerAddressAndPort(
#if defined(Q_OS_WIN)
					     const SOCKET socketDescriptor,
#else
					     const int socketDescriptor,
#endif
					     quint16 *port)
{
  QHostAddress address;
  socklen_t length = 0;
  struct sockaddr_storage peeraddr;

  length = sizeof(peeraddr);

  if(port)
    *port = 0;

  if(getpeername(socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
      if(peeraddr.ss_family == AF_INET)
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      address.setAddress
		(ntohl(sockaddr->sockaddr_in.sin_addr.s_addr));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in.sin_port);
	    }
	}
      else
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      Q_IPV6ADDR temp;

	      memcpy(&temp.c, &sockaddr->sockaddr_in6.sin6_addr.s6_addr,
		     qMin(sizeof(sockaddr->sockaddr_in6.sin6_addr.s6_addr),
			  sizeof(temp.c)));
	      address.setAddress(temp);
	      address.setScopeId
		(QString::number(sockaddr->sockaddr_in6.sin6_scope_id));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in6.sin6_port);
	    }
	}
    }

  return address;
}

QList<QByteArray> spoton_misc::findEchoKeys(const QByteArray &bytes1,
					    const QByteArray &bytes2,
					    QString &type,
					    spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::findEchoKeys(): crypt "
	 "is zero.");
      return QList<QByteArray> ();
    }

  /*
  ** bytes1: encrypted portion.
  ** bytes2: digest portion.
  */

  QList<QByteArray> echoKeys;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "accept, "              // 0
		      "authentication_key, "  // 1
		      "cipher_type, "         // 2
		      "encryption_key, "      // 3
		      "hash_type, "           // 4
		      "signatures_required "  // 5
		      "FROM echo_key_sharing_secrets");

	if(query.exec())
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      bool ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QByteArray bytes;

		  bytes = crypt->
		    decryptedAfterAuthenticated(QByteArray::
						fromBase64(query.value(i).
							   toByteArray()),
						&ok);

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(!ok)
		continue;
	      else if(list.value(0) != "true")
		continue;

	      {
		QByteArray computedHash;
		spoton_crypt crypt(list.value(2).constData(),
				   list.value(4).constData(),
				   QByteArray(),
				   list.value(3),
				   list.value(1),
				   0,
				   0,
				   "");

		computedHash = crypt.keyedHash(bytes1, &ok);

		if(ok)
		  if(!computedHash.isEmpty() && !bytes2.isEmpty() &&
		     spoton_crypt::memcmp(bytes2, computedHash))
		    {
		      QByteArray data(crypt.decrypted(bytes1, &ok));

		      if(!ok)
			break;

		      QByteArray a;
		      QDataStream stream(&data, QIODevice::ReadOnly);

		      stream >> a;

		      if(stream.status() == QDataStream::Ok)
			{
			  echoKeys << list.value(3)
				   << list.value(2)
				   << list.value(1)
				   << list.value(4)
				   << list.value(5);
			  type = a;
			}

		      break;
		    }
	      }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return echoKeys;
}

QList<QByteArray> spoton_misc::findForwardSecrecyKeys(const QByteArray &bytes1,
						      const QByteArray &bytes2,
						      QString &messageType,
						      spoton_crypt *crypt)
{
  messageType.clear();

  if(!crypt)
    {
      logError
	("spoton_misc::findForwardSecrecyKeys(): crypt "
	 "is zero.");
      return QList<QByteArray> ();
    }

  /*
  ** bytes1: encrypted portion.
  ** bytes2: digest portion.
  */

  QList<QByteArray> forwardSecrecyKeys;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "forward_secrecy_authentication_algorithm, " // 0
		      "forward_secrecy_authentication_key, "       // 1
		      "forward_secrecy_encryption_algorithm, "     // 2
		      "forward_secrecy_encryption_key, "           // 3
		      "public_key_hash "                           // 4
		      "FROM friends_public_keys WHERE "
		      "forward_secrecy_authentication_algorithm IS NOT NULL "
		      "AND "
		      "forward_secrecy_authentication_key IS NOT NULL AND "
		      "forward_secrecy_encryption_algorithm IS NOT NULL AND "
		      "forward_secrecy_encryption_key IS NOT NULL AND "
		      "neighbor_oid = -1");

	if(ok && query.exec())
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      bool ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  bytes = crypt->
		    decryptedAfterAuthenticated(QByteArray::
						fromBase64(query.value(i).
							   toByteArray()),
						&ok);

		  if(ok)
		    list << bytes;
		  else
		    break;
		}

	      if(!ok)
		continue;

	      {
		QByteArray computedHash;
		spoton_crypt crypt(list.value(2).constData(),
				   list.value(0).constData(),
				   QByteArray(),
				   list.value(3),
				   list.value(1),
				   0,
				   0,
				   "");

		computedHash = crypt.keyedHash(bytes1, &ok);

		if(ok)
		  if(!computedHash.isEmpty() && !bytes2.isEmpty() &&
		     spoton_crypt::memcmp(bytes2, computedHash))
		    {
		      QByteArray data(crypt.decrypted(bytes1, &ok));

		      if(!ok)
			break;

		      QByteArray a;
		      QDataStream stream(&data, QIODevice::ReadOnly);

		      stream >> a; // Message Type

		      if(stream.status() == QDataStream::Ok)
			{
			  messageType = a;

			  /*
			  ** symmetricKeys[0]: Encryption Key
			  ** symmetricKeys[1]: Encryption Type
			  ** symmetricKeys[2]: Hash Key
			  ** symmetricKeys[3]: Hash Type
			  ** symmetricKeys[4]: public_key_hash
			  */

			  forwardSecrecyKeys << list.value(3)
					     << list.value(2)
					     << list.value(1)
					     << list.value(0)
					     << QByteArray::
			                        fromBase64(query.value(4).
							   toByteArray());
			}

		      break;
		    }
	      }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return forwardSecrecyKeys;
}

QList<QHash<QString, QVariant> > spoton_misc::poptasticSettings
(const QString &in_username, spoton_crypt *crypt, bool *ok)
{
  if(!crypt)
    {
      if(ok)
	*ok = false;

      logError
	("spoton_misc::poptasticSettings(): crypt is zero.");
      return QList<QHash<QString, QVariant> > ();
    }

  QMap<QString, QHash<QString, QVariant> > map;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(in_username.trimmed().isEmpty())
	  query.prepare("SELECT * FROM poptastic");
	else
	  {
	    query.prepare
	      ("SELECT * FROM poptastic WHERE in_username_hash = ?");
	    query.bindValue(0, crypt->keyedHash(in_username.
						trimmed().toLatin1(),
						ok).toBase64());
	  }

	if(query.exec())
	  {
	    while(query.next())
	      {
		QHash<QString, QVariant> hash;
		QSqlRecord record(query.record());

		for(int i = 0; i < record.count(); i++)
		  {
		    if(record.fieldName(i) == "proxy_enabled" ||
		       record.fieldName(i) == "proxy_password" ||
		       record.fieldName(i) == "proxy_server_address" ||
		       record.fieldName(i) == "proxy_server_port" ||
		       record.fieldName(i) == "proxy_username" ||
		       record.fieldName(i).endsWith("_localname") ||
		       record.fieldName(i).endsWith("_method") ||
		       record.fieldName(i).endsWith("_password") ||
		       record.fieldName(i).endsWith("_server_address") ||
		       record.fieldName(i).endsWith("_server_port") ||
		       record.fieldName(i).endsWith("_ssltls") ||
		       record.fieldName(i).endsWith("_username") ||
		       record.fieldName(i).endsWith("_verify_host") ||
		       record.fieldName(i).endsWith("_verify_peer"))
		      {
			QByteArray bytes
			  (QByteArray::fromBase64(record.value(i).
						  toByteArray()));
			bool ok = true;

			bytes = crypt->decryptedAfterAuthenticated(bytes, &ok);

			if(ok)
			  hash.insert(record.fieldName(i), bytes);
			else
			  break;
		      }
		    else
		      hash.insert(record.fieldName(i), record.value(i));
		  }

		if(hash.size() != record.count())
		  {
		    if(ok)
		      *ok = false;
		  }
		else
		  {
		    map.insert(hash.value("in_username").toString(), hash);

		    if(ok)
		      *ok = true;
		  }
	      }
	  }
	else if(ok)
	  *ok = false;
      }
    else if(ok)
      *ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return map.values();
}

QPair<QByteArray, QByteArray> spoton_misc::decryptedAdaptiveEchoPair
(const QPair<QByteArray, QByteArray> &pair, spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::decryptedAdaptiveEchoPair(): crypt "
	 "is zero.");
      return QPair<QByteArray, QByteArray> ();
    }

  QByteArray t1(pair.first);
  QByteArray t2(pair.second);
  bool ok = true;

  t1 = crypt->decryptedAfterAuthenticated(t1, &ok);

  if(ok)
    t2 = crypt->decryptedAfterAuthenticated(t2, &ok);

  if(ok)
    return QPair<QByteArray, QByteArray> (t1, t2);
  else
    return QPair<QByteArray, QByteArray> ();
}

QPair<QByteArray, QByteArray> spoton_misc::findGeminiInCosmos
(const QByteArray &data, const QByteArray &hash, spoton_crypt *crypt)
{
  QPair<QByteArray, QByteArray> gemini;

  if(crypt && !hash.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName
	  (homePath() + QDir::separator() + "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare("SELECT gemini, gemini_hash_key "
			  "FROM friends_public_keys WHERE "
			  "gemini IS NOT NULL AND "
			  "gemini_hash_key IS NOT NULL AND "
			  "key_type_hash IN (?, ?) AND "
			  "neighbor_oid = -1");
	    query.bindValue(0, crypt->keyedHash(QByteArray("chat"), &ok).
			    toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->keyedHash(QByteArray("poptastic"), &ok).
		 toBase64());

	    if(ok && query.exec())
	      while(query.next())
		{
		  bool ok = true;

		  gemini.first = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).
					    toByteArray()),
		     &ok);

		  if(ok)
		    gemini.second = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).
					      toByteArray()),
		       &ok);

		  if(ok)
		    if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
		      {
			QByteArray computedHash
			  (spoton_crypt::keyedHash(data, gemini.second,
						   "sha512", &ok));

			if(ok)
			  if(!computedHash.isEmpty() && !hash.isEmpty() &&
			     spoton_crypt::memcmp(computedHash, hash))
			    break; // We have something!
		      }

		  gemini.first.clear();
		  gemini.second.clear();
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  return gemini;
}

QString spoton_misc::adjustPQConnectOptions(const QString &s)
{
  QString str(s.trimmed());

  while(str.indexOf(";;") > 0)
    str.replace(";;", ";");

  if(str.endsWith(";"))
    str = str.mid(0, str.length() - 1);

  if(str.startsWith(";"))
    str = str.mid(1);

  if(str == ";")
    return "";
  else
    return str;
}

QString spoton_misc::countryCodeFromIPAddress(const QString &ipAddress)
{
  const char *code = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  QHostAddress address(ipAddress);
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      QSettings settings;

      fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      QSettings settings;

      fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();
    }
  else
    return QString("Unknown");

  GeoIP *gi = 0;
  QFileInfo fileInfo;

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    {
      gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

      if(gi)
	code = GeoIP_country_code_by_addr
	  (gi, ipAddress.toLatin1().constData());
      else
	logError("spoton_misc::countryCodeFromIPAddress(): gi is zero.");
    }

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!code || qstrnlen(code, 2) == 0)
    return QString("Unknown");
  else
    return QString(code);
}

QString spoton_misc::countryNameFromIPAddress(const QString &ipAddress)
{
  const char *country = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  QHostAddress address(ipAddress);
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      QSettings settings;

      fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      QSettings settings;

      fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();
    }
  else
    return QString("Unknown");

  GeoIP *gi = 0;
  QFileInfo fileInfo;

  fileInfo.setFile(fileName);

  if(fileInfo.isReadable())
    {
      gi = GeoIP_open(fileName.toUtf8().constData(), GEOIP_MEMORY_CACHE);

      if(gi)
	country = GeoIP_country_name_by_addr
	  (gi, ipAddress.toLatin1().constData());
      else
	logError("spoton_misc::countryNameFromIPAddress(): gi is zero.");
    }

  GeoIP_delete(gi);
#else
  Q_UNUSED(ipAddress);
#endif

  if(!country || qstrnlen(country, 256) == 0)
    return QString("Unknown");
  else
    return QString(country);
}

QSqlDatabase spoton_misc::database(QString &connectionName)
{
  QSqlDatabase db;
  quint64 dbId = 0;

  QWriteLocker locker(&s_dbMutex);

  dbId = s_dbId += 1;
  locker.unlock();
  db = QSqlDatabase::addDatabase
    ("QSQLITE", QString("spoton_database_%1_%2").arg(qrand()).arg(dbId));
  connectionName = db.connectionName();
  return db;
}

QString spoton_misc::databaseName(void)
{
  quint64 dbId = 0;

  QWriteLocker locker(&s_dbMutex);

  dbId = s_dbId += 1;
  locker.unlock();
  return QString("spoton_database_%1_%2").arg(qrand()).arg(dbId);
}

QString spoton_misc::homePath(void)
{
  QByteArray homepath(qgetenv("SPOTON_HOME"));

  if(homepath.isEmpty())
#if defined(Q_OS_WIN)
    return QDir::currentPath() + QDir::separator() + ".spot-on";
#else
    return QDir::homePath() + QDir::separator() + ".spot-on";
#endif
  else
    return homepath.mid(0, spoton_common::SPOTON_HOME_MAXIMUM_PATH_LENGTH);
}

QString spoton_misc::htmlEncode(const QString &string)
{
  QString str("");

  for(int i = 0; i < string.size(); i++)
    if(string.at(i) == '%')
      str.append("&amp;");
    else if(string.at(i) == '<')
      str.append("&lt;");
    else if(string.at(i) == '>')
      str.append("&gt;");
    else if(string.at(i) == '\"')
      str.append("&quot;");
    else if(string.at(i) == '\'')
      str.append("&apos;");
    else
      str.append(string.at(i));

  return str;
}

QString spoton_misc::keyTypeFromPublicKeyHash(const QByteArray &publicKeyHash,
					      spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::keyTypeFromPublicKeyHash(): crypt "
	 "is zero.");
      return "";
    }

  QString connectionName("");
  QString keyType("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT key_type FROM friends_public_keys "
		      "WHERE public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    keyType = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	if(!ok)
	  keyType.clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return keyType;
}

QString spoton_misc::massageIpForUi(const QString &ip, const QString &protocol)
{
  QString iipp(ip);

  if(protocol == "IPv4")
    {
      QStringList digits;
      QStringList list;

      list = iipp.split(".", QString::KeepEmptyParts);

      for(int i = 0; i < list.size(); i++)
	digits.append(list.at(i));

      iipp.clear();
      iipp = QString::number(digits.value(0).toInt()) + "." +
	QString::number(digits.value(1).toInt()) + "." +
	QString::number(digits.value(2).toInt()) + "." +
	QString::number(digits.value(3).toInt());
      iipp.remove("...");
    }

  return iipp;
}

QString spoton_misc::nameFromPublicKeyHash(const QByteArray &publicKeyHash,
					   spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::nameFromPublicKeyHash(): crypt "
	 "is zero.");
      return "unknown";
    }

  QString connectionName("");
  QString name("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT name FROM friends_public_keys "
		      "WHERE public_key_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  if(query.next())
	    {
	      QByteArray bytes
		(crypt->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.
							value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		name = QString::fromUtf8(bytes.constData(), bytes.length());
	    }

	if(!ok)
	  name.clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return name;
}

QString spoton_misc::percentEncoding(const QString &string)
{
  QString str("");

  for(int i = 0; i < string.length(); i++)
    if(string.at(i) == '%')
      {
	QByteArray hex(string.mid(i + 1, 2).toLatin1());
	int d = 0;
	std::stringstream stream;

	stream << std::hex << hex.constData();
	stream >> d;
	str.append("&#");
	str.append(d < 10 ? QString("0%1").arg(d) : QString::number(d));
	str.append(';');
	i += 2;
      }
    else
      str.append(string[i]);

  return str;
}

QString spoton_misc::prettyFileSize(const qint64 size)
{
  if(size < 0)
    return QObject::tr("0 Bytes");

  if(size == 0)
    return QObject::tr("0 Bytes");
  else if(size == 1)
    return QObject::tr("1 Byte");
  else if(size < 1024)
    return QString(QObject::tr("%1 Bytes")).arg(size);
  else if(size < 1048576)
    return QString(QObject::tr("%1 KiB")).arg
      (QString::number(qRound(static_cast<double> (size) / 1024.0)));
  else
    return QString(QObject::tr("%1 MiB")).arg
      (QString::number(static_cast<double> (size) / 1048576.0, 'f', 1));
}

QString spoton_misc::removeSpecialHtmlTags(const QString &text)
{
  /*
  ** We cannot trust the source.
  */

  return QString(text).remove(QRegExp("<[^>]*>"));
}

bool spoton_misc::acceptableTimeSeconds(const QDateTime &then, const int delta)
{
  if(!then.isValid())
    return false;

  QDateTime now(QDateTime::currentDateTimeUtc());

  now.setTimeSpec(Qt::UTC);
  return qAbs(now.secsTo(then)) <= static_cast<qint64> (delta);
}

bool spoton_misc::allParticipantsHaveGeminis(void)
{
  QString connectionName("");
  qint64 count = -1;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM friends_public_keys WHERE "
		      "gemini IS NULL AND gemini_hash_key IS NULL AND "
		      "neighbor_oid = -1"))
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count == 0;
}

bool spoton_misc::authenticateAccount(QByteArray &name,
				      QByteArray &password,
				      const qint64 listenerOid,
				      const QByteArray &hash,
				      const QByteArray &salt,
				      spoton_crypt *crypt)
{
  if(!crypt || salt.length() < spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE)
    {
      if(!crypt)
	logError
	  ("spoton_misc::authenticateAccount(): crypt "
	   "is zero.");
      else
	logError
	  ("spoton_misc::authenticateAccount(): salt is peculiar.");

      name.clear();
      password.clear();
      return false;
    }

  QString connectionName("");
  bool found = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool exists = true;

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 FROM "
		      "listeners_accounts_consumed_authentications "
		      "WHERE data = ? AND listener_oid = ?)");
	query.bindValue(0, hash.toBase64());
	query.bindValue(1, listenerOid);

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toBool();

	if(!exists)
	  {
	    QByteArray newHash;
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT account_name, account_password "
			  "FROM listeners_accounts WHERE "
			  "listener_oid = ?");
	    query.bindValue(0, listenerOid);

	    if(query.exec())
	      while(query.next())
		{
		  bool ok = true;

		  name = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).toByteArray()),
		     &ok);

		  if(ok)
		    password = crypt->decryptedAfterAuthenticated
		      (QByteArray::fromBase64(query.value(1).toByteArray()),
		       &ok);

		  if(ok)
		    newHash = spoton_crypt::keyedHash
		      (QDateTime::currentDateTime().toUTC().
		       toString("MMddyyyyhhmm").
		       toLatin1() + salt, name + password, "sha512", &ok);

		  if(ok)
		    if(!hash.isEmpty() && !newHash.isEmpty() &&
		       spoton_crypt::memcmp(hash, newHash))
		      {
			found = true;
			break;
		      }

		  if(ok)
		    newHash = spoton_crypt::keyedHash
		      (QDateTime::currentDateTime().toUTC().addSecs(60).
		       toString("MMddyyyyhhmm").
		       toLatin1() + salt, name + password, "sha512", &ok);

		  if(ok)
		    if(!hash.isEmpty() && !newHash.isEmpty() &&
		       spoton_crypt::memcmp(hash, newHash))
		      {
			found = true;
			break;
		      }
		}

	    if(found)
	      {
		/*
		** Record the authentication data.
		*/

		QSqlQuery query(db);
		bool ok = true;

		query.exec("PRAGMA secure_delete = ON");
		query.prepare("DELETE FROM listeners_accounts "
			      "WHERE account_name_hash = ? AND "
			      "listener_oid = ? AND one_time_account = 1");
		query.bindValue
		  (0, crypt->keyedHash(name, &ok).toBase64());
		query.bindValue(1, listenerOid);

		if(ok)
		  query.exec();

		/*
		** I think we only wish to create an entry in
		** listeners_accounts_consumed_authentications if
		** the discovered account is not temporary.
		*/

		if(!ok || query.numRowsAffected() <= 0)
		  {
		    query.prepare
		      ("INSERT OR REPLACE INTO "
		       "listeners_accounts_consumed_authentications "
		       "(data, insert_date, listener_oid) "
		       "VALUES (?, ?, ?)");
		    query.bindValue(0, hash.toBase64());
		    query.bindValue
		      (1, QDateTime::currentDateTime().toString(Qt::ISODate));
		    query.bindValue(2, listenerOid);
		    query.exec();
		  }
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!found)
    {
      name.clear();
      password.clear();
    }

  return found;
}

bool spoton_misc::importUrl(const QByteArray &c, // Content
			    const QByteArray &d, // Description
			    const QByteArray &t, // Title
			    const QByteArray &u, // URL
			    const QSqlDatabase &db,
			    const int maximum_keywords,
			    const bool disable_synchronous_sqlite_writes,
			    QAtomicInt &atomic,
			    QString &error,
			    spoton_crypt *crypt)
{
  if(c.trimmed().isEmpty())
    {
      error = "spoton_misc::importUrl(): empty content.";
      logError(error);
      return false;
    }

  if(!crypt)
    {
      error = "spoton_misc::importUrl(): crypt is zero.";
      logError(error);
      return false;
    }

  if(!db.isOpen())
    {
      error = "spoton_misc::importUrl(): db is closed.";
      logError(error);
      return false;
    }

  QUrl url(QUrl::fromUserInput(u.trimmed()));

  if(url.isEmpty() || !url.isValid())
    {
      error = "spoton_misc::importUrl(): empty or invalid URL.";
      logError(error);
      return false;
    }

  QString scheme(url.scheme().toLower().trimmed());

  if(!spoton_common::ACCEPTABLE_URL_SCHEMES.contains(scheme))
    {
      if(!scheme.isEmpty())
	error = QString("spoton_misc::importUrl(): the URL scheme %1 "
			"is not acceptable.").arg(scheme);
      else
	error = "spoton_misc::importUrl(): invalid URL scheme.";

      logError(error);
      return false;
    }

  url.setScheme(scheme);

  QByteArray all_keywords;
  QByteArray content(qCompress(c.trimmed(), 9));
  QByteArray description(d.trimmed());
  QByteArray title(t.trimmed());
  bool separate = true;

  if(!description.isEmpty())
    all_keywords = description;

  if(!title.isEmpty())
    all_keywords.append(" ").append(title);
  else if(title.isEmpty())
    title = urlToEncoded(url);

  all_keywords.append(" ").append(url.toString().toUtf8());

  QByteArray urlHash;
  bool ok = true;

  urlHash = crypt->keyedHash(urlToEncoded(url), &ok).toHex();

  if(!ok)
    {
      error = "spoton_misc::importUrl(): keyedHash() failure.";
      logError(error);
      return ok;
    }

  QSqlQuery query(db);

  if(db.driverName() == "QSQLITE")
    query.exec("PRAGMA journal_mode = WAL");

  query.setForwardOnly(true);
  query.prepare(QString("SELECT content FROM spot_on_urls_%1 WHERE "
			"url_hash = ?").
		arg(urlHash.mid(0, 2).constData()));
  query.bindValue(0, urlHash.constData());

  if(query.exec())
    {
      /*
      ** We will delegate the correctness of the content
      ** to the reader process.
      */

      if(query.next())
	if(!query.value(0).toByteArray().isEmpty())
	  {
	    QByteArray previous(query.value(0).toByteArray());

	    /*
	    ** Update the current content.
	    */

	    query.prepare(QString("UPDATE spot_on_urls_%1 "
				  "SET content = ? "
				  "WHERE url_hash = ?").
			  arg(urlHash.mid(0, 2).constData()));
	    query.bindValue
	      (0, crypt->encryptedThenHashed(content, &ok).toBase64());
	    query.bindValue(1, urlHash.constData());

	    if(ok)
	      ok = query.exec();

	    if(!ok)
	      {
		error = QString("spoton_misc::importUrl(): a failure occurred "
				"while attempting to update the URL content. "
				"The URL is %1.").
		  arg(urlToEncoded(url).constData());
		logError(error);
		return ok;
	      }

	    /*
	    ** Create a new revision using the previous content if the
	    ** content has not changed.
	    */

	    QByteArray original(QByteArray::fromBase64(previous));

	    original = crypt->decryptedAfterAuthenticated(original, &ok);
	    original = qUncompress(original);

	    QByteArray hash1;
	    QByteArray hash2;

	    if(ok)
	      hash1 = crypt->keyedHash(c.trimmed(), &ok);

	    if(ok)
	      hash2 = crypt->keyedHash(original, &ok);

	    /*
	    ** Ignore digest errors.
	    */

	    if(!hash1.isEmpty() && !hash2.isEmpty())
	      if(spoton_crypt::memcmp(hash1, hash2))
		return true;

	    ok = true;

	    if(db.driverName() == "QPSQL")
	      {
		query.prepare
		  (QString("INSERT INTO spot_on_urls_revisions_%1 ("
			   "content, "
			   "content_hash, "
			   "date_time_inserted, "
			   "url_hash) "
			   "VALUES (?, ?, "
			   "(SELECT TO_CHAR(NOW(), 'yyyy-mm-ddThh24:mi:ss')), "
			   "?)").
		   arg(urlHash.mid(0, 2).constData()));
		query.bindValue(0, previous);

		if(ok)
		  query.bindValue
		    (1, crypt->keyedHash(original, &ok).toBase64());

		query.bindValue(2, urlHash.constData());
	      }
	    else
	      {
		query.prepare
		  (QString("INSERT INTO spot_on_urls_revisions_%1 ("
			   "content, "
			   "content_hash, "
			   "date_time_inserted, "
			   "url_hash) "
			   "VALUES (?, ?, ?, ?)").
		   arg(urlHash.mid(0, 2).constData()));
		query.bindValue(0, previous);

		if(ok)
		  query.bindValue
		    (1, crypt->keyedHash(original, &ok).toBase64());

		query.bindValue
		  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(3, urlHash.constData());
	      }

	    if(ok)
	      if(!query.exec())
		if(!query.lastError().text().toLower().contains("unique"))
		  ok = false;

	    if(!ok)
	      {
		error =
		  QString("spoton_misc::importUrl(): an error occurred while "
			  "attempting to create a URL revision. "
			  "The URL is %1.").
		  arg(urlToEncoded(url).constData());
		logError(error);
	      }

	    return ok;
	  }
    }
  else
    {
      ok = false;
      error = QString("spoton_misc::importUrl(): "
		      "%1.").arg(query.lastError().text());
      logError(error);
      return ok;
    }

  if(!ok)
    return ok;

  if(db.driverName() == "QPSQL")
    {
      query.prepare
	(QString("INSERT INTO spot_on_urls_%1 ("
		 "content, "
		 "date_time_inserted, "
		 "description, "
		 "title, "
		 "unique_id, "
		 "url, "
		 "url_hash) VALUES (?, "
		 "(SELECT TO_CHAR(now(), 'yyyy-mm-ddThh24:mi:ss')), "
		 "?, ?, nextval('serial'), "
		 "?, ?)").
	 arg(urlHash.mid(0, 2).constData()));
      query.bindValue(0, crypt->encryptedThenHashed(content, &ok).toBase64());

      if(ok)
	query.bindValue
	  (1, crypt->encryptedThenHashed(description, &ok).
	   toBase64());

      if(ok)
	query.bindValue
	  (2, crypt->encryptedThenHashed(title, &ok).toBase64());

      if(ok)
	query.bindValue
	  (3, crypt->encryptedThenHashed(urlToEncoded(url), &ok).
	   toBase64());

      query.bindValue(4, urlHash.constData());
    }
  else
    {
      qint64 id = -1;

      if(query.exec("INSERT INTO sequence VALUES (NULL)"))
	{
	  QVariant variant(query.lastInsertId());

	  if(variant.isValid())
	    {
	      id = variant.toLongLong();
	      query.exec
		(QString("DELETE FROM sequence WHERE value < %1").arg(id));
	    }
	  else
	    {
	      ok = false;
	      error = "spoton_misc::importUrl(): invalid variant.";
	      logError(error);
	    }
	}
      else
	{
	  ok = false;
	  error = QString("spoton_misc::importUrl(): "
			  "%1.").arg(query.lastError().text());
	  logError(error);
	}

      if(disable_synchronous_sqlite_writes)
	query.exec("PRAGMA synchronous = NORMAL");
      else
	query.exec("PRAGMA synchronous = NORMAL");

      query.prepare
	(QString("INSERT INTO spot_on_urls_%1 ("
		 "content, "
		 "date_time_inserted, "
		 "description, "
		 "title, "
		 "unique_id, "
		 "url, "
		 "url_hash) VALUES (?, ?, ?, ?, ?, ?, ?)").
	 arg(urlHash.mid(0, 2).constData()));

      if(ok)
	query.bindValue
	  (0, crypt->encryptedThenHashed(content, &ok).toBase64());

      query.bindValue(1, QDateTime::currentDateTime().toString(Qt::ISODate));

      if(ok)
	query.bindValue
	  (2, crypt->encryptedThenHashed(description, &ok).
	   toBase64());

      if(ok)
	query.bindValue
	  (3, crypt->encryptedThenHashed(title, &ok).toBase64());

      if(id != -1)
	query.bindValue(4, id);

      if(ok)
	query.bindValue
	  (5, crypt->encryptedThenHashed(urlToEncoded(url), &ok).
	   toBase64());

      query.bindValue(6, urlHash.constData());
    }

  /*
  ** If a unique-constraint violation was raised, ignore it.
  */

  if(ok)
    if(!query.exec())
      if(!query.lastError().text().toLower().contains("unique"))
	{
	  ok = false;
	  error = QString("spoton_misc::importUrl(): "
			  "%1.").arg(query.lastError().text());
	  logError(error);
	}

  if(ok)
    if(all_keywords.isEmpty())
      separate = false;

  if(ok && separate)
    {
      QHash<QString, char> discovered;
      QSqlQuery query(db);
      QStringList keywords
	(QString::fromUtf8(all_keywords.toLower().constData(),
			   all_keywords.length()).
	 split(QRegExp("\\W+"), QString::SkipEmptyParts));
      int count = 0;

      std::sort(keywords.begin(), keywords.end(), lengthGreaterThan);

      if(db.driverName() == "QSQLITE")
	{
	  if(disable_synchronous_sqlite_writes)
	    query.exec("PRAGMA synchronous = NORMAL");
	  else
	    query.exec("PRAGMA synchronous = NORMAL");
	}

      for(int i = 0; i < keywords.size(); i++)
	{
	  if(atomic.fetchAndAddOrdered(0))
	    break;

	  if(!discovered.contains(keywords.at(i)))
	    discovered[keywords.at(i)] = '0';
	  else
	    continue;

	  QByteArray keywordHash;
	  bool ok = true;

	  keywordHash = crypt->keyedHash(keywords.at(i).toUtf8(), &ok).toHex();

	  if(!ok)
	    continue;

	  query.prepare
	    (QString("INSERT INTO spot_on_keywords_%1 ("
		     "keyword_hash, "
		     "url_hash) "
		     "VALUES (?, ?)").arg(keywordHash.mid(0, 2).constData()));
	  query.bindValue(0, keywordHash.constData());
	  query.bindValue(1, urlHash.constData());

	  if(query.exec())
	    count += 1;
	  else
	    {
	      error = QString("spoton_misc::importUrl(): "
			      "%1.").arg(query.lastError().text());
	      logError(error);
	    }

	  if(count >= maximum_keywords)
	    break;
	}
    }

  return ok;
}

bool spoton_misc::isAcceptedIP(const QHostAddress &address,
			       const qint64 id,
			       spoton_crypt *crypt)
{
  if(address.isNull())
    {
      logError
	("spoton_misc::isAcceptedIP(): address is empty.");
      return false;
    }
  else
    return isAcceptedIP(address.toString(), id, crypt);
}

bool spoton_misc::isAcceptedIP(const QString &address,
			       const qint64 id,
			       spoton_crypt *crypt)
{
  if(address.isEmpty())
    {
      logError
	("spoton_misc::isAcceptedIP(): address is empty.");
      return false;
    }
  else if(!crypt)
    {
      logError
	("spoton_misc::isAcceptedIP(): crypt "
	 "is zero.");
      return false;
    }

  QString connectionName("");
  bool exists = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 FROM listeners_allowed_ips "
		      "WHERE ip_address_hash IN (?, ?) AND "
		      "listener_oid = ?)");
	query.bindValue
	  (0, crypt->keyedHash(address.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash("Any", &ok).toBase64());

	query.bindValue(2, id);

	if(ok)
	  if(query.exec())
	    if(query.next())
	      exists = query.value(0).toBool();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return exists;
}

bool spoton_misc::isAcceptedParticipant(const QByteArray &publicKeyHash,
					const QString &keyType,
					spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::isAcceptedParticipant(): crypt is zero.");
      return false;
    }

  QString connectionName("");
  bool exists = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND "
		      "neighbor_oid = -1 AND "
		      "public_key_hash = ?)");
	query.bindValue
	  (0, crypt->keyedHash(keyType.toLatin1(), &ok).toBase64());
	query.bindValue(1, publicKeyHash.toBase64());

	if(ok && query.exec())
	  if(query.next())
	    exists = query.value(0).toBool();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return exists;
}

bool spoton_misc::isAuthenticatedHint(spoton_crypt *crypt)
{
  if(!crypt)
    return false;

  QByteArray bytes;
  QSettings settings;
  bool ok = true;

  bytes = crypt->decryptedAfterAuthenticated
    (QByteArray::fromBase64(settings.
			    value("gui/authenticationHint").toByteArray()),
     &ok);
  return ok;
}

bool spoton_misc::isIpBlocked(const QHostAddress &address, spoton_crypt *crypt)
{
  if(address.isNull())
    {
      logError
	("spoton_misc::isIpBlocked(): address is empty.");
      return true;
    }
  else
    return isIpBlocked(address.toString(), crypt);
}

bool spoton_misc::isIpBlocked(const QString &address, spoton_crypt *crypt)
{
  if(address.isEmpty())
    {
      logError("spoton_misc::isIpBlocked(): address is empty.");
      return true;
    }
  else if(!crypt)
    {
      logError("spoton_misc::isIpBlocked(): crypt is zero.");
      return true;
    }

  QString connectionName("");
  bool exists = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 FROM neighbors WHERE "
		      "remote_ip_address_hash = ? AND "
		      "status_control = 'blocked')");
	query.bindValue
	  (0, crypt->keyedHash(address.toLatin1(), &ok).toBase64());

	if(ok)
	  if(query.exec())
	    if(query.next())
	      exists = query.value(0).toBool();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return exists;
}

bool spoton_misc::isMulticastAddress(const QHostAddress &address)
{
  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      quint32 a = address.toIPv4Address();

      if(!((a & 0xf0000000) == 0xe0000000))
	return false;
      else
	return true;
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      Q_IPV6ADDR a6 = address.toIPv6Address();

      if(a6.c[0] != 0xff)
	return false;
      else
	return true;
    }
  else
    return false;
}

bool spoton_misc::isPrivateNetwork(const QHostAddress &address)
{
  bool isPrivate = false;

  if(address.isNull())
    return isPrivate;
  else if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      QPair<QHostAddress, int> pair1
	(QHostAddress::parseSubnet("10.0.0.0/8"));
      QPair<QHostAddress, int> pair2
	(QHostAddress::parseSubnet("127.0.0.0/8"));
      QPair<QHostAddress, int> pair3
	(QHostAddress::parseSubnet("169.254.0.0/16"));
      QPair<QHostAddress, int> pair4
	(QHostAddress::parseSubnet("172.16.0.0/12"));
      QPair<QHostAddress, int> pair5
	(QHostAddress::parseSubnet("192.168.0.0/16"));

      isPrivate = address.isInSubnet(pair1) || address.isInSubnet(pair2) ||
	address.isInSubnet(pair3) || address.isInSubnet(pair4) ||
	address.isInSubnet(pair5);
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      QPair<QHostAddress, int> pair1
	(QHostAddress::parseSubnet("::1/128"));
      QPair<QHostAddress, int> pair2
	(QHostAddress::parseSubnet("fc00::/7"));
      QPair<QHostAddress, int> pair3
	(QHostAddress::parseSubnet("fe80::/10"));

      isPrivate = address.isInSubnet(pair1) || address.isInSubnet(pair2) ||
	address.isInSubnet(pair3);
    }

  return isPrivate;
}

bool spoton_misc::isValidBuzzMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  QStringList starts;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  starts << "ct="
	 << "hk="
	 << "ht="
	 << "rn="
	 << "xf="
	 << "xs="
	 << "xt=";

  for(int i = 0; i < list.size(); i++)
    {
      QString str(list.at(i).trimmed());

      if(starts.contains("ct=") && str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ct=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("rn=") && str.startsWith("rn="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("rn=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ht=") && str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::buzzHashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ht=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("hk=") && str.startsWith("hk="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("hk=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xf=") && str.startsWith("xf="))
	{
	  str.remove(0, 3);

	  bool ok = true;
	  int integer = str.toInt(&ok);

	  if(integer < 10000 || integer > 999999999 || !ok)
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xf=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xs=") && str.startsWith("xs="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xs=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:buzz")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xt=");
	      tokens += 1;
	    }
	}
    }

  if(tokens == 7)
    valid = true;

 done_label:
  return valid;
}

bool spoton_misc::isValidBuzzMagnetData(const QByteArray &data)
{
  QList<QByteArray> list(data.split('\n'));
  bool valid = false;

  for(int i = 0; i < 7; i++)
    {
      QByteArray str(QByteArray::fromBase64(list.value(i)));

      if(i == 0) // Channel
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 1) // Iteration Count
	{
	  bool ok = true;
	  int integer = str.toInt(&ok);

	  if(integer < 10000 || integer > 999999999 || !ok)
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 2) // Channel Salt
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 3) // Channel Type
	{
	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 4) // Hash
	{
	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 5) // Hash Type
	{
	  if(!spoton_crypt::buzzHashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	}
      else if(i == 6) // Urn
	{
	  if(str != "urn:buzz")
	    {
	      valid = false;
	      goto done_label;
	    }
	}
    }

  valid = true;

 done_label:
  return valid;
}

bool spoton_misc::isValidForwardSecrecyMagnet(const QByteArray &magnet,
					      QList<QByteArray> &values)
{
  values.clear();

  if(magnet.isEmpty())
    return false;

  QByteArray aa;
  QByteArray ak;
  QByteArray ea;
  QByteArray ek;
  QByteArray urn;
  QList<QByteArray> list;
  QStringList starts;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    return false;

  starts << "aa="
	 << "ak="
	 << "ea="
	 << "ek="
	 << "xt=";

  for(int i = 0; i < list.size(); i++)
    {
      QByteArray str(list.at(i).trimmed());

      if(starts.contains("aa=") && str.startsWith("aa="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::hashTypes().contains(str))
	    break;
	  else
	    {
	      starts.removeAll("aa=");
	      aa = str;
	    }
	}
      else if(starts.contains("ak=") && str.startsWith("ak="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    break;
	  else
	    {
	      starts.removeAll("ak=");
	      ak = str;
	    }
	}
      else if(starts.contains("ea=") && str.startsWith("ea="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    break;
	  else
	    {
	      starts.removeAll("ea=");
	      ea = str;
	    }
	}
      else if(starts.contains("ek=") && str.startsWith("ek="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    break;
	  else
	    {
	      starts.removeAll("ek=");
	      ek = str;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:forward-secrecy")
	    break;
	  else
	    {
	      starts.removeAll("xt=");
	      urn = str;
	    }
	}
    }

  if(!aa.isEmpty() && !ak.isEmpty() && !ea.isEmpty() && !ek.isEmpty() &&
     !urn.isEmpty())
    {
      values << aa << ak << ea << ek;
      return true;
    }

  return false;
}

bool spoton_misc::isValidInstitutionMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  QStringList starts;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  starts << "ct="
	 << "ht="
	 << "in="
	 << "pa="
	 << "xt=";

  for(int i = 0; i < list.size(); i++)
    {
      QString str(list.at(i).trimmed());

      if(starts.contains("in=") && str.startsWith("in="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("in=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ct=") && str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ct=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("pa=") && str.startsWith("pa="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("pa=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ht=") && str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::hashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ht=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:institution")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xt=");
	      tokens += 1;
	    }
	}
    }

  if(tokens == 5)
    valid = true;

 done_label:
  return valid;
}

bool spoton_misc::isValidSMPMagnet(const QByteArray &magnet,
				   QList<QByteArray> &values)
{
  QList<QByteArray> list;
  QStringList starts;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  starts << "xt=";

  for(int i = 0; i < list.size(); i++)
    {
      QString str(list.at(i).trimmed());

      if(str.startsWith("value="))
	{
	  str.remove(0, 6);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      values.append(QByteArray::fromBase64(str.toLatin1()));
	      tokens += 1;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:smp")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xt=");
	      tokens += 1;
	    }
	}
    }

  if(tokens >= 2 && tokens <= 12)
    valid = true;

 done_label:

  if(!valid)
    values.clear();

  return valid;
}

bool spoton_misc::isValidSignature(const QByteArray &data,
				   const QByteArray &publicKeyHash,
				   const QByteArray &signature,
				   spoton_crypt *crypt)
{
  /*
  ** We must locate the signature public key that's associated with the
  ** provided public key hash. Remember, publicKeyHash is the hash of the
  ** non-signature public key.
  */

  QByteArray publicKey
    (signaturePublicKeyFromPublicKeyHash(publicKeyHash, crypt));

  if(publicKey.isEmpty())
    {
      logError
	("spoton_misc::isValidSignature(): "
	 "signaturePublicKeyFromPublicKeyHash() failure.");
      return false;
    }

  return spoton_crypt::isValidSignature(data, publicKey, signature);
}

bool spoton_misc::isValidStarBeamMagnet(const QByteArray &magnet)
{
  QList<QByteArray> list;
  QStringList starts;
  bool valid = false;
  int tokens = 0;

  /*
  ** Validate the magnet.
  */

  if(magnet.startsWith("magnet:?"))
    list = magnet.mid(static_cast<int> (qstrlen("magnet:?"))).split('&');
  else
    goto done_label;

  starts << "ct="
	 << "ek="
	 << "ht="
	 << "mk="
	 << "xt=";

  for(int i = 0; i < list.size(); i++)
    {
      QString str(list.at(i).trimmed());

      if(starts.contains("ct=") && str.startsWith("ct="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::cipherTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ct=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ek=") && str.startsWith("ek="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ek=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ht=") && str.startsWith("ht="))
	{
	  str.remove(0, 3);

	  if(!spoton_crypt::hashTypes().contains(str))
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ht=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("mk=") && str.startsWith("mk="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("mk=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:starbeam")
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("xt=");
	      tokens += 1;
	    }
	}
    }

  if(tokens == 5)
    valid = true;

 done_label:
  return valid;
}

bool spoton_misc::joinMulticastGroup(const QHostAddress &address,
				     const QVariant &loop,
#if defined(Q_OS_WIN)
				     const SOCKET socketDescriptor,
#else
				     const int socketDescriptor,
#endif
				     const quint16 port)
{
  bool ok = true;

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    {
      ip_mreq mreq4;
      socklen_t length = sizeof(mreq4);

      memset(&mreq4, 0, sizeof(mreq4));
      mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
      mreq4.imr_multiaddr.s_addr = htonl(address.toIPv4Address());

#if defined(Q_OS_WIN)
      if(setsockopt(socketDescriptor, IPPROTO_IP,
		    IP_ADD_MEMBERSHIP, (const char *) &mreq4, (int) length)
	 == -1)
#else
      if(setsockopt(socketDescriptor, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    &mreq4, length) == -1)
#endif
	{
	  ok = false;
	  spoton_misc::logError
	    (QString("spoton_misc::joinMulticastGroup(): "
		     "setsockopt() failure for %1:%2.").
	     arg(address.toString()).arg(port));
	}
      else
	{
	  socklen_t length = 0;
	  u_char option = static_cast<u_char> (loop.toChar().toLatin1());

	  length = sizeof(option);

#if defined(Q_OS_WIN)
	  if(setsockopt(socketDescriptor,
			IPPROTO_IP,
			IP_MULTICAST_LOOP, (const char *) &option, (int) length)
	     == -1)
#else
	  if(setsockopt(socketDescriptor,
			IPPROTO_IP, IP_MULTICAST_LOOP, &option,
			length) == -1)
#endif
	    {
	      ok = false;
	      spoton_misc::logError
		(QString("spoton_misc::joinMulticastGroup(): "
			 "setsockopt() failure for %1:%2.").
		 arg(address.toString()).arg(port));
	    }
	}
    }
  else if(address.protocol() == QAbstractSocket::IPv6Protocol)
    {
      Q_IPV6ADDR ip6 = address.toIPv6Address();
      ipv6_mreq mreq6;
      socklen_t length = sizeof(mreq6);

      memset(&mreq6, 0, sizeof(mreq6));
      memcpy(&mreq6.ipv6mr_multiaddr, &ip6, sizeof(ip6));
      mreq6.ipv6mr_interface = 0;

#if defined(Q_OS_WIN)
      if(setsockopt(socketDescriptor, IPPROTO_IPV6,
		    IPV6_JOIN_GROUP, (const char *) &mreq6,
		    (int) length) == -1)
#else
      if(setsockopt(socketDescriptor, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
		    length) == -1)
#endif
	{
	  ok = false;
	  spoton_misc::logError
	    (QString("spoton_misc::joinMulticastGroup(): "
		     "setsockopt() failure for %1:%2.").
	     arg(address.toString()).arg(port));
	}
      else
	{
	  socklen_t length = 0;
	  u_int option = loop.toUInt();

	  length = sizeof(option);

#if defined(Q_OS_WIN)
	  if(setsockopt(socketDescriptor,
			IPPROTO_IPV6,
			IPV6_MULTICAST_LOOP, (const char *) &option,
			(int) length) == -1)
#else
	  if(setsockopt(socketDescriptor,
			IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &option,
			length) == -1)
#endif
	    {
	      ok = false;
	      spoton_misc::logError
		(QString("spoton_misc::joinMulticastGroup(): "
			 "setsockopt() failure for %1:%2.").
		 arg(address.toString()).arg(port));
	    }
	}
    }

  return ok;
}

bool spoton_misc::prepareUrlDistillersDatabase(void)
{
  QString connectionName("");
  bool ok = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("CREATE TABLE IF NOT EXISTS distillers ("
		       "direction TEXT NOT NULL, "
		       "direction_hash TEXT NOT NULL, " /*
							** Keyed hash.
							*/
		       "domain TEXT NOT NULL, "
		       "domain_hash TEXT KEY NOT NULL, " /*
							 ** Keyed hash.
							 */
		       "permission TEXT NOT NULL, "
		       "PRIMARY KEY (direction_hash, domain_hash))"))
	  ok = false;
	else
	  ok = true;
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

bool spoton_misc::prepareUrlKeysDatabase(void)
{
  QString connectionName("");
  bool ok = false;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("CREATE TABLE IF NOT EXISTS import_key_information ("
		       "cipher_type TEXT NOT NULL, "
		       "symmetric_key TEXT NOT NULL)"))
	  ok = false;
	else
	  ok = true;

	if(!query.exec("CREATE TRIGGER IF NOT EXISTS "
		       "import_key_information_trigger "
		       "BEFORE INSERT ON import_key_information "
		       "BEGIN "
		       "DELETE FROM import_key_information; "
		       "END"))
	  ok = false;
	else
	  ok &= true;

	if(!query.exec("CREATE TABLE IF NOT EXISTS remote_key_information ("
		       "cipher_type TEXT NOT NULL, "
		       "encryption_key TEXT NOT NULL, "
		       "hash_key TEXT NOT NULL, "
		       "hash_type TEXT NOT NULL)"))
	  ok = false;
	else
	  ok &= true;

	if(!query.exec("CREATE TRIGGER IF NOT EXISTS "
		       "remote_key_information_trigger "
		       "BEFORE INSERT ON remote_key_information "
		       "BEGIN "
		       "DELETE FROM remote_key_information; "
		       "END"))
	  ok = false;
	else
	  ok &= true;
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

bool spoton_misc::publicKeyExists(const qint64 oid)
{
  QString connectionName("");
  bool exists = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT EXISTS(SELECT 1 FROM "
		      "friends_public_keys WHERE "
		      "OID = ?)");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toBool();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return exists;
}

bool spoton_misc::saveFriendshipBundle(const QByteArray &keyType,
				       const QByteArray &n, // Name
				       const QByteArray &publicKey,
				       const QByteArray &sPublicKey,
				       const qint64 neighborOid,
				       const QSqlDatabase &db,
				       spoton_crypt *crypt,
				       const bool useKeyTypeForName)
{
  if(!crypt)
    {
      logError
	("spoton_misc::saveFriendshipBundle(): crypt is zero.");
      return false;
    }
  else if(!db.isOpen())
    {
      logError
	("spoton_misc::saveFriendshipBundle(): db is closed.");
      return false;
    }

  QByteArray name(n);
  QSqlQuery query(db);
  bool ok = true;

  query.setForwardOnly(true);
  query.prepare("SELECT name FROM friends_public_keys WHERE "
		"name_changed_by_user = 1 AND public_key_hash = ?");
  query.bindValue(0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok && query.exec())
    if(query.next())
      name = crypt->decryptedAfterAuthenticated
	(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

  ok = true;
  query.prepare("INSERT OR REPLACE INTO friends_public_keys "
		"(gemini, gemini_hash_key, key_type, key_type_hash, "
		"name, public_key, public_key_hash, "
		"neighbor_oid, last_status_update, name_changed_by_user) "
		"VALUES ((SELECT gemini FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"(SELECT gemini_hash_key FROM friends_public_keys WHERE "
		"public_key_hash = ?), "
		"?, ?, ?, ?, ?, ?, ?, "
		"(SELECT name_changed_by_user FROM friends_public_keys WHERE "
		"public_key_hash = ?))");
  query.bindValue(0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue(1, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue(2, crypt->encryptedThenHashed(keyType, &ok).toBase64());

  if(ok)
    query.bindValue(3, crypt->keyedHash(keyType, &ok).toBase64());

  if(spoton_common::SPOTON_ENCRYPTION_KEY_NAMES.contains(keyType))
    {
      if(ok)
	{
	  if(name.isEmpty())
	    {
	      if(keyType == "poptastic")
		query.bindValue
		  (4, crypt->
		   encryptedThenHashed(QByteArray("unknown@unknown.org"),
				       &ok).toBase64());
	      else
		query.bindValue
		  (4, crypt->
		   encryptedThenHashed(QByteArray("unknown"),
				       &ok).toBase64());
	    }
	  else
	    query.bindValue
	      (4, crypt->
	       encryptedThenHashed(name.
				   mid(0, spoton_common::
				       NAME_MAXIMUM_LENGTH),
				   &ok).toBase64());
	}
    }
  else if(ok)
    {
      if(useKeyTypeForName)
	query.bindValue(4, crypt->encryptedThenHashed(keyType, &ok).
			toBase64());
      else
	query.bindValue(4, crypt->encryptedThenHashed(name, &ok).
			toBase64());
    }

  if(ok)
    query.bindValue
      (5, crypt->encryptedThenHashed(publicKey, &ok).toBase64());

  if(ok)
    query.bindValue
      (6, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  query.bindValue(7, neighborOid);
  query.bindValue
    (8, QDateTime::currentDateTime().toString(Qt::ISODate));

  if(ok)
    query.bindValue(9, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

  if(ok)
    ok = query.exec();

  if(ok)
    if(!sPublicKey.isEmpty())
      {
	/*
	** Record the relationship between the public key and the
	** signature public key.
	*/

	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO relationships_with_signatures "
		      "(public_key_hash, signature_public_key_hash) "
		      "VALUES (?, ?)");
	query.bindValue
	  (0, spoton_crypt::sha512Hash(publicKey, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, spoton_crypt::sha512Hash(sPublicKey, &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

  return ok;
}

bool spoton_misc::saveGemini(const QPair<QByteArray, QByteArray> &gemini,
			     const QString &oid,
			     spoton_crypt *crypt)
{
  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ? "
		      "WHERE OID = ? AND "
		      "neighbor_oid = -1");

	if(gemini.first.isEmpty() || gemini.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    if(crypt)
	      {
		query.bindValue
		  (0, crypt->encryptedThenHashed(gemini.first,
						 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, crypt->encryptedThenHashed(gemini.second,
						   &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue(2, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

bool spoton_misc::saveReceivedStarBeamHashes(const QSqlDatabase &db,
					     const QByteArray &hash1,
					     const QByteArray &hash2,
					     const QString &oid,
					     spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::saveReceivedStarBeamHashes(): crypt "
	 "is zero.");
      return false;
    }
  else if(!db.isOpen())
    {
      logError
	("spoton_misc::saveReceivedStarBeamHashes(): db is closed.");
      return false;
    }

  QSqlQuery query(db);
  bool ok = true;

  query.prepare
    ("UPDATE received SET hash = ?, sha3_512_hash = ? WHERE OID = ?");

  if(hash1.isEmpty())
    query.bindValue(0, QVariant::String);
  else
    query.bindValue
      (0, crypt->encryptedThenHashed(hash1.toHex(), &ok).toBase64());

  if(hash2.isEmpty())
    query.bindValue(1, QVariant::String);
  else
    query.bindValue
      (1, crypt->encryptedThenHashed(hash2.toHex(), &ok).toBase64());

  query.bindValue(2, oid);

  if(ok)
    ok = query.exec();

  return ok;
}

bool spoton_misc::storeAlmostAnonymousLetter(const QList<QByteArray> &list,
					     spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::storeAlmostAnonymousLetter(): crypt "
	 "is zero.");
      return false;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QByteArray attachmentData(list.value(5));
	QByteArray message(list.value(4));
	QByteArray name(list.value(2));
	QByteArray senderPublicKeyHash(list.value(1));
	QByteArray subject(list.value(3));
	QDateTime now(QDateTime::currentDateTime());
	QSqlQuery query(db);

	query.prepare("INSERT INTO folders "
		      "(date, "
		      "folder_index, "
		      "from_account, "
		      "goldbug, "
		      "hash, "
		      "message, "
		      "message_code, "
		      "receiver_sender, "
		      "receiver_sender_hash, "
		      "sign, "
		      "signature, "
		      "status, "
		      "subject, "
		      "participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->
	   encryptedThenHashed(now.toString(Qt::ISODate).
			       toLatin1(), &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue(2, crypt->encryptedThenHashed(QByteArray(), &ok).
			  toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->
	     encryptedThenHashed(QByteArray::number(0), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->keyedHash(now.toString(Qt::ISODate).toLatin1() +
				 message + subject,
				 &ok).toBase64());

	if(ok)
	  if(!message.isEmpty())
	    query.bindValue
	      (5, crypt->encryptedThenHashed(message,
					     &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  if(!name.isEmpty())
	    query.bindValue
	      (7, crypt->encryptedThenHashed(name,
					     &ok).toBase64());

	query.bindValue
	  (8, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (11, crypt->
	     encryptedThenHashed(QByteArray("Unread"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (12, crypt->encryptedThenHashed(subject, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (13, crypt->
	     encryptedThenHashed(QByteArray::number(-1), &ok).
	     toBase64());

	if(ok)
	  if((ok = query.exec()))
	    {
	      if(!attachmentData.isEmpty())
		{
		  QVariant variant(query.lastInsertId());
		  qint64 id = query.lastInsertId().toLongLong();

		  if(variant.isValid())
		    {
		      QByteArray data(qUncompress(attachmentData));

		      if(!data.isEmpty())
			{
			  QDataStream stream(&data, QIODevice::ReadOnly);
			  QList<QPair<QByteArray, QByteArray> > attachments;

			  stream >> attachments;

			  if(stream.status() != QDataStream::Ok)
			    attachments.clear();

			  for(int i = 0; i < attachments.size(); i++)
			    {
			      QPair<QByteArray, QByteArray> pair
				(attachments.at(i));
			      QSqlQuery query(db);

			      query.prepare("INSERT INTO folders_attachment "
					    "(data, folders_oid, name) "
					    "VALUES (?, ?, ?)");
			      query.bindValue
				(0, crypt->encryptedThenHashed(pair.first,
							       &ok).
				 toBase64());
			      query.bindValue(1, id);

			      if(ok)
				query.bindValue
				  (2, crypt->
				   encryptedThenHashed(pair.second,
						       &ok).toBase64());

			      if(ok)
				ok = query.exec();
			    }
			}
		    }
		}
	    }
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return ok;
}

int spoton_misc::minimumNeighborLaneWidth(void)
{
  QString connectionName("");
  int laneWidth = spoton_common::LANE_WIDTH_MINIMUM;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT MIN(lane_width) FROM neighbors");

	if(query.exec())
	  if(query.next())
	    laneWidth = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return laneWidth;
}

int spoton_misc::sendQueueSize(QTcpSocket *tcpSocket)
{
  if(!tcpSocket)
    return -1;

  int count = 0;

#ifdef Q_OS_FREEBSD
  if(ioctl(static_cast<int> (tcpSocket->socketDescriptor()),
	   FIONWRITE,
	   &count) == -1)
    count = tcpSocket->bytesToWrite();
#elif defined(Q_OS_LINUX)
  if(ioctl(static_cast<int> (tcpSocket->socketDescriptor()),
	   SIOCOUTQ,
	   &count) == -1)
    count = tcpSocket->bytesToWrite();
#elif defined(Q_OS_MAC)
  socklen_t length = (socklen_t) sizeof(count);

  if(getsockopt(static_cast<int> (tcpSocket->socketDescriptor()),
		SOL_SOCKET,
		SO_NWRITE,
		&count,
		&length) == -1)
    count = tcpSocket->bytesToWrite();
#elif defined(Q_OS_OPENBSD)
  if(ioctl(static_cast<int> (tcpSocket->socketDescriptor()),
	   TIOCOUTQ,
	   &count) == -1)
    count = tcpSocket->bytesToWrite();
#else
  count = tcpSocket->bytesToWrite();
#endif
  return count;
}

qint64 spoton_misc::oidFromPublicKeyHash(const QByteArray &publicKeyHash)
{
  QString connectionName("");
  qint64 oid = -1;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT OID "
		      "FROM friends_public_keys WHERE "
		      "public_key_hash = ?");
	query.bindValue(0, publicKeyHash);

	if(query.exec())
	  if(query.next())
	    oid = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return oid;
}

qint64 spoton_misc::participantCount(const QString &keyType,
				     spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::participantCount(): crypt "
	 "is zero.");
      return 0;
    }

  QString connectionName("");
  qint64 count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM friends_public_keys "
		      "WHERE key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue
	  (0, crypt->keyedHash(keyType.toLatin1(), &ok).toBase64());

	if(ok && query.exec())
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count;
}

quint64 spoton_misc::databaseAccesses(void)
{
  QReadLocker locker(&s_dbMutex);

  return s_dbId;
}

spoton_crypt *spoton_misc::cryptFromForwardSecrecyMagnet
(const QByteArray &magnet)
{
  QList<QByteArray> list;

  if(!isValidForwardSecrecyMagnet(magnet, list))
    return 0;

  return new spoton_crypt(list.value(2),
			  list.value(0),
			  QByteArray(),
			  list.value(3),
			  list.value(1),
			  0,
			  0,
			  "");
}

spoton_crypt *spoton_misc::parsePrivateApplicationMagnet
(const QByteArray &magnet)
{
  QList<QByteArray> list
    (QByteArray(magnet.trimmed()).
     remove(0, static_cast<int> (qstrlen("magnet:?"))).split('&'));
  QByteArray ek;
  QByteArray hk;
  QByteArray xt;
  QString ct("");
  QString ht("");
  spoton_crypt *crypt = 0;
  unsigned long int ic = 0;

  for(int i = 0; i < list.size(); i++)
    {
      QByteArray bytes(list.at(i).trimmed());

      if(bytes.startsWith("ct="))
	{
	  bytes.remove(0, 3);
	  ct = bytes;
	}
      else if(bytes.startsWith("ht="))
	{
	  bytes.remove(0, 3);
	  ht = bytes;
	}
      else if(bytes.startsWith("ic="))
	{
	  bytes.remove(0, 3);
	  ic = qBound(0UL, bytes.toULong(), 999999999UL);
	}
      else if(bytes.startsWith("s1="))
	{
	  bytes.remove(0, 3);
	  ek = QByteArray::fromBase64(bytes);
	}
      else if(bytes.startsWith("s2="))
	{
	  bytes.remove(0, 3);
	  hk = QByteArray::fromBase64(bytes);
	}
      else if(bytes.startsWith("xt"))
	{
	  bytes.remove(0, 3);
	  xt = bytes;
	}
      else
	break;
    }

  if(ek.length() > 0 && hk.length() > 0 && ic > 0 &&
     spoton_crypt::cipherTypes().contains(ct) &&
     spoton_crypt::hashTypes().contains(ht) &&
     xt == "urn:private-application-credentials")
    crypt = new spoton_crypt
      (ct, ht, QByteArray(), ek, hk, 0, ic, QString(""));

  return crypt;
}

spoton_crypt *spoton_misc::retrieveUrlCommonCredentials(spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::retrieveUrlCommonCredentials(): crypt "
	 "is zero.");
      return 0;
    }

  QString connectionName("");
  spoton_crypt *c = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, encryption_key, "
		      "hash_key, hash_type FROM "
		      "remote_key_information") && query.next())
	  {
	    QByteArray encryptionKey;
	    QByteArray hashKey;
	    QString cipherType("");
	    QString hashType("");
	    bool ok = true;

	    cipherType = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()),
	       &ok).constData();

	    if(ok)
	      encryptionKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(1).toByteArray()),
		 &ok);

	    if(ok)
	      hashKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(2).toByteArray()),
		 &ok);

	    if(ok)
	      hashType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(3).toByteArray()),
		 &ok).constData();

	    if(ok)
	      c = new spoton_crypt(cipherType,
				   hashType,
				   QByteArray(),
				   encryptionKey,
				   hashKey,
				   0,
				   0,
				   "");
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return c;
}

void spoton_misc::alterDatabasesAfterAuthentication(spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("SELECT EXISTS (SELECT signatures_required FROM "
		       "echo_key_sharing_secrets)"))
	  {
	    /*
	    ** Perhaps signatures_required does not exist.
	    */

	    query.exec
	      ("CREATE TABLE IF NOT EXISTS "
	       "echo_key_sharing_secrets_temporary ("
	       "accept TEXT NOT NULL, "
	       "authentication_key TEXT NOT NULL, "
	       "category_oid INTEGER NOT NULL, "
	       "cipher_type TEXT NOT NULL, "
	       "encryption_key TEXT NOT NULL, "
	       "hash_type TEXT NOT NULL, "
	       "iteration_count TEXT NOT NULL, "
	       "name TEXT NOT NULL, "
	       "name_hash TEXT NOT NULL, "
	       "share TEXT NOT NULL, "
	       "signatures_required TEXT NOT NULL, "
	       "PRIMARY KEY (category_oid, name_hash))");

	    if(query.exec("SELECT accept, "
			  "authentication_key, "
			  "category_oid, "
			  "cipher_type, "
			  "encryption_key, "
			  "hash_type, "
			  "iteration_count, "
			  "name, "
			  "name_hash, "
			  "share FROM echo_key_sharing_secrets"))
	      {
		while(query.next())
		  {
		    QSqlQuery insertQuery(db);
		    bool ok = true;

		    insertQuery.prepare
		      ("INSERT INTO echo_key_sharing_secrets_temporary "
		       "(authentication_key, category_oid, cipher_type, "
		       "encryption_key, hash_type, iteration_count, "
		       "name, name_hash, share, signatures_required) "
		       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

		    for(int i = 0; i < query.record().count(); i++)
		      insertQuery.bindValue(i, query.value(i));

		    insertQuery.bindValue
		      (10, crypt->encryptedThenHashed(QByteArray("true"),
						      &ok).toBase64());
		    insertQuery.exec();
		  }

		query.exec("DROP TABLE echo_key_sharing_secrets");
		query.exec("ALTER TABLE echo_key_sharing_secrets_temporary "
			   "RENAME TO echo_key_sharing_secrets");
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::cleanupDatabases(spoton_crypt *crypt)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("UPDATE friends_public_keys SET status = 'offline' "
		   "WHERE status <> 'offline'");

	/*
	** Delete asymmetric keys that were not completely shared.
	*/

	query.exec("DELETE FROM friends_public_keys WHERE "
		   "neighbor_oid <> -1");
	purgeSignatureRelationships(db, crypt);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM kernel_gui_server");
	query.exec("DELETE FROM kernel_statistics");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM listeners WHERE "
		   "status_control = 'deleted'");
	query.exec("DELETE FROM listeners_accounts WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("DELETE FROM listeners_accounts_consumed_authentications");
	query.exec("DELETE FROM listeners_allowed_ips WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("UPDATE listeners SET connections = 0, "
		   "external_ip_address = NULL, "
		   "status = 'offline'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSettings settings;
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");

	if(settings.value("gui/keepOnlyUserDefinedNeighbors", true).toBool())
	  query.exec("DELETE FROM neighbors WHERE "
		     "status_control <> 'blocked' AND user_defined = 0");

	query.exec("UPDATE neighbors SET "
		   "account_authenticated = NULL, "
		   "buffered_content = 0, "
		   "bytes_discarded_on_write = 0, "
		   "bytes_read = 0, "
		   "bytes_written = 0, "
		   "external_ip_address = NULL, "
		   "is_encrypted = 0, "
		   "local_ip_address = NULL, "
		   "local_port = NULL, "
		   "ssl_session_cipher = NULL, "
		   "status = 'disconnected', "
		   "uptime = 0");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM transmitted WHERE "
		   "status_control = 'deleted'");
	query.exec("DELETE FROM transmitted_magnets WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
	query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::closeSocket
#if QT_VERSION < 0x050000
(const int socketDescriptor)
#else
(const qintptr socketDescriptor)
#endif
{
#if defined(Q_OS_WIN)
  shutdown((SOCKET) socketDescriptor, SD_BOTH);
  closesocket((SOCKET) socketDescriptor);
#else
  shutdown((int) socketDescriptor, SHUT_RDWR);
  close((int) socketDescriptor);
#endif
}

void spoton_misc::correctSettingsContainer(QHash<QString, QVariant> settings)
{
  /*
  ** Attempt to correct flawed configuration settings.
  */

  QString str("");
  QStringList list;
  bool ok = true;
  double rational = 0.00;
  int integer = 0;

  integer = qAbs(settings.value("gui/congestionCost", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 1000 || integer > 65536)
    integer = 10000;

  settings.insert("gui/congestionCost", integer);
  integer = qAbs(settings.value("gui/emailRetrievalInterval", 5).toInt(&ok));

  if(!ok)
    integer = 5;
  else if(integer < 5 || integer > 60)
    integer = 5;

  settings.insert("gui/emailRetrievalInterval", integer);
  str = settings.value("gui/fsCipherType").toString();

  if(!(str == "aes256" || str == "camellia256" ||
       str == "serpent256" || str == "twofish"))
    str = "aes256";

  settings.insert("gui/fsCipherType", str);
  str = settings.value("gui/fsHashType").toString();

  if(!(str == "sha512" || str == "stribog512" ||
       str == "whirlpool"))
    str = "sha512";

  settings.insert("gui/fsHashType", str);
  integer = qAbs
    (settings.value("gui/gcryctl_init_secmem",
		    spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE).toInt(&ok));

  if(!ok)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;
  else if(integer == 0)
    {
    }
  else if(integer > 999999999)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;

  settings.insert("gui/gcryctl_init_secmem", integer);
  integer = settings.value("gui/guiExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/guiExternalIpInterval", integer);
  str = settings.value("gui/hashType").toString();

  if(!(str == "sha512" || str == "stribog512" ||
       str == "whirlpool"))
    str = "sha512";

  settings.insert("gui/hashType", str);
  str = settings.value("gui/iconSet", "nouve").toString();

  if(!(str == "everaldo" ||
       str == "meego" ||
       str == "nouve" ||
       str == "nuvola"))
    str = "nouve";

  settings.insert("gui/iconSet", str);
  integer = qAbs(settings.value("gui/iterationCount", 10000).toInt(&ok));

  if(!ok)
    integer = 10000;
  else if(integer < 10000 || integer > 999999999)
    integer = 10000;

  settings.insert("gui/iterationCount", integer);
  str = settings.value("gui/kernelCipherType").toString();

  if(!(str == "aes256" || str == "camellia256" ||
       str == "serpent256" || str == "twofish"))
    str = "aes256";

  settings.insert("gui/kernelCipherType", str);
  integer = settings.value("gui/kernelExternalIpInterval", -1).toInt(&ok);

  if(!ok)
    integer = -1;
  else if(!(integer == -1 || integer == 30 || integer == 60))
    integer = -1;

  settings.insert("gui/kernelExternalIpInterval", integer);
  str = settings.value("gui/kernelHashType").toString();

  if(!(str == "sha512" || str == "stribog512" || str == "whirlpool"))
    str = "sha512";

  settings.insert("gui/kernelHashType", str);
  integer = qAbs(settings.value("gui/kernelKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 0 ||
	    integer == 2048 ||
	    integer == 3072 ||
	    integer == 4096))
    integer = 2048;

  settings.insert("gui/kernelKeySize", integer);
  integer = qAbs(settings.value("gui/kernel_url_batch_size", 5).toInt(&ok));

  if(!ok)
    integer = 5;
  else if(integer <= 0 || integer > 15)
    integer = 5;

  settings.insert("gui/kernel_url_batch_size", integer);
  integer = qAbs(settings.value("gui/limitConnections", 10).toInt(&ok));

  if(!ok)
    integer = 10;
  else if(integer <= 0 || integer > 50)
    integer = 10;

  settings.insert("gui/limitConnections", integer);
  integer = qAbs(settings.value("gui/maximum_url_keywords_import_interface",
				50).toInt(&ok));

  if(!ok)
    integer = 50;
  else if(integer < 50 || integer > 65535)
    integer = 50;

  settings.insert("gui/maximum_url_keywords_import_interface", integer);
  integer = qAbs(settings.value("gui/maximum_url_keywords_import_kernel",
				50).toInt(&ok));

  if(!ok)
    integer = 50;
  else if(integer < 50 || integer > 65535)
    integer = 50;

  settings.insert("gui/maximum_url_keywords_import_kernel", integer);
  integer = qAbs(settings.value("gui/maximumEmailFileSize", 1024).toInt(&ok));

  if(!ok)
    integer = 1024;
  else if(integer < 1 || integer > 5000)
    integer = 1024;

  settings.insert("gui/maximumEmailFileSize", integer);
  integer = qBound
    (0,
     settings.value("gui/postgresql_kernel_url_distribution_timeout", 45000).
     toInt(&ok),
     999999999);

  if(!ok)
    integer = 45000;

  settings.insert("gui/postgresql_kernel_url_distribution_timeout", integer);
  integer = qAbs(settings.value("gui/postofficeDays", 1).toInt(&ok));

  if(!ok)
    integer = 1;
  else if(integer < 1 || integer > 366)
    integer = 1;

  settings.insert("gui/postofficeDays", integer);
  integer = qAbs(settings.value("gui/publishedKeySize", 2048).toInt(&ok));

  if(!ok)
    integer = 2048;
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096))
    integer = 2048;

  settings.insert("gui/publishedKeySize", integer);
  integer = qAbs(settings.value("gui/maxMosaicSize", 512).toInt(&ok));

  if(!ok)
    integer = 512;
  else if(integer < 1 || integer > 5000)
    integer = 512;

  settings.insert("gui/maxMosaicSize", integer);
  integer = qAbs(settings.value("gui/saltLength", 512).toInt(&ok));

  if(!ok)
    integer = 512;
  else if(integer < 512 || integer > 999999999)
    integer = 512;

  settings.insert("gui/saltLength", integer);
  integer = qAbs(settings.value("gui/searchResultsPerPage", 10).toInt(&ok));

  if(!ok)
    integer = 10;
  else if(integer < 10 || integer > 1000)
    integer = 10;

  settings.insert("gui/searchResultsPerPage", integer);
  rational = qAbs(settings.value("kernel/cachePurgeInterval", 15.00).
		  toDouble(&ok));

  if(!ok)
    rational = 15.00;
  else if(rational < 5.00 || rational > 90.00)
    rational = 15.00;

  settings.insert("kernel/cachePurgeInterval", rational);
  integer = qAbs(settings.value("kernel/gcryctl_init_secmem",
				spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE).
		 toInt(&ok));

  if(!ok)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;
  else if(integer == 0)
    {
    }
  else if(integer > 999999999)
    integer = spoton_common::MINIMUM_SECURE_MEMORY_POOL_SIZE;

  settings.insert("kernel/gcryctl_init_secmem", integer);
  str = settings.value("kernel/messaging_cache_algorithm", "sha224").
    toString().toLower().trimmed();

  if(!spoton_crypt::congestionHashAlgorithms().contains(str))
    str = "sha224";

  settings.insert("kernel/messaging_cache_algorithm", str);
  integer = qAbs
    (settings.value("kernel/server_account_verification_window_msecs",
		    15000).toInt(&ok));

  if(!ok)
    integer = 15000;
  else if(integer < 1 || integer > 999999999)
    integer = 15000;

  settings.insert
    ("kernel/server_account_verification_window_msecs", integer);

  /*
  ** Correct timer intervals.
  */

  integer = settings.value("gui/emailRetrievalInterval", 5).toInt(&ok);

  if(!ok)
    integer = 5;
  else if(integer < 5 || integer > 60)
    integer = 5;

  settings.insert("gui/emailRetrievalInterval", integer);
  integer = settings.value("gui/poptasticNumberOfMessages", 15).toInt(&ok);

  if(!ok)
    integer = 15;
  else if(integer < 15 || integer > 999999999)
    integer = 15;

  settings.insert("gui/poptasticNumberOfMessages", integer);
  rational = settings.value("gui/poptasticRefreshInterval", 5.00).
    toDouble(&ok);

  if(!ok)
    rational = 5.00;
  else if(rational < 5.00)
    rational = 5.00;

  settings.insert("gui/poptasticRefreshInterval", rational);
  list.clear();
  list << "gui/kernelUpdateTimer"
       << "gui/listenersUpdateTimer"
       << "gui/neighborsUpdateTimer"
       << "gui/participantsUpdateTimer"
       << "gui/starbeamUpdateTimer";

  for(int i = 0; i < list.size(); i++)
    {
      rational = settings.value(list.at(i), 3.50).toDouble(&ok);

      if(!ok)
	rational = 3.50;
      else if(rational < 0.50 || rational > 10.00)
	rational = 3.50;

      settings.insert(list.at(i), rational);
    }
}

void spoton_misc::enableLog(const bool state)
{
  s_enableLog.fetchAndStoreOrdered(state ? 1 : 0);
}

void spoton_misc::logError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;
  else if(!s_enableLog.fetchAndAddOrdered(0))
    return;

  QtConcurrent::run(&spoton_misc::logErrorThread, error);
}

void spoton_misc::logErrorThread(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;
  else if(!s_enableLog.fetchAndAddOrdered(0))
    return;

  QWriteLocker locker(&s_logMutex);
  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.size() > spoton_common::LOG_FILE_MAXIMUM_SIZE)
    /*
    ** Too large!
    */

    file.remove();

  if(file.open(QIODevice::Append | QIODevice::WriteOnly))
    {
      QDateTime now(QDateTime::currentDateTime());
#if defined(Q_OS_WIN)
      QString eol("\r\n");
#else
      QString eol("\n");
#endif

      file.write(now.toString(Qt::ISODate).toLatin1());
      file.write(eol.toLatin1());
      file.write(error.trimmed().toLatin1());
      file.write(eol.toLatin1());
      file.write(eol.toLatin1());
      file.flush();
    }

  file.close();
}

void spoton_misc::populateUrlsDatabase(const QList<QList<QVariant> > &list,
				       spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::populateUrlsDatabase(): crypt is zero.");
      return;
    }
  else if(list.isEmpty())
    {
      logError
	("spoton_misc::populateUrlsDatabase(): list is empty.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    /*
    ** Determine the correct URL database file.
    */

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT INTO urls (date_time_inserted, "
		      "description, hash, title, url) "
		      "VALUES (?, ?, ?, ?, ?)");

	for(int i = 0; i < list.size(); i++)
	  {
	    /*
	    ** 0: description
	    ** 1: title
	    ** 2: url
	    */

	    const QList<QVariant> &variants(list.at(i));
	    bool ok = true;

	    query.bindValue
	      (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query.bindValue
	      (1, crypt->encryptedThenHashed
	       (variants.value(0).toByteArray(), &ok).
	       toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->keyedHash(variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->encryptedThenHashed
		 (variants.value(1).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->encryptedThenHashed
		 (variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::prepareAuthenticationHint(spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QSettings settings;

  if(settings.contains("gui/authenticationHint"))
    return;

  QByteArray bytes(spoton_crypt::weakRandomBytes(256));
  bool ok = true;

  bytes = crypt->encryptedThenHashed(bytes, &ok);

  if(!ok)
    return;

  settings.setValue("gui/authenticationHint", bytes.toBase64());
}

void spoton_misc::prepareDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "buzz_channels.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS buzz_channels ("
		   "data BLOB NOT NULL, "
		   "data_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "congestion_control.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("CREATE TABLE IF NOT EXISTS congestion_control ("
		   "date_time_inserted BIGINT NOT NULL, "
		   "hash TEXT PRIMARY KEY NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "echo_key_sharing_secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS categories ("
		   "category TEXT NOT NULL, "
		   "category_hash TEXT PRIMARY KEY NOT NULL)"); /*
								** Keyed
								** hash.
								*/
	query.exec("CREATE TABLE IF NOT EXISTS echo_key_sharing_secrets ("
		   "accept TEXT NOT NULL, "
		   "authentication_key TEXT NOT NULL, "
		   "category_oid INTEGER NOT NULL, "
		   "cipher_type TEXT NOT NULL, "
		   "encryption_key TEXT NOT NULL, "
		   "hash_type TEXT NOT NULL, "
		   "iteration_count TEXT NOT NULL, "
		   "name TEXT NOT NULL, "
		   "name_hash TEXT NOT NULL, " // Keyed hash.
		   "share TEXT NOT NULL, "
		   "signatures_required TEXT NOT NULL, "
		   "PRIMARY KEY (category_oid, name_hash))");
	query.exec("CREATE TRIGGER IF NOT EXISTS "
		   "purge AFTER DELETE ON categories "
		   "FOR EACH row "
		   "BEGIN "
		   "DELETE FROM echo_key_sharing_secrets "
		   "WHERE category_oid = old.oid; "
		   "END;");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS folders ("
		   "date TEXT NOT NULL, "
		   "folder_index INTEGER NOT NULL "
		   "CHECK (folder_index >= 0 AND folder_index <= 2), "
		   "from_account TEXT NOT NULL, "
		   "goldbug TEXT NOT NULL, " /*
					     ** 0 or 1 for inbound,
					     ** magnet for outbound.
					     */
		   "hash TEXT NOT NULL, " /*
					  ** Keyed hash of the date,
					  ** the message, and
					  ** the subject.
					  */
		   "message BLOB NOT NULL, "
		   "message_code TEXT NOT NULL, " /*
						  ** Not yet used.
						  */
		   "mode TEXT, " /*
				 ** forward-secrecy
				 ** normal
				 ** pure-forward-secrecy
				 */
		   "participant_oid TEXT NOT NULL, " // Encrypted?
		   "receiver_sender TEXT NOT NULL, "
		   "receiver_sender_hash TEXT NOT NULL, " /*
							  ** SHA-512 hash of
							  ** the receiver's
							  ** or the sender's
							  ** public key.
							  */
		   "sign TEXT NOT NULL, "
		   "signature TEXT NOT NULL, "
		   "status TEXT NOT NULL, " /*
					    ** Deleted, read, etc.
					    */
		   "subject BLOB NOT NULL, "
		   "PRIMARY KEY (folder_index, hash, receiver_sender_hash))");
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "folders_attachment ("
		   "data BLOB NOT NULL, "
		   "folders_oid INTEGER NOT NULL, "
		   "name TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS institutions ("
		   "cipher_type TEXT NOT NULL, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** Keyed hash of the
						      ** name.
						      */
		   "hash_type TEXT NOT NULL, "
		   "name TEXT NOT NULL, "
		   "postal_address TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS post_office ("
		   "date_received TEXT NOT NULL, "
		   "message_bundle BLOB NOT NULL, "
		   "message_bundle_hash TEXT NOT NULL, " // Keyed hash.
		   "recipient_hash TEXT NOT NULL, " /*
						    ** SHA-512 hash of the
						    ** recipient's public
						    ** key.
						    */
		   "PRIMARY KEY (recipient_hash, message_bundle_hash))");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec
	  ("CREATE TABLE IF NOT EXISTS friends_public_keys ("
	   "gemini TEXT DEFAULT NULL, "
	   "key_type TEXT NOT NULL, "
	   "key_type_hash TEXT NOT NULL, " // Keyed hash.
	   "name TEXT NOT NULL DEFAULT 'unknown', "
	   "public_key BLOB NOT NULL, "
	   "public_key_hash TEXT PRIMARY KEY NOT NULL, " /*
							 ** SHA-512
							 ** hash of
							 ** the public
							 ** key.
							 */
	   /*
	   ** Why do we need the neighbor's OID?
	   ** When a neighbor shares a public key, we need
	   ** to be able to remove the key if the socket connection
	   ** is lost before we complete the exchange. The field
	   ** provides us with some safety.
	   */
	   "neighbor_oid INTEGER NOT NULL DEFAULT -1, "
	   "status TEXT NOT NULL DEFAULT 'offline', "
	   "last_status_update TEXT NOT NULL DEFAULT 'now', "
	   "gemini_hash_key TEXT DEFAULT NULL, "
	   "name_changed_by_user INTEGER NOT NULL DEFAULT 0, "
	   "forward_secrecy_authentication_algorithm TEXT, "
	   "forward_secrecy_authentication_key TEXT, "
	   "forward_secrecy_encryption_algorithm TEXT, "
	   "forward_secrecy_encryption_key TEXT)");
	query.exec
	  ("CREATE TABLE IF NOT EXISTS relationships_with_signatures ("
	   "public_key_hash TEXT PRIMARY KEY NOT NULL, " /*
							 ** SHA-512
							 ** hash of
							 ** the public
							 ** key.
							 */
	   "signature_public_key_hash "
	   "TEXT NOT NULL)"); /*
			      ** SHA-512 hash of the signature
			      ** public key.
			      */
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS idiotes ("
		   "id TEXT NOT NULL, "
		   "id_hash TEXT PRIMARY KEY NOT NULL, " // Keyed hash.
		   "private_key BLOB NOT NULL, "
		   "public_key BLOB NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS kernel_gui_server ("
		   "port INTEGER PRIMARY KEY NOT NULL "
		   "CHECK (port >= 0 AND port <= 65535))");
	query.exec("CREATE TRIGGER IF NOT EXISTS kernel_gui_server_trigger "
		   "BEFORE INSERT ON kernel_gui_server "
		   "BEGIN "
		   "DELETE FROM kernel_gui_server; "
		   "END");
	query.exec("CREATE TABLE IF NOT EXISTS kernel_statistics ("
		   "statistic TEXT PRIMARY KEY NOT NULL, "
		   "value TEXT)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "kernel_web_server.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS kernel_web_server ("
		   "certificate TEXT NOT NULL, "
		   "private_key TEXT NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS kernel_web_server_trigger "
		   "BEFORE INSERT ON kernel_web_server "
		   "BEGIN "
		   "DELETE FROM kernel_web_server; "
		   "END");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS listeners ("
		   "ip_address TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "source_of_randomness INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (source_of_randomness >= 0 AND "
		   "source_of_randomness <= %5), "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'offline' "
		   "CHECK (status IN ('deleted', 'offline', 'online')), "
		   "status_control TEXT NOT NULL DEFAULT 'online' "
		   "CHECK (status_control IN ('deleted', 'offline', "
		   "'online')), "
		   "connections INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (connections >= 0), "
		   "maximum_clients INTEGER NOT NULL DEFAULT 5 "
		   "CHECK (maximum_clients >= 0), " /*
						    ** Please set to zero
						    ** for an unlimited
						    ** number of clients.
						    */
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** The keyed hash of
						      ** the IP address,
						      ** the port,
						      ** the scope id, and
						      ** the transport.
						      */
		   "socket_options TEXT, "
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'%4', "
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "echo_mode TEXT NOT NULL, "
		   "certificate BLOB NOT NULL, "
		   "private_key BLOB NOT NULL, "
		   "public_key BLOB NOT NULL, "       // Not used.
		   "use_accounts INTEGER NOT NULL DEFAULT 0, "
		   "maximum_buffer_size INTEGER NOT NULL DEFAULT %1 "
		   "CHECK (maximum_buffer_size > 0), "
		   "maximum_content_length INTEGER NOT NULL DEFAULT %2 "
		   "CHECK (maximum_content_length > 0), "
		   "transport TEXT NOT NULL, "
		   "share_udp_address INTEGER NOT NULL DEFAULT 0, "
		   "orientation TEXT NOT NULL, "
		   "lane_width INTEGER NOT NULL DEFAULT %3 "
		   "CHECK (lane_width > 0), "
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.', "
		   "passthrough INTEGER NOT NULL DEFAULT 0, "
		   "private_application_credentials TEXT)").
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH).
	   arg(spoton_common::LANE_WIDTH_DEFAULT).
	   arg(spoton_common::SSL_CONTROL_STRING).
	   arg(std::numeric_limits<unsigned short>::max()));
	query.exec("CREATE TABLE IF NOT EXISTS listeners_accounts ("
		   "account_name TEXT NOT NULL, "
		   "account_name_hash TEXT NOT NULL, " // Keyed hash.
		   "account_password TEXT NOT NULL, "
		   "listener_oid INTEGER NOT NULL, "
		   "one_time_account INTEGER NOT NULL DEFAULT 0, "
		   "PRIMARY KEY (listener_oid, account_name_hash))");
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "listeners_accounts_consumed_authentications ("
		   "data TEXT NOT NULL, "
		   "insert_date TEXT NOT NULL, "
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (listener_oid, data))");
	query.exec("CREATE TABLE IF NOT EXISTS "
		   "listeners_adaptive_echo_tokens ("
		   "token TEXT NOT NULL, " /*
					   ** Please
					   ** note that the table
					   ** houses both encryption
					   ** and hash keys. Apologies
					   ** for violating some
					   ** database principles.
					   */
		   "token_hash TEXT PRIMARY KEY NOT NULL, " /*
							    ** Keyed hash of
							    ** the token and
							    ** the token type.
							    */
		   "token_type TEXT NOT NULL)"); /*
						 ** The token_type contains
						 ** both cipher and hash
						 ** algorithm information.
						 */
	query.exec("CREATE TABLE IF NOT EXISTS listeners_allowed_ips ("
		   "ip_address TEXT NOT NULL, "
		   "ip_address_hash TEXT NOT NULL, " // Keyed hash.
		   "listener_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (ip_address_hash, listener_oid))");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS neighbors ("
		   "local_ip_address TEXT , "
		   "local_port TEXT, "
		   "remote_ip_address TEXT NOT NULL, "
		   "remote_port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'disconnected' CHECK "
		   "(status IN ('blocked', 'bound', "
		   "'connected', 'connecting', 'closing', "
		   "'deleted', "
		   "'disconnected', 'host-lookup')), "
		   "status_control TEXT NOT NULL DEFAULT 'connected' CHECK "
		   "(status_control IN ('blocked', 'connected', 'deleted', "
		   "'disconnected')), "
		   "sticky INTEGER NOT NULL DEFAULT 1, "
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "uuid TEXT NOT NULL, "
		   "country TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** Keyed hash of the
						      ** proxy IP address,
						      ** the proxy port,
						      ** the remote IP
						      ** address, the remote
						      ** port, the scope id,
						      ** and the transport.
						      */
		   "private_application_credentials TEXT, "
		   "remote_ip_address_hash TEXT NOT NULL, " // Keyed hash.
		   "qt_country_hash TEXT, " // Keyed hash.
		   "user_defined INTEGER NOT NULL DEFAULT 1, "
		   "proxy_hostname TEXT NOT NULL, "
		   "proxy_password TEXT NOT NULL, "
		   "proxy_port TEXT NOT NULL, "
		   "proxy_type TEXT NOT NULL, "
		   "proxy_username TEXT NOT NULL, "
		   "is_encrypted INTEGER NOT NULL DEFAULT 0, "
		   "maximum_buffer_size INTEGER NOT NULL DEFAULT %1 "
		   "CHECK (maximum_buffer_size > 0), "
		   "maximum_content_length INTEGER NOT NULL DEFAULT %2 "
		   "CHECK (maximum_content_length > 0), "
		   "echo_mode TEXT NOT NULL, "
		   "socket_options TEXT, "
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "uptime INTEGER NOT NULL DEFAULT 0, "
		   "certificate BLOB NOT NULL, "
		   "allow_exceptions INTEGER NOT NULL DEFAULT 0, "
		   "bytes_discarded_on_write INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (bytes_discarded_on_write >= 0), "
		   "bytes_read INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (bytes_read >= 0), "
		   "bytes_written INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (bytes_written >= 0), "
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'%5', "
		   "ssl_session_cipher TEXT, "
		   "ssl_required INTEGER NOT NULL DEFAULT 1, "
		   "account_name TEXT NOT NULL, "
		   "account_password TEXT NOT NULL, "
		   "account_authenticated TEXT, "
		   "transport TEXT NOT NULL, "
		   "orientation TEXT NOT NULL, "
		   "lane_width INTEGER NOT NULL DEFAULT %3 "
		   "CHECK (lane_width > 0), "
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.', "
		   "ae_token TEXT, " /*
				     ** Please note that the table
				     ** houses both encryption
				     ** and hash keys of adaptive
				     ** echo tokens. Apologies
				     ** for violating some
				     ** database principles.
				     */
		   "ae_token_type TEXT, " /*
					  ** The ae_token_type contains
					  ** both cipher and hash
					  ** algorithm information.
					  */
		   "passthrough INTEGER NOT NULL DEFAULT 0, "
		   "priority INTEGER NOT NULL DEFAULT 4 CHECK "
		   "(priority >= 0 AND priority <= 6), " /*
							 ** High
							 ** priority.
							 */
		   "waitforbyteswritten_msecs INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (waitforbyteswritten_msecs >= 0 AND "
		   "waitforbyteswritten_msecs <= %4), "
		   "silence_time INTEGER NOT NULL DEFAULT 90 "
		   "CHECK (silence_time >= 0 AND silence_time <= %6), "
		   "buffered_content INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (buffered_content >= 0))").
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH).
	   arg(spoton_common::LANE_WIDTH_DEFAULT).
	   arg(spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM).
	   arg(spoton_common::SSL_CONTROL_STRING).
	   arg(999999999));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS poptastic ("
		   "in_authentication TEXT NOT NULL, "
		   "in_method TEXT NOT NULL, "
		   "in_password TEXT NOT NULL, "
		   "in_remove_remote INTEGER NOT NULL DEFAULT 1, "
		   "in_server_address TEXT NOT NULL, "
		   "in_server_port TEXT NOT NULL, "
		   "in_ssltls TEXT NOT NULL, "
		   "in_username TEXT NOT NULL, "
		   "in_username_hash TEXT PRIMARY KEY NOT NULL, " /*
								  ** Keyed
								  ** hash.
								  */
		   "in_verify_host TEXT NOT NULL, "
		   "in_verify_peer TEXT NOT NULL, "
		   "out_authentication TEXT NOT NULL, "
		   "out_method TEXT NOT NULL, "
		   "out_password TEXT NOT NULL, "
		   "out_server_address TEXT NOT NULL, "
		   "out_server_port TEXT NOT NULL, "
		   "out_ssltls TEXT NOT NULL, "
		   "out_username TEXT NOT NULL, "
		   "out_verify_host TEXT NOT NULL, "
		   "out_verify_peer TEXT NOT NULL, "
		   "proxy_enabled TEXT NOT NULL, "
		   "proxy_password TEXT NOT NULL, "
		   "proxy_server_address TEXT NOT NULL, "
		   "proxy_server_port TEXT NOT NULL, "
		   "proxy_type TEXT NOT NULL CHECK "
		   "(proxy_type IN ('HTTP', 'SOCKS5')), "
		   "proxy_username TEXT NOT NULL, "
		   "smtp_localname TEXT NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS secrets ("
		   "generated_data TEXT NOT NULL, "
		   "generated_data_hash TEXT NULL PRIMARY KEY, " // Keyed hash.
		   "hint TEXT NOT NULL, "
		   "key_type TEXT NOT NULL)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

#ifdef Q_PROCESSOR_ARM
	query.exec("PRAGMA journal_mode = DELETE");
#else
	query.exec("PRAGMA journal_mode = DELETE");
#endif
	query.exec("CREATE TABLE IF NOT EXISTS magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT PRIMARY KEY NOT NULL, " // Keyed hash.
		   "one_time_magnet INTEGER NOT NULL DEFAULT 0)");
	query.exec("CREATE TABLE IF NOT EXISTS received ("
		   "expected_file_hash TEXT, "
		   "expected_sha3_512_hash TEXT, "
		   "file TEXT NOT NULL, "
		   "file_hash TEXT PRIMARY KEY NOT NULL, " /*
							   ** Keyed hash of
							   ** the file name.
							   */
		   "hash TEXT, "                           /*
							   ** SHA-1 hash of
							   ** the file.
							   */
		   "locked INTEGER NOT NULL DEFAULT 0, "
		   "pulse_size TEXT NOT NULL, "
		   "sha3_512_hash TEXT, "
		   "total_size TEXT NOT NULL)");
	query.exec("CREATE TABLE IF NOT EXISTS received_novas ("
		   "nova TEXT NOT NULL, " /*
					  ** Please
					  ** note that the table
					  ** houses both encryption
					  ** and hash keys. Apologies
					  ** for violating some
					  ** database principles.
					  */
		   "nova_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
	query.exec("CREATE TABLE IF NOT EXISTS transmitted ("
		   "file TEXT NOT NULL, "
		   "fragmented INTEGER NOT NULL DEFAULT 0, "
		   "hash TEXT NOT NULL, " /*
					  ** SHA-1 hash of the file.
					  */
		   "mosaic TEXT PRIMARY KEY NOT NULL, "
		   "nova TEXT NOT NULL, " /*
					  ** Please
					  ** note that the table
					  ** houses both encryption
					  ** and hash keys. Apologies
					  ** for violating some
					  ** database principles.
					  */
		   "position TEXT NOT NULL, "
		   "pulse_size TEXT NOT NULL, "
		   "read_interval REAL NOT NULL DEFAULT 1.500 "
		   "CHECK (read_interval >= 0.100), "
		   "sha3_512_hash TEXT, "
		   "status_control TEXT NOT NULL DEFAULT 'paused' CHECK "
		   "(status_control IN ('completed', 'deleted', 'paused', "
		   "'transmitting')), "
		   "total_size TEXT NOT NULL, "
		   "ultra INTEGER NOT NULL DEFAULT 1)"); // Ignored.
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (magnet_hash, transmitted_oid))");
	query.exec("CREATE TABLE IF NOT EXISTS transmitted_scheduled_pulses ("
		   "position TEXT NOT NULL, "
		   "position_hash TEXT NOT NULL, " // Keyed hash.
		   "transmitted_oid INTEGER NOT NULL, "
		   "PRIMARY KEY (position_hash, transmitted_oid))");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  /*
  ** We shall prepare the URL databases somewhere else.
  */
}

void spoton_misc::prepareSignalHandler(void (*signal_handler) (int))
{
  QList<int> list;

  list << SIGABRT
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
       << SIGBUS
#endif
       << SIGFPE
       << SIGILL
       << SIGINT
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
       << SIGQUIT
#endif
       << SIGSEGV
       << SIGTERM;

  for(int i = 0; i < list.size(); i++)
    {
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
      struct sigaction act;

      act.sa_flags = 0;
      act.sa_handler = signal_handler;
      sigemptyset(&act.sa_mask);

      if(sigaction(list.at(i), &act, 0))
	logError(QString("spoton_misc::prepareSignalHandler(): "
			 "sigaction() failure for %1.").arg(list.at(i)));
#else
      if(signal(list.at(i), signal_handler) == SIG_ERR)
	logError(QString("spoton_misc::prepareSignalHandler(): "
			 "signal() failure for %1.").arg(list.at(i)));
#endif
    }
}

void spoton_misc::purgeSignatureRelationships(const QSqlDatabase &db,
					      spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError("spoton_misc::purgeSignatureRelationships(): crypt is zero.");
      return;
    }
  else if(!db.isOpen())
    {
      logError("spoton_misc::purgeSignatureRelationships(): db is closed.");
      return;
    }

  QStringList list(spoton_common::SPOTON_SIGNATURE_KEY_NAMES);

  for(int i = 0; i < list.size(); i++)
    {
      QSqlQuery query(db);
      bool ok = true;

      /*
      ** Delete relationships that do not have corresponding entries
      ** in the friends_public_keys table.
      */

      query.exec("PRAGMA secure_delete = ON");
      query.prepare("DELETE FROM relationships_with_signatures WHERE "
		    "public_key_hash NOT IN "
		    "(SELECT public_key_hash FROM friends_public_keys WHERE "
		    "key_type_hash <> ?)");
      query.bindValue
	(0, crypt->keyedHash(list.at(i).toLatin1(), &ok).toBase64());

      if(ok)
	query.exec();

      /*
      ** Delete signature public keys from friends_public_keys that
      ** do not have relationships.
      */

      query.prepare
	("DELETE FROM friends_public_keys WHERE "
	 "key_type_hash = ? AND public_key_hash NOT IN "
	 "(SELECT signature_public_key_hash FROM "
	 "relationships_with_signatures)");

      if(ok)
	query.bindValue
	  (0, crypt->keyedHash(list.at(i).toLatin1(), &ok).toBase64());

      if(ok)
	query.exec();
    }
}

void spoton_misc::removeOneTimeStarBeamMagnets(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM magnets WHERE one_time_magnet = 1");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::retrieveSymmetricData
(QPair<QByteArray, QByteArray> &gemini,
 QByteArray &publicKey,
 QByteArray &symmetricKey,
 QByteArray &hashKey,
 QByteArray &startsWith,
 QString &neighborOid,
 QString &receiverName,
 const QByteArray &cipherType,
 const QString &oid,
 spoton_crypt *crypt,
 bool *ok)
{
  if(!crypt)
    {
      if(ok)
	*ok = false;

      logError
	("spoton_misc::retrieveSymmetricData(): crypt is zero.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT gemini, neighbor_oid, public_key, "
		      "gemini_hash_key, name "
		      "FROM friends_public_keys WHERE "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  {
	    if(ok)
	      *ok = true;

	    if(query.next())
	      {
		size_t symmetricKeyLength = spoton_crypt::cipherKeyLength
		  (cipherType);

		if(symmetricKeyLength > 0)
		  {
		    if(!query.isNull(0))
		      gemini.first = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(0).
						toByteArray()),
			 ok);

		    if(ok && *ok)
		      {
			if(!query.isNull(3))
			  gemini.second = crypt->decryptedAfterAuthenticated
			    (QByteArray::fromBase64(query.value(3).
						    toByteArray()),
			     ok);
		      }
		    else if(!ok)
		      if(!query.isNull(3))
			gemini.second = crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(3).
						  toByteArray()),
			   ok);

		    neighborOid = query.value(1).toString();

		    if(ok && *ok)
		      publicKey = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(2).
						toByteArray()),
			 ok);
		    else if(!ok)
		      publicKey = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(2).
						toByteArray()),
			 ok);

		    if((ok && *ok) || !ok)
		      {
			startsWith = publicKey.mid(0, 25);
			publicKey = qCompress(publicKey);
		      }

		    if(ok && *ok)
		      receiverName = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(4).
						toByteArray()),
			 ok);
		    else if(!ok)
		      receiverName = crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(4).
						toByteArray()),
			 ok);

		    bool found = false;

		    for(int i = 1;
			i <= spoton_common::IDENTICAL_CREDENTIALS_ITERATIONS;
			i++)
		      {
			symmetricKey = spoton_crypt::strongRandomBytes
			  (symmetricKeyLength);

			if(!spoton_crypt::memcmp(gemini.first, symmetricKey))
			  {
			    found = true;
			    break;
			  }
		      }

		    if(found)
		      {
			found = false;

			for(int i = 1;
			    i <= spoton_common::
			      IDENTICAL_CREDENTIALS_ITERATIONS;
			    i++)
			  {
			    hashKey = spoton_crypt::strongRandomBytes
			      (static_cast<size_t>
			       (spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));

			    if(!spoton_crypt::memcmp(gemini.second, hashKey))
			      {
				found = true;
				break;
			      }
			  }
		      }

		    if(!found)
		      if(ok)
			*ok = false;
		  }
		else
		  {
		    if(ok)
		      *ok  = false;

		    logError
		      ("spoton_misc::retrieveSymmetricData(): "
		       "cipherKeyLength() failure.");
		  }
	      }
	    else if(ok)
	      *ok = false;
	  }

	if(query.lastError().isValid())
	  {
	    if(ok)
	      *ok = false;
	  }
      }
    else if(ok)
      *ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::saveParticipantStatus(const QByteArray &name,
					const QByteArray &publicKeyHash,
					const QByteArray &status,
					const QByteArray &timestamp,
					const int seconds,
					spoton_crypt *crypt)
{
  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      logError
	("spoton_misc(): saveParticipantStatus(): "
	 "invalid date-time object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  qint64 secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= static_cast<qint64> (seconds)))
    {
      logError
	(QString("spoton_misc::saveParticipantStatus(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(status.isEmpty())
	  {
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ?, "
			      "status = 'online' "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
		query.exec();
	      }
	    else if(crypt)
	      {
		bool ok = true;

		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ?, "
			      "status = 'online' "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
		query.exec();
		query.prepare("UPDATE friends_public_keys SET "
			      "name = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   crypt->
		   encryptedThenHashed(name.
				       mid(0, spoton_common::
					   NAME_MAXIMUM_LENGTH), &ok).
		   toBase64());
		query.bindValue(1, publicKeyHash.toBase64());

		if(ok)
		  query.exec();
	      }
	  }
	else
	  {
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status.toLower() == "away" ||
		   status.toLower() == "busy" ||
		   status.toLower() == "offline" ||
		   status.toLower() == "online")
		  query.bindValue(0, status.toLower());
		else
		  query.bindValue
		    (0, status.
		     mid(0, spoton_common::STATUS_TEXT_MAXIMUM_LENGTH));

		query.bindValue
		  (1, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
		query.exec();
	      }
	    else if(crypt)
	      {
		QDateTime now(QDateTime::currentDateTime());
		bool ok = true;

		query.prepare("UPDATE friends_public_keys SET "
			      "name = ?, "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   crypt->
		   encryptedThenHashed(name.
				       mid(0, spoton_common::
					   NAME_MAXIMUM_LENGTH), &ok).
		   toBase64());

		if(status.toLower() == "away" ||
		   status.toLower() == "busy" ||
		   status.toLower() == "offline" ||
		   status.toLower() == "online")
		  query.bindValue(1, status.toLower());
		else
		  query.bindValue
		    (1, status.
		     mid(0, spoton_common::STATUS_TEXT_MAXIMUM_LENGTH));

		query.bindValue
		  (2, now.toString(Qt::ISODate));
		query.bindValue(3, publicKeyHash.toBase64());

		if(ok)
		  query.exec();

		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status.toLower() == "away" ||
		   status.toLower() == "busy" ||
		   status.toLower() == "offline" ||
		   status.toLower() == "online")
		  query.bindValue(0, status.toLower());
		else
		  query.bindValue
		    (0, status.
		     mid(0, spoton_common::STATUS_TEXT_MAXIMUM_LENGTH));

		query.bindValue
		  (1, now.toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

#if QT_VERSION >= 0x050501 && defined(SPOTON_BLUETOOTH_ENABLED)
void spoton_misc::savePublishedNeighbor(const QBluetoothAddress &address,
					const quint16 port,
					const QString &statusControl,
					const QString &orientation,
					spoton_crypt *crypt)
{
  if(address.isNull())
    {
      logError
	("spoton_misc::savePublishedNeighbor(): address is empty.");
      return;
    }
  else if(!crypt)
    {
      logError
	("spoton_misc::savePublishedNeighbor(): crypt "
	 "is zero.");
      return;
    }

  QString connectionName("");
  QString transport("bluetooth");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName
      (homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString country
	  (countryNameFromIPAddress(address.toString()));
	bool ok = true;

	query.prepare
	  ("INSERT INTO neighbors "
	   "(local_ip_address, "
	   "local_port, "
	   "protocol, "
	   "remote_ip_address, "
	   "remote_port, "
	   "scope_id, "
	   "status_control, "
	   "hash, "
	   "sticky, "
	   "country, "
	   "remote_ip_address_hash, "
	   "qt_country_hash, "
	   "user_defined, "
	   "proxy_hostname, "
	   "proxy_password, "
	   "proxy_port, "
	   "proxy_type, "
	   "proxy_username, "
	   "uuid, "
	   "echo_mode, "
	   "ssl_key_size, "
	   "certificate, "
	   "account_name, "
	   "account_password, "
	   "transport, "
	   "orientation, "
	   "ssl_control_string) "
	   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
	   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));
	query.bindValue(2, crypt->encryptedThenHashed("", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3,
	     crypt->encryptedThenHashed(address.toString().toLatin1(),
					&ok).toBase64());

	if(ok)
	  query.bindValue
	    (4,
	     crypt->
	     encryptedThenHashed(QByteArray::number(port), &ok).toBase64());

	if(ok)
	  query.bindValue(5, crypt->encryptedThenHashed("", &ok).toBase64());

	if(statusControl.toLower() == "connected" ||
	   statusControl.toLower() == "disconnected")
	  query.bindValue(6, statusControl.toLower());
	else
	  query.bindValue(6, "disconnected");

	if(ok)
	  /*
	  ** We do not have proxy information.
	  */

	  query.bindValue
	    (7,
	     crypt->keyedHash((address.toString() +
			       QString::number(port) +
			       "" + // Scope ID
			       transport).toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, 1); // Sticky

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(country.toLatin1(),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->keyedHash(address.toString().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, crypt->keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	query.bindValue(12, 1);

	QString proxyHostName("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType(QString::number(QNetworkProxy::NoProxy));
	QString proxyUsername("");

	if(ok)
	  query.bindValue
	    (13, crypt->encryptedThenHashed(proxyHostName.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->encryptedThenHashed(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->encryptedThenHashed(proxyPort.toLatin1(),
					    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->encryptedThenHashed(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->encryptedThenHashed(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (18, crypt->
	     encryptedThenHashed("{00000000-0000-0000-0000-000000000000}",
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->encryptedThenHashed("full", &ok).toBase64());

	query.bindValue(20, 0);

	if(ok)
	  query.bindValue
	    (21, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (22, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (23, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (24, crypt->encryptedThenHashed(transport.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  {
	    if(orientation == "packet" || orientation == "stream")
	      query.bindValue
		(25, crypt->encryptedThenHashed(orientation.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(25, crypt->encryptedThenHashed("packet", &ok).toBase64());
	  }

	query.bindValue(26, "N/A");

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
#endif

void spoton_misc::savePublishedNeighbor(const QHostAddress &address,
					const quint16 port,
					const QString &p_transport,
					const QString &statusControl,
					const QString &orientation,
					spoton_crypt *crypt)
{
  if(address.isNull())
    {
      logError("spoton_misc::savePublishedNeighbor(): address is empty.");
      return;
    }
  else if(!crypt)
    {
      logError("spoton_misc::savePublishedNeighbor(): crypt is zero.");
      return;
    }

  QString transport(p_transport.toLower().trimmed());

  if(!(transport == "sctp" ||
       transport == "tcp" ||
       transport == "udp" ||
       transport == "websocket"))
    return;

  /*
  ** We are not concerned with availability of particular protocols here.
  */

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString country(countryNameFromIPAddress(address.toString()));
	bool ok = true;

	query.prepare
	  ("INSERT INTO neighbors "
	   "(local_ip_address, "
	   "local_port, "
	   "protocol, "
	   "remote_ip_address, "
	   "remote_port, "
	   "scope_id, "
	   "status_control, "
	   "hash, "
	   "sticky, "
	   "country, "
	   "remote_ip_address_hash, "
	   "qt_country_hash, "
	   "user_defined, "
	   "proxy_hostname, "
	   "proxy_password, "
	   "proxy_port, "
	   "proxy_type, "
	   "proxy_username, "
	   "uuid, "
	   "echo_mode, "
	   "ssl_key_size, "
	   "certificate, "
	   "account_name, "
	   "account_password, "
	   "transport, "
	   "orientation, "
	   "ssl_control_string) "
	   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
	   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));

	if(address.protocol() == QAbstractSocket::IPv4Protocol)
	  query.bindValue
	    (2, crypt->encryptedThenHashed("IPv4", &ok).toBase64());
	else
	  query.bindValue
	    (2, crypt->encryptedThenHashed("IPv6", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3,
	     crypt->encryptedThenHashed(address.toString().toLatin1(),
					&ok).toBase64());

	if(ok)
	  query.bindValue
	    (4,
	     crypt->
	     encryptedThenHashed(QByteArray::number(port), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5,
	     crypt->encryptedThenHashed(address.scopeId().toLatin1(),
					&ok).toBase64());

	if(statusControl.toLower() == "connected" ||
	   statusControl.toLower() == "disconnected")
	  query.bindValue(6, statusControl.toLower());
	else
	  query.bindValue(6, "disconnected");

	if(ok)
	  /*
	  ** We do not have proxy information.
	  */

	  query.bindValue
	    (7,
	     crypt->keyedHash((address.toString() +
			       QString::number(port) +
			       address.scopeId() +
			       transport).toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, 1); // Sticky

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(country.toLatin1(),
					   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->keyedHash(address.toString().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, crypt->keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	query.bindValue(12, 1);

	QString proxyHostName("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType(QString::number(QNetworkProxy::NoProxy));
	QString proxyUsername("");

	if(ok)
	  query.bindValue
	    (13, crypt->encryptedThenHashed(proxyHostName.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->encryptedThenHashed(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->encryptedThenHashed(proxyPort.toLatin1(),
					    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->encryptedThenHashed(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->encryptedThenHashed(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (18, crypt->
	     encryptedThenHashed("{00000000-0000-0000-0000-000000000000}",
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->encryptedThenHashed("full", &ok).toBase64());

	if(ok)
	  {
	    if(transport == "tcp" ||
	       transport == "udp" ||
	       transport == "websocket")
	      {
		QSettings settings;
		bool ok = true;
		int keySize = 2048;

		keySize = settings.value
		  ("gui/publishedKeySize", "2048").toInt(&ok);

		if(!ok)
		  keySize = 2048;
		else if(!(keySize == 2048 ||
			  keySize == 3072 ||
			  keySize == 4096))
		  keySize = 2048;

		query.bindValue(20, keySize);
	      }
	    else
	      query.bindValue(20, 0);
	  }

	if(ok)
	  query.bindValue
	    (21, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (22, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (23, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (24,
	     crypt->encryptedThenHashed(transport.toLatin1(), &ok).toBase64());

	if(ok)
	  {
	    if(orientation == "packet" || orientation == "stream")
	      query.bindValue
		(25, crypt->encryptedThenHashed(orientation.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(25, crypt->encryptedThenHashed("packet", &ok).toBase64());
	  }

	if(transport == "tcp" ||
	   transport == "udp" ||
	   transport == "websocket")
	  query.bindValue(26, spoton_common::SSL_CONTROL_STRING);
	else
	  query.bindValue(26, "N/A");

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::setTimeVariables(const QHash<QString, QVariant> &settings)
{
  /*
  ** Issue as soon as possible!
  */

  QList<int> defaults;
  QList<int> values;
  QStringList keys;

  defaults
    << spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC
    << spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC
    << spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
  keys << "gui/chat_time_delta"
       << "gui/forward_secrecy_time_delta"
       << "gui/gemini_time_delta"
       << "gui/kernel_cache_object_lifetime"
       << "gui/kernel_url_dispatcher_interval"
       << "gui/poptastic_forward_secrecy_time_delta"
       << "gui/poptastic_gemini_time_delta"
       << "gui/retrieve_mail_time_delta";

  for(int i = 0; i < keys.size(); i++)
    values << settings.value(keys.at(i), defaults.at(i)).toInt();

  spoton_common::CHAT_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(0), 600);
  spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(1), 600);
  spoton_common::GEMINI_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(2), 600);
  spoton_common::CACHE_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(3), 600);
  spoton_common::KERNEL_URL_DISPATCHER_INTERVAL =
    qBound(45, values.value(4), 600);
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(5), 600);
  spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(6), 60 * 60 * 24 * 7);
  spoton_common::MAIL_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(7), 600);
}

void spoton_misc::vacuumAllDatabases(void)
{
  QStringList list;

  list << "buzz_channels.db"
       << "congestion_control.db"
       << "echo_key_sharing_secrets.db"
       << "email.db"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "kernel_web_server.db"
       << "listeners.db"
       << "neighbors.db"
       << "poptastic.db"
       << "rss.db"
       << "secrets.db"
       << "shared.db"
       << "starbeam.db"
       << "urls_distillers_information.db"
       << "urls_key_information.db";

  for(int i = 0; i < list.size(); i++)
    {
      QString connectionName("");

      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName(homePath() + QDir::separator() + list.at(i));

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.exec("VACUUM");
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}
