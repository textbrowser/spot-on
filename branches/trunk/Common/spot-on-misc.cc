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

#include <QDataStream>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QLocale>
#include <QNetworkProxy>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QString>
#include <QUrl>

#include <limits>

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

QReadWriteLock spoton_misc::s_dbMutex;
QReadWriteLock spoton_misc::s_enableLogMutex;
bool spoton_misc::s_enableLog = false;
quint64 spoton_misc::s_dbId = 0;

QString spoton_misc::homePath(void)
{
  QByteArray homepath(qgetenv("SPOTON_HOME"));

  if(homepath.isEmpty())
#ifdef Q_OS_WIN32
    return QDir::currentPath() + QDir::separator() + ".spot-on";
#else
    return QDir::homePath() + QDir::separator() + ".spot-on";
#endif
  else
    return homepath.mid(0, spoton_common::SPOTON_HOME_MAXIMUM_PATH_LENGTH).
      constData();
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

	query.exec("CREATE TABLE IF NOT EXISTS buzz_channels ("
		   "data BLOB NOT NULL, "
		   "data_hash TEXT PRIMARY KEY NOT NULL)"); // Keyed hash.
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
		   "PRIMARY KEY (category_oid, name_hash))");
	query.exec("CREATE TRIGGER purge AFTER DELETE ON categories "
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

	query.exec("CREATE TABLE IF NOT EXISTS folders ("
		   "date TEXT NOT NULL, "
		   "folder_index INTEGER NOT NULL "
		   "CHECK (folder_index >= 0 AND folder_index <= 2), "
		   "goldbug TEXT NOT NULL, " /*
					     ** 0 or 1 for inbound.
					     ** Magnet for outbound.
					     */
		   "hash TEXT NOT NULL, " /*
					  ** Keyed hash of the message and
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

    db.setDatabaseName(homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS listeners ("
		   "ip_address TEXT NOT NULL, "
		   "port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'offline' "
		   "CHECK (status IN ('deleted', 'offline', 'online')), "
		   "status_control TEXT NOT NULL DEFAULT 'online' "
		   "CHECK (status_control IN ('deleted', 'offline', "
		   "'online')), "
		   "connections INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (connections >= 0), "
		   "maximum_clients INTEGER NOT NULL DEFAULT 5 "
		   "CHECK (maximum_clients > 0), "
		   "external_ip_address TEXT, "
		   "external_port TEXT, "
		   "hash TEXT PRIMARY KEY NOT NULL, " /*
						      ** The keyed hash of
						      ** the IP address,
						      ** the port,
						      ** the scope id, and
						      ** the transport.
						      */
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH', "
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
		   "motd TEXT NOT NULL DEFAULT 'Welcome to Spot-On.')").
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH).
	   arg(spoton_common::LANE_WIDTH_DEFAULT));
	query.exec(QString("ALTER TABLE listeners "
			   "ADD lane_width INTEGER NOT NULL DEFAULT %1 "
			   "CHECK (lane_width > 0)").
		   arg(spoton_common::LANE_WIDTH_DEFAULT));
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
		   "insert_date TEXT NOT NULL DEFAULT 'now', "
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

	query.exec
	  (QString("CREATE TABLE IF NOT EXISTS neighbors ("
		   "local_ip_address TEXT , "
		   "local_port TEXT, "
		   "remote_ip_address TEXT NOT NULL, "
		   "remote_port TEXT NOT NULL, "
		   "scope_id TEXT, "
		   "protocol TEXT NOT NULL, "
		   "status TEXT NOT NULL DEFAULT 'disconnected' CHECK "
		   "(status IN ('blocked', 'connected', 'deleted', "
		   "'disconnected')), "
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
		   "ssl_key_size INTEGER NOT NULL DEFAULT 2048, "
		   "uptime INTEGER NOT NULL DEFAULT 0, "
		   "certificate BLOB NOT NULL, "
		   "allow_exceptions INTEGER NOT NULL DEFAULT 0, "
		   "bytes_read INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (bytes_read >= 0), "
		   "bytes_written INTEGER NOT NULL DEFAULT 0 "
		   "CHECK (bytes_written >= 0), "
		   "ssl_control_string TEXT NOT NULL DEFAULT "
		   "'HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH', "
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
				     ** Please
				     ** note that the table
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
		   "priority INTEGER NOT NULL DEFAULT 4 CHECK "
		   "(priority >= 0 AND priority <= 7))"). /*
							  ** High
							  ** priority.
							  */
	   arg(spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE).
	   arg(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH).
	   arg(spoton_common::LANE_WIDTH_DEFAULT));
	query.exec(QString("ALTER TABLE neighbors "
			   "ADD lane_width INTEGER NOT NULL DEFAULT %1 "
			   "CHECK (lane_width > 0)").
		   arg(spoton_common::LANE_WIDTH_DEFAULT));
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

	query.exec("CREATE TABLE IF NOT EXISTS poptastic ("
		   "in_authentication TEXT NOT NULL, "
		   "in_method TEXT NOT NULL CHECK "
		   "(in_method IN ('Disable', 'IMAP', 'POP3')), "
		   "in_password TEXT NOT NULL, "
		   "in_server_address TEXT NOT NULL, "
		   "in_server_port TEXT NOT NULL, "
		   "in_ssltls TEXT NOT NULL CHECK "
		   "(in_ssltls IN ('None', 'SSL', 'TLS')), "
		   "in_username TEXT NOT NULL, "
		   "out_authentication TEXT NOT NULL, "
		   "out_method TEXT NOT NULL CHECK "
		   "(out_method IN ('Disable', 'SMTP')), "
		   "out_password TEXT NOT NULL, "
		   "out_server_address TEXT NOT NULL, "
		   "out_server_port TEXT NOT NULL, "
		   "out_ssltls TEXT NOT NULL CHECK "
		   "(out_ssltls IN ('None', 'SSL', 'TLS')), "
		   "out_username TEXT NOT NULL, "
		   "proxy_enabled TEXT NOT NULL, "
		   "proxy_password TEXT NOT NULL, "
		   "proxy_server_address TEXT NOT NULL, "
		   "proxy_server_port TEXT NOT NULL, "
		   "proxy_type TEXT NOT NULL CHECK "
		   "(proxy_type IN ('HTTP', 'SOCKS5')), "
		   "proxy_username TEXT NOT NULL, "
		   "smtp_localname TEXT NOT NULL)");
	query.exec("CREATE TRIGGER IF NOT EXISTS "
		   "poptastic_trigger "
		   "BEFORE INSERT ON poptastic "
		   "BEGIN "
		   "DELETE FROM poptastic; "
		   "END");
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

	query.exec("CREATE TABLE IF NOT EXISTS magnets ("
		   "magnet BLOB NOT NULL, "
		   "magnet_hash TEXT PRIMARY KEY NOT NULL, " // Keyed hash.
		   "one_time_magnet INTEGER NOT NULL DEFAULT 1)");
	query.exec("CREATE TABLE IF NOT EXISTS received ("
		   "expected_file_hash TEXT, "
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
		   "hash TEXT NOT NULL, " /*
					  ** SHA-1 hash of the file.
					  */
		   "missing_links BLOB NOT NULL, "
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
		   "status_control TEXT NOT NULL DEFAULT 'paused' CHECK "
		   "(status_control IN ('completed', 'deleted', 'paused', "
		   "'transmitting')), "
		   "total_size TEXT NOT NULL)");
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

void spoton_misc::logError(const QString &error)
{
  QReadLocker locker(&s_enableLogMutex);

  if(!s_enableLog)
    return;

  locker.unlock();

  if(error.trimmed().isEmpty())
    return;

  QFile file(homePath() + QDir::separator() + "error_log.dat");

  if(file.size() > 512 * 1024)
    /*
    ** Too large!
    */

    file.remove();

  if(file.open(QIODevice::Append | QIODevice::WriteOnly))
    {
      QDateTime now(QDateTime::currentDateTime());
#ifdef Q_OS_WIN32
      QString eol("\r\n");
#else
      QString eol("\n");
#endif

      file.write(now.toString().toLatin1());
      file.write(eol.toLatin1());
      file.write(error.trimmed().toLatin1());
      file.write(eol.toLatin1());
      file.write(eol.toLatin1());
      file.flush();
    }

  file.close();
}

QString spoton_misc::countryCodeFromIPAddress(const QString &ipAddress)
{
  const char *code = 0;

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  GeoIP *gi = 0;
  QFileInfo fileInfo;
  QHostAddress address(ipAddress);
  QSettings settings;
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
  else
    fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();

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
  GeoIP *gi = 0;
  QFileInfo fileInfo;
  QHostAddress address(ipAddress);
  QSettings settings;
  QString fileName("");

  if(address.protocol() == QAbstractSocket::IPv4Protocol)
    fileName = settings.value("gui/geoipPath4", "GeoIP.dat").toString();
  else
    fileName = settings.value("gui/geoipPath6", "GeoIP.dat").toString();

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
	QSqlQuery query1(db);
	QSqlQuery query2(db);

	query1.prepare("INSERT INTO urls (date_time_inserted, "
		       "description, hash, title, url) "
		       "VALUES (?, ?, ?, ?, ?)");

	for(int i = 0; i < list.size(); i++)
	  {
	    /*
	    ** 0: description
	    ** 1: title
	    ** 2: url
	    */

	    QList<QVariant> variants(list.at(i));
	    bool ok = true;

	    query1.bindValue
	      (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query1.bindValue
	      (1, crypt->encryptedThenHashed
	       (variants.value(0).toByteArray(), &ok).
	       toBase64());

	    if(ok)
	      query1.bindValue
		(2, crypt->keyedHash(variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(3, crypt->encryptedThenHashed
		 (variants.value(1).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.bindValue
		(4, crypt->encryptedThenHashed
		 (variants.value(2).toByteArray(), &ok).
		 toBase64());

	    if(ok)
	      query1.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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

  if(keyType == "chat" || keyType == "email" || keyType == "poptastic" ||
     keyType == "rosetta" || keyType == "url")
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

	if(ok)
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

void spoton_misc::retrieveSymmetricData
(QPair<QByteArray, QByteArray> &gemini,
 QByteArray &publicKey,
 QByteArray &symmetricKey,
 QByteArray &hashKey,
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

		    symmetricKey.resize
		      (static_cast<int> (symmetricKeyLength));
		    symmetricKey = spoton_crypt::strongRandomBytes
		      (static_cast<size_t> (symmetricKey.length()));
		    hashKey.resize
		      (spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);
		    hashKey = spoton_crypt::strongRandomBytes
		      (static_cast<size_t> (hashKey.length()));
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
	query.prepare("SELECT COUNT(*) "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND "
		      "neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(keyType.toLatin1(), &ok).toBase64());
	query.bindValue(1, publicKeyHash.toBase64());

	if(ok && query.exec())
	  if(query.next())
	    count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
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

void spoton_misc::moveSentMailToSentFolder(const QList<qint64> &oids,
					   spoton_crypt *crypt)
{
  QSettings settings;
  bool keep = settings.value("gui/saveCopy", true).toBool();

  if(keep)
    if(!crypt)
      {
	logError
	  ("spoton_misc::moveSentMailToSentFolder(): crypt is zero.");
	return;
      }

  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "email.db");

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

	if(settings.
	   value("gui/keepOnlyUserDefinedNeighbors", true).toBool())
	  query.exec("DELETE FROM neighbors WHERE "
		     "status_control <> 'blocked' AND user_defined = 0");

	query.exec("UPDATE neighbors SET "
		   "account_authenticated = NULL, "
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

QString spoton_misc::countryCodeFromName(const QString &country)
{
  QString code("");

  if(country == "United States")
    code = "us";

  return code;
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

void spoton_misc::savePublishedNeighbor(const QHostAddress &address,
					const quint16 port,
					const QString &p_transport,
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
  QString transport(p_transport.toLower());

#ifdef SPOTON_SCTP_ENABLED
  if(!(transport == "sctp" || transport == "tcp" || transport == "udp"))
    transport = "tcp";
#else
  if(!(transport == "tcp" || transport == "udp"))
    transport = "tcp";
#endif

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

	if(address.protocol() == QAbstractSocket::IPv4Protocol)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed("IPv4", &ok).toBase64());
	else
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed("IPv6", &ok).toBase64());

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
	    if(transport == "tcp")
	      {
		QSettings settings;
		QString error("");
		bool ok = true;
		int keySize = 2048;

		keySize = settings.value
		  ("gui/publishedKeySize", "2048").toInt(&ok);

		if(!ok)
		  keySize = 2048;
		else if(!(keySize == 2048 ||
			  keySize == 3072 ||
			  keySize == 4096 ||
			  keySize == 8192))
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
	  {
#ifdef SPOTON_SCTP_ENABLED
	    if(transport == "sctp" ||
	       transport == "tcp" ||
	       transport == "udp")
#else
	    if(transport == "tcp" || transport == "udp")
#endif
	      query.bindValue
		(24, crypt->encryptedThenHashed(transport.toLatin1(), &ok).
		 toBase64());
	    else
	      query.bindValue
		(24, crypt->encryptedThenHashed("tcp", &ok).toBase64());
	  }

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

	if(transport == "tcp")
	  query.bindValue
	    (26, "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH");
	else
	  query.bindValue(26, "N/A");

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_misc::purgeSignatureRelationships(const QSqlDatabase &db,
					      spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::purgeSignatureRelationships(): crypt "
	 "is zero.");
      return;
    }
  else if(!db.isOpen())
    {
      logError
	("spoton_misc::purgeSignatureRelationships(): db is closed.");
      return;
    }

  QList<QByteArray> list;

  list << "chat"
       << "email"
       << "poptastic"
       << "rosetta"
       << "url";

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
	(0, crypt->keyedHash(list.at(i) + "-signature", &ok).toBase64());

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
	  (0, crypt->keyedHash(list.at(i) + "-signature", &ok).toBase64());

      if(ok)
	query.exec();
    }
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
  integer = qAbs(settings.value("gui/emailRetrievalInterval",
				5).toInt(&ok));

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
  integer = qAbs(settings.value("gui/gcryctl_init_secmem", 262144).toInt(&ok));

  if(!ok)
    integer = 262144;
  else if(integer < 131072 || integer > 999999999)
    integer = 262144;

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

  if(!(str == "everaldo" || str == "nouve" || str == "nuvola"))
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
  else if(!(integer == 2048 || integer == 3072 ||
	    integer == 4096 || integer == 8192))
    integer = 2048;

  settings.insert("gui/kernelKeySize", integer);
  integer = qAbs(settings.value("gui/limitConnections", 10).toInt(&ok));

  if(!ok)
    integer = 10;
  else if(integer <= 0 || integer > 50)
    integer = 10;

  settings.insert("gui/limitConnections", integer);
  integer = qAbs(settings.value("gui/maximumEmailFileSize", 100).toInt(&ok));

  if(!ok)
    integer = 100;
  else if(integer < 1 || integer > 5000)
    integer = 100;

  settings.insert("gui/maximumEmailFileSize", integer);
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
	    integer == 4096 || integer == 8192))
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
  integer = qAbs(settings.value("gui/searchResultsPerPage", 10).toInt());

  if(!ok)
    integer = 10;
  else if(integer < 10 || integer > 100)
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
				262144).toInt(&ok));

  if(!ok)
    integer = 262144;
  else if(integer < 131072 || integer > 999999999)
    integer = 262144;

  settings.insert("kernel/gcryctl_init_secmem", integer);
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

void spoton_misc::enableLog(const bool state)
{
  QWriteLocker locker(&s_enableLogMutex);

  s_enableLog = state;
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

bool spoton_misc::isAcceptedIP(const QHostAddress &address,
			       const qint64 id,
			       spoton_crypt *crypt)
{
  if(address.isNull() || address.toString().isEmpty())
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
  qint64 count = 0;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM listeners_allowed_ips "
		      "WHERE ip_address_hash IN (?, ?) AND "
		      "listener_oid = ?");
	query.bindValue(0, crypt->keyedHash(address.toString().
					    toLatin1(), &ok).
			toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash("Any", &ok).toBase64());

	query.bindValue(2, id);

	if(ok)
	  if(query.exec())
	    if(query.next())
	      count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
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
	query.prepare("SELECT COUNT(*) FROM "
		      "listeners_accounts_consumed_authentications "
		      "WHERE data = ? AND listener_oid = ?");
	query.bindValue(0, hash.toBase64());
	query.bindValue(1, listenerOid);

	if(query.exec())
	  if(query.next())
	    exists = query.value(0).toLongLong() > 0;

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
	  if(!spoton_crypt::hashTypes().contains(str))
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

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

bool spoton_misc::isValidStarBeamMissingLinksMagnet(const QByteArray &magnet)
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

  starts << "fn="
	 << "ml="
	 << "ps="
	 << "xt=";

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(starts.contains("fn=") && str.startsWith("fn="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("fn=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ps=") && str.startsWith("ps="))
	{
	  str.remove(0, 3);

	  bool ok = true;
	  qint64 integer = str.toLongLong(&ok);

	  if(integer < 1024 || !ok) // Please see controlcenter.ui.
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ps=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("ml=") && str.startsWith("ml="))
	{
	  str.remove(0, 3);

	  if(str.isEmpty())
	    {
	      valid = false;
	      goto done_label;
	    }
	  else
	    {
	      starts.removeAll("ml=");
	      tokens += 1;
	    }
	}
      else if(starts.contains("xt=") && str.startsWith("xt="))
	{
	  str.remove(0, 3);

	  if(str != "urn:starbeam-missing-links")
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

  if(tokens == 4)
    valid = true;

 done_label:
  return valid;
}

void spoton_misc::prepareSignalHandler(void (*signal_handler) (int))
{
  QList<int> list;
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  struct sigaction act;
#endif
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

  while(!list.isEmpty())
    {
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
      act.sa_handler = signal_handler;
      sigemptyset(&act.sa_mask);
      act.sa_flags = 0;
      sigaction(list.takeFirst(), &act, 0);
#else
      signal(list.takeFirst(), signal_handler);
#endif
    }
}

void spoton_misc::vacuumAllDatabases(void)
{
  QStringList list;

  list << "buzz_channels.db"
       << "echo_key_sharing_secrets.db"
       << "email.db"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "listeners.db"
       << "neighbors.db"
       << "poptastic.db"
       << "shared.db"
       << "starbeam.db"
       << "urls_distillers_information.db"
       << "urls_key_information.db";

  while(!list.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = database(connectionName);

	db.setDatabaseName(homePath() + QDir::separator() + list.takeFirst());

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

QByteArray spoton_misc::findPublicKeyHashGivenHash
(const QByteArray &randomBytes,
 const QByteArray &hash, const QByteArray &hashKey,
 const QByteArray &hashType, spoton_crypt *crypt)
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

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

bool spoton_misc::isIpBlocked(const QHostAddress &address,
			      spoton_crypt *crypt)
{
  if(address.isNull() || address.toString().isEmpty())
    {
      logError
	("spoton_misc::isIpBlocked(): address is empty.");
      return true;
    }
  else if(!crypt)
    {
      logError
	("spoton_misc::isIpBlocked(): crypt "
	 "is zero.");
      return true;
    }

  QString connectionName("");
  qint64 count = -1;

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM neighbors WHERE "
		      "remote_ip_address_hash = ? AND "
		      "status_control = 'blocked'");
	query.bindValue
	  (0, crypt->
	   keyedHash(address.toString().toLatin1(), &ok).toBase64());

	if(ok)
	  if(query.exec())
	    if(query.next())
	      count = query.value(0).toLongLong();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return count > 0;
}

QPair<QByteArray, QByteArray> spoton_misc::decryptedAdaptiveEchoPair
(const QPair<QByteArray, QByteArray> pair, spoton_crypt *crypt)
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

QHostAddress spoton_misc::peerAddressAndPort(const int socketDescriptor,
					     quint16 *port)
{
  QHostAddress address;
  socklen_t length = 0;
#ifdef Q_OS_OS2
  struct sockaddr peeraddr;
#else
  struct sockaddr_storage peeraddr;
#endif

  length = sizeof(peeraddr);

  if(port)
    *port = 0;

  if(getpeername(socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
#ifndef Q_OS_OS2
      if(peeraddr.ss_family == AF_INET)
#endif
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
#ifndef Q_OS_OS2
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
#endif
    }

  return address;
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

QHash<QString, QVariant> spoton_misc::poptasticSettings(spoton_crypt *crypt,
							bool *ok)
{
  if(!crypt)
    {
      logError
	("spoton_misc::poptasticSettings(): crypt "
	 "is zero.");
      return QHash<QString, QVariant> ();
    }

  QHash<QString, QVariant> hash;
  QString connectionName("");

  {
    QSqlDatabase db = database(connectionName);

    db.setDatabaseName(homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT * FROM poptastic") && query.next())
	  {
	    QSqlRecord record(query.record());

	    for(int i = 0; i < record.count(); i++)
	      {
		if(record.fieldName(i) == "proxy_enabled" ||
		   record.fieldName(i) == "proxy_password" ||
		   record.fieldName(i) == "proxy_server_address" ||
		   record.fieldName(i) == "proxy_server_port" ||
		   record.fieldName(i) == "proxy_username" ||
		   record.fieldName(i).endsWith("_localname") ||
		   record.fieldName(i).endsWith("_password") ||
		   record.fieldName(i).endsWith("_server_address") ||
		   record.fieldName(i).endsWith("_server_port") ||
		   record.fieldName(i).endsWith("_username"))
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
	      if(ok)
		*ok = false;
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return hash;
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

  int secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= seconds))
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

	query.exec("PRAGMA synchronous = OFF");

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

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

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

  if(tokens >= 2 && tokens <= 5)
    valid = true;

 done_label:

  if(!valid)
    values.clear();

  return valid;
}

bool spoton_misc::saveReceivedStarBeamHash(const QSqlDatabase &db,
					   const QByteArray &hash,
					   const QString &oid,
					   spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::saveReceivedStarBeamHash(): crypt "
	 "is zero.");
      return false;
    }
  else if(!db.isOpen())
    {
      logError
	("spoton_misc::saveReceivedStarBeamHash(): db is closed.");
      return false;
    }

  QSqlQuery query(db);
  bool ok = true;

  query.prepare
    ("UPDATE received SET hash = ? WHERE OID = ?");

  if(hash.isEmpty())
    query.bindValue(0, QVariant::String);
  else
    query.bindValue
      (0, crypt->encryptedThenHashed(hash.toHex(), &ok).
       toBase64());

  query.bindValue(1, oid);

  if(ok)
    ok = query.exec();

  return ok;
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
	      c = new (std::nothrow) spoton_crypt(cipherType,
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

quint64 spoton_misc::databaseAccesses(void)
{
  QReadLocker locker(&s_dbMutex);

  return s_dbId;
}

bool spoton_misc::importUrl(const QByteArray &d, // Description
			    const QByteArray &t, // Title
			    const QByteArray &u, // URL
			    const QSqlDatabase &db,
			    const int maximum_keywords,
			    const bool disable_synchronous_sqlite_writes,
			    spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::importUrl(): crypt "
	 "is zero.");
      return false;
    }

  if(!db.isOpen())
    {
      logError
	("spoton_misc::importUrl(): db is closed.");
      return false;
    }

  QUrl url(QUrl::fromUserInput(u.trimmed()));

  if(url.isEmpty() || !url.isValid())
    {
      logError
	("spoton_misc::importUrl(): invalid URL.");
      return false;
    }

  QString scheme(url.scheme().toLower().trimmed());

  if(!spoton_common::ACCEPTABLE_URL_SCHEMES.contains(scheme))
    return false;

  url.setScheme(scheme);

  QByteArray all_keywords;
  QByteArray description(d.trimmed());
  QByteArray title(t.trimmed());
  bool separate = true;

  if(description.isEmpty())
    description = url.toString().toUtf8();
  else
    all_keywords = description;

  if(title.isEmpty())
    title = url.toString().toUtf8();
  else
    all_keywords.append(" ").append(title);

  QByteArray urlHash;
  bool ok = true;

  urlHash = crypt->keyedHash(url.toEncoded(), &ok).toHex();

  if(!ok)
    {
      logError
	("spoton_misc::importUrl(): keyedHash() failure.");
      return ok;
    }

  if(db.driverName() == "QSQLITE")
    {
      QSqlQuery query(db);

      query.setForwardOnly(true);
      query.prepare(QString("SELECT COUNT(*) FROM spot_on_urls_%1 WHERE "
			    "url_hash = ?").
		    arg(urlHash.mid(0, 2).constData()));
      query.bindValue(0, urlHash.constData());

      if(query.exec())
	{
	  if(query.next())
	    if(query.value(0).toLongLong() > 0)
	      return ok;
	}
      else
	{
	  ok = false;
	  logError(QString("spoton_misc::importUrl(): "
			   "%1.").arg(query.lastError().text()));
	  return ok;
 	}
    }

  if(!ok)
    return ok;

  QSqlQuery query(db);

  if(db.driverName() == "QPSQL")
    {
      query.prepare
	(QString("INSERT INTO spot_on_urls_%1 ("
		 "date_time_inserted, "
		 "description, "
		 "title, "
		 "unique_id, "
		 "url, "
		 "url_hash) VALUES (?, ?, ?, nextval('serial'), "
		 "?, ?)").
	 arg(urlHash.mid(0, 2).constData()));
      query.bindValue(0, QDateTime::currentDateTime().toString(Qt::ISODate));

      if(ok)
	query.bindValue
	  (1, crypt->encryptedThenHashed(description, &ok).
	   toBase64());

      if(ok)
	query.bindValue
	  (2, crypt->encryptedThenHashed(title, &ok).toBase64());

      if(ok)
	query.bindValue
	  (3, crypt->encryptedThenHashed(url.toEncoded(), &ok).
	   toBase64());

      query.bindValue(4, urlHash.constData());
    }
  else
    {
      qint64 id = -1;

      if(query.exec("INSERT INTO sequence VALUES (NULL)"))
	{
	  if(query.exec("SELECT MAX(value) FROM sequence"))
	    {
	      if(query.next())
		id = query.value(0).toLongLong();
	    }
	  else
	    {
	      ok = false;
	      logError(QString("spoton_misc::importUrl(): "
			       "%1.").arg(query.lastError().text()));
	    }
	}
      else
	{
	  ok = false;
	  logError(QString("spoton_misc::importUrl(): "
			   "%1.").arg(query.lastError().text()));
	}

      if(disable_synchronous_sqlite_writes)
	query.exec("PRAGMA synchronous = OFF");
      else
	query.exec("PRAGMA synchronous = NORMAL");

      query.prepare
	(QString("INSERT INTO spot_on_urls_%1 ("
		 "date_time_inserted, "
		 "description, "
		 "title, "
		 "unique_id, "
		 "url, "
		 "url_hash) VALUES (?, ?, ?, ?, ?, ?)").
	 arg(urlHash.mid(0, 2).constData()));
      query.bindValue(0, QDateTime::currentDateTime().toString(Qt::ISODate));

      if(ok)
	query.bindValue
	  (1, crypt->encryptedThenHashed(description, &ok).
	   toBase64());

      if(ok)
	query.bindValue
	  (2, crypt->encryptedThenHashed(title, &ok).toBase64());

      if(id != -1)
	query.bindValue(3, id);

      if(ok)
	query.bindValue
	  (4, crypt->encryptedThenHashed(url.toEncoded(), &ok).
	   toBase64());

      query.bindValue(5, urlHash.constData());
    }

  /*
  ** If a unique-constraint violation was raised, ignore it.
  */

  if(ok)
    if(!query.exec())
      if(!query.lastError().text().toLower().contains("unique"))
	{
	  ok = false;
	  logError(QString("spoton_misc::importUrl(): "
			   "%1.").arg(query.lastError().text()));
	}

  if(ok)
    if(all_keywords.isEmpty())
      separate = false;

  if(ok && separate)
    {
      QHash<QString, char> discovered;
      QSqlQuery query(db);
      QStringList keywords
	(QString::fromUtf8(all_keywords.toLower().constData()).
	 split(QRegExp("\\W+"), QString::SkipEmptyParts));
      int count = 0;

      if(db.driverName() == "QSQLITE")
	{
	  if(disable_synchronous_sqlite_writes)
	    query.exec("PRAGMA synchronous = OFF");
	  else
	    query.exec("PRAGMA synchronous = NORMAL");
	}

      for(int i = 0; i < keywords.size(); i++)
	{
	  if(!discovered.contains(keywords.at(i)))
	    discovered[keywords.at(i)] = '0';
	  else
	    continue;

	  QByteArray keywordHash;
	  bool ok = true;

	  keywordHash = crypt->keyedHash
	    (keywords.at(i).toUtf8(), &ok).toHex();

	  if(!ok)
	    continue;

	  query.prepare
	    (QString("INSERT INTO spot_on_keywords_%1 ("
		     "keyword_hash, "
		     "url_hash) "
		     "VALUES (?, ?)").arg(keywordHash.mid(0, 2).
					  constData()));
	  query.bindValue(0, keywordHash.constData());
	  query.bindValue(1, urlHash.constData());

	  if(query.exec())
	    count += 1;
	  else
	    logError(QString("spoton_misc::importUrl(): "
			     "%1.").arg(query.lastError().text()));

	  if(count >= maximum_keywords)
	    break;
	}
    }

  return ok;
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
		      "hash_type "            // 4
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
				   << list.value(4);
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
	query.exec("DELETE FROM magnets WHERE "
		   "one_time_magnet = 1");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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

spoton_crypt *spoton_misc::cryptFromForwardSecrecyMagnet
(const QByteArray &magnet)
{
  QList<QByteArray> list;

  if(!isValidForwardSecrecyMagnet(magnet, list))
    return 0;

  return new (std::nothrow) spoton_crypt(list.value(2),
					 list.value(0),
					 QByteArray(),
					 list.value(3),
					 list.value(1),
					 0,
					 0,
					 "");
}

QString spoton_misc::nameFromPublicKeyHash(const QByteArray &publicKeyHash,
					   spoton_crypt *crypt)
{
  if(!crypt)
    {
      logError
	("spoton_misc::nameFromPublicKeyHash(): crypt "
	 "is zero.");
      return "";
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
	    name = QString::fromUtf8
	      (crypt->
	       decryptedAfterAuthenticated(QByteArray::
					   fromBase64(query.
						      value(0).
						      toByteArray()),
					   &ok).constData());

	if(!ok)
	  name.clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return name;
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

  while(!list.isEmpty())
    {
      QByteArray str(list.takeFirst());

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

void spoton_misc::setTimeVariables(const QHash<QString, QVariant> &settings)
{
  /*
  ** Issue as soon as possible!
  */

  QList<int> defaults;
  QList<int> values;
  QStringList keys;

  defaults << spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC
	   << spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
	   << spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC
	   << spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC
	   << spoton_common::
              POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC
	   << spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
  keys << "gui/chat_time_delta"
       << "gui/forward_secrecy_time_delta"
       << "gui/gemini_time_delta"
       << "gui/kernel_cache_object_lifetime"
       << "gui/poptastic_forward_secrecy_time_delta"
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
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(4), 600);
  spoton_common::MAIL_TIME_DELTA_MAXIMUM =
    qBound(5, values.value(5), 600);
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
		      "forward_secrecy_encryption_key IS NOT NULL");

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
	QByteArray attachment(list.value(5));
	QByteArray attachmentName(list.value(6));
	QByteArray message(list.value(4));
	QByteArray name(list.value(2));
	QByteArray senderPublicKeyHash(list.value(1));
	QByteArray subject(list.value(3));
	QSqlQuery query(db);

	query.prepare("INSERT INTO folders "
		      "(date, folder_index, goldbug, hash, "
		      "message, message_code, "
		      "receiver_sender, receiver_sender_hash, "
		      "status, subject, participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	query.bindValue
	  (0, crypt->
	   encryptedThenHashed(QDateTime::currentDateTime().
			       toString(Qt::ISODate).
			       toLatin1(), &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed(QByteArray::number(0), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->keyedHash(message + subject,
				 &ok).toBase64());

	if(ok)
	  if(!message.isEmpty())
	    query.bindValue
	      (4, crypt->encryptedThenHashed(message,
					     &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  if(!name.isEmpty())
	    query.bindValue
	      (6, crypt->encryptedThenHashed(name,
					     &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (8, crypt->
	     encryptedThenHashed(QByteArray("Unread"), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->encryptedThenHashed(subject, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, crypt->
	     encryptedThenHashed(QByteArray::number(-1), &ok).
	     toBase64());

	if(ok)
	  if((ok = query.exec()))
	    {
	      if(!attachment.isEmpty() && !attachmentName.isEmpty())
		{
		  QVariant variant(query.lastInsertId());
		  qint64 id = query.lastInsertId().toLongLong();

		  if(variant.isValid())
		    {
		      QByteArray data;

		      data = qUncompress(attachment);

		      if(!data.isEmpty())
			{
			  query.prepare("INSERT INTO folders_attachment "
					"(data, folders_oid, name) "
					"VALUES (?, ?, ?)");
			  query.bindValue
			    (0, crypt->encryptedThenHashed(data,
							   &ok).toBase64());
			  query.bindValue(1, id);

			  if(ok)
			    query.bindValue
			      (2, crypt->
			       encryptedThenHashed(attachmentName,
						   &ok).toBase64());

			  if(ok)
			    ok = query.exec();
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
