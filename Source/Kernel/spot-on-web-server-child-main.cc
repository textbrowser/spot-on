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

#include <QCoreApplication>
#include <QDataStream>
#include <QDir>
#include <QHostInfo>
#include <QRegularExpression>
#include <QSqlQuery>
#include <QSslKey>
#include <QSslSocket>
#include <QSysInfo>
#include <QUrl>

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS) || defined(Q_OS_UNIX)
extern "C"
{
#include <sys/resource.h>
}
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-misc.h"
#include "spot-on-web-server-child-main.h"

QString spoton_common::POSTGRESQL_CONNECTION_OPTIONS =
  "connect_timeout=10;sslmode=verify-full";
QString spoton_common::SSL_CONTROL_STRING =
  "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";
QStringList spoton_common::ACCEPTABLE_URL_SCHEMES =
  QStringList() << "ftp" << "gopher" << "http" << "https";
QStringList spoton_common::SPOTON_ENCRYPTION_KEY_NAMES =
  QStringList() << "chat"
		<< "email"
		<< "open-library"
		<< "poptastic"
		<< "rosetta"
		<< "url";
QStringList spoton_common::SPOTON_SIGNATURE_KEY_NAMES =
  QStringList() << "chat-signature"
		<< "email-signature"
		<< "open-library-signature"
		<< "poptastic-signature"
		<< "rosetta-signature"
		<< "url-signature";
const int spoton_common::ACCOUNTS_RANDOM_BUFFER_SIZE;
const int spoton_common::BUZZ_MAXIMUM_ID_LENGTH;
const int spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::CHAT_MAXIMUM_REPLAY_QUEUE_SIZE;
const int spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::ELEGANT_STARBEAM_SIZE;
const int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::HARVEST_POST_OFFICE_LETTERS_INTERVAL;
const int spoton_common::KERNEL_CERTIFICATE_DAYS_VALID;
const int spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC;
const int spoton_common::LANE_WIDTH_DEFAULT;
const int spoton_common::LANE_WIDTH_MAXIMUM;
const int spoton_common::LANE_WIDTH_MINIMUM;
const int spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST;
const int spoton_common::MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS;
const int spoton_common::MAXIMUM_UDP_DATAGRAM_SIZE;
const int spoton_common::MINIMUM_STARBEAM_PULSE_SIZE;
const int spoton_common::MOSAIC_SIZE;
const int spoton_common::NAME_MAXIMUM_LENGTH;
const int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC;
const int spoton_common::POPTASTIC_MAXIMUM_EMAIL_SIZE;
const int spoton_common::POPTASTIC_STATUS_INTERVAL;
const int spoton_common::REAP_POST_OFFICE_LETTERS_INTERVAL;
const int spoton_common::SEND_QUEUED_EMAIL_INTERVAL;
const int spoton_common::SPOTON_HOME_MAXIMUM_PATH_LENGTH;
const int spoton_common::STATUS_INTERVAL;
const int spoton_common::STATUS_TEXT_MAXIMUM_LENGTH;
const int spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_MAXIMUM;
const int spoton_common::WAIT_FOR_BYTES_WRITTEN_MSECS_PREFERRED;
const qint64 spoton_common::MAXIMUM_BLUETOOTH_PACKET_SIZE;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE;
const qint64 spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH;
const qint64 spoton_common::MAXIMUM_SCTP_PACKET_SIZE;
const qint64 spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE;
const qint64 spoton_common::MAXIMUM_TCP_PACKET_SIZE;
const qint64 spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH;
const unsigned long int spoton_common::GEMINI_ITERATION_COUNT;
int spoton_common::CACHE_TIME_DELTA_MAXIMUM =
  spoton_common::CACHE_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::CHAT_TIME_DELTA_MAXIMUM =
  spoton_common::CHAT_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::GEMINI_TIME_DELTA_MAXIMUM =
  spoton_common::GEMINI_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::KERNEL_URL_DISPATCHER_INTERVAL =
  spoton_common::KERNEL_URL_DISPATCHER_INTERVAL_STATIC;
int spoton_common::MAIL_TIME_DELTA_MAXIMUM =
  spoton_common::MAIL_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM =
  spoton_common::POPTASTIC_FORWARD_SECRECY_TIME_DELTA_MAXIMUM_STATIC;
int spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM =
  spoton_common::POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM_STATIC;
static int s_bytesPerWrite = 4096;
static int s_waitForBytesWritten = 250;
static int s_waitForEncrypted = 1000;
static int s_waitForReadyRead = 10;
static quint64 s_urlLimit = 10;

int main(int argc, char *argv[])
{
#ifdef Q_OS_UNIX
  struct rlimit limit = {0, 0};

  setrlimit(RLIMIT_CORE, &limit); // Disable core files.
#endif

  auto rc = EXIT_SUCCESS;

  try
    {
      QByteArray settings;

      for(int i = 1; i < argc; i++)
	if(argv && argv[i] && strcmp(argv[i], "-s") == 0)
	  {
	    if(argc > i + 1)
	      settings = QByteArray::fromBase64(argv[i + 1]);

	    break;
	  }

      if(!settings.isEmpty())
	{
#ifdef Q_OS_MACOS
	  qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1");
#endif
	  QCoreApplication qapplication(argc, argv);
	  spoton_web_server_child_main thread(settings);

	  rc = qapplication.exec();
	}
      else
	rc = EXIT_FAILURE;
    }
  catch(const std::bad_alloc &exception)
    {
      std::cerr << "Spot-On-Web-Server-Child memory failure! Aborting!"
		<< std::endl;
      rc = EXIT_FAILURE;
    }
  catch(...)
    {
      std::cerr << "Spot-On-Web-Server-Child exception. Aborting!"
		<< std::endl;
      rc = EXIT_FAILURE;
    }

  return rc;
}

spoton_web_server_child_main::spoton_web_server_child_main
(QByteArray &settings):QObject()
{
  QDataStream stream(&settings, QIODevice::ReadOnly);

  stream >> m_settings;

  if(stream.status() != QDataStream::Ok)
    throw std::invalid_argument("Invalid data stream.");

  connect(this,
	  SIGNAL(keysReceived(void)),
	  this,
	  SLOT(slotKeysReceived(void)));
  spoton_misc::enableLog(true);

  auto keySize = m_settings.value("gui/kernelKeySize").toInt();
  auto port = static_cast<quint16> (m_settings.value("guiServerPort").toInt());

  if(keySize == 0)
    {
      connect(&m_kernelSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotKernelConnected(void)));
      m_kernelSocket.connectToHost("127.0.0.1", port);
    }
  else
    {
      connect(&m_kernelSocket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotKernelEncrypted(void)));
      connect(&m_kernelSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      &m_kernelSocket,
	      SLOT(ignoreSslErrors(void)));
      m_kernelSocket.connectToHostEncrypted("127.0.0.1", port);
    }
}

spoton_web_server_child_main::~spoton_web_server_child_main()
{
  QCoreApplication::exit(0);
}

QSqlDatabase spoton_web_server_child_main::urlDatabase
(QString &connectionName) const
{
  connectionName = spoton_misc::databaseName();

  QSqlDatabase db;

  if(m_settings.value("gui/sqliteSearch", true).toBool())
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
      auto const database
	(m_settings.value("gui/postgresql_database", "").toString().trimmed());
      auto const host
	(m_settings.value("gui/postgresql_host", "localhost").
	 toString().trimmed());
      auto const port = m_settings.value("gui/postgresql_port", 5432).toInt();
      auto const ssltls = m_settings.value("gui/postgresql_ssltls", true).
	toBool();
      auto ok = true;
      auto options
	(m_settings.value("gui/postgresql_web_connection_options",
			  spoton_common::POSTGRESQL_CONNECTION_OPTIONS).
	 toString().trimmed());

      if(!options.contains("connect_timeout="))
	options.append(";connect_timeout=10");

      if(m_crypt)
	{
	  name = m_crypt->decryptedAfterAuthenticated
	    (QByteArray::
	     fromBase64(m_settings.value("gui/postgresql_web_name", "").
			toByteArray()), &ok);

	  if(ok)
	    password = m_crypt->decryptedAfterAuthenticated
	      (QByteArray::
	       fromBase64(m_settings.value("gui/postgresql_web_password", "").
			  toByteArray()), &ok);
	}

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

  return db;
}

void spoton_web_server_child_main::process
(const QPair<QByteArray, QByteArray> &credentials)
{
  QScopedPointer<QSslSocket> socket(new QSslSocket());

  if(!socket->setSocketDescriptor(m_socketDescriptor))
    {
      QTimer::singleShot(1000, QCoreApplication::instance(), SLOT(quit(void)));
      spoton_misc::closeSocket(m_socketDescriptor);
      return;
    }

  connect(socket.data(),
	  SIGNAL(disconnected(void)),
	  QCoreApplication::instance(),
	  SLOT(quit(void)));

  /*
  ** Prepare the socket!
  */

  auto const readBufferSize =
    qMax(0,
	 m_settings.value("MAXIMUM_KERNEL_WEB_SERVER_SOCKET_READ_BUFFER_SIZE",
			  spoton_common::
			  MAXIMUM_KERNEL_WEB_SERVER_SOCKET_READ_BUFFER_SIZE).
	 toInt());

  socket->setReadBufferSize(static_cast<qint64> (readBufferSize));
  socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

  if(!credentials.first.isEmpty())
    {
      QSslConfiguration configuration;
      auto const keySize = m_settings.value
	("WEB_SERVER_KEY_SIZE", 3072).toInt();
      auto const sslCS
	(m_settings.value("gui/sslControlString",
			  spoton_common::SSL_CONTROL_STRING).
	 toString().trimmed());

      configuration.setLocalCertificate(QSslCertificate(credentials.first));
      configuration.setPeerVerifyMode(QSslSocket::VerifyNone);

      QSslKey key;

      if(keySize < 1024)
	key = QSslKey(credentials.second, QSsl::Ec);
      else
	key = QSslKey(credentials.second, QSsl::Rsa);

      configuration.setPrivateKey(key);
      configuration.setSslOption(QSsl::SslOptionDisableCompression, true);
      configuration.setSslOption(QSsl::SslOptionDisableEmptyFragments, true);
      configuration.setSslOption
	(QSsl::SslOptionDisableLegacyRenegotiation, true);
#if QT_VERSION >= 0x050501
      configuration.setSslOption
	(QSsl::SslOptionDisableSessionPersistence, true);
      configuration.setSslOption(QSsl::SslOptionDisableSessionSharing, true);
#endif
      configuration.setSslOption
	(QSsl::SslOptionDisableSessionTickets,
	 m_settings.value("WEB_SERVER_SSL_OPTION_DISABLE_SESSION_TICKETS",
			  true).toBool());
#if QT_VERSION >= 0x050501
      spoton_crypt::setSslCiphers
	(QSslConfiguration::supportedCiphers(), sslCS, configuration);
#else
      spoton_crypt::setSslCiphers
	(socket->supportedCiphers(), sslCS, configuration);
#endif
      socket->setSslConfiguration(configuration);
      socket->startServerEncryption();
    }

  if(!credentials.first.isEmpty())
    for(int i = 1; i <= qCeil(30000 / qMax(10, s_waitForEncrypted)); i++)
      if(socket->state() == QAbstractSocket::ConnectedState &&
	 socket->waitForEncrypted(s_waitForEncrypted))
	break;

  /*
  ** Read the socket data!
  */

  for(int i = 1; i <= qCeil(30000 / qMax(10, s_waitForReadyRead)); i++)
    if(socket->bytesAvailable() > 0 ||
       (socket->state() == QAbstractSocket::ConnectedState &&
	socket->waitForReadyRead(s_waitForReadyRead)))
      break;

  QByteArray data;

  while(socket->bytesAvailable() > 0)
    {
      data.append(socket->readAll().toLower());

      if(data.length() > readBufferSize)
	break;

      if(socket->state() == QAbstractSocket::ConnectedState)
	socket->waitForReadyRead(s_waitForReadyRead);
      else
	break;
    }

  if(data.endsWith("\r\n\r\n") &&
     data.simplified().trimmed().startsWith("get / http/1."))
    writeDefaultPage(socket.data());
  else if(data.endsWith("\r\n\r\n") &&
	  data.simplified().trimmed().startsWith("get /about"))
    {
      QLocale const locale;
      QString about("");

      about.append("<p><font size=3>");
      about.append("<b>Build ABI:</b> ");
      about.append(QSysInfo::buildAbi());
      about.append("<br>");
      about.append("<b>Build CPU:</b> ");
      about.append(QSysInfo::buildCpuArchitecture());
      about.append("<br>");
      about.append("<b>CPU:</b> ");
      about.append(QSysInfo::currentCpuArchitecture());
      about.append("<br>");
      about.append("<b>Kernel Type:</b> ");
      about.append(QSysInfo::kernelType());
      about.append("<br>");
      about.append("<b>Kernel Version:</b> ");
      about.append(QSysInfo::kernelVersion());
      about.append("<br>");
      about.append("<b>Machine Host Name:</b> ");
#if QT_VERSION < 0x050600
      about.append(QHostInfo::localHostName());
#else
      about.append(QSysInfo::machineHostName());
#endif
      about.append("<br>");
      about.append("<b>Product Type:</b> ");
      about.append(QSysInfo::productType());
      about.append("<br>");
      about.append("<b>Product Version:</b> ");
      about.append(QSysInfo::productVersion());
      about.append("<br>");
      about.append("<b>Spot-On Kernel Uptime Minute(s):</b> ");
      about.append
	(locale.toString(m_settings.value("uptimeMinutes").toLongLong()));
      about.append("<br>");

      QString connectionName("");
      auto db(urlDatabase(connectionName));

      about.append("<b>Total Spot-On Web Pages:</b> ");
      about.append(locale.toString(spoton_misc::urlsCount(db)));
      about.append("</font></p>");
      db.close();
      db = QSqlDatabase();
      QSqlDatabase::removeDatabase(connectionName);

      QString html("");

      html.append(m_search);
      html.remove("</html>");
      html.append(about);
      html.append("</html>");
      write(socket.data(),
	    "HTTP/1.1 200 OK\r\nContent-Length: " +
	    QByteArray::number(html.toUtf8().length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");
      write(socket.data(), html.toUtf8());
    }
  else if(data.endsWith("\r\n\r\n") &&
	  data.simplified().trimmed().startsWith("get /current="))
    {
      data = data.simplified().trimmed().mid(5); // get /c <- c
      data = data.mid(0, data.indexOf(' '));

      const QPair<QString, QString> address
	(socket->localAddress().toString(),
	 QString::number(socket->localPort()));

      process(socket.data(), data, address);
    }
  else if(data.endsWith("\r\n\r\n") &&
	  data.simplified().trimmed().startsWith("get /local-"))
    {
      if(m_settings.value("gui/web_server_serve_local_content", false).toBool())
	{
	  data = data.simplified().trimmed().mid(11); // get /local-x <- x
	  data = data.mid(0, data.indexOf(' '));
	  processLocal(socket.data(), data);
	}
      else
	writeDefaultPage(socket.data(), true);
    }
  else if(data.endsWith("\r\n\r\n") &&
	  data.simplified().trimmed().startsWith("get /"))
    writeDefaultPage(socket.data(), true);
  else if(data.simplified().startsWith("post / http/1.") ||
	  data.simplified().startsWith("post /current="))
    {
      data = data.simplified().trimmed();
      data = data.mid(data.lastIndexOf("current="));
      data = data.mid(0, data.indexOf(' '));

      const QPair<QString, QString> address
	(socket->localAddress().toString(),
	 QString::number(socket->localPort()));

      process(socket.data(), data, address);
    }
  else if(!data.isEmpty())
    writeDefaultPage(socket.data(), true);

  QTimer::singleShot(1000, QCoreApplication::instance(), SLOT(quit(void)));
}

void spoton_web_server_child_main::process
(QSslSocket *socket,
 const QByteArray &data,
 const QPair<QString, QString> &address)
{
  if(!socket)
    return;

  auto list(QString(data.mid(data.indexOf("current=") + 8)).split("&"));

  if(list.size() != 4)
    {
      writeDefaultPage(socket, true);
      return;
    }

  quint64 current = 0;
  quint64 offset = 0;
  quint64 pages = 0;

  for(int i = 0; i < list.size(); i++)
    list.replace
      (i,
       QString(list.at(i)).remove("link=").remove("pages=").remove("search="));

  current = list.value(0).toULongLong();
  offset = current * s_urlLimit;
  pages = qMax(1ULL, list.value(2).toULongLong());

  if(current > pages)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QScopedPointer<spoton_crypt> crypt
    (spoton_misc::retrieveUrlCommonCredentials(m_crypt.data()));

  if(!crypt)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QElapsedTimer elapsed;

  elapsed.start();

  QString connectionName("");
  QString html("");
  auto db(urlDatabase(connectionName));

  if(db.isOpen())
    {
      QString particles(data.mid(data.indexOf("current=")));
      QString querystr("");
      QString search("");
      auto const link(list.value(1).toLower());
      quint64 count = 0;

      search = list.value(3);
      search = spoton_misc::percentEncoding(search);
      search.replace("+", " ");

      if(search.trimmed().isEmpty())
	{
	  querystr.append(m_emptyQuery);
	  querystr.append(" ORDER BY 5 DESC ");
	  querystr.append(QString(" LIMIT %1 ").arg(s_urlLimit));
	  querystr.append(QString(" OFFSET %1 ").arg(offset));
	}
      else
	{
	  QSet<QString> keywords;
	  QString keywordsearch("");
	  QStringList keywordsearches;
	  auto ok = true;
	  auto originalSearch(search);

	  originalSearch.replace("&#34;", "\"");
	  originalSearch.replace("&#38;", "&");
	  originalSearch.replace("&#47;", "/");
	  originalSearch.replace("&#58;", ":");
	  originalSearch.replace("&#61;", "=");
	  originalSearch.replace("&#63;", "?");

	  do
	    {
	      auto const s = originalSearch.indexOf('"');
	      int e = -1;

	      if(s < 0)
		break;

	      e = originalSearch.indexOf('"', s + 1);

	      if(e < 0 || e - s - 1 <= 0)
		break;

	      auto const bundle
		(originalSearch.mid(s + 1, e - s - 1).trimmed());

	      if(bundle.isEmpty())
		break;

	      keywords.clear();
	      keywordsearch.clear();
	      originalSearch.remove(s, e - s + 1);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	      auto const list
		(bundle.split(QRegularExpression("\\W+"), Qt::SkipEmptyParts));
#else
	      auto const list
		(bundle.split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

	      for(int i = 0; i < list.size(); i++)
		keywords.insert(list.at(i));

	      QSetIterator<QString> it(keywords);

	      while(it.hasNext())
		{
		  auto const keywordHash
		    (crypt->keyedHash(it.next().toUtf8(), &ok));

		  if(!ok)
		    continue;

		  auto const keywordHashHex(keywordHash.toHex());

		  keywordsearch.append
		     (QString("SELECT url_hash FROM "
			      "spot_on_keywords_%1 WHERE "
			      "keyword_hash = '%2' ").
		      arg(keywordHashHex.mid(0, 2).constData()).
		      arg(keywordHashHex.constData()));

		  if(it.hasNext())
		    keywordsearch.append(" INTERSECT ");
		}

	      keywordsearches << keywordsearch;
	    }
	  while(true);

	  keywords.clear();
	  keywordsearch.clear();

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	  auto const list
	    (originalSearch.toLower().trimmed().
	     split(QRegularExpression("\\W+"), Qt::SkipEmptyParts));
#else
	  auto const list
	    (originalSearch.toLower().trimmed().
	     split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

	  for(int i = 0; i < list.size(); i++)
	    keywords.insert(list.at(i));

	  QSetIterator<QString> it(keywords);

	  while(it.hasNext())
	    {
	      auto const keywordHash
		(crypt->keyedHash(it.next().toUtf8(), &ok));

	      if(!ok)
		continue;

	      auto const keywordHashHex(keywordHash.toHex());

	      keywordsearch.append
		(QString("SELECT url_hash FROM "
			 "spot_on_keywords_%1 WHERE "
			 "keyword_hash = '%2' ").
		 arg(keywordHashHex.mid(0, 2).constData()).
		 arg(keywordHashHex.constData()));

	      if(it.hasNext())
		keywordsearch.append(" UNION ALL ");
	    }

	  if(!keywords.isEmpty())
	    keywordsearches << keywordsearch;

	  keywordsearch.clear();

	  QMap<QString, QString> prefixes;

	  for(int i = 0; i < keywordsearches.size(); i++)
	    {
	      QSqlQuery query(db);

	      query.setForwardOnly(true);

	      if(query.exec(keywordsearches.at(i)))
		while(query.next())
		  {
		    auto const hash(query.value(0).toString());
		    auto const prefix(hash.mid(0, 2));

		    if(!prefixes.contains(prefix))
		      prefixes.insert(prefix, QString("'%1'").arg(hash));
		    else
		      {
			auto str(prefixes.value(prefix));

			str.append(QString(", '%1'").arg(hash));
			prefixes.insert(prefix, str);
		      }
		  }
	    }

	  if(!prefixes.isEmpty())
	    {
	      QMapIterator<QString, QString> it(prefixes);

	      while(it.hasNext())
		{
		  it.next();

		  /*
		  ** For absolute correctness, we ought to use parameters in
		  ** the SQL queries.
		  */

		  querystr.append
		    (QString("SELECT title, "      // 0
			     "url, "               // 1
			     "description, "       // 2
			     "url_hash, "          // 3
			     "date_time_inserted " // 4
			     "FROM spot_on_urls_%1 WHERE url_hash IN (%2) ").
		     arg(it.key()).arg(it.value()));

		  if(it.hasNext())
		    querystr.append(" UNION ALL ");
		}

	      querystr.append(" ORDER BY 5 DESC ");
	      querystr.append(QString(" LIMIT %1 ").arg(s_urlLimit));
	      querystr.append(QString(" OFFSET %1 ").arg(offset));
	    }
	}

      QSqlQuery query(db);

      if(!querystr.trimmed().isEmpty())
	{
	  query.setForwardOnly(true);
	  query.prepare(querystr);
	}

      if(query.exec() || querystr.trimmed().isEmpty())
	{
	  int position = -1;

	  html.append(m_search);
	  html.replace("value=\"\"", QString("value=\"%1\"").arg(search));
	  html.remove("</html>");
	  html.append("<p><font color=\"#696969\" size=2>");
	  position = html.length();
	  html.append("<div id=\"footer\">");

	  while(query.next())
	    {
	      QByteArray bytes;
	      QString description("");
	      QString title("");
	      QUrl url;
	      auto const date(query.value(4).toString().trimmed());
	      auto const urlHash(query.value(3).toByteArray());
	      auto ok = true;

	      bytes = crypt-> decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(2).toByteArray()), &ok);
	      description = QString::fromUtf8
		(bytes.constData(), bytes.length()).trimmed();

	      if(ok)
		{
		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
		  title = QString::fromUtf8
		    (bytes.constData(), bytes.length()).trimmed();
		  title = spoton_misc::removeSpecialHtmlTags(title).trimmed();
		}

	      if(ok)
		{
		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()), &ok);
		  url = QUrl::fromUserInput
		    (QString::fromUtf8(bytes.constData(), bytes.length()));
		}

	      if(ok)
		{
		  description = spoton_misc::removeSpecialHtmlTags(description);

	          if(description.length() > spoton_common::
		     MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS)
		    {
		      description = description.mid
			(0, spoton_common::
			 MAXIMUM_DESCRIPTION_LENGTH_SEARCH_RESULTS).trimmed();

		      if(description.endsWith("..."))
			{
			}
		      else if(description.endsWith(".."))
			description.append(".");
		      else if(description.endsWith("."))
			description.append("..");
		      else
			description.append("...");
		    }

		  auto const scheme(url.scheme().toLower().trimmed());

		  url.setScheme(scheme);

		  if(title.isEmpty())
		    title = spoton_misc::urlToEncoded(url);

		  html.append("<p>");
		  html.append("<a href=\"");
		  html.append(spoton_misc::urlToEncoded(url));
		  html.append("\" target=\"_blank\"><font color=\"#0000EE\">");
		  html.append(title);
		  html.append("</font></a>");

		  if(m_settings.value("gui/web_server_serve_local_content",
				      false).toBool())
		    {
		      if(!socket->isEncrypted())
			html.append(" | <a href=\"http://");
		      else
			html.append(" | <a href=\"https://");

		      html.append(address.first);
		      html.append(":");
		      html.append(address.second);
		      html.append("/local-");
		      html.append(urlHash);
		      html.append
			("\" target=\"_blank\"><font color=\"#0000EE\">");
		      html.append("View Locally");
		      html.append("</font></a>");
		    }

		  html.append("<br>");
		  html.append
		    (QString("<font color=\"green\" size=2>%1</font>").
		     arg(spoton_misc::urlToEncoded(url).constData()));

		  if(!description.isEmpty())
		    {
		      html.append("<br>");
		      html.append
			(QString("<font color=\"#696969\" size=2>%1</font>").
			 arg(description));
		    }

		  html.append("<br>");
		  html.append
		    (QString("<font color=\"#2f4f4f\" size=2>%1</font>").
		     arg(date));
		  html.append("</p>");
		  count += 1;
		}
	    }

	  if(count == 0)
	    count = 1;

	  if(link == "n")
	    {
	      current += 1;
	      offset += s_urlLimit;
	    }
	  else
	    {
	      current = link.toULongLong();
	      offset = (current - 1) * s_urlLimit;
	    }

	  QString str("");
	  quint64 lower = 0;
	  quint64 upper = 0;

	  // 1  ... 10.
	  // 11 ... 20.
	  // Find the lower and upper bounds.

	  lower = offset / s_urlLimit + 1;
	  upper = lower + s_urlLimit;

	  if(pages < upper)
	    upper = pages;

	  if(upper > s_urlLimit) // Number of pages to display.
	    lower = upper - s_urlLimit;
	  else
	    lower = 1;

	  search.replace(" ", "+");
	  html.append("<p class=\"footer\">");

	  if(!(current >= lower && current <= upper))
	    current = lower;

	  for(quint64 i = lower; i <= upper; i++)
	    if(i != current)
	      {
		particles = QString
		  ("current=%1&link=%2&pages=%3&search=%4").
		  arg(i - 1).
		  arg(i).
		  arg(pages).
		  arg(search);
		str.append
		  (QString(" <a href=\"%1\"><font color=\"#c0c0c0\">%2</font>"
			   "</a> ").arg(particles).arg(i));
	      }
	    else
	      str.append
		(QString(" <font color=\"#696969\">| %1 |</font> ").arg(i));

	  if(count >= s_urlLimit)
	    {
	      if(current + 1 <= pages)
		particles = QString("current=%1&link=n&pages=%2&search=%3").
		  arg(current).arg(pages).arg(search);
	      else
		particles = QString("current=%1&link=n&pages=%2&search=%3").
		  arg(current).arg(pages + 1).arg(search);

	      str.append(QString(" <a href=\"%1\">></a> ").arg(particles));
	    }

	  if(current != 1)
	    {
	      particles = QString
		("current=%1&link=%2&pages=%3&search=%4").
		arg(current - 2).
		arg(current - 1).
		arg(pages).
		arg(search);
	      str.prepend
		(QString(" <a href=\"%1\"><</a> ").arg(particles));
	    }

	  str = str.trimmed();
	  html.append(str);
	  html.append("</p></div></html>");
	  html.insert
	    (position,
	     QString("Query completed in %1 second(s).</font></p>").
	     arg(qAbs(static_cast<double> (elapsed.elapsed())) / 1000.0));
	}
    }

  db.close();
  db = QSqlDatabase();
  QSqlDatabase::removeDatabase(connectionName);

  if(html.isEmpty())
    {
      write(socket,
	    "HTTP/1.1 200 OK\r\nContent-Length: " +
	    QByteArray::number(m_search.length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");
      write(socket, m_search);
    }
  else
    {
      write(socket,
	    "HTTP/1.1 200 OK\r\nContent-Length: " +
	    QByteArray::number(html.toUtf8().length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");
      write(socket, html.toUtf8());
    }
}

void spoton_web_server_child_main::processLocal
(QSslSocket *socket, const QByteArray &data)
{
  if(!socket)
    return;

  QScopedPointer<spoton_crypt> crypt
    (spoton_misc::retrieveUrlCommonCredentials(m_crypt.data()));

  if(!crypt)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QByteArray html;
  QString connectionName("");
  auto db(urlDatabase(connectionName));

  if(db.isOpen())
    {
      QSqlQuery query(db);
      QString querystr("");

      querystr.append("SELECT content FROM spot_on_urls_");
      querystr.append(data.mid(0, 2).constData());
      querystr.append(" WHERE url_hash = ?");
      query.setForwardOnly(true);
      query.prepare(querystr);
      query.addBindValue(data.constData());

      if(query.exec() && query.next())
	{
	  QByteArray content;
	  auto ok = true;

	  content = crypt->decryptedAfterAuthenticated
	    (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	  if(ok)
	    {
	      content = qUncompress(content);

	      if(!content.isEmpty())
		{
		  QFileInfo fileInfo
		    (m_settings.
		     value("WEB_SERVER_HTML2TEXT_PATH").toString().trimmed());

		  if(fileInfo.isExecutable())
		    {
		      QProcess process;

		      process.setArguments(QStringList() << "-utf8");
		      process.setProgram(fileInfo.absoluteFilePath());
		      process.start();
		      process.waitForStarted();
		      process.write(content);
		      process.waitForBytesWritten();
		      process.closeWriteChannel();
		      process.waitForFinished();

		      if(process.exitStatus() == QProcess::NormalExit)
			{
			  auto const data(process.readAllStandardOutput());

			  if(!data.isEmpty())
			    {
			      content = data;
			      content.replace("\n", "<br>");
			    }
			}

		      process.kill();
		      process.terminate();
		    }

		  html = "HTTP/1.1 200 OK\r\nContent-Length: " +
		    QByteArray::number(content.length()) +
		    "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
		  html.append(content);
		}
	    }
	}
    }

  db.close();
  db = QSqlDatabase();
  QSqlDatabase::removeDatabase(connectionName);

  if(html.isEmpty())
    writeDefaultPage(socket, true);
  else
    write(socket, html);
}

void spoton_web_server_child_main::slotKernelConnected(void)
{
  connect(&m_kernelSocket,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotKernelRead(void)),
	  Qt::UniqueConnection);
  m_kernelSocket.write("requestkeys\n");
}

void spoton_web_server_child_main::slotKernelEncrypted(void)
{
  connect(&m_kernelSocket,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotKernelRead(void)),
	  Qt::UniqueConnection);
  m_kernelSocket.write("requestkeys\n");
}

void spoton_web_server_child_main::slotKernelRead(void)
{
  auto bytes(m_kernelSocket.readAll());

  while(bytes.size() < 500 && m_kernelSocket.bytesAvailable() > 0)
    bytes.append(m_kernelSocket.readAll());

  if(bytes.endsWith("\n") || bytes.size() >= 500)
    {
      auto const list(bytes.trimmed().split('_'));

      if(list.size() == 6)
	{
	  auto const cipherType(QString(list.at(0)));
	  auto const hashType(QString(list.at(1)));
	  auto const iterationCount = static_cast<unsigned long int>
	    (list.at(3).toInt());
	  auto const saltLength = list.at(2).toInt();

	  m_crypt.reset
	    (new spoton_crypt(cipherType,
			      hashType,
			      QByteArray(),
			      QByteArray::fromBase64(list.at(4)),
			      QByteArray::fromBase64(list.at(5)),
			      saltLength,
			      iterationCount,
			      "chat"));
	  emit keysReceived();
	}
      else
	QTimer::singleShot
	  (1000, QCoreApplication::instance(), SLOT(quit(void)));

      m_kernelSocket.abort();
      m_kernelSocket.close();
    }
}

void spoton_web_server_child_main::slotKeysReceived(void)
{
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
	  m_emptyQuery.append
	    (QString("SELECT title, "      // 0
		     "url, "               // 1
		     "description, "       // 2
		     "url_hash, "          // 3
		     "date_time_inserted " // 4
		     "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	else
	  m_emptyQuery.append
	    (QString("SELECT title, "      // 0
		     "url, "               // 1
		     "description, "       // 2
		     "url_hash, "          // 3
		     "date_time_inserted " // 4
		     "FROM spot_on_urls_%1%2 UNION ALL ").arg(c1).arg(c2));
      }

  QFile file(":/search.html");

  file.open(QFile::ReadOnly);
  m_search = file.readAll();
  file.close();

  QPair<QByteArray, QByteArray> credentials;

  if(m_crypt && m_settings.value("https").toBool())
    {
      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() +
	   QDir::separator() +
	   "kernel_web_server.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);

	    if(query.exec("SELECT certificate, " // 0
			  "private_key "         // 1
			  "FROM kernel_web_server"))
	      while(query.next())
		{
		  auto ok = true;

		  credentials.first = m_crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(0).toByteArray()),
		     &ok);
		  credentials.second = m_crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);
		}

	    db.close();
	  }

	QSqlDatabase::removeDatabase(connectionName);
      }
    }

  m_socketDescriptor = m_settings.value("socketDescriptor").toLongLong();
  process(credentials);
}

void spoton_web_server_child_main::write
(QSslSocket *socket, const QByteArray &data)
{
  if(!socket || data.isEmpty())
    return;

  for(int i = 0;;)
    {
      if(i >= data.length() ||
	 socket->state() != QAbstractSocket::ConnectedState)
	break;

      auto const rc = socket->write(data.mid(i, s_bytesPerWrite));

      socket->flush();

      if(rc > 0)
	{
	  i += static_cast<int> (rc);
	  socket->waitForBytesWritten(s_waitForBytesWritten);
	}
    }
}

void spoton_web_server_child_main::writeDefaultPage
(QSslSocket *socket, const bool redirect)
{
  if(!socket)
    return;

  if(redirect)
    {
      /*
      ** New URL for the client.
      */

      QByteArray location;

      if(!socket->isEncrypted())
	location = "http://";
      else
	location = "https://";

      location.append(socket->localAddress().toString().toUtf8() +
		      ":" +
		      QByteArray::number(socket->localPort()));
      write(socket,
	    "HTTP/1.1 301 Moved Permanently\r\nContent-Length: " +
	    QByteArray::number(m_search.length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n"
	    "Location: " +
	    location +
	    "\r\n\r\n");
    }
  else
    write(socket,
	  "HTTP/1.1 200 OK\r\nContent-Length: " +
	  QByteArray::number(m_search.length()) +
	  "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");

  write(socket, m_search);
}
