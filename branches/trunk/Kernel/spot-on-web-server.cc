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

#include <QHostInfo>
#include <QSqlQuery>
#include <QSslKey>
#include <QSslSocket>
#include <QSysInfo>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-socket-options.h"
#include "spot-on-web-server.h"
#include "spot-on-kernel.h"

static QByteArray s_search;
static QString s_emptyQuery;
static int s_bytesPerWrite = 4096;

/*
** Wait for at least 30 seconds. Be careful!
*/

static int s_waitForBytesWritten = 250;
static int s_waitForEncrypted = 1000;
static int s_waitForReadyRead = 10;
static quint64 s_urlLimit = 10;

void spoton_web_server_tcp_server::incomingConnection(qintptr socketDescriptor)
{
  emit newConnection(static_cast<qint64> (socketDescriptor));
}

spoton_web_server::spoton_web_server(QObject *parent):QObject(parent)
{
  m_abort = new QAtomicInt(0);
  m_http = new spoton_web_server_tcp_server(this);
  m_httpClientCount = new QAtomicInt(0);
  m_https = new spoton_web_server_tcp_server(this);
  m_httpsClientCount = new QAtomicInt(0);

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
	  s_emptyQuery.append
	    (QString("SELECT title, "      // 0
		     "url, "               // 1
		     "description, "       // 2
		     "url_hash, "          // 3
		     "date_time_inserted " // 4
		     "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	else
	  s_emptyQuery.append
	    (QString("SELECT title, "      // 0
		     "url, "               // 1
		     "description, "       // 2
		     "url_hash, "          // 3
		     "date_time_inserted " // 4
		     "FROM spot_on_urls_%1%2 UNION ").arg(c1).arg(c2));
      }

  QFile file(":/search.html");

  file.open(QFile::ReadOnly);
  s_search = file.readAll();
  file.close();
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(m_http,
	  SIGNAL(newConnection(const qint64)),
	  this,
	  SLOT(slotHttpClientConnected(const qint64)));
  connect(m_https,
	  SIGNAL(newConnection(const qint64)),
	  this,
	  SLOT(slotHttpsClientConnected(const qint64)));
  m_generalTimer.start(2500);
}

spoton_web_server::~spoton_web_server()
{
  m_abort->fetchAndStoreOrdered(1);
  m_generalTimer.stop();
  m_http->close();
  m_https->close();

  foreach(spoton_web_server_thread *thread,
	  findChildren<spoton_web_server_thread *> ())
    thread->wait();

  delete m_abort;
  delete m_httpClientCount;
  delete m_httpsClientCount;
}

int spoton_web_server::httpClientCount(void) const
{
  return m_httpClientCount->fetchAndAddOrdered(0);
}

int spoton_web_server::httpsClientCount(void) const
{
  return m_httpsClientCount->fetchAndAddOrdered(0);
}

void spoton_web_server::slotHttpClientConnected(const qint64 socketDescriptor)
{
  if(m_httpClientCount->fetchAndAddOrdered(0) >=
     spoton_kernel::setting("gui/soss_maximum_clients", 10).toInt() ||
     socketDescriptor < 0)
    {
      spoton_misc::closeSocket(socketDescriptor);
      return;
    }

  spoton_web_server_thread *thread = new spoton_web_server_thread
    (m_abort, this, QPair<QByteArray, QByteArray> (), socketDescriptor);

  connect
    (thread, SIGNAL(finished(void)), this, SLOT(slotHttpThreadFinished(void)));
  connect(thread, SIGNAL(finished(void)), thread, SLOT(deleteLater(void)));
  m_httpClientCount->fetchAndAddOrdered(1);
  thread->start();
}

void spoton_web_server::slotHttpThreadFinished(void)
{
  m_httpClientCount->fetchAndAddOrdered(-1);
}

void spoton_web_server::slotHttpsClientConnected(const qint64 socketDescriptor)
{
  if(m_httpsClientCount->fetchAndAddOrdered(0) >=
     spoton_kernel::setting("gui/soss_maximum_clients", 10).toInt() ||
     m_https->certificate().isEmpty() ||
     m_https->privateKey().isEmpty() ||
     socketDescriptor < 0)
    {
      spoton_misc::closeSocket(socketDescriptor);
      return;
    }

  QPair<QByteArray, QByteArray> credentials
    (m_https->certificate(), m_https->privateKey());
  spoton_web_server_thread *thread = new spoton_web_server_thread
    (m_abort, this, credentials, socketDescriptor);

  connect
    (thread, SIGNAL(finished(void)), this, SLOT(slotHttpsThreadFinished(void)));
  connect(thread, SIGNAL(finished(void)), thread, SLOT(deleteLater(void)));
  m_httpsClientCount->fetchAndAddOrdered(1);
  thread->start();
}

void spoton_web_server::slotHttpsThreadFinished(void)
{
  m_httpsClientCount->fetchAndAddOrdered(-1);
}

void spoton_web_server::slotTimeout(void)
{
  int maximumClients = spoton_kernel::setting
    ("gui/soss_maximum_clients", 10).toInt();
  quint16 port = static_cast<quint16>
    (spoton_kernel::setting("gui/web_server_port", 0).toInt());

  if(port == 0)
    {
      m_http->close();
      m_https->clear();
      m_https->close();
      return;
    }

  if((m_http->isListening() && m_http->serverPort() != port) ||
     m_httpClientCount->fetchAndAddOrdered(0) >= maximumClients)
    m_http->close();

  if((m_https->isListening() &&
      m_https->serverPort() != static_cast<quint16> (port + 5)) ||
     m_httpsClientCount->fetchAndAddOrdered(0) >= maximumClients)
    {
      m_https->clear();
      m_https->close();
    }

  if(m_https->certificate().isEmpty() || m_https->privateKey().isEmpty())
    {
      spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() +
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
		      QByteArray certificate;
		      QByteArray privateKey;
		      bool ok = true;

		      certificate = s_crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(0).toByteArray()),
			 &ok);
		      privateKey = s_crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(1).toByteArray()),
			 &ok);
		      m_https->setCertificate(certificate);
		      m_https->setPrivateKey(privateKey);
		    }
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }

  if(!m_http->isListening() &&
     m_httpClientCount->fetchAndAddOrdered(0) < maximumClients)
    if(!m_http->listen(spoton_misc::localAddressIPv4(), port))
      spoton_misc::logError
	("spoton_web_server::slotTimeout(): m_http->listen() failure. "
	 "This is a serious problem!");

  if(m_http->isListening())
    {
      int so_linger = spoton_kernel::setting
	("WEB_SERVER_HTTP_SO_LINGER", -1).toInt();

      spoton_socket_options::setSocketOptions
	("so_linger=" + QString::number(so_linger),
	 "tcp",
	 m_http->socketDescriptor(),
	 0);
    }

  if(!m_https->isListening() &&
     m_httpsClientCount->fetchAndAddOrdered(0) < maximumClients)
    if(!m_https->listen(spoton_misc::localAddressIPv4(),
			static_cast<quint16> (port + 5)))
      spoton_misc::logError
	("spoton_web_server::slotTimeout(): m_https->listen() failure. "
	 "This is a serious problem!");

  if(m_https->isListening())
    {
      int so_linger = spoton_kernel::setting
	("WEB_SERVER_HTTPS_SO_LINGER", -1).toInt();

      spoton_socket_options::setSocketOptions
	("so_linger=" + QString::number(so_linger),
	 "tcp",
	 m_https->socketDescriptor(),
	 0);
    }
}

void spoton_web_server_thread::process
(const QPair<QByteArray, QByteArray> &credentials,
 const qint64 socketDescriptor)
{
  QScopedPointer<QSslSocket> socket(new QSslSocket());

  if(!socket->setSocketDescriptor(socketDescriptor))
    {
      spoton_misc::closeSocket(socketDescriptor);
      return;
    }

  /*
  ** Prepare the socket!
  */

  auto readBufferSize =
    qMax(0,
	 spoton_kernel::
	 setting("MAXIMUM_KERNEL_WEB_SERVER_SOCKET_READ_BUFFER_SIZE",
		 spoton_common::
		 MAXIMUM_KERNEL_WEB_SERVER_SOCKET_READ_BUFFER_SIZE).
	 toInt());

  socket->setReadBufferSize(static_cast<qint64> (readBufferSize));
  socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

  if(!credentials.first.isEmpty())
    {
      QSslConfiguration configuration;
      QString sslCS
	(spoton_kernel::setting("gui/sslControlString",
				spoton_common::SSL_CONTROL_STRING).toString());

      configuration.setLocalCertificate(QSslCertificate(credentials.first));
      configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
      configuration.setPrivateKey(QSslKey(credentials.second, QSsl::Rsa));
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
	 spoton_kernel::
	 setting("WEB_SERVER_SSL_OPTION_DISABLE_SESSION_TICKETS",
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
      if(m_abort->fetchAndAddOrdered(0) ||
	 (socket->state() == QAbstractSocket::ConnectedState &&
	  socket->waitForEncrypted(s_waitForEncrypted)))
	break;

  /*
  ** Read the socket data!
  */

  for(int i = 1; i <= qCeil(30000 / qMax(10, s_waitForReadyRead)); i++)
    if(m_abort->fetchAndAddOrdered(0) ||
       (socket->state() ==
	QAbstractSocket::ConnectedState &&
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
      QString about("");

      about.append("Build ABI: ");
      about.append(QSysInfo::buildAbi());
      about.append("<br>");
      about.append("Build CPU: ");
      about.append(QSysInfo::buildCpuArchitecture());
      about.append("<br>");
      about.append("CPU: ");
      about.append(QSysInfo::currentCpuArchitecture());
      about.append("<br>");
      about.append("Kernel Type: ");
      about.append(QSysInfo::kernelType());
      about.append("<br>");
      about.append("Kernel Version: ");
      about.append(QSysInfo::kernelVersion());
      about.append("<br>");
      about.append("Machine Host Name: ");
#if QT_VERSION < 0x050600
      about.append(QHostInfo::localHostName());
#else
      about.append(QSysInfo::machineHostName());
#endif
      about.append("<br>");
      about.append("Product Type: ");
      about.append(QSysInfo::productType());
      about.append("<br>");
      about.append("Product Version: ");
      about.append(QSysInfo::productVersion());

      QString html("");

      html.append(s_search);
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

      QPair<QString, QString> address(socket->localAddress().toString(),
				      QString::number(socket->localPort()));

      process(socket.data(), data, address);
    }
  else if(data.endsWith("\r\n\r\n") &&
	  data.simplified().trimmed().startsWith("get /local-"))
    {
      if(spoton_kernel::
	 setting("gui/web_server_serve_local_content", false).toBool())
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

      QPair<QString, QString> address(socket->localAddress().toString(),
				      QString::number(socket->localPort()));

      process(socket.data(), data, address);
    }
  else if(!data.isEmpty())
    writeDefaultPage(socket.data(), true);
}

void spoton_web_server_thread::process(QSslSocket *socket,
				       const QByteArray &data,
				       const QPair<QString, QString> &address)
{
  if(!socket)
    return;

  QStringList list(QString(data.mid(data.indexOf("current=") + 8)).split("&"));

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
       QString(list.at(i)).
       remove("link=").
       remove("pages=").
       remove("search="));

  current = list.value(0).toULongLong();
  offset = current * s_urlLimit;
  pages = qMax(1ULL, list.value(2).toULongLong());

  if(current > pages)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QScopedPointer<spoton_crypt> crypt
    (spoton_misc::retrieveUrlCommonCredentials(spoton_kernel::crypt("chat")));

  if(!crypt)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QElapsedTimer elapsed;

  elapsed.start();

  QSqlDatabase db(spoton_kernel::urlDatabase());
  QString connectionName(db.connectionName());
  QString html("");

  if(db.isOpen())
    {
      QString link(list.value(1).toLower());
      QString querystr("");
      QString search("");
      QString particles(data.mid(data.indexOf("current=")));
      quint64 count = 0;

      search = list.value(3);
      search = spoton_misc::percentEncoding(search);
      search.replace("+", " ");

      if(search.trimmed().isEmpty())
	{
	  querystr.append(s_emptyQuery);
	  querystr.append(" ORDER BY 5 DESC ");
	  querystr.append(QString(" LIMIT %1 ").arg(s_urlLimit));
	  querystr.append(QString(" OFFSET %1 ").arg(offset));
	}
      else
	{
	  QSet<QString> keywords;
	  QString keywordsearch("");
	  QString originalSearch(search);
	  QStringList keywordsearches;
	  bool ok = true;

	  originalSearch.replace("&#34;", "\"");
	  originalSearch.replace("&#38;", "&");
	  originalSearch.replace("&#47;", "/");
	  originalSearch.replace("&#58;", ":");
	  originalSearch.replace("&#61;", "=");
	  originalSearch.replace("&#63;", "?");

	  do
	    {
	      int e = -1;
	      int s = originalSearch.indexOf('"');

	      if(s < 0)
		break;

	      e = originalSearch.indexOf('"', s + 1);

	      if(e < 0 || e - s - 1 <= 0)
		break;

	      QString bundle(originalSearch.mid(s + 1, e - s - 1).trimmed());

	      if(bundle.isEmpty())
		break;

	      keywords.clear();
	      keywordsearch.clear();
	      originalSearch.remove(s, e - s + 1);

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
	      QStringList list
		(bundle.split(QRegExp("\\W+"), Qt::SkipEmptyParts));
#else
	      QStringList list
		(bundle.split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

	      for(int i = 0; i < list.size(); i++)
		keywords.insert(list.at(i));

	      QSetIterator<QString> it(keywords);

	      while(it.hasNext())
		{
		  QByteArray keywordHash
		    (crypt->keyedHash(it.next().toUtf8(), &ok));

		  if(!ok)
		    continue;

		  QByteArray keywordHashHex(keywordHash.toHex());

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

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
	  QStringList list
	    (originalSearch.toLower().trimmed().
	     split(QRegExp("\\W+"), Qt::SkipEmptyParts));
#else
	  QStringList list
	    (originalSearch.toLower().trimmed().
	     split(QRegExp("\\W+"), QString::SkipEmptyParts));
#endif

	  for(int i = 0; i < list.size(); i++)
	    keywords.insert(list.at(i));

	  QSetIterator<QString> it(keywords);

	  while(it.hasNext())
	    {
	      QByteArray keywordHash(crypt->keyedHash(it.next().toUtf8(), &ok));

	      if(!ok)
		continue;

	      QByteArray keywordHashHex(keywordHash.toHex());

	      keywordsearch.append
		(QString("SELECT url_hash FROM "
			 "spot_on_keywords_%1 WHERE "
			 "keyword_hash = '%2' ").
		 arg(keywordHashHex.mid(0, 2).constData()).
		 arg(keywordHashHex.constData()));

	      if(it.hasNext())
		keywordsearch.append(" UNION ");
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
		    QString hash(query.value(0).toString());
		    QString prefix(hash.mid(0, 2));

		    if(!prefixes.contains(prefix))
		      prefixes.insert(prefix, QString("'%1'").arg(hash));
		    else
		      {
			QString str(prefixes.value(prefix));

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
		    querystr.append(" UNION ");
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

	  html.append(s_search);
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
	      QString urlHash(query.value(3).toByteArray());
	      QUrl url;
	      bool ok = true;

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

		  QString scheme(url.scheme().toLower().trimmed());

		  url.setScheme(scheme);

		  if(title.isEmpty())
		    title = spoton_misc::urlToEncoded(url);

		  html.append("<p>");
		  html.append("<a href=\"");
		  html.append(spoton_misc::urlToEncoded(url));
		  html.append("\" target=\"_blank\"><font color=\"#0000EE\">");
		  html.append(title);
		  html.append("</font></a>");

		  if(spoton_kernel::
		     setting("gui/web_server_serve_local_content", false).
		     toBool())
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
	    QByteArray::number(s_search.length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");
      write(socket, s_search);
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

void spoton_web_server_thread::processLocal
(QSslSocket *socket, const QByteArray &data)
{
  if(!socket)
    return;

  QScopedPointer<spoton_crypt> crypt
    (spoton_misc::retrieveUrlCommonCredentials(spoton_kernel::crypt("chat")));

  if(!crypt)
    {
      writeDefaultPage(socket, true);
      return;
    }

  QByteArray html;
  QSqlDatabase db(spoton_kernel::urlDatabase());
  QString connectionName(db.connectionName());

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
	  bool ok = true;

	  content = crypt->decryptedAfterAuthenticated
	    (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	  if(ok)
	    {
	      content = qUncompress(content);

	      if(!content.isEmpty())
		{
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

void spoton_web_server_thread::run(void)
{
  process(m_credentials, m_socketDescriptor);
}

void spoton_web_server_thread::write
(QSslSocket *socket, const QByteArray &data)
{
  if(data.isEmpty() || !socket)
    return;

  for(int i = 0;;)
    {
      if(i >= data.length() ||
	 m_abort->fetchAndAddOrdered(0) ||
	 socket->state() != QAbstractSocket::ConnectedState)
	break;

      qint64 rc = socket->write(data.mid(i, s_bytesPerWrite));

      socket->flush();

      if(rc > 0)
	{
	  i += static_cast<int> (rc);
	  socket->waitForBytesWritten(s_waitForBytesWritten);
	}
    }
}

void spoton_web_server_thread::writeDefaultPage
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

      location.append(socket->localAddress().toString() +
		      ":" +
		      QByteArray::number(socket->localPort()));
      write(socket,
	    "HTTP/1.1 301 Moved Permanently\r\nContent-Length: " +
	    QByteArray::number(s_search.length()) +
	    "\r\nContent-Type: text/html; charset=utf-8\r\n"
	    "Location: " +
	    location +
	    "\r\n\r\n");
    }
  else
    write(socket,
	  "HTTP/1.1 200 OK\r\nContent-Length: " +
	  QByteArray::number(s_search.length()) +
	  "\r\nContent-Type: text/html; charset=utf-8\r\n\r\n");

  write(socket, s_search);
}
