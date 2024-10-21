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

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-receive.h"
#include "spot-on-kernel.h"
#include "spot-on-mailer.h"

#ifdef SPOTON_POPTASTIC_SUPPORTED
static QByteArray curl_receive_data;
static QList<QByteArray> curl_payload_text;

struct curl_upload_status
{
  int lines_read;
};

static size_t curl_payload_source(void *ptr,
				  size_t size,
				  size_t nmemb,
				  void *userp)
{
  if(nmemb == 0 || !ptr || size == 0 || (nmemb * size) < 1 || !userp)
    return 0;

  auto upload_ctx = static_cast<struct curl_upload_status *> (userp);

  if(!upload_ctx || upload_ctx->lines_read >= curl_payload_text.size())
    return 0;

  auto data = curl_payload_text[upload_ctx->lines_read].constData();

  if(data)
    {
      auto const length = strlen(data);

      if(length > 0)
	memcpy(ptr, data, qMin(length, nmemb * size));

      upload_ctx->lines_read++;
      return length;
    }
  else
    spoton_misc::logError("curl_payload_source(): data is zero!");

  return 0;
}

static size_t curl_write_memory_callback(void *contents,
					 size_t size,
					 size_t nmemb)
{
  if(!contents || nmemb == 0 || size == 0)
    return 0;

  curl_receive_data.append
    (static_cast<const char *> (contents), static_cast<int> (nmemb *size));
  return nmemb * size;
}
#endif

void spoton_kernel::importUrls(void)
{
  {
    QReadLocker locker(&m_urlListMutex);

    if(m_urlList.isEmpty())
      return;
  }

  auto s_crypt = this->crypt("chat");
  spoton_crypt *crypt = 0;

  crypt = spoton_misc::retrieveUrlCommonCredentials(s_crypt);

  if(!crypt || !s_crypt)
    {
      delete crypt;

      QWriteLocker locker(&m_urlListMutex);

      m_urlList.clear();
      return;
    }

  QList<QPair<QUrl, QString> > polarizers;
  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "urls_distillers_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT domain, " // 0
		      "permission "     // 1
		      "FROM distillers WHERE "
		      "direction_hash = ?");
	query.bindValue(0, s_crypt->keyedHash("download", &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray domain;
	      QByteArray permission;
	      auto ok = true;

	      domain = s_crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(0).
						       toByteArray()),
					    &ok);

	      if(ok)
		permission = s_crypt->
		  decryptedAfterAuthenticated(QByteArray::
					      fromBase64(query.
							 value(1).
							 toByteArray()),
					      &ok);

	      if(ok)
		{
		  auto const url(QUrl::fromUserInput(domain));

		  if(!url.isEmpty())
		    if(url.isValid())
		      {
			QPair<QUrl, QString> pair;

			pair.first = url;
			pair.second = permission;
			polarizers.append(pair);
		      }
		}

	      if(m_urlImportFutureInterrupt.fetchAndAddOrdered(0))
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_urlImportFutureInterrupt.fetchAndAddOrdered(0))
    {
      delete crypt;

      QWriteLocker locker(&m_urlListMutex);

      m_urlList.clear();
      return;
    }

  {
    connectionName = spoton_misc::databaseName();

    QSqlDatabase db;

    if(setting("gui/sqliteSearch", true).toBool())
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
	  (setting("gui/postgresql_database", "").toString().trimmed());
	auto const host
	  (setting("gui/postgresql_host", "localhost").toString().trimmed());
	auto const port = setting("gui/postgresql_port", 5432).toInt();
	auto const ssltls = setting("gui/postgresql_ssltls", false).toBool();
	auto ok = true;
	auto options
	  (spoton_kernel::setting("gui/postgresql_connection_options",
				  spoton_common::POSTGRESQL_CONNECTION_OPTIONS).
	   toString().trimmed());

	if(!options.contains("connect_timeout="))
	  options.append(";connect_timeout=10");

	name = s_crypt->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(setting("gui/postgresql_name", "").
		      toByteArray()), &ok);

	if(ok)
	  password = s_crypt->decryptedAfterAuthenticated
	    (QByteArray::
	     fromBase64(setting("gui/postgresql_password", "").
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
	do
	  {
	    if(m_urlImportFutureInterrupt.fetchAndAddOrdered(0))
	      break;

	    QWriteLocker locker(&m_urlListMutex);

	    if(m_urlList.isEmpty())
	      break;

	    auto const urls(m_urlList.mid(0, 4));

	    for(int i = 0; i < urls.size(); i++)
	      m_urlList.removeAt(0);

	    locker.unlock();

	    auto const content(qUncompress(urls.value(3)));
	    auto const description(urls.value(2));
	    auto const title(urls.value(1));
	    auto const url(urls.value(0));
	    auto ok = false;

	    for(int i = 0; i < polarizers.size(); i++)
	      {
		auto const type(polarizers.at(i).second);
		auto const u1(polarizers.at(i).first);
		auto const u2(QUrl::fromUserInput(url.trimmed()));

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

	    if(ok)
	      {
		QString error("");

		if(spoton_misc::importUrl(content,
					  description,
					  title,
					  url,
					  db,
					  setting("gui/maximum_url_keywords_"
						  "import_kernel",
						  50).toInt(),
					  setting("gui/disable_kernel_"
						  "synchronous_sqlite_url_"
						  "download",
						  false).toBool(),
					  m_urlImportFutureInterrupt,
					  error,
					  crypt))
		  {
		    QWriteLocker locker(&m_urlsProcessedMutex);

		    m_urlsProcessed += 1;
		  }
	      }
	  }
	while(true);
      }
    else
      {
	QWriteLocker locker(&m_urlListMutex);

	m_urlList.clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete crypt;
}

void spoton_kernel::popPoptastic(void)
{
#ifdef SPOTON_POPTASTIC_SUPPORTED
  if(property("disable_poptastic").toBool())
    return;

  auto s_crypt = crypt("poptastic");

  if(!s_crypt)
    return;

  QHash<QString, QVariant> hash;
  auto ok = true;

  if(m_poptasticAccounts.isEmpty())
    m_poptasticAccounts = spoton_misc::poptasticSettings("", s_crypt, &ok);

  /*
  ** Discover an enabled account.
  */

  for(int i = m_poptasticAccounts.size() - 1; i >= 0; i--)
    {
      hash = m_poptasticAccounts.at(i);

      if(hash.value("in_method").toString() != "Disable")
	{
	  m_poptasticAccounts.removeAt(i);
	  break;
	}
      else
	hash.clear();
    }

  if(hash.isEmpty() || !ok)
    {
      m_poptasticAccounts.clear();

      if(!ok)
	spoton_misc::logError("spoton_kernel::popPoptastic(): "
			      "spoton_misc::poptasticSettings() failed.");

      return;
    }

  CURL *curl = 0;
  QHash<QByteArray, char> cache;
  auto const method(hash.value("in_method").toString().toUpper().trimmed());
  auto const limit = setting("gui/poptasticNumberOfMessages", 15).toInt();
  qint64 uid = 0;

  for(int ii = 1; ii <= limit + 1; ii++)
    {
      if(curl == 0)
	curl = curl_easy_init();

      if(!curl)
	continue;
      else
	curl_easy_reset(curl);

      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 hash.value("in_password").toByteArray().constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 hash.value("in_username").toByteArray().trimmed().constData());

      long int timeout = 10L;

      if(hash.value("proxy_enabled").toBool())
	{
	  timeout += 15L;

	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = hash.value("proxy_server_address").toString().trimmed();
	  port = hash.value("proxy_server_port").toString().trimmed();

	  if(hash.value("proxy_type") == "SOCKS5")
	    scheme = "socks5";
	  else
	    scheme = "http";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt
	    (curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   hash.value("proxy_password").toString().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   hash.value("proxy_username").toString().
			   trimmed().toLatin1().constData());
	}

      QString removeUrl("");
      QString url("");
      auto const ssltls
	(hash.value("in_ssltls").toString().toUpper().trimmed());

      if(ssltls == "SSL" || ssltls == "TLS")
	{
	  if(method == "IMAP")
	    {
	      removeUrl = QString("imaps://%1:%2/INBOX/;UID=").
		arg(hash.value("in_server_address").toString().trimmed()).
		arg(hash.value("in_server_port").toString().trimmed());

	      if(ii == 1)
		url = QString("imaps://%1:%2").
		  arg(hash.value("in_server_address").toString().trimmed()).
		  arg(hash.value("in_server_port").toString().trimmed());
	      else if(uid > 0)
		url = QString("imaps://%1:%2/INBOX/;UID=%3").
		  arg(hash.value("in_server_address").toString().trimmed()).
		  arg(hash.value("in_server_port").toString().trimmed()).
		  arg(uid);
	    }
	  else
	    url = QString("pop3s://%1:%2/%3").
	      arg(hash.value("in_server_address").toString().trimmed()).
	      arg(hash.value("in_server_port").toString().trimmed()).
	      arg(ii);

	  auto verify = static_cast<long int>
	    (hash.value("in_verify_host").toInt());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long int>
	    (hash.value("in_verify_peer").toInt());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(ssltls == "TLS")
	    {
	      QFileInfo const fileInfo
		(setting("gui/poptasticCAPath", "").toString());

	      if(fileInfo.isReadable())
		curl_easy_setopt
		  (curl, CURLOPT_CAINFO,
		   fileInfo.absoluteFilePath().toUtf8().constData());

	      curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	    }
	}
      else
	{
	  if(method == "IMAP")
	    {
	      removeUrl = QString("imap://%1:%2/INBOX/;UID=").
		arg(hash.value("in_server_address").toString().trimmed()).
		arg(hash.value("in_server_port").toString().trimmed());

	      if(ii == 1)
		url = QString("imap://%1:%2").
		  arg(hash.value("in_server_address").toString().trimmed()).
		  arg(hash.value("in_server_port").toString().trimmed());
	      else if(uid > 0)
		url = QString("imap://%1:%2/INBOX/;UID=%3").
		  arg(hash.value("in_server_address").toString().trimmed()).
		  arg(hash.value("in_server_port").toString().trimmed()).
		  arg(uid);
	    }
	  else
	    url = QString("pop3://%1:%2/%3").
	      arg(hash.value("in_server_address").toString().trimmed()).
	      arg(hash.value("in_server_port").toString().trimmed()).
	      arg(ii);
	}

      curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 128L); // cURL sometimes dies.

      if(ii == 1 && method == "IMAP")
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "EXAMINE INBOX");

      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_memory_callback);

      CURLcode rc = CURLE_OK;

      if((rc = curl_easy_perform(curl)) == CURLE_OK)
	{
	  if(!curl_receive_data.isEmpty())
	    {
	      if(ii == 1 && method == "IMAP")
		{
		  auto const list(curl_receive_data.split('\n'));
		  qint64 exists = 0;
		  qint64 uidnext = 0;

		  for(int i = 0; i < list.size(); i++)
		    {
		      QString str(list.at(i).toLower().trimmed());

		      if(str.contains("exists"))
			exists = str.remove(QRegularExpression("[^\\d]")).
			  toLongLong();
		      else if(str.contains("uidnext"))
			uidnext = str.remove(QRegularExpression("[^\\d]")).
			  toLongLong();
		    }

		  if(exists > 0)
		    {
		      if(uidnext > 1) // UIDs must be greater than zero!
			uid = uidnext - 1; // Latest.
		      else
			uid = 1;
		    }
		  else
		    uid = 0;
		}
	      else
		{
		  QByteArray hash;
		  auto ok = true;

		  hash = s_crypt->keyedHash(curl_receive_data, &ok);

		  if(!cache.contains(hash))
		    {
		      emit poppedMessage(curl_receive_data);
		      cache[hash] = 0;
		    }

		  removeUrl.append(QString::number(uid));
		}
	    }
	}

      if(m_poptasticPopFuture.isCanceled())
	break;

      if(hash.value("in_remove_remote", true).toBool() && ii > 1 && uid > 0)
	if(method == "IMAP" && rc == CURLE_OK)
	  {
	    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	    curl_easy_setopt
	      (curl, CURLOPT_URL, removeUrl.toLatin1().constData());
	    curl_easy_setopt
	      (curl, CURLOPT_CUSTOMREQUEST,
	       QString("STORE %1 +Flags \\Deleted").
	       arg(1).toLatin1().constData());

	    CURLcode rc = CURLE_OK;

	    if((rc = curl_easy_perform(curl)) != CURLE_OK)
	      spoton_misc::logError
		(QString("spoton_kernel::popPoptastic(): "
			 "curl_easy_perform(STORE) failure (%1).").
		 arg(rc));

	    curl_easy_setopt
	      (curl, CURLOPT_CUSTOMREQUEST, "EXPUNGE");
	    rc = curl_easy_perform(curl);

	    if(rc != CURLE_OK)
	      spoton_misc::logError
		(QString("spoton_kernel::popPoptastic(): "
			 "curl_easy_perform(EXPUNGE) failure (%1).").
		 arg(rc));
	  }

      if(m_poptasticPopFuture.isCanceled())
	break;

      curl_receive_data.clear();
    }

  if(curl)
    curl_easy_cleanup(curl);

  curl_receive_data.clear();
#endif
}

void spoton_kernel::postPoptastic(void)
{
#ifdef SPOTON_POPTASTIC_SUPPORTED
  auto s_crypt = crypt("poptastic");

  if(!s_crypt || property("disable_poptastic").toBool())
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  QList<QHash<QString, QVariant> > list;
  auto ok = true;

  list = spoton_misc::poptasticSettings("", s_crypt, &ok);

  if(list.isEmpty() || !ok)
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  auto disabled = true;

  for(int i = 0; i < list.size(); i++)
    if(list.at(i).value("out_method") != "Disable")
      {
	disabled = false;
	break;
      }

  if(disabled)
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  QReadLocker locker(&m_poptasticCacheMutex);

  if(!m_poptasticCache.isEmpty())
    {
      auto const values(m_poptasticCache.head());

      locker.unlock();

      QHash<QString, QVariant> h;

      for(int i = 0; i < list.size(); i++)
	/*
	** We wish to verify that the from_account matches an
	** account having the in_username (not the out_username) because
	** the UI creates a listing using the in_username values.
	*/

	if(list.at(i).value("in_username").toString() ==
	   values.value("from_account").toString())
	  {
	    h = list.at(i);

	    if(h.value("out_method") == "Disable")
	      {
		/*
		** Remove the values item from the cache.
		*/

		QWriteLocker locker(&m_poptasticCacheMutex);

		if(m_poptasticCache.contains(values))
		  m_poptasticCache.removeOne(values);

		return;
	      }

	    break;
	  }

      if(h.isEmpty())
	{
	  /*
	  ** Remove the values item.
	  */

	  QWriteLocker locker(&m_poptasticCacheMutex);

	  if(m_poptasticCache.contains(values))
	    m_poptasticCache.removeOne(values);

	  return;
	}

      auto const hash(h);
      auto curl = curl_easy_init();

      if(curl)
	{
	  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	  curl_easy_setopt
	    (curl, CURLOPT_PASSWORD,
	     hash.value("out_password").toByteArray().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_USERNAME,
	     hash.value("out_username").toByteArray().trimmed().constData());

	  long int timeout = 10L;

	  if(hash.value("proxy_enabled").toBool())
	    {
	      timeout += 15L;

	      QString address("");
	      QString port("");
	      QString scheme("");
	      QString url("");

	      address = hash.value("proxy_server_address").toString().
		trimmed();
	      port = hash.value("proxy_server_port").toString().trimmed();

	      if(hash.value("proxy_type") == "SOCKS5")
		scheme = "socks5";
	      else
		scheme = "http";

	      url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	      curl_easy_setopt
		(curl, CURLOPT_PROXY, url.toLatin1().constData());
	      curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			       hash.value("proxy_password").toString().
			       toUtf8().constData());
	      curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			       hash.value("proxy_username").toString().
			       trimmed().toLatin1().constData());
	    }

	  /*
	  ** The UI creates a listing using the in_username values.
	  */

	  QString url("");
	  auto const from(hash.value("in_username").toString().trimmed());
	  auto const ssltls(hash.value("out_ssltls").toString().toUpper().
			    trimmed());

	  if(ssltls == "SSL" || ssltls == "TLS")
	    {
	      if(ssltls == "SSL")
		url = QString("smtps://%1:%2/%3").
		  arg(hash.value("out_server_address").toString().trimmed()).
		  arg(hash.value("out_server_port").toString().trimmed()).
		  arg(hash.value("smtp_localname", "localhost").
		      toString());
	      else
		url = QString("smtp://%1:%2/%3").
		  arg(hash.value("out_server_address").toString().trimmed()).
		  arg(hash.value("out_server_port").toString().trimmed()).
		  arg(hash.value("smtp_localname", "localhost").
		      toString());

	      auto verify = static_cast<long int>
		(hash.value("out_verify_host").toInt());

	      if(verify)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	      else
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	      verify = static_cast<long int>
		(hash.value("out_verify_peer").toInt());
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	      if(ssltls == "TLS")
		{
		  QFileInfo const fileInfo
		    (setting("gui/poptasticCAPath", "").toString());

		  if(fileInfo.isReadable())
		    curl_easy_setopt
		      (curl, CURLOPT_CAINFO,
		       fileInfo.absoluteFilePath().toUtf8().constData());

		  curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		}
	    }
	  else
	    url = QString("smtp://%1:%2/%3").
	      arg(hash.value("out_server_address").toString().trimmed()).
	      arg(hash.value("out_server_port").toString().trimmed()).
	      arg(hash.value("smtp_localname", "localhost").
		  toString());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

	  for(int i = 1;; i++)
	    {
	      QReadLocker locker(&m_poptasticCacheMutex);

	      if(m_poptasticCache.isEmpty())
		break;

	      locker.unlock();

	      auto bytes(values.value("message").toByteArray());
	      long int count = 0;
	      struct curl_slist *recipients = 0;
	      struct curl_upload_status upload_ctx;

	      upload_ctx.lines_read = 0;
	      curl_easy_setopt
		(curl, CURLOPT_MAIL_FROM,
		 QString("<%1>").arg(from).toLatin1().constData());

	      /*
	      ** Prepare curl_payload_text.
	      */

	      curl_payload_text.clear();
	      curl_payload_text.append
		(QString("Date: %1\r\n").arg(QDateTime::currentDateTimeUtc().
					     toString()).toLatin1());

	      if(values.size() == 4)
		curl_payload_text.append(QString("To: <%1> (%1)\r\n").
					 arg(values.value("receiver_name").
					     toString()).
					 toLatin1());
	      else
		curl_payload_text.append
		  (QString("To: <%1> (%1)\r\n").
		   arg(values.value("name").toByteArray().constData()).
		   toLatin1());

	      curl_payload_text.append(QString("From: <%1>\r\n").arg(from).
				       toLatin1());
	      curl_payload_text.append
		(QString("Message-ID: <%1>\r\n").
		 arg(spoton_crypt::weakRandomBytes(16).toHex().
		     constData()).toLatin1());

	      if(values.size() == 4)
		{
		  curl_payload_text.append
		    (QString("Subject: %1\r\n").
		     arg(spoton_crypt::preferredHash(bytes.simplified()).
			 toHex().constData()).toLatin1());
		  curl_payload_text.append("\r\n");
		}
	      else
		{
		  curl_payload_text.append("Subject: ");
		  curl_payload_text.append(values.value("subject").
					   toByteArray());
		  curl_payload_text.append("\r\n");
		}

	      auto attachmentData(values.value("attachment").toByteArray());

	      if(attachmentData.isEmpty() || values.size() == 4)
		{
		  while(!bytes.isEmpty())
		    {
		      count += 1;
		      curl_payload_text.append
			(bytes.mid(0, CURL_MAX_WRITE_SIZE));
		      bytes.remove(0, CURL_MAX_WRITE_SIZE);
		    }
		}
	      else if(!attachmentData.isEmpty())
		{
		  QDataStream stream(&attachmentData, QIODevice::ReadOnly);
		  QList<QPair<QByteArray, QByteArray> > attachments;

		  stream >> attachments;

		  if(stream.status() != QDataStream::Ok)
		    attachments.clear();

		  QByteArray attachment;
		  QByteArray attachmentName;
		  size_t attachmentSize = 0;

		  if(!attachments.isEmpty())
		    {
		      attachment = attachments.at(0).first.toBase64();
		      attachmentName = attachments.at(0).second;
		      attachmentSize = static_cast<size_t>
			(attachment.length());
		    }

		  QByteArray bytes;
		  QString str("");
		  auto const r1(spoton_crypt::weakRandomBytes(8).toHex());
		  auto const r2(spoton_crypt::weakRandomBytes(8).toHex());

		  str.append
		    (QString("Content-Type: multipart/mixed; "
			     "boundary=%1\r\n"
			     "\r\n"
			     "--%1\r\n"
			     "Content-Type: multipart/alternative; "
			     "boundary=%2\r\n"
			     "\r\n"
			     "--%2\r\n"
			     "Content-Type: text/html; charset=UTF-8\r\n"
			     "\r\n"
			     "%3\r\n"
			     "\r\n"
			     "--%2--\r\n"
			     "--%1\r\n"
			     "Content-Type: application/octet-stream; name="
			     "\"%4\"\r\n"
			     "Content-Disposition: attachment; filename="
			     "\"%4\"\r\n"
			     "Content-Transfer-Encoding: base64\r\n\r\n").
		     arg(r1.constData()).
		     arg(r2.constData()).
		     arg(values.value("message").toByteArray().constData()).
		     arg(attachmentName.constData()));
		  bytes.append(str.toUtf8());

		  while(!attachment.isEmpty())
		    {
		      bytes.append(attachment.mid(0, 76));
		      attachment.remove(0, 76);
		      bytes.append("\r\n");
		    }

		  bytes.append("--");
		  bytes.append(r1);
		  bytes.append("--\r\n");

		  while(!bytes.isEmpty())
		    {
		      count += 1;
		      curl_payload_text.append
			(bytes.mid(0, CURL_MAX_WRITE_SIZE));
		      bytes.remove(0, CURL_MAX_WRITE_SIZE);
		    }

		  curl_easy_setopt
		    (curl, CURLOPT_INFILESIZE, attachmentSize);
		}

	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append(0);

	      if(values.size() == 4)
		recipients = curl_slist_append
		  (recipients, values.value("receiver_name").toString().
		   toLatin1().constData());
	      else
		recipients = curl_slist_append
		  (recipients, values.value("name").toByteArray().constData());

	      curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	      curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	      curl_easy_setopt
		(curl, CURLOPT_READFUNCTION, curl_payload_source);

	      if(count <= 1)
		curl_easy_setopt
		  (curl, CURLOPT_TIMEOUT, timeout);
	      else
		/*
		** 2.5 seconds per CURL_MAX_WRITE_SIZE bytes.
		*/

		curl_easy_setopt
		  (curl,
		   CURLOPT_TIMEOUT,
		   static_cast<long int> (2.5 * count + timeout));

	      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	      CURLcode rc = CURLE_OK;

	      if((rc = curl_easy_perform(curl)) == CURLE_OK)
		{
		  QWriteLocker locker(&m_poptasticCacheMutex);

		  if(m_poptasticCache.contains(values))
		    m_poptasticCache.removeOne(values);

		  locker.unlock();

		  qint64 mailOid = -1;

		  if(!values.isEmpty())
		    mailOid = values.value("mail_oid").toLongLong();

		  if(mailOid > -1)
		    spoton_mailer::moveSentMailToSentFolder
		      (QList<qint64> () << mailOid, s_crypt);

		  curl_slist_free_all(recipients);
		  break;
		}
	      else
		{
		  curl_slist_free_all(recipients);
		  spoton_misc::logError
		    (QString("spoton_kernel::postPoptastic(): "
			     "curl_easy_perform() failure (%1).").
		     arg(rc));

		  if(i >= spoton_common::MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST)
		    {
		      QWriteLocker locker(&m_poptasticCacheMutex);

		      if(m_poptasticCache.contains(values))
			m_poptasticCache.removeOne(values);

		      locker.unlock();
		      break;
		    }
		}

	      if(m_poptasticPostFuture.isCanceled())
		break;
	    }

	  curl_easy_cleanup(curl);
	}
      else
	spoton_misc::logError("spoton_kernel::postPoptastic(): "
			      "curl_easy_init() failure.");
    }
#endif
}

void spoton_kernel::saveGeminiPoptastic(const QByteArray &publicKeyHash,
					const QByteArray &gemini,
					const QByteArray &geminiHashKey,
					const QByteArray &timestamp,
					const QByteArray &signature,
					const QString &messageType)
{
  /*
  ** Some of the following is similar to logic in spoton_neighbor.
  */

  if(!setting("gui/acceptGeminis", true).toBool())
    return;

  auto dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      spoton_misc::logError
	("spoton_kernel::saveGeminiPoptastic(): invalid date-time object.");
      return;
    }

  auto const now(QDateTime::currentDateTimeUtc());

#if (QT_VERSION >= QT_VERSION_CHECK(6, 8, 0))
  dateTime.setTimeZone(QTimeZone(QTimeZone::UTC));
#else
  dateTime.setTimeSpec(Qt::UTC);
#endif

  auto const secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= static_cast<qint64> (spoton_common::
				      POPTASTIC_GEMINI_TIME_DELTA_MAXIMUM)))
    {
      spoton_misc::logError
	(QString("spoton_kernel::saveGeminiPoptastic(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }
  else if(duplicateGeminis(publicKeyHash +
			   gemini +
			   geminiHashKey))
    {
      spoton_misc::logError
	("spoton_kernel::saveGeminiPoptastic(): duplicate keys.");
      return;
    }

  geminisCacheAdd(publicKeyHash + gemini + geminiHashKey);

  QString connectionName("");

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QPair<QByteArray, QByteArray> geminis;
	QSqlQuery query(db);
	auto ok = true;

	geminis.first = gemini;
	geminis.second = geminiHashKey;
	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ?, "
		      "last_status_update = ?, status = 'online' "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");

	if(geminis.first.isEmpty() || geminis.second.isEmpty())
	  {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	    query.bindValue(0, QVariant(QMetaType(QMetaType::QString)));
	    query.bindValue(1, QVariant(QMetaType(QMetaType::QString)));
#else
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
#endif
	  }
	else
	  {
	    auto s_crypt = crypt("chat");

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
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
		query.bindValue(0, QVariant(QMetaType(QMetaType::QString)));
		query.bindValue(1, QVariant(QMetaType(QMetaType::QString)));
#else
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
#endif
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
		   tr("The participant %1...%2 terminated%3 the call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned));
	      else if(messageType == "0000a")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call%3.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned));
	      else if(messageType == "0000b")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call%3 "
		      "within a call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()).
		   arg(notsigned));
	      else if(messageType == "0000d")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call "
		      "via Forward Secrecy.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_kernel::saveUrls(const QList<QByteArray> &urls)
{
  if(urls.isEmpty() || urls.size() % 4 != 0)
    return;

  QWriteLocker locker1(&m_urlListMutex);

  m_urlList << urls;
  locker1.unlock();
}

void spoton_kernel::slotForwardSecrecyInformationReceivedFromUI
(const QByteArrayList &list)
{
  if(list.isEmpty())
    return;

  /*
  ** list[0]: Destination's Name
  ** list[1]: Destination's Public Key Hash
  ** list[2]: Temporary Private Key
  ** list[3]: Temporary Public Key
  ** list[4]: Key Type (chat, email, poptastic, etc.)
  ** list[5]: Widget Type (chat, email)
  */

  auto const keyType(list.value(4));

  if(!(keyType == "chat" ||
       keyType == "email" ||
       keyType == "open-library" ||
       keyType == "poptastic" ||
       keyType == "url"))
    return;

  auto const widgetType(list.value(5));
  auto ok = true;
  auto s_crypt1 = crypt(keyType);
  auto s_crypt2 = crypt(keyType + "-signature");

  if(!s_crypt1 || !s_crypt2)
    return;

  auto const myPublicKey(s_crypt1->publicKey(&ok));

  if(!ok)
    return;

  auto const cipherType(setting("gui/fsCipherType", "aes256").
			toString().toLatin1());
  auto const hashType(setting("gui/fsHashType", "sha512").
		      toString().toLatin1());
  auto const myPublicKeyHash(spoton_crypt::preferredHash(myPublicKey));
  auto const publicKey
    (spoton_misc::publicKeyFromHash(list.value(1), false, s_crypt1));

  if(publicKey.isEmpty())
    return;

  QByteArray symmetricKey;
  auto const symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength == 0)
    return;

  QByteArray hashKey;

  hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
  hashKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (hashKey.length()));
  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
  symmetricKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (symmetricKey.length()));

  QByteArray keyInformation;

  {
    QDataStream stream(&keyInformation, QIODevice::WriteOnly);

    stream << QByteArray("0091a")
	   << symmetricKey
	   << hashKey
	   << cipherType
	   << hashType;

    if(stream.status() != QDataStream::Ok)
      return;
  }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (keyInformation, qCompress(publicKey), publicKey.mid(0, 25), &ok);

  if(!ok)
    return;

  auto sign = true;

  if(keyType == "chat" && !setting("gui/chatSignMessages", true).toBool())
    sign = false;
  else if(keyType == "email" && !setting("gui/emailSignMessages", true).
	  toBool())
    sign = false;
  else if(keyType == "poptastic")
    {
      // if(!setting("gui/chatSignMessages", true).toBool() &&
      //    widgetType == "chat")
      //   sign = false;
      // else if(!setting("gui/emailSignMessages", true).toBool() &&
      // 	 widgetType == "email")
      //   sign = false;

      sign = true; // Mandatory signatures!
    }
  else if(keyType == "url" && !setting("gui/urlSignMessages", true).toBool())
    sign = false;

  QByteArray signature;
  auto const utcDate(QDateTime::currentDateTimeUtc().
		     toString("MMddyyyyhhmmss").toLatin1());

  if(sign)
    {
      auto const recipientDigest
	(spoton_crypt::preferredHash(publicKey));

      signature = s_crypt2->digitalSignature
	("0091a" +
	 symmetricKey +
	 hashKey +
	 cipherType +
	 hashType +
	 myPublicKeyHash +
	 list.value(3) +
	 utcDate +
	 recipientDigest,
	 &ok);

      if(!ok)
	return;
    }

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     hashType,
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  {
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << myPublicKeyHash
	   << list.value(3)
	   << utcDate
	   << signature;

    if(stream.status() != QDataStream::Ok)
      ok = false;

    if(ok)
      data = crypt.encrypted(data, &ok);

    if(!ok)
      return;
  }

  auto const messageCode
    (crypt.keyedHash(keyInformation + data, &ok));

  if(!ok)
    return;

  data = keyInformation.toBase64() + "\n" + data.toBase64() + "\n" +
    messageCode.toBase64();

  if(keyType == "chat" || keyType == "email" || keyType == "url")
    emit sendForwardSecrecyPublicKey(data);
  else if(keyType == "poptastic")
    {
      auto const message
	(spoton_send::message0091a(data, QPair<QByteArray, QByteArray> ()));
      auto const name(QString::fromUtf8(list.value(0).constData(),
					list.value(0).length()));

      postPoptasticMessage(name, message);
    }

  QPair<QByteArray, QByteArray> keys(list.value(2), list.value(3));

  keys.first = s_crypt1->encryptedThenHashed(keys.first, &ok);

  if(ok)
    keys.second = s_crypt1->encryptedThenHashed(keys.second, &ok);

  if(ok)
    {
      QVector<QVariant> vector;

      vector << keys.first
	     << keys.second
	     << QDateTime::currentDateTime()
	     << keyType;

      QWriteLocker locker(&m_forwardSecrecyKeysMutex);

      m_forwardSecrecyKeys.insert(list.value(1), vector);
    }
}

void spoton_kernel::slotForwardSecrecyResponseReceivedFromUI
(const QByteArrayList &list)
{
  if(list.size() != 7)
    return;

  /*
  ** list[0]: Destination's Public Key Hash
  ** list[1]: Temporary Public Key
  ** list[2]: Key Type (chat, email, poptastic, etc.)
  ** list[3]: Authentication Algorithm
  ** list[4]: Authentication Key
  ** list[5]: Encryption Algorithm
  ** list[6]: Encryption Key
  */

  auto const keyType(list.value(2));

  if(!(keyType == "chat" ||
       keyType == "email" ||
       keyType == "open-library" ||
       keyType == "poptastic" ||
       keyType == "url"))
    return;

  auto ok = true;
  auto s_crypt1 = crypt(keyType);
  auto s_crypt2 = crypt(keyType + "-signature");

  if(!s_crypt1 || !s_crypt2)
    return;

  auto const myPublicKey(s_crypt1->publicKey(&ok));

  if(!ok)
    return;

  auto const cipherType(setting("gui/fsCipherType", "aes256").
			toString().toLatin1());
  auto const hashType(setting("gui/fsHashType", "sha512").
		      toString().toLatin1());
  auto const myPublicKeyHash(spoton_crypt::preferredHash(myPublicKey));
  auto const publicKey
    (spoton_misc::publicKeyFromHash(list.value(0), false, s_crypt1));

  if(publicKey.isEmpty())
    return;

  QByteArray symmetricKey;
  auto const symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength == 0)
    return;

  QByteArray hashKey;

  hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
  hashKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (hashKey.length()));
  symmetricKey.resize(static_cast<int> (symmetricKeyLength));
  symmetricKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (symmetricKey.length()));

  QByteArray keyInformation;

  {
    QDataStream stream(&keyInformation, QIODevice::WriteOnly);

    stream << QByteArray("0091b")
	   << symmetricKey
	   << hashKey
	   << cipherType
	   << hashType;

    if(stream.status() != QDataStream::Ok)
      return;
  }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (keyInformation, qCompress(publicKey), publicKey.mid(0, 25), &ok);

  if(!ok)
    return;

  QByteArray bundle;

  {
    QDataStream stream(&bundle, QIODevice::WriteOnly);

    stream << list.value(3)
	   << list.value(4)
	   << list.value(5)
	   << list.value(6);

    if(stream.status() != QDataStream::Ok)
      return;

    bundle = qCompress(bundle, 9);
  }

  auto const pk(qUncompress(list.value(1)));

  bundle = spoton_crypt::publicKeyEncrypt
    (bundle, list.value(1), pk.mid(0, 25), &ok);

  if(!ok)
    return;

  auto sign = true;

  if(keyType == "chat" && !setting("gui/chatSignMessages", true).toBool())
    sign = false;
  else if(keyType == "email" && !setting("gui/emailSignMessages", true).
	  toBool())
    sign = false;
  else if(keyType == "poptastic")
    sign = true; // Mandatory signatures!
  else if(keyType == "url" && !setting("gui/urlSignMessages", true).toBool())
    sign = false;

  QByteArray signature;
  auto const utcDate(QDateTime::currentDateTimeUtc().
		     toString("MMddyyyyhhmmss").toLatin1());

  if(sign)
    {
      QByteArray recipientDigest
	(spoton_crypt::preferredHash(publicKey));

      signature = s_crypt2->digitalSignature
	("0091b" +
	 symmetricKey +
	 hashKey +
	 cipherType +
	 hashType +
	 myPublicKeyHash +
	 bundle +
	 utcDate +
	 recipientDigest,
	 &ok);

      if(!ok)
	return;
    }

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     hashType,
		     QByteArray(),
		     symmetricKey,
		     hashKey,
		     0,
		     0,
		     "");

  {
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << myPublicKeyHash
	   << bundle
	   << utcDate
	   << signature;

    if(stream.status() != QDataStream::Ok)
      ok = false;

    if(ok)
      data = crypt.encrypted(data, &ok);

    if(!ok)
      return;
  }

  auto const messageCode
    (crypt.keyedHash(keyInformation + data, &ok));

  if(!ok)
    return;

  data = keyInformation.toBase64() + "\n" + data.toBase64() + "\n" +
    messageCode.toBase64();

  if(keyType == "chat" || keyType == "email" || keyType == "url")
    emit sendForwardSecrecySessionKeys(data);
  else if(keyType == "poptastic")
    {
      auto const message
	(spoton_send::message0091b(data, QPair<QByteArray, QByteArray> ()));
      auto const name
	(spoton_misc::nameFromPublicKeyHash(list.value(0), s_crypt1));

      postPoptasticMessage(name, message);
    }
}

void spoton_kernel::slotPoppedMessage(const QByteArray &message)
{
  /*
  ** We popping Poptastic!
  */

  auto data
    (message.mid(message.indexOf("content=") +
		 static_cast<int> (qstrlen("content="))));

  data = data.mid
    (0, data.indexOf(spoton_send::EOM)).trimmed();

  if(data.isEmpty())
    return;
  else if(data.length() > spoton_common::POPTASTIC_MAXIMUM_EMAIL_SIZE)
    {
      spoton_misc::logError
	(QString("spoton_kernel::slotPoppedMessage(): "
		 "too much data (%1 bytes). "
		 "Ignoring.").
	 arg(data.length()));
      return;
    }

  /*
  ** The following logic must agree with the logic in
  ** spoton_neighbor.
  */

  QList<QByteArray> symmetricKeys;
  auto const messageType
    (spoton_receive::findMessageType(data,
				     symmetricKeys,
				     interfaces(),
				     "poptastic",
				     crypt("poptastic")));

  if(messageType == "0000")
    {
      auto const list
	(spoton_receive::
	 process0000(data.length(),
		     data,
		     symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).toBool(),
		     "127.0.0.1",
		     0,
		     crypt("poptastic")));

      if(!list.isEmpty())
	{
	  spoton_misc::saveParticipantStatus
	    (list.value(1),                                  // Name
	     list.value(0),                                  /*
							     ** Public
							     ** Key Hash
							     */
	     QByteArray(),                                   // Status
	     QDateTime::currentDateTimeUtc().
	     toString("MMddyyyyhhmmss").
	     toLatin1(),                                     // Timestamp
	     2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL, // Seconds
	     crypt("poptastic"));
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
  else if(messageType == "0000a")
    {
      auto const list
	(spoton_receive::
	 process0000a(data.length(),
		      data,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      "127.0.0.1",
		      0,
		      messageType,
		      crypt("poptastic")));

      if(!list.isEmpty())
	saveGeminiPoptastic(list.value(0),
			    list.value(1),
			    list.value(2),
			    list.value(3),
			    list.value(4),
			    "0000a");
    }
  else if(messageType == "0000b")
    {
      auto const list
	(spoton_receive::
	 process0000b(data.length(),
		      data,
		      symmetricKeys,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      "127.0.0.1",
		      0,
		      crypt("poptastic")));

      if(!list.isEmpty())
	saveGeminiPoptastic(list.value(1),
			    list.value(2),
			    list.value(3),
			    list.value(4),
			    list.value(5),
			    "0000b");
    }
  else if(messageType == "0000d")
    {
      auto const list
	(spoton_receive::
	 process0000d(data.length(),
		      data,
		      symmetricKeys,
		      "127.0.0.1",
		      0,
		      crypt("poptastic")));

      if(!list.isEmpty())
	saveGeminiPoptastic(list.value(0),
			    list.value(1),
			    list.value(2),
			    list.value(3),
			    QByteArray(),
			    "0000d");
    }
  else if(messageType == "0001b")
    {
      auto const list
	(spoton_receive::process0001b(data.length(),
				      data,
				      "127.0.0.1",
				      0,
				      crypt("poptastic")));

      if(!list.isEmpty())
	{
	  QFileInfo const fileInfo(spoton_misc::homePath() +
				   QDir::separator() +
				   "email.db");
	  auto const maximumSize = 1048576 * setting
	    ("gui/maximumEmailFileSize", 1024).toLongLong();

	  if(fileInfo.size() >= maximumSize)
	    {
	      spoton_misc::logError
		("spoton_kernel::slotPoppedMessage(): "
		 "email.db has exceeded the specified limit.");
	      return;
	    }

	  auto s_crypt = crypt("poptastic");

	  if(!s_crypt)
	    return;

	  QByteArray attachmentData;
	  QByteArray date;
	  QByteArray message;
	  QByteArray name;
	  QByteArray senderPublicKeyHash;
	  QByteArray signature;
	  QByteArray subject;
	  auto goldbugUsed = false;

	  attachmentData = list.value(5);
	  date = list.value(4);
	  goldbugUsed = QVariant(list.value(6)).toBool();
	  message = list.value(3);
	  name = list.value(1);
	  senderPublicKeyHash = list.value(0);
	  signature = list.value(7);
	  subject = list.value(2);

	  if(!goldbugUsed && setting("gui/emailAcceptSignedMessagesOnly",
				     true).toBool())
	    {
	      QByteArray recipientDigest;
	      auto ok = true;

	      recipientDigest = s_crypt->publicKey(&ok);
	      recipientDigest = spoton_crypt::preferredHash(recipientDigest);

	      if(!ok ||
		 !spoton_misc::
		 isValidSignature("0001b" +
				  symmetricKeys.value(0) + // Encryption Key
				  symmetricKeys.value(2) + // Hash Key
				  symmetricKeys.value(1) + // Encryption Type
				  symmetricKeys.value(3) + // Hash Type
				  senderPublicKeyHash +
				  name +
				  subject +
				  message +
				  date +
				  attachmentData +
				  QByteArray::number(goldbugUsed) +
				  recipientDigest,
				  senderPublicKeyHash,
				  signature, s_crypt))
		{
		  spoton_misc::logError
		    ("spoton_kernel::slotPoppedMessage(): invalid signature.");
		  return;
		}
	    }

	  /*
	  ** We need to remember that the information here may have been
	  ** encoded with a goldbug. The interface will prompt the user
	  ** for the symmetric key.
	  */

	  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash,
						 "poptastic",
						 s_crypt))
	    return;

	  QString connectionName("");
	  auto attachmentData_l(attachmentData);
	  auto date_l(date);
	  auto goldbugUsed_l = goldbugUsed;
	  auto message_l(message);
	  auto name_l(name);
	  auto subject_l(subject);

	  if(goldbugUsed_l)
	    {
	      {
		auto db(spoton_misc::database(connectionName));

		db.setDatabaseName
		  (spoton_misc::homePath() +
		   QDir::separator() +
		   "friends_public_keys.db");

		if(db.open())
		  {
		    QSqlQuery query(db);
		    auto ok = true;

		    query.setForwardOnly(true);
		    query.prepare
		      ("SELECT forward_secrecy_authentication_algorithm, " // 0
		       "forward_secrecy_authentication_key, "              // 1
		       "forward_secrecy_encryption_algorithm, "            // 2
		       "forward_secrecy_encryption_key "                   // 3
		       "FROM friends_public_keys WHERE "
		       "neighbor_oid = -1 AND "
		       "public_key_hash = ?");
		    query.bindValue(0, senderPublicKeyHash.toBase64());

		    if(query.exec() && query.next())
		      if(!query.isNull(0) &&
			 !query.isNull(1) &&
			 !query.isNull(2) &&
			 !query.isNull(3))
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
			      magnet = spoton_misc::
				forwardSecrecyMagnetFromList
				(QList<QByteArray> () << aa << ak << ea << ek);

			      auto crypt =
				spoton_misc::cryptFromForwardSecrecyMagnet
				(magnet);

			      if(crypt)
				{
				  attachmentData_l = crypt->
				    decryptedAfterAuthenticated
				    (attachmentData_l, &ok);

				  if(ok)
				    date_l = crypt->
				      decryptedAfterAuthenticated(date_l, &ok);

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
	    auto db(spoton_misc::database(connectionName));

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "email.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		auto ok = true;

		query.prepare("INSERT INTO folders "
			      "(date, folder_index, from_account, "
			      "goldbug, hash, "
			      "message, message_code, "
			      "receiver_sender, receiver_sender_hash, sign, "
			      "signature, "
			      "status, subject, participant_oid) "
			      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
			      "?, ?, ?, ?, ?)");
		query.bindValue
		  (0, s_crypt->
		   encryptedThenHashed(date_l, &ok).toBase64());
		query.bindValue(1, 0); // Inbox Folder

		if(ok)
		  query.bindValue(2, s_crypt->encryptedThenHashed(QByteArray(),
								  &ok).
				  toBase64());

		if(ok)
		  query.bindValue
		    (3, s_crypt->
		     encryptedThenHashed(QByteArray::number(goldbugUsed_l),
					 &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (4, s_crypt->keyedHash(date_l + message_l + subject_l,
					   &ok).toBase64());

		if(ok)
		  if(!message_l.isEmpty())
		    query.bindValue
		      (5, s_crypt->encryptedThenHashed(message_l,
						       &ok).toBase64());

		if(ok)
		  query.bindValue
		    (6, s_crypt->encryptedThenHashed(QByteArray(), &ok).
		     toBase64());

		if(ok)
		  if(!name.isEmpty())
		    query.bindValue
		      (7, s_crypt->encryptedThenHashed(name_l,
						       &ok).toBase64());

		query.bindValue
		  (8, senderPublicKeyHash.toBase64());

		if(ok)
		  query.bindValue
		    (9, s_crypt->encryptedThenHashed(QByteArray(),
						     &ok).toBase64());

		if(ok)
		  query.bindValue
		    (10, s_crypt->encryptedThenHashed(signature,
						     &ok).toBase64());

		if(ok)
		  query.bindValue
		    (11, s_crypt->
		     encryptedThenHashed(QByteArray("Unread"), &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (12, s_crypt->encryptedThenHashed(subject_l, &ok).
		     toBase64());

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
			  auto const variant(query.lastInsertId());
			  auto const id = query.lastInsertId().toLongLong();

			  if(variant.isValid())
			    {
			      QByteArray data;

			      if(!goldbugUsed_l)
				data = qUncompress(attachmentData_l);
			      else
				data = attachmentData_l;

			      if(!data.isEmpty())
				{
				  QList<QPair<QByteArray, QByteArray> >
				    attachments;

				  if(!goldbugUsed_l)
				    {
				      QDataStream stream
					(&data, QIODevice::ReadOnly);

				      stream >> attachments;

				      if(stream.status() != QDataStream::Ok)
					attachments.clear();
				    }
				  else
				    attachments <<
				      QPair<QByteArray, QByteArray>
				      (data, data);

				  for(int i = 0; i < attachments.size(); i++)
				    {
				      QSqlQuery query(db);
				      auto const pair(attachments.at(i));

				      query.prepare
					("INSERT INTO folders_attachment "
					 "(data, folders_oid, name) "
					 "VALUES (?, ?, ?)");
				      query.bindValue
					(0, s_crypt->
					 encryptedThenHashed(pair.first,
							     &ok).
					 toBase64());
				      query.bindValue(1, id);

				      if(ok)
					query.bindValue
					  (2, s_crypt->
					   encryptedThenHashed(pair.second,
							       &ok).
					   toBase64());

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
    }
  else if(messageType == "0001c")
    {
      auto const list
	(spoton_receive::process0001c(data.length(),
				      data,
				      symmetricKeys,
				      "127.0.0.1",
				      0,
				      "poptastic",
				      crypt("email")));

      if(!list.isEmpty())
	emit newEMailArrived();
    }
  else if(messageType == "0013")
    {
      auto const list
	(spoton_receive::
	 process0013(data.length(),
		     data,
		     symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     "127.0.0.1",
		     0,
		     crypt("poptastic")));

      if(!list.isEmpty())
	spoton_misc::saveParticipantStatus
	  (list.value(1),                                  // Name
	   list.value(0),                                  // Public Key Hash
	   list.value(2),                                  // Status
	   list.value(3),                                  // Timestamp
	   2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL, // Seconds
	   crypt("poptastic"));
    }
  else if(messageType == "0091a")
    {
      auto const list
	(spoton_receive::process0091(data.length(),
				     data,
				     symmetricKeys,
				     "127.0.0.1",
				     0,
				     messageType));

      if(!list.isEmpty())
	emit forwardSecrecyRequest(list);
    }
  else if(messageType == "0091b")
    {
      auto const list
	(spoton_receive::process0091(data.length(),
				     data,
				     symmetricKeys,
				     "127.0.0.1",
				     0,
				     messageType));

      if(!list.isEmpty())
	slotSaveForwardSecrecySessionKeys(list);
    }
  else if(messageType == "0092")
    {
      auto const list
	(spoton_receive::process0092(data.length(),
				     data,
				     symmetricKeys,
				     "127.0.0.1",
				     0));

      if(!list.isEmpty())
	emit smpMessage(list);
    }
  else
    {
      QFileInfo const fileInfo
	(spoton_misc::homePath() + QDir::separator() + "email.db");
      auto const maximumSize = 1048576 * setting
	("gui/maximumEmailFileSize", 1024).toLongLong();

      if(fileInfo.size() >= maximumSize)
	{
	  spoton_misc::logError
	    ("spoton_kernel::slotPoppedMessage(): "
	     "email.db has exceeded the specified limit.");
	  return;
	}

      auto s_crypt = crypt("poptastic");

      if(!s_crypt)
	return;

      QByteArray boundary;
      QByteArray from;
      QByteArray subject;
      QList<QByteArray> mList;
      auto const hash
	(spoton_crypt::preferredHash(message.mid(message.indexOf("content=")).
				     simplified()).toHex());
      auto const list(message.trimmed().split('\n'));
      auto date(QDateTime::currentDateTime());

      for(int i = 0; i < list.size(); i++)
	if(list.value(i).toLower().contains("content-type: text/"))
	  {
	    if(!from.isEmpty())
	      boundary = list.value(i).toLower();
	  }
	else if(list.value(i).toLower().startsWith("date:"))
	  {
	    auto str(list.value(i));

	    str.remove(0, static_cast<int> (qstrlen("date:")));
	    str = str.trimmed();

	    if(!str.isEmpty())
	      date = QDateTime::fromString(str, Qt::RFC2822Date);
	  }
	else if(list.value(i).toLower().startsWith("from:"))
	  {
	    if(from.isEmpty())
	      {
		from = list.value(i);
		from.remove(0, static_cast<int> (qstrlen("from:")));
		from = from.trimmed();
		from = from.replace("<", "").replace(">", "");

		if(from.contains(" "))
		  {
		    from = from.mid(from.lastIndexOf(" "));
		    from = from.trimmed();
		  }
	      }
	  }
	else if(list.value(i).toLower().startsWith("subject:"))
	  {
	    if(subject.isEmpty())
	      {
		subject = list.value(i);
		subject.remove(0, static_cast<int> (qstrlen("subject:")));
		subject = subject.trimmed();
	      }
	  }
	else if(!boundary.isEmpty() && mList.isEmpty())
	  {
	    while(i < list.size())
	      {
		if(list.value(i).trimmed().isEmpty())
		  {
		    if(!mList.isEmpty() && i + 1 < list.size())
		      mList << "\n";
		  }
		else if(list.value(i).contains(boundary))
		  break;
		else
		  mList << list.value(i).trimmed();

		i += 1;
	      }
	  }

      if(spoton_crypt::memcmp(hash, subject))
	/*
	** Ignore messages that we believe were created by other
	** Spot-On participants.
	*/

	return;

      QByteArray attachment;
      QByteArray attachmentName;

      for(int i = 0; i < list.size(); i++)
	if(list.value(i).toLower().
	   contains("content-disposition: attachment; filename="))
	  {
	    attachmentName = list.value(i).trimmed();
	    attachmentName.remove
	      (0, static_cast<int> (qstrlen("content-disposition: "
					    "attachment; "
					    "filename=")));
	    attachmentName.replace('"', "");

	    while(i < list.size())
	      {
		if(list.value(i).trimmed().isEmpty())
		  break;

		i += 1;
	      }

	    i += 1;

	    QByteArray bytes;

	    while(i < list.size())
	      {
		if(list.value(i).trimmed().isEmpty())
		  break;
		else
		  {
		    QRegularExpression rx("[^a-zA-Z0-9+/=]");
		    auto const match
		      (rx.match(list.value(i).trimmed()));

		    if(!match.hasMatch())
		      bytes.append(list.value(i).trimmed());
		    else
		      break;
		  }

		i += 1;
	      }

	    if(!bytes.isEmpty())
	      attachment = QByteArray::fromBase64(bytes);

	    break;
	  }

      QByteArray m;

      for(int i = 0; i < mList.size(); i++)
	 /*
	 ** The e-mail widget supports HTML.
	 */

	m.append(mList.at(i).trimmed()).append("<br>");

      m = m.trimmed();

      if(m.isEmpty())
	/*
	** Humans are excellent readers.
	*/

	m = message;

      QString connectionName("");

      {
	auto db(spoton_misc::database(connectionName));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "email.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    auto ok = true;

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, from_account, goldbug, hash, "
			  "message, message_code, "
			  "receiver_sender, receiver_sender_hash, "
			  "sign, signature, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, s_crypt->
	       encryptedThenHashed(date.toString(Qt::RFC2822Date).
				   toLatin1(), &ok).toBase64());
	    query.bindValue(1, 0); // Inbox Folder

	    if(ok)
	      query.bindValue(2, s_crypt->encryptedThenHashed(QByteArray(),
							      &ok).
			      toBase64());

	    if(ok)
	      query.bindValue
		(3, s_crypt->
		 encryptedThenHashed(QByteArray::number(0), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(4, s_crypt->keyedHash(date.toString(Qt::RFC2822Date).
				       toLatin1() + m + subject,
				       &ok).toBase64());

	    if(ok)
	      if(!m.isEmpty())
		query.bindValue
		  (5, s_crypt->encryptedThenHashed(m,
						   &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, s_crypt->encryptedThenHashed(QByteArray(), &ok).
		 toBase64());

	    if(ok)
	      if(!from.isEmpty())
		query.bindValue
		  (7, s_crypt->encryptedThenHashed(from,
						   &ok).toBase64());

	    if(ok)
	      {
		auto const senderPublicKeyHash
		  (spoton_crypt::preferredHash(from + "-poptastic"));

		query.bindValue
		  (8, senderPublicKeyHash.toBase64());
	      }

	    if(ok)
	      query.bindValue(9, s_crypt->encryptedThenHashed(QByteArray(),
							      &ok).
			      toBase64());

	    if(ok)
	      query.bindValue(10, s_crypt->
			      encryptedThenHashed(QByteArray(), &ok).
			      toBase64());

	    if(ok)
	      query.bindValue
		(11, s_crypt->
		 encryptedThenHashed(QByteArray("Unread"), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(12, s_crypt->encryptedThenHashed(subject, &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(13, s_crypt->
		 encryptedThenHashed(QByteArray::number(-1), &ok).
		 toBase64());

	    if(ok)
	      if(query.exec())
		{
		  if(!attachment.isEmpty() && !attachmentName.isEmpty())
		    {
		      auto const variant(query.lastInsertId());
		      auto const id = query.lastInsertId().toLongLong();

		      if(variant.isValid())
			{
			  auto const data(attachment);

			  if(!data.isEmpty())
			    {
			      QSqlQuery query(db);

			      query.prepare
				("INSERT INTO folders_attachment "
				 "(data, folders_oid, name) "
				 "VALUES (?, ?, ?)");
			      query.bindValue
				(0, s_crypt->
				 encryptedThenHashed(data,
						     &ok).toBase64());
			      query.bindValue(1, id);

			      if(ok)
				query.bindValue
				  (2, s_crypt->
				   encryptedThenHashed(attachmentName,
						       &ok).toBase64());

			      if(ok)
				query.exec();
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
}

void spoton_kernel::slotPoptasticPop(void)
{
  if(m_poptasticPopFuture.isFinished())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    m_poptasticPopFuture =
      QtConcurrent::run(&spoton_kernel::popPoptastic, this);
#else
    m_poptasticPopFuture =
      QtConcurrent::run(this, &spoton_kernel::popPoptastic);
#endif
}

void spoton_kernel::slotPoptasticPost(void)
{
  if(m_poptasticPostFuture.isFinished())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    m_poptasticPostFuture =
      QtConcurrent::run(&spoton_kernel::postPoptastic, this);
#else
    m_poptasticPostFuture =
      QtConcurrent::run(this, &spoton_kernel::postPoptastic);
#endif
}

void spoton_kernel::slotSaveForwardSecrecySessionKeys
(const QByteArrayList &list)
{
  if(list.isEmpty())
    return;

  auto s_crypt = crypt("chat");

  if(!s_crypt)
    return;

  QByteArray data;
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);
  QMutableHashIterator<QByteArray, QVector<QVariant> > it
    (m_forwardSecrecyKeys);
  auto const bundle(list.value(1));

  while(it.hasNext())
    {
      it.next();

      QPair<QByteArray, QByteArray> pair;
      auto const vector(it.value());
      auto ok = true;

      pair.first = s_crypt->decryptedAfterAuthenticated
	(vector.value(0).toByteArray(), &ok);

      if(!ok)
	continue;

      pair.second = s_crypt->decryptedAfterAuthenticated
	(vector.value(1).toByteArray(), &ok);

      if(!ok)
	continue;

      pair.first = qUncompress(pair.first);
      pair.second = qUncompress(pair.second);

      spoton_crypt crypt(pair.first, pair.second);

      data = crypt.publicKeyDecrypt(bundle, &ok);

      if(ok)
	{
	  it.remove();
	  break;
	}
    }

  locker.unlock();

  if(data.isEmpty())
    return;

  data = qUncompress(data);

  QDataStream stream(&data, QIODevice::ReadOnly);
  QList<QByteArray> output;

  for(int i = 0; i < 4; i++)
    {
      QByteArray a;

      stream >> a;

      if(stream.status() != QDataStream::Ok)
	{
	  output.clear();
	  break;
	}
      else
	output << a;
    }

  if(output.size() != 4)
    return;

  QString connectionName("");
  auto ok = false;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE friends_public_keys "
	   "SET forward_secrecy_authentication_algorithm = ?, "
	   "forward_secrecy_authentication_key = ?, "
	   "forward_secrecy_encryption_algorithm = ?, "
	   "forward_secrecy_encryption_key = ? WHERE "
	   "public_key_hash = ?");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(output.value(0), &ok).
	   toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->encryptedThenHashed(output.value(1),
					     &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->encryptedThenHashed(output.value(2), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->encryptedThenHashed(output.value(3),
					     &ok).toBase64());

	if(ok)
	  query.bindValue(4, list.value(0).toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    emit forwardSecrecyResponseReceived(list);
}

void spoton_kernel::slotUrlImportTimerExpired(void)
{
  for(int i = 0; i < m_urlImportFutures.size(); i++)
    if(m_urlImportFutures.at(i).isFinished())
      {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
	m_urlImportFutures.replace
	  (i, QtConcurrent::run(&spoton_kernel::importUrls, this));
#else
	m_urlImportFutures.replace
	  (i, QtConcurrent::run(this, &spoton_kernel::importUrls));
#endif
	break;
      }
}
