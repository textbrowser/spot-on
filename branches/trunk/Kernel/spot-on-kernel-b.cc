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

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-receive.h"
#include "spot-on-kernel.h"

#include <QSqlQuery>

static QList<QByteArray> curl_payload_text;

struct curl_memory
{
  char *memory;
  size_t size;
};

struct curl_upload_status
{
  int lines_read;
};

static size_t curl_payload_source
(void *ptr, size_t size, size_t nmemb, void *userp)
{
  if(nmemb <= 0 || !ptr || size <= 0 || (nmemb * size) < 1 || !userp)
    return 0;

  struct curl_upload_status *upload_ctx =
    (struct curl_upload_status *) userp;

  if(!upload_ctx || upload_ctx->lines_read >= curl_payload_text.size())
    return 0;

  const char *data = curl_payload_text[upload_ctx->lines_read].constData();

  if(data)
    {
      size_t length = strlen(data);

      if(length > 0)
	memcpy(ptr, data, qMin(length, nmemb * size));

      upload_ctx->lines_read++;
      return length;
    }
  else
    spoton_misc::logError("curl_payload_source(): data is zero!");

  return 0;
}

static size_t curl_write_memory_callback(void *contents, size_t size,
					 size_t nmemb, void *userp)
{
  if(!contents || nmemb <= 0 || size <= 0 || !userp)
    return 0;

  struct curl_memory *memory = (struct curl_memory *) userp;

  if(!memory)
    return 0;

  size_t realsize = nmemb * size;

  memory->memory = (char *)
    realloc(memory->memory, memory->size + realsize + 1);

  if(!memory->memory)
    {
      spoton_misc::logError
	("curl_write_memory_callback(): memory->memory is zero!");
      return 0;
    }

  memcpy(&(memory->memory[memory->size]), contents, realsize);
  memory->size += realsize;
  memory->memory[memory->size] = 0;
  return realsize;
}

void spoton_kernel::slotPoptasticPop(void)
{
  if(m_poptasticPopFuture.isFinished())
    m_poptasticPopFuture =
      QtConcurrent::run(this, &spoton_kernel::popPoptastic);
}

void spoton_kernel::slotPoptasticPost(void)
{
  if(m_poptasticPostFuture.isFinished())
    m_poptasticPostFuture =
      QtConcurrent::run(this, &spoton_kernel::postPoptastic);
}

void spoton_kernel::popPoptastic(void)
{
  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

  if(!s_crypt)
    return;

  QHash<QString, QVariant> hash;
  bool ok = true;

  if(m_poptasticAccounts.isEmpty())
    m_poptasticAccounts = spoton_misc::poptasticSettings("", s_crypt, &ok);

  /*
  ** Discover an enabled account.
  */

  for(int i = m_poptasticAccounts.size() - 1; i >= 0; i--)
    {
      hash = m_poptasticAccounts.at(i);

      if(hash["in_method"].toString() != "Disable")
	{
	  m_poptasticAccounts.removeAt(i);
	  break;
	}
      else
	hash.clear();
    }

  if(hash.isEmpty() || !ok)
    {
      spoton_misc::logError("spoton_kernel::popPoptastic(): "
			    "spoton_misc::poptasticSettings() failed or "
			    "Poptastic inbound accounts are disabled.");
      return;
    }

  CURL *curl = 0;
  QHash<QByteArray, char> cache;
  QList<int> list;
  bool popRound = true;

 begin_label:
  curl = curl_easy_init();

  if(curl)
    {
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 hash["in_password"].toByteArray().constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 hash["in_username"].toByteArray().trimmed().constData());

      long timeout = 10L;

      if(hash["proxy_enabled"].toBool())
	{
	  timeout += 15L;

	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = hash["proxy_server_address"].toString().trimmed();
	  port = hash["proxy_server_port"].toString().trimmed();

	  if(hash["proxy_type"] == "HTTP")
	    scheme = "http";
	  else
	    scheme = "socks5";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt
	    (curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   hash["proxy_password"].toString().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   hash["proxy_username"].toString().
			   trimmed().toLatin1().constData());
	}

      QString method(hash["in_method"].toString().toUpper().trimmed());
      QString ssltls(hash["in_ssltls"].toString().toUpper().trimmed());
      QString url("");

      if(ssltls == "SSL" || ssltls == "TLS")
	{
	  if(method == "IMAP")
	    {
	      if(popRound)
		url = QString("imaps://%1:%2/INBOX/;UID=1").
		  arg(hash["in_server_address"].toString().trimmed()).
		  arg(hash["in_server_port"].toString().trimmed());
	      else
		url = QString("imaps://%1:%2/INBOX").
		  arg(hash["in_server_address"].toString().trimmed()).
		  arg(hash["in_server_port"].toString().trimmed());
	    }
	  else
	    url = QString("pop3s://%1:%2/1").
	      arg(hash["in_server_address"].toString().trimmed()).
	      arg(hash["in_server_port"].toString().trimmed());

	  long verify = static_cast<long>(hash["in_verify_host"].toInt());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long>(hash["in_verify_peer"].toInt());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(ssltls == "TLS")
	    {
	      QFileInfo fileInfo
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
	      if(popRound)
		url = QString("imap://%1:%2/INBOX/;UID=1").
		  arg(hash["in_server_address"].toString().trimmed()).
		  arg(hash["in_server_port"].toString().trimmed());
	      else
		url = QString("imap://%1:%2/INBOX").
		  arg(hash["in_server_address"].toString().trimmed()).
		  arg(hash["in_server_port"].toString().trimmed());
	    }
	  else
	    url = QString("pop3://%1:%2/1").
	      arg(hash["in_server_address"].toString().trimmed()).
	      arg(hash["in_server_port"].toString().trimmed());
	}

      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

      if(popRound)
	{
	  popRound = false;

	  for(int i = 1; i <= 15; i++)
	    {
	      struct curl_memory chunk;

	      chunk.memory = (char *) malloc(1);

	      if(!chunk.memory)
		break;

	      chunk.size = 0;
	      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);
	      curl_easy_setopt
		(curl, CURLOPT_WRITEFUNCTION, curl_write_memory_callback);

	      CURLcode rc = CURLE_OK;

	      if((rc = curl_easy_perform(curl)) == CURLE_OK)
		{
		  if(method == "IMAP")
		    {
		      list.append(i);
		      url.replace
			(QString("UID=%1").arg(i),
			 QString("UID=%1").arg(i + 1));
		      curl_easy_setopt
			(curl, CURLOPT_URL, url.toLatin1().constData());
		    }
		  else
		    {
		      url = url.mid(0, url.lastIndexOf('/'));
		      url.append("/");
		      url.append(QByteArray::number(i));
		      curl_easy_setopt
			(curl, CURLOPT_URL, url.toLatin1().constData());
		    }

		  if(chunk.size > 0)
		    {
		      QByteArray hash;
		      QByteArray message
			(QByteArray(chunk.memory,
				    static_cast<int> (chunk.size)));
		      bool ok = true;

		      hash = s_crypt->keyedHash(message, &ok);

		      if(!cache.contains(hash))
			{
			  emit poppedMessage(message);
			  cache[hash] = 0;
			}
		    }
		}
	      else
		{
		  free(chunk.memory);
		  spoton_misc::logError
		    (QString("spoton_kernel::popPoptastic(): "
			     "curl_easy_perform() failure (%1).").arg(rc));
		  break;
		}

	      free(chunk.memory);

	      if(m_poptasticPopFuture.isCanceled())
		break;
	    }
	}
      else
	{
	  while(!list.isEmpty())
	    {
	      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	      curl_easy_setopt
		(curl, CURLOPT_URL, url.toLatin1().constData());
	      curl_easy_setopt
		(curl, CURLOPT_CUSTOMREQUEST,
		 QString("STORE %1 +Flags \\Deleted").
		 arg(list.takeFirst()).toLatin1().constData());

	      CURLcode rc = CURLE_OK;

	      if((rc = curl_easy_perform(curl)) != CURLE_OK)
		{
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
	    }
	}

      curl_easy_cleanup(curl);

      if(m_poptasticPopFuture.isCanceled())
	return;
    }
  else
    spoton_misc::logError("spoton_kernel::popPoptastic(): "
			  "curl_easy_init() failure.");

  if(!list.isEmpty())
    goto begin_label;
}

void spoton_kernel::postPoptastic(void)
{
  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

  if(!s_crypt)
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  QList<QHash<QString, QVariant> > list;
  bool ok = true;

  list = spoton_misc::poptasticSettings("", s_crypt, &ok);

  if(list.isEmpty() || !ok)
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  bool disabled = true;

  for(int i = 0; i < list.size(); i++)
    if(list.at(i)["out_method"] != "Disable")
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
      const QHash<QString, QVariant> v(m_poptasticCache.head());

      locker.unlock();

      QHash<QString, QVariant> h;

      for(int i = 0; i < list.size(); i++)
	if(list.at(i)["in_username"].toString() == v["from_account"].toString())
	  {
	    h = list.at(i);

	    if(h["out_method"] == "Disable")
	      {
		/*
		** Remove the values item from the cache.
		*/

		QWriteLocker locker(&m_poptasticCacheMutex);

		if(!m_poptasticCache.isEmpty())
		  m_poptasticCache.removeOne(v);

		return;
	      }

	    break;
	  }

      CURL *curl = curl_easy_init();
      const QHash<QString, QVariant> hash(h);

      if(curl)
	{
	  curl_easy_setopt
	    (curl, CURLOPT_PASSWORD,
	     hash["out_password"].toByteArray().constData());
	  curl_easy_setopt
	    (curl, CURLOPT_USERNAME,
	     hash["out_username"].toByteArray().trimmed().constData());

	  long timeout = 10L;

	  if(hash["proxy_enabled"].toBool())
	    {
	      timeout += 15L;

	      QString address("");
	      QString port("");
	      QString scheme("");
	      QString url("");

	      address = hash["proxy_server_address"].toString().trimmed();
	      port = hash["proxy_server_port"].toString().trimmed();

	      if(hash["proxy_type"] == "HTTP")
		scheme = "http";
	      else
		scheme = "socks5";

	      url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	      curl_easy_setopt
		(curl, CURLOPT_PROXY, url.toLatin1().constData());
	      curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			       hash["proxy_password"].toString().
			       toUtf8().constData());
	      curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			       hash["proxy_username"].toString().
			       trimmed().toLatin1().constData());
	    }

	  QString from(hash["in_username"].toString().trimmed());
	  QString ssltls(hash["out_ssltls"].toString().toUpper().trimmed());
	  QString url("");

	  if(ssltls == "SSL" || ssltls == "TLS")
	    {
	      if(ssltls == "SSL")
		url = QString("smtps://%1:%2/%3").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed()).
		  arg(hash.value("smtp_localname", "localhost").
		      toString());
	      else
		url = QString("smtp://%1:%2/%3").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed()).
		  arg(hash.value("smtp_localname", "localhost").
		      toString());

	      long verify = static_cast<long>
		(hash["out_verify_host"].toInt());

	      if(verify)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	      else
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	      verify = static_cast<long>
		(hash["out_verify_peer"].toInt());
	      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	      if(ssltls == "TLS")
		{
		  QFileInfo fileInfo
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
	      arg(hash["out_server_address"].toString().trimmed()).
	      arg(hash["out_server_port"].toString().trimmed()).
	      arg(hash.value("smtp_localname", "localhost").
		  toString());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

	  for(int i = 1, j = 1; i <= 15;)
	    {
	      QReadLocker locker(&m_poptasticCacheMutex);

	      if(m_poptasticCache.isEmpty())
		break;

	      const QHash<QString, QVariant> values(m_poptasticCache.head());

	      locker.unlock();

	      QByteArray bytes(values["message"].toByteArray());
	      long count = 0;
	      struct curl_slist *recipients = 0;
	      struct curl_upload_status upload_ctx;

	      upload_ctx.lines_read = 0;
	      curl_easy_setopt
		(curl, CURLOPT_MAIL_FROM,
		 QString("<%1>").arg(from).toLatin1().constData());
	      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	      /*
	      ** Prepare curl_payload_text.
	      */

	      curl_payload_text.clear();
	      curl_payload_text.append
		(QString("Date: %1\r\n").arg(QDateTime::currentDateTime().
					     toUTC().toString()).toLatin1());

	      if(values.size() == 4)
		curl_payload_text.append(QString("To: <%1> (%1)\r\n").
					 arg(values["receiver_name"].
					     toString()).
					 toLatin1());
	      else
		curl_payload_text.append(QString("To: <%1> (%1)\r\n").
					 arg(values["name"].toByteArray().
					     constData()).
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
		     arg(spoton_crypt::sha512Hash(bytes.simplified(), &ok).
			 toHex().constData()).toLatin1());
		  curl_payload_text.append("\r\n");
		}
	      else
		{
		  curl_payload_text.append("Subject: ");
		  curl_payload_text.append(values["subject"].toByteArray());
		  curl_payload_text.append("\r\n");
		}

	      QByteArray attachment(values["attachment"].toByteArray());
	      QByteArray attachmentName
		(values["attachment_name"].toByteArray());

	      if(attachment.isEmpty() || attachmentName.isEmpty() ||
		 values.size() == 4)
		{
		  while(!bytes.isEmpty())
		    {
		      count += 1;
		      curl_payload_text.append
			(bytes.mid(0, CURL_MAX_WRITE_SIZE));
		      bytes.remove(0, CURL_MAX_WRITE_SIZE);
		    }
		}
	      else if(!attachment.isEmpty() && !attachmentName.isEmpty())
		{
		  QByteArray a(attachment.toBase64());
		  QByteArray bytes;
		  QByteArray r1(spoton_crypt::weakRandomBytes(8).toHex());
		  QByteArray r2(spoton_crypt::weakRandomBytes(8).toHex());
		  QString str("");

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
		     arg(values["message"].toByteArray().constData()).
		     arg(attachmentName.constData()));
		  bytes.append(str);

		  while(!a.isEmpty())
		    {
		      bytes.append(a.mid(0, 76));
		      a.remove(0, 76);
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
		    (curl, CURLOPT_INFILESIZE,
		     static_cast<size_t> (attachment.toBase64().length()));
		}

	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append("\r\n");
	      curl_payload_text.append(0);

	      if(values.size() == 4)
		recipients = curl_slist_append
		  (recipients, values["receiver_name"].toString().
		   toLatin1().constData());
	      else
		recipients = curl_slist_append
		  (recipients, values["name"].toByteArray().constData());

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
		  (curl, CURLOPT_TIMEOUT, (long) 2.5 * count + timeout);

	      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	      CURLcode rc = CURLE_OK;

	      if((rc = curl_easy_perform(curl)) == CURLE_OK)
		{
		  i += 1;
		  j = 1;

		  QWriteLocker locker(&m_poptasticCacheMutex);

		  if(!m_poptasticCache.isEmpty())
		    m_poptasticCache.removeOne(values);

		  locker.unlock();

		  qint64 mailOid = -1;

		  if(!values.isEmpty())
		    mailOid = values["mail_oid"].toLongLong();

		  if(mailOid > -1)
		    spoton_misc::moveSentMailToSentFolder
		      (QList<qint64> () << mailOid, s_crypt);
		}
	      else
		{
		  if(j >= spoton_common::MAXIMUM_ATTEMPTS_PER_POPTASTIC_POST)
		    {
		      i += 1;
		      j = 1;

		      QWriteLocker locker(&m_poptasticCacheMutex);

		      if(!m_poptasticCache.isEmpty())
			m_poptasticCache.removeOne(values);

		      locker.unlock();
		    }
		  else
		    j += 1;

		  spoton_misc::logError
		    (QString("spoton_kernel::postPoptastic(): "
			     "curl_easy_perform() failure (%1).").
		     arg(rc));
		}

	      curl_slist_free_all(recipients);

	      if(m_poptasticPostFuture.isCanceled())
		break;
	    }

	  curl_easy_cleanup(curl);
	}
      else
	spoton_misc::logError("spoton_kernel::postPoptastic(): "
			      "curl_easy_init() failure.");
    }
}

void spoton_kernel::slotPoppedMessage(const QByteArray &message)
{
  QByteArray data
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
  ** spot-on-neighbor.cc.
  */

  QList<QByteArray> symmetricKeys;
  QString messageType
    (spoton_receive::findMessageType(data, symmetricKeys,
				     interfaces(),
				     "poptastic",
				     s_crypts.value("poptastic", 0)));

  if(messageType == "0000")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000(data.length(), data, symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     "127.0.0.1", 0,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	{
	  spoton_misc::saveParticipantStatus
	    (list.value(1),                                  // Name
	     list.value(0),                                  /*
							     ** Public
							     ** Key Hash
							     */
	     QByteArray(),                                   // Status
	     QDateTime::currentDateTime().toUTC().
	     toString("MMddyyyyhhmmss").
	     toLatin1(),                                     // Timestamp
	     2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL, // Seconds
	     s_crypts.value("poptastic", 0));
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
      QList<QByteArray> list
	(spoton_receive::
	 process0000a(data.length(), data,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      "127.0.0.1", 0,
		      messageType,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(0), list.value(1),
		   list.value(2), list.value(3),
		   list.value(4), "0000a");
    }
  else if(messageType == "0000b")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000b(data.length(), data, symmetricKeys,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      "127.0.0.1", 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(1), list.value(2),
		   list.value(3), list.value(4),
		   list.value(5), "0000b");
    }
  else if(messageType == "0000d")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000d(data.length(), data, symmetricKeys,
		      "127.0.0.1", 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(0), list.value(1),
		   list.value(2), list.value(3),
		   QByteArray(), "0000d");
    }
  else if(messageType == "0001b")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0001b(data.length(), data,
		      "127.0.0.1", 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	{
	  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
			     "email.db");
	  qint64 maximumSize = 1048576 * setting
	    ("gui/maximumEmailFileSize", 100).toLongLong();

	  if(fileInfo.size() >= maximumSize)
	    {
	      spoton_misc::logError
		("spoton_kernel::slotPoppedMessage(): "
		 "email.db has exceeded the specified limit.");
	      return;
	    }

	  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

	  if(!s_crypt)
	    return;

	  QByteArray attachment;
	  QByteArray attachmentName;
	  QByteArray message;
	  QByteArray name;
	  QByteArray senderPublicKeyHash;
	  QByteArray signature;
	  QByteArray subject;
	  bool goldbugUsed = false;

	  senderPublicKeyHash = list.value(0);
	  name = list.value(1);
	  subject = list.value(2);
	  message = list.value(3);
	  attachment = list.value(4);
	  attachmentName = list.value(5);
	  signature = list.value(6);
	  goldbugUsed = QVariant(list.value(7)).toBool();

	  if(setting("gui/emailAcceptSignedMessagesOnly",
		     true).toBool())
	    if(!spoton_misc::
	       isValidSignature("0001b" +
				symmetricKeys.value(0) + // Encryption Key
				symmetricKeys.value(2) + // Hash Key
				symmetricKeys.value(1) + // Encryption Type
				symmetricKeys.value(3) + // Hash Type
				senderPublicKeyHash +
				name +
				subject +
				message +
				attachment +
				attachmentName,
				senderPublicKeyHash,
				signature, s_crypt))
	      {
		spoton_misc::logError
		  ("spoton_kernel::slotPoppedMessage(): invalid signature.");
		return;
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

	  QByteArray attachmentName_l(attachmentName);
	  QByteArray attachment_l(attachment);
	  QByteArray message_l(message);
	  QByteArray name_l(name);
	  QByteArray subject_l(subject);
	  QString connectionName("");
	  bool goldbugUsed_l = goldbugUsed;

	  if(goldbugUsed_l)
	    {
	      {
		QSqlDatabase db = spoton_misc::database(connectionName);

		db.setDatabaseName
		  (spoton_misc::homePath() + QDir::separator() +
		   "friends_public_keys.db");

		if(db.open())
		  {
		    QSqlQuery query(db);
		    bool ok = true;

		    query.setForwardOnly(true);
		    query.prepare
		      ("SELECT forward_secrecy_authentication_algorithm, "
		       "forward_secrecy_authentication_key, "
		       "forward_secrecy_encryption_algorithm, "
		       "forward_secrecy_encryption_key FROM "
		       "friends_public_keys WHERE "
		       "neighbor_oid = -1 AND "
		       "public_key_hash = ?");
		    query.bindValue(0, senderPublicKeyHash.toBase64());

		    if(query.exec() && query.next())
		      if(!query.isNull(0) && !query.isNull(1) &&
			 !query.isNull(2) && !query.isNull(3))
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

			      spoton_crypt *crypt =
				spoton_misc::cryptFromForwardSecrecyMagnet
				(magnet);

			      if(crypt)
				{
				  attachmentName_l = crypt->
				    decryptedAfterAuthenticated
				    (attachmentName_l, &ok);

				  if(ok)
				    attachment_l = crypt->
				      decryptedAfterAuthenticated
				      (attachment_l, &ok);

				  if(ok)
				    message_l = crypt->
				      decryptedAfterAuthenticated
				      (message_l, &ok);

				  if(ok)
				    name_l = crypt->
				      decryptedAfterAuthenticated
				      (name_l, &ok);

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

				      attachmentName_l = attachmentName;
				      attachment_l = attachment;
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
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "email.db");

	    if(db.open())
	      {
		QDateTime now(QDateTime::currentDateTime());
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("INSERT INTO folders "
			      "(date, folder_index, from_account, "
			      "goldbug, hash, "
			      "message, message_code, "
			      "receiver_sender, receiver_sender_hash, "
			      "signature, "
			      "status, subject, participant_oid) "
			      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
			      "?, ?, ?, ?, ?)");
		query.bindValue
		  (0, s_crypt->
		   encryptedThenHashed(now.toString(Qt::ISODate).
				       toLatin1(), &ok).toBase64());
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
		    (4, s_crypt->keyedHash(now.toString(Qt::ISODate).
					   toLatin1() + message_l + subject_l,
					   &ok).toBase64());

		if(ok)
		  if(!message.isEmpty())
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
		    (9, s_crypt->encryptedThenHashed(signature,
						     &ok).toBase64());

		if(ok)
		  query.bindValue
		    (10, s_crypt->
		     encryptedThenHashed(QByteArray("Unread"), &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (11, s_crypt->encryptedThenHashed(subject_l, &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (12, s_crypt->
		     encryptedThenHashed(QByteArray::number(-1), &ok).
		     toBase64());

		if(ok)
		  if(query.exec())
		    {
		      if(!attachment_l.isEmpty() &&
			 !attachmentName_l.isEmpty())
			{
			  QVariant variant(query.lastInsertId());
			  qint64 id = query.lastInsertId().toLongLong();

			  if(variant.isValid())
			    {
			      QByteArray data;

			      if(!goldbugUsed_l)
				data = qUncompress(attachment_l);
			      else
				data = attachment_l;

			      if(!data.isEmpty())
				{
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
				       encryptedThenHashed(attachmentName_l,
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
  else if(messageType == "0001c")
    {
      QList<QByteArray> list
	(spoton_receive::process0001c(data.length(), data, symmetricKeys,
				      "127.0.0.1", 0,
				      "poptastic",
				      spoton_kernel::s_crypts.
				      value("email", 0)));

      if(!list.isEmpty())
	emit newEMailArrived();
    }
  else if(messageType == "0013")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0013(data.length(), data, symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     "127.0.0.1", 0,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	spoton_misc::saveParticipantStatus
	  (list.value(1),                                  // Name
	   list.value(0),                                  // Public Key Hash
	   list.value(2),                                  // Status
	   list.value(3),                                  // Timestamp
	   2.5 * spoton_common::POPTASTIC_STATUS_INTERVAL, // Seconds
	   s_crypts.value("poptastic", 0));
    }
  else if(messageType == "0091a")
    {
      QList<QByteArray> list
	(spoton_receive::process0091(data.length(), data, symmetricKeys,
				     "127.0.0.1", 0,
				     messageType));

      if(!list.isEmpty())
	emit forwardSecrecyRequest(list);
    }
  else if(messageType == "0091b")
    {
      QList<QByteArray> list
	(spoton_receive::process0091(data.length(), data, symmetricKeys,
				     "127.0.0.1", 0,
				     messageType));

      if(!list.isEmpty())
	slotSaveForwardSecrecySessionKeys(list);
    }
  else
    {
      QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
			 "email.db");
      qint64 maximumSize = 1048576 * setting
	("gui/maximumEmailFileSize", 100).toLongLong();

      if(fileInfo.size() >= maximumSize)
	{
	  spoton_misc::logError
	    ("spoton_kernel::slotPoppedMessage(): "
	     "email.db has exceeded the specified limit.");
	  return;
	}

      spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

      if(!s_crypt)
	return;

      QByteArray boundary;
      QByteArray from;
      QByteArray hash
	(spoton_crypt::sha512Hash(message.mid(message.indexOf("content=")).
				  simplified(), 0).toHex());
      QByteArray subject;
      QList<QByteArray> list(message.trimmed().split('\n'));
      QList<QByteArray> mList;

      for(int i = 0; i < list.size(); i++)
	if(list.value(i).toLower().contains("content-type: text/"))
	  {
	    if(!from.isEmpty())
	      boundary = list.value(i).toLower();
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
		    QRegExp rx("[^a-zA-Z0-9+/=]");

		    if(rx.indexIn(list.value(i).trimmed().constData()) == -1)
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
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "email.db");

	if(db.open())
	  {
	    QDateTime now(QDateTime::currentDateTime());
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, from_account, goldbug, hash, "
			  "message, message_code, "
			  "receiver_sender, receiver_sender_hash, "
			  "signature, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, s_crypt->
	       encryptedThenHashed(now.toString(Qt::ISODate).
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
		(4, s_crypt->keyedHash(now.toString(Qt::ISODate).toLatin1() +
				       m + subject,
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
		QByteArray senderPublicKeyHash
		  (spoton_crypt::sha512Hash(from + "-poptastic", &ok));

		query.bindValue
		  (8, senderPublicKeyHash.toBase64());
	      }

	    if(ok)
	      query.bindValue(9, s_crypt->
			      encryptedThenHashed(QByteArray(), &ok).
			      toBase64());

	    if(ok)
	      query.bindValue
		(10, s_crypt->
		 encryptedThenHashed(QByteArray("Unread"), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(11, s_crypt->encryptedThenHashed(subject, &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(12, s_crypt->
		 encryptedThenHashed(QByteArray::number(-1), &ok).
		 toBase64());

	    if(ok)
	      if(query.exec())
		{
		  if(!attachment.isEmpty() && !attachmentName.isEmpty())
		    {
		      QVariant variant(query.lastInsertId());
		      qint64 id = query.lastInsertId().toLongLong();

		      if(variant.isValid())
			{
			  QByteArray data(attachment);

			  if(!data.isEmpty())
			    {
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

void spoton_kernel::saveGemini(const QByteArray &publicKeyHash,
			       const QByteArray &gemini,
			       const QByteArray &geminiHashKey,
			       const QByteArray &timestamp,
			       const QByteArray &signature,
			       const QString &messageType)
{
  /*
  ** Some of the following is similar to logic in
  ** spot-on-neighbor.cc.
  */

  if(!setting("gui/acceptGeminis", true).toBool())
    return;

  QDateTime dateTime
    (QDateTime::fromString(timestamp.constData(), "MMddyyyyhhmmss"));

  if(!dateTime.isValid())
    {
      spoton_misc::logError
	("spoton_kernel::saveGemini(): invalid date-time object.");
      return;
    }

  QDateTime now(QDateTime::currentDateTimeUtc());

  dateTime.setTimeSpec(Qt::UTC);
  now.setTimeSpec(Qt::UTC);

  qint64 secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= static_cast<qint64> (spoton_common::
				      GEMINI_TIME_DELTA_MAXIMUM)))
    {
      spoton_misc::logError
	(QString("spoton_kernel::saveGemini(): "
		 "large time delta (%1).").arg(secsTo));
      return;
    }
  else if(duplicateGeminis(publicKeyHash +
			   gemini +
			   geminiHashKey))
    {
      spoton_misc::logError
	("spoton_kernel::saveGemini(): duplicate keys.");
      return;
    }

  geminisCacheAdd(publicKeyHash + gemini + geminiHashKey);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QPair<QByteArray, QByteArray> geminis;
	QSqlQuery query(db);
	bool ok = true;

	geminis.first = gemini;
	geminis.second = geminiHashKey;
	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ?, "
		      "last_status_update = ?, status = 'online' "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");

	if(geminis.first.isEmpty() || geminis.second.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    spoton_crypt *s_crypt = s_crypts.value("chat", 0);

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
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
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

void spoton_kernel::slotUrlImportTimerExpired(void)
{
  for(int i = 0; i < m_urlImportFutures.size(); i++)
    if(m_urlImportFutures.at(i).isFinished())
      {
	m_urlImportFutures.replace
	  (i, QtConcurrent::run(this, &spoton_kernel::importUrls));
	break;
      }
}

void spoton_kernel::importUrls(void)
{
  {
    QReadLocker locker(&m_urlListMutex);

    if(m_urlList.isEmpty())
      return;
  }

  spoton_crypt *crypt = 0;
  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

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
	query.bindValue(0, s_crypt->keyedHash("download", &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray domain;
	      QByteArray permission;
	      bool ok = true;

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

	      if(m_urlImportFutureInterrupt.fetchAndAddRelaxed(0))
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_urlImportFutureInterrupt.fetchAndAddRelaxed(0))
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
	QByteArray password;
	QString database
	  (setting("gui/postgresql_database", "").
	   toString().trimmed());
	QString host
	  (setting("gui/postgresql_host", "localhost").toString().trimmed());
	QString name
	  (setting("gui/postgresql_name", "").toString().trimmed());
	QString str("connect_timeout=10");
	bool ok = true;
	bool ssltls = setting("gui/postgresql_ssltls", false).toBool();
	int port = setting("gui/postgresql_port", 5432).toInt();

	password = s_crypt->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(setting("gui/postgresql_password", "").
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
	do
	  {
	    if(m_urlImportFutureInterrupt.fetchAndAddRelaxed(0))
	      break;

	    QWriteLocker locker(&m_urlListMutex);

	    if(m_urlList.isEmpty())
	      break;

	    QList<QByteArray> urls(m_urlList.mid(0, 4));

	    for(int i = 0; i < urls.size(); i++)
	      m_urlList.removeAt(0);

	    locker.unlock();

	    QByteArray content(qUncompress(urls.value(3)));
	    QByteArray description(urls.value(2));
	    QByteArray title(urls.value(1));
	    QByteArray url(urls.value(0));
	    bool ok = false;

	    for(int i = 0; i < polarizers.size(); i++)
	      {
		QString type(polarizers.at(i).second);
		QUrl u1(polarizers.at(i).first);
		QUrl u2(QUrl::fromUserInput(url.trimmed()));

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
					crypt))
		{
		  QWriteLocker locker(&m_urlsProcessedMutex);

		  m_urlsProcessed += 1;
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

void spoton_kernel::saveUrls(const QList<QByteArray> &urls)
{
  if(urls.isEmpty())
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

  QByteArray keyType(list.value(4));

  if(!(keyType == "chat" || keyType == "email" || keyType == "poptastic" ||
       keyType == "url"))
    return;

  QByteArray widgetType(list.value(5));
  bool ok = true;
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);
  spoton_crypt *s_crypt2 = s_crypts.value(keyType + "-signature", 0);

  if(!s_crypt1 || !s_crypt2)
    return;

  QByteArray myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(myPublicKey, &ok));

  if(!ok)
    return;

  QByteArray cipherType(setting("gui/fsCipherType",
				"aes256").toString().toLatin1());
  QByteArray hashType(setting("gui/fsHashType", "sha512").
		      toString().toLatin1());
  QByteArray publicKey
    (spoton_misc::publicKeyFromHash(list.value(1), s_crypt1));

  if(publicKey.isEmpty())
    return;

  QByteArray symmetricKey;
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength <= 0)
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
    (keyInformation, publicKey, &ok);

  if(!ok)
    return;

  bool sign = true;

  if(keyType == "chat" && !setting("gui/chatSignMessages", true).toBool())
    sign = false;
  else if(keyType == "email" && !setting("gui/emailSignMessages", true).
	  toBool())
    sign = false;
  else if(keyType == "poptastic")
    {
      if(widgetType == "chat" && !setting("gui/chatSignMessages", true).
	 toBool())
	sign = false;
      else if(widgetType == "email" && !setting("gui/emailSignMessages",
						true).toBool())
	sign = false;

      sign = true; // Mandatory signatures!
    }
  else if(keyType == "url" && !setting("gui/urlSignMessages", true).toBool())
    sign = false;

  QByteArray signature;
  QByteArray utcDate(QDateTime::currentDateTime().toUTC().
		     toString("MMddyyyyhhmmss").toLatin1());

  if(sign)
    {
      signature = s_crypt2->digitalSignature
	("0091a" +
	 symmetricKey +
	 hashKey +
	 cipherType +
	 hashType +
	 myPublicKeyHash +
	 list.value(3) +
	 utcDate, &ok);

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

  QByteArray messageCode
    (crypt.keyedHash(keyInformation + data, &ok));

  if(!ok)
    return;

  data = keyInformation.toBase64() + "\n" + data.toBase64() + "\n" +
    messageCode.toBase64();

  if(keyType == "chat" || keyType == "email" || keyType == "url")
    emit sendForwardSecrecyPublicKey(data);
  else if(keyType == "poptastic")
    {
      QByteArray message
	(spoton_send::message0091a(data, QPair<QByteArray, QByteArray> ()));
      QString name(QString::fromUtf8(list.value(0).constData(),
				     list.value(0).length()));

      postPoptasticMessage(name, message);
    }

  QPair<QByteArray, QByteArray> keys(list.value(2), list.value(3));

  keys.first = s_crypt1->encryptedThenHashed(keys.first, &ok);

  if(ok)
    keys.second = s_crypt1->encryptedThenHashed(keys.second, &ok);

  if(ok)
    {
      QWriteLocker locker(&m_forwardSecrecyKeysMutex);

      m_forwardSecrecyKeys.insert(list.value(1), keys);
    }
}

void spoton_kernel::slotForwardSecrecyResponseReceivedFromUI
(const QByteArrayList &list)
{
  if(list.isEmpty())
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

  QByteArray keyType(list.value(2));

  if(!(keyType == "chat" || keyType == "email" || keyType == "poptastic" ||
       keyType == "url"))
    return;

  bool ok = true;
  spoton_crypt *s_crypt1 = s_crypts.value(keyType, 0);
  spoton_crypt *s_crypt2 = s_crypts.value(keyType + "-signature", 0);

  if(!s_crypt1 || !s_crypt2)
    return;

  QByteArray myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    return;

  QByteArray myPublicKeyHash(spoton_crypt::sha512Hash(myPublicKey, &ok));

  if(!ok)
    return;

  QByteArray cipherType(setting("gui/fsCipherType",
				"aes256").toString().toLatin1());
  QByteArray hashType(setting("gui/fsHashType", "sha512").
		      toString().toLatin1());
  QByteArray publicKey
    (spoton_misc::publicKeyFromHash(list.value(0), s_crypt1));

  if(publicKey.isEmpty())
    return;

  QByteArray symmetricKey;
  size_t symmetricKeyLength = spoton_crypt::cipherKeyLength(cipherType);

  if(symmetricKeyLength <= 0)
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
    (keyInformation, publicKey, &ok);

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

  bundle = spoton_crypt::publicKeyEncrypt
    (bundle, list.value(1), &ok);

  if(!ok)
    return;

  bool sign = true;

  if(keyType == "chat" && !setting("gui/chatSignMessages", true).toBool())
    sign = false;
  else if(keyType == "email" && !setting("gui/emailSignMessages", true).
	  toBool())
    sign = false;
  else if(keyType == "poptastic")
    sign = true; // Mandatory signatures!
  else if(keyType == "url" && !setting("gui/urlSignMessages", true).toBool())
    sign = false;

  QByteArray utcDate(QDateTime::currentDateTime().toUTC().
		     toString("MMddyyyyhhmmss").toLatin1());
  QByteArray signature;

  if(sign)
    {
      signature = s_crypt2->digitalSignature
	("0091b" +
	 symmetricKey +
	 hashKey +
	 cipherType +
	 hashType +
	 myPublicKeyHash +
	 bundle +
	 utcDate,
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

  QByteArray messageCode
    (crypt.keyedHash(keyInformation + data, &ok));

  if(!ok)
    return;

  data = keyInformation.toBase64() + "\n" + data.toBase64() + "\n" +
    messageCode.toBase64();

  if(keyType == "chat" || keyType == "email" || keyType == "url")
    emit sendForwardSecrecySessionKeys(data);
  else if(keyType == "poptastic")
    {
      QByteArray message
	(spoton_send::message0091b(data, QPair<QByteArray, QByteArray> ()));
      QString name
	(spoton_misc::nameFromPublicKeyHash(list.value(0), s_crypt1));

      postPoptasticMessage(name, message);
    }
}

void spoton_kernel::slotSaveForwardSecrecySessionKeys
(const QByteArrayList &list)
{
  if(list.isEmpty())
    return;

  spoton_crypt *s_crypt = s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray bundle(list.value(1));
  QByteArray data;
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);

  QMutableHashIterator<QByteArray, QPair<QByteArray, QByteArray> > it
    (m_forwardSecrecyKeys);

  while(it.hasNext())
    {
      it.next();

      QPair<QByteArray, QByteArray> pair(it.value());
      bool ok = true;

      pair.first = s_crypt->decryptedAfterAuthenticated(pair.first, &ok);

      if(!ok)
	continue;

      pair.second = s_crypt->decryptedAfterAuthenticated(pair.second, &ok);

      if(!ok)
	continue;

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
  bool ok = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

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
