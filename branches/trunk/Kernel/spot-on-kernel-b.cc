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
    return 0;

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
  if(setting("gui/disablePop3", false).toBool())
    return;

  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

  if(!s_crypt)
    return;

  QHash<QString, QVariant> hash;
  bool ok = true;

  hash = spoton_misc::poptasticSettings(s_crypt, &ok);

  if(hash.isEmpty() || !ok)
    return;

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

	  long verify = static_cast<long>
	    (setting("gui/poptasticVerifyPopHost", 0).toInt());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long>
	    (setting("gui/poptasticVerifyPopPeer", 0).toInt());
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

	      if(curl_easy_perform(curl) == CURLE_OK)
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

	      if(curl_easy_perform(curl) != CURLE_OK)
		{
		  curl_easy_setopt
		    (curl, CURLOPT_CUSTOMREQUEST, "EXPUNGE");
		  curl_easy_perform(curl);
		}

	      if(m_poptasticPopFuture.isCanceled())
		break;
	    }
	}

      curl_easy_cleanup(curl);

      if(m_poptasticPopFuture.isCanceled())
	return;
    }

  if(!list.isEmpty())
    goto begin_label;
}

void spoton_kernel::postPoptastic(void)
{
  if(setting("gui/disableSmtp", false).toBool())
    {
      QWriteLocker locker(&m_poptasticCacheMutex);

      m_poptasticCache.clear();
      return;
    }

  spoton_crypt *s_crypt = s_crypts.value("poptastic", 0);

  if(!s_crypt)
    return;

  QHash<QString, QVariant> hash;
  bool ok = true;

  hash = spoton_misc::poptasticSettings(s_crypt, &ok);

  if(hash.isEmpty() || !ok)
    return;

  QReadLocker locker(&m_poptasticCacheMutex);

  if(!m_poptasticCache.isEmpty())
    {
      locker.unlock();

      CURL *curl = curl_easy_init();

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
		url = QString("smtps://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());
	      else
		url = QString("smtp://%1:%2/").
		  arg(hash["out_server_address"].toString().trimmed()).
		  arg(hash["out_server_port"].toString().trimmed());

	      long verify = static_cast<long>
		(setting("gui/poptasticVerifySmtpHost", 0).toInt());

	      if(verify)
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	      else
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	      verify = static_cast<long>
		(setting("gui/poptasticVerifySmtpPeer", 0).toInt());
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
	    url = QString("smtp://%1:%2/").
	      arg(hash["out_server_address"].toString().trimmed()).
	      arg(hash["out_server_port"].toString().trimmed());

	  curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());

	  for(int i = 1; i <= 15; i++)
	    {
	      QList<QVariant> values;
	      QWriteLocker locker(&m_poptasticCacheMutex);

	      if(m_poptasticCache.isEmpty())
		break;
	      else
		values = m_poptasticCache.dequeue();

	      locker.unlock();

	      QByteArray bytes(values.value(1).toByteArray());
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
	      curl_payload_text.append(QString("To: <%1> (%1)\r\n").
				       arg(values.value(0).toString()).
				       toLatin1());
	      curl_payload_text.append(QString("From: <%1>\r\n").arg(from).
				       toLatin1());
	      curl_payload_text.append
		(QString("Message-ID: <%1>\r\n").
		 arg(spoton_crypt::weakRandomBytes(16).toHex().
		     constData()).toLatin1());

	      if(values.size() == 3)
		{
		  curl_payload_text.append
		    (QString("Subject: %1\r\n").
		     arg(spoton_crypt::sha512Hash(from.toLatin1(), &ok).toHex().
			 constData()).toLatin1());
		  curl_payload_text.append("\r\n");
		}
	      else
		{
		  curl_payload_text.append("Subject: ");
		  curl_payload_text.append(values.value(2).toByteArray());
		  curl_payload_text.append("\r\n");
		}

	      QByteArray attachment(values.value(3).toByteArray());
	      QByteArray attachmentName(values.value(4).toByteArray());

	      if(attachment.isEmpty() || attachmentName.isEmpty() ||
		 values.size() == 3)
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
		     arg(values.value(1).toByteArray().constData()).
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
	      recipients = curl_slist_append
		(recipients, values.value(0).toByteArray().constData());
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

	      if(curl_easy_perform(curl) == CURLE_OK)
		{
		  qint64 mailOid = -1;

		  if(!values.isEmpty())
		    mailOid = values.value(values.size() - 1).toLongLong();

		  if(mailOid > -1)
		    spoton_misc::moveSentMailToSentFolder
		      (QList<qint64> () << mailOid, s_crypt);
		}

	      curl_slist_free_all(recipients);

	      if(m_poptasticPostFuture.isCanceled())
		break;
	    }

	  curl_easy_cleanup(curl);
	}
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
  else if(data.length() > spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE)
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
		     QHostAddress("127.0.0.1"), 0,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	{
	  spoton_misc::saveParticipantStatus
	    (list.value(1),                   // Name
	     list.value(0),                   // Public Key Hash
	     QByteArray(),                    // Status
	     QDateTime::currentDateTime().toUTC().
	     toString("MMddyyyyhhmmss").
	     toLatin1(),                      // Timestamp
	     2.5 * POPTASTIC_STATUS_INTERVAL, // Seconds
	     s_crypts.value("poptastic", 0));
	  emit receivedChatMessage
	    ("message_" +
	     list.value(0).toBase64() + "_" +
	     list.value(1).toBase64() + "_" +
	     list.value(2).toBase64() + "_" +
	     list.value(3).toBase64() + "_" +
	     list.value(4).toBase64() + "_" +
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
		      QHostAddress("127.0.0.1"), 0,
		      messageType,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(0), list.value(1),
		   list.value(2), list.value(3),
		   "0000a");
    }
  else if(messageType == "0000b")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0000b(data.length(), data, symmetricKeys,
		      setting("gui/chatAcceptSignedMessagesOnly", true).
		      toBool(),
		      QHostAddress("127.0.0.1"), 0,
		      s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	saveGemini(list.value(1), list.value(2),
		   list.value(3), list.value(4),
		   "0000b");
    }
  else if(messageType == "0001b")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0001b(data.length(), data,
		      QHostAddress("127.0.0.1"), 0,
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

	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "email.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("INSERT INTO folders "
			      "(date, folder_index, goldbug, hash, "
			      "message, message_code, "
			      "receiver_sender, receiver_sender_hash, "
			      "status, subject, participant_oid) "
			      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
		query.bindValue
		  (0, s_crypt->
		   encryptedThenHashed(QDateTime::currentDateTime().
				       toString(Qt::ISODate).
				       toLatin1(), &ok).toBase64());
		query.bindValue(1, 0); // Inbox Folder

		if(ok)
		  query.bindValue
		    (2, s_crypt->
		     encryptedThenHashed(QByteArray::number(goldbugUsed), &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (3, s_crypt->keyedHash(message + subject,
					   &ok).toBase64());

		if(ok)
		  if(!message.isEmpty())
		    query.bindValue
		      (4, s_crypt->encryptedThenHashed(message,
						       &ok).toBase64());

		if(ok)
		  query.bindValue
		    (5, s_crypt->encryptedThenHashed(QByteArray(), &ok).
		     toBase64());

		if(ok)
		  if(!name.isEmpty())
		    query.bindValue
		      (6, s_crypt->encryptedThenHashed(name,
						       &ok).toBase64());

		if(ok)
		  query.bindValue
		    (7, senderPublicKeyHash.toBase64());

		if(ok)
		  query.bindValue
		    (8, s_crypt->
		     encryptedThenHashed(QByteArray("Unread"), &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (9, s_crypt->encryptedThenHashed(subject, &ok).
		     toBase64());

		if(ok)
		  query.bindValue
		    (10, s_crypt->
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
			      QByteArray data;

			      if(!goldbugUsed)
				data = qUncompress(attachment);
			      else
				data = attachment;

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
  else if(messageType == "0013")
    {
      QList<QByteArray> list
	(spoton_receive::
	 process0013(data.length(), data, symmetricKeys,
		     setting("gui/chatAcceptSignedMessagesOnly", true).
		     toBool(),
		     QHostAddress("127.0.0.1"), 0,
		     s_crypts.value("poptastic", 0)));

      if(!list.isEmpty())
	spoton_misc::saveParticipantStatus
	  (list.value(1),                   // Name
	   list.value(0),                   // Public Key Hash
	   list.value(2),                   // Status
	   list.value(3),                   // Timestamp
	   2.5 * POPTASTIC_STATUS_INTERVAL, // Seconds
	   s_crypts.value("poptastic"));
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
      QByteArray hash;
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

		bool ok = true;

		hash = spoton_crypt::sha512Hash(from, &ok).toHex();
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

      if(hash == subject)
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
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, goldbug, hash, "
			  "message, message_code, "
			  "receiver_sender, receiver_sender_hash, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, s_crypt->
	       encryptedThenHashed(QDateTime::currentDateTime().
				   toString(Qt::ISODate).
				   toLatin1(), &ok).toBase64());
	    query.bindValue(1, 0); // Inbox Folder

	    if(ok)
	      query.bindValue
		(2, s_crypt->
		 encryptedThenHashed(QByteArray::number(0), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(3, s_crypt->keyedHash(m + subject,
				       &ok).toBase64());

	    if(ok)
	      if(!m.isEmpty())
		query.bindValue
		  (4, s_crypt->encryptedThenHashed(m,
						   &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, s_crypt->encryptedThenHashed(QByteArray(), &ok).
		 toBase64());

	    if(ok)
	      if(!from.isEmpty())
		query.bindValue
		  (6, s_crypt->encryptedThenHashed(from,
						   &ok).toBase64());

	    if(ok)
	      {
		QByteArray senderPublicKeyHash
		  (spoton_crypt::sha512Hash(from + "-poptastic", &ok));

		if(ok)
		  query.bindValue
		    (7, senderPublicKeyHash.toBase64());
	      }

	    if(ok)
	      query.bindValue
		(8, s_crypt->
		 encryptedThenHashed(QByteArray("Unread"), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(9, s_crypt->encryptedThenHashed(subject, &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(10, s_crypt->
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

  int secsTo = qAbs(now.secsTo(dateTime));

  if(!(secsTo <= GEMINI_TIME_DELTA_MAXIMUM))
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
	      if(geminis.first.isEmpty() ||
		 geminis.second.isEmpty())
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 terminated the call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	      else if(messageType == "0000a")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call.").
		   arg(publicKeyHash.toBase64().mid(0, 16).constData()).
		   arg(publicKeyHash.toBase64().right(16).constData()));
	      else if(messageType == "0000b")
		emit statusMessageReceived
		  (publicKeyHash,
		   tr("The participant %1...%2 initiated a call "
		      "within a call.").
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
  if(m_urlImportFuture.isFinished())
    m_urlImportFuture = QtConcurrent::run(this, &spoton_kernel::importUrls);
}

void spoton_kernel::importUrls(void)
{
  spoton_crypt *crypt = 0;
  spoton_crypt *s_crypt = s_crypts.value("url", 0);

  crypt = spoton_misc::retrieveUrlCommonCredentials(s_crypt);

  if(!crypt || !s_crypt)
    {
      delete crypt;
      spoton_misc::deleteSharedUrls
	(spoton_misc::homePath() + QDir::separator() + "shared-kernel.db");
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

	query.setForwardOnly(true);
	query.prepare("SELECT domain, type FROM distillers WHERE "
		      "LOWER(TRIM(direction)) = 'upload'");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray domain;
	      bool ok = true;

	      domain = s_crypt->
		decryptedAfterAuthenticated(QByteArray::
					    fromBase64(query.
						       value(0).
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
			pair.second =
			  query.value(1).toString().toLower().trimmed();
			polarizers.append(pair);
		      }
		}

	      if(m_urlImportFuture.isCanceled())
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_urlImportFuture.isCanceled())
    {
      delete crypt;
      return;
    }

  {
    QSqlDatabase db;

    connectionName = spoton_misc::databaseName();

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
	db.setHostName(host);
	db.setDatabaseName(database);
	db.setPort(port);

	if(ok)
	  db.open(name, password);
      }

    if(db.isOpen())
      {
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete crypt;
}
