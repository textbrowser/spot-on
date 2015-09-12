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

#include <QDateTime>
#include <QString>

#include "Common/spot-on-crypt.h"
#include "spot-on-crypt.h"
#include "spot-on-send.h"

QByteArray spoton_send::EOM = "\r\n\r\n\r\n";

QByteArray spoton_send::adaptiveEchoAuthentication
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated;
  bool ok = true;

  if(!adaptiveEchoPair.first.isEmpty() && !adaptiveEchoPair.second.isEmpty())
    {
      QByteArray timestamp
	(QDateTime::currentDateTime().toUTC().toString("MMddyyyyhhmmss").
	 toLatin1());
      int length = static_cast<int>
	(spoton_crypt::cipherKeyLength("aes256"));
      spoton_crypt crypt(adaptiveEchoPair.second.split('\n').value(0),
			 adaptiveEchoPair.second.split('\n').value(1),
			 QByteArray(),
			 adaptiveEchoPair.first.mid(0, length),
			 adaptiveEchoPair.first.mid(length),
			 0,
			 0,
			 "");

      timestamp = crypt.encrypted(timestamp, &ok);

      if(ok)
	authenticated = crypt.keyedHash(message + timestamp, &ok) +
	  timestamp;
    }
  else
    ok = false;

  if(ok)
    authenticated = message + "\n" + authenticated.toBase64();
  else
    authenticated = message + "\n" +
      spoton_crypt::weakRandomBytes(100).toBase64(); /*
						     ** 64 (hash) +
						     ** 14 (timestamp) +
						     ** 2  (block size minimum)
						     ** 4  (length) +
						     ** 16 (init. vector)
						     */

  return authenticated;
}

QByteArray spoton_send::message0000(const QByteArray &message)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, QPair<QByteArray, QByteArray> ()));
  QByteArray results("content=");

  results.append(authenticated);
  return results;
}

QByteArray spoton_send::message0000
(const QByteArray &message,
 const spoton_send_method sendMethod,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0000a(const QByteArray &message)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, QPair<QByteArray, QByteArray> ()));
  QByteArray results("content=");

  results.append(authenticated);
  return results;
}

QByteArray spoton_send::message0000a
(const QByteArray &message,
 const spoton_send_method sendMethod,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0000b(const QByteArray &message)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, QPair<QByteArray, QByteArray> ()));
  QByteArray results("content=");

  results.append(authenticated);
  return results;
}

QByteArray spoton_send::message0000b
(const QByteArray &message,
 const spoton_send_method sendMethod,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0001a
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0001b(const QByteArray &message)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, QPair<QByteArray, QByteArray> ()));
  QByteArray results("content=");

  results.append(authenticated);
  return results;
}

QByteArray spoton_send::message0001b
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0002a
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0002b
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0011(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const QByteArray &sPublicKey,
				    const QByteArray &sSignature)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0011&content=%2\r\n"
     "\r\n\r\n");
  content.append(keyType.toBase64());
  content.append("\n");
  content.append(name.toBase64());
  content.append("\n");
  content.append(publicKey.toBase64());
  content.append("\n");
  content.append(signature.toBase64());
  content.append("\n");
  content.append(sPublicKey.toBase64());
  content.append("\n");
  content.append(sSignature.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.length() +
			QString("type=0011&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content);
  return results;
}

QByteArray spoton_send::message0012(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0012&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.length() +
			QString("type=0012&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message);
  return results;
}

QByteArray spoton_send::message0013(const QByteArray &message)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, QPair<QByteArray, QByteArray> ()));
  QByteArray results("content=");

  results.append(authenticated);
  return results;
}

QByteArray spoton_send::message0013
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0014(const QByteArray &uuid)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0014&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(uuid.toBase64().length() +
			QString("type=0014&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", uuid.toBase64());
  return results;
}

QByteArray spoton_send::message0030(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0030&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.length() +
			QString("type=0030&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message);
  return results;
}

QByteArray spoton_send::message0030(const QHostAddress &address,
				    const quint16 port,
				    const QString &transport,
				    const QString &orientation)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0030&content=%2\r\n"
     "\r\n\r\n");
  content.append(address.toString().toLatin1().toBase64());
  content.append("\n");
  content.append(QByteArray::number(port).toBase64());
  content.append("\n");
  content.append(address.scopeId().toLatin1().toBase64());
  content.append("\n");
  content.append(transport.toLatin1().toBase64());
  content.append("\n");
  content.append(orientation.toLatin1().toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.length() +
			QString("type=0030&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content);
  return results;
}

QByteArray spoton_send::message0040a(const QByteArray &message)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", message);
  return results;
}

QByteArray spoton_send::message0040b(const QByteArray &message,
				     const spoton_send_method sendMethod)
{
  QByteArray results;

  if(sendMethod == ARTIFICIAL_GET)
    results.append("HTTP/1.1 200 OK\r\n");
  else
    results.append("POST HTTP/1.1\r\n");

  results.append
    ("Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(message.length() +
			QString("content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", message);
  return results;
}

QByteArray spoton_send::message0050(const QByteArray &hash,
				    const QByteArray &salt)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0050&content=%2\r\n"
     "\r\n\r\n");
  content.append(hash.toBase64());
  content.append("\n");
  content.append(salt.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.length() +
			QString("type=0050&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content);
  return results;
}

QByteArray spoton_send::message0051(const QByteArray &hash,
				    const QByteArray &salt)
{
  QByteArray content;
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0051&content=%2\r\n"
     "\r\n\r\n");
  content.append(hash.toBase64());
  content.append("\n");
  content.append(salt.toBase64());
  results.replace
    ("%1",
     QByteArray::number(content.length() +
			QString("type=0051&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", content);
  return results;
}

QByteArray spoton_send::message0052(void)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0052&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(QByteArray("0").toBase64().length() +
			QString("type=0052&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", QByteArray("0").toBase64());
  return results;
}

QByteArray spoton_send::message0060
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0065(const QByteArray &magnet)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0065&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(magnet.toBase64().length() +
			QString("type=0065&content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", magnet.toBase64());
  return results;
}

QByteArray spoton_send::message0070(const QByteArray &motd)
{
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "type=0070&content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(motd.toBase64().length() +
			QString("type=0070&content=\r\n\r\n\r\n").length()));
  results.replace
    ("%2", motd.toBase64());
  return results;
}

QByteArray spoton_send::message0080
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0090
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}

QByteArray spoton_send::message0091a
(const QByteArray &message,
 const QPair<QByteArray, QByteArray> &adaptiveEchoPair)
{
  QByteArray authenticated
    (adaptiveEchoAuthentication(message, adaptiveEchoPair));
  QByteArray results;

  results.append
    ("POST HTTP/1.1\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: %1\r\n"
     "\r\n"
     "content=%2\r\n"
     "\r\n\r\n");
  results.replace
    ("%1",
     QByteArray::number(authenticated.length() +
			QString("content=\r\n\r\n\r\n").
			length()));
  results.replace
    ("%2", authenticated);
  return results;
}
