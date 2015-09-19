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

#ifndef _spoton_send_h_
#define _spoton_send_h_

#include <QByteArray>
#include <QHostAddress>

class spoton_send
{
 public:
  enum spoton_send_method
  {
    ARTIFICIAL_GET = 0,
    NORMAL_POST
  };

  static QByteArray EOM;
  static QByteArray message0000(const QByteArray &message);
  static QByteArray message0000
    (const QByteArray &message,
     const spoton_send_method sendMethod,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0000a(const QByteArray &message);
  static QByteArray message0000a
    (const QByteArray &message,
     const spoton_send_method sendMethod,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0000b(const QByteArray &message);
  static QByteArray message0000b
    (const QByteArray &message,
     const spoton_send_method sendMethod,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0001a
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0001b(const QByteArray &message);
  static QByteArray message0001b
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0001c(const QByteArray &message);
  static QByteArray message0001c
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0002a
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0002b
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0011(const QByteArray &keyType,
				const QByteArray &name,
				const QByteArray &publicKey,
				const QByteArray &signature,
				const QByteArray &sPublicKey,
				const QByteArray &sSignature);
  static QByteArray message0012(const QByteArray &message);
  static QByteArray message0013(const QByteArray &message);
  static QByteArray message0013
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0014(const QByteArray &uuid);
  static QByteArray message0030(const QByteArray &message);
  static QByteArray message0030(const QHostAddress &address,
				const quint16 port,
				const QString &transport,
				const QString &orientation);
  static QByteArray message0040a(const QByteArray &message);
  static QByteArray message0040b(const QByteArray &message,
				 const spoton_send_method sendMethod);
  static QByteArray message0050(const QByteArray &hash,
				const QByteArray &salt);
  static QByteArray message0051(const QByteArray &hash,
				const QByteArray &salt);
  static QByteArray message0052(void);
  static QByteArray message0060
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0065(const QByteArray &magnet);
  static QByteArray message0070(const QByteArray &motd);
  static QByteArray message0080
    (const QByteArray &data,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0090
    (const QByteArray &data,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0091a
    (const QByteArray &data,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static QByteArray message0091b
    (const QByteArray &data,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);

 private:
  spoton_send(void);
  static QByteArray adaptiveEchoAuthentication
    (const QByteArray &message,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
};

#endif
