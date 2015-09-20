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

#ifndef _spoton_receive_h_
#define _spoton_receive_h_

#include <QByteArray>
#include <QList>

class spoton_crypt;

class spoton_receive
{
 public:
  static QList<QByteArray> process0000(int length, const QByteArray &dataIn,
				       const QList<QByteArray> &symmetricKeys,
				       const bool acceptSignedMessagesOnly,
				       const QHostAddress &address,
				       const quint16 port,
				       spoton_crypt *s_crypt);
  static QList<QByteArray> process0000a(int length, const QByteArray &dataIn,
					const bool acceptSignedMessagesOnly,
					const QHostAddress &address,
					const quint16 port,
					const QString &messageType,
					spoton_crypt *s_crypt);
  static QList<QByteArray> process0000b
    (int length, const QByteArray &dataIn,
     const QList<QByteArray> &symmetricKeys,
     const bool acceptSignedMessagesOnly,
     const QHostAddress &address,
     const quint16 port,
     spoton_crypt *s_crypt);
  static QList<QByteArray> process0001b
    (int length, const QByteArray &dataIn,
     const QHostAddress &address,
     const quint16 port,
     spoton_crypt *s_crypt);
  static QList<QByteArray> process0001c
    (int length, const QByteArray &dataIn,
     const QList<QByteArray> &symmetricKeys,
     const QHostAddress &address,
     const quint16 port,
     const QString &keyType,
     spoton_crypt *s_crypt);
  static QList<QByteArray> process0013
    (int length, const QByteArray &dataIn,
     const QList<QByteArray> &symmetricKeys,
     const bool acceptSignedMessagesOnly,
     const QHostAddress &address,
     const quint16 port,
     spoton_crypt *s_crypt);
  static QList<QByteArray> process0091
    (int length, const QByteArray &dataIn,
     const QList<QByteArray> &symmetricKeys,
     const QHostAddress &address,
     const quint16 port,
     const QString &messageType);
  static QString findMessageType
    (const QByteArray &data,
     QList<QByteArray> &symmetricKeys,
     const int interfaces,
     const QString &keyType,
     spoton_crypt *s_crypt);

 private:
  spoton_receive(void);
};

#endif
