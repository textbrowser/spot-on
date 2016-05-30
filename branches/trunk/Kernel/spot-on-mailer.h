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

#ifndef _spoton_mailer_h_
#define _spoton_mailer_h_

#include <QObject>
#include <QTimer>

#include "Common/spot-on-common.h"

class spoton_crypt;

class spoton_mailer: public QObject
{
  Q_OBJECT

 public:
  spoton_mailer(QObject *parent);
  ~spoton_mailer();
  static QMap<qint64, char> s_oids;
  static void moveSentMailToSentFolder(const QList<qint64> &oids,
				       spoton_crypt *crypt);

 private:
  QList<QList<QByteArray> > m_publicKeyHashesAdaptiveEchoPairs;
  QTimer m_reaperTimer;
  QTimer m_retrieveMailTimer;
  QTimer m_timer;

 private slots:
  void slotReap(void);
  void slotRetrieveMail
    (const QByteArray &data,
     const QByteArray &publicKeyHash,
     const QByteArray &timestamp,
     const QByteArray &signature,
     const QPairByteArrayByteArray &adaptiveEchoPair);
  void slotRetrieveMailTimeout(void);
  void slotTimeout(void);

 signals:
  void sendMail(const QByteArray &goldbug,
		const QByteArray &message,
		const QByteArray &name,
		const QByteArray &publicKey,
		const QByteArray &subject,
		const QByteArray &attachmentData,
		const QByteArray &keyType,
		const QByteArray &receiverName,
		const QByteArray &mode,
		const QByteArray &fromAccount,
		const bool sign,
		const qint64 mailOid);
  void sendMailFromPostOffice
    (const QByteArray &message,
     const QPairByteArrayByteArray &adaptiveEchoPair);
};

#endif
