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

#ifndef _spoton_starbeam_reader_h_
#define _spoton_starbeam_reader_h_

#include <QFuture>
#include <QHash>
#include <QObject>
#include <QSqlDatabase>
#include <QTimer>

class spoton_crypt;

class spoton_starbeam_reader: public QObject
{
  Q_OBJECT

 public:
  spoton_starbeam_reader(const qint64 id, const double readInterval,
			 QObject *parent);
  ~spoton_starbeam_reader();
  void setReadInterval(const double readInterval);

 private:
  QFuture<QPair<QByteArray, qint64> > m_readFuture;
  QList<QByteArray> m_magnets;
  QList<QByteArray> m_missingLinks;
  QListIterator<QByteArray> *m_missingLinksIterator;
  QTimer m_timer;
  bool m_fragmented;
  bool m_read;
  bool m_ultra;
  double m_readInterval;
  int m_neighborIndex;
  qint64 m_acknowledgedPosition;
  qint64 m_expectedReponseWindow;
  qint64 m_id;
  qint64 m_lastResponse;
  qint64 m_position;
  QHash<QString, QByteArray> elementsFromMagnet(const QByteArray &magnet,
						spoton_crypt *crypt);
  QPair<QByteArray, qint64> read(const QString &fileName,
				 const QString &pulseSize,
				 const qint64 position);
  void populateMagnets(const QSqlDatabase &db);
  void pulsate(const QByteArray &buffer,
	       const QString &fileName,
	       const QString &pulseSize,
	       const QString &fileSize,
	       const QByteArray &magnet,
	       const QByteArray &nova,
	       const QByteArray &hash,
	       const QSqlDatabase &db,
	       const qint64 rc,
	       spoton_crypt *crypt);
  void savePositionAndStatus(const QString &status, const QSqlDatabase &db);
  void setAcknowledgedPosition(const qint64 position);

 private slots:
  void slotTimeout(void);
};

#endif
