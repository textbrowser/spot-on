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

#ifndef _spoton_starbeam_writer_h_
#define _spoton_starbeam_writer_h_

#include <QAtomicInt>
#include <QFuture>
#include <QHash>
#include <QQueue>
#include <QReadWriteLock>
#include <QTimer>

#include "Common/spot-on-common.h"

class spoton_starbeam_writer_statistics;

class spoton_starbeam_writer: public QObject
{
  Q_OBJECT

 public:
  spoton_starbeam_writer(QObject *parent);
  ~spoton_starbeam_writer();
  bool append(const QByteArray &data,
	      QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  void processData(const QByteArray &data, const QStringByteArrayHash &magnet);
  void start(void);
  void stop(void);

 private:
  QAtomicInt m_abort;
  QFuture<void> m_future;
  QHash<QString, spoton_starbeam_writer_statistics> m_statistics;
  QList<QByteArray> m_novas;
  QList<QHash<QString, QByteArray> > m_magnets;
  QQueue<QPair<QByteArray, QHash<QString, QByteArray> > > m_queue;
  QReadWriteLock m_keyMutex;
  QReadWriteLock m_queueMutex;
  QReadWriteLock m_statisticsMutex;
  QTimer m_etaTimer;
  QByteArray eta(const QString &fileName);
  void processData(void);

 private slots:
  void slotETATimerTimeout(void);
  void slotReadKeys(void);

 signals:
  void notifyStarBeamReader(const qint64 id, const qint64 position);
  void writeMessage0061(const QByteArray &data);
};

class spoton_starbeam_writer_statistics
{
 public:
  QString m_fileName;
  int m_stalled;
  qint64 m_position;
  qint64 m_previousPosition;
  qint64 m_rate;
  qint64 m_time0;
  qint64 m_totalSize;
};

#endif
