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

#ifndef _spoton_import_published_pages_h_
#define _spoton_import_published_pages_h_

#include <QAtomicInt>
#include <QFuture>
#include <QTimer>

class spoton_crypt;

class spoton_import_published_pages: public QObject
{
  Q_OBJECT

 public:
  spoton_import_published_pages(QObject *parent);
  ~spoton_import_published_pages();
  quint64 imported(void) const;
  void deactivate(void);

 private:
  QAtomicInteger<quint64> m_imported;
  QTimer m_importTimer;
  QVector<QFuture<void > > m_importFutures;
  mutable QAtomicInt m_cancelImport;
  spoton_crypt *urlCommonCrypt(void) const;
  bool allow(const QList<QPair<QUrl, QString> > &list, const QUrl &url) const;
  void import(const QList<QVariant> &values);

 private slots:
  void slotImport(void);
  void slotLogError(const QString &error);

 signals:
  void logError(const QString &error);
};

#endif
