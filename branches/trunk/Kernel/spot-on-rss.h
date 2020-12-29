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

#ifndef _spoton_rss_h_
#define _spoton_rss_h_

#include <QAtomicInt>
#include <QFuture>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>

class spoton_crypt;

class spoton_rss: public QObject
{
  Q_OBJECT

 public:
  spoton_rss(QObject *parent);
  ~spoton_rss();
  void deactivate(void);

 private:
  QAtomicInt m_cancelImport;
  QByteArray m_feedDownloadContent;
  QFuture<void> m_parseXmlFuture;
  QNetworkAccessManager m_contentNetworkAccessManager;
  QNetworkAccessManager m_feedNetworkAccessManager;
  QPair<QByteArray, qint64> m_lastUniqueId;
  QTimer m_downloadContentTimer;
  QTimer m_downloadTimer;
  QTimer m_importTimer;
  QTimer m_populateTimer;
  QVector<QFuture<void > > m_importFutures;
  bool importUrl(const QList<QVariant> &list, const int maximumKeywords);
  spoton_crypt *urlCommonCrypt(void) const;
  void import(const int maximumKeywords);
  void parseXmlContent(const QByteArray &data, const QUrl &url);
  void populateFeeds(void);
  void prepareDatabases(void);
  void saveFeedData(const QString &description,
		    const QString &link,
		    const QString &title);
  void saveFeedLink(const QString &description,
		    const QString &link,
		    const QString &publicationDate,
		    const QString &title,
		    const QUrl &url);

 private slots:
  void slotContentReplyFinished(void);
  void slotDownloadContent(void);
  void slotDownloadTimeout(void);
  void slotFeedReplyFinished(void);
  void slotFeedReplyReadyRead(void);
  void slotImport(void);
  void slotLogError(const QString &error);
  void slotPopulateFeeds(void);
  void slotReplyError(QNetworkReply::NetworkError code);

 signals:
  void logError(const QString &error);
};

#endif
