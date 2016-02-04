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

#include <QFuture>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTimer>

#include "ui_spot-on-rss.h"

class spoton_crypt;

class spoton_rss: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_rss(QWidget *parent);
  ~spoton_rss();
  void center(QWidget *parent);
  void deactivate(void);
  void prepareAfterAuthentication(void);
  void show(void);

 private:
  QByteArray m_feedDownloadContent;
  QFuture<void> m_parseXmlFuture;
  QNetworkAccessManager m_networkAccessManager;
  QPalette m_originalFindPalette;
  QString removeSpecialTags(const QString &text);
  QTimer m_downloadTimer;
  QTimer m_downloadContentTimer;
  QTimer m_importTimer;
  QTimer m_statisticsTimer;
  Ui_rss m_ui;
  int m_currentFeedRow;
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
  bool event(QEvent *event);
#endif
#endif
  bool importUrl(const QList<QVariant> &list,
		 const bool batch);
  spoton_crypt *urlCommonCrypt(void) const;
  void closeEvent(QCloseEvent *event);
  void hideUrl(const QUrl &url, const bool state);
  void logError(const QString &error);
  void parseXmlContent(const QByteArray &data,
		       const QUrl &url);
  void populateFeeds(void);
  void prepareDatabases(void);
  void saveFeedData(const QString &description,
		    const QString &link,
		    const QString &title);
  void saveFeedImage(const QByteArray &data, const QString &link);
  void saveFeedLink(const QString &description,
		    const QString &link,
		    const QString &publicationDate,
		    const QString &title,
		    const QUrl &url);

 private slots:
  void slotAddFeed(void);
  void slotActivate(bool state);
  void slotActivateImport(bool state);
  void slotContentReplyFinished(void);
  void slotCopyFeedLink(void);
  void slotDeleteAllFeeds(void);
  void slotDeleteFeed(void);
  void slotDownloadContent(void);
  void slotDownloadFeedImage(const QUrl &imageUrl, const QUrl &url);
  void slotDownloadIntervalChanged(double value);
  void slotDownloadTimeout(void);
  void slotFeedImageReplyFinished(void);
  void slotFeedReplyFinished(void);
  void slotFeedReplyReadyRead(void);
  void slotFind(void);
  void slotFindInitialize(void);
  void slotImport(void);
  void slotMaximumKeywordsChanged(int value);
  void slotPopulateFeeds(void);
  void slotProxyClicked(bool state);
  void slotPurge(void);
  void slotPurgeDaysChanged(int value);
  void slotRefreshTimeline(void);
  void slotReplyError(QNetworkReply::NetworkError code);
  void slotSaveProxy(void);
  void slotScheduleFeedUpdate(void);
  void slotShowContextMenu(const QPoint &point);
  void slotStatisticsTimeout(void);
  void slotTabChanged(int index);
  void slotTimeOrderBy(bool state);
  void slotTimelineShowOption(bool state);
  void slotToggleState(void);
  void slotUrlClicked(const QUrl &url);

 signals:
  void downloadFeedImage(const QUrl &imageUrl, const QUrl &url);
};

#endif
