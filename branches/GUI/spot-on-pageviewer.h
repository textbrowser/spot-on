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

#ifndef _spoton_pageviewer_h_
#define _spoton_pageviewer_h_

#include <QMainWindow>
#include <QPointer>
#include <QSqlDatabase>
#ifdef SPOTON_WEBENGINE_ENABLED
#include <QWebEngineView>
#elif defined(SPOTON_WEBKIT_ENABLED)
#include <QWebView>
#endif

#if !defined(SPOTON_WEBENGINE_ENABLED) && !defined(SPOTON_WEBKIT_ENABLED)
#include "spot-on-textbrowser.h"
#endif
#include "ui_spot-on-pageviewer.h"

class QPrinter;
class spoton;
class spoton_crypt;

#ifdef SPOTON_WEBENGINE_ENABLED
class spoton_webengine_page: public QWebEnginePage
{
  Q_OBJECT

 public:
  spoton_webengine_page(QObject *parent):QWebEnginePage(parent)
  {
  }

  ~spoton_webengine_page()
  {
  }

 private:
  bool acceptNavigationRequest(const QUrl &url,
			       NavigationType type,
			       bool isMainFrame)
  {
    Q_UNUSED(isMainFrame);
    Q_UNUSED(type);
    Q_UNUSED(url);
    return true;
  }
};
#endif

class spoton_pageviewer: public QMainWindow
{
  Q_OBJECT

 public:
  spoton_pageviewer(QSqlDatabase *db,
		    const QString &urlHash,
		    spoton *parent);
  ~spoton_pageviewer();
  void setPage(const QByteArray &data,
	       const QUrl &url,
	       const int compressedSize);

 private:
  QByteArray m_content;
  QPalette m_originalFindPalette;
  QPointer<spoton> m_parent;
  QSqlDatabase *m_database;
  QString m_hoveredLink;
  QString m_urlHash;
#ifdef SPOTON_WEBENGINE_ENABLED
  QWebEngineView *m_webView;
#elif defined(SPOTON_WEBKIT_ENABLED)
  QWebView *m_webView;
#endif
  Ui_spoton_pageviewer m_ui;
#if !defined(SPOTON_WEBENGINE_ENABLED) && !defined(SPOTON_WEBKIT_ENABLED)
  spoton_textbrowser *m_webView;
#endif

 private slots:
  void slotCopyLinkLocation(void);
  void slotCustomContextMenuRequested(const QPoint &point);
  void slotFind(void);
  void slotFindInitialize(void);
  void slotLinkHovered(const QString &url);
  void slotLoadFinished(bool ok);
  void slotPagePrintPreview(void);
  void slotPrint(QPrinter *printer);
  void slotRevisionChanged(int index);
};

#endif
