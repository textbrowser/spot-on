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

#include <QPrintPreviewDialog>
#include <QPrinter>
#include <QSqlQuery>
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
#include <QWebEngineProfile>
#elif defined(SPOTON_WEBKIT_ENABLED)
#include <QWebHitTestResult>
#endif

#include "../Common/spot-on-crypt.h"
#include "spot-on-defines.h"
#include "spot-on-pageviewer.h"
#include "spot-on-textbrowser.h"
#include "spot-on.h"

spoton_pageviewer::spoton_pageviewer(QSqlDatabase *db,
				     const QString &urlHash,
				     spoton *parent):QMainWindow(parent)
{
  m_database = db;
  m_parent = parent;
  m_ui.setupUi(this);
  m_urlHash = urlHash;
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  m_webView = new QWebEngineView(this);
  m_webView->setContextMenuPolicy(Qt::CustomContextMenu);
  m_webView->setPage(new spoton_webengine_page(this));
  connect(m_webView,
	  SIGNAL(loadFinished(bool)),
	  this,
	  SLOT(slotLoadFinished(bool)));
  connect(m_webView->page(),
	  SIGNAL(linkHovered(const QString &)),
	  this,
	  SLOT(slotLinkHovered(const QString &)));
#elif defined(SPOTON_WEBKIT_ENABLED)
  m_webView = new QWebView(this);
  m_webView->page()->networkAccessManager()->
    setNetworkAccessible(QNetworkAccessManager::NotAccessible);
  m_webView->page()->setLinkDelegationPolicy(QWebPage::DelegateAllLinks);
  m_webView->setContextMenuPolicy(Qt::CustomContextMenu);
  m_webView->setRenderHints(QPainter::Antialiasing |
			    QPainter::HighQualityAntialiasing |
			    QPainter::SmoothPixmapTransform |
			    QPainter::TextAntialiasing);
#else
  m_webView = new spoton_textbrowser(this);
  m_webView->setOpenExternalLinks(false);
  m_webView->setOpenLinks(false);
#endif
  m_ui.frame->layout()->addWidget(m_webView);
  connect(m_ui.action_Find,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotFindInitialize(void)));
  connect(m_ui.action_Print_Preview,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotPagePrintPreview(void)));
  connect(m_ui.find,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotFind(void)));
  connect(m_ui.find,
	  SIGNAL(textChanged(const QString &)),
	  this,
	  SLOT(slotFind(void)));
#if defined(SPOTON_WEBENGINE_ENABLED) || defined(SPOTON_WEBKIT_ENABLED)
  connect(m_webView,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotCustomContextMenuRequested(const QPoint &)));
#endif
  m_originalFindPalette = m_ui.find->palette();
  m_ui.find->setPlaceholderText(tr("Find Text"));
  m_ui.revision->setEnabled(false);
  setAttribute(Qt::WA_DeleteOnClose);
  setWindowTitle(tr("%1: Page Viewer").arg(SPOTON_APPLICATION_NAME));
}

spoton_pageviewer::~spoton_pageviewer()
{
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  QWebEngineProfile::defaultProfile()->clearAllVisitedLinks();
#elif defined(SPOTON_WEBKIT_ENABLED)
  QWebSettings::clearMemoryCaches();
#endif
}

void spoton_pageviewer::setPage(const QByteArray &data, const QUrl &url,
				const int compressedSize)
{
  disconnect(m_ui.revision,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotRevisionChanged(int)));
  m_ui.revision->clear();

  if(m_database && m_database->isOpen())
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QSqlQuery query(*m_database);

      query.setForwardOnly(true);
      query.prepare
	(QString("SELECT content_hash, date_time_inserted "
		 "FROM spot_on_urls_revisions_%1 WHERE url_hash = ? "
		 "ORDER BY 2 DESC").
	 arg(m_urlHash.mid(0, 2)));
      query.bindValue(0, m_urlHash);

      if(query.exec())
	while(query.next())
	  m_ui.revision->addItem(query.value(1).toString(),
				 query.value(0).toByteArray());

      QApplication::restoreOverrideCursor();
    }

  if(m_ui.revision->count() > 0)
    {
      m_ui.revision->insertItem(0, tr("Current"));
      m_ui.revision->insertSeparator(1);
      m_ui.revision->setCurrentIndex(0);
      connect(m_ui.revision,
	      SIGNAL(activated(int)),
	      this,
	      SLOT(slotRevisionChanged(int)));
      m_ui.revision->setEnabled(true);
    }
  else
    {
      m_ui.revision->addItem(tr("Current"));
      m_ui.revision->setEnabled(false);
    }

  /*
  ** Fuzzy Wuzzy was a bear,
  ** Fuzzy Wuzzy had no hair,
  ** Fuzzy Wuzzy wasn't fuzzy,
  ** was he?
  */

  QLocale locale;

  m_ui.size->setText
    (tr("%1 KiB, Compressed %2 KiB").
     arg(locale.toString(data.length() / 1024)).
     arg(locale.toString(compressedSize / 1024)));

  if(data.trimmed().isEmpty())
    {
      m_content = "Malformed content. Enjoy!";
      m_webView->setContent(m_content);
    }
  else
    {
      m_content = data;

      /*
      ** setContent() will not display
      ** some characters. setHtml() may
      ** produce network activity.
      */

      m_webView->setHtml(m_content);
    }

  m_webView->setFocus();
  m_ui.url->setText(url.toString());
}

void spoton_pageviewer::slotCopyLinkLocation(void)
{
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    {
      clipboard->setText(m_hoveredLink);
      m_hoveredLink.clear();
    }
#elif defined(SPOTON_WEBKIT_ENABLED)
  m_webView->triggerPageAction(QWebPage::CopyLinkToClipboard);
#else
  m_webView->copy();
#endif
}

void spoton_pageviewer::slotCustomContextMenuRequested(const QPoint &point)
{
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  if(m_hoveredLink.isEmpty())
    return;

  QMenu menu(this);

  menu.addAction(tr("Copy &Last Hovered Link"),
		 this,
		 SLOT(slotCopyLinkLocation(void)));
  menu.exec(m_webView->mapToGlobal(point));
#elif defined(SPOTON_WEBKIT_ENABLED)
  QWebHitTestResult result = m_webView->page()->currentFrame()->
    hitTestContent(point);

  if(!result.linkUrl().isEmpty())
    {
      QMenu menu(this);

      menu.addAction(tr("Copy &Link Location"),
		     this,
		     SLOT(slotCopyLinkLocation(void)));
      menu.exec(m_webView->mapToGlobal(point));
    }
#else
  Q_UNUSED(point);
#endif
}

void spoton_pageviewer::slotFind(void)
{
  QString text(m_ui.find->text());

#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  m_webView->findText(text);
#elif defined(SPOTON_WEBKIT_ENABLED)
  if(!m_webView->findText(text, QWebPage::FindWrapsAroundDocument))
    {
      if(!text.isEmpty())
	{
	  QColor color(240, 128, 128); // Light Coral
	  QPalette palette(m_ui.find->palette());

	  palette.setColor(m_ui.find->backgroundRole(), color);
	  m_ui.find->setPalette(palette);
	}
      else
	m_ui.find->setPalette(m_originalFindPalette);
    }
  else
    m_ui.find->setPalette(m_originalFindPalette);
#else
  if(!m_webView->find(text))
    m_webView->moveCursor(QTextCursor::Start);
#endif
}

void spoton_pageviewer::slotFindInitialize(void)
{
  m_ui.find->selectAll();
  m_ui.find->setFocus();
}

void spoton_pageviewer::slotLinkHovered(const QString &url)
{
  m_hoveredLink = url;
}

void spoton_pageviewer::slotLoadFinished(bool ok)
{
  Q_UNUSED(ok);
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  /*
  ** WebEngine may attempt to load an external page regardless
  ** of all of the restrictions.
  */

  m_webView->back();
#endif
}

void spoton_pageviewer::slotPagePrintPreview(void)
{
  QPrinter printer(QPrinter::HighResolution);
  QPrintPreviewDialog printDialog(&printer, this);

  printDialog.setWindowModality(Qt::WindowModal);
  connect(&printDialog,
	  SIGNAL(paintRequested(QPrinter *)),
	  this,
	  SLOT(slotPrint(QPrinter *)));
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  printDialog.show();
  QApplication::restoreOverrideCursor();

  if(printDialog.exec() == QDialog::Accepted)
    {
#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
#elif defined(SPOTON_WEBKIT_ENABLED)
      m_webView->print(&printer);
#else
      m_webView->print(&printer);
#endif
    }
}

void spoton_pageviewer::slotPrint(QPrinter *printer)
{
  if(!printer)
    return;

#if QT_VERSION >= 0x050000 && defined(SPOTON_WEBENGINE_ENABLED)
  spoton_textbrowser textbrowser(this);

  textbrowser.setHtml(m_content);
  textbrowser.print(printer);
#elif defined(SPOTON_WEBKIT_ENABLED)
  m_webView->print(printer);
#else
  m_webView->print(printer);
#endif
}

void spoton_pageviewer::slotRevisionChanged(int index)
{
  spoton_crypt *crypt = m_parent ? m_parent->urlCommonCrypt() : 0;

  if(!crypt || !m_database || !m_database->isOpen())
    {
      disconnect(m_ui.revision,
		 SIGNAL(activated(int)),
		 this,
		 SLOT(slotRevisionChanged(int)));
      m_ui.revision->setCurrentIndex(0);
      return;
    }
  else if(index == 1) // A separator.
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QSqlQuery query(*m_database);
  QString dateTime(m_ui.revision->itemText(index));

  query.setForwardOnly(true);

  if(index == 0)
    {
      query.prepare(QString("SELECT content "
			    "FROM spot_on_urls_%1 WHERE url_hash = ?").
		    arg(m_urlHash.mid(0, 2)));
      query.bindValue(0, m_urlHash);
    }
  else
    {
      query.prepare(QString("SELECT content "
			    "FROM spot_on_urls_revisions_%1 WHERE "
			    "date_time_inserted = ? AND url_hash = ?").
		    arg(m_urlHash.mid(0, 2)));
      query.bindValue(0, dateTime);
      query.bindValue(1, m_urlHash);
    }

  if(query.exec())
    if(query.next())
      {
	QByteArray content;
	bool ok = true;

	content = crypt->decryptedAfterAuthenticated
	  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	if(ok)
	  {
	    content = qUncompress(content);

	    if(content.trimmed().isEmpty())
	      {
		m_content = "Malformed content. Enjoy!";
		m_webView->setContent(m_content);
	      }
	    else
	      {
		m_content = content;

		/*
		** setContent() will not
		** display some characters.
		** setHtml() may produce
		** network activity.
		*/

		m_webView->setHtml(m_content);
	      }

	    QLocale locale;

	    m_ui.size->setText
	      (tr("%1 KiB, Compressed %2 KiB").
	       arg(locale.toString(m_content.length() / 1024)).
	       arg(locale.toString(query.value(0).
				   toByteArray().length() / 1024)));
	  }
      }

  QApplication::restoreOverrideCursor();
}
