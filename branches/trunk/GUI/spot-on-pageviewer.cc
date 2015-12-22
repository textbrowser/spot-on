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
#include <iostream>

#include "../Common/spot-on-crypt.h"
#include "spot-on-defines.h"
#include "spot-on-pageviewer.h"

spoton_pageviewer::spoton_pageviewer(const QSqlDatabase &db,
				     const QString &urlHash,
				     spoton_crypt *crypt,
				     QWidget *parent):QMainWindow(parent)
{
  m_crypt = crypt;
  m_database = db;
  m_ui.setupUi(this);
  m_urlHash = urlHash;
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
  m_originalFindPalette = m_ui.find->palette();
#if QT_VERSION >= 0x040700
  m_ui.find->setPlaceholderText(tr("Find Text"));
#endif
  m_ui.revision->setEnabled(false);
  setAttribute(Qt::WA_DeleteOnClose);
  setWindowTitle(tr("%1: Page Viewer").arg(SPOTON_APPLICATION_NAME));
}

spoton_pageviewer::~spoton_pageviewer()
{
}

void spoton_pageviewer::slotFind(void)
{
  if(m_ui.find->text().isEmpty())
    m_ui.find->setPalette(m_originalFindPalette);
  else if(!m_ui.textBrowser->find(m_ui.find->text()))
    {
      QColor color(240, 128, 128); // Light Coral
      QPalette palette(m_ui.find->palette());

      palette.setColor(m_ui.find->backgroundRole(), color);
      m_ui.find->setPalette(palette);
      m_ui.textBrowser->moveCursor(QTextCursor::Start);
    }
  else
    m_ui.find->setPalette(m_originalFindPalette);
}

void spoton_pageviewer::slotFindInitialize(void)
{
  m_ui.find->selectAll();
  m_ui.find->setFocus();
}

void spoton_pageviewer::setPage(const QString &text, const QUrl &url,
				const int compressedSize)
{
  disconnect(m_ui.revision,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotRevisionChanged(int)));
  m_ui.revision->clear();

  QSqlQuery query(m_database);

  query.setForwardOnly(true);
  query.prepare(QString("SELECT content_hash, date_time_inserted "
			"FROM spot_on_urls_revisions_%1 WHERE url_hash = ? "
			"ORDER BY 2 DESC").
		arg(m_urlHash.mid(0, 2)));
  query.bindValue(0, m_urlHash);

  if(query.exec())
    while(query.next())
      m_ui.revision->addItem(query.value(1).toString(),
			     query.value(0).toByteArray());

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

  QLocale locale;

  m_ui.size->setText
    (QString("%1 KiB, Compressed %2 KiB").
     arg(locale.toString(text.length() / 1024)).
     arg(locale.toString(compressedSize / 1024)));
  m_ui.textBrowser->setHtml(text);
  m_ui.url->setText(url.toString());
}

void spoton_pageviewer::slotPagePrintPreview(void)
{
  QPrinter printer(QPrinter::HighResolution);
  QPrintPreviewDialog printDialog(&printer, this);

#ifdef Q_OS_MAC
  printDialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  printDialog.setWindowModality(Qt::WindowModal);
  connect(&printDialog,
	  SIGNAL(paintRequested(QPrinter *)),
	  this,
	  SLOT(slotPrint(QPrinter *)));
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  printDialog.show();
  QApplication::restoreOverrideCursor();

  if(printDialog.exec() == QDialog::Accepted)
    m_ui.textBrowser->print(&printer);
}

void spoton_pageviewer::slotPrint(QPrinter *printer)
{
  if(!printer)
    return;

  m_ui.textBrowser->print(printer);
}

void spoton_pageviewer::slotRevisionChanged(int index)
{
  if(!m_crypt || !m_database.isOpen())
    {
      disconnect(m_ui.revision,
		 SIGNAL(activated(int)),
		 this,
		 SLOT(slotRevisionChanged(int)));
      m_ui.revision->setCurrentIndex(0);
      m_ui.revision->setEnabled(false);
      return;
    }
  else if(index == 1) // A separator.
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QSqlQuery query(m_database);
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

	content = m_crypt->decryptedAfterAuthenticated
	  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	if(ok)
	  {
	    content = qUncompress(content);
	    m_ui.textBrowser->setHtml(content.constData());

	    QLocale locale;

	    m_ui.size->setText
	      (QString("%1 KiB, Compressed %2 KiB").
	       arg(locale.toString(content.length() / 1024)).
	       arg(locale.toString(query.value(0).
				   toByteArray().length() / 1024)));
	  }
      }

  QApplication::restoreOverrideCursor();
}
