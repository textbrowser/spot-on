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

#include <QDesktopServices>
#include <QPrintPreviewDialog>
#include <QPrinter>

#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-documentation.h"

spoton_documentation::spoton_documentation(QWidget *parent):QMainWindow(parent)
{
  m_ui.setupUi(this);
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
  connect(m_ui.textBrowser,
	  SIGNAL(anchorClicked(const QUrl &)),
	  this,
	  SLOT(slotAnchorClicked(const QUrl &)));
  m_ui.find->setPlaceholderText(tr("Find Text"));
  m_ui.textBrowser->setSource(QUrl("qrc:/Spot-On.html"));
  setWindowTitle(tr("%1: Documentation").arg(SPOTON_APPLICATION_NAME));
}

spoton_documentation::~spoton_documentation()
{
}

void spoton_documentation::slotAnchorClicked(const QUrl &url)
{
  QString scheme(url.scheme().toLower().trimmed());

  if(scheme != "qrc")
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to open %1?").
		 arg(url.toString()));
      mb.setWindowModality(Qt::WindowModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() == QMessageBox::Yes)
	QDesktopServices::openUrl(url);

      if(m_ui.textBrowser->isBackwardAvailable())
	QTimer::singleShot(250, m_ui.textBrowser, SLOT(backward(void)));
      else
	QTimer::singleShot(250, this, SLOT(slotReload(void)));
    }
}

void spoton_documentation::slotFind(void)
{
  QString text(m_ui.find->text());

  if(!m_ui.textBrowser->find(text))
    m_ui.textBrowser->moveCursor(QTextCursor::Start);
}

void spoton_documentation::slotFindInitialize(void)
{
  m_ui.find->selectAll();
  m_ui.find->setFocus();
}

void spoton_documentation::slotPagePrintPreview(void)
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

void spoton_documentation::slotPrint(QPrinter *printer)
{
  if(!printer)
    return;

  m_ui.textBrowser->print(printer);
}

void spoton_documentation::slotReload(void)
{
  m_ui.textBrowser->setSource(QUrl("qrc:/Spot-On.html"));
}
