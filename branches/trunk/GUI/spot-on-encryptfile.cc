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

#include <QKeyEvent>
#include <QMessageBox>
#include <QSettings>

#include "spot-on-defines.h"
#include "spot-on-encryptfile-page.h"
#include "spot-on-encryptfile.h"
#include "spot-on-utilities.h"

spoton_encryptfile::spoton_encryptfile(void):QMainWindow()
{
  ui.setupUi(this);
  setWindowTitle(tr("%1: File Encryption").arg(SPOTON_APPLICATION_NAME));
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.action_New_Page,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotNewPage(void)));
  connect(ui.tabWidget,
	  SIGNAL(tabCloseRequested(int)),
	  this,
	  SLOT(slotCloseTab(int)));
  slotSetIcons();
  ui.tabWidget->setStyleSheet
    ("QTabBar::tear {"
     "image: none;"
     "}"
     );
  slotNewPage();
#ifdef Q_OS_MACOS
  spoton_utilities::enableTabDocumentMode(this);
#endif
}

spoton_encryptfile::~spoton_encryptfile()
{
}

bool spoton_encryptfile::occupied(void) const
{
  for(int i = 0; i < ui.tabWidget->count(); i++)
    {
      auto p = qobject_cast<spoton_encryptfile_page *>
	(ui.tabWidget->widget(i));

      if(p && p->occupied())
	return true;
    }

  return false;
}

void spoton_encryptfile::abort(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  for(int i = 0; i < ui.tabWidget->count(); i++)
    {
      auto p = qobject_cast<spoton_encryptfile_page *>
	(ui.tabWidget->widget(i));

      if(p)
	p->abort();
    }

  QApplication::restoreOverrideCursor();
}

void spoton_encryptfile::keyPressEvent(QKeyEvent *event)
{
  QMainWindow::keyPressEvent(event);
}

void spoton_encryptfile::show(QWidget *parent)
{
  spoton_utilities::centerWidget(this, parent);
  showNormal();
  activateWindow();
  raise();
}

void spoton_encryptfile::slotClose(void)
{
  close();
}

void spoton_encryptfile::slotCloseTab(int index)
{
  auto p = qobject_cast<spoton_encryptfile_page *>
    (ui.tabWidget->widget(index));

  if(!p)
    return;

  if(p->occupied())
    {
      ui.tabWidget->setCurrentIndex(index);

      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("The current page is processing data. Abort?"));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return;
	}

      QApplication::processEvents();
    }

  p->abort();
  p->deleteLater();
  ui.tabWidget->removeTab(index);
}

void spoton_encryptfile::slotNewPage(void)
{
  auto p = new spoton_encryptfile_page(this);

  ui.tabWidget->addTab(p, tr("Page"));
}

void spoton_encryptfile::slotSetIcons(void)
{
  QSettings settings;
  auto iconSet(settings.value("gui/iconSet", "nuove").toString().toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";
}

void spoton_encryptfile::slotStatus(const QString &status)
{
  statusBar()->showMessage(status.trimmed());
  statusBar()->repaint();
}
