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

#include <QDir>
#include <QKeyEvent>
#include <QScrollBar>
#include <QSettings>

#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-logviewer.h"

spoton_logviewer::spoton_logviewer(void):QMainWindow()
{
  ui.setupUi(this);
  setWindowTitle
    (tr("%1: Log Viewer").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#if QT_VERSION >= 0x050000
  setWindowFlags(windowFlags() & ~Qt::WindowFullscreenButtonHint);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.action_Empty_Log,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.clear,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.actionEnable_Log,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnableLog(bool)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));

  QSettings settings;

  ui.actionEnable_Log->setChecked(settings.value("gui/guiLogEvents",
						 false).toBool());
  spoton_misc::enableLog(ui.actionEnable_Log->isChecked());
  m_timer.setInterval(2500);
  slotSetIcons();
  m_lastModificationTime = QDateTime();

  QFont font(ui.log->font());

  font.setStyleHint(QFont::Monospace);
  ui.log->setFont(font);
}

spoton_logviewer::~spoton_logviewer()
{
  m_timer.stop();
}

void spoton_logviewer::slotClose(void)
{
  close();
  m_timer.stop();
}

void spoton_logviewer::slotClear(void)
{
  QFile::remove
    (spoton_misc::homePath() + QDir::separator() + "error_log.dat");
  ui.log->clear();
}

void spoton_logviewer::show(QWidget *parent)
{
  showNormal();
  activateWindow();
  raise();

  if(parent)
    {
      QPoint p(parent->pos());
      int X = 0;
      int Y = 0;

      if(parent->width() >= width())
	X = p.x() + (parent->width() - width()) / 2;
      else
	X = p.x() - (width() - parent->width()) / 2;

      if(parent->height() >= height())
	Y = p.y() + (parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - parent->height()) / 2;

      move(X, Y);
    }

  m_lastModificationTime = QDateTime();
  m_timer.start();
}

void spoton_logviewer::slotTimeout(void)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "error_log.dat");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() > m_lastModificationTime)
	m_lastModificationTime = fileInfo.lastModified();
      else
	return;
    }
  else
    m_lastModificationTime = QDateTime();

  QFile file(fileInfo.absoluteFilePath());

  if(file.open(QIODevice::ReadOnly))
    {
      int vValue = ui.log->verticalScrollBar()->value();

      if(file.seek(qMax(static_cast<qint64> (0),
			file.size() - 256 * 1024)))
	{
	  ui.log->setPlainText(file.read(256 * 1024).trimmed());
	  ui.log->verticalScrollBar()->setValue(vValue);
	}

      file.close();
    }
}

void spoton_logviewer::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_logviewer::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  toLower());

  if(!(iconSet == "everaldo" || iconSet == "nouve" || iconSet == "nuvola"))
    iconSet = "nouve";

  ui.clear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_logviewer::event(QEvent *event)
{
  if(event)
    if(event->type() == QEvent::WindowStateChange)
      if(windowState() == Qt::WindowNoState)
	{
	  /*
	  ** Minimizing the window on OS 10.6.8 and Qt 5.x will cause
	  ** the window to become stale once it has resurfaced.
	  */

	  hide();
	  show(0);
	  update();
	}

  return QMainWindow::event(event);
}
#endif
#endif

void spoton_logviewer::slotEnableLog(bool state)
{
  spoton_misc::enableLog(state);

  QSettings settings;

  settings.setValue("gui/guiLogEvents", state);
}
