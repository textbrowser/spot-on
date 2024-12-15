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
#include "spot-on-utilities.h"

spoton_logviewer::spoton_logviewer(void):QMainWindow()
{
  ui.setupUi(this);
  setWindowTitle(tr("%1: Log Viewer").arg(SPOTON_APPLICATION_NAME));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.action_Empty_Log,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClear(void)));
  connect(ui.action_Enable_Log,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnableLog(bool)));
  connect(ui.clear,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClear(void)));

  QSettings settings;

  ui.action_Enable_Log->setChecked
    (settings.value("gui/guiLogEvents", false).toBool());
  spoton_misc::enableLog(ui.action_Enable_Log->isChecked());
  m_timer.setInterval(2500);
  slotSetIcons();
  m_lastModificationTime = QDateTime();

#ifndef Q_OS_MACOS
  auto font(ui.log->font());

  font.setStyleHint(QFont::Monospace);
  ui.log->setFont(font);
#endif
}

spoton_logviewer::~spoton_logviewer()
{
  m_timer.stop();
}

void spoton_logviewer::keyPressEvent(QKeyEvent *event)
{
  QMainWindow::keyPressEvent(event);
}

void spoton_logviewer::show(QWidget *parent)
{
  m_lastModificationTime = QDateTime();
  m_timer.start();
  showNormal();
  activateWindow();
  raise();
  spoton_utilities::centerWidget(this, parent);
}

void spoton_logviewer::slotClear(void)
{
  QFile::remove
    (spoton_misc::homePath() + QDir::separator() + "error_log.dat");
  ui.log->clear();
}

void spoton_logviewer::slotClose(void)
{
  close();
  m_timer.stop();
}

void spoton_logviewer::slotEnableLog(bool state)
{
  spoton_misc::enableLog(state);

  QSettings settings;

  settings.setValue("gui/guiLogEvents", state);
}

void spoton_logviewer::slotSetIcons(void)
{
  QSettings settings;
  auto iconSet(settings.value("gui/iconSet", "nuove").toString().toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";

  ui.clear->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
}

void spoton_logviewer::slotTimeout(void)
{
  QFileInfo const fileInfo
    (spoton_misc::homePath() + QDir::separator() + "error_log.dat");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() >= m_lastModificationTime)
	{
	  if(fileInfo.lastModified() == m_lastModificationTime)
	    m_lastModificationTime = fileInfo.lastModified().addMSecs(1);
	  else
	    m_lastModificationTime = fileInfo.lastModified();
	}
      else
	return;
    }
  else
    m_lastModificationTime = QDateTime();

  QFile file(fileInfo.absoluteFilePath());

  if(file.open(QIODevice::ReadOnly))
    {
      auto const vValue = ui.log->verticalScrollBar()->value();

      if(file.seek(qMax(static_cast<qint64> (0), file.size() - 256 * 1024)))
	{
	  ui.log->setPlainText(file.read(256 * 1024).trimmed());
	  ui.log->verticalScrollBar()->setValue(vValue);
	}

      file.close();
    }
}
