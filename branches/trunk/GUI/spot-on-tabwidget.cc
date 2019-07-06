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

#include <QFileInfo>

#include "Common/spot-on-misc.h"
#include "spot-on-tabwidget.h"
#include "spot-on.h"

spoton_tabwidget::spoton_tabwidget(QWidget *parent):QTabWidget(parent)
{
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(2500);
#ifdef Q_OS_MAC
  setStyleSheet("QTabWidget::tab-bar {"
		"alignment: left;}");
#endif
}

spoton_tabwidget::~spoton_tabwidget()
{
}

QTabBar *spoton_tabwidget::tabBar(void) const
{
  return QTabWidget::tabBar();
}

void spoton_tabwidget::slotTimeout(void)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 * (spoton::instance() ?
				  spoton::instance()->m_settings.
				  value("gui/maximumEmailFileSize", 1024).
				  toLongLong() : 1024);

  if(fileInfo.size() >= maximumSize)
    {
      tabBar()->setTabTextColor(2, QColor("red"));
      tabBar()->setTabToolTip
	(2, tr("The database file email.db has reached its designated "
	       "capacity."));
    }
  else if((1.0 * fileInfo.size()) / (1.0 * maximumSize) >= 0.90)
    {
      tabBar()->setTabTextColor(2, QColor("orange"));
      tabBar()->setTabToolTip
	(2, tr("The database file email.db has almost reached its "
	       "designated capacity."));
    }
  else
    {
      tabBar()->setTabTextColor(2, QColor());
      tabBar()->setTabToolTip(2, "");
    }
}
