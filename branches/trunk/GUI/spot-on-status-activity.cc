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

#include "spot_on_status_activity.h"

spot_on_status_activity::spot_on_status_activity(QWidget *parent):
  QWidget(parent)
{
  m_dataReceived = 0;
  m_dataSent = 0;
  m_ui.setupUi(this);
}

spot_on_status_activity::
~spot_on_status_activity()
{
}

void spot_on_status_activity::slotDataReceived(const qint64 size)
{
  m_dataReceived += qAbs(size);
  m_ui.down->setPixmap(QPixmap(":/down_blue.png"));
  m_ui.down->setToolTip(QString::number(m_dataReceived));
  QTimer::singleShot(10, this, SLOT(slotNormalDown(void)));
}

void spot_on_status_activity::slotDataSent(const qint64 size)
{
  m_dataSent += qAbs(size);
  m_ui.up->setPixmap(QPixmap(":/up_blue.png"));
  m_ui.up->setToolTip(QString::number(m_dataSent));
  QTimer::singleShot(10, this, SLOT(slotNormalUp(void)));
}

void spot_on_status_activity::slotNormalDown(void)
{
  m_ui.down->setPixmap(QPixmap(":/down.png"));
}

void spot_on_status_activity::slotNormalUp(void)
{
  m_ui.up->setPixmap(QPixmap(":/up.png"));
}
