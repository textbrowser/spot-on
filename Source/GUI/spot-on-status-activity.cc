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

#include <QTimer>

#include "Common/spot-on-misc.h"
#include "spot-on-status-activity.h"

spoton_status_activity::spoton_status_activity
(QLabel *down, QLabel *up, QWidget *parent):QWidget(parent)
{
  m_dataReceived = 0;
  m_dataSent = 0;
  m_down = down;
  m_up = up;
}

spoton_status_activity::~spoton_status_activity()
{
}

void spoton_status_activity::slotDataReceived(const qint64 size)
{
  m_dataReceived += qAbs(size);

  if(m_down)
    {
      m_down->setPixmap(QPixmap(":/generic/down_bright.png"));
      m_down->setToolTip(spoton_misc::prettyFileSize(m_dataReceived));
    }

  QTimer::singleShot(10, this, SLOT(slotNormalDown(void)));
}

void spoton_status_activity::slotDataSent(const qint64 size)
{
  m_dataSent += qAbs(size);

  if(m_up)
    {
      m_up->setPixmap(QPixmap(":/generic/up_bright.png"));
      m_up->setToolTip(spoton_misc::prettyFileSize(m_dataSent));
    }

  QTimer::singleShot(10, this, SLOT(slotNormalUp(void)));
}

void spoton_status_activity::slotNormalDown(void)
{
  if(m_down)
    m_down->setPixmap(QPixmap(":/generic/down.png"));
}

void spoton_status_activity::slotNormalUp(void)
{
  if(m_up)
    m_up->setPixmap(QPixmap(":/generic/up.png"));
}
