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
#include "spot-on-emailwindow.h"

spoton_emailwindow::spoton_emailwindow(QWidget *parent):QMainWindow(parent)
{
  m_ui.setupUi(this);
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.emailParticipants->setColumnHidden(1, true); // OID
  m_ui.emailParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.emailParticipants->setColumnHidden(3, true); // public_key_hash
#ifdef Q_OS_WIN32
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
#endif
  connect(m_ui.reloadEmailNames,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPopulateParticipants(void)));
  
  foreach(QAbstractButton *button,
	  m_ui.emailParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Select All"));

  setWindowTitle(tr("%1: E-Mail").arg(SPOTON_APPLICATION_NAME));
  slotPopulateParticipants();
  slotUpdate();
}

spoton_emailwindow::~spoton_emailwindow()
{
}

void spoton_emailwindow::closeEvent(QCloseEvent *event)
{
  Q_UNUSED(event);
  deleteLater();
}

void spoton_emailwindow::slotPopulateParticipants(void)
{
  if(!spoton::instance())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.emailName->clear();
  m_ui.emailName->addItem
    (QString::fromUtf8(spoton::instance()->
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().constData(),
		       spoton::instance()->
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().length()).trimmed());

  QList<QHash<QString, QVariant> > list
    (spoton_misc::
     poptasticSettings("", spoton::instance()->crypts().value("chat", 0), 0));

  for(int i = 0; i < list.size(); i++)
    {
      if(i == 0)
	m_ui.emailName->insertSeparator(1);

      m_ui.emailName->addItem(list.at(i).value("in_username").toString());
    }

  QApplication::restoreOverrideCursor();
}

void spoton_emailwindow::slotReload(void)
{
}

void spoton_emailwindow::slotUpdate(void)
{
  if(!spoton::instance())
    return;

  m_ui.emailParticipants->setAlternatingRowColors
    (spoton::instance()->m_settings.
     value("gui/emailAlternatingRowColors", true).toBool());
}
