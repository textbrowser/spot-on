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

#include "Common/spot-on-crypt.h"
#include "spot-on.h"
#include "spot-on-defines.h"
#include "spot-on-smpwindow.h"
#include "spot-on-utilities.h"

spoton_smpwindow::spoton_smpwindow(void):QMainWindow()
{
  ui.setupUi(this);
  setWindowTitle(tr("%1: SMP Window").arg(SPOTON_APPLICATION_NAME));
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
  connect(ui.refresh,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefresh(void)));
  slotSetIcons();
}

spoton_smpwindow::~spoton_smpwindow()
{
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_smpwindow::event(QEvent *event)
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

void spoton_smpwindow::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_smpwindow::show(QWidget *parent)
{
  showNormal();
  activateWindow();
  raise();
  spoton_utilities::centerWidget(this, parent);
}

void spoton_smpwindow::slotClose(void)
{
  close();
}

void spoton_smpwindow::slotRefresh(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  ui.participants->clearContents();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	ui.participants->setSortingEnabled(false);

	QSqlQuery query(db);
	bool ok = true;
	int row = 0;

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "name, "
		      "key_type, "
		      "public_key "
		      "FROM friends_public_keys "
		      "WHERE key_type_hash IN (?, ?, ?, ?, ?, ?)");
	query.addBindValue
	  (crypt->keyedHash(QByteArray("chat"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("email"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("open-library"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("poptastic"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("rosetta"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      ui.participants->setRowCount(row + 1);

	      for(int i = 0; i < 3; i++)
		{
		  QByteArray bytes;
		  QTableWidgetItem *item = 0;

		  bytes = crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    item = new QTableWidgetItem(bytes.constData());
		  else
		    item = new QTableWidgetItem(tr("error"));

		  if(i == 2 && ok)
		    item->setText(spoton_crypt::publicKeyAlgorithm(bytes));

		  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		  ui.participants->setItem(row, i, item);
		}

	      row += 1;
	    }

	ui.participants->setSortingEnabled(true);
	ui.participants->horizontalHeader()->setSortIndicator
	  (0, Qt::AscendingOrder);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().toLower());

  if(!(iconSet == "everaldo" ||
       iconSet == "meego" ||
       iconSet == "nouve" ||
       iconSet == "nuvola"))
    iconSet = "nouve";
}
