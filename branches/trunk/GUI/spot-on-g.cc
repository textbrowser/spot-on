/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

#include "spot-on.h"

void spoton::slotShowMainTabContextMenu(const QPoint &point)
{
  if(m_locked)
    return;

  QWidget *widget = m_ui.tab->widget(m_ui.tab->tabBar()->tabAt(point));

  if(!widget)
    return;
  else if(!widget->isEnabled())
    return;

  QMapIterator<int, QWidget *> it(m_tabWidgets);
  QString name("");

  while(it.hasNext())
    {
      it.next();

      if(it.value() == widget)
	{
	  name = m_tabWidgetsProperties[it.key()]["name"].toString();
	  break;
	}
    }

  bool enabled = true;

  if(!(name == "buzz" || name == "listeners" || name == "neighbors" ||
       name == "search" || name == "starbeam" || name == "urls"))
    enabled = false;
  else if(name.isEmpty())
    enabled = false;

  QAction *action = 0;
  QMenu menu(this);

  action = menu.addAction(tr("&Close Page"), this, SLOT(slotCloseTab(void)));
  action->setEnabled(enabled);
  action->setProperty("name", name);
  menu.exec(m_ui.tab->tabBar()->mapToGlobal(point));
}

void spoton::slotCloseTab(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString name(action->property("name").toString());

  if(name == "buzz")
    m_ui.action_Buzz->setChecked(false);
  else if(name == "listeners")
    m_ui.action_Listeners->setChecked(false);
  else if(name == "neighbors")
    m_ui.action_Neighbors->setChecked(false);
  else if(name == "search")
    m_ui.action_Search->setChecked(false);
  else if(name == "starbeam")
    m_ui.action_StarBeam->setChecked(false);
  else if(name == "urls")
    m_ui.action_Urls->setChecked(false);
}

void spoton::slotRemoveAttachment(const QUrl &url)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QStringList list(m_ui.attachment->toPlainText().split('\n'));

  m_ui.attachment->clear();

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str != url.toString())
	m_ui.attachment->append(QString("<a href=\"%1\">%1</a>").arg(str));
    }

  QApplication::restoreOverrideCursor();
}

QByteArray spoton::poptasticNameEmail(void) const
{
  return m_settings["gui/poptasticNameEmail"].toByteArray();
}

void spoton::slotShowNotificationsWindow(void)
{
  m_notificationsWindow->showNormal();
  m_notificationsWindow->activateWindow();
  m_notificationsWindow->raise();
  centerWidget(m_notificationsWindow, this);
}

QByteArray spoton::copyMyOpenLibraryPublicKey(void) const
{
  if(!m_crypts.value("open-library", 0) ||
     !m_crypts.value("open-library-signature", 0))
    return QByteArray();

  QByteArray name;
  QByteArray mPublicKey;
  QByteArray mSignature;
  QByteArray sPublicKey;
  QByteArray sSignature;
  bool ok = true;

  name = m_settings.value("gui/openLibraryName", "unknown").toByteArray();
  mPublicKey = m_crypts.value("open-library")->publicKey(&ok);

  if(ok)
    mSignature = m_crypts.value("open-library")->
      digitalSignature(mPublicKey, &ok);

  if(ok)
    sPublicKey = m_crypts.value("open-library-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("open-library-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    return "K" + QByteArray("open-library").toBase64() + "@" +
      name.toBase64() + "@" +
      mPublicKey.toBase64() + "@" + mSignature.toBase64() + "@" +
      sPublicKey.toBase64() + "@" + sSignature.toBase64();
  else
    return QByteArray();
}

void spoton::slotCopyMyOpenLibraryPublicKey(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyOpenLibraryPublicKey());
}

void spoton::slotShareOpenLibraryPublicKey(void)
{
  if(!m_crypts.value("open-library", 0) ||
     !m_crypts.value("open-library-signature", 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypts.value("open-library")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("open-library")->digitalSignature
      (publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("open-library-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("open-library-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/openLibraryName", "unknown").
		      toByteArray());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("open-library").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotShareOpenLibraryPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }
}

void spoton::slotBuzzInvite(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QModelIndexList list
    (m_ui.participants->selectionModel()->selectedRows(1)); // OID
  QStringList oids;

  for(int i = 0; i < list.size(); i++)
    {
      if(list.value(i).data(Qt::UserRole).toBool())
	/*
	** Ignore temporary participants.
	*/

	continue;

      else if(list.value(i).
	      data(Qt::ItemDataRole(Qt::UserRole + 1)) != "chat")
	/*
	** Ignore non-chat participants.
	*/

	continue;
      else
	oids << list.value(i).data().toString();
    }

  if(oids.isEmpty())
    return;

  for(int i = 0; i < oids.size(); i++)
    {
      QByteArray message;

      message.append("buzzinvite_");
      message.append(oids.at(i).toLatin1());
      message.append("_");
      message.append("\n");

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::slotBuzzInvite(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }
}
