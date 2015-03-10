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
#include "spot-on-defines.h"
#include "ui_adaptiveechoprompt.h"
#include "ui_ipinformation.h"

static bool lengthGreaterThan(const QString &string1, const QString &string2)
{
  return string1.toLower() > string2.toLower();
}

void spoton::slotDiscoverMissingLinks(void)
{
  if(!m_starbeamAnalyzer)
    return;

  QString fileName("");
  QString oid("");
  QString pulseSize("");
  QString totalSize("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      QTableWidgetItem *item = 0;

      item = m_ui.received->item(row, 4); // File

      if(item)
	fileName = item->text();

      item = m_ui.received->item(row, 2); // Pulse Size

      if(item)
	pulseSize = item->text();

      item = m_ui.received->item(row, 3); // Total Size

      if(item)
	totalSize = item->text();

      item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  m_starbeamAnalyzer->add(fileName, oid, pulseSize, totalSize);
  m_starbeamAnalyzer->show(this);
}

void spoton::slotShowStarBeamAnalyzer(void)
{
  if(m_starbeamAnalyzer)
    m_starbeamAnalyzer->show(this);
}

void spoton::slotDemagnetizeMissingLinks(void)
{
  QStringList list
    (m_ui.missingLinks->text().remove("magnet:?").split("&"));

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("fn="))
	{
	  str.remove(0, 3);
	  m_ui.transmittedFile->setText(str);
	}
      else if(str.startsWith("ps="))
	{
	  str.remove(0, 3);
	  m_ui.pulseSize->setValue(str.toInt());
	}
      else
	break;
    }
}

void spoton::slotUpdateChatWindows(void)
{
  /*
  ** Remove m_chatWindows entries that are invalid.
  */

  QMutableHashIterator<QString, QPointer<spoton_chatwindow> > it
    (m_chatWindows);

  while(it.hasNext())
    {
      it.next();

      if(!it.value())
	it.remove();
    }

  /*
  ** Update existing chat windows.
  */

  QStringList list;

  if(!m_chatWindows.isEmpty())
    for(int i = 0; i < m_ui.participants->rowCount(); i++)
      {
	QIcon icon;
	QString name("");
	QString oid("");
	QString publicKeyHash("");
	QTableWidgetItem *item = 0;

	item = m_ui.participants->item(i, 0);

	if(item)
	  {
	    icon = item->icon();
	    name = item->text();
	  }

	item = m_ui.participants->item(i, 1);

	if(item)
	  oid = item->text();

	if(!oid.isEmpty())
	  {
	    if(!m_chatWindows.contains(oid))
	      m_chatWindows.remove(oid);

	    emit statusChanged(icon, name, oid);
	  }

	item = m_ui.participants->item(i, 3);

	if(item)
	  publicKeyHash = item->text();

	if(!publicKeyHash.isEmpty())
	  list.append(publicKeyHash);
      }

  /*
  ** Remove chat windows that do not have corresponding participant
  ** entries.
  */

  it.toFront();

  while(it.hasNext())
    {
      it.next();

      if(!list.contains(it.key()))
	{
	  if(it.value())
	    it.value()->deleteLater();

	  it.remove();
	}
    }
}

void spoton::refreshInstitutions(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.institutions->clearContents();
	m_ui.institutions->setRowCount(0);
	m_ui.institutions->setSortingEnabled(false);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, hash_type, "
		      "name, postal_address FROM institutions"))
	  while(query.next())
	    {
	      m_ui.institutions->setRowCount
		(m_ui.institutions->rowCount() + 1);

	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      bool ok = true;

	      cipherType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		hashType = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		name = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		postalAddress = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      QTableWidgetItem *item = 0;

	      if(ok)
		item = new QTableWidgetItem(name.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 0, item);

	      if(ok)
		item = new QTableWidgetItem(cipherType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 1, item);

	      if(ok)
		item = new QTableWidgetItem(postalAddress.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 2, item);

	      if(ok)
		item = new QTableWidgetItem(hashType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem
		(m_ui.institutions->rowCount() - 1, 3, item);
	    }

	m_ui.institutions->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotAddInstitution(const QString &text)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QString name("");
  QString nameType("");
  QString postalAddress("");
  QString postalAddressType("");

  if(m_ui.addInstitutionCheckBox->isChecked() || !text.isEmpty())
    {
      QStringList list;

      if(text.isEmpty())
	list = m_ui.addInstitutionLineEdit->text().
	  remove("magnet:?").split("&");
      else
	list = text.mid(0).remove("magnet:?").split("&");

      for(int i = 0; i < list.size(); i++)
	{
	  QString str(list.at(i));

	  if(str.startsWith("in="))
	    {
	      str.remove(0, 3);
	      name = str;
	    }
	  else if(str.startsWith("ct="))
	    {
	      str.remove(0, 3);
	      nameType = str;
	    }
	  else if(str.startsWith("pa="))
	    {
	      str.remove(0, 3);
	      postalAddress = str;
	    }
	  else if(str.startsWith("ht="))
	    {
	      str.remove(0, 3);
	      postalAddressType = str;
	    }
	}
    }
  else
    {
      name = m_ui.institutionName->text();
      nameType = m_ui.institutionNameType->currentText();
      postalAddress = m_ui.institutionPostalAddress->text();
      postalAddressType = m_ui.institutionPostalAddressType->currentText();
    }

  if(name.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution name."));
      return;
    }

  if(postalAddress.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution "
			       "postal address."));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO institutions "
	   "(cipher_type, hash_type, hash, name, postal_address) "
	   "VALUES (?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(nameType.toLatin1(),
					 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(postalAddressType.toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->keyedHash(name.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->encryptedThenHashed(name.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->
	     encryptedThenHashed(postalAddress.toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(text.isEmpty())
	{
	  m_ui.addInstitutionLineEdit->clear();
	  m_ui.institutionName->clear();
	  m_ui.institutionNameType->setCurrentIndex(0);
	  m_ui.institutionPostalAddress->clear();
	  m_ui.institutionPostalAddressType->setCurrentIndex(0);
	}

      refreshInstitutions();
    }
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("Unable to record the institution."));
}

void spoton::slotDeleteInstitution(void)
{
  QModelIndexList list
    (m_ui.institutions->selectionModel()->selectedRows(0)); // Name

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM institutions WHERE hash = ?");

	if(m_crypts.value("email", 0))
	  query.bindValue
	    (0, m_crypts.value("email")->
	     keyedHash(list.value(0).data().toString().toLatin1(), &ok).
	     toBase64());
	else
	  ok = false;

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  refreshInstitutions();
}

void spoton::slotCopyInstitution(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.institutions->currentRow()) >= 0)
    {
      QTableWidgetItem *item1 = m_ui.institutions->item(row, 0);
      QTableWidgetItem *item2 = m_ui.institutions->item(row, 1);
      QTableWidgetItem *item3 = m_ui.institutions->item(row, 2);
      QTableWidgetItem *item4 = m_ui.institutions->item(row, 3);

      if(item1 && item2 && item3 && item4)
	{
	  QString magnet(QString("magnet:?"
				 "in=%1&"
				 "ct=%2&"
				 "pa=%3&"
				 "ht=%4&"
				 "xt=urn:institution").
			 arg(item1->text()).
			 arg(item2->text()).
			 arg(item3->text()).
			 arg(item4->text()));

	  clipboard->setText(magnet);
	}
    }
}

void spoton::slotShowMinimalDisplay(bool state)
{
#if SPOTON_GOLDBUG == 1
  m_ui.buildInformation->setHidden(state);
  m_ui.label_27->setHidden(state);
  m_ui.passphraseGroupBox->setHidden(state);
  m_ui.label_58->setHidden(state);
  m_ui.geoipPath4->setHidden(state);
  m_ui.selectGeoIP4->setHidden(state);
  m_ui.geoipPath6->setHidden(state);
  m_ui.selectGeoIP6->setHidden(state);
  m_ui.label_81->setHidden(state);
  m_ui.pid->setHidden(state);
  m_ui.label_17->setHidden(state);
  m_ui.line_4->setHidden(state);
  m_ui.label_4->setHidden(state);
  m_ui.cipherType->setHidden(state);
  m_ui.hashType->setHidden(state);
  m_ui.iterationCount->setHidden(state);
  m_ui.saltLength->setHidden(state);
  m_ui.label_58->setHidden(state);
  m_ui.label_43->setHidden(state);
  m_ui.sslControlString->setHidden(state);
  m_ui.saveSslControlString->setHidden(state);
  m_ui.label_42->setHidden(state);
  m_ui.label_41->setHidden(state);
  m_ui.label_40->setHidden(state);
  m_ui.label_42->setHidden(state);
  m_ui.label_38->setHidden(state);
  m_ui.ipv4Listener->setHidden(state);
  m_ui.ipv6Listener->setHidden(state);
  m_ui.listenerScopeIdLabel->setHidden(state);
  m_ui.listenerScopeId->setHidden(state);
  m_ui.label_12->setHidden(state);
  m_ui.listenerPort->setHidden(state);
  m_ui.label_15->setHidden(state);
  m_ui.sslListener->setHidden(state);
  m_ui.listenerKeySize->setHidden(state);
  m_ui.listenersEchoMode->setHidden(state);
  m_ui.deleteAllListeners->setHidden(state);
  m_ui.label_28->setHidden(state);
  m_ui.publishedKeySize->setHidden(state);
  m_ui.recordIPAddress->setHidden(state);
  m_ui.permanentCertificate->setHidden(state);
  m_ui.groupBox_5->setHidden(state);
  m_ui.accountsGB->setHidden(state);
  m_ui.listeners->setHidden(state);
  m_ui.label_65->setHidden(state);
  m_ui.listenerTransport->setHidden(state);
  m_ui.label_71->setHidden(state);
  m_ui.listenerOrientation->setHidden(state);
  m_ui.listenersActionMenu->setHidden(state);
  m_ui.listeners->setColumnHidden(2, state);
  m_ui.listeners->setColumnHidden(5, state);
  m_ui.listeners->setColumnHidden(6, state);
  m_ui.listeners->setColumnHidden(9, state);
  m_ui.listeners->setColumnHidden(10, state);
  m_ui.listeners->setColumnHidden(11, state);
  m_ui.proxy->setHidden(state);
  m_ui.neighborKeySize->setHidden(state);
  m_ui.label_13->setHidden(state);
  m_ui.neighborPort->setHidden(state);
  m_ui.neighborScopeIdLabel->setHidden(state);
  m_ui.neighborScopeId->setHidden(state);
  m_ui.ipv4Neighbor->setHidden(state);
  m_ui.ipv6Neighbor->setHidden(state);
  m_ui.dynamicdns->setHidden(state);
  m_ui.neighborsEchoMode->setHidden(state);
  m_ui.addException->setHidden(state);
  m_ui.groupBox_4->setHidden(state);
  m_ui.requireSsl->setHidden(state);
  m_ui.label_32->setHidden(state);
  m_ui.buzzName->setHidden(state);
  m_ui.saveBuzzName->setHidden(state);
  m_ui.clearMessages->setHidden(state);
  m_ui.copyrepleo_chat->setHidden(state);
  m_ui.acceptChatKeys->setHidden(state);
  m_ui.participants->setColumnHidden(4, state);
  m_ui.participants->setColumnHidden(7, state);
  m_ui.mail->setColumnHidden(0, state);
  m_ui.mail->setColumnHidden(2, state);
  m_ui.label_16->setHidden(state);
  m_ui.emailName->setHidden(state);
  m_ui.saveEmailName->setHidden(state);
  m_ui.saveCopy->setHidden(state);
  m_ui.line_18->setHidden(state);
  m_ui.postoffice->setHidden(state);
  m_ui.label_79->setHidden(state);
  m_ui.label_80->setHidden(state);
  m_ui.institutionNameType->setHidden(state);
  m_ui.institutionPostalAddressType->setHidden(state);
  m_ui.institutions->setColumnHidden(1, state);
  m_ui.institutions->setColumnHidden(3, state);
  m_ui.etpMagnets->setHidden(state);
  m_ui.label_52->setHidden(state);
  m_ui.label_57->setHidden(state);
  m_ui.etpCipherType->setHidden(state);
  m_ui.etpHashType->setHidden(state);
  m_ui.generate->setHidden(state);
  m_ui.label_60->setHidden(state);
  m_ui.label_69->setHidden(state);
  m_ui.generateNova->setHidden(state);
  m_ui.transmitNova->setHidden(state);
  m_ui.label_54->setHidden(state);
  m_ui.pulseSize->setHidden(state);
  m_ui.magnetsActionMenu->setHidden(state);
  m_ui.missingLinksCheckBox->setHidden(state);
  m_ui.missingLinks->setHidden(state);
  m_ui.demagnetizeMissingLinks->setHidden(state);
  m_ui.label_85->setHidden(state);
  m_ui.ae_e_type->setHidden(state);
  m_ui.ae_h_type->setHidden(state);
  m_ui.deleteAEToken->setHidden(state);
  m_ui.label_86->setHidden(state);
  m_ui.resend->setHidden(state);
  m_ui.label_59->setHidden(state);
  m_ui.etpMaxMosaicSize->setHidden(state);
#else
  m_sb.errorlog->setHidden(state);
  m_ui.neighborSummary->setHidden(state);
#endif
}

void spoton::slotSaveMOTD(void)
{
  QString connectionName("");
  QString error("");
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      error = tr("Invalid listener OID. Please select a listener.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString str(m_ui.motd->toPlainText());

	if(str.isEmpty())
	  str = QString("Welcome to %1.").
	    arg(SPOTON_APPLICATION_NAME);

	query.prepare("UPDATE listeners SET motd = ? WHERE OID = ?");
	query.bindValue(0, str);
	query.bindValue(1, oid);

	if(!query.exec())
	  error = tr
	    ("Database error. Unable to save the message of the day.");
      }
    else
      error = tr("Unable to open listeners.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
}

void spoton::populateMOTD(const QString &listenerOid)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	m_ui.motd->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT motd FROM listeners "
		      "WHERE OID = ?");
	query.bindValue(0, listenerOid);

	if(query.exec())
	  if(query.next())
	    m_ui.motd->setPlainText(query.value(0).toString().trimmed());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotChatPopup(void)
{
  QList<QTableWidgetItem *> items(m_ui.participants->selectedItems());

  if(!items.isEmpty() && items.at(0))
    slotParticipantDoubleClicked
      (m_ui.participants->item(items.at(0)->row(), 0));
}

void spoton::slotCommonBuzzChannelsActivated(int index)
{
  repaint();
  m_ui.demagnetize->setText
    (m_ui.commonBuzzChannels->itemData(index).toString());
  demagnetize();
  m_ui.demagnetize->clear();
  m_ui.buzzActions->setCurrentIndex(0);
  disconnect(m_ui.commonBuzzChannels,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotCommonBuzzChannelsActivated(int)));
  m_ui.commonBuzzChannels->setCurrentIndex(0);
  connect(m_ui.commonBuzzChannels,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotCommonBuzzChannelsActivated(int)));
}

void spoton::slotConnectAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE neighbors SET status_control = 'connected' "
	   "WHERE status_control <> 'deleted' AND "
	   "user_defined = 1");
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDisconnectAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE neighbors SET status_control = 'disconnected' "
	   "WHERE status_control <> 'deleted'");
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotMessagesAnchorClicked(const QUrl &link)
{
  QString type("");

  if(spoton_misc::isValidBuzzMagnet(link.toString().toLatin1()))
    type = "buzz";
  else if(spoton_misc::isValidInstitutionMagnet(link.toString().toLatin1()))
    type = "institution";
  else if(spoton_misc::isValidStarBeamMagnet(link.toString().toLatin1()))
    type = "starbeam";

  if(type.isEmpty())
    return;

  QAction *action = 0;
  QMenu menu(this);

  action = menu.addAction(tr("&Add magnet."),
			  this,
			  SLOT(slotAddMagnet(void)));
  action->setProperty("type", type);
  action->setProperty("url", link);
  menu.exec(QCursor::pos());
}

void spoton::slotAddMagnet(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString type(action->property("type").toString().toLower());
  QUrl url(action->property("url").toUrl());

  if(type == "buzz")
    {
      spoton_crypt *crypt = m_crypts.value("chat", 0);

      if(!crypt)
	{
	  QMessageBox::critical(this, tr("%1: Error").
				arg(SPOTON_APPLICATION_NAME),
				tr("Invalid spoton_crypt object. This is "
				   "a fatal flaw."));
	  return;
	}

      QByteArray channel;
      QByteArray channelSalt;
      QByteArray channelType;
      QByteArray hashKey;
      QByteArray hashType;
      QByteArray iterationCount;
      QStringList list
	(url.toString().remove("magnet:?").split("&"));

      while(!list.isEmpty())
	{
	  QString str(list.takeFirst());

	  if(str.startsWith("rn="))
	    {
	      str.remove(0, 3);
	      channel = str.toLatin1();
	    }
	  else if(str.startsWith("xf="))
	    {
	      str.remove(0, 3);
	      iterationCount = str.toLatin1();
	    }
	  else if(str.startsWith("xs="))
	    {
	      str.remove(0, 3);
	      channelSalt = str.toLatin1();
	    }
	  else if(str.startsWith("ct="))
	    {
	      str.remove(0, 3);
	      channelType = str.toLatin1();
	    }
	  else if(str.startsWith("hk="))
	    {
	      str.remove(0, 3);
	      hashKey = str.toLatin1();
	    }
	  else if(str.startsWith("ht="))
	    {
	      str.remove(0, 3);
	      hashType = str.toLatin1();
	    }
	  else if(str.startsWith("xt="))
	    {
	    }
	}

      QString connectionName("");
      bool ok = true;

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "buzz_channels.db");

	if(db.open())
	  {
	    QByteArray data;
	    QSqlQuery query(db);

	    data.append(channel.toBase64());
	    data.append("\n");
	    data.append(iterationCount.toBase64());
	    data.append("\n");
	    data.append(channelSalt.toBase64());
	    data.append("\n");
	    data.append(channelType.toBase64());
	    data.append("\n");
	    data.append(hashKey.toBase64());
	    data.append("\n");
	    data.append(hashType.toBase64());
	    data.append("\n");
	    data.append(QByteArray("urn:buzz").toBase64());
	    query.prepare("INSERT OR REPLACE INTO buzz_channels "
			  "(data, data_hash) "
			  "VALUES (?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(data, &ok).toBase64());

	    if(ok)
	      query.bindValue(1, crypt->keyedHash(data, &ok).toBase64());

	    if(ok)
	      ok = query.exec();
	  }
	else
	  ok = false;

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("An error occurred while attempting to "
				 "save the channel data. Please enable "
				 "logging via the Log Viewer and try again."));
      else
	slotPopulateBuzzFavorites();
    }
  else if(type == "institution")
    slotAddInstitution(url.toString());
  else if(type == "starbeam")
    slotAddEtpMagnet(url.toString());
}

void spoton::slotAddAEToken(void)
{
  QString connectionName("");
  QString error("");
  QString token(m_ui.ae_token->text());
  QString type(m_ui.ae_e_type->currentText() + "\n" +
	       m_ui.ae_h_type->currentText());
  QStringList list;
  bool ok = true;
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(m_ui.ae_listeners_magnet->isChecked())
    {
      list = parseAEMagnet(token);

      if(list.isEmpty())
	{
	  error = tr("Invalid adaptive echo magnet.");
	  goto done_label;
	}
      else
	{
	  token = list.value(2);
	  type = list.value(0) + "\n" + list.value(1);
	}
    }

  if(token.isEmpty() || type == "n/a")
    {
      error = tr("Please provide a token and a token type.");
      goto done_label;
    }
  else if(token.length() < 96)
    {
      error = tr("Please provide a token that contains at "
		 "least ninety-six characters.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO listeners_adaptive_echo_tokens "
	   "(token, "
	   "token_hash, "
	   "token_type) "
	   "VALUES (?, ?, ?)");
	query.bindValue
	  (0, crypt->encryptedThenHashed(token.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash((token + type).toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->encryptedThenHashed(type.toLatin1(),
					   &ok).toBase64());

	if(ok)
	  query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error has occurred.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME), error);
  else
    {
      m_ui.ae_e_type->setCurrentIndex(0);
      m_ui.ae_h_type->setCurrentIndex(0);
      m_ui.ae_listeners_magnet->setChecked(false);
      m_ui.ae_token->clear();
      populateAETokens();
    }
}

void spoton::slotDeleteAEToken(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QList<QTableWidgetItem *> list(m_ui.ae_tokens->selectedItems());

  if(list.size() != 3 || !list.at(0) || !list.at(1) || !list.at(2))
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Please select a token to delete."));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM listeners_adaptive_echo_tokens WHERE "
		      "token_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash((list.at(0)->text() +
				list.at(1)->text() +
				"\n" +
				list.at(2)->text()).toLatin1(), &ok).
	   toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateAETokens();
}

void spoton::populateAETokens(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QByteArray bytes1;
	QByteArray bytes2;
	QByteArray bytes3;
	QModelIndexList list;

	list = m_ui.ae_tokens->selectionModel()->selectedRows(0);

	if(!list.isEmpty())
	  bytes1 = list.at(0).data().toByteArray();

	list = m_ui.ae_tokens->selectionModel()->selectedRows(1);

	if(!list.isEmpty())
	  bytes2 = list.at(0).data().toByteArray();

	list = m_ui.ae_tokens->selectionModel()->selectedRows(2);

	if(!list.isEmpty())
	  bytes3 = list.at(0).data().toByteArray();

	m_ui.ae_tokens->setSortingEnabled(false);
	m_ui.ae_tokens->clearContents();
	m_ui.ae_tokens->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare
	  ("SELECT token, token_type FROM listeners_adaptive_echo_tokens");

	if(query.exec())
	  while(query.next())
	    {
	      m_ui.ae_tokens->setRowCount(m_ui.ae_tokens->rowCount() + 1);

	      QByteArray eType;
	      QByteArray hType;
	      QByteArray token;
	      QByteArray type;
	      bool ok = true;

	      token = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		type = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		{
		  eType = type.split('\n').value(0);
		  hType = type.split('\n').value(1);
		}

	      QTableWidgetItem *item = 0;

	      if(ok)
		item = new QTableWidgetItem(token.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem
		(m_ui.ae_tokens->rowCount() - 1, 0, item);

	      if(ok)
		item = new QTableWidgetItem(eType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem
		(m_ui.ae_tokens->rowCount() - 1, 1, item);

	      if(ok)
		item = new QTableWidgetItem(hType.constData());
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem
		(m_ui.ae_tokens->rowCount() - 1, 2, item);

	      if(bytes1 == token && bytes2 == eType && bytes3 == hType)
		m_ui.ae_tokens->selectRow
		  (m_ui.ae_tokens->rowCount() - 1);
	    }

	m_ui.ae_tokens->setSortingEnabled(true);
	m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotResetAETokenInformation(void)
{
  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "ae_token = NULL, "
		      "ae_token_type = NULL "
		      "WHERE OID = ? AND user_defined = 1");
	query.bindValue(0, list.at(0).data());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSetAETokenInformation(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QModelIndexList list;
  QString oid("");

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid neighbor OID. "
			       "Please select a neighbor."));
      return;
    }
  else
    oid = list.at(0).data().toString();

  QStringList etypes(spoton_crypt::cipherTypes());

  if(etypes.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("The method spoton_crypt::cipherTypes() has "
			       "failed. "
			       "This is a fatal flaw."));
      return;
    }

  QStringList htypes(spoton_crypt::hashTypes());

  if(htypes.isEmpty())
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("The method spoton_crypt::hashTypes() has "
			       "failed. "
			       "This is a fatal flaw."));
      return;
    }

  QDialog dialog(this);
  Ui_adaptiveechoprompt ui;

  dialog.setWindowTitle
    (tr("%1: Adaptive Echo Information").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(&dialog);
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  ui.token_e_type->addItems(etypes);
  ui.token_h_type->addItems(htypes);

  if(dialog.exec() == QDialog::Accepted)
    {
      QString token(ui.token->text());
      QString tokenType(ui.token_e_type->currentText() + "\n" +
			ui.token_h_type->currentText());
      QStringList list;

      if(ui.magnet->isChecked())
	{
	  list = parseAEMagnet(token);

	  if(list.isEmpty())
	    {
	      token.clear();
	      tokenType.clear();
	    }
	  else
	    {
	      token = list.value(2);
	      tokenType = list.value(0) + "\n" + list.value(1);
	    }
	}

      if(token.length() >= 96)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "ae_token = ?, "
			      "ae_token_type = ? "
			      "WHERE OID = ? AND user_defined = 1");
		query.bindValue
		  (0, crypt->encryptedThenHashed(token.toLatin1(),
						 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, crypt->encryptedThenHashed(tokenType.toLatin1(),
						   &ok).toBase64());

		query.bindValue(2, oid);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
      else
	QMessageBox::critical(this, tr("%1: Error").
			      arg(SPOTON_APPLICATION_NAME),
			      tr("The token must contain "
				 "at least ninety-six characters."));
    }
}

void spoton::joinDefaultBuzzChannel(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Joining a default Buzz channel. "
			  "Please be patient."));
  m_sb.status->repaint();

  int index = m_ui.commonBuzzChannels->findData
    ("Spot-On_Developer_Channel_Key", Qt::UserRole, Qt::MatchContains);

  if(index >= 0)
    slotCommonBuzzChannelsActivated(index);

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
}

void spoton::slotSaveBuzzAutoJoin(bool state)
{
  m_settings["gui/buzzAutoJoin"] = state;

  QSettings settings;

  settings.setValue("gui/buzzAutoJoin", state);
}

void spoton::slotEnableChatEmoticons(bool state)
{
  m_settings["gui/enableChatEmoticons"] = state;

  QSettings settings;

  settings.setValue("gui/enableChatEmoticons", state);
}

void spoton::slotLimitConnections(int value)
{
  m_settings["gui/limitConnections"] = value;

  QSettings settings;

  settings.setValue("gui/limitConnections", value);
}

QString spoton::mapIconToEmoticon(const QString &content)
{
  QList<QString> list;
  QMap<QString, QString> map;
  QString str(content);

  map[":-)"] = map[":)"] = map[":O)"] = map[":]"] = map[":}"] =
    "<img src=\":/emoticons/smile.png\"></img>";
  map[":-D"] = map[":D"] = "<img src=\":/emoticons/laugh.png\"></img>";
  map[":-))"] = "<img src=\":/emoticons/happy.png\"></img>";
  map[":-("] = map[":("] =
    map[":-["] = map[":["] =
    map[":{"] = "<img src=\":/emoticons/sad.png\"></img>";
  map[";)"] = "<img src=\":/emoticons/wink.png\"></img>";
  map[":-||"] = "<img src=\":/emoticons/angry.png\"></img>";
  map[":'-("] = map[":'("] = "<img src=\":/emoticons/crying.png\"></img>";
  map[":-O"] = map[":O"] =
    "<img src=\":/emoticons/shocked.png\"></img>";
  map[":*"] = map[":^*"] = map[":-)(-:"] =
    "<img src=\":/emoticons/kiss.png\"></img>";
  map[":-P"] = map[":P"] =
    "<img src=\":/emoticons/tongue.png\"></img>";
  map[":-/"] = map[":\\"] =
    "<img src=\":/emoticons/confused.png\"></img>";
  map[":|"] = map[":-|"] = "<img src=\":/emoticons/neutral.png\"></img>";
  map["O:-)"] =
    "<img src=\":/emoticons/angel.png\"></img>";
  map["}:)"] = map["}:-)"] = "<img src=\":/emoticons/devil.png\"></img>";
  map["O-)"] = "<img src=\":/emoticons/cyclops.png\"></img>";
  map["(T)"] = "<img src=\":/emoticons/phone.png\"></img>";
  map["C:-)"] = map["C:)"] = "<img src=\":/emoticons/skywalker.png\"></img>";
  map["8-)"] = map["B-)"] = map["|;-)"] =
    "<img src=\":/emoticons/glasses-cool.png\"></img>";
  map["@>-->--"] = map["@}-;-'---"] =
    "<img src=\":/emoticons/rose.png\"></img>";

  list = map.keys();
  qSort(list.begin(), list.end(), lengthGreaterThan);

  for(int i = 0; i < list.size(); i++)
    str.replace(list.at(i), map[list.at(i)], Qt::CaseInsensitive);

  return str;
}

void spoton::slotAutoAddSharedSBMagnets(bool state)
{
  m_settings["gui/autoAddSharedSBMagnets"] = state;

  QSettings settings;

  settings.setValue("gui/autoAddSharedSBMagnets", state);
}

bool spoton::promptBeforeExit(void)
{
  if(m_ui.pid->text().toInt() > 0)
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setWindowTitle(tr("%1: Question").
			arg(SPOTON_APPLICATION_NAME));
      mb.setWindowModality(Qt::WindowModal);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("The kernel appears to be active. Closing %1 "
		    "will not deactivate the kernel. Continue?").
		 arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	return true;
    }

  return false;
}

void spoton::slotSignatureKeyTypeChanged(int index)
{
  QStringList list;

  if(index == 0)
    list << "3072"
	 << "4096"
	 << "7680"
	 << "8192"
	 << "15360";
  else if(index == 1)
    list << "224"
	 << "256"
	 << "384"
	 << "521";
  else if(index == 2)
    list << "Ed25519";
  else if(index == 3)
    list << "3072"
	 << "4096"
	 << "7680"
	 << "8192"
	 << "15360";
  else
    list << "3072"
	 << "4096"
	 << "7680"
	 << "8192"
	 << "15360";

  m_ui.signatureKeySize->clear();
  m_ui.signatureKeySize->addItems(list);
  m_ui.signatureKeySize->setCurrentIndex(0);
}

void spoton::slotShowEncryptFile(void)
{
  m_encryptFile.show(this);
}

void spoton::slotDisplayPopups(bool state)
{
  m_settings["gui/displayPopupsAutomatically"] = state;

  QSettings settings;

  settings.setValue("gui/displayPopupsAutomatically", state);
}

void spoton::slotAddAttachment(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Attachment").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    m_ui.attachment->setText(dialog.selectedFiles().value(0));
}

void spoton::slotSaveAttachment(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QModelIndexList list;

  list = m_ui.mail->selectionModel()->selectedRows(4); // Attachment(s)

  if(list.isEmpty() || list.value(0).data(Qt::UserRole).toInt() <= 0)
    return;

  list = m_ui.mail->selectionModel()->selectedRows
    (m_ui.mail->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QByteArray attachment;
  QString attachmentName("");
  bool ok = false;

  {
    QString connectionName("");

    {
      QSqlDatabase db = spoton_misc::database(connectionName);

      db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			 "email.db");

      if(db.open())
	{
	  QSqlQuery query(db);

	  query.setForwardOnly(true);
	  query.prepare("SELECT data, name FROM folders_attachment "
			"WHERE folders_oid = ?");
	  query.bindValue(0, list.value(0).data().toString());

	  if(query.exec())
	    if(query.next())
	      {
		attachment = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).
					  toByteArray()),
		   &ok);

		if(ok)
		  attachmentName = QString::fromUtf8
		    (crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.value(1).
							    toByteArray()),
						 &ok));
	      }
	}

      db.close();
    }

    QSqlDatabase::removeDatabase(connectionName);
  }

  if(ok)
    {
      QFileDialog dialog(this);

      dialog.setAcceptMode(QFileDialog::AcceptSave);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
      dialog.setConfirmOverwrite(true);
      dialog.setDirectory(QDir::homePath());
      dialog.setFileMode(QFileDialog::AnyFile);
      dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
      dialog.selectFile(attachmentName);
      dialog.setWindowTitle(tr("%1: Save Attachment").
			    arg(SPOTON_APPLICATION_NAME));

      if(dialog.exec() == QDialog::Accepted)
	{
	  QFile file(dialog.selectedFiles().value(0));

	  if(file.open(QIODevice::WriteOnly))
	    file.write(attachment, attachment.length());

	  file.close();
	}
    }
}

void spoton::applyGoldbugToAttachments(const QString &folderOid,
				       const QSqlDatabase &db,
				       int *count,
				       spoton_crypt *crypt1,
				       bool *ok1)
{
  if(!count || !crypt1)
    {
      if(ok1)
	*ok1 = false;

      return;
    }

  spoton_crypt *crypt2 = m_crypts.value("email", 0);

  if(!crypt2)
    {
      if(ok1)
	*ok1 = false;

      return;
    }

  QSqlQuery query(db);

  query.setForwardOnly(true);
  query.prepare("SELECT data, name, OID FROM folders_attachment WHERE "
		"folders_oid = ?");
  query.bindValue(0, folderOid);

  if(query.exec())
    {
      while(query.next())
	{
	  QByteArray attachment
	    (QByteArray::fromBase64(query.value(0).toByteArray()));
	  QByteArray attachmentName
	    (QByteArray::fromBase64(query.value(1).toByteArray()));
	  bool ok2 = true;

	  attachment = crypt2->decryptedAfterAuthenticated(attachment, &ok2);

	  if(ok2)
	    attachmentName = crypt2->decryptedAfterAuthenticated
	      (attachmentName, &ok2);

	  if(ok2)
	    {
	      attachment = crypt1->decrypted(attachment, &ok2);

	      if(ok2)
		{
		  if(!attachment.isEmpty())
		    attachment = qUncompress(attachment);

		  attachmentName = crypt1->decrypted(attachmentName, &ok2);
		}

	      if(ok2)
		{
		  if(!attachment.isEmpty() && !attachmentName.isEmpty())
		    {
		      QSqlQuery updateQuery(db);

		      updateQuery.prepare("UPDATE folders_attachment "
					  "SET data = ?, "
					  "name = ? "
					  "WHERE OID = ?");
		      updateQuery.bindValue
			(0, crypt2->encryptedThenHashed(attachment, &ok2).
			 toBase64());

		      if(ok2)
			updateQuery.bindValue
			  (1, crypt2->encryptedThenHashed(attachmentName,
							  &ok2).
			   toBase64());

		      updateQuery.bindValue(2, query.value(2));

		      if(ok2)
			{
			  if(updateQuery.exec())
			    *count += 1;
			  else
			    {
			      if(*ok1)
				*ok1 = false;

			      break;
			    }
			}
		      else
			{
			  if(ok1)
			    *ok1 = false;

			  break;
			}
		    }
		  else
		    {
		      QSqlQuery deleteQuery(db);

		      deleteQuery.exec("PRAGMA secure_delete = ON");
		      deleteQuery.prepare("DELETE FROM folders_attachment "
					  "WHERE OID = ?");
		      deleteQuery.bindValue(0, query.value(2));

		      if(deleteQuery.exec())
			*count -= 1;
		      else
			{
			  if(ok1)
			    *ok1 = false;

			  break;
			}
		    }
		}
	      else
		{
		  if(ok1)
		    *ok1 = false;

		  break;
		}
	    }
	  else
	    {
	      if(*ok1)
		*ok1 = false;

	      break;
	    }
	}
    }
  else if(ok1)
    *ok1 = false;
}

void spoton::slotEncryptionKeyTypeChanged(int index)
{
  QStringList list;

  if(index == 0 || index == 2)
    list << "3072"
	 << "4096"
	 << "7680"
	 << "8192"
	 << "15360";
  else
    list << "EES1087EP2"
	 << "EES1171EP1"
	 << "EES1499EP1";

  m_ui.encryptionKeySize->clear();
  m_ui.encryptionKeySize->addItems(list);
  m_ui.encryptionKeySize->setCurrentIndex(0);
}

void spoton::slotAddInstitutionCheckBoxToggled(bool state)
{
  if(state)
    {
      m_ui.institutionName->clear();
      m_ui.institutionNameType->setCurrentIndex(0);
      m_ui.institutionPostalAddress->clear();
      m_ui.institutionPostalAddressType->setCurrentIndex(0);
    }
  else
    m_ui.addInstitutionLineEdit->clear();
}

void spoton::slotNewKeys(bool state)
{
  Q_UNUSED(state);
  m_ui.encryptionKeySize->setCurrentIndex(0);
  m_ui.encryptionKeyType->setCurrentIndex(2);
  m_ui.keys->setCurrentIndex(0);
  m_ui.signatureKeySize->setCurrentIndex(0);
  m_ui.signatureKeyType->setCurrentIndex(4);
}

void spoton::slotMagnetRadioToggled(bool state)
{
  if(state)
    {
      m_ui.etpCipherType->setCurrentIndex(0);
      m_ui.etpEncryptionKey->clear();
      m_ui.etpHashType->setCurrentIndex(0);
      m_ui.etpMacKey->clear();
    }
  else
    m_ui.etpMagnet->clear();
}

void spoton::slotPassphraseRadioToggled(bool state)
{
  if(state)
    {
      m_ui.answer->clear();
      m_ui.question->clear();
    }
  else
    {
      m_ui.passphrase1->clear();
      m_ui.passphrase2->clear();
    }
}

void spoton::slotPassphraseAuthenticateRadioToggled(bool state)
{
  if(state)
    {
      m_ui.answer_authenticate->clear();
      m_ui.question_authenticate->clear();
    }
  else
    m_ui.passphrase->clear();
}

void spoton::slotResendMail(void)
{
  if(!(m_ui.folder->currentIndex() == 1 ||
       m_ui.folder->currentIndex() == 2))
    return;

  QModelIndexList list
    (m_ui.mail->selectionModel()->
     selectedRows(m_ui.mail->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QString oid(list.takeFirst().data().toString());
	    bool ok = true;

	    query.prepare("UPDATE folders SET folder_index = 1, "
			  "status = ? WHERE "
			  "OID = ?");

	    if(m_crypts.value("email", 0))
	      query.bindValue
		(0, m_crypts.value("email")->
		 encryptedThenHashed(QByteArray("Queued"), &ok).
		 toBase64());
	    else
	      ok = false;

	    query.bindValue(1, oid);

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  slotRefreshMail();
}

QStringList spoton::parseAEMagnet(const QString &magnet) const
{
  QStringList list1(QString(magnet).remove("magnet:?").split("&"));
  QStringList list2;

  while(!list1.isEmpty())
    {
      QString str(list1.takeFirst());

      if(str.startsWith("ct="))
	{
	  str.remove(0, 3);
	  list2.append(str);
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);
	  list2.append(str);
	}
      else if(str.startsWith("to="))
	{
	  str.remove(0, 3);
	  list2.append(str);
	}
      else if(str.startsWith("xt="))
	{
	  str.remove(0, 3);
	  list2.append("urn:adaptive-echo");
	}
      else
	break;
    }

  if(!list2.contains("urn:adaptive-echo"))
    list2.clear();

  return list2;
}

void spoton::slotCopyAEMagnet(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  int row = -1;

  if(action->property("from") == "listeners")
    row = m_ui.ae_tokens->currentRow();
  else
    row = m_ui.neighbors->currentRow();

  if(row < 0)
    return;

  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  QString magnet("");
  QTableWidgetItem *item1 = 0;
  QTableWidgetItem *item2 = 0;
  QTableWidgetItem *item3 = 0;

  if(action->property("from") == "listeners")
    {
      item1 = m_ui.ae_tokens->item
	(row, 0); // Adaptive Echo Token
      item2 = m_ui.ae_tokens->item
	(row, 1); // Adaptive Echo Token Encryption Type
      item3 = m_ui.ae_tokens->item
	(row, 2); // Adaptive Echo Token Hash Type

      if(item1 && item2 && item3)
	magnet = QString("magnet:?"
			 "ct=%1&"
			 "ht=%2&"
			 "to=%3&"
			 "xt=urn:adaptive-echo").
	  arg(item2->text()).
	  arg(item3->text()).
	  arg(item1->text());
    }
  else
    {
      item1 = m_ui.neighbors->item
	(row, 32); // Adaptive Echo Token
      item2 = m_ui.neighbors->item
	(row, 33); // Adaptive Echo Token Type

      if(item1 && item2)
	magnet = QString("magnet:?"
			 "ct=%1&"
			 "ht=%2&"
			 "to=%3&"
			 "xt=urn:adaptive-echo").
	  arg(item2->text().split("\n").value(0).trimmed()).
	  arg(item2->text().split("\n").value(1)).
	  arg(item1->text());
    }

  clipboard->setText(magnet);
}

void spoton::slotClearClipboardBuffer(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->clear();
}

void spoton::slotAssignNewIPToNeighbor(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  int row = m_ui.neighbors->currentRow();

  if(row < 0)
    return;

  QString ip("");
  QString oid("");
  QString protocol("");
  QString proxyHostName("");
  QString proxyPort("");
  QString remoteIP("");
  QString remotePort("");
  QString scopeId("");
  QString transport("");

  for(int i = 0; i < m_ui.neighbors->columnCount(); i++)
    {
      QTableWidgetItem *item = m_ui.neighbors->item(row, i);

      if(!item)
	continue;

      if(i == 10)
	remoteIP = item->text();
      else if(i == 11)
	remotePort = item->text();
      else if(i == 12)
	scopeId = item->text();
      else if(i == 13)
	protocol = item->text();
      else if(i == 14)
	proxyHostName = item->text();
      else if(i == 15)
	proxyPort = item->text();
      else if(i == 27)
	transport = item->text();
      else if(i == m_ui.neighbors->columnCount() - 1)
	oid = item->text();
    }

  QDialog dialog(this);
  Ui_ipinformation ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Neighbor Remote IP Information").
     arg(SPOTON_APPLICATION_NAME));

  if(protocol == "IPv4")
    {
      ui.ip->setInputMask("000.000.000.000; ");
      ui.scope->setEnabled(false);
    }
  else if(protocol == "IPv6")
    ui.ip->setInputMask("hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh; ");

  ui.ip->setText(remoteIP);
  ui.port->setValue(remotePort.toInt());
  ui.scope->setText(scopeId);

  if(dialog.exec() == QDialog::Accepted)
    {
      if(protocol == "Dynamic DNS")
	ip = ui.ip->text().trimmed();
      else
	ip = QHostAddress(ui.ip->text().trimmed()).toString();

      if(ip.isEmpty())
	return;

      remotePort = QString::number(ui.port->value());
      scopeId = ui.scope->text();

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);
	QString country
	  (spoton_misc::countryNameFromIPAddress(ip));

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("UPDATE neighbors SET "
			  "country = ?, "
			  "hash = ?, "
			  "qt_country_hash = ?, "
			  "remote_ip_address = ?, "
			  "remote_ip_address_hash = ?, "
			  "remote_port = ?, "
			  "scope_id = ?, "
			  "status_control = 'disconnected' "
			  "WHERE OID = ? AND status_control <> 'deleted' AND "
			  "user_defined = 1");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(country.toLatin1(), &ok).
	       toBase64());

	    if(ok)
	      query.bindValue
		(1,
		 crypt->keyedHash((ip +
				   remotePort +
				   scopeId +
				   transport).toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(2, crypt->keyedHash(country.remove(" ").toLatin1(),
				     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->encryptedThenHashed(ip.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->keyedHash(ip.toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, crypt->encryptedThenHashed(remotePort.toLatin1(),
					       &ok).toBase64());

	    if(ok)
	      query.bindValue
		(6, crypt->encryptedThenHashed(scopeId.toLatin1(), &ok).
		 toBase64());

	    query.bindValue(7, oid);

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

QString spoton::currentTabName(void) const
{
  QString name("");
  int index = m_ui.tab->currentIndex();

#if SPOTON_GOLDBUG == 1
  if(index == 0)
    name = "chat";
  else if(index == 1)
    name = "email";
  else if(index == 2)
    name = "buzz";
  else if(index == 3)
    name = "starbeam";
  else if(index == 4)
    name = "addfriend";
  else if(index == 5)
    name = "neighbors";
  else if(index == 6)
    name = "listeners";
  else if(index == 7)
    name = "settings";
  else
    name = "about";
#else
  if(index == 0)
    name = "buzz";
  else if(index == 1)
    name = "chat";
  else if(index == 2)
    name = "email";
  else if(index == 3)
    name = "listeners";
  else if(index == 4)
    name = "neighbors";
  else if(index == 5)
    name = "search";
  else if(index == 6)
    name = "settings";
  else if(index == 7)
    name = "starbeam";
  else if(index == 8)
    name = "urls";
  else
    name = "about";
#endif

  return name;
}

void spoton::slotMosaicLocked(bool state)
{
  QCheckBox *check = qobject_cast<QCheckBox *> (sender());

  if(!check)
    return;

  QFile file(check->property("filename").toString());

  if(state)
    {
      QFile::Permissions g(file.permissions());
      QFile::Permissions s = 0;

      if(g & QFile::ExeOther)
	s |= QFile::ExeOther;

      if(g & QFile::WriteOther)
	s |= QFile::WriteOther;

      if(g & QFile::ReadOther)
	s |= QFile::ReadOther;

      if(g & QFile::ExeGroup)
	s |= QFile::ExeGroup;

      if(g & QFile::WriteGroup)
	s |= QFile::WriteGroup;

      if(g & QFile::ReadGroup)
	s |= QFile::ReadGroup;

      if(g & QFile::ExeUser)
	s |= QFile::ExeUser;

      if(g & QFile::ReadUser)
	s |= QFile::ReadUser;

      if(g & QFile::ExeOwner)
	s |= QFile::ExeOwner;

      if(g & QFile::ReadOwner)
	s |= QFile::ReadOwner;

      file.setPermissions(s);
    }
  else
    file.setPermissions(file.permissions() | QFile::WriteOwner);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("UPDATE received SET locked = ? WHERE OID = ?");
	query.bindValue(0, state);
	query.bindValue(1, check->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotUpdateSpinBoxChanged(double value)
{
  QDoubleSpinBox *doubleSpinBox = qobject_cast<QDoubleSpinBox *> (sender());
  QSettings settings;

  if(value < 0.50)
    value = 3.50;

  if(doubleSpinBox == m_optionsUi.chatUpdateInterval)
    {
      m_participantsUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/participantsUpdateTimer"] = value;
      settings.setValue("gui/participantsUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.kernelUpdateInterval)
    {
      m_kernelUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/kernelUpdateTimer"] = value;
      settings.setValue("gui/kernelUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.listenersUpdateInterval)
    {
      m_listenersUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/listenersUpdateTimer"] = value;
      settings.setValue("gui/listenersUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.neighborsUpdateInterval)
    {
      m_neighborsUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/neighborsUpdateTimer"] = value;
      settings.setValue("gui/neighborsUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.starbeamUpdateInterval)
    {
      m_starbeamUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/starbeamUpdateTimer"] = value;
      settings.setValue("gui/starbeamUpdateTimer", value);
    }
}

void spoton::prepareUrlContainers(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "urls_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, encryption_key, "
		      "hash_key, hash_type FROM "
		      "remote_key_information") && query.next())
	  {
	    QByteArray encryptionKey;
	    QByteArray hashKey;
	    QString cipherType("");
	    QString hashType("");
	    bool ok = true;

	    cipherType = crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()),
	       &ok).constData();

	    if(ok)
	      encryptionKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(1).toByteArray()),
		 &ok);

	    if(ok)
	      hashKey = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(2).toByteArray()),
		 &ok);

	    if(ok)
	      hashType = crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(3).toByteArray()),
		 &ok).constData();

	    if(ok)
	      {
		delete m_urlCommonCrypt;
		m_urlCommonCrypt = new spoton_crypt
		  (cipherType,
		   hashType,
		   QByteArray(),
		   encryptionKey,
		   hashKey,
		   0,
		   0,
		   QString(""));
	      }
	  }

	db.close();
      }
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotPostgreSQLDisconnect(bool state)
{
  m_ui.postgresqlConnect->setProperty("user_text", "connect");
  m_ui.postgresqlConnect->setText(tr("PostgreSQL Connect"));
  m_urlDatabase.close();
  m_urlDatabase = QSqlDatabase();

  if(QSqlDatabase::contains("URLDatabase"))
    QSqlDatabase::removeDatabase("URLDatabase");

  if(state)
    {
      m_urlDatabase = QSqlDatabase::addDatabase("QSQLITE", "URLDatabase");
      m_urlDatabase.setDatabaseName
	(spoton_misc::homePath() + QDir::separator() + "urls.db");
      m_urlDatabase.open();
    }

  m_settings["gui/sqliteSearch"] = state;

  QSettings settings;

  settings.setValue("gui/sqliteSearch", state);
}

void spoton::generateHalfGeminis(void)
{
  int row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item1 = m_ui.participants->item(row, 1); // OID
  QTableWidgetItem *item2 = m_ui.participants->item
    (row, 6); // Gemini Encryption Key
  QTableWidgetItem *item3 = m_ui.participants->item
    (row, 7); // Gemini Hash Key

  if(!item1 || !item2 || !item3)
    return;

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = spoton_crypt::
    strongRandomBytes(spoton_crypt::cipherKeyLength("aes256") / 2);
  gemini.second = spoton_crypt::strongRandomBytes
    (spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES / 2);

  if(saveGemini(gemini, item1->text()))
    {
      disconnect(m_ui.participants,
		 SIGNAL(itemChanged(QTableWidgetItem *)),
		 this,
		 SLOT(slotGeminiChanged(QTableWidgetItem *)));
      item2->setText(gemini.first.toBase64());
      item3->setText(gemini.second.toBase64());
      connect(m_ui.participants,
	      SIGNAL(itemChanged(QTableWidgetItem *)),
	      this,
	      SLOT(slotGeminiChanged(QTableWidgetItem *)));
    }
}

void spoton::slotSetListenerSSLControlString(void)
{
  QString oid("");
  QString sslCS("");
  QString transport("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 2); // SSL Control String

      if(item)
	sslCS = item->text();

      item = m_ui.listeners->item(row, 15); // Transport

      if(item)
	transport = item->text().toUpper();
    }

  if(oid.isEmpty())
    return;

  bool ok = true;

  if(transport != "TCP")
    sslCS = "N/A";

  sslCS = QInputDialog::getText
    (this, tr("%1: SSL Control String").arg(SPOTON_APPLICATION_NAME),
     tr("&SSL Control String"),
     QLineEdit::Normal, sslCS, &ok);

  if(!ok)
    return;

  if(sslCS.isEmpty())
    sslCS = m_ui.listenersSslControlString->text().trimmed();

  if(sslCS.isEmpty())
    sslCS = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

  if(transport != "TCP")
    sslCS = "N/A";

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE listeners SET ssl_control_string = ? "
		      "WHERE OID = ?");
	query.bindValue(0, sslCS);
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSetNeighborSSLControlString(void)
{
  QString oid("");
  QString sslCS("");
  QString transport("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.neighbors->item(row, 34); // SSL Control String

      if(item)
	sslCS = item->text();

      item = m_ui.neighbors->item(row, 27); // Transport

      if(item)
	transport = item->text().toUpper();
    }

  if(oid.isEmpty())
    return;

  bool ok = true;

  if(transport != "TCP")
    sslCS = "N/A";

  sslCS = QInputDialog::getText
    (this, tr("%1: SSL Control String").arg(SPOTON_APPLICATION_NAME),
     tr("&SSL Control String"),
     QLineEdit::Normal, sslCS, &ok);

  if(!ok)
    return;

  if(sslCS.isEmpty())
    sslCS = m_ui.neighborsSslControlString->text().trimmed();

  if(sslCS.isEmpty())
    sslCS = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

  if(transport != "TCP")
    sslCS = "N/A";

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET ssl_control_string = ? "
		      "WHERE OID = ? AND user_defined = 1");
	query.bindValue(0, sslCS);
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSharePoptasticPublicKey(void)
{
  if(!m_crypts.value("poptastic", 0) ||
     !m_crypts.value("poptastic-signature", 0))
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

  publicKey = m_crypts.value("poptastic")->publicKey(&ok);

  if(ok)
    signature = m_crypts.value("poptastic")->digitalSignature
      (publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value("poptastic-signature")->publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value("poptastic-signature")->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_poptasticSettingsUi.in_username->text().
		      trimmed().toUtf8());

      if(name.isEmpty())
	name = "unknown@unknown.org";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(QByteArray("poptastic").toBase64());
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
	  (QString("spoton::slotSharePoptasticPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }
}
