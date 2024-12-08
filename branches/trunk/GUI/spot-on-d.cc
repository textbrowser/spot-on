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

#include <QDataStream>

#include "spot-on-defines.h"
#include "spot-on.h"
#include "ui_spot-on-adaptive-echo-prompt.h"
#include "ui_spot-on-ipinformation.h"

static bool lengthGreaterThan(const QString &string1, const QString &string2)
{
  return string1.length() > string2.length();
}

QString spoton::currentTabName(void) const
{
  QMapIterator<int, QWidget *> it(m_tabWidgets);
  QString name("");

  while(it.hasNext())
    {
      it.next();

      if(it.value() == m_ui.tab->currentWidget())
	{
	  name = m_tabWidgetsProperties[it.key()].value("name").toString();
	  break;
	}
    }

  return name;
}

QString spoton::mapIconToEmoticon(const QString &content)
{
  QList<QString> list;
  QMap<QString, QString> map;
  auto str(content);

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
  std::sort(list.begin(), list.end(), lengthGreaterThan);

  for(int i = 0; i < list.size(); i++)
    str.replace(list.at(i), map[list.at(i)], Qt::CaseInsensitive);

  return str;
}

QStringList spoton::parseAEMagnet(const QString &magnet) const
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
  auto const list1
    (QString(magnet).remove("magnet:?").split('&', Qt::SkipEmptyParts));
#else
  auto const list1
    (QString(magnet).remove("magnet:?").split('&', QString::SkipEmptyParts));
#endif
  QStringList list2;

  for(int i = 0; i < list1.size(); i++)
    {
      auto str(list1.at(i).trimmed());

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

bool spoton::promptBeforeExit(void)
{
  if(m_encryptFile.occupied())
    {
      QMessageBox mb(this);

      mb.setIcon(QMessageBox::Question);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("The File Encryption application is occupied. "
		    "Are you sure that you wish to exit %1?").
		 arg(SPOTON_APPLICATION_NAME));
      mb.setWindowIcon(windowIcon());
      mb.setWindowModality(Qt::ApplicationModal);
      mb.setWindowTitle(tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

      if(mb.exec() != QMessageBox::Yes)
	{
	  QApplication::processEvents();
	  return true;
	}

      QApplication::processEvents();
    }

  if(!m_optionsUi.terminate_kernel_on_ui_exit->isChecked())
    if(m_ui.pid->text().toLongLong() > 0)
      {
	QMessageBox mb(this);

	mb.setIcon(QMessageBox::Question);
	mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	mb.setText(tr("The kernel appears to be active. Closing %1 "
		      "will not deactivate the kernel. Are you "
		      "sure that you wish to exit %1?").
		   arg(SPOTON_APPLICATION_NAME));
	mb.setWindowIcon(windowIcon());
	mb.setWindowModality(Qt::ApplicationModal);
	mb.setWindowTitle(tr("%1: Question").arg(SPOTON_APPLICATION_NAME));

	if(mb.exec() != QMessageBox::Yes)
	  {
	    QApplication::processEvents();
	    return true;
	  }

	QApplication::processEvents();
      }

  m_quit = true;
  return false;
}

void spoton::applyGoldBugToAttachments(const QString &folderOid,
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

  auto crypt2 = m_crypts.value("email", 0);

  if(!crypt2)
    {
      if(ok1)
	*ok1 = false;

      return;
    }

  *count = 0;

  QSqlQuery query(db);

  query.setForwardOnly(true);
  query.prepare("SELECT data, " // 0
		"OID "          // 1
		"FROM folders_attachment WHERE "
		"folders_oid = ?");
  query.bindValue(0, folderOid);

  if(query.exec())
    {
      if(query.next())
	{
	  auto attachmentData
	    (QByteArray::fromBase64(query.value(0).toByteArray()));
	  auto ok2 = true;

	  attachmentData = crypt2->decryptedAfterAuthenticated
	    (attachmentData, &ok2);

	  if(ok2)
	    attachmentData = crypt1->decryptedAfterAuthenticated
	      (attachmentData, &ok2);

	  if(ok2)
	    {
	      if(!attachmentData.isEmpty())
		attachmentData = qUncompress(attachmentData);

	      if(!attachmentData.isEmpty())
		{
		  QDataStream stream(&attachmentData, QIODevice::ReadOnly);
		  QList<QPair<QByteArray, QByteArray> > attachments;

		  stream >> attachments;

		  if(stream.status() != QDataStream::Ok)
		    {
		      if(ok1)
			*ok1 = false;

		      attachments.clear();
		    }

		  for(int i = 0; i < attachments.size(); i++)
		    {
		      auto const pair(attachments.at(i));
		      QSqlQuery query(db);

		      query.prepare("INSERT INTO folders_attachment "
				    "(data, folders_oid, name) "
				    "VALUES (?, ?, ?)");
		      query.bindValue
			(0, crypt2->encryptedThenHashed(pair.first,
							&ok2).
			 toBase64());
		      query.bindValue(1, folderOid);

		      if(ok2)
			query.bindValue
			  (2, crypt2->
			   encryptedThenHashed(pair.second,
					       &ok2).toBase64());

		      if(ok2)
			ok2 = query.exec();

		      if(ok2)
			*count += 1;
		      else
			{
			  if(ok1)
			    *ok1 = false;

			  break;
			}
		    }
		}
	    }
	}
    }
  else if(ok1)
    *ok1 = false;

  query.exec("PRAGMA secure_delete = ON");
  query.prepare("DELETE FROM folders_attachment WHERE OID = ?");
  query.bindValue(0, folderOid);

  if(!query.exec())
    {
      if(ok1)
	*ok1 = false;
    }
}

void spoton::generateHalfGeminis(void)
{
  auto const row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  auto item = m_ui.participants->item(row, 1); // OID

  if(!item)
    return;

  QPair<QByteArray, QByteArray> gemini;

  gemini.first = spoton_crypt::
    strongRandomBytes(spoton_crypt::
		      cipherKeyLength(spoton_crypt::
				      preferredCipherAlgorithm()) / 2);
  gemini.second = spoton_crypt::strongRandomBytes
    (spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES / 2);
  saveGemini(gemini, item->text());
}

void spoton::joinDefaultBuzzChannel(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Joining a default Buzz channel. "
			  "Please be patient."));
  m_sb.status->repaint();

  auto const index = m_ui.commonBuzzChannels->findData
    ("Spot-On_Developer_Channel_Key", Qt::UserRole, Qt::MatchContains);

  if(index >= 0)
    slotCommonBuzzChannelsActivated(index);

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
}

void spoton::populateAETokens(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

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
	m_ui.ae_tokens->setRowCount(0);

	QSqlQuery query(db);
	int row = 0;
	int totalRows = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM listeners_adaptive_echo_tokens"))
	  if(query.next())
	    m_ui.ae_tokens->setRowCount(query.value(0).toInt());

	query.prepare("SELECT token, " // 0
		      "token_type "    // 1
		      "FROM listeners_adaptive_echo_tokens");

	if(query.exec())
	  while(query.next() && totalRows < m_ui.ae_tokens->rowCount())
	    {
	      totalRows += 1;

	      QByteArray eType;
	      QByteArray hType;
	      QByteArray token;
	      QByteArray type;
	      auto ok = true;

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
		item = new QTableWidgetItem(QString(token));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem(row, 0, item);

	      if(ok)
		item = new QTableWidgetItem(QString(eType));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem(row, 1, item);

	      if(ok)
		item = new QTableWidgetItem(QString(hType));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags
		(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.ae_tokens->setItem(row, 2, item);

	      if(bytes1 == token && bytes2 == eType && bytes3 == hType)
		m_ui.ae_tokens->selectRow(row);

	      row += 1;
	    }

	m_ui.ae_tokens->setRowCount(totalRows);
	m_ui.ae_tokens->setSortingEnabled(true);
	m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::populateMOTD(const QString &listenerOid)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

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
	    m_ui.motd->setPlainText
	      (QString::fromUtf8(query.value(0).toByteArray().constData(),
				 query.value(0).toByteArray().length()).
	       trimmed());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::prepareUrlContainers(void)
{
  auto crypt = spoton_misc::retrieveUrlCommonCredentials
    (m_crypts.value("chat", 0));

  if(!crypt)
    return;

  delete m_urlCommonCrypt;
  m_urlCommonCrypt = crypt;
}

void spoton::refreshInstitutions(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	m_ui.institutions->setRowCount(0);
	m_ui.institutions->setSortingEnabled(false);

	QSqlQuery query(db);
	int row = 0;
	int totalRows = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM institutions"))
	  if(query.next())
	    m_ui.institutions->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT cipher_type, " // 0
		      "hash_type, "          // 1
		      "name, "               // 2
		      "postal_address "      // 3
		      "FROM institutions"))
	  while(query.next() && totalRows < m_ui.institutions->rowCount())
	    {
	      totalRows += 1;

	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      auto ok = true;

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
		item = new QTableWidgetItem(QString(name));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem(row, 0, item);

	      if(ok)
		item = new QTableWidgetItem(QString(cipherType));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem(row, 1, item);

	      if(ok)
		item = new QTableWidgetItem(QString(postalAddress));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem(row, 2, item);

	      if(ok)
		item = new QTableWidgetItem(QString(hashType));
	      else
		item = new QTableWidgetItem(tr("error"));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.institutions->setItem(row, 3, item);
	      row += 1;
	    }

	m_ui.institutions->setRowCount(totalRows);
	m_ui.institutions->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotAddAEToken(void)
{
  QString connectionName("");
  QString error("");
  QStringList list;
  auto crypt = m_crypts.value("chat", 0);
  auto ok = true;
  auto token(m_ui.ae_token->text());
  auto type
    (m_ui.ae_e_type->currentText() + "\n" + m_ui.ae_h_type->currentText());

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

  prepareDatabasesFromUI();

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

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
	  ok = query.exec();
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
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    {
      m_ui.ae_e_type->setCurrentIndex(0);
      m_ui.ae_h_type->setCurrentIndex(0);
      m_ui.ae_listeners_magnet->setChecked(false);
      m_ui.ae_token->clear();
      populateAETokens();
    }
}

void spoton::slotAddAttachment(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select Attachment").arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFiles);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      auto list(dialog.selectedFiles());

      std::sort(list.begin(), list.end());

      for(int i = 0; i < list.size(); i++)
	{
	  QFileInfo const fileInfo(list.at(i));

	  m_ui.attachment->append
	    (QString("<a href=\"%1 (%2)\">%1 (%2)</a>").
	     arg(fileInfo.absoluteFilePath()).
	     arg(spoton_misc::prettyFileSize(fileInfo.size())));
	}

      QApplication::restoreOverrideCursor();
    }

  QApplication::processEvents();
}

void spoton::slotAddInstitution(const QString &text)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
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
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	list = m_ui.addInstitutionLineEdit->text().
	  remove("magnet:?").split('&', Qt::SkipEmptyParts);
#else
        list = m_ui.addInstitutionLineEdit->text().
	  remove("magnet:?").split('&', QString::SkipEmptyParts);
#endif
      else
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	list = text.mid(0).remove("magnet:?").split('&', Qt::SkipEmptyParts);
#else
        list = text.mid(0).remove("magnet:?").split
	  ('&', QString::SkipEmptyParts);
#endif

      for(int i = 0; i < list.size(); i++)
	{
	  auto str(list.at(i));

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
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution name."));
      QApplication::processEvents();
      return;
    }

  if(postalAddress.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please provide an institution "
			       "postal address."));
      QApplication::processEvents();
      return;
    }

  prepareDatabasesFromUI();

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

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
	     encryptedThenHashed(postalAddressType.toLatin1(), &ok).toBase64());

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
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Unable to record the institution."));
      QApplication::processEvents();
    }
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

void spoton::slotAddMagnet(void)
{
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  prepareDatabasesFromUI();

  auto const type(action->property("type").toString().toLower());
  auto const url(action->property("url").toUrl());

  if(type == "buzz")
    {
      auto crypt = m_crypts.value("chat", 0);

      if(!crypt)
	{
	  QMessageBox::critical(this,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("Invalid spoton_crypt object. This is "
				   "a fatal flaw."));
	  QApplication::processEvents();
	  return;
	}

      QByteArray channel;
      QByteArray channelSalt;
      QByteArray channelType;
      QByteArray hashKey;
      QByteArray hashType;
      QByteArray iterationCount;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
      auto const list
	(url.toString().remove("magnet:?").split('&', Qt::SkipEmptyParts));
#else
      auto const list
	(url.toString().remove("magnet:?").split
	 ('&', QString::SkipEmptyParts));
#endif

      for(int i = 0; i < list.size(); i++)
	{
	  auto str(list.at(i).trimmed());

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
      QString error("");
      auto ok = true;

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "buzz_channels.db");

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

	    if(query.lastError().isValid())
	      error = query.lastError().text().trimmed();
	  }
	else
	  {
	    ok = false;

	    if(db.lastError().isValid())
	      error = db.lastError().text().trimmed();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(!ok)
	{
	  if(error.isEmpty())
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("An error occurred while attempting to "
				     "save the channel data. Please enable "
				     "logging via the Log Viewer and try "
				     "again."));
	  else
	    QMessageBox::critical
	      (this,
	       tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	       tr("An error (%1) occurred while attempting to "
		  "save the channel data.").arg(error));

	  QApplication::processEvents();
	}
      else
	slotPopulateBuzzFavorites();
    }
  else if(type == "institution")
    slotAddInstitution(url.toString());
  else if(type == "starbeam")
    slotAddEtpMagnet(url.toString());
}

void spoton::slotAssignNewIPToNeighbor(void)
{
  auto crypt = m_crypts.value("chat", 0);

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
      auto item = m_ui.neighbors->item(row, i);

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
  Ui_spoton_ipinformation ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Neighbor Remote IP Information").arg(SPOTON_APPLICATION_NAME));

  if(protocol == "IPv4" || protocol.isEmpty())
    {
      ui.ip->setInputMask("");
      ui.scope->setEnabled(false);
    }

  ui.ip->setText(remoteIP);
  ui.ip->setCursorPosition(0);
  ui.ip->selectAll();
  ui.port->setValue(remotePort.toInt());
  ui.scope->setText(scopeId);
  ui.scope->setCursorPosition(0);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      ip = ui.ip->text().trimmed();

      if(!ip.isEmpty())
	ip = spoton_misc::massageIpForUi(ip, protocol);

      remotePort = QString::number(ui.port->value());
      scopeId = ui.scope->text();

      QString connectionName("");

      {
	auto country(spoton_misc::countryNameFromIPAddress(ip));
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    auto ok = true;

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
		(1, crypt->
		 keyedHash((proxyHostName + proxyPort + ip + remotePort +
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

  QApplication::processEvents();
}

void spoton::slotAutoAddSharedSBMagnets(bool state)
{
  m_settings["gui/autoAddSharedSBMagnets"] = state;

  QSettings settings;

  settings.setValue("gui/autoAddSharedSBMagnets", state);
}

void spoton::slotChatPopup(void)
{
  auto const items(m_ui.participants->selectionModel()->selectedRows());

  if(!items.isEmpty() && items.at(0).isValid())
    slotParticipantDoubleClicked
      (m_ui.participants->item(items.at(0).row(), 0));
}

void spoton::slotClearClipboardBuffer(void)
{
  auto clipboard = QApplication::clipboard();

  if(clipboard)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      menuBar()->repaint();
      repaint();
      QApplication::processEvents();
      clipboard->clear();
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotCommonBuzzChannelsActivated(int index)
{
  repaint();
  QApplication::processEvents();
  m_ui.demagnetize->setText
    (m_ui.commonBuzzChannels->itemData(index).toString());
  m_ui.demagnetize->setCursorPosition(0);
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
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

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

void spoton::slotCopyAEMagnet(void)
{
  auto action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  int row = -1;

  if(action->property("from") == "listeners")
    row = m_ui.ae_tokens->currentRow();
  else
    row = m_ui.neighbors->currentRow();

  if(row < 0)
    return;

  auto clipboard = QApplication::clipboard();

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
	{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
	  auto const list(item2->text().split('\n', Qt::SkipEmptyParts));
#else
	  auto const list(item2->text().split('\n', QString::SkipEmptyParts));
#endif

	  magnet = QString("magnet:?"
			   "ct=%1&"
			   "ht=%2&"
			   "to=%3&"
			   "xt=urn:adaptive-echo").
	    arg(list.value(0).trimmed()).
	    arg(list.value(1)).
	    arg(item1->text());
	}
    }

  clipboard->setText(magnet);
}

void spoton::slotCopyInstitution(void)
{
  auto clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.institutions->currentRow()) >= 0)
    {
      auto item1 = m_ui.institutions->item(row, 0);
      auto item2 = m_ui.institutions->item(row, 1);
      auto item3 = m_ui.institutions->item(row, 2);
      auto item4 = m_ui.institutions->item(row, 3);

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

void spoton::slotDeleteAEToken(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  auto const list(m_ui.ae_tokens->selectedItems());

  if(list.size() != 3 || !list.at(0) || !list.at(1) || !list.at(2))
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Please select a token to delete."));
      QApplication::processEvents();
      return;
    }

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

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
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting "
			       "to delete the specified adaptive echo "
			       "token."));
      QApplication::processEvents();
    }
  else
    populateAETokens();
}

void spoton::slotDeleteInstitution(void)
{
  auto const list
    (m_ui.institutions->selectionModel()->selectedRows(0)); // Name

  if(list.isEmpty())
    return;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

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

void spoton::slotDisconnectAllNeighbors(void)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

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

void spoton::slotDisplayPopups(bool state)
{
  m_settings["gui/displayPopupsAutomatically"] = state;

  QSettings settings;

  settings.setValue("gui/displayPopupsAutomatically", state);
}

void spoton::slotEnableChatEmoticons(bool state)
{
  m_settings["gui/enableChatEmoticons"] = state;

  QSettings settings;

  settings.setValue("gui/enableChatEmoticons", state);
}

void spoton::slotEncryptionKeyTypeChanged(int index)
{
  QStringList list;

  if(index == 0)
    list << s_publicKeySizes["elgamal"];
  else if(index == 1)
    list << s_publicKeySizes["mceliece"];
  else if(index == 2)
    list << s_publicKeySizes["ntru"];
  else
    list << s_publicKeySizes["rsa"];

  m_ui.encryptionKeySize->clear();
  m_ui.encryptionKeySize->addItems(list);
  m_ui.encryptionKeySize->setCurrentIndex(0);

  /*
  ** Let's disable some values.
  */

  for(int i = 0; i < m_ui.encryptionKeySize->count(); i++)
    m_ui.encryptionKeySize->model()->setData
      (m_ui.encryptionKeySize->model()->index(i, 0),
       1 | 32,
       Qt::UserRole - 1);

  if(index == 1 && !spoton_crypt::hasShake())
    {
      QStringList list;

      list << "m11t51-fujisaki-okamoto-b" << "m12t68-fujisaki-okamoto-b";

      for(int i = 0; i < list.size(); i++)
	{
	  auto const index = s_publicKeySizes.value("mceliece").indexOf
	    (list.at(i));

	  if(index >= 0)
	    m_ui.encryptionKeySize->model()->setData
	      (m_ui.encryptionKeySize->model()->index(index, 0),
	       0,
	       Qt::UserRole - 1);
	}
    }
}

void spoton::slotLimitConnections(int value)
{
  m_settings["gui/limitConnections"] = value;

  QSettings settings;

  settings.setValue("gui/limitConnections", value);
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

void spoton::slotMessagesAnchorClicked(const QUrl &link)
{
  QString type("");

  if(spoton_misc::isValidBuzzMagnet(link.toString().toLatin1()))
    {
      type = "buzz";
      joinBuzzChannel(link);
      return;
    }
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

void spoton::slotNewKeys(bool state)
{
  Q_UNUSED(state);
  m_ui.encryptionKeySize->setCurrentIndex(0);
  m_ui.encryptionKeyType->setCurrentIndex(3);
  m_ui.keys->setCurrentIndex(0);
  m_ui.signatureKeySize->setCurrentIndex(0);
  m_ui.signatureKeyType->setCurrentIndex(4);
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

#if SPOTON_GOLDBUG == 1
  m_ui.answer_authenticate->setEnabled(!state);
  m_ui.passphrase->setEnabled(state);
  m_ui.question_authenticate->setEnabled(!state);
#endif
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

void spoton::slotPostgreSQLDisconnect(int index)
{
  m_pqUrlFaultyCounter.fetchAndStoreOrdered(0);
  m_ui.postgresqlConnect->setProperty("user_text", "connect");
  m_ui.postgresqlConnect->setText(tr("&PostgreSQL Connect..."));
  m_ui.url_database_connection_information->clear();
  m_urlDatabase.close();
  m_urlDatabase = QSqlDatabase();

  if(QSqlDatabase::contains("URLDatabase"))
    QSqlDatabase::removeDatabase("URLDatabase");

  if(index == 0)
    {
      m_ui.postgresqlConnect->setVisible(true);
      m_ui.postgresql_credentials->setVisible(true);
    }
  else
    {
      m_ui.postgresqlConnect->setVisible(false);
      m_ui.postgresql_credentials->setVisible(false);
      m_urlDatabase = QSqlDatabase::addDatabase("QSQLITE", "URLDatabase");
      m_urlDatabase.setDatabaseName
	(spoton_misc::homePath() + QDir::separator() + "urls.db");
      m_urlDatabase.open();

      if(m_urlDatabase.isOpen())
	m_ui.url_database_connection_information->setText
	  (QString("%1@%2/%3").arg("sqlite").arg("localhost").
	   arg("urls.db"));
    }

  m_settings["gui/sqliteSearch"] = index == 1;

  QSettings settings;

  settings.setValue("gui/sqliteSearch", index == 1);
}

void spoton::slotReceiversChanged(QTableWidgetItem *item)
{
  if(!item)
    return;

  if(!(item->column() == 0)) // Locked
    return;

  QFile file;

  if(m_ui.received->item(item->row(), 4)) // File
    file.setFileName(m_ui.received->item(item->row(), 4)->text());

  if(file.exists())
    {
      if(item->checkState() == Qt::Checked)
	{
	  auto const g(file.permissions());
	  auto s = QFile::Permissions();

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
	file.setPermissions(QFile::WriteOwner | file.permissions());
    }

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	QString oid("");

	if(m_ui.received->item(item->row(), m_ui.received->columnCount() - 1))
	  oid = m_ui.received->item
	    (item->row(), m_ui.received->columnCount() - 1)->text();

	if(item->column() == 0)
	  {
	    query.prepare("UPDATE received SET locked = ? WHERE OID = ?");
	    query.bindValue(0, item->checkState() == Qt::Checked ? 1 : 0);
	    query.bindValue(1, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotResendMail(void)
{
  if(!(m_ui.folder->currentIndex() == 1 ||
       m_ui.folder->currentIndex() == 2))
    return;

  auto const list
    (m_ui.mail->selectionModel()->
     selectedRows(m_ui.mail->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	for(int i = 0; i < list.size(); i++)
	  {
	    auto const oid(list.at(i).data().toString());
	    auto ok = true;

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
  QApplication::restoreOverrideCursor();
  slotRefreshMail();
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
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

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

void spoton::slotSaveAttachment(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
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

  QFileDialog dialog(this);

  dialog.setAcceptMode(QFileDialog::AcceptOpen);
  dialog.setDirectory(QDir::homePath());
  dialog.setFileMode(QFileDialog::Directory);
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setWindowTitle
    (tr("%1: Save Attachment(s)").arg(SPOTON_APPLICATION_NAME));

  if(dialog.exec() != QDialog::Accepted)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto ok = false;

  {
    QString connectionName("");

    {
      auto db = spoton_misc::database(connectionName);

      db.setDatabaseName
	(spoton_misc::homePath() + QDir::separator() + "email.db");

      if(db.open())
	{
	  QSqlQuery query(db);

	  query.setForwardOnly(true);
	  query.prepare("SELECT data, " // 0
			"name "         // 1
			"FROM folders_attachment "
			"WHERE folders_oid = ?");
	  query.bindValue(0, list.value(0).data().toString());

	  if(query.exec())
	    while(query.next())
	      {
		QByteArray attachment;
		QString attachmentName("");

		attachment = crypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).
					  toByteArray()),
		   &ok);

		if(ok)
		  {
		    auto const bytes
		      (crypt->
		       decryptedAfterAuthenticated(QByteArray::
						   fromBase64(query.value(1).
							      toByteArray()),
						   &ok));

		    if(ok)
		      attachmentName = QString::fromUtf8(bytes.constData(),
							 bytes.length());

		    if(attachmentName.trimmed().length() > 0 && ok)
		      {
			attachmentName.replace(" ", "-");

                        QFile file(dialog.selectedFiles().value(0) +
                                   QDir::separator() + attachmentName);

			if(file.open(QIODevice::WriteOnly))
			  file.write(attachment, attachment.length());

			file.close();
		      }
		  }

		if(!ok)
		  break;
	      }
	}

      db.close();
    }

    QSqlDatabase::removeDatabase(connectionName);
  }

  QApplication::restoreOverrideCursor();

  if(!ok)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting "
			       "to extract the attachment(s)."));
      QApplication::processEvents();
    }
}

void spoton::slotSaveBuzzAutoJoin(bool state)
{
  m_settings["gui/buzzAutoJoin"] = state;

  QSettings settings;

  settings.setValue("gui/buzzAutoJoin", state);
}

void spoton::slotSaveMOTD(void)
{
  QString connectionName("");
  QString error("");
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
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
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto str(m_ui.motd->toPlainText().trimmed());

	if(str.isEmpty())
	  str = QString("Welcome to %1.").arg(SPOTON_APPLICATION_NAME);

	query.prepare("UPDATE listeners SET motd = ? WHERE OID = ?");
	query.bindValue(0, str.toUtf8());
	query.bindValue(1, oid);

	if(!query.exec())
	  error = tr("Database error. Unable to save the message of the day.");
      }
    else
      error = tr("Unable to open listeners.db.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    {
      QMessageBox::critical
	(this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
      QApplication::processEvents();
    }
  else
    m_ui.motd->selectAll();
}

void spoton::slotSetAETokenInformation(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QModelIndexList list;
  QString oid("");

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid neighbor OID. "
			       "Please select a neighbor."));
      QApplication::processEvents();
      return;
    }
  else
    oid = list.at(0).data().toString();

  auto const etypes(spoton_crypt::cipherTypes());

  if(etypes.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("The method spoton_crypt::cipherTypes() has "
			       "failed. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  auto const htypes(spoton_crypt::hashTypes());

  if(htypes.isEmpty())
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("The method spoton_crypt::hashTypes() has "
			       "failed. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QDialog dialog(this);
  Ui_spoton_adaptiveechoprompt ui;

  ui.setupUi(&dialog);
  dialog.setWindowTitle
    (tr("%1: Adaptive Echo Information").arg(SPOTON_APPLICATION_NAME));
  ui.token_e_type->addItems(etypes);
  ui.token_h_type->addItems(htypes);

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();

      QStringList list;
      auto token(ui.token->text());
      auto tokenType(ui.token_e_type->currentText() + "\n" +
		     ui.token_h_type->currentText());

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
	  auto ok = true;

	  {
	    auto db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

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
		  ok = query.exec();
	      }
	    else
	      ok = false;

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);

	  if(!ok)
	    QMessageBox::critical(this,
				  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				  tr("An error occurred while attempting "
				     "to set an adaptive echo token."));
	}
      else
	QMessageBox::critical(this,
			      tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			      tr("The token must contain "
				 "at least ninety-six characters."));
    }

  QApplication::processEvents();
}

void spoton::slotSetListenerSSLControlString(void)
{
  QString oid("");
  QString sslCS("");
  QString transport("");
  int keySize = 0;
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      auto item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.listeners->item(row, 2); // SSL Key Size

      if(item)
	keySize = item->text().toInt();

      item = m_ui.listeners->item(row, 19); // SSL Control String

      if(item)
	sslCS = item->text();

      item = m_ui.listeners->item(row, 15); // Transport

      if(item)
	transport = item->text().toUpper();
    }

  if(keySize <= 0 || oid.isEmpty())
    return;

  if(transport == "TCP")
    goto continue_label;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  if(transport == "UDP")
    goto continue_label;
#endif

#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  if(transport == "WEBSOCKET")
    goto continue_label;
#endif

  return;

 continue_label:

  auto ok = true;

  sslCS = QInputDialog::getText
    (this,
     tr("%1: SSL Control String").arg(SPOTON_APPLICATION_NAME),
     tr("&SSL Control String"),
     QLineEdit::Normal,
     sslCS,
     &ok);

  if(!ok)
    return;

  if(sslCS.isEmpty())
    sslCS = m_ui.listenersSslControlString->text().trimmed();

  if(sslCS.isEmpty())
    sslCS = spoton_common::SSL_CONTROL_STRING;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

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
  int keySize = 0;
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.neighbors->item(row, 3); // SSL Key Size

      if(item)
	keySize = item->text().toInt();

      item = m_ui.neighbors->item(row, 34); // SSL Control String

      if(item)
	sslCS = item->text();

      item = m_ui.neighbors->item(row, 27); // Transport

      if(item)
	transport = item->text().toUpper();
    }

  if(keySize <= 0 || oid.isEmpty())
    return;

  if(transport == "TCP")
    goto continue_label;

#if (QT_VERSION >= QT_VERSION_CHECK(5, 12, 0)) && !defined(SPOTON_DTLS_DISABLED)
  if(transport == "UDP")
    goto continue_label;
#endif

#if QT_VERSION >= 0x050300 && defined(SPOTON_WEBSOCKETS_ENABLED)
  if(transport == "WEBSOCKET")
    goto continue_label;
#endif

  return;

 continue_label:

  auto ok = true;

  sslCS = QInputDialog::getText
    (this,
     tr("%1: SSL Control String").arg(SPOTON_APPLICATION_NAME),
     tr("&SSL Control String"),
     QLineEdit::Normal,
     sslCS,
     &ok);

  if(!ok)
    return;

  if(sslCS.isEmpty())
    sslCS = m_ui.neighborsSslControlString->text().trimmed();

  if(sslCS.isEmpty())
    sslCS = spoton_common::SSL_CONTROL_STRING;

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

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
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  if(m_ui.neighborsActionMenu->menu())
    m_ui.neighborsActionMenu->menu()->repaint();

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      auto item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      QApplication::restoreOverrideCursor();
      return;
    }

  QByteArray publicKey;
  QByteArray signature;
  auto ok = true;

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
      auto name(poptasticName());

      if(name.isEmpty())
	name = "unknown@unknown.org";

      message.append("sharepublickey_");
      message.append(oid.toUtf8());
      message.append("_");
      message.append(QByteArray("poptastic").toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(qCompress(signature).toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append("\n");

      if(!writeKernelSocketData(message))
	spoton_misc::logError
	  (QString("spoton::slotSharePoptasticPublicKey(): write() failure "
		   "for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotShowEncryptFile(void)
{
  m_encryptFile.show(this);
}

void spoton::slotShowMinimalDisplay(bool state)
{
#if SPOTON_GOLDBUG == 1
  foreach(auto object, m_ui.kernelBox->children())
    if(qobject_cast<QWidget *> (object))
      qobject_cast<QWidget *> (object)->setVisible(!state);

  m_optionsUi.saveCopy->setVisible(!state);
  m_ui.activateKernel->setVisible(true);
  m_ui.addException->setVisible(!state);
  m_ui.aeBox->setVisible(!state);
  m_ui.approvedIPs->setVisible(!state);
  m_ui.buildInformation->setVisible(!state);
  m_ui.buzzHashType->setVisible(!state);
  m_ui.buzzIterationCount->setVisible(!state);
  m_ui.buzzName->setVisible(!state);
  m_ui.channelType->setVisible(!state);
  m_ui.cipherType->setVisible(!state);
  m_ui.commonUrlCipher->setVisible(!state);
  m_ui.commonUrlHash->setVisible(!state);
  m_ui.commonUrlIterationCount->setVisible(!state);
  m_ui.days->setVisible(!state);
  m_ui.days_valid->setVisible(!state);
  m_ui.deactivateKernel->setVisible(true);
  m_ui.dynamicdns->setVisible(!state);
  m_ui.hashType->setVisible(!state);
  m_ui.ipv4Neighbor->setVisible(!state);
  m_ui.ipv6Neighbor->setVisible(!state);
  m_ui.iterationCount->setVisible(!state);
  m_ui.kernelPath->setVisible(true);
  m_ui.kernelPathLabel->setVisible(true);
  m_ui.label->setVisible(!state);
  m_ui.label_104->setVisible(!state);
  m_ui.label_117->setVisible(!state);
  m_ui.label_122->setVisible(!state);
  m_ui.label_138->setVisible(!state);
  m_ui.label_139->setVisible(!state);
  m_ui.label_14->setVisible(!state);
  m_ui.label_140->setVisible(!state);
  m_ui.label_15->setVisible(!state);
  m_ui.label_16->setVisible(!state);
  m_ui.label_21->setVisible(!state);
  m_ui.label_23->setVisible(!state);
  m_ui.label_27->setVisible(!state);
  m_ui.label_28->setVisible(!state);
  m_ui.label_32->setVisible(!state);
  m_ui.label_36->setVisible(!state);
  m_ui.label_39->setVisible(!state);
  m_ui.label_44->setVisible(!state);
  m_ui.label_54->setVisible(!state);
  m_ui.label_62->setVisible(!state);
  m_ui.label_64->setVisible(!state);
  m_ui.label_66->setVisible(!state);
  m_ui.label_70->setVisible(!state);
  m_ui.label_71->setVisible(!state);
  m_ui.label_78->setVisible(!state);
  m_ui.listenerOrientation->setVisible(!state);
  m_ui.listenersSslControlString->setVisible(!state);
  m_ui.motdBox->setVisible(!state);
  m_ui.neighborKeySize->setVisible(!state);
  m_ui.neighborOrientation->setVisible(!state);
  m_ui.neighborScopeId->setVisible(!state);
  m_ui.neighborScopeIdLabel->setVisible(!state);
  m_ui.neighborTransport->setVisible(!state);
  m_ui.neighborsEchoMode->setVisible(!state);
  m_ui.neighborsSslControlString->setVisible(!state);
  m_ui.neighborsSslControlString->setVisible(!state);
  m_ui.proxy->setVisible(!state);
  m_ui.publicKeysBox->setVisible(!state);
  m_ui.pulseSize->setVisible(!state);
  m_ui.requireSsl->setVisible(!state);
  m_ui.saltLength->setVisible(!state);
  m_ui.saveBuzzName->setVisible(!state);
  m_ui.searchfor->setVisible(!state);
  m_ui.selectKernelPath->setVisible(true);
  m_ui.shareBuzzMagnet->setVisible(!state);
  m_ui.sslKeySizeLabel->setVisible(!state);
  m_ui.urlDistributionModel->setVisible(!state);
#else
  m_settings["gui/minimal"] = state;
  m_ui.action_Listeners->setChecked(!state);
  m_ui.action_Neighbors->setChecked(!state);
  m_ui.action_Search->setChecked(!state);
  m_ui.action_Settings->setChecked(!state);
  m_ui.action_Urls->setChecked(!state);
  m_ui.buzz_details->setVisible(!state);
  m_ui.chat_frame->setVisible(!state);

  if(state)
    {
      if(m_ui.mailTab->count() == 2)
	{
	  m_careOfPage = m_ui.mailTab->widget(1);
	  m_careOfPageIcon = m_ui.mailTab->tabIcon(1);
	}

      m_ui.mailTab->removeTab(1);
    }
  else if(m_ui.mailTab->count() == 1)
    {
      m_ui.mailTab->addTab(m_careOfPage, tr("C/O"));
      m_ui.mailTab->setTabIcon(1, m_careOfPageIcon);
    }

  QSettings settings;

  settings.setValue("gui/minimal", state);
#endif
  m_sb.errorlog->setHidden(state);
  emit minimal(state);
}

void spoton::slotSignatureKeyTypeChanged(int index)
{
  QStringList list;

  if(index == 0)
    list << s_publicKeySizes["dsa"];
  else if(index == 1)
    list << s_publicKeySizes["ecdsa"];
  else if(index == 2)
    list << s_publicKeySizes["eddsa"];
  else if(index == 3)
    list << s_publicKeySizes["elgamal"];
  else
    list << s_publicKeySizes["rsa"];

  m_ui.signatureKeySize->clear();
  m_ui.signatureKeySize->addItems(list);
  m_ui.signatureKeySize->setCurrentIndex(0);
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
	QString status("");
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

	item = m_ui.participants->item(i, 4);

	if(item)
	  status = item->text();

	if(!oid.isEmpty())
	  {
	    if(!m_chatWindows.contains(oid))
	      m_chatWindows.remove(oid);

	    emit statusChanged(icon, name, oid, status);
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

void spoton::slotUpdateSpinBoxChanged(double value)
{
  auto doubleSpinBox = qobject_cast<QDoubleSpinBox *> (sender());

  if(!doubleSpinBox)
    return;

  if(value < 0.50)
    value = 3.50;

  if(doubleSpinBox == m_optionsUi.chatUpdateInterval)
    {
      QSettings settings;

      m_participantsUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/participantsUpdateTimer"] = value;
      settings.setValue("gui/participantsUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.kernelCacheInterval)
    {
      QSettings settings;

      if(value < 5.00)
	value = 15.00;

      m_settings["kernel/cachePurgeInterval"] = value;
      settings.setValue("kernel/cachePurgeInterval", value);
    }
  else if(doubleSpinBox == m_optionsUi.kernelUpdateInterval)
    {
      QSettings settings;

      m_kernelUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/kernelUpdateTimer"] = value;
      settings.setValue("gui/kernelUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.listenersUpdateInterval)
    {
      QSettings settings;

      m_listenersUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/listenersUpdateTimer"] = value;
      settings.setValue("gui/listenersUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.neighborsUpdateInterval)
    {
      QSettings settings;

      m_neighborsUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/neighborsUpdateTimer"] = value;
      settings.setValue("gui/neighborsUpdateTimer", value);
    }
  else if(doubleSpinBox == m_optionsUi.starbeamUpdateInterval)
    {
      QSettings settings;

      m_starbeamUpdateTimer.setInterval(static_cast<int> (1000 * value));
      m_settings["gui/starbeamUpdateTimer"] = value;
      settings.setValue("gui/starbeamUpdateTimer", value);
    }
}
