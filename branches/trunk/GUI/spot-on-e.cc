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

#ifdef SPOTON_POPTASTIC_SUPPORTED
extern "C"
{
#include <curl/curl.h>
}
#endif

#include <QApplication>
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#include <QAudioOutput>
#endif
#include <QCoreApplication>
#include <QSettings>

#include "spot-on-defines.h"
#include "spot-on-echo-key-share.h"
#include "spot-on-smp.h"
#include "spot-on-utilities.h"
#include "spot-on.h"
#include "ui_spot-on-keyboard.h"

QByteArray spoton::poptasticName(void) const
{
  return m_settings.value("gui/poptasticName").toByteArray();
}

QHash<QString, spoton_crypt *> spoton::crypts(void) const
{
  return m_crypts;
}

QStandardItemModel *spoton::starbeamReceivedModel(void) const
{
  return m_starbeamReceivedModel;
}

QString spoton::savePoptasticAccount(void)
{
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return "Invalid spoton_crypt object. This is a fatal flaw.";
  else if(m_poptasticRetroPhoneSettingsUi.in_username->text().
	  trimmed().isEmpty())
    return "Empty Incoming Server Username.";

  QString connectionName("");
  QString error("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);
	auto ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO poptastic "
	   "(in_authentication, "
	   "in_method, in_password, in_remove_remote, in_server_address, "
	   "in_server_port, in_ssltls, in_username, "
	   "in_username_hash, "
	   "in_verify_host, in_verify_peer, "
	   "out_authentication, "
	   "out_method, out_password, out_server_address, "
	   "out_server_port, out_ssltls, out_username, "
	   "out_verify_host, out_verify_peer, "
	   "proxy_enabled, "
	   "proxy_password, proxy_server_address, proxy_server_port, "
	   "proxy_type, proxy_username, smtp_localname) "
	   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
	   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.addBindValue
	  (m_poptasticRetroPhoneSettingsUi.in_authentication->
	   currentText());
	query.addBindValue
	  (crypt->
	   encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.in_method->
			       currentText().toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
					in_password->
					text().
					toUtf8(), &ok).toBase64());

	query.addBindValue(m_poptasticRetroPhoneSettingsUi.
			   in_remove_remote->isChecked() ? 1 : 0);

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 in_server_address->
				 text().trimmed().
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_server_port->
					value()), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.in_ssltls->
				 currentText().toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 in_username->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     keyedHash(m_poptasticRetroPhoneSettingsUi.
		       in_username->text().trimmed().toLatin1(),
		       &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_verify_host->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_verify_peer->isChecked() ?
					1 : 0), &ok).toBase64());

	query.addBindValue
	  (m_poptasticRetroPhoneSettingsUi.out_authentication->
	   currentText());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_method->currentText().toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_password->
				 text().
				 toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_server_address->
				 text().trimmed().
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_server_port->
					value()), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_ssltls->currentText().toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_username->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_verify_host->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_verify_peer->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					proxy->
					isChecked() ? 1 : 0),
				 &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_password->text().
				 toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_server_address->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					proxy_server_port->
					value()), &ok).toBase64());

	query.addBindValue(m_poptasticRetroPhoneSettingsUi.proxy_type->
			   currentText().toUpper());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_username->
				 text().trimmed().toUtf8(),
				 &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 smtp_localname->text().
				 toUtf8(), &ok).toBase64());

	if(ok)
	  {
	    if(!query.exec())
	      error = query.lastError().text();
	  }
	else
	  error = "An error occured with spoton_crypt.";
      }
    else
      error = "Unable to access poptastic.db.";

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  return error;
}

static QStringList curl_protocols(void)
{
  QStringList list;
#ifdef SPOTON_POPTASTIC_SUPPORTED
  auto data = curl_version_info(CURLVERSION_NOW);

  for(int i = 0; data->protocols[i] != 0; i++)
    list << QString(data->protocols[i]).toLower();
#endif
  return list;
}

void spoton::computeFileDigests(const QString &fileName,
				const QString &oid,
				spoton_crypt *crypt)
{
  if(fileName.trimmed().isEmpty())
    return;

  QFile file;

  file.setFileName(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      QString connectionName("");

      {
	auto db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

	if(db.open())
	  {
	    auto const hash1
	      (spoton_crypt::sha1FileHash(fileName,
					  m_starbeamDigestInterrupt));
	    auto const hash2
	      (spoton_crypt::sha3_512FileHash(fileName,
					      m_starbeamDigestInterrupt));

	    if(!m_starbeamDigestInterrupt.fetchAndAddOrdered(0))
	      spoton_misc::saveReceivedStarBeamHashes
		(db, hash1, hash2, oid, crypt);
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  file.close();
}

void spoton::initializeSMP(const QString &hash)
{
  if(hash.isEmpty())
    return;

  spoton_smp *smp = 0;

  if(m_smps.contains(hash))
    smp = m_smps.value(hash, 0);

  if(smp)
    smp->initialize();
  else
    spoton_misc::logError("spoton::initializeSMP(): smp is zero!");

  QPointer<spoton_chatwindow> chat = m_chatWindows.value(hash, 0);

  if(chat)
    chat->setSMPVerified(false);
}

void spoton::initializeUrlDistillers(void)
{
  spoton_misc::prepareUrlDistillersDatabase();

  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  prepareDatabasesFromUI();

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() +
       QDir::separator() +
       "urls_distillers_information.db");

    if(db.open())
      {
	QList<QList<QVariant> > list;
	QList<QVariant> tuple;

	tuple.append(QUrl::fromUserInput("ftp:"));
	tuple.append("download");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("gopher:"));
	tuple.append("download");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("http:"));
	tuple.append("download");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("https:"));
	tuple.append("download");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("ftp:"));
	tuple.append("shared");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("gopher:"));
	tuple.append("shared");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("http:"));
	tuple.append("shared");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("https:"));
	tuple.append("shared");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("ftp:"));
	tuple.append("upload");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("gopher:"));
	tuple.append("upload");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("http:"));
	tuple.append("upload");
	tuple.append("accept");
	list << tuple;
	tuple.clear();
	tuple.append(QUrl::fromUserInput("https:"));
	tuple.append("upload");
	tuple.append("accept");
	list << tuple;
	tuple.clear();

	for(int i = 0; i < list.size(); i++)
	  {
	    QSqlQuery query(db);
	    auto const direction(list.at(i).value(1).toByteArray());
	    auto const domain
	      (list.at(i).value(0).toUrl().scheme().toLatin1() + "://" +
	       list.at(i).value(0).toUrl().host().toUtf8() +
	       list.at(i).value(0).toUrl().path().toUtf8());
	    auto const permission(list.at(i).value(2).toByteArray());
	    auto ok = true;

	    query.prepare("INSERT INTO distillers "
			  "(direction, "
			  "direction_hash, "
			  "domain, "
			  "domain_hash, "
			  "permission) "
			  "VALUES "
			  "(?, ?, ?, ?, ?)");
	    query.bindValue
	      (0,
	       crypt->encryptedThenHashed(direction, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1,
		 crypt->keyedHash(direction, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2,
		 crypt->encryptedThenHashed(domain, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, crypt->keyedHash(domain, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4, crypt->encryptedThenHashed(permission, &ok).toBase64());

	    if(ok)
	      ok = query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::playSound(const QString &name)
{
  auto player = findChild<QMediaPlayer *> ();

  if(player)
    player->deleteLater();

  if(m_locked)
    return;

  if(!m_optionsUi.play_sounds->isChecked())
    return;

  QFileInfo fileInfo;
  auto const str
    (QDir::cleanPath(QCoreApplication::applicationDirPath() +
		     QDir::separator() +
		     "Sounds" +
		     QDir::separator() +
		     name));

  fileInfo.setFile(str);

  if(!fileInfo.isReadable() || fileInfo.size() < 8192)
    return;

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
  auto output = new QAudioOutput();

  output->setVolume(100);
  player = new QMediaPlayer(this);
  player->setAudioOutput(output);
  player->setSource(QUrl::fromLocalFile(str));
  connect(player,
	  SIGNAL(errorOccurred(QMediaPlayer::Error, const QString &)),
	  this,
	  SLOT(slotMediaError(QMediaPlayer::Error, const QString &)));
#else
  player = new QMediaPlayer(this, QMediaPlayer::LowLatency);
  connect(player,
	  SIGNAL(error(QMediaPlayer::Error)),
	  this,
	  SLOT(slotMediaError(QMediaPlayer::Error)));
  player->setMedia(QUrl::fromLocalFile(str));
  player->setVolume(100);
#endif
  connect(player,
	  SIGNAL(mediaStatusChanged(QMediaPlayer::MediaStatus)),
	  this,
	  SLOT(slotMediaStatusChanged(QMediaPlayer::MediaStatus)));
  player->play();
}

void spoton::populatePoptasticWidgets(const QHash<QString, QVariant> &hash)
{
  if(hash.isEmpty())
    return;

  int index = -1;

  index = m_poptasticRetroPhoneSettingsUi.in_method->findText
    (hash.value("in_method").toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.in_password->setText
    (hash.value("in_password").toString());
  m_poptasticRetroPhoneSettingsUi.in_password->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.in_password->setToolTip
    (m_poptasticRetroPhoneSettingsUi.in_password->text());
  m_poptasticRetroPhoneSettingsUi.in_remove_remote->setChecked
    (hash.value("in_remove_remote").toBool());
  m_poptasticRetroPhoneSettingsUi.in_server_address->setText
    (hash.value("in_server_address").toString());
  m_poptasticRetroPhoneSettingsUi.in_server_address->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue
    (hash.value("in_server_port").toInt());
  index = m_poptasticRetroPhoneSettingsUi.in_ssltls->findText
    (hash.value("in_ssltls").toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.in_username->setText
    (hash.value("in_username").toString());
  m_poptasticRetroPhoneSettingsUi.in_username->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked
    (hash.value("in_verify_host").toBool());
  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked
    (hash.value("in_verify_peer").toBool());
  index = m_poptasticRetroPhoneSettingsUi.out_method->findText
    (hash.value("out_method").toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);

  m_poptasticRetroPhoneSettingsUi.out_password->setText
    (hash.value("out_password").toString());
  m_poptasticRetroPhoneSettingsUi.out_password->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.out_password->setToolTip
    (m_poptasticRetroPhoneSettingsUi.out_password->text());
  m_poptasticRetroPhoneSettingsUi.out_server_address->setText
    (hash.value("out_server_address").toString());
  m_poptasticRetroPhoneSettingsUi.out_server_address->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue
    (hash.value("out_server_port").toInt());
  index = m_poptasticRetroPhoneSettingsUi.out_ssltls->findText
    (hash.value("out_ssltls").toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.out_username->setText
    (hash.value("out_username").toString());
  m_poptasticRetroPhoneSettingsUi.out_username->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.out_verify_host->setChecked
    (hash.value("out_verify_host").toBool());
  m_poptasticRetroPhoneSettingsUi.out_verify_peer->setChecked
    (hash.value("out_verify_peer").toBool());
  m_poptasticRetroPhoneSettingsUi.proxy->setChecked
    (hash.value("proxy_enabled").toBool());
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible
    (hash.value("proxy_enabled").toBool());
  m_poptasticRetroPhoneSettingsUi.proxy_password->setText
    (hash.value("proxy_password").toString());
  m_poptasticRetroPhoneSettingsUi.proxy_password->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->setText
    (hash.value("proxy_server_address").toString());
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue
    (hash.value("proxy_server_port").toInt());

  if(hash.value("proxy_type").toString().toUpper() == "SOCKS5")
    m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(1);
  else
    m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);

  m_poptasticRetroPhoneSettingsUi.proxy_username->setText
    (hash.value("proxy_username").toString());
  m_poptasticRetroPhoneSettingsUi.proxy_username->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.smtp_localname->setText
    (hash.value("smtp_localname", "localhost").toString());
  m_poptasticRetroPhoneSettingsUi.smtp_localname->setCursorPosition(0);
}

void spoton::prepareSMP(const QString &hash)
{
  if(hash.isEmpty())
    return;

  spoton_smp *smp = 0;

  if(m_smps.contains(hash))
    smp = m_smps.value(hash, 0);

  QString guess("");
  spoton_virtual_keyboard dialog(QApplication::activeWindow());

  if(smp)
    {
      dialog.m_ui.passphrase->setText(smp->guessString());
      dialog.m_ui.passphrase->setCursorPosition(0);
    }

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      guess = dialog.m_ui.passphrase->text();
    }
  else
    {
      QApplication::processEvents();
      return;
    }

  if(!smp)
    {
      smp = new spoton_smp(this);
      m_smps[hash] = smp;
    }

  if(smp)
    smp->setGuess(guess);
  else
    spoton_misc::logError("spoton::prepareSMP(): smp is zero!");

  QPointer<spoton_chatwindow> chat = m_chatWindows.value(hash, 0);

  if(chat)
    chat->setSMPVerified(false);
}

void spoton::sendSMPLinkToKernel(const QList<QByteArray> &list,
				 const QString &keyType,
				 const QString &oid)
{
  if(keyType.isEmpty())
    return;
  else if(list.isEmpty())
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;
  else if(oid.isEmpty())
    return;

  QString magnet("magnet:?");

  for(int i = 0; i < list.size(); i++)
    magnet.append
      (QString("value=%2&").arg(list.at(i).toBase64().constData()));

  magnet.append("xt=urn:smp");

  QByteArray message;
  QByteArray name;

  if(keyType.toLower() == "chat")
    message.append("message_");
  else
    message.append("poptasticmessage_");

  message.append(QString("%1_").arg(oid).toUtf8());

  if(keyType.toLower() == "chat")
    name = m_settings.value("gui/nodeName", "unknown").toByteArray();
  else
    name = m_settings.value("gui/poptasticName",
			    "unknown@unknown.org").toByteArray();

  if(name.isEmpty())
    {
      if(keyType.toLower() == "chat")
	name = "unknown";
      else
	name = "unknown@unknown.org";
    }

  message.append(name.toBase64());
  message.append("_");
  message.append(magnet.toLatin1().toBase64());
  message.append("_");
  message.append(QByteArray("1").toBase64()); // Artificial sequence number.
  message.append("_");
  message.append(QDateTime::currentDateTimeUtc().
		 toString("MMddyyyyhhmmss").toLatin1().toBase64());
  message.append("_");
  message.append(QByteArray::number(selectedHumanProxyOID()));
  message.append("\n");

  if(!writeKernelSocketData(message))
    spoton_misc::logError
      (QString("spoton::sendSMPLinkToKernel(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::setSBField(const QString &oid,
			const QVariant &value,
			const QString &field)
{
  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  (QString("UPDATE transmitted SET %1 = ? "
		   "WHERE OID = ? AND status_control <> 'deleted'").
	   arg(field));
	query.bindValue(0, value);
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::showError(const QString &error)
{
  if(error.trimmed().isEmpty())
    return;

  QMessageBox::critical
    (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error.trimmed());
  QApplication::processEvents();
}

void spoton::slotAcceptGeminis(bool state)
{
  m_settings["gui/acceptGeminis"] = state;

  QSettings settings;

  settings.setValue("gui/acceptGeminis", state);
}

void spoton::slotActiveUrlDistribution(bool state)
{
  m_settings["gui/activeUrlDistribution"] = state;

  QSettings settings;

  settings.setValue("gui/activeUrlDistribution", state);
}

void spoton::slotConfigurePoptastic(void)
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

  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
  m_poptasticRetroPhoneSettingsUi.account->clear();
  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);
  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
  m_poptasticRetroPhoneSettingsUi.email_primary_account->clear();

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
  if(m_poptasticRetroPhoneSettingsUi.poptastic_label->
     pixmap(Qt::ReturnByValue).isNull())
#else
  if(!m_poptasticRetroPhoneSettingsUi.poptastic_label->pixmap() ||
     m_poptasticRetroPhoneSettingsUi.poptastic_label->pixmap()->isNull())
#endif
    {
      QPixmap pixmap;

      if(pixmap.load(":/Logo/poptastic.png"))
	{
	  pixmap = pixmap.scaled(QSize(256, 256),
				 Qt::IgnoreAspectRatio,
				 Qt::SmoothTransformation);

	  if(pixmap.isNull())
	    m_poptasticRetroPhoneSettingsUi.poptastic_label->setVisible(false);
	  else
	    m_poptasticRetroPhoneSettingsUi.poptastic_label->setPixmap(pixmap);
	}
      else
	m_poptasticRetroPhoneSettingsUi.poptastic_label->setVisible(false);
    }

  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(false);

  QList<QHash<QString, QVariant> > list;
  auto ok = true;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  list = spoton_misc::poptasticSettings("", crypt, &ok);
  QApplication::restoreOverrideCursor();

  if(!ok)
    {
      m_poptasticRetroPhoneDialog->show();
      QMessageBox::critical(m_poptasticRetroPhoneDialog, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("A failure occurred with "
			       "spoton_misc::poptasticSettings()."));
      QApplication::processEvents();
    }
  else
    {
      m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);

      for(int i = 0; i < list.size(); i++)
	{
	  m_poptasticRetroPhoneSettingsUi.account->addItem
	    (list.at(i).value("in_username").toString());
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
	    (list.at(i).value("in_username").toString());
	  m_poptasticRetroPhoneSettingsUi.email_primary_account->addItem
	    (list.at(i).value("in_username").toString());
	}

      m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

      auto index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	findText(m_settings.value("gui/poptasticName").toByteArray());

      if(index >= 0)
	m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	  setCurrentIndex(index);
      else
	m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	  setCurrentIndex(0);

      index = m_poptasticRetroPhoneSettingsUi.email_primary_account->
	findText(m_settings.value("gui/poptasticNameEmail").toByteArray());

      if(index >= 0)
	m_poptasticRetroPhoneSettingsUi.email_primary_account->
	  setCurrentIndex(index);
      else
	m_poptasticRetroPhoneSettingsUi.email_primary_account->
	  setCurrentIndex(0);
    }

  auto const protocols(curl_protocols());

  connect(m_poptasticRetroPhoneSettingsUi.account,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotPoptasticAccountChanged(int)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.
	  buttonBox->button(QDialogButtonBox::Reset),
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPoptasticSettingsReset(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.delete_account,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeletePoptasticAccount(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.proxy,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotPoptasticSettingsReset(bool)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.save_account,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSavePoptasticAccount(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.selectcapath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectCAPath(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.testpop3,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticPop3Settings(void)),
	  Qt::UniqueConnection);
  connect(m_poptasticRetroPhoneSettingsUi.testsmtp,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestPoptasticSmtpSettings(void)),
	  Qt::UniqueConnection);
  m_poptasticRetroPhoneDialog->setWindowTitle
    (tr("%1: Poptastic & RetroPhone Settings").arg(SPOTON_APPLICATION_NAME));
  m_poptasticRetroPhoneSettingsUi.capath->setText
    (m_settings.value("gui/poptasticCAPath", "").toString());
  m_poptasticRetroPhoneSettingsUi.capath->setCursorPosition(0);
  m_poptasticRetroPhoneSettingsUi.number_of_messages->setValue
    (m_settings.value("gui/poptasticNumberOfMessages", 15).toInt());
  m_poptasticRetroPhoneSettingsUi.poptasticRefresh->setValue
    (m_settings.value("gui/poptasticRefreshInterval", 5.00).toDouble());
  m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.in_remove_remote->setChecked(true);
  m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.out_verify_host->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.out_verify_peer->setChecked(false);

  if(!protocols.contains("pop3s"))
    {
      m_poptasticRetroPhoneSettingsUi.in_ssltls->clear();
      m_poptasticRetroPhoneSettingsUi.in_ssltls->addItem("None");
    }

  if(!protocols.contains("smtps"))
    {
      m_poptasticRetroPhoneSettingsUi.out_ssltls->clear();
      m_poptasticRetroPhoneSettingsUi.out_ssltls->addItem("None");
    }

  if(!(protocols.contains("pop3") ||
       protocols.contains("pop3s")))
    {
      m_poptasticRetroPhoneSettingsUi.testpop3->setEnabled(false);
      m_poptasticRetroPhoneSettingsUi.testpop3->setToolTip
	(tr("Your version of libcURL does not support POP3."));
    }

  if(!(protocols.contains("smtp") ||
       protocols.contains("smtps")))
    {
      m_poptasticRetroPhoneSettingsUi.testsmtp->setEnabled(false);
      m_poptasticRetroPhoneSettingsUi.testsmtp->setToolTip
	(tr("Your version of libcURL does not support SMTP."));
    }

  populatePoptasticWidgets(list.value(0));

  if(m_poptasticRetroPhoneDialog->exec() == QDialog::Accepted)
    {
      QApplication::processEvents();
      prepareDatabasesFromUI();

      QString error("");

      if(ok)
	error = savePoptasticAccount();
      else
	error = "An error occurred with spoton_crypt.";

      if(!error.isEmpty())
	{
	  m_poptasticRetroPhoneDialog->show();
	  QMessageBox::critical(this,
				tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
				tr("An error (%1) occurred while "
				   "attempting to save the Poptastic "
				   "information.").arg(error));
	  QApplication::processEvents();
	  return;
	}

      QSettings settings;

      m_settings["gui/poptasticCAPath"] =
	m_poptasticRetroPhoneSettingsUi.capath->text();
      m_settings["gui/poptasticNumberOfMessages"] =
	m_poptasticRetroPhoneSettingsUi.number_of_messages->value();
      m_settings["gui/poptasticRefreshInterval"] =
	m_poptasticRetroPhoneSettingsUi.poptasticRefresh->value();
      settings.setValue
	("gui/poptasticCAPath",
	 m_poptasticRetroPhoneSettingsUi.capath->text());
      settings.setValue
	("gui/poptasticNumberOfMessages",
	 m_poptasticRetroPhoneSettingsUi.number_of_messages->value());
      settings.setValue
	("gui/poptasticRefreshInterval",
	 m_poptasticRetroPhoneSettingsUi.poptasticRefresh->value());
      updatePoptasticNameSettingsFromWidgets(crypt);
      slotReloadEmailNames();
    }

  QApplication::processEvents();
  m_poptasticRetroPhoneSettingsUi.in_password->clear();
  m_poptasticRetroPhoneSettingsUi.in_password->setToolTip("");
  m_poptasticRetroPhoneSettingsUi.in_remove_remote->setChecked(true);
  m_poptasticRetroPhoneSettingsUi.in_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue(995);
  m_poptasticRetroPhoneSettingsUi.out_password->clear();
  m_poptasticRetroPhoneSettingsUi.out_password->setToolTip("");
  m_poptasticRetroPhoneSettingsUi.out_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue(587);
  m_poptasticRetroPhoneSettingsUi.out_username->clear();
  m_poptasticRetroPhoneSettingsUi.proxy->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(false);
  m_poptasticRetroPhoneSettingsUi.proxy_password->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.proxy_username->clear();
}

void spoton::slotDeletePoptasticAccount(void)
{
  if(m_poptasticRetroPhoneSettingsUi.account->currentText().trimmed().isEmpty())
    return;

  QMessageBox mb(m_poptasticRetroPhoneDialog);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to delete the specified "
		"Poptastic account?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(m_poptasticRetroPhoneDialog,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      QApplication::processEvents();
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  auto ok = true;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM poptastic WHERE in_username_hash = ?");
	query.bindValue
	  (0, crypt->keyedHash(m_poptasticRetroPhoneSettingsUi.
			       account->currentText().toLatin1(), &ok).
	   toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();

  if(ok)
    {
      QList<QHash<QString, QVariant> > list;
      auto ok = true;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      list = spoton_misc::poptasticSettings("", crypt, &ok);
      QApplication::restoreOverrideCursor();

      if(ok)
	{
	  populatePoptasticWidgets(list.value(0));
	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
	  m_poptasticRetroPhoneSettingsUi.account->clear();
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
	  m_poptasticRetroPhoneSettingsUi.email_primary_account->clear();

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_poptasticRetroPhoneSettingsUi.account->addItem
		(list.at(i).value("in_username").toString());
	      m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
		(list.at(i).value("in_username").toString());
	      m_poptasticRetroPhoneSettingsUi.email_primary_account->addItem
		(list.at(i).value("in_username").toString());
	    }

	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

	  int index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	    findText(m_settings.value("gui/poptasticName").toByteArray());

	  if(index >= 0)
	    m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	      setCurrentIndex(index);
	  else
	    {
	      m_poptasticRetroPhoneSettingsUi.chat_primary_account->
		setCurrentIndex(0);
	      m_settings["gui/poptasticName"] =
		m_poptasticRetroPhoneSettingsUi.
		chat_primary_account->currentText().toLatin1();

	      QSettings settings;

	      settings.setValue
		("gui/poptasticName",
		 crypt->encryptedThenHashed(m_settings.
					    value("gui/poptasticName").
					    toByteArray(), &ok).toBase64());
	    }

	  index = m_poptasticRetroPhoneSettingsUi.email_primary_account->
	    findText(m_settings.value("gui/poptasticNameEmail").toByteArray());

	  if(index >= 0)
	    m_poptasticRetroPhoneSettingsUi.email_primary_account->
	      setCurrentIndex(index);
	  else
	    {
	      m_poptasticRetroPhoneSettingsUi.email_primary_account->
		setCurrentIndex(0);
	      m_settings["gui/poptasticNameEmail"] =
		m_poptasticRetroPhoneSettingsUi.
		email_primary_account->currentText().toLatin1();

	      QSettings settings;

	      settings.setValue
		("gui/poptasticNameEmail",
		 crypt->
		 encryptedThenHashed(m_settings.
				     value("gui/poptasticNameEmail").
				     toByteArray(), &ok).toBase64());
	    }
	}

      if(list.isEmpty())
	{
	  m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(0);
	  m_poptasticRetroPhoneSettingsUi.in_password->clear();
	  m_poptasticRetroPhoneSettingsUi.in_password->setToolTip("");
	  m_poptasticRetroPhoneSettingsUi.in_remove_remote->setChecked(true);
	  m_poptasticRetroPhoneSettingsUi.in_server_address->clear();
	  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue(995);
	  m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(2);
	  m_poptasticRetroPhoneSettingsUi.in_username->clear();
	  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked(false);
	  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked(false);
	  m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);
	  m_poptasticRetroPhoneSettingsUi.out_password->clear();
	  m_poptasticRetroPhoneSettingsUi.out_password->setToolTip("");
	  m_poptasticRetroPhoneSettingsUi.out_server_address->clear();
	  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue(587);
	  m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(2);
	  m_poptasticRetroPhoneSettingsUi.out_username->clear();
	  m_poptasticRetroPhoneSettingsUi.out_verify_host->setChecked(false);
	  m_poptasticRetroPhoneSettingsUi.out_verify_peer->setChecked(false);
	}

      slotReloadEmailNames();
    }
}

void spoton::slotDeriveGeminiPairViaSMP(const QString &publicKeyHash,
					const QString &oid)
{
  auto const list(findItems(m_ui.participants, oid, 1));

  if(list.isEmpty())
    return;

  auto item = list.at(0);

  if(!item)
    return;
  else if(item->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!

  auto smp = m_smps.value(publicKeyHash, 0);

  if(!smp)
    return;

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QPair<QByteArray, QByteArray> gemini;
  QString error("");

  gemini = spoton_crypt::derivedKeys
    (spoton_crypt::preferredCipherAlgorithm(),
     spoton_crypt::preferredHashAlgorithm(),
     spoton_common::GEMINI_ITERATION_COUNT,
     smp->guessWhirlpool().toHex(),
     smp->guessSha(),
     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
     false,
     error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    return;

  saveGemini(gemini, oid);
}

void spoton::slotDeriveGeminiPairViaSMP(void)
{
  auto const row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  auto item1 = m_ui.participants->item(row, 1); // OID
  auto item2 = m_ui.participants->item(row, 3); // public_key_hash

  if(!item1 || !item2)
    return;
  else if(item1->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!

  auto smp = m_smps.value(item2->text(), 0);

  if(!smp)
    return;

  repaint();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QPair<QByteArray, QByteArray> gemini;
  QString error("");

  gemini = spoton_crypt::derivedKeys
    (spoton_crypt::preferredCipherAlgorithm(),
     spoton_crypt::preferredHashAlgorithm(),
     spoton_common::GEMINI_ITERATION_COUNT,
     smp->guessWhirlpool().toHex(),
     smp->guessSha(),
     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
     false,
     error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    return;

  saveGemini(gemini, item1->text());
}

void spoton::slotInitializeSMP(const QString &hash)
{
  /*
  ** Chat windows only please!
  */

  initializeSMP(hash);
}

void spoton::slotInitializeSMP(void)
{
  QString hash("");
  auto temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      auto item = m_ui.participants->item(row, 1); // OID

      if(item)
	temporary = item->data(Qt::UserRole).toBool();

      item = m_ui.participants->item(row, 3); // public_key_hash

      if(item)
	hash = item->text();
    }

  if(hash.isEmpty())
    return;
  else if(temporary) // Temporary friend?
    return; // Not allowed!

  initializeSMP(hash);
}

void spoton::slotLaunchKernelAfterAuthentication(bool state)
{
  m_settings["gui/launchKernelAfterAuth"] = state;

  QSettings settings;

  settings.setValue("gui/launchKernelAfterAuth", state);
}

void spoton::slotMediaError(QMediaPlayer::Error error)
{
  auto player = qobject_cast<QMediaPlayer *> (sender());

  if(!player)
    return;

  if(error != QMediaPlayer::NoError)
    player->deleteLater();
}

void spoton::slotMediaError(QMediaPlayer::Error error,
			    const QString &errorString)
{
  Q_UNUSED(errorString);

  auto player = qobject_cast<QMediaPlayer *> (sender());

  if(!player)
    return;

  if(error != QMediaPlayer::NoError)
    player->deleteLater();
}

void spoton::slotMediaStatusChanged(QMediaPlayer::MediaStatus status)
{
  auto player = qobject_cast<QMediaPlayer *> (sender());

  if(!player)
    return;

  if(status == QMediaPlayer::EndOfMedia)
    player->deleteLater();
}

void spoton::slotOntopChatDialogs(bool state)
{
  m_settings["gui/ontopChatDialogs"] = state;

  QSettings settings;

  settings.setValue("gui/ontopChatDialogs", state);
}

void spoton::slotPoptasticAccountChanged(int index)
{
  QList<QHash<QString, QVariant> > list;
  auto const text(m_poptasticRetroPhoneSettingsUi.account->itemText(index));
  auto ok = true;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  list = spoton_misc::poptasticSettings(text, m_crypts.value("chat", 0), &ok);
  QApplication::restoreOverrideCursor();

  if(ok)
    populatePoptasticWidgets(list.value(0));
}

void spoton::slotPoptasticSettingsReset(bool state)
{
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(state);
  m_poptasticRetroPhoneSettingsUi.proxy_password->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.proxy_username->clear();
}

void spoton::slotPoptasticSettingsReset(void)
{
  QMessageBox mb(m_poptasticRetroPhoneDialog);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to reset your Poptastic "
		"settings?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::ApplicationModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();
  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
  m_poptasticRetroPhoneSettingsUi.account->clear();
  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);
  m_poptasticRetroPhoneSettingsUi.capath->clear();
  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
  m_poptasticRetroPhoneSettingsUi.email_primary_account->clear();
  m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.in_password->clear();
  m_poptasticRetroPhoneSettingsUi.in_password->setToolTip("");
  m_poptasticRetroPhoneSettingsUi.in_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue(995);
  m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(2);
  m_poptasticRetroPhoneSettingsUi.in_username->clear();
  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.number_of_messages->setValue
    (m_poptasticRetroPhoneSettingsUi.number_of_messages->minimum());
  m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.out_password->clear();
  m_poptasticRetroPhoneSettingsUi.out_password->setToolTip("");
  m_poptasticRetroPhoneSettingsUi.out_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue(587);
  m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(2);
  m_poptasticRetroPhoneSettingsUi.out_username->clear();
  m_poptasticRetroPhoneSettingsUi.out_verify_host->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.out_verify_peer->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.poptasticRefresh->setValue(5.00);
  m_poptasticRetroPhoneSettingsUi.proxy->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(false);
  m_poptasticRetroPhoneSettingsUi.proxy_password->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.proxy_username->clear();
  m_poptasticRetroPhoneSettingsUi.smtp_localname->setText("localhost");
  m_poptasticRetroPhoneSettingsUi.smtp_localname->setCursorPosition(0);
  m_settings["gui/poptasticCAPath"] = "";
  m_settings["gui/poptasticName"] = "";
  m_settings["gui/poptasticNameEmail"] = "";
  m_settings["gui/poptasticNumberOfMessages"] =
    m_poptasticRetroPhoneSettingsUi.number_of_messages->value();
  m_settings["gui/poptasticRefreshInterval"] = 5.00;

  QSettings settings;

  settings.remove("gui/poptasticCAPath");
  settings.remove("gui/poptasticName");
  settings.remove("gui/poptasticNameEmail");
  settings.remove("gui/poptasticNumberOfMessages");
  settings.remove("gui/poptasticRefreshInterval");
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.exec("DELETE FROM poptastic");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotPrepareSMP(const QString &hash)
{
  /*
  ** Chat windows only please!
  */

  prepareSMP(hash);
}

void spoton::slotPrepareSMP(void)
{
  QString hash("");
  auto temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      auto item = m_ui.participants->item(row, 1); // OID

      if(item)
	temporary = item->data(Qt::UserRole).toBool();

      item = m_ui.participants->item(row, 3); // public_key_hash

      if(item)
	hash = item->text();
    }

  if(hash.isEmpty())
    return;
  else if(temporary) // Temporary friend?
    return; // Not allowed!

  prepareSMP(hash);
}

void spoton::slotReloadEmailNames(void)
{
  m_ui.emailName->clear();
  m_ui.emailName->addItem
    (QString::fromUtf8(m_settings.value("gui/emailName", "unknown").
		       toByteArray().constData(),
		       m_settings.value("gui/emailName", "unknown").
		       toByteArray().length()).trimmed());
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const list
    (spoton_misc::poptasticSettings("", m_crypts.value("chat", 0), 0));

  for(int i = 0; i < list.size(); i++)
    {
      if(i == 0)
	m_ui.emailName->insertSeparator(1);

      m_ui.emailName->addItem(list.at(i).value("in_username").toString());
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotRemoveOtmOnExit(bool state)
{
  m_settings["gui/removeOtmOnExit"] = state;

  QSettings settings;

  settings.setValue("gui/removeOtmOnExit", state);
}

void spoton::slotSaveAlternatingColors(bool state)
{
  auto checkBox = qobject_cast<QCheckBox *> (sender());

  if(!checkBox)
    return;

  QString str("");

  if(checkBox == m_optionsUi.chatAlternatingRowColors)
    {
      m_ui.participants->setAlternatingRowColors(state);
      str = "gui/chatAlternatingRowColors";
    }
  else if(checkBox == m_optionsUi.emailAlternatingRowColors)
    {
      m_ui.emailParticipants->setAlternatingRowColors(state);
      str = "gui/emailAlternatingRowColors";
    }
  else if(checkBox == m_optionsUi.urlsAlternatingRowColors)
    {
      m_ui.urlParticipants->setAlternatingRowColors(state);
      str = "gui/urlsAlternatingRowColors";
    }

  if(!str.isEmpty())
    {
      m_settings[str] = state;

      QSettings settings;

      settings.setValue(str, state);
      emit updateEmailWindows();
    }
}

void spoton::slotSaveCustomStatus(void)
{
  auto const text
    (m_ui.custom->toPlainText().
     mid(0, spoton_common::STATUS_TEXT_MAXIMUM_LENGTH));

  m_settings["gui/customStatus"] = text.trimmed().toUtf8();

  QSettings settings;

  settings.setValue("gui/customStatus", text.trimmed().toUtf8());
}

void spoton::slotSaveOpenLinks(bool state)
{
  m_settings["gui/openLinks"] = state;

  QSettings settings;

  settings.setValue("gui/openLinks", state);
}

void spoton::slotSavePoptasticAccount(void)
{
  prepareDatabasesFromUI();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  auto const error(savePoptasticAccount());

  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    {
      QMessageBox::critical(m_poptasticRetroPhoneDialog,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error (%1) occurred while "
			       "attempting to save the Poptastic "
			       "information.").arg(error));
      QApplication::processEvents();
    }
  else
    {
      QList<QHash<QString, QVariant> > list;
      auto ok = true;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      list = spoton_misc::poptasticSettings("", m_crypts.value("chat", 0), &ok);
      QApplication::restoreOverrideCursor();

      if(ok)
	{
	  auto const account
	    (m_poptasticRetroPhoneSettingsUi.account->currentText());
	  auto const initial = m_poptasticRetroPhoneSettingsUi.
	    account->count() == 0;

	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
	  m_poptasticRetroPhoneSettingsUi.account->clear();
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
	  m_poptasticRetroPhoneSettingsUi.email_primary_account->clear();
	  m_poptasticRetroPhoneSettingsUi.in_password->setToolTip
	    (m_poptasticRetroPhoneSettingsUi.in_password->text());
	  m_poptasticRetroPhoneSettingsUi.out_password->setToolTip
	    (m_poptasticRetroPhoneSettingsUi.out_password->text());

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_poptasticRetroPhoneSettingsUi.account->addItem
		(list.at(i)["in_username"].toString());
	      m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
		(list.at(i)["in_username"].toString());
	      m_poptasticRetroPhoneSettingsUi.email_primary_account->addItem
		(list.at(i)["in_username"].toString());
	    }

	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

	  int index = -1;

	  if((index = m_poptasticRetroPhoneSettingsUi.account->
	      findText(account)) >= 0)
	    m_poptasticRetroPhoneSettingsUi.account->setCurrentIndex(index);
	  else
	    m_poptasticRetroPhoneSettingsUi.account->setCurrentIndex(0);

	  index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	    findText(m_settings["gui/poptasticName"].toByteArray());

	  if(index >= 0)
	    m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	      setCurrentIndex(index);
	  else
	    m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	      setCurrentIndex(0);

	  index = m_poptasticRetroPhoneSettingsUi.email_primary_account->
	    findText(m_settings["gui/poptasticNameEmail"].toByteArray());

	  if(index >= 0)
	    m_poptasticRetroPhoneSettingsUi.email_primary_account->
	      setCurrentIndex(index);
	  else
	    m_poptasticRetroPhoneSettingsUi.email_primary_account->
	      setCurrentIndex(0);

	  if(initial)
	    updatePoptasticNameSettingsFromWidgets(m_crypts.value("chat", 0));

	  slotReloadEmailNames();
	}
    }
}

void spoton::slotSaveRefreshEmail(bool state)
{
  m_settings["gui/refreshEmail"] = state;

  QSettings settings;

  settings.setValue("gui/refreshEmail", state);
}

void spoton::slotSaveSharePrivateKeys(bool state)
{
  m_settings["gui/sharePrivateKeysWithKernel"] = state;

  QSettings settings;

  settings.setValue("gui/sharePrivateKeysWithKernel", state);

  if(state)
    if(m_keysShared.value("keys_sent_to_kernel") == "ignore")
      m_keysShared["keys_sent_to_kernel"] = "false";
}

void spoton::slotSaveStarBeamAutoVerify(bool state)
{
  m_settings["gui/starbeamAutoVerify"] = state;

  QSettings settings;

  settings.setValue("gui/starbeamAutoVerify", state);
}

void spoton::slotSaveUrlDistribution(int index)
{
  Q_UNUSED(index);

  QString str("linear");

  m_settings["gui/urlDistribution"] = str;

  QSettings settings;

  settings.setValue("gui/urlDistribution", str);
}

void spoton::slotSearchResultsPerPage(int value)
{
  m_settings["gui/searchResultsPerPage"] = value;

  QSettings settings;

  settings.setValue("gui/searchResultsPerPage", value);
}

void spoton::slotSelectCAPath(void)
{
  QString fileName("");

  if(m_poptasticRetroPhoneSettingsUi.selectcapath == sender())
    {
      QFileDialog dialog(m_poptasticRetroPhoneDialog);

      dialog.setWindowTitle
	(tr("%1: Select CA File").arg(SPOTON_APPLICATION_NAME));
      dialog.setFileMode(QFileDialog::ExistingFile);
      dialog.setDirectory(QDir::homePath());
      dialog.setLabelText(QFileDialog::Accept, tr("Select"));
      dialog.setAcceptMode(QFileDialog::AcceptOpen);

      if(dialog.exec() == QDialog::Accepted)
	{
	  QApplication::processEvents();
	  fileName = dialog.selectedFiles().value(0);
	  m_poptasticRetroPhoneSettingsUi.capath->setText
	    (dialog.selectedFiles().value(0));
	  m_poptasticRetroPhoneSettingsUi.capath->setCursorPosition(0);
	}

      QApplication::processEvents();
    }
  else
    fileName = m_poptasticRetroPhoneSettingsUi.capath->text();
}

void spoton::slotSetIconSize(int index)
{
  QSettings settings;
  QSize size;

  if(index == 0)
    size = QSize(16, 16);
  else if(index == 1)
    size = QSize(24, 24);
  else if(index == 2)
    size = QSize(32, 32);
  else
    size = QSize(64, 64);

  m_settings["gui/tabIconSize"] = size;
  m_ui.tab->setIconSize(size);
  settings.setValue("gui/tabIconSize", size);
}

void spoton::slotSetNeighborPriority(void)
{
  auto action = qobject_cast<QAction *> (sender());
  auto priority = QThread::HighPriority;

  if(!action)
    return;
  else
    priority = QThread::Priority(action->property("priority").toInt());

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

  QString connectionName("");

  if(priority < 0 || priority > 7)
    priority = QThread::HighPriority;

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "priority = ? "
		      "WHERE OID = ?");
	query.bindValue(0, priority);
	query.bindValue(1, list.at(0).data());
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSetSBPulseSize(void)
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

  QString oid("");
  int integer = 15000;
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      auto item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.transmitted->item(row, 2); // Pulse Size

      if(item)
	integer = item->text().toInt();
    }

  if(oid.isEmpty())
    return;

  auto ok = true;

  integer = QInputDialog::getInt
    (this,
     tr("%1: StarBeam Pulse Size").arg(SPOTON_APPLICATION_NAME),
     tr("&Pulse Size"),
     integer,
     spoton_common::MINIMUM_STARBEAM_PULSE_SIZE,
     static_cast<int> (spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE),
     1,
     &ok);

  if(!ok)
    return;

  auto const bytes
    (crypt->encryptedThenHashed(QByteArray::number(integer), &ok).toBase64());

  if(ok)
    setSBField(oid, bytes, "pulse_size");
  else
    {
      QMessageBox::critical(this,
			    tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			    tr("An error occurred while attempting to "
			       "secure the pulse size."));
      QApplication::processEvents();
    }
}

void spoton::slotSetSBReadInterval(void)
{
  QString oid("");
  double rational = 1.500;
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      auto item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.transmitted->item(row, 8); // Read Interval

      if(item)
	rational = item->text().toDouble();
    }

  if(oid.isEmpty())
    return;

  auto ok = true;

  rational = QInputDialog::getDouble
    (this,
     tr("%1: StarBeam Read Interval").arg(SPOTON_APPLICATION_NAME),
     tr("&Read Interval"),
     rational,
     0.025,
     60.000,
     3,
     &ok);

  if(!ok)
    return;

  setSBField(oid, rational, "read_interval");
}

void spoton::slotShareKeysWithKernel(const QString &link)
{
  Q_UNUSED(link);
  m_keysShared["keys_sent_to_kernel"] = "false";
}

void spoton::slotShareStarBeam(void)
{
  auto const row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  auto item1 = m_ui.participants->item(row, 0); // Participant
  auto item2 = m_ui.participants->item(row, 1); // OID
  auto item3 = m_ui.participants->item(row, 3); // Public Key Hash

  if(!item1 || !item2 || !item3)
    return;
  else if(item2->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!
  else if(item2->data(Qt::ItemDataRole(Qt::UserRole + 1)).
	  toString() == "poptastic")
    return;

  QString error("");
  auto crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      showError(error);
      return;
    }

  /*
  ** Some of this logic is redundant. Please see sendMessage().
  */

  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      showError(error);
      return;
    }
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    {
      error = tr("The connection to the kernel is not encrypted.");
      showError(error);
      return;
    }

  auto const list(m_ui.participants->selectionModel()->selectedRows(1)); // OID

  if(list.isEmpty())
    {
      error = tr
	("Please select at least one participant for StarBeam sharing.");
      showError(error);
      return;
    }

  auto const participant(item1->text());
  auto const publicKeyHash(item3->text());

  /*
  ** Select a file.
  */

  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select StarBeam Transmit File").arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);

  if(dialog.exec() != QDialog::Accepted)
    {
      QApplication::processEvents();
      return;
    }

  QApplication::processEvents();

  QFileInfo const fileInfo(dialog.selectedFiles().value(0));

  if(!fileInfo.exists() || !fileInfo.isReadable())
    {
      error = tr("The selected file is not readable.");
      showError(error);
      return;
    }

  /*
  ** Create a StarBeam magnet.
  */

  QByteArray magnet;
  auto const eKey
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::
		       cipherKeyLength(spoton_crypt::
				       preferredCipherAlgorithm())).
     toBase64());
  auto const mKey
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
     toBase64());
  auto ok = true;

  magnet.append("magnet:?");
  magnet.append("ct=");
  magnet.append(spoton_crypt::preferredCipherAlgorithm());
  magnet.append("&");
  magnet.append("ek=");
  magnet.append(eKey);
  magnet.append("&");
  magnet.append("ht=");
  magnet.append(spoton_crypt::preferredHashAlgorithm());
  magnet.append("&");
  magnet.append("mk=");
  magnet.append(mKey);
  magnet.append("&");
  magnet.append("xt=urn:starbeam");
  m_ui.message->setText(magnet);
  sendMessage(&ok);

  if(!ok)
    return;

  prepareDatabasesFromUI();

  QString connectionName("");

  /*
  ** Create a StarBeam database entry.
  */

  {
    auto db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QByteArray encryptedMosaic;
	QSqlQuery query(db);
	auto const mosaic
	  (spoton_crypt::strongRandomBytes(spoton_common::MOSAIC_SIZE).
	   toBase64());

	query.prepare("INSERT OR REPLACE INTO magnets "
		      "(magnet, magnet_hash, origin) "
		      "VALUES (?, ?, ?)");
	query.addBindValue(crypt->encryptedThenHashed(magnet, &ok).toBase64());

	if(ok)
	  query.addBindValue(crypt->keyedHash(magnet, &ok).toBase64());

	if(ok)
	  {
	    QString origin;

	    origin = QString("%1 (%2)").arg(participant).arg(publicKeyHash);
	    query.addBindValue
	      (crypt->encryptedThenHashed(origin.toUtf8(), &ok).toBase64());
	  }

	if(ok)
	  ok = query.exec();

	query.prepare("INSERT INTO transmitted "
		      "(file, hash, mosaic, nova, "
		      "position, pulse_size, read_interval, sha3_512_hash, "
		      "status_control, total_size, ultra) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->
	   encryptedThenHashed(fileInfo.absoluteFilePath().toUtf8(),
			       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed(spoton_crypt::
				 sha1FileHash(fileInfo.absoluteFilePath()).
				 toHex(), &ok).toBase64());

	if(ok)
	  {
	    encryptedMosaic = crypt->encryptedThenHashed(mosaic, &ok);

	    if(ok)
	      query.bindValue(2, encryptedMosaic.toBase64());
	  }

	if(ok)
	  query.bindValue
	    (3, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->encryptedThenHashed("0", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->
	     encryptedThenHashed(QByteArray::number(spoton_common::
						    ELEGANT_STARBEAM_SIZE),
				 &ok).toBase64());

	query.bindValue(6, 2.500);

	if(ok)
	  query.bindValue
	    (7,
	     crypt->
	     encryptedThenHashed(spoton_crypt::
				 sha3_512FileHash(fileInfo.absoluteFilePath()).
				 toHex(), &ok).toBase64());

	query.bindValue(8, "transmitting");

	if(ok)
	  query.bindValue
	    (9, crypt->
	     encryptedThenHashed(QByteArray::number(fileInfo.size()),
				 &ok).toBase64());

	query.bindValue(10, 1);

	if(ok)
	  ok = query.exec();

	query.prepare("INSERT INTO transmitted_magnets "
		      "(magnet, magnet_hash, transmitted_oid) "
		      "VALUES (?, ?, (SELECT OID FROM transmitted WHERE "
		      "mosaic = ?))");

	if(ok)
	  query.bindValue
	    (0, crypt->encryptedThenHashed(magnet, &ok).toBase64());

	if(ok)
	  query.bindValue(1, crypt->keyedHash(magnet, &ok).toBase64());

	if(ok)
	  query.bindValue(2, encryptedMosaic.toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotShowOptions(void)
{
  spoton_utilities::centerWidget(m_optionsWindow, this);
  m_optionsWindow->showNormal();
  m_optionsWindow->activateWindow();
  m_optionsWindow->raise();
  m_optionsUi.scrollArea->setFocus();
}

void spoton::slotTestPoptasticPop3Settings(void)
{
#ifdef SPOTON_POPTASTIC_SUPPORTED
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  QString error("");
  auto ok = false;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  curl = curl_easy_init();

  if(curl)
    {
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 m_poptasticRetroPhoneSettingsUi.in_password->text().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticRetroPhoneSettingsUi.in_username->
	 text().trimmed().toLatin1().
	 constData());

      if(m_poptasticRetroPhoneSettingsUi.proxy->isChecked())
	{
	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = m_poptasticRetroPhoneSettingsUi.proxy_server_address->
	    text().trimmed();
	  port = QString::number(m_poptasticRetroPhoneSettingsUi.
				 proxy_server_port->value());

	  if(m_poptasticRetroPhoneSettingsUi.proxy_type->
	     currentText() == "HTTP")
	    scheme = "http";
	  else
	    scheme = "socks5";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt(curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   m_poptasticRetroPhoneSettingsUi.proxy_password->
			   text().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   m_poptasticRetroPhoneSettingsUi.proxy_username->
			   text().
			   trimmed().toLatin1().constData());
	}

      QString url("");
      auto const index = m_poptasticRetroPhoneSettingsUi.
	in_ssltls->currentIndex();
      auto const method
	(m_poptasticRetroPhoneSettingsUi.in_method->currentText().toUpper());

      if(index == 1 || index == 2)
	{
	  if(method == "IMAP")
	    url = QString("imaps://%1:%2/").
	      arg(m_poptasticRetroPhoneSettingsUi.
		  in_server_address->text().trimmed()).
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_port->value());
	  else if(method == "POP3")
	    url = QString("pop3s://%1:%2/").
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_address->
		  text().trimmed()).
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_port->value());

	  auto verify = static_cast<long int>
	    (m_poptasticRetroPhoneSettingsUi.in_verify_host->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long int>
	    (m_poptasticRetroPhoneSettingsUi.in_verify_peer->isChecked());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    {
	      QFileInfo const fileInfo
		(m_settings.value("gui/poptasticCAPath", "").toString());

	      if(fileInfo.isReadable())
		curl_easy_setopt
		  (curl,
		   CURLOPT_CAINFO,
		   fileInfo.absoluteFilePath().toUtf8().constData());

	      curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	    }
	}
      else
	{
	  if(method == "IMAP")
	    url = QString("imap://%1:%2/").
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_address->
		  text().trimmed()).
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_port->value());
	  else if(method == "POP3")
	    url = QString("pop3://%1:%2/").
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_address->
		  text().trimmed()).
	      arg(m_poptasticRetroPhoneSettingsUi.in_server_port->value());
	}

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;
      else
	error = curl_easy_strerror(res);

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information
      (m_poptasticRetroPhoneDialog,
       tr("%1: Poptastic Incoming Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Test successful!"));
  else
    QMessageBox::critical
      (m_poptasticRetroPhoneDialog,
       tr("%1: Poptastic Incoming Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Failure!\nError: %1.").arg(error));

  QApplication::processEvents();
#endif
}

void spoton::slotTestPoptasticSmtpSettings(void)
{
#ifdef SPOTON_POPTASTIC_SUPPORTED
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  QString error("");
  auto ok = false;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  curl = curl_easy_init();

  if(curl)
    {
      curl_easy_setopt
	(curl, CURLOPT_PASSWORD,
	 m_poptasticRetroPhoneSettingsUi.out_password->text().toLatin1().
	 constData());
      curl_easy_setopt
	(curl, CURLOPT_USERNAME,
	 m_poptasticRetroPhoneSettingsUi.out_username->text().
	 trimmed().toLatin1().
	 constData());

      if(m_poptasticRetroPhoneSettingsUi.proxy->isChecked())
	{
	  QString address("");
	  QString port("");
	  QString scheme("");
	  QString url("");

	  address = m_poptasticRetroPhoneSettingsUi.proxy_server_address->
	    text().trimmed();
	  port = QString::number(m_poptasticRetroPhoneSettingsUi.
				 proxy_server_port->value());

	  if(m_poptasticRetroPhoneSettingsUi.proxy_type->
	     currentText() == "HTTP")
	    scheme = "http";
	  else
	    scheme = "socks5";

	  url = QString("%1://%2:%3").arg(scheme).arg(address).arg(port);
	  curl_easy_setopt(curl, CURLOPT_PROXY, url.toLatin1().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD,
			   m_poptasticRetroPhoneSettingsUi.
			   proxy_password->text().
			   toUtf8().constData());
	  curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME,
			   m_poptasticRetroPhoneSettingsUi.
			   proxy_username->text().
			   trimmed().toLatin1().constData());
	}

      QString url("");
      auto const index = m_poptasticRetroPhoneSettingsUi.
	out_ssltls->currentIndex();
      auto const method
	(m_poptasticRetroPhoneSettingsUi.out_method->currentText().toUpper());

      if(index == 1 || index == 2)
	{
	  if(method == "SMTP")
	    {
	      if(index == 1) // SSL
		url = QString("smtps://%1:%2/%3").
		  arg(m_poptasticRetroPhoneSettingsUi.
		      out_server_address->text().
		      trimmed()).
		  arg(m_poptasticRetroPhoneSettingsUi.
		      out_server_port->value()).
		  arg(m_poptasticRetroPhoneSettingsUi.
		      smtp_localname->text());
	      else // TLS
		url = QString("smtp://%1:%2/%3").
		  arg(m_poptasticRetroPhoneSettingsUi.
		      out_server_address->text().
		      trimmed()).
		  arg(m_poptasticRetroPhoneSettingsUi.
		      out_server_port->value()).
		  arg(m_poptasticRetroPhoneSettingsUi.
		      smtp_localname->text());
	    }

	  auto verify = static_cast<long int>
	    (m_poptasticRetroPhoneSettingsUi.out_verify_host->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long int>
	    (m_poptasticRetroPhoneSettingsUi.out_verify_peer->isChecked());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    {
	      QFileInfo const fileInfo
		(m_settings.value("gui/poptasticCAPath", "").toString());

	      if(fileInfo.isReadable())
		curl_easy_setopt
		  (curl, CURLOPT_CAINFO,
		   fileInfo.absoluteFilePath().toUtf8().constData());

	      curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
	    }
	}
      else
	{
	  if(method == "SMTP")
	    url = QString("smtp://%1:%2/%3").
	      arg(m_poptasticRetroPhoneSettingsUi.out_server_address->
		  text().trimmed()).
	      arg(m_poptasticRetroPhoneSettingsUi.out_server_port->value()).
	      arg(m_poptasticRetroPhoneSettingsUi.smtp_localname->text());
	}

      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
      curl_easy_setopt(curl, CURLOPT_URL, url.toLatin1().constData());
      res = curl_easy_perform(curl);

      if(res == CURLE_OK)
	ok = true;
      else
	error = curl_easy_strerror(res);

      curl_easy_cleanup(curl);
    }

  QApplication::restoreOverrideCursor();

  if(ok)
    QMessageBox::information
      (m_poptasticRetroPhoneDialog,
       tr("%1: Poptastic Outgoing Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Test successful!"));
  else
    QMessageBox::critical
      (m_poptasticRetroPhoneDialog,
       tr("%1: Poptastic Outgoing Connection Test").
       arg(SPOTON_APPLICATION_NAME),
       tr("Failure!\nError: %1.").arg(error));

  QApplication::processEvents();
#endif
}

void spoton::slotVerifySMPSecret(const QString &hash,
				 const QString &keyType,
				 const QString &oid)
{
  /*
  ** Chat windows only please!
  */

  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  verifySMPSecret(hash, keyType, oid);
}

void spoton::slotVerifySMPSecret(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted() &&
	  m_ui.kernelKeySize->currentText().toInt() > 0)
    return;

  QString hash("");
  QString keyType("");
  QString oid("");
  auto temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      auto item = m_ui.participants->item(row, 1); // OID

      if(item)
	{
	  keyType = item->data
	    (Qt::ItemDataRole(Qt::UserRole + 1)).toString();
	  oid = item->text();
	  temporary = item->data(Qt::UserRole).toBool();
	}

      item = m_ui.participants->item(row, 3); // public_key_hash

      if(item)
	hash = item->text();
    }

  if(hash.isEmpty())
    return;
  else if(keyType.isEmpty())
    return;
  else if(oid.isEmpty())
    return;
  else if(temporary) // Temporary friend?
    return; // Not allowed!

  verifySMPSecret(hash, keyType, oid);
}

void spoton::slotViewEchoKeyShare(void)
{
  m_echoKeyShare->show(this);
}

void spoton::verifySMPSecret(const QString &hash,
			     const QString &keyType,
			     const QString &oid)
{
  if(hash.isEmpty() || keyType.isEmpty() || oid.isEmpty())
    return;

  spoton_smp *smp = 0;

  if(!m_smps.contains(hash))
    return;
  else
    smp = m_smps.value(hash, 0);

  QList<QByteArray> list;
  auto ok = true;

  if(smp)
    {
      smp->initialize();
      list = smp->step1(&ok);
    }
  else
    {
      ok = false;
      spoton_misc::logError("spoton::verifySMPSecret(): smp is zero!");
    }

  if(ok)
    sendSMPLinkToKernel(list, keyType, oid);
}
