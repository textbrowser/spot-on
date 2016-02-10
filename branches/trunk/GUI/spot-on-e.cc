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

extern "C"
{
#include <curl/curl.h>
}

#include <QSettings>
#include <QThread>

#if QT_VERSION >= 0x050000
#include <QCoreApplication>
#include <QtConcurrent>
#include <QtCore>
#endif

#include "spot-on.h"
#include "spot-on-defines.h"
#include "ui_spot-on-keyboard.h"

static QStringList curl_protocols(void)
{
  QStringList list;
  curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);

  for(int i = 0; data->protocols[i] != 0; i++)
    list << QString(data->protocols[i]).toLower();

  return list;
}

void spoton::slotConfigurePoptastic(void)
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

  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
  m_poptasticRetroPhoneSettingsUi.account->clear();
  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);
  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(false);

  QList<QHash<QString, QVariant> > list;
  bool ok = true;

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
    }
  else
    {
      m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);

      for(int i = 0; i < list.size(); i++)
	{
	  m_poptasticRetroPhoneSettingsUi.account->addItem
	    (list.at(i)["in_username"].toString());
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
	    (list.at(i)["in_username"].toString());
	}

      m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

      int index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	findText(m_settings["gui/poptasticName"].toByteArray());

      if(index >= 0)
	m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	  setCurrentIndex(index);
      else
	m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	  setCurrentIndex(0);
    }

  QStringList protocols(curl_protocols());

  connect(m_poptasticRetroPhoneSettingsUi.account,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotPoptasticAccountChanged(const QString &)),
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
  connect(m_poptasticRetroPhoneSettingsUi.selectcapath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectCAPath(void)),
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
    (tr("%1: Poptastic & RetroPhone Settings").
     arg(SPOTON_APPLICATION_NAME));
#ifdef Q_OS_MAC
  m_poptasticRetroPhoneDialog->setAttribute(Qt::WA_MacMetalStyle, false);
#endif
  m_poptasticRetroPhoneSettingsUi.capath->setText
    (m_settings.value("gui/poptasticCAPath", "").toString());
  m_poptasticRetroPhoneSettingsUi.poptasticRefresh->setValue
    (m_settings.value("gui/poptasticRefreshInterval", 5.00).toDouble());
  m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(0);
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
      prepareDatabasesFromUI();

      QString error("");

      if(ok)
	error = savePoptasticAccount();
      else
	error = "An error occurred with spoton_crypt.";

      if(!error.isEmpty())
	{
	  QMessageBox::critical(this, tr("%1: Error").
				arg(SPOTON_APPLICATION_NAME),
				tr("An error (%1) occurred while "
				   "attempting to save the Poptastic "
				   "information.").arg(error));
	  return;
	}

      QSettings settings;

      m_settings["gui/poptasticCAPath"] =
	m_poptasticRetroPhoneSettingsUi.capath->text();
      m_settings["gui/poptasticName"] =
	m_poptasticRetroPhoneSettingsUi.chat_primary_account->currentText().
	toLatin1();
      m_settings["gui/poptasticRefreshInterval"] =
	m_poptasticRetroPhoneSettingsUi.poptasticRefresh->value();
      settings.setValue
	("gui/poptasticCAPath",
	 m_poptasticRetroPhoneSettingsUi.capath->text());
      settings.setValue
	("gui/poptasticName",
	 crypt->encryptedThenHashed(m_settings["gui/poptasticName"].
				    toByteArray(), &ok).toBase64());
      settings.setValue
	("gui/poptasticRefreshInterval",
	 m_poptasticRetroPhoneSettingsUi.poptasticRefresh->value());
      slotReloadEmailNames();
    }

  m_poptasticRetroPhoneSettingsUi.in_password->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.out_password->clear();
  m_poptasticRetroPhoneSettingsUi.out_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.out_username->clear();
  m_poptasticRetroPhoneSettingsUi.proxy->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible(false);
  m_poptasticRetroPhoneSettingsUi.proxy_password->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue(1);
  m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.proxy_username->clear();
}

void spoton::slotTestPoptasticPop3Settings(void)
{
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  bool ok = false;

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

      QString method
	(m_poptasticRetroPhoneSettingsUi.in_method->currentText().toUpper());
      QString url("");
      int index = m_poptasticRetroPhoneSettingsUi.in_ssltls->currentIndex();

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

	  long verify = static_cast<long>
	    (m_poptasticRetroPhoneSettingsUi.in_verify_host->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long>
	    (m_poptasticRetroPhoneSettingsUi.in_verify_peer->isChecked());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    {
	      QFileInfo fileInfo
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
       tr("Failure!"));
}

void spoton::slotTestPoptasticSmtpSettings(void)
{
  CURL *curl = 0;
  CURLcode res = CURLE_OK;
  bool ok = false;

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

      QString method
	(m_poptasticRetroPhoneSettingsUi.out_method->currentText().toUpper());
      QString url("");
      int index = m_poptasticRetroPhoneSettingsUi.out_ssltls->currentIndex();

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

	  long verify = static_cast<long>
	    (m_poptasticRetroPhoneSettingsUi.out_verify_host->isChecked());

	  if(verify)
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	  else
	    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	  verify = static_cast<long>
	    (m_poptasticRetroPhoneSettingsUi.out_verify_peer->isChecked());
	  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);

	  if(index == 2) // TLS
	    {
	      QFileInfo fileInfo
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
       tr("Failure!"));
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

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").
		    arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to reset your Poptastic "
		"settings?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
  m_poptasticRetroPhoneSettingsUi.account->clear();
  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);
  m_poptasticRetroPhoneSettingsUi.capath->clear();
  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();
  m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.in_password->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_address->clear();
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue(995);
  m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(2);
  m_poptasticRetroPhoneSettingsUi.in_username->clear();
  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked(false);
  m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);
  m_poptasticRetroPhoneSettingsUi.out_password->clear();
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
  m_settings["gui/poptasticName"] = "";

  QSettings settings;

  settings.remove("gui/poptasticCAPath");
  settings.remove("gui/poptasticName");
  settings.remove("gui/poptasticRefreshInterval");
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "poptastic.db");

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

void spoton::slotSelectCAPath(void)
{
  QString fileName("");

  if(m_poptasticRetroPhoneSettingsUi.selectcapath == sender())
    {
      QFileDialog dialog(m_poptasticRetroPhoneDialog);

      dialog.setWindowTitle
	(tr("%1: Select CA File").
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
	{
	  fileName = dialog.selectedFiles().value(0);
	  m_poptasticRetroPhoneSettingsUi.capath->setText
	    (dialog.selectedFiles().value(0));
	}
    }
  else
    fileName = m_poptasticRetroPhoneSettingsUi.capath->text();
}

void spoton::slotSetNeighborPriority(void)
{
  QAction *action = qobject_cast<QAction *> (sender());
  QThread::Priority priority = QThread::HighPriority;

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
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

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

void spoton::slotAcceptGeminis(bool state)
{
  m_settings["gui/acceptGeminis"] = state;

  QSettings settings;

  settings.setValue("gui/acceptGeminis", state);
}

void spoton::slotShareKeysWithKernel(const QString &link)
{
  Q_UNUSED(link);
  m_keysShared["keys_sent_to_kernel"] = "false";
}

void spoton::slotSaveUrlDistribution(int index)
{
  Q_UNUSED(index);

  QString str("linear");

  m_settings["gui/urlDistribution"] = str;

  QSettings settings;

  settings.setValue("gui/urlDistribution", str);
}

void spoton::slotSaveSharePrivateKeys(bool state)
{
  m_settings["gui/sharePrivateKeysWithKernel"] = state;

  QSettings settings;

  settings.setValue("gui/sharePrivateKeysWithKernel", state);

  if(state)
    if(m_keysShared["keys_sent_to_kernel"] == "ignore")
      m_keysShared["keys_sent_to_kernel"] = "false";
}

void spoton::slotShowOptions(void)
{
  QPoint p(pos());
  int X = 0;
  int Y = 0;

  if(width() >= m_optionsWindow->width())
    X = p.x() + (width() - m_optionsWindow->width()) / 2;
  else
    X = p.x() - (m_optionsWindow->width() - width()) / 2;

  if(height() >= m_optionsWindow->height())
    Y = p.y() + (height() - m_optionsWindow->height()) / 2;
  else
    Y = p.y() - (m_optionsWindow->height() - height()) / 2;

  m_optionsWindow->move(X, Y);
  m_optionsWindow->show();
  m_optionsWindow->raise();
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

void spoton::slotSaveOpenLinks(bool state)
{
  m_settings["gui/openLinks"] = state;

  QSettings settings;

  settings.setValue("gui/openLinks", state);
}

void spoton::slotDeriveGeminiPairViaSMP(const QString &publicKeyHash,
					const QString &oid)
{
  QList<QTableWidgetItem *> list(findItems(m_ui.participants,
					   oid,
					   1));

  if(list.isEmpty())
    return;

  QTableWidgetItem *item = list.at(0);

  if(!item)
    return;
  else if(item->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!

  spoton_smp *smp = m_smps.value(publicKeyHash, 0);

  if(!smp)
    return;

#ifndef Q_OS_MAC
  QApplication::processEvents();
#endif
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QPair<QByteArray, QByteArray> gemini;
  QString error("");

  gemini = spoton_crypt::derivedKeys
    ("aes256",
     "sha512",
     spoton_common::GEMINI_ITERATION_COUNT,
     smp->guessWhirlpool().toHex(),
     smp->guessSha(),
     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
     error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    return;

  saveGemini(gemini, oid);
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
  bool temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

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

void spoton::prepareSMP(const QString &hash)
{
  if(hash.isEmpty())
    return;

  QString guess("");
  spoton_virtual_keyboard dialog(QApplication::activeWindow());

  if(dialog.exec() == QDialog::Accepted)
    guess = dialog.m_ui.passphrase->text();
  else
    return;

  spoton_smp *smp = 0;

  if(m_smps.contains(hash))
    smp = m_smps.value(hash, 0);
  else
    {
      smp = new spoton_smp();
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

void spoton::slotVerifySMPSecret(const QString &hash, const QString &keyType,
				 const QString &oid)
{
  /*
  ** Chat windows only please!
  */

  verifySMPSecret(hash, keyType, oid);
}

void spoton::slotVerifySMPSecret(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString hash("");
  QString keyType("");
  QString oid("");
  bool temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

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

void spoton::verifySMPSecret(const QString &hash, const QString &keyType,
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
  bool ok = true;

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
  else if(!m_kernelSocket.isEncrypted())
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

  message.append(QString("%1_").arg(oid));

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
  message.append(QDateTime::currentDateTime().toUTC().
		 toString("MMddyyyyhhmmss").toLatin1().toBase64());
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::sendSMPLinkToKernel(): write() failure for "
	       "%1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::playSong(const QString &name)
{
  if(m_locked)
    return;

#if QT_VERSION >= 0x050000
  QMediaPlayer *player = findChild<QMediaPlayer *> ();
  QString str
    (QDir::cleanPath(QCoreApplication::applicationDirPath() +
		     QDir::separator() + "Sounds" + QDir::separator() +
		     name));

  if(player)
    player->deleteLater();

  player = new (std::nothrow) QMediaPlayer(this, QMediaPlayer::LowLatency);

  if(player)
    {
      connect(player,
	      SIGNAL(error(QMediaPlayer::Error)),
	      this,
	      SLOT(slotMediaError(QMediaPlayer::Error)));
      connect(player,
	      SIGNAL(mediaStatusChanged(QMediaPlayer::MediaStatus)),
	      this,
	      SLOT(slotMediaStatusChanged(QMediaPlayer::MediaStatus)));
      player->setMedia(QUrl::fromLocalFile(str));
      player->setVolume(100);
      player->play();
    }
  else
    QApplication::beep();
#else
  Q_UNUSED(name);
  QApplication::beep();
#endif
}

#if QT_VERSION >= 0x050000
void spoton::slotMediaError(QMediaPlayer::Error error)
{
  QMediaPlayer *player = qobject_cast<QMediaPlayer *> (sender());

  if(!player)
    return;

  if(error != QMediaPlayer::NoError)
    player->deleteLater();
}

void spoton::slotMediaStatusChanged(QMediaPlayer::MediaStatus status)
{
  QMediaPlayer *player = qobject_cast<QMediaPlayer *> (sender());

  if(!player)
    return;

  if(status == QMediaPlayer::EndOfMedia)
    player->deleteLater();
}
#endif

void spoton::slotLaunchKernelAfterAuthentication(bool state)
{
  m_settings["gui/launchKernelAfterAuth"] = state;

  QSettings settings;

  settings.setValue("gui/launchKernelAfterAuth", state);
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
  bool temporary = true;
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

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

void spoton::slotSaveRefreshEmail(bool state)
{
  m_settings["gui/refreshEmail"] = state;

  QSettings settings;

  settings.setValue("gui/refreshEmail", state);
}

void spoton::slotSetSBPulseSize(void)
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

  QString oid("");
  int integer = 15000;
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.transmitted->item(row, 2); // Pulse Size

      if(item)
	integer = item->text().toInt();
    }

  if(oid.isEmpty())
    return;

  bool ok = true;

  integer = QInputDialog::getInt
    (this, tr("%1: StarBeam Pulse Size").arg(SPOTON_APPLICATION_NAME),
     tr("&Pulse Size"), integer, 1024, 250000, 1, &ok);

  if(!ok)
    return;

  QByteArray bytes(crypt->encryptedThenHashed(QByteArray::number(integer),
					      &ok).toBase64());

  if(ok)
    setSBField(oid, bytes, "pulse_size");
  else
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error occurred while attempting to "
			     "secure the pulse size."));
}

void spoton::slotSetSBReadInterval(void)
{
  QString oid("");
  double rational = 1.500;
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.transmitted->item(row, 8); // Read Interval

      if(item)
	rational = item->text().toDouble();
    }

  if(oid.isEmpty())
    return;

  bool ok = true;

  rational = QInputDialog::getDouble
    (this, tr("%1: StarBeam Read Interval").arg(SPOTON_APPLICATION_NAME),
     tr("&Read Interval"), rational, 0.100, 60.000, 3, &ok);

  if(!ok)
    return;

  setSBField(oid, rational, "read_interval");
}

void spoton::setSBField(const QString &oid, const QVariant &value,
			const QString &field)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

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

void spoton::slotShareStarBeam(void)
{
  int row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item = m_ui.participants->item(row, 1); // OID

  if(!item)
    return;
  else if(item->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!
  else if(item->data(Qt::ItemDataRole(Qt::UserRole + 1)).
	  toString() == "poptastic")
    return;

  QString error("");
  spoton_crypt *crypt = m_crypts.value("chat", 0);

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
  else if(!m_kernelSocket.isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      showError(error);
      return;
    }

  QModelIndexList list(m_ui.participants->selectionModel()->
		       selectedRows(1)); // OID

  if(list.isEmpty())
    {
      error = tr
	("Please select at least one participant for StarBeam sharing.");
      showError(error);
      return;
    }

  /*
  ** Select a file.
  */

  QFileDialog dialog(this);

  dialog.setWindowTitle(tr("%1: Select StarBeam Transmit File").
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

  if(dialog.exec() != QDialog::Accepted)
    return;

  QFileInfo fileInfo(dialog.selectedFiles().value(0));

  if(!fileInfo.exists() || !fileInfo.isReadable())
    {
      error = tr("The selected file is not readable.");
      showError(error);
      return;
    }

  /*
  ** Create a StarBeam magnet.
  */

  QByteArray eKey(spoton_crypt::strongRandomBytes(spoton_crypt::
						  cipherKeyLength("aes256")).
		  toBase64());
  QByteArray mKey(spoton_crypt::
		  strongRandomBytes(spoton_crypt::
				    XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES).
		  toBase64());
  QByteArray magnet;
  bool ok = true;

  magnet.append("magnet:?");
  magnet.append("ct=aes256&");
  magnet.append("ek=");
  magnet.append(eKey);
  magnet.append("&");
  magnet.append("ht=sha512&");
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
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QByteArray encryptedMosaic;
	QByteArray mosaic
	  (spoton_crypt::strongRandomBytes(spoton_common::MOSAIC_SIZE).
	   toBase64());
	QSqlQuery query(db);

	query.prepare("INSERT INTO transmitted "
		      "(file, hash, missing_links, mosaic, nova, "
		      "position, pulse_size, read_interval, "
		      "status_control, total_size) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, crypt->
	   encryptedThenHashed(fileInfo.absoluteFilePath().toUtf8(),
			       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->
	     encryptedThenHashed
	     (spoton_crypt::
	      sha1FileHash(fileInfo.absoluteFilePath()).toHex(),
	      &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->
	     encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  {
	    encryptedMosaic = crypt->encryptedThenHashed(mosaic, &ok);

	    if(ok)
	      query.bindValue(3, encryptedMosaic.toBase64());
	  }

	if(ok)
	  query.bindValue
	    (4, crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->encryptedThenHashed("0", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->
	     encryptedThenHashed(QByteArray::
				 number(qMin(spoton_common::
					     ELEGANT_STARBEAM_SIZE,
					     spoton_misc::
					     minimumNeighborLaneWidth())),
				 &ok).toBase64());

	query.bindValue(7, 2.500);
	query.bindValue(8, "transmitting");

	if(ok)
	  query.bindValue
	    (9, crypt->
	     encryptedThenHashed(QByteArray::number(fileInfo.size()),
				 &ok).toBase64());

	if(ok)
	  query.exec();

	query.prepare("INSERT INTO transmitted_magnets "
		      "(magnet, magnet_hash, transmitted_oid) "
		      "VALUES (?, ?, (SELECT OID FROM transmitted WHERE "
		      "mosaic = ?))");

	if(ok)
	  query.bindValue
	    (0, crypt->
	     encryptedThenHashed(magnet, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, crypt->keyedHash(magnet, &ok).toBase64());

	if(ok)
	  query.bindValue(2, encryptedMosaic.toBase64());

	if(ok)
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

  QMessageBox::critical(this, tr("%1: Error").
			arg(SPOTON_APPLICATION_NAME), error.trimmed());
}

QStandardItemModel *spoton::starbeamReceivedModel(void) const
{
  return m_starbeamReceivedModel;
}

void spoton::slotSaveStarBeamAutoVerify(bool state)
{
  m_settings["gui/starbeamAutoVerify"] = state;

  QSettings settings;

  settings.setValue("gui/starbeamAutoVerify", state);
}

void spoton::slotSaveCustomStatus(void)
{
  QString text
    (m_ui.custom->toPlainText().
     mid(0, spoton_common::STATUS_TEXT_MAXIMUM_LENGTH));

  m_settings["gui/customStatus"] = text.trimmed().toUtf8();

  QSettings settings;

  settings.setValue("gui/customStatus", text.trimmed().toUtf8());
}

void spoton::slotSaveAlternatingColors(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

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
    }
}

void spoton::computeFileDigest(const QByteArray &expectedFileHash,
			       const QString &fileName,
			       const QString &oid,
			       spoton_crypt *crypt)
{
  Q_UNUSED(expectedFileHash);

  QFile file;

  file.setFileName(fileName);

  if(file.open(QIODevice::ReadOnly))
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

	if(db.open())
	  {
	    QByteArray hash
	      (spoton_crypt::sha1FileHash(fileName,
					  m_starbeamDigestInterrupt));

	    if(!m_starbeamDigestInterrupt.fetchAndAddRelaxed(0))
	      spoton_misc::saveReceivedStarBeamHash(db, hash, oid, crypt);
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  file.close();
}

void spoton::slotDeriveGeminiPairViaSMP(void)
{
  int row = m_ui.participants->currentRow();

  if(row < 0)
    return;

  QTableWidgetItem *item1 = m_ui.participants->item(row, 1); // OID
  QTableWidgetItem *item2 = m_ui.participants->item
    (row, 3); // public_key_hash

  if(!item1 || !item2)
    return;
  else if(item1->data(Qt::UserRole).toBool()) // Temporary friend?
    return; // Temporary!

  spoton_smp *smp = m_smps.value(item2->text(), 0);

  if(!smp)
    return;

#ifndef Q_OS_MAC
  QApplication::processEvents();
#endif
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QPair<QByteArray, QByteArray> gemini;
  QString error("");

  gemini = spoton_crypt::derivedKeys
    ("aes256",
     "sha512",
     spoton_common::GEMINI_ITERATION_COUNT,
     smp->guessWhirlpool().toHex(),
     smp->guessSha(),
     spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES,
     error);
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    return;

  saveGemini(gemini, item1->text());
}

void spoton::slotOntopChatDialogs(bool state)
{
  m_settings["gui/ontopChatDialogs"] = state;

  QSettings settings;

  settings.setValue("gui/ontopChatDialogs", state);
}

void spoton::slotRemoveOtmOnExit(bool state)
{
  m_settings["gui/removeOtmOnExit"] = state;

  QSettings settings;

  settings.setValue("gui/removeOtmOnExit", state);
}

void spoton::slotSearchResultsPerPage(int value)
{
  m_settings["gui/searchResultsPerPage"] = value;

  QSettings settings;

  settings.setValue("gui/searchResultsPerPage", value);
}

void spoton::slotActiveUrlDistribution(bool state)
{
  m_settings["gui/activeUrlDistribution"] = state;

  QSettings settings;

  settings.setValue("gui/activeUrlDistribution", state);
}

void spoton::initializeUrlDistillers(void)
{
  spoton_misc::prepareUrlDistillersDatabase();

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return;

  prepareDatabasesFromUI();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
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
	    QByteArray direction(list.at(i).value(1).toByteArray());
	    QByteArray domain
	      (list.at(i).value(0).toUrl().scheme().toLatin1() + "://" +
	       list.at(i).value(0).toUrl().host().toUtf8() +
	       list.at(i).value(0).toUrl().path().toUtf8());
	    QByteArray permission(list.at(i).value(2).toByteArray());
	    QSqlQuery query(db);
	    bool ok = true;

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

void spoton::slotViewEchoKeyShare(void)
{
  m_echoKeyShare->show(this);
}

QHash<QString, spoton_crypt *> spoton::crypts(void) const
{
  return m_crypts;
}

QByteArray spoton::poptasticName(void) const
{
  return m_settings["gui/poptasticName"].toByteArray();
}

void spoton::slotSavePoptasticAccount(void)
{
  prepareDatabasesFromUI();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString error(savePoptasticAccount());

  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    QMessageBox::critical(m_poptasticRetroPhoneDialog, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("An error (%1) occurred while "
			     "attempting to save the Poptastic "
			     "information.").arg(error));
  else
    {
      QList<QHash<QString, QVariant> > list;
      bool ok = true;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      list = spoton_misc::poptasticSettings
	("", m_crypts.value("chat", 0), &ok);
      QApplication::restoreOverrideCursor();

      if(ok)
	{
	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
	  m_poptasticRetroPhoneSettingsUi.account->clear();
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_poptasticRetroPhoneSettingsUi.account->addItem
		(list.at(i)["in_username"].toString());
	      m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
		(list.at(i)["in_username"].toString());
	    }

	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

	  int index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	    findText(m_settings["gui/poptasticName"].toByteArray());

	  if(index >= 0)
	    m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	      setCurrentIndex(index);
	  else
	    m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	      setCurrentIndex(0);
	}
    }
}

QString spoton::savePoptasticAccount(void)
{
  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    return "Invalid spoton_crypt object. This is a fatal flaw.";
  else if(m_poptasticRetroPhoneSettingsUi.in_username->text().
	  trimmed().isEmpty())
    return "Empty Incoming Server Username.";

  QString connectionName("");
  QString error("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "poptastic.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO poptastic "
	   "(in_authentication, "
	   "in_method, in_password, in_server_address, "
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
	   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, m_poptasticRetroPhoneSettingsUi.in_authentication->
	   currentText());
	query.bindValue
	  (1, crypt->
	   encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.in_method->
			       currentText().toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, crypt->encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
					   in_password->
					   text().
					   toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 in_server_address->
				 text().trimmed().
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_server_port->
					value()), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.in_ssltls->
				 currentText().toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 in_username->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (7, crypt->
	     keyedHash(m_poptasticRetroPhoneSettingsUi.
		       in_username->text().trimmed().toLatin1(),
		       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (8, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_verify_host->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					in_verify_peer->isChecked() ?
					1 : 0), &ok).toBase64());

	query.bindValue
	  (10, m_poptasticRetroPhoneSettingsUi.out_authentication->
	   currentText());

	if(ok)
	  query.bindValue
	    (11, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_method->currentText().toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (12, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_password->
				 text().
				 toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (13, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_server_address->
				 text().trimmed().
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (14, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_server_port->
					value()), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (15, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_ssltls->currentText().toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (16, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 out_username->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_verify_host->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (18, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					out_verify_peer->isChecked() ?
					1 : 0), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (19, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					proxy->
					isChecked() ? 1 : 0),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (20, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_password->text().
				 toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (21, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_server_address->text().
				 trimmed().toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (22, crypt->
	     encryptedThenHashed(QByteArray::
				 number(m_poptasticRetroPhoneSettingsUi.
					proxy_server_port->
					value()), &ok).toBase64());

	query.bindValue(23, m_poptasticRetroPhoneSettingsUi.proxy_type->
			currentText());

	if(ok)
	  query.bindValue
	    (24, crypt->
	     encryptedThenHashed(m_poptasticRetroPhoneSettingsUi.
				 proxy_username->
				 text().trimmed().toUtf8(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (25, crypt->
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

void spoton::populatePoptasticWidgets(const QHash<QString, QVariant> &hash)
{
  if(hash.isEmpty())
    return;

  int index = -1;

  index = m_poptasticRetroPhoneSettingsUi.in_method->findText
    (hash["in_method"].toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.in_method->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.in_password->setText
    (hash["in_password"].toString());
  m_poptasticRetroPhoneSettingsUi.in_server_address->setText
    (hash["in_server_address"].toString());
  m_poptasticRetroPhoneSettingsUi.in_server_port->setValue
    (hash["in_server_port"].toInt());
  index = m_poptasticRetroPhoneSettingsUi.in_ssltls->findText
    (hash["in_ssltls"].toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.in_ssltls->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.in_username->setText
    (hash["in_username"].toString());
  m_poptasticRetroPhoneSettingsUi.in_verify_host->setChecked
    (hash["in_verify_host"].toBool());
  m_poptasticRetroPhoneSettingsUi.in_verify_peer->setChecked
    (hash["in_verify_peer"].toBool());
  index = m_poptasticRetroPhoneSettingsUi.out_method->findText
    (hash["out_method"].toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.out_method->setCurrentIndex(0);

  m_poptasticRetroPhoneSettingsUi.out_password->setText
    (hash["out_password"].toString());
  m_poptasticRetroPhoneSettingsUi.out_server_address->setText
    (hash["out_server_address"].toString());
  m_poptasticRetroPhoneSettingsUi.out_server_port->setValue
    (hash["out_server_port"].toInt());
  index = m_poptasticRetroPhoneSettingsUi.out_ssltls->findText
    (hash["out_ssltls"].toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.out_ssltls->setCurrentIndex(2);

  m_poptasticRetroPhoneSettingsUi.out_username->setText
    (hash["out_username"].toString());
  m_poptasticRetroPhoneSettingsUi.out_verify_host->setChecked
    (hash["out_verify_host"].toBool());
  m_poptasticRetroPhoneSettingsUi.out_verify_peer->setChecked
    (hash["out_verify_peer"].toBool());
  m_poptasticRetroPhoneSettingsUi.proxy->setChecked
    (hash["proxy_enabled"].toBool());
  m_poptasticRetroPhoneSettingsUi.proxy_frame->setVisible
    (hash["proxy_enabled"].toBool());
  m_poptasticRetroPhoneSettingsUi.proxy_password->setText
    (hash["proxy_password"].toString());
  m_poptasticRetroPhoneSettingsUi.proxy_server_address->setText
    (hash["proxy_server_address"].toString());
  m_poptasticRetroPhoneSettingsUi.proxy_server_port->setValue
    (hash["proxy_server_port"].toInt());
  index = m_poptasticRetroPhoneSettingsUi.proxy_type->findText
    (hash["proxy_type"].toString());

  if(index >= 0)
    m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(index);
  else
    m_poptasticRetroPhoneSettingsUi.proxy_type->setCurrentIndex(0);

  m_poptasticRetroPhoneSettingsUi.proxy_username->setText
    (hash["proxy_username"].toString());
  m_poptasticRetroPhoneSettingsUi.smtp_localname->setText
    (hash.value("smtp_localname", "localhost").toString());
}

void spoton::slotPoptasticAccountChanged(const QString &text)
{
  QList<QHash<QString, QVariant> > list;
  bool ok = true;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  list = spoton_misc::poptasticSettings(text, m_crypts.value("chat", 0), &ok);
  QApplication::restoreOverrideCursor();

  if(ok)
    populatePoptasticWidgets(list.value(0));
}

void spoton::slotDeletePoptasticAccount(void)
{
  if(m_poptasticRetroPhoneSettingsUi.account->currentText().trimmed().
     isEmpty())
    return;

  QMessageBox mb(m_poptasticRetroPhoneDialog);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").
		    arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to delete the specified "
		"Poptastic account?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  spoton_crypt *crypt = m_crypts.value("chat", 0);

  if(!crypt)
    {
      QMessageBox::critical(m_poptasticRetroPhoneDialog, tr("%1: Error").
			    arg(SPOTON_APPLICATION_NAME),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "poptastic.db");

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
      bool ok = true;

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      list = spoton_misc::poptasticSettings("", crypt, &ok);
      QApplication::restoreOverrideCursor();

      if(ok)
	{
	  populatePoptasticWidgets(list.value(0));
	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(true);
	  m_poptasticRetroPhoneSettingsUi.account->clear();
	  m_poptasticRetroPhoneSettingsUi.chat_primary_account->clear();

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_poptasticRetroPhoneSettingsUi.account->addItem
		(list.at(i)["in_username"].toString());
	      m_poptasticRetroPhoneSettingsUi.chat_primary_account->addItem
		(list.at(i)["in_username"].toString());
	    }

	  m_poptasticRetroPhoneSettingsUi.account->blockSignals(false);

	  int index = m_poptasticRetroPhoneSettingsUi.chat_primary_account->
	    findText(m_settings["gui/poptasticName"].toByteArray());

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
		 crypt->encryptedThenHashed(m_settings["gui/poptasticName"].
					    toByteArray(), &ok).toBase64());
	    }
	}
    }
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

  QList<QHash<QString, QVariant> > list
    (spoton_misc::poptasticSettings("", m_crypts.value("chat", 0), 0));

  for(int i = 0; i < list.size(); i++)
    {
      if(i == 0)
	m_ui.emailName->insertSeparator(1);

      m_ui.emailName->addItem(list.at(i)["in_username"].toString());
    }

  QApplication::restoreOverrideCursor();
}
