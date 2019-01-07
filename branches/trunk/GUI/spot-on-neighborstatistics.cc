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

#include <QFuture>
#include <QSqlField>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "Common/spot-on-crypt.h"
#include "spot-on.h"
#include "spot-on-neighborstatistics.h"

spoton_neighborstatistics::spoton_neighborstatistics(QWidget *parent):
  QMainWindow(parent)
{
  m_ui.setupUi(this);
  connect(&m_futureWatcher,
	  SIGNAL(finished(void)),
	  this,
	  SLOT(slotFinished(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.setInterval(2500);
  m_timer.start();
#ifdef Q_OS_MAC
  statusBar()->setSizeGripEnabled(false);
#endif
}

spoton_neighborstatistics::~spoton_neighborstatistics()
{
  m_timer.stop();
  m_future.cancel();
  m_future.waitForFinished();
}

QString spoton_neighborstatistics::query(void)
{
  QString text("");
  spoton_crypt *crypt = spoton::instance() ?
    spoton::instance()->crypts().value("chat", 0) : 0;

  if(crypt)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.exec("PRAGMA read_uncommitted = True");
	    query.prepare("SELECT * FROM neighbors WHERE "
			  "oid = ?");
	    query.bindValue(0, objectName());

	    if(query.exec() && query.next())
	      {
		text.append("<html>");

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QByteArray bytes
		      (QByteArray::fromBase64(query.value(i).toByteArray()));

		    text.append(QString("<b>%1:</b> ").
				arg(query.record().fieldName(i)));

		    if(query.record().field(i).type() != QVariant::ByteArray &&
		       query.record().field(i).type() != QVariant::String)
		      text.append(query.value(i).toString());
		    else
		      {
			bool ok = true;

			bytes = crypt->decryptedAfterAuthenticated(bytes, &ok);

			if(ok)
			  {
			    if(query.record().field(i).name() == "certificate")
			      {
				text.append(bytes);
				text.append("<br>");

				QSslCertificate certificate(bytes);

				if(!certificate.isNull())
				  text.append
				    (tr("<b>Cert. Effective Date:</b> %1<br>"
					"<b>Cert. Expiration Date:</b> %2<br>"
					"<b>Cert. Issuer Organization:</b> "
					"%3<br>"
					"<b>Cert. Issuer Common Name:</b> "
					"%4<br>"
					"<b>Cert. Issuer Locality Name:</b> "
					"%5<br>"
					"<b>Cert. Issuer Organizational Unit "
					"Name:</b> %6<br>"
					"<b>Cert. Issuer Country Name:</b> %7"
					"<br>"
					"<b>Cert. Issuer State or Province "
					"Name:</b> %8<br>"
					"<b>Cert. Serial Number:</b> %9<br>"
					"<b>Cert. Subject Organization:</b> "
					"%10<br>"
					"<b>Cert. Subject Common Name:</b> "
					"%11<br>"
					"<b>Cert. Subject Locality Name:</b> "
					"%12<br>"
					"<b>Cert. Subject Organizational Unit "
					"Name:</b> %13<br>"
					"<b>Cert. Subject Country Name:</b> "
					"%14<br>"
					"<b>Cert. Subject State or Province "
					"Name:</b> %15<br>"
					"<b>Cert. Version:</b> %16").
				     arg(certificate.effectiveDate().
					 toString("MM/dd/yyyy")).
				     arg(certificate.expiryDate().
					 toString("MM/dd/yyyy")).
#if QT_VERSION < 0x050000
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    Organization)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    CommonName)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    LocalityName)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    OrganizationalUnitName)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    CountryName)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    StateOrProvinceName)).
#else
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    Organization).value(0)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    CommonName).value(0)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    LocalityName).value(0)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    OrganizationalUnitName).
					 value(0)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    CountryName).value(0)).
				     arg(certificate.
					 issuerInfo(QSslCertificate::
						    StateOrProvinceName).
					 value(0)).
#endif
				     arg(certificate.serialNumber().
					 constData()).
#if QT_VERSION < 0x050000
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     Organization)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     CommonName)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     LocalityName)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     OrganizationalUnitName)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     CountryName)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     StateOrProvinceName)).
#else
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     Organization).
					 value(0)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     CommonName).
					 value(0)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     LocalityName).
					 value(0)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     OrganizationalUnitName).
					 value(0)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     CountryName).
					 value(0)).
				     arg(certificate.
					 subjectInfo(QSslCertificate::
						     StateOrProvinceName).
					 value(0)).
#endif
				     arg(certificate.version().constData()));
			      }
			    else
			      text.append(bytes);
			  }
			else
			  text.append(query.value(i).toString());
		      }

		    text.append("<br>");
		  }

		text.append("</html");
	      }
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  return text;
}

void spoton_neighborstatistics::closeEvent(QCloseEvent *event)
{
  m_timer.stop();
  m_future.cancel();
  m_future.waitForFinished();
  QMainWindow::closeEvent(event);
}

void spoton_neighborstatistics::show(void)
{
  if(!m_timer.isActive())
    m_timer.start();

  QMainWindow::show();
}

void spoton_neighborstatistics::slotFinished(void)
{
  if(m_future.results().value(0).length() > 0)
    {
      QPair<int, int> s(m_ui.textBrowser->textCursor().selectionStart(),
			m_ui.textBrowser->textCursor().selectionEnd());
      int h = m_ui.textBrowser->horizontalScrollBar()->value();
      int v = m_ui.textBrowser->verticalScrollBar()->value();

      m_ui.textBrowser->setHtml(m_future.results().value(0));

      QTextCursor cursor(m_ui.textBrowser->textCursor());

      cursor.setPosition(s.first);
      cursor.setPosition(s.second, QTextCursor::KeepAnchor);
      m_ui.textBrowser->setTextCursor(cursor);
      m_ui.textBrowser->horizontalScrollBar()->setValue(h);
      m_ui.textBrowser->verticalScrollBar()->setValue(v);
    }
  else
    deleteLater();
}

void spoton_neighborstatistics::slotTimeout(void)
{
  if(m_future.isFinished())
    {
      m_future = QtConcurrent::run(this, &spoton_neighborstatistics::query);
      m_futureWatcher.setFuture(m_future);
    }
}
