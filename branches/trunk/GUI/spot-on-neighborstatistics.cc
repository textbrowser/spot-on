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
#include "spot-on-neighborstatistics.h"
#include "spot-on.h"

spoton_neighborstatistics::spoton_neighborstatistics(spoton *parent):
  QMainWindow(parent)
{
  m_parent = parent;
  m_ui.setupUi(this);
  m_ui.table->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
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
#if defined(Q_OS_MAC) || defined(Q_OS_WIN)
  setWindowFlags(windowFlags() | Qt::WindowStaysOnTopHint);
#endif
}

spoton_neighborstatistics::~spoton_neighborstatistics()
{
  m_timer.stop();
  m_future.cancel();
  m_future.waitForFinished();
}

QList<QPair<QString, QString> > spoton_neighborstatistics::query(void)
{
  QList<QPair<QString, QString> > list;
  spoton_crypt *crypt = m_parent ? m_parent->crypts().value("chat", 0) : 0;

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
	    query.prepare("SELECT * FROM neighbors WHERE oid = ?");
	    query.bindValue(0, objectName());

	    if(query.exec() && query.next())
	      for(int i = 0; i < query.record().count(); i++)
		{
		  QByteArray bytes
		    (QByteArray::fromBase64(query.value(i).toByteArray()));
		  QPair<QString, QString> pair;
		  QString text("");

		  pair.first = query.record().fieldName(i);

		  if(query.record().field(i).type() != QVariant::ByteArray &&
		     query.record().field(i).type() != QVariant::String)
		    text = query.value(i).toString();
		  else
		    {
		      bool ok = true;

		      bytes = crypt->decryptedAfterAuthenticated(bytes, &ok);

		      if(ok)
			{
			  if(query.record().field(i).name() == "certificate")
			    {
			      text = bytes;
			      text.append("\n");

			      QSslCertificate certificate(bytes);

			      if(!certificate.isNull())
				text.append
				  (tr("Cert. Effective Date: %1\n"
				      "Cert. Expiration Date: %2\n"
				      "Cert. Issuer Organization: %3\n"
				      "Cert. Issuer Common Name: %4\n"
				      "Cert. Issuer Locality Name: %5\n"
				      "Cert. Issuer Organizational Unit "
				      "Name: %6\n"
				      "Cert. Issuer Country Name: %7\n"
				      "Cert. Issuer State or Province "
				      "Name: %8\n"
				      "Cert. Serial Number: %9\n"
				      "Cert. Subject Organization: %10\n"
				      "Cert. Subject Common Name: %11\n"
				      "Cert. Subject Locality Name: %12\n"
				      "Cert. Subject Organizational Unit "
				      "Name: %13\n"
				      "Cert. Subject Country Name: %14\n"
				      "Cert. Subject State or Province "
				      "Name: %15\n"
				      "Cert. Version: %16").
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
			    text = bytes;
			}
		      else
			text = query.value(i).toString();
		    }

		  pair.second = text;
		  list << pair;
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  return list;
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
  if(m_future.resultCount() > 0)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_ui.table->setSortingEnabled(false);

      QList<QPair<QString, QString> > list(m_future.results().value(0));
      QString fieldName("");
      int hval = m_ui.table->horizontalScrollBar()->value();
      int vval = m_ui.table->verticalScrollBar()->value();

      if(!m_ui.table->selectionModel()->selectedRows(0).isEmpty())
	fieldName = m_ui.table->selectionModel()->selectedRows(0).at(0).
	  data().toString();

      m_ui.table->setRowCount(list.size());

      for(int i = 0; i < list.size(); i++)
	{
	  QTableWidgetItem *item = 0;

	  item = new QTableWidgetItem();
	  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	  item->setText(list.at(i).first);
	  m_ui.table->setItem(i, 0, item);
	  item = new QTableWidgetItem();
	  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	  item->setText(list.at(i).second);
	  item->setToolTip(QString("<html>%1</html>").arg(item->text()));
	  m_ui.table->setItem(i, 1, item);

	  if(fieldName == list.at(i).first)
	    m_ui.table->selectRow(i);
	}

      m_ui.table->setSortingEnabled(true);
      m_ui.table->horizontalScrollBar()->setValue(hval);
      m_ui.table->verticalScrollBar()->setValue(vval);
      QApplication::restoreOverrideCursor();
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
