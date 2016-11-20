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
  ui.participants->setColumnHidden
    (ui.participants->columnCount() - 1, true); // OID
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
  connect(ui.execute,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotExecute(void)));
  connect(ui.refresh,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefresh(void)));
  slotSetIcons();
}

spoton_smpwindow::~spoton_smpwindow()
{
  QMutableHashIterator<QString, spoton_smpwindow_smp *> it(m_smps);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
      it.remove();
    }
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
  statusBar()->showMessage
    (tr("A total of %1 SMP objects are registered.").arg(m_smps.size()));
  showNormal();
  activateWindow();
  raise();
  spoton_utilities::centerWidget(this, parent);
}

void spoton_smpwindow::showError(const QString &error)
{
  if(QApplication::overrideCursor() &&
     QApplication::overrideCursor()->shape() == Qt::WaitCursor)
    QApplication::restoreOverrideCursor();

  QMessageBox::critical
    (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
}

void spoton_smpwindow::slotClose(void)
{
  close();
}

void spoton_smpwindow::slotExecute(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QModelIndexList list
    (ui.participants->selectionModel()->selectedRows(1)); // Public Key Type
  QString error("");
  QString keyType(list.value(0).data().toString());
  spoton_crypt *s_crypt1 = spoton::instance() ? spoton::instance()->
    crypts().value(keyType, 0) : 0;
  spoton_crypt *s_crypt2 = spoton::instance() ? spoton::instance()->
    crypts().value(keyType + "-signature", 0) : 0;

  if(!s_crypt1 || !s_crypt2)
    {
      showError(tr("Invalid spoton_crypt object(s). This is a fatal flaw."));
      return;
    }

  QSslSocket *kernelSocket = spoton::instance() ?
    spoton::instance()->kernelSocket() : 0;

  if(!kernelSocket)
    {
      error = tr("The interface's kernel socket is zero.");
      showError(error);
      return;
    }
  else if(kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      showError(error);
      return;
    }
  else if(!kernelSocket->isEncrypted())
    {
      error = tr("The connection to the kernel is not encrypted.");
      showError(error);
      return;
    }

  QString secret(ui.secret->text().trimmed());

  if(secret.isEmpty())
    {
      error = tr("Please provide a non-empty secret.");
      showError(error);
      return;
    }

  list = ui.participants->selectionModel()->
    selectedRows(ui.participants->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      error = tr("Please select at least one participant.");
      showError(error);
      return;
    }

  QByteArray publicKey;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("SELECT public_key FROM friends_public_keys "
		      "WHERE OID = ?");
	query.addBindValue(list.value(0).data().toString());

	if(query.exec())
	  if(query.next())
	    publicKey = s_crypt1->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(publicKey.isEmpty())
    {
      error = tr("A database error occurred while attempting to retrieve "
		 "the specified participant's public key.");
      showError(error);
      return;
    }

  bool ok = true;
  spoton_smpwindow_smp *smp = m_smps.value(publicKey, 0);

  if(!smp)
    {
      smp = new spoton_smpwindow_smp(secret);
      smp->m_keyType = keyType;
      smp->m_publicKey = publicKey;
      m_smps[publicKey] = smp;
      statusBar()->showMessage(tr("A total of %1 SMP objects are "
				  "registered.").arg(m_smps.size()));
    }

  smp->m_smp->initialize();

  QList<QByteArray> values(smp->m_smp->step1(&ok));

  if(!ok)
    {
      error = tr("An error occurred with spoton_smp::step1().");
      showError(error);
      return;
    }

  QByteArray data;

  {
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << values;

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	showError(error);
	return;
      }
  }

  QByteArray myPublicKey;
  QByteArray myPublicKeyHash;

  myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    {
      error = tr("Unable to gather your public key.");
      showError(error);
      return;
    }

  myPublicKeyHash = spoton_crypt::sha512Hash(myPublicKey, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::sha512Hash().");
      showError(error);
      return;
    }

  QByteArray encryptionKey;
  QByteArray hashKey;

  hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
  hashKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (hashKey.length()));
  encryptionKey.resize(32);
  encryptionKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (encryptionKey.length()));

  QByteArray keyInformation;

  {
    QDataStream stream(&keyInformation, QIODevice::WriteOnly);

    stream << QByteArray("0092")
	   << encryptionKey
	   << hashKey
	   << QByteArray("aes256")
	   << QByteArray("sha512");

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	showError(error);
	return;
      }
  }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (keyInformation, publicKey, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::publicKeyEncrypt().");
      showError(error);
      return;
    }

  QByteArray signature;
  QDateTime dateTime(QDateTime::currentDateTime());

  signature = s_crypt2->digitalSignature
    ("0092" +
     encryptionKey +
     hashKey +
     "aes256" +
     "sha512" +
     myPublicKeyHash +
     data +
     dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1(),
     &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::digitalSignature().");
      showError(error);
      return;
    }

  QByteArray bytes;

  {
    QDataStream stream(&bytes, QIODevice::WriteOnly);

    stream << myPublicKeyHash
	   << data
	   << dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1()
	   << signature;

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	showError(error);
	return;
      }
  }

  spoton_crypt crypt("aes256",
		     "sha512",
		     QByteArray(),
		     encryptionKey,
		     hashKey,
		     0,
		     0,
		     "");

  bytes = crypt.encrypted(bytes, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::encrypted().");
      showError(error);
      return;
    }

  QByteArray messageCode(crypt.keyedHash(keyInformation + bytes, &ok));

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::keyedHash().");
      showError(error);
      return;
    }

  QString name
    (ui.participants->selectionModel()->selectedRows(0).value(0).data().
     toString());

  bytes = "smp_" + keyType.toLatin1().toBase64() + "_" +
    name.toUtf8().toBase64() + "_" +
    keyInformation.toBase64() + "_" +
    bytes.toBase64() + "_" +
    messageCode.toBase64() + "\n";

  if(kernelSocket->write(bytes.constData(), bytes.length()) != bytes.length())
    {
      error = tr("An error occurred while writing to the kernel socket.");
      showError(error);
      return;
    }

  QString message;

  message = tr("%1: Contacted participant %2... Please wait for a response.").
    arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).arg(name);
  ui.output->append(message);
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotRefresh(void)
{
  spoton_crypt *crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!crypt)
    {
      showError(tr("Invalid spoton_crypt object. This is a fatal flaw."));
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
		      "public_key, "
		      "OID "
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

	      QTableWidgetItem *item = new QTableWidgetItem
		(QString::
		 number(query.value(query.record().count() - 1).toLongLong()));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      ui.participants->setItem
		(row, ui.participants->columnCount() - 1, item);
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
