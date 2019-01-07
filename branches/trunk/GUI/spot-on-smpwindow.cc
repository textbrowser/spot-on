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
  m_ui.setupUi(this);
  m_ui.participants->setColumnHidden
    (m_ui.participants->columnCount() - 1, true); // OID
  m_ui.secrets->setColumnHidden(0, true); // Stream
  m_ui.secrets->setColumnHidden(m_ui.secrets->columnCount() - 1, true); // OID
  setWindowTitle(tr("%1: SMP").arg(SPOTON_APPLICATION_NAME));
  connect(m_ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(m_ui.action_Purge_SMP_State_Machines,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotPurgeSMPStateMachines(void)));
  connect(m_ui.clear,
	  SIGNAL(clicked(void)),
	  m_ui.output,
	  SLOT(clear(void)));
  connect(m_ui.execute,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotExecute(void)));
  connect(m_ui.generate,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotGenerateData(void)));
  connect(m_ui.prepare_smp_object,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotPrepareSMPObject(void)));
  connect(m_ui.refresh,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefresh(void)));
  connect(m_ui.remove,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRemove(void)));
  slotSetIcons();
  m_ui.generator_hash_type->addItems(spoton_crypt::hashTypes());

  if(m_ui.generator_hash_type->count() == 0)
    m_ui.generator_hash_type->addItem("n/a");

  m_ui.transfer_cipher_type->addItems(spoton_crypt::cipherTypes());

  if(m_ui.transfer_cipher_type->count() == 0)
    m_ui.transfer_cipher_type->addItem("n/a");

  m_ui.transfer_hash_type->addItems(spoton_crypt::hashTypes());

  if(m_ui.transfer_hash_type->count() == 0)
    m_ui.transfer_hash_type->addItem("n/a");

  QSettings settings;
  QString str("");

  str = settings.value("smpwindow/generator_hash_type", "sha512").toString().
    toLower().trimmed();

  if(m_ui.generator_hash_type->findText(str) >= 0)
    m_ui.generator_hash_type->setCurrentIndex
      (m_ui.generator_hash_type->findText(str));
  else
    m_ui.generator_hash_type->setCurrentIndex(0);

  m_ui.generator_stream_size->setValue
    (settings.value("smpwindow/generator_stream_size", 100).toInt());
  m_ui.iteration_count->setValue
    (settings.value("smpwindow/iteration_count", 25000).toInt());
  str = settings.value("smpwindow/transfer_cipher_type", "aes256").toString().
    toLower().trimmed();

  if(m_ui.transfer_cipher_type->findText(str) >= 0)
    m_ui.transfer_cipher_type->setCurrentIndex
      (m_ui.transfer_cipher_type->findText(str));
  else
    m_ui.transfer_cipher_type->setCurrentIndex(0);

  str = settings.value("smpwindow/transfer_hash_type", "sha512").toString().
    toLower().trimmed();

  if(m_ui.transfer_hash_type->findText(str) >= 0)
    m_ui.transfer_hash_type->setCurrentIndex
      (m_ui.transfer_hash_type->findText(str));
  else
    m_ui.transfer_hash_type->setCurrentIndex(0);

  /*
  ** Avoid signals.
  */

  connect(m_ui.generator_hash_type,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotSaveCombinationBoxOption(const QString &)));
  connect(m_ui.generator_stream_size,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSaveSpinBoxOption(int)));
  connect(m_ui.iteration_count,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotSaveSpinBoxOption(int)));
  connect(m_ui.transfer_cipher_type,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotSaveCombinationBoxOption(const QString &)));
  connect(m_ui.transfer_hash_type,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotSaveCombinationBoxOption(const QString &)));
}

spoton_smpwindow::~spoton_smpwindow()
{
  QMutableHashIterator<QByteArray, spoton_smpwindow_smp *> it(m_smps);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
      it.remove();
    }
}

QMap<QString, QByteArray> spoton_smpwindow::streams
(const QStringList &keyTypes) const
{
  QMap<QString, QByteArray> map;

  for(int i = 0; i < m_ui.secrets->rowCount(); i++)
    if(m_ui.secrets->item(i, 0) &&
       m_ui.secrets->item(i, 2) &&
       m_ui.secrets->item(i, 3))
      if(keyTypes.contains(m_ui.secrets->item(i, 2)->text()))
	map[m_ui.secrets->item(i, 3)->text()] = m_ui.secrets->item(i, 0)->
	  text().toLatin1();

  return map;
}

void spoton_smpwindow::generateSecretData(spoton_smpwindow_smp *smp)
{
  QDateTime dateTime(QDateTime::currentDateTime());
  QString message("");

  if(!smp)
    {
      message = tr
	("%1: The smp object is zero in generateSecretData().").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value(smp->m_keyType, 0) : 0;

  if(!s_crypt)
    {
      message = tr
	("%1: The s_crypt object is zero in generateSecretData().").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  QByteArray myPublicKey;
  bool ok = true;

  myPublicKey = s_crypt->publicKey(&ok);

  if(!ok)
    {
      message = tr
	("%1: An error occurred with spoton_crypt::publicKey() in "
	 "generateSecretData().").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  QByteArray salt(spoton_misc::xor_arrays(myPublicKey, smp->m_publicKey));
  QByteArray stream(m_ui.generator_stream_size->value(), 0);
  QString guess(smp->m_smp->guessString());

  guess.append(smp->m_keyType);

  if(gcry_kdf_derive(guess.toUtf8().constData(),
		     static_cast<size_t> (guess.toUtf8().length()),
		     GCRY_KDF_PBKDF2,
		     gcry_md_map_name(m_ui.generator_hash_type->
				      currentText().toLatin1().
				      constData()),
		     salt.constData(),
		     static_cast<size_t> (salt.length()),
		     static_cast<unsigned long int> (m_ui.iteration_count->
						     value()),
		     static_cast<size_t> (stream.length()),
		     stream.data()) != 0)
    {
      message = tr
	("%1: An error occurred with gcry_kdf_derive() in "
	 "generateSecretData().").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "secrets.db");

    if(db.open())
      {
	QByteArray hint;
	QSqlQuery query(db);
	bool ok = true;

	hint.append(smp->m_name);
	hint.append(" - ");
	hint.append(smp->m_keyType);
	hint.append(" - ");
	hint.append(QDateTime::currentDateTime().
		    toString("yyyy-MM-dd hh:mm:ss"));
	query.prepare("INSERT INTO secrets "
		      "(generated_data, generated_data_hash, hint, key_type) "
		      "VALUES (?, ?, ?, ?)");
	query.addBindValue(s_crypt->encryptedThenHashed(stream, &ok).
			   toBase64());

	if(ok)
	  query.addBindValue(s_crypt->keyedHash(stream, &ok).toBase64());

	if(ok)
	  query.addBindValue(s_crypt->encryptedThenHashed(hint, &ok).
			     toBase64());

	if(ok)
	  query.addBindValue(s_crypt->encryptedThenHashed(smp->m_keyType.
							  toLatin1(), &ok).
			     toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_smpwindow::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_smpwindow::populateSecrets(void)
{
  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!s_crypt)
    return;

  m_ui.secrets->setRowCount(0);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "secrets.db");

    if(db.open())
      {
	m_ui.secrets->setSortingEnabled(false);

	QSqlQuery query(db);
	int row = -1;
	int totalRows = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) FROM secrets"))
	  if(query.next())
	    m_ui.secrets->setRowCount(query.value(0).toInt());

	if(query.exec("SELECT "
		      "generated_data, "
		      "generated_data_hash, "
		      "key_type, "
		      "hint, "
		      "OID "
		      "FROM secrets"))
	  while(query.next() && totalRows < m_ui.secrets->rowCount())
	    {
	      row += 1;
	      totalRows += 1;

	      for(int i = 0; i < 4; i++)
		{
		  QByteArray bytes;
		  QTableWidgetItem *item = 0;
		  bool ok = true;

		  if(i != 1)
		    bytes = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::
		       fromBase64(query.value(i).toByteArray()), &ok);
		  else
		    bytes = QByteArray::fromBase64
		      (query.value(i).toByteArray()).toHex();

		  if(ok)
		    {
		      if(i == 0)
			item = new QTableWidgetItem
			  (bytes.toBase64().constData());
		      else
			item = new QTableWidgetItem(bytes.constData());
		    }
		  else
		    item = new QTableWidgetItem(tr("error"));

		  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		  m_ui.secrets->setItem(row, i, item);
		}

	      QTableWidgetItem *item = new QTableWidgetItem
		(QString::
		 number(query.value(query.record().count() - 1).toLongLong()));

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.secrets->setItem(row, m_ui.secrets->columnCount() - 1, item);
	    }

	m_ui.secrets->setRowCount(totalRows);
	m_ui.secrets->setSortingEnabled(true);
	m_ui.secrets->horizontalHeader()->setSortIndicator
	  (1, Qt::AscendingOrder);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_smpwindow::show(QWidget *parent)
{
  if(!isVisible())
    slotRefresh();

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
    (m_ui.participants->selectionModel()->selectedRows(1)); // Public Key Type
  QString keyType(list.value(0).data().toString());
  spoton_crypt *s_crypt1 = spoton::instance() ? spoton::instance()->
    crypts().value(keyType, 0) : 0;
  spoton_crypt *s_crypt2 = spoton::instance() ? spoton::instance()->
    crypts().value(keyType + "-signature", 0) : 0;

  if(!s_crypt1 || !s_crypt2)
    {
      showError(tr("Invalid spoton_crypt object(s). This is a fatal flaw. "
		   "Is a participant selected?"));
      return;
    }

  QSslSocket *kernelSocket = spoton::instance() ?
    spoton::instance()->kernelSocket() : 0;
  QString error("");

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
  else if(!kernelSocket->isEncrypted() &&
	  kernelSocket->property("key_size").toInt() > 0)
    {
      error = tr("The connection to the kernel is not encrypted.");
      showError(error);
      return;
    }

  QString secret(m_ui.secret->text().trimmed());

  if(secret.isEmpty())
    {
      error = tr("Please provide a non-empty secret.");
      showError(error);
      return;
    }

  list = m_ui.participants->selectionModel()->
    selectedRows(m_ui.participants->columnCount() - 1); // OID

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

  QByteArray bytes;
  bool ok = true;

  bytes = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::sha512Hash().");
      showError(error);
      return;
    }

  QString name
    (m_ui.participants->selectionModel()->selectedRows(0).value(0).data().
     toString());
  spoton_smpwindow_smp *smp = m_smps.value(bytes, 0);

  if(!smp)
    {
      smp = new spoton_smpwindow_smp(secret);
      smp->m_keyType = keyType;
      smp->m_name = name;
      smp->m_publicKey = publicKey;
      m_smps[bytes] = smp;
      statusBar()->showMessage(tr("A total of %1 SMP objects are "
				  "registered.").arg(m_smps.size()));
    }
  else
    smp->m_smp->setGuess(secret);

  smp->m_cache.clear();
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
	   << m_ui.transfer_cipher_type->currentText().toLatin1()
	   << m_ui.transfer_hash_type->currentText().toLatin1();

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	showError(error);
	return;
      }
  }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (keyInformation, qCompress(publicKey), publicKey.mid(0, 25), &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::publicKeyEncrypt().");
      showError(error);
      return;
    }

  QByteArray signature;
  QDateTime dateTime(QDateTime::currentDateTime());
  QByteArray recipientDigest(spoton_crypt::sha512Hash(publicKey, &ok));

  signature = s_crypt2->digitalSignature
    ("0092" +
     encryptionKey +
     hashKey +
     m_ui.transfer_cipher_type->currentText().toLatin1() +
     m_ui.transfer_hash_type->currentText().toLatin1() +
     myPublicKeyHash +
     data +
     dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1() +
     recipientDigest,
     &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::digitalSignature().");
      showError(error);
      return;
    }

  bytes.clear();

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

  spoton_crypt crypt(m_ui.transfer_cipher_type->currentText(),
		     m_ui.transfer_hash_type->currentText(),
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

  QString message("");

  message = tr("%1: Contacting participant %2... Please wait for a response.").
    arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).arg(name);
  m_ui.output->append(message);
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotGenerateData(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!s_crypt)
    {
      showError(tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QByteArray publicKey;
  QString connectionName("");
  QString error("");

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
	query.addBindValue
	  (m_ui.participants->selectionModel()->
	   selectedRows(m_ui.participants->columnCount() - 1).value(0).data().
	   toString()); // OID

	if(query.exec())
	  if(query.next())
	    publicKey = s_crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  QString keyType
    (m_ui.participants->selectionModel()->selectedRows(1).value(0).data().
     toString());
  QString name
    (m_ui.participants->selectionModel()->selectedRows(0).value(0).data().
     toString());

  if(keyType.isEmpty() || name.isEmpty() || publicKey.isEmpty())
    {
      error = tr("Please select a participant.");
      showError(error);
      return;
    }

  QString secret(m_ui.secret->text().trimmed());

  if(secret.isEmpty())
    {
      error = tr("Please provide a non-empty secret.");
      showError(error);
      return;
    }

  QScopedPointer<spoton_smpwindow_smp> smp;

  smp.reset(new spoton_smpwindow_smp(secret));
  smp->m_keyType = keyType;
  smp->m_name = name;
  smp->m_publicKey = publicKey;
  generateSecretData(smp.data());
  populateSecrets();
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotPrepareSMPObject(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!s_crypt)
    {
      showError(tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QModelIndexList list
    (m_ui.participants->selectionModel()->selectedRows(1)); // Public Key Type
  QString error("");
  QString keyType(list.value(0).data().toString());
  QString secret(m_ui.secret->text().trimmed());

  if(secret.isEmpty())
    {
      error = tr("Please provide a non-empty secret.");
      showError(error);
      return;
    }

  list = m_ui.participants->selectionModel()->
    selectedRows(m_ui.participants->columnCount() - 1); // OID

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
	    publicKey = s_crypt->decryptedAfterAuthenticated
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

  QByteArray bytes;
  bool ok = true;

  bytes = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::sha512Hash().");
      showError(error);
      return;
    }

  spoton_smpwindow_smp *smp = m_smps.value(bytes, 0);

  if(!smp)
    {
      smp = new spoton_smpwindow_smp(secret);
      smp->m_keyType = keyType;
      smp->m_name = m_ui.participants->selectionModel()->selectedRows(0).
	value(0).data().toString();
      smp->m_publicKey = publicKey;
      m_smps[bytes] = smp;
      statusBar()->showMessage(tr("A total of %1 SMP objects are "
				  "registered.").arg(m_smps.size()));
    }
  else
    smp->m_smp->setGuess(secret);

  smp->m_cache.clear();
  smp->m_smp->setStep0();
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotPurgeSMPStateMachines(void)
{
  QMutableHashIterator<QByteArray, spoton_smpwindow_smp *> it(m_smps);

  while(it.hasNext())
    {
      it.next();
      delete it.value();
      it.remove();
    }

  statusBar()->showMessage(tr("A total of 0 SMP objects are registered."));
}

void spoton_smpwindow::slotRefresh(void)
{
  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!s_crypt)
    {
      showError(tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_ui.participants->setRowCount(0);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	m_ui.participants->setSortingEnabled(false);

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
	  (s_crypt->keyedHash(QByteArray("chat"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(QByteArray("email"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(QByteArray("open-library"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(QByteArray("poptastic"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(QByteArray("rosetta"), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QList<QByteArray> list;

	      for(int i = 0; i < 3; i++)
		{
		  QByteArray bytes;
		  bool ok = true;

		  bytes = s_crypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(i).toByteArray()), &ok);

		  if(ok)
		    {
		      list << bytes;

		      if(list.value(1) == "poptastic" &&
			 list.value(2).endsWith("-poptastic"))
			{
			  list.clear();
			  break;
			}
		    }
		  else
		    list << tr("error").toUtf8();
		}

	      if(list.isEmpty())
		continue;

	      m_ui.participants->setRowCount(row + 1);

	      for(int i = 0; i < list.size(); i++)
		{
		  QTableWidgetItem *item = 0;

		  item = new QTableWidgetItem(list.at(i).constData());

		  if(i == 2)
		    item->setText
		      (spoton_crypt::publicKeyAlgorithm(list.at(i)));

		  item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		  m_ui.participants->setItem(row, i, item);
		}

	      QTableWidgetItem *item = 0;

	      item = new QTableWidgetItem
		(QString::
		 number(query.value(query.record().count() - 1).toLongLong()));
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.participants->setItem
		(row, m_ui.participants->columnCount() - 1, item);
	      row += 1;
	    }

	m_ui.participants->setSortingEnabled(true);
	m_ui.participants->horizontalHeader()->setSortIndicator
	  (0, Qt::AscendingOrder);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateSecrets();
  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotRemove(void)
{
  QModelIndexList list
    (m_ui.secrets->selectionModel()->
     selectedRows(m_ui.secrets->columnCount() - 1)); // OID

  if(list.isEmpty())
    return;

  spoton_crypt *s_crypt = spoton::instance() ? spoton::instance()->
    crypts().value("chat", 0) : 0;

  if(!s_crypt)
    {
      showError(tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  QMessageBox mb(this);

  mb.setIcon(QMessageBox::Question);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected secret?"));
  mb.setWindowIcon(windowIcon());
  mb.setWindowModality(Qt::WindowModal);
  mb.setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "secrets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM secrets WHERE OID = ?");
	query.addBindValue(list.value(0).data().toString());

	if(query.exec())
	  m_ui.secrets->removeRow(list.value(0).row());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_smpwindow::slotSMPMessageReceivedFromKernel
(const QByteArrayList &list)
{
  QDateTime dateTime(QDateTime::currentDateTime());
  QString message("");
  spoton_smpwindow_smp *smp = m_smps.value(list.value(0), 0);

  if(!smp)
    {
      message = tr
	("%1: Received a response from an unknown participant... Ignoring.").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  spoton_crypt *s_crypt1 = spoton::instance() ? spoton::instance()->
    crypts().value(smp->m_keyType, 0) : 0;
  spoton_crypt *s_crypt2 = spoton::instance() ? spoton::instance()->
    crypts().value(smp->m_keyType + "-signature", 0) : 0;

  if(!s_crypt1 || !s_crypt2)
    {
      message = tr("%1: Invalid spoton_crypt object(s). This is a fatal flaw.").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss"));
      m_ui.output->append(message);
      return;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QList<QByteArray> values;

  {
    QByteArray bytes(list.value(1));

    if(smp->m_cache.contains(s_crypt1->keyedHash(bytes, 0)))
      {
	QApplication::restoreOverrideCursor();
	return;
      }
    else
      smp->m_cache[s_crypt1->keyedHash(bytes, 0)] = 0;

    QDataStream stream(&bytes, QIODevice::ReadOnly);

    stream >> values;
  }

  QString name(smp->m_name);

  message = tr("%1: Received a response from %2. Currently at step %3.").
    arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
    arg(name).
    arg(smp->m_smp->step());
  m_ui.output->append(message);

  QByteArray bytes;
  QByteArray data;
  QByteArray encryptionKey;
  QByteArray hashKey;
  QByteArray keyInformation;
  QByteArray messageCode;
  QByteArray myPublicKey;
  QByteArray myPublicKeyHash;
  QByteArray recipientDigest;
  QByteArray signature;
  QScopedPointer<spoton_crypt> crypt;
  QSslSocket *kernelSocket = spoton::instance() ?
    spoton::instance()->kernelSocket() : 0;
  QString error("");
  bool ok = true;
  bool passed = false;

  if(!kernelSocket)
    {
      error = tr("The interface's kernel socket is zero.");
      goto done_label;
    }
  else if(kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("The interface is not connected to the kernel.");
      goto done_label;
    }
  else if(!kernelSocket->isEncrypted() &&
	  kernelSocket->property("key_size").toInt() > 0)
    {
      error = tr("The connection to the kernel is not encrypted.");
      goto done_label;
    }

  values = smp->m_smp->nextStep(values, &ok, &passed);

  if(!ok || smp->m_smp->step() == 4 || smp->m_smp->step() == 5)
    {
      if(smp->m_smp->step() == 4 || smp->m_smp->step() == 5)
	{
	  if(passed)
	    {
	      message = tr("%1: Verified secrets with %2.").
		arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
		arg(name);
	      smp->m_cache.clear();
	      smp->m_smp->setStep0();
	      generateSecretData(smp);
	      populateSecrets();
	    }
	  else
	    message = tr("%1: SMP verification with %2 has failed. "
			 "The secrets are not congruent.").
	      arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
	      arg(name);
	}
      else
	message = tr("%1: SMP verification with %2 experienced a protocol "
		     "failure. Current step is %3. "
		     "The specific state machine has been reset.").
	  arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
	  arg(name).
	  arg(smp->m_smp->step());

      if(!ok)
	{
	  smp->m_cache.clear();
	  smp->m_smp->initialize();
	}

      m_ui.output->append(message);
    }

  if(values.isEmpty())
    goto done_label;

  {
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << values;

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	goto done_label;
      }
  }

  myPublicKey = s_crypt1->publicKey(&ok);

  if(!ok)
    {
      error = tr("Unable to gather your public key.");
      goto done_label;
    }

  myPublicKeyHash = spoton_crypt::sha512Hash(myPublicKey, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::sha512Hash().");
      goto done_label;
    }

  recipientDigest = spoton_crypt::sha512Hash(smp->m_publicKey, &ok);

  if(!ok)
    {
      error = tr("A failure occurred while computing the SHA-512 "
		 "digest of the recipient's public key.");
      goto done_label;
    }

  hashKey.resize(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);
  hashKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (hashKey.length()));
  encryptionKey.resize(32);
  encryptionKey = spoton_crypt::strongRandomBytes
    (static_cast<size_t> (encryptionKey.length()));

  {
    QDataStream stream(&keyInformation, QIODevice::WriteOnly);

    stream << QByteArray("0092")
	   << encryptionKey
	   << hashKey
	   << m_ui.transfer_cipher_type->currentText().toLatin1()
	   << m_ui.transfer_hash_type->currentText().toLatin1();

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	goto done_label;
      }
  }

  keyInformation = spoton_crypt::publicKeyEncrypt
    (keyInformation,
     qCompress(smp->m_publicKey),
     smp->m_publicKey.mid(0, 25),
     &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::publicKeyEncrypt().");
      goto done_label;
    }

  signature = s_crypt2->digitalSignature
    ("0092" +
     encryptionKey +
     hashKey +
     m_ui.transfer_cipher_type->currentText().toLatin1() +
     m_ui.transfer_hash_type->currentText().toLatin1() +
     myPublicKeyHash +
     data +
     dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1() +
     recipientDigest,
     &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::digitalSignature().");
      showError(error);
      return;
    }

  {
    QDataStream stream(&bytes, QIODevice::WriteOnly);

    stream << myPublicKeyHash
	   << data
	   << dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1()
	   << signature;

    if(stream.status() != QDataStream::Ok)
      {
	error = tr("QDataStream error.");
	goto done_label;
      }
  }

  crypt.reset(new spoton_crypt(m_ui.transfer_cipher_type->currentText(),
			       m_ui.transfer_hash_type->currentText(),
			       QByteArray(),
			       encryptionKey,
			       hashKey,
			       0,
			       0,
			       ""));

  bytes = crypt->encrypted(bytes, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::encrypted().");
      goto done_label;
    }

  messageCode = crypt->keyedHash(keyInformation + bytes, &ok);

  if(!ok)
    {
      error = tr("An error occurred with spoton_crypt::keyedHash().");
      goto done_label;
    }

  bytes = "smp_" + smp->m_keyType.toLatin1().toBase64() + "_" +
    name.toUtf8().toBase64() + "_" +
    keyInformation.toBase64() + "_" +
    bytes.toBase64() + "_" +
    messageCode.toBase64() + "\n";

  if(kernelSocket->write(bytes.constData(), bytes.length()) != bytes.length())
    {
      error = tr("An error occurred while writing to the kernel socket.");
      goto done_label;
    }
  else
    {
      message = tr("%1: Submitted a response to %2.").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
	arg(name);
      m_ui.output->append(message);
    }

 done_label:

  if(!error.isEmpty())
    {
      message = tr("%1: An error (%2) occurred while attempting to prepare "
		   "the next SMP protocol step with %3.").
	arg(dateTime.toString("MM/dd/yyyy hh:mm:ss")).
	arg(error).
	arg(name);
      m_ui.output->append(message);
    }

  QApplication::restoreOverrideCursor();
}

void spoton_smpwindow::slotSaveCombinationBoxOption(const QString &text)
{
  QString str("");

  if(sender() == m_ui.generator_hash_type)
    str = "smpwindow/generator_hash_type";
  else if(sender() == m_ui.transfer_cipher_type)
    str = "smpwindow/transfer_cipher_type";
  else if(sender() == m_ui.transfer_hash_type)
    str = "smpwindow/transfer_hash_type";

  if(str.isEmpty())
    return;

  QSettings settings;

  settings.setValue(str, text);
}

void spoton_smpwindow::slotSaveSpinBoxOption(int value)
{
  QString str("");

  if(sender() == m_ui.generator_stream_size)
    str = "smpwindow/generator_stream_size";
  else if(sender() == m_ui.iteration_count)
    str = "smpwindow/iteration_count";

  if(str.isEmpty())
    return;

  QSettings settings;

  settings.setValue(str, value);
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
