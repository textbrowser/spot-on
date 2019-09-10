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

#include <QDir>
#include <QFileDialog>
#include <QMessageBox>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "Common/spot-on-crypt.h"
#include "spot-on-defines.h"
#include "spot-on-encryptfile-page.h"

spoton_encryptfile_page::spoton_encryptfile_page(QWidget *parent):
  QWidget(parent)
{
  m_occupied = false;
  m_quit = false;
  ui.setupUi(this);
  ui.cancel->setVisible(false);
  ui.progressBar->setVisible(false);
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
  ui.gcm->setEnabled(false);
#endif
  connect(this,
	  SIGNAL(completed(const QString &)),
	  this,
	  SLOT(slotCompleted(const QString &)));
  connect(this,
	  SIGNAL(completed(const int)),
	  this,
	  SLOT(slotCompleted(const int)));
  connect(ui.cancel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCancel(void)));
  connect(ui.cipher,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotCipherTypeChanged(const QString &)));
  connect(ui.convert,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotConvert(void)));
  connect(ui.encrypt,
	  SIGNAL(toggled(bool)),
	  ui.sign,
	  SLOT(setEnabled(bool)));
  connect(ui.reset,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotReset(void)));
  connect(ui.select,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelect(void)));
  connect(ui.selectDestination,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelect(void)));
  ui.cipher->addItems(spoton_crypt::cipherTypes());
  ui.hash->addItems(spoton_crypt::hashTypes());

  if(ui.cipher->count() == 0)
    ui.cipher->addItem("n/a");

  if(ui.hash->count() == 0)
    ui.hash->addItem("n/a");
}

spoton_encryptfile_page::~spoton_encryptfile_page()
{
  m_future.cancel();
  m_future.waitForFinished();
}

bool spoton_encryptfile_page::occupied(void) const
{
  return m_future.isRunning() || m_occupied;
}

void spoton_encryptfile_page::abort(void)
{
  slotCancel();
}

void spoton_encryptfile_page::decrypt(const QString &fileName,
				      const QString &destination,
				      const QList<QVariant> &credentials,
				      const QString &modeOfOperation)
{
  QFile file1(fileName);
  QFile file2(destination);
  QString error("");
  bool sign = true;

  if(file1.open(QIODevice::ReadOnly) && file2.open(QIODevice::Truncate |
						   QIODevice::Unbuffered |
						   QIODevice::WriteOnly))
    {
      QByteArray bytes(1, 0);
      QByteArray hash(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES, 0);
      QByteArray hashes;
      qint64 rc = 0;

      rc = file1.read(bytes.data(), bytes.length());

      if(bytes.length() == rc)
	{
	  sign = bytes.mid(0, 1).toInt();
	  bytes.clear();

	  /*
	  ** 4 = length of the original buffer in bytes.
	  ** For Threefish, we append an extra block (32 bytes). The
	  ** extra block contains the length of the original buffer. Also,
	  ** an initialization vector has a length of 32 bytes for Threefish.
	  */

	  bytes.resize
	    (qMax(1024, 1024 * credentials.value(4).toInt()) +
	     (credentials.value(0).toString() == "threefish" ? (32 + 32) :
	      (static_cast<int> (spoton_crypt::
				 ivLength(credentials.value(0).toString())) +
	       4)));
	}
      else
	{
	  error = tr("File read error.");
	  goto done_label;
	}

      if(sign)
	{
	  emit status(tr("Verifying the hash of %1.").arg(fileName));
	  rc = file1.read(hash.data(),
			  spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES);

	  if(rc != spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES)
	    {
	      error = tr("File read failure.");
	      goto done_label;
	    }

	  while((rc = file1.read(bytes.data(), bytes.length())) > 0)
	    {
	      if(m_future.isCanceled())
		{
		  error = tr("Operation canceled.");
		  break;
		}

	      QByteArray data(bytes.mid(0, static_cast<int> (rc)));
	      spoton_crypt crypt(credentials.value(0).toString(),
				 credentials.value(1).toString(),
				 QByteArray(),
				 credentials.value(2).toByteArray(),
				 credentials.value(3).toByteArray(),
				 0,
				 0,
				 "",
				 modeOfOperation);

	      {
		QByteArray hash;
		bool ok = true;

		hash = crypt.keyedHash(data, &ok);

		if(!ok)
		  {
		    error = tr("Hash failure.");
		    break;
		  }
		else
		  hashes.append(hash);
	      }

	      emit completed
		(static_cast<int> (100.00 *
				   static_cast<double> (file1.pos()) /
				   static_cast<double>
				   (qMax(static_cast<qint64> (1),
					 file1.size()))));
	    }

	  if(error.isEmpty() && rc == -1)
	    error = tr("File read error.");

	  if(error.isEmpty())
	    {
	      bool ok = true;
	      spoton_crypt crypt(credentials.value(0).toString(),
				 credentials.value(1).toString(),
				 QByteArray(),
				 credentials.value(2).toByteArray(),
				 credentials.value(3).toByteArray(),
				 0,
				 0,
				 "",
				 modeOfOperation);

	      hashes = crypt.keyedHash(hashes, &ok);

	      if(!ok)
		error = tr("Hash failure.");
	      else
		{
		  if(!spoton_crypt::memcmp(hash, hashes))
		    error = tr("Incorrect signature.");
		}
	    }

	  if(!error.isEmpty())
	    goto done_label;
	}

      /*
      ** Seek to the data area.
      */

      if(!file1.seek(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES + 1))
	{
	  error = tr("File seek failure.");
	  goto done_label;
	}
      else
	emit completed(0);

      emit status(tr("Decrypting the file %1.").arg(fileName));

      QByteArray eKey(credentials.value(2).toByteArray());

      while((rc = file1.read(bytes.data(), bytes.length())) > 0)
	{
	  if(m_future.isCanceled())
	    {
	      error = tr("Operation canceled.");
	      break;
	    }

	  QByteArray data(bytes.mid(0, static_cast<int> (rc)));
	  bool ok = true;
	  spoton_crypt crypt(credentials.value(0).toString(),
			     credentials.value(1).toString(),
			     QByteArray(),
			     eKey,
			     credentials.value(3).toByteArray(),
			     0,
			     0,
			     "",
			     modeOfOperation);

	  data = crypt.decrypted(data, &ok);

	  if(!ok)
	    {
	      error = tr("Decryption failure.");
	      break;
	    }
	  else
	    {
	      if(gcry_kdf_derive(eKey.constData(),
				 static_cast<size_t> (eKey.length()),
				 GCRY_KDF_PBKDF2,
				 gcry_md_map_name(credentials.value(1).
						  toByteArray().constData()),
				 bytes.mid(0, static_cast<int> (rc)).
				 constData(),
				 static_cast<size_t> (bytes.
						      mid(0,
							  static_cast
							  <int> (rc)).
						      length()),
				 1,
				 static_cast<size_t> (eKey.length()),
				 eKey.data()) != 0)
		error = tr("gcry_kdf_derive() failure.");

	      if(error.isEmpty())
		rc = file2.write(data, data.length());
	      else
		break;
	    }

	  if(data.length() != rc)
	    {
	      error = tr("File write error.");
	      break;
	    }
	  else
	    emit completed
	      (static_cast<int> (100.00 *
				 static_cast<double> (file1.pos()) /
				 static_cast<double>
				 (qMax(static_cast<qint64> (1),
				       file1.size()))));
	}

      if(error.isEmpty() && rc == -1)
	error = tr("File read error.");
    }
  else
    error = tr("File open error.");

 done_label:
  file1.close();
  file2.close();

  if(error.isEmpty())
    if(!sign)
      error = "1"; // A signature was not provided.

  emit completed(error);
}

void spoton_encryptfile_page::encrypt(const bool sign,
				      const QString &fileName,
				      const QString &destination,
				      const QList<QVariant> &credentials,
				      const QString &modeOfOperation)
{
  QFile file1(fileName);
  QFile file2(destination);
  QString error("");

  if(file1.open(QIODevice::ReadOnly) && file2.open(QIODevice::Truncate |
						   QIODevice::Unbuffered |
						   QIODevice::WriteOnly))
    {
      QByteArray bytes;
      QByteArray hashes;
      qint64 rc = 0;

      bytes.append(QByteArray::number(sign));
      bytes.append
	(QByteArray(spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES, 0));
      rc = file2.write(bytes.constData(), bytes.length());

      if(bytes.length() != rc)
	{
	  error = tr("File write error.");
	  goto done_label;
	}

      bytes.clear();
      bytes.resize(qMax(1024, 1024 * credentials.value(4).toInt()));
      emit status(tr("Encrypting the file %1.").arg(fileName));

      QByteArray eKey(credentials.value(2).toByteArray());

      while((rc = file1.read(bytes.data(), bytes.length())) > 0)
	{
	  if(m_future.isCanceled())
	    {
	      error = tr("Operation canceled.");
	      break;
	    }

	  QByteArray data(bytes.mid(0, static_cast<int> (rc)));
	  bool ok = true;
	  spoton_crypt crypt(credentials.value(0).toString(),
			     credentials.value(1).toString(),
			     QByteArray(),
			     eKey,
			     credentials.value(3).toByteArray(),
			     0,
			     0,
			     "",
			     modeOfOperation);

	  data = crypt.encrypted(data, &ok);

	  if(!ok)
	    {
	      error = tr("Encryption failure.");
	      break;
	    }
	  else
	    {
	      if(gcry_kdf_derive(eKey.constData(),
				 static_cast<size_t> (eKey.length()),
				 GCRY_KDF_PBKDF2,
				 gcry_md_map_name(credentials.value(1).
						  toByteArray().constData()),
				 data.constData(),
				 static_cast<size_t> (data.length()),
				 1,
				 static_cast<size_t> (eKey.length()),
				 eKey.data()) != 0)
		error = tr("gcry_kdf_derive() failure.");

	      if(error.isEmpty())
		rc = file2.write(data, data.length());
	      else
		break;
	    }

	  if(data.length() != rc)
	    {
	      error = tr("File write error.");
	      break;
	    }
	  else
	    {
	      if(sign)
		{
		  QByteArray hash(crypt.keyedHash(data, &ok));

		  if(!ok)
		    {
		      error = tr("Hash failure.");
		      break;
		    }

		  hashes.append(hash);
		}

	      emit completed
		(static_cast<int> (100.00 *
				   static_cast<double> (file1.pos()) /
				   static_cast<double>
				   (qMax(static_cast<qint64> (1),
					 file1.size()))));
	    }
	}

      if(error.isEmpty() && rc == -1)
	error = tr("File read error.");

      if(error.isEmpty() && !hashes.isEmpty())
	{
	  bool ok = true;
	  spoton_crypt crypt(credentials.value(0).toString(),
			     credentials.value(1).toString(),
			     QByteArray(),
			     credentials.value(2).toByteArray(),
			     credentials.value(3).toByteArray(),
			     0,
			     0,
			     "",
			     modeOfOperation);

	  hashes = crypt.keyedHash(hashes, &ok);

	  if(!ok)
	    error = tr("Hash failure.");
	  else
	    {
	      if(!file2.seek(1))
		{
		  error = tr("File seek error.");
		  goto done_label;
		}

	      rc = file2.write(hashes.constData(), hashes.length());

	      if(hashes.length() != rc)
		error = tr("File write error.");
	    }
	}
    }
  else
    error = tr("File open error.");

 done_label:
  file1.close();
  file2.close();
  emit completed(error);
}

void spoton_encryptfile_page::slotCancel(void)
{
  m_quit = true;
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_future.cancel();
  m_future.waitForFinished();
  QApplication::restoreOverrideCursor();
}

void spoton_encryptfile_page::slotCipherTypeChanged(const QString &text)
{
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
  Q_UNUSED(text);
  ui.gcm->setEnabled(false);
#else
  if(text == "threefish")
    {
      ui.cbc->setChecked(true);
      ui.gcm->setEnabled(false);
    }
  else
    ui.gcm->setEnabled(true);
#endif
}

void spoton_encryptfile_page::slotCompleted(const QString &error)
{
  if(ui.directory_mode->isChecked())
    return;

  ui.cancel->setVisible(false);
  ui.convert->setEnabled(true);
  ui.progressBar->setVisible(false);
  ui.reset->setEnabled(true);
  ui.status_label->clear();

  if(error.length() == 1)
    ui.status_label->setText
      (tr("The conversion process completed successfully. A signature "
	  "was not discovered."));
  else if(error.isEmpty())
    ui.status_label->setText
      (tr("The conversion process completed successfully."));
  else
    ui.status_label->setText(error);
}

void spoton_encryptfile_page::slotCompleted(const int percentage)
{
  ui.progressBar->setValue(percentage);
}

void spoton_encryptfile_page::slotConvert(void)
{
  if(!m_future.isFinished())
    return;

  QFileInfo destination(ui.destination->text());
  QFileInfo fileInfo(ui.file->text());
  QList<QVariant> list;
  QPair<QByteArray, QByteArray> derivedKeys;
  QScopedPointer<QMessageBox> mb;
  QString error("");
  QString modeOfOperation("");
  QString password(ui.password->text());
  QString pin(ui.pin->text());

  if(destination.absoluteFilePath().isEmpty())
    {
      error = tr("Please provide a valid destination path.");
      goto done_label;
    }

  if(!fileInfo.isReadable())
    {
      error = tr("Please provide a valid origin path.");
      goto done_label;
    }

  if(ui.file_mode->isChecked())
    if(destination == fileInfo)
      {
	error = tr("The destination and origin should be distinct.");
	goto done_label;
      }

  if(password.length() < 16)
    {
      error = tr("Please provide a secret that contains at least "
		 "sixteen characters.");
      goto done_label;
    }

  if(pin.isEmpty())
    {
      error = tr("Please provide a PIN.");
      goto done_label;
    }

  mb.reset(new QMessageBox(this));
  mb->setIcon(QMessageBox::Question);
  mb->setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb->setText(tr("Continue with the conversion process?"));
  mb->setWindowIcon(windowIcon());
  mb->setWindowModality(Qt::ApplicationModal);
  mb->setWindowTitle(tr("%1: Confirmation").arg(SPOTON_APPLICATION_NAME));

  if(mb->exec() != QMessageBox::Yes)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  ui.status_label->setText
    (tr("Generating derived keys. Please be patient."));
  ui.status_label->repaint();
  derivedKeys = spoton_crypt::derivedKeys
    (ui.cipher->currentText(),
     ui.hash->currentText(),
     static_cast<unsigned long int> (ui.iteration_count->value()),
     password.toUtf8(),
     pin.toUtf8(),
     false,
     error);
  ui.status_label->clear();
  QApplication::restoreOverrideCursor();

  if(!error.isEmpty())
    {
      error = tr("An error occurred while deriving keys.");
      goto done_label;
    }

  list << ui.cipher->currentText();
  list << ui.hash->currentText();
  list << derivedKeys.first;
  list << derivedKeys.second;
  list << ui.readSize->currentText();
  ui.cancel->setVisible(true);
  ui.convert->setEnabled(false);
  ui.reset->setEnabled(false);
  ui.progressBar->setValue(0);
  ui.progressBar->setVisible(true);

  if(ui.cbc->isChecked())
    modeOfOperation = "cbc";
  else
    modeOfOperation = "gcm";

  m_occupied = true;
  m_quit = false;

  if(ui.directory_mode->isChecked())
    {
      QStringList filters;

      if(ui.decrypt->isChecked())
	filters << "*.enc";
      else
	filters << "*";

      QDir baseDir(destination.absoluteFilePath());
      QDir dir(fileInfo.absoluteFilePath());
      QFileInfoList files(dir.entryInfoList(filters, QDir::Files));

      while(true)
	{
	  repaint();
#ifndef Q_OS_MAC
	  QApplication::processEvents();
#endif

	  if(files.isEmpty() || m_quit)
	    break;
	  else if(m_future.isRunning())
	    continue;

	  QFileInfo fileInfo(files.takeFirst());

	  if(ui.decrypt->isChecked())
	    {
	      QString destination(baseDir.absolutePath());

	      destination.append(QDir::separator());
	      destination.append(fileInfo.fileName());

	      if(destination.endsWith(".enc"))
		destination = destination.mid(0, destination.length() - 4);

	      m_future = QtConcurrent::run
		(this, &spoton_encryptfile_page::decrypt,
		 fileInfo.absoluteFilePath(),
		 destination,
		 list,
		 modeOfOperation);
	    }
	  else
	    {
	      QString destination(baseDir.absolutePath());

	      destination.append(QDir::separator());
	      destination.append(fileInfo.fileName());
	      destination.append(".enc");
	      m_future = QtConcurrent::run
		(this, &spoton_encryptfile_page::encrypt,
		 ui.sign->isChecked(),
		 fileInfo.absoluteFilePath(),
		 destination,
		 list,
		 modeOfOperation);
	    }
        }

      ui.cancel->setVisible(false);
      ui.convert->setEnabled(true);
      ui.reset->setEnabled(true);
      ui.progressBar->setVisible(false);
      ui.status_label->clear();
    }
  else
    {
      if(ui.decrypt->isChecked())
	m_future = QtConcurrent::run
	  (this, &spoton_encryptfile_page::decrypt,
	   fileInfo.absoluteFilePath(),
	   destination.absoluteFilePath(),
	   list,
	   modeOfOperation);
      else
	m_future = QtConcurrent::run
	  (this, &spoton_encryptfile_page::encrypt,
	   ui.sign->isChecked(),
	   fileInfo.absoluteFilePath(),
	   destination.absoluteFilePath(),
	   list,
	   modeOfOperation);
    }

 done_label:
  m_occupied = false;

  if(!error.isEmpty())
    ui.status_label->setText(error);
}

void spoton_encryptfile_page::slotReset(void)
{
  if(!m_future.isFinished())
    return;

  ui.cbc->setChecked(true);
  ui.cipher->setCurrentIndex(0);
  ui.destination->clear();
  ui.encrypt->setChecked(true);
  ui.file->clear();
  ui.file_mode->setChecked(true);
  ui.hash->setCurrentIndex(0);
  ui.iteration_count->setValue(ui.iteration_count->minimum());
  ui.password->clear();
  ui.pin->clear();
  ui.readSize->setCurrentIndex(1);
  ui.sign->setChecked(true);
}

void spoton_encryptfile_page::slotSelect(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select File").
     arg(SPOTON_APPLICATION_NAME));

  if(sender() == ui.select)
    {
      if(ui.directory_mode->isChecked())
	dialog.setFileMode(QFileDialog::Directory);
      else
	dialog.setFileMode(QFileDialog::ExistingFile);
    }
  else
    {
      if(ui.directory_mode->isChecked())
	dialog.setFileMode(QFileDialog::Directory);
      else
	dialog.setFileMode(QFileDialog::AnyFile);
    }

  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);

  if(dialog.exec() == QDialog::Accepted)
    {
      if(sender() == ui.select)
	{
	  QString str(dialog.selectedFiles().value(0));

	  ui.file->setText(str);

	  if(ui.destination->text().trimmed().isEmpty())
	    {
	      if(ui.encrypt->isChecked())
		ui.destination->setText
		  (str + (ui.file_mode->isChecked() ? ".enc" : ""));
	      else if(str.endsWith(".enc") && ui.file_mode->isChecked())
		ui.destination->setText(str.mid(0, str.length() - 4));
	    }
	}
      else
	ui.destination->setText(dialog.selectedFiles().value(0));
    }
}
