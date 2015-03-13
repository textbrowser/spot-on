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
#include <QKeyEvent>
#include <QMessageBox>
#include <QSettings>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-defines.h"
#include "spot-on-encryptfile.h"

spoton_encryptfile::spoton_encryptfile(void):QMainWindow()
{
  ui.setupUi(this);
  ui.cancel->setVisible(false);
  ui.progressBar->setVisible(false);
  setWindowTitle
    (tr("%1: File Encryption").
     arg(SPOTON_APPLICATION_NAME));
#if !defined(GCRYPT_VERSION_NUMBER) || GCRYPT_VERSION_NUMBER < 0x010600
  ui.gcm->setEnabled(false);
#endif
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#if QT_VERSION >= 0x050000
  setWindowFlags(windowFlags() & ~Qt::WindowFullscreenButtonHint);
#endif
  statusBar()->setSizeGripEnabled(false);
#endif
  connect(this,
	  SIGNAL(completed(const QString &)),
	  this,
	  SLOT(slotCompleted(const QString &)));
  connect(this,
	  SIGNAL(completed(const int)),
	  this,
	  SLOT(slotCompleted(const int)));
  connect(this,
	  SIGNAL(status(const QString &)),
	  this,
	  SLOT(slotStatus(const QString &)));
  connect(ui.action_Close,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotClose(void)));
  connect(ui.cancel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCancel(void)));
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

  slotSetIcons();
}

spoton_encryptfile::~spoton_encryptfile()
{
  m_future.cancel();
  m_future.waitForFinished();
}

void spoton_encryptfile::slotCancel(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_future.cancel();
  m_future.waitForFinished();
  QApplication::restoreOverrideCursor();
}

void spoton_encryptfile::slotClose(void)
{
  close();
}

void spoton_encryptfile::show(QWidget *parent)
{
  if(parent)
    {
      QPoint p(parent->pos());
      int X = 0;
      int Y = 0;

      if(parent->width() >= width())
	X = p.x() + (parent->width() - width()) / 2;
      else
	X = p.x() - (width() - parent->width()) / 2;

      if(parent->height() >= height())
	Y = p.y() + (parent->height() - height()) / 2;
      else
	Y = p.y() - (height() - parent->height()) / 2;

      move(X, Y);
    }

  QMainWindow::show();
  raise();
}

void spoton_encryptfile::keyPressEvent(QKeyEvent *event)
{
  if(event)
    {
      if(event->key() == Qt::Key_Escape)
	close();
    }

  QMainWindow::keyPressEvent(event);
}

void spoton_encryptfile::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nuove").toString().
		  toLower());

  if(!(iconSet == "everaldo" || iconSet == "nouve" || iconSet == "nuvola"))
    iconSet = "nouve";
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000 && QT_VERSION < 0x050300
bool spoton_encryptfile::event(QEvent *event)
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

void spoton_encryptfile::slotConvert(void)
{
  if(!m_future.isFinished())
    return;

  QFileInfo destination(ui.destination->text());
  QFileInfo fileInfo(ui.file->text());
  QList<QVariant> list;
  QPair<QByteArray, QByteArray> derivedKeys;
  QString error("");
  QString modeOfOperation("");
  QString password(ui.password->text());
  QString pin(ui.pin->text());

  if(destination.absoluteFilePath().isEmpty())
    {
      error = tr("Please provide a valid destination file.");
      goto done_label;
    }

  if(!fileInfo.isReadable())
    {
      error = tr("Please provide a valid origin file.");
      goto done_label;
    }

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

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  statusBar()->showMessage
    (tr("Generating derived keys. Please be patient."));
  statusBar()->repaint();
  derivedKeys = spoton_crypt::derivedKeys(ui.cipher->currentText(),
					  ui.hash->currentText(),
					  15000,
					  password.toUtf8(),
					  pin.toUtf8(),
					  error);
  statusBar()->clearMessage();
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
  list << ui.readSize->currentText().toInt();
  ui.cancel->setVisible(true);
  ui.convert->setEnabled(false);
  ui.readSize->setEnabled(false);
  ui.reset->setEnabled(false);
  ui.progressBar->setValue(0);
  ui.progressBar->setVisible(true);

  if(ui.cbc->isChecked())
    modeOfOperation = "cbc";
  else
    modeOfOperation = "gcm";

  if(ui.decrypt->isChecked())
    m_future = QtConcurrent::run
      (this, &spoton_encryptfile::decrypt,
       fileInfo.absoluteFilePath(),
       destination.absoluteFilePath(),
       list,
       modeOfOperation);
  else
    m_future = QtConcurrent::run
      (this, &spoton_encryptfile::encrypt,
       ui.sign->isChecked(),
       fileInfo.absoluteFilePath(),
       destination.absoluteFilePath(),
       list,
       modeOfOperation);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical
      (this, tr("%1: Error").arg(SPOTON_APPLICATION_NAME), error);
}

void spoton_encryptfile::decrypt(const QString &fileName,
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
      QByteArray hash(spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES, 0);
      QByteArray hashes;
      qint64 rc = 0;
      spoton_crypt crypt(credentials.value(0).toString(),
			 credentials.value(1).toString(),
			 QByteArray(),
			 credentials.value(2).toByteArray(),
			 credentials.value(3).toByteArray(),
			 0,
			 0,
			 QString(""),
			 modeOfOperation);

      rc = file1.read(bytes.data(), bytes.length());

      if(bytes.length() == rc)
	{
	  sign = bytes.mid(0, 1).toInt();
	  bytes.clear();
	  bytes.resize
	    (qMax(1024 / 8, credentials.value(4).toInt() / 8) + 16 + 4);
	  /*
	  ** 16 = length of initialization
	  **      vector.
	  ** 4 = length of original buffer.
	  */
	}
      else
	{
	  error = tr("File read error.");
	  goto done_label;
	}

      if(sign)
	{
	  emit status(tr("Verifying the hash."));

	  if(file1.seek(file1.size() -
			spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES))
	    {
	      rc = file1.read(hash.data(),
			      spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);

	      if(rc != spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES)
		{
		  error = tr("File read failure.");
		  goto done_label;
		}
	    }
	  else
	    {
	      error = tr("File seek failure.");
	      goto done_label;
	    }

	  if(!file1.seek(1))
	    {
	      error = tr("File seek failure.");
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

	      if(file1.atEnd())
		data = data.mid
		  (0, data.length() -
		   spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);

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

	  if(!file1.seek(1))
	    {
	      error = tr("File seek failure.");
	      goto done_label;
	    }
	  else
	    emit completed(0);
	}

      emit status("Decrypting the file.");
      bytes.clear();
      bytes.resize(4096);

      while((rc = file1.read(bytes.data(), bytes.length())) > 0)
	{
	  if(m_future.isCanceled())
	    {
	      error = tr("Operation canceled.");
	      break;
	    }

	  QByteArray data(bytes.mid(0, static_cast<int> (rc)));

	  if(sign)
	    if(file1.atEnd())
	      data = data.mid(0, data.length() -
			      spoton_crypt::SHA512_OUTPUT_SIZE_IN_BYTES);

	  bool ok = true;

	  data = crypt.decrypted(data, &ok);

	  if(!ok)
	    {
	      error = tr("Decryption failure.");
	      break;
	    }
	  else
	    rc = file2.write(data, data.length());

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

void spoton_encryptfile::encrypt(const bool sign,
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
      spoton_crypt crypt(credentials.value(0).toString(),
			 credentials.value(1).toString(),
			 QByteArray(),
			 credentials.value(2).toByteArray(),
			 credentials.value(3).toByteArray(),
			 0,
			 0,
			 QString(""),
			 modeOfOperation);

      bytes.append(QByteArray::number(sign));
      rc = file2.write(bytes.constData(), bytes.length());

      if(bytes.length() != rc)
	{
	  error = tr("File write error.");
	  goto done_label;
	}

      bytes.clear();
      bytes.resize(qMax(1024 / 8, credentials.value(4).toInt() / 8));
      emit status("Encrypting the file.");

      while((rc = file1.read(bytes.data(), bytes.length())) > 0)
	{
	  if(m_future.isCanceled())
	    {
	      error = tr("Operation canceled.");
	      break;
	    }

	  QByteArray data(bytes.mid(0, static_cast<int> (rc)));
	  bool ok = true;

	  data = crypt.encrypted(data, &ok);

	  if(!ok)
	    {
	      error = tr("Encryption failure.");
	      break;
	    }
	  else
	    rc = file2.write(data, data.length());

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

	  hashes = crypt.keyedHash(hashes, &ok);

	  if(!ok)
	    error = tr("Hash failure.");
	  else
	    {
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

void spoton_encryptfile::slotSelect(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select File").
     arg(SPOTON_APPLICATION_NAME));

  if(sender() == ui.select)
    dialog.setFileMode(QFileDialog::ExistingFile);
  else
    dialog.setFileMode(QFileDialog::AnyFile);

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
      if(sender() == ui.select)
	{
	  QString str(dialog.selectedFiles().value(0));

	  ui.file->setText(str);

	  if(ui.destination->text().trimmed().isEmpty())
	    {
	      if(ui.encrypt->isChecked())
		ui.destination->setText(str + ".enc");
	      else if(str.endsWith(".enc"))
		ui.destination->setText(str.mid(0, str.length() - 4));
	    }
	}
      else
	ui.destination->setText(dialog.selectedFiles().value(0));
    }
}

void spoton_encryptfile::slotCompleted(const QString &error)
{
  statusBar()->clearMessage();
  ui.cancel->setVisible(false);
  ui.convert->setEnabled(true);
  ui.readSize->setEnabled(true);
  ui.reset->setEnabled(true);
  ui.progressBar->setVisible(false);

  if(error.length() == 1)
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The conversion process completed successfully. A signature "
	  "was not discovered."));
  else if(error.isEmpty())
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The conversion process completed successfully."));
  else
    QMessageBox::critical
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME), error);
}

void spoton_encryptfile::slotCompleted(const int percentage)
{
  ui.progressBar->setValue(percentage);
}

void spoton_encryptfile::slotReset(void)
{
  if(!m_future.isFinished())
    return;

  ui.cbc->setChecked(true);
  ui.cipher->setCurrentIndex(0);
  ui.destination->clear();
  ui.encrypt->setChecked(true);
  ui.file->clear();
  ui.hash->setCurrentIndex(0);
  ui.password->clear();
  ui.pin->clear();
  ui.readSize->setCurrentIndex(1);
  ui.sign->setChecked(true);
}

void spoton_encryptfile::slotStatus(const QString &status)
{
  statusBar()->showMessage(status);
  statusBar()->repaint();
}
