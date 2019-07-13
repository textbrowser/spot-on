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
#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-starbeam-writer.h"

#ifdef Q_OS_UNIX
extern "C"
{
#include <unistd.h>
}
#endif

spoton_starbeam_writer::spoton_starbeam_writer(QObject *parent):
  QThread(parent)
{
}

spoton_starbeam_writer::~spoton_starbeam_writer()
{
  quit();
  wait();
}

bool spoton_starbeam_writer::append
(const QByteArray &data,
 QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair)
{
  if(data.isEmpty())
    {
      spoton_misc::logError("spoton_starbeam_writer::append(): "
			    "data is empty.");
      return false;
    }

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    {
      spoton_misc::logError("spoton_starbeam_writer::append(): "
			    "s_crypt is zero.");
      return false;
    }

  spoton_kernel::discoverAdaptiveEchoPair
    (data.trimmed(), discoveredAdaptiveEchoPair);

  QReadLocker locker(&m_keyMutex);

  if(m_magnets.isEmpty())
    return false;

  QHash<QString, QByteArray> magnet;
  QList<QByteArray> list(data.trimmed().split('\n'));

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  for(int i = 0; i < m_magnets.size(); i++)
    {
      QByteArray messageCode;
      bool ok = true;

      messageCode = spoton_crypt::keyedHash
	(list.value(0),
	 m_magnets.at(i).value("mk"),
	 m_magnets.at(i).value("ht"),
	 &ok);

      if(ok)
	if(!list.value(1).isEmpty() && !messageCode.isEmpty() &&
	   spoton_crypt::memcmp(list.value(1), messageCode))
	  {
	    magnet = m_magnets.at(i);
	    break;
	  }
    }

  locker.unlock();

  if(!magnet.isEmpty() &&
     spoton_kernel::setting("gui/etpReceivers", false).toBool())
    {
      /*
      ** If the thread is not active, it should be!
      */

      if(!isRunning())
	start();

      emit newData(data, magnet);
    }

  return !magnet.isEmpty();
}

bool spoton_starbeam_writer::isActive(void) const
{
  return isRunning();
}

void spoton_starbeam_writer::processData
(const QByteArray &dataIn, const QStringByteArrayHash &magnet)
{
  if(dataIn.isEmpty() || magnet.isEmpty())
    {
      if(dataIn.isEmpty())
	spoton_misc::logError("spoton_starbeam_writer::processData(): "
			      "dataIn is empty.");
      else
	spoton_misc::logError("spoton_starbeam_writer::processData(): "
			      "magnet is empty.");

      return;
    }

  QByteArray data(dataIn.trimmed());
  QList<QByteArray> list(data.split('\n'));

  if(list.size() != 3)
    return;

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  bool ok = true;
  spoton_crypt crypt(magnet.value("ct").constData(),
		     "",
		     QByteArray(),
		     magnet.value("ek"),
		     0,
		     0,
		     "");
  static const int expectedEntries0060 = 11;
  static const int expectedEntries0061 = 4;

  data = crypt.decrypted(list.value(0), &ok);

  if(!ok)
    return;

  QList<QByteArray> novas;
  QReadLocker locker(&m_keyMutex);

  novas = m_novas;
  locker.unlock();

  QByteArray d
    (data.mid(0, data.length() -
	      spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));
  QByteArray messageCode(data.mid(d.length()));
  bool found = false;

  for(int i = 0; i < novas.size(); i++)
    {
      QByteArray bytes;
      QByteArray computedHash;
      bool ok = true;
      spoton_crypt crypt
	("aes256",
	 "sha512",
	 QByteArray(),
	 novas.at(i).mid(0,
			 static_cast<int> (spoton_crypt::
					   cipherKeyLength("aes256"))),
	 novas.at(i).mid(static_cast<int> (spoton_crypt::
					   cipherKeyLength("aes256"))),
	 0,
	 0,
	 "");

      computedHash = crypt.keyedHash(d, &ok);

      if(!ok)
	continue;

      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	 spoton_crypt::memcmp(computedHash, messageCode))
	{
	  bytes = crypt.decrypted(d, &ok);

	  if(ok)
	    {
	      found = true;
	      list.clear();

	      QByteArray type;
	      QDataStream stream(&bytes, QIODevice::ReadOnly);

	      for(int i = 1;; i++)
		{
		  QByteArray a;

		  stream >> a;

		  if(stream.status() != QDataStream::Ok)
		    {
		      list.clear();
		      break;
		    }
		  else
		    list << a;

		  if(i == 1)
		    type = a;

		  if(type == "0060")
		    {
		      if(i == expectedEntries0060)
			break;
		    }
		  else if(type == "0061")
		    {
		      if(i == expectedEntries0061)
			break;
		    }
		  else
		    break;
		}

	      break;
	    }
	}
    }

  if(!found)
    {
      QByteArray type;
      QDataStream stream(&data, QIODevice::ReadOnly);

      list.clear();

      for(int i = 1;; i++)
	{
	  QByteArray a;

	  stream >> a;

	  if(stream.status() != QDataStream::Ok)
	    {
	      list.clear();
	      break;
	    }
	  else
	    list << a;

	  if(i == 1)
	    type = a;

	  if(type == "0060")
	    {
	      if(i == expectedEntries0060)
		break;
	    }
	  else if(type == "0061")
	    {
	      if(i == expectedEntries0061)
		break;
	    }
	  else
	    break;
	}
    }

  if(!(list.value(0) == "0060" || list.value(0) == "0061"))
    return;

  QDateTime dateTime;

  if(list.value(0) == "0060")
    dateTime = QDateTime::fromString
      (list.value(8).constData(), "MMddyyyyhhmmss");
  else
    dateTime = QDateTime::fromString
      (list.value(2).constData(), "MMddyyyyhhmmss");

  dateTime.setTimeSpec(Qt::UTC);

  if(!spoton_misc::
     acceptableTimeSeconds(dateTime, spoton_common::STARBEAM_TIME_DELTA))
    return;

  if(list.value(0) == "0061")
    {
      /*
      ** The StarBeam reader having the identity ID should now read
      ** the next bundle of data.
      */

      emit notifyStarBeamReader
	(list.value(3).toLongLong(), list.value(1).toLongLong());
      return;
    }

  QString connectionName("");
  QString fileName
    (spoton_kernel::setting("gui/etpDestinationPath", QDir::homePath()).
     toString() + QDir::separator() +
     QString::fromUtf8(list.value(1).constData(),
		       list.value(1).length()).replace(" ", "-"));
  int locked = 0;
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(s_crypt)
    {
      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare("SELECT locked FROM received WHERE file_hash = ?");
	    query.bindValue
	      (0, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	    if(ok)
	      if(query.exec() && query.next())
		locked = query.value(0).toInt();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      if(locked)
	return;
    }

  QByteArray hash = list.value(7);
  bool ultra = list.value(10).toShort();
  qint64 dataSize = qAbs(list.value(3).toLongLong());
  qint64 id = list.value(9).toLongLong();
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maxMosaicSize", 512).toLongLong();
  qint64 position = qAbs(list.value(2).toLongLong());
  qint64 pulseSize = qAbs(list.value(6).toLongLong());
  qint64 totalSize = qAbs(list.value(4).toLongLong());

  Q_UNUSED(id);
  Q_UNUSED(ultra);

  if(dataSize != static_cast<qint64> (list.value(5).length())) // Data
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize != list.value(5).length().");
      return;
    }
  else if(dataSize > (pulseSize + pulseSize / 100 + 12))
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > (pulseSize + pulseSize / 100 + 12).");
      return;
    }
  else if(dataSize > maximumSize || totalSize > maximumSize)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > maximumSize or totalSize > maximumSize.");
      return;
    }
  else if(dataSize > totalSize || position >= totalSize)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > totalSize or position >= totalSize.");
      return;
    }
  else if(pulseSize > maximumSize ||
	  pulseSize > spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "pulseSize > maximumSize or pulseSize > "
	 "spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE.");
      return;
    }

  QFile file;

  file.setFileName(fileName);

  if(file.exists())
    if(!(file.permissions() & QFile::WriteOwner))
      {
	spoton_misc::logError
	  ("spoton_starbeam_writer::processData(): "
	   "file permissions error.");
	return;
      }

  if(file.open(QIODevice::ReadWrite | QIODevice::Unbuffered))
    {
      if(position > file.size())
	if(!file.resize(position))
	  {
	    ok = false;
	    spoton_misc::logError("spoton_starbeam_writer::processData(): "
				  "resize() failure.");
	  }

      if(file.seek(position))
	{
	  QByteArray data(list.value(5));

	  data = qUncompress(data);

	  if(static_cast<int> (file.write(data.constData(),
					  data.length())) != data.length())
	    {
	      ok = false;
	      spoton_misc::logError
		("spoton_starbeam_writer::processData(): "
		 "write() failure.");
	    }

	  file.flush();
	}
      else
	{
	  ok = false;
	  spoton_misc::logError("spoton_starbeam_writer::processData(): "
				"seek() failure.");
	}
    }
  else
    spoton_misc::logError("spoton_starbeam_writer::processData(): "
			  "QFile::open() failure.");

#ifdef Q_OS_UNIX
  fsync(file.handle());
#endif
  file.close();

  if(!ok)
    return;

  if(!s_crypt)
    {
      spoton_misc::logError("spoton_starbeam_writer::processData(): "
			    "s_crypt is zero.");
      return;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received "
	   "(expected_file_hash, file, file_hash, hash, pulse_size, "
	   "total_size) "
	   "VALUES (?, ?, ?, "
	   "(SELECT hash FROM received WHERE file_hash = ?), ?, ?)");

	if(hash.isEmpty())
	  query.bindValue(0, QVariant::String);
	else
	  query.bindValue
	    (0, s_crypt->encryptedThenHashed(hash, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1,
	     s_crypt->encryptedThenHashed(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4, s_crypt->
	     encryptedThenHashed(QByteArray::number(pulseSize), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (5, s_crypt->
	     encryptedThenHashed(QByteArray::number(totalSize), &ok).
	     toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::run(void)
{
  spoton_starbeam_writer_worker worker(this);

  connect(this,
	  SIGNAL(newData(const QByteArray &,
			 const QStringByteArrayHash &)),
	  &worker,
	  SLOT(slotNewData(const QByteArray &,
			   const QStringByteArrayHash &)));
  exec();
}

void spoton_starbeam_writer::slotReadKeys(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    {
      spoton_misc::logError("spoton_starbeam_writer::slotReadKeys(): "
			    "s_crypt is zero.");
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QWriteLocker locker(&m_keyMutex);

	m_magnets.clear();
	m_novas.clear();
	locker.unlock();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT magnet FROM magnets");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decryptedAfterAuthenticated(data, &ok);

	      if(!ok)
		continue;

	      QHash<QString, QByteArray> elements;
	      QList<QByteArray> list
		(data.remove(0, static_cast<int> (qstrlen("magnet:?"))).
		 split('&'));

	      while(!list.isEmpty())
		{
		  QByteArray bytes(list.takeFirst());

		  if(bytes.startsWith("ct=")) // Cipher Type
		    {
		      bytes.remove(0, 3);
		      elements.insert("ct", bytes);
		    }
		  else if(bytes.startsWith("ek=")) // Encryption Key
		    {
		      bytes.remove(0, 3);
		      elements.insert("ek", bytes);
		    }
		  else if(bytes.startsWith("ht=")) // Hash Type
		    {
		      bytes.remove(0, 3);
		      elements.insert("ht", bytes);
		    }
		  else if(bytes.startsWith("mk=")) // MAC Key
		    {
		      bytes.remove(0, 3);
		      elements.insert("mk", bytes);
		    }
		  else if(bytes.startsWith("xt="))
		    {
		      bytes.remove(0, 3);

		      if(bytes == "urn:starbeam")
			elements.insert("xt", bytes);
		    }
		}

	      if(elements.contains("xt"))
		{
		  QWriteLocker locker(&m_keyMutex);

		  m_magnets.append(elements);
		}
	    }

	query.prepare("SELECT nova FROM received_novas");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decryptedAfterAuthenticated(data, &ok);

	      if(!ok)
		continue;

	      QWriteLocker locker(&m_keyMutex);

	      m_novas.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::start(void)
{
  /*
  ** Magnets and nova updates from the user interface
  ** will trigger slotReadKeys().
  */

  slotReadKeys();
  QThread::start();
}

void spoton_starbeam_writer::stop(void)
{
  quit();
  wait();

  QWriteLocker locker(&m_keyMutex);

  m_magnets.clear();
  m_novas.clear();
}
