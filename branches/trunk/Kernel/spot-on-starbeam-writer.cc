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

spoton_starbeam_writer::spoton_starbeam_writer(QObject *parent):QObject(parent)
{
  connect(&m_etaTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotETATimerTimeout(void)));
  m_abort = 0;
  m_etaTimer.setInterval(2500);
}

spoton_starbeam_writer::~spoton_starbeam_writer()
{
  m_abort.fetchAndStoreOrdered(1);
  m_etaTimer.stop();
  m_future.cancel();
  m_future.waitForFinished();
}

QByteArray spoton_starbeam_writer::eta(const QString &fileName)
{
  spoton_starbeam_writer_statistics statistics;

  if(m_statistics.contains(fileName))
    statistics = m_statistics.value(fileName);
  else
    return tr("stalled (0 B / s)").toUtf8();

  QString eta(tr("stalled"));
  QString rate("");
  qint64 seconds = qAbs
    (QDateTime::currentMSecsSinceEpoch() / 1000 - statistics.m_time0);

  if(statistics.m_rate > 0)
    eta = tr("%1 minutes(s)").
      arg((static_cast<double> (statistics.m_totalSize -
				statistics.m_position) /
	   static_cast<double> (statistics.m_rate)) / 60.0, 0, 'f', 2);

  if(seconds >= 1)
    {
      qint64 rate = statistics.m_rate;

      statistics.m_rate = static_cast<qint64>
	(static_cast<double> (qAbs(statistics.m_position -
				   statistics.m_previousPosition)) /
	 static_cast<double> (seconds));

      if(statistics.m_rate > 0)
	statistics.m_stalled = 0;
      else if(statistics.m_stalled++ <= 3)
	statistics.m_rate = rate;

      statistics.m_previousPosition = statistics.m_position;
      statistics.m_time0 = QDateTime::currentMSecsSinceEpoch() / 1000;
      m_statistics[fileName] = statistics;
    }

  rate = spoton_misc::formattedSize(statistics.m_rate) + tr(" / s");
  return (eta + " (" + rate + ")").toUtf8();
}

bool spoton_starbeam_writer::append
(const QByteArray &data,
 QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair)
{
  if(data.isEmpty() || m_abort.fetchAndAddOrdered(0))
    {
      if(data.isEmpty())
	spoton_misc::logError
	  ("spoton_starbeam_writer::append(): data is empty.");

      return false;
    }

  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::append(): s_crypt is zero.");
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

  if(!magnet.isEmpty())
    {
      {
	QWriteLocker locker(&m_queueMutex);

	m_queue.enqueue
	  (QPair<QByteArray, QHash<QString, QByteArray> > (data, magnet));
      }

      /*
      ** If the thread is not active, it should be!
      */

      if(m_future.isFinished())
	m_future = QtConcurrent::run
	  (this, &spoton_starbeam_writer::processData);
    }

  return !magnet.isEmpty();
}

void spoton_starbeam_writer::processData(void)
{
  QByteArray data;
  QHash<QString, QByteArray> magnet;

 start_label:

  if(m_abort.fetchAndAddOrdered(0) || m_future.isCanceled())
    return;

  {
    QWriteLocker locker(&m_queueMutex);

    if(!m_queue.isEmpty())
      {
	QPair<QByteArray, QHash<QString, QByteArray> > pair(m_queue.dequeue());

	data = pair.first.trimmed();
	magnet = pair.second;
      }
    else
      return;
  }

  if(data.isEmpty() || magnet.isEmpty())
    {
      if(data.isEmpty())
	spoton_misc::logError("spoton_starbeam_writer::processData(): "
			      "data is empty.");
      else
	spoton_misc::logError("spoton_starbeam_writer::processData(): "
			      "magnet is empty.");

      goto start_label;
    }

  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): s_crypt is zero.");
      return;
    }

  QList<QByteArray> list(data.split('\n'));

  if(list.size() != 3)
    goto start_label;

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  bool ok = true;
  const int expectedEntries0060 = 12;
  const int expectedEntries0061 = 4;
  spoton_crypt crypt(magnet.value("ct").constData(),
		     magnet.value("ht").constData(),
		     QByteArray(),
		     magnet.value("ek"),
		     magnet.value("mk"),
		     0,
		     0,
		     "");

  data = crypt.decrypted(list.value(0), &ok);

  if(!ok)
    goto start_label;

  QReadLocker locker(&m_keyMutex);
  const QList<QByteArray> &novas(m_novas);

  locker.unlock();

  QByteArray messageCode;
  QByteArray nova;
  bool found = false;
  const QByteArray &d
    (data.
     mid(0, data.length() - spoton_crypt::XYZ_DIGEST_OUTPUT_SIZE_IN_BYTES));

  messageCode = data.mid(d.length());

  for(int i = 0; i < novas.size(); i++)
    {
      QByteArray bytes;
      QByteArray computedHash;
      bool ok = true;
      spoton_crypt crypt
	(spoton_crypt::preferredCipherAlgorithm(),
	 spoton_crypt::preferredHashAlgorithm(),
	 QByteArray(),
	 novas.at(i).
	 mid(0,
	     static_cast<int> (spoton_crypt::
			       cipherKeyLength(spoton_crypt::
					       preferredCipherAlgorithm()))),
	 novas.at(i).
	 mid(static_cast<int> (spoton_crypt::
			       cipherKeyLength(spoton_crypt::
					       preferredCipherAlgorithm()))),
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
	      nova = novas.at(i);

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
    goto start_label;

  QDateTime dateTime;

  if(list.value(0) == "0060")
    dateTime = QDateTime::fromString
      (list.value(8).constData(), "MMddyyyyhhmmss");
  else
    dateTime = QDateTime::fromString
      (list.value(2).constData(), "MMddyyyyhhmmss");

  dateTime.setTimeSpec(Qt::UTC);

  if(!spoton_misc::acceptableTimeSeconds(dateTime,
					 spoton_common::STARBEAM_TIME_DELTA))
    goto start_label;

  if(list.value(0) == "0061")
    {
      /*
      ** The StarBeam reader having the identity ID should now read
      ** the next bundle of data.
      */

      emit notifyStarBeamReader
	(list.value(3).toLongLong(), list.value(1).toLongLong());
      goto start_label;
    }

  qint64 fileId = list.value(9).toLongLong();

  if(spoton_kernel::instance() &&
     spoton_kernel::instance()->hasStarBeamReaderId(fileId))
    goto start_label;

  const QByteArray &hash(list.value(7));
  const QByteArray &sha3_512_hash(list.value(11));
  qint64 dataSize = qAbs(list.value(3).toLongLong());
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maxMosaicSize", 512).toLongLong();
  qint64 position = qAbs(list.value(2).toLongLong());
  qint64 pulseSize = qAbs(list.value(6).toLongLong());
  qint64 totalSize = qAbs(list.value(4).toLongLong());

  if(dataSize != static_cast<qint64> (list.value(5).length())) // Data
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize != list.value(5).length().");
      goto start_label;
    }
  else if(dataSize > (pulseSize + pulseSize / 100 + 12))
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > (pulseSize + pulseSize / 100 + 12).");
      goto start_label;
    }
  else if(dataSize > maximumSize || totalSize > maximumSize)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > maximumSize or totalSize > maximumSize.");
      goto start_label;
    }
  else if(dataSize > totalSize || position >= totalSize)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "dataSize > totalSize or position >= totalSize.");
      goto start_label;
    }
  else if(pulseSize > maximumSize ||
	  pulseSize > spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE)
    {
      spoton_misc::logError
	("spoton_starbeam_writer::processData(): "
	 "pulseSize > maximumSize or pulseSize > "
	 "spoton_common::MAXIMUM_STARBEAM_PULSE_SIZE.");
      goto start_label;
    }

  QString fileName
    (spoton_kernel::setting("gui/etpDestinationPath",
			    QDir::homePath()).toString() +
     QDir::separator() +
     QString::fromUtf8(list.value(1).constData(),
		       list.value(1).length()).replace(" ", "-"));

  if(QFileInfo(fileName).size() == totalSize)
    goto start_label;

  QString connectionName("");
  int locked = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

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
    goto start_label;

  QFile file;

  file.setFileName(fileName);

  if(file.exists())
    if(!(file.permissions() & QFile::WriteOwner))
      {
	spoton_misc::logError
	  ("spoton_starbeam_writer::processData(): file permissions error.");
	goto start_label;
      }

  if(file.open(QIODevice::ReadWrite | QIODevice::Unbuffered))
    {
      if(position > file.size())
	if(!file.resize(position))
	  {
	    ok = false;
	    spoton_misc::logError
	      ("spoton_starbeam_writer::processData(): resize() failure.");
	  }

      if(file.seek(position))
	{
	  QByteArray data(qUncompress(list.value(5)));

	  if(static_cast<int> (file.write(data)) != data.length())
	    {
	      ok = false;
	      spoton_misc::logError
		("spoton_starbeam_writer::processData(): write() failure.");
	    }

	  file.flush();
	}
      else
	{
	  ok = false;
	  spoton_misc::logError
	    ("spoton_starbeam_writer::processData(): seek() failure.");
	}
    }
  else
    spoton_misc::logError
      ("spoton_starbeam_writer::processData(): QFile::open() failure.");

  file.flush();
  file.close();

  if(!ok)
    goto start_label;
  else
    {
      QWriteLocker locker(&m_statisticsMutex);

      if(!m_statistics.contains(fileName))
	{
	  spoton_starbeam_writer_statistics statistics;

	  statistics.m_fileName = fileName;
	  statistics.m_stalled = 0;
	  statistics.m_position = position;
	  statistics.m_previousPosition = 0;
	  statistics.m_rate = 0;
	  statistics.m_time0 = QDateTime::currentMSecsSinceEpoch();
	  statistics.m_totalSize = totalSize;
	  m_statistics[fileName] = statistics;
	}
      else
	{
	  spoton_starbeam_writer_statistics statistics
	    (m_statistics.value(fileName));

	  statistics.m_position = position;
	  m_statistics[fileName] = statistics;
	}
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received ("
	   "estimated_time_arrival, "  // 0
	   "expected_file_hash, "      // 1
	   "expected_sha3_512_hash, "  // 2
	   "file, "                    // 3
	   "file_hash, "               // 4
	   "hash, "                    // 5
	   "pulse_size, "              // 6
	   "sha3_512_hash, "           // 7
	   "total_size) "              // 8
	   "VALUES (?, "
	   "?, "
	   "?, "
	   "?, "
	   "?, "
	   "(SELECT hash FROM received WHERE file_hash = ?), "
	   "?, "
	   "(SELECT sha3_512_hash FROM received WHERE file_hash = ?), "
	   "?)");

	{
	  QWriteLocker locker(&m_statisticsMutex);

	  query.addBindValue
	    (s_crypt->encryptedThenHashed(eta(fileName), &ok).toBase64());
	}

	if(hash.isEmpty())
	  query.addBindValue(QVariant::String);
	else if(ok)
	  query.addBindValue
	    (s_crypt->encryptedThenHashed(hash, &ok).toBase64());

	if(ok)
	  {
	    if(sha3_512_hash.isEmpty())
	      query.addBindValue(QVariant::String);
	    else
	      query.addBindValue
		(s_crypt->encryptedThenHashed(sha3_512_hash, &ok).toBase64());
	  }

	if(ok)
	  query.addBindValue
	    (s_crypt->encryptedThenHashed(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->encryptedThenHashed(QByteArray::number(pulseSize), &ok).
	     toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.addBindValue
	    (s_crypt->encryptedThenHashed(QByteArray::number(totalSize), &ok).
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
    goto start_label;

  /*
  ** Produce a response.
  */

  QByteArray bytes;
  QDataStream stream(&bytes, QIODevice::WriteOnly);

  stream << QByteArray("0061")
	 << QByteArray::number(position)
	 << QDateTime::currentDateTime().toUTC().toString("MMddyyyyhhmmss").
            toLatin1()
	 << QByteArray::number(fileId);

  if(stream.status() != QDataStream::Ok)
    ok = false;
  else
    ok = true;

  if(nova.isEmpty())
    {
      if(ok)
	data = crypt.encrypted(bytes, &ok);
    }
  else
    {
      QPair<QByteArray, QByteArray> pair;

      pair.first = nova.mid
	(0, static_cast<int> (spoton_crypt::
			      cipherKeyLength(spoton_crypt::
					      preferredCipherAlgorithm())));
      pair.second = nova.mid(pair.first.length());

      {
	spoton_crypt crypt(spoton_crypt::preferredCipherAlgorithm(),
			   spoton_crypt::preferredHashAlgorithm(),
			   QByteArray(),
			   pair.first,
			   pair.second,
			   0,
			   0,
			   "");

	if(ok)
	  data = crypt.encrypted(bytes, &ok);

	if(ok)
	  data = data + crypt.keyedHash(data, &ok);
      }

      if(ok)
	data = crypt.encrypted(data, &ok);
    }

  if(ok)
    messageCode = crypt.keyedHash(data, &ok);

  if(ok)
    data = data.toBase64() + "\n" + messageCode.toBase64();

  if(ok)
    emit writeMessage0061(data);

  {
    QReadLocker locker(&m_queueMutex);

    if(!m_queue.isEmpty())
      goto start_label;
  }
}

void spoton_starbeam_writer::slotETATimerTimeout(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

	if(!s_crypt)
	  {
	    spoton_misc::logError
	      ("spoton_starbeam_writer::slotETATimerTimeout(): "
	       "s_crypt is zero.");
	    goto done_label;
	  }

	QWriteLocker locker(&m_statisticsMutex);
	QHashIterator<QString, spoton_starbeam_writer_statistics> it
	  (m_statistics);
	QStringList list;

	while(it.hasNext())
	  {
	    it.next();

	    QSqlQuery query(db);
	    bool ok = true;
	    bool remove = false;

	    query.exec("PRAGMA synchronous = NORMAL");
	    query.prepare("UPDATE received SET "
			  "estimated_time_arrival = ? "
			  "WHERE file_hash = ?");

	    if(QFileInfo(it.key()).size() == it.value().m_totalSize)
	      {
		query.addBindValue(QVariant::String);
		remove = true;
	      }
	    else
	      query.addBindValue
		(s_crypt->encryptedThenHashed(eta(it.key()), &ok).toBase64());

	    if(ok)
	      query.addBindValue
		(s_crypt->keyedHash(it.key().toUtf8(), &ok).toBase64());

	    if(ok)
	      query.exec();

	    if(remove)
	      list << it.key();
	  }

	for(int i = 0; i < list.size(); i++)
	  m_statistics.remove(list.at(i));
      }

    db.close();
  }

 done_label:
  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::slotReadKeys(void)
{
  spoton_crypt *s_crypt = spoton_kernel::crypt("chat");

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

	      for(int i = 0; i < list.size(); i++)
		{
		  QByteArray bytes(list.at(i).trimmed());

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
  ** Magnet and nova updates from the user interface will trigger
  ** slotReadKeys().
  */

  m_abort.fetchAndStoreOrdered(0);
  m_etaTimer.start();
  slotReadKeys();
}

void spoton_starbeam_writer::stop(void)
{
  m_abort.fetchAndStoreOrdered(1);
  m_etaTimer.stop();
  m_future.cancel();
  m_future.waitForFinished();

  {
    QWriteLocker locker(&m_keyMutex);

    m_magnets.clear();
    m_novas.clear();
  }

  {
    QWriteLocker locker(&m_queueMutex);

    m_queue.clear();
  }
}
