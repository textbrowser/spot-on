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

#include <QSqlQuery>
#include <QSqlRecord>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-receive.h"
#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"
#include "spot-on-starbeam-reader.h"

QSqlDatabase spoton_kernel::urlDatabase(QString &connectionName)
{
  connectionName = spoton_misc::databaseName();

  QSqlDatabase db;

  if(setting("gui/sqliteSearch", true).toBool())
    {
      db = QSqlDatabase::addDatabase("QSQLITE", connectionName);
      db.setDatabaseName
	(spoton_misc::homePath() + QDir::separator() + "urls.db");
      db.open();
    }
  else
    {
      QByteArray name;
      QByteArray password;
      auto const database
	(setting("gui/postgresql_database", "").toString().trimmed());
      auto const host
	(setting("gui/postgresql_host", "localhost").toString().trimmed());
      auto const port = setting("gui/postgresql_port", 5432).toInt();
      auto const ssltls = setting("gui/postgresql_ssltls", true).toBool();
      auto ok = true;
      auto options
	(setting("gui/postgresql_web_connection_options",
		 spoton_common::POSTGRESQL_CONNECTION_OPTIONS).
	 toString().trimmed());
      auto s_crypt = crypt("chat");

      if(!options.contains("connect_timeout="))
	options.append(";connect_timeout=10");

      if(s_crypt)
	{
	  name = s_crypt->decryptedAfterAuthenticated
	    (QByteArray::fromBase64(setting("gui/postgresql_web_name", "").
				    toByteArray()), &ok);

	  if(ok)
	    password = s_crypt->decryptedAfterAuthenticated
	      (QByteArray::
	       fromBase64(setting("gui/postgresql_web_password", "").
			  toByteArray()), &ok);
	}

      if(ssltls)
	options.append(";requiressl=1");

      db = QSqlDatabase::addDatabase("QPSQL", connectionName);
      db.setConnectOptions(spoton_misc::adjustPQConnectOptions(options));
      db.setDatabaseName(database);
      db.setHostName(host);
      db.setPort(port);

      if(ok)
	db.open(name, password);
    }

  return db;
}

QString spoton_kernel::prisonBluesSequence(void)
{
  return QString("%1").arg
    (s_prisonBluesSequence.fetchAndAddOrdered(1), 10, 10, QChar('0'));
}

bool spoton_kernel::hasStarBeamReaderId(const qint64 id)
{
  if(!instance())
    return false;

  QHashIterator<qint64, QPointer<spoton_starbeam_reader> > it
    (instance()->m_starbeamReaders);

  while(it.hasNext())
    {
      it.next();

      if(it.value() && id == it.value()->id())
	return true;
    }

  return false;
}

bool spoton_kernel::initialized(void) const
{
  return m_initialized;
}

bool spoton_kernel::prepareAlmostAnonymousEmail
(const QByteArray &attachmentData,
 const QByteArray &fromAccount,
 const QByteArray &goldbug,
 const QByteArray &keyType,
 const QByteArray &message,
 const QByteArray &name,
 const QByteArray &receiverName,
 const QByteArray &subject,
 const QByteArray &date,
 const qint64 mailOid,
 QByteArray &data)
{
  data.clear();

  auto s_crypt = crypt(keyType);

  if(!s_crypt)
    return false;

  auto crypt = spoton_misc::cryptFromForwardSecrecyMagnet(goldbug);

  if(!crypt)
    return false;

  QByteArray group1;
  QByteArray group2;
  QDataStream stream(&data, QIODevice::WriteOnly);
  auto ok = true;

  if(attachmentData.isEmpty())
    stream << QByteArray("0001c")
	   << name
	   << subject
	   << message
	   << date
	   << QByteArray();
  else
    stream << QByteArray("0001c")
	   << name
	   << subject
	   << message
	   << date
	   << qCompress(attachmentData, 9);

  if(stream.status() != QDataStream::Ok)
    {
      ok = false;
      goto done_label;
    }

  group1 = crypt->encrypted(data, &ok);

  if(!ok)
    goto done_label;

  group2 = crypt->keyedHash(group1, &ok);

  if(!ok)
    goto done_label;

  data = group1.toBase64() + "\n" + group2.toBase64();

  if(keyType == "poptastic")
    {
      auto const message(spoton_send::message0001c(data));

      postPoptasticMessage(receiverName, message, fromAccount, mailOid);
    }

 done_label:
  delete crypt;

  if(!ok)
    data.clear();

  return ok;
}

qint64 spoton_kernel::uptimeMinutes(void)
{
  return s_uptime.elapsed() / 60000;
}

spoton_crypt *spoton_kernel::crypt(const QString &key)
{
  QReadLocker locker(&s_cryptsMutex);

  return s_crypts.value(key, nullptr);
}

void spoton_kernel::cryptSave(const QString &k, spoton_crypt *crypt)
{
  if(!crypt)
    return;

  QWriteLocker locker(&s_cryptsMutex);
  auto const key(k.trimmed());

  if(s_crypts.contains(key))
    {
      delete s_crypts.value(key);
      s_crypts.remove(key);
    }

  s_crypts.insert(key, crypt);
}

void spoton_kernel::readPrisonBlues(void)
{
  auto s_crypt = crypt("chat");

  if(!s_crypt)
    return;

  auto ok = false;
  auto const myPublicKeyHash = spoton_crypt::sha512Hash
    (qCompress(s_crypt->publicKey(nullptr)), &ok).toHex();

  if(!ok)
    return;

  foreach(auto const &directory,
	  spoton_misc::prisonBluesDirectories(crypt("chat")))
    {
      if(m_readPrisonBluesFuture.isCanceled())
	break;

      QDir const dir
	(directory.absoluteFilePath() + QDir::separator() + myPublicKeyHash);

      if(!dir.isReadable())
	continue;

      foreach(auto const &entry, dir.entryInfoList(QDir::Files, QDir::Time))
	{
	  if(m_readPrisonBluesFuture.isCanceled())
	    break;

	  QFile file(entry.absoluteFilePath());

	  if(file.open(QIODevice::ReadOnly))
	    {
	      auto data(file.readAll());

	      if(spoton_kernel::messagingCacheContains(data))
		{
		  file.remove();
		  continue;
		}
	      else
		spoton_kernel::messagingCacheAdd(data);

	      data = data.mid
		(data.indexOf("content=") +
		 static_cast<int> (qstrlen("content=")));
	      data = data.mid(0, data.indexOf(spoton_send::EOM)).trimmed();

	      auto const list
		(spoton_receive::
		 process0000(data.length(),
			     data,
			     QList<QByteArray> (),
			     setting("gui/chatAcceptSignedMessagesOnly",
				     true).toBool(),
			     "127.0.0.1",
			     0,
			     s_crypt));

	      if(list.isEmpty())
		continue;

	      spoton_misc::saveParticipantStatus
		(list.value(1), // Name
		 list.value(0), // Public Key Hash
		 QByteArray(),  // Status
		 QDateTime::currentDateTimeUtc().toString("MMddyyyyhhmmss").
		 toLatin1(),    // Timestamp
		 2.5 * spoton_common::PRISON_BLUES_STATUS_INTERVAL, // Seconds
		 s_crypt);
	      emit receivedChatMessage
		("message_" +
		 list.value(0).toBase64() + "_" +
		 list.value(1).toBase64() + "_" +
		 list.value(2).toBase64() + "_" +
		 list.value(3).toBase64() + "_" +
		 list.value(4).toBase64() + "_" +
		 list.value(5).toBase64() + "_" +
		 list.last().toBase64().append("\n"));
	      file.remove(); // Be careful, yes?
	    }
	}
    }
}

void spoton_kernel::setSetting(const QString &key, const QVariant &value)
{
  if(key.trimmed().isEmpty())
    return;

  QWriteLocker locker(&s_settingsMutex);

  s_settings[key.trimmed()] = value;
}

void spoton_kernel::slotCallParticipantUsingForwardSecrecy
(const QByteArray &keyType, const qint64 oid)
{
  auto s_crypt = crypt(keyType);

  if(!s_crypt)
    return;

  QByteArray data;
  QString connectionName("");
  QString receiverName("");
  auto ok = false;

  {
    auto db(spoton_misc::database(connectionName));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT "
		      "forward_secrecy_authentication_algorithm, " // 0
		      "forward_secrecy_authentication_key, "       // 1
		      "forward_secrecy_encryption_algorithm, "     // 2
		      "forward_secrecy_encryption_key, "           // 3
		      "gemini, "                                   // 4
		      "gemini_hash_key, "                          // 5
		      "name "                                      // 6
		      "FROM friends_public_keys WHERE "
		      "key_type_hash IN (?, ?) AND neighbor_oid = -1 AND "
		      "OID = ?");
	query.bindValue(0, s_crypt->keyedHash(QByteArray("chat"),
					      &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt->keyedHash(QByteArray("poptastic"),
						&ok).toBase64());

	query.bindValue(2, oid);

	if(ok && query.exec())
	  if(query.next())
	    {
	      QList<QByteArray> list;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  auto const bytes
		    (s_crypt->
		     decryptedAfterAuthenticated(QByteArray::
						 fromBase64(query.
							    value(i).
							    toByteArray()),
						 &ok));

		  if(!ok)
		    break;

		  list << bytes;

		  if(i == 6)
		    receiverName = bytes;
		}

	      QByteArray messageCode;
	      QDataStream stream(&data, QIODevice::WriteOnly);
	      auto const dateTime(QDateTime::currentDateTime());
	      spoton_crypt crypt(list.value(2).constData(),
				 list.value(0).constData(),
				 QByteArray(),
				 list.value(3),
				 list.value(1),
				 0,
				 0,
				 "");

	      stream << QByteArray("0000d")
		     << list.value(4)
		     << list.value(5)
		     << dateTime.toUTC().toString("MMddyyyyhhmmss").toLatin1();

	      if(stream.status() != QDataStream::Ok)
		ok = false;

	      if(ok)
		data = crypt.encrypted(data, &ok);

	      if(ok)
		messageCode = crypt.keyedHash(data, &ok);

	      if(ok)
		{
		  data = data.toBase64();
		  data.append("\n");
		  data.append(messageCode.toBase64());
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      if(keyType == "poptastic")
	postPoptasticMessage(receiverName, spoton_send::message0000d(data));
      else
	emit callParticipant(data, "0000d");
    }
}

void spoton_kernel::slotDropped(const QByteArray &data)
{
  if(data.isEmpty())
    return;

  auto neighbor = qobject_cast<spoton_neighbor *> (sender());

  if(!neighbor)
    return;

  auto const hash(spoton_crypt::preferredHash(data));
  QPair<QByteArray, qint64> pair(hash, neighbor->id());

  {
    QWriteLocker locker(&m_droppedPacketsMutex);

    if(m_droppedPackets.contains(pair))
      return;

    m_droppedPackets[pair] = data;
  }

  if(!m_droppedTimer.isActive())
    m_droppedTimer.start();
}

void spoton_kernel::slotDroppedTimeout(void)
{
  {
    QReadLocker locker(&m_droppedPacketsMutex);

    if(m_droppedPackets.isEmpty())
      {
	m_droppedTimer.stop();
	return;
      }
  }

  QPair<QByteArray, qint64> key;
  QPointer<spoton_neighbor> neighbor;

  {
    QReadLocker locker(&m_droppedPacketsMutex);

    key = m_droppedPackets.begin().key();
  }

  neighbor = m_neighbors.value(key.second);

  if(!neighbor)
    {
      QWriteLocker locker(&m_droppedPacketsMutex);

      m_droppedPackets.remove(key);
    }
  else if(neighbor->readyToWrite())
    {
      auto const data(m_droppedPackets.value(key));

      if(neighbor->write(data.constData(),
			 data.length(),
			 false) == data.length())
	{
	  QWriteLocker locker(&m_droppedPacketsMutex);

	  m_droppedPackets.remove(key);
	}
    }

  QReadLocker locker(&m_droppedPacketsMutex);

  if(m_droppedPackets.isEmpty())
    m_droppedTimer.stop();
}

void spoton_kernel::slotPrepareObjects(void)
{
  spoton_misc::prepareDatabases();
  prepareListeners();
  prepareNeighbors();
  prepareStarbeamReaders();
}

void spoton_kernel::slotPrisonBluesTimeout(void)
{
  spoton_misc::launchPrisonBluesProcesses
    (this, nullptr, m_prisonBluesProcesses, false, crypt("chat"));
}

void spoton_kernel::slotPurgeEphemeralKeyPair(const QByteArray &publicKeyHash)
{
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);

  m_forwardSecrecyKeys.remove(publicKeyHash);
}

void spoton_kernel::slotPurgeEphemeralKeys(void)
{
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);

  m_forwardSecrecyKeys.clear();
}

void spoton_kernel::slotPurgeEphemeralKeysTimeout(void)
{
  QWriteLocker locker(&m_forwardSecrecyKeysMutex);
  QMutableHashIterator<QByteArray, QVector<QVariant> > it
    (m_forwardSecrecyKeys);
  auto const delta1 = setting("gui/forward_secrecy_time_delta", 30).
    toLongLong() + 5;
  auto const delta2 = setting("gui/poptastic_forward_secrecy_time_delta", 60).
    toLongLong() + 10;

  while(it.hasNext())
    {
      it.next();

      auto const dateTime(it.value().value(2).toDateTime());
      auto const keyType(it.value().value(3).toString());
      auto const now(QDateTime::currentDateTime());
      auto const secsTo = qAbs(now.secsTo(dateTime));

      if(keyType != "poptastic")
	{
	  if(secsTo >= delta1)
	    it.remove();
	}
      else
	{
	  if(secsTo >= delta2)
	    it.remove();
	}
    }
}

void spoton_kernel::slotReadPrisonBlues(void)
{
  if(interfaces() == 0)
    return;

  if(m_readPrisonBluesFuture.isFinished())
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    m_readPrisonBluesFuture = QtConcurrent::run
      (&spoton_kernel::readPrisonBlues, this);
#else
    m_readPrisonBluesFuture = QtConcurrent::run
      (this, &spoton_kernel::readPrisonBlues);
#endif
}

void spoton_kernel::slotSMPMessageReceivedFromUI(const QByteArrayList &list)
{
  if(QByteArray::fromBase64(list.value(0)) == "poptastic")
    postPoptasticMessage
      (QByteArray::fromBase64(list.value(1)),
       spoton_send::messageXYZ(list.value(2) +
			       "\n" +
			       list.value(3) +
			       "\n" +
			       list.value(4),
			       QPair<QByteArray, QByteArray> ()));
}

void spoton_kernel::slotSaveUrls(const QList<QByteArray> &urls)
{
  saveUrls(urls);
}

void spoton_kernel::slotWriteMessage0061(const QByteArray &data)
{
  writeMessage006X(data, "0061", nullptr, nullptr);
}

void spoton_kernel::writePrisonBluesChat
(const QByteArray &message, const QByteArray &publicKeyHash)
{
  if(message.trimmed().isEmpty() || publicKeyHash.trimmed().isEmpty())
    return;

  auto const publicKeyHashHex(publicKeyHash.toHex());
  auto state = false;

  foreach(auto const &directory,
	  spoton_misc::prisonBluesDirectories(crypt("chat")))
    if(directory.exists() && directory.isWritable())
      {
	QDir().mkpath
	  (directory.absoluteFilePath() +
	   QDir::separator() +
	   publicKeyHashHex);

	QTemporaryFile file
	  (directory.absoluteFilePath() +
	   QDir::separator() +
	   publicKeyHashHex +
	   QDir::separator() +
	   "PrisonBluesXXXXXXXXXX.txt");

	if(file.open())
	  {
	    QTextStream stream(&file);

	    Q_UNUSED(file.fileName()); // Prevents removal of file.
	    file.setAutoRemove(false);
	    state = true;
	    stream << message;
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
	    stream << Qt::endl;
#else
	    stream << endl;
#endif
	  }
      }

  m_prisonBluesTimer.remainingTime() >= 5500 && state ?
    slotPrisonBluesTimeout() : (void) 0;
}
