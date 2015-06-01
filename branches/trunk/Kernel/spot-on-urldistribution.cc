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

#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTimer>

#include "../Common/spot-on-common.h"
#include "../Common/spot-on-crypt.h"
#include "../Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-urldistribution.h"

spoton_urldistribution::spoton_urldistribution(QObject *parent):
  QThread(parent)
{
  m_limit = spoton_common::KERNEL_URLS_BATCH_SIZE;
  m_offset = 0;
  m_quit = false;
}

spoton_urldistribution::~spoton_urldistribution()
{
  quit();
  wait();
}

void spoton_urldistribution::quit(void)
{
  QWriteLocker locker(&m_quitLocker);

  m_quit = true;
  locker.unlock();
  QThread::quit();
}

void spoton_urldistribution::run(void)
{
  QWriteLocker locker(&m_quitLocker);

  m_quit = false;
  locker.unlock();

  QTimer timer;

  connect(&timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  timer.start(30000);
  exec();
}

void spoton_urldistribution::slotTimeout(void)
{
  spoton_crypt *s_crypt1 = spoton_kernel::s_crypts.value("url", 0);

  if(!s_crypt1)
    return;

  spoton_crypt *s_crypt2 = spoton_kernel::s_crypts.value("url-signature", 0);

  if(!s_crypt2)
    return;

  /*
  ** First, let's retrieve the public keys.
  */

  QList<QByteArray> publicKeys;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "key_type_hash = ? AND neighbor_oid = -1");
	query.bindValue
	  (0, s_crypt1->keyedHash(QByteArray("url"), &ok).toBase64());

	if(ok && query.exec())
	  while(query.next())
	    {
	      QByteArray publicKey;
	      bool ok = true;

	      publicKey = s_crypt1->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		publicKeys.append(publicKey);

	      QReadLocker locker(&m_quitLocker);

	      if(m_quit)
		break;
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    QReadLocker locker(&m_quitLocker);

    if(m_quit)
      return;
  }

  if(publicKeys.isEmpty())
    return;

  /*
  ** Retrieve at most spoton_common::KERNEL_URLS_BATCH_SIZE URLs.
  */

  QByteArray data;

  {
    QSqlDatabase db;

    if(spoton_kernel::setting("gui/sqliteSearch", true).toBool())
      {
	db = QSqlDatabase::addDatabase("QSQLITE", "URLDatabase");
	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "urls.db");
	db.open();
      }
    else
      {
	QByteArray password;
	QString database
	  (spoton_kernel::setting("gui/postgresql_database", "").
	   toString().trimmed());
	QString host
	  (spoton_kernel::setting("gui/postgresql_host", "localhost").
	   toString().trimmed());
	QString name
	  (spoton_kernel::setting("gui/postgresql_name", "").toString().
	   trimmed());
	QString str("connect_timeout=10");
	bool ok = true;
	bool ssltls = spoton_kernel::setting
	  ("gui/postgresql_ssltls", false).toBool();
	int port = spoton_kernel::setting
	  ("gui/postgresql_port", 5432).toInt();

	password = s_crypt1->decryptedAfterAuthenticated
	  (QByteArray::
	   fromBase64(spoton_kernel::setting("gui/postgresql_password", "").
		      toByteArray()), &ok);

	if(ssltls)
	  str.append(";requiressl=1");

	db = QSqlDatabase::addDatabase("QPSQL", "URLDatabase");
	db.setConnectOptions(str);
	db.setHostName(host);
	db.setDatabaseName(database);
	db.setPort(port);
	db.open(name, password);
      }

    if(db.isOpen())
      {
	QDataStream stream(&data, QIODevice::WriteOnly);
	QSqlQuery query(db);
	QString querystr("");

	for(int i = 0; i < 10 + 6; i++)
	  for(int j = 0; j < 10 + 6; j++)
	    {
	      QChar c1;
	      QChar c2;

	      if(i <= 9)
		c1 = QChar(i + 48);
	      else
		c1 = QChar(i + 97 - 10);

	      if(j <= 9)
		c2 = QChar(j + 48);
	      else
		c2 = QChar(j + 97 - 10);

	      if(i == 15 && j == 15)
		querystr.append
		  (QString("SELECT url, title, description "
			   "FROM spot_on_urls_%1%2 ").arg(c1).arg(c2));
	      else
		querystr.append
		  (QString("SELECT url, title, description "
			   "FROM spot_on_urls_%1%2 UNION ").arg(c1).arg(c2));
	    }

	querystr.append(QString(" LIMIT %1 ").arg(m_limit));
	querystr.append(QString(" OFFSET %1 ").arg(m_offset));

	if(query.exec(querystr))
	  do
	    {
	      if(!query.next())
		{
		  m_offset = 0;
		  break;
		}

	      QList<QByteArray> bytes;
	      bool ok = true;

	      bytes.append
		(s_crypt1->
		 decryptedAfterAuthenticated(QByteArray::
					     fromBase64(query.value(0).
							toByteArray()),
					     &ok));

	      if(ok)
		bytes.append
		  (s_crypt1->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(1).
							  toByteArray()),
					       &ok));

	      if(ok)
		bytes.append
		  (s_crypt1->
		   decryptedAfterAuthenticated(QByteArray::
					       fromBase64(query.value(2).
							  toByteArray()),
					       &ok));

	      if(ok)
		stream << bytes.value(0)
		       << bytes.value(1)
		       << bytes.value(2);

	      QReadLocker locker(&m_quitLocker);

	      if(m_quit)
		break;

	      m_offset += 1;
	    }
	  while(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("URLDatabase");

  if(data.isEmpty())
    return;

  {
    QReadLocker locker(&m_quitLocker);

    if(m_quit)
      return;
  }

  data = qCompress(data, 9);

  for(int i = 0; i < publicKeys.size(); i++)
    {
    }
}
