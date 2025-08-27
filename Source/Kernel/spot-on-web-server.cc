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

#include <QProcess>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-socket-options.h"
#include "spot-on-kernel.h"
#include "spot-on-web-server.h"

void spoton_web_server_tcp_server::incomingConnection(qintptr socketDescriptor)
{
  emit newConnection(static_cast<qint64> (socketDescriptor));
}

spoton_web_server::spoton_web_server(QObject *parent):QObject(parent)
{
  m_http = new spoton_web_server_tcp_server(this);
  m_httpClientCount = new QAtomicInt(0);
  m_https = new spoton_web_server_tcp_server(this);
  m_httpsClientCount = new QAtomicInt(0);
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(m_http,
	  SIGNAL(newConnection(const qint64)),
	  this,
	  SLOT(slotHttpClientConnected(const qint64)));
  connect(m_https,
	  SIGNAL(newConnection(const qint64)),
	  this,
	  SLOT(slotHttpsClientConnected(const qint64)));
  m_generalTimer.start(2500);
}

spoton_web_server::~spoton_web_server()
{
  m_generalTimer.stop();
  m_http->close();
  m_https->close();
  delete m_httpClientCount;
  delete m_httpsClientCount;
}

int spoton_web_server::httpClientCount(void) const
{
  return m_httpClientCount->fetchAndAddOrdered(0);
}

int spoton_web_server::httpsClientCount(void) const
{
  return m_httpsClientCount->fetchAndAddOrdered(0);
}

void spoton_web_server::slotHttpClientConnected(const qint64 socketDescriptor)
{
  if(m_httpClientCount->fetchAndAddOrdered(0) >=
     spoton_kernel::setting("gui/soss_maximum_clients", 10).toInt() ||
     socketDescriptor < 0)
    {
      spoton_misc::closeSocket(socketDescriptor);
      return;
    }

  auto process = new QProcess(this);

  connect(process,
	  SIGNAL(finished(int, QProcess:ExitStatus)),
	  this,
	  SLOT(slotHttpThreadFinished(void)));
  connect(process,
	  SIGNAL(finished(int, QProcess::ExitStatus)),
	  process,
	  SLOT(deleteLater(void)));
  m_httpClientCount->fetchAndAddOrdered(1);
}

void spoton_web_server::slotHttpThreadFinished(void)
{
  m_httpClientCount->fetchAndAddOrdered(-1);
}

void spoton_web_server::slotHttpsClientConnected(const qint64 socketDescriptor)
{
  if(m_httpsClientCount->fetchAndAddOrdered(0) >=
     spoton_kernel::setting("gui/soss_maximum_clients", 10).toInt() ||
     m_https->certificate().isEmpty() ||
     m_https->privateKey().isEmpty() ||
     socketDescriptor < 0)
    {
      spoton_misc::closeSocket(socketDescriptor);
      return;
    }

  auto process = new QProcess(this);

  connect(process,
	  SIGNAL(finished(int, QProcess:ExitStatus)),
	  this,
	  SLOT(slotHttpThreadFinished(void)));
  connect(process,
	  SIGNAL(finished(int, QProcess::ExitStatus)),
	  process,
	  SLOT(deleteLater(void)));
  m_httpsClientCount->fetchAndAddOrdered(1);
}

void spoton_web_server::slotHttpsThreadFinished(void)
{
  m_httpsClientCount->fetchAndAddOrdered(-1);
}

void spoton_web_server::slotTimeout(void)
{
  auto const port = static_cast<quint16>
    (spoton_kernel::setting("gui/web_server_port", 0).toInt());

  if(port == 0)
    {
      m_http->close();
      m_https->clear();
      m_https->close();
      return;
    }

  auto const maximumClients = spoton_kernel::setting
    ("gui/soss_maximum_clients", 10).toInt();

  if((m_http->isListening() && m_http->serverPort() != port) ||
     m_httpClientCount->fetchAndAddOrdered(0) >= maximumClients)
    m_http->close();

  if((m_https->isListening() &&
      m_https->serverPort() != static_cast<quint16> (port + 5)) ||
     m_httpsClientCount->fetchAndAddOrdered(0) >= maximumClients)
    {
      m_https->clear();
      m_https->close();
    }

  if(m_https->certificate().isEmpty() || m_https->privateKey().isEmpty())
    {
      auto s_crypt = spoton_kernel::crypt("chat");

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    auto db(spoton_misc::database(connectionName));

	    db.setDatabaseName(spoton_misc::homePath() +
			       QDir::separator() +
			       "kernel_web_server.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

		query.setForwardOnly(true);

		if(query.exec("SELECT certificate, " // 0
			      "private_key "         // 1
			      "FROM kernel_web_server"))
		  while(query.next())
		    {
		      QByteArray certificate;
		      QByteArray privateKey;
		      auto ok = true;

		      certificate = s_crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(0).toByteArray()),
			 &ok);
		      privateKey = s_crypt->decryptedAfterAuthenticated
			(QByteArray::fromBase64(query.value(1).toByteArray()),
			 &ok);
		      m_https->setCertificate(certificate);
		      m_https->setPrivateKey(privateKey);
		    }
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }

  if(!m_http->isListening() &&
     m_httpClientCount->fetchAndAddOrdered(0) < maximumClients)
    if(!m_http->listen(spoton_misc::localAddressIPv4(), port))
      spoton_misc::logError
	("spoton_web_server::slotTimeout(): m_http->listen() failure. "
	 "This is a serious problem!");

  if(m_http->isListening())
    {
      auto const so_linger = spoton_kernel::setting
	("WEB_SERVER_HTTP_SO_LINGER", -1).toInt();

      spoton_socket_options::setSocketOptions
	("so_linger=" + QString::number(so_linger),
	 "tcp",
	 m_http->socketDescriptor(),
	 nullptr);
    }

  if(!m_https->isListening() &&
     m_httpsClientCount->fetchAndAddOrdered(0) < maximumClients)
    if(!m_https->listen(spoton_misc::localAddressIPv4(),
			static_cast<quint16> (port + 5)))
      spoton_misc::logError
	("spoton_web_server::slotTimeout(): m_https->listen() failure. "
	 "This is a serious problem!");

  if(m_https->isListening())
    {
      auto const so_linger = spoton_kernel::setting
	("WEB_SERVER_HTTPS_SO_LINGER", -1).toInt();

      spoton_socket_options::setSocketOptions
	("so_linger=" + QString::number(so_linger),
	 "tcp",
	 m_https->socketDescriptor(),
	 nullptr);
    }
}
