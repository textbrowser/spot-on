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

#include <QAbstractSocket>

#ifdef SPOTON_SCTP_ENABLED
#ifdef Q_OS_FREEBSD
extern "C"
{
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}
#elif defined(Q_OS_LINUX)
extern "C"
{
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <usrsctp.h>
}
#elif defined(Q_OS_WIN)
extern "C"
{
#include <winsock2.h>
#include <ws2sctp.h>
}
#endif
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-socket-options.h"
#include "spot-on-kernel.h"
#include "spot-on-sctp-server.h"

spoton_sctp_server::spoton_sctp_server(const qint64 id,
				       QObject *parent):QObject(parent)
{
  m_id = id;
  m_isListening = false;
  m_serverPort = 0;
#if defined(Q_OS_WIN)
  m_socketDescriptor = INVALID_SOCKET;
#else
  m_socketDescriptor = -1;
#endif
#ifdef SPOTON_SCTP_ENABLED
  m_backlog = 30;
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  m_socketNotifier = 0;
#else
  m_timer.setInterval(100);
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
#endif
#else
  m_backlog = 0;
#endif
}

spoton_sctp_server::~spoton_sctp_server()
{
  close();
}

QHostAddress spoton_sctp_server::serverAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_serverAddress;
#else
  return QHostAddress();
#endif
}

QString spoton_sctp_server::errorString(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_errorString;
#else
  return "";
#endif
}

bool spoton_sctp_server::isListening(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_isListening;
#else
  return false;
#endif
}

bool spoton_sctp_server::listen(const QHostAddress &address,
				const quint16 port,
				const QString &socketOptions)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_isListening)
    return true;
#if defined(Q_OS_WIN)
  else if(m_socketDescriptor != INVALID_SOCKET)
    return m_isListening;
#else
  else if(m_socketDescriptor > -1)
    return m_isListening;
#endif

  QAbstractSocket::NetworkLayerProtocol protocol =
    QAbstractSocket::IPv4Protocol;
  int optval = 0;
  int rc = 0;
  socklen_t optlen = sizeof(optval);
#if defined(Q_OS_WIN)
  unsigned long int enabled = 1;
#endif

  if(QHostAddress(address).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    m_socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

#if defined(Q_OS_WIN)
  if(m_socketDescriptor == INVALID_SOCKET)
    rc = -1;
#else
  rc = m_socketDescriptor;
#endif

  if(rc == -1)
    {
#if defined(Q_OS_WIN)
      m_errorString = QString("listen()::socket()::error=%1").arg
	(WSAGetLastError());
#else
      m_errorString = QString("listen()::socket()::errno=%1").arg(errno);
#endif
      goto done_label;
    }

#if defined(Q_OS_WIN)
  rc = ioctlsocket(m_socketDescriptor, FIONBIO, &enabled);

  if(rc != 0)
    {
      m_errorString = "listen()::fcntl()::ioctlsocket()";
      goto done_label;
    }
#else
  rc = fcntl(m_socketDescriptor, F_GETFL, 0);

  if(rc == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }

  rc = fcntl(m_socketDescriptor, F_SETFL, O_NONBLOCK | rc);

  if(rc == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }
#endif
  rc = 0;

  /*
  ** Set the read and write buffer sizes.
  */

#if defined(Q_OS_WIN)
  spoton_socket_options::setSocketOptions
    (socketOptions, "sctp", m_socketDescriptor, 0);
#else
  spoton_socket_options::setSocketOptions
    (socketOptions, "sctp", static_cast<qint64> (m_socketDescriptor), 0);
#endif

  /*
  ** Reuse the address.
  */

  optval = 1;
#if defined(Q_OS_WIN)
  rc = setsockopt
    (m_socketDescriptor, SOL_SOCKET,
     SO_REUSEADDR, (const char *) &optval, (int) optlen);
#else
  rc = setsockopt(m_socketDescriptor, SOL_SOCKET, SO_REUSEADDR,
		  &optval, optlen);
#endif

  if(rc != 0)
    spoton_misc::logError
      ("spoton_sctp_server::listen(): setsockopt() failure, SO_REUSEADDR.");

  /*
  ** Let's bind.
  */

  if(protocol == QAbstractSocket::IPv4Protocol)
    {
      socklen_t length = 0;
      struct sockaddr_in serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin_family = AF_INET;
      serveraddr.sin_port = htons(port);
#if defined(Q_OS_WIN)
      rc = WSAStringToAddressA((LPSTR) address.toString().toLatin1().data(),
			       AF_INET, 0, (LPSOCKADDR) &serveraddr, &length);
#else
      rc = inet_pton(AF_INET, address.toString().toLatin1().constData(),
		     &serveraddr.sin_addr.s_addr);
#endif

#if defined(Q_OS_WIN)

      if(rc != 0)
	{
	  m_errorString = QString("listen()::WSAStringToAddressA()::"
				  "error=%1").arg(WSAGetLastError());
	  goto done_label;
	}

      /*
      ** Reset sin_port.
      */

      serveraddr.sin_port = htons(port);
#else
      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
#endif
      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
#if defined(Q_OS_WIN)
	  m_errorString = QString
	    ("listen()::bind()::error=%1").arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("listen()::bind()::errno=%1").arg(errno);
#endif
	  goto done_label;
	}
    }
  else
    {
      socklen_t length = 0;
      struct sockaddr_in6 serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin6_family = AF_INET6;
      serveraddr.sin6_port = htons(port);
#if defined(Q_OS_WIN)
      rc = WSAStringToAddressA((LPSTR) address.toString().toLatin1().data(),
			       AF_INET6, 0, (LPSOCKADDR) &serveraddr, &length);
#else
      rc = inet_pton(AF_INET6, address.toString().toLatin1().constData(),
		     &serveraddr.sin6_addr);
#endif

#if defined(Q_OS_WIN)
      if(rc != 0)
	{
	  m_errorString = QString("listen()::WSAStringToAddressA()::rc=%1").
	    arg(rc);
	  goto done_label;
	}

      /*
      ** Reset sin6_port.
      */

      serveraddr.sin6_port = htons(port);
#else
      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
#endif
      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
#if defined(Q_OS_WIN)
	  m_errorString = QString
	    ("listen()::bind()::error=%1").arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("listen()::bind()::errno=%1").arg(errno);
#endif
	  goto done_label;
	}
    }

  rc = ::listen(m_socketDescriptor, m_backlog);

  if(rc == 0)
    {
      m_isListening = true;
      m_serverAddress = address;
      m_serverPort  = port;
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
      if(m_socketNotifier)
	m_socketNotifier->deleteLater();

      m_socketNotifier = 0;

      try
	{
          m_socketNotifier = new QSocketNotifier
	    (m_socketDescriptor, QSocketNotifier::Read, this);
	  connect(m_socketNotifier,
		  SIGNAL(activated(int)),
		  this,
		  SLOT(slotActivated(int)));
        }
      catch(const std::bad_alloc &exception)
	{
	  m_socketNotifier = 0;
	}
      catch(...)
	{
	  if(m_socketNotifier)
	    m_socketNotifier->deleteLater();

	  m_socketNotifier = 0;
        }

      if(Q_LIKELY(m_socketNotifier))
	m_socketNotifier->setEnabled(true);
      else
	{
	  m_errorString = "listen()::listen()::memory allocation failure";
	  rc = 1;
	}
#else
      m_timer.start();
#endif
    }
  else
#if defined(Q_OS_WIN)
    m_errorString = QString("listen()::listen()::error=%1").
      arg(WSAGetLastError());
#else
    m_errorString = QString("listen()::listen()::errno=%1").arg(errno);
#endif

 done_label:

  if(rc != 0)
    {
      close();
      return false;
    }

  return true;
#else
  Q_UNUSED(address);
  Q_UNUSED(port);
  Q_UNUSED(socketOptions);
  return false;
#endif
}

int spoton_sctp_server::maxPendingConnections(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_backlog;
#else
  return 0;
#endif
}

int spoton_sctp_server::socketDescriptor(void) const
{
#if defined(Q_OS_WIN)
  return static_cast<int> (m_socketDescriptor);
#else
  return m_socketDescriptor;
#endif
}

quint16 spoton_sctp_server::serverPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_serverPort;
#else
  return 0;
#endif
}

void spoton_sctp_server::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
#if defined(Q_OS_WIN)
  closesocket(m_socketDescriptor);
#else
  ::close(m_socketDescriptor);
#endif
  m_isListening = false;
  m_serverAddress.clear();
  m_serverPort = 0;
#if defined(Q_OS_WIN)
  m_socketDescriptor = INVALID_SOCKET;
#else
  m_socketDescriptor = -1;
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  if(m_socketNotifier)
    m_socketNotifier->deleteLater();

  m_socketNotifier = 0;
#else
  m_timer.stop();
#endif
#endif
}

void spoton_sctp_server::setMaxPendingConnections(const int numConnections)
{
#ifdef SPOTON_SCTP_ENABLED
  m_backlog = qBound(1, numConnections, SOMAXCONN);
#else
  Q_UNUSED(numConnections);
#endif
}

#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
void spoton_sctp_server::slotActivated(int socketDescriptor)
#else
void spoton_sctp_server::slotTimeout(void)
#endif
{
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
  Q_UNUSED(socketDescriptor);
#endif
#ifdef SPOTON_SCTP_ENABLED
  QAbstractSocket::NetworkLayerProtocol protocol =
    QAbstractSocket::IPv4Protocol;

  if(QHostAddress(m_serverAddress).protocol() ==
     QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    {
      QHostAddress address;
#if defined(Q_OS_WIN)
      SOCKET socketDescriptor = INVALID_SOCKET;
#else
      int socketDescriptor = -1;
#endif
      quint16 port = 0;
      socklen_t length = 0;
      struct sockaddr_in clientaddr;

      length = sizeof(clientaddr);
      memset(&clientaddr, 0, sizeof(clientaddr));
      socketDescriptor = accept
	(m_socketDescriptor, (struct sockaddr *) &clientaddr,
	 &length);

#if defined(Q_OS_WIN)
      if(socketDescriptor != INVALID_SOCKET)
#else
      if(socketDescriptor > -1)
#endif
	{
	  if(spoton_kernel::s_connectionCounts.count(m_id) >= m_backlog)
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      return;
	    }

	  address.setAddress
	    (ntohl(clientaddr.sin_addr.s_addr));
	  port = ntohs(clientaddr.sin_port);

	  if(spoton_kernel::instance() &&
	     !spoton_kernel::instance()->
	     acceptRemoteConnection(m_serverAddress, address))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	    }
	  else if(!spoton_misc::isAcceptedIP(address, m_id,
					     spoton_kernel::s_crypts.
					     value("chat", 0)))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotActivated(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#else
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#endif
	    }
	  else if(spoton_misc::isIpBlocked(address,
					   spoton_kernel::s_crypts.
					   value("chat", 0)))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotActivated(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#else
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 blocked for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#endif
	    }
	  else
#if QT_VERSION < 0x050000
	    emit newConnection(static_cast<int> (socketDescriptor),
			       address,
			       port);
#else
	    emit newConnection(static_cast<qintptr> (socketDescriptor),
			       address, port);
#endif
	}
#if defined(Q_OS_WIN)
      else if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
      else if(!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
	{
#if defined(Q_OS_WIN)
	  m_errorString = QString
	    ("run()::accept()::error=%1").
	    arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("run()::accept()::errno=%1").
	    arg(errno);
#endif
	  close();
	}
    }
  else
    {
      QHostAddress address;
#if defined(Q_OS_WIN)
      SOCKET socketDescriptor = INVALID_SOCKET;
#else
      int socketDescriptor = -1;
#endif
      quint16 port = 0;
      socklen_t length = 0;
      struct sockaddr_in6 clientaddr;

      length = sizeof(clientaddr);
      memset(&clientaddr, 0, sizeof(clientaddr));
      socketDescriptor = accept
	(m_socketDescriptor, (struct sockaddr *) &clientaddr,
	 &length);

#if defined(Q_OS_WIN)
      if(socketDescriptor != INVALID_SOCKET)
#else
      if(socketDescriptor > -1)
#endif
	{
	  if(spoton_kernel::s_connectionCounts.count(m_id) >= m_backlog)
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      return;
	    }

	  Q_IPV6ADDR temp;

	  memcpy(&temp.c, &clientaddr.sin6_addr.s6_addr,
		 qMin(sizeof(clientaddr.sin6_addr.s6_addr), sizeof(temp.c)));
	  address.setAddress(temp);
	  address.setScopeId
	    (QString::number(clientaddr.sin6_scope_id));
	  port = ntohs(clientaddr.sin6_port);

	  if(spoton_kernel::instance() &&
	     !spoton_kernel::instance()->
	     acceptRemoteConnection(m_serverAddress, address))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	    }
	  else if(!spoton_misc::isAcceptedIP(address, m_id,
					     spoton_kernel::s_crypts.
					     value("chat", 0)))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotActivated(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#else
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#endif
	    }
	  else if(spoton_misc::isIpBlocked(address,
					   spoton_kernel::s_crypts.
					   value("chat", 0)))
	    {
#if defined(Q_OS_WIN)
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MAC) || defined(Q_OS_UNIX)
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotActivated(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#else
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 blocked for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
#endif
	    }
	  else
#if QT_VERSION < 0x050000
	    emit newConnection(static_cast<int> (socketDescriptor),
			       address,
			       port);
#else
	    emit newConnection(static_cast<qintptr> (socketDescriptor),
			       address, port);
#endif
	}
#if defined(Q_OS_WIN)
      else if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
      else if(!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
	{
#if defined(Q_OS_WIN)
	  m_errorString = QString
	    ("run()::accept()::error=%1").
	    arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("run()::accept()::errno=%1").
	    arg(errno);
#endif
	  close();
	}
    }
#else
#endif
}
