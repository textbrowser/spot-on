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
#elif defined(Q_OS_WIN32)
extern "C"
{
#include <winsock2.h>
#include <ws2sctp.h>
}
#endif
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-misc.h"
#include "spot-on-sctp-socket.h"

spoton_sctp_socket::spoton_sctp_socket(QObject *parent):QObject(parent)
{
  m_bufferSize = 65535;
  m_connectToPeerPort = 0;
  m_hostLookupId = -1;
  m_readBufferSize = spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE;
  m_socketDescriptor = -1;
  m_state = UnconnectedState;
  m_timer.setInterval(100);
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
}

spoton_sctp_socket::~spoton_sctp_socket()
{
  m_timer.stop();
  close();
}

QByteArray spoton_sctp_socket::readAll(void)
{
#ifdef SPOTON_SCTP_ENABLED
  QByteArray data(m_readBuffer);

  m_readBuffer.clear();
  return data;
#else
  return QByteArray();
#endif
}

QHostAddress spoton_sctp_socket::localAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return localAddressAndPort(0);
#else
  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::localAddressAndPort(quint16 *port) const
{
#ifdef SPOTON_SCTP_ENABLED
  if(port)
    *port = 0;

  if(m_socketDescriptor < 0)
    return QHostAddress();

  QHostAddress address;
  socklen_t length = 0;
  struct sockaddr_storage peeraddr;

  length = sizeof(peeraddr);

  if(getsockname(m_socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
      if(peeraddr.ss_family == AF_INET)
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      address.setAddress
		(ntohl(sockaddr->sockaddr_in.sin_addr.s_addr));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in.sin_port);
	    }
	}
      else
	{
	  spoton_type_punning_sockaddr_t *sockaddr =
	    (spoton_type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      Q_IPV6ADDR temp;

	      memcpy(&temp.c, &sockaddr->sockaddr_in6.sin6_addr.s6_addr,
		     qMin(sizeof(sockaddr->sockaddr_in6.sin6_addr.s6_addr),
			  sizeof(temp.c)));
	      address.setAddress(temp);
	      address.setScopeId
		(QString::number(sockaddr->sockaddr_in6.sin6_scope_id));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in6.sin6_port);
	    }
	}
    }

  return address;
#else
  if(port)
    *port = 0;

  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::peerAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return peerAddressAndPort(0);
#else
  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::peerAddressAndPort(quint16 *port) const
{
#ifdef SPOTON_SCTP_ENABLED
  if(port)
    *port = 0;

  if(m_socketDescriptor < 0)
    return QHostAddress();

  return spoton_misc::peerAddressAndPort(m_socketDescriptor, port);
#else
  if(port)
    *port = 0;

  return QHostAddress();
#endif
}

QString spoton_sctp_socket::peerName(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_connectToPeerName;
#else
  return "";
#endif
}

spoton_sctp_socket::SocketState spoton_sctp_socket::state(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_state;
#else
  return UnconnectedState;
#endif
}

bool spoton_sctp_socket::setSocketDescriptor(const int socketDescriptor)
{
#ifdef SPOTON_SCTP_ENABLED
  if(socketDescriptor >= 0)
    {
      close();
      m_socketDescriptor = socketDescriptor;
      m_state = ConnectedState;

      /*
      ** Let's hope that the socket descriptor inherited the server's
      ** read and write buffer sizes.
      */

      if(setSocketBlockingOrNon() != 0)
	{
	  close();
	  return false;
	}
      else
	{
	  m_timer.start();
	  return true;
	}
    }
  else
    return false;
#else
  Q_UNUSED(socketDescriptor);
  return false;
#endif
}

int spoton_sctp_socket::inspectConnectResult
(const int rc, const int errorcode)
{
#ifdef SPOTON_SCTP_ENABLED
  if(rc == -1)
    {
#ifdef Q_OS_WIN32
      if(errorcode == WSAEWOULDBLOCK)
	return 0;

      QString errorstr(QString("inspectConnectResult::error=%1,socket=%2").
		       arg(errorcode).arg(m_socketDescriptor));

      emit error(errorstr, UnknownSocketError);
#else
      if(errorcode == EINPROGRESS)
	return 0;

      QString errorstr(QString("inspectConnectResult::errno=%1,socket=%2").
		       arg(errorcode).arg(m_socketDescriptor));

      if(errorcode == EACCES || errorcode == EPERM)
	emit error(errorstr, SocketAccessError);
      else if(errorcode == EALREADY)
	emit error(errorstr, UnfinishedSocketOperationError);
      else if(errorcode == ECONNREFUSED)
	emit error(errorstr, ConnectionRefusedError);
      else if(errorcode == ENETUNREACH)
	emit error(errorstr, NetworkError);
      else
	emit error(errorstr, UnknownSocketError);
#endif
      return -1;
    }
  else
    return rc;
#else
  Q_UNUSED(errorcode);
  Q_UNUSED(rc);
  return -1;
#endif
}

int spoton_sctp_socket::setSocketBlockingOrNon(void)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0)
    {
      spoton_misc::logError("spoton_sctp_socket::setSocketBlockingOrNon(): "
			    "m_socketDescriptor is less than zero.");
      return -1;
    }

  int rc = 0;

#ifdef Q_OS_WIN32
  unsigned long enabled = 1;

  rc = ioctlsocket(m_socketDescriptor, FIONBIO, &enabled);

  if(rc != 0)
    {
      QString errorstr("setSocketBlockingOrNon()::ioctlsocket()");

      emit error(errorstr, UnknownSocketError);
      return -1;
    }
#else
  rc = fcntl(m_socketDescriptor, F_GETFL, 0);

  if(rc == -1)
    {
      QString errorstr(QString("setSocketBlockingOrNon()::fcntl()::"
			       "errno=%1").
		       arg(errno));

      emit error(errorstr, UnknownSocketError);
      return -1;
    }

  rc = fcntl(m_socketDescriptor, F_SETFL, O_NONBLOCK | rc);

  if(rc == -1)
    {
      QString errorstr(QString("setSocketBlockingOrNon()::fcntl()::"
			       "errno=%1").
		       arg(errno));

      emit error(errorstr, UnknownSocketError);
      return -1;
    }
#endif
  return 0;
#else
  return -1;
#endif
}

int spoton_sctp_socket::socketDescriptor(void) const
{
  return m_socketDescriptor;
}

qint64 spoton_sctp_socket::read(char *data, const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0 || m_state != ConnectedState)
    return -1;
  else if(!data || size < 0)
    return -1;
  else if(size == 0)
    return 0;

  fd_set efds, rfds, wfds;
  ssize_t rc = 0;
  struct timeval tv;

  FD_ZERO(&efds);
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  FD_SET(m_socketDescriptor, &efds);
  FD_SET(m_socketDescriptor, &rfds);
  FD_SET(m_socketDescriptor, &wfds);
  tv.tv_sec = 0;
  tv.tv_usec = 250000;

  if(select(m_socketDescriptor + 1, &rfds, &wfds, &efds, &tv) > 0)
    {
      if(FD_ISSET(m_socketDescriptor, &rfds))
	rc = recv
	  (m_socketDescriptor, data, static_cast<size_t> (size), 0);
      else
#ifdef Q_OS_WIN32
	WSASetLastError(WSAEWOULDBLOCK);
#else
        errno = EWOULDBLOCK;
#endif
    }
  else
#ifdef Q_OS_WIN32
    WSASetLastError(WSAEWOULDBLOCK);
#else
    errno = EWOULDBLOCK;
#endif

  if(rc == -1)
    {
#ifdef Q_OS_WIN32
      QString errorstr(QString("read()::recv()::error=%1").
		       arg(WSAGetLastError()));

      if(WSAGetLastError() == WSAEWOULDBLOCK)
	/*
	** We'll ignore this condition.
	*/

	rc = 0;
      else
	emit error(errorstr, UnknownSocketError);
#else
      QString errorstr(QString("read()::recv()::errno=%1").
		       arg(errno));

      if(errno == EAGAIN || errno == EINPROGRESS || errno == EWOULDBLOCK)
	/*
	** We'll ignore this condition.
	*/

	rc = 0;
      else if(errno == ECONNREFUSED)
	emit error(errorstr, ConnectionRefusedError);
      else if(errno == ECONNRESET)
	emit error(errorstr, RemoteHostClosedError);
      else if(errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error(errorstr, SocketResourceError);
      else if(errno == ENOTCONN)
	emit error(errorstr, NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error(errorstr, UnsupportedSocketOperationError);
      else
	emit error(errorstr, UnknownSocketError);
#endif
    }

  return static_cast<qint64> (rc);
#else
  Q_UNUSED(data);
  Q_UNUSED(size);
  return 0;
#endif
}

qint64 spoton_sctp_socket::write(const char *data, const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0 || m_state != ConnectedState)
    return -1;
  else if(!data || size < 0)
    return -1;
  else if(size == 0)
    return 0;

  qint64 written = -1;
  ssize_t remaining = static_cast<ssize_t> (size);
  ssize_t sent = 0;
  ssize_t writeSize = 65535;

  /*
  ** We'll send a fraction of the desired buffer size. Otherwise,
  ** our process may become exhausted.
  */

  while(remaining > 0)
    {
#ifdef Q_OS_WIN32
      sent = send
	(m_socketDescriptor, data,
	 static_cast<size_t> (qMin(remaining, writeSize)), 0);
#else
      sent = send
	(m_socketDescriptor, data,
	 static_cast<size_t> (qMin(remaining, writeSize)), MSG_DONTWAIT);
#endif

      if(sent == -1)
	{
#ifdef Q_OS_WIN32
	  if(WSAGetLastError() == WSAEWOULDBLOCK)
#else
	  if(errno == EAGAIN || errno == EWOULDBLOCK)
#endif
	    sent = 0;
#ifdef Q_OS_WIN32
	  else if(WSAGetLastError() == WSAEMSGSIZE)
#else
	  else if(errno == EMSGSIZE)
#endif
	    {
	      writeSize /= 2;

	      if(writeSize <= 0)
		break;
	      else
		sent = 0;
	    }
	  else
	    break;
	}
      else if(sent > 0)
	{
	  if(written == -1)
	    written = 0;

	  data += sent;
	  remaining -= sent;
	  written += static_cast<qint64> (sent);
	}
      else
	{
	  if(written == -1)
	    written = 0;

	  break;
	}
    }

  if(sent == -1)
    {
#ifdef Q_OS_WIN32
      QString errorstr(QString("write()::send()::error=%1").
		       arg(WSAGetLastError()));

      emit error(errorstr, UnknownSocketError);
#else
      QString errorstr(QString("write()::send()::errno=%1").
		       arg(errno));

      if(errno == EACCES)
	emit error(errorstr, SocketAccessError);
      else if(errno == ECONNRESET)
	emit error(errorstr, RemoteHostClosedError);
      else if(errno == EMSGSIZE || errno == ENOBUFS || errno == ENOMEM)
	emit error(errorstr, SocketResourceError);
      else if(errno == EHOSTUNREACH || errno == ENETDOWN ||
	      errno == ENETUNREACH || errno == ENOTCONN)
	emit error(errorstr, NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error(errorstr, UnsupportedSocketOperationError);
      else
	emit error(errorstr, UnknownSocketError);
#endif
    }

  return written;
#else
  Q_UNUSED(data);
  Q_UNUSED(size);
  return 0;
#endif
}

quint16 spoton_sctp_socket::localPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  quint16 port = 0;

  localAddressAndPort(&port);
  return port;
#else
  return 0;
#endif
}

quint16 spoton_sctp_socket::peerPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  quint16 port = 0;

  peerAddressAndPort(&port);
  return port;
#else
  return 0;
#endif
}

void spoton_sctp_socket::abort(void)
{
#ifdef SPOTON_SCTP_ENABLED
#ifdef Q_OS_WIN32
  shutdown(m_socketDescriptor, SD_BOTH);
#else
  shutdown(m_socketDescriptor, SHUT_RDWR);
#endif
  close();
#endif
}

void spoton_sctp_socket::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
  SocketState state = m_state;

  QHostInfo::abortHostLookup(m_hostLookupId);
#ifdef Q_OS_WIN32
  shutdown(m_socketDescriptor, SD_BOTH);
  closesocket(m_socketDescriptor);
#else
  shutdown(m_socketDescriptor, SHUT_RDWR);
  ::close(m_socketDescriptor);
#endif
  m_connectToPeerName.clear();
  m_connectToPeerPort = 0;
  m_hostLookupId = -1;
  m_ipAddress.clear();
  m_readBuffer.clear();
  m_socketDescriptor = -1;
  m_state = UnconnectedState;
  m_timer.stop();

  if(state != UnconnectedState)
    emit disconnected();
#endif
}

void spoton_sctp_socket::connectToHost(const QString &hostName,
				       const quint16 port)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor > -1)
    return;
  else if(m_state != UnconnectedState)
    return;

  m_connectToPeerName = hostName;
  m_connectToPeerPort = port;

  if(QHostAddress(hostName).isNull())
    {
      m_hostLookupId = QHostInfo::lookupHost
	(hostName, this, SLOT(slotHostFound(const QHostInfo &)));
      m_state = HostLookupState;
    }
  else
    {
      m_ipAddress = hostName;
      connectToHostImplementation();
    }
#else
  Q_UNUSED(hostName);
  Q_UNUSED(port);
#endif
}

void spoton_sctp_socket::connectToHostImplementation(void)
{
#ifdef SPOTON_SCTP_ENABLED
  NetworkLayerProtocol protocol = IPv4Protocol;
  int optval = 0;
  int rc = 0;
  socklen_t optlen = sizeof(optval);

  if(QHostAddress(m_ipAddress).protocol() ==
     QAbstractSocket::NetworkLayerProtocol(IPv6Protocol))
    protocol = IPv6Protocol;

  if(protocol == IPv4Protocol)
    m_socketDescriptor = rc = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = rc = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  if(rc == -1)
    {
#ifdef Q_OS_WIN32
      QString errorstr
	(QString("connectToHostImplementation()::socket()::error=%1").
	 arg(WSAGetLastError()));

      emit error(errorstr, UnknownSocketError);
#else
      QString errorstr
	(QString("connectToHostImplementation()::socket()::errno=%1").
	 arg(errno));

      if(errno == EACCES)
	emit error(errorstr, SocketAccessError);
      else if(errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
	emit error(errorstr, UnsupportedSocketOperationError);
      else if(errno == EISCONN || errno == EMFILE ||
	      errno == ENFILE || errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error(errorstr, SocketResourceError);
      else
	emit error(errorstr, UnknownSocketError);
#endif
      goto done_label;
    }

  if((rc = setSocketBlockingOrNon()) == -1)
    goto done_label;

  /*
  ** Set the read and write buffer sizes.
  */

  optval = m_bufferSize;
#ifdef Q_OS_WIN32
  setsockopt(m_socketDescriptor, SOL_SOCKET,
	     SO_RCVBUF, (const char *) &optval, optlen);
#else
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
#endif
  optval = m_bufferSize;
#ifdef Q_OS_WIN32
  setsockopt(m_socketDescriptor, SOL_SOCKET,
	     SO_SNDBUF, (const char *) &optval, optlen);
#else
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, &optval, optlen);
#endif

  if(protocol == IPv4Protocol)
    {
      socklen_t length = 0;
      struct sockaddr_in serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
      serveraddr.sin_family = AF_INET;
      serveraddr.sin_port = htons(m_connectToPeerPort);

#ifdef Q_OS_WIN32
      rc = WSAStringToAddressA((LPSTR) m_ipAddress.toLatin1().data(),
			       AF_INET, 0, (LPSOCKADDR) &serveraddr, &length);

      if(rc != 0)
	{
	  emit error("connectToHostImplementation()::WSAStringToAddressA()",
		     UnknownSocketError);
	  goto done_label;
	}

      /*
      ** Reset sin_port.
      */

      serveraddr.sin_port = htons(m_connectToPeerPort);
#else
      rc = inet_pton(AF_INET, m_ipAddress.toLatin1().constData(),
		     &serveraddr.sin_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    {
	      if(errno == EAFNOSUPPORT)
		emit error("connectToHostImplementation()::inet_pton()",
			   UnsupportedSocketOperationError);
	      else
		emit error("connectToHostImplementation()::inet_pton()",
			   UnknownSocketError);
	    }
	  else
	    emit error("connectToHostImplementation()::inet_pton()",
		       UnknownSocketError);

	  goto done_label;
	}
#endif
      m_state = ConnectingState;
      rc = ::connect
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc == 0)
	{
	  /*
	  ** The connection was established immediately.
	  */

	  m_state = ConnectedState;
	  emit connected();
	}
      else
#ifdef Q_OS_WIN32
	rc = inspectConnectResult(rc, WSAGetLastError());
#else
        rc = inspectConnectResult(rc, errno);
#endif
    }
  else
    {
      socklen_t length = 0;
      struct sockaddr_in6 serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin6_addr = in6addr_any;
      serveraddr.sin6_family = AF_INET6;
      serveraddr.sin6_port = htons(m_connectToPeerPort);

#ifdef Q_OS_WIN32
      rc = WSAStringToAddressA((LPSTR) m_ipAddress.toLatin1().data(),
			       AF_INET6, 0, (LPSOCKADDR) &serveraddr, &length);

      if(rc != 0)
	{
	  emit error("connectToHostImplementation()::WSAStringToAddressA()",
		     UnknownSocketError);
	  goto done_label;
	}

      /*
      ** Reset sin6_port.
      */

      serveraddr.sin6_port = htons(m_connectToPeerPort);
#else
      rc = inet_pton(AF_INET6, m_ipAddress.toLatin1().constData(),
		     &serveraddr.sin6_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    {
	      if(errno == EAFNOSUPPORT)
		emit error("connectToHostImplementation()::inet_pton()",
			   UnsupportedSocketOperationError);
	      else
		emit error("connectToHostImplementation()::inet_pton()",
			   UnknownSocketError);
	    }
	  else
	    emit error("connectToHostImplementation()::inet_pton()",
		       UnknownSocketError);

	  goto done_label;
	}
#endif
      m_state = ConnectingState;
      rc = ::connect
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc == 0)
	{
	  /*
	  ** The connection was established immediately.
	  */

	  m_state = ConnectedState;
	  emit connected();
	}
      else
#ifdef Q_OS_WIN32
	rc = inspectConnectResult(rc, WSAGetLastError());
#else
        rc = inspectConnectResult(rc, errno);
#endif
    }

 done_label:

  if(rc != 0)
    close();
  else
    m_timer.start();

#endif
}

void spoton_sctp_socket::setReadBufferSize(const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  m_readBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   size,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
#else
  Q_UNUSED(size);
#endif
}

void spoton_sctp_socket::setSocketOption(const SocketOption option,
					 const QVariant &value)
{
#ifdef SPOTON_SCTP_ENABLED
  switch(option)
    {
    case KeepAliveOption:
      {
	int optval = static_cast<int> (value.toLongLong());
	socklen_t optlen = sizeof(optval);

#ifdef Q_OS_WIN32
	setsockopt
	  (m_socketDescriptor, SOL_SOCKET,
	   SO_KEEPALIVE, (const char *) &optval, optlen);
#else
	setsockopt(m_socketDescriptor, SOL_SOCKET, SO_KEEPALIVE,
		   &optval, optlen);
#endif
	break;
      }
    case LowDelayOption:
      {
	int optval = static_cast<int> (value.toLongLong());
	socklen_t optlen = sizeof(optval);

#ifdef Q_OS_WIN32
	setsockopt
	  (m_socketDescriptor, IPPROTO_SCTP,
	   SCTP_NODELAY, (const char *) &optval, optlen);
#else
	setsockopt(m_socketDescriptor, IPPROTO_SCTP, SCTP_NODELAY,
		   &optval, optlen);
#endif
	break;
      }
    default:
      {
	break;
      }
    }
#else
  Q_UNUSED(option);
  Q_UNUSED(value);
#endif
}

void spoton_sctp_socket::slotHostFound(const QHostInfo &hostInfo)
{
#ifdef SPOTON_SCTP_ENABLED
  m_ipAddress.clear();

  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	/*
	** In the future, we'll need attempt several connections.
	*/

	m_ipAddress = address.toString();
	connectToHostImplementation();
	break;
      }

  if(QHostAddress(m_ipAddress).isNull())
    emit error("slotHostFound()", HostNotFoundError);
#else
  Q_UNUSED(hostInfo);
#endif
}

void spoton_sctp_socket::slotTimeout(void)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_state != ConnectedState)
    {
      fd_set rfds, wfds;
      struct timeval tv;

      FD_ZERO(&rfds);
      FD_ZERO(&wfds);
      FD_SET(m_socketDescriptor, &rfds);
      FD_SET(m_socketDescriptor, &wfds);
      tv.tv_sec = 0;
      tv.tv_usec = 250000;

      if(select(m_socketDescriptor + 1, &rfds, &wfds, 0, &tv) > 0)
	{
	  if(FD_ISSET(m_socketDescriptor, &rfds) ||
	     FD_ISSET(m_socketDescriptor, &wfds))
	    {
	      int errorcode = 0;
	      int rc = 0;
	      socklen_t length = sizeof(errorcode);

#ifdef Q_OS_WIN32
	      rc = getsockopt
		(m_socketDescriptor, SOL_SOCKET,
		 SO_ERROR, (char *) &errorcode, &length);
#else
	      rc = getsockopt
		(m_socketDescriptor, SOL_SOCKET,
		 SO_ERROR, &errorcode, &length);
#endif

	      if(rc == 0)
		if(errorcode == 0)
		  if(m_state == ConnectingState)
		    {
		      m_state = ConnectedState;
		      emit connected();
		    }
	    }
	  else
	    close();
	}
      else
	close();
    }

  if(m_socketDescriptor < 0 || m_state != ConnectedState)
    return;

  QByteArray data(static_cast<int> (m_readBufferSize), 0);
  qint64 rc = read(data.data(), data.length());

  if(rc > 0)
    {
      if(static_cast<int> (rc) <= m_readBufferSize - m_readBuffer.length())
	m_readBuffer.append(data.mid(0, static_cast<int> (rc)));
      else
	{
	  int n = qMin
	    (static_cast<int> (m_readBufferSize) - m_readBuffer.length(),
	     static_cast<int> (rc));

	  if(n > 0)
	    m_readBuffer.append(data.mid(0, n));
	}

      emit readyRead();
    }
#ifdef Q_OS_WIN32
  else if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
  else if(!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
    close();
#endif
}
