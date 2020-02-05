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

#include <QStringList>

#include <limits>

#include "spot-on-misc.h"
#include "spot-on-socket-options.h"

#ifdef Q_OS_FREEBSD
extern "C"
{
#include <netinet/in.h>
#ifdef SPOTON_SCTP_ENABLED
#include <netinet/sctp.h>
#endif
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
}
#elif defined(Q_OS_LINUX)
extern "C"
{
#include <linux/net_tstamp.h>
#include <netinet/in.h>
#ifdef SPOTON_SCTP_ENABLED
#include <netinet/sctp.h>
#endif
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef SPOTON_SCTP_ENABLED
#include <usrsctp.h>
#endif
}
#elif defined(Q_OS_OPENBSD)
extern "C"
{
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
}
#elif defined(Q_OS_WIN)
extern "C"
{
#include <winsock2.h>
#ifdef SPOTON_SCTP_ENABLED
#include <ws2sctp.h>
#endif
}
#endif

void spoton_socket_options::setSocketOptions(const QString &options,
					     const QString &t,
#if defined(Q_OS_WIN)
					     const SOCKET socket,
#else
					     const qint64 socket,
#endif
					     bool *ok)
{
#if defined(Q_OS_WIN)
  if(socket == INVALID_SOCKET)
#else
  if(socket < 0)
#endif
    {
      if(ok)
	*ok = false;

      return;
    }

  QString transport(t.toLower().trimmed());
  QStringList list(options.toLower().split(";", QString::SkipEmptyParts));

  if(list.isEmpty())
    {
      if(ok)
	*ok = true;

      return;
    }

  if(ok)
    *ok = true;

  foreach(QString string, list)
    if(string.startsWith("nodelay=") && (transport == "sctp" ||
					 transport == "tcp" ||
					 transport == "websocket"))
      {
	string = string.mid(static_cast<int> (qstrlen("nodelay=")));

	if(!string.isEmpty())
	  {
#if SPOTON_SCTP_ENABLED
	    int level = IPPROTO_SCTP;
	    int option = SCTP_NODELAY;
#else
	    int level = IPPROTO_TCP;
	    int option = TCP_NODELAY;
#endif
	    int rc = 0;
	    int v = qBound(0, string.toInt(), 1);
	    socklen_t length = (socklen_t) sizeof(v);

	    if(transport == "tcp" || transport == "websocket")
	      {
		level = IPPROTO_TCP;
		option = TCP_NODELAY;
	      }

#if defined(Q_OS_WIN)
	    rc = setsockopt
	      (socket, level, option, (const char *) &v, (int) length);
#else
	    rc = setsockopt((int) socket, level, option, &v, length);
#endif

	    if(rc != 0)
	      {
		if(ok)
		  *ok = false;

		spoton_misc::logError
		  ("spoton_socket_options::setSocketOptions(): "
		   "setsockopt() failure on NODELAY.");
	      }
	  }
      }
    else if(string.
	    startsWith("so_keepalive=") && (transport == "sctp" ||
					    transport == "tcp" ||
					    transport == "websocket"))
      {
	string = string.mid(static_cast<int> (qstrlen("so_keepalive=")));

	if(!string.isEmpty())
	  {
	    int rc = 0;
	    int v = qBound(0, string.toInt(), 1);
	    socklen_t length = (socklen_t) sizeof(v);

#if defined(Q_OS_WIN)
	    rc = setsockopt(socket,
			    SOL_SOCKET,
			    SO_KEEPALIVE,
			    (const char *) &v,
			    (int) length);
#else
	    rc = setsockopt((int) socket, SOL_SOCKET, SO_KEEPALIVE, &v, length);
#endif

	    if(rc != 0)
	      {
		if(ok)
		  *ok = false;

		spoton_misc::logError
		  ("spoton_socket_options::setSocketOptions(): "
		   "setsockopt() failure on SO_KEEPALIVE.");
	      }
	  }
      }
    else if(string.startsWith("so_linger="))
      {
	string = string.mid(static_cast<int> (qstrlen("so_linger=")));

	int v = string.toInt();

	if(!string.isEmpty() && v >= 0)
	  {
	    int rc = 0;
	    socklen_t length = 0;

#if defined(Q_OS_WIN)
	    struct linger
	    {
	      u_short l_onoff;
	      u_short l_linger;
	    } l;

	    l.l_onoff = 1;
	    l.l_linger = static_cast<u_short> (v);
	    length = (socklen_t) sizeof(l);
	    rc = setsockopt
	      (socket, SOL_SOCKET, SO_LINGER, (const char *) &l, (int) length);
#else
	    struct linger l;

	    l.l_onoff = 1;
	    l.l_linger = v;
	    length = (socklen_t) sizeof(l);
	    rc = setsockopt((int) socket, SOL_SOCKET, SO_LINGER, &l, length);
#endif

	    if(rc != 0)
	      {
		if(ok)
		  *ok = false;

		spoton_misc::logError
		  ("spoton_socket_options::setSocketOptions(): "
		   "setsockopt() failure on SO_LINGER.");
	      }
	  }
      }
    else if((string.startsWith("so_rcvbuf=") ||
	     string.startsWith("so_sndbuf=")) && transport == "sctp")
      {
	string = string.mid(static_cast<int> (qstrlen("so_rcvbuf=")));

	if(!string.isEmpty())
	  {
	    int option = 0;

	    if(string.startsWith("so_rcvbuf="))
	      option = SO_RCVBUF;
	    else
	      option = SO_SNDBUF;

	    int rc = 0;
	    int v = qBound
	      (4096, string.toInt(), std::numeric_limits<int>::max());
	    socklen_t length = (socklen_t) sizeof(v);

#if defined(Q_OS_WIN)
	    rc = setsockopt
	      (socket, SOL_SOCKET, option, (const char *) &v, (int) length);
#else
	    rc = setsockopt((int) socket, SOL_SOCKET, option, &v, length);
#endif

	    if(rc != 0)
	      {
		if(ok)
		  *ok = false;

		spoton_misc::logError
		  ("spoton_socket_options::setSocketOptions(): "
		   "setsockopt() failure on SO_RCVBUF / SO_SNDBUF.");
	      }
	  }
      }
    else if(string.
	    startsWith("so_timestamping=") && (transport == "sctp" ||
					       transport == "tcp" ||
					       transport == "websocket" ||
					       transport == "udp"))
      {
#if defined(SO_TIMESTAMPING)
	string = string.mid(static_cast<int> (qstrlen("so_timestamping=")));

	if(!string.isEmpty())
	  {
	    int rc = 0;
	    int so_timestamping_flags = 0;

	    if(qBound(0, string.toInt(), 1))
	      {
		so_timestamping_flags |= SOF_TIMESTAMPING_RAW_HARDWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_RX_HARDWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_RX_SOFTWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_SOFTWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_SYS_HARDWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_TX_HARDWARE;
		so_timestamping_flags |= SOF_TIMESTAMPING_TX_SOFTWARE;
	      }

#if defined(Q_OS_WIN)
	    rc = setsockopt
	      (socket,
	       SOL_SOCKET,
	       SO_TIMESTAMPING,
	       (const char *) &so_timestamping_flags,
	       (int) sizeof(so_timestamping_flags));
#else
	    rc = setsockopt((int) socket,
			    SOL_SOCKET,
			    SO_TIMESTAMPING,
			    &so_timestamping_flags,
			    (socklen_t) sizeof(so_timestamping_flags));
#endif

	    if(rc != 0)
	      {
		if(ok)
		  *ok = false;

		spoton_misc::logError
		  ("spoton_socket_options::setSocketOptions(): "
		   "setsockopt() failure on SO_TIMESTAMPING.");
	      }
	  }
#endif
      }
}
