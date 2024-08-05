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
#elif defined(Q_OS_MACOS)
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
#endif

#include "spot-on-misc.h"
#include "spot-on-socket-options.h"

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

#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
  auto const &list(options.toLower().split(';', Qt::SkipEmptyParts));
#else
  auto const &list(options.toLower().split(';', QString::SkipEmptyParts));
#endif
  auto const &transport(t.toLower().trimmed());

  if(list.isEmpty())
    {
      if(ok)
	*ok = true;

      return;
    }

  if(ok)
    *ok = true;

  foreach(auto const &s, list)
    {
      auto string(s);

      if(string.startsWith("ip_tos="))
	{
#ifndef Q_OS_WIN
	  string = string.mid(static_cast<int> (qstrlen("ip_tos=")));

	  if(!string.isEmpty())
	    {
	      auto const v = string.toInt();
	      auto const length = (socklen_t) sizeof(v);
	      int level = IPPROTO_IP;
	      int option = IP_TOS;
	      int rc = 0;

	      rc = setsockopt((int) socket, level, option, &v, length);

	      if(rc != 0)
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_socket_options::setSocketOptions(): "
		     "setsockopt() failure on IP_TOS.");
		}
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success on IP_TOS (%1)!").arg(v));
	    }
#endif
	}
      else if(string.startsWith("nodelay=") && (transport == "sctp" ||
						transport == "tcp" ||
						transport == "websocket"))
	{
	  string = string.mid(static_cast<int> (qstrlen("nodelay=")));

	  if(!string.isEmpty())
	    {
	      auto const v = qBound(0, string.toInt(), 1);
	      auto const length = (socklen_t) sizeof(v);
#ifdef SPOTON_SCTP_ENABLED
	      int level = IPPROTO_SCTP;
	      int option = SCTP_NODELAY;
#else
	      int level = IPPROTO_TCP;
	      int option = TCP_NODELAY;
#endif
	      int rc = 0;

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
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success on NODELAY (%1)!").arg(v));
	    }
	}
      else if(string.startsWith("so_keepalive=") && (transport == "sctp" ||
						     transport == "tcp" ||
						     transport == "websocket"))
	{
	  string = string.mid(static_cast<int> (qstrlen("so_keepalive=")));

	  if(!string.isEmpty())
	    {
	      auto const v = qBound(0, string.toInt(), 1);
	      auto const length = (socklen_t) sizeof(v);
	      int rc = 0;

#if defined(Q_OS_WIN)
	      rc = setsockopt(socket,
			      SOL_SOCKET,
			      SO_KEEPALIVE,
			      (const char *) &v,
			      (int) length);
#else
	      rc = setsockopt
		((int) socket, SOL_SOCKET, SO_KEEPALIVE, &v, length);
#endif

	      if(rc != 0)
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_socket_options::setSocketOptions(): "
		     "setsockopt() failure on SO_KEEPALIVE.");
		}
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success on SO_KEEPALIVE (%1)!").
		   arg(v));
	    }
	}
      else if(string.startsWith("so_linger="))
	{
	  string = string.mid(static_cast<int> (qstrlen("so_linger=")));

	  auto const v = string.toInt();

	  if(!string.isEmpty())
	    {
	      int rc = 0;
	      socklen_t length = 0;
#if defined(Q_OS_WIN)
	      struct linger
	      {
		u_short l_onoff;
		u_short l_linger;
	      } l;

	      l.l_linger = static_cast<u_short> (qAbs(v));
	      l.l_onoff = v < 0 ? 0 : 1;
	      length = (socklen_t) sizeof(l);
	      rc = setsockopt(socket,
			      SOL_SOCKET,
			      SO_LINGER,
			      (const char *) &l,
			      (int) length);
#else
	      struct linger l = {};

	      l.l_linger = qAbs(v);
	      l.l_onoff = v < 0 ? 0 : 1;
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
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success on SO_LINGER (%1)!").arg(v));
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

	      auto const v = qBound
		(4096, string.toInt(), std::numeric_limits<int>::max());
	      auto const length = (socklen_t) sizeof(v);
	      int rc = 0;

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
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success (%1) "
			   "on SO_RCVBUF / SO_SNDBUF!").
		   arg(v));
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
	      rc = setsockopt(socket,
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
	      else
		spoton_misc::logError
		  (QString("spoton_socket_options::setSocketOptions(): "
			   "setsockopt() success on SO_TIMESTAMPING (%1)!").
		   arg(so_timestamping_flags));
	    }
#endif
	}
    }
}
