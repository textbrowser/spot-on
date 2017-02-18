/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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
#include <sys/socket.h>
#include <sys/types.h>
}
#elif defined(Q_OS_LINUX)
extern "C"
{
#include <sys/socket.h>
#include <sys/types.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <sys/socket.h>
#include <sys/types.h>
}
#elif defined(Q_OS_WIN32)
extern "C"
{
#include <winsock2.h>
}
#endif

void spoton_socket_options::setSocketOptions
(const QString &options, const qint64 socket, bool *ok)
{
  if(socket < 0)
    {
      if(ok)
	*ok = false;

      return;
    }

  QStringList list(options.split(";", QString::SkipEmptyParts));

  if(list.isEmpty())
    {
      if(ok)
	*ok = true;

      return;
    }

  if(ok)
    *ok = true;

  foreach(QString string, list)
    if(string.startsWith("so_linger="))
      {
	string = string.mid(static_cast<int> (qstrlen("so_linger=")));

	int v = string.toInt();

	if(!string.isEmpty() && v >= 0)
	  {
	    int rc = 0;
	    socklen_t length = 0;

#ifdef Q_OS_WIN32
	    struct linger
	    {
	      u_short l_onoff;
	      u_short l_linger;
	    } l;

	    l.l_onoff = 1;
	    l.l_linger = static_cast<u_short> (v);
	    length = sizeof(l);
	    rc = setsockopt
	      ((SOCKET) socket,
	       SOL_SOCKET, SO_LINGER, (const char *) &l, (int) length);
#else
	    struct linger l;

	    l.l_onoff = 1;
	    l.l_linger = v;
	    length = sizeof(l);
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
    else if(string.startsWith("so_rcvbuf=") ||
	    string.startsWith("so_sndbuf="))
      {
	int option = 0;

	if(string.startsWith("so_rcvbuf="))
	  option = SO_RCVBUF;
	else
	  option = SO_SNDBUF;

	string = string.mid(static_cast<int> (qstrlen("so_rcvbuf=")));

	int v = qBound(4096, string.toInt(), std::numeric_limits<int>::max());

	if(!string.isEmpty() && v > 0)
	  {
	    int rc = 0;
	    socklen_t length = sizeof(v);

#ifdef Q_OS_WIN32
	    rc = setsockopt
	      ((SOCKET) socket,
	       SOL_SOCKET, option, (const char *) &v, (int) length);
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
}
