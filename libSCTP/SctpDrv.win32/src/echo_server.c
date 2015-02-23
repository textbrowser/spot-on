/*
 * Copyright (c) 2008 CO-CONV, Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#if !defined(__Windows__)
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#else
#include <winsock2.h>
#include <mswsock.h>
#include <WS2tcpip.h>
#include <WS2sctp.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENTS	32
#define BUFSIZE 1024

void usage(char *argv0);

#if defined(__Windows__)

void err(int eval, const char *fmt, ...);
void errx(int eval, const char *fmt, ...);
void warn(const char *fmt, ...);
void warnx(const char *fmt, ...);

void
err(
    int eval,
    const char *fmt,
    ...)
{
	va_list ap;
	LPSTR lpMsgBuf;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	FormatMessageA(
	    FORMAT_MESSAGE_ALLOCATE_BUFFER |
	    FORMAT_MESSAGE_FROM_SYSTEM,
	    NULL,
	    WSAGetLastError(),
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	    (LPSTR)&lpMsgBuf,
	    0, NULL );
	fprintf(stderr, ": %s", lpMsgBuf);

	exit(eval);
}

void
errx(
    int eval,
    const char *fmt,
    ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(eval);
}

void
warn(
    const char *fmt,
    ...)
{
	va_list ap;
	LPSTR lpMsgBuf;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	FormatMessageA(
	    FORMAT_MESSAGE_ALLOCATE_BUFFER |
	    FORMAT_MESSAGE_FROM_SYSTEM,
	    NULL,
	    WSAGetLastError(),
	    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	    (LPSTR)&lpMsgBuf,
	    0, NULL );
	fprintf(stderr, ": %s", lpMsgBuf);
	LocalFree(lpMsgBuf);
}

void
warnx(
    const char *fmt,
    ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#else
#define closesocket close
#define INVALID_SOCKET (-1)
#define __cdecl
typedef int SOCKET;
#endif

void
usage(
    char *argv0)
{
	fprintf(stderr, "Usage: %s serv\n", argv0);
	exit(1);
}

int
__cdecl
main(
    int argc,
    char *argv[])
{
	int error = 0;
	struct servent *servent;
	struct addrinfo hints, *res, *res0;
	SOCKET sfd = INVALID_SOCKET;
	SOCKET s = INVALID_SOCKET;
	SOCKET sfds[MAX_CLIENTS];
	SOCKET maxsfd = INVALID_SOCKET;
	int num_sfds = 0;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct fd_set readfds, oreadfds;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char buf[BUFSIZE];
	int n, len, i;
	struct sctp_sndrcvinfo sinfo;
	int msg_flags = 0;
#if defined(__Windows__)
	WSADATA wsaData;
	int ret = 0;
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		err(1, "WSAStartup");
		/*NOTREACHED*/
	}
#endif

	if (argc < 2) {
#if defined(__Windows)
		WSACleanup();
#endif
		usage(argv[0]);
		/*NOTREACHED*/
	}

	/* Set up the server socket, sfd */

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_SCTP;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(NULL,
	    argv[1], &hints, &res0);

	if (error) {
		errx(1, "%s", gai_strerror(error));
		/*NOTREACHED*/
	}

	for (res = res0; res; res = res->ai_next) {
		sfd = socket(res->ai_family,
		    res->ai_socktype,
		    res->ai_protocol);

		if (sfd == INVALID_SOCKET) {
			warn("socket(domain=%d,type=%d,protocol=%d)",
			    res->ai_family,
			    res->ai_socktype,
			    res->ai_protocol);
			continue;
		}

		error = getnameinfo(res->ai_addr, res->ai_addrlen,
		    hbuf, NI_MAXHOST,
		    sbuf, NI_MAXSERV,
		    NI_NUMERICHOST | NI_NUMERICSERV);

		if (error) {
			errx(1, "%s", gai_strerror(error));
			/*NOTREACHED*/
		}

		fprintf(stderr, "Binding to [%s]:%s ...\n", hbuf, sbuf);

		if (bind(sfd, res->ai_addr, res->ai_addrlen) < 0) {
			warn("Bind to [%s]:%s", hbuf, sbuf);
			closesocket(sfd);
			sfd = INVALID_SOCKET;
			continue;
		}

		if (listen(sfd, 5) < 0) {
			warn("Listen to [%s]:%s", hbuf, sbuf);
			closesocket(sfd);
			sfd = INVALID_SOCKET;
			continue;
		}

		fprintf(stderr, "Listening Completed.\n");
		break;
	}

	freeaddrinfo(res0);

	if (sfd == INVALID_SOCKET) {
#if defined(__Windows__)
		WSACleanup();
#endif
		return 1;
	}

	FD_ZERO(&oreadfds);
	FD_SET(sfd, &oreadfds);
	maxsfd = sfd;

	num_sfds = 0;
	for (;;) {
		for (i = 0; i < num_sfds; i++) {
			if (sfds[i] == INVALID_SOCKET)
				break;
		}
		if (i < num_sfds && i < MAX_CLIENTS - 1)
			memmove(&sfds[i], &sfds[i + 1], MAX_CLIENTS - 1 - i);

		readfds = oreadfds;
		n = select((int)maxsfd + 1, &readfds, NULL, NULL, NULL);
		if (n < 0) {
			err(1, "select");
			/*NOTREACHED*/
		}

		/* if the server fd is set, we have a new connection. */
		if (FD_ISSET(sfd, &readfds)) {
			memset(&addr, 0, sizeof(addr));
			addrlen = sizeof(addr);
			s = accept(sfd, (struct sockaddr *)&addr, &addrlen);
			if (s == INVALID_SOCKET) {
				warn("accept");
				continue;
			}

			error = getnameinfo((struct sockaddr *)&addr, addrlen,
			    hbuf, NI_MAXHOST,
			    sbuf, NI_MAXSERV,
			    NI_NUMERICHOST | NI_NUMERICSERV);
			if (error) {
				errx(1, "%s", gai_strerror(error));
				/*NOTREACHED*/
			}

			fprintf(stderr, "accept from [%s]:%s,s=%x\n", hbuf, sbuf, s);

			if (num_sfds < MAX_CLIENTS) {
				FD_SET(s, &oreadfds);
				sfds[num_sfds] = s;
				num_sfds++;
				if (maxsfd < s)
					maxsfd = s;
			} else {
				warnx("too many clients");
				closesocket(s);
			}
		} else {
			/* otherwise, an existing connection has data */
			for (i = 0; i < num_sfds; i++) {
				if (!FD_ISSET(sfds[i], &readfds))
					continue;

#if 0
				len = recv(sfds[i], (char *)buf, sizeof(char) * BUFSIZE, 0);
#else
				addrlen = sizeof(addr);
				memset(&sinfo, 0, sizeof(sinfo));
				len = sctp_recvmsg(sfds[i], buf, sizeof(char) * BUFSIZE, (struct sockaddr *)&addr, &addrlen, &sinfo, &msg_flags);
#endif
				if (len <= 0) {
					if (len < 0)
						warn("recv");

					fprintf(stderr, "close,s=%x\n", sfds[i]);
					closesocket(sfds[i]);
					FD_CLR(sfds[i], &oreadfds);
					sfds[i] = INVALID_SOCKET;
					num_sfds--;
					continue;
				}

				fprintf(stderr, "len=%d,sinfo_stream=%d,sinfo_assoc_id=%x\n", len, sinfo.sinfo_stream, sinfo.sinfo_assoc_id);

#if 0
				if (send(sfds[i], buf, len, 0) < 0) {
#else
				if (sctp_sendmsg(sfds[i], buf, len, NULL, 0, 0, 0, 1, 0, 0) < 0) {
#endif
					warn("send");
					fprintf(stderr, "close,s=%x\n", sfds[i]);
					closesocket(sfds[i]);
					FD_CLR(sfds[i], &oreadfds);
					sfds[i] = INVALID_SOCKET;
					num_sfds--;
					continue;
				}
			}
		}
	}

	closesocket(sfd);

#if defined(__Windows__)
	WSACleanup();
#endif

	return 0;
}
