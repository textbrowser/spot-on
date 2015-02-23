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
#include <sys/socket.h>
#include <sys/time.h>
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

#define BUFSIZE 1024

#if defined(__Windows__)

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
    const TCHAR *fmt,
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
	fprintf(stderr, "Usage: %s host serv\n", argv0);
	exit(1);
}

int
__cdecl
main(
    int argc,
    TCHAR *argv[])
{
	int error = 0;
	struct addrinfo hints, *res, *res0;
	SOCKET sfd = INVALID_SOCKET;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char buf[BUFSIZE];
	int len;
	struct sockaddr_storage from;
	socklen_t fromlen;
#if defined(__Windows__)
	WSADATA wsaData;
	int ret = 0;
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		err(1, "WSAStartup");
		/*NOTREACHED*/
	}
#endif

	if (argc < 3) {
		usage(argv[0]);
		/*NOTREACHED*/
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	error = getaddrinfo(argv[1],
	    argv[2],
	    &hints, &res0);

	if (error) {
		errx(1, "%s", gai_strerror(error));
		/*NOTREACHED*/
	}

	for (res = res0; res; res = res->ai_next) {
		res->ai_protocol = IPPROTO_SCTP;
		sfd = socket(res->ai_family,
		    res->ai_socktype,
		    res->ai_protocol);
		if (sfd == INVALID_SOCKET) {
			warn("socket");
			continue;
		}

		error = getnameinfo(res->ai_addr, (socklen_t)res->ai_addrlen,
		    hbuf, NI_MAXHOST,
		    sbuf, NI_MAXSERV,
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (error) {
			errx(1, "%s", gai_strerror(error));
			/*NOTREACHED*/
		}

		fprintf(stderr, "Connecting to [%s]:%s ...\n", hbuf, sbuf);

		if (connect(sfd,
			res->ai_addr,
			(int)res->ai_addrlen)
		    < 0) {
			warn("Connection to [%s]:%s", hbuf, sbuf);
			closesocket(sfd);
			sfd = INVALID_SOCKET;
			continue;
		}
		fprintf(stderr, "Connecting Completed.\n");
		break;
	}

	freeaddrinfo(res0);

	if (sfd == INVALID_SOCKET) {
#if defined(__Windows__)
		WSACleanup();
#endif
		return 1;
	}

	for (;;) {
		memset(buf, 0, sizeof(buf));
		fgets(buf, _countof(buf), stdin);
		if (buf[0] == '\r' || buf[0] == '\n') {
			break;
		}

		if (sctp_send(sfd, buf, strlen(buf), NULL, 0) < 0) {
			err(1, "send");
			/*NOTREACHED*/
		}

		memset(buf, 0, BUFSIZE*sizeof(char));
		fromlen = sizeof(from);
		len = recvfrom(sfd, buf, BUFSIZE*sizeof(char), 0, (struct sockaddr *)&from, &fromlen);
		if (len < 0) {
			err(1, "recvfrom");
			/*NOTREACHED*/
		}
		fprintf(stderr, "SERVER: %s", buf);
	}

	closesocket(sfd);

#if defined(__Windows__)
	WSACleanup();
#endif

	return 0;
}
