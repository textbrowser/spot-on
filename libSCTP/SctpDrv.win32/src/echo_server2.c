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
    TCHAR *argv[])
{
	int error = 0;
	struct servent *servent;
	struct addrinfo hints, *res, *res0;
	SOCKET sfd = INVALID_SOCKET;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	struct sctp_event_subscribe events;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char buf[BUFSIZE];
	int n, len, i;
#if defined(__Windows__)
	DWORD bytes;

	LPFN_WSARECVMSG WSARecvMsg;
	GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
	LPFN_WSASENDMSG WSASendMsg;
	GUID WSASendMsg_GUID = WSAID_WSASENDMSG;

	WSAMSG msg;
	unsigned char msgbuf[(WSA_CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)))];
	WSACMSGHDR *cmsgp;
	WSABUF iovec;
	struct sctp_sndrcvinfo *srcv;
	sctp_assoc_t assoc_id;

	WSADATA wsaData;
	int ret = 0;
	ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		err(1, "WSAStartup");
		/*NOTREACHED*/
	}
#endif

	if (argc < 2) {
#if defined(__Windows__)
		WSACleanup();
#endif
		usage(argv[0]);
		/*NOTREACHED*/
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	error = getaddrinfo(NULL,
	    argv[1],
	    &hints, &res0);

	if (error) {
		errx(1, "%s", gai_strerror(error));
		/*NOTREACHED*/
	}

	for (res = res0; res; res = res->ai_next) {
		res->ai_socktype = SOCK_SEQPACKET;
		res->ai_protocol = IPPROTO_SCTP;

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

		if (WSAIoctl(sfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID),
			&WSARecvMsg, sizeof(void*),
			&bytes, NULL, NULL) != 0) {
			err(1, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER,WSARecvMsg)");
			/*NOTREACHED*/
		}

		if (WSAIoctl(sfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&WSASendMsg_GUID, sizeof(WSASendMsg_GUID),
			&WSASendMsg, sizeof(void*),
			&bytes, NULL, NULL) != 0) {
			err(1, "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER,WSASendMsg)");
			/*NOTREACHED*/
		}

		memset(&events, 0, sizeof(events));
		events.sctp_data_io_event = 1;
		if (setsockopt(sfd, IPPROTO_SCTP, SCTP_EVENTS,
			(char *)&events, sizeof(events)) < 0) {
			err(1, "setsockopt(IPPROTO_SCTP, SCTP_EVENTS)");
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
#if defined(__Windows)
		WSACleanup();
#endif
		return 1;
	}

	memset(&msgbuf, 0, sizeof(msgbuf));
	cmsgp = (WSACMSGHDR *)msgbuf;
	cmsgp->cmsg_level = IPPROTO_SCTP;
	cmsgp->cmsg_type = SCTP_SNDRCV;
	cmsgp->cmsg_len = sizeof(msgbuf);

	srcv = (struct sctp_sndrcvinfo *)(WSA_CMSG_DATA(cmsgp));

	memset(&msg, 0, sizeof(msg));
	iovec.buf = buf;
	iovec.len = sizeof(buf);

	msg.lpBuffers = &iovec;
	msg.dwBufferCount = 1;
	msg.name = (struct sockaddr *)&addr;
	msg.namelen = sizeof(addr);
	msg.Control.buf = msgbuf;
	msg.Control.len = sizeof(msgbuf);


	for (;;) {
		if (WSARecvMsg(sfd, &msg, &len,
			NULL, NULL) < 0) {
			warn("WSARecvMsg");
			continue;
		}
		error = GetNameInfo(msg.name, msg.namelen,
		    hbuf, NI_MAXHOST,
		    sbuf, NI_MAXSERV,
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (error) {
			errx(1, "%s", gai_strerror(error));
			/*NOTREACHED*/
		}
		assoc_id = srcv->sinfo_assoc_id;

		fprintf(stderr, "WSARecvMsg from [%s]:%s,sinfo_assoc_id=%x\n",
		    hbuf, sbuf,
		    assoc_id);

		memset(srcv, 0, sizeof(struct sctp_sndrcvinfo));
		srcv->sinfo_assoc_id = assoc_id;

#if 0
		if (WSASendMsg(sfd, &msg, 0, &len,
			NULL, NULL) < 0) {
#else
		if (sctp_send(sfd, buf, sizeof(buf), srcv, 0) < 0) {
#endif
			warn("WSASendMsg");
			continue;
		}
	}

	closesocket(sfd);

#if defined(__Windows__)
	WSACleanup();
#endif

	return 0;
}
