/*	$OpenBSD: socks.c,v 1.17 2006/09/25 04:51:20 ray Exp $	*/

/*
 * Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>
#include <strings.h>
#include "atomicio.h"

#define	SOCKS_PORT	"1080"
#define	HTTP_PROXY_PORT	"3128"
#define	HTTP_MAXHDRS	64
#define	SOCKS_V5	5
#define	SOCKS_V4	4
#define	SOCKS_NOAUTH	0
#define	SOCKS_NOMETHOD	0xff
#define	SOCKS_CONNECT	1
#define	SOCKS_IPV4	1
#define	SOCKS_DOMAIN	3
#define	SOCKS_IPV6	4

#define	HTTP_10_407	"HTTP/1.0 407 "
#define	HTTP_10_200	"HTTP/1.0 200 "
#define	HTTP_11_200	"HTTP/1.1 200 "

int remote_connect(const char *, const char *, struct addrinfo);
int socks_connect(const char *, const char *,
	    const char *, const char *, struct addrinfo, int,
	    const char *);

/*
 * Convert string representation of host (h) and service/port (p) into
 * sockaddr structure and return 0 on success, -1 on failure.
 * Indicate whether the host address is IPv4 (v4only) and numeric.
 */
static int
decode_addrport(const char *h, const char *p, struct sockaddr *addr,
    socklen_t addrlen, int v4only, int numeric)
{
	int r;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof (hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	if (r != 0) {
		if (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		return (-1);
	}
	if (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	(void) memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (0);
}

/*
 * Read single line from a descriptor into buffer up to bufsz bytes,
 * byte by byte. Returns length of the line (including ending NULL),
 * exits upon failure.
 */
static int
proxy_read_line(int fd, char *buf, size_t bufsz)
{
	size_t off;

	for (off = 0; ; ) {
		if (off >= bufsz)
			errx(1, "proxy read too long");
		if (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		if (buf[off] == '\r')
			continue;
		if (buf[off] == '\n') {
			buf[off] = '\0';
			break;
		}
		/*
		 * we rewite \r\n to NULL since socks_connect() relies
		 * on *buf being zero in that case.
		 */
		off++;
	}
	return (off);
}

/*
 * Read proxy password from user and return it. The arguments are used
 * only for prompt construction.
 */
static const char *
getproxypass(const char *proxyuser, const char *proxyhost)
{
	char prompt[512];
	const char *pw;

	(void) snprintf(prompt, sizeof (prompt), "Proxy password for %s@%s: ",
	    proxyuser, proxyhost);
	if ((pw = getpassphrase(prompt)) == NULL)
		errx(1, "Unable to read proxy passphrase");
	return (pw);
}

/* perform connection via proxy using SOCKSv[45] or HTTP proxy CONNECT */
int
socks_connect(const char *host, const char *port, const char *proxyhost,
    const char *proxyport, struct addrinfo proxyhints, int socksv,
    const char *proxyuser)
{
	int proxyfd, r, authretry = 0;
	size_t hlen, wlen;
	char buf[1024];
	size_t cnt;
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	in_port_t serverport;
	const char *proxypass = NULL;

	if (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	if (decode_addrport("0.0.0.0", port, (struct sockaddr *)&addr,
	    sizeof (addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

again:
	if (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	if (proxyfd < 0)
		return (-1);

	if (socksv == 5) {
		if (decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof (addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		if (cnt != 3)
			err(1, "write failed (%zu/3)", cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		if (cnt != 2)
			err(1, "read failed (%zu/2)", cnt);

		if ((unsigned char)buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		case 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			if (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			(void) memcpy(buf + 5, host, hlen);
			(void) memcpy(buf + 5 + hlen, &serverport,
			    sizeof (serverport));
			wlen = 5 + hlen + sizeof (serverport);
			break;
		case AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			(void) memcpy(buf + 4, &in4->sin_addr,
			    sizeof (in4->sin_addr));
			(void) memcpy(buf + 8, &in4->sin_port,
			    sizeof (in4->sin_port));
			wlen = 4 + sizeof (in4->sin_addr) +
			    sizeof (in4->sin_port);
			break;
		case AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			(void) memcpy(buf + 4, &in6->sin6_addr,
			    sizeof (in6->sin6_addr));
			(void) memcpy(buf + 20, &in6->sin6_port,
			    sizeof (in6->sin6_port));
			wlen = 4 + sizeof (in6->sin6_addr) +
			    sizeof (in6->sin6_port);
			break;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		/*
		 * read proxy reply which is 4 byte "header", BND.ADDR
		 * and BND.PORT according to RFC 1928, section 6. BND.ADDR
		 * is 4 bytes in case of IPv4 which gives us 10 bytes in sum.
		 */
		cnt = atomicio(read, proxyfd, buf, 10);
		if (cnt != 10)
			err(1, "read failed (%zu/10)", cnt);
		if (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} else if (socksv == 4) {
		/* This will exit on lookup failure */
		(void) decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof (addr), 1, 0);

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		(void) memcpy(buf + 2, &in4->sin_port, sizeof (in4->sin_port));
		(void) memcpy(buf + 4, &in4->sin_addr, sizeof (in4->sin_addr));
		buf[8] = 0;	/* empty username */
		wlen = 9;

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", cnt, wlen);

		/*
		 * SOCKSv4 proxy replies consists of 2 byte "header",
		 * port number and numeric IPv4 address which gives 8 bytes.
		 */
		cnt = atomicio(read, proxyfd, buf, 8);
		if (cnt != 8)
			err(1, "read failed (%zu/8)", cnt);
		if (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} else if (socksv == -1) {
		/* HTTP proxy CONNECT according to RFC 2817, section 5 */

		/* Disallow bad chars in hostname */
		if (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		if (strchr(host, ':') != NULL) {
			r = snprintf(buf, sizeof (buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} else {
			r = snprintf(buf, sizeof (buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		if (r == -1 || (size_t)r >= sizeof (buf))
			errx(1, "hostname too long");
		r = strlen(buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		if (cnt != r)
			err(1, "write failed (%zu/%d)", cnt, r);

		if (authretry > 1) {
			char resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf(buf, sizeof (buf), "%s:%s",
			    proxyuser, proxypass);
			free((void *)proxypass);
			if (r == -1 || (size_t)r >= sizeof (buf) ||
			    b64_ntop((unsigned char *)buf, strlen(buf), resp,
			    sizeof (resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf(buf, sizeof (buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			if (r == -1 || (size_t)r >= sizeof (buf))
				errx(1, "Proxy auth response too long");
			r = strlen(buf);
			if ((cnt = atomicio(vwrite, proxyfd, buf, r)) != r)
				err(1, "write failed (%zu/%d)", cnt, r);
		}

		/* Terminate headers */
		if ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		(void) proxy_read_line(proxyfd, buf, sizeof (buf));
		if (proxyuser != NULL &&
		    strncmp(buf, HTTP_10_407, strlen(HTTP_10_407)) == 0) {
			if (authretry > 1) {
				(void) fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			(void) close(proxyfd);
			goto again;
		} else if (strncmp(buf, HTTP_10_200,
		    strlen(HTTP_10_200)) != 0 && strncmp(buf, HTTP_11_200,
		    strlen(HTTP_11_200)) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		/* Headers continue until we hit an empty line */
		for (r = 0; r < HTTP_MAXHDRS; r++) {
			(void) proxy_read_line(proxyfd, buf, sizeof (buf));
			if (*buf == '\0')
				break;
		}
		if (*buf != '\0')
			errx(1, "Too many proxy headers received");
	} else
		errx(1, "Unknown proxy protocol %d", socksv);

	return (proxyfd);
}
