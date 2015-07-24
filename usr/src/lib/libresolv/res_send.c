/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2015 Gary Mills
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Send query to name server and wait for reply.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include "crossl.h"

/*
 * Undocumented external function in libsocket
 */
extern int
_socket(int, int, int);

static int s = -1;	/* socket used for communications */
#if	BSD >= 43
static struct sockaddr no_addr;
#endif /* BSD */


#ifndef FD_SET
#define	NFDBITS		32
#define	FD_SETSIZE	32
#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#ifdef SYSV
#define	FD_ZERO(p)	(void) memset((void *)(p), 0, sizeof (*(p)))
#else
#define	FD_ZERO(p)	bzero((char *)(p), sizeof (*(p)))
#endif
#endif

/*
 * 1247019: Kludge to time out quickly if there is no /etc/resolv.conf
 * and a TCP connection to the local DNS server fails.
 */

static int _confcheck()
{
	int ns;
	struct stat rc_stat;
	struct sockaddr_in ns_sin;


	/* First, we check to see if /etc/resolv.conf exists.
	 * If it doesn't, then localhost is mostlikely to be
	 * the nameserver.
	 */
	if (stat(_PATH_RESCONF, &rc_stat) == -1 && errno == ENOENT) {

		/* Next, we check to see if _res.nsaddr is set to loopback.
		 * If it isn't, it has been altered by the application
		 * explicitly and we then want to bail with success.
		 */
		if (_res.nsaddr.sin_addr.S_un.S_addr == htonl(INADDR_LOOPBACK)) {

			/* Lastly, we try to connect to the TCP port of the
			 * nameserver.  If this fails, then we know that
			 * DNS is misconfigured and we can quickly exit.
			 */
			ns = socket(AF_INET, SOCK_STREAM, 0);
			IN_SET_LOOPBACK_ADDR(&ns_sin);
			ns_sin.sin_port = htons(NAMESERVER_PORT);
			if (connect(ns, (struct sockaddr *) &ns_sin,
				    sizeof ns_sin) == -1) {
				close(ns);
				return(-1);
			}
			else {
				close(ns);
				return(0);
			}
		}
	
		return(0);
	}
	
	return (0);
}

int
res_send(buf, buflen, answer, anslen)
	char *buf;
	int buflen;
	char *answer;
	int anslen;
{
	register int n;
	int try, v_circuit, resplen, ns;
	int gotsomewhere = 0;
#if	BSD >= 43
	int connected = 0;
#endif /* BSD */
	int connreset = 0;
	u_short id, len;
	char *cp;
	fd_set dsmask;
	struct timeval timeout;
	HEADER *hp = (HEADER *) buf;
	HEADER *anhp = (HEADER *) answer;
	struct iovec iov[2];
	int terrno = ETIMEDOUT;
	char junk[512];

#ifdef DEBUG
	if (_res.options & RES_DEBUG) {
		printf("res_send()\n");
		p_query(buf);
	}
#endif
	if (!(_res.options & RES_INIT))
		if (res_init() == -1) {
			return (-1);
		}

	/* 1247019: Check to see if we can bailout quickly. */
	if (_confcheck() == -1)
	    return(-1);

	v_circuit = (_res.options & RES_USEVC) || buflen > PACKETSZ;
	id = hp->id;
	/*
	 * Send request, RETRY times, or until successful
	 */
	for (try = 0; try < _res.retry; try++) {
		for (ns = 0; ns < _res.nscount; ns++) {
#ifdef DEBUG
			if (_res.options & RES_DEBUG)
				printf("Querying server (# %d) address = %s\n",
				ns+1, inet_ntoa(_res.nsaddr_list[ns].sin_addr));
#endif
		usevc:
			if (v_circuit) {
				int truncated = 0;

				/*
				 * Use virtual circuit;
				 * at most one attempt per server.
				 */
				try = _res.retry;
				if (s < 0) {
					s = _socket(AF_INET, SOCK_STREAM, 0);
					if (s < 0) {
						terrno = errno;
#ifdef DEBUG
						if (_res.options & RES_DEBUG) {
						perror("socket (vc) failed");
						}
#endif
						continue;
					}
					if (connect(s, (struct sockaddr *) &_res.nsaddr_list[ns],
						sizeof (struct sockaddr)) < 0) {
						terrno = errno;
#ifdef DEBUG
						if (_res.options & RES_DEBUG) {
						perror("connect failed");
						}
#endif
						(void) close(s);
						s = -1;
						continue;
					}
				}
				/*
				 * Send length & message
				 */
				len = htons((u_short)buflen);
				iov[0].iov_base = (caddr_t)&len;
				iov[0].iov_len = sizeof (len);
				iov[1].iov_base = buf;
				iov[1].iov_len = buflen;
				if (writev(s, iov, 2) != sizeof (len) +
								buflen) {
					terrno = errno;
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						perror("write failed");
#endif
					(void) close(s);
					s = -1;
					continue;
				}
				/*
				 * Receive length & response
				 */
				cp = answer;
				len = sizeof (short);
				while (len != 0 && (n = read
					(s, (char *)cp, (int)len)) > 0) {
					cp += n;
					len -= n;
				}
				if (n <= 0) {
					terrno = errno;
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						perror("read failed");
#endif
					(void) close(s);
					s = -1;
				/*
				 * A long running process might get its TCP
				 * connection reset if the remote server was
				 * restarted.  Requery the server instead of
				 * trying a new one.  When there is only one
				 * server, this means that a query might work
				 * instead of failing.  We only allow one reset
				 * per query to prevent looping.
				 */
					if (terrno == ECONNRESET &&
							!connreset) {
						connreset = 1;
						ns--;
					}
					continue;
				}
				cp = answer;
				if ((resplen = ntohs(*(u_short *)cp)) >
								anslen) {
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						fprintf(stderr,
							"response truncated\n");
#endif
					len = anslen;
					truncated = 1;
				} else
					len = resplen;
				while (len != 0 &&
					(n = read(s, (char *)cp,
							(int)len)) > 0) {
					cp += n;
					len -= n;
				}
				if (n <= 0) {
					terrno = errno;
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						perror("read failed");
#endif
					(void) close(s);
					s = -1;
					continue;
				}
				if (truncated) {
					/*
					 * Flush rest of answer
					 * so connection stays in synch.
					 */
					anhp->tc = 1;
					len = resplen - anslen;
					/*
					 * set the value of resplen to anslen,
					 * this is done because the caller
					 * assumes resplen contains the size of
					 * message read into the "answer" buffer
					 * passed in.
					 */
					resplen = anslen;

					while (len != 0) {
						n = (len > sizeof (junk) ?
							sizeof (junk) : len);
						if ((n = read(s, junk, n)) > 0)
							len -= n;
						else
							break;
					}
				}
			} else {
				/*
				 * Use datagrams.
				 */
				if (s < 0) {
					s = _socket(AF_INET, SOCK_DGRAM, 0);
					if (s < 0) {
						terrno = errno;
#ifdef DEBUG
						if (_res.options & RES_DEBUG) {
						perror("socket (dg) failed");
						}
#endif
						continue;
					}
				}
#if	BSD >= 43
			/*
			 * I'm tired of answering this question, so:
			 * On a 4.3BSD+ machine (client and server,
			 * actually), sending to a nameserver datagram
			 * port with no nameserver will cause an
			 * ICMP port unreachable message to be returned.
			 * If our datagram socket is "connected" to the
			 * server, we get an ECONNREFUSED error on the next
			 * socket operation, and select returns if the
			 * error message is received.  We can thus detect
			 * the absence of a nameserver without timing out.
			 * If we have sent queries to at least two servers,
			 * however, we don't want to remain connected,
			 * as we wish to receive answers from the first
			 * server to respond.
			 */
				if (_res.nscount == 1 ||
						(try == 0 && ns == 0)) {
					/*
					 * Don't use connect if we might
					 * still receive a response
					 * from another server.
					 */
					if (connected == 0) {
						if (connect(s,
						(struct sockaddr *) &_res.nsaddr_list[ns],
						sizeof (struct sockaddr)) < 0) {
#ifdef DEBUG
							if (_res.options &
								RES_DEBUG) {
							perror("connect");
							}
#endif
							continue;
						}
						connected = 1;
					}
					if (send(s, buf, buflen, 0) != buflen) {
#ifdef DEBUG
						if (_res.options & RES_DEBUG)
							perror("send");
#endif
						continue;
					}
				} else {
					/*
					 * Disconnect if we want to listen for
					 * responses from more than one server.
					 */
					if (connected) {
						(void) connect(s, &no_addr,
							sizeof (no_addr));
						connected = 0;
					}
#endif /* BSD */
					if (sendto(s, buf, buflen, 0,
						(struct sockaddr *) &_res.nsaddr_list[ns],
					sizeof (struct sockaddr)) != buflen) {
#ifdef DEBUG
						if (_res.options & RES_DEBUG)
							perror("sendto");
#endif
						continue;
					}
#if	BSD >= 43
				}
#endif

				/*
				 * Wait for reply
				 */
				timeout.tv_sec = (_res.retrans << try);
				if (try > 0)
					timeout.tv_sec /= _res.nscount;
				if (timeout.tv_sec <= 0)
					timeout.tv_sec = 1;
				timeout.tv_usec = 0;
wait:
				FD_ZERO(&dsmask);
				FD_SET(s, &dsmask);
				n = select(s+1, &dsmask, (fd_set *)NULL,
						(fd_set *)NULL, &timeout);
				if (n < 0) {
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						perror("select");
#endif
					continue;
				}
				if (n == 0) {
					/*
					 * timeout
					 */
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						printf("timeout\n");
#endif
#if BSD >= 43
					gotsomewhere = 1;
#endif
					continue;
				}
				if ((resplen = recv(s, answer, anslen, 0))
									<= 0) {
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						perror("recvfrom");
#endif
					continue;
				}
				gotsomewhere = 1;
				if (id != anhp->id) {
					/*
					 * response from old query, ignore it
					 */
#ifdef DEBUG
					if (_res.options & RES_DEBUG) {
						printf("old answer:\n");
						p_query(answer);
					}
#endif
					goto wait;
				}
				if (!(_res.options & RES_IGNTC) && anhp->tc) {
					/*
					 * get rest of answer;
					 * use TCP with same server.
					 */
#ifdef DEBUG
					if (_res.options & RES_DEBUG)
						printf("truncated answer\n");
#endif
					(void) close(s);
					s = -1;
					v_circuit = 1;
					goto usevc;
				}
			}
#ifdef DEBUG
			if (_res.options & RES_DEBUG) {
				printf("got answer:\n");
				p_query(answer);
			}
#endif
		/*
		 * If using virtual circuits, we assume that the first server
		 * is preferred * over the rest (i.e. it is on the local
		 * machine) and only keep that one open.
		 * If we have temporarily opened a virtual circuit,
		 * or if we haven't been asked to keep a socket open,
		 * close the socket.
		 */
			if ((v_circuit &&
				((_res.options & RES_USEVC) == 0 || ns != 0)) ||
				(_res.options & RES_STAYOPEN) == 0) {
				(void) close(s);
				s = -1;
			}
			return (resplen);
		}
	}
	if (s >= 0) {
		(void) close(s);
		s = -1;
	}
	if (v_circuit == 0)
		if (gotsomewhere == 0)
			errno = ECONNREFUSED;	/* no nameservers found */
		else
			errno = ETIMEDOUT;	/* no answer obtained */
	else
		errno = terrno;
	return (-1);
}

/*
 * This routine is for closing the socket if a virtual circuit is used and
 * the program wants to close it.  This provides support for endhostent()
 * which expects to close the socket.
 *
 * This routine is not expected to be user visible.
 */
void
_res_close()
{
	if (s != -1) {
		(void) close(s);
		s = -1;
	}
}
