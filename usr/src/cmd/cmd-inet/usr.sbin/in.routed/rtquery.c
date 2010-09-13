/*
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 *
 * $FreeBSD: src/sbin/routed/rtquery/rtquery.c,v 1.14 2000/08/11 08:24:39
 * sheldonh Exp $
 * char copyright[] = "@(#) Copyright (c) 1982, 1986, 1993\n"
 * "The Regents of the University of California.  All rights reserved.\n";
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#define	RIPVERSION RIPv2
#include <protocols/routed.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <md5.h>
#include <libintl.h>
#include <locale.h>
#include <net/if.h>
#include <netinet/udp.h>

#ident "$Revision: 1.12 $"

#define	WTIME	15		/* Time to wait for all responses */
#define	STIME	(250*1000)	/* usec to wait for another response */

/*
 * The size of the control buffer passed to recvmsg() used to receive
 * ancillary data.
 */
#define	CONTROL_BUFSIZE 1024

static	const char *pgmname;

static	union {
	struct rip rip;
	char	packet[MAXPACKETSIZE+MAXPATHLEN];
} omsg_buf;
#define	OMSG omsg_buf.rip
static int omsg_len = sizeof (struct rip);

static	union {
	struct	rip rip;
	char	packet[MAXPACKETSIZE+1024];
} imsg_buf;
#define	IMSG imsg_buf.rip

static	int	wtime = WTIME;
static	int	auth_type = RIP_AUTH_NONE;
char	passwd[RIP_AUTH_PW_LEN+1];
static	ulong_t	keyid;
static	boolean_t	ripv2 = _B_TRUE;		/* use RIP version 2 */
static	boolean_t	trace, not_trace;	/* send trace command or not */
static	boolean_t	nflag;			/* numbers, no names */
static	boolean_t	pflag;			/* play the `gated` game */
static	boolean_t	rflag;		/* 1=ask about a particular route */

static	struct timeval sent;			/* when query sent */

static char *default_argv[] = {"localhost", 0};

static void rip_input(struct sockaddr_in *, int, uint_t);
static int out(const char *, int);
static void trace_loop(char *argv[], int);
static void query_loop(char *argv[], int, int);
static uint_t incoming_interface(struct msghdr *);
static void usage(void);


int
main(int argc, char *argv[])
{
#define	MAX_RCVBUF 127*1024
#define	MIN_RCVBUF  4*1024

	int ch, bsize, soc;
	char *p, *tmp_ptr, *options, *value, delim;
	const char *result;
	in_addr_t netaddr, netmask;
	int on;

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)   /* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEXT"
#endif	/* ! TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	OMSG.rip_nets[0].n_dst = RIP_DEFAULT;
	OMSG.rip_nets[0].n_family = RIP_AF_UNSPEC;
	OMSG.rip_nets[0].n_metric = htonl(HOPCNT_INFINITY);

	if ((pgmname = argv[0]) == NULL)
		pgmname = "rtquery";
	while ((ch = getopt(argc, argv, "np1w:r:t:a:")) != -1)
		switch (ch) {
		case 'n':
			not_trace = _B_TRUE;
			nflag = _B_TRUE;
			break;

		case 'p':
			not_trace = _B_TRUE;
			pflag = _B_TRUE;
			break;

		case '1':
			ripv2 = _B_FALSE;
			break;

		case 'w':
			not_trace = _B_TRUE;
			wtime = (int)strtoul(optarg, &p, 0);
			if (*p != '\0' || wtime <= 0 || p == optarg)
				usage();
			break;

		case 'r':
			not_trace = _B_TRUE;
			if (rflag)
				usage();
			rflag = getnet(optarg, &netaddr, &netmask);
			if (rflag) {
				OMSG.rip_nets[0].n_dst = htonl(netaddr);
				OMSG.rip_nets[0].n_family = RIP_AF_INET;
				OMSG.rip_nets[0].n_mask = htonl(netmask);
			} else {
				struct hostent *hp = gethostbyname(optarg);
				if (hp == NULL) {
					(void) fprintf(stderr, "%s: %s: %s\n",
					    pgmname, optarg,
					    hstrerror(h_errno));
					exit(EXIT_FAILURE);
				}
				(void) memcpy(&OMSG.rip_nets[0].n_dst,
				    hp->h_addr,
				    sizeof (OMSG.rip_nets[0].n_dst));
				OMSG.rip_nets[0].n_family = RIP_AF_INET;
				OMSG.rip_nets[0].n_mask = INADDR_BROADCAST;
				rflag = _B_TRUE;
			}
			break;

		case 't':
			trace = _B_TRUE;
			options = optarg;
			while (*options != '\0') {
				/* messy complications to make -W -Wall happy */
				static char on_str[] = "on";
				static char more_str[] = "more";
				static char off_str[] = "off";
				static char dump_str[] = "dump";
				static char *traceopts[] = {
#define	TRACE_ON	0
					on_str,
#define	TRACE_MORE	1
					more_str,
#define	TRACE_OFF	2
					off_str,
#define	TRACE_DUMP	3
					dump_str,
					0
				};
				result = "";
				switch (getsubopt(&options, traceopts,
				    &value)) {
				case TRACE_ON:
					OMSG.rip_cmd = RIPCMD_TRACEON;
					if (value == NULL ||
					    strlen(value) > MAXPATHLEN)
					    usage();
					result = value;
					break;
				case TRACE_MORE:
					if (value != NULL)
					    usage();
					OMSG.rip_cmd = RIPCMD_TRACEON;
					break;
				case TRACE_OFF:
					if (value != NULL)
					    usage();
					OMSG.rip_cmd = RIPCMD_TRACEOFF;
					break;
				case TRACE_DUMP:
					if (value != NULL)
					    usage();
					OMSG.rip_cmd = RIPCMD_TRACEON;
					result = "dump/../table";
					break;
				default:
					usage();
				}
				(void) strlcpy((char *)OMSG.rip_tracefile,
				    result, MAXPATHLEN);
				omsg_len += strlen(result) -
				    sizeof (OMSG.ripun);
			}
			break;

		case 'a':
			not_trace = _B_TRUE;
			p = strchr(optarg, '=');
			if (p == NULL)
				usage();
			*p++ = '\0';
			if (0 == strcasecmp("passwd", optarg))
				auth_type = RIP_AUTH_PW;
			else if (0 == strcasecmp("md5_passwd", optarg))
				auth_type = RIP_AUTH_MD5;
			else
				usage();
			if (0 > parse_quote(&p, "|", &delim,
			    passwd, sizeof (passwd)))
				usage();
			if (auth_type == RIP_AUTH_MD5 &&
			    delim == '|') {
				tmp_ptr = p+1;
				keyid = strtoul(p+1, &p, 0);
				if (keyid > 255 || *p != '\0' ||
				    p == tmp_ptr)
					usage();
			} else if (delim != '\0') {
				usage();
			}
			break;

		default:
			usage();
	}
	argv += optind;
	argc -= optind;
	if (not_trace && trace)
		usage();
	if (argc == 0) {
		argc = 1;
		argv = default_argv;
	}

	soc = socket(PF_INET, SOCK_DGRAM, 0);
	if (soc < 0) {
		perror("rtquery: socket");
		exit(EXIT_FAILURE);
	}

	on = 1;
	if (setsockopt(soc, IPPROTO_IP, IP_RECVIF, &on, sizeof (on)))
		perror("rtquery: setsockopt IP_RECVIF");

	/* be prepared to receive a lot of routes */
	for (bsize = MAX_RCVBUF; ; bsize -= 1024) {
		if (setsockopt(soc, SOL_SOCKET, SO_RCVBUF,
		    &bsize, sizeof (bsize)) == 0)
			break;
		if (bsize <= MIN_RCVBUF) {
			perror("rtquery: setsockopt SO_RCVBUF");
			break;
		}
	}

	if (trace)
		trace_loop(argv, soc);
	else
		query_loop(argv, argc, soc);
	/* NOTREACHED */
	return (0);
}


static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage:  %s [-np1] [-r tgt_rt] [-w wtime]"
		" [-a type=passwd] [host1 ...]\n"),
	    pgmname);
	(void) fprintf(stderr,
	    gettext("\t%s -t {on=filename|more|off|dump} [host1 ...]\n"),
	    pgmname);
	exit(EXIT_FAILURE);
}


/* Tell the target hosts about tracing */
static void
trace_loop(char *argv[], int soc)
{
	struct sockaddr_in myaddr;
	int res;
	int optval = 1;

	if (ripv2) {
		OMSG.rip_vers = RIPv2;
	} else {
		OMSG.rip_vers = RIPv1;
	}

	(void) memset(&myaddr, 0, sizeof (myaddr));
	myaddr.sin_family = AF_INET;
	if (setsockopt(soc, IPPROTO_UDP, UDP_ANONPRIVBIND,
	    &optval, sizeof (optval)) < 0) {
		perror("rtquery: setsockopt UDP_ANONPRIVBIND");
		exit(EXIT_FAILURE);
	}

	if (bind(soc, (struct sockaddr *)&myaddr, sizeof (myaddr)) < 0) {
		perror("rtquery: bind");
		exit(EXIT_FAILURE);
	}

	res = EXIT_FAILURE;
	while (*argv != NULL) {
		if (out(*argv++, soc) == 0)
			res = EXIT_SUCCESS;
	}
	exit(res);
}


/* Query all of the listed hosts */
static void
query_loop(char *argv[], int argc, int soc)
{
#define	NA0 (OMSG.rip_auths[0])
#define	NA2 (OMSG.rip_auths[2])
	struct seen {
		struct seen *next;
		struct in_addr addr;
	} *seen, *sp;
	int answered = 0;
	int cc;
	fd_set bits;
	struct timeval now, delay;
	struct sockaddr_in from;
	MD5_CTX md5_ctx;
	struct msghdr msg;
	uint_t	ifindex;
	struct iovec iov;
	uint8_t ancillary_data[CONTROL_BUFSIZE];


	OMSG.rip_cmd = (pflag) ? RIPCMD_POLL : RIPCMD_REQUEST;
	if (ripv2) {
		OMSG.rip_vers = RIPv2;
		if (auth_type == RIP_AUTH_PW) {
			OMSG.rip_nets[1] = OMSG.rip_nets[0];
			NA0.a_family = RIP_AF_AUTH;
			NA0.a_type = RIP_AUTH_PW;
			(void) memcpy(NA0.au.au_pw, passwd, RIP_AUTH_PW_LEN);
			omsg_len += sizeof (OMSG.rip_nets[0]);

		} else if (auth_type == RIP_AUTH_MD5) {
			OMSG.rip_nets[1] = OMSG.rip_nets[0];
			NA0.a_family = RIP_AF_AUTH;
			NA0.a_type = RIP_AUTH_MD5;
			NA0.au.a_md5.md5_keyid = (int8_t)keyid;
			NA0.au.a_md5.md5_auth_len = RIP_AUTH_MD5_LEN;
			NA0.au.a_md5.md5_seqno = 0;
			cc = (char *)&NA2-(char *)&OMSG;
			NA0.au.a_md5.md5_pkt_len = htons(cc);
			NA2.a_family = RIP_AF_AUTH;
			NA2.a_type = RIP_AUTH_TRAILER;
			MD5Init(&md5_ctx);
			MD5Update(&md5_ctx, (uchar_t *)&OMSG, cc+4);
			MD5Update(&md5_ctx,
			    (uchar_t *)passwd, RIP_AUTH_MD5_LEN);
			MD5Final(NA2.au.au_pw, &md5_ctx);
			omsg_len += 2*sizeof (OMSG.rip_nets[0]);
		}

	} else {
		OMSG.rip_vers = RIPv1;
		OMSG.rip_nets[0].n_mask = 0;
	}

	/* ask the first (valid) host */
	seen = NULL;
	while (0 > out(*argv++, soc)) {
		if (*argv == NULL)
			exit(EXIT_FAILURE);
		answered++;
	}

	iov.iov_base = &imsg_buf;
	iov.iov_len = sizeof (imsg_buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &from;
	msg.msg_control = &ancillary_data;

	(void) FD_ZERO(&bits);
	FD_SET(soc, &bits);
	for (;;) {
		delay.tv_sec = 0;
		delay.tv_usec = STIME;
		cc = select(soc+1, &bits, 0, 0, &delay);
		if (cc > 0) {
			msg.msg_namelen = sizeof (from);
			msg.msg_controllen = sizeof (ancillary_data);
			cc = recvmsg(soc, &msg, 0);
			if (cc < 0) {
				perror("rtquery: recvmsg");
				exit(EXIT_FAILURE);
			}

			/* avoid looping on high traffic */
			if (answered > argc + 200)
				break;

			/*
			 * count the distinct responding hosts.
			 * You cannot match responding hosts with
			 * addresses to which queries were transmitted,
			 * because a router might respond with a
			 * different source address.
			 */
			for (sp = seen; sp != NULL; sp = sp->next) {
				if (sp->addr.s_addr == from.sin_addr.s_addr)
					break;
			}
			if (sp == NULL) {
				sp = malloc(sizeof (*sp));
				if (sp != NULL) {
					sp->addr = from.sin_addr;
					sp->next = seen;
					seen = sp;
				} else {
					perror("rtquery: malloc");
				}
				answered++;
			}

			ifindex = incoming_interface(&msg);
			rip_input(&from, cc, ifindex);
			continue;
		}

		if (cc < 0) {
			if (errno == EINTR)
				continue;
			perror("rtquery: select");
			exit(EXIT_FAILURE);
		}

		/*
		 * After a pause in responses, probe another host.
		 * This reduces the intermingling of answers.
		 */
		while (*argv != NULL && 0 > out(*argv++, soc))
			answered++;

		/*
		 * continue until no more packets arrive
		 * or we have heard from all hosts
		 */
		if (answered >= argc)
			break;

		/* or until we have waited a long time */
		if (gettimeofday(&now, 0) < 0) {
			perror("rtquery: gettimeofday");
			exit(EXIT_FAILURE);
		}
		if (sent.tv_sec + wtime <= now.tv_sec)
			break;
	}

	/* fail if there was no answer */
	exit(answered >= argc ? EXIT_SUCCESS : EXIT_FAILURE);
}


/* Send to one host */
static int
out(const char *host, int soc)
{

	struct addrinfo hints, *res;
	int ret;

	if (gettimeofday(&sent, 0) < 0) {
		perror("rtquery: gettimeofday");
		return (-1);
	}

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if ((ret = getaddrinfo(host, "route", &hints, &res)) != 0) {
		(void) fprintf(stderr, "%s: getaddrinfo: %s: %s\n", pgmname,
		    host, gai_strerror(ret));
		return (-1);
	}

	if (sendto(soc, &omsg_buf, omsg_len, 0, res->ai_addr,
	    res->ai_addrlen) < 0) {
		perror("rtquery: sendto");
		return (-1);
	}

	freeaddrinfo(res);
	return (0);
}

/*
 * Handle an incoming RIP packet.
 */
static void
rip_input(struct sockaddr_in *from, int size, uint_t ifindex)
{
	struct netinfo *n, *lim;
	struct in_addr in;
	const char *name;
	char net_buf[80];
	uchar_t hash[RIP_AUTH_MD5_LEN];
	MD5_CTX md5_ctx;
	uchar_t md5_authed = 0;
	in_addr_t mask, dmask;
	struct in_addr tmp_addr;
	char *sp;
	char  ifname[IF_NAMESIZE+1];
	int i;
	struct hostent *hp;
	struct netent *np;
	struct netauth *na;
	char srcaddr[MAXHOSTNAMELEN + sizeof (" (123.123.123.123)") + 1];
	char ifstring[IF_NAMESIZE + 3*sizeof (ifindex) + sizeof (" ()") + 1];

	if (!nflag && (hp = gethostbyaddr((char *)&from->sin_addr,
	    sizeof (struct in_addr), AF_INET)) != NULL) {
		(void) snprintf(srcaddr, sizeof (srcaddr), "%s (%s)",
		    hp->h_name, inet_ntoa(from->sin_addr));
	} else {
		/* safe; cannot overflow destination */
		(void) strcpy(srcaddr, inet_ntoa(from->sin_addr));
	}
	if (ifindex == 0) {
		(void) printf("%s:", srcaddr);
	} else {
		if (if_indextoname(ifindex, ifname) != NULL)
			(void) snprintf(ifstring, sizeof (ifstring), "%s (%d)",
			    ifname, ifindex);
		else
			(void) snprintf(ifstring, sizeof (ifstring), "%d",
			    ifindex);
		(void) printf(gettext("%1$s received on interface %2$s:"),
		    srcaddr, ifstring);
	}

	if (IMSG.rip_cmd != RIPCMD_RESPONSE) {
		(void) printf(gettext("\n    unexpected response type %d\n"),
		    IMSG.rip_cmd);
		return;
	}
	(void) printf(gettext(" RIPv%1$d%2$s %3$d bytes\n"), IMSG.rip_vers,
	    (IMSG.rip_vers != RIPv1 && IMSG.rip_vers != RIPv2) ? " ?" : "",
	    size);
	if (size > MAXPACKETSIZE) {
		if (size > sizeof (imsg_buf) - sizeof (*n)) {
			(void) printf(
			    gettext("       at least %d bytes too long\n"),
			    size-MAXPACKETSIZE);
			size = sizeof (imsg_buf) - sizeof (*n);
		} else {
			(void) printf(gettext("       %d bytes too long\n"),
			    size-MAXPACKETSIZE);
		}
	} else if (size%sizeof (*n) != sizeof (struct rip)%sizeof (*n)) {
		(void) printf(gettext("    response of bad length=%d\n"), size);
	}

	n = IMSG.rip_nets;
	lim = n + (size - 4) / sizeof (struct netinfo);
	for (; n < lim; n++) {
		name = "";
		if (n->n_family == RIP_AF_INET) {
			in.s_addr = n->n_dst;
			(void) strlcpy(net_buf, inet_ntoa(in),
			    sizeof (net_buf));

			tmp_addr.s_addr = (n->n_mask);
			mask = ntohl(n->n_mask);
			dmask = mask & -mask;
			if (mask != 0) {
				sp = &net_buf[strlen(net_buf)];
				if (IMSG.rip_vers == RIPv1) {
					(void) snprintf(sp,
					    (sizeof (net_buf) -
					    strlen(net_buf)),
					    gettext(" mask=%s ? "),
					    inet_ntoa(tmp_addr));
					mask = 0;
				} else if (mask + dmask == 0) {
					i = ffs(mask) - 1;
					(void) snprintf(sp,
					    (sizeof (net_buf) -
					    strlen(net_buf)), "/%d", 32-i);
				} else {
					(void) snprintf(sp,
					    (sizeof (net_buf) -
						strlen(net_buf)),
					    gettext(" (mask %s)"),
					    inet_ntoa(tmp_addr));
				}
			}

			if (!nflag) {
				if (mask == 0) {
					mask = std_mask(in.s_addr);
					if ((ntohl(in.s_addr) & ~mask) != 0)
						mask = 0;
				}
				/*
				 * Without a netmask, do not worry about
				 * whether the destination is a host or a
				 * network. Try both and use the first name
				 * we get.
				 *
				 * If we have a netmask we can make a
				 * good guess.
				 */
				if ((in.s_addr & ~mask) == 0) {
					np = getnetbyaddr((long)in.s_addr,
					    AF_INET);
					if (np != NULL)
						name = np->n_name;
					else if (in.s_addr == 0)
						name = "default";
				}
				if (name[0] == '\0' &&
				    ((in.s_addr & ~mask) != 0 ||
				    mask == 0xffffffff)) {
					hp = gethostbyaddr((char *)&in,
					    sizeof (in), AF_INET);
					if (hp != NULL)
						name = hp->h_name;
				}
			}

		} else if (n->n_family == RIP_AF_AUTH) {
			na = (struct netauth *)n;
			if (na->a_type == RIP_AUTH_PW &&
			    n == IMSG.rip_nets) {
				(void) printf(
				    gettext("  Password Authentication:"
				    " \"%s\"\n"),
				    qstring(na->au.au_pw,
				    RIP_AUTH_PW_LEN));
				continue;
			}

			if (na->a_type == RIP_AUTH_MD5 &&
			    n == IMSG.rip_nets) {
				(void) printf(gettext("  MD5 Auth"
				    " len=%1$d KeyID=%2$d"
				    " auth_len=%3$d"
				    " seqno=%4$#x"
				    " rsvd=%5$#x,%6$#x\n"),
				    ntohs(na->au.a_md5.md5_pkt_len),
				    na->au.a_md5.md5_keyid,
				    na->au.a_md5.md5_auth_len,
				    (int)ntohl(na->au.a_md5.md5_seqno),
				    na->au.a_md5.rsvd[0],
				    na->au.a_md5.rsvd[1]);
				md5_authed = 1;
				continue;
			}
			(void) printf(gettext("  Authentication type %d: "),
			    ntohs(na->a_type));
			for (i = 0; i < sizeof (na->au.au_pw); i++)
				(void) printf("%02x ",
				    na->au.au_pw[i]);
			(void) putchar('\n');
			if (md5_authed && n+1 > lim &&
			    na->a_type == RIP_AUTH_TRAILER) {
				MD5Init(&md5_ctx);
				MD5Update(&md5_ctx, (uchar_t *)&IMSG,
				    (char *)na-(char *)&IMSG);
				MD5Update(&md5_ctx,
				    (uchar_t *)passwd, RIP_AUTH_MD5_LEN);
				MD5Final(hash, &md5_ctx);
				(void) printf(gettext("    %s hash\n"),
				    memcmp(hash, na->au.au_pw, sizeof (hash)) ?
				    gettext("WRONG") : gettext("correct"));
			} else if (md5_authed && n+1 > lim &&
			    na->a_type != RIP_AUTH_TRAILER) {
				(void) printf(gettext("Error -"
				"authentication entry missing hash\n"));
			}
			continue;

		} else {
			tmp_addr.s_addr = n->n_dst;
			(void) snprintf(net_buf, sizeof (net_buf),
			    gettext("(address family %1$u) %2$s"),
			    ntohs(n->n_family), inet_ntoa(tmp_addr));
		}

		(void) printf(gettext("  %1$-18s metric %2$2lu %3$-10s"),
		    net_buf, ntohl(n->n_metric), name);

		if (n->n_nhop != 0) {
			in.s_addr = n->n_nhop;
			if (nflag)
				hp = NULL;
			else
				hp = gethostbyaddr((char *)&in, sizeof (in),
				    AF_INET);
			(void) printf(gettext(" nhop=%1$-15s%2$s"),
			    (hp != NULL) ? hp->h_name : inet_ntoa(in),
			    (IMSG.rip_vers == RIPv1) ? " ?" : "");
		}
		if (n->n_tag != 0)
			(void) printf(gettext(" tag=%1$#x%2$s"), n->n_tag,
			    (IMSG.rip_vers == RIPv1) ? " ?" : "");
		(void) putchar('\n');
	}
}

/*
 * Find the interface which received the given message.
 */
static uint_t
incoming_interface(struct msghdr *msg)
{
	void *opt;
	uint_t ifindex = 0;

	/*
	 * Determine which physical interface this packet was received on by
	 * processing the message's ancillary data to find the
	 * IP_RECVIF option we requested.
	 */
	if ((opt = find_ancillary(msg, IP_RECVIF)) == NULL)
		(void) fprintf(stderr,
		    gettext("%s: unable to retrieve input interface\n"),
		    pgmname);
	else
		ifindex = *(uint_t *)opt;
	return (ifindex);
}
