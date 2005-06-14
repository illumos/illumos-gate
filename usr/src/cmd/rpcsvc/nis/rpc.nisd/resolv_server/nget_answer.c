/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1993,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Taken from 4.1.3 ypserv resolver code. */

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <syslog.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "nres.h"
#include "prnt.h"

#ifndef NO_DATA
#define	NO_DATA NO_ADDRESS
#endif

#ifndef LOG_AUTH
#define	LOG_AUTH 0
#endif

typedef union {
	HEADER	hdr;
	uchar_t	buf[MAXPACKET];
} querybuf;

typedef union {
    int32_t al;
    char ac;
} align;

extern int h_errno;

static struct hostent *getanswer(const querybuf *, int, const char *, int);
extern int lookup_AF_type(struct cache_ent *chl);
extern uint16_t _getshort(const uchar_t *);
extern uint32_t _getlong(const uchar_t *);

#define	MAXALIASES	35
#define	MAXADDRS	35

static const char AskedForGot[] =
		"gethostby*.getanswer: asked for \"%s\", got \"%s\"";

static char *h_addr_ptrs[MAXADDRS + 1];
static struct hostent host;
static char *host_aliases[MAXALIASES];
static char hostbuf[8*1024];



struct hostent *
nres_getanswer(temp)
struct nres *temp;
{
	querybuf	*answer;
	int		anslen;
	char 		*name;
	struct hostent	*ret;

	answer = (querybuf *)temp->answer;
	anslen = temp->answer_len;
	name = temp->name;
	if (ret = getanswer(answer, anslen, name, temp->qtype)) {
		temp->h_errno = 0;
		prnt(P_INFO, "nres_getanswer: return OK.\n");
		return (ret);
	}

	temp->h_errno = h_errno;
	prnt(P_INFO, "nres_getanswer: return FAIL(err=%d).\n", h_errno);
	return ((struct hostent *)NULL);
}


int
nres_chkreply(temp)
struct nres *temp;
{
	char		*answer;
	int		anslen;
	HEADER		*hp;
	answer = temp -> answer;
	anslen = temp -> answer_len;

	/* initialize some hosts variables for getanswer */
	host.h_addrtype = lookup_AF_type(temp->userinfo);
	host.h_length = (host.h_addrtype == AF_INET) ? INADDRSZ : IN6ADDRSZ;

	if (anslen <= 0) {
		prnt(P_INFO, "nres_chkreply: send error.\n");
		temp->h_errno = TRY_AGAIN;
		return (anslen);
	}
	hp = (HEADER *) answer;
	if (hp->rcode != NOERROR || ntohs(hp->ancount) == 0) {
		prnt(P_INFO, "rcode = %d, ancount=%d.\n", hp->rcode,
							ntohs(hp->ancount));
		switch (hp->rcode) {
		case NXDOMAIN:
			temp->h_errno = HOST_NOT_FOUND;
			break;
		case SERVFAIL:
			temp->h_errno = TRY_AGAIN;
			break;
		case NOERROR:
			temp->h_errno = NO_DATA;
			break;
		case FORMERR:
		case NOTIMP:
		case REFUSED:
		default:
			temp->h_errno = NO_RECOVERY;
			break;
		}
		return (-1);
	}
	return (anslen);
}





/*
 * getanswer() is copied from usr/src/lib/libresolv2/common/gethnamaddr.c.
 */

static struct hostent *
getanswer(answer, anslen, qname, qtype)
	const querybuf *answer;
	int anslen;
	const char *qname;
	int qtype;
{
	const HEADER *hp;
	const uchar_t *cp;
	int n;
	const uchar_t *eom;
	char *bp, **ap, **hap;
	int type, class, buflen, ancount, qdcount;
	int haveanswer, had_error;
	int toobig = 0;
	char tbuf[MAXDNAME+1];
	const char *tname;
	int (*name_ok) __P((const char *));

	prnt(P_INFO, "getanswer: qname=%s\n", qname);
	tname = qname;
	host.h_name = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
		name_ok = res_hnok;
		break;
	case T_PTR:
		name_ok = res_dnok;
		break;
	default:
		return (NULL);
	}
	/*
	 * find first satisfactory answer
	 */
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	buflen = sizeof (hostbuf);
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, buflen);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (qtype == T_A || qtype == T_AAAA) {
		/*
		 * res_send() has already verified that the query name is the
		 * same as the one we sent; this just gets the expanded name
		 * (i.e., with the succeeding search-domain tacked on).
		 */
		n = strlen(bp) + 1;		/* for the \0 */
		host.h_name = bp;
		bp += n;
		buflen -= n;
		/* The qname can be abbreviated, but h_name is now absolute. */
		qname = host.h_name;
	}
	ap = host_aliases;
	*ap = NULL;
	host.h_aliases = host_aliases;
	hap = h_addr_ptrs;
	*hap = NULL;
	host.h_addr_list = h_addr_ptrs;
	haveanswer = 0;
	had_error = 0;
	while (ancount-- > 0 && cp < eom && !had_error) {
		n = dn_expand(answer->buf, eom, cp, bp, buflen);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		type = _getshort(cp);
		cp += INT16SZ;			/* type */
		class = _getshort(cp);
		cp += INT16SZ + INT32SZ;	/* class, TTL */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if (class != C_IN) {
			/* XXX - debug? syslog? */
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
			if (ap >= &host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer->buf, eom, cp, tbuf,
							sizeof (tbuf));
			if ((n < 0) || !(*name_ok)(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			bp += n;
			buflen -= n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			host.h_name = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer->buf, eom, cp, tbuf,
							sizeof (tbuf));
			if ((n < 0) || !res_hnok(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > buflen) {
				had_error++;
				continue;
			}
			strcpy(bp, tbuf);
			tname = bp;
			bp += n;
			buflen -= n;
			continue;
		}
		if (type != qtype) {
			syslog(LOG_NOTICE|LOG_AUTH,
		"gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"",
				qname, p_class(C_IN), p_type(qtype),
				p_type(type));
			cp += n;
			continue;		/* XXX - had_error++ ? */
		}
		switch (type) {
		case T_PTR:
			if (strcasecmp(tname, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
					AskedForGot, tname, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
			n = dn_expand(answer->buf, eom, cp, bp, buflen);
			if ((n < 0) || !res_hnok(bp)) {
				had_error++;
				break;
			}
/*
 *	#if MULTI_PTRS_ARE_ALIASES
 *			cp += n;
 *			if (!haveanswer)
 *				host.h_name = bp;
 *			else if (ap < &host_aliases[MAXALIASES-1])
 *				*ap++ = bp;
 *			else
 *				n = -1;
 *			if (n != -1) {
 *				n = strlen(bp) + 1;	* for the \0 *
 *				bp += n;
 *				buflen -= n;
 *			}
 *			break;
 *	#else
 */
			host.h_name = bp;
			h_errno = NETDB_SUCCESS;
			return (&host);
/*
 *	#endif
 */
		case T_A:
		case T_AAAA:
			if (strcasecmp(host.h_name, bp) != 0) {
				syslog(LOG_NOTICE|LOG_AUTH,
					AskedForGot, host.h_name, bp);
				cp += n;
				continue;	/* XXX - had_error++ ? */
			}
#ifdef SUNW_REJECT_BOGUS_H_LENGTH
			/* Don't accept unexpected address length */
			if (n != host.h_length) {
				cp += n;
				continue;
			}
			if (!haveanswer) {
#else
			if (haveanswer) {
				if (n != host.h_length) {
					cp += n;
					continue;
				}
			} else {
#endif
				int nn;

				host.h_name = bp;
				nn = (int)(strlen(bp) + 1);	/* for the \0 */
				bp += nn;
				buflen -= nn;
			}

			bp += sizeof (align) - ((ulong_t)bp % sizeof (align));

			if (bp + n >= &hostbuf[sizeof (hostbuf)]) {
				prnt(P_INFO, "getanswer: size (%ld) too big\n",
					(int)n);
				had_error++;
				continue;
			}
			if (hap >= &h_addr_ptrs[MAXADDRS-1]) {
				if (!toobig++)
					prnt(P_INFO,
					"getanswer: Too many addresses (%d)\n",
					MAXADDRS);
				cp += n;
				continue;
			}
			bcopy(cp, *hap++ = bp, n);
			bp += n;
			buflen -= n;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error)
			haveanswer++;
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
		if (!host.h_name) {
			n =  strlen(qname) + 1;	/* for the \0 */
			if (n > buflen)
				goto try_again;
			strcpy(bp, qname);
			host.h_name = bp;
			bp += n;
			buflen -= n;
		}
		h_errno = NETDB_SUCCESS;
		return (&host);
	}
try_again:
	h_errno = TRY_AGAIN;
	return (NULL);
}
