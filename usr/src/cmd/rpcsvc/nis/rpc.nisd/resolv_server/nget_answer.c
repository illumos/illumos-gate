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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Formerly taken from 4.1.3 ypserv resolver code. */

/*
 * Copyright (c) 1995,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */


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

static int makecanon(const char *, char *, size_t);
static int samename(const char *, const char *);
static struct hostent *getanswer(const querybuf *, int, const char *,
    struct nres *);
extern int lookup_AF_type(struct cache_ent *chl);
extern uint16_t _getshort(const uchar_t *);
extern uint32_t _getlong(const uchar_t *);

#define	MAXALIASES	35
#define	MAXADDRS	35

static const char AskedForGot[] =
		"gethostby*.getanswer: asked for \"%s\", got \"%s\"";
static const char QuestionWas[] =
		"%s: question was \"%s\", came back as \"%s\"";

static char *h_addr_ptrs[MAXADDRS + 1];
static struct hostent host;
static char *host_aliases[MAXALIASES];
static char hostbuf[8*1024];

struct hostent *
nres_getanswer(struct nres *temp)
{
	querybuf	*answer;
	int		anslen;
	char 		*name;
	struct hostent	*ret;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	answer = (querybuf *)temp->answer;
	anslen = temp->answer_len;
	prnt(P_INFO, "nres_getanswer: name=%s search_name=%s\n",
	    temp->name, temp->search_name);
	name = temp->search_name;
	if (ret = getanswer(answer, anslen, name, temp)) {
		temp->h_errno = 0;
		prnt(P_INFO, "nres_getanswer: return OK.\n");
		return (ret);
	}

	temp->h_errno = h_errno;
	prnt(P_INFO, "nres_getanswer: return FAIL(err=%d).\n", h_errno);
	return ((struct hostent *)NULL);
}


int
nres_chkreply(struct nres *temp)
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
	/* LINTED E_BAD_PTR_CAST_ALIGN */
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
 * From usr/src/lib/libresolv2/common/nameser/ns_samedomain.c
 *
 * int
 * samename(a, b)
 *	determine whether domain name "a" is the same as domain name "b"
 * return:
 *	-1 on error
 *	0 if names differ
 *	1 if names are the same
 */

static int
samename(const char *a, const char *b) {
	char ta[MAXDNAME], tb[MAXDNAME];

	if (makecanon(a, ta, sizeof (ta)) < 0 ||
	    makecanon(b, tb, sizeof (tb)) < 0)
		return (-1);
	if (strcasecmp(ta, tb) == 0)
		return (1);
	else
		return (0);
}

/*
 * From usr/src/lib/libresolv2/common/nameser/ns_samedomain.c
 *
 * int
 * makecanon(src, dst, dstsize)
 *	make a canonical copy of domain name "src"
 * notes:
 *	foo -> foo.
 *	foo. -> foo.
 *	foo.. -> foo.
 *	foo\. -> foo\..
 *	foo\\. -> foo\\.
 * return:
 *	-1 if length of src string + "." > dstsize.
 *	0 Name canonized.
 *
 */

static int
makecanon(const char *src, char *dst, size_t dstsize) {
	size_t n = strlen(src);

	if (n + sizeof (".") > dstsize) {
		errno = EMSGSIZE;
		return (-1);
	}
	(void) strcpy(dst, src);
	while (n > 0 && dst[n - 1] == '.')		/* Ends in "." */
		if (n > 1 && dst[n - 2] == '\\' &&	/* Ends in "\." */
		    (n <= 2 || dst[n - 3] != '\\'))	/* But not "\\." */
			break;
		else
			dst[--n] = '\0';
	dst[n++] = '.';
	dst[n] = '\0';
	return (0);
}

/*
 * getanswer() formerly copied from
 * usr/src/lib/libresolv2/common/gethnamaddr.c.
 * Since then getanswer() has been replaced by gethostans() in
 * usr/src/lib/libresolv2/common/irs/dns_ho.c.
 * This function here is a mix between the old and new to maintain
 * compatibility.
 */

static struct hostent *
getanswer(const querybuf *answer, int anslen, const char *qname,
    struct nres *nres_ptr)
{
	const char *iam = "getanswer";
	const HEADER *hp;	/* Header Pointer */
	const uchar_t *cp;	/* Current Pointer */
	int n;
	const uchar_t *eom;	/* End Of Memory */
	const uchar_t *eor;	/* End Of Range */
	char *bp;		/* Beginning Pointer */
	char *ep;		/* End Pointer */
	char **ap;		/* Alias Names */
	char **hap;		/* Alias PTR */
	int type, class;
	int ancount, qdcount;	/* Answer count, Queried Count */
	int haveanswer, had_error;
	int toobig = 0;
	char tbuf[MAXDNAME+1];
	const char *tname;
	int (*name_ok) __P((const char *));
	int qtype = nres_ptr->qtype;
	int ttl; 		/* Time To Live */

	prnt(P_INFO, "%s: qname=%s\n", iam, qname);
	tname = qname;
	host.h_name = NULL;
	eom = answer->buf + anslen;
	switch (qtype) {
	case T_A:
	case T_AAAA:
		host.h_name = (char *)qname; /* Maybe changed by T_CNAME */
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
	if (answer->buf + HFIXEDSZ > eom) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	hp = &answer->hdr;
	ancount = ntohs(hp->ancount);
	qdcount = ntohs(hp->qdcount);
	bp = hostbuf;
	ep = hostbuf + sizeof (hostbuf);
	cp = answer->buf + HFIXEDSZ;
	if (qdcount != 1) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
	if ((n < 0) || !(*name_ok)(bp)) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}
	cp += n + QFIXEDSZ;
	if (cp > eom) {
		h_errno = NO_RECOVERY;
		return (NULL);
	}

	/* Verify this is the name we asked for */
	if (samename(qname, bp) != 1) {
		syslog(LOG_NOTICE|LOG_AUTH,
		    QuestionWas, iam, qname, bp);
		prnt(P_INFO, (char *)QuestionWas, iam, qname, bp);
		h_errno = NO_RECOVERY;
		return (NULL);
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
		n = dn_expand(answer->buf, eom, cp, bp, ep - bp);
		if ((n < 0) || !(*name_ok)(bp)) {
			had_error++;
			continue;
		}
		cp += n;			/* name */
		if ((cp + (3 * INT16SZ + INT32SZ)) > eom) {
			had_error++;
			continue;
		}
		type = _getshort(cp);
		cp += INT16SZ;			/* type */
		class = _getshort(cp);
		cp += INT16SZ;			/* class */
		ttl = _getlong(cp);
		cp += INT32SZ;			/* ttl */
		n = _getshort(cp);
		cp += INT16SZ;			/* len */
		if ((cp + n) > eom) {
			had_error++;
			continue;
		}
		if (class != C_IN) {
			cp += n;
			continue;
		}
		eor = cp + n;	/* limit name access to within len */
		if ((qtype == T_A || qtype == T_AAAA) && type == T_CNAME) {
			if (ap >= &host_aliases[MAXALIASES-1])
				continue;
			n = dn_expand(answer->buf, eor, cp, tbuf,
			    sizeof (tbuf));
			if ((n < 0) || !(*name_ok)(tbuf)) {
				prnt(P_INFO, "%s: CName not OK!\n", iam);
				had_error++;
				continue;
			}
			cp += n;
			/* Store alias. */
			*ap++ = bp;
			n = strlen(bp) + 1;	/* for the \0 */
			bp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > (ep - bp) || n > MAXHOSTNAMELEN) {
				had_error++;
				continue;
			}
			(void) strcpy(bp, tbuf);
			host.h_name = bp;
			bp += n;
			continue;
		}
		if (qtype == T_PTR && type == T_CNAME) {
			n = dn_expand(answer->buf, eor, cp, tbuf,
			    sizeof (tbuf));
			if ((n < 0) || !res_hnok(tbuf)) {
				had_error++;
				continue;
			}
			cp += n;
			/* Get canonical name. */
			n = strlen(tbuf) + 1;	/* for the \0 */
			if (n > (ep - bp)) {
				had_error++;
				continue;
			}
			(void) strcpy(bp, tbuf);
			tname = bp;
			bp += n;
			continue;
		}
		if (type != qtype) {
			syslog(LOG_NOTICE|LOG_AUTH,
			    "gethostby*.%s: "
			    "asked for \"%s %s %s\", got type \"%s\"",
			    iam, qname, p_class(C_IN), p_type(qtype),
			    p_type(type));
			cp += n;
			continue;
		}
		switch (type) {
		case T_PTR:
			if (samename(tname, bp) != 1) {
				syslog(LOG_NOTICE|LOG_AUTH,
				    AskedForGot, tname, bp);
				prnt(P_INFO, (char *)AskedForGot, iam,
				    tname, bp);
				cp += n;
				continue;
			}
			n = dn_expand(answer->buf, eor, cp, bp, (ep - bp));
			if ((n < 0) || !res_hnok(bp) ||
			    n >= MAXHOSTNAMELEN) {
				had_error++;
				break;
			}
#ifdef ORIGINAL_ISC_CODE	/* This isn't defined, see comment below */
			cp += n;
			if (!haveanswer) {
				host.h_name = bp;
			} else if (ap < &host_aliases[MAXALIASES-1])
				*ap++ = bp;
			else
				n = -1;
			if (n != -1) {
				n = strlen(bp) + 1;	/* for the \0 */
				bp += n;
			}
			break;
#else
			/*
			 * After looking up an address (REVERSE_PTR)
			 * nres_dorecv() immediately looks up the name
			 * returned here (REVERSE_A) and returns that
			 * as the result, assuming the answers match.
			 * Thus there is no reason to store more than
			 * one address here or the ttl.  Should that
			 * behavior change then this code would be
			 * removed.
			 */
			host.h_name = bp;
			h_errno = NETDB_SUCCESS;
			return (&host);
#endif
		case T_A:
		case T_AAAA:
			if (samename(host.h_name, bp) != 1) {
				syslog(LOG_NOTICE|LOG_AUTH,
				    AskedForGot, host.h_name, bp);
				prnt(P_INFO, (char *)AskedForGot,
				    iam, host.h_name, bp);
				cp += n;
				continue;
			}

			/* Don't accept unexpected address length */
			if (n != host.h_length) {
				cp += n;
				continue;
			}
			if (!haveanswer) {
				int nn;

				nn = (int)(strlen(bp) + 1);	/* for the \0 */
				if (nn >= MAXHOSTNAMELEN) {
					cp += n;
					had_error++;
					continue;
				}
				host.h_name = bp;
				bp += nn;
			}

			bp += sizeof (align) - ((ulong_t)bp % sizeof (align));

			if (bp + n >= &hostbuf[sizeof (hostbuf)]) {
				prnt(P_INFO, "%s: size (%ld) too big\n",
				    iam, (int)n);
				had_error++;
				continue;
			}
			if (hap >= &h_addr_ptrs[MAXADDRS-1]) {
				if (!toobig++)
					prnt(P_INFO,
					"%s: Too many addresses (%d)\n",
					    iam, MAXADDRS);
				cp += n;
				continue;
			}
			bcopy(cp, *hap++ = bp, n);
			bp += n;
			cp += n;
			break;
		default:
			abort();
		}
		if (!had_error) {
			haveanswer++;
			if (haveanswer == 1) /* Save first TTL */
				nres_ptr->ttl = ttl;
		}
	}
	if (haveanswer) {
		*ap = NULL;
		*hap = NULL;
		if (!host.h_name) {
			n =  strlen(qname) + 1;	/* for the \0 */
			if (n > (ep - bp))
				goto try_again;
			(void) strcpy(bp, qname);
			host.h_name = bp;
			bp += n;
		}
		h_errno = NETDB_SUCCESS;
		return (&host);
	}
try_again:
	h_errno = TRY_AGAIN;
	return (NULL);
}
