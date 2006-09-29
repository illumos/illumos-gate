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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Ye olde non-reentrant interface (MT-unsafe, caveat utor)
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
#include <sys/socket.h>

/*
 * Still just a global.  If you want per-thread h_errno,
 * use the reentrant interfaces (gethostbyname_r et al)
 */
int h_errno;

#ifdef	NSS_INCLUDE_UNSAFE

/*
 * Don't free this, even on an endhostent(), because bitter experience shows
 * that there's production code that does getXXXbyYYY(), then endXXXent(),
 * and then continues to use the pointer it got back.
 */
static nss_XbyY_buf_t *buffer;
#define	GETBUF()	\
	NSS_XbyY_ALLOC(&buffer, sizeof (struct hostent), NSS_BUFLEN_HOSTS)
	/* === ?? set ENOMEM on failure?  */

struct hostent *
gethostbyname(const char *nam)
{
	nss_XbyY_buf_t  *b;

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (gethostbyname_r(nam, b->result, b->buffer, b->buflen,
		    &h_errno));
}

struct hostent *
gethostbyaddr(const void *addr, socklen_t len, int type)
{
	nss_XbyY_buf_t	*b;

	h_errno = 0;
	if (type == AF_INET6)
		return (getipnodebyaddr(addr, len, type, &h_errno));

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (gethostbyaddr_r(addr, len, type,
		    b->result, b->buffer, b->buflen, &h_errno));
}

struct hostent *
gethostent(void)
{
	nss_XbyY_buf_t	*b;

	if ((b = GETBUF()) == 0)
		return (NULL);
	return (gethostent_r(b->result, b->buffer, b->buflen, &h_errno));
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
int
__str2hostent(int af, const char *instr, int lenstr, void *ent, char *buffer,
    int buflen)
{
	struct hostent	*host	= (struct hostent *)ent;
	const char	*p, *addrstart, *limit;
	int		naddr, i, aliases_erange = 0;
	int		addrlen, res;
	char		addrbuf[100];  /* Why 100? */
	struct in_addr	*addrp;
	struct in6_addr	*addrp6;
	char		**addrvec;

	if ((instr >= buffer && (buffer + buflen) > instr) ||
	    (buffer >= instr && (instr + lenstr) > buffer))
		return (NSS_STR_PARSE_PARSE);
	if (af != AF_INET && af != AF_INET6) {
		/*
		 * XXX - Returning ERANGE here is completely bogus.
		 * Unfortunately, there's no error code identifying
		 * bogus calls from the backend (and nothing the user
		 * can do about our bugs anyway).
		 */
		return (NSS_STR_PARSE_ERANGE);
	}

	/*
	 * The DNS-via-YP code returns multiple lines for a key.
	 * Normal YP return values do not contain newlines (nor do
	 * lines from /etc/hosts or other sources)
	 * We count the number of newlines; this should give us
	 * the number of IP addresses specified.
	 * We'll also call the aliases code and instruct it to
	 * stop at the first newline as the remaining lines will
	 * all contain the same hostname/aliases (no aliases, unfortunately).
	 *
	 * When confronted with a string with embedded newlines,
	 * this code will take the hostname/aliases on the first line
	 * and each of the IP addresses at the start of all lines.
	 * Because the NIS protocol limits return values to 1024 bytes,
	 * we still do not get all addresses.  If you want to fix
	 * that problem, do not look here.
	 */

	p = instr;

	/* Strip trailing newlines */
	while (lenstr > 0 && p[lenstr - 1] == '\n')
		lenstr--;

	naddr = 1;
	limit = p + lenstr;

	for (; p < limit && (p = memchr(p, '\n', limit - p)); p++)
		naddr++;

	/* Allocate space for naddr addresses and h_addr_list */

	if (af == AF_INET6) {
		addrp6 = (struct in6_addr *)ROUND_DOWN(buffer + buflen,
		    sizeof (*addrp6));
		addrp6 -= naddr;
		addrvec = (char **)ROUND_DOWN(addrp6, sizeof (*addrvec));
		addrvec -= naddr + 1;
	} else {
		addrp = (struct in_addr *)ROUND_DOWN(buffer + buflen,
		    sizeof (*addrp));
		addrp -= naddr;
		addrvec = (char **)ROUND_DOWN(addrp, sizeof (*addrvec));
		addrvec -= naddr + 1;
	}

	if ((char *)addrvec < buffer)
		return (NSS_STR_PARSE_ERANGE);

	/* For each addr, parse and get it */

	p = instr;

	for (i = 0; i < naddr; i ++) {

		limit = memchr(p, '\n', lenstr - (p - instr));
		if (limit == NULL)
			limit = instr + lenstr;

		while (p < limit && isspace(*p))
			p++;
		addrstart = p;
		while (p < limit && !isspace(*p))
			p++;
		if (p >= limit)
		    /* Syntax error - no hostname present or truncated line */
		    return (NSS_STR_PARSE_PARSE);
		addrlen = p - addrstart;
		if (addrlen >= sizeof (addrbuf))
			/* Syntax error -- supposed IP address is too long */
			return (NSS_STR_PARSE_PARSE);
		(void) memcpy(addrbuf, addrstart, addrlen);
		addrbuf[addrlen] = '\0';

		if (addrlen > ((af == AF_INET6) ? INET6_ADDRSTRLEN
							: INET_ADDRSTRLEN))
			/* Syntax error -- supposed IP address is too long */
			return (NSS_STR_PARSE_PARSE);
		if (af == AF_INET) {
			/*
			 * inet_pton() doesn't handle d.d.d, d.d, or d formats,
			 * so we must use inet_addr() for IPv4 addresses.
			 */
			addrvec[i] = (char *)&addrp[i];
			if ((addrp[i].s_addr = inet_addr(addrbuf)) ==
								0xffffffffU)
				/* Syntax error -- bogus IPv4 address */
				return (NSS_STR_PARSE_PARSE);
		} else {
			/*
			 * In the case of AF_INET6, we can have both v4 and v6
			 * addresses, so we convert v4's to v4 mapped addresses
			 * and return them as such.
			 */
			addrvec[i] = (char *)&addrp6[i];
			if (strchr(addrbuf, ':') != 0) {
				if (inet_pton(af, addrbuf, &addrp6[i]) != 1)
					return (NSS_STR_PARSE_PARSE);
			} else {
				struct in_addr in4;
				if ((in4.s_addr = inet_addr(addrbuf)) ==
								0xffffffffU)
					return (NSS_STR_PARSE_PARSE);
				IN6_INADDR_TO_V4MAPPED(&in4, &addrp6[i]);
			}
		}

		/* First address, this is where we get the hostname + aliases */
		if (i == 0) {
			while (p < limit && isspace(*p)) {
				p++;
			}
			host->h_aliases = _nss_netdb_aliases(p, limit - p,
				buffer, ((char *)addrvec) - buffer);
			if (host->h_aliases == NULL)
				aliases_erange = 1; /* too big for buffer */
		}
		if (limit >= instr + lenstr)
			break;
		else
			p = limit + 1;		/* skip NL */
	}

	if (host->h_aliases == 0) {
		if (aliases_erange)
			res = NSS_STR_PARSE_ERANGE;
		else
			res = NSS_STR_PARSE_PARSE;
	} else {
		/* Success */
		host->h_name = host->h_aliases[0];
		host->h_aliases++;
		res = NSS_STR_PARSE_SUCCESS;
	}
	/*
	 * If i < naddr, we quit the loop early and addrvec[i+1] needs NULL
	 * otherwise, we ran naddr iterations and addrvec[naddr] needs NULL
	 */
	addrvec[i >= naddr ? naddr : i + 1] = 0;
	if (af == AF_INET6) {
		host->h_length    = sizeof (struct in6_addr);
	} else {
		host->h_length    = sizeof (struct in_addr);
	}
	host->h_addrtype  = af;
	host->h_addr_list = addrvec;

	return (res);
}
#endif	/* NSS_INCLUDE_UNSAFE */
