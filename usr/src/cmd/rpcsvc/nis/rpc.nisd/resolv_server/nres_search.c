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

/* Taken from 4.1.3 ypserv resolver code. */

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "nres.h"
#include "prnt.h"

static void nres_querydomain(char *, char *, char *);
static char *nres_hostalias(char *);

int
nres_search(struct nres *block)
{
	register char	*cp, *domain;
	int		n, trailing_dot = 0;

	if ((_res.options & RES_INIT) == 0 && res_init() == -1)
		return (-1);

	block->retries = 0;	/* start clock */
	/* Return if domain search previously exhausted. */
	if (block->search_index < 0)
		return (-1);

	/* Reverse lookups have limited domains. */
	if (block->reverse == REVERSE_PTR) {
		if (block->af_type == AF_INET6) { /* IPv6 */
			/*
			 * Reverse lookups strictly speaking only have
			 * one domain. But the IPv6 one changed and so
			 * for backward compatibility we try both of
			 * them, using search_index to signify which
			 * has been tried.
			 */
			if (block->search_index == 0) {
				/* First pass, try RFC 3152 address. */
				(void) nres_querydomain(block->name,
				    "ip6.arpa", block->search_name);
				block->search_index = 1;
			} else {
				/* Final pass, try RFC 1886 address. */
				(void) nres_querydomain(block->name,
				    "ip6.int", block->search_name);
				block->search_index = -1;
			}
			return (0);
		} else if (block->af_type == AF_INET) { /* IPv4 */
			(void) nres_querydomain(block->name, "in-addr.arpa",
			    block->search_name);
			block->search_index = -1;
			return (0);
		}
	} else if (block->reverse == REVERSE_A) {
		/* We only lookup the exact name in this case. */
		(void) nres_querydomain(block->name, (char *)NULL,
		    block->search_name);
		block->search_index = -1;
		return (0);
	}

	/* Count the number of dots and record trailing dot status. */
	for (cp = block->name, n = 0; *cp; cp++)
		if (*cp == '.')
			n++;
	if (*--cp == '.')
		trailing_dot = 1;

	/* First time in search_index is zero (memory from calloc()) */
	if (block->search_index == 0) {
		/* If there aren't any dots, check if it's an alias. */
		if (n == 0 && (cp = nres_hostalias(block->name))) {
			/* It is an alias, use the substituted name only. */
			(void) strncpy(block->search_name, cp, 2 * MAXDNAME);
			block->search_index = -1; /* if hostalias try 1 name */
			return (0);
		}
	}

	/*
	 * If there are enough dots, or a trailing dot is present then
	 * give it a try as is.
	 */
	if (block->tried_asis == 0 && (n >= _res.ndots || trailing_dot)) {
		block->tried_asis = 1; /* Don't come through here again. */
		(void) nres_querydomain(block->name, (char *)NULL,
		    block->search_name);
		return (0);
	}
	/*
	 * Search through domain name if:
	 * - there is no dot and RES_DEFNAME (use default domain) is set, or
	 * - there is at least one dot, there is no trailing dot,
	 *   and RES_DNSRCH (search up local domain tree) is set.
	 */
	if ((n == 0 && (_res.options & RES_DEFNAMES)) ||
	    (n > 0 && !trailing_dot && (_res.options & RES_DNSRCH))) {
		domain = _res.dnsrch[block->search_index];
		if (domain) {
			(void) nres_querydomain(block->name, domain,
			    block->search_name);
			block->search_index++;
			return (0);
		}
	}
	/*
	 * If dots are present, and we haven't previously tried
	 * without appending a domain name then try that now.
	 */
	if (n && block->tried_asis == 0) {
		(void) nres_querydomain(block->name, (char *)NULL,
		    block->search_name);
		block->search_index = -1;
		return (0);
	}
	block->search_index = -1;
	return (-1);
}

/*
 * Perform a call on res_query on the concatenation of name and domain,
 * removing a trailing dot from name if domain is NULL.
 */
static void
nres_querydomain(char *name, char *domain, char *nbuf)
{
	int		n;

	if (domain == NULL) {
		/*
		 * Check for trailing '.'; copy without '.' if present.
		 */
		n = strlen(name) - 1;
		if (name[n] == '.') {
			(void) memcpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else
			(void) strcpy(nbuf, name);
	} else
		(void) sprintf(nbuf, "%.*s.%.*s",
		    MAXDNAME, name, MAXDNAME, domain);

	prnt(P_INFO, "nres_querydomain(, %s).\n", nbuf);
}

static char *
nres_hostalias(char *name)
{
	register char  *C1, *C2;
	FILE		*fp;
	char		*file;
	char		buf[BUFSIZ];
	static char	abuf[MAXDNAME];

	file = getenv("HOSTALIASES");
	if (file == NULL || (fp = fopen(file, "r")) == NULL)
		return (NULL);
	buf[sizeof (buf) - 1] = '\0';
	while (fgets(buf, sizeof (buf), fp)) {
		for (C1 = buf; *C1 && !isspace(*C1); ++C1);
		if (!*C1)
			break;
		*C1 = '\0';
		if (!strcasecmp(buf, name)) {
			while (isspace(*++C1));
			if (!*C1)
				break;
			for (C2 = C1 + 1; *C2 && !isspace(*C2); ++C2);
			abuf[sizeof (abuf) - 1] = *C2 = '\0';
			(void) strncpy(abuf, C1, sizeof (abuf) - 1);
			(void) fclose(fp);
			return (abuf);
		}
	}
	(void) fclose(fp);
	return (NULL);
}
