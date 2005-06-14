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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * files/gethostent.c -- "files" backend for nsswitch "hosts" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include "files_common.h"
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <ctype.h>

static int check_name();
static char *do_aliases();
static char *strcasestr();
nss_status_t __nss_files_XY_hostbyname();
int __nss_files_2herrno();

static int
check_name(host, args)
	struct hostent		*host;
	nss_XbyY_args_t		*args;
{
	const char		*name = args->key.name;
	char			**aliasp;

	if (!host->h_name)
		return (0);
	if (strcasecmp(host->h_name, name) == 0) {
		return (1);
	}
	for (aliasp = host->h_aliases;  *aliasp != 0;  aliasp++) {
		if (strcasecmp(*aliasp, name) == 0) {
			return (1);
		}
	}
	return (0);
}

static nss_status_t
getbyname(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	res = __nss_files_XY_hostbyname(be, argp, argp->key.name, AF_INET);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss_files_2herrno(res);
	return (res);
}


int
__nss_files_check_addr(argp)
	nss_XbyY_args_t		*argp;
{
	struct hostent		*host	= (struct hostent *)argp->returnval;

	/*
	 * We know that /etc/hosts can only store one address per host, so...
	 */
	return (host->h_length == argp->key.hostaddr.len &&
		host->h_addrtype == argp->key.hostaddr.type &&
		memcmp(host->h_addr_list[0], argp->key.hostaddr.addr,
			argp->key.hostaddr.len) == 0);
}


static nss_status_t
getbyaddr(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp	= (nss_XbyY_args_t *)a;
	nss_status_t		res;

	res = _nss_files_XY_all(be, argp, 1, 0, __nss_files_check_addr);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss_files_2herrno(res);
	return (res);
}


static files_backend_op_t host_ops[] = {
	_nss_files_destr,
	_nss_files_endent,
	_nss_files_setent,
	_nss_files_getent_netdb,
	getbyname,
	getbyaddr,
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_hosts_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(host_ops,
				sizeof (host_ops) / sizeof (host_ops[0]),
				_PATH_HOSTS,
				NSS_LINELEN_HOSTS,
				NULL));
}


/*
 * XXX - this duplicates code from files_common.c because we need to keep
 * going after we've found a match to satisfy the multihomed host case.
 */
nss_status_t
__nss_files_XY_hostbyname(be, args, filter, type)
	files_backend_ptr_t be;
	nss_XbyY_args_t *args;
	const char *filter;		/* hint for name string */
	int type;
{
	nss_status_t res;
	int parsestat;
	char *first;
	char *last;
	int i, nhosts = 0;
	struct hostent he, *hp, *thp;
	in_addr_t taddr[MAXADDRS];
	struct in6_addr taddr6[MAXADDRS];
	char *abuf = 0;		/* alias buffer */
	char *abuf_start = 0, *abuf_end;
	int	(*func)();

	if (be->buf == 0 &&
		(be->buf = malloc(be->minbuf)) == 0) {
		return (NSS_UNAVAIL);
	}

	if (be->f == 0) {
		if ((res = _nss_files_setent(be, 0)) != NSS_SUCCESS)
			return (res);
	}

	res = NSS_NOTFOUND;
	args->erange = 0;
	args->returnval = (char *)0;
	hp = thp = (struct hostent *)args->buf.result;

	for (;;) {
		char *instr = be->buf;
		int linelen;

		if ((linelen = _nss_files_read_line(be->f,
		    instr, be->minbuf)) < 0) {
			break;		/* EOF */
		}

		/*
		 * This check avoids a malloc()/free() for the common
		 * case. Also, if we're trying to match an alias and an
		 * already matched entry doesn't share a canonical name
		 * with the current one, bail.
		 */
		if (nhosts == 0 && strcasestr(instr, filter) == 0) {
			continue;
		}

		if ((last = strchr(instr, '#')) == 0)
			last = instr + linelen;
		*last-- = '\0';
		for (first = instr;  isspace(*first);  first++)
			;
		/* Ignore blank and comment lines */
		if (*first == '\0')
			continue;

		while (isspace(*last))
			--last;
		linelen = last - first + 1;
		if (first != instr)
			instr = first;

		if (nhosts && strcasestr(instr, hp->h_name) == 0) {
			break;
		}
		/*
		 * If we've already matched once and have a possible match
		 * on this line, copy the aliases where they're safe from
		 * being overwritten when we look at the next entry. They're
		 * saved as a string of blank separated names for the alias
		 * parser. On errors, we return failure whether or not we
		 * have already obtained a valid address.
		 */
		if (nhosts == 1 && !abuf) {
			abuf = malloc(args->buf.buflen);
			if (abuf == NULL) {
				res = NSS_UNAVAIL;
				break;
			}
			abuf_start = &abuf[0];
			abuf_end = abuf_start + args->buf.buflen;
			if (abuf + strlen(hp->h_name) + 1 > abuf_end) {
				free(abuf_start);
				abuf = NULL;
				args->erange = 1;
				res = NSS_NOTFOUND;
				break;
			}
			(void) strcpy(abuf, hp->h_name);
			abuf += strlen(hp->h_name);
			*abuf++ = ' ';
			abuf = do_aliases(hp, abuf, abuf_start, abuf_end);
			if (abuf == NULL) {
				args->erange = 1;
				res = NSS_NOTFOUND;
				break;
			}
		}
		func = args->str2ent;
		parsestat = (*func)(instr, linelen, thp,
		    args->buf.buffer, args->buf.buflen);

		if (parsestat != NSS_STR_PARSE_SUCCESS) {
			if (parsestat == NSS_STR_PARSE_ERANGE)
				args->erange = 1;
			continue;
		}

		/*
		 * Still need to check, strcasestr() above is just a hint.
		 */

		if (type == thp->h_addrtype)
		if (check_name(thp, args)) {
			if (type == AF_INET)
				taddr[nhosts++] =
				(*(in_addr_t *)thp->h_addr_list[0]);
			else {
				memcpy(&taddr6[nhosts++], thp->h_addr_list[0],
				sizeof (struct in6_addr));
			}


			if (nhosts == 1) {
				res = NSS_SUCCESS;
				args->returnval = args->buf.result;
				thp = &he;	/* switch to tmp hostent */
				continue;
			}
			if (nhosts >= MAXADDRS)
				break;
			abuf = do_aliases(thp, abuf, abuf_start, abuf_end);
			if (abuf == NULL) {
				args->erange = 1;
				res = NSS_NOTFOUND;
				break;
			}
		} else if (abuf &&
		    strcasecmp(hp->h_name, thp->h_name) == 0) {
			/*
			 * This line didn't have the requested name but
			 * is part of the same multihomed host (i.e. it
			 * has the same canonical name as the previous
			 * line), so march on...
			 */
			continue;
		} else if (nhosts) {
			break;
		}
	}

	if (abuf) {
		struct in_addr *addrp;
		struct in6_addr *addrp6;

		if (type == AF_INET) {
			addrp = (struct in_addr *)(ROUND_DOWN(args->buf.buffer +
			    args->buf.buflen, sizeof (*addrp)));
			hp->h_addr_list = (char **)(ROUND_DOWN(addrp -
			    ((nhosts + 1) * sizeof (char *) +
			    (nhosts * sizeof (*addrp))), sizeof (char *)));
			for (i = 0, --addrp; i < nhosts; i++, --addrp) {
				(*(in_addr_t *)addrp) = taddr[i];
				hp->h_addr_list[i] = (char *)addrp;
			}
		} else {
			addrp6 = (struct in6_addr *)
			(ROUND_DOWN(args->buf.buffer + args->buf.buflen,
			sizeof (*addrp6)));
			hp->h_addr_list = (char **)(ROUND_DOWN(addrp6 -
			    ((nhosts + 1) * sizeof (char *) +
			    (nhosts * sizeof (*addrp6))), sizeof (char *)));
			for (i = 0, --addrp6; i < nhosts; i++, --addrp6) {
				memcpy(addrp6, &taddr6[i],
				sizeof (struct in6_addr));
				hp->h_addr_list[i] = (char *)addrp6;
			}
		}

		hp->h_addr_list[nhosts] = 0;
		hp->h_aliases = _nss_netdb_aliases(abuf_start,
		    abuf - abuf_start, args->buf.buffer,
		    (char *)hp->h_addr_list - args->buf.buffer);
		if (hp->h_aliases == 0) {
			args->erange = 1;
			res = NSS_STR_PARSE_ERANGE;
		} else {
			hp->h_name = hp->h_aliases[0];
			hp->h_aliases++;
		}
		free(abuf_start);
	}

	/*
	 * stayopen is set to 0 by default in order to close the opened
	 * file.  Some applications may break if it is set to 1.
	 */
	if (!args->stayopen)
		(void) _nss_files_endent(be, 0);

	return (res);
}

/*
 * A case-insensitive version of strstr().
 */
static char *
strcasestr(as1, as2)
	char *as1;
	char *as2;
{
	int c2;
	register char *tptr;
	register char *s1, *s2;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return (0);

	while (*s1) {
		if (tolower(*s1++) == tolower(c2 = *s2)) {
			tptr = s1;
			while ((tolower(c2 = *++s2) ==
			    tolower(*s1++)) && c2 != 0)
				;
			if (c2 == 0)
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
		}
	}
	return (0);
}


static char *
do_aliases(hp, abuf, start, end)
	struct hostent *hp;
	char *abuf;
	char *start;
	char *end;
{
	char **cp;

	for (cp = hp->h_aliases; cp && *cp && **cp; cp++) {
		size_t len;

		len = strlen(*cp);
		if (abuf+len+1 >= end) {
			free(start);
			return ((char *)0);
		}
		(void) strcpy(abuf, *cp);
		abuf += len;
		*abuf++ = ' ';
	}
	*abuf = '\0';

	return (abuf);
}


/*
 * This is a copy of a routine in libnsl/nss/netdir_inet.c.  It is
 * here because /etc/lib/nss_files.so.1 cannot call routines
 * in libnsl.  Care should be taken to keep the two copies in sync.
 */
int
__nss_files_2herrno(nsstat)
	nss_status_t nsstat;
{
	switch (nsstat) {
	case NSS_SUCCESS:
		/* no macro-defined success code for h_errno */
		return (0);
	case NSS_NOTFOUND:
		return (HOST_NOT_FOUND);
	case NSS_TRYAGAIN:
		return (TRY_AGAIN);
	case NSS_UNAVAIL:
		return (NO_RECOVERY);
	}
	/* anything else */
	return (NO_RECOVERY);
}
