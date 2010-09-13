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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * files/netmasks.c -- "files" backend for nsswitch "netmasks" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All routines necessary to deal with the file /etc/inet/netmasks.  The file
 * contains mappings from 32 bit network internet addresses to their
 * corresponding 32 bit mask internet addresses. The addresses are in dotted
 * internet address form.
 */

#include "files_common.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nss_dbdefs.h>
#include <ctype.h>

/*
 * Validate 'files' netmasks entry. The comparison objects are in IPv4
 * internet address format.
 */
static int
check_addr(nss_XbyY_args_t *argp, const char *line, int linelen)
{
	const char	*limit, *linep, *addrstart;
	int		addrlen;
	char		addrbuf[NSS_LINELEN_NETMASKS];
	struct in_addr	lineaddr, argsaddr;

	linep = line;
	limit = line + linelen;

	/* skip leading spaces */
	while (linep < limit && isspace(*linep))
		linep++;

	addrstart = linep;
	while (linep < limit && !isspace(*linep))
		linep++;
	if (linep == limit)
		return (0);
	addrlen = linep - addrstart;
	if (addrlen < sizeof (addrbuf)) {
		(void) memcpy(addrbuf, addrstart, addrlen);
		addrbuf[addrlen] = '\0';
		if ((lineaddr.s_addr = inet_addr(addrbuf)) ==
						(in_addr_t)0xffffffffU)
			return (0);
		if ((argsaddr.s_addr = inet_addr(argp->key.name))
				== (in_addr_t)0xffffffffU)
			return (0);
		return (lineaddr.s_addr == argsaddr.s_addr);
	}
	return (0);
}

static nss_status_t
getbynet(be, a)
	files_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;
	char			tmpbuf[NSS_LINELEN_NETMASKS];

	/*
	 * use the buffer passed in if result is to be returned
	 * in /etc file format
	 */
	if (argp->buf.result != NULL) {
		argp->buf.buffer = tmpbuf;
		argp->buf.buflen = NSS_LINELEN_NETMASKS;
	}
	res = _nss_files_XY_all(be, argp, 1, argp->key.name, check_addr);
	if (argp->buf.result != NULL) {
		argp->buf.buffer = NULL;
		argp->buf.buflen = 0;
	} else {
		/* the frontend expects the netmask data only */
		if (res == NSS_SUCCESS)	 {
			char	*m;
			char	*s = (char *)argp->returnval;
			int	l = 0;

			m = s + argp->returnlen - 1;

			/* skip trailing spaces */
			while (s < m && isspace(*m))
				m--;

			for (; s <= m; m--) {
				if (isspace(*m))
					break;
				l++;
			}
			m++;
			(void) memmove(argp->returnval, m, l);
			argp->returnlen = l;
			*(s + l) = '\0';
		}
	}

	return (res);
}

static files_backend_op_t netmasks_ops[] = {
	_nss_files_destr,
	getbynet
};

/*ARGSUSED*/
nss_backend_t *
_nss_files_netmasks_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_files_constr(netmasks_ops,
	    sizeof (netmasks_ops) / sizeof (netmasks_ops[0]),
	    _PATH_NETMASKS, NSS_LINELEN_NETMASKS, NULL));
}
