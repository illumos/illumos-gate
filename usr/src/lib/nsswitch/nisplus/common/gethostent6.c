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
 * Copyright 1988-1992, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	nisplus/gethostent6.c -- NIS+ backend for nsswitch "ipnodes" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"
#include <inet/ip6.h>

const char *inet_ntop(int af, const void *src, char *dst, size_t size);

static nss_status_t
getbyname(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	nss_status_t		res;

	/*
	 * Don't have to do anything for case-insensitivity;  the NIS+ table
	 * has the right flags enabled in the 'cname' and 'name' columns.
	 */
	res = _nss_nisplus_expand_lookup(be, argp, HOST_TAG_NAME,
		argp->key.ipnode.name, IPNODES_TBLNAME);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss2herrno(res);
	return (res);
}

static nss_status_t
getbyaddr(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	struct in6_addr		addr;
	char			addrbuf[INET6_ADDRSTRLEN + 1];
	nss_status_t		res;

	if (argp->key.hostaddr.type != AF_INET6 ||
			argp->key.hostaddr.len  != sizeof (addr)) {
		return (NSS_NOTFOUND);
	}

	memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	if (IN6_IS_ADDR_V4MAPPED(&addr)) {
		if (inet_ntop(AF_INET, (void *) &addr.s6_addr[12],
				(void *)addrbuf, INET_ADDRSTRLEN) == NULL) {
			return (NSS_NOTFOUND);
		}
	} else {
		if (inet_ntop(AF_INET6, (void *)&addr, (void *)addrbuf,
				INET6_ADDRSTRLEN) == NULL)
			return (NSS_NOTFOUND);
	}

	res = _nss_nisplus_expand_lookup(be, argp, HOST_TAG_ADDR, addrbuf,
		IPNODES_TBLNAME);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss2herrno(res);
	return (res);
}


/*
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2ent(nobj, obj, argp)
	int		nobj;
	nis_object	*obj;
	nss_XbyY_args_t	*argp;
{
	char	*buffer, *limit;
	int		buflen = argp->buf.buflen;
	struct 	hostent *host;
	struct	in6_addr *addrp;
	int		count, ret;

	limit = argp->buf.buffer + buflen;
	host = (struct hostent *)argp->buf.result;
	buffer = argp->buf.buffer;

/*
 * <--------------- buffer + buflen -------------------------------------->
 * |-----------------|-----------------|----------------|----------------|
 * | pointers vector | pointers vector | aliases grow   | addresses grow |
 * | for addresses   | for aliases     |		|		 |
 * | this way ->     | this way ->     | <- this way	|<- this way	 |
 * |-----------------|-----------------|----------------|----------------|
 * | grows in PASS 1 | grows in PASS2  | grows in PASS2 | grows in PASS 1|
 *
 *
 * ASSUME: the name and aliases columns in NIS+ tables ARE
 * null terminated.
 *
 *
 * PASS 1: get addresses
 */

	addrp = (struct in6_addr *)ROUND_DOWN(limit, sizeof (*addrp));
	host->h_addr_list = (char **)ROUND_UP(buffer, sizeof (char **));
	if ((char *)host->h_addr_list >= limit ||
			(char *)addrp <= (char *)host->h_addr_list) {
		return (NSS_STR_PARSE_ERANGE);
	}

	ret = __netdb_aliases_from_nisobj(obj, nobj, NULL,
		host->h_addr_list, (char **)&addrp, 0, &count, AF_INET6);
	if (ret != NSS_STR_PARSE_SUCCESS)
		return (ret);

	/*
	 * PASS 2: get cname and aliases
	 */

	host->h_aliases =  host->h_addr_list + count + 1;
	host->h_name = NULL;

	/*
	 * Assume that CNAME is the first column and NAME the second.
	 */
	ret = __netdb_aliases_from_nisobj(obj, nobj, NULL,
		host->h_aliases, (char **)&addrp, &(host->h_name), &count,
		AF_INET6);
	if (ret != NSS_STR_PARSE_SUCCESS)
		return (ret);

	host->h_addrtype = AF_INET6;
	host->h_length   = IPV6_ADDR_LEN;

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t ipnodes_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_ipnodes_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(ipnodes_ops,
		    sizeof (ipnodes_ops) / sizeof (ipnodes_ops[0]),
				    IPNODES_TBLNAME, nis_object2ent));
}
