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
 *	dns_common.c
 *
 * Copyright (c) 1993,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "dns_common.h"

#define	DNS_ALIASES	0
#define	DNS_ADDRLIST	1
#define	DNS_MAPDLIST	2

static int
dns_netdb_aliases(from_list, to_list, aliaspp, type, count, af_type)
	char	**from_list, **to_list,	**aliaspp;
	int	type, *count, af_type;
{
	char		*fstr;
	int		cnt = 0;
	size_t		len;

	*count = 0;
	if ((char *)to_list >= *aliaspp)
		return (NSS_STR_PARSE_ERANGE);

	for (fstr = from_list[cnt]; fstr != NULL; fstr = from_list[cnt]) {
		if (type == DNS_ALIASES)
			len = strlen(fstr) + 1;
		else
			len = (af_type == AF_INET) ? sizeof (struct in_addr)
						: sizeof (struct in6_addr);
		*aliaspp -= len;
		to_list[cnt] = *aliaspp;
		if (*aliaspp <= (char *)&to_list[cnt+1])
			return (NSS_STR_PARSE_ERANGE);
		if (type == DNS_MAPDLIST) {
			struct in6_addr *addr6p = (struct in6_addr *) *aliaspp;

			(void) memset(addr6p, '\0', sizeof (struct in6_addr));
			(void) memcpy(&addr6p->s6_addr[12], fstr,
					sizeof (struct in_addr));
			addr6p->s6_addr[10] = 0xffU;
			addr6p->s6_addr[11] = 0xffU;
			++cnt;
		} else {
			(void) memcpy (*aliaspp, fstr, len);
			++cnt;
		}
	}
	to_list[cnt] = NULL;

	*count = cnt;
	if (cnt == 0)
		return (NSS_STR_PARSE_PARSE);

	return (NSS_STR_PARSE_SUCCESS);
}


int
ent2result(he, argp, af_type)
	struct hostent		*he;
	nss_XbyY_args_t		*argp;
	int			af_type;
{
	char		*buffer, *limit;
	int		buflen = argp->buf.buflen;
	int		ret, count;
	size_t len;
	struct hostent 	*host;
	struct in_addr	*addrp;
	struct in6_addr	*addrp6;

	limit = argp->buf.buffer + buflen;
	host = (struct hostent *) argp->buf.result;
	buffer = argp->buf.buffer;

	/* h_addrtype and h_length */
	host->h_addrtype = af_type;
	host->h_length = (af_type == AF_INET) ? sizeof (struct in_addr)
					: sizeof (struct in6_addr);

	/* h_name */
	len = strlen(he->h_name) + 1;
	host->h_name = buffer;
	if (host->h_name + len >= limit)
		return (NSS_STR_PARSE_ERANGE);
	(void) memcpy(host->h_name, he->h_name, len);
	buffer += len;

	/* h_addr_list */
	if (af_type == AF_INET) {
		addrp = (struct in_addr *) ROUND_DOWN(limit, sizeof (*addrp));
		host->h_addr_list = (char **)
				ROUND_UP(buffer, sizeof (char **));
		ret = dns_netdb_aliases(he->h_addr_list, host->h_addr_list,
			(char **)&addrp, DNS_ADDRLIST, &count, af_type);
		if (ret != NSS_STR_PARSE_SUCCESS)
			return (ret);
		/* h_aliases */
		host->h_aliases = host->h_addr_list + count + 1;
		ret = dns_netdb_aliases(he->h_aliases, host->h_aliases,
			(char **)&addrp, DNS_ALIASES, &count, af_type);
	} else {
		addrp6 = (struct in6_addr *)
			ROUND_DOWN(limit, sizeof (*addrp6));
		host->h_addr_list = (char **)
			ROUND_UP(buffer, sizeof (char **));
		if (he->h_addrtype == AF_INET && af_type == AF_INET6) {
			ret = dns_netdb_aliases(he->h_addr_list,
				host->h_addr_list, (char **)&addrp6,
				DNS_MAPDLIST, &count, af_type);
		} else {
			ret = dns_netdb_aliases(he->h_addr_list,
				host->h_addr_list, (char **)&addrp6,
				DNS_ADDRLIST, &count, af_type);
		}
		if (ret != NSS_STR_PARSE_SUCCESS)
			return (ret);
		/* h_aliases */
		host->h_aliases = host->h_addr_list + count + 1;
		ret = dns_netdb_aliases(he->h_aliases, host->h_aliases,
			(char **)&addrp6, DNS_ALIASES, &count, af_type);
	}
	if (ret == NSS_STR_PARSE_PARSE)
		ret = NSS_STR_PARSE_SUCCESS;

	return (ret);
}


nss_backend_t *
_nss_dns_constr(dns_backend_op_t ops[], int n_ops)
{
	dns_backend_ptr_t	be;

	if ((be = (dns_backend_ptr_t) malloc(sizeof (*be))) == 0)
		return (0);

	be->ops = ops;
	be->n_ops = n_ops;
	return ((nss_backend_t *) be);
}
