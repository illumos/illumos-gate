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
 *	getnetent.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 *
 *	nisplus/getnetent.c -- NIS+ backend for nsswitch "net" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static int nettoa(int anet, char *buf, int buflen);

static nss_status_t
getbyname(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	/*
	 * Don't have to do anything for case-insensitivity;  the NIS+ table
	 * has the right flags enabled in the 'cname' and 'name' columns.
	 */
	return (_nss_nisplus_lookup(be, argp, NET_TAG_NAME, argp->key.name));
}

static nss_status_t
getbyaddr(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	char		addrstr[16];

	if (nettoa((int) argp->key.netaddr.net, addrstr, 16) != 0)
		return (NSS_UNAVAIL);   /* it's really ENOMEM */

	return (_nss_nisplus_lookup(be, argp, NET_TAG_ADDR, addrstr));
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
	char	*buffer, *limit, *val;
	int		buflen = argp->buf.buflen;
	struct 	netent *net;
	int		len, ret;
	struct	entry_col *ecol;

	limit = argp->buf.buffer + buflen;
	net = (struct netent *)argp->buf.result;
	buffer = argp->buf.buffer;

	/*
	 * <-----buffer + buflen -------------->
	 * |-----------------|----------------|
	 * | pointers vector | aliases grow   |
	 * | for aliases     |                |
	 * | this way ->     | <- this way    |
	 * |-----------------|----------------|
	 *
	 *
	 * ASSUME: name, aliases and number columns in NIS+ tables ARE
	 * null terminated.
	 *
	 * get cname and aliases
	 */

	net->n_aliases = (char **) ROUND_UP(buffer, sizeof (char **));
	if ((char *)net->n_aliases >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}

	net->n_name = NULL;

	/*
	 * Assume that CNAME is the first column and NAME the second.
	 */
	ret = netdb_aliases_from_nisobj(obj, nobj, NULL,
		net->n_aliases, &limit, &(net->n_name), &len);
	if (ret != NSS_STR_PARSE_SUCCESS)
		return (ret);

	/*
	 * get network number from the first object
	 *
	 */
	ecol = obj->EN_data.en_cols.en_cols_val;
	EC_SET(ecol, NET_NDX_ADDR, len, val);
	if (len <= 0 || ((net->n_net = inet_network(val)) == (in_addr_t)-1))
		return (NSS_STR_PARSE_PARSE);

	net->n_addrtype = AF_INET;

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t net_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_networks_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(net_ops,
				sizeof (net_ops) / sizeof (net_ops[0]),
				NET_TBLNAME, nis_object2ent));
}

/*
 * Takes an unsigned integer in host order, and returns a printable
 * string for it as a network number.  To allow for the possibility of
 * naming subnets, only trailing dot-zeros are truncated.
 */
static int
nettoa(anet, buf, buflen)
	int		anet;
	char	*buf;
	int		buflen;
{
	char *p;
	struct in_addr in;
	int addr;

	if (buf == 0)
		return (1);
	in = inet_makeaddr(anet, INADDR_ANY);
	addr = in.s_addr;
	(void) strncpy(buf, inet_ntoa(in), buflen);
	if ((IN_CLASSA_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
	} else if ((IN_CLASSB_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		p = strchr(p+1, '.');
		if (p == NULL)
			return (1);
		*p = 0;
	} else if ((IN_CLASSC_HOST & htonl(addr)) == 0) {
		p = strrchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
	}
	return (0);
}
