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
 *	getrpcent.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 *
 *	nisplus/getrpcent.c -- NIS+ backend for nsswitch "rpc" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
#include <rpc/rpcent.h>
#include <stdlib.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

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
	return (_nss_nisplus_lookup(be, argp, RPC_TAG_NAME, argp->key.name));
}

static nss_status_t
getbynumber(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	char		 numstr[12];

	sprintf(numstr, "%d", argp->key.number);
	return (_nss_nisplus_lookup(be, argp, RPC_TAG_NUMBER, numstr));
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
	struct 	rpcent *rpc;
	int		len, ret;
	struct	entry_col *ecol;

	limit = argp->buf.buffer + buflen;
	rpc = (struct rpcent *)argp->buf.result;
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

	rpc->r_aliases = (char **) ROUND_UP(buffer, (sizeof (char **)));
	if ((char *)rpc->r_aliases >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}

	rpc->r_name = NULL;

	/*
	 * Assume that CNAME is the first column and NAME the second.
	 */
	ret = netdb_aliases_from_nisobj(obj, nobj, NULL,
		rpc->r_aliases, &limit, &(rpc->r_name), &len);
	if (ret != NSS_STR_PARSE_SUCCESS)
		return (ret);

	/*
	 * get program number from the first object
	 *
	 */
	ecol = obj->EN_data.en_cols.en_cols_val;
	EC_SET(ecol, RPC_NDX_NUMBER, len, val);
	if (len <= 0)
		return (NSS_STR_PARSE_PARSE);
	rpc->r_number = atoi(val);

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t rpc_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbyname,
	getbynumber
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_rpc_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(rpc_ops,
				sizeof (rpc_ops) / sizeof (rpc_ops[0]),
				RPC_TBLNAME, nis_object2ent));
}
