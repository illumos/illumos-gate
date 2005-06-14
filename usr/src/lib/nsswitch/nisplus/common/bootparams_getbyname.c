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
 *	nisplus/bootparams_getbyname.c -- "nisplus" backend for nsswitch
 *  "bootparams"  database.
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nss_dbdefs.h>
#include <strings.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static nss_status_t
getbyname(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	return (_nss_nisplus_lookup(be, argp, BOOTPARAM_TAG_KEY,
		argp->key.name));
}

/*
 * place the results from the nis_object structure into argp->buf.buffer
 * (hid argp->buf.buflen) that was supplied by the caller.
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
/*ARGSUSED*/
static int
nis_object2ent(nobj, obj, argp)
	int		nobj;
	nis_object	*obj;
	nss_XbyY_args_t	*argp;
{
	char	*buffer, *val;
	int		buflen = argp->buf.buflen;
	struct	entry_col *ecol;
	int		len;

	buffer = argp->buf.buffer;

	/*
	 * If we got more than one nis_object, we just ignore it.
	 * Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < BOOTPARAM_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/*
	 * datum
	 */
	EC_SET(ecol, BOOTPARAM_NDX_DATUM, len, val);
	if (len < 2) {
		*buffer = 0;
		return (NSS_STR_PARSE_SUCCESS);
	}
	if (len > buflen)
		return (NSS_STR_PARSE_ERANGE);
	strncpy(buffer, val, len);

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t bootparams_ops[] = {
	_nss_nisplus_destr,
	getbyname
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_bootparams_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(bootparams_ops,
			sizeof (bootparams_ops) / sizeof (bootparams_ops[0]),
			BOOTPARAM_TBLNAME, nis_object2ent));
}
