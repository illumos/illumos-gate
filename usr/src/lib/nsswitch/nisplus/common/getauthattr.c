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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <auth_attr.h>
#include <stdlib.h>
#include <string.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"


static nss_status_t
getbynam(nisplus_backend_ptr_t be, void *a)
{
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;

	return (_nss_nisplus_lookup(be, argp, AUTHATTR_TAG_NAME,
	    argp->key.name));
}

/*
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2authstr(int nobj, nis_object *obj, nss_XbyY_args_t *argp)
{
	int			len;
	int			buflen = argp->buf.buflen;
	char			*buffer, *limit, *val, *endnum, *nullstring;
	char			*empty = "";
	authstr_t		*auth;
	struct entry_col	*ecol;

	limit = argp->buf.buffer + buflen;
	auth = (authstr_t *)argp->buf.result;
	buffer = argp->buf.buffer;

	/*
	 * If we got more than one nis_object, we just ignore object(s)
	 * except the first. Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are
	 * null terminated.
	 */

	if (obj->zo_data.zo_type != ENTRY_OBJ ||
	    obj->EN_data.en_cols.en_cols_len < AUTHATTR_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/*
	 * authstr->name: authorization name
	 */
	EC_SET(ecol, AUTHATTR_NDX_NAME, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->name = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->name, val);
	nullstring = (buffer - 1);

	/*
	 * authstr->res1: reserved field 1
	 */
	EC_SET(ecol, AUTHATTR_NDX_RES1, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->res1 = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->res1, val);
	nullstring = (buffer - 1);

	/*
	 * authstr->res2: reserved field 2
	 */
	EC_SET(ecol, AUTHATTR_NDX_RES2, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->res2 = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->res2, val);
	nullstring = (buffer - 1);

	/*
	 * authstr->short_desc: short description
	 */
	EC_SET(ecol, AUTHATTR_NDX_SHORTDESC, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->short_desc = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->short_desc, val);
	nullstring = (buffer - 1);

	/*
	 * authstr->long_desc: long description
	 */
	EC_SET(ecol, AUTHATTR_NDX_LONGDESC, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->long_desc = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->long_desc, val);
	nullstring = (buffer - 1);

	/*
	 * authstr->attrs: key-value pairs of attributes
	 */
	EC_SET(ecol, AUTHATTR_NDX_ATTR, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	auth->attr = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(auth->attr, val);
	nullstring = (buffer - 1);

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t authattr_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbynam
};

nss_backend_t *
_nss_nisplus_auth_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5,
    const char *dummy6)
{
	return (_nss_nisplus_constr(authattr_ops,
	    sizeof (authattr_ops)/sizeof (authattr_ops[0]),
	    AUTHATTR_TBLNAME,
	    nis_object2authstr));
}
