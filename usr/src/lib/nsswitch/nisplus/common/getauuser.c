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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "nisplus_common.h"
/*
 * GROUP is defined in sys/acl.h and rpcsvc/nis.h.
 * We really don't need either definition, so we will
 * undefine it since it gets pulled in indirectly through
 * nisplus_common.h and libbsm.h and causes a compilation
 * warning.
 */
#undef GROUP
#include <bsm/libbsm.h>
#include <secdb.h>
#include "nisplus_tables.h"


static nss_status_t
getbynam(nisplus_backend_ptr_t be, void *a)
{
	nss_XbyY_args_t *argp = (nss_XbyY_args_t *)a;

	return (_nss_nisplus_lookup(be,
		argp, AUDITUSER_TAG_NAME, argp->key.name));
}

/*
 * place the results from the nis_object structure into argp->buf.result
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2auuser(int nobj, nis_object *obj, nss_XbyY_args_t *argp)
{
	int			len;
	int			buflen = argp->buf.buflen;
	char			*p, *buffer, *limit, *val, *endnum, *nullstring;
	char			*empty = "";
	au_user_str_t		*au_user;
	struct entry_col	*ecol;

	limit = argp->buf.buffer + buflen;
	au_user = (au_user_str_t *)argp->buf.result;
	buffer = argp->buf.buffer;
	/*
	 * If we got more than one nis_object, we just ignore object(s) except
	 * the first. Although it should never have happened.
	 *
	 * ASSUMPTION: All the columns in the NIS+ tables are null terminated.
	 */
	if (obj->zo_data.zo_type != ENTRY_OBJ ||
	    obj->EN_data.en_cols.en_cols_len < AUDITUSER_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	/*
	 * au_user->name: user name
	 */
	EC_SET(ecol, AUDITUSER_NDX_NAME, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	au_user->au_name = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(au_user->au_name, val);
	nullstring = (buffer - 1);

	/*
	 * au_user->au_always: always audited events
	 */
	EC_SET(ecol, AUDITUSER_NDX_ALWAYS, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	au_user->au_always = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(au_user->au_always, val);
	nullstring = (buffer - 1);

	/*
	 * au_user->au_never: never audited events
	 */
	EC_SET(ecol, AUDITUSER_NDX_NEVER, len, val);
	if (len < 1 || (*val == '\0')) {
		val = empty;
	}
	au_user->au_never = buffer;
	buffer += len;
	if (buffer >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	strcpy(au_user->au_never, val);
	nullstring = (buffer - 1);

	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t auuser_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbynam
};

nss_backend_t  *
_nss_nisplus_audit_user_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3)
{
	return (_nss_nisplus_constr(auuser_ops,
		sizeof (auuser_ops)/sizeof (auuser_ops[0]),
		AUDITUSER_TBLNAME,
		nis_object2auuser));
}
