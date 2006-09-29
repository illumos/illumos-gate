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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;

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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char		 numstr[12];

	(void) snprintf(numstr, 12, "%d", argp->key.number);
	return (_nss_nisplus_lookup(be, argp, RPC_TAG_NUMBER, numstr));
}


/*
 * Convert nisplus object into files format
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2str(nobj, obj, be, argp)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
{
	char			*buffer, *linep, *limit;
	char			*cname, *number, *endnum;
	int			buflen, cnamelen, numberlen;
	int			stat;
	struct	entry_col	*ecol;

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < RPC_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	buflen = argp->buf.buflen;
	buffer = argp->buf.buffer;
	(void) memset(buffer, 0, buflen);

	/* cname */
	__NISPLUS_GETCOL_OR_RETURN(ecol, RPC_NDX_CNAME,
		cnamelen, cname);

	/* number */
	__NISPLUS_GETCOL_OR_RETURN(ecol, RPC_NDX_NUMBER,
		numberlen, number);
	(void) strtol(number, &endnum, 10);
	if (*endnum != 0 || endnum == number)
		return (NSS_STR_PARSE_PARSE);

	if (cnamelen + numberlen + 2  > buflen)
		return (NSS_STR_PARSE_ERANGE);
	(void) snprintf(buffer, buflen, "%s %s", cname, number);

	linep = buffer + cnamelen + numberlen + 1;
	limit = buffer + buflen;

	stat = nis_aliases_object2str(obj, nobj, cname, NULL, linep, limit);
	if (stat != NSS_STR_PARSE_SUCCESS)
		return (stat);

	if (argp->buf.result != NULL) {
		/*
		 * Some front end marshallers may require the
		 * files formatted data in a distinct buffer
		 */
		if ((be->buffer = strdup(buffer)) == NULL)
			return (NSS_STR_PARSE_PARSE);
		be->buflen = strlen(buffer);
		buffer = be->buffer;
	}
#ifdef DEBUG
	(void) fprintf(stdout, "rpc [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
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
				RPC_TBLNAME, nis_object2str));
}
