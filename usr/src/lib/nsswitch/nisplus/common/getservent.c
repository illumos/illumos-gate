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
 *	nisplus/getservent.c -- NIS+ backend for nsswitch "serv" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
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
	 *
	 * Make sure that nis_object2str would cull out only those entries
	 * with the given protocol if it is non-NULL, or the first one it
	 * finds in the nis_object if user supplied proto is NULL.
	 */
	return (_nss_nisplus_lookup(be, argp, SERV_TAG_NAME,
			argp->key.serv.serv.name));
}

static nss_status_t
getbyport(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *)a;
	char		portstr[12];

	/*
	 * Make sure that nis_object2str would cull out only those entries
	 * with the given protocol if it is non-NULL, or the first one it
	 * finds in the nis_object if user supplied proto is NULL.
	 */
	(void) snprintf(portstr, 12, "%d",
		ntohs((ushort_t)argp->key.serv.serv.port));
	return (_nss_nisplus_lookup(be, argp, SERV_TAG_PORT, portstr));
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
	char			*cname, *port, *proto, *endnum;
	int			buflen, cnamelen, portlen, protolen;
	const char		*protokey = NULL;
	int			protokeylen = 0, stat;
	struct	entry_col	*ecol;

	/*
	 * For getent request, we don't want to set protokey
	 * and protokeylen, since argp->key.serv.proto won't
	 * be initialized.
	 */
	if (be->table_path == NULL) {
		protokey = argp->key.serv.proto;
		protokeylen = (protokey) ? strlen(protokey) : 0;
	}

	for (; nobj > 0; obj++, nobj--) {
		if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
			obj->EN_data.en_cols.en_cols_len < SERV_COL) {
			/* namespace/table/object is curdled */
			return (NSS_STR_PARSE_PARSE);
		}
		ecol = obj->EN_data.en_cols.en_cols_val;

		/* protocol */
		__NISPLUS_GETCOL_OR_RETURN(ecol, SERV_NDX_PROTO,
			protolen, proto);
		if (protokey != NULL) {
			if (protolen != protokeylen ||
				strncasecmp(proto, protokey, protolen) != 0)
				continue;
		}

		/*
		 * If the caller does not care about a specific protocol
		 * (udp or tcp usually), pick the one from the first nis_object
		 * and parse all the entries associated with only this protocol.
		 * NULL proto is also specified by getservent() functions. We
		 * end up doing extraneous work in the case.
		 */
		break;
	}

	if (nobj <= 0)
		return (NSS_STR_PARSE_PARSE);

	buflen = argp->buf.buflen;
	buffer = argp->buf.buffer;
	(void) memset(buffer, 0, buflen);

	/* cname */
	__NISPLUS_GETCOL_OR_RETURN(ecol, SERV_NDX_CNAME, cnamelen, cname);

	/* port */
	__NISPLUS_GETCOL_OR_RETURN(ecol, SERV_NDX_PORT, portlen, port);
	(void) strtol(port, &endnum, 10);
	if (*endnum != 0 || endnum == port)
		return (NSS_STR_PARSE_PARSE);

	if (cnamelen + portlen + protolen + 3  > buflen)
		return (NSS_STR_PARSE_ERANGE);
	(void) snprintf(buffer, buflen, "%s %s/%s", cname, port, proto);

	linep = buffer + cnamelen + portlen + protolen + 2;
	limit = buffer + buflen;

	stat = nis_aliases_object2str(obj, nobj, cname, proto, linep, limit);
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
	(void) fprintf(stdout, "services [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}

static nisplus_backend_op_t serv_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbyname,
	getbyport
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_services_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(serv_ops,
				    sizeof (serv_ops) / sizeof (serv_ops[0]),
				    SERV_TBLNAME, nis_object2str));
}
