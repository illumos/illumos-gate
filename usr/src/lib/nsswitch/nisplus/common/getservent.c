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
 *	getservent.c
 *
 *	Copyright (c) 1988-1992 Sun Microsystems Inc
 *	All Rights Reserved.
 *
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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;

	/*
	 * Don't have to do anything for case-insensitivity;  the NIS+ table
	 * has the right flags enabled in the 'cname' and 'name' columns.
	 *
	 * Make sure that nis_object2ent would cull out only those entries
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
	nss_XbyY_args_t		*argp = (nss_XbyY_args_t *) a;
	char		portstr[12];

	/*
	 * Make sure that nis_object2ent would cull out only those entries
	 * with the given protocol if it is non-NULL, or the first one it
	 * finds in the nis_object if user supplied proto is NULL.
	 */
	sprintf(portstr, "%d", ntohs((u_short)argp->key.serv.serv.port));
	return (_nss_nisplus_lookup(be, argp, SERV_TAG_PORT, portstr));
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
	char		*buffer, *limit, *val;
	int		buflen = argp->buf.buflen;
	struct servent	*serv;
	int		len, ret;
	struct entry_col	*ecol;
	const char	*proto = argp->key.serv.proto;
	int		i;

	limit = argp->buf.buffer + buflen;
	serv = (struct servent *)argp->buf.result;
	buffer = argp->buf.buffer;

	/*
	 * If the caller does not care about a specific protocol
	 * (udp or tcp usually), pick the one from the first nis_object
	 * and parse all the entries associated with only this protocol.
	 * NULL proto is also specified by getservent() functions. We
	 * end up doing extraneous work in the case.
	 */
	if (proto == NULL) {

		if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
			obj->EN_data.en_cols.en_cols_len < SERV_COL) {
			return (NSS_STR_PARSE_PARSE);
		}
		ecol = obj->EN_data.en_cols.en_cols_val;
		EC_SET(ecol, SERV_NDX_PROTO, len, proto);
		if (len < 2)
			return (NSS_STR_PARSE_PARSE);
	} else {
		len = strlen(proto) + 1;
	}
	/*
	 * Return (a copy of) proto in serv->s_proto
	 */
	if (buffer + len > limit) {
		return (NSS_STR_PARSE_ERANGE);
	}
	memcpy(buffer, proto, len);
	serv->s_proto = buffer;
	buffer += len;
	buflen -= len;

	/*
	 * <-----buffer + buflen -------------->
	 * |-----------------|----------------|
	 * | pointers vector | aliases grow   |
	 * | for aliases     |                |
	 * | this way ->     | <- this way    |
	 * |-----------------|----------------|
	 *
	 *
	 * ASSUME: name, aliases, proto and port columns in NIS+ tables ARE
	 * null terminated.
	 *
	 * get cname and aliases
	 */

	serv->s_aliases = (char **) ROUND_UP(buffer, sizeof (char **));
	if ((char *)serv->s_aliases >= limit) {
		return (NSS_STR_PARSE_ERANGE);
	}

	serv->s_name = NULL;

	/*
	 * Assume that CNAME is the first column and NAME the second.
	 */
	ret = netdb_aliases_from_nisobj(obj, nobj, proto,
		serv->s_aliases, &limit, &(serv->s_name), &len);
	if (ret != NSS_STR_PARSE_SUCCESS)
		return (ret);

	/*
	 * Read port from the first object having the desired protocol.
	 * There is guaranteed to be at least one such object, or
	 * netdb_aliases_from_nisobj() wouldn't have returned SUCCESS.
	 */
	for (i = 0; i < nobj; i++) {
		ecol = obj[i].EN_data.en_cols.en_cols_val;
		EC_SET(ecol, SERV_NDX_PROTO, len, val);
		if (len < 2)
			return (NSS_STR_PARSE_PARSE);
		if (strcmp(proto, val) == 0)
			break;
	}
	if (i == nobj) {  /* none found...  can't happen, but what the heck */
		return (NSS_STR_PARSE_PARSE);
	}
	EC_SET(ecol, SERV_NDX_PORT, len, val);
	if (len < 2) {
		return (NSS_STR_PARSE_PARSE);
	}
	serv->s_port = htons((u_short)atoi(val));

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
				    SERV_TBLNAME, nis_object2ent));
}
