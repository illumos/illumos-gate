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
 *	nisplus/gethostent.c -- NIS+ backend for nsswitch "hosts" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

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
		argp->key.name, HOST_TBLNAME);
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
	struct in_addr		addr;
	char			addrbuf[18];
	nss_status_t		res;

	(void) memcpy(&addr, argp->key.hostaddr.addr, sizeof (addr));
	(void) inet_ntoa_r(addr, addrbuf);
	res = _nss_nisplus_expand_lookup(be, argp, HOST_TAG_ADDR, addrbuf,
		HOST_TBLNAME);
	if (res != NSS_SUCCESS)
		argp->h_errno = __nss2herrno(res);
	return (res);
}


/*
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
static int
nis_object2str(nobj, obj, be, argp)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
{
	return (nis_hosts_object2str(nobj, obj, be, argp, AF_INET));
}


/*
 * Returns NSS_STR_PARSE_{SUCCESS, ERANGE, PARSE}
 */
int
nis_hosts_object2str(nobj, obj, be, argp, af)
	int			nobj;
	nis_object		*obj;
	nisplus_backend_ptr_t	be;
	nss_XbyY_args_t		*argp;
	int			af;
{
	char			*buffer;
	char			*cname, *name, *addr;
	int			buflen, cnamelen, namelen, addrlen;
	int			first;
	struct in_addr		addr4;
	struct entry_col	*ecol;

	buflen = argp->buf.buflen;
	buffer = argp->buf.buffer;
	(void) memset(buffer, 0, buflen);

	for (first = 1; nobj > 0; nobj--, obj++) {
		if (obj == NULL)
			return (NSS_STR_PARSE_PARSE);
		if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
			obj->EN_data.en_cols.en_cols_len < HOST_COL) {
			/* namespace/table/object is curdled */
			return (NSS_STR_PARSE_PARSE);
		}
		ecol = obj->EN_data.en_cols.en_cols_val;

		/* cname */
		__NISPLUS_GETCOL_OR_RETURN(ecol, HOST_NDX_CNAME,
			cnamelen, cname);

		/* addr */
		__NISPLUS_GETCOL_OR_RETURN(ecol, HOST_NDX_ADDR,
			addrlen, addr);
		if (af == AF_INET) {
			addr4.s_addr = inet_addr(addr);
			if (addr4.s_addr == INADDR_NONE)
				return (NSS_STR_PARSE_PARSE);
		}

		/* name */
		__NISPLUS_GETCOL_OR_EMPTY(ecol, HOST_NDX_NAME,
			namelen, name);

		/*
		 * newline is used to separate multiple
		 * entries. There is no newline before
		 * the first entry and after the last
		 * entry
		 */
		if (first) {
			first = 0;
		} else if (buflen > 1) {
			*buffer = '\n';
			buffer++;
			buflen--;
		} else {
			return (NSS_STR_PARSE_ERANGE);
		}

		if (namelen > 1) {
			if ((addrlen + cnamelen + namelen + 3)
					> buflen)
				return (NSS_STR_PARSE_ERANGE);
			(void) snprintf(buffer, buflen, "%s %s %s",
					addr, cname, name);
			buffer += addrlen + cnamelen + namelen + 2;
			buflen -= (addrlen + cnamelen + namelen + 2);
		} else {
			if ((addrlen + cnamelen + 2) > buflen)
				return (NSS_STR_PARSE_ERANGE);
			(void) snprintf(buffer, buflen, "%s %s",
					addr, cname);
			buffer += addrlen + cnamelen + 1;
			buflen -= (addrlen + cnamelen + 1);
		}
	}

	if (argp->buf.result != NULL) {
		/*
		 * Some front end marshallers may require the
		 * files formatted data in a distinct buffer
		 */
		if ((be->buffer = strdup(argp->buf.buffer)) == NULL)
			return (NSS_STR_PARSE_PARSE);
		be->buflen = strlen(be->buffer);
	}
#ifdef	DEBUG
	(void) fprintf(stdout, "%s [%s]\n",
			(af == AF_INET)?"hosts":"ipnodes",
			argp->buf.buffer);
	(void) fflush(stdout);
#endif	/* DEBUG */
	return (NSS_STR_PARSE_SUCCESS);
}


static nisplus_backend_op_t host_ops[] = {
	_nss_nisplus_destr,
	_nss_nisplus_endent,
	_nss_nisplus_setent,
	_nss_nisplus_getent,
	getbyname,
	getbyaddr
};

/*ARGSUSED*/
nss_backend_t *
_nss_nisplus_hosts_constr(dummy1, dummy2, dummy3)
	const char	*dummy1, *dummy2, *dummy3;
{
	return (_nss_nisplus_constr(host_ops,
				    sizeof (host_ops) / sizeof (host_ops[0]),
				    HOST_TBLNAME, nis_object2str));
}
