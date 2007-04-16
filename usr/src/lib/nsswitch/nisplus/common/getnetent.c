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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	nisplus/getnetent.c -- NIS+ backend for nsswitch "net" database
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nisplus_common.h"
#include "nisplus_tables.h"

static int nettoa(int anet, char *buf, int buflen, char **pnull);

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
	return (_nss_nisplus_lookup(be, argp, NET_TAG_NAME, argp->key.name));
}

static nss_status_t
getbyaddr(be, a)
	nisplus_backend_ptr_t	be;
	void			*a;
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		addrstr[16];
	char		*pnull;
	nss_status_t	rc;

	if (nettoa((int)argp->key.netaddr.net, addrstr, 16, &pnull) != 0)
		return (NSS_UNAVAIL);   /* it's really ENOMEM */
	rc = _nss_nisplus_lookup(be, argp, NET_TAG_ADDR, addrstr);

	/*
	 * if not found, try again with the untruncated address string
	 * that has the trailing zero(s)
	 */
	if (rc == NSS_NOTFOUND && pnull != NULL) {
		*pnull = '.';
		rc = _nss_nisplus_lookup(be, argp, NET_TAG_ADDR, addrstr);
	}
	return (rc);
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
	char			*cname, *addr;
	int			buflen, cnamelen, addrlen;
	int			stat;
	struct	entry_col	*ecol;

	if (obj->zo_data.zo_type != NIS_ENTRY_OBJ ||
		obj->EN_data.en_cols.en_cols_len < NET_COL) {
		/* namespace/table/object is curdled */
		return (NSS_STR_PARSE_PARSE);
	}
	ecol = obj->EN_data.en_cols.en_cols_val;

	buflen = argp->buf.buflen;
	buffer = argp->buf.buffer;
	(void) memset(buffer, 0, buflen);

	/* cname */
	__NISPLUS_GETCOL_OR_RETURN(ecol, NET_NDX_CNAME,
		cnamelen, cname);

	/* addr */
	__NISPLUS_GETCOL_OR_RETURN(ecol, NET_NDX_ADDR,
		addrlen, addr);
	if (inet_network(addr) == (in_addr_t)-1)
		return (NSS_STR_PARSE_PARSE);

	if (cnamelen + addrlen + 2  > buflen)
		return (NSS_STR_PARSE_ERANGE);
	(void) snprintf(buffer, buflen, "%s %s", cname, addr);

	linep = buffer + cnamelen + addrlen + 1;
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
	(void) fprintf(stdout, "networks [%s]\n", buffer);
	(void) fflush(stdout);
#endif  /* DEBUG */
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
				NET_TBLNAME, nis_object2str));
}

/*
 * Takes an unsigned integer in host order, and returns a printable
 * string for it as a network number.  To allow for the possibility of
 * naming subnets, only trailing dot-zeros are truncated. The location
 * where the string is truncated (or set to '\0') is returned in *pnull.
 */
static int
nettoa(int anet, char *buf, int buflen, char **pnull)
{
	char		*p;
	struct in_addr	in;
	int		addr;

	*pnull = NULL;
	if (buf == 0)
		return (1);
	in = inet_makeaddr(anet, INADDR_ANY);
	addr = in.s_addr;
	(void) strlcpy(buf, inet_ntoa(in), buflen);
	if ((IN_CLASSA_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	} else if ((IN_CLASSB_HOST & htonl(addr)) == 0) {
		p = strchr(buf, '.');
		if (p == NULL)
			return (1);
		p = strchr(p+1, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	} else if ((IN_CLASSC_HOST & htonl(addr)) == 0) {
		p = strrchr(buf, '.');
		if (p == NULL)
			return (1);
		*p = 0;
		*pnull = p;
	}
	return (0);
}
