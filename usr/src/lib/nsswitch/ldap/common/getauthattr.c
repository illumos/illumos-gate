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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <secdb.h>
#include <auth_attr.h>
#include "ldap_common.h"


/* auth_attr attributes filters */
#define	_AUTH_NAME		"cn"
#define	_AUTH_RES1		"SolarisAttrReserved1"
#define	_AUTH_RES2		"SolarisAttrReserved2"
#define	_AUTH_SHORTDES		"SolarisAttrShortDesc"
#define	_AUTH_LONGDES		"SolarisAttrLongDesc"
#define	_AUTH_ATTRS		"SolarisAttrKeyValue"
#define	_AUTH_GETAUTHNAME 	"(&(objectClass=SolarisAuthAttr)(cn=%s))"
#define	_AUTH_GETAUTHNAME_SSD 	"(&(%%s)(cn=%s))"


static const char *auth_attrs[] = {
	_AUTH_NAME,
	_AUTH_RES1,
	_AUTH_RES2,
	_AUTH_SHORTDES,
	_AUTH_LONGDES,
	_AUTH_ATTRS,
	(char *)NULL
};
/*
 * _nss_ldap_auth2str is the data marshaling method for the auth_attr
 * system call getauthattr and getauthnam.
 * This method is called after a successful search has been performed.
 * This method will parse the search results into the file format.
 * e.g.
 *
 * solaris.:::All Solaris Authorizations::help=AllSolAuthsHeader.html
 *
 */
static int
_nss_ldap_auth2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result;
	int			buflen = 0;
	unsigned long		len = 0L;
	char			*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	char			**name, **res1, **res2, **sdes, **ldes, **attr;
	char			*res1_str, *res2_str, *sdes_str, *ldes_str;
	char			*attr_str;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	buflen = argp->buf.buflen;
	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	name = __ns_ldap_getAttr(result->entry, _AUTH_NAME);
	if (name == NULL || name[0] == NULL ||
			(strlen(name[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_auth2str;
	}
	res1 = __ns_ldap_getAttr(result->entry, _AUTH_RES1);
	if (res1 == NULL || res1[0] == NULL || (strlen(res1[0]) < 1))
		res1_str = _NO_VALUE;
	else
		res1_str = res1[0];

	res2 = __ns_ldap_getAttr(result->entry, _AUTH_RES2);
	if (res2 == NULL || res2[0] == NULL || (strlen(res2[0]) < 1))
		res2_str = _NO_VALUE;
	else
		res2_str = res2[0];

	sdes = __ns_ldap_getAttr(result->entry, _AUTH_SHORTDES);
	if (sdes == NULL || sdes[0] == NULL || (strlen(sdes[0]) < 1))
		sdes_str = _NO_VALUE;
	else
		sdes_str = sdes[0];

	ldes = __ns_ldap_getAttr(result->entry, _AUTH_LONGDES);
	if (ldes == NULL || ldes[0] == NULL || (strlen(ldes[0]) < 1))
		ldes_str = _NO_VALUE;
	else
		ldes_str = ldes[0];

	attr = __ns_ldap_getAttr(result->entry, _AUTH_ATTRS);
	if (attr == NULL || attr[0] == NULL || (strlen(attr[0]) < 1))
		attr_str = _NO_VALUE;
	else
		attr_str = attr[0];
	/* 6 = 5 ':' + 1 '\0' */
	len = strlen(name[0]) + strlen(res1_str) + strlen(res2_str) +
		strlen(sdes_str) + strlen(ldes_str) + strlen(attr_str) + 6;
	if (len > buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_auth2str;
	}

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_auth2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;
	(void) snprintf(buffer, len, "%s:%s:%s:%s:%s:%s",
			name[0], res1_str, res2_str, sdes_str,
			ldes_str, attr_str);
	/* The front end marshaller doesn't need the trailing null */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_auth2str:
	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, SEARCHFILTERLEN,
	    _AUTH_GETAUTHNAME, name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _AUTH_GETAUTHNAME_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
	    _AUTHATTR, searchfilter, NULL, _merge_SSD_filter, userdata));
}


static ldap_backend_op_t authattr_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname
};


/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_auth_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
	return ((nss_backend_t *)_nss_ldap_constr(authattr_ops,
		sizeof (authattr_ops)/sizeof (authattr_ops[0]), _AUTHATTR,
		auth_attrs, _nss_ldap_auth2str));
}
