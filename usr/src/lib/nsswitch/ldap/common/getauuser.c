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
#include "ldap_common.h"
#include <bsm/libbsm.h>


/* audit_user attributes */
#define	_AU_NAME		"uid"
#define	_AU_ALWAYS		"SolarisAuditAlways"
#define	_AU_NEVER		"SolarisAuditNever"
#define	_AU_GETAUUSERNAME	"(&(objectClass=SolarisAuditUser)(uid=%s))"
#define	_AU_GETAUUSERNAME_SSD	"(&(%%s)(uid=%s))"


static const char *auuser_attrs[] = {
	_AU_NAME,
	_AU_ALWAYS,
	_AU_NEVER,
	(char *)NULL
};
/*
 * _nss_ldap_au2str is the data marshaling method for the audit_user
 * system call getauusernam, getauusernam_r, getauuserent and getauuserent_r.
 * This method is called after a successful search has been performed.
 * This method will parse the search results into the file format.
 * e.g.
 *
 * root:lo:no
 *
 */
static int
_nss_ldap_au2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result;
	int			buflen = 0;
	unsigned long		len = 0L;
	char			*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	char			**name, **al, **ne, *al_str, *ne_str;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	buflen = argp->buf.buflen;
	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	name = __ns_ldap_getAttr(result->entry, _AU_NAME);
	if (name == NULL || name[0] == NULL ||
			(strlen(name[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_au2str;
	}
	al = __ns_ldap_getAttr(result->entry, _AU_ALWAYS);
	if (al == NULL || al[0] == NULL || (strlen(al[0]) < 1))
		al_str = _NO_VALUE;
	else
		al_str = al[0];

	ne = __ns_ldap_getAttr(result->entry, _AU_NEVER);
	if (ne == NULL || ne[0] == NULL || (strlen(ne[0]) < 1))
		ne_str = _NO_VALUE;
	else
		ne_str = ne[0];

	/* 3 = 2 ':' + 1 '\0' */
	len = strlen(name[0]) + strlen(al_str) + strlen(ne_str) + 3;
	if (len > buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_au2str;
	}

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_au2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;
	(void) snprintf(buffer, len, "%s:%s:%s",
			name[0], al_str, ne_str);
	/* The front end marshaller doesn't need the trailing null */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_au2str:
	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	int		ret;

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _AU_GETAUUSERNAME, name);

	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _AU_GETAUUSERNAME_SSD, name);

	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return (_nss_ldap_lookup(be, argp, _AUUSER, searchfilter, NULL,
	    _merge_SSD_filter, userdata));
}


static ldap_backend_op_t auuser_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname
};


/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_audit_user_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
	return ((nss_backend_t *)_nss_ldap_constr(auuser_ops,
		sizeof (auuser_ops)/sizeof (auuser_ops[0]), _AUUSER,
		auuser_attrs, _nss_ldap_au2str));
}
