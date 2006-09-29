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

#include "ldap_common.h"
#include <sys/tsol/tndb.h>

/* tnrhtp attributes filters */
#define	_TNRHTP_NAME		"ipTnetTemplateName"
#define	_TNRHTP_ATTRS		"SolarisAttrKeyValue"
#define	_F_GETTNTPBYNAME	"(&(objectClass=ipTnetTemplate)"\
				"(!(objectClass=ipTnetHost))" \
				"(ipTnetTemplateName=%s))"
#define	_F_GETTNTPBYNAME_SSD	"(&(%%s)(ipTnetTemplateName=%s))"

static const char *tnrhtp_attrs[] = {
	_TNRHTP_NAME,
	_TNRHTP_ATTRS,
	NULL
};

/*
 * _nss_ldap_tnrhtp2str is the data marshaling method for the tnrhtp
 * (tsol_gettpbyaddr()/tsol_gettpent()) backend processes.
 * This method is called after a successful ldap search has been performed.
 * This method will parse the ldap search values into the file format.
 *
 * e.g.
 *
 * admin_low:host_type=unlabeled;def_label=[0x0000000000000000000000000000000000
 * 0000000000000000000000000000000000];min_sl=0x00000000000000000000000000000000
 * 000000000000000000000000000000000000;max_sl=0x7ffffffffffffffffffffffffffffff
 * fffffffffffffffffffffffffffffffffffff;doi=0;
 */
static int
_nss_ldap_tnrhtp2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			nss_result = NSS_STR_PARSE_SUCCESS;
	int			len = 0;
	char			*buffer = NULL;
	char			**attrs, **template;
	ns_ldap_result_t	*result = be->result;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	template = __ns_ldap_getAttr(result->entry, _TNRHTP_NAME);
	if (template == NULL || template[0] == NULL ||
			(strlen(template[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhtp2str;
	}
	attrs = __ns_ldap_getAttr(result->entry, _TNRHTP_ATTRS);
	if (attrs == NULL || attrs[0] == NULL || (strlen(attrs[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhtp2str;
	}

	/* "template:attrs" */
	len = strlen(template[0]) + strlen(attrs[0]) + 2;

	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_tnrhtp2str;
		}
		be->buflen = len - 1;
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	(void) snprintf(buffer, len, "%s:%s", template[0], attrs[0]);

result_tnrhtp2str:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

	if (argp->key.name == NULL)
		return (NSS_NOTFOUND);

	if (snprintf(searchfilter, SEARCHFILTERLEN, _F_GETTNTPBYNAME,
	    argp->key.name) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	if (snprintf(userdata, sizeof (userdata), _F_GETTNTPBYNAME_SSD,
	    argp->key.name) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return (_nss_ldap_lookup(be, argp, _TNRHTP, searchfilter, NULL,
	    _merge_SSD_filter, userdata));
}


static ldap_backend_op_t tnrhtp_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname
};

/* ARGSUSED */
nss_backend_t *
_nss_ldap_tnrhtp_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
	return ((nss_backend_t *)_nss_ldap_constr(tnrhtp_ops,
		sizeof (tnrhtp_ops)/sizeof (tnrhtp_ops[0]), _TNRHTP,
		tnrhtp_attrs, _nss_ldap_tnrhtp2str));
}
