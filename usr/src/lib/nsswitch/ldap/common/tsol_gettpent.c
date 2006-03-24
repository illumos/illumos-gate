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
				"(ipTnetTemplateName=%s))"
#define	_F_GETTNTPBYNAME_SSD	"(&(%%s)(ipTnetTemplateName=%s))"

static const char *tnrhtp_attrs[] = {
	_TNRHTP_NAME,
	_TNRHTP_ATTRS,
	NULL
};

static int
_nss_ldap_tnrhtp2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, nss_result;
	int			len = 0;
	int			buflen = 0;
	char			*buffer = NULL;
	char			*ceiling = NULL;
	ns_ldap_attr_t		*attrptr;
	ns_ldap_result_t	*result = be->result;
	tsol_tpstr_t		*tpstrp;

	buffer = argp->buf.buffer;
	buflen = argp->buf.buflen;
	if (argp->buf.result == NULL) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_tnrhtp2ent;
	}
	tpstrp = (tsol_tpstr_t *)(argp->buf.result);
	tpstrp->template = tpstrp->attrs = NULL;
	ceiling = buffer + buflen;
	(void) memset(argp->buf.buffer, 0, buflen);
	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_tnrhtp2ent;
	}
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_tnrhtp2ent;
		}
#ifdef	DEBUG
		(void) fprintf(stdout,
		    "\n[tsol_gettpent.c: _nss_ldap_tnrhtp2ent %d]\n", i);
		(void) fprintf(stdout, "      entry value count %d: %s:%s\n",
		    attrptr->value_count,
		    attrptr->attrname ? attrptr->attrname : "NULL",
		    attrptr->attrvalue[0] ? attrptr->attrvalue[0] : "NULL");
#endif	/* DEBUG */
		if (strcasecmp(attrptr->attrname, _TNRHTP_NAME) == 0) {
			len = strlen(attrptr->attrvalue[0]);
			if (len < 1 || (attrptr->attrvalue[0] == '\0')) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_tnrhtp2ent;
			}
			tpstrp->template = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_tnrhtp2ent;
			}
			(void) strcpy(tpstrp->template, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _TNRHTP_ATTRS) == 0) {
			len = strlen(attrptr->attrvalue[0]);
			if (len < 1 || (attrptr->attrvalue[0] == '\0')) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_tnrhtp2ent;
			}
			tpstrp->attrs = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_tnrhtp2ent;
			}
			(void) strcpy(tpstrp->attrs, attrptr->attrvalue[0]);
			continue;
		}
	}
	if (tpstrp->attrs == NULL)
		nss_result = NSS_STR_PARSE_PARSE;
	else
		nss_result = NSS_STR_PARSE_SUCCESS;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[tsol_gettpent.c: _nss_ldap_tnrhtp2ent]\n");
	(void) fprintf(stdout, "      template: [%s]\n",
	    tpstrp->template ? tpstrp->template : "NULL");
	(void) fprintf(stdout, "      attrs: [%s]\n",
	    tpstrp->attrs ? tpstrp->attrs : "NULL");
#endif	/* DEBUG */

result_tnrhtp2ent:
	(void) __ns_ldap_freeResult(&be->result);
	return (nss_result);
}


static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[tsol_gettpent.c: getbyname]\n");
#endif	/* DEBUG */

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


nss_backend_t *
_nss_ldap_tnrhtp_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[gettnrhtpattr.c: _nss_ldap_tnrhtp_constr]\n");
#endif
	return ((nss_backend_t *)_nss_ldap_constr(tnrhtp_ops,
		sizeof (tnrhtp_ops)/sizeof (tnrhtp_ops[0]), _TNRHTP,
		tnrhtp_attrs, _nss_ldap_tnrhtp2ent));
}
