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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <project.h>
#include "ldap_common.h"

/* Project attributes filters */
#define	_PROJ_NAME	"SolarisProjectName"
#define	_PROJ_PROJID	"SolarisProjectID"
#define	_PROJ_DESCR	"description"
#define	_PROJ_USERS	"memberUid"
#define	_PROJ_GROUPS	"memberGid"
#define	_PROJ_ATTR	"SolarisProjectAttr"

#define	_F_GETPROJNAME	"(&(objectClass=SolarisProject)(SolarisProjectName=%s))"
#define	_F_GETPROJID	"(&(objectClass=SolarisProject)(SolarisProjectID=%ld))"

static const char *project_attrs[] = {
	_PROJ_NAME,
	_PROJ_PROJID,
	_PROJ_DESCR,
	_PROJ_USERS,
	_PROJ_GROUPS,
	_PROJ_ATTR,
	(char *)NULL
};

/*
 * _nss_ldap_proj2str is the data marshalling method for the project getXbyY
 * (getprojbyname, getprojbyid, getprojent) backend processes. This method
 * is called after a successful ldap search has been performed. This method
 * will parse the ldap search values into the file format.
 * e.g.
 *
 * system:0:System:::
 *
 * beatles:100:The Beatles:john,paul,george,ringo::task.max-lwps=
 * 	(privileged,100,signal=SIGTERM),(privileged,110,deny)
 *
 * (All in one line)
 */
static int
_nss_ldap_proj2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i;
	int			nss_result;
	int			buflen = 0, len;
	int			firsttime;
	char			*buffer, *comment, *attr_str;
	ns_ldap_result_t	*result = be->result;
	char			**name, **id, **descr, **attr;
	ns_ldap_attr_t		*users, *groups;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;

	if (argp->buf.result != NULL) {
		/* In all cases it must be deallocated by caller */
		if ((be->buffer = calloc(1, buflen)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_proj2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(buffer, 0, buflen);

	name = __ns_ldap_getAttr(result->entry, _PROJ_NAME);
	if (name == NULL || name[0] == NULL || (strlen(name[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_proj2str;
	}
	id = __ns_ldap_getAttr(result->entry, _PROJ_PROJID);
	if (id == NULL || id[0] == NULL || (strlen(id[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_proj2str;
	}
	descr = __ns_ldap_getAttr(result->entry, _PROJ_DESCR);
	if (descr == NULL || descr[0] == NULL || (strlen(descr[0]) < 1))
		comment = _NO_VALUE;
	else
		comment = descr[0];
	len = snprintf(buffer, buflen, "%s:%s:%s:", name[0], id[0],
	    comment);
	TEST_AND_ADJUST(len, buffer, buflen, result_proj2str);

	users = __ns_ldap_getAttrStruct(result->entry, _PROJ_USERS);
	if (!(users == NULL || users->attrvalue == NULL)) {
		firsttime = 1;
		for (i = 0; i < users->value_count; i++) {
			if (users->attrvalue[i] == NULL) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_proj2str;
			}
			if (firsttime) {
				len = snprintf(buffer, buflen, "%s",
				    users->attrvalue[i]);
				firsttime = 0;
			} else {
				len = snprintf(buffer, buflen, ",%s",
				    users->attrvalue[i]);
			}
			TEST_AND_ADJUST(len, buffer, buflen, result_proj2str);
		}
	}
	len = snprintf(buffer, buflen, ":");
	TEST_AND_ADJUST(len, buffer, buflen, result_proj2str);

	groups = __ns_ldap_getAttrStruct(result->entry, _PROJ_GROUPS);
	if (!(groups == NULL || groups->attrvalue == NULL)) {
		firsttime = 1;
		for (i = 0; i < groups->value_count; i++) {
			if (groups->attrvalue[i] == NULL) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_proj2str;
			}
			if (firsttime) {
				len = snprintf(buffer, buflen, "%s",
				    groups->attrvalue[i]);
				firsttime = 0;
			} else {
				len = snprintf(buffer, buflen, ",%s",
				    groups->attrvalue[i]);
			}
			TEST_AND_ADJUST(len, buffer, buflen, result_proj2str);
		}
	}

	attr = __ns_ldap_getAttr(result->entry, _PROJ_ATTR);
	if (attr == NULL || attr[0] == NULL || (strlen(attr[0]) < 1))
		attr_str = _NO_VALUE;

	else
		attr_str = attr[0];
	len = snprintf(buffer, buflen, ":%s", attr_str);
	TEST_AND_ADJUST(len, buffer, buflen, result_proj2str);

	/* The front end marshaller doesn't need the trailing nulls */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);
result_proj2str:
	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


/*
 * getbyname gets a project entry by name. This function constructs an ldap
 * search filter using the name invocation parameter and the getprojname search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct project for the frontend
 * process. The function _nss_ldap_proj2ent performs the data marshaling.
 */
static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char searchfilter[SEARCHFILTERLEN];

	if (snprintf(searchfilter, SEARCHFILTERLEN,
	    _F_GETPROJNAME, argp->key.name) < 0)
		return (NSS_NOTFOUND);
	return (_nss_ldap_lookup(be, argp, _PROJECT, searchfilter, NULL, NULL,
	    NULL));
}


/*
 * getbyprojid gets a project entry by number. This function constructs an ldap
 * search filter using the name invocation parameter and the getprojid search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct project for the frontend
 * process. The function _nss_ldap_proj2ent performs the data marshaling.
 */
static nss_status_t
getbyprojid(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char searchfilter[SEARCHFILTERLEN];

	if (snprintf(searchfilter, SEARCHFILTERLEN, _F_GETPROJID,
	    (long)argp->key.projid) < 0)
		return (NSS_NOTFOUND);
	return (_nss_ldap_lookup(be, argp, _PROJECT, searchfilter, NULL, NULL,
	    NULL));
}

static ldap_backend_op_t project_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
	getbyprojid
};


/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_project_constr(const char *dummy1, const char *dummy2,
    const char *dummy3)
{
	return (_nss_ldap_constr(project_ops,
	    sizeof (project_ops) / sizeof (project_ops[0]),
	    _PROJECT, project_attrs, _nss_ldap_proj2str));
}
