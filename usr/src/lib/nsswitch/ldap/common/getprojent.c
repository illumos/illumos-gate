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
	int nss_result, buflen;
	unsigned long len = 0;
	char *buffer, *comment, *user_str, *group_str, *attr_str;
	ns_ldap_result_t *result = be->result;
	char **name, **id, **descr, **users, **groups, **attr;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

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

	users = __ns_ldap_getAttr(result->entry, _PROJ_USERS);
	if (users == NULL || users[0] == NULL || (strlen(users[0]) < 1))
		user_str = _NO_VALUE;

	else
		user_str = users[0];

	groups = __ns_ldap_getAttr(result->entry, _PROJ_GROUPS);
	if (groups == NULL || groups[0] == NULL || (strlen(groups[0]) < 1))
		group_str = _NO_VALUE;

	else
		group_str = groups[0];

	attr = __ns_ldap_getAttr(result->entry, _PROJ_ATTR);
	if (attr == NULL || attr[0] == NULL || (strlen(attr[0]) < 1))
		attr_str = _NO_VALUE;

	else
		attr_str = attr[0];

	/* 6 = 5 ':' + 1 '\0' */
	len = strlen(name[0]) + strlen(id[0]) + strlen(comment) +
		strlen(user_str) + strlen(group_str) + strlen(attr_str) + 6;
	if (len >= buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_proj2str;
	}
	if (argp->buf.result != NULL) {
		if ((be->buffer = calloc(1, len)) == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_proj2str;
		}
		buffer = be->buffer;
		/* The front end marshaller does not need trailing nulls */
		be->buflen = len - 1;
	} else
		buffer = argp->buf.buffer;

	(void) snprintf(buffer, len, "%s:%s:%s:%s:%s:%s", name[0], id[0],
			comment, user_str, group_str, attr_str);

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
	return (_nss_ldap_lookup(be, argp, _PROJECT, searchfilter, NULL,
			NULL, NULL));
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

	if (snprintf(searchfilter, SEARCHFILTERLEN,
		_F_GETPROJID, (long)argp->key.projid) < 0)
		return (NSS_NOTFOUND);
	return (_nss_ldap_lookup(be, argp, _PROJECT, searchfilter, NULL,
			NULL, NULL));
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
