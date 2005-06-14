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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

static char *
gettok(char **nextpp, char sep)
{
	char *p = *nextpp;
	char *q = p;
	char c;

	if (p == NULL)
		return (NULL);
	while ((c = *q) != '\0' && c != sep)
		q++;
	if (c == '\0')
		*nextpp = 0;
	else {
		*q++ = '\0';
		*nextpp = q;
	}
	return (p);
}

/*
 * _nss_ldap_proj2ent is the data marshalling method for the project getXbyY
 * (getprojbyname, getprojbyid, getprojent) backend processes. This method
 * is called after a successful ldap search has been performed. This method
 * will parse the ldap search values into struct project = argp->buf.buffer
 * which the frontend routine expects. Three error conditions are expected
 * and returned to nsswitch.
 */
static int
_nss_ldap_proj2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int i, nss_result;
	unsigned long len = 0;
	char **uglist;
	char *buffer, *ceiling;
	char *users, *groups, *p;
	struct project *proj;
	ns_ldap_result_t *result = be->result;
	ns_ldap_attr_t *attrptr;

	buffer = argp->buf.buffer;
	if (!argp->buf.result) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_proj2ent;
	}
	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_proj2ent;
	}
	nss_result = NSS_STR_PARSE_SUCCESS;
	proj = argp->buf.result;
	proj->pj_users = proj->pj_groups = NULL;
	proj->pj_attr = proj->pj_comment = NULL;
	ceiling = (char *)ROUND_DOWN(buffer + argp->buf.buflen,
	    sizeof (char *));
	(void) memset(argp->buf.buffer, 0, argp->buf.buflen);
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_proj2ent;
		}
		len = strlen(attrptr->attrvalue[0]);
		if (strcasecmp(attrptr->attrname, _PROJ_NAME) == 0) {
			if (len == 0) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_proj2ent;
			}
			proj->pj_name = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			(void) strcpy(proj->pj_name, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROJ_PROJID) == 0) {
			if (len == 0) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_proj2ent;
			}
			errno = 0;
			proj->pj_projid =
			    (projid_t)strtol(attrptr->attrvalue[0],
			    NULL, 10);
			if (errno != 0) {
				nss_result = NSS_STR_PARSE_PARSE;
				goto result_proj2ent;
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROJ_DESCR) == 0) {
			proj->pj_comment = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			(void) strcpy(proj->pj_comment, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROJ_ATTR) == 0) {
			proj->pj_attr = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			(void) strcpy(proj->pj_attr, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROJ_USERS) == 0) {
			buffer = (char *)ROUND_UP(buffer, sizeof (char *));
			users = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			(void) strcpy(users, attrptr->attrvalue[0]);
			buffer = (char *)ROUND_UP(buffer, sizeof (char *));
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			proj->pj_users = uglist = (char **)buffer;
			*uglist = NULL;
			while (uglist < (char **)ceiling) {
				p = gettok(&users, ',');
				if (p == NULL || *p == '\0') {
					*uglist++ = 0;
					break;
				}
				*uglist++ = p;
			}
			buffer = (char *)uglist;
			if (buffer >= ceiling)
				return (NSS_STR_PARSE_ERANGE);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROJ_GROUPS) == 0) {
			buffer = (char *)ROUND_UP(buffer, sizeof (char *));
			groups = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			(void) strcpy(groups, attrptr->attrvalue[0]);
			buffer = (char *)ROUND_UP(buffer, sizeof (char *));
			if (buffer >= ceiling) {
				nss_result = NSS_STR_PARSE_ERANGE;
				goto result_proj2ent;
			}
			proj->pj_groups = uglist = (char **)buffer;
			*uglist = NULL;
			while (uglist < (char **)ceiling) {
				p = gettok(&groups, ',');
				if (p == NULL || *p == '\0') {
					*uglist++ = 0;
					break;
				}
				*uglist++ = p;
			}
			buffer = (char *)uglist;
			if (buffer >= ceiling)
				return (NSS_STR_PARSE_ERANGE);
			continue;
		}
	}
	if (proj->pj_comment == NULL) {
		buffer = (char *)ROUND_UP(buffer, sizeof (char *));
		if (buffer >= ceiling) {
			nss_result = NSS_STR_PARSE_ERANGE;
			goto result_proj2ent;
		}
		proj->pj_comment = buffer;
		*buffer = '\0';
		buffer++;
	}
	if (proj->pj_users == NULL) {
		buffer = (char *)ROUND_UP(buffer, sizeof (char *));
		if (buffer >= ceiling) {
			nss_result = NSS_STR_PARSE_ERANGE;
			goto result_proj2ent;
		}
		proj->pj_users = (char **)buffer;
		*buffer = '\0';
		buffer++;
	}
	if (proj->pj_groups == NULL) {
		buffer = (char *)ROUND_UP(buffer, sizeof (char *));
		if (buffer >= ceiling) {
			nss_result = NSS_STR_PARSE_ERANGE;
			goto result_proj2ent;
		}
		proj->pj_groups = (char **)buffer;
		*buffer = '\0';
		buffer++;
	}
	if (proj->pj_attr == NULL) {
		buffer = (char *)ROUND_UP(buffer, sizeof (char *));
		if (buffer >= ceiling) {
			nss_result = NSS_STR_PARSE_ERANGE;
			goto result_proj2ent;
		}
		proj->pj_attr = buffer;
		*buffer = '\0';
		buffer++;
	}

result_proj2ent:
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
	    _PROJECT, project_attrs, _nss_ldap_proj2ent));
}
