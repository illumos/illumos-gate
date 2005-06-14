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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <secdb.h>
#include <prof_attr.h>
#include "ldap_common.h"


/* prof_attr attributes filters */
#define	_PROF_NAME		"cn"
#define	_PROF_RES1		"SolarisAttrReserved1"
#define	_PROF_RES2		"SolarisAttrReserved2"
#define	_PROF_DESC		"SolarisAttrLongDesc"
#define	_PROF_ATTRS		"SolarisAttrKeyValue"
#define	_PROF_GETPROFNAME	"(&(objectClass=SolarisProfAttr)(cn=%s))"
#define	_PROF_GETPROFNAME_SSD	"(&(%%s)(cn=%s))"

static const char *prof_attrs[] = {
	_PROF_NAME,
	_PROF_RES1,
	_PROF_RES2,
	_PROF_DESC,
	_PROF_ATTRS,
	(char *)NULL
};


static int
_nss_ldap_prof2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, nss_result;
	int			buflen = (int)0;
	unsigned long		len = 0L;
	char			*nullstring = (char *)NULL;
	char			*buffer = (char *)NULL;
	char			*ceiling = (char *)NULL;
	profstr_t		*prof = (profstr_t *)NULL;
	ns_ldap_attr_t		*attrptr;
	ns_ldap_result_t	*result = be->result;

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_prof2ent;
	}
	prof = (profstr_t *)(argp->buf.result);
	ceiling = buffer + buflen;
	prof->name = (char *)NULL;
	prof->res1 = (char *)NULL;
	prof->res2 = (char *)NULL;
	prof->desc = (char *)NULL;
	prof->attr = (char *)NULL;
	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_prof2ent;
	}

	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_prof2ent;
		}
		if (strcasecmp(attrptr->attrname, _PROF_NAME) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_prof2ent;
			}
			prof->name = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_prof2ent;
			}
			(void) strcpy(prof->name, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROF_RES1) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				prof->res1 = nullstring;
			} else {
				prof->res1 = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_prof2ent;
				}
				(void) strcpy(prof->res1,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROF_RES2) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				prof->res2 = nullstring;
			} else {
				prof->res2 = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_prof2ent;
				}
				(void) strcpy(prof->res2,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROF_DESC) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				prof->desc = nullstring;
			} else {
				prof->desc = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_prof2ent;
				}
				(void) strcpy(prof->desc,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _PROF_ATTRS) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				prof->attr = nullstring;
			} else {
				prof->attr = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_prof2ent;
				}
				(void) strcpy(prof->attr,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
	}

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getprofattr.c: _nss_ldap_prof2ent]\n");
	(void) fprintf(stdout, "      prof-name: [%s]\n", prof->name);
	if (prof->res1 != (char *)NULL) {
		(void) fprintf(stdout, "      res1: [%s]\n", prof->res1);
	}
	if (prof->res2 != (char *)NULL) {
		(void) fprintf(stdout, "      res2: [%s]\n", prof->res2);
	}
	if (prof->desc != (char *)NULL) {
		(void) fprintf(stdout, "      desc: [%s]\n", prof->desc);
	}
	if (prof->attr != (char *)NULL) {
		(void) fprintf(stdout, "      attr: [%s]\n", prof->attr);
	}
#endif	/* DEBUG */

result_prof2ent:
	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}


static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	int		ret;
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getprofattr.c: getbyname]\n");
#endif	/* DEBUG */

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _PROF_GETPROFNAME, name);
	if (ret < 0 || ret >= sizeof (searchfilter))
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _PROF_GETPROFNAME_SSD, name);
	if (ret < 0 || ret >= sizeof (userdata))
		return ((nss_status_t)NSS_NOTFOUND);

	return (_nss_ldap_lookup(be, argp,
	    _PROFATTR, searchfilter, NULL, _merge_SSD_filter, userdata));
}


static ldap_backend_op_t profattr_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname
};


/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_prof_attr_constr(const char *dummy1,
    const char *dummy2,
    const char *dummy3,
    const char *dummy4,
    const char *dummy5)
{
#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[getprofattr.c: _nss_ldap_prof_attr_constr]\n");
#endif
	return ((nss_backend_t *)_nss_ldap_constr(profattr_ops,
		sizeof (profattr_ops)/sizeof (profattr_ops[0]), _PROFATTR,
		prof_attrs, _nss_ldap_prof2ent));
}
