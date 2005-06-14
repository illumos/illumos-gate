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


static int
_nss_ldap_auth2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, nss_result;
	int			buflen = (int)0;
	unsigned long		len = 0L;
	char			*nullstring = (char *)NULL;
	char			*buffer = (char *)NULL;
	char			*ceiling = (char *)NULL;
	authstr_t		*auth = (authstr_t *)NULL;
	ns_ldap_attr_t		*attrptr;
	ns_ldap_result_t	*result = be->result;

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_auth2ent;
	}
	auth = (authstr_t *)(argp->buf.result);
	ceiling = buffer + buflen;
	auth->name = (char *)NULL;
	auth->res1 = (char *)NULL;
	auth->res2 = (char *)NULL;
	auth->short_desc = (char *)NULL;
	auth->long_desc = (char *)NULL;
	auth->attr = (char *)NULL;
	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_auth2ent;
	}

	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_auth2ent;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_NAME) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_auth2ent;
			}
			auth->name = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_auth2ent;
			}
			(void) strcpy(auth->name, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_RES1) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				auth->res1 = nullstring;
			} else {
				auth->res1 = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_auth2ent;
				}
				(void) strcpy(auth->res1,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_RES2) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				auth->res2 = nullstring;
			} else {
				auth->res2 = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_auth2ent;
				}
				(void) strcpy(auth->res2,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_SHORTDES) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				auth->short_desc = nullstring;
			} else {
				auth->short_desc = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_auth2ent;
				}
				(void) strcpy(auth->short_desc,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_LONGDES) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				auth->long_desc = nullstring;
			} else {
				auth->long_desc = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_auth2ent;
				}
				(void) strcpy(auth->long_desc,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AUTH_ATTRS) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				auth->attr = nullstring;
			} else {
				auth->attr = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_auth2ent;
				}
				(void) strcpy(auth->attr,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
	}

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getauthattr.c: _nss_ldap_auth2ent]\n");
	(void) fprintf(stdout, "      auth-name: [%s]\n", auth->name);
	if (auth->res1 != (char *)NULL) {
		(void) fprintf(stdout, "      res1: [%s]\n", auth->res1);
	}
	if (auth->res2 != (char *)NULL) {
		(void) fprintf(stdout, "      res2: [%s]\n", auth->res2);
	}
	if (auth->short_desc != (char *)NULL) {
		(void) fprintf(stdout, "      short_desc: [%s]\n",
		    auth->short_desc);
	}
	if (auth->long_desc != (char *)NULL) {
		(void) fprintf(stdout, "      long_desc: [%s]\n",
		    auth->long_desc);
	}
	if (auth->attr != (char *)NULL) {
		(void) fprintf(stdout, "      attr: [%s]\n", auth->attr);
	}
#endif	/* DEBUG */

result_auth2ent:
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

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getauthattr.c: getbyname]\n");
#endif	/* DEBUG */

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
#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[getauthattr.c: _nss_ldap_auth_attr_constr]\n");
#endif
	return ((nss_backend_t *)_nss_ldap_constr(authattr_ops,
		sizeof (authattr_ops)/sizeof (authattr_ops[0]), _AUTHATTR,
		auth_attrs, _nss_ldap_auth2ent));
}
