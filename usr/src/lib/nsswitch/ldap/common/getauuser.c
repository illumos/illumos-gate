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


static int
_nss_ldap_au2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, nss_result;
	int			buflen = (int)0;
	unsigned long		len = 0L;
	char			*nullstring = (char *)NULL;
	char			*buffer = (char *)NULL;
	char			*ceiling = (char *)NULL;
	au_user_str_t		*au_user = (au_user_str_t *)NULL;
	ns_ldap_attr_t		*attrptr;
	ns_ldap_result_t	*result = be->result;

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_au2ent;
	}
	au_user = (au_user_str_t *)(argp->buf.result);
	ceiling = buffer + buflen;
	au_user->au_name = (char *)NULL;
	au_user->au_always = (char *)NULL;
	au_user->au_never = (char *)NULL;
	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	attrptr = getattr(result, 0);
	if (attrptr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_au2ent;
	}
	for (i = 0; i < result->entry->attr_count; i++) {
		attrptr = getattr(result, i);
		if (attrptr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_au2ent;
		}
		if (strcasecmp(attrptr->attrname, _AU_NAME) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_au2ent;
			}
			au_user->au_name = buffer;
			buffer += len + 1;
			if (buffer >= ceiling) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_au2ent;
			}
			(void) strcpy(au_user->au_name, attrptr->attrvalue[0]);
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AU_ALWAYS) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				au_user->au_always = nullstring;
			} else {
				au_user->au_always = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_au2ent;
				}
				(void) strcpy(au_user->au_always,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
		if (strcasecmp(attrptr->attrname, _AU_NEVER) == 0) {
			if ((attrptr->attrvalue[0] == NULL) ||
			    (len = strlen(attrptr->attrvalue[0])) < 1) {
				au_user->au_never = nullstring;
			} else {
				au_user->au_never = buffer;
				buffer += len + 1;
				if (buffer >= ceiling) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_au2ent;
				}
				(void) strcpy(au_user->au_never,
				    attrptr->attrvalue[0]);
			}
			continue;
		}
	}

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getauuser.c: _nss_ldap_au2ent]\n");
	(void) fprintf(stdout, "      au_name: [%s]\n", au_user->au_name);
	if (au_user->au_always != (char *)NULL) {
		(void) fprintf(stdout, "      au_always: [%s]\n",
		    au_user->au_always);
	}
	if (au_user->au_never != (char *)NULL) {
		(void) fprintf(stdout, "      au_never: [%s]\n",
		    au_user->au_never);
	}
#endif	/* DEBUG */

result_au2ent:
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

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getauuser.c: getbyname]\n");
#endif	/* DEBUG */

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
#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[getauuser.c: _nss_ldap_audit_user_constr]\n");
#endif
	return ((nss_backend_t *)_nss_ldap_constr(auuser_ops,
		sizeof (auuser_ops)/sizeof (auuser_ops[0]), _AUUSER,
		auuser_attrs, _nss_ldap_au2ent));
}
