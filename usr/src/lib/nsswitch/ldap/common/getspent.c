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


#include <shadow.h>
#include <stdlib.h>
#include "ldap_common.h"

/* shadow attributes filters */
#define	_S_UID			"uid"
#define	_S_USERPASSWORD		"userpassword"
#define	_S_FLAG			"shadowflag"

#define	_F_GETSPNAM		"(&(objectClass=shadowAccount)(uid=%s))"
#define	_F_GETSPNAM_SSD		"(&(%%s)(uid=%s))"

static const char *sp_attrs[] = {
	_S_UID,
	_S_USERPASSWORD,
	_S_FLAG,
	(char *)NULL
};

/*
 * _nss_ldap_shadow2str is the data marshaling method for the shadow getXbyY
 * (e.g., getspnam(), getspent()) backend processes. This method is called after
 * a successful ldap search has been performed. This method will parse the
 * ldap search values into the file format.
 * e.g.
 *
 * myname:gaBXNJuz4JDmA:6445::::::
 *
 */

static int
_nss_ldap_shadow2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		nss_result;
	int		buflen = 0;
	unsigned long	len = 0L;
	char		*tmp, *buffer = NULL;
	char		*pw_passwd = NULL;
	ns_ldap_result_t	*result = be->result;
	char		**uid, **passwd, **flag, *flag_str;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);
	buflen = argp->buf.buflen;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	uid = __ns_ldap_getAttr(result->entry, _S_UID);
	if (uid == NULL || uid[0] == NULL || (strlen(uid[0]) < 1)) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_spd2str;
	}
	len += strlen(uid[0]);

	passwd = __ns_ldap_getAttr(result->entry, _S_USERPASSWORD);
	if (passwd == NULL || passwd[0] == NULL) {
		/*
		 * ACL does not allow userpassword to return or
		 * userpassword is not defined
		 */
		pw_passwd = NOPWDRTR;
	} else if (strcmp(passwd[0], "") == 0) {
		/*
		 * An empty password is not supported
		 */
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_spd2str;
	} else {
		if ((tmp = strstr(passwd[0], "{crypt}")) != NULL ||
			(tmp = strstr(passwd[0], "{CRYPT}")) != NULL) {
			if (tmp != passwd[0])
				pw_passwd = NOPWDRTR;
			else
				pw_passwd = tmp + strlen("{crypt}");
		} else {
		/* mark password as not retrievable */
			pw_passwd = NOPWDRTR;
		}
	}
	len += strlen(pw_passwd);

	/*
	 * Ignore the following password aging related attributes:
	 * -- shadowlastchange
	 * -- shadowmin
	 * -- shadowmax
	 * -- shadowwarning
	 * -- shadowinactive
	 * -- shadowexpire
	 * This is because the LDAP naming service does not
	 * really support the password aging fields defined
	 * in the shadow structure. These fields, sp_lstchg,
	 * sp_min, sp_max, sp_warn, sp_inact, and sp_expire,
	 * will be set to -1 by the front end marshaller.
	 */
	flag = __ns_ldap_getAttr(result->entry, _S_FLAG);
	if (flag == NULL || flag[0] == NULL)
		flag_str = _NO_VALUE;
	else
		flag_str = flag[0];

	/* 9 = 8 ':' + 1 '\0' */
	len += strlen(flag_str) + 9;

	if (len > buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_spd2str;
	}

	if (argp->buf.result != NULL) {
		be->buffer = calloc(1, len);
		if (be->buffer == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_spd2str;
		}
		buffer = be->buffer;
	} else
		buffer = argp->buf.buffer;

	(void) snprintf(buffer, len, "%s:%s:::::::%s",
			uid[0], pw_passwd, flag_str);

	/* The front end marhsaller doesn't need the trailing null */
	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);
result_spd2str:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}

/*
 * getbynam gets a passwd entry by uid name. This function constructs an ldap
 * search filter using the name invocation parameter and the getspnam search
 * filter defined. Once the filter is constructed we search for a matching
 * entry and marshal the data results into struct shadow for the frontend
 * process. The function _nss_ldap_shadow2ent performs the data marshaling.
 */

static nss_status_t
getbynam(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN + 1];
	int		ret;

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETSPNAM, name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETSPNAM_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return (_nss_ldap_lookup(be, argp, _SHADOW, searchfilter, NULL,
		_merge_SSD_filter, userdata));
}

static ldap_backend_op_t sp_ops[] = {
    _nss_ldap_destr,
    _nss_ldap_endent,
    _nss_ldap_setent,
    _nss_ldap_getent,
    getbynam
};


/*
 * _nss_ldap_passwd_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_shadow_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(sp_ops,
		sizeof (sp_ops)/sizeof (sp_ops[0]),
		_SHADOW, sp_attrs, _nss_ldap_shadow2str));
}
