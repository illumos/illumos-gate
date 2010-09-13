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

#include <pwd.h>
#include "ldap_common.h"

/* passwd attributes filters */
#define	_PWD_CN			"cn"
#define	_PWD_UID		"uid"
#define	_PWD_USERPASSWORD	"userpassword"
#define	_PWD_UIDNUMBER		"uidnumber"
#define	_PWD_GIDNUMBER		"gidnumber"
#define	_PWD_GECOS		"gecos"
#define	_PWD_DESCRIPTION	"description"
#define	_PWD_HOMEDIRECTORY	"homedirectory"
#define	_PWD_LOGINSHELL		"loginshell"


#define	_F_GETPWNAM		"(&(objectClass=posixAccount)(uid=%s))"
#define	_F_GETPWNAM_SSD		"(&(%%s)(uid=%s))"
#define	_F_GETPWUID		"(&(objectClass=posixAccount)(uidNumber=%ld))"
#define	_F_GETPWUID_SSD		"(&(%%s)(uidNumber=%ld))"

static const char *pwd_attrs[] = {
	_PWD_CN,
	_PWD_UID,
	_PWD_UIDNUMBER,
	_PWD_GIDNUMBER,
	_PWD_GECOS,
	_PWD_DESCRIPTION,
	_PWD_HOMEDIRECTORY,
	_PWD_LOGINSHELL,
	(char *)NULL
};

/*
 * _nss_ldap_passwd2str is the data marshaling method for the passwd getXbyY
 * (e.g., getbyuid(), getbyname(), getpwent()) backend processes. This method is
 * called after a successful ldap search has been performed. This method will
 * parse the ldap search values into the file format.
 * e.g.
 *
 * nobody:x:60001:60001:Nobody:/:
 *
 */
static int
_nss_ldap_passwd2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int		nss_result;
	int		buflen = 0;
	unsigned long	str_len = 0L;
	char		*buffer = NULL;
	ns_ldap_result_t	*result = be->result;
	ns_ldap_entry_t	*entry;
	char		**uid_v, **uidn_v, **gidn_v;
	char		**gecos_v, **homedir_v, **shell_v;
	char		*NULL_STR = "";
	char		uid_nobody[NOBODY_STR_LEN];
	char		gid_nobody[NOBODY_STR_LEN], *end;
	char		*uid_nobody_v[1], *gid_nobody_v[1];

	(void) snprintf(uid_nobody, sizeof (uid_nobody), "%u", UID_NOBODY);
	uid_nobody_v[0] = uid_nobody;
	(void) snprintf(gid_nobody, sizeof (gid_nobody), "%u", GID_NOBODY);
	gid_nobody_v[0] = gid_nobody;

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	entry = result->entry;

	buflen = argp->buf.buflen;
	buffer = argp->buf.buffer;

	nss_result = NSS_STR_PARSE_SUCCESS;
	(void) memset(buffer, 0, buflen);

	/* 8 = 6 ':' + 1 '\0' + 1 'x' */
	buflen -=  8;

	uid_v = __ns_ldap_getAttr(entry, _PWD_UID);
	uidn_v = __ns_ldap_getAttr(entry, _PWD_UIDNUMBER);
	gidn_v = __ns_ldap_getAttr(entry, _PWD_GIDNUMBER);
	if (uid_v == NULL || uidn_v == NULL || gidn_v == NULL ||
	    uid_v[0] == NULL || uidn_v[0] == NULL || gidn_v[0] == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_pwd2str;
	}
	/* Validate UID and GID */
	if (strtoul(uidn_v[0], &end, 10) > MAXUID)
		uidn_v = uid_nobody_v;
	if (strtoul(gidn_v[0], &end, 10) > MAXUID)
		gidn_v = gid_nobody_v;
	str_len = strlen(uid_v[0]) + strlen(uidn_v[0]) + strlen(gidn_v[0]);
	if (str_len >  buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_pwd2str;
	}

	gecos_v = __ns_ldap_getAttr(entry, _PWD_GECOS);
	if (gecos_v == NULL || gecos_v[0] == NULL || *gecos_v[0] == '\0')
		gecos_v = &NULL_STR;
	else
		str_len += strlen(gecos_v[0]);

	homedir_v = __ns_ldap_getAttr(entry, _PWD_HOMEDIRECTORY);
	if (homedir_v == NULL || homedir_v[0] == NULL || *homedir_v[0] == '\0')
		homedir_v = &NULL_STR;
	else
		str_len += strlen(homedir_v[0]);

	shell_v = __ns_ldap_getAttr(entry, _PWD_LOGINSHELL);
	if (shell_v == NULL || shell_v[0] == NULL || *shell_v[0] == '\0')
		shell_v = &NULL_STR;
	else
		str_len += strlen(shell_v[0]);

	if (str_len >  buflen) {
		nss_result = NSS_STR_PARSE_ERANGE;
		goto result_pwd2str;
	}

	if (argp->buf.result != NULL) {
		be->buflen = str_len + 8;
		be->buffer = malloc(be->buflen);
		if (be->buffer == NULL) {
			nss_result = (int)NSS_STR_PARSE_ERANGE;
			goto result_pwd2str;
		}

		(void) snprintf(be->buffer, be->buflen,
		    "%s:%s:%s:%s:%s:%s:%s",
		    uid_v[0], "x", uidn_v[0], gidn_v[0],
		    gecos_v[0], homedir_v[0], shell_v[0]);
	} else {
		(void) snprintf(argp->buf.buffer, (str_len + 8),
		    "%s:%s:%s:%s:%s:%s:%s",
		    uid_v[0], "x", uidn_v[0], gidn_v[0],
		    gecos_v[0], homedir_v[0], shell_v[0]);
	}

result_pwd2str:

	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}

/*
 * getbyname gets a passwd entry by uid name. This function constructs an ldap
 * search filter using the name invocation parameter and the getpwnam search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct passwd for the frontend
 * process. The function _nss_ldap_passwd2ent performs the data marshaling.
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	char		name[SEARCHFILTERLEN];
	int		ret;

	if (_ldap_filter_name(name, argp->key.name, sizeof (name)) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter), _F_GETPWNAM, name);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata), _F_GETPWNAM_SSD, name);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
	    _PASSWD, searchfilter, NULL, _merge_SSD_filter, userdata));
}


/*
 * getbyuid gets a passwd entry by uid number. This function constructs an ldap
 * search filter using the uid invocation parameter and the getpwuid search
 * filter defined. Once the filter is constructed, we search for a matching
 * entry and marshal the data results into struct passwd for the frontend
 * process. The function _nss_ldap_passwd2ent performs the data marshaling.
 */

static nss_status_t
getbyuid(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];
	char		userdata[SEARCHFILTERLEN];
	int		ret;

	if (argp->key.uid > MAXUID)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(searchfilter, sizeof (searchfilter),
	    _F_GETPWUID, (long)argp->key.uid);
	if (ret >= sizeof (searchfilter) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	ret = snprintf(userdata, sizeof (userdata),
	    _F_GETPWUID_SSD, (long)argp->key.uid);
	if (ret >= sizeof (userdata) || ret < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
	    _PASSWD, searchfilter, NULL, _merge_SSD_filter, userdata));
}

static ldap_backend_op_t passwd_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
	getbyuid
};


/*
 * _nss_ldap_passwd_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_passwd_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

	return ((nss_backend_t *)_nss_ldap_constr(passwd_ops,
	    sizeof (passwd_ops)/sizeof (passwd_ops[0]),
	    _PASSWD, pwd_attrs, _nss_ldap_passwd2str));
}
