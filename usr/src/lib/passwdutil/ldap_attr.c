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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ns_sldap.h"

#include <nss_dbdefs.h>
#include <nsswitch.h>

#include <pwd.h>
#include <shadow.h>
#include <syslog.h>

#include "passwdutil.h"

#include "utils.h"

int ldap_getattr(char *name, attrlist *item, pwu_repository_t *rep);
int ldap_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);
int ldap_update(attrlist *items, pwu_repository_t *rep, void *buf);
int ldap_putpwnam(char *name, char *oldpw, char *dummy,
	pwu_repository_t *rep, void *buf);
int ldap_user_to_authenticate(char *name, pwu_repository_t *rep,
	char **auth_user, int *privileged);

/*
 * ldap function pointer table, used by passwdutil_init to initialize
 * the global Repository-OPerations table "rops"
 */
struct repops ldap_repops = {
	NULL,	/* checkhistory */
	ldap_getattr,
	ldap_getpwnam,
	ldap_update,
	ldap_putpwnam,
	ldap_user_to_authenticate,
	NULL,	/* lock */
	NULL	/* unlock */
};

/*
 * structure used to keep state between get/update/put calls
 */
typedef struct {
	char *passwd;		/* encrypted password */
	struct passwd *pwd;
	ns_ldap_attr_t **attrs;
} ldapbuf_t;

/*
 * The following define's are taken from
 *	usr/src/lib/nsswitch/ldap/common/getpwnam.c
 */

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

/*
 * int ldap_user_to_authenticate(user, rep, auth_user, privileged)
 *
 * We can't determine whether the user is "privileged" in the LDAP
 * sense. The operation should be attempted and will succeed if
 * the user had privileges.
 *
 * For our purposes, we say that the user is privileged if he/she
 * is attempting to change another user's password attributes.
 */
int
ldap_user_to_authenticate(char *user, pwu_repository_t *rep,
	char **auth_user, int *privileged)
{
	struct passwd *pw;
	uid_t uid;
	uid_t priviledged_uid;
	int res = PWU_SUCCESS;

	if (strcmp(user, "root") == 0)
		return (PWU_NOT_FOUND);

	if ((pw = getpwnam_from(user, rep, REP_LDAP)) == NULL)
		return (PWU_NOT_FOUND);

	uid = getuid();

	if (uid == pw->pw_uid) {
		/* changing out own, not privileged */
		*privileged = 0;
		if ((*auth_user = strdup(user)) == NULL)
			res = PWU_NOMEM;
	} else {
		char pwd_buf[1024];
		struct passwd pwr;

		*privileged = 1;
		/*
		 * specific case for root
		 * we want 'user' to be authenticated.
		 */
		if (uid == 0)  {
			priviledged_uid = pw->pw_uid;
		} else {
			priviledged_uid = uid;
		}
		if (getpwuid_r(priviledged_uid, &pwr, pwd_buf,
				sizeof (pwd_buf)) != NULL) {
			if ((*auth_user = strdup(pwr.pw_name)) ==  NULL)
				res = PWU_NOMEM;
		} else {
			/* hmm. can't find name of current user...??? */

#define	MAX_UID_LEN 11	/* UID's larger than 2^32 won't fit... */
			if ((*auth_user = malloc(MAX_UID_LEN)) == NULL) {
				res = PWU_NOMEM;
			} else {
				(void) snprintf(*auth_user, MAX_UID_LEN, "%d",
				    (int)uid);
			}
		}
	}

	return (res);
}

/*
 * int ldap_getattr(name, item, rep)
 *
 * retrieve attributes specified in "item" for user "name".
 */
/*ARGSUSED*/
int
ldap_getattr(char *name, attrlist *items, pwu_repository_t *rep)
{
	int res;
	struct passwd *pw = NULL;
	struct spwd *spw = NULL;
	attrlist *w;

	int need_shadow = 0;	/* Need shadow info from LDAP server */
	int need_normal = 0;	/* Need non-shadow info from LDAP server */

	/* We need the "shadow" map for the password only */
	for (w = items; w != NULL; w = w->next) {
		if (w->type == ATTR_PASSWD ||
			w->type == ATTR_PASSWD_SERVER_POLICY)
			need_shadow = 1;
		else
			need_normal = 1;
	}

	if (need_normal) {
		res = dup_pw(&pw, getpwnam_from(name, rep, REP_LDAP));
		if (res != PWU_SUCCESS)
			goto out;
	}

	if (need_shadow) {
		res = dup_spw(&spw, getspnam_from(name, rep, REP_LDAP));
		if (res != PWU_SUCCESS) {
			goto out;
		}
	}

	for (w = items; res == PWU_SUCCESS && w != NULL; w = w->next) {
		switch (w->type) {
		case ATTR_NAME:
			if ((w->data.val_s = strdup(pw->pw_name)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_COMMENT:
			if ((w->data.val_s = strdup(pw->pw_comment)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_GECOS:
			if ((w->data.val_s = strdup(pw->pw_gecos)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_HOMEDIR:
			if ((w->data.val_s = strdup(pw->pw_dir)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_SHELL:
			if ((w->data.val_s = strdup(pw->pw_shell)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			if ((w->data.val_s = strdup(spw->sp_pwdp)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_AGE:
			if ((w->data.val_s = strdup(pw->pw_age)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_REP_NAME:
			if ((w->data.val_s = strdup("ldap")) == NULL)
				res = PWU_NOMEM;
			break;

		/* integer values */
		case ATTR_UID:
			w->data.val_i = pw->pw_uid;
			break;
		case ATTR_GID:
			w->data.val_i = pw->pw_gid;
			break;
		case ATTR_LSTCHG:
			w->data.val_i = -1;
			break;
		case ATTR_MIN:
			w->data.val_i = -1;
			break;
		case ATTR_MAX:
			w->data.val_i = -1;
			break;
		case ATTR_WARN:
			w->data.val_i = -1;
			break;
		case ATTR_INACT:
			w->data.val_i = -1;
			break;
		case ATTR_EXPIRE:
			w->data.val_i = -1;
			break;
		case ATTR_FLAG:
			break;
		default:
			break;
		}
	}

out:
	if (pw)
		free_pwd(pw);
	if (spw)
		free_spwd(spw);

	return (res);
}

/*
 * int ldap_getpwnam(name, items, rep, buf)
 *
 * There is no need to get the old values from the ldap
 * server, as the update will update each item individually.
 * Therefore, we only allocate a buffer that will be used by
 * _update and _putpwnam to hold the attributes to update.
 *
 * Only when we're about to update a password, we need to retrieve
 * the old password since it contains salt-information.
 */
/*ARGSUSED*/
int
ldap_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf)
{
	attrlist *p;
	int nr_items;
	int need_pwd = 0;
	ldapbuf_t *ldapbuf;
	int res;

	for (nr_items = 0, p = items; p != NULL; p = p->next) {
		nr_items++;
		if (p->type == ATTR_PASSWD ||
		    p->type == ATTR_PASSWD_SERVER_POLICY)
			need_pwd = 1;
	}


	ldapbuf = calloc(1, sizeof (ldapbuf_t));
	if (ldapbuf == NULL)
		return (PWU_NOMEM);

	ldapbuf->attrs = calloc(nr_items, sizeof (ns_ldap_attr_t *));
	if (ldapbuf->attrs == NULL)
		return (PWU_NOMEM);

	if (need_pwd) {
		struct spwd *spw;

		res = dup_pw(&ldapbuf->pwd, getpwnam_from(name, rep, REP_LDAP));
		if (res != PWU_SUCCESS)
			return (res);

		spw  = getspnam_from(name, rep, REP_LDAP);
		if (spw) {
			ldapbuf->passwd = strdup(spw->sp_pwdp);
			if (ldapbuf->passwd == NULL)
				return (PWU_NOMEM);
		}
	}

	*buf = ldapbuf;
	return (0);
}

/*
 * new_attr(name, value)
 *
 * create a new LDAP attribute to be sent to the server
 */
ns_ldap_attr_t *
new_attr(char *name, char *value)
{
	ns_ldap_attr_t *tmp;

	tmp = malloc(sizeof (*tmp));
	if (tmp != NULL) {
		tmp->attrname = name;
		tmp->attrvalue = (char **)calloc(2, sizeof (char *));
		if (tmp->attrvalue == NULL) {
			free(tmp);
			return (NULL);
		}
		tmp->attrvalue[0] = value;
		tmp->value_count = 1;
	}

	return (tmp);
}

/*
 * ldap_update(items, rep, buf)
 *
 * create LDAP attributes in 'buf' for each attribute in 'items'.
 */
/*ARGSUSED*/
int
ldap_update(attrlist *items, pwu_repository_t *rep, void *buf)
{
	attrlist *p;
	int idx = 0;
	ldapbuf_t *ldapbuf = (ldapbuf_t *)buf;
	ns_ldap_attr_t **attrs = ldapbuf->attrs;
	char *pwd, *val;
	char *salt;
	size_t cryptlen;

	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_PASSWD:
			salt = crypt_gensalt(ldapbuf->passwd, ldapbuf->pwd);

			if (salt == NULL) {
				if (errno == ENOMEM)
					return (PWU_NOMEM);
				else {
					/* algorithm problem? */
					syslog(LOG_AUTH | LOG_ALERT,
					    "passwdutil: crypt_gensalt "
					    "%m");
					return (PWU_UPDATE_FAILED);
				}
			}

			pwd = crypt(p->data.val_s, salt);
			free(salt);
			cryptlen = strlen(pwd) + sizeof ("{crypt}");
			val = malloc(cryptlen);
			if (val == NULL)
				return (PWU_NOMEM);
			(void) snprintf(val, cryptlen, "{crypt}%s", pwd);

			attrs[idx] = new_attr(_PWD_USERPASSWORD, val);
			break;
		/*
		 * For server policy, don't crypt the password,
		 * send the password as is to the server and
		 * let the LDAP server do its own password
		 * encryption
		 */
		case ATTR_PASSWD_SERVER_POLICY:
			val = strdup(p->data.val_s);
			if (val == NULL)
				return (PWU_NOMEM);

			attrs[idx] = new_attr(_PWD_USERPASSWORD, val);
			break;
		case ATTR_COMMENT:
			/* XX correct? */
			attrs[idx] = new_attr(_PWD_DESCRIPTION, p->data.val_s);
			break;
		case ATTR_GECOS:
			attrs[idx] = new_attr(_PWD_GECOS, p->data.val_s);
			break;
		case ATTR_HOMEDIR:
			attrs[idx] = new_attr(_PWD_HOMEDIRECTORY,
						p->data.val_s);
			break;
		case ATTR_SHELL:
			attrs[idx] = new_attr(_PWD_LOGINSHELL, p->data.val_s);
			break;
		/* Unsupported items are below this line */
		case ATTR_NAME:
		case ATTR_UID:
		case ATTR_GID:
		case ATTR_AGE:
		case ATTR_LSTCHG:
		case ATTR_MIN:
		case ATTR_MAX:
		case ATTR_WARN:
		case ATTR_INACT:
		case ATTR_EXPIRE:
		case ATTR_FLAG:
			break;
		default:
			break;
		}
		if (attrs[idx] == NULL)
			return (PWU_NOMEM);
		idx++;
	}

	attrs[idx] = NULL;

	return (PWU_SUCCESS);
}

/*
 * ldap_to_pwu_code(error, pwd_status)
 *
 * translation from LDAP return values and PWU return values
 */
int
ldap_to_pwu_code(int error, int pwd_status)
{
	switch (error) {
	case NS_LDAP_SUCCESS:	return (PWU_SUCCESS);
	case NS_LDAP_OP_FAILED:	return (PWU_DENIED);
	case NS_LDAP_NOTFOUND:	return (PWU_NOT_FOUND);
	case NS_LDAP_MEMORY:	return (PWU_NOMEM);
	case NS_LDAP_CONFIG:	return (PWU_NOT_FOUND);
	case NS_LDAP_INTERNAL:
		switch (pwd_status) {
		case NS_PASSWD_EXPIRED:
			return (PWU_DENIED);
		case NS_PASSWD_CHANGE_NOT_ALLOWED:
			return (PWU_CHANGE_NOT_ALLOWED);
		case NS_PASSWD_TOO_SHORT:
			return (PWU_PWD_TOO_SHORT);
		case NS_PASSWD_INVALID_SYNTAX:
			return (PWU_PWD_INVALID);
		case NS_PASSWD_IN_HISTORY:
			return (PWU_PWD_IN_HISTORY);
		case NS_PASSWD_WITHIN_MIN_AGE:
			return (PWU_WITHIN_MIN_AGE);
		default:
			return (PWU_SYSTEM_ERROR);
		}
	default:		return (PWU_SYSTEM_ERROR);
	}
}

int
ldap_replaceattr(const char *dn, ns_ldap_attr_t **attrs, const char *binddn,
	const char *pwd, int *pwd_status)
{
	int		result = NS_LDAP_OP_FAILED;
	int		ldaprc;
	int		authstried = 0;
	char		**certpath = NULL;
	ns_auth_t	**app;
	ns_auth_t	**authpp = NULL;
	ns_auth_t	*authp = NULL;
	ns_cred_t	*credp;
	ns_ldap_error_t	*errorp = NULL;

	debug("%s: replace_ldapattr()", __FILE__);

	if ((credp = (ns_cred_t *)calloc(1, sizeof (ns_cred_t))) == NULL)
		return (PWU_NOMEM);

	/* Fill in the user name and password */
	if (dn == NULL || pwd == NULL)
		goto out;

	credp->cred.unix_cred.userID = strdup(binddn);
	credp->cred.unix_cred.passwd = strdup(pwd);

	/* get host certificate path, if one is configured */
	ldaprc = __ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
		(void ***)&certpath, &errorp);
	if (ldaprc != NS_LDAP_SUCCESS)
		goto out;

	if (certpath && *certpath)
		credp->hostcertpath = *certpath;

	/* Load the service specific authentication method */
	ldaprc = __ns_ldap_getServiceAuthMethods("passwd-cmd", &authpp,
		&errorp);

	if (ldaprc != NS_LDAP_SUCCESS)
		goto out;

	/*
	 * if authpp is null, there is no serviceAuthenticationMethod
	 * try default authenticationMethod
	 */
	if (authpp == NULL) {
		ldaprc = __ns_ldap_getParam(NS_LDAP_AUTH_P, (void ***)&authpp,
			&errorp);
		if (ldaprc != NS_LDAP_SUCCESS)
			goto out;
	}

	/*
	 * if authpp is still null, then can not authenticate, syslog
	 * error message and return error
	 */
	if (authpp == NULL) {
		syslog(LOG_ERR,
		"passwdutil: no legal LDAP authentication method configured");
		result = NS_LDAP_OP_FAILED;
		goto out;
	}

	/*
	 * Walk the array and try all authentication methods in order except
	 * for "none".
	 */
	for (app = authpp; *app; app++) {
		authp = *app;
		/* what about disabling other mechanisms? "tls:sasl/EXTERNAL" */
		if (authp->type == NS_LDAP_AUTH_NONE)
			continue;
		authstried++;
		credp->auth.type = authp->type;
		credp->auth.tlstype = authp->tlstype;
		credp->auth.saslmech = authp->saslmech;
		credp->auth.saslopt = authp->saslopt;

		ldaprc = __ns_ldap_repAttr("shadow", dn,
			(const ns_ldap_attr_t * const *)attrs,
			credp, 0, &errorp);
		if (ldaprc == NS_LDAP_SUCCESS) {
			result = NS_LDAP_SUCCESS;
			goto out;
		}

		/*
		 * other errors might need to be added to this list, for
		 * the current supported mechanisms this is sufficient
		 */
		if ((ldaprc == NS_LDAP_INTERNAL) &&
			(errorp->pwd_mgmt.status == NS_PASSWD_GOOD) &&
			((errorp->status == LDAP_INAPPROPRIATE_AUTH) ||
			(errorp->status == LDAP_INVALID_CREDENTIALS))) {
			result = ldaprc;
			goto out;
		}

		/*
		 * If there is error related to password policy,
		 * return it to caller
		 */
		if ((ldaprc == NS_LDAP_INTERNAL) &&
			errorp->pwd_mgmt.status != NS_PASSWD_GOOD) {
			*pwd_status = errorp->pwd_mgmt.status;
			result = ldaprc;
			goto out;
		} else
			*pwd_status = NS_PASSWD_GOOD;

		/* we don't really care about the error, just clean it up */
		if (errorp)
			(void) __ns_ldap_freeError(&errorp);
	}
	if (authstried == 0) {
		syslog(LOG_ERR,
		"passwdutil: no legal LDAP authentication method configured");
		result = NS_LDAP_CONFIG;
		goto out;
	}
	result = PWU_DENIED;

out:
	if (credp)
		(void) __ns_ldap_freeCred(&credp);

	if (authpp)
		(void) __ns_ldap_freeParam((void ***)&authpp);

	if (errorp)
		(void) __ns_ldap_freeError(&errorp);

	return (result);
}



/*
 * ldap_putpwnam(name, oldpw, dummy, rep, buf)
 *
 * update the LDAP server with the attributes contained in 'buf'.
 * The dummy parameter is a placeholder for NIS+ where the old
 * RPC password is passwd.
 */
/*ARGSUSED*/
int
ldap_putpwnam(char *name, char *oldpw, char *dummy,
	pwu_repository_t *rep, void *buf)
{
	int res;
	char *dn;	/* dn of user whose attributes we are changing */
	char *binddn;	/* dn of user who is performing the change */
	ns_ldap_error_t *errorp;
	ldapbuf_t *ldapbuf = (ldapbuf_t *)buf;
	ns_ldap_attr_t **attrs = ldapbuf->attrs;
	struct passwd *pw;
	int pwd_status;
	uid_t uid;

	if (strcmp(name, "root") == 0)
		return (PWU_NOT_FOUND);

	/*
	 * The LDAP server checks whether we are permitted to perform
	 * the requested change. We need to send the name of the user
	 * who is executing this piece of code, together with his
	 * current password to the server.
	 * If this is executed by a normal user changing his/her own
	 * password, this will simply be the OLD password that is to
	 * be changed.
	 * Specific case if the user who is executing this piece
	 * of code is root. We will then issue the LDAP request
	 * with the DN of the user we want to change the passwd of.
	 */

	/*
	 * convert name of user whose attributes we are changing
	 * to a distinguished name
	 */
	res = __ns_ldap_uid2dn(name, &dn, NULL, &errorp);
	if (res != NS_LDAP_SUCCESS)
		goto out;

	/*
	 * create a dn for the user who is executing this code
	 */
	uid = getuid();
	if (uid == 0) {
		if ((pw = getpwnam_from(name, rep, REP_LDAP)) == NULL) {
			res = NS_LDAP_OP_FAILED;
			goto out;
		}
	} else if ((pw = getpwuid_from(uid, rep, REP_LDAP)) == NULL) {
		/*
		 * User executing this code is not known to the LDAP
		 * server. This operation is to be denied
		 */
		res = NS_LDAP_OP_FAILED;
		goto out;
	}

	res = __ns_ldap_uid2dn(pw->pw_name, &binddn, NULL, &errorp);
	if (res != NS_LDAP_SUCCESS)
		goto out;

	res = ldap_replaceattr(dn, attrs, binddn, oldpw,
			&pwd_status);

out:
	while (*attrs) {
		free((*attrs)->attrvalue[0]);
		free(*attrs);
		attrs++;
	}
	if (ldapbuf->passwd) {
		(void) memset(ldapbuf->passwd, 0, strlen(ldapbuf->passwd));
		free(ldapbuf->passwd);
	}
	if (ldapbuf->pwd)
		free_pwd(ldapbuf->pwd);
	free(dn);

	return (ldap_to_pwu_code(res, pwd_status));
}
