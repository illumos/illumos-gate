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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <priv.h>

#include "ns_sldap.h"

#include <nss_dbdefs.h>
#include <nsswitch.h>

#include <pwd.h>
#include <shadow.h>
#include <syslog.h>

#include "passwdutil.h"

#include "utils.h"

#define	MAX_INT_LEN 11	/* 10+1 %d buflen for words/ints [not longs] */

#define	STRDUP_OR_RET(to, from) \
	if ((to = strdup(from)) == NULL) \
		return (PWU_NOMEM);

#define	STRDUP_OR_ERR(to, from, err) \
	if (((to) = strdup(from)) == NULL) \
		(err) = PWU_NOMEM;

#define	NUM_TO_STR(to, from) \
	{ \
		char nb[MAX_INT_LEN]; \
		if (snprintf(nb, MAX_INT_LEN, "%d", (from)) >= MAX_INT_LEN) \
			return (PWU_NOMEM); \
		STRDUP_OR_RET(to, nb); \
	}

#define	NEW_ATTR(p, i, attr, val) \
	{ \
		p[i] = new_attr(attr, (val)); \
		if (p[i] == NULL) \
			return (PWU_NOMEM); \
		i++; \
	}

int ldap_getattr(char *name, attrlist *item, pwu_repository_t *rep);
int ldap_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);
int ldap_update(attrlist *items, pwu_repository_t *rep, void *buf);
int ldap_putpwnam(char *name, char *oldpw, pwu_repository_t *rep, void *buf);
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
	char *passwd;			/* encrypted password */
	struct passwd *pwd;
	ns_ldap_attr_t **pattrs;	/* passwd attrs */
	int npattrs;			/* max attrs */
	struct spwd *spwd;
	ns_ldap_attr_t **sattrs;	/* passwd attrs */
	int nsattrs;			/* max attrs */
	boolean_t shadow_update_enabled;	/* shadow update configured */
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

#define	_PWD_MAX_ATTR		10	/* 9+NULL */

/* shadow attributes filters */
#define	_S_LASTCHANGE		"shadowlastchange"
#define	_S_MIN			"shadowmin"
#define	_S_MAX			"shadowmax"
#define	_S_WARNING		"shadowwarning"
#define	_S_INACTIVE		"shadowinactive"
#define	_S_EXPIRE		"shadowexpire"
#define	_S_FLAG			"shadowflag"

#define	_S_MAX_ATTR		8	/* 7+NULL */

/*
 * Frees up an ldapbuf_t
 */

static void
free_ldapbuf(ldapbuf_t *p)
{
	int i;

	if (p == NULL)
		return;
	if (p->passwd) {
		(void) memset(p->passwd, 0, strlen(p->passwd));
		free(p->passwd);
	}
	if (p->pwd)
		free_pwd(p->pwd);
	if (p->spwd)
		free_spwd(p->spwd);
	if (p->pattrs) {
		for (i = 0; i < p->npattrs; i++) {
			if (p->pattrs[i] != NULL) {
				free(p->pattrs[i]->attrvalue[0]);
				free(p->pattrs[i]);
			}
		}
		free(p->pattrs);
	}
	if (p->sattrs) {
		for (i = 0; i < p->nsattrs; i++) {
			if (p->sattrs[i] != NULL) {
				free(p->sattrs[i]->attrvalue[0]);
				free(p->sattrs[i]);
			}
		}
		free(p->sattrs);
	}
}

/*
 * int ldap_user_to_authenticate(user, rep, auth_user, privileged)
 *
 * If the Shadow Update functionality is enabled, then we check to
 * see if the caller has 0 as the euid or has all zone privs. If so,
 * the caller would be able to modify shadow(4) data stored on the
 * LDAP server. Otherwise, when LDAP Shadow Update is not enabled,
 * we can't determine whether the user is "privileged" in the LDAP
 * sense. The operation should be attempted and will succeed if the
 * user had privileges. For our purposes, we say that the user is
 * privileged if they are attempting to change another user's
 * password attributes.
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

	/*
	 * need equivalent of write access to /etc/shadow
	 * the privilege escalation model is euid == 0 || all zone privs
	 */
	if (__ns_ldap_is_shadow_update_enabled()) {
		boolean_t priv;

		priv = (geteuid() == 0);
		if (!priv) {
			priv_set_t *ps = priv_allocset();	/* caller */
			priv_set_t *zs;				/* zone */

			(void) getppriv(PRIV_EFFECTIVE, ps);
			zs = priv_str_to_set("zone", ",", NULL);
			priv = priv_isequalset(ps, zs);
			priv_freeset(ps);
			priv_freeset(zs);
		}
		/*
		 * priv can change anyone's password,
		 * only root isn't prompted.
		 */
		*privileged = 0;	/* for proper prompting */
		if (priv) {
			if (uid == 0) {
				*privileged = 1;
				*auth_user = NULL;
				return (res);
			} else if (uid == pw->pw_uid) {
				STRDUP_OR_ERR(*auth_user, user, res);
				return (res);
			}
		}

		return (PWU_DENIED);
	}

	if (uid == pw->pw_uid) {
		/* changing our own, not privileged */
		*privileged = 0;
		STRDUP_OR_RET(*auth_user, user);
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
			STRDUP_OR_ERR(*auth_user, pwr.pw_name, res);
		} else {
			/* hmm. can't find name of current user...??? */

			if ((*auth_user = malloc(MAX_INT_LEN)) == NULL) {
				res = PWU_NOMEM;
			} else {
				(void) snprintf(*auth_user, MAX_INT_LEN, "%d",
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
	attrlist *w;
	int res;
	ldapbuf_t *ldapbuf;
	struct passwd *pw = NULL;
	struct spwd *spw = NULL;

	res = ldap_getpwnam(name, items, rep, (void **)&ldapbuf);
	if (res != PWU_SUCCESS)
		return (res);

	pw = ldapbuf->pwd;
	spw = ldapbuf->spwd;

	for (w = items; res == PWU_SUCCESS && w != NULL; w = w->next) {
		switch (w->type) {
		case ATTR_NAME:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_name, res);
			break;
		case ATTR_COMMENT:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_comment, res);
			break;
		case ATTR_GECOS:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_gecos, res);
			break;
		case ATTR_HOMEDIR:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_dir, res);
			break;
		case ATTR_SHELL:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_shell, res);
			break;
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			STRDUP_OR_ERR(w->data.val_s, spw->sp_pwdp, res);
			break;
		case ATTR_AGE:
			STRDUP_OR_ERR(w->data.val_s, pw->pw_age, res);
			break;
		case ATTR_REP_NAME:
			STRDUP_OR_ERR(w->data.val_s, "ldap", res);
			break;

		/* integer values */
		case ATTR_UID:
			w->data.val_i = pw->pw_uid;
			break;
		case ATTR_GID:
			w->data.val_i = pw->pw_gid;
			break;
		case ATTR_LSTCHG:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_lstchg;
			else
				w->data.val_i = -1;
			break;
		case ATTR_MIN:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_min;
			else
				w->data.val_i = -1;
			break;
		case ATTR_MAX:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_max;
			else
				w->data.val_i = -1;
			break;
		case ATTR_WARN:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_warn;
			else
				w->data.val_i = -1;
			break;
		case ATTR_INACT:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_inact;
			else
				w->data.val_i = -1;
			break;
		case ATTR_EXPIRE:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_expire;
			else
				w->data.val_i = -1;
			break;
		case ATTR_FLAG:
			if (ldapbuf->shadow_update_enabled)
				w->data.val_i = spw->sp_flag;
			break;
		case ATTR_FAILED_LOGINS:
			w->data.val_i = spw->sp_flag & FAILCOUNT_MASK;
			break;
		default:
			break;
		}
	}

out:
	free_ldapbuf(ldapbuf);
	free(ldapbuf);
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
	ldapbuf_t *ldapbuf;
	int res = PWU_NOMEM;

	/*
	 * [sp]attrs is treated as NULL terminated
	 */

	ldapbuf = calloc(1, sizeof (ldapbuf_t));
	if (ldapbuf == NULL)
		return (PWU_NOMEM);

	ldapbuf->pattrs = calloc(_PWD_MAX_ATTR, sizeof (ns_ldap_attr_t *));
	if (ldapbuf->pattrs == NULL)
		goto out;
	ldapbuf->npattrs = _PWD_MAX_ATTR;

	ldapbuf->sattrs = calloc(_S_MAX_ATTR, sizeof (ns_ldap_attr_t *));
	if (ldapbuf->sattrs == NULL)
		goto out;
	ldapbuf->nsattrs = _S_MAX_ATTR;

	res = dup_pw(&ldapbuf->pwd, getpwnam_from(name, rep, REP_LDAP));
	if (res != PWU_SUCCESS)
		goto out;

	res = dup_spw(&ldapbuf->spwd, getspnam_from(name, rep, REP_LDAP));
	if (res != PWU_SUCCESS)
		goto out;
	else {
		char *spw = ldapbuf->spwd->sp_pwdp;
		if (spw != NULL && *spw != '\0') {
			ldapbuf->passwd = strdup(spw);
			if (ldapbuf->passwd == NULL)
				goto out;
		} else
			ldapbuf->passwd = NULL;
	}

	/* remember if shadow update is enabled */
	ldapbuf->shadow_update_enabled = __ns_ldap_is_shadow_update_enabled();

	*buf = (void *)ldapbuf;
	return (PWU_SUCCESS);

out:
	free_ldapbuf(ldapbuf);
	free(ldapbuf);
	return (res);
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
 * max_present(list)
 *
 * returns '1' if a ATTR_MAX with value != -1 is present. (in other words:
 * if password aging is to be turned on).
 */
static int
max_present(attrlist *list)
{
	while (list != NULL)
		if (list->type == ATTR_MAX && list->data.val_i != -1)
			return (1);
		else
			list = list->next;
	return (0);
}

/*
 * attr_addmod(attrs, idx, item, val)
 *
 * Adds or updates attribute 'item' in ldap_attrs list to value
 * update idx if item is added
 * return:  -1 - PWU_NOMEM/error, 0 - success
 */
static int
attr_addmod(ns_ldap_attr_t **attrs, int *idx, char *item, int value)
{
	char numbuf[MAX_INT_LEN], *strp;
	int i;

	/* stringize the value or abort */
	if (snprintf(numbuf, MAX_INT_LEN, "%d", value) >= MAX_INT_LEN)
		return (-1);

	/* check for existence and modify existing */
	for (i = 0; i < *idx; i++) {
		if (attrs[i] != NULL &&
		    strcmp(item, attrs[i]->attrname) == 0) {
			strp = strdup(numbuf);
			if (strp == NULL)
				return (-1);
			free(attrs[i]->attrvalue[0]);
			attrs[i]->attrvalue[0] = strp;
			return (0);
		}
	}
	/* else add */
	strp = strdup(numbuf);
	if (strp == NULL)
		return (-1);
	attrs[*idx] = new_attr(item, strp);
	if (attrs[*idx] == NULL)
		return (-1);
	(*idx)++;
	return (0);
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
	ldapbuf_t *ldapbuf = (ldapbuf_t *)buf;
	struct spwd *spw;
	ns_ldap_attr_t **pattrs = ldapbuf->pattrs;
	int pidx = 0;
	ns_ldap_attr_t **sattrs = ldapbuf->sattrs;
	int sidx = 0;
	char *pwd, *val;
	char *salt;
	size_t cryptlen;
	int len;
	int count;
	int rc = PWU_SUCCESS;
	int aging_needed = 0;
	int aging_set = 0;
	int disable_aging;

	spw = ldapbuf->spwd;

	/*
	 * if sp_max==0 and shadow update is enabled:
	 * disable passwd aging after updating the password
	 */
	disable_aging = (spw != NULL && spw->sp_max == 0 &&
	    ldapbuf->shadow_update_enabled);

	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_PASSWD:
			/*
			 * There is a special case for ldap: if the
			 * password is to be deleted (-d to passwd),
			 * p->data.val_s will be NULL.
			 */
			if (p->data.val_s == NULL) {
				if (!ldapbuf->shadow_update_enabled)
					return (PWU_CHANGE_NOT_ALLOWED);
				cryptlen =
				    sizeof ("{crypt}" NS_LDAP_NO_UNIX_PASSWORD);
				val = malloc(cryptlen);
				if (val == NULL)
					return (PWU_NOMEM);
				(void) snprintf(val, cryptlen,
				"{crypt}" NS_LDAP_NO_UNIX_PASSWORD);
			} else { /* not deleting password */
				salt = crypt_gensalt(ldapbuf->passwd,
				    ldapbuf->pwd);

				if (salt == NULL) {
					if (errno == ENOMEM)
						return (PWU_NOMEM);

					/* algorithm problem? */
					syslog(LOG_AUTH | LOG_ALERT,
					    "passwdutil: crypt_gensalt "
					    "%m");
					return (PWU_UPDATE_FAILED);
				}

				pwd = crypt(p->data.val_s, salt);
				free(salt);
				cryptlen = strlen(pwd) + sizeof ("{crypt}");
				val = malloc(cryptlen);
				if (val == NULL)
					return (PWU_NOMEM);
				(void) snprintf(val, cryptlen,
				    "{crypt}%s", pwd);
			}

			/*
			 * If not managing passwordAccount,
			 * insert the new password in the
			 * passwd attr array and break.
			 */
			if (!ldapbuf->shadow_update_enabled) {
				NEW_ATTR(pattrs, pidx,
				    _PWD_USERPASSWORD, val);
				break;
			}

			/*
			 * Managing passwordAccount, insert the
			 * new password, along with lastChange and
			 * shadowFlag, in the shadow attr array.
			 */
			NEW_ATTR(sattrs, sidx, _PWD_USERPASSWORD, val);

			if (attr_addmod(sattrs, &sidx, _S_LASTCHANGE,
			    DAY_NOW_32) < 0)
				return (PWU_NOMEM);
			spw->sp_lstchg = DAY_NOW_32;

			if (attr_addmod(sattrs, &sidx, _S_FLAG,
			    spw->sp_flag & ~FAILCOUNT_MASK) < 0)
				return (PWU_NOMEM);
			spw->sp_flag &= ~FAILCOUNT_MASK; /* reset count */
			aging_needed = 1;
			break;
		case ATTR_PASSWD_SERVER_POLICY:
			/*
			 * For server policy, don't crypt the password,
			 * send the password as is to the server and
			 * let the LDAP server do its own password
			 * encryption
			 */
			STRDUP_OR_RET(val, p->data.val_s);

			NEW_ATTR(pattrs, pidx, _PWD_USERPASSWORD, val);
			break;
		case ATTR_COMMENT:
			/* XX correct? */
			NEW_ATTR(pattrs, pidx, _PWD_DESCRIPTION, p->data.val_s);
			break;
		case ATTR_GECOS:
			if (!ldapbuf->shadow_update_enabled) {
				NEW_ATTR(pattrs, pidx, _PWD_GECOS,
				    p->data.val_s);
			} else {
				NEW_ATTR(sattrs, sidx, _PWD_GECOS,
				    p->data.val_s);
			}
			break;
		case ATTR_HOMEDIR:
			if (!ldapbuf->shadow_update_enabled) {
				NEW_ATTR(pattrs, pidx, _PWD_HOMEDIRECTORY,
				    p->data.val_s);
			} else {
				NEW_ATTR(sattrs, sidx, _PWD_HOMEDIRECTORY,
				    p->data.val_s);
			}
			break;
		case ATTR_SHELL:
			if (!ldapbuf->shadow_update_enabled) {
				NEW_ATTR(pattrs, pidx, _PWD_LOGINSHELL,
				    p->data.val_s);
			} else {
				NEW_ATTR(sattrs, sidx, _PWD_LOGINSHELL,
				    p->data.val_s);
			}
			break;
		/* We don't update NAME, UID, GID */
		case ATTR_NAME:
		case ATTR_UID:
		case ATTR_GID:
		/* Unsupported item */
		case ATTR_AGE:
			break;
		case ATTR_LOCK_ACCOUNT:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			if (spw->sp_pwdp == NULL) {
				spw->sp_pwdp = LOCKSTRING;
			} else if ((strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) != 0) &&
			    (strcmp(spw->sp_pwdp, NOLOGINSTRING) != 0)) {
				len = sizeof (LOCKSTRING)-1 +
				    strlen(spw->sp_pwdp) + 1 +
				    sizeof ("{crypt}");
				pwd = malloc(len);
				if (pwd == NULL) {
					return (PWU_NOMEM);
				}
				(void) strlcpy(pwd, "{crypt}", len);
				(void) strlcat(pwd, LOCKSTRING, len);
				(void) strlcat(pwd, spw->sp_pwdp, len);
				free(spw->sp_pwdp);
				spw->sp_pwdp = pwd;
				NEW_ATTR(sattrs, sidx, _PWD_USERPASSWORD,
				    spw->sp_pwdp);
			}
			if (attr_addmod(sattrs, &sidx, _S_LASTCHANGE,
			    DAY_NOW_32) < 0)
				return (PWU_NOMEM);
			spw->sp_lstchg = DAY_NOW_32;
			break;

		case ATTR_UNLOCK_ACCOUNT:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			if (spw->sp_pwdp &&
			    strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) == 0) {
				len = (sizeof ("{crypt}") -
				    sizeof (LOCKSTRING)) +
				    strlen(spw->sp_pwdp) + 1;
				pwd = malloc(len);
				if (pwd == NULL) {
					return (PWU_NOMEM);
				}
				(void) strlcpy(pwd, "{crypt}", len);
				(void) strlcat(pwd, spw->sp_pwdp +
				    sizeof (LOCKSTRING)-1, len);
				free(spw->sp_pwdp);
				spw->sp_pwdp = pwd;

				NEW_ATTR(sattrs, sidx, _PWD_USERPASSWORD,
				    spw->sp_pwdp);
				if (attr_addmod(sattrs, &sidx, _S_LASTCHANGE,
				    DAY_NOW_32) < 0)
					return (PWU_NOMEM);
				spw->sp_lstchg = DAY_NOW_32;
			}
			break;

		case ATTR_NOLOGIN_ACCOUNT:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			free(spw->sp_pwdp);
			STRDUP_OR_RET(spw->sp_pwdp, "{crypt}" NOLOGINSTRING);
			NEW_ATTR(sattrs, sidx, _PWD_USERPASSWORD, spw->sp_pwdp);
			if (attr_addmod(sattrs, &sidx, _S_LASTCHANGE,
			    DAY_NOW_32) < 0)
				return (PWU_NOMEM);
			spw->sp_lstchg = DAY_NOW_32;
			break;

		case ATTR_EXPIRE_PASSWORD:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			NUM_TO_STR(val, 0);
			NEW_ATTR(sattrs, sidx, _S_LASTCHANGE, val);
			break;

		case ATTR_LSTCHG:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_LASTCHANGE, val);
			break;

		case ATTR_MIN:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			if (spw->sp_max == -1 && p->data.val_i != -1 &&
			    max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_MIN, val);
			aging_set = 1;
			break;

		case ATTR_MAX:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			if (p->data.val_i == -1) {
				/* Turn off aging. Reset min and warn too */
				spw->sp_max = spw->sp_min = spw->sp_warn = -1;
				NUM_TO_STR(val, -1);
				NEW_ATTR(sattrs, sidx, _S_MIN, val);
				NUM_TO_STR(val, -1);
				NEW_ATTR(sattrs, sidx, _S_WARNING, val);
			} else {
				/* Turn account aging on */
				if (spw->sp_min == -1) {
					/*
					 * minage was not set with command-
					 * line option: set to zero
					 */
					spw->sp_min = 0;
					NUM_TO_STR(val, 0);
					NEW_ATTR(sattrs, sidx, _S_MIN,
					    val);
				}
				/*
				 * If aging was turned off, we update lstchg.
				 * We take care not to update lstchg if the
				 * user has no password, otherwise the user
				 * might not be required to provide a password
				 * the next time they log in.
				 *
				 * Also, if lstchg != -1 (i.e., not set)
				 * we keep the old value.
				 */
				if (spw->sp_max == -1 &&
				    spw->sp_pwdp != NULL && *spw->sp_pwdp &&
				    spw->sp_lstchg == -1) {
					if (attr_addmod(sattrs, &sidx,
					    _S_LASTCHANGE,
					    DAY_NOW_32) < 0)
						return (PWU_NOMEM);
					spw->sp_lstchg = DAY_NOW_32;
				}
			}
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_MAX, val);
			aging_set = 1;
			break;

		case ATTR_WARN:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			if (spw->sp_max == -1 &&
			    p->data.val_i != -1 && max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_WARNING, val);
			break;

		case ATTR_INACT:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_INACTIVE, val);
			break;

		case ATTR_EXPIRE:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_EXPIRE, val);
			break;

		case ATTR_FLAG:
			if (!ldapbuf->shadow_update_enabled)
				break;	/* not managing passwordAccount */
			NUM_TO_STR(val, p->data.val_i);
			NEW_ATTR(sattrs, sidx, _S_FLAG, val);
			break;
		case ATTR_INCR_FAILED_LOGINS:
			if (!ldapbuf->shadow_update_enabled) {
				rc = PWU_CHANGE_NOT_ALLOWED;
				break;	/* not managing passwordAccount */
			}
			count = (spw->sp_flag & FAILCOUNT_MASK) + 1;
			spw->sp_flag &= ~FAILCOUNT_MASK;
			spw->sp_flag |= min(FAILCOUNT_MASK, count);
			p->data.val_i = count;
			NUM_TO_STR(val, spw->sp_flag);
			NEW_ATTR(sattrs, sidx, _S_FLAG, val);
			break;
		case ATTR_RST_FAILED_LOGINS:
			if (!ldapbuf->shadow_update_enabled) {
				rc = PWU_CHANGE_NOT_ALLOWED;
				break;	/* not managing passwordAccount */
			}
			p->data.val_i = spw->sp_flag & FAILCOUNT_MASK;
			spw->sp_flag &= ~FAILCOUNT_MASK;
			NUM_TO_STR(val, spw->sp_flag);
			NEW_ATTR(sattrs, sidx, _S_FLAG, val);
			break;
		default:
			break;
		}
	}

	/*
	 * If the ldap client is configured with shadow update enabled,
	 * then what should the new aging values look like?
	 *
	 * There are a number of different conditions
	 *
	 *  a) aging is already configured: don't touch it
	 *
	 *  b) disable_aging is set: disable aging
	 *
	 *  c) aging is not configured: turn on default aging;
	 *
	 *  b) and c) of course only if aging_needed and !aging_set.
	 *  (i.e., password changed, and aging values not changed)
	 */

	if (ldapbuf->shadow_update_enabled && spw != NULL && spw->sp_max <= 0) {
		/* a) aging not yet configured */
		if (aging_needed && !aging_set) {
			if (disable_aging) {
				/* b) turn off aging */
				spw->sp_min = spw->sp_max = spw->sp_warn = -1;
				if (attr_addmod(sattrs, &sidx, _S_MIN, -1) < 0)
					return (PWU_NOMEM);
				if (attr_addmod(sattrs, &sidx, _S_MAX, -1) < 0)
					return (PWU_NOMEM);
				if (attr_addmod(sattrs, &sidx, _S_WARNING,
				    -1) < 0)
					return (PWU_NOMEM);
			} else {
				/* c) */
				turn_on_default_aging(spw);

				if (attr_addmod(sattrs, &sidx, _S_MIN,
				    spw->sp_min) < 0)
					return (PWU_NOMEM);
				if (attr_addmod(sattrs, &sidx, _S_MAX,
				    spw->sp_max) < 0)
					return (PWU_NOMEM);
				if (attr_addmod(sattrs, &sidx,
				    _S_WARNING, spw->sp_warn) < 0)
					return (PWU_NOMEM);
			}
		}
	}

	pattrs[pidx] = NULL;
	sattrs[sidx] = NULL;

	return (rc);
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
	const char *pwd, int *pwd_status, int flags)
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
		return (NS_LDAP_MEMORY); /* map to PWU_NOMEM */

	/* for admin shadow update, dn and pwd will be set later in libsldap */
	if ((flags & NS_LDAP_UPDATE_SHADOW) == 0) {
		/* Fill in the user name and password */
		if (dn == NULL || pwd == NULL)
			goto out;
		credp->cred.unix_cred.userID = strdup(binddn);
		credp->cred.unix_cred.passwd = strdup(pwd);
	}

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
		    credp, flags, &errorp);
		if (ldaprc == NS_LDAP_SUCCESS) {
			result = NS_LDAP_SUCCESS;
			goto out;
		}

		/*
		 * if change not allowed due to configuration, indicate so
		 * to the caller
		 */
		if (ldaprc == NS_LDAP_CONFIG &&
		    errorp->status == NS_CONFIG_NOTALLOW) {
			result = NS_LDAP_CONFIG;
			*pwd_status = NS_PASSWD_CHANGE_NOT_ALLOWED;
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
	result = NS_LDAP_OP_FAILED; /* map to PWU_DENIED */

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
 * ldap_putpwnam(name, oldpw, rep, buf)
 *
 * update the LDAP server with the attributes contained in 'buf'.
 */
/*ARGSUSED*/
int
ldap_putpwnam(char *name, char *oldpw, pwu_repository_t *rep, void *buf)
{
	int res;
	char *dn;	/* dn of user whose attributes we are changing */
	char *binddn;	/* dn of user who is performing the change */
	ns_ldap_error_t *errorp;
	ldapbuf_t *ldapbuf = (ldapbuf_t *)buf;
	ns_ldap_attr_t **pattrs = ldapbuf->pattrs;
	ns_ldap_attr_t **sattrs = ldapbuf->sattrs;
	struct passwd *pw;
	int pwd_status;
	uid_t uid;

	if (strcmp(name, "root") == 0)
		return (PWU_NOT_FOUND);

	/*
	 * convert name of user whose attributes we are changing
	 * to a distinguished name
	 */
	res = __ns_ldap_uid2dn(name, &dn, NULL, &errorp);
	if (res != NS_LDAP_SUCCESS)
		goto out;

	/* update shadow via ldap_cachemgr if it is enabled */
	if (ldapbuf->shadow_update_enabled &&
	    sattrs != NULL && sattrs[0] != NULL) {
		/*
		 * flag NS_LDAP_UPDATE_SHADOW indicates the shadow update
		 * should be done via ldap_cachemgr
		 */
		res = ldap_replaceattr(dn, sattrs, NULL, NULL, &pwd_status,
		    NS_LDAP_UPDATE_SHADOW);
		goto out;
	}

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

	if (pattrs && pattrs[0] != NULL) {
		res = ldap_replaceattr(dn, pattrs, binddn, oldpw,
		    &pwd_status, 0);
	} else
		res = NS_LDAP_OP_FAILED;

out:
	free_ldapbuf(ldapbuf);
	free(dn);

	return (ldap_to_pwu_code(res, pwd_status));
}
