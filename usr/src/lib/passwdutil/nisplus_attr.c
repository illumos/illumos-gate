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
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <shadow.h>
#include <syslog.h>
#include <rpc/types.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nispasswd.h>
#include <limits.h>
#include <nss_dbdefs.h>

#include <rpcsvc/nis_dhext.h>

#include "passwdutil.h"
#include "utils.h"
#include "npd_clnt.h"

/*
 * nis+ definition
 */
#define	PKTABLE		"cred.org_dir"
#define	PKTABLELEN	12
#define	PASSTABLE	"passwd.org_dir"
#define	PASSTABLELEN	14
#define	PKMAP		"publickey.byname"

/*
 * NIS+ columns
 */
#define	COL_NAME	0
#define	COL_PASSWD	1
#define	COL_UID		2
#define	COL_GID		3
#define	COL_GECOS	4
#define	COL_HOMEDIR	5
#define	COL_SHELL	6
#define	COL_SHADOW 	7

/*
 * undocumented NIS+ interface
 */
extern bool_t	__nis_isadmin(char *, char *, char *);


int nisplus_getattr(char *name, attrlist *item, pwu_repository_t *rep);
int nisplus_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);
int nisplus_update(attrlist *items, pwu_repository_t *rep, void *buf);
int nisplus_putpwnam(char *name, char *oldpw, char *oldrpcpw,
	pwu_repository_t *rep, void *buf);
int nisplus_user_to_authenticate(char *user, pwu_repository_t *rep,
	char **auth_user, int *privileged);

/*
 * nisplus function pointer table, used by passwdutil_init to initialize
 * the global Repository-OPerations table "rops"
 */
struct repops nisplus_repops = {
	NULL,	/* checkhistory */
	nisplus_getattr,
	nisplus_getpwnam,
	nisplus_update,
	nisplus_putpwnam,
	nisplus_user_to_authenticate,
	NULL,	/* lock */
	NULL	/* unlock */
};

#define	PWU_NO_PROTO	0
#define	PWU_OLD_PROTO	1
#define	PWU_NEW_PROTO	2

/*
 * This structure is used to keep state between get/update/put calls
 */
struct statebuf {
	struct passwd *pwd;
	struct spwd *spwd;
	char *domain;
	int proto;		/* which protocol to use for the update */
	int col_flags[8];	/* keep track of which NIS+ columns changed */
	int hash_pword;		/* password is plaintext, hash before storing */
};

/*
 * These messages match the nispasswd_code values in <rpcsvc/nispasswd.h>
 */
char *npd_errmsg[] = {
	"Password update daemon is not running with NIS+ master server",
	"User has no NIS+ password entry",
	"NIS+ identifier invalid",
	"User has no NIS+ password entry",
	"No shadow password information",
	"Shadow information corrupt",
	"NIS+ password has not aged enough",
	"Couldn't generate a common DES key",
	"Invalid verifier",
	"NIS+ password invalid",
	"NIS+ server failed to encrypt verifier",
	"NIS+ server failed to decrypt password",
	"NIS+ keys updated",
	"NIS+ server could not re-encrypt key",
	"Permission denied",
	"NIS+ server not responding",
	"NIS+ error",
	"NIS+ system error",
	"NIS+ buffer too small",
	"Invalid arguments"
};

int nisplus_get_cred(uid_t uid, char *domain, nis_result **cred_res);
int extract_sec_keyinfo(nis_object *cred_entry, char **seckey,
	char **authtype, keylen_t *keylen, algtype_t *algtype);

char *reencrypt_secret(char *oldsec, char *oldpass, char *newpass,
	uid_t uid, keylen_t keylen, algtype_t algtype);
int nisplus_old_proto(char *name, char *oldpw, char *oldrpcpw,
	pwu_repository_t *rep, void *buf);

/*
 * nisplus_handle(name, domain, access_type)
 *
 * Create a handle used to talk to the NIS+ server
 *
 * 'access_type' flag is used to check whether we are doing a lookup or
 * an update. If it's update, we will use MASTER_ONLY flag in the
 * call to nis_list(). If it's lookup, it's okay to go and search
 * in replica's database when master is down.
 *
 */
nis_result *
nisplus_handle(char *name, char *domain, int access_type)
{
	char buf[NIS_MAXNAMELEN+1];
	nis_result *handle;

	if ((strlen(name) + strlen(domain) + PASSTABLELEN + 9) >
	    (size_t)NIS_MAXNAMELEN)
		return (NULL);

	(void) snprintf(buf, sizeof (buf), "[name=%s],%s.%s", name, PASSTABLE,
	    domain);
	if (buf[strlen(buf) - 1] != '.')
		(void) strcat(buf, ".");

	if (access_type == NISPLUS_LOOKUP)
		handle = nis_list(buf,
		    USE_DGRAM+FOLLOW_LINKS+FOLLOW_PATH, NULL, NULL);
	else
		handle = nis_list(buf,
		    USE_DGRAM+FOLLOW_LINKS+FOLLOW_PATH+MASTER_ONLY, NULL, NULL);

	if (handle->status != NIS_SUCCESS)
		return (NULL);

	return (handle);
}

/*
 * determine the name of the domain this user's account resides in.
 */
nis_name
get_pwd_domain(char *user, char *domain)
{
	nis_result *handle;
	nis_name pwd_domain;

	handle = nisplus_handle(user, domain, NISPLUS_LOOKUP);
	if (handle == NULL)
		return (nis_local_directory());

	pwd_domain = NIS_RES_OBJECT(handle)->zo_domain;

	if (strcmp(nis_leaf_of(pwd_domain), "org_dir") == 0)
		pwd_domain = nis_domain_of(pwd_domain);

	return (pwd_domain);
}

int
nisplus_privileged(char *user, char *domain)
{
	nis_name local_principal;
	uid_t old_euid;

	/*
	 * In contrast to what we'd like, we really need to set the effective
	 * UID here, in order for nis_local_principal() to return an answer
	 * based on *who* we are instead of *what privileges* we have.
	 *
	 * This makes this module thread-unsafe!
	 */
	old_euid = seteuid(getuid());
	local_principal = nis_local_principal();
	(void) seteuid(old_euid);

	return (__nis_isadmin(local_principal, "passwd",
	    get_pwd_domain(user, domain)));
}


/*
 * nisplus_user_to_authenticate(user, rep, auth_user, privileged)
 */
int
nisplus_user_to_authenticate(char *user, pwu_repository_t *rep,
    char **auth_user, int *privileged)
{
	int res;
	struct statebuf *buf = NULL;

	/*
	 * special case: don't bother to get root from NIS+
	 */
	if (strcmp(user, "root") == 0)
		return (PWU_NOT_FOUND);

	res = nisplus_getpwnam(user, NULL, rep, (void **)&buf);
	if (res != PWU_SUCCESS)
		return (res);

	res = PWU_SUCCESS;

	if (nisplus_privileged(user, buf->domain) == 0) {
		*privileged = 0;
		if ((*auth_user = strdup(user)) == NULL)
			res = PWU_NOMEM;
		goto out;
	} else {
		uid_t uid = getuid();
		char pwd_buf[NSS_BUFLEN_PASSWD];
		struct passwd pwr;

		*privileged = 1;

		if (getpwuid_r(uid, &pwr, pwd_buf, sizeof (pwd_buf)) == NULL) {
#define	MAX_UID_LEN 11	/* UID's larger than 2^32 won't fit */
			if ((*auth_user = malloc(MAX_UID_LEN)) == NULL) {
				res = PWU_NOMEM;
				goto out;
			}
			(void) snprintf(*auth_user, MAX_UID_LEN, "%d",
			    (int)uid);
		} else {
			if ((*auth_user = strdup(pwr.pw_name)) == NULL)
				res = PWU_NOMEM;
		}
	}

out:
	if (buf->pwd)
		free_pwd(buf->pwd);
	if (buf->spwd)
		free_spwd(buf->spwd);
	if (buf)
		free(buf);

	return (res);
}

/*
 * nisplus_getattr(name, items, rep)
 *
 * retrieve attributes specified in "items"
 */
int
nisplus_getattr(char *name, attrlist *items, pwu_repository_t *rep)
{
	attrlist *p;
	int res;
	struct statebuf *buf = NULL;

	res = nisplus_getpwnam(name, items, rep, (void **)&buf);
	if (res != PWU_SUCCESS)
		return (res);

	for (p = items; res == PWU_SUCCESS && p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_NAME:
			if ((p->data.val_s = strdup(buf->pwd->pw_name)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_GECOS:
			p->data.val_s = strdup(buf->pwd->pw_gecos);
			if (p->data.val_s == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_HOMEDIR:
			if ((p->data.val_s = strdup(buf->pwd->pw_dir)) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_SHELL:
			p->data.val_s = strdup(buf->pwd->pw_shell);
			if (p->data.val_s == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			p->data.val_s = strdup(buf->spwd->sp_pwdp);
			if (p->data.val_s == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_REP_NAME:
			if ((p->data.val_s = strdup("nisplus")) == NULL)
				res = PWU_NOMEM;
			break;

		case ATTR_UID:
			p->data.val_i = buf->pwd->pw_uid;
			break;
		case ATTR_GID:
			p->data.val_i = buf->pwd->pw_gid;
			break;
		case ATTR_LSTCHG:
			p->data.val_i = buf->spwd->sp_lstchg;
			break;
		case ATTR_MIN:
			p->data.val_i = buf->spwd->sp_min;
			break;
		case ATTR_MAX:
			p->data.val_i = buf->spwd->sp_max;
			break;
		case ATTR_WARN:
			p->data.val_i = buf->spwd->sp_warn;
			break;
		case ATTR_INACT:
			p->data.val_i = buf->spwd->sp_inact;
			break;
		case ATTR_EXPIRE:
			p->data.val_i = buf->spwd->sp_expire;
			break;
		case ATTR_FLAG:
			p->data.val_i = buf->spwd->sp_flag;
			break;
		default:
			break;
		}
	}

out:
	if (buf->pwd)
		free_pwd(buf->pwd);
	if (buf->spwd)
		free_spwd(buf->spwd);
	if (buf)
		free(buf);

	return (res);
}

/*
 * nisplus_getpwnam(name, items, rep, buf)
 *
 * Get all account info on user "name".
 */
/*ARGSUSED*/
int
nisplus_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf)
{
	struct statebuf *statebuf;
	int res;

	statebuf = (struct statebuf *)calloc(1, sizeof (struct statebuf));
	if (statebuf == NULL)
		return (PWU_NOMEM);

	res = dup_pw(&statebuf->pwd, getpwnam_from(name, rep, REP_NISPLUS));
	if (res != PWU_SUCCESS) {
		if (statebuf->pwd)
			free_pwd(statebuf->pwd);
		free(statebuf);
		return (res);
	}

	res = dup_spw(&statebuf->spwd, getspnam_from(name, rep, REP_NISPLUS));
	if (res != PWU_SUCCESS) {
		if (statebuf->pwd)
			free_pwd(statebuf->pwd);
		if (statebuf->spwd)
			free_spwd(statebuf->spwd);
		free(statebuf);
		return (res);
	}

	*buf = (void *)statebuf;

	if (rep && rep->scope)
		statebuf->domain = strdup(rep->scope);
	else
		statebuf->domain =
		    strdup(get_pwd_domain(name, nis_local_directory()));

	/*
	 * The protocol to use will be determined in nisplus_update()
	 */
	statebuf->proto = PWU_NO_PROTO;
	statebuf->hash_pword = 0;

	return (PWU_SUCCESS);
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
 * nisplus_update(items, rep, buf)
 *
 * Update the information in "buf" to reflect the attributes specified
 * in items
 */
/*ARGSUSED*/
int
nisplus_update(attrlist *items, pwu_repository_t *rep, void *buf)
{
	attrlist *p;
	struct statebuf *statebuf;
	struct passwd *pw;
	struct spwd *spw;
	char *pword;
	int len;
	char newpw[_PASS_MAX+1];

	statebuf = (struct statebuf *)buf;
	pw = statebuf->pwd;
	spw = statebuf->spwd;

	/*
	 * There are two different protocols that can be used to
	 * update the NIS+ server. The "new" protocol can be used
	 * for "passwd", "gecos" and "shell" info. All other info
	 * needs to be changed using the "old" protocol.
	 *
	 * Since nisplus_putpwnam() does not know what attributes
	 * have been changed, we keep track of which protocol to use
	 * in here.
	 */

	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		/*
		 * We don't update NAME, UID, GID
		 */
		case ATTR_NAME:
		case ATTR_UID:
		case ATTR_GID:
			break;
		/*
		 * AGE and COMMENT are not supported by NIS+
		 */
		case ATTR_AGE:
		case ATTR_COMMENT:
			break;

		/*
		 * Nothing special needs to be done for
		 * server policy
		 */
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			if (spw->sp_pwdp)
				free(spw->sp_pwdp);
			/*
			 * Note that we don't encrypt the new password.
			 * This encryption is done by the NPD client
			 * routines
			 */
			if (strlen(p->data.val_s) > __NPD2_MAXPASSBYTES)
				return (PWU_DENIED);

			(void) strlcpy(newpw, p->data.val_s, sizeof (newpw));
			if ((spw->sp_pwdp = strdup(newpw)) == NULL)
				return (PWU_NOMEM);
			statebuf->proto |= PWU_NEW_PROTO;
			statebuf->hash_pword = 1;
			/*
			 * We don't set col_flags since we use the new
			 * protocol to update the password
			 */

			/*
			 * In case we need to fall-back on the old protocol,
			 * we set the age fields here. Normally the NPD
			 * will update this field for us, but using the old
			 * update protocol, we need to do it ourselves.
			 */
			if (spw->sp_max == 0) {
				/* Forced password change. Disable aging */
				spw->sp_max = -1;
				spw->sp_min = -1;
			}
			spw->sp_lstchg = DAY_NOW_32;
			statebuf->col_flags[COL_PASSWD] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_LOCK_ACCOUNT:
			if (spw->sp_pwdp == NULL) {
				spw->sp_pwdp = LOCKSTRING;
				spw->sp_lstchg = DAY_NOW_32;
				statebuf->proto |= PWU_OLD_PROTO;
				statebuf->hash_pword = 0;
				statebuf->col_flags[COL_PASSWD] =
				    EN_CRYPT|EN_MODIFIED;
				statebuf->col_flags[COL_SHADOW] =
				    EN_CRYPT|EN_MODIFIED;
			} else if ((strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) != 0) &&
			    (strcmp(spw->sp_pwdp, NOLOGINSTRING) != 0)) {
				len = sizeof (LOCKSTRING)-1 +
				    strlen(spw->sp_pwdp) + 1;
				pword = malloc(len);
				if (pword == NULL) {
					return (PWU_NOMEM);
				}
				(void) strlcpy(pword, LOCKSTRING, len);
				(void) strlcat(pword, spw->sp_pwdp, len);
				free(spw->sp_pwdp);
				spw->sp_pwdp = pword;
				spw->sp_lstchg = DAY_NOW_32;
				statebuf->proto |= PWU_OLD_PROTO;
				statebuf->hash_pword = 0;
				statebuf->col_flags[COL_PASSWD] =
				    EN_CRYPT|EN_MODIFIED;
				statebuf->col_flags[COL_SHADOW] =
				    EN_CRYPT|EN_MODIFIED;
			}
			break;

		case ATTR_UNLOCK_ACCOUNT:
			if (spw->sp_pwdp &&
			    strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) == 0) {
				(void) strcpy(spw->sp_pwdp,
				    spw->sp_pwdp + sizeof (LOCKSTRING)-1);
				spw->sp_lstchg = DAY_NOW_32;
				statebuf->proto |= PWU_OLD_PROTO;
				statebuf->hash_pword = 0;
				statebuf->col_flags[COL_PASSWD] =
				    EN_CRYPT|EN_MODIFIED;
				statebuf->col_flags[COL_SHADOW] =
				    EN_CRYPT|EN_MODIFIED;
			}
			break;

		case ATTR_NOLOGIN_ACCOUNT:
			if (spw->sp_pwdp) {
				free(spw->sp_pwdp);
			}
			if ((spw->sp_pwdp = strdup(NOLOGINSTRING)) == NULL) {
				return (PWU_NOMEM);
			}
			spw->sp_lstchg = DAY_NOW_32;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->hash_pword = 0;
			statebuf->col_flags[COL_PASSWD] =
			    EN_CRYPT|EN_MODIFIED;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_EXPIRE_PASSWORD:
			spw->sp_lstchg = 0;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;
		case ATTR_GECOS:
			if (pw->pw_gecos)
				free(pw->pw_gecos);
			if ((pw->pw_gecos = strdup(p->data.val_s)) == NULL)
				return (PWU_NOMEM);
			statebuf->proto |= PWU_NEW_PROTO;
			statebuf->col_flags[COL_GECOS] = EN_MODIFIED;
			break;

		case ATTR_HOMEDIR:
			if (pw->pw_dir)
				free(pw->pw_dir);
			if ((pw->pw_dir = strdup(p->data.val_s)) == NULL)
				return (PWU_NOMEM);
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_HOMEDIR] = EN_MODIFIED;
			break;

		case ATTR_SHELL:
			if (pw->pw_shell)
				free(pw->pw_shell);
			if ((pw->pw_shell = strdup(p->data.val_s)) == NULL)
				return (PWU_NOMEM);
			statebuf->proto |= PWU_NEW_PROTO;
			statebuf->col_flags[COL_SHELL] = EN_MODIFIED;
			break;

		case ATTR_LSTCHG:
			spw->sp_lstchg = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_MIN:
			if (spw->sp_max == -1 && p->data.val_i != -1 &&
			    max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			spw->sp_min = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_MAX:
			if (p->data.val_i == -1) {
				/* Turn off aging. Reset min and warn too */
				spw->sp_max = spw->sp_min = spw->sp_warn = -1;
			} else {
				/* Turn account aging on */
				if (spw->sp_min == -1) {
					/*
					 * minage was not set with command-
					 * line option: set to zero
					 */
					spw->sp_min = 0;
				}
				/*
				 * If aging was turned off, we update lstchg.
				 * We take care not to update lstchg if the
				 * user has no password, otherwise the user
				 * Might not be required to provide a password
				 * the next time [s]he logs in.
				 */
				if (spw->sp_max == -1 &&
				    spw->sp_pwdp != NULL && *spw->sp_pwdp) {
					spw->sp_lstchg = DAY_NOW_32;
				}
			}
			spw->sp_max = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_WARN:
			if (spw->sp_max == -1 &&
			    p->data.val_i != -1 && max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			spw->sp_warn = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_INACT:
			spw->sp_inact = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_EXPIRE:
			spw->sp_expire = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		case ATTR_FLAG:
			spw->sp_flag = p->data.val_i;
			statebuf->proto |= PWU_OLD_PROTO;
			statebuf->col_flags[COL_SHADOW] =
			    EN_CRYPT|EN_MODIFIED;
			break;

		default:
			break;
		}
	}

	return (PWU_SUCCESS);
}

/*
 * nisplus_update_cred()
 *
 * Update the user's credentials. This routine is called if the
 * old password is different from the old rpc password. In that case,
 * the update though the npd will have changed the password, but not
 * the credentials.
 */
int
nisplus_update_cred(char *name, char *oldrpcpw, pwu_repository_t *rep,
	struct statebuf *buf)
{
	struct passwd *pw;
	char *domain;
	nis_result *cred_res;
	nis_result *handle;
	char short_newpw[DESCREDPASSLEN+1], *short_newpwp = NULL;

	entry_col ecol[5];
	nis_object *eobj;
	char mname[NIS_MAXNAMELEN];
	nis_result *mres;
	int reencrypt_tries = 0;
	int reencrypt_success = 0;
	int mod_entry = 0;

	int res;
	int i;
	uid_t uid;

	if (oldrpcpw == NULL) {
		return (PWU_BAD_CREDPASS);
	}

	if (rep && rep->scope)
		domain = rep->scope;
	else
		domain = get_pwd_domain(name, nis_local_directory());

	/*
	 * a privileged user won't be able to update the user's credentials
	 */
	if (nisplus_privileged(name, domain)) {
		return (PWU_NO_PRIV_CRED_UPDATE);
	}

	pw = getpwnam_from(name, rep, REP_NISPLUS);
	if (pw == NULL) {
		return (PWU_NOT_FOUND);
	}

	uid = pw->pw_uid;

	handle = nisplus_handle(name, domain, NISPLUS_UPDATE);
	if (handle == NULL)
		return (PWU_RECOVERY_ERR);

	res = nisplus_get_cred(uid, domain, &cred_res);
	if (res != PWU_SUCCESS) {
		return (PWU_SYSTEM_ERROR);
	}

	if (cred_res == NULL) {
		return (PWU_SUCCESS);
	}

	(void) strlcpy(short_newpw, buf->spwd->sp_pwdp, sizeof (short_newpw));
	short_newpwp = short_newpw;

	for (i = 0; i < cred_res->objects.objects_len; i++) {
		nis_object *cred_entry;
		char *oldcryptsecret;
		char *newcryptsecret;
		char *authtype;
		keylen_t keylen;
		algtype_t algtype;

		cred_entry = &(cred_res->objects.objects_val[i]);

		if (!extract_sec_keyinfo(cred_entry, &oldcryptsecret,
		    &authtype, &keylen, &algtype)) {
			continue;
		}
		reencrypt_tries++;

		newcryptsecret = reencrypt_secret(oldcryptsecret, oldrpcpw,
		    short_newpwp, uid, keylen, algtype);

		if (newcryptsecret == NULL) {
			continue;
		}

		reencrypt_success++;

		/* update cred at server */
		(void) memset((void *)ecol, 0, sizeof (ecol));
		ecol[4].ec_value.ec_value_val = newcryptsecret;
		ecol[4].ec_value.ec_value_len = strlen(newcryptsecret)+1;
		ecol[4].ec_flags = EN_CRYPT|EN_MODIFIED;
		eobj = nis_clone_object(cred_entry, NULL);
		if (eobj == NULL) {
			free(newcryptsecret);
			return (PWU_RECOVERY_ERR);
		}
		eobj->EN_data.en_cols.en_cols_val = ecol;
		eobj->EN_data.en_cols.en_cols_len = 5;

		if (snprintf(mname, sizeof (mname),
		    "[cname=%s.%s,auth_type=%s],cred.%s", name, domain,
		    authtype,
		    NIS_RES_OBJECT(handle)->zo_domain) > sizeof (mname)-1) {
			(void) memset(short_newpw, '\0', strlen(short_newpw));
			(void) memset(oldrpcpw, '\0', strlen(oldrpcpw));
			free(newcryptsecret);
			return (PWU_RECOVERY_ERR);
		}

		if (mname[strlen(mname) - 1] != '.' &&
		    strlcat(mname, ".", sizeof (mname)) >= sizeof (mname)) {
			free(newcryptsecret);
			return (PWU_RECOVERY_ERR);
		}

		mres = nis_modify_entry(mname, eobj, 0);
		if (mres->status == NIS_SUCCESS)
			mod_entry++;

		free(newcryptsecret);

		/* set column stuff to NULL to that we can free eobj */
		eobj->EN_data.en_cols.en_cols_val = NULL;
		eobj->EN_data.en_cols.en_cols_len = 0;
		(void) nis_destroy_object(eobj);
		(void) nis_freeresult(mres);
	}

	(void) memset(short_newpw, '\0', strlen(short_newpw));
	short_newpwp = NULL;
	(void) memset(oldrpcpw, '\0', strlen(oldrpcpw));

	if (reencrypt_tries > 0 && mod_entry == 0) {
		return (PWU_RECOVERY_ERR);
	}

	if (mod_entry < reencrypt_tries) {
		return (PWU_UPDATED_SOME_CREDS);
	}
	return (PWU_SUCCESS);
}


/*
 * nisplus_new_proto(name, oldpw, oldrpcpw, rep, buf)
 *
 * Implement NIS+ attribute updates using the NIS+ Password Daemon (NPD)
 * This routine is used to update passwd, gecos and shell attributes
 */
int
nisplus_new_proto(char *name, char *oldpw, char *oldrpcpw,
	pwu_repository_t *rep, void *buf)
{
	struct statebuf *statebuf;
	CLIENT *clnt = NULL;

	/* pointers to possibly updated fields */
	char *newpass;
	char *gecos;
	char *shell;

	/* NIS+ server key material */
	char		*srv_pubkey = NULL;
	char		*key_type = NULL;
	keylen_t	srv_keylen;
	algtype_t	srv_keyalgtype;

	/* User key material */
	uchar_t *u_pubkey = NULL;
	char *u_seckey = NULL;

	des_block deskeys[3];
	uint32_t	ident = 0;
	uint32_t	randval = 0;
	int		error = 0;
	int		retval;
	int		npd_res;
	nispasswd_error	*errlist = NULL;
	char		short_opass[DESCREDPASSLEN+1], *short_opassp = NULL;

	statebuf = (struct statebuf *)buf;

	if (npd_makeclnthandle(statebuf->domain, &clnt, &srv_pubkey,
	    &srv_keylen, &srv_keyalgtype, &key_type) == FALSE) {
		syslog(LOG_ERR,
		    "Couldn't make a client handle to NIS+ password daemon");
		retval = PWU_RECOVERY_ERR;
		goto out;
	}

	if ((u_pubkey = malloc(BITS2NIBBLES(srv_keylen) + 1)) == NULL) {
		retval = PWU_NOMEM;
		goto out;
	}

	if ((u_seckey = malloc(BITS2NIBBLES(srv_keylen) + 1)) == NULL) {
		retval = PWU_NOMEM;
		goto out;
	}

	(void) strlcpy(short_opass, oldpw, sizeof (short_opass));
	short_opassp = short_opass;

	/* Generate a key-pair for this user */
	if (__gen_dhkeys_g((char *)u_pubkey, u_seckey, srv_keylen,
	    srv_keyalgtype, short_opassp) == 0) {
		syslog(LOG_ERR, "Couldn't create a D-H key-pair "
		    "(len = %d, type = %d)", srv_keylen, srv_keyalgtype);
		retval = PWU_RECOVERY_ERR;
		goto out;
	}

	/*
	 * Get the common DES key(s) from the server's pubkey and the
	 * user's secret key
	 */
	if (__gen_common_dhkeys_g(srv_pubkey, u_seckey, srv_keylen,
	    srv_keyalgtype, deskeys,
	    AUTH_DES_KEY(srv_keylen, srv_keyalgtype) ? 1 : 3) == 0) {
		syslog(LOG_ERR, "Couldn't get a common DES key "
		    "(keylen = %d, algtype = %d)", srv_keylen, srv_keyalgtype);
		retval = PWU_RECOVERY_ERR;
		goto out;
	}

	/*
	 * Must preserve password length here since NPD decrypts the login
	 * password as part of the authentication.
	 */
	npd_res = nispasswd_auth(name, statebuf->domain, oldpw, u_pubkey,
	    key_type, srv_keylen, srv_keyalgtype, deskeys, clnt, &ident,
	    &randval, &error);

	if (npd_res == NPD_FAILED) {
		if (error >= 0 &&
		    error < sizeof (npd_errmsg) / sizeof (npd_errmsg[0]))
			syslog(LOG_ALERT, "%s", npd_errmsg[error]);
		else
			syslog(LOG_ALERT, "NIS+ fatal error: %d", error);

		if (error == NPD_INVALIDARGS) {
			retval = PWU_RECOVERY_ERR;
		} else if (error == NPD_PASSINVALID) {
			retval = PWU_DENIED;
		} else {
			syslog(LOG_ALERT, "Failover to old protocol");
			/*
			 * we need to tell the old protocol to update
			 * the password and the age fields.
			 */
			statebuf->col_flags[COL_SHADOW] = EN_CRYPT|EN_MODIFIED;
			retval = nisplus_old_proto(name, oldpw, oldrpcpw,
			    rep, buf);
		}
		goto out;
	} else if (npd_res == NPD_TRYAGAIN) {
		/*
		 * Since the the non-privileged user's password has already
		 * been verified, we only get here if the privileged user
		 * entered a wrong NIS+ administrator password.
		 * The origional passwd requested administrator
		 * password again. We bail-out instead.
		 */
		retval = PWU_RECOVERY_ERR;
		goto out;
	}

	if (statebuf->col_flags[COL_PASSWD] & EN_MODIFIED)
		newpass = statebuf->spwd->sp_pwdp;
	else
		newpass = oldpw;	/* we're updating attributes */

	if (statebuf->col_flags[COL_GECOS] & EN_MODIFIED)
		gecos = statebuf->pwd->pw_gecos;
	else
		gecos = NULL;
	if (statebuf->col_flags[COL_SHELL] & EN_MODIFIED)
		shell = statebuf->pwd->pw_shell;
	else
		shell = NULL;

	npd_res = nispasswd_pass(clnt, ident, randval, &deskeys[0],
	    newpass, gecos, shell, &error, &errlist);

	if (npd_res == NPD_FAILED) {
		retval = PWU_RECOVERY_ERR;
	} else if (npd_res == NPD_PARTIALSUCCESS) {
		if (statebuf->col_flags[COL_PASSWD] & EN_MODIFIED) {
			/*
			 * This can only indicate that the server
			 * failed to update the credentials (SECRETKEY).
			 * We therefore try to update the credentials directly.
			 */
			retval = nisplus_update_cred(name,
			    oldrpcpw ? oldrpcpw : short_opassp, rep, buf);
		} else {
			/* We don't update creds for gecos/shell updates */
			retval = PWU_SUCCESS;
		}
	} else {
		retval = PWU_SUCCESS;
	}
	__npd_free_errlist(errlist);

out:
	if (u_pubkey) free(u_pubkey);
	if (u_seckey) free(u_seckey);
	if (srv_pubkey) free(srv_pubkey);
	if (key_type) free(key_type);

	if (clnt) {
		auth_destroy(clnt->cl_auth);
		clnt_destroy(clnt);
	}
	return (retval);
}

/*
 * nisplus_old_proto(name, oldpw, oldrpcpw, rep, buf)
 *
 * Update account attributes using the nis_tables(3NSL) interface
 */
int
nisplus_old_proto(char *name, char *oldpw, char *oldrpcpw,
	pwu_repository_t *rep, void *buf)
{
	entry_col ecol[8];
	struct statebuf *statebuf;
	struct passwd *pw;
	struct spwd *spw;
	int *col_flags;
	char shadow[80]; /* 80 is also used in rpc.nispasswdd/npd_svc.c */
	nis_object *eobj;
	nis_result *result;
	char key[NIS_MAXNAMELEN];
	nis_result *handle;
	int pw_changed = 0;	/* indicates whether we should update creds */
	int retval;
	char short_opass[DESCREDPASSLEN+1], *short_opassp = NULL;

	(void) strlcpy(short_opass, oldpw, sizeof (short_opass));
	short_opassp = short_opass;
	statebuf = (struct statebuf *)buf;
	pw = statebuf->pwd;
	spw = statebuf->spwd;
	col_flags = statebuf->col_flags;

	handle = nisplus_handle(name, statebuf->domain, NISPLUS_UPDATE);

	if (handle == NULL)
		return (PWU_RECOVERY_ERR);

	(void) memset(ecol, 0, sizeof (ecol));

#define	EC_VAL	ec_value.ec_value_val
#define	EC_LEN	ec_value.ec_value_len

	if (col_flags[COL_PASSWD]) {
		if (statebuf->hash_pword) {
			char *salt;
			salt = crypt_gensalt(spw->sp_pwdp, pw);

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
			ecol[COL_PASSWD].EC_VAL = crypt(spw->sp_pwdp, salt);
			free(salt);
			pw_changed = 1;
		} else {
			ecol[COL_PASSWD].EC_VAL = strdup(spw->sp_pwdp);
		}
		ecol[COL_PASSWD].EC_LEN = strlen(ecol[COL_PASSWD].EC_VAL) + 1;
		ecol[COL_PASSWD].ec_flags = col_flags[COL_PASSWD];
	}
	if (col_flags[COL_GECOS]) {
		ecol[COL_GECOS].EC_VAL = pw->pw_gecos;
		ecol[COL_GECOS].EC_LEN = strlen(pw->pw_gecos) + 1;
		ecol[COL_GECOS].ec_flags = col_flags[COL_GECOS];
	}
	if (col_flags[COL_HOMEDIR]) {
		ecol[COL_HOMEDIR].EC_VAL = pw->pw_dir;
		ecol[COL_HOMEDIR].EC_LEN = strlen(pw->pw_dir) + 1;
		ecol[COL_HOMEDIR].ec_flags = col_flags[COL_HOMEDIR];
	}
	if (col_flags[COL_SHELL]) {
		ecol[COL_SHELL].EC_VAL = pw->pw_shell;
		ecol[COL_SHELL].EC_LEN = strlen(pw->pw_shell) + 1;
		ecol[COL_SHELL].ec_flags = col_flags[COL_SHELL];
	}
	if (col_flags[COL_SHADOW]) {
		if (spw->sp_expire != -1) {
			(void) snprintf(shadow, sizeof (shadow),
			    "%d:%d:%d:%d:%d::%u",
			    spw->sp_lstchg, spw->sp_min, spw->sp_max,
			    spw->sp_warn, spw->sp_inact, spw->sp_flag);
		} else {
			(void) snprintf(shadow, sizeof (shadow),
			    "%d:%d:%d:%d:%d:%d:%u",
			    spw->sp_lstchg, spw->sp_min, spw->sp_max,
			    spw->sp_warn, spw->sp_inact, spw->sp_expire,
			    spw->sp_flag);
		}
		ecol[COL_SHADOW].EC_VAL = shadow;
		ecol[COL_SHADOW].EC_LEN = strlen(shadow) + 1;
		ecol[COL_SHADOW].ec_flags = col_flags[COL_SHADOW];
	}

	if ((eobj = nis_clone_object(NIS_RES_OBJECT(handle), NULL)) == NULL) {
		syslog(LOG_ERR, "NIS+ clone object failed");
		return (PWU_RECOVERY_ERR);
	}

	eobj->EN_data.en_cols.en_cols_val = ecol;
	eobj->EN_data.en_cols.en_cols_len = 8;

	if (snprintf(key, sizeof (key), "[name=%s],%s.%s", name,
	    NIS_RES_OBJECT(handle)->zo_name,
	    NIS_RES_OBJECT(handle)->zo_domain) >= sizeof (key) - 1) {
		syslog(LOG_ERR, "NIS+ name too long");
		retval = PWU_NOMEM;
		goto out;
	}

	if (key[strlen(key) - 1] != '.')
		(void) strcat(key, ".");

again:
	result = nis_modify_entry(key, eobj, 0);

	/*
	 * It is possible that we have permission to modify the
	 * encrypted password but not the shadow column in the
	 * NIS+ table. In this case, we should try updating only
	 * the password field and not the aging stuff (lstchg).
	 * With the current NIS+ passwd table format, this would
	 * be the case most of the times.
	 */
	if (result->status == NIS_PERMISSION &&
	    ecol[COL_SHADOW].ec_flags != 0) {
		ecol[COL_SHADOW].ec_flags = 0;
		goto again;
	} else if (result->status != NIS_SUCCESS) {
		syslog(LOG_ERR, "NIS+ password information update failed\n");
		retval = PWU_ATTR_UPDATE_ERR;
	} else {
		retval = PWU_SUCCESS;
	}
	eobj->EN_data.en_cols.en_cols_val = NULL;
	eobj->EN_data.en_cols.en_cols_len = 0;
	(void) nis_destroy_object(eobj);
	if (result)
		(void) nis_freeresult(result);
	result = NULL;
out:
	if (ecol[COL_PASSWD].EC_VAL)
		free(ecol[COL_PASSWD].EC_VAL);

	if (pw_changed == 1 && retval == PWU_SUCCESS)
		retval = nisplus_update_cred(name, oldrpcpw ? oldrpcpw
		    : short_opassp, rep, buf);

	return (retval);

#undef	EC_VAL
#undef	EC_LEN
}
/*
 * nis_putpwnam(name, oldpw, oldrpcpw, rep, buf)
 *
 * update the NIS+ server using the appropriate protocol(s) for the
 * attributes that have changed.
 */
int
nisplus_putpwnam(char *name, char *oldpw, char *oldrpcpw,
	pwu_repository_t *rep, void *buf)
{
	struct statebuf *statebuf;
	int result = PWU_SUCCESS;
	uid_t cur_euid;
	char short_rpcpw[_PASS_MAX_XPG+1];
	char *short_rpcpwptr = NULL;
	char pw[_PASS_MAX+1];
	char *pw_ptr = NULL;

	if (strcmp(name, "root") == 0)
		return (PWU_NOT_FOUND);

	if (oldpw) {
		(void) strlcpy(pw, oldpw, sizeof (pw));
		pw_ptr = pw;
	} else /* oldpw is NULL. rpc.nispasswdd non-responsive ??? */
		return (PWU_RECOVERY_ERR);

	if (oldrpcpw) {
		(void) strlcpy(short_rpcpw, oldrpcpw, sizeof (short_rpcpw));
		short_rpcpwptr = short_rpcpw;
	} else
		return (PWU_RECOVERY_ERR);

	statebuf = (struct statebuf *)buf;

	if (statebuf->proto & PWU_OLD_PROTO) {
		result = nisplus_old_proto(name, pw_ptr,
		    short_rpcpwptr, rep, buf);
	}

	if (result == PWU_SUCCESS && (statebuf->proto & PWU_NEW_PROTO)) {
		cur_euid = geteuid();
		if (getuid() != 0)
			(void) seteuid(getuid());

		result = nisplus_new_proto(name, pw_ptr,
		    short_rpcpwptr, rep, buf);
		(void) seteuid(cur_euid);
	}

	return (result);
}


/*
 * Given a cred table entry, return the secret key, auth type, key length
 * of secret key, and algorithm type of secret key.
 *
 * The type of key must be listed in the NIS+ security cf.
 *
 * Return TRUE on success and FALSE on failure.
 */
int
extract_sec_keyinfo(
	nis_object *cred_entry,
	char **seckey,
	char **authtype,
	keylen_t *keylen,
	algtype_t *algtype)
{
	char mechalias[MECH_MAXALIASNAME+1];

	if ((*authtype = ENTRY_VAL(cred_entry, 1)) == NULL) {
		syslog(LOG_ERR, "auth type field is empty for cred entry");
		return (0);
	}

	/* Don't need the "local" unix system cred. */
	if (strncmp(*authtype, "LOCAL", sizeof ("LOCAL")) == 0) {
		return (0);
	}

	if (!__nis_authtype2mechalias(*authtype, mechalias,
	    sizeof (mechalias))) {
		syslog(LOG_ERR,
		    "can't convert authtype '%s' to mechanism alias",
		    *authtype);
		return (0);
	}

	/* Make sure the mech is in the NIS+ security cf. */
	if (__nis_translate_mechanism(mechalias, keylen, algtype) < 0) {
		syslog(LOG_WARNING,
		    "can't convert mechanism alias '%s' to keylen and algtype",
		    mechalias);
		return (0);
	}

	if ((*seckey = ENTRY_VAL(cred_entry, 4)) == NULL) {
		return (0);
	}

	return (1);
}

int
nisplus_get_cred(uid_t uid, char *domain, nis_result **cred_res)
{
	char buf[NIS_MAXNAMELEN + 1];
	int namelen;
	struct nis_result *local_res;
	nis_name cred_domain;
	char *local_cname;

	*cred_res = NULL;

	namelen = snprintf(buf, sizeof (buf),
	    "[auth_name=%d,auth_type=LOCAL],%s.%s",
	    (int)uid, PKTABLE, domain);
	if (namelen >= sizeof (buf)) {
		syslog(LOG_ERR, "nisplus_get_cred: name too long");
		return (PWU_SYSTEM_ERROR);
	}
	if (buf[namelen-1] != '.')
		(void) strcat(buf, ".");

	local_res = nis_list(buf, USE_DGRAM + FOLLOW_LINKS + FOLLOW_PATH +
	    MASTER_ONLY, NULL, NULL);

	if (local_res == NULL || local_res->status != NIS_SUCCESS) {
		if (local_res)
			nis_freeresult(local_res);
		return (PWU_SUCCESS);
	}

	local_cname = ENTRY_VAL(NIS_RES_OBJECT(local_res), 0);
	if (local_cname == NULL) {
		nis_freeresult(local_res);
		return (PWU_CRED_ERROR);
	}

	cred_domain = nis_domain_of(local_cname);

	namelen = snprintf(buf, sizeof (buf),
	    "[cname=%s],%s.%s",		/* get all entries for user */
	    local_cname, PKTABLE, cred_domain);

	if (namelen >= sizeof (buf)) {
		syslog(LOG_ERR, "nisplus_get_cred: cname too long");
		*cred_res = NULL;
		nis_freeresult(local_res);
		return (PWU_SYSTEM_ERROR);
	}

	nis_freeresult(local_res);

	*cred_res = nis_list(buf, USE_DGRAM + FOLLOW_LINKS + FOLLOW_PATH +
	    MASTER_ONLY, NULL, NULL);

	return (PWU_SUCCESS);
}

int
nisplus_getnetnamebyuid(char *name, uid_t uid)
{
	if (uid == 0)
		return (host2netname(name, (char *)NULL, (char *)NULL));
	else
		return (user2netname(name, uid, (char *)NULL));
}

/*
 * oldpw was truncated in pam_dhkeys' pam_sm_chauthtok.
 */
int
nisplus_verify_rpc_passwd(char *name, char *oldpw, pwu_repository_t *rep)
{
	int res;
	int i;
	int success_cnt;
	struct passwd *pw;
	char *domain;
	nis_result *cred_res;

	if (strcmp(name, "root") == 0)
		return (PWU_SUCCESS);

	/* We need the user's uid */
	pw = getpwnam_from(name, rep, REP_NISPLUS);
	if (pw == NULL)
		return (PWU_NOT_FOUND);

	if (rep && rep->scope)
		domain = rep->scope;
	else
		domain = get_pwd_domain(name, nis_local_directory());

	if (nisplus_privileged(name, domain)) {
		/* privileged user; don't ask for old RPC password */
		return (PWU_SUCCESS);
	}

	if (oldpw == NULL)
		return (PWU_CRED_ERROR);

	res = nisplus_get_cred(pw->pw_uid, domain, &cred_res);

	if (res != PWU_SUCCESS)
		return (PWU_SYSTEM_ERROR);

	if (cred_res == NULL)
		return (PWU_CRED_ERROR);

	/*
	 * Decrypt each of the credentials found with the oldpw.
	 * count the number of succesfull decrypts.
	 */
	success_cnt = 0;

	for (i = 0; i < cred_res->objects.objects_len; i++) {
		nis_object *entry = &(cred_res->objects.objects_val[i]);
		char *auth;
		char *key;
		keylen_t keylen;
		algtype_t alg;
		char netname[MAXNETNAMELEN+1];
		char *tmpkey;

		if (!extract_sec_keyinfo(entry, &key, &auth, &keylen, &alg))
			continue;

		if (!nisplus_getnetnamebyuid(netname, pw->pw_uid)) {
			syslog(LOG_ERR, "nisplus_verify_rpc_passwd: "
			    "Can't get netname");
			continue;
		}
		if ((tmpkey = strdup(key)) == NULL)
			return (PWU_NOMEM);

		if (xdecrypt_g(tmpkey, keylen, alg, oldpw, netname, TRUE))
			success_cnt++;

		free(tmpkey);
	}

	if (success_cnt)
		return (PWU_SUCCESS);
	else
		return (PWU_BAD_CREDPASS);
}

char *
reencrypt_secret(char *oldsec, char *oldpass, char *newpass,
	uid_t uid, keylen_t keylen, algtype_t algtype)
{
	char netname[MAXNETNAMELEN+1];
	char *newsec;

	if (nisplus_getnetnamebyuid(netname, uid) == 0) {
		return (NULL);
	}

	if (!xdecrypt_g(oldsec, keylen, algtype, oldpass, netname, TRUE)) {
		syslog(LOG_INFO, "secret key decrypt failed for %s/%d-%d",
		    netname, keylen, algtype);
		return (NULL);
	}

	if (!xencrypt_g(oldsec, keylen, algtype, newpass, netname,
	    &newsec, TRUE)) {
		syslog(LOG_ERR, "secret key encrypt failed for user %s/%d-%d",
		    netname, keylen, algtype);
		return (NULL);
	}

	return (newsec);
}
