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

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <nss_dbdefs.h>
#include <macros.h>
#include <syslog.h>

#include <limits.h>		/* LOGNAME_MAX -- max Solaris user name */

#include "passwdutil.h"

int files_lock(void);
int files_unlock(void);
int files_checkhistory(char *user, char *passwd, pwu_repository_t *rep);
int files_getattr(char *name, attrlist *item, pwu_repository_t *rep);
int files_getpwnam(char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);
int files_update(attrlist *items, pwu_repository_t *rep, void *buf);
int files_putpwnam(char *name, char *oldpw, pwu_repository_t *rep, void *buf);
int files_user_to_authenticate(char *name, pwu_repository_t *rep,
	char **auth_user, int *privileged);

static int files_update_history(char *name, struct spwd *spwd);

/*
 * files function pointer table, used by passwdutil_init to initialize
 * the global Repository-OPerations table "rops"
 */
struct repops files_repops = {
	files_checkhistory,
	files_getattr,
	files_getpwnam,
	files_update,
	files_putpwnam,
	files_user_to_authenticate,
	files_lock,
	files_unlock
};

/*
 * this structure defines the buffer used to keep state between
 * get/update/put calls
 */
struct pwbuf {
	int	update_history;
	struct passwd *pwd;
	char   *pwd_scratch;
	struct spwd *spwd;
	char   *spwd_scratch;
	char   *new_sp_pwdp;
};

/*
 * We should use sysconf, but there is no sysconf name for SHADOW
 * so we use these from nss_dbdefs
 */
#define	PWD_SCRATCH_SIZE NSS_LINELEN_PASSWD
#define	SPW_SCRATCH_SIZE NSS_LINELEN_SHADOW

/*
 * lock functions for files repository
 */
int
files_lock(void)
{
	int res;

	if (lckpwdf()) {
		switch (errno) {
		case EINTR:
			res = PWU_BUSY;
			break;
		case EACCES:
			res = PWU_DENIED;
			break;
		case 0:
			res = PWU_SUCCESS;
			break;
		}
	} else
		res = PWU_SUCCESS;

	return (res);
}

int
files_unlock(void)
{
	if (ulckpwdf())
		return (PWU_SYSTEM_ERROR);

	return (PWU_SUCCESS);
}

/*
 * files_privileged
 *
 * Are we a privileged user with regard to the files repository?
 */
int
files_privileged(void)
{
	return (getuid() == 0);
}

/*
 *
 * private_getpwnam_r()
 *
 * A private implementation of getpwnam_r which does *not* fall back to
 * other services possibly defined in nsswitch.conf
 *
 * behaves like getpwnam_r().
 */
struct passwd *
private_getpwnam_r(const char *name, struct passwd *result, char *buffer,
    int buflen)
{
	FILE *fp;
	int found;

	if ((fp = fopen(PASSWD, "rF")) == NULL)
		return (NULL);

	found = 0;
	while (!found && fgetpwent_r(fp, result, buffer, buflen) != NULL) {
		if (strcmp(name, result->pw_name) == 0)
			found = 1;
	}

	(void) fclose(fp);

	if (!found) {
		(void) memset(buffer, 0, buflen);
		(void) memset(result, 0, sizeof (*result));
		return (NULL);
	}

	return (result);
}

/*
 * private_getspnam_r()
 *
 * A private implementation of getspnam_r which does *not* fall back to
 * other services possibly defined in nsswitch.conf.
 *
 * Behaves like getspnam_r(). Since we use fgetspent_t(), all numeric
 * fields that are undefined in /etc/shadow will be set to -1.
 *
 */
struct spwd *
private_getspnam_r(const char *name, struct spwd *result, char *buffer,
    int buflen)
{
	FILE *fp;
	int found;

	fp = fopen(SHADOW, "rF");
	if (fp == NULL)
		return (NULL);

	found = 0;
	while (!found && fgetspent_r(fp, result, buffer, buflen) != NULL) {
		if (strcmp(name, result->sp_namp) == 0)
			found = 1;
	}

	(void) fclose(fp);

	if (!found) {
		(void) memset(buffer, 0, buflen);
		(void) memset(result, 0, sizeof (*result));
		return (NULL);
	}
	return (result);
}

/*
 * files_getpwnam(name, items, rep, buf)
 *
 */
/*ARGSUSED*/
int
files_getpwnam(char *name, attrlist *items, pwu_repository_t *rep, void **buf)
{
	attrlist *p;
	struct pwbuf *pwbuf;
	int err = PWU_SUCCESS;

	*buf = calloc(1, sizeof (struct pwbuf));
	pwbuf = (struct pwbuf *)*buf;
	if (pwbuf == NULL)
		return (PWU_NOMEM);

	/*
	 * determine which password structure (/etc/passwd or /etc/shadow)
	 * we need for the items we need to update
	 */
	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_NAME:
		case ATTR_UID:
		case ATTR_GID:
		case ATTR_AGE:
		case ATTR_COMMENT:
		case ATTR_GECOS:
		case ATTR_HOMEDIR:
		case ATTR_SHELL:
			if (pwbuf->pwd == NULL) {
				pwbuf->pwd = malloc(sizeof (struct passwd));
				if (pwbuf->pwd == NULL) {
					err = PWU_NOMEM;
					goto error;
				}
			}
			break;
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
		case ATTR_LSTCHG:
		case ATTR_MIN:
		case ATTR_MAX:
		case ATTR_WARN:
		case ATTR_INACT:
		case ATTR_EXPIRE:
		case ATTR_FLAG:
		case ATTR_LOCK_ACCOUNT:
		case ATTR_EXPIRE_PASSWORD:
		case ATTR_FAILED_LOGINS:
		case ATTR_INCR_FAILED_LOGINS:
		case ATTR_RST_FAILED_LOGINS:
		case ATTR_NOLOGIN_ACCOUNT:
		case ATTR_UNLOCK_ACCOUNT:
			if (pwbuf->spwd == NULL) {
				pwbuf->spwd = malloc(sizeof (struct spwd));
				if (pwbuf->spwd == NULL) {
					err = PWU_NOMEM;
					goto error;
				}
			}
			break;
		default:
			/*
			 * Some other repository might have different values
			 * so we ignore those.
			 */
			break;
		}
	}

	if (pwbuf->pwd) {
		if ((pwbuf->pwd_scratch = malloc(PWD_SCRATCH_SIZE)) == NULL) {
			err = PWU_NOMEM;
			goto error;
		}
		if (private_getpwnam_r(name, pwbuf->pwd, pwbuf->pwd_scratch,
		    PWD_SCRATCH_SIZE) == NULL) {
			err = PWU_NOT_FOUND;
			goto error;
		}
	}

	if (pwbuf->spwd) {
		if ((pwbuf->spwd_scratch = malloc(SPW_SCRATCH_SIZE)) == NULL) {
			err = PWU_NOMEM;
			goto error;
		}
		if (private_getspnam_r(name, pwbuf->spwd, pwbuf->spwd_scratch,
		    SPW_SCRATCH_SIZE) == NULL) {
			err = PWU_NOT_FOUND;
			goto error;
		}
	}

	return (PWU_SUCCESS);
error:
	if (pwbuf->pwd) free(pwbuf->pwd);
	if (pwbuf->pwd_scratch) free(pwbuf->pwd_scratch);
	if (pwbuf->spwd) free(pwbuf->spwd);
	if (pwbuf->spwd_scratch) free(pwbuf->spwd_scratch);
	free(pwbuf);
	*buf = NULL;

	return (err);
}

/*
 * int files_user_to_authenticate(name, rep, auth_user, privileged)
 * Determine which user needs to be authenticated. For files, the
 * possible return values are:
 * 	PWU_NOT_FOUND
 *	PWU_SUCCESS	and (auth_user == NULL || auth_user = user)
 *	PWU_DENIED
 *	PWU_NOMEM
 */
/*ARGSUSED*/
int
files_user_to_authenticate(char *user, pwu_repository_t *rep,
	char **auth_user, int *privileged)
{
	struct pwbuf *pwbuf;
	int res;
	attrlist attr_tmp[1] = { { ATTR_UID, NULL, NULL } };

	/* check to see if target user is present in files */
	res = files_getpwnam(user, &attr_tmp[0], rep, (void **)&pwbuf);
	if (res != PWU_SUCCESS)
		return (res);

	if (files_privileged()) {
		*auth_user = NULL;
		*privileged = 1;
		res = PWU_SUCCESS;
	} else {
		*privileged = 0;
		if (getuid() == pwbuf->pwd->pw_uid) {
			if ((*auth_user = strdup(user)) == NULL) {
				res = PWU_NOMEM;
			} else {
				res = PWU_SUCCESS;
			}
		} else {
			res = PWU_DENIED;
		}
	}

	if (pwbuf->pwd) free(pwbuf->pwd);
	if (pwbuf->pwd_scratch) free(pwbuf->pwd_scratch);
	if (pwbuf->spwd) free(pwbuf->spwd);
	if (pwbuf->spwd_scratch) free(pwbuf->spwd_scratch);
	free(pwbuf);

	return (res);
}

/*
 *	Password history file format:
 *		user:crypw1: ... crypwn: such that n <= MAXHISTORY
 */
#define	HISTORY		"/etc/security/passhistory"
#define	HISTEMP		"/etc/security/pwhistemp"
#define	OHISTORY	"/etc/security/opwhistory"
#define	HISTMODE	S_IRUSR	/* mode to create history file */
/*
 * XXX
 *	3*LOGNAME_MAX just in case there are long user names.
 *	Traditionally Solaris LOGNAME_MAX (_POSIX_LOGIN_NAME_MAX) is 13,
 *	but some sites often user more.
 *	If LOGNAME_MAX ever becomes reasonable (128) and actually enforced,
 *	fix up here.
 * XXX
 */
#define	MAX_LOGNAME (3 * LOGNAME_MAX)

/*
 *	files_checkhistory - check if a user's new password is in the user's
 *		old password history.
 *
 *	Entry
 *		user = username.
 *		passwd = new clear text password.
 *
 *	Exit
 *		PWU_SUCCESS, passwd found in user's old password history.
 *			The caller should only be interested and fail if
 *			PWU_SUCCESS is returned.
 *		PWU_NOT_FOUND, passwd not in user's old password history.
 *		PWU_errors, PWU_ errors from other routines.
 *
 */
int
files_checkhistory(char *user, char *passwd, pwu_repository_t *rep)
{
	attrlist attr;
	int res;

	attr.type = ATTR_HISTORY;
	attr.data.val_s = NULL;
	attr.next = NULL;

	debug("files_checkhistory(user=%s)", user);

	/*
	 * XXX
	 *	This depends on the underlying files_getattr implementation
	 *	treating user not found in backing store or no history as
	 *	an error.
	 * XXX
	 */

	if ((res = files_getattr(user, &attr, rep)) == PWU_SUCCESS) {
		char	*s;
		char	*crypt_passwd;
		int	histsize;
		char	*last = attr.data.val_s;

		if ((histsize = def_getint("HISTORY=", DEFHISTORY)) == 0) {
			debug("files_checkhistory: no history requested");
			res = PWU_NOT_FOUND;
			goto out;
		}

		debug("files_checkhistory: histsize = %d", histsize);
		if (histsize > MAXHISTORY)
			histsize = MAXHISTORY;

		debug("line to test\n\t%s", last);

		/* compare crypt_passwd to attr.data.val_s strings. */
		res = PWU_NOT_FOUND;
		while ((histsize-- > 0) &&
		    (((s = strtok_r(NULL, ":", &last)) != NULL) &&
		    (*s != '\n'))) {

			crypt_passwd = crypt(passwd, s);
			debug("files_checkhistory: user_pw=%s, history_pw=%s",
			    crypt_passwd, s);
			if (strcmp(crypt_passwd, s) == 0) {
				res = PWU_SUCCESS;
				break;
			}
		}
		debug("files_checkhistory(%s, %s) = %d", user, crypt_passwd,
		    res);
	}
out:
	if (attr.data.val_s != NULL)
		free(attr.data.val_s);

	return (res);
}

/*
 * files_getattr(name, items, rep)
 *
 * Get attributes specified in list 'items'
 */
int
files_getattr(char *name, attrlist *items, pwu_repository_t *rep)
{
	struct pwbuf *pwbuf;
	struct passwd *pw;
	struct spwd *spw;
	attrlist *w;
	int res;

	res = files_getpwnam(name, items, rep, (void **)&pwbuf);
	if (res != PWU_SUCCESS)
		return (res);

	pw = pwbuf->pwd;
	spw = pwbuf->spwd;

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
		/*
		 * Nothing special needs to be done for
		 * server policy
		 */
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
			if ((w->data.val_s = strdup("files")) == NULL)
				res = PWU_NOMEM;
			break;
		case ATTR_HISTORY: {
			FILE	*history;
			char	buf[MAX_LOGNAME + MAXHISTORY +
			    (MAXHISTORY * CRYPT_MAXCIPHERTEXTLEN)+1];
			char	*s, *s1;

			debug("files_getattr: Get password history for %s ",
			    name);

			if ((history = fopen(HISTORY, "rF")) == NULL) {
				debug("files_getattr: %s not found", HISTORY);
				res = PWU_OPEN_FAILED;
				goto getattr_exit;
			}
			res = PWU_NOT_FOUND;
			while ((s = fgets(buf, sizeof (buf), history)) !=
			    NULL) {
				s1 = strchr(s, ':');
				if (s1 != NULL) {
					*s1 = '\0';
				} else {
					res = PWU_NOT_FOUND;
					break;
				}
#ifdef	DEBUG
				debug("got history line for %s", s);
#endif	/* DEBUG */
				if (strcmp(s, name) == 0) {
					/* found user */
					if ((items->data.val_s =
					    strdup(s1+1)) == NULL)
						res = PWU_NOMEM;
					else
						res = PWU_SUCCESS;
					break;
				}
			}
			(void) fclose(history);
			break;
		}

		/* integer values */
		case ATTR_UID:
			w->data.val_i = pw->pw_uid;
			break;
		case ATTR_GID:
			w->data.val_i = pw->pw_gid;
			break;
		case ATTR_LSTCHG:
			w->data.val_i = spw->sp_lstchg;
			break;
		case ATTR_MIN:
			w->data.val_i = spw->sp_min;
			break;
		case ATTR_MAX:
			w->data.val_i = spw->sp_max;
			break;
		case ATTR_WARN:
			w->data.val_i = spw->sp_warn;
			break;
		case ATTR_INACT:
			w->data.val_i = spw->sp_inact;
			break;
		case ATTR_EXPIRE:
			w->data.val_i = spw->sp_expire;
			break;
		case ATTR_FLAG:
			w->data.val_i = spw->sp_flag;
			break;
		case ATTR_FAILED_LOGINS:
			w->data.val_i = spw->sp_flag & FAILCOUNT_MASK;
			break;
		default:
			break;
		}
	}

getattr_exit:
	if (pwbuf->pwd) free(pwbuf->pwd);
	if (pwbuf->pwd_scratch) free(pwbuf->pwd_scratch);
	if (pwbuf->spwd) free(pwbuf->spwd);
	if (pwbuf->spwd_scratch) free(pwbuf->spwd_scratch);
	free(pwbuf);

	return (res);
}

/*
 * max_present(list)
 *
 * see if attribute ATTR_MAX, with value != -1, is present in
 * attribute-list "list".
 *
 * returns 1 if present, 0 otherwise.
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
 * files_update(items, rep, buf)
 *
 * update the information in buf with the attributes specified in
 * items.
 */
/*ARGSUSED*/
int
files_update(attrlist *items, pwu_repository_t *rep, void *buf)
{
	struct pwbuf *pwbuf = (struct pwbuf *)buf;
	struct passwd *pw;
	struct spwd *spw;
	attrlist *p;
	int aging_needed = 0;
	int aging_set = 0;
	int disable_aging;
	char *pword;
	int len;

	pw = pwbuf->pwd;
	spw = pwbuf->spwd;
	pwbuf->update_history = 0;

	/*
	 * if sp_max==0 : disable passwd aging after updating the password
	 */
	disable_aging = (spw != NULL && spw->sp_max == 0);

	for (p = items; p != NULL; p = p->next) {
		switch (p->type) {
		case ATTR_NAME:
			break;	/* We are able to handle this, but... */
		case ATTR_UID:
			pw->pw_uid = (uid_t)p->data.val_i;
			break;
		case ATTR_GID:
			pw->pw_gid = (gid_t)p->data.val_i;
			break;
		case ATTR_AGE:
			pw->pw_age = p->data.val_s;
			break;
		case ATTR_COMMENT:
			pw->pw_comment = p->data.val_s;
			break;
		case ATTR_GECOS:
			pw->pw_gecos = p->data.val_s;
			break;
		case ATTR_HOMEDIR:
			pw->pw_dir = p->data.val_s;
			break;
		case ATTR_SHELL:
			pw->pw_shell = p->data.val_s;
			break;

		/*
		 * Nothing special needs to be done for
		 * server policy
		 */
		case ATTR_PASSWD:
		case ATTR_PASSWD_SERVER_POLICY:
			/*
			 * There is a special case only for files: if the
			 * password is to be deleted (-d to passwd),
			 * p->data.val_s will be NULL.
			 */
			if (p->data.val_s == NULL) {
				spw->sp_pwdp = "";
			} else {
				char *salt = NULL;
				char *hash = NULL;

				salt = crypt_gensalt(spw->sp_pwdp, pw);

				if (salt == NULL) {
					if (errno == ENOMEM)
						return (PWU_NOMEM);
					/* algorithm problem? */
					syslog(LOG_AUTH | LOG_ALERT,
					    "passwdutil: crypt_gensalt %m");
					return (PWU_UPDATE_FAILED);
				}
				hash = crypt(p->data.val_s, salt);
				free(salt);
				if (hash == NULL) {
					errno = ENOMEM;
					return (PWU_NOMEM);
				}
				pword = strdup(hash);
				if (pword == NULL) {
					errno = ENOMEM;
					return (PWU_NOMEM);
				}

				if (pwbuf->new_sp_pwdp)
					free(pwbuf->new_sp_pwdp);
				pwbuf->new_sp_pwdp = pword;
				spw->sp_pwdp = pword;
				aging_needed = 1;
				pwbuf->update_history = 1;
			}
			spw->sp_flag &= ~FAILCOUNT_MASK; /* reset count */
			spw->sp_lstchg = DAY_NOW_32;
			break;
		case ATTR_LOCK_ACCOUNT:
			if (spw->sp_pwdp == NULL) {
				spw->sp_pwdp = LOCKSTRING;
			} else if ((strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) != 0) &&
			    (strcmp(spw->sp_pwdp, NOLOGINSTRING) != 0)) {
				len = sizeof (LOCKSTRING)-1 +
				    strlen(spw->sp_pwdp) + 1;
				pword = malloc(len);
				if (pword == NULL) {
					errno = ENOMEM;
					return (PWU_NOMEM);
				}
				(void) strlcpy(pword, LOCKSTRING, len);
				(void) strlcat(pword, spw->sp_pwdp, len);
				if (pwbuf->new_sp_pwdp)
					free(pwbuf->new_sp_pwdp);
				pwbuf->new_sp_pwdp = pword;
				spw->sp_pwdp = pword;
			}
			spw->sp_lstchg = DAY_NOW_32;
			break;
		case ATTR_UNLOCK_ACCOUNT:
			if (spw->sp_pwdp != NULL &&
			    strncmp(spw->sp_pwdp, LOCKSTRING,
			    sizeof (LOCKSTRING)-1) == 0) {
				(void) strcpy(spw->sp_pwdp, spw->sp_pwdp +
				    sizeof (LOCKSTRING)-1);
			}
			spw->sp_lstchg = DAY_NOW_32;
			break;
		case ATTR_NOLOGIN_ACCOUNT:
			spw->sp_pwdp = NOLOGINSTRING;
			if (pwbuf->new_sp_pwdp) {
				free(pwbuf->new_sp_pwdp);
				pwbuf->new_sp_pwdp = NULL;
			}
			spw->sp_lstchg = DAY_NOW_32;
			break;
		case ATTR_EXPIRE_PASSWORD:
			spw->sp_lstchg = 0;
			break;
		case ATTR_LSTCHG:
			spw->sp_lstchg = p->data.val_i;
			break;
		case ATTR_MIN:
			if (spw->sp_max == -1 &&
			    p->data.val_i != -1 && max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			spw->sp_min = p->data.val_i;
			aging_set = 1;
			break;
		case ATTR_MAX:
			if (p->data.val_i == -1) {
				/* Turn aging off -> Reset min and warn too */

				spw->sp_min = -1;
				spw->sp_warn = -1;
			} else {
				/* Turn aging on */

				if (spw->sp_min == -1) {
					/*
					 * If minage has not been set with
					 * a command-line option, we set it
					 * to zero.
					 */
					spw->sp_min = 0;
				}

				/*
				 * If aging was turned off, we update lstchg.
				 *
				 * We take care not to update lstchg if the
				 * user has no password, otherwise the user
				 * might not be required to provide a password
				 * the next time they log-in.
				 *
				 * Also, if lstchg != -1 (i.e., not set in
				 * /etc/shadow), we keep the old value.
				 */
				if (spw->sp_max == -1 &&
				    spw->sp_pwdp != NULL && *spw->sp_pwdp &&
				    spw->sp_lstchg == -1) {
					spw->sp_lstchg = DAY_NOW_32;
				}
			}

			spw->sp_max = p->data.val_i;

			aging_set = 1;

			break;
		case ATTR_WARN:
			if (spw->sp_max == -1 && p->data.val_i != -1 &&
			    max_present(p->next) == 0)
				return (PWU_AGING_DISABLED);
			spw->sp_warn =  p->data.val_i;
			break;
		case ATTR_INACT:
			spw->sp_inact = p->data.val_i;
			break;
		case ATTR_EXPIRE:
			spw->sp_expire = p->data.val_i;
			break;
		case ATTR_FLAG:
			spw->sp_flag = p->data.val_i;
			break;
		case ATTR_INCR_FAILED_LOGINS:
			{
			int count = (spw->sp_flag & FAILCOUNT_MASK) + 1;
			spw->sp_flag &= ~FAILCOUNT_MASK;
			spw->sp_flag |= min(FAILCOUNT_MASK, count);
			p->data.val_i = count;
			}
			break;
		case ATTR_RST_FAILED_LOGINS:
			p->data.val_i = spw->sp_flag & FAILCOUNT_MASK;
			spw->sp_flag &= ~FAILCOUNT_MASK;
			break;
		default:
			break;
		}
	}

	/*
	 * What should the new aging values look like?
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

	if (spw != NULL && spw->sp_max <= 0) {
		/* a) aging not yet configured */
		if (aging_needed && !aging_set) {
			if (disable_aging) {
				/* b) turn off aging */
				spw->sp_min = spw->sp_max = spw->sp_warn = -1;
			} else {
				/* c) */
				turn_on_default_aging(spw);
			}
		}
	}

	return (PWU_SUCCESS);
}

/*
 * files_update_shadow(char *name, struct spwd *spwd)
 *
 * update the shadow password file SHADOW to contain the spwd structure
 * "spwd" for user "name"
 */
int
files_update_shadow(char *name, struct spwd *spwd)
{
	struct stat64 stbuf;
	FILE *dst;
	FILE *src;
	struct spwd cur;
	char buf[SPW_SCRATCH_SIZE];
	int tempfd;
	mode_t filemode;
	int result = -1;
	int err = PWU_SUCCESS;

	/* Mode of the shadow file should be 400 or 000 */
	if (stat64(SHADOW, &stbuf) < 0) {
		err = PWU_STAT_FAILED;
		goto shadow_exit;
	}

	/* copy mode from current shadow file (0400 or 0000) */
	filemode = stbuf.st_mode & S_IRUSR;

	/*
	 * we can't specify filemodes to fopen(), and we SHOULD NOT
	 * set umask in multi-thread safe libraries, so we use
	 * a combination of open() and fdopen()
	 */
	tempfd = open(SHADTEMP, O_WRONLY|O_CREAT|O_TRUNC, filemode);
	if (tempfd < 0) {
		err = PWU_OPEN_FAILED;
		goto shadow_exit;
	}
	(void) fchown(tempfd, (uid_t)0, stbuf.st_gid);

	if ((dst = fdopen(tempfd, "wF")) == NULL) {
		err = PWU_OPEN_FAILED;
		goto shadow_exit;
	}

	if ((src = fopen(SHADOW, "rF")) == NULL) {
		err = PWU_OPEN_FAILED;
		(void) fclose(dst);
		(void) unlink(SHADTEMP);
		goto shadow_exit;
	}

	/*
	 * copy old shadow to temporary file while replacing the entry
	 * that matches "name".
	 */
	while (fgetspent_r(src, &cur, buf, sizeof (buf)) != NULL) {

		if (strcmp(cur.sp_namp, name) == 0)
			result = putspent(spwd, dst);
		else
			result = putspent(&cur, dst);

		if (result != 0) {
			err = PWU_WRITE_FAILED;
			(void) fclose(src);
			(void) fclose(dst);
			goto shadow_exit;
		}
	}

	(void) fclose(src);

	if (fclose(dst) != 0) {
		/*
		 * Something went wrong (ENOSPC for example). Don't
		 * use the resulting temporary file!
		 */
		err = PWU_CLOSE_FAILED;
		(void) unlink(SHADTEMP);
		goto shadow_exit;
	}

	/*
	 * Rename stmp to shadow:
	 *   1. make sure /etc/oshadow is gone
	 *   2. ln /etc/shadow /etc/oshadow
	 *   3. mv /etc/stmp /etc/shadow
	 */
	if (unlink(OSHADOW) && access(OSHADOW, 0) == 0) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(SHADTEMP);
		goto shadow_exit;
	}

	if (link(SHADOW, OSHADOW) == -1) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(SHADTEMP);
		goto shadow_exit;
	}

	if (rename(SHADTEMP, SHADOW) == -1) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(SHADTEMP);
		goto shadow_exit;
	}
	(void) unlink(OSHADOW);

shadow_exit:
	return (err);
}

int
files_update_passwd(char *name, struct passwd *pwd)
{
	struct stat64 stbuf;
	FILE *src, *dst;
	int tempfd;
	struct passwd cur;
	char buf[PWD_SCRATCH_SIZE];
	int result;
	int err = PWU_SUCCESS;

	if (stat64(PASSWD, &stbuf) < 0) {
		err = PWU_STAT_FAILED;
		goto passwd_exit;
	}

	/* see files_update_shadow() for open()+fdopen() rationale */

	if ((tempfd = open(PASSTEMP, O_WRONLY|O_CREAT|O_TRUNC, 0600)) < 0) {
		err = PWU_OPEN_FAILED;
		goto passwd_exit;
	}
	if ((dst = fdopen(tempfd, "wF")) == NULL) {
		err = PWU_OPEN_FAILED;
		goto passwd_exit;
	}
	if ((src = fopen(PASSWD, "rF")) == NULL) {
		err = PWU_OPEN_FAILED;
		(void) fclose(dst);
		(void) unlink(PASSTEMP);
		goto passwd_exit;
	}

	/*
	 * copy old password entries to temporary file while replacing
	 * the entry that matches "name"
	 */
	while (fgetpwent_r(src, &cur, buf, sizeof (buf)) != NULL) {
		if (strcmp(cur.pw_name, name) == 0)
			result = putpwent(pwd, dst);
		else
			result = putpwent(&cur, dst);
		if (result != 0) {
			err = PWU_WRITE_FAILED;
			(void) fclose(src);
			(void) fclose(dst);
			goto passwd_exit;
		}
	}

	(void) fclose(src);
	if (fclose(dst) != 0) {
		err = PWU_CLOSE_FAILED;
		goto passwd_exit; /* Don't trust the temporary file */
	}

	/* Rename temp to passwd */
	if (unlink(OPASSWD) && access(OPASSWD, 0) == 0) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(PASSTEMP);
		goto passwd_exit;
	}

	if (link(PASSWD, OPASSWD) == -1) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(PASSTEMP);
		goto passwd_exit;
	}

	if (rename(PASSTEMP, PASSWD) == -1) {
		err = PWU_UPDATE_FAILED;
		(void) unlink(PASSTEMP);
		goto passwd_exit;
	}

	(void) chmod(PASSWD, 0644);

passwd_exit:
	return (err);

}

/*
 * files_putpwnam(name, oldpw, rep, buf)
 *
 * store the password attributes contained in "buf" in /etc/passwd and
 * /etc/shadow.
 */
/*ARGSUSED*/
int
files_putpwnam(char *name, char *oldpw, pwu_repository_t *rep, void *buf)
{
	struct pwbuf *pwbuf = (struct pwbuf *)buf;
	int result = PWU_SUCCESS;

	if (pwbuf->pwd) {
		result = files_update_passwd(name, pwbuf->pwd);
	}

	if (result == PWU_SUCCESS && pwbuf->spwd) {
		if (pwbuf->update_history != 0) {
			debug("update_history = %d", pwbuf->update_history);
			result = files_update_history(name, pwbuf->spwd);
		} else {
			debug("no password change");
		}
		if (result == PWU_SUCCESS) {
			result = files_update_shadow(name, pwbuf->spwd);
		}
	}

	if (pwbuf->pwd) {
		(void) memset(pwbuf->pwd, 0, sizeof (struct passwd));
		(void) memset(pwbuf->pwd_scratch, 0, PWD_SCRATCH_SIZE);
		free(pwbuf->pwd);
		free(pwbuf->pwd_scratch);
	}
	if (pwbuf->spwd) {
		(void) memset(pwbuf->spwd, 0, sizeof (struct spwd));
		(void) memset(pwbuf->spwd_scratch, 0, SPW_SCRATCH_SIZE);
		free(pwbuf->spwd);
		free(pwbuf->spwd_scratch);
	}
	if (pwbuf->new_sp_pwdp) {
		free(pwbuf->new_sp_pwdp);
	}

	return (result);
}

/*
 *	NOTE:  This is all covered under the repository lock held for updating
 *	passwd(4) and shadow(4).
 */
int
files_update_history(char *name, struct spwd *spwd)
{
	int	histsize;
	int	tmpfd;
	FILE	*src;	/* history database file */
	FILE	*dst;	/* temp history database being updated */
	struct	stat64 statbuf;
	char buf[MAX_LOGNAME + MAXHISTORY +
	    (MAXHISTORY * CRYPT_MAXCIPHERTEXTLEN)+1];
	int	found;

	if ((histsize = def_getint("HISTORY=", DEFHISTORY)) == 0) {
		debug("files_update_history(%s) no history, unlinking", name);
		(void) unlink(HISTORY);
		return (PWU_SUCCESS);	/* no history update defined */
	}
	debug("files_update_history(%s, %s) histsize = %d", name, spwd->sp_pwdp,
	    histsize);

	if (histsize > MAXHISTORY)
		histsize = MAXHISTORY;
	if ((tmpfd = open(HISTEMP, O_WRONLY|O_CREAT|O_TRUNC, HISTMODE)) < 0) {
		return (PWU_OPEN_FAILED);
	}
	(void) fchown(tmpfd, (uid_t)0, (gid_t)0);

	/* get ready to copy */
	if (((src = fopen(HISTORY, "rF")) == NULL) &&
	    (errno != ENOENT)) {
		(void) unlink(HISTEMP);
		return (PWU_OPEN_FAILED);
	}
	if ((dst = fdopen(tmpfd, "wF")) == NULL) {
		(void) fclose(src);
		(void) unlink(HISTEMP);
		return (PWU_OPEN_FAILED);
	}

	/* Copy and update if found.  Add if not found. */

	found = 0;

	while ((src != NULL) &&
	    (fgets(buf, sizeof (buf), src) != NULL)) {
		char	*user;
		char	*last;

		/* get username field */
		user = strtok_r(buf, ":", &last);

#ifdef	DEBUG
		debug("files_update_history: read=\"%s\"", user);
#endif	/* DEBUG */

		if (strcmp(user, name) == 0) {
			char	*crypt;
			int	i;

			/* found user, update */
			found++;
			(void) fprintf(dst, "%s:%s:", name, spwd->sp_pwdp);
			debug("files_update_history: update user\n"
			    "\t%s:%s:", name, spwd->sp_pwdp);

			/* get old crypted password history */
			for (i = 0; i < MAXHISTORY-1; i++) {
				crypt = strtok_r(NULL, ":", &last);
				if (crypt == NULL ||
				    *crypt == '\n') {
					break;
				}
				(void) fprintf(dst, "%s:", crypt);
				debug("\t%d = %s:", i+1, crypt);
			}
			(void) fprintf(dst, "\n");
		} else {

			/* copy other users to updated file */
			(void) fprintf(dst, "%s:%s", user, last);
#ifdef	DEBUG
			debug("files_update_history: copy line %s",
			    user);
#endif	/* DEBUG */
		}
	}

	if (found == 0) {

		/* user not found, add to history file */
		(void) fprintf(dst, "%s:%s:\n", name, spwd->sp_pwdp);
		debug("files_update_history: add line\n"
		    "\t%s:%s:", name, spwd->sp_pwdp);
	}

	(void) fclose(src);

	/* If something messed up in file system, loose the update */
	if (fclose(dst) != 0) {

		debug("files_update_history: update file close failed %d",
		    errno);
		(void) unlink(HISTEMP);
		return (PWU_CLOSE_FAILED);
	}

	/*
	 * rename history to ohistory,
	 * rename tmp to history,
	 * unlink ohistory.
	 */

	(void) unlink(OHISTORY);

	if (stat64(OHISTORY, &statbuf) == 0 ||
	    ((src != NULL) && (link(HISTORY, OHISTORY) != 0)) ||
	    rename(HISTEMP, HISTORY) != 0) {

		/* old history won't go away, loose the update */
		debug("files_update_history: update file rename failed %d",
		    errno);
		(void) unlink(HISTEMP);
		return (PWU_UPDATE_FAILED);
	}

	(void) unlink(OHISTORY);
	return (PWU_SUCCESS);
}
