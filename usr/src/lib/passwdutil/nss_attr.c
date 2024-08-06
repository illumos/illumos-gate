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
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <nss_dbdefs.h>

#include "passwdutil.h"

/* from files_attr.c */
struct passwd *private_getpwnam_r(const char *name, struct passwd *result,
    char *buffer, int buflen);

int nss_getattr(const char *name, attrlist *item, pwu_repository_t *rep);
int nss_getpwnam(const char *name, attrlist *items, pwu_repository_t *rep,
    void **buf);

/*
 * nss function pointer table, used by passwdutil_init to initialize
 * the global Repository-OPerations table "rops"
 */
struct repops nss_repops = {
	NULL,		/* checkhistory */
	nss_getattr,
	nss_getpwnam,
	NULL,		/* update */
	NULL,		/* putpwnam */
	NULL,		/* user_to_authenticate */
	NULL,		/* lock */
	NULL		/* unlock */
};

/*
 * this structure defines the buffer used to keep state between
 * get/update/put calls
 */
struct pwbuf {
	struct passwd *pwd;
	char   *pwd_scratch;
	struct spwd *spwd;
	char   *spwd_scratch;
	char   *rep_name;
};

/*
 * We should use sysconf, but there is no sysconf name for SHADOW
 * so we use these from nss_dbdefs
 */
#define	PWD_SCRATCH_SIZE NSS_LINELEN_PASSWD
#define	SPW_SCRATCH_SIZE NSS_LINELEN_SHADOW


/*
 * nss_getpwnam(name, items, rep, buf)
 *
 */
/*ARGSUSED*/
int
nss_getpwnam(const char *name, attrlist *items, pwu_repository_t *rep,
    void **buf)
{
	attrlist *p;
	struct pwbuf *pwbuf;
	int repositories = REP_ERANGE;	/* changed if ATTR_REP_NAME is set */
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
			if (pwbuf->pwd == NULL)
				pwbuf->pwd = (struct passwd *)
				    malloc(sizeof (struct passwd));
			if (pwbuf->pwd == NULL) {
				errno = ENOMEM;
				if (pwbuf->spwd)
					free(pwbuf->spwd);
				return (PWU_NOMEM);
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
			if (pwbuf->spwd == NULL)
				pwbuf->spwd = (struct spwd *)
				    malloc(sizeof (struct spwd));
			if (pwbuf->spwd == NULL) {
				errno = ENOMEM;
				if (pwbuf->pwd)
					free(pwbuf->pwd);
				return (PWU_NOMEM);
			}
			break;
		case ATTR_REP_NAME:
			/* get the compat names (REP_COMPAT_*) */
			repositories = get_ns(rep, PWU_READ);
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
		if (getpwnam_r(name, pwbuf->pwd, pwbuf->pwd_scratch,
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
		if (getspnam_r(name, pwbuf->spwd, pwbuf->spwd_scratch,
		    SPW_SCRATCH_SIZE) == NULL) {
			err = PWU_NOT_FOUND;
			goto error;
		}
	}

	/* pwbuf->rep_name tells us where the user in fact comes from */
	if (repositories != REP_ERANGE) {
		struct passwd pwd;
		char pwd_scratch[PWD_SCRATCH_SIZE];

		/* can we find the user locally? */
		if (private_getpwnam_r(name, &pwd, pwd_scratch,
		    PWD_SCRATCH_SIZE) != NULL)
			pwbuf->rep_name = "files";
		else if (repositories & REP_COMPAT_LDAP)
			pwbuf->rep_name = "ldap";
		else if (repositories & REP_COMPAT_NIS)
			pwbuf->rep_name = "nis";
		else
			pwbuf->rep_name = "nss";
	} else
		pwbuf->rep_name = "nss";

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
 * nss_getattr(name, items, rep)
 *
 * Get attributes specified in list 'items'
 */
int
nss_getattr(const char *name, attrlist *items, pwu_repository_t *rep)
{
	struct pwbuf *pwbuf;
	struct passwd *pw;
	struct spwd *spw;
	attrlist *w;
	int res = 0;

	res = nss_getpwnam(name, items, rep, (void **)&pwbuf);
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
			if ((w->data.val_s = strdup(pwbuf->rep_name)) == NULL)
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

	if (pwbuf->pwd) free(pwbuf->pwd);
	if (pwbuf->pwd_scratch) free(pwbuf->pwd_scratch);
	if (pwbuf->spwd) free(pwbuf->spwd);
	if (pwbuf->spwd_scratch) free(pwbuf->spwd_scratch);
	free(pwbuf);

	return (res);
}
