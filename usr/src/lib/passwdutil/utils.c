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

#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <thread.h>
#include <unistd.h>
#include <stdlib.h>
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>

#include <deflt.h>

#include "passwdutil.h"

#define	PWADMIN "/etc/default/passwd"

#define	MINWEEKS	-1
#define	MAXWEEKS	-1
#define	WARNWEEKS	-1

extern repops_t files_repops, nis_repops,
	nisplus_repops, ldap_repops, nss_repops;

repops_t *rops[REP_LAST+1] = {
	NULL,
	&files_repops,
	&nis_repops,
	NULL,
	&nisplus_repops,
	NULL,
	NULL,
	NULL,
	&ldap_repops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&nss_repops,
};

void
free_pwd(struct passwd *pw)
{
	if (pw->pw_name) free(pw->pw_name);
	if (pw->pw_passwd) free(pw->pw_passwd);
	if (pw->pw_gecos) free(pw->pw_gecos);
	if (pw->pw_dir) free(pw->pw_dir);
	if (pw->pw_shell) free(pw->pw_shell);
	free(pw);
}

void
free_spwd(struct spwd *spw)
{
	if (spw->sp_namp) free(spw->sp_namp);
	if (spw->sp_pwdp) free(spw->sp_pwdp);
	free(spw);
}

int
dup_pw(struct passwd **d, struct passwd *s)
{
	if (s == NULL) {
		*d = NULL;
		return (PWU_NOT_FOUND);
	}
	if ((*d = calloc(1, sizeof (**d))) == NULL)
		return (PWU_NOMEM);

	if (s->pw_name) {
		if (((*d)->pw_name = strdup(s->pw_name)) == NULL)
			goto no_mem;
	}
	if (s->pw_passwd) {
		if (((*d)->pw_passwd = strdup(s->pw_passwd)) == NULL)
			goto no_mem;
	}
	(*d)->pw_uid = s->pw_uid;
	(*d)->pw_gid = s->pw_gid;

	if (s->pw_gecos) {
		if (((*d)->pw_gecos = strdup(s->pw_gecos)) == NULL)
			goto no_mem;
	}
	if (s->pw_dir) {
		if (((*d)->pw_dir = strdup(s->pw_dir)) == NULL)
			goto no_mem;
	}
	if (s->pw_shell) {
		if (((*d)->pw_shell = strdup(s->pw_shell)) == NULL)
			goto no_mem;
	}

	return (PWU_SUCCESS);

no_mem:
	free_pwd(*d);
	*d = NULL;
	return (PWU_NOMEM);
}

int
dup_spw(struct spwd **d, struct spwd *s)
{
	if (s == NULL) {
		*d = NULL;
		return (PWU_NOT_FOUND);
	}
	if ((*d = calloc(1, sizeof (**d))) == NULL)
		return (PWU_NOMEM);

	**d = *s;

	if (s->sp_namp)
		if (((*d)->sp_namp = strdup(s->sp_namp)) == NULL)
			goto no_mem;
	if (s->sp_pwdp)
		if (((*d)->sp_pwdp = strdup(s->sp_pwdp)) == NULL)
			goto no_mem;
	return (PWU_SUCCESS);

no_mem:
	free_spwd(*d);
	return (PWU_NOMEM);
}

/*
 * read a value from the defaults file, and return it if it is
 * a positive integer. If the value is not defined, or negative,
 * return the supplied default value
 */
int
def_getuint(char *name, int defvalue, void *defp)
{
	char *p;
	int val = -1;	/* -1 is a guard to catch undefined values */

	if ((p = defread_r(name, defp)) != NULL)
		val = atoi(p);

	return (val >= 0 ? val : defvalue);
}

void
turn_on_default_aging(struct spwd *spw)
{
	int minweeks;
	int maxweeks;
	int warnweeks;
	void	*defp;

	if ((defp = defopen_r(PWADMIN)) == NULL) {
		minweeks = MINWEEKS;
		maxweeks = MAXWEEKS;
		warnweeks = WARNWEEKS;
	} else {
		minweeks = def_getuint("MINWEEKS=", MINWEEKS, defp);
		maxweeks = def_getuint("MAXWEEKS=", MAXWEEKS, defp);
		warnweeks = def_getuint("WARNWEEKS=", WARNWEEKS, defp);
		defclose_r(defp);
	}

	/*
	 * The values specified in /etc/default/passwd are interpreted
	 * in a specific way. Special cases are
	 *   MINWEEKS==0 (results in sp_min = -1)
	 *   MAXWEEKS==0 (results in sp_max = default)
	 */
	spw->sp_min = 7 * minweeks;
	if (spw->sp_min <= 0)
		spw->sp_min = -1;

	spw->sp_max = 7 * maxweeks;
	if (spw->sp_max == 0)
		spw->sp_max = 7 * MAXWEEKS;
	if (spw->sp_max < 0)
		spw->sp_max = -1;

	spw->sp_warn = 7 * warnweeks;
	if (spw->sp_warn <= 0)
		spw->sp_warn = -1;
}

/*
 * open and read a value from the defaults file,
 * return value found or default value if not found.
 */
int
def_getint(char *name, int defvalue)
{
	int	val;
	void	*defp;

	if ((defp = defopen_r(PWADMIN)) == NULL) {
		val = defvalue;
	} else {
		val = def_getuint(name, defvalue, defp);
		defclose_r(defp);
	}

	return (val);
}
