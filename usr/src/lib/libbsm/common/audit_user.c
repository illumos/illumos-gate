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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Interfaces to audit_user(4) (/etc/security/audit_user) */

#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <string.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include <stdlib.h>
#include <utmpx.h>

#define	MAX_USERNAME	sizeof (((struct utmpx *)0)->ut_user)

static mutex_t mutex_userfile = DEFAULTMUTEX;
static au_user_ent_t *auuserstr2ent(au_user_ent_t *, au_user_str_t *);

/* Externs from libnsl */
extern void _setauuser(void);
extern void _endauuser(void);
extern au_user_str_t *_getauuserent(au_user_str_t *, char *, int, int *);
extern au_user_str_t *_getauusernam(char *, au_user_str_t *, char *, int,
    int *);

void
setauuser()
{
	(void) mutex_lock(&mutex_userfile);
	_setauuser();
	(void) mutex_unlock(&mutex_userfile);
}

void
endauuser()
{
	(void) mutex_lock(&mutex_userfile);
	_endauuser();
	(void) mutex_unlock(&mutex_userfile);
}

au_user_ent_t *
getauuserent()
{
	static au_user_ent_t au_user_entry;
	static char	logname[MAX_USERNAME+1];

	/* initialize au_user_entry structure */
	au_user_entry.au_name = logname;

	return (getauuserent_r(&au_user_entry));

}

au_user_ent_t *
getauuserent_r(au_user_ent_t *au_user_entry)
{
	au_user_str_t	us;
	au_user_str_t	*tmp;
	char 		buf[NSS_BUFLEN_AUDITUSER];
	int 		errp = 0;

	(void) mutex_lock(&mutex_userfile);
	(void) memset(buf, NULL, NSS_BUFLEN_AUDITUSER);
	tmp = _getauuserent(&us, buf, NSS_BUFLEN_AUDITUSER, &errp);
	(void) mutex_unlock(&mutex_userfile);

	return (auuserstr2ent(au_user_entry, tmp));
}

au_user_ent_t *
getauusernam(char *name)
{
	static au_user_ent_t u;
	static char	logname[MAX_USERNAME+1];

	/* initialize au_user_entry structure */
	u.au_name = logname;

	return (getauusernam_r(&u, name));
}

au_user_ent_t *
getauusernam_r(au_user_ent_t *u, char *name)
{
	au_user_str_t	us;
	au_user_str_t	*tmp;
	char		buf[NSS_BUFLEN_AUDITUSER];
	int		errp = 0;

	if (name == NULL) {
		return ((au_user_ent_t *)NULL);
	}
	tmp = _getauusernam(name, &us, buf, NSS_BUFLEN_AUDITUSER, &errp);

	return (auuserstr2ent(u, tmp));
}

static au_user_ent_t *
auuserstr2ent(au_user_ent_t *ue, au_user_str_t *us)
{
	if (us == NULL)
		return (NULL);

	if (getauditflagsbin(us->au_always, &ue->au_always) < 0) {
		return (NULL);
	}
	if (getauditflagsbin(us->au_never, &ue->au_never) < 0) {
		ue->au_never.am_success = AU_MASK_NONE;
		ue->au_never.am_failure = AU_MASK_NONE;
	}
	(void) strncpy(ue->au_name, us->au_name, MAX_USERNAME);

	return (ue);
}
