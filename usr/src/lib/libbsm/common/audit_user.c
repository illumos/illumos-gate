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

/*
 * Interfaces to audit_user(4)  (/etc/security/audit_user)
 */

#include <stdio.h>
#include <limits.h>
#include <sys/types.h>
#include <string.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include <stdlib.h>


#define	MAX_USERNAME	32	/* same size as utmpx.ut_user */


static char	au_user_fname[PATH_MAX] = AUDITUSERFILE;
static FILE *au_user_file = NULL;
static mutex_t mutex_userfile = DEFAULTMUTEX;
static int use_nsswitch = 1;
static au_user_ent_t *auuserstr2ent(au_user_ent_t *, au_user_str_t *);

/*
 * Externs from libnsl
 */
extern void _setauuser(void);
extern void _endauuser(void);
extern au_user_str_t *_getauuserent(au_user_str_t *, char *, int, int *);
extern au_user_str_t *_getauusernam(char *, au_user_str_t *, char *, int,
    int *);


void
setauuser()
{
	(void) mutex_lock(&mutex_userfile);
	if (use_nsswitch)
		_setauuser();
	else if (au_user_file) {
		(void) fseek(au_user_file, 0L, 0);
	}
	(void) mutex_unlock(&mutex_userfile);
}


void
endauuser()
{
	(void) mutex_lock(&mutex_userfile);
	if (use_nsswitch)
		_endauuser();
	else if (au_user_file) {
		(void) fclose(au_user_file);
		au_user_file = NULL;
	}
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
	int	i, error = 0, found = 0;
	char	*s, input[256];


	(void) mutex_lock(&mutex_userfile);

	if (use_nsswitch) {
		au_user_str_t us;
		au_user_str_t *tmp;
		char buf[NSS_BUFLEN_AUDITUSER];
		int errp = 0;

		(void) memset(buf, NULL, NSS_BUFLEN_AUDITUSER);
		tmp = _getauuserent(&us, buf, NSS_BUFLEN_AUDITUSER, &errp);
		(void) mutex_unlock(&mutex_userfile);
		return (auuserstr2ent(au_user_entry, tmp));
	}

	/* open audit user file if it isn't already */
	if (!au_user_file)
		if (!(au_user_file = fopen(au_user_fname, "rF"))) {
			(void) mutex_unlock(&mutex_userfile);
			return (NULL);
		}

	while (fgets(input, 256, au_user_file)) {
		if (input[0] != '#') {
			s = input + strspn(input, " \t\r\n");
			if ((*s == '\0') || (*s == '#')) {
				continue;
			}
			found = 1;
			s = input;

			/* parse login name */
			i = strcspn(s, ":");

			s[i] = '\0';
			(void) strncpy(au_user_entry->au_name, s, MAX_USERNAME);
			s = &s[i+1];

			/* parse first mask */
			i = strcspn(s, ":");

			s[i] = '\0';
			if (getauditflagsbin(s,
			    &au_user_entry->au_always) < 0)
				error = 1;
			s = &s[i+1];


			/* parse second mask */

			i = strcspn(s, "\n\0");

			s[i] = '\0';
			if (getauditflagsbin(s,
			    &au_user_entry->au_never) < 0)
				error = 1;


			break;
		}
	}

	(void) mutex_unlock(&mutex_userfile);

	if (!error && found) {
		return (au_user_entry);
	} else {
		return (NULL);
	}
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

	if (use_nsswitch) {
		au_user_str_t us;
		au_user_str_t *tmp;
		char buf[NSS_BUFLEN_AUDITUSER];
		int errp = 0;

		if (name == NULL) {
			return ((au_user_ent_t *)NULL);
		}
		tmp = _getauusernam(name, &us, buf, NSS_BUFLEN_AUDITUSER,
		    &errp);
		return (auuserstr2ent(u, tmp));
	}
	while (getauuserent_r(u) != NULL) {
		if (strcmp(u->au_name, name) == 0) {
			return (u);
		}
	}
	return ((au_user_ent_t *)NULL);
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

#ifdef DEBUG
void
print_auuser(au_user_ent_t *ue)
{
	char *empty = "empty";
	char *bad = "bad flags";
	char always[256];
	char never[256];
	int retval;

	if (ue == NULL) {
		printf("NULL\n");
		return;
	}

	printf("name=%s\n", ue->au_name ? ue->au_name : empty);
	retval = getauditflagschar(always, ue->au_always, 0);
	printf("always=%s\n", retval == 0 ? always : bad);
	retval = getauditflagschar(never, ue->au_never, 0);
	printf("never=%s\n", retval == 0 ? never : bad);
}
#endif	/* DEBUG */
