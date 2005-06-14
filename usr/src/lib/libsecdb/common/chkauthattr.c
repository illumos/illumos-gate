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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <limits.h>
#include <deflt.h>
#include <auth_attr.h>
#include <prof_attr.h>
#include <user_attr.h>


static int _is_authorized(const char *, char *);
static int _chk_policy_auth(const char *, char **, int *);
static int _chkprof_for_auth(const char *, const char *, char **, int *);


int
chkauthattr(const char *authname, const char *username)
{
	int		auth_granted = 0;
	char		*auths;
	char		*profiles;
	userattr_t	*user;
	char		*chkedprof[MAXPROFS];
	int		chkedprof_cnt = 0;
	int		i;

	if (authname == NULL || username == NULL)
		return (0);

	auth_granted = _chk_policy_auth(authname, chkedprof, &chkedprof_cnt);
	if (auth_granted) {
		return (1);
	}
	if ((user = getusernam(username)) == NULL)
		return (0);

	if ((auths = kva_match(user->attr, USERATTR_AUTHS_KW)) != NULL) {
		if (_is_authorized(authname, auths)) {
			free_userattr(user);
			return (1);
		}
	}

	if ((profiles = kva_match(user->attr, USERATTR_PROFILES_KW)) == NULL) {
		free_userattr(user);
		return (0);
	}

	auth_granted = _chkprof_for_auth(profiles, authname,
	    chkedprof, &chkedprof_cnt);

	/* free memory allocated for checked array */
	for (i = 0; i < chkedprof_cnt; i++) {
		free(chkedprof[i]);
	}

	free_userattr(user);

	return (auth_granted);
}

static int
_chkprof_for_auth(const char *profs, const char *authname,
    char **chkedprof, int *chkedprof_cnt)
{

	char *prof, *lasts, *auths, *profiles;
	profattr_t	*pa;
	int		i;
	int		checked = 0;

	for (prof = strtok_r((char *)profs, ",", &lasts); prof != NULL;
	    prof = strtok_r(NULL, ",", &lasts)) {

		checked = 0;
		/* check if this profile has been checked */
		for (i = 0; i < *chkedprof_cnt; i++) {
			if (strcmp(chkedprof[i], prof) == 0) {
				checked = 1;
				break;
			}
		}

		if (!checked) {

			chkedprof[*chkedprof_cnt] = strdup(prof);
			*chkedprof_cnt = *chkedprof_cnt + 1;

			if ((pa = getprofnam(prof)) == NULL)
				continue;

			if ((auths = kva_match(pa->attr,
			    PROFATTR_AUTHS_KW)) != NULL) {
				if (_is_authorized(authname, auths)) {
					free_profattr(pa);
					return (1);
				}
			}
			if ((profiles =
			    kva_match(pa->attr, PROFATTR_PROFS_KW)) != NULL) {
				/* Check for authorization in subprofiles */
				if (_chkprof_for_auth(profiles, authname,
				    chkedprof, chkedprof_cnt)) {
					free_profattr(pa);
					return (1);
				}
			}
			free_profattr(pa);
		}
	}
	/* authorization not found in any profile */
	return (0);
}

int
_auth_match(const char *pattern, const char *auth)
{
	size_t len;
	char wildcard = KV_WILDCHAR;
	char *grant;

	len = strlen(pattern);

	/*
	 * If the wildcard is not in the last position in the string, don't
	 * match against it.
	 */
	if (pattern[len-1] != wildcard)
		return (0);

	/*
	 * If the strings are identical up to the wildcard and auth does not
	 * end in "grant", then we have a match.
	 */
	if (strncmp(pattern, auth, len-1) == 0) {
		grant = strrchr(auth, '.');
		if (grant != NULL) {
			if (strncmp(grant + 1, "grant", 5) != NULL)
				return (1);
		}
	}

	return (0);
}

static int
_is_authorized(const char *authname, char *auths)
{
	int	found = 0;	/* have we got a match, yet */
	char	wildcard = '*';
	char	*auth;		/* current authorization being compared */
	char	*buf;
	char	*lasts;

	buf = strdup(auths);
	for (auth = strtok_r(auths, ",", &lasts); auth != NULL && !found;
	    auth = strtok_r(NULL, ",", &lasts)) {
		if (strcmp((char *)authname, auth) == 0) {
			/* Exact match.  We're done. */
			found = 1;
		} else if (strchr(auth, wildcard) != NULL) {
			if (_auth_match(auth, authname)) {
				found = 1;
				break;
			}
		}
	}

	free(buf);

	return (found);
}


int
_get_auth_policy(char **def_auth, char **def_prof)
{
	char *cp;

	if (defopen(AUTH_POLICY) != 0)
		return (-1);

	cp = defread(DEF_AUTH);
	if (cp != NULL) {
		*def_auth = strdup(cp);
		if (*def_auth == NULL)
			return (-1);
	} else {
		*def_auth = NULL;
	}

	cp = defread(DEF_PROF);
	if (cp != NULL) {
		*def_prof = strdup(cp);
		if (*def_prof == NULL) {
			free(*def_auth);
			return (-1);
		}
	} else {
		*def_prof = NULL;
	}

	(void) defopen(NULL);
	return (0);
}

/*
 * read /etc/security/policy.conf for AUTHS_GRANTED.
 * return 1 if found matching authname.
 * Otherwise, read PROFS_GRANTED to see if authname exists in any
 * default profiles.
 */
static int
_chk_policy_auth(const char *authname, char **chkedprof, int *chkedprof_cnt)
{
	char	*auths, *profs;
	int	ret = 1;

	if (_get_auth_policy(&auths, &profs) != 0)
		return (0);

	if (auths != NULL) {
		if (_is_authorized(authname, auths))
			goto exit;
	}

	if (profs != NULL) {
		if (_chkprof_for_auth(profs, authname, chkedprof,
		    chkedprof_cnt))
			goto exit;
	}
	ret = 0;

exit:
	free(auths);
	free(profs);
	return (ret);
}
