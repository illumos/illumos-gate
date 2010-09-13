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

#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include "getent.h"

/*
 * getpwnam - get entries from password database
 */
int
dogetpw(const char **list)
{
	struct passwd *pwp;
	int rc = EXC_SUCCESS;
	char *ptr;
	uid_t uid;


	if (list == NULL || *list == NULL) {
		while ((pwp = getpwent()) != NULL)
			(void) putpwent(pwp, stdout);
	} else {
		for (; *list != NULL; list++) {
			errno = 0;

			/*
			 * Here we assume that the argument passed is
			 * a uid, if it can be completely transformed
			 * to a long integer. So we check for uid in
			 * the database and if we fail then we check
			 * for the user name.
			 * If the argument passed is not numeric, then
			 * we take it as the user name and proceed.
			 */
			uid = strtoul(*list, &ptr, 10);
			if (!(*ptr == '\0' && errno == 0) ||
			    ((pwp = getpwuid(uid)) == NULL)) {
				pwp = getpwnam(*list);
			}

			if (pwp == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putpwent(pwp, stdout);
		}
	}

	return (rc);
}
