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
 * Copyright (c) 2018 Peter Tribble.
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include <user_attr.h>
#include "getent.h"

static int
putuserattr(const userattr_t *user, FILE *fp)
{
	int i;
	kva_t *attrs;
	kv_t *data;

	if (user == NULL)
		return (1);

	if (fprintf(fp, "%s:%s:%s:%s:",
	    user->name != NULL ? user->name : "",
	    user->qualifier != NULL ? user->res1 : "",
	    user->res1 != NULL ? user->res1 : "",
	    user->res2 != NULL ? user->res2 : "") == EOF)
		return (1);
	attrs = user->attr;
	if (attrs != NULL) {
		data = attrs->data;
		for (i = 0; i < attrs->length; i++) {
			if (fprintf(fp, "%s=%s%s",
			    data[i].key != NULL ? data[i].key : "",
			    data[i].value != NULL ? data[i].value : "",
			    i < (attrs->length)-1 ? ";" : "") == EOF)
				return (1);
		}
	}
	if (putc('\n', fp) == EOF)
		return (1);
	return (0);
}

int
dogetuserattr(const char **list)
{
	struct passwd *pwp;
	userattr_t *puser;
	int rc = EXC_SUCCESS;
	char *ptr;
	uid_t uid;

	if (list == NULL || *list == NULL) {
		setuserattr();
		while ((puser = getuserattr()) != NULL)
			(void) putuserattr(puser, stdout);
		enduserattr();
	} else {
		for (; *list != NULL; list++) {
			uid = strtoul(*list, &ptr, 10);
			if (*ptr == '\0' && errno == 0) {
				if ((pwp = getpwuid(uid)) == NULL) {
					puser = getusernam(*list);
				} else {
					puser = getusernam(pwp->pw_name);
				}
			} else {
				puser = getusernam(*list);
			}
			if (puser == NULL)
				rc = EXC_NAME_NOT_FOUND;
			else
				(void) putuserattr(puser, stdout);
		}
	}

	return (rc);
}
