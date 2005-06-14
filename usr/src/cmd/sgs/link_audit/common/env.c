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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <env.h>

static const char	*token = ":";

void
build_env_list(Elist **list, const char *env)
{
	char	*envstr;
	char	*tok;
	char	*lasts;

	if ((envstr = getenv(env)) == NULL)
		return;
	envstr = strdup(envstr);
	tok = strtok_r(envstr, token, &lasts);
	while (tok) {
		Elist	*lp;
		if ((lp = (Elist *)malloc(sizeof (Elist))) == 0) {
			(void) printf("build_list: malloc failed\n");
			exit(1);
		}
		lp->l_libname = strdup(tok);
		lp->l_next = *list;
		*list = lp;
		tok = strtok_r(NULL, token, &lasts);
	}
	free(envstr);
}


Elist *
check_list(Elist *list, const char *str)
{
	const char	*basestr;

	if (list == NULL)
		return (NULL);

	/*
	 * Is this a basename or a relativepath name
	 */
	if ((basestr = strrchr(str, '/')) != 0)
		basestr++;
	else
		basestr = str;


	for (; list; list = list->l_next) {
		if (strchr(list->l_libname, '/') == 0) {
			if (strcmp(basestr, list->l_libname) == 0)
				return (list);
		} else {
			if (strcmp(str, list->l_libname) == 0)
				return (list);
		}
	}
	return (NULL);
}

char *
checkenv(const char *env)
{
	char	*envstr;
	if ((envstr = getenv(env)) == NULL)
		return (NULL);
	while (*envstr == ' ')
		envstr++;
	if (*envstr == '\0')
		return (NULL);
	return (envstr);
}
