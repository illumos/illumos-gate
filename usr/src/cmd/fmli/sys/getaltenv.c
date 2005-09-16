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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	"wish.h"
#include	"var_arrays.h"

char **Altenv = NULL;
char *getaltenv();

/* LES: replace with MACRO
char *
getAltenv(name)
char *name;
{
	return(getaltenv(Altenv, name));
}
*/

char *
getaltenv(the_env, name)
char **the_env;
char *name;
{
	int i;

	if (the_env && ((i = findaltenv(the_env, name)) != FAIL))
		return(strchr(the_env[i], '=') + 1);
	return(NULL);
}

int
findaltenv(the_env, name)
char **the_env;
char *name;
{
	int i, len;
	int	lcv;

	len = strlen(name);
	lcv = array_len(the_env);
	for (i = 0; i < lcv; i++)
		if ((strncmp(name, the_env[i], len) == 0) && (the_env[i][len] == '='))
			return(i);
	return(FAIL);
}
