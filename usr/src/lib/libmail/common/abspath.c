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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  NAME
 *	abspath - expand a path relative to some `.'
 *
 *  SYNOPSIS
 *	string *abspath(char *path, char *dot, string *to)
 *
 *  DESCRIPTION
 *	If "path" is relative, ie: does not start with `.', the
 *	the value of "dot" will be prepended and the result
 *	returned in "to". Otherwise, the value of "path" is
 *	returned in "to".
 */
#include "libmail.h"
#include <sys/types.h>

string *
abspath(char *path, char *dot, string *to)
{
	if (*path == '/') {
		to = s_append(to, path);
	} else {
		to = s_append(to, dot);
		to = s_append(to, path);
	}
	return (to);
}
