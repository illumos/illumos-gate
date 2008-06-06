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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	string duplication
 *	returns pointer to a new string which is the duplicate of string
 *	pointed to by s1
 *	NULL is returned if new string can't be created
 */

#include "lint.h"
#include <stdlib.h>
#include <widec.h>
#include "libc.h"

wchar_t *
wsdup(const wchar_t *s1)
{
	wchar_t *s2;

	s2 = malloc((wcslen(s1) + 1) * sizeof (wchar_t));
	return (s2 == NULL ? NULL : wcscpy(s2, s1));
}
