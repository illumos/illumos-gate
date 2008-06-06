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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include "tsd.h"

/*
 * This is in a separate source file from strtok_r() so that the
 * dynamic linker (ld.so.1) will not needlessly get a reference
 * to tsdalloc() and pull in more than it needs from libc_pic.a
 */
char *
strtok(char *string, const char *sepset)
{
	char **lasts = tsdalloc(_T_STRTOK, sizeof (char *), NULL);

	if (lasts == NULL)
		return (NULL);
	return (strtok_r(string, sepset, lasts));
}
