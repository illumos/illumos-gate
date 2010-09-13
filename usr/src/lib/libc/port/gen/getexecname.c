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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _getexecname = getexecname

#include "lint.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/auxv.h>

extern void *___getauxptr(int type);

/*
 * Return the pointer to the fully-resolved path name of the process's
 * executable file obtained from the AT_SUN_EXECNAME aux vector entry.
 */
const char *
getexecname(void)
{
	return ((const char *)___getauxptr(AT_SUN_EXECNAME));
}
