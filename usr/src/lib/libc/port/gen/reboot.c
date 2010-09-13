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

#include "lint.h"
#include <sys/types.h>
#include <sys/uadmin.h>
#include <sys/reboot.h>

/*
 * Note that not all of BSD's semantics are supported.
 */
int
reboot(int howto, char *bootargs)
{
	int cmd = A_SHUTDOWN;
	int fcn = AD_BOOT;

	if (howto & RB_DUMP)
		cmd = A_DUMP;

	if (howto & RB_HALT)
		fcn = AD_HALT;
	else if (howto & RB_ASKNAME)
		fcn = AD_IBOOT;

	return (uadmin(cmd, fcn, (uintptr_t)bootargs));
}
