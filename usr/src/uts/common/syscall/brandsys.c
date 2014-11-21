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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/brand.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/zone.h>

/*
 * brand(2) system call.
 */
int64_t
brandsys(int cmd, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5)
{
	struct proc *p = curthread->t_procp;
	int64_t rval = 0;
	int err;

	/*
	 * The brandsys system call can only be executed from inside a
	 * branded zone.
	 */
	if (INGLOBALZONE(p) || !ZONE_IS_BRANDED(p->p_zone))
		return (set_errno(ENOSYS));

	if ((err = ZBROP(p->p_zone)->b_brandsys(cmd, &rval, arg1, arg2, arg3,
	    arg4, arg5)) != 0)
		return (set_errno(err));

	return (rval);
}
