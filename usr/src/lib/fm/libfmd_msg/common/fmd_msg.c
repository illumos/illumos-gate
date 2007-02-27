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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <synch.h>

static rwlock_t fmd_msg_rwlock;

#pragma init(fmd_msg_init)
static void
fmd_msg_init(void)
{
	(void) rwlock_init(&fmd_msg_rwlock, USYNC_THREAD, NULL);
}

#pragma fini(fmd_msg_fini)
static void
fmd_msg_fini(void)
{
	(void) rwlock_destroy(&fmd_msg_rwlock);
}

void
fmd_msg_lock(void)
{
	if (rw_wrlock(&fmd_msg_rwlock) != 0)
		abort();
}

void
fmd_msg_unlock(void)
{
	if (rw_unlock(&fmd_msg_rwlock) != 0)
		abort();
}
