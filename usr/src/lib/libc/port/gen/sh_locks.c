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

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <synch.h>
#include <thread.h>
#include <pthread.h>
#include "libc.h"

/*
 * fork1-safety.
 * These three routines were used to make some libc interfaces fork1-safe.
 * With the merge of libthread into libc, almost all libc internal-only
 * locks are acquired via lmutex_lock() or lrw_rdlock()/lrw_wrlock(),
 * which makes them automatically fork1-safe (as well as async-signal
 * safe), so these functions are now used only for the locks that cannot
 * be used with lmutex_lock or lrw_rdlock()/lrw_wrlock().
 */

extern void atexit_locks(void);
extern void atexit_unlocks(void);

extern void stdio_locks(void);
extern void stdio_unlocks(void);

extern void malloc_locks(void);
extern void malloc_unlocks(void);

static void
libc_prepare_atfork(void)
{
	atexit_locks();
	stdio_locks();
	malloc_locks();
}

static void
libc_child_atfork(void)
{
	malloc_unlocks();
	stdio_unlocks();
	atexit_unlocks();
}

static void
libc_parent_atfork(void)
{
	malloc_unlocks();
	stdio_unlocks();
	atexit_unlocks();
}

/* called from libc_init() */
void
atfork_init(void)
{
	(void) pthread_atfork(libc_prepare_atfork,
	    libc_parent_atfork, libc_child_atfork);
}
