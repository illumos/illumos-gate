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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <sys/synch.h>
#include <sys/synch32.h>
#include "thr_uberdata.h"

/*
 * This file generates two values used by _lwp_mutex_unlock.s:
 *	a) the byte offset (in lwp_mutex_t) of the word containing the lock byte
 *	b) a mask to extract the waiter field from the word containing it
 * These offsets do not change between 32-bit and 64-bit.
 * Mutexes can be shared between 32-bit and 64-bit programs.
 */

int
main(void)
{
	(void) printf("#define\tMUTEX_LOCK_WORD\t0x%p\n",
	    offsetof(lwp_mutex_t, mutex_lockword));
	(void) printf("#define\tWAITER_MASK\t0xff\n");

	(void) printf("#define\tSIG_SETMASK\t0x%lx\n", SIG_SETMASK);
	(void) printf("#define\tMASKSET0\t0x%lx\n", MASKSET0);
	(void) printf("#define\tMASKSET1\t0x%lx\n", MASKSET1);
	(void) printf("#define\tMASKSET2\t0x%lx\n", MASKSET2);
	(void) printf("#define\tMASKSET3\t0x%lx\n", MASKSET3);
	(void) printf("#define\tSIGSEGV\t0x%lx\n", SIGSEGV);

	return (0);
}
