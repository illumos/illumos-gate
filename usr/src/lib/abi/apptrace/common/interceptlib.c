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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <apptrace.h>
#include <assert.h>
#include "abienv.h"

#define	NOTID 0xffffffff

/*
 * This file is meant to contain support functions
 * for interceptors.  They are built into the auditing
 * object making the namespace available to "children"
 * objects.
 */

static lwp_mutex_t abi_stdio_mutex = DEFAULTMUTEX;
static volatile thread_t locktid = NOTID;
static volatile int count;

/* Return true on empty */
int
is_empty_string(char const *s)
{
	if (s != NULL && *s != '\0')
		return (0);

	return (1);
}

void
abilock(sigset_t *mask)
{
	thread_t tid;

	if ((*abi_thr_main)() != -1) {
		tid = (*abi_thr_self)();

		if (tid == locktid) {
			count++;
		} else {
			(void) _lwp_mutex_lock(&abi_stdio_mutex);
			(void) sigprocmask(SIG_BLOCK, &abisigset, mask);
			locktid = tid;
			count = 1;
		}
	}
}

void
abiunlock(sigset_t *mask)
{
	thread_t tid;

	(void) fflush(ABISTREAM);

	if ((*abi_thr_main)() != -1) {
		tid = (*abi_thr_self)();
		assert(tid == locktid);
		count--;
		if (count <= 0) {
			count = 0;
			locktid = NOTID;
			(void) sigprocmask(SIG_SETMASK, mask, NULL);
			(void) _lwp_mutex_unlock(&abi_stdio_mutex);
		}
	}
}
