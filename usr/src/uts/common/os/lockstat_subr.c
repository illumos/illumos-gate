/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/time.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cyclic.h>
#include <sys/lockstat.h>
#include <sys/spl.h>

/*
 * Resident support for the lockstat driver.
 */

dtrace_id_t lockstat_probemap[LS_NPROBES];
void (*lockstat_probe)(dtrace_id_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t);

int
lockstat_active_threads(void)
{
	kthread_t *tp;
	int active = 0;

	mutex_enter(&pidlock);
	tp = curthread;
	do {
		if (tp->t_lockstat)
			active++;
	} while ((tp = tp->t_next) != curthread);
	mutex_exit(&pidlock);
	return (active);
}
