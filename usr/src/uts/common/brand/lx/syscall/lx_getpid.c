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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/zone.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

/*
 * return the pid
 */
long
lx_getpid(void)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);
	long rv;

	if (curproc->p_pid == curproc->p_zone->zone_proc_initpid) {
		rv = 1;
	} else {
		VERIFY(lwpd != NULL);

		rv = lwpd->br_tgid;
	}

	return (rv);
}

/*
 * return the parent pid
 */
long
lx_getppid(void)
{
	return (lx_lwp_ppid(ttolwp(curthread), NULL, NULL));
}

/*
 * return the thread id
 */
long
lx_gettid(void)
{
	lx_lwp_data_t *lwpd = ttolxlwp(curthread);

	return (lwpd->br_pid);
}
