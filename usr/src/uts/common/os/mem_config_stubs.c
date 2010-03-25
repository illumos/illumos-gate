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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/page.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>

/* These should be in a platform stubs file. */

int kcage_on;
kthread_id_t kcage_cageout_thread;
pgcnt_t kcage_freemem;
pgcnt_t kcage_throttlefree;
pgcnt_t kcage_minfree;
pgcnt_t kcage_desfree;
pgcnt_t kcage_needfree;
pgcnt_t	kcage_lotsfree = 1;

#if !defined(__x86) || defined(__xpv)
/*ARGSUSED*/
int
kphysm_setup_func_register(kphysm_setup_vector_t *vec, void *arg)
{
	return (0);
}

/*ARGSUSED*/
void
kphysm_setup_func_unregister(kphysm_setup_vector_t *vec, void *arg)
{
}
#endif

/*ARGSUSED*/
int
kcage_create_throttle(pgcnt_t npages, int flags)
{
	return (0);
}

void
kcage_cageout_init(void)
{
}

void
kcage_cageout_wakeup()
{
}

void
kcage_tick()
{
}

/*ARGSUSED*/
int
kcage_current_pfn(pfn_t *pfn)
{
	return (0);
}
