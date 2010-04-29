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
 * Copyright (c) 2010, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/page.h>
#include <sys/mem_config.h>
#include <sys/kflt_mem.h>

/* These should be in a platform stubs file. */

int kflt_on;
pgcnt_t kflt_freemem;
pgcnt_t kflt_throttlefree;
pgcnt_t kflt_minfree;
pgcnt_t kflt_desfree;
pgcnt_t kflt_needfree;
pgcnt_t	kflt_lotsfree;

/*ARGSUSED*/
int
kflt_create_throttle(pgcnt_t npages, int flags)
{
	return (0);
}

void
kflt_init(void)
{
}

void
kflt_evict_wakeup(void)
{
}

void
kflt_tick(void)
{
}
