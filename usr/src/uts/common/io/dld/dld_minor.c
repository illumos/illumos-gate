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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/types.h>
#include	<sys/mkdev.h>
#include	<sys/conf.h>
#include	<sys/stat.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/vmem.h>
#include	<sys/atomic.h>

#include	<sys/dld.h>
#include	<sys/dld_impl.h>

static vmem_t		*minor_arenap;
static uint32_t		minor_count;

#define	MINOR_TO_PTR(minor)	((void *)(uintptr_t)(minor))
#define	PTR_TO_MINOR(ptr)	((minor_t)(uintptr_t)(ptr))

/*
 * Initialize this module's data structures.
 */
void
dld_minor_init(void)
{
	/*
	 * Allocate a vmem arena to manage minor numbers. The range of the
	 * arena will be from 1 to MAXMIN (maximum legal minor number).
	 */
	minor_arenap = vmem_create("dld_minor_arena", MINOR_TO_PTR(1), MAXMIN,
	    1, NULL, NULL, NULL, 0, VM_SLEEP);
	ASSERT(minor_arenap != NULL);
}

/*
 * Tear down this module's data structures.
 */
int
dld_minor_fini(void)
{
	/*
	 * Check to see if there are any minor numbers still in use.
	 */
	if (minor_count != 0)
		return (EBUSY);

	vmem_destroy(minor_arenap);
	return (0);
}

/*
 * Allocate a new minor number.
 */
minor_t
dld_minor_hold(boolean_t sleep)
{
	minor_t		minor;

	/*
	 * Grab a value from the arena.
	 */
	if ((minor = PTR_TO_MINOR(vmem_alloc(minor_arenap, 1,
	    (sleep) ? VM_SLEEP : VM_NOSLEEP))) == 0)
		return (0);

	atomic_add_32(&minor_count, 1);
	return (minor);
}

/*
 * Release a previously allocated minor number.
 */
void
dld_minor_rele(minor_t minor)
{
	/*
	 * Return the value to the arena.
	 */
	vmem_free(minor_arenap, MINOR_TO_PTR(minor), 1);

	atomic_add_32(&minor_count, -1);
}
