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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/async.h>

static bus_func_desc_t *bfd_list = NULL; /* list of busfunc descriptors */
kmutex_t bfd_lock;		/* lock protecting bfd_list */

/*
 * Register a new bus function.  We expect this function to be called from a
 * driver attach or detach routine, so we can safely perform a sleeping
 * allocation here.  We just insert the new element at the head of the list.
 * For more information on bus_func semantics, refer to sun4u/sys/async.h.
 */
void
bus_func_register(int type, busfunc_t func, void *arg)
{
	bus_func_desc_t *bfd = kmem_alloc(sizeof (bus_func_desc_t), KM_SLEEP);

	bfd->bf_type = type;
	bfd->bf_func = func;
	bfd->bf_arg = arg;

	mutex_enter(&bfd_lock);
	bfd->bf_next = bfd_list;
	bfd_list = bfd;
	mutex_exit(&bfd_lock);
}

/*
 * Unregister the specified bus function.  We only delete an element that
 * exactly matches the specified (type, func, arg) tuple.  We expect this
 * function to only be called from driver detach context.
 */
void
bus_func_unregister(int type, busfunc_t func, void *arg)
{
	bus_func_desc_t *bfd, **pp;

	mutex_enter(&bfd_lock);
	pp = &bfd_list;

	for (bfd = bfd_list; bfd != NULL; bfd = bfd->bf_next) {
		if (bfd->bf_type == type && bfd->bf_func == func &&
		    bfd->bf_arg == arg) {
			*pp = bfd->bf_next;
			break;
		}
		pp = &bfd->bf_next;
	}

	mutex_exit(&bfd_lock);

	if (bfd != NULL)
		kmem_free(bfd, sizeof (bus_func_desc_t));
}

/*
 * Invoke the registered bus functions of the specified type.  We return the
 * maximum of the result values (e.g. BF_FATAL if any call returned BF_FATAL).
 * This function assumes that (1) the BF_* constants are defined so that the
 * most fatal error has the highest numerical value, and (2) that the bf_func
 * callbacks obey the rules described in async.h.
 */
uint_t
bus_func_invoke(int type)
{
	bus_func_desc_t *bfd;
	uint_t err = BF_NONE;

	mutex_enter(&bfd_lock);

	for (bfd = bfd_list; bfd != NULL; bfd = bfd->bf_next) {
		if (bfd->bf_type == type) {
			uint_t status = bfd->bf_func(bfd->bf_arg);
			err = MAX(err, status);
		}
	}

	mutex_exit(&bfd_lock);
	return (err);
}
