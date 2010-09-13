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

/*
 * Minor number allocation for various protocol modules.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <inet/common.h>

typedef struct inet_arena {
	vmem_t *ineta_arena;	/* Minor number arena */
	minor_t ineta_maxminor;	/* max minor number in the arena */
} inet_arena_t;

void *
inet_minor_create(char *name, dev_t min_dev, dev_t max_dev, int kmflags)
{
	inet_arena_t *arena = kmem_alloc(sizeof (inet_arena_t), kmflags);

	if (arena != NULL) {
		arena->ineta_maxminor = max_dev;
		arena->ineta_arena = vmem_create(name,
		    (void *)min_dev, arena->ineta_maxminor - min_dev + 1,
		    1, NULL, NULL, NULL, 1, kmflags | VMC_IDENTIFIER);

		if (arena->ineta_arena == NULL) {
			kmem_free(arena, sizeof (inet_arena_t));
			arena = NULL;
		}
	}

	return (arena);
}

void
inet_minor_destroy(void *a)
{
	inet_arena_t *arena = (inet_arena_t *)a;

	if (arena != NULL) {
		vmem_destroy(arena->ineta_arena);
		kmem_free(arena, sizeof (inet_arena_t));
	}
}

dev_t
inet_minor_alloc(void *arena)
{
	return ((dev_t)vmem_alloc(((inet_arena_t *)arena)->ineta_arena,
	    1, VM_NOSLEEP));
}

void
inet_minor_free(void *arena, dev_t dev)
{
	ASSERT((dev != OPENFAIL) && (dev != 0) && (dev <= MAXMIN));
	vmem_free(((inet_arena_t *)arena)->ineta_arena, (void *)dev, 1);
}

/*
 * This function is used to free a message that has gone through
 * mi_copyin processing which modifies the M_IOCTL mblk's b_next
 * and b_prev pointers. We use this function to set b_next/b_prev
 * to NULL and free them.
 */
void
inet_freemsg(mblk_t *mp)
{
	mblk_t	*bp = mp;

	for (; bp != NULL; bp = bp->b_cont) {
		bp->b_prev = NULL;
		bp->b_next = NULL;
	}
	freemsg(mp);
}
