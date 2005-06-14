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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

/* Maximum minor number to use */
static minor_t inet_maxminor = INET_MAXMINOR;

void *
inet_minor_create(char *name, dev_t min_dev, int kmflags)
{
	inet_arena_t *arena = kmem_alloc(sizeof (inet_arena_t), kmflags);

	if (arena != NULL) {
		arena->ineta_maxminor = MIN(MAXMIN32, inet_maxminor);
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
inet_minor_alloc(void *a)
{
	inet_arena_t *arena = (inet_arena_t *)a;
	dev_t dev;

	while ((dev = (dev_t)vmem_alloc(arena->ineta_arena, 1,
		    VM_NOSLEEP)) == 0) {
		if (arena->ineta_maxminor >= inet_maxminor)
			return (0);
		if (vmem_add(arena->ineta_arena,
		    (void *)(uintptr_t)(arena->ineta_maxminor + 1),
		    inet_maxminor - arena->ineta_maxminor, VM_NOSLEEP) == NULL)
			return (0);
		arena->ineta_maxminor = inet_maxminor;
	}
	return (dev);
}

void
inet_minor_free(void *a, dev_t dev)
{
	ASSERT((dev != OPENFAIL) && (dev != 0) && (dev <= inet_maxminor));
	vmem_free(((inet_arena_t *)a)->ineta_arena, (void *)dev, 1);
}
