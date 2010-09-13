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

#include <sys/vmem.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <vm/seg_kmem.h>

static vmem_t *id32_arena;
static kmem_cache_t *id32_cache;

#define	ID32_BITS	5
#define	ID32_ALIGN	(1 << ID32_BITS)
#define	ID32_MOD	(ID32_ALIGN - 1)

#if defined(__amd64)
/*
 * For amd64 the 32 bit id is the offset of the entry in the arena.
 */
extern char *heap_core_base;
#define	ID32_ENCODE(x)	(((x) - (uintptr_t)heap_core_base) | \
	((((x) - (uintptr_t)heap_core_base) % ID32_MOD)) + 1)
#define	ID32_DECODE(x)	(P2ALIGN((x), (uintptr_t)ID32_ALIGN) + \
	(uintptr_t)heap_core_base)
#define	ID32_VALID(x)	(ID32_ENCODE(ID32_DECODE(x)) == (x))
#else	/* __amd64 */
/*
 * All other architectures use the 32 bit pointer value for the 32 bit id.
 */
#define	ID32_ENCODE(x)	(((x) | ((x) % ID32_MOD)) + 1)
#define	ID32_DECODE(x)	P2ALIGN((x), ID32_ALIGN)
#define	ID32_VALID(x)	(ID32_ENCODE(ID32_DECODE(x)) == (x))
#endif	/* __amd64 */

void
id32_init(void)
{
	id32_arena = vmem_create("id32", NULL, 0, PAGESIZE,
	    segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);

	id32_cache = kmem_cache_create("id32_cache", ID32_ALIGN, ID32_ALIGN,
	    NULL, NULL, NULL, NULL, id32_arena, 0);
}

/*
 * Return a 32-bit identifier for the specified pointer.
 */
uint32_t
id32_alloc(void *ptr, int kmflag)
{
	void **hent = kmem_cache_alloc(id32_cache, kmflag);
	uintptr_t id;

	if (hent == NULL)
		return (0);

	*hent = ptr;
	id = ID32_ENCODE((uintptr_t)hent);
	ASSERT64(id <= UINT32_MAX);
	return ((uint32_t)id);
}

/*
 * Free a 32-bit ID.
 */
void
id32_free(uint32_t id)
{
	if (!ID32_VALID(id)) {
		cmn_err(CE_WARN, "id32_free(%x): bad ID rejected\n", id);
		return;
	}

	kmem_cache_free(id32_cache, (void *)(uintptr_t)ID32_DECODE(id));
}

/*
 * Return the pointer described by a 32-bit ID, or NULL if the ID is bad.
 */
void *
id32_lookup(uint32_t id)
{
	if (!ID32_VALID(id)) {
		cmn_err(CE_WARN, "id32_lookup(%x): bad ID rejected\n", id);
		return (NULL);
	}

	return (((void **)(uintptr_t)ID32_DECODE(id))[0]);
}
