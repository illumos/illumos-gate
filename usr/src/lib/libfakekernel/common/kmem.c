/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#include <sys/kmem.h>

#include <sys/debug.h>
#include <sys/ksynch.h>
#include <sys/systm.h>

#include <umem.h>

void	abort(void) __NORETURN;

static int
kmem_failed_cb(void)
{
	abort();
	return (UMEM_CALLBACK_RETRY);
}

#pragma init(_kmem_init)
static int
_kmem_init(void)
{
	umem_nofail_callback(kmem_failed_cb);
	return (0);
}

static int
kmem2umem_flags(int kmflags)
{
	int umflags = UMEM_NOFAIL;
	if (kmflags & KM_NOSLEEP)
		umflags = UMEM_DEFAULT;
	return (umflags);
}

int
kmem_debugging(void)
{
	return (0);
}

void *
kmem_alloc(size_t size, int kmflags)
{
	return (umem_alloc(size, kmem2umem_flags(kmflags)));
}

void *
kmem_zalloc(size_t size, int kmflags)
{
	return (umem_zalloc(size, kmem2umem_flags(kmflags)));
}


void
kmem_free(void *buf, size_t size)
{
	umem_free(buf, size);
}

/* void *kmem_alloc_tryhard(size_t size, size_t *alloc_size, int kmflags); */

kmem_cache_t *
kmem_cache_create(
	char *name,		/* descriptive name for this cache */
	size_t bufsize,		/* size of the objects it manages */
	size_t align,		/* required object alignment */
	int (*constructor)(void *, void *, int), /* object constructor */
	void (*destructor)(void *, void *),	/* object destructor */
	void (*reclaim)(void *), /* memory reclaim callback */
	void *private,		/* pass-thru arg for constr/destr/reclaim */
	vmem_t *vmp,		/* vmem source for slab allocation */
	int kcflags)		/* cache creation flags */
{
	umem_cache_t *uc;
	int ucflags = 0;

	/* Ignore KMC_NOTOUCH - not needed for userland caches */
	if (kcflags & KMC_NODEBUG)
		ucflags |= UMC_NODEBUG;
	if (kcflags & KMC_NOMAGAZINE)
		ucflags |= UMC_NOMAGAZINE;
	if (kcflags & KMC_NOHASH)
		ucflags |= UMC_NOHASH;

	uc = umem_cache_create(name, bufsize, align,
	    constructor, destructor, reclaim,
	    private, vmp, ucflags);
	return ((kmem_cache_t *)uc);
}

void
kmem_cache_destroy(kmem_cache_t *kc)
{
	umem_cache_destroy((umem_cache_t *)kc);
}

void *
kmem_cache_alloc(kmem_cache_t *kc, int kmflags)
{
	return (umem_cache_alloc((umem_cache_t *)kc,
	    kmem2umem_flags(kmflags)));
}

void
kmem_cache_free(kmem_cache_t *kc, void *p)
{
	umem_cache_free((umem_cache_t *)kc, p);
}

/* ARGSUSED */
void
kmem_cache_set_move(kmem_cache_t *kc,
    kmem_cbrc_t (*fun)(void *, void *, size_t, void *))
{
}

boolean_t
kmem_cache_reap_active(void)
{
	return (B_FALSE);
}

/* ARGSUSED */
void
kmem_cache_reap_soon(kmem_cache_t *kc)
{
}

/* uint64_t kmem_cache_stat(kmem_cache_t *, char *); */

/* ARGSUSED */
void
vmem_qcache_reap(struct  vmem *vmp)
{
}

void
strfree(char *str)
{
	ASSERT(str != NULL);
	kmem_free(str, strlen(str) + 1);
}
