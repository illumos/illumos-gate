/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/atomic.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/containerof.h>
#include <inet/ip.h>
#include <inet/ipclassifier.h>
#include <inet/tcp.h>

#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_regs_values.h"
#include "t4_l2t.h"

/* identifies sync vs async L2T_WRITE_REQs */
#define	S_SYNC_WR	12
#define	V_SYNC_WR(x)	((x) << S_SYNC_WR)
#define	F_SYNC_WR	V_SYNC_WR(1)
#define	VLAN_NONE	0xfff

/*
 * jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 */

/* NOTE: Arguments are modified. */
#define	__jhash_mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define	JHASH_GOLDEN_RATIO	0x9e3779b9

/*
 * A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *	 done at the end is not done here.
 */
static inline u32
jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_GOLDEN_RATIO;
	b += JHASH_GOLDEN_RATIO;
	c += initval;

	__jhash_mix(a, b, c);

	return (c);
}

static inline u32
jhash_2words(u32 a, u32 b, u32 initval)
{
	return (jhash_3words(a, b, 0, initval));
}

#if defined(__GNUC__)
#define	likely(x)	__builtin_expect((x), 1)
#define	unlikely(x)	__builtin_expect((x), 0)
#else
#define	likely(x)	(x)
#define	unlikely(x)	(x)
#endif /* defined(__GNUC__) */

enum {
	L2T_STATE_VALID,	/* entry is up to date */
	L2T_STATE_STALE,	/* entry may be used but needs revalidation */
	L2T_STATE_RESOLVING,	/* entry needs address resolution */
	L2T_STATE_SYNC_WRITE,	/* synchronous write of entry underway */

	/* when state is one of the below the entry is not hashed */
	L2T_STATE_SWITCHING,	/* entry is being used by a switching filter */
	L2T_STATE_UNUSED	/* entry not in use */
};

struct l2t_data {
	krwlock_t lock;
	u_int l2t_size;
	volatile uint_t nfree;	 /* number of free entries */
	struct l2t_entry *rover; /* starting point for next allocation */
	struct l2t_entry l2tab[];
};

#define	VLAN_NONE	0xfff
#define	SA(x)		((struct sockaddr *)(x))
#define	SIN(x)		((struct sockaddr_in *)(x))
#define	SINADDR(x)	(SIN(x)->sin_addr.s_addr)
#define	atomic_read(x) atomic_add_int_nv(x, 0)

struct l2t_data *
t4_init_l2t(struct adapter *sc)
{
	int i, l2t_size;
	struct l2t_data *d;

	l2t_size = sc->vres.l2t.size;
	if(l2t_size < 1)
		return (NULL);

	d = kmem_zalloc(sizeof(*d) + l2t_size * sizeof (struct l2t_entry), KM_SLEEP);
	if (!d)
		return (NULL);

	d->l2t_size = l2t_size;

	d->rover = d->l2tab;
	(void) atomic_swap_uint(&d->nfree, l2t_size);
	rw_init(&d->lock, NULL, RW_DRIVER, NULL);

	for (i = 0; i < l2t_size; i++) {
		/* LINTED: E_ASSIGN_NARROW_CONV */
		d->l2tab[i].idx = i;
		d->l2tab[i].state = L2T_STATE_UNUSED;
		mutex_init(&d->l2tab[i].lock, NULL, MUTEX_DRIVER, NULL);
		(void) atomic_swap_uint(&d->l2tab[i].refcnt, 0);
	}

	return (d);
}

int
t4_free_l2t(struct l2t_data *d)
{
	int i;

	for (i = 0; i < L2T_SIZE; i++)
		mutex_destroy(&d->l2tab[i].lock);
	rw_destroy(&d->lock);
	kmem_free(d, sizeof (*d));

	return (0);
}
