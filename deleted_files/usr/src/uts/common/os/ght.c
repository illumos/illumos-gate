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
 * Generic Hash Table Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/atomic.h>
#include <sys/ght.h>

/*
 * Revelations of the hash table and element structures.
 *
 * ght_t 	->	ght_impl_t *
 * ghte_t	->	ghte_impl_t *
 */
typedef struct ght_impl		ght_impl_t;
typedef struct ghte_impl	ghte_impl_t;

struct ghte_impl {
	ght_key_t	ghtei_key;
	ght_val_t	ghtei_val;
	ghte_impl_t	**ghtei_prevp;
	ghte_impl_t	*ghtei_next;
	ght_impl_t	*ghtei_table;
	boolean_t	ghtei_active;
	uint_t		ghtei_ref;
};

struct ght_impl {
	char		ghti_name[MAXNAMELEN];
	uint_t		ghti_nbuckets;
	uint_t		ghti_entries;
	ghte_impl_t	**ghti_bucket;
	krwlock_t	ghti_lock;
	kmem_cache_t	*ghti_cache;
	uintptr_t	(*ghti_hash)(ght_key_t);
	int		(*ghti_keycmp)(ght_key_t, ght_key_t);
};

static uintptr_t	i_ght_str_hash(ght_key_t);
static int		i_ght_str_keycmp(ght_key_t, ght_key_t);
static uintptr_t	i_ght_scalar_hash(ght_key_t);
static int		i_ght_scalar_keycmp(ght_key_t, ght_key_t);
static int		i_ght_ctor(void *, void *, int);
static void		i_ght_dtor(void *, void *);
static int		i_ght_create(char *, uint_t, uintptr_t (*)(ght_key_t),
    int (*)(ght_key_t, ght_key_t), ght_impl_t **);

#define	GHT_LINKINFO	"Generic Hash Table v%I%"

static struct modlmisc		modlmisc = {
	&mod_miscops,
	GHT_LINKINFO
};

static struct modlinkage	modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Hash function for text string keys
 */
static uintptr_t
i_ght_str_hash(ght_key_t key)
{
	char		*k = (char *)key;
	uintptr_t	hash;

	ASSERT(k != NULL);
	hash = *k++;
	while (*k != '\0') {
		uint_t	g;

		hash = (hash << 4) + *k++;
		if ((g = (hash & 0xf0000000)) == 0)
			continue;

		hash ^= (g >> 24) ^ g;
	}

	return (hash);
}

/*
 * Comparitor for text string keys
 */
static int
i_ght_str_keycmp(ght_key_t key1, ght_key_t key2)
{
	return (strcmp((char *)key1, (char *)key2));
}

/*
 * Hash function for scalar keys
 */
static uintptr_t
i_ght_scalar_hash(ght_key_t key)
{
	return ((uintptr_t)key);
}

/*
 * Comparitor for scalar keys
 */
static int
i_ght_scalar_keycmp(ght_key_t key1, ght_key_t key2)
{
	uintptr_t	k1 = (uintptr_t)key1;
	uintptr_t	k2 = (uintptr_t)key2;

	return ((k1 == k2) ? 0 : ((k1 > k2) ? 1 : -1));
}

/*
 * Cache constructor for hash table entries
 */
/*ARGSUSED*/
static int
i_ght_ctor(void *buf, void *arg, int kmflags)
{
	ghte_impl_t	*ghteip = buf;

	bzero(buf, sizeof (ghte_impl_t));

	ghteip->ghtei_table = (ght_impl_t *)arg;

	return (0);
}

/*
 * Cache destructor for hash table entries
 */
static void
i_ght_dtor(void *buf, void *arg)
{
	ghte_impl_t	*ghteip = buf;

	ASSERT(!(ghteip->ghtei_active));
	ASSERT((void *)ghteip->ghtei_table == arg);
	ASSERT(ghteip->ghtei_next == NULL);
}

/*
 * Create a hash table
 */
static int
i_ght_create(char *name, uint_t nbuckets, uintptr_t (*hash)(ght_key_t),
    int (*keycmp)(ght_key_t, ght_key_t), ght_impl_t **ghtipp)
{
	int		len;
	size_t		size;
	ght_impl_t	*ghtip;

	ASSERT(name != NULL);
	ASSERT(hash != NULL);
	ASSERT(keycmp != NULL);
	ASSERT(ghtipp != NULL);

	if ((len = strlen(name)) >= MAXNAMELEN)
		return (EINVAL);

	size = sizeof (ght_impl_t) + (nbuckets * sizeof (ghte_impl_t));
	ghtip = kmem_zalloc(size, KM_SLEEP);

	(void) strlcpy(ghtip->ghti_name, name, MAXNAMELEN);
	ghtip->ghti_name[len] = '\0';
	ghtip->ghti_bucket = (ghte_impl_t **)&ghtip[1];
	ghtip->ghti_nbuckets = nbuckets;
	ghtip->ghti_entries = 0;
	ghtip->ghti_hash = hash;
	ghtip->ghti_keycmp = keycmp;

	rw_init(&ghtip->ghti_lock, NULL, RW_DRIVER, NULL);
	ghtip->ghti_cache = kmem_cache_create(name, sizeof (ghte_impl_t), 0,
	    i_ght_ctor, i_ght_dtor, NULL, (void *)ghtip, NULL, 0);

	*ghtipp = ghtip;
	return (0);
}

/*
 * External functions.
 */

/*
 * Lock a table.
 */
void
ght_lock(ght_t ght, int flag)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;

	ASSERT(flag == GHT_READ || flag == GHT_WRITE);
	rw_enter(&(ghtip->ghti_lock), (flag == GHT_READ) ? RW_READER :
	    RW_WRITER);
}

/*
 * Unlock a table.
 */
void
ght_unlock(ght_t ght)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;

	rw_exit(&(ghtip->ghti_lock));
}

/*
 * Create a string keyed table.
 */
int
ght_str_create(char *name, uint_t nbuckets, ght_t *ghtp)
{
	ght_impl_t	*ghtip;
	int		err;

	if ((err = i_ght_create(name, nbuckets, i_ght_str_hash,
	    i_ght_str_keycmp, &ghtip)) != 0)
		return (err);

	*ghtp = (ght_t)ghtip;
	return (0);
}

/*
 * Create a scalar keyed table.
 */
int
ght_scalar_create(char *name, uint_t nbuckets, ght_t *ghtp)
{
	ght_impl_t	*ghtip;
	int		err;

	if ((err = i_ght_create(name, nbuckets, i_ght_scalar_hash,
	    i_ght_scalar_keycmp, &ghtip)) != 0)
		return (err);

	*ghtp = (ght_t)ghtip;
	return (0);
}

/*
 * Destroy a table.
 */
int
ght_destroy(ght_t ght)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;
	size_t		size;

	ASSERT(ghtip != NULL);

	if (ghtip->ghti_entries != 0)
		return (EBUSY);

	kmem_cache_destroy(ghtip->ghti_cache);
	rw_destroy(&ghtip->ghti_lock);

	size = sizeof (ght_impl_t) +
	    (ghtip->ghti_nbuckets * sizeof (ghte_impl_t));
	kmem_free(ghtip, size);

	return (0);
}

/*
 * Return the number of entries in a table.
 */
uint_t
ght_count(ght_t ght)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;

	return (ghtip->ghti_entries);
}

/*
 * Allocate a new entry for a table.
 */
ghte_t
ght_alloc(ght_t ght, int kmflags)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;
	ghte_impl_t	*ghteip;

	if ((ghteip = kmem_cache_alloc(ghtip->ghti_cache, kmflags)) == NULL)
		return (NULL);

	return ((ghte_t)ghteip);
}

/*
 * Free a table entry (after it has been removed).
 */
void
ght_free(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;
	ght_impl_t	*ghtip = ghteip->ghtei_table;

	ASSERT(!(ghteip->ghtei_active));
	ASSERT(ghteip->ghtei_ref == 0);

	kmem_cache_free(ghtip->ghti_cache, ghteip);
}

/*
 * Insert an entry into a table.
 */
int
ght_insert(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;
	ght_impl_t	*ghtip = ghteip->ghtei_table;
	ghte_impl_t	**pp;
	ghte_impl_t	*p;
	uint_t		n;

	ASSERT(ghteip != NULL);
	ASSERT(!(ghteip->ghtei_active));
	ASSERT(rw_write_held(&(ghtip->ghti_lock)));

	n = ghtip->ghti_hash(ghteip->ghtei_key) % ghtip->ghti_nbuckets;
	for (pp = &(ghtip->ghti_bucket[n]); (p = *pp) != NULL;
	    pp = &(p->ghtei_next)) {
		if (ghtip->ghti_keycmp(ghteip->ghtei_key, p->ghtei_key) == 0)
			return (EEXIST);
	}

	ghteip->ghtei_next = p;
	ghteip->ghtei_prevp = pp;
	*pp = ghteip;

	ghteip->ghtei_active = B_TRUE;
	ghtip->ghti_entries++;
	return (0);
}

/*
 * Look-up an enrty in a table.
 */
int
ght_find(ght_t ght, ght_key_t key, ghte_t *ghtep)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;
	ghte_impl_t	*p;
	uint_t		n;

	ASSERT(ghtip != NULL);
	ASSERT(rw_read_held(&(ghtip->ghti_lock)) ||
	    rw_write_held(&(ghtip->ghti_lock)));

	n = ghtip->ghti_hash(key) % ghtip->ghti_nbuckets;
	for (p = ghtip->ghti_bucket[n]; p != NULL; p = p->ghtei_next) {
		ASSERT(p->ghtei_active);
		if (ghtip->ghti_keycmp(key, p->ghtei_key) == 0)
			break;
	}
	if (p == NULL)
		return (ENOENT);

	*ghtep = (ghte_t)p;
	return (0);
}

/*
 * Increment the reference count on a hash table entry.
 */
void
ght_hold(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;
	ght_impl_t	*ghtip = ghteip->ghtei_table;

	ASSERT(ghteip->ghtei_active);
	ASSERT(rw_read_held(&(ghtip->ghti_lock)) ||
	    rw_write_held(&(ghtip->ghti_lock)));

	atomic_add_32(&(ghteip->ghtei_ref), 1);
}

/*
 * Decrement the reference count on a hash table entry.
 */
void
ght_rele(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;

	ASSERT(ghteip->ghtei_active);
	ASSERT(ghteip->ghtei_ref != 0);

	atomic_add_32(&(ghteip->ghtei_ref), -1);
}

/*
 * Return the reference count on a hash table entry.
 */
uint_t
ght_ref(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;
	ght_impl_t	*ghtip = ghteip->ghtei_table;

	ASSERT(ghteip->ghtei_active);
	ASSERT(rw_read_held(&(ghtip->ghti_lock)) ||
	    rw_write_held(&(ghtip->ghti_lock)));

	return (ghteip->ghtei_ref);
}

/*
 * Remove an entry from its table.
 */
void
ght_remove(ghte_t ghte)
{
	ghte_impl_t	*ghteip = (ghte_impl_t *)ghte;
	ght_impl_t	*ghtip = ghteip->ghtei_table;
	ghte_impl_t	**pp;
	ghte_impl_t	*p;

	ASSERT(ghteip != NULL);
	ASSERT(ghteip->ghtei_active);
	ASSERT(rw_write_held(&(ghtip->ghti_lock)));

	pp = ghteip->ghtei_prevp;
	p = ghteip->ghtei_next;

	*pp = p;
	if (p != NULL) {
		ASSERT(p->ghtei_prevp == &(ghteip->ghtei_next));
		p->ghtei_prevp = pp;
	}

	ghteip->ghtei_prevp = NULL;
	ghteip->ghtei_next = NULL;

	ghteip->ghtei_active = B_FALSE;
	--ghtip->ghti_entries;
}

/*
 * Walk table entries calling fn() for each one.
 */
void
ght_walk(ght_t ght, boolean_t (*fn)(void *, ghte_t), void *arg)
{
	ght_impl_t	*ghtip = (ght_impl_t *)ght;
	uint_t		n;
	ghte_impl_t	*p;

	ASSERT(ghtip != NULL);
	ASSERT(rw_read_held(&(ghtip->ghti_lock)) ||
	    rw_write_held(&(ghtip->ghti_lock)));
	ASSERT(fn != NULL);

	for (n = 0; n < ghtip->ghti_nbuckets; n++) {
		for (p = ghtip->ghti_bucket[n]; p != NULL; p = p->ghtei_next) {
			ASSERT(p->ghtei_active);
			if (!(fn(arg, (ghte_t)p)))
				return;
		}
	}
}
