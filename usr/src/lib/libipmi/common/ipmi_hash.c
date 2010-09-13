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

#include <strings.h>

#include <assert.h>
#include <ipmi_impl.h>
#include <string.h>
#include <strings.h>

/*
 * The (prime) number 137 happens to have the nice property that -- when
 * multiplied by two and added to 33 -- one gets a pretty long series of
 * primes:
 *
 *   307, 647, 1327, 2687, 5407, 10847, 21727, 43487
 *
 * And beyond 43487, the numbers in the series have few factors or are prime.
 * That is, one can have a prime number and roughly double it to get another
 * prime number -- but the series starts at 137.  A size of 137 buckets doesn't
 * particularly accommodate small hash tables, but we note that 13 also yields
 * a reasonable sequence when doubling it and adding 5:
 *
 *   13, 31, 67, 139, 283, 571
 *
 * So we start with this second sequence, crossing over to the first when
 * the size is greater than 137.  (And when reducing the size of the hash
 * table, we cross back when the size gets below 67.)
 */
#define	IPMI_HASHCROSSOVER	137
#define	IPMI_HASHCROSSUNDER	67
#define	IPMI_HASHMINSIZE		13

static ulong_t
ipmi_hash_double(ulong_t size)
{
	ulong_t nsize;

	if (size < IPMI_HASHCROSSOVER) {
		nsize = (size * 2) + 5;
		return (nsize < IPMI_HASHCROSSOVER ? nsize :
		    IPMI_HASHCROSSOVER);
	}

	return ((size * 2) + 33);
}

static ulong_t
ipmi_hash_half(ulong_t size)
{
	ulong_t nsize;

	if (size > IPMI_HASHCROSSUNDER) {
		nsize = (size - 33) / 2;
		return (nsize > IPMI_HASHCROSSUNDER ? nsize :
		    IPMI_HASHCROSSUNDER);
	}

	nsize = (size - 5) / 2;

	return (nsize > IPMI_HASHMINSIZE ? nsize : IPMI_HASHMINSIZE);
}

ipmi_hash_t *
ipmi_hash_create(ipmi_handle_t *hp, size_t linkoffs,
    const void *(*convert)(const void *elem),
    ulong_t (*compute)(const void *key),
    int (*compare)(const void *lkey, const void *rkey))
{
	ipmi_hash_t *ihp;

	if ((ihp = ipmi_zalloc(hp, sizeof (ipmi_hash_t))) == NULL)
		return (NULL);

	ihp->ih_handle = hp;
	ihp->ih_nbuckets = IPMI_HASHMINSIZE;
	ihp->ih_linkoffs = linkoffs;
	ihp->ih_convert = convert;
	ihp->ih_compute = compute;
	ihp->ih_compare = compare;

	if ((ihp->ih_buckets = ipmi_zalloc(hp,
	    ihp->ih_nbuckets * sizeof (void *))) == NULL) {
		ipmi_free(hp, ihp);
		return (NULL);
	}

	return (ihp);
}

void
ipmi_hash_destroy(ipmi_hash_t *ihp)
{
	if (ihp != NULL) {
		ipmi_free(ihp->ih_handle, ihp->ih_buckets);
		ipmi_free(ihp->ih_handle, ihp);
	}
}

ulong_t
ipmi_hash_strhash(const void *key)
{
	ulong_t g, h = 0;
	const char *p;

	for (p = key; *p != '\0'; p++) {
		h = (h << 4) + *p;

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

int
ipmi_hash_strcmp(const void *lhs, const void *rhs)
{
	return (strcmp(lhs, rhs));
}

ulong_t
ipmi_hash_ptrhash(const void *key)
{
	return (*((const uintptr_t *)key) >> 4);
}

int
ipmi_hash_ptrcmp(const void *lhs, const void *rhs)
{
	const uintptr_t *l = lhs, *r = rhs;

	return (*l == *r ? 0 : -1);
}


static ulong_t
ipmi_hash_compute(ipmi_hash_t *ihp, const void *elem)
{
	return (ihp->ih_compute(ihp->ih_convert(elem)) % ihp->ih_nbuckets);
}

static void
ipmi_hash_resize(ipmi_hash_t *ihp, ulong_t nsize)
{
	size_t osize = ihp->ih_nbuckets;
	ipmi_handle_t *hp = ihp->ih_handle;
	ipmi_hash_link_t *link, **nbuckets;
	ulong_t idx, nidx;

	assert(nsize >= IPMI_HASHMINSIZE);

	if (nsize == osize)
		return;

	if ((nbuckets = ipmi_zalloc(hp, nsize * sizeof (void *))) == NULL) {
		/*
		 * This routine can't fail, so we just eat the failure here.
		 * The consequences of this failing are only for performance;
		 * correctness is not affected by our inability to resize
		 * the hash table.
		 */
		return;
	}

	ihp->ih_nbuckets = nsize;

	for (idx = 0; idx < osize; idx++) {
		while ((link = ihp->ih_buckets[idx]) != NULL) {
			void *elem;

			/*
			 * For every hash element, we need to remove it from
			 * this bucket, and rehash it given the new bucket
			 * size.
			 */
			ihp->ih_buckets[idx] = link->ihl_next;
			elem = (void *)((uintptr_t)link - ihp->ih_linkoffs);
			nidx = ipmi_hash_compute(ihp, elem);

			link->ihl_next = nbuckets[nidx];
			nbuckets[nidx] = link;
		}
	}

	ipmi_free(hp, ihp->ih_buckets);
	ihp->ih_buckets = nbuckets;
}

void *
ipmi_hash_lookup(ipmi_hash_t *ihp, const void *search)
{
	ulong_t idx = ihp->ih_compute(search) % ihp->ih_nbuckets;
	ipmi_hash_link_t *hl;

	for (hl = ihp->ih_buckets[idx]; hl != NULL; hl = hl->ihl_next) {
		void *elem = (void *)((uintptr_t)hl - ihp->ih_linkoffs);

		if (ihp->ih_compare(ihp->ih_convert(elem), search) == 0)
			return (elem);
	}

	return (NULL);
}

void *
ipmi_hash_first(ipmi_hash_t *ihp)
{
	void *link = ipmi_list_next(&(ihp)->ih_list);

	if (link == NULL)
		return (NULL);

	return ((void *)((uintptr_t)link - ihp->ih_linkoffs));
}

void *
ipmi_hash_next(ipmi_hash_t *ihp, void *elem)
{
	void *link = ipmi_list_next((uintptr_t)elem + ihp->ih_linkoffs);

	if (link == NULL)
		return (NULL);

	return ((void *)((uintptr_t)link - ihp->ih_linkoffs));
}

void
ipmi_hash_insert(ipmi_hash_t *ihp, void *elem)
{
	ipmi_hash_link_t *link = (void *)((uintptr_t)elem + ihp->ih_linkoffs);
	ulong_t idx = ipmi_hash_compute(ihp, elem);

	assert(ipmi_hash_lookup(ihp, ihp->ih_convert(elem)) == NULL);

	link->ihl_next = ihp->ih_buckets[idx];
	ihp->ih_buckets[idx] = link;

	ipmi_list_append(&ihp->ih_list, link);

	if (++ihp->ih_nelements > ihp->ih_nbuckets / 2)
		ipmi_hash_resize(ihp, ipmi_hash_double(ihp->ih_nbuckets));
}

void
ipmi_hash_remove(ipmi_hash_t *ihp, void *elem)
{
	ulong_t idx = ipmi_hash_compute(ihp, elem);
	ipmi_hash_link_t *link = (void *)((uintptr_t)elem + ihp->ih_linkoffs);
	ipmi_hash_link_t **hlp = &ihp->ih_buckets[idx];

	for (; *hlp != NULL; hlp = &(*hlp)->ihl_next) {
		if (*hlp == link)
			break;
	}

	assert(*hlp != NULL);
	*hlp = (*hlp)->ihl_next;

	ipmi_list_delete(&ihp->ih_list, link);

	assert(ihp->ih_nelements > 0);

	if (--ihp->ih_nelements < ihp->ih_nbuckets / 4)
		ipmi_hash_resize(ihp, ipmi_hash_half(ihp->ih_nbuckets));
}

size_t
ipmi_hash_count(ipmi_hash_t *ihp)
{
	return (ihp->ih_nelements);
}
