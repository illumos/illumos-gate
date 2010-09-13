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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>

#include <sys/param.h>
#include <sys/tihdr.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_listutils.h>

/*
 * These functions perform set operations on sets of ipv6 addresses.
 * The sets are formatted as slist_t's (defined in <inet/ip.h>):
 *	typedef struct slist_s {
 *		int		sl_nusmrc;
 *		in6_addr_t	sl_addr[MAX_FILTER_SIZE];
 *	} slist_t;
 *
 * The functions were designed specifically for the implementation of
 * IGMPv3 and MLDv2 in ip; they were not meant to be general-purpose.
 */

/*
 * Tells if lists A and B are different or not - true if different;
 * caller guarantees that lists are <= MAX_FILTER_SIZE
 */
boolean_t
lists_are_different(const slist_t *a, const slist_t *b)
{
	int i, j;
	int acnt = SLIST_CNT(a);
	int bcnt = SLIST_CNT(b);
	boolean_t found;

	if (acnt != bcnt)
		return (B_TRUE);

	ASSERT(acnt <= MAX_FILTER_SIZE);
	ASSERT(bcnt <= MAX_FILTER_SIZE);

	for (i = 0; i < acnt; i++) {
		found = B_FALSE;
		for (j = 0; j < bcnt; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &a->sl_addr[i], &b->sl_addr[j])) {
				found = B_TRUE;
				break;
			}
		}
		if (!found)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Tells if list a contains address addr - true if it does, false if not;
 * caller guarantees that list is <= MAX_FILTER_SIZE.
 */
boolean_t
list_has_addr(const slist_t *a, const in6_addr_t *addr)
{
	int i;

	if (SLIST_IS_EMPTY(a))
		return (B_FALSE);

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);

	for (i = 0; i < a->sl_numsrc; i++) {
		if (IN6_ARE_ADDR_EQUAL(&a->sl_addr[i], addr))
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Implements a * b and stores the result in target; caller guarantees
 * that a and b are <= MAX_FILTER_SIZE, and that target is a valid pointer.
 * target must not be the same as a or b; for that case see
 * l_intersection_in_a().
 */
void
l_intersection(const slist_t *a, const slist_t *b, slist_t *target)
{
	int i, j;

	target->sl_numsrc = 0;

	if (SLIST_IS_EMPTY(a) || SLIST_IS_EMPTY(b))
		return;

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);
	ASSERT(b->sl_numsrc <= MAX_FILTER_SIZE);

	for (i = 0; i < a->sl_numsrc; i++) {
		for (j = 0; j < b->sl_numsrc; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &a->sl_addr[i], &b->sl_addr[j])) {
				target->sl_addr[target->sl_numsrc++] =
				    a->sl_addr[i];
				break;
			}
		}
	}
}

/*
 * Implements a - b and stores the result in target; caller guarantees
 * that a and b are <= MAX_FILTER_SIZE, and that target is a valid pointer.
 * target must not be the same as a or b; for that case see l_difference_in_a().
 */
void
l_difference(const slist_t *a, const slist_t *b, slist_t *target)
{
	int i, j;
	boolean_t found = B_FALSE;

	target->sl_numsrc = 0;

	if (SLIST_IS_EMPTY(a))
		return;

	if (SLIST_IS_EMPTY(b)) {
		l_copy(a, target);
		return;
	}

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);
	ASSERT(b->sl_numsrc <= MAX_FILTER_SIZE);

	for (i = 0; i < a->sl_numsrc; i++) {
		for (j = 0; j < b->sl_numsrc; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &a->sl_addr[i], &b->sl_addr[j])) {
				found = B_TRUE;
				break;
			}
		}
		if (!found) {
			target->sl_addr[target->sl_numsrc++] = a->sl_addr[i];
		} else {
			found = B_FALSE;
		}
	}
}

/*
 * Removes addr from list a.  Caller guarantees that addr is a valid
 * pointer, and that a <= MAX_FILTER_SIZE.  addr will only be removed
 * once from the list; if it appears in the list multiple times, extra
 * copies may remain.
 */
void
l_remove(slist_t *a, const in6_addr_t *addr)
{
	int i, mvsize;

	if (SLIST_IS_EMPTY(a))
		return;

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);

	for (i = 0; i < a->sl_numsrc; i++) {
		if (IN6_ARE_ADDR_EQUAL(&a->sl_addr[i], addr)) {
			a->sl_numsrc--;
			mvsize = (a->sl_numsrc - i) * sizeof (in6_addr_t);
			(void) memmove(&a->sl_addr[i], &a->sl_addr[i + 1],
			    mvsize);
			break;
		}
	}
}

/*
 * Make a copy of list a by allocating a new slist_t and copying only
 * a->sl_numsrc addrs.  Caller guarantees that a <= MAX_FILTER_SIZE.
 * Return a pointer to the newly alloc'd list, or NULL if a is empty
 * (no memory is alloc'd in this case).
 */
slist_t *
l_alloc_copy(const slist_t *a)
{
	slist_t *b;

	if (SLIST_IS_EMPTY(a))
		return (NULL);

	if ((b = l_alloc()) == NULL)
		return (NULL);

	l_copy(a, b);

	return (b);
}

/*
 * Copy the address list from slist a into slist b, overwriting anything
 * that might already be in slist b.  Assumes that a <= MAX_FILTER_SIZE
 * and that b points to a properly allocated slist.
 */
void
l_copy(const slist_t *a, slist_t *b)
{
	if (SLIST_IS_EMPTY(a)) {
		b->sl_numsrc = 0;
		return;
	}

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);

	b->sl_numsrc = a->sl_numsrc;
	(void) memcpy(b->sl_addr, a->sl_addr,
	    a->sl_numsrc * sizeof (in6_addr_t));
}

/*
 * Append to a any addrs in b that are not already in a (i.e. perform
 * a + b and store the result in a).  If b is empty, the function returns
 * without taking any action.
 *
 * Caller guarantees that a and b are <= MAX_FILTER_SIZE, and that a
 * and overflow are valid pointers.
 *
 * If an overflow occurs (a + b > MAX_FILTER_SIZE), a will contain the
 * first MAX_FILTER_SIZE addresses of the union, and *overflow will be
 * set to true.  Otherwise, *overflow will be set to false.
 */
void
l_union_in_a(slist_t *a, const slist_t *b, boolean_t *overflow)
{
	int i, j;
	boolean_t found;

	*overflow = B_FALSE;

	if (SLIST_IS_EMPTY(b))
		return;

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);
	ASSERT(b->sl_numsrc <= MAX_FILTER_SIZE);

	for (i = 0; i < b->sl_numsrc; i++) {
		found = B_FALSE;
		for (j = 0; j < a->sl_numsrc; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &b->sl_addr[i], &a->sl_addr[j])) {
				found = B_TRUE;
				break;
			}
		}
		if (!found) {
			if (a->sl_numsrc == MAX_FILTER_SIZE) {
				*overflow = B_TRUE;
				break;
			} else {
				a->sl_addr[a->sl_numsrc++] = b->sl_addr[i];
			}
		}
	}
}

/*
 * Remove from list a any addresses that are not also in list b
 * (i.e. perform a * b and store the result in a).
 *
 * Caller guarantees that a and b are <= MAX_FILTER_SIZE, and that
 * a is a valid pointer.
 */
void
l_intersection_in_a(slist_t *a, const slist_t *b)
{
	int i, j, shift;
	boolean_t found;

	if (SLIST_IS_EMPTY(b)) {
		a->sl_numsrc = 0;
		return;
	}

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);
	ASSERT(b->sl_numsrc <= MAX_FILTER_SIZE);

	shift = 0;
	for (i = 0; i < a->sl_numsrc; i++) {
		found = B_FALSE;
		for (j = 0; j < b->sl_numsrc; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &a->sl_addr[i], &b->sl_addr[j])) {
				found = B_TRUE;
				break;
			}
		}
		if (!found)
			shift++;
		else if (shift > 0)
			a->sl_addr[i - shift] = a->sl_addr[i];
	}
	a->sl_numsrc -= shift;
}

/*
 * Remove from list a any addresses that are in list b (i.e. perform
 * a - b and store the result in a).
 *
 * Caller guarantees that a and b are <= MAX_FILTER_SIZE.  If either
 * list is empty (or a null pointer), the function returns without
 * taking any action.
 */
void
l_difference_in_a(slist_t *a, const slist_t *b)
{
	int i, j, shift;
	boolean_t found;

	if (SLIST_IS_EMPTY(a) || SLIST_IS_EMPTY(b))
		return;

	ASSERT(a->sl_numsrc <= MAX_FILTER_SIZE);
	ASSERT(b->sl_numsrc <= MAX_FILTER_SIZE);

	shift = 0;
	for (i = 0; i < a->sl_numsrc; i++) {
		found = B_FALSE;
		for (j = 0; j < b->sl_numsrc; j++) {
			if (IN6_ARE_ADDR_EQUAL(
			    &a->sl_addr[i], &b->sl_addr[j])) {
				found = B_TRUE;
				break;
			}
		}
		if (found)
			shift++;
		else if (shift > 0)
			a->sl_addr[i - shift] = a->sl_addr[i];
	}
	a->sl_numsrc -= shift;
}

/*
 * Wrapper function to alloc an slist_t.
 */
slist_t *
l_alloc()
{
	slist_t *p;

	p = (slist_t *)mi_alloc(sizeof (slist_t), BPRI_MED);
	if (p != NULL)
		p->sl_numsrc = 0;
	return (p);
}

/*
 * Frees an slist_t structure.  Provided for symmetry with l_alloc().
 */
void
l_free(slist_t *a)
{
	mi_free(a);
}
