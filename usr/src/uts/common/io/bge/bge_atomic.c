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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "bge_impl.h"

/*
 * Atomically decrement a counter, but only if it will remain
 * strictly positive (greater than zero) afterwards.  We return
 * the decremented value if so, otherwise zero (in which case
 * the counter is unchanged).
 *
 * This is used for keeping track of available resources such
 * as transmit ring slots ...
 */
uint64_t
bge_atomic_reserve(uint64_t *count_p, uint64_t n)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval - n;
		if (oldval <= n)
			return (0);		/* no resources left	*/
	} while (atomic_cas_64(count_p, oldval, newval) != oldval);

	return (newval);
}

/*
 * Atomically increment a counter
 */
void
bge_atomic_renounce(uint64_t *count_p, uint64_t n)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval + n;
	} while (atomic_cas_64(count_p, oldval, newval) != oldval);
}

/*
 * Atomically claim a slot in a descriptor ring
 */
uint64_t
bge_atomic_claim(uint64_t *count_p, uint64_t limit)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = NEXT(oldval, limit);
	} while (atomic_cas_64(count_p, oldval, newval) != oldval);

	return (oldval);
}

/*
 * Atomically NEXT a 64-bit integer, returning the
 * value it had *before* the NEXT was applied
 */
uint64_t
bge_atomic_next(uint64_t *sp, uint64_t limit)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *sp;
		newval = NEXT(oldval, limit);
	} while (atomic_cas_64(sp, oldval, newval) != oldval);

	return (oldval);
}

/*
 * Atomically decrement a counter
 */
void
bge_atomic_sub64(uint64_t *count_p, uint64_t n)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval - n;
	} while (atomic_cas_64(count_p, oldval, newval) != oldval);
}

/*
 * Atomically clear bits in a 64-bit word, returning
 * the value it had *before* the bits were cleared.
 */
uint64_t
bge_atomic_clr64(uint64_t *sp, uint64_t bits)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *sp;
		newval = oldval & ~bits;
	} while (atomic_cas_64(sp, oldval, newval) != oldval);

	return (oldval);
}

/*
 * Atomically shift a 32-bit word left, returning
 * the value it had *before* the shift was applied
 */
uint32_t
bge_atomic_shl32(uint32_t *sp, uint_t count)
{
	uint32_t oldval;
	uint32_t newval;

	/* ATOMICALLY */
	do {
		oldval = *sp;
		newval = oldval << count;
	} while (atomic_cas_32(sp, oldval, newval) != oldval);

	return (oldval);
}
