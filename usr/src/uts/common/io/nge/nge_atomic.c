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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "nge.h"

/*
 * Atomically decrement a counter, but only if it will remain
 * positive (>=0) afterwards.
 */
boolean_t
nge_atomic_decrease(uint64_t *count_p, uint64_t n)
{
	uint64_t oldval;
	uint64_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		newval = oldval - n;
		if (oldval < n)
			return (B_FALSE);
	} while (atomic_cas_64(count_p, oldval, newval) != oldval);

	return (B_TRUE);
}

/*
 * Atomically increment a counter
 */
void
nge_atomic_increase(uint64_t *count_p, uint64_t n)
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
 * Atomically shift a 32-bit word left, returning
 * the value it had *before* the shift was applied
 */
uint32_t
nge_atomic_shl32(uint32_t *sp, uint_t count)
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
