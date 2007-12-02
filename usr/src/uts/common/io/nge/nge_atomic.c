/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file may contain confidential information of Nvidia
 * and should not be distributed in source form without approval
 * from Sun Legal.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	} while (cas64(count_p, oldval, newval) != oldval);

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
	} while (cas64(count_p, oldval, newval) != oldval);
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
	} while (cas32(sp, oldval, newval) != oldval);

	return (oldval);
}
