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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"
#include "gnu_prime.h"


/*
 * hashpjw
 *
 * Calculates the hash value from the specified string.
 * Actual hashid will be mod(hash value, PRIME_NUMBER).
 *
 * Ref: Compilers - Principles, Techniques, and Tools
 * Aho, Sethi, and Ullman
 */
unsigned int
hashpjw(const char *str)
{
	const char	*p;
	unsigned int	h = 0, g;

	for (p = str; *p; p++) {
		h = (h << 4) + *p;
		g = h & 0xf0000000;
		if (g) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}

	return (h);
}

static unsigned int
find_prime_big(unsigned int n)
{
	int	t;
	unsigned int	max_tbl_prime, prd;
	max_tbl_prime = prime[MAX_PRIME_INDEX] + 2;

	for (; ; ) {
		for (t = 1; t <= MAX_PRIME_INDEX; t++) {
			if (n % prime[t] == 0) {
				/* n is not a prime number */
				break;
			}
		}
		if (t <= MAX_PRIME_INDEX) {
			n += 2;
			continue;
		}

		prd = max_tbl_prime;
		while ((prd * prd < n) && (n % prd != 0)) {
			prd += 2;
		}
		if (n % prd == 0) {
			n += 2;
			continue;
		}
		return (n);
	}
	/* NOTREACHED */
}

unsigned int
find_prime(unsigned int tbl_size)
{
	int	t, d;
	unsigned int	n, prd;

	/* for compatibility with GNU msgfmt */
	if (tbl_size == 1)
		return (1);
	else if (tbl_size == 2)
		return (5);

	n = 4 * tbl_size / 3;

	/* make n an odd number */
	n |= 1;

	prd = n / 100;
	if (prd <= MAX_INDEX_INDEX) {
		/* first, search the table */
		for (t = index[prd] + 1; t <= MAX_PRIME_INDEX; t++) {
			if (prime[t] >= n)
				return (prime[t]);
		}
		error(ERR_PRIME, n);
		/* NOTREACHED */
	}
	t = START_SEARCH_INDEX;
	for (; ; ) {
		while (prime[t] * prime[t] < n) {
			if (t == MAX_PRIME_INDEX) {
				return (find_prime_big(n));
			}
			t++;
		}
		for (d = 1; d <= t; d++) {
			if (n % prime[d] == 0) {
				/* n is not a prime number */
				break;
			}
		}
		if (d > t) {
			/* n is a prime number */
			return (n);
		}
		n += 2;
	}
	/* NOTREACHED */
}

unsigned int
get_hash_index(unsigned int *hash_tbl, unsigned int hash_value,
	unsigned int hash_size)
{
	unsigned int	idx, inc;

	idx = hash_value % hash_size;
	inc = 1 + (hash_value % (hash_size - 2));

	for (; ; ) {
		if (!hash_tbl[idx])
			return (idx);
		idx = (idx + inc) % hash_size;
	}
	/* NOTREACHED */
}
