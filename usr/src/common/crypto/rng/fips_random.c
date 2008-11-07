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

#include <sys/types.h>
#include <rng/fips_random.h>
#include <sys/sha1.h>

/*
 * Adds val1 and val2 and stores result into sum.  The various input
 * pointers can be exactly aliased.  (They cannot be offset and
 * overlapping, but no one would ever do that.)  Values are big endian
 * by words and native byte order within words.  The return value's
 * 2-bit is 0 if the result is zero, it's 1 bit is carry out.  (This
 * is reused code.  The return code is not used by n2rng.)  Thus,
 * calling with both carryin and complement_val2 ones does a
 * subtraction.  A null sum pointer parameter is allowed.  The
 * subtraction features were required when this code was orginally
 * written so it could do a mod q operation.
 */
static int
fips_add160(uint32_t *sum, uint32_t const *val1, uint32_t const *val2,
    const unsigned carryin, const int complement_val2)
{
	int i;
	uint32_t partialsum;
	uint32_t carry = (carryin > 0);
	uint32_t non_zero = 0;

	for (i = 4; i >= 0; --i) {
		partialsum = val1[i] + (complement_val2 ? ~val2[i] : val2[i]) +
		    carry;
		if (carry) {
			carry = (partialsum <= val1[i]);
		} else {
			carry = (partialsum < val1[i]);
		}
		if (sum) {
			sum[i] = partialsum;
		}
		non_zero |= partialsum;
	}

	return (((non_zero != 0) * 2) | carry);
}

/*
 * Computes a new random value, which is stored in x_j; updates
 * XKEY.  XSEED_j is additional input.  In principle, we should
 * protect XKEY, perhaps by putting it on a non-pagable page, but we
 * aways clobber XKEY with fresh entropy just before we use it.  And
 * step 3d irreversibly updates it just after we use it.  The only
 * risk is that if an attacker captured the state while the entropy
 * generator was broken, the attacker could predict future values.
 * There are two cases: 1.  The attack gets root access to a live
 * system.  But there is no defense against that.  2.  The attacker
 * gets access to a crash dump.  But by then no values are being
 * generated.
 *
 * Note that XSEEDj is overwritten with sensitive stuff, and must be
 * zeroed by the caller.  We use two separate symbols (XVAL and
 * XSEEDj) to make each step match the notation in FIPS 186-2.
 */
void
fips_random_inner(uint32_t *key, uint32_t *x_j,
    uint32_t *XSEED_j)
{
	int		i;
	SHA1_CTX	sha1_context;
	/* Alias to preserve terminology from FIPS 186-2 */
#define	XVAL XSEED_j
	/*
	 * K&R section A8.7: If the array has fixed size, the number
	 * of initializers may not exceed the number of members in the
	 * array; if there are fewer, the trailing members are
	 * initialized with 0.
	 */
	static const char	zero[SHA1BLOCKBYTES - SHA1BYTES] = {0};

	/*
	 * Step 3b: XVAL = (XKEY + XSEED_sub_j) mod 2^b.  The mod is
	 * implicit in the 160 bit representation.  Note that XVAL and
	 * XSEED_j are actually the same location.
	 */
	(void) fips_add160(XVAL, key, XSEED_j, 0, 0);
	/*
	 * Step 3c: x_sub_j = G(t, XVAL).
	 */
	SHA1Init(&sha1_context);
	SHA1Update(&sha1_context, (unsigned char *)XVAL, SHA1BYTES);
	/*
	 * Filling to 64 bytes is requried by FIPS 186-2 Appendix 3.3.
	 * It also triggers SHA1Transform (the steps a-e of the spec).
	 *
	 * zero is a const char[], but SHA1update does not declare its
	 * second parameter const, even though it does not modify it,
	 * so we cast to suppress a compiler warning.
	 */
	SHA1Update(&sha1_context, (unsigned char *)zero,
	    SHA1BLOCKBYTES - SHA1BYTES);
	/*
	 * The code below directly accesses the state field of
	 * sha1_context, which is of type SHA1_CTX, defined in sha1.h.
	 */
	/* copy out to x_j */
	for (i = 0; i < 5; i++) {
		x_j[i] = sha1_context.state[i];
	}
	/*
	 * Step 3d: XKEY = (1 + XKEY + x_sub_j) mod 2^b.  b=160.  The
	 * mod 2^160 is implicit in the 160 bit representation.  The
	 * one is added via the carry-in flag.
	 */
	(void) fips_add160(key, key, x_j, 1, 0);
#undef XVAL
}
