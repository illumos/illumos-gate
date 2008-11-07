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
#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/hsvc.h>
#include <sys/machsystm.h>
#include <sys/ksynch.h>
#include <sys/hypervisor_api.h>
#include <sys/n2rng.h>
#include <sys/sha1.h>
#include <sys/ddi.h>  /* near end to get min and max macros right */
#include <sys/sunddi.h>
#include <rng/fips_random.h>

/* n must be a power of 2 */
#define	ROUNDUP(k, n)		(((k) + (n) - 1) & ~((n) - 1))

/*
 * Policy.  ENTROPY_STARVATION is the maximum number of calls each
 * FIPS instance will accept without successfully getting more
 * entropy.  It needs to be large enough to allow RNG operations to
 * not stall because of health checks, etc.  But we don't want it too
 * large.  FIPS 186-2 change 1 (5 October 2001) states that no more
 * that 2,000,000 DSA signatures (done using this algorithm) should be
 * done without reseeding.  We make sure we add 64 bits of entropy at
 * most every 10000 operations, hence we will have stirred in 160 bits
 * of entropy at most once every 30000 operations.  Normally, we stir
 * in 64 bits of entropy for every number generated.
 */
#define	ENTROPY_STARVATION	10000ULL


int
fips_random(n2rng_t *n2rng, uint8_t *out, size_t nbytes)
{
	int			i;
	fipsrandomstruct_t	*frsp;
	int			rv;
	union {
		uint32_t	as32[SHA1WORDS];
		uint64_t	as64[ROUNDUP(SHA1WORDS, 2) >> 1];
	} entropy = {0};
	uint32_t		tempout[SHA1WORDS];


	for (i = 0; i < nbytes; i += SHA1BYTES) {
		frsp = &n2rng->n_frs.fipsarray[
		    atomic_inc_32_nv(&n2rng->n_frs.fips_round_robin_j) %
		    N2RNG_FIPS_INSTANCES];
		/*
		 * Since in the new scheme of things, the RNG latency
		 * will be high on reads after the first, we get just
		 * one word of entropy per call.
		 */
		if ((rv = n2rng_getentropy(n2rng, (void *)&entropy.as64[1],
		    sizeof (uint64_t))) != 0) {

			/*
			 * If all rngs have failed, dispatch task to unregister
			 * from kcf and put the driver in an error state.  If
			 * recoverable errors persist, a configuration retry
			 * will be initiated.
			 */
			if (rv == EPERM) {
				n2rng_failure(n2rng);
				return (EIO);
			}
			/* Failure with possible recovery */
			entropy.as64[1] = 0;
		}

		/*
		 * The idea here is that a Niagara2 chip is highly
		 * parallel, with many strands.  If we have just one
		 * instance of the FIPS data, then only one FIPS
		 * computation can happen at a time, serializeing all
		 * the RNG stuff.  So we make N2RNG_FIPS_INSTANCES,
		 * and use them round-robin, with the counter being
		 * n2rng->n_frs.fips_round_robin_j.  We increment the
		 * counter with an atomic op, avoiding having to have
		 * a global muxtex.  The atomic ops are also
		 * significantly faster than mutexes.  The mutex is
		 * put inside the loop, otherwise one thread reading
		 * many blocks could stall all other strands.
		 */
		frsp = &n2rng->n_frs.fipsarray[
		    atomic_inc_32_nv(&n2rng->n_frs.fips_round_robin_j) %
		    N2RNG_FIPS_INSTANCES];

		mutex_enter(&frsp->mtx);

		if (entropy.as64[1] == 0) {
			/*
			 * If we did not get any entropy, entropyword
			 * is zero.  We get a false positive with
			 * probablitity 2^-64.  It's not worth a few
			 * extra stores and tests eliminate the false
			 * positive.
			 */
			if (++frsp->entropyhunger > ENTROPY_STARVATION) {
				mutex_exit(&frsp->mtx);
				n2rng_unconfigured(n2rng);
				return (EIO);
			}
		} else {
			frsp->entropyhunger = 0;
		}

		/* nbytes - i is bytes to go */
		fips_random_inner(frsp->XKEY, tempout, entropy.as32);
		bcopy(tempout, &out[i], min(nbytes - i,  SHA1BYTES));

		mutex_exit(&frsp->mtx);
	}

	/* Zeroize sensitive information */

	entropy.as64[1] = 0;
	bzero(tempout, SHA1BYTES);

	return (0);
}

/*
 * Initializes one FIPS RNG instance.  Must be called once for each
 * instance.
 */
int
n2rng_fips_random_init(n2rng_t *n2rng, fipsrandomstruct_t *frsp)
{
	/*
	 * All FIPS-approved algorithms will operate as cryptograpic
	 * quality PRNGs even if there is no entropy source.  (In
	 * fact, this the only one that accepts entropy on the fly.)
	 * One motivation for this is that they system keeps on
	 * delivering cryptographic quality random numbers, even if
	 * the entropy source fails.
	 */

	int rv;

	rv = n2rng_getentropy(n2rng, (void *)frsp->XKEY, ROUNDUP(SHA1BYTES, 8));
	if (rv) {
		return (rv);
	}
	frsp->entropyhunger = 0;
	mutex_init(&frsp->mtx, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

void
n2rng_fips_random_fini(fipsrandomstruct_t *frsp)
{
	mutex_destroy(&frsp->mtx);
	/*
	 * Zeroise fips data.  Not really necessary, since the
	 * algorithm has backtracking resistance, but do it anyway.
	 */
	bzero(frsp, sizeof (fipsrandomstruct_t));
}
