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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/hsvc.h>
#include <sys/machsystm.h>
#include <sys/param.h>
#include <sys/hypervisor_api.h>
#include <sys/n2rng.h>

/*
 * There are 3 noise cells each with its own oscillator, and each
 * oscillator can be set to 4 different bias setttings.  The bias
 * setting controls the nominal frequency of the oscillator.  The 3
 * and 4 and hardcoded throughout this file.
 */

#define	BITS_IN(type) (8 * sizeof (type))
#define	EXTRACTBIT64(val, bit) (((val) >> (bit)) & 1UL)

/*
 * Policy settings
 */
/* Log2 of the number of bits */
#define	SETTLECYCLES		1000000
#define	NORMAL_BYPASS		1
#define	NUMOSC			3
#define	LOG2_DATA_WORDS		15
#define	DATA_WORDS		(1 << LOG2_DATA_WORDS)

#define	ENTROPY_PASS_VALUE	150000000ULL

/*
 * There is a hardware bug that causes the RNG_DATA register to
 * occasionally be read one cycle before the specifed time.
 * LOGIC_TEST_EXPECTED_M1 is the value one cycle before
 * LOGIC_TEST_CYCLES.  And there is a second bug that causes the read
 * to be delayed.  We have seen delays of about 150 cycles, but do not
 * know that maximum that could possibly occur.
 *
 * We collect LOGIC_TEST_WORDS words using a diagnostic read with all
 * entropy turned off.  The first one we skip, becuase we have no
 * knowledge of the time since the last read.  We check that the
 * remaining values fall in the window of values that should occur
 * between LOGIC_TEST_CYCLES - 1 and LOGIC_TEST_CYCLES +
 * LOGIC_TEST_BUG_MAX.  As further protecion against false positives,
 * we report success if the the number of mismatches does not exceed
 * LOGIC_TEST_ERRORS_ALLOWED.
 */

#define	LOGIC_TEST_CYCLES	38859
#define	LOGIC_TEST_EXPECTED_M1	0xb8820c7bd387e32cULL
#define	LOGIC_TEST_BUG_MAX	400
#define	LOGIC_TEST_WORDS	8 /* includes first one, unused */
#define	LOGIC_TEST_ERRORS_ALLOWED 1
#define	RNG_POLY		0x231dcee91262b8a3ULL
#define	ENTDIVISOR		(((1ULL << LOG_VAL_SCALE) + 500ULL) / 1000ULL)

#define	ENCODEBIAS(osc, bias)	(((bias) & 0x3) << (2 * (osc)))
#define	EXTRACTBIAS(blob, osc)	(((blob) >> (2 * (osc))) & 0x3)

extern int n2rng_herr2kerr(uint64_t hv_errcode);


/*
 * Each value is a representation of the polynomail bit_i * x^i, where
 * i=0 corresponds to the least significant bit of the word.  The
 * modulus polynomial is x^64 + the interpretation of poly.  Out is
 * set to in * x^exp mod moduluspolynomial.  This corresponds to
 * running the LFSR exp cycles.  This implemenation directly simulates
 * the lfsr.  It's running time is O(exp), but the constant is small.
 * (This code was taken verbatim from Legion.)
 */
static void
lfsr64_adv_seq(uint64_t poly, uint64_t in, uint64_t exp, uint64_t *out)
{
	int		i;
	uint64_t	res = in;

	for (i = 0; i < exp; i++) {
		if (res & 0x8000000000000000ULL) {
			res = (res << 1) ^ poly;
		} else {
			res <<= 1;
		}
	}

	*out = res;
}


int
n2rng_logic_test(n2rng_t *n2rng)
{
	n2rng_setup_t	logictest;
	uint64_t	buffer[LOGIC_TEST_WORDS];
	uint64_t	reg;
	int		rv;
	int		i, j;
	int		correctcount = 0;

	/*
	 * This test runs the RNG with no entropy for
	 * LOGIC_TEST_CYCLES cycles.  Ideally the value would be be
	 * LOGIC_TEST_RESULT, but because of the RNG bug, the actual
	 * register read may be delayed by upto LOGIC_TEST_BUG_MAX
	 * cycles.  So we simulate over that window, and a match
	 * occurs, we report success.
	 */

	logictest.ctlwds[0].word = 0;
	logictest.ctlwds[0].fields.rnc_anlg_sel = N2RNG_NOANALOGOUT;
	logictest.ctlwds[1] = logictest.ctlwds[0];
	logictest.ctlwds[2] = logictest.ctlwds[0];
	logictest.ctlwds[3] = logictest.ctlwds[0];
	logictest.ctlwds[3].fields.rnc_mode = 1;
	logictest.ctlwds[3].fields.rnc_cnt = LOGIC_TEST_CYCLES - 2;

	/* read LOGIC_TEST_WORDS 64-bit words */


	rv = n2rng_collect_diag_bits(n2rng, &logictest, buffer,
	    LOGIC_TEST_WORDS * sizeof (uint64_t),
	    &n2rng->n_preferred_config, n2rng->n_rng_state);
	if (rv) {
		cmn_err(CE_WARN,
		    "n2rng: n2rng_collect_diag_bits fails with 0x%x", rv);
		return (rv);
	}

	reg = LOGIC_TEST_EXPECTED_M1;
	for (i = 0; i <= LOGIC_TEST_BUG_MAX; i++) {
		for (j = 1; j < LOGIC_TEST_WORDS; ++j) {
			if (buffer[j] == reg) {
				++correctcount;
			}
		}
		/* advance reg by one step */
		lfsr64_adv_seq(RNG_POLY, reg, 1, &reg);
	}

	if (correctcount < LOGIC_TEST_WORDS - 1 - LOGIC_TEST_ERRORS_ALLOWED) {
		cmn_err(CE_WARN, "n2rng: logic error in rng.");
		return (EIO);
	}

	return (0);
}


/*
 * gets the metric for the specified state.
 */
int
n2rng_collect_metrics(n2rng_t *n2rng, n2rng_setup_t *setupp,
    n2rng_setup_t *exit_setupp,
    uint64_t exit_state, n2rng_osc_perf_t *metricp)
{
	int		rv;
	int		bufsize;
	uint64_t	*buffer = NULL;


	bufsize = DATA_WORDS * sizeof (uint64_t);
	buffer = (uint64_t *)contig_mem_alloc_align(bufsize,
	    CONTIG_ALIGNMENT);
	if (buffer == NULL) {
		return (ENOMEM);
	}

	rv = n2rng_collect_diag_bits(n2rng, setupp, buffer, bufsize,
	    exit_setupp, exit_state);
	if (rv) {
		cmn_err(CE_WARN,
		    "n2rng: n2rng_collect_bits returns 0x%x", rv);
	} else {
		n2rng_renyi_entropy(buffer, LOG2_DATA_WORDS, metricp);
	}

	contig_mem_free(buffer, bufsize);

	return (rv);
}


/*
 * Fills in table with the performance of each oscillator at each
 * bias setting.  A particular datum goes in table[osc][bias].
 */
int
collect_rng_perf(n2rng_t *n2rng, n2rng_osc_perf_table_t ptable)
{
	int		bias;
	int		osc;
	n2rng_setup_t	rngstate;
	int		rv;

	rngstate.ctlwds[0].word = 0;
	rngstate.ctlwds[0].fields.rnc_anlg_sel = N2RNG_NOANALOGOUT;
	rngstate.ctlwds[1] = rngstate.ctlwds[0];
	rngstate.ctlwds[2] = rngstate.ctlwds[0];
	rngstate.ctlwds[3] = rngstate.ctlwds[0];

	for (osc = 0; osc < N2RNG_NOSC; osc++) {
		rngstate.ctlwds[3].fields.rnc_selbits = 1 << osc;
		for (bias = 0; bias < N2RNG_NBIASES; bias++) {
			rngstate.ctlwds[3].fields.rnc_vcoctl = bias;
			rv = n2rng_collect_metrics(n2rng, &rngstate,
			    &n2rng->n_preferred_config,
			    n2rng->n_rng_state,
			    &(ptable[osc][bias]));
			if (rv) {
				return (rv);
			}
		}
	}

	return (rv);
}



/*
 * The following 2 functions test the performance of each noise cell
 * and select the bias settings.  They implement the following
 * policies:
 *
 * 1. No two cells may be set to the same bias. (Cells with the same bias,
 *    which controls frequency, may beat together, with long
 *    runs of no entropy as a pair when they are nearly synchronized.)
 * 2. The entropy of each cell is determined (for now) by the Renyi H2
 *    entropy of a collection of samples of raw bits.
 * 3. The selected configuration is the one that has the largest total
 *    entropy, computed as stated above.
 * 4. The delay is hard coded.
 */


/*
 * Finds the preferred configuration from perf data.  Sets the
 * preferred configuration in the n2rng structure.
 */
int
n2rng_noise_gen_preferred(n2rng_t *n2rng)
{
	int			rv;
	int			rventropy = 0; /* EIO if entropy is too low */
	int			b0, b1, b2;
	int			osc;
	int			bset;
	n2rng_osc_perf_t	*candidates[N2RNG_NOSC];
	uint64_t		bestcellentropy[N2RNG_NOSC] = {0};
	uint64_t		bestentropy = 0;
	n2rng_ctl_t		rng_ctl = {0};
	int			i;

	rv = collect_rng_perf(n2rng, n2rng->n_perftable);
	if (rv) {
		return (rv);
	}

	/*
	 * bset is the bias setting of all 3 oscillators packed into a
	 * word, 2 bits for each: b2:b1:b0.  First we set up an
	 * arbitrary assignement, because in an earlier version of
	 * this code, there were cases where the assignment would
	 * never happen.  Also, that way we don't need to prove
	 * assignment to prove we never have uninitalized variables,
	 * and hence it might avoid lint warnings.
	 *
	 * This block of code picks the "best" setting of the biases,
	 * where "best" is defined by the rules in the big comment
	 * block above.
	 *
	 * There are only 24 possible combinations such that no two
	 * oscillators get the same bias.  We just do a brute force
	 * exhaustive search of the entire space.
	 */
	bset = ENCODEBIAS(2, 2) | ENCODEBIAS(1, 1) | ENCODEBIAS(0, 0);
	for (b0 = 0; b0 < N2RNG_NBIASES; b0++) {
		candidates[0] = &n2rng->n_perftable[0][b0];
		for (b1 = 0; b1 < N2RNG_NBIASES; b1++) {
			if (b0 == b1) continue;
			candidates[1] = &n2rng->n_perftable[1][b1];
			for (b2 = 0; b2 < N2RNG_NBIASES; b2++) {
				uint64_t totalentropy = 0;

				if (b0 == b2 || b1 == b2) continue;
				candidates[2] = &n2rng->n_perftable[2][b2];
				for (i = 0; i < N2RNG_NOSC; i++) {
					totalentropy += candidates[i]->H2;
				}
				if (totalentropy > bestentropy) {
					bestentropy = totalentropy;
					bset = ENCODEBIAS(0, b0) |
					    ENCODEBIAS(1, b1) |
					    ENCODEBIAS(2, b2);
					for (i = 0; i < N2RNG_NOSC; i++) {
						bestcellentropy[i] =
						    candidates[i]->H2;
					}

				}

			}
		}
	}

	if (bestentropy < ENTROPY_PASS_VALUE) {
		cmn_err(CE_WARN,
		    "n2rng: RNG hardware producing insufficient "
		    "entropy (producing %ld, need %lld)",
		    bestentropy, ENTROPY_PASS_VALUE);
		rventropy = EIO;
	}

	/*
	 * Set up fields of control words that will be the same for all
	 * osciallators and for final value that selects all
	 * oscillators.
	 */
	rng_ctl.fields.rnc_cnt = RNG_DEFAULT_ACCUMULATE_CYCLES;
	rng_ctl.fields.rnc_mode = 1;  /* set normal mode */
	rng_ctl.fields.rnc_anlg_sel = N2RNG_NOANALOGOUT;


	/*
	 * Now set the oscillator biases.
	 */
	for (osc = 0; osc < N2RNG_NOSC; osc++) {
		rng_ctl.fields.rnc_selbits = 1 << osc;
		rng_ctl.fields.rnc_vcoctl = EXTRACTBIAS(bset, osc);
		n2rng->n_preferred_config.ctlwds[osc] = rng_ctl;
	}

	rng_ctl.fields.rnc_cnt = RNG_DEFAULT_ACCUMULATE_CYCLES;
	rng_ctl.fields.rnc_vcoctl = 0;
	rng_ctl.fields.rnc_selbits = 0x7;
	n2rng->n_preferred_config.ctlwds[3] = rng_ctl;

	/*
	 * Log the entropy and bias setting for the admin and security
	 * auditors.
	 */
	if (rventropy == 0) {
		cmn_err(CE_NOTE,
		    "!n2rng: RNG passes, "
		    "cell 0 bias %d: %ld, "
		    "cell 1 bias %d: %ld, "
		    "cell 2 bias %d: %ld",
		    EXTRACTBIAS(bset, 0),
		    (uint64_t)(bestcellentropy[0] / ENTDIVISOR),
		    EXTRACTBIAS(bset, 1),
		    (uint64_t)(bestcellentropy[1] / ENTDIVISOR),
		    EXTRACTBIAS(bset, 2),
		    (uint64_t)(bestcellentropy[2] / ENTDIVISOR));

	}

	return (rv ? rv : rventropy);
}



/*
 * Do a logic test, then find and set the best bias confuration
 * (failing if insufficient entropy is generated, then set state to
 * configured.
 */
int
n2rng_do_health_check(n2rng_t *n2rng)
{
	int		rv;
	int		hverr;

	/* Take control of RNG */
	do {
		hverr = hv_rng_get_diag_control();
		rv = n2rng_herr2kerr(hverr);
	} while (hverr == H_EWOULDBLOCK);

	if (hverr)
		return (rv);

	rv = n2rng_logic_test(n2rng);
	if (rv) {
		return (rv);
	}

	rv = n2rng_noise_gen_preferred(n2rng);
	if (rv) {
		return (rv);
	}

	/* Push the selected config into HW */
	rv = n2rng_collect_diag_bits(n2rng, NULL, NULL, 0,
	    &n2rng->n_preferred_config, CTL_STATE_CONFIGURED);
	if (rv) {
		return (rv);
	}

	n2rng->n_rng_state = CTL_STATE_CONFIGURED;

	return (rv);
}
