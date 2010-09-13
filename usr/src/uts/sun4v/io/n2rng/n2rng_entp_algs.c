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


#include <sys/ddi.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/n2rng.h>
#include <sys/int_types.h>


/*
 * This whole file is really doing floating point type stuff, and
 * would be quite simple in user space.  But since we are in the
 * kernel, (a) we can't use floating point, and (b) we don't have a
 * math library.
 */

/* used inside msb */
#define	MSBSTEP(word, shift, counter)  \
if (word & (~0ULL << shift)) {	       \
	word >>= shift;		       \
	counter += shift;	       \
}

/*
 * returns the position of the MSB of x.  The 1 bit is position 0.  An
 * all zero arg returns -1.
 */
static int
msb(uint64_t x)
{
	int		bit;

	if (x == 0) {
		return (-1);
	}

	bit = 0;
	MSBSTEP(x, 32, bit);
	MSBSTEP(x, 16, bit);
	MSBSTEP(x, 8, bit);
	MSBSTEP(x, 4, bit);
	MSBSTEP(x, 2, bit);
	MSBSTEP(x, 1, bit);

	return (bit);
}

/*
 * lg2 computes 2^(LOG_VAL_SCALE) * log2(x/2^LOG_ARG_SCALE), where ^
 * is exponentiation.
 *
 * The following conditions must be satisfied: LOG_VAL_SCALE <= 62,
 * LOG_VAL_SCALE + log2(maxarg) < 64, LOG_VAL_SCALE >= 0,
 * LOG_ARG_SCALE <= 63.  Recommended LOG_VAL_SCALE is 57, which is the
 * largest value such that overflow is impossible.
 */
static int64_t
lg2(uint64_t x)
{
	/*
	 * logtable[i-1] == round(2^63 * log2(2^i/(2^i - 1))), where ^
	 * is exponentiation.
	 */
	static const uint64_t logtable[] = {
		9223372036854775808ULL, 3828045265094622256ULL,
		1776837224931603046ULL, 858782676832593460ULL,
		422464469962470743ULL, 209555718266071751ULL,
		104365343613858422ULL, 52080352580344565ULL,
		26014696649359209ULL, 13000990870918027ULL,
		6498907625079429ULL, 3249057053828501ULL,
		1624429361456373ULL, 812189892390238ULL,
		406088749488886ULL, 203042825615163ULL,
		101521025531171ULL, 50760415947221ULL,
		25380183769112ULL, 12690085833443ULL,
		6345041403945ULL, 3172520323778ULL,
		1586260067341ULL, 793130010033ULL,
		396564999107ULL, 198282498076ULL,
		99141248669ULL, 49570624242ULL,
		24785312098ULL, 12392656043ULL, 6196328020ULL, 3098164010ULL,
		1549082005ULL, 774541002ULL, 387270501ULL, 193635251ULL,
		96817625ULL, 48408813ULL, 24204406ULL, 12102203ULL, 6051102ULL,
		3025551ULL, 1512775ULL, 756388ULL, 378194ULL, 189097ULL,
		94548ULL, 47274ULL, 23637ULL, 11819ULL, 5909ULL, 2955ULL,
		1477ULL, 739ULL, 369ULL, 185ULL, 92ULL, 46ULL, 23ULL,
		12ULL, 6ULL, 3ULL, 1ULL
	};

	uint64_t	xx;
	uint64_t	logx;
	uint64_t	tmp;
	int		i;

	if (x == 0) {
		return (-INT64_MAX - 1);
	}

	/*
	 * Invariant: log2(xx) + logx == log2(x).  This is true at the after
	 * the normalization.  At each adjustment step we multiply xx by
	 * (2^i-1)/2^i, which effectively decreases log2(xx) by
	 * log2(2^i/(2^i-1)), and a the same time, we add table[i], which
	 * equals log2(2^i/(2^i-1)), to logx.  By induction the invariant is
	 * true at the end.  At the end xx==1, so log2(xx)==0, and thus
	 * logx=log2(x);
	 */
	/* Normalize */
	i = msb(x); /* use i in computing preshift */
	if (i - LOG_ARG_SCALE > 0) {
		xx = x >> (i - LOG_ARG_SCALE);
	} else {
		xx = x << (LOG_ARG_SCALE - i);
	}
	logx = (int64_t)(i - LOG_ARG_SCALE) << LOG_VAL_SCALE;

	for (i = 1; i <= LOG_ARG_SCALE;	 i++) {
		/* 1ULL << (i-1) is rounding */
		while ((tmp = xx - ((xx + (1ULL << (i-1))) >> i)) >=
		    1ULL << LOG_ARG_SCALE) {
			xx = tmp;
			/* 1ULL << (63 - LOG_VAL_SCALE -1) is rounding */
			logx += (logtable[i-1] +
			    (1ULL << (63 - LOG_VAL_SCALE - 1))) >>
			    (63 - LOG_VAL_SCALE);
		}
	}

	return (logx);
}



/*
 * The EXCHANGE macro swaps entries j & k if necessary so that
 * data[j] <= data[k].
 *
 * If OBLIVIOUS is defined, no branches are used.  This would allow
 * this algorithm to be used by the CPU manufacturing people who run
 * on a tester that requires the exact same instruction address stream
 * on every test. (It's a bit slower with OBLIVIOUS defined.)
 */
#ifdef OBLIVIOUS
#define	EXCHANGE(j, k)			\
	{				\
		uint64_t tmp, mask;	\
		mask = (uint64_t)(((int64_t)(data[k] - data[j])) >> 63); \
		tmp = data[j] + data[k];			\
		data[j] = data[k] & mask | data[j] & ~mask;	\
		data[k] = tmp - data[j];			\
	}
#else
#define	EXCHANGE(j, k)				\
	{					\
		uint64_t tmp;			\
		if (data[j] > data[k]) {	\
			tmp = data[j];		\
			data[j] = data[k];	\
			data[k] = tmp;		\
		}				\
	}
#endif



/*
 * This is a Batcher sort from Knuth v. 3.  There is no flow control
 * that depends on the values being sorted, except in the EXCHANGE
 * step, but that can be made oblivious to the data values, too, by
 * setting OBLIVIOUS.  So this code could be using in chip testers
 * that require fixed flow through a test.
 *
 * This is presently hard-coded for sorting uint64_t values.
 */
void
n2rng_sort(uint64_t *data, int log2_size)
{
	int p, q, d, r, i;

	for (p = 1 << (log2_size - 1); p > 0; p >>= 1) {
		d = p;
		r = 0;
		for (q = 1 << (log2_size - 1); q >= p; q >>= 1) {
			for (i = 0; i + d < (1 << log2_size); i++) {
				if ((i & p) == r) {
					EXCHANGE(i, i+d);
				}
			}
			d = q - p;
			r = p;
		}
	}
}


/*
 * Computes several measures of entropy per word: Renyi H0 (log2 of
 * number of distinct symbols), Renyi H1 (Shannon),
 * Renyi H2 (-log2 of sum(P_i^2)), and
 * Renyi H-infinity (min).  The results are coded as H *
 * 2^LOG_VAL_SCALE).  The samples array is modified by sorting in
 * place.
 *
 * None if this is really valid, since it requres that the block
 * length be at least as long as the largest non-approximately-zero
 * coefficient in the autocorrelation function, and that the number
 * of samples be much larger than 2^longest_block_length_in_bits.
 * But we hope that bigger is better, even when it is invalid.
 */
void
n2rng_renyi_entropy(uint64_t *samples, int lg2samples, n2rng_osc_perf_t *entp)
{
	size_t i;
	uint64_t cv = samples[0]; /* current value */
	size_t count = 1;
	size_t numdistinct = 0;
	size_t largestcount = 0;
	uint64_t shannonsum = 0;
	uint64_t sqsum = 0;

	n2rng_sort(samples, lg2samples);

	for (i = 1; i < (1 << lg2samples); i++) {
		if (samples[i] != cv) {
			numdistinct++;
			if (count > largestcount) {
				largestcount = count;
			}
#ifdef COMPUTE_SHANNON_ENTROPY
			shannonsum -= (count * (lg2(count) +
			    ((int64_t)(LOG_ARG_SCALE - lg2samples) <<
			    LOG_VAL_SCALE))) >> lg2samples;
#endif /* COMPUTE_SHANNON_ENTROPY */
			sqsum += count * count;
			count = 1;
			cv = samples[i];
		} else {
			count++;
		}
	}
	/* process last block */
	numdistinct++;
	if (count > largestcount) {
		largestcount = count;
	}
#ifdef COMPUTE_SHANNON_ENTROPY
	shannonsum -= (count * (lg2(count) +
	    ((int64_t)(LOG_ARG_SCALE - lg2samples) << LOG_VAL_SCALE))) >>
	    lg2samples;
#endif /* COMPUTE_SHANNON_ENTROPY */
	sqsum += count * count;

	entp->numvals = numdistinct;
	/* H1 is shannon entropy: -sum(p_i * log2(p_i)) */
	entp->H1 = shannonsum / 64;
	/* H2 is -log2(sum p_i^2) */
	entp->H2 = -(lg2(sqsum) +
	    ((int64_t)(LOG_ARG_SCALE - 2 * lg2samples) << LOG_VAL_SCALE)) / 64;
	/* Hinf = -log2(highest_probability) */
	entp->Hinf = -(lg2(largestcount) +
	    ((int64_t)(LOG_ARG_SCALE - lg2samples) << LOG_VAL_SCALE)) / 64;
}
