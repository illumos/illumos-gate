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

#include <stdio.h>
#include <fcntl.h>
#include <math.h>
#include "filebench.h"
#include "ipc.h"
#include "gamma_dist.h"

static int urandomfd;

/*
 * Reads a 64 bit random number from the urandom "file".
 * Shuts down the run if the read fails. Otherwise returns
 * the random number after rounding it off by "round".
 * Returns 0 on success, -1 on failure.
 */
int
filebench_randomno64(uint64_t *randp, uint64_t max,
    uint64_t round, avd_t avd)
{
	uint64_t random;

	/* check for round value too large */
	if (max <= round) {
		*randp = 0;

		/* if it just fits, its ok, otherwise error */
		if (max == round)
			return (0);
		else
			return (-1);
	}

	if (avd) {

		/* get it from the variable */
		random = avd_get_int(avd);

	} else {

		/* get it from urandom */
		if (read(urandomfd, &random,
		    sizeof (uint64_t)) != sizeof (uint64_t)) {
			filebench_log(LOG_ERROR,
			    "read /dev/urandom failed: %s", strerror(errno));
			filebench_shutdown(1);
		}
	}

	/* clip with max and optionally round */
	max -= round;
	random = random / (FILEBENCH_RANDMAX64 / max);
	if (round) {
		random = random / round;
		random *= round;
	}
	if (random > max)
		random = max;

	*randp = random;
	return (0);
}


/*
 * Reads a 32 bit random number from the urandom "file".
 * Shuts down the run if the read fails. Otherwise returns
 * the random number after rounding it off by "round".
 * Returns 0 on success, -1 on failure.
 */
int
filebench_randomno32(uint32_t *randp, uint32_t max,
    uint32_t round, avd_t avd)
{
	uint32_t random;

	/* check for round value too large */
	if (max <= round) {
		*randp = 0;

		/* if it just fits, its ok, otherwise error */
		if (max == round)
			return (0);
		else
			return (-1);
	}

	if (avd) {

		/* get it from the variable */
		random = (uint32_t)avd_get_int(avd);

	} else {

		/* get it from urandom */
		if (read(urandomfd, &random,
		    sizeof (uint32_t)) != sizeof (uint32_t)) {
			filebench_log(LOG_ERROR,
			    "read /dev/urandom failed: %s", strerror(errno));
			filebench_shutdown(1);
		}
	}

	/* clip with max and optionally round */
	max -= round;
	random = random / (FILEBENCH_RANDMAX32 / max);
	if (round) {
		random = random / round;
		random *= round;
	}
	if (random > max)
		random = max;

	*randp = random;
	return (0);
}

/*
 * fetch a source random number from the pseudo random number generator:
 * erand48()
 */
static double
rand_src_rand48(unsigned short *xi)
{
	return (erand48(xi));
}

/*
 * fetch a source random number from the hardware random number device:
 * urandomfd. Convert it to a floating point probability.
 */
/* ARGSUSED */
static double
rand_src_urandom(unsigned short *xi)
{
	fbint_t randnum;

	if (read(urandomfd, &randnum,
	    sizeof (fbint_t)) != sizeof (fbint_t)) {
		filebench_log(LOG_ERROR,
		    "read /dev/urandom failed: %s", strerror(errno));
		filebench_shutdown(1);
		return (0.0);
	}

	/* convert to 0-1 probability */
	return ((double)randnum / (double)(FILEBENCH_RANDMAX64));
}

/*
 * fetch a uniformly distributed random number from the supplied
 * random object.
 */
static double
rand_uniform_get(randdist_t *rndp)
{
	double		dprob, dmin, dres, dround;

	dmin = (double)rndp->rnd_vint_min;
	dround = (double)rndp->rnd_vint_round;

	dprob = (*rndp->rnd_src)(rndp->rnd_xi);

	dres = (dprob * (2.0 * (rndp->rnd_dbl_mean - dmin))) + dmin;

	if (dround == 0.0)
		return (dres);
	else
		return (round(dres / dround) * dround);
}

/*
 * fetch a gamma distributed random number from the supplied
 * random object.
 */
static double
rand_gamma_get(randdist_t *rndp)
{
	double		dmult, dres, dmin, dround;

	dmin = (double)rndp->rnd_vint_min;
	dround = (double)rndp->rnd_vint_round;

	dmult = (rndp->rnd_dbl_mean - dmin) / rndp->rnd_dbl_gamma;

	dres = gamma_dist_knuth_src(rndp->rnd_dbl_gamma,
	    dmult, rndp->rnd_src, rndp->rnd_xi) + dmin;

	if (dround == 0.0)
		return (dres);
	else
		return (round(dres / dround) * dround);
}

/*
 * fetch a table driven random number from the supplied
 * random object.
 */
static double
rand_table_get(randdist_t *rndp)
{
	double		dprob, dprcnt, dtabres, dsclres, dmin, dround;
	int		idx;

	dmin = (double)rndp->rnd_vint_min;
	dround = (double)rndp->rnd_vint_round;

	dprob = (*rndp->rnd_src)(rndp->rnd_xi);

	dprcnt = (dprob * (double)(PF_TAB_SIZE));
	idx = (int)dprcnt;

	dtabres = (rndp->rnd_rft[idx].rf_base +
	    (rndp->rnd_rft[idx].rf_range * (dprcnt - (double)idx)));

	dsclres = (dtabres * (rndp->rnd_dbl_mean - dmin)) + dmin;

	if (dround == 0.0)
		return (dsclres);
	else
		return (round(dsclres / dround) * dround);
}

/*
 * Set the random seed in the supplied random object.
 */
static void
rand_seed_set(randdist_t *rndp)
{
	union {
		uint64_t  ll;
		uint16_t  w[4];
	} temp1;
	int  idx;

	temp1.ll = (uint64_t)avd_get_int(rndp->rnd_seed);

	for (idx = 0; idx < 3; idx++) {

#ifdef _BIG_ENDIAN
		rndp->rnd_xi[idx] = temp1.w[3-idx];
#else
		rndp->rnd_xi[idx] = temp1.w[idx];
#endif
	}
}

/*
 * Define a random entity which will contain the parameters of a random
 * distribution.
 */
randdist_t *
randdist_alloc(void)
{
	randdist_t *rndp;

	if ((rndp = (randdist_t *)ipc_malloc(FILEBENCH_RANDDIST)) == NULL) {
		filebench_log(LOG_ERROR, "Out of memory for random dist");
		return (NULL);
	}

	/* place on global list */
	rndp->rnd_next = filebench_shm->shm_rand_list;
	filebench_shm->shm_rand_list = rndp;

	return (rndp);
}

/*
 * Initializes a random distribution entity, converting avd_t
 * parameters to doubles, and converting the list of probability density
 * function table entries, if supplied, into a probablilty function table
 */
static void
randdist_init_one(randdist_t *rndp)
{
	probtabent_t	*rdte_hdp, *ptep;
	double		tablemean, tablemin;
	int		pteidx;

	/* convert parameters to doubles */
	rndp->rnd_dbl_mean  = (double)avd_get_int(rndp->rnd_mean);
	rndp->rnd_dbl_gamma = (double)avd_get_int(rndp->rnd_gamma) / 1000.0;

	rndp->rnd_vint_min  = avd_get_int(rndp->rnd_min);
	rndp->rnd_vint_round  = avd_get_int(rndp->rnd_round);

	filebench_log(LOG_DEBUG_IMPL,
	    "init random var %s: Mean = %6.0llf, Gamma = %6.3llf, Min = %lld",
	    rndp->rnd_var->var_name, rndp->rnd_dbl_mean, rndp->rnd_dbl_gamma,
	    rndp->rnd_vint_min);

	/* initialize distribution to apply */
	switch (rndp->rnd_type & RAND_TYPE_MASK) {
	case RAND_TYPE_UNIFORM:
		rndp->rnd_get = rand_uniform_get;
		break;

	case RAND_TYPE_GAMMA:
		rndp->rnd_get = rand_gamma_get;
		break;

	case RAND_TYPE_TABLE:
		rndp->rnd_get = rand_table_get;
		break;

	default:
		filebench_log(LOG_DEBUG_IMPL, "Random Type not Specified");
		filebench_shutdown(1);
		return;
	}

	/* initialize source of random numbers */
	if (rndp->rnd_type & RAND_SRC_GENERATOR) {
		rndp->rnd_src = rand_src_rand48;
		rand_seed_set(rndp);
	} else {
		rndp->rnd_src = rand_src_urandom;
	}

	/* any random distribution table to convert? */
	if ((rdte_hdp = rndp->rnd_probtabs) == NULL)
		return;

	/* determine random distribution max and mins and initialize table */
	pteidx = 0;
	tablemean = 0.0;
	for (ptep = rdte_hdp; ptep; ptep = ptep->pte_next) {
		double	dmin, dmax;
		int	entcnt;

		dmax = (double)avd_get_int(ptep->pte_segmax);
		dmin = (double)avd_get_int(ptep->pte_segmin);

		/* initialize table minimum on first pass */
		if (pteidx == 0)
			tablemin = dmin;

		/* update table minimum */
		if (tablemin > dmin)
			tablemin = dmin;

		entcnt = (int)avd_get_int(ptep->pte_percent);
		tablemean += (((dmin + dmax)/2.0) * (double)entcnt);

		/* populate the lookup table */

		for (; entcnt > 0; entcnt--) {
			rndp->rnd_rft[pteidx].rf_base = dmin;
			rndp->rnd_rft[pteidx].rf_range = dmax - dmin;
			pteidx++;
		}
	}

	/* check to see if probability equals 100% */
	if (pteidx != PF_TAB_SIZE)
		filebench_log(LOG_ERROR,
		    "Prob table only totals %d%%", pteidx);

	/* If table is not supplied with a mean value, set it to table mean */
	if (rndp->rnd_dbl_mean == 0.0)
		rndp->rnd_dbl_mean = (double)tablemean / (double)PF_TAB_SIZE;

	/* now normalize the entries for a min value of 0, mean of 1 */
	tablemean = (tablemean / 100.0) - tablemin;

	/* special case if really a constant value */
	if (tablemean == 0.0) {
		for (pteidx = 0; pteidx < PF_TAB_SIZE; pteidx++) {
			rndp->rnd_rft[pteidx].rf_base = 0.0;
			rndp->rnd_rft[pteidx].rf_range = 0.0;
		}
		return;
	}

	for (pteidx = 0; pteidx < PF_TAB_SIZE; pteidx++) {

		rndp->rnd_rft[pteidx].rf_base =
		    ((rndp->rnd_rft[pteidx].rf_base - tablemin) / tablemean);
		rndp->rnd_rft[pteidx].rf_range =
		    (rndp->rnd_rft[pteidx].rf_range / tablemean);
	}
}

/*
 * initialize all the random distribution entities
 */
void
randdist_init(void)
{
	randdist_t *rndp;

	for (rndp = filebench_shm->shm_rand_list; rndp; rndp = rndp->rnd_next)
		randdist_init_one(rndp);
}

/*
 * Initialize the urandom random number source
 */
void
fb_random_init(void)
{
	/* open the "urandom" random number device file */
	if ((urandomfd = open("/dev/urandom", O_RDONLY)) < 0) {
		filebench_log(LOG_ERROR, "open /dev/urandom failed: %s",
		    strerror(errno));
		filebench_shutdown(1);
	}
}
