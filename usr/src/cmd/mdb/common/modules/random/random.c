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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/random.h>

/*
 * rnd_stats dcmd - Print out the global rnd_stats structure, nicely formatted.
 */
/*ARGSUSED*/
static int
rnd_get_stats(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rnd_stats_t rnd_stats, rnd_stats_cpu;
	uint32_t random_max_ncpus;
	size_t rndmag_pad_t_size;
	ulong_t rndmag_t_offset;
	uintptr_t rndmag;
	int i;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&rnd_stats, "rnd_stats") == -1) {
		mdb_warn("failed to read rnd_stats structure");
		return (DCMD_ERR);
	}

	if (((rndmag_t_offset = mdb_ctf_offsetof_by_name("rndmag_t", "rm_stats")) == -1) ||
	    (mdb_readvar(&random_max_ncpus, "random_max_ncpus") == -1) ||
	    (mdb_readvar(&rndmag, "rndmag") == -1) ||
	    ((rndmag_pad_t_size = mdb_ctf_sizeof_by_name("rndmag_pad_t")) == -1)) {
		/* Can't find per-cpu stats.  Don't add them in. */
		random_max_ncpus = 0;
	}

	/*
	 * Read and aggregate per-cpu stats if we have them.
	 */
	for (i = 0; i < random_max_ncpus; i++) {
		mdb_vread(&rnd_stats_cpu, sizeof (rnd_stats_cpu),
		    rndmag + rndmag_t_offset + i * rndmag_pad_t_size);

		rnd_stats.rs_rndOut += rnd_stats_cpu.rs_rndOut;
		rnd_stats.rs_rndcOut += rnd_stats_cpu.rs_rndcOut;
		rnd_stats.rs_urndOut += rnd_stats_cpu.rs_urndOut;
	}

	mdb_printf("Random number device statistics:\n");

	mdb_printf("%8llu bytes generated for /dev/random\n",
	    rnd_stats.rs_rndOut);
	mdb_printf("%8llu bytes read from /dev/random cache\n",
	    rnd_stats.rs_rndcOut);
	mdb_printf("%8llu bytes generated for /dev/urandom\n",
	    rnd_stats.rs_urndOut);

	return (DCMD_OK);
}

/*
 * swrand_stats dcmd - Print out the global swrand_stats structure,
 * nicely formatted.
 */
/*ARGSUSED*/
static int
swrand_get_stats(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	swrand_stats_t swrand_stats;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (mdb_readvar(&swrand_stats, "swrand_stats") == -1) {
		mdb_warn("failed to read swrand_stats structure");
		return (DCMD_ERR);
	}

	mdb_printf("Software-based Random number generator statistics:\n");

	mdb_printf("%8u bits of entropy estimate\n", swrand_stats.ss_entEst);
	mdb_printf("%8llu bits of entropy added to the pool\n",
	    swrand_stats.ss_entIn);
	mdb_printf("%8llu bits of entropy extracted from the pool\n",
	    swrand_stats.ss_entOut);
	mdb_printf("%8llu bytes added to the random pool\n",
	    swrand_stats.ss_bytesIn);
	mdb_printf("%8llu bytes extracted from the random pool\n",
	    swrand_stats.ss_bytesOut);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "rnd_stats",
	    NULL,
	    "print random number device statistics",
	    rnd_get_stats },
	{ "swrand_stats",
	    NULL,
	    "print kernel random number provider statistics",
	    swrand_get_stats },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
