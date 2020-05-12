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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <sys/mdb_modapi.h>
#include <sys/cpuvar.h>
#include <sys/machcpuvar.h>
#include <sys/error.h>


/*ARGSUSED*/
int
resumable(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;
	cpu_t cpu;
	uintptr_t current, first;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&first, "cpu_list") == -1) {
		mdb_warn("failed to read 'cpu_list'");
		return (DCMD_ERR);
	}

	if (verbose)
		mdb_printf("CPUID ADDRESS\n");

	current = first;
	do {
		if (mdb_vread(&cpu, sizeof (cpu), current) == -1) {
			mdb_warn("failed to read cpu at %p", current);
			return (DCMD_ERR);
		}

		if (verbose) {
			if (cpu.cpu_m.cpu_rq_lastre == 0)
				mdb_printf("%-5d empty\n", cpu.cpu_id);
			else
				mdb_printf("%-5d %lx\n", cpu.cpu_id,
				    cpu.cpu_m.cpu_rq_lastre);
		} else if (cpu.cpu_m.cpu_rq_lastre != 0)
			mdb_printf("%lx\n", cpu.cpu_m.cpu_rq_lastre);
	} while ((current = (uintptr_t)cpu.cpu_next) != first);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
nonresumable(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;
	cpu_t cpu;
	uintptr_t current, first;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&first, "cpu_list") == -1) {
		mdb_warn("failed to read 'cpu_list'");
		return (DCMD_ERR);
	}

	if (verbose)
		mdb_printf("CPUID ADDRESS\n");

	current = first;
	do {
		if (mdb_vread(&cpu, sizeof (cpu), current) == -1) {
			mdb_warn("failed to read cpu at %p", current);
			return (DCMD_ERR);
		}

		if (verbose) {
			if (cpu.cpu_m.cpu_nrq_lastnre == 0)
				mdb_printf("%-5d empty\n", cpu.cpu_id);
			else
				mdb_printf("%-5d %lx\n", cpu.cpu_id,
				    cpu.cpu_m.cpu_nrq_lastnre);
		} else if (cpu.cpu_m.cpu_nrq_lastnre != 0)
			mdb_printf("%lx\n", cpu.cpu_m.cpu_nrq_lastnre);
	} while ((current = (uintptr_t)cpu.cpu_next) != first);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
rqueue(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;
	cpu_t cpu;
	uintptr_t ao, lower, upper, current;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&cpu, sizeof (cpu_t), addr) == -1) {
		mdb_warn("failed to find cpu at %p", addr);
		return (DCMD_ERR);
	}

	ao = (uintptr_t)cpu.cpu_m.cpu_rq_lastre;	/* beginning and end */
	lower = (uintptr_t)cpu.cpu_m.cpu_rq_va + CPU_RQ_SIZE;
	upper = lower + CPU_RQ_SIZE - Q_ENTRY_SIZE;

	if (ao < lower || upper < ao) {
		if (verbose)
			mdb_printf("empty\n");
		return (DCMD_OK);
	}

	for (current = ao; current >= lower; current -= Q_ENTRY_SIZE)
		mdb_printf("%lx\n", current);

	for (current = upper; current > ao; current -= Q_ENTRY_SIZE)
		mdb_printf("%lx\n", current);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
nrqueue(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = 0;
	cpu_t cpu;
	uintptr_t lower, ao, upper;
	uintptr_t current;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, 1, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&cpu, sizeof (cpu_t), addr) == -1) {
		mdb_warn("failed to find cpu at %p", addr);
		return (DCMD_ERR);
	}

	ao = (uintptr_t)cpu.cpu_m.cpu_nrq_lastnre;	/* beginning and end */
	lower = (uintptr_t)cpu.cpu_m.cpu_nrq_va + CPU_NRQ_SIZE;
	upper = lower + CPU_NRQ_SIZE - Q_ENTRY_SIZE;

	if (ao < lower || upper < ao) {
		if (verbose)
			mdb_printf("empty\n");
		return (DCMD_OK);
	}

	for (current = ao; current >= lower; current -= Q_ENTRY_SIZE)
		mdb_printf("%lx\n", current);

	for (current = upper; current > ao; current -= Q_ENTRY_SIZE)
		mdb_printf("%lx\n", current);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
errh_prtaddr(uintptr_t addr, const void *data, void *private)
{
	mdb_printf("%lx\n", addr);
	return (WALK_NEXT);
}

int
rq_walk_init(mdb_walk_state_t *wsp)
{
	cpu_t cpu;
	uintptr_t *ao, *lower, *upper;

	if (wsp->walk_addr == (uintptr_t)NULL) {
		mdb_warn("address of struct cpu_t is required\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&cpu, sizeof (cpu_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to find cpu at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_callback = (mdb_walk_cb_t)errh_prtaddr;
	wsp->walk_addr = (uintptr_t)cpu.cpu_m.cpu_rq_lastre;
	wsp->walk_data = mdb_alloc(sizeof (uintptr_t) * 3, UM_SLEEP);

	ao = lower = upper = wsp->walk_data;
	lower += 1;
	upper += 2;

	*ao = (uintptr_t)wsp->walk_addr;	/* beginning and end */
	*lower = (uintptr_t)cpu.cpu_m.cpu_rq_va + CPU_RQ_SIZE;
	*upper = (uintptr_t)*lower + CPU_RQ_SIZE - Q_ENTRY_SIZE;

	if (wsp->walk_addr < *lower || *upper < wsp->walk_addr) {
		mdb_free(wsp->walk_data, sizeof (uintptr_t) * 3);
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

int
nrq_walk_init(mdb_walk_state_t *wsp)
{
	cpu_t cpu;
	uintptr_t *ao, *lower, *upper;

	if (wsp->walk_addr == (uintptr_t)NULL) {
		mdb_warn("address of struct cpu_t is required\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&cpu, sizeof (cpu_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to find cpu at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_callback = (mdb_walk_cb_t)errh_prtaddr;
	wsp->walk_addr = (uintptr_t)cpu.cpu_m.cpu_nrq_lastnre;
	wsp->walk_data = mdb_alloc(sizeof (uintptr_t) * 3, UM_SLEEP);

	ao = lower = upper = wsp->walk_data;
	lower += 1;
	upper += 2;

	*ao = (uintptr_t)wsp->walk_addr;	/* beginning and end */
	*lower = (uintptr_t)cpu.cpu_m.cpu_nrq_va + CPU_NRQ_SIZE;
	*upper = (uintptr_t)*lower + CPU_NRQ_SIZE - Q_ENTRY_SIZE;

	if (wsp->walk_addr < *lower || *upper < wsp->walk_addr) {
		mdb_free(wsp->walk_data, sizeof (uintptr_t) * 3);
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

int
errh_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	uintptr_t *ao, *lower, *upper;

	if (wsp->walk_addr == (uintptr_t)NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr -= Q_ENTRY_SIZE;

	ao = lower = upper = wsp->walk_data;
	lower += 1;
	upper += 2;

	if (wsp->walk_addr < *lower)
		wsp->walk_addr = *upper;		/* wrap around */
	else if (wsp->walk_addr == *ao)
		return (WALK_DONE);			/* end of loop */

	return (status);
}

void
errh_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (uintptr_t) * 3);
}

/*
 * MDB module linkage information:
 *
 * Declare a list of structures describing dcmds, and a function
 * named _mdb_init to return a pointer to module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "errhre", "[-v]", "addr of sun4v resumable error element",
	    resumable },
	{ "errhnre", "[-v]", "addr of sun4v nonresumable error element",
	    nonresumable },
	{ "errhrq", ":", "addr of sun4v resumable errors in RQ", rqueue },
	{ "errhnrq", ":", "addr of sun4v nonresumable errors in NRQ", nrqueue },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "errhrq", "walk a cpu-specific sun4v resumble error queue",
	    rq_walk_init, errh_walk_step, errh_walk_fini, NULL },
	{ "errhnrq", "walk a cpu-specific sun4v nonresumble error queue",
	    nrq_walk_init, errh_walk_step, errh_walk_fini, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
