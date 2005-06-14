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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "lgrp.h"
#include "cpupart_mdb.h"

#include <sys/cpuvar.h>
#include <sys/cpupart.h>

/* ARGSUSED */
static int
cpupart_cpulist_callback(uintptr_t addr, const void *arg, void *cb_data)
{
	cpu_t *cpu = (cpu_t *)arg;

	ulong_t *cpuset = cb_data;

	BT_SET(cpuset, cpu->cpu_id);

	return (WALK_NEXT);
}

/* ARGSUSED */
int
cpupart(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	cpupart_t cpupart;
	int cpusetsize;
	int _ncpu;
	ulong_t *cpuset;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("cpupart_walk", "cpupart", argc, argv)
		    == -1) {
			mdb_warn("can't walk 'cpupart'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%3s %?s %4s %4s\n",
		    "ID",
		    "ADDR",
		    "#CPU",
		    "CPUS");
	}

	if (mdb_vread(&cpupart, sizeof (cpupart_t), addr) == -1) {
		mdb_warn("unable to read 'cpupart_t' at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%3d %?p %4d ",
	    cpupart.cp_id,
	    addr,
	    cpupart.cp_ncpus);

	if (cpupart.cp_ncpus == 0) {
		mdb_printf("\n");
		return (DCMD_OK);
	}

	/*
	 * figure out what cpus we've got
	 */


	if (mdb_readsym(&_ncpu, sizeof (int), "_ncpu") == -1) {
		mdb_warn("symbol '_ncpu' not found");
		return (DCMD_ERR);
	}

	/*
	 * allocate enough space for set of longs to hold cpuid bitfield
	 */

	cpusetsize = BT_BITOUL(_ncpu) * sizeof (ulong_t);
	cpuset = mdb_zalloc(cpusetsize, UM_SLEEP | UM_GC);

	if (mdb_pwalk("cpupart_cpulist", cpupart_cpulist_callback, cpuset,
	    addr) == -1) {
		mdb_warn("unable to walk cpupart_cpulist");
		return (DCMD_ERR);
	}

	print_cpuset_range(cpuset, cpusetsize/sizeof (ulong_t), 0);

	mdb_printf("\n");

	return (DCMD_OK);
}

typedef struct cpupart_cpulist_walk {
	uintptr_t	ccw_firstcpu;
	int 		ccw_cpusleft;
} cpupart_cpulist_walk_t;

int
cpupart_cpulist_walk_init(mdb_walk_state_t *wsp)
{
	cpupart_cpulist_walk_t *ccw;
	cpupart_t cpupart;

	ccw = mdb_alloc(sizeof (cpupart_cpulist_walk_t), UM_SLEEP | UM_GC);

	if (mdb_vread(&cpupart, sizeof (cpupart_t), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read 'cpupart' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	ccw->ccw_firstcpu = (uintptr_t)cpupart.cp_cpulist;
	ccw->ccw_cpusleft = cpupart.cp_ncpus;

	wsp->walk_data = ccw;
	wsp->walk_addr = ccw->ccw_firstcpu;

	return (WALK_NEXT);
}

int
cpupart_cpulist_walk_step(mdb_walk_state_t *wsp)
{
	cpupart_cpulist_walk_t *ccw = (cpupart_cpulist_walk_t *)
	    wsp->walk_data;
	uintptr_t addr = wsp->walk_addr;
	cpu_t cpu;
	int status;

	if (mdb_vread(&cpu, sizeof (cpu_t), addr) == -1) {
		mdb_warn("couldn't read 'cpupart' at %p", addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(addr, &cpu, wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	addr = (uintptr_t)cpu.cpu_next_part;
	wsp->walk_addr = addr;

	ccw->ccw_cpusleft--;

	if (ccw->ccw_cpusleft < 0) {
		mdb_warn("cpu count doesn't match cpupart list");
		return (WALK_ERR);
	}

	if (ccw->ccw_firstcpu == addr) {
		if (ccw->ccw_cpusleft != 0) {
			mdb_warn("cpu count doesn't match cpupart list");
			return (WALK_ERR);
		}
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

int
cpupart_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t addr;

	if (mdb_lookup_by_name("cp_default", &sym) == -1) {
		mdb_warn("failed to find 'cp_default'\n");
		return (WALK_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	wsp->walk_data = (void *)addr;
	wsp->walk_addr = addr;

	return (WALK_NEXT);
}

int
cpupart_walk_step(mdb_walk_state_t *wsp)
{
	cpupart_t cpupart;
	int status;

	if (mdb_vread(&cpupart, sizeof (cpupart_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("unable to read cpupart at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &cpupart,
	    wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	wsp->walk_addr = (uintptr_t)cpupart.cp_next;

	if (wsp->walk_addr == (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	return (WALK_NEXT);

}
