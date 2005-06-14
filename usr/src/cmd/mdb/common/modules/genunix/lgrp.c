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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lgrp.h"

#include <mdb/mdb_modapi.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/cpupart.h>

int
print_range(int start, int end, int separator)
{
	int	count;
	char	tmp;
	char	*format;

	if (start == end) {
		/* Unfortunately, mdb_printf returns void */
		format = separator ? ", %d" : "%d";
		mdb_printf(format, start);
		count = mdb_snprintf(&tmp, 1, format, start);
	} else {
		format = separator ? ", %d-%d" : "%d-%d";
		mdb_printf(format, start, end);
		count = mdb_snprintf(&tmp, 1, format, start, end);
	}

	return (count);
}

void
print_cpuset_range(ulong_t *cs, int words, int width)
{
	int i, j;
	ulong_t m;
	int in = 0;
	int start;
	int end;
	int count = 0;
	int sep = 0;

	for (i = 0; i < words; i++)
		for (j = 0, m = 1; j < BT_NBIPUL; j++, m <<= 1)
			if (cs[i] & m) {
				if (in == 0) {
					start = i * BT_NBIPUL + j;
					in = 1;
				}
			} else {
				if (in == 1) {
					end = i * BT_NBIPUL + j - 1;
					count += print_range(start, end, sep);
					sep = 1;
					in = 0;
				}
			}
	if (in == 1) {
		end = i * BT_NBIPUL - 1;
		count += print_range(start, end, sep);
	}

	/*
	 * print width - count spaces
	 */

	if (width > count)
		mdb_printf("%*s", width - count, "");
}
typedef struct lgrp_cpu_walk {
	uintptr_t 	lcw_firstcpu;
	int 		lcw_cpusleft;
} lgrp_cpu_walk_t;

int
lgrp_cpulist_walk_init(mdb_walk_state_t *wsp)
{
	lgrp_cpu_walk_t *lcw;
	lgrp_t		lgrp;

	lcw = mdb_alloc(sizeof (lgrp_cpu_walk_t), UM_SLEEP | UM_GC);

	if (mdb_vread(&lgrp, sizeof (struct lgrp), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read 'lgrp' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	lcw->lcw_firstcpu = (uintptr_t)lgrp.lgrp_cpu;
	lcw->lcw_cpusleft = lgrp.lgrp_cpucnt;

	wsp->walk_data = lcw;
	wsp->walk_addr = lcw->lcw_firstcpu;

	return (WALK_NEXT);
}

int
lgrp_cpulist_walk_step(mdb_walk_state_t *wsp)
{
	lgrp_cpu_walk_t *lcw = (lgrp_cpu_walk_t *)wsp->walk_data;
	uintptr_t addr = (uintptr_t)wsp->walk_addr;
	cpu_t cpu;
	int status;

	if (lcw->lcw_cpusleft-- == 0)
		return (WALK_DONE);

	if (mdb_vread(&cpu, sizeof (cpu_t), addr) == -1) {
		mdb_warn("couldn't read 'cpu' at %p", addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(addr, &cpu, wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	addr = (uintptr_t)cpu.cpu_next_lgrp;
	wsp->walk_addr = addr;

	if (lcw->lcw_cpusleft == NULL && addr != lcw->lcw_firstcpu) {
		mdb_warn("number of cpus in lgroup cpu != lgroup cpucnt\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

typedef struct lgrp_cpuwalk_cbdata {
	uint_t  lcc_opt_p;
	uint_t  lcc_count;
	uint_t  lcc_used;
	uint_t  *lcc_psrsetid;
	ulong_t **lcc_cpuset;
	uint_t  *lcc_cpucnt;
	int	*lcc_loadavg;
} lgrp_cpuwalk_cbdata_t;

/* ARGSUSED */
static int
lgrp_cpuwalk_callback(uintptr_t addr, const void *arg, void *cb_data)
{
	cpu_t *cpu = (cpu_t *)arg;
	lgrp_cpuwalk_cbdata_t *lcc = (lgrp_cpuwalk_cbdata_t *)cb_data;
	uint_t opt_p = lcc->lcc_opt_p;

	int offset = 0;

	/*
	 * if opt_p is set, we're going to break up info for
	 * each lgrp by processor set.
	 */

	if (opt_p != 0) {
		cpupartid_t	cp_id;
		cpupart_t cpupart;
		lpl_t lpl;


		if (mdb_vread(&cpupart, sizeof (cpupart_t),
		    (uintptr_t)cpu->cpu_part) == -1) {
			mdb_warn("cannot read cpu partition at %p",
			    cpu->cpu_part);
			return (WALK_ERR);
		}
		cp_id = cpupart.cp_id;

		for (offset = 0; offset < lcc->lcc_used; offset++)
			if (cp_id == lcc->lcc_psrsetid[offset]) {
				goto found;
			}

		if (offset >= lcc->lcc_count) {
			mdb_warn(
			    "number of cpu partitions changed during walk");
			return (WALK_ERR);
		}

		lcc->lcc_psrsetid[offset] = cp_id;
		lcc->lcc_used++;

		if (mdb_vread(&lpl, sizeof (lpl_t), (uintptr_t)cpu->cpu_lpl)
		    == -1) {
			mdb_warn("Cannot read lpl at %p", cpu->cpu_lpl);
			return (WALK_ERR);
		}

		lcc->lcc_loadavg[offset] = lpl.lpl_loadavg;
	}

found:	lcc->lcc_cpucnt[offset]++;
	BT_SET(lcc->lcc_cpuset[offset], cpu->cpu_id);

	return (WALK_NEXT);
}


/* ARGSUSED */
int
lgrp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	lgrp_t lgrp;
	lgrp_cpuwalk_cbdata_t lcc;
	int cpusetsize;
	int lcpu; /* cpus in lgrp */
	int _ncpu;
	int opt_p = 0; /* display partition fraction loads */
	int opt_q = 0; /* display only address. */
	int i;
	const char *s_index = NULL, *s_handle = NULL, *s_parent = NULL;
	uintptr_t index;
	uintptr_t handle;
	uintptr_t parent;
	int filters = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("lgrptbl", "lgrp", argc, argv) == -1) {
			mdb_warn("can't walk 'lgrps'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, TRUE, &opt_p,
	    'q', MDB_OPT_SETBITS, TRUE, &opt_q,
	    'P', MDB_OPT_STR, &s_parent,
	    'i', MDB_OPT_STR, &s_index,
	    'h', MDB_OPT_STR, &s_handle,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (s_index != NULL)
		filters++;
	if (s_handle != NULL)
		filters++;
	if (s_parent != NULL)
		filters++;

	if (flags & DCMD_PIPE_OUT)
		opt_q = B_TRUE;

	if (s_index != NULL)
		index = mdb_strtoull(s_index);

	if (s_parent != NULL)
		parent = mdb_strtoull(s_parent);

	if (s_handle != NULL) {
		if (strcmp(s_handle, "NULL") == 0)
			handle = (uintptr_t)LGRP_NULL_HANDLE;
		else if (strcmp(s_handle, "DEFAULT") == 0)
			handle = (uintptr_t)LGRP_DEFAULT_HANDLE;
		else
			handle = mdb_strtoull(s_handle);
	}

	if (DCMD_HDRSPEC(flags) && !opt_q) {
		if (opt_p == 0)
			mdb_printf("%9s %?s %?s %?s %9s %9s\n",
			    "LGRPID",
			    "ADDR",
			    "PARENT",
			    "PLATHAND",
			    "#CPU",
			    "CPUS");
		else
			mdb_printf("%9s %9s %9s %9s %9s\n",
			    "LGRPID",
			    "PSRSETID",
			    "LOAD",
			    "#CPU",
			    "CPUS");
	}

	if (mdb_vread(&lgrp, sizeof (struct lgrp), addr) == -1) {
		mdb_warn("unable to read 'lgrp' at %p", addr);
		return (DCMD_ERR);
	}

	/*
	 * Do not report free lgrp unless specifically asked for.
	 */
	if ((lgrp.lgrp_id == LGRP_NONE) &&
	    ((s_index == NULL) || ((int)index != LGRP_NONE)))
		return (DCMD_OK);

	/*
	 * If lgrp doesn't pass filtering criteria, don't print anything and
	 * just return.
	 */
	if (filters) {
		if ((s_parent != NULL) &&
		    parent != (uintptr_t)lgrp.lgrp_parent)
			return (DCMD_OK);
		if ((s_index != NULL) && index != (uintptr_t)lgrp.lgrp_id)
			return (DCMD_OK);
		if ((s_handle != NULL) &&
		    handle != (uintptr_t)lgrp.lgrp_plathand)
			return (DCMD_OK);
	}

	if (opt_q) {
		mdb_printf("%0?p\n", addr);
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
	if (opt_p)
		lcpu = lgrp.lgrp_cpucnt;
	else
		lcpu = 1;

	cpusetsize = BT_BITOUL(_ncpu) * sizeof (uintptr_t);

	lcc.lcc_used = 0;
	lcc.lcc_cpucnt = mdb_zalloc(sizeof (uint_t) * lcpu,
	    UM_SLEEP | UM_GC);
	lcc.lcc_psrsetid = mdb_zalloc(sizeof (uint_t) * lcpu,
	    UM_SLEEP | UM_GC);
	lcc.lcc_cpuset = mdb_zalloc(sizeof (uintptr_t) * lcpu,
	    UM_SLEEP | UM_GC);
	for (i = 0; i < lcpu; i++)
		lcc.lcc_cpuset[i] = mdb_zalloc(cpusetsize,
		    UM_SLEEP | UM_GC);
	lcc.lcc_loadavg = mdb_zalloc(sizeof (int) * lcpu,
	    UM_SLEEP | UM_GC);
	lcc.lcc_count = lcpu;
	lcc.lcc_opt_p = opt_p;

	if (mdb_pwalk("lgrp_cpulist", lgrp_cpuwalk_callback, &lcc,
	    addr) == -1) {
		mdb_warn("unable to walk lgrp_cpulist");
	}

	if (opt_p == 0) {
		if (lgrp.lgrp_plathand == LGRP_NULL_HANDLE) {
			mdb_printf("%9d %?p %?p %?s %9d      ",
			    lgrp.lgrp_id,
			    addr,
			    lgrp.lgrp_parent,
			    "NULL",
			    lgrp.lgrp_cpucnt);
		} else if (lgrp.lgrp_plathand == LGRP_DEFAULT_HANDLE) {
			mdb_printf("%9d %?p %?p %?s %9d      ",
			    lgrp.lgrp_id,
			    addr,
			    lgrp.lgrp_parent,
			    "DEFAULT",
			    lgrp.lgrp_cpucnt);
		} else {
			mdb_printf("%9d %?p %?p %?p %9d      ",
			    lgrp.lgrp_id,
			    addr,
			    lgrp.lgrp_parent,
			    lgrp.lgrp_plathand,
			    lgrp.lgrp_cpucnt);
		}

		if (lgrp.lgrp_cpucnt != 0) {
			print_cpuset_range(lcc.lcc_cpuset[0],
			    cpusetsize/sizeof (ulong_t), 0);
		}
		mdb_printf("\n");
	} else {
		for (i = 0; i < lcc.lcc_used; i++) {
			mdb_printf("%9d %9d %9d %9d      ",
			    lgrp.lgrp_id,
			    lcc.lcc_psrsetid[i],
			    lcc.lcc_loadavg[i],
			    lcc.lcc_cpucnt[i]);
			if (lcc.lcc_cpucnt[i])
				print_cpuset_range(lcc.lcc_cpuset[i],
				    cpusetsize/sizeof (ulong_t), 0);
			mdb_printf("\n");
		}
	}
	return (DCMD_OK);

}

typedef struct lgrp_walk_data {
	int	lwd_nlgrps;
	uintptr_t *lwd_lgrp_tbl;
	int	lwd_iter;
} lgrp_walk_data_t;

int
lgrp_walk_init(mdb_walk_state_t *wsp)
{
	lgrp_walk_data_t *lwd;
	GElf_Sym sym;

	lwd = mdb_zalloc(sizeof (lgrp_walk_data_t), UM_SLEEP | UM_GC);

	if (mdb_readsym(&lwd->lwd_nlgrps, sizeof (int),
	    "lgrp_alloc_max") == -1) {
		mdb_warn("symbol 'lgrp_alloc_max' not found");
		return (WALK_ERR);
	}

	if (lwd->lwd_nlgrps < 0) {
		mdb_warn("lgrp_alloc_max of bounds (%d)\n", lwd->lwd_nlgrps);
		return (WALK_ERR);
	}

	lwd->lwd_nlgrps++;

	if (mdb_lookup_by_name("lgrp_table", &sym) == -1) {
		mdb_warn("failed to find 'lgrp_table'");
		return (WALK_ERR);
	}

	/* Get number of valid entries in lgrp_table */
	if (sym.st_size < lwd->lwd_nlgrps * sizeof (lgrp_t *)) {
		mdb_warn("lgrp_table size inconsistent with lgrp_alloc_max");
		return (WALK_ERR);
	}

	lwd->lwd_lgrp_tbl = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);

	if (mdb_readsym(lwd->lwd_lgrp_tbl, lwd->lwd_nlgrps * sizeof (lgrp_t *),
	    "lgrp_table") == -1) {
		mdb_warn("unable to read lgrp_table");
		return (WALK_ERR);
	}


	wsp->walk_data = lwd;
	wsp->walk_addr = lwd->lwd_lgrp_tbl[0];

	return (WALK_NEXT);
}
int
lgrp_walk_step(mdb_walk_state_t *wsp)
{
	lgrp_walk_data_t *lwd = wsp->walk_data;
	lgrp_t lgrp;
	int status;


	if (mdb_vread(&lgrp, sizeof (struct lgrp),
	    wsp->walk_addr) == -1) {
		mdb_warn("unable to read lgrp at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &lgrp,
	    wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	lwd->lwd_iter++;

	if (lwd->lwd_iter >= lwd->lwd_nlgrps)
		return (WALK_DONE);

	wsp->walk_addr = lwd->lwd_lgrp_tbl[lwd->lwd_iter];

	if (wsp->walk_addr == NULL) {
		mdb_warn("NULL lgrp pointer in lgrp_table[%d]",
		    lwd->lwd_iter);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}
