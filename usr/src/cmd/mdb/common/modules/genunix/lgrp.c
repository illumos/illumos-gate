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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
	uintptr_t	lcw_firstcpu;
	int		lcw_cpusleft;
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

	if (lcw->lcw_cpusleft == 0 && addr != lcw->lcw_firstcpu) {
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

/*
 * Common routine for several walkers.
 * Read lgroup from wsp->walk_addr and call wsp->walk_callback for it.
 * Normally returns the result of the callback.
 * Returns WALK_DONE if walk_addr is NULL and WALK_ERR if cannot read the
 * lgroup.
 */
static int
lgrp_walk_step_common(mdb_walk_state_t *wsp)
{
	lgrp_t lgrp;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&lgrp, sizeof (lgrp_t), wsp->walk_addr) == -1) {
		mdb_warn("unable to read lgrp at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(wsp->walk_addr, &lgrp, wsp->walk_cbdata));
}

/*
 * Get one lgroup from the lgroup table and adjust lwd_iter to point to the next
 * one.
 */
int
lgrp_walk_step(mdb_walk_state_t *wsp)
{
	lgrp_walk_data_t *lwd = wsp->walk_data;
	int status = lgrp_walk_step_common(wsp);

	if (status == WALK_NEXT) {
		lwd->lwd_iter++;

		if (lwd->lwd_iter >= lwd->lwd_nlgrps) {
			status = WALK_DONE;
		} else {
			wsp->walk_addr = lwd->lwd_lgrp_tbl[lwd->lwd_iter];

			if (wsp->walk_addr == 0) {
				mdb_warn("NULL lgrp pointer in lgrp_table[%d]",
				    lwd->lwd_iter);
				return (WALK_ERR);
			}
		}
	}

	return (status);
}

/*
 * Initialize walker to traverse parents of lgroups. Nothing to do here.
 */
/* ARGSUSED */
int
lgrp_parents_walk_init(mdb_walk_state_t *wsp)
{
	return (WALK_NEXT);
}

/*
 * Call wsp callback on current lgroup in wsp and replace the lgroup with its
 * parent.
 */
int
lgrp_parents_walk_step(mdb_walk_state_t *wsp)
{
	lgrp_t lgrp;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&lgrp, sizeof (struct lgrp), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read 'lgrp' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &lgrp, wsp->walk_cbdata);

	if (status == WALK_NEXT)
		wsp->walk_addr = (uintptr_t)lgrp.lgrp_parent;

	return (status);
}

/*
 * Given the set return the ID of the first member of the set.
 * Returns LGRP_NONE if the set has no elements smaller than max_lgrp.
 */
static lgrp_id_t
lgrp_set_get_first(klgrpset_t set, int max_lgrp)
{
	lgrp_id_t id;
	klgrpset_t bit = 1;

	if (set == (klgrpset_t)0)
		return (LGRP_NONE);

	for (id = 0; (id < max_lgrp) && !(set & bit); id++, bit <<= 1)
		;

	if (id >= max_lgrp)
		id = LGRP_NONE;

	return (id);
}

/*
 * lgrp_set_walk_data is used to walk lgroups specified by a set.
 * On every iteration one element is removed from the set.
 */
typedef struct lgrp_set_walk_data {
	int		lswd_nlgrps;		/* Number of lgroups */
	uintptr_t	*lwsd_lgrp_tbl;		/* Full lgroup table */
	klgrpset_t	lwsd_set;		/* Set of lgroups to walk */
} lgrp_set_walk_data_t;

/*
 * Initialize iterator for walkers over a set of lgroups
 */
static int
lgrp_set_walk_init(mdb_walk_state_t *wsp, klgrpset_t set)
{
	lgrp_set_walk_data_t *lwsd;
	int nlgrps;
	lgrp_id_t id;
	GElf_Sym sym;

	/* Nothing to do if the set is empty */
	if (set == (klgrpset_t)0)
		return (WALK_DONE);

	lwsd = mdb_zalloc(sizeof (lgrp_set_walk_data_t), UM_SLEEP | UM_GC);

	/* Get the total number of lgroups */
	if (mdb_readsym(&nlgrps, sizeof (int), "lgrp_alloc_max") == -1) {
		mdb_warn("symbol 'lgrp_alloc_max' not found");
		return (WALK_ERR);
	}

	if (nlgrps < 0) {
		mdb_warn("lgrp_alloc_max of bounds (%d)\n", nlgrps);
		return (WALK_ERR);
	}

	nlgrps++;

	/* Find ID of the first lgroup in the set */
	if ((id = lgrp_set_get_first(set, nlgrps)) == LGRP_NONE) {
		mdb_warn("No set elements within %d lgroups\n", nlgrps);
		return (WALK_ERR);
	}

	/* Read lgroup_table and copy it to lwsd_lgrp_tbl */
	if (mdb_lookup_by_name("lgrp_table", &sym) == -1) {
		mdb_warn("failed to find 'lgrp_table'");
		return (WALK_ERR);
	}

	/* Get number of valid entries in lgrp_table */
	if (sym.st_size < nlgrps * sizeof (lgrp_t *)) {
		mdb_warn("lgrp_table size inconsistent with lgrp_alloc_max");
		return (WALK_ERR);
	}

	lwsd->lwsd_lgrp_tbl = mdb_alloc(sym.st_size, UM_SLEEP | UM_GC);
	lwsd->lswd_nlgrps = nlgrps;

	if (mdb_readsym(lwsd->lwsd_lgrp_tbl, nlgrps * sizeof (lgrp_t *),
		"lgrp_table") == -1) {
		mdb_warn("unable to read lgrp_table");
		return (WALK_ERR);
	}

	wsp->walk_data = lwsd;

	/* Save the first lgroup from the set and remove it from the set */
	wsp->walk_addr = lwsd->lwsd_lgrp_tbl[id];
	lwsd->lwsd_set = set & ~(1 << id);

	return (WALK_NEXT);
}

/*
 * Get current lgroup and advance the lgroup to the next one in the lwsd_set.
 */
int
lgrp_set_walk_step(mdb_walk_state_t *wsp)
{
	lgrp_id_t id = 0;
	lgrp_set_walk_data_t *lwsd = wsp->walk_data;
	int status = lgrp_walk_step_common(wsp);

	if (status == WALK_NEXT) {
		id = lgrp_set_get_first(lwsd->lwsd_set, lwsd->lswd_nlgrps);
		if (id == LGRP_NONE) {
			status = WALK_DONE;
		} else {
			/* Move to the next lgroup in the set */
			wsp->walk_addr = lwsd->lwsd_lgrp_tbl[id];

			/* Remove id from the set */
			lwsd->lwsd_set = lwsd->lwsd_set & ~(1 << id);
		}
	}

	return (status);
}

/*
 * Initialize resource walker for a given lgroup and resource. The lgroup
 * address is specified in walk_addr.
 */
static int
lgrp_rsrc_walk_init(mdb_walk_state_t *wsp, int resource)
{
	lgrp_t lgrp;

	if (mdb_vread(&lgrp, sizeof (struct lgrp), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read 'lgrp' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (lgrp_set_walk_init(wsp, lgrp.lgrp_set[resource]));
}

/*
 * Initialize CPU resource walker
 */
int
lgrp_rsrc_cpu_walk_init(mdb_walk_state_t *wsp)
{
	return (lgrp_rsrc_walk_init(wsp, LGRP_RSRC_CPU));
}

/*
 * Initialize memory resource walker
 */
int
lgrp_rsrc_mem_walk_init(mdb_walk_state_t *wsp)
{
	return (lgrp_rsrc_walk_init(wsp, LGRP_RSRC_MEM));
}

/*
 * Display bitmap as a list of integers
 */
/* ARGSUSED */
int
lgrp_set(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint64_t set = (uint64_t)addr;
	uint64_t mask = 1;
	int i = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (set == 0)
		return (DCMD_OK);

	for (; set != (uint64_t)0; i++, mask <<= 1) {
		if (set & mask) {
			mdb_printf("%d ", i);
			set &= ~mask;
		}
	}
	mdb_printf("\n");
	return (DCMD_OK);
}
