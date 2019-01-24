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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/taskq.h>
#include <sys/taskq_impl.h>

#include "taskq.h"

typedef struct tqarray_ent {
	uintptr_t	tq_addr;
	char		tq_name[TASKQ_NAMELEN + 1];
	int		tq_instance;
	uint_t		tq_flags;
} tqarray_ent_t;

typedef struct tq_info {
	tqarray_ent_t	*tqi_array;
	size_t		tqi_count;
	size_t		tqi_size;
} tq_info_t;

/*
 * We sort taskqs as follows:
 *
 *	DYNAMIC last
 *	NOINSTANCE first
 *	within NOINSTANCE, sort by order of creation (instance #)
 *	within non-NOINSTANCE, sort by name (case-insensitive) then instance #
 */
int
tqcmp(const void *lhs, const void *rhs)
{
	const tqarray_ent_t *l = lhs;
	const tqarray_ent_t *r = rhs;
	uint_t lflags = l->tq_flags;
	uint_t rflags = r->tq_flags;
	int ret;

	if ((lflags & TASKQ_DYNAMIC) && !(rflags & TASKQ_DYNAMIC))
		return (1);
	if (!(lflags & TASKQ_DYNAMIC) && (rflags & TASKQ_DYNAMIC))
		return (-1);

	if ((lflags & TASKQ_NOINSTANCE) && !(rflags & TASKQ_NOINSTANCE))
		return (-1);
	if (!(lflags & TASKQ_NOINSTANCE) && (rflags & TASKQ_NOINSTANCE))
		return (1);

	if (!(lflags & TASKQ_NOINSTANCE) &&
	    (ret = strcasecmp(l->tq_name, r->tq_name)) != 0)
		return (ret);

	if (l->tq_instance < r->tq_instance)
		return (-1);
	if (l->tq_instance > r->tq_instance)
		return (1);
	return (0);
}

/*ARGSUSED*/
int
tq_count(uintptr_t addr, const void *ignored, void *arg)
{
	tq_info_t *ti = arg;

	ti->tqi_size++;
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
tq_fill(uintptr_t addr, const void *ignored, tq_info_t *ti)
{
	int idx = ti->tqi_count;
	taskq_t tq;
	tqarray_ent_t *tqe = &ti->tqi_array[idx];

	if (idx == ti->tqi_size) {
		mdb_warn("taskq: inadequate slop\n");
		return (WALK_ERR);
	}
	if (mdb_vread(&tq, sizeof (tq), addr) == -1) {
		mdb_warn("unable to read taskq_t at %p", addr);
		return (WALK_NEXT);
	}

	ti->tqi_count++;
	tqe->tq_addr = addr;
	strncpy(tqe->tq_name, tq.tq_name, TASKQ_NAMELEN);
	tqe->tq_instance = tq.tq_instance;
	tqe->tq_flags = tq.tq_flags;

	return (WALK_NEXT);
}

void
taskq_help(void)
{
	mdb_printf("%s",
	    "  -a    Only show taskqs with active threads.\n"
	    "  -t    Display active thread stacks in each taskq.\n"
	    "  -T    Display all thread stacks in each taskq.\n"
	    "  -m min_maxq\n"
	    "        Only show Dynamic taskqs and taskqs with a MAXQ of at\n"
	    "        least min_maxq.\n"
	    "  -n name\n"
	    "        Only show taskqs which contain name somewhere in their\n"
	    "        name.\n");
}

int
taskq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	taskq_t tq;

	const char *name = NULL;
	uintptr_t minmaxq = 0;
	uint_t	active = FALSE;
	uint_t	print_threads = FALSE;
	uint_t	print_threads_all = FALSE;

	size_t tact, tcount, queued, maxq;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &active,
	    'm', MDB_OPT_UINTPTR, &minmaxq,
	    'n', MDB_OPT_STR, &name,
	    't', MDB_OPT_SETBITS, TRUE, &print_threads,
	    'T', MDB_OPT_SETBITS, TRUE, &print_threads_all,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		size_t idx;
		tq_info_t tqi;

		bzero(&tqi, sizeof (tqi));

		if (mdb_walk("taskq_cache", tq_count, &tqi) == -1) {
			mdb_warn("unable to walk taskq_cache");
			return (DCMD_ERR);
		}
		tqi.tqi_size += 10;	/* slop */
		tqi.tqi_array = mdb_zalloc(
		    sizeof (*tqi.tqi_array) * tqi.tqi_size, UM_SLEEP|UM_GC);

		if (mdb_walk("taskq_cache", (mdb_walk_cb_t)tq_fill,
		    &tqi) == -1) {
			mdb_warn("unable to walk taskq_cache");
			return (DCMD_ERR);
		}
		qsort(tqi.tqi_array, tqi.tqi_count, sizeof (*tqi.tqi_array),
		    tqcmp);

		flags &= ~DCMD_PIPE;
		flags |= DCMD_LOOP | DCMD_LOOPFIRST | DCMD_ADDRSPEC;
		for (idx = 0; idx < tqi.tqi_count; idx++) {
			int ret = taskq(tqi.tqi_array[idx].tq_addr, flags,
			    argc, argv);
			if (ret != DCMD_OK)
				return (ret);
			flags &= ~DCMD_LOOPFIRST;
		}

		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%-?s %-31s %4s/%4s %4s %5s %4s%</u>\n",
		    "ADDR", "NAME", "ACT", "THDS",
		    "Q'ED", "MAXQ", "INST");
	}

	if (mdb_vread(&tq, sizeof (tq), addr) == -1) {
		mdb_warn("failed to read taskq_t at %p", addr);
		return (DCMD_ERR);
	}

	/* terminate the name, just in case */
	tq.tq_name[sizeof (tq.tq_name) - 1] = 0;

	tact = tq.tq_active;
	tcount = tq.tq_nthreads;
	queued = tq.tq_tasks - tq.tq_executed;
	maxq = tq.tq_maxtasks;

	if (tq.tq_flags & TASKQ_DYNAMIC) {
		size_t bsize = tq.tq_nbuckets * sizeof (*tq.tq_buckets);
		size_t idx;
		taskq_bucket_t *b = mdb_zalloc(bsize, UM_SLEEP | UM_GC);

		if (mdb_vread(b, bsize, (uintptr_t)tq.tq_buckets) == -1) {
			mdb_warn("unable to read buckets for taskq %p", addr);
			return (DCMD_ERR);
		}

		tcount += (tq.tq_tcreates - tq.tq_tdeaths);

		for (idx = 0; idx < tq.tq_nbuckets; idx++) {
			tact += b[idx].tqbucket_nalloc;
		}
	}

	/* filter out taskqs that aren't of interest. */
	if (name != NULL && strstr(tq.tq_name, name) == NULL)
		return (DCMD_OK);
	if (active && tact == 0 && queued == 0)
		return (DCMD_OK);
	if (!(tq.tq_flags & TASKQ_DYNAMIC) && maxq < minmaxq)
		return (DCMD_OK);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%?p %-31s %4d/%4d %4d ",
	    addr, tq.tq_name, tact, tcount, queued);

	if (tq.tq_flags & TASKQ_DYNAMIC)
		mdb_printf("%5s ", "-");
	else
		mdb_printf("%5d ", maxq);

	if (tq.tq_flags & TASKQ_NOINSTANCE)
		mdb_printf("%4s", "-");
	else
		mdb_printf("%4x", tq.tq_instance);

	mdb_printf("\n");

	if (print_threads || print_threads_all) {
		int ret;
		char strbuf[128];
		const char *arg =
		    print_threads_all ? "" : "-C \"taskq_thread_wait\"";

		/*
		 * We can't use mdb_pwalk_dcmd() here, because ::stacks needs
		 * to get the full pipeline.
		 */
		mdb_snprintf(strbuf, sizeof (strbuf),
		    "%p::walk taskq_thread | ::stacks -a %s",
		    addr, arg);

		(void) mdb_inc_indent(4);
		ret = mdb_eval(strbuf);
		(void) mdb_dec_indent(4);

		/* abort, since they could have control-Ced the eval */
		if (ret == -1)
			return (DCMD_ABORT);
	}

	return (DCMD_OK);
}

/*
 * Dump a taskq_ent_t given its address.
 */
/*ARGSUSED*/
int
taskq_ent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	taskq_ent_t	taskq_ent;

	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&taskq_ent, sizeof (taskq_ent_t), addr) == -1) {
		mdb_warn("failed to read taskq_ent_t at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%-?s %-?s %-s%</u>\n",
		"ENTRY", "ARG", "FUNCTION");
	}

	mdb_printf("%-?p %-?p %a\n", addr, taskq_ent.tqent_arg,
	    taskq_ent.tqent_func);

	return (DCMD_OK);
}


/*
 * Given the address of the (taskq_t) task queue head, walk the queue listing
 * the address of every taskq_ent_t.
 */
int
taskq_ent_walk_init(mdb_walk_state_t *wsp)
{
	taskq_t	tq_head;


	if (wsp->walk_addr == 0) {
		mdb_warn("start address required\n");
		return (WALK_ERR);
	}


	/*
	 * Save the address of the list head entry.  This terminates the list.
	 */
	wsp->walk_data = (void *)
	    ((size_t)wsp->walk_addr + OFFSETOF(taskq_t, tq_task));


	/*
	 * Read in taskq head, set walk_addr to point to first taskq_ent_t.
	 */
	if (mdb_vread((void *)&tq_head, sizeof (taskq_t), wsp->walk_addr) ==
	    -1) {
		mdb_warn("failed to read taskq list head at %p",
		    wsp->walk_addr);
	}
	wsp->walk_addr = (uintptr_t)tq_head.tq_task.tqent_next;


	/*
	 * Check for null list (next=head)
	 */
	if (wsp->walk_addr == (uintptr_t)wsp->walk_data) {
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}


int
taskq_ent_walk_step(mdb_walk_state_t *wsp)
{
	taskq_ent_t	tq_ent;
	int		status;


	if (mdb_vread((void *)&tq_ent, sizeof (taskq_ent_t), wsp->walk_addr) ==
	    -1) {
		mdb_warn("failed to read taskq_ent_t at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, (void *)&tq_ent,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)tq_ent.tqent_next;


	/* Check if we're at the last element (next=head) */
	if (wsp->walk_addr == (uintptr_t)wsp->walk_data) {
		return (WALK_DONE);
	}

	return (status);
}

typedef struct taskq_thread_info {
	uintptr_t	tti_addr;
	uintptr_t	*tti_tlist;
	size_t		tti_nthreads;
	size_t		tti_idx;

	kthread_t	tti_thread;
} taskq_thread_info_t;

int
taskq_thread_walk_init(mdb_walk_state_t *wsp)
{
	taskq_thread_info_t	*tti;
	taskq_t			tq;
	uintptr_t		*tlist;
	size_t			nthreads;

	tti = wsp->walk_data = mdb_zalloc(sizeof (*tti), UM_SLEEP);
	tti->tti_addr = wsp->walk_addr;

	if (wsp->walk_addr != 0 &&
	    mdb_vread(&tq, sizeof (tq), wsp->walk_addr) != -1 &&
	    !(tq.tq_flags & TASKQ_DYNAMIC)) {

		nthreads = tq.tq_nthreads;
		tlist = mdb_alloc(nthreads * sizeof (*tlist), UM_SLEEP);
		if (tq.tq_nthreads_max == 1) {
			tlist[0] = (uintptr_t)tq.tq_thread;

		} else if (mdb_vread(tlist, nthreads * sizeof (*tlist),
		    (uintptr_t)tq.tq_threadlist) == -1) {
			mdb_warn("unable to read threadlist for taskq_t %p",
			    wsp->walk_addr);
			mdb_free(tlist, nthreads * sizeof (*tlist));
			return (WALK_ERR);
		}

		tti->tti_tlist = tlist;
		tti->tti_nthreads = nthreads;
		return (WALK_NEXT);
	}

	wsp->walk_addr = 0;
	if (mdb_layered_walk("thread", wsp) == -1) {
		mdb_warn("can't walk \"thread\"");
		return (WALK_ERR);
	}
	return (0);
}

int
taskq_thread_walk_step(mdb_walk_state_t *wsp)
{
	taskq_thread_info_t	*tti = wsp->walk_data;

	const kthread_t *kt = wsp->walk_layer;
	taskq_t *tq = (taskq_t *)tti->tti_addr;

	if (kt == NULL) {
		uintptr_t addr;

		if (tti->tti_idx >= tti->tti_nthreads)
			return (WALK_DONE);

		addr = tti->tti_tlist[tti->tti_idx];
		tti->tti_idx++;

		if (addr == 0)
			return (WALK_NEXT);

		if (mdb_vread(&tti->tti_thread, sizeof (kthread_t),
		    addr) == -1) {
			mdb_warn("unable to read kthread_t at %p", addr);
			return (WALK_ERR);
		}
		return (wsp->walk_callback(addr, &tti->tti_thread,
		    wsp->walk_cbdata));
	}

	if (kt->t_taskq == NULL)
		return (WALK_NEXT);

	if (tq != NULL && kt->t_taskq != tq)
		return (WALK_NEXT);

	return (wsp->walk_callback(wsp->walk_addr, kt, wsp->walk_cbdata));
}

void
taskq_thread_walk_fini(mdb_walk_state_t *wsp)
{
	taskq_thread_info_t	*tti = wsp->walk_data;

	if (tti->tti_nthreads > 0) {
		mdb_free(tti->tti_tlist,
		    tti->tti_nthreads * sizeof (*tti->tti_tlist));
	}
	mdb_free(tti, sizeof (*tti));
}
