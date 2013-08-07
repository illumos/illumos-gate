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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/thread.h>
#include <sys/modctl.h>
#include <assert.h>

#include "findstack.h"
#include "thread.h"
#include "sobj.h"

int findstack_debug_on = 0;

/*
 * "sp" is a kernel VA.
 */
static int
print_stack(uintptr_t sp, uintptr_t pc, uintptr_t addr,
    int argc, const mdb_arg_t *argv, int free_state)
{
	int showargs = 0, count, err;

	count = mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &showargs, NULL);
	argc -= count;
	argv += count;

	if (argc > 1 || (argc == 1 && argv->a_type != MDB_TYPE_STRING))
		return (DCMD_USAGE);

	mdb_printf("stack pointer for thread %p%s: %p\n",
	    addr, (free_state ? " (TS_FREE)" : ""), sp);
	if (pc != 0)
		mdb_printf("[ %0?lr %a() ]\n", sp, pc);

	mdb_inc_indent(2);
	mdb_set_dot(sp);

	if (argc == 1)
		err = mdb_eval(argv->a_un.a_str);
	else if (showargs)
		err = mdb_eval("<.$C");
	else
		err = mdb_eval("<.$C0");

	mdb_dec_indent(2);

	return ((err == -1) ? DCMD_ABORT : DCMD_OK);
}

int
findstack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	findstack_info_t fsi;
	int retval;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bzero(&fsi, sizeof (fsi));

	if ((retval = stacks_findstack(addr, &fsi, 1)) != DCMD_OK ||
	    fsi.fsi_failed)
		return (retval);

	return (print_stack(fsi.fsi_sp, fsi.fsi_pc, addr,
	    argc, argv, fsi.fsi_tstate == TS_FREE));
}

/*ARGSUSED*/
int
findstack_debug(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *av)
{
	findstack_debug_on ^= 1;

	mdb_printf("findstack: debugging is now %s\n",
	    findstack_debug_on ? "on" : "off");

	return (DCMD_OK);
}

static void
uppercase(char *p)
{
	for (; *p != '\0'; p++) {
		if (*p >= 'a' && *p <= 'z')
			*p += 'A' - 'a';
	}
}

static void
sobj_to_text(uintptr_t addr, char *out, size_t out_sz)
{
	sobj_ops_to_text(addr, out, out_sz);
	uppercase(out);
}

#define	SOBJ_ALL	1

static int
text_to_sobj(const char *text, uintptr_t *out)
{
	if (strcasecmp(text, "ALL") == 0) {
		*out = SOBJ_ALL;
		return (0);
	}

	return (sobj_text_to_ops(text, out));
}

#define	TSTATE_PANIC	-2U
static int
text_to_tstate(const char *text, uint_t *out)
{
	if (strcasecmp(text, "panic") == 0)
		*out = TSTATE_PANIC;
	else if (thread_text_to_state(text, out) != 0) {
		mdb_warn("tstate \"%s\" not recognized\n", text);
		return (-1);
	}
	return (0);
}

static void
tstate_to_text(uint_t tstate, uint_t paniced, char *out, size_t out_sz)
{
	if (paniced)
		mdb_snprintf(out, out_sz, "panic");
	else
		thread_state_to_text(tstate, out, out_sz);
	uppercase(out);
}

typedef struct stacks_entry {
	struct stacks_entry	*se_next;
	struct stacks_entry	*se_dup;	/* dups of this stack */
	uintptr_t		se_thread;
	uintptr_t		se_sp;
	uintptr_t		se_sobj_ops;
	uint32_t		se_tstate;
	uint32_t		se_count;	/* # threads w/ this stack */
	uint8_t			se_overflow;
	uint8_t			se_depth;
	uint8_t			se_failed;	/* failure reason; FSI_FAIL_* */
	uint8_t			se_panic;
	uintptr_t		se_stack[1];
} stacks_entry_t;
#define	STACKS_ENTRY_SIZE(x) OFFSETOF(stacks_entry_t, se_stack[(x)])

#define	STACKS_HSIZE 127

/* Maximum stack depth reported in stacks */
#define	STACKS_MAX_DEPTH	254

typedef struct stacks_info {
	size_t		si_count;	/* total stacks_entry_ts (incl dups) */
	size_t		si_entries;	/* # entries in hash table */
	stacks_entry_t	**si_hash;	/* hash table */
	findstack_info_t si_fsi;	/* transient callback state */
} stacks_info_t;

/* global state cached between invocations */
#define	STACKS_STATE_CLEAN	0
#define	STACKS_STATE_DIRTY	1
#define	STACKS_STATE_DONE	2
static uint_t stacks_state = STACKS_STATE_CLEAN;
static stacks_entry_t **stacks_hash;
static stacks_entry_t **stacks_array;
static size_t stacks_array_size;

size_t
stacks_hash_entry(stacks_entry_t *sep)
{
	size_t depth = sep->se_depth;
	uintptr_t *stack = sep->se_stack;

	uint64_t total = depth;

	while (depth > 0) {
		total += *stack;
		stack++; depth--;
	}

	return (total % STACKS_HSIZE);
}

/*
 * This is used to both compare stacks for equality and to sort the final
 * list of unique stacks.  forsort specifies the latter behavior, which
 * additionally:
 *	compares se_count, and
 *	sorts the stacks by text function name.
 *
 * The equality test is independent of se_count, and doesn't care about
 * relative ordering, so we don't do the extra work of looking up symbols
 * for the stack addresses.
 */
int
stacks_entry_comp_impl(stacks_entry_t *l, stacks_entry_t *r,
    uint_t forsort)
{
	int idx;

	int depth = MIN(l->se_depth, r->se_depth);

	/* no matter what, panic stacks come last. */
	if (l->se_panic > r->se_panic)
		return (1);
	if (l->se_panic < r->se_panic)
		return (-1);

	if (forsort) {
		/* put large counts earlier */
		if (l->se_count > r->se_count)
			return (-1);
		if (l->se_count < r->se_count)
			return (1);
	}

	if (l->se_tstate > r->se_tstate)
		return (1);
	if (l->se_tstate < r->se_tstate)
		return (-1);

	if (l->se_failed > r->se_failed)
		return (1);
	if (l->se_failed < r->se_failed)
		return (-1);

	for (idx = 0; idx < depth; idx++) {
		char lbuf[MDB_SYM_NAMLEN];
		char rbuf[MDB_SYM_NAMLEN];

		int rval;
		uintptr_t laddr = l->se_stack[idx];
		uintptr_t raddr = r->se_stack[idx];

		if (laddr == raddr)
			continue;

		if (forsort &&
		    mdb_lookup_by_addr(laddr, MDB_SYM_FUZZY,
		    lbuf, sizeof (lbuf), NULL) != -1 &&
		    mdb_lookup_by_addr(raddr, MDB_SYM_FUZZY,
		    rbuf, sizeof (rbuf), NULL) != -1 &&
		    (rval = strcmp(lbuf, rbuf)) != 0)
			return (rval);

		if (laddr > raddr)
			return (1);
		return (-1);
	}

	if (l->se_overflow > r->se_overflow)
		return (-1);
	if (l->se_overflow < r->se_overflow)
		return (1);

	if (l->se_depth > r->se_depth)
		return (1);
	if (l->se_depth < r->se_depth)
		return (-1);

	if (l->se_sobj_ops > r->se_sobj_ops)
		return (1);
	if (l->se_sobj_ops < r->se_sobj_ops)
		return (-1);

	return (0);
}

int
stacks_entry_comp(const void *l_arg, const void *r_arg)
{
	stacks_entry_t * const *lp = l_arg;
	stacks_entry_t * const *rp = r_arg;

	return (stacks_entry_comp_impl(*lp, *rp, 1));
}

void
stacks_cleanup(int force)
{
	int idx = 0;
	stacks_entry_t *cur, *next;

	if (stacks_state == STACKS_STATE_CLEAN)
		return;

	if (!force && stacks_state == STACKS_STATE_DONE)
		return;

	/*
	 * Until the array is sorted and stable, stacks_hash will be non-NULL.
	 * This way, we can get at all of the data, even if qsort() was
	 * interrupted while mucking with the array.
	 */
	if (stacks_hash != NULL) {
		for (idx = 0; idx < STACKS_HSIZE; idx++) {
			while ((cur = stacks_hash[idx]) != NULL) {
				while ((next = cur->se_dup) != NULL) {
					cur->se_dup = next->se_dup;
					mdb_free(next,
					    STACKS_ENTRY_SIZE(next->se_depth));
				}
				next = cur->se_next;
				stacks_hash[idx] = next;
				mdb_free(cur, STACKS_ENTRY_SIZE(cur->se_depth));
			}
		}
		if (stacks_array != NULL)
			mdb_free(stacks_array,
			    stacks_array_size * sizeof (*stacks_array));

		mdb_free(stacks_hash, STACKS_HSIZE * sizeof (*stacks_hash));

	} else if (stacks_array != NULL) {
		for (idx = 0; idx < stacks_array_size; idx++) {
			if ((cur = stacks_array[idx]) != NULL) {
				while ((next = cur->se_dup) != NULL) {
					cur->se_dup = next->se_dup;
					mdb_free(next,
					    STACKS_ENTRY_SIZE(next->se_depth));
				}
				stacks_array[idx] = NULL;
				mdb_free(cur, STACKS_ENTRY_SIZE(cur->se_depth));
			}
		}
		mdb_free(stacks_array,
		    stacks_array_size * sizeof (*stacks_array));
	}

	stacks_findstack_cleanup();

	stacks_array_size = 0;
	stacks_state = STACKS_STATE_CLEAN;
	stacks_hash = NULL;
	stacks_array = NULL;
}

/*ARGSUSED*/
int
stacks_thread_cb(uintptr_t addr, const void *ignored, void *cbarg)
{
	stacks_info_t *sip = cbarg;
	findstack_info_t *fsip = &sip->si_fsi;

	stacks_entry_t **sepp, *nsep, *sep;
	int idx;
	size_t depth;

	if (stacks_findstack(addr, fsip, 0) != DCMD_OK &&
	    fsip->fsi_failed == FSI_FAIL_BADTHREAD) {
		mdb_warn("couldn't read thread at %p\n", addr);
		return (WALK_NEXT);
	}

	sip->si_count++;

	depth = fsip->fsi_depth;
	nsep = mdb_zalloc(STACKS_ENTRY_SIZE(depth), UM_SLEEP);
	nsep->se_thread = addr;
	nsep->se_sp = fsip->fsi_sp;
	nsep->se_sobj_ops = fsip->fsi_sobj_ops;
	nsep->se_tstate = fsip->fsi_tstate;
	nsep->se_count = 1;
	nsep->se_overflow = fsip->fsi_overflow;
	nsep->se_depth = depth;
	nsep->se_failed = fsip->fsi_failed;
	nsep->se_panic = fsip->fsi_panic;

	for (idx = 0; idx < depth; idx++)
		nsep->se_stack[idx] = fsip->fsi_stack[idx];

	for (sepp = &sip->si_hash[stacks_hash_entry(nsep)];
	    (sep = *sepp) != NULL;
	    sepp = &sep->se_next) {

		if (stacks_entry_comp_impl(sep, nsep, 0) != 0)
			continue;

		nsep->se_dup = sep->se_dup;
		sep->se_dup = nsep;
		sep->se_count++;
		return (WALK_NEXT);
	}

	nsep->se_next = NULL;
	*sepp = nsep;
	sip->si_entries++;

	return (WALK_NEXT);
}

int
stacks_run_tlist(mdb_pipe_t *tlist, stacks_info_t *si)
{
	size_t idx;
	size_t found = 0;
	int ret;

	for (idx = 0; idx < tlist->pipe_len; idx++) {
		uintptr_t addr = tlist->pipe_data[idx];

		found++;

		ret = stacks_thread_cb(addr, NULL, si);
		if (ret == WALK_DONE)
			break;
		if (ret != WALK_NEXT)
			return (-1);
	}

	if (found)
		return (0);
	return (-1);
}

int
stacks_run(int verbose, mdb_pipe_t *tlist)
{
	stacks_info_t si;
	findstack_info_t *fsip = &si.si_fsi;
	size_t idx;
	stacks_entry_t **cur;

	bzero(&si, sizeof (si));

	stacks_state = STACKS_STATE_DIRTY;

	stacks_hash = si.si_hash =
	    mdb_zalloc(STACKS_HSIZE * sizeof (*si.si_hash), UM_SLEEP);
	si.si_entries = 0;
	si.si_count = 0;

	fsip->fsi_max_depth = STACKS_MAX_DEPTH;
	fsip->fsi_stack =
	    mdb_alloc(fsip->fsi_max_depth * sizeof (*fsip->fsi_stack),
	    UM_SLEEP | UM_GC);

	if (verbose)
		mdb_warn("stacks: processing kernel threads\n");

	if (tlist != NULL) {
		if (stacks_run_tlist(tlist, &si))
			return (DCMD_ERR);
	} else {
		if (mdb_walk("thread", stacks_thread_cb, &si) != 0) {
			mdb_warn("cannot walk \"thread\"");
			return (DCMD_ERR);
		}
	}

	if (verbose)
		mdb_warn("stacks: %d unique stacks / %d threads\n",
		    si.si_entries, si.si_count);

	stacks_array_size = si.si_entries;
	stacks_array =
	    mdb_zalloc(si.si_entries * sizeof (*stacks_array), UM_SLEEP);
	cur = stacks_array;
	for (idx = 0; idx < STACKS_HSIZE; idx++) {
		stacks_entry_t *sep;
		for (sep = si.si_hash[idx]; sep != NULL; sep = sep->se_next)
			*(cur++) = sep;
	}

	if (cur != stacks_array + si.si_entries) {
		mdb_warn("stacks: miscounted array size (%d != size: %d)\n",
		    (cur - stacks_array), stacks_array_size);
		return (DCMD_ERR);
	}
	qsort(stacks_array, si.si_entries, sizeof (*stacks_array),
	    stacks_entry_comp);

	/* Now that we're done, free the hash table */
	stacks_hash = NULL;
	mdb_free(si.si_hash, STACKS_HSIZE * sizeof (*si.si_hash));

	if (tlist == NULL)
		stacks_state = STACKS_STATE_DONE;

	if (verbose)
		mdb_warn("stacks: done\n");

	return (DCMD_OK);
}

static int
stacks_has_caller(stacks_entry_t *sep, uintptr_t addr)
{
	uintptr_t laddr = addr;
	uintptr_t haddr = addr + 1;
	int idx;
	char c[MDB_SYM_NAMLEN];
	GElf_Sym sym;

	if (mdb_lookup_by_addr(addr, MDB_SYM_FUZZY,
	    c, sizeof (c), &sym) != -1 &&
	    addr == (uintptr_t)sym.st_value) {
		laddr = (uintptr_t)sym.st_value;
		haddr = (uintptr_t)sym.st_value + sym.st_size;
	}

	for (idx = 0; idx < sep->se_depth; idx++)
		if (sep->se_stack[idx] >= laddr && sep->se_stack[idx] < haddr)
			return (1);

	return (0);
}

static int
stacks_has_module(stacks_entry_t *sep, stacks_module_t *mp)
{
	int idx;

	for (idx = 0; idx < sep->se_depth; idx++) {
		if (sep->se_stack[idx] >= mp->sm_text &&
		    sep->se_stack[idx] < mp->sm_text + mp->sm_size)
			return (1);
	}

	return (0);
}

static int
stacks_module_find(const char *name, stacks_module_t *mp)
{
	(void) strncpy(mp->sm_name, name, sizeof (mp->sm_name));

	if (stacks_module(mp) != 0)
		return (-1);

	if (mp->sm_size == 0) {
		mdb_warn("stacks: module \"%s\" is unknown\n", name);
		return (-1);
	}

	return (0);
}

static int
uintptrcomp(const void *lp, const void *rp)
{
	uintptr_t lhs = *(const uintptr_t *)lp;
	uintptr_t rhs = *(const uintptr_t *)rp;
	if (lhs > rhs)
		return (1);
	if (lhs < rhs)
		return (-1);
	return (0);
}

/*ARGSUSED*/
int
stacks(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t idx;

	char *seen = NULL;

	const char *caller_str = NULL;
	const char *excl_caller_str = NULL;
	uintptr_t caller = 0, excl_caller = 0;
	const char *module_str = NULL;
	const char *excl_module_str = NULL;
	stacks_module_t module, excl_module;
	const char *sobj = NULL;
	const char *excl_sobj = NULL;
	uintptr_t sobj_ops = 0, excl_sobj_ops = 0;
	const char *tstate_str = NULL;
	const char *excl_tstate_str = NULL;
	uint_t tstate = -1U;
	uint_t excl_tstate = -1U;
	uint_t printed = 0;

	uint_t all = 0;
	uint_t force = 0;
	uint_t interesting = 0;
	uint_t verbose = 0;

	/*
	 * We have a slight behavior difference between having piped
	 * input and 'addr::stacks'.  Without a pipe, we assume the
	 * thread pointer given is a representative thread, and so
	 * we include all similar threads in the system in our output.
	 *
	 * With a pipe, we filter down to just the threads in our
	 * input.
	 */
	uint_t addrspec = (flags & DCMD_ADDRSPEC);
	uint_t only_matching = addrspec && (flags & DCMD_PIPE);

	mdb_pipe_t p;

	bzero(&module, sizeof (module));
	bzero(&excl_module, sizeof (excl_module));

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &all,
	    'f', MDB_OPT_SETBITS, TRUE, &force,
	    'i', MDB_OPT_SETBITS, TRUE, &interesting,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'c', MDB_OPT_STR, &caller_str,
	    'C', MDB_OPT_STR, &excl_caller_str,
	    'm', MDB_OPT_STR, &module_str,
	    'M', MDB_OPT_STR, &excl_module_str,
	    's', MDB_OPT_STR, &sobj,
	    'S', MDB_OPT_STR, &excl_sobj,
	    't', MDB_OPT_STR, &tstate_str,
	    'T', MDB_OPT_STR, &excl_tstate_str,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (interesting) {
		if (sobj != NULL || excl_sobj != NULL ||
		    tstate_str != NULL || excl_tstate_str != NULL) {
			mdb_warn(
			    "stacks: -i is incompatible with -[sStT]\n");
			return (DCMD_USAGE);
		}
		excl_sobj = "CV";
		excl_tstate_str = "FREE";
	}

	if (caller_str != NULL) {
		mdb_set_dot(0);
		if (mdb_eval(caller_str) != 0) {
			mdb_warn("stacks: evaluation of \"%s\" failed",
			    caller_str);
			return (DCMD_ABORT);
		}
		caller = mdb_get_dot();
	}

	if (excl_caller_str != NULL) {
		mdb_set_dot(0);
		if (mdb_eval(excl_caller_str) != 0) {
			mdb_warn("stacks: evaluation of \"%s\" failed",
			    excl_caller_str);
			return (DCMD_ABORT);
		}
		excl_caller = mdb_get_dot();
	}
	mdb_set_dot(addr);

	if (module_str != NULL && stacks_module_find(module_str, &module) != 0)
		return (DCMD_ABORT);

	if (excl_module_str != NULL &&
	    stacks_module_find(excl_module_str, &excl_module) != 0)
		return (DCMD_ABORT);

	if (sobj != NULL && text_to_sobj(sobj, &sobj_ops) != 0)
		return (DCMD_USAGE);

	if (excl_sobj != NULL && text_to_sobj(excl_sobj, &excl_sobj_ops) != 0)
		return (DCMD_USAGE);

	if (sobj_ops != 0 && excl_sobj_ops != 0) {
		mdb_warn("stacks: only one of -s and -S can be specified\n");
		return (DCMD_USAGE);
	}

	if (tstate_str != NULL && text_to_tstate(tstate_str, &tstate) != 0)
		return (DCMD_USAGE);

	if (excl_tstate_str != NULL &&
	    text_to_tstate(excl_tstate_str, &excl_tstate) != 0)
		return (DCMD_USAGE);

	if (tstate != -1U && excl_tstate != -1U) {
		mdb_warn("stacks: only one of -t and -T can be specified\n");
		return (DCMD_USAGE);
	}

	/*
	 * If there's an address specified, we're going to further filter
	 * to only entries which have an address in the input.  To reduce
	 * overhead (and make the sorted output come out right), we
	 * use mdb_get_pipe() to grab the entire pipeline of input, then
	 * use qsort() and bsearch() to speed up the search.
	 */
	if (addrspec) {
		mdb_get_pipe(&p);
		if (p.pipe_data == NULL || p.pipe_len == 0) {
			p.pipe_data = &addr;
			p.pipe_len = 1;
		}
		qsort(p.pipe_data, p.pipe_len, sizeof (uintptr_t),
		    uintptrcomp);

		/* remove any duplicates in the data */
		idx = 0;
		while (idx < p.pipe_len - 1) {
			uintptr_t *data = &p.pipe_data[idx];
			size_t len = p.pipe_len - idx;

			if (data[0] == data[1]) {
				memmove(data, data + 1,
				    (len - 1) * sizeof (*data));
				p.pipe_len--;
				continue; /* repeat without incrementing idx */
			}
			idx++;
		}

		seen = mdb_zalloc(p.pipe_len, UM_SLEEP | UM_GC);
	}

	/*
	 * Force a cleanup if we're connected to a live system. Never
	 * do a cleanup after the first invocation around the loop.
	 */
	force |= (mdb_get_state() == MDB_STATE_RUNNING);
	if (force && (flags & (DCMD_LOOPFIRST|DCMD_LOOP)) == DCMD_LOOP)
		force = 0;

	stacks_cleanup(force);

	if (stacks_state == STACKS_STATE_CLEAN) {
		int res = stacks_run(verbose, addrspec ? &p : NULL);
		if (res != DCMD_OK)
			return (res);
	}

	for (idx = 0; idx < stacks_array_size; idx++) {
		stacks_entry_t *sep = stacks_array[idx];
		stacks_entry_t *cur = sep;
		int frame;
		size_t count = sep->se_count;

		if (addrspec) {
			stacks_entry_t *head = NULL, *tail = NULL, *sp;
			size_t foundcount = 0;
			/*
			 * We use the now-unused hash chain field se_next to
			 * link together the dups which match our list.
			 */
			for (sp = sep; sp != NULL; sp = sp->se_dup) {
				uintptr_t *entry = bsearch(&sp->se_thread,
				    p.pipe_data, p.pipe_len, sizeof (uintptr_t),
				    uintptrcomp);
				if (entry != NULL) {
					foundcount++;
					seen[entry - p.pipe_data]++;
					if (head == NULL)
						head = sp;
					else
						tail->se_next = sp;
					tail = sp;
					sp->se_next = NULL;
				}
			}
			if (head == NULL)
				continue;	/* no match, skip entry */

			if (only_matching) {
				cur = sep = head;
				count = foundcount;
			}
		}

		if (caller != 0 && !stacks_has_caller(sep, caller))
			continue;

		if (excl_caller != 0 && stacks_has_caller(sep, excl_caller))
			continue;

		if (module.sm_size != 0 && !stacks_has_module(sep, &module))
			continue;

		if (excl_module.sm_size != 0 &&
		    stacks_has_module(sep, &excl_module))
			continue;

		if (tstate != -1U) {
			if (tstate == TSTATE_PANIC) {
				if (!sep->se_panic)
					continue;
			} else if (sep->se_panic || sep->se_tstate != tstate)
				continue;
		}
		if (excl_tstate != -1U) {
			if (excl_tstate == TSTATE_PANIC) {
				if (sep->se_panic)
					continue;
			} else if (!sep->se_panic &&
			    sep->se_tstate == excl_tstate)
				continue;
		}

		if (sobj_ops == SOBJ_ALL) {
			if (sep->se_sobj_ops == 0)
				continue;
		} else if (sobj_ops != 0) {
			if (sobj_ops != sep->se_sobj_ops)
				continue;
		}

		if (!(interesting && sep->se_panic)) {
			if (excl_sobj_ops == SOBJ_ALL) {
				if (sep->se_sobj_ops != 0)
					continue;
			} else if (excl_sobj_ops != 0) {
				if (excl_sobj_ops == sep->se_sobj_ops)
					continue;
			}
		}

		if (flags & DCMD_PIPE_OUT) {
			while (sep != NULL) {
				mdb_printf("%lr\n", sep->se_thread);
				sep = only_matching ?
				    sep->se_next : sep->se_dup;
			}
			continue;
		}

		if (all || !printed) {
			mdb_printf("%<u>%-?s %-8s %-?s %8s%</u>\n",
			    "THREAD", "STATE", "SOBJ", "COUNT");
			printed = 1;
		}

		do {
			char state[20];
			char sobj[100];

			tstate_to_text(cur->se_tstate, cur->se_panic,
			    state, sizeof (state));
			sobj_to_text(cur->se_sobj_ops,
			    sobj, sizeof (sobj));

			if (cur == sep)
				mdb_printf("%-?p %-8s %-?s %8d\n",
				    cur->se_thread, state, sobj, count);
			else
				mdb_printf("%-?p %-8s %-?s %8s\n",
				    cur->se_thread, state, sobj, "-");

			cur = only_matching ? cur->se_next : cur->se_dup;
		} while (all && cur != NULL);

		if (sep->se_failed != 0) {
			char *reason;
			switch (sep->se_failed) {
			case FSI_FAIL_NOTINMEMORY:
				reason = "thread not in memory";
				break;
			case FSI_FAIL_THREADCORRUPT:
				reason = "thread structure stack info corrupt";
				break;
			case FSI_FAIL_STACKNOTFOUND:
				reason = "no consistent stack found";
				break;
			default:
				reason = "unknown failure";
				break;
			}
			mdb_printf("%?s <%s>\n", "", reason);
		}

		for (frame = 0; frame < sep->se_depth; frame++)
			mdb_printf("%?s %a\n", "", sep->se_stack[frame]);
		if (sep->se_overflow)
			mdb_printf("%?s ... truncated ...\n", "");
		mdb_printf("\n");
	}

	if (flags & DCMD_ADDRSPEC) {
		for (idx = 0; idx < p.pipe_len; idx++)
			if (seen[idx] == 0)
				mdb_warn("stacks: %p not in thread list\n",
				    p.pipe_data[idx]);
	}
	return (DCMD_OK);
}
