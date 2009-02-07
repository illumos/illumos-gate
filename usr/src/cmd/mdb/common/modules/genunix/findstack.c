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

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/stack.h>
#include <sys/thread.h>

#include "findstack.h"
#include "thread.h"
#include "sobj.h"

typedef struct findstack_info {
	uintptr_t	*fsi_stack;	/* place to record frames */

	uintptr_t	fsi_sp;		/* stack pointer */
	uintptr_t	fsi_pc;		/* pc */
	uintptr_t	fsi_sobj_ops;	/* sobj_ops */

	uint_t		fsi_tstate;	/* t_state */

	uchar_t		fsi_depth;	/* stack depth */
	uchar_t		fsi_failed;	/* search failed */
	uchar_t		fsi_overflow;	/* stack was deeper than max_depth */
	uchar_t		fsi_panic;	/* thread called panic() */

	uchar_t		fsi_max_depth;	/* stack frames available */
} findstack_info_t;
#define	FSI_FAIL_BADTHREAD	1
#define	FSI_FAIL_NOTINMEMORY	2
#define	FSI_FAIL_THREADCORRUPT	3
#define	FSI_FAIL_STACKNOTFOUND	4

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

#define	fs_dprintf(x)					\
	if (findstack_debug_on) {			\
		mdb_printf("findstack debug: ");	\
		/*CSTYLED*/				\
		mdb_printf x ;				\
	}

static int findstack_debug_on = 0;

#if defined(__i386) || defined(__amd64)
struct rwindow {
	uintptr_t rw_fp;
	uintptr_t rw_rtn;
};
#endif

#define	TOO_BIG_FOR_A_STACK (1024 * 1024)

#define	KTOU(p) ((p) - kbase + ubase)
#define	UTOK(p) ((p) - ubase + kbase)

#define	CRAWL_FOUNDALL	(-1)

/*
 * Given a stack pointer, try to crawl down it to the bottom.
 * "frame" is a VA in MDB's address space.
 *
 * Returns the number of frames successfully crawled down, or
 * CRAWL_FOUNDALL if it got to the bottom of the stack.
 */
static int
crawl(uintptr_t frame, uintptr_t kbase, uintptr_t ktop, uintptr_t ubase,
    int kill_fp, findstack_info_t *fsip)
{
	int levels = 0;

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	fs_dprintf(("<0> frame = %p, kbase = %p, ktop = %p, ubase = %p\n",
	    frame, kbase, ktop, ubase));
	for (;;) {
		uintptr_t fp;
		long *fpp = (long *)&((struct rwindow *)frame)->rw_fp;

		fs_dprintf(("<1> fpp = %p, frame = %p\n", fpp, frame));

		if ((frame & (STACK_ALIGN - 1)) != 0)
			break;

		fp = ((struct rwindow *)frame)->rw_fp + STACK_BIAS;
		if (fsip->fsi_depth < fsip->fsi_max_depth)
			fsip->fsi_stack[fsip->fsi_depth++] =
			    ((struct rwindow *)frame)->rw_rtn;
		else
			fsip->fsi_overflow = 1;

		fs_dprintf(("<2> fp = %p\n", fp));

		if (fp == ktop)
			return (CRAWL_FOUNDALL);
		fs_dprintf(("<3> not at base\n"));

#if defined(__i386) || defined(__amd64)
		if (ktop - fp == sizeof (struct rwindow)) {
			fs_dprintf(("<4> found base\n"));
			return (CRAWL_FOUNDALL);
		}
#endif

		fs_dprintf(("<5> fp = %p, kbase = %p, ktop - size = %p\n",
		    fp, kbase, ktop - sizeof (struct rwindow)));

		if (fp < kbase || fp >= (ktop - sizeof (struct rwindow)))
			break;

		frame = KTOU(fp);
		fs_dprintf(("<6> frame = %p\n", frame));

		/*
		 * NULL out the old %fp so we don't go down this stack
		 * more than once.
		 */
		if (kill_fp) {
			fs_dprintf(("<7> fpp = %p\n", fpp));
			*fpp = NULL;
		}

		fs_dprintf(("<8> levels = %d\n", levels));
		levels++;
	}

	return (levels);
}

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

/*ARGSUSED*/
static int
do_findstack(uintptr_t addr, findstack_info_t *fsip, uint_t print_warnings)
{
	kthread_t thr;
	size_t stksz;
	uintptr_t ubase, utop;
	uintptr_t kbase, ktop;
	uintptr_t win, sp;

	fsip->fsi_failed = 0;
	fsip->fsi_pc = 0;
	fsip->fsi_sp = 0;
	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	bzero(&thr, sizeof (thr));
	if (mdb_ctf_vread(&thr, "kthread_t", addr,
	    MDB_CTF_VREAD_IGNORE_ALL) == -1) {
		if (print_warnings)
			mdb_warn("couldn't read thread at %p\n", addr);
		fsip->fsi_failed = FSI_FAIL_BADTHREAD;
		return (DCMD_ERR);
	}

	fsip->fsi_sobj_ops = (uintptr_t)thr.t_sobj_ops;
	fsip->fsi_tstate = thr.t_state;
	fsip->fsi_panic = !!(thr.t_flag & T_PANIC);

	if ((thr.t_schedflag & TS_LOAD) == 0) {
		if (print_warnings)
			mdb_warn("thread %p isn't in memory\n", addr);
		fsip->fsi_failed = FSI_FAIL_NOTINMEMORY;
		return (DCMD_ERR);
	}

	if (thr.t_stk < thr.t_stkbase) {
		if (print_warnings)
			mdb_warn(
			    "stack base or stack top corrupt for thread %p\n",
			    addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	kbase = (uintptr_t)thr.t_stkbase;
	ktop = (uintptr_t)thr.t_stk;
	stksz = ktop - kbase;

#ifdef __amd64
	/*
	 * The stack on amd64 is intentionally misaligned, so ignore the top
	 * half-frame.  See thread_stk_init().  When handling traps, the frame
	 * is automatically aligned by the hardware, so we only alter ktop if
	 * needed.
	 */
	if ((ktop & (STACK_ALIGN - 1)) != 0)
		ktop -= STACK_ENTRY_ALIGN;
#endif

	/*
	 * If the stack size is larger than a meg, assume that it's bogus.
	 */
	if (stksz > TOO_BIG_FOR_A_STACK) {
		if (print_warnings)
			mdb_warn("stack size for thread %p is too big to be "
			    "reasonable\n", addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	/*
	 * This could be (and was) a UM_GC allocation.  Unfortunately,
	 * stksz tends to be very large.  As currently implemented, dcmds
	 * invoked as part of pipelines don't have their UM_GC-allocated
	 * memory freed until the pipeline completes.  With stksz in the
	 * neighborhood of 20k, the popular ::walk thread |::findstack
	 * pipeline can easily run memory-constrained debuggers (kmdb) out
	 * of memory.  This can be changed back to a gc-able allocation when
	 * the debugger is changed to free UM_GC memory more promptly.
	 */
	ubase = (uintptr_t)mdb_alloc(stksz, UM_SLEEP);
	utop = ubase + stksz;
	if (mdb_vread((caddr_t)ubase, stksz, kbase) != stksz) {
		mdb_free((void *)ubase, stksz);
		if (print_warnings)
			mdb_warn("couldn't read entire stack for thread %p\n",
			    addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	/*
	 * Try the saved %sp first, if it looks reasonable.
	 */
	sp = KTOU((uintptr_t)thr.t_sp + STACK_BIAS);
	if (sp >= ubase && sp <= utop) {
		if (crawl(sp, kbase, ktop, ubase, 0, fsip) == CRAWL_FOUNDALL) {
			fsip->fsi_sp = (uintptr_t)thr.t_sp;
#if !defined(__i386)
			fsip->fsi_pc = (uintptr_t)thr.t_pc;
#endif
			goto found;
		}
	}

	/*
	 * Now walk through the whole stack, starting at the base,
	 * trying every possible "window".
	 */
	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		if (crawl(win, kbase, ktop, ubase, 1, fsip) == CRAWL_FOUNDALL) {
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	/*
	 * We didn't conclusively find the stack.  So we'll take another lap,
	 * and print out anything that looks possible.
	 */
	if (print_warnings)
		mdb_printf("Possible stack pointers for thread %p:\n", addr);
	(void) mdb_vread((caddr_t)ubase, stksz, kbase);

	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		uintptr_t fp = ((struct rwindow *)win)->rw_fp;
		int levels;

		if ((levels = crawl(win, kbase, ktop, ubase, 1, fsip)) > 1) {
			if (print_warnings)
				mdb_printf("  %p (%d)\n", fp, levels);
		} else if (levels == CRAWL_FOUNDALL) {
			/*
			 * If this is a live system, the stack could change
			 * between the two mdb_vread(ubase, utop, kbase)'s,
			 * and we could have a fully valid stack here.
			 */
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;
	fsip->fsi_failed = FSI_FAIL_STACKNOTFOUND;

	mdb_free((void *)ubase, stksz);
	return (DCMD_ERR);
found:
	mdb_free((void *)ubase, stksz);
	return (DCMD_OK);
}

int
findstack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	findstack_info_t fsi;
	int retval;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	bzero(&fsi, sizeof (fsi));

	if ((retval = do_findstack(addr, &fsi, 1)) != DCMD_OK ||
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

	stacks_array_size = 0;
	stacks_state = STACKS_STATE_CLEAN;
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

	if (do_findstack(addr, fsip, 0) != DCMD_OK &&
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
stacks_run(int verbose)
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

	if (mdb_walk("thread", stacks_thread_cb, &si) != 0) {
		mdb_warn("cannot walk \"thread\"");
		return (DCMD_ERR);
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
static void
print_sobj_help(int type, const char *name, const char *ops_name, void *ign)
{
	mdb_printf(" %s", name);
}

/*ARGSUSED*/
static void
print_tstate_help(uint_t state, const char *name, void *ignored)
{
	mdb_printf(" %s", name);
}

void
stacks_help(void)
{
	mdb_printf(
"::stacks processes all of the thread stacks on the system, grouping\n"
"together threads which have the same:\n"
"\n"
"  * Thread state,\n"
"  * Sync object type, and\n"
"  * PCs in their stack trace.\n"
"\n"
"The default output (no address or options) is just a dump of the thread\n"
"groups in the system.  For a view of active threads, use \"::stacks -i\",\n"
"which filters out FREE threads (interrupt threads which are currently\n"
"inactive) and threads sleeping on a CV. (Note that those threads may still\n"
"be noteworthy; this is just for a first glance.)  More general filtering\n"
"options are described below, in the \"FILTERS\" section.\n"
"\n"
"::stacks can be used in a pipeline.  The input to ::stacks is one or more\n"
"thread pointers.  For example, to get a summary of threads in a process,\n"
"you can do:\n"
"\n"
"  %<b>procp%</b>::walk thread | ::stacks\n"
"\n"
"When output into a pipe, ::stacks prints all of the threads input,\n"
"filtered by the given filtering options.  This means that multiple\n"
"::stacks invocations can be piped together to achieve more complicated\n"
"filters.  For example, to get threads which have both 'fop_read' and\n"
"'cv_wait_sig_swap' in their stack trace, you could do:\n"
"\n"
"  ::stacks -c fop_read | ::stacks -c cv_wait_sig_swap_core\n"
"\n"
"To get the full list of threads in each group, use the '-a' flag:\n"
"\n"
"  ::stacks -a\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -a    Print all of the grouped threads, instead of just a count.\n"
"  -f    Force a re-run of the thread stack gathering.\n"
"  -v    Be verbose about thread stack gathering.\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>FILTERS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -i    Show active threads; equivalent to '-S CV -T FREE'.\n"
"  -c func[+offset]\n"
"        Only print threads whose stacks contain func/func+offset.\n"
"  -C func[+offset]\n"
"        Only print threads whose stacks do not contain func/func+offset.\n"
"  -s {type | ALL}\n"
"        Only print threads which are on a 'type' synchronization object\n"
"        (SOBJ).\n"
"  -S {type | ALL}\n"
"        Only print threads which are not on a 'type' SOBJ.\n"
"  -t tstate\n"
"        Only print threads which are in thread state 'tstate'.\n"
"  -T tstate\n"
"        Only print threads which are not in thread state 'tstate'.\n"
"\n");
	mdb_printf("   SOBJ types:");
	sobj_type_walk(print_sobj_help, NULL);
	mdb_printf("\n");
	mdb_printf("Thread states:");
	thread_walk_states(print_tstate_help, NULL);
	mdb_printf(" panic\n");
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
	const char *sobj = NULL;
	const char *excl_sobj = NULL;
	uintptr_t sobj_ops = 0, excl_sobj_ops = 0;
	const char *tstate_str = NULL;
	const char *excl_tstate_str = NULL;
	uint_t tstate = -1U;
	uint_t excl_tstate = -1U;

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

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &all,
	    'f', MDB_OPT_SETBITS, TRUE, &force,
	    'i', MDB_OPT_SETBITS, TRUE, &interesting,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'c', MDB_OPT_STR, &caller_str,
	    'C', MDB_OPT_STR, &excl_caller_str,
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

	if (sobj != NULL &&
	    text_to_sobj(sobj, &sobj_ops) != 0)
		return (DCMD_USAGE);

	if (excl_sobj != NULL &&
	    text_to_sobj(excl_sobj, &excl_sobj_ops) != 0)
		return (DCMD_USAGE);

	if (sobj_ops != 0 && excl_sobj_ops != 0) {
		mdb_warn("stacks: only one of -s and -S can be specified\n");
		return (DCMD_USAGE);
	}

	if (tstate_str &&
	    text_to_tstate(tstate_str, &tstate) != 0)
		return (DCMD_USAGE);
	if (excl_tstate_str &&
	    text_to_tstate(excl_tstate_str, &excl_tstate) != 0)
		return (DCMD_USAGE);

	if (tstate != -1U && excl_tstate != -1U) {
		mdb_warn("stacks: only one of -t and -T can be specified\n");
		return (DCMD_USAGE);
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
		int res = stacks_run(verbose);
		if (res != DCMD_OK)
			return (res);
	}

	if (!all && DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%-?s %-8s %-?s %8s%</u>\n",
		    "THREAD", "STATE", "SOBJ", "COUNT");
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

		if (all) {
			mdb_printf("%<u>%-?s %-8s %-?s %8s%</u>\n",
			    "THREAD", "STATE", "SOBJTYPE", "COUNT");
		}

		do {
			char state[20];
			char sobj[100];

			tstate_to_text(cur->se_tstate, cur->se_panic,
			    state, sizeof (state));
			sobj_to_text(cur->se_sobj_ops,
			    sobj, sizeof (sobj));

			if (cur == sep)
				mdb_printf("%?p %-8s %-?s %8d\n",
				    cur->se_thread, state, sobj, count);
			else
				mdb_printf("%?p %-8s %-?s %8s\n",
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
