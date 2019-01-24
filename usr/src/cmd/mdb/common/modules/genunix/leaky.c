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

/*
 * A generic memory leak detector.  The target interface, defined in
 * <leaky_impl.h>, is implemented by the genunix and libumem dmods to fill
 * in the details of operation.
 */

#include <mdb/mdb_modapi.h>

#include "leaky.h"
#include "leaky_impl.h"

#define	LK_BUFCTLHSIZE	127

/*
 * We re-use the low bit of the lkm_addr as the 'marked' bit.
 */
#define	LK_MARKED(b)	((uintptr_t)(b) & 1)
#define	LK_MARK(b)	((b) |= 1)
#define	LK_ADDR(b)	((uintptr_t)(b) & ~1UL)

/*
 * Possible values for lk_state.
 */
#define	LK_CLEAN	0	/* No outstanding mdb_alloc()'s */
#define	LK_SWEEPING	1	/* Potentially some outstanding mdb_alloc()'s */
#define	LK_DONE		2	/* All mdb_alloc()'s complete */
#define	LK_CLEANING	3	/* Currently cleaning prior mdb_alloc()'s */

static volatile int lk_state;

#define	LK_STATE_SIZE	10000	/* completely arbitrary */

typedef int leak_ndx_t;		/* change if >2 billion buffers are needed */

typedef struct leak_state {
	struct leak_state *lks_next;
	leak_ndx_t lks_stack[LK_STATE_SIZE];
} leak_state_t;

typedef struct leak_beans {
	int lkb_dups;
	int lkb_follows;
	int lkb_misses;
	int lkb_dismissals;
	int lkb_pushes;
	int lkb_deepest;
} leak_beans_t;

typedef struct leak_type {
	int		lt_type;
	size_t		lt_leaks;
	leak_bufctl_t	**lt_sorted;
} leak_type_t;

typedef struct leak_walk {
	int lkw_ndx;
	leak_bufctl_t *lkw_current;
	leak_bufctl_t *lkw_hash_next;
} leak_walk_t;

#define	LK_SCAN_BUFFER_SIZE	16384
static uintptr_t *lk_scan_buffer;

static leak_mtab_t *lk_mtab;
static leak_state_t *lk_free_state;
static leak_ndx_t lk_nbuffers;
static leak_beans_t lk_beans;
static leak_bufctl_t *lk_bufctl[LK_BUFCTLHSIZE];
static leak_type_t lk_types[LK_NUM_TYPES];
static size_t lk_memusage;
#ifndef _KMDB
static hrtime_t lk_begin;
static hrtime_t lk_vbegin;
#endif
static uint_t lk_verbose = FALSE;

static void
leaky_verbose(char *str, uint64_t stat)
{
	if (lk_verbose == FALSE)
		return;

	mdb_printf("findleaks: ");

	if (str == NULL) {
		mdb_printf("\n");
		return;
	}

	mdb_printf("%*s => %lld\n", 30, str, stat);
}

static void
leaky_verbose_perc(char *str, uint64_t stat, uint64_t total)
{
	uint_t perc = (stat * 100) / total;
	uint_t tenths = ((stat * 1000) / total) % 10;

	if (lk_verbose == FALSE)
		return;

	mdb_printf("findleaks: %*s => %-13lld (%2d.%1d%%)\n",
	    30, str, stat, perc, tenths);
}

static void
leaky_verbose_begin(void)
{
	/* kmdb can't tell time */
#ifndef _KMDB
	extern hrtime_t gethrvtime(void);
	lk_begin = gethrtime();
	lk_vbegin = gethrvtime();
#endif
	lk_memusage = 0;
}

static void
leaky_verbose_end(void)
{
	/* kmdb can't tell time */
#ifndef _KMDB
	extern hrtime_t gethrvtime(void);

	hrtime_t ts = gethrtime() - lk_begin;
	hrtime_t sec = ts / (hrtime_t)NANOSEC;
	hrtime_t nsec = ts % (hrtime_t)NANOSEC;

	hrtime_t vts = gethrvtime() - lk_vbegin;
	hrtime_t vsec = vts / (hrtime_t)NANOSEC;
	hrtime_t vnsec = vts % (hrtime_t)NANOSEC;
#endif

	if (lk_verbose == FALSE)
		return;

	mdb_printf("findleaks: %*s => %lu kB\n",
	    30, "peak memory usage", (lk_memusage + 1023)/1024);
#ifndef _KMDB
	mdb_printf("findleaks: %*s => %lld.%lld seconds\n",
	    30, "elapsed CPU time", vsec, (vnsec * 10)/(hrtime_t)NANOSEC);
	mdb_printf("findleaks: %*s => %lld.%lld seconds\n",
	    30, "elapsed wall time", sec, (nsec * 10)/(hrtime_t)NANOSEC);
#endif
	leaky_verbose(NULL, 0);
}

static void *
leaky_alloc(size_t sz, uint_t flags)
{
	void *buf = mdb_alloc(sz, flags);

	if (buf != NULL)
		lk_memusage += sz;

	return (buf);
}

static void *
leaky_zalloc(size_t sz, uint_t flags)
{
	void *buf = mdb_zalloc(sz, flags);

	if (buf != NULL)
		lk_memusage += sz;

	return (buf);
}

static int
leaky_mtabcmp(const void *l, const void *r)
{
	const leak_mtab_t *lhs = (const leak_mtab_t *)l;
	const leak_mtab_t *rhs = (const leak_mtab_t *)r;

	if (lhs->lkm_base < rhs->lkm_base)
		return (-1);
	if (lhs->lkm_base > rhs->lkm_base)
		return (1);

	return (0);
}

static leak_ndx_t
leaky_search(uintptr_t addr)
{
	leak_ndx_t left = 0, right = lk_nbuffers - 1, guess;

	while (right >= left) {
		guess = (right + left) >> 1;

		if (addr < LK_ADDR(lk_mtab[guess].lkm_base)) {
			right = guess - 1;
			continue;
		}

		if (addr >= lk_mtab[guess].lkm_limit) {
			left = guess + 1;
			continue;
		}

		return (guess);
	}

	return (-1);
}

void
leaky_grep(uintptr_t addr, size_t size)
{
	uintptr_t *buf, *cur, *end;
	size_t bytes, newsz, nptrs;
	leak_state_t *state = NULL, *new_state;
	uint_t state_idx;
	uintptr_t min = LK_ADDR(lk_mtab[0].lkm_base);
	uintptr_t max = lk_mtab[lk_nbuffers - 1].lkm_limit;
	int dups = 0, misses = 0, depth = 0, deepest = 0;
	int follows = 0, dismissals = 0, pushes = 0;
	leak_ndx_t mtab_ndx;
	leak_mtab_t *lmp;
	uintptr_t nbase;
	uintptr_t base;
	size_t base_size;
	const uintptr_t mask = sizeof (uintptr_t) - 1;

	if (addr == 0 || size == 0)
		return;

	state_idx = 0;

	/*
	 * Our main loop, led by the 'pop' label:
	 *	1)  read in a buffer piece by piece,
	 *	2)  mark all unmarked mtab entries reachable from it, and
	 *	    either scan them in-line or push them onto our stack of
	 *	    unfinished work.
	 *	3)  pop the top mtab entry off the stack, and loop.
	 */
pop:
	base = addr;
	base_size = size;

	/*
	 * If our address isn't pointer-aligned, we need to align it and
	 * whack the size appropriately.
	 */
	if (size < mask) {
		size = 0;
	} else if (addr & mask) {
		size -= (mask + 1) - (addr & mask);
		addr += (mask + 1) - (addr & mask);
	}
	size -= (size & mask);

	while (size > 0) {
		buf = lk_scan_buffer;
		end = &buf[LK_SCAN_BUFFER_SIZE / sizeof (uintptr_t)];

		bytes = MIN(size, LK_SCAN_BUFFER_SIZE);
		cur = end - (bytes / sizeof (uintptr_t));

		if (mdb_vread(cur, bytes, addr) == -1) {
			mdb_warn("[%p, %p): couldn't read %ld bytes at %p",
			    base, base + base_size, bytes, addr);
			break;
		}

		addr += bytes;
		size -= bytes;

		/*
		 * The buffer looks like:  ('+'s are unscanned data)
		 *
		 * -----------------------------++++++++++++++++
		 * |				|		|
		 * buf				cur		end
		 *
		 * cur scans forward.  When we encounter a new buffer, and
		 * it will fit behind "cur", we read it in and back up cur,
		 * processing it immediately.
		 */
		while (cur < end) {
			uintptr_t ptr = *cur++;

			if (ptr < min || ptr > max) {
				dismissals++;
				continue;
			}

			if ((mtab_ndx = leaky_search(ptr)) == -1) {
				misses++;
				continue;
			}

			lmp = &lk_mtab[mtab_ndx];
			if (LK_MARKED(lmp->lkm_base)) {
				dups++;			/* already seen */
				continue;
			}

			/*
			 * Found an unmarked buffer.  Mark it, then either
			 * read it in, or add it to the stack of pending work.
			 */
			follows++;
			LK_MARK(lmp->lkm_base);

			nbase = LK_ADDR(lmp->lkm_base);
			newsz = lmp->lkm_limit - nbase;

			nptrs = newsz / sizeof (uintptr_t);
			newsz = nptrs * sizeof (uintptr_t);

			if ((nbase & mask) == 0 && nptrs <= (cur - buf) &&
			    mdb_vread(cur - nptrs, newsz, nbase) != -1) {
				cur -= nptrs;
				continue;
			}

			/*
			 * couldn't process it in-place -- add it to the
			 * stack.
			 */
			if (state == NULL || state_idx == LK_STATE_SIZE) {
				if ((new_state = lk_free_state) != NULL)
					lk_free_state = new_state->lks_next;
				else
					new_state = leaky_zalloc(
					    sizeof (*state), UM_SLEEP | UM_GC);

				new_state->lks_next = state;
				state = new_state;
				state_idx = 0;
			}

			pushes++;
			state->lks_stack[state_idx++] = mtab_ndx;
			if (++depth > deepest)
				deepest = depth;
		}
	}

	/*
	 * Retrieve the next mtab index, extract its info, and loop around
	 * to process it.
	 */
	if (state_idx == 0 && state != NULL) {
		new_state = state->lks_next;

		state->lks_next = lk_free_state;
		lk_free_state = state;

		state = new_state;
		state_idx = LK_STATE_SIZE;
	}

	if (depth > 0) {
		mtab_ndx = state->lks_stack[--state_idx];

		addr = LK_ADDR(lk_mtab[mtab_ndx].lkm_base);
		size = lk_mtab[mtab_ndx].lkm_limit - addr;
		depth--;

		goto pop;
	}

	/*
	 * update the beans
	 */
	lk_beans.lkb_dups += dups;
	lk_beans.lkb_dismissals += dismissals;
	lk_beans.lkb_misses += misses;
	lk_beans.lkb_follows += follows;
	lk_beans.lkb_pushes += pushes;

	if (deepest > lk_beans.lkb_deepest)
		lk_beans.lkb_deepest = deepest;
}

static void
leaky_do_grep_ptr(uintptr_t loc, int process)
{
	leak_ndx_t ndx;
	leak_mtab_t *lkmp;
	size_t sz;

	if (loc < LK_ADDR(lk_mtab[0].lkm_base) ||
	    loc > lk_mtab[lk_nbuffers - 1].lkm_limit) {
		lk_beans.lkb_dismissals++;
		return;
	}
	if ((ndx = leaky_search(loc)) == -1) {
		lk_beans.lkb_misses++;
		return;
	}

	lkmp = &lk_mtab[ndx];
	sz = lkmp->lkm_limit - lkmp->lkm_base;

	if (LK_MARKED(lkmp->lkm_base)) {
		lk_beans.lkb_dups++;
	} else {
		LK_MARK(lkmp->lkm_base);
		lk_beans.lkb_follows++;
		if (process)
			leaky_grep(lkmp->lkm_base, sz);
	}
}

void
leaky_grep_ptr(uintptr_t loc)
{
	leaky_do_grep_ptr(loc, 1);
}

void
leaky_mark_ptr(uintptr_t loc)
{
	leaky_do_grep_ptr(loc, 0);
}

/*
 * This may be used to manually process a marked buffer.
 */
int
leaky_lookup_marked(uintptr_t loc, uintptr_t *addr_out, size_t *size_out)
{
	leak_ndx_t ndx;
	leak_mtab_t *lkmp;

	if ((ndx = leaky_search(loc)) == -1)
		return (0);

	lkmp = &lk_mtab[ndx];
	*addr_out = LK_ADDR(lkmp->lkm_base);
	*size_out = lkmp->lkm_limit - LK_ADDR(lkmp->lkm_base);
	return (1);
}

void
leaky_add_leak(int type, uintptr_t addr, uintptr_t bufaddr, hrtime_t timestamp,
    leak_pc_t *stack, uint_t depth, uintptr_t cid, uintptr_t data)
{
	leak_bufctl_t *nlkb, *lkb;
	uintptr_t total = 0;
	size_t ndx;
	int i;

	if (type < 0 || type >= LK_NUM_TYPES || depth != (uint8_t)depth) {
		mdb_warn("invalid arguments to leaky_add_leak()\n");
		return;
	}

	nlkb = leaky_zalloc(LEAK_BUFCTL_SIZE(depth), UM_SLEEP);
	nlkb->lkb_type = type;
	nlkb->lkb_addr = addr;
	nlkb->lkb_bufaddr = bufaddr;
	nlkb->lkb_cid = cid;
	nlkb->lkb_data = data;
	nlkb->lkb_depth = depth;
	nlkb->lkb_timestamp = timestamp;

	total = type;
	for (i = 0; i < depth; i++) {
		total += stack[i];
		nlkb->lkb_stack[i] = stack[i];
	}

	ndx = total % LK_BUFCTLHSIZE;

	if ((lkb = lk_bufctl[ndx]) == NULL) {
		lk_types[type].lt_leaks++;
		lk_bufctl[ndx] = nlkb;
		return;
	}

	for (;;) {
		if (lkb->lkb_type != type || lkb->lkb_depth != depth ||
		    lkb->lkb_cid != cid)
			goto no_match;

		for (i = 0; i < depth; i++)
			if (lkb->lkb_stack[i] != stack[i])
				goto no_match;

		/*
		 * If we're here, we've found a matching stack; link it in.
		 * Note that the volatile cast assures that these stores
		 * will occur in program order (thus assuring that we can
		 * take an interrupt and still be in a sane enough state to
		 * throw away the data structure later, in leaky_cleanup()).
		 */
		((volatile leak_bufctl_t *)nlkb)->lkb_next = lkb->lkb_next;
		((volatile leak_bufctl_t *)lkb)->lkb_next = nlkb;
		lkb->lkb_dups++;

		/*
		 * If we're older, swap places so that we are the
		 * representative leak.
		 */
		if (timestamp < lkb->lkb_timestamp) {
			nlkb->lkb_addr = lkb->lkb_addr;
			nlkb->lkb_bufaddr = lkb->lkb_bufaddr;
			nlkb->lkb_data = lkb->lkb_data;
			nlkb->lkb_timestamp = lkb->lkb_timestamp;

			lkb->lkb_addr = addr;
			lkb->lkb_bufaddr = bufaddr;
			lkb->lkb_data = data;
			lkb->lkb_timestamp = timestamp;
		}
		break;

no_match:
		if (lkb->lkb_hash_next == NULL) {
			lkb->lkb_hash_next = nlkb;
			lk_types[type].lt_leaks++;
			break;
		}
		lkb = lkb->lkb_hash_next;
	}
}

int
leaky_ctlcmp(const void *l, const void *r)
{
	const leak_bufctl_t *lhs = *((const leak_bufctl_t **)l);
	const leak_bufctl_t *rhs = *((const leak_bufctl_t **)r);

	return (leaky_subr_bufctl_cmp(lhs, rhs));
}

void
leaky_sort(void)
{
	int type, i, j;
	leak_bufctl_t *lkb;
	leak_type_t *ltp;

	for (type = 0; type < LK_NUM_TYPES; type++) {
		ltp = &lk_types[type];

		if (ltp->lt_leaks == 0)
			continue;

		ltp->lt_sorted = leaky_alloc(ltp->lt_leaks *
		    sizeof (leak_bufctl_t *), UM_SLEEP);

		j = 0;
		for (i = 0; i < LK_BUFCTLHSIZE; i++) {
			for (lkb = lk_bufctl[i]; lkb != NULL;
			    lkb = lkb->lkb_hash_next) {
				if (lkb->lkb_type == type)
					ltp->lt_sorted[j++] = lkb;
			}
		}
		if (j != ltp->lt_leaks)
			mdb_warn("expected %d leaks, got %d\n", ltp->lt_leaks,
			    j);

		qsort(ltp->lt_sorted, ltp->lt_leaks, sizeof (leak_bufctl_t *),
		    leaky_ctlcmp);
	}
}

void
leaky_cleanup(int force)
{
	int i;
	leak_bufctl_t *lkb, *l, *next;

	/*
	 * State structures are allocated UM_GC, so we just need to nuke
	 * the freelist pointer.
	 */
	lk_free_state = NULL;

	switch (lk_state) {
	case LK_CLEAN:
		return;		/* nothing to do */

	case LK_CLEANING:
		mdb_warn("interrupted during ::findleaks cleanup; some mdb "
		    "memory will be leaked\n");

		for (i = 0; i < LK_BUFCTLHSIZE; i++)
			lk_bufctl[i] = NULL;

		for (i = 0; i < LK_NUM_TYPES; i++) {
			lk_types[i].lt_leaks = 0;
			lk_types[i].lt_sorted = NULL;
		}

		bzero(&lk_beans, sizeof (lk_beans));
		lk_state = LK_CLEAN;
		return;

	case LK_SWEEPING:
		break;		/* must clean up */

	case LK_DONE:
	default:
		if (!force)
			return;
		break;		/* only clean up if forced */
	}

	lk_state = LK_CLEANING;

	for (i = 0; i < LK_NUM_TYPES; i++) {
		if (lk_types[i].lt_sorted != NULL) {
			mdb_free(lk_types[i].lt_sorted,
			    lk_types[i].lt_leaks * sizeof (leak_bufctl_t *));
			lk_types[i].lt_sorted = NULL;
		}
		lk_types[i].lt_leaks = 0;
	}

	for (i = 0; i < LK_BUFCTLHSIZE; i++) {
		for (lkb = lk_bufctl[i]; lkb != NULL; lkb = next) {
			for (l = lkb->lkb_next; l != NULL; l = next) {
				next = l->lkb_next;
				mdb_free(l, LEAK_BUFCTL_SIZE(l->lkb_depth));
			}
			next = lkb->lkb_hash_next;
			mdb_free(lkb, LEAK_BUFCTL_SIZE(lkb->lkb_depth));
		}
		lk_bufctl[i] = NULL;
	}

	bzero(&lk_beans, sizeof (lk_beans));
	lk_state = LK_CLEAN;
}

int
leaky_filter(const leak_pc_t *stack, int depth, uintptr_t filter)
{
	int i;
	GElf_Sym sym;
	char c;

	if (filter == 0)
		return (1);

	for (i = 0; i < depth; i++) {
		if (stack[i] == filter)
			return (1);

		if (mdb_lookup_by_addr(stack[i], MDB_SYM_FUZZY,
		    &c, sizeof (c), &sym) == -1)
			continue;

		if ((uintptr_t)sym.st_value == filter)
			return (1);
	}

	return (0);
}

void
leaky_dump(uintptr_t filter, uint_t dump_verbose)
{
	int i;
	size_t leaks;
	leak_bufctl_t **sorted;
	leak_bufctl_t *lkb;
	int seen = 0;

	for (i = 0; i < LK_NUM_TYPES; i++) {
		leaks = lk_types[i].lt_leaks;
		sorted = lk_types[i].lt_sorted;

		leaky_subr_dump_start(i);
		while (leaks-- > 0) {
			lkb = *sorted++;

			if (!leaky_filter(lkb->lkb_stack, lkb->lkb_depth,
			    filter))
				continue;

			seen = 1;
			leaky_subr_dump(lkb, 0);
		}
		leaky_subr_dump_end(i);
	}

	if (!seen) {
		if (filter != 0)
			mdb_printf(
			    "findleaks: no memory leaks matching %a found\n",
			    filter);
		else
			mdb_printf(
			    "findleaks: no memory leaks detected\n");
	}

	if (!dump_verbose || !seen)
		return;

	mdb_printf("\n");

	for (i = 0; i < LK_NUM_TYPES; i++) {
		leaks = lk_types[i].lt_leaks;
		sorted = lk_types[i].lt_sorted;

		while (leaks-- > 0) {
			lkb = *sorted++;

			if (!leaky_filter(lkb->lkb_stack, lkb->lkb_depth,
			    filter))
				continue;

			leaky_subr_dump(lkb, 1);
		}
	}
}

static const char *const findleaks_desc =
	"Does a conservative garbage collection of the heap in order to find\n"
	"potentially leaked buffers.  Similar leaks are coalesced by stack\n"
	"trace, with the oldest leak picked as representative.  The leak\n"
	"table is cached between invocations.\n"
	"\n"
	"addr, if provided, should be a function or PC location.  Reported\n"
	"leaks will then be limited to those with that function or PC in\n"
	"their stack trace.\n"
	"\n"
	"The 'leak' and 'leakbuf' walkers can be used to retrieve coalesced\n"
	"leaks.\n";

static const char *const findleaks_args =
	"  -d    detail each representative leak (long)\n"
	"  -f    throw away cached state, and do a full run\n"
	"  -v    report verbose information about the findleaks run\n";

void
findleaks_help(void)
{
	mdb_printf("%s\n", findleaks_desc);
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s", findleaks_args);
}

#define	LK_REPORT_BEAN(x) leaky_verbose_perc(#x, lk_beans.lkb_##x, total);

/*ARGSUSED*/
int
findleaks(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t est = 0;
	leak_ndx_t i;
	leak_mtab_t *lmp;
	ssize_t total;
	uintptr_t filter = 0;
	uint_t dump = 0;
	uint_t force = 0;
	uint_t verbose = 0;
	int ret;

	if (flags & DCMD_ADDRSPEC)
		filter = addr;

	if (mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &dump,
	    'f', MDB_OPT_SETBITS, TRUE, &force,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (verbose || force)
		lk_verbose = verbose;

	/*
	 * Clean any previous ::findleaks.
	 */
	leaky_cleanup(force);

	if (lk_state == LK_DONE) {
		if (lk_verbose)
			mdb_printf("findleaks: using cached results "
			    "(use '-f' to force a full run)\n");
		goto dump;
	}

	leaky_verbose_begin();

	if ((ret = leaky_subr_estimate(&est)) != DCMD_OK)
		return (ret);

	leaky_verbose("maximum buffers", est);

	/*
	 * Now we have an upper bound on the number of buffers.  Allocate
	 * our mtab array.
	 */
	lk_mtab = leaky_zalloc(est * sizeof (leak_mtab_t), UM_SLEEP | UM_GC);
	lmp = lk_mtab;

	if ((ret = leaky_subr_fill(&lmp)) != DCMD_OK)
		return (ret);

	lk_nbuffers = lmp - lk_mtab;

	qsort(lk_mtab, lk_nbuffers, sizeof (leak_mtab_t), leaky_mtabcmp);

	/*
	 * validate the mtab table now that it is sorted
	 */
	for (i = 0; i < lk_nbuffers; i++) {
		if (lk_mtab[i].lkm_base >= lk_mtab[i].lkm_limit) {
			mdb_warn("[%p, %p): invalid mtab\n",
			    lk_mtab[i].lkm_base, lk_mtab[i].lkm_limit);
			return (DCMD_ERR);
		}

		if (i < lk_nbuffers - 1 &&
		    lk_mtab[i].lkm_limit > lk_mtab[i + 1].lkm_base) {
			mdb_warn("[%p, %p) and [%p, %p): overlapping mtabs\n",
			    lk_mtab[i].lkm_base, lk_mtab[i].lkm_limit,
			    lk_mtab[i + 1].lkm_base, lk_mtab[i + 1].lkm_limit);
			return (DCMD_ERR);
		}
	}

	leaky_verbose("actual buffers", lk_nbuffers);

	lk_scan_buffer = leaky_zalloc(LK_SCAN_BUFFER_SIZE, UM_SLEEP | UM_GC);

	if ((ret = leaky_subr_run()) != DCMD_OK)
		return (ret);

	lk_state = LK_SWEEPING;

	for (i = 0; i < lk_nbuffers; i++) {
		if (LK_MARKED(lk_mtab[i].lkm_base))
			continue;
		leaky_subr_add_leak(&lk_mtab[i]);
	}

	total = lk_beans.lkb_dismissals + lk_beans.lkb_misses +
	    lk_beans.lkb_dups + lk_beans.lkb_follows;

	leaky_verbose(NULL, 0);
	leaky_verbose("potential pointers", total);
	LK_REPORT_BEAN(dismissals);
	LK_REPORT_BEAN(misses);
	LK_REPORT_BEAN(dups);
	LK_REPORT_BEAN(follows);

	leaky_verbose(NULL, 0);
	leaky_verbose_end();

	leaky_sort();
	lk_state = LK_DONE;
dump:
	leaky_dump(filter, dump);

	return (DCMD_OK);
}

int
leaky_walk_init(mdb_walk_state_t *wsp)
{
	leak_walk_t *lw;
	leak_bufctl_t *lkb, *cur;

	uintptr_t addr;
	int i;

	if (lk_state != LK_DONE) {
		mdb_warn("::findleaks must be run %sbefore leaks can be"
		    " walked\n", lk_state != LK_CLEAN ? "to completion " : "");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0) {
		lkb = NULL;
		goto found;
	}

	addr = wsp->walk_addr;

	/*
	 * Search the representative leaks first, since that's what we
	 * report in the table.  If that fails, search everything.
	 *
	 * Note that we goto found with lkb as the head of desired dup list.
	 */
	for (i = 0; i < LK_BUFCTLHSIZE; i++) {
		for (lkb = lk_bufctl[i]; lkb != NULL; lkb = lkb->lkb_hash_next)
			if (lkb->lkb_addr == addr)
				goto found;
	}

	for (i = 0; i < LK_BUFCTLHSIZE; i++) {
		for (lkb = lk_bufctl[i]; lkb != NULL; lkb = lkb->lkb_hash_next)
			for (cur = lkb; cur != NULL; cur = cur->lkb_next)
				if (cur->lkb_addr == addr)
					goto found;
	}

	mdb_warn("%p is not a leaked ctl address\n", addr);
	return (WALK_ERR);

found:
	wsp->walk_data = lw = mdb_zalloc(sizeof (*lw), UM_SLEEP);
	lw->lkw_ndx = 0;
	lw->lkw_current = lkb;
	lw->lkw_hash_next = NULL;

	return (WALK_NEXT);
}

leak_bufctl_t *
leaky_walk_step_common(mdb_walk_state_t *wsp)
{
	leak_walk_t *lw = wsp->walk_data;
	leak_bufctl_t *lk;

	if ((lk = lw->lkw_current) == NULL) {
		if ((lk = lw->lkw_hash_next) == NULL) {
			if (wsp->walk_addr)
				return (NULL);

			while (lk == NULL && lw->lkw_ndx < LK_BUFCTLHSIZE)
				lk = lk_bufctl[lw->lkw_ndx++];

			if (lw->lkw_ndx == LK_BUFCTLHSIZE)
				return (NULL);
		}

		lw->lkw_hash_next = lk->lkb_hash_next;
	}

	lw->lkw_current = lk->lkb_next;
	return (lk);
}

int
leaky_walk_step(mdb_walk_state_t *wsp)
{
	leak_bufctl_t *lk;

	if ((lk = leaky_walk_step_common(wsp)) == NULL)
		return (WALK_DONE);

	return (leaky_subr_invoke_callback(lk, wsp->walk_callback,
	    wsp->walk_cbdata));
}

void
leaky_walk_fini(mdb_walk_state_t *wsp)
{
	leak_walk_t *lw = wsp->walk_data;

	mdb_free(lw, sizeof (leak_walk_t));
}

int
leaky_buf_walk_step(mdb_walk_state_t *wsp)
{
	leak_bufctl_t *lk;

	if ((lk = leaky_walk_step_common(wsp)) == NULL)
		return (WALK_DONE);

	return (wsp->walk_callback(lk->lkb_bufaddr, NULL, wsp->walk_cbdata));
}
