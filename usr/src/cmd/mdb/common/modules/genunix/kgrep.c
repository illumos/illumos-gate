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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic memory walker, used by both the genunix and libumem dmods.
 */

#include <mdb/mdb_modapi.h>
#include <sys/sysmacros.h>

#include "kgrep.h"

#define	KGREP_FULL_MASK		(~(uintmax_t)0)

typedef struct kgrep_data {
	uintmax_t kg_pattern;
	uintmax_t kg_mask;		/* fancy only */
	uintmax_t kg_dist;		/* fancy only */
	uintptr_t kg_minaddr;		/* fancy only */
	uintptr_t kg_maxaddr;		/* fancy only */
	void *kg_page;
	size_t kg_pagesize;
	char kg_cbtype;
	char kg_seen;
} kgrep_data_t;

#define	KG_BASE		0
#define	KG_VERBOSE	1
#define	KG_PIPE		2

static void
kgrep_cb(uintptr_t addr, uintmax_t *val, int type)
{
	switch (type) {
	case KG_BASE:
	default:
		mdb_printf("%p\n", addr);
		break;
	case KG_VERBOSE:
		mdb_printf("%p:\t%llx\n", addr, *val);
		break;
	case KG_PIPE:
		mdb_printf("%#lr\n", addr);
		break;
	}
}

static int
kgrep_range_basic(uintptr_t base, uintptr_t lim, void *kg_arg)
{
	kgrep_data_t *kg = kg_arg;
	size_t pagesize = kg->kg_pagesize;
	uintptr_t pattern = kg->kg_pattern;
	uintptr_t *page = kg->kg_page;
	uintptr_t *page_end = &page[pagesize / sizeof (uintptr_t)];
	uintptr_t *pos;

	uintptr_t addr, offset;
	int seen = 0;

	/*
	 * page-align everything, to simplify the loop
	 */
	base = P2ALIGN(base, pagesize);
	lim = P2ROUNDUP(lim, pagesize);

	for (addr = base; addr < lim; addr += pagesize) {
		if (mdb_vread(page, pagesize, addr) == -1)
			continue;
		seen = 1;

		for (pos = page; pos < page_end; pos++) {
			if (*pos != pattern)
				continue;

			offset = (caddr_t)pos - (caddr_t)page;
			kgrep_cb(addr + offset, NULL, kg->kg_cbtype);
		}
	}
	if (seen)
		kg->kg_seen = 1;

	return (WALK_NEXT);
}

/*
 * Full-service template -- instantiated for each supported size.  We support
 * the following options:
 *
 *	addr in [minaddr, maxaddr), and
 *		value in [pattern, pattern + dist) OR
 *		mask matching: (value & mask) == (pattern & mask)
 */
#define	KGREP_FANCY_TEMPLATE(kgrep_range_fancybits, uintbits_t)		\
static int								\
kgrep_range_fancybits(uintptr_t base, uintptr_t lim, void *kg_arg)	\
{									\
	kgrep_data_t *kg = kg_arg;					\
									\
	uintbits_t pattern = kg->kg_pattern;				\
	uintbits_t dist = kg->kg_dist;					\
	uintbits_t mask = kg->kg_mask;					\
	uintptr_t minaddr = kg->kg_minaddr;				\
	uintptr_t maxaddr = kg->kg_maxaddr;				\
	size_t pagesize = kg->kg_pagesize;				\
	uintbits_t *page = (uintbits_t *)kg->kg_page;			\
	uintbits_t *page_end;						\
	uintbits_t *pos;						\
	uintbits_t cur;							\
	uintmax_t out;							\
									\
	uintptr_t addr, size, offset;					\
	int seen = 0;							\
									\
	base = P2ROUNDUP(MAX(base, minaddr), sizeof (uintbits_t));	\
									\
	if (maxaddr != 0 && lim > maxaddr)				\
		lim = maxaddr;						\
									\
	for (addr = base; addr < lim; addr += size) {			\
		/* P2END(...) computes the next page boundry */		\
		size = MIN(lim, P2END(addr, pagesize)) - addr;		\
									\
		if (mdb_vread(page, size, addr) == -1)			\
			continue;					\
									\
		seen = 1;						\
									\
		page_end = &page[size / sizeof (uintbits_t)];		\
		for (pos = page; pos < page_end; pos++) {		\
			cur = *pos;					\
									\
			if (((cur ^ pattern) & mask) != 0 &&		\
			    (cur - pattern) >= dist)			\
				continue;				\
									\
			out = cur;					\
			offset = (caddr_t)pos - (caddr_t)page;		\
			kgrep_cb(addr + offset, &out, kg->kg_cbtype);	\
		}							\
	}								\
	if (seen)							\
		kg->kg_seen = 1;					\
									\
	return (WALK_NEXT);						\
}

KGREP_FANCY_TEMPLATE(kgrep_range_fancy8, uint8_t)
KGREP_FANCY_TEMPLATE(kgrep_range_fancy16, uint16_t)
KGREP_FANCY_TEMPLATE(kgrep_range_fancy32, uint32_t)
KGREP_FANCY_TEMPLATE(kgrep_range_fancy64, uint64_t)

#undef KGREP_FANCY_TEMPLATE

void
kgrep_help(void)
{
	mdb_printf(
"\n"
"Search the entire virtual address space for a particular pattern,\n"
"%<u>addr%</u>.  By default, a pointer-sized search for an exact match is\n"
"done.\n\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf(
"  -v    Report the value matched at each address\n"
"  -a minaddr\n"
"        Restrict the search to addresses >= minaddr\n"
"  -A maxaddr\n"
"        Restrict the search to addresses < maxaddr\n"
"  -d dist\n"
"        Search for values in [addr, addr + dist)\n"
"  -m mask\n"
"        Search for values where (value & mask) == addr\n"
"  -M invmask\n"
"        Search for values where (value & ~invmask) == addr\n"
"  -s size\n"
"        Instead of pointer-sized values, search for size-byte values.\n"
"        size must be 1, 2, 4, or 8.\n");
}

/*ARGSUSED*/
int
kgrep(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintmax_t pattern = mdb_get_dot();
	uintmax_t mask = KGREP_FULL_MASK;
	uintmax_t invmask = 0;
	uintmax_t dist = 0;
	uintptr_t size = sizeof (uintptr_t);
	uintptr_t minaddr = 0;
	uintptr_t maxaddr = 0;
	size_t pagesize = kgrep_subr_pagesize();
	int verbose = 0;
	int ret;
	int args = 0;

	kgrep_cb_func *func;
	kgrep_data_t kg;

	uintmax_t size_mask;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_UINTPTR, &minaddr,
	    'A', MDB_OPT_UINTPTR, &maxaddr,
	    'd', MDB_OPT_UINT64, &dist,
	    'm', MDB_OPT_UINT64, &mask,
	    'M', MDB_OPT_UINT64, &invmask,
	    's', MDB_OPT_UINTPTR, &size,
	    'v', MDB_OPT_SETBITS, B_TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (invmask != 0)
		args++;
	if (mask != KGREP_FULL_MASK)
		args++;
	if (dist != 0)
		args++;

	if (args > 1) {
		mdb_warn("only one of -d, -m and -M may be specified\n");
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (invmask != 0)
		mask = ~invmask;

	if (pattern & ~mask)
		mdb_warn("warning: pattern does not match mask\n");

	if (size > sizeof (uintmax_t)) {
		mdb_warn("sizes greater than %d not supported\n",
		    sizeof (uintmax_t));
		return (DCMD_ERR);
	}

	if (size == 0 || (size & (size - 1)) != 0) {
		mdb_warn("size must be a power of 2\n");
		return (DCMD_ERR);
	}

	if (size == sizeof (uintmax_t))
		size_mask = KGREP_FULL_MASK;
	else
		size_mask = (1ULL << (size * NBBY)) - 1ULL;

	if (pattern & ~size_mask)
		mdb_warn("warning: pattern %llx overflows requested size "
		    "%d (max: %llx)\n",
		    pattern, size, size_mask);

	if (dist > 0 &&
	    ((dist & ~size_mask) || size_mask + 1 - dist < pattern)) {
		mdb_warn("pattern %llx + distance %llx overflows size\n"
		    "%d (max: %llx)\n", pattern, dist, size, size_mask);
		return (DCMD_ERR);
	}

	/*
	 * All arguments have now been validated.
	 */

	(void) memset(&kg, '\0', sizeof (kg));
	kg.kg_page = mdb_alloc(pagesize, UM_SLEEP | UM_GC);
	kg.kg_pagesize = pagesize;
	kg.kg_pattern = pattern;
	kg.kg_mask = mask;
	kg.kg_dist = dist;
	kg.kg_minaddr = minaddr;
	kg.kg_maxaddr = maxaddr;

	if (flags & DCMD_PIPE_OUT) {
		verbose = 0;
		kg.kg_cbtype = KG_PIPE;
	} else if (verbose) {
		kg.kg_cbtype = KG_VERBOSE;
	} else {
		kg.kg_cbtype = KG_BASE;
	}

	/*
	 * kgrep_range_basic handles the common case (no arguments)
	 * with dispatch.
	 */
	if (size == sizeof (uintptr_t) && !verbose && mask == KGREP_FULL_MASK &&
	    dist == 0 && minaddr == 0 && maxaddr == 0)
		func = kgrep_range_basic;
	else {
		switch (size) {
		case 1:
			func = kgrep_range_fancy8;
			break;
		case 2:
			func = kgrep_range_fancy16;
			break;
		case 4:
			func = kgrep_range_fancy32;
			break;
		case 8:
			func = kgrep_range_fancy64;
			break;
		default:
			mdb_warn("can't happen: non-recognized kgrep size\n");
			return (DCMD_ERR);
		}
	}

	/*
	 * Invoke the target, which should invoke func(start, end, &kg) for
	 * every range [start, end) of vaddrs which might have backing.
	 * Both start and end must be multiples of kgrep_subr_pagesize().
	 */
	ret = kgrep_subr(func, &kg);

	if (ret == DCMD_OK && !kg.kg_seen)
		mdb_warn("warning: nothing searched\n");

	return (ret);
}
