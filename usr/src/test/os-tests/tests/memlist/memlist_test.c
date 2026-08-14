/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Tests for memlist operations.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <upanic.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>

typedef struct {
	uint64_t	ms_addr;
	uint64_t	ms_size;
} ml_span_t;

typedef bool (*ml_test_f)(void);

typedef struct {
	const char	*mt_name;
	ml_test_f	mt_func;
} ml_test_t;

static const char *ml_curtest;

static void
ml_fail(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "FAIL %s: ", ml_curtest);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");
}

/*
 * Render list as "[base 1,limit 1) [base 2,limit 2) ..." for failure messages.
 */
static const char *
ml_display(const struct memlist *ml)
{
	static char buf[1024];
	size_t off = 0;

	if (ml == NULL)
		return ("<empty>");

	buf[0] = '\0';
	for (; ml != NULL && off < sizeof (buf); ml = ml->ml_next) {
		int n = snprintf(buf + off, sizeof (buf) - off,
		    "[0x%" PRIx64 ",0x%" PRIx64 ") ", ml->ml_address,
		    ml->ml_address + ml->ml_size);
		if (n < 0)
			break;
		off += (size_t)n;
	}

	return (buf);
}

/*
 * Every list handed back by the relaxed operations should be sorted, free of
 * overlaps, free of empty entries, coalesced (no two entries meeting exactly),
 * and correctly doubly linked.
 */
static bool
ml_check(const struct memlist *ml)
{
	const struct memlist *prev = NULL;
	uint64_t last_end = 0;
	bool first = true;
	bool ok = true;

	for (; ml != NULL; prev = ml, ml = ml->ml_next) {
		if (ml->ml_prev != prev) {
			ml_fail("ml_prev is wrong at 0x%" PRIx64,
			    ml->ml_address);
			ok = false;
		}
		if (ml->ml_size == 0) {
			ml_fail("empty entry at 0x%" PRIx64, ml->ml_address);
			ok = false;
		}
		if (!first && ml->ml_address < last_end) {
			ml_fail("overlap or bad order at 0x%" PRIx64,
			    ml->ml_address);
			ok = false;
		}
		if (!first && ml->ml_address == last_end) {
			ml_fail("uncoalesced entries meeting at 0x%" PRIx64,
			    ml->ml_address);
			ok = false;
		}
		last_end = ml->ml_address + ml->ml_size;
		first = false;
	}

	return (ok);
}

/*
 * Compare a list against what the test expects, and check its invariants.
 */
static bool
ml_expect(const struct memlist *ml, const ml_span_t *want, uint_t nwant)
{
	const struct memlist *cur = ml;

	for (uint_t i = 0; i < nwant; i++, cur = cur->ml_next) {
		if (cur == NULL) {
			ml_fail("list is too short: want %u spans, got %s",
			    nwant, ml_display(ml));
			return (false);
		}
		if (cur->ml_address != want[i].ms_addr ||
		    cur->ml_size != want[i].ms_size) {
			ml_fail("span %u is [0x%" PRIx64 ",0x%" PRIx64 "), "
			    "want [0x%" PRIx64 ",0x%" PRIx64 ") -- list is %s",
			    i, cur->ml_address, cur->ml_address + cur->ml_size,
			    want[i].ms_addr, want[i].ms_addr + want[i].ms_size,
			    ml_display(ml));
			return (false);
		}
	}

	if (cur != NULL) {
		ml_fail("list is too long: want %u spans, got %s", nwant,
		    ml_display(ml));
		return (false);
	}

	return (ml_check(ml));
}

/*
 * ---------------------------------------------------------------------------
 * Relaxed span addition and deletion, which is what memlist_rsrc_add() and
 * memlist_rsrc_delete() provide.
 * ---------------------------------------------------------------------------
 */

static bool
ml_t_add_coalesce(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x800 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x400, 0x100);
	memlist_rsrc_add(&ml, 0x800, 0x100);

	/*
	 * A span covering all three should collapse them into one.
	 */
	memlist_rsrc_add(&ml, 0x150, 0x700);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_add_adjacent(void)
{
	static const ml_span_t want[] = {
		{ 0x800, 0x2800 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x1000, 0x1000);

	/*
	 * Adding adjacent spans on either side should coalesce.
	 */
	memlist_rsrc_add(&ml, 0x2000, 0x1000);
	memlist_rsrc_add(&ml, 0x800, 0x800);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_add_gap(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x500, 0x100 },
		{ 0x900, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x900, 0x100);

	/*
	 * Adding a disjoint span should show up in sorted order.
	 */
	memlist_rsrc_add(&ml, 0x500, 0x100);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_delete_partial(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x80 },
		{ 0x880, 0x80 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x400, 0x100);
	memlist_rsrc_add(&ml, 0x800, 0x100);

	/*
	 * This removes part of the first span, all of the second, and part of
	 * the third, leaving two spans.
	 */
	memlist_rsrc_delete(&ml, 0x180, 0x700);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_delete_middle(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x40 },
		{ 0x1c0, 0x40 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);

	/*
	 * Partially deleting a span in the middle splits it into two.
	 */
	memlist_rsrc_delete(&ml, 0x140, 0x80);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_delete_absent(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);

	/*
	 * Deleting non-existent spans are a nop with relaxed semantics
	 * and leave the list as-is.
	 */
	memlist_rsrc_delete(&ml, 0x900, 0x100);
	memlist_rsrc_delete(&ml, 0x0, 0x10);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_zero_len_relaxed(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x500, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x500, 0x100);

	/*
	 * Deleting a zero-length span is a nop with relaxed semantics.
	 */
	memlist_rsrc_add(&ml, 0x300, 0);	/* in the gap */
	memlist_rsrc_add(&ml, 0x900, 0);	/* past the end */
	memlist_rsrc_add(&ml, 0x150, 0);	/* inside a span */
	memlist_rsrc_delete(&ml, 0x150, 0);	/* inside a span */
	memlist_rsrc_delete(&ml, 0x300, 0);	/* in the gap */
	memlist_rsrc_delete(&ml, 0x100, 0);	/* at a span's base */

	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

/*
 * ---------------------------------------------------------------------------
 * The non-relaxed span operations, where an overlap is an error rather than
 * simply coalesced.
 * ---------------------------------------------------------------------------
 */

static bool
ml_t_strict_overlap(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x400, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	VERIFY3S(xmemlist_add_span(&memlist_kmem_pool, 0x100, 0x100, &ml, 0),
	    ==, MEML_SPANOP_OK);
	VERIFY3S(xmemlist_add_span(&memlist_kmem_pool, 0x400, 0x100, &ml, 0),
	    ==, MEML_SPANOP_OK);

	ret = xmemlist_add_span(&memlist_kmem_pool, 0x180, 0x100, &ml, 0);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("overlapping strict add returned %d, want %d", ret,
		    MEML_SPANOP_ESPAN);
		ok = false;
	}

	/*
	 * The failed add must leave the list as it was.
	 */
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&memlist_kmem_pool, &ml);
	return (ok);
}

static bool
ml_t_strict_delete_missing(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	VERIFY3S(xmemlist_add_span(&memlist_kmem_pool, 0x100, 0x100, &ml, 0),
	    ==, MEML_SPANOP_OK);

	ret = xmemlist_delete_span(&memlist_kmem_pool, 0x900, 0x10, &ml, 0);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("strict delete of an absent span returned %d, want %d",
		    ret, MEML_SPANOP_ESPAN);
		ok = false;
	}

	/*
	 * Running off the end of a span is an error too.
	 */
	ret = xmemlist_delete_span(&memlist_kmem_pool, 0x180, 0x100, &ml, 0);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("strict delete past a span's end returned %d, want %d",
		    ret, MEML_SPANOP_ESPAN);
		ok = false;
	}

	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&memlist_kmem_pool, &ml);
	return (ok);
}

static bool
ml_t_zero_len_strict(void)
{
	static const ml_span_t want[] = {
		{ 0x10, 0x30 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	VERIFY3S(xmemlist_add_span(&memlist_kmem_pool, 0x10, 0x30, &ml, 0),
	    ==, MEML_SPANOP_OK);

	/*
	 * Deleting a zero-length span at an address which is not the base of an
	 * entry is a nop with strict semantics, and leaves the list as-is.
	 */
	ret = xmemlist_delete_span(&memlist_kmem_pool, 0x30, 0, &ml, 0);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("zero length strict delete returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * Similarly, trying to delete a zero-length span at an address
	 * contained within an existing entry is a nop and importantly doesn't
	 * split the entry into adjacent span.
	 */
	ret = xmemlist_delete_span(&memlist_kmem_pool, 0x20, 0, &ml, 0);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("zero length strict delete inside an entry returned %d,"
		    " want %d", ret, MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * Now let's add a zero-length span.
	 */
	VERIFY3S(xmemlist_add_span(&memlist_kmem_pool, 0x100, 0, &ml, 0),
	    ==, MEML_SPANOP_OK);
	if (memlist_count(ml) != 2) {
		ml_fail("expected an empty entry to be inserted, got %s",
		    ml_display(ml));
		ok = false;
	}

	/*
	 * Deleting the zero-length span we just added should succeed.
	 */
	ret = xmemlist_delete_span(&memlist_kmem_pool, 0x100, 0, &ml, 0);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("deleting an empty entry returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&memlist_kmem_pool, &ml);
	return (ok);
}

/*
 * ---------------------------------------------------------------------------
 * Finding and claiming spans.
 * ---------------------------------------------------------------------------
 */

static bool
ml_t_claim_align(void)
{
	static const ml_span_t want[] = {
		{ 0x1010, 0xff0 },
		{ 0x3000, 0x10 },
	};
	struct memlist *ml = NULL;
	uint64_t addr = 0;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x1010, 0x2000);

	ret = memlist_rsrc_claim(&ml, 0x1000, 0x1000, &addr);
	if (ret != MEML_SPANOP_OK || addr != 0x2000) {
		ml_fail("claim returned %d addr 0x%" PRIx64
		    ", want %d addr 0x2000", ret, addr, MEML_SPANOP_OK);
		ok = false;
	}

	/*
	 * What was claimed is gone with the remaining spans adjusted by
	 * the requested alignment.
	 */
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_claim_fail(void)
{
	static const ml_span_t want[] = {
		{ 0x1000, 0x100 },
	};
	struct memlist *ml = NULL;
	uint64_t addr = 0xdeadbeef;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x1000, 0x100);

	ret = memlist_rsrc_claim(&ml, 0x1000, 0, &addr);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("oversized claim returned %d, want %d", ret,
		    MEML_SPANOP_ESPAN);
		ok = false;
	}
	if (addr != 0xdeadbeef) {
		ml_fail("failed claim wrote 0x%" PRIx64 " to the out param",
		    addr);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * An empty list should always result in a span-not-found error.
	 */
	memlist_rsrc_free(&ml);
	ret = memlist_rsrc_claim(&ml, 0x10, 0, &addr);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("claim from an empty list returned %d, want %d", ret,
		    MEML_SPANOP_ESPAN);
		ok = false;
	}

	return (ok);
}

/*
 * Zero is a perfectly good address, and a successful claim of it has to be
 * distinguishable from a failure to claim anything.
 */
static bool
ml_t_claim_at_zero(void)
{
	static const ml_span_t want[] = {
		{ 0x1000, 0x1000 },
	};
	struct memlist *ml = NULL;
	uint64_t addr = 0xdeadbeef;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x0, 0x2000);

	ret = memlist_rsrc_claim(&ml, 0x1000, 0x1000, &addr);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("claim at address zero returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	if (addr != 0) {
		ml_fail("claim returned 0x%" PRIx64 ", want 0", addr);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

static bool
ml_t_claim_at(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x440, 0xc0 },
	};
	struct memlist *ml = NULL;
	uint64_t addr = 0xdeadbeef;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x400, 0x100);

	/*
	 * The _at variant only matches an entry which begins exactly at the
	 * requested address.
	 */
	ret = memlist_rsrc_claim_at(&ml, 0x420, 0x10, 0, &addr);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("claim_at into the middle returned %d, want %d", ret,
		    MEML_SPANOP_ESPAN);
		ok = false;
	}

	ret = memlist_rsrc_claim_at(&ml, 0x400, 0x40, 0, &addr);
	if (ret != MEML_SPANOP_OK || addr != 0x400) {
		ml_fail("claim_at returned %d addr 0x%" PRIx64
		    ", want %d addr 0x400", ret, addr, MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

/*
 * memlist_find_span() answers the question a claim would answer without
 * actually taking anything, and accepts a NULL out parameter for callers which
 * only want to know whether a span exists.
 */
static bool
ml_t_find_span(void)
{
	static const ml_span_t want[] = {
		{ 0x1010, 0x2000 },
	};
	struct memlist *ml = NULL;
	uint64_t found = 0xdeadbeef, claimed = 0;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x1010, 0x2000);

	ret = memlist_find_span(ml, 0x1000, 0x1000, NULL);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("find_span with a NULL out param returned %d, want %d",
		    ret, MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	ret = memlist_find_span(ml, 0x9999999, 0, &found);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("find_span for an oversized span returned %d, want %d",
		    ret, MEML_SPANOP_ESPAN);
		ok = false;
	}
	if (found != 0xdeadbeef) {
		ml_fail("failed find_span wrote 0x%" PRIx64 " to the out param",
		    found);
		ok = false;
	}

	/*
	 * _find and _claim should always agree for the same inputs.
	 */
	ret = memlist_find_span(ml, 0x1000, 0x1000, &found);
	VERIFY3S(ret, ==, MEML_SPANOP_OK);
	ret = memlist_rsrc_claim(&ml, 0x1000, 0x1000, &claimed);
	VERIFY3S(ret, ==, MEML_SPANOP_OK);
	if (found != claimed) {
		ml_fail("find_span said 0x%" PRIx64 " but claim took 0x%"
		    PRIx64, found, claimed);
		ok = false;
	}

	/*
	 * An empty list will always return ESPAN.
	 */
	memlist_rsrc_free(&ml);
	if (memlist_find_span(ml, 0x10, 0, NULL) != MEML_SPANOP_ESPAN) {
		ml_fail("find_span on an empty list did not report ESPAN");
		ok = false;
	}

	return (ok);
}

/*
 * ---------------------------------------------------------------------------
 * Whole list operations.
 * ---------------------------------------------------------------------------
 */

static bool
ml_t_merge_subsume(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x300, 0x100 },
	};
	struct memlist *src = NULL, *dst = NULL;
	bool ok = true;

	memlist_rsrc_add(&src, 0x100, 0x100);
	memlist_rsrc_add(&src, 0x300, 0x100);

	/*
	 * _merge() copies, leaving the source intact.
	 */
	memlist_rsrc_merge(src, &dst);
	ok &= ml_expect(src, want, ARRAY_SIZE(want));
	ok &= ml_expect(dst, want, ARRAY_SIZE(want));

	/*
	 * subsume() moves, draining the source.
	 */
	memlist_rsrc_free(&dst);
	memlist_rsrc_subsume(&src, &dst);
	if (src != NULL) {
		ml_fail("subsume left the source as %s", ml_display(src));
		ok = false;
	}
	ok &= ml_expect(dst, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&dst);
	return (ok);
}

static bool
ml_t_delete_list(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x80 },
		{ 0x200, 0x100 },
		{ 0x400, 0x100 },
	};
	static const ml_span_t want2[] = {
		{ 0x180, 0x80 },
		{ 0x300, 0x100 },
	};
	struct memlist *ml = NULL, *del = NULL;
	bool ok;

	memlist_rsrc_add(&ml, 0x100, 0x400);
	memlist_rsrc_add(&del, 0x180, 0x80);
	memlist_rsrc_add(&del, 0x300, 0x100);

	memlist_rsrc_delete_list(&ml, del);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * The list being subtracted is left as-is.
	 */
	ok &= ml_expect(del, want2, ARRAY_SIZE(want2));

	memlist_rsrc_free(&ml);
	memlist_rsrc_free(&del);
	return (ok);
}

static bool
ml_t_dup_count(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x300, 0x100 },
		{ 0x500, 0x100 },
	};
	static const ml_span_t want2[] = {
		{ 0x100, 0x100 },
		{ 0x500, 0x100 },
	};
	struct memlist *ml = NULL, *dup;
	bool ok = true;

	if (memlist_count(NULL) != 0) {
		ml_fail("memlist_count(NULL) is not zero");
		ok = false;
	}

	memlist_rsrc_add(&ml, 0x100, 0x100);
	memlist_rsrc_add(&ml, 0x300, 0x100);
	memlist_rsrc_add(&ml, 0x500, 0x100);

	if (memlist_count(ml) != 3) {
		ml_fail("memlist_count is %zu, want 3", memlist_count(ml));
		ok = false;
	}

	dup = memlist_rsrc_dup(ml);
	ok &= ml_expect(dup, want, ARRAY_SIZE(want));

	/*
	 * The copy is its own list: changing it leaves the original alone.
	 */
	memlist_rsrc_delete(&dup, 0x300, 0x100);
	ok &= ml_expect(dup, want2, ARRAY_SIZE(want2));
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	if (memlist_rsrc_dup(NULL) != NULL) {
		ml_fail("duplicating an empty list did not give an empty list");
		ok = false;
	}

	memlist_rsrc_free(&ml);
	memlist_rsrc_free(&dup);
	return (ok);
}

/*
 * Every resource operation treats an empty list as a list which simply has
 * nothing in it, so callers need not guard against one.
 */
static bool
ml_t_empty_list_ops(void)
{
	struct memlist *ml = NULL, *other = NULL;

	memlist_rsrc_delete(&ml, 0x100, 0x100);
	memlist_rsrc_delete_list(&ml, NULL);
	memlist_rsrc_merge(NULL, &ml);
	memlist_rsrc_subsume(&other, &ml);
	memlist_rsrc_free(&ml);

	if (ml != NULL || other != NULL) {
		ml_fail("an operation on empty lists produced %s",
		    ml_display(ml));
		return (false);
	}

	return (true);
}

/*
 * ---------------------------------------------------------------------------
 * Pools.
 * ---------------------------------------------------------------------------
 */

/*
 * A freelist backed pool hands out the entries it has been given and reports
 * MEML_SPANOP_EALLOC once they are gone.  Early boot consumers may respond by
 * stocking the pool with another page and retrying the identical operation, so
 * a partly applied relaxed deletion has to be safe to repeat.
 */
static bool
ml_t_pool_exhaustion(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x40 },
		{ 0x180, 0x80 },
		{ 0x400, 0x100 },
	};
	static struct memlist backing[8];
	memlist_pool_t pool;
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	bzero(&pool, sizeof (pool));
	bzero(backing, sizeof (backing));
	pool.mp_flags = MEMLP_FL_EARLYBOOT;

	/*
	 * We start with two entries, which is enough for two disjoint spans
	 * and no more.
	 */
	xmemlist_free_block(&pool, (caddr_t)backing,
	    2 * sizeof (struct memlist));

	ret = xmemlist_add_span(&pool, 0x100, 0x100, &ml, MEML_FL_RELAXED);
	VERIFY3S(ret, ==, MEML_SPANOP_OK);
	ret = xmemlist_add_span(&pool, 0x400, 0x100, &ml, MEML_FL_RELAXED);
	VERIFY3S(ret, ==, MEML_SPANOP_OK);

	ret = xmemlist_add_span(&pool, 0x800, 0x100, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_EALLOC) {
		ml_fail("add from a drained pool returned %d, want %d", ret,
		    MEML_SPANOP_EALLOC);
		ok = false;
	}

	/*
	 * Splitting a span needs an entry too, and there is none to be had.
	 */
	ret = xmemlist_delete_span(&pool, 0x140, 0x40, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_EALLOC) {
		ml_fail("splitting delete from a drained pool returned %d, "
		    "want %d", ret, MEML_SPANOP_EALLOC);
		ok = false;
	}

	/*
	 * Stock the pool and repeat the very same deletion.
	 */
	xmemlist_free_block(&pool, (caddr_t)&backing[4],
	    2 * sizeof (struct memlist));
	ret = xmemlist_delete_span(&pool, 0x140, 0x40, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("retried delete returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * Relaxed deletion is idempotent: doing it again changes nothing.
	 */
	ret = xmemlist_delete_span(&pool, 0x140, 0x40, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("repeated delete returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&pool, &ml);
	return (ok);
}

/*
 * Entries freed to a pool come back out of it, so a pool which is returned
 * everything it lent can satisfy the same requests again.
 */
static bool
ml_t_pool_recycle(void)
{
	static struct memlist backing[4];
	memlist_pool_t pool;
	struct memlist *ml = NULL;
	bool ok = true;
	uint_t i;

	bzero(&pool, sizeof (pool));
	bzero(backing, sizeof (backing));
	pool.mp_flags = MEMLP_FL_EARLYBOOT;
	xmemlist_free_block(&pool, (caddr_t)backing, sizeof (backing));

	for (i = 0; i < 8; i++) {
		int ret = xmemlist_add_span(&pool, 0x100, 0x100, &ml,
		    MEML_FL_RELAXED);

		if (ret != MEML_SPANOP_OK) {
			ml_fail("round %u: add returned %d, want %d", i, ret,
			    MEML_SPANOP_OK);
			ok = false;
			break;
		}
		xmemlist_free_all(&pool, &ml);
	}

	if (pool.mp_freelist_count != ARRAY_SIZE(backing)) {
		ml_fail("pool holds %u entries, want %u",
		    pool.mp_freelist_count, (uint_t)ARRAY_SIZE(backing));
		ok = false;
	}

	return (ok);
}

/*
 * The same thing, but on a pool which actually takes its lock.
 */
static bool
ml_t_pool_locked(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x400, 0x100 },
	};
	static struct memlist backing[4];
	memlist_pool_t pool;
	struct memlist *ml = NULL;
	bool ok;

	bzero(&pool, sizeof (pool));
	bzero(backing, sizeof (backing));
	xmemlist_free_block(&pool, (caddr_t)backing, sizeof (backing));

	VERIFY3S(xmemlist_add_span(&pool, 0x100, 0x100, &ml, MEML_FL_RELAXED),
	    ==, MEML_SPANOP_OK);
	VERIFY3S(xmemlist_add_span(&pool, 0x400, 0x100, &ml, MEML_FL_RELAXED),
	    ==, MEML_SPANOP_OK);
	ok = ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&pool, &ml);
	return (ok);
}

/*
 * Entries belong to the pool they were taken from, so handing a list to a
 * different pool means copying it rather than relinking it.
 */
static bool
ml_t_pool_dup(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
		{ 0x400, 0x100 },
	};
	static struct memlist backing[4];
	memlist_pool_t pool;
	struct memlist *ml = NULL, *copy;
	bool ok;

	bzero(&pool, sizeof (pool));
	bzero(backing, sizeof (backing));
	pool.mp_flags = MEMLP_FL_EARLYBOOT;
	xmemlist_free_block(&pool, (caddr_t)backing, sizeof (backing));

	VERIFY3S(xmemlist_add_span(&pool, 0x100, 0x100, &ml, MEML_FL_RELAXED),
	    ==, MEML_SPANOP_OK);
	VERIFY3S(xmemlist_add_span(&pool, 0x400, 0x100, &ml, MEML_FL_RELAXED),
	    ==, MEML_SPANOP_OK);

	copy = xmemlist_dup(&memlist_kmem_pool, ml);
	ok = ml_expect(copy, want, ARRAY_SIZE(want));

	/*
	 * Each list goes back to the pool it came from.
	 */
	xmemlist_free_all(&memlist_kmem_pool, &copy);
	xmemlist_free_all(&pool, &ml);

	if (pool.mp_freelist_count != ARRAY_SIZE(backing)) {
		ml_fail("pool holds %u entries after being emptied, want %u",
		    pool.mp_freelist_count, (uint_t)ARRAY_SIZE(backing));
		ok = false;
	}

	return (ok);
}

/*
 * ---------------------------------------------------------------------------
 * Overflow.
 * ---------------------------------------------------------------------------
 */

/*
 * Attempting to add a span which wraps should return an error and leave the
 * list unmodified.
 */
static bool
ml_t_overflow_add(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x100, 0x100);

	ret = xmemlist_add_span(&memlist_kmem_pool, UINT64_MAX - 0xff, 0x200,
	    &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("wrapping relaxed add returned %d, want %d", ret,
		    MEML_SPANOP_EOVERFLOW);
		ok = false;
	}

	ret = xmemlist_add_span(&memlist_kmem_pool, UINT64_MAX, 2, &ml, 0);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("wrapping strict add returned %d, want %d", ret,
		    MEML_SPANOP_EOVERFLOW);
		ok = false;
	}

	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

/*
 * Similarly, attempting to delete a wrapping span should fail gracefully and
 * leave the list unmodified.
 */
static bool
ml_t_overflow_delete(void)
{
	static const ml_span_t want[] = {
		{ 0x100, 0x100 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x100, 0x100);

	ret = xmemlist_delete_span(&memlist_kmem_pool, UINT64_MAX - 0xff,
	    0x200, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("wrapping relaxed delete returned %d, want %d", ret,
		    MEML_SPANOP_EOVERFLOW);
		ok = false;
	}

	ret = xmemlist_delete_span(&memlist_kmem_pool, 1, UINT64_MAX, &ml, 0);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("wrapping strict delete returned %d, want %d", ret,
		    MEML_SPANOP_EOVERFLOW);
		ok = false;
	}

	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

/*
 * A span may extend until UINT64_MAX, but not beyond.
 */
static bool
ml_t_overflow_boundary(void)
{
	static const ml_span_t want[] = {
		{ UINT64_MAX - 0x1000, 0x1000 },
	};
	struct memlist *ml = NULL;
	bool ok = true;
	int ret;

	/*
	 * A span ending exactly at UINT64_MAX (exclusive) is the largest one
	 * that can be described, and has to be accepted.
	 */
	ret = xmemlist_add_span(&memlist_kmem_pool, UINT64_MAX - 0x1000,
	    0x1000, &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("adding maximal span returned %d, want %d", ret,
		    MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * A span ending at UINT64_MAX (inclusive) though is not representable.
	 */
	ret = xmemlist_add_span(&memlist_kmem_pool, UINT64_MAX - 0xfff, 0x1000,
	    &ml, MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("span ending at 2^64 returned %d, want %d", ret,
		    MEML_SPANOP_EOVERFLOW);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	/*
	 * But a zero-length span at UINT64_MAX is allowed.
	 */
	ret = xmemlist_add_span(&memlist_kmem_pool, UINT64_MAX, 0, &ml,
	    MEML_FL_RELAXED);
	if (ret != MEML_SPANOP_OK) {
		ml_fail("zero-length span at the top returned %d, want %d",
		    ret, MEML_SPANOP_OK);
		ok = false;
	}
	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	xmemlist_free_all(&memlist_kmem_pool, &ml);
	return (ok);
}

/*
 * A size so large that adding an entry's alignment padding to it would wrap
 * must not erroneously be satisfied.
 */
static bool
ml_t_overflow_align(void)
{
	static const ml_span_t want[] = {
		{ 0x1010, 0x2000 },
	};
	struct memlist *ml = NULL;
	uint64_t addr = 0xdeadbeef;
	bool ok = true;
	int ret;

	memlist_rsrc_add(&ml, 0x1010, 0x2000);

	/*
	 * A size + alignment combination which would wrap is not satisfiable
	 * and should fail as such.
	 */

	ret = memlist_find_span(ml, UINT64_MAX - 0x10, 0x1000, &addr);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("find_span for a near-maximal size returned %d, want "
		    "%d", ret, MEML_SPANOP_ESPAN);
		ok = false;
	}
	if (addr != 0xdeadbeef) {
		ml_fail("failed find_span wrote 0x%" PRIx64 " to the out param",
		    addr);
		ok = false;
	}

	ret = memlist_rsrc_claim(&ml, UINT64_MAX - 0x10, 0x1000, &addr);
	if (ret != MEML_SPANOP_ESPAN) {
		ml_fail("claim of a near-maximal size returned %d, want %d",
		    ret, MEML_SPANOP_ESPAN);
		ok = false;
	}

	/*
	 * _claim_at though explicitly passes an address which may overflow with
	 * the given size so it returns EOVERFLOW in that case.
	 */
	ret = memlist_rsrc_claim_at(&ml, 0x1010, UINT64_MAX - 0x10, 0x1000,
	    &addr);
	if (ret != MEML_SPANOP_EOVERFLOW) {
		ml_fail("claim_at of a near-maximal size returned %d, want %d",
		    ret, MEML_SPANOP_EOVERFLOW);
		ok = false;
	}

	ok &= ml_expect(ml, want, ARRAY_SIZE(want));

	memlist_rsrc_free(&ml);
	return (ok);
}

/*
 * ---------------------------------------------------------------------------
 */

static const ml_test_t ml_tests[] = {
	{ "add/coalesce",		ml_t_add_coalesce },
	{ "add/adjacent",		ml_t_add_adjacent },
	{ "add/gap",			ml_t_add_gap },
	{ "delete/partial",		ml_t_delete_partial },
	{ "delete/middle",		ml_t_delete_middle },
	{ "delete/absent",		ml_t_delete_absent },
	{ "span/zero-length-relaxed",	ml_t_zero_len_relaxed },
	{ "span/strict-overlap",	ml_t_strict_overlap },
	{ "span/strict-delete-missing",	ml_t_strict_delete_missing },
	{ "span/zero-length-strict",	ml_t_zero_len_strict },
	{ "claim/alignment",		ml_t_claim_align },
	{ "claim/failure",		ml_t_claim_fail },
	{ "claim/address-zero",		ml_t_claim_at_zero },
	{ "claim/at",			ml_t_claim_at },
	{ "claim/find-span",		ml_t_find_span },
	{ "list/merge-subsume",		ml_t_merge_subsume },
	{ "list/delete-list",		ml_t_delete_list },
	{ "list/dup-count",		ml_t_dup_count },
	{ "list/empty-is-not-special",	ml_t_empty_list_ops },
	{ "pool/exhaustion",		ml_t_pool_exhaustion },
	{ "pool/recycle",		ml_t_pool_recycle },
	{ "pool/locked",		ml_t_pool_locked },
	{ "pool/dup-between-pools",	ml_t_pool_dup },
	{ "overflow/add",		ml_t_overflow_add },
	{ "overflow/delete",		ml_t_overflow_delete },
	{ "overflow/boundary",		ml_t_overflow_boundary },
	{ "overflow/alignment",		ml_t_overflow_align },
};

int
main(void)
{
	uint_t nfail = 0;
	char *poe;

	for (uint_t i = 0; i < ARRAY_SIZE(ml_tests); i++) {
		ml_curtest = ml_tests[i].mt_name;

		if (ml_tests[i].mt_func()) {
			(void) printf("TEST PASSED: %s\n", ml_curtest);
		} else {
			(void) printf("TEST FAILED: %s\n", ml_curtest);
			nfail++;
		}
	}

	if ((poe = getenv("PANIC_ON_EXIT")) != NULL && strcmp(poe, "1") == 0) {
		const char *msg = "PANIC_ON_EXIT set; panicking for findleaks";

		upanic(msg, strlen(msg));
	}

	return (nfail == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
