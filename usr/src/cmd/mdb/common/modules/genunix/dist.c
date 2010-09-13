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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#ifndef	_KMDB
#include <math.h>
#endif

#include "dist.h"

/*
 * Divides the given range (inclusive at both endpoints) evenly into the given
 * number of buckets, adding one bucket at the end that is one past the end of
 * the range. The returned buckets will be automatically freed when the dcmd
 * completes or is forcibly aborted.
 */
const int *
dist_linear(int buckets, int beg, int end)
{
	int *out = mdb_alloc((buckets + 1) * sizeof (*out), UM_SLEEP | UM_GC);
	int pos;
	int dist = end - beg + 1;

	for (pos = 0; pos < buckets; pos++)
		out[pos] = beg + (pos * dist)/buckets;
	out[buckets] = end + 1;

	return (out);
}

/*
 * We want the bins to be a constant ratio:
 *
 *	b_0	  = beg;
 *	b_idx	  = b_{idx-1} * r;
 *	b_buckets = end + 1;
 *
 * That is:
 *
 *	       buckets
 *	beg * r        = end
 *
 * Which reduces to:
 *
 *		  buckets ___________________
 *	      r = -------/ ((end + 1) / beg)
 *
 *		  log ((end + 1) / beg)
 *	  log r = ---------------------
 *		         buckets
 *
 *		   (log ((end + 1) / beg)) / buckets
 *	      r = e
 */
/* ARGSUSED */
const int *
dist_geometric(int buckets, int beg, int end, int minbucketsize)
{
#ifdef	_KMDB
	return (dist_linear(buckets, beg, end));
#else
	int *out = mdb_alloc((buckets + 1) * sizeof (*out), UM_SLEEP | UM_GC);

	double r;
	double b;
	int idx = 0;
	int last;
	int begzero;

	if (minbucketsize == 0)
		minbucketsize = 1;

	if (buckets == 1) {
		out[0] = beg;
		out[1] = end + 1;
		return (out);
	}

	begzero = (beg == 0);
	if (begzero)
		beg = 1;

	r = exp(log((double)(end + 1) / beg) / buckets);

	/*
	 * We've now computed r, using the previously derived formula.  We
	 * now need to generate the array of bucket bounds.  There are
	 * two major variables:
	 *
	 *	b	holds b_idx, the current index, as a double.
	 *	last	holds the integer which goes into out[idx]
	 *
	 * Our job is to transform the smooth function b_idx, defined
	 * above, into integer-sized buckets, with a specified minimum
	 * bucket size.  Since b_idx is an exponentially growing function,
	 * any inadequate buckets must be at the beginning.  To deal
	 * with this, we make buckets of minimum size until b catches up
	 * with last.
	 *
	 * A final wrinkle is that beg *can* be zero.  We compute r and b
	 * as if beg was 1, then start last as 0.  This can lead to a bit
	 * of oddness around the 0 bucket, but it's mostly reasonable.
	 */

	b = last = beg;
	if (begzero)
		last = 0;

	for (idx = 0; idx < buckets; idx++) {
		int next;

		out[idx] = last;

		b *= r;
		next = (int)b;

		if (next > last + minbucketsize - 1)
			last = next;
		else
			last += minbucketsize;
	}
	out[buckets] = end + 1;

	return (out);
#endif
}

#define	NCHARS	50
/*
 * Print the distribution header with the given bucket label. The header is
 * printed on a single line, and the label is assumed to fit within the given
 * width (number of characters). The default label width when unspecified (0)
 * is eleven characters. Optionally, a label other than "count" may be specified
 * for the bucket counts.
 */
void
dist_print_header(const char *label, int width, const char *count)
{
	int n;
	const char *dist = " Distribution ";
	char dashes[NCHARS + 1];

	if (width == 0)
		width = 11;

	if (count == NULL)
		count = "count";

	n = (NCHARS - strlen(dist)) / 2;
	(void) memset(dashes, '-', n);
	dashes[n] = '\0';

	mdb_printf("%*s  %s%s%s %s\n", width, label, dashes, dist, dashes,
	    count);
}

/*
 * Print one distribution bucket whose range is from distarray[i] inclusive to
 * distarray[i + 1] exclusive by totalling counts in that index range.  The
 * given total is assumed to be the sum of all elements in the counts array.
 * Each bucket is labeled by its range in the form "first-last" (omit "-last" if
 * the range is a single value) where first and last are integers, and last is
 * one less than the first value of the next bucket range. The bucket label is
 * assumed to fit within the given width (number of characters), which should
 * match the width value passed to dist_print_header(). The default width when
 * unspecified (0) is eleven characters.
 */
void
dist_print_bucket(const int *distarray, int i, const uint_t *counts,
    uint64_t total, int width)
{
	int b;				/* bucket range index */
	int bb = distarray[i];		/* bucket begin */
	int be = distarray[i + 1] - 1;	/* bucket end */
	uint64_t count = 0;		/* bucket value */

	int nats;
	char ats[NCHARS + 1], spaces[NCHARS + 1];
	char range[40];

	if (width == 0)
		width = 11;

	if (total == 0)
		total = 1;		/* avoid divide-by-zero */

	for (b = bb; b <= be; b++)
		count += counts[b];

	nats = (NCHARS * count) / total;
	(void) memset(ats, '@', nats);
	ats[nats] = 0;
	(void) memset(spaces, ' ', NCHARS - nats);
	spaces[NCHARS - nats] = 0;

	if (bb == be)
		(void) mdb_snprintf(range, sizeof (range), "%d", bb);
	else
		(void) mdb_snprintf(range, sizeof (range), "%d-%d", bb, be);
	mdb_printf("%*s |%s%s %lld\n", width, range, ats, spaces, count);
}
#undef NCHARS
