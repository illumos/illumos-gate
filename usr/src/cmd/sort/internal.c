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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "internal.h"

#define	INSERTION_THRESHOLD	12

static void
swap_range(int i, int j, int n, line_rec_t **I)
{
	while (n-- > 0) {
		line_rec_t *t;

		t = I[i];
		I[i++] = I[j];
		I[j++] = t;
	}
}

/*
 * offset_is_algorithm() implements a simple insertion sort on line records that
 * allows comparison from an offset into the l_collate field (since the subfiles
 * should have already been sorted to that depth).
 */
static void
offset_is_algorithm(line_rec_t **X, ssize_t n,
    int (*collate_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t),
    ssize_t depth, flag_t coll_flags)
{
	ssize_t i;

	__S(stats_incr_subfiles());

	/*
	 * Place lowest element in X[0].
	 */
	for (i = 0; i < n; i++) {
		if (collate_fcn(X[0], X[i], depth, coll_flags) > 0) {
			swap((void **)&X[0], (void **)&X[i]);
			ASSERT(collate_fcn(X[0], X[i], depth, coll_flags) <= 0);
		}
	}

	/*
	 * Insertion sort.
	 */
	for (i = 2; i < n; i++) {
		ssize_t j = i;
		line_rec_t *t = X[i];
		while (collate_fcn(t, X[j - 1], depth, coll_flags) < 0) {
			X[j] = X[j - 1];
			j--;
			ASSERT(j > 0);
		}
		X[j] = t;
	}
}

/*
 * tqs_algorithm() is called from rqs_algorithm() when a subpartition is
 * encountered whose line records share indistinguishable l_collate fields.  It
 * implements a semi-iterative ternary quicksort.
 */
static void
tqs_algorithm(line_rec_t **X, ssize_t n,
    int (*collate_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t),
    flag_t coll_flags)
{
	ssize_t	l;			/* boundary of left partition */
	ssize_t	le;			/* boundary of left equal partition */
	ssize_t	r;			/* boundary of right partition */
	ssize_t	re;			/* boundary of right equal partition */

	ssize_t	p, q;			/* scratch for indices, comparisons */

	coll_flags |= COLL_DATA_ONLY;

tqs_start:

	/*
	 * completion criteria
	 */
	if (n <= 1)
		return;

	if (n <= INSERTION_THRESHOLD) {
		offset_is_algorithm(X, n, collate_fcn, 0, coll_flags);
		return;
	}

	/*
	 * selection of partition element
	 */
	le = rand() % n;
	swap((void **)&X[0], (void **)&X[le]);

	le = l = 1;
	r = re = n - 1;

	for (;;) {
		while (l <= r &&
		    (p = collate_fcn(X[l], X[0], 0, coll_flags)) <= 0) {
			if (p == 0)
				swap((void **)&X[le++], (void **)&X[l]);
			l++;
		}

		while (l <= r &&
		    (p = collate_fcn(X[r], X[0], 0, coll_flags)) >= 0) {
			if (p == 0)
				swap((void **)&X[r], (void **)&X[re--]);
			r--;
		}

		if (l > r)
			break;

		swap((void **)&X[l++], (void **)&X[r--]);
	}

	/*
	 * swap equal partitions into middle
	 */
	p = MIN(le, l - le);
	swap_range(0, l - p, p, X);
	p = MIN(re - r, n - re - 1);
	swap_range(l, n - p, p, X);

	/*
	 * Iterate with larger subpartition, recurse into smaller.
	 */
	p = l - le;
	q = re - r;

	if (p > q) {
		tqs_algorithm(&X[n - q], q, collate_fcn, coll_flags);

		n = p;
	} else {
		tqs_algorithm(X, p, collate_fcn, coll_flags);

		X = &X[n - q];
		n = q;
	}

	goto tqs_start;
	/*NOTREACHED*/
}

/*
 * The following semi-iterative radix quicksort is derived from that presented
 * in
 *	J. Bentley and R. Sedgewick, Fast Algorithms for Sorting and Searching
 *	Strings, in Eighth Annual ACM-SIAM Symposium on Discrete Algorithms,
 *	1997 (SODA 1997),
 * and
 *	R. Sedgewick, Algorithms in C, 3rd ed., vol. 1, Addison-Wesley, 1998.
 */

static void
rqs_algorithm(line_rec_t **X, ssize_t n, ssize_t depth,
    int (*collate_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t),
    flag_t coll_flags)
{
	uchar_t v;			/* partition radix value */

	ssize_t	l;			/* boundary of left partition */
	ssize_t	le;			/* boundary of left equal partition */
	ssize_t	r;			/* boundary of right partition */
	ssize_t	re;			/* boundary of right equal partition */

	ssize_t	p;			/* scratch for indices, comparisons */
	line_rec_t *t;			/* scratch for swaps */

rqs_start:

	/*
	 * completion criteria
	 */
	if (n <= 1)
		return;

	if (n <= INSERTION_THRESHOLD) {
		offset_is_algorithm(X, n, collate_fcn, depth, coll_flags);
		return;
	}

	/*
	 * selection of partition element
	 */
	le = rand() % n;
	swap((void **)&X[0], (void **)&X[le]);
	v = X[0]->l_collate.usp[depth];

	le = l = 1;
	r = re = n - 1;

	for (;;) {
		while (l <= r &&
		    (p = *(X[l]->l_collate.usp + depth) - v) <= 0) {
			if (p == 0) {
				t = X[le];
				X[le] = X[l];
				X[l] = t;
				le++;
			}
			(l)++;
		}

		while (l <= r &&
		    (p = *(X[r]->l_collate.usp + depth) - v) >= 0) {
			if (p == 0) {
				t = X[r];
				X[r] = X[re];
				X[re] = t;
				(re)--;
			}
			(r)--;
		}

		if (l > r)
			break;

		t = X[l];
		X[l] = X[r];
		X[r] = t;
		(l)++;
		(r)--;
	}

	/*
	 * swap equal partitions into middle
	 */
	p = MIN(le, l - le);
	swap_range(0, l - p, p, X);
	p = MIN(re - r, n - re - 1);
	swap_range(l, n - p, p, X);

	/*
	 * recurse into subpartitions as necessary
	 */
	p = re - r;
	if (p > 0)
		rqs_algorithm(&X[n - p], p, depth, collate_fcn, coll_flags);

	p = l - le;
	if (p > 0)
		rqs_algorithm(X, p, depth, collate_fcn, coll_flags);

	if (le + n - re - 1 <= 1)
		return;

	/*
	 * - 1 so that we don't count the final null.
	 */
	if (X[p]->l_collate_length - 1 > depth) {
		/*
		 * Equivalent recursion: rqs_algorithm(&X[p], le + n - re - 1,
		 * depth + 1, collate_fcn, coll_only);
		 */
		X = &X[p];
		n = le + n - re - 1;
		depth++;
		goto rqs_start;
	}

	if (!(coll_flags & COLL_UNIQUE)) {
		__S(stats_incr_tqs_calls());
		tqs_algorithm(&X[p], le + n - re - 1, collate_fcn, coll_flags);
	}
}

static void
radix_quicksort(stream_t *C, flag_t coll_flags)
{
	ASSERT((C->s_status & STREAM_SOURCE_MASK) == STREAM_ARRAY);

	if (C->s_element_size == sizeof (char))
		rqs_algorithm(C->s_type.LA.s_array, C->s_type.LA.s_array_size,
		    0, collated, coll_flags);
	else
		rqs_algorithm(C->s_type.LA.s_array, C->s_type.LA.s_array_size,
		    0, collated_wide, coll_flags);
}

void
internal_sort(sort_t *S)
{
	size_t input_mem, sort_mem;
	size_t prev_sort_mem = 0;
	void *prev_sort_buf = NULL;

	int numerator, denominator;
	int memory_left;
	int currently_primed;
	flag_t coll_flags;

	stream_t *sort_stream = NULL;
	stream_t *cur_stream;

	set_memory_ratio(S, &numerator, &denominator);
	set_cleanup_chain(&S->m_temporary_streams);

	if (S->m_field_options & FIELD_REVERSE_COMPARISONS)
		coll_flags = COLL_REVERSE;
	else
		coll_flags = 0;

	/*
	 * For the entire line special case, we can speed comparisons by
	 * recognizing that the collation vector contains all the information
	 * required to order the line against other lines of the file.
	 * COLL_UNIQUE provides such an exit; if we use the standard put-line
	 * operation for the output stream, we achieve the desired fast path.
	 */
	if (S->m_entire_line)
		coll_flags |= COLL_UNIQUE;

	hold_file_descriptor();

	cur_stream = S->m_input_streams;
	while (cur_stream != NULL) {
		if (!(cur_stream->s_status & STREAM_OPEN)) {
			if (stream_open_for_read(S, cur_stream) == -1)
				die(EMSG_DESCRIPTORS);
		}

		if (cur_stream->s_status & STREAM_MMAP) {
			input_mem = 0;
		} else {
			input_mem = (size_t)(((u_longlong_t)numerator *
			    S->m_memory_available) / denominator);
			stream_set_size(cur_stream, input_mem);
		}

		sort_mem = S->m_memory_available - input_mem;

		currently_primed = SOP_PRIME(cur_stream);

		sort_stream = safe_realloc(sort_stream, sizeof (stream_t));
		stream_clear(sort_stream);
		sort_stream->s_buffer = prev_sort_buf;
		sort_stream->s_buffer_size = prev_sort_mem;
		stream_set(sort_stream, STREAM_OPEN | STREAM_ARRAY);
		sort_stream->s_element_size = S->m_single_byte_locale ?
		    sizeof (char) : sizeof (wchar_t);
		stream_set_size(sort_stream, sort_mem);
		prev_sort_buf = sort_stream->s_buffer;
		prev_sort_mem = sort_stream->s_buffer_size;

		for (;;) {
			if (currently_primed == PRIME_SUCCEEDED) {
				memory_left =
				    stream_insert(S, cur_stream, sort_stream);

				if (memory_left != ST_MEM_AVAIL)
					break;
			}

			if (SOP_EOS(cur_stream)) {
				if (cur_stream->s_consumer == NULL) {
					(void) SOP_FREE(cur_stream);
					(void) SOP_CLOSE(cur_stream);
				}

				cur_stream = cur_stream->s_next;

				if (cur_stream == NULL)
					break;

				if (!(cur_stream->s_status & STREAM_OPEN) &&
				    (stream_open_for_read(S, cur_stream) == -1))
					break;

				if (!(cur_stream->s_status & STREAM_MMAP)) {
					input_mem = numerator *
					    S->m_memory_available / denominator;
					stream_set_size(cur_stream,
					    input_mem);
				}
				currently_primed = SOP_PRIME(cur_stream);
			}
		}

		radix_quicksort(sort_stream, coll_flags);

#ifndef DEBUG_NO_CACHE_TEMP
		/*
		 * cur_stream is set to NULL only when memory isn't filled and
		 * no more input streams remain.  In this case, we can safely
		 * cache the sort results.
		 *
		 * Otherwise, we have either exhausted available memory or
		 * available file descriptors.  If we've use all the available
		 * file descriptors, we aren't able to open the next input file.
		 * In this case, we can't cache the sort results, because more
		 * input files remain.
		 *
		 * If memory was filled, then there must be at least one
		 * leftover line unprocessed in the input stream, even though
		 * stream will indicated EOS if asked. We can't cache in this
		 * case, as we need one more round for the pending line or
		 * lines.
		 */
		if (cur_stream == NULL) {
			(void) stream_push_to_temporary(&S->m_temporary_streams,
			    sort_stream, ST_CACHE |
			    (S->m_single_byte_locale ? 0 : ST_WIDE));
			break;
		} else {
#endif
			release_file_descriptor();
			(void) stream_push_to_temporary(&S->m_temporary_streams,
			    sort_stream, ST_NOCACHE |
			    (S->m_single_byte_locale ? 0 : ST_WIDE));

			hold_file_descriptor();
#ifdef DEBUG_NO_CACHE_TEMP
			if (cur_stream == NULL)
				break;
#endif
			stream_unset(cur_stream, STREAM_NOT_FREEABLE);
			stream_close_all_previous(cur_stream);
			cur_stream->s_consumer = NULL;
#ifndef DEBUG_NO_CACHE_TEMP
		}
#endif
	}

	release_file_descriptor();
}
