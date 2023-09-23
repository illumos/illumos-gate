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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "merge.h"

/*
 * External merge sort
 *
 *   The following code implements the merge phase of sort(1) using a heap-based
 *   priority queue.  Fast paths for merging two files as well as outputting a
 *   single file are provided.
 *
 * Memory footprint management
 *
 *   The N-way fan-out of the merge phase can lead to compromising memory
 *   consumption if not constrained, so two mechanisms are used to regulate
 *   the memory footprint during the merge phase:
 *
 *   1.  Single use memory advice.  Since we proceed through each merge file in
 *       order, any line we have output is never required again--at least, not
 *       from that input file.  Accordingly, we use the SOP_RELEASE_LINE()
 *       operation to advise that the memory backing the raw data for the stream
 *       up to that line is no longer of interest.  (For certain classes of
 *       streams, this leads to an madvise(3C) call with the MADV_DONTNEED
 *       flag.)
 *
 *   2.  Number of merge files.  The number of merge files is constrained based
 *       on the amount of physical memory specified via the -S option (or deemed
 *       available based on an inquiry of sysconf(3C) for _SC_AVPHYS_PAGES).
 *       The number of merge files is calculated based on the average resident
 *       size of a stream that supports the SOP_RELEASE_LINE() operation; this
 *       number is conservative for streams that do not support this operation.
 *       A minimum of four subfiles will always be used, resource limits
 *       permitting.
 *
 * Temporary filespace footprint management
 *
 *   Once the merge sort has utilized a temporary file, it may be deleted at
 *   close, as it's not used again and preserving the files until exit may
 *   compromise sort completion when limited temporary space is available.
 */

static int pq_N;
static stream_t	**pq_queue;
static int (*pq_coll_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t);

static ssize_t (*mg_coll_convert)(field_t *, line_rec_t *, flag_t, vchar_t);

static int
prepare_output_stream(stream_t *ostrp, sort_t *S)
{
	stream_clear(ostrp);
	stream_unset(ostrp, STREAM_OPEN);

	stream_set(ostrp,
	    (S->m_single_byte_locale ? STREAM_SINGLE : STREAM_WIDE) |
	    (S->m_unique_lines ? STREAM_UNIQUE : 0));

	if (S->m_output_to_stdout) {
		stream_set(ostrp, STREAM_NOTFILE);
		ostrp->s_filename = (char *)filename_stdout;
	} else
		ostrp->s_filename = S->m_output_filename;

	return (SOP_OPEN_FOR_WRITE(ostrp));
}

static void
merge_one_stream(field_t *fields_chain, stream_t *strp, stream_t *outstrp,
    vchar_t field_separator)
{
	size_t element_size = strp->s_element_size;
	size_t initial_size = INITIAL_COLLATION_SIZE * element_size;

	if (strp->s_status & STREAM_SINGLE || strp->s_status & STREAM_WIDE)
		stream_set(strp, STREAM_INSTANT);

	if (SOP_PRIME(strp) == PRIME_SUCCEEDED) {
		strp->s_current.l_collate_bufsize = initial_size;
		strp->s_current.l_collate.sp = safe_realloc(NULL, initial_size);

		(void) mg_coll_convert(fields_chain, &strp->s_current,
		    FCV_REALLOC, field_separator);
		SOP_PUT_LINE(outstrp, &strp->s_current);
		SOP_RELEASE_LINE(strp);

		while (!SOP_EOS(strp)) {
			SOP_FETCH(strp);
			if (strp->s_current.l_collate_length == 0)
				(void) mg_coll_convert(fields_chain,
				    &strp->s_current, FCV_REALLOC,
				    field_separator);
			SOP_PUT_LINE(outstrp, &strp->s_current);
			SOP_RELEASE_LINE(strp);
		}

		(void) SOP_CLOSE(strp);
		SOP_FLUSH(outstrp);
	}
}

static void
merge_two_streams(field_t *fields_chain, stream_t *str_a, stream_t *str_b,
    stream_t *outstrp, vchar_t field_separator, flag_t coll_flags)
{
	int (*collate_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t);
	size_t element_size = str_a->s_element_size;
	size_t initial_size = INITIAL_COLLATION_SIZE * element_size;

	ASSERT(str_a->s_element_size == str_b->s_element_size);

	if (str_a->s_element_size == sizeof (char))
		collate_fcn = collated;
	else
		collate_fcn = collated_wide;

	if (str_a->s_status & STREAM_SINGLE || str_a->s_status & STREAM_WIDE)
		stream_set(str_a, STREAM_INSTANT);
	if (str_b->s_status & STREAM_SINGLE || str_b->s_status & STREAM_WIDE)
		stream_set(str_b, STREAM_INSTANT);

	if (SOP_PRIME(str_a) != PRIME_SUCCEEDED) {
		if (SOP_PRIME(str_b) != PRIME_SUCCEEDED)
			return;

		merge_one_stream(fields_chain, str_b, outstrp,
		    field_separator);
		return;
	}

	if (SOP_PRIME(str_b) != PRIME_SUCCEEDED) {
		merge_one_stream(fields_chain, str_a, outstrp,
		    field_separator);
		return;
	}

	str_a->s_current.l_collate_bufsize =
	    str_b->s_current.l_collate_bufsize = initial_size;

	str_a->s_current.l_collate.sp = safe_realloc(NULL, initial_size);
	str_b->s_current.l_collate.sp = safe_realloc(NULL, initial_size);

	(void) mg_coll_convert(fields_chain, &str_a->s_current, FCV_REALLOC,
	    field_separator);
	(void) mg_coll_convert(fields_chain, &str_b->s_current, FCV_REALLOC,
	    field_separator);

	for (;;) {
		if (collate_fcn(&str_a->s_current, &str_b->s_current, 0,
		    coll_flags) < 0) {
			SOP_PUT_LINE(outstrp, &str_a->s_current);
			SOP_RELEASE_LINE(str_a);
			if (SOP_EOS(str_a)) {
				(void) SOP_CLOSE(str_a);
				str_a = str_b;
				break;
			}
			SOP_FETCH(str_a);
			if (str_a->s_current.l_collate_length != 0)
				continue;
			(void) mg_coll_convert(fields_chain, &str_a->s_current,
			    FCV_REALLOC, field_separator);
		} else {
			SOP_PUT_LINE(outstrp, &str_b->s_current);
			SOP_RELEASE_LINE(str_b);
			if (SOP_EOS(str_b)) {
				SOP_CLOSE(str_b);
				break;
			}
			SOP_FETCH(str_b);
			if (str_b->s_current.l_collate_length != 0)
				continue;
			(void) mg_coll_convert(fields_chain, &str_b->s_current,
			    FCV_REALLOC, field_separator);
		}
	}

	SOP_PUT_LINE(outstrp, &str_a->s_current);
	SOP_RELEASE_LINE(str_a);

	while (!SOP_EOS(str_a)) {
		SOP_FETCH(str_a);
		if (str_a->s_current.l_collate_length == 0)
			(void) mg_coll_convert(fields_chain, &str_a->s_current,
			    FCV_REALLOC, field_separator);
		SOP_PUT_LINE(outstrp, &str_a->s_current);
		SOP_RELEASE_LINE(str_a);
	}

	(void) SOP_CLOSE(str_a);
	SOP_FLUSH(outstrp);
}

/*
 * priority queue routines
 *   used for merges involving more than two sources
 */
static void
heap_up(stream_t **A, int k, flag_t coll_flags)
{
	while (k > 1 &&
	    pq_coll_fcn(&A[k / 2]->s_current, &A[k]->s_current, 0,
	    coll_flags) > 0) {
		swap((void **)&pq_queue[k], (void **)&pq_queue[k / 2]);
		k /= 2;
	}
}

static void
heap_down(stream_t **A, int k, int N, flag_t coll_flags)
{
	int	j;

	while (2 * k <= N) {
		j = 2 * k;
		if (j < N && pq_coll_fcn(&A[j]->s_current,
		    &A[j + 1]->s_current, 0, coll_flags) > 0)
			j++;
		if (pq_coll_fcn(&A[k]->s_current, &A[j]->s_current, 0,
		    coll_flags) <= 0)
			break;
		swap((void **)&pq_queue[k], (void **)&pq_queue[j]);
		k = j;
	}
}

static int
pqueue_empty()
{
	return (pq_N == 0);
}

static void
pqueue_init(size_t max_size,
    int (*coll_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t))
{
	pq_queue = safe_realloc(NULL, sizeof (stream_t *) * (max_size + 1));
	pq_N = 0;
	pq_coll_fcn = coll_fcn;
}

static void
pqueue_insert(stream_t *source, flag_t coll_flags)
{
	pq_queue[++pq_N] = source;
	heap_up(pq_queue, pq_N, coll_flags);
}

static stream_t *
pqueue_head(flag_t coll_flags)
{
	swap((void **)&pq_queue[1], (void **)&pq_queue[pq_N]);
	heap_down(pq_queue, 1, pq_N - 1, coll_flags);
	return (pq_queue[pq_N--]);
}

static void
merge_n_streams(sort_t *S, stream_t *head_streamp, int n_streams,
    stream_t *out_streamp, flag_t coll_flags)
{
	stream_t *top_streamp;
	stream_t *cur_streamp;
	stream_t *bot_streamp;
	stream_t *loop_out_streamp;
	flag_t is_single_byte = S->m_single_byte_locale;

	int n_opens = 0;
	int threshold_opens;

	threshold_opens = MAX(4,
	    2 * S->m_memory_available / DEFAULT_RELEASE_SIZE);

	pqueue_init(n_streams, is_single_byte ? collated : collated_wide);

	top_streamp = bot_streamp = head_streamp;

	for (;;) {
		hold_file_descriptor();
		while (bot_streamp != NULL) {

			if (n_opens > threshold_opens ||
			    stream_open_for_read(S, bot_streamp) == -1) {
				/*
				 * Available file descriptors would exceed
				 * memory target or have been exhausted; back
				 * off to the last valid, primed stream.
				 */
				bot_streamp = bot_streamp->s_previous;
				break;
			}

			if (bot_streamp->s_status & STREAM_SINGLE ||
			    bot_streamp->s_status & STREAM_WIDE)
				stream_set(bot_streamp, STREAM_INSTANT);

			bot_streamp = bot_streamp->s_next;
			n_opens++;
		}
		release_file_descriptor();

		if (bot_streamp == NULL) {
			if (prepare_output_stream(out_streamp, S) != -1)
				loop_out_streamp = out_streamp;
			else
				die(EMSG_DESCRIPTORS);
		} else {
			loop_out_streamp = stream_push_to_temporary(
			    &head_streamp, NULL, ST_OPEN | ST_NOCACHE |
			    (is_single_byte ? 0 : ST_WIDE));

			if (loop_out_streamp == NULL ||
			    top_streamp == bot_streamp)
				/*
				 * We need three file descriptors to make
				 * progress; if top_streamp == bot_streamp, then
				 * we have only two.
				 */
				die(EMSG_DESCRIPTORS);
		}

		for (cur_streamp = top_streamp; cur_streamp != bot_streamp;
		    cur_streamp = cur_streamp->s_next) {
			/*
			 * Empty stream?
			 */
			if (!(cur_streamp->s_status & STREAM_ARRAY) &&
			    SOP_EOS(cur_streamp)) {
				stream_unlink_temporary(cur_streamp);
				continue;
			}

			/*
			 * Given that stream is not empty, any error in priming
			 * must be fatal.
			 */
			if (SOP_PRIME(cur_streamp) != PRIME_SUCCEEDED)
				die(EMSG_BADPRIME);

			cur_streamp->s_current.l_collate_bufsize =
			    INITIAL_COLLATION_SIZE;
			cur_streamp->s_current.l_collate.sp =
			    safe_realloc(NULL, INITIAL_COLLATION_SIZE);
			(void) mg_coll_convert(S->m_fields_head,
			    &cur_streamp->s_current, FCV_REALLOC,
			    S->m_field_separator);

			pqueue_insert(cur_streamp, coll_flags);
		}

		while (!pqueue_empty()) {
			cur_streamp = pqueue_head(coll_flags);

			SOP_PUT_LINE(loop_out_streamp, &cur_streamp->s_current);
			SOP_RELEASE_LINE(cur_streamp);

			if (!SOP_EOS(cur_streamp)) {
				SOP_FETCH(cur_streamp);
				(void) mg_coll_convert(S->m_fields_head,
				    &cur_streamp->s_current, FCV_REALLOC,
				    S->m_field_separator);
				pqueue_insert(cur_streamp, coll_flags);
			}
		}

		cur_streamp = top_streamp;
		while (cur_streamp != bot_streamp) {
			if (!(cur_streamp->s_status & STREAM_ARRAY))
				safe_free(cur_streamp->s_current.l_collate.sp);
			cur_streamp->s_current.l_collate.sp = NULL;

			(void) SOP_FREE(cur_streamp);
			stream_unlink_temporary(cur_streamp);
			(void) SOP_CLOSE(cur_streamp);

			cur_streamp = cur_streamp->s_next;
		}

		(void) SOP_FLUSH(loop_out_streamp);

		if (bot_streamp == NULL)
			break;

		if (!(loop_out_streamp->s_status & STREAM_NOTFILE)) {
			(void) SOP_CLOSE(loop_out_streamp);
			/*
			 * Get file size so that we may treat intermediate files
			 * with our stream_mmap facilities.
			 */
			stream_stat_chain(loop_out_streamp);
			__S(stats_incr_merge_files());
		}

		n_opens = 0;

		top_streamp = bot_streamp;
		bot_streamp = bot_streamp->s_next;
	}
}

void
merge(sort_t *S)
{
	stream_t *merge_chain;
	stream_t *cur_streamp;
	stream_t out_stream;
	uint_t n_merges;
	flag_t coll_flags;

	if (S->m_merge_only) {
		merge_chain = S->m_input_streams;
		set_cleanup_chain(&S->m_input_streams);
	} else {
		/*
		 * Otherwise we're inheriting the temporary output files from
		 * our internal sort.
		 */
		merge_chain = S->m_temporary_streams;
		stream_stat_chain(merge_chain);
		__S(stats_set_merge_files(stream_count_chain(merge_chain)));
	}

	if (S->m_field_options & FIELD_REVERSE_COMPARISONS)
		coll_flags = COLL_REVERSE;
	else
		coll_flags = 0;
	if (S->m_entire_line)
		coll_flags |= COLL_UNIQUE;

	n_merges = stream_count_chain(merge_chain);

	mg_coll_convert = S->m_coll_convert;
	cur_streamp = merge_chain;

	switch (n_merges) {
		case 0:
			/*
			 * No files for merge.
			 */
			warn(gettext("no files available to merge\n"));
			break;
		case 1:
			/*
			 * Fast path: only one file for merge.
			 */
			(void) stream_open_for_read(S, cur_streamp);
			(void) prepare_output_stream(&out_stream, S);
			merge_one_stream(S->m_fields_head, cur_streamp,
			    &out_stream, S->m_field_separator);
			break;
		case 2:
			/*
			 * Fast path: only two files for merge.
			 */
			(void) stream_open_for_read(S, cur_streamp);
			(void) stream_open_for_read(S, cur_streamp->s_next);
			if (prepare_output_stream(&out_stream, S) == -1)
				die(EMSG_DESCRIPTORS);
			merge_two_streams(S->m_fields_head, cur_streamp,
			    cur_streamp->s_next, &out_stream,
			    S->m_field_separator, coll_flags);
			break;
		default:
			/*
			 * Full merge.
			 */
			merge_n_streams(S, cur_streamp, n_merges, &out_stream,
			    coll_flags);
			break;
	}

	remove_output_guard();
}
