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

#include "check.h"

#ifndef DEBUG
#define	MSG_DISORDER		gettext("sort: disorder: ")
#define	MSG_NONUNIQUE		gettext("sort: non-unique: ")
#else /* DEBUG */
#define	MSG_DISORDER		gettext("sort: disorder (%llu): ")
#define	MSG_NONUNIQUE		gettext("sort: non-unique (%llu): ")
#endif /* DEBUG */

#define	CHECK_FAILURE_DISORDER	0x1
#define	CHECK_FAILURE_NONUNIQUE	0x2
#define	CHECK_WIDE		0x4

static void
fail_check(line_rec_t *L, int flags, u_longlong_t lineno)
{
	char *line;
	ssize_t length;

	if (flags & CHECK_WIDE) {
		if ((length = (ssize_t)wcstombs(NULL, L->l_data.wp, 0)) < 0)
			die(EMSG_ILLEGAL_CHAR);

		/*
		 * +1 for null character
		 */
		line = alloca(length + 1);
		(void) wcstombs(line, L->l_data.wp, L->l_data_length);
		line[length] = '\0';
	} else {
		line = L->l_data.sp;
		length = L->l_data_length;
	}

	if (flags & CHECK_FAILURE_DISORDER) {
		(void) fprintf(stderr, MSG_DISORDER, lineno);
		(void) write(fileno(stderr), line, length);
		(void) fprintf(stderr, "\n");
		return;
	}

	(void) fprintf(stderr, MSG_NONUNIQUE);
	(void) write(fileno(stderr), line, length);
	(void) fprintf(stderr, "\n");
}

static void
swap_coll_bufs(line_rec_t *A, line_rec_t *B)
{
	char *coll_buffer = B->l_collate.sp;
	ssize_t coll_bufsize = B->l_collate_bufsize;

	safe_free(B->l_raw_collate.sp);
	copy_line_rec(A, B);

	A->l_collate.sp = coll_buffer;
	A->l_collate_bufsize = coll_bufsize;
	A->l_raw_collate.sp = NULL;
}

/*
 * check_if_sorted() interacts with a stream in a slightly different way than a
 * simple sort or a merge operation:  the check involves looking at two adjacent
 * lines of the file and verifying that they are collated according to the key
 * specifiers given.  For files accessed via mmap(), this is simply done as the
 * entirety of the file is present in the address space.  For files accessed via
 * stdio, regardless of locale, we must be able to guarantee that two lines are
 * present in memory at once.  The basic buffer code for stdio does not make
 * such a guarantee, so we use stream_swap_buffer() to alternate between two
 * input buffers.
 */
void
check_if_sorted(sort_t *S)
{
	size_t input_mem;
	int numerator, denominator;

	char *data_buffer = NULL;
	size_t data_bufsize = 0;
	line_rec_t last_line;
	u_longlong_t lineno = 0;
	int r;
	int swap_required;
	flag_t coll_flags;
	stream_t *cur_streamp = S->m_input_streams;

	ssize_t (*conversion_fcn)(field_t *, line_rec_t *, flag_t, vchar_t) =
	    field_convert;
	int (*collation_fcn)(line_rec_t *, line_rec_t *, ssize_t, flag_t) =
	    collated;

	set_memory_ratio(S, &numerator, &denominator);

	if (stream_open_for_read(S, cur_streamp) > 1)
		die(EMSG_CHECK);

	if (SOP_EOS(cur_streamp))
		exit(E_SUCCESS);

	(void) memset(&last_line, 0, sizeof (line_rec_t));

	/*
	 * We need to swap data buffers for the stream with each fetch, except
	 * on STREAM_MMAP (which are implicitly STREAM_SUSTAIN).
	 */
	swap_required = !(cur_streamp->s_status & STREAM_MMAP);
	if (swap_required) {
		stream_set(cur_streamp, STREAM_INSTANT);
		/*
		 * We use one half of the available memory for input, half for
		 * each buffer.  (The other half is left unreserved, in case
		 * conversions to collatable form require it.)
		 */
		input_mem = numerator * S->m_memory_available / denominator / 4;

		stream_set_size(cur_streamp, input_mem);
		stream_swap_buffer(cur_streamp, &data_buffer, &data_bufsize);
		stream_set_size(cur_streamp, input_mem);

		if (cur_streamp->s_status & STREAM_WIDE) {
			conversion_fcn = field_convert_wide;
			collation_fcn = collated_wide;
		}
	}

	if (SOP_PRIME(cur_streamp) > 1)
		die(EMSG_CHECK);

	if (S->m_field_options & FIELD_REVERSE_COMPARISONS)
		coll_flags = COLL_REVERSE;
	else
		coll_flags = 0;
	if (S->m_unique_lines)
		coll_flags |= COLL_UNIQUE;

	cur_streamp->s_current.l_collate_bufsize = INITIAL_COLLATION_SIZE
	    * cur_streamp->s_element_size;
	cur_streamp->s_current.l_collate.sp = safe_realloc(NULL,
	    cur_streamp->s_current.l_collate_bufsize);
	cur_streamp->s_current.l_raw_collate.sp = NULL;

	last_line.l_collate_bufsize = INITIAL_COLLATION_SIZE *
	    cur_streamp->s_element_size;
	last_line.l_collate.sp = safe_realloc(NULL,
	    last_line.l_collate_bufsize);
	last_line.l_raw_collate.sp = NULL;

	(void) conversion_fcn(S->m_fields_head, &cur_streamp->s_current,
	    FCV_REALLOC, S->m_field_separator);

	swap_coll_bufs(&cur_streamp->s_current, &last_line);
	if (swap_required)
		stream_swap_buffer(cur_streamp, &data_buffer, &data_bufsize);

	while (!SOP_EOS(cur_streamp)) {
		(void) SOP_FETCH(cur_streamp);
		lineno++;

		(void) conversion_fcn(S->m_fields_head, &cur_streamp->s_current,
		    FCV_REALLOC, S->m_field_separator);

		r = collation_fcn(&last_line, &cur_streamp->s_current, 0,
		    coll_flags);

		if (r < 0 || (r == 0 && S->m_unique_lines == 0)) {
			swap_coll_bufs(&cur_streamp->s_current, &last_line);
			if (swap_required)
				stream_swap_buffer(cur_streamp, &data_buffer,
				    &data_bufsize);
			continue;
		}

		if (r > 0) {
#ifndef	XPG4
			fail_check(&cur_streamp->s_current,
			    CHECK_FAILURE_DISORDER |
			    (S->m_single_byte_locale ? 0 : CHECK_WIDE),
			    lineno);
#endif /* XPG4 */
			exit(E_FAILED_CHECK);
		}

		if (r == 0 && S->m_unique_lines != 0) {
#ifndef	XPG4
			fail_check(&cur_streamp->s_current,
			    CHECK_FAILURE_NONUNIQUE |
			    (S->m_single_byte_locale ? 0 : CHECK_WIDE),
			    lineno);
#endif /* XPG4 */
			exit(E_FAILED_CHECK);
		}
	}

	exit(E_SUCCESS);
	/*NOTREACHED*/
}
