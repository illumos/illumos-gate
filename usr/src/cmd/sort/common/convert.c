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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * convert
 *   given a sort invocation, convert input files, and display sort collation
 *   vectors to stdout.
 */

#include "main.h"

#define	COLLATE_BUFSIZE	4096

static void
convert(sort_t *S)
{
	stream_t *convert_chain = S->m_input_streams;
	stream_t *cur_streamp = convert_chain;
	flag_t coll_flags;
	ssize_t (*coll_convert)(field_t *, line_rec_t *, flag_t, vchar_t);

	coll_convert = S->m_coll_convert;

	if (S->m_field_options & FIELD_REVERSE_COMPARISONS)
		coll_flags = COLL_REVERSE;
	else
		coll_flags = 0;

	if (S->m_entire_line)
		coll_flags |= COLL_UNIQUE;

	while (cur_streamp != NULL) {
		u_longlong_t lineno = 0;

		stream_open_for_read(S, cur_streamp);
		if (cur_streamp->s_status & STREAM_SINGLE ||
		    cur_streamp->s_status & STREAM_WIDE)
			stream_set(cur_streamp, STREAM_INSTANT);

		SOP_PRIME(cur_streamp);

		cur_streamp->s_current.l_collate.sp = safe_realloc(NULL,
		    COLLATE_BUFSIZE);
		cur_streamp->s_current.l_collate_bufsize = COLLATE_BUFSIZE;

		for (;;) {
			(void) coll_convert(S->m_fields_head,
			    &cur_streamp->s_current, FCV_REALLOC,
			    S->m_field_separator);

			(void) fprintf(stdout, "(%llu) ", lineno++);
			if (cur_streamp->s_status & STREAM_WIDE)
				(void) fprintf(stdout, "%.*ws\n\n",
				    cur_streamp->s_current.l_data_length,
				    cur_streamp->s_current.l_data.wp);
			else
				(void) fprintf(stdout, "%.*s\n\n",
				    cur_streamp->s_current.l_data_length,
				    cur_streamp->s_current.l_data.usp);
			xdump(stdout, cur_streamp->s_current.l_collate.usp,
			    cur_streamp->s_current.l_collate_length,
			    cur_streamp->s_status & STREAM_WIDE);
			(void) fprintf(stdout, "\n");

			if (SOP_EOS(cur_streamp))
				break;

			SOP_FETCH(cur_streamp);
		}

		(void) SOP_FREE(cur_streamp);
		(void) SOP_CLOSE(cur_streamp);

		cur_streamp = cur_streamp->s_next;
	}
}

int
main(int argc, char *argv[])
{
	sort_t S;

	initialize_pre(&S);

	if (options(&S, argc, argv))
		return (E_ERROR);

	initialize_post(&S);

	convert(&S);

	return (E_SUCCESS);
}
