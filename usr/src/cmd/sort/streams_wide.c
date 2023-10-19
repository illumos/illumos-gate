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

#include "streams_wide.h"
#include "streams_common.h"

#define	WIDE_VBUF_SIZE	(64 * KILOBYTE)

#define	SHELF_OCCUPIED	1
#define	SHELF_VACANT	0
static int shelf = SHELF_VACANT;

/*
 * Wide character streams implementation
 *
 *   The wide character streams implementation is, for the most part, a
 *   reimplementation of the stdio streams implementation, using wide character
 *   string routines.  However, fgetws(3C) retains the newline that fgets(3C)
 *   discards while reading a complete line.  As a result, the wide character
 *   routines need to guard against coincidental exhaustion of the buffer, as
 *   well as overwriting the end-of-line character and correcting the
 *   l_data_length field.
 */

static int
stream_wide_prime(stream_t *str)
{
	stream_buffered_file_t *BF = &(str->s_type.BF);
	wchar_t *current_position;
	wchar_t *end_of_buffer;
	wchar_t *next_nl;

	ASSERT(!(str->s_status & STREAM_OUTPUT));
	ASSERT(str->s_status & STREAM_OPEN);

	if (str->s_status & STREAM_INSTANT && (str->s_buffer == NULL)) {
		str->s_buffer = xzmap(0, WIDE_VBUF_SIZE, PROT_READ |
		    PROT_WRITE, MAP_PRIVATE, 0);
		if (str->s_buffer == MAP_FAILED)
			die(EMSG_MMAP);
		str->s_buffer_size = WIDE_VBUF_SIZE;
	}

	ASSERT(str->s_buffer != NULL);

	if (stream_is_primed(str)) {
		int shelf_state = shelf;

		ASSERT(str->s_current.l_data_length >= -1);
		(void) memcpy(str->s_buffer, str->s_current.l_data.wp,
		    (str->s_current.l_data_length + 1) * sizeof (wchar_t));
		str->s_current.l_data.wp = str->s_buffer;

		if ((str->s_current.l_data_length == -1 ||
		    shelf_state == SHELF_OCCUPIED ||
		    *(str->s_current.l_data.wp +
		    str->s_current.l_data_length) != L'\0') &&
		    SOP_FETCH(str) == NEXT_LINE_INCOMPLETE &&
		    shelf_state == SHELF_OCCUPIED)
			die(EMSG_MEMORY);

		return (PRIME_SUCCEEDED);
	}

	stream_set(str, STREAM_PRIMED);

	current_position = (wchar_t *)str->s_buffer;
	/*LINTED ALIGNMENT*/
	end_of_buffer = (wchar_t *)((char *)str->s_buffer +
	    str->s_buffer_size);

	trip_eof(BF->s_fp);
	if (!feof(BF->s_fp))
		(void) fgetws(current_position, end_of_buffer
		    - current_position, BF->s_fp);
	else {
		stream_set(str, STREAM_EOS_REACHED);
		stream_unset(str, STREAM_PRIMED);
		return (PRIME_FAILED_EMPTY_FILE);
	}

	str->s_current.l_data.wp = current_position;
	next_nl = xmemwchar(current_position, L'\n', end_of_buffer -
	    current_position);
	if (next_nl == NULL) {
		warn(WMSG_NEWLINE_ADDED, str->s_filename);
		str->s_current.l_data_length = MIN(wslen(current_position),
		    end_of_buffer - current_position);
	} else {
		str->s_current.l_data_length = next_nl - current_position;
	}
	*(str->s_current.l_data.wp + str->s_current.l_data_length) = L'\0';

	str->s_current.l_collate.wp = NULL;
	str->s_current.l_collate_length = 0;

	__S(stats_incr_fetches());
	return (PRIME_SUCCEEDED);
}

static ssize_t
stream_wide_fetch(stream_t *str)
{
	ssize_t dist_to_buf_end;
	int ret_val;
	wchar_t *graft_pt;
	wchar_t *next_nl;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT((str->s_status & STREAM_EOS_REACHED) == 0);

	graft_pt = str->s_current.l_data.wp + str->s_current.l_data_length + 1;

	if (shelf == SHELF_VACANT)
		str->s_current.l_data.wp = graft_pt;
	else if (str->s_current.l_data_length > -1)
		graft_pt--;

	dist_to_buf_end = str->s_buffer_size / sizeof (wchar_t) - (graft_pt -
	    (wchar_t *)str->s_buffer);

	if (dist_to_buf_end <= 1) {
		str->s_current.l_data_length = -1;
		return (NEXT_LINE_INCOMPLETE);
	}

	if (fgetws(graft_pt, dist_to_buf_end, str->s_type.BF.s_fp) == NULL) {
		if (feof(str->s_type.BF.s_fp))
			stream_set(str, STREAM_EOS_REACHED);
		else
			die(EMSG_READ, str->s_filename);
	}

	trip_eof(str->s_type.BF.s_fp);
	if ((next_nl = xmemwchar(str->s_current.l_data.wp, L'\n',
	    dist_to_buf_end)) == NULL) {
		str->s_current.l_data_length =
		    MIN(wslen(str->s_current.l_data.wp), dist_to_buf_end);
	} else {
		str->s_current.l_data_length = next_nl -
		    str->s_current.l_data.wp;
	}

	str->s_current.l_collate_length = 0;

	if (*(str->s_current.l_data.wp + str->s_current.l_data_length) !=
	    L'\n') {
		if (!feof(str->s_type.BF.s_fp)) {
			if (shelf == SHELF_OCCUPIED)
				die(EMSG_MEMORY);

			shelf = SHELF_OCCUPIED;
			ret_val = NEXT_LINE_INCOMPLETE;
			__S(stats_incr_shelves());
		} else {
			stream_set(str, STREAM_EOS_REACHED);
			warn(WMSG_NEWLINE_ADDED, str->s_filename);
		}
	} else {
		shelf = SHELF_VACANT;
		ret_val = NEXT_LINE_COMPLETE;
		*(str->s_current.l_data.wp + str->s_current.l_data_length) =
		    L'\0';
		__S(stats_incr_fetches());
	}

	return (ret_val);
}

ssize_t
stream_wide_fetch_overwrite(stream_t *str)
{
	ssize_t dist_to_buf_end;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT((str->s_status & STREAM_EOS_REACHED) == 0);

	str->s_current.l_data.wp = str->s_buffer;
	dist_to_buf_end = str->s_buffer_size / sizeof (wchar_t);

	if (fgetws(str->s_current.l_data.wp, dist_to_buf_end,
	    str->s_type.BF.s_fp) == NULL) {
		if (feof(str->s_type.BF.s_fp))
			stream_set(str, STREAM_EOS_REACHED);
		else
			die(EMSG_READ, str->s_filename);
	}

	trip_eof(str->s_type.BF.s_fp);
	str->s_current.l_data_length = wslen(str->s_current.l_data.wp) - 1;
	str->s_current.l_collate_length = 0;

	if (str->s_current.l_data_length == -1 ||
	    *(str->s_current.l_data.wp + str->s_current.l_data_length) !=
	    L'\n') {
		if (!feof(str->s_type.BF.s_fp)) {
			die(EMSG_MEMORY);
		} else {
			stream_set(str, STREAM_EOS_REACHED);
			warn(WMSG_NEWLINE_ADDED, str->s_filename);
			str->s_current.l_data_length++;
		}
	}

	*(str->s_current.l_data.wp + str->s_current.l_data_length) = L'\0';

	__S(stats_incr_fetches());
	return (NEXT_LINE_COMPLETE);
}

static void
stream_wide_send_eol(stream_t *str)
{
	wchar_t w_crlf[2] = { L'\n', L'\0' };

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (wxwrite(str->s_type.SF.s_fd, w_crlf) < 0)
		die(EMSG_WRITE, str->s_filename);
}

static void
stream_wide_put_line(stream_t *str, line_rec_t *line)
{
	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (line->l_data_length >= 0) {
		if (wxwrite(str->s_type.SF.s_fd, line->l_data.wp) >= 0) {
			stream_wide_send_eol(str);
			__S(stats_incr_puts());
		} else
			die(EMSG_WRITE, str->s_filename);
	}
	safe_free(line->l_raw_collate.wp);
	line->l_raw_collate.wp = NULL;
}

void
stream_wide_put_line_unique(stream_t *str, line_rec_t *line)
{
	static line_rec_t pvs;
	static size_t collate_buf_len;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if ((pvs.l_collate.sp == NULL ||
	    collated_wide(&pvs, line, 0, COLL_UNIQUE) != 0) &&
	    line->l_data_length >= 0) {
		stream_wide_put_line(str, line);

		if (line->l_collate_length + sizeof (wchar_t) >
		    collate_buf_len) {
			pvs.l_collate.sp = safe_realloc(pvs.l_collate.sp,
			    line->l_collate_length + sizeof (wchar_t));
			collate_buf_len = line->l_collate_length +
			    sizeof (wchar_t);
		}

		(void) memcpy(pvs.l_collate.sp, line->l_collate.sp,
		    line->l_collate_length);
		/* LINTED ALIGNMENT */
		*(wchar_t *)(pvs.l_collate.sp + line->l_collate_length) = L'\0';
		pvs.l_collate_length = line->l_collate_length;
	}
}

static int
stream_wide_eos(stream_t *str)
{
	int retval = 0;

	if (str == NULL || str->s_status & STREAM_EOS_REACHED)
		return (1);

	trip_eof(str->s_type.BF.s_fp);
	if (feof(str->s_type.BF.s_fp) &&
	    shelf == SHELF_VACANT &&
	    str->s_current.l_collate_length != -1) {
		retval = 1;
		stream_set(str, STREAM_EOS_REACHED);
	}

	return (retval);
}

/*ARGSUSED*/
static void
stream_wide_release_line(stream_t *str)
{
}

const stream_ops_t stream_wide_ops = {
	stream_stdio_is_closable,
	stream_stdio_close,
	stream_wide_eos,
	stream_wide_fetch,
	stream_stdio_flush,
	stream_stdio_free,
	stream_stdio_open_for_write,
	stream_wide_prime,
	stream_wide_put_line,
	stream_wide_release_line,
	stream_wide_send_eol,
	stream_stdio_unlink
};
