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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "streams_stdio.h"
#include "streams_common.h"

#define	SHELF_OCCUPIED	1
#define	SHELF_VACANT	0
static int shelf = SHELF_VACANT;

/*
 * Single-byte character file i/o-based streams implementation
 *
 *   The routines in this file contain the implementation of the i/o streams
 *   interface for those situations where the input is via stdio.
 *
 * The "shelf"
 *   In the case where the input buffer contains insufficient room to hold the
 *   entire line, the fractional line is shelved, and will be grafted to on the
 *   subsequent read.
 */
int
stream_stdio_open_for_write(stream_t *str)
{
	stream_simple_file_t	*SF = &(str->s_type.SF);

	ASSERT(!(str->s_status & STREAM_OPEN));
	ASSERT(!(str->s_status & STREAM_OUTPUT));

	if (str->s_status & STREAM_NOTFILE)
		SF->s_fd = fileno(stdout);
	else
		if ((SF->s_fd = open(str->s_filename, O_CREAT | O_TRUNC |
		    O_WRONLY, OUTPUT_MODE)) < 0) {
			if (errno == EMFILE || errno == ENFILE)
				return (-1);
			else
				die(EMSG_OPEN, str->s_filename);
		}

	stream_set(str, STREAM_OPEN | STREAM_OUTPUT);

	return (1);
}

/*
 * In the case of an instantaneous stream, we allocate a small buffer (64k) here
 * for the stream; otherwise, the s_buffer and s_buffer_size members should have
 * been set by stream_set_size() prior to calling stream_prime().
 *
 * Repriming (priming an already primed stream) is done when we are reentering a
 * file after having sorted a previous portion of the file.
 */
static int
stream_stdio_prime(stream_t *str)
{
	stream_buffered_file_t *BF = &(str->s_type.BF);
	char *current_position;
	char *end_of_buffer;
	char *next_nl;

	ASSERT(!(str->s_status & STREAM_OUTPUT));
	ASSERT(str->s_status & (STREAM_SINGLE | STREAM_WIDE));
	ASSERT(str->s_status & STREAM_OPEN);

	if (str->s_status & STREAM_INSTANT && (str->s_buffer == NULL)) {
		str->s_buffer = xzmap(0, STDIO_VBUF_SIZE, PROT_READ |
		    PROT_WRITE, MAP_PRIVATE, 0);
		if (str->s_buffer == MAP_FAILED)
			die(EMSG_MMAP);
		str->s_buffer_size = STDIO_VBUF_SIZE;
	}

	ASSERT(str->s_buffer != NULL);

	if (stream_is_primed(str)) {
		/*
		 * l_data_length is only set to -1 in the case of coincidental
		 * exhaustion of the input butter.  This is thus the only case
		 * which involves no copying on a re-prime.
		 */
		int shelf_state = shelf;

		ASSERT(str->s_current.l_data_length >= -1);
		(void) memcpy(str->s_buffer, str->s_current.l_data.sp,
		    str->s_current.l_data_length + 1);
		str->s_current.l_data.sp = str->s_buffer;

		/*
		 * If our current line is incomplete, we need to get the rest of
		 * the line--if we can't, then we've exhausted memory.
		 */
		if ((str->s_current.l_data_length == -1 ||
		    shelf_state == SHELF_OCCUPIED ||
		    *(str->s_current.l_data.sp +
		    str->s_current.l_data_length) != '\n') &&
		    SOP_FETCH(str) == NEXT_LINE_INCOMPLETE &&
		    shelf_state == SHELF_OCCUPIED)
			die(EMSG_MEMORY);

		str->s_current.l_collate.sp = NULL;
		str->s_current.l_collate_length = 0;

		return (PRIME_SUCCEEDED);
	}

	stream_set(str, STREAM_PRIMED);

	current_position = (char *)str->s_buffer;
	end_of_buffer = (char *)str->s_buffer + str->s_buffer_size;

	trip_eof(BF->s_fp);
	if (!feof(BF->s_fp))
		(void) fgets(current_position, end_of_buffer - current_position,
		    BF->s_fp);
	else {
		stream_set(str, STREAM_EOS_REACHED);
		stream_unset(str, STREAM_PRIMED);
		return (PRIME_FAILED_EMPTY_FILE);
	}

	str->s_current.l_data.sp = current_position;
	/*
	 * Because one might run sort on a binary file, strlen() is no longer
	 * trustworthy--we must explicitly search for a newline.
	 */
	if ((next_nl = memchr(current_position, '\n',
	    end_of_buffer - current_position)) == NULL) {
		warn(WMSG_NEWLINE_ADDED, str->s_filename);
		str->s_current.l_data_length = MIN(strlen(current_position),
		    end_of_buffer - current_position);
	} else {
		str->s_current.l_data_length = next_nl - current_position;
	}

	str->s_current.l_collate.sp = NULL;
	str->s_current.l_collate_length = 0;

	__S(stats_incr_fetches());
	return (PRIME_SUCCEEDED);
}

/*
 * stream_stdio_fetch() guarantees the return of a complete line, or a flag
 * indicating that the complete line could not be read.
 */
static ssize_t
stream_stdio_fetch(stream_t *str)
{
	ssize_t	dist_to_buf_end;
	int ret_val;
	char *graft_pt, *next_nl;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & (STREAM_SINGLE | STREAM_WIDE));
	ASSERT((str->s_status & STREAM_EOS_REACHED) == 0);

	graft_pt = str->s_current.l_data.sp + str->s_current.l_data_length + 1;

	if (shelf == SHELF_VACANT) {
		/*
		 * The graft point is the start of the current line.
		 */
		str->s_current.l_data.sp = graft_pt;
	} else if (str->s_current.l_data_length > -1) {
		/*
		 * Correct for terminating NUL on shelved line.  This NUL is
		 * only present if we didn't have the coincidental case
		 * mentioned in the comment below.
		 */
		graft_pt--;
	}

	dist_to_buf_end = str->s_buffer_size - (graft_pt -
	    (char *)str->s_buffer);

	if (dist_to_buf_end <= 1) {
		/*
		 * fgets()'s behaviour in the case of a one-character buffer is
		 * somewhat unhelpful:  it fills the buffer with '\0' and
		 * returns successfully (even if EOF has been reached for the
		 * file in question).  Since we may be in the middle of a
		 * grafting operation, we leave early, maintaining the shelf in
		 * its current state.
		 */
		str->s_current.l_data_length = -1;
		return (NEXT_LINE_INCOMPLETE);
	}

	if (fgets(graft_pt, dist_to_buf_end, str->s_type.BF.s_fp) == NULL) {
		if (feof(str->s_type.BF.s_fp))
			stream_set(str, STREAM_EOS_REACHED);
		else
			die(EMSG_READ, str->s_filename);
	}

	trip_eof(str->s_type.BF.s_fp);
	/*
	 * Because one might run sort on a binary file, strlen() is no longer
	 * trustworthy--we must explicitly search for a newline.
	 */
	if ((next_nl = memchr(str->s_current.l_data.sp, '\n',
	    dist_to_buf_end)) == NULL) {
		str->s_current.l_data_length = strlen(str->s_current.l_data.sp);
	} else {
		str->s_current.l_data_length = next_nl -
		    str->s_current.l_data.sp;
	}

	str->s_current.l_collate_length = 0;

	if (*(str->s_current.l_data.sp + str->s_current.l_data_length) !=
	    '\n') {
		if (!feof(str->s_type.BF.s_fp)) {
			/*
			 * We were only able to read part of the line; note that
			 * we have something on the shelf for our next fetch.
			 * If the shelf was previously occupied, and we still
			 * can't get the entire line, then we need more
			 * resources.
			 */
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
		__S(stats_incr_fetches());
	}

	return (ret_val);
}

/*
 * stdio_fetch_overwrite() is used when we are performing an operation where we
 * need the buffer contents only over a single period.  (merge and check are
 * operations of this kind.)  In this case, we read the current line at the head
 * of the stream's defined buffer.  If we cannot read the entire line, we have
 * not allocated sufficient memory.
 */
ssize_t
stream_stdio_fetch_overwrite(stream_t *str)
{
	ssize_t	dist_to_buf_end;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & (STREAM_SINGLE | STREAM_WIDE));
	ASSERT((str->s_status & STREAM_EOS_REACHED) == 0);

	str->s_current.l_data.sp = str->s_buffer;
	dist_to_buf_end = str->s_buffer_size;

	if (fgets(str->s_current.l_data.sp, dist_to_buf_end,
	    str->s_type.BF.s_fp) == NULL) {
		if (feof(str->s_type.BF.s_fp))
			stream_set(str, STREAM_EOS_REACHED);
		else
			die(EMSG_READ, str->s_filename);
	}

	trip_eof(str->s_type.BF.s_fp);
	str->s_current.l_data_length = strlen(str->s_current.l_data.sp) - 1;
	str->s_current.l_collate_length = 0;

	if (str->s_current.l_data_length == -1 ||
	    *(str->s_current.l_data.sp + str->s_current.l_data_length) !=
	    '\n') {
		if (!feof(str->s_type.BF.s_fp)) {
			/*
			 * In the overwrite case, failure to read the entire
			 * line means our buffer size was insufficient (as we
			 * are using all of it).  Exit, requesting more
			 * resources.
			 */
			die(EMSG_MEMORY);
		} else {
			stream_set(str, STREAM_EOS_REACHED);
			warn(WMSG_NEWLINE_ADDED, str->s_filename);
		}
	}

	__S(stats_incr_fetches());
	return (NEXT_LINE_COMPLETE);
}

int
stream_stdio_is_closable(stream_t *str)
{
	if (str->s_status & STREAM_OPEN && !(str->s_status & STREAM_NOTFILE))
		return (1);
	return (0);
}

int
stream_stdio_close(stream_t *str)
{
	ASSERT(str->s_status & STREAM_OPEN);

	if (!(str->s_status & STREAM_OUTPUT)) {
		if (!(str->s_status & STREAM_NOTFILE))
			(void) fclose(str->s_type.BF.s_fp);

		if (str->s_type.BF.s_vbuf != NULL) {
			free(str->s_type.BF.s_vbuf);
			str->s_type.BF.s_vbuf = NULL;
		}
	} else {
		if (cxwrite(str->s_type.SF.s_fd, NULL, 0) == 0)
			(void) close(str->s_type.SF.s_fd);
		else
			die(EMSG_WRITE, str->s_filename);
	}

	stream_unset(str, STREAM_OPEN | STREAM_PRIMED | STREAM_OUTPUT);
	return (1);
}

static void
stream_stdio_send_eol(stream_t *str)
{
	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (cxwrite(str->s_type.SF.s_fd, "\n", 1) < 0)
		die(EMSG_WRITE, str->s_filename);
}

void
stream_stdio_flush(stream_t *str)
{
	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (cxwrite(str->s_type.SF.s_fd, NULL, 0) < 0)
		die(EMSG_WRITE, str->s_filename);
}

static void
stream_stdio_put_line(stream_t *str, line_rec_t *line)
{
	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (line->l_data_length >= 0) {
		if (cxwrite(str->s_type.SF.s_fd, line->l_data.sp,
		    line->l_data_length) < 0)
			die(EMSG_WRITE, str->s_filename);

		stream_stdio_send_eol(str);
		__S(stats_incr_puts());
	}
	safe_free(line->l_raw_collate.sp);
	line->l_raw_collate.sp = NULL;
}

void
stream_stdio_put_line_unique(stream_t *str, line_rec_t *line)
{
	static line_rec_t pvs;
	static size_t collate_buf_len;

	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_status & STREAM_OUTPUT);

	if (pvs.l_collate.sp != NULL &&
	    collated(&pvs, line, 0, COLL_UNIQUE) == 0) {
		__S(stats_incr_not_unique());
		return;
	}

	__S(stats_incr_put_unique());
	stream_stdio_put_line(str, line);

	if (line->l_collate_length + 1 > collate_buf_len) {
		pvs.l_collate.sp = safe_realloc(pvs.l_collate.sp,
		    line->l_collate_length + 1);
		collate_buf_len = line->l_collate_length + 1;
	}

	(void) memcpy(pvs.l_collate.sp, line->l_collate.sp,
	    line->l_collate_length);
	*(pvs.l_collate.sp + line->l_collate_length) = '\0';
	pvs.l_collate_length = line->l_collate_length;
}

int
stream_stdio_unlink(stream_t *str)
{
	if (!(str->s_status & STREAM_NOTFILE))
		return (unlink(str->s_filename));

	return (0);
}

int
stream_stdio_free(stream_t *str)
{
	/*
	 * Unmap the memory we allocated for input, if it's valid to do so.
	 */
	if (!(str->s_status & STREAM_OPEN) ||
	    (str->s_consumer != NULL &&
	    str->s_consumer->s_status & STREAM_NOT_FREEABLE))
		return (0);

	if (str->s_buffer != NULL) {
		if (munmap(str->s_buffer, str->s_buffer_size) < 0)
			die(EMSG_MUNMAP, "/dev/zero");
		else {
			str->s_buffer = NULL;
			str->s_buffer_size = 0;
		}
	}

	stream_unset(str, STREAM_PRIMED | STREAM_INSTANT);

	return (1);
}

static int
stream_stdio_eos(stream_t *str)
{
	int retval = 0;

	ASSERT(!(str->s_status & STREAM_OUTPUT));
	ASSERT(str->s_status & (STREAM_SINGLE | STREAM_WIDE));

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
stream_stdio_release_line(stream_t *str)
{
}

const stream_ops_t stream_stdio_ops = {
	stream_stdio_is_closable,
	stream_stdio_close,
	stream_stdio_eos,
	stream_stdio_fetch,
	stream_stdio_flush,
	stream_stdio_free,
	stream_stdio_open_for_write,
	stream_stdio_prime,
	stream_stdio_put_line,
	stream_stdio_release_line,
	stream_stdio_send_eol,
	stream_stdio_unlink
};
