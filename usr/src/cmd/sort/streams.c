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

#include "streams.h"

static const stream_ops_t invalid_ops = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

stream_t *
stream_new(int src)
{
	stream_t *str = safe_realloc(NULL, sizeof (stream_t));

	stream_clear(str);
	stream_set(str, src);

	return (str);
}

void
stream_set(stream_t *str, flag_t flags)
{
	if (flags & STREAM_SOURCE_MASK) {
		ASSERT((flags & STREAM_SOURCE_MASK) == STREAM_ARRAY ||
		    (flags & STREAM_SOURCE_MASK) == STREAM_SINGLE ||
		    (flags & STREAM_SOURCE_MASK) == STREAM_MMAP ||
		    (flags & STREAM_SOURCE_MASK) == STREAM_WIDE);

		str->s_status &= ~STREAM_SOURCE_MASK;
		str->s_status |= flags & STREAM_SOURCE_MASK;

		switch (flags & STREAM_SOURCE_MASK) {
			case STREAM_NO_SOURCE:
				str->s_element_size = 0;
				str->s_ops = invalid_ops;
				return;
			case STREAM_ARRAY:
				/*
				 * Array streams inherit element size.
				 */
				str->s_ops = stream_array_ops;
				break;
			case STREAM_MMAP:
				str->s_element_size = sizeof (char);
				str->s_ops = stream_mmap_ops;
				break;
			case STREAM_SINGLE:
				str->s_element_size = sizeof (char);
				str->s_ops = stream_stdio_ops;
				break;
			case STREAM_WIDE:
				str->s_element_size = sizeof (wchar_t);
				str->s_ops = stream_wide_ops;
				break;
			default:
				die(EMSG_UNKN_STREAM, str->s_status);
		}
	}

	str->s_status |= (flags & ~STREAM_SOURCE_MASK);

	if (str->s_status & STREAM_UNIQUE)
		switch (str->s_status & STREAM_SOURCE_MASK) {
			case STREAM_SINGLE :
				str->s_ops.sop_put_line =
				    stream_stdio_put_line_unique;
				break;
			case STREAM_WIDE :
				str->s_ops.sop_put_line =
				    stream_wide_put_line_unique;
				break;
			default :
				break;
		}

	if (str->s_status & STREAM_INSTANT)
		switch (str->s_status & STREAM_SOURCE_MASK) {
			case STREAM_SINGLE :
				str->s_ops.sop_fetch =
				    stream_stdio_fetch_overwrite;
				break;
			case STREAM_WIDE :
				str->s_ops.sop_fetch =
				    stream_wide_fetch_overwrite;
				break;
			default :
				break;
		}
}

void
stream_unset(stream_t *streamp, flag_t flags)
{
	ASSERT(!(flags & STREAM_SOURCE_MASK));

	streamp->s_status &= ~(flags & ~STREAM_SOURCE_MASK);
}

int
stream_is_primed(stream_t *streamp)
{
	return (streamp->s_status & STREAM_PRIMED);
}

void
stream_clear(stream_t *str)
{
	(void) memset(str, 0, sizeof (stream_t));
}

static void
stream_copy(stream_t *dest, stream_t *src)
{
	(void) memcpy(dest, src, sizeof (stream_t));
}

void
stream_stat_chain(stream_t *strp)
{
	struct stat buf;
	stream_t *cur_strp = strp;

	while (cur_strp != NULL) {
		if (cur_strp->s_status & STREAM_NOTFILE ||
		    cur_strp->s_status & STREAM_ARRAY) {
			cur_strp = cur_strp->s_next;
			continue;
		}

		if (stat(cur_strp->s_filename, &buf) < 0)
			die(EMSG_STAT, cur_strp->s_filename);

		cur_strp->s_dev = buf.st_dev;
		cur_strp->s_ino = buf.st_ino;
		cur_strp->s_filesize = buf.st_size;

		cur_strp = cur_strp->s_next;
	}
}

uint_t
stream_count_chain(stream_t *str)
{
	uint_t n = 0;

	while (str != NULL) {
		n++;
		str = str->s_next;
	}

	return (n);
}

int
stream_open_for_read(sort_t *S, stream_t *str)
{
	int fd;

	ASSERT(!(str->s_status & STREAM_OUTPUT));

	/*
	 * STREAM_ARRAY streams are open by definition.
	 */
	if ((str->s_status & STREAM_SOURCE_MASK) == STREAM_ARRAY) {
		stream_set(str, STREAM_ARRAY | STREAM_OPEN);
		return (1);
	}

	/*
	 * Set data type according to locale for input from stdin.
	 */
	if (str->s_status & STREAM_NOTFILE) {
		str->s_type.BF.s_fp = stdin;
		stream_set(str, STREAM_OPEN | (S->m_single_byte_locale ?
		    STREAM_SINGLE : STREAM_WIDE));
		return (1);
	}

	ASSERT(str->s_filename);

#ifndef DEBUG_DISALLOW_MMAP
	if (S->m_single_byte_locale &&
	    str->s_filesize > 0 &&
	    str->s_filesize < SSIZE_MAX) {
		/*
		 * make mmap() attempt; set s_status and return if successful
		 */
		fd = open(str->s_filename, O_RDONLY);
		if (fd < 0) {
			if (errno == EMFILE || errno == ENFILE)
				return (-1);
			else
				die(EMSG_OPEN, str->s_filename);
		}
		str->s_buffer = mmap(0, str->s_filesize, PROT_READ,
		    MAP_SHARED, fd, 0);

		if (str->s_buffer != MAP_FAILED) {
			str->s_buffer_size = str->s_filesize;
			str->s_type.SF.s_fd = fd;

			stream_set(str, STREAM_MMAP | STREAM_OPEN);
			stream_unset(str, STREAM_PRIMED);
			return (1);
		}

		/*
		 * Otherwise the mmap() failed due to address space exhaustion;
		 * since we have already opened the file, we close it and drop
		 * into the normal (STDIO) case.
		 */
		(void) close(fd);
		str->s_buffer = NULL;
	}
#endif /* DEBUG_DISALLOW_MMAP */

	if ((str->s_type.BF.s_fp = fopen(str->s_filename, "r")) == NULL) {
		if (errno == EMFILE || errno == ENFILE)
			return (-1);
		else
			die(EMSG_OPEN, str->s_filename);
	}

	str->s_type.BF.s_vbuf = safe_realloc(NULL, STDIO_VBUF_SIZE);
	if (setvbuf(str->s_type.BF.s_fp, str->s_type.BF.s_vbuf, _IOFBF,
	    STDIO_VBUF_SIZE) != 0) {
		safe_free(str->s_type.BF.s_vbuf);
		str->s_type.BF.s_vbuf = NULL;
	}

	stream_set(str, STREAM_OPEN | (S->m_single_byte_locale ? STREAM_SINGLE :
	    STREAM_WIDE));
	stream_unset(str, STREAM_PRIMED);

	return (1);
}

void
stream_set_size(stream_t *str, size_t new_size)
{
	/*
	 * p_new_size is new_size rounded upwards to nearest multiple of
	 * PAGESIZE, since mmap() is going to reserve it in any case.  This
	 * ensures that the far end of the buffer is also aligned, such that we
	 * obtain aligned pointers if we choose to subtract from it.
	 */
	size_t p_new_size = (new_size + PAGESIZE) & ~(PAGESIZE - 1);

	if (str->s_buffer_size == p_new_size)
		return;

	if (str->s_buffer != NULL)
		(void) munmap(str->s_buffer, str->s_buffer_size);

	if (new_size == 0) {
		str->s_buffer = NULL;
		str->s_buffer_size = 0;
		return;
	}

	str->s_buffer = xzmap(0, p_new_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE, 0);

	if (str->s_buffer == MAP_FAILED)
		die(EMSG_MMAP);

	str->s_buffer_size = p_new_size;
}

void
stream_add_file_to_chain(stream_t **str_chain, char *filename)
{
	stream_t *str;

	str = stream_new(STREAM_NO_SOURCE);

	str->s_filename = filename;
	str->s_type.SF.s_fd = -1;

	stream_push_to_chain(str_chain, str);
}

void
stream_push_to_chain(stream_t **str_chain, stream_t *streamp)
{
	stream_t *cur_streamp = *str_chain;

	if (cur_streamp == NULL) {
		*str_chain = streamp;
		streamp->s_next = NULL;
		return;
	}

	while (cur_streamp->s_next != NULL)
		cur_streamp = cur_streamp->s_next;

	cur_streamp->s_next = streamp;
	streamp->s_previous = cur_streamp;
	streamp->s_next = NULL;
}

static void
stream_dump(stream_t *str_in, stream_t *str_out)
{
	ASSERT(!(str_in->s_status & STREAM_OUTPUT));
	ASSERT(str_out->s_status & STREAM_OUTPUT);

	SOP_PUT_LINE(str_out, &str_in->s_current);

	while (!SOP_EOS(str_in)) {
		SOP_FETCH(str_in);
		SOP_PUT_LINE(str_out, &str_in->s_current);
	}
}

/*
 * stream_push_to_temporary() with flags set to ST_CACHE merely copies the
 * stream_t pointer onto the chain.  With flags set to ST_NOCACHE, the stream is
 * written out to a file.  Stream pointers passed to stream_push_to_temporary()
 * must refer to allocated objects, and not to objects created on function
 * stacks.  Finally, if strp == NULL, stream_push_to_temporary() creates and
 * pushes the new stream; the output stream is left open if ST_OPEN is set.
 */
stream_t *
stream_push_to_temporary(stream_t **str_chain, stream_t *streamp, int flags)
{
	stream_t *out_streamp;

	if (flags & ST_CACHE) {
		ASSERT(streamp->s_status & STREAM_ARRAY);
		stream_set(streamp, STREAM_NOT_FREEABLE | STREAM_TEMPORARY);
		stream_push_to_chain(str_chain, streamp);
		return (streamp);
	}

	out_streamp = safe_realloc(NULL, sizeof (stream_t));

	if (streamp != NULL) {
		stream_copy(out_streamp, streamp);
		stream_unset(out_streamp, STREAM_OPEN);
		ASSERT(streamp->s_element_size == sizeof (char) ||
		    streamp->s_element_size == sizeof (wchar_t));
		stream_set(out_streamp,
		    streamp->s_element_size == 1 ? STREAM_SINGLE : STREAM_WIDE);
		out_streamp->s_buffer = NULL;
		out_streamp->s_buffer_size = 0;
	} else {
		stream_clear(out_streamp);
		stream_set(out_streamp, flags & ST_WIDE ? STREAM_WIDE :
		    STREAM_SINGLE);
	}

	(void) bump_file_template();
	out_streamp->s_filename = strdup(get_file_template());

	if (SOP_OPEN_FOR_WRITE(out_streamp) == -1)
		return (NULL);

	stream_set(out_streamp, STREAM_TEMPORARY);
	stream_push_to_chain(str_chain, out_streamp);

	if (streamp != NULL) {
		/*
		 * We reset the input stream to the beginning, and copy it in
		 * sequence to the output stream, freeing the raw_collate field
		 * as we go.
		 */
		if (SOP_PRIME(streamp) != PRIME_SUCCEEDED)
			die(EMSG_BADPRIME);
		stream_dump(streamp, out_streamp);
	}

	if (!(flags & ST_OPEN)) {
		SOP_FREE(out_streamp);
		(void) SOP_CLOSE(out_streamp);
	}

	/*
	 * Now that we've written this stream to disk, we needn't protect any
	 * in-memory consumer.
	 */
	if (streamp != NULL)
		streamp->s_consumer = NULL;

	return (out_streamp);
}

void
stream_close_all_previous(stream_t *tail_streamp)
{
	stream_t *cur_streamp;

	ASSERT(tail_streamp != NULL);

	cur_streamp = tail_streamp->s_previous;
	while (cur_streamp != NULL) {
		(void) SOP_FREE(cur_streamp);
		if (SOP_IS_CLOSABLE(cur_streamp))
			(void) SOP_CLOSE(cur_streamp);

		cur_streamp = cur_streamp->s_previous;
	}
}

void
stream_unlink_temporary(stream_t *streamp)
{
	if (streamp->s_status & STREAM_TEMPORARY) {
		(void) SOP_FREE(streamp);

		if (streamp->s_ops.sop_unlink)
			(void) SOP_UNLINK(streamp);
	}
}

/*
 * stream_insert() takes input from src stream, converts to each line to
 * collatable form, and places a line_rec_t in dest stream, which is of type
 * STREAM_ARRAY.
 */
int
stream_insert(sort_t *S, stream_t *src, stream_t *dest)
{
	ssize_t i = dest->s_type.LA.s_array_size;
	line_rec_t *l_series;
	char *l_convert = dest->s_buffer;
	int return_val = ST_MEM_AVAIL;
	int fetch_result = NEXT_LINE_COMPLETE;

	/*
	 * Scan through until total bytes allowed accumulated, and return.
	 * Use SOP_FETCH(src) so that this works for all stream types,
	 * and so that we can repeat until eos.
	 *
	 * For each new line, we move back sizeof (line_rec_t) from the end of
	 * the array buffer, and copy into the start of the array buffer.  When
	 * the pointers meet, or when we exhaust the current stream, we return.
	 * If we have not filled the current memory allocation, we return
	 * ST_MEM_AVAIL, else we return ST_MEM_FILLED.
	 */
	ASSERT(stream_is_primed(src));
	ASSERT(dest->s_status & STREAM_ARRAY);

	/*LINTED ALIGNMENT*/
	l_series = (line_rec_t *)((caddr_t)dest->s_buffer
	    + dest->s_buffer_size) - dest->s_type.LA.s_array_size;

	if (dest->s_type.LA.s_array_size)
		l_convert = l_series->l_collate.sp +
		    l_series->l_collate_length + src->s_element_size;

	/*
	 * current line has been set prior to entry
	 */
	src->s_current.l_collate.sp = l_convert;
	src->s_current.l_collate_bufsize = (caddr_t)l_series
	    - (caddr_t)l_convert - sizeof (line_rec_t);
	src->s_current.l_raw_collate.sp = NULL;

	if (src->s_current.l_collate_bufsize <= 0)
		return (ST_MEM_FILLED);

	src->s_consumer = dest;

	while (src->s_current.l_collate_bufsize > 0 &&
	    (src->s_current.l_collate_length = S->m_coll_convert(
	    S->m_fields_head, &src->s_current, FCV_FAIL,
	    S->m_field_separator)) >= 0) {
		ASSERT((char *)l_series > l_convert);
		l_series--;
		l_convert += src->s_current.l_collate_length;

		if ((char *)l_series <= l_convert) {
			__S(stats_incr_insert_filled_downward());
			l_series++;
			return_val = ST_MEM_FILLED;
			break;
		}

		/*
		 * There's no collision with the lower part of the buffer, so we
		 * can safely begin processing the line.  In the debug case, we
		 * test for uninitialized data by copying a non-zero pattern.
		 */
#ifdef DEBUG
		memset(l_series, 0x1ff11ff1, sizeof (line_rec_t));
#endif

		copy_line_rec(&src->s_current, l_series);
		i++;

		if (SOP_EOS(src) ||
		    (fetch_result = SOP_FETCH(src)) == NEXT_LINE_INCOMPLETE)
			break;

		src->s_current.l_collate.sp = l_convert;
		src->s_current.l_collate_bufsize = (caddr_t)l_series
		    - (caddr_t)l_convert - sizeof (line_rec_t);
		src->s_current.l_raw_collate.sp = NULL;
	}

	if (fetch_result == NEXT_LINE_INCOMPLETE) {
		__S(stats_incr_insert_filled_input());
		return_val = ST_MEM_FILLED;
	} else if (src->s_current.l_collate_length < 0 ||
	    src->s_current.l_collate_bufsize <= 0) {
		__S(stats_incr_insert_filled_upward());
		return_val = ST_MEM_FILLED;
	}

	if (fetch_result != NEXT_LINE_INCOMPLETE &&
	    src->s_current.l_collate_length < 0 &&
	    i == 0)
		/*
		 * There's no room for conversion of our only line; need to
		 * execute with larger memory.
		 */
		die(EMSG_MEMORY);

	/*
	 * Set up pointer array to line records.
	 */
	if (i > dest->s_type.LA.s_array_size)
		dest->s_type.LA.s_array = safe_realloc(dest->s_type.LA.s_array,
		    sizeof (line_rec_t *) * i);
	dest->s_type.LA.s_array_size = i;

	i = 0;
	while (i < dest->s_type.LA.s_array_size) {
		dest->s_type.LA.s_array[i] = l_series;
		l_series++;
		i++;
	}

	/*
	 * LINES_ARRAY streams are always open.
	 */
	stream_set(dest, STREAM_OPEN);

	return (return_val);
}

/*
 * stream_swap_buffer() exchanges the stream's buffer with the proffered one;
 * s_current is not adjusted so this is safe only for STREAM_INSTANT.
 */
void
stream_swap_buffer(stream_t *str, char **buf, size_t *size)
{
	void *tb = *buf;
	size_t ts = *size;

	*buf = str->s_buffer;
	*size = str->s_buffer_size;

	str->s_buffer = tb;
	str->s_buffer_size = ts;
}
