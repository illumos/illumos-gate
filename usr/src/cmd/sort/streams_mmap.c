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

#include "streams_mmap.h"
#include "streams_common.h"

/*
 * Single-byte character memory map-based streams implementation
 */

static int
stream_mmap_prime(stream_t *str)
{
	char *nl;

	if (stream_is_primed(str))
		return (PRIME_SUCCEEDED);

	stream_set(str, STREAM_PRIMED);

	if (str->s_buffer_size == 0) {
		stream_set(str, STREAM_EOS_REACHED);
		return (PRIME_FAILED_EMPTY_FILE);
	}

	str->s_current.l_data.sp = str->s_buffer;
	str->s_type.SF.s_release_origin = str->s_buffer;
	if ((nl = (char *)memchr(str->s_buffer, '\n', str->s_buffer_size)) ==
	    NULL) {
		warn(WMSG_NEWLINE_ADDED, str->s_filename);
		str->s_current.l_data_length = str->s_buffer_size;
	} else {
		str->s_current.l_data_length = nl - (char *)str->s_buffer;
	}

	str->s_current.l_collate.sp = NULL;
	str->s_current.l_collate_length = 0;

	__S(stats_incr_fetches());
	return (PRIME_SUCCEEDED);
}

/*
 * stream_mmap_fetch() sets the fields of str->s_current to delimit the next
 * line of the field.
 */
static ssize_t
stream_mmap_fetch(stream_t *str)
{
	ssize_t dist_to_buf_end;
	char *next_nl;

	ASSERT(stream_is_primed(str));
	ASSERT((str->s_status & STREAM_EOS_REACHED) == 0);

	/*
	 * adding one for newline
	 */
	str->s_current.l_data.sp = str->s_current.l_data.sp +
	    str->s_current.l_data_length + 1;

	dist_to_buf_end = str->s_buffer_size - (str->s_current.l_data.sp
	    - (char *)str->s_buffer);
	ASSERT(dist_to_buf_end >= 0 && dist_to_buf_end <= str->s_buffer_size);

	next_nl = memchr(str->s_current.l_data.sp, '\n', dist_to_buf_end);

	if (next_nl)
		str->s_current.l_data_length = next_nl
		    - str->s_current.l_data.sp;
	else {
		warn(WMSG_NEWLINE_ADDED, str->s_filename);
		str->s_current.l_data_length = dist_to_buf_end;
	}

	/*
	 * adding one for newline
	 */
	if (str->s_current.l_data.sp + str->s_current.l_data_length + 1 >=
	    (char *)str->s_buffer + str->s_buffer_size)
		stream_set(str, STREAM_EOS_REACHED);

	str->s_current.l_collate_length = 0;

	__S(stats_incr_fetches());
	return (NEXT_LINE_COMPLETE);
}

static int
stream_mmap_is_closable(stream_t *str)
{
	if (str->s_status & STREAM_OPEN)
		return (1);
	return (0);
}

static int
stream_mmap_close(stream_t *str)
{
	if (str->s_type.SF.s_fd > -1) {
		(void) close(str->s_type.SF.s_fd);
		stream_unset(str, STREAM_OPEN);
		return (1);
	}

	return (0);
}

static int
stream_mmap_free(stream_t *str)
{
	if (!(str->s_status & STREAM_OPEN) ||
	    (str->s_consumer != NULL &&
	    str->s_consumer->s_status & STREAM_NOT_FREEABLE))
		return (0);

	if (str->s_buffer == NULL)
		return (1);

	if (munmap(str->s_buffer, str->s_buffer_size) < 0)
		die(EMSG_MUNMAP, str->s_filename);

	str->s_buffer = NULL;
	str->s_buffer_size = 0;

	stream_unset(str, STREAM_PRIMED);

	return (1);
}

static int
stream_mmap_eos(stream_t *str)
{
	int retval = 0;

	if (str == NULL || str->s_status & STREAM_EOS_REACHED)
		return (1);

	/*
	 * If the file's size is known to be zero, then we are at EOS; the
	 * remaining checks are only sensible if we successfully primed this
	 * stream.  The additional character is for the optional newline.
	 */
	if (str->s_filesize == 0 ||
	    (stream_is_primed(str) && str->s_current.l_data.sp -
	    (char *)str->s_buffer + str->s_current.l_data_length + 1 >=
	    str->s_buffer_size)) {
		retval = 1;
		stream_set(str, STREAM_EOS_REACHED);
	}

	return (retval);
}

#define	ALIGNED		(~(ulong_t)(PAGESIZE - 1))

/*
 * In certain cases, we know that we will never need the data on a page again
 * for the duration of the sort.  (These cases are associated with merges
 * involving temporary files.)  We can thus release all pages previous to the
 * page containing the current line, using the MADV_DONTNEED flag to
 * madvise(3C).  This additional memory management improves our chances of
 * avoiding a paging situation, by evicting pages we know are of no use.
 */
static void
stream_mmap_release_line(stream_t *str)
{
	caddr_t origin = str->s_type.SF.s_release_origin;
	size_t release = 0;

	while ((caddr_t)((ulong_t)str->s_current.l_data.sp & ALIGNED) -
	    (origin + release) >= DEFAULT_RELEASE_SIZE)
		release += DEFAULT_RELEASE_SIZE;

	if (release == 0)
		return;

	if (madvise(origin, release, MADV_DONTNEED) == -1)
		warn(gettext("madvise failed"));

	str->s_type.SF.s_release_origin += release;
}

const stream_ops_t stream_mmap_ops = {
	stream_mmap_is_closable,
	stream_mmap_close,
	stream_mmap_eos,
	stream_mmap_fetch,
	NULL,
	stream_mmap_free,
	NULL,
	stream_mmap_prime,
	NULL,
	stream_mmap_release_line,
	NULL,
	stream_stdio_unlink
};
