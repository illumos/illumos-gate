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

#include "streams_array.h"
#include "streams_common.h"

/*
 * Single-byte character memory map-based streams implementation
 */

static int
stream_array_prime(stream_t *str)
{
	ASSERT((str->s_status & STREAM_SOURCE_MASK) == STREAM_ARRAY);

	str->s_type.LA.s_cur_index = MIN(0, str->s_type.LA.s_array_size - 1);
	if (str->s_type.LA.s_cur_index >= 0)
		copy_line_rec(
		    str->s_type.LA.s_array[str->s_type.LA.s_cur_index],
		    &str->s_current);
	else {
		stream_set(str, STREAM_EOS_REACHED);
		stream_unset(str, STREAM_PRIMED);
		return (PRIME_FAILED_EMPTY_FILE);
	}

	stream_set(str, STREAM_PRIMED);

	return (PRIME_SUCCEEDED);
}

static ssize_t
stream_array_fetch(stream_t *str)
{
	ASSERT(str->s_status & STREAM_OPEN);
	ASSERT(str->s_type.LA.s_cur_index < str->s_type.LA.s_array_size);

	if (++str->s_type.LA.s_cur_index == str->s_type.LA.s_array_size - 1)
		stream_set(str, STREAM_EOS_REACHED);

	copy_line_rec(str->s_type.LA.s_array[str->s_type.LA.s_cur_index],
	    &str->s_current);

	return (NEXT_LINE_COMPLETE);
}

/*ARGSUSED*/
static int
stream_array_is_closable(stream_t *str)
{
	/*
	 * Array streams are not closable.  That is, there is no open file
	 * descriptor directly associated with an array stream.
	 */
	return (0);
}

static int
stream_array_close(stream_t *str)
{
	stream_unset(str, STREAM_OPEN | STREAM_PRIMED);

	return (1);
}

static int
stream_array_free(stream_t *str)
{
	/*
	 * It's now safe for us to close the various streams backing the array
	 * stream's data.
	 */
	stream_unset(str, STREAM_PRIMED | STREAM_NOT_FREEABLE);

	return (1);
}

static int
stream_array_eos(stream_t *str)
{
	int retval = 0;

	if (str == NULL || str->s_status & STREAM_EOS_REACHED)
		return (1);

	if (str->s_type.LA.s_cur_index + 1 >= str->s_type.LA.s_array_size) {
		retval = 1;
		stream_set(str, STREAM_EOS_REACHED);
	}

	return (retval);
}

/*ARGSUSED*/
static void
stream_array_release_line(stream_t *str)
{
}

const stream_ops_t stream_array_ops = {
	stream_array_is_closable,
	stream_array_close,
	stream_array_eos,
	stream_array_fetch,
	NULL,
	stream_array_free,
	NULL,
	stream_array_prime,
	NULL,
	stream_array_release_line,
	NULL,
	NULL
};
