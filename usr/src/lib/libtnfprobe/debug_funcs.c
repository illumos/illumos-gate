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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <assert.h>
#include <limits.h>
#include <values.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tnf/probe.h>
#include "tnf_trace.h"
#include "tnf_args.h"

/*
 * tnf_probe_debug() - a debug final function
 */

#define	BUF_LIMIT	1024
#define	NAME_LIMIT	32
#define	ATTR_LIMIT	128

/*
 * code coverage comment out
 * #pragma covcc !instr
 */

void
tnf_probe_debug(tnf_probe_setup_t *set_p)
{
	char 		tmp_buf[BUF_LIMIT];
	char		*buf_p;
	tnf_probe_control_t *probe_p;
	const char 	*attr_start, *name_start, *name_end;
	ulong_t		attr_len;
	int 		num_args, i, str_len, name_len;
	void 		*arg_position;
	tnf_arg_kind_t	arg_type;
	void 		*buffer;

	buf_p = tmp_buf;
	probe_p = set_p->probe_p;
	buffer = set_p->buffer_p;

	/* get the name of the probe */
	attr_start = tnf_probe_get_value(probe_p, "name", &attr_len);
	assert(attr_start);
	attr_len = (attr_len > (NAME_LIMIT - 1)) ? (NAME_LIMIT - 1) : attr_len;
	str_len = sprintf(buf_p, "probe %.*s; ", attr_len, attr_start);
	buf_p += str_len;

	/* get the sunw%debug attribute */
	attr_start = tnf_probe_get_value(probe_p, "sunw%debug", &attr_len);
	if (attr_start) {
	    attr_len = (attr_len > (ATTR_LIMIT - 1)) ?
				(ATTR_LIMIT - 1) : attr_len;
	    str_len = sprintf(buf_p, "sunw%%debug \"%.*s\"; ",
				attr_len, attr_start);
	    buf_p += str_len;
	}

	/* number of args ? we are done if there are only standard args */
	num_args = tnf_probe_get_num_args(probe_p);
	if (num_args <= 2) {
	    (void) sprintf(buf_p, "\n");
	    (void) write(STDERR_FILENO, tmp_buf, strlen(tmp_buf));
	    return;
	}

	/* get the slot names */
	name_start = tnf_probe_get_value(probe_p, "slots", &attr_len);
	assert(name_start);

	num_args = tnf_probe_get_num_args(probe_p);
	if (num_args <= 2)
	    return;
	/* print each of the arguments to the probe */
	for (i = 2; i < num_args; i++) {
	    /* find slot names - number of spaces is equal to number of args */
	    name_end = strchr(name_start, VAL_SEPARATOR);
	    /* LINTED - result is <= string length */
	    name_len = name_end - name_start;
	    name_len = (name_len > (NAME_LIMIT - 1)) ?
				(NAME_LIMIT - 1) : name_len;
	    str_len = sprintf(buf_p, "%.*s=", name_len, name_start);
	    buf_p += str_len;
	    name_start = name_end + 1;

	    arg_position = tnf_probe_get_arg_indexed(probe_p, i, buffer);
	    arg_type = tnf_probe_get_type_indexed(probe_p, i);

	    switch (arg_type) {
	    case TNF_UNKNOWN:
		str_len = sprintf(buf_p, "<unknown>; ");
		buf_p += str_len;
		break;
	    case TNF_INT32:
		str_len = sprintf(buf_p, "%ld; ",
					tnf_probe_get_int(arg_position));
		buf_p += str_len;
		break;
	    case TNF_UINT32:
		str_len = sprintf(buf_p, "%lu; ",
					tnf_probe_get_uint(arg_position));
		buf_p += str_len;
		break;
	    case TNF_INT64:
		/* LINTED malformed format string */
		str_len = sprintf(buf_p, "%lld; ",
					tnf_probe_get_longlong(arg_position));
		buf_p += str_len;
		break;
	    case TNF_UINT64:
		/* LINTED malformed format string */
		str_len = sprintf(buf_p, "%llu; ",
					tnf_probe_get_ulonglong(arg_position));
		buf_p += str_len;
		break;
	    case TNF_FLOAT32:
		str_len = sprintf(buf_p, "%f; ",
					tnf_probe_get_float(arg_position));
		buf_p += str_len;
		break;
	    case TNF_FLOAT64:
		str_len = sprintf(buf_p, "%f; ",
					tnf_probe_get_double(arg_position));
		buf_p += str_len;
		break;
	    case TNF_STRING:
		attr_start = tnf_probe_get_chars(arg_position);
		attr_len = strlen(attr_start);
		attr_len = (attr_len > (ATTR_LIMIT - 1)) ? (ATTR_LIMIT - 1) :
					attr_len;
		str_len = sprintf(buf_p, "\"%.*s\"; ", attr_len, attr_start);
		buf_p += str_len;
		break;
	    case TNF_ARRAY:
		/* no break */
	    case TNF_STRUCT:
		/* no break */
	    case TNF_OPAQUE:
		str_len = sprintf(buf_p, "0x%lx; ",
					tnf_probe_get_ulong(arg_position));
		buf_p += str_len;
		break;
	    default:
		str_len = sprintf(buf_p, "<error>; ");
		buf_p += str_len;
		break;
	    }
	}

	(void) sprintf(buf_p, "\n");
	(void) write(STDERR_FILENO, tmp_buf, strlen(tmp_buf));

	return;

}   /* end tnf_probe_debug */


/*
 * code coverage comment out
 * #pragma covcc instr
 */

#ifdef TESTING
/*
 * tnf_probe_empty() - an empty final function
 */

/*ARGSUSED0*/
void
tnf_probe_empty(tnf_probe_setup_t *set_p)
{

	return;

}   /* end tnf_probe_empty */
#endif
