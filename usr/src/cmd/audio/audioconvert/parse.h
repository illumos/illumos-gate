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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _AUDIOCONVERT_PARSE_H
#define	_AUDIOCONVERT_PARSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	K_NULL = 0, K_ENCODING = 1, K_FORMAT, K_RATE, K_CHANNELS,
	K_OFFSET, K_INFO, K_AMBIG = -1
} keyword_type;

typedef enum {
	F_RAW = 0, F_SUN = 1, F_AIFF, F_UNKNOWN = -1
} format_type;

struct keyword_table {
	char		*name;
	keyword_type	type;
};

extern int	parse_format(char *, AudioHdr&, format_type&, off_t&);

#ifdef __cplusplus
}
#endif

#endif /* !_AUDIOCONVERT_PARSE_H */
