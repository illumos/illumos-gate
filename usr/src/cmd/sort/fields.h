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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SORT_FIELDS_H
#define	_SORT_FIELDS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <alloca.h>
#include <ctype.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <widec.h>

#include "statistics.h"
#include "types.h"
#include "utility.h"

#define	FCV_REALLOC	0x1
#define	FCV_FAIL	0x2

#define	INITIAL_COLLATION_SIZE	1024

#define	COLL_NONUNIQUE	0x0
#define	COLL_UNIQUE	0x1
#define	COLL_DATA_ONLY	0x2
#define	COLL_REVERSE	0x4

extern void field_initialize(sort_t *);

extern field_t *field_new(sort_t *);
extern void field_delete(field_t *);
extern void field_add_to_chain(field_t **, field_t *);
extern void field_print(field_t *);

extern ssize_t field_convert_alpha(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);
extern ssize_t field_convert_alpha_simple(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);
extern ssize_t field_convert_month(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);
extern ssize_t field_convert_numeric(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);

extern int collated(line_rec_t *, line_rec_t *, ssize_t, flag_t);
extern ssize_t field_convert(field_t *, line_rec_t *, flag_t, vchar_t);

extern ssize_t field_convert_alpha_wide(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);
extern ssize_t field_convert_month_wide(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);
extern ssize_t field_convert_numeric_wide(field_t *, line_rec_t *, vchar_t,
    ssize_t, ssize_t, ssize_t);

extern int collated_wide(line_rec_t *, line_rec_t *, ssize_t, flag_t);
extern ssize_t field_convert_wide(field_t *, line_rec_t *, flag_t, vchar_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SORT_FIELDS_H */
