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
 *
 * lut.h -- public definitions for lookup table module
 *
 * this module is a very simple look-up table implementation.  used
 * all over this program to implement tables of various sorts.
 */

#ifndef	_ESC_COMMON_LUT_H
#define	_ESC_COMMON_LUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "tree.h"

void lut_init(void);
void lut_fini(void);
typedef int (*lut_cmp)(void *lhs, void *rhs);
struct lut *lut_add(struct lut *root, void *lhs, void *rhs,
    int (*cmp_func)(void *old_lhs, void *new_lhs));
void *lut_lookup(struct lut *root, void *lhs, lut_cmp cmp_func);
void *lut_lookup_lhs(struct lut *root, void *lhs, lut_cmp cmp_func);
typedef void (*lut_cb)(void *lhs, void *rhs, void *arg);
void lut_walk(struct lut *root, lut_cb callback, void *arg);
void lut_free(struct lut *root, lut_cb callback, void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_LUT_H */
