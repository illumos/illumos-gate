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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * logadm/lut.h -- public definitions for lookup table module
 */

#ifndef	_LOGADM_LUT_H
#define	_LOGADM_LUT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct lut *lut_add(struct lut *root, const char *lhs, void *rhs);
struct lut *lut_dup(struct lut *root);
void *lut_lookup(struct lut *root, const char *lhs);
void lut_walk(struct lut *root,
    void (*callback)(const char *lhs, void *rhs, void *arg), void *arg);
void lut_free(struct lut *root, void (*callback)(void *rhs));

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGADM_LUT_H */
