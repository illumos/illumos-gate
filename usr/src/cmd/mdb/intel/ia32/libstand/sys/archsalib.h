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

#ifndef _ARCHSALIB_H
#define	_ARCHSALIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Intel-specific standalone functions that are to be exported by kmdb.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int64_t __mul64(int64_t, int64_t);
extern uint64_t __udiv64(uint64_t, uint64_t);
extern uint64_t __urem64(int64_t, int64_t);
extern int64_t __div64(int64_t, int64_t);
extern int64_t __rem64(int64_t, int64_t);

#ifdef __cplusplus
}
#endif

#endif /* _ARCHSALIB_H */
