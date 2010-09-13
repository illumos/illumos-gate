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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */

#ifndef	_SYS_MEMBAR_H
#define	_SYS_MEMBAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)
extern void membar_ldld(void);
extern void membar_stld(void);
extern void membar_ldst(void);
extern void membar_stst(void);

extern void membar_ldld_ldst(void);
extern void membar_ldld_stld(void);
extern void membar_ldld_stst(void);

extern void membar_stld_ldld(void);
extern void membar_stld_ldst(void);
extern void membar_stld_stst(void);

extern void membar_ldst_ldld(void);
extern void membar_ldst_stld(void);
extern void membar_ldst_stst(void);

extern void membar_stst_ldld(void);
extern void membar_stst_stld(void);
extern void membar_stst_ldst(void);

extern void membar_lookaside(void);
extern void membar_memissue(void);
extern void membar_sync(void);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEMBAR_H */
