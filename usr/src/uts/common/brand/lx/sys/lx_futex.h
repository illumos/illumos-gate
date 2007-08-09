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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LX_FUTEX_H
#define	_SYS_LX_FUTEX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FUTEX_WAIT		0
#define	FUTEX_WAKE		1
#define	FUTEX_FD		2
#define	FUTEX_REQUEUE		3
#define	FUTEX_CMP_REQUEUE	4
#define	FUTEX_MAX_CMD		FUTEX_CMP_REQUEUE

#ifdef _KERNEL
extern long lx_futex(uintptr_t addr, int cmd, int val, uintptr_t lx_timeout,
    uintptr_t addr2, int val2);
extern void lx_futex_init(void);
extern int lx_futex_fini(void);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_FUTEX_H */
