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
 * Copyright (c) 1986 by Sun Microsystems, Inc.
 */

#ifndef _SYS_PSW_H
#define	_SYS_PSW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS psl.h 1.2 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file only exists for v7 backwards compatibility.
 * Kernel code shoulf not include it.
 */
#ifdef _KERNEL
#error Kernel include of psw.h
#else

#include <v7/sys/psr.h>

/*
 * The following defines are obsolete; they exist only for existing
 * application compatibility.
 */
#define	SR_SMODE	PSR_PS

/*
 * Macros to decode psr.
 *
 * XXX - note that AT&T's usage of BASEPRI() is reversed from ours
 * (i.e. (!BASEPRI(ps)) means that you *are* at the base priority).
 */
#define	BASEPRI(ps)	(((ps) & PSR_PIL) == 0)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSW_H */
