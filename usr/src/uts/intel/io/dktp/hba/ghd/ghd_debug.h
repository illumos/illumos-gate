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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GHD_DEBUG_H
#define	_GHD_DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/varargs.h>

extern void ghd_err(const char *fmt, ...) __KPRINTFLIKE(1);
extern ulong_t ghd_debug_flags;

#define	GDBG_FLAG_ERROR		0x0001
#define	GDBG_FLAG_INTR		0x0002
#define	GDBG_FLAG_PEND_INTR	0x0004
#define	GDBG_FLAG_START		0x0008
#define	GDBG_FLAG_WARN		0x0010
#define	GDBG_FLAG_DMA		0x0020
#define	GDBG_FLAG_PKT		0x0040
#define	GDBG_FLAG_INIT		0x0080
#define	GDBG_FLAG_WAITQ		0x0100

/*
 * Use prom_printf() or vcmn_err()
 */
#ifdef GHD_DEBUG_PROM_PRINTF
#define	GDBG_PRF(fmt)	prom_printf fmt
#include <sys/promif.h>
#else
#define	GDBG_PRF(fmt)	ghd_err fmt
#endif

#if defined(GHD_DEBUG) || defined(__lint)

#define	GDBG_FLAG_CHK(flag, fmt) if (ghd_debug_flags & (flag)) GDBG_PRF(fmt)

#else	/* GHD_DEBUG || __lint */

#define	GDBG_FLAG_CHK(flag, fmt)

#endif	/* GHD_DEBUG || __lint */

/*
 * Always print "real" error messages on non-debugging kernels
 */

#if defined(GHD_DEBUG) || defined(__lint)
#define	GDBG_ERROR(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_ERROR, fmt)
#else
#define	GDBG_ERROR(fmt)	ghd_err fmt
#endif

/*
 * Debugging printf macros
 */

#define	GDBG_INTR(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_INTR, fmt)
#define	GDBG_PEND_INTR(fmt)	GDBG_FLAG_CHK(GDBG_FLAG_PEND_INTR, fmt)
#define	GDBG_START(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_START, fmt)
#define	GDBG_WARN(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_WARN, fmt)
#define	GDBG_DMA(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_DMA, fmt)
#define	GDBG_PKT(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_PKT, fmt)
#define	GDBG_INIT(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_INIT, fmt)
#define	GDBG_WAITQ(fmt)		GDBG_FLAG_CHK(GDBG_FLAG_WAITQ, fmt)

#ifdef	__cplusplus
}
#endif

#endif /* _GHD_DEBUG_H */
