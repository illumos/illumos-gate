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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ATA_DEBUG_H
#define	_ATA_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * debugging options
 */

/*
 * Always print "real" error messages on non-debugging kernels
 */

#ifdef	ATA_DEBUG
#define	ADBG_ERROR(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_ERROR, fmt)
#else
#define	ADBG_ERROR(fmt)	ghd_err fmt
#endif

/*
 * ... everything else is conditional on the ATA_DEBUG preprocessor symbol
 */

#define	ADBG_WARN(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_WARN, fmt)
#define	ADBG_TRACE(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_TRACE, fmt)
#define	ADBG_INIT(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_INIT, fmt)
#define	ADBG_TRANSPORT(fmt)	ADBG_FLAG_CHK(ADBG_FLAG_TRANSPORT, fmt)
#define	ADBG_DMA(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_DMA, fmt)
#define	ADBG_ARQ(fmt)		ADBG_FLAG_CHK(ADBG_FLAG_ARQ, fmt)




extern int ata_debug;

#define	ADBG_FLAG_ERROR		0x0001
#define	ADBG_FLAG_WARN		0x0002
#define	ADBG_FLAG_TRACE		0x0004
#define	ADBG_FLAG_INIT		0x0008
#define	ADBG_FLAG_TRANSPORT	0x0010
#define	ADBG_FLAG_DMA		0x0020
#define	ADBG_FLAG_ARQ		0x0040



#ifdef	ATA_DEBUG
#define	ADBG_FLAG_CHK(flag, fmt) if (ata_debug & (flag)) GDBG_PRF(fmt)
#else
#define	ADBG_FLAG_CHK(flag, fmt)
#endif



#ifdef	__cplusplus
}
#endif

#endif /* _ATA_DEBUG_H */
