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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SC_CVC_H
#define	_SYS_SC_CVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


#define	CVC_IOSRAM_POLL_USECS	100000

#if defined(DEBUG)

#define	CVC_DBG_ATTACH		0x0001
#define	CVC_DBG_DETACH		0x0002
#define	CVC_DBG_OPEN		0x0004
#define	CVC_DBG_CLOSE		0x0008
#define	CVC_DBG_IOCTL		0x0010
#define	CVC_DBG_REDIR		0x0020
#define	CVC_DBG_WPUT		0x0040
#define	CVC_DBG_WSRV		0x0080
#define	CVC_DBG_IOSRAM_WR	0x0100
#define	CVC_DBG_IOSRAM_RD	0x0200
#define	CVC_DBG_NETWORK_WR	0x0400
#define	CVC_DBG_NETWORK_RD	0x0800
#define	CVC_DBG_IOSRAM_CNTL	0x1000


#define	CVC_DBG0(flag, fmt) \
	cvc_dbg(flag, fmt, 0, 0, 0, 0, 0);
#define	CVC_DBG1(flag, fmt, a1) \
	cvc_dbg(flag, fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	CVC_DBG2(flag, fmt, a1, a2) \
	cvc_dbg(flag, fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	CVC_DBG3(flag, fmt, a1, a2, a3) \
	cvc_dbg(flag, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), 0, 0);
#define	CVC_DBG4(flag, fmt, a1, a2, a3, a4) \
	cvc_dbg(flag, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), 0);
#define	CVC_DBG5(flag, fmt, a1, a2, a3, a4, a5) \
	cvc_dbg(flag, fmt, (uintptr_t)(a1), (uintptr_t)(a2), \
		(uintptr_t)(a3), (uintptr_t)(a4), (uintptr_t)(a5));

#else /* DEBUG */

#define	CVC_DBG0(flag, fmt)
#define	CVC_DBG1(flag, fmt, a1)
#define	CVC_DBG2(flag, fmt, a1, a2)
#define	CVC_DBG3(flag, fmt, a1, a2, a3)
#define	CVC_DBG4(flag, fmt, a1, a2, a3, a4)
#define	CVC_DBG5(flag, fmt, a1, a2, a3, a4, a5)

#endif /* DEBUG */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SC_CVC_H */
