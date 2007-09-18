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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved 	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_XENCONS_H
#define	_SYS_XENCONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/tty.h>
#include <sys/ksynch.h>
#include <sys/dditypes.h>
#include <xen/public/io/console.h>


/*
 * Xencons tracing macros.  These are a similar to some macros in sys/vtrace.h.
 *
 * XXX - Needs review:  would it be better to use the macros in sys/vtrace.h ?
 */
#ifdef DEBUG
#define	DEBUGWARN0(fac, format) \
	if (debug & (fac)) \
		cmn_err(CE_WARN, format)
#define	DEBUGNOTE0(fac, format) \
	if (debug & (fac)) \
		cmn_err(CE_NOTE, format)
#define	DEBUGNOTE1(fac, format, arg1) \
	if (debug & (fac)) \
		cmn_err(CE_NOTE, format, arg1)
#define	DEBUGNOTE2(fac, format, arg1, arg2) \
	if (debug & (fac)) \
		cmn_err(CE_NOTE, format, arg1, arg2)
#define	DEBUGNOTE3(fac, format, arg1, arg2, arg3) \
	if (debug & (fac)) \
		cmn_err(CE_NOTE, format, arg1, arg2, arg3)
#define	DEBUGCONT0(fac, format) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format)
#define	DEBUGCONT1(fac, format, arg1) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format, arg1)
#define	DEBUGCONT2(fac, format, arg1, arg2) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format, arg1, arg2)
#define	DEBUGCONT3(fac, format, arg1, arg2, arg3) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format, arg1, arg2, arg3)
#define	DEBUGCONT4(fac, format, arg1, arg2, arg3, arg4) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format, arg1, arg2, arg3, arg4)
#define	DEBUGCONT10(fac, format, \
	arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10) \
	if (debug & (fac)) \
		cmn_err(CE_CONT, format, \
		arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)
#else
#define	DEBUGWARN0(fac, format)
#define	DEBUGNOTE0(fac, format)
#define	DEBUGNOTE1(fac, format, arg1)
#define	DEBUGNOTE2(fac, format, arg1, arg2)
#define	DEBUGNOTE3(fac, format, arg1, arg2, arg3)
#define	DEBUGCONT0(fac, format)
#define	DEBUGCONT1(fac, format, arg1)
#define	DEBUGCONT2(fac, format, arg1, arg2)
#define	DEBUGCONT3(fac, format, arg1, arg2, arg3)
#define	DEBUGCONT4(fac, format, arg1, arg2, arg3, arg4)
#define	DEBUGCONT10(fac, format, \
	arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)
#endif

/* enum value for sw and hw flow control action */
typedef enum {
	FLOW_CHECK,
	FLOW_STOP,
	FLOW_START
} async_flowc_action;

#define	async_stopc	async_ttycommon.t_stopc
#define	async_startc	async_ttycommon.t_startc

/*
 * Console instance data.
 * Each of the fields in this structure is required to be protected by a
 * mutex lock at the highest priority at which it can be altered.
 */

struct xencons {
	int		flags;	/* random flags  */
	struct asyncline *priv;	/* protocol private data -- asyncline */
	dev_info_t	*dip;	/* dev_info */
	int		unit;	/* which port */
	kmutex_t	excl;	/* adaptive mutex */
	kcondvar_t	excl_cv;	/* condition variable */
	struct cons_polledio polledio;	/* polled I/O functions */
	unsigned char	pollbuf[60];	/* polled I/O data */
	int		polldix;	/* polled data buffer index */
	int		polllen;	/* polled data buffer length */
	volatile struct xencons_interface *ifp;	/* console ring buffers */
	int		console_irq;	/* dom0 console interrupt */
	int		evtchn;		/* console event channel */
};

/*
 * Asychronous protocol private data structure for ASY.
 * Each of the fields in the structure is required to be protected by
 * the lower priority lock except the fields that are set only at
 * base level but cleared (with out lock) at interrupt level.
 */

struct asyncline {
	int		async_flags;	/* random flags */
	kcondvar_t	async_flags_cv; /* condition variable for flags */
	dev_t		async_dev;	/* device major/minor numbers */
	mblk_t		*async_xmitblk;	/* transmit: active msg block */
	struct xencons	*async_common;	/* device common data */
	tty_common_t 	async_ttycommon; /* tty driver common data */
	bufcall_id_t	async_wbufcid;	/* id for pending write-side bufcall */
	timeout_id_t	async_polltid;	/* softint poll timeout id */
	timeout_id_t    async_dtrtid;   /* delaying DTR turn on */
	timeout_id_t    async_utbrktid; /* hold minimum untimed break time id */

	/*
	 * The following fields are protected by the excl_hi lock.
	 * Some, such as async_flowc, are set only at the base level and
	 * cleared (without the lock) only by the interrupt level.
	 */
	uchar_t		*async_optr;	/* output pointer */
	int		async_ocnt;	/* output count */
	ushort_t	async_rput;	/* producing pointer for input */
	ushort_t	async_rget;	/* consuming pointer for input */
	int		async_inflow_source; /* input flow control type */

	union {
		struct {
			uchar_t _hw;	/* overrun (hw) */
			uchar_t _sw;	/* overrun (sw) */
		} _a;
		ushort_t uover_overrun;
	} async_uover;
#define	async_overrun		async_uover._a.uover_overrun
#define	async_hw_overrun	async_uover._a._hw
#define	async_sw_overrun	async_uover._a._sw
	short		async_ext;	/* modem status change count */
	short		async_work;	/* work to do flag */
};

/* definitions for async_flags field */
#define	ASYNC_EXCL_OPEN	 0x10000000	/* exclusive open */
#define	ASYNC_WOPEN	 0x00000001	/* waiting for open to complete */
#define	ASYNC_ISOPEN	 0x00000002	/* open is complete */
#define	ASYNC_STOPPED	 0x00000010	/* output is stopped */
#define	ASYNC_PROGRESS	 0x00001000	/* made progress on output effort */
#define	ASYNC_CLOSING	 0x00002000	/* processing close on stream */
#define	ASYNC_SW_IN_FLOW 0x00020000	/* sw input flow control in effect */
#define	ASYNC_SW_OUT_FLW 0x00040000	/* sw output flow control in effect */
#define	ASYNC_SW_IN_NEEDED 0x00080000	/* sw input flow control char is */
					/* needed to be sent */
#define	ASYNC_OUT_FLW_RESUME 0x00100000 /* output need to be resumed */
					/* because of transition of flow */
					/* control from stop to start */


/* definitions for asy_flags field */
#define	ASY_CONSOLE	0x00000080

/* definitions for async_inflow_source field in struct asyncline */
#define	IN_FLOW_NULL	0x00000000
#define	IN_FLOW_STREAMS	0x00000002
#define	IN_FLOW_USER	0x00000004

#define	XENCONS_BURST	128	/* burst size for console writes */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XENCONS_H */
