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
 * Copyright (c) 1991-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SER_ASYNC_H
#define	_SYS_SER_ASYNC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Initial port setup parameters for async lines
 */

#include <sys/ksynch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following macro can be used to generate the baud rate generator's
 * time constants.  The parameters are the input clock to the BRG (eg,
 * 5000000 for 5MHz) and the desired baud rate.  This macro assumes that
 * the clock needed is 16x the desired baud rate.
 */
#define	ZSTimeConst(InputClock, BaudRate) \
	(ushort_t)((((int)InputClock+(BaudRate*16)) \
	/ (2*(int)(BaudRate*16))) - 2)

#define	ZSDelayConst(Hertz, FifoSize, BitsByte, BaudRate) \
	(ushort_t)((((int)(Hertz)*(FifoSize)*(BitsByte)) \
	/ (int)(BaudRate)) + 1)

#define	ZSPEED(n)	ZSTimeConst(PCLK, n)

#define	ZFIFOSZ		3
/*
 * this macro needs a constant Hertz, but we can now have a hires_tick.
 * ztdelay in zs_async.c converts to a true delay based on hz so we
 * can use 100 for Hertz here.
 */
#define	ZDELAY(n)	ZSDelayConst(100, ZFIFOSZ, NBBY, n)

#define	ISPEED		B9600
#define	ISPEED_SVID	B300
#define	IFLAGS		(CS7|CREAD|PARENB)
#define	IFLAGS_SVID	(CS8|CREAD|HUPCL)
#define	I_IFLAGS	0
#define	I_CFLAGS	((ISPEED << IBSHIFT) | ISPEED | CS8 | CREAD | HUPCL)

/*
 * Ring buffer and async line management definitions for CPU lines:
 */
#ifdef  _KERNEL
#ifndef _ASM
#define	RINGBITS	8		/* # of bits in ring ptrs */
#define	RINGSIZE	(1<<RINGBITS)	/* size of ring */
#define	RINGMASK	(RINGSIZE-1)
#define	RINGFRAC	2		/* fraction of ring to force flush */

#define	RING_INIT(zap)	((zap)->za_rput = (zap)->za_rget = 0)
#define	RING_CNT(zap)	(((zap)->za_rput - (zap)->za_rget) & RINGMASK)
#define	RING_FRAC(zap)	((int)RING_CNT(zap) >= (int)(RINGSIZE/RINGFRAC))
#define	RING_POK(zap, n) ((int)RING_CNT(zap) < (int)(RINGSIZE-(n)))
#define	RING_PUT(zap, c) \
	((zap)->za_ring[(zap)->za_rput++ & RINGMASK] =  (uchar_t)(c))
#define	RING_UNPUT(zap)	((zap)->za_rput--)
#define	RING_GOK(zap, n) ((int)RING_CNT(zap) >= (int)(n))
#define	RING_GET(zap)	((zap)->za_ring[(zap)->za_rget++ & RINGMASK])
#define	RING_EAT(zap, n) ((zap)->za_rget += (n))

/*
 *  To process parity errors/breaks in-band
 */
#define	SBITS		8
#define	S_UNMARK	0x00FF
#define	S_PARERR	(0x01<<SBITS)
#define	S_BREAK		(0x02<<SBITS)
#define	RING_MARK(zap, c, s) \
	((zap)->za_ring[(zap)->za_rput++ & RINGMASK] = ((uchar_t)(c)|(s)))
#define	RING_UNMARK(zap) \
	((zap)->za_ring[((zap)->za_rget) & RINGMASK] &= S_UNMARK)
#define	RING_ERR(zap, c) \
	((zap)->za_ring[((zap)->za_rget) & RINGMASK] & (c))


/*
 * These flags are shared with mcp_async.c and should be kept in sync.
 */
#define	ZAS_WOPEN	0x00000001	/* waiting for open to complete */
#define	ZAS_ISOPEN	0x00000002	/* open is complete */
#define	ZAS_OUT		0x00000004	/* line being used for dialout */
#define	ZAS_CARR_ON	0x00000008	/* carrier on last time we looked */
#define	ZAS_STOPPED	0x00000010	/* output is stopped */
#define	ZAS_DELAY	0x00000020	/* waiting for delay to finish */
#define	ZAS_BREAK	0x00000040	/* waiting for break to finish */
#define	ZAS_BUSY	0x00000080	/* waiting for transmission to finish */
#define	ZAS_DRAINING	0x00000100	/* waiting for output to drain */
					/* from chip */
#define	ZAS_SERVICEIMM	0x00000200	/* queue soft interrupt as soon as */
					/* receiver interrupt occurs */
#define	ZAS_SOFTC_ATTN	0x00000400	/* check soft carrier state in close */
#define	ZAS_PAUSED	0x00000800	/* MCP: dma interrupted and pending */
#define	ZAS_LNEXT	0x00001000	/* MCP: next input char is quoted */
#define	ZAS_XMIT_ACTIVE	0x00002000	/* MCP: Transmit dma running */
#define	ZAS_DMA_DONE	0x00004000	/* MCP: DMA done interrupt received */
#define	ZAS_ZSA_START	0x00010000	/* MCP: DMA done interrupt received */


/*
 * Asynchronous protocol private data structure for ZS and MCP/ALM2
 */
#define	ZSA_MIN_RSTANDBY	12
#define	ZSA_MAX_RSTANDBY	256

#define	ZSA_RDONE_MIN		60
#define	ZSA_RDONE_MAX		350

struct asyncline {
	int		za_flags;	/* random flags */
	kcondvar_t	za_flags_cv;	/* condition variable for flags */
	dev_t		za_dev;		/* device major/minor numbers */
	mblk_t		*za_xmitblk;	/* transmit: active msg block */
	mblk_t		*za_rcvblk;	/* receive: active msg block */
	struct zscom	*za_common;	/* device common data */
	tty_common_t	za_ttycommon;	/* tty driver common data */
	bufcall_id_t	za_wbufcid;	/* id of pending write-side bufcall */
	timeout_id_t	za_polltid;	/* softint poll timeout id */

	/*
	 * The following fields are protected by the zs_excl_hi lock.
	 * Some, such as za_flowc, are set only at the base level and
	 * cleared (without the lock) only by the interrupt level.
	 */
	uchar_t		*za_optr;	/* output pointer */
	int		za_ocnt;	/* output count */
	uchar_t		za_rput;	/* producing pointer for input */
	uchar_t		za_rget;	/* consuming pointer for input */
	uchar_t		za_flowc;	/* flow control char to send */
	uchar_t		za_rr0;		/* status latch for break detection */
	/*
	 * Each character stuffed into the ring has two bytes associated
	 * with it.  The first byte is used to indicate special conditions
	 * and the second byte is the actual data.  The ring buffer
	 * needs to be defined as ushort_t to accomodate this.
	 */
	ushort_t 	za_ring[RINGSIZE];
	timeout_id_t	za_kick_rcv_id;
	int 		za_kick_rcv_count;
	timeout_id_t	za_zsa_restart_id;
	bufcall_id_t	za_bufcid;
	mblk_t		*za_rstandby[ZSA_MAX_RSTANDBY];
					/* receive: standby message blocks */
	mblk_t		*za_rdone[ZSA_RDONE_MAX];
					/* complete messages to be sent up */
	int		za_rdone_wptr;
	int		za_rdone_rptr;
	int		za_bad_count_int;
	uint_t		za_rcv_flags_mask;
#ifdef ZSA_DEBUG
	int		za_wr;
	int		za_rd;
#endif
	volatile uchar_t za_soft_active;
	volatile uchar_t za_kick_active;
#define	DO_STOPC	(1<<8)
#define	DO_ESC		(1<<9)
#define	DO_SERVICEIMM	(1<<10)
#define	DO_TRANSMIT	(1<<11)
#define	DO_RETRANSMIT	(1<<12)
/*
 * ZS exclusive stuff.
 */
	short		za_break;	/* break count */
	union {
		struct {
			uchar_t  _hw;    /* overrun (hw) */
			uchar_t  _sw;    /* overrun (sw) */
		} _z;
		ushort_t uover_overrun;
	} za_uover;
#define	za_overrun	za_uover.uover_overrun
#define	za_hw_overrun	za_uover._z._hw
#define	za_sw_overrun	za_uover._z._sw
	short		za_ext;		/* modem status change count */
	short		za_work;	/* work to do flag */
	short		za_grace_flow_control;
	uchar_t		za_do_kick_rcv_in_softint;
	uchar_t		za_m_error;
/*
 * MCP exclusive stuff.
 * These should all be protected by a high priority lock.
 */
	uchar_t		*za_xoff;	/* xoff char in h/w XOFF buffer */
	uchar_t		za_lnext;	/* treat next char as literal */
	uchar_t		*za_devctl;	/* device control reg for this port */
	uchar_t		*za_dmabuf;	/* dma ram buffer for this port */
	int		za_breakoff;	/* SLAVIO */
	int		za_slav_break;	/* SLAVIO */
/*
 * NTP PPS exclusive stuff.
 */
	short		za_pps;		/* PPS on? */
};

#endif /* _ASM */
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_SER_ASYNC_H */
