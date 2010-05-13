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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_ASY_H
#define	_SYS_ASY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/tty.h>
#include <sys/ksynch.h>
#include <sys/dditypes.h>

/*
 * internal bus type naming
 */
#define	ASY_BUS_PCI	(0)
#define	ASY_BUS_ISA	(1)
#define	ASY_BUS_UNKNOWN	(-1)

#define	ASY_MINOR_LEN	(40)

#define	COM1_IOADDR	0x3f8
#define	COM2_IOADDR	0x2f8
#define	COM3_IOADDR	0x3e8
#define	COM4_IOADDR	0x2e8

/*
 * Definitions for INS8250 / 16550  chips
 */

/* defined as offsets from the data register */
#define	DAT		0 	/* receive/transmit data */
#define	ICR		1  	/* interrupt control register */
#define	ISR		2   	/* interrupt status register */
#define	LCR		3   	/* line control register */
#define	MCR		4   	/* modem control register */
#define	LSR		5   	/* line status register */
#define	MSR		6   	/* modem status register */
#define	SCR		7   	/* scratch register */
#define	DLL		0   	/* divisor latch (lsb) */
#define	DLH		1   	/* divisor latch (msb) */
#define	FIFOR		ISR	/* FIFO register for 16550 */
#define	EFR		ISR	/* Enhanced feature register for 16650 */

/*
 * INTEL 8210-A/B & 16450/16550 Registers Structure.
 */

/* Line Control Register */
#define	WLS0		0x01	/* word length select bit 0 */
#define	WLS1		0x02	/* word length select bit 2 */
#define	STB		0x04	/* number of stop bits */
#define	PEN		0x08	/* parity enable */
#define	EPS		0x10	/* even parity select */
#define	SETBREAK 	0x40	/* break key */
#define	DLAB		0x80	/* divisor latch access bit */
#define	RXLEN   	0x03   	/* # of data bits per received/xmitted char */
#define	STOP1   	0x00
#define	STOP2   	0x04
#define	PAREN   	0x08
#define	PAREVN  	0x10
#define	PARMARK 	0x20
#define	SNDBRK  	0x40
#define	EFRACCESS	0xBF	/* magic value for 16650 EFR access */

#define	BITS5		0x00	/* 5 bits per char */
#define	BITS6		0x01	/* 6 bits per char */
#define	BITS7		0x02	/* 7 bits per char */
#define	BITS8		0x03	/* 8 bits per char */

/* Line Status Register */
#define	RCA		0x01	/* data ready */
#define	OVRRUN		0x02	/* overrun error */
#define	PARERR		0x04	/* parity error */
#define	FRMERR		0x08	/* framing error */
#define	BRKDET  	0x10	/* a break has arrived */
#define	XHRE		0x20	/* tx hold reg is now empty */
#define	XSRE		0x40	/* tx shift reg is now empty */
#define	RFBE		0x80	/* rx FIFO Buffer error */

/* Interrupt Id Regisger */
#define	MSTATUS		0x00	/* modem status changed */
#define	NOINTERRUPT	0x01	/* no interrupt pending */
#define	TxRDY		0x02	/* Transmitter Holding Register Empty */
#define	RxRDY		0x04	/* Receiver Data Available */
#define	FFTMOUT 	0x0c	/* FIFO timeout - 16550AF */
#define	RSTATUS 	0x06	/* Receiver Line Status */

/* Interrupt Enable Register */
#define	RIEN		0x01	/* Received Data Ready */
#define	TIEN		0x02	/* Tx Hold Register Empty */
#define	SIEN		0x04	/* Receiver Line Status */
#define	MIEN		0x08	/* Modem Status */

/* Modem Control Register */
#define	DTR		0x01	/* Data Terminal Ready */
#define	RTS		0x02	/* Request To Send */
#define	OUT1		0x04	/* Aux output - not used */
#define	OUT2		0x08	/* turns intr to 386 on/off */
#define	ASY_LOOP	0x10	/* loopback for diagnostics */

/* Modem Status Register */
#define	DCTS		0x01	/* Delta Clear To Send */
#define	DDSR		0x02	/* Delta Data Set Ready */
#define	DRI		0x04	/* Trail Edge Ring Indicator */
#define	DDCD		0x08	/* Delta Data Carrier Detect */
#define	CTS		0x10	/* Clear To Send */
#define	DSR		0x20	/* Data Set Ready */
#define	RI		0x40	/* Ring Indicator */
#define	DCD		0x80	/* Data Carrier Detect */

#define	DELTAS(x)	((x)&(DCTS|DDSR|DRI|DDCD))
#define	STATES(x)	((x)&(CTS|DSR|RI|DCD))

/* flags for FCR (FIFO Control register) */
#define	FIFO_OFF	0x00	/* fifo disabled */
#define	FIFO_ON		0x01	/* fifo enabled */
#define	FIFORXFLSH	0x02	/* flush receiver FIFO */
#define	FIFOTXFLSH	0x04	/* flush transmitter FIFO */
#define	FIFODMA		0x08	/* DMA mode 1 */
#define	FIFOEXTRA1	0x10	/* Longer fifos on some 16650's */
#define	FIFOEXTRA2	0x20	/* Longer fifos on some 16650's and 16750 */
#define	FIFO_TRIG_1	0x00	/* 1 byte trigger level */
#define	FIFO_TRIG_4	0x40	/* 4 byte trigger level */
#define	FIFO_TRIG_8	0x80	/* 8 byte trigger level */
#define	FIFO_TRIG_14	0xC0	/* 14 byte trigger level */

/* Serial in/out requests */

#define	OVERRUN		040000
#define	FRERROR		020000
#define	PERROR		010000
#define	S_ERRORS	(PERROR|OVERRUN|FRERROR)

/* EFR - Enhanced feature register for 16650 */
#define	ENHENABLE	0x10

/* SCR - scratch register */
#define	SCRTEST		0x5a	/* arbritrary value for testing SCR register */

/*
 * Ring buffer and async line management definitions.
 */
#define	RINGBITS	16		/* # of bits in ring ptrs */
#define	RINGSIZE	(1<<RINGBITS)   /* size of ring */
#define	RINGMASK	(RINGSIZE-1)
#define	RINGFRAC	12		/* fraction of ring to force flush */

#define	RING_INIT(ap)  ((ap)->async_rput = (ap)->async_rget = 0)
#define	RING_CNT(ap)   (((ap)->async_rput >= (ap)->async_rget) ? \
	((ap)->async_rput - (ap)->async_rget):\
	((0x10000 - (ap)->async_rget) + (ap)->async_rput))
#define	RING_FRAC(ap)  ((int)RING_CNT(ap) >= (int)(RINGSIZE/RINGFRAC))
#define	RING_POK(ap, n) ((int)RING_CNT(ap) < (int)(RINGSIZE-(n)))
#define	RING_PUT(ap, c) \
	((ap)->async_ring[(ap)->async_rput++ & RINGMASK] =  (uchar_t)(c))
#define	RING_UNPUT(ap) ((ap)->async_rput--)
#define	RING_GOK(ap, n) ((int)RING_CNT(ap) >= (int)(n))
#define	RING_GET(ap)   ((ap)->async_ring[(ap)->async_rget++ & RINGMASK])
#define	RING_EAT(ap, n) ((ap)->async_rget += (n))
#define	RING_MARK(ap, c, s) \
	((ap)->async_ring[(ap)->async_rput++ & RINGMASK] = ((uchar_t)(c)|(s)))
#define	RING_UNMARK(ap) \
	((ap)->async_ring[((ap)->async_rget) & RINGMASK] &= ~S_ERRORS)
#define	RING_ERR(ap, c) \
	((ap)->async_ring[((ap)->async_rget) & RINGMASK] & (c))

/*
 * Asy tracing macros.  These are a bit similar to some macros in sys/vtrace.h .
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

/*
 * Hardware channel common data. One structure per port.
 * Each of the fields in this structure is required to be protected by a
 * mutex lock at the highest priority at which it can be altered.
 * The asy_flags, and asy_next fields can be altered by interrupt
 * handling code that must be protected by the mutex whose handle is
 * stored in asy_excl_hi.  All others can be protected by the asy_excl
 * mutex, which is lower priority and adaptive.
 */

struct asycom {
	int		asy_flags;	/* random flags  */
					/* protected by asy_excl_hi lock */
	uint_t		asy_hwtype;	/* HW type: ASY16550A, etc. */
	uint_t		asy_use_fifo;	/* HW FIFO use it or not ?? */
	uint_t		asy_fifo_buf;	/* With FIFO = 16, otherwise = 1 */
	uint_t		asy_flags2;	/* flags which don't change, no lock */
	uint8_t		*asy_ioaddr;	/* i/o address of ASY port */
	struct asyncline *asy_priv;	/* protocol private data -- asyncline */
	dev_info_t	*asy_dip;	/* dev_info */
	int		asy_unit;	/* which port */
	ddi_iblock_cookie_t asy_iblock;
	kmutex_t	asy_excl;	/* asy adaptive mutex */
	kmutex_t	asy_excl_hi;	/* asy spinlock mutex */
	kmutex_t	asy_soft_lock;	/* soft lock for guarding softpend. */
	int		asysoftpend;	/* Flag indicating soft int pending. */
	ddi_softintr_t	asy_softintr_id;
	ddi_iblock_cookie_t asy_soft_iblock;

	/*
	 * The asy_soft_sr mutex should only be taken by the soft interrupt
	 * handler and the driver DDI_SUSPEND/DDI_RESUME code.  It
	 * shouldn't be taken by any code that may get called indirectly
	 * by the soft interrupt handler (e.g. as a result of a put or
	 * putnext call).
	 */
	kmutex_t	asy_soft_sr;	/* soft int suspend/resume mutex */
	uchar_t		asy_msr;	/* saved modem status */
	uchar_t		asy_mcr;	/* soft carrier bits */
	uchar_t		asy_lcr;	/* console lcr bits */
	uchar_t		asy_bidx;	/* console baud rate index */
	tcflag_t	asy_cflag;	/* console mode bits */
	struct cons_polledio	polledio;	/* polled I/O functions */
	ddi_acc_handle_t	asy_iohandle;	/* Data access handle */
	tcflag_t	asy_ocflag;	/* old console mode bits */
	uchar_t		asy_com_port;	/* COM port number, or zero */
	uchar_t		asy_fifor;	/* FIFOR register setting */
#ifdef DEBUG
	int		asy_msint_cnt;	/* number of times in async_msint */
#endif
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
	kcondvar_t	async_ops_cv;	/* condition variable for async_ops */
	dev_t		async_dev;	/* device major/minor numbers */
	mblk_t		*async_xmitblk;	/* transmit: active msg block */
	struct asycom	*async_common;	/* device common data */
	tty_common_t 	async_ttycommon; /* tty driver common data */
	bufcall_id_t	async_wbufcid;	/* id for pending write-side bufcall */
	size_t		async_wbufcds;	/* Buffer size requested in bufcall */
	timeout_id_t	async_polltid;	/* softint poll timeout id */
	timeout_id_t    async_dtrtid;   /* delaying DTR turn on */
	timeout_id_t    async_utbrktid; /* hold minimum untimed break time id */

	/*
	 * The following fields are protected by the asy_excl_hi lock.
	 * Some, such as async_flowc, are set only at the base level and
	 * cleared (without the lock) only by the interrupt level.
	 */
	uchar_t		*async_optr;	/* output pointer */
	int		async_ocnt;	/* output count */
	uint_t		async_rput;	/* producing pointer for input */
	uint_t		async_rget;	/* consuming pointer for input */

	/*
	 * Each character stuffed into the ring has two bytes associated
	 * with it.  The first byte is used to indicate special conditions
	 * and the second byte is the actual data.  The ring buffer
	 * needs to be defined as ushort_t to accomodate this.
	 */
	ushort_t	async_ring[RINGSIZE];

	short		async_break;	/* break count */
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
	timeout_id_t	async_timer;	/* close drain progress timer */

	mblk_t		*async_suspqf;	/* front of suspend queue */
	mblk_t		*async_suspqb;	/* back of suspend queue */
	int		async_ops;	/* active operations counter */
};

/* definitions for async_flags field */
#define	ASYNC_EXCL_OPEN	 0x10000000	/* exclusive open */
#define	ASYNC_WOPEN	 0x00000001	/* waiting for open to complete */
#define	ASYNC_ISOPEN	 0x00000002	/* open is complete */
#define	ASYNC_OUT	 0x00000004	/* line being used for dialout */
#define	ASYNC_CARR_ON	 0x00000008	/* carrier on last time we looked */
#define	ASYNC_STOPPED	 0x00000010	/* output is stopped */
#define	ASYNC_DELAY	 0x00000020	/* waiting for delay to finish */
#define	ASYNC_BREAK	 0x00000040	/* waiting for break to finish */
#define	ASYNC_BUSY	 0x00000080	/* waiting for transmission to finish */
#define	ASYNC_DRAINING	 0x00000100	/* waiting for output to drain */
#define	ASYNC_SERVICEIMM 0x00000200	/* queue soft interrupt as soon as */
#define	ASYNC_HW_IN_FLOW 0x00000400	/* input flow control in effect */
#define	ASYNC_HW_OUT_FLW 0x00000800	/* output flow control in effect */
#define	ASYNC_PROGRESS	 0x00001000	/* made progress on output effort */
#define	ASYNC_CLOSING	 0x00002000	/* processing close on stream */
#define	ASYNC_OUT_SUSPEND 0x00004000    /* waiting for TIOCSBRK to finish */
#define	ASYNC_HOLD_UTBRK 0x00008000	/* waiting for untimed break hold */
					/* the minimum time */
#define	ASYNC_DTR_DELAY  0x00010000	/* delaying DTR turn on */
#define	ASYNC_SW_IN_FLOW 0x00020000	/* sw input flow control in effect */
#define	ASYNC_SW_OUT_FLW 0x00040000	/* sw output flow control in effect */
#define	ASYNC_SW_IN_NEEDED 0x00080000	/* sw input flow control char is */
					/* needed to be sent */
#define	ASYNC_OUT_FLW_RESUME 0x00100000 /* output need to be resumed */
					/* because of transition of flow */
					/* control from stop to start */
#define	ASYNC_DDI_SUSPENDED  0x00200000	/* suspended by DDI */
#define	ASYNC_RESUME_BUFCALL 0x00400000	/* call bufcall when resumed by DDI */

/* asy_hwtype definitions */
#define	ASY8250A	0x2		/* 8250A or 16450 */
#define	ASY16550	0x3		/* broken FIFO which must not be used */
#define	ASY16550A	0x4		/* usable FIFO */
#define	ASY16650	0x5
#define	ASY16750	0x6

/* definitions for asy_flags field */
#define	ASY_NEEDSOFT	0x00000001
#define	ASY_DOINGSOFT	0x00000002
#define	ASY_PPS		0x00000004
#define	ASY_PPS_EDGE	0x00000008
#define	ASY_DOINGSOFT_RETRY	0x00000010
#define	ASY_RTS_DTR_OFF	0x00000020
#define	ASY_IGNORE_CD	0x00000040
#define	ASY_CONSOLE	0x00000080
#define	ASY_DDI_SUSPENDED	0x00000100 /* suspended by DDI */

/* definitions for asy_flags2 field */
#define	ASY2_NO_LOOPBACK 0x00000001	/* Device doesn't support loopback */

/* definitions for async_inflow_source field in struct asyncline */
#define	IN_FLOW_NULL	0x00000000
#define	IN_FLOW_RINGBUFF	0x00000001
#define	IN_FLOW_STREAMS	0x00000002
#define	IN_FLOW_USER	0x00000004

/*
 * OUTLINE defines the high-order flag bit in the minor device number that
 * controls use of a tty line for dialin and dialout simultaneously.
 */
#ifdef _LP64
#define	OUTLINE		(1 << (NBITSMINOR32 - 1))
#else
#define	OUTLINE		(1 << (NBITSMINOR - 1))
#endif
#define	UNIT(x)		(getminor(x) & ~OUTLINE)

/*
 * ASYSETSOFT macro to pend a soft interrupt if one isn't already pending.
 */

#define	ASYSETSOFT(asy)	{			\
	if (mutex_tryenter(&asy->asy_soft_lock)) {	\
		asy->asy_flags |= ASY_NEEDSOFT;		\
		if (!asy->asysoftpend) {		\
			asy->asysoftpend = 1;		\
			mutex_exit(&asy->asy_soft_lock);	\
			ddi_trigger_softintr(asy->asy_softintr_id);	\
		}					\
		else					\
			mutex_exit(&asy->asy_soft_lock);	\
	}							\
}

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ASY_H */
