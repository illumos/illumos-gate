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
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2023 Oxide Computer Company
 * Copyright 2024 Hans Rosenfeld
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
 * asy_hwtype definitions
 *
 * W.r.t the supported device registers, the 16650 actually a superset of the
 * 16750, hence the ordering.
 */
#define	ASY_8250A	0x00008250	/* 8250A or 16450 */
#define	ASY_16550	0x10016550	/* broken FIFO which must not be used */
#define	ASY_16550A	0x20016551	/* usable FIFO */
#define	ASY_16750	0x30016750	/* 64 byte FIFO, auto flow control */
#define	ASY_16650	0x40016650	/* 32 byte FIFO, auto flow control */
#define	ASY_16950	0x50016950	/* 128 byte FIFO, auto flow control */
#define	ASY_MAXCHIP	ASY_16950

/*
 * Definitions for INS8250 / 16550  chips
 */
typedef enum {
	ASY_ILLEGAL = 0,
	/* 8250 / 16450 / 16550 registers */
	ASY_THR,		/* Transmitter Holding Register	(W) */
	ASY_RHR,		/* Receiver Holding Register	(R) */
	ASY_IER,		/* Interrupt Enable Register	(R/W) */
	ASY_FCR,		/* FIFO Control Register	(W) */
	ASY_ISR,		/* Interrupt Status Register	(R) */
	ASY_LCR,		/* Line Control Register	(R/W) */
	ASY_MCR,		/* Modem Control Register	(R/W) */
	ASY_LSR,		/* Line Status Register		(R) */
	ASY_MSR,		/* Modem Status Register	(R) */
	ASY_SPR,		/* Scratch Pad Register		(R/W) */
	ASY_DLL,		/* Divisor Latch Low		(R/W) */
	ASY_DLH,		/* Divisor Latch High		(R/W) */

	/* 16750 extended register */
	ASY_EFR,		/* Extended Feature Register	(R/W) */

	/* 16650 extended registers */
	ASY_XON1,		/* XON Character 1		(R/W) */
	ASY_XON2,		/* XON Character 2		(R/W) */
	ASY_XOFF1,		/* XOFF Character 1		(R/W) */
	ASY_XOFF2,		/* XOFF Character 2		(R/W) */

	/* 16950 additional registers */
	ASY_ASR,		/* Additional Status Register	(R/W) */
	ASY_RFL,		/* Receiver FIFO Length		(R/W) */
	ASY_TFL,		/* Transmitter FIFO Length	(R/W) */
	ASY_ICR,		/* Indexed Control Register	(R/W) */

	/* 16950 indexed registers */
	ASY_ACR,		/* Additional Control Register  (R/W) */
	ASY_CPR,		/* Clock Prescaler Register	(R/W) */
	ASY_TCR,		/* Times Clock Register		(R/W) */
	ASY_CKS,		/* Clock Select Register	(R/W) */
	ASY_TTL,		/* Transmitter Trigger Level	(R/W) */
	ASY_RTL,		/* Receiver Trigger Level	(R/W) */
	ASY_FCL,		/* Flow Control Low-Level	(R/W) */
	ASY_FCH,		/* Flow Control High-Level	(R/W) */
	ASY_ID1,		/* Device Identification 1	(R) */
	ASY_ID2,		/* Device Identification 2	(R) */
	ASY_ID3,		/* Device Identification 3	(R) */
	ASY_REV,		/* Device Revision		(R) */
	ASY_CSR,		/* Channel Software Reset	(W) */
	ASY_NMR,		/* Nine-Bit Mode Register	(R/W) */

	ASY_NREG,
} asy_reg_t;

/*
 * INTEL 8210-A/B & 16450/16550 Registers Structure.
 */

/* Interrupt Enable Register */
#define	ASY_IER_RIEN	0x01	/* Received Data Ready */
#define	ASY_IER_TIEN	0x02	/* Tx Hold Register Empty */
#define	ASY_IER_SIEN	0x04	/* Receiver Line Status */
#define	ASY_IER_MIEN	0x08	/* Modem Status */
#define	ASY_IER_ALL	\
	(ASY_IER_RIEN | ASY_IER_TIEN | ASY_IER_SIEN | ASY_IER_MIEN)

/* FIFO Control register */
#define	ASY_FCR_FIFO_EN	0x01	/* FIFOs enabled */
#define	ASY_FCR_RHR_FL	0x02	/* flush receiver FIFO */
#define	ASY_FCR_THR_FL	0x04	/* flush transmitter FIFO */
#define	ASY_FCR_DMA	0x08	/* DMA mode 1 */
#define	ASY_FCR_THR_TR0	0x10	/* transmitter trigger level bit 0 (16650) */
#define	ASY_FCR_THR_TR1	0x20	/* transmitter trigger level bit 1 (16650) */
#define	ASY_FCR_FIFO64	0x20	/* 64 byte FIFO enable (16750) */
#define	ASY_FCR_RHR_TR0	0x40	/* receiver trigger level bit 0 */
#define	ASY_FCR_RHR_TR1	0x80	/* receiver trigger level bit 1 */

/* 16550 receiver trigger levels */
#define	ASY_FCR_RHR_TRIG_1	0		/*  1 byte RX trigger level */
#define	ASY_FCR_RHR_TRIG_4	ASY_FCR_RHR_TR0	/*  4 byte RX trigger level */
#define	ASY_FCR_RHR_TRIG_8	ASY_FCR_RHR_TR1	/*  8 byte RX trigger level */
#define	ASY_FCR_RHR_TRIG_14	\
	(ASY_FCR_THR_TR0 | ASY_FCR_THR_TR1)	/* 14 byte RX trigger level */

/* 16650 transmitter trigger levels */
#define	ASY_FCR_THR_TRIG_16	0		/* 16 byte TX trigger level */
#define	ASY_FCR_THR_TRIG_8	ASY_FCR_THR_TR0	/*  8 byte TX trigger level */
#define	ASY_FCR_THR_TRIG_24	ASY_FCR_THR_TR1	/* 24 byte TX trigger level */
#define	ASY_FCR_THR_TRIG_30	\
	(ASY_FCR_THR_TR0 | ASY_FCR_THR_TR1)	/* 30 byte TX trigger level */

#define	ASY_FCR_FIFO_OFF 0	/* FIFOs disabled */

/* Interrupt Status Register */
#define	ASY_ISR_NOINTR	0x01	/* no interrupt pending */
#define	ASY_ISR_MASK	0x0e	/* interrupt identification mask */
#define	ASY_ISR_EMASK	0x3e	/* interrupt id mask when EFR[4] = 1 (16650) */

#define	ASY_ISR_FIFO64	0x20	/* 64 byte FIFOs enabled (16750) */
#define	ASY_ISR_FIFOEN	0xc0	/* FIFOs enabled (16550A and up) */

#define	ASY_ISR_ID_RLST	0x06	/* Receiver Line Status */
#define	ASY_ISR_ID_RDA	0x04	/* Receiver Data Available */
#define	ASY_ISR_ID_TMO	0x0c	/* Character timeout (16550A and up) */
#define	ASY_ISR_ID_THRE	0x02	/* Transmitter Holding Register Empty */
#define	ASY_ISR_ID_MST	0x00	/* Modem Status changed */
#define	ASY_ISR_ID_XOFF	0x10	/* Received XOFF / special character (16650) */
#define	ASY_ISR_ID_RCTS	0x20	/* RTS/CTS changed (16650) */

/* Line Control Register */
#define	ASY_LCR_WLS0	0x01	/* word length select bit 0 */
#define	ASY_LCR_WLS1	0x02	/* word length select bit 2 */
#define	ASY_LCR_STB	0x04	/* number of stop bits */
#define	ASY_LCR_PEN	0x08	/* parity enable */
#define	ASY_LCR_EPS	0x10	/* even parity select */
#define	ASY_LCR_SPS	0x20	/* stick parity select */
#define	ASY_LCR_SETBRK	0x40	/* break key */
#define	ASY_LCR_DLAB	0x80	/* divisor latch access bit */

#define	ASY_LCR_STOP1	0x00
#define	ASY_LCR_STOP2	ASY_LCR_STB

#define	ASY_LCR_EFRACCESS	0xBF	/* magic value for 16650 EFR access */

#define	ASY_LCR_BITS5	0x00				/* 5 bits per char */
#define	ASY_LCR_BITS6	ASY_LCR_WLS0			/* 6 bits per char */
#define	ASY_LCR_BITS7	ASY_LCR_WLS1			/* 7 bits per char */
#define	ASY_LCR_BITS8	(ASY_LCR_WLS0 | ASY_LCR_WLS1)	/* 8 bits per char */

/* Modem Control Register */
#define	ASY_MCR_DTR	0x01	/* Data Terminal Ready */
#define	ASY_MCR_RTS	0x02	/* Request To Send */
#define	ASY_MCR_OUT1	0x04	/* Aux output - not used */
#define	ASY_MCR_OUT2	0x08	/* turns intr to 386 on/off */
#define	ASY_MCR_LOOP	0x10	/* loopback for diagnostics */

#define	ASY_MCR_LOOPBACK	\
	(ASY_MCR_DTR | ASY_MCR_RTS | ASY_MCR_OUT1 | ASY_MCR_OUT2 | ASY_MCR_LOOP)

/* Line Status Register */
#define	ASY_LSR_DR	0x01	/* data ready */
#define	ASY_LSR_OE	0x02	/* overrun error */
#define	ASY_LSR_PE	0x04	/* parity error */
#define	ASY_LSR_FE	0x08	/* framing error */
#define	ASY_LSR_BI	0x10	/* break interrupt */
#define	ASY_LSR_THRE	0x20	/* transmitter holding register empty */
#define	ASY_LSR_TEMT	0x40	/* transmitter empty (THR + TSR empty) */
#define	ASY_LSR_DE	0x80	/* Receiver FIFO data error */

#define	ASY_LSR_ERRORS	\
	(ASY_LSR_OE | ASY_LSR_PE | ASY_LSR_FE | ASY_LSR_BI)

/* Modem Status Register */
#define	ASY_MSR_DCTS	0x01	/* Delta Clear To Send */
#define	ASY_MSR_DDSR	0x02	/* Delta Data Set Ready */
#define	ASY_MSR_TERI	0x04	/* Trailing Edge Ring Indicator */
#define	ASY_MSR_DDCD	0x08	/* Delta Data Carrier Detect */
#define	ASY_MSR_CTS	0x10	/* Clear To Send */
#define	ASY_MSR_DSR	0x20	/* Data Set Ready */
#define	ASY_MSR_RI	0x40	/* Ring Indicator */
#define	ASY_MSR_DCD	0x80	/* Data Carrier Detect */

#define	ASY_MSR_DELTAS(x)	\
	((x) & (ASY_MSR_DCTS | ASY_MSR_DDSR | ASY_MSR_TERI | ASY_MSR_DDCD))
#define	ASY_MSR_STATES(x)	\
	((x) & (ASY_MSR_CTS | ASY_MSR_DSR | ASY_MSR_RI | ASY_MSR_DCD))

/* Scratch Pad Register */
#define	ASY_SPR_TEST	0x5a	/* arbritrary value for testing SPR */

/* Extended Feature Register (16650) */
#define	ASY_EFR_ENH_EN	0x10	/* IER[4:7], ISR[4,5], FCR[4,5], MCR[5:7] */

/* Additional Status Register (16950) */
#define	ASY_ASR_TD	0x01	/* Transmitter Disabled */
#define	ASY_ASR_RTD	0x02	/* Remote Transmitter Disabled */
#define	ASY_ASR_RTS	0x04	/* RTS status */
#define	ASY_ASR_DTR	0x08	/* DTR status */
#define	ASY_ASR_SCD	0x10	/* Special Character detected */
#define	ASY_ASR_FIFOSEL	0x20	/* FIFOSEL pin status */
#define	ASY_ASR_FIFOSZ	0x40	/* FIFO size */
#define	ASY_ASR_TI	0x80	/* Transmitter Idle */

/* Additional Control Register (16950) */
#define	ASY_ACR_RD	0x01	/* Receiver Disable */
#define	ASY_ACR_TD	0x02	/* Transmitter Disable */
#define	ASY_ACR_DSR	0x04	/* Automatic DSR flow control */
#define	ASY_ACR_DTR	0x18	/* DTR line configuration */
#define	ASY_ACR_TRIG	0x20	/* 950 mode trigger levels enable */
#define	ASY_ACR_ICR	0x40	/* ICR read enable */
#define	ASY_ACR_ASR	0x80	/* Additional Status Enable */

#define	ASY_ACR_DTR_NORM	0x00	/* DTR normal (compatible) */
#define	ASY_ACR_DTR_FLOW	0x08	/* DTR used for flow-control */
#define	ASY_ACR_DTR_RS485_LOW	0x10	/* DTR drives ext. RS485 buffer low */
#define	ASY_ACR_DTR_RS485_HIGH	0x18	/* DTR drives ext. RS485 buffer high */


/* Serial in/out requests */

#define	OVERRUN		040000
#define	FRERROR		020000
#define	PERROR		010000
#define	S_ERRORS	(PERROR|OVERRUN|FRERROR)

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

/* definitions for asy_progress */
typedef enum {
	ASY_PROGRESS_REGS =	0x01,
	ASY_PROGRESS_SOFTINT =	0x02,
	ASY_PROGRESS_INT =	0x04,
	ASY_PROGRESS_MUTEX =	0x08,
	ASY_PROGRESS_ASYNC =	0x10,
	ASY_PROGRESS_MINOR =	0x20
} asy_progress_t;

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
#ifdef DEBUG
	int		asy_debug;	/* per-instance debug flags */
#endif
	asy_progress_t	asy_progress;	/* attach progress */
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
	kmutex_t	asy_excl;	/* asy adaptive mutex */
	kmutex_t	asy_excl_hi;	/* asy spinlock mutex */
	kmutex_t	asy_soft_lock;	/* soft lock for guarding softpend. */
	int		asysoftpend;	/* Flag indicating soft int pending. */

	ddi_softint_handle_t asy_soft_inth;
	uint_t		asy_soft_intr_pri;

	ddi_intr_handle_t *asy_inth;
	size_t		asy_inth_sz;
	uint_t		asy_intr_pri;
	int		asy_intr_cnt;
	int		asy_intr_cap;
	int		asy_intr_type;
	int		asy_intr_types;

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
	uint8_t		asy_acr;	/* 16950 additional control register */
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
	tty_common_t	async_ttycommon; /* tty driver common data */
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

/* This corresponds to DDI_SOFTINT_MED used by the old softint routines. */
#define	ASY_SOFT_INT_PRI	6


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ASY_H */
