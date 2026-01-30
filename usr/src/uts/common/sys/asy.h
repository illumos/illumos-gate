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
 * Copyright 2026 Oxide Computer Company
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
typedef enum {
	ASY_IER_RIEN = 1 << 0,	/* Received Data Ready */
	ASY_IER_TIEN = 1 << 1,	/* Tx Hold Register Empty */
	ASY_IER_SIEN = 1 << 2,	/* Receiver Line Status */
	ASY_IER_MIEN = 1 << 3	/* Modem Status */
} asy_ier_t;

#define	ASY_IER_ALL	\
	(ASY_IER_RIEN | ASY_IER_TIEN | ASY_IER_SIEN | ASY_IER_MIEN)

/* FIFO Control register */
typedef enum {
	ASY_FCR_FIFO_EN =	1 << 0,	/* FIFOs enabled */
	ASY_FCR_RHR_FL =	1 << 1,	/* flush receiver FIFO */
	ASY_FCR_THR_FL =	1 << 2,	/* flush transmitter FIFO */
	ASY_FCR_DMA =		1 << 3,	/* DMA mode 1 */
	ASY_FCR_THR_TR0 =	1 << 4,	/* xmit trigger level bit 0 (16650) */
	ASY_FCR_THR_TR1 =	1 << 5,	/* xmit trigger level bit 1 (16650) */
	ASY_FCR_RHR_TR0 =	1 << 6,	/* receiver trigger level bit 0 */
	ASY_FCR_RHR_TR1 =	1 << 7,	/* receiver trigger level bit 1 */
} asy_fcr_t;

#define	ASY_FCR_FIFO64		ASY_FCR_THR_TR1	/* 64 byte FIFO en (16750) */

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
typedef enum {
	ASY_LCR_WLS0 =	1 << 0,	/* word length select bit 0 */
	ASY_LCR_WLS1 =	1 << 1,	/* word length select bit 2 */
	ASY_LCR_STB =	1 << 2,	/* number of stop bits */
	ASY_LCR_PEN =	1 << 3,	/* parity enable */
	ASY_LCR_EPS =	1 << 4,	/* even parity select */
	ASY_LCR_SPS =	1 << 5,	/* stick parity select */
	ASY_LCR_SETBRK = 1 << 6, /* break key */
	ASY_LCR_DLAB =	1 << 7	/* divisor latch access bit */
} asy_lcr_t;

#define	ASY_LCR_STOP1	0x00
#define	ASY_LCR_STOP2	ASY_LCR_STB

#define	ASY_LCR_EFRACCESS	0xBF	/* magic value for 16650 EFR access */

#define	ASY_LCR_BITS5	0x00				/* 5 bits per char */
#define	ASY_LCR_BITS6	ASY_LCR_WLS0			/* 6 bits per char */
#define	ASY_LCR_BITS7	ASY_LCR_WLS1			/* 7 bits per char */
#define	ASY_LCR_BITS8	(ASY_LCR_WLS0 | ASY_LCR_WLS1)	/* 8 bits per char */

/* Modem Control Register */
typedef enum {
	ASY_MCR_DTR =	1 << 0,	/* Data Terminal Ready */
	ASY_MCR_RTS =	1 << 1,	/* Request To Send */
	ASY_MCR_OUT1 =	1 << 2,	/* Aux output - not used */
	ASY_MCR_OUT2 =	1 << 3,	/* turns intr to 386 on/off */
	ASY_MCR_LOOP =	1 << 4	/* loopback for diagnostics */
} asy_mcr_t;

#define	ASY_MCR_LOOPBACK	\
	(ASY_MCR_DTR | ASY_MCR_RTS | ASY_MCR_OUT1 | ASY_MCR_OUT2 | ASY_MCR_LOOP)

/* Line Status Register */
typedef enum {
	ASY_LSR_DR =	1 << 0,	/* data ready */
	ASY_LSR_OE =	1 << 1,	/* overrun error */
	ASY_LSR_PE =	1 << 2,	/* parity error */
	ASY_LSR_FE =	1 << 3,	/* framing error */
	ASY_LSR_BI =	1 << 4,	/* break interrupt */
	ASY_LSR_THRE =	1 << 5,	/* transmitter holding register empty */
	ASY_LSR_TEMT =	1 << 6,	/* transmitter empty (THR + TSR empty) */
	ASY_LSR_DE =	1 << 7	/* Receiver FIFO data error */
} asy_lsr_t;

#define	ASY_LSR_ERRORS	\
	(ASY_LSR_OE | ASY_LSR_PE | ASY_LSR_FE | ASY_LSR_BI)

/* Modem Status Register */
typedef enum {
	ASY_MSR_DCTS =	1 << 0,	/* Delta Clear To Send */
	ASY_MSR_DDSR =	1 << 1,	/* Delta Data Set Ready */
	ASY_MSR_TERI =	1 << 2,	/* Trailing Edge Ring Indicator */
	ASY_MSR_DDCD =	1 << 3,	/* Delta Data Carrier Detect */
	ASY_MSR_CTS =	1 << 4,	/* Clear To Send */
	ASY_MSR_DSR =	1 << 5,	/* Data Set Ready */
	ASY_MSR_RI =	1 << 6,	/* Ring Indicator */
	ASY_MSR_DCD =	1 << 7	/* Data Carrier Detect */
} asy_msr_t;

#define	ASY_MSR_DELTAS(x)	\
	((x) & (ASY_MSR_DCTS | ASY_MSR_DDSR | ASY_MSR_TERI | ASY_MSR_DDCD))
#define	ASY_MSR_STATES(x)	\
	((x) & (ASY_MSR_CTS | ASY_MSR_DSR | ASY_MSR_RI | ASY_MSR_DCD))

/* Scratch Pad Register */
#define	ASY_SPR_TEST	0x5a	/* arbritrary value for testing SPR */

/* Extended Feature Register (16650) */
#define	ASY_EFR_ENH_EN	0x10	/* IER[4:7], ISR[4,5], FCR[4,5], MCR[5:7] */

/* Additional Status Register (16950) */
typedef enum {
	ASY_ASR_TD =	1 << 0,	/* Transmitter Disabled */
	ASY_ASR_RTD =	1 << 1,	/* Remote Transmitter Disabled */
	ASY_ASR_RTS =	1 << 2,	/* RTS status */
	ASY_ASR_DTR =	1 << 3,	/* DTR status */
	ASY_ASR_SCD =	1 << 4,	/* Special Character detected */
	ASY_ASR_FIFOSEL = 1 << 5, /* FIFOSEL pin status */
	ASY_ASR_FIFOSZ = 1 << 6, /* FIFO size */
	ASY_ASR_TI =	1 << 7	/* Transmitter Idle */
} asy_16950_asr_t;

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

/* Clock Select Register (16950) */
#define	ASY_CKS_RCLK	0x00	/* RCLK pin drives receiver clock */
#define	ASY_CKS_RDSR	0x01	/* DSR pin drives receiver clock */
#define	ASY_CKS_RBDOUT	0x02	/* BDOUT pint drives receiver clock */
#define	ASY_CKS_RTCLK	0x03	/* transmitter clock drives receiver clock */

#define	ASY_CKS_BDO_DIS	0x04	/* Disable BDOUT pin */
#define	ASY_CKS_RCLK_1X	0x08	/* Receiver clock in isochronous 1x mode */

#define	ASY_CKS_DTR_NO	0x00	/* DTR pin defined by ACR[ASY_ACR_DTR] */
#define	ASY_CKS_DTR_T1X	0x10	/* Transmitter 1x clock on DTR pin */
#define	ASY_CKS_DTR_BDO	0x20	/* Baud rate generator output on DTR pin */

#define	ASY_CKS_TCLK_RI	0x40	/* External transmitter clock on RI pin */
#define	ASY_CKS_TCLK_1X	0x80	/* Transmitter clock in isochronous 1x mode */

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
	ASY_PROGRESS_REGS =	1 << 0,
	ASY_PROGRESS_SOFTINT =	1 << 1,
	ASY_PROGRESS_INT =	1 << 2,
	ASY_PROGRESS_MUTEX =	1 << 3,
	ASY_PROGRESS_ASYNC =	1 << 4,
	ASY_PROGRESS_MINOR =	1 << 5
} asy_progress_t;


/* definitions for asy_flags field */
typedef enum {
	ASY_NEEDSOFT =		1 << 0,
	ASY_DOINGSOFT =		1 << 1,
	ASY_PPS =		1 << 2,
	ASY_PPS_EDGE =		1 << 3,
	ASY_DOINGSOFT_RETRY =	1 << 4,
	ASY_RTS_DTR_OFF =	1 << 5,
	ASY_IGNORE_CD =		1 << 6,
	ASY_CONSOLE =		1 << 7,
	ASY_DDI_SUSPENDED =	1 << 8, /* suspended by DDI */
} asy_flags_t;

/* definitions for asy_flags2 field */
typedef enum {
	ASY2_NO_LOOPBACK = 1 << 0	/* Device doesn't support loopback */
} asy_flags2_t;

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
	asy_flags_t	asy_flags;	/* random flags  */
					/* protected by asy_excl_hi lock */
	uint_t		asy_hwtype;	/* HW type: ASY16550A, etc. */
	uint_t		asy_use_fifo;	/* HW FIFO use it or not ?? */
	uint_t		asy_fifo_buf;	/* With FIFO = 16, otherwise = 1 */
	asy_flags2_t	asy_flags2;	/* flags which don't change, no lock */
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

/* definitions for async_flags field */
typedef enum {
	ASYNC_EXCL_OPEN =	1 << 28, /* exclusive open */
	ASYNC_WOPEN =		1 << 0,  /* waiting for open to complete */
	ASYNC_ISOPEN =		1 << 1,  /* open is complete */
	ASYNC_OUT =		1 << 2,  /* line being used for dialout */
	ASYNC_CARR_ON =		1 << 3,  /* carrier on last time we looked */
	ASYNC_STOPPED =		1 << 4,  /* output is stopped */
	ASYNC_DELAY =		1 << 5,  /* waiting for delay to finish */
	ASYNC_BREAK =		1 << 6,  /* waiting for break to finish */
	ASYNC_BUSY =		1 << 7,  /* waiting for transmission finish */
	ASYNC_DRAINING =	1 << 8,  /* waiting for output to drain */
	ASYNC_SERVICEIMM =	1 << 9,  /* queue soft interrupt as soon as */
	ASYNC_HW_IN_FLOW =	1 << 10, /* input flow control in effect */
	ASYNC_HW_OUT_FLW =	1 << 11, /* output flow control in effect */
	ASYNC_PROGRESS =	1 << 12, /* made progress on output effort */
	ASYNC_CLOSING =		1 << 13, /* processing close on stream */
	ASYNC_OUT_SUSPEND =	1 << 14, /* waiting for TIOCSBRK to finish */
	ASYNC_HOLD_UTBRK =	1 << 15, /* waiting for untimed break hold */
					/* the minimum time */
	ASYNC_DTR_DELAY =	1 << 16, /* delaying DTR turn on */
	ASYNC_SW_IN_FLOW =	1 << 17, /* sw input flow control in effect */
	ASYNC_SW_OUT_FLW =	1 << 18, /* sw output flow control in effect */
	ASYNC_SW_IN_NEEDED =	1 << 19, /* sw input flow control char is */
					/* needed to be sent */
	ASYNC_OUT_FLW_RESUME =	1 << 20, /* output need to be resumed */
					/* because of transition of flow */
					/* control from stop to start */
	ASYNC_DDI_SUSPENDED =	1 << 21, /* suspended by DDI */
	ASYNC_RESUME_BUFCALL =	1 << 22  /* call bufcall when resumed by DDI */
} async_flags_t;

/* definitions for async_inflow_source field in struct asyncline */
typedef enum {
	IN_FLOW_NULL =		0 << 0,
	IN_FLOW_RINGBUFF =	1 << 0,
	IN_FLOW_STREAMS =	1 << 1,
	IN_FLOW_USER =		1 << 2
} async_inflow_t;

/*
 * Asychronous protocol private data structure for ASY.
 * Each of the fields in the structure is required to be protected by
 * the lower priority lock except the fields that are set only at
 * base level but cleared (with out lock) at interrupt level.
 */

struct asyncline {
	async_flags_t	async_flags;	/* random flags */
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
	async_inflow_t	async_inflow_source; /* input flow control type */

	/*
	 * This union presumably exists to support a change that happened some
	 * time in the distant past.  The two overrun fields are used as
	 * booleans; one imagines that the split between hardware and software
	 * overruns was made some time after the driver was initially written
	 * and that the earliest versions just had the single `async_overrun`
	 * field.
	 *
	 * By using the union, out-of-tree consumers could presumably still
	 * detect any type of overrun via testing the `async_overrun` field,
	 * which would _de facto_ combine the two, while the driver keeps
	 * finer-grained track of the specific kind of overrun.  Of course,
	 * this only works if consuming code treats any non-zero value as true,
	 * and does not compare against 1 specifically.
	 *
	 * It is unclear if this is still necessary.  One hopes that any such
	 * consumers, if they exist, neither assign through `async_overrun` nor
	 * look specifically for the value one to mean true.
	 */
	union {
		struct {
			uint8_t _hw;	/* overrun (hw) */
			uint8_t _sw;	/* overrun (sw) */
		} _a;
		uint16_t uover_overrun;
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
