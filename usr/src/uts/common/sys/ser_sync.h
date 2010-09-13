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
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SER_SYNC_H
#define	_SYS_SER_SYNC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Initial port setup parameters for sync lines
 */

#include <sys/stream.h>
#include <sys/time_impl.h>
#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	zIOC	('z' << 8)

#define	S_IOCGETMODE	(zIOC|01)	/* return struct scc_mode */
#define	S_IOCSETMODE	(zIOC|02)	/* set SCC from struct scc_mode */
#define	S_IOCGETSTATS	(zIOC|03)	/* return sync data stats */
#define	S_IOCCLRSTATS	(zIOC|04)	/* clear sync stats */
#define	S_IOCGETSPEED	(zIOC|05)	/* return int baudrate */
#define	S_IOCGETMRU	(zIOC|06)	/* return int max receive unit */
#define	S_IOCSETMRU	(zIOC|07)	/* set max receive unit */
#define	S_IOCGETMTU	(zIOC|010)	/* return int max transmission unit */
#define	S_IOCSETMTU	(zIOC|011)	/* set max transmission unit */
#define	S_IOCGETMCTL	(zIOC|012)	/* return current CD/CTS state */
#define	S_IOCSETDTR	(zIOC|013)	/* Drive DTR signal */

/* reason codes for IOCSETMODE */
#define	SMERR_TXC	0x0001		/* transmit clock source not valid */
#define	SMERR_RXC	0x0002		/* receive clock source not valid */
#define	SMERR_IFLAGS	0x0004		/* inversion flags not valid */
#define	SMERR_HDX	0x0008		/* CONN_HDX set without CONN_IBM */
#define	SMERR_MPT	0x0010		/* CONN_MPT set without CONN_IBM */
#define	SMERR_LPBKS	0x0020		/* invalid loopback/echo combination */
#define	SMERR_BAUDRATE	0x0040		/* baudrate translates to 0 timeconst */
#define	SMERR_PLL	0x0080		/* PLL set with BRG or w/o NRZI */

/*
 * Definitions for modes of operations of
 * synchronous lines, both RS-232 and RS-449
 */
struct scc_mode {
	char	sm_txclock;	/* enum - transmit clock sources */
	char	sm_rxclock;	/* enum - receive clock sources */
	char    sm_iflags;	/* data and clock invert flags: see hsparam.h */
	uchar_t	sm_config;	/* see CONN defines below */
	int	sm_baudrate;
	int	sm_retval;	/* SMERR codes go here, query with GETMODE */
};

/*
 * defines for txclock
 */
#define	TXC_IS_TXC	0	/* use incoming transmit clock */
#define	TXC_IS_RXC	1	/* use incoming receive clock */
#define	TXC_IS_BAUD	2	/* use baud rate generator */
#define	TXC_IS_PLL	3	/* use phase-lock loop output */

/*
 * defines for rxclock
 */
#define	RXC_IS_RXC	0	/* use incoming receive clock */
#define	RXC_IS_TXC	1	/* use incoming transmit clock */
#define	RXC_IS_BAUD	2	/* use baud rate - only good for loopback */
#define	RXC_IS_PLL	3	/* use phase-lock loop */

/*
 * defines for clock/data inversion: from hsparam.h
 */
#define	TXC_IS_SYSCLK	4
#define	RXC_IS_SYSCLK	4
#define	TXC_IS_INVERT	5
#define	RXC_IS_INVERT	5
#define	TRXD_NO_INVERT	0
#define	RXD_IS_INVERT	1
#define	TXD_IS_INVERT	2
#define	TRXD_IS_INVERT	3

/*
 * defines for config
 */
#define	CONN_HDX    0x01    /* half-duplex if set, else full-duplex */
#define	CONN_MPT    0x02    /* multipoint if set, else point-point */
#define	CONN_IBM    0x04    /* set up in IBM-SDLC mode */
#define	CONN_SIGNAL 0x08    /* report modem signal changes asynchronously */
#define	CONN_NRZI   0x10    /* boolean - use NRZI */
#define	CONN_LPBK   0x20    /* do internal loopback */
#define	CONN_ECHO   0x40    /* place in auto echo mode */

struct sl_status {
	int		type;
	int		status;
	timestruc_t	tstamp;
};

#if defined(_SYSCALL32)

struct sl_status32 {
	int32_t		type;
	int32_t		status;
	timestruc32_t	tstamp;
};

#endif	/* _SYSCALL32 */

/*
 * defines for type field in sl_status
 */
#define	SLS_MDMSTAT	0x01	/* Non-IBM modem line status change */
#define	SLS_LINKERR	0x02	/* IBM mode Link Error, usually modem line. */

/*
 * defines for status field in sl_status
 * DO NOT change the values for CS_(DCD|CTS)_(UP|DOWN)!!!
 */
#define	CS_DCD_DOWN   	0x08
#define	CS_DCD_UP   	0x0c
#define	CS_DCD_DROP   	0x10
#define	CS_CTS_DOWN	0x20
#define	CS_CTS_UP	0x30
#define	CS_CTS_DROP   	0x40
#define	CS_CTS_TO   	0x80
#define	CS_DCD		CS_DCD_DOWN
#define	CS_CTS		CS_CTS_DOWN

/*
 * Event statistics reported by hardware.
 */
struct sl_stats {
	int	ipack;		/* input packets */
	int	opack;		/* output packets */
	int	ichar;		/* input bytes */
	int	ochar;		/* output bytes */
	int	abort;		/* abort received */
	int	crc;		/* CRC error */
	int	cts;		/* CTS timeouts */
	int	dcd;		/* Carrier drops */
	int	overrun;	/* receiver overrun */
	int	underrun;	/* xmitter underrun */
	int	ierror;		/* input error (rxbad) */
	int	oerror;		/* output error (watchdog timeout) */
	int	nobuffers;	/* no active receive block available */
};



/*
 * Per-stream structure.  Each of these points to only one device instance,
 * but there may be more than one doing so.  If marked as ST_CLONE, it has
 * been opened throught the clone device, and cannot have the data path.
 */
struct ser_str {
	queue_t		*str_rq;	/* This stream's read queue */
	caddr_t		str_com;	/* Back pointer to device struct */
	int		str_inst;	/* Device instance (unit) number */
	int		str_state;	/* see below */
};

/*
 * Synchronous Protocol Private Data Structure
 */
#define	ZSH_MAX_RSTANDBY	6
#define	ZSH_RDONE_MAX		20
struct syncline {
	struct ser_str	sl_stream;	/* data path device points thru here */
	struct scc_mode	sl_mode;	/* clock, etc. modes */
	struct sl_stats	sl_st;		/* Data and error statistics */
	mblk_t		*sl_rhead;	/* receive: head of active message */
	mblk_t		*sl_ractb;	/* receive: active message block */
	mblk_t		*sl_rstandby[ZSH_MAX_RSTANDBY];
					/* receive: standby message blocks */
	mblk_t		*sl_xhead;	/* transmit: head of active message */
	mblk_t		*sl_xactb;	/* transmit: active message block */
	mblk_t		*sl_xstandby;	/* transmit: next available message */
	mblk_t		*sl_rdone[ZSH_RDONE_MAX];
					/* complete messages to be sent up */
	int		sl_rdone_wptr;
	int		sl_rdone_rptr;
	mblk_t		*sl_mstat;	/* most recent modem status change */
	bufcall_id_t	sl_bufcid;	/* pending bufcall ID */
	timeout_id_t	sl_wd_id;	/* watchdog timeout ID */
	int		sl_wd_count;	/* watchdog counter */
	int		sl_ocnt;	/* output message size */
	int		sl_mru;		/* Maximum Receive Unit */
	int		sl_bad_count_int;
	uchar_t		sl_rr0;		/* saved RR0 */
	uchar_t		sl_address;	/* station address */
	uchar_t		sl_txstate;	/* transmit state */
	uchar_t		sl_flags;	/* see below */
	uchar_t		sl_m_error;
	volatile uchar_t sl_soft_active; /*  */
};

/*
 * Bit definitions for sl_txstate.
 */
#define	TX_OFF		0x0		/* Not available */
#define	TX_IDLE		0x1		/* Initialized */
#define	TX_RTS		0x2		/* IBM: RTS up, okay to transmit */
#define	TX_ACTIVE	0x4		/* Transmission in progress */
#define	TX_CRC		0x8		/* Sent all Data */
#define	TX_FLAG		0x10		/* Sent CRC bytes */
#define	TX_LAST		0x20		/* End-Of-Frame, OK to start new msg */
#define	TX_ABORTED	0x40		/* Transmit was aborted */

/*
 * Bit definitions for sl_flags.
 */
#define	SF_FDXPTP	0x1	/* Full duplex AND Point-To-Point */
#define	SF_XMT_INPROG	0x2	/* Write queue is not empty */
#define	SF_LINKERR	0x4	/* Underrun or CTS/DCD drop */
#define	SF_FLUSH_WQ	0x8	/*  */
#define	SF_INITIALIZED	0x10	/* This channel programmed for this protocol */
#define	SF_PHONY	0x20	/* Dummy frame has been sent to close frame */
#define	SF_ZSH_START	0x40	/*  */
/*
 * Bit definitions for str_state.
 */
#define	STR_CLONE	1	/* This was opened thru clone device */

extern int hz;
#define	SIO_WATCHDOG_TICK	(2 * hz)	/* Two second timeout */
#define	SIO_WATCHDOG_ON		(zss->sl_wd_id > 0)	/* Is it on? */


#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_SER_SYNC_H */
