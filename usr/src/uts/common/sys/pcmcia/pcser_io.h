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
 * Copyright (c) 1995,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PCSER_IO_H
#define	_PCSER_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for users of pcser devices.
 */

/*
 * Minor device number encoding:
 *
 *	o c s s | s s s s
 *
 *	o - set if this device is an outgoing serial line
 *	c - set if this device is a control device
 *	s - socket number of this device
 */

/*
 * Ioctl definitions - why 'd'?  why, for "defaults", of course
 *
 *	PCSER_DCONTROL -	sets/gets default parameters for any line
 *			flushes write queues for any line
 *			and a miscellany of other functions, read the man page
 *	PCSER_SDEFAULTS - sets default parameters for line that take effect on
 *			next open
 *	PCSER_GDEFAULTS - get default parameters (may not be active yet)
 */
#define	sIOC			('s'<<8)
#define	PCSER_DCONTROL		(sIOC|250)
#define	PCSER_SDEFAULTS	(sIOC|251)
#define	PCSER_GDEFAULTS	(sIOC|252)
#define	PCSER_GSTATS		(sIOC|255)

/*
 * we define this here so that it can be exported to users using the
 * serial ioctl()'s to manipulate line default parameters; if you
 * change this, the driver must be recompiled
 */
#define	PCSER_SILOSIZE	1024	/* size of (soft) rx silo in line struct */

/*
 * macro that returns 1 if parameter is out of range, used for range checking
 * on valued parameters passed to driver via pcser_defaults_t and ppc_params_t
 */
#define	FUNKY(v, min, max)	((v < min) || (v > max))

/*
 * fields of pcser_default_t structure
 *
 * flags for the serial lines in the pcser_line_t->flags member
 */
#define	DTR_ASSERT		0x0001	/* assert DTR on open */
#define	SOFT_CARR		0x0002	/* ignore CD input on open */
#define	PCSER_DTRCLOSE		0x0004	/* zs DTR close semantics if clear */
#define	PCSER_CFLOWFLUSH	0x0008	/* flush data in close if blocked */
#define	PCSER_CFLOWMSG		0x0010	/* display message in close */
#define	PCSER_INSTANTFLOW	0x0020	/* if s/w flow disabled, enable xmtr */
#define	PCSER_DTRFORCE		0x0040	/* force DTR always on */
#define	PCSER_IGNORE_CD_ON_OPEN	0x0080	/* ignore CD timeout on every open */
#define	PCSER_VALID_IO_INFO	0x0100	/* have valid IO infor from CIS */

/*
 * parameters for the serial lines. min and max values are listed.
 * if you put a strange value in, the ioctl will return an EINVAL and
 * no defaults will be changed
 */
#define	MIN_DRAIN_SIZE	4		/* min buf size in pcser_drainsilo() */
#define	MAX_DRAIN_SIZE	1024		/* max buf size in pcser_drainsilo() */
#define	MIN_HIWATER	2		/* min hiwater mark for Rx silo */
#define	MAX_HIWATER	(PCSER_SILOSIZE - 2)	/* max hiwater for Rx silo */
#define	MIN_LOWWATER	2			/* min lowwater for Rx silo */
#define	MAX_LOWWATER	((pcser_defaults->pcser_hiwater)-2) /* max lowwater */
#define	MIN_RTPR	1		/* min Rx timeout regtister value */
#define	MAX_RTPR	255		/* max Rx timeout regtister value */
#define	MIN_RX_FIFO	1		/* min value for Rx FIFO threshold */
#define	MAX_RX_FIFO	8		/* max value for Rx FIFO threshold */

#ifdef	XXXNODEFSXXX
/*
 * the structure that gets passed back and forth to deal with the defaults
 */
struct pcser_defaults_t {
	int		flags;		/* things like soft carrier, etc... */
	/* serial port Rx handler parameters */
	int		drain_size;	/* size of buf in pcser_drainsilo() */
	int		pcser_hiwater;	/* high water mark in CHECK_RTS() */
	int		pcser_lowwater;	/* low water mark in CHECK_RTS() */
	int		rtpr;		/* inter-character receive timer */
	int		rx_fifo_thld;	/* cd-180 RxFIFO threshold */
	struct termios	termios;	/* baud rates, parity, etc... */
	/* for the control device */
	int		line_no;	/* line number to operate on */
	int		op;		/* operation */
};

/*
 * op field return values for PCSER_GDEFAULTS, PCSER_DCONTROL(PCSER_CDEFGET)
 * and PCSER_DCONTROL(PCSER_SPARAM_GET)
 */
#define	PCSER_SERIAL	0x01		/* this is a serial line */
#define	PCSER_CNTRL	0x04		/* this is the control line */

/*
 * the op parameters, only written for the control device per board
 * used only with the PCSER_DCONTROL ioctl() and then only if the
 * device is the board control device (read the man page)
 *
 * PCSER_GDEFAULTS will return the type of line it's connected to
 * in the op field
 *
 * PCSER_DCONTROL(PCSER_CDEFGET) and PCSER_DCONTROL(PCSER_SPARAM_GET) will
 * return the type of line specified by the line_no field in
 * the op field
 *
 * PCSER_DCONTROL(PCSER_SPARAM_SET) and PCSER_DCONTROL(PCSER_SPARAM_GET) will
 * return an PCSER_NOTOPEN_ERR error if the referenced line is not open
 *
 * Note on PCSER_CFLUSH: set the line # that you want to flush in
 * the "line_no" field of the "pcser_defaults_t" struct that you
 * pass to PCSER_DCONTROL; if you want to flush the printer, set
 * the line number to 64 or use the PCSER_LP_SETLINE() macro
 *
 * PCSER_REGIOR, PCSER_REGIOW, PCSER_PPCREGR and PCSER_PPCREGW are designed
 * mostly for diagnostic use - don't try them unless you know what
 * you're doing; you can cause all sorts of problems like enabling
 * interrupts when they shouldn't be, resetting the cd180 and/or the
 * PPC and generally wreaking havoc with the whole system
 * to get register offsets for these, include <sbusdev/pcserreg.h>
 * for the diagnostic ops, specify the line number to operate on
 * as 0 (unless you want the passed line number to be loaded into
 * the cd180's CAR (channel address register) before each cd180
 * register access; if so, OR in PCSER_SETCAR to the op field)
 */
/* set another line's defaults */
#define	PCSER_CDEFSET		0x00000001
/* get another line's defaults */
#define	PCSER_CDEFGET		0x00000002
/* set serial port parameters immediately */
#define	PCSER_SPARAM_SET	0x00000004
/* get serial port parameters currently in use */
#define	PCSER_SPARAM_GET	0x00000008
/* flush a line's write queue */
#define	PCSER_CFLUSH		0x00008000
/* return if line is not open for PCSER_SPARAM_SET/PCSER_SPARAM_GET */
#define	PCSER_NOTOPEN_ERR	ESRCH

#endif	/* XXXNODEFSXXX */

/*
 * the pcser_stats_t struct is used for statistics gathering and monitoring
 *	driver performance of the serial lines (statistics gathering is
 *	not supported on the parallel line)
 */
struct pcser_stats_t {
	int		cmd;		/* command (see flags below) */
	int		qpunt;		/* punting in pcser_drainsilo */
	int		drain_timer;	/* posted a timer in pcser_drainsilo */
	int		no_canput;	/* canput failed in pcser_drainsilo */
	int		no_rcv_drain;	/* pcser_rcv no call pcser_drainsilo */
	int		pcser_drain;	/* PCSER_DRAIN flag set */
	int		pcser_break;	/* BREAK requested on XMIT */
	int		pcser_sbreak;	/* start BREAK requested pcser_ioctl */
	int		pcser_ebreak;	/* end BREAK requested pcser_ioctl */
	int		set_modem;	/* set modem lines in pcser_ioctl */
	int		get_modem;	/* get modem lines in pcser_ioctl */
	int		ioc_error;	/* bad ioctl */
	int		set_params;	/* call to pcser_param */
	int		no_start;	/* already in pcser_start */
	int		xmit_int;	/* transmit int	errupts */
	int		rcv_int;	/* receive int	errupts */
	int		rcvex_int;	/* receive exception interrupts */
	int		modem_int;	/* modem change interrupts */
	int		xmit_cc;	/* characters transmitted */
	int		rcv_cc;		/* characters received */
	int		break_cnt;	/* BREAKs received */
	int		bufcall;	/* times couldn't get STREAMS buffer */
	int		canwait;	/* pending timer in pcser_drainsilo */
	int		nqfretry;	/* num q retries in pcser_drainsilo */
	unsigned	flags;		/* misc flags */
};
/*
 * flags in pcser_stats_t.cmd field
 */
#define	STAT_SET		0x0002		/* set line parameters */
#define	STAT_CLEAR		0x0001		/* clear line statistics */
#define	STAT_GET		0x0000		/* get line statistics */

/*
 * flags in pcser_stats_t.flags field
 */
#define	CARD_IN_SOCKET		0x0001		/* card is in socket */

#ifdef	__cplusplus
}
#endif

#endif	/* _PCSER_IO_H */
