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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_TTYMUX_H
#define	_TTYMUX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/obpdefs.h>
#include <sys/tty.h>
#include <sys/ttymuxuser.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SM_MAX_ABSLEN	24	/* maximum length for the s/w abort sequence */
#define	SM_MIN_ABSLEN	2

#define	SM_COPYIN	0x1
#define	SM_COPYOUT	0x2

typedef
struct sm_iocdata {
	int sm_iocid;
	int sm_nacks;	/* number of responses expected */
	int sm_ackcnt;	/* number of ACKs received */
	int sm_nakcnt;	/* number of NAKs received */
	int sm_acnt;	/* number of responses received */
	int sm_acked;	/* has the message been acked (only one of them) */
	int sm_policy;	/* which policy is used for acknowleding this ioctl */
	uint_t sm_flags;
			/* indicates when copyin/out has been sent upstream */
	ulong_t  sm_timeval;
} sm_iocdata_t;

/*
 * Each minor (refered to as a logical device) created by the multiplexor
 * maps onto multiple real devices.
 * I/O on a logical device is duplicated across multiple real devices.
 * i.e. input from any of the real devices (identified by lqs) is funneled
 * through the queue identified in the ttycommon field of a logical unit.
 * output arriving on the queue identified in the ttycommon field of a logical
 * unit is distributed to all real devices identified by lqs.
 *
 * When a logical unit is open there is a unique queue upstream (identified
 * by ttycommon).
 * When a real unit is open there is a unique lower queue to the h/w driver
 * (identified by ttycommon).
 *
 * If the control lines on RS232 port for a physical unit are unknown and
 * a request for their status has been issued then flags contains the bits
 * TIOCM_PEND and tiocmgetid contains the id of the M_IOCTL streams	message
 * sent down the write queue to obtain the current status (placed in mbits).
 */
typedef
struct sm_uqi {
	int		sm_lunit;	/* logical unit */
	int		sm_protocol;	/* in use for this protocol */
	uint_t		sm_flags;	/* flags */
	uint_t		sm_mbits;	/* consolidated status of modem lines */
	tcflag_t	sm_cmask;	/* ignore these control bits */
	uint_t		sm_policy;	/* ioctl response policy */
	struct sm_lqi	*sm_lqs;	/* lower queues mapped to this lunit */
	int		sm_nlqs;
	kmutex_t	sm_umutex[1];	/* protects uflags */
	kcondvar_t	sm_ucv[1];	/* waiting for uflags to change */
	bufcall_id_t	sm_ttybid;	/* ttycommon bufcall */
	dev_t		sm_dev;		/* currently attached device */
	int		sm_nwaiters;	/* no. of threads waiting for carrier */
	queue_t		*sm_waitq;	/* identity of blocked queue */
	tty_common_t	sm_ttycommon[1];
					/* queue common data when is open */
	sm_iocdata_t	sm_siocdata;	/* active ioctl */
	sm_iocdata_t	sm_piocdata;	/* active private ioctl */
} sm_uqi_t;

typedef
struct sm_lqi {
	struct sm_lqi	*sm_nlqi;	/* chain units together into lists */
	sm_uqi_t	*sm_uqi;	/* this lunit and uqi are associated */
	int		sm_linkid;	/* mux id for the link */
	uint64_t	sm_tag;		/* tag for the link */
	uint_t		sm_flags;		/* flags */
	uint_t		sm_uqflags;	/* written by an upper queue */
	io_mode_t	sm_ioflag;	/* input and/or output stream */
	int		sm_ctrla_abort_on;
	int		sm_break_abort_on;
	uint_t		sm_mbits;	/* status of the modem control lines */
	tcflag_t	sm_cmask;	/* ignore these control bits */
	mblk_t		*sm_mp;		/* mblk for next write */
	bufcall_id_t	sm_bid;		/* bufcall id */
	bufcall_id_t	sm_ttybid;	/* ttymodes changed bufcall */
	kmutex_t	sm_umutex[1];	/* protects open code */
	kcondvar_t	sm_ucv[1];
	dev_info_t	*sm_dip;
	dev_t		sm_dev;
	int		sm_unit;
	unsigned char	*sm_hadkadbchar;
	char		*sm_nachar;
	int		sm_piocid;
	tty_common_t	sm_ttycommon[1];
					/* queue common data when open */
	char		sm_path[MAXPATHLEN];
} sm_lqi_t;

/*
 * This structure maintains the state of the console.
 */
typedef struct console {
	dev_t		sm_dev;		/* the minor node of a console */
	int		sm_muxid;	/* STREAM's link identifier */
	io_mode_t	sm_mode;	/* I/O mode */
	boolean_t	sm_obp_con;	/* is it an OBP console */
	ihandle_t	sm_i_ihdl;	/* ihandle of the OBP input device */
	ihandle_t	sm_o_ihdl;	/* ihandle of the OBP output device */
	char		*sm_path;	/* device tree device path */
	char		*sm_alias;	/* device path alias */
} sm_console_t;

/*
 * This structure contains the information for an open device.
 * If an instance of it exists it is available as a named pointer:
 */
#define	TTYMUXPTR "ttymuxconfig"

typedef struct mux_state {

	/* protects ttymux configuration */
	kmutex_t	sm_cons_mutex;

	/* Information about the standard I/O devices */
	sm_console_t	sm_cons_stdin;
	sm_console_t	sm_cons_stdout;

	/* List of multiplexed serial consoles */
	uint_t		sm_cons_cnt;
	char		*sm_ialias;
	char		*sm_oalias;
	sm_console_t	sm_cons_links[TTYMUX_MAX_LINKS];

} sm_mux_state_t;

/*
 * Driver instance private information.
 */
typedef
struct sm_ss
{
	dev_info_t	*sm_dip;	/* device tree information */
	uint_t		sm_trflag;	/* debug and information levels */
	sm_uqi_t	*sm_lconsole;	/* the current logical console */
	sm_mux_state_t	*sm_ms;		/* state associated with a console */

	sm_lqi_t	*sm_lqs;
	sm_uqi_t	*sm_uqs;
	uint_t		sm_break_abort_on;
	uint_t		sm_ctrla_abort_on;

	int		sm_min_redundancy;
	char		sm_abs[SM_MAX_ABSLEN];

} sm_ss_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _TTYMUX_H */
