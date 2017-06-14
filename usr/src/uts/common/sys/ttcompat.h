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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_SYS_TTCOMPAT_H
#define	_SYS_TTCOMPAT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * BSD/XENIX/V7 ttcompat module header file
 */

/*
 * Old-style terminal state.
 */
typedef struct {
	int	t_flags;		/* flags */
	char	t_ispeed, t_ospeed;	/* speeds */
	char	t_erase;		/* erase last character */
	char	t_kill;			/* erase entire line */
	char	t_intrc;		/* interrupt */
	char	t_quitc;		/* quit */
	char	t_startc;		/* start output */
	char	t_stopc;		/* stop output */
	char	t_eofc;			/* end-of-file */
	char	t_brkc;			/* input delimiter (like nl) */
	char	t_suspc;		/* stop process signal */
	char	t_dsuspc;		/* delayed stop process signal */
	char	t_rprntc;		/* reprint line */
	char	t_flushc;		/* flush output (toggles) */
	char	t_werasc;		/* word erase */
	char	t_lnextc;		/* literal next character */
	int	t_xflags;		/* XXX extended flags */
} compat_state_t;

/*
 * Per-tty structure.
 */
typedef struct {
	mblk_t	*t_iocpending;		/* ioctl pending successful */
					/* allocation */
	compat_state_t t_curstate;	/* current emulated state */
	struct sgttyb t_new_sgttyb;	/* new sgttyb from TIOCSET[PN] */
	struct tchars t_new_tchars;	/* new tchars from TIOCSETC */
	struct ltchars t_new_ltchars;	/* new ltchars from TIOCSLTC */
	int	t_new_lflags;		/* new lflags from TIOCLSET/LBIS/LBIC */
	int	t_state;		/* state bits */
	int	t_iocid;		/* ID of "ioctl" we handle specially */
	int	t_ioccmd;		/* ioctl code for that "ioctl" */
	bufcall_id_t t_bufcallid;	/* ID from qbufcall */
	intptr_t t_arg;			/* third argument to ioctl */
} ttcompat_state_t;


#define	TS_FREE	 0x00	/* not in use */
#define	TS_INUSE 0x01	/* allocated */
#define	TS_W_IN	 0x02	/* waiting for an M_IOCDATA response to an */
			/* M_COPYIN request */
#define	TS_W_OUT 0x04	/* waiting for an M_IOCDATA response to an */
			/* M_COPYOUT request */
#define	TS_IOCWAIT 0x08	/* waiting for an M_IOCACK/M_IOCNAK from downstream */
#define	TS_TIOCNAK 0x10	/* received a NAK in response to a ttcompat message */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TTCOMPAT_H */
