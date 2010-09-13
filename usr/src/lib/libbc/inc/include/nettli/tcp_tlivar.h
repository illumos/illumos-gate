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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TCP_TLIVAR_
#define	_TCP_TLIVAR_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data structure definitions for the streams interface
 * to the socket-based TCP implementation.
 */

/*
 * Socket Information block contains the special socket wakeup
 * hooks. When a block of tt_sockinfo is allocated, the wupalt.wup_arg
 * points to the beginning of tt_sockinfo.
 */

struct tt_sockinfo {
	struct	wupalt	ts_sowakeup;	/* special sock wakeup hook */
	u_long		ts_seqnum;	/* connection sequence number */
	long		ts_flags;	/* see below */
	struct tt_softc *ts_ttp;	/* back ptr to dev-instance handle */
};
/*
 * No connection assoicated with this socket
 */
#define	TT_TS_NOTUSED	0x00
/*
 * This socket is connected or pending connection
 */
#define	TT_TS_INUSE	0x01

/*
 * Per-device instance state information.
 *
 * To aid in handling resource starvation situations, we pre-allocate two
 * messages for reporting errors.  Tt_merror is used as a last resort, when
 * attempts to allocate a normal error reply fail.  It's allocated in the
 * open routine and freed in the close routine.  The routines that produce
 * response messages try to keep tt_errack pre-allocated, but don't insist
 * that it always be valid.  This strategy attempts to minimize the
 * probability of having to fall back on the drastic measure of using the
 * M_ERROR message.
 */
struct tt_softc {
	/* The tt_unit & tt_unitnext fields aren't yet used. */
	struct tt_softc	*tt_next;	/* link to next device instance */
	u_short		tt_unit;	/* instance number */
	u_short		tt_unitnext;	/* next unit # to be used on open */

	queue_t		*tt_rq;		/* cross-link to read queue */
	struct socket	*tt_so;		/* socket for this device instance */
	mblk_t		*tt_merror;	/* pre-allocated M_ERROR message */
	mblk_t		*tt_errack;	/* pre-allocated T_error_ack message */
	u_int		tt_state;	/* current state of the tli automaton */
	long		tt_seqnext;	/* next sequence number to assign */
	u_long		tt_flags;	/* see below */
	u_long		tt_event;	/* service event inidication */
	struct	proc	*tt_auxprocp;	/* Aux proc handle */
	struct	in_addr	tt_laddr;	/* saved local address */
	u_short		tt_lport;	/* saved local port number */
};

/*
 * Flag (tt_flags) bits private to the driver.
 */
#define	TT_OPEN		0x01	/* device instance is currently open */
#define	TT_ERROR	0x02	/* in error state -- unusable */
#define	TT_CLOSE	0x04	/* this device instance is closed */
#define	TT_TIMER	0x08	/* scheduled wakeup timer is already set */
/*
 * Event (tt_event) bits private to the driver.
 */
#define	TTE_EVENT	0x01	/* aux proc service wanted indication */
#define	TTE_ONQUEUE	0x02	/* set if this ttp has wakeup-event pending */

/*
 * Internet style address for TLI
 */
struct	taddr_in {
	short   sin_family;
	u_short sin_port;
	struct  in_addr sin_addr;
};

/*
 * For use with direct-read only
 *  when:
 *    - TI is in the correct state
 *    - there are data to be read
 *    - socket is in state to receive
 *    - socket buffer not locked (we are running this
 *            at interrupt level !)
 *    - the auxproc is not running
 */
#define	TT_DIRECT_READ(ttp, so) { \
	extern int tcptli_auxproc_running; \
	if (((ttp)->tt_state & TL_DATAXFER) && \
		((so)->so_rcv.sb_cc != 0) && \
		(!((so)->so_state & SS_CANTRCVMORE)) && \
		(!((so)->so_rcv.sb_flags & SB_LOCK)) && \
		(!tcptli_auxproc_running)) \
		if (tcptli_Ercv((ttp))) \
			return; \
}

#ifdef	TLIDEBUG
extern	tcptli_debug;
#define	TCPTLI_PRINTF if (tcptli_debug) printf
#else
#define	TCPTLI_PRINTF
#endif	/* TLIDEBUG */

#endif	/* _TCP_TLIVAR_ */
