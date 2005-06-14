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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LOGINDMUX_IMPL_H
#define	_SYS_LOGINDMUX_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This structure is shared between two logindmux peer instances and
 * ensures that only one of the peers will be actively processing an
 * I_UNLINK ioctl at any one time.
 */
typedef struct unlinkinfo {
	kmutex_t	state_lock;	/* serialize access to state */
	int		state;		/* state of I_UNLINK operation */
	mblk_t		*prot_mp;	/* carries protocol messages */
} unlinkinfo_t;

/*
 * Logindmux state structure; one per open instance.
 */
struct tmx {
	queue_t		*rdq;		/* our mux upper read queue */
	queue_t		*muxq;		/* our mux lower write queue */
	queue_t		*peerq; 	/* peer mux lower write queue */
	minor_t		dev0;		/* our minor device number */
	boolean_t	isptm;		/* true if ptm is downstream */
	mblk_t		*unlink_mp;	/* mblk used in logdmux_unlink_timer */
	unlinkinfo_t	*unlinkinfop;	/* used during I_UNLINK processing */
	bufcall_id_t	wbufcid;	/* needed for recovery */
	bufcall_id_t	rbufcid;	/* needed for recovery */
	timeout_id_t	utimoutid;	/* unlink timer identifier */
	timeout_id_t	wtimoutid;	/* needed for recovery */
	timeout_id_t	rtimoutid;	/* needed for recovery */
};

#define	LOGDMX_ID		107	/* module id number */

/*
 * The arguments for calls to qtimeout, in microseconds.
 */
#define	SIMWAIT			100000	/* logdmux_timer */
#define	LOGDMUX_POLL_WAIT	10	/* logdmux_unlink_timer */

/*
 * State of peer linkage.
 */
enum {
	LOGDMUX_LINKED		= 1,	/* peer instances are in linked state */
	LOGDMUX_UNLINK_PENDING	= 2,	/* a peer is actively I_UNLINKing */
	LOGDMUX_UNLINKED	= 3	/* a peer has completed its I_UNLINK */
};

/*
 * Protocol message magic cookie.
 */
#define	LOGDMUX_MCTL		(LOGDMX_ID << 16)

/*
 * peer to peer protocol messages.
 */
#define	LOGDMUX_UNLINK_REQ	(LOGDMUX_MCTL|1) /* peer wants to unlink */
#define	LOGDMUX_UNLINK_RESP	(LOGDMUX_MCTL|2) /* ok for peer to unlink */

/*
 * Macro to determine if an mblk is a logindmux protocol mblk.
 */
#define	LOGDMUX_PROTO_MBLK(mp)						   \
	((DB_TYPE(mp) == M_CTL)						&& \
	((mp)->b_cont != NULL)						&& \
	(DB_TYPE((mp)->b_cont) == M_IOCTL)				&& \
	(((struct iocblk *)((mp)->b_cont->b_rptr))->ioc_cmd == I_UNLINK))


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOGINDMUX_IMPL_H */
