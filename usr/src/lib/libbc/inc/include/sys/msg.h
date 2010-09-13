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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#ifndef _sys_msg_h
#define	_sys_msg_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	IPC Message Facility.
 */

/*
 *	Message Operation Flags.
 */
#define	MSG_NOERROR	010000	/* no error if big message */

/*
 *	Structure Definitions.
 */

/*
 *	There is one msg queue id data structure for each q in the system.
 */

struct msqid_ds {
	struct ipc_perm	msg_perm;	/* operation permission struct */
	struct msg	*msg_first;	/* ptr to first message on q */
	struct msg	*msg_last;	/* ptr to last message on q */
	ushort		msg_cbytes;	/* current # bytes on q */
	ushort		msg_qnum;	/* # of messages on q */
	ushort		msg_qbytes;	/* max # of bytes on q */
	ushort		msg_lspid;	/* pid of last msgsnd */
	ushort		msg_lrpid;	/* pid of last msgrcv */
	time_t		msg_stime;	/* last msgsnd time */
	time_t		msg_rtime;	/* last msgrcv time */
	time_t		msg_ctime;	/* last change time */
};

/*
 *	User message buffer template for msgsnd and msgrcv system calls.
 */

/* HACK :: change the name when compiling the kernel to avoid conflicts */
struct msgbuf {
	long	mtype;		/* message type */
	char	mtext[1];	/* message text */
};

/*
 *	There is one msg structure for each message that may be in the system.
 */

struct msg {
	struct msg	*msg_next;	/* ptr to next message on q */
	long		msg_type;	/* message type */
	ushort		msg_ts;		/* message text size */
	ushort		msg_spot;	/* message text map address */
};

#endif /* !_sys_msg_h */
