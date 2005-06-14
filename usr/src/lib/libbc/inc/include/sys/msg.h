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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	IPC Message Facility.
 */

#ifndef _sys_msg_h
#define _sys_msg_h

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
#ifdef KERNEL
struct ipcmsgbuf {
#else
struct msgbuf {
#endif KERNEL
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



#ifdef KERNEL
/*
 *	Implementation Constants.
 */

#define	PMSG	(PZERO + 2)	/* message facility sleep priority */

/*
 *	Permission Definitions.
 */

#define	MSG_R	0400	/* read permission */
#define	MSG_W	0200	/* write permission */

/*
 *	ipc_perm Mode Definitions.
 */

#define	MSG_RWAIT	001000	/* a reader is waiting for a message */
#define	MSG_WWAIT	002000	/* a writer is waiting to send */
#define	MSG_LOCKED	004000	/* msqid locked */
#define	MSG_LOCKWAIT	010000	/* msqid wanted */

/* define resource locking macros */
#define MSGWAKEUP(addr) {				\
	curpri = PMSG;					\
	wakeup((caddr_t)(addr));			\
}

#define	MSGLOCK(qp) {						\
	while ((qp)->msg_perm.mode & MSG_LOCKED) {		\
		(qp)->msg_perm.mode |= MSG_LOCKWAIT;		\
		if (sleep((caddr_t)(qp), PMSG | PCATCH)) {	\
			(qp)->msg_perm.mode &= ~MSG_LOCKWAIT;	\
			u.u_error = EINTR;			\
			return (NULL);				\
		}						\
	}							\
	(qp)->msg_perm.mode |= MSG_LOCKED;			\
}

#define MSGUNLOCK(qp) {					\
	(qp)->msg_perm.mode &= ~MSG_LOCKED;		\
	if ((qp)->msg_perm.mode & MSG_LOCKWAIT) {	\
		(qp)->msg_perm.mode &= ~MSG_LOCKWAIT;	\
		MSGWAKEUP(qp);				\
	}						\
}


/*
 *	Message information structure.
 */

struct msginfo {
	int	msgmap,	/* # of entries in msg map */
		msgmax,	/* max message size */
		msgmnb,	/* max # bytes on queue */
		msgmni,	/* # of message queue identifiers */
		msgssz,	/* msg segment size (should be word size multiple) */
		msgtql;	/* # of system message headers */
	ushort	msgseg;	/* # of msg segments (MUST BE < 32768) */
};
struct msginfo	msginfo;	/* message parameters */


/*
 *	Configuration Parameters
 * These parameters are tuned by editing the system configuration file.
 * The following lines establish the default values.
 */
#ifndef	MSGPOOL
#define	MSGPOOL	8	/* size, in kilobytes, of message pool */
#endif
#ifndef	MSGMNB
#define	MSGMNB	2048	/* default max number of bytes on a queue */
#endif
#ifndef	MSGMNI
#define	MSGMNI	50	/* number of message queue identifiers */
#endif
#ifndef	MSGTQL
#define	MSGTQL	50	/* # of system message headers */
#endif

/* The following parameters are assumed not to require tuning */
#ifndef	MSGMAP
#define	MSGMAP	100	/* number of entries in msg map */
#endif
#ifndef	MSGMAX
#define	MSGMAX	(MSGPOOL * 1024)	/* max message size (in bytes) */
#endif
#ifndef	MSGSSZ
#define	MSGSSZ	8	/* msg segment size (should be word size multiple) */
#endif
#define	MSGSEG	((MSGPOOL * 1024) / MSGSSZ) /* # segments (MUST BE < 32768) */


/*
 * Structures allocated in machdep.c
 */
char		*msg;		/* base address of message buffer */
struct map	*msgmap;	/* msg allocation map */
struct msg	*msgh;		/* message headers */
struct msqid_ds	*msgque;	/* msg queue headers */

#endif KERNEL

#endif /*!_sys_msg_h*/
