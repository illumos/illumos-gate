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

#ifndef	_SYS_MSG_IMPL_H
#define	_SYS_MSG_IMPL_H

#include <sys/ipc_impl.h>
#if defined(_KERNEL) || defined(_KMEMUSER)
#include <sys/msg.h>
#include <sys/t_lock.h>
#include <sys/list.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Argument vectors for the various flavors of msgsys().
 */

#define	MSGGET	0
#define	MSGCTL	1
#define	MSGRCV	2
#define	MSGSND	3
#define	MSGIDS	4
#define	MSGSNAP	5

#if defined(_KERNEL) || defined(_KMEMUSER)

typedef struct  msgq_wakeup {
	list_node_t	msgw_list;
	long		msgw_type;	/* Message type request. */
	long		msgw_snd_wake;	/* Type of msg from msgsnd */
	size_t		msgw_snd_size;	/* Designates size of the msg sending */
	kthread_t	*msgw_thrd;	/* Thread waiting */
	kcondvar_t	msgw_wake_cv;	/* waiting on this */
} msgq_wakeup_t;


typedef struct msg_select {
	msgq_wakeup_t *(*selection)();
	struct msg_select *next_selection;
} msg_select_t;

/*
 * There is one msg structure for each message in the system.
 */
struct msg {
	list_node_t	msg_node;	/* message list node */
	long		msg_type;	/* message type */
	size_t		msg_size;	/* message text size */
	void		*msg_addr;	/* message text address */
	long		msg_flags;	/* message flags */
	long		msg_copycnt;	/* current # of copyouts on message */
};

/*
 * Per message flags
 */
#define	MSG_RCVCOPY	00001	/* msgrcv is copying out this message */
#define	MSG_UNLINKED	00002	/* msg has been unlinked from queue */

/*
 * msg_rcv_cv is now an array of kcondvar_t for performance reason.
 * We use multiple condition variables (kcondvar_t) to avoid needing
 * to wake all readers when sending a single message.
 */

#define	MSG_NEG_INTERVAL 8
#define	MSG_MAX_QNUM	64
#define	MSG_MAX_QNUM_CV	65

typedef struct kmsqid {
	kipc_perm_t	msg_perm;	/* operation permission struct */
	list_t		msg_list;	/* list of messages on q */
	msglen_t	msg_cbytes;	/* current # bytes on q */
	msgqnum_t	msg_qnum;	/* # of messages on q */
	msgqnum_t	msg_qmax;	/* max # of messages on q */
	msglen_t	msg_qbytes;	/* max # of bytes on q */
	pid_t		msg_lspid;	/* pid of last msgsnd */
	pid_t		msg_lrpid;	/* pid of last msgrcv */
	time_t		msg_stime;	/* last msgsnd time */
	time_t		msg_rtime;	/* last msgrcv time */
	time_t		msg_ctime;	/* last change time */
	uint_t		msg_snd_cnt;	/* # of waiting senders */
	uint_t		msg_rcv_cnt;	/* # of waiting receivers */
	uint64_t	msg_lowest_type; /* Smallest type on queue */
	/*
	 * linked list of routines used to determine what to wake up next.
	 * 	msg_fnd_sndr:	Routines for waking up readers waiting
	 *			for a message from the sender.
	 *	msg_fnd_rdr:	Routines for waking up readers waiting
	 *			for a copyout to finish.
	 */
	msg_select_t	*msg_fnd_sndr;
	msg_select_t	*msg_fnd_rdr;
	/*
	 * Various counts and queues for controlling the sleeping
	 * and waking up of processes that are waiting for various
	 * message queue events.
	 *
	 * msg_cpy_block:   List of receiving threads that are blocked because
	 *		    the message of choice is being copied out.
	 * msg_wait_snd:    List of receiving threads whose type specifier
	 *		    is positive or 0 but are blocked because there
	 *		    are no matches.
	 * msg_wait_snd_ngt:
	 *		    List of receiving threads whose type specifier is
	 *		    negative message type but are blocked because
	 *		    there are no types that qualify.
	 * msg_wait_rcv:    List of sending threads that are blocked because
	 *		    there is no room left on the message queue.
	 */
	kcondvar_t	msg_snd_cv;
	list_t		msg_cpy_block;
	list_t		msg_wait_snd[MSG_MAX_QNUM_CV];
	list_t		msg_wait_snd_ngt[MSG_MAX_QNUM_CV];
	list_t		msg_wait_rcv;
	size_t		msg_snd_smallest; /* Smallest msg on send wait list */
	int		msg_ngt_cnt;	/* # of negative receivers blocked */
	char		msg_neg_copy;	/* Neg type copy underway */
} kmsqid_t;

#endif	/* _KERNEL */

#if defined(_SYSCALL32)
/*
 * LP64 view of the ILP32 msgbuf structure
 */
struct ipcmsgbuf32 {
	int32_t	mtype;		/* message type */
	char	mtext[1];	/* message text */
};

/*
 * LP64 view of the ILP32 msgsnap_head and msgsnap_mhead structures
 */
struct msgsnap_head32 {
	size32_t msgsnap_size;	/* bytes consumed/required in the buffer */
	size32_t msgsnap_nmsg;	/* number of messages in the buffer */
};

struct msgsnap_mhead32 {
	size32_t msgsnap_mlen;	/* number of bytes in message that follows */
	int32_t	msgsnap_mtype;	/* message type */
};

/*
 * LP64 view of the ILP32 msqid_ds structure
 */
struct msqid_ds32 {
	struct ipc_perm32 msg_perm;	/* operation permission struct */
	caddr32_t	msg_first;	/* ptr to first message on q */
	caddr32_t	msg_last;	/* ptr to last message on q */
	uint32_t	msg_cbytes;	/* current # bytes on q */
	uint32_t	msg_qnum;	/* # of messages on q */
	uint32_t	msg_qbytes;	/* max # of bytes on q */
	pid32_t		msg_lspid;	/* pid of last msgsnd */
	pid32_t		msg_lrpid;	/* pid of last msgrcv */
	time32_t	msg_stime;	/* last msgsnd time */
	int32_t		msg_pad1;	/* reserved for time_t expansion */
	time32_t	msg_rtime;	/* last msgrcv time */
	int32_t		msg_pad2;	/* time_t expansion */
	time32_t	msg_ctime;	/* last change time */
	int32_t		msg_pad3;	/* time expansion */
	int16_t		msg_cv;
	int16_t		msg_qnum_cv;
	int32_t		msg_pad4[3];	/* reserve area */
};
#endif	/* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MSG_IMPL_H */
