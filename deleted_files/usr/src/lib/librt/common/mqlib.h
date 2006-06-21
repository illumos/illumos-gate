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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MQLIB_H
#define	_MQLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mqlib.h - Header file for POSIX.4 message queue
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "sigev_thread.h"

/*
 * Default values per message queue
 */
#define	MQ_MAXMSG	128
#define	MQ_MAXSIZE	1024

#define	MQ_MAGIC	0x4d534751		/* "MSGQ" */

/*
 * Message header which is part of messages in link list
 */
typedef struct {
	uint64_t 	msg_next;	/* offset of next message in the link */
	uint64_t	msg_len;	/* length of the message */
} msghdr_t;

/*
 * message queue description
 */
struct mq_dn {
	size_t		mqdn_flags;	/* open description flags */
};

/*
 * message queue descriptor structure
 */
typedef struct mq_des {
	struct mq_des	*mqd_next;	/* list of all open mq descriptors, */
	struct mq_des	*mqd_prev;	/* needed for fork-safety */
	int		mqd_magic;	/* magic # to identify mq_des */
	int		mqd_flags;	/* operation flag per open */
	struct mq_header *mqd_mq;	/* address pointer of message Q */
	struct mq_dn	*mqd_mqdn;	/* open	description */
	thread_communication_data_t *mqd_tcd;	/* SIGEV_THREAD notification */
} mqdes_t;


/*
 * message queue common header, part of the mmap()ed file.
 * Since message queues may be shared between 32- and 64-bit processes,
 * care must be taken to make sure that the elements of this structure
 * are identical for both _LP64 and _ILP32 cases.
 */
typedef struct mq_header {
	/* first field must be mq_totsize, DO NOT insert before this	*/
	int64_t		mq_totsize;	/* total size of the Queue */
	int64_t		mq_maxsz;	/* max size of each message */
	uint32_t	mq_maxmsg;	/* max messages in the queue */
	uint32_t	mq_maxprio;	/* maximum mqueue priority */
	uint32_t	mq_curmaxprio;	/* current maximum MQ priority */
	uint32_t	mq_mask;	/* priority bitmask */
	uint64_t	mq_freep;	/* free message's head pointer */
	uint64_t	mq_headpp;	/* pointer to head pointers */
	uint64_t	mq_tailpp;	/* pointer to tail pointers */
	signotify_id_t	mq_sigid;	/* notification id (3 int's) */
	uint32_t	mq_ntype;	/* notification type (SIGEV_*) */
	uint64_t	mq_des;		/* pointer to msg Q descriptor */
	mutex_t		mq_exclusive;	/* acquire for exclusive access */
	sem_t		mq_rblocked;	/* number of processes rblocked */
	sem_t		mq_notfull;	/* mq_send()'s block on this */
	sem_t		mq_notempty;	/* mq_receive()'s block on this */
	sem_t		mq_spawner;	/* spawner thread blocks on this */
} mqhdr_t;

extern mutex_t mq_list_lock;
extern mqdes_t *mq_list;

/* prototype for signotify system call. unexposed to user */
int __signotify(int cmd, siginfo_t *sigonfo, signotify_id_t *sn_id);

#ifdef	__cplusplus
}
#endif

#endif	/* _MQLIB_H */
