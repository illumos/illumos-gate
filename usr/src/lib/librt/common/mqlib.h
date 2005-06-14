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

#ifndef	_MQLIB_H
#define	_MQLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mqlib.h - Header file for POSIX.4 message queue
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/feature_tests.h>

#include <sys/types.h>
#include <synch.h>
#include <sys/types.h>
#include <signal.h>
#include <mqueue.h>
#include <semaphore.h>

/*
 * Default values per message queue
 */
#define	MQ_MAXMSG	128
#define	MQ_MAXSIZE	1024

#define	MQ_MAGIC	0x4d534751		/* "MSGQ" */

/*
 * Message header which is part of messages in link list
 */
typedef struct mq_msg_hdr {
	uint64_t 	msg_next;	/* offset of next message in the link */
	uint64_t	msg_len;	/* length of the message */
} msghdr_t;

/*
 * message queue descriptor structure
 */
typedef struct mq_des {
	size_t		mqd_magic;	/* magic # to identify mq_des */
	struct mq_header *mqd_mq;	/* address pointer of message Q */
	size_t		mqd_flags;	/* operation flag per open */
	struct mq_dn	*mqd_mqdn;	/* open	description */
} mqdes_t;

/*
 * message queue description
 */
struct mq_dn {
	size_t		mqdn_flags;	/* open description flags */
};


/*
 * message queue common header which is part of mmap()ed file.
 */
typedef struct mq_header {
	/* first field must be mq_totsize, DO NOT insert before this	*/
	int64_t		mq_totsize;	/* total size of the Queue */
	int64_t		mq_maxsz;	/* max size of each message */
	uint_t		mq_maxmsg;	/* max messages in the queue */
	uint_t		mq_maxprio;	/* maximum mqueue priority */
	uint_t		mq_curmaxprio;	/* current maximum MQ priority */
	uint_t		mq_mask;	/* priority bitmask */
	uint64_t	mq_freep;	/* free message's head pointer */
	uint64_t	mq_headpp;	/* pointer to head pointers */
	uint64_t	mq_tailpp;	/* pointer to tail pointers */
	uint_t		mq_magic;	/* support more implementations */
	signotify_id_t	mq_sigid;	/* notification id */
	uint64_t	mq_des;		/* pointer to msg Q descriptor */
	sem_t		mq_exclusive;	/* acquire for exclusive access */
	sem_t		mq_rblocked;	/* number of processes rblocked */
	sem_t		mq_notfull;	/* mq_send()'s block on this */
	sem_t		mq_notempty;	/* mq_receive()'s block on this */
	int64_t		mq_pad[4];	/* reserved for future */
} mqhdr_t;

/* prototype for signotify system call. unexposed to user */
int __signotify(int cmd, siginfo_t *sigonfo, signotify_id_t *sn_id);

#ifdef	__cplusplus
}
#endif

#endif	/* _MQLIB_H */
