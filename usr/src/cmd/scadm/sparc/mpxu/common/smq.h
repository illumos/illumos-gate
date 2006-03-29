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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMQ_H
#define	_SMQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <time.h>

#include "xsem.h"

/* THIS IS CURRENTLY ONLY WRITTEN TO HANDLE A SINGLE PRODUCER, SINGLE */
/* CONSUMER !!!!!!!!!!!!!!!! */

/* Simple message queue */
/* This package allows threads to pass simple messages through shared	*/
/* local memory.  The goal is to keep it simple and somewhat fast	*/

/* smq_init() creates a simple message queue structure.  It returns	*/
/* 0 on success.  You pass it a descriptor, the location of the buffer	*/
/* where the messages will be stored, and the size of the buffer	*/
/* (the number of messages that can be stored).  The memory allocation	*/
/* of the simple message buffer is the programmers responsibility.	*/

/* smq_destroy() deativates a message queue structure */

/* smq_receive() retrieves a message off of the simple message queue.	*/
/* The message will be  removed from the queue when this routine	*/
/* returns.  It suspends the thread until a message is received.	*/

/* smq_send() places a message on the specified simple message queue. */
/* It returns 0 on success. If the simple message queue is full, */
/* SMQ_FULL is returned. */

/* smq_pendingmsgs() returns the number of pending messages currently */
/* on the queue. It returns 0 on success. */

/* smq_depth() returns the depth of the queue. It returns 0 on */
/* success. */

/* smq_timedreceive() retrieves a message off of the simple message */
/* queue. The message will be  removed from the queue when this  */
/* routine returns.  It suspends the thread until a message is  */
/* received or until 'timeout' has expired. It returns 0 on success */
/* and SMQ_TIMEOUT if timeout has expired. */


#define	SMQ_INVALID		-1
#define	SMQ_FULL		-2
#define	SMQ_NOT_IMPLEMENTED	-3
#define	SMQ_TIMEOUT		-4
#define	SMQ_ETIME		-5
#define	SMQ_ERROR		-127

/* Do NOT read or write to these structures directly. They are  */
/* implementation dependent and may change over time */
/* Be sure to declare any instantiation of these to be static if */
/* you are alocating them on the stack */
typedef uint32_t	smq_msg_t;
typedef struct
{
	int		smq_control;
	int		smq_depth;	/* maximum message count */
	int		smq_count;	/* current message count */
	smq_msg_t	*smq_msgBuffer;
	xsem_t		smq_msgAvail;
	smq_msg_t	*smq_head;
	smq_msg_t	*smq_tail;
} smq_t;


int smq_init(smq_t *smq, smq_msg_t *msgbuffer, int depth);
int smq_destroy(smq_t *smq);
int smq_receive(smq_t *smq, smq_msg_t *msg);
int smq_send(smq_t *smq, smq_msg_t *msg);
int smq_pendingmsgs(smq_t *smq, int *num);
int smq_depth(smq_t *smq, int *depth);
int smq_xreceive(smq_t *smq, timestruc_t *timeout, smq_msg_t *msg);

#ifdef	__cplusplus
}
#endif

#endif /* _SMQ_H */
