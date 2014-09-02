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

/*
 * smq.c: to provide a message queue system for scadm functions (used in the
 * firmware download context where BP messages, received from the service
 * processor, are stored in the message queue)
 *
 * these routines come from the libxposix library
 */

#include <sys/types.h>
#include <time.h>

#include "xsem.h"
#include "smq.h"


#define	SMQ_VALID_SMQ		0x0000003b
#define	SMQ_VALID_SMQ_MASK	0x000000FF


int
smq_init(smq_t *smq, smq_msg_t *msgbuffer, int depth)
{
	/* allocate local semaphore initialized to 0 */
	if (xsem_init(&smq->smq_msgAvail, 0, 0) != 0)
		return (SMQ_ERROR);

	smq->smq_control	= SMQ_VALID_SMQ;
	smq->smq_msgBuffer	= msgbuffer;
	smq->smq_head		= msgbuffer;
	smq->smq_tail		= msgbuffer;
	smq->smq_count		= 0;
	smq->smq_depth		= depth;

	return (0);
}


int
smq_destroy(smq_t *smq)
{
	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	smq->smq_control = 0;
	(void) xsem_destroy(&smq->smq_msgAvail);

	return (0);
}


int
smq_receive(smq_t *smq, smq_msg_t *msg)
{
	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	/* Wait for message */
	(void) xsem_wait(&smq->smq_msgAvail);

	if (smq->smq_count == 0)
		return (SMQ_ERROR);

	/* Copy messaged into queue */
	*msg = *smq->smq_head;

	smq->smq_head++;
	if ((unsigned long)smq->smq_head > ((unsigned long)smq->smq_msgBuffer +
	    (unsigned long)(smq->smq_depth * sizeof (smq_msg_t)))) {
		smq->smq_head = smq->smq_msgBuffer;
	}
	smq->smq_count--;

	return (0);
}


int
smq_send(smq_t *smq, smq_msg_t *msg)
{
	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	if (smq->smq_count == smq->smq_depth)
		return (SMQ_FULL);

	/* Copy messaged into queue */
	*smq->smq_tail = *msg;

	smq->smq_tail++;
	if ((unsigned long)smq->smq_tail > ((unsigned long)smq->smq_msgBuffer +
	    (unsigned long)(smq->smq_depth * sizeof (smq_msg_t)))) {
		smq->smq_tail = smq->smq_msgBuffer;
	}

	smq->smq_count++;
	(void) xsem_post(&smq->smq_msgAvail);

	return (0);
}


int
smq_pendingmsgs(smq_t *smq, int *num)
{
	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	*num = smq->smq_count;

	return (0);
}


int
smq_depth(smq_t *smq, int *depth)
{
	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	*depth = smq->smq_depth;

	return (0);
}


int
smq_xreceive(smq_t *smq, timestruc_t *timeout, smq_msg_t *msg)
{
	int Status;


	if ((smq->smq_control & SMQ_VALID_SMQ_MASK) != SMQ_VALID_SMQ)
		return (SMQ_INVALID);

	/* Wait for message */
	if ((Status = xsem_xwait(&smq->smq_msgAvail, 1, timeout)) == XSEM_ETIME)
		return (SMQ_ETIME);

	if (Status != 0)
		return (SMQ_ERROR);

	if (smq->smq_count == 0)
		return (SMQ_ERROR);

	/* Copy messaged into queue */
	*msg = *smq->smq_head;

	smq->smq_head++;
	if ((unsigned long)smq->smq_head > ((unsigned long)smq->smq_msgBuffer +
	    (unsigned long)(smq->smq_depth * sizeof (smq_msg_t)))) {
		smq->smq_head = smq->smq_msgBuffer;
	}
	smq->smq_count--;


	return (0);
}
