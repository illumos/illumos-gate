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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ISNS_MSGQ_H
#define	_ISNS_MSGQ_H

#include <pthread.h>
#include <synch.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TEST_CLI_STOPPED	(0x0001)
#define	DD_SERVICE_STOPPED	(0x0002)
#define	SCN_STOPPED		(0x0004)
#define	ESI_STOPPED		(0x0008)

typedef enum msg_id {
	DATA_ADD = 1,
	DATA_UPDATE,
	DATA_DELETE,
	DATA_DELETE_ASSOC,
	DATA_COMMIT,
	DATA_RETREAT,
	REG_EXP,
	DEAD_PORTAL,
	SYS_QUIT_OK,
	SCN_ADD = 100,
	SCN_REMOVE,
	SCN_REMOVE_P,
	SCN_SET,
	SCN_TRIGGER,
	SCN_IGNORE,
	SCN_STOP,
	SERVER_EXIT,
	CONFIG_RELOAD
} msg_id_t;

typedef struct msg_text {
	struct msg_text	*prev;
	struct msg_text	*next;
	msg_id_t	 id;
	void		*data;
} msg_text_t;

typedef struct msg_queue {
	msg_text_t	*q_head;
	msg_text_t	*q_tail;
	pthread_mutex_t	 q_mutex;
	sema_t		 q_sema;
} msg_queue_t;

/* function prototypes */
msg_queue_t *queue_calloc();
int queue_msg_set(msg_queue_t *, msg_id_t, void *);
msg_text_t *queue_msg_get(msg_queue_t *);
void queue_msg_free(msg_text_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_MSGQ_H */
