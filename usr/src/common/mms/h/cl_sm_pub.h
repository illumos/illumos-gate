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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CL_SM_PUB_
#define	_CL_SM_PUB_
#include <limits.h>
#include <time.h>

#ifndef _CL_QM_DEFS_
#include "cl_qm_defs.h"
#endif

#ifndef _LH_DEFS_
#include "lh_defs.h"
#endif

#define	MAX_TIMEOUT		100000000L
#define	NOW		time((time_t *)0)
#define	WAIT_ACTIVITY		10
#define	WAIT_FOREVER		LONG_MAX
#define	WAIT_RETRY		RETRY_TIMEOUT
#define	WAIT_ZERO		0


#define	CL_SM_ACTIVATE(tqep, nevt) do {     \
    tqep->prev_event = tqep->event;         \
    tqep->prev_timeout = tqep->timeout;     \
    tqep->event = nevt;                     \
    tqep->timeout = NOW;                    \
} while (0)

#define	CL_SM_CONTINUE() do {               \
    cl_tqep->event = cl_tqep->prev_event;   \
    cl_tqep->timeout = cl_tqep->prev_timeout;\
    if (1)				    \
return (SME_SUSPEND);                                              \
} while (0)

#define	CL_SM_EXIT()  do {                  \
    if (1)			     \
	return (SME_EXIT);  		    \
} while (0)

#define	CL_SM_SUSPEND(period, tevt)  do {  \
    cl_tqep->event = tevt;                 \
    cl_tqep->timeout = (time_t)(period);   \
    cl_tqep->timeout += (cl_tqep->timeout == WAIT_FOREVER) ? 0 : NOW;       \
    if (1)				\
	return (SME_SUSPEND);                                              \
} while (0)

#define	CL_SM_SWITCH(ntbl, nstt, nevt) do { \
    cl_tqep->table = ntbl;                  \
    cl_tqep->state = nstt;                  \
    cl_tqep->event = nevt;
	cl_tqep->timeout = NOW;                                           \
	if (1)				\
	return (SME_SWITCH);                                               \
} while (0)

#define	CL_SM_TERMINATE() do {             \
    if (1)				\
	return (SME_TERMINATE);                                            \
} while (0)


	typedef enum {

		SME_FIRST = 0,
		SME_CANCELLED,
		SME_CAN_REQUESTED,
		SME_CAP_BUSY,
		SME_CAP_CLOSED,

		SME_CAP_EMPTY,
		SME_CAP_ERROR,
		SME_CAP_FULL,
		SME_CAP_OPEN,
		SME_CELL_EMPTY,

		SME_CELL_FULL,
		SME_CLEANUP,
		SME_COMPLETE,
		SME_CONFIG_ERROR,
		SME_EJECT_COMPLETE,

		SME_ENTER_COMPLETE,
		SME_EXIT,
		SME_INTERMEDIATE,
		SME_LIBRARY_BUSY,
		SME_LIBRARY_FAIL,

		SME_LSM_ERROR,
		SME_PROCESS_FAIL,
		SME_RECOV_COMPLETE,
		SME_REQUEST_ERROR,
		SME_REQ_OVERRIDDEN,

		SME_SERVER_IDLE,
		SME_START,
		SME_SUSPEND,
		SME_SWITCH,
		SME_TERMINATE,

		SME_TIMED_OUT,
		SME_TIMED_OUT2,
		SME_VOLUME_ERROR,
		SME_VOL_MISPLACED,
		SME_WAKEUP,

		SME_LAST
	} CL_SM_EVENT;


typedef enum {

	SMS_FIRST = 0,
	SMS_CANCEL_RETRY,
	SMS_CANCEL_WAIT,
	SMS_CAP_WAIT1,
	SMS_CAP_WAIT2,

	SMS_CAT_CELL1,
	SMS_CAT_CELL2,
	SMS_CAT_DRIVE,
	SMS_CAT_RETRY1,
	SMS_CAT_RETRY2,

	SMS_CAT_RETRY3,
	SMS_CAT_RETRY4,
	SMS_CAT_WAIT1,
	SMS_CAT_WAIT2,
	SMS_CAT_WAIT3,

	SMS_CAT_WAIT4,
	SMS_EJECT_COMPLETE,
	SMS_EJECT_RETRY,
	SMS_EJECT_WAIT1,
	SMS_EJECT_WAIT2,

	SMS_EJECT_WAIT3,
	SMS_END,
	SMS_ENTER_COMPLETE,
	SMS_ENTER_RETRY,
	SMS_ENTER_WAIT1,

	SMS_ENTER_WAIT2,
	SMS_ENTER_WAIT3,
	SMS_MOVE_RETRY,
	SMS_MOVE_VOLUME,
	SMS_MOVE_WAIT,

	SMS_RELEASE_RETRY1,
	SMS_RELEASE_WAIT1,
	SMS_RESERVE_RETRY,
	SMS_RESERVE_WAIT1,
	SMS_RESERVE_WAIT2,

	SMS_RESERVE_WAIT3,
	SMS_START,
	SMS_STATUS_RETRY1,
	SMS_STATUS_RETRY2,
	SMS_STATUS_WAIT1,

	SMS_STATUS_WAIT2,
	SMS_UNLOCK_RETRY,
	SMS_UNLOCK_WAIT,
	SMS_VARY_RETRY,
	SMS_VARY_WAIT,

	SMS_WAIT,
	SMS_LAST
} CL_SM_STATE;


typedef CL_SM_EVENT (*CL_SM_ARP)(void *);
typedef STATUS	(*CL_SM_MHP)(char *, int);

typedef struct {
	TYPE		sender;
	CL_SM_MHP		handler;
} CL_SM_HANDLER;

typedef struct {
	CL_SM_STATE		state;
	CL_SM_EVENT		event;
	CL_SM_ARP		action;
	CL_SM_STATE		nxt_state;
} CL_SM_TABLE;

typedef struct {
	QM_MID		task_id;
	CL_SM_TABLE		*table;
	CL_SM_STATE		state;
	CL_SM_EVENT		event;
	time_t		timeout;
	void		*taskp;
	RESPONSE_STATUS	status;
	CL_SM_EVENT		prev_event;
	time_t		prev_timeout;
} CL_SM_TASK;



extern		LH_RESPONSE		*cl_lh_response;
extern		CL_SM_TASK		*cl_tqep;
extern		QM_QID		cl_tskq;


char 	*cl_sm_event(CL_SM_EVENT event);
STATUS 	cl_sm_execute(void);
STATUS 	cl_sm_response(char *mbuf, int bcnt);
char 	*cl_sm_state(CL_SM_STATE state);
char 	*cl_sm_table(CL_SM_TABLE *table);
STATUS 	cl_sm_tcreate(CL_SM_TABLE *table, void *taskp, CL_SM_TASK **tqe);
STATUS 	cl_sm_tselect(CL_SM_HANDLER *mhtp);


#endif /* _CL_SM_PUB_ */
