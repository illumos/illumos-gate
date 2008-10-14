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

#ifndef _ISCSI_THREAD_H
#define	_ISCSI_THREAD_H

/*
 * Block comment which describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#define	SIG_ISCSI_THREAD		0x54485244

#define	ISCSI_TH_MAX_NAME_LEN		32

#define	ISCSI_THREAD_SIGNAL_KILL	0x00000001
#define	ISCSI_THREAD_SIGNAL_WAKEUP	0x00000002

#define	ISCSI_THREAD_STATE_STOPPED	0x00000001
#define	ISCSI_THREAD_STATE_STOPPING	0x00000002
#define	ISCSI_THREAD_STATE_STARTED	0x00000004
#define	ISCSI_THREAD_STATE_STARTING	0x00000008
#define	ISCSI_THREAD_STATE_DESTROYING	0x00000010

struct _iscsi_thread;

typedef void (*iscsi_thread_ep_t)(struct _iscsi_thread *, void *);

typedef struct _iscsi_thread {
	uint32_t		signature;
	uint32_t		state;
	ddi_taskq_t		*tq;
	iscsi_thread_ep_t	entry_point;
	void			*arg;
	dev_info_t		*dip;
	boolean_t		running;
	struct {
		uint32_t	bitmap;
		kmutex_t	mtx;
		kcondvar_t	cdv;
	} sign;
	struct {
		kmutex_t	mtx;
	} mgnt;
} iscsi_thread_t;

iscsi_thread_t *
iscsi_thread_create(
	dev_info_t		*dip,
	char			*name,
	iscsi_thread_ep_t	entry_point,
	void			*arg
);

void
iscsi_thread_destroy(
	iscsi_thread_t		*thread
);

boolean_t
iscsi_thread_start(
	iscsi_thread_t		*thread
);

boolean_t
iscsi_thread_stop(
	iscsi_thread_t		*thread
);

void
iscsi_thread_send_kill(
	iscsi_thread_t		*thread
);

void
iscsi_thread_send_wakeup(
	iscsi_thread_t		*thread
);

int
iscsi_thread_wait(
	iscsi_thread_t		*thread,
	clock_t			timeout
);

uint32_t
iscsi_thread_check_signals(
	iscsi_thread_t		*thread
);

#ifdef __cplusplus
}
#endif

#endif /* _ISCSI_THREAD_H */
