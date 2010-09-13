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

#ifndef	_SIGEV_THREAD_H
#define	_SIGEV_THREAD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <signal.h>
#include <port.h>
#include <mqueue.h>
#include <time.h>
#include <limits.h>
#include <semaphore.h>
#include <thread_pool.h>

#define	SIGEV_THREAD_TERM	1

typedef enum {TIMER = 1, MQ, AIO} subsystem_t;	/* Calling sub-system */

typedef struct {
	void (*std_func)(union sigval);	/* User-defined notification function */
	union sigval std_arg;	/* Parameter of user-defined notification fct */
} sigev_thread_data_t;

typedef struct thread_communication_data {
	struct thread_communication_data *tcd_next;
	struct sigevent	tcd_notif;	/* encapsulates usr fct and usr vals */
	pthread_attr_t	tcd_user_attr;	/* copy of caller's attributes */
	pthread_attr_t	*tcd_attrp;	/* NULL if caller passed NULL */
	int		tcd_port;	/* port this spawner is controlling */
	thread_t	tcd_server_id;	/* thread id of server thread */
	subsystem_t	tcd_subsystem;	/* event generating subsystem */
	tpool_t		*tcd_poolp;	/* worker thread pool */
	/* for creation/termination synchronization protocol */
	mutex_t		tcd_lock;
	cond_t		tcd_cv;
	/* subsystem-specific data */
	union {
		struct {
			int	overruns;	/* number of overruns */
		} timer;
		struct {
			int	msg_enabled;	/* notification enabled */
			int	msg_closing;	/* mq_close() is waiting */
			sem_t	*msg_avail;	/* wait for message available */
			void	*msg_object;	/* mqd_t */
			void	*msg_userval;	/* notification user value */
		} mqueue;
	} tcd_object;
} thread_communication_data_t;

#define	tcd_overruns	tcd_object.timer.overruns

#define	tcd_msg_enabled	tcd_object.mqueue.msg_enabled
#define	tcd_msg_closing	tcd_object.mqueue.msg_closing
#define	tcd_msg_avail	tcd_object.mqueue.msg_avail
#define	tcd_msg_object	tcd_object.mqueue.msg_object
#define	tcd_msg_userval	tcd_object.mqueue.msg_userval

/* Generic functions common to all entities */
extern thread_communication_data_t *setup_sigev_handler(
		const struct sigevent *, subsystem_t);
extern void free_sigev_handler(thread_communication_data_t *);
extern int launch_spawner(thread_communication_data_t *);
extern void tcd_teardown(thread_communication_data_t *);

/* Additional functions for different entities */
extern void *timer_spawner(void *);
extern int del_sigev_timer(timer_t);
extern int sigev_timer_getoverrun(timer_t);
extern void *mqueue_spawner(void *);
extern void del_sigev_mq(thread_communication_data_t *);
extern void *aio_spawner(void *);

/* Private interfaces elsewhere in libc */
extern int pthread_attr_clone(pthread_attr_t *, const pthread_attr_t *);
extern int pthread_attr_equal(const pthread_attr_t *, const pthread_attr_t *);
extern int _port_dispatch(int, int, int, int, uintptr_t, void *);

extern thread_communication_data_t *sigev_aio_tcd;

extern int timer_max;
extern thread_communication_data_t **timer_tcd;

#ifdef	__cplusplus
}
#endif

#endif	/* _SIGEV_THREAD_H */
