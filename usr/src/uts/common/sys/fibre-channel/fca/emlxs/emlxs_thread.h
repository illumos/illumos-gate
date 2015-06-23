/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_THREAD_H
#define	_EMLXS_THREAD_H

#ifdef	__cplusplus
extern "C" {
#endif


#define	EMLXS_MAX_TASKQ_THREADS	4

typedef struct emlxs_thread
{
	struct emlxs_thread	*next;
	struct emlxs_thread	*prev;

	struct emlxs_hba	*hba;

	kthread_t		*thread;
	uint32_t		flags;

	void			(*func) (void *);
	void			*arg1;
	void			*arg2;

	kmutex_t		lock;
	kcondvar_t		cv_flag;
} emlxs_thread_t;


typedef struct emlxs_taskq_thread
{
	struct emlxs_taskq_thread	*next;
	struct emlxs_taskq		*taskq;

	kthread_t			*thread;
	uint32_t			flags;

	void				(*func) (void *);
	void				*arg;

	kmutex_t			lock;
	kcondvar_t			cv_flag;
} emlxs_taskq_thread_t;


typedef struct emlxs_taskq
{
	emlxs_taskq_thread_t	thread_list[EMLXS_MAX_TASKQ_THREADS];

	void			*hba;

	emlxs_taskq_thread_t	*get_head;
	uint32_t		get_count;
	uint32_t		open;
	kmutex_t		get_lock;

	emlxs_taskq_thread_t	*put_head;
	uint32_t		put_count;
	kmutex_t		put_lock;
} emlxs_taskq_t;

/* flags */
#define	EMLXS_THREAD_INITD	0x00000001
#define	EMLXS_THREAD_STARTED	0x00000002
#define	EMLXS_THREAD_ASLEEP	0x00000004
#define	EMLXS_THREAD_BUSY	0x00000008
#define	EMLXS_THREAD_KILLED	0x00000010
#define	EMLXS_THREAD_ENDED	0x00000020
#define	EMLXS_THREAD_TRIGGERED	0x80000000
#define	EMLXS_THREAD_RUN_ONCE	0x00000100

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_THREAD_H */
