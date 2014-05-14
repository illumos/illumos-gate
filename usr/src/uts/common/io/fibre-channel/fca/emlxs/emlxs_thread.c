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

#include <emlxs.h>


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_THREAD_C);

static void	emlxs_thread(emlxs_thread_t *ethread);
static void	emlxs_taskq_thread(emlxs_taskq_thread_t *tthread);


static void
emlxs_taskq_thread(emlxs_taskq_thread_t *tthread)
{
	emlxs_taskq_t *taskq;
	void (*func) ();
	void *arg;

	taskq = tthread->taskq;

	mutex_enter(&tthread->lock);
	tthread->flags |= EMLXS_THREAD_STARTED;

	while (!(tthread->flags & EMLXS_THREAD_KILLED)) {
		mutex_enter(&taskq->put_lock);
		tthread->next = taskq->put_head;
		taskq->put_head = tthread;
		taskq->put_count++;
		mutex_exit(&taskq->put_lock);

		tthread->flags |= EMLXS_THREAD_ASLEEP;
		cv_wait(&tthread->cv_flag, &tthread->lock);
		tthread->flags &= ~EMLXS_THREAD_ASLEEP;

		if (tthread->func) {
			func = tthread->func;
			arg = tthread->arg;

			tthread->flags |= EMLXS_THREAD_BUSY;
			mutex_exit(&tthread->lock);

			func(taskq->hba, arg);

			mutex_enter(&tthread->lock);
			tthread->flags &= ~EMLXS_THREAD_BUSY;
		}
	}

	tthread->flags |= EMLXS_THREAD_ENDED;
	mutex_exit(&tthread->lock);

	thread_exit();

} /* emlxs_taskq_thread() */



uint32_t
emlxs_taskq_dispatch(emlxs_taskq_t *taskq, void (*func) (), void *arg)
{
	emlxs_taskq_thread_t *tthread = NULL;

	mutex_enter(&taskq->get_lock);

	/* Make sure taskq is open for business */
	if (!taskq->open) {
		mutex_exit(&taskq->get_lock);
		return (0);
	}

	/* Check get_list for a thread */
	if (taskq->get_head) {
		/* Get the next thread */
		tthread = taskq->get_head;
		taskq->get_count--;
		taskq->get_head = (taskq->get_count) ? tthread->next : NULL;
		tthread->next = NULL;
	}

	/* Else check put_list for a thread */
	else if (taskq->put_head) {

		/* Move put_list to get_list */
		mutex_enter(&taskq->put_lock);
		taskq->get_head = taskq->put_head;
		taskq->get_count = taskq->put_count;
		taskq->put_head = NULL;
		taskq->put_count = 0;
		mutex_exit(&taskq->put_lock);

		/* Get the next thread */
		tthread = taskq->get_head;
		taskq->get_count--;
		taskq->get_head = (taskq->get_count) ? tthread->next : NULL;
		tthread->next = NULL;
	}

	mutex_exit(&taskq->get_lock);

	/* Wake up the thread if one exists */
	if (tthread) {
		mutex_enter(&tthread->lock);
		tthread->func = func;
		tthread->arg = arg;
		cv_signal(&tthread->cv_flag);
		mutex_exit(&tthread->lock);

		return (1);
	}

	return (0);

} /* emlxs_taskq_dispatch() */



void
emlxs_taskq_create(emlxs_hba_t *hba, emlxs_taskq_t *taskq)
{
	emlxs_taskq_thread_t *tthread;
	uint32_t i;


	/* If taskq is already open then quit */
	if (taskq->open) {
		return;
	}

	/* Zero the taskq */
	bzero(taskq, sizeof (emlxs_taskq_t));

	mutex_init(&taskq->get_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	mutex_enter(&taskq->get_lock);

	taskq->hba = hba;

	mutex_init(&taskq->put_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	for (i = 0; i < EMLXS_MAX_TASKQ_THREADS; i++) {
		tthread = &taskq->thread_list[i];
		tthread->taskq = taskq;

		mutex_init(&tthread->lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(hba->intr_arg));

		cv_init(&tthread->cv_flag, NULL, CV_DRIVER, NULL);

		tthread->flags |= EMLXS_THREAD_INITD;
		tthread->thread =
		    thread_create(NULL, 0, emlxs_taskq_thread,
		    (char *)tthread, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	}

	/* Open the taskq */
	taskq->open = 1;

	mutex_exit(&taskq->get_lock);

	return;

} /* emlxs_taskq_create() */


void
emlxs_taskq_destroy(emlxs_taskq_t *taskq)
{
	emlxs_taskq_thread_t *tthread;
	uint32_t i;

	/* If taskq already closed, then quit */
	if (!taskq->open) {
		return;
	}

	mutex_enter(&taskq->get_lock);

	/* If taskq already closed, then quit */
	if (!taskq->open) {
		mutex_exit(&taskq->get_lock);
		return;
	}

	taskq->open = 0;
	mutex_exit(&taskq->get_lock);


	/* No more threads can be dispatched now */

	/* Kill the threads */
	for (i = 0; i < EMLXS_MAX_TASKQ_THREADS; i++) {
		tthread = &taskq->thread_list[i];

		/*
		 * If the thread lock can be acquired,
		 * it is in one of these states:
		 * 1. Thread not started.
		 * 2. Thread asleep.
		 * 3. Thread busy.
		 * 4. Thread ended.
		 */
		mutex_enter(&tthread->lock);
		tthread->flags |= EMLXS_THREAD_KILLED;
		cv_signal(&tthread->cv_flag);

		/* Wait for thread to die */
		while (!(tthread->flags & EMLXS_THREAD_ENDED)) {
			mutex_exit(&tthread->lock);
			delay(drv_usectohz(10000));
			mutex_enter(&tthread->lock);
		}
		mutex_exit(&tthread->lock);

		/* Clean up thread */
		mutex_destroy(&tthread->lock);
		cv_destroy(&tthread->cv_flag);
	}

	/* Clean up taskq */
	mutex_destroy(&taskq->put_lock);
	mutex_destroy(&taskq->get_lock);

	return;

} /* emlxs_taskq_destroy() */



static void
emlxs_thread(emlxs_thread_t *ethread)
{
	emlxs_hba_t *hba;
	void (*func) ();
	void *arg1;
	void *arg2;

	if (ethread->flags & EMLXS_THREAD_RUN_ONCE) {
		hba = ethread->hba;
		ethread->flags |= EMLXS_THREAD_STARTED;

		if (!(ethread->flags & EMLXS_THREAD_KILLED)) {
			func = ethread->func;
			arg1 = ethread->arg1;
			arg2 = ethread->arg2;

			func(hba, arg1, arg2);
		}

		ethread->flags |= EMLXS_THREAD_ENDED;
		ethread->flags &= ~EMLXS_THREAD_INITD;

		/* Remove the thread from the spawn thread list */
		mutex_enter(&EMLXS_SPAWN_LOCK);
		if (hba->spawn_thread_head == ethread)
			hba->spawn_thread_head = ethread->next;
		if (hba->spawn_thread_tail == ethread)
			hba->spawn_thread_tail = ethread->prev;

		if (ethread->prev)
			ethread->prev->next = ethread->next;
		if (ethread->next)
			ethread->next->prev = ethread->prev;

		ethread->next = ethread->prev = NULL;

		kmem_free(ethread, sizeof (emlxs_thread_t));

		mutex_exit(&EMLXS_SPAWN_LOCK);
	}
	else
	{
	/*
	 * If the thread lock can be acquired,
	 * it is in one of these states:
	 * 1. Thread not started.
	 * 2. Thread asleep.
	 * 3. Thread busy.
	 * 4. Thread ended.
	 */
	mutex_enter(&ethread->lock);
	ethread->flags |= EMLXS_THREAD_STARTED;

	while (!(ethread->flags & EMLXS_THREAD_KILLED)) {
		if (!(ethread->flags & EMLXS_THREAD_TRIGGERED)) {
			ethread->flags |= EMLXS_THREAD_ASLEEP;
			cv_wait(&ethread->cv_flag, &ethread->lock);
		}

		ethread->flags &=
		    ~(EMLXS_THREAD_ASLEEP | EMLXS_THREAD_TRIGGERED);

		if (ethread->func) {
			func = ethread->func;
			arg1 = ethread->arg1;
			arg2 = ethread->arg2;
			ethread->func = NULL;
			ethread->arg1 = NULL;
			ethread->arg2 = NULL;

			ethread->flags |= EMLXS_THREAD_BUSY;
			mutex_exit(&ethread->lock);

			func(ethread->hba, arg1, arg2);

			mutex_enter(&ethread->lock);
			ethread->flags &= ~EMLXS_THREAD_BUSY;
		}
	}

	ethread->flags |= EMLXS_THREAD_ENDED;
	mutex_exit(&ethread->lock);
	}

	thread_exit();

} /* emlxs_thread() */


void
emlxs_thread_create(emlxs_hba_t *hba, emlxs_thread_t *ethread)
{
	uint16_t pri;

	if (ethread->flags & EMLXS_THREAD_INITD) {
		return;
	}

	bzero(ethread, sizeof (emlxs_thread_t));

	mutex_init(&ethread->lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(hba->intr_arg));

	cv_init(&ethread->cv_flag, NULL, CV_DRIVER, NULL);

	ethread->hba = hba;
	ethread->flags |= EMLXS_THREAD_INITD;

	pri = v.v_maxsyspri - 2;

	ethread->thread =
	    thread_create(NULL, 0, emlxs_thread, (char *)ethread, 0, &p0,
	    TS_RUN, pri);

} /* emlxs_thread_create() */


void
emlxs_thread_destroy(emlxs_thread_t *ethread)
{
	/*
	 * If the thread lock can be acquired,
	 * it is in one of these states:
	 * 1. Thread not started.
	 * 2. Thread asleep.
	 * 3. Thread busy.
	 * 4. Thread ended.
	 */
	if (!(ethread->flags & EMLXS_THREAD_INITD)) {
		return;
	}


	mutex_enter(&ethread->lock);

	if (ethread->flags & EMLXS_THREAD_ENDED) {
		mutex_exit(&ethread->lock);
		return;
	}

	ethread->flags &= ~EMLXS_THREAD_INITD;
	ethread->flags |= (EMLXS_THREAD_KILLED | EMLXS_THREAD_TRIGGERED);
	ethread->func = NULL;
	ethread->arg1 = NULL;
	ethread->arg2 = NULL;
	cv_signal(&ethread->cv_flag);

	/* Wait for thread to end */
	while (!(ethread->flags & EMLXS_THREAD_ENDED)) {
		mutex_exit(&ethread->lock);
		delay(drv_usectohz(10000));
		mutex_enter(&ethread->lock);
	}

	mutex_exit(&ethread->lock);

	cv_destroy(&ethread->cv_flag);
	mutex_destroy(&ethread->lock);

	return;

} /* emlxs_thread_destroy() */


void
emlxs_thread_trigger1(emlxs_thread_t *ethread, void (*func) ())
{

	/*
	 * If the thread lock can be acquired,
	 * it is in one of these states:
	 * 1. Thread not started.
	 * 2. Thread asleep.
	 * 3. Thread busy.
	 * 4. Thread ended.
	 */
	if (!(ethread->flags & EMLXS_THREAD_INITD)) {
		return;
	}

	mutex_enter(&ethread->lock);

	if (ethread->flags & EMLXS_THREAD_ENDED) {
		return;
	}

	while (!(ethread->flags & EMLXS_THREAD_STARTED)) {
		mutex_exit(&ethread->lock);
		delay(drv_usectohz(10000));
		mutex_enter(&ethread->lock);

		if (ethread->flags & EMLXS_THREAD_ENDED) {
			return;
		}
	}

	ethread->flags |= EMLXS_THREAD_TRIGGERED;
	ethread->func = func;
	ethread->arg1 = NULL;
	ethread->arg2 = NULL;

	if (ethread->flags & EMLXS_THREAD_ASLEEP) {
		cv_signal(&ethread->cv_flag);
	}

	mutex_exit(&ethread->lock);

	return;

} /* emlxs_thread_trigger1() */


void
emlxs_thread_trigger2(emlxs_thread_t *ethread, void (*func) (), CHANNEL *cp)
{

	/*
	 * If the thread lock can be acquired,
	 * it is in one of these states:
	 * 1. Thread not started.
	 * 2. Thread asleep.
	 * 3. Thread busy.
	 * 4. Thread ended.
	 */
	if (!(ethread->flags & EMLXS_THREAD_INITD)) {
		return;
	}

	mutex_enter(&ethread->lock);

	if (ethread->flags & EMLXS_THREAD_ENDED) {
		return;
	}

	while (!(ethread->flags & EMLXS_THREAD_STARTED)) {
		mutex_exit(&ethread->lock);
		delay(drv_usectohz(10000));
		mutex_enter(&ethread->lock);

		if (ethread->flags & EMLXS_THREAD_ENDED) {
			return;
		}
	}

	ethread->flags |= EMLXS_THREAD_TRIGGERED;
	ethread->func = func;
	ethread->arg1 = (void *)cp;
	ethread->arg2 = NULL;

	if (ethread->flags & EMLXS_THREAD_ASLEEP) {
		cv_signal(&ethread->cv_flag);
	}

	mutex_exit(&ethread->lock);

	return;

} /* emlxs_thread_trigger2() */


void
emlxs_thread_spawn(emlxs_hba_t *hba, void (*func) (), void *arg1, void *arg2)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_thread_t	*ethread;

	/* Create a thread */
	ethread = (emlxs_thread_t *)kmem_alloc(sizeof (emlxs_thread_t),
	    KM_NOSLEEP);

	if (ethread == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "Unable to allocate thread object.");

		return;
	}

	bzero(ethread, sizeof (emlxs_thread_t));
	ethread->hba = hba;
	ethread->flags = EMLXS_THREAD_INITD | EMLXS_THREAD_RUN_ONCE;
	ethread->func = func;
	ethread->arg1 = arg1;
	ethread->arg2 = arg2;

	/* Queue the thread on the spawn thread list */
	mutex_enter(&EMLXS_SPAWN_LOCK);

	/* Dont spawn the thread if the spawn list is closed */
	if (hba->spawn_open == 0) {
		mutex_exit(&EMLXS_SPAWN_LOCK);

		/* destroy the thread */
		kmem_free(ethread, sizeof (emlxs_thread_t));
		return;
	}

	if (hba->spawn_thread_head == NULL) {
		hba->spawn_thread_head = ethread;
	}
	else
	{
		hba->spawn_thread_tail->next = ethread;
		ethread->prev = hba->spawn_thread_tail;
	}

	hba->spawn_thread_tail = ethread;
	mutex_exit(&EMLXS_SPAWN_LOCK);

	(void) thread_create(NULL, 0, &emlxs_thread, (char *)ethread, 0, &p0,
	    TS_RUN, v.v_maxsyspri - 2);

} /* emlxs_thread_spawn() */


void
emlxs_thread_spawn_create(emlxs_hba_t *hba)
{
	mutex_enter(&EMLXS_SPAWN_LOCK);
	if (hba->spawn_open) {
		mutex_exit(&EMLXS_SPAWN_LOCK);
		return;
	}

	hba->spawn_thread_head = NULL;
	hba->spawn_thread_tail = NULL;

	hba->spawn_open = 1;
	mutex_exit(&EMLXS_SPAWN_LOCK);

}


void
emlxs_thread_spawn_destroy(emlxs_hba_t *hba)
{
	emlxs_thread_t	*ethread;

	mutex_enter(&EMLXS_SPAWN_LOCK);
	if (hba->spawn_open == 0) {
		mutex_exit(&EMLXS_SPAWN_LOCK);
		return;
	}

	hba->spawn_open = 0;

	for (ethread = hba->spawn_thread_head; ethread;
	    ethread = ethread->next) {
		ethread->flags |= EMLXS_THREAD_KILLED;
	}

	/* Wait for all the spawned threads to complete */
	while (hba->spawn_thread_head) {
		mutex_exit(&EMLXS_SPAWN_LOCK);
		delay(drv_usectohz(10000));
		mutex_enter(&EMLXS_SPAWN_LOCK);
	}

	mutex_exit(&EMLXS_SPAWN_LOCK);
}
