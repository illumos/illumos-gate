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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2008 Denis Cheng
 */

#include "config.h"
#include <pthread.h>
#ifdef HAVE_LWPS
#include <sys/lwp.h>
#endif
#include <signal.h>

#include "filebench.h"
#include "threadflow.h"
#include "flowop.h"
#include "ipc.h"

static threadflow_t *threadflow_define_common(procflow_t *procflow,
    char *name, threadflow_t *inherit, int instance);

/*
 * Threadflows are filebench entities which manage operating system
 * threads. Each worker threadflow spawns a separate filebench thread,
 * with attributes inherited from a FLOW_MASTER threadflow created during
 * f model language parsing. This section contains routines to define,
 * create, control, and delete threadflows.
 *
 * Each thread defined in the f model creates a FLOW_MASTER
 * threadflow which encapsulates the defined attributes and flowops of
 * the f language thread, including the number of instances to create.
 * At runtime, a worker threadflow instance with an associated filebench
 * thread is created, which runs until told to quit or is specifically
 * deleted.
 */


/*
 * Prints information about threadflow syntax.
 */
void
threadflow_usage(void)
{
	(void) fprintf(stderr, "  thread  name=<name>[,instances=<count>]\n");
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "  {\n");
	(void) fprintf(stderr, "    flowop ...\n");
	(void) fprintf(stderr, "    flowop ...\n");
	(void) fprintf(stderr, "    flowop ...\n");
	(void) fprintf(stderr, "  }\n");
	(void) fprintf(stderr, "\n");
}

/*
 * Creates a thread for the supplied threadflow. If interprocess
 * shared memory is desired, then increments the amount of shared
 * memory needed by the amount specified in the threadflow's
 * tf_memsize parameter. The thread starts in routine
 * flowop_start() with a poineter to the threadflow supplied
 * as the argument.
 */
static int
threadflow_createthread(threadflow_t *threadflow)
{
	fbint_t memsize;
	memsize = avd_get_int(threadflow->tf_memsize);
	threadflow->tf_constmemsize = memsize;

	filebench_log(LOG_DEBUG_SCRIPT, "Creating thread %s, memory = %ld",
	    threadflow->tf_name, memsize);

	if (threadflow->tf_attrs & THREADFLOW_USEISM)
		filebench_shm->shm_required += memsize;

	if (pthread_create(&threadflow->tf_tid, NULL,
	    (void *(*)(void*))flowop_start, threadflow) != 0) {
		filebench_log(LOG_ERROR, "thread create failed");
		filebench_shutdown(1);
		return (FILEBENCH_ERROR);
	}

	return (FILEBENCH_OK);
}

/*
 * Creates threads for the threadflows associated with a procflow.
 * The routine iterates through the list of threadflows in the
 * supplied procflow's pf_threads list. For each threadflow on
 * the list, it defines tf_instances number of cloned
 * threadflows, and then calls threadflow_createthread() for
 * each to create and start the actual operating system thread.
 * Note that each of the newly defined threadflows will be linked
 * into the procflows threadflow list, but at the head of the
 * list, so they will not become part of the supplied set. After
 * all the threads have been created, threadflow_init enters
 * a join loop for all the threads in the newly defined
 * threadflows. Once all the created threads have exited,
 * threadflow_init will return 0. If errors are encountered, it
 * will return a non zero value.
 */
int
threadflow_init(procflow_t *procflow)
{
	threadflow_t *threadflow = procflow->pf_threads;
	int ret = 0;

	(void) ipc_mutex_lock(&filebench_shm->shm_threadflow_lock);

	while (threadflow) {
		threadflow_t *newthread;
		int instances;
		int i;

		instances = avd_get_int(threadflow->tf_instances);
		filebench_log(LOG_VERBOSE,
		    "Starting %d %s threads",
		    instances, threadflow->tf_name);

		for (i = 1; i < instances; i++) {
			/* Create threads */
			newthread =
			    threadflow_define_common(procflow,
			    threadflow->tf_name, threadflow, i + 1);
			if (newthread == NULL)
				return (-1);
			ret |= threadflow_createthread(newthread);
		}

		newthread = threadflow_define_common(procflow,
		    threadflow->tf_name,
		    threadflow, 1);

		if (newthread == NULL)
			return (-1);

		/* Create each thread */
		ret |= threadflow_createthread(newthread);

		threadflow = threadflow->tf_next;
	}

	threadflow = procflow->pf_threads;

	(void) ipc_mutex_unlock(&filebench_shm->shm_threadflow_lock);

	while (threadflow) {
		/* wait for all threads to finish */
		if (threadflow->tf_tid) {
			void *status;

			if (pthread_join(threadflow->tf_tid, &status) == 0)
				ret += *(int *)status;
		}
		threadflow = threadflow->tf_next;
	}

	procflow->pf_running = 0;

	return (ret);
}

/*
 * Tells the threadflow's thread to stop and optionally signals
 * its associated process to end the thread.
 */
static void
threadflow_kill(threadflow_t *threadflow)
{
	int wait_cnt = 2;

	/* Tell thread to finish */
	threadflow->tf_abort = 1;

	/* wait a bit for threadflow to stop */
	while (wait_cnt && threadflow->tf_running) {
		(void) sleep(1);
		wait_cnt--;
	}

	if (threadflow->tf_running) {
		threadflow->tf_running = FALSE;
		pthread_kill(threadflow->tf_tid, SIGKILL);
	}
}

/*
 * Deletes the specified threadflow from the specified threadflow
 * list after first terminating the threadflow's thread, deleting
 * the threadflow's flowops, and finally freeing the threadflow
 * entity. It also subtracts the threadflow's shared memory
 * requirements from the total amount required, shm_required. If
 * the specified threadflow is found, returns 0, otherwise
 * returns -1.
 */
static int
threadflow_delete(threadflow_t **threadlist, threadflow_t *threadflow)
{
	threadflow_t *entry = *threadlist;

	filebench_log(LOG_DEBUG_IMPL, "Deleting thread: (%s-%d)",
	    threadflow->tf_name,
	    threadflow->tf_instance);

	if (threadflow->tf_attrs & THREADFLOW_USEISM)
		filebench_shm->shm_required -= threadflow->tf_constmemsize;

	if (threadflow == *threadlist) {
		/* First on list */
		filebench_log(LOG_DEBUG_IMPL, "Deleted thread: (%s-%d)",
		    threadflow->tf_name,
		    threadflow->tf_instance);

		threadflow_kill(threadflow);
		flowop_delete_all(&threadflow->tf_thrd_fops);
		*threadlist = threadflow->tf_next;
		(void) pthread_mutex_destroy(&threadflow->tf_lock);
		ipc_free(FILEBENCH_THREADFLOW, (char *)threadflow);
		return (0);
	}

	while (entry->tf_next) {
		filebench_log(LOG_DEBUG_IMPL,
		    "Delete thread: (%s-%d) == (%s-%d)",
		    entry->tf_next->tf_name,
		    entry->tf_next->tf_instance,
		    threadflow->tf_name,
		    threadflow->tf_instance);

		if (threadflow == entry->tf_next) {
			/* Delete */
			filebench_log(LOG_DEBUG_IMPL,
			    "Deleted thread: (%s-%d)",
			    entry->tf_next->tf_name,
			    entry->tf_next->tf_instance);
			threadflow_kill(entry->tf_next);
			flowop_delete_all(&entry->tf_next->tf_thrd_fops);
			(void) pthread_mutex_destroy(&threadflow->tf_lock);
			ipc_free(FILEBENCH_THREADFLOW, (char *)threadflow);
			entry->tf_next = entry->tf_next->tf_next;
			return (0);
		}
		entry = entry->tf_next;
	}

	return (-1);
}

/*
 * Given a pointer to the thread list of a procflow, cycles
 * through all the threadflows on the list, deleting each one
 * except the FLOW_MASTER.
 */
void
threadflow_delete_all(threadflow_t **threadlist)
{
	threadflow_t *threadflow;

	(void) ipc_mutex_lock(&filebench_shm->shm_threadflow_lock);

	threadflow = *threadlist;
	filebench_log(LOG_DEBUG_IMPL, "Deleting all threads");

	while (threadflow) {
		if (threadflow->tf_instance &&
		    (threadflow->tf_instance == FLOW_MASTER)) {
			threadflow = threadflow->tf_next;
			continue;
		}
		(void) threadflow_delete(threadlist, threadflow);
		threadflow = threadflow->tf_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_threadflow_lock);
}

/*
 * Waits till all threadflows are started, or a timeout occurs.
 * Checks through the list of threadflows, waiting up to 10
 * seconds for each one to set its tf_running flag to 1. If not
 * set after 10 seconds, continues on to the next threadflow
 * anyway.
 */
void
threadflow_allstarted(pid_t pid, threadflow_t *threadflow)
{
	(void) ipc_mutex_lock(&filebench_shm->shm_threadflow_lock);

	while (threadflow) {
		int waits;

		if ((threadflow->tf_instance == 0) ||
		    (threadflow->tf_instance == FLOW_MASTER)) {
			threadflow = threadflow->tf_next;
			continue;
		}

		filebench_log(LOG_DEBUG_IMPL, "Checking pid %d thread %s-%d",
		    pid,
		    threadflow->tf_name,
		    threadflow->tf_instance);

		waits = 10;
		while (waits && (threadflow->tf_running == 0) &&
		    (filebench_shm->shm_f_abort == 0)) {
			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_threadflow_lock);
			if (waits < 3)
				filebench_log(LOG_INFO,
				    "Waiting for pid %d thread %s-%d",
				    pid,
				    threadflow->tf_name,
				    threadflow->tf_instance);

			(void) sleep(1);
			(void) ipc_mutex_lock(
			    &filebench_shm->shm_threadflow_lock);
			waits--;
		}

		threadflow = threadflow->tf_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_threadflow_lock);
}

/*
 * Create an in-memory thread object linked to a parent procflow.
 * A threadflow entity is allocated from shared memory and
 * initialized from the "inherit" threadflow if supplied,
 * otherwise to zeros. The threadflow is assigned a unique
 * thread id, the supplied instance number, the supplied name
 * and added to the procflow's pf_thread list. If no name is
 * supplied or the threadflow can't be allocated, NULL is
 * returned Otherwise a pointer to the newly allocated threadflow
 * is returned.
 *
 * The filebench_shm->shm_threadflow_lock must be held by the caller.
 */
static threadflow_t *
threadflow_define_common(procflow_t *procflow, char *name,
    threadflow_t *inherit, int instance)
{
	threadflow_t *threadflow;
	threadflow_t **threadlistp = &procflow->pf_threads;

	if (name == NULL)
		return (NULL);

	threadflow = (threadflow_t *)ipc_malloc(FILEBENCH_THREADFLOW);

	if (threadflow == NULL)
		return (NULL);

	if (inherit)
		(void) memcpy(threadflow, inherit, sizeof (threadflow_t));
	else
		(void) memset(threadflow, 0, sizeof (threadflow_t));

	threadflow->tf_utid = ++filebench_shm->shm_utid;

	threadflow->tf_instance = instance;
	(void) strcpy(threadflow->tf_name, name);
	threadflow->tf_process = procflow;
	(void) pthread_mutex_init(&threadflow->tf_lock,
	    ipc_mutexattr(IPC_MUTEX_NORMAL));

	filebench_log(LOG_DEBUG_IMPL, "Defining thread %s-%d",
	    name, instance);

	/* Add threadflow to list */
	if (*threadlistp == NULL) {
		*threadlistp = threadflow;
		threadflow->tf_next = NULL;
	} else {
		threadflow->tf_next = *threadlistp;
		*threadlistp = threadflow;
	}

	return (threadflow);
}

/*
 * Create an in memory FLOW_MASTER thread object as described
 * by the syntax. Acquire the  filebench_shm->shm_threadflow_lock and
 * call threadflow_define_common() to create a threadflow entity.
 * Set the number of instances to create at runtime,
 * tf_instances, to "instances". Return the threadflow pointer
 * returned by the threadflow_define_common call.
 */
threadflow_t *
threadflow_define(procflow_t *procflow, char *name,
    threadflow_t *inherit, avd_t instances)
{
	threadflow_t *threadflow;

	(void) ipc_mutex_lock(&filebench_shm->shm_threadflow_lock);

	if ((threadflow = threadflow_define_common(procflow, name,
	    inherit, FLOW_MASTER)) == NULL)
		return (NULL);

	threadflow->tf_instances = instances;

	(void) ipc_mutex_unlock(&filebench_shm->shm_threadflow_lock);

	return (threadflow);
}


/*
 * Searches the provided threadflow list for the named threadflow.
 * A pointer to the threadflow is returned, or NULL if threadflow
 * is not found.
 */
threadflow_t *
threadflow_find(threadflow_t *threadlist, char *name)
{
	threadflow_t *threadflow = threadlist;

	(void) ipc_mutex_lock(&filebench_shm->shm_threadflow_lock);

	while (threadflow) {
		if (strcmp(name, threadflow->tf_name) == 0) {

			(void) ipc_mutex_unlock(
			    &filebench_shm->shm_threadflow_lock);

			return (threadflow);
		}
		threadflow = threadflow->tf_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_threadflow_lock);


	return (NULL);
}
