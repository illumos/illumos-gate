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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#ifdef HAVE_LWPS
#include <sys/lwp.h>
#endif
#include <fcntl.h>
#include "filebench.h"
#include "flowop.h"
#include "stats.h"

#ifdef LINUX_PORT
#include <sys/types.h>
#include <linux/unistd.h>
#endif

static flowop_t *flowop_define_common(threadflow_t *threadflow, char *name,
	flowop_t *inherit, int instance, int type);


/*
 * A collection of flowop support functions. The actual code that
 * implements the various flowops is in flowop_library.c.
 *
 * Routines for defining, creating, initializing and destroying
 * flowops, cyclically invoking the flowops on each threadflow's flowop
 * list, collecting statistics about flowop execution, and other
 * housekeeping duties are included in this file.
 */


/*
 * Prints the name and instance number of each flowop in
 * the supplied list to the filebench log.
 */
int
flowop_printlist(flowop_t *list)
{
	flowop_t *flowop = list;

	while (flowop) {
		filebench_log(LOG_DEBUG_IMPL, "flowop-list %s-%d",
		    flowop->fo_name, flowop->fo_instance);
		flowop = flowop->fo_threadnext;
	}
	return (0);
}

#define	TIMESPEC_TO_HRTIME(s, e) (((e.tv_sec - s.tv_sec) * 1000000000LL) + \
					(e.tv_nsec - s.tv_nsec))
/*
 * Puts current high resolution time in start time entry
 * for threadflow and may also calculate running filebench
 * overhead statistics.
 */
void
flowop_beginop(threadflow_t *threadflow, flowop_t *flowop)
{
#ifdef HAVE_PROCFS
	if ((noproc == 0) && (threadflow->tf_lwpusagefd == 0)) {
		char procname[128];

		(void) snprintf(procname, sizeof (procname),
		    "/proc/%d/lwp/%d/lwpusage", pid, _lwp_self());
		threadflow->tf_lwpusagefd = open(procname, O_RDONLY);
	}

	(void) pread(threadflow->tf_lwpusagefd,
	    &threadflow->tf_susage,
	    sizeof (struct prusage), 0);

	/* Compute overhead time in this thread around op */
	if (threadflow->tf_eusage.pr_stime.tv_nsec) {
		flowop->fo_stats.fs_mstate[FLOW_MSTATE_OHEAD] +=
		    TIMESPEC_TO_HRTIME(threadflow->tf_eusage.pr_utime,
		    threadflow->tf_susage.pr_utime) +
		    TIMESPEC_TO_HRTIME(threadflow->tf_eusage.pr_ttime,
		    threadflow->tf_susage.pr_ttime) +
		    TIMESPEC_TO_HRTIME(threadflow->tf_eusage.pr_stime,
		    threadflow->tf_susage.pr_stime);
	}
#endif
	/* Start of op for this thread */
	threadflow->tf_stime = gethrtime();
}

flowstat_t controlstats;
static int controlstats_zeroed = 0;

/*
 * Updates flowop's latency statistics, using saved start
 * time and current high resolution time. Updates flowop's
 * io count and transferred bytes statistics. Also updates
 * threadflow's and flowop's cumulative read or write byte
 * and io count statistics.
 */
void
flowop_endop(threadflow_t *threadflow, flowop_t *flowop)
{
	hrtime_t t;

	flowop->fo_stats.fs_mstate[FLOW_MSTATE_LAT] +=
	    (gethrtime() - threadflow->tf_stime);
#ifdef HAVE_PROCFS
	if ((pread(threadflow->tf_lwpusagefd, &threadflow->tf_eusage,
	    sizeof (struct prusage), 0)) != sizeof (struct prusage))
		filebench_log(LOG_ERROR, "cannot read /proc");

	t =
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_utime,
	    threadflow->tf_eusage.pr_utime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_ttime,
	    threadflow->tf_eusage.pr_ttime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_stime,
	    threadflow->tf_eusage.pr_stime);
	flowop->fo_stats.fs_mstate[FLOW_MSTATE_CPU] += t;

	flowop->fo_stats.fs_mstate[FLOW_MSTATE_WAIT] +=
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_tftime,
	    threadflow->tf_eusage.pr_tftime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_dftime,
	    threadflow->tf_eusage.pr_dftime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_kftime,
	    threadflow->tf_eusage.pr_kftime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_kftime,
	    threadflow->tf_eusage.pr_kftime) +
	    TIMESPEC_TO_HRTIME(threadflow->tf_susage.pr_slptime,
	    threadflow->tf_eusage.pr_slptime);
#endif

	flowop->fo_stats.fs_count++;
	flowop->fo_stats.fs_bytes += *flowop->fo_iosize;
	if ((flowop->fo_type & FLOW_TYPE_IO) ||
	    (flowop->fo_type & FLOW_TYPE_AIO)) {
		controlstats.fs_count++;
		controlstats.fs_bytes += *flowop->fo_iosize;
	}
	if (flowop->fo_attrs & FLOW_ATTR_READ) {
		threadflow->tf_stats.fs_rbytes += *flowop->fo_iosize;
		threadflow->tf_stats.fs_rcount++;
		flowop->fo_stats.fs_rcount++;
		controlstats.fs_rbytes += *flowop->fo_iosize;
		controlstats.fs_rcount++;
	} else if (flowop->fo_attrs & FLOW_ATTR_WRITE) {
		threadflow->tf_stats.fs_wbytes += *flowop->fo_iosize;
		threadflow->tf_stats.fs_wcount++;
		flowop->fo_stats.fs_wcount++;
		controlstats.fs_wbytes += *flowop->fo_iosize;
		controlstats.fs_wcount++;
	}
}

/*
 * Calls the flowop's initialization function, pointed to by
 * flowop->fo_init.
 */
static int
flowop_initflow(flowop_t *flowop)
{
	if ((*flowop->fo_init)(flowop) < 0) {
		filebench_log(LOG_ERROR, "flowop %s-%d init failed",
		    flowop->fo_name, flowop->fo_instance);
		return (-1);
	}
	return (0);
}

/*
 * The final initialization and main execution loop for the
 * worker threads. Sets threadflow and flowop start times,
 * waits for all process to start, then creates the runtime
 * flowops from those defined by the F language workload
 * script. It does some more initialization, then enters a
 * loop to repeatedly execute the flowops on the flowop list
 * until an abort condition is detected, at which time it exits.
 * This is the starting routine for the new worker thread
 * created by threadflow_createthread(), and is not currently
 * called from anywhere else.
 */
void
flowop_start(threadflow_t *threadflow)
{
	flowop_t *flowop;
	size_t memsize;
	int ret = 0;

	pid = getpid();

#ifdef HAVE_PROCFS
	if (noproc == 0) {
		char procname[128];
		long ctl[2] = {PCSET, PR_MSACCT};
		int pfd;

		(void) snprintf(procname, sizeof (procname),
		    "/proc/%d/lwp/%d/lwpctl", pid, _lwp_self());
		pfd = open(procname, O_WRONLY);
		(void) pwrite(pfd, &ctl, sizeof (ctl), 0);
		(void) close(pfd);
	}
#endif

	if (!controlstats_zeroed) {
		(void) memset(&controlstats, 0, sizeof (controlstats));
		controlstats_zeroed = 1;
	}

	flowop = threadflow->tf_ops;
	threadflow->tf_stats.fs_stime = gethrtime();
	flowop->fo_stats.fs_stime = gethrtime();

	/* Hold the flowop find lock as reader to prevent lookups */
	(void) pthread_rwlock_rdlock(&filebench_shm->flowop_find_lock);

	/*
	 * Block until all processes have started, acting like
	 * a barrier. The original filebench process initially
	 * holds the run_lock as a reader, preventing any of the
	 * threads from obtaining the writer lock, and hence
	 * passing this point. Once all processes and threads
	 * have been created, the original process unlocks
	 * run_lock, allowing each waiting thread to lock
	 * and then immediately unlock it, then begin running.
	 */
	(void) pthread_rwlock_wrlock(&filebench_shm->run_lock);
	(void) pthread_rwlock_unlock(&filebench_shm->run_lock);

	/* Create the runtime flowops from those defined by the script */
	(void) ipc_mutex_lock(&filebench_shm->flowop_lock);
	while (flowop) {
		flowop_t *newflowop;

		if (flowop == threadflow->tf_ops)
			threadflow->tf_ops = NULL;
		newflowop = flowop_define_common(threadflow, flowop->fo_name,
		    flowop, 1, 0);
		if (newflowop == NULL)
			return;
		if (flowop_initflow(newflowop) < 0) {
			filebench_log(LOG_ERROR, "Flowop init of %s failed",
			    newflowop->fo_name);
		}
		flowop = flowop->fo_threadnext;
	}
	(void) ipc_mutex_unlock(&filebench_shm->flowop_lock);

	/* Release the find lock as reader to allow lookups */
	(void) pthread_rwlock_unlock(&filebench_shm->flowop_find_lock);

	/* Set to the start of the new flowop list */
	flowop = threadflow->tf_ops;

	threadflow->tf_abort = 0;
	threadflow->tf_running = 1;

	/* If we are going to use ISM, allocate later */
	if (threadflow->tf_attrs & THREADFLOW_USEISM) {
		threadflow->tf_mem =
		    ipc_ismmalloc((size_t)*threadflow->tf_memsize);
	} else {
		threadflow->tf_mem = malloc((size_t)*threadflow->tf_memsize);
	}

	memsize = *threadflow->tf_memsize;
	(void) memset(threadflow->tf_mem, 0, memsize);
	filebench_log(LOG_DEBUG_SCRIPT, "Thread allocated %d bytes", memsize);

#ifdef HAVE_LWPS
	filebench_log(LOG_DEBUG_SCRIPT, "Thread %zx (%d) started",
	    threadflow,
	    _lwp_self());
#endif

	/* Main filebench worker loop */
	/* CONSTCOND */
	while (1) {
		int i;

		/* Abort if asked */
		if (threadflow->tf_abort || filebench_shm->f_abort) {
			(void) ipc_mutex_lock(&threadflow->tf_lock);
			threadflow->tf_running = 0;
			(void) ipc_mutex_unlock(&threadflow->tf_lock);
			break;
		}

		/* Be quiet while stats are gathered */
		if (filebench_shm->bequiet) {
			(void) sleep(1);
			continue;
		}

		/* Take it easy until everyone is ready to go */
		if (!filebench_shm->allrunning)
			(void) sleep(1);

		if (flowop->fo_stats.fs_stime == 0)
			flowop->fo_stats.fs_stime = gethrtime();

		if (flowop == NULL) {
			filebench_log(LOG_ERROR, "flowop_read null flowop");
			return;
		}

		if (threadflow->tf_memsize == 0) {
			filebench_log(LOG_ERROR,
			    "Zero memory size for thread %s",
			    threadflow->tf_name);
			return;
		}

		filebench_log(LOG_DEBUG_SCRIPT, "%s: executing flowop %s-%d",
		    threadflow->tf_name, flowop->fo_name, flowop->fo_instance);

		/* Execute the flowop for fo_iters times */
		for (i = 0; i < *flowop->fo_iters; i++) {
			filebench_log(LOG_DEBUG_SCRIPT, "%s: executing flowop "
			    "%s-%d", threadflow->tf_name, flowop->fo_name,
			    flowop->fo_instance);
			ret = (*flowop->fo_func)(threadflow, flowop);
			filebench_log(LOG_DEBUG_SCRIPT, "%s: executing flowop "
			    "%s-%d", threadflow->tf_name, flowop->fo_name,
			    flowop->fo_instance);

			/* Return value > 0 means "stop the filebench run" */
			if (ret > 0) {
				filebench_log(LOG_VERBOSE,
				    "%s: exiting flowop %s-%d",
				    threadflow->tf_name, flowop->fo_name,
				    flowop->fo_instance);
				(void) ipc_mutex_lock(&threadflow->tf_lock);
				threadflow->tf_abort = 1;
				filebench_shm->f_abort = 1;
				threadflow->tf_running = 0;
				(void) ipc_mutex_unlock(&threadflow->tf_lock);
				break;
			}
			/*
			 * Return value < 0 means "flowop failed, stop the
			 * filebench run"
			 */
			if (ret < 0) {
				filebench_log(LOG_ERROR, "flowop %s failed",
				    flowop->fo_name);
				(void) ipc_mutex_lock(&threadflow->tf_lock);
				threadflow->tf_abort = 1;
				filebench_shm->f_abort = 1;
				threadflow->tf_running = 0;
				(void) ipc_mutex_unlock(&threadflow->tf_lock);
				break;
			}
		}

		/* advance to next flowop */
		flowop = flowop->fo_threadnext;

		/* but if at end of list, start over from the beginning */
		if (flowop == NULL) {
			flowop = threadflow->tf_ops;
			threadflow->tf_stats.fs_count++;
		}
	}

#ifdef HAVE_LWPS
	filebench_log(LOG_DEBUG_SCRIPT, "Thread %d exiting",
	    _lwp_self());
#endif

	pthread_exit(&ret);
}

void
flowop_init(void)
{
	flowoplib_init();
}

/*
 * Calls the flowop's destruct function, pointed to by
 * flowop->fo_destruct.
 */
static void
flowop_destructflow(flowop_t *flowop)
{
	(*flowop->fo_destruct)(flowop);
}

/*
 * Delete the designated flowop from the thread's flowop list.
 * After removal from the list, the flowop is destroyed with
 * flowop_destructflow().
 */
static void
flowop_delete(flowop_t **flowoplist, flowop_t *flowop)
{
	flowop_t *entry = *flowoplist;
	int found = 0;

	filebench_log(LOG_DEBUG_IMPL, "Deleting flowop (%s-%d)",
	    flowop->fo_name,
	    flowop->fo_instance);

	/* Delete from thread's flowop list */
	if (flowop == *flowoplist) {
		/* First on list */
		*flowoplist = flowop->fo_threadnext;
		filebench_log(LOG_DEBUG_IMPL,
		    "Delete0 flowop: (%s-%d)",
		    flowop->fo_name,
		    flowop->fo_instance);
	} else {
		while (entry->fo_threadnext) {
			filebench_log(LOG_DEBUG_IMPL,
			    "Delete0 flowop: (%s-%d) == (%s-%d)",
			    entry->fo_threadnext->fo_name,
			    entry->fo_threadnext->fo_instance,
			    flowop->fo_name,
			    flowop->fo_instance);

			if (flowop == entry->fo_threadnext) {
				/* Delete */
				filebench_log(LOG_DEBUG_IMPL,
				    "Deleted0 flowop: (%s-%d)",
				    entry->fo_threadnext->fo_name,
				    entry->fo_threadnext->fo_instance);
				entry->fo_threadnext =
				    entry->fo_threadnext->fo_threadnext;
				break;
			}
			entry = entry->fo_threadnext;
		}
	}

	/* Call destructor */
	flowop_destructflow(flowop);

#ifdef HAVE_PROCFS
	/* Close /proc stats */
	if (flowop->fo_thread)
		(void) close(flowop->fo_thread->tf_lwpusagefd);
#endif

	/* Delete from global list */
	entry = filebench_shm->flowoplist;

	if (flowop == filebench_shm->flowoplist) {
		/* First on list */
		filebench_shm->flowoplist = flowop->fo_next;
		found = 1;
	} else {
		while (entry->fo_next) {
			filebench_log(LOG_DEBUG_IMPL,
			    "Delete flowop: (%s-%d) == (%s-%d)",
			    entry->fo_next->fo_name,
			    entry->fo_next->fo_instance,
			    flowop->fo_name,
			    flowop->fo_instance);

			if (flowop == entry->fo_next) {
				/* Delete */
				entry->fo_next = entry->fo_next->fo_next;
				found = 1;
				break;
			}

			entry = entry->fo_next;
		}
	}
	if (found) {
		filebench_log(LOG_DEBUG_IMPL,
		    "Deleted flowop: (%s-%d)",
		    flowop->fo_name,
		    flowop->fo_instance);
		ipc_free(FILEBENCH_FLOWOP, (char *)flowop);
	} else {
		filebench_log(LOG_DEBUG_IMPL, "Flowop %s-%d not found!",
		    flowop->fo_name,
		    flowop->fo_instance);
	}
}

/*
 * Deletes all the flowops from a flowop list.
 */
void
flowop_delete_all(flowop_t **flowoplist)
{
	flowop_t *flowop = *flowoplist;

	filebench_log(LOG_DEBUG_IMPL, "Deleting all flowops...");
	while (flowop) {
		filebench_log(LOG_DEBUG_IMPL, "Deleting all flowops (%s-%d)",
		    flowop->fo_name, flowop->fo_instance);
		flowop = flowop->fo_threadnext;
	}

	flowop = *flowoplist;

	(void) ipc_mutex_lock(&filebench_shm->flowop_lock);

	while (flowop) {
		if (flowop->fo_instance &&
		    (flowop->fo_instance == FLOW_MASTER)) {
			flowop = flowop->fo_threadnext;
			continue;
		}
		flowop_delete(flowoplist, flowop);
		flowop = flowop->fo_threadnext;
	}

	(void) ipc_mutex_unlock(&filebench_shm->flowop_lock);
}

/*
 * Allocates a flowop entity and initializes it with inherited
 * contents from the "inherit" flowop, if it is supplied, or
 * with zeros otherwise. In either case the file descriptor
 * (fo_fd) is set to -1, and the fo_next and fo_threadnext
 * pointers are set to NULL, and fo_thread is set to point to
 * the owning threadflow. The initialized flowop is placed at
 * the head of the global flowop list, and also placed on the
 * tail of thethreadflow's tf_ops list. The routine locks the
 * flowop's fo_lock and leaves it held on return. If successful,
 * it returns a pointer to the allocated and initialized flowop,
 * otherwise NULL.
 *
 * filebench_shm->flowop_lock must be held by caller.
 */
static flowop_t *
flowop_define_common(threadflow_t *threadflow, char *name, flowop_t *inherit,
    int instance, int type)
{
	flowop_t *flowop;

	if (name == NULL)
		return (NULL);

	if ((flowop = (flowop_t *)ipc_malloc(FILEBENCH_FLOWOP)) == NULL) {
		filebench_log(LOG_ERROR,
		    "flowop_define: Can't malloc flowop");
		return (NULL);
	}

	filebench_log(LOG_DEBUG_IMPL, "defining flowops %s-%d, addr %zx",
	    name, instance, flowop);

	if (flowop == NULL)
		return (NULL);

	if (inherit) {
		(void) memcpy(flowop, inherit, sizeof (flowop_t));
		(void) pthread_mutex_init(&flowop->fo_lock, ipc_mutexattr());
		(void) ipc_mutex_lock(&flowop->fo_lock);
		flowop->fo_next = NULL;
		flowop->fo_threadnext = NULL;
		flowop->fo_fd = -1;
		filebench_log(LOG_DEBUG_IMPL,
		    "flowop %s-%d calling init", name, instance);
	} else {
		(void) memset(flowop, 0, sizeof (flowop_t));
		flowop->fo_fd = -1;
		flowop->fo_iters = integer_alloc(1);
		flowop->fo_type = type;
		(void) pthread_mutex_init(&flowop->fo_lock, ipc_mutexattr());
		(void) ipc_mutex_lock(&flowop->fo_lock);
	}

	/* Create backpointer to thread */
	flowop->fo_thread = threadflow;

	/* Add flowop to global list */
	if (filebench_shm->flowoplist == NULL) {
		filebench_shm->flowoplist = flowop;
		flowop->fo_next = NULL;
	} else {
		flowop->fo_next = filebench_shm->flowoplist;
		filebench_shm->flowoplist = flowop;
	}

	(void) strcpy(flowop->fo_name, name);
	flowop->fo_instance = instance;

	if (threadflow == NULL)
		return (flowop);

	/* Add flowop to thread op list */
	if (threadflow->tf_ops == NULL) {
		threadflow->tf_ops = flowop;
		flowop->fo_threadnext = NULL;
	} else {
		flowop_t *flowend;

		/* Find the end of the thread list */
		flowend = threadflow->tf_ops;
		while (flowend->fo_threadnext != NULL)
			flowend = flowend->fo_threadnext;
		flowend->fo_threadnext = flowop;
		flowop->fo_threadnext = NULL;
	}

	return (flowop);
}

/*
 * Calls flowop_define_common() to allocate and initialize a
 * flowop, and holds the shared flowop_lock during the call.
 * It releases the created flowop's fo_lock when done.
 */
flowop_t *
flowop_define(threadflow_t *threadflow, char *name, flowop_t *inherit,
    int instance, int type)
{
	flowop_t *flowop;

	(void) ipc_mutex_lock(&filebench_shm->flowop_lock);
	flowop = flowop_define_common(threadflow, name,
	    inherit, instance, type);
	(void) ipc_mutex_unlock(&filebench_shm->flowop_lock);

	if (flowop == NULL)
		return (NULL);

	(void) ipc_mutex_unlock(&flowop->fo_lock);

	return (flowop);
}

/*
 * Attempts to take a write lock on the flowop_find_lock that is
 * defined in interprocess shared memory. Since each call to
 * flowop_start() holds a read lock on flowop_find_lock, this
 * routine effectively blocks until all instances of
 * flowop_start() have finished. The flowop_find() routine calls
 * this routine so that flowops won't be searched for until all
 * flowops have been created by flowop_start.
 */
static void
flowop_find_barrier(void)
{
	/* Block on wrlock to ensure find waits for all creates */
	(void) pthread_rwlock_wrlock(&filebench_shm->flowop_find_lock);
	(void) pthread_rwlock_unlock(&filebench_shm->flowop_find_lock);
}

/*
 * Returns a list of flowops named "name" from the master
 * flowop list.
 */
flowop_t *
flowop_find(char *name)
{
	flowop_t *flowop = filebench_shm->flowoplist;
	flowop_t *result = NULL;

	flowop_find_barrier();

	(void) ipc_mutex_lock(&filebench_shm->flowop_lock);

	while (flowop) {
		if (strcmp(name, flowop->fo_name) == 0) {

			/* Add flowop to result list */
			if (result == NULL) {
				result = flowop;
				flowop->fo_resultnext = NULL;
			} else {
				flowop->fo_resultnext = result;
				result = flowop;
			}
		}
		flowop = flowop->fo_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->flowop_lock);


	return (result);
}

/*
 * Returns a pointer to the specified instance of flowop
 * "name" from the list returned by flowop_find().
 */
flowop_t *
flowop_find_one(char *name, int instance)
{
	flowop_t *result;

	result = flowop_find(name);

	while (result) {
		if ((strcmp(name, result->fo_name) == 0) &&
		    (instance == result->fo_instance))
			break;
		result = result->fo_next;
	}

	return (result);
}
