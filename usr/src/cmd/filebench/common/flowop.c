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
    flowop_t *inherit, flowop_t **flowoplist_hdp, int instance, int type);
static int flowop_composite(threadflow_t *threadflow, flowop_t *flowop);
static int flowop_composite_init(flowop_t *flowop);
static void flowop_composite_destruct(flowop_t *flowop);

/*
 * A collection of flowop support functions. The actual code that
 * implements the various flowops is in flowop_library.c.
 *
 * Routines for defining, creating, initializing and destroying
 * flowops, cyclically invoking the flowops on each threadflow's flowop
 * list, collecting statistics about flowop execution, and other
 * housekeeping duties are included in this file.
 *
 * User Defined Composite Flowops
 *    The ability to define new flowops as lists of built-in or previously
 * defined flowops has been added to Filebench. In a sense they are like
 * in-line subroutines, which can have default attributes set at definition
 * time and passed arguments at invocation time. Like other flowops (and
 * unlike conventional subroutines) you can invoke them with an iteration
 * count (the "iter" attribute), and they will loop through their associated
 * list of flowops for "iter" number of times each time they are encountered
 * in the thread or outer composite flowop which invokes them.
 *
 * Composite flowops are created with a "define" command, are given a name,
 * optional default attributes, and local variable definitions on the
 * "define" command line, followed by a brace enclosed list of flowops
 * to execute. The enclosed flowops may include attributes that reference
 * the local variables, as well as constants and global variables.
 *
 * Composite flowops are used pretty much like regular flowops, but you can
 * also set local variables to constants or global variables ($local_var =
 * [$var | $random_var | string | boolean | integer | double]) as part of
 * the invocation. Thus each invocation can pass customized values to its
 * inner flowops, greatly increasing their generality.
 *
 * All flowops are placed on a global, singly linked list, with fo_next
 * being the link pointer for this list. The are also placed on a private
 * list for the thread or composite flowop they are part of. The tf_thrd_fops
 * pointer in the thread will point to the list of top level flowops in the
 * thread, which are linked together by fo_exec_next. If any of these flowops
 * are composite flowops, they will have a list of second level flowops rooted
 * at the composite flowop's fo_comp_fops pointer. So, there is one big list
 * of all flowops, and an n-arry tree of threads, composite flowops, and
 * flowops, with composite flowops being the branch nodes in the tree.
 *
 * To illustrate, if we have three first level flowops, the first of which is
 * a composite flowop consisting of two other flowops, we get:
 *
 * Thread->tf_thrd_fops -> flowop->fo_exec_next -> flowop->fo_exec_next
 *			   flowop->fo_comp_fops		    |
 *				    |			    V
 *				    |			flowop->fo_exec_next
 *				    |
 *				    V
 *				flowop->fo_exec_next -> flowop->fo_exec_next
 *
 * And all five flowops (plus others from any other threads) are on a global
 * list linked with fo_next.
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
		flowop = flowop->fo_exec_next;
	}
	return (0);
}

/*
 * Prints the name and instance number of all flowops on
 * the master flowop list to the console and the filebench log.
 */
void
flowop_printall(void)
{
	flowop_t *flowop = filebench_shm->shm_flowoplist;

	while (flowop) {
		filebench_log(LOG_VERBOSE, "flowop-list %s-%d",
		    flowop->fo_name, flowop->fo_instance);
		flowop = flowop->fo_next;
	}
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
		    "/proc/%d/lwp/%d/lwpusage", my_pid, _lwp_self());
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
pthread_mutex_t controlstats_lock;
static int controlstats_zeroed = 0;

/*
 * Updates flowop's latency statistics, using saved start
 * time and current high resolution time. Updates flowop's
 * io count and transferred bytes statistics. Also updates
 * threadflow's and flowop's cumulative read or write byte
 * and io count statistics.
 */
void
flowop_endop(threadflow_t *threadflow, flowop_t *flowop, int64_t bytes)
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
	flowop->fo_stats.fs_bytes += bytes;
	(void) ipc_mutex_lock(&controlstats_lock);
	if ((flowop->fo_type & FLOW_TYPE_IO) ||
	    (flowop->fo_type & FLOW_TYPE_AIO)) {
		controlstats.fs_count++;
		controlstats.fs_bytes += bytes;
	}
	if (flowop->fo_attrs & FLOW_ATTR_READ) {
		threadflow->tf_stats.fs_rbytes += bytes;
		threadflow->tf_stats.fs_rcount++;
		flowop->fo_stats.fs_rcount++;
		controlstats.fs_rbytes += bytes;
		controlstats.fs_rcount++;
	} else if (flowop->fo_attrs & FLOW_ATTR_WRITE) {
		threadflow->tf_stats.fs_wbytes += bytes;
		threadflow->tf_stats.fs_wcount++;
		flowop->fo_stats.fs_wcount++;
		controlstats.fs_wbytes += bytes;
		controlstats.fs_wcount++;
	}
	(void) ipc_mutex_unlock(&controlstats_lock);
}

/*
 * Calls the flowop's initialization function, pointed to by
 * flowop->fo_init.
 */
static int
flowop_initflow(flowop_t *flowop)
{
	/*
	 * save static copies of two items, in case they are supplied
	 * from random variables
	 */
	flowop->fo_constvalue = avd_get_int(flowop->fo_value);
	flowop->fo_constwss = avd_get_int(flowop->fo_wss);

	if ((*flowop->fo_init)(flowop) < 0) {
		filebench_log(LOG_ERROR, "flowop %s-%d init failed",
		    flowop->fo_name, flowop->fo_instance);
		return (-1);
	}
	return (0);
}

static int
flowop_create_runtime_flowops(threadflow_t *threadflow, flowop_t **ops_list_ptr)
{
	flowop_t *flowop = *ops_list_ptr;

	while (flowop) {
		flowop_t *newflowop;

		if (flowop == *ops_list_ptr)
			*ops_list_ptr = NULL;

		newflowop = flowop_define_common(threadflow, flowop->fo_name,
		    flowop, ops_list_ptr, 1, 0);
		if (newflowop == NULL)
			return (FILEBENCH_ERROR);

		/* check for fo_filename attribute, and resolve if present */
		if (flowop->fo_filename) {
			char *name;

			name = avd_get_str(flowop->fo_filename);
			newflowop->fo_fileset = fileset_find(name);

			if (newflowop->fo_fileset == NULL) {
				filebench_log(LOG_ERROR,
				    "flowop %s: file %s not found",
				    newflowop->fo_name, name);
				filebench_shutdown(1);
			}
		}

		if (flowop_initflow(newflowop) < 0) {
			filebench_log(LOG_ERROR, "Flowop init of %s failed",
			    newflowop->fo_name);
		}

		flowop = flowop->fo_exec_next;
	}
	return (FILEBENCH_OK);
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
 * call the destruct funtions of all the threadflow's flowops,
 * if it is still flagged as "running".
 */
void
flowop_destruct_all_flows(threadflow_t *threadflow)
{
	flowop_t *flowop;

	/* wait a moment to give other threads a chance to stop too */
	(void) sleep(1);

	(void) ipc_mutex_lock(&threadflow->tf_lock);

	/* prepare to call destruct flow routines, if necessary */
	if (threadflow->tf_running == 0) {

		/* allready destroyed */
		(void) ipc_mutex_unlock(&threadflow->tf_lock);
		return;
	}

	flowop = threadflow->tf_thrd_fops;
	threadflow->tf_running = 0;
	(void) ipc_mutex_unlock(&threadflow->tf_lock);

	while (flowop) {
		flowop_destructflow(flowop);
		flowop = flowop->fo_exec_next;
	}
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

#ifdef HAVE_PROCFS
	if (noproc == 0) {
		char procname[128];
		long ctl[2] = {PCSET, PR_MSACCT};
		int pfd;

		(void) snprintf(procname, sizeof (procname),
		    "/proc/%d/lwp/%d/lwpctl", my_pid, _lwp_self());
		pfd = open(procname, O_WRONLY);
		(void) pwrite(pfd, &ctl, sizeof (ctl), 0);
		(void) close(pfd);
	}
#endif

	(void) ipc_mutex_lock(&controlstats_lock);
	if (!controlstats_zeroed) {
		(void) memset(&controlstats, 0, sizeof (controlstats));
		controlstats_zeroed = 1;
	}
	(void) ipc_mutex_unlock(&controlstats_lock);

	flowop = threadflow->tf_thrd_fops;
	threadflow->tf_stats.fs_stime = gethrtime();
	flowop->fo_stats.fs_stime = gethrtime();

	/* Hold the flowop find lock as reader to prevent lookups */
	(void) pthread_rwlock_rdlock(&filebench_shm->shm_flowop_find_lock);

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
	(void) pthread_rwlock_wrlock(&filebench_shm->shm_run_lock);
	(void) pthread_rwlock_unlock(&filebench_shm->shm_run_lock);

	/* Create the runtime flowops from those defined by the script */
	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);
	if (flowop_create_runtime_flowops(threadflow, &threadflow->tf_thrd_fops)
	    != FILEBENCH_OK) {
		(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);
		filebench_shutdown(1);
		return;
	}
	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);

	/* Release the find lock as reader to allow lookups */
	(void) pthread_rwlock_unlock(&filebench_shm->shm_flowop_find_lock);

	/* Set to the start of the new flowop list */
	flowop = threadflow->tf_thrd_fops;

	threadflow->tf_abort = 0;
	threadflow->tf_running = 1;

	memsize = (size_t)threadflow->tf_constmemsize;

	/* If we are going to use ISM, allocate later */
	if (threadflow->tf_attrs & THREADFLOW_USEISM) {
		threadflow->tf_mem =
		    ipc_ismmalloc(memsize);
	} else {
		threadflow->tf_mem =
		    malloc(memsize);
	}

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
		int i, count;

		/* Abort if asked */
		if (threadflow->tf_abort || filebench_shm->shm_f_abort)
			break;

		/* Be quiet while stats are gathered */
		if (filebench_shm->shm_bequiet) {
			(void) sleep(1);
			continue;
		}

		/* Take it easy until everyone is ready to go */
		if (!filebench_shm->shm_procs_running) {
			(void) sleep(1);
			continue;
		}

		if (flowop == NULL) {
			filebench_log(LOG_ERROR, "flowop_read null flowop");
			return;
		}

		if (flowop->fo_stats.fs_stime == 0)
			flowop->fo_stats.fs_stime = gethrtime();

		/* Execute the flowop for fo_iters times */
		count = (int)avd_get_int(flowop->fo_iters);
		for (i = 0; i < count; i++) {

			filebench_log(LOG_DEBUG_SCRIPT, "%s: executing flowop "
			    "%s-%d", threadflow->tf_name, flowop->fo_name,
			    flowop->fo_instance);

			ret = (*flowop->fo_func)(threadflow, flowop);

			/*
			 * Return value FILEBENCH_ERROR means "flowop
			 * failed, stop the filebench run"
			 */
			if (ret == FILEBENCH_ERROR) {
				filebench_log(LOG_ERROR,
				    "%s-%d: flowop %s-%d failed",
				    threadflow->tf_name,
				    threadflow->tf_instance,
				    flowop->fo_name,
				    flowop->fo_instance);
				(void) ipc_mutex_lock(&threadflow->tf_lock);
				threadflow->tf_abort = 1;
				filebench_shm->shm_f_abort =
				    FILEBENCH_ABORT_ERROR;
				(void) ipc_mutex_unlock(&threadflow->tf_lock);
				break;
			}

			/*
			 * Return value of FILEBENCH_NORSC means "stop
			 * the filebench run" if in "end on no work mode",
			 * otherwise it indicates an error
			 */
			if (ret == FILEBENCH_NORSC) {
				(void) ipc_mutex_lock(&threadflow->tf_lock);
				threadflow->tf_abort = FILEBENCH_DONE;
				if (filebench_shm->shm_rmode ==
				    FILEBENCH_MODE_Q1STDONE) {
					filebench_shm->shm_f_abort =
					    FILEBENCH_ABORT_RSRC;
				} else if (filebench_shm->shm_rmode !=
				    FILEBENCH_MODE_QALLDONE) {
					filebench_log(LOG_ERROR1,
					    "WARNING! Run stopped early:\n   "
					    "             flowop %s-%d could "
					    "not obtain a file. Please\n      "
					    "          reduce runtime, "
					    "increase fileset entries "
					    "($nfiles), or switch modes.",
					    flowop->fo_name,
					    flowop->fo_instance);
					filebench_shm->shm_f_abort =
					    FILEBENCH_ABORT_ERROR;
				}
				(void) ipc_mutex_unlock(&threadflow->tf_lock);
				break;
			}

			/*
			 * Return value of FILEBENCH_DONE means "stop
			 * the filebench run without error"
			 */
			if (ret == FILEBENCH_DONE) {
				(void) ipc_mutex_lock(&threadflow->tf_lock);
				threadflow->tf_abort = FILEBENCH_DONE;
				filebench_shm->shm_f_abort =
				    FILEBENCH_ABORT_DONE;
				(void) ipc_mutex_unlock(&threadflow->tf_lock);
				break;
			}

			/*
			 * If we get here and the return is something other
			 * than FILEBENCH_OK, it means a spurious code
			 * was returned, so treat as major error. This
			 * probably indicates a bug in the flowop.
			 */
			if (ret != FILEBENCH_OK) {
				filebench_log(LOG_ERROR,
				    "Flowop %s unexpected return value = %d\n",
				    flowop->fo_name, ret);
				filebench_shm->shm_f_abort =
				    FILEBENCH_ABORT_ERROR;
				break;
			}
		}

		/* advance to next flowop */
		flowop = flowop->fo_exec_next;

		/* but if at end of list, start over from the beginning */
		if (flowop == NULL) {
			flowop = threadflow->tf_thrd_fops;
			threadflow->tf_stats.fs_count++;
		}
	}

#ifdef HAVE_LWPS
	filebench_log(LOG_DEBUG_SCRIPT, "Thread %d exiting",
	    _lwp_self());
#endif

	/* Tell flowops to destroy locally acquired state */
	flowop_destruct_all_flows(threadflow);

	pthread_exit(&threadflow->tf_abort);
}

void
flowop_init(void)
{
	(void) pthread_mutex_init(&controlstats_lock, ipc_mutexattr());
	flowoplib_init();
}

/*
 * Delete the designated flowop from the thread's flowop list.
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
		*flowoplist = flowop->fo_exec_next;
		filebench_log(LOG_DEBUG_IMPL,
		    "Delete0 flowop: (%s-%d)",
		    flowop->fo_name,
		    flowop->fo_instance);
	} else {
		while (entry->fo_exec_next) {
			filebench_log(LOG_DEBUG_IMPL,
			    "Delete0 flowop: (%s-%d) == (%s-%d)",
			    entry->fo_exec_next->fo_name,
			    entry->fo_exec_next->fo_instance,
			    flowop->fo_name,
			    flowop->fo_instance);

			if (flowop == entry->fo_exec_next) {
				/* Delete */
				filebench_log(LOG_DEBUG_IMPL,
				    "Deleted0 flowop: (%s-%d)",
				    entry->fo_exec_next->fo_name,
				    entry->fo_exec_next->fo_instance);
				entry->fo_exec_next =
				    entry->fo_exec_next->fo_exec_next;
				break;
			}
			entry = entry->fo_exec_next;
		}
	}

#ifdef HAVE_PROCFS
	/* Close /proc stats */
	if (flowop->fo_thread)
		(void) close(flowop->fo_thread->tf_lwpusagefd);
#endif

	/* Delete from global list */
	entry = filebench_shm->shm_flowoplist;

	if (flowop == filebench_shm->shm_flowoplist) {
		/* First on list */
		filebench_shm->shm_flowoplist = flowop->fo_next;
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

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);

	while (flowop) {
		filebench_log(LOG_DEBUG_IMPL, "Deleting flowop (%s-%d)",
		    flowop->fo_name, flowop->fo_instance);

		if (flowop->fo_instance &&
		    (flowop->fo_instance == FLOW_MASTER)) {
			flowop = flowop->fo_exec_next;
			continue;
		}
		flowop_delete(flowoplist, flowop);
		flowop = flowop->fo_exec_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);
}

/*
 * Allocates a flowop entity and initializes it with inherited
 * contents from the "inherit" flowop, if it is supplied, or
 * with zeros otherwise. In either case the fo_next and fo_exec_next
 * pointers are set to NULL, and fo_thread is set to point to
 * the owning threadflow. The initialized flowop is placed at
 * the head of the global flowop list, and also placed on the
 * tail of the supplied local flowop list, which will either
 * be a threadflow's tf_thrd_fops list or a composite flowop's
 * fo_comp_fops list. The routine locks the flowop's fo_lock and
 * leaves it held on return. If successful, it returns a pointer
 * to the allocated and initialized flowop, otherwise it returns NULL.
 *
 * filebench_shm->shm_flowop_lock must be held by caller.
 */
static flowop_t *
flowop_define_common(threadflow_t *threadflow, char *name, flowop_t *inherit,
    flowop_t **flowoplist_hdp, int instance, int type)
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
		flowop->fo_exec_next = NULL;
		filebench_log(LOG_DEBUG_IMPL,
		    "flowop %s-%d calling init", name, instance);
	} else {
		(void) memset(flowop, 0, sizeof (flowop_t));
		flowop->fo_iters = avd_int_alloc(1);
		flowop->fo_type = type;
		(void) pthread_mutex_init(&flowop->fo_lock, ipc_mutexattr());
		(void) ipc_mutex_lock(&flowop->fo_lock);
	}

	/* Create backpointer to thread */
	flowop->fo_thread = threadflow;

	/* Add flowop to global list */
	if (filebench_shm->shm_flowoplist == NULL) {
		filebench_shm->shm_flowoplist = flowop;
		flowop->fo_next = NULL;
	} else {
		flowop->fo_next = filebench_shm->shm_flowoplist;
		filebench_shm->shm_flowoplist = flowop;
	}

	(void) strcpy(flowop->fo_name, name);
	flowop->fo_instance = instance;

	if (flowoplist_hdp == NULL)
		return (flowop);

	/* Add flowop to thread op list */
	if (*flowoplist_hdp == NULL) {
		*flowoplist_hdp = flowop;
		flowop->fo_exec_next = NULL;
	} else {
		flowop_t *flowend;

		/* Find the end of the thread list */
		flowend = *flowoplist_hdp;
		while (flowend->fo_exec_next != NULL)
			flowend = flowend->fo_exec_next;
		flowend->fo_exec_next = flowop;
		flowop->fo_exec_next = NULL;
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
    flowop_t **flowoplist_hdp, int instance, int type)
{
	flowop_t	*flowop;

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);
	flowop = flowop_define_common(threadflow, name,
	    inherit, flowoplist_hdp, instance, type);
	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);

	if (flowop == NULL)
		return (NULL);

	(void) ipc_mutex_unlock(&flowop->fo_lock);
	return (flowop);
}

/*
 * Calls flowop_define_common() to allocate and initialize a
 * composite flowop, and holds the shared flowop_lock during the call.
 * It releases the created flowop's fo_lock when done.
 */
flowop_t *
flowop_new_composite_define(char *name)
{
	flowop_t *flowop;

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);
	flowop = flowop_define_common(NULL, name,
	    NULL, NULL, 0, FLOW_TYPE_COMPOSITE);
	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);

	if (flowop == NULL)
		return (NULL);

	flowop->fo_func = flowop_composite;
	flowop->fo_init = flowop_composite_init;
	flowop->fo_destruct = flowop_composite_destruct;
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
	(void) pthread_rwlock_wrlock(&filebench_shm->shm_flowop_find_lock);
	(void) pthread_rwlock_unlock(&filebench_shm->shm_flowop_find_lock);
}

/*
 * Returns a list of flowops named "name" from the master
 * flowop list.
 */
flowop_t *
flowop_find(char *name)
{
	flowop_t *flowop;
	flowop_t *result = NULL;

	flowop_find_barrier();

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);

	flowop = filebench_shm->shm_flowoplist;

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

	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);


	return (result);
}

/*
 * Returns a pointer to the specified instance of flowop
 * "name" from the global list.
 */
flowop_t *
flowop_find_one(char *name, int instance)
{
	flowop_t *test_flowop;

	flowop_find_barrier();

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);

	test_flowop = filebench_shm->shm_flowoplist;

	while (test_flowop) {
		if ((strcmp(name, test_flowop->fo_name) == 0) &&
		    (instance == test_flowop->fo_instance))
			break;

		test_flowop = test_flowop->fo_next;
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);

	return (test_flowop);
}

/*
 * recursively searches through lists of flowops on a given thread
 * and those on any included composite flowops for the named flowop.
 * either returns with a pointer to the named flowop or NULL if it
 * cannot be found.
 */
static flowop_t *
flowop_recurse_search(char *path, char *name, flowop_t *list)
{
	flowop_t *test_flowop;
	char fullname[MAXPATHLEN];

	test_flowop = list;

	/*
	 * when searching a list of inner flowops, "path" is the fullname
	 * of the containing composite flowop. Use it to form the
	 * full name of the inner flowop to search for.
	 */
	if (path) {
		if ((strlen(path) + strlen(name) + 1) > MAXPATHLEN) {
			filebench_log(LOG_ERROR,
			    "composite flowop path name %s.%s too long",
			    path, name);
			return (NULL);
		}

		/* create composite_name.name for recursive search */
		(void) strcpy(fullname, path);
		(void) strcat(fullname, ".");
		(void) strcat(fullname, name);
	} else {
		(void) strcpy(fullname, name);
	}

	/*
	 * loop through all flowops on the supplied tf_thrd_fops (flowop)
	 * list or fo_comp_fops (inner flowop) list.
	 */
	while (test_flowop) {
		if (strcmp(fullname, test_flowop->fo_name) == 0)
			return (test_flowop);

		if (test_flowop->fo_type == FLOW_TYPE_COMPOSITE) {
			flowop_t *found_flowop;

			found_flowop = flowop_recurse_search(
			    test_flowop->fo_name, name,
			    test_flowop->fo_comp_fops);

			if (found_flowop)
				return (found_flowop);
		}
		test_flowop = test_flowop->fo_exec_next;
	}

	/* not found here or on any child lists */
	return (NULL);
}

/*
 * Returns a pointer to flowop named "name" from the supplied tf_thrd_fops
 * list of flowops. Returns the named flowop if found, or NULL.
 */
flowop_t *
flowop_find_from_list(char *name, flowop_t *list)
{
	flowop_t *found_flowop;

	flowop_find_barrier();

	(void) ipc_mutex_lock(&filebench_shm->shm_flowop_lock);

	found_flowop = flowop_recurse_search(NULL, name, list);

	(void) ipc_mutex_unlock(&filebench_shm->shm_flowop_lock);

	return (found_flowop);
}

/*
 * Composite flowop method. Does one pass through its list of
 * inner flowops per iteration.
 */
static int
flowop_composite(threadflow_t *threadflow, flowop_t *flowop)
{
	flowop_t	*inner_flowop;

	/* get the first flowop in the list */
	inner_flowop = flowop->fo_comp_fops;

	/* make a pass through the list of sub flowops */
	while (inner_flowop) {
		int	i, count;

		/* Abort if asked */
		if (threadflow->tf_abort || filebench_shm->shm_f_abort)
			return (FILEBENCH_DONE);

		if (inner_flowop->fo_stats.fs_stime == 0)
			inner_flowop->fo_stats.fs_stime = gethrtime();

		/* Execute the flowop for fo_iters times */
		count = (int)avd_get_int(inner_flowop->fo_iters);
		for (i = 0; i < count; i++) {

			filebench_log(LOG_DEBUG_SCRIPT, "%s: executing flowop "
			    "%s-%d", threadflow->tf_name,
			    inner_flowop->fo_name,
			    inner_flowop->fo_instance);

			switch ((*inner_flowop->fo_func)(threadflow,
			    inner_flowop)) {

			/* all done */
			case FILEBENCH_DONE:
				return (FILEBENCH_DONE);

			/* quit if inner flowop limit reached */
			case FILEBENCH_NORSC:
				return (FILEBENCH_NORSC);

			/* quit on inner flowop error */
			case FILEBENCH_ERROR:
				filebench_log(LOG_ERROR,
				    "inner flowop %s failed",
				    inner_flowop->fo_name);
				return (FILEBENCH_ERROR);

			/* otherwise keep going */
			default:
				break;
			}

		}

		/* advance to next flowop */
		inner_flowop = inner_flowop->fo_exec_next;
	}

	/* finished with this pass */
	return (FILEBENCH_OK);
}

/*
 * Composite flowop initialization. Creates runtime inner flowops
 * from prototype inner flowops.
 */
static int
flowop_composite_init(flowop_t *flowop)
{
	int err;

	err = flowop_create_runtime_flowops(flowop->fo_thread,
	    &flowop->fo_comp_fops);
	if (err != FILEBENCH_OK)
		return (err);

	(void) ipc_mutex_unlock(&flowop->fo_lock);
	return (0);
}

/*
 * clean up inner flowops
 */
static void
flowop_composite_destruct(flowop_t *flowop)
{
	flowop_t *inner_flowop = flowop->fo_comp_fops;

	while (inner_flowop) {
		filebench_log(LOG_DEBUG_IMPL, "Deleting inner flowop (%s-%d)",
		    inner_flowop->fo_name, inner_flowop->fo_instance);

		if (inner_flowop->fo_instance &&
		    (inner_flowop->fo_instance == FLOW_MASTER)) {
			inner_flowop = inner_flowop->fo_exec_next;
			continue;
		}
		flowop_delete(&flowop->fo_comp_fops, inner_flowop);
		inner_flowop = inner_flowop->fo_exec_next;
	}
}
