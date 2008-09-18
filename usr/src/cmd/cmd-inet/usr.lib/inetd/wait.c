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

/*
 * This file contains a set of routines used to perform wait based method
 * reaping.
 */

#include <wait.h>
#include <sys/param.h>
#include <fcntl.h>
#include <libcontract.h>
#include <errno.h>
#include <libintl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include "inetd_impl.h"

/* inetd's open file limit, set in method_init() */
#define	INETD_NOFILE_LIMIT RLIM_INFINITY

/* structure used to represent an active method process */
typedef struct {
	int			fd;	/* fd of process's /proc psinfo file */
	/* associated contract id if known, else -1 */
	ctid_t			cid;
	pid_t			pid;
	instance_t		*inst;	/* pointer to associated instance */
	instance_method_t	method;	/* the method type running */
	uu_list_node_t		link;
} method_el_t;


static void unregister_method(method_el_t *);


/* list of currently executing method processes */
static uu_list_pool_t		*method_pool = NULL;
static uu_list_t		*method_list = NULL;

/*
 * File limit saved during initialization before modification, so that it can
 * be reverted back to for inetd's exec'd methods.
 */
static struct rlimit		saved_file_limit;

/*
 * Setup structures used for method termination monitoring.
 * Returns -1 if an allocation failure occurred, else 0.
 */
int
method_init(void)
{
	struct rlimit rl;

	/*
	 * Save aside the old file limit and impose one large enough to support
	 * all the /proc file handles we could have open.
	 */

	(void) getrlimit(RLIMIT_NOFILE, &saved_file_limit);

	rl.rlim_cur = rl.rlim_max = INETD_NOFILE_LIMIT;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		error_msg("Failed to set file limit: %s", strerror(errno));
		return (-1);
	}

	if ((method_pool = uu_list_pool_create("method_pool",
	    sizeof (method_el_t), offsetof(method_el_t, link), NULL,
	    UU_LIST_POOL_DEBUG)) == NULL) {
		error_msg("%s: %s", gettext("Failed to create method pool"),
		    uu_strerror(uu_error()));
		return (-1);
	}

	if ((method_list = uu_list_create(method_pool, NULL, 0)) == NULL) {
		error_msg("%s: %s",
		    gettext("Failed to create method list"),
		    uu_strerror(uu_error()));
		/* let method_fini() clean-up */
		return (-1);
	}

	return (0);
}

/*
 * Tear-down structures created in method_init().
 */
void
method_fini(void)
{
	if (method_list != NULL) {
		method_el_t *me;

		while ((me = uu_list_first(method_list)) != NULL)
			unregister_method(me);

		(void) uu_list_destroy(method_list);
		method_list = NULL;
	}
	if (method_pool != NULL) {
		(void) uu_list_pool_destroy(method_pool);
		method_pool = NULL;
	}

	/* revert file limit */
	method_preexec();
}

/*
 * Revert file limit back to pre-initialization one. This shouldn't fail as
 * long as its called *after* descriptor cleanup.
 */
void
method_preexec(void)
{
	(void) setrlimit(RLIMIT_NOFILE, &saved_file_limit);
}


/*
 * Callback function that handles the timeout of an instance's method.
 * 'arg' points at the method_el_t representing the method.
 */
/* ARGSUSED0 */
static void
method_timeout(iu_tq_t *tq, void *arg)
{
	method_el_t *mp = arg;

	error_msg(gettext("The %s method of instance %s timed-out"),
	    methods[mp->method].name, mp->inst->fmri);

	mp->inst->timer_id = -1;

	if (mp->method == IM_START) {
		process_start_term(mp->inst);
	} else {
		process_non_start_term(mp->inst, IMRET_FAILURE);
	}

	unregister_method(mp);
}

/*
 * Registers the attributes of a running method passed as arguments so that
 * the method's termination is noticed and any further processing of the
 * associated instance is carried out. The function also sets up any
 * necessary timers so we can detect hung methods.
 * Returns -1 if either it failed to open the /proc psinfo file which is used
 * to monitor the method process, it failed to setup a required timer or
 * memory allocation failed; else 0.
 */
int
register_method(instance_t *ins, pid_t pid, ctid_t cid, instance_method_t mthd)
{
	char		path[MAXPATHLEN];
	int		fd;
	method_el_t	*me;

	/* open /proc psinfo file of process to listen for POLLHUP events on */
	(void) snprintf(path, sizeof (path), "/proc/%u/psinfo", pid);
	for (;;) {
		if ((fd = open(path, O_RDONLY)) >= 0) {
			break;
		} else if (errno != EINTR) {
			/*
			 * Don't output an error for ENOENT; we get this
			 * if a method has gone away whilst we were stopped,
			 * and we're now trying to re-listen for it.
			 */
			if (errno != ENOENT) {
				error_msg(gettext("Failed to open %s: %s"),
				    path, strerror(errno));
			}
			return (-1);
		}
	}

	/* add method record to in-memory list */
	if ((me = calloc(1, sizeof (method_el_t))) == NULL) {
		error_msg(strerror(errno));
		(void) close(fd);
		return (-1);
	}
	me->fd = fd;
	me->inst = (instance_t *)ins;
	me->method = mthd;
	me->pid = pid;
	me->cid = cid;

	/* register a timeout for the method, if required */
	if (mthd != IM_START) {
		method_info_t *mi = ins->config->methods[mthd];

		if (mi->timeout > 0) {
			assert(ins->timer_id == -1);
			ins->timer_id = iu_schedule_timer(timer_queue,
			    mi->timeout, method_timeout, me);
			if (ins->timer_id == -1) {
				error_msg(gettext(
				    "Failed to schedule method timeout"));
				free(me);
				(void) close(fd);
				return (-1);
			}
		}
	}

	/*
	 * Add fd of psinfo file to poll set, but pass 0 for events to
	 * poll for, so we should only get a POLLHUP event on the fd.
	 */
	if (set_pollfd(fd, 0) == -1) {
		cancel_inst_timer(ins);
		free(me);
		(void) close(fd);
		return (-1);
	}

	uu_list_node_init(me, &me->link, method_pool);
	(void) uu_list_insert_after(method_list, NULL, me);

	return (0);
}

/*
 * A counterpart to register_method(), this function stops the monitoring of a
 * method process for its termination.
 */
static void
unregister_method(method_el_t *me)
{
	/* cancel any timer associated with the method */
	if (me->inst->timer_id != -1)
		cancel_inst_timer(me->inst);

	/* stop polling on the psinfo file fd */
	clear_pollfd(me->fd);
	(void) close(me->fd);

	/* remove method record from list */
	uu_list_remove(method_list, me);

	free(me);
}

/*
 * Unregister all methods associated with instance 'inst'.
 */
void
unregister_instance_methods(const instance_t *inst)
{
	method_el_t *me = uu_list_first(method_list);

	while (me != NULL) {
		if (me->inst == inst) {
			method_el_t *tmp = me;

			me = uu_list_next(method_list, me);
			unregister_method(tmp);
		} else  {
			me = uu_list_next(method_list, me);
		}
	}
}

/*
 * Process any terminated methods. For each method determined to have
 * terminated, the function determines its return value and calls the
 * appropriate handling function, depending on the type of the method.
 */
void
process_terminated_methods(void)
{
	method_el_t	*me = uu_list_first(method_list);

	while (me != NULL) {
		struct pollfd	*pfd;
		pid_t		pid;
		int		status;
		int		ret;
		method_el_t	*tmp;

		pfd = find_pollfd(me->fd);

		/*
		 * We expect to get a POLLHUP back on the fd of the process's
		 * open psinfo file from /proc when the method terminates.
		 * A POLLERR could(?) mask a POLLHUP, so handle this
		 * also.
		 */
		if ((pfd->revents & (POLLHUP|POLLERR)) == 0) {
			me = uu_list_next(method_list, me);
			continue;
		}

		/* get the method's exit code (no need to loop for EINTR) */
		pid = waitpid(me->pid, &status, WNOHANG);

		switch (pid) {
		case 0:					/* child still around */
			/*
			 * Either poll() is sending us invalid POLLHUP events
			 * or is flagging a POLLERR on the fd. Neither should
			 * happen, but in the event they do, ignore this fd
			 * this time around and wait out the termination
			 * of its associated method. This may result in
			 * inetd swiftly looping in event_loop(), but means
			 * we don't miss the termination of a method.
			 */
			me = uu_list_next(method_list, me);
			continue;

		case -1:				/* non-existent child */
			assert(errno == ECHILD);
			/*
			 * the method must not be owned by inetd due to it
			 * persisting over an inetd restart. Let's assume the
			 * best, that it was successful.
			 */
			ret = IMRET_SUCCESS;
			break;

		default:				/* child terminated */
			if (WIFEXITED(status)) {
				ret = WEXITSTATUS(status);
				debug_msg("process %ld of instance %s returned "
				    "%d", pid, me->inst->fmri, ret);
			} else if (WIFSIGNALED(status)) {
				/*
				 * Terminated by signal.  This may be due
				 * to a kill that we sent from a disable or
				 * offline event. We flag it as a failure, but
				 * this flagged failure will only be processed
				 * in the case of non-start methods, or when
				 * the instance is still enabled.
				 */
				debug_msg("process %ld of instance %s exited "
				    "due to signal %d", pid, me->inst->fmri,
				    WTERMSIG(status));
				ret = IMRET_FAILURE;
			} else {
				/*
				 * Can we actually get here?  Don't think so.
				 * Treat it as a failure, anyway.
				 */
				debug_msg("waitpid() for %s method of "
				    "instance %s returned %d",
				    methods[me->method].name, me->inst->fmri,
				    status);
				ret = IMRET_FAILURE;
			}
		}

		remove_method_ids(me->inst, me->pid, me->cid, me->method);

		/* continue state transition processing of the instance */
		if (me->method != IM_START) {
			process_non_start_term(me->inst, ret);
		} else {
			process_start_term(me->inst);
		}

		if (me->cid != -1)
			(void) abandon_contract(me->cid);

		tmp = me;
		me = uu_list_next(method_list, me);
		unregister_method(tmp);
	}
}
