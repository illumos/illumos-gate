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
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 */

/*
 * wait.c - asynchronous monitoring of "wait registered" start methods
 *
 * Use event ports to poll on the set of fds representing the /proc/[pid]/psinfo
 * files.  If one of these fds returns an event, then we inform the restarter
 * that it has stopped.
 *
 * The wait_info_list holds the series of processes currently being monitored
 * for exit.  The wi_fd member, which contains the file descriptor of the psinfo
 * file being polled upon ("event ported upon"), will be set to -1 if the file
 * descriptor is inactive (already closed or not yet opened).
 */

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif /* _FILE_OFFSET_BITS */

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libuutil.h>
#include <poll.h>
#include <port.h>
#include <pthread.h>
#include <procfs.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include "startd.h"

#define	WAIT_FILES	262144		/* reasonably high maximum */

static int port_fd;
static scf_handle_t *wait_hndl;
static struct rlimit init_fd_rlimit;

static uu_list_pool_t *wait_info_pool;
static uu_list_t *wait_info_list;

static pthread_mutex_t wait_info_lock;

/*
 * void wait_remove(wait_info_t *, int)
 *   Remove the given wait_info structure from our list, performing various
 *   cleanup operations along the way.  If the direct flag is false (meaning
 *   that we are being called with from restarter instance list context) and
 *   the instance should not be ignored, then notify the restarter that the
 *   associated instance has exited. If the wi_ignore flag is true then it
 *   means that the stop was initiated from within svc.startd, rather than
 *   from outside it.
 *
 *   Since we may no longer be the startd that started this process, we only are
 *   concerned with a waitpid(3C) failure if the wi_parent field is non-zero.
 */
static void
wait_remove(wait_info_t *wi, int direct)
{
	int status;
	stop_cause_t cause = RSTOP_EXIT;

	if (waitpid(wi->wi_pid, &status, 0) == -1) {
		if (wi->wi_parent)
			log_framework(LOG_INFO,
			    "instance %s waitpid failure: %s\n", wi->wi_fmri,
			    strerror(errno));
	} else {
		if (WEXITSTATUS(status) != 0) {
			log_framework(LOG_NOTICE,
			    "instance %s exited with status %d\n", wi->wi_fmri,
			    WEXITSTATUS(status));
			if (WEXITSTATUS(status) == SMF_EXIT_ERR_CONFIG)
				cause = RSTOP_ERR_CFG;
			else
				cause = RSTOP_ERR_EXIT;
		}
	}

	MUTEX_LOCK(&wait_info_lock);
	if (wi->wi_fd != -1) {
		startd_close(wi->wi_fd);
		wi->wi_fd = -1;
	}
	uu_list_remove(wait_info_list, wi);
	MUTEX_UNLOCK(&wait_info_lock);

	/*
	 * Make an attempt to clear out any utmpx record associated with this
	 * PID.
	 */
	utmpx_mark_dead(wi->wi_pid, status, B_FALSE);

	if (!direct && !wi->wi_ignore) {
		/*
		 * Bind wait_hndl lazily.
		 */
		if (wait_hndl == NULL) {
			for (wait_hndl =
			    libscf_handle_create_bound(SCF_VERSION);
			    wait_hndl == NULL;
			    wait_hndl =
			    libscf_handle_create_bound(SCF_VERSION)) {
				log_error(LOG_INFO, "[wait_remove] Unable to "
				    "bind a new repository handle: %s\n",
				    scf_strerror(scf_error()));
				(void) sleep(2);
			}
		}

		log_framework(LOG_DEBUG,
		    "wait_remove requesting stop of %s\n", wi->wi_fmri);
		(void) stop_instance_fmri(wait_hndl, wi->wi_fmri, cause);
	}

	uu_list_node_fini(wi, &wi->wi_link, wait_info_pool);
	startd_free(wi, sizeof (wait_info_t));
}

/*
 * void wait_ignore_by_fmri(const char *)
 *   wait_ignore_by_fmri is called when svc.startd is going to stop the
 *   instance. Since we need to wait on the process and close the utmpx record,
 *   we're going to set the wi_ignore flag, so that when the process exits we
 *   clean up, but don't tell the restarter to stop it.
 */
void
wait_ignore_by_fmri(const char *fmri)
{
	wait_info_t *wi;

	MUTEX_LOCK(&wait_info_lock);

	for (wi = uu_list_first(wait_info_list); wi != NULL;
	    wi = uu_list_next(wait_info_list, wi)) {
		if (strcmp(wi->wi_fmri, fmri) == 0)
			break;
	}

	if (wi != NULL) {
		wi->wi_ignore = 1;
	}

	MUTEX_UNLOCK(&wait_info_lock);
}

/*
 * int wait_register(pid_t, char *, int, int)
 *   wait_register is called after we have called fork(2), and know which pid we
 *   wish to monitor.  However, since the child may have already exited by the
 *   time we are called, we must handle the error cases from open(2)
 *   appropriately.  The am_parent flag is recorded to handle waitpid(2)
 *   behaviour on removal; similarly, the direct flag is passed through to a
 *   potential call to wait_remove() to govern its behaviour in different
 *   contexts.
 *
 *   Returns 0 if registration successful, 1 if child pid did not exist, and -1
 *   if a different error occurred.
 */
int
wait_register(pid_t pid, const char *inst_fmri, int am_parent, int direct)
{
	char *fname = uu_msprintf("/proc/%ld/psinfo", pid);
	int fd;
	wait_info_t *wi;

	assert(pid != 0);

	if (fname == NULL)
		return (-1);

	wi = startd_alloc(sizeof (wait_info_t));

	uu_list_node_init(wi, &wi->wi_link, wait_info_pool);

	wi->wi_fd = -1;
	wi->wi_pid = pid;
	wi->wi_fmri = inst_fmri;
	wi->wi_parent = am_parent;
	wi->wi_ignore = 0;

	MUTEX_LOCK(&wait_info_lock);
	(void) uu_list_insert_before(wait_info_list, NULL, wi);
	MUTEX_UNLOCK(&wait_info_lock);

	if ((fd = open(fname, O_RDONLY)) == -1) {
		if (errno == ENOENT) {
			/*
			 * Child has already exited.
			 */
			wait_remove(wi, direct);
			uu_free(fname);
			return (1);
		} else {
			log_error(LOG_WARNING,
			    "open %s failed; not monitoring %s: %s\n", fname,
			    inst_fmri, strerror(errno));
			uu_free(fname);
			return (-1);
		}
	}

	uu_free(fname);

	wi->wi_fd = fd;

	if (port_associate(port_fd, PORT_SOURCE_FD, fd, 0, wi)) {
		log_error(LOG_WARNING,
		    "initial port_association of %d / %s failed: %s\n", fd,
		    inst_fmri, strerror(errno));
		return (-1);
	}

	log_framework(LOG_DEBUG, "monitoring PID %ld on fd %d (%s)\n", pid, fd,
	    inst_fmri);

	return (0);
}

/*ARGSUSED*/
void *
wait_thread(void *args)
{
	for (;;) {
		port_event_t pe;
		int fd;
		wait_info_t *wi;

		if (port_get(port_fd, &pe, NULL) != 0) {
			if (errno == EINTR)
				continue;
			else {
				log_error(LOG_WARNING,
				    "port_get() failed with %s\n",
				    strerror(errno));
				bad_error("port_get", errno);
			}
		}

		fd = pe.portev_object;
		wi = pe.portev_user;
		assert(wi != NULL);
		assert(fd == wi->wi_fd);

		if ((pe.portev_events & POLLHUP) == POLLHUP) {
			psinfo_t psi;

			if (lseek(fd, 0, SEEK_SET) != 0 ||
			    read(fd, &psi, sizeof (psinfo_t)) !=
			    sizeof (psinfo_t)) {
				log_framework(LOG_WARNING,
				    "couldn't get psinfo data for %s (%s); "
				    "assuming failed\n", wi->wi_fmri,
				    strerror(errno));
				goto err_remove;
			}

			if (psi.pr_nlwp != 0 ||
			    psi.pr_nzomb != 0 ||
			    psi.pr_lwp.pr_lwpid != 0) {
				/*
				 * We have determined, in accordance with the
				 * definition in proc(4), this process is not a
				 * zombie.  Reassociate.
				 */
				if (port_associate(port_fd, PORT_SOURCE_FD, fd,
				    0, wi))
					log_error(LOG_WARNING,
					    "port_association of %d / %s "
					    "failed\n", fd, wi->wi_fmri);
				continue;
			}
		} else if (
		    (pe.portev_events & POLLERR) == 0) {
			if (port_associate(port_fd, PORT_SOURCE_FD, fd, 0, wi))
				log_error(LOG_WARNING,
				    "port_association of %d / %s "
				    "failed\n", fd, wi->wi_fmri);
			continue;
		}

err_remove:
		wait_remove(wi, 0);
	}

	/*LINTED E_FUNC_HAS_NO_RETURN_STMT*/
}

void
wait_prefork()
{
	MUTEX_LOCK(&wait_info_lock);
}

void
wait_postfork(pid_t pid)
{
	wait_info_t *wi;

	MUTEX_UNLOCK(&wait_info_lock);

	if (pid != 0)
		return;

	/*
	 * Close all of the child's wait-related fds.  The wait_thread() is
	 * gone, so no need to worry about returning events.  We always exec(2)
	 * after a fork request, so we needn't free the list elements
	 * themselves.
	 */

	for (wi = uu_list_first(wait_info_list);
	    wi != NULL;
	    wi = uu_list_next(wait_info_list, wi)) {
		if (wi->wi_fd != -1)
			startd_close(wi->wi_fd);
	}

	startd_close(port_fd);

	(void) setrlimit(RLIMIT_NOFILE, &init_fd_rlimit);
}

void
wait_init()
{
	struct rlimit fd_new;

	(void) getrlimit(RLIMIT_NOFILE, &init_fd_rlimit);
	(void) getrlimit(RLIMIT_NOFILE, &fd_new);

	fd_new.rlim_max = fd_new.rlim_cur = WAIT_FILES;

	(void) setrlimit(RLIMIT_NOFILE, &fd_new);

	if ((port_fd = port_create()) == -1)
		uu_die("wait_init couldn't port_create");

	wait_info_pool = uu_list_pool_create("wait_info", sizeof (wait_info_t),
	    offsetof(wait_info_t, wi_link), NULL, UU_LIST_POOL_DEBUG);
	if (wait_info_pool == NULL)
		uu_die("wait_init couldn't create wait_info_pool");

	wait_info_list = uu_list_create(wait_info_pool, wait_info_list, 0);
	if (wait_info_list == NULL)
		uu_die("wait_init couldn't create wait_info_list");

	(void) pthread_mutex_init(&wait_info_lock, &mutex_attrs);
}
