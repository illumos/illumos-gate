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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * fork.c - safe forking for svc.startd
 *
 * fork_configd() and fork_sulogin() are related, special cases that handle the
 * spawning of specific client processes for svc.startd.
 */

#include <sys/contract/process.h>
#include <sys/corectl.h>
#include <sys/ctfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libscf_priv.h>
#include <limits.h>
#include <poll.h>
#include <port.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>
#include <spawn.h>

#include "manifest_hash.h"
#include "configd_exit.h"
#include "protocol.h"
#include "startd.h"

static	struct	utmpx	*utmpp;	/* pointer for getutxent() */

pid_t
startd_fork1(int *forkerr)
{
	pid_t p;

	/*
	 * prefork stack
	 */
	wait_prefork();
	utmpx_prefork();

	p = fork1();

	if (p == -1 && forkerr != NULL)
		*forkerr = errno;

	/*
	 * postfork stack
	 */
	utmpx_postfork();
	wait_postfork(p);

	return (p);
}

/*
 * void fork_mount(char *, char *)
 *   Run mount(1M) with the given options and mount point.  (mount(1M) has much
 *   hidden knowledge; it's much less correct to reimplement that logic here to
 *   save a fork(2)/exec(2) invocation.)
 */
int
fork_mount(char *path, char *opts)
{
	pid_t pid;
	uint_t tries = 0;
	int status;

	for (pid = fork1(); pid == -1; pid = fork1()) {
		if (++tries > MAX_MOUNT_RETRIES)
			return (-1);

		(void) sleep(tries);
	}

	if (pid != 0) {
		(void) waitpid(pid, &status, 0);

		/*
		 * If our mount(1M) invocation exited by peculiar means, or with
		 * a non-zero status, our mount likelihood is low.
		 */
		if (!WIFEXITED(status) ||
		    WEXITSTATUS(status) != 0)
			return (-1);

		return (0);
	}

	(void) execl("/sbin/mount", "mount", "-o", opts, path, NULL);

	return (-1);
}

/*
 * pid_t fork_common(...)
 *   Common routine used by fork_sulogin, fork_emi, and fork_configd to
 *   fork a process in a contract with the provided terms.  Invokes
 *   fork_sulogin (with its no-fork argument set) on errors.
 */
static pid_t
fork_common(const char *name, const char *svc_fmri, int retries, ctid_t *ctidp,
    uint_t inf, uint_t crit, uint_t fatal, uint_t param, uint64_t cookie)
{
	uint_t tries = 0;
	int ctfd, err;
	pid_t pid;

	/*
	 * Establish process contract terms.
	 */
	if ((ctfd = open64(CTFS_ROOT "/process/template", O_RDWR)) == -1) {
		fork_sulogin(B_TRUE, "Could not open process contract template "
		    "for %s: %s\n", name, strerror(errno));
		/* NOTREACHED */
	}

	err = ct_tmpl_set_critical(ctfd, crit);
	err |= ct_pr_tmpl_set_fatal(ctfd, fatal);
	err |= ct_tmpl_set_informative(ctfd, inf);
	err |= ct_pr_tmpl_set_param(ctfd, param);
	err |= ct_tmpl_set_cookie(ctfd, cookie);
	err |= ct_pr_tmpl_set_svc_fmri(ctfd, svc_fmri);
	err |= ct_pr_tmpl_set_svc_aux(ctfd, name);
	if (err) {
		(void) close(ctfd);
		fork_sulogin(B_TRUE, "Could not set %s process contract "
		    "terms\n", name);
		/* NOTREACHED */
	}

	if (err = ct_tmpl_activate(ctfd)) {
		(void) close(ctfd);
		fork_sulogin(B_TRUE, "Could not activate %s process contract "
		    "template: %s\n", name, strerror(err));
		/* NOTREACHED */
	}

	utmpx_prefork();

	/*
	 * Attempt to fork "retries" times.
	 */
	for (pid = fork1(); pid == -1; pid = fork1()) {
		if (++tries > retries) {
			/*
			 * When we exit the sulogin session, init(1M)
			 * will restart svc.startd(1M).
			 */
			err = errno;
			(void) ct_tmpl_clear(ctfd);
			(void) close(ctfd);
			utmpx_postfork();
			fork_sulogin(B_TRUE, "Could not fork to start %s: %s\n",
			    name, strerror(err));
			/* NOTREACHED */
		}
		(void) sleep(tries);
	}

	utmpx_postfork();

	/*
	 * Clean up, return pid and ctid.
	 */
	if (pid != 0 && (errno = contract_latest(ctidp)) != 0)
		uu_die("Could not get new contract id for %s\n", name);
	(void) ct_tmpl_clear(ctfd);
	(void) close(ctfd);

	return (pid);
}

/*
 * void fork_sulogin(boolean_t, const char *, ...)
 *   When we are invoked with the -s flag from boot (or run into an unfixable
 *   situation), we run a private copy of sulogin.  When the sulogin session
 *   is ended, we continue.  This is the last fallback action for system
 *   maintenance.
 *
 *   If immediate is true, fork_sulogin() executes sulogin(1M) directly, without
 *   forking.
 *
 *   Because fork_sulogin() is needed potentially before we daemonize, we leave
 *   it outside the wait_register() framework.
 */
/*PRINTFLIKE2*/
void
fork_sulogin(boolean_t immediate, const char *format, ...)
{
	va_list args;
	int fd_console;

	(void) printf("Requesting System Maintenance Mode\n");

	if (!booting_to_single_user)
		(void) printf("(See /lib/svc/share/README for more "
		    "information.)\n");

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);

	if (!immediate) {
		ctid_t	ctid;
		pid_t	pid;

		pid = fork_common("sulogin", SVC_SULOGIN_FMRI,
		    MAX_SULOGIN_RETRIES, &ctid, CT_PR_EV_HWERR, 0,
		    CT_PR_EV_HWERR, CT_PR_PGRPONLY, SULOGIN_COOKIE);

		if (pid != 0) {
			(void) waitpid(pid, NULL, 0);
			contract_abandon(ctid);
			return;
		}
		/* close all inherited fds */
		closefrom(0);
	} else {
		(void) printf("Directly executing sulogin.\n");
		/*
		 * Can't call closefrom() in this MT section
		 * so safely close a minimum set of fds.
		 */
		(void) close(STDIN_FILENO);
		(void) close(STDOUT_FILENO);
		(void) close(STDERR_FILENO);
	}

	(void) setpgrp();

	/* open the console for sulogin */
	if ((fd_console = open("/dev/console", O_RDWR)) >= 0) {
		if (fd_console != STDIN_FILENO)
			while (dup2(fd_console, STDIN_FILENO) < 0 &&
			    errno == EINTR)
				;
		if (fd_console != STDOUT_FILENO)
			while (dup2(fd_console, STDOUT_FILENO) < 0 &&
			    errno == EINTR)
				;
		if (fd_console != STDERR_FILENO)
			while (dup2(fd_console, STDERR_FILENO) < 0 &&
			    errno == EINTR)
				;
		if (fd_console > STDERR_FILENO)
			(void) close(fd_console);
	}

	setutxent();
	while ((utmpp = getutxent()) != NULL) {
		if (strcmp(utmpp->ut_user, "LOGIN") != 0) {
			if (strcmp(utmpp->ut_line, "console") == 0) {
				(void) kill(utmpp->ut_pid, 9);
				break;
			}
		}
	}

	(void) execl("/sbin/sulogin", "sulogin", NULL);

	uu_warn("Could not exec() sulogin");

	exit(1);
}

#define	CONFIGD_PATH	"/lib/svc/bin/svc.configd"

/*
 * void fork_configd(int status)
 *   We are interested in exit events (since the parent's exiting means configd
 *   is ready to run and since the child's exiting indicates an error case) and
 *   in empty events.  This means we have a unique template for initiating
 *   configd.
 */
void
fork_configd(int exitstatus)
{
	pid_t pid;
	ctid_t ctid = -1;
	int err;
	char path[PATH_MAX];

	/*
	 * Checking the existatus for the potential failure of the
	 * daemonized svc.configd.  If this is not the first time
	 * through, but a call from the svc.configd monitoring thread
	 * after a failure this is the status that is expected.  Other
	 * failures are exposed during initialization or are fixed
	 * by a restart (e.g door closings).
	 *
	 * If this is on-disk database corruption it will also be
	 * caught by a restart but could be cleared before the restart.
	 *
	 * Or this could be internal database corruption due to a
	 * rogue service that needs to be cleared before restart.
	 */
	if (WEXITSTATUS(exitstatus) == CONFIGD_EXIT_DATABASE_BAD) {
		fork_sulogin(B_FALSE, "svc.configd exited with database "
		    "corrupt error after initialization of the repository\n");
	}

retry:
	log_framework(LOG_DEBUG, "fork_configd trying to start svc.configd\n");

	/*
	 * If we're retrying, we will have an old contract lying around
	 * from the failure.  Since we're going to be creating a new
	 * contract shortly, we abandon the old one now.
	 */
	if (ctid != -1)
		contract_abandon(ctid);
	ctid = -1;

	pid = fork_common("svc.configd", SCF_SERVICE_CONFIGD,
	    MAX_CONFIGD_RETRIES, &ctid, 0, CT_PR_EV_EXIT, 0,
	    CT_PR_INHERIT | CT_PR_REGENT, CONFIGD_COOKIE);

	if (pid != 0) {
		int exitstatus;

		st->st_configd_pid = pid;

		if (waitpid(pid, &exitstatus, 0) == -1) {
			fork_sulogin(B_FALSE, "waitpid on svc.configd "
			    "failed: %s\n", strerror(errno));
		} else if (WIFEXITED(exitstatus)) {
			char *errstr;

			/*
			 * Examine exitstatus.  This will eventually get more
			 * complicated, as we will want to teach startd how to
			 * invoke configd with alternate repositories, etc.
			 *
			 * Note that exec(2) failure results in an exit status
			 * of 1, resulting in the default clause below.
			 */

			/*
			 * Assign readable strings to cases we don't handle, or
			 * have error outcomes that cannot be eliminated.
			 */
			switch (WEXITSTATUS(exitstatus)) {
			case CONFIGD_EXIT_BAD_ARGS:
				errstr = "bad arguments";
				break;

			case CONFIGD_EXIT_DATABASE_BAD:
				errstr = "database corrupt";
				break;

			case CONFIGD_EXIT_DATABASE_LOCKED:
				errstr = "database locked";
				break;
			case CONFIGD_EXIT_INIT_FAILED:
				errstr = "initialization failure";
				break;
			case CONFIGD_EXIT_DOOR_INIT_FAILED:
				errstr = "door initialization failure";
				break;
			case CONFIGD_EXIT_DATABASE_INIT_FAILED:
				errstr = "database initialization failure";
				break;
			case CONFIGD_EXIT_NO_THREADS:
				errstr = "no threads available";
				break;
			case CONFIGD_EXIT_LOST_MAIN_DOOR:
				errstr = "lost door server attachment";
				break;
			case 1:
				errstr = "execution failure";
				break;
			default:
				errstr = "unknown error";
				break;
			}

			/*
			 * Remedial actions for various configd failures.
			 */
			switch (WEXITSTATUS(exitstatus)) {
			case CONFIGD_EXIT_OKAY:
				break;

			case CONFIGD_EXIT_DATABASE_LOCKED:
				/* attempt remount of / read-write */
				if (fs_is_read_only("/", NULL) == 1) {
					if (fs_remount("/") == -1)
						fork_sulogin(B_FALSE,
						    "remount of root "
						    "filesystem failed\n");

					goto retry;
				}
				break;

			default:
				fork_sulogin(B_FALSE, "svc.configd exited "
				    "with status %d (%s)\n",
				    WEXITSTATUS(exitstatus), errstr);
				goto retry;
			}
		} else if (WIFSIGNALED(exitstatus)) {
			char signame[SIG2STR_MAX];

			if (sig2str(WTERMSIG(exitstatus), signame))
				(void) snprintf(signame, SIG2STR_MAX,
				    "signum %d", WTERMSIG(exitstatus));

			fork_sulogin(B_FALSE, "svc.configd signalled:"
			    " %s\n", signame);

			goto retry;
		} else {
			fork_sulogin(B_FALSE, "svc.configd non-exit "
			    "condition: 0x%x\n", exitstatus);

			goto retry;
		}

		/*
		 * Announce that we have a valid svc.configd status.
		 */
		MUTEX_LOCK(&st->st_configd_live_lock);
		st->st_configd_lives = 1;
		err = pthread_cond_broadcast(&st->st_configd_live_cv);
		assert(err == 0);
		MUTEX_UNLOCK(&st->st_configd_live_lock);

		log_framework(LOG_DEBUG, "fork_configd broadcasts configd is "
		    "live\n");
		return;
	}

	/*
	 * Set our per-process core file path to leave core files in
	 * /etc/svc/volatile directory, named after the PID to aid in debugging.
	 */
	(void) snprintf(path, sizeof (path),
	    "/etc/svc/volatile/core.configd.%%p");

	(void) core_set_process_path(path, strlen(path) + 1, getpid());

	log_framework(LOG_DEBUG, "executing svc.configd\n");

	(void) execl(CONFIGD_PATH, CONFIGD_PATH, NULL);

	/*
	 * Status code is used above to identify configd exec failure.
	 */
	exit(1);
}

void *
fork_configd_thread(void *vctid)
{
	int fd, err;
	ctid_t configd_ctid = (ctid_t)vctid;

	if (configd_ctid == -1) {
		log_framework(LOG_DEBUG,
		    "fork_configd_thread starting svc.configd\n");
		fork_configd(0);
	} else {
		/*
		 * configd_ctid is known:  we broadcast and continue.
		 * test contract for appropriate state by verifying that
		 * there is one or more processes within it?
		 */
		log_framework(LOG_DEBUG,
		    "fork_configd_thread accepting svc.configd with CTID %ld\n",
		    configd_ctid);
		MUTEX_LOCK(&st->st_configd_live_lock);
		st->st_configd_lives = 1;
		(void) pthread_cond_broadcast(&st->st_configd_live_cv);
		MUTEX_UNLOCK(&st->st_configd_live_lock);
	}

	fd = open64(CTFS_ROOT "/process/pbundle", O_RDONLY);
	if (fd == -1)
		uu_die("process bundle open failed");

	/*
	 * Make sure we get all events (including those generated by configd
	 * before this thread was started).
	 */
	err = ct_event_reset(fd);
	assert(err == 0);

	for (;;) {
		int efd, sfd;
		ct_evthdl_t ev;
		uint32_t type;
		ctevid_t evid;
		ct_stathdl_t status;
		ctid_t ctid;
		uint64_t cookie;
		pid_t pid;

		if (err = ct_event_read_critical(fd, &ev)) {
			assert(err != EINVAL && err != EAGAIN);
			log_error(LOG_WARNING,
			    "Error reading next contract event: %s",
			    strerror(err));
			continue;
		}

		evid = ct_event_get_evid(ev);
		ctid = ct_event_get_ctid(ev);
		type = ct_event_get_type(ev);

		/* Fetch cookie. */
		sfd = contract_open(ctid, "process", "status", O_RDONLY);
		if (sfd < 0) {
			ct_event_free(ev);
			continue;
		}

		if (err = ct_status_read(sfd, CTD_COMMON, &status)) {
			log_framework(LOG_WARNING, "Could not get status for "
			    "contract %ld: %s\n", ctid, strerror(err));

			ct_event_free(ev);
			startd_close(sfd);
			continue;
		}

		cookie = ct_status_get_cookie(status);

		ct_status_free(status);

		startd_close(sfd);

		/*
		 * Don't process events from contracts we aren't interested in.
		 */
		if (cookie != CONFIGD_COOKIE) {
			ct_event_free(ev);
			continue;
		}

		if (type == CT_PR_EV_EXIT) {
			int exitstatus;

			(void) ct_pr_event_get_pid(ev, &pid);
			(void) ct_pr_event_get_exitstatus(ev,
			    &exitstatus);

			if (st->st_configd_pid != pid) {
				/*
				 * This is the child exiting, so we
				 * abandon the contract and restart
				 * configd.
				 */
				contract_abandon(ctid);
				fork_configd(exitstatus);
			}
		}

		efd = contract_open(ctid, "process", "ctl", O_WRONLY);
		if (efd != -1) {
			(void) ct_ctl_ack(efd, evid);
			startd_close(efd);
		}

		ct_event_free(ev);

	}

	/*NOTREACHED*/
	return (NULL);
}

void
fork_rc_script(char rl, const char *arg, boolean_t wait)
{
	pid_t pid;
	int tmpl, err, stat;
	char path[20] = "/sbin/rc.", log[20] = "rc..log", timebuf[20];
	time_t now;
	struct tm ltime;
	size_t sz;
	char *pathenv;
	char **nenv;

	path[8] = rl;

	tmpl = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (tmpl >= 0) {
		err = ct_tmpl_set_critical(tmpl, 0);
		assert(err == 0);

		err = ct_tmpl_set_informative(tmpl, 0);
		assert(err == 0);

		err = ct_pr_tmpl_set_fatal(tmpl, 0);
		assert(err == 0);

		err = ct_tmpl_activate(tmpl);
		assert(err == 0);

		err = close(tmpl);
		assert(err == 0);
	} else {
		uu_warn("Could not create contract template for %s.\n", path);
	}

	pid = startd_fork1(NULL);
	if (pid < 0) {
		return;
	} else if (pid != 0) {
		/* parent */
		if (wait) {
			do
				err = waitpid(pid, &stat, 0);
			while (err != 0 && errno == EINTR)
				;

			if (!WIFEXITED(stat)) {
				log_framework(LOG_INFO,
				    "%s terminated with waitpid() status %d.\n",
				    path, stat);
			} else if (WEXITSTATUS(stat) != 0) {
				log_framework(LOG_INFO,
				    "%s failed with status %d.\n", path,
				    WEXITSTATUS(stat));
			}
		}

		return;
	}

	/* child */

	log[2] = rl;

	setlog(log);

	now = time(NULL);
	sz = strftime(timebuf, sizeof (timebuf), "%b %e %T",
	    localtime_r(&now, &ltime));
	assert(sz != 0);

	(void) fprintf(stderr, "%s Executing %s %s\n", timebuf, path, arg);

	if (rl == 'S')
		pathenv = "PATH=/sbin:/usr/sbin:/usr/bin";
	else
		pathenv = "PATH=/usr/sbin:/usr/bin";

	nenv = set_smf_env(NULL, 0, pathenv, NULL, NULL);

	(void) execle(path, path, arg, 0, nenv);

	perror("exec");
	exit(0);
}

#define	SVCCFG_PATH	"/usr/sbin/svccfg"
#define	EMI_MFST	"/lib/svc/manifest/system/early-manifest-import.xml"
#define	EMI_PATH	"/lib/svc/method/manifest-import"

/*
 * Set Early Manifest Import service's state and log file.
 */
static int
emi_set_state(restarter_instance_state_t state, boolean_t setlog)
{
	int r, ret = 1;
	instance_data_t idata;
	scf_handle_t *hndl = NULL;
	scf_instance_t *inst = NULL;

retry:
	if (hndl == NULL)
		hndl = libscf_handle_create_bound(SCF_VERSION);

	if (hndl == NULL) {
		/*
		 * In the case that we can't bind to the repository
		 * (which should have been started), we need to allow
		 * the user into maintenance mode to determine what's
		 * failed.
		 */
		fork_sulogin(B_FALSE, "Unable to bind a new repository"
		    " handle: %s\n", scf_strerror(scf_error()));
		goto retry;
	}

	if (inst == NULL)
		inst = safe_scf_instance_create(hndl);

	if (scf_handle_decode_fmri(hndl, SCF_INSTANCE_EMI, NULL, NULL,
	    inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			goto out;

		case SCF_ERROR_CONNECTION_BROKEN:
		case SCF_ERROR_NOT_BOUND:
			libscf_handle_rebind(hndl);
			goto retry;

		default:
			fork_sulogin(B_FALSE, "Couldn't fetch %s service: "
			    "%s\n", SCF_INSTANCE_EMI,
			    scf_strerror(scf_error()));
			goto retry;
		}
	}

	if (setlog) {
		(void) libscf_note_method_log(inst, st->st_log_prefix, EMI_LOG);
		log_framework(LOG_DEBUG,
		    "Set logfile property for %s\n", SCF_INSTANCE_EMI);
	}

	idata.i_fmri = SCF_INSTANCE_EMI;
	idata.i_state =  RESTARTER_STATE_NONE;
	idata.i_next_state = RESTARTER_STATE_NONE;
	switch (r = _restarter_commit_states(hndl, &idata, state,
	    RESTARTER_STATE_NONE, NULL)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(hndl);
		goto retry;

	case ENOMEM:
	case ENOENT:
	case EPERM:
	case EACCES:
	case EROFS:
		fork_sulogin(B_FALSE, "Could not set state of "
		    "%s: %s\n", SCF_INSTANCE_EMI, strerror(r));
		goto retry;

	case EINVAL:
	default:
		bad_error("_restarter_commit_states", r);
	}
	ret = 0;

out:
	scf_instance_destroy(inst);
	scf_handle_destroy(hndl);
	return (ret);
}

/*
 * It is possible that the early-manifest-import service is disabled.  This
 * would not be the normal case for Solaris, but it may happen on dedicated
 * systems.  So this function checks the state of the general/enabled
 * property for Early Manifest Import.
 *
 * It is also possible that the early-manifest-import service does not yet
 * have a repository representation when this function runs.  This happens
 * if non-Early Manifest Import system is upgraded to an Early Manifest
 * Import based system.  Thus, the non-existence of general/enabled is not
 * an error.
 *
 * Returns 1 if Early Manifest Import is disabled and 0 otherwise.
 */
static int
emi_is_disabled()
{
	int disabled = 0;
	int disconnected = 1;
	int enabled;
	scf_handle_t *hndl = NULL;
	scf_instance_t *inst = NULL;
	uchar_t stored_hash[MHASH_SIZE];
	char *pname;
	int hashash, r;

	while (hndl == NULL) {
		hndl = libscf_handle_create_bound(SCF_VERSION);

		if (hndl == NULL) {
			/*
			 * In the case that we can't bind to the repository
			 * (which should have been started), we need to
			 * allow the user into maintenance mode to
			 * determine what's failed.
			 */
			fork_sulogin(B_FALSE, "Unable to bind a new repository "
			    "handle: %s\n", scf_strerror(scf_error()));
		}
	}

	while (disconnected) {
		r = libscf_fmri_get_instance(hndl, SCF_INSTANCE_EMI, &inst);
		if (r != 0) {
			switch (r) {
			case ECONNABORTED:
				libscf_handle_rebind(hndl);
				continue;

			case ENOENT:
				/*
				 * Early Manifest Import service is not in
				 * the repository. Check the manifest file
				 * and service's hash in smf/manifest to
				 * figure out whether Early Manifest Import
				 * service was deleted. If Early Manifest Import
				 * service was deleted, treat that as a disable
				 * and don't run early import.
				 */

				if (access(EMI_MFST, F_OK)) {
					/*
					 * Manifest isn't found, so service is
					 * properly removed.
					 */
					disabled = 1;
				} else {
					/*
					 * If manifest exists and we have the
					 * hash, the service was improperly
					 * deleted, generate a warning and treat
					 * this as a disable.
					 */

					if ((pname = mhash_filename_to_propname(
					    EMI_MFST, B_TRUE)) == NULL) {
						/*
						 * Treat failure to get propname
						 * as a disable.
						 */
						disabled = 1;
						uu_warn("Failed to get propname"
						    " for %s.\n",
						    SCF_INSTANCE_EMI);
					} else {
						hashash = mhash_retrieve_entry(
						    hndl, pname,
						    stored_hash,
						    NULL) == 0;
						uu_free(pname);

						if (hashash) {
							disabled = 1;
							uu_warn("%s service is "
							    "deleted \n",
							    SCF_INSTANCE_EMI);
						}
					}

				}

				disconnected = 0;
				continue;

			default:
				bad_error("libscf_fmri_get_instance",
				    scf_error());
			}
		}
		r = libscf_get_basic_instance_data(hndl, inst, SCF_INSTANCE_EMI,
		    &enabled, NULL, NULL);
		if (r == 0) {
			/*
			 * enabled can be returned as -1, which indicates
			 * that the enabled property was not found.  To us
			 * that means that the service was not disabled.
			 */
			if (enabled == 0)
				disabled = 1;
		} else {
			switch (r) {
			case ECONNABORTED:
				libscf_handle_rebind(hndl);
				continue;

			case ECANCELED:
			case ENOENT:
				break;
			default:
				bad_error("libscf_get_basic_instance_data", r);
			}
		}
		disconnected = 0;
	}

out:
	if (inst != NULL)
		scf_instance_destroy(inst);
	scf_handle_destroy(hndl);
	return (disabled);
}

void
fork_emi()
{
	pid_t pid;
	ctid_t ctid = -1;
	char **envp, **np;
	char *emipath;
	char corepath[PATH_MAX];
	char *svc_state;
	int setemilog;
	int sz;

	if (emi_is_disabled()) {
		log_framework(LOG_NOTICE, "%s is  disabled and will "
		    "not be run.\n", SCF_INSTANCE_EMI);
		return;
	}

	/*
	 * Early Manifest Import should run only once, at boot. If svc.startd
	 * is some how restarted, Early Manifest Import  should not run again.
	 * Use the Early Manifest Import service's state to figure out whether
	 * Early Manifest Import has successfully completed earlier and bail
	 * out if it did.
	 */
	if (svc_state = smf_get_state(SCF_INSTANCE_EMI)) {
		if (strcmp(svc_state, SCF_STATE_STRING_ONLINE) == 0) {
			free(svc_state);
			return;
		}
		free(svc_state);
	}

	/*
	 * Attempt to set Early Manifest Import service's state and log file.
	 * If emi_set_state fails, set log file again in the next call to
	 * emi_set_state.
	 */
	setemilog = emi_set_state(RESTARTER_STATE_OFFLINE, B_TRUE);

	/* Don't go further if /usr isn't available */
	if (access(SVCCFG_PATH, F_OK)) {
		log_framework(LOG_NOTICE, "Early Manifest Import is not "
		    "supported on systems with a separate /usr filesystem.\n");
		return;
	}

fork_retry:
	log_framework(LOG_DEBUG, "Starting Early Manifest Import\n");

	/*
	 * If we're retrying, we will have an old contract lying around
	 * from the failure.  Since we're going to be creating a new
	 * contract shortly, we abandon the old one now.
	 */
	if (ctid != -1)
		contract_abandon(ctid);
	ctid = -1;

	pid = fork_common(SCF_INSTANCE_EMI, SCF_INSTANCE_EMI,
	    MAX_EMI_RETRIES, &ctid, 0, 0, 0, 0, EMI_COOKIE);

	if (pid != 0) {
		int exitstatus;

		if (waitpid(pid, &exitstatus, 0) == -1) {
			fork_sulogin(B_FALSE, "waitpid on %s failed: "
			    "%s\n", SCF_INSTANCE_EMI, strerror(errno));
		} else if (WIFEXITED(exitstatus)) {
			if (WEXITSTATUS(exitstatus)) {
				fork_sulogin(B_FALSE, "%s exited with status "
				    "%d \n", SCF_INSTANCE_EMI,
				    WEXITSTATUS(exitstatus));
				goto fork_retry;
			}
		} else if (WIFSIGNALED(exitstatus)) {
			char signame[SIG2STR_MAX];

			if (sig2str(WTERMSIG(exitstatus), signame))
				(void) snprintf(signame, SIG2STR_MAX,
				    "signum %d", WTERMSIG(exitstatus));

			fork_sulogin(B_FALSE, "%s signalled: %s\n",
			    SCF_INSTANCE_EMI, signame);
			goto fork_retry;
		} else {
			fork_sulogin(B_FALSE, "%s non-exit condition: 0x%x\n",
			    SCF_INSTANCE_EMI, exitstatus);
			goto fork_retry;
		}

		log_framework(LOG_DEBUG, "%s completed successfully\n",
		    SCF_INSTANCE_EMI);

		/*
		 * Once Early Manifest Import completed, the Early Manifest
		 * Import service must have been imported so set log file and
		 * state properties. Since this information is required for
		 * late manifest import and common admin operations, failing to
		 * set these properties should result in su login so admin can
		 * correct the problem.
		 */
		(void) emi_set_state(RESTARTER_STATE_ONLINE,
		    setemilog ? B_TRUE : B_FALSE);

		return;
	}

	/* child */

	/*
	 * Set our per-process core file path to leave core files in
	 * /etc/svc/volatile directory, named after the PID to aid in debugging.
	 */
	(void) snprintf(corepath, sizeof (corepath),
	    "/etc/svc/volatile/core.emi.%%p");
	(void) core_set_process_path(corepath, strlen(corepath) + 1, getpid());

	/*
	 * Similar to running legacy services, we need to manually set
	 * log files here and environment variables.
	 */
	setlog(EMI_LOG);

	envp = startd_zalloc(sizeof (char *) * 3);
	np = envp;

	sz = sizeof ("SMF_FMRI=") + strlen(SCF_INSTANCE_EMI);
	*np = startd_zalloc(sz);
	(void) strlcpy(*np, "SMF_FMRI=", sz);
	(void) strncat(*np, SCF_INSTANCE_EMI, sz);
	np++;

	emipath = getenv("PATH");
	if (emipath == NULL)
		emipath = strdup("/usr/sbin:/usr/bin");

	sz = sizeof ("PATH=") + strlen(emipath);
	*np = startd_zalloc(sz);
	(void) strlcpy(*np, "PATH=", sz);
	(void) strncat(*np, emipath, sz);

	log_framework(LOG_DEBUG, "executing Early Manifest Import\n");
	(void) execle(EMI_PATH, EMI_PATH, NULL, envp);

	/*
	 * Status code is used above to identify Early Manifest Import
	 * exec failure.
	 */
	exit(1);
}

extern char **environ;

/*
 * A local variation on system(3c) which accepts a timeout argument.  This
 * allows us to better ensure that the system will actually shut down.
 *
 * gracetime specifies an amount of time in seconds which the routine must wait
 * after the command exits, to allow for asynchronous effects (like sent
 * signals) to take effect.  This can be zero.
 */
void
fork_with_timeout(const char *cmd, uint_t gracetime, uint_t timeout)
{
	int err = 0;
	pid_t pid;
	char *argv[4];
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t factions;

	sigset_t mask, savemask;
	uint_t msec_timeout;
	uint_t msec_spent = 0;
	uint_t msec_gracetime;
	int status;

	msec_timeout = timeout * 1000;
	msec_gracetime = gracetime * 1000;

	/*
	 * See also system(3c) in libc.  This is very similar, except
	 * that we avoid some unneeded complexity.
	 */
	err = posix_spawnattr_init(&attr);
	if (err == 0)
		err = posix_spawnattr_setflags(&attr,
		    POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF |
		    POSIX_SPAWN_NOSIGCHLD_NP | POSIX_SPAWN_WAITPID_NP |
		    POSIX_SPAWN_NOEXECERR_NP);

	/*
	 * We choose to close fd's above 2, a deviation from system.
	 */
	if (err == 0)
		err = posix_spawn_file_actions_init(&factions);
	if (err == 0)
		err = posix_spawn_file_actions_addclosefrom_np(&factions,
		    STDERR_FILENO + 1);

	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	(void) thr_sigsetmask(SIG_BLOCK, &mask, &savemask);

	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = (char *)cmd;
	argv[3] = NULL;

	if (err == 0)
		err = posix_spawn(&pid, "/bin/sh", &factions, &attr,
		    (char *const *)argv, (char *const *)environ);

	(void) posix_spawnattr_destroy(&attr);
	(void) posix_spawn_file_actions_destroy(&factions);

	if (err) {
		uu_warn("Failed to spawn %s: %s\n", cmd, strerror(err));
	} else {
		for (;;) {
			int w;
			w = waitpid(pid, &status, WNOHANG);
			if (w == -1 && errno != EINTR)
				break;
			if (w > 0) {
				/*
				 * Command succeeded, so give it gracetime
				 * seconds for it to have an effect.
				 */
				if (status == 0 && msec_gracetime != 0)
					(void) poll(NULL, 0, msec_gracetime);
				break;
			}

			(void) poll(NULL, 0, 100);
			msec_spent += 100;
			/*
			 * If we timed out, kill off the process, then try to
			 * wait for it-- it's possible that we could accumulate
			 * a zombie here since we don't allow waitpid to hang,
			 * but it's better to let that happen and continue to
			 * make progress.
			 */
			if (msec_spent >= msec_timeout) {
				uu_warn("'%s' timed out after %d "
				    "seconds.  Killing.\n", cmd,
				    timeout);
				(void) kill(pid, SIGTERM);
				(void) poll(NULL, 0, 100);
				(void) kill(pid, SIGKILL);
				(void) poll(NULL, 0, 100);
				(void) waitpid(pid, &status, WNOHANG);
				break;
			}
		}
	}
	(void) thr_sigsetmask(SIG_BLOCK, &savemask, NULL);
}
