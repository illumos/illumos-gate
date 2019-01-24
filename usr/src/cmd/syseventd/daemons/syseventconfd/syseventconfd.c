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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * syseventconfd - The sysevent conf daemon
 *
 * This daemon is a companion to the sysevent_conf_mod module.
 *
 * The sysevent_conf_mod module receives events from syseventd,
 * and compares those events against event specs in the
 * sysevent.conf files.  For each matching event spec, the
 * specified command is invoked.
 *
 * This daemon manages the fork/exec's on behalf of sysevent_conf_mod.
 * The events and associated nvlist are delivered via a door upcall
 * from sysevent_conf_mod.  Arriving events are queued, and the
 * main thread of this daemon dequeues events one by one, and
 * builds the necessary arguments to fork/exec the command.
 *
 * Since sysevent_conf_mod is running in the context of syseventd,
 * invoking the fork/exec from that module blocks the door upcalls
 * from the kernel delivering events to syseventd.  We avoid a
 * major performance bottleneck in this fashion.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <syslog.h>
#include <pthread.h>
#include <door.h>
#include <libsysevent.h>
#include <limits.h>
#include <locale.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>

#include "syseventconfd.h"
#include "syseventconfd_door.h"
#include "message_confd.h"



static int	debug_level	= 0;
static char	*root_dir	= "";	/* Relative root for lock and door */
static char	*prog;

static struct cmd	*cmd_list;
static struct cmd	*cmd_tail;

static mutex_t		cmd_list_lock;
static cond_t		cmd_list_cv;

extern char *optarg;

/*
 * Support for door server thread handling
 */
#define	MAX_SERVER_THREADS	1

static mutex_t create_cnt_lock;
static int cnt_servers = 0;


static void
usage() {
	(void) fprintf(stderr, "usage: syseventconfd [-d <debug_level>]\n");
	exit(2);
}


static void
set_root_dir(char *dir)
{
	root_dir = malloc(strlen(dir) + 1);
	if (root_dir == NULL) {
		syserrmsg(INIT_ROOT_DIR_ERR, strerror(errno));
		exit(2);
	}
	(void) strcpy(root_dir, dir);
}


int
main(int argc, char **argv)
{
	int c;
	int fd;
	sigset_t set;
	struct cmd *cmd;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (getuid() != 0) {
		(void) fprintf(stderr, "Must be root to run syseventconfd\n");
		exit(1);
	}

	if ((prog = strrchr(argv[0], '/')) == NULL) {
		prog = argv[0];
	} else {
		prog++;
	}

	if ((c = getopt(argc, argv, "d:r:")) != EOF) {
		switch (c) {
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 'r':
			/*
			 * Private flag for suninstall to run
			 * daemon during install.
			 */
			set_root_dir(optarg);
			break;
		case '?':
		default:
			usage();
		}
	}


	if (fork()) {
		exit(0);
	}

	(void) chdir("/");

	(void) setsid();
	if (debug_level <= 1) {
		closefrom(0);
		fd = open("/dev/null", 0);
		(void) dup2(fd, 1);
		(void) dup2(fd, 2);
	}

	openlog("syseventconfd", LOG_PID, LOG_DAEMON);

	printmsg(1,
	    "syseventconfd started, debug level = %d\n", debug_level);

	/*
	 * Block all signals to all threads include the main thread.
	 * The sigwait_thr thread will catch and process all signals.
	 */
	(void) sigfillset(&set);
	(void) thr_sigsetmask(SIG_BLOCK, &set, NULL);

	/* Create signal catching thread */
	if (thr_create(NULL, 0, (void *(*)(void *))sigwait_thr,
		NULL, 0, NULL) < 0) {
		syserrmsg(INIT_THR_CREATE_ERR, strerror(errno));
		exit(2);
	}

	/*
	 * Init mutex and list of cmds to be fork/exec'ed
	 * This is multi-threaded so the fork/exec can be
	 * done without blocking the door upcall.
	 */
	cmd_list = NULL;
	cmd_tail = NULL;

	(void) mutex_init(&create_cnt_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&cmd_list_lock, USYNC_THREAD, NULL);
	(void) cond_init(&cmd_list_cv, USYNC_THREAD, NULL);

	/*
	 * Open communication channel from sysevent_conf_mod
	 */
	if (open_channel() == NULL) {
		exit(1);
	}

	/*
	 * main thread to wait for events to arrive and be placed
	 * on the queue.  As events are queued, dequeue them
	 * here and invoke the associated fork/exec.
	 */
	(void) mutex_lock(&cmd_list_lock);
	for (;;) {
		while (cmd_list == NULL)
			(void) cond_wait(&cmd_list_cv, &cmd_list_lock);

		cmd = cmd_list;
		cmd_list = cmd->cmd_next;
		if (cmd_list == NULL)
			cmd_tail = NULL;

		(void) mutex_unlock(&cmd_list_lock);
		exec_cmd(cmd);
		free_cmd(cmd);
		(void) mutex_lock(&cmd_list_lock);
	}
	/* NOTREACHED */
	return (0);
}

/*
 * Events sent via the door call from sysevent_conf_mod arrive
 * here.  Queue each event for the main thread to invoke, and
 * return.  We want to avoid doing the fork/exec while in the
 * context of the door call.
 */
/*ARGSUSED*/
static void
event_handler(sysevent_t *event)
{
	nvlist_t	*nvlist;
	struct cmd	*cmd;

	nvlist = NULL;
	if (sysevent_get_attr_list(event, &nvlist) != 0) {
		syslog(LOG_ERR, NO_NVLIST_ERR);
		return;
	}

	if ((cmd = alloc_cmd(nvlist)) != NULL) {
		(void) mutex_lock(&cmd_list_lock);
		if (cmd_list == NULL) {
			cmd_list = cmd;
			cmd_tail = cmd;
		} else {
			cmd_tail->cmd_next = cmd;
			cmd_tail = cmd;
		}
		cmd->cmd_next = NULL;
		(void) cond_signal(&cmd_list_cv);
		(void) mutex_unlock(&cmd_list_lock);
	}

	nvlist_free(nvlist);
}


/*
 * Decode the command, build the exec args and fork/exec the command
 * All command attributes are packed into the nvlist bundled with
 * the delivered event.
 */
static void
exec_cmd(struct cmd *cmd)
{
	char		*path;
	char		*cmdline;
	uid_t		uid;
	gid_t		gid;
	char		*file;
	int		line;
	char		*user;
	arg_t		*args;
	pid_t		pid;
	char		*lp;
	char		*p;
	int		i;
	sigset_t	set, prior_set;

	if (nvlist_lookup_string(cmd->cmd_nvlist, "user", &user) != 0) {
		syslog(LOG_ERR, NVLIST_FORMAT_ERR, "user");
		return;
	}
	if (nvlist_lookup_string(cmd->cmd_nvlist, "file", &file) != 0) {
		syslog(LOG_ERR, NVLIST_FORMAT_ERR, "file");
		return;
	}

	if (nvlist_lookup_string(cmd->cmd_nvlist, "path", &path) != 0) {
		syslog(LOG_ERR, NVLIST_FILE_LINE_FORMAT_ERR, "path");
		return;
	}
	if (nvlist_lookup_string(cmd->cmd_nvlist, "cmd", &cmdline) != 0) {
		syslog(LOG_ERR, NVLIST_FILE_LINE_FORMAT_ERR, "cmd");
		return;
	}
	if (nvlist_lookup_int32(cmd->cmd_nvlist, "line", &line) != 0) {
		syslog(LOG_ERR, NVLIST_FILE_LINE_FORMAT_ERR, "line");
		return;
	}
	if (nvlist_lookup_int32(cmd->cmd_nvlist, "uid", (int *)&uid) == 0) {
		if (nvlist_lookup_int32(cmd->cmd_nvlist,
		    "gid", (int *)&gid) != 0) {
			syslog(LOG_ERR, NVLIST_FILE_LINE_FORMAT_ERR, "gid");
			return;
		}
	} else {
		uid = 0;
		gid = 0;
	}

	args = init_arglist(32);

	lp = cmdline;
	while ((p = next_arg(&lp)) != NULL) {
		if (add_arg(args, p)) {
			free_arglist(args);
			return;
		}
	}

	if (debug_level >= DBG_EXEC) {
		printmsg(DBG_EXEC, "path=%s\n", path);
		printmsg(DBG_EXEC, "cmd=%s\n", cmdline);
	}

	if (debug_level >= DBG_EXEC_ARGS) {
		for (i = 0; i < args->arg_nargs; i++) {
			printmsg(DBG_EXEC_ARGS,
				"arg[%d]: '%s'\n", i, args->arg_args[i]);
		}
	}

	(void) sigprocmask(SIG_SETMASK, NULL, &set);
	(void) sigaddset(&set, SIGCHLD);
	(void) sigprocmask(SIG_SETMASK, &set, &prior_set);

again:
	if ((pid = fork1()) == (pid_t)-1) {
		if (errno == EINTR)
			goto again;
		syslog(LOG_ERR, CANNOT_FORK_ERR, strerror(errno));
		free_arglist(args);
		return;
	}
	if (pid != (pid_t)0) {
		(void) sigprocmask(SIG_SETMASK, &prior_set, NULL);
		free_arglist(args);
		return;
	}

	/*
	 * The child
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDONLY);
	(void) dup2(0, 1);
	(void) dup2(0, 2);

	if (uid != (uid_t)0) {
		i = setgid(gid);
		if (i == 0)
			i = setuid(uid);
		if (i != 0) {
			syslog(LOG_ERR, SETUID_ERR,
				file, line, user, strerror(errno));
			_exit(0);
		}
	}

	/*
	 * Unblock all signals in the child
	 */
	(void) sigprocmask(SIG_UNBLOCK, &prior_set, NULL);

	if (execv(path, args->arg_args) == -1) {
		syslog(LOG_ERR, CANNOT_EXEC_ERR,
			path, strerror(errno));
		_exit(0);
	}
}


/*
 * Thread to handle in-coming signals
 */
static void
sigwait_thr()
{
	int	sig;
	sigset_t signal_set;

	/*
	 * SIGCHLD is ignored by default, and we need to handle this
	 * signal to reap the status of all children spawned by
	 * this daemon.
	 */
	(void) sigset(SIGCHLD, reapchild);

	for (;;) {
		(void) sigfillset(&signal_set);
		if (sigwait(&signal_set, &sig) == 0) {
			/*
			 * Block all signals until the signal handler completes
			 */
			(void) sigfillset(&signal_set);
			(void) thr_sigsetmask(SIG_BLOCK, &signal_set, NULL);

			if (sig == SIGCHLD) {
				reapchild(sig);
			} else {
				flt_handler(sig);
			}
		}
	}
	/* NOTREACHED */
}



/*
 * reapchild - reap the status of each child as it exits
 */
/*ARGSUSED*/
static void
reapchild(int sig)
{
	siginfo_t info;
	char *signam;
	int err;

	for (;;) {
		(void) memset(&info, 0, sizeof (info));
		err = waitid(P_ALL, 0, &info, WNOHANG|WEXITED);
		if (err == -1) {
			if (errno != EINTR && errno != EAGAIN)
				return;
		} else if (info.si_pid == 0) {
			return;
		}

		if (debug_level >= DBG_CHILD) {
			printmsg(DBG_CHILD, CHILD_EXIT_STATUS_ERR,
				info.si_pid, info.si_status);
		}

		if (info.si_status) {
			if (info.si_code == CLD_EXITED) {
				syserrmsg(CHILD_EXIT_STATUS_ERR,
					info.si_pid, info.si_status);
			} else {
				signam = strsignal(info.si_status);
				if (signam == NULL)
					signam = "";
				if (info.si_code == CLD_DUMPED) {
					syserrmsg(
					    CHILD_EXIT_CORE_ERR,
					    info.si_pid, signam);
				} else {
					syserrmsg(
					    CHILD_EXIT_SIGNAL_ERR,
					    info.si_pid, signam);
				}
			}
		}
	}
}


/*
 * Fault handler for other signals caught
 */
/*ARGSUSED*/
static void
flt_handler(int sig)
{
	struct sigaction act;

	(void) memset(&act, 0, sizeof (act));
	act.sa_handler = SIG_DFL;
	act.sa_flags = SA_RESTART;
	(void) sigfillset(&act.sa_mask);
	(void) sigaction(sig, &act, NULL);

	switch (sig) {
		case SIGINT:
		case SIGSTOP:
		case SIGTERM:
		case SIGHUP:
			exit(1);
			/*NOTREACHED*/
	}
}


static arg_t *
init_arglist(int hint)
{
	arg_t	*arglist;

	if ((arglist = sc_malloc(sizeof (arg_t))) == NULL)
		return (NULL);
	arglist->arg_args = NULL;
	arglist->arg_nargs = 0;
	arglist->arg_alloc = 0;
	arglist->arg_hint = hint;
	return (arglist);
}


static void
free_arglist(arg_t *arglist)
{
	if (arglist->arg_args) {
		free(arglist->arg_args);
	}
	free(arglist);
}


static int
add_arg(arg_t *arglist, char *arg)
{
	char	**new_args;
	int	len;

	len = arglist->arg_nargs + 2;
	if (arglist->arg_alloc < len) {
		arglist->arg_alloc = len + arglist->arg_hint;
		new_args = (arglist->arg_nargs == 0) ?
			sc_malloc(arglist->arg_alloc * sizeof (char **)) :
			sc_realloc(arglist->arg_args,
				arglist->arg_alloc * sizeof (char **));
		if (new_args == NULL)
			return (1);
		arglist->arg_args = new_args;
	}

	arglist->arg_args[arglist->arg_nargs++] = arg;
	arglist->arg_args[arglist->arg_nargs] = NULL;

	return (0);
}

/*
 * next_arg() is used to break up a command line
 * into the arguments for execv(2).  Break up
 * arguments separated by spaces, but respecting
 * single/double quotes.
 */
static char *
next_arg(char **cpp)
{
	char	*cp = *cpp;
	char	*start;
	char	quote;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == 0) {
		*cpp = 0;
		return (NULL);
	}
	start = cp;
	while (*cp && *cp != ' ' && *cp != '\t') {
		if (*cp == '"' || *cp == '\'') {
			quote = *cp++;
			while (*cp && *cp != quote) {
				cp++;
			}
			if (*cp == 0) {
				*cpp = 0;
				return (NULL);
			} else {
				cp++;
			}
		} else {
			cp++;
		}
	}
	if (*cp != 0)
		*cp++ = 0;
	*cpp = cp;
	return (start);
}


static struct cmd *
alloc_cmd(nvlist_t *nvlist)
{
	struct cmd *cmd;

	cmd = sc_malloc(sizeof (struct cmd));
	if (cmd) {
		if (nvlist_dup(nvlist, &cmd->cmd_nvlist, 0) != 0) {
			syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
			free(cmd);
			return (NULL);
		}
	}
	return (cmd);
}

static void
free_cmd(struct cmd *cmd)
{
	nvlist_free(cmd->cmd_nvlist);
	free(cmd);
}


static void *
sc_malloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (p == NULL) {
		syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
	}
	return (p);
}

static void *
sc_realloc(void *p, size_t n)
{
	p = realloc(p, n);
	if (p == NULL) {
		syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
	}
	return (p);
}



/*
 * syserrsg - print error messages to the terminal if not
 *			yet daemonized or to syslog.
 */
/*PRINTFLIKE1*/
static void
syserrmsg(char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	(void) vsyslog(LOG_ERR, message, ap);
	va_end(ap);
}

/*
 * printmsg -  print messages to the terminal or to syslog
 *			the following levels are implemented:
 */
/*PRINTFLIKE2*/
static void
printmsg(int level, char *message, ...)
{
	va_list ap;

	if (level > debug_level) {
		return;
	}

	va_start(ap, message);
	(void) syslog(LOG_DEBUG, "%s[%ld]: ", prog, getpid());
	(void) vsyslog(LOG_DEBUG, message, ap);
	va_end(ap);
}

/* ARGSUSED */
static void *
create_door_thr(void *arg)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);
	return (NULL);
}

/*
 * Control creation of door server threads
 *
 * If first creation of server thread fails there is nothing
 * we can do about. Doors would not work.
 */
/* ARGSUSED */
static void
mk_thr_pool(door_info_t *dip)
{
	(void) mutex_lock(&create_cnt_lock);
	if (++cnt_servers > MAX_SERVER_THREADS) {
		cnt_servers--;
		(void) mutex_unlock(&create_cnt_lock);
		return;
	}
	(void) mutex_unlock(&create_cnt_lock);

	(void) thr_create(NULL, 0, create_door_thr, NULL,
	    THR_BOUND|THR_DETACHED, NULL);
}

static sysevent_handle_t *
open_channel()
{
	char	door_path[MAXPATHLEN];
	const char *subclass_list;
	sysevent_handle_t *handle;

	if (snprintf(door_path, sizeof (door_path), "%s/%s",
	    root_dir, SYSEVENTCONFD_SERVICE_DOOR) >= sizeof (door_path)) {
		syserrmsg(CHANNEL_OPEN_ERR);
		return (NULL);
	}

	/*
	 * Setup of door server create function to limit the
	 * amount of door servers
	 */
	(void) door_server_create(mk_thr_pool);

	handle = sysevent_open_channel_alt(door_path);
	if (handle == NULL) {
		syserrmsg(CHANNEL_OPEN_ERR);
		return (NULL);
	}
	if (sysevent_bind_subscriber(handle, event_handler) != 0) {
		syserrmsg(CHANNEL_BIND_ERR);
		sysevent_close_channel(handle);
		return (NULL);
	}
	subclass_list = EC_SUB_ALL;
	if (sysevent_register_event(handle, EC_ALL, &subclass_list, 1)
	    != 0) {
		syserrmsg(CHANNEL_BIND_ERR);
		(void) sysevent_unbind_subscriber(handle);
		(void) sysevent_close_channel(handle);
		return (NULL);
	}
	return (handle);
}
