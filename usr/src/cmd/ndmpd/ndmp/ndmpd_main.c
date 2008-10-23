/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */

#include <errno.h>
#include <signal.h>
#include <libgen.h>
#include <libscf.h>
#include <libintl.h>
#include <sys/wait.h>
#include <zone.h>
#include <tsol/label.h>
#include <dlfcn.h>
#include "ndmpd.h"
#include "ndmpd_common.h"


/* zfs library handle & mutex */
libzfs_handle_t *zlibh;
mutex_t	zlib_mtx;
void *mod_plp;

static void ndmpd_sig_handler(int sig);

typedef struct ndmpd {
	int s_shutdown_flag;	/* Fields for shutdown control */
	int s_sigval;
} ndmpd_t;

ndmpd_t	ndmpd;


/*
 * Load and initialize the plug-in module
 */
static int
mod_init()
{
	char *plname;
	ndmp_plugin_t *(*plugin_init)(int);

	ndmp_pl = NULL;
	if ((plname = ndmpd_get_prop(NDMP_PLUGIN_PATH)) == NULL)
		return (0);

	if ((mod_plp = dlopen(plname, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		syslog(LOG_ERR, "Error loading the plug-in %s", plname);
		return (0);
	}

	plugin_init = (ndmp_plugin_t *(*)(int))dlsym(mod_plp, "_ndmp_init");
	if (plugin_init == NULL) {
		(void) dlclose(mod_plp);
		return (0);
	}
	if ((ndmp_pl = plugin_init(NDMP_PLUGIN_VERSION)) == NULL) {
		syslog(LOG_ERR, "Error loading the plug-in %s", plname);
		return (-1);
	}
	return (0);
}

/*
 * Unload
 */
static void
mod_fini()
{
	if (ndmp_pl == NULL)
		return;

	void (*plugin_fini)(ndmp_plugin_t *);

	plugin_fini = (void (*)(ndmp_plugin_t *))dlsym(mod_plp, "_ndmp_fini");
	if (plugin_fini == NULL) {
		(void) dlclose(mod_plp);
		return;
	}
	plugin_fini(ndmp_pl);
	(void) dlclose(mod_plp);
}

static void
daemonize_init(char *arg)
{
	sigset_t set, oset;
	pid_t pid;

	/*
	 * Set effective sets privileges to 'least' required. If fails, send
	 * error messages to log file and proceed.
	 */
	if (priv_set(PRIV_SET, PRIV_EFFECTIVE,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, PRIV_PROC_SESSION,
	    PRIV_PROC_FORK, PRIV_PROC_EXEC,
	    PRIV_PROC_AUDIT, PRIV_PROC_SETID, PRIV_PROC_OWNER, PRIV_FILE_CHOWN,
	    PRIV_FILE_CHOWN_SELF, PRIV_FILE_DAC_READ, PRIV_FILE_DAC_SEARCH,
	    PRIV_FILE_DAC_WRITE, PRIV_FILE_OWNER, PRIV_FILE_SETID,
	    PRIV_SYS_LINKDIR, PRIV_SYS_DEVICES, PRIV_SYS_MOUNT, PRIV_SYS_CONFIG,
	    NULL))
		syslog(LOG_ERR,
		    "Failed to set least required privileges to the service.");

	/*
	 * Block all signals prior to the fork and leave them blocked in the
	 * parent so we don't get in a situation where the parent gets SIGINT
	 * and returns non-zero exit status and the child is actually running.
	 * In the child, restore the signal mask once we've done our setsid().
	 */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT);
	(void) sigprocmask(SIG_BLOCK, &set, &oset);

	if ((pid = fork()) == -1) {
		openlog(arg, LOG_PID | LOG_NDELAY, LOG_DAEMON);
		syslog(LOG_ERR, "Failed to start process in background.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* If we're the parent process, exit. */
	if (pid != 0) {
		_exit(0);
	}
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
	(void) umask(0);
}

static void
daemonize_fini(void)
{
	int fd;

	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		(void) fcntl(fd, F_DUP2FD, STDIN_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDOUT_FILENO);
		(void) fcntl(fd, F_DUP2FD, STDERR_FILENO);
		(void) close(fd);
	}
}

/*
 * main
 *
 * The main NDMP daemon function
 *
 * Parameters:
 *   argc (input) - the argument count
 *   argv (input) - command line options
 *
 * Returns:
 *   0
 */
int
main(int argc, char *argv[])
{
	char c;
	struct sigaction act;
	sigset_t set;
	void *arg = 0;

	openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * Check for existing ndmpd door server (make sure ndmpd is not already
	 * running)
	 */
	if (ndmp_door_check()) {
		/* ndmpd is already running, exit. */
		return (0);
	}

	/* load ENVs */
	if (ndmpd_load_prop()) {
		syslog(LOG_ERR,
		    "%s SMF properties initialization failed.", argv[0]);
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* Global zone check */
	if (getzoneid() != GLOBAL_ZONEID) {
		syslog(LOG_ERR, "Local zone not supported.");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* Trusted Solaris check */
	if (is_system_labeled()) {
		syslog(LOG_ERR, "Trusted Solaris not supported.");
		exit(SMF_EXIT_ERR_FATAL);
	}

	opterr = 0;
	while ((c = getopt(argc, argv, ":d")) != -1) {
		switch (c) {
		case 'd':
			(void) set_debug_level(TRUE);
			break;
		default:
			syslog(LOG_ERR, "%s: Invalid option -%c.",
			    argv[0], optopt);
			syslog(LOG_ERR, "Usage: %s [-d]", argv[0]);
			exit(SMF_EXIT_ERR_CONFIG);
		}

	}

	closelog();
	/*
	 * close any open file descriptors which are greater
	 * than STDERR_FILENO
	 */
	closefrom(STDERR_FILENO + 1);

	/* set up signal handler */
	(void) sigfillset(&set);
	(void) sigdelset(&set, SIGABRT); /* always unblocked for ASSERT() */
	(void) sigfillset(&act.sa_mask);
	act.sa_handler = ndmpd_sig_handler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGUSR1, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGUSR1);

	(void) daemonize_init(argv[0]);

	openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);
	(void) mutex_init(&log_lock, 0, NULL);

	if (mod_init() != 0) {
		syslog(LOG_ERR, "Failed to load the plugin module.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* libzfs init */
	if ((zlibh = libzfs_init()) == NULL) {
		syslog(LOG_ERR, "Failed to initialize ZFS library.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* initialize and start the door server */
	if (ndmp_door_init()) {
		syslog(LOG_ERR, "Can not start ndmpd door server.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	(void) tlm_init();

	/*
	 * Prior to this point, we are single-threaded. We will be
	 * multi-threaded from this point on.
	 */
	(void) pthread_create(NULL, NULL, (funct_t)ndmpd_main,
	    (void *)&arg);

	while (!ndmpd.s_shutdown_flag) {
		(void) sigsuspend(&set);

		switch (ndmpd.s_sigval) {
		case 0:
			break;

		case SIGHUP:
			/* Refresh SMF properties */
			if (ndmpd_load_prop())
				syslog(LOG_ERR,
				    "Service properties initialization "
				    "failed.");
			break;

		default:
			/*
			 * Typically SIGINT or SIGTERM.
			 */
			ndmpd.s_shutdown_flag = 1;
			break;
		}

		ndmpd.s_sigval = 0;
	}

	(void) mutex_destroy(&log_lock);
	libzfs_fini(zlibh);
	mod_fini();
	ndmp_door_fini();
	daemonize_fini();
	free(ndmp_log_path);
	return (SMF_EXIT_OK);
}

static void
ndmpd_sig_handler(int sig)
{
	if (ndmpd.s_sigval == 0)
		ndmpd.s_sigval = sig;
}

/*
 * Enable libumem debugging by default on DEBUG builds.
 */
#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif
