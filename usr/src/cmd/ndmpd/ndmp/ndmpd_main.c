/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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

	plname = ndmpd_get_prop(NDMP_PLUGIN_PATH);
	if (plname == NULL || *plname == '\0')
		return (0);

	if ((mod_plp = dlopen(plname, RTLD_LOCAL | RTLD_NOW)) == NULL) {
		NDMP_LOG(LOG_ERR, "Error loading the plug-in %s: %s",
		    plname, dlerror());
		return (0);
	}

	plugin_init = (ndmp_plugin_t *(*)(int))dlsym(mod_plp, "_ndmp_init");
	if (plugin_init == NULL) {
		(void) dlclose(mod_plp);
		return (0);
	}
	if ((ndmp_pl = plugin_init(NDMP_PLUGIN_VERSION)) == NULL) {
		NDMP_LOG(LOG_ERR, "Error loading the plug-in %s", plname);
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
set_privileges(void)
{
	priv_set_t *pset = priv_allocset();

	/*
	 * Set effective sets privileges to 'least' required. If fails, send
	 * error messages to log file and proceed.
	 */
	if (pset != NULL) {
		priv_basicset(pset);
		(void) priv_addset(pset, PRIV_PROC_AUDIT);
		(void) priv_addset(pset, PRIV_PROC_SETID);
		(void) priv_addset(pset, PRIV_PROC_OWNER);
		(void) priv_addset(pset, PRIV_FILE_CHOWN);
		(void) priv_addset(pset, PRIV_FILE_CHOWN_SELF);
		(void) priv_addset(pset, PRIV_FILE_DAC_READ);
		(void) priv_addset(pset, PRIV_FILE_DAC_SEARCH);
		(void) priv_addset(pset, PRIV_FILE_DAC_WRITE);
		(void) priv_addset(pset, PRIV_FILE_OWNER);
		(void) priv_addset(pset, PRIV_FILE_SETID);
		(void) priv_addset(pset, PRIV_SYS_LINKDIR);
		(void) priv_addset(pset, PRIV_SYS_DEVICES);
		(void) priv_addset(pset, PRIV_SYS_MOUNT);
		(void) priv_addset(pset, PRIV_SYS_CONFIG);
	}

	if (pset == NULL || setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) != 0) {
		(void) fprintf(stderr,
		    "Failed to set least required privileges to the service\n");
	}
	priv_freeset(pset);
}

static void
daemonize_init(void)
{
	sigset_t set, oset;
	pid_t pid;

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
		(void) fprintf(stderr,
		    "Failed to start process in background.\n");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* If we're the parent process, exit. */
	if (pid != 0) {
		_exit(0);
	}
	(void) setsid();
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	(void) chdir("/");
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
	struct sigaction act;
	sigset_t set;
	char c;
	void *arg = NULL;
	boolean_t run_in_foreground = B_FALSE;
	boolean_t override_debug = B_FALSE;

	/*
	 * Check for existing ndmpd door server (make sure ndmpd is not already
	 * running)
	 */
	if (ndmp_door_check()) {
		/* ndmpd is already running, exit. */
		(void) fprintf(stderr, "ndmpd is already running.\n");
		return (0);
	}

	/* Global zone check */
	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr, "Non-global zone not supported.\n");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* Trusted Solaris check */
	if (is_system_labeled()) {
		(void) fprintf(stderr, "Trusted Solaris not supported.\n");
		exit(SMF_EXIT_ERR_FATAL);
	}

	/* load SMF configuration */
	if (ndmpd_load_prop()) {
		(void) fprintf(stderr,
		    "SMF properties initialization failed.\n");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	opterr = 0;
	while ((c = getopt(argc, argv, "df")) != -1) {
		switch (c) {
		case 'd':
			override_debug = B_TRUE;
			break;
		case 'f':
			run_in_foreground = B_TRUE;
			break;
		default:
			(void) fprintf(stderr, "%s: Invalid option -%c.\n",
			    argv[0], optopt);
			(void) fprintf(stderr, "Usage: %s [-df]\n", argv[0]);
			exit(SMF_EXIT_ERR_CONFIG);
		}
	}

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
	(void) sigaction(SIGPIPE, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigdelset(&set, SIGHUP);
	(void) sigdelset(&set, SIGINT);
	(void) sigdelset(&set, SIGUSR1);
	(void) sigdelset(&set, SIGPIPE);

	set_privileges();
	(void) umask(077);
	openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * Open log file before we detach from terminal in case that open
	 * fails and error message is printed to stderr.
	 */
	if (ndmp_log_open_file(run_in_foreground, override_debug) != 0)
		exit(SMF_EXIT_ERR_FATAL);

	if (!run_in_foreground)
		daemonize_init();

	(void) mutex_init(&ndmpd_zfs_fd_lock, 0, NULL);

	if (mod_init() != 0) {
		NDMP_LOG(LOG_ERR, "Failed to load the plugin module.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* libzfs init */
	if ((zlibh = libzfs_init()) == NULL) {
		NDMP_LOG(LOG_ERR, "Failed to initialize ZFS library.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	/* initialize and start the door server */
	if (ndmp_door_init()) {
		NDMP_LOG(LOG_ERR, "Can not start ndmpd door server.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

	if (tlm_init() == -1) {
		NDMP_LOG(LOG_ERR, "Failed to initialize tape manager.");
		exit(SMF_EXIT_ERR_CONFIG);
	}

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

		case SIGPIPE:
			break;

		case SIGHUP:
			/* Refresh SMF properties */
			if (ndmpd_load_prop())
				NDMP_LOG(LOG_ERR,
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

	(void) mutex_destroy(&ndmpd_zfs_fd_lock);
	libzfs_fini(zlibh);
	mod_fini();
	ndmp_door_fini();
	ndmp_log_close_file();

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
