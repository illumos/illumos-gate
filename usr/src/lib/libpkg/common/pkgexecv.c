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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

/* global environment inherited by this process */
extern char	**environ;

/* dstream.c */
extern int	ds_curpartcnt;
extern int	ds_close(int pkgendflg);

/*
 * global internal (private) variables
 */

/* received signal count - bumped with hooked signals are caught */

static int	sig_received = 0;

/*
 * Name:	sig_trap
 * Description:	hooked up to signal counts number of signals received
 * Arguments:	a_signo - [RO, *RO] - (int)
 *			Integer representing the signal received; see signal(3c)
 * Returns:	<void>
 */

static void
sig_trap(int a_signo)
{
	sig_received++;
}

/*
 * Name:	pkgexecv
 * Description:	Asynchronously execute a package command in a separate process
 *		and return results - the subprocess MUST arm it's own SIGINT
 *		and SIGHUP signals and must return a standard package command
 *		exit code (see returns below)
 *		Only another package command (such as pkginstall, pkgremove,
 *		etc.) may be called via this interface. No files are closed
 *		because open files are passed across to certain commands using
 *		either implicit agreements between the two (yuk!) or by using
 *		the '-p' option which passes a string of digits, some of which
 *		represent open file descriptors passed through this interface!
 * Arguments:	filein - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the file to
 *			use for the package commands's stdin
 *			== (char *)NULL or == "" - the current stdin
 *			is used for the new package command process
 *		fileout - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the file to
 *			use for the package commands's stdout and stderr
 *			== (char *)NULL or == "" - the current stdout/stderr
 *			is used for the new package command process
 *		uname - [RO, *RO] - (char *)
 *			Pointer to string representing the user name to execute
 *			the package command as - the user name is looked up
 *			using the ncgrpw:cpwnam() interface
 *			== (char *)NULL or == "" - the user name of the current
 *			process is used for the new package command process
 *		gname - [RO, *RO] - (char *)
 *			Pointer to string representing the group name to execute
 *			the package command as - the group name is looked up
 *			using the ncgrpw:cgrnam() interface
 *			== (char *)NULL or == "" - the group name of the current
 *			process is used for the new package command process
 *		arg - [RO, *RO] - (char **)
 *			Pointer to array of character pointers representing the
 *			arguments to pass to the package command - the array is
 *			terminated with a pointer to (char *)NULL
 * Returns:	int
 *			== 99 - exec() of package command failed
 *			== -1 - fork failed or other fatal error during
 *				execution of the package command
 *			otherwise - exit code from package command:
 *			0 - successful
 *			1 - package operation failed (fatal error)
 *			2 - non-fatal error (warning)
 *			3 - operation interrupted (including SIGINT/SIGHUP)
 *			4 - admin settings prevented operation
 *			5 - administration required and -n was specified
 *			IN addition:
 *			10 is added to the return code if reboot after the
 *				installation of all packages is required
 *			20 is added to the return code if immediate reboot
 *				after installation of this package is required
 */

int
pkgexecv(char *filein, char *fileout, char *uname, char *gname, char *arg[])
{
	int			exit_no;
	int			n;
	int			status;
	pid_t			pid;
	pid_t			waitstat;
	struct group		*grp;
	struct passwd		*pwp;
	struct sigaction	nact;
	struct sigaction	oact;
	void			(*funcSighup)();
	void			(*funcSigint)();

	/* flush standard i/o before creating new process */

	(void) fflush(stdout);
	(void) fflush(stderr);

	/*
	 * hold SIGINT/SIGHUP signals and reset signal received counter;
	 * after the vfork() the parent and child need to setup their respective
	 * interrupt handling and release the hold on the signals
	 */

	(void) sighold(SIGINT);
	(void) sighold(SIGHUP);

	sig_received = 0;

	/*
	 * create new process to execute command in;
	 * vfork() is being used to avoid duplicating the parents
	 * memory space - this means that the child process may
	 * not modify any of the parents memory including the
	 * standard i/o descriptors - all the child can do is
	 * adjust interrupts and open files as a prelude to a
	 * call to exec().
	 */

	pid = vfork();

	if (pid < 0) {
		/*
		 * *************************************************************
		 * fork failed!
		 * *************************************************************
		 */

		progerr(pkg_gt(ERR_FORK_FAILED), errno, strerror(errno));

		/* release hold on signals */

		(void) sigrelse(SIGHUP);
		(void) sigrelse(SIGINT);

		return (-1);
	}

	if (pid > 0) {
		/*
		 * *************************************************************
		 * This is the forking (parent) process
		 * *************************************************************
		 */

		/* close datastream if any portion read */

		if (ds_curpartcnt >= 0) {
			if (ds_close(0) != 0) {
				/* kill child process */

				(void) sigsend(P_PID, pid, SIGKILL);

				/* release hold on signals */

				(void) sigrelse(SIGHUP);
				(void) sigrelse(SIGINT);

				return (-1);
			}
		}

		/*
		 * setup signal handlers for SIGINT and SIGHUP and release hold
		 */

		/* hook SIGINT to sig_trap() */

		nact.sa_handler = sig_trap;
		nact.sa_flags = SA_RESTART;
		(void) sigemptyset(&nact.sa_mask);

		if (sigaction(SIGINT, &nact, &oact) < 0) {
			funcSigint = SIG_DFL;
		} else {
			funcSigint = oact.sa_handler;
		}

		/* hook SIGHUP to sig_trap() */

		nact.sa_handler = sig_trap;
		nact.sa_flags = SA_RESTART;
		(void) sigemptyset(&nact.sa_mask);

		if (sigaction(SIGHUP, &nact, &oact) < 0) {
			funcSighup = SIG_DFL;
		} else {
			funcSighup = oact.sa_handler;
		}

		/* release hold on signals */

		(void) sigrelse(SIGHUP);
		(void) sigrelse(SIGINT);

		/*
		 * wait for the process to exit, reap child exit status
		 */

		for (;;) {
			status = 0;
			waitstat = waitpid(pid, (int *)&status, 0);
			if (waitstat < 0) {
				/* waitpid returned error */
				if (errno == EAGAIN) {
					/* try again */
					continue;
				}
				if (errno == EINTR) {
					continue;
				}
				/* error from waitpid: bail */
				break;
			} else if (waitstat == pid) {
				/* child exit status available */
				break;
			}
		}

		/*
		 * reset signal handlers
		 */

		/* reset SIGINT */

		nact.sa_handler = funcSigint;
		nact.sa_flags = SA_RESTART;
		(void) sigemptyset(&nact.sa_mask);

		(void) sigaction(SIGINT, &nact, (struct sigaction *)NULL);

		/* reset SIGHUP */

		nact.sa_handler = funcSighup;
		nact.sa_flags = SA_RESTART;
		(void) sigemptyset(&nact.sa_mask);

		(void) sigaction(SIGHUP, &nact, (struct sigaction *)NULL);

		/* error if child process does not match */

		if (waitstat != pid) {
			progerr(pkg_gt(ERR_WAIT_FAILED), pid, waitstat, status,
				errno, strerror(errno));
			return (-1);
		}

		/*
		 * determine final exit code:
		 * - if signal received, then return interrupted (3)
		 * - if child exit status is available, return exit child status
		 * - otherwise return error (-1)
		 */

		if (sig_received != 0) {
			exit_no = 3;	/* interrupted */
		} else if (WIFEXITED(status)) {
			exit_no = WEXITSTATUS(status);
		} else {
			exit_no = -1;	/* exec() or other process error */
		}

		return (exit_no);
	}

	/*
	 * *********************************************************************
	 * This is the forked (child) process
	 * *********************************************************************
	 */

	/* reset all signals to default */

	for (n = 0; n < NSIG; n++) {
		(void) sigset(n, SIG_DFL);
	}

	/* release hold on signals held by parent before fork() */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	/*
	 * The caller wants to have stdin connected to filein.
	 */

	if (filein && *filein) {
		/*
		 * If input is supposed to be connected to /dev/tty
		 */
		if (strncmp(filein, "/dev/tty", 8) == 0) {
			/*
			 * If stdin is connected to a tty device.
			 */
			if (isatty(STDIN_FILENO)) {
				/*
				 * Reopen it to /dev/tty.
				 */
				n = open(filein, O_RDONLY);
				if (n >= 0) {
					(void) dup2(n, STDIN_FILENO);
				}
			}
		} else {
			/*
			 * If we did not want to be connected to /dev/tty, we
			 * connect input to the requested file no questions.
			 */
			n = open(filein, O_RDONLY);
			if (n >= 0) {
				(void) dup2(n, STDIN_FILENO);
			}
		}
	}

	/*
	 * The caller wants to have stdout and stderr connected to fileout.
	 * If "fileout" is "/dev/tty" then reconnect stdout to "/dev/tty"
	 * only if /dev/tty is not already associated with "a tty".
	 */

	if (fileout && *fileout) {
		/*
		 * If output is supposed to be connected to /dev/tty
		 */
		if (strncmp(fileout, "/dev/tty", 8) == 0) {
			/*
			 * If stdout is connected to a tty device.
			 */
			if (isatty(STDOUT_FILENO)) {
				/*
				 * Reopen it to /dev/tty if /dev/tty available.
				 */
				n = open(fileout, O_WRONLY);
				if (n >= 0) {
					/*
					 * /dev/tty is available - close the
					 * current standard output stream, and
					 * reopen it on /dev/tty
					 */
					(void) dup2(n, STDOUT_FILENO);
				}
			}
			/*
			 * not connected to tty device - probably redirect to
			 * file - preserve existing output device
			 */
		} else {
			/*
			 * If we did not want to be connected to /dev/tty, we
			 * connect output to the requested file no questions.
			 */
			/* LINTED O_CREAT without O_EXCL specified in call to */
			n = open(fileout, O_WRONLY|O_CREAT|O_APPEND, 0666);
			if (n >= 0) {
				(void) dup2(n, STDOUT_FILENO);
			}
		}

		/*
		 * Dup stderr from stdout.
		 */

		(void) dup2(STDOUT_FILENO, STDERR_FILENO);
	}

	/*
	 * do NOT close all file descriptors except stdio
	 * file descriptors are passed in to some subcommands
	 * (see dstream:ds_getinfo() and dstream:ds_putinfo())
	 */

	/* set group/user i.d. if requested */

	if (gname && *gname && (grp = cgrnam(gname)) != NULL) {
		if (setgid(grp->gr_gid) == -1) {
			progerr(pkg_gt(ERR_SETGID), grp->gr_gid);
		}
	}
	if (uname && *uname && (pwp = cpwnam(uname)) != NULL) {
		if (setuid(pwp->pw_uid) == -1) {
			progerr(pkg_gt(ERR_SETUID), pwp->pw_uid);
		}
	}

	/* execute target executable */

	(void) execve(arg[0], arg, environ);
	progerr(pkg_gt(ERR_EX_FAIL), arg[0], errno);
	_exit(99);
	/*NOTREACHED*/
}
