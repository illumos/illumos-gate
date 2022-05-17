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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio_ext.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <sys/resource.h>
#include <sys/termios.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <ulimit.h>
#include <libdevinfo.h>

#include "sac.h"
#include "ttymon.h"
#include "tmstruct.h"
#include "tmextern.h"

static	int	Initialized;

static	void	initialize(void);
static	void	open_all(void);
static	int	set_poll(struct pollfd *);
static	int	check_spawnlimit(struct pmtab *);
static	int	mod_ttydefs(void);

void	open_device(struct pmtab *);
void	set_softcar(struct pmtab *);

/*
 *	ttymon	- a port monitor under SAC
 *		- monitor ports, set terminal modes, baud rate
 *		  and line discipline for the port
 *		- invoke service on port if connection request received
 *		- Usage: ttymon
 *			 ttymon -g [options]
 *			 Valid options are
 *			 -h
 *			 -d device
 *			 -l ttylabel
 *			 -t timeout
 *			 -m modules
 *			 -p prompt
 *
 *		- ttymon without args is invoked by SAC
 *		- ttymon -g is invoked by process that needs to
 *		  have login service on the fly
 */

int
main(int argc, char *argv[])
{
	int	nfds;

	/*
	 * Only the superuser should execute this command.
	 */
	if (getuid() != 0)
		return (1);

	/* remember original signal mask and dispositions */
	(void) sigprocmask(SIG_SETMASK, NULL, &Origmask);
	(void) sigaction(SIGINT, NULL, &Sigint);
	(void) sigaction(SIGALRM, NULL, &Sigalrm);
	(void) sigaction(SIGPOLL, NULL, &Sigpoll);
	(void) sigaction(SIGQUIT, NULL, &Sigquit);
	(void) sigaction(SIGCLD, NULL, &Sigcld);
	(void) sigaction(SIGTERM, NULL, &Sigterm);
#ifdef	DEBUG
	(void) sigaction(SIGUSR1, NULL, &Sigusr1);
	(void) sigaction(SIGUSR2, NULL, &Sigusr2);
#endif

	/*
	 * SIGQUIT needs to be ignored. Otherwise, hitting ^\ from
	 * console kills ttymon.
	 */
	(void) signal(SIGQUIT, SIG_IGN);

	if ((argc > 1) || (strcmp(lastname(argv[0]), "getty") == 0)) {
		ttymon_express(argc, argv);
		return (1);	/*NOTREACHED*/
	}

	initialize();

	for (;;) {
		nfds = set_poll(Pollp);
		if (!Reread_flag) {
			if (nfds > 0)
				do_poll(Pollp, nfds);
			else
				(void) pause();
		}
		/*
		 * READDB messages may arrive during poll or pause.
		 * So the flag needs to be checked again.
		 */
		if (Reread_flag) {
			Reread_flag = FALSE;
			re_read();
		}
		while (Retry) {
			Retry = FALSE;
			open_all();
		}
	}
}

static	void
initialize(void)
{
	struct	pmtab	*tp;
	struct passwd *pwdp;
	struct	group	*gp;
	struct	rlimit rlimit;

	Initialized = FALSE;
	/*
	 * get_environ() must be called first,
	 * otherwise we don't know where the log file is
	 */
	get_environ();
	openttymonlog();
	openpid();
	openpipes();
	setup_PCpipe();

	log("PMTAG: %s", Tag);
	log("Starting state: %s",
	    (State == PM_ENABLED) ? "enabled" : "disabled");

#ifdef	DEBUG
	opendebug(FALSE);
	debug("***** ttymon in initialize *****");
	log("debug mode is \t on");
#endif

	catch_signals();

	/* register to receive SIGPOLL when data comes to pmpipe */
	if (ioctl(Pfd, I_SETSIG, S_INPUT) < 0)
		fatal("I_SETSIG on pmpipe failed: %s", strerror(errno));

	sacpoll(); /* this is needed because there may be data already */

	Maxfiles = (int)ulimit(4, 0L);	/* get max number of open files */
	if (Maxfiles < 0)
		fatal("ulimit(4,0L) failed: %s", strerror(errno));

	if (getrlimit(RLIMIT_NOFILE, &Rlimit) == -1)
		fatal("getrlimit failed: %s", strerror(errno));

	rlimit.rlim_cur = rlimit.rlim_max = Rlimit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rlimit) == -1)
		fatal("setrlimit failed: %s", strerror(errno));

	(void) enable_extended_FILE_stdio(-1, -1);

	Maxfiles = rlimit.rlim_cur;
	Maxfds = Maxfiles - FILE_RESERVED;

	log("max open files = %d", Maxfiles);
	log("max ports ttymon can monitor = %d", Maxfds);

	read_pmtab();

	/*
	 * setup poll array
	 *	- we allocate 10 extra pollfd so that
	 *	  we do not have to re-malloc when there is
	 *	  minor fluctuation in Nentries
	 */
	Npollfd = Nentries + 10;
	if (Npollfd > Maxfds)
		Npollfd = Maxfds;
	if ((Pollp = (struct pollfd *)
	    malloc((unsigned)(Npollfd * sizeof (struct pollfd))))
	    == (struct pollfd *)NULL)
		fatal("malloc for Pollp failed");

	(void) mod_ttydefs();	/* just to initialize Mtime */
	if (check_version(TTYDEFS_VERS, TTYDEFS) != 0)
		fatal("check /etc/ttydefs version failed");

	read_ttydefs(NULL, FALSE);

	/* initialize global variables, Uucp_uid & Tty_gid */
	if ((pwdp = getpwnam(UUCP)) != NULL)
		Uucp_uid = pwdp->pw_uid;
	if ((gp = getgrnam(TTY)) == NULL)
		log("no group entry for <tty>, default is used");
	else
		Tty_gid = gp->gr_gid;
	endgrent();
	endpwent();
#ifdef	DEBUG
	debug("Uucp_uid = %u, Tty_gid = %u", Uucp_uid, Tty_gid);
#endif

	log("Initialization Completed");

	/* open the devices ttymon monitors */
	Retry = TRUE;
	while (Retry) {
		Retry = FALSE;
		for (tp = PMtab; tp; tp = tp->p_next) {
			if ((tp->p_status > 0) && (tp->p_fd == 0) &&
			    (tp->p_childpid == 0) &&
			    !(tp->p_ttyflags & I_FLAG) &&
			    (!((State == PM_DISABLED) &&
			    ((tp->p_dmsg == NULL)||(*(tp->p_dmsg) == '\0'))))) {
				open_device(tp);
				if (tp->p_fd > 0)
					got_carrier(tp);
			}
		}
	}
	Initialized = TRUE;
}

static	void	free_defs(void);

/*
 *	open_all - open devices in pmtab if the entry is
 *	         - valid, fd = 0, and pid = 0
 */
static void
open_all(void)
{
	struct	pmtab	*tp;
	int	check_modtime;
	sigset_t cset;
	sigset_t tset;

#ifdef	DEBUG
	debug("in open_all");
#endif
	check_modtime = TRUE;

	for (tp = PMtab; tp; tp = tp->p_next) {
		if ((tp->p_status > 0) && (tp->p_fd == 0) &&
		    (tp->p_childpid == 0) &&
		    !(tp->p_ttyflags & I_FLAG) && (!((State == PM_DISABLED) &&
		    ((tp->p_dmsg == NULL)||(*(tp->p_dmsg) == '\0'))))) {
			/*
			 * if we have not check modification time and
			 * /etc/ttydefs was modified, need to re-read it
			 */
			if (check_modtime && mod_ttydefs()) {
				check_modtime = FALSE;
				(void) sigprocmask(SIG_SETMASK, NULL, &cset);
				tset = cset;
				(void) sigaddset(&tset, SIGCLD);
				(void) sigprocmask(SIG_SETMASK, &tset, NULL);
				free_defs();
#ifdef	DEBUG
				debug("/etc/ttydefs is modified, re-read it");
#endif
				read_ttydefs(NULL, FALSE);
				(void) sigprocmask(SIG_SETMASK, &cset, NULL);
			}
			open_device(tp);
			if (tp->p_fd > 0)
				got_carrier(tp);
		} else if (((tp->p_status == LOCKED) ||
		    (tp->p_status == SESSION) ||
		    (tp->p_status == UNACCESS)) &&
		    (tp->p_fd > 0) &&
		    (!((State == PM_DISABLED) &&
		    ((tp->p_dmsg == NULL)||(*(tp->p_dmsg) == '\0'))))) {
			if (check_modtime && mod_ttydefs()) {
				check_modtime = FALSE;
				(void) sigprocmask(SIG_SETMASK, NULL, &cset);
				tset = cset;
				(void) sigaddset(&tset, SIGCLD);
				(void) sigprocmask(SIG_SETMASK, &tset, NULL);
				free_defs();
#ifdef	DEBUG
				debug("/etc/ttydefs is modified, re-read it");
#endif
				read_ttydefs(NULL, FALSE);
				(void) sigprocmask(SIG_SETMASK, &cset, NULL);
			}
			tp->p_status = VALID;
			open_device(tp);
			if (tp->p_fd > 0)
				got_carrier(tp);
		}
	}
}

void
set_softcar(struct pmtab *pmptr)
{

	int fd, val = 0;

#ifdef	DEBUG
	debug("in set_softcar");
#endif
	/*
	 * If soft carrier is not set one way or
	 * the other, leave it alone.
	 */
	if (*pmptr->p_softcar == '\0')
		return;

	if (*pmptr->p_softcar == 'y')
		val = 1;

	if ((fd = open(pmptr->p_device, O_RDONLY|O_NONBLOCK|O_NOCTTY)) < 0) {
		log("open (%s) failed: %s", pmptr->p_device, strerror(errno));
		return;
	}

	if (ioctl(fd, TIOCSSOFTCAR, &val) < 0)
		log("set soft-carrier (%s) failed: %s", pmptr->p_device,
		    strerror(errno));

	(void) close(fd);
}


/*
 *	open_device(pmptr)	- open the device
 *				- check device lock
 *				- change owner of device
 *				- push line disciplines
 *				- set termio
 */

void
open_device(struct pmtab *pmptr)
{
	int	fd, tmpfd;
	struct	sigaction	sigact;

#ifdef	DEBUG
	debug("in open_device");
#endif

	if (pmptr->p_status == GETTY) {
		revokedevaccess(pmptr->p_device, 0, 0, 0);

		if ((fd = open(pmptr->p_device, O_RDWR)) == -1)
			fatal("open (%s) failed: %s", pmptr->p_device,
			    strerror(errno));

	} else {
		if (check_spawnlimit(pmptr) == -1) {
			pmptr->p_status = NOTVALID;
			log("service <%s> is respawning too rapidly",
			    pmptr->p_tag);
			return;
		}
		if (pmptr->p_fd > 0) { /* file already open */
			fd = pmptr->p_fd;
			pmptr->p_fd = 0;
		} else if ((fd = open(pmptr->p_device, O_RDWR|O_NONBLOCK))
		    == -1) {
			log("open (%s) failed: %s", pmptr->p_device,
			    strerror(errno));
			if ((errno ==  ENODEV) || (errno == EBUSY)) {
				pmptr->p_status = UNACCESS;
				Nlocked++;
				if (Nlocked == 1) {
					sigact.sa_flags = 0;
					sigact.sa_handler = sigalarm;
					(void) sigemptyset(&sigact.sa_mask);
					(void) sigaction(SIGALRM, &sigact,
					    NULL);
					(void) alarm(ALARMTIME);
				}
			} else
				Retry = TRUE;
			return;
		}
		/* set close-on-exec flag */
		if (fcntl(fd, F_SETFD, 1) == -1)
			fatal("F_SETFD fcntl failed: %s", strerror(errno));

		if (tm_checklock(fd) != 0) {
			pmptr->p_status = LOCKED;
			(void) close(fd);
			Nlocked++;
			if (Nlocked == 1) {
				sigact.sa_flags = 0;
				sigact.sa_handler = sigalarm;
				(void) sigemptyset(&sigact.sa_mask);
				(void) sigaction(SIGALRM, &sigact, NULL);
				(void) alarm(ALARMTIME);
			}
			return;
		}
		if (check_session(fd) != 0) {
			if ((Initialized) && (pmptr->p_inservice != SESSION)) {
				log("Warning -- active session exists on <%s>",
				    pmptr->p_device);
			} else {
				/*
				 * this may happen if a service is running
				 * and ttymon dies and is restarted,
				 * or another process is running on the
				 * port.
				 */
				pmptr->p_status = SESSION;
				pmptr->p_inservice = 0;
				(void) close(fd);
				Nlocked++;
				if (Nlocked == 1) {
					sigact.sa_flags = 0;
					sigact.sa_handler = sigalarm;
					(void) sigemptyset(&sigact.sa_mask);
					(void) sigaction(SIGALRM, &sigact,
					    NULL);
					(void) alarm(ALARMTIME);
				}
				return;
			}
		}
		pmptr->p_inservice = 0;
	}

	if (pmptr->p_ttyflags & H_FLAG) {
		/* drop DTR */
		(void) hang_up_line(fd);
		/*
		 * After hang_up_line, the stream is in STRHUP state.
		 * We need to do another open to reinitialize streams
		 * then we can close one fd
		 */
		if ((tmpfd = open(pmptr->p_device, O_RDWR|O_NONBLOCK)) == -1) {
			log("open (%s) failed: %s", pmptr->p_device,
			    strerror(errno));
			Retry = TRUE;
			(void) close(fd);
			return;
		}
		(void) close(tmpfd);
	}

#ifdef DEBUG
	debug("open_device (%s), fd = %d", pmptr->p_device, fd);
#endif

	/* Change ownership of the tty line to root/uucp and */
	/* set protections to only allow root/uucp to read the line. */

	if (pmptr->p_ttyflags & (B_FLAG|C_FLAG))
		(void) fchown(fd, Uucp_uid, Tty_gid);
	else
		(void) fchown(fd, ROOTUID, Tty_gid);
	(void) fchmod(fd, 0620);

	if ((pmptr->p_modules != NULL)&&(*(pmptr->p_modules) != '\0')) {
		if (push_linedisc(fd, pmptr->p_modules, pmptr->p_device)
		    == -1) {
			Retry = TRUE;
			(void) close(fd);
			return;
		}
	}

	if (initial_termio(fd, pmptr) == -1)  {
		Retry = TRUE;
		(void) close(fd);
		return;
	}

	(void) di_devperm_logout((const char *)pmptr->p_device);
	pmptr->p_fd = fd;
}

/*
 *	set_poll(fdp)	- put all fd's in a pollfd array
 *			- set poll event to POLLIN and POLLMSG
 *			- return number of fd to be polled
 */

static	int
set_poll(struct pollfd *fdp)
{
	struct	pmtab	*tp;
	int	nfd = 0;

	for (tp = PMtab; tp; tp = tp->p_next) {
		if (tp->p_fd > 0)  {
			fdp->fd = tp->p_fd;
			fdp->events = POLLIN;
			fdp++;
			nfd++;
		}
	}
	return (nfd);
}

/*
 *	check_spawnlimit	- return 0 if spawnlimit is not reached
 *				- otherwise return -1
 */
static	int
check_spawnlimit(struct pmtab *pmptr)
{
	time_t	now;

	(void) time(&now);
	if (pmptr->p_time == 0L)
		pmptr->p_time = now;
	if (pmptr->p_respawn >= SPAWN_LIMIT) {
		if ((now - pmptr->p_time) < SPAWN_INTERVAL) {
			pmptr->p_time = now;
			pmptr->p_respawn = 0;
			return (-1);
		}
		pmptr->p_time = now;
		pmptr->p_respawn = 0;
	}
	pmptr->p_respawn++;
	return (0);
}

/*
 * mod_ttydefs	- to check if /etc/ttydefs has been modified
 *		- return TRUE if file modified
 *		- otherwise, return FALSE
 */
static	int
mod_ttydefs(void)
{
	struct	stat	statbuf;

	if (stat(TTYDEFS, &statbuf) == -1) {
		/* if stat failed, don't bother reread ttydefs */
		return (FALSE);
	}
	if ((long)statbuf.st_mtime != Mtime) {
		Mtime = (long)statbuf.st_mtime;
		return (TRUE);
	}
	return (FALSE);
}

/*
 *	free_defs - free the Gdef table
 */
static	void
free_defs(void)
{
	int	i;
	struct	Gdef	*tp;
	tp = &Gdef[0];
	for (i = 0; i < Ndefs; i++, tp++) {
		free(tp->g_id);
		free(tp->g_iflags);
		free(tp->g_fflags);
		free(tp->g_nextid);
		tp->g_id = NULL;
		tp->g_iflags = NULL;
		tp->g_fflags = NULL;
		tp->g_nextid = NULL;
	}
	Ndefs = 0;
}

/*
 * struct Gdef *get_speed(ttylabel)
 *	- search "/etc/ttydefs" for speed and term. specification
 *	  using "ttylabel". If "ttylabel" is NULL, default
 *	  to DEFAULT
 * arg:	  ttylabel - label/id of speed settings.
 */

struct Gdef *
get_speed(char *ttylabel)
{
	struct Gdef *sp;

	if ((ttylabel != NULL) && (*ttylabel != '\0')) {
		if ((sp = find_def(ttylabel)) == NULL) {
			log("unable to find <%s> in \"%s\"", ttylabel, TTYDEFS);
			sp = &DEFAULT; /* use default */
		}
	} else sp = &DEFAULT; /* use default */
	return (sp);
}

/*
 * setup_PCpipe()	- setup the pipe between Parent and Children
 *			- the pipe is used for a tmchild to send its
 *			  pid to inform ttymon that it is about to
 *			  invoke service
 *			- the pipe also serves as a mean for tmchild
 *			  to detect failure of ttymon
 */
void
setup_PCpipe(void)
{
	int	flag = 0;

	if (pipe(PCpipe) == -1)
		fatal("pipe() failed: %s", strerror(errno));

	/* set close-on-exec flag */
	if (fcntl(PCpipe[0], F_SETFD, 1) == -1)
		fatal("F_SETFD fcntl failed: %s", strerror(errno));

	if (fcntl(PCpipe[1], F_SETFD, 1) == -1)
		fatal("F_SETFD fcntl failed: %s", strerror(errno));

	/* set O_NONBLOCK flag */
	if (fcntl(PCpipe[0], F_GETFL, flag) == -1)
		fatal("F_GETFL failed: %s", strerror(errno));

	flag |= O_NONBLOCK;
	if (fcntl(PCpipe[0], F_SETFL, flag) == -1)
		fatal("F_SETFL failed: %s", strerror(errno));

	/* set message discard mode */
	if (ioctl(PCpipe[0], I_SRDOPT, RMSGD) == -1)
		fatal("I_SRDOPT RMSGD failed: %s", strerror(errno));

	/* register to receive SIGPOLL when data come */
	if (ioctl(PCpipe[0], I_SETSIG, S_INPUT) == -1)
		fatal("I_SETSIG S_INPUT failed: %s", strerror(errno));

#ifdef	DEBUG
	log("PCpipe[0]\t = %d", PCpipe[0]);
	log("PCpipe[1]\t = %d", PCpipe[1]);
#endif
}
