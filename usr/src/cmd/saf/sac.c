/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utmpx.h>
#include <memory.h>
#include "msgs.h"
#include "extern.h"
#include <sac.h>
#include "misc.h"
#include "structs.h"

#include <security/pam_appl.h>

#define	RESP	1		/* pollfail via no response to sanity poll */
#define	DEATH	2		/* pollfail via child death */

/* signal whose dispositions will be changed */

static struct sigaction	Sigpoll;	/* SIGPOLL */
static struct sigaction	Sigcld;		/* SIGCLD */
static struct sigaction	Sigalrm;	/* SIGALRM */
static sigset_t Origmask;		/* original signal mask */

void usage(void);
void initialize(void);
void startpms(void);
void readutmpx(void);
int startpm(struct sactab *);
void cleanutx(struct sactab *);
void account(struct sactab *, pid_t);
void startit(struct sactab *);
char **mkargv(struct sactab *);
void pollpms(int);
void reap(int);
void pollfail(struct sactab *, int);
void readpipe(void);
int validstate(uchar_t);
int mk_cmd_pipe(void);
void startpoll(void);



/*
 * main - scan args for sac, initialize everything, and wait for commands
 *	  from sacadm via the command pipe
 */

int
main(int argc, char *argv[])
{
	int c;	/* place to hold options */
	struct sigaction sigact;	/* for signal handling */

	(void) sigprocmask(SIG_SETMASK, NULL, &Origmask);
	if (argc == 1)
		usage();
	(void) setpgrp();
	while ((c = getopt(argc, argv, "t:")) != -1) {
		switch (c) {
		case 't':
			if (Stime != 0)
				usage();
			Stime = atoi(optarg);
			if (Stime <= 0)
				usage();
			break;
		case '?':
			usage();
		}
	}
	if (optind < argc)
		usage();

	initialize();
	sigact.sa_flags = 0;
	sigact.sa_handler = pollpms;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGALRM);
	(void) sigaction(SIGALRM, &sigact, &Sigalrm);

/*
 * minimize time spent in STARTING or UNKNOWN, pollpms() sets alarm
 */

	pollpms(SIGALRM);
	for (;;)
		readpipe();
}


/*
 * usage - output a usage message on the console
 */

void
usage()
{
	FILE *fp;	/* scratch file pointer */

	fp = fopen("/dev/console", "w");
	if (fp)
		(void) fprintf(fp, "SAC: Usage: sac -t sanity_interval\n");
	exit(1);
}


/*
 * initialize - initialization stuff
 */


void
initialize()
{
	int ret;			/* return code from doconfig() */
	struct sigaction sigact;	/* for signal handling */

	openlog();
	log("*** SAC starting ***");
#ifdef DEBUG
	opendebug();
	log("Debugging turned on");
#endif
	if (chdir(HOME) < 0)
		error(E_CHDIR, EXIT);

/*
 * pass an invalid fd, shouldn't be doing pushes and pops in this per-system
 * configuration script (_sysconfig)
 */

	if ((ret = doconfig(-1, SYSCONFIG, 0)) != 0) {
		if (ret == -1)
			error(E_SYSCONF, EXIT);
		else {
			(void) sprintf(Scratch,
			    "Error in _sysconfig: line %d", ret);
			log(Scratch);
			error(E_BADSYSCONF, EXIT);
		}
	}

	sigact.sa_flags = 0;
	sigact.sa_handler = reap;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGCLD);
	(void) sigaction(SIGCLD, &sigact, &Sigcld);

/*
 * establish pipe for PMS to communicate with sac
 */

	if (access("_sacpipe", 0) != 0) {
		/* not there, create one */
		(void) umask(0);
		if (mknod("_sacpipe", S_IFIFO | 0600, 0) < 0)
			error(E_NOPIPE, EXIT);
	}
	Sfd = open("_sacpipe", O_RDWR);
	if (Sfd < 0)
		error(E_NOPIPE, EXIT);

/*
 * establish pipe for sacadm to communicate with sac
 */

	Cfd = mk_cmd_pipe();

/*
 * read in _sactab, but don't start port monitors as a by-product
 * since we may be in recovery - start them explicitly instead
 */

	read_table(FALSE);
	startpoll();
	startpms();
}


/*
 * startpms - start initial set of port monitors
 */


void
startpms()
{
	struct sactab *sp;	/* working pointer */
	int rflag;			/* recovery flag */
	pid_t checklock();

/*
 * check to see if we're really a recovering SAC (if any port monitors hold
 * locks, assume that we're in recovery), if so, start differently
 */

	rflag = 0;
	for (sp = Sactab; sp; sp = sp->sc_next) {
		if (checklock(sp)) {
			rflag = 1;
			sp->sc_sstate = sp->sc_pstate = UNKNOWN;
			sp->sc_ok = 1;
			sp->sc_exit = 0;
			(void) sprintf(Scratch, "%s/_pmpipe", sp->sc_tag);
			sp->sc_fd = open(Scratch, O_RDWR);
			if (sp->sc_fd < 0) {

/*
 * if we get into here, we're in deep trouble.  PM seems to be running
 * and we're trying to recover, but we can't talk to it.  Unfortunately,
 * there's not much that can be done other than to try and restore a
 * sane state.  By setting sp->sc_ok to 0, this will look like a poll failure
 * and if sp->rs_rsmax > 0, PM will be restarted.
 */

				(void) sprintf(Scratch, "Could not open "
				    "_pmpipe for port monitor <%s>",
				    sp->sc_tag);
				log(Scratch);
				(void) sendsig(sp, SIGTERM);
				sp->sc_ok = 0;
			}
		}
	}
	if (rflag) {
		readutmpx();
		log("SAC in recovery");
		return;
	}

/*
 * normal startup
 */

	for (sp = Sactab; sp; sp = sp->sc_next) {
		if (sp->sc_flags & X_FLAG) {
			/* System Administator specified don't start */
			continue;
		}
		(void) startpm(sp);
	}
}


/*
 * readutmpx - read the utmpx file to find out the ids of running port
 *		monitors (only called during a recover start up).  Note:
 *		after a sac failure, init will inherit all of the port
 *		monitors and should get the SIGCLD's if they die (and
 *		will clean up).  This is mainly for stuck processes,
 *		although init would get the SIGCLD when the stuckie gets
 *		killed, it doesn't hurt to have the sac check.  This is
 *		only done once.
 *
 */


void
readutmpx()
{
	struct sactab *sp;	/* working pointer */
	struct sactab *savesp;	/* rembered port monitor match */
	struct utmpx *uxp;	/* working pointer */

	setutxent();
	while (uxp = getutxent()) {
		/* we're only interested in login processes */
		if (uxp->ut_type != LOGIN_PROCESS)
			continue;
		if (uxp->ut_user[sizeof (uxp->ut_user) - 1] == '\0') {

/*
 * possible port monitor and name is short enough to do a normal compare
 */

			sp = findpm(uxp->ut_user);
			if (sp && (sp->sc_sstate == UNKNOWN)) {
				/* found one */
				(void) memcpy(sp->sc_utid, uxp->ut_id, IDLEN);
				sp->sc_pid = uxp->ut_pid;
			}
		} else {

/*
 * possible port monitor name, but it could have been truncated.  If
 * a match is found on a unique prefix, then it should be the correct
 * entry.  If an ambiguity is found, ignore the entry, init will clean
 * up the entry if it dies.
 */

			savesp = NULL;
			for (sp = Sactab; sp; sp = sp->sc_next) {
				if (strncmp(uxp->ut_user, sp->sc_tag,
				    sizeof (uxp->ut_user)) == 0) {
					if (savesp) {
						/* already found a match */
						savesp = NULL;
						(void) sprintf(Scratch,
						    "ambiguous utmpx entry "
						    "<%.8s>", sp->sc_tag);
						log(Scratch);
						break;
					} else {
						savesp = sp;
					}
				}
			}
			if (savesp && (savesp->sc_sstate == UNKNOWN)) {
				/* found it */
				(void) memcpy(savesp->sc_utid, uxp->ut_id,
				    IDLEN);
				savesp->sc_pid = uxp->ut_pid;
			}
		}
	}
	endutxent();
}


/*
 * startpm - start a particular PM, return code:
 *		-1: _pid file locked
 *		-2: any other reason
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port monitor
 */

int
startpm(struct sactab *sp)
{
	sigset_t cset;		/* for signal handling */
	sigset_t tset;		/* for signal handling */
	pid_t pid;		/* pid of new port monitor */
	pid_t checklock();

#ifdef DEBUG
	debug("in startpm");
#endif
	if (checklock(sp)) {
		(void) sprintf(Scratch,
		    "could not start <%s> - _pid file locked", sp->sc_tag);
		log(Scratch);
		return (-1);
	}

	(void) sprintf(Scratch, "%s/_pmpipe", sp->sc_tag);
	if (access(Scratch, 0) != 0) {
		/* not there, create one */
		(void) umask(0);
		if (mknod(Scratch, S_IFIFO | 0600, 0) < 0) {
			(void) sprintf(Scratch, "Could not create _pmpipe "
			    "for port monitor <%s>, errno is %d",
			    sp->sc_tag, errno);
			log(Scratch);
			return (-2);
		}
	}
	sp->sc_fd = open(Scratch, O_RDWR);
	if (sp->sc_fd < 0) {
		(void) sprintf(Scratch, "Could not open _pmpipe for port "
		    "monitor <%s>, errno is %d", sp->sc_tag, errno);
		log(Scratch);
		return (-2);
	}

	/* in case child dies too quickly */
	(void) sigprocmask(SIG_SETMASK, NULL, &cset);
	tset = cset;
	(void) sigaddset(&tset, SIGCLD);
	(void) sigprocmask(SIG_SETMASK, &tset, NULL);
	if ((pid = fork()) < 0) {
		(void) sprintf(Scratch,
		    "Could not fork port monitor <%s>", sp->sc_tag);
		log(Scratch);
		return (-2);
	} else if (!pid) {
		startit(sp);
		/* no return */
	}

/*
 * clean up old utmpx if its there
 */

	cleanutx(sp);

/*
 * create a utmpx entry and set initial states
 */

	account(sp, pid);
	sp->sc_pstate = STARTING;
	if (sp->sc_lstate == NOTRUNNING)
		sp->sc_sstate = (sp->sc_flags & D_FLAG) ? DISABLED : ENABLED;
	else
		sp->sc_sstate = sp->sc_lstate;
	sp->sc_ok = 1;
	sp->sc_exit = 0;
	sp->sc_pid = pid;
	/* ok to take signals now that the table is up-to-table */
	(void) sigprocmask(SIG_SETMASK, &cset, NULL);
	return (0);
}


/*
 * cleanutx - clean out a utmpx record for a port monitor
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port monitor
 */


void
cleanutx(struct sactab *sp)
{
	int i;			 /* scratch variable */
	int zerocheck;		  /* scratch variable */
	char buf[SIZE];		 /* scratch buffer */
	pam_handle_t *pamh;		/* PAM auth descriptor */
	struct utmpx ut;
	struct utmpx *up;
	int pid;
	char user[sizeof (up->ut_user) + 1];
	char ttyn[sizeof (up->ut_line) + 1];
	char rhost[sizeof (up->ut_host) + 1];
/*
 * check to see if there is a utmpx entry to clean up (indicated by a non
 * zero utmpx id
 */
	zerocheck = 0;
	for (i = 0; i < IDLEN; ++i) {
		zerocheck += sp->sc_utid[i];
	}
	if (zerocheck == 0)
		return;

	pid = sp->sc_pid;
	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS) {
				/*
				 * Cleaned up elsewhere.
				 */
				break;
			}
			strncpy(user, up->ut_user, sizeof (up->ut_user));
			user[sizeof (up->ut_user)] = '\0';
			strncpy(ttyn, up->ut_line, sizeof (up->ut_line));
			ttyn[sizeof (up->ut_line)] = '\0';
			strncpy(rhost, up->ut_host, sizeof (up->ut_host));
			rhost[sizeof (up->ut_host)] = '\0';

			if ((pam_start("sac", user, NULL, &pamh)) ==
			    PAM_SUCCESS) {
				(void) pam_set_item(pamh, PAM_TTY, ttyn);
				(void) pam_set_item(pamh, PAM_RHOST, rhost);
				(void) pam_close_session(pamh, 0);
				pam_end(pamh, PAM_SUCCESS);
			}

			up->ut_type = DEAD_PROCESS;
			up->ut_exit.e_termination = WTERMSIG(sp->sc_exit);
			up->ut_exit.e_exit = WEXITSTATUS(sp->sc_exit);
			(void) memcpy(up->ut_id, sp->sc_utid,
			    sizeof (up->ut_id));
			(void) time(&up->ut_tv.tv_sec);
			if (modutx(up) == NULL) {
				/*
				 * Since modutx failed we'll
				 * write out the new entry
				 * ourselves.
				 */
				(void) pututxline(up);
				updwtmpx("wtmpx", up);
			}
			break;
		}
	}
	endutxent();
}

/*
 * account - create a utmp record for a port monitor
 *
 *	args:	pid - process id of port monitor
 */


void
account(struct sactab *sp, pid_t pid)
{
	struct utmpx utmpx;			/* prototype utmpx entry */
	struct utmpx *up = &utmpx;		/* and a pointer to it */

	(void) memset(up, '\0', sizeof (utmpx));
	(void) strncpy(up->ut_user, sp->sc_tag, sizeof (up->ut_user));
	up->ut_pid = pid;
	up->ut_type = LOGIN_PROCESS;
	up->ut_id[0] = 'P';
	up->ut_id[1] = 'M';
	up->ut_id[2] = SC_WILDC;
	up->ut_id[3] = SC_WILDC;
	(void) time(&up->ut_xtime);
	if (makeutx(up) == NULL) {
		log("Could not create utmpx entry");
		(void) memset(sp->sc_utid, '\0', IDLEN);
	} else {
		(void) memcpy(sp->sc_utid, up->ut_id, IDLEN);
	}
}


/*
 * startit - finish starting a particular port monitor, establish environment,
 *		etc. (Note: this is the child at this point)
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port monitor
 */


void
startit(struct sactab *sp)
{
	static char istate[SIZE];	/* place to put ISTATE env var. */
	static char pmtag[SIZE];	/* place to put PMTAG env var. */
	char **argvp;			/* arglist for PM */
	int i;				/* loop control variable */
	long ndesc;			/* # of file descriptors configured */
	int ret;			/* return value from doconfig */
	sigset_t cset;			/* for signal handling */
	sigset_t tset;			/* for signal handling */

/*
 * establish the home directory
 */

	if (chdir(sp->sc_tag) < 0) {
		(void) sprintf(Scratch,
		    "Cannot chdir to <%s/%s>, port monitor not started",
		    HOME, sp->sc_tag);
		log(Scratch);
		exit(1);
	}

/*
 * interpret the configuration script, pass an invalid fd, shouldn't be
 * doing pushes and pops in this script
 */

	(void) sigprocmask(SIG_SETMASK, NULL, &cset);
	tset = cset;
	(void) sigaddset(&tset, SIGCLD);
	(void) sigprocmask(SIG_SETMASK, &tset, NULL);
	if ((ret = doconfig(-1, "_config", 0)) != 0) {
		if (ret == -1) {
			(void) sprintf(Scratch,
			    "system error in _config script for <%s>",
			    sp->sc_tag);
			log(Scratch);
			exit(1);
		} else {
			(void) sprintf(Scratch,
			    "Error in _config script for <%s>: line %d",
			    sp->sc_tag, ret);
			log(Scratch);
			exit(1);
		}
	}

/*
 * add the promised environment variables
 */

	if (sp->sc_lstate == NOTRUNNING)
		(void) sprintf(istate, "ISTATE=%s",
		    (sp->sc_flags & D_FLAG) ? "disabled" : "enabled");
	else
		(void) sprintf(istate, "ISTATE=%s",
		    (sp->sc_lstate == DISABLED) ? "disabled" : "enabled");
	if (putenv(istate)) {
		(void) sprintf(Scratch,
		    "can't expand port monitor <%s> environment",
		    sp->sc_tag);
		log(Scratch);
		exit(1);
	}
	(void) sprintf(pmtag, "PMTAG=%s", sp->sc_tag);
	if (putenv(pmtag)) {
		(void) sprintf(Scratch,
		    "can't expand port monitor <%s> environment",
		    sp->sc_tag);
		log(Scratch);
		exit(1);
	}

/*
 * build an argv
 */

	argvp = mkargv(sp);

	(void) sprintf(Scratch, "starting port monitor <%s>", sp->sc_tag);
	log(Scratch);
	ndesc = ulimit(4, 0L);
	for (i = 0; i < ndesc; i++)
		(void) fcntl(i, F_SETFD, 1);
	/* restore orignal handlers and mask */
	(void) sigaction(SIGPOLL, &Sigpoll, NULL);
	(void) sigaction(SIGCLD, &Sigcld, NULL);
	(void) sigaction(SIGALRM, &Sigalrm, NULL);
	(void) sigprocmask(SIG_SETMASK, &Origmask, NULL);
	(void) execve(argvp[0], argvp, environ);
	(void) sprintf(Scratch, "exec of port monitor <%s> failed", sp->sc_tag);
	log(Scratch);
	exit(1);
}


/*
 * mkargv - Given a pointer to a struct sactab, construct argv
 *		for an exec system call.
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port montior
 */


#define	NARGS	50	/* max # of args */

static char *newargv[NARGS];	/* place for argv list */
static char *delim = " \t'\"";	/* delimiter list */

char **
mkargv(struct sactab *sp)
{
	char **argvp = newargv;			/* scratch pointer */
	char *p = sp->sc_cmd;			/* working pointer */
	char delch;				/* delimiter seen */
	char *savep;				/* scratch pointer */
	char *tp;				/* scratch pointer */

	*argvp = 0;
	savep = p;
	while (p && *p) {
		if (p = strpbrk(p, delim)) {
			switch (*p) {
			case ' ':
			case '\t':
				/* "normal" cases */
				*p++ = '\0';
				*argvp++ = savep;
				/* zap trailing white space */
				while (isspace(*p))
					p++;
				savep = p;
				break;
			case '"':
			case '\'':
				/* found a string */
				delch = *p; /* remember the delimiter */
				savep = ++p;

/*
 * We work the string in place, embedded instances of the string delimiter,
 * i.e. \" must have the '\' removed.  Since we'd have to do a compare to
 * decide if a copy were needed, it's less work to just do the copy, even
 * though it is most likely unnecessary.
 */

				tp = p;
				for (;;) {
					if (*p == '\0') {
						(void) sprintf(Scratch,
						    "invalid command line, "
						    "non-terminated string for "
						    "port monitor %s",
						    sp->sc_tag);
						log(Scratch);
						exit(1);
					}
					if (*p == delch) {
						if (*(tp - 1) == '\\') {
							/* \delim */
							*(tp - 1) = *p;
							p++;
						} else { /* end of string */
							*tp = 0;
							*argvp++ = savep;
							p++;
						/* zap trailing white space */
							while (isspace(*p))
								p++;
							savep = p;
							break;
						}
					} else {
						*tp++ = *p++;
					}
				}
				break;
			default:
				log("Internal error in parse routine");
				exit(1);
			}
		}
		else
			*argvp++ = savep;
	}
	*argvp = 0;
	return (newargv);
}


/*
 * pollpms - send out sanity polls, if sc_sstate and sc_pstate are
 *	the same (everyone agrees on the state) or if SAC thinks PM
 *	should be stopping, send out a status message;
 *	otherwise, send out a message indicating the state the SAC
 *	thinks the PM should be entering
 */

void
pollpms(int signal __unused)
{
	struct sactab *sp;	/* working pointer */
	struct sacmsg sacmsg;		/* message to send to PM */

#ifdef DEBUG
	debug("alarm went off");
#endif
	for (sp = Sactab; sp; sp = sp->sc_next) {
		if (sp->sc_pstate == NOTRUNNING || sp->sc_pstate == FAILED) {
			/* don't bother if no one is home */
			continue;
		}
		if (sp->sc_ok == 0) {
			/* PM has stopped responding */
			pollfail(sp, RESP);
			continue;
		}

/*
 * note - if we're in recovery, a SC_STATUS message is sent
 * (sc_sstate = UNKNOWN and sc_pstate = UNKNOWN)
 */

		if (sp->sc_sstate == sp->sc_pstate) {
			sacmsg.sc_type = SC_STATUS;
			sacmsg.sc_size = 0;
		} else {
			switch (sp->sc_sstate) {
			case ENABLED:
				sacmsg.sc_type = SC_ENABLE;
				sacmsg.sc_size = 0;
				break;
			case DISABLED:
				sacmsg.sc_type = SC_DISABLE;
				sacmsg.sc_size = 0;
				break;
			case STARTING:
			case STOPPING:
			case NOTRUNNING:
			case FAILED:
			case UNKNOWN:
				/*
				 * if NOTRUNNING or FAILED, PM will probably
				 * not respond to poll, that's how we detect
				 * that it's gone
				 */
				sacmsg.sc_type = SC_STATUS;
				sacmsg.sc_size = 0;
				break;
			default:
				error(E_BADSTATE, EXIT);
			}
		}

		/* send the message */
		sendpmmsg(sp, &sacmsg);
		sp->sc_ok = 0;
	}
	(void) alarm(Stime);
}


/*
 * reap - clean up dead children, equivalent to a "fast" poll failure
 *
 *	args:	signo - signal #
 */

void
reap(int signo)
{
	struct sactab *sp;		/* working pointer */
	pid_t pid;			/* returned pid from wait */
	int status;			/* returned status from wait */

	pid = wait(&status);
	for (sp = Sactab; sp; sp = sp->sc_next) {
		if (sp->sc_pid == pid)
			break;
	}
	if (sp == NULL) {
		/* not from a port monitor we know about */
		return;
	}
	sp->sc_exit = status;
	/* only call pollfail for "stuck" and stopping processes */
	if (sp->sc_pstate != NOTRUNNING && sp->sc_pstate != FAILED)
		pollfail(sp, DEATH);
}


/*
 * pollfail - handle the case where a PM stops responding to a sanity poll
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port monitor
 *		reason - RESP or DEATH (indicates why pollfail called)
 */


void
pollfail(struct sactab *sp, int reason)
{
	char buf[SIZE];			/* scratch buffer */
	sigset_t cset;			/* for signal handling */
	sigset_t tset;			/* for signal handling */

#ifdef DEBUG
	debug("in pollfail");
#endif

/* first, remove the utmpx entry and clean up any links */

	cleanutx(sp);

	if (sp->sc_pstate == STOPPING) {
		(void) sprintf(buf, "<%s> has stopped", sp->sc_tag);
		log(buf);
		sp->sc_pstate = NOTRUNNING;
		sp->sc_lstate = NOTRUNNING;
		(void) close(sp->sc_fd);
	} else {

/*
 * PM in trouble - if it's still there, try to put it out of its misery
 * We play with SIGCLD here to that after SIGKILL is sent, the catcher
 * routine reap() is not called until we're ready (note: when a catcher
 * is established for SIGCLD and any zombies are present, the signal is
 * immediately received)
 */

		(void) sigprocmask(SIG_SETMASK, NULL, &cset);
		tset = cset;
		(void) sigaddset(&tset, SIGCLD);
		(void) sigprocmask(SIG_SETMASK, &tset, NULL);
		(void) sendsig(sp, SIGKILL);
		if (sp->sc_rscnt < sp->sc_rsmax) {
			/* try to restart it */
			if (reason == RESP)
				(void) sprintf(buf, "<%s> stopped responding "
				    "to sanity polls - trying to restart",
				    sp->sc_tag);
			else
				(void) sprintf(buf,
				    "<%s> has died - trying to restart",
				    sp->sc_tag);
			log(buf);
			sp->sc_rscnt++;
			(void) close(sp->sc_fd);
			(void) startpm(sp);
		} else {
			sp->sc_sstate = sp->sc_pstate = FAILED;
			(void) close(sp->sc_fd);
			(void) sprintf(buf, "<%s> has FAILED", sp->sc_tag);
			log(buf);
		}
	}
	(void) sigprocmask(SIG_SETMASK, &cset, NULL);
}


/*
 * readpipe - read messages from _sacpipe
 */


void
readpipe()
{
	struct pmmsg pmmsg;			/* incoming message */
	struct pmmsg *pp = &pmmsg;		/* and a pointer to it */
	struct sactab *sp;			/* working pointer */
	int ret;				/* return value from read */

/*
 * This routine's main purpose is to maintain the state associated with
 * each of the known port monitors.  Because it may be confusing, following
 * is a brief discussion of what is happening.  Three different views of
 * a port monitor's state exist: sc_sstate, sc_pstate, and sc_lstate.
 * sc_sstate is the state in which the sac has been instructed to place
 * a port monitor.  sc_lstate is essentially a shadow of this field, however,
 * it will only take on the values ENABLED, DISABLED, and NOTRUNNING.
 * sc_lstate is used if a port monitor dies to restart it in the state in
 * which it was last running.  sc_pstate is the last state that the port
 * monitor reported itself in.  Note that if the administrator specifies
 * a state change, there is a window where sc_sstate and sc_pstate will
 * be different (until the port monitor enacts and acknowledges the change).
 *
 * These states interact with the polling loop to determine which message
 * should be sent to a port monitor.  If the states agree, an SC_STATUS
 * is sent.  If they disagree, the appropriate message to put the port
 * monitor in the correct state is sent (SC_ENABLE or SC_DISABLE).  sc_pstate
 * is the state that is reported back to an AC_STATUS request.  Finally,
 * when in recovery (sc_sstate and sc_pstate both = UNKNOWN), the sac will
 * take the port monitor's reported state as the true state.  This is the
 * only instance in which a port monitor can cause sc_sstate to change.
 */

	for (;;) {
		if (read(Sfd, pp, sizeof (pmmsg)) < 0) {
			if (errno != EINTR)
				error(E_BADREAD, EXIT);
			continue;
		}

		while (pp->pm_size) {

/*
 * there's data after the header, unfortunately, we don't understand
 * any of it because only class 1 (no data) messages are defined.  Just
 * flush it
 */

			ret = read(Sfd, Scratch, (pp->pm_size > SIZE) ?
			    (unsigned)SIZE : (unsigned)pp->pm_size);
			if (ret < 0) {
				if (errno != EINTR)
					error(E_BADREAD, EXIT);
				continue;
			}
			else
				pp->pm_size -= ret;
		}

		sp = findpm(pp->pm_tag);
		if (sp == NULL) {
			log("message from unknown process");
			continue;
		}
		switch (pp->pm_type) {
		case PM_UNKNOWN:
			(void) sprintf(Scratch,
			    "port monitor <%s> didn't recognize message",
			    sp->sc_tag);
			log(Scratch);
			/* fall through */
		case PM_STATUS:
			/*
			 * paranoia check, if port monitor reports garbage
			 * state, pretend it said UNKNOWN
			 */
			if (!validstate(pp->pm_state)) {
				pp->pm_state = UNKNOWN;
				(void) sprintf(Scratch, "port monitor <%s> "
				    "reporting invalid state", sp->sc_tag);
				log(Scratch);
			}
			if (sp->sc_sstate == sp->sc_pstate) {
				/* everyone agrees on the current state */
				if (sp->sc_sstate == UNKNOWN) {
					/* special case for recovery */
					sp->sc_sstate = pp->pm_state;
					sp->sc_pstate = pp->pm_state;
					if (pp->pm_state == ENABLED ||
					    pp->pm_state == DISABLED)
					/* sc_lstate NOTRUNNING by default */
						sp->sc_lstate = pp->pm_state;
				}
				if (pp->pm_state != sp->sc_pstate) {
					/*
					 * something isn't right here, PM
					 * changed state without orders, try
					 * to restore to correct state
					 */
					sp->sc_pstate = pp->pm_state;
				}
			} else if (sp->sc_sstate == pp->pm_state) {
				/* PM changed to state requested */
				(void) sprintf(Scratch, "port monitor <%s> "
				    "changed state from %s to %s",
				    sp->sc_tag, pstate(sp->sc_pstate),
				    pstate(pp->pm_state));
				log(Scratch);
				sp->sc_pstate = pp->pm_state;
			} else if (sp->sc_pstate != pp->pm_state) {
				/*
				 * something isn't right here, PM isn't
				 * in the state it was, nor is it in the
				 * state we just tried to put it in, try
				 * to restore to correct state if we should
				 */
				if (sp->sc_pstate != STOPPING)
					sp->sc_pstate = pp->pm_state;
			}
			break;
		default:
			(void) sprintf(Scratch, "port monitor <%s> sent an "
			    "invalid message - ignoring it", sp->sc_tag);
			log(Scratch);
			break;
		}
		/* no matter what, PM did answer the poll */
		sp->sc_ok = 1;
		/* Note the messages it understands */
		sp->sc_maxclass = pp->pm_maxclass;
	}
}


/*
 * validstate - determine if arg s a valid return state from a port monitor
 *	return 1 if ok, 0 otherwise
 *
 *	args:	state - state to be verified
 */
int
validstate(uchar_t state)
{
	switch (state) {
	case PM_ENABLED:
	case PM_DISABLED:
	case PM_STARTING:
	case PM_STOPPING:
		return (1);
	default:
		return (0);
	}
}


/*
 * mk_cmd_pipe - create the command pipe used by sacadm
 */

int
mk_cmd_pipe()
{
	int fds[2];			/* pipe endpoints */
	int fd;				/* scratch file descriptor */

	/* make sure there is a file here to mount on */
	(void) unlink(CMDPIPE);
	fd = open(CMDPIPE, O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		error(E_CMDPIPE, EXIT);
	close(fd);
	if (pipe(fds) < 0)
		error(E_PIPE, EXIT);
	if (fattach(fds[0], CMDPIPE) < 0)
		error(E_FATTACH, EXIT);
	return (fds[1]);
}


/*
 * startpoll - enable polling on command pipe by setting up to catch SIGPOLL
 */


void
startpoll()
{
	struct sigaction sigact;	/* for signal handling */

	if (ioctl(Cfd, I_SETSIG, S_INPUT) < 0)
		error(E_SETSIG, EXIT);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigpoll;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGPOLL);
	(void) sigaction(SIGPOLL, &sigact, &Sigpoll);
}
