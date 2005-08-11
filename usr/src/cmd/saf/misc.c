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
/*	  All Rights Reserved  	*/
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <signal.h>
#include <sys/stat.h>
#include <poll.h>
#include "misc.h"
#include "msgs.h"
#include "extern.h"
#include <sac.h>
#include "adm.h"
#include "structs.h"


/*
 * findpm - find a port monitor entry
 *
 *	args:	tag - tag of desired port monitor
 */


struct sactab *
findpm(tag)
register char *tag;
{
	register struct sactab *sp;	/* working pointer */

	for (sp = Sactab; sp; sp = sp->sc_next) {
		if (!strcmp(tag, sp->sc_tag))
			return(sp);
	}
	return(NULL);
}


/*
 * sigpoll - handle messages coming in on the command pipe (SIGPOLL signal
 *		handler)
 */


void
sigpoll()
{
	struct pollfd fds;			/* array of fds to poll */
	struct admcmd cmd;			/* incoming command */
	register struct admcmd *ap = &cmd;	/* and a pointer to it */
	struct admack ack;			/* acknowledgment */
	register struct admack *ak = &ack;	/* and a pointer to it */
	register struct sactab *sp;		/* working pointer */
	struct sacmsg sacmsg;			/* message to port monitor */
	char **data;				/* "dumped" sactab */
	char *p;				/* scratch pointer */
	register int i;				/* loop control variable */
	int ret;				/* return value */
	sigset_t cset;				/* for signal handling */
	sigset_t tset;				/* for signal handling */

# ifdef DEBUG
	debug("in sigpoll");
# endif
	fds.fd = Cfd;
	fds.events = POLLIN;
	fds.revents = 0;
	if (poll(&fds, 1, 0) < 0)
		error(E_POLL, EXIT);
	switch (fds.revents) {
	case POLLIN:
		if (read(Cfd, ap, sizeof(struct admcmd)) < 0) {
			error(E_READ, EXIT);
		}
		switch (ap->ac_mtype) {

/*
 * request to start a port monitor
 */

		case AC_START:
# ifdef DEBUG
			(void) sprintf(Scratch, "Got AC_START for <%s>", ap->ac_tag);
			log(Scratch);
# endif
			if ((sp = findpm(ap->ac_tag)) == NULL) {
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_NOPM;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			switch (sp->sc_sstate) {
			case UNKNOWN:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_RECOVER;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case FAILED:
			case NOTRUNNING:
				sp->sc_rscnt = 0;	/* fresh start in life */
				if (ret = startpm(sp)) {
					ak->ak_pid = ap->ac_pid;
					if (ret == -1)
						ak->ak_resp = AK_PMLOCK;
					else
						ak->ak_resp = AK_REQFAIL;
					ak->ak_size = 0;
					sendack(ak);
					break;
				}
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case ENABLED:
			case DISABLED:
			case STARTING:
			case STOPPING:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_PMRUN;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			break;

/*
 * request to kill a port monitor
 */

		case AC_KILL:
# ifdef DEBUG
			(void) sprintf(Scratch, "Got AC_KILL for <%s>", ap->ac_tag);
			log(Scratch);
# endif
			if ((sp = findpm(ap->ac_tag)) == NULL) {
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_NOPM;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			switch (sp->sc_sstate) {
			case UNKNOWN:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_RECOVER;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case NOTRUNNING:
			case FAILED:
			case STOPPING:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_PMNOTRUN;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case STARTING:
			case ENABLED:
			case DISABLED:
				(void) sigprocmask(SIG_SETMASK, NULL, &cset);
				tset = cset;
				(void) sigaddset(&tset, SIGALRM);
				(void) sigaddset(&tset, SIGCLD);
				(void) sigprocmask(SIG_SETMASK, &tset, NULL);
				if (sendsig(sp, SIGTERM)) {
					(void) sprintf(Scratch, "could not send SIGTERM to <%s>", sp->sc_tag);
					log(Scratch);
					ak->ak_pid = ap->ac_pid;
					ak->ak_resp = AK_NOCONTACT;
					ak->ak_size = 0;
					sendack(ak);
					(void) sigprocmask(SIG_SETMASK, &cset, NULL);
					break;
				}
				/* signal sent ok */
				sp->sc_lstate = NOTRUNNING;
				sp->sc_sstate = NOTRUNNING;
				sp->sc_pstate = STOPPING;
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				(void) sprintf(Scratch, "terminating <%s>", sp->sc_tag);
				log(Scratch);
				(void) sigprocmask(SIG_SETMASK, &cset, NULL);
				break;
			}
			break;

/*
 * request to enable a port monitor
 */

		case AC_ENABLE:
# ifdef DEBUG
			(void) sprintf(Scratch, "Got AC_ENABLE for <%s>", ap->ac_tag);
			log(Scratch);
# endif
			if ((sp = findpm(ap->ac_tag)) == NULL) {
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_NOPM;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			switch (sp->sc_sstate) {
			case UNKNOWN:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_RECOVER;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case NOTRUNNING:
			case FAILED:
			case STOPPING:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_PMNOTRUN;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case STARTING:
			case DISABLED:
				sacmsg.sc_type = SC_ENABLE;
				sacmsg.sc_size = 0;
				sp->sc_sstate = ENABLED;
				sp->sc_lstate = ENABLED;
				sendpmmsg(sp, &sacmsg);
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case ENABLED:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			break;

/*
 * request to disable a port monitor
 */

		case AC_DISABLE:
# ifdef DEBUG
			(void) sprintf(Scratch, "Got AC_DISABLE for <%s>", ap->ac_tag);
			log(Scratch);
# endif
			if ((sp = findpm(ap->ac_tag)) == NULL) {
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_NOPM;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			switch (sp->sc_sstate) {
			case UNKNOWN:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_RECOVER;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case NOTRUNNING:
			case FAILED:
			case STOPPING:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_PMNOTRUN;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case STARTING:
			case ENABLED:
				sacmsg.sc_type = SC_DISABLE;
				sacmsg.sc_size = 0;
				sp->sc_sstate = DISABLED;
				sp->sc_lstate = DISABLED;
				sendpmmsg(sp, &sacmsg);
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case DISABLED:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			break;

/*
 * request for port monitor status information
 */

		case AC_STATUS:
# ifdef DEBUG
			log("Got AC_STATUS");
# endif
			/* get all the info in one convenient place */
			data = dump_table();
			if ((data == NULL) && (Nentries > 0)) {
				/* something bad happened in dump_table */
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_REQFAIL;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			/* count how big it is */
			ak->ak_size = 0;
			for (i = 0; i < Nentries; ++i)
				ak->ak_size += strlen(data[i]);
# ifdef DEBUG
			(void) sprintf(Scratch, "ak_size is %d", ak->ak_size);
			debug(Scratch);
# endif
			/* get a contiguous chunk */
			if ((p = malloc((unsigned) (ak->ak_size + 1))) == NULL) {
				error(E_MALLOC, CONT);
				for (i = 0; i < Nentries; ++i)
					free(data[i]);
				free((char *) data);
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_REQFAIL;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			/* condense the data into the contiguous chunk */
			*p = '\0';
			for (i = 0; i < Nentries; ++i) {
				(void) strcat(p, data[i]);
				free(data[i]);
			}
# ifdef DEBUG
			debug(p);
# endif
			if (data)
				free((char *) data);
			/* ak->ak_size was set above */
			ak->ak_pid = ap->ac_pid;
			ak->ak_resp = AK_ACK;
			sendack(ak);
			if (ak->ak_size)
				if (write(Cfd, p, (unsigned) ak->ak_size) != ak->ak_size)
					log("could not send info");
			free(p);
			break;

/*
 * request for sac to read sactab
 */

		case AC_SACREAD:
# ifdef DEBUG
			log("Got AC_SACREAD");
# endif
			ak->ak_pid = ap->ac_pid;
			ak->ak_resp = AK_ACK;
			ak->ak_size = 0;
			read_table(TRUE);
			sendack(ak);
			break;

/*
 * request for port monitor to read _pmtab
 */

		case AC_PMREAD:
# ifdef DEBUG
			(void) sprintf(Scratch, "Got AC_PMREAD for <%s>", ap->ac_tag);
			log(Scratch);
# endif
			if ((sp = findpm(ap->ac_tag)) == NULL) {
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_NOPM;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			switch (sp->sc_sstate) {
			case UNKNOWN:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_RECOVER;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case NOTRUNNING:
			case FAILED:
			case STOPPING:
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_PMNOTRUN;
				ak->ak_size = 0;
				sendack(ak);
				break;
			case STARTING:
			case ENABLED:
			case DISABLED:
				sacmsg.sc_type = SC_READDB;
				sacmsg.sc_size = 0;
				sendpmmsg(sp, &sacmsg);
				ak->ak_pid = ap->ac_pid;
				ak->ak_resp = AK_ACK;
				ak->ak_size = 0;
				sendack(ak);
				break;
			}
			break;
/*
 * garbled message
 */

		default:
			(void) sprintf(Scratch, "Got unknown message for <%s>", ap->ac_tag);
			log(Scratch);
			ak->ak_pid = ap->ac_pid;
			ak->ak_resp = AK_UNKNOWN;
			ak->ak_size = 0;
			sendack(ak);
			break;
		}
		break;
	default:
		error(E_POLL, EXIT);
	}
}


/*
 * sendack - send a response to the administrative command
 *
 *	args:	ap - pointer to acknowlegment message
 */

void
sendack(ap)
struct admack *ap;
{
# ifdef DEBUG
	debug("in sendack");
# endif
	if (write(Cfd, ap, sizeof(struct admack)) != sizeof(struct admack))
		log("Could not send ack");
}


/*
 * sendpmmsg - send a message to a PM.  Note: sc_size is always 0 in
 *	       this version so just send the header.
 *
 *	args:	sp - pointer to sac's port monitor information for
 *		     designated port monitor
 *		sm - pointer to message to send
 */

void
sendpmmsg(sp, sm)
register struct sactab *sp;
register struct sacmsg *sm;
{
	char buf[SIZE];			/* scratch buffer */

# ifdef DEBUG
	debug("in sendpmmsg");
# endif
	if (write(sp->sc_fd, sm, sizeof(struct sacmsg)) != sizeof(struct sacmsg)) {
		(void) sprintf(buf, "message to <%s> failed", sp->sc_tag);
		log(buf);
	}
}

/*
 * sendsig - send a signal to the port monitor
 * 
 *	args:	sp - pointer to sac's port monitor infomation for
 *		     designated port monitor
 *		signo - signal number to send
 */

int
sendsig(struct sactab *sp, int signo)
{
	pid_t pid;	/* pid of designated port monitor */
	pid_t checklock();

# ifdef DEBUG
	(void) sprintf(Scratch, "in sendsig - sending signo %d to %s", signo, sp->sc_tag);
	debug(Scratch);
# endif
	if (pid = checklock(sp)) {
		if (kill(pid, signo) < 0) {
# ifdef DEBUG
			debug("in sendsig - kill failed");
# endif
			return(-1);
		}
		else
			return(0);
	}
	else {
# ifdef DEBUG
		debug("in sendsig - checklock failed");
# endif
		return(-1);
	}
}


/*
 * checklock - check to see if a _pid file is locked
 *		if so, return pid in file, else 0
 *
 *	args:	sp - pointer to sac's port monitor infomation for
 *		     designated port monitor
 */

pid_t
checklock(sp)
register struct sactab *sp;
{
	int fd;			/* scratch file descriptor */
	char buf[SIZE];		/* scratch buffer */
	int ret;		/* return value */

# ifdef DEBUG
	debug("in checklock");
# endif
	(void) sprintf(Scratch, "%s/%s/_pid", HOME, sp->sc_tag);
	fd = open(Scratch, O_RDONLY);
	if (fd < 0) {
		(void) sprintf(Scratch, "can not open _pid file for <%s>", sp->sc_tag);
		log(Scratch);
		return((pid_t)0);
	}
	if (lockf(fd, F_TEST, 0) < 0) {
		if ((ret = read(fd, buf, SIZE - 1)) < 0) {
			(void) close(fd);
			return((pid_t)0);
		}
		(void) close(fd);
		/* in case pid wasn't null-terminated */
		buf[ret] = '\0';
		return((pid_t)atol(buf));
	}
	(void) close(fd);
	return((pid_t)0);
}
