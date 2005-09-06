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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <poll.h>
#include <sys/dlpi.h>
#include "rpld.h"

/* Global run-time parameters */
char	configFile[MAXPATHLEN]	= {DFT_CONFIGFILE};
int	debugLevel	= DFT_DEBUGLEVEL;
int	debugDest	= DFT_DEBUGDEST;
int	maxClients	= DFT_MAXCLIENTS;
int	backGround	= DFT_BACKGROUND;
char	logFile[MAXPATHLEN]	= {DFT_LOGFILE};
unsigned long	startDelay	= DFT_STARTDELAY;
unsigned long	delayGran	= DFT_DELAYGRAN;
int	frameSize	= DFT_FRAMESIZE;
char	ifName[MAXPATHLEN] = "";
int	ifUnit = 0;
int	ppanum = 1;
int	need_llc = 0;

extern	void	dumpctl();
extern	void	dumpdata();
extern  void	sighuphdr();
extern  void	sigusr1hdr();

int goaround(void);

int	if_fd;		/* file descriptor for network interface name */
struct	pollfd llc_fd;	/* file descriptor for llc device */
FILE   *log_str = NULL;	/* file stream for log file */
char	ctlbuf[100];	/* control buffer for incoming frame */
char	databuf[2000];	/* data buffer for incoming frame */
char	debugmsg[MAXPATHLEN+200];	/* debug output message buffer */
struct	strbuf	ctl, data;	/* for use with getmsg() for incoming frame */
client_t *clntp = NULL;	/* pointer to the current client being served */
int	totclnt = 0;	/* total clients being served right now */
int	outblocked = 0;

int
main(int argc, char *argv[], char *envp[])
{
	time_t	t;

	/* program initialize */
	if (initialize(argc, argv, envp) < 0)
		exit(-1);

	/* start processing requests */
	if (debugLevel >= MSG_INFO_1) {
		t = time((time_t *)NULL);
		sprintf(debugmsg, "%s", ctime(&t));
		senddebug(MSG_INFO_1);
		sprintf(debugmsg, "Start listening to RPL requests ...\n");
		senddebug(MSG_INFO_1);
	}

	while (1) {
		if (service() < 0)
			exit(-1);
	}
}

int
service(void)
{
	int	flags;
	int	rc;
	int	n;

	if (outblocked)
		llc_fd.events = POLLIN | POLLOUT;
	else
		llc_fd.events = POLLIN;

	if (totclnt > 0)
		n = poll(&llc_fd, 1, 1);	/* 1 ms timeout */
	else
		n = poll(&llc_fd, 1, -1);	/* blocking poll */

	if (llc_fd.revents & POLLIN) {
		rc = incoming(llc_fd.fd);
		if (debugLevel >= MSG_ALWAYS) {
			sprintf(debugmsg, "incoming() returned\n");
			senddebug(MSG_ALWAYS);
		}
	}
	if (llc_fd.revents & POLLOUT)
		outblocked = 0;
	goaround();
	return (rc);
}


/*
 * This is the scheduler for all the outgoing traffic.  Go around the
 * circular linked list and only process and advance 1 in the list
 * and then return no matter whether anything is being sent out in
 * this step or not.
 */
int
goaround(void)
{
	if (totclnt == 0 || clntp == NULL)
		return (0);

	switch (clntp->status) {
	case ST_FIND_RCVD:
		sendFOUND(llc_fd.fd, clntp);
		break;
	case ST_DATA_XFER:
		sendFILE(llc_fd.fd, clntp);
		break;
	case ST_SEND_FINAL:
		sendFINAL(llc_fd.fd, clntp);
		break;
	case ST_FINISH:
		if ((--(clntp->delay)) == 0) {
			if ((time((time_t)0) - clntp->timeo) > REMOVETIMEOUT)
				clientremove(clntp);
			else
				clntp->delay = clntp->maxdelay;
		}
		break;
	}
	if (totclnt > 0 && clntp->next)
		clntp = clntp->next;

	return (0);
}

int
initialize(int argc, char *argv[], char *envp[])
{
	char	*cp;
	union	DL_primitives dl;
	struct sigaction sa;

	/*
	 * Parse command line, read appropriate config file and set up
	 * defaults
	 */
	if (parseargs(argc, argv, envp) < 0)
		return (-1);

	/*
	 * Here, if the -a option is specified, we are actually running in
	 * a child process with all the parameters stored in the set of
	 * global variables.
	 */

	/* daemonize it if running in background */
	if (backGround) {
		switch (fork()) {
		case -1:
			return (-1);
			break;
		case 0: /* child: close FD's and detach terminal */
			close(0);
			close(1);
			close(2);
			(void) open("/", O_RDONLY, 0);
			(void) dup2(0, 1);
			(void) dup2(0, 2);
			/*
			 * Detach terminal
			 */
			setsid();
			break;
		default: /* parent */
			exit(0);
			break;
		}
		if (setpgrp() < 0)
			return (-1);
		sa.sa_handler = SIG_IGN;
		sa.sa_flags = SA_RESTART;
		(void) sigemptyset(&sa.sa_mask);
		(void) sigaction(SIGHUP, &sa, NULL);
		if (fork() > 0)
			return (-1);
	}

	if (llcsetup() < 0)
		return (-1);

	clntp = (client_t *)NULL;
	totclnt = 0;

	sa.sa_handler = sighuphdr;
	sa.sa_flags = SA_RESTART;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sigusr1hdr;
	sa.sa_flags = SA_RESTART;
	(void) sigemptyset(&sa.sa_mask);
	(void) sigaction(SIGUSR1, &sa, NULL);

	return (0);
}
