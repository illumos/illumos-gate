/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines for dialing up on DN-11
 */
#include "tip.h"

void	alarmtr(void);

static sigjmp_buf	jmpbuf;
static int	child = -1, dn;

int
dn_dialer(char *num, char *acu)
{
	int lt, nw;
	int timelim;
	struct termios buf;

	if (boolean(value(VERBOSE)))
		(void) printf("\nstarting call...");
	if ((dn = open(acu, 1)) < 0) {
		if (errno == EBUSY)
			(void) printf("line busy...");
		else
			(void) printf("acu open error...");
		return (0);
	}
	if (sigsetjmp(jmpbuf, 1)) {
		(void) kill(child, SIGKILL);
		(void) close(dn);
		return (0);
	}
	(void) signal(SIGALRM, (sig_handler_t)alarmtr);
	timelim = 5 * strlen(num);
	(void) alarm(timelim < 30 ? 30 : timelim);
	if ((child = fork()) == 0) {
		/*
		 * ignore this stuff for aborts
		 */
		(void) signal(SIGALRM, SIG_IGN);
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		(void) sleep(2);
		nw = write(dn, num, lt = strlen(num));
		exit(nw != lt);
	}
	/*
	 * open line - will return on carrier
	 */
	if ((FD = open(DV, 2)) < 0) {
		if (errno == EIO)
			(void) printf("lost carrier...");
		else
			(void) printf("dialup line open failed...");
		(void) alarm(0);
		(void) kill(child, SIGKILL);
		(void) close(dn);
		return (0);
	}
	(void) alarm(0);
	(void) ioctl(dn, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	(void) ioctl(dn, TCSETSF, &buf);
	(void) signal(SIGALRM, SIG_DFL);
	while ((nw = wait(&lt)) != child && nw != -1)
		;
	(void) fflush(stdout);
	(void) close(dn);
	if (lt != 0) {
		(void) close(FD);
		return (0);
	}
	return (1);
}

void
alarmtr(void)
{

	(void) alarm(0);
	siglongjmp(jmpbuf, 1);
}

/*
 * Insurance, for some reason we don't seem to be
 *  hanging up...
 */
void
dn_disconnect(void)
{
	int dtr = TIOCM_DTR;

	(void) sleep(2);
	if (FD > 0)
		(void) ioctl(FD, TIOCMBIC, &dtr);
	(void) close(FD);
}

void
dn_abort(void)
{
	int dtr = TIOCM_DTR;

	(void) sleep(2);
	if (child > 0)
		(void) kill(child, SIGKILL);
	if (dn > 0)
		(void) close(dn);
	if (FD > 0)
		(void) ioctl(FD, TIOCMBIC, &dtr);
	(void) close(FD);
}
