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

#include "tip.h"

static	sigjmp_buf deadline;
static	int deadfl;

void
dead(void)
{

	deadfl = 1;
	siglongjmp(deadline, 1);
}

int
hunt(char *name)
{
	char *cp;
	sig_handler_t	f;

	f = signal(SIGALRM, (sig_handler_t)dead);
	while (cp = getremote(name)) {
		deadfl = 0;
		uucplock = cp;
		if (tip_mlock(uucplock) < 0) {
			delock(uucplock);
			continue;
		}
		/*
		 * Straight through call units, such as the BIZCOMP,
		 * VADIC and the DF, must indicate they're hardwired in
		 *  order to get an open file descriptor placed in FD.
		 * Otherwise, as for a DN-11, the open will have to
		 *  be done in the "open" routine.
		 */
		if (!HW)
			break;
		if (sigsetjmp(deadline, 1) == 0) {
			(void) alarm(10);
			if (!trusted_device)
				userperm();
			errno = 0;
			if ((FD = open(cp, O_RDWR)) < 0 && errno != EBUSY) {
				(void) fprintf(stderr, "tip: ");
				perror(cp);
			}
			if (!trusted_device)
				myperm();
			if (FD >= 0 && !isatty(FD)) {
				(void) fprintf(stderr, "tip: %s: not a tty\n",
				    cp);
				(void) close(FD);
				FD = -1;
			}
		}
		(void) alarm(0);
		if (!deadfl && FD >= 0) {
			struct termios t;

			(void) ioctl(FD, TCGETS, &t);
			t.c_cflag |= XCLUDE|HUPCL;
			(void) ioctl(FD, TCSETSF, &t);
			(void) signal(SIGALRM, f);
			return ((int)cp);
		}
		delock(uucplock);
	}
	(void) signal(SIGALRM, f);
	return (deadfl ? -1 : (int)cp);
}
