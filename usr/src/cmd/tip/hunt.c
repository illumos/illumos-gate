/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 4.7 6/25/83 */

#include "tip.h"

extern char *getremote();
extern int errno;

static	sigjmp_buf deadline;
static	int deadfl;

void
dead()
{

	deadfl = 1;
	siglongjmp(deadline, 1);
}

hunt(name)
	char *name;
{
	register char *cp;
	void (*f)();

	f = signal(SIGALRM, (sig_handler_t)dead);
	while (cp = getremote(name)) {
		deadfl = 0;
		uucplock = cp;
		if (mlock(uucplock) < 0) {
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
			alarm(10);
			if (!trusted_device)
				userperm();
			errno = 0;
			if ((FD = open(cp, O_RDWR)) < 0 && errno != EBUSY) {
				fprintf(stderr, "tip: ");
				perror(cp);
			}
			if (!trusted_device)
				myperm();
			if (FD >= 0 && !isatty(FD)) {
				fprintf(stderr, "tip: %s: not a tty\n", cp);
				close(FD);
				FD = -1;
			}
		}
		alarm(0);
		if (!deadfl && FD >= 0) {
			struct termios t;

			ioctl(FD, TCGETS, &t);
			t.c_cflag |= XCLUDE|HUPCL;
			ioctl(FD, TCSETSF, &t);
			signal(SIGALRM, f);
			return ((int)cp);
		}
		delock(uucplock);
	}
	signal(SIGALRM, f);
	return (deadfl ? -1 : (int)cp);
}
