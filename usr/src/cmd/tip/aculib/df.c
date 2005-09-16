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
 * Dial the DF02-AC or DF03-AC
 */

#include "tip.h"

static sigjmp_buf	Sjbuf;
static void	timeout(void);

void	df_disconnect(void);
int	df_dialer(char *, char *, int);

int
df02_dialer(char *num, char *acu)
{

	return (df_dialer(num, acu, 0));
}

int
df03_dialer(char *num, char *acu)
{

	return (df_dialer(num, acu, 1));
}

/* ARGSUSED */
int
df_dialer(char *num, char *acu, int df03)
{
	int f = FD;
	struct termios buf;
	int speed = 0;
	char c = '\0';

	(void) ioctl(f, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	(void) ioctl(f, TCSETS, &buf);
	if (sigsetjmp(Sjbuf, 1)) {
		(void) printf("connection timed out\r\n");
		df_disconnect();
		return (0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("\ndialing...");
	(void) fflush(stdout);
#ifdef TIOCMSET
	if (df03) {
		int st = TIOCM_ST;	/* secondary Transmit flag */

		(void) ioctl(f, TCGETS, &buf);
		if (cfgetospeed(&buf) != B1200) { /* must dial at 1200 baud */
			speed = cfgetospeed(&buf);
			(void) cfsetospeed(&buf, B0);
			(void) cfsetispeed(&buf, B0);
			(void) cfsetospeed(&buf, B1200);
			(void) ioctl(f, TCSETSW, &buf);
			/* clear ST for 300 baud */
			(void) ioctl(f, TIOCMBIC, &st);
		} else
			/* set ST for 1200 baud */
			(void) ioctl(f, TIOCMBIS, &st);
	}
#endif
	(void) signal(SIGALRM, (sig_handler_t)timeout);
	(void) alarm(5 * strlen(num) + 10);
	(void) ioctl(f, TCFLSH, TCOFLUSH);
	(void) write(f, "\001", 1);
	(void) sleep(1);
	(void) write(f, "\002", 1);
	(void) write(f, num, strlen(num));
	(void) read(f, &c, 1);
#ifdef TIOCMSET
	if (df03 && speed) {
		(void) cfsetospeed(&buf, B0);
		(void) cfsetispeed(&buf, B0);
		(void) cfsetospeed(&buf, speed);
		(void) ioctl(f, TCSETSW, &buf);
	}
#endif
	return (c == 'A');
}

void
df_disconnect(void)
{

	(void) write(FD, "\001", 1);
	(void) sleep(1);
	(void) ioctl(FD, TCFLSH, TCOFLUSH);
}

void
df_abort(void)
{

	df_disconnect();
}


static void
timeout(void)
{

	siglongjmp(Sjbuf, 1);
}
