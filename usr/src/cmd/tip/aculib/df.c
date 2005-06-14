/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 4.8 6/25/83 */

/*
 * Dial the DF02-AC or DF03-AC
 */

#include "tip.h"

static sigjmp_buf Sjbuf;
static void timeout();

df02_dialer(num, acu)
	char *num, *acu;
{

	return (df_dialer(num, acu, 0));
}

df03_dialer(num, acu)
	char *num, *acu;
{

	return (df_dialer(num, acu, 1));
}

df_dialer(num, acu, df03)
	char *num, *acu;
	int df03;
{
	register int f = FD;
	struct termios buf;
	int speed = 0;
	char c = '\0';

	ioctl(f, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	ioctl(f, TCSETS, &buf);
	if (sigsetjmp(Sjbuf, 1)) {
		printf("connection timed out\r\n");
		df_disconnect();
		return (0);
	}
	if (boolean(value(VERBOSE)))
		printf("\ndialing...");
	fflush(stdout);
#ifdef TIOCMSET
	if (df03) {
		int st = TIOCM_ST;	/* secondary Transmit flag */

		ioctl(f, TCGETS, &buf);
		if (cfgetospeed(&buf) != B1200) { /* must dial at 1200 baud */
			speed = cfgetospeed(&buf);
			cfsetospeed(&buf, B0);
			cfsetispeed(&buf, B0);
			cfsetospeed(&buf, B1200);
			ioctl(f, TCSETSW, &buf);
			ioctl(f, TIOCMBIC, &st); /* clear ST for 300 baud */
		} else
			ioctl(f, TIOCMBIS, &st); /* set ST for 1200 baud */
	}
#endif
	signal(SIGALRM, timeout);
	alarm(5 * strlen(num) + 10);
	ioctl(f, TCFLSH, TCOFLUSH);
	write(f, "\001", 1);
	sleep(1);
	write(f, "\002", 1);
	write(f, num, strlen(num));
	read(f, &c, 1);
#ifdef TIOCMSET
	if (df03 && speed) {
		cfsetospeed(&buf, B0);
		cfsetispeed(&buf, B0);
		cfsetospeed(&buf, speed);
		ioctl(f, TCSETSW, &buf);
	}
#endif
	return (c == 'A');
}

df_disconnect()
{

	write(FD, "\001", 1);
	sleep(1);
	ioctl(FD, TCFLSH, TCOFLUSH);
}


df_abort()
{

	df_disconnect();
}


static void
timeout()
{

	siglongjmp(Sjbuf, 1);
}
