/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 1.5 6/25/83 */

/*
 * Routines for calling up on a Ventel Modem
 * Define VENNOECHO if the Ventel is strapped for "no echo".
 */
#include "tip.h"

#define	MAXRETRY	5

static	void sigALRM();
static	int timeout = 0;
static	sigjmp_buf timeoutbuf;

ven_dialer(num, acu)
	register char *num;
	char *acu;
{
	register char *cp;
	register int connected = 0;
	struct termios buf;
#ifdef ACULOG
	char line[80];
#endif
	/*
	 * Get in synch with a couple of carriage returns
	 */
	if (!vensync(FD)) {
		printf("can't synchronize with ventel\n");
#ifdef ACULOG
		logent(value(HOST), num, "ventel", "can't synch up");
#endif
		return (0);
	}
	if (boolean(value(VERBOSE)))
		printf("\ndialing...");
	fflush(stdout);
	ioctl(FD, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	ioctl(FD, TCSETSF, &buf);
#ifdef VENNOECHO
	echo("#k$\r$\n$D$I$A$L$:$ ");
	for (cp = num; *cp; cp++) {
		sleep(1);
		write(FD, cp, 1);
	}
	echo("\r$\n");
#else
	echo("k$\r$\n$D$I$A$L$:$ <");
	for (cp = num; *cp; cp++) {
		char c;

		sleep(1);
		write(FD, cp, 1);
		read(FD, &c, 1);
	}
	echo(">\r$\n");
#endif
	if (gobble('\n'))
		connected = gobble('!');
	ioctl(FD, TCFLSH, TCIOFLUSH);
#ifdef ACULOG
	if (timeout) {
		sprintf(line, "%d second dial timeout",
			number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "ventel", line);
	}
#endif
	if (timeout)
		ven_disconnect();	/* insurance */
	return (connected);
}

ven_disconnect()
{

	close(FD);
}

ven_abort()
{

	write(FD, "\03", 1);
	close(FD);
}

static int
echo(s)
	register char *s;
{
	char c;

	while (c = *s++) {
		switch (c) {
		case '$':
			read(FD, &c, 1);
			s++;
			break;

		case '#':
			c = *s++;
			write(FD, &c, 1);
			break;

		default:
			write(FD, &c, 1);
			read(FD, &c, 1);
		}
	}
}

static void
sigALRM()
{

	printf("\07timeout waiting for reply\n");
	timeout = 1;
	siglongjmp(timeoutbuf, 1);
}

static int
gobble(match)
	register char match;
{
	char c;
	sig_handler_t f;

	f = signal(SIGALRM, (sig_handler_t)sigALRM);
	timeout = 0;
	do {
		if (sigsetjmp(timeoutbuf, 1)) {
			signal(SIGALRM, f);
			return (0);
		}
		alarm(number(value(DIALTIMEOUT)));
		read(FD, &c, 1);
		alarm(0);
		c &= 0177;
#ifdef notdef
		if (boolean(value(VERBOSE)))
			putchar(c);
#endif
	} while (c != '\n' && c != match);
	signal(SIGALRM, SIG_DFL);
	return (c == match);
}

#define	min(a, b)	(((a) > (b)) ? (b) : (a))
/*
 * This convoluted piece of code attempts to get
 * the ventel in sync.  If you don't have FIONREAD
 * there are gory ways to simulate this.
 */
static int
vensync(fd)
{
	int already = 0, nread;
	char buf[60];
	int dtr = TIOCM_DTR;

	/*
	 * Toggle DTR to force anyone off that might have left
	 * the modem connected, and insure a consistent state
	 * to start from.
	 *
	 * If you don't have the ioctl calls to diddle directly
	 * with DTR, you can always try setting the baud rate to 0.
	 */
	ioctl(FD, TIOCMBIC, &dtr);
	sleep(2);
	ioctl(FD, TIOCMBIS, &dtr);
	while (already < MAXRETRY) {
		/*
		 * After reseting the modem, send it two \r's to
		 * autobaud on. Make sure to delay between them
		 * so the modem can frame the incoming characters.
		 */
		write(fd, "\r", 1);
#ifdef VMUNIX
		{
#include <sys/time.h>
		struct timeval tv = {0, 500000};

		select(0, 0, 0, 0, &tv);
		}
#else
		sleep(1);
#endif
		write(fd, "\r", 1);
		sleep(3);
		if (ioctl(fd, FIONREAD, (caddr_t)&nread) < 0) {
			perror("tip: ioctl");
			continue;
		}
		while (nread > 0) {
			read(fd, buf, min(nread, 60));
			if ((buf[nread - 1] & 0177) == '$')
				return (1);
			nread -= min(nread, 60);
		}
		sleep(1);
		already++;
	}
	return (0);
}
