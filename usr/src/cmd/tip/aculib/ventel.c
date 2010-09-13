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
 * Routines for calling up on a Ventel Modem
 * Define VENNOECHO if the Ventel is strapped for "no echo".
 */
#include "tip.h"

#define	MAXRETRY	5

static int	vensync(int);
static int	gobble(char);
static void	echo(char *);
static void	sigALRM(void);
static int	timeout = 0;
static sigjmp_buf	timeoutbuf;

void	ven_disconnect(void);

/* ARGSUSED */
int
ven_dialer(char *num, char *acu)
{
	char *cp;
	int connected = 0;
	struct termios buf;
#ifdef ACULOG
	char line[80];
#endif
	/*
	 * Get in synch with a couple of carriage returns
	 */
	if (!vensync(FD)) {
		(void) printf("can't synchronize with ventel\n");
#ifdef ACULOG
		logent(value(HOST), num, "ventel", "can't synch up");
#endif
		return (0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("\ndialing...");
	(void) fflush(stdout);
	(void) ioctl(FD, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	(void) ioctl(FD, TCSETSF, &buf);
#ifdef VENNOECHO
	echo("#k$\r$\n$D$I$A$L$:$ ");
	for (cp = num; *cp; cp++) {
		(void) sleep(1);
		(void) write(FD, cp, 1);
	}
	echo("\r$\n");
#else
	echo("k$\r$\n$D$I$A$L$:$ <");
	for (cp = num; *cp; cp++) {
		char c;

		(void) sleep(1);
		(void) write(FD, cp, 1);
		(void) read(FD, &c, 1);
	}
	echo(">\r$\n");
#endif
	if (gobble('\n'))
		connected = gobble('!');
	(void) ioctl(FD, TCFLSH, TCIOFLUSH);
#ifdef ACULOG
	if (timeout) {
		(void) sprintf(line, "%d second dial timeout",
		    number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "ventel", line);
	}
#endif
	if (timeout)
		ven_disconnect();	/* insurance */
	return (connected);
}

void
ven_disconnect(void)
{

	(void) close(FD);
}

void
ven_abort(void)
{

	(void) write(FD, "\03", 1);
	(void) close(FD);
}

static void
echo(char *s)
{
	char c;

	while (c = *s++) {
		switch (c) {
		case '$':
			(void) read(FD, &c, 1);
			s++;
			break;

		case '#':
			c = *s++;
			(void) write(FD, &c, 1);
			break;

		default:
			(void) write(FD, &c, 1);
			(void) read(FD, &c, 1);
		}
	}
}

static void
sigALRM(void)
{

	(void) printf("\07timeout waiting for reply\n");
	timeout = 1;
	siglongjmp(timeoutbuf, 1);
}

static int
gobble(char match)
{
	char c;
	sig_handler_t f;

	f = signal(SIGALRM, (sig_handler_t)sigALRM);
	timeout = 0;
	do {
		if (sigsetjmp(timeoutbuf, 1)) {
			(void) signal(SIGALRM, f);
			return (0);
		}
		(void) alarm(number(value(DIALTIMEOUT)));
		(void) read(FD, &c, 1);
		(void) alarm(0);
		c &= 0177;
#ifdef notdef
		if (boolean(value(VERBOSE)))
			(void) putchar(c);
#endif
	} while (c != '\n' && c != match);
	(void) signal(SIGALRM, SIG_DFL);
	return (c == match);
}

#define	min(a, b)	(((a) > (b)) ? (b) : (a))
/*
 * This convoluted piece of code attempts to get
 * the ventel in sync.  If you don't have FIONREAD
 * there are gory ways to simulate this.
 */
static int
vensync(int fd)
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
	(void) ioctl(FD, TIOCMBIC, &dtr);
	(void) sleep(2);
	(void) ioctl(FD, TIOCMBIS, &dtr);
	while (already < MAXRETRY) {
		/*
		 * After reseting the modem, send it two \r's to
		 * autobaud on. Make sure to delay between them
		 * so the modem can frame the incoming characters.
		 */
		(void) write(fd, "\r", 1);
#ifdef VMUNIX
		{
#include <sys/time.h>
		struct timeval tv = {0, 500000};

		(void) select(0, 0, 0, 0, &tv);
		}
#else
		(void) sleep(1);
#endif
		(void) write(fd, "\r", 1);
		(void) sleep(3);
		if (ioctl(fd, FIONREAD, (caddr_t)&nread) < 0) {
			perror("tip: ioctl");
			continue;
		}
		while (nread > 0) {
			(void) read(fd, buf, min(nread, 60));
			if ((buf[nread - 1] & 0177) == '$')
				return (1);
			nread -= min(nread, 60);
		}
		(void) sleep(1);
		already++;
	}
	return (0);
}
