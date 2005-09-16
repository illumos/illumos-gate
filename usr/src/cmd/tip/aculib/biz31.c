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

#define	MAXRETRY	3		/* sync up retry count */
#define	DISCONNECT_CMD	"\21\25\11\24"	/* disconnection string */

static int	detect(char *);
static int	bizsync(int);
static void	echo(char *);
static void	flush(char *);
static void	sigALRM(void);
static int	timeout = 0;
static sigjmp_buf	timeoutbuf;

void	biz31_disconnect(void);

/*
 * Dial up on a BIZCOMP Model 1031 with either
 * 	tone dialing (mod = "f")
 *	pulse dialing (mod = "w")
 */
static int
biz_dialer(char *num, char *mod)
{
	int connected = 0;

	if (!bizsync(FD)) {
		logent(value(HOST), "", "biz", "out of sync");
		(void) printf("bizcomp out of sync\n");
		delock(uucplock);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("\nstarting call...");
	echo("#\rk$\r$\n");			/* disable auto-answer */
	echo("$>$.$ #\r");			/* tone/pulse dialing */
	echo(mod);
	echo("$\r$\n");
	echo("$>$.$ #\re$ ");			/* disconnection sequence */
	echo(DISCONNECT_CMD);
	echo("\r$\n$\r$\n");
	echo("$>$.$ #\rr$ ");			/* repeat dial */
	echo(num);
	echo("\r$\n");
	if (boolean(value(VERBOSE)))
		(void) printf("ringing...");
	/*
	 * The reply from the BIZCOMP should be:
	 *	`^G NO CONNECTION\r\n^G\r\n'	failure
	 *	` CONNECTION\r\n^G'		success
	 */
	connected = detect(" ");
#ifdef ACULOG
	if (timeout) {
		char line[80];

		(void) sprintf(line, "%d second dial timeout",
		    number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "biz", line);
	}
#endif
	if (!connected)
		flush(" NO CONNECTION\r\n\07\r\n");
	else
		flush("CONNECTION\r\n\07");
	if (timeout)
		biz31_disconnect();	/* insurance */
	return (connected);
}

/* ARGSUSED */
int
biz31w_dialer(char *num, char *acu)
{

	return (biz_dialer(num, "w"));
}

/* ARGSUSED */
int
biz31f_dialer(char *num, char *acu)
{

	return (biz_dialer(num, "f"));
}

void
biz31_disconnect(void)
{

	(void) write(FD, DISCONNECT_CMD, 4);
	(void) sleep(2);
	(void) ioctl(FD, TCFLSH, TCOFLUSH);
}

void
biz31_abort(void)
{

	(void) write(FD, "\33", 1);
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

	timeout = 1;
	siglongjmp(timeoutbuf, 1);
}

static int
detect(char *s)
{
	char c;
	sig_handler_t f;

	f = signal(SIGALRM, (sig_handler_t)sigALRM);
	timeout = 0;
	while (*s) {
		if (sigsetjmp(timeoutbuf, 1)) {
			(void) printf("\07timeout waiting for reply\n");
			biz31_abort();
			break;
		}
		(void) alarm(number(value(DIALTIMEOUT)));
		(void) read(FD, &c, 1);
		(void) alarm(0);
		if (c != *s++)
			break;
	}
	(void) signal(SIGALRM, f);
	return (timeout == 0);
}

static void
flush(char *s)
{
	char c;
	sig_handler_t f;

	f = signal(SIGALRM, (sig_handler_t)sigALRM);
	while (*s++) {
		if (sigsetjmp(timeoutbuf, 1))
			break;
		(void) alarm(10);
		(void) read(FD, &c, 1);
		(void) alarm(0);
	}
	(void) signal(SIGALRM, f);
	timeout = 0;			/* guard against disconnection */
}

/*
 * This convoluted piece of code attempts to get
 *  the bizcomp in sync.  If you don't have the capacity or nread
 *  call there are gory ways to simulate this.
 */
static int
bizsync(int fd)
{
#ifdef FIOCAPACITY
	struct capacity b;
#define	chars(b)	((b).cp_nbytes)
#define	IOCTL	FIOCAPACITY
#endif
#ifdef FIONREAD
	long b;
#define	chars(b)	(b)
#define	IOCTL	FIONREAD
#endif
	int already = 0;
	char buf[10];

retry:
	if (ioctl(fd, IOCTL, (caddr_t)&b) >= 0 && chars(b) > 0)
		(void) ioctl(fd, TCFLSH, TCIOFLUSH);
	(void) write(fd, "\rp>\r", 4);
	(void) sleep(1);
	if (ioctl(fd, IOCTL, (caddr_t)&b) >= 0) {
		if (chars(b) != 10) {
	nono:
			if (already > MAXRETRY)
				return (0);
			(void) write(fd, DISCONNECT_CMD, 4);
			(void) sleep(2);
			already++;
			goto retry;
		} else {
			(void) read(fd, buf, 10);
			if (strncmp(buf, "p >\r\n\r\n>", 8))
				goto nono;
		}
	}
	return (1);
}
