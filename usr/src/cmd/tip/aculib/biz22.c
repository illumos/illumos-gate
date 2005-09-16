/*
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

#define	DISCONNECT_CMD	"\20\04"	/* disconnection string */

static void	sigALRM(void);
static int	cmd(char *);
static int	detect(char *);

static	int timeout = 0;
static	sigjmp_buf timeoutbuf;

void	biz22_disconnect(void);

/*
 * Dial up on a BIZCOMP Model 1022 with either
 * 	tone dialing (mod = "V")
 *	pulse dialing (mod = "W")
 */
static int
biz_dialer(char *num, char *mod)
{
	int connected = 0;
	char cbuf[40];

	if (boolean(value(VERBOSE)))
		(void) printf("\nstarting call...");
	/*
	 * Disable auto-answer and configure for tone/pulse
	 *  dialing
	 */
	if (cmd("\02K\r")) {
		(void) printf("can't initialize bizcomp...");
		return (0);
	}
	(void) strcpy(cbuf, "\02.\r");
	cbuf[1] = *mod;
	if (cmd(cbuf)) {
		(void) printf("can't set dialing mode...");
		return (0);
	}
	(void) strcpy(cbuf, "\02D");
	(void) strlcat(cbuf, num, sizeof (cbuf));
	(void) strlcat(cbuf, "\r", sizeof (cbuf));
	(void) write(FD, cbuf, strlen(cbuf));
	if (!detect("7\r")) {
		(void) printf("can't get dial tone...");
		return (0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("ringing...");
	/*
	 * The reply from the BIZCOMP should be:
	 *	2 \r or 7 \r	failure
	 *	1 \r		success
	 */
	connected = detect("1\r");
#ifdef ACULOG
	if (timeout) {
		char line[80];

		(void) sprintf(line, "%d second dial timeout",
		    number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "biz1022", line);
	}
#endif
	if (timeout)
		biz22_disconnect();	/* insurance */
	return (connected);
}

/* ARGSUSED */
int
biz22w_dialer(char *num, char *acu)
{

	return (biz_dialer(num, "W"));
}

/* ARGSUSED */
int
biz22f_dialer(char *num, char *acu)
{

	return (biz_dialer(num, "V"));
}

void
biz22_disconnect(void)
{

	(void) write(FD, DISCONNECT_CMD, 4);
	(void) sleep(2);
	(void) ioctl(FD, TCFLSH, TCOFLUSH);
}

void
biz22_abort(void)
{

	(void) write(FD, "\02", 1);
}

static void
sigALRM(void)
{

	timeout = 1;
	siglongjmp(timeoutbuf, 1);
}

static int
cmd(char *s)
{
	char c;
	sig_handler_t f;

	(void) write(FD, s, strlen(s));
	f = signal(SIGALRM, (sig_handler_t)sigALRM);
	if (sigsetjmp(timeoutbuf, 1)) {
		biz22_abort();
		(void) signal(SIGALRM, f);
		return (1);
	}
	(void) alarm(number(value(DIALTIMEOUT)));
	(void) read(FD, &c, 1);
	(void) alarm(0);
	(void) signal(SIGALRM, f);
	c &= 0177;
	return (c != '\r');
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
			biz22_abort();
			break;
		}
		(void) alarm(number(value(DIALTIMEOUT)));
		(void) read(FD, &c, 1);
		(void) alarm(0);
		c &= 0177;
		if (c != *s++)
			return (0);
	}
	(void) signal(SIGALRM, f);
	return (timeout == 0);
}
