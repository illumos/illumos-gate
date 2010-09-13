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

static int	hayes_sync(int);
static void	sigALRM(void);
static sigjmp_buf	timeoutbuf;

void	hayes_disconnect(void);

/*
 * Dial up on a Hayes Smart Modem 1200 or 2400
 */
/* ARGSUSED */
int
hayes_dialer(char *num, char *acu)
{
	char code = 0, cr = 0;
	sig_handler_t	f;
	struct termios buf;

	f = signal(SIGALRM, (sig_handler_t)sigALRM);

	if (!hayes_sync(FD)) {
		(void) printf("can't synchronize with hayes\n");
#ifdef ACULOG
		logent(value(HOST), num, "hayes", "can't synch up");
#endif
		(void) signal(SIGALRM, f);
		return (0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("\ndialing...");
	(void) fflush(stdout);
	(void) ioctl(FD, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	(void) ioctl(FD, TCSETS, &buf);
	(void) ioctl(FD, TCFLSH, TCIOFLUSH);

	if (sigsetjmp(timeoutbuf, 1)) {
#ifdef ACULOG
		char line[80];

		(void) sprintf(line, "%d second dial timeout",
		    number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "hayes", line);
#endif
		hayes_disconnect();
		(void) signal(SIGALRM, f);
		return (0);
	}
	(void) alarm(number(value(DIALTIMEOUT)));
	(void) ioctl(FD, TCFLSH, TCIOFLUSH);
	if (*num == 'S')
		(void) write(FD, "AT", 2);
	else
		(void) write(FD, "ATDT", 4);	/* use tone dialing */
	(void) write(FD, num, strlen(num));
	(void) write(FD, "\r", 1);
	(void) read(FD, &code, 1);
	(void) read(FD, &cr, 1);
	if (code == '1' && cr == '0')
		(void) read(FD, &cr, 1);
	(void) alarm(0);
	(void) signal(SIGALRM, f);
	if ((code == '1' || code == '5') && cr == '\r')
		return (1);
	return (0);
}

void
hayes_disconnect(void)
{
	(void) close(FD);
}

void
hayes_abort(void)
{
	int dtr = TIOCM_DTR;

	(void) alarm(0);
	(void) ioctl(FD, TIOCMBIC, &dtr);
	(void) sleep(2);
	(void) ioctl(FD, TCFLSH, TCIOFLUSH);
	(void) close(FD);
}

static void
sigALRM(void)
{
	siglongjmp(timeoutbuf, 1);
}

/*
 * This piece of code attempts to get the hayes in sync.
 */
static int
hayes_sync(int fd)
{
	int tries;
	char code = 0, cr = 0;
	int dtr = TIOCM_DTR;

	/*
	 * Toggle DTR to force anyone off that might have left
	 * the modem connected, and insure a consistent state
	 * to start from.
	 */
	(void) ioctl(fd, TIOCMBIC, &dtr);
	(void) sleep(1);
	(void) ioctl(fd, TIOCMBIS, &dtr);
	for (tries = 0; tries < 3; tries++) {
		/*
		 * After reseting the modem, initialize all
		 * parameters to required vaules:
		 *
		 *	V0	- result codes are single digits
		 *	Q0	- result codes ARE sent
		 *	E0	- do not echo
		 *	S0=1	- automatically answer phone
		 *	S2=255	- disable escape character
		 *	S12=255	- longest possible escape guard time
		 */
		(void) write(fd, "ATV0Q0E0S0=1S2=255S12=255\r", 26);
		(void) sleep(1);
		/* flush any echoes or return codes */
		(void) ioctl(fd, TCFLSH, TCIOFLUSH);
		/* now see if the modem is talking to us properly */
		(void) write(fd, "AT\r", 3);
		if (sigsetjmp(timeoutbuf, 1) == 0) {
			(void) alarm(2);
			(void) read(FD, &code, 1);
			(void) read(FD, &cr, 1);
			if (code == '0' && cr == '\r')
				return (1);
		}
	}
	return (0);
}
