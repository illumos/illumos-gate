/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"

static void sigALRM();
static sigjmp_buf timeoutbuf;

/*
 * Dial up on a Hayes Smart Modem 1200 or 2400
 */
int
hayes_dialer(num, acu)
	char *num, *acu;
{
	char code = 0, cr = 0;
	void (*f)();
	struct termios buf;

	f = signal(SIGALRM, sigALRM);

	if (!hayes_sync(FD)) {
		printf("can't synchronize with hayes\n");
#ifdef ACULOG
		logent(value(HOST), num, "hayes", "can't synch up");
#endif
		signal(SIGALRM, f);
		return (0);
	}
	if (boolean(value(VERBOSE)))
		printf("\ndialing...");
	fflush(stdout);
	ioctl(FD, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	ioctl(FD, TCSETS, &buf);
	ioctl(FD, TCFLSH, TCIOFLUSH);

	if (sigsetjmp(timeoutbuf, 1)) {
#ifdef ACULOG
		char line[80];

		sprintf(line, "%d second dial timeout",
			number(value(DIALTIMEOUT)));
		logent(value(HOST), num, "hayes", line);
#endif
		hayes_disconnect();
		signal(SIGALRM, f);
		return (0);
	}
	alarm(number(value(DIALTIMEOUT)));
	ioctl(FD, TCFLSH, TCIOFLUSH);
	if (*num == 'S')
		write(FD, "AT", 2);
	else
		write(FD, "ATDT", 4);	/* use tone dialing */
	write(FD, num, strlen(num));
	write(FD, "\r", 1);
	read(FD, &code, 1);
	read(FD, &cr, 1);
	if (code == '1' && cr == '0')
		read(FD, &cr, 1);
	alarm(0);
	signal(SIGALRM, f);
	if ((code == '1' || code == '5') && cr == '\r')
		return (1);
	return (0);
}

hayes_disconnect()
{
	close(FD);
}

hayes_abort()
{
	int dtr = TIOCM_DTR;

	alarm(0);
	ioctl(FD, TIOCMBIC, &dtr);
	sleep(2);
	ioctl(FD, TCFLSH, TCIOFLUSH);
	close(FD);
}

static void
sigALRM()
{
	siglongjmp(timeoutbuf, 1);
}

/*
 * This piece of code attempts to get the hayes in sync.
 */
static int
hayes_sync(fd)
{
	register int tries;
	char code = 0, cr = 0;
	int dtr = TIOCM_DTR;

	/*
	 * Toggle DTR to force anyone off that might have left
	 * the modem connected, and insure a consistent state
	 * to start from.
	 */
	ioctl(fd, TIOCMBIC, &dtr);
	sleep(1);
	ioctl(fd, TIOCMBIS, &dtr);
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
		write(fd, "ATV0Q0E0S0=1S2=255S12=255\r", 26);
		sleep(1);
		/* flush any echoes or return codes */
		ioctl(fd, TCFLSH, TCIOFLUSH);
		/* now see if the modem is talking to us properly */
		write(fd, "AT\r", 3);
		if (sigsetjmp(timeoutbuf, 1) == 0) {
			alarm(2);
			read(FD, &code, 1);
			read(FD, &cr, 1);
			if (code == '0' && cr == '\r')
				return (1);
		}
	}
	return (0);
}
