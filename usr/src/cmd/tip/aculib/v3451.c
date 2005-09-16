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

/*
 * Routines for calling up on a Vadic 3451 Modem
 */
#include "tip.h"

static int	expect(char *);
static int	notin(char *, char *);
static int	prefix(char *, char *);
static void	vawrite(char *, int);
static void	alarmtr(void);

static sigjmp_buf	Sjbuf;

/* ARGSUSED */
int
v3451_dialer(char *num, char *acu)
{
	int ok;
	sig_handler_t	func;
	struct termios buf;
	int slow = number(value(BAUDRATE)) < 1200;
	char phone[50];
#ifdef ACULOG
	char line[80];
#endif

	/*
	 * Get in synch
	 */
	vawrite("I\r", 1 + slow);
	vawrite("I\r", 1 + slow);
	vawrite("I\r", 1 + slow);
	vawrite("\005\r", 2 + slow);
	if (!expect("READY")) {
		(void) printf("can't synchronize with vadic 3451\n");
#ifdef ACULOG
		logent(value(HOST), num, "vadic", "can't synch up");
#endif
		return (0);
	}
	(void) ioctl(FD, TCGETS, &buf);
	buf.c_cflag |= HUPCL;
	(void) ioctl(FD, TCSETSF, &buf);
	(void) sleep(1);
	vawrite("D\r", 2 + slow);
	if (!expect("NUMBER?")) {
		(void) printf("Vadic will not accept dial command\n");
#ifdef ACULOG
		logent(value(HOST), num, "vadic", "will not accept dial");
#endif
		return (0);
	}
	(void) strlcpy(phone, num, sizeof (phone));
	(void) strlcat(phone, "\r", sizeof (phone));
	vawrite(phone, 1 + slow);
	if (!expect(phone)) {
		(void) printf("Vadic will not accept phone number\n");
#ifdef ACULOG
		logent(value(HOST), num, "vadic", "will not accept number");
#endif
		return (0);
	}
	func = signal(SIGINT, SIG_IGN);
	/*
	 * You cannot interrupt the Vadic when its dialing;
	 * even dropping DTR does not work (definitely a
	 * brain damaged design).
	 */
	vawrite("\r", 1 + slow);
	vawrite("\r", 1 + slow);
	if (!expect("DIALING:")) {
		(void) printf("Vadic failed to dial\n");
#ifdef ACULOG
		logent(value(HOST), num, "vadic", "failed to dial");
#endif
		return (0);
	}
	if (boolean(value(VERBOSE)))
		(void) printf("\ndialing...");
	ok = expect("ON LINE");
	(void) signal(SIGINT, func);
	if (!ok) {
		(void) printf("call failed\n");
#ifdef ACULOG
		logent(value(HOST), num, "vadic", "call failed");
#endif
		return (0);
	}
	(void) ioctl(FD, TCFLSH, TCOFLUSH);
	return (1);
}

void
v3451_disconnect(void)
{

	(void) close(FD);
}

void
v3451_abort(void)
{

	(void) close(FD);
}

static void
vawrite(char *cp, int delay)
{

	for (; *cp; (void) sleep(delay), cp++)
		(void) write(FD, cp, 1);
}

static int
expect(char *cp)
{
	char buf[300];
	char *rp = buf;
	int timeout = 30, online = 0;

	if (strcmp(cp, "\"\"") == 0)
		return (1);
	*rp = 0;
	/*
	 * If we are waiting for the Vadic to complete
	 * dialing and get a connection, allow more time
	 * Unfortunately, the Vadic times out 24 seconds after
	 * the last digit is dialed
	 */
	online = strcmp(cp, "ON LINE") == 0;
	if (online)
		timeout = number(value(DIALTIMEOUT));
	(void) signal(SIGALRM, (sig_handler_t)alarmtr);
	if (sigsetjmp(Sjbuf, 1))
		return (0);
	(void) alarm(timeout);
	while (notin(cp, buf) && rp < buf + sizeof (buf) - 1) {
		if (online && notin("FAILED CALL", buf) == 0)
			return (0);
		if (read(FD, rp, 1) < 0) {
			(void) alarm(0);
			return (0);
		}
		if (*rp &= 0177)
			rp++;
		*rp = '\0';
	}
	(void) alarm(0);
	return (1);
}

static void
alarmtr(void)
{

	siglongjmp(Sjbuf, 1);
}

static int
notin(char *sh, char *lg)
{

	for (; *lg; lg++)
		if (prefix(sh, lg))
			return (0);
	return (1);
}

static int
prefix(char *s1, char *s2)
{
	char c;

	while ((c = *s1++) == *s2++)
		if (c == '\0')
			return (1);
	return (c == '\0');
}
