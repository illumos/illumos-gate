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
 * Routines for dialing up on Vadic 831
 */
#include <sys/time.h>

#include "tip.h"

static char	dialit(char *, char *);
static char	*sanitize(char *);
static void	alarmtr(void);

static sigjmp_buf	jmpbuf;
static int	child = -1;

int
v831_dialer(char *num, char *acu)
{
	int status, pid;
	int timelim;

	if (boolean(value(VERBOSE)))
		(void) printf("\nstarting call...");
#ifdef DEBUG
	(void) printf("(acu=%s)\n", acu);
#endif
	if ((AC = open(acu, O_RDWR)) < 0) {
		if (errno == EBUSY)
			(void) printf("line busy...");
		else
			(void) printf("acu open error...");
		return (0);
	}
	if (sigsetjmp(jmpbuf, 1)) {
		(void) kill(child, SIGKILL);
		(void) close(AC);
		return (0);
	}
	(void) signal(SIGALRM, (sig_handler_t)alarmtr);
	timelim = 5 * strlen(num);
	(void) alarm(timelim < 30 ? 30 : timelim);
	if ((child = fork()) == 0) {
		/*
		 * ignore this stuff for aborts
		 */
		(void) signal(SIGALRM, SIG_IGN);
		(void) signal(SIGINT, SIG_IGN);
		(void) signal(SIGQUIT, SIG_IGN);
		(void) sleep(2);
		exit(dialit(num, acu) != 'A');
	}
	/*
	 * open line - will return on carrier
	 */
	if ((FD = open(DV, O_RDWR)) < 0) {
#ifdef DEBUG
		(void) printf("(after open, errno=%d)\n", errno);
#endif
		if (errno == EIO)
			(void) printf("lost carrier...");
		else
			(void) printf("dialup line open failed...");
		(void) alarm(0);
		(void) kill(child, SIGKILL);
		(void) close(AC);
		return (0);
	}
	(void) alarm(0);
	(void) signal(SIGALRM, SIG_DFL);
	while ((pid = wait(&status)) != child && pid != -1)
		;
	if (status) {
		(void) close(AC);
		return (0);
	}
	return (1);
}

static void
alarmtr(void)
{

	(void) alarm(0);
	siglongjmp(jmpbuf, 1);
}

/*
 * Insurance, for some reason we don't seem to be
 *  hanging up...
 */
void
v831_disconnect(void)
{
	struct termios cntrl;
	int dtr = TIOCM_DTR;

	(void) sleep(2);
#ifdef DEBUG
	printf("[disconnect: FD=%d]\n", FD);
#endif
	if (FD > 0) {
		(void) ioctl(FD, TIOCMBIC, &dtr);
		(void) ioctl(FD, TCGETS, &cntrl);
		(void) cfsetospeed(&cntrl, B0);
		cntrl.c_cflag &= ~XCLUDE;
		(void) ioctl(FD, TCSETSF, &cntrl);
	}
	(void) close(FD);
}

void
v831_abort(void)
{
	int dtr = TIOCM_DTR;
	struct termios buf;

#ifdef DEBUG
	(void) printf("[abort: AC=%d]\n", AC);
#endif
	(void) sleep(2);
	if (child > 0)
		(void) kill(child, SIGKILL);
	if (AC > 0) {
		(void) ioctl(FD, TCGETS, &buf);
		buf.c_cflag &= ~XCLUDE;
		(void) ioctl(FD, TCSETSF, &buf);
		(void) close(AC);
	}
	if (FD > 0)
		(void) ioctl(FD, TIOCMBIC, &dtr);
	(void) close(FD);
}

/*
 * Sigh, this probably must be changed at each site.
 */
struct vaconfig {
	char	*vc_name;
	char	vc_rack;
	char	vc_modem;
} vaconfig[] = {
	{ "/dev/cua0", '4', '0' },
	{ "/dev/cua1", '4', '1' },
	{ 0 }
};

#define	pc(x)	(c = x, (void) write(AC, &c, 1))
#define	ABORT	01
#define	SI	017
#define	STX	02
#define	ETX	03

static char
dialit(char *phonenum, char *acu)
{
	struct vaconfig *vp;
	struct termios cntrl;
	char c;
	int i;

	phonenum = sanitize(phonenum);
#ifdef DEBUG
	(void) printf("(dial phonenum=%s)\n", phonenum);
#endif
	if (*phonenum == '<' && phonenum[1] == 0)
		return ('Z');
	for (vp = vaconfig; vp->vc_name; vp++)
		if (strcmp(vp->vc_name, acu) == 0)
			break;
	if (vp->vc_name == 0) {
		(void) printf("Unable to locate dialer (%s)\n", acu);
		return ('K');
	}
	(void) ioctl(AC, TCGETS, &cntrl);
	(void) cfsetospeed(&cntrl, B0);
	(void) cfsetispeed(&cntrl, B0);
	cntrl.c_cflag &= ~(CSIZE|PARENB|PARODD);
	(void) cfsetospeed(&cntrl, B2400);
	cntrl.c_cflag |= CS8;
	cntrl.c_iflag &= IXOFF|IXANY;
	cntrl.c_lflag &= ~(ICANON|ISIG);
	cntrl.c_oflag = 0;
	cntrl.c_cc[VMIN] = cntrl.c_cc[VTIME] = 0;
	(void) ioctl(AC, TCSETSF, &cntrl);
	(void) ioctl(AC, TCFLSH, TCOFLUSH);
	pc(STX);
	pc(vp->vc_rack);
	pc(vp->vc_modem);
	while (*phonenum && *phonenum != '<')
		pc(*phonenum++);
	pc(SI);
	pc(ETX);
	(void) sleep(1);
	i = read(AC, &c, 1);
#ifdef DEBUG
	printf("read %d chars, char=%c, errno %d\n", i, c, errno);
#endif
	if (i != 1)
		c = 'M';
	if (c == 'B' || c == 'G') {
		char cc, oc = c;

		pc(ABORT);
		(void) read(AC, &cc, 1);
#ifdef DEBUG
		(void) printf("abort response=%c\n", cc);
#endif
		c = oc;
		v831_disconnect();
	}
	(void) close(AC);
#ifdef DEBUG
	(void) printf("dialit: returns %c\n", c);
#endif
	return (c);
}

static char *
sanitize(char *s)
{
	static char buf[128];
	char *cp;

	for (cp = buf; *s; s++) {
		if (!isdigit(*s) && *s == '<' && *s != '_')
			continue;
		if (*s == '_')
			*s = '=';
		*cp++ = *s;
	}
	*cp++ = 0;
	return (buf);
}
