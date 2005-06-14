/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 4.5 6/25/83 */

/*
 * Routines for dialing up on Vadic 831
 */
#include <sys/time.h>

#include "tip.h"

int	v831_abort();
static	void alarmtr();
extern	errno;

static sigjmp_buf jmpbuf;
static int child = -1;

v831_dialer(num, acu)
	char *num, *acu;
{
	int status, pid, connected = 1;
	register int timelim;

	if (boolean(value(VERBOSE)))
		printf("\nstarting call...");
#ifdef DEBUG
	printf("(acu=%s)\n", acu);
#endif
	if ((AC = open(acu, O_RDWR)) < 0) {
		if (errno == EBUSY)
			printf("line busy...");
		else
			printf("acu open error...");
		return (0);
	}
	if (sigsetjmp(jmpbuf, 1)) {
		kill(child, SIGKILL);
		close(AC);
		return (0);
	}
	signal(SIGALRM, alarmtr);
	timelim = 5 * strlen(num);
	alarm(timelim < 30 ? 30 : timelim);
	if ((child = fork()) == 0) {
		/*
		 * ignore this stuff for aborts
		 */
		signal(SIGALRM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		sleep(2);
		exit(dialit(num, acu) != 'A');
	}
	/*
	 * open line - will return on carrier
	 */
	if ((FD = open(DV, O_RDWR)) < 0) {
#ifdef DEBUG
		printf("(after open, errno=%d)\n", errno);
#endif
		if (errno == EIO)
			printf("lost carrier...");
		else
			printf("dialup line open failed...");
		alarm(0);
		kill(child, SIGKILL);
		close(AC);
		return (0);
	}
	alarm(0);
	signal(SIGALRM, SIG_DFL);
	while ((pid = wait(&status)) != child && pid != -1)
		;
	if (status) {
		close(AC);
		return (0);
	}
	return (1);
}

static void
alarmtr()
{

	alarm(0);
	siglongjmp(jmpbuf, 1);
}

/*
 * Insurance, for some reason we don't seem to be
 *  hanging up...
 */
v831_disconnect()
{
	struct termios cntrl;
	int dtr = TIOCM_DTR;

	sleep(2);
#ifdef DEBUG
	printf("[disconnect: FD=%d]\n", FD);
#endif
	if (FD > 0) {
		ioctl(FD, TIOCMBIC, &dtr);
		ioctl(FD, TCGETS, &cntrl);
		cfsetospeed(&cntrl, B0);
		cntrl.c_cflag &= ~XCLUDE;
		ioctl(FD, TCSETSF, &cntrl);
	}
	close(FD);
}

v831_abort()
{
	int dtr = TIOCM_DTR;
	struct termios buf;

#ifdef DEBUG
	printf("[abort: AC=%d]\n", AC);
#endif
	sleep(2);
	if (child > 0)
		kill(child, SIGKILL);
	if (AC > 0) {
		ioctl(FD, TCGETS, &buf);
		buf.c_cflag &= ~XCLUDE;
		ioctl(FD, TCSETSF, &buf);
		close(AC);
	}
	if (FD > 0)
		ioctl(FD, TIOCMBIC, &dtr);
	close(FD);
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

#define	pc(x)	(c = x, write(AC, &c, 1))
#define	ABORT	01
#define	SI	017
#define	STX	02
#define	ETX	03

static
dialit(phonenum, acu)
	register char *phonenum;
	char *acu;
{
	register struct vaconfig *vp;
	struct termios cntrl;
	char c, *sanitize();
	int i;

	phonenum = sanitize(phonenum);
#ifdef DEBUG
	printf("(dial phonenum=%s)\n", phonenum);
#endif
	if (*phonenum == '<' && phonenum[1] == 0)
		return ('Z');
	for (vp = vaconfig; vp->vc_name; vp++)
		if (strcmp(vp->vc_name, acu) == 0)
			break;
	if (vp->vc_name == 0) {
		printf("Unable to locate dialer (%s)\n", acu);
		return ('K');
	}
	ioctl(AC, TCGETS, &cntrl);
	cfsetospeed(&cntrl, B0);
	cfsetispeed(&cntrl, B0);
	cntrl.c_cflag &= ~(CSIZE|PARENB|PARODD);
	cfsetospeed(&cntrl, B2400);
	cntrl.c_cflag |= CS8;
	cntrl.c_iflag &= IXOFF|IXANY;
	cntrl.c_lflag &= ~(ICANON|ISIG);
	cntrl.c_oflag = 0;
	cntrl.c_cc[VMIN] = cntrl.c_cc[VTIME] = 0;
	ioctl(AC, TCSETSF, &cntrl);
	ioctl(AC, TCFLSH, TCOFLUSH);
	pc(STX);
	pc(vp->vc_rack);
	pc(vp->vc_modem);
	while (*phonenum && *phonenum != '<')
		pc(*phonenum++);
	pc(SI);
	pc(ETX);
	sleep(1);
	i = read(AC, &c, 1);
#ifdef DEBUG
	printf("read %d chars, char=%c, errno %d\n", i, c, errno);
#endif
	if (i != 1)
		c = 'M';
	if (c == 'B' || c == 'G') {
		char cc, oc = c;

		pc(ABORT);
		read(AC, &cc, 1);
#ifdef DEBUG
		printf("abort response=%c\n", cc);
#endif
		c = oc;
		v831_disconnect();
	}
	close(AC);
#ifdef DEBUG
	printf("dialit: returns %c\n", c);
#endif
	return (c);
}

static char *
sanitize(s)
	register char *s;
{
	static char buf[128];
	register char *cp;

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
