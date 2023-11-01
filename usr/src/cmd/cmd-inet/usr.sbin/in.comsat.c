/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted provided
 * that: (1) source distributions retain this entire copyright notice and
 * comment, and (2) distributions including binaries display the following
 * acknowledgement: ``This product includes software developed by the
 * University of California, Berkeley and its contributors'' in the
 * documentation or other materials provided with the distribution and in
 * all advertising materials mentioning features or use of this software.
 * Neither the name of the University nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>

#include <netinet/in.h>

#include <stdio.h>
#include <sys/ttold.h>
#include <utmpx.h>
#include <signal.h>
#include <errno.h>
#include <sys/param.h>	/* for MAXHOSTNAMELEN */
#include <netdb.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <pwd.h>

/*
 * comsat
 */


#ifndef UTMPX_FILE
#define	UTMPX_FILE "/etc/utmpx"
#endif	/* UTMPX_FILE */

int	debug = 0;
#define	dsyslog	if (debug) syslog

struct	sockaddr_in sin = { AF_INET };

char	hostname[MAXHOSTNAMELEN];
struct	utmpx *utmp = NULL;
int	nutmp;
int	uf;
unsigned utmpmtime = 0;			/* last modification time for utmp */
unsigned utmpsize = 0;			/* last malloced size for utmp */
time_t	lastmsgtime;

#ifndef SYSV
int	reapchildren();
#else

#define	rindex strrchr
#define	index strchr
#define	signal(s, f)	sigset((s), (f))

#ifndef sigmask
#define	sigmask(m)	(1 << ((m)-1))
#endif

#define	set2mask(setp)	((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : (((setp)->__sigbits[0]) = (mask)))

static int
sigsetmask(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
	return (set2mask(&oset));
}

static int
sigblock(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);
	return (set2mask(&oset));
}

#endif /* SYSV */


#define	MAXIDLE	120
#define	NAMLEN (sizeof (uts[0].ut_name) + 1)

void jkfprintf(FILE *tp, char *name, int mbox, int offset);
void mailfor(char *name);
void notify(struct utmpx *utp, int offset);
void onalrm(int sig);

int
main(int argc, char *argv[])
{
	int cc;
	char buf[BUFSIZ];
	char msgbuf[100];
	struct sockaddr_in from;
	socklen_t fromlen;
	int c;
	extern int optind;
	extern int getopt();
	extern char *optarg;

	openlog("comsat", 0, LOG_DAEMON);

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch ((char)c) {
		case'd':
			debug++;
			break;
		default:
			syslog(LOG_ERR, "invalid argument %s", argv[optind]);
			exit(1);
		}
	}

	/* verify proper invocation */
	fromlen = (socklen_t)sizeof (from);
	if (getsockname(0, (struct sockaddr *)&from, &fromlen) < 0) {
		fprintf(stderr, "%s: ", argv[0]);
		perror("getsockname");
		_exit(1);
	}

#ifdef SYSV
	chdir("/var/mail");
#else
	chdir("/var/spool/mail");
#endif /* SYSV */
	if ((uf = open(UTMPX_FILE, 0)) < 0) {
		syslog(LOG_ERR, "%s: %m", UTMPX_FILE);
		(void) recv(0, msgbuf, sizeof (msgbuf) - 1, 0);
		exit(1);
	}
	(void) time(&lastmsgtime);
	(void) gethostname(hostname, sizeof (hostname));
	onalrm(0);
	(void) signal(SIGALRM, onalrm);
	(void) signal(SIGTTOU, SIG_IGN);
#ifndef SYSV
	(void) signal(SIGCHLD, reapchildren);
#else
	(void) signal(SIGCHLD, SIG_IGN); /* no zombies */
#endif /* SYSV */
	for (;;) {
		cc = recv(0, msgbuf, sizeof (msgbuf) - 1, 0);
		if (cc <= 0) {
			if (errno != EINTR)
				sleep(1);
			errno = 0;
			continue;
		}
		if (nutmp == 0)			/* no users (yet) */
			continue;
		sigblock(sigmask(SIGALRM));
		msgbuf[cc] = 0;
		(void) time(&lastmsgtime);
		mailfor(msgbuf);
		sigsetmask(0);
	}
}

#ifndef SYSV
reapchildren()
{

	while (wait3((struct wait *)0, WNOHANG, (struct rusage *)0) > 0)
		;
}
#endif /* SYSV */

/* ARGSUSED */
void
onalrm(int sig)
{
	struct stat statbf;
	time_t now;

	(void) time(&now);
	if ((ulong_t)now - (ulong_t)lastmsgtime >= MAXIDLE)
		exit(0);
	dsyslog(LOG_DEBUG, "alarm\n");
	alarm(15);
	fstat(uf, &statbf);
	if (statbf.st_mtime > utmpmtime) {
		dsyslog(LOG_DEBUG, " changed\n");
		utmpmtime = statbf.st_mtime;
		if (statbf.st_size > utmpsize) {
			utmpsize = statbf.st_size + 10 * sizeof (struct utmpx);
			if (utmp)
				utmp = (struct utmpx *)realloc(utmp, utmpsize);
			else
				utmp = (struct utmpx *)malloc(utmpsize);
			if (! utmp) {
				dsyslog(LOG_DEBUG, "malloc failed\n");
				exit(1);
			}
		}
		lseek(uf, 0, 0);
		nutmp = read(uf, utmp, statbf.st_size)/sizeof (struct utmpx);
	} else
		dsyslog(LOG_DEBUG, " ok\n");
}

void
mailfor(char *name)
{
	struct utmpx *utp = &utmp[nutmp];
	char *cp;
	char *rindex();
	int offset;

	/*
	 * Don't bother doing anything if nobody is
	 * logged into the system.
	 */
	if (utmp == NULL || nutmp == 0)
		return;
	dsyslog(LOG_DEBUG, "mailfor %s\n", name);
	cp = name;
	while (*cp && *cp != '@')
		cp++;
	if (*cp == 0) {
		dsyslog(LOG_DEBUG, "bad format\n");
		return;
	}
	*cp = 0;
	offset = atoi(cp+1);
	while (--utp >= utmp)
		if (utp->ut_type == USER_PROCESS &&
		    strncmp(utp->ut_name, name, sizeof (utmp[0].ut_name)) == 0)
			notify(utp, offset);
}

char	*cr;

void
notify(struct utmpx *utp, int offset)
{
	FILE *tp;
	struct sgttyb gttybuf;
	char tty[sizeof (utmp[0].ut_line) + 5];
	char name[sizeof (utmp[0].ut_name) + 1];
	struct stat stb, stl;
	time_t timep[2];
	struct passwd *pwd;
	int fd, mbox;


	strcpy(tty, "/dev/");
	strncat(tty, utp->ut_line, sizeof (utp->ut_line));
	dsyslog(LOG_DEBUG, "notify %s on %s\n", utp->ut_name, tty);
	if (stat(tty, &stb) == -1) {
		dsyslog(LOG_DEBUG, "can't stat tty\n");
		return;
	}
	if ((stb.st_mode & 0100) == 0) {
		dsyslog(LOG_DEBUG, "wrong mode\n");
		return;
	}
	if (fork())
		return;
	signal(SIGALRM, SIG_DFL);
	alarm(30);

	strncpy(name, utp->ut_name, sizeof (utp->ut_name));
	name[sizeof (name) - 1] = '\0';

	/*
	 * Do all operations that check protections as the user who
	 * will be getting the biff.
	 */
	if ((pwd = getpwnam(name)) == (struct passwd *)-1) {
		dsyslog(LOG_DEBUG, "getpwnam failed\n");
		exit(1);
	}
	if (setuid(pwd->pw_uid) == -1) {
		dsyslog(LOG_DEBUG, "setuid failed\n");
		exit(1);
	}

	/*
	 * We need to make sure that the tty listed in the utmp
	 * file really is a tty device so that a corrupted utmp
	 * file doesn't cause us to over-write a real file.
	 */
	if ((fd = open(tty, O_RDWR)) == -1) {
		dsyslog(LOG_DEBUG, "can't open tty");
		exit(1);
	}
	if (isatty(fd) == 0) {
		dsyslog(LOG_DEBUG, "line listed in utmp file is not a tty\n");
		exit(1);
	}

	/*
	 * For the case where the user getting the biff is root,
	 * we need to make sure that the tty we will be sending
	 * the biff to is also owned by root.
	 *
	 * Check after open, to prevent race on open.
	 */

	if (fstat(fd, &stb) != 0 || stb.st_uid != pwd->pw_uid) {
		dsyslog(LOG_DEBUG,
		    "tty is not owned by user getting the biff\n");
		exit(1);
	}

	/*
	 * Prevent race by doing fdopen on fd, not fopen
	 * Fopen opens w/ O_CREAT, which is dangerous too
	 */
	if ((tp = fdopen(fd, "w")) == 0) {
		dsyslog(LOG_DEBUG, "fdopen failed\n");
		exit(-1);
	}

	if (ioctl(fd, TIOCGETP, &gttybuf) == -1) {
		dsyslog(LOG_DEBUG, "ioctl TIOCGETP failed\n");
		exit(1);
	}
	cr = (gttybuf.sg_flags&CRMOD) && !(gttybuf.sg_flags&RAW) ? "" : "\r";
	fprintf(tp, "%s\n\007New mail for %s@%.*s\007 has arrived:%s\n",
	    cr, name, sizeof (hostname), hostname, cr);
	fprintf(tp, "----%s\n", cr);

	if ((mbox = open(name, O_RDONLY)) == -1) {
		dsyslog(LOG_DEBUG, "can't open mailbox for %s", name);
		exit(1);
	}
	/*
	 * In case of a worldwritable mail spool directory, we must take
	 * care we don't open and read from the wrong file.
	 */
	if (fstat(mbox, &stb) == -1 || lstat(name, &stl) == -1) {
		dsyslog(LOG_DEBUG, "stat() failed on mail file\n");
		exit(1);
	}

	/*
	 * Here we make sure that the file wasn't a hardlink or softlink
	 * while we opened it and that it wasn't changed afterwards
	 */
	if (!S_ISREG(stl.st_mode) ||
	    stl.st_dev != stb.st_dev ||
	    stl.st_ino != stb.st_ino ||
	    stl.st_uid != pwd->pw_uid ||
	    stb.st_nlink != 1) {
		dsyslog(LOG_DEBUG, "mail spool file must be plain file\n");
		exit(1);
	}

	timep[0] = stb.st_atime;
	timep[1] = stb.st_mtime;
	jkfprintf(tp, name, mbox, offset);
	utime(name, timep);
	exit(0);
}

void
jkfprintf(FILE *tp, char *name, int mbox, int offset)
{
	FILE *fi;
	int linecnt, charcnt;
	char line[BUFSIZ];
	int inheader;

	dsyslog(LOG_DEBUG, "HERE %s's mail starting at %d\n",
	    name, offset);
	if ((fi = fdopen(mbox, "r")) == NULL) {
		dsyslog(LOG_DEBUG, "Cant read the mail\n");
		return;
	}

	fseek(fi, offset, L_SET);

	/*
	 * Print the first 7 lines or 560 characters of the new mail
	 * (whichever comes first).  Skip header crap other than
	 * From, Subject, To, and Date.
	 */
	linecnt = 7;
	charcnt = 560;
	inheader = 1;


	while (fgets(line, sizeof (line), fi) != NULL) {
		char *cp;
		char *index();
		int cnt;
		int i;

		if (linecnt <= 0 || charcnt <= 0) {
			fprintf(tp, "...more...%s\n", cr);
			return;
		}
		if (strncmp(line, "From ", 5) == 0)
			continue;
		if (inheader && (line[0] == ' ' || line[0] == '\t'))
			continue;
		cp = index(line, ':');
		if (cp == 0 || (index(line, ' ') && index(line, ' ') < cp))
			inheader = 0;
		else
			cnt = cp - line;
		if (inheader &&
		    strncmp(line, "Date", cnt) &&
		    strncmp(line, "From", cnt) &&
		    strncmp(line, "Subject", cnt) &&
		    strncmp(line, "To", cnt))
			continue;
		cp = index(line, '\n');
		if (cp)
			*cp = '\0';

		for (i = strlen(line); i-- > 0; )
			if (!isprint(line[i]))
				line[i] = ' ';


		fprintf(tp, "%s%s\n", line, cr);
		linecnt--, charcnt -= strlen(line);
	}
	fprintf(tp, "----%s\n", cr);
}
