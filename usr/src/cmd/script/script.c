/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved */


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*	Portions Copyright(c) 1988, Sun Microsystems, Inc.	*/
/*	All Rights Reserved.					*/

/*
 * script: Produce a record of a terminal session.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <locale.h>
#include <time.h>
#include <sys/stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/file.h>
#include <errno.h>

int	grantpt();
int	unlockpt();
char	*ptsname();
void	doinput() __NORETURN;
void	dooutput();
void	doshell();
void	fixtty();
void	fail();
void	done() __NORETURN;
void	getmanager();
void	getsubsid();

char	*shell;
FILE	*fscript;
int	manager;	/* file descriptor for manager pseudo-tty */
int	subsid;		/* file descriptor for subsidiary pseudo-tty */
int	child;
int	subchild;
char	*fname = "typescript";
void	sigwinch();
void	finish();

struct	termios b;
struct	winsize size;
int	lb;
int	l;
char	*mptname = "/dev/ptmx";	/* manager pseudo-tty device */

int	aflg;

int
main(int argc, char *argv[])
{
	uid_t ruidt;
	gid_t gidt;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	shell = getenv("SHELL");
	if (shell == NULL)
		shell = "/bin/sh";
	argc--, argv++;
	while (argc > 0 && argv[0][0] == '-') {
		switch (argv[0][1]) {

		case 'a':
			aflg++;
			break;

		default:
			fprintf(stderr,
			    gettext("usage: script [ -a ] [ typescript ]\n"));
			exit(1);
		}
		argc--, argv++;
	}
	if (argc > 0)
		fname = argv[0];
	ruidt = getuid();
	gidt = getgid();
	if ((fscript = fopen(fname, aflg ? "a" : "w")) == NULL) {
		perror(fname);
		fail();
	}
	setbuf(fscript, NULL);
	chown(fname, ruidt, gidt);
	getmanager();
	printf(gettext("Script started, file is %s\n"), fname);
	fixtty();

	(void) signal(SIGCHLD, finish);
	child = fork();
	if (child < 0) {
		perror("fork");
		fail();
	}
	if (child == 0) {
		subchild = child = fork();
		if (child < 0) {
			perror("fork");
			fail();
		}
		if (child)
			dooutput();
		else
			doshell();
	}
	doinput();
	/* NOTREACHED */
	return (0);
}

void
doinput()
{
	char ibuf[BUFSIZ];
	int cc;

	(void) fclose(fscript);
	sigset(SIGWINCH, sigwinch);

	while ((cc = read(0, ibuf, BUFSIZ)) != 0) {
		if (cc == -1) {
			if (errno == EINTR) {   /* SIGWINCH probably */
				continue;
			} else {
				break;
			}
		}
		(void) write(manager, ibuf, cc);
	}
	done();
}

void
sigwinch()
{
	struct winsize ws;

	if (ioctl(0, TIOCGWINSZ, &ws) == 0)
		(void) ioctl(manager, TIOCSWINSZ, &ws);
}

#include <sys/wait.h>

void
finish()
{
	int status;
	register int pid;
	register int die = 0;

	while ((pid = wait(&status)) > 0)
		if (pid == child)
			die = 1;

	if (die)
		done();
}

void
dooutput()
{
	time_t tvec;
	char obuf[BUFSIZ];
	char tbuf[BUFSIZ];
	int cc;

	(void) close(0);
	tvec = time((time_t *)0);
	strftime(tbuf, BUFSIZ, "%c", localtime(&tvec));
	fprintf(fscript, gettext("Script started on %s\n"), tbuf);
	for (;;) {
		cc = read(manager, obuf, sizeof (obuf));
		if (cc <= 0)
			break;
		(void) write(1, obuf, cc);
		(void) fwrite(obuf, 1, cc, fscript);
	}
	done();
}

void
doshell()
{

	setpgrp();	/* relinquish control terminal */
	getsubsid();
	(void) close(manager);
	(void) fclose(fscript);
	(void) dup2(subsid, 0);
	(void) dup2(subsid, 1);
	(void) dup2(subsid, 2);
	(void) close(subsid);
	execl(shell, shell, "-i", (char *)0);
	perror(shell);
	fail();
}

void
fixtty()
{
	struct termios sbuf;

	sbuf = b;
	sbuf.c_iflag &= ~(INLCR|IGNCR|ICRNL|IUCLC|IXON);
	sbuf.c_oflag &= ~OPOST;
	sbuf.c_lflag &= ~(ICANON|ISIG|ECHO);
	sbuf.c_cc[VMIN] = 1;
	sbuf.c_cc[VTIME] = 0;
	(void) ioctl(0, TCSETSF, (char *)&sbuf);
}

void
fail()
{

	(void) kill(0, SIGTERM);
	done();
}

void
done()
{
	time_t tvec;
	char tbuf[BUFSIZ];

	if (subchild) {
		tvec = time((time_t *)0);
		strftime(tbuf, BUFSIZ, "%c", localtime(&tvec));
		fprintf(fscript, gettext("\nscript done on %s\n"), tbuf);
		(void) fclose(fscript);
		(void) close(manager);
	} else {
		(void) ioctl(0, TCSETSW, (char *)&b);
		printf(gettext("Script done, file is %s\n"), fname);
	}
	exit(0);
}

void
getmanager()
{
	struct stat stb;

	if ((manager = open(mptname, O_RDWR)) >= 0) { /* a pseudo-tty is free */
		(void) ioctl(0, TCGETS, (char *)&b);
		(void) ioctl(0, TIOCGWINSZ, (char *)&size);
		return;
	} else {				/* out of pseudo-tty's */
		perror(mptname);
		fprintf(stderr, gettext("Out of pseudo-tty's\n"));
		fail();
	}
}

void
getsubsid()
{
	char *subsidname;	/* name of subsidiary pseudo-tty */

	grantpt(manager);		/* change permissions of subsidiary */
	unlockpt(manager);			/* unlock subsidiary */
	subsidname = ptsname(manager);		/* get name of subsidiary */
	subsid = open(subsidname, O_RDWR);	/* open subsidiary */
	if (subsid < 0) {			/* error opening subsidiary */
		perror(subsidname);
		fail();
	}
	ioctl(subsid, I_PUSH, "ptem");	/* push pt hw emulation module */
	ioctl(subsid, I_PUSH, "ldterm");	/* push line discipline */

	(void) ioctl(subsid, TCSETSF, (char *)&b);
	(void) ioctl(subsid, TIOCSWINSZ, (char *)&size);
}
