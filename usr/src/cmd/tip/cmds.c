/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "tip.h"
#include <limits.h>
#ifdef USG
#include <unistd.h>
#else
#include <vfork.h>
#endif

/*
 * tip
 *
 * miscellaneous commands
 */

int	quant[] = { 60, 60, 24 };

char	null = '\0';
char	*sep[] = { "second", "minute", "hour" };
static	char *argv[10];		/* argument vector for take and put */

sigjmp_buf intbuf;		/* for interrupts and timeouts */

void	timeout(void);		/* timeout function called on alarm */
void	intcopy(void);		/* interrupt routine for file transfers */
void	transfer(char *, int, char *);
void	transmit(FILE *, char *, char *);
void	send(char);
void	execute(char *);
void	prtime(char *, time_t);
void	hardwareflow(char *);
void	intr(char *);
int	args(char *, char *[], size_t);
int	anyof(char *, char *);

/*
 * FTP - remote ==> local
 *  get a file from the remote host
 */
void
getfl(int c)
{
	char buf[256], *cp;

	(void) putchar(c);
	/*
	 * get the UNIX receiving file's name
	 */
	if (prompt("Local file name? ", copyname, sizeof (copyname)))
		return;
	cp = expand(copyname);
	if (cp == NOSTR)
		return;
	if ((sfd = creat(cp, 0666)) < 0) {
		(void) printf("\r\n%s: cannot creat\r\n", copyname);
		return;
	}

	/*
	 * collect parameters
	 */
	if (prompt("List command for remote system? ", buf, sizeof (buf))) {
		(void) unlink(copyname);
		return;
	}
	transfer(buf, sfd, value(EOFREAD));
}

/*
 * Cu-like take command
 */
/* ARGSUSED */
void
cu_take(int cc)
{
	int fd, argc;
	char line[BUFSIZ], *cp;

	if (prompt("[take] ", copyname, sizeof (copyname)))
		return;
	argc = args(copyname, argv, sizeof (argv)/sizeof (char *));
	if (argc < 1 || argc > 2) {
		(void) printf("usage: <take> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	cp = expand(argv[1]);
	if (cp == NOSTR)
		return;
	if ((fd = creat(cp, 0666)) < 0) {
		(void) printf("\r\n%s: cannot create\r\n", argv[1]);
		return;
	}
	(void) snprintf(line, sizeof (line), "cat %s; echo \01", argv[0]);
	transfer(line, fd, "\01");
}

/*
 * Bulk transfer routine --
 *  used by getfl(), cu_take(), and pipefile()
 */
void
transfer(char *buf, int fd, char *eofchars)
{
	int ct;
	char c, buffer[BUFSIZ];
	char *p = buffer;	/* can't be register because of longjmp */
	int cnt, eof, bol;
	time_t start;
	sig_handler_t	f;

	parwrite(FD, (unsigned char *)buf, strlen(buf));
	(void) kill(pid, SIGIOT);
	/* Wait until read process stops */
	(void) read(repdes[0], (char *)&ccc, 1);

	/*
	 * finish command
	 */
	parwrite(FD, (unsigned char *)"\r", 1);
	do
		(void) read(FD, &c, 1);
	while ((c&0177) != '\n')
		;

	if (sigsetjmp(intbuf, 1))
		goto out;
	f = signal(SIGINT, (sig_handler_t)intcopy);
	intr("on");

	start = time(0);
	bol = 1;
	ct = 0;
	for (;;) {
		eof = read(FD, &c, 1) <= 0;
		if (noparity)
			c &= 0377;
		else
			c &= 0177;
		if (eof || (bol && any(c, eofchars)))
			break;
		if (c == 0)
			continue;	/* ignore nulls */
		if (c == '\r')
			continue;
		*p++ = c;

		if (c == '\n') {
			bol = 1;
			if (boolean(value(VERBOSE)))
				(void) printf("\r%d", ++ct);
		} else
			bol = 0;
		if ((cnt = (p-buffer)) == number(value(FRAMESIZE))) {
			if (write(fd, buffer, cnt) != cnt) {
				(void) printf("\r\nwrite error\r\n");
				goto out;
			}
			p = buffer;
		}
	}
out:
	if ((cnt = (p-buffer)) != 0)
		if (write(fd, buffer, cnt) != cnt)
			(void) printf("\r\nwrite error\r\n");

	if (boolean(value(VERBOSE)))
		prtime(" lines transferred in ", time(0)-start);
	intr("off");
	(void) write(fildes[1], (char *)&ccc, 1);
	(void) signal(SIGINT, f);
	(void) close(fd);
}

/*
 * FTP - remote ==> local process
 *   send remote input to local process via pipe
 */
/* ARGSUSED */
void
pipefile(int cc)
{
	int cpid, pdes[2];
	char buf[256];
	int status, p;

	if (prompt("Local command? ", buf, sizeof (buf)))
		return;

	if (pipe(pdes)) {
		(void) printf("can't establish pipe\r\n");
		return;
	}

	if ((cpid = fork()) < 0) {
		(void) printf("can't fork!\r\n");
		return;
	} else if (cpid) {
		if (prompt("List command for remote system? ", buf,
		    sizeof (buf))) {
			(void) close(pdes[0]), (void) close(pdes[1]);
			(void) kill(cpid, SIGKILL);
		} else {
			(void) close(pdes[0]);
			(void) signal(SIGPIPE, (sig_handler_t)intcopy);
			transfer(buf, pdes[1], value(EOFREAD));
			(void) signal(SIGPIPE, SIG_DFL);
			while ((p = wait(&status)) > 0 && p != cpid)
				;
		}
	} else {
		int f;

		userperm();
		(void) dup2(pdes[0], 0);
		(void) close(pdes[0]);
		for (f = 3; f < 20; f++)
			(void) close(f);
		execute(buf);
		(void) printf("can't execl!\r\n");
		exit(0);
	}
}

/*
 * FTP - local ==> remote
 *  send local file to remote host
 *  terminate transmission with pseudo EOF sequence
 */
void
tip_sendfile(int cc)
{
	FILE *fd;
	char *fnamex;

	(void) putchar(cc);
	/*
	 * get file name
	 */
	if (prompt("Local file name? ", fname, sizeof (fname)))
		return;

	/*
	 * look up file
	 */
	fnamex = expand(fname);
	if (fnamex == NOSTR)
		return;
	if ((fd = fopen(fnamex, "r")) == NULL) {
		(void) printf("%s: cannot open\r\n", fname);
		return;
	}
	transmit(fd, value(EOFWRITE), NULL);
	if (!boolean(value(ECHOCHECK))) {
		struct termios buf;

		(void) ioctl(FD, TCGETS, (char *)&buf);	/* this does a */
		(void) ioctl(FD, TCSETSF, (char *)&buf);	/* wflushtty */
	}
}

/*
 * Bulk transfer routine to remote host --
 *   used by tip_sendfile() and cu_put()
 */
void
transmit(FILE *fd, char *eofchars, char *command)
{
	sig_handler_t	ointr;
	char *pc, lastc, rc;
	int c, ccount, lcount;
	time_t start_t, stop_t;

	(void) kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	timedout = 0;
	if (sigsetjmp(intbuf, 1)) {
		if (timedout)
			(void) printf("\r\ntimed out at eol\r\n");
		(void) alarm(0);
		goto out;
	}
	ointr = signal(SIGINT, (sig_handler_t)intcopy);
	intr("on");
	(void) read(repdes[0], (char *)&ccc, 1);
	if (command != NULL) {
		for (pc = command; *pc; pc++)
			send(*pc);
		if (boolean(value(ECHOCHECK)))
			(void) read(FD, (char *)&c, 1);	/* trailing \n */
		else {
			struct termios buf;
			/* wait for remote stty to take effect */
			(void) sleep(5);
			/* this does a */
			(void) ioctl(FD, TCGETS, (char *)&buf);
			/* wflushtty */
			(void) ioctl(FD, TCSETSF, (char *)&buf);
		}
	}
	lcount = 0;
	lastc = '\0';
	start_t = time(0);
	if (boolean(value(RAWFTP))) {
		while ((c = getc(fd)) != EOF) {
			lcount++;
			send(c);
			if (boolean(value(VERBOSE)) && lcount%100 == 0)
				(void) printf("\r%d", lcount);
		}
		if (boolean(value(VERBOSE)))
			(void) printf("\r%d", lcount);
		goto out;
	}
	for (;;) {
		ccount = 0;
		do {
			c = getc(fd);
			if (c == EOF)
				goto out;
			if (c == 0177)
				continue;
			lastc = c;
			if (c < 040) {
				if (c == '\n') {
					c = '\r';
				} else if (c == '\t') {
					if (boolean(value(TABEXPAND))) {
						send(' ');
						while ((++ccount % 8) != 0)
							send(' ');
						continue;
					}
				} else
					continue;
			}
			send(c);
		} while (c != '\r');
		if (boolean(value(VERBOSE)))
			(void) printf("\r%d", ++lcount);
		if (boolean(value(ECHOCHECK))) {
			(void) alarm(number(value(ETIMEOUT)));
			do {	/* wait for prompt */
				(void) read(FD, &rc, 1);
			} while ((rc&0177) != character(value(PROMPT)));
			(void) alarm(0);
		}
	}
out:
	if (lastc != '\n' && !boolean(value(RAWFTP)))
		send('\r');
	if (eofchars)
		for (pc = eofchars; *pc; pc++)
			send(*pc);
	stop_t = time(0);
	(void) fclose(fd);
	if (boolean(value(VERBOSE)))
		if (boolean(value(RAWFTP)))
			prtime(" chars transferred in ", stop_t-start_t);
		else
			prtime(" lines transferred in ", stop_t-start_t);
	(void) write(fildes[1], (char *)&ccc, 1);
	intr("off");
	(void) signal(SIGINT, ointr);
}

/*
 * Cu-like put command
 */
/* ARGSUSED */
void
cu_put(int cc)
{
	FILE *fd;
	char line[BUFSIZ];
	int argc;
	char *copynamex;

	if (prompt("[put] ", copyname, sizeof (copyname)))
		return;
	argc = args(copyname, argv, sizeof (argv)/sizeof (char *));
	if (argc < 1 || argc > 2) {
		(void) printf("usage: <put> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	copynamex = expand(argv[0]);
	if (copynamex == NOSTR)
		return;
	if ((fd = fopen(copynamex, "r")) == NULL) {
		(void) printf("%s: cannot open\r\n", copynamex);
		return;
	}
	if (boolean(value(ECHOCHECK)))
		(void) snprintf(line, sizeof (line), "cat>%s\r", argv[1]);
	else
		(void) snprintf(line, sizeof (line),
		    "stty -echo; cat>%s; stty echo\r", argv[1]);
	transmit(fd, "\04", line);
}

/*
 * FTP - send single character
 *  wait for echo & handle timeout
 */
void
send(char c)
{
	char cc;
	int retry = 0;

	cc = c;
	parwrite(FD, (unsigned char *)&cc, 1);
#ifdef notdef
	if (number(value(CDELAY)) > 0 && c != '\r')
		nap(number(value(CDELAY)));
#endif
	if (!boolean(value(ECHOCHECK))) {
#ifdef notdef
		if (number(value(LDELAY)) > 0 && c == '\r')
			nap(number(value(LDELAY)));
#endif
		return;
	}
tryagain:
	timedout = 0;
	if (sigsetjmp(intbuf, 1) && timedout) {
		(void) printf("\r\ntimeout error (%s)\r\n", ctrl(c));
		if (retry++ > 3)
			return;
		parwrite(FD, (unsigned char *)&null, 1); /* poke it */
		goto tryagain;
	}
	(void) alarm(number(value(ETIMEOUT)));
	(void) read(FD, &cc, 1);
	(void) alarm(0);
}

void
timeout(void)
{
	(void) signal(SIGALRM, (sig_handler_t)timeout);
	timedout = 1;
	siglongjmp(intbuf, 1);
}

/*
 * Stolen from consh() -- puts a remote file on the output of a local command.
 *	Identical to consh() except for where stdout goes.
 */
void
pipeout(int c)
{
	char buf[256];
	int cpid, status, p;
	time_t start;

	(void) putchar(c);
	if (prompt("Local command? ", buf, sizeof (buf)))
		return;
	(void) kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	intr("on");
	(void) read(repdes[0], (char *)&ccc, 1);
	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		(void) printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
	} else {
		int i;

		userperm();
		(void) dup2(FD, 1);
		for (i = 3; i < 20; i++)
			(void) close(i);
		(void) signal(SIGINT, SIG_DFL);
		(void) signal(SIGQUIT, SIG_DFL);
		execute(buf);
		(void) printf("can't find `%s'\r\n", buf);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		prtime("away for ", time(0)-start);
	(void) write(fildes[1], (char *)&ccc, 1);
	intr("off");
	(void) signal(SIGINT, SIG_DFL);
	(void) signal(SIGQUIT, SIG_DFL);
}

/*
 * Fork a program with:
 *  0 <-> remote tty in
 *  1 <-> remote tty out
 *  2 <-> local tty stderr out
 */
void
consh(int c)
{
	char buf[256];
	int cpid, status, p;
	sig_handler_t	ointr, oquit;
	time_t start;

	(void) putchar(c);
	if (prompt("Local command? ", buf, sizeof (buf)))
		return;
	(void) kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	(void) read(repdes[0], (char *)&ccc, 1);
	ointr = signal(SIGINT, SIG_IGN);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		(void) printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
		raw();
		(void) signal(SIGINT, ointr);
		(void) signal(SIGQUIT, oquit);
	} else {
		int i;

		userperm();
		(void) dup2(FD, 0);
		(void) dup2(0, 1);
		for (i = 3; i < 20; i++)
			(void) close(i);
		(void) signal(SIGINT, SIG_DFL);
		(void) signal(SIGQUIT, SIG_DFL);
		execute(buf);
		(void) printf("can't find `%s'\r\n", buf);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		prtime("\r\naway for ", time(0)-start);
	(void) write(fildes[1], (char *)&ccc, 1);
}

/*
 * Escape to local shell
 */
/* ARGSUSED */
void
shell(int cc)
{
	int shpid, status;
	sig_handler_t	ointr, oquit;
	char *cp;

	(void) printf("[sh]\r\n");
	ointr = signal(SIGINT, SIG_IGN);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	if (shpid = fork()) {
		while (shpid != wait(&status))
			;
		raw();
		(void) printf("\r\n!\r\n");
		(void) signal(SIGINT, ointr);
		(void) signal(SIGQUIT, oquit);
	} else {
		userperm();
		(void) signal(SIGQUIT, SIG_DFL);
		(void) signal(SIGINT, SIG_DFL);
		if ((cp = strrchr(value(SHELL), '/')) == NULL)
			cp = value(SHELL);
		else
			cp++;
		(void) execl(value(SHELL), cp, 0);
		(void) printf("\r\ncan't execl!\r\n");
		exit(1);
	}
}

/*
 * TIPIN portion of scripting
 *   initiate the conversation with TIPOUT
 */
void
setscript(void)
{
	char c;

	if (strlen(value(RECORD)) >= PATH_MAX-1) {
		(void) fprintf(stderr, "tip: record file name too long\r\n");
		return;
	}
	/*
	 * enable TIPOUT side for dialogue
	 */
	(void) kill(pid, SIGEMT);
	if (boolean(value(SCRIPT)))
		(void) write(fildes[1], value(RECORD), strlen(value(RECORD)));
	(void) write(fildes[1], "\n", 1);
	/*
	 * wait for TIPOUT to finish
	 */
	(void) read(repdes[0], &c, 1);
	if (c == 'n')
		(void) fprintf(stderr, "tip: can't create record file %s\r\n",
		    value(RECORD));
}

/*
 * Change current working directory of
 *   local portion of tip
 */
/* ARGSUSED */
void
chdirectory(int cc)
{
	char dirname[80];
	char *cp = dirname;

	if (prompt("[cd] ", dirname, sizeof (dirname))) {
		if (stoprompt)
			return;
		cp = value(HOME);
	}
	if (chdir(cp) < 0)
		(void) printf("%s: bad directory\r\n", cp);
	(void) printf("!\r\n");
}

void
tip_abort(char *msg)
{
	/* don't want to hear about our child */
	(void) signal(SIGCHLD, SIG_DFL);
	(void) kill(pid, SIGTERM);
	myperm();
	disconnect(msg);
	if (msg != NOSTR)
		(void) printf("\r\n%s", msg);
	(void) printf("\r\n[EOT]\r\n");
	delock(uucplock);
	unraw();
	exit(0);
}

/* ARGSUSED */
void
finish(int cc)
{
	char *dismsg;

	if ((dismsg = value(DISCONNECT)) != NOSTR) {
		(void) write(FD, dismsg, strlen(dismsg));
		(void) sleep(5);
	}
	tip_abort(NOSTR);
}

void
intcopy(void)
{

	(void) signal(SIGINT, SIG_IGN);
	siglongjmp(intbuf, 1);
}

void
execute(char *s)
{
	char *cp;

	if ((cp = strrchr(value(SHELL), '/')) == NULL)
		cp = value(SHELL);
	else
		cp++;
	(void) execl(value(SHELL), cp, "-c", s, 0);
}

int
args(char *buf, char *a[], size_t na)
{
	char *p = buf, *start;
	char **parg = a;
	int n = 0;

	do {
		while (*p && (*p == ' ' || *p == '\t'))
			p++;
		start = p;
		if (*p)
			*parg = p;
		while (*p && (*p != ' ' && *p != '\t'))
			p++;
		if (p != start)
			parg++, n++;
		if (*p)
			*p++ = '\0';
	} while (*p && n < na);

	return (n);
}

void
prtime(char *s, time_t a)
{
	int i;
	int nums[3];

	for (i = 0; i < 3; i++) {
		nums[i] = (int)(a % quant[i]);
		a /= quant[i];
	}
	(void) printf("%s", s);
	while (--i >= 0)
		if (nums[i] || i == 0 && nums[1] == 0 && nums[2] == 0)
			(void) printf("%d %s%c ", nums[i], sep[i],
			    nums[i] == 1 ? '\0' : 's');
	(void) printf("\r\n!\r\n");
}

/* ARGSUSED */
void
variable(int cc)
{
	char	buf[256];

	if (prompt("[set] ", buf, sizeof (buf)))
		return;
	vlex(buf);
	if (vtable[BEAUTIFY].v_access&CHANGED) {
		vtable[BEAUTIFY].v_access &= ~CHANGED;
		(void) kill(pid, SIGSYS);
	}
	if (vtable[SCRIPT].v_access&CHANGED) {
		vtable[SCRIPT].v_access &= ~CHANGED;
		setscript();
		/*
		 * So that "set record=blah script" doesn't
		 *  cause two transactions to occur.
		 */
		if (vtable[RECORD].v_access&CHANGED)
			vtable[RECORD].v_access &= ~CHANGED;
	}
	if (vtable[RECORD].v_access&CHANGED) {
		vtable[RECORD].v_access &= ~CHANGED;
		if (boolean(value(SCRIPT)))
			setscript();
	}
	if (vtable[TAND].v_access&CHANGED) {
		vtable[TAND].v_access &= ~CHANGED;
		if (boolean(value(TAND)))
			tandem("on");
		else
			tandem("off");
	}
	if (vtable[LECHO].v_access&CHANGED) {
		vtable[LECHO].v_access &= ~CHANGED;
		boolean(value(HALFDUPLEX)) = boolean(value(LECHO));
	}
	if (vtable[PARITY].v_access&CHANGED) {
		vtable[PARITY].v_access &= ~CHANGED;
		setparity(NULL);
	}
	if (vtable[BAUDRATE].v_access&CHANGED) {
		vtable[BAUDRATE].v_access &= ~CHANGED;
		ttysetup(speed(number(value(BAUDRATE))));
	}
	if (vtable[HARDWAREFLOW].v_access & CHANGED) {
		vtable[HARDWAREFLOW].v_access &= ~CHANGED;
		if (boolean(value(HARDWAREFLOW)))
			hardwareflow("on");
		else
			hardwareflow("off");
	}
}

/*
 * Turn tandem mode on or off for remote tty.
 */
void
tandem(char *option)
{
	struct termios rmtty;

	(void) ioctl(FD, TCGETS, (char *)&rmtty);
	if (equal(option, "on")) {
		rmtty.c_iflag |= IXOFF|IXON;
		arg.c_iflag |= IXOFF|IXON;
		rmtty.c_cc[VSTART] = defarg.c_cc[VSTART];
		rmtty.c_cc[VSTOP] = defarg.c_cc[VSTOP];
	} else {
		rmtty.c_iflag &= ~(IXOFF|IXON);
		arg.c_iflag &= ~(IXOFF|IXON);
	}
	(void) ioctl(FD, TCSETSF, (char *)&rmtty);
	(void) ioctl(0, TCSETSF, (char *)&arg);
}

/*
 * Turn hardwareflow mode on or off for remote tty.
 */
void
hardwareflow(char *option)
{
	struct termios rmtty;

	(void) ioctl(FD, TCGETS, (char *)&rmtty);
	if (equal(option, "on")) {
		rmtty.c_cflag |= (CRTSCTS|CRTSXOFF);
	} else {
		rmtty.c_cflag &= ~(CRTSCTS|CRTSXOFF);
	}
	(void) ioctl(FD, TCSETSF, (char *)&rmtty);
}

/*
 * Turn interrupts from local tty on or off.
 */
void
intr(char *option)
{

	if (equal(option, "on"))
		arg.c_lflag |= ISIG;
	else
		arg.c_lflag &= ~ISIG;
	(void) ioctl(0, TCSETSF, (char *)&arg);
}

/*
 * Send a break.
 */
/* ARGSUSED */
void
genbrk(int cc)
{

	(void) ioctl(FD, TCSBRK, 0);
}

/*
 * Suspend tip
 */
void
suspend(int c)
{

	unraw();
	(void) kill(c == _CTRL('y') ? getpid() : 0, SIGTSTP);
	raw();
}

/*
 *	expand a file name if it includes shell meta characters
 */

char *
expand(char name[])
{
	static char xname[BUFSIZ];
	char cmdbuf[BUFSIZ];
	int pid, l;
	char *cp, *Shell;
	int s, pivec[2];

	if (!anyof(name, "~{[*?$`'\"\\"))
		return (name);
	if (pipe(pivec) < 0) {
		perror("pipe");
		return (name);
	}
	(void) snprintf(cmdbuf, sizeof (cmdbuf), "echo %s", name);
	if ((pid = vfork()) == 0) {
		userperm();
		Shell = value(SHELL);
		if (Shell == NOSTR)
			Shell = "/bin/sh";
		(void) close(pivec[0]);
		(void) close(1);
		(void) dup(pivec[1]);
		(void) close(pivec[1]);
		(void) close(2);
		(void) execl(Shell, Shell, "-c", cmdbuf, 0);
		_exit(1);
	}
	if (pid == -1) {
		perror("fork");
		(void) close(pivec[0]);
		(void) close(pivec[1]);
		return (NOSTR);
	}
	(void) close(pivec[1]);
	l = read(pivec[0], xname, BUFSIZ);
	(void) close(pivec[0]);
	while (wait(&s) != pid)
		;
	s &= 0377;
	if (s != 0 && s != SIGPIPE) {
		(void) fprintf(stderr, "\"Echo\" failed\n");
		return (NOSTR);
	}
	if (l < 0) {
		perror("read");
		return (NOSTR);
	}
	if (l == 0) {
		(void) fprintf(stderr, "\"%s\": No match\n", name);
		return (NOSTR);
	}
	if (l == BUFSIZ) {
		(void) fprintf(stderr, "Buffer overflow expanding \"%s\"\n",
		    name);
		return (NOSTR);
	}
	xname[l] = 0;
	for (cp = &xname[l-1]; *cp == '\n' && cp > xname; cp--)
		;
	*++cp = '\0';
	return (xname);
}

/*
 * Are any of the characters in the two strings the same?
 */

int
anyof(char *s1, char *s2)
{
	int c;

	while ((c = *s1++) != 0)
		if (any(c, s2))
			return (1);
	return (0);
}
