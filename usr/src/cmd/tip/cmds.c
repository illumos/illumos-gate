/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 5.4 5/5/86 */

#include "tip.h"
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

void	timeout();		/* timeout function called on alarm */
void	intcopy();		/* interrupt routine for file transfers */

/*
 * FTP - remote ==> local
 *  get a file from the remote host
 */
getfl(c)
	char c;
{
	char buf[256], *cp, *expand();

	putchar(c);
	/*
	 * get the UNIX receiving file's name
	 */
	if (prompt("Local file name? ", copyname, sizeof (copyname)))
		return;
	cp = expand(copyname);
	if (cp == NOSTR)
		return;
	if ((sfd = creat(cp, 0666)) < 0) {
		printf("\r\n%s: cannot creat\r\n", copyname);
		return;
	}

	/*
	 * collect parameters
	 */
	if (prompt("List command for remote system? ", buf, sizeof (buf))) {
		unlink(copyname);
		return;
	}
	transfer(buf, sfd, value(EOFREAD));
}

/*
 * Cu-like take command
 */
cu_take(cc)
	char cc;
{
	int fd, argc;
	char line[BUFSIZ], *expand(), *cp;

	if (prompt("[take] ", copyname, sizeof (copyname)))
		return;
	argc = args(copyname, argv, sizeof (argv)/sizeof (char *));
	if (argc < 1 || argc > 2) {
		printf("usage: <take> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	cp = expand(argv[1]);
	if (cp == NOSTR)
		return;
	if ((fd = creat(cp, 0666)) < 0) {
		printf("\r\n%s: cannot create\r\n", argv[1]);
		return;
	}
	sprintf(line, "cat %s; echo \01", argv[0]);
	transfer(line, fd, "\01");
}

/*
 * Bulk transfer routine --
 *  used by getfl(), cu_take(), and pipefile()
 */
transfer(buf, fd, eofchars)
	char *buf, *eofchars;
{
	register int ct;
	char c, buffer[BUFSIZ];
	char *p = buffer;	/* can't be register because of longjmp */
	register int cnt, eof, bol;
	time_t start;
	void (*f)();

	parwrite(FD, buf, strlen(buf));
	kill(pid, SIGIOT);
	read(repdes[0], (char *)&ccc, 1);  /* Wait until read process stops */

	/*
	 * finish command
	 */
	parwrite(FD, "\r", 1);
	do
		read(FD, &c, 1);
	while ((c&0177) != '\n');

	if (sigsetjmp(intbuf, 1))
		goto out;
	f = signal(SIGINT, intcopy);
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
				printf("\r%d", ++ct);
		} else
			bol = 0;
		if ((cnt = (p-buffer)) == number(value(FRAMESIZE))) {
			if (write(fd, buffer, cnt) != cnt) {
				printf("\r\nwrite error\r\n");
				goto out;
			}
			p = buffer;
		}
	}
out:
	if (cnt = (p-buffer))
		if (write(fd, buffer, cnt) != cnt)
			printf("\r\nwrite error\r\n");

	if (boolean(value(VERBOSE)))
		prtime(" lines transferred in ", time(0)-start);
	intr("off");
	write(fildes[1], (char *)&ccc, 1);
	signal(SIGINT, f);
	close(fd);
}

/*
 * FTP - remote ==> local process
 *   send remote input to local process via pipe
 */
pipefile()
{
	int cpid, pdes[2];
	char buf[256];
	int status, p;
	extern int errno;

	if (prompt("Local command? ", buf, sizeof (buf)))
		return;

	if (pipe(pdes)) {
		printf("can't establish pipe\r\n");
		return;
	}

	if ((cpid = fork()) < 0) {
		printf("can't fork!\r\n");
		return;
	} else if (cpid) {
		if (prompt("List command for remote system? ", buf,
			    sizeof (buf))) {
			close(pdes[0]), close(pdes[1]);
			kill(cpid, SIGKILL);
		} else {
			close(pdes[0]);
			signal(SIGPIPE, intcopy);
			transfer(buf, pdes[1], value(EOFREAD));
			signal(SIGPIPE, SIG_DFL);
			while ((p = wait(&status)) > 0 && p != cpid)
				;
		}
	} else {
		register int f;

		userperm();
		dup2(pdes[0], 0);
		close(pdes[0]);
		for (f = 3; f < 20; f++)
			close(f);
		execute(buf);
		printf("can't execl!\r\n");
		exit(0);
	}
}

/*
 * FTP - local ==> remote
 *  send local file to remote host
 *  terminate transmission with pseudo EOF sequence
 */
sendfile(cc)
	char cc;
{
	FILE *fd;
	char *fnamex;
	char *expand();

	putchar(cc);
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
		printf("%s: cannot open\r\n", fname);
		return;
	}
	transmit(fd, value(EOFWRITE), NULL);
	if (!boolean(value(ECHOCHECK))) {
		struct termios buf;

		ioctl(FD, TCGETS, (char *)&buf);	/* this does a */
		ioctl(FD, TCSETSF, (char *)&buf);	/*   wflushtty */
	}
}

/*
 * Bulk transfer routine to remote host --
 *   used by sendfile() and cu_put()
 */
transmit(fd, eofchars, command)
	FILE *fd;
	char *eofchars, *command;
{
	void (*ointr)();
	char *pc, lastc, rc;
	int c, ccount, lcount;
	time_t start_t, stop_t;

	kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	timedout = 0;
	if (sigsetjmp(intbuf, 1)) {
		if (timedout)
			printf("\r\ntimed out at eol\r\n");
		alarm(0);
		goto out;
	}
	ointr = signal(SIGINT, intcopy);
	intr("on");
	read(repdes[0], (char *)&ccc, 1);
	if (command != NULL) {
		for (pc = command; *pc; pc++)
			send(*pc);
		if (boolean(value(ECHOCHECK)))
			read(FD, (char *)&c, 1);	/* trailing \n */
		else {
			struct termios buf;

			sleep(5); /* wait for remote stty to take effect */
			ioctl(FD, TCGETS, (char *)&buf); /* this does a */
			ioctl(FD, TCSETSF, (char *)&buf); /*   wflushtty */
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
				printf("\r%d", lcount);
		}
		if (boolean(value(VERBOSE)))
			printf("\r%d", lcount);
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
			printf("\r%d", ++lcount);
		if (boolean(value(ECHOCHECK))) {
			alarm(number(value(ETIMEOUT)));
			do {	/* wait for prompt */
				read(FD, &rc, 1);
			} while ((rc&0177) != character(value(PROMPT)));
			alarm(0);
		}
	}
out:
	if (lastc != '\n' && !boolean(value(RAWFTP)))
		send('\r');
	if (eofchars)
		for (pc = eofchars; *pc; pc++)
			send(*pc);
	stop_t = time(0);
	fclose(fd);
	if (boolean(value(VERBOSE)))
		if (boolean(value(RAWFTP)))
			prtime(" chars transferred in ", stop_t-start_t);
		else
			prtime(" lines transferred in ", stop_t-start_t);
	write(fildes[1], (char *)&ccc, 1);
	intr("off");
	signal(SIGINT, ointr);
}

/*
 * Cu-like put command
 */
cu_put(cc)
	char cc;
{
	FILE *fd;
	char line[BUFSIZ];
	int argc;
	char *expand();
	char *copynamex;

	if (prompt("[put] ", copyname, sizeof (copyname)))
		return;
	argc = args(copyname, argv, sizeof (argv)/sizeof (char *));
	if (argc < 1 || argc > 2) {
		printf("usage: <put> from [to]\r\n");
		return;
	}
	if (argc == 1)
		argv[1] = argv[0];
	copynamex = expand(argv[0]);
	if (copynamex == NOSTR)
		return;
	if ((fd = fopen(copynamex, "r")) == NULL) {
		printf("%s: cannot open\r\n", copynamex);
		return;
	}
	if (boolean(value(ECHOCHECK)))
		sprintf(line, "cat>%s\r", argv[1]);
	else
		sprintf(line, "stty -echo; cat>%s; stty echo\r", argv[1]);
	transmit(fd, "\04", line);
}

/*
 * FTP - send single character
 *  wait for echo & handle timeout
 */
send(c)
	char c;
{
	char cc;
	int retry = 0;

	cc = c;
	parwrite(FD, &cc, 1);
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
		printf("\r\ntimeout error (%s)\r\n", ctrl(c));
		if (retry++ > 3)
			return;
		parwrite(FD, &null, 1); /* poke it */
		goto tryagain;
	}
	alarm(number(value(ETIMEOUT)));
	read(FD, &cc, 1);
	alarm(0);
}

void
timeout()
{
	signal(SIGALRM, (sig_handler_t)timeout);
	timedout = 1;
	siglongjmp(intbuf, 1);
}

/*
 * Stolen from consh() -- puts a remote file on the output of a local command.
 *	Identical to consh() except for where stdout goes.
 */
pipeout(c)
{
	char buf[256];
	int cpid, status, p;
	time_t start;

	putchar(c);
	if (prompt("Local command? ", buf, sizeof (buf)))
		return;
	kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	intr("on");
	read(repdes[0], (char *)&ccc, 1);
	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
	} else {
		register int i;

		userperm();
		dup2(FD, 1);
		for (i = 3; i < 20; i++)
			close(i);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		execute(buf);
		printf("can't find `%s'\r\n", buf);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		prtime("away for ", time(0)-start);
	write(fildes[1], (char *)&ccc, 1);
	intr("off");
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
}

/*
 * Fork a program with:
 *  0 <-> remote tty in
 *  1 <-> remote tty out
 *  2 <-> local tty stderr out
 */
consh(c)
{
	char buf[256];
	int cpid, status, p;
	void (*ointr)(), (*oquit)();
	time_t start;

	putchar(c);
	if (prompt("Local command? ", buf, sizeof (buf)))
		return;
	kill(pid, SIGIOT);	/* put TIPOUT into a wait state */
	read(repdes[0], (char *)&ccc, 1);
	ointr = signal(SIGINT, SIG_IGN);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	/*
	 * Set up file descriptors in the child and
	 *  let it go...
	 */
	if ((cpid = fork()) < 0)
		printf("can't fork!\r\n");
	else if (cpid) {
		start = time(0);
		while ((p = wait(&status)) > 0 && p != cpid)
			;
		raw();
		signal(SIGINT, ointr);
		signal(SIGQUIT, oquit);
	} else {
		register int i;

		userperm();
		dup2(FD, 0);
		dup2(0, 1);
		for (i = 3; i < 20; i++)
			close(i);
		signal(SIGINT, SIG_DFL);
		signal(SIGQUIT, SIG_DFL);
		execute(buf);
		printf("can't find `%s'\r\n", buf);
		exit(0);
	}
	if (boolean(value(VERBOSE)))
		prtime("\r\naway for ", time(0)-start);
	write(fildes[1], (char *)&ccc, 1);
}

/*
 * Escape to local shell
 */
shell()
{
	int shpid, status;
	void (*ointr)(), (*oquit)();
	char *cp;

	printf("[sh]\r\n");
	ointr = signal(SIGINT, SIG_IGN);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	if (shpid = fork()) {
		while (shpid != wait(&status))
			;
		raw();
		printf("\r\n!\r\n");
		signal(SIGINT, ointr);
		signal(SIGQUIT, oquit);
	} else {
		userperm();
		signal(SIGQUIT, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		if ((cp = strrchr(value(SHELL), '/')) == NULL)
			cp = value(SHELL);
		else
			cp++;
		execl(value(SHELL), cp, 0);
		printf("\r\ncan't execl!\r\n");
		exit(1);
	}
}

/*
 * TIPIN portion of scripting
 *   initiate the conversation with TIPOUT
 */
setscript()
{
	char c;
	/*
	 * enable TIPOUT side for dialogue
	 */
	kill(pid, SIGEMT);
	if (boolean(value(SCRIPT)))
		write(fildes[1], value(RECORD), strlen(value(RECORD)));
	write(fildes[1], "\n", 1);
	/*
	 * wait for TIPOUT to finish
	 */
	read(repdes[0], &c, 1);
	if (c == 'n')
		fprintf(stderr, "tip: can't create record file %s\r\n",
		    value(RECORD));
}

/*
 * Change current working directory of
 *   local portion of tip
 */
chdirectory()
{
	char dirname[80];
	register char *cp = dirname;

	if (prompt("[cd] ", dirname, sizeof (dirname))) {
		if (stoprompt)
			return;
		cp = value(HOME);
	}
	if (chdir(cp) < 0)
		printf("%s: bad directory\r\n", cp);
	printf("!\r\n");
}

/* XXX - really should rename this routine to avoid conflict with libc */
abort(msg)
	char *msg;
{

	signal(SIGCHLD, SIG_DFL);	/* don't want to hear about our child */
	kill(pid, SIGTERM);
	myperm();
	disconnect(msg);
	if (msg != NOSTR)
		printf("\r\n%s", msg);
	printf("\r\n[EOT]\r\n");
	delock(uucplock);
	unraw();
	exit(0);
}

finish()
{
	char *dismsg;

	if ((dismsg = value(DISCONNECT)) != NOSTR) {
		write(FD, dismsg, strlen(dismsg));
		sleep(5);
	}
	abort(NOSTR);
}

void
intcopy()
{

	signal(SIGINT, SIG_IGN);
	siglongjmp(intbuf, 1);
}

execute(s)
	char *s;
{
	register char *cp;

	if ((cp = strrchr(value(SHELL), '/')) == NULL)
		cp = value(SHELL);
	else
		cp++;
	execl(value(SHELL), cp, "-c", s, 0);
}

args(buf, a, na)
	char *buf, *a[];
	size_t na;
{
	register char *p = buf, *start;
	register char **parg = a;
	register int n = 0;

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

prtime(s, a)
	char *s;
	time_t a;
{
	register i;
	int nums[3];

	for (i = 0; i < 3; i++) {
		nums[i] = (int)(a % quant[i]);
		a /= quant[i];
	}
	printf("%s", s);
	while (--i >= 0)
		if (nums[i] || i == 0 && nums[1] == 0 && nums[2] == 0)
			printf("%d %s%c ", nums[i], sep[i],
				nums[i] == 1 ? '\0' : 's');
	printf("\r\n!\r\n");
}

variable()
{
	char	buf[256];

	if (prompt("[set] ", buf, sizeof (buf)))
		return;
	vlex(buf);
	if (vtable[BEAUTIFY].v_access&CHANGED) {
		vtable[BEAUTIFY].v_access &= ~CHANGED;
		kill(pid, SIGSYS);
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
tandem(option)
	char *option;
{
	struct termios rmtty;

	ioctl(FD, TCGETS, (char *)&rmtty);
	if (equal(option, "on")) {
		rmtty.c_iflag |= IXOFF|IXON;
		arg.c_iflag |= IXOFF|IXON;
		rmtty.c_cc[VSTART] = defarg.c_cc[VSTART];
		rmtty.c_cc[VSTOP] = defarg.c_cc[VSTOP];
	} else {
		rmtty.c_iflag &= ~(IXOFF|IXON);
		arg.c_iflag &= ~(IXOFF|IXON);
	}
	ioctl(FD, TCSETSF, (char *)&rmtty);
	ioctl(0, TCSETSF, (char *)&arg);
}

/*
 * Turn hardwareflow mode on or off for remote tty.
 */
hardwareflow(option)
	char *option;
{
	struct termios rmtty;

	ioctl(FD, TCGETS, (char *)&rmtty);
	if (equal(option, "on")) {
		rmtty.c_cflag |= (CRTSCTS|CRTSXOFF);
	} else {
		rmtty.c_cflag &= ~(CRTSCTS|CRTSXOFF);
	}
	ioctl(FD, TCSETSF, (char *)&rmtty);
}

/*
 * Turn interrupts from local tty on or off.
 */
intr(option)
	char *option;
{

	if (equal(option, "on"))
		arg.c_lflag |= ISIG;
	else
		arg.c_lflag &= ~ISIG;
	ioctl(0, TCSETSF, (char *)&arg);
}

/*
 * Send a break.
 */
genbrk()
{

	ioctl(FD, TCSBRK, 0);
}

/*
 * Suspend tip
 */
suspend(c)
	char c;
{

	unraw();
	kill(c == _CTRL('y') ? getpid() : 0, SIGTSTP);
	raw();
}

/*
 *	expand a file name if it includes shell meta characters
 */

char *
expand(name)
	char name[];
{
	static char xname[BUFSIZ];
	char cmdbuf[BUFSIZ];
	register int pid, l, rc;
	register char *cp, *Shell;
	int s, pivec[2];
	void (*sigint)();

	if (!anyof(name, "~{[*?$`'\"\\"))
		return (name);
	/* sigint = signal(SIGINT, SIG_IGN); */
	if (pipe(pivec) < 0) {
		perror("pipe");
		/* signal(SIGINT, sigint) */
		return (name);
	}
	sprintf(cmdbuf, "echo %s", name);
	if ((pid = vfork()) == 0) {
		userperm();
		Shell = value(SHELL);
		if (Shell == NOSTR)
			Shell = "/bin/sh";
		close(pivec[0]);
		close(1);
		dup(pivec[1]);
		close(pivec[1]);
		close(2);
		execl(Shell, Shell, "-c", cmdbuf, 0);
		_exit(1);
	}
	if (pid == -1) {
		perror("fork");
		close(pivec[0]);
		close(pivec[1]);
		return (NOSTR);
	}
	close(pivec[1]);
	l = read(pivec[0], xname, BUFSIZ);
	close(pivec[0]);
	while (wait(&s) != pid);
		;
	s &= 0377;
	if (s != 0 && s != SIGPIPE) {
		fprintf(stderr, "\"Echo\" failed\n");
		return (NOSTR);
	}
	if (l < 0) {
		perror("read");
		return (NOSTR);
	}
	if (l == 0) {
		fprintf(stderr, "\"%s\": No match\n", name);
		return (NOSTR);
	}
	if (l == BUFSIZ) {
		fprintf(stderr, "Buffer overflow expanding \"%s\"\n", name);
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

anyof(s1, s2)
	register char *s1, *s2;
{
	register int c;

	while (c = *s1++)
		if (any(c, s2))
			return (1);
	return (0);
}
