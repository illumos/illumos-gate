/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* from UCB 5.4 4/3/86 */

/*
 * tip - UNIX link to other systems
 *  tip [-v] [-speed] system-name
 * or
 *  cu phone-number [-s speed] [-l line] [-a acu]
 */
#include "tip.h"
#include <sys/wait.h>
#include <locale.h>

/*
 * Baud rate mapping table
 */
int bauds[] = {
	0, 50, 75, 110, 134, 150, 200, 300, 600,
	1200, 1800, 2400, 4800, 9600, 19200, 38400,
	57600, 76800, 115200, 153600, 230400, 307200, 460800, -1
};

void	intprompt();
void	timeout();
void	deadkid();
void	cleanup();
char	*sname();
char	PNbuf[256];			/* This limits the size of a number */
int	noparity = 0;


main(argc, argv)
	char *argv[];
{
	char *system = NOSTR;
	register int i;
	register char *p;
	char sbuf[12];

	gid = getgid();
	egid = getegid();
	uid = getuid();
	euid = geteuid();
	if (equal(sname(argv[0]), "cu")) {
		cumode = 1;
		cumain(argc, argv);
		goto cucommon;
	}

	if (argc > 4) {
		fprintf(stderr, "usage: tip [-v] [-speed] [system-name]\n");
		exit(1);
	}
	if (!isatty(0)) {
		fprintf(stderr, "tip: must be interactive\n");
		exit(1);
	}

	for (; argc > 1; argv++, argc--) {
		if (argv[1][0] != '-')
			system = argv[1];
		else switch (argv[1][1]) {

		case 'v':
			vflag++;
			break;

		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			BR = atoi(&argv[1][1]);
			break;

		default:
			fprintf(stderr, "tip: %s, unknown option\n", argv[1]);
			break;
		}
	}

	(void) setlocale(LC_CTYPE, "");

	if (system == NOSTR)
		goto notnumber;
	for (p = system; *p; p++)
		if (isalpha(*p))
			goto notnumber;
	/*
	 * System name is really a phone number...
	 * Copy the number then stomp on the original (in case the number
	 *	is private, we don't want 'ps' or 'w' to find it).
	 */
	if (strlen(system) > sizeof (PNbuf) - 1) {
		fprintf(stderr, "tip: phone number too long (max = %d bytes)\n",
		    sizeof (PNbuf) - 1);
		exit(1);
	}
	strncpy(PNbuf, system, sizeof (PNbuf) - 1);
	for (p = system; *p; p++)
		*p = '\0';
	PN = PNbuf;
	sprintf(sbuf, "tip%d", BR);
	system = sbuf;

notnumber:
	signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);
	signal(SIGHUP, cleanup);
	signal(SIGTERM, cleanup);

	if ((i = hunt(system)) == 0) {
		printf("all ports busy\n");
		exit(3);
	}
	if (i == -1) {
		printf("link down\n");
		delock(uucplock);
		exit(3);
	}
	setbuf(stdout, NULL);
	loginit();

	/*
	 * Now that we have the logfile and the ACU open
	 *  return to the real uid and gid.  These things will
	 *  be closed on exit.  The saved-setuid uid and gid
	 *  allows us to get the original setuid permissions back
	 *  for removing the uucp lock.
	 */
	userperm();

	/*
	 * Kludge, there's no easy way to get the initialization
	 *   in the right order, so force it here.
	 * Do the open here, before we change back to real uid.
	 * We will check whether the open succeeded later, when
	 * (and if) we actually go to use the file.
	 */
	if ((PH = getenv("PHONES")) == NOSTR) {
		myperm();
		PH = "/etc/phones";
	}
	phfd = fopen(PH, "r");

	userperm();

	vinit();				/* init variables */
	setparity("none");			/* set the parity table */
	if ((i = speed(number(value(BAUDRATE)))) == NULL) {
		printf("tip: bad baud rate %d\n", number(value(BAUDRATE)));
		myperm();
		delock(uucplock);
		exit(3);
	}


	/*
	 * Hardwired connections require the
	 *  line speed set before they make any transmissions
	 *  (this is particularly true of things like a DF03-AC)
	 */
	if (HW)
		ttysetup(i);
	if (p = connect()) {
		printf("\07%s\n[EOT]\n", p);
		myperm();
		delock(uucplock);
		exit(1);
	}

	/*
	 * Always setup the tty again here in case hardware flow
	 *  control was selected, which can only be set after the
	 *  connection is made, or in case this is not a hardwired
	 *  modem (rare these days) that likewise can only be setup
	 *  after the connection is made.
	 */
	ttysetup(i);
cucommon:
	/*
	 * From here down the code is shared with
	 * the "cu" version of tip.
	 */

	ioctl(0, TCGETS, (char *)&defarg);
	arg = defarg;
	/* turn off input processing */
	arg.c_lflag &= ~(ICANON|ISIG|ECHO|IEXTEN);
	arg.c_cc[VMIN] = 1;
	arg.c_cc[VTIME] = 0;
	arg.c_iflag &= ~(INPCK|IXON|IXOFF|ICRNL);
	arg.c_oflag = 0;		/* turn off all output processing */
	/* handle tandem mode in case was set in remote file */
	if (boolean(value(TAND)))
		tandem("on");
	else
		tandem("off");
	raw();

	pipe(fildes); pipe(repdes);
	signal(SIGALRM, timeout);

	/*
	 * Everything's set up now:
	 *	connection established (hardwired or dialup)
	 *	line conditioned (baud rate, mode, etc.)
	 *	internal data structures (variables)
	 * so, fork one process for local side and one for remote.
	 */
	if (CM != NOSTR) {
		sleep(2);	/* let line settle */
		parwrite(FD, CM, strlen(CM));
	}
	printf(cumode ? "Connected\r\n" : "\07connected\r\n");
	signal(SIGCHLD, deadkid);
	if (pid = fork())
		tipin();
	else
		tipout();
	/*NOTREACHED*/
}

void
deadkid()
{

	if (pid >= 0 && waitpid(pid, NULL, WNOHANG) == pid)
		abort("Connection Closed");
}

void
cleanup()
{

	if (uid != getuid()) {
		myperm();
	}
	delock(uucplock);
	exit(0);
}

/*
 * put the controlling keyboard into raw mode
 */
raw()
{

	ioctl(0, TCSETSF, (char *)&arg);
}


/*
 * return keyboard to normal mode
 */
unraw()
{

	ioctl(0, TCSETSF, (char *)&defarg);
}

/*
 * switch to using invoking user's permissions
 */
userperm()
{

	setegid(gid);
	seteuid(uid);
}

/*
 * switch to using my special (setuid) permissions
 */
myperm()
{

	setegid(egid);
	seteuid(euid);
}

static	sigjmp_buf promptbuf;

/*
 * Print string ``s'', then read a string
 *  in from the terminal.  Handles signals & allows use of
 *  normal erase and kill characters.
 */
prompt(s, p, len)
	char *s;
	register char *p;
	size_t len;
{
	register char *b = p;
	register int c;
	void (*ointr)(), (*oquit)();

	stoprompt = 0;
	ointr = signal(SIGINT, intprompt);
	oquit = signal(SIGQUIT, SIG_IGN);
	unraw();
	printf("%s", s);
	if (sigsetjmp(promptbuf, 1) == 0)
		while (p < b + len - 1 &&
		    ((c = getchar()) != EOF) && (c != '\n'))
			*p++ = c;
	*p = '\0';

	raw();
	signal(SIGINT, ointr);
	signal(SIGQUIT, oquit);
	return (stoprompt || p == b);
}

/*
 * Interrupt service routine during prompting
 */
void
intprompt()
{

	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	stoprompt = 1;
	printf("\r\n");
	siglongjmp(promptbuf, 1);
}

/*
 * ****TIPIN   TIPIN****
 */
tipin()
{
	unsigned char gch, c;
	int bol = 1;

	/*
	 * Kinda klugey here...
	 *   check for scripting being turned on from the .tiprc file,
	 *   but be careful about just using setscript(), as we may
	 *   send a SIGEMT before tipout has a chance to set up catching
	 *   it; so wait a second, then setscript()
	 */
	if (boolean(value(SCRIPT))) {
		sleep(1);
		setscript();
	}

	for (;;) {
		gch = getchar()&0377;
		if ((gch == character(value(ESCAPE))) && bol) {
			if (!(gch = escape()))
				continue;
		} else if (!cumode && gch == character(value(RAISECHAR))) {
			boolean(value(RAISE)) = !boolean(value(RAISE));
			continue;
		} else if (gch == '\r') {
			bol = 1;
			parwrite(FD, &gch, 1);
			if (boolean(value(HALFDUPLEX)))
				printf("\r\n");
			continue;
		} else if (!cumode && gch == character(value(FORCE)))
			gch = getchar()&0377;
		bol = any(gch, value(EOL));
		if (boolean(value(RAISE)) && islower(gch))
			gch = toupper(gch);
		c = gch;
		parwrite(FD, &gch, 1);
		if (boolean(value(HALFDUPLEX)))
			putchar(c);
	}
}

/*
 * Escape handler --
 *  called on recognition of ``escapec'' at the beginning of a line
 */
escape()
{
	register unsigned char gch;
	register esctable_t *p;
	char c = character(value(ESCAPE));
	extern esctable_t etable[];

	gch = (getchar()&0377);
	for (p = etable; p->e_char; p++)
		if (p->e_char == gch) {
			if ((p->e_flags&PRIV) && uid)
				continue;
			printf("%s", ctrl(c));
			(*p->e_func)(gch);
			return (0);
		}
	/* ESCAPE ESCAPE forces ESCAPE */
	if (c != gch)
		parwrite(FD, &c, 1);
	return (gch);
}

speed(n)
	int n;
{
	register int *p;

	for (p = bauds; *p != -1;  p++)
		if (*p == n)
			return (p - bauds);
	return (NULL);
}

any(c, p)
	register char c, *p;
{
	while (p && *p)
		if (*p++ == c)
			return (1);
	return (0);
}

char *
interp(s)
	register char *s;
{
	static char buf[256];
	register char *p = buf, c, *q;

	while (c = *s++) {
		for (q = "\nn\rr\tt\ff\033E\bb"; *q; q++)
			if (*q++ == c) {
				*p++ = '\\'; *p++ = *q;
				goto next;
			}
		if (c < 040) {
			*p++ = '^'; *p++ = c + 'A'-1;
		} else if (c == 0177) {
			*p++ = '^'; *p++ = '?';
		} else
			*p++ = c;
	next:
		;
	}
	*p = '\0';
	return (buf);
}

char *
ctrl(c)
	char c;
{
	static char s[3];

	if (c < 040 || c == 0177) {
		s[0] = '^';
		s[1] = c == 0177 ? '?' : c+'A'-1;
		s[2] = '\0';
	} else {
		s[0] = c;
		s[1] = '\0';
	}
	return (s);
}

/*
 * Help command
 */
help(c)
	char c;
{
	register esctable_t *p;
	extern esctable_t etable[];

	printf("%c\r\n", c);
	for (p = etable; p->e_char; p++) {
		if ((p->e_flags&PRIV) && uid)
			continue;
		printf("%2s", ctrl(character(value(ESCAPE))));
		printf("%-2s %c   %s\r\n", ctrl(p->e_char),
			p->e_flags&EXP ? '*': ' ', p->e_help);
	}
}

/*
 * Set up the "remote" tty's state
 */
ttysetup(speed)
	int speed;
{
	struct termios buf;
	char *loc;

	ioctl(FD, TCGETS, (char *)&buf);
	buf.c_cflag &= (CREAD|HUPCL|CLOCAL|CRTSCTS|CRTSXOFF);
	buf.c_cflag |= CS8;
	cfsetospeed(&buf, speed);
	if (boolean(value(HARDWAREFLOW))) {
		int i = TIOCM_CAR;

		/*
		 * Only set hardware flow control if carrier is up,
		 * because some devices require both CD and RTS to
		 * be up before sending.
		 */
		ioctl(FD, TIOCMGET, &i);
		if (i & TIOCM_CAR)
			buf.c_cflag |= (CRTSCTS|CRTSXOFF);
	}

	/*
	 * Careful to only penalize the 8-bit users here on the
	 * incoming tty port.  The default 7-bit users will
	 * still get the parity bit from the other side's login
	 * process (which happens to be the default for sun tip
	 * configurations).
	 */
	loc = setlocale(LC_CTYPE, NULL);
	if (noparity && loc != 0 && strcmp(loc, "C") != 0)
		buf.c_iflag = 0;
	else
		buf.c_iflag = ISTRIP;
	buf.c_oflag = 0;
	buf.c_lflag = 0;
	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;
	ioctl(FD, TCSETSF, (char *)&buf);
}

/*
 * Return "simple" name from a file name,
 * strip leading directories.
 */
char *
sname(s)
	register char *s;
{
	register char *p = s;

	while (*s)
		if (*s++ == '/')
			p = s;
	return (p);
}

static char partab[0400];

/*
 * Do a write to the remote machine with the correct parity.
 * We are doing 8 bit wide output, so we just generate a character
 * with the right parity and output it.
 */
parwrite(fd, buf, n)
	int fd;
	unsigned char *buf;
	register int n;
{
	register int i;
	register unsigned char *bp;
	extern int errno;

	bp = buf;
	for (i = 0; i < n; i++) {
		*bp = partab[(*bp)&0377];
		bp++;
	}
	if (write(fd, buf, n) < 0) {
		if (errno == EIO || errno == ENXIO)
			abort("Lost carrier.");
		/* this is questionable */
		perror("write");
	}
}

/*
 * Build a parity table with appropriate high-order bit.
 */
setparity(defparity)
	char *defparity;
{
	register int i;
	char *parity;
	extern char evenpartab[];

	if (value(PARITY) == NOSTR)
		value(PARITY) = defparity;
	parity = value(PARITY);
	for (i = 0; i < 0400; i++)
		partab[i] = evenpartab[i];
	if (equal(parity, "even"))
		;
	else if (equal(parity, "odd")) {
		for (i = 0; i < 0400; i++)
			partab[i] ^= 0200;	/* reverse bit 7 */
	} else if (equal(parity, "none")) {
		/* Do nothing so we can pass thru 8-bit chars */
		noparity = 1;
		for (i = 0; i < 0400; i++)
			partab[i] = i;
	} else if (equal(parity, "zero")) {
		for (i = 0; i < 0400; i++)
			partab[i] &= ~0200;	/* turn off bit 7 */
	} else if (equal(parity, "one")) {
		for (i = 0; i < 0400; i++)
			partab[i] |= 0200;	/* turn on bit 7 */
	} else {
		fprintf(stderr, "%s: unknown parity value\n", PA);
		fflush(stderr);
	}
}
