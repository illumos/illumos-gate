/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012 Gary Mills
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *	tput - print terminal attribute
 *
 *  return-codes - command line arguments:
 *	0: ok if boolean capname -> TRUE
 *	1: for boolean capname -> FALSE
 *
 *  return-codes - standard input arguments:
 *	0: ok; tput for all lines was successful
 *
 *  return-codes - both cases:
 *	2	usage error
 *	3	bad terminal type given or no terminfo database
 *	4	unknown capname
 *	-1	capname is a numeric variable that is not specified in the
 *		terminfo database(E.g. tpu -T450 lines).
 *
 *  tput printfs a value if an INT capname was given; e.g. cols.
 *	putp's a string if a STRING capname was given; e.g. clear. and
 *  for BOOLEAN capnames, e.g. hard-copy, just returns the boolean value.
 */

#include <curses.h>
#include <term.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <locale.h>

/* externs from libcurses */
extern int tigetnum();

static int outputcap(char *cap, int argc, char **argv);
static int allnumeric(char *string);
static int getpad(char *cap);
static void setdelay();
static void settabs();
static void cat(char *file);
static void initterm();
static void reset_term();

static char *progname;		/* argv[0] */
static int CurrentBaudRate;	/* current baud rate */
static int reset = 0;		/* called as reset_term */
static int fildes = 1;

int
main(int argc, char **argv)
{
	int i, std_argc;
	char *term = getenv("TERM");
	char *cap, std_input = FALSE;
	int setuperr;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];

	while ((i = getopt(argc, argv, "ST:")) != EOF) {
		switch (i) {
		case 'T':
			fildes = -1;
			(void) putenv("LINES=");
			(void) putenv("COLUMNS=");
			term = optarg;
			break;

		case 'S':
			std_input = TRUE;
			break;

		case '?':			/* FALLTHROUGH		*/
		usage:				/* FALLTHROUGH		*/
		default:
			(void) fprintf(stderr, gettext(
			    "usage:\t%s [-T [term]] capname "
			    "[parm argument...]\n"), progname);
			(void) fprintf(stderr, gettext("OR:\t%s -S <<\n"),
			    progname);
			exit(2);
		}
	}

	if (!term || !*term) {
		(void) fprintf(stderr,
		    gettext("%s: No value for $TERM and no -T specified\n"),
		    progname);
		exit(2);
	}

	(void) setupterm(term, fildes, &setuperr);

	switch (setuperr) {
	case -2:
		(void) fprintf(stderr,
		    gettext("%s: unreadable terminal descriptor \"%s\"\n"),
		    progname, term);
		exit(3);
		break;

	case -1:
		(void) fprintf(stderr,
		    gettext("%s: no terminfo database\n"), progname);
		exit(3);
		break;

	case 0:
		(void) fprintf(stderr,
		    gettext("%s: unknown terminal \"%s\"\n"),
		    progname, term);
		exit(3);
	}

	reset_shell_mode();

	/* command line arguments */
	if (!std_input) {
		if (argc == optind)
			goto usage;

		cap = argv[optind++];

		if (strcmp(cap, "init") == 0)
			initterm();
		else if (strcmp(cap, "reset") == 0)
			reset_term();
		else if (strcmp(cap, "longname") == 0)
			(void) printf("%s\n", longname());
		else
			exit(outputcap(cap, argc, argv));
		return (0);
	} else {			/* standard input argumets	*/
		char buff[128];
		char **v;

		/* allocate storage for the 'faked' argv[] array	*/
		v = (char **)malloc(10 * sizeof (char *));
		for (i = 0; i < 10; i++)
			v[i] = (char *)malloc(32 * sizeof (char));

		while (fgets(buff, sizeof (buff), stdin) != NULL) {
			/* read standard input line; skip over empty lines */
			if ((std_argc =
			    sscanf(buff,
			    "%31s %31s %31s %31s %31s %31s %31s %31s "
			    "%31s %31s",
			    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
			    v[8], v[9])) < 1) {
				continue;
			}

			cap = v[0];
			optind = 1;

			if (strcmp(cap, "init") == 0) {
				initterm();
			} else if (strcmp(cap, "reset") == 0) {
				reset_term();
			} else if (strcmp(cap, "longname") == 0) {
				(void) printf("%s\n", longname());
			} else {
				(void) outputcap(cap, std_argc, v);
			}
			(void) fflush(stdout);
		}

		return (0);
	}
}

static long parm[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0
};

static int
outputcap(char *cap, int argc, char **argv)
{
	int parmset = 0;
	char *thisstr;
	int i;

	if ((i = tigetflag(cap)) >= 0)
		return (1 - i);

	if ((i = tigetnum(cap)) >= -1) {
		(void) printf("%d\n", i);
		return (0);
	}

	if ((thisstr = tigetstr(cap)) != (char *)-1) {
		if (!thisstr) {
			return (1);
		}
		for (parmset = 0; optind < argc; optind++, parmset++)
			if (allnumeric(argv[optind]))
				parm[parmset] = atoi(argv[optind]);
			else
				parm[parmset] = (int)argv[optind];

		if (parmset)
			putp(tparm(thisstr,
			    parm[0], parm[1], parm[2], parm[3],
			    parm[4], parm[5], parm[6], parm[7], parm[8]));
		else
			putp(thisstr);
		return (0);
	}

	(void) fprintf(stderr,
	    gettext("%s: unknown terminfo capability '%s'\n"), progname, cap);

	exit(4);
	/* NOTREACHED */
}

/*
 *  The decision as to whether an argument is a number or not is to simply
 *  look at whether there are any non-digits in the string.
 */
static int
allnumeric(char *string)
{
	if (*string) {
		while (*string) {
			if (!isdigit(*string++)) {
				return (0);
			}
		}
		return (1);
	} else {
		return (0);
	}
}

/*
 *  SYSTEM DEPENDENT TERMINAL DELAY TABLES
 *
 *	These tables maintain the correspondence between the delays
 *	defined in terminfo and the delay algorithms in the tty driver
 *	on the particular systems. For each type of delay, the bits used
 *	for that delay must be specified, in XXbits, and a table
 *	must be defined giving correspondences between delays and
 *	algorithms. Algorithms which are not fixed delays, such
 *	as dependent on current column or line number, must be
 *	kludged in some way at this time.
 *
 *	Some of this was taken from tset(1).
 */

struct delay
{
    int d_delay;
    int d_bits;
};

/* The appropriate speeds for various termio settings. */
static int speeds[] = {
		0,	/*  B0,		*/
		50,	/*  B50,	*/
		75,	/*  B75,	*/
		110,	/*  B110,	*/
		134,	/*  B134,	*/
		150,	/*  B150,	*/
		200,	/*  B200,	*/
		300,	/*  B300,	*/
		600,	/*  B600,	*/
		1200,	/*  B1200,	*/
		1800,	/*  B1800,	*/
		2400,	/*  B2400,	*/
		4800,	/*  B4800,	*/
		9600,	/*  B9600,	*/
		19200,	/*  EXTA,	*/
		38400,	/*  EXTB,	*/
		57600,	/*  B57600,	*/
		76800,	/*  B76800,	*/
		115200,	/*  B115200,	*/
		153600,	/*  B153600,	*/
		230400,	/*  B230400,	*/
		307200,	/*  B307200,	*/
		460800,	/*  B460800,	*/
		921600, /*  B921600,	*/
		0,
};

#if defined(SYSV) || defined(USG)
/*	Unix 3.0 on up */

/*    Carriage Return delays	*/

static int	CRbits = CRDLY;
static struct delay	CRdelay[] =
{
	0,	CR0,
	80,	CR1,
	100,	CR2,
	150,	CR3,
	-1
};

/*	New Line delays	*/

static int	NLbits = NLDLY;
static struct delay	NLdelay[] =
{
	0,	NL0,
	100,	NL1,
	-1
};

/*	Back Space delays	*/

static int	BSbits = BSDLY;
static struct delay	BSdelay[] =
{
	0,	BS0,
	50,	BS1,
	-1
};

/*	TaB delays	*/

static int	TBbits = TABDLY;
static struct delay	TBdelay[] =
{
	0,	TAB0,
	11,	TAB1,		/* special M37 delay */
	100,	TAB2,
				/* TAB3 is XTABS and not a delay */
	-1
};

/*	Form Feed delays	*/

static int	FFbits = FFDLY;
static struct delay	FFdelay[] =
{
	0,	FF0,
	2000,	FF1,
	-1
};

#else	/* BSD */

/*	Carriage Return delays	*/

int	CRbits = CRDELAY;
struct delay	CRdelay[] =
{
	0,	CR0,
	9,	CR3,
	80,	CR1,
	160,	CR2,
	-1
};

/*	New Line delays	*/

int	NLbits = NLDELAY;
struct delay	NLdelay[] =
{
	0,	NL0,
	66,	NL1,		/* special M37 delay */
	100,	NL2,
	-1
};

/*	Tab delays	*/

int	TBbits = TBDELAY;
struct delay	TBdelay[] =
{
	0,	TAB0,
	11,	TAB1,		/* special M37 delay */
	-1
};

/*	Form Feed delays	*/

int	FFbits = VTDELAY;
struct delay	FFdelay[] =
{
	0,	FF0,
	2000,	FF1,
	-1
};
#endif	/* BSD */

/*
 *  Initterm, a.k.a. reset_term, does terminal specific initialization. In
 *  particular, the init_strings from terminfo are output and tabs are
 *  set, if they aren't hardwired in. Much of this stuff was done by
 *  the tset(1) program.
 */

/*
 *  Figure out how many milliseconds of padding the capability cap
 *  needs and return that number. Padding is stored in the string as "$<n>",
 *  where n is the number of milliseconds of padding. More than one
 *  padding string is allowed within the string, although this is unlikely.
 */

static int
getpad(char *cap)
{
	int padding = 0;

	/* No padding needed at speeds below padding_baud_rate */
	if (padding_baud_rate > CurrentBaudRate || cap == NULL)
		return (0);

	while (*cap) {
		if ((cap[0] == '$') && (cap[1] == '<')) {
			cap++;
			cap++;
			padding += atoi(cap);
			while (isdigit (*cap))
				cap++;
			while (*cap == '.' || *cap == '/' || *cap == '*' ||
			    isdigit(*cap))
				cap++;
			while (*cap == '>')
				cap++;
		} else {
			cap++;
		}
	}

	return (padding);
}

/*
 *  Set the appropriate delay bits in the termio structure for
 *  the given delay.
 */
static void
setdelay(delay, delaytable, bits, flags)
register int delay;
struct delay delaytable[];
int bits;
#ifdef SYSV
tcflag_t *flags;
#else	/* SYSV */
unsigned short *flags;
#endif	/* SYSV */
{
	register struct delay  *p;
	register struct delay  *lastdelay;

	/* Clear out the bits, replace with new ones */
	*flags &= ~bits;

	/* Scan the delay table for first entry with adequate delay */
	for (lastdelay = p = delaytable;
	    (p -> d_delay >= 0) && (p -> d_delay < delay);
	    p++) {
		lastdelay = p;
	}

	/* use last entry if none will do */
	*flags |= lastdelay -> d_bits;
}

/*
 * Set the hardware tabs on the terminal, using clear_all_tabs,
 * set_tab, and column_address capabilities. Cursor_address and cursor_right
 * may also be used, if necessary.
 * This is done before the init_file and init_3string, so they can patch in
 * case we blow this.
 */

static void
settabs()
{
	register int c;

	/* Do not set tabs if they power up properly. */
	if (init_tabs == 8)
		return;

	if (set_tab) {
		/* Force the cursor to be at the left margin. */
		if (carriage_return)
			putp(carriage_return);
		else
			(void) putchar('\r');

		/* Clear any current tab settings. */
		if (clear_all_tabs)
			putp(clear_all_tabs);

		/* Set the tabs. */
		for (c = 8; c < columns; c += 8) {
			/* Get to that column. */
			(void) fputs("        ", stdout);

			/* Set the tab. */
			putp(set_tab);
		}

		/* Get back to the left column. */
		if (carriage_return)
			putp(carriage_return);
		else
			(void) putchar('\r');

	}
}

/*
 *  Copy "file" onto standard output.
 */

static void
cat(file)
char *file;				/* File to copy. */
{
	register int fd;			/* File descriptor. */
	register ssize_t i;			/* Number characters read. */
	char buf[BUFSIZ];			/* Buffer to read into. */

	fd = open(file, O_RDONLY);

	if (fd < 0) {
		perror("Cannot open initialization file");
	} else {
		while ((i = read(fd, buf, BUFSIZ)) > (ssize_t)0)
			(void) write(fileno(stdout), buf, (unsigned)i);
		(int)close(fd);
	}
}

/*
 *  Initialize the terminal.
 *  Send the initialization strings to the terminal.
 */

static void
initterm()
{
	register int filedes;		/* File descriptor for ioctl's. */
#if defined(SYSV) || defined(USG)
	struct termio termmode;		/* To hold terminal settings. */
	struct termios termmodes;	/* To hold terminal settings. */
	int i;
	int istermios = -1;
#define	GTTY(fd, mode)	ioctl(fd, TCGETA, mode)
#define	GTTYS(fd, mode) \
	(istermios = ioctl(fd, TCGETS, mode))
#define	STTY(fd, mode)	ioctl(fd, TCSETAW, mode)
#define	STTYS(fd, mode)	ioctl(fd, TCSETSW, mode)
#define	SPEED(mode)	(mode.c_cflag & CBAUD)
#define	SPEEDS(mode)	(cfgetospeed(&mode))
#define	OFLAG(mode)	mode.c_oflag
#else	/* BSD */
	struct sgttyb termmode;		/* To hold terminal settings. */
#define	GTTY(fd, mode)	gtty(fd, mode)
#define	STTY(fd, mode)	stty(fd, mode)
#define	SPEED(mode)	(mode.sg_ospeed & 017)
#define	OFLAG(mode)	mode.sg_flags
#define	TAB3		XTABS
#endif

	/* Get the terminal settings. */
	/* First try standard output, then standard error, */
	/* then standard input, then /dev/tty. */
#ifdef SYSV
	if ((filedes = 1, GTTYS(filedes, &termmodes) < 0) ||
	    (filedes = 2, GTTYS(filedes, &termmodes) < 0) ||
	    (filedes = 0, GTTYS(filedes, &termmodes) < 0) ||
	    (filedes = open("/dev/tty", O_RDWR),
	    GTTYS(filedes, &termmodes) < 0)) {
#endif	/* SYSV */
		if ((filedes = 1, GTTY(filedes, &termmode) == -1) ||
		    (filedes = 2, GTTY(filedes, &termmode) == -1) ||
		    (filedes = 0, GTTY(filedes, &termmode) == -1) ||
		    (filedes = open("/dev/tty", O_RDWR),
		    GTTY(filedes, &termmode) == -1)) {
			filedes = -1;
			CurrentBaudRate = speeds[B1200];
		} else
			CurrentBaudRate = speeds[SPEED(termmode)];
#ifdef SYSV
		termmodes.c_lflag = termmode.c_lflag;
		termmodes.c_oflag = termmode.c_oflag;
		termmodes.c_iflag = termmode.c_iflag;
		termmodes.c_cflag = termmode.c_cflag;
		for (i = 0; i < NCC; i++)
			termmodes.c_cc[i] = termmode.c_cc[i];
	} else
		CurrentBaudRate = speeds[SPEEDS(termmodes)];
#endif	/* SYSV */

	if (xon_xoff) {
#ifdef SYSV
		OFLAG(termmodes) &=
		    ~(NLbits | CRbits | BSbits | FFbits | TBbits);
#else	/* SYSV */
		OFLAG(termmode) &=
		    ~(NLbits | CRbits | BSbits | FFbits | TBbits);
#endif	/* SYSV */
	} else {
#ifdef SYSV
		setdelay(getpad(carriage_return),
		    CRdelay, CRbits, &OFLAG(termmodes));
		setdelay(getpad(scroll_forward),
		    NLdelay, NLbits, &OFLAG(termmodes));
		setdelay(getpad(cursor_left),
		    BSdelay, BSbits, &OFLAG(termmodes));
		setdelay(getpad(form_feed),
		    FFdelay, FFbits, &OFLAG(termmodes));
		setdelay(getpad(tab),
		    TBdelay, TBbits, &OFLAG(termmodes));
#else	/* SYSV */
		setdelay(getpad(carriage_return),
		    CRdelay, CRbits, &OFLAG(termmode));
		setdelay(getpad(scroll_forward),
		    NLdelay, NLbits, &OFLAG(termmode));
		setdelay(getpad(cursor_left),
		    BSdelay, BSbits, &OFLAG(termmode));
		setdelay(getpad(form_feed),
		    FFdelay, FFbits, &OFLAG(termmode));
		setdelay(getpad(tab),
		    TBdelay, TBbits, &OFLAG(termmode));
#endif	/* SYSV */
	}

	/* If tabs can be sent to the tty, turn off their expansion. */
	if (tab && set_tab || init_tabs == 8) {
#ifdef SYSV
		OFLAG(termmodes) &= ~(TAB3);
#else	/* SYSV */
		OFLAG(termmode) &= ~(TAB3);
#endif	/* SYSV */
	} else {
#ifdef SYSV
		OFLAG(termmodes) |= TAB3;
#else	/* SYSV */
		OFLAG(termmode) |= TAB3;
#endif	/* SYSV */
	}

	/* Do the changes to the terminal settings */
#ifdef SYSV
	if (istermios < 0) {
		int i;

		termmode.c_lflag = termmodes.c_lflag;
		termmode.c_oflag = termmodes.c_oflag;
		termmode.c_iflag = termmodes.c_iflag;
		termmode.c_cflag = termmodes.c_cflag;
		for (i = 0; i < NCC; i++)
			termmode.c_cc[i] = termmodes.c_cc[i];
		(void) STTY(filedes, &termmode);
	} else
		(void) STTYS(filedes, &termmodes);

#else	/* SYSV */
	(void) STTY(filedes, &termmode);
#endif	/* SYSV */

	/* Send first initialization strings. */
	if (init_prog)
	(void) system(init_prog);

	if (reset && reset_1string) {
		putp(reset_1string);
	} else if (init_1string) {
		putp(init_1string);
	}

	if (reset && reset_2string) {
		putp(reset_2string);
	} else if (init_2string) {
		putp(init_2string);
	}

	/* Set up the tabs stops. */
	settabs();

	/* Send out initializing file. */
	if (reset && reset_file) {
		cat(reset_file);
	} else if (init_file) {
		cat(init_file);
	}

	/* Send final initialization strings. */
	if (reset && reset_3string) {
		putp(reset_3string);
	} else if (init_3string) {
		putp(init_3string);
	}

	if (carriage_return) {
		putp(carriage_return);
	} else {
		(void) putchar('\r');
	}

	/* Send color initialization strings */

	if (orig_colors)
		putp(orig_colors);

	if (orig_pair)
	putp(orig_pair);

	/* Let the terminal settle down. */
	(void) fflush(stdout);
	(void) sleep(1);
}

static void
reset_term()
{
	reset++;
	initterm();
}
