/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 *  TSET -- set terminal modes
 *
 *	This program does sophisticated terminal initialization.
 *	I recommend that you include it in your .profile or .login
 *	file to initialize whatever terminal you are on.
 *
 *	There are several features:
 *
 *	A special file or sequence (as controlled by the termcap file)
 *	is sent to the terminal.
 *
 *	Mode bits are set on a per-terminal_type basis (much better
 *	than UNIX itself).  This allows special delays, automatic
 *	tabs, etc.
 *
 *	Erase and Kill characters can be set to whatever you want.
 *	Default is to change erase to control-H on a terminal which
 *	can overstrike, and leave it alone on anything else.  Kill
 *	is always left alone unless specifically requested.  These
 *	characters can be represented as "^X" meaning control-X;
 *	X is any character.
 *
 *	Terminals which are dialups or plugboard types can be aliased
 *	to whatever type you may have in your home or office.  Thus,
 *	if you know that when you dial up you will always be on a
 *	TI 733, you can specify that fact to tset.  You can represent
 *	a type as "?type".  This will ask you what type you want it
 *	to be -- if you reply with just a newline, it will default
 *	to the type given.
 *
 *	The current terminal type can be queried.
 *
 *	Usage:
 *		tset [-] [-EC] [-eC] [-kC] [-iC] [-s] [-h] [-u] [-r]
 *			[-m [ident] [test baudrate] :type]
 *			[-Q] [-I] [-S] [type]
 *
 *		In systems with environments, use:
 *			eval `tset -s ...`
 *		Actually, this doesn't work in old csh's.
 *		Instead, use:
 *			tset -s ... > tset.tmp
 *			source tset.tmp
 *			rm tset.tmp
 *		or:
 *			set noglob
 *			set term=(`tset -S ....`)
 *			setenv TERM $term[1]
 *			setenv TERMCAP "$term[2]"
 *			unset term
 *			unset noglob
 *
 *	Positional Parameters:
 *		type -- the terminal type to force.  If this is
 *			specified, initialization is for this
 *			terminal type.
 *
 *	Flags:
 *		- -- report terminal type.  Whatever type is
 *			decided on is reported.  If no other flags
 *			are stated, the only affect is to write
 *			the terminal type on the standard output.
 *		-r -- report to user in addition to other flags.
 *		-EC -- set the erase character to C on all terminals
 *			except those which cannot backspace (e.g.,
 *			a TTY 33).  C defaults to control-H.
 *		-eC -- set the erase character to C on all terminals.
 *			C defaults to control-H.  If not specified,
 *			the erase character is untouched; however, if
 *			not specified and the erase character is NULL
 *			(zero byte), the erase character is set to CERASE.
 *		-kC -- set the kill character to C on all terminals.
 *			Default for C is control-U.  If not specified,
 *			the kill character is untouched; however, if
 *			not specified and the kill character is NULL
 *			(zero byte), the kill character is set to CKILL.
 *		-iC -- set the interrupt character to C on all terminals.
 *			Default for C is control-C.  If not specified, the
 *			interrupt character is untouched; however, if
 *			not specified and the interrupt character is NULL
 *			(zero byte), the interrupt character is set to
 *			control-C.
 *		-qC -- reserved for setable quit character.
 *		-m -- map the system identified type to some user
 *			specified type. The mapping can be baud rate
 *			dependent. This replaces the old -d, -p flags.
 *			(-d type  ->  -m dialup:type)
 *			(-p type  ->  -m plug:type)
 *			Syntax:	-m identifier [test baudrate] :type
 *			where: ``identifier'' is terminal type found in
 *			/etc/ttys for this port, (abscence of an identifier
 *			matches any identifier); ``test'' may be any combination
 *			of  >  =  <  !  @; ``baudrate'' is as with stty(1);
 *			``type'' is the actual terminal type to use if the
 *			mapping condition is met. Multiple maps are scanned
 *			in order and the first match prevails.
 *		-n -- If the new tty driver from UCB is available, this flag
 *			will activate the new options for erase and kill
 *			processing. This will be different for printers
 *			and crt's. For crts, if the baud rate is < 1200 then
 *			erase and kill don't remove characters from the screen.
 *		-h -- don't read htmp file.  Normally the terminal type
 *			is determined by reading the htmp file or the
 *			environment (unless some mapping is specified).
 *			This forces a read of the ttytype file -- useful
 *			when htmp is somehow wrong. (V6 only)
 *		-u -- don't update htmp.  It seemed like this should
 *			be put in.  Note that htmp is never actually
 *			written if there are no changes, so don't bother
 *			bother using this for efficiency reasons alone.
 *		-s -- output setenv commands for TERM.  This can be
 *			used with
 *				`tset -s ...`
 *			and is to be prefered to:
 *				setenv TERM `tset - ...`
 *			because -s sets the TERMCAP variable also.
 *		-S -- Similar to -s but outputs 2 strings suitable for
 *			use in csh .login files as follows:
 *				set noglob
 *				set term=(`tset -S .....`)
 *				setenv TERM $term[1]
 *				setenv TERMCAP "$term[2]"
 *				unset term
 *				unset noglob
 *		-Q -- be quiet.  don't output 'Erase set to' etc.
 *		-I -- don't do terminal initialization (is & if
 *			strings).
 *		-v -- On virtual terminal systems, don't set up a
 *			virtual terminal.  Otherwise tset will tell
 *			the operating system what kind of terminal you
 *			are on (if it is a known terminal) and fix up
 *			the output of -s to use virtual terminal sequences.
 *
 *	Files:
 *		/etc/ttys
 *			contains a terminal id -> terminal type
 *			mapping; used when any user mapping is specified,
 *			or the environment doesn't have TERM set.
 *		/etc/termcap
 *			a terminal_type -> terminal_capabilities
 *			mapping.
 *
 *	Return Codes:
 *		-1 -- couldn't open termcap.
 *		1 -- bad terminal type, or standard output not tty.
 *		0 -- ok.
 *
 *	Defined Constants:
 *		DIALUP -- the type code for a dialup port.
 *		PLUGBOARD -- the type code for a plugboard port.
 *		ARPANET -- the type code for an arpanet port.
 *		BACKSPACE -- control-H, the default for -e.
 *		CNTL('U') -- control-U, the default for -k.
 *		OLDERASE -- the ancient default erase character.
 *		FILEDES -- the file descriptor to do the operation
 *			on, nominally 1 or 2.
 *		STDOUT -- the standard output file descriptor.
 *		UIDMASK -- the bit pattern to mask with the getuid()
 *			call to get just the user id.
 *		GTTYN -- defines file containing generalized ttynames
 *			and compiles code to look there.
 *
 *	Requires:
 *		Routines to handle htmp, ttys, and termcap.
 *
 *	Compilation Flags:
 *		OLDFLAGS -- must be defined to compile code for any of
 *			the -d, -p, or -a flags.
 *		OLDDIALUP -- accept the -d flag.
 *		OLDPLUGBOARD -- accept the -p flag.
 *		OLDARPANET -- accept the -a flag.
 *		V6 -- if clear, use environments, not htmp.
 *			also use TIOCSETN rather than stty to avoid flushing
 *		GTTYN -- if set, compiles code to look at /etc/ttys.
 *
 *	Trace Flags:
 *		none
 *
 *	Diagnostics:
 *		Bad flag
 *			An incorrect option was specified.
 *		Too few args
 *			more command line arguments are required.
 *		Unexpected arg
 *			wrong type of argument was encountered.
 *		Cannot open ...
 *			The specified file could not be openned.
 *		Type ... unknown
 *			An unknown terminal type was specified.
 *		Cannot update htmp
 *			Cannot update htmp file when the standard
 *			output is not a terminal.
 *		Erase set to ...
 *			Telling that the erase character has been
 *			set to the specified character.
 *		Kill set to ...
 *			Ditto for kill
 *		Erase is ...    Kill is ...
 *			Tells that the erase/kill characters were
 *			wierd before, but they are being left as-is.
 *		Not a terminal
 *			Set if FILEDES is not a terminal.
 *
 *	Compilation Instructions:
 *		cc -n -O tset.c -ltermlib
 *		mv a.out tset
 *		chown bin tset
 *		chmod 4755 tset
 *
 *		where 'bin' should be whoever owns the 'htmp' file.
 *		If 'htmp' is 666, then tset need not be setuid.
 *
 *		For version 6 the compile command should be:
 *		cc -n -O -I/usr/include/retrofit tset.c -ltermlib -lretro -lS
 *
 *
 *	History:
 *		1/81 -- Added alias checking for mapping identifiers.
 *		7/80 -- '-S' added. '-m' mapping added. TERMCAP string
 *			cleaned up.
 *		3/80 -- Changed to use tputs.  Prc & flush added.
 *		10/79 -- '-s' option extended to handle TERMCAP
 *			variable, set noglob, quote the entry,
 *			and know about the Bourne shell.  Terminal
 *			initialization moved to before any information
 *			output so screen clears would not screw you.
 *			'-Q' option added.
 *		8/79 -- '-' option alone changed to only output
 *			type.  '-s' option added.  'VERSION7'
 *			changed to 'V6' for compatibility.
 *		12/78 -- modified for eventual migration to VAX/UNIX,
 *			so the '-' option is changed to output only
 *			the terminal type to STDOUT instead of
 *			FILEDES.
 *		9/78 -- '-' and '-p' options added (now fully
 *			compatible with ttytype!), and spaces are
 *			permitted between the -d and the type.
 *		8/78 -- The sense of -h and -u were reversed, and the
 *			-f flag is dropped -- same effect is available
 *			by just stating the terminal type.
 *		10/77 -- Written.
 */


#define	index strchr
#define	rindex strrchr
#define	curerase modes.c_cc[VERASE]
#define	curkill modes.c_cc[VKILL]
#define	curintr modes.c_cc[VINTR]
#define	olderase oldmodes.c_cc[VERASE]
#define	oldkill oldmodes.c_cc[VKILL]
#define	oldintr oldmodes.c_cc[VINTR]

#include	<stdio.h>
#include	<stdlib.h>
#include	<termio.h>
#include	<signal.h>


#define	YES		1
#define	NO		0
#undef CNTL
#define	CNTL(c)		((c)&037)
#define	BACKSPACE	(CNTL('H'))
#define	isdigit(c)	(c >= '0' && c <= '9')
#define	isalnum(c)	(c > ' ' && (index("<@=>!:|\177", c) == NULL))
#define	OLDERASE	'#'

/* default special characters */
#ifndef CERASE
#define	CERASE	'\177'
#endif
#ifndef CKILL
#define	CKILL	CNTL('U')
#endif
#ifndef CINTR
#define	CINTR	CNTL('C')
#endif
#ifndef CDSUSP
#define	CQUIT	034		/* FS, ^\ */
#define	CSTART	CNTL('Q')
#define	CSTOP	CNTL('S')
#define	CEOF	CNTL('D')
#define	CEOT	CEOF
#define	CBRK	0377
#define	CSUSP	CNTL('Z')
#define	CDSUSP	CNTL('Y')
#define	CRPRNT	CNTL('R')
#define	CFLUSH	CNTL('O')
#define	CWERASE	CNTL('W')
#define	CLNEXT	CNTL('V')
#endif

#define	FILEDES		2	/* do gtty/stty on this descriptor */
#define	STDOUT		1	/* output of -s/-S to this descriptor */

#define	UIDMASK		-1

#define	USAGE	"usage: tset [-] [-rsIQS] [-eC] [-kC] "	\
		"[-iC] [-m [ident][test speed]:type] [type]\n"

#define	OLDFLAGS
#define	DIALUP		"dialup"
#define	OLDDIALUP	"sd"
#define	PLUGBOARD	"plugboard"
#define	OLDPLUGBOARD	"sp"

#define	DEFTYPE		"unknown"

/*
 * Baud Rate Conditionals
 */
#define	ANY		0
#define	GT		1
#define	EQ		2
#define	LT		4
#define	GE		(GT|EQ)
#define	LE		(LT|EQ)
#define	NE		(GT|LT)
#define	ALL		(GT|EQ|LT)



#define	NMAP		10

struct	map {
	char *Ident;
	char Test;
	char Speed;
	char *Type;
} map[NMAP];

struct map *Map = map;

/* This should be available in an include file */
struct
{
	char	*string;
	int	speed;
	int	baudrate;
} speeds[] = {
	"0",	B0,	0,
	"50",	B50,	50,
	"75",	B75,	75,
	"110",	B110,	110,
	"134",	B134,	134,
	"134.5", B134,	134,
	"150",	B150,	150,
	"200",	B200,	200,
	"300",	B300,	300,
	"600",	B600,	600,
	"1200",	B1200,	1200,
	"1800",	B1800,	1800,
	"2400",	B2400,	2400,
	"4800",	B4800,	4800,
	"9600",	B9600,	9600,
	"19200", EXTA,	19200,
	"exta",	EXTA,	19200,
	"extb",	EXTB,	38400,
	"57600", B57600,	57600,
	"76800", B76800,	76800,
	"115200", B115200, 115200,
	"153600", B153600, 153600,
	"230400", B230400, 230400,
	"307200", B307200, 307200,
	"460800", B460800, 460800,
	"921600", B921600, 921600,
	0,
};

signed char Erase_char;		/* new erase character */
char	Kill_char;		/* new kill character */
char	Intr_char;		/* new interrupt character */
char	Specialerase;	/* set => Erase_char only on terminals with backspace */

char	*TtyType;		/* type of terminal */
char	*DefType;		/* default type if none other computed */
char	*NewType;		/* mapping identifier based on old flags */
int	Mapped;			/* mapping has been specified */
int	Dash_u;			/* don't update htmp */
int	Dash_h;			/* don't read htmp */
int	DoSetenv;		/* output setenv commands */
int	BeQuiet;		/* be quiet */
int	NoInit;			/* don't output initialization string */
int	IsReset;		/* invoked as reset */
int	Report;			/* report current type */
int	Ureport;		/* report to user */
int	RepOnly;		/* report only */
int	CmndLine;		/* output full command lines (-s option) */
int	Ask;			/* ask user for termtype */
int	DoVirtTerm = YES;	/* Set up a virtual terminal */
int	PadBaud;		/* Min rate of padding needed */

#define	CAPBUFSIZ	1024
char	Capbuf[CAPBUFSIZ];	/* line from /etc/termcap for this TtyType */
char	*Ttycap;		/* termcap line from termcap or environ */

char	Aliasbuf[128];
char	*Alias[16];

extern char *strcpy();
extern char *index();

struct delay
{
	int	d_delay;
	int	d_bits;
};

#include	"tset.delays.h"

struct termio	mode;
struct termio	oldmode;
struct termios	modes;
struct termios	oldmodes;
int		istermios;

void reportek(char *, char, char, char);
void setdelay(char *, struct delay [], tcflag_t, tcflag_t *);
void prs(char *);
void prc(char);
void flush(void);
void cat(char *);
void bmove(char *, char *, int);
void makealias(char *);
void wrtermcap(char *);
void fatal(char *, char *);
char reset();			/* Routine for checking&resetting chars */

int
main(int argc, char *argv[])
{
	char		buf[CAPBUFSIZ];
	char		termbuf[32];
	auto char	*bufp;
	char		*p;
	char		*command;
	int		i;
	int		Break;
	int		Not;
	char		*nextarg();
	char		*mapped();
	extern char	*rindex();
	struct winsize	win;
	extern char	*getenv();
	extern char	*tgetstr();
	char		bs_char;
	int		csh;
	int		settle = NO;
	void		setmode();
	extern char	PC;
	extern short	ospeed;

	if ((istermios = ioctl(FILEDES, TCGETS, (char *)&modes)) < 0) {
		if (ioctl(FILEDES, TCGETA, (char *)&mode) < 0) {
			prs("Not a terminal\n");
			exit(1);
		}
		bmove((char *)&mode, (char *)&oldmode, sizeof (mode));
		modes.c_lflag = oldmodes.c_lflag = mode.c_lflag;
		modes.c_oflag = oldmodes.c_oflag = mode.c_oflag;
		modes.c_iflag = oldmodes.c_iflag = mode.c_iflag;
		modes.c_cflag = oldmodes.c_cflag = mode.c_cflag;
		for (i = 0; i < NCC; i++)
			modes.c_cc[i] = oldmodes.c_cc[i] = mode.c_cc[i];
	} else
		bmove((char *)&modes, (char *)&oldmodes, sizeof (modes));
	ospeed = cfgetospeed(&modes);
	(void) signal(SIGINT, setmode);
	(void) signal(SIGQUIT, setmode);
	(void) signal(SIGTERM, setmode);

	if (command = rindex(argv[0], '/'))
		command++;
	else
		command = argv[0];
	if (sequal(command, "reset")) {
		/*
		 * Reset the teletype mode bits to a sensible state.
		 * Copied from the program by Kurt Shoens & Mark Horton.
		 * Very useful after crapping out in raw.
		 */
		if ((istermios = ioctl(FILEDES, TCGETS, (char *)&modes)) < 0) {
			(void) ioctl(FILEDES, TCGETA, (char *)&mode);
			modes.c_lflag = mode.c_lflag;
			modes.c_oflag = mode.c_oflag;
			modes.c_iflag = mode.c_iflag;
			modes.c_cflag = mode.c_cflag;
			for (i = 0; i < NCC; i++)
				modes.c_cc[i] = mode.c_cc[i];
		}
		curerase = reset(curerase, CERASE);
		curkill = reset(curkill, CKILL);
		curintr = reset(curintr, CINTR);
		modes.c_cc[VQUIT] = reset(modes.c_cc[VQUIT], CQUIT);
		modes.c_cc[VEOF] = reset(modes.c_cc[VEOF], CEOF);

		modes.c_iflag |= (BRKINT|ISTRIP|ICRNL|IXON);
		modes.c_iflag &= ~(IGNBRK|PARMRK|INPCK|INLCR|IGNCR|IUCLC|IXOFF);
		modes.c_oflag |= (OPOST|ONLCR);
		modes.c_oflag &= ~(OLCUC|OCRNL|ONOCR|ONLRET|OFILL|OFDEL|
		    NLDLY|CRDLY|TABDLY|BSDLY|VTDLY|FFDLY);
		modes.c_cflag |= (CS7|CREAD);
		modes.c_cflag &= ~(PARODD|CLOCAL);
		modes.c_lflag |= (ISIG|ICANON|ECHO|ECHOK);
		modes.c_lflag &= ~(XCASE|ECHONL|NOFLSH);
		if (istermios < 0) {
			mode.c_lflag = modes.c_lflag;
			mode.c_oflag = modes.c_oflag;
			mode.c_iflag = modes.c_iflag;
			mode.c_cflag = modes.c_cflag;
			for (i = 0; i < NCC; i++)
				mode.c_cc[i] = modes.c_cc[i];
			(void) ioctl(FILEDES, TCSETAW, (char *)&mode);
		} else
			(void) ioctl(FILEDES, TCSETSW, (char *)&modes);
		Dash_u = YES;
		BeQuiet = YES;
		IsReset = YES;
	} else if (argc == 2 && sequal(argv[1], "-")) {
		RepOnly = YES;
		Dash_u = YES;
	}
	argc--;

	/* scan argument list and collect flags */
	while (--argc >= 0) {
		p = *++argv;
		if (*p == '-') {
			if (*++p == NULL)
				Report = YES; /* report current terminal type */
			else
				while (*p)
					switch (*p++) {

			case 'r':	/* report to user */
				Ureport = YES;
				continue;

			case 'E':
				/* special erase: operate on all but TTY33 */
				Specialerase = YES;
				/* explicit fall-through to -e case */
				/* FALLTHROUGH */

			case 'e':	/* erase character */
				if (*p == NULL)
					Erase_char = -1;
				else {
					if (*p == '^' && p[1] != NULL)
						if (*++p == '?')
							Erase_char = '\177';
						else
							Erase_char = CNTL(*p);
					else
						Erase_char = *p;
					p++;
				}
				continue;

			case 'i':	/* interrupt character */
				if (*p == NULL)
					Intr_char = CNTL('C');
				else {
					if (*p == '^' && p[1] != NULL)
						if (*++p == '?')
							Intr_char = '\177';
						else
							Intr_char = CNTL(*p);
					else
						Intr_char = *p;
					p++;
				}
				continue;

			case 'k':	/* kill character */
				if (*p == NULL)
					Kill_char = CNTL('U');
				else {
					if (*p == '^' && p[1] != NULL)
						if (*++p == '?')
							Kill_char = '\177';
						else
							Kill_char = CNTL(*p);
					else
						Kill_char = *p;
					p++;
				}
				continue;

#ifdef OLDFLAGS
#ifdef	OLDDIALUP
			case 'd':	/* dialup type */
				NewType = DIALUP;
				goto mapold;
#endif

#ifdef OLDPLUGBOARD
			case 'p':	/* plugboard type */
				NewType = PLUGBOARD;
				goto mapold;
#endif

#ifdef OLDARPANET
			case 'a':	/* arpanet type */
				Newtype = ARPANET;
				goto mapold;
#endif

mapold:				Map->Ident = NewType;
				Map->Test = ALL;
				if (*p == NULL) {
					p = nextarg(argc--, argv++);
				}
				Map->Type = p;
				Map++;
				Mapped = YES;
				p = "";
				continue;
#endif

			case 'm':	/* map identifier to type */
				/*
				 * This code is very loose. Almost no
				 * syntax checking is done!! However,
				 * illegal syntax will only produce
				 * weird results.
				 */
				if (*p == NULL) {
					p = nextarg(argc--, argv++);
				}
				if (isalnum(*p)) {
					Map->Ident = p;	/* identifier */
					while (isalnum(*p)) p++;
				}
				else
					Map->Ident = "";
				Break = NO;
				Not = NO;
				while (!Break)
					switch (*p) {
					case NULL:
						p = nextarg(argc--, argv++);
						continue;

					case ':':	/* mapped type */
						*p++ = NULL;
						Break = YES;
						continue;

					case '>':	/* conditional */
						Map->Test |= GT;
						*p++ = NULL;
						continue;

					case '<':	/* conditional */
						Map->Test |= LT;
						*p++ = NULL;
						continue;

					case '=':	/* conditional */
					case '@':
						Map->Test |= EQ;
						*p++ = NULL;
						continue;

					case '!':	/* invert conditions */
						Not = ~Not;
						*p++ = NULL;
						continue;

					case 'B':	/* Baud rate */
						p++;
						/* intentional fallthru */
					default:
						if (isdigit(*p) || *p == 'e') {
							Map->Speed =
							    baudrate(p);
							while (isalnum(*p) ||
							    *p == '.')
								p++;
						} else
							Break = YES;
						continue;
				}
				if (Not) {	/* invert sense of test */
					Map->Test = (~(Map->Test))&ALL;
				}
				if (*p == NULL) {
					p = nextarg(argc--, argv++);
				}
				Map->Type = p;
				p = "";
				Map++;
				Mapped = YES;
				continue;

			case 'h':	/* don't get type from htmp or env */
				Dash_h = YES;
				continue;

			case 'u':	/* don't update htmp */
				Dash_u = YES;
				continue;

			case 's':	/* output setenv commands */
				DoSetenv = YES;
				CmndLine = YES;
				continue;

			case 'S':	/* output setenv strings */
				DoSetenv = YES;
				CmndLine = NO;
				continue;

			case 'Q':	/* be quiet */
				BeQuiet = YES;
				continue;

			case 'I':	/* no initialization */
				NoInit = YES;
				continue;

			case 'A':	/* Ask user */
				Ask = YES;
				continue;

			case 'v':	/* no virtual terminal */
				DoVirtTerm = NO;
				continue;

			default:
				*p-- = NULL;
				fatal("Bad flag -", p);
			}
		} else {
			/* terminal type */
			DefType = p;
		}
	}

	if (DefType) {
		if (Mapped) {
			Map->Ident = "";	/* means "map any type" */
			Map->Test = ALL;	/* at all baud rates */
			Map->Type = DefType;	/* to the default type */
		} else
			TtyType = DefType;
	}

	/*
	 * Get rid of $TERMCAP, if it's there, so we get a real
	 * entry from /etc/termcap.  This prevents us from being
	 * fooled by out of date stuff in the environment, and
	 * makes tabs work right on CB/Unix.
	 */
	bufp = getenv("TERMCAP");
	if (bufp && *bufp != '/')
		(void) strcpy(bufp-8, "NOTHING"); /* overwrite only "TERMCAP" */
	/* get current idea of terminal type from environment */
	if (!Dash_h && TtyType == NULL)
		TtyType = getenv("TERM");

	/* If still undefined, use DEFTYPE */
	if (TtyType == NULL) {
		TtyType = DEFTYPE;
	}

	/* check for dialup or other mapping */
	if (Mapped) {
		if (!(Alias[0] && isalias(TtyType)))
			if (tgetent(Capbuf, TtyType) > 0)
				makealias(Capbuf);
		TtyType = mapped(TtyType);
	}

	/* TtyType now contains a pointer to the type of the terminal */
	/* If the first character is '?', ask the user */
	if (TtyType[0] == '?') {
		Ask = YES;
		TtyType++;
		if (TtyType[0] == '\0')
			TtyType = DEFTYPE;
	}
	if (Ask) {
ask:
		prs("TERM = (");
		prs(TtyType);
		prs(") ");
		flush();

		/* read the terminal.  If not empty, set type */
		i = read(2, termbuf, sizeof (termbuf) - 1);
		if (i > 0) {
			if (termbuf[i - 1] == '\n')
				i--;
			termbuf[i] = '\0';
			if (termbuf[0] != '\0')
				TtyType = termbuf;
		}
	}

	/* get terminal capabilities */
	if (!(Alias[0] && isalias(TtyType))) {
		switch (tgetent(Capbuf, TtyType)) {
		case -1:
			prs("Cannot find termcap\n");
			flush();
			exit(-1);

		case 0:
			prs("Type ");
			prs(TtyType);
			prs(" unknown\n");
			flush();
			if (DoSetenv) {
				TtyType = DEFTYPE;
				Alias[0] = '\0';
				goto ask;
			} else
				exit(1);
		}
	}
	Ttycap = Capbuf;

	if (!RepOnly) {
		/* determine erase and kill characters */
		if (Specialerase && !tgetflag("bs"))
			Erase_char = 0;
		bufp = buf;
		p = tgetstr("kb", &bufp);
		if (p == NULL || p[1] != '\0')
			p = tgetstr("bc", &bufp);
		if (p != NULL && p[1] == '\0')
			bs_char = p[0];
		else if (tgetflag("bs"))
			bs_char = BACKSPACE;
		else
			bs_char = 0;
		/*
		 * The next statement can't be fixed, because now users
		 * depend on keeping their erase character as DEL if the
		 * system set it there.  People who want backspace have
		 * to say tset -e.
		 */
		if (Erase_char == 0 && !tgetflag("os") &&
		    curerase == OLDERASE) {
			if (tgetflag("bs") || bs_char != 0)
				Erase_char = -1;
		}
		if (Erase_char < 0)
			Erase_char = (bs_char != 0) ? bs_char : BACKSPACE;

		if (curerase == 0)
			curerase = CERASE;
		if (Erase_char != 0)
			curerase = Erase_char;

		if (curintr == 0)
			curintr = CINTR;
		if (Intr_char != 0)
			curintr = Intr_char;

		if (curkill == 0)
			curkill = CKILL;
		if (Kill_char != 0)
			curkill = Kill_char;

		/* set modes */
		PadBaud = tgetnum("pb");	/* OK if fails */
		for (i = 0; speeds[i].string; i++)
			if (speeds[i].baudrate == PadBaud) {
				PadBaud = speeds[i].speed;
				break;
			}
		setdelay("dC", CRdelay, CRbits, &modes.c_oflag);
		setdelay("dN", NLdelay, NLbits, &modes.c_oflag);
		setdelay("dB", BSdelay, BSbits, &modes.c_oflag);
		setdelay("dF", FFdelay, FFbits, &modes.c_oflag);
		setdelay("dT", TBdelay, TBbits, &modes.c_oflag);
		setdelay("dV", VTdelay, VTbits, &modes.c_oflag);

		if (tgetflag("UC") || (command[0] & 0140) == 0100) {
			modes.c_iflag |= IUCLC;
			modes.c_oflag |= OLCUC;
			modes.c_cflag |= XCASE;
		} else if (tgetflag("LC")) {
			modes.c_iflag &= ~IUCLC;
			modes.c_oflag &= ~OLCUC;
			modes.c_cflag &= ~XCASE;
		}
		modes.c_iflag &= ~(PARMRK|INPCK);
		modes.c_lflag |= ICANON;
		if (tgetflag("EP")) {
			modes.c_iflag |= INPCK;
			modes.c_cflag |= PARENB;
			modes.c_cflag &= ~PARODD;
		}
		if (tgetflag("OP")) {
			modes.c_iflag |= INPCK;
			modes.c_cflag |= PARENB;
			modes.c_cflag |= PARODD;
		}

		modes.c_oflag |= ONLCR;
		modes.c_iflag |= ICRNL;
		modes.c_lflag |= ECHO;
		modes.c_oflag |= TAB3;
		if (tgetflag("NL")) {	/* new line, not line feed */
			modes.c_oflag &= ~ONLCR;
			modes.c_iflag &= ~ICRNL;
		}
		if (tgetflag("HD"))	/* half duplex */
			modes.c_lflag &= ~ECHO;
		if (tgetflag("pt"))	/* print tabs */
			modes.c_oflag &= ~TAB3;

		modes.c_lflag |= (ECHOE|ECHOK);
		if (tgetflag("hc")) {	/* set printer modes */
			modes.c_lflag &= ~ECHOE;
		}

		/* get pad character */
		bufp = buf;
		if (tgetstr("pc", &bufp) != 0)
			PC = buf[0];

		/* output startup string */
		if (!NoInit) {
			if (oldmodes.c_oflag&(TAB3|ONLCR|OCRNL|ONLRET)) {
				oldmodes.c_oflag &= (TAB3|ONLCR|OCRNL|ONLRET);
				setmode(-1);
			}
			if (settabs()) {
				settle = YES;
				flush();
			}
			bufp = buf;
			if (IsReset && tgetstr("rs", &bufp) != 0 ||
			    tgetstr("is", &bufp) != 0) {
				tputs(buf, 0, prc);
				settle = YES;
				flush();
			}
			bufp = buf;
			if (IsReset && tgetstr("rf", &bufp) != 0 ||
			    tgetstr("if", &bufp) != 0) {
				cat(buf);
				settle = YES;
			}
			if (settle) {
				prc('\r');
				if (IsReset)
					prc('\n');  /* newline too */
				flush();
				sleep(1);	/* let terminal settle down */
			}
		}

		setmode(0);	/* set new modes, if they've changed */

		/* set up environment for the shell we are using */
		/* (this code is rather heuristic, checking for $SHELL */
		/* ending in the 3 characters "csh") */
		csh = NO;
		if (DoSetenv) {
			char *sh;

			if ((sh = getenv("SHELL")) && (i = strlen(sh)) >= 3) {
				if ((csh = sequal(&sh[i-3], "csh")) && CmndLine)
					(void) write(STDOUT,
					    "set noglob;\n", 12);
			}
			if (!csh) {	/* running Bourne shell */
				(void) write(STDOUT,
				    "export TERMCAP TERM;\n", 21);
			}
		}
	}

	/* report type if appropriate */
	if (DoSetenv || Report || Ureport) {
		/* if type is the short name, find first alias (if any) */
		makealias(Ttycap);
		if (sequal(TtyType, Alias[0]) && Alias[1]) {
			TtyType = Alias[1];
		}

		if (DoSetenv) {
			if (csh) {
				if (CmndLine)
					(void) write(STDOUT,
					    "setenv TERM ", 12);
				(void) write(STDOUT, TtyType, strlen(TtyType));
				(void) write(STDOUT, " ", 1);
				if (CmndLine)
					(void) write(STDOUT, ";\n", 2);
			} else {
				(void) write(STDOUT, "TERM=", 5);
				(void) write(STDOUT, TtyType, strlen(TtyType));
				(void) write(STDOUT, ";\n", 2);
			}
		} else if (Report) {
			(void) write(STDOUT, TtyType, strlen(TtyType));
			(void) write(STDOUT, "\n", 1);
		}
		if (Ureport) {
			prs("Terminal type is ");
			prs(TtyType);
			prs("\n");
			flush();
		}

		if (DoSetenv) {
			if (csh) {
				if (CmndLine)
					(void) write(STDOUT,
					    "setenv TERMCAP '", 16);
			} else
				(void) write(STDOUT, "TERMCAP='", 9);
			wrtermcap(Ttycap);
			if (csh) {
				if (CmndLine) {
					(void) write(STDOUT, "';\n", 3);
					(void) write(STDOUT,
					    "unset noglob;\n", 14);
				}
			} else
				(void) write(STDOUT, "';\n", 3);
		}
	}

	if (RepOnly)
		exit(0);

	/* tell about changing erase, kill and interrupt characters */
	reportek("Erase", curerase, olderase, CERASE);
	reportek("Kill", curkill, oldkill, CKILL);
	reportek("Interrupt", curintr, oldintr, CINTR);

	return (0);
}

/*
 * Set the hardware tabs on the terminal, using the ct (clear all tabs),
 * st (set one tab) and ch (horizontal cursor addressing) capabilities.
 * This is done before if and is, so they can patch in case we blow this.
 */
int
settabs(void)
{
	char caps[100];
	char *capsp = caps;
	char *clear_tabs, *set_tab, *set_column, *set_pos;
	char *tg_out, *tgoto();
	int c;
	extern char *tgetstr();
	int lines, columns;

	clear_tabs = tgetstr("ct", &capsp);
	set_tab = tgetstr("st", &capsp);
	set_column = tgetstr("ch", &capsp);
	if (set_column == 0)
		set_pos = tgetstr("cm", &capsp);

	if (clear_tabs && set_tab) {
		prc('\r');	/* force to be at left margin */
		tputs(clear_tabs, 0, prc);
	}
	if (set_tab) {
		columns = tgetnum("co");
		lines = tgetnum("li");
		for (c = 0; c < columns; c += 8) {
			/* get to that column. */
			tg_out = "OOPS";	/* also returned by tgoto */
			if (set_column)
				tg_out = tgoto(set_column, 0, c);
			if (*tg_out == 'O' && set_pos)
				tg_out = tgoto(set_pos, c, lines-1);
			if (*tg_out != 'O')
				tputs(tg_out, 1, prc);
			else if (c != 0) {
				prc(' '); prc(' '); prc(' '); prc(' ');
				prc(' '); prc(' '); prc(' '); prc(' ');
			}
			/* set the tab */
			tputs(set_tab, 0, prc);
		}
		prc('\r');
		return (1);
	}
	return (0);
}

/*
 * flag serves several purposes:
 *	if called as the result of a signal, flag will be > 0.
 *	if called from terminal init, flag == -1 means reset "oldmode".
 *	called with flag == 0 at end of normal mode processing.
 */
void
setmode(int flag)
{
	struct termio *ttymode;
	struct termios *ttymodes;
	int i;

	ttymode = (struct termio *)0;
	ttymodes = (struct termios *)0;

	if (flag < 0) { /* unconditionally reset oldmode (called from init) */
		if (istermios < 0) {
			oldmode.c_lflag = oldmodes.c_lflag;
			oldmode.c_oflag = oldmodes.c_oflag;
			oldmode.c_iflag = oldmodes.c_iflag;
			oldmode.c_cflag = oldmodes.c_cflag;
			for (i = 0; i < NCC; i++)
				oldmode.c_cc[i] = oldmodes.c_cc[i];
			ttymode = &oldmode;
		} else
			ttymodes = &oldmodes;
	} else {
		if (istermios < 0) {
			oldmode.c_lflag = oldmodes.c_lflag;
			oldmode.c_oflag = oldmodes.c_oflag;
			oldmode.c_iflag = oldmodes.c_iflag;
			oldmode.c_cflag = oldmodes.c_cflag;
			for (i = 0; i < NCC; i++)
				oldmode.c_cc[i] = oldmodes.c_cc[i];
			mode.c_lflag = modes.c_lflag;
			mode.c_oflag = modes.c_oflag;
			mode.c_iflag = modes.c_iflag;
			mode.c_cflag = modes.c_cflag;
			for (i = 0; i < NCC; i++)
				mode.c_cc[i] = modes.c_cc[i];
			if (!bequal((char *)&mode, (char *)&oldmode,
			    sizeof (mode)))
				ttymode = &mode;
		} else if (!bequal((char *)&modes, (char *)&oldmodes,
		    sizeof (modes)))
			ttymodes = &modes;
	}

	if (ttymode) {
		(void) ioctl(FILEDES, TCSETAW, (char *)ttymode);
	} else if (ttymodes) {
		(void) ioctl(FILEDES, TCSETSW, (char *)ttymodes);
	}
	if (flag > 0)	/* trapped signal */
		exit(1);
}

void
reportek(char *name, char new, char old, char def)
{
	char	o;
	char	n;
	char	*p;
	char		buf[32];
	char		*bufp;
	extern char *tgetstr();

	if (BeQuiet)
		return;
	o = old;
	n = new;

	if (o == n && n == def)
		return;
	prs(name);
	if (o == n)
		prs(" is ");
	else
		prs(" set to ");
	bufp = buf;
	if (tgetstr("kb", &bufp) > (char *)0 && n == buf[0] && buf[1] == NULL)
		prs("Backspace\n");
	else if (n == 0177)
		prs("Delete\n");
	else {
		if (n < 040) {
			prs("Ctrl-");
			n ^= 0100;
		}
		p = "x\n";
		p[0] = n;
		prs(p);
	}
	flush();
}



void
setdelay(char *cap, struct delay dtab[], tcflag_t bits, tcflag_t *flags)
{
	int		i;
	struct delay	*p;
	extern short	ospeed;

	/* see if this capability exists at all */
	i = tgetnum(cap);
	if (i < 0)
		i = 0;
	/* No padding at speeds below PadBaud */
	if (PadBaud > ospeed)
		i = 0;

	/* clear out the bits, replace with new ones */
	*flags &= ~bits;

	/* scan dtab for first entry with adequate delay */
	for (p = dtab; p->d_delay >= 0; p++) {
		if (p->d_delay >= i) {
			p++;
			break;
		}
	}

	/* use last entry if none will do */
	*flags |= (tcflag_t)((--p)->d_bits);
}

void
prs(char *s)
{
	while (*s != '\0')
		prc(*s++);
}


char	OutBuf[256];
int	OutPtr;

void
prc(char c)
{
	OutBuf[OutPtr++] = c;
	if (OutPtr >= sizeof (OutBuf))
		flush();
}

void
flush(void)
{
	if (OutPtr > 0)
		(void) write(2, OutBuf, OutPtr);
	OutPtr = 0;
}

void
cat(char *file)
{
	int	fd;
	int	i;
	char		buf[BUFSIZ];

	fd = open(file, 0);
	if (fd < 0) {
		prs("Cannot open ");
		prs(file);
		prs("\n");
		flush();
		return;
	}

	while ((i = read(fd, buf, BUFSIZ)) > 0)
		(void) write(FILEDES, buf, i);

	(void) close(fd);
}


void
bmove(char *from, char *to, int length)
{
	char	*p, *q;
	int	i;

	i = length;
	p = from;
	q = to;

	while (i-- > 0)
		*q++ = *p++;
}


int
bequal(char *a, char *b, int len)	/* must be same thru len chars */
{
	char	*p, *q;
	int	i;

	i = len;
	p = a;
	q = b;

	while ((*p == *q) && --i > 0) {
		p++; q++;
	}
	return ((*p == *q) && i >= 0);
}

int
sequal(char *a, char *b)	/* must be same thru NULL */
{
	char *p = a, *q = b;

	while (*p && *q && (*p == *q)) {
		p++; q++;
	}
	return (*p == *q);
}

void
makealias(char *buf)
{
	int i;
	char *a;
	char *b;

	Alias[0] = a = Aliasbuf;
	b = buf;
	i = 1;
	while (*b && *b != ':') {
		if (*b == '|') {
			*a++ = NULL;
			Alias[i++] = a;
			b++;
		} else
			*a++ = *b++;
	}
	*a = NULL;
	Alias[i] = NULL;
#ifdef	DEB
	for (i = 0; Alias[i]; printf("A:%s\n", Alias[i++]))
		;
#endif
}

int
isalias(char *ident)	/* is ident same as one of the aliases? */
{
	char **a = Alias;

	if (*a)
		while (*a)
			if (sequal(ident, *a))
				return (YES);
			else
				a++;
	return (NO);
}


/*
 * routine to output the string for the environment TERMCAP variable
 */
#define	WHITE(c)	(c == ' ' || c == '\t')
char delcap[128][2];
int ncap = 0;

void
wrtermcap(char *bp)
{
	char buf[CAPBUFSIZ];
	char *p = buf;
	char *tp;
	char *putbuf();
	int space, empty;

	/* discard names with blanks */
/* May not be desireable ? */
	while (*bp && *bp != ':') {
		if (*bp == '|') {
			tp = bp+1;
			space = NO;
			while (*tp && *tp != '|' && *tp != ':') {
				space = (space || WHITE(*tp));
				tp++;
			}
			if (space) {
				bp = tp;
				continue;
			}
		}
		*p++ = *bp++;
	}
/* */

	while (*bp) {
		switch (*bp) {
		case ':':	/* discard empty, cancelled  or dupl fields */
			tp = bp + 1;
			empty = YES;
			while (*tp && *tp != ':') {
				empty = (empty && WHITE(*tp));
				tp++;
			}
			if (empty || cancelled(bp+1)) {
				bp = tp;
				continue;
			}
			break;

		case ' ':	/* no spaces in output */
			p = putbuf(p, "\\040");
			bp++;
			continue;

		case '!':	/* the shell thinks this is history */
			p = putbuf(p, "\\041");
			bp++;
			continue;

		case ',':	/* the shell thinks this is history */
			p = putbuf(p, "\\054");
			bp++;
			continue;

		case '"':	/* no quotes in output */
			p = putbuf(p, "\\042");
			bp++;
			continue;

		case '\'':	/* no quotes in output */
			p = putbuf(p, "\\047");
			bp++;
			continue;

		case '`':	/* no back quotes in output */
			p = putbuf(p, "\\140");
			bp++;
			continue;

		case '\\':
		case '^':	/* anything following is OK */
			*p++ = *bp++;
		}
		*p++ = *bp++;
	}
	*p++ = ':';	/* we skipped the last : with the : lookahead hack */
	(void) write(STDOUT, buf, p-buf);
}

int
cancelled(char *cap)
{
	int i;

	for (i = 0; i < ncap; i++) {
		if (cap[0] == delcap[i][0] && cap[1] == delcap[i][1])
			return (YES);
	}
	/* delete a second occurrance of the same capability */
	delcap[ncap][0] = cap[0];
	delcap[ncap][1] = cap[1];
	ncap++;
	return (cap[2] == '@');
}

char *
putbuf(ptr, str)
char	*ptr;
char	*str;
{
	char buf[20];

	while (*str) {
		switch (*str) {
		case '\033':
			ptr = putbuf(ptr, "\\E");
			str++;
			break;
		default:
			if (*str <= ' ') {
				(void) sprintf(buf, "\\%03o", *str);
				ptr = putbuf(ptr, buf);
				str++;
			} else
				*ptr++ = *str++;
		}
	}
	return (ptr);
}

int
baudrate(char *p)
{
	char buf[8];
	int i = 0;

	while (i < 7 && (isalnum(*p) || *p == '.'))
		buf[i++] = *p++;
	buf[i] = NULL;
	for (i = 0; speeds[i].string; i++)
		if (sequal(speeds[i].string, buf))
			return (speeds[i].speed);
	return (-1);
}

char *
mapped(type)
char	*type;
{
	extern short	ospeed;
	int	match;

#ifdef DEB
	printf("spd:%d\n", ospeed);
	prmap();
#endif
	Map = map;
	while (Map->Ident) {
		if (*(Map->Ident) == NULL ||
		    sequal(Map->Ident, type) || isalias(Map->Ident)) {
			match = NO;
			switch (Map->Test) {
			case ANY:	/* no test specified */
			case ALL:
				match = YES;
				break;

			case GT:
				match = (ospeed > Map->Speed);
				break;

			case GE:
				match = (ospeed >= Map->Speed);
				break;

			case EQ:
				match = (ospeed == Map->Speed);
				break;

			case LE:
				match = (ospeed <= Map->Speed);
				break;

			case LT:
				match = (ospeed < Map->Speed);
				break;

			case NE:
				match = (ospeed != Map->Speed);
				break;
			}
			if (match)
				return (Map->Type);
		}
		Map++;
	}
	/* no match found; return given type */
	return (type);
}

#ifdef DEB
prmap()
{
	Map = map;
	while (Map->Ident) {
		printf("%s t:%d s:%d %s\n",
		    Map->Ident, Map->Test, Map->Speed, Map->Type);
		Map++;
	}
}
#endif

char *
nextarg(argc, argv)
int	argc;
char	*argv[];
{
	if (argc <= 0)
		fatal("Too few args: ", *argv);
	if (*(*++argv) == '-')
		fatal("Unexpected arg: ", *argv);
	return (*argv);
}

void
fatal(char *mesg, char *obj)
{
	prs(mesg);
	prs(obj);
	prc('\n');
	prs(USAGE);
	flush();
	exit(1);
}


/*
 * Stolen from /usr/src/ucb/reset.c, which this mod obsoletes.
 */
char
reset(ch, def)
	char ch;
	int def;
{
	if (ch == 0 || (ch&0377) == 0377)
		return (def);
	return (ch);
}
