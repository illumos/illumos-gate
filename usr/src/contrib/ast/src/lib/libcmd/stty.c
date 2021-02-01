/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * stty.c
 * Written by David Korn
 * Tue Apr  4 10:46:00 EDT 1995
 */

static const char usage[] =
"[-?@(#)$Id: stty (AT&T Research) 2010-04-01 $\n]"
USAGE_LICENSE
"[+NAME?stty - set or get terminal modes]"
"[+DESCRIPTION?\bstty\b sets certain terminal I/O modes for the device "
    "that is the current standard input; without arguments, it writes the "
    "settings of certain modes to standard output.]"
"[a:all?Writes to standard output all of the mode settings.]"
"[f|F:fd|file?Use \afd\a as the terminal fd.]#[fd:=0]"
"[g:save?Writes the current settings to standard output in a form that "
    "can be used as an argument to another \bstty\b command. The \brows\b "
    "and \bcolumns\b values are not included.]"
"[t:terminal-group?Print the terminal group id of the device, -1 if "
    "unknown.]"
"\n"
"\n[mode ...]\n"
"\n"
"[+EXTENDED DESCRIPTION?Modes are specified either as a single name or "
    "as a name followed by a value. As indicated below, many of the mode "
    "names can be preceded by a \b-\b to negate its meaning. Modes are "
    "listed by group corresponding to field in the \btermios\b structure "
    "defined in \b<termios.h>\b. Modes in the last group are implemented "
    "using options in the previous groups. Note that many combinations of "
    "modes make no sense, but no sanity checking is performed. The modes are "
    "selected from the following:]"
    "{\fabc\f}"
"[+EXIT STATUS?]"
    "{"
        "[+0?All modes reported or set successfully.]"
        "[+>0?Standard input not a terminaol or one or more modes "
            "failed.]"
    "}"
"[+SEE ALSO?\btegetattr\b(2), \btcsetattr\b(2), \bioctl\b(2)]"
;

#include	<cmd.h>
#include	<ccode.h>
#include	<ctype.h>
#include	<ast_tty.h>
#if _sys_ioctl
#include	<sys/ioctl.h>
#endif

#define C(x)	ERROR_catalog(x)

#ifndef _POSIX_VDISABLE
#   define _POSIX_VDISABLE 0
#endif

#ifndef NCCS
#   ifdef NCC
#	define NCCS	NCC
#   else
#	define NCCS	elementsof(((struct termio*)0)->c_cc)
#   endif
#endif

/* command options */
#define A_FLAG	1
#define G_FLAG	2
#define T_FLAG	4

/* termios fields */
#define C_FLAG	1
#define C_LINE	2
#define C_SPEED	3
#define I_FLAG	4
#define O_FLAG	5
#define L_FLAG	6
#define T_CHAR	7
#define W_SIZE	8

#define BIT	1
#define BITS	2
#define NUM	3
#define CHAR	4
#define SPEED	5
#define SIZE	6
#define MIXED	7
#define SANE	8
#define COOKED	9
#define CASE	10
#define TABS	11
#define WIND	12

#undef	SS			/* who co-opted this namespace?	*/

#define IG	0x0001		/* ignore display		*/
#define NL	0x0002		/* entry ends line of display	*/
#define SS	0x0004		/* set in sane mode		*/
#define US	0x0010		/* unset in sane mode		*/

typedef struct tty_s
{
	const char	name[8];
	unsigned char	type;
	unsigned char	field;
	short		flags;
	unsigned long	mask;
	unsigned long	val;
	const char	description[76];
} Tty_t; 

static const Tty_t Ttable[] =
{
#ifdef CBAUD
{ "ispeed",	NUM,	C_SPEED,0,	CBAUD, 0, C("\an\a is the input baud rate") },
{ "ospeed",	NUM,	C_SPEED,0,	CBAUD, 0, C("\an\a is the output baud rate") },
{ "speed",	NUM,	C_SPEED,IG,	CBAUD },
#endif
{ "0",		SPEED,	C_FLAG,	0,	B0 },
{ "50",		SPEED,	C_FLAG,	0,	B50 },
{ "75",		SPEED,	C_FLAG,	0,	B75 },
{ "110",	SPEED,	C_FLAG,	0,	B110 },
{ "134",	SPEED,	C_FLAG,	0,	B134 },
{ "150",	SPEED,	C_FLAG,	0,	B150 },
{ "200",	SPEED,	C_FLAG,	0,	B200 },
{ "300",	SPEED,	C_FLAG,	0,	B300 },
{ "600",	SPEED,	C_FLAG,	0,	B600 },
{ "1200",	SPEED,	C_FLAG,	0,	B1200 },
{ "1800",	SPEED,	C_FLAG,	0,	B1800 },
{ "2400",	SPEED,	C_FLAG,	0,	B2400 },
{ "4800",	SPEED,	C_FLAG,	0,	B4800 },
{ "9600",	SPEED,	C_FLAG,	0,	B9600 },
{ "19200",	SPEED,	C_FLAG,	0,	B19200 },
{ "38400",	SPEED,	C_FLAG,	0,	B38400 },

#ifdef TIOCSWINSZ
{ "rows",	WIND,	W_SIZE,	IG,	0, 24, C("\an\a is the number of lines for display") },
{ "cols",	WIND,	W_SIZE,	IG,	1, 80, C("\an\a is the number of columns for display") },
{ "columns",	WIND,	W_SIZE,	IG,	1, 80, C("Same as \bcols\b") },
#endif
{ "intr",	CHAR,	T_CHAR,	SS,	VINTR, 'C', C("Send an interrupt signal") },
{ "quit",	CHAR,	T_CHAR,	SS,	VQUIT, '|', C("Send a quit signal") },
{ "erase",	CHAR,	T_CHAR,	SS,	VERASE, 'H', C("Erase the last character entered") },
{ "kill",	CHAR,	T_CHAR,	NL|SS,	VKILL, 'U', C("Erase the current line") },
{ "eof",	CHAR,	T_CHAR,	SS,	VEOF, 'D', C("Send an end of file") },
#ifdef VEOL2
{ "eol2",	CHAR,	T_CHAR,	US,	VEOL2, _POSIX_VDISABLE, C("Alternate character to end the line") },
#endif /* VEOL2 */
#ifdef VSWTCH
{ "swtch",	CHAR,	T_CHAR,	US,	VSWTCH, _POSIX_VDISABLE, C("Switch to a different shell layer") },
#endif /* VSWTCH */
{ "eol",	CHAR,	T_CHAR,	NL|US,	VEOL, _POSIX_VDISABLE, C("End the line") },
#ifdef VSTART
{ "start",	CHAR,	T_CHAR,	SS,	VSTART, 'Q', C("Restart the output after stopping it") },
#endif /* VSTART */
#ifdef VSTOP
{ "stop",	CHAR,	T_CHAR,	SS,	VSTOP, 'S', C("Stop the output") },
#endif /* VSTOP */
#ifdef VDSUSP
{ "dsusp",	CHAR,	T_CHAR,	SS,	VDSUSP, 'Y', C("Send a terminal stop signal after flushing the input") },
#endif /* VDSUSP */
#ifdef VSUSP
{ "susp",	CHAR,	T_CHAR,	NL|SS,	VSUSP, 'Z', C("Send a terminal stop signal") },
#endif /* VSUSP */
#ifdef VREPRINT
{ "rprnt",	CHAR,	T_CHAR,	SS,	VREPRINT, 'R', C("Redraw the current line") },
#endif /* VREPRINT */
#ifdef VDISCARD
{ "flush",	CHAR,	T_CHAR,	SS,	VDISCARD, 'O', C("Discard output") },
#endif /* VDISCARD */
#ifdef VWERASE
{ "werase",	CHAR,	T_CHAR,	SS,	VWERASE, 'W', C("Erase the last word entered") },
#endif /* VWERASE */
#ifdef VLNEXT
{ "lnext",	CHAR,	T_CHAR,	NL|SS,	VLNEXT, 'V', C("Enter the next input character literally") },
#endif /* VLNEXT */
	
#if _mem_c_line_termios
{ "line",	NUM,	C_LINE,	0,	0, 0, C("Line discipline number") },
#endif
{ "min",	NUM,	T_CHAR,	0,	VMIN, 0, C("Mininmum number of characters to read in raw mode") },
{ "time",	NUM,	T_CHAR,	0,	VTIME, 0, C("Number of .1 second intervals with raw mode") },

{ "parenb",	BIT,	C_FLAG,	0,	PARENB,	PARENB, C("Enable (disable) parity generation and detection") },
{ "parodd",	BIT,	C_FLAG,	0,	PARODD, PARODD, C("Use odd (even) parity") },
#ifdef PAREXT
{ "parext",	BIT,	C_FLAG,	0,	PAREXT, PAREXT },
#endif /* PAREXT */
#ifdef CREAD
{ "cread",	BIT,	C_FLAG,	SS,	CREAD, CREAD, C("Enable (disable) input") },
#endif /* CREAD */
{ "cs5",	SIZE,	C_FLAG,	0,	CSIZE,	CS5 , C("Char size 5") },
{ "cs6",	SIZE,	C_FLAG,	0,	CSIZE,	CS6 , C("Char size 6") },
{ "cs7",	SIZE,	C_FLAG,	0,	CSIZE,	CS7 , C("Char size 7") },
{ "cs8",	SIZE,	C_FLAG,	0,	CSIZE,	CS8 , C("Char size 8") },
{ "hupcl",	BIT,	C_FLAG,	0,	HUPCL, HUPCL, C("Hangup (do not hangup) connection on last close") },
{ "hup",	BIT,	C_FLAG,	IG,	HUPCL, HUPCL, C("Same as \bhupcl\b") },
{ "cstopb",	BIT,	C_FLAG,	0,	CSTOPB, CSTOPB, C("Use two (one) stop bits") },
#ifdef CRTSCTS
{ "crtscts",	BIT,	C_FLAG,	0,	CRTSCTS, CRTSCTS, C("Enable (disable) RTS/CTS handshaking") },
#endif /* CRTSCTS */
{ "clocal",	BIT,	C_FLAG,	NL,	CLOCAL, CLOCAL, C("Disable (enable) modem control signals") },
	
{ "ignbrk",	BIT,	I_FLAG,	US,	IGNBRK, IGNBRK, C("Ignore (do not ignore) break characters") },
{ "brkint",	BIT,	I_FLAG,	SS,	BRKINT, BRKINT, C("Generate (do not generate) INTR signal on break") },
{ "ignpar",	BIT,	I_FLAG,	0,	IGNPAR, IGNPAR, C("Ignore (do not ignore) characters with parity errors") },
{ "parmrk",	BIT,	I_FLAG,	0,	PARMRK, PARMRK, C("Mark (do not mark) parity errors") },
{ "inpck",	BIT,	I_FLAG,	0,	INPCK, INPCK, C("Enable (disable) input parity checking") },
{ "istrip",	BIT,	I_FLAG,	0,	ISTRIP, ISTRIP, C("Clear (do not clear) high bit of input characters") },
{ "inlcr",	BIT,	I_FLAG,	US,	INLCR, INLCR, C("Translate (do not translate) carriage return to newline") },
{ "igncr",	BIT,	I_FLAG,	US,	IGNCR, IGNCR, C("Ignore (do not ignore) carriage return") },
#ifdef IUCLC
{ "iuclc",	BIT,	I_FLAG,	US,	IUCLC, IUCLC, C("Map (do not map) upper-case to lower case") },
#endif /* IUCLC */
{ "ixon",	BIT,	I_FLAG,	0,	IXON, IXON, C("Enable (disable) XON/XOFF flow control. \bstop\b character stops output") },
#ifdef IXANY
{ "ixany",	BIT,	I_FLAG,	US,	IXANY, IXANY, C("Any character (only start character) can restart output.") },
{ "decctlq",	BIT,	I_FLAG,	IG,	IXANY, 0, C("Same as \b-ixany\b") },
#endif /* IXANY */
{ "ixoff",	BIT,	I_FLAG,	US,	IXOFF, IXOFF, C("Disable (enable) XON/XOFF flow control") },
#ifdef IMAXBEL
{ "imaxbel",	BIT,	I_FLAG,	SS,	IMAXBEL, IMAXBEL, C("Beep (do not beep) if a character arrives with full input buffer") },
#endif /* IMAXBEL */
{ "icrnl",	BIT,	I_FLAG,	NL|SS,	ICRNL, ICRNL, C("Translate (do not translate) carriage return to newline") },
	
{ "isig",	BIT,	L_FLAG,	SS,	ISIG, ISIG, C("Enable (disable) \bintr\b, \bquit\b, and \bsusp\b special characters") },
{ "icanon",	BIT,	L_FLAG,	SS,	ICANON, ICANON, C("Enable (disable) \berase\b, \bkill\b, \bwerase\b, and \brprnt\b special characters") },
{ "icannon",	BIT,	L_FLAG,	SS,	ICANON, ICANON },
#ifdef IEXTEN
{ "iexten",	BIT,	L_FLAG,	SS,	IEXTEN, IEXTEN, C("Enable (disable) non-POSIX special characters") },
#endif /* IEXTEN */
{ "echo",	BIT,	L_FLAG,	SS,	ECHO|ECHONL, ECHO|ECHONL, C("Echo (do not echo) input characters") },
{ "echoe",	BIT,	L_FLAG,	SS,	ECHOE, ECHOE, C("Echo (do not echo) erase characters as backspace-space-backspace") },
{ "echok",	BIT,	L_FLAG,	SS,	ECHOK, ECHOK, C("Echo (do not echo) a newline after a kill character") },
#ifdef ECHOKE
{ "echoke",	BIT,	L_FLAG,	SS,	ECHOKE, ECHOKE, C("Echo (do not echo) a newline after a kill character") },
#endif
{ "lfkc",	BIT,	L_FLAG,	IG,	ECHOK, ECHOK, C("Same as \bechok\b (\b-echok\b); obsolete") },
{ "echonl",	BIT,	L_FLAG,	SS,	ECHONL, ECHONL,"Echo (do not echo) newline even if not echoing other character" },
#ifdef ECHOCTL
{ "echoctl",	BIT,	L_FLAG,	SS,	ECHOCTL, ECHOCTL, C("Echo (do not echo) control characters as \b^\b\ac\a") },
#else
#define ECHOCTL		0
#endif /* ECHOCTL */
#ifdef ECHOPRT
{ "echoprt",	BIT,	L_FLAG,	US,	ECHOPRT, ECHOPRT, C("Echo (do not echo) erased characters backward, between '\\' and '/'") },
#else
#define ECHOPRT		0
#endif /* ECHOPRT */
#ifdef XCASE
{ "xcase",	BIT,	L_FLAG,	US,	XCASE, XCASE, C("Enable (disable) \bicanon\b uppercase as lowercase with '\\' prefix") },
#endif /* XCASE */
#ifdef DEFECHO
{ "defecho",	BIT,	L_FLAG,	0,	DEFECHO, DEFECHO },
#endif /* DEFECHO */
#ifdef FLUSHO
{ "flusho",	BIT,	L_FLAG,	0,	FLUSHO, FLUSHO, C("Discard (do not discard) written data. Cleared by subsequent input") },
#endif /* FLUSHO */
#ifdef PENDIN
{ "pendin",	BIT,	L_FLAG,	0,	PENDIN, PENDIN, C("Redisplay pending input at next read and then automatically clear \bpendin\b") },
#endif /* PENDIN */
{ "noflsh",	BIT,	L_FLAG,	US,	NOFLSH, NOFLSH, C("Disable (enable) flushing after \bintr\b and \bquit\b special characters") },
#ifdef TOSTOP
{ "tostop",	BIT,	L_FLAG,	NL|US,	TOSTOP, TOSTOP, C("Stop (do not stop) background jobs that try to write to the terminal") },
#endif /* TOSTOP */
#ifdef OLCUC
{ "olcuc",	BIT,	O_FLAG,	US,	OLCUC, OLCUC, C("Translate (do not translate) lowercase characters to uppercase") },
#endif /* OLCUC */
#ifdef ONLCR
{ "onlcr",	BIT,	O_FLAG,	SS,	ONLCR, ONLCR, C("Translate (do not translate) newline to carriage return-newline") },
#endif /* ONLCR */
#ifdef ONLRET
{ "onlret",	BIT,	O_FLAG,	US,	ONLRET, ONLRET, C("Newline performs (does not perform) a carriage return") },
#endif /* ONLRET */
#ifdef OCRNL
{ "ocrnl",	BIT,	O_FLAG,	US,	OCRNL, OCRNL, C("Translate (do not translate) carriage return to newline") },
#endif /* OCRNL */
#ifdef ONOCR
{ "onocr",	BIT,	O_FLAG,	US,	ONOCR, ONOCR, C("Do not (do) print carriage returns in the first column") },
#endif /* ONOCR */
#ifdef OFILL
{ "ofill",	BIT,	O_FLAG,	US,	OFILL, OFILL, C("Use fill characters (use timing) for delays") },
#endif /* OFILL */
#ifdef OFDEL
{ "ofdel",	BIT,	O_FLAG,	US,	OFDEL, OFDEL, C("Use DEL (NUL) as fill characters for delays") },
#endif /* OFDEL */
{ "opost",	BIT,	O_FLAG,	SS,	OPOST, OPOST, C(" Postprocess (do not postprocess) output") },
#ifdef CRDLY
{ "cr0",	BITS,	O_FLAG,	IG|SS,	CRDLY, CR0  },
{ "cr1",	BITS,	O_FLAG,	US,	CRDLY, CR1  },
{ "cr2",	BITS,	O_FLAG,	US,	CRDLY, CR2  },
{ "cr3",	BITS,	O_FLAG,	US,	CRDLY, CR3  },
#endif
#ifdef NLDLY
{ "nl0",	BITS,	O_FLAG,	IG|US,	NLDLY, NL0  },
{ "nl1",	BITS,	O_FLAG,	US,	NLDLY, NL1  },
#endif
#ifdef TABDLY
{ "tabs",	TABS,	O_FLAG,	IG,	TABDLY, TAB3, C("Preserve (expand to spaces) tabs") },
#ifdef TAB0
{ "tab0",	BITS,	O_FLAG,	IG|SS,	TABDLY, TAB0  },
#endif
#ifdef TAB1
{ "tab1",	BITS,	O_FLAG,	US,	TABDLY, TAB1  },
#endif
#ifdef TAB2
{ "tab2",	BITS,	O_FLAG,	US,	TABDLY, TAB2  },
#endif
{ "tab3",	BITS,	O_FLAG,	US,	TABDLY, TAB3  },
#endif
#ifdef BSDLY
{ "bs0",	BITS,	O_FLAG,	IG|SS,	BSDLY, BS0 },
{ "bs1",	BITS,	O_FLAG,	US,	BSDLY, BS1  },
#endif
#ifdef VTDLY
{ "vt0",	BITS,	O_FLAG,	IG|SS,	VTDLY, VT0  },
{ "vt1",	BITS,	O_FLAG,	US,	VTDLY, VT1  },
#endif
#ifdef FFDLY
{ "ff0",	BITS,	O_FLAG,	IG|SS,	FFDLY, FF0 },
{ "ff1",	BITS,	O_FLAG,	US,	FFDLY, FF1 },
#endif
{ "",		MIXED,	O_FLAG,	NL|IG },
	
{ "evenp",	MIXED,	C_FLAG,	IG,	PARENB, 0, C("Same as \bparenb -parodd cs7\b") },
{ "oddp",	MIXED,	C_FLAG,	IG,	PARODD, 0, C("Same as \bparenb parodd cs7\b") },
{ "parity",	MIXED,	C_FLAG,	IG,	0, 0, C("Same as parenb \b-parodd cs7\b") },
{ "ek",		MIXED,	C_FLAG,	IG,	0, 0, C("Reset the \berase\b and \bkill\b special characters to their default values") },
{ "sane",	SANE,	C_FLAG,	IG,	0, 0, C("Reset all modes to some reasonable values") },
{ "cooked",	COOKED,	C_FLAG,	IG,	0, 0, C("Disable raw input and output") },
{ "raw",	COOKED,	C_FLAG,	IG,	0, 0, C("Enable raw input and output") },
{ "lcase",	CASE,	C_FLAG,	IG,	0 , 0, C("Set \bxcase\b, \biuclc\b, and \bolcuc\b") },
{ "LCASE",	CASE,	C_FLAG,	IG,	0 , 0, C("Same as \blcase\b") }
};

#if CC_NATIVE == CC_ASCII
#define cntl(x)		(((x)=='?')?0177:((x)&037))
#else
#define cntl(x)		(((x)=='?')?ccmapc(0177,CC_ASCII,CC_NATIVE):ccmapc(ccmapc(x,CC_NATIVE,CC_ASCII)&037,CC_ASCII,CC_NATIVE))
#endif

static void sane(register struct termios *sp)
{
	register const Tty_t*	tp;

	for (tp = Ttable; tp < &Ttable[elementsof(Ttable)]; tp++)
		if (tp->flags & (SS|US))
			switch (tp->type)
			{
			case BIT:
			case BITS:
				switch (tp->field)
				{
				case C_FLAG:
					if (tp->flags & SS)
						sp->c_cflag |= tp->mask;
					else
						sp->c_cflag &= ~tp->mask;
					break;
				case I_FLAG:
					if (tp->flags & SS)
						sp->c_iflag |= tp->mask;
					else
						sp->c_iflag &= ~tp->mask;
					break;
				case O_FLAG:
					if (tp->flags & SS)
						sp->c_oflag |= tp->mask;
					else
						sp->c_oflag &= ~tp->mask;
					break;
				case L_FLAG:
					if (tp->flags & SS)
						sp->c_lflag |= tp->mask;
					else
						sp->c_lflag &= ~tp->mask;
					break;
				}
				break;
			case CHAR:
				sp->c_cc[tp->mask] = cntl(tp->val);
				break;
			}
}

static int gin(char *arg,struct termios *sp)
{
	register int i;
	if(*arg++ != ':')
		return(0);
	sp->c_iflag = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	sp->c_oflag = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	sp->c_cflag = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	sp->c_lflag = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	for(i=0;i< NCCS; i++)
	{
		sp->c_cc[i] = strtol(arg,&arg,16);
		if(*arg++ != ':')
			return(0);
	}
#if _mem_c_line_termios
	sp->c_line =
#endif
		strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	i = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	cfsetispeed(sp, i);
	i = strtol(arg,&arg,16);
	if(*arg++ != ':')
		return(0);
	cfsetospeed(sp, i);
	if(*arg)
		return(0);
	return(1);
}

static void gout(struct termios *sp)
{
	register int i;
	sfprintf(sfstdout,":%x",sp->c_iflag);
	sfprintf(sfstdout,":%x",sp->c_oflag);
	sfprintf(sfstdout,":%x",sp->c_cflag);
	sfprintf(sfstdout,":%x",sp->c_lflag);
	for(i=0;i< NCCS; i++)
		sfprintf(sfstdout,":%x",sp->c_cc[i]);
#if _mem_c_line_termios
	sfprintf(sfstdout,":%x", sp->c_line);
#else
	sfprintf(sfstdout,":%x", 0);
#endif
	sfprintf(sfstdout,":%x",cfgetispeed(sp));
	sfprintf(sfstdout,":%x",cfgetospeed(sp));
	sfprintf(sfstdout,":\n");
}

static void output(struct termios *sp, int flags)
{
	const Tty_t *tp;
	struct termios tty;
	register int delim = ' ';
	register int i,off,off2;
	char schar[2];
	unsigned int ispeed = cfgetispeed(sp);
	unsigned int ospeed = cfgetospeed(sp);
	if(flags&G_FLAG)
	{
		gout(sp);
		return;
	}
	tty = *sp;
	sane(&tty);
	for(i=0; i < elementsof(Ttable); i++)
	{
		tp= &Ttable[i];
		if(tp->flags&IG)
		{
			if(tp->flags&NL)
				sfputc(sfstdout,'\n');
			continue;
		}
		switch(tp->type)
		{
		    case BIT:
		    case BITS:
			off = off2 = 1;
			switch(tp->field)
			{
			    case C_FLAG:
				if(sp->c_cflag&tp->mask)
					off = 0;
				if(tty.c_cflag&tp->mask)
					off2 = 0;
				break;
			    case I_FLAG:
				if(sp->c_iflag&tp->mask)
					off = 0;
				if(tty.c_iflag&tp->mask)
					off2 = 0;
				break;
			    case O_FLAG:
				if((sp->c_oflag&tp->mask)==tp->val)
					off = 0;
				if(tty.c_oflag&tp->mask)
					off2 = 0;
				break;
			    case L_FLAG:
				if(sp->c_lflag&tp->mask)
					off = 0;
				if(tty.c_lflag&tp->mask)
					off2 = 0;
			}
			if(tp->flags&NL)
				delim = '\n';
			if(!flags && off==off2)
				continue;
			if(!off)
				sfprintf(sfstdout,"%s%c",tp->name,delim);
			else if(tp->type==BIT)
				sfprintf(sfstdout,"-%s%c",tp->name,delim);
			delim = ' ';
			break;

		    case CHAR:
			off = sp->c_cc[tp->mask];
			if(tp->flags&NL)
				delim = '\n';
			if(!flags && off==(unsigned char)tty.c_cc[tp->mask])
				continue;
			if(off==_POSIX_VDISABLE)
				sfprintf(sfstdout,"%s = <undef>;%c",tp->name,delim);
			else if(isprint(off&0xff))
				sfprintf(sfstdout,"%s = %c;%c",tp->name,off,delim);
			else
#if CC_NATIVE == CC_ASCII
			sfprintf(sfstdout,"%s = ^%c;%c",tp->name,off==0177?'?':(off^0100),delim);
#else
			{
				off = ccmapc(off, CC_NATIVE, CC_ASCII);
				sfprintf(sfstdout,"%s = ^%c;%c",tp->name,off==0177?'?':ccmapc(off^0100,CC_ASCII,CC_NATIVE),delim);
			}
#endif
			delim = ' ';
			break;
		    case SIZE:
			if((sp->c_cflag&CSIZE)!=tp->mask)
				continue;
			if(flags || (sp->c_cflag&CSIZE) != (tty.c_cflag&CSIZE))
				sfprintf(sfstdout,"%s ",tp->name);
			break;
		    case SPEED:
			if(tp->mask==ispeed)
			{
				if(ispeed!=ospeed)
					schar[0]='i';
				else
					schar[0]=0;
			}
			else if(tp->mask==ospeed)
				schar[0]='o';
			else
				continue;
			schar[1] = 0;
#ifdef TIOCSWINSZ
			{
				struct winsize win;
				off = ioctl(0,TIOCGWINSZ,&win);
				if(off>=0)
					sfprintf(sfstdout,"%sspeed %s baud; rows %d; columns %d;\n",schar,tp->name,win.ws_row,win.ws_col);
			}
			if(off<0)
#endif
				sfprintf(sfstdout,"%sspeed %s baud;\n",schar,tp->name);
		}
	}
	if(delim=='\n')
		sfputc(sfstdout,'\n');
}

static const Tty_t *lookup(const char *name)
{
	register int i;
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(strcmp(Ttable[i].name,name)==0)
			return(&Ttable[i]);
	}
	return(0);

}

static const Tty_t *getspeed(unsigned long val)
{
	register int i;
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(Ttable[i].type==SPEED && Ttable[i].mask==val)
			return(&Ttable[i]);
	}
	return(0);
}

static int gettchar(register const char *cp)
{
	if(*cp==0)
		return(-1);
	if(cp[1]==0)
		return((unsigned)cp[0]);
	if(*cp=='^' && cp[1] && cp[2]==0)
	{
		switch(cp[1])
		{
		    case '-':
			return(-1);
		    default:
			return(cntl(cp[1]));
		}
	}
	if(streq(cp,"undef") || streq(cp,"<undef>"))
		return(-1);
	return(*((unsigned char*)cp));
}

static void set(char *argv[], struct termios *sp)
{
	const Tty_t *tp;
	register int c,off;
	char *cp;
	char *ep;
	while(cp = *argv++)
	{
		off = 0;
		if(*cp=='-')
		{
			cp++;
			off=1;
		}
		if(!(tp=lookup(cp)) || (off && (tp->type!=BIT) && (tp->type!=TABS)))
			error(ERROR_exit(1),"%s: unknown mode",cp);
		switch(tp->type)
		{
		    case CHAR:
			if(off)
				error(ERROR_exit(1),"%s: unknown mode",cp);
			if(!*argv)
				error(ERROR_exit(1),"missing argument to %s",cp);
			c = gettchar(*argv++);
			if(c>=0)
				sp->c_cc[tp->mask] = c;
			else
				sp->c_cc[tp->mask] = _POSIX_VDISABLE;
			break;
		    case BIT: case BITS:
			switch(tp->field)
			{
			    case C_FLAG:
				if(off)
					sp->c_cflag &= ~tp->mask;
				else
					sp->c_cflag |= tp->mask;
				break;
			    case I_FLAG:
				if(off)
					sp->c_iflag &= ~tp->mask;
				else
					sp->c_iflag |= tp->mask;
				break;
			    case O_FLAG:
				sp->c_oflag &= ~tp->mask;
				sp->c_oflag |= tp->val;
				break;
			    case L_FLAG:
				if(off)
					sp->c_lflag &= ~tp->mask;
				else
					sp->c_lflag |= tp->mask;
				break;
			}
			break;
		    case TABS:
			sp->c_oflag &= ~tp->mask;
			if(off)
				sp->c_oflag |= tp->val;
			break;
#ifdef TIOCSWINSZ
		    case WIND:
		    {
			struct winsize win;
			int n;
			if(ioctl(0,TIOCGWINSZ,&win)<0)
				error(ERROR_system(1),"cannot set %s",tp->name);
			if(!(cp= *argv))
			{
				sfprintf(sfstdout,"%d\n",tp->mask?win.ws_col:win.ws_row);
				break;
			}
			argv++;
			n=strtol(cp,&cp,10);
			if(*cp)
				error(ERROR_system(1),"%d: invalid number of %s",argv[-1],tp->name);
			if(tp->mask)
				win.ws_col = n;
			else
				win.ws_row = n;
			if(ioctl(0,TIOCSWINSZ,&win)<0)
				error(ERROR_system(1),"cannot set %s",tp->name);
			break;
		    }
#endif
		    case NUM:
			cp = *argv;
			if (!cp)
			{
				if (tp->field == C_SPEED)
				{
					if (tp = getspeed(*tp->name == 'i' ? cfgetispeed(sp) : cfgetospeed(sp)))
						sfprintf(sfstdout, "%s\n", tp->name);
					break;
				}
				error(ERROR_exit(1), "%s: missing numeric argument", tp->name);
			}
			argv++;
			c = (int)strtol(cp, &ep, 10);
			if (*ep)
				error(ERROR_exit(1), "%s: %s: numeric argument expected", tp->name, cp);
			switch (tp->field)
			{
#if _mem_c_line_termios
			case C_LINE:
				sp->c_line = c;
				break;
#endif
			case C_SPEED:
				if(getspeed(c))
				{
					if (*tp->name != 'o')
						cfsetispeed(sp, c);
					if (*tp->name != 'i')
						cfsetospeed(sp, c);
				}
				else
					error(ERROR_exit(1), "%s: %s: invalid speed", tp->name, cp);
				break;
			case T_CHAR:
				sp->c_cc[tp->mask] = c;
				break;
			}
			break;
		    case SPEED:
			cfsetospeed(sp, tp->mask);
			cfsetispeed(sp, tp->mask);
			break;
		    case SIZE:
			sp->c_cflag &= ~CSIZE;
			sp->c_cflag |= tp->mask;
			break;
		    case SANE:
			sane(sp);
			break;
#if defined(OLCUC) && defined(IUCLC)
		    case CASE:
			if(off)
			{
				sp->c_iflag |= IUCLC;
				sp->c_oflag |= OLCUC;
			}
			else
			{
				sp->c_iflag &= ~IUCLC;
				sp->c_oflag &= ~OLCUC;
			}
			break;
#endif /* OLCUC && IUCLC */
		}
	}
}


static void listchars(Sfio_t *sp,int type)
{
	int i,c;
	c = (type==CHAR?'c':'n');
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(Ttable[i].type==type && *Ttable[i].description)
			sfprintf(sp,"[+%s \a%c\a?%s.]",Ttable[i].name,c,Ttable[i].description);
	}
}

static void listgroup(Sfio_t *sp,int type, const char *description)
{
	int i;
	sfprintf(sp,"[+");
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(Ttable[i].type==type)
			sfprintf(sp,"%s ",Ttable[i].name);
	}
	sfprintf(sp,"?%s.]",description);
}

static void listmask(Sfio_t *sp,unsigned int mask,const char *description)
{
	int i;
	sfprintf(sp,"[+");
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(Ttable[i].mask==mask && Ttable[i].type==BITS)
			sfprintf(sp,"%s ",Ttable[i].name);
	}
	sfprintf(sp,"?%s.]",description);
}

static void listfields(Sfio_t *sp,int field)
{
	int i;
	for(i=0; i < elementsof(Ttable); i++)
	{
		if(Ttable[i].field==field &&  Ttable[i].type==BIT && *Ttable[i].description)
			sfprintf(sp,"[+%s (-%s)?%s.]",Ttable[i].name,Ttable[i].name,Ttable[i].description);
	}
}

static void listmode(Sfio_t *sp,const char *name)
{
	sfprintf(sp,"[+%s?%s.]",name,lookup(name)->description);
}

static int infof(Opt_t* op, Sfio_t* sp, const char* s, Optdisc_t* dp)
{
	NoP(op);
	NoP(s);
	NoP(dp);
	sfprintf(sp,"[+Control Modes.]{");
	listfields(sp,C_FLAG);
	listgroup(sp,SPEED,"Attempt to set input and output baud rate to number given.  A value of \b0\b causes immediate hangup");
	listchars(sp,NUM);
	listgroup(sp,SIZE,"Number of bits in a character");
	sfprintf(sp,"}[+Input Modes.]{");
	listfields(sp,I_FLAG);
	sfprintf(sp,"}[+Output Modes.]{");
	listfields(sp,O_FLAG);
#ifdef CRDLY
	listmask(sp,CRDLY,"Carriage return delay style");
#endif
#ifdef NLDLY
	listmask(sp,NLDLY,"Newline delay style");
#endif
#ifdef TABDLY
	listmask(sp,TABDLY,"Horizontal tab delay style");
#endif
#ifdef BSDLY
	listmask(sp,BSDLY,"Backspace delay style");
#endif
#ifdef FFDLY
	listmask(sp,FFDLY,"Form feed delay style");
#endif
#ifdef VTDLY
	listmask(sp,VTDLY,"Vertical tab delay style");
#endif
	sfprintf(sp,"}[+Local Modes.]{");
	listfields(sp,L_FLAG);
	sfprintf(sp,"}[+Control Assignments.?If \ac\a is \bundef\b or an empty "
		"string then the control assignment is disabled.]{");
	listchars(sp,WIND);
	listchars(sp,CHAR);
	sfprintf(sp,"}[+Combination Modes.]{");
	listmode(sp,"ek");
	listmode(sp,"evenp");
	listmode(sp,"lcase");
	listmode(sp,"oddp");
	listmode(sp,"parity");
	listmode(sp,"sane");
	listmode(sp,"tabs");
	listmode(sp,"LCASE");
	sfputc(sp,'}');
	return(1);
}

#ifndef _lib_tcgetpgrp
#  ifdef TIOCGPGRP
	   static int _i_;
#	   define tcgetpgrp(a) (ioctl(a, TIOCGPGRP, &_i_)>=0?_i_:-1)	
#  else
#	   define tcgetpgrp(a) (-1)
#  endif /* TIOCGPGRP */
#endif /* _lib_tcgetpgrp */

int
b_stty(int argc, char** argv, Shbltin_t* context)
{
	struct termios		tty;
	register int		n;
	register int		flags = 0;
	int			fd = 0;
	const Tty_t*		tp;
	Optdisc_t		disc;

	cmdinit(argc, argv, context, ERROR_CATALOG, ERROR_INTERACTIVE);
	memset(&disc, 0, sizeof(disc));
	disc.version = OPT_VERSION;
	disc.infof = infof;
	opt_info.disc = &disc;
	for (;;)
	{
		switch (n = optget(argv, usage))
		{
		case 'f':
			fd = (int)opt_info.num;
			continue;
		case 'a':
		case 'g':
		case 't':
			if (!opt_info.offset || !argv[opt_info.index][opt_info.offset])
			{
				switch (n)
				{
				case 'a':
					flags |= A_FLAG;
					break;
				case 'g':
					flags |= G_FLAG;
					break;
				case 't':
					flags |= T_FLAG;
					break;
				}
				continue;
			}
			/*FALLTHROUGH*/
		case ':':
			if (!opt_info.offset)
				error(2, "%s", opt_info.arg);
			else if (!(tp = lookup(argv[opt_info.index]+1)) || (tp->type != BIT && tp->type != TABS))
				error(ERROR_exit(1), "%s: unknown mode", argv[opt_info.index]);
			break;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || (flags && *argv) || (flags&(flags-1)))
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (tcgetattr(fd, &tty) < 0)
		error(ERROR_system(1), "not a tty");
	if (flags & T_FLAG)
		sfprintf(sfstdout, "%d\n", tcgetpgrp(0));
	else if (*argv)
	{
		if (!argv[1] && **argv == ':')
			gin(*argv, &tty);
		else
			set(argv, &tty);
		if (tcsetattr(0, TCSANOW, &tty) < 0)
			error(ERROR_system(1), "cannot set tty");
	}
	else
		output(&tty, flags);
	return error_info.errors;
}
