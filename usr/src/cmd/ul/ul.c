/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Copyright (c) 1983, 1984 1985, 1986, 1987, 1988, 2000 Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#include <stdio.h>
#include <locale.h>
#include <wctype.h>
#include <widec.h>
#include <euc.h>
#include <limits.h>
#include <stdlib.h>

#define	IESC	L'\033'
#define	SO	L'\016'
#define	SI	L'\017'
#define	HFWD	L'9'
#define	HREV	L'8'
#define	FREV	L'7'
#define	CDUMMY	-1

#define	NORMAL	000
#define	ALTSET	001	/* Reverse */
#define	SUPERSC	002	/* Dim */
#define	SUBSC	004	/* Dim | Ul */
#define	UNDERL	010	/* Ul */
#define	BOLD	020	/* Bold */

#define	MEMFCT	16
/*
 * MEMFCT is a number that is likely to be large enough as a factor for
 * allocating more memory and to be small enough so as not wasting memory
 */

int	must_use_uc, must_overstrike;
char	*CURS_UP, *CURS_RIGHT, *CURS_LEFT,
	*ENTER_STANDOUT, *EXIT_STANDOUT, *ENTER_UNDERLINE, *EXIT_UNDERLINE,
	*ENTER_DIM, *ENTER_BOLD, *ENTER_REVERSE, *UNDER_CHAR, *EXIT_ATTRIBUTES;

struct	CHAR	{
	char	c_mode;
	wchar_t	c_char;
};

struct	CHAR	obuf[LINE_MAX];
int	col, maxcol;
int	mode;
int	halfpos;
int	upln;
int	iflag;

eucwidth_t wp;
int scrw[4];

main(argc, argv)
	int argc;
	char **argv;
{
	int c;
	char *cp, *termtype;
	FILE *f;
	char termcap[1024];
	char *getenv();
	extern int optind;
	extern char *optarg;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	getwidth(&wp);
	scrw[0] = 1;
	scrw[1] = wp._scrw1;
	scrw[2] = wp._scrw2;
	scrw[3] = wp._scrw3;

	termtype = getenv("TERM");
	if (termtype == NULL || (argv[0][0] == 'c' && !isatty(1)))
		termtype = "lpr";
	while ((c=getopt(argc, argv, "it:T:")) != EOF)
		switch (c) {

		case 't':
		case 'T': /* for nroff compatibility */
				termtype = optarg;
			break;
		case 'i':
			iflag = 1;
			break;

		default:
			fprintf(stderr,
			gettext("\
Usage: %s [ -i ] [ -t terminal ] [ filename...]\n"),
				argv[0]);
			exit(1);
		}

	switch (tgetent(termcap, termtype)) {

	case 1:
		break;

	default:
		fprintf(stderr, gettext("trouble reading termcap"));
		/* fall through to ... */

	case 0:
		/* No such terminal type - assume dumb */
		strcpy(termcap, "dumb:os:col#80:cr=^M:sf=^J:am:");
		break;
	}
	initcap();
	if ((tgetflag("os") && ENTER_BOLD==NULL) ||
		(tgetflag("ul") && ENTER_UNDERLINE==NULL && UNDER_CHAR==NULL))
			must_overstrike = 1;
	initbuf();
	if (optind == argc)
		filter(stdin);
	else for (; optind<argc; optind++) {
		f = fopen(argv[optind], "r");
		if (f == NULL) {
			perror(argv[optind]);
			exit(1);
		} else
			filter(f);
	}
	exit(0);
}

filter(f)
FILE *f;
{
	register wchar_t c;
	register i;

	while ((c = getwc(f)) != EOF) {
		if (maxcol >= LINE_MAX)
		{
			fprintf(stderr,
	gettext("Input line longer than %d characters\n"), LINE_MAX);
			exit(1);
		}
		switch (c) {

		case L'\b':
			if (col > 0)
				col--;
			continue;

		case L'\t':
			col = (col+8) & ~07;
			if (col > maxcol)
				maxcol = col;
			continue;

		case L'\r':
			col = 0;
			continue;

		case SO:
			mode |= ALTSET;
			continue;

		case SI:
			mode &= ~ALTSET;
			continue;

		case IESC:
			switch (c = getwc(f)) {
			case HREV:
				if (halfpos == 0) {
					mode |= SUPERSC;
					halfpos--;
				} else if (halfpos > 0) {
					mode &= ~SUBSC;
					halfpos--;
				} else {
					halfpos = 0;
					reverse();
				}
				continue;

			case HFWD:
				if (halfpos == 0) {
					mode |= SUBSC;
					halfpos++;
				} else if (halfpos < 0) {
					mode &= ~SUPERSC;
					halfpos++;
				} else {
					halfpos = 0;
					fwd();
				}
				continue;
			case FREV:
				reverse();
				continue;

			default:
				fprintf(stderr,
			gettext("Unknown escape sequence in input: %o, %o\n"),
					IESC, c);
				exit(1);
			}
			continue;

		case L'_':
			if (obuf[col].c_char)
				obuf[col].c_mode |= UNDERL | mode;
			else
				obuf[col].c_char = '_';
		case L' ':
			col++;
			if (col > maxcol)
				maxcol = col;
			continue;

		case L'\n':
			flushln();
			continue;

		default:
			if (c < L' ')	/* non printing */
				continue;
			if (obuf[col].c_char == L'\0') {
				obuf[col].c_char = c;
				obuf[col].c_mode = mode;
				i = scrw[wcsetno(c)];
				while (--i > 0)
					obuf[++col].c_char = CDUMMY;
			} else if (obuf[col].c_char == L'_') {
				obuf[col].c_char = c;
				obuf[col].c_mode |= UNDERL|mode;
				i = scrw[wcsetno(c)];
				while (--i > 0)
					obuf[++col].c_char = CDUMMY;
			} else if (obuf[col].c_char == c)
				obuf[col].c_mode |= BOLD|mode;
			else {
				obuf[col].c_char = c;
				obuf[col].c_mode = mode;
			}
			col++;
			if (col > maxcol)
				maxcol = col;
			continue;
		}
	}
	if (maxcol)
		flushln();
}

flushln()
{
	register lastmode;
	register i;
	int hadmodes = 0;

	lastmode = NORMAL;
	for (i=0; i<maxcol; i++) {
		if (obuf[i].c_mode != lastmode) {
			hadmodes++;
			setmode(obuf[i].c_mode);
			lastmode = obuf[i].c_mode;
		}
		if (obuf[i].c_char == L'\0') {
			if (upln) {
				puts(CURS_RIGHT);
			} else
				outc(L' ');
		} else
			outc(obuf[i].c_char);
	}
	if (lastmode != NORMAL) {
		setmode(0);
	}
	if (must_overstrike && hadmodes)
		overstrike();
	putwchar(L'\n');
	if (iflag && hadmodes)
		iattr();
	if (upln)
		upln--;
	initbuf();
}

/*
 * For terminals that can overstrike, overstrike underlines and bolds.
 * We don't do anything with halfline ups and downs, or Greek.
 */
overstrike()
{
	register int i, n;
	wchar_t *cp, *scp;
	size_t  szbf = 256, tszbf;
	int hadbold=0;

	scp = (wchar_t *)malloc(sizeof (wchar_t) * szbf);
	if (!scp) {
	/* this kind of message need not to be gettext'ed */
		(void) fprintf(stderr, "malloc failed\n");
		exit(1);
	}
	cp = scp;
	tszbf = szbf;
#ifdef DEBUG
	/*
	 * to allocate a memory after the chunk of the current scp
	 * and to make sure the following realloc() allocates
	 * memory from different chunks.
	 */
	(void) malloc(1024 * 1024);
#endif

	/* Set up overstrike buffer */
	for (i=0; i<maxcol; i++) {
		n = scrw[wcsetno(obuf[i].c_char)];
		if (tszbf <= n) {
		/* may not enough buffer for this char */
			size_t  pos;

			/* obtain the offset of cp */
			pos = cp - scp;
			/* reallocate another (n * MEMFCT) * sizeof (wchar_t) */
			scp = (wchar_t *)realloc(scp,
				sizeof (wchar_t) * (szbf + (n * MEMFCT)));
			if (!scp) {
				(void) fprintf(stderr, "malloc failed\n");
				exit(1);
			}
			/* get the new address of cp */
			cp = scp + pos;
			szbf += n * MEMFCT;
			tszbf += n * MEMFCT;
		}
		switch (obuf[i].c_mode) {
		case NORMAL:
		default:
			tszbf -= n;
			*cp++ = L' ';
			while (--n > 0) {
				*cp++ = L' ';
				i++;
			}
			break;
		case UNDERL:
			tszbf -= n;
			*cp++ = L'_';
			while (--n > 0) {
				*cp++ = L'_';
				i++;
			}
			break;
		case BOLD:
			tszbf--;
			*cp++ = obuf[i].c_char;
			hadbold=1;
			break;
		}
	}
	putwchar(L'\r');
	for (*cp=L' '; *cp==L' '; cp--)
		*cp = L'\0';
	for (cp=scp; *cp; cp++)
		putwchar(*cp);
	if (hadbold) {
		putwchar(L'\r');
		for (cp=scp; *cp; cp++)
			putwchar(*cp==L'_' ? L' ' : *cp);
		putwchar(L'\r');
		for (cp=scp; *cp; cp++)
			putwchar(*cp==L'_' ? L' ' : *cp);
	}
	free(scp);
}

iattr()
{
	register int i, n;
	wchar_t *cp, *scp;
	register wchar_t cx;
	size_t  szbf = 256, tszbf;

	scp = (wchar_t *)malloc(sizeof (wchar_t) * szbf);
	if (!scp) {
		/* this kind of message need not to be gettext'ed */
		(void) fprintf(stderr, "malloc failed\n");
		exit(1);
	}
	cp = scp;
	tszbf = szbf;
#ifdef DEBUG
	/*
	 * to allocate a memory after the chunk of the current scp
	 * and to make sure the following realloc() allocates
	 * memory from different chunks.
	 */
	(void) malloc(1024 * 1024);
#endif
	for (i=0; i<maxcol; i++) {
		switch (obuf[i].c_mode) {
		case NORMAL:	cx = ' '; break;
		case ALTSET:	cx = 'g'; break;
		case SUPERSC:	cx = '^'; break;
		case SUBSC:	cx = 'v'; break;
		case UNDERL:	cx = '_'; break;
		case BOLD:	cx = '!'; break;
		default:	cx = 'X'; break;
		}
		n = scrw[wcsetno(obuf[i].c_char)];
		if (tszbf <= n) {
			/* may not enough buffer for this char */
			size_t  pos;

			/* obtain the offset of cp */
			pos = cp - scp;
			/* reallocate another (n * MEMFCT) * sizeof (wchar_t) */
			scp = (wchar_t *)realloc(scp,
				sizeof (wchar_t) * (szbf + (n * MEMFCT)));
			if (!scp) {
				(void) fprintf(stderr, "malloc failed\n");
				exit(1);
			}
			/* get the new address of cp */
			cp = scp + pos;
			szbf += n * MEMFCT;
			tszbf += n * MEMFCT;
		}
		tszbf -= n;
		 *cp++ = cx;
		while (--n > 0) {
			*cp++ = cx;
			i++;
		}
	}
	for (*cp=L' '; *cp==L' '; cp--)
		*cp = L'\0';
	for (cp=scp; *cp; cp++)
		putwchar(*cp);
	putwchar(L'\n');
	free(scp);
}

initbuf()
{
	register i;

	/* following depends on NORMAL == 000 */
	for (i = 0; i < LINE_MAX; i++)
		obuf[i].c_char = obuf[i].c_mode = 0;

	col = 0;
	maxcol = 0;
	mode &= ALTSET;
}

fwd()
{
	register oldcol, oldmax;

	oldcol = col;
	oldmax = maxcol;
	flushln();
	col = oldcol;
	maxcol = oldmax;
}

reverse()
{
	upln++;
	fwd();
	puts(CURS_UP);
	puts(CURS_UP);
	upln++;
}

initcap()
{
	static char tcapbuf[512];
	char *termtype;
	char *bp = tcapbuf;
	char *getenv(), *tgetstr();

	/* This nonsense attempts to work with both old and new termcap */
	CURS_UP =		tgetstr("up", &bp);
	CURS_RIGHT =		tgetstr("ri", &bp);
	if (CURS_RIGHT == NULL)
		CURS_RIGHT =	tgetstr("nd", &bp);
	CURS_LEFT =		tgetstr("le", &bp);
	if (CURS_LEFT == NULL)
		CURS_LEFT =	tgetstr("bc", &bp);
	if (CURS_LEFT == NULL && tgetflag("bs"))
		CURS_LEFT =	"\b";

	ENTER_STANDOUT =	tgetstr("so", &bp);
	EXIT_STANDOUT =		tgetstr("se", &bp);
	ENTER_UNDERLINE =	tgetstr("us", &bp);
	EXIT_UNDERLINE =	tgetstr("ue", &bp);
	ENTER_DIM =		tgetstr("mh", &bp);
	ENTER_BOLD =		tgetstr("md", &bp);
	ENTER_REVERSE =		tgetstr("mr", &bp);
	EXIT_ATTRIBUTES =	tgetstr("me", &bp);

	if (!ENTER_BOLD && ENTER_REVERSE)
		ENTER_BOLD = ENTER_REVERSE;
	if (!ENTER_BOLD && ENTER_STANDOUT)
		ENTER_BOLD = ENTER_STANDOUT;
	if (!ENTER_UNDERLINE && ENTER_STANDOUT) {
		ENTER_UNDERLINE = ENTER_STANDOUT;
		EXIT_UNDERLINE = EXIT_STANDOUT;
	}
	if (!ENTER_DIM && ENTER_STANDOUT)
		ENTER_DIM = ENTER_STANDOUT;
	if (!ENTER_REVERSE && ENTER_STANDOUT)
		ENTER_REVERSE = ENTER_STANDOUT;
	if (!EXIT_ATTRIBUTES && EXIT_STANDOUT)
		EXIT_ATTRIBUTES = EXIT_STANDOUT;

	/*
	 * Note that we use REVERSE for the alternate character set,
	 * not the as/ae capabilities.  This is because we are modelling
	 * the model 37 teletype (since that's what nroff outputs) and
	 * the typical as/ae is more of a graphics set, not the greek
	 * letters the 37 has.
	 */

#ifdef notdef
printf("so %s se %s us %s ue %s me %s\n",
	ENTER_STANDOUT, EXIT_STANDOUT, ENTER_UNDERLINE,
	EXIT_UNDERLINE, EXIT_ATTRIBUTES);
#endif
	UNDER_CHAR =		tgetstr("uc", &bp);
	must_use_uc = (UNDER_CHAR && !ENTER_UNDERLINE);
}

outchar(c)
char c;
{
	putchar(c&0177);
}

puts(str)
const char *str;
{
	if (str)
		tputs(str, 1, outchar);
}

static curmode = 0;
outc(c)
wchar_t c;
{
	register int m, n;

	if (c == CDUMMY)
		return;
	putwchar(c);
	if (must_use_uc && (curmode & UNDERL)) {
		m = n = scrw[wcsetno(c)];
		puts(CURS_LEFT);
		while (--m > 0)
			puts(CURS_LEFT);
		puts(UNDER_CHAR);
		while (--n > 0)
			puts(UNDER_CHAR);
	}
}

setmode(newmode)
int newmode;
{
	if (!iflag)
	{
		if (curmode != NORMAL && newmode != NORMAL)
			setmode(NORMAL);
		switch (newmode) {
		case NORMAL:
			switch (curmode) {
			case NORMAL:
				break;
			case UNDERL:
				puts(EXIT_UNDERLINE);
				break;
			default:
				/* This includes standout */
				puts(EXIT_ATTRIBUTES);
				break;
			}
			break;
		case ALTSET:
			puts(ENTER_REVERSE);
			break;
		case SUPERSC:
			/*
			 * This only works on a few terminals.
			 * It should be fixed.
			 */
			puts(ENTER_UNDERLINE);
			puts(ENTER_DIM);
			break;
		case SUBSC:
			puts(ENTER_DIM);
			break;
		case UNDERL:
			puts(ENTER_UNDERLINE);
			break;
		case BOLD:
			puts(ENTER_BOLD);
			break;
		default:
			/*
			 * We should have some provision here for multiple modes
			 * on at once.  This will have to come later.
			 */
			puts(ENTER_STANDOUT);
			break;
		}
	}
	curmode = newmode;
}
