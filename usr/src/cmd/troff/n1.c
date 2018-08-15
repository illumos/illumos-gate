/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * n1.c
 *
 *	consume options, initialization, main loop,
 *	input routines, escape function calling
 */

#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <time.h>
#include <stdarg.h>
#include <locale.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef 	EUC
#ifdef	NROFF
#include <stddef.h>
#include <limits.h>
#endif	/* NROFF */
#endif	/* EUC */

#include "tdef.h"
#include "ext.h"

#ifdef NROFF
#include "tw.h"
#endif

#define	MAX_RECURSION_DEPTH	512

jmp_buf sjbuf;
extern	void	fdprintf(int, char *, ...);
extern	char	*roff_sprintf(char *, char *, ...);
filep	ipl[NSO];
long	offl[NSO];
long	ioff;
char	*ttyp;
char	cfname[NSO+1][NS];	/*file name stack*/
int	cfline[NSO];		/*input line count stack*/
char	*progname;	/* program name (troff) */
#ifdef	EUC
#ifdef	NROFF
char	mbbuf1[MB_LEN_MAX + 1];
char	*mbbuf1p = mbbuf1;
wchar_t	twc = 0;
#endif	/* NROFF */
#endif	/* EUC */

#ifdef	DEBUG
int	debug = 0;	/*debug flag*/
#endif	/* DEBUG */

static char *sprintn(char *, long, int);
static int printn(long, int);

int
main(int argc, char **argv)
{
	char	*p, *q;
	int	j;
	tchar i;
	int eileenct;		/*count to test for "Eileen's loop"*/
	extern void catch(), kcatch();
	char	**oargv;

	(void)setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void)textdomain(TEXT_DOMAIN);
	progname = argv[0];
	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		signal(SIGHUP, catch);
	if (signal(SIGINT, catch) == SIG_IGN) {
		signal(SIGHUP, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
	}
	signal(SIGPIPE, catch);
	signal(SIGTERM, kcatch);
	oargv = argv;
	strcpy(cfname[0], "<standard input>");
	mrehash();
	nrehash();
	init0();
#ifdef EUC
#ifdef NROFF
	(void)localize();
#endif /* NROFF */
#endif /* EUC */
	if ((p = getenv("TYPESETTER")) != 0)
		strcpy(devname, p);
	while (--argc > 0 && (++argv)[0][0] == '-')
		switch (argv[0][1]) {

		case 'F':	/* switch font tables from default */
			if (argv[0][2] != '\0') {
				strcpy(termtab, &argv[0][2]);
				strcpy(fontfile, &argv[0][2]);
			} else {
				argv++; argc--;
				if (argv[0] != NULL) {
					strcpy(termtab, argv[0]);
					strcpy(fontfile, argv[0]);
				} else
					errprint(gettext("missing the font directory"));
			}
			continue;
		case 0:
			goto start;
		case 'i':
			stdi++;
			continue;
		case 'q':
#ifdef	NROFF
			quiet++;
			save_tty();
#else
			errprint(gettext("-q option ignored in troff"));
#endif	/* NROFF */
			continue;
		case 'n':
			npn = ctoi(&argv[0][2]);
			continue;
		case 'u':	/* set emboldening amount */
			bdtab[3] = ctoi(&argv[0][2]);
			if (bdtab[3] < 0 || bdtab[3] > 50)
				bdtab[3] = 0;
			continue;
		case 's':
			if (!(stop = ctoi(&argv[0][2])))
				stop++;
			continue;
		case 't':
			ptid = 1;
			continue;
		case 'r':
			if (strlen(&argv[0][2]) >= 2) {
				eibuf = roff_sprintf(ibuf+strlen(ibuf),
				    ".nr %c %s\n", argv[0][2], &argv[0][3]);
			} else {
				errprint(gettext("wrong options"));
			}
			continue;
		case 'c':
		case 'm':
			if (mflg++ >= NMF) {
				errprint(gettext("Too many macro packages: %s"),
					 argv[0]);
				continue;
			}
		        if (argv[0][2] == '\0') {
				errprint(gettext("No library provided with -m"));
				done(02);
			}
			p = getenv("TROFFMACS");
			if (p != NULL && *p != '\0') {
			     if (tryfile(getenv("TROFFMACS"), &argv[0][2], nmfi))
			       nmfi++;
			} else
			  if (tryfile("/usr/share/lib/tmac/", &argv[0][2], nmfi)
			  || tryfile("/usr/share/lib/tmac/tmac.", &argv[0][2], nmfi))
				nmfi++;
			  else {
				errprint(gettext("Cannot find library %s\n"),
					argv[0]);
				done(02);
			  } 
			continue;
		case 'o':
			getpn(&argv[0][2]);
			continue;
		case 'T':
			strcpy(devname, &argv[0][2]);
			dotT++;
			continue;
#ifdef NROFF
		case 'h':
			hflg++;
			continue;
		case 'z':
			no_out++;
			continue;
		case 'e':
			eqflg++;
			continue;
#endif
#ifndef NROFF
		case 'z':
			no_out++;
		case 'a':
			ascii = 1;
			nofeed++;
			continue;
		case 'f':
			nofeed++;
			continue;
#endif
		case '#':
#ifdef	DEBUG
			debug = ctoi(&argv[0][2]);
#else
			errprint("DEBUG not enabled");
#endif	/* DEBUG */
			continue;
		default:
			errprint(gettext("unknown option %s"), argv[0]);
			done(02);
		}

start:
	init1(oargv[0][0]);
	argp = argv;
	rargc = argc;
	nmfi = 0;
	init2();
	setjmp(sjbuf);
	eileenct = 0;		/*reset count for "Eileen's loop"*/
loop:
	copyf = lgf = nb = nflush = nlflg = 0;
	if (ip && rbf0(ip) == 0 && ejf && frame->pframe <= ejl) {
		nflush++;
		trap = 0;
		eject((struct s *)0);
#ifdef	DEBUG
	if (debug & DB_LOOP)
		fdprintf(stderr, "loop: NL=%d, ejf=%d, lss=%d, eileenct=%d\n",
			numtab[NL].val, ejf, lss, eileenct);
#endif	/* DEBUG */
		if (eileenct > 20) {
			errprint(gettext("job looping; check abuse of macros"));
			ejf = 0;	/*try to break Eileen's loop*/
			eileenct = 0;
		} else
			eileenct++;
		goto loop;
	}
	eileenct = 0;		/*reset count for "Eileen's loop"*/
	i = getch();
	if (pendt)
		goto Lt;
	if ((j = cbits(i)) == XPAR) {
		copyf++;
		tflg++;
		while (cbits(i) != '\n')
			pchar(i = getch());
		tflg = 0;
		copyf--;
		goto loop;
	}
	if (j == cc || j == c2) {
		if (j == c2)
			nb++;
		copyf++;
		while ((j = cbits(i = getch())) == ' ' || j == '\t')
			;
		ch = i;
		copyf--;
		control(getrq(), 1);
		flushi();
		goto loop;
	}
Lt:
	ch = i;
	text();
	if (nlflg)
		numtab[HP].val = 0;
	goto loop;
}


int
tryfile(pat, fn, idx)
char *pat, *fn;
int idx;
{
	strcpy(mfiles[idx], pat);
	strcat(mfiles[idx], fn);
	if (access(mfiles[idx], 4) == -1)
		return(0);
	else return(1);
}	

void catch()
{
	done3(01);
}


void kcatch()
{
	signal(SIGTERM, SIG_IGN);
	done3(01);
}

int
init0()
{
	eibuf = ibufp = ibuf;
	ibuf[0] = 0;
	numtab[NL].val = -1;
	return (0);
}


int
init1(a)
char	a;
{
	char	*p;
	int i;

	p = tmp_name;
	if (a == 'a')
		p = &p[9];
	if ((ibf = mkstemp(p)) == -1) {
		errprint(gettext("cannot create temp file."));
		exit(-1);
	}
	unlkp = p;
	for (i = NTRTAB; --i; )
		trtab[i] = i;
	trtab[UNPAD] = ' ';
	return (0);
}


int
init2()
{
	int	i, j;
	extern char	*setbrk();
	extern char	*ttyname();

	ttyod = 2;
	if ((ttyp=ttyname(j=0)) != 0 || (ttyp=ttyname(j=1)) != 0 || (ttyp=ttyname(j=2)) != 0)
		;
	else 
		ttyp = "notty";
	iflg = j;
	if (ascii)
		mesg(0);
	obufp = obuf;
	ptinit();
	mchbits();
	cvtime();
	numtab[PID].val = getpid();
	olinep = oline;
	ioff = 0;
	numtab[HP].val = init = 0;
	numtab[NL].val = -1;
	nfo = 0;
	ifile = 0;
	copyf = raw = 0;
	eibuf = roff_sprintf(ibuf+strlen(ibuf), ".ds .T %s\n", devname);
	numtab[CD].val = -1;	/* compensation */
	cpushback(ibuf);
	ibufp = ibuf;
	nx = mflg;
	frame = stk = (struct s *)setbrk(DELTA);
	dip = &d[0];
	nxf = frame + 1;
#ifdef INCORE
	for (i = 0; i < NEV; i++) {
		extern tchar corebuf[];
		*(struct env *)&corebuf[i * sizeof(env)/sizeof(tchar)] = env;
	}
#else
	for (i = NEV; i--; )
		write(ibf, (char *) & env, sizeof(env));
#endif
	return (0);
}

int
cvtime()
{
	time_t	tt;
	struct tm *tm;

	tt = time((time_t *) 0);
	tm = localtime(&tt);
	numtab[DY].val = tm->tm_mday;
	numtab[DW].val = tm->tm_wday + 1;
	numtab[YR].val = tm->tm_year;
	numtab[MO].val = tm->tm_mon + 1;

	return (0);
}


int
ctoi(s)
	char *s;
{
	int	n;

	while (*s == ' ')
		s++;
	n = 0;
	while (isdigit((unsigned char)*s))
		n = 10 * n + *s++ - '0';
	return n;
}


int
mesg(f)
int	f;
{
	static int	mode;
	struct stat stbuf;

	if (!f) {
		stat(ttyp, &stbuf);
		mode = stbuf.st_mode;
		chmod(ttyp, mode & ~0122);	/* turn off writing for others */
	} else {
		if (ttyp && *ttyp && mode)
			chmod(ttyp, mode);
	}

	return (0);
}

int
errprint(s, s1, s2, s3, s4, s5)	/* error message printer */
	char *s, *s1, *s2, *s3, *s4, *s5;
{
	fdprintf(stderr, "%s: ", progname);
	fdprintf(stderr, s, s1, s2, s3, s4, s5);
	if (numtab[CD].val > 0)
		fdprintf(stderr, gettext("; line %d, file %s"), numtab[CD].val,
			 cfname[ifi]);
	fdprintf(stderr, "\n");
	stackdump();
#ifdef	DEBUG
	if (debug)
		abort();
#endif	/* DEBUG */
	return (0);
}


/*
 * Scaled down version of C Library printf.
 * Only %s %u %d (==%u) %o %c %x %D are recognized.
 */
#undef putchar
#define	putchar(n)	(*pfbp++ = (n))	/* NO CHECKING! */

static char	pfbuf[NTM];
static char	*pfbp = pfbuf;
int	stderr	 = 2;	/* NOT stdio value */

void
fdprintf(int fd, char *fmt, ...)
{
	int	c;
	char	*s;
	int	i;
	va_list	ap;

	pfbp = pfbuf;
	va_start(ap, fmt);
loop:
	while ((c = *fmt++) != '%') {
		if (c == '\0') {
			if (fd == stderr)
				write(stderr, pfbuf, pfbp - pfbuf);
			else {
				*pfbp = 0;
				pfbp = pfbuf;
				while (*pfbp) {
					*obufp++ = *pfbp++;
					if (obufp >= &obuf[OBUFSZ])
						flusho();
				}
			}
			va_end(ap);
			return;
		}
		putchar(c);
	}
	c = *fmt++;
	if (c == 'd') {
		i = va_arg(ap, int);
		if (i < 0) {
			putchar('-');
			i = -i;
		}
		printn((long)i, 10);
	} else if (c == 'u' || c == 'o' || c == 'x')
		printn(va_arg(ap, long), c == 'o' ? 8 : (c == 'x' ? 16 : 10));
	else if (c == 'c') {
		if (c > 0177 || c < 040)
			putchar('\\');
		putchar(va_arg(ap, int) & 0177);
	} else if (c == 's') {
		s = va_arg(ap, char *);
		while (c = *s++)
			putchar(c);
	} else if (c == 'D') {
		printn(va_arg(ap, long), 10);
	} else if (c == 'O') {
		printn(va_arg(ap, long), 8);
	}
	goto loop;
}


/*
 * Print an unsigned integer in base b.
 */
static int
printn(n, b)
	long	n;
	int	b;
{
	long	a;

	if (n < 0) {	/* shouldn't happen */
		putchar('-');
		n = -n;
	}
	if (a = n / b)
		printn(a, b);
	putchar("0123456789ABCDEF"[(int)(n%b)]);

	return (0);
}

/* scaled down version of library roff_sprintf */
/* same limits as fdprintf */
/* returns pointer to \0 that ends the string */

/* VARARGS2 */
char *roff_sprintf(char *str, char *fmt, ...)
{
	int	c;
	char	*s;
	int	i;
	va_list ap;

	va_start(ap, fmt);
loop:
	while ((c = *fmt++) != '%') {
		if (c == '\0') {
			*str = 0;
			va_end(ap);
			return str;
		}
		*str++ = c;
	}
	c = *fmt++;
	if (c == 'd') {
		i = va_arg(ap, int);
		if (i < 0) {
			*str++ = '-';
			i = -i;
		}
		str = sprintn(str, (long)i, 10);
	} else if (c == 'u' || c == 'o' || c == 'x')
		str = sprintn(str, va_arg(ap, long), c == 'o' ? 8 : (c == 'x' ? 16 : 10));
	else if (c == 'c') {
		if (c > 0177 || c < 040)
			*str++ = '\\';
		*str++ = va_arg(ap, int) & 0177;
	} else if (c == 's') {
		s = va_arg(ap, char *);
		while (c = *s++)
			*str++ = c;
	} else if (c == 'D') {
		str = sprintn(str, va_arg(ap, long), 10);
	} else if (c == 'O') {
		str = sprintn(str, va_arg(ap, unsigned) , 8);
	}
	goto loop;
}

/*
 * Print an unsigned integer in base b.
 */
static char *sprintn(s, n, b)
	char *s;
	long n;
	int b;
{
	long	a;

	if (n < 0) {	/* shouldn't happen */
		*s++ = '-';
		n = -n;
	}
	if (a = n / b)
		s = sprintn(s, a, b);
	*s++ = "0123456789ABCDEF"[(int)(n%b)];
	return s;
}


int
control(a, b)
int	a, b;
{
	int	j;

	if (a == 0 || (j = findmn(a)) == -1)
		return(0);

	/*
	 * Attempt to find endless recursion at runtime. Arbitrary
	 * recursion limit of MAX_RECURSION_DEPTH was chosen as
	 * it is extremely unlikely that a correct nroff/troff
	 * invocation would exceed this value.
	 */

	if (frame != stk) {
		int frame_cnt = 0;
		struct s *p;

		for (p = frame; p != stk; p = p->pframe)
			frame_cnt++;
		if (frame_cnt > MAX_RECURSION_DEPTH) {
			errprint(
			    gettext("Exceeded maximum stack size (%d) when "
			    "executing macro %c%c. Stack dump follows"),
			    MAX_RECURSION_DEPTH,
			    frame->mname & 0177, (frame->mname >> BYTE) & 0177);
			edone(02);
		}
	}

#ifdef	DEBUG
	if (debug & DB_MAC)
		fdprintf(stderr, "control: macro %c%c, contab[%d]\n",
			a&0177, (a>>BYTE)&0177 ? (a>>BYTE)&0177 : ' ', j);
#endif	/* DEBUG */
	if (contab[j].f == 0) {
		nxf->nargs = 0;
		if (b)
			collect();
		flushi();
		return pushi((filep)contab[j].mx, a);
	} else if (b)
		return((*contab[j].f)(0));
	else
		return(0);
}

int
getrq()
{
	int	i, j;

	if (((i = getach()) == 0) || ((j = getach()) == 0))
		goto rtn;
	i = PAIR(i, j);
rtn:
	return(i);
}

/*
 * table encodes some special characters, to speed up tests
 * in getchar, viz FLSS, RPT, f, \b, \n, fc, tabch, ldrch
 */

char
gchtab[] = {
	000,004,000,000,010,000,000,000, /* fc, ldr */
	001,002,001,000,001,000,000,000, /* \b, tab, nl, RPT */
	000,000,000,000,000,000,000,000,
	000,001,000,000,000,000,000,000, /* FLSS */
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,001,000, /* f */
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
	000,000,000,000,000,000,000,000,
};

tchar
getch()
{
	int	k;
	tchar i, j;
	tchar setht(), setslant();

g0:
	if (i = ch) {
#ifdef	DEBUG
		if (debug & DB_GETC)
			fdprintf(stderr, "getch: ch is %x (%c)\n",
				ch, (ch&0177) < 040 ? 0177 : ch&0177);
#endif	/* DEBUG */
		if (cbits(i) == '\n')
			nlflg++;
		ch = 0;
		return(i);
	}

#ifdef	DEBUG
	if (nlflg)
		if (debug & DB_GETC)
			fdprintf(stderr,"getch: nlflg is %x\n", nlflg);
#endif	/* DEBUG */
	if (nlflg)
		return('\n');
	i = getch0();
#ifdef	DEBUG
	if (debug & DB_GETC)
		fdprintf(stderr, "getch: getch0 returns %x (%c)\n",
			i, (i&0177) < 040 ? 0177 : i&0177);
#endif	/* DEBUG */
	if (ismot(i))
		return(i);
	k = cbits(i);
	if (k != ESC) {
		/*
		 * gchtab[] has only 128 entries
		 * if k is out of the range, it should be
		 * handled as gchtab[k] == 0
		 */
		if (!isascii(k) || gchtab[k]==0)
			return(i);
		if (k == '\n') {
			if (cbits(i) == '\n') {
				nlflg++;
				if (ip == 0)
					numtab[CD].val++; /* line number */
			}
			return(k);
		}
		if (k == FLSS) {
			copyf++; 
			raw++;
			i = getch0();
			if (!fi)
				flss = i;
			copyf--; 
			raw--;
			goto g0;
		}
		if (k == RPT) {
			setrpt();
			goto g0;
		}
		if (!copyf) {
			if (k == 'f' && lg && !lgf) {
				i = getlg(i);
				return(i);
			}
			if (k == fc || k == tabch || k == ldrch) {
				if ((i = setfield(k)) == 0)
					goto g0; 
				else 
					return(i);
			}
			if (k == '\b') {
				i = makem(-width(' ' | chbits));
				return(i);
			}
		}
		return(i);
	}
	k = cbits(j = getch0());
	if (ismot(j))
		return(j);
	switch (k) {

	case 'X':	/* \X'...' for copy through */
		setxon();
		goto g0;
	case '\n':	/* concealed newline */
		goto g0;
	case 'n':	/* number register */
		setn();
		goto g0;
	case '*':	/* string indicator */
		setstr();
		goto g0;
	case '$':	/* argument indicator */
		seta();
		goto g0;
	case '{':	/* LEFT */
		i = LEFT;
		goto gx;
	case '}':	/* RIGHT */
		i = RIGHT;
		goto gx;
	case '"':	/* comment */
		while (cbits(i = getch0()) != '\n')
			;
		nlflg++;
		if (ip == 0)
			numtab[CD].val++;
		return(i);
	case ESC:	/* double backslash */
		i = eschar;
		goto gx;
	case 'e':	/* printable version of current eschar */
		i = PRESC;
		goto gx;
	case ' ':	/* unpaddable space */
		i = UNPAD;
		goto gx;
	case '\'':	/* \(aa */
		i = ACUTE;
		goto gx;
	case '`':	/* \(ga */
		i = GRAVE;
		goto gx;
	case '_':	/* \(ul */
		i = UNDERLINE;
		goto gx;
	case '-':	/* current font minus */
		i = MINUS;
		goto gx;
	case '&':	/* filler */
		i = FILLER;
		goto gx;
	case 'c':	/* to be continued */
		i = CONT;
		goto gx;
	case '!':	/* transparent indicator */
		i = XPAR;
		goto gx;
	case 't':	/* tab */
		i = '\t';
		return(i);
	case 'a':	/* leader (SOH) */
		i = LEADER;
		return(i);
	case '%':	/* ohc */
		i = OHC;
		return(i);
	case 'g':	/* return format of a number register */
		setaf();
		goto g0;
	case 'N':	/* absolute character number */
		i = setabs();
		goto gx;
	case '.':	/* . */
		i = '.';
gx:
		setsfbits(i, sfbits(j));
		return(i);
	}
	if (copyf) {
		*pbp++ = j;
		return(eschar);
	}
	switch (k) {

	case 'p':	/* spread */
		spread++;
		goto g0;
	case '(':	/* special char name */
		if ((i = setch()) == 0)
			goto g0;
		return(i);
	case 's':	/* size indicator */
		setps();
		goto g0;
	case 'H':	/* character height */
		return(setht());
	case 'S':	/* slant */
		return(setslant());
	case 'f':	/* font indicator */
		setfont(0);
		goto g0;
	case 'w':	/* width function */
		setwd();
		goto g0;
	case 'v':	/* vert mot */
		if (i = vmot())
			return(i);
		goto g0;
	case 'h': 	/* horiz mot */
		if (i = hmot())
			return(i);
		goto g0;
	case 'z':	/* zero with char */
		return(setz());
	case 'l':	/* hor line */
		setline();
		goto g0;
	case 'L':	/* vert line */
		setvline();
		goto g0;
	case 'D':	/* drawing function */
		setdraw();
		goto g0;
	case 'b':	/* bracket */
		setbra();
		goto g0;
	case 'o':	/* overstrike */
		setov();
		goto g0;
	case 'k':	/* mark hor place */
		if ((k = findr(getsn())) != -1) {
			numtab[k].val = numtab[HP].val;
		}
		goto g0;
	case '0':	/* number space */
		return(makem(width('0' | chbits)));
#ifdef NROFF
	case '|':
	case '^':
		goto g0;
#else
	case '|':	/* narrow space */
		return(makem((int)(EM)/6));
	case '^':	/* half narrow space */
		return(makem((int)(EM)/12));
#endif
	case 'x':	/* extra line space */
		if (i = xlss())
			return(i);
		goto g0;
	case 'u':	/* half em up */
	case 'r':	/* full em up */
	case 'd':	/* half em down */
		return(sethl(k));
	default:
		return(j);
	}
	/* NOTREACHED */
}

int
setxon()	/* \X'...' for copy through */
{
	tchar xbuf[NC];
	tchar *i;
	tchar c;
	int delim, k;

	if (ismot(c = getch()))
		return (0);
	delim = cbits(c);
	i = xbuf;
	*i++ = XON;
	while ((k = cbits(c = getch())) != delim && k != '\n' && i < xbuf+NC-1) {
		if (k == ' ')
			setcbits(c, UNPAD);
		*i++ = c | ZBIT;
	}
	*i++ = XOFF;
	*i = 0;
	pushback(xbuf);

	return (0);
}


char	ifilt[32] = {
	0, 001, 002, 003, 0, 005, 006, 007, 010, 011, 012};

tchar getch0()
{
	int	j;
	tchar i;
#ifdef	EUC
#ifdef	NROFF
	int	n;
	int col_index;
#endif	/* NROFF */
#endif	/* EUC */

again:
	if (pbp > lastpbp)
		i = *--pbp;
	else if (ip) {
#ifdef INCORE
		extern tchar corebuf[];
		i = corebuf[ip];
		if (i == 0)
			i = rbf();
		else {
			if ((++ip & (BLK - 1)) == 0) {
				--ip;
				(void)rbf();
			}
		}
#else
		i = rbf();
#endif
	} else {
		if (donef || ndone)
			done(0);
		if (nx || ibufp >= eibuf) {
			if (nfo==0) {
g0:
				if (nextfile()) {
					if (ip)
						goto again;
					if (ibufp < eibuf)
						goto g2;
				}
			}
			nx = 0;
			if ((j = read(ifile, ibuf, IBUFSZ)) <= 0)
				goto g0;
			ibufp = ibuf;
			eibuf = ibuf + j;
			if (ip)
				goto again;
		}
g2:
#ifndef	EUC
		i = *ibufp++ & 0177;
		ioff++;
		if (i >= 040 && i < 0177)
#else
#ifndef	NROFF
		i = *ibufp++ & 0177;
		ioff++;
		if (i >= 040 && i < 0177)
#else
		i = *ibufp++ & 0377;
		*mbbuf1p++ = i;
		*mbbuf1p = 0;
		if (!multi_locale) {
			twc = 0;
			mbbuf1p = mbbuf1;
		} else if ((n = mbtowc(&twc, mbbuf1, MB_CUR_MAX)) <= 0) {
			if (mbbuf1p >= mbbuf1 + MB_CUR_MAX) {
				i &= ~(MBMASK | CSMASK);
				twc = 0;
				mbbuf1p = mbbuf1;
				*mbbuf1p = 0;
			} else {
				i |= (MIDDLEOFMB);
			}
		} else {
			if (n > 1)
				i |= (LASTOFMB);
			else
				i |= (BYTE_CHR);
			if (isascii(twc)) {
				col_index = 0;
			} else {
				if ((col_index = wcwidth(twc)) < 0)
					col_index = 0;
			}
			setcsbits(i, col_index);
			twc = 0;
			mbbuf1p = mbbuf1;
		}
		ioff++;
		if (i >= 040 && i != 0177)
#endif	/* NROFF */
#endif	/* EUC */
			goto g4;
		if (i != 0177) 
			i = ifilt[i];
	}
	if (cbits(i) == IMP && !raw)
		goto again;
	if ((i == 0 || i == 0177) && !init && !raw) {
		goto again;
	}
g4:
#ifndef EUC
	if (copyf == 0 && (i & ~BYTEMASK) == 0)
#else
#ifndef NROFF
	if (copyf == 0 && (i & ~BYTEMASK) == 0)
#else
	if (copyf == 0 && (i & ~CHMASK) == 0)
#endif /* NROFF */
#endif /* EUC */
		i |= chbits;
#ifdef EUC
#ifdef NROFF
	if (multi_locale)
		if (i & MBMASK1)
			i |= ZBIT;
#endif /* NROFF */
#endif /* EUC */
	if (cbits(i) == eschar && !raw)
		setcbits(i, ESC);
	return(i);
}

int
pushback(b)
tchar *b;
{
	tchar *ob = b;

	while (*b++)
		;
	b--;
	while (b > ob && pbp < &pbbuf[NC-3])
		*pbp++ = *--b;
	if (pbp >= &pbbuf[NC-3]) {
		errprint(gettext("pushback overflow"));
		done(2);
	}

	return (0);
}

int
cpushback(b)
char *b;
{
	char *ob = b;

	while (*b++)
		;
	b--;
	while (b > ob && pbp < &pbbuf[NC-3])
		*pbp++ = *--b;
	if (pbp >= &pbbuf[NC-3]) {
		errprint(gettext("cpushback overflow"));
		done(2);
	}

	return (0);
}

int
nextfile()
{
	char	*p;

n0:
	if (ifile)
		close(ifile);
	if (nx  ||  nmfi < mflg) {
		p = mfiles[nmfi++];
		if (*p != 0)
			goto n1;
	}
	if (ifi > 0) {
		if (popf())
			goto n0; /* popf error */
		return(1); /* popf ok */
	}
	if (rargc-- <= 0) {
		if ((nfo -= mflg) && !stdi)
			done(0);
		nfo++;
		numtab[CD].val = ifile = stdi = mflg = 0;
		strcpy(cfname[ifi], "<standard input>");
		ioff = 0;
		return(0);
	}
	p = (argp++)[0];
n1:
	numtab[CD].val = 0;
	if (p[0] == '-' && p[1] == 0) {
		ifile = 0;
		strcpy(cfname[ifi], "<standard input>");
	} else if ((ifile = open(p, 0)) < 0) {
		errprint(gettext("cannot open file %s"), p);
		nfo -= mflg;
		done(02);
	} else
		strcpy(cfname[ifi],p);
	nfo++;
	ioff = 0;
	return(0);
}


int
popf()
{
	int	i;
	char	*p, *q;
	extern char	*ttyname();

	ioff = offl[--ifi];
	numtab[CD].val = cfline[ifi];		/*restore line counter*/
	ip = ipl[ifi];
	if ((ifile = ifl[ifi]) == 0) {
		p = xbuf;
		q = ibuf;
		ibufp = xbufp;
		eibuf = xeibuf;
		while (q < eibuf)
			*q++ = *p++;
		return(0);
	}
	if (lseek(ifile, (long)(ioff & ~(IBUFSZ-1)), 0) == (long) -1
	   || (i = read(ifile, ibuf, IBUFSZ)) < 0)
		return(1);
	eibuf = ibuf + i;
	ibufp = ibuf;
	if (ttyname(ifile) == 0)
		/* was >= ... */
		if ((ibufp = ibuf + (int)(ioff & (IBUFSZ - 1))) > eibuf)
			return(1);
	return(0);
}


int
flushi()
{
	if (nflush)
		return (0);
	ch = 0;
	copyf++;
	while (!nlflg) {
		if (donef && (frame == stk))
			break;
		getch();
	}
	copyf--;

	return (0);
}


int
getach()
{
	tchar i;
	int	j;

	lgf++;
	j = cbits(i = getch());
#ifndef	EUC
	if (ismot(i) || j == ' ' || j == '\n' || j & 0200) {
#else
#ifndef	NROFF
	if (ismot(i) || j == ' ' || j == '\n' || j & 0200) {
#else
	if (ismot(i) || j == ' ' || j == '\n' || j > 0200) {
#endif	/* NROFF */
#endif	/* EUC */

		ch = i;
		j = 0;
	}
	lgf--;
	return(j & 0177);
}


int
casenx()
{
	lgf++;
	skip();
	getname();
	nx++;
	if (nmfi > 0)
		nmfi--;
	strcpy(mfiles[nmfi], nextf);
	nextfile();
	nlflg++;
	ip = 0;
	pendt = 0;
	frame = stk;
	nxf = frame + 1;

	return (0);
}


int
getname()
{
	int	j, k;
	tchar i;

	lgf++;
	for (k = 0; k < (NS - 1); k++) {
#ifndef EUC
		if (((j = cbits(i = getch())) <= ' ') || (j > 0176))
#else
#ifndef NROFF
		if (((j = cbits(i = getch())) <= ' ') || (j > 0176))
#else
		if (((j = cbits(i = getch())) <= ' ') || (j == 0177))
#endif /* NROFF */
#endif /* EUC */
			break;
		nextf[k] = j & BYTEMASK;
	}
	nextf[k] = 0;
	ch = i;
	lgf--;
	return((int)nextf[0]);
}


int
caseso()
{
	int	i;
	char	*p, *q;

	lgf++;
	nextf[0] = 0;
	if (skip() || !getname() || ((i = open(nextf, 0)) < 0) || (ifi >= NSO)) {
		errprint(gettext("can't open file %s"), nextf);
		done(02);
	}
	strcpy(cfname[ifi+1], nextf);
	cfline[ifi] = numtab[CD].val;		/*hold line counter*/
	numtab[CD].val = 0;
	flushi();
	ifl[ifi] = ifile;
	ifile = i;
	offl[ifi] = ioff;
	ioff = 0;
	ipl[ifi] = ip;
	ip = 0;
	nx++;
	nflush++;
	if (!ifl[ifi++]) {
		p = ibuf;
		q = xbuf;
		xbufp = ibufp;
		xeibuf = eibuf;
		while (p < eibuf)
			*q++ = *p++;
	}

	return (0);
}

int
caself()	/* set line number and file */
{
	int n;

	if (skip())
		return (0);
	n = atoi();
	cfline[ifi] = numtab[CD].val = n - 2;
	if (skip())
		return (0);
	if (getname())
		strcpy(cfname[ifi], nextf);

	return (0);
}


int
casecf()
{	/* copy file without change */
#ifndef NROFF
	int	fd, n;
	char	buf[512];
	extern int hpos, esc, po;
	nextf[0] = 0;
	if (skip() || !getname() || (fd = open(nextf, 0)) < 0) {
		errprint(gettext("can't open file %s"), nextf);
		done(02);
	}
	tbreak();
	/* make it into a clean state, be sure that everything is out */
	hpos = po;
	esc = un;
	ptesc();
	ptlead();
	ptps();
	ptfont();
	flusho();
	while ((n = read(fd, buf, sizeof buf)) > 0)
		write(ptid, buf, n);
	close(fd);
#endif
	return (0);
}


int
casesy()	/* call system */
{
	char	sybuf[NTM];
	int	i;

	lgf++;
	copyf++;
	skip();
	for (i = 0; i < NTM - 2; i++)
		if ((sybuf[i] = getch()) == '\n')
			break;
	sybuf[i] = 0;
	system(sybuf);
	copyf--;
	lgf--;

	return (0);
}


int
getpn(a)
	char *a;
{
	int n, neg;

	if (*a == 0)
		return (0);
	neg = 0;
	for ( ; *a; a++)
		switch (*a) {
		case '+':
		case ',':
			continue;
		case '-':
			neg = 1;
			continue;
		default:
			n = 0;
			if (isdigit((unsigned char)*a)) {
				do
					n = 10 * n + *a++ - '0';
				while (isdigit((unsigned char)*a));
				a--;
			} else
				n = 9999;
			*pnp++ = neg ? -n : n;
			neg = 0;
			if (pnp >= &pnlist[NPN-2]) {
				errprint(gettext("too many page numbers"));
				done3(-3);
			}
		}
	if (neg)
		*pnp++ = -9999;
	*pnp = -32767;
	print = 0;
	pnp = pnlist;
	if (*pnp != -32767)
		chkpn();

	return (0);
}


int
setrpt()
{
	tchar i, j;

	copyf++;
	raw++;
	i = getch0();
	copyf--;
	raw--;
	if (i < 0 || cbits(j = getch0()) == RPT)
		return (0);
	i &= BYTEMASK;
	while (i>0 && pbp < &pbbuf[NC-3]) {
		i--;
		*pbp++ = j;
	}

	return (0);
}


int
casedb()
{
#ifdef	DEBUG
	debug = 0;
	if (skip())
		return (0);
	noscale++;
	debug = max(atoi(), 0);
	noscale = 0;
#endif	/* DEBUG */

	return (0);
}
