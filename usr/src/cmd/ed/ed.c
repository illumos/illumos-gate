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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Editor
 */

#include	<crypt.h>
#include	<libgen.h>
#include	<wait.h>
#include	<string.h>
#include	<sys/types.h>
#include	<locale.h>
#include	<regexpr.h>
#include	<regex.h>
#include	<errno.h>
#include	<paths.h>

static const 	char	*msgtab[] =
{
	"write or open on pipe failed",			/*  0 */
	"warning: expecting `w'",			/*  1 */
	"mark not lower case ascii",			/*  2 */
	"Cannot open input file",			/*  3 */
	"PWB spec problem",				/*  4 */
	"nothing to undo",				/*  5 */
	"restricted shell",				/*  6 */
	"cannot create output file",			/*  7 */
	"filesystem out of space!",			/*  8 */
	"cannot open file",				/*  9 */
	"cannot link",					/* 10 */
	"Range endpoint too large",			/* 11 */
	"unknown command",				/* 12 */
	"search string not found",			/* 13 */
	"-",						/* 14 */
	"line out of range",				/* 15 */
	"bad number",					/* 16 */
	"bad range",					/* 17 */
	"Illegal address count",			/* 18 */
	"incomplete global expression",			/* 19 */
	"illegal suffix",				/* 20 */
	"illegal or missing filename",			/* 21 */
	"no space after command",			/* 22 */
	"fork failed - try again",			/* 23 */
	"maximum of 64 characters in file names",	/* 24 */
	"`\\digit' out of range",			/* 25 */
	"interrupt",					/* 26 */
	"line too long",				/* 27 */
	"illegal character in input file",		/* 28 */
	"write error",					/* 29 */
	"out of memory for append",			/* 30 */
	"temp file too big",				/* 31 */
	"I/O error on temp file",			/* 32 */
	"multiple globals not allowed",			/* 33 */
	"global too long",				/* 34 */
	"no match",					/* 35 */
	"illegal or missing delimiter",			/* 36 */
	"-",						/* 37 */
	"replacement string too long",			/* 38 */
	"illegal move destination",			/* 39 */
	"-",						/* 40 */
	"no remembered search string",			/* 41 */
	"'\\( \\)' imbalance",				/* 42 */
	"Too many `\\(' s",				/* 43 */
	"more than 2 numbers given",			/* 44 */
	"'\\}' expected",				/* 45 */
	"first number exceeds second",			/* 46 */
	"incomplete substitute",			/* 47 */
	"newline unexpected",				/* 48 */
	"'[ ]' imbalance",				/* 49 */
	"regular expression overflow",			/* 50 */
	"regular expression error",			/* 51 */
	"command expected",				/* 52 */
	"a, i, or c not allowed in G",			/* 53 */
	"end of line expected",				/* 54 */
	"no remembered replacement string",		/* 55 */
	"no remembered command",			/* 56 */
	"illegal redirection",				/* 57 */
	"possible concurrent update",			/* 58 */
	"-",						/* 59 */
	"the x command has become X (upper case)",	/* 60 */
	"Warning: 'w' may destroy input file "
	"(due to `illegal char' read earlier)",
							/* 61 */
	"Caution: 'q' may lose data in buffer;"
	" 'w' may destroy input file",
							/* 62 */
	"Encryption of string failed",			/* 63 */
	"Encryption facility not available",		/* 64 */
	"Cannot encrypt temporary file",		/* 65 */
	"Enter key:",					/* 66 */
	"Illegal byte sequence",			/* 67 */
	"File does not exist",				/* 68 */
	"tempnam failed",				/* 69 */
	"Cannot open temporary file",			/* 70 */
	0
};

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <termio.h>
#include <ctype.h>
#include <setjmp.h>
#include <fcntl.h>
#include <wchar.h>	/* I18N */
#include <wctype.h>	/* I18N */
#include <widec.h>	/* I18N */

#define	FTYPE(A)	(A.st_mode)
#define	FMODE(A)	(A.st_mode)
#define	IDENTICAL(A, B)	(A.st_dev == B.st_dev && A.st_ino == B.st_ino)
#define	ISBLK(A)	((A.st_mode & S_IFMT) == S_IFBLK)
#define	ISCHR(A)	((A.st_mode & S_IFMT) == S_IFCHR)
#define	ISDIR(A)	((A.st_mode & S_IFMT) == S_IFDIR)
#define	ISFIFO(A)	((A.st_mode & S_IFMT) == S_IFIFO)
#define	ISREG(A)	((A.st_mode & S_IFMT) == S_IFREG)

#define	PUTM()	if (xcode >= 0) puts(gettext(msgtab[xcode]))
#define	UNGETC(c)	(peekc = c)
#define	FNSIZE	PATH_MAX
#define	LBSIZE	LINE_MAX

/* size of substitution replacement pattern buffer */
#define	RHSIZE	(LINE_MAX*2)

#define	KSIZE	8

#define	READ	0
#define	WRITE	1

extern  char	*optarg;	/* Value of argument */
extern  int	optind;		/* Indicator of argument */
extern	int __xpg4;	/* defined in xpg4.c; 0 if not xpg4-compiled program */

struct  Fspec   {
	char    Ftabs[22];
	char    Fdel;
	unsigned char   Flim;
	char    Fmov;
	char    Ffill;
};
static struct  Fspec   fss;

static char	*fsp;
static int	fsprtn;
static char	line[70];
static char	*linp = line;
static int	sig;
static int	Xqt = 0;
static int	lastc;
static char	savedfile[FNSIZE];
static char	file[FNSIZE];
static char	funny[FNSIZE];
static int	funlink = 0;
static char	linebuf[LBSIZE];
static char	*tstring = linebuf;

static char *expbuf;

static char	rhsbuf[RHSIZE];
struct	lin	{
	long cur;
	long sav;
};
typedef struct lin *LINE;
static LINE	zero;
static LINE	dot;
static LINE	dol;
static LINE	endcore;
static LINE	fendcore;
static LINE	addr1;
static LINE	addr2;
static LINE	savdol, savdot;
static int	globflg;
static int	initflg;
static char	genbuf[LBSIZE];
static long	count;
static int	numpass;	/* Number of passes thru dosub(). */
static int	gsubf;		/* Occurrence value. LBSIZE-1=all. */
static int	ocerr1;	/* Allows lines NOT changed by dosub() to NOT be put */
			/* out. Retains last line changed as current line. */
static int	ocerr2;	/* Flags if ANY line changed by substitute(). 0=nc. */
static char	*nextip;
static char	*linebp;
static int	ninbuf;
static int	peekc;
static int	io;
static void	(*oldhup)(), (*oldintr)();
static void	(*oldquit)(), (*oldpipe)();
static void	quit(int);
static int	vflag = 1;
static int	xflag;
static int	xtflag;
static int	kflag;
static int	crflag;
		/* Flag for determining if file being read is encrypted */
static int	hflag;
static int	xcode = -1;
static char	crbuf[LBSIZE];
static	int	perm[2];
static int	tperm[2];
static int	permflag;
static int	tpermflag;
static int	col;
static char	*globp;
static int	tfile = -1;
static int	tline;
static char	*tfname;
extern char	*locs;
static char	ibuff[LBSIZE];
static int	iblock = -1;
static char	obuff[LBSIZE];
static int	oblock = -1;
static int	ichanged;
static int	nleft;
static long	savnames[26], names[26];
static int	anymarks;
static long	subnewa;
static int	fchange;
static int	nline;
static int	fflg, shflg;
static char	prompt[16] = "*";
static int	rflg;
static int	readflg;
static int 	eflg;
static int 	qflg = 0;
static int 	ncflg;
static int 	listn;
static int 	listf;
static int 	pflag;
static int 	flag28 = 0; /* Prevents write after a partial read */
static int 	save28 = 0; /* Flag whether buffer empty at start of read */
static long 	savtime;
static char	*name = "SHELL";
static char	*rshell = "/usr/lib/rsh";
static char	*val;
static char	*home;
static int	nodelim;

int	makekey(int *);
int	_mbftowc(char *, wchar_t *, int (*)(), int *);
static int	error(int code);
static void	tlist(struct Fspec *);
static void	tstd(struct Fspec *);
static void	gdelete(void);
static void	delete(void);
static void	exfile(void);
static void	filename(int comm);
static void	newline(void);
static int	gettty(void);
static void	commands(void);
static void	undo(void);
static void	save(void);
static void	strcopy(char *source, char *dest);
static int	strequal(char **scan1, char *str);
static int	stdtab(char *, char *);
static int	lenchk(char *, struct Fspec *);
static void	clear(struct Fspec *);
static int	expnd(char *, char *, int *, struct Fspec *);
static void	tincr(int, struct Fspec *);
static void	targ(struct Fspec *);
static int	numb(void);
static int	fspec(char *, struct Fspec *, int);
static void	red(char *);
static void	newtime(void);
static void	chktime(void);
static void	getime(void);
static void	mkfunny(void);
static int	eopen(char *, int);
static void	eclose(int f);
static void	globaln(int);
static char	*getkey(const char *);
static int	execute(int, LINE);
static void	error1(int);
static int	getcopy(void);
static void	move(int);
static void	dosub(void);
static int	getsub(void);
static int	compsub(void);
static void	substitute(int);
static void	join(void);
static void	global(int);
static void	init(void);
static void	rdelete(LINE, LINE);
static void	append(int (*)(void), LINE);
static int	getfile(void);
static void	putfile(void);
static void	onpipe(int);
static void	onhup(int);
static void	onintr(int);
static void	setdot(void);
static void	setall(void);
static void	setnoaddr(void);
static void	nonzero(void);
static void	setzeroasone(void);
static long	putline(void);
static LINE	address(void);
static char	*getaline(long);
static char	*getblock(long, long);
static char	*place(char *, char *, char *);
static void	comple(wchar_t);
static void	putchr(unsigned char);
static void	putwchr(wchar_t);
static int	getchr(void);
static void	unixcom(void);
static void	blkio(int, char *, ssize_t (*)());
static void	reverse(LINE, LINE);
static void	putd();
static wchar_t	get_wchr(void);

static struct stat	Fl, Tf;
#ifndef RESEARCH
static struct statvfs	U;
static int	Short = 0;
static mode_t	oldmask; /* No umask while writing */
#endif
static jmp_buf	savej;

#ifdef	NULLS
int	nulls;	/* Null count */
#endif
static long	ccount;

static int	errcnt = 0;


static void
onpipe(int sig)
{
	(int)error(0);
}

int
main(int argc, char **argv)
{
	char *p1, *p2;
	int c;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	oldquit = signal(SIGQUIT, SIG_IGN);
	oldhup = signal(SIGHUP, SIG_IGN);
	oldintr = signal(SIGINT, SIG_IGN);
	oldpipe = signal(SIGPIPE, onpipe);
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		signal(SIGTERM, quit);
	p1 = *argv;
	while (*p1++)
		;
	while (--p1 >= *argv)
		if (*p1 == '/')
			break;
	*argv = p1 + 1;
	/* if SHELL set in environment and is /usr/lib/rsh, set rflg */
	if ((val = getenv(name)) != NULL)
		if (strcmp(val, rshell) == 0)
			rflg++;
	if (**argv == 'r')
		rflg++;
	home = getenv("HOME");
	while (1) {
		while ((c = getopt(argc, argv, "sp:qxC")) != EOF) {
			switch (c) {

			case 's':
				vflag = 0;
				break;

			case 'p':
				strncpy(prompt, optarg, sizeof (prompt)-1);
				shflg = 1;
				break;

			case 'q':
				signal(SIGQUIT, SIG_DFL);
				vflag = 1;
				break;

			case 'x':
				crflag = -1;
				xflag = 1;
				break;

			case 'C':
				crflag = 1;
				xflag = 1;
				break;

			case '?':
				(void) fprintf(stderr, gettext(
		"Usage:   ed [- | -s] [-p string] [-x] [-C] [file]\n"
		"	  red [- | -s] [-p string] [-x] [-C] [file]\n"));
				exit(2);
			}
		}
		if (argv[optind] && strcmp(argv[optind], "-") == 0 &&
		    strcmp(argv[optind-1], "--") != 0) {
			vflag = 0;
			optind++;
			continue;
		}
		break;
	}
	argc = argc - optind;
	argv = &argv[optind];

	if (xflag) {
		if (permflag)
			crypt_close(perm);
		permflag = 1;
		kflag = run_setkey(&perm[0], getkey(msgtab[66]));
		if (kflag == -1) {
			puts(gettext(msgtab[64]));
			xflag = 0;
			kflag = 0;
		}
		if (kflag == 0)
			crflag = 0;
	}

	if (argc > 0) {
		p1 = *argv;
		if (strlen(p1) >= (size_t)FNSIZE) {
			puts(gettext("file name too long"));
			if (kflag)
				crypt_close(perm);
			exit(2);
		}
		p2 = savedfile;
		while (*p2++ = *p1++)
			;
		globp = "e";
		fflg++;
	} else 	/* editing with no file so set savtime to 0 */
		savtime = 0;
	eflg++;
	if ((tfname = tempnam("", "ea")) == NULL) {
		puts(gettext(msgtab[69]));
		exit(2);
	}

	fendcore = (LINE)sbrk(0);
	init();
	if (oldintr != SIG_IGN)
		signal(SIGINT, onintr);
	if (oldhup != SIG_IGN)
		signal(SIGHUP, onhup);
	setjmp(savej);
	commands();
	quit(sig);
	return (0);
}

static void
commands(void)
{
	LINE a1;
	int c;
	char *p1, *p2;
	int fsave, m, n;

	for (;;) {
	nodelim = 0;
	if (pflag) {
		pflag = 0;
		addr1 = addr2 = dot;
		goto print;
	}
	if (shflg && globp == 0)
		write(1, gettext(prompt), strlen(gettext(prompt)));
	addr1 = 0;
	addr2 = 0;
	if ((c = getchr()) == ',') {
		addr1 = zero + 1;
		addr2 = dol;
#ifdef XPG6
	/* XPG4 - it was an error if the second address was */
	/* input and the first address was ommitted	*/
	/* Parse second address	*/
		if ((a1 = address()) != 0) {
			addr2 = a1;
		}
#endif
		c = getchr();
		goto swch;
	} else if (c == ';') {
		addr1 = dot;
		addr2 = dol;
#ifdef XPG6
	/* XPG4 - it was an error if the second address was */
	/* input and the first address was ommitted	*/
	/* Parse second address	*/
		if ((a1 = address()) != 0) {
			addr2 = a1;
		}
#endif
		c = getchr();
		goto swch;
	} else
		peekc = c;
	do {
		addr1 = addr2;
		if ((a1 = address()) == 0) {
			c = getchr();
			break;
		}
		addr2 = a1;
		if ((c = getchr()) == ';') {
			c = ',';
			dot = a1;
		}
	} while (c == ',');
	if (addr1 == 0)
		addr1 = addr2;
swch:
	switch (c) {

	case 'a':
		setdot();
		newline();
		if (!globflg) save();
		append(gettty, addr2);
		continue;

	case 'c':
#ifdef XPG6
		setzeroasone();
#endif
		delete();
		append(gettty, addr1-1);

		/* XPG4 - If no new lines are inserted, then the current */
		/* line becomes the line after the lines deleted. */

		if (((linebuf[0] != '.') || (dot == (addr1-1))) &&
		    (addr2 <= dol))
			dot = addr1;
		continue;

	case 'd':
		delete();
		continue;

	case 'E':
		fchange = 0;
		c = 'e';
	case 'e':
		fflg++;
		setnoaddr();
		if (vflag && fchange) {
			fchange = 0;
			(void) error(1);
		}
		filename(c);
		eflg++;
		init();
		addr2 = zero;
		goto caseread;

	case 'f':
		setnoaddr();
		filename(c);
		if (!ncflg)  /* there is a filename */
			getime();
		else
			ncflg--;
		puts(savedfile);
		continue;

	case 'g':
		global(1);
		continue;
	case 'G':
		globaln(1);
		continue;

	case 'h':
		newline();
		setnoaddr();
		PUTM();
		continue;

	case 'H':
		newline();
		setnoaddr();
		if (!hflag) {
			hflag = 1;
			PUTM();
		}
		else
			hflag = 0;
		continue;

	case 'i':
#ifdef XPG6
		setzeroasone();
#endif
		setdot();
		nonzero();
		newline();
		if (!globflg) save();
		append(gettty, addr2-1);
		if (dot == addr2-1)
			dot += 1;
		continue;

	case 'j':
		if (addr2 == 0) {
			addr1 = dot;
			addr2 = dot+1;
		}
		setdot();
		newline();
		nonzero();
		if (!globflg) save();
		join();
		continue;

	case 'k':
		if ((c = getchr()) < 'a' || c > 'z')
			(void) error(2);
		newline();
		setdot();
		nonzero();
		names[c-'a'] = addr2->cur & ~01;
		anymarks |= 01;
		continue;

	case 'm':
		move(0);
		continue;

	case '\n':
		if (addr2 == 0)
			addr2 = dot+1;
		addr1 = addr2;
		goto print;

	case 'n':
		listn++;
		newline();
		goto print;

	case 'l':
		listf++;
	case 'p':
		newline();
	print:
		setdot();
		nonzero();
		a1 = addr1;
		do {
			if (listn) {
				count = a1 - zero;
				putd();
				putchr('\t');
			}
			puts(getaline((a1++)->cur));
		} while (a1 <= addr2);
		dot = addr2;
		pflag = 0;
		listn = 0;
		listf = 0;
		continue;

	case 'Q':
		fchange = 0;
	case 'q':
		setnoaddr();
		newline();
		quit(sig);

	case 'r':
		filename(c);
	caseread:
		readflg = 1;
		save28 = (dol != fendcore);
		if (crflag == 2 || crflag == -2)
			crflag = -1; /* restore crflag for next file */
		errno = 0;
		if ((io = eopen(file, O_RDONLY)) < 0) {
			lastc = '\n';
			/* if first entering editor and file does not exist */
			/* set saved access time to 0 */
			if (eflg) {
				savtime = 0;
				eflg  = 0;
				if (c == 'e' && vflag == 0)
					qflg = 1;
			}
			if (errno == ENOENT) {
				(void) error(68);
			} else {
				(void) error(3);
			}
		}
		/* get last mod time of file */
		/* eflg - entered editor with ed or e  */
		if (eflg) {
			eflg = 0;
			getime();
		}
		setall();
		ninbuf = 0;
		n = zero != dol;
#ifdef NULLS
		nulls = 0;
#endif
		if (!globflg && (c == 'r')) save();
		append(getfile, addr2);
		exfile();
		readflg = 0;
		fchange = n;
		continue;

	case 's':
		setdot();
		nonzero();
		if (!globflg) save();
		substitute(globp != 0);
		continue;

	case 't':
		move(1);
		continue;

	case 'u':
		setdot();
		newline();
		if (!initflg)
			undo();
		else
			(void) error(5);
		fchange = 1;
		continue;

	case 'v':
		global(0);
		continue;
	case 'V':
		globaln(0);
		continue;

	case 'W':
	case 'w':
		if (flag28) {
			flag28 = 0;
			fchange = 0;
			(void) error(61);
		}
		setall();

		/* on NULL-RE condition do not generate error */

		if ((linebuf[0] != '.') && (zero != dol) &&
		    (addr1 <= zero || addr2 > dol))
			(void) error(15);
		filename(c);
		if (Xqt) {
			io = eopen(file, O_WRONLY);
			n = 1;	/* set n so newtime will not execute */
		} else {
			struct stat lFl;
			fstat(tfile, &Tf);
			if (stat(file, &Fl) < 0) {
				if ((io = creat(file, S_IRUSR|S_IWUSR|S_IRGRP
				    |S_IWGRP|S_IROTH|S_IWOTH)) < 0)
					(void) error(7);
				fstat(io, &Fl);
				Fl.st_mtime = 0;
				lFl = Fl;
				close(io);
			} else {
#ifndef	RESEARCH
				oldmask = umask(0);
				/*
				 * Must determine if file is
				 * a symbolic link
				 */
				lstat(file, &lFl);
#endif
			}
#ifndef RESEARCH
			/*
			 * Determine if there are enough free blocks on system
			 */
			if (!Short && statvfs(file, &U) == 0 &&
			    U.f_bfree < ((Tf.st_size/U.f_frsize) + 100)) {
				Short = 1;
				(void) error(8);
			}
			Short = 0;
#endif
			p1 = savedfile;		/* The current filename */
			p2 = file;
			m = strcmp(p1, p2);
			if (c == 'w' && Fl.st_nlink == 1 && ISREG(lFl)) {
				if (close(open(file, O_WRONLY)) < 0)
					(void) error(9);
				if (!(n = m))
					chktime();
				mkfunny();
				/*
				 * If funlink equals one it means that
				 * funny points to a valid file which must
				 * be unlinked when interrupted.
				 */

				funlink = 1;
				if ((io = creat(funny, FMODE(Fl))) >= 0) {
					chown(funny, Fl.st_uid, Fl.st_gid);
					chmod(funny, FMODE(Fl));
					putfile();
					exfile();

					if (rename(funny, file))
						(void) error(10);
					funlink = 0;
					/* if filenames are the same */
					if (!n)
						newtime();
					/* check if entire buffer was written */
					fsave = fchange;
					if (((addr1 == zero) ||
					    (addr1 == (zero + 1))) &&
					    (addr2 == dol))
						fchange = 0;
					else
						fchange = 1;
					if (fchange == 1 && m != 0)
						fchange = fsave;
					continue;
				}
			} else {
				n = 1;	/* set n so newtime will not execute */
			}
			if ((io = open(file,
			    (c == 'w') ? O_WRONLY|O_CREAT|O_TRUNC
			    : O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR
			    |S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)) < 0)
				(void) error(7);
		}
		putfile();
		exfile();
		if (!n)
			newtime();
		fsave = fchange;
		fchange = (((addr1 == zero) || (addr1 == (zero + 1))) &&
		    (addr2 == dol)) ? 0 : 1;
	/* Leave fchange alone if partial write was to another file */
		if (fchange == 1 && m != 0) fchange = fsave;
		continue;

	case 'C':
		crflag = 1;
			/*
			 * C is same as X, but always assume input files are
			 * ciphertext
			 */
		goto encrypt;

	case 'X':
		crflag = -1;
encrypt:
		setnoaddr();
		newline();
		xflag = 1;
		if (permflag)
			(void) crypt_close(perm);
		permflag = 1;
		if ((kflag = run_setkey(&perm[0], getkey(msgtab[66]))) == -1) {
			xflag = 0;
			kflag = 0;
			crflag = 0;
			(void) error(64);
		}
		if (kflag == 0)
			crflag = 0;
		continue;

	case '=':
		setall();
		newline();
		count = (addr2-zero)&077777;
		putd();
		putchr('\n');
		continue;

	case '!':
		unixcom();
		continue;

	case EOF:
		return;

	case 'P':
		setnoaddr();
		newline();
		if (shflg)
			shflg = 0;
		else
			shflg++;
		continue;
	}
	if (c == 'x')
		(void) error(60);
	else
		(void) error(12);
	}
}

LINE
address(void)
{
	int minus, c;
	LINE a1;
	int n, relerr, retval;

	minus = 0;
	a1 = 0;
	for (;;) {
		c = getchr();
		if ('0' <= c && c <= '9') {
			n = 0;
			do {
				n *= 10;
				n += c - '0';
			} while ((c = getchr()) >= '0' && c <= '9');
			peekc = c;
			if (a1 == 0)
				a1 = zero;
			if (minus < 0)
				n = -n;
			a1 += n;
			minus = 0;
			continue;
		}
		relerr = 0;
		if (a1 || minus)
			relerr++;
		switch (c) {
		case ' ':
		case '\t':
			continue;

		case '+':
			minus++;
			if (a1 == 0)
				a1 = dot;
			continue;

		case '-':
		case '^':
			minus--;
			if (a1 == 0)
				a1 = dot;
			continue;

		case '?':
		case '/':
			comple(c);
			a1 = dot;
			for (;;) {
				if (c == '/') {
					a1++;
					if (a1 > dol)
						a1 = zero;
				} else {
					a1--;
					if (a1 < zero)
						a1 = dol;
				}

				if (execute(0, a1))
					break;
				if (a1 == dot)
					(void) error(13);
			}
			break;

		case '$':
			a1 = dol;
			break;

		case '.':
			a1 = dot;
			break;

		case '\'':
			if ((c = getchr()) < 'a' || c > 'z')
				(void) error(2);
			for (a1 = zero; a1 <= dol; a1++)
				if (names[c-'a'] == (a1->cur & ~01))
					break;
			break;

		default:
			peekc = c;
			if (a1 == 0)
				return (0);
			a1 += minus;

			/* on NULL-RE condition do not generate error */

			if ((linebuf[0] != '.') && (a1 < zero || a1 > dol))
				(void) error(15);
			return (a1);
		}
		if (relerr)
			(void) error(16);
	}
}

static void
setdot(void)
{
	if (addr2 == 0)
		addr1 = addr2 = dot;
	if (addr1 > addr2)
		(void) error(17);
}

static void
setall(void)
{
	if (addr2 == 0) {
		addr1 = zero+1;
		addr2 = dol;
		if (dol == zero)
			addr1 = zero;
	}
	setdot();
}

static void
setnoaddr(void)
{
	if (addr2)
		(void) error(18);
}

static void
nonzero(void)
{
	/* on NULL-RE condition do not generate error */

	if ((linebuf[0] != '.') && (addr1 <= zero || addr2 > dol))
		(void) error(15);
}

static void
setzeroasone(void)
{
/* for the c and i commands 0 equal to 1 address */
	if (addr1 == zero) {
		addr1 = zero+1;
	}
	if (addr2 == zero) {
		addr2 = zero+1;
	}
}


static void
newline(void)
{
	int c;

	if ((c = getchr()) == '\n')
		return;
	if (c == 'p' || c == 'l' || c == 'n') {
		pflag++;
		if (c == 'l') listf++;
		if (c == 'n') listn++;
		if ((c = getchr()) == '\n')
			return;
	}
	(void) error(20);
}

static void
filename(int comm)
{
	char *p1, *p2;
	int c;
	int i = 0;

	count = 0;
	c = getchr();
	if (c == '\n' || c == EOF) {
		p1 = savedfile;
		if (*p1 == 0 && comm != 'f')
			(void) error(21);
		/* ncflg set means do not get mod time of file */
		/* since no filename followed f */
		if (comm == 'f')
			ncflg++;
		p2 = file;
		while (*p2++ = *p1++)
			;
		red(savedfile);
		return;
	}
	if (c != ' ')
		(void) error(22);
	while ((c = getchr()) == ' ')
		;
	if (c == '!')
		++Xqt, c = getchr();
	if (c == '\n')
		(void) error(21);
	p1 = file;
	do {
		if (++i >= FNSIZE)
			(void) error(24);
		*p1++ = c;
		if (c == EOF || (c == ' ' && !Xqt))
			(void) error(21);
	} while ((c = getchr()) != '\n');
	*p1++ = 0;
	if (Xqt)
		if (comm == 'f') {
			--Xqt;
			(void) error(57);
		}
		else
			return;
	if (savedfile[0] == 0 || comm == 'e' || comm == 'f') {
		p1 = savedfile;
		p2 = file;
		while (*p1++ = *p2++)
			;
	}
	red(file);
}


static void
exfile(void)
{
#ifdef NULLS
	int c;
#endif

#ifndef RESEARCH
	if (oldmask) {
		umask(oldmask);
		oldmask = 0;
	}
#endif
	eclose(io);
	io = -1;
	if (vflag) {
		putd();
		putchr('\n');
#ifdef NULLS
		if (nulls) {
			c = count;
			count = nulls;
			nulls = 0;
			putd();
			puts(gettext(" nulls replaced by '\\0'"));
			count = c;
		}
#endif
	}
}

static void
onintr(int sig)
{
	signal(SIGINT, onintr);
	putchr('\n');
	lastc = '\n';
	globflg = 0;
	if (funlink) unlink(funny); /* remove tmp file */
	/* if interrupted a read, only part of file may be in buffer */
	if (readflg) {
		sprintf(tstring, "\007read may be incomplete - beware!\007");
		puts(gettext(tstring));
		fchange = 0;
	}
	(void) error(26);
}

static void
onhup(int sig)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	/*
	 * if there are lines in file and file was not written
	 * since last update, save in ed.hup, or $HOME/ed.hup
	 */
	if (dol > zero && fchange == 1) {
		addr1 = zero+1;
		addr2 = dol;
		io = creat("ed.hup",
		    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
		if (io < 0 && home) {
			char	*fn;

			fn = (char *)calloc(strlen(home) + 8, sizeof (char));
			if (fn) {
				strcpy(fn, home);
				strcat(fn, "/ed.hup");
				io = creat(fn, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP
				    |S_IROTH|S_IWOTH);
				free(fn);
			}
		}
		if (io > 0)
			putfile();
	}
	fchange = 0;
	++errcnt;
	quit(sig);
}

static int
error(int code)
{
	int c;

	if (code == 28 && save28 == 0) {
		fchange = 0;
		flag28++;
	}
	readflg = 0;
	++errcnt;
	listf = listn = 0;
	pflag = 0;
#ifndef RESEARCH
	if (oldmask) {
		umask(oldmask);
		oldmask = 0;
	}
#endif
#ifdef NULLS	/* Not really nulls, but close enough */
	/* This is a bug because of buffering */
	if (code == 28) /* illegal char. */
		putd();
#endif
	/* Cant open file or file does not exist */
	if ((code == 3) || (code == 68)) {
		if (qflg == 0) {
			putchr('?');
			puts(file);
		}
		else
			qflg = 0;
	}
	else
	{
		putchr('?');
		putchr('\n');
	}
	count = 0;
	lseek(0, (long)0, 2);
	if (globp)
		lastc = '\n';
	globp = 0;
	peekc = lastc;
	if (lastc)
		while ((c = getchr()) != '\n' && c != EOF)
			;
	if (io) {
		eclose(io);
		io = -1;
	}
	xcode = code;
	if (hflag)
		PUTM();
	if (code == 4)
		return (0);	/* Non-fatal error. */
	longjmp(savej, 1);
	/* NOTREACHED */
}

static int
getchr(void)
{
	char c;
	if (lastc = peekc) {
		peekc = 0;
		return (lastc);
	}
	if (globp) {
		if ((lastc = (unsigned char)*globp++) != 0)
			return (lastc);
		globp = 0;
		return (EOF);
	}
	if (read(0, &c, 1) <= 0)
		return (lastc = EOF);
	lastc = (unsigned char)c;
	return (lastc);
}

static int
gettty(void)
{
	int c;
	char *gf;
	char *p;

	p = linebuf;
	gf = globp;
	while ((c = getchr()) != '\n') {
		if (c == EOF) {
			if (gf)
				peekc = c;
			return (c);
		}
		if (c == 0)
			continue;
		*p++ = c;

		if (p > &linebuf[LBSIZE-1])
			(void) error(27);
	}
	*p++ = 0;
	if (linebuf[0] == '.' && linebuf[1] == 0)
		return (EOF);

	/*
	 * POSIX.2/XPG4 explicitly says no to this:
	 *
	 * in Solaris backslash followed by special character "." is
	 * special character "." itself; (so terminating input mode can be
	 * "\.\n").
	 *
	 * however, POSIX2/XPG4 says, input mode is terminated by
	 * entering line consisting of only 2 characters: ".\n"
	 *
	 * if (linebuf[0]=='\\' && linebuf[1]=='.' && linebuf[2]==0) {
	 *	linebuf[0] = '.';
	 *	linebuf[1] = 0;
	 * }
	 */
	return (0);
}

static int
getfile(void)
{
	char c;
	char *lp, *fp;

	lp = linebuf;
	fp = nextip;
	do {
		if (--ninbuf < 0) {
			if ((ninbuf = read(io, genbuf, LBSIZE)-1) < 0)
				if (lp > linebuf) {
					puts(gettext("'\\n' appended"));
					*genbuf = '\n';
				}
				else
					return (EOF);
			if (crflag == -1) {
				if (isencrypt(genbuf, ninbuf + 1))
					crflag = 2;
				else
					crflag = -2;
			}
			fp = genbuf;
			if (crflag > 0)
			if (run_crypt(count, genbuf, ninbuf+1, perm) == -1)
				(void) error(63);
		}
		if (lp >= &linebuf[LBSIZE]) {
			lastc = '\n';
			(void) error(27);
		}
		if ((*lp++ = c = *fp++) == 0) {
#ifdef NULLS
			lp[-1] = '\\';
			*lp++ = '0';
			nulls++;
#else
			lp--;
			continue;
#endif
		}
		count++;
	} while (c != '\n');
	*--lp = 0;
	nextip = fp;
	if (fss.Ffill && fss.Flim && lenchk(linebuf, &fss) < 0) {
		write(1, gettext("line too long: lno = "),
		    strlen(gettext("line too long: lno = ")));
		ccount = count;
		count = (++dot-zero)&077777;
		dot--;
		putd();
		count = ccount;
		putchr('\n');
	}
	return (0);
}

static void
putfile(void)
{
	int n;
	LINE a1;
	char *fp, *lp;
	int nib;

	nib = LBSIZE;
	fp = genbuf;
	a1 = addr1;
	do {
		lp = getaline(a1++->cur);
		if (fss.Ffill && fss.Flim && lenchk(linebuf, &fss) < 0) {
			write(1, gettext("line too long: lno = "),
			    strlen(gettext("line too long: lno = ")));
			ccount = count;
			count = (a1-zero-1)&077777;
			putd();
			count = ccount;
			putchr('\n');
		}
		for (;;) {
			if (--nib < 0) {
				n = fp-genbuf;
				if (kflag)
				if (run_crypt(count-n, genbuf, n, perm) == -1)
					(void) error(63);
				if (write(io, genbuf, n) != n)
					(void) error(29);
				nib = LBSIZE - 1;
				fp = genbuf;
			}
			if (dol->cur == 0L)break; /* Allow write of null file */
			count++;
			if ((*fp++ = *lp++) == 0) {
				fp[-1] = '\n';
				break;
			}
		}
	} while (a1 <= addr2);
	n = fp-genbuf;
	if (kflag)
		if (run_crypt(count-n, genbuf, n, perm) == -1)
			(void) error(63);
	if (write(io, genbuf, n) != n)
		(void) error(29);
}

static void
append(int (*f)(void), LINE a)
{
	LINE a1, a2, rdot;
	long tl;

	nline = 0;
	dot = a;
	while ((*f)() == 0) {
		if (dol >= endcore) {
			if ((int)sbrk(512 * sizeof (struct lin)) == -1) {
				lastc = '\n';
				(void) error(30);
			}
			endcore += 512;
		}
		tl = putline();
		nline++;
		a1 = ++dol;
		a2 = a1+1;
		rdot = ++dot;
		while (a1 > rdot)
			(--a2)->cur = (--a1)->cur;
		rdot->cur = tl;
	}
}

static void
unixcom(void)
{
	void (*savint)();
	pid_t	pid, rpid;
	int retcode;
	static char savcmd[LBSIZE];	/* last command */
	char curcmd[LBSIZE];		/* current command */
	char *psavcmd, *pcurcmd, *psavedfile;
	int endflg = 1, shflg = 0;
	wchar_t	c;
	int	len;

	setnoaddr();
	if (rflg)
		(void) error(6);
	pcurcmd = curcmd;
	/* read command til end */

	/*
	 * a '!' found in beginning of command is replaced with the saved
	 * command.  a '%' found in command is replaced with the current
	 * filename
	 */

	c = getchr();
	if (c == '!') {
		if (savcmd[0] == 0)
			(void) error(56);
		else {
			psavcmd = savcmd;
			while (*pcurcmd++ = *psavcmd++)
				;
			--pcurcmd;
			shflg = 1;
		}
	} else
		UNGETC(c);  /* put c back */
	while (endflg == 1) {
		while ((c = get_wchr()) != '\n' && c != '%' && c != '\\') {
			if ((len = wctomb(pcurcmd, c)) <= 0) {
				*pcurcmd = (unsigned char)c;
				len = 1;
			}
			pcurcmd += len;
		}

		if (c == '%') {
			if (savedfile[0] == 0)
				(void) error(21);
			else {
				psavedfile = savedfile;
				while (pcurcmd < curcmd + LBSIZE &&
				    (*pcurcmd++ = *psavedfile++))
					;
				--pcurcmd;
				shflg = 1;
			}
		} else if (c == '\\') {
			c = get_wchr();
			if (c != '%')
				*pcurcmd++ = '\\';
			if ((len = wctomb(pcurcmd, c)) <= 0) {
				*pcurcmd = (unsigned char)c;
				len = 1;
			}
			pcurcmd += len;
		}
		else
			/* end of command hit */
			endflg = 0;
	}
	*pcurcmd++ = 0;
	if (shflg == 1)
		puts(curcmd);
	/* save command */
	strcpy(savcmd, curcmd);

	if ((pid = fork()) == 0) {
		signal(SIGHUP, oldhup);
		signal(SIGQUIT, oldquit);
		close(tfile);
		execlp(_PATH_BSHELL, "sh", "-c", curcmd, NULL);
		exit(0100);
	}
	savint = signal(SIGINT, SIG_IGN);
	while ((rpid = wait(&retcode)) != pid && rpid != (pid_t)-1)
		;
	signal(SIGINT, savint);
	if (vflag) puts("!");
}

static void
quit(int sig)
{
	if (vflag && fchange) {
		fchange = 0;
		if (flag28) {
			flag28 = 0;
			(void) error(62);
		}

		/*
		 * For case where user reads in BOTH a good
		 * file & a bad file
		 */
		(void) error(1);
	}
	unlink(tfname);
	if (kflag)
		crypt_close(perm);
	if (xtflag)
		crypt_close(tperm);
	exit(errcnt? 2: 0);
}

static void
delete(void)
{
	setdot();
	newline();
	nonzero();
	if (!globflg)
		save();
	rdelete(addr1, addr2);
}

static void
rdelete(LINE ad1, LINE ad2)
{
	LINE a1, a2, a3;

	a1 = ad1;
	a2 = ad2+1;
	a3 = dol;
	dol -= a2 - a1;
	do {
		(a1++)->cur = (a2++)->cur;
	} while (a2 <= a3);
	a1 = ad1;
	if (a1 > dol)
		a1 = dol;
	dot = a1;
	fchange = 1;
}

static void
gdelete(void)
{
	LINE a1, a2, a3;

	a3 = dol;
	for (a1 = zero+1; (a1->cur&01) == 0; a1++)
		if (a1 >= a3)
			return;
	for (a2 = a1 + 1; a2 <= a3; ) {
		if (a2->cur & 01) {
			a2++;
			dot = a1;
		} else
			(a1++)->cur = (a2++)->cur;
	}
	dol = a1-1;
	if (dot > dol)
		dot = dol;
	fchange = 1;
}

static char *
getaline(long tl)
{
	char *bp, *lp;
	int nl;

	lp = linebuf;
	bp = getblock(tl, READ);
	nl = nleft;
	tl &= ~0377;
	while (*lp++ = *bp++)
		if (--nl == 0) {
			bp = getblock(tl += 0400, READ);
			nl = nleft;
		}
	return (linebuf);
}

static long
putline(void)
{
	char *bp, *lp;
	int nl;
	long tl;

	fchange = 1;
	lp = linebuf;
	tl = tline;
	bp = getblock(tl, WRITE);
	nl = nleft;
	tl &= ~0377;
	while (*bp = *lp++) {
		if (*bp++ == '\n') {
			*--bp = 0;
			linebp = lp;
			break;
		}
		if (--nl == 0) {
			bp = getblock(tl += 0400, WRITE);
			nl = nleft;
		}
	}
	nl = tline;
	tline += (((lp-linebuf)+03)>>1)&077776;
	return (nl);
}

static char *
getblock(long atl, long iof)
{
	int bno, off;
	char *p1, *p2;
	int n;

	bno = atl >> 8;
	off = (atl<<1)&0774;

	/* bno is limited to 16 bits */
	if (bno >= 65535) {
		lastc = '\n';
		(void) error(31);
	}
	nleft = 512 - off;
	if (bno == iblock) {
		ichanged |= iof;
		return (ibuff+off);
	}
	if (bno == oblock)
		return (obuff+off);
	if (iof == READ) {
		if (ichanged) {
			if (xtflag)
				if (run_crypt(0L, ibuff, 512, tperm) == -1)
					(void) error(63);
			blkio(iblock, ibuff, write);
		}
		ichanged = 0;
		iblock = bno;
		blkio(bno, ibuff, read);
		if (xtflag)
			if (run_crypt(0L, ibuff, 512, tperm) == -1)
				(void) error(63);
		return (ibuff+off);
	}
	if (oblock >= 0) {
		if (xtflag) {
			p1 = obuff;
			p2 = crbuf;
			n = 512;
			while (n--)
				*p2++ = *p1++;
			if (run_crypt(0L, crbuf, 512, tperm) == -1)
				(void) error(63);
			blkio(oblock, crbuf, write);
		} else
			blkio(oblock, obuff, write);
	}
	oblock = bno;
	return (obuff+off);
}

static void
blkio(int b, char *buf, ssize_t (*iofcn)())
{
	lseek(tfile, (long)b<<9, 0);
	if ((*iofcn)(tfile, buf, 512) != 512) {
		if (dol != zero)
			(void) error(32); /* Bypass this if writing null file */
	}
}

static void
init(void)
{
	long *markp;
	mode_t omask;

	if (tfile != -1) {
		(void) close(tfile);
		(void) unlink(tfname);
	}

	tline = 2;
	for (markp = names; markp < &names[26]; )
		*markp++ = 0L;
	subnewa = 0L;
	anymarks = 0;
	iblock = -1;
	oblock = -1;
	ichanged = 0;
	initflg = 1;
	omask = umask(0);

	if ((tfile = open(tfname, O_CREAT|O_EXCL|O_RDWR,
	    S_IRUSR|S_IWUSR)) < 0) {
		puts(gettext(msgtab[70]));
		exit(2);
	}

	umask(omask);
	if (xflag) {
		xtflag = 1;
		if (tpermflag)
			(void) crypt_close(tperm);
		tpermflag = 1;
		if (makekey(tperm)) {
			xtflag = 0;
			puts(gettext(msgtab[65]));
		}
	}
	brk((char *)fendcore);
	dot = zero = dol = savdot = savdol = fendcore;
	flag28 = save28 = 0;
	endcore = fendcore - sizeof (struct lin);
}

static void
global(int k)
{
	char *gp;
	wchar_t l;
	char multic[MB_LEN_MAX];
	wchar_t c;
	LINE a1;
	char globuf[LBSIZE];
	int n;
	int	len;

	if (globp)
		(void) error(33);
	setall();
	nonzero();
	if ((n = _mbftowc(multic, &l, getchr, &peekc)) <= 0)
		(void) error(67);
	if (l == '\n')
		(void) error(19);
	save();
	comple(l);
	gp = globuf;
	while ((c = get_wchr()) != '\n') {
		if (c == EOF)
			(void) error(19);

		/* '\\' has special meaning only if preceding a '\n' */
		if (c == '\\') {
			c = get_wchr();
			if (c != '\n')
				*gp++ = '\\';
		}
		if ((gp + (unsigned int)MB_CUR_MAX) >= &globuf[LBSIZE-1])
			(void) error(34);
		if ((len = wctomb(gp, c)) <= 0) {
			*gp = (unsigned char)c;
			len = 1;
		}
		gp += len;
	}
	if (gp == globuf)
		*gp++ = 'p';
	*gp++ = '\n';
	*gp++ = 0;
	for (a1 = zero; a1 <= dol; a1++) {
		a1->cur &= ~01;
		if (a1 >= addr1 && a1 <= addr2 && execute(0, a1) == k)
			a1->cur |= 01;
	}
	/*
	 * Special case: g/.../d (avoid n^2 algorithm)
	 */
	if (globuf[0] == 'd' && globuf[1] == '\n' && globuf[2] == '\0') {
		gdelete();
		return;
	}
	for (a1 = zero; a1 <= dol; a1++) {
		if (a1->cur & 01) {
			a1->cur &= ~01;
			dot = a1;
			globp = globuf;
			globflg = 1;
			commands();
			globflg = 0;
			a1 = zero;
		}
	}
}

static void
join(void)
{
	char *gp, *lp;
	LINE a1;

	if (addr1 == addr2)
		return;
	gp = genbuf;
	for (a1 = addr1; a1 <= addr2; a1++) {
		lp = getaline(a1->cur);
		while (*gp = *lp++)
			if (gp++ > &genbuf[LBSIZE-1])
				(void) error(27);
	}
	lp = linebuf;
	gp = genbuf;
	while (*lp++ = *gp++)
		;
	addr1->cur = putline();
	if (addr1 < addr2)
		rdelete(addr1+1, addr2);
	dot = addr1;
}

static void
substitute(int inglob)
{
	int nl;
	LINE a1;
	long *markp;
	int ingsav;		/* For saving arg. */

	ingsav = inglob;
	ocerr2 = 0;
	gsubf = compsub();
	for (a1 = addr1; a1 <= addr2; a1++) {
		if (execute(0, a1) == 0)
			continue;
		numpass = 0;
		ocerr1 = 0;
		inglob |= 01;
		dosub();
		if (gsubf) {
			while (*loc2) {
				if (execute(1, (LINE)0) == 0)
					break;
				dosub();
			}
		}
		if (ocerr1 == 0)continue;	/* Don't put out-not changed. */
		subnewa = putline();
		a1->cur &= ~01;
		if (anymarks) {
			for (markp = names; markp < &names[26]; markp++)
				if (*markp == a1->cur)
					*markp = subnewa;
		}
		a1->cur = subnewa;
		append(getsub, a1);
		nl = nline;
		a1 += nl;
		addr2 += nl;
	}
	if (ingsav)
		return;	/* Was in global-no error msg allowed. */
	if (inglob == 0)
		(void) error(35);	/* Not in global, but not found. */
	if (ocerr2 == 0)
		(void) error(35); /* RE found, but occurrence match failed. */
}

static int
compsub(void)
{
	int c;
	wchar_t seof;
	char *p;
	char multic[MB_LEN_MAX];
	int n;
	static char remem[RHSIZE];
	static int remflg = -1;
	int i;

	if ((n = _mbftowc(multic, &seof, getchr, &peekc)) <= 0)
		(void) error(67);
	if (seof == '\n' || seof == ' ')
		(void) error(36);
	comple(seof);
	p = rhsbuf;
	for (;;) {
		wchar_t cl;
		if ((n = _mbftowc(multic, &cl, getchr, &peekc)) <= 0)
			(void) error(67);
		if (cl == '\\') {
			*p++ = '\\';
			if (p >= &rhsbuf[RHSIZE])
				(void) error(38);
			if ((n = _mbftowc(multic, &cl, getchr, &peekc)) <= 0)
				(void) error(67);
		} else if (cl == '\n') {
			if (nodelim == 1) {
				nodelim = 0;
				(void) error(36);
			}
			if (!(globp && globp[0])) {
				UNGETC('\n');
				pflag++;
				break;
			}
		} else if (cl == seof)
			break;
		if (p + n > &rhsbuf[RHSIZE])
			(void) error(38);
		(void) strncpy(p, multic, n);
		p += n;
	}
	*p++ = 0;
	if (rhsbuf[0] == '%' && rhsbuf[1] == 0)
		/*
		 * If there isn't a remembered string, it is an error;
		 * otherwise the right hand side is the previous right
		 * hand side.
		 */

		if (remflg == -1)
			(void) error(55);
		else
			strcpy(rhsbuf, remem);
	else {
		strcpy(remem, rhsbuf);
		remflg = 0;
	}
	c = 0;
	peekc = getchr();	/* Gets char after third delimiter. */
	if (peekc == 'g') {
		c = LBSIZE; peekc = 0;
	}
	if (peekc >= '1' && peekc <= '9') {
		c = peekc-'0';
		peekc = 0;	/* Allows getchr() to get next char. */
		while (1) {
			i = getchr();
			if (i < '0' || i > '9')
				break;
			c = c*10 + i-'0';
			if (c > LBSIZE-1)
				(void) error(20);	/* "Illegal suffix" */
			}
		peekc = i;	/* Effectively an unget. */
		}
	newline();
	return (c);

	/*
	 * Returns occurrence value. 0 & 1 both do first occurrence
	 * only: c = 0 if ordinary substitute; c = 1
	 * if use 1 in global sub(s/a/b/1). 0 in global form is illegal.
	 */
}

static int
getsub(void)
{
	char *p1, *p2;

	p1 = linebuf;
	if ((p2 = linebp) == 0)
		return (EOF);
	while (*p1++ = *p2++)
		;
	linebp = 0;
	return (0);
}

static void
dosub(void)
{
	char *lp, *sp, *rp;
	int c;

	if (gsubf > 0 && gsubf < LBSIZE) {
		numpass++;
		if (gsubf != numpass)
			return;
	}
	ocerr1++;
	ocerr2++;
	lp = linebuf;
	sp = genbuf;
	rp = rhsbuf;
	while (lp < loc1)
		*sp++ = *lp++;
	while (c = *rp++) {
		if (c == '&') {
			sp = place(sp, loc1, loc2);
			continue;
		} else if (c == '\\') {
			c = *rp++;
			if (c >= '1' && c < nbra + '1') {
				sp = place(sp, braslist[c-'1'],
				    braelist[c-'1']);
				continue;
			}
		}
		*sp++ = c;
		if (sp >= &genbuf[LBSIZE])
			(void) error(27);
	}
	lp = loc2;
	loc2 = sp - genbuf + linebuf;
	while (*sp++ = *lp++)
		if (sp >= &genbuf[LBSIZE])
			(void) error(27);
	lp = linebuf;
	sp = genbuf;
	while (*lp++ = *sp++)
		;
}

static char *
place(char *sp, char *l1, char *l2)
{

	while (l1 < l2) {
		*sp++ = *l1++;
		if (sp >= &genbuf[LBSIZE])
			(void) error(27);
	}
	return (sp);
}

static void
comple(wchar_t seof)
{
	int cclass = 0;
	wchar_t c;
	int n;
	char *cp = genbuf;
	char multic[MB_LEN_MAX];

	while (1) {
		if ((n = _mbftowc(multic, &c, getchr, &peekc)) < 0)
			error1(67);
		if (n == 0 || c == '\n') {
			if (cclass)
				error1(49);
			else
				break;
		}
		if (c == seof && !cclass)
			break;
		if (cclass && c == ']') {
			cclass = 0;
			if (cp > &genbuf[LBSIZE-1])
				error1(50);
			*cp++ = ']';
			continue;
		}
		if (c == '[' && !cclass) {
			cclass = 1;
			if (cp > &genbuf[LBSIZE-1])
				error1(50);
			*cp++ = '[';
			if ((n = _mbftowc(multic, &c, getchr, &peekc)) < 0)
				error1(67);
			if (n == 0 || c == '\n')
				error1(49);
		}
		if (c == '\\' && !cclass) {
			if (cp > &genbuf[LBSIZE-1])
				error1(50);
			*cp++ = '\\';
			if ((n = _mbftowc(multic, &c, getchr, &peekc)) < 0)
				error1(67);
			if (n == 0 || c == '\n')
				error1(36);
		}
		if (cp + n > &genbuf[LBSIZE-1])
			error1(50);
		(void) strncpy(cp, multic, n);
		cp += n;
	}
	*cp = '\0';
	if (n != 0 && c == '\n')
		UNGETC('\n');
	if (n == 0 || c == '\n')
		nodelim = 1;

	/*
	 * NULL RE: do not compile a null regular expression; but process
	 * input with last regular expression encountered
	 */

	if (genbuf[0] != '\0') {
		if (expbuf)
			free(expbuf);
		expbuf = compile(genbuf, (char *)0, (char *)0);
	}
	if (regerrno)
		error1(regerrno);
}

static void
move(int cflag)
{
	LINE adt, ad1, ad2;

	setdot();
	nonzero();
	if ((adt = address()) == 0)
		(void) error(39);
	newline();
	if (!globflg) save();
	if (cflag) {
		ad1 = dol;
		append(getcopy, ad1++);
		ad2 = dol;
	} else {
		ad2 = addr2;
		for (ad1 = addr1; ad1 <= ad2; )
			(ad1++)->cur &= ~01;
		ad1 = addr1;
	}
	ad2++;
	if (adt < ad1) {
		dot = adt + (ad2-ad1);
		if ((++adt) == ad1)
			return;
		reverse(adt, ad1);
		reverse(ad1, ad2);
		reverse(adt, ad2);
	} else if (adt >= ad2) {
		dot = adt++;
		reverse(ad1, ad2);
		reverse(ad2, adt);
		reverse(ad1, adt);
	} else
		(void) error(39);
	fchange = 1;
}

static void
reverse(LINE a1, LINE a2)
{
	long t;

	for (;;) {
		t = (--a2)->cur;
		if (a2 <= a1)
			return;
		a2->cur = a1->cur;
		(a1++)->cur = t;
	}
}

static int
getcopy(void)
{

	if (addr1 > addr2)
		return (EOF);
	(void) getaline((addr1++)->cur);
	return (0);
}


/*
 * Handles error code returned from comple() routine: regular expression
 * compile and match routines
 */

static void
error1(int code)
{
	nbra = 0;
	(void) error(code);
}


static int
execute(int gf, LINE addr)
{
	char *p1;
	int c;

	for (c = 0; c < nbra; c++) {
		braslist[c] = 0;
		braelist[c] = 0;
	}
	if (gf)
		locs = p1 = loc2;
	else {
		if (addr == zero)
			return (0);
		p1 = getaline(addr->cur);
		locs = 0;
	}
	return (step(p1, expbuf));
}


static void
putd()
{
	int r;

	r = (int)(count%10);
	count /= 10;
	if (count)
		putd();
	putchr(r + '0');
}


int
puts(const char *sp)
{
	int n;
	wchar_t c;
	int sz, i;
	if (fss.Ffill && (listf == 0)) {

		/* deliberate attempt to remove constness of sp because */
		/* it needs to be expanded */

		if ((i = expnd((char *)sp, funny, &sz, &fss)) == -1) {
			write(1, funny, fss.Flim & 0377);
			putchr('\n');
			write(1, gettext("too long"),
			    strlen(gettext("too long")));
		}
		else
			write(1, funny, sz);
		putchr('\n');
		if (i == -2)
			write(1, gettext("tab count\n"),
			    strlen(gettext("tab count\n")));
		return (0);
	}
	col = 0;
	while (*sp) {
		n = mbtowc(&c, sp, MB_LEN_MAX);
		if (listf) {
			if (n < 1)
				(void) error(28);
			else if (n == 1)
				putchr((unsigned char)*sp++);
			else {
				sp += n;
				putwchr(c);
			}
		} else {
			putchr((unsigned char)*sp++);
		}
	}
#ifndef XPG6
	if (listf)
		putchr('$');    /* end of line is marked with a $ */
#else
	if (listf) {
	/* xpg6 - ensure that the end of line $ is not preceeded with a "\" */
	/* by doing a putchr() with listf=0, thereby avoiding the $ case */
	/* statement  in putchr() */
		listf = 0;
		putchr('$');    /* end of line is marked with a $ */
		listf++;
	}
#endif
	putchr('\n');
	return (1);
}


static void
putwchr(wchar_t ac)
{
	char buf[MB_LEN_MAX], *p;
	char *lp;
	wchar_t c;
	short len;

	lp = linp;
	c = ac;
	if (listf) {
		if (!iswprint(c)) {
			p = &buf[0];
			if ((len = wctomb(p, c)) <= 0) {
				*p = (unsigned char)c;
				len = 1;
			};
			while (len--) {
				if (col + 4 >= 72) {
					col = 0;
					*lp++ = '\\';
					*lp++ = '\n';
				}
				(void) sprintf(lp, "\\%03o",
				    *(unsigned char *)p++);
				col += 4;
				lp += 4;
			}
		} else {
			if ((len = wcwidth(c)) <= 0)
				len = 0;
			if (col + len >= 72) {
				col = 0;
				*lp++ = '\\';
				*lp++ = '\n';
			}
			col += len;
			if ((len = wctomb(lp, c)) <= 0) {
				*lp = (unsigned char)c;
				len = 1;
			}
			lp += len;
		}
	} else {
		if ((len = wctomb(lp, c)) <= 0) {
			*lp = (unsigned char)c;
			len = 1;
		}
		lp += len;
	}
	if (c == '\n' || lp >= &line[64]) {
		linp = line;
		len = lp - line;
		write(1, line, len);
		return;
	}
	linp = lp;
}


static void
putchr(unsigned char c)
{
	char *lp;
	int len;

	lp = linp;
	if (listf && c != '\n') {
		switch (c) {
			case '\\' :
				*lp++ = '\\';
				*lp++ = '\\';
				col += 2;
				break;
			case '\007' :
				*lp++ = '\\';
				*lp++ = 'a';
				col += 2;
				break;
			case '\b' :
				*lp++ = '\\';
				*lp++ = 'b';
				col += 2;
				break;
			case '\f' :
				*lp++ = '\\';
				*lp++ = 'f';
				col += 2;
				break;
			case '\r' :
				*lp++ = '\\';
				*lp++ = 'r';
				col += 2;
				break;
			case '\t' :
				*lp++ = '\\';
				*lp++ = 't';
				col += 2;
				break;
			case '\v' :
				*lp++ = '\\';
				*lp++ = 'v';
				col += 2;
				break;
#ifdef XPG6
		/* if $ characters are within the line preceed with \ */
			case '$' :
				*lp++ = '\\';
				*lp++ = '$';
				col += 2;
				break;
#endif
			default:
				if (isprint(c)) {
					*lp++ = c;
					col += 1;
				} else {
					(void) sprintf(lp, "\\%03o", c);
					col += 4;
					lp += 4;
				}
				break;
		}

	/*
	 * long lines are folded w/ pt of folding indicated by writing
	 * backslash/newline character
	 */

		if (col + 1 >= 72) {
			col = 0;
			*lp++ = '\\';
			*lp++ = '\n';
		}
	} else
		*lp++ = c;
	if (c == '\n' || lp >= &line[64]) {
		linp = line;
		len = lp - line;
		(void) write(1, line, len);
		return;
	}
	linp = lp;
}


static char *
getkey(const char *prompt)
{
	struct termio b;
	int save;
	void (*sig)();
	static char key[KSIZE+1];
	char *p;
	int c;

	sig = signal(SIGINT, SIG_IGN);
	ioctl(0, TCGETA, &b);
	save = b.c_lflag;
	b.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	ioctl(0, TCSETAW, &b);
	write(1, gettext(prompt), strlen(gettext(prompt)));
	p = key;
	while (((c = getchr()) != EOF) && (c != '\n')) {
		if (p < &key[KSIZE])
			*p++ = c;
	}
	*p = 0;
	write(1, "\n", 1);
	b.c_lflag = save;
	ioctl(0, TCSETAW, &b);
	signal(SIGINT, sig);
	return (key);
}


static void
globaln(int k)
{
	char *gp;
	int c;
	int n;
	wchar_t cl;
	LINE a1;
	int  nfirst;
	char globuf[LBSIZE];
	char multic[MB_LEN_MAX];
	int	len;
	int pflag_save = 0;
	int listf_save = 0;
	int listn_save = 0;

	if (globp)
		(void) error(33);
	setall();
	nonzero();
	if ((n = _mbftowc(multic, &cl, getchr, &peekc)) <= 0)
		(void) error(67);
	if (cl == '\n')
		(void) error(19);
	save();
	comple(cl);
	for (a1 = zero; a1 <= dol; a1++) {
		a1->cur &= ~01;
		if (a1 >= addr1 && a1 <= addr2 && execute(0, a1) == k)
			a1->cur |= 01;
	}
	nfirst = 0;
	newline();
	/*
	 * preserve the p, l, and n suffix commands of the G and V
	 * commands during the interactive section and restore
	 * on completion of the G and V command.
	 */
	pflag_save = pflag;
	listf_save = listf;
	listn_save = listn;
	pflag = 0;
	listf = 0;
	listn = 0;
	for (a1 = zero; a1 <= dol; a1++) {
		if (a1->cur & 01) {
			a1->cur &= ~01;
			dot = a1;
			puts(getaline(a1->cur));
			if ((c = get_wchr()) == EOF)
				(void) error(52);
			if (c == 'a' || c == 'i' || c == 'c')
				(void) error(53);
			if (c == '\n') {
				a1 = zero;
				continue;
			}
			if (c != '&') {
				gp = globuf;
				if ((len = wctomb(gp, c)) <= 0) {
					*gp = (unsigned char)c;
					len = 1;
				}
				gp += len;
				while ((c = get_wchr()) != '\n') {

			/* '\\' has special meaning only if preceding a '\n' */
					if (c == '\\') {
						c = get_wchr();
						if (c != '\n')
							*gp++ = '\\';
					}
					if ((gp + (unsigned int)MB_CUR_MAX) >=
					    &globuf[LBSIZE-1])
						(void) error(34);

					if ((len = wctomb(gp, c)) <= 0) {
						*gp = (unsigned char)c;
						len = 1;
					}
					gp += len;
				}
				*gp++ = '\n';
				*gp++ = 0;
				nfirst = 1;
			} else if ((c = get_wchr()) != '\n')
				(void) error(54);
			globp = globuf;
			if (nfirst) {
				globflg = 1;
				commands();
				globflg = 0;
			} else
				(void) error(56);
			globp = 0;
			a1 = zero;
		}
	}
	pflag = pflag_save;
	listf = listf_save;
	listn = listn_save;
}


static int
eopen(char *string, int rw)
{
#define	w_or_r(a, b) (rw ? a : b)
	int pf[2];
	pid_t i;
	int io;
	int chcount;	/* # of char read. */

	if (rflg) {	/* restricted shell */
		if (Xqt) {
			Xqt = 0;
			(void) error(6);
		}
	}
	if (!Xqt) {
		if ((io = open(string, rw)) >= 0) {
			if (fflg) {
				chcount = read(io, crbuf, LBSIZE);
				if (crflag == -1) {
					if (isencrypt(crbuf, chcount))
						crflag = 2;
					else
						crflag = -2;
				}
				if (crflag > 0)
				if (run_crypt(0L, crbuf, chcount, perm) == -1)
						(void) error(63);
				if (fspec(crbuf, &fss, 0) < 0) {
					fss.Ffill = 0;
					fflg = 0;
					(void) error(4);
				}
				lseek(io, 0L, 0);
			}
		}
		fflg = 0;
		return (io);
	}
	if (pipe(pf) < 0)
xerr:		(void) error(0);
	if ((i = fork()) == 0) {
		signal(SIGHUP, oldhup);
		signal(SIGQUIT, oldquit);
		signal(SIGPIPE, oldpipe);
		signal(SIGINT, (void (*)()) 0);
		close(w_or_r(pf[1], pf[0]));
		close(w_or_r(0, 1));
		dup(w_or_r(pf[0], pf[1]));
		close(w_or_r(pf[0], pf[1]));
		execlp(_PATH_BSHELL, "sh", "-c", string, (char *)0);
		exit(1);
	}
	if (i == (pid_t)-1)
		goto xerr;
	close(w_or_r(pf[0], pf[1]));
	return (w_or_r(pf[1], pf[0]));
}


static void
eclose(int f)
{
	close(f);
	if (Xqt)
		Xqt = 0, wait((int *)0);
}


static void
mkfunny(void)
{
	char *p, *p1, *p2;

	p2 = p1 = funny;
	p = file;
	/*
	 * Go to end of file name
	 */
	while (*p)
		p++;
	while (*--p  == '/')	/* delete trailing slashes */
		*p = '\0';
	/*
	 * go back to beginning of file
	 */
	p = file;
	/*
	 * Copy file name to funny setting p2 at
	 * basename of file.
	 */
	while (*p1++ = *p)
		if (*p++ == '/')
			p2 = p1;
	/*
	 * Set p1 to point to basename of tfname.
	 */
	p1 = strrchr(tfname, '/');
	if (strlen(tfname) > (size_t)6)
		p1 = &tfname[strlen(tfname)-6];
	p1++;
	*p2 = '\007'; /* add unprintable char for funny  a unique name */
	/*
	 * Copy tfname to file.
	 */
	while (*++p2 = *p1++)
		;
}


static void
getime(void) /* get modified time of file and save */
{
	if (stat(file, &Fl) < 0)
		savtime = 0;
	else
		savtime = Fl.st_mtime;
}


static void
chktime(void) /* check saved mod time against current mod time */
{
	if (savtime != 0 && Fl.st_mtime != 0) {
		if (savtime != Fl.st_mtime)
			(void) error(58);
	}
}


static void
newtime(void) /* get new mod time and save */
{
	stat(file, &Fl);
	savtime = Fl.st_mtime;
}


/*
 * restricted - check for '/' in name and delete trailing '/'
 */
static void
red(char *op)
{
	char *p;

	p = op;
	while (*p)
		if (*p++ == '/'&& rflg) {
			*op = 0;
			(void) error(6);
		}
	/* delete trailing '/' */
	while (p > op) {
		if (*--p == '/')
			*p = '\0';
		else break;
	}
}


/*
 * Searches thru beginning of file looking for a string of the form
 *	<: values... :>
 *
 * where "values" are
 *
 *	\b      ignored
 *	s<num>  sets the Flim to <num>
 *	t???    sets tab stop stuff
 *	d       ignored
 *	m<num>  ignored
 *	e       ignored
 */

static int
fspec(char line[], struct Fspec *f, int up)
{
	struct termio arg;
	int havespec, n;
	int	len;

	if (!up) clear(f);

	havespec = fsprtn = 0;
	for (fsp = line; *fsp && *fsp != '\n'; fsp += len) {
		if ((len = mblen(fsp, MB_CUR_MAX)) <= 0)
			len = 1;
		switch (*fsp) {

			case '<':	if (havespec)
						return (-1);
					if (*(fsp+1) == ':') {
						havespec = 1;
						clear(f);
						if (!ioctl(1, TCGETA, &arg) &&
						    ((arg.c_oflag & TAB3) ==
						    TAB3))
							f->Ffill = 1;
						fsp++;
						continue;
					}

			case ' ':	continue;

			case 's':	if (havespec && (n = numb()) >= 0)
						f->Flim = n;
					continue;

			case 't':	if (havespec) targ(f);
					continue;

			case 'd':	continue;

			case 'm':	if (havespec)  n = numb();
					continue;

			case 'e':	continue;
			case ':':	if (!havespec) continue;
					if (*(fsp+1) != '>') fsprtn = -1;
					return (fsprtn);

			default:	if (!havespec) continue;
					return (-1);
		}
	}
	return (1);
}


static int
numb(void)
{
	int n;

	n = 0;
	while (*++fsp >= '0' && *fsp <= '9')
		n = 10*n + *fsp-'0';
	fsp--;
	return (n);
}


static void
targ(struct Fspec *f)
{

	if (*++fsp == '-') {
		if (*(fsp + 1) >= '0' && *(fsp+1) <= '9') tincr(numb(), f);
		else tstd(f);
		return;
	}
	if (*fsp >= '0' && *fsp <= '9') {
		tlist(f);
		return;
	}
	fsprtn = -1;
	fsp--;
}


static void
tincr(int n, struct Fspec *f)
{
	int l, i;

	l = 1;
	for (i = 0; i < 20; i++)
		f->Ftabs[i] = l += n;
	f->Ftabs[i] = 0;
}


static void
tstd(struct Fspec *f)
{
	char std[3];

	std[0] = *++fsp;
	if (*(fsp+1) >= '0' && *(fsp+1) <= '9')  {
						std[1] = *++fsp;
						std[2] = '\0';
	} else {
		std[1] = '\0';
	}
	fsprtn = stdtab(std, f->Ftabs);
}


static void
tlist(struct Fspec *f)
{
	int n, last, i;

	fsp--;
	last = i = 0;

	do {
		if ((n = numb()) <= last || i >= 20) {
			fsprtn = -1;
			return;
		}
		f->Ftabs[i++] = last = n;
	} while (*++fsp == ',');

	f->Ftabs[i] = 0;
	fsp--;
}


static int
expnd(char line[], char buf[], int *sz, struct Fspec *f)
{
	char *l, *t;
	int b;

	l = line - 1;
	b = 1;
	t = f->Ftabs;
	fsprtn = 0;

	while (*++l && *l != '\n' && b < 511) {
		if (*l == '\t') {
			while (*t && b >= *t)
				t++;
			if (*t == 0)
				fsprtn = -2;
			do {
				buf[b-1] = ' ';
			} while (++b < *t);
		} else {
			buf[b++ - 1] = *l;
		}
	}

	buf[b] = '\0';
	*sz = b;
	if (*l != '\0' && *l != '\n') {
		buf[b-1] = '\n';
		return (-1);
	}
	buf[b-1] = *l;
	if (f->Flim && (b-1 > (int)f->Flim))
		return (-1);
	return (fsprtn);
}


static void
clear(struct Fspec *f)
{
	f->Ftabs[0] = f->Fdel = f->Fmov = f->Ffill = 0;
	f->Flim = 0;
}


static int
lenchk(char line[], struct Fspec *f)
{
	char *l, *t;
	int b;

	l = line - 1;
	b = 1;
	t = f->Ftabs;

	while (*++l && *l != '\n' && b < 511) {
		if (*l == '\t') {
			while (*t && b >= *t)
				t++;
			while (++b < *t)
				;
		} else {
			b++;
		}
	}

	if ((*l != '\0' && *l != '\n') || (f->Flim && (b-1 > (int)f->Flim)))
		return (-1);
	return (0);
}
#define	NTABS 21


/*
 *	stdtabs: standard tabs table
 *	format: option code letter(s), null, tabs, null
 */

static char stdtabs[] = {
'a', 0, 1, 10, 16, 36, 72, 0,			/* IBM 370 Assembler */
'a', '2', 0, 1, 10, 16, 40, 72, 0,		/* IBM Assembler alternative */
'c', 0, 1, 8, 12, 16, 20, 55, 0,		/* COBOL, normal */
'c', '2', 0, 1, 6, 10, 14, 49, 0,		/* COBOL, crunched */
'c', '3', 0, 1, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50,
	54, 58, 62, 67, 0,
'f', 0, 1, 7, 11, 15, 19, 23, 0,		/* FORTRAN */
'p', 0, 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 0,
						/* PL/I */
's', 0, 1, 10, 55, 0,    			/* SNOBOL */
'u', 0, 1, 12, 20, 44, 0, 			/* UNIVAC ASM */
0 };


/*
 *	stdtab: return tab list for any "canned" tab option.
 *		entry: option points to null-terminated option string
 *		tabvect points to vector to be filled in
 *	exit: return (0) if legal, tabvect filled, ending with zero
 *		return (-1) if unknown option
 */


static int
stdtab(char option[], char tabvect[NTABS])
{
	char *scan;
	tabvect[0] = 0;
	scan = stdtabs;
	while (*scan) {
		if (strequal(&scan, option)) {
			strcopy(scan, tabvect);
			break;
		} else
			while (*scan++)		/* skip over tab specs */
				;
	}

/*	later: look up code in /etc/something */
	return (tabvect[0] ? 0 : -1);
}


/*
 *	strequal: checks strings for equality
 *		entry: scan1 points to scan pointer, str points to string
 *	exit: return (1) if equal, return (0) if not
 *		*scan1 is advanced to next nonzero byte after null
 */


static int
strequal(char **scan1, char *str)
{
	char c, *scan;
	scan = *scan1;
	while ((c = *scan++) == *str && c)
		str++;
	*scan1 = scan;
	if (c == 0 && *str == 0)
		return (1);
	if (c)
		while (*scan++)
			;
	*scan1 = scan;
	return (0);
}


/*	strcopy: copy source to destination */


static void
strcopy(char *source, char *dest)
{
	while (*dest++ = *source++)
		;
}


/* This is called before a buffer modifying command so that the */
/* current array of line ptrs is saved in sav and dot and dol are saved */


static void
save(void)
{
	LINE i;
	int	j;

	savdot = dot;
	savdol = dol;
	for (j = 0; j <= 25; j++)
		savnames[j] = names[j];

	for (i = zero + 1; i <= dol; i++)
		i->sav = i->cur;
	initflg = 0;
}


/* The undo command calls this to restore the previous ptr array sav */
/* and swap with cur - dot and dol are swapped also. This allows user to */
/* undo an undo */


static void
undo(void)
{
	int j;
	long tmp;
	LINE i, tmpdot, tmpdol;

	tmpdot = dot; dot = savdot; savdot = tmpdot;
	tmpdol = dol; dol = savdol; savdol = tmpdol;
	/* swap arrays using the greater of dol or savdol as upper limit */
	for (i = zero + 1; i <= ((dol > savdol) ? dol : savdol); i++) {
		tmp = i->cur;
		i->cur = i->sav;
		i->sav = tmp;
	}
		/*
		 * If the current text lines are swapped with the
		 * text lines in the save buffer, then swap the current
		 * marks with those in the save area.
		 */

		for (j = 0; j <= 25; j++) {
			tmp = names[j];
			names[j] = savnames[j];
			savnames[j] = tmp;
		}
}

static wchar_t
get_wchr(void)
{
	wchar_t	wc;
	char	multi[MB_LEN_MAX];

	if (_mbftowc(multi, &wc, getchr, &peekc) <= 0)
		wc = getchr();
	return (wc);
}
