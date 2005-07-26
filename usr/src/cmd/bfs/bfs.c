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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <regexpr.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <wait.h>
#include <fcntl.h>
int setjmp();
static jmp_buf env;

extern int scrwidth(wchar_t);

#define	BRKTYP	char
#define	BRKSIZ	8192
#define	BRKTWO	4
#define	BFSAND
#define	BFSLIM	511
#define	BFSTRU	511
#define	BFSBUF	512

struct Comd {
	int Cnumadr;
	int Cadr[2];
	char Csep;
	char Cop;
};

static int Dot, Dollar;
static int markarray[26], *mark;
static int fstack[15] = {1, -1};
static int infildes = 0;
static int outfildes = 1;
static char internal[512], *intptr;
static char comdlist[100];
static char *endds;
static char charbuf = '\n';
static int peeked;
static char currex[100];
static int trunc = BFSTRU;
static int crunch = -1;
static int segblk[512], segoff[512], txtfd, prevblk, prevoff;
static int oldfd = 0;
static int flag4 = 0;
static int flag3 = 0;
static int flag2 = 0;
static int flag1 = 0;
static int flag = 0;
static int lprev = 1;
static int status[1];
static BRKTYP *lincnt;
static char *perbuf;
static char *rebuf;
static char *glbuf;
static char tty, *bigfile;
static char fle[80];
static char prompt = 1;
static char verbose = 1;	/* 1=print # of bytes read in; 0=silent. */
static char varray[10][100];	/* Holds xv cmd parameters. */
static double outcnt;
static char strtmp[32];

static void reset();
static void begin(struct Comd *p);
static int  bigopen(char file[]);
static void sizeprt(int blk, int off);
static void bigread(int l, char rec[]);
static int gcomd(struct Comd *p, int k);
static int fcomd(struct Comd *p);
static void ecomd();
static int kcomd(struct Comd *p);
static int xncomd(struct Comd *p);
static int pcomd(struct Comd *p);
static int qcomd();
static int xcomds(struct Comd *p);
static int xbcomd(struct Comd *p);
static int xccomd(struct Comd *p);
static int xfcomd(struct Comd *p);
static int xocomd(struct Comd *p);
static int xtcomd(struct Comd *p);
static int xvcomd();
static int wcomd(struct Comd *p);
static int nlcomd(struct Comd *p);
static int eqcomd(struct Comd *p);
static int colcomd(struct Comd *p);
static int excomd();
static int xcomdlist(struct Comd *p);
static int defaults(struct Comd *p, int prt, int max,
		    int def1, int def2, int setdot, int errsok);
static int getcomd(struct Comd *p, int prt);
static int getadrs(struct Comd *p, int prt);
static int getadr(struct Comd *p, int prt);
static int getnumb(struct Comd *p, int prt);
static int rdnumb(int prt);
static int getrel(struct Comd *p, int prt);
static int getmark(struct Comd *p, int prt);
static int getrex(struct Comd *p, int prt, char c);
static int hunt(int prt, char rex[], int start, int down, int wrap, int errsok);
static int jump(int prt, char label[]);
static int getstr(int prt, char buf[], char brk, char ignr, int nonl);
static int regerr(int c);
static int err(int prt, char msg[]);
static char mygetc();
static int readc(int f, char *c);
static int percent(char line[256]);
static int newfile(int prt, char f[]);
static void push(int s[], int d);
static int pop(int s[]);
static int peekc();
static void eat();
static int more();
static void quit();
static void out(char *ln);
static char *untab(char l[]);
static int patoi(char *b);
static int equal(char *a, char *b);

int
main(int argc, char *argv[])
{
	struct Comd comdstruct, *p;
	(void) setlocale(LC_ALL, "");
	if (argc < 2 || argc > 3) {
		(void) err(1, "arg count");
		quit();
	}
	mark = markarray-'a';
	if (argc == 3) {
		verbose = 0;
	}
	setbuf(stdout, 0);
	if (bigopen(bigfile = argv[argc-1]))
		quit();
	tty = isatty(0);
	p = &comdstruct;
	/* Look for 0 or more non-'%' char followed by a '%' */
	perbuf = compile("[^%]*%", (char *)0, (char *)0);
	if (regerrno)
		(void) regerr(regerrno);
	(void) setjmp(env);
#if defined(__STDC__)
	(void) signal(SIGINT, (void (*)(int))reset);
#else
	(void) signal(SIGINT, reset);
#endif
	(void) err(0, "");
	(void) printf("\n");
	flag = 0;
	prompt = 0;
	/*CONSTCOND*/	for (;;)
		begin(p);

	/* NOTREACHED */
	return (0);
}

static void
reset()		/* for longjmp on signal */
{
	longjmp(env, 1);
}

static void
begin(struct Comd *p)
{
	char line[256];
	strtagn:
	if (flag == 0)
		eat();
	if (infildes != 100) {
		if (infildes == 0 && prompt)
			(void) printf("*");
		flag3 = 1;
		if (getstr(1, line, 0, 0, 0))
			exit(1);
		flag3 = 0;
		if (percent(line) < 0)
			goto strtagn;
		(void) newfile(1, "");
	}
	if (!(getcomd(p, 1) < 0)) {
		switch (p->Cop) {
		case 'e':
			if (!flag)
				ecomd();
			else
				(void) err(0, "");
			break;

		case 'f':
			(void) fcomd(p);
			break;

		case 'g':
			if (flag == 0)
				(void) gcomd(p, 1);
			else
				(void) err(0, "");
			break;

		case 'k':
			(void)  kcomd(p);
			break;

		case 'p':
			(void) pcomd(p);
			break;

		case 'q':
			(void) qcomd();
			break;

		case 'v':
			if (flag == 0)
				(void) gcomd(p, 0);
			else
				(void) err(0, "");
			break;

		case 'x':
			if (!flag)
				(void) xcomds(p);
			else
				(void) err(0, "");
			break;

		case 'w':
			(void) wcomd(p);
			break;

		case '\n':
			(void)  nlcomd(p);
			break;

		case '=':
			(void) eqcomd(p);
			break;

		case ':':
			(void) colcomd(p);
			break;

		case '!':
			(void) excomd();
			break;

		case 'P':
			prompt = !prompt;
			break;

		default:
			if (flag)
				(void) err(0, "");
			else
				(void) err(1, "bad command");
			break;
		}
	}
}

static int
bigopen(char file[])
{
	int l, off, cnt;
	int blk, newline, n, s;
	char block[512];
	size_t totsiz;
	BRKTYP *tptr;
	if ((txtfd = open(file, 0)) < 0)
		return (err(1, "can't open"));
	blk = -1;
	newline = 1;
	l = cnt = s = 0;
	off = 512;
	totsiz = 0;
	if ((lincnt = (BRKTYP *)malloc(BRKSIZ)) == (BRKTYP *)NULL)
		return (err(1, "too many lines"));
	endds = (BRKTYP *)lincnt;
	totsiz += BRKSIZ;
	while ((n = read(txtfd, block, 512)) > 0) {
		blk++;
		for (off = 0; off < n; off++) {
			if (newline) {
				newline = 0;
				if (l > 0 && !(l&07777)) {
					totsiz += BRKSIZ;
					tptr = (BRKTYP *)
					    realloc(lincnt, totsiz);
					if (tptr == NULL)
						return
						    (err(1, "too many lines"));
					else
						lincnt = tptr;
				}
				lincnt[l] = (char)cnt;
				cnt = 0;
				if (!(l++ & 077)) {
					segblk[s] = blk;
					segoff[s++] = off;
				}
				if (l < 0 || l > 32767)
					return (err(1, "too many lines"));
			}
			if (block[off] == '\n') newline = 1;
			cnt++;
		}
	}
	if (!(l&07777)) {
		totsiz += BRKTWO;
		tptr = (BRKTYP *)realloc(lincnt, totsiz);
		if (tptr == NULL)
			return (err(1, "too many lines"));
		else
			lincnt = tptr;
	}
	lincnt[Dot = Dollar = l] = (char)cnt;
	sizeprt(blk, off);
	return (0);
}

static void
sizeprt(int blk, int off)
{
	if (verbose)
		(void) printf("%.0f", 512.*blk+off);
}

static int saveblk = -1;

static void
bigread(int l, char rec[])
{
	int i;
	char *r, *b;
	int off;
	static char savetxt[512];

	if ((i = l-lprev) == 1) prevoff += lincnt[lprev]BFSAND;
	else if (i >= 0 && i <= 32)
		for (i = lprev; i < l; i++) prevoff += lincnt[i]BFSAND;
	else if (i < 0 && i >= -32)
		for (i = lprev-1; i >= l; i--) prevoff -= lincnt[i]BFSAND;
	else {
		prevblk = segblk[i = (l-1)>>6];
		prevoff = segoff[i];
		for (i = (i<<6)+1; i < l; i++) prevoff += lincnt[i]BFSAND;
	}

	prevblk += prevoff>>9;
	prevoff &= 0777;
	lprev = l;
	if (prevblk != saveblk) {
		(void) lseek(txtfd, ((long)(saveblk = prevblk))<<9, 0);
		(void) read(txtfd, savetxt, 512);
	}
	r = rec;
	off = prevoff;
	/*CONSTCOND*/while (1) {
		for (b = savetxt+off; b < savetxt+512; b++) {
			if ((*r++ = *b) == '\n') {
				*(r-1) = '\0';
				return;
			}
			if (((unsigned)r - (unsigned)rec) > BFSLIM) {

				(void) write(2,
				    "Line too long--output truncated\n", 32);
				return;
			}
		}
		(void) read(txtfd, savetxt, 512);
		off = 0;
		saveblk++;
	}
}

static void
ecomd()
{
	int i = 0;
	while (peekc() == ' ')
		(void) mygetc();
	while ((fle[i++] = mygetc()) != '\n');
	fle[--i] = '\0';
	/* Without this, ~20 "e" cmds gave "can't open" msg. */
	(void) close(txtfd);
	free(endds);
	/* Reset parameters. */
	lprev = 1;
	prevblk = 0;
	prevoff = 0;
	saveblk = -1;
	if (bigopen(bigfile  = fle))
		quit();
	(void) printf("\n");
}

static int
fcomd(struct Comd *p)
{
	if (more() || defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);
	(void) printf("%s\n", bigfile);
	return (0);
}

static int
gcomd(struct Comd *p, int k)
{
	char d;
	int i, end;
	char line[BFSBUF];
	if (defaults(p, 1, 2, 1, Dollar, 0, 0))
		return (-1);
	if ((d = mygetc()) == '\n')
		return (err(1, "syntax"));
	if (peekc() == d)
		(void) mygetc();
	else
		if (getstr(1, currex, d, 0, 1))
			return (-1);
	glbuf = compile(currex, (char *)0, (char *)0);
	if (regerrno) {
		(void) regerr(regerrno);
		return (-1);
	} else {
		if (glbuf)
			free(glbuf);
	}

	if (getstr(1, comdlist, 0, 0, 0))
		return (-1);
	i = p->Cadr[0];
	end = p->Cadr[1];
	while (i <= end) {
		bigread(i, line);
		if (!(step(line, glbuf))) {
			if (!k) {
				Dot = i;
				if (xcomdlist(p))
					return (err(1, "bad comd list"));
			}
			i++;
		} else {
			if (k) {
				Dot = i;
				if (xcomdlist(p))
					return (err(1, "bad comd list"));
			}
			i++;
		}
	}
	return (0);
}

static int
kcomd(struct Comd *p)
{
	char c;
	if ((c = peekc()) < 'a' || c > 'z')
		return (err(1, "bad mark"));
	(void) mygetc();
	if (more() || defaults(p, 1, 1, Dot, 0, 1, 0))
		return (-1);
	mark[c] = Dot = p->Cadr[0];
	return (0);
}

static int
xncomd(struct Comd *p)
{
	char c;
	if (more() || defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);

	for (c = 'a'; c <= 'z'; c++)
		if (mark[c])
			(void) printf("%c\n", c);

	return (0);
}

static int
pcomd(struct Comd *p)
{
	int i;
	char line[BFSBUF];
	if (more() || defaults(p, 1, 2, Dot, Dot, 1, 0))
		return (-1);
	for (i = p->Cadr[0]; i <= p->Cadr[1] && i > 0; i++) {
		bigread(i, line);
		out(line);
	}
	return (0);
}

static int
qcomd()
{
	if (more())
		return (-1);
	quit();
	return (0);
}

static int
xcomds(struct Comd *p)
{
	switch (mygetc()) {
	case 'b':	return (xbcomd(p));
	case 'c':	return (xccomd(p));
	case 'f':	return (xfcomd(p));
	case 'n':	return (xncomd(p));
	case 'o':	return (xocomd(p));
	case 't':	return (xtcomd(p));
	case 'v':	return (xvcomd());
	default:	return (err(1, "bad command"));
	}
}

static int
xbcomd(struct Comd *p)
{
	int fail,  n;
	char d;
	char str[50];

	fail = 0;
	if (defaults(p, 0, 2, Dot, Dot, 0, 1))
		fail = 1;
	else {
		if ((d = mygetc()) == '\n')
			return (err(1, "syntax"));
		if (d == 'z') {
			if (status[0] != 0)
				return (0);
			(void) mygetc();
			if (getstr(1, str, 0, 0, 0))
				return (-1);
			return (jump(1, str));
		}
		if (d == 'n') {
			if (status[0] == 0)
				return (0);
			(void) mygetc();
			if (getstr(1, str, 0, 0, 0))
				return (-1);
			return (jump(1, str));
		}
		if (getstr(1, str, d, ' ', 0))
			return (-1);
		if ((n = hunt(0, str, p->Cadr[0]-1, 1, 0, 1)) < 0)
			fail = 1;
		if (getstr(1, str, 0, 0, 0))
			return (-1);
		if (more())
			return (err(1, "syntax"));
	}
	if (!fail) {
		Dot = n;
		return (jump(1, str));
	}
	return (0);
}

static int
xccomd(struct Comd *p)
{
	char arg[100];
	if (getstr(1, arg, 0, ' ', 0) || defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);
	if (equal(arg, ""))
		crunch = -crunch;
	else if (equal(arg, "0"))
		crunch = -1;
	else if (equal(arg, "1"))
		crunch = 1;
	else
		return (err(1, "syntax"));

	return (0);
}

static int
xfcomd(struct Comd *p)
{
	char fl[100];
	char *f;
	if (defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);

	while (peekc() == ' ')
		(void) mygetc();
	for (f = fl; (*f = mygetc()) != '\n'; f++);
	if (f == fl)
		return (err(1, "no file"));
	*f = '\0';

	return (newfile(1, fl));
}

static int
xocomd(struct Comd *p)
{
	int fd;
	char arg[100];

	if (getstr(1, arg, 0, ' ', 0) || defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);

	if (!arg[0]) {
		if (outfildes == 1)
			return (err(1, "no diversion"));
		(void) close(outfildes);
		outfildes = 1;
	} else {
		if (outfildes != 1)
			return (err(1, "already diverted"));
		if ((fd = open(arg, O_WRONLY|O_CREAT|O_TRUNC,
		    (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH))) < 0)
			return (err(1, "can't create"));
		outfildes = fd;
	}
	return (0);
}

static int
xtcomd(struct Comd *p)
{
	int t;

	while (peekc() == ' ')
		(void) mygetc();
	if ((t = rdnumb(1)) < 0 || more() || defaults(p, 1, 0, 0, 0, 0, 0))
		return (-1);

	trunc = t;
	return (0);
}

static int
xvcomd()
{
	char c;
	int i;
	int temp0, temp1, temp2;
	int fildes[2];

	if ((c = peekc()) < '0' || c > '9')
		return (err(1, "digit required"));
	(void) mygetc();
	c -= '0';
	while (peekc() == ' ')
		(void) mygetc();
	if (peekc() == '\\')
		(void) mygetc();
	else if (peekc()  ==  '!') {
		if (pipe(fildes) < 0) {
			(void) printf("Try again");
			return (-1);
		}
		temp0 = dup(0);
		temp1 = dup(1);
		temp2 = infildes;
		(void) close(0);
		(void) dup(fildes[0]);
		(void) close(1);
		(void) dup(fildes[1]);
		(void) close(fildes[0]);
		(void) close(fildes[1]);
		(void) mygetc();
		flag4 = 1;
		(void) excomd();
		(void) close(1);
		infildes = 0;
	}
	for (i = 0; (varray[c][i] = mygetc()) != '\n'; i++);
	varray[c][i] = '\0';
	if (flag4) {
		infildes = temp2;
		(void) close(0);
		(void) dup(temp0);
		(void) close(temp0);
		(void) dup(temp1);
		(void) close(temp1);
		flag4 = 0;
		charbuf = ' ';
	}
	return (0);
}

static int
wcomd(struct Comd *p)
{
	int i, fd, savefd;
	int savecrunch, savetrunc;
	char arg[100], line[BFSBUF];

	if (getstr(1, arg, 0, ' ', 0) || defaults(p, 1, 2, 1, Dollar, 1, 0))
		return (-1);
	if (!arg[0])
		return (err(1, "no file name"));
	if (equal(arg, bigfile))
		return (err(1, "no change indicated"));
	if ((fd = open(arg, O_WRONLY|O_CREAT|O_TRUNC,
	    (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)))  < 0)
		return (err(1, "can't create"));

	savefd = outfildes;
	savetrunc = trunc;
	savecrunch = crunch;
	outfildes = fd;
	trunc = BFSTRU;
	crunch = -1;

	outcnt = 0;
	for (i = p->Cadr[0]; i <= p->Cadr[1] && i > 0; i++) {
		bigread(i, line);
		out(line);
	}
	if (verbose)
		(void) printf("%.0f\n", outcnt);
	(void) close(fd);

	outfildes = savefd;
	trunc = savetrunc;
	crunch = savecrunch;
	return (0);
}

static int
nlcomd(struct Comd *p)
{
	if (defaults(p, 1, 2, Dot+1, Dot+1, 1, 0)) {
		(void) mygetc();
		return (-1);
	}
	return (pcomd(p));
}

static int
eqcomd(struct Comd *p)
{
	if (more() || defaults(p, 1, 1, Dollar, 0, 0, 0))
		return (-1);
	(void) printf("%d\n", p->Cadr[0]);
	return (0);
}

static int
colcomd(struct Comd *p)
{
	return (defaults(p, 1, 0, 0, 0, 0, 0));
}

static int
xcomdlist(struct Comd *p)
{
	flag = 1;
	flag2 = 1;
	(void) newfile(1, "");
	while (flag2)
		begin(p);
	if (flag == 0)
		return (1);
	flag = 0;
	return (0);
}

static int
excomd()
{
	pid_t i;
	int j;
	if (infildes != 100)
		charbuf = '\n';
	while ((i = fork()) < (pid_t)0)
		(void) sleep(10);
	if (i == (pid_t)0) {
		/* Guarantees child can be intr. */
		(void) signal(SIGINT, SIG_DFL);
		if (infildes == 100 || flag4) {
			(void) execl("/usr/bin/sh", "sh", "-c", intptr, 0);
			exit(0);
		}
		if (infildes != 0) {
			(void) close(0);
			(void) dup(infildes);
		}
		for (j = 3; j < 15; j++) (void) close(j);
		(void) execl("/usr/bin/sh", "sh", "-t", 0);
		exit(0);
	}
	(void) signal(SIGINT, SIG_IGN);
	while (wait(status) != i);
	status[0] = status[0] >> 8;

#if defined(__STDC__)
	(void) signal(SIGINT, (void (*)(int))reset);
#else
	(void) signal(SIGINT, reset);	/* Restore signal to previous status */
#endif

	if (((infildes == 0) || ((infildes  == 100) &&
	    (fstack[fstack[0]] == 0)))&& verbose && (!flag4))
		(void) printf("!\n");
	return (0);
}

static int
defaults(struct Comd *p, int prt, int max,
    int def1, int def2, int setdot, int errsok)
{
	if (!def1)
		def1 = Dot;
	if (!def2)
		def2 = def1;
	if (p->Cnumadr >= max)
		return (errsok?-1:err(prt, "adr count"));
	if (p->Cnumadr < 0) {
		p->Cadr[++p->Cnumadr] = def1;
		p->Cadr[++p->Cnumadr] = def2;
	} else if (p->Cnumadr < 1)
		p->Cadr[++p->Cnumadr] = p->Cadr[0];
	if (p->Cadr[0] < 1 || p->Cadr[0] > Dollar ||
	    p->Cadr[1] < 1 || p->Cadr[1] > Dollar)
		return (errsok?-1:err(prt, "range"));
	if (p->Cadr[0] > p->Cadr[1])
		return (errsok?-1:err(prt, "adr1 > adr2"));
	if (setdot)
		Dot = p->Cadr[1];
	return (0);
}

static int
getcomd(struct Comd *p, int prt)
{
	int r;
	int c;

	p->Cnumadr = -1;
	p->Csep = ' ';
	switch (c = peekc()) {
	case ',':
	case ';':	p->Cop = mygetc();
		return (0);
	}

	if ((r = getadrs(p, prt)) < 0)
		return (r);

	if ((c = peekc()) < 0)
		return (err(prt, "syntax"));
	if (c == '\n')
		p->Cop = '\n';
	else
		p->Cop = mygetc();

	return (0);
}

static int
getadrs(struct Comd *p, int prt)
{
	int r;
	char c;

	if ((r = getadr(p, prt)) < 0)
		return (r);

	switch (c = peekc()) {
		case ';':
			Dot = p->Cadr[0];
			(void) mygetc();
			p->Csep = c;
			return (getadr(p, prt));
		case ',':
			(void) mygetc();
			p->Csep = c;
			return (getadr(p, prt));
		}

	return (0);
}

static int
getadr(struct Comd *p, int prt)
{
	int r;
	char c;

	r = 0;
	while (peekc() == ' ')
		(void) mygetc();	/* Ignore leading spaces */
	switch (c = peekc()) {
		case '\n':
		case ',':
		case ';':	return (0);
		case '\'':	(void) mygetc();
			r = getmark(p, prt);
			break;

		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':	r = getnumb(p, prt);
			break;
		case '.':	(void) mygetc();
			p->Cadr[++p->Cnumadr] = Dot;
			break;
		case '+':
		case '-':	p->Cadr[++p->Cnumadr] = Dot;
			break;
		case '$':	(void) mygetc();
			p->Cadr[++p->Cnumadr] = Dollar;
			break;
		case '^':	(void) mygetc();
			p->Cadr[++p->Cnumadr] = Dot - 1;
			break;
		case '/':
		case '?':
		case '>':
		case '<':	(void) mygetc();
			r = getrex(p, prt, c);
			break;
		default:	return (0);
		}

	if (r == 0)
		r = getrel(p, prt);
	return (r);
}

static int
getnumb(struct Comd *p, int prt)
{
	int i;

	if ((i = rdnumb(prt)) < 0)
		return (-1);
	p->Cadr[++p->Cnumadr] = i;
	return (0);
}

static int
rdnumb(int prt)
{
	char num[20],  *n;
	int i;

	n = num;
	while ((*n = peekc()) >= '0' && *n <= '9') {
		n++;
		(void) mygetc();
	}

	*n = '\0';
	if ((i = patoi(num)) >= 0)
		return (i);
	return (err(prt, "bad num"));
}

static int
getrel(struct Comd *p, int prt)
{
	int op, n;
	char c;
	int j;

	n = 0;
	op = 1;
	while ((c = peekc()) == '+' || c == '-') {
		if (c == '+')
			n++;
		else
			n--;
		(void) mygetc();
	}
	j = n;
	if (n < 0)
		op = -1;
	if (c == '\n')
		p->Cadr[p->Cnumadr] += n;
	else {
		if ((n = rdnumb(0)) > 0 && p->Cnumadr >= 0) {
			p->Cadr[p->Cnumadr] += op*n;
			(void) getrel(p, prt);
		} else {
			p->Cadr[p->Cnumadr] += j;
		}
	}
	return (0);
}

static int
getmark(struct Comd *p, int prt)
{
	char c;

	if ((c = peekc()) < 'a' || c > 'z')
		return (err(prt, "bad mark"));
	(void) mygetc();

	if (!mark[c])
		return (err(prt, "undefined mark"));
	p->Cadr[++p->Cnumadr] = mark[c];
	return (0);
}

static int
getrex(struct Comd *p, int prt, char c)
{
	int down, wrap, start;

	if (peekc() == c)
		(void) mygetc();
	else if (getstr(prt, currex, c, 0, 1))
		return (-1);

	switch (c) {
	case '/':	down = 1; wrap = 1; break;
	case '?':	down = 0; wrap = 1; break;
	case '>':	down = 1; wrap = 0; break;
	case '<':	down = 0; wrap = 0; break;
	}

	if (p->Csep == ';')
		start = p->Cadr[0];
	else
		start = Dot;

	if ((p->Cadr[++p->Cnumadr] = hunt(prt, currex, start, down, wrap, 0))
	    < 0)
		return (-1);
	return (0);
}

static int
hunt(int prt, char rex[], int start, int down, int wrap, int errsok)
{
	int i, end1, incr;
	int start1, start2;
	char line[BFSBUF];

	if (down) {
		start1 = start + 1;
		end1 = Dollar;
		start2 = 1;
		incr = 1;
	} else {
		start1 = start  - 1;
		end1 = 1;
		start2 = Dollar;
		incr = -1;
	}

	rebuf = compile(rex, (char *)0, (char *)0);
	if (regerrno)
		(void) regerr(regerrno);
	else
		if (rebuf)
			free(rebuf);

	for (i = start1; i != end1+incr; i += incr) {
		bigread(i, line);
		if (step(line, rebuf)) {
			return (i);
		}
	}

	if (!wrap)
		return (errsok?-1:err(prt, "not found"));

	for (i = start2; i != start1; i += incr) {
		bigread(i, line);
		if (step(line, rebuf)) {
			return (i);
		}
	}

	return (errsok?-1:err(prt, "not found"));
}

static int
jump(int prt, char label[])
{
	char *l;
	char line[256];

	if (infildes == 0 && tty)
		return (err(prt, "jump on tty"));
	if (infildes == 100)
		intptr = internal;
	else
		(void) lseek(infildes, 0L, 0);

	(void) snprintf(strtmp,
	    sizeof (strtmp) * sizeof (char), "^: *%s$", label);
	rebuf = compile(strtmp, (char *)0, (char *)0);
	if (regerrno) {
		(void) regerr(regerrno);
		return (-1);
	}

	for (l = line; readc(infildes, l); l++) {
		if (*l == '\n') {
			*l = '\0';
			if (step(line, rebuf)) {
				charbuf = '\n';
				return (peeked = 0);
			}
			l = line - 1;
		}
	}

	return (err(prt, "label not found"));
}

static int
getstr(int prt, char buf[], char brk, char ignr, int nonl)
{
	char *b, c, prevc;

	prevc = 0;
	for (b = buf; c = peekc(); prevc = c) {
		if (c == '\n') {
			if (prevc == '\\' && (!flag3)) *(b-1) = mygetc();
			else if (prevc == '\\' && flag3) {
				*b++ = mygetc();
			} else if (nonl)
				break;
			else
				return (*b = '\0');
		} else {
			(void) mygetc();
			if (c == brk) {
				if (prevc == '\\') *(b-1) = c;
				else return (*b = '\0');
			} else if (b != buf || c != ignr) *b++ = c;
		}
	}
	return (err(prt, "syntax"));
}

static int
regerr(int c)
{
	if (prompt) {
		switch (c) {
		case 11: (void) printf("Range endpoint too large.\n");
			break;
		case 16: (void) printf("Bad number.\n");
			break;
		case 25: (void) printf("``\\digit'' out of range.\n");
			break;
		case 41: (void) printf("No remembered search string.\n");
			break;
		case 42: (void) printf("() imbalance.\n");
			break;
		case 43: (void) printf("Too many (.\n");
			break;
		case 44: (void) printf("More than 2 numbers given in { }.\n");
			break;
		case 45: (void) printf("} expected after \\.\n");
			break;
		case 46: (void) printf("First number exceeds second in { }.\n");
			break;
		case 49: (void) printf("[] imbalance.\n");
			break;
		case 50: (void) printf("Regular expression overflow.\n");
			break;
		case 67: (void) printf("Illegal byte sequence.\n");
			break;
		default: (void) printf("RE error.\n");
			break;
		}
	} else {
		(void) printf("?\n");
	}
	return (-1);
}

static int
err(int prt, char msg[])
{
	if (prt) (prompt? (void) printf("%s\n", msg): (void) printf("?\n"));
	if (infildes != 0) {
		infildes = pop(fstack);
		charbuf = '\n';
		peeked = 0;
		flag3 = 0;
		flag2 = 0;
		flag = 0;
	}
	return (-1);
}

static char
mygetc()
{
	if (!peeked) {
		while ((!(infildes == oldfd && flag)) && (!flag1) &&
		    (!readc(infildes, &charbuf))) {
			if (infildes == 100 && (!flag)) flag1 = 1;
			if ((infildes = pop(fstack)) == -1) quit();
			if ((!flag1) && infildes == 0 && flag3 && prompt)
				(void) printf("*");
		}
		if (infildes == oldfd && flag) flag2 = 0;
		flag1 = 0;
	} else peeked = 0;
	return (charbuf);
}

static int
readc(int f, char *c)
{
	if (f == 100) {
		if (!(*c = *intptr++)) {
			intptr--;
			charbuf = '\n';
			return (0);
		}
	} else if (read(f, c, 1) != 1) {
		(void) close(f);
		charbuf = '\n';
		return (0);
	}
	return (1);
}

static int
percent(char line[256])
{
	char *lp, *var;
	char *front, *per, c[2], *olp, p[2], fr[256];
	int i, j;

	per = p;
	var = c;
	front = fr;
	j = 0;
	while (!j) {
		j = 1;
		olp = line;
		intptr = internal;
		while (step(olp, perbuf)) {
			while (loc1 < loc2) *front++ = *loc1++;
			*(--front) = '\0';
			front = fr;
			*per++ = '%';
			*per = '\0';
			per = p;
			*var = *loc2;
			if ((i = 1 + strlen(front)) >= 2 && fr[i-2] == '\\') {
				(void) strcat(front, "");
				--intptr;
				(void) strcat(per, "");
			} else {
				if (!(*var >= '0' && *var <= '9'))
					return (err(1, "usage: %digit"));
				(void) strcat(front, "");
				(void) strcat(varray[*var-'0'], "");
				j  = 0;
				loc2++;	/* Compensate for removing --lp above */
			}
			olp = loc2;
		}
		(void) strcat(olp, "");
		*intptr = '\0';
		if (!j) {
			intptr = internal;
			lp = line;
			(void)
			    strncpy(intptr, lp, sizeof (intptr)*sizeof (char));
		}
	}
	return (0);
}

static int
newfile(int prt, char f[])
{
	int fd;

	if (!*f) {
		if (flag != 0) {
			oldfd = infildes;
			intptr = comdlist;
		} else intptr = internal;
		fd = 100;
	} else if ((fd = open(f, 0)) < 0) {
		(void) snprintf(strtmp, sizeof (strtmp) * sizeof (char),
		    "cannot open %s", f);
		return (err(prt, strtmp));
	}

	push(fstack, infildes);
	if (flag4) oldfd = fd;
	infildes = fd;
	return (peeked = 0);
}

static void
push(int s[], int d)
{
	s[++s[0]] = d;
}

static int
pop(int s[])
{
	return (s[s[0]--]);
}

static int
peekc()
{
	int c;

	c = mygetc();
	peeked = 1;

	return (c);
}

static void
eat()
{
	if (charbuf != '\n')
		while (mygetc() != '\n');
	peeked = 0;
}

static int
more()
{
	if (mygetc() != '\n')
		return (err(1, "syntax"));
	return (0);
}

static void
quit()
{
	exit(0);
}

static void
out(char *ln)
{
	char *rp, *wp, prev;
	int w, width;
	char *oldrp;
	wchar_t cl;
	int p;
	ptrdiff_t lim;
	if (crunch > 0) {

		ln = untab(ln);
		rp = wp = ln - 1;
		prev = ' ';

		while (*++rp) {
			if (prev != ' ' || *rp != ' ')
				*++wp = *rp;
			prev = *rp;
		}
		*++wp = '\n';
		lim = (ptrdiff_t)wp - (ptrdiff_t)ln;
		*++wp = '\0';

		if (*ln == '\n')
			return;
	} else
		ln[lim = strlen(ln)] = '\n';

	if (MB_CUR_MAX <= 1) {
		if (lim > trunc)
			ln[lim = trunc] = '\n';
	} else {
		if ((trunc < (BFSBUF -1)) || (lim > trunc)) {
			w = 0;
			oldrp = rp = ln;
			/*CONSTCOND*/while (1) {
				if ((p = mbtowc(&cl, rp, MB_LEN_MAX)) == 0) {
					break;
				}
				if (p == -1) {
					width = p = 1;
				} else {
					width = scrwidth(cl);
					if (width == 0)
						width = 1;
				}
				if ((w += width) > trunc)
					break;
				rp += p;
			}
			*rp = '\n';
			lim = (ptrdiff_t)rp - (ptrdiff_t)oldrp;
		}
	}

	outcnt += write(outfildes, ln, lim+1);
}

static char *
untab(char l[])
{
	static char line[BFSBUF];
	char *q, *s;

	s = l;
	q = line;
	do {
		if (*s == '\t')
			do
				*q++ = ' ';
			while (((ptrdiff_t)q-(ptrdiff_t)line)%8);
		else *q++ = *s;
	} while (*s++);
	return (line);
}

/*
 *	Function to convert ascii string to integer.  Converts
 *	positive numbers only.  Returns -1 if non-numeric
 *	character encountered.
 */

static int
patoi(char *b)
{
	int i;
	char *a;

	a = b;
	i = 0;
	while (*a >= '0' && *a <= '9') i = 10 * i + *a++ - '0';

	if (*a)
		return (-1);
	return (i);
}

/*
 *	Compares 2 strings.  Returns 1 if equal, 0 if not.
 */

static int
equal(char *a, char *b)
{
	char *x, *y;

	x = a;
	y = b;
	while (*x == *y++)
		if (*x++ == 0)
			return (1);
	return (0);
}
