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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stropts.h>
#include <sys/eucioctl.h>
#ifndef PRESUNEUC
#include <locale.h>
/* Undef putchar/getchar if they're defined. */
#ifdef putchar
#	undef putchar
#endif
#ifdef getchar
#	undef getchar
#endif
#endif /* PRESUNEUC */

#include "ex.h"
#include "ex_re.h"
#include "ex_tty.h"
#include "ex_vis.h"

/*
 * Random routines, in alphabetical order.
 */

any(c, s)
	int c;
	register unsigned char *s;
{
	register int x;

	while (x = *s++)
		if (x == c)
			return (1);
	return (0);
}

backtab(i)
	register int i;
{
	register int j;

	j = i % value(vi_SHIFTWIDTH);
	if (j == 0)
		j = value(vi_SHIFTWIDTH);
	i -= j;
	if (i < 0)
		i = 0;
	return (i);
}

change()
{

	tchng++;
	chng = tchng;
}

/*
 * Column returns the number of
 * columns occupied by printing the
 * characters through position cp of the
 * current line.
 */
column(cp)
	register unsigned char *cp;
{

	if (cp == 0)
		cp = &linebuf[LBSIZE - 2];
	return (qcolumn(cp, (char *) 0));
}

/* lcolumn is same as column except it returns number of columns
 * occupied by characters before position
 * cp of the current line
 */
lcolumn(cp)
	register unsigned char *cp;
{

	if (cp == 0)
		cp = &linebuf[LBSIZE - 2];
	return(nqcolumn(lastchr(linebuf, cp), (char *)0));
}

/*
 * Ignore a comment to the end of the line.
 * This routine eats the trailing newline so don't call donewline().
 */
comment()
{
	register int c;

	do {
		c = getchar();
	} while (c != '\n' && c != EOF);
	if (c == EOF)
		ungetchar(c);
}

Copy(to, from, size)
	register unsigned char *from, *to;
	register int size;
{

	if (size > 0)
		do
			*to++ = *from++;
		while (--size > 0);
}

copyw(to, from, size)
	register line *from, *to;
	register int size;
{

	if (size > 0)
		do
			*to++ = *from++;
		while (--size > 0);
}

copywR(to, from, size)
	register line *from, *to;
	register int size;
{

	while (--size >= 0)
		to[size] = from[size];
}

ctlof(c)
	int c;
{

	return (c == DELETE ? '?' : c | ('A' - 1));
}

dingdong()
{

	if (flash_screen && value(vi_FLASH))
		putpad(flash_screen);
	else if (value(vi_ERRORBELLS))
		putpad(bell);
}

fixindent(indent)
	int indent;
{
	register int i;
	register unsigned char *cp;

	i = whitecnt(genbuf);
	cp = vpastwh(genbuf);
	if (*cp == 0 && i == indent && linebuf[0] == 0) {
		genbuf[0] = 0;
		return (i);
	}
	CP(genindent(i), cp);
	return (i);
}

filioerr(cp)
	unsigned char *cp;
{
	register int oerrno = errno;

	lprintf("\"%s\"", cp);
	errno = oerrno;
	syserror(1);
}

unsigned char *
genindent(indent)
	register int indent;
{
	register unsigned char *cp;

	for (cp = genbuf; indent >= value(vi_TABSTOP); indent -= value(vi_TABSTOP))
		*cp++ = '\t';
	for (; indent > 0; indent--)
		*cp++ = ' ';
	return (cp);
}

getDOT()
{

	getline(*dot);
}

line *
getmark(c)
	register int c;
{
	register line *addr;
	
	for (addr = one; addr <= dol; addr++)
		if (names[c - 'a'] == (*addr &~ 01)) {
			return (addr);
		}
	return (0);
}

getn(cp)
	register unsigned char *cp;
{
	register int i = 0;

	while (isdigit(*cp))
		i = i * 10 + *cp++ - '0';
	if (*cp)
		return (0);
	return (i);
}

ignnEOF()
{
	register int c = getchar();

	if (c == EOF)
		ungetchar(c);
	else if (c=='"')
		comment();
}

iswhite(c)
	int c;
{

	return (c == ' ' || c == '\t');
}

junk(c)
	register wchar_t c;
{

	if (c && !value(vi_BEAUTIFY))
		return (0);
	if (c >= ' ' && c != DELETE)
		return (0);
	switch (c) {

	case '\t':
	case '\n':
	case '\f':
		return (0);

	default:
		return (1);
	}
}

killed()
{

	killcnt(addr2 - addr1 + 1);
}

killcnt(cnt)
	register int cnt;
{
	extern char *verbalize();

	if (inopen) {
		notecnt = cnt;
		notenam = notesgn = (unsigned char *)"";
		return;
	}
	if (!notable(cnt))
		return;
	if (value(vi_TERSE) == 0) {
		verbalize(cnt, Command, "");
	} else {
		if (cnt == 1) {
			printf(gettext("1 line"), cnt);
		} else {
			printf(gettext("%d lines"), cnt);
		}
	}
	putNFL();
}

lineno(a)
	line *a;
{

	return (a - zero);
}

lineDOL()
{

	return (lineno(dol));
}

lineDOT()
{

	return (lineno(dot));
}

markDOT()
{

	markpr(dot);
}

markpr(which)
	line *which;
{

	if ((inglobal == 0 || inopen) && which <= endcore) {
		names['z'-'a'+1] = *which & ~01;
		if (inopen)
			ncols['z'-'a'+1] = cursor;
	}
}

markreg(c)
	register int c;
{

	if (c == '\'' || c == '`')
		return ('z' + 1);
	if (c >= 'a' && c <= 'z')
		return (c);
	return (0);
}

/*
 * Mesg decodes the terse/verbose strings. Thus
 *	'xxx@yyy' -> 'xxx' if terse, else 'xxx yyy'
 *	'xxx|yyy' -> 'xxx' if terse, else 'yyy'
 * All others map to themselves.
 */
/*
 * The feature described above was disabled for localizable messaging.
 */
unsigned char *
mesg(str)
	register unsigned char *str;
{
	register unsigned char *cp;

	str = (unsigned char *)strcpy(genbuf, str);
	/* commented out for localizable messaging */
/*	for (cp = str; *cp; cp++)
		switch (*cp) {

		case '@':
			if (value(vi_TERSE))
				*cp = 0;
			else
				*cp = ' ';
			break;

		case '|':
			if (value(vi_TERSE) == 0)
				return (cp + 1);
			*cp = 0;
			break;
		}	*/
	return (str);
}

/*VARARGS2*/
merror(seekpt, i)
	unsigned char *seekpt;
	int i;
{
	register unsigned char *cp = linebuf;

	if (seekpt == 0)
		return;
	merror1(seekpt);
	if (*cp == '\n')
		putnl(), cp++;
	if (inopen > 0 && clr_eol)
		vclreol();
	if (enter_standout_mode && exit_bold)
		putpad(enter_standout_mode);
#ifdef PRESUNEUC
	printf(mesg(cp), i);
#else
	printf((char *)mesg(cp), i);
#endif /* PRESUNEUC */
	if (enter_standout_mode && exit_bold)
		putpad(exit_bold);
}

merror1(seekpt)
	unsigned char *seekpt;
{

	strcpy(linebuf, seekpt);
}

#define MAXDATA (56*1024)
morelines()
{
	register unsigned char *end;

	if ((int) sbrk(1024 * sizeof (line)) == -1) {
		if (endcore >= (line *) MAXDATA)
			return -1;
		end = (unsigned char *) MAXDATA;
		/*
		 * Ask for end+2 sice we want end to be the last used location.
		 */
		while (brk(end+2) == -1)
			end -= 64;
		if (end <= (unsigned char *) endcore)
			return -1;
		endcore = (line *) end;
	} else {
		endcore += 1024;
	}
	return (0);
}

nonzero()
{

	if (addr1 == zero) {
		notempty();
		error(value(vi_TERSE) ? gettext("Nonzero address required") :
gettext("Nonzero address required on this command"));
	}
}

notable(i)
	int i;
{

	return (hush == 0 && !inglobal && i > value(vi_REPORT));
}


notempty()
{

	if (dol == zero)
		error(value(vi_TERSE) ? gettext("No lines") :
gettext("No lines in the buffer"));
}


netchHAD(cnt)
	int cnt;
{

	netchange(lineDOL() - cnt);
}

netchange(i)
	register int i;
{
	register unsigned char *cp;

	if (i > 0)
		notesgn = cp = (unsigned char *)"more ";
	else
		notesgn = cp = (unsigned char *)"fewer ", i = -i;
	if (inopen) {
		notecnt = i;
		notenam = (unsigned char *)"";
		return;
	}
	if (!notable(i))
		return;
	if (*cp == 'm')	/* for ease of messge localization */
#ifdef PRESUNEUC
		printf(mesg(value(vi_TERSE) ?
#else
		printf((char *)mesg(value(vi_TERSE) ?
#endif /* PRESUNEUC */
gettext("%d more lines") :
		/*
		 * TRANSLATION_NOTE
		 *	Reference order of arguments must not
		 *	be changed using '%digit$', since vi's
		 *	printf() does not support it.
		 */
gettext("%d more lines in file after %s")), i, Command);
	else
#ifdef PRESUNEUC
		printf(mesg(value(vi_TERSE) ?
#else
		printf((char *)mesg(value(vi_TERSE) ?
#endif /* PRESUNEUC */
gettext("%d fewer lines") :
		/*
		 * TRANSLATION_NOTE
		 *	Reference order of arguments must not
		 *	be changed using '%digit$', since vi's
		 *	printf() does not support it.
		 */
gettext("%d fewer lines in file after %s")), i, Command);
	putNFL();
}

putmark(addr)
	line *addr;
{

	putmk1(addr, putline());
}

putmk1(addr, n)
	register line *addr;
	int n;
{
	register line *markp;
	register oldglobmk;

	oldglobmk = *addr & 1;
	*addr &= ~1;
	for (markp = (anymarks ? names : &names['z'-'a'+1]);
	  markp <= &names['z'-'a'+1]; markp++)
		if (*markp == *addr)
			*markp = n;
	*addr = n | oldglobmk;
}

unsigned char *
plural(i)
	long i;
{

	return (i == 1 ? (unsigned char *)"" : (unsigned char *)"s");
}

int	qcount();
short	vcntcol;

qcolumn(lim, gp)
	register unsigned char *lim, *gp;
{
	register int x, length;
	int	col;
	wchar_t wchar;
	int (*OO)();

	OO = Outchar;
	Outchar = qcount;
	vcntcol = 0;
	if (lim != NULL) {
		if(lim == linebuf - 1 || lim == &linebuf[LBSIZE-2])
			length = 1;
		else
			length = mbtowc(&wchar, (char *)lim, MULTI_BYTE_MAX);
		if(length < 0)
			length = 1;
		x = lim[length]; 
		lim[length] = 0;
	}
	pline(0);
	if (lim != NULL)
		lim[length] = x;
	if(length > 1 && !gp) {
		/* put cursor at beginning of multibyte character */
		if ((col = wcwidth(wchar)) < 0)
			col = 0;
		vcntcol = vcntcol - col + 1;
	}
 	if (gp)
		while (*gp) {
			length = mbtowc(&wchar, (char *)gp, MULTI_BYTE_MAX);
			if(length < 0) {
				putoctal = 1;
				putchar(*gp++);
				putoctal = 0;
			} else {
				putchar(wchar);
				gp += length;
			}
		}
	Outchar = OO;
	return (vcntcol);
}

/* This routine puts cursor after multibyte character */
nqcolumn(lim, gp)
	register unsigned char *lim, *gp;
{
	register int x, length;
	wchar_t wchar;
	int (*OO)();

	OO = Outchar;
	Outchar = qcount;
	vcntcol = 0;
	if (lim != NULL) {
		if(lim == linebuf - 1 || lim == &linebuf[LBSIZE-2])
			length = 1;
		else
			length = mbtowc(&wchar, (char *)lim, MULTI_BYTE_MAX);
		if(length < 0)
			length = 1;
		x = lim[length]; 
		lim[length] = 0;
	}
	pline(0);
	if (lim != NULL)
		lim[length] = x;
 	if (gp)
		while (*gp) {
			length = mbtowc(&wchar, (char *)gp, MULTI_BYTE_MAX);
			if(length < 0) {
				putoctal = 1;
				putchar(*gp++);
				putoctal = 0;
			} else {
				putchar(wchar);
				gp += length;
			}
		}
	Outchar = OO;
	return (vcntcol);
}

int
qcount(c)
wchar_t c;
{
	register int cols;
#ifndef PRESUNEUC
	register int remcols;
	register short OWCOLS;
#endif /* PRESUNEUC */

	if (c == '\t') {
		vcntcol += value(vi_TABSTOP) - vcntcol % value(vi_TABSTOP);
		return;
	}
#ifdef PRESUNEUC
	if ((cols = wcwidth(c)) > 0)
		vcntcol += cols;
#else
	if ((cols = wcwidth(c)) < 0)
		cols = 0;
	OWCOLS = WCOLS;
	if (WCOLS == 0)
		WCOLS = columns;
	if ((mc_wrap) == 1 && (remcols = (WCOLS - (vcntcol % WCOLS))) < cols)
		vcntcol += remcols;
	WCOLS = OWCOLS;
	vcntcol += cols;
#endif /* PRESUNEUC */
}

reverse(a1, a2)
	register line *a1, *a2;
{
	register line t;

	for (;;) {
		t = *--a2;
		if (a2 <= a1)
			return;
		*a2 = *a1;
		*a1++ = t;
	}
}

save(a1, a2)
	line *a1;
	register line *a2;
{
	register int more;

	if (!FIXUNDO)
		return;
#ifdef UNDOTRACE
	if (trace)
		vudump("before save");
#endif
	undkind = UNDNONE;
	undadot = dot;
	more = (a2 - a1 + 1) - (unddol - dol);
	while (more > (endcore - truedol))
		if (morelines() < 0)
			error(value(vi_TERSE) ? gettext("Out of memory") :
gettext("Out of memory saving lines for undo - try using ed"));
	if (more)
		(*(more > 0 ? copywR : copyw))(unddol + more + 1, unddol + 1,
		    (truedol - unddol));
	unddol += more;
	truedol += more;
	copyw(dol + 1, a1, a2 - a1 + 1);
	undkind = UNDALL;
	unddel = a1 - 1;
	undap1 = a1;
	undap2 = a2 + 1;
#ifdef UNDOTRACE
	if (trace)
		vudump("after save");
#endif
}

save12()
{

	save(addr1, addr2);
}

saveall()
{

	save(one, dol);
}

span()
{

	return (addr2 - addr1 + 1);
}

sync()
{

	chng = 0;
	tchng = 0;
	xchng = 0;
}


skipwh()
{
	register int wh;

	wh = 0;
	while (iswhite(peekchar())) {
		wh++;
		ignchar();
	}
	return (wh);
}

/*VARARGS2*/
smerror(seekpt, cp)
	unsigned char *seekpt;
	unsigned char *cp;
{

	errcnt++;
	merror1(seekpt);
	if (inopen && clr_eol)
		vclreol();
	if (enter_standout_mode && exit_bold)
		putpad(enter_standout_mode);
	lprintf(mesg(linebuf), cp);
	if (enter_standout_mode && exit_bold)
		putpad(exit_bold);
}

unsigned char *
strend(cp)
	register unsigned char *cp;
{

	while (*cp)
		cp++;
	return (cp);
}

strcLIN(dp)
	unsigned char *dp;
{

	CP(linebuf, dp);
}

/*
 * A system error has occurred that we need to perror.
 * danger is true if we are unsure of the contents of
 * the file or our buffer, e.g. a write error in the
 * middle of a write operation, or a temp file error.
 */
syserror(danger)
int danger;
{
	register int e = errno;
	char *errstr;
	extern char *strerror();

	dirtcnt = 0;
	putchar(' ');
	if (danger)
		edited = 0;	/* for temp file errors, for example */
	if ((errstr = strerror(e)) != NULL)
		error(errstr);
	else
		error(gettext("System error %d"), e);
}

/*
 * Return the column number that results from being in column col and
 * hitting a tab, where tabs are set every ts columns.  Work right for
 * the case where col > columns, even if ts does not divide columns.
 */
tabcol(col, ts)
int col, ts;
{
	int offset, result;

	if (col >= columns) {
		offset = columns * (col/columns);
		col -= offset;
	} else
		offset = 0;
	result = col + ts - (col % ts) + offset;
	return (result);
}

unsigned char *
vfindcol(i)
	int i;
{
	register unsigned char *cp, *oldcp;
	register int (*OO)() = Outchar;
	register int length;
	unsigned char x;
	wchar_t wchar;

	Outchar = qcount;
	(void)qcolumn(linebuf - 1, NOSTR);
	for (cp = linebuf; *cp && vcntcol < i; ) {
		oldcp = cp;
		length = mbtowc(&wchar, (char *)cp, MULTI_BYTE_MAX);
		if(length < 0) {
			putoctal = 1;
			putchar(*cp++);
			putoctal = 0;
		} else {
			putchar(wchar);
			cp += length;
		}
	}
	if (cp != linebuf)
		cp = oldcp;
	Outchar = OO;
	return (cp);
}

unsigned char *
vskipwh(cp)
	register unsigned char *cp;
{

	while (iswhite(*cp) && cp[1])
		cp++;
	return (cp);
}


unsigned char *
vpastwh(cp)
	register unsigned char *cp;
{

	while (iswhite(*cp))
		cp++;
	return (cp);
}

whitecnt(cp)
	register unsigned char *cp;
{
	register int i;

	i = 0;
	for (;;)
		switch (*cp++) {

		case '\t':
			i += value(vi_TABSTOP) - i % value(vi_TABSTOP);
			break;

		case ' ':
			i++;
			break;

		default:
			return (i);
		}
}

markit(addr)
	line *addr;
{

	if (addr != dot && addr >= one && addr <= dol)
		markDOT();
}

/*
 * The following code is defensive programming against a bug in the
 * pdp-11 overlay implementation.  Sometimes it goes nuts and asks
 * for an overlay with some garbage number, which generates an emt
 * trap.  This is a less than elegant solution, but it is somewhat
 * better than core dumping and losing your work, leaving your tty
 * in a weird state, etc.
 */
int _ovno;

/*ARGSUSED*/
void 
onemt(sig)
int sig;
{
	int oovno;

	signal(SIGEMT, onemt);
	oovno = _ovno;
	/* 2 and 3 are valid on 11/40 type vi, so */
	if (_ovno < 0 || _ovno > 3)
		_ovno = 0;
	error(value(vi_TERSE) ? gettext("emt trap, _ovno is %d ") :
gettext("emt trap, _ovno is %d   - try again"));
}

/*
 * When a hangup occurs our actions are similar to a preserve
 * command.  If the buffer has not been [Modified], then we do
 * nothing but remove the temporary files and exit.
 * Otherwise, we sync the temp file and then attempt a preserve.
 * If the preserve succeeds, we unlink our temp files.
 * If the preserve fails, we leave the temp files as they are
 * as they are a backup even without preservation if they
 * are not removed.
 */

/*ARGSUSED*/
void 
onhup(sig)
int sig;
{

	/*
	 * USG tty driver can send multiple HUP's!!
	 */
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	if (chng == 0) {
		cleanup(1);
		exit(++errcnt);
	}
	if (setexit() == 0) {
		if (preserve()) {
			cleanup(1);
			exit(++errcnt);
		}
	}
	if (kflag)
		crypt_close(perm);
	if (xtflag)
		crypt_close(tperm);
	exit(++errcnt);
}

/*
 * Similar to onhup.  This happens when any random core dump occurs,
 * e.g. a bug in vi.  We preserve the file and then generate a core.
 */
void oncore(sig)
int sig;
{
	static int timescalled = 0;
	char *messagep;	/* for message localization */

	/*
	 * USG tty driver can send multiple HUP's!!
	 */
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(sig, SIG_DFL);	/* Insure that we don't catch it again */
	messagep = (char *)gettext("\r\nYour file has been preserved\r\n");
	if (timescalled++ == 0 && chng && setexit() == 0) {
		if (inopen)
			vsave();
		preserve();
		write(1, messagep, strlen(messagep));
	}
	if (timescalled < 2) {
		normal(normf);
		cleanup(2);
		kill(getpid(), sig);	/* Resend ourselves the same signal */
		/* We won't get past here */
	}
	if (kflag)
		crypt_close(perm);
	if (xtflag)
		crypt_close(tperm);
	exit(++errcnt);
}

/*
 * An interrupt occurred.  Drain any output which
 * is still in the output buffering pipeline.
 * Catch interrupts again.  Unless we are in visual
 * reset the output state (out of -nl mode, e.g).
 * Then like a normal error (with the \n before Interrupt
 * suppressed in visual mode).
 */

/*ARGSUSED*/
void 
onintr(sig)
int sig;
{
#ifndef CBREAK
	signal(SIGINT, onintr);
#else
	signal(SIGINT, inopen ? vintr : onintr);
#endif
	cancelalarm();
	draino();
	if (!inopen) {
		pstop();
		setlastchar('\n');
#ifdef CBREAK
	}
#else
	} else
		vraw();
#endif
	error(gettext("\nInterrupt") + (inopen!=0));
}

/*
 * If we are interruptible, enable interrupts again.
 * In some critical sections we turn interrupts off,
 * but not very often.
 */
setrupt()
{

	if (ruptible) {
#ifndef CBREAK
		signal(SIGINT, onintr);
#else
		signal(SIGINT, inopen ? vintr : onintr);
#endif
#ifdef SIGTSTP
		if (dosusp)
			signal(SIGTSTP, onsusp);
#endif
	}
}

preserve()
{

#ifdef VMUNIX
	tflush();
#endif
	synctmp();
	pid = fork();
	if (pid < 0)
		return (0);
	if (pid == 0) {
		close(0);
		dup(tfile);
		execlp(EXPRESERVE, "expreserve", (char *) 0);
		exit(++errcnt);
	}
	waitfor();
	if (rpid == pid && status == 0)
		return (1);
	return (0);
}

#ifndef V6
void exit(i)
	int i;
{

#ifdef TRACE
	if (trace)
		fclose(trace);
#endif
	_exit(i);
}
#endif

#ifdef SIGTSTP
/*
 * We have just gotten a susp.  Suspend and prepare to resume.
 */
extern void redraw();

/*ARGSUSED*/
void 
onsusp(sig)
int sig;
{
	ttymode f;
	int savenormtty;

	f = setty(normf);
	vnfl();
	putpad(exit_ca_mode);
	flush();
	resetterm();
	savenormtty = normtty;
	normtty = 0;

	signal(SIGTSTP, SIG_DFL);
	kill(0, SIGTSTP);

	/* the pc stops here */

	signal(SIGTSTP, onsusp);
	normtty = savenormtty;
	vcontin(0);
	flush();
	setty(f);
	if (!inopen)
		error(0);
	else {
		if(vcnt < 0) {
			vcnt = -vcnt;
			if(state == VISUAL)
				vclear();
			else if(state == CRTOPEN)
				vcnt = 0;
		}
		vdirty(0, lines);
		if (sig)
			vrepaint(cursor);
	}	
}
#endif

unsigned char *nextchr(cursor)
unsigned char *cursor;
{

	wchar_t wchar;
	int length;
	length = mbtowc(&wchar, (char *)cursor, MULTI_BYTE_MAX);
	if(length <= 0)
		return(++cursor);
	return(cursor + length);
}

unsigned char *lastchr(linebuf, cursor)
unsigned char *linebuf, *cursor;
{
	wchar_t wchar;
	int length;
	unsigned char *ccursor, *ocursor;
	if(cursor == linebuf)
		return(linebuf - 1);
	ccursor = ocursor = linebuf;
	while(ccursor < cursor) {
		length = mbtowc(&wchar, (char *)ccursor, MULTI_BYTE_MAX);
		ocursor =  ccursor;
		if(length <= 0)
			ccursor++;
		else
			ccursor += length;
	}
	return(ocursor);
}		 	

ixlatctl(flag)
	int flag;
{
	static struct strioctl sb = {0, 0, 0, 0};

	if (!(MULTI_BYTE_MAX > 1))
		return (0);

	switch (flag) {
	case 0:
		sb.ic_cmd = EUC_MSAVE;
		sb.ic_len = 0;
		sb.ic_dp = 0;
		if (ioctl(0, I_STR, &sb) < 0)
			return (-1);
		return (0);
	case 1:
		sb.ic_cmd = EUC_MREST;
		sb.ic_len = 0;
		sb.ic_dp = 0;
		if (ioctl(0, I_STR, &sb) < 0)
			return (-1);
		return (0);
	case 11:
		return (0);
	default:
		return (-1);
	}
}
#ifndef PRESUNEUC

/* locale specific initialization */
int localize()
{
	wchar_t fillerchar;
	extern int	wdchkind();
	extern int	wdbindf();
	extern wchar_t	*wddelim();
	extern wchar_t	mcfiller();

	wdwc = wdchkind;
	wdbdg = wdbindf;
	wddlm = wddelim;
	mcfllr = mcfiller;
	mc_wrap = 1;
	fillerchar = mcfiller();
	mc_filler = isascii(fillerchar) ? (fillerchar & 0x7f) : '~';
}
#endif /* PRESUNEUC */
