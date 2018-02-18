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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_tty.h"
#include "ex_vis.h"

/*
 * Input routines for open/visual.
 * We handle upper case only terminals in visual and reading from the
 * echo area here as well as notification on large changes
 * which appears in the echo area.
 */

/*
 * Return the key.
 */
void
ungetkey(int c)
{

	if (Peekkey != ATTN)
		Peekkey = c;
}

/*
 * Return a keystroke, but never a ^@.
 */
int
getkey(void)
{
	int c;		/* char --> int */

	do {
		c = getbr();
		if (c==0)
			(void) beep();
	} while (c == 0);
	return (c);
}

/*
 * Tell whether next keystroke would be a ^@.
 */
int
peekbr(void)
{

	Peekkey = getbr();
	return (Peekkey == 0);
}

short	precbksl;

/*
 * Get a keystroke, including a ^@.
 * If an key was returned with ungetkey, that
 * comes back first.  Next comes unread input (e.g.
 * from repeating commands with .), and finally new
 * keystrokes.
 *
 * The hard work here is in mapping of \ escaped
 * characters on upper case only terminals.
 */
int
getbr(void)
{
	unsigned char ch;
	int c, d;
	unsigned char *colp;
	int cnt;
	static unsigned char Peek2key;
	extern short slevel, ttyindes;

getATTN:
	if (Peekkey) {
		c = Peekkey;
		Peekkey = 0;
		return (c);
	}
	if (Peek2key) {
		c = Peek2key;
		Peek2key = 0;
		return (c);
	}
	if (vglobp) {
		if (*vglobp)
			return (lastvgk = *vglobp++);
		lastvgk = 0;
		return (ESCAPE);
	}
	if (vmacp) {
		if (*vmacp)
			return(*vmacp++);
		/* End of a macro or set of nested macros */
		vmacp = 0;
		if (inopen == -1)	/* don't mess up undo for esc esc */
			vundkind = VMANY;
		inopen = 1;	/* restore old setting now that macro done */
		vch_mac = VC_NOTINMAC;
	}
	flusho();
again:
	if ((c=read(slevel == 0 ? 0 : ttyindes, &ch, 1)) != 1) {
		if (errno == EINTR)
			goto getATTN;
		else if (errno == EIO)
		  kill(getpid(), SIGHUP);

		error(gettext("Input read error"));
	}
	c = ch;
	if (beehive_glitch && slevel==0 && c == ESCAPE) {
		if (read(0, &Peek2key, 1) != 1)
			goto getATTN;
		switch (Peek2key) {
		case 'C':	/* SPOW mode sometimes sends \EC for space */
			c = ' ';
			Peek2key = 0;
			break;
		case 'q':	/* f2 -> ^C */
			c = CTRL('c');
			Peek2key = 0;
			break;
		case 'p':	/* f1 -> esc */
			Peek2key = 0;
			break;
		}
	}

	/*
	 * The algorithm here is that of the UNIX kernel.
	 * See the description in the programmers manual.
	 */
	if (UPPERCASE) {
		if (isupper(c))
			c = tolower(c);
		if (c == '\\') {
			if (precbksl < 2)
				precbksl++;
			if (precbksl == 1)
				goto again;
		} else if (precbksl) {
			d = 0;
			if (islower(c))
				d = toupper(c);
			else {
				colp = (unsigned char *)"({)}!|^~'~";
				while (d = *colp++)
					if (d == c) {
						d = *colp++;
						break;
					} else
						colp++;
			}
			if (precbksl == 2) {
				if (!d) {
					Peekkey = c;
					precbksl = 0;
					c = '\\';
				}
			} else if (d)
				c = d;
			else {
				Peekkey = c;
				precbksl = 0;
				c = '\\';
			}
		}
		if (c != '\\')
			precbksl = 0;
	}
#ifdef TRACE
	if (trace) {
		if (!techoin) {
			tfixnl();
			techoin = 1;
			fprintf(trace, "*** Input: ");
		}
		tracec(c);
	}
#endif
	lastvgk = 0;
	return (c);
}

/*
 * Get a key, but if a delete, quit or attention
 * is typed return 0 so we will abort a partial command.
 */
int
getesc(void)
{
	int c;

	c = getkey();
	switch (c) {

	case CTRL('v'):
	case CTRL('q'):
		c = getkey();
		return (c);

	case ATTN:
	case QUIT:
		ungetkey(c);
		return (0);

	case ESCAPE:
		return (0);
	}
	return (c);
}

/*
 * Peek at the next keystroke.
 */
int
peekkey(void)
{

	Peekkey = getkey();
	return (Peekkey);
}

/*
 * Read a line from the echo area, with single character prompt c.
 * A return value of 1 means the user blewit or blewit away.
 */
int
readecho(c)
	unsigned char c;
{
	unsigned char *sc = cursor;
	int (*OP)();
	bool waste;
	int OPeek;

	if (WBOT == WECHO)
		vclean();
	else
		vclrech(0);
	splitw++;
	vgoto(WECHO, 0);
	putchar(c);
	vclreol();
	vgoto(WECHO, 1);
	cursor = linebuf; linebuf[0] = 0; genbuf[0] = c;
	ixlatctl(1);
	if (peekbr()) {
		if (!INS[0] || (unsigned char)INS[128] == 0200) {
			INS[128] = 0;
			goto blewit;
		}
		vglobp = INS;
	}
	OP = Pline; Pline = normline;
	(void)vgetline(0, genbuf + 1, &waste, c);
	doomed = 0;	/* don't care about doomed characters in echo line */
	ixlatctl(0);
	if (Outchar == termchar)
		putchar('\n');
	vscrap();
	Pline = OP;
	if (Peekkey != ATTN && Peekkey != QUIT && Peekkey != CTRL('h')) {
		cursor = sc;
		vclreol();
		return (0);
	}
blewit:
	OPeek = Peekkey==CTRL('h') ? 0 : Peekkey; Peekkey = 0;
	splitw = 0;
	vclean();
	vshow(dot, NOLINE);
	vnline(sc);
	Peekkey = OPeek;
	return (1);
}

/*
 * A complete command has been defined for
 * the purposes of repeat, so copy it from
 * the working to the previous command buffer.
 */
void
setLAST(void)
{

	if (vglobp || vmacp)
		return;
	lastreg = vreg;
	lasthad = Xhadcnt;
	lastcnt = Xcnt;
	*lastcp = 0;
	CP(lastcmd, workcmd);
}

/*
 * Gather up some more text from an insert.
 * If the insertion buffer oveflows, then destroy
 * the repeatability of the insert.
 */
void
addtext(unsigned char *cp)
{

	if (vglobp)
		return;
	addto(INS, cp);
	if ((unsigned char)INS[128] == 0200)
		lastcmd[0] = 0;
}

void
setDEL(void)
{

	setBUF(DEL);
}

/*
 * Put text from cursor upto wcursor in BUF.
 */
void
setBUF(unsigned char *BUF)
{
	int c;
	unsigned char *wp = wcursor;

	c = *wp;
	*wp = 0;
	BUF[0] = 0;
	BUF[128] = 0;
	addto(BUF, cursor);
	*wp = c;
}

void
addto(unsigned char *buf, unsigned char *str)
{

	if ((unsigned char)buf[128] == 0200)
		return;
	if (strlen(buf) + strlen(str) + 1 >= VBSIZE) {
		buf[128] = 0200;
		return;
	}
	(void)strcat(buf, str);
	buf[128] = 0;
}

/*
 * Verbalize command name and embed it in message.
 */
char *
verbalize(cnt, cmdstr, sgn)
int cnt;
char *cmdstr, *sgn;
{
	if (cmdstr[0] == '\0')
		cmdstr = (char *)Command;
	if (sgn[0] == '\0') {
		switch (cmdstr[0]) {
		    case 'c':
			if (cmdstr[1] == 'h') {
				viprintf((cnt == 1) ?
				    gettext("1 line changed") :
				    gettext("%d lines changed"), cnt);
				break;
			} else if (cmdstr[1] != 'o') {
				goto Default;
			}
			/* FALLTHROUGH */
		    case 't':
			if (cmdstr[1] != '\0')
				goto Default;
			viprintf((cnt == 1) ? gettext("1 line copied") :
			       gettext("%d lines copied"), cnt);
			break;
		    case 'd':
			viprintf((cnt == 1) ? gettext("1 line deleted") :
			       gettext("%d lines deleted"), cnt);
			break;
		    case 'j':
			viprintf((cnt == 1) ? gettext("1 line joined") :
			       gettext("%d lines joined"), cnt);
			break;
		    case 'm':
			viprintf((cnt == 1) ? gettext("1 line moved") :
			       gettext("%d lines moved"), cnt);
			break;
		    case 'p':
			viprintf((cnt == 1) ? gettext("1 line put") :
			       gettext("%d lines put"), cnt);
			break;
		    case 'y':
			viprintf((cnt == 1) ? gettext("1 line yanked") :
			       gettext("%d lines yanked"), cnt);
			break;
		    case '>':
			viprintf((cnt == 1) ? gettext("1 line >>ed") :
			       gettext("%d lines >>ed"), cnt);
			break;
		    case '=':
			viprintf((cnt == 1) ? gettext("1 line =ed") :
			       gettext("%d lines =ed"), cnt);
			break;
		    case '<':
			viprintf((cnt == 1) ? gettext("1 line <<ed") :
			       gettext("%d lines <<ed"), cnt);
			break;
		    default:
Default:
			viprintf((cnt == 1) ? gettext("1 line") :
			       gettext("%d lines"), cnt);
			break;
		}
	} else if (sgn[0] == 'm') {
		viprintf((cnt == 1) ? gettext("1 more line") :
			gettext("%d more lines"), cnt);
	} else {
		viprintf((cnt == 1) ? gettext("1 fewer line") :
			gettext("%d fewer lines"), cnt);
	}
	return (NULL);
}

/*
 * Note a change affecting a lot of lines, or non-visible
 * lines.  If the parameter must is set, then we only want
 * to do this for open modes now; return and save for later
 * notification in visual.
 */
int
noteit(must)
	bool must;
{
	int sdl = destline, sdc = destcol;

	if (notecnt < 1 || !must && state == VISUAL)
		return (0);
	splitw++;
	if (WBOT == WECHO)
		vmoveitup(1, 1);
	vigoto(WECHO, 0);

	verbalize(notecnt, notenam, notesgn);
	vclreol();
	notecnt = 0;
	if (state != VISUAL)
		vcnt = vcline = 0;
	splitw = 0;
	if (state == ONEOPEN || state == CRTOPEN)
		vup1();
	destline = sdl; destcol = sdc;
	return (1);
}

/*
 * Ring or beep.
 * If possible, flash screen.
 */
int
beep(void)
{

	if (flash_screen && value(vi_FLASH))
		vputp(flash_screen, 0);
	else if (bell)
		vputp(bell, 0);
	return (0);
}

/*
 * Map the command input character c,
 * for keypads and labelled keys which do cursor
 * motions.  I.e. on an adm3a we might map ^K to ^P.
 * DM1520 for example has a lot of mappable characters.
 */

int
map(c, maps, commch)
	int c;
	struct maps *maps;
	unsigned char commch; /* indicate if in append/insert/replace mode */
{
	int d;
	unsigned char *p, *q;
	unsigned char b[10];	/* Assumption: no keypad sends string longer than 10 */
	unsigned char *st;

	/*
	 * Mapping for special keys on the terminal only.
	 * BUG: if there's a long sequence and it matches
	 * some chars and then misses, we lose some chars.
	 *
	 * For this to work, some conditions must be met.
	 * 1) Keypad sends SHORT (2 or 3 char) strings
	 * 2) All strings sent are same length & similar
	 * 3) The user is unlikely to type the first few chars of
	 *    one of these strings very fast.
	 * Note: some code has been fixed up since the above was laid out,
	 * so conditions 1 & 2 are probably not required anymore.
	 * However, this hasn't been tested with any first char
	 * that means anything else except escape.
	 */
#ifdef MDEBUG
	if (trace)
		fprintf(trace,"map(%c): ",c);
#endif
	/*
	 * If c==0, the char came from getesc typing escape.  Pass it through
	 * unchanged.  0 messes up the following code anyway.
	 */
	if (c==0)
		return(0);

	b[0] = c;
	b[1] = 0;
	for (d=0; d < MAXNOMACS && maps[d].mapto; d++) {
#ifdef MDEBUG
		if (trace)
			fprintf(trace,"\ntry '%s', ",maps[d].cap);
#endif
		if (p = maps[d].cap) {
			for (q=b; *p; p++, q++) {
#ifdef MDEBUG
				if (trace)
					fprintf(trace,"q->b[%d], ",q-b);
#endif
				if (*q==0) {
					/*
					 * Is there another char waiting?
					 *
					 * This test is oversimplified, but
					 * should work mostly. It handles the
					 * case where we get an ESCAPE that
					 * wasn't part of a keypad string.
					 */
					if ((c=='#' ? peekkey() : fastpeekkey()) == 0) {
#ifdef MDEBUG
						if (trace)
							fprintf(trace,"fpk=0: will return '%c'",c);
#endif
						/*
						 * Nothing waiting.  Push back
						 * what we peeked at & return
						 * failure (c).
						 *
						 * We want to be able to undo
						 * commands, but it's nonsense
						 * to undo part of an insertion
						 * so if in input mode don't.
						 */
#ifdef MDEBUG
						if (trace)
							fprintf(trace, "Call macpush, b %d %d %d\n", b[0], b[1], b[2]);
#endif
						macpush(&b[1],maps == arrows);
#ifdef MDEBUG
						if (trace)
							fprintf(trace, "return %d\n", c);	
#endif
						return(c);
					}
					*q = getkey();
					q[1] = 0;
				}
				if (*p != *q)
					goto contin;
			}
			macpush(maps[d].mapto,maps == arrows);
			/*
			 * For all macros performed within insert,
			 * append, or replacement mode, we must end
			 * up returning back to that mode when we
			 * return (except that append will become
			 * insert for <home> key, so cursor is not
			 * in second column).
			 *
			 * In order to preserve backward movement
			 * when leaving insert mode, an 'l' must be
			 * done to compensate for the left done by
			 * the <esc> (except when cursor is already
			 * in the first column: i.e., outcol = 0).
			 */
			 if ((maps == immacs) 
			 && strcmp(maps[d].descr, maps[d].cap)) {
				switch (commch) {
				  case 'R':
					if (!strcmp(maps[d].descr, "home"))
						st = (unsigned char *)"R";
					else
						if (outcol == 0)
							st = (unsigned char *)"R";
						else
							st = (unsigned char *)"lR"; 
					break;
				  case 'i':
					if (!strcmp(maps[d].descr, "home"))
						st = (unsigned char *)"i";
					else
						if (outcol == 0)
							st = (unsigned char *)"i";
						else
							st = (unsigned char *)"li"; 
					break;
				  case 'a':
					if (!strcmp(maps[d].descr, "home"))
						st = (unsigned char *)"i";
					else
						st = (unsigned char *)"a";
					break;
				  default:
					st = (unsigned char *)"i";
				}
				if(strlen(vmacbuf)  + strlen(st) > BUFSIZE) 
					error(value(vi_TERSE) ?
gettext("Macro too long") : gettext("Macro too long  - maybe recursive?"));
				else
					/* 
					 * Macros such as function keys are
					 * performed by leaving the insert,
					 * replace, or append mode, executing 
					 * the proper cursor movement commands
					 * and returning to the mode we are
					 * currently in (commch).
					 */
					strcat(vmacbuf, st);
			}
			c = getkey();
#ifdef MDEBUG
			if (trace)
				fprintf(trace,"Success: push(%s), return %c",maps[d].mapto, c);
#endif
			return(c);	/* first char of map string */
			contin:;
		}
	}
#ifdef MDEBUG
	if (trace)
		fprintf(trace,"Fail: push(%s), return %c", &b[1], c);
#endif
	macpush(&b[1],0);
	return(c);
}

/*
 * Push st onto the front of vmacp. This is tricky because we have to
 * worry about where vmacp was previously pointing. We also have to
 * check for overflow (which is typically from a recursive macro)
 * Finally we have to set a flag so the whole thing can be undone.
 * canundo is 1 iff we want to be able to undo the macro.  This
 * is false for, for example, pushing back lookahead from fastpeekkey(),
 * since otherwise two fast escapes can clobber our undo.
 */
void
macpush(unsigned char *st, int canundo)
{
	unsigned char tmpbuf[BUFSIZE];

	if (st==0 || *st==0)
		return;
#ifdef MDEBUG
	if (trace)
		fprintf(trace, "macpush(%s), canundo=%d\n",st,canundo);
#endif
	if ((vmacp ? strlen(vmacp) : 0) + strlen(st) > BUFSIZE)
		error(value(vi_TERSE) ? gettext("Macro too long") :
gettext("Macro too long  - maybe recursive?"));
	if (vmacp) {
		strcpy(tmpbuf, vmacp);
		if (!FIXUNDO)
			canundo = 0;	/* can't undo inside a macro anyway */
	}
	strcpy(vmacbuf, st);
	if (vmacp)
		strcat(vmacbuf, tmpbuf);
	vmacp = vmacbuf;
	/* arrange to be able to undo the whole macro */
	if (canundo) {
#ifdef notdef
		otchng = tchng;
		vsave();
		saveall();
		inopen = -1;	/* no need to save since it had to be 1 or -1 before */
		vundkind = VMANY;
#endif
		vch_mac = VC_NOCHANGE;
	}
}

#ifdef UNDOTRACE
visdump(s)
unsigned char *s;
{
	int i;

	if (!trace) return;

	fprintf(trace, "\n%s: basWTOP=%d, basWLINES=%d, WTOP=%d, WBOT=%d, WLINES=%d, WCOLS=%d, WECHO=%d\n",
		s, basWTOP, basWLINES, WTOP, WBOT, WLINES, WCOLS, WECHO);
	fprintf(trace, "   vcnt=%d, vcline=%d, cursor=%d, wcursor=%d, wdot=%d\n",
		vcnt, vcline, cursor-linebuf, wcursor-linebuf, wdot-zero);
	for (i=0; i<TUBELINES; i++)
		if (vtube[i] && *vtube[i])
			fprintf(trace, "%d: '%s'\n", i, vtube[i]);
	tvliny();
}

vudump(s)
unsigned char *s;
{
	line *p;
	unsigned char savelb[1024];

	if (!trace) return;

	fprintf(trace, "\n%s: undkind=%d, vundkind=%d, unddel=%d, undap1=%d, undap2=%d,\n",
		s, undkind, vundkind, lineno(unddel), lineno(undap1), lineno(undap2));
	fprintf(trace, "  undadot=%d, dot=%d, dol=%d, unddol=%d, truedol=%d\n",
		lineno(undadot), lineno(dot), lineno(dol), lineno(unddol), lineno(truedol));
	fprintf(trace, "  [\n");
	CP(savelb, linebuf);
	fprintf(trace, "linebuf = '%s'\n", linebuf);
	for (p=zero+1; p<=truedol; p++) {
		fprintf(trace, "%o ", *p);
		getaline(*p);
		fprintf(trace, "'%s'\n", linebuf);
	}
	fprintf(trace, "]\n");
	CP(linebuf, savelb);
}
#endif

/*
 * Get a count from the keyed input stream.
 * A zero count is indistinguishable from no count.
 */
int
vgetcnt(void)
{
	int c, cnt;

	cnt = 0;
	for (;;) {
		c = getkey();
		if (!isdigit(c))
			break;
		cnt *= 10, cnt += c - '0';
	}
	ungetkey(c);
	Xhadcnt = 1;
	Xcnt = cnt;
	return(cnt);
}

/*
 * fastpeekkey is just like peekkey but insists the character come in
 * fast (within 1 second). This will succeed if it is the 2nd char of
 * a machine generated sequence (such as a function pad from an escape
 * flavor terminal) but fail for a human hitting escape then waiting.
 */
int
fastpeekkey(void)
{
	void trapalarm();
	int c;

	/*
	 * If the user has set notimeout, we wait forever for a key.
	 * If we are in a macro we do too, but since it's already
	 * buffered internally it will return immediately.
	 * In other cases we force this to die in 1 second.
	 * This is pretty reliable (VMUNIX rounds it to .5 - 1.5 secs,
	 * but UNIX truncates it to 0 - 1 secs) but due to system delays
	 * there are times when arrow keys or very fast typing get counted
	 * as separate.  notimeout is provided for people who dislike such
	 * nondeterminism.
	 */
	CATCH
		if (value(vi_TIMEOUT) && inopen >= 0) {
			signal(SIGALRM, trapalarm);
			setalarm();
		}
		c = peekkey();
		cancelalarm();
	ONERR
		c = 0;
	ENDCATCH
	/* Should have an alternative method based on select for 4.2BSD */
	return(c);
}

static int ftfd;
struct requestbuf {
	short time;
	short signo;
};

/*
 * Arrange for SIGALRM to come in shortly, so we don't
 * hang very long if the user didn't type anything.  There are
 * various ways to do this on different systems.
 */
void
setalarm(void)
{
	unsigned char ftname[20];
	struct requestbuf rb;

#ifdef FTIOCSET
	/*
	 * Use nonstandard "fast timer" to get better than
	 * one second resolution.  We must wait at least
	 * 1/15th of a second because some keypads don't
	 * transmit faster than this.
	 */

	/* Open ft psuedo-device - we need our own copy. */
	if (ftfd == 0) {
		strcpy(ftname, "/dev/ft0");
		while (ftfd <= 0 && ftname[7] <= '~') {
			ftfd = open(ftname, 0);
			if (ftfd <= 0)
				ftname[7] ++;
		}
	}
	if (ftfd <= 0) {	/* Couldn't open a /dev/ft? */
		alarm(1);
	} else {
		rb.time = 6;	/* 6 ticks = 100 ms > 67 ms. */
		rb.signo = SIGALRM;
		ioctl(ftfd, FTIOCSET, &rb);
	}
#else
	/*
	 * No special capabilities, so we use alarm, with 1 sec. resolution.
	 */
	alarm(1);
#endif
}

/*
 * Get rid of any impending incoming SIGALRM.
 */
void
cancelalarm(void)
{
	struct requestbuf rb;
#ifdef FTIOCSET
	if (ftfd > 0) {
		rb.time = 0;
		rb.signo = SIGALRM;
		ioctl(ftfd, FTIOCCANCEL, &rb);
	}
#endif
	alarm(0);	/* Have to do this whether or not FTIOCSET */
}

void trapalarm() {
	alarm(0);
	longjmp(vreslab,1);
}
