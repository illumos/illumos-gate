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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_tty.h"
#include "ex_vis.h"
#ifndef PRESUNEUC
#include <wctype.h>
/* Undef putchar/getchar if they're defined. */
#ifdef putchar
#	undef putchar
#endif
#ifdef getchar
#	undef getchar
#endif
#endif /* PRESUNEUC */

/*
 * This is the main routine for visual.
 * We here decode the count and possible named buffer specification
 * preceding a command and interpret a few of the commands.
 * Commands which involve a target (i.e. an operator) are decoded
 * in the routine operate in ex_voperate.c.
 */

#define	forbid(a)	{ if (a) goto fonfon; }

extern int windowchg;
extern int sigok;
#ifdef XPG6
int redisplay;	/* XPG6 assertion 313 [count]r\n :  Also used in ex_vops2.c */
#endif
void redraw(), windowinit();

#ifdef XPG4
extern int P_cursor_offset;
#endif

void
vmain(void)
{
	int c, cnt, i;
	wchar_t esave[TUBECOLS];
	extern wchar_t atube[];
	unsigned char *oglobp;
	short d;
	line *addr;
	int ind, nlput;
	int shouldpo = 0;
	int tag_reset_wrap = 0;
	int onumber, olist, (*OPline)(), (*OPutchar)();

	
	vch_mac = VC_NOTINMAC;
	ixlatctl(0);

	/*
	 * If we started as a vi command (on the command line)
	 * then go process initial commands (recover, next or tag).
	 */
	if (initev) {
		oglobp = globp;
		globp = initev;
		hadcnt = cnt = 0;
		i = tchng;
		addr = dot;
		goto doinit;
	}

	vshowmode("");		/* As a precaution */
	/*
	 * NB:
	 *
	 * The current line is always in the line buffer linebuf,
	 * and the cursor at the position cursor.  You should do
	 * a vsave() before moving off the line to make sure the disk
	 * copy is updated if it has changed, and a getDOT() to get
	 * the line back if you mung linebuf.  The motion
	 * routines in ex_vwind.c handle most of this.
	 */
	for (;;) {
		/*
		 * Decode a visual command.
		 * First sync the temp file if there has been a reasonable
		 * amount of change.  Clear state for decoding of next
		 * command.
		 */
		TSYNC();
		vglobp = 0;
		vreg = 0;
		hold = 0;
		seenprompt = 1;
		wcursor = 0;
		Xhadcnt = hadcnt = 0;
		Xcnt = cnt = 1;
		splitw = 0;
		if (i = holdupd && !windowchg) {
			if (state == VISUAL) {
				sigok = 1;
				(void)peekkey();
				sigok = 0;
			}

			holdupd = 0;
/*
			if (LINE(0) < ZERO) {
				vclear();
				vcnt = 0;
				i = 3;
			}
*/
			if (state != VISUAL) {
				vcnt = 0;
				vsave();
				vrepaint(cursor);
			} else if (i == 3)
				vredraw(WTOP);
			else
				vsync(WTOP);
			vfixcurs();
		} else if(windowchg)
			redraw();

#ifdef XPG6
		if (redisplay) {
			/* XPG6 assertion 313 & 254 : after [count]r\n */
			fixdisplay();
		}
		redisplay = 0;
#endif
		/*
		 * Gobble up counts and named buffer specifications.
		 */
		for (;;) {
looptop:
#ifdef MDEBUG
			if (trace)
				fprintf(trace, "pc=%c",peekkey());
#endif
			sigok = 1;
			c = peekkey();
			sigok = 0;
			if (isdigit(peekkey()) && peekkey() != '0') {
				hadcnt = 1;
				cnt = vgetcnt();
				forbid (cnt <= 0);
			}
			if (peekkey() != '"')
				break;
			(void)getkey(), c = getkey();
			/*
			 * Buffer names be letters or digits.
			 * But not '0' as that is the source of
			 * an 'empty' named buffer spec in the routine
			 * kshift (see ex_temp.c).
			 */
			if(!isascii(c) && MB_CUR_MAX > 1) {
				/* get rest of character */
				wchar_t wchar;
				char multic[MULTI_BYTE_MAX];
				ungetkey(c);
				(void)_mbftowc(multic, &wchar, getkey, &Peekkey);
			}
			forbid (c == '0' || !isalpha(c) && !isascii(c) && !isdigit(c));
			vreg = c;
		}
reread:
		/*
		 * Come to reread from below after some macro expansions.
		 * The call to map allows use of function key pads
		 * by performing a terminal dependent mapping of inputs.
		 */
#ifdef MDEBUG
		if (trace)
			fprintf(trace,"pcb=%c,",peekkey());
#endif
		op = getkey();
		maphopcnt = 0;
		do {
			/*
			 * Keep mapping the char as long as it changes.
			 * This allows for double mappings, e.g., q to #,
			 * #1 to something else.
			 */
			c = op;
			op = map(c, arrows, 0);
#ifdef MDEBUG
			if (trace)
				fprintf(trace,"pca=%c,",c);
#endif
			/*
			 * Maybe the mapped to char is a count. If so, we have
			 * to go back to the "for" to interpret it. Likewise
			 * for a buffer name.
			 */
			if ((isdigit(c) && c!='0') || c == '"') {
				ungetkey(c);
				goto looptop;
			}
			if (!value(vi_REMAP)) {
				c = op;
				break;
			}
			if (++maphopcnt > 256)
				error(gettext("Infinite macro loop"));
		} while (c != op);

		/*
		 * Begin to build an image of this command for possible
		 * later repeat in the buffer workcmd.  It will be copied
		 * to lastcmd by the routine setLAST
		 * if/when completely specified.
		 */
		lastcp = workcmd;
		if (!vglobp)
			*lastcp++ = c;

		/*
		 * First level command decode.
		 */
		switch (c) {

		/*
		 * ^L		Clear screen e.g. after transmission error.
		 */

		/*
		 * ^R		Retype screen, getting rid of @ lines.
		 *		If in open, equivalent to ^L.
		 *		On terminals where the right arrow key sends
		 *		^L we make ^R act like ^L, since there is no
		 *		way to get ^L.  These terminals (adm31, tvi)
		 *		are intelligent so ^R is useless.  Soroc
		 *		will probably foul this up, but nobody has
		 *		one of them.
		 */
		case CTRL('l'):
		case CTRL('r'):
			if (c == CTRL('l') || (key_right && *key_right==CTRL('l'))) {
				vclear();
				vdirty(0, vcnt);
			}
			if (state != VISUAL) {
				/*
				 * Get a clean line, throw away the
				 * memory of what is displayed now,
				 * and move back onto the current line.
				 */
				vclean();
				vcnt = 0;
				vmoveto(dot, cursor, 0);
				continue;
			}
			vredraw(WTOP);
			/*
			 * Weird glitch -- when we enter visual
			 * in a very small window we may end up with
			 * no lines on the screen because the line
			 * at the top is too long.  This forces the screen
			 * to be expanded to make room for it (after
			 * we have printed @'s ick showing we goofed).
			 */
			if (vcnt == 0)
				vrepaint(cursor);
			vfixcurs();
			continue;

		/*
		 * $		Escape just cancels the current command
		 *		with a little feedback.
		 */
		case ESCAPE:
			(void) beep();
			continue;

		/*
		 * @   		Macros. Bring in the macro and put it
		 *		in vmacbuf, point vglobp there and punt.
		 */
		 case '@':
			c = getesc();
			if (c == 0)
				continue;
			if (c == '@')
				c = lastmac;
			if (isupper(c))
				c = tolower(c);
			forbid(!islower(c));
			lastmac = c;
			vsave();
			CATCH
				unsigned char tmpbuf[BUFSIZE];

				regbuf(c, tmpbuf, sizeof (vmacbuf));
				macpush(tmpbuf, 1);
			ONERR
				lastmac = 0;
				splitw = 0;
				getDOT();
				vrepaint(cursor);
				continue;
			ENDCATCH
			vmacp = vmacbuf;
			goto reread;

		/*
		 * .		Repeat the last (modifying) open/visual command.
		 */
		case '.':
			/*
			 * Check that there was a last command, and
			 * take its count and named buffer unless they
			 * were given anew.  Special case if last command
			 * referenced a numeric named buffer -- increment
			 * the number and go to a named buffer again.
			 * This allows a sequence like "1pu.u.u...
			 * to successively look for stuff in the kill chain
			 * much as one does in EMACS with C-Y and M-Y.
			 */
			forbid (lastcmd[0] == 0);
			if (hadcnt)
				lastcnt = cnt;
			if (vreg)
				lastreg = vreg;
			else if (isdigit(lastreg) && lastreg < '9')
				lastreg++;
			vreg = lastreg;
			cnt = lastcnt;
			hadcnt = lasthad;
			vglobp = lastcmd;
			goto reread;

		/*
		 * ^U		Scroll up.  A count sticks around for
		 *		future scrolls as the scroll amount.
		 *		Attempt to hold the indentation from the
		 *		top of the screen (in logical lines).
		 *
		 * BUG:		A ^U near the bottom of the screen
		 *		on a dumb terminal (which can't roll back)
		 *		causes the screen to be cleared and then
		 *		redrawn almost as it was.  In this case
		 *		one should simply move the cursor.
		 */
		case CTRL('u'):
			if (hadcnt)
				vSCROLL = cnt;
			cnt = vSCROLL;
			if (state == VISUAL)
				ind = vcline, cnt += ind;
			else
				ind = 0;
			vmoving = 0;
			vup(cnt, ind, 1);
			vnline((unsigned char *)NOSTR);
			continue;

		/*
		 * ^D		Scroll down.  Like scroll up.
		 */
		case CTRL('d'):
#ifdef TRACE
		if (trace)
			fprintf(trace, "before vdown in ^D, dot=%d, wdot=%d, dol=%d\n", lineno(dot), lineno(wdot), lineno(dol));
#endif
			if (hadcnt)
				vSCROLL = cnt;
			cnt = vSCROLL;
			if (state == VISUAL)
				ind = vcnt - vcline - 1, cnt += ind;
			else
				ind = 0;
			vmoving = 0;
			vdown(cnt, ind, 1);
#ifdef TRACE
		if (trace)
			fprintf(trace, "before vnline in ^D, dot=%d, wdot=%d, dol=%d\n", lineno(dot), lineno(wdot), lineno(dol));
#endif
			vnline((unsigned char *)NOSTR);
#ifdef TRACE
		if (trace)
			fprintf(trace, "after vnline in ^D, dot=%d, wdot=%d, dol=%d\n", lineno(dot), lineno(wdot), lineno(dol));
#endif
			continue;

		/*
		 * ^E		Glitch the screen down (one) line.
		 *		Cursor left on same line in file.
		 */
		case CTRL('e'):
			if (state != VISUAL)
				continue;
			if (!hadcnt)
				cnt = 1;
			/* Bottom line of file already on screen */
			forbid(lineDOL()-lineDOT() <= vcnt-1-vcline);
			ind = vcnt - vcline - 1 + cnt;
			vdown(ind, ind, 1);
			vnline(cursor);
			continue;

		/*
		 * ^Y		Like ^E but up
		 */
		case CTRL('y'):
			if (state != VISUAL)
				continue;
			if (!hadcnt)
				cnt = 1;
			forbid(lineDOT()-1<=vcline); /* line 1 already there */
			ind = vcline + cnt;
			vup(ind, ind, 1);
			vnline(cursor);
			continue;


		/*
		 * m		Mark position in mark register given
		 *		by following letter.  Return is
		 *		accomplished via ' or `; former
		 *		to beginning of line where mark
		 *		was set, latter to column where marked.
		 */
		case 'm':
			/*
			 * Getesc is generally used when a character
			 * is read as a latter part of a command
			 * to allow one to hit rubout/escape to cancel
			 * what you have typed so far.  These characters
			 * are mapped to 0 by the subroutine.
			 */
			c = getesc();
			if (c == 0)
				continue;

			/*
			 * Markreg checks that argument is a letter
			 * and also maps ' and ` to the end of the range
			 * to allow '' or `` to reference the previous
			 * context mark.
			 */
			c = markreg(c);
			forbid (c == 0);
			vsave();
			names[c - 'a'] = (*dot &~ 01);
			ncols[c - 'a'] = cursor;
			anymarks = 1;
			continue;

		/*
		 * ^F		Window forwards, with 2 lines of continuity.
		 *		Count repeats.
		 */
		case CTRL('f'):
			vsave();
			if (vcnt > 2) {
				addr = dot + (vcnt - vcline) - 2 + (cnt-1)*basWLINES;
				forbid(addr > dol);
				dot = addr;
				vcnt = vcline = 0;
			}
			vzop(0, 0, '+');
			continue;

		/*
		 * ^B		Window backwards, with 2 lines of continuity.
		 *		Inverse of ^F.
		 */
		case CTRL('b'):
			vsave();
			if (one + vcline != dot && vcnt > 2) {
				addr = dot - vcline + 2 - (cnt-1)*basWLINES;
				forbid (addr <= zero);
				dot = addr;
				vcnt = vcline = 0;
			}
			vzop(0, 0, '^');
			continue;

		/*
		 * z		Screen adjustment, taking a following character:
		 *			zcarriage_return		current line to top
		 *			z<NL>		like zcarriage_return
		 *			z-		current line to bottom
		 *		also z+, z^ like ^F and ^B.
		 *		A preceding count is line to use rather
		 *		than current line.  A count between z and
		 *		specifier character changes the screen size
		 *		for the redraw.
		 *
		 */
		case 'z':
			if (state == VISUAL) {
				i = vgetcnt();
				if (i > 0)
					vsetsiz(i);
				c = getesc();
				if (c == 0)
					continue;
			}
			vsave();
			vzop(hadcnt, cnt, c);
			continue;

		/*
		 * Y		Yank lines, abbreviation for y_ or yy.
		 *		Yanked lines can be put later if no
		 *		changes intervene, or can be put in named
		 *		buffers and put anytime in this session.
		 */
		case 'Y':
			ungetkey('_');
			c = 'y';
			break;

		/*
		 * J		Join lines, 2 by default.  Count is number
		 *		of lines to join (no join operator sorry.)
		 */
		case 'J':
			forbid (dot == dol);
			if (cnt == 1)
				cnt = 2;
			if (cnt > (i = dol - dot + 1))
				cnt = i;
			vsave();
			vmacchng(1);
			setLAST();
			cursor = strend(linebuf);
			vremote(cnt, join, 0);
			notenam = (unsigned char *)"join";
			vmoving = 0;
			killU();
			vreplace(vcline, cnt, 1);
			if (!*cursor && cursor > linebuf)
				cursor--;
			if (notecnt == 2)
				notecnt = 0;
			vrepaint(cursor);
			continue;

		/*
		 * S		Substitute text for whole lines, abbrev for c_.
		 *		Count is number of lines to change.
		 */
		case 'S':
			ungetkey('_');
			c = 'c';
			break;

		/*
		 * O		Create a new line above current and accept new
		 *		input text, to an escape, there.
		 *		A count specifies, for dumb terminals when
		 *		slowopen is not set, the number of physical
		 *		line space to open on the screen.
		 *
		 * o		Like O, but opens lines below.
		 */
		case 'O':
		case 'o':
			vmacchng(1);
			voOpen(c, cnt);
			continue;

		/*
		 * C		Change text to end of line, short for c$.
		 */
		case 'C':
			if (*cursor) {
				ungetkey('$'), c = 'c';
				break;
			}
			goto appnd;

		/*
		 * ~	Switch case of letter under cursor
		 */
		case '~':
			{
				unsigned char mbuf[2049];
				unsigned char *ccursor = cursor;
#ifdef PRESUNEUC
				int tmp, length;
				wchar_t wchar;
				unsigned char tmp1;
#else
				int tmp, len;
				wchar_t wc;
#endif /* PRESUNEUC */
				setLAST();
				for (tmp = 0; tmp + 3 < 2048; ) {
				/*
				 * Use multiple 'r' commands to replace
				 * alpha with alternate case.
				 */

					if(cnt-- <= 0)
						break;
#ifdef PRESUNEUC
					length = mbtowc(&wchar, (char *)ccursor, MULTI_BYTE_MAX);
#else
					len = mbtowc(&wc, (char *)ccursor, MULTI_BYTE_MAX);
#endif /* PRESUNEUC */
#ifdef PRESUNEUC
					if(length > 1) {
#else
					if(len > 1 && !iswalpha(wc)) {
#endif /* PRESUNEUC */
						mbuf[tmp+0] = ' ';
						tmp++;
#ifdef PRESUNEUC
						ccursor += length;
#else
						ccursor += len;
#endif /* PRESUNEUC */
						continue;
					}
					mbuf[tmp] = 'r';
#ifdef PRESUNEUC
					mbuf[tmp+1] = *ccursor++;
#else
					ccursor += ((len > 0) ? len : 1);
#endif /* PRESUNEUC */
				/*
				 * If pointing to an alpha character,
				 * change the case.
				 */

#ifdef PRESUNEUC
					tmp1 = mbuf[tmp+1];
					if (isupper((unsigned char)tmp1))
						mbuf[tmp+1] = tolower((unsigned char)tmp1);
					else
						mbuf[tmp+1] = toupper((unsigned char)tmp1);
#else
					if (iswupper(wc))
						len = wctomb((char *)(mbuf + tmp + 1),
							(wc = towlower(wc)));
					else
						len = wctomb((char *)(mbuf + tmp + 1),
							(wc = towupper(wc)));
					tmp += len - 1;
#endif /* PRESUNEUC */
					if(*ccursor) 
				/* 
				 * If at end of line do not advance
				 * to the next character, else use a
				 * space to advance 1 column.
				 */
						mbuf[tmp+2] = ' ';
					else {
						mbuf[tmp+2] = '\0';
						tmp +=3;
						break;
					}
					tmp += 3;
				}

				mbuf[tmp] = 0;
				macpush(mbuf, 1);
			}
			continue;


		/*
		 * A		Append at end of line, short for $a.
		 */
		case 'A':
			operate('$', 1);
appnd:
			c = 'a';
			/* FALLTHROUGH */

		/*
		 * a		Appends text after cursor.  Text can continue
		 *		through arbitrary number of lines.
		 */
		case 'a':
			if (*cursor) {
				wchar_t wchar;
				int length = mbtowc(&wchar, (char *)cursor, MULTI_BYTE_MAX); 
				if (state == HARDOPEN) {
					if(length < 0) {
						putoctal = 1;
						putchar(*cursor);
						putoctal = 0;
					} else 
						putchar(wchar);
				}
				if(length < 0)
					cursor++;
				else
					cursor += length;
			}
			goto insrt;

		/*
		 * I		Insert at beginning of whitespace of line,
		 *		short for ^i.
		 */
		case 'I':
			operate('^', 1);
			c = 'i';
			/* FALLTHROUGH */

		/*
		 * R		Replace characters, one for one, by input
		 *		(logically), like repeated r commands.
		 *
		 * BUG:		This is like the typeover mode of many other
		 *		editors, and is only rarely useful.  Its
		 *		implementation is a hack in a low level
		 *		routine and it doesn't work very well, e.g.
		 *		you can't move around within a R, etc.
		 */
		case 'R':
			/* FALLTHROUGH */

		/*
		 * i		Insert text to an escape in the buffer.
		 *		Text is arbitrary.  This command reminds of
		 *		the i command in bare teco.
		 */
		case 'i':
insrt:
			/*
			 * Common code for all the insertion commands.
			 * Save for redo, position cursor, prepare for append
			 * at command and in visual undo.  Note that nothing
			 * is doomed, unless R when all is, and save the
			 * current line in a the undo temporary buffer.
			 */
			vmacchng(1);
			setLAST();
			vcursat(cursor);
			prepapp();
			vnoapp();
			doomed = c == 'R' ? 10000 : 0;
			if(FIXUNDO)
				vundkind = VCHNG;
			vmoving = 0;
			CP(vutmp, linebuf);

			/*
			 * If this is a repeated command, then suppress
			 * fake insert mode on dumb terminals which looks
			 * ridiculous and wastes lots of time even at 9600B.
			 */
			if (vglobp)
				hold = HOLDQIK;
			vappend(c, cnt, 0);
			continue;

		/*
		 * 	An attention, normally a DEL, just beeps.
		 *	If you are a vi command within ex, then
		 *	two ATTN's will drop you back to command mode.
		 */
		case ATTN:
			(void) beep();
			if (initev || peekkey() != ATTN)
				continue;
			/* FALLTHROUGH */

		/*
		 * ^\		A quit always gets command mode.
		 */
		case QUIT:
			/*
			 * Have to be careful if we were called
			 *	g/xxx/vi
			 * since a return will just start up again.
			 * So we simulate an interrupt.
			 */
			if (inglobal)
				onintr(0);
			/* fall into... */

#ifdef notdef
		/*
		 * q		Quit back to command mode, unless called as
		 *		vi on command line in which case dont do it
		 */
		case 'q':	/* quit */
			if (initev) {
				vsave();
				CATCH
					error(gettext("Q gets ex command mode, :q leaves vi"));
				ENDCATCH
				splitw = 0;
				getDOT();
				vrepaint(cursor);
				continue;
			}
#endif
			/* FALLTHROUGH */

		/*
		 * Q		Is like q, but always gets to command mode
		 *		even if command line invocation was as vi.
		 */
		case 'Q':
			vsave();
			/*
			 * If we are in the middle of a macro, throw away
			 * the rest and fix up undo.
			 * This code copied from getbr().
			 */
			if (vmacp) {
				vmacp = 0;
				if (inopen == -1)	/* don't mess up undo for esc esc */
					vundkind = VMANY;
				inopen = 1;	/* restore old setting now that macro done */
			}
			ixlatctl(1);
			return;


		/*
		 * ZZ		Like :x
		 */
		 case 'Z':
			forbid(getkey() != 'Z');
			oglobp = globp;
			globp = (unsigned char *)"x";
			vclrech(0);
			goto gogo;
			
		/*
		 * P		Put back text before cursor or before current
		 *		line.  If text was whole lines goes back
		 *		as whole lines.  If part of a single line
		 *		or parts of whole lines splits up current
		 *		line to form many new lines.
		 *		May specify a named buffer, or the delete
		 *		saving buffers 1-9.
		 *
		 * p		Like P but after rather than before.
		 */
		case 'P':
		case 'p':
			vmoving = 0;
#ifdef XPG4
			P_cursor_offset = 0;
#endif
#ifdef notdef
			forbid (!vreg && value(vi_UNDOMACRO) && inopen < 0);
#endif
			/*
			 * If previous delete was partial line, use an
			 * append or insert to put it back so as to
			 * use insert mode on intelligent terminals.
			 */
			if (!vreg && DEL[0]) {
				setLAST();
				forbid ((unsigned char)DEL[128] == 0200);
				vglobp = DEL;
				ungetkey(c == 'p' ? 'a' : 'i');
				goto reread;
			}

			/*
			 * If a register wasn't specified, then make
			 * sure there is something to put back.
			 */
			forbid (!vreg && unddol == dol);
			/*
			 * If we just did a macro the whole buffer is in
			 * the undo save area.  We don't want to put THAT.
			 */
			forbid (vundkind == VMANY && undkind==UNDALL);
			vsave();
			vmacchng(1);
			setLAST();
			i = 0;
			if (vreg && partreg(vreg) || !vreg && pkill[0]) {
				/*
				 * Restoring multiple lines which were partial
				 * lines; will leave cursor in middle
				 * of line after shoving restored text in to
				 * split the current line.
				 */
				i++;
				if (c == 'p' && *cursor)
					cursor = nextchr(cursor);
			} else {
				/*
				 * In whole line case, have to back up dot
				 * for P; also want to clear cursor so
				 * cursor will eventually be positioned
				 * at the beginning of the first put line.
				 */
				cursor = 0;
				if (c == 'P') {
					dot--, vcline--;
					c = 'p';
				}
			}
			killU();

			/*
			 * The call to putreg can potentially
			 * bomb since there may be nothing in a named buffer.
			 * We thus put a catch in here.  If we didn't and
			 * there was an error we would end up in command mode.
			 */
			addr = dol;	/* old dol */
			CATCH
				vremote(1,
				    vreg ? (int (*)())putreg : put, vreg);
			ONERR
				if (vreg == -1) {
					splitw = 0;
					if (op == 'P')
						dot++, vcline++;
					goto pfixup;
				}
			ENDCATCH
			splitw = 0;
			nlput = dol - addr + 1;
			if (!i) {
				/*
				 * Increment undap1, undap2 to make up
				 * for their incorrect initialization in the
				 * routine vremote before calling put/putreg.
				 */
				if (FIXUNDO)
					undap1++, undap2++;
				vcline++;
				nlput--;

				/*
				 * After a put want current line first line,
				 * and dot was made the last line put in code
				 * run so far.  This is why we increment vcline
				 * above and decrease dot here.
				 */
				dot -= nlput - 1;
			}
#ifdef TRACE
			if (trace)
				fprintf(trace, "vreplace(%d, %d, %d), undap1=%d, undap2=%d, dot=%d\n", vcline, i, nlput, lineno(undap1), lineno(undap2), lineno(dot));
#endif
			vreplace(vcline, i, nlput);
#ifdef XPG4
			if (op == 'P' && i > 0) {
				dot += nlput - 1;
				vcline += nlput - 1;
				cursor += P_cursor_offset;
			}
#endif
			if (state != VISUAL) {
				/*
				 * Special case in open mode.
				 * Force action on the screen when a single
				 * line is put even if it is identical to
				 * the current line, e.g. on YP; otherwise
				 * you can't tell anything happened.
				 */
				vjumpto(dot, cursor, '.');
				continue;
			}
pfixup:
			vrepaint(cursor);
			vfixcurs();
			continue;

		/*
		 * ^^		Return to previous file.
		 *		Like a :e #, and thus can be used after a
		 *		"No Write" diagnostic.
		 */
		case CTRL('^'):
			forbid (hadcnt);
			vsave();
			ckaw();
			oglobp = globp;
			if (value(vi_AUTOWRITE) && !value(vi_READONLY))
				globp = (unsigned char *)"e! #";
			else
				globp = (unsigned char *)"e #";
			goto gogo;

#ifdef TAG_STACK
                /*
                 * ^T           Pop the tag stack if enabled or else reset it
                 *              if not.
                 */
                case CTRL('t'):
                        forbid (hadcnt);
                        vsave();
                        oglobp = globp;
                        globp = (unsigned char *) "pop";
                        goto gogo;
#endif
		/*
		 * ^]		Takes word after cursor as tag, and then does
		 *		tag command.  Read ``go right to''.
		 *		This is not a search, so the wrapscan setting
		 *		must be ignored.  If set, then it is unset
		 *		here and restored later.
		 */
		case CTRL(']'):
			grabtag();
			oglobp = globp;
			if (value(vi_WRAPSCAN) == 0) {
				tag_reset_wrap = 1;
				value(vi_WRAPSCAN) = 1;
			}
			globp = (unsigned char *)"tag";
			goto gogo;

		/*
		 * &		Like :&
		 */
		 case '&':
			oglobp = globp;
			globp = (unsigned char *)"&";
			goto gogo;
			
		/*
		 * ^G		Bring up a status line at the bottom of
		 *		the screen, like a :file command.
		 *
		 * BUG:		Was ^S but doesn't work in cbreak mode
		 */
		case CTRL('g'):
			oglobp = globp;
			globp = (unsigned char *)"file";
gogo:
			addr = dot;
			vsave();
			goto doinit;

#ifdef SIGTSTP
		/*
		 * ^Z:	suspend editor session and temporarily return
		 * 	to shell.  Only works with Berkeley/IIASA process
		 *	control in kernel.
		 */
		case CTRL('z'):
			forbid(dosusp == 0);
			vsave();
			oglobp = globp;
			globp = (unsigned char *)"stop";
			goto gogo;
#endif

		/*
		 * :		Read a command from the echo area and
		 *		execute it in command mode.
		 */
		case ':':
			forbid (hadcnt);
			vsave();
			i = tchng;
			addr = dot;
			if (readecho(c)) {
				esave[0] = 0;
				goto fixup;
			}
			getDOT();
			/*
			 * Use the visual undo buffer to store the global
			 * string for command mode, since it is idle right now.
			 */
			oglobp = globp; strcpy(vutmp, genbuf+1); globp = vutmp;
doinit:
			esave[0] = 0;
			fixech();

			/*
			 * Have to finagle around not to lose last
			 * character after this command (when run from ex
			 * command mode).  This is clumsy.
			 */
			d = peekc; ungetchar(0);
			if (shouldpo) {
				/*
				 * So after a "Hit return..." ":", we do
				 * another "Hit return..." the next time
				 */
				pofix();
				shouldpo = 0;
			}
			CATCH
				/*
				 * Save old values of options so we can
				 * notice when they change; switch into
				 * cooked mode so we are interruptible.
				 */
				onumber = value(vi_NUMBER);
				olist = value(vi_LIST);
				OPline = Pline;
				OPutchar = Putchar;
#ifndef CBREAK
				vcook();
#endif
				commands(1, 1);
				if (dot == zero && dol > zero)
					dot = one;
#ifndef CBREAK
				vraw();
#endif
			ONERR
#ifndef CBREAK
				vraw();
#endif
				copy(esave, vtube[WECHO], TUBECOLS * sizeof(wchar_t));
			ENDCATCH
			fixol();
			Pline = OPline;
			Putchar = OPutchar;
			ungetchar(d);
			globp = oglobp;

			/*
			 * If we ended up with no lines in the buffer, make
			 * a line.
			 */
			if (dot == zero) {
				fixzero();
			}
			splitw = 0;

			/*
			 * Special case: did list/number options change?
			 */
			if (onumber != value(vi_NUMBER))
				setnumb(value(vi_NUMBER));
			if (olist != value(vi_LIST))
				setlist(value(vi_LIST));

fixup:
			/*
			 * If a change occurred, other than
			 * a write which clears changes, then
			 * we should allow an undo even if .
			 * didn't move.
			 *
			 * BUG: You can make this wrong by
			 * tricking around with multiple commands
			 * on one line of : escape, and including
			 * a write command there, but it's not
			 * worth worrying about.
			 */
			if (FIXUNDO && tchng && tchng != i)
				vundkind = VMANY, cursor = 0;

			/*
			 * If we are about to do another :, hold off
			 * updating of screen.
			 */
			if (vcnt < 0 && Peekkey == ':') {
				getDOT();
				shouldpo = 1;
				continue;
			}
			shouldpo = 0;

			/*
			 * In the case where the file being edited is
			 * new; e.g. if the initial state hasn't been
			 * saved yet, then do so now.
			 */
			if (unddol == truedol) {
				vundkind = VNONE;
				Vlines = lineDOL();
				if (!inglobal)
					savevis();
				addr = zero;
				vcnt = 0;
				if (esave[0] == 0)
					copy(esave, vtube[WECHO], TUBECOLS * sizeof(wchar_t));
			}

			/*
			 * If the current line moved reset the cursor position.
			 */
			if (dot != addr) {
				vmoving = 0;
				cursor = 0;
			}

			/*
			 * If current line is not on screen or if we are
			 * in open mode and . moved, then redraw.
			 */
			i = vcline + (dot - addr);
			if(windowchg) 
				windowinit();
			if (i < 0 || i >= vcnt && i >= -vcnt || state != VISUAL && dot != addr) {
				if (state == CRTOPEN)
					vup1();
				if (vcnt > 0)
					vcnt = 0;
				vjumpto(dot, (unsigned char *) 0, '.');
			} else {
				/*
				 * Current line IS on screen.
				 * If we did a [Hit return...] then
				 * restore vcnt and clear screen if in visual
				 */
				vcline = i;
				if (vcnt < 0) {
					vcnt = -vcnt;
					if (state == VISUAL)
						vclear();
					else if (state == CRTOPEN) {
						vcnt = 0;
					}
				}

				/*
				 * Limit max value of vcnt based on $
				 */
				i = vcline + lineDOL() - lineDOT() + 1;
				if (i < vcnt)
					vcnt = i;
				
				/*
				 * Dirty and repaint.
				 */
				vdirty(0, lines);
				vrepaint(cursor);
			}

			/*
			 * If in visual, put back the echo area
			 * if it was clobbered.
			 */
			if (state == VISUAL) {
				int sdc = destcol, sdl = destline;

				splitw++;
				vigoto(WECHO, 0);
				for (i = 0; i < TUBECOLS - 1; i++) {
					if (esave[i] == 0)
						break;
					if(esave[i] != FILLER)
						(void) vputchar(esave[i]);
				}
				splitw = 0;
				vgoto(sdl, sdc);
			}
			if (tag_reset_wrap == 1) {
				tag_reset_wrap = 0;
				value(vi_WRAPSCAN) = 0;
			}
			continue;

		/*
		 * u		undo the last changing command.
		 */
		case 'u':
			vundo(1);
			continue;

		/*
		 * U		restore current line to initial state.
		 */
		case 'U':
			vUndo();
			continue;

fonfon:
			(void) beep();
			vmacp = 0;
			inopen = 1;	/* might have been -1 */
			continue;
		}

		/*
		 * Rest of commands are decoded by the operate
		 * routine.
		 */
		operate(c, cnt);
	}
}

/*
 * Grab the word after the cursor so we can look for it as a tag.
 */
void
grabtag(void)
{
	unsigned char *cp, *dp;

	cp = vpastwh(cursor);
	if (*cp) {
		dp = lasttag;
		do {
			if (dp < &lasttag[sizeof lasttag - 2])
				*dp++ = *cp;
			cp++;
			/* only allow ascii alphabetics */
		} while ((isascii(*cp) && isalpha(*cp)) || isdigit(*cp) || *cp == '_');
		*dp++ = 0;
	}
}

/*
 * Before appending lines, set up addr1 and
 * the command mode undo information.
 */
void
prepapp(void)
{

	addr1 = dot;
	deletenone();
	addr1++;
	appendnone();
}

/*
 * Execute function f with the address bounds addr1
 * and addr2 surrounding cnt lines starting at dot.
 */
void
vremote(cnt, f, arg)
	int cnt, (*f)(), arg;
{
	int oing = inglobal;

	addr1 = dot;
	addr2 = dot + cnt - 1;
	inglobal = 0;
	if (FIXUNDO)
		undap1 = undap2 = dot;
	(*f)(arg);
	inglobal = oing;
	if (FIXUNDO)
		vundkind = VMANY;
	/*
	 * XPG6 assertion 273: For the following commands, don't set vmcurs
	 * to 0, so that undo positions the cursor column correctly when
	 * we've moved off the initial line that was changed eg. when G has
	 * moved us off the line, or when a multi-line change was done.
	 */
	if (lastcmd[0] != 'C' && lastcmd[0] != 'c' && lastcmd[0] != 'o' &&
	    lastcmd[0] != 'R' && lastcmd[0] != 'S' && lastcmd[0] != 's' &&
	    lastcmd[0] != 'i' && lastcmd[0] != 'a' && lastcmd[0] != 'A') {
		vmcurs = 0;
	}
}

/*
 * Save the current contents of linebuf, if it has changed.
 */
void
vsave(void)
{
	unsigned char temp[LBSIZE];

	strncpy(temp, linebuf, sizeof (temp));
	if (FIXUNDO && vundkind == VCHNG || vundkind == VCAPU) {
		/*
		 * If the undo state is saved in the temporary buffer
		 * vutmp, then we sync this into the temp file so that
		 * we will be able to undo even after we have moved off
		 * the line.  It would be possible to associate a line
		 * with vutmp but we assume that vutmp is only associated
		 * with line dot (e.g. in case ':') above, so beware.
		 */
		prepapp();
		strcLIN(vutmp);
		putmark(dot);
		vremote(1, yank, 0);
		vundkind = VMCHNG;
		notecnt = 0;
		undkind = UNDCHANGE;
	}
	/*
	 * Get the line out of the temp file and do nothing if it hasn't
	 * changed.  This may seem like a loss, but the line will
	 * almost always be in a read buffer so this may well avoid disk i/o.
	 */
	getDOT();
	if (strncmp(linebuf, temp, sizeof (temp)) == 0)
		return;
	strcLIN(temp);
	putmark(dot);
}

#undef	forbid
#define	forbid(a)	if (a) { (void) beep(); return; }

/*
 * Do a z operation.
 * Code here is rather long, and very uninteresting.
 */
void
vzop(bool hadcnt, int cnt, int c)
{
	line *addr;

	if (state != VISUAL) {
		/*
		 * Z from open; always like a z=.
		 * This code is a mess and should be cleaned up.
		 */
		vmoveitup(1, 1);
		vgoto(outline, 0);
		ostop(normf);
		setoutt();
		addr2 = dot;
		vclear();
		destline = WECHO;
		zop2(Xhadcnt ? Xcnt : value(vi_WINDOW) - 1, '=');
		if (state == CRTOPEN)
			putnl();
		putNFL();
		termreset();
		Outchar = vputchar;
		(void)ostart();
		vcnt = 0;
		outline = destline = 0;
		vjumpto(dot, cursor, 0);
		return;
	}
	if (hadcnt) {
		addr = zero + cnt;
		if (addr < one)
			addr = one;
		if (addr > dol)
			addr = dol;
		markit(addr);
	} else
		switch (c) {

		case '+':
			addr = dot + vcnt - vcline;
			break;

		case '^':
			addr = dot - vcline - 1;
			forbid (addr < one);
			c = '-';
			break;

		default:
			addr = dot;
			break;
		}
	switch (c) {

	case '.':
	case '-':
		break;

	case '^':
		forbid (addr <= one);
		break;

	case '+':
		forbid (addr >= dol);
		/* FALLTHROUGH */

	case CR:
	case NL:
		c = CR;
		break;

	default:
		(void) beep();
		return;
	}
	vmoving = 0;
	vjumpto(addr, (unsigned char *)NOSTR, c);
}
