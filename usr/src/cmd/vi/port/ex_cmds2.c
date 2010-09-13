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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ex.h"
#include "ex_argv.h"
#include "ex_temp.h"
#include "ex_tty.h"
#include "ex_vis.h"
#include <unistd.h>

extern bool	pflag, nflag;		/* extern; also in ex_cmds.c */
extern int	poffset;		/* extern; also in ex_cmds.c */
extern short	slevel;			/* extern; has level of source() */

/*
 * Subroutines for major command loop.
 */

/*
 * Is there a single letter indicating a named buffer next?
 */
int
cmdreg(void)
{
	int c = 0;
	int wh = skipwh();

#ifdef XPG4
	if (wh && isalpha(c = peekchar()) && isascii(c) && !isdigit(c))
#else /* XPG4 */
	if (wh && isalpha(c = peekchar()) && isascii(c))
#endif /* XPG4 */
		c = getchar();

#ifdef XPG4
	if (isdigit(c)) {
		c = 0;
	}
#endif /* XPG4 */
	return (c);
}

/*
 * Tell whether the character ends a command
 */
int
endcmd(int ch)
{
	switch (ch) {

	case '\n':
	case EOF:
		endline = 1;
		return (1);

	case '|':
	case '"':
		endline = 0;
		return (1);
	}
	return (0);
}

/*
 * Insist on the end of the command.
 */
void
eol(void)
{

	if (!skipend())
		error(value(vi_TERSE) ? gettext("Extra chars") :
			gettext("Extra characters at end of command"));
	ignnEOF();
}

#ifdef XPG4
/*
 * Print out the message in the error message file at str,
 * with i an integer argument to printf.
 */
/*VARARGS2*/
void
error(str, i)
	unsigned char *str;
	int i;
{
	tagflg = 0;
	errcnt++;
	noerror(str, i);
}

/*
 * noerror(): like error(), but doesn't inc errcnt. 
 * the reason why we created this routine, instead of fixing up errcnt
 * after error() is called, is because we will do a longjmp, and
 * not a return. it does other things closing file i/o, reset, etc;
 * so we follow those procedures.
 */
/*VARARGS2*/
void
noerror(str, i)
	unsigned char *str;
	int i;
{

	error0();
	merror(str, i);
	if (writing) {
		serror((unsigned char *)
		    gettext(" [Warning - %s is incomplete]"), file);
		writing = 0;
	}
	error1(str);
}

#else /* !XPG4 */
/*
 * Print out the message in the error message file at str,
 * with i an integer argument to printf.
 */
/*VARARGS2*/
void
error(str, i)
	unsigned char *str;
	int i;
{
	tagflg = 0;
	errcnt++;
	error0();
	merror(str, i);
	if (writing) {
		serror((unsigned char *)
		    gettext(" [Warning - %s is incomplete]"), file);
		writing = 0;
	}
	error1(str);
}
#endif /* XPG4 */

/*
 * Rewind the argument list.
 */
void
erewind(void)
{

	argc = argc0;
	argv = argv0;
	args = args0;
	if (argc > 1 && !hush && cur_term) {
		viprintf(mesg(value(vi_TERSE) ? gettext("%d files") :
			gettext("%d files to edit")), argc);
		if (inopen)
			putchar(' ');
		else
			putNFL();
	}
}

/*
 * Guts of the pre-printing error processing.
 * If in visual and catching errors, then we don't mung up the internals,
 * just fixing up the echo area for the print.
 * Otherwise we reset a number of externals, and discard unused input.
 */
void
error0(void)
{

	if (laste) {
#ifdef VMUNIX
		tlaste();
#endif
		laste = 0;
		sync();
	}
	if (vcatch) {
		if (splitw == 0)
			fixech();
		if (!enter_standout_mode || !exit_bold)
			dingdong();
		return;
	}
	if (input) {
		input = strend(input) - 1;
		if (*input == '\n')
			setlastchar('\n');
		input = 0;
	}
	setoutt();
	flush();
	resetflav();
	if (!enter_standout_mode || !exit_bold)
		dingdong();
	if (inopen) {
		/*
		 * We are coming out of open/visual ungracefully.
		 * Restore columns, undo, and fix tty mode.
		 */
		columns = OCOLUMNS;
		undvis();
		ostop(normf);
		/* ostop should be doing this
		putpad(cursor_normal);
		putpad(key_eol);
		*/
		putnl();
	}
	inopen = 0;
	holdcm = 0;
}

/*
 * Post error printing processing.
 * Close the i/o file if left open.
 * If catching in visual then throw to the visual catch,
 * else if a child after a fork, then exit.
 * Otherwise, in the normal command mode error case,
 * finish state reset, and throw to top.
 */
void
error1(unsigned char *str)
{
	bool die;
	extern short ttyindes;

	if ((io > 0) && (io != ttyindes)) {
		close(io);
		io = -1;
	}
	
	die = (getpid() != ppid);	/* Only children die */
	inappend = inglobal = 0;
	globp = vglobp = vmacp = 0;
	if (vcatch && !die) {
		inopen = 1;
		vcatch = 0;
		if (str)
			noonl();
		fixol();
		if (slevel > 0)
			reset();
		longjmp(vreslab,1);
	}
	if (str && !vcatch)
		putNFL();
	if (die)
		exit(++errcnt);
	lseek(0, 0L, 2);
	if (inglobal)
		setlastchar('\n');

	if (inexrc) {
		/*
		 * Set inexrc to 0 so that this error is printed only
		 * once (eg. when stdin is redirected from /dev/null and
		 * vi prints "Input read error" because it is unable to
		 * read() the <CR>).
		 */
		inexrc = 0;
		lprintf(gettext(
		    "Error detected in .exrc.[Hit return to continue] "),
		    0);
		putNFL();
		getkey();
	}

	while ((lastchar() != '\n') && (lastchar() != EOF))
		ignchar();
	ungetchar(0);
	endline = 1;
	reset();
}

void
fixol(void)
{
	if (Outchar != vputchar) {
		flush();
		if (state == ONEOPEN || state == HARDOPEN)
			outline = destline = 0;
		Outchar = vputchar;
		vcontin(1);
		/*
		 * Outchar could be set to termchar() through vcontin(). 
		 * So reset it again.
		 */
		Outchar = vputchar;
	} else {
		if (destcol)
			vclreol();
		vclean();
	}
}

/*
 * Does an ! character follow in the command stream?
 */
int
exclam(void)
{

	if (peekchar() == '!') {
		ignchar();
		return (1);
	}
	return (0);
}

/*
 * Make an argument list for e.g. next.
 */
void
makargs(void)
{

	glob(&frob);
	argc0 = frob.argc0;
	argv0 = frob.argv;
	args0 = argv0[0];
	erewind();
}

/*
 * Advance to next file in argument list.
 */
void
next(void)
{
	extern short isalt;	/* defined in ex_io.c */

	if (argc == 0)
		error(value(vi_TERSE) ?
			(unsigned char *)gettext("No more files") :
			(unsigned char *)gettext("No more files to edit"));
	morargc = argc;
	isalt = (strcmp(altfile, args)==0) + 1;
	if (savedfile[0])
		CP(altfile, savedfile);
	(void) strlcpy(savedfile, args, sizeof (savedfile));
	argc--;
	args = argv ? *++argv : strend(args) + 1;
#if i386 || i286
	destcol = 0;
#endif
}

/*
 * Eat trailing flags and offsets after a command,
 * saving for possible later post-command prints.
 */
void
donewline(void)
{
	int c;

	resetflav();
	for (;;) {
		c = getchar();
		switch (c) {

		case '^':
		case '-':
			poffset--;
			break;

		case '+':
			poffset++;
			break;

		case 'l':
			listf++;
			break;

		case '#':
			nflag++;
			break;

		case 'p':
			listf = 0;
			break;

		case ' ':
		case '\t':
			continue;

		case '"':
			comment();
			setflav();
			return;

		default:
			if (!endcmd(c))
			    serror(value(vi_TERSE) ?
				(unsigned char *)gettext("Extra chars") :
				(unsigned char *)gettext(
				"Extra characters at end of \"%s\" command"),
				    Command);
			if (c == EOF)
				ungetchar(c);
			setflav();
			return;
		}
		pflag++;
	}
}

/*
 * Before quit or respec of arg list, check that there are
 * no more files in the arg list.
 */
int
nomore(void)
{

	if (argc == 0 || morargc == argc)
		return(0);
	morargc = argc;
	if (argc == 1) {
		merror(value(vi_TERSE) ? gettext("1 more file") :
		       gettext("1 more file to edit"), argc);
	} else {
		merror(value(vi_TERSE) ? gettext("%d more files") :
			gettext("%d more files to edit"), argc);
	}
	return(1);
}

/*
 * Before edit of new file check that either an ! follows
 * or the file has not been changed.
 */
int
quickly(void)
{

	if (exclam())
		return (1);
	if (chng && dol > zero) {
/*
		chng = 0;
*/
		xchng = 0;
		error(value(vi_TERSE) ? (unsigned char *)gettext("No write") :
		    (unsigned char *)
		    gettext("No write since last change (:%s! overrides)"),
		    Command);
	}
	return (0);
}

/*
 * Reset the flavor of the output to print mode with no numbering.
 */
void
resetflav(void)
{

	if (inopen)
		return;
	listf = 0;
	nflag = 0;
	pflag = 0;
	poffset = 0;
	setflav();
}

/*
 * Print an error message with a %s type argument to printf.
 * Message text comes from error message file.
 */
void
serror(unsigned char *str, unsigned char *cp)
{
	tagflg = 0;
	error0();
	smerror(str, cp);
	error1(str);
}

/*
 * Set the flavor of the output based on the flags given
 * and the number and list options to either number or not number lines
 * and either use normally decoded (ARPAnet standard) characters or list mode,
 * where end of lines are marked and tabs print as ^I.
 */
void
setflav(void)
{

	if (inopen)
		return;
	setnumb(nflag || value(vi_NUMBER));
	setlist(listf || value(vi_LIST));
	if (!inopen)
		setoutt();
}

/*
 * Skip white space and tell whether command ends then.
 */
int
skipend(void)
{

	pastwh();
	return (endcmd(peekchar()) && peekchar() != '"');
}

/*
 * Set the command name for non-word commands.
 */
void
tailspec(int c)
{
	static unsigned char foocmd[2];

	foocmd[0] = c;
	Command = foocmd;
}

/*
 * Try to read off the rest of the command word.
 * If alphabetics follow, then this is not the command we seek.
 */
void
tail(unsigned char *comm)
{

	tailprim(comm, 1, 0);
}

void
tail2of(unsigned char *comm)
{

	tailprim(comm, 2, 0);
}

unsigned char	tcommand[20];

void
tailprim(unsigned char *comm, int i, bool notinvis)
{
	unsigned char *cp;
	int c;

	Command = comm;
	for (cp = tcommand; i > 0; i--)
		*cp++ = *comm++;
	while (*comm && peekchar() == *comm)
		*cp++ = getchar(), comm++;
	c = peekchar();
	if (notinvis || (isalpha(c) && isascii(c))) {
		/*
		 * Of the trailing lp funny business, only dl and dp
		 * survive the move from ed to ex.
		 */
		if (tcommand[0] == 'd' && any(c, "lp"))
			goto ret;
		if (tcommand[0] == 's' && any(c, "gcr"))
			goto ret;
		while (cp < &tcommand[19] && isalpha(c = peekchar()) && isascii(c))
			*cp++ = getchar();
		*cp = 0;
		if (notinvis)
			serror(value(vi_TERSE) ?
			    (unsigned char *)gettext("What?") :
			    (unsigned char *)gettext(
			    "%s: No such command from open/visual"), tcommand);
		else
			serror(value(vi_TERSE) ?
			    (unsigned char *)gettext("What?") :
			    (unsigned char *)gettext(
			    "%s: Not an editor command"), tcommand);
	}
ret:
	*cp = 0;
}

/*
 * Continue after a : command from open/visual.
 */
void
vcontin(bool ask)
{

	if (vcnt > 0)
		vcnt = -vcnt;
	if (inopen) {
		if (state != VISUAL) {
			/*
			 * We don't know what a shell command may have left on
			 * the screen, so we move the cursor to the right place
			 * and then put out a newline.  But this makes an extra
			 * blank line most of the time so we only do it for :sh
			 * since the prompt gets left on the screen.
			 *
			 * BUG: :!echo longer than current line \\c
			 * will mess it up.
			 */
			if (state == CRTOPEN) {
				termreset();
				vgoto(WECHO, 0);
			}
			if (!ask) {
				(void) putch('\r');
				(void) putch('\n');
			}
			return;
		}
		if (ask) {
			merror(gettext("[Hit return to continue] "));
			flush();
		}
#ifndef CBREAK
		vraw();
#endif
		if (ask) {
#ifdef notdef
			/*
			 * Gobble ^Q/^S since the tty driver should be eating
			 * them (as far as the user can see)
			 */
			while (peekkey() == CTRL('Q') || peekkey() == CTRL('S'))
				ignore(getkey());
#endif
			if(getkey() == ':') {
				/* Extra newlines, but no other way */
				(void) putch('\n');
				outline = WECHO;
				ungetkey(':');
			}
		}
		vclrech(1);
		if (Peekkey != ':') {
			fixterm();
			putpad((unsigned char *)enter_ca_mode);
			tostart();
		}
	}
}

/*
 * Put out a newline (before a shell escape)
 * if in open/visual.
 */
void
vnfl(void)
{

	if (inopen) {
		if (state != VISUAL && state != CRTOPEN && destline <= WECHO)
			vclean();
		else
			vmoveitup(1, 0);
		vgoto(WECHO, 0);
		vclrbyte(vtube[WECHO], WCOLS);
		tostop();
		/* replaced by the ostop above
		putpad(cursor_normal);
		putpad(key_eol);
		*/
	}
	flush();
}
