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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Generally useful tty stuff.
 */

#include "rcv.h"
#include <locale.h>

#ifdef	USG_TTY

static char	*readtty(char pr[], char src[]);
static int	savetty(void);
static void	ttycont(int);

static	int	c_erase;		/* Current erase char */
static	int	c_kill;			/* Current kill char */
static	int	c_intr;			/* interrupt char */
static	int	c_quit;			/* quit character */
static	struct termio savtty;
static	char canonb[LINESIZE];		/* canonical buffer for input */
					/* processing */

#ifndef TIOCSTI
static void	Echo(int cc);
static int	countcol(void);
static void	outstr(register char *s);
static void	resetty(void);
static void	rubout(register char *cp);
static int	setty(void);

static	int	c_word;			/* Current word erase char */
static	int	Col;			/* current output column */
static	int	Pcol;			/* end column of prompt string */
static	int	Out;			/* file descriptor of stdout */
static	int	erasing;		/* we are erasing characters */
static	struct termio ttybuf;
#else
static	jmp_buf	rewrite;		/* Place to go when continued */
#endif

#ifdef SIGCONT
# ifdef preSVr4
typedef int	sig_atomic_t;
# endif
static	sig_atomic_t	hadcont;		/* Saw continue signal */

/*ARGSUSED*/
static void 
#ifdef	__cplusplus
ttycont(int)
#else
/* ARGSUSED */
ttycont(int s)
#endif
{
	hadcont++;
	longjmp(rewrite, 1);
}

#ifndef TIOCSTI
/*ARGSUSED*/
static void 
ttystop(int s)
{
	resetty();
	kill(mypid, SIGSTOP);
}
#endif
#endif

/*
 * Read all relevant header fields.
 */

int 
grabh(register struct header *hp, int gflags, int subjtop)
{
#ifdef SIGCONT
	void (*savecont)(int);
#ifndef TIOCSTI
	void (*savestop)(int);
#endif
#endif
	if (savetty())
		return -1;
#ifdef SIGCONT
	savecont = sigset(SIGCONT, ttycont);
#ifndef TIOCSTI
	savestop = sigset(SIGTSTP, ttystop);
#endif
#endif
	if (gflags & GTO) {
		hp->h_to = addto(NOSTR, readtty("To: ", hp->h_to));
		if (hp->h_to != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GSUBJECT && subjtop) {
		hp->h_subject = readtty("Subject: ", hp->h_subject);
		if (hp->h_subject != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GCC) {
		hp->h_cc = addto(NOSTR, readtty("Cc: ", hp->h_cc));
		if (hp->h_cc != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GBCC) {
		hp->h_bcc = addto(NOSTR, readtty("Bcc: ", hp->h_bcc));
		if (hp->h_bcc != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GSUBJECT && !subjtop) {
		hp->h_subject = readtty("Subject: ", hp->h_subject);
		if (hp->h_subject != NOSTR)
			hp->h_seq++;
	}
#ifdef SIGCONT
	(void) sigset(SIGCONT, savecont);
#ifndef TIOCSTI
	(void) sigset(SIGTSTP, savestop);
#endif
#endif
	return(0);
}

/*
 * Read up a header from standard input.
 * The source string has the preliminary contents to
 * be read.
 *
 */

static char *
readtty(char pr[], char src[])
{
	int c;
	register char *cp;

#ifndef TIOCSTI
	register char *cp2;

	erasing = 0;
	Col = 0;
	outstr(pr);
	Pcol = Col;
#else
	fputs(pr, stdout);
#endif
	fflush(stdout);
	if (src != NOSTR && (int)strlen(src) > LINESIZE - 2) {
		printf(gettext("too long to edit\n"));
		return(src);
	}
#ifndef TIOCSTI
	if (setty())
		return(src);
	cp2 = src==NOSTR ? "" : src;
	for (cp=canonb; *cp2; cp++, cp2++)
		*cp = *cp2;
	*cp = '\0';
	outstr(canonb);
#else
	cp = src == NOSTR ? "" : src;
	while (c = *cp++) {
		char ch;

		if (c == c_erase || c == c_kill) {
			ch = '\\';
			ioctl(0, TIOCSTI, &ch);
		}
		ch = c;
		ioctl(0, TIOCSTI, &ch);
	}
	cp = canonb;
	*cp = 0;
	if (setjmp(rewrite))
		goto redo;
#endif

	for (;;) {
		fflush(stdout);
#ifdef SIGCONT
		hadcont = 0;
#endif
		c = getc(stdin);

#ifndef TIOCSTI
		if (c==c_erase) {
			if (cp > canonb)
				if (cp[-1]=='\\' && !erasing) {
					*cp++ = (char)c;
					Echo(c);
				} else {
					rubout(--cp);
				}
		} else if (c==c_kill) {
			if (cp > canonb && cp[-1]=='\\') {
				*cp++ = (char)c;
				Echo(c);
			} else while (cp > canonb) {
				rubout(--cp);
			}
		} else if (c==c_word) {
			if (cp > canonb)
				if (cp[-1]=='\\' && !erasing) {
					*cp++ = (char)c;
					Echo(c);
				} else {
					while (--cp >= canonb)
						if (!isspace(*cp))
							break;
						else
							rubout(cp);
					while (cp >= canonb)
						if (!isspace(*cp))
							rubout(cp--);
						else
							break;
					if (cp < canonb)
						cp = canonb;
					else if (*cp)
						cp++;
				}
		} else
#endif
		if (c==EOF || ferror(stdin) || c==c_intr || c==c_quit) {
#ifdef SIGCONT
			if (hadcont) {
#ifndef TIOCSTI
				(void) setty();
				outstr("(continue)\n");
				Col = 0;
				outstr(pr);
				*cp = '\0';
				outstr(canonb);
				clearerr(stdin);
				continue;
#else
			redo:
				hadcont = 0;
				cp = canonb[0] != 0 ? canonb : src;
				clearerr(stdin);
				return(readtty(pr, cp));
#endif
			}
#endif
#ifndef TIOCSTI
			resetty();
#endif
			savedead(c==c_quit? SIGQUIT: SIGINT);
		} else switch (c) {
			case '\n':
			case '\r':
#ifndef TIOCSTI
				resetty();
				putchar('\n');
				fflush(stdout);
#endif
				if (canonb[0]=='\0')
					return(NOSTR);
				return(savestr(canonb));
			default:
				*cp++ = (char)c;
				*cp = '\0';
#ifndef TIOCSTI
				erasing = 0;
				Echo(c);
#endif
		}
	}
}

static int 
savetty(void)
{
	if (ioctl(fileno(stdout), TCGETA, &savtty) < 0)
	{	perror("ioctl");
		return(-1);
	}
	c_erase = savtty.c_cc[VERASE];
	c_kill = savtty.c_cc[VKILL];
	c_intr = savtty.c_cc[VINTR];
	c_quit = savtty.c_cc[VQUIT];
#ifndef TIOCSTI
	c_word = 'W' & 037;	/* erase word character */
	Out = fileno(stdout);
	ttybuf = savtty;
#ifdef	u370
	ttybuf.c_cflag &= ~PARENB;	/* disable parity */
	ttybuf.c_cflag |= CS8;		/* character size = 8 */
#endif	/* u370 */
	ttybuf.c_cc[VTIME] = 0;
	ttybuf.c_cc[VMIN] = 1;
	ttybuf.c_iflag &= ~(BRKINT);
	ttybuf.c_lflag &= ~(ICANON|ISIG|ECHO);
#endif
	return 0;
}

#ifndef TIOCSTI
static int 
setty(void)
{
	if (ioctl(Out, TCSETAW, &ttybuf) < 0) {
		perror("ioctl");
		return(-1);
	}
	return(0);
}

static void 
resetty(void)
{
	if (ioctl(Out, TCSETAW, &savtty) < 0)
		perror("ioctl");
}

static void 
outstr(register char *s)
{
	while (*s)
		Echo(*s++);
}

static void 
rubout(register char *cp)
{
	register int oldcol;
	register int c = *cp;

	erasing = 1;
	*cp = '\0';
	switch (c) {
	case '\t':
		oldcol = countcol();
		do
			putchar('\b');
		while (--Col > oldcol);
		break;
	case '\b':
		if (isprint(cp[-1]))
			putchar(*(cp-1));
		else
			putchar(' ');
		Col++;
		break;
	default:
		if (isprint(c)) {
			fputs("\b \b", stdout);
			Col--;
		}
	}
}

static int 
countcol(void)
{
	register int col;
	register char *s;

	for (col=Pcol, s=canonb; *s; s++)
		switch (*s) {
		case '\t':
			while (++col % 8)
				;
			break;
		case '\b':
			col--;
			break;
		default:
			if (isprint(*s))
				col++;
		}
	return(col);
}

static void 
Echo(int cc)
{
	char c = (char)cc;

	switch (c) {
	case '\t':
		do
			putchar(' ');
		while (++Col % 8);
		break;
	case '\b':
		if (Col > 0) {
			putchar('\b');
			Col--;
		}
		break;
	case '\r':
	case '\n':
		Col = 0;
		fputs("\r\n", stdout);
		break;
	default:
		if (isprint(c)) {
			Col++;
			putchar(c);
		}
	}
}
#endif

#else

#ifdef SIGCONT
static void	signull(int);
#endif

static	int	c_erase;		/* Current erase char */
static	int	c_kill;			/* Current kill char */
static	int	hadcont;		/* Saw continue signal */
static	jmp_buf	rewrite;		/* Place to go when continued */
#ifndef TIOCSTI
static	int	ttyset;			/* We must now do erase/kill */
#endif

/*
 * Read all relevant header fields.
 */

int 
grabh(struct header *hp, int gflags, int subjtop)
{
	struct sgttyb ttybuf;
	void (*savecont)(int);
	register int s;
	int errs;
#ifndef TIOCSTI
	void (*savesigs[2])(int);
#endif

#ifdef SIGCONT
	savecont = sigset(SIGCONT, signull);
#endif
	errs = 0;
#ifndef TIOCSTI
	ttyset = 0;
#endif
	if (gtty(fileno(stdin), &ttybuf) < 0) {
		perror("gtty");
		return(-1);
	}
	c_erase = ttybuf.sg_erase;
	c_kill = ttybuf.sg_kill;
#ifndef TIOCSTI
	ttybuf.sg_erase = 0;
	ttybuf.sg_kill = 0;
	for (s = SIGINT; s <= SIGQUIT; s++)
		if ((savesigs[s-SIGINT] = sigset(s, SIG_IGN)) == SIG_DFL)
			sigset(s, SIG_DFL);
#endif
	if (gflags & GTO) {
#ifndef TIOCSTI
		if (!ttyset && hp->h_to != NOSTR)
			ttyset++, stty(fileno(stdin), &ttybuf);
#endif
		hp->h_to = addto(NOSTR, readtty("To: ", hp->h_to));
		if (hp->h_to != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GSUBJECT && subjtop) {
#ifndef TIOCSTI
		if (!ttyset && hp->h_subject != NOSTR)
			ttyset++, stty(fileno(stdin), &ttybuf);
#endif
		hp->h_subject = readtty("Subject: ", hp->h_subject);
		if (hp->h_subject != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GCC) {
#ifndef TIOCSTI
		if (!ttyset && hp->h_cc != NOSTR)
			ttyset++, stty(fileno(stdin), &ttybuf);
#endif
		hp->h_cc = addto(NOSTR, readtty("Cc: ", hp->h_cc));
		if (hp->h_cc != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GBCC) {
#ifndef TIOCSTI
		if (!ttyset && hp->h_bcc != NOSTR)
			ttyset++, stty(fileno(stdin), &ttybuf);
#endif
		hp->h_bcc = addto(NOSTR, readtty("Bcc: ", hp->h_bcc));
		if (hp->h_bcc != NOSTR)
			hp->h_seq++;
	}
	if (gflags & GSUBJECT && !subjtop) {
#ifndef TIOCSTI
		if (!ttyset && hp->h_subject != NOSTR)
			ttyset++, stty(fileno(stdin), &ttybuf);
#endif
		hp->h_subject = readtty("Subject: ", hp->h_subject);
		if (hp->h_subject != NOSTR)
			hp->h_seq++;
	}
#ifdef SIGCONT
	sigset(SIGCONT, savecont);
#endif
#ifndef TIOCSTI
	ttybuf.sg_erase = c_erase;
	ttybuf.sg_kill = c_kill;
	if (ttyset)
		stty(fileno(stdin), &ttybuf);
	for (s = SIGINT; s <= SIGQUIT; s++)
		sigset(s, savesigs[s-SIGINT]);
#endif
	return(errs);
}

/*
 * Read up a header from standard input.
 * The source string has the preliminary contents to
 * be read.
 *
 */

char *
readtty(char pr[], char src[])
{
	char ch, canonb[LINESIZE];
	int c;
	register char *cp, *cp2;

	fputs(pr, stdout);
	fflush(stdout);
	if (src != NOSTR && strlen(src) > LINESIZE - 2) {
		printf(gettext("too long to edit\n"));
		return(src);
	}
#ifndef TIOCSTI
	if (src != NOSTR)
		cp = copy(src, canonb);
	else
		cp = copy("", canonb);
	fputs(canonb, stdout);
	fflush(stdout);
#else
	cp = src == NOSTR ? "" : src;
	while (c = *cp++) {
		if (c == c_erase || c == c_kill) {
			ch = '\\';
			ioctl(0, TIOCSTI, &ch);
		}
		ch = c;
		ioctl(0, TIOCSTI, &ch);
	}
	cp = canonb;
	*cp = 0;
#endif
	cp2 = cp;
	while (cp2 < canonb + LINESIZE)
		*cp2++ = 0;
	cp2 = cp;
	if (setjmp(rewrite))
		goto redo;
#ifdef SIGCONT
	sigset(SIGCONT, ttycont);
#endif
	clearerr(stdin);
	while (cp2 < canonb + LINESIZE) {
		c = getc(stdin);
		if (c == EOF || c == '\n')
			break;
		*cp2++ = c;
	}
	*cp2 = 0;
#ifdef SIGCONT
	sigset(SIGCONT, signull);
#endif
	if (c == EOF && ferror(stdin) && hadcont) {
redo:
		hadcont = 0;
		cp = strlen(canonb) > 0 ? canonb : NOSTR;
		clearerr(stdin);
		return(readtty(pr, cp));
	}
	clearerr(stdin);
#ifndef TIOCSTI
	if (cp == NOSTR || *cp == '\0')
		return(src);
	cp2 = cp;
	if (!ttyset)
		return(strlen(canonb) > 0 ? savestr(canonb) : NOSTR);
	while (*cp != '\0') {
		c = *cp++;
		if (c == c_erase) {
			if (cp2 == canonb)
				continue;
			if (cp2[-1] == '\\') {
				cp2[-1] = c;
				continue;
			}
			cp2--;
			continue;
		}
		if (c == c_kill) {
			if (cp2 == canonb)
				continue;
			if (cp2[-1] == '\\') {
				cp2[-1] = c;
				continue;
			}
			cp2 = canonb;
			continue;
		}
		*cp2++ = c;
	}
	*cp2 = '\0';
#endif
	if (equal("", canonb))
		return(NOSTR);
	return(savestr(canonb));
}

#ifdef SIGCONT
/*
 * Receipt continuation.
 */
/*ARGSUSED*/
void 
ttycont(int)
{

	hadcont++;
	longjmp(rewrite, 1);
}

/*
 * Null routine to allow us to hold SIGCONT
 */
/*ARGSUSED*/
static void 
signull(int)
{}
#endif
#endif	/* USG_TTY */
