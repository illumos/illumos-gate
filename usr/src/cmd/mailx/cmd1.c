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
 * Copyright 2014 Joyent, Inc.
 */

/*
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
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

#include <err.h>
#include "rcv.h"
#include <locale.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * User commands.
 */

static char	*dispname(char *hdr);
static void	print(register struct message *mp, FILE *obuf, int doign);
static int	type1(int *msgvec, int doign, int page);
static int	topputs(const char *line, FILE *obuf);

void	brokpipe(int sig);
jmp_buf	pipestop;

/*
 * Print the current active headings.
 * Don't change dot if invoker didn't give an argument.
 */

static int curscreen = 0, oldscreensize = 0;

int
headers(int *msgvec)
{
	register int n, mesg, flag;
	register struct message *mp;
	int size;

	size = screensize();
	n = msgvec[0];
	if (n != 0)
		curscreen = (n-1)/size;
	if (curscreen < 0)
		curscreen = 0;
	mp = &message[curscreen * size];
	if (mp >= &message[msgCount])
		mp = &message[msgCount - size];
	if (mp < &message[0])
		mp = &message[0];
	flag = 0;
	mesg = mp - &message[0];
	if (dot != &message[n-1])
		dot = mp;
	if (Hflag)
		mp = message;
	for (; mp < &message[msgCount]; mp++) {
		mesg++;
		if (mp->m_flag & MDELETED)
			continue;
		if (flag++ >= size && !Hflag)
			break;
		printhead(mesg);
		sreset();
	}
	if (flag == 0) {
		printf(gettext("No more mail.\n"));
		return (1);
	}
	return (0);
}

/*
 * Scroll to the next/previous screen
 */

int
scroll(char arg[])
{
	register int s, size;
	int cur[1];

	cur[0] = 0;
	size = screensize();
	s = curscreen;
	switch (*arg) {
	case 0:
	case '+':
		s++;
		if (s * size > msgCount) {
			printf(gettext("On last screenful of messages\n"));
			return (0);
		}
		curscreen = s;
		break;

	case '-':
		if (--s < 0) {
			printf(gettext("On first screenful of messages\n"));
			return (0);
		}
		curscreen = s;
		break;

	default:
		printf(gettext("Unrecognized scrolling command \"%s\"\n"), arg);
		return (1);
	}
	return (headers(cur));
}

/*
 * Compute what the screen size should be.
 * We use the following algorithm:
 *	If user specifies with screen option, use that.
 *	If baud rate < 1200, use  5
 *	If baud rate = 1200, use 10
 *	If baud rate > 1200, use 20
 */
int
screensize(void)
{
	register char *cp;
	register int newscreensize, tmp;
#ifdef	TIOCGWINSZ
	struct winsize ws;
#endif

	if ((cp = value("screen")) != NOSTR && (tmp = atoi(cp)) > 0)
		newscreensize = tmp;
	else if (baud < B1200)
		newscreensize = 5;
	else if (baud == B1200)
		newscreensize = 10;
#ifdef	TIOCGWINSZ
	else if (ioctl(fileno(stdout), TIOCGWINSZ, &ws) == 0 && ws.ws_row > 4)
		newscreensize = ws.ws_row - 4;
#endif
	else
		newscreensize = 20;
	/* renormalize the value of curscreen */
	if (newscreensize != oldscreensize) {
		curscreen = curscreen * oldscreensize / newscreensize;
		oldscreensize = newscreensize;
	}
	return (newscreensize);
}

/*
 * Print out the headlines for each message
 * in the passed message list.
 */

int
from(int *msgvec)
{
	register int *ip;

	for (ip = msgvec; *ip != NULL; ip++) {
		printhead(*ip);
		sreset();
	}
	if (--ip >= msgvec)
		dot = &message[*ip - 1];
	return (0);
}

/*
 * Print out the header of a specific message.
 * This is a slight improvement to the standard one.
 */

void
printhead(int mesg)
{
	struct message *mp;
	FILE *ibuf;
	char headline[LINESIZE], *subjline, dispc, curind;
	char *fromline;
	char pbuf[LINESIZE];
	char name[LINESIZE];
	headline_t *hl;
	register char *cp;
	int showto;

	if (headline_alloc(&hl) != 0) {
		err(1, "could not allocate memory");
	}

	mp = &message[mesg-1];
	ibuf = setinput(mp);
	readline(ibuf, headline);
	if ((subjline = hfield("subject", mp, addone)) == NOSTR &&
	    (subjline = hfield("subj", mp, addone)) == NOSTR &&
	    (subjline = hfield("message-status", mp, addone)) == NOSTR)
		subjline = "";

	curind = (!Hflag && dot == mp) ? '>' : ' ';
	dispc = ' ';
	showto = 0;
	if ((mp->m_flag & (MREAD|MNEW)) == (MREAD|MNEW))
		dispc = 'R';
	if (!(int)value("bsdcompat") && (mp->m_flag & (MREAD|MNEW)) == MREAD)
		dispc = 'O';
	if ((mp->m_flag & (MREAD|MNEW)) == MNEW)
		dispc = 'N';
	if ((mp->m_flag & (MREAD|MNEW)) == 0)
		dispc = 'U';
	if (mp->m_flag & MSAVED)
		if ((int)value("bsdcompat"))
			dispc = '*';
		else
			dispc = 'S';
	if (mp->m_flag & MPRESERVE)
		if ((int)value("bsdcompat"))
			dispc = 'P';
		else
			dispc = 'H';
	if (mp->m_flag & MBOX)
		dispc = 'M';
	if (parse_headline(headline, hl) == -1) {
		headline_reset(hl);
	}
	if (custr_len(hl->hl_date) == 0) {
		if (custr_append(hl->hl_date, "<Unknown date>") != 0) {
			err(1, "could not print header");
		}
	}

	/*
	 * Netnews interface?
	 */

	if (newsflg) {
		if ((fromline = hfield("newsgroups", mp, addone)) == NOSTR &&
		    (fromline = hfield("article-id", mp, addone)) == NOSTR)
			fromline = "<>";
		else
			for (cp = fromline; *cp; cp++) { /* limit length */
				if (any(*cp, " ,\n")) {
					*cp = '\0';
					break;
				}
			}
	/*
	 * else regular.
	 */

	} else {
		fromline = nameof(mp);
		if (value("showto") &&
		    samebody(myname, skin(fromline), FALSE) &&
		    (cp = hfield("to", mp, addto))) {
			showto = 1;
			yankword(cp, fromline = name, sizeof (name),
				docomma(cp));
		}
		if (value("showname"))
			fromline = dispname(fromline);
		else
			fromline = skin(fromline);
	}
	printf("%c%c%3d ", curind, dispc, mesg);
	if ((int)value("showfull")) {
		if (showto)
			printf("To %-15s ", fromline);
		else
			printf("%-18s ", fromline);
	} else {
		if (showto)
			printf("To %-15.15s ", fromline);
		else
			printf("%-18.18s ", fromline);
	}
	if (mp->m_text) {
		printf("%16.16s %4ld/%-5ld %-.25s\n",
		    custr_cstr(hl->hl_date), mp->m_lines, mp->m_size,
		    subjline);
	} else {
		printf("%16.16s binary/%-5ld %-.25s\n", custr_cstr(hl->hl_date),
		    mp->m_size, subjline);
	}

	headline_free(hl);
}

/*
 * Return the full name from an RFC-822 header line
 * or the last two (or one) component of the address.
 */

static char *
dispname(char *hdr)
{
	char *cp, *cp2;

	if (hdr == 0)
		return (0);
	if (((cp = strchr(hdr, '<')) != 0) && (cp > hdr)) {
		*cp = 0;
		if ((*hdr == '"') && ((cp = strrchr(++hdr, '"')) != 0))
			*cp = 0;
		return (hdr);
	} else if ((cp = strchr(hdr, '(')) != 0) {
		hdr = ++cp;
		if ((cp = strchr(hdr, '+')) != 0)
			*cp = 0;
		if ((cp = strrchr(hdr, ')')) != 0)
			*cp = 0;
		return (hdr);
	}
	cp = skin(hdr);
	if ((cp2 = strrchr(cp, '!')) != 0) {
		while (cp2 >= cp && *--cp2 != '!');
		cp = ++cp2;
	}
	return (cp);
}

/*
 * Print out the value of dot.
 */

int
pdot(void)
{
	printf("%d\n", dot - &message[0] + 1);
	return (0);
}

/*
 * Print out all the possible commands.
 */

int
pcmdlist(void)
{
	register const struct cmd *cp;
	register int cc;

	printf("Commands are:\n");
	for (cc = 0, cp = cmdtab; cp->c_name != NULL; cp++) {
		cc += strlen(cp->c_name) + 2;
		if (cc > 72) {
			printf("\n");
			cc = strlen(cp->c_name) + 2;
		}
		if ((cp+1)->c_name != NOSTR)
			printf("%s, ", cp->c_name);
		else
			printf("%s\n", cp->c_name);
	}
	return (0);
}

/*
 * Paginate messages, honor ignored fields.
 */
int
more(int *msgvec)
{
	return (type1(msgvec, 1, 1));
}

/*
 * Paginate messages, even printing ignored fields.
 */
int
More(int *msgvec)
{

	return (type1(msgvec, 0, 1));
}

/*
 * Type out messages, honor ignored fields.
 */
int
type(int *msgvec)
{

	return (type1(msgvec, 1, 0));
}

/*
 * Type out messages, even printing ignored fields.
 */
int
Type(int *msgvec)
{

	return (type1(msgvec, 0, 0));
}

/*
 * Type out the messages requested.
 */
static int
type1(int *msgvec, int doign, int page)
{
	int *ip;
	register struct message *mp;
	register int mesg;
	register char *cp;
	long nlines;
	FILE *obuf;
	void (*sigint)(int), (*sigpipe)(int);
	int setsigs = 0;

	obuf = stdout;
	if (setjmp(pipestop)) {
		if (obuf != stdout) {
			pipef = NULL;
			npclose(obuf);
		}
		goto ret0;
	}
	if (intty && outtty && (page || (cp = value("crt")) != NOSTR)) {
		if (!page) {
			nlines = 0;
			for (ip = msgvec, nlines = 0;
			    *ip && ip-msgvec < msgCount; ip++)
				nlines += message[*ip - 1].m_lines;
		}
		if (page ||
		    nlines > (*cp == '\0' ? screensize() - 2 : atoi(cp))) {
			obuf = npopen(MORE, "w");
			if (obuf == NULL) {
				perror(MORE);
				obuf = stdout;
			} else {
				pipef = obuf;
				sigint = sigset(SIGINT, SIG_IGN);
				sigpipe = sigset(SIGPIPE, brokpipe);
				setsigs++;
			}
		}
	}
	for (ip = msgvec; *ip && ip-msgvec < msgCount; ip++) {
		mesg = *ip;
		touch(mesg);
		mp = &message[mesg-1];
		dot = mp;
		print(mp, obuf, doign);
	}
	if (obuf != stdout) {
		pipef = NULL;
		npclose(obuf);
	}
ret0:
	if (setsigs) {
		sigset(SIGPIPE, sigpipe);
		sigset(SIGINT, sigint);
	}
	return (0);
}

/*
 * Respond to a broken pipe signal --
 * probably caused by user quitting more.
 */
void
#ifdef	__cplusplus
brokpipe(int)
#else
/* ARGSUSED */
brokpipe(int s)
#endif
{
#ifdef OLD_BSD_SIGS
	sigrelse(SIGPIPE);
#endif
	longjmp(pipestop, 1);
}

/*
 * Print the indicated message on standard output.
 */

static void
print(register struct message *mp, FILE *obuf, int doign)
{

	if (value("quiet") == NOSTR && (!doign || !isign("message", 0)))
		fprintf(obuf, "Message %2d:\n", mp - &message[0] + 1);
	touch(mp - &message[0] + 1);
	if (mp->m_text) {
		(void) msend(mp, obuf, doign ? M_IGNORE : 0, fputs);
	} else {
		fprintf(obuf, "\n%s\n", gettext(binmsg));
	}
}

/*
 * Print the top so many lines of each desired message.
 * The number of lines is taken from the variable "toplines"
 * and defaults to 5.
 */

static	long	top_linecount, top_maxlines, top_lineb;
static	jmp_buf	top_buf;

int
top(int *msgvec)
{
	register int *ip;
	register struct message *mp;
	register int mesg;
	char *valtop;

	top_maxlines = 5;
	valtop = value("toplines");
	if (valtop != NOSTR) {
		top_maxlines = atoi(valtop);
		if (top_maxlines < 0 || top_maxlines > 10000)
			top_maxlines = 5;
	}
	top_lineb = 1;
	for (ip = msgvec; *ip && ip-msgvec < msgCount; ip++) {
		mesg = *ip;
		touch(mesg);
		mp = &message[mesg-1];
		dot = mp;
		if (value("quiet") == NOSTR)
			printf("Message %2d:\n", mesg);
		if (!top_lineb)
			printf("\n");
		top_linecount = 0;
		if (setjmp(top_buf) == 0) {
			if (mp->m_text) {
				(void) msend(mp, stdout, M_IGNORE, topputs);
			} else {
				printf("\n%s\n", gettext(binmsg));
			}
		}
	}
	return (0);
}

int
topputs(const char *line, FILE *obuf)
{
	if (top_linecount++ >= top_maxlines)
		longjmp(top_buf, 1);
	top_lineb = blankline(line);
	return (fputs(line, obuf));
}

/*
 * Touch all the given messages so that they will
 * get mboxed.
 */

int
stouch(int msgvec[])
{
	register int *ip;

	for (ip = msgvec; *ip != 0; ip++) {
		dot = &message[*ip-1];
		dot->m_flag |= MTOUCH;
		dot->m_flag &= ~MPRESERVE;
	}
	return (0);
}

/*
 * Make sure all passed messages get mboxed.
 */

int
mboxit(int msgvec[])
{
	register int *ip;

	for (ip = msgvec; *ip != 0; ip++) {
		dot = &message[*ip-1];
		dot->m_flag |= MTOUCH|MBOX;
		dot->m_flag &= ~MPRESERVE;
	}
	return (0);
}

/*
 * List the folders the user currently has.
 */
int
folders(char **arglist)
{
	char dirname[BUFSIZ], cmd[BUFSIZ];

	if (getfold(dirname) < 0) {
		printf(gettext("No value set for \"folder\"\n"));
		return (-1);
	}
	if (*arglist) {
		nstrcat(dirname, sizeof (dirname), "/");
		nstrcat(dirname, sizeof (dirname), *arglist);
	}
	snprintf(cmd, sizeof (cmd), "%s %s", LS, dirname);
	return (system(cmd));
}
