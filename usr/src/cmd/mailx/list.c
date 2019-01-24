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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved   */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include "rcv.h"
#include <locale.h>
#include <stdlib.h>
#include <string.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Message list handling.
 */

static int	check(int mesg, int f);
static int	evalcol(int col);
static int	isinteger(char *buf);
static void	mark(int mesg);
static int	markall(char buf[], int f);
static int	matchsubj(char *str, int mesg);
static int	metamess(int meta, int f);
static void	regret(int token);
static int	scan(char **sp);
static void	scaninit(void);
static int	sender(char *str, int mesg);
static void	unmark(int mesg);

/*
 * Process message operand list.
 * Convert the user string of message numbers and
 * store the numbers into vector.
 *
 * Returns the count of messages picked up or -1 on error.
 */
int
getmessage(char *buf, int *vector, int flags)
{
	int *ip;
	struct message *mp;
	int firstmsg = -1;
	char delims[] = "\t- ";
	char *result  = NULL;

	if (markall(buf, flags) < 0)
		return (-1);
	ip = vector;

	/*
	 * Check for first message number and make sure it is
	 * at the beginning of the vector.
	 */
	result = strtok(buf, delims);
	if (result != NULL && isinteger(result)) {
		firstmsg = atoi(result);
		*ip++ = firstmsg;
	}

	/*
	 * Add marked messages to vector and skip first
	 * message number because it is already at the
	 * beginning of the vector
	 */
	for (mp = &message[0]; mp < &message[msgCount]; mp++) {
		if (firstmsg == mp - &message[0] + 1)
			continue;
		if (mp->m_flag & MMARK)
			*ip++ = mp - &message[0] + 1;
	}
	*ip = 0;
	return (ip - vector);
}

/*
 * Check to see if string is an integer
 *
 * Returns 1 if is an integer and 0 if it is not
 */
static int
isinteger(char *buf)
{
	int i, result = 1;

	/* check for empty string */
	if (strcmp(buf, "") == 0) {
		result = 0;
		return (result);
	}

	i = 0;
	while (buf[i] != '\0') {
		if (!isdigit(buf[i])) {
			result = 0;
			break;
		}
		i++;
	}
	return (result);
}

/*
 * Process msglist operand list.
 * Convert the user string of message numbers and
 * store the numbers into vector.
 *
 * Returns the count of messages picked up or -1 on error.
 */

int
getmsglist(char *buf, int *vector, int flags)
{
	int *ip;
	struct message *mp;

	if (markall(buf, flags) < 0)
		return (-1);
	ip = vector;
	for (mp = &message[0]; mp < &message[msgCount]; mp++)
		if (mp->m_flag & MMARK)
			*ip++ = mp - &message[0] + 1;
	*ip = 0;
	return (ip - vector);
}


/*
 * Mark all messages that the user wanted from the command
 * line in the message structure.  Return 0 on success, -1
 * on error.
 */

/*
 * Bit values for colon modifiers.
 */

#define	CMNEW		01		/* New messages */
#define	CMOLD		02		/* Old messages */
#define	CMUNREAD	04		/* Unread messages */
#define	CMDELETED	010		/* Deleted messages */
#define	CMREAD		020		/* Read messages */

/*
 * The following table describes the letters which can follow
 * the colon and gives the corresponding modifier bit.
 */

static struct coltab {
	char	co_char;		/* What to find past : */
	int	co_bit;			/* Associated modifier bit */
	int	co_mask;		/* m_status bits to mask */
	int	co_equal;		/* ... must equal this */
} coltab[] = {
	'n',		CMNEW,		MNEW,		MNEW,
	'o',		CMOLD,		MNEW,		0,
	'u',		CMUNREAD,	MREAD,		0,
	'd',		CMDELETED,	MDELETED,	MDELETED,
	'r',		CMREAD,		MREAD,		MREAD,
	0,		0,		0,		0
};

static	int	lastcolmod;

static int
markall(char buf[], int f)
{
	char **np;
	int i;
	struct message *mp;
	char *namelist[NMLSIZE], *bufp;
	int tok, beg, mc, star, other, colmod, colresult;

	colmod = 0;
	for (i = 1; i <= msgCount; i++)
		unmark(i);
	bufp = buf;
	mc = 0;
	np = &namelist[0];
	scaninit();
	tok = scan(&bufp);
	star = 0;
	other = 0;
	beg = 0;
	while (tok != TEOL) {
		switch (tok) {
		case TNUMBER:
number:
			if (star) {
				printf(gettext("No numbers mixed with *\n"));
				return (-1);
			}
			mc++;
			other++;
			if (beg != 0) {
				if (check(lexnumber, f))
					return (-1);
				for (i = beg; i <= lexnumber; i++)
					if ((message[i-1].m_flag&MDELETED) == f)
						mark(i);
				beg = 0;
				break;
			}
			beg = lexnumber;
			if (check(beg, f))
				return (-1);
			tok = scan(&bufp);
			if (tok != TDASH) {
				regret(tok);
				mark(beg);
				beg = 0;
			}
			break;

		case TSTRING:
			if (beg != 0) {
				printf(gettext(
				    "Non-numeric second argument\n"));
				return (-1);
			}
			other++;
			if (lexstring[0] == ':') {
				colresult = evalcol(lexstring[1]);
				if (colresult == 0) {
					printf(gettext(
					    "Unknown colon modifier \"%s\"\n"),
					    lexstring);
					return (-1);
				}
				colmod |= colresult;
			}
			else
				*np++ = savestr(lexstring);
			break;

		case TDASH:
		case TPLUS:
		case TDOLLAR:
		case TUP:
		case TDOT:
			lexnumber = metamess(lexstring[0], f);
			if (lexnumber == -1)
				return (-1);
			goto number;

		case TSTAR:
			if (other) {
				printf(gettext(
				    "Can't mix \"*\" with anything\n"));
				return (-1);
			}
			star++;
			break;
		}
		tok = scan(&bufp);
	}
	lastcolmod = colmod;
	*np = NOSTR;
	mc = 0;
	if (star) {
		for (i = 0; i < msgCount; i++)
			if ((message[i].m_flag & MDELETED) == f) {
				mark(i+1);
				mc++;
			}
		if (mc == 0) {
			printf(gettext("No applicable messages\n"));
			return (-1);
		}
		return (0);
	}

	/*
	 * If no numbers were given, mark all of the messages,
	 * so that we can unmark any whose sender was not selected
	 * if any user names were given.
	 */

	if ((np > namelist || colmod != 0) && mc == 0)
		for (i = 1; i <= msgCount; i++)
			if ((message[i-1].m_flag & MDELETED) == f)
				mark(i);

	/*
	 * If any names were given, go through and eliminate any
	 * messages whose senders were not requested.
	 */

	if (np > namelist) {
		for (i = 1; i <= msgCount; i++) {
			for (mc = 0, np = &namelist[0]; *np != NOSTR; np++)
				if (**np == '/') {
					if (matchsubj(*np, i)) {
						mc++;
						break;
					}
				} else {
					if (sender(*np, i)) {
						mc++;
						break;
					}
				}
			if (mc == 0)
				unmark(i);
		}

		/*
		 * Make sure we got some decent messages.
		 */

		mc = 0;
		for (i = 1; i <= msgCount; i++)
			if (message[i-1].m_flag & MMARK) {
				mc++;
				break;
			}
		if (mc == 0) {
			printf(gettext("No applicable messages from {%s"),
namelist[0]);
			for (np = &namelist[1]; *np != NOSTR; np++)
				printf(", %s", *np);
			printf("}\n");
			return (-1);
		}
	}

	/*
	 * If any colon modifiers were given, go through and
	 * unmark any messages which do not satisfy the modifiers.
	 */

	if (colmod != 0) {
		for (i = 1; i <= msgCount; i++) {
			struct coltab *colp;

			mp = &message[i - 1];
			for (colp = &coltab[0]; colp->co_char; colp++)
				if (colp->co_bit & colmod)
					if ((mp->m_flag & colp->co_mask)
					    != colp->co_equal)
						unmark(i);

		}
		for (mp = &message[0]; mp < &message[msgCount]; mp++)
			if (mp->m_flag & MMARK)
				break;
		if (mp >= &message[msgCount]) {
			struct coltab *colp;

			printf(gettext("No messages satisfy"));
			for (colp = &coltab[0]; colp->co_char; colp++)
				if (colp->co_bit & colmod)
					printf(" :%c", colp->co_char);
			printf("\n");
			return (-1);
		}
	}
	return (0);
}

/*
 * Turn the character after a colon modifier into a bit
 * value.
 */
static int
evalcol(int col)
{
	struct coltab *colp;

	if (col == 0)
		return (lastcolmod);
	for (colp = &coltab[0]; colp->co_char; colp++)
		if (colp->co_char == col)
			return (colp->co_bit);
	return (0);
}

/*
 * Check the passed message number for legality and proper flags.
 */
static int
check(int mesg, int f)
{
	struct message *mp;

	if (mesg < 1 || mesg > msgCount) {
		printf(gettext("%d: Invalid message number\n"), mesg);
		return (-1);
	}
	mp = &message[mesg-1];
	if ((mp->m_flag & MDELETED) != f) {
		printf(gettext("%d: Inappropriate message\n"), mesg);
		return (-1);
	}
	return (0);
}

/*
 * Scan out the list of string arguments, shell style
 * for a RAWLIST.
 */

int
getrawlist(char line[], char **argv, int argc)
{
	char **ap, *cp, *cp2;
	char linebuf[LINESIZE], quotec;
	char **last;

	ap = argv;
	cp = line;
	last = argv + argc - 1;
	while (*cp != '\0') {
		while (any(*cp, " \t"))
			cp++;
		cp2 = linebuf;
		quotec = 0;
		while (*cp != '\0') {
			if (quotec) {
				if (*cp == quotec) {
					quotec = 0;
					cp++;
				} else
					*cp2++ = *cp++;
			} else {
				if (*cp == '\\') {
					if (*(cp+1) != '\0') {
						*cp2++ = *++cp;
						cp++;
					} else {
						printf(gettext(
						    "Trailing \\; ignoring\n"));
						break;
					}
				}
				if (any(*cp, " \t"))
					break;
				if (any(*cp, "'\""))
					quotec = *cp++;
				else
					*cp2++ = *cp++;
			}
		}
		*cp2 = '\0';
		if (cp2 == linebuf)
			break;
		if (ap >= last) {
			printf(gettext("Too many elements in the list;"
			    " excess discarded\n"));
			break;
		}
		*ap++ = savestr(linebuf);
	}
	*ap = NOSTR;
	return (ap-argv);
}

/*
 * scan out a single lexical item and return its token number,
 * updating the string pointer passed **p.  Also, store the value
 * of the number or string scanned in lexnumber or lexstring as
 * appropriate.  In any event, store the scanned `thing' in lexstring.
 */

static struct lex {
	char	l_char;
	char	l_token;
} singles[] = {
	'$',	TDOLLAR,
	'.',	TDOT,
	'^',	TUP,
	'*',	TSTAR,
	'-',	TDASH,
	'+',	TPLUS,
	'(',	TOPEN,
	')',	TCLOSE,
	0,	0
};

static int
scan(char **sp)
{
	char *cp, *cp2;
	char c;
	struct lex *lp;
	int quotec;

	if (regretp >= 0) {
		copy(stringstack[regretp], lexstring);
		lexnumber = numberstack[regretp];
		return (regretstack[regretp--]);
	}
	cp = *sp;
	cp2 = lexstring;
	c = *cp++;

	/*
	 * strip away leading white space.
	 */

	while (any(c, " \t"))
		c = *cp++;

	/*
	 * If no characters remain, we are at end of line,
	 * so report that.
	 */

	if (c == '\0') {
		*sp = --cp;
		return (TEOL);
	}

	/*
	 * If the leading character is a digit, scan
	 * the number and convert it on the fly.
	 * Return TNUMBER when done.
	 */

	if (isdigit(c)) {
		lexnumber = 0;
		while (isdigit(c)) {
			lexnumber = lexnumber*10 + c - '0';
			*cp2++ = c;
			c = *cp++;
		}
		*cp2 = '\0';
		*sp = --cp;
		return (TNUMBER);
	}

	/*
	 * Check for single character tokens; return such
	 * if found.
	 */

	for (lp = &singles[0]; lp->l_char != 0; lp++)
		if (c == lp->l_char) {
			lexstring[0] = c;
			lexstring[1] = '\0';
			*sp = cp;
			return (lp->l_token);
		}

	/*
	 * We've got a string!  Copy all the characters
	 * of the string into lexstring, until we see
	 * a null, space, or tab.
	 * If the lead character is a " or ', save it
	 * and scan until you get another.
	 */

	quotec = 0;
	if (any(c, "'\"")) {
		quotec = c;
		c = *cp++;
	}
	while (c != '\0') {
		if (quotec == 0 && c == '\\') {
			if (*cp != '\0') {
				c = *cp++;
			} else {
				fprintf(stderr, gettext("Trailing \\; "
				    "ignoring\n"));
			}
		}
		if (c == quotec) {
			cp++;
			break;
		}
		if (quotec == 0 && any(c, " \t"))
			break;
		if (cp2 - lexstring < STRINGLEN-1)
			*cp2++ = c;
		c = *cp++;
	}
	if (quotec && c == 0)
		fprintf(stderr, gettext("Missing %c\n"), quotec);
	*sp = --cp;
	*cp2 = '\0';
	return (TSTRING);
}

/*
 * Unscan the named token by pushing it onto the regret stack.
 */

static void
regret(int token)
{
	if (++regretp >= REGDEP)
		panic("Too many regrets");
	regretstack[regretp] = token;
	lexstring[STRINGLEN-1] = '\0';
	stringstack[regretp] = savestr(lexstring);
	numberstack[regretp] = lexnumber;
}

/*
 * Reset all the scanner global variables.
 */

static void
scaninit(void)
{
	regretp = -1;
}

/*
 * Find the first message whose flags & m == f  and return
 * its message number.
 */

int
first(int f, int m)
{
	int mesg;
	struct message *mp;

	mesg = dot - &message[0] + 1;
	f &= MDELETED;
	m &= MDELETED;
	for (mp = dot; mp < &message[msgCount]; mp++) {
		if ((mp->m_flag & m) == f)
			return (mesg);
		mesg++;
	}
	mesg = dot - &message[0];
	for (mp = dot-1; mp >= &message[0]; mp--) {
		if ((mp->m_flag & m) == f)
			return (mesg);
		mesg--;
	}
	return (0);
}

/*
 * See if the passed name sent the passed message number.  Return true
 * if so.
 */
static int
sender(char *str, int mesg)
{
	return (samebody(str, skin(nameof(&message[mesg-1])), TRUE));
}

/*
 * See if the given string matches inside the subject field of the
 * given message.  For the purpose of the scan, we ignore case differences.
 * If it does, return true.  The string search argument is assumed to
 * have the form "/search-string."  If it is of the form "/," we use the
 * previous search string.
 */

static char lastscan[128];

static int
matchsubj(char *str, int mesg)
{
	struct message *mp;
	char *cp, *cp2, *backup;

	str++;
	if (strlen(str) == 0)
		str = lastscan;
	else
		nstrcpy(lastscan, sizeof (lastscan), str);
	mp = &message[mesg-1];

	/*
	 * Now look, ignoring case, for the word in the string.
	 */

	cp = str;
	cp2 = hfield("subject", mp, addone);
	if (cp2 == NOSTR)
		return (0);
	backup = cp2;
	while (*cp2) {
		if (*cp == 0)
			return (1);
		if (toupper(*cp++) != toupper(*cp2++)) {
			cp2 = ++backup;
			cp = str;
		}
	}
	return (*cp == 0);
}

/*
 * Mark the named message by setting its mark bit.
 */

static void
mark(int mesg)
{
	int i;

	i = mesg;
	if (i < 1 || i > msgCount)
		panic("Bad message number to mark");
	message[i-1].m_flag |= MMARK;
}

/*
 * Unmark the named message.
 */

static void
unmark(int mesg)
{
	int i;

	i = mesg;
	if (i < 1 || i > msgCount)
		panic("Bad message number to unmark");
	message[i-1].m_flag &= ~MMARK;
}

/*
 * Return the message number corresponding to the passed meta character.
 */
static int
metamess(int meta, int f)
{
	int c, m;
	struct message *mp;

	c = meta;
	switch (c) {
	case '^':
		/*
		 * First 'good' message left.
		 */
		for (mp = &message[0]; mp < &message[msgCount]; mp++)
			if ((mp->m_flag & MDELETED) == f)
				return (mp - &message[0] + 1);
		printf(gettext("No applicable messages\n"));
		return (-1);

	case '+':
		/*
		 * Next 'good' message left.
		 */
		for (mp = dot + 1; mp < &message[msgCount]; mp++)
			if ((mp->m_flag & MDELETED) == f)
				return (mp - &message[0] + 1);
		printf(gettext("Referencing beyond last message\n"));
		return (-1);

	case '-':
		/*
		 * Previous 'good' message.
		 */
		for (mp = dot - 1; mp >= &message[0]; mp--)
			if ((mp->m_flag & MDELETED) == f)
				return (mp - &message[0] + 1);
		printf(gettext("Referencing before first message\n"));
		return (-1);

	case '$':
		/*
		 * Last 'good message left.
		 */
		for (mp = &message[msgCount-1]; mp >= &message[0]; mp--)
			if ((mp->m_flag & MDELETED) == f)
				return (mp - &message[0] + 1);
		printf(gettext("No applicable messages\n"));
		return (-1);

	case '.':
		/*
		 * Current message.
		 */
		m = dot - &message[0] + 1;
		if ((dot->m_flag & MDELETED) != f) {
			printf(gettext("%d: Inappropriate message\n"), m);
			return (-1);
		}
		return (m);

	default:
		printf(gettext("Unknown metachar (%c)\n"), c);
		return (-1);
	}
}
