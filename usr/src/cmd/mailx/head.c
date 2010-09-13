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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcv.h"

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Routines for processing and detecting headlines.
 */

static char	*copyin(char src[], char **space);
static char	*nextword(char wp[], char wbuf[]);

/*
 * See if the passed line buffer is a mail header.
 * Return true if yes.
 */

int 
ishead(char linebuf[])
{
	register char *cp;
	struct headline hl;
	char parbuf[BUFSIZ];

	cp = linebuf;
	if (strncmp("From ", cp, 5) != 0)
		return(0);
	parse(cp, &hl, parbuf);
	if (hl.l_from == NOSTR) {
		return(0);
	}
	return(1);
}

/*
 * Split a headline into its useful components.
 * Copy the line into dynamic string space, then set
 * pointers into the copied line in the passed headline
 * structure.  Actually, it scans.
 */
void 
parse(char line[], struct headline *hl, char pbuf[])
{
	register char *cp, *dp;
	char *sp;
	char word[LINESIZE];

	hl->l_from = NOSTR;
	hl->l_date = NOSTR;
	cp = line;
	sp = pbuf;

	/*
	 * Skip the first "word" of the line, which should be "From"
	 * anyway.
	 */

	cp = nextword(cp, word);
	dp = nextword(cp, word);
	if (!equal(word, ""))
		hl->l_from = copyin(word, &sp);
	if (dp != NOSTR)
		hl->l_date = copyin(dp, &sp);
}

/*
 * Copy the string on the left into the string on the right
 * and bump the right (reference) string pointer by the length.
 * Thus, dynamically allocate space in the right string, copying
 * the left string into it.
 */

static char *
copyin(char src[], char **space)
{
	register char *cp, *top;
	register int s;

	s = strlen(src);
	cp = *space;
	top = cp;
	strcpy(cp, src);
	cp += s + 1;
	*space = cp;
	return(top);
}

/*
 * Collect a liberal (space, tab delimited) word into the word buffer
 * passed.  Also, return a pointer to the next word following that,
 * or NOSTR if none follow.
 */

static char *
nextword(char wp[], char wbuf[])
{
	register char *cp, *cp2;

	if ((cp = wp) == NOSTR) {
		copy("", wbuf);
		return(NOSTR);
	}
	cp2 = wbuf;
	while (!any(*cp, " \t") && *cp != '\0')
		if (*cp == '"') {
			*cp2++ = *cp++;
			while (*cp != '\0' && *cp != '"')
				*cp2++ = *cp++;
			if (*cp == '"')
				*cp2++ = *cp++;
		} else
			*cp2++ = *cp++;
	*cp2 = '\0';
	while (any(*cp, " \t"))
		cp++;
	if (*cp == '\0')
		return(NOSTR);
	return(cp);
}

/*
 * Copy str1 to str2, return pointer to null in str2.
 */

char *
copy(char *str1, char *str2)
{
	register char *s1, *s2;

	s1 = str1;
	s2 = str2;
	while (*s1)
		*s2++ = *s1++;
	*s2 = 0;
	return(s2);
}

/*
 * Is ch any of the characters in str?
 */

int 
any(int ch, char *str)
{
	register char *f;
	int c;

	f = str;
	c = ch;
	while (*f)
		if (c == *f++)
			return(1);
	return(0);
}
