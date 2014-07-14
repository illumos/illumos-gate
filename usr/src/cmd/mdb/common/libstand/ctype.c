/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * ASCII versions of ctype character classification functions.  This avoids
 * pulling in the entire locale framework that is in libc.
 */

int
isdigit(int c)
{
	return ((c >= '0' && c <= '9') ? 1 : 0);
}

int
isupper(int c)
{
	return ((c >= 'A' && c <= 'Z') ? 1 : 0);
}


int
islower(int c)
{
	return ((c >= 'a' && c <= 'z') ? 1 : 0);
}

int
isspace(int c)
{
	return (((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n') ||
	    (c == '\v') || (c == '\f')) ? 1 : 0);
}

int
isxdigit(int c)
{
	return ((isdigit(c) || (c >= 'A' && c <= 'F') ||
	    (c >= 'a' && c <= 'f')) ? 1 : 0);
}

int
isalpha(int c)
{
	return ((isupper(c) || islower(c)) ? 1 : 0);
}


int
isalnum(int c)
{
	return ((isalpha(c) || isdigit(c)) ? 1 : 0);
}

int
ispunct(int c)
{
	return (((c >= '!') && (c <= '/')) ||
	    ((c >= ':') && (c <= '@')) ||
	    ((c >= '[') && (c <= '`')) ||
	    ((c >= '{') && (c <= '~')));
}

int
iscntrl(int c)
{
	return ((c < 0x20) || (c == 0x7f));
}

int
isprint(int c)
{
	/*
	 * Almost the inverse of iscntrl, but be careful that c > 0x7f
	 * returns false for everything.
	 */
	return ((c >= ' ') && (c <= '~'));
}

int
isgraph(int c)
{
	/* isgraph is like is print, but excludes <space> */
	return ((c >= '!') && (c <= '~'));
}
