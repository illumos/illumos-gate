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
 * Copyright 1985-2002 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

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
#include <locale.h>

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Auxiliary functions.
 */

static char	*phrase(char *name, int token, int comma);
static char	*ripoff(register char *buf);

/*
 * Return a pointer to a dynamic copy of the argument.
 */

char *
savestr(char *str)
{
	register char *cp, *cp2, *top;

	for (cp = str; *cp; cp++)
		;
	top = (char *)salloc((unsigned)(cp-str + 1));
	if (top == NOSTR)
		return(NOSTR);
	for (cp = str, cp2 = top; *cp; cp++)
		*cp2++ = *cp;
	*cp2 = 0;
	return(top);
}

/*
 * Announce a fatal error and die.
 */

void
panic(char *str)
{
	fprintf(stderr, gettext("mailx: Panic - %s\n"), str);
	exit(1);
	/* NOTREACHED */
}

/*
 * Touch the named message by setting its MTOUCH flag.
 * Touched messages have the effect of not being sent
 * back to the system mailbox on exit.
 */

void 
touch(int mesg)
{
	register struct message *mp;

	if (mesg < 1 || mesg > msgCount)
		return;
	mp = &message[mesg-1];
	mp->m_flag |= MTOUCH;
	if ((mp->m_flag & MREAD) == 0)
		mp->m_flag |= MREAD|MSTATUS;
}

/*
 * Test to see if the passed file name is a directory.
 * Return true if it is.
 */

int 
isdir(char name[])
{
	struct stat sbuf;

	if (stat(name, &sbuf) < 0)
		return(0);
	return((sbuf.st_mode & S_IFMT) == S_IFDIR);
}

/*
 * Count the number of arguments in the given string raw list.
 */

int 
argcount(char **argv)
{
	register char **ap;

	for (ap = argv; *ap != NOSTR; ap++)
		;	
	return(ap-argv);
}

/*
 * Return the desired header line from the passed message
 * pointer (or NOSTR if the desired header field is not available).
 * Read all the header lines and concatenate multiple instances of
 * the requested header.
 */

char *
hfield(char field[], struct message *mp, char *(*add)(char *, char *))
{
	register FILE *ibuf;
	char linebuf[LINESIZE];
	register long lc;
	char *r = NOSTR;

	ibuf = setinput(mp);
	if ((lc = mp->m_lines) <= 0)
		return(NOSTR);
	if (readline(ibuf, linebuf) < 0)
		return(NOSTR);
	lc--;
	while ((lc = gethfield(ibuf, linebuf, lc)) >= 0)
		if (ishfield(linebuf, field))
			r = (*add)(r, hcontents(linebuf));
	return r;
}

/*
 * Return the next header field found in the given message.
 * Return > 0 if something found, <= 0 elsewise.
 * Must deal with \ continuations & other such fraud.
 */

int
gethfield(
	register FILE *f,
	char linebuf[],
	register long rem)
{
	char line2[LINESIZE];
	register char *cp, *cp2;
	register int c;

	for (;;) {
		if (rem <= 0)
			return(-1);
		if (readline(f, linebuf) < 0)
			return(-1);
		rem--;
		if (strlen(linebuf) == 0)
			return(-1);
		if (isspace(linebuf[0]))
			continue;
		if (!headerp(linebuf))
			return(-1);

		/*
		 * I guess we got a headline.
		 * Handle wraparounding
		 */

		for (;;) {
			if (rem <= 0)
				break;
			c = getc(f);
			ungetc(c, f);
			if (!isspace(c) || c == '\n')
				break;
			if (readline(f, line2) < 0)
				break;
			rem--;
			cp2 = line2;
			for (cp2 = line2; *cp2 != 0 && isspace(*cp2); cp2++)
				;
			if (strlen(linebuf) + strlen(cp2) >=
			    (unsigned)LINESIZE-2)
				break;
			cp = &linebuf[strlen(linebuf)];
			while (cp > linebuf &&
			    (isspace(cp[-1]) || cp[-1] == '\\'))
				cp--;
			*cp++ = ' ';
			for (cp2 = line2; *cp2 != 0 && isspace(*cp2); cp2++)
				;
			nstrcpy(cp, LINESIZE - (cp - linebuf), cp2);
		}
		if ((c = strlen(linebuf)) > 0) {
			cp = &linebuf[c-1];
			while (cp > linebuf && isspace(*cp))
				cp--;
			*++cp = 0;
		}
		return(rem);
	}
	/* NOTREACHED */
}

/*
 * Check whether the passed line is a header line of
 * the desired breed.
 */

int 
ishfield(char linebuf[], char field[])
{
	register char *cp;

	if ((cp = strchr(linebuf, ':')) == NOSTR)
		return(0);
	if (cp == linebuf)
		return(0);
	*cp = 0;
	if (icequal(linebuf, field)) {
		*cp = ':';
		return(1);
	}
	*cp = ':';
	return(0);
}

/*
 * Extract the non label information from the given header field
 * and return it.
 */

char *
hcontents(char hfield[])
{
	register char *cp;

	if ((cp = strchr(hfield, ':')) == NOSTR)
		return(NOSTR);
	cp++;
	while (*cp && isspace(*cp))
		cp++;
	return(cp);
}

/*
 * Compare two strings, ignoring case.
 */

int 
icequal(register char *s1, register char *s2)
{

	while (toupper(*s1++) == toupper(*s2))
		if (*s2++ == 0)
			return(1);
	return(0);
}

/*
 * Copy a string, lowercasing it as we go. Here dstsize is the size of
 * the destination buffer dst.
 */
void 
istrcpy(char *dst, int dstsize, char *src)
{
	register char *cp, *cp2;

	cp2 = dst;
	cp = src;

	while (--dstsize > 0 && *cp != '\0')
		*cp2++ = tolower(*cp++);
	*cp2 = '\0';
}

/*
 * The following code deals with input stacking to do source
 * commands.  All but the current file pointer are saved on
 * the stack.
 */

static	int	ssp = -1;		/* Top of file stack */
static struct sstack {
	FILE	*s_file;		/* File we were in. */
	int	s_cond;			/* Saved state of conditionals */
	int	s_loading;		/* Loading .mailrc, etc. */
} *sstack;

/*
 * Pushdown current input file and switch to a new one.
 * Set the global flag "sourcing" so that others will realize
 * that they are no longer reading from a tty (in all probability).
 */

int 
source(char name[])
{
	register FILE *fi;
	register char *cp;

	if ((cp = expand(name)) == NOSTR)
		return(1);
	if ((fi = fopen(cp, "r")) == NULL) {
		printf(gettext("Unable to open %s\n"), cp);
		return(1);
	}

	if (!maxfiles) {
		if ((maxfiles = (int)ulimit(4, 0)) < 0)
#ifndef _NFILE
# define _NFILE 20
#endif
			maxfiles = _NFILE;
		sstack = (struct sstack *)calloc(maxfiles, sizeof(struct sstack));
		if (sstack == NULL) {
			printf(gettext(
			    "Couldn't allocate memory for sourcing stack\n"));
			fclose(fi);
			return(1);
		}
	}

	sstack[++ssp].s_file = input;
	sstack[ssp].s_cond = cond;
	sstack[ssp].s_loading = loading;
	loading = 0;
	cond = CANY;
	input = fi;
	sourcing++;
	return(0);
}

/*
 * Pop the current input back to the previous level.
 * Update the "sourcing" flag as appropriate.
 */

int 
unstack(void)
{
	if (ssp < 0) {
		printf(gettext("\"Source\" stack over-pop.\n"));
		sourcing = 0;
		return(1);
	}
	fclose(input);
	if (cond != CANY)
		printf(gettext("Unmatched \"if\"\n"));
	cond = sstack[ssp].s_cond;
	loading = sstack[ssp].s_loading;
	input = sstack[ssp--].s_file;
	if (ssp < 0)
		sourcing = loading;
	return(0);
}

/*
 * Touch the indicated file.
 * This is nifty for the shell.
 * If we have the utime() system call, this is better served
 * by using that, since it will work for empty files.
 * On non-utime systems, we must sleep a second, then read.
 */

void 
alter(char name[])
{
	int rc = utime(name, utimep);
	extern int errno;

	if (rc != 0) {
		fprintf(stderr, gettext("Cannot utime %s in aux:alter\n"),
name);
		fprintf(stderr, gettext("Errno: %d\n"), errno);
	}
}

/*
 * Examine the passed line buffer and
 * return true if it is all blanks and tabs.
 */

int 
blankline(const char linebuf[])
{
	register const char *cp;

	for (cp = linebuf; *cp; cp++)
		if (!any(*cp, " \t"))
			return(0);
	return(1);
}

/*
 * Skin an arpa net address according to the RFC 822 interpretation
 * of "host-phrase."
 */
static char *
phrase(char *name, int token, int comma)
{
	register char c;
	register char *cp, *cp2;
	char *bufend, *nbufp;
	int gotlt, lastsp, didq;
	char nbuf[LINESIZE];
	int nesting;

	if (name == NOSTR)
		return(NOSTR);
	if (strlen(name) >= (unsigned)LINESIZE)
		nbufp = (char *)salloc(strlen(name));
	else
		nbufp = nbuf;
	gotlt = 0;
	lastsp = 0;
	bufend = nbufp;
	for (cp = name, cp2 = bufend; (c = *cp++) != 0;) {
		switch (c) {
		case '(':
			/*
				Start of a comment, ignore it.
			*/
			nesting = 1;
			while ((c = *cp) != 0) {
				cp++;
				switch(c) {
				case '\\':
					if (*cp == 0) goto outcm;
					cp++;
					break;
				case '(':
					nesting++;
					break;
				case ')':
					--nesting;
					break;
				}
				if (nesting <= 0) break;
			}
		outcm:
			lastsp = 0;
			break;
		case '"':
			/*
				Start a quoted string.
				Copy it in its entirety.
			*/
			didq = 0;
			while ((c = *cp) != 0) {
				cp++;
				switch (c) {
				case '\\':
					if ((c = *cp) == 0) goto outqs;
					cp++;
					break;
				case '"':
					goto outqs;
				}
				if (gotlt == 0 || gotlt == '<') {
					if (lastsp) {
						lastsp = 0;
						*cp2++ = ' ';
					}
					if (!didq) {
						*cp2++ = '"';
						didq++;
					}
					*cp2++ = c;
				}
			}
		outqs:
			if (didq)
				*cp2++ = '"';
			lastsp = 0;
			break;

		case ' ':
		case '\t':
		case '\n':
			if (token && (!comma || c == '\n')) {
			done:
				cp[-1] = 0;
				return cp;
			}
			lastsp = 1;
			break;

		case ',':
			*cp2++ = c;
			if (gotlt != '<') {
				if (token)
					goto done;
				bufend = cp2;
				gotlt = 0;
			}
			break;

		case '<':
			cp2 = bufend;
			gotlt = c;
			lastsp = 0;
			break;

		case '>':
			if (gotlt == '<') {
				gotlt = c;
				break;
			}

			/* FALLTHROUGH . . . */

		default:
			if (gotlt == 0 || gotlt == '<') {
				if (lastsp) {
					lastsp = 0;
					*cp2++ = ' ';
				}
				*cp2++ = c;
			}
			break;
		}
	}
	*cp2 = 0;
	return (token ? --cp : equal(name, nbufp) ? name :
	    nbufp == nbuf ? savestr(nbuf) : nbufp);
}

char *
skin(char *name)
{
	return phrase(name, 0, 0);
}

/*
 * Here sz is the buffer size of word.
 */
char *
yankword(char *name, char *word, int sz, int comma)
{
	char *cp;

	if (name == 0)
		return 0;
	while (isspace(*name))
		name++;
	if (*name == 0)
		return 0;
	cp = phrase(name, 1, comma);
	nstrcpy(word, sz, name);
	return cp;
}

int 
docomma(char *s)
{
	return s && strpbrk(s, "(<,");
}

/*
 * Fetch the sender's name from the passed message.
 */

char *
nameof(register struct message *mp)
{
	char namebuf[LINESIZE];
	char linebuf[LINESIZE];
	register char *cp, *cp2;
	register FILE *ibuf;
	int first = 1, wint = 0;
	char	*tmp;

	if (value("from") && (cp = hfield("from", mp, addto)) != NOSTR)
		return ripoff(cp);
	ibuf = setinput(mp);
	copy("", namebuf);
	if (readline(ibuf, linebuf) <= 0)
		return(savestr(namebuf));
newname:
	for (cp = linebuf; *cp != ' '; cp++)
		;
	while (any(*cp, " \t"))
		cp++;
	for (cp2 = &namebuf[strlen(namebuf)]; *cp && !any(*cp, " \t") &&
	    cp2-namebuf < LINESIZE-1; *cp2++ = *cp++)
		;
	*cp2 = '\0';
	for (;;) {
		if (readline(ibuf, linebuf) <= 0)
			break;
		if (substr(linebuf,"forwarded by ") != -1)
			continue;
		if (linebuf[0] == 'F')
			cp = linebuf;
		else if (linebuf[0] == '>')
			cp = linebuf + 1;
		else
			break;
		if (strncmp(cp, "From ", 5) != 0)
			break;
		if ((wint = substr(cp, "remote from ")) != -1) {
			cp += wint + 12;
			if (first) {
				copy(cp, namebuf);
				first = 0;
			} else {
				tmp = strrchr(namebuf, '!') + 1;
				nstrcpy(tmp,
					sizeof (namebuf) - (tmp  - namebuf),
					cp);
			}
			nstrcat(namebuf, sizeof (namebuf), "!");
			goto newname;
		} else
			break;
	}
	for (cp = namebuf; *cp == '!'; cp++);
	while (ishost(host, cp))
		cp = strchr(cp, '!') + 1;
	if (value("mustbang") && !strchr(cp, '!')) {
		snprintf(linebuf, sizeof (linebuf), "%s!%s",
			host, cp);
		cp = linebuf;
	}
	if (cp2 = hfield("from", mp, addto))
		return(splice(cp, cp2));
	else
		return(savestr(cp));
}

/*
 * Splice an address into a commented recipient header.
 */
char *
splice(char *addr, char *hdr)
{
	char buf[LINESIZE];
	char *cp, *cp2;

	if (cp = strchr(hdr, '<')) {
		cp2 = strchr(cp, '>');
		if (cp2 == NULL) {
			nstrcpy(buf, sizeof (buf), addr);
		} else {
			snprintf(buf, sizeof (buf), "%.*s%s%s",
				cp - hdr + 1, hdr, addr, cp2);
		}
	} else if (cp = strchr(hdr, '(')) {
		snprintf(buf, sizeof (buf), "%s %s",
			addr, cp);
	} else
		nstrcpy(buf, sizeof (buf), addr);
	return savestr(ripoff(buf));
}

static char *
ripoff(register char *buf)
{
	register char *cp;

	cp = buf + strlen(buf);
	while (--cp >= buf && isspace(*cp));
	if (cp >= buf && *cp == ',')
		cp--;
	*++cp = 0;
	return buf;
}

/*
 * Are any of the characters in the two strings the same?
 */

int 
anyof(register char *s1, register char *s2)
{
	register int c;

	while ((c = *s1++) != 0)
		if (any(c, s2))
			return(1);
	return(0);
}

/*
 * See if the given header field is supposed to be ignored.
 * Fields of the form "Content-*" can't be ignored when saving.
 */
int 
isign(char *field, int saving)
{
	char realfld[BUFSIZ];

	/*
	 * Lower-case the string, so that "Status" and "status"
	 * will hash to the same place.
	 */
	istrcpy(realfld, sizeof (realfld), field);

	if (saving && strncmp(realfld, "content-", 8) == 0)
		return (0);

	if (nretained > 0)
		return (!member(realfld, retain));
	else
		return (member(realfld, ignore));
}

int 
member(register char *realfield, register struct ignore **table)
{
	register struct ignore *igp;

	for (igp = table[hash(realfield)]; igp != 0; igp = igp->i_link)
		if (equal(igp->i_field, realfield))
			return (1);

	return (0);
}

/*
 * This routine looks for string2 in string1.
 * If found, it returns the position string2 is found at,
 * otherwise it returns a -1.
 */
int 
substr(char *string1, char *string2)
{
	int i, j, len1, len2;

	len1 = strlen(string1);
	len2 = strlen(string2);
	for (i = 0; i < len1 - len2 + 1; i++) {
		for (j = 0; j < len2 && string1[i+j] == string2[j]; j++)
			;
		if (j == len2)
			return(i);
	}
	return(-1);
}

/*
 * Copies src to the dstsize buffer at dst. The copy will never
 * overflow the destination buffer and the buffer will always be null
 * terminated.
 */
char *
nstrcpy(char *dst, int dstsize, char *src)
{
	char *cp, *cp2;

	cp2 = dst;
	cp = src;

	while (--dstsize > 0 && *cp != '\0')
		*cp2++ = *cp++;
	*cp2 = '\0';
	return(dst);
}

/*
 * Appends src to the dstsize buffer at dst. The append will never
 * overflow the destination buffer and the buffer will always be null
 * terminated.
 */
char *
nstrcat(char *dst, int dstsize, char *src)
{
	char *cp, *cp2;

	cp2 = dst;
	cp = src;

	while (*cp2 != '\0') {
		cp2++;
		dstsize--;
	}
	while (--dstsize > 0 && *cp != '\0')
		*cp2++ = *cp++;
	*cp2 = '\0';
	return(dst);
}
