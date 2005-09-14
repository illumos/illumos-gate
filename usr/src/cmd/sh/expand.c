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

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	UNIX shell
 *
 */

#include	"defs.h"
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<dirent.h>



/*
 * globals (file name generation)
 *
 * "*" in params matches r.e ".*"
 * "?" in params matches r.e. "."
 * "[...]" in params matches character class
 * "[...a-z...]" in params matches a through z.
 *
 */
static void addg(unsigned char *, unsigned char *, unsigned char *,
    unsigned char *);
void makearg(struct argnod *);

int
expand(unsigned char	*as, int rcnt)
{
	int	count;
	DIR	*dirf;
	BOOL	dir = 0;
	unsigned char	*rescan = 0;
	unsigned char 	*slashsav = 0;
	unsigned char	*s, *cs;
	unsigned char *s2 = 0;
	struct argnod	*schain = gchain;
	BOOL	slash;
	int	len;
	wchar_t	wc;

	if (trapnote & SIGSET)
		return (0);
	s = cs = as;
	/*
	 * check for meta chars
	 */
	{
		BOOL open;

		slash = 0;
		open = 0;
		do
		{
			if ((len = mbtowc(&wc, (char *)cs, MB_LEN_MAX)) <= 0) {
				len = 1;
				wc = (unsigned char)*cs;
			}

			cs += len;
			switch (wc) {
			case 0:
				if (rcnt && slash)
					break;
				else
					return (0);

			case '/':
				slash++;
				open = 0;
				continue;

			case '[':
				open++;
				continue;

			case ']':
				if (open == 0)
					continue;

			case '?':
			case '*':
				if (rcnt > slash)
					continue;
				else
					cs--;
				break;

			case '\\':
				cs++;
			default:
				continue;
			}
			break;
		} while (TRUE);
	}

	for (;;) {
		if (cs == s) {
			s = (unsigned char *)nullstr;
			break;
		} else if (*--cs == '/') {
			*cs = 0;
			if (s == cs)
				s = (unsigned char *)"/";
			else {
				/*
				 * push trimmed copy of directory prefix
				 * onto stack
				 */
				s2 = cpystak(s);
				trim(s2);
				s = s2;
			}
			break;
		}
	}

	if ((dirf = opendir(*s ? (char *)s : (char *)".")) != 0)
		dir++;

	/* Let s point to original string because it will be trimmed later */
	if (s2)
		s = as;
	count = 0;
	if (*cs == 0)
		slashsav = cs++; /* remember where first slash in as is */

	/* check for rescan */
	if (dir) {
		unsigned char *rs;
		struct dirent *e;

		rs = cs;
		do /* find next / in as */
		{
			if (*rs == '/') {
				rescan = rs;
				*rs = 0;
				gchain = 0;
			}
		} while (*rs++);

		while ((e = readdir(dirf)) && (trapnote & SIGSET) == 0) {
			if (e->d_name[0] == '.' && *cs != '.')
				continue;

			if (gmatch(e->d_name, cs)) {
				addg(s, (unsigned char *)e->d_name, rescan,
				    slashsav);
				count++;
			}
		}
		(void) closedir(dirf);

		if (rescan) {
			struct argnod	*rchain;

			rchain = gchain;
			gchain = schain;
			if (count) {
				count = 0;
				while (rchain) {
					count += expand(rchain->argval,
							slash + 1);
					rchain = rchain->argnxt;
				}
			}
			*rescan = '/';
		}
	}

	if (slashsav)
		*slashsav = '/';
	return (count);
}

static void
addg(unsigned char *as1, unsigned char *as2, unsigned char *as3,
    unsigned char *as4)
{
	unsigned char	*s1, *s2;
	int	c;
	int		len;
	wchar_t		wc;

	s2 = locstak() + BYTESPERWORD;
	s1 = as1;
	if (as4) {
		while (c = *s1++) {
			if (s2 >= brkend)
				growstak(s2);
			*s2++ = c;
		}
		/*
		 * Restore first slash before the first metacharacter
		 * if as1 is not "/"
		 */
		if (as4 + 1 == s1) {
			if (s2 >= brkend)
				growstak(s2);
			*s2++ = '/';
		}
	}
/* add matched entries, plus extra \\ to escape \\'s */
	s1 = as2;
	for (;;) {
		if ((len = mbtowc(&wc, (char *)s1, MB_LEN_MAX)) <= 0) {
			len = 1;
			wc = (unsigned char)*s1;
		}
		if (s2 >= brkend)
			growstak(s2);

		if (wc == 0) {
			*s2 = *s1++;
			break;
		}

		if (wc == '\\') {
			*s2++ = '\\';
			if (s2 >= brkend)
				growstak(s2);
			*s2++ = '\\';
			s1++;
			continue;
		}
		if ((s2 + len) >= brkend)
			growstak(s2 + len);
		memcpy(s2, s1, len);
		s2 += len;
		s1 += len;
	}
	if (s1 = as3) {
		if (s2 >= brkend)
			growstak(s2);
		*s2++ = '/';
		do
		{
			if (s2 >= brkend)
				growstak(s2);
		}
		while (*s2++ = *++s1);
	}
	makearg((struct argnod *)endstak(s2));
}

void
makearg(struct argnod *args)
{
	args->argnxt = gchain;
	gchain = args;
}
