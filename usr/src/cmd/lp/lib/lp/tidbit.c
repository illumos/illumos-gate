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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.12	*/

#include "errno.h"
#include "string.h"
#include "sys/types.h"
#include "sys/stat.h"

#if	defined(__STDC__)
#include "stdarg.h"
#else
#include "varargs.h"
#endif

#include "lp.h"

extern char		*boolnames[],
			*numnames[],
			*strnames[];

extern char		*getenv();

ushort_t		tidbit_boolean	= 0;

short			tidbit_number	= 0;

char			*tidbit_string	= 0;

#if	defined(__STDC__)
static int		open_terminfo_file(char *, char *);
#else
static int		open_terminfo_file();
#endif

/*
 * _Getsh() - GET TWO-BYTE SHORT FROM "char *" POINTER PORTABLY
 */

/*
 * "function" to get a short from a pointer.  The short is in a standard
 * format: two bytes, the first is the low order byte, the second is
 * the high order byte (base 256).  The only negative number allowed is
 * -1, which is represented as 255, 255.  This format happens to be the
 * same as the hardware on the pdp-11 and vax, making it fast and
 * convenient and small to do this on a pdp-11.
 */

#if	vax || pdp11 || i386
#define	_Getsh(ip)	(*((short *)((char *)(ip))))
#endif	/* vax || pdp11 || i386 */

/*
 * The following macro is partly due to Mike Laman, laman@sdcsvax
 *	NCR @ Torrey Pines.		- Tony Hansen
 */
#if	u3b || u3b15 || u3b2 || m68000 || sparc
#define	_Getsh(ip)	((short)(*((unsigned char *) ip) | (*(ip+1) << 8)))
#endif	/* u3b || u3b15 || u3b2 || m68000 || sparc */

#ifndef	_Getsh
/*
 * Here is a more portable version, which does not assume byte ordering
 * in shorts, sign extension, etc. It does assume that the C preprocessor
 * does sign-extension the same as on the machine being compiled for.
 * When ANSI C comes along, this should be changed to check <limits.h>
 * to see if the low character value is negative.
 */

static int
#if	defined(__STDC__)
_Getsh(
	register char		*p
)
#else
_Getsh(p)
	register char		*p;
#endif
{
	register int		rv,
				rv2;

#if	-1 == '\377'			/* sign extension occurs */
	rv = (*p++) & 0377;
	rv2 = (*p) & 0377;
#else	/* -1 == '\377' */			/* no sign extension */
	rv = *p++;
	rv2 = *p;
#endif	/* -1 == '\377' */
	if ((rv2 == 0377) && ((rv == 0377) || (rv == 0376)))
		return (-1);
	return (rv + (rv2 * 256));
}
#endif	/* _Getsh */

#define	MAX_TIDBS	32

static struct tidb	{

	int			snames,
				nbools,
				nints,
				nstrs;

	char			*term,
				*tiebuf,
				*boolean_offset,
				*number_offset,
				*string_offset,
				*string_table;

}			tidbs[MAX_TIDBS + 1];	/* one for last ditch */

/*
 * tidbit() - TERMINFO DATABASE LOOKUP
 */

/*
 * Four forms of calling:
 *
 *	tidbit ("term-type", "boolean-cap-name", &ushort)
 *	tidbit ("term-type", "numeric-cap-name", &short)
 *	tidbit ("term-type", "string-cap-name", &charstar)
 *	tidbit ("term-type", "any-cap-name", (char *)0)
 *
 * The last one is chancy, because of the pointer alignment
 * problem, but hey--what the heck. Anyway, the last one
 * causes the value to be stored in one of
 *
 *	ushort  tidbit_boolean;
 *	short   tidbit_number;
 *	char   *tidbit_string;
 *
 * as appropriate, and returns one of 1, 2, or 3 as the type
 * of the capability is boolean, numeric, or string.
 *
 * For example, to extract the size of the screen for a 5410:
 *
 *	short cols, lines;
 *
 *	tidbit ("5410", "cols", &cols);
 *	tidbit ("5410", "lines", &lines);
 *
 * Note that for the lines and columns, this does NOT check
 * the LINES and COLUMNS environment variables nor the window
 * size, if running on a windowing terminal. That can be done
 * by the caller.
 *
 * If first argument is (char *)0, "tidbit()" uses the same TERM
 * used in the last call, or the TERM environment variable if this
 * is the first call.
 * If second argument is (char *)0, no lookup just verification
 * of terminal type.
 *
 * Return is 0 (or 1, 2, 3 as above) if successful, otherwise -1
 * with "errno" set:
 *
 *	ENOENT		can't open Terminfo file for terminal type
 *	EBADF		Terminfo file is corrupted
 *	ENOMEM		malloc failed
 */

/*VARARGS2*/
int
#if	defined(__STDC__)
tidbit(
	char			*term,
	char			*cap,
	...
)
#else
tidbit(term, cap, va_alist)
	char			*term,
				*cap;
	va_dcl
#endif
{
	va_list			ap;

	int			rc;

	register int		i;

	register char		**pp;

	register struct tidb	*pt;

	static char		*last_term;


	if (!term)
		if (last_term)
			term = last_term;
		else {
			term = getenv("TERM");
			if (!term || !*term)
				term = NAME_UNKNOWN;
		}
	if (term != last_term) {
		if (last_term)
			Free(last_term);
		last_term = Strdup(term);
	}

	for (i = 0; i < MAX_TIDBS; i++)
		if (tidbs[i].term && STREQU(tidbs[i].term, term)) {
			pt = &tidbs[i];
			break;
		}

	/*
	 * Not cached, so read the file and cache it.
	 */
	if (i >= MAX_TIDBS) {

		register int		n,
					tfd;

		register char		*terminfo;

		struct stat		statbuf;


		/*
		 * If no empty spot can be found, "i" will index the
		 * last spot, a spare reserved to avoid problems with
		 * a full cache.
		 */
		for (i = 0; i < MAX_TIDBS; i++)
			if (!tidbs[i].term)
				break;
		pt = &tidbs[i];

		tfd = -1;
		if ((terminfo = getenv("TERMINFO")) && *terminfo)
			tfd = open_terminfo_file(terminfo, term);
#if	defined(TERMINFO)
		if (tfd < 0)
			tfd = open_terminfo_file(TERMINFO, term);
#endif
		if (tfd >= 0)
			(void) Fstat(tfd, &statbuf);

		if (tfd < 0 || !statbuf.st_size) {
			errno = ENOENT;
			return (-1);
		}

		if (pt->tiebuf)
			Free(pt->tiebuf);
		if (!(pt->tiebuf = Malloc(statbuf.st_size))) {
			errno = ENOMEM;
			return (-1);
		}

		n = Read(tfd, pt->tiebuf, statbuf.st_size);
		(void) Close(tfd);
		if (n <= 0 || n >= 4096 || _Getsh(pt->tiebuf) != 0432) {
			Free(pt->tiebuf);
			pt->tiebuf = 0;
			errno = EBADF;
			return (-1);
		}

		if (pt->term)
			Free(pt->term);
		if (!(pt->term = Strdup(term))) {
			Free(pt->tiebuf);
			pt->tiebuf = 0;
			errno = ENOMEM;
			return (-1);
		}

		pt->snames = _Getsh(pt->tiebuf + 2);
		pt->nbools = _Getsh(pt->tiebuf + 4);
		pt->nints = _Getsh(pt->tiebuf + 6);
		pt->nstrs = _Getsh(pt->tiebuf + 8);

		pt->boolean_offset = pt->tiebuf + 6 * 2 + pt->snames;

		pt->number_offset = pt->boolean_offset + pt->nbools;
		if ((unsigned int)pt->number_offset & 1)
			pt->number_offset++;

		pt->string_offset = pt->number_offset + pt->nints * 2;

		pt->string_table = pt->string_offset + pt->nstrs * 2;

	}

	rc = 0;

#if	defined(__STDC__)
	va_start(ap, cap);
#else
	va_start(ap);
#endif

	if (!cap || !*cap)
		;

	else if ((pp = wherelist(cap, boolnames))) {
		register ushort_t	*ushort_p;

		register char		*ip;

		register int		index	= pp - boolnames;

		if (!(ushort_p = va_arg(ap, ushort_t *))) {
			ushort_p = &tidbit_boolean;
			rc = 1;
		}

		if (index >= pt->nbools)
			*ushort_p = 0;
		else {
			ip = pt->boolean_offset + index;
			*ushort_p = (*ip & 01);
		}

	} else if ((pp = wherelist(cap, numnames))) {
		register short		*short_p;

		register char		*ip;

		register int		index	= pp - numnames;

		if (!(short_p = va_arg(ap, short *))) {
			short_p = &tidbit_number;
			rc = 2;
		}

		if (index >= pt->nints)
			*short_p = -1;
		else {
			ip = pt->number_offset + index * 2;
			*short_p = _Getsh(ip);
			if (*short_p == -2)
				*short_p = -1;
		}

	} else if ((pp = wherelist(cap, strnames))) {
		register char		**charstar_p;

		register char		*ip;

		register int		index	= pp - strnames;

		register short		sindex;


		if (!(charstar_p = va_arg(ap, char **))) {
			charstar_p = &tidbit_string;
			rc = 3;
		}

		if (index >= pt->nstrs)
			*charstar_p = 0;
		else {
			ip = pt->string_offset + index * 2;
			if ((sindex = _Getsh(ip)) >= 0)
				*charstar_p = pt->string_table + sindex;
			else
				*charstar_p = 0;
		}
	}

	va_end(ap);
	return (rc);
}

/*
 * untidbit() - FREE SPACE ASSOCIATED WITH A TERMINFO ENTRY
 */

void
#if	defined(__STDC__)
untidbit(
	char			*term
)
#else
untidbit(term)
	char			*term;
#endif
{
	register int		i;


	for (i = 0; i < MAX_TIDBS; i++)
		if (tidbs[i].term && STREQU(tidbs[i].term, term)) {
			if (tidbs[i].tiebuf) {
				Free(tidbs[i].tiebuf);
				tidbs[i].tiebuf = 0;
			}
			Free(tidbs[i].term);
			tidbs[i].term = 0;
			break;
		}
}

/*
 * open_terminfo_file() - OPEN FILE FOR TERM ENTRY
 */

static int
#if	defined(__STDC__)
open_terminfo_file(
	char			*terminfo,
	char			*term
)
#else
open_terminfo_file(terminfo, term)
	char			*terminfo,
				*term;
#endif
{
	char			*first_letter	= "X",
				*path;

	int			fd;

	first_letter[0] = term[0];
	path = makepath(terminfo, first_letter, term, (char *)0);

	/* start fix for bugid 1109709	*/
	if (path == NULL) {
		return (-1);
	}
	/* end fix for bugid 1109709	*/

	fd = Open(path, 0);
	Free(path);
	return (fd);
}
