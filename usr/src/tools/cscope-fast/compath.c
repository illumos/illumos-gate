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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	compath(pathname)
 *
 *	This compresses pathnames.  All strings of multiple slashes are
 *	changed to a single slash.  All occurrences of "./" are removed.
 *	Whenever possible, strings of "/.." are removed together with
 *	the directory names that they follow.
 *
 *	WARNING: since pathname is altered by this function, it should
 *		 be located in a temporary buffer. This avoids the problem
 *		 of accidently changing strings obtained from makefiles
 *		 and stored in global structures.
 */

#include <string.h>

char *
compath(char *pathname)
{
	char	*nextchar;
	char	*lastchar;
	char	*sofar;
	char	*pnend;

	int	pnlen;

		/*
		 *	do not change the path if it has no "/"
		 */

	if (strchr(pathname, '/') == 0)
		return (pathname);

		/*
		 *	find all strings consisting of more than one '/'
		 */

	for (lastchar = pathname + 1; *lastchar != '\0'; lastchar++)
		if ((*lastchar == '/') && (*(lastchar - 1) == '/')) {

			/*
			 *	find the character after the last slash
			 */

			nextchar = lastchar;
			while (*++lastchar == '/') {
			}

			/*
			 *	eliminate the extra slashes by copying
			 *	everything after the slashes over the slashes
			 */

			sofar = nextchar;
			while ((*nextchar++ = *lastchar++) != '\0')
				;
			lastchar = sofar;
		}

		/*
		 *	find all strings of "./"
		 */

	for (lastchar = pathname + 1; *lastchar != '\0'; lastchar++)
		if ((*lastchar == '/') && (*(lastchar - 1) == '.') &&
		    ((lastchar - 1 == pathname) || (*(lastchar - 2) == '/'))) {

			/*
			 *	copy everything after the "./" over the "./"
			 */

			nextchar = lastchar - 1;
			sofar = nextchar;
			while ((*nextchar++ = *++lastchar) != '\0')
				;
			lastchar = sofar;
		}

		/*
		 *	find each occurrence of "/.."
		 */

	for (lastchar = pathname + 1; *lastchar != '\0'; lastchar++)
		if ((lastchar != pathname) && (*lastchar == '/') &&
		    (*(lastchar + 1) == '.') && (*(lastchar + 2) == '.') &&
		    ((*(lastchar + 3) == '/') || (*(lastchar + 3) == '\0'))) {

			/*
			 *	find the directory name preceding the "/.."
			 */

			nextchar = lastchar - 1;
			while ((nextchar != pathname) &&
			    (*(nextchar - 1) != '/'))
				--nextchar;

			/*
			 *	make sure the preceding directory's name
			 *	is not "." or ".."
			 */

			if ((*nextchar == '.') &&
			    (*(nextchar + 1) == '/') ||
			    ((*(nextchar + 1) == '.') &&
			    (*(nextchar + 2) == '/'))) {
				/* EMPTY */;
			} else {

				/*
				 * 	prepare to eliminate either
				 *	"dir_name/../" or "dir_name/.."
				 */

				if (*(lastchar + 3) == '/')
					lastchar += 4;
				else
					lastchar += 3;

				/*
				 *	copy everything after the "/.." to
				 *	before the preceding directory name
				 */

				sofar = nextchar - 1;
				while ((*nextchar++ = *lastchar++) != '\0');

				lastchar = sofar;

				/*
				 *	if the character before what was taken
				 *	out is '/', set up to check if the
				 *	slash is part of "/.."
				 */

				if ((sofar + 1 != pathname) && (*sofar == '/'))
					--lastchar;
			}
		}

	/*
	 *	if the string is more than a character long and ends
	 *	in '/', eliminate the '/'.
	 */

	pnlen = strlen(pathname);
	pnend = strchr(pathname, '\0') - 1;

	if ((pnlen > 1) && (*pnend == '/')) {
		*pnend-- = '\0';
		pnlen--;
	}

	/*
	 *	if the string has more than two characters and ends in
	 *	"/.", remove the "/.".
	 */

	if ((pnlen > 2) && (*(pnend - 1) == '/') && (*pnend == '.'))
		*--pnend = '\0';

	/*
	 *	if all characters were deleted, return ".";
	 *	otherwise return pathname
	 */

	if (*pathname == '\0')
		(void) strcpy(pathname, ".");

	return (pathname);
}
