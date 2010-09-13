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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

/*
 * generate a vector of pointers (arps) to the
 * substrings in string "s".
 * Each substring is separated by blanks and/or tabs.
 *	s	-> string to analyze -- s GETS MODIFIED
 *	arps	-> array of pointers -- count + 1 pointers
 *	count	-> max number of fields
 * returns:
 *	i	-> # of subfields
 *	arps[i] = NULL
 */

GLOBAL int
getargs(s, arps, count)
register char *s, *arps[];
register int count;
{
	register int i;
	char	*prev;

	prev = _uu_setlocale(LC_ALL, "C");
	for (i = 0; i < count; i++) {
		while (*s == ' ' || *s == '\t')
			*s++ = '\0';
		if (*s == '\n')
			*s = '\0';
		if (*s == '\0')
			break;
		arps[i] = s++;
		while (*s != '\0' && *s != ' '
			&& *s != '\t' && *s != '\n')
				s++;
	}
	arps[i] = NULL;
	(void) _uu_resetlocale(LC_ALL, prev);
	return(i);
}

/*
 *      bsfix(args) - remove backslashes from args
 *
 *      \123 style strings are collapsed into a single character
 *	\000 gets mapped into \N for further processing downline.
 *      \ at end of string is removed
 *	\t gets replaced by a tab
 *	\n gets replaced by a newline
 *	\r gets replaced by a carriage return
 *	\b gets replaced by a backspace
 *	\s gets replaced by a blank 
 *	any other unknown \ sequence is left intact for further processing
 *	downline.
 */

GLOBAL void
bsfix (args)
char **args;
{
	register char *str, *to, *cp;
	register int num;
	char	*prev;

	prev = _uu_setlocale(LC_ALL, "C");
	for (; *args; args++) {
		str = *args;
		for (to = str; *str; str++) {
			if (*str == '\\') {
				if (str[1] == '\0')
					break;
				switch (*++str) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					for ( num = 0, cp = str
					    ; cp - str < 3
					    ; cp++
					    ) {
						if ('0' <= *cp && *cp <= '7') {
							num <<= 3;
							num += *cp - '0';
						}
						else
						    break;
					}
					if (num == 0) {
						*to++ = '\\';
						*to++ = 'N';
					} else
						*to++ = (char) num;
					str = cp-1;
					break;

				case 't':
					*to++ = '\t';
					break;

				case 's':	
					*to++ = ' ';
					break;

				case 'n':
					*to++ = '\n';
					break;

				case 'r':
					*to++ = '\r';
					break;

				case 'b':
					*to++ = '\b';
					break;

				default:
					*to++ = '\\';
					*to++ = *str;
					break;
				}
			}
			else
				*to++ = *str;
		}
		*to = '\0';
	}
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}

/*
** This routine is used so that the current
** locale can be saved and then restored. 
*/
char *
_uu_setlocale(int category, char *locale)
{
	char *tmp, *ret;
	int len;

	/* get current locale */
	if ((tmp = setlocale(category, NULL)) == NULL)
		return (NULL); 

	/* allocate space for the current locale and copy it */
	len = strlen(tmp) + 1;

	if ((ret = malloc(len)) == NULL)
		return ((char *) 0);

	strncpy(ret, tmp, len);

	/* now set the new locale */
	if (setlocale(category, locale) == NULL) {
		free(ret);
		return ((char *) 0);
	}
	return (ret);
}

/*
** Reset the previous locale, free memory
*/
void
_uu_resetlocale(int category, char *locale)
{
	if (locale == NULL)
		return;
	(void) setlocale(category, locale);
	free(locale);
}
