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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL
#include <stdlib.h>
#include <string.h>
#else
#include <sys/types.h>
#include <sys/sunddi.h>
#endif
#include <smbsrv/ctype.h>


/*
 *	c	Any non-special character matches itslef
 *	?	Match any character
 *	ab	character 'a' followed by character 'b'
 *	S	Any string of non-special characters
 *	AB	String 'A' followed by string 'B'
 *	*	Any String, including the empty string
 */
int
smb_match(char *patn, char *str)
{
	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			} else {
				return (0);
			}
			/*NOTREACHED*/

#if 0
		case '[':
			int	invert = 0, clower, cupper;

			patn++;
			if (*patn == '!') {
				invert = 1;
				patn++;
			}
			for (;;) {
				clower = *patn;
				if (clower == 0)
					break;
				if (clower == ']') {
					patn++;
					break;
				}
				patn++;
				if (*patn == '-') {
					/* range */
					patn++;
					cupper = *patn;
					if (cupper == 0)
						break;
					patn++;
				} else {
					cupper = clower;
				}
				if (*str < clower || cupper < *str)
					continue;

				/* match */
				if (invert)
					return (0);

				while (*patn && *patn++ != ']')
					;
				str++;
				continue; /* THIS WON`T WORK */
			}
			if (invert) {
				str++;
				continue;
			}
			return (0);

#endif

		case '*':
			patn++;
			if (*patn == 0)
				return (1);

#if 0
			if (*patn != '?' && *patn != '*' && *patn != '[') {
				/* accelerate */
				while (*str) {
					if (*str == *patn &&
					    match(patn+1, str+1))
						return (1);
					str++;
				}
				return (0);
			}
#endif

			while (*str) {
				if (smb_match(patn, str))
					return (1);
				str++;
			}
			return (0);

		default:
			if (*str != *patn)
				return (0);
			str++;
			patn++;
			continue;
		}
	}
}

int
smb_match83(char *patn, char *str83)
{
	int	avail;
	char	*ptr;
	char	name83[14];

	ptr = name83;
	for (avail = 8; (avail > 0) && (*patn != '.') && (*patn != 0);
	    avail--) {
		*(ptr++) = *(patn++);
	}
	while (avail--)
		*(ptr++) = ' ';
	*(ptr++) = '.';

	if (*patn == '.')
		patn++;
	else if (*patn != 0)
		return (0);

	for (avail = 3; (avail > 0) && (*patn != 0); avail--) {
		*(ptr++) = *(patn++);
	}
	if (*patn != 0)
		return (0);

	while (avail--)
		*(ptr++) = ' ';
	*ptr = 0;

	return (smb_match_ci(name83, str83));
}



int
smb_match_ci(char *patn, char *str)
{
	/*
	 * "<" is a special pattern that matches only those names that do
	 * NOT have an extension. "." and ".." are ok.
	 */
	if (strcmp(patn, "<") == 0) {
		if ((strcmp(str, ".") == 0) || (strcmp(str, "..") == 0))
			return (1);
		if (strchr(str, '.') == 0)
			return (1);
		return (0);
	}
	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			} else {
				return (0);
			}
			/*NOTREACHED*/


		case '*':
			patn++;
			if (*patn == 0)
				return (1);

			while (*str) {
				if (smb_match_ci(patn, str))
					return (1);
				str++;
			}
			return (0);

		default:
			if (*str != *patn) {
				int	c1 = *str;
				int	c2 = *patn;

				c1 = mts_tolower(c1);
				c2 = mts_tolower(c2);
				if (c1 != c2)
					return (0);
			}
			str++;
			patn++;
			continue;
		}
	}
	/* NOT REACHED */
}
