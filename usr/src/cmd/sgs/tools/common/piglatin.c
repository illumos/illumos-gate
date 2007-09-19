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
 *	Copyright 2007 Sun Microsystems, Inc.
 *	All rights reserved.
 *	Use is subject to license terms.
 *
 * Very crude pig latin converter.
 * Piglatin is an encoded form of English that is often used by  children
 * as a game. A piglatin word is formed from an English word by:
 *
 *  .	If the word begins with a consonant, move the consonant to the end of
 *	the word and append the letters "ay". Example: "door" becomes "oorday".
 *
 *  .	If the word begins with a vowel, merely append "way" to the word.
 *	Example: "ate" becomes "ateway
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>

int
main()
{
	char	buffer[32767], * cb, * sb;
	int	ic, ignore = 0, word = 0;

	sb = cb = &buffer[0];
	*sb = '\0';

	while ((ic = getc(stdin)) != EOF) {
		char c = (char)ic;

		/*
		 * Ignore all possible formatting statements.
		 */
		if (c == '%')
			ignore = 1;

		/*
		 * Isolate the word that will be converted.
		 */
		if (isspace(ic) || (ispunct(ic) && ((ignore == 0) ||
		    ((c != '%') && (c != '.') && (c != '#') && (c != '-'))))) {
			char s = buffer[0];

			/*
			 * If we haven't collected any words yet simply
			 * printf the last character.
			 */
			if (word == 0) {
				(void) putc(ic, stdout);
				continue;
			}

			/*
			 * Leave format strings alone - contain "%".
			 * Leave single characters alone, typically
			 * these result from "\n", "\t" etc.
			 */
			if ((ignore == 0) && ((cb - buffer) > 1)) {
				if ((s == 'a') || (s == 'A') ||
				    (s == 'e') || (s == 'E') ||
				    (s == 'i') || (s == 'I') ||
				    (s == 'o') || (s == 'O') ||
				    (s == 'u') || (s == 'U')) {
					/*
					 * Append "way" to the word.
					 */
					(void) strcpy(cb, "way");
				} else {
					/*
					 * Move first letter to the end
					 * of the word and add "ay".
					 */
					sb++;
					*cb = s;
					(void) strcpy(++cb, "ay");
				}
			} else
				*cb = '\0';

			/*
			 * Output the collected buffer, the last character
			 * read and reinitialize pointers for next round.
			 */
			(void) printf("%s", sb);
			(void) putc(ic, stdout);

			sb = cb = &buffer[0];
			word = ignore = 0;

			continue;
		}

		/*
		 * Store this character into the word buffer.
		 */
		*cb++ = c;
		*cb = '\0';
		word = 1;
	}

	return (0);
}
