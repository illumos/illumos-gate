/*
 * rfc2047.c -- decode RFC-2047 header format
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static char sccsi2[] = "%W% (Sun) %G%";
#endif

/*
 * Copyright (c) 1997-1998 Richard Coleman
 * All rights reserved.
 *
 * Permission is hereby granted, without written agreement and without
 * license or royalty fees, to use, copy, modify, and distribute this
 * software and to distribute modified versions of this software for any
 * purpose, provided that the above copyright notice and the following two
 * paragraphs appear in all copies of this software.
 *
 * In no event shall Richard Coleman be liable to any party for direct,
 * indirect, special, incidental, or consequential damages arising out of
 * the use of this software and its documentation, even if Richard Coleman
 * has been advised of the possibility of such damage.
 *
 * Richard Coleman specifically disclaims any warranties, including, but
 * not limited to, the implied warranties of merchantability and fitness
 * for a particular purpose.  The software provided hereunder is on an "as
 * is" basis, and Richard Coleman has no obligation to provide maintenance,
 * support, updates, enhancements, or modifications.
 */

/*
 * Parts of this code were derived from metamail, which is ...
 *
 * Copyright (c) 1991 Bell Communications Research, Inc. (Bellcore)
 *
 * Permission to use, copy, modify, and distribute this material 
 * for any purpose and without fee is hereby granted, provided 
 * that the above copyright notice and this permission notice 
 * appear in all copies, and that the name of Bellcore not be 
 * used in advertising or publicity pertaining to this 
 * material without the specific, prior written permission 
 * of an authorized representative of Bellcore.  BELLCORE 
 * MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY 
 * OF THIS MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", 
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
 */

/*
 * Copyright (c) 1998, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <string.h>

typedef int bool;

#define	FALSE	0
#define	TRUE	1

static signed char hexindex[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	0,   1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static signed char index_64[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#define	char64(c) (((unsigned char) (c) > 127) ? -1 : \
	index_64[(unsigned char) (c)])

static int
unqp(unsigned char byte1, unsigned char byte2)
{
	if (hexindex[byte1] == -1 || hexindex[byte2] == -1)
		return (-1);
	return (hexindex[byte1] << 4 | hexindex[byte2]);
}

/* Check if character is linear whitespace */
#define	is_lws(c)  ((c) == ' ' || (c) == '\t' || (c) == '\n')

/*
 * Decode the string as a RFC-2047 header field
 */

bool
decode_rfc2047(char *str, char *dst, char *charset)
{
	char *p, *q, *pp;
	char *startofmime, *endofmime;
	int c, quoted_printable;
	bool encoding_found = FALSE;	/* did we decode anything?	  */
	bool between_encodings = FALSE;	/* are we between two encodings?  */
	bool equals_pending = FALSE;	/* is there a '=' pending?	  */
	int whitespace = 0;	/* how much whitespace between encodings? */

	if (str == NULL)
		return (FALSE);

	/*
	 * Do a quick and dirty check for the '=' character.
	 * This should quickly eliminate many cases.
	 */
	if (!strchr(str, '='))
		return (FALSE);

	for (p = str, q = dst; *p; p++) {
		/*
		 * If we had an '=' character pending from
		 * last iteration, then add it first.
		 */
		if (equals_pending) {
			*q++ = '=';
			equals_pending = FALSE;
			between_encodings = FALSE; /* we added non-WS text */
		}

		if (*p != '=') {
			/* count linear whitespace while between encodings */
			if (between_encodings && is_lws(*p))
				whitespace++;
			else
				between_encodings = FALSE; /* non-WS added */
			*q++ = *p;
			continue;
		}

		equals_pending = TRUE;	/* we have a '=' pending */

		/* Check for initial =? */
		if (*p == '=' && p[1] && p[1] == '?' && p[2]) {
			startofmime = p + 2;

			/* Scan ahead for the next '?' character */
			for (pp = startofmime; *pp && *pp != '?'; pp++)
				;

			if (!*pp)
				continue;

			strncpy(charset, startofmime, pp - startofmime);
			charset[pp - startofmime] = '\0';

			startofmime = pp + 1;

			/* Check for valid encoding type */
			if (*startofmime != 'B' && *startofmime != 'b' &&
			    *startofmime != 'Q' && *startofmime != 'q')
				continue;

			/* Is encoding quoted printable or base64? */
			quoted_printable = (*startofmime == 'Q' ||
					    *startofmime == 'q');
			startofmime++;

			/* Check for next '?' character */
			if (*startofmime != '?')
				continue;
			startofmime++;

			/*
			 * Scan ahead for the ending ?=
			 *
			 * While doing this, we will also check if encoded
			 * word has any embedded linear whitespace.
			 */
			endofmime = NULL;
			for (pp = startofmime; *pp && *(pp+1); pp++) {
				if (is_lws(*pp))
					break;
				else if (*pp == '?' && pp[1] == '=') {
					endofmime = pp;
					break;
				}
			}
			if (is_lws(*pp) || endofmime == NULL)
				continue;

			/*
			 * We've found an encoded word, so we can drop
			 * the '=' that was pending
			 */
			equals_pending = FALSE;

			/*
			 * If we are between two encoded words separated only
			 * by linear whitespace, then we ignore the whitespace.
			 * We will roll back the buffer the number of whitespace
			 * characters we've seen since last encoded word.
			 */
			if (between_encodings)
				q -= whitespace;

			/* Now decode the text */
			if (quoted_printable) {
				for (pp = startofmime; pp < endofmime; pp++) {
					if (*pp == '=') {
						c = unqp(pp[1], pp[2]);
						if (c == -1)
							continue;
						if (c != 0)
							*q++ = c;
						pp += 2;
					} else if (*pp == '_')
						*q++ = ' ';
					else
						*q++ = *pp;
				}
			} else {
				/* base64 */
				int c1, c2, c3, c4;

				pp = startofmime;
				while (pp < endofmime) {
					/* 6 + 2 bits */
					while ((pp < endofmime) &&
						((c1 = char64(*pp)) == -1)) {
						pp++;
					}
					if (pp < endofmime)
						pp++;
					while ((pp < endofmime) &&
						((c2 = char64(*pp)) == -1)) {
						pp++;
					}
					if (pp < endofmime && c1 != -1 &&
								c2 != -1) {
						*q++ = (c1 << 2) | (c2 >> 4);
						pp++;
					}
					/* 4 + 4 bits */
					while ((pp < endofmime) &&
						((c3 = char64(*pp)) == -1)) {
						pp++;
					}
					if (pp < endofmime && c2 != -1 &&
								c3 != -1) {
						*q++ = ((c2 & 0xF) << 4) |
								(c3 >> 2);
						pp++;
					}
					/* 2 + 6 bits */
					while ((pp < endofmime) &&
						((c4 = char64(*pp)) == -1)) {
						pp++;
					}
					if (pp < endofmime && c3 != -1 &&
								c4 != -1) {
						*q++ = ((c3 & 0x3) << 6) | (c4);
						pp++;
					}
				}
			}

			/*
			 * Now that we are done decoding this particular
			 * encoded word, advance string to trailing '='.
			 */
			p = endofmime + 1;

			encoding_found = TRUE;	 /* found (>= 1) encoded word */
			between_encodings = TRUE; /* just decoded something   */
			whitespace = 0; /* re-initialize amount of whitespace */
		}
	}

	/* If an equals was pending at end of string, add it now. */
	if (equals_pending)
		*q++ = '=';
	*q = '\0';

	return (encoding_found);
}
