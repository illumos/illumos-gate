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
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include "lint.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/*
 * This function is apparently referenced by parts of ON.  It is
 * not intended for public API usage -- and it is not documented.
 *
 * The usage appears to be to consume bytes until a character is
 * gathered, using a supplied function.   It reads exactly one
 * character and returns the number of bytes in the multibyte string
 * that were consumed.
 *
 * The string "s" is storage for the multibyte string, the
 * wc will receive the interpreted character, the peek function
 * obtains the next character (as an int so we can get EOF),
 * and errorc is stuffed with the character that is responsible
 * for a parse error, if any.
 */

int
_mbftowc(char *s, wchar_t *wc, int (*peek)(void), int *errorc)
{
	int		c;
	mbstate_t	mbs;
	char		*start = s;
	size_t		cons = 0;

	for (;;) {
		c = peek();
		if (c < 0) {
			/* No bytes returned? */
			return (s - start);
		}

		*s = (char)c;
		s++;

		(void) memset(&mbs, 0, sizeof (mbs));
		cons = mbrtowc(wc, start, s - start, &mbs);
		if ((int)cons >= 0) {
			/* fully translated character */
			return (cons);
		}
		if (cons == (size_t)-2) {
			/* incomplete, recycle */
			continue;
		}

		/*
		 * Parse error, don't consider the first character part
		 * of the error.
		 */
		s--;
		cons = (s - start);
		*errorc = c >= 0 ?  c : 0;
		break;
	}

	return (cons);
}
