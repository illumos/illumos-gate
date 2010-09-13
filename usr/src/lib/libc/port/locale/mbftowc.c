/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
