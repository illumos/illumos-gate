/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004 Darren Tucker.
 * Copyright 2022 Oxide Computer Company
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <lint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define	INIT_SZ	128

int
vasprintf(char **str, const char *format, va_list ap)
{
	char string[INIT_SZ];
	char *newstr;
	int ret;
	size_t len;

	*str = NULL;
	ret = vsnprintf(string, INIT_SZ, format, ap);
	if (ret < 0)	/* retain the value of errno from vsnprintf() */
		return (-1);
	if (ret < INIT_SZ) {
		len = ret + 1;
		if ((newstr = malloc(len)) == NULL)
			return (-1);	/* retain errno from malloc() */
		/*
		 * Prior versions of this used strlcpy. This has two problems.
		 * One, it doesn't handle embedded '\0' characters. Secondly,
		 * it's recalculating the length we already know. Please do not
		 * use a string-based copying function.
		 */
		(void) memcpy(newstr, string, len);
		*str = newstr;
		return (ret);
	}
	/*
	 * We will perform this loop more than once only if some other
	 * thread modifies one of the vasprintf() arguments after our
	 * previous call to vsnprintf().
	 */
	for (;;) {
		if (ret == INT_MAX) {	/* Bad length */
			errno = ENOMEM;
			return (-1);
		}
		len = ret + 1;
		if ((newstr = malloc(len)) == NULL)
			return (-1);	/* retain errno from malloc() */
		ret = vsnprintf(newstr, len, format, ap);
		if (ret < 0) {		/* retain errno from vsnprintf() */
			free(newstr);
			return (-1);
		}
		if (ret < len) {
			*str = newstr;
			return (ret);
		}
		free(newstr);
	}
}

int
asprintf(char **str, const char *format, ...)
{
	va_list ap;
	int ret;

	*str = NULL;
	va_start(ap, format);
	ret = vasprintf(str, format, ap);
	va_end(ap);

	return (ret);
}
