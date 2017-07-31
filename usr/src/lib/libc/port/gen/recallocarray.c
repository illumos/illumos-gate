/*
 * Copyright (c) 2008, 2017 Otto Moerbeek <otto@drijf.net>
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

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/*
 * This is sqrt(SIZE_MAX+1), as s1*s2 <= SIZE_MAX
 * if both s1 < MUL_NO_OVERFLOW and s2 < MUL_NO_OVERFLOW
 */
#define	MUL_NO_OVERFLOW ((size_t)1 << (sizeof (size_t) * 4))

void *
recallocarray(void *ptr, size_t oldnelem, size_t newnelem, size_t elsize)
{
	size_t oldsize, newsize;
	void *newptr;

	if (ptr == NULL)
		return (calloc(newnelem, elsize));

	if ((newnelem >= MUL_NO_OVERFLOW || elsize >= MUL_NO_OVERFLOW) &&
	    newnelem > 0 && SIZE_MAX / newnelem < elsize) {
		errno = ENOMEM;
		return (NULL);
	}
	newsize = newnelem * elsize;

	if ((oldnelem >= MUL_NO_OVERFLOW || elsize >= MUL_NO_OVERFLOW) &&
	    oldnelem > 0 && SIZE_MAX / oldnelem < elsize) {
		errno = EINVAL;
		return (NULL);
	}
	oldsize = oldnelem * elsize;

	/*
	 * Don't bother too much if we're shrinking just a bit,
	 * we do not shrink for series of small steps, oh well.
	 */
	if (newsize <= oldsize) {
		size_t d = oldsize - newsize;

		if (d < oldsize / 2 && d < getpagesize()) {
			(void) memset((char *)ptr + newsize, 0, d);
			return (ptr);
		}
	}

	newptr = malloc(newsize);
	if (newptr == NULL)
		return (NULL);

	if (newsize > oldsize) {
		(void) memcpy(newptr, ptr, oldsize);
		(void) memset((char *)newptr + oldsize, 0, newsize - oldsize);
	} else {
		(void) memcpy(newptr, ptr, newsize);
	}

	explicit_bzero(ptr, oldsize);
	free(ptr);

	return (newptr);
}
