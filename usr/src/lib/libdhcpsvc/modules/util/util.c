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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Internal libdhcpsvc public module utility functions: a collection of
 * general-purpose routines that are used by assorted public modules.
 * Someday we should integrate this into the build process a bit more
 * intelligently.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/isa_defs.h>
#include <dhcp_svc_public.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <ctype.h>

#include "util.h"

/*
 * Open a file at path `pathname'; depending on the flags passed in through
 * `dsvc_flags', this file may be optionally created or opened read-only.
 * On success, DSVC_SUCCESS is returned and `fdp' points to the opened file
 * descriptor.  On failure, a DSVC_* error code is returned.
 */
int
open_file(const char *pathname, unsigned int dsvc_flags, int *fdp)
{
	int open_flags;

	/*
	 * Note that we always open with read access, independent of
	 * dsvc_flags, because an update operation (add, delete, modify)
	 * needs to lookup records to detect collisions.
	 */
	open_flags = O_RDONLY;
	if (dsvc_flags & DSVC_WRITE)
		open_flags = O_RDWR;
	if (dsvc_flags & DSVC_CREATE)
		open_flags |= O_CREAT|O_EXCL;

	*fdp = open(pathname, open_flags, 0644);
	if (*fdp == -1)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}

/*
 * Read input a chunk at a time, avoiding as much copying as possible.  To
 * this end, we don't read into a temporary buffer, but rather read
 * directly into dynamically reallocated storage (on the assumption that
 * most of the time we will have to return something).  Returns NULL either
 * on failure or EOF; use feof(3C) on `fp' to determine which condition
 * occurred.
 */
char *
read_entry(FILE *fp)
{
	char		*newline, *new_result, *result = NULL;
	unsigned int	len = 0, size = 0, chunksize = BUFSIZ;

	for (;;) {
		/*
		 * See if we need to grow the buffer; we always try to read
		 * `chunksize' bytes, so we need at least `chunksize' around;
		 * grab a little more just to avoid constant realloc'ing
		 */
		if (len + chunksize > size) {
			size = len + (chunksize * 2);
			new_result = realloc(result, size);
			if (new_result == NULL) {
				free(result);
				return (NULL);
			}
		}

		if (fgets(&new_result[len], chunksize, fp) == NULL) {
			/*
			 * Hit EOF; if we never read any data, then free
			 * `new_result' and return NULL.  If we are
			 * returning data, it's in `new_result', not
			 * `result'.
			 */
			if (result == NULL)
				free(new_result);
			else
				result = new_result;
			break;
		}
		result = new_result;

		/*
		 * If we read a newline, then see if the preceding
		 * character was an escape.  If so, remove the escape and
		 * continue; otherwise we're done.  Note that we need to
		 * do the strrchr() on `&result[len]' so that NUL's that
		 * may be lurking elsewhere on the line don't confuse us.
		 */
		newline = strrchr(&result[len], '\n');
		if (newline != NULL) {
			len = newline - result;
			if (newline == result || newline[-1] != '\\') {
				newline[0] = '\0';
				break;
			}
			newline[-1] = '\0';
			len -= 2;
		} else {
			/*
			 * We either `chunksize' worth of data or we hit a
			 * NUL somewhere in the data stream.  If we hit a
			 * NUL, then we can't "see" beyond the NUL; just
			 * advance to the NUL itself and continue.
			 */
			len += strlen(&result[len]);
		}
	}
	return (result);
}

/*
 * Given a buffer `buf' of words separated by one or more of the characters
 * in `seps', split it into at most `nfields' fields, by changing the
 * separator character following a field to a NUL character.  Set
 * `fields[i]' to point to the beginning of field i in `buf'.  Return the
 * number of fields set in `fields[]'.  This routine is quite similar to
 * bufsplit(3G), but less general, faster, and also handles multiple
 * multiple whitespace separator characters differently.
 */
unsigned int
field_split(char *buf, unsigned int nfields, char *fields[], const char *seps)
{
	unsigned int	i = 0;
	char		*ch;

	for (;;) {
		fields[i] = buf;

		/*
		 * Look for the field separator, byte-at-a-time; ignore
		 * separators that have been escaped.  Believe it or not,
		 * strchr(3C) will match `seps' if `*buf' is the NUL byte
		 * (which indicates we're done).
		 */
		for (;;) {
			ch = strchr(seps, *buf);
			if (ch != NULL && *ch == '\0')
				return (i + 1);
			if (ch != NULL && (buf == fields[i] || buf[-1] != '\\'))
				break;
			buf++;
		}

		/*
		 * If this is the last field, then consider any remaining
		 * text on the line part of the last field.  This is
		 * similar to how `read' in sh(1) works.
		 */
		if (++i == nfields)
			return (i);

		if (*buf == '\0')
			return (i);

		*buf = '\0';

		/*
		 * If separator is whitespace, then skip all consecutive
		 * pieces of whitespace.
		 */
		while (ch != NULL && isspace(*ch)) {
			ch = strchr(seps, buf[1]);
			if (ch != NULL && isspace(*ch))
				buf++;
		}
		buf++;
	}
}

/*
 * Map a standard errno into a corresponding DSVC_* code.  If there
 * is no translation, default to DSVC_INTERNAL.
 */
int
syserr_to_dsvcerr(int error)
{
	switch (error) {

	case EEXIST:
		return (DSVC_TABLE_EXISTS);

	case ENOMEM:
		return (DSVC_NO_MEMORY);

	case ENOSPC:
		return (DSVC_NO_RESOURCES);

	case EROFS:
	case EPERM:
	case EACCES:
		return (DSVC_ACCESS);

	case ENOENT:
		return (DSVC_NO_TABLE);

	default:
		break;
	}

	return (DSVC_INTERNAL);
}

/*
 * Convert an object of `len' bytes pointed to by `srcraw' between
 * network-order and host-order and store in `dstraw'.  The length `len'
 * must be the actual length of the objects pointed to by `srcraw' and
 * `dstraw' (or zero) or the results are undefined.  Note that `srcraw' and
 * `dstraw' may be the same, in which case the object is converted
 * in-place.  This routine will convert from host-order to network-order or
 * network-order to host-order, since the conversion is the same.
 */
void
nhconvert(void *dstraw, const void *srcraw, size_t len)
{
#ifdef	_LITTLE_ENDIAN
	uint8_t	b1, b2;
	uint8_t *dst, *src;
	size_t i;

	/*
	 * If both `srcraw' and `dstraw' are 32-bit aligned and `len' is 4,
	 * then use ntohl() to do the byteswap, since it's hand-tuned.
	 */
	if (IS_P2ALIGNED(dstraw, 4) && IS_P2ALIGNED(srcraw, 4) && len == 4) {
		*(uint32_t *)dstraw = ntohl(*(uint32_t *)srcraw);
		return;
	}

	dst = (uint8_t *)dstraw;
	src = (uint8_t *)srcraw;

	for (i = 0; i < len / 2; i++) {
		b1 = src[i];
		b2 = src[len - i - 1];
		dst[i] = b2;
		dst[len - i - 1] = b1;
	}
#else
	if (srcraw != dstraw)
		(void) memmove(dstraw, srcraw, len);
#endif
}

/*
 * Positioned n-byte read: read `buflen' bytes at offset `off' at open file
 * `fd' into `buffer', or "read" none at all.  Returns -1 if all `buflen'
 * bytes cannot be read; otherwise, returns 0.
 */
int
pnread(int fd, void *buffer, size_t buflen, off_t off)
{
	size_t	nread;
	ssize_t	nbytes;
	char	*buf = buffer;

	for (nread = 0; nread < buflen; nread += nbytes) {
		nbytes = pread(fd, &buf[nread], buflen - nread, off + nread);
		if (nbytes == -1)
			return (-1);
		if (nbytes == 0) {
			errno = EIO;
			return (-1);
		}
	}

	assert(nread == buflen);
	return (0);
}

/*
 * Positioned n-byte write: write `buflen' bytes from `buffer' to offset
 * `off' in open file `fd'.  Tries to write all `buflen' bytes, but does
 * not attempt to "undo" what it has done in the case of failure.  Returns
 * -1 if all `buflen' bytes cannot be written, otherwise returns 0.
 */
int
pnwrite(int fd, const void *buffer, size_t buflen, off_t off)
{
	size_t		nwritten;
	ssize_t		nbytes;
	const char	*buf = buffer;

	for (nwritten = 0; nwritten < buflen; nwritten += nbytes) {
		nbytes = pwrite(fd, &buf[nwritten], buflen - nwritten,
		    off + nwritten);
		if (nbytes == -1)
			return (-1);
		if (nbytes == 0) {
			errno = EIO;
			return (-1);
		}
	}

	assert(nwritten == buflen);
	return (0);
}

/*
 * Copy `nbytes' efficiently from offset `srcoff' in `srcfd' to offset
 * `dstoff' in `dstfd'; returns a DSVC_* return code.  Note that we make
 * `nbytes' a uint64_t (rather than a size_t) so that we can copy 2^64
 * bits even when compiled ILP32.
 */
int
copy_range(int srcfd, off_t srcoff, int dstfd, off_t dstoff, uint64_t nbytes)
{
	const size_t	chunksize = 16 * PAGESIZE;
	size_t		validsize;
	size_t		skip;
	uint64_t	nwritten = 0;
	int		mflags = MAP_PRIVATE;
	char		*buf = NULL;
	int		error;

	/*
	 * Handle trivial copy specially so we don't call munmap() below.
	 */
	if (nbytes == 0)
		return (DSVC_SUCCESS);

	/*
	 * The `off' argument to mmap(2) must be page-aligned, so align it;
	 * compute how many bytes we need to skip over in the mmap()'d
	 * buffer as a result.
	 */
	skip = srcoff % PAGESIZE;
	srcoff -= skip;

	while (nwritten < nbytes) {
		buf = mmap(buf, chunksize, PROT_READ, mflags, srcfd, srcoff);
		if (buf == MAP_FAILED)
			return (DSVC_INTERNAL);
		mflags |= MAP_FIXED;

		validsize = MIN(chunksize, nbytes - nwritten + skip);
		if (pnwrite(dstfd, &buf[skip], validsize - skip, dstoff)
		    == -1) {
			error = errno;
			(void) munmap(buf, chunksize);
			return (syserr_to_dsvcerr(error));
		}

		nwritten += validsize - skip;
		dstoff += validsize - skip;
		srcoff += validsize;
		skip = 0;
	}
	(void) munmap(buf, chunksize);

	return (DSVC_SUCCESS);
}

/*
 * Unescape all instances of `delimiter' in `buffer' and store result in
 * `unescaped', which is `size' bytes.  To guarantee that all data is
 * copied, `unescaped' should be at least as long as `buffer'.
 */
void
unescape(char delimiter, const char *buffer, char *unescaped, size_t size)
{
	int i, j;

	size--;
	for (i = 0, j = 0; buffer[i] != '\0' && j < size; i++, j++) {
		if (buffer[i] == '\\' && buffer[i + 1] == delimiter)
			i++;
		unescaped[j] = buffer[i];
	}
	unescaped[j] = '\0';
}

/*
 * Escape all instances of `delimiter' in `buffer' and store result in
 * `escaped', which is `size' bytes.  To guarantee that all data is
 * copied, `escaped' should be at least twice as long as `buffer'.
 */
void
escape(char delimiter, const char *buffer, char *escaped, size_t size)
{
	int i, j;

	size--;
	for (i = 0, j = 0; buffer[i] != '\0' && j < size; i++, j++) {
		if (buffer[i] == delimiter)
			escaped[j++] = '\\';
		escaped[j] = buffer[i];
	}
	escaped[j] = '\0';
}

/*
 * Generate a signature for a new record.  The signature is conceptually
 * divided into two pieces: a random 16-bit "generation number" and a
 * 48-bit monotonically increasing integer.  The generation number protects
 * against stale updates to records that have been deleted and since
 * recreated.
 */
uint64_t
gensig(void)
{
	static int seeded = 0;

	if (seeded == 0) {
		srand48((long)gethrtime());
		seeded++;
	}

	return ((uint64_t)lrand48() << 48 | 1);
}
