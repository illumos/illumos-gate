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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "nsl_stdio_prv.h"

/*
 * This is a limited implementation to allow libraries to use
 * stdio and avoid the limitation of 256 open file descriptors.
 * The newly implemented stdio functions are closely based on
 * the implementation in C library.
 * To simplify, certain assumptions are made:
 * - a file may be opened for either readonly or write only
 * - file descriptors should not be shared between threads
 * - only seek to beginning of file
 * - ungetc may only work for the last char. ie., ungetc will work
 *   once (but not necessarily more) after a read
 */

static int
_raise_fd(int fd)
{
	int nfd;
	static const int min_fd = 256;

	if (fd >= min_fd)
		return (fd);

	if ((nfd = _fcntl(fd, F_DUPFD, min_fd)) == -1) {
		/*
		 * If the shell limits [See limit(1)] the
		 * descriptors to 256, _fcntl will fail
		 * and errno will be set to EINVAL. Since
		 * the intention is to ignore _fcntl failures
		 * and continue working with 'fd', we should
		 * reset errno to _prevent_ apps relying on errno
		 * to treat this as an error.
		 */
		errno = 0;
		return (fd);
	}

	(void) close(fd);

	return (nfd);
}

__NSL_FILE *
__nsl_fopen(const char *filename, const char *mode)
{
	int		flag;
	int		oflag;
	int		fd;
	__NSL_FILE	*stream;

	if (mode == NULL || filename == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	switch (mode[0]) {
		default:
			errno = EINVAL;
			return (NULL);
		case 'r':
			flag = 0;
			oflag = O_RDONLY;
			break;
		case 'w':
			flag = __NSL_FILE_WRITE_ONLY;
			oflag = O_WRONLY | O_TRUNC | O_CREAT;
			break;
	}
	if (mode[1] != '\0') {
		errno = EINVAL;
		return (NULL);
	}

	fd = open(filename, oflag | O_LARGEFILE, 0666);
	if (fd < 0)
		return (NULL);

	stream = (__NSL_FILE *)malloc(sizeof (__NSL_FILE));
	if (stream != NULL) {
		stream->_nsl_file = _raise_fd(fd);
		stream->_nsl_cnt = flag & __NSL_FILE_WRITE_ONLY ?
			sizeof (stream->_nsl_base) : 0;
		stream->_nsl_ptr = stream->_nsl_base;
		stream->_nsl_flag = flag;
	} else {
		(void) close(fd);
	}

	return (stream);
}

int
__nsl_fclose(__NSL_FILE *stream)
{
	int res = 0;

	if (stream == NULL)
		return (EOF);

	res = __nsl_fflush(stream);

	if (close(stream->_nsl_file) < 0)
		res = EOF;

	free(stream);

	return (res);
}

/* fill buffer, return 0 or EOF */
static int
_filbuf(__NSL_FILE *stream)
{
	int res;

	stream->_nsl_ptr = stream->_nsl_base;

	if ((res = read(stream->_nsl_file, (char *)stream->_nsl_base,
		__NSL_FILE_BUF_SIZE)) > 0) {
		stream->_nsl_cnt = res;
		return (0);
	} else {
		stream->_nsl_cnt = 0;
		if (res == 0)
			stream->_nsl_flag |= __NSL_FILE_EOF;
		else
			stream->_nsl_flag |= __NSL_FILE_ERR;
		return (EOF);
	}
}

char *
__nsl_fgets(char *buf, int size, __NSL_FILE *stream)
{
	char *ptr = buf;
	char *p;
	int n;

	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY) {
		errno = EBADF;
		return (NULL);
	}

	size--;		/* room for '\0' */
	while (size > 0) {
		if (stream->_nsl_cnt == 0) {
			if (_filbuf(stream) == EOF)
				break;		/* nothing left to read */
		}
		n = (int)(size < stream->_nsl_cnt ? size : stream->_nsl_cnt);
		if ((p = memccpy(ptr, (char *)stream->_nsl_ptr, '\n',
		    (size_t)n)) != NULL)
			n = (int)(p - ptr);
		ptr += n;
		stream->_nsl_cnt -= n;
		stream->_nsl_ptr += n;
		if (p != NULL)
			break; /* newline found */
		size -= n;
	}

	if (ptr == buf)		/* never read anything */
		return (NULL);

	*ptr = '\0';
	return (buf);
}

int
__nsl_feof(__NSL_FILE *stream)
{
	return (stream->_nsl_flag & __NSL_FILE_EOF);
}

int
__nsl_fseek(__NSL_FILE *stream, long offset, int whence)
{
	off_t	p;

	stream->_nsl_flag &= ~(__NSL_FILE_EOF | __NSL_FILE_ERR);

	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY) {
		if (whence == SEEK_CUR)
			offset -= sizeof (stream->_nsl_base) - stream->_nsl_cnt;
		if (__nsl_fflush(stream) == EOF)
			return (-1);
	} else  {
		if (whence == SEEK_CUR)
			offset -= stream->_nsl_cnt;

		stream->_nsl_cnt = 0;
		stream->_nsl_ptr = stream->_nsl_base;
	}

	p = lseek(stream->_nsl_file, (off_t)offset, whence);
	return ((p == (off_t)-1) ? -1 : 0);
}

void
__nsl_frewind(__NSL_FILE *stream)
{
	(void) __nsl_fseek(stream, 0, SEEK_SET);
}

long
__nsl_ftell(__NSL_FILE *stream)
{
	ptrdiff_t adjust;
	off64_t tres;

	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY)
		adjust = (ptrdiff_t)
			(sizeof (stream->_nsl_base) - stream->_nsl_cnt);
	else
		adjust = (ptrdiff_t)(-stream->_nsl_cnt);

	tres = lseek64(stream->_nsl_file, 0, SEEK_CUR);
	if (tres >= 0)
		tres += adjust;

	if (tres > LONG_MAX) {
		errno = EOVERFLOW;
		return (EOF);
	}

	return ((long)tres);
}

size_t
__nsl_fread(void *ptr, size_t size, size_t nitems, __NSL_FILE *stream)
{
	ssize_t	s;
	char	*dptr = (char *)ptr;

	/* is it a readable stream */
	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY) {
		stream->_nsl_flag |= __NSL_FILE_ERR;
		errno = EBADF;
		return (0);
	}

	if (stream->_nsl_flag & __NSL_FILE_EOF)
		return (0);

	s = size * nitems;

	while (s > 0) {
		if (stream->_nsl_cnt < s) {
			if (stream->_nsl_cnt > 0) {
				(void) memcpy((void*)dptr, stream->_nsl_ptr,
				    stream->_nsl_cnt);
				dptr += stream->_nsl_cnt;
				s -= stream->_nsl_cnt;
			}
			/*
			 * filbuf clobbers _cnt & _ptr,
			 * so don't waste time setting them.
			 */
			if (_filbuf(stream) == EOF)
				break;
		}
		if (stream->_nsl_cnt >= s) {
			(void) memcpy((void*)dptr, stream->_nsl_ptr, (size_t)s);
			stream->_nsl_ptr += s;
			stream->_nsl_cnt -= s;
			return (nitems);
		}
	}
	return (size != 0 ? nitems - ((s + size - 1) / size) : 0);
}

int
__nsl_fgetc(__NSL_FILE *stream)
{
	/* is it a readable stream */
	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY) {
		stream->_nsl_flag |= __NSL_FILE_ERR;
		errno = EBADF;
		return (0);
	}

	if (stream->_nsl_cnt <= 0) {
		if (_filbuf(stream) == EOF)
			return (EOF);
	}
	--stream->_nsl_cnt;
	return (*stream->_nsl_ptr++);
}

int
__nsl_fflush(__NSL_FILE *stream)
{
	ssize_t n;
	ssize_t num_wrote;
	unsigned char *base;

	if (!(stream->_nsl_flag & __NSL_FILE_DIRTY)) {
		return (0);
	}

	base = stream->_nsl_base;
	n = stream->_nsl_ptr - stream->_nsl_base;

	stream->_nsl_flag &= ~__NSL_FILE_DIRTY;
	if (n > 0) {
		while ((num_wrote =
			write(stream->_nsl_file, base, (size_t)n)) != n) {
			if (num_wrote <= 0) {
				stream->_nsl_flag |= __NSL_FILE_ERR;
				return (EOF);
			}
			n -= num_wrote;
			base += num_wrote;
		}
	}
	stream->_nsl_ptr = stream->_nsl_base;
	stream->_nsl_cnt = sizeof (stream->_nsl_base);
	return (0);
}

int
__nsl_ungetc(int c, __NSL_FILE *stream)
{
	if (stream->_nsl_flag & __NSL_FILE_WRITE_ONLY)
		return (EOF);
	if (c == EOF)
		return (EOF);
	if (stream->_nsl_ptr <= stream->_nsl_base)
			return (EOF);
	stream->_nsl_flag &= ~(__NSL_FILE_EOF | __NSL_FILE_ERR);
	*--stream->_nsl_ptr = c;
	++stream->_nsl_cnt;
	return (c);
}

__NSL_FILE *
__nsl_fdopen(int fildes, const char *mode)
{
	int		flag;
	__NSL_FILE	*stream;

	if (mode == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	switch (mode[0]) {
		default:
			errno = EINVAL;
			return (NULL);
		case 'r':
			flag = 0;
			break;
		case 'w':
			flag = __NSL_FILE_WRITE_ONLY;
			break;
	}
	if (mode[1] != '\0') {
		errno = EINVAL;
		return (NULL);
	}

	stream = (__NSL_FILE *)malloc(sizeof (__NSL_FILE));
	if (stream != NULL) {
		stream->_nsl_file = fildes;
		stream->_nsl_cnt = flag & __NSL_FILE_WRITE_ONLY ?
			sizeof (stream->_nsl_base) : 0;
		stream->_nsl_ptr = stream->_nsl_base;
		stream->_nsl_flag = flag;
	}

	return (stream);
}

size_t
__nsl_fwrite(const void *ptr, size_t size, size_t nitems,
				__NSL_FILE *stream)
{
	ssize_t s;
	const unsigned char *dptr = (const unsigned char *)ptr;

	if (!(stream->_nsl_flag & __NSL_FILE_WRITE_ONLY))
		return (0);

	if (size < 1 || nitems < 1)
		return (0);

	s = size * nitems;

	stream->_nsl_flag |= __NSL_FILE_DIRTY;

	while (s > 0) {
		if (stream->_nsl_cnt < s) {
			if (stream->_nsl_cnt > 0) {
				(void) memcpy(stream->_nsl_ptr, (void *)dptr,
				    stream->_nsl_cnt);
				dptr += stream->_nsl_cnt;
				stream->_nsl_ptr += stream->_nsl_cnt;
				s -= stream->_nsl_cnt;
				stream->_nsl_cnt = 0;
			}
			if (__nsl_fflush(stream) == EOF)
				break;
		}
		if (stream->_nsl_cnt >= s) {
			(void) memcpy(stream->_nsl_ptr, (void *)dptr, s);
			stream->_nsl_ptr += s;
			stream->_nsl_cnt -= s;

			return (nitems);
		}
	}

	return (size != 0 ? nitems - ((s + size - 1) / size) : 0);
}

int
__nsl_fputc(int c, __NSL_FILE *stream)
{
	if (!(stream->_nsl_flag & __NSL_FILE_WRITE_ONLY))
		return (EOF);

	if (stream->_nsl_cnt == 0) {
		if (__nsl_fflush(stream) == EOF)
			return (EOF);
	}
	(*stream->_nsl_ptr++) = (unsigned char)c;
	--stream->_nsl_cnt;

	return ((unsigned char)c);
}
