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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * "buffered" i/o functions for the standalone environment. (ugh).
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/varargs.h>
#include <sys/bootvfs.h>
#include <sys/salib.h>

enum {
	F_OPEN		= 0x01,
	F_ERROR		= 0x02,
	F_SEEKABLE	= 0x04
};

FILE	__iob[_NFILE] = {
	{ F_OPEN, 0, 0, 0, "stdin"	},
	{ F_OPEN, 1, 0, 0, "stdout"	},
	{ F_OPEN, 2, 0, 0, "stderr"	}
};

static boolean_t
fcheck(FILE *stream, int flags)
{
	errno = 0;
	if ((stream->_flag & flags) != flags) {
		errno = EBADF;
		return (B_FALSE);
	}
	return (B_TRUE);
}

int
fclose(FILE *stream)
{
	if (!fcheck(stream, F_OPEN))
		return (EOF);

	(void) close(stream->_file);
	stream->_flag = 0;
	stream->_file = -1;
	stream->_name[0] = '\0';
	return (0);
}

int
feof(FILE *stream)
{
	if (!fcheck(stream, F_OPEN))
		return (0);

	return (stream->_len == stream->_offset);
}

int
ferror(FILE *stream)
{
	if (!fcheck(stream, F_OPEN))
		return (0);

	return ((stream->_flag & F_ERROR) != 0);
}

void
clearerr(FILE *stream)
{
	stream->_flag &= ~F_ERROR;
}

int
fflush(FILE *stream)
{
	if (!fcheck(stream, F_OPEN))
		return (EOF);

	/* Currently, a nop */
	return (0);
}

char *
fgets(char *s, int n, FILE *stream)
{
	int	bytes;
	ssize_t	cnt;

	if (!fcheck(stream, F_OPEN))
		return (NULL);

	for (bytes = 0; bytes < (n - 1); ++bytes) {
		cnt = read(stream->_file, &s[bytes], 1);
		if (cnt < 0) {
			if (bytes != 0) {
				s[bytes] = '\0';
				return (s);
			} else {
				stream->_flag |= F_ERROR;
				return (NULL);
			}
		} else if (cnt == 0) {
			/* EOF */
			if (bytes != 0) {
				s[bytes] = '\0';
				return (s);
			} else
				return (NULL);
		} else {
			stream->_offset++;
			if (s[bytes] == '\n') {
				s[bytes + 1] = '\0';
				return (s);
			}
		}
	}
	s[bytes] = '\0';
	return (s);
}

/*
 * We currently only support read-only ("r" mode) opens and unbuffered I/O.
 */
FILE *
fopen(const char *filename, const char *mode)
{
	FILE		*stream;
	const char	*t;
	int		fd, i;

	errno = 0;

	/*
	 * Make sure we have a filesystem underneath us before even trying.
	 */
	if (get_default_fs() == NULL)
		return (NULL);

	for (t = mode; t != NULL && *t != '\0'; t++) {
		switch (*t) {
		case 'b':
			/* We ignore this a'la ISO C standard conformance */
			break;
		case 'r':
			/* We ignore this because we always open for reading */
			break;

		case 'a':
		case 'w':
		case '+':
			errno = EROFS;
			return (NULL);

		default:
			errno = EINVAL;
			return (NULL);
		}
	}

	for (i = 0; i < _NFILE; i++) {
		stream = &__iob[i];
		if ((stream->_flag & F_OPEN) == 0) {
			fd = open(filename, O_RDONLY);
			if (fd < 0)
				return (NULL);

			stream->_file = fd;
			stream->_flag |= F_OPEN;
			(void) strlcpy(stream->_name, filename,
			    sizeof (stream->_name));
			return (stream);
		}
	}

	errno = EMFILE;
	return (NULL);
}

/* PRINTFLIKE1 */
void
printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	prom_vprintf(fmt, adx);
	va_end(adx);
}

/*
 * Only writing to stderr or stdout is permitted.
 */
/* PRINTFLIKE2 */
int
fprintf(FILE *stream, const char *format, ...)
{
	int	nwritten;
	va_list	va;

	if (!fcheck(stream, F_OPEN))
		return (-1);

	/*
	 * Since fopen() doesn't return writable streams, the only valid
	 * writable streams are stdout and stderr.
	 */
	if (stream != stdout && stream != stderr) {
		errno = EBADF;
		return (-1);
	}

	va_start(va, format);
	printf(format, va);
	va_end(va);

	va_start(va, format);
	nwritten = vsnprintf(NULL, 0, format, va);
	va_end(va);

	return (nwritten);
}

size_t
fread(void *ptr, size_t size, size_t nitems, FILE *stream)
{
	size_t	items;
	ssize_t	bytes, totbytes = 0;
	char	*strp = ptr;

	if (!fcheck(stream, F_OPEN))
		return (0);

	for (items = 0, bytes = 0; items < nitems; items++) {
		bytes = read(stream->_file, &strp[totbytes], size);
		if (bytes < 0) {
			stream->_flag |= F_ERROR;
			return (0);
		} else if (bytes == 0) {
			/* EOF */
			return ((totbytes == 0) ? 0 : totbytes / size);
		} else if (bytes == size) {
			stream->_offset += bytes;
			totbytes += bytes;
		} else {
			(void) lseek(stream->_file, stream->_offset, SEEK_SET);
			return (totbytes / size);
		}
	}

	return (totbytes / size);
}

/*
 * We don't grow files.
 */
int
fseek(FILE *stream, long offset, int whence)
{
	off_t	new_offset, result;

	if (!fcheck(stream, F_OPEN | F_SEEKABLE))
		return (-1);

	switch (whence) {
	case SEEK_SET:
		new_offset = (off_t)offset;
		break;
	case SEEK_CUR:
		new_offset = stream->_offset + (off_t)offset;
		break;
	case SEEK_END:
		new_offset = (off_t)stream->_len + (off_t)offset;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (new_offset > (off_t)stream->_len) {
		errno = EFBIG;
	} else if (new_offset < 0L) {
		errno = EOVERFLOW;
	} else {
		errno = 0;
	}

	result = lseek(stream->_file, new_offset, SEEK_SET);
	if (result >= 0)
		stream->_offset = result;
	else
		stream->_flag |= F_ERROR;

	return (result);
}

long
ftell(FILE *stream)
{
	if (!fcheck(stream, F_OPEN | F_SEEKABLE))
		return (0);

	return ((long)stream->_offset);
}

size_t
fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
{
	if (!fcheck(stream, F_OPEN))
		return (0);

	/*
	 * Since fopen() doesn't return writable streams, the only valid
	 * writable streams are stdout and stderr.
	 */
	if (stream != stdout && stream != stderr) {
		errno = EBADF;
		return (0);
	}

	prom_writestr(ptr, size * nitems);
	return (nitems);
}

/*ARGSUSED*/
int
setvbuf(FILE *stream, char *buf, int type, size_t size)
{
	if (!fcheck(stream, F_OPEN))
		return (-1);

	/* Currently a nop, probably always will be. */
	return (0);
}
