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

#ifndef	_NSL_STDIO_PRV_H
#define	_NSL_STDIO_PRV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/xdr.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * To avoid the 256 file descriptor limitation in stdio, we use our own
 * private version of stdio functions. A modified FILE structure is used
 * in our private stdio functions.
 * To simplify, certain assumptions are made:
 * - a file may be opened for either readonly or write only
 * - file descriptors should not be shared between threads
 * - only seek to beginning of file
 * - ungetc may only work for the last char. ie., ungetc will work
 *   once (but not necessarily more) after a read
 */

#define	__NSL_FILE_BUF_SIZE	1024

/* __NSL_FILE flags */
#define	__NSL_FILE_EOF		0x01
#define	__NSL_FILE_WRITE_ONLY	0x02
#define	__NSL_FILE_ERR		0x04
#define	__NSL_FILE_DIRTY	0x08

typedef struct {
	int		_nsl_file;	/* integer datatype to hold */
					/* file descriptor */

	int		_nsl_cnt;	/* number of bytes available to read */
					/* or write as per the access mode */

	unsigned char	*_nsl_ptr;	/* location of next byte in buffer to */
					/* read or write as per access mode */

	int		_nsl_flag;
	unsigned char	_nsl_base[__NSL_FILE_BUF_SIZE];
} __NSL_FILE;

extern __NSL_FILE	*__nsl_fopen(const char *filename, const char *mode);
extern int 		__nsl_fclose(__NSL_FILE *stream);
extern char		*__nsl_fgets(char *s, int n, __NSL_FILE *stream);
extern int		__nsl_feof(__NSL_FILE *stream);
extern int		__nsl_fseek(__NSL_FILE *stream, long offset,
				int whence);
extern void		__nsl_frewind(__NSL_FILE *stream);
extern long		__nsl_ftell(__NSL_FILE *stream);
extern size_t		__nsl_fread(void *ptr, size_t size, size_t nitems,
				__NSL_FILE *stream);
extern int		__nsl_fflush(__NSL_FILE *stream);
extern int		__nsl_getc(__NSL_FILE *stream);
extern int		__nsl_fgetc(__NSL_FILE *stream);
extern int		__nsl_ungetc(int c, __NSL_FILE *stream);
extern __NSL_FILE	*__nsl_fdopen(int fildes, const char *mode);
extern size_t		__nsl_fwrite(const void *ptr, size_t size,
				size_t nitems, __NSL_FILE *stream);
extern int		__nsl_fputc(int c, __NSL_FILE *stream);
extern void		__nsl_xdrstdio_create(XDR *xdrs, __NSL_FILE *file,
				enum xdr_op op);

#define	__nsl_fputstring(s, stream) __nsl_fwrite(s, strlen(s), 1, stream)
#define	__nsl_fileno(s) s->_nsl_file
#define	__nsl_getc_unlocked(f) __nsl_fgetc(f)
#define	__nsl_getc(f) __nsl_fgetc(f)
#define	__nsl_rewind(f) __nsl_frewind(f)

/* external functions */

extern int	_fcntl(int, int, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _NSL_STDIO_PRV_H */
