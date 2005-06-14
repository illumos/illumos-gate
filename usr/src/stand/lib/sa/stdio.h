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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_STDIO_H
#define	_SA_STDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdarg.h>

/*
 * Exported interfaces for standalone's subset of libc's <stdio.h>.
 * All standalone code *must* use this header rather than libc's.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NULL
#define	NULL	0
#endif

#ifndef	EOF
#define	EOF	(-1)
#endif

/*
 * Flags to setvbuf() which we pretend to support.  We're always really _IONBF.
 */
#define	_IOFBF	0000	/* full buffered */
#define	_IOLBF	0100	/* line buffered */
#define	_IONBF	0004	/* not buffered */

typedef struct {
	unsigned char	_flag; 		/* state of the stream */
	int		_file;		/* file descriptor */
	ssize_t		_len;		/* total len of file */
	ssize_t		_offset;	/* offset within the file */
	char		_name[256];	/* name of the file (for debugging) */
} FILE;

#define	stdin	(&__iob[0])
#define	stdout	(&__iob[1])
#define	stderr	(&__iob[2])

#define	_NFILE	10
extern	FILE	__iob[_NFILE];

extern int	fclose(FILE *);
extern int	feof(FILE *);
extern int	fflush(FILE *);
extern int	ferror(FILE *);
extern void	clearerr(FILE *);

extern char	*fgets(char *, int, FILE *);
extern FILE	*fopen(const char *, const char *);
extern size_t	fread(void *, size_t, size_t, FILE *);
extern int	fseek(FILE *, long, int);
extern long	ftell(FILE *);
extern size_t	fwrite(const void *, size_t, size_t, FILE *);
extern int	setvbuf(FILE *, char *, int, size_t);

/* PRINTFLIKE1 */
extern void	printf(const char *, ...);
/* PRINTFLIKE2 */
extern int	fprintf(FILE *, const char *, ...);
/* PRINTFLIKE2 */
extern int	sprintf(char *, const char *, ...);
/* PRINTFLIKE3 */
extern size_t	snprintf(char *, size_t, const char *, ...);
extern int	vsprintf(char *, const char *, va_list);
extern size_t	vsnprintf(char *, size_t, const char *, va_list);

#ifdef __cplusplus
}
#endif

#endif /* _SA_STDIO_H */
