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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * User-visible pieces of the ANSI C standard I/O package.
 */

#ifndef _STDIO_H
#define	_STDIO_H

#include <sys/feature_tests.h>
#include <sys/va_list.h>
#include <stdio_tag.h>
#include <stdio_impl.h>
#include <sys/null.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BSD
#define	BSD
#endif

#ifndef _SIZE_T
#define	_SIZE_T
#if !defined(_LP64) && defined(__cplusplus)
typedef unsigned int	size_t;
#else
typedef unsigned long	size_t;
#endif
#endif

#ifndef _SSIZE_T
#define	_SSIZE_T
#if !defined(_LP64) && defined(__cplusplus)
typedef int	ssize_t;
#else
typedef long	ssize_t;
#endif
#endif

typedef long	fpos_t;

#define	BUFSIZ		1024

#if defined(__i386)
#define	_NFILE	60	/* initial number of streams: Intel x86 ABI */
#else
#define	_NFILE	20	/* initial number of streams: SPARC ABI and default */
#endif

#define	_SBFSIZ	8	/* compatibility with shared libs */

#define	_IOFBF		0000	/* full buffered */
#define	_IOLBF		0100	/* line buffered */
#define	_IONBF		0004	/* not buffered */
#define	_IOEOF		0020	/* EOF reached on read */
#define	_IOERR		0040	/* I/O error from system */

#define	_IOREAD		0001	/* currently reading */
#define	_IOWRT		0002	/* currently writing */
#define	_IORW		0200	/* opened for reading and writing */
#define	_IOMYBUF	0010	/* stdio malloc()'d buffer */

#ifndef EOF
#define	EOF	(-1)
#endif

#define	FOPEN_MAX	_NFILE
#define	FILENAME_MAX    1024	/* max # of characters in a path name */

#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2
#define	TMP_MAX		17576	/* 26 * 26 * 26 */

#if !defined(_STRICT_STDC) || defined(_POSIX_SOURCE) || defined(_XOPEN_SOURCE)
#define	L_ctermid	9
#define	L_cuserid	9
#define	P_tmpdir	"/var/tmp/"
#endif

#define	L_tmpnam	25	/* (sizeof(P_tmpdir) + 15) */

#define	stdin	(&__iob[0])
#define	stdout	(&__iob[1])
#define	stderr	(&__iob[2])

#ifndef	_FILEDEFED
#define	_FILEDEFED
typedef	__FILE FILE;
#endif

extern FILE		__iob[_NFILE];
extern FILE		*_lastbuf;
extern unsigned char 	*_bufendtab[];
extern unsigned char	 _sibuf[], _sobuf[];

/* Large file interfaces */
/* transition back from explicit 64-bit offset to implicit (64-bit) offset */
#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	fopen64		fopen
#pragma redefine_extname	freopen64	freopen
#else
#define	fopen64			fopen
#define	freopen64		freopen
#endif
#endif

/* transition from 32-bit offset to explicit 64-bit offset */
#if !defined(_LP64) && (_FILE_OFFSET_BITS == 64)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	fopen		fopen64
#pragma redefine_extname	freopen		freopen64
#else
#define	fopen			fopen64
#define	freopen			freopen64
#endif
#endif


extern int	remove(const char *);
extern int	rename(const char *, const char *);
extern int	fclose(FILE *);
extern int	fflush(FILE *);
extern FILE	*fopen(const char *, const char *);
extern FILE	*freopen(const char *, const char *, FILE *);
extern void	setbuf(FILE *, char *);
extern void	setbuffer(FILE *, char *, int);
extern int	setlinebuf(FILE *);
extern int	setvbuf(FILE *, char *, int, size_t);
/* PRINTFLIKE2 */
extern int	fprintf(FILE *, const char *, ...);
/* SCANFLIKE2 */
extern int	fscanf(FILE *, const char *, ...);
/* PRINTFLIKE1 */
extern int	printf(const char *, ...);
/* SCANFLIKE1 */
extern int	scanf(const char *, ...);
/* PRINTFLIKE2 */
extern char	*sprintf(const char *, const char *, ...);
/* SCANFLIKE2 */
extern int	sscanf(const char *, const char *, ...);
extern int	vfprintf(FILE *, const char *, __va_list);
extern int	vprintf(const char *, __va_list);
extern char	*vsprintf(char *, char *, __va_list);
extern int	fgetc(FILE *);
extern char	*fgets(char *, int, FILE *);
extern int	fputc(int, FILE *);
extern int	fputs(const char *, FILE *);
extern int	getc(FILE *);
extern int	getchar(void);
extern char	*gets(char *);
extern int	putc(int, FILE *);
extern int	putchar(int);
extern int	puts(const char *);
extern int	ungetc(int, FILE *);
extern size_t	fread(void *, size_t, size_t, FILE *);
extern size_t	fwrite(const void *, size_t, size_t, FILE *);
extern int	fgetpos(FILE *, fpos_t *);
extern int	fseek(FILE *, long, int);
extern int	fsetpos(FILE *, const fpos_t *);
extern long	ftell(FILE *);
extern void	rewind(FILE *);
extern void	clearerr(FILE *);
extern int	feof(FILE *);
extern int	ferror(FILE *);
extern void	perror(const char *);

extern int	__filbuf(FILE *);
extern int	__flsbuf(int, FILE *);

#if !defined(_STRICT_STDC) || defined(_POSIX_SOURCE) || defined(_XOPEN_SOURCE)
	/* non-ANSI standard compilation */

extern FILE    *fdopen(int, const char *);
extern FILE    *popen(const char *, const char *);
extern char    *ctermid(char *);
extern char    *cuserid(char *);
extern char    *tempnam(const char *, const char *);
extern int	getw(FILE *);
extern int	putw(int, FILE *);
extern int	pclose(FILE *);
extern int	system(const char *);
extern int	fileno(FILE *);

#endif	/* !defined(_STRICT_STDC) */


#ifndef __lint

#ifndef _LP64


#define	getc(p)		(--(p)->_cnt < 0 ? __filbuf(p) : (int)*(p)->_ptr++)
#define	putc(x, p)	(--(p)->_cnt < 0 ? __flsbuf((x), (p)) \
				: (int)(*(p)->_ptr++ = (x)))


#define	clearerr(p)	((void) ((p)->_flag &= ~(_IOERR | _IOEOF)))
#define	feof(p)		((p)->_flag & _IOEOF)
#define	ferror(p)	((p)->_flag & _IOERR)

#endif /* _LP64 */

#define	getchar()	getc(stdin)
#define	putchar(x)	putc((x), stdout)

#endif /* __lint */

#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern FILE	*fopen64(const char *, const char *);
extern FILE	*freopen64(const char *, const char *, FILE *);
#endif	/* _LARGEFILE64_SOURCE... */

#ifdef __cplusplus
}
#endif

#endif	/* _STDIO_H */
