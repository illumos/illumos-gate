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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */


#ifndef	__5include_stdio_h
#define	__5include_stdio_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stdtypes.h>	/* for size_t */

#if	pdp11
#define	BUFSIZ	512
#elif	u370
#define	BUFSIZ	4096
#else	/* just about every other UNIX system in existence */
#define	BUFSIZ	1024
#endif
#ifndef	EOF
#define	EOF		(-1)
#endif
#define	L_ctermid	9
#define	L_cuserid	9
#define	L_tmpnam	25		/* (sizeof (_tmpdir) + 15) */
#define	_tmpdir		"/usr/tmp/"
#define	FILENAME_MAX	1025
#define	TMP_MAX		17576

/*
 * ANSI C requires definitions of SEEK_CUR, SEEK_END, and SEEK_SET here.
 * They must be kept in sync with SEEK_* in <sys/unistd.h> (as required
 * by POSIX.1) and L_* in <sys/file.h>.
 * FOPEN_MAX should follow definition of _POSIX_OPEN_MAX in <sys/unistd.h>.
 */

#ifndef SEEK_SET
#define	SEEK_SET	0
#define	SEEK_CUR	1
#define	SEEK_END	2
#endif

#define	FOPEN_MAX	16

#ifndef	_POSIX_SOURCE
#define	P_tmpdir	_tmpdir
#endif
#ifndef	NULL
#define	NULL		0
#endif
#define	stdin		(&_iob[0])
#define	stdout		(&_iob[1])
#define	stderr		(&_iob[2])
/*
 * _IOLBF means that a file's output will be buffered line by line
 * In addition to being flags, _IONBF, _IOLBF and _IOFBF are possible
 * values for "type" in setvbuf.
 */
#define	_IOFBF		0000
#define	_IOREAD		0001
#define	_IOWRT		0002
#define	_IONBF		0004
#define	_IOMYBUF	0010
#define	_IOEOF		0020
#define	_IOERR		0040
#define	_IOSTRG		0100
#define	_IOLBF		0200
#define	_IORW		0400
/*
 * buffer size for multi-character output to unbuffered files
 */
#define	_SBFSIZ 8

typedef	struct {
#if	pdp11 || u370
	unsigned char	*_ptr;
	int	_cnt;
#else	/* just about every other UNIX system in existence */
	int	_cnt;
	unsigned char	*_ptr;
#endif
	unsigned char	*_base;
	int	_bufsiz;
	short	_flag;
	unsigned char	_file;	/* should be short */
} FILE;

#ifndef	_POSIX_SOURCE
extern char	*ctermid(char *);	/* unistd.h */
extern char	*cuserid(char *);	/* unistd.h */
extern FILE	*popen(char *, char *);
extern char	*tempnam(char *, char *);
#endif

extern void	clearerr(FILE *);
extern int	fclose(FILE *);
extern FILE	*fdopen(int, char *);
extern int	feof(FILE *);
extern int	ferror(FILE *);
extern int	fflush(FILE *);
extern int	fgetc(FILE *);
extern int	fileno(FILE *);
extern FILE	*fopen(char *, char *);
extern char	*fgets(char *, int, FILE *);
extern int	fprintf(FILE *, char *, ...);
extern int	fputc(int, FILE *);
extern int	fputs(char *, FILE *);
extern size_t	fread(char *, int, int, FILE *);
extern FILE	*freopen(char *, char *, FILE *);
extern int	fscanf(FILE *, char *, ...);
extern int	fseek(FILE *, long int, int);
extern long	ftell(FILE *);
extern size_t	fwrite(char *, int, int, FILE *);
extern int	getc(FILE *);
extern int	getchar(void);
extern char	*gets(char *);
extern void	perror(char *);
extern int	printf(char *, ...);
extern int	putc(int, FILE *);
extern int	putchar(int);
extern int	puts(char *);
extern int	remove(char *);
extern int	rename(char *, char *);
extern void	rewind(FILE *);
extern int	scanf(char *, ...);
extern void	setbuf(FILE *, char *);
extern int	sprintf(char *, char *, ...);
extern int	sscanf(char *, char *, ...);
extern FILE	*tmpfile(void);
extern char	*tmpnam(char *);
extern int	ungetc(int, FILE *);

#ifndef	lint
#define	getc(p)		(--(p)->_cnt >= 0 ? ((int) *(p)->_ptr++) : _filbuf(p))
#define	putc(x, p)	(--(p)->_cnt >= 0 ?\
	(int)(*(p)->_ptr++ = (unsigned char)(x)) :\
	(((p)->_flag & _IOLBF) && -(p)->_cnt < (p)->_bufsiz ?\
		((*(p)->_ptr = (unsigned char)(x)) != '\n' ?\
			(int)(*(p)->_ptr++) :\
			_flsbuf(*(unsigned char *)(p)->_ptr, p)) :\
		_flsbuf((unsigned char)(x), p)))
#define	getchar()	getc(stdin)
#define	putchar(x)	putc((x), stdout)
#define	clearerr(p)	((void) ((p)->_flag &= ~(_IOERR | _IOEOF)))
#define	feof(p)		(((p)->_flag & _IOEOF) != 0)
#define	ferror(p)	(((p)->_flag & _IOERR) != 0)
#endif

extern FILE	_iob[];

#endif	/* !__5include_stdio_h */
