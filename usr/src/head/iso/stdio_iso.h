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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 PALO, Richard.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <stdio.h>.
 */

/*
 * User-visible pieces of the ANSI C standard I/O package.
 */

#ifndef _ISO_STDIO_ISO_H
#define	_ISO_STDIO_ISO_H

#include <sys/feature_tests.h>
#include <sys/null.h>
#include <sys/va_list.h>
#include <stdio_tag.h>
#include <stdio_impl.h>

/*
 * If feature test macros are set that enable interfaces that use types
 * defined in <sys/types.h>, get those types by doing the include.
 *
 * Note that in asking for the interfaces associated with this feature test
 * macro one also asks for definitions of the POSIX types.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LP64) && (_FILE_OFFSET_BITS == 64 || defined(_LARGEFILE64_SOURCE))
/*
 * The following typedefs are adopted from ones in <sys/types.h> (with leading
 * underscores added to avoid polluting the ANSI C name space).  See the
 * commentary there for further explanation.
 */
#if defined(_LONGLONG_TYPE)
typedef	long long	__longlong_t;
#else
/* used to reserve space and generate alignment */
typedef union {
	double	_d;
	int	_l[2];
} __longlong_t;
#endif
#endif  /* !_LP64 && _FILE_OFFSET_BITS == 64 || defined(_LARGEFILE64_SOURCE) */

#if __cplusplus >= 199711L
namespace std {
#endif

#if !defined(_FILEDEFED) || __cplusplus >= 199711L
#define	_FILEDEFED
typedef	__FILE FILE;
#endif

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef unsigned long	size_t;		/* size of something in bytes */
#else
typedef unsigned int	size_t;		/* (historical version) */
#endif
#endif	/* !_SIZE_T */

#if defined(_LP64) || _FILE_OFFSET_BITS == 32
typedef long		fpos_t;
#else
typedef	__longlong_t	fpos_t;
#endif

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#define	BUFSIZ	1024

/*
 * The value of _NFILE is defined in the Processor Specific ABI.  The value
 * is chosen for historical reasons rather than for truly processor related
 * attribute.  Note that the SPARC Processor Specific ABI uses the common
 * UNIX historical value of 20 so it is allowed to fall through.
 */
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

#define	L_tmpnam	25	/* (sizeof(P_tmpdir) + 15) */

extern __FILE	__iob[_NFILE];
#define	stdin	(&__iob[0])
#define	stdout	(&__iob[1])
#define	stderr	(&__iob[2])

#if __cplusplus >= 199711L
namespace std {
#endif

#if !defined(_LP64) && !defined(_LONGLONG_TYPE)

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname fprintf	_fprintf_c89
#pragma redefine_extname printf		_printf_c89
#pragma redefine_extname sprintf	_sprintf_c89
#pragma redefine_extname vfprintf	_vfprintf_c89
#pragma redefine_extname vprintf	_vprintf_c89
#pragma redefine_extname vsprintf	_vsprintf_c89
#pragma redefine_extname fscanf		_fscanf_c89
#pragma redefine_extname scanf		_scanf_c89
#pragma redefine_extname sscanf		_sscanf_c89
#else
#define	fprintf		_fprintf_c89
#define	printf		_printf_c89
#define	sprintf		_sprintf_c89
#define	vfprintf	_vfprintf_c89
#define	vprintf		_vprintf_c89
#define	vsprintf	_vsprintf_c89
#define	fscanf		_fscanf_c89
#define	scanf		_scanf_c89
#define	sscanf		_sscanf_c89
#endif

#endif /* !defined(_LP64) && !defined(_LONGLONG_TYPE) */

extern int	remove(const char *);
extern int	rename(const char *, const char *);
extern FILE	*tmpfile(void);
extern char	*tmpnam(char *);
extern int	fclose(FILE *);
extern int	fflush(FILE *);
extern FILE	*fopen(const char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD);
extern FILE	*freopen(const char *_RESTRICT_KYWD,
			const char *_RESTRICT_KYWD, FILE *_RESTRICT_KYWD);
extern void	setbuf(FILE *_RESTRICT_KYWD, char *_RESTRICT_KYWD);
extern int	setvbuf(FILE *_RESTRICT_KYWD, char *_RESTRICT_KYWD, int,
			size_t);
/* PRINTFLIKE2 */
extern int	fprintf(FILE *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, ...);
/* SCANFLIKE2 */
extern int	fscanf(FILE *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, ...);
/* PRINTFLIKE1 */
extern int	printf(const char *_RESTRICT_KYWD, ...);
/* SCANFLIKE1 */
extern int	scanf(const char *_RESTRICT_KYWD, ...);
/* PRINTFLIKE2 */
extern int	sprintf(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, ...);
/* SCANFLIKE2 */
extern int	sscanf(const char *_RESTRICT_KYWD,
			const char *_RESTRICT_KYWD, ...);
extern int	vfprintf(FILE *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
			__va_list);
extern int	vprintf(const char *_RESTRICT_KYWD, __va_list);
extern int	vsprintf(char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
			__va_list);
extern int	fgetc(FILE *);
extern char	*fgets(char *_RESTRICT_KYWD, int, FILE *_RESTRICT_KYWD);
extern int	fputc(int, FILE *);
extern int	fputs(const char *_RESTRICT_KYWD, FILE *_RESTRICT_KYWD);
#if (__cplusplus >= 199711L && (defined(_LP64) || defined(_REENTRANT))) || \
	__cplusplus < 199711L
extern int	getc(FILE *);
extern int	putc(int, FILE *);
#endif
#if (__cplusplus >= 199711L && defined(_REENTRANT)) || \
	__cplusplus < 199711L
extern int	getchar(void);
extern int	putchar(int);
#endif

/*
 * ISO/IEC C11 removed gets from the standard library. Therefore if a strict C11
 * environment has been requested, we remove it.
 */
#if !defined(_STDC_C11) || defined(__EXTENSIONS__)
extern char	*gets(char *);
#endif
extern int	puts(const char *);
extern int	ungetc(int, FILE *);
extern size_t	fread(void *_RESTRICT_KYWD, size_t, size_t,
	FILE *_RESTRICT_KYWD);
extern size_t	fwrite(const void *_RESTRICT_KYWD, size_t, size_t,
	FILE *_RESTRICT_KYWD);
#if !defined(__lint) || defined(_LP64) || _FILE_OFFSET_BITS == 32
extern int	fgetpos(FILE *_RESTRICT_KYWD, fpos_t *_RESTRICT_KYWD);
extern int	fsetpos(FILE *, const fpos_t *);
#endif
extern int	fseek(FILE *, long, int);
extern long	ftell(FILE *);
extern void	rewind(FILE *);
#if (__cplusplus >= 199711L && (defined(_LP64) || defined(_REENTRANT))) || \
	__cplusplus < 199711L
extern void	clearerr(FILE *);
extern int	feof(FILE *);
extern int	ferror(FILE *);
#endif
extern void	perror(const char *);

#ifndef	_LP64
extern int	__filbuf(FILE *);
extern int	__flsbuf(int, FILE *);
#endif	/*	_LP64	*/

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#if !defined(__lint)

#if	!defined(_REENTRANT) && !defined(_LP64)

#if __cplusplus >= 199711L
namespace std {
inline int getc(FILE *_p) {
	return (--_p->_cnt < 0 ? __filbuf(_p) : (int)*_p->_ptr++); }
inline int putc(int _x, FILE *_p) {
	return (--_p->_cnt < 0 ? __flsbuf(_x, _p)
		: (int)(*_p->_ptr++ = (unsigned char) _x)); }
}
#else /* __cplusplus >= 199711L */
#define	getc(p)		(--(p)->_cnt < 0 ? __filbuf(p) : (int)*(p)->_ptr++)
#define	putc(x, p)	(--(p)->_cnt < 0 ? __flsbuf((x), (p)) \
				: (int)(*(p)->_ptr++ = (unsigned char) (x)))
#endif /* __cplusplus >= 199711L */

#endif /* !defined(_REENTRANT) && !defined(_LP64) */

#ifndef	_REENTRANT

#if __cplusplus >= 199711L
namespace std {
inline int getchar() { return getc(stdin); }
inline int putchar(int _x) { return putc(_x, stdout); }
}
#else
#define	getchar()	getc(stdin)
#define	putchar(x)	putc((x), stdout)
#endif /* __cplusplus >= 199711L */

#ifndef	_LP64
#if __cplusplus >= 199711L
namespace std {
inline void clearerr(FILE *_p) { _p->_flag &= ~(_IOERR | _IOEOF); }
inline int feof(FILE *_p) { return _p->_flag & _IOEOF; }
inline int ferror(FILE *_p) { return _p->_flag & _IOERR; }
}
#else /* __cplusplus >= 199711L */
#define	clearerr(p)	((void)((p)->_flag &= ~(_IOERR | _IOEOF)))
#define	feof(p)		((p)->_flag & _IOEOF)
#define	ferror(p)	((p)->_flag & _IOERR)
#endif /* __cplusplus >= 199711L */
#endif	/* _LP64 */

#endif	/* _REENTRANT */

#endif	/* !defined(__lint) */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_STDIO_ISO_H */
