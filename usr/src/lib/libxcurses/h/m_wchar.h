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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ISO/IEC 9899: 1990/Add.3: 1993 (E): Wide character header file
 *
 * Copyright 1992, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * $Header: /rd/h/rcs/m_wchar.h 1.51 1995/09/20 19:17:54 ant Exp $
 * 
 */

#ifndef __M_M_WCHAR_H__
#define __M_M_WCHAR_H__ 1

/*
 * m_wchar.h:
 *   configuration file for multi-byte vs. single byte enablement
 */

#include <wchar.h>
#include <wctype.h>
#include <limits.h>		/* Fetch MB_LEN_MAX */

#ifdef M_I18N_LOCKING_SHIFT
extern char *m_strsanitize (char *);
#else
#define m_strsanitize(str)	(str)
#endif /* M_I18N_LOCKING_SHIFT */

#ifdef	M_I18N_MB

# ifndef MB_LEN_MAX
#  error M_I18N_MB defined; but the local system does not support multibyte
# endif /* MB_LEN_MAX */

#define	MB_BEGIN	if (MB_CUR_MAX > 1) {
#define	MB_ELSE		} else {
#define	MB_END		}

#define	M_MB_L(s)	L##s

#ifndef _WUCHAR_T
#define _WUCHAR_T
/* a typedef to allow single byte distinction between char and uchar 
 * in MKS environment
 */
typedef	wchar_t	wuchar_t;
#endif /*_WUCHAR_T*/

extern wint_t	m_escapewc(wchar_t **);
extern int	m_fputmbs(FILE* fp, char *mbs, int wid, int prec, int ljust);
extern int	m_fgetws (wchar_t *, size_t, FILE *);
extern FILE	*m_fwopen (wchar_t *, char *);
extern	wchar_t	*m_wcsdup (const wchar_t *);
extern wchar_t	*m_mbstowcsdup (const char *s);
extern char	*m_wcstombsdup (const wchar_t *w);
extern char	*m_mbschr (const char *, int);
extern char	*m_mbsrchr (const char *, int);
extern char	*m_mbspbrk (const char *, const char *);
extern wchar_t	*m_wcsset (wchar_t *, wchar_t, size_t);
extern int	iswabsname (wchar_t *);

#define m_smalls(s) (s)
#define wctomb_init() wctomb(NULL,0)

#else	/* !M_I18N_MB */

/* include <stdlib.h> here,
 * We must include the multibyte function prototypes (in <stdlib.h>) before
 * redefining the prototype function names below.
 *
 * AND including <stdlib.h> DOES NOT cause a problem with wchar_t.
 *
 * ANSI says that the typedef of wchar_t should be defined in stdlib.h.
 * Thus, the prototypes in stdlib.h are declared using stdlib's definition
 * of wchar_t.
 */

#include <stdlib.h> 	/* DO NOT MOVE THIS include - THIS must be first */
#undef	m_escapewc
#undef	m_fgetws
#undef	m_fwopen
#undef	m_wcsdup
#undef	m_mbstowcsdup
#undef	m_wcstombsdup
#undef	m_mbschr
#undef	m_mbsrchr
#undef	m_mbspbrk
#undef	m_wcsset
#undef	iswabsname
#undef	m_fputmbs

#define	m_escapewc	m_escapec
#define	m_fgetws	m_fgets
#define	m_fwopen	fopen
#define	m_wcsdup	strdup
#define	m_mbstowcsdup	strdup
#define	m_wcstombsdup	strdup
#define	m_mbschr	strchr
#define	m_mbsrchr	strrchr
#define	m_mbspbrk	strpbrk
#define	m_wcsset	memset
#define	iswabsname(s)	isabsname(s)

#define	m_fputmbs(fp, str, wid, prec, ljust) \
	fprintf((fp), (ljust) ? "%-*.*s" : "%*.*s", wid, prec, str)


#define	MB_BEGIN	if (0) {
#define	MB_ELSE		} else {
#define	MB_END		}

#define	M_MB_L(s)	s

/*
 * Types and Macros
 */
#undef WEOF
#undef wint_t
#undef wuchar_t
#undef wchar_t

#define	WEOF	EOF
#define	wchar_t	char		/* ensures we never use the wchar_t typedef */
#define	wint_t	int		/* type as large as either wchar_t or WEOF */
#define	wuchar_t unsigned char 		/* Force override of typedef */

/*
 * Must define _WCHAR_T, _WINT_T and _WUCHAR_T to avoid typedefs collisions
 * in other system headers.
 * Most systems do something like this:
 *    #ifndef _WCHAR_T
 *      #define _WCHAR_T
 *      typedef unsigned short wchar_t
 *    #endif
 * in their system headers to avoid multiple declarations of wchar_t
 */
#undef _WCHAR_T
#undef _WINT_T
#undef _WUCHAR_T
#define _WCHAR_T
#define _WINT_T
#define _WUCHAR_T

/*
 * Input/Output
 */
#undef	fgetwc
#undef	getwc
#undef	getwchar
#undef	fputwc
#undef	putwc
#undef	putwchar
#undef	fputws
#undef	puts
#undef	fgetwx
#undef	getws
#undef	ungetwc
#undef	fwprintf
#undef	fwscanf
#undef	wprintf
#undef	wscanf
#undef	swscanf
#undef	vfwprintf
#undef	vwprintf
#undef	vswprintf

#define	fgetwc		fgetc
#define	getwc		getc
#define	getwchar	getchar
#define	fputwc		fputc
#define	putwc		putc
#define	putwchar	putchar
#define	fputws		fputs
#define	fgetws		fgets
#define	getws		gets
#define	ungetwc		ungetc
#define	fwprintf	fprintf
#define	fwscanf		fscanf
#define	wprintf		printf
#define	wscanf		scanf
#define	swscanf		sscanf
#define	vfwprintf	vfprintf
#define	vwprintf	vprintf
/* NOTE:
 *  In single byte mode, both swprintf() and vswprintf() are converted to
 *  similar, but NOT IDENTICAL, functions that have slightly different
 *  semantics.
 *  The 2nd argument to both these routines (e.g the size_t arg)
 *  is not used in the singlebyte environment since sprintf() and vsprintf()
 *  do not support this argument.
 *  One has to be careful when using this routine to not depend on
 *  the enforcement/safety of this 2nd argument. 
 *  
 *  swprintf() is converted to m_swprintf(), which is a C function
 *  (because it can use  a variable number of args),
 *  which is implemented as a call to vsprint() 
 *  vswprintf() is converted to vsprintf()
 *  
 */
#define	swprintf		m_swprintf
#define	vswprintf(w,n,f,v)	vsprintf((char*)w,(const char*)f, v)

#ifndef m_smalls
extern wchar_t *m_smalls (const wchar_t *);
#endif /*m_smalls*/

/*
 * General Utilities
 */
#undef wcstod
#undef wcstol
#undef wcstoul
#undef wctomb_init

#define	wcstod		strtod
#define	wcstol		strtol
#define	wcstoul		strtoul
#define wctomb_init()   (0)	 /* No state dependency for nonmultibyte. */

/*
 * Wide string handling
 */
#undef	wcscpy
#undef	wcsncpy
#undef	wcscat
#undef	wcsncat
#undef	wcscoll
#undef	wcscmp
#undef	wcsncmp
#undef	wcsxfrm
#undef	wcschr
#undef	wcscspn
#undef	wcspbrk
#undef	wcsrchr
#undef	wcsspn
#undef	wcsstr
#undef	wcstok
#undef	wcslen
#undef	wcswidth
#undef	wcwidth

#define	wcscpy		strcpy
#define	wcsncpy		strncpy
#define	wcscat		strcat
#define	wcsncat		strncat
#define	wcscoll		strcoll
#define	wcscmp		strcmp
#define	wcsncmp		strncmp
#define	wcsxfrm		strxfrm
#define	wcschr		strchr
#define	wcscspn		strcspn
#define	wcspbrk		strpbrk
#define	wcsrchr		strrchr
#define	wcsspn		strspn
#define	wcsstr		strstr
#define	wcstok(x, y, z)	strtok(x, y)
#define	wcslen		strlen
#define	wcswidth(s1, n)		strlen(s1)	/* Need a strnlen? */
#define	wcwidth(c)		1

/*
 * Date and time
 */
#undef wcsftime
#define	wcsftime	strftime

/*
 * Extended Multibyte functions
 */

#undef wctob
#undef sisinit

#define	wctob(c)		((int) (wint_t) (c))
#define	sisinit(p)		(1)	/* Always in initial state */

/*
 * Define prototypes for singlebyte equivalents of multibyte functions.
 * We have to use macros to map them to other function names, so that
 * they do not conflict with the prototypes from <stdlib.h> that may have
 * used a different definition of wchar_t.  The restartable functions are
 * mapped to their non-restartable counterparts, since there is no state
 * information to be preserved.
 */

#undef mblen
#undef mbrlen
#undef mbtowc
#undef mbrtowc
#undef wctomb
#undef wcrtomb
#undef mbstowcs
#undef mbsrtowcs
#undef wcstombs
#undef wcsrtombs

#define mblen(s, n)			m_sb_mblen(s, n)
#define mbrlen(s, n, ps)		m_sb_mblen(s, n)
#define mbtowc(pwc, s, n)		m_sb_mbtowc(pwc, s, n)
#define	mbrtowc(pwc, s, n, ps)		m_sb_mbtowc(pwc, s, n)
#define wctomb(s, wc)			m_sb_wctomb(s, wc)
#define	wcrtomb(s, wc, ps)		m_sb_wctomb(s, wc)
#define mbstowcs(pwcs, s, n)		m_sb_mbstowcs(pwcs, s, n)
#define mbsrtowcs(pwcs, s, n, ps)	m_sb_mbstowcs(pwcs, s, n)
#define wcstombs(s, pwcs, n)		m_sb_wcstombs(s, pwcs, n)
#define wcsrtombs(s, pwcs, n, ps)	m_sb_wcstombs(s, pwcs, n)

extern int m_sb_mblen(const char *s, size_t n);
extern int m_sb_mbtowc(wchar_t *pwc, const char *s, size_t n);
extern int m_sb_wctomb(char *s, wchar_t wc);
extern size_t m_sb_mbstowcs(wchar_t *pwcs, const char *s, size_t n);
extern size_t m_sb_wcstombs(char *s, const wchar_t *pwcs, size_t n);

/*
 * convert definitions from <wctype.h>
 */
#undef	iswalnum
#undef	iswalpha
#undef	iswcntrl
#undef	iswdigit
#undef	iswgraph
#undef	iswlower
#undef	iswprint
#undef	iswpunct
#undef	iswspace
#undef	iswupper
#undef	iswxdigit
#undef	iswblank
#undef	towlower
#undef	towupper

#define	iswalnum(c)	isalnum(c)
#define	iswalpha(c)	isalpha(c)
#define	iswcntrl(c)	iscntrl(c)
#define	iswdigit(c)	isdigit(c)
#define	iswgraph(c)	isgraph(c)
#define	iswlower(c)	islower(c)
#define	iswprint(c)	isprint(c)
#define	iswpunct(c)	ispunct(c)
#define	iswspace(c)	isspace(c)
#define	iswupper(c)	isupper(c)
#define	iswxdigit(c)	isxdigit(c)
#define	iswblank(c)	isblank(c)
#define	towlower(c)	tolower(c)
#define	towupper(c)	toupper(c)

/*
 * Note: MKS libc/gen/iswctype.c contains the system independent version 
 *       of wctype() and iswctype().
 *
 * In single byte mode, we can't use the names wctype() and iswctype().
 * These may have been defined in the system's headers (e.g <wctype.h>)
 * using the system definition of wint_t and wctype_t.
 * BUT we have just changed the meaning of wint_t above, to an 'int'
 * which may not be the same size as wint_t.
 * Thus, we rename them so that we don't get any prototype conflicts
 */
#undef wctype
#undef iswctype
#define wctype _m_wctype
#define iswctype _m_iswctype

extern wctype_t wctype(const char *property);
extern int iswctype(wint_t wc, wctype_t desc);


/*
 * .2 Functions
 */
#include <fnmatch.h>
#undef fnwwmatch
#undef fnwnmatch
#define	fnwwmatch	fnmatch
#define	fnwnmatch	fnmatch

#include <regex.h>
#undef regwcomp
#undef regwexec
#undef regwdosub
#undef regwdosuba
#undef regwmatch_t

#define regwcomp	regcomp
#define regwexec	regexec
#define regwdosub	regdosub
#define regwdosuba	regdosuba
#define regwmatch_t	regmatch_t

#endif	/* M_I18N_MB */

/*
 * prototypes that are common to both SingleByte and MultiByte
 */
extern int	m_mbswidth (const char *, size_t);
extern int	m_mbsrwidth (const char *, size_t, mbstate_t *);


#endif /*__M_M_WCHAR_H__*/ 
