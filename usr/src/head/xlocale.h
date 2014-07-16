/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#ifndef _XLOCALE_H
#define	_XLOCALE_H

/*
 * This file supplies declarations for extended locale routines, as
 * originally delivered by MacOS X.  Many of these things are now
 * officially part of XPG7.  (Note that while the interfaces are the
 * same as MacOS X, there is no shared implementation.)
 *
 * Those declarations that are part of XPG7 are provided for the in the
 * XPG7-specified location.  This file lists just the declarations that
 * were not part of the standard.  These will be useful in their own right,
 * and will aid porting programs that don't strictly follow the standard.
 *
 * Note that it is an error to include this file in a program with strict
 * symbol visibilty rules (under strict ANSI or POSIX_C_SOURCE rules.)
 * If this is done, the symbols defined here will indeed be exposed to your
 * program, but those symbols that are part of the related standards might
 * not be.
 */

#include <sys/feature_tests.h>
#include <wchar.h>
#include <locale.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

extern int mbsinit_l(const mbstate_t *, locale_t);

extern size_t mbsrtowcs_l(wchar_t *_RESTRICT_KYWD, const char **_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t);

extern size_t mbsnrtowcs_l(wchar_t *_RESTRICT_KYWD, const char **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD, locale_t);

extern char *strptime_l(const char *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    struct tm *_RESTRICT_KYWD, locale_t);

extern int wcwidth_l(wchar_t, locale_t);

extern int wcswidth_l(const wchar_t *, size_t, locale_t);

extern int iswspecial_l(wint_t, locale_t);
extern int iswnumber_l(wint_t, locale_t);
extern int iswhexnumber_l(wint_t, locale_t);
extern int iswideogram_l(wint_t, locale_t);
extern int iswphonogram_l(wint_t, locale_t);

extern wint_t btowc_l(int, locale_t);
extern int wctob_l(wint_t, locale_t);
extern size_t mbrtowc_l(wchar_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t);
extern size_t mbstowcs_l(wchar_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD,
    size_t, locale_t);
extern int mblen_l(const char *, size_t, locale_t);
extern size_t mbrlen_l(const char *_RESTRICT_KYWD, size_t,
    mbstate_t *_RESTRICT_KYWD, locale_t);
extern int mbtowc_l(wchar_t *_RESTRICT_KYWD, const char *_RESTRICT_KYWD, size_t,
    locale_t);
extern size_t wcsrtombs_l(char *_RESTRICT_KYWD, const wchar_t **_RESTRICT_KYWD,
    size_t, mbstate_t *_RESTRICT_KYWD, locale_t);
extern size_t wcsnrtombs_l(char *_RESTRICT_KYWD, const wchar_t **_RESTRICT_KYWD,
    size_t, size_t, mbstate_t *_RESTRICT_KYWD, locale_t);
extern size_t wcrtomb_l(char *_RESTRICT_KYWD, wchar_t,
    mbstate_t *_RESTRICT_KYWD, locale_t);
extern size_t wcstombs_l(char *_RESTRICT_KYWD, const wchar_t *_RESTRICT_KYWD,
    size_t, locale_t);
extern int wctomb_l(char *, wchar_t, locale_t);

extern unsigned char __mb_cur_max_l(locale_t);
#ifndef	MB_CUR_MAX_L
#define	MB_CUR_MAX_L(l)	(__mb_cur_max_l(l))
#endif


#if defined(_XPG4) && !defined(_FILEDEFED) || __cplusplus >= 199711L
#define	_FILEDEFED
typedef __FILE FILE;
#endif

extern wint_t fgetwc_l(FILE *, locale_t);
extern wint_t getwc_l(FILE *, locale_t);

#ifndef getwchar_l
#define	getwchar_l(l)	fgetwc_l(stdin, (l))
#endif

#ifdef __cplusplus
}
#endif

#endif /* _XLOCALE_H */
