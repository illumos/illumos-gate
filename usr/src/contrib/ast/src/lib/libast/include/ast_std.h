/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Advanced Software Technology Library
 * AT&T Research
 *
 * a union of standard headers that works
 * with local extensions enabled
 * and local omission compensation
 */

#ifndef _AST_STD_H
#define _AST_STD_H		1
#define _AST_STD_I		1

#include <ast_common.h>

#if _BLD_ast
#define _BLD_aso	1
#define _BLD_cdt	1
#define _BLD_sfio	1
#if !_UWIN
#define _BLD_vmalloc	1
#endif
#endif

#ifdef	_SFSTDIO_H
#define _SKIP_SFSTDIO_H
#else
#define _SFSTDIO_H
#ifndef FILE
#ifndef _SFIO_H
struct _sfio_s;
#endif
#define FILE		struct _sfio_s
#ifndef	__FILE_typedef
#define __FILE_typedef	1
#endif
#ifndef _FILEDEFED
#define _FILEDEFED	1
#endif
#endif
#endif

#include <ast_lib.h>
#include <ast_sys.h>
#include <ast_getopt.h>	/* <stdlib.h> does this */
#include <ast_fcntl.h>
#include <ast_limits.h>
#include <ast_botch.h>

#ifdef	_SKIP_SFSTDIO_H
#undef	_SKIP_SFSTDIO_H
#else
#undef	_SFSTDIO_H
#undef	FILE
#endif

/* locale stuff */

#if !_hdr_locale

struct lconv
{
	char*	decimal_point;
	char*	thousands_sep;
	char*	grouping;
	char*	int_curr_symbol;
	char*	currency_symbol;
	char*	mon_decimal_point;
	char*	mon_thousands_sep;
	char*	mon_grouping;
	char*	positive_sign;
	char*	negative_sign;
	char	int_frac_digits;
	char	frac_digits;
	char	p_cs_precedes;
	char	p_sep_by_space;
	char	n_cs_precedes;
	char	n_sep_by_space;
	char	p_sign_posn;
	char	n_sign_posn;
};

#endif

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#if !_UWIN /* for ast54 compatibility */

#undef	getenv
#define getenv		_ast_getenv

#undef	setenviron
#define setenviron	_ast_setenviron

extern char*		getenv(const char*);

#endif

#undef	localeconv
#define localeconv	_ast_localeconv

#undef	setlocale
#define setlocale	_ast_setlocale

#undef	strerror
#define strerror	_ast_strerror

extern struct lconv*	localeconv(void);
extern char*		setenviron(const char*);
extern char*		setlocale(int, const char*);
extern char*		strerror(int);

#define AST_MESSAGE_SET		3	/* see <mc.h> mcindex()		*/

/*
 * maintain this order when adding categories
 */

#define AST_LC_ALL		0
#define AST_LC_COLLATE		1
#define AST_LC_CTYPE		2
#define AST_LC_MESSAGES		3
#define AST_LC_MONETARY		4
#define AST_LC_NUMERIC		5
#define AST_LC_TIME		6
#define AST_LC_IDENTIFICATION	7
#define AST_LC_ADDRESS		8
#define AST_LC_NAME		9
#define AST_LC_TELEPHONE	10
#define AST_LC_XLITERATE	11
#define AST_LC_MEASUREMENT	12
#define AST_LC_PAPER		13
#define AST_LC_COUNT		14
#define AST_LC_LANG		255

#define AST_LC_internal		1
#define AST_LC_test		(1L<<26)
#define AST_LC_setenv		(1L<<27)
#define AST_LC_find		(1L<<28)
#define AST_LC_debug		(1L<<29)
#define AST_LC_setlocale	(1L<<30)
#define AST_LC_translate	(1L<<31)

#ifndef LC_ALL
#define LC_ALL			(-AST_LC_ALL)
#endif
#ifndef LC_COLLATE
#define LC_COLLATE		(-AST_LC_COLLATE)
#endif
#ifndef LC_CTYPE
#define LC_CTYPE		(-AST_LC_CTYPE)
#endif
#ifndef LC_MESSAGES
#define LC_MESSAGES		(-AST_LC_MESSAGES)
#endif
#ifndef LC_MONETARY
#define LC_MONETARY		(-AST_LC_MONETARY)
#endif
#ifndef LC_NUMERIC
#define LC_NUMERIC		(-AST_LC_NUMERIC)
#endif
#ifndef LC_TIME
#define LC_TIME			(-AST_LC_TIME)
#endif
#ifndef LC_ADDRESS
#define LC_ADDRESS		(-AST_LC_ADDRESS)
#endif
#ifndef LC_IDENTIFICATION
#define LC_IDENTIFICATION	(-AST_LC_IDENTIFICATION)
#endif
#ifndef LC_NAME
#define LC_NAME			(-AST_LC_NAME)
#endif
#ifndef LC_TELEPHONE
#define LC_TELEPHONE		(-AST_LC_TELEPHONE)
#endif
#ifndef LC_XLITERATE
#define LC_XLITERATE		(-AST_LC_XLITERATE)
#endif
#ifndef LC_MEASUREMENT
#define LC_MEASUREMENT		(-AST_LC_MEASUREMENT)
#endif
#ifndef LC_PAPER
#define LC_PAPER		(-AST_LC_PAPER)
#endif
#ifndef LC_LANG
#define LC_LANG			(-AST_LC_LANG)
#endif

#undef	extern

#undef	strcoll
#if _std_strcoll
#define strcoll		_ast_info.collate
#else
#define strcoll		strcmp
#endif

typedef struct
{

	char*		id;

	struct
	{
	uint32_t	serial;
	uint32_t	set;
	}		locale;

	long		tmp_long;
	size_t		tmp_size;
	short		tmp_short;
	char		tmp_char;
	wchar_t		tmp_wchar;

	int		(*collate)(const char*, const char*);

	int		tmp_int;
	void*		tmp_pointer;

	int		mb_cur_max;
	int		(*mb_len)(const char*, size_t);
	int		(*mb_towc)(wchar_t*, const char*, size_t);
	size_t		(*mb_xfrm)(char*, const char*, size_t);
	int		(*mb_width)(wchar_t);
	int		(*mb_conv)(char*, wchar_t);

	uint32_t	env_serial;
	uint32_t	mb_sync;
	uint32_t	version;

	int		(*mb_alpha)(wchar_t);

	char		pad[936 - sizeof(void*)];

} _Ast_info_t;

#if _BLD_ast && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern _Ast_info_t	_ast_info;

#undef	extern

/* largefile hackery -- ast uses the large versions by default */

#if _typ_ino64_t
#undef	ino_t
#define ino_t		ino64_t
#endif
#if _typ_off64_t
#undef	off_t
#define off_t		off64_t
#endif
#if !defined(ftruncate) && _lib_ftruncate64
#define ftruncate	ftruncate64
extern int		ftruncate64(int, off64_t);
#endif
#if !defined(lseek) && _lib_lseek64
#define lseek		lseek64
extern off64_t		lseek64(int, off64_t, int);
#endif
#if !defined(truncate) && _lib_truncate64
#define truncate	truncate64
extern int		truncate64(const char*, off64_t);
#endif

/* direct macro access for bsd crossover */

#if !defined(__cplusplus)

#if !defined(memcpy) && !defined(_lib_memcpy) && defined(_lib_bcopy)
#define memcpy(t,f,n)	(bcopy(f,t,n),(t))
#endif

#if !defined(memzero) && !defined(_lib_memzero)
#if defined(_lib_memset) || !defined(_lib_bzero)
#define memzero(b,n)	memset(b,0,n)
#else
#define memzero(b,n)	(bzero(b,n),(b))
#endif
#endif

#endif

#if !defined(remove)
extern int		remove(const char*);
#endif

#if !defined(rename)
extern int		rename(const char*, const char*);
#endif

#if !defined(strchr) && !defined(_lib_strchr) && defined(_lib_index)
#define strchr(s,c)	index(s,c)
#endif

#if !defined(strrchr) && !defined(_lib_strrchr) && defined(_lib_rindex)
#define strrchr(s,c)	rindex(s,c)
#endif

/* and now introducing prototypes botched by the standard(s) */

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#undef	getpgrp
#define	getpgrp()	_ast_getpgrp()
extern int		_ast_getpgrp(void);

#undef	extern

/*
 * and finally, standard interfaces hijacked by ast
 * _AST_STD_I delays headers that require <ast_map.h>
 */

#include <ast_map.h>

#undef	_AST_STD_I

#if _AST_GETOPT_H < 0
#undef	_AST_GETOPT_H
#include <ast_getopt.h>
#endif

#if _GETOPT_H < 0
#undef	_GETOPT_H
#include <getopt.h>
#endif

#if _REGEX_H < 0
#undef	_REGEX_H
#include <regex.h>
#endif

#endif
