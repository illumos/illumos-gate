/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
 * Glenn Fowler
 * AT&T Research
 *
 * generate limits features
 *
 *	FOPEN_MAX	POSIX says ANSI defines it but it's not in ANSI
 *
 * NOTE: two's complement binary integral representation assumed
 */

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide getpagesize getdtablesize
#else
#define getpagesize	______getpagesize
#define getdtablesize	______getdtablesize
#endif

/*
 * we'd like as many symbols as possible defined
 * the standards push the vendors the other way
 * but don't provide guard that lets everything through
 * so each vendor adds their own guard
 * many now include something like <standards.h> to
 * get it straight in one place -- <sys/types.h> should
 * kick that in
 */

#include "FEATURE/standards"
#include "FEATURE/lib"

#ifdef __sun
#define _timespec	timespec
#endif

#include <sys/types.h>

#undef	_SGIAPI
#define _SGIAPI		1

#if _hdr_limits
#include <limits.h>
#endif

#undef	_SGIAPI
#define _SGIAPI		0

#include "FEATURE/lib"
#include "FEATURE/common"

#if _hdr_unistd
#include <unistd.h>
#endif

#include "FEATURE/param"

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide getpagesize getdtablesize
#else
#undef	getpagesize
#undef	getdtablesize   
#endif

int main()
{
	char			c;
	unsigned char		uc;
	unsigned short		us;
	unsigned int		ui;
	unsigned long		ul;
	unsigned long		val;
#if _typ_uint64_t
	uint64_t		ull;
	uint64_t		vll;
#endif

	/*
	 * <limits.h> with *constant* valued macros
	 */

	printf("\n");
#ifndef CHAR_BIT
	uc = 0;
	uc = ~uc;
	val = 1;
	while (uc >>= 1) val++;
	printf("#define CHAR_BIT	%lu\n", val);
#endif
#ifndef MB_LEN_MAX
	val = 1;
	printf("#define MB_LEN_MAX	%lu\n", val);
#endif

	c = 0;
	c = ~c;
	uc = 0;
	uc = ~uc;
	us = 0;
	us = ~us;
	ui = 0;
	ui = ~ui;
	ul = 0;
	ul = ~ul;
#if _typ_uint64_t
	ull = 0;
	ull = ~ull;
#endif

#ifndef UCHAR_MAX
	val = uc;
	printf("#if defined(__STDC__)\n");
	printf("#define UCHAR_MAX	%luU\n", val);
	printf("#else\n");
	printf("#define UCHAR_MAX	%lu\n", val);
	printf("#endif\n");
#endif

#ifndef SCHAR_MIN
	val = (unsigned char)(uc >> 1) + 1;
	printf("#define SCHAR_MIN	(-%lu)\n", val);
#endif

#ifndef SCHAR_MAX
	val = (unsigned char)(uc >> 1);
	printf("#define SCHAR_MAX	%lu\n", val);
#endif

	if (c < 0)
	{
#ifndef CHAR_MIN
		printf("#define CHAR_MIN	SCHAR_MIN\n");
#endif

#ifndef CHAR_MAX
		printf("#define CHAR_MAX	SCHAR_MAX\n");
#endif
	}
	else
	{
#ifndef CHAR_MIN
		printf("#define CHAR_MIN	0\n");
#endif

#ifndef CHAR_MAX
		printf("#define CHAR_MAX	UCHAR_MAX\n");
#endif
	}

#ifndef USHRT_MAX
	val = us;
	printf("#if defined(__STDC__)\n");
	printf("#define USHRT_MAX	%luU\n", val);
	printf("#else\n");
	printf("#define USHRT_MAX	%lu\n", val);
	printf("#endif\n");
#endif

#ifndef SHRT_MIN
	val = (unsigned short)(us >> 1) + 1;
	printf("#define SHRT_MIN	(-%lu)\n", val);
#endif

#ifndef SHRT_MAX
	val = (unsigned short)(us >> 1);
	printf("#define SHRT_MAX	%lu\n", val);
#endif

	if (ui == us)
	{
#ifndef UINT_MAX
		printf("#define UINT_MAX	USHRT_MAX\n");
#endif

#ifndef INT_MIN
		printf("#define INT_MIN		SHRT_MIN\n");
#endif

#ifndef INT_MAX
		printf("#define INT_MAX		SHRT_MAX\n");
#endif
	}
	else
	{
#ifndef UINT_MAX
		val = ui;
		printf("#if defined(__STDC__)\n");
		printf("#define UINT_MAX	%luU\n", val);
		printf("#else\n");
		printf("#define UINT_MAX	%lu\n", val);
		printf("#endif\n");
#endif

#ifndef INT_MIN
		val = (unsigned int)(ui >> 1) + 1;
		if (ui == ul) printf("#define INT_MIN		(-%lu-1)\n", val - 1);
		else printf("#define INT_MIN		(-%lu)\n", val);
#endif

#ifndef INT_MAX
		val = (unsigned int)(ui >> 1);
		printf("#define INT_MAX		%lu\n", val);
#endif
	}

	if (ul == ui)
	{
#ifndef ULONG_MAX
		printf("#define ULONG_MAX	UINT_MAX\n");
#endif

#ifndef LONG_MIN
		printf("#define LONG_MIN	INT_MIN\n");
#endif

#ifndef LONG_MAX
		printf("#define LONG_MAX	INT_MAX\n");
#endif
	}
	else
	{
#ifndef ULONG_MAX
		val = ul;
		printf("#if defined(__STDC__)\n");
		printf("#define ULONG_MAX	%luLU\n", val);
		printf("#else\n");
		printf("#define ULONG_MAX	%lu\n", val);
		printf("#endif\n");
#endif

#ifndef LONG_MIN
		val = (unsigned long)(ul >> 1) + 1;
		printf("#define LONG_MIN	(-%luL-1L)\n", val - 1);
#endif

#ifndef LONG_MAX
		val = (unsigned long)(ul >> 1);
		printf("#define LONG_MAX	%luL\n", val);
#endif
	}

#if _typ_uint64_t && !_ast_intmax_long
	if (ull == ul)
	{
#ifndef ULLONG_MAX
		printf("#define ULLONG_MAX	ULONG_MAX\n");
#endif

#ifndef LLONG_MIN
		printf("#define LLONG_MIN	LONG_MIN\n");
#endif

#ifndef LLONG_MAX
		printf("#define LLONG_MAX	LONG_MAX\n");
#endif
	}
	else
	{
#ifndef ULLONG_MAX
		vll = ull;
		printf("#ifndef ULLONG_MAX\n");
		printf("#if defined(__STDC__) && _ast_LL\n");
		printf("#define ULLONG_MAX	%lluULL\n", vll);
		printf("#else\n");
		printf("#define ULLONG_MAX	%llu\n", vll);
		printf("#endif\n");
		printf("#endif\n");
#endif

#ifndef LLONG_MIN
		vll = (uint64_t)(ull >> 1) + 1;
		printf("#ifndef LLONG_MIN\n");
		printf("#if defined(__STDC__) && _ast_LL\n");
		printf("#define LLONG_MIN	(-%lluLL-1LL)\n", vll - 1);
		printf("#else\n");
		printf("#define LLONG_MIN	(-%llu-1)\n", vll - 1);
		printf("#endif\n");
		printf("#endif\n");
#endif

#ifndef LLONG_MAX
		vll = (uint64_t)(ull >> 1);
		printf("#ifndef LLONG_MAX\n");
		printf("#if defined(__STDC__) && _ast_LL\n");
		printf("#define LLONG_MAX	%lluLL\n", vll);
		printf("#else\n");
		printf("#define LLONG_MAX	%llu\n", vll);
		printf("#endif\n");
		printf("#endif\n");
#endif
	}
#endif

	printf("\n");
#ifdef _UWIN
	printf("#ifdef _UWIN\n");
	printf("#ifndef DBL_DIG\n");
	printf("#define DBL_DIG		15\n");
	printf("#endif\n");
	printf("#ifndef DBL_MAX\n");
	printf("#define DBL_MAX		1.7976931348623158e+308\n");
	printf("#endif\n");
	printf("#ifndef FLT_DIG\n");
	printf("#define FLT_DIG		6\n");
	printf("#endif\n");
	printf("#ifndef FLT_MAX\n");
	printf("#define FLT_MAX		3.402823466e+38F\n");
	printf("#endif\n");
	printf("#endif\n");
	printf("\n");
#endif

#include "conflim.h"

	printf("\n");

	return 0;
}
