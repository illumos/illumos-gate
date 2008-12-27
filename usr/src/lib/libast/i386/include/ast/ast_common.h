/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
/* : : generated from /home/gisburn/ksh93/ast_ksh_20081104/build_i386_32bit/src/lib/libast/features/common by iffe version 2008-01-31 : : */
#ifndef _AST_COMMON_H
#define _AST_COMMON_H	1
#define _sys_types	1	/* #include <sys/types.h> ok */
#define _hdr_pthread	1	/* #include <pthread.h> ok */
#define _hdr_stdarg	1	/* #include <stdarg.h> ok */
#define _hdr_stddef	1	/* #include <stddef.h> ok */
#define _hdr_stdint	1	/* #include <stdint.h> ok */
#define _hdr_inttypes	1	/* #include <inttypes.h> ok */
#define _hdr_unistd	1	/* #include <unistd.h> ok */
#define _hdr_time	1	/* #include <time.h> ok */
#define _sys_time	1	/* #include <sys/time.h> ok */
#define _sys_times	1	/* #include <sys/times.h> ok */
#define _hdr_stdlib	1	/* #include <stdlib.h> ok */
#define _typ_long_double	1	/* long double is a type */
#define _typ_size_t	1	/* size_t is a type */
#define _typ_ssize_t	1	/* ssize_t is a type */
#define _sys_stat	1	/* #include <sys/stat.h> ok */
#define _sys_socket	1	/* #include <sys/socket.h> ok */
#define _std_proto	1	/* standard C prototypes ok */
#define _ptr_void	1	/* standard C void* ok */
/* disable non-standard linux/gnu inlines */
#ifdef __GNUC__	
#	undef	__OPTIMIZE_SIZE__
#	define	__OPTIMIZE_SIZE__	1
#endif

/* __STD_C indicates that the language is ANSI-C or C++ */
#if !defined(__STD_C) && __STDC__
#	define	__STD_C		1
#endif
#if !defined(__STD_C) && (__cplusplus || c_plusplus)
#	define __STD_C		1
#endif
#if !defined(__STD_C) && _std_proto
#	define __STD_C		1
#endif
#if !defined(__STD_C)
#	define __STD_C		0
#endif

/* extern symbols must be protected against C++ name mangling */
#ifndef _BEGIN_EXTERNS_
#	if __cplusplus || c_plusplus
#		define _BEGIN_EXTERNS_	extern "C" {
#		define _END_EXTERNS_	}
#	else
#		define _BEGIN_EXTERNS_
#		define _END_EXTERNS_
#	endif
#endif

/* _ARG_ simplifies function prototyping among flavors of C */
#ifndef _ARG_
#	if __STD_C
#		define _ARG_(x)	x
#	else
#		define _ARG_(x)	()
#	endif
#endif

/* _NIL_ simplifies defining nil pointers to a given type */
#ifndef _NIL_
#	define _NIL_(x)	((x)0)
#endif

/* __INLINE__ is the inline keyword */
#if !defined(__INLINE__) && defined(__cplusplus)
#	define __INLINE__	inline
#endif
#if !defined(__INLINE__) && defined(_WIN32) && !defined(__GNUC__)
#	define __INLINE__	__inline
#endif

/* Void_t is defined so that Void_t* can address any type */
#ifndef Void_t
#	if __STD_C
#		define Void_t		void
#	else
#		define Void_t		char
#	endif
#endif

/* windows variants and veneers */
#if !defined(_WINIX) && (_UWIN || __CYGWIN__ || __EMX__)
#	define _WINIX		1
#endif

/* dynamic linked library external scope handling */
#ifdef __DYNAMIC__
#	undef	__DYNAMIC__
#	ifndef _DLL
#		define _DLL		1
#	endif
#endif
#if _dll_import
#	if _BLD_STATIC && !_BLD_DLL
#		undef	_DLL
#	else
#		if !_UWIN && !defined(_DLL)
#			define _DLL		1
#		endif
#	endif
#	if !defined(__EXPORT__) && _BLD_DLL
#		define __EXPORT__	__declspec(dllexport)
#	endif
#	if !defined(__IMPORT__) && ( _BLD_DLL || defined(_DLL) )
#		define __IMPORT__	__declspec(dllimport)
#	endif
#	if _BLD_DLL && _UWIN
#	define __DYNAMIC__(v)		(_ast_getdll()->_ast_ ## v)
#	endif
#endif
#if !defined(_astimport)
#	if defined(__IMPORT__) && defined(_DLL)
#		define _astimport	__IMPORT__
#	else
#		define _astimport	extern
#	endif
#endif
#if _dll_import && ( !_BLD_DLL || _WINIX && !_UWIN )
#	ifdef __STDC__
#	define __EXTERN__(T,obj)	extern T obj; T* _imp__ ## obj = &obj
#	define __DEFINE__(T,obj,val)	T obj = val; T* _imp__ ## obj = &obj
#	else
#	define __EXTERN__(T,obj)	extern T obj; T* _imp__/**/obj = &obj
#	define __DEFINE__(T,obj,val)	T obj = val; T* _imp__/**/obj = &obj
#	endif
#else
#	define __EXTERN__(T,obj)	extern T obj
#	define __DEFINE__(T,obj,val)	T obj = val
#endif

#define _ast_LL	1	/* LL numeric suffix supported */
#define _ast_int1_t		char
#define _ast_int2_t		short
#define _ast_int4_t		int
#define _ast_int8_t		long long
#define _ast_intmax_t		_ast_int8_t
#define _ast_intswap		7

#define _ast_flt4_t		float
#define _ast_flt8_t		double
#define _ast_flt12_t		long double
#define _ast_fltmax_t		_ast_flt12_t
#define _typ_int8_t	1	/* int8_t is a type */
#define _typ_uint8_t	1	/* uint8_t is a type */
#define _typ_int16_t	1	/* int16_t is a type */
#define _typ_uint16_t	1	/* uint16_t is a type */
#define _typ_int32_t	1	/* int32_t is a type */
#define _typ_uint32_t	1	/* uint32_t is a type */
#define _typ_int64_t	1	/* int64_t is a type */
#define _typ_uint64_t	1	/* uint64_t is a type */
#define _typ_intmax_t	1	/* intmax_t is a type */
#define _typ_uintmax_t	1	/* uintmax_t is a type */

#ifndef va_listref
#define va_listref(p) (p)	/* pass va_list to varargs function */
#define va_listval(p) (p)	/* retrieve va_list from va_arg(ap,va_listarg) */
#define va_listarg va_list	/* va_arg() va_list type */
#ifndef	va_start
#if __STD_C
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#endif
#endif
#ifndef _AST_STD_H
#	if __STD_C && _hdr_stddef
#	include	<stddef.h>
#	endif
#	if _sys_types
#	include	<sys/types.h>
#	endif
#	if _hdr_stdint
#	include	<stdint.h>
#	else
#		if _hdr_inttypes
#		include	<inttypes.h>
#		endif
#	endif
#endif
#if !_typ_size_t
#	define _typ_size_t	1
	typedef int size_t;
#endif
#if !_typ_ssize_t
#	define _typ_ssize_t	1
	typedef int ssize_t;
#endif
#ifndef _AST_STD_H
#	if !_def_map_ast
#		include <ast_map.h>
#	endif
#endif

#endif
