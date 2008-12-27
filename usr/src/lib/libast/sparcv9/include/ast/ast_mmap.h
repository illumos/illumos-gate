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
/* : : generated from /home/gisburn/ksh93/ast_ksh_20081104/build_sparc_64bit/src/lib/libast/features/mmap by iffe version 2008-01-31 : : */
#ifndef _def_mmap_ast
#define _def_mmap_ast	1
#define _sys_types	1	/* #include <sys/types.h> ok */
#define _sys_mman	1	/* #include <sys/mman.h> ok */
#define _lib_mmap	1	/* standard mmap interface that works */
#define _lib_mmap64	1	/* mmap64 interface and implementation work */
#define _mmap_anon	1	/* use mmap MAP_ANON to get raw memory */
#define _mmap_devzero	1	/* use mmap on /dev/zero to get raw memory */

/* some systems get it wrong but escape concise detection */
#ifndef _NO_MMAP
#if __CYGWIN__
#define _NO_MMAP	1
#endif
#endif

#if _NO_MMAP
#undef	_lib_mmap
#undef	_lib_mmap64
#undef	_mmap_anon
#undef	_mmap_devzero
#undef	_mmap_worthy
#endif

#endif
