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
/* : : generated from /home/gisburn/ksh93/ast_ksh_20081104/build_i386_32bit/src/lib/libast/features/align.c by iffe version 2008-01-31 : : */
#ifndef _def_align_ast
#define _def_align_ast	1
#define _sys_types	1	/* #include <sys/types.h> ok */
typedef unsigned long ALIGN_INTEGRAL;

#define ALIGN_CHUNK		8192
#define ALIGN_INTEGRAL		long
#define ALIGN_INTEGER(x)	((ALIGN_INTEGRAL)(x))
#define ALIGN_POINTER(x)	((char*)(x))
#define ALIGN_ROUND(x,y)	ALIGN_POINTER(ALIGN_INTEGER((x)+(y)-1)&~((y)-1))

#define ALIGN_BOUND		ALIGN_BOUND2
#define ALIGN_ALIGN(x)		ALIGN_ALIGN2(x)
#define ALIGN_TRUNC(x)		ALIGN_TRUNC2(x)

#define ALIGN_BIT1		0x1
#define ALIGN_BOUND1		ALIGN_BOUND2
#define ALIGN_ALIGN1(x)		ALIGN_ALIGN2(x)
#define ALIGN_TRUNC1(x)		ALIGN_TRUNC2(x)
#define ALIGN_CLRBIT1(x)	ALIGN_POINTER(ALIGN_INTEGER(x)&0xfffffffe)
#define ALIGN_SETBIT1(x)	ALIGN_POINTER(ALIGN_INTEGER(x)|0x1)
#define ALIGN_TSTBIT1(x)	ALIGN_POINTER(ALIGN_INTEGER(x)&0x1)

#define ALIGN_BIT2		0x2
#define ALIGN_BOUND2		4
#define ALIGN_ALIGN2(x)		ALIGN_TRUNC2((x)+3)
#define ALIGN_TRUNC2(x)		ALIGN_POINTER(ALIGN_INTEGER(x)&0xfffffffc)
#define ALIGN_CLRBIT2(x)	ALIGN_POINTER(ALIGN_INTEGER(x)&0xfffffffd)
#define ALIGN_SETBIT2(x)	ALIGN_POINTER(ALIGN_INTEGER(x)|0x2)
#define ALIGN_TSTBIT2(x)	ALIGN_POINTER(ALIGN_INTEGER(x)&0x2)

#endif
