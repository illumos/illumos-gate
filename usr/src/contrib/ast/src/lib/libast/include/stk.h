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
 * David Korn
 * AT&T Research
 *
 * Interface definitions for a stack-like storage library
 *
 */

#ifndef _STK_H
#define _STK_H

#include <sfio.h>

#define _Stk_data	_Stak_data

#define stkstd		(&_Stk_data)

#define	Stk_t		Sfio_t

#define STK_SMALL	1		/* small stkopen stack		*/
#define STK_NULL	2		/* return NULL on overflow	*/

#define	stkptr(sp,n)	((char*)((sp)->_data)+(n))
#define stktop(sp)	((char*)(sp)->_next)
#define	stktell(sp)	((sp)->_next-(sp)->_data)
#define stkseek(sp,n)	((n)==0?(char*)((sp)->_next=(sp)->_data):_stkseek(sp,n))

#if _BLD_ast && defined(__EXPORT__)
#define extern		extern __EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern Sfio_t		_Stk_data;

#undef	extern

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern Stk_t*		stkopen(int);
extern Stk_t*		stkinstall(Stk_t*, char*(*)(int));
extern int		stkclose(Stk_t*);
extern int		stklink(Stk_t*);
extern char*		stkalloc(Stk_t*, size_t);
extern char*		stkcopy(Stk_t*, const char*);
extern char*		stkset(Stk_t*, char*, size_t);
extern char*		_stkseek(Stk_t*, ssize_t);
extern char*		stkfreeze(Stk_t*, size_t);
extern int		stkon(Stk_t*, char*);

#undef	extern

#endif
