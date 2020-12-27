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
 * homogenous stack routine definitions
 */

#ifndef _STACK_H
#define _STACK_H

typedef struct stacktable* STACK;	/* stack pointer		*/
typedef struct stackposition STACKPOS;	/* stack position		*/

struct stackblock			/* stack block cell		*/
{
	void**		  stack;	/* actual stack			*/
	struct stackblock* prev;	/* previous block in list	*/
	struct stackblock* next;	/* next block in list		*/
};

struct stackposition			/* stack position		*/
{
	struct stackblock* block;	/* current block pointer	*/
	int		index;		/* index within current block	*/
};

struct stacktable			/* stack information		*/
{
	struct stackblock* blocks;	/* stack table blocks		*/
	void*		error;		/* error return value		*/
	int		size;		/* size of each block		*/
	STACKPOS	position;	/* current stack position	*/
};

/*
 * map old names to new
 */

#define mkstack		stackalloc
#define rmstack		stackfree
#define clrstack	stackclear
#define getstack	stackget
#define pushstack	stackpush
#define popstack	stackpop
#define posstack	stacktell

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern STACK		stackalloc(int, void*);
extern void		stackfree(STACK);
extern void		stackclear(STACK);
extern void*		stackget(STACK);
extern int		stackpush(STACK, void*);
extern int		stackpop(STACK);
extern void		stacktell(STACK, int, STACKPOS*);

#undef	extern

#endif
