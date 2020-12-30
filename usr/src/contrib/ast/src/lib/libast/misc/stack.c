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
 * pointer stack routines
 */

static const char id_stack[] = "\n@(#)$Id: stack (AT&T Bell Laboratories) 1984-05-01 $\0\n";

#include <ast.h>
#include <stack.h>

/*
 * create a new stack
 */

STACK
stackalloc(register int size, void* error)
{
	register STACK			stack;
	register struct stackblock	*b;

	if (size <= 0) size = 100;
	if (!(stack = newof(0, struct stacktable, 1, 0))) return(0);
	if (!(b = newof(0, struct stackblock, 1, 0)))
	{
		free(stack);
		return(0);
	}
	if (!(b->stack = newof(0, void*, size, 0)))
	{
		free(b);
		free(stack);
		return(0);
	}
	stack->blocks = b;
	stack->size = size;
	stack->error = error;
	stack->position.block = b;
	stack->position.index = -1;
	b->next = 0;
	b->prev = 0;
	return(stack);
}

/*
 * remove a stack
 */

void
stackfree(register STACK stack)
{
	register struct stackblock*	b;
	register struct stackblock*	p;

	b = stack->blocks;
	while (p = b)
	{
		b = p->next;
		free(p->stack);
		free(p);
	}
	free(stack);
}

/*
 * clear stack
 */

void
stackclear(register STACK stack)
{
	stack->position.block = stack->blocks;
	stack->position.index = -1;
}

/*
 * get value on top of stack
 */

void*
stackget(register STACK stack)
{
	if (stack->position.index < 0) return(stack->error);
	else return(stack->position.block->stack[stack->position.index]);
}

/*
 * push value on to stack
 */

int
stackpush(register STACK stack, void* value)
{
	register struct stackblock	*b;

	if (++stack->position.index >= stack->size)
	{
		b = stack->position.block;
		if (b->next) b = b->next;
		else
		{
			if (!(b->next = newof(0, struct stackblock, 1, 0)))
				return(-1);
			b = b->next;
			if (!(b->stack = newof(0, void*, stack->size, 0)))
				return(-1);
			b->prev = stack->position.block;
			b->next = 0;
		}
		stack->position.block = b;
		stack->position.index = 0;
	}
	stack->position.block->stack[stack->position.index] = value;
	return(0);
}

/*
 * pop value off stack
 */

int
stackpop(register STACK stack)
{
	/*
	 * return:
	 *
	 *	-1	if stack empty before pop
	 *	 0	if stack empty after pop
	 *	 1	if stack not empty before & after pop
	 */

	if (stack->position.index < 0) return(-1);
	else if (--stack->position.index < 0)
	{
		if (!stack->position.block->prev) return(0);
		stack->position.block = stack->position.block->prev;
		stack->position.index = stack->size - 1;
		return(1);
	}
	else return(1);
}

/*
 * set|get stack position
 */

void
stacktell(register STACK stack, int set, STACKPOS* position)
{
	if (set) stack->position = *position;
	else *position = stack->position;
}
