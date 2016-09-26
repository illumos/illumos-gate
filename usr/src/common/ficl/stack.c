/*
 * s t a c k . c
 * Forth Inspired Command Language
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 16 Oct 1997
 * $Id: stack.c,v 1.11 2010/08/12 13:57:22 asau Exp $
 */
/*
 * Copyright (c) 1997-2001 John Sadler (john_sadler@alum.mit.edu)
 * All rights reserved.
 *
 * Get the latest Ficl release at http://ficl.sourceforge.net
 *
 * I am interested in hearing from anyone who uses Ficl. If you have
 * a problem, a success story, a defect, an enhancement request, or
 * if you would like to contribute to the Ficl release, please
 * contact me by email at the address above.
 *
 * L I C E N S E  and  D I S C L A I M E R
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ficl.h"

#define	STKDEPTH(s)	(((s)->top - (s)->base) + 1)

/*
 * N O T E: Stack convention:
 *
 * THIS CHANGED IN FICL 4.0!
 *
 * top points to the *current* top data value
 * push: increment top, store value at top
 * pop:  fetch value at top, decrement top
 * Stack grows from low to high memory
 */

/*
 * v m C h e c k S t a c k
 * Check the parameter stack for underflow or overflow.
 * size controls the type of check: if size is zero,
 * the function checks the stack state for underflow and overflow.
 * If size > 0, checks to see that the stack has room to push
 * that many cells. If less than zero, checks to see that the
 * stack has room to pop that many cells. If any test fails,
 * the function throws (via vmThrow) a VM_ERREXIT exception.
 */
void
ficlStackCheck(ficlStack *stack, int popCells, int pushCells)
{
#if FICL_ROBUST >= 1
	int nFree = stack->size - STKDEPTH(stack);

	if (popCells > STKDEPTH(stack))
		ficlVmThrowError(stack->vm, "Error: %s stack underflow",
		    stack->name);

	if (nFree < pushCells - popCells)
		ficlVmThrowError(stack->vm, "Error: %s stack overflow",
		    stack->name);
#else /* FICL_ROBUST >= 1 */
	FICL_IGNORE(stack);
	FICL_IGNORE(popCells);
	FICL_IGNORE(pushCells);
#endif /* FICL_ROBUST >= 1 */
}

/*
 * s t a c k C r e a t e
 */

ficlStack *
ficlStackCreate(ficlVm *vm, char *name, unsigned size)
{
	size_t totalSize = sizeof (ficlStack) + (size * sizeof (ficlCell));
	ficlStack *stack = ficlMalloc(totalSize);

	FICL_VM_ASSERT(vm, size != 0);
	FICL_VM_ASSERT(vm, stack != NULL);

	stack->size = size;
	stack->frame = NULL;

	stack->vm = vm;
	stack->name = name;

	ficlStackReset(stack);
	return (stack);
}

/*
 *                  s t a c k D e l e t e
 */
void
ficlStackDestroy(ficlStack *stack)
{
	if (stack)
		ficlFree(stack);
}

/*
 * s t a c k D e p t h
 */
int
ficlStackDepth(ficlStack *stack)
{
	return (STKDEPTH(stack));
}

/*
 * s t a c k D r o p
 */
void
ficlStackDrop(ficlStack *stack, int n)
{
	FICL_VM_ASSERT(stack->vm, n > 0);
	stack->top -= n;
}

/*
 * s t a c k F e t c h
 */
ficlCell
ficlStackFetch(ficlStack *stack, int n)
{
	return (stack->top[-n]);
}

void
ficlStackStore(ficlStack *stack, int n, ficlCell c)
{
	stack->top[-n] = c;
}

/*
 * s t a c k G e t T o p
 */
ficlCell
ficlStackGetTop(ficlStack *stack)
{
	return (stack->top[0]);
}

#if FICL_WANT_LOCALS
/*
 * s t a c k L i n k
 * Link a frame using the stack's frame pointer. Allot space for
 * size cells in the frame
 * 1) Push frame
 * 2) frame = top
 * 3) top += size
 */
void
ficlStackLink(ficlStack *stack, int size)
{
	ficlStackPushPointer(stack, stack->frame);
	stack->frame = stack->top + 1;
	stack->top += size;
}

/*
 * s t a c k U n l i n k
 * Unink a stack frame previously created by stackLink
 * 1) top = frame
 * 2) frame = pop()
 */
void
ficlStackUnlink(ficlStack *stack)
{
	stack->top = stack->frame - 1;
	stack->frame = ficlStackPopPointer(stack);
}
#endif /* FICL_WANT_LOCALS */

/*
 *                  s t a c k P i c k
 */
void
ficlStackPick(ficlStack *stack, int n)
{
	ficlStackPush(stack, ficlStackFetch(stack, n));
}

/*
 * s t a c k P o p
 */
ficlCell
ficlStackPop(ficlStack *stack)
{
	return (*stack->top--);
}

void *
ficlStackPopPointer(ficlStack *stack)
{
	return ((*stack->top--).p);
}

ficlUnsigned
ficlStackPopUnsigned(ficlStack *stack)
{
	return ((*stack->top--).u);
}

ficlInteger
ficlStackPopInteger(ficlStack *stack)
{
	return ((*stack->top--).i);
}

ficl2Integer
ficlStackPop2Integer(ficlStack *stack)
{
	ficl2Integer ret;
	ficlInteger high = ficlStackPopInteger(stack);
	ficlInteger low = ficlStackPopInteger(stack);
	FICL_2INTEGER_SET(high, low, ret);
	return (ret);
}

ficl2Unsigned
ficlStackPop2Unsigned(ficlStack *stack)
{
	ficl2Unsigned ret;
	ficlUnsigned high = ficlStackPopUnsigned(stack);
	ficlUnsigned low = ficlStackPopUnsigned(stack);
	FICL_2UNSIGNED_SET(high, low, ret);
	return (ret);
}

#if (FICL_WANT_FLOAT)
ficlFloat
ficlStackPopFloat(ficlStack *stack)
{
	return ((*stack->top--).f);
}
#endif

/*
 * s t a c k P u s h
 */
void
ficlStackPush(ficlStack *stack, ficlCell c)
{
	*++stack->top = c;
}

void
ficlStackPushPointer(ficlStack *stack, void *ptr)
{
	ficlCell c;

	c.p = ptr;
	*++stack->top = c;
}

void
ficlStackPushInteger(ficlStack *stack, ficlInteger i)
{
	ficlCell c;

	c.i = i;
	*++stack->top = c;
}

void
ficlStackPushUnsigned(ficlStack *stack, ficlUnsigned u)
{
	ficlCell c;

	c.u = u;
	*++stack->top = c;
}

void
ficlStackPush2Unsigned(ficlStack *stack, ficl2Unsigned du)
{
	ficlStackPushUnsigned(stack, FICL_2UNSIGNED_GET_LOW(du));
	ficlStackPushUnsigned(stack, FICL_2UNSIGNED_GET_HIGH(du));
}

void
ficlStackPush2Integer(ficlStack *stack, ficl2Integer di)
{
	ficl2Unsigned du;
	FICL_2UNSIGNED_SET(FICL_2UNSIGNED_GET_HIGH(di),
	    FICL_2UNSIGNED_GET_LOW(di), du);
	ficlStackPush2Unsigned(stack, du);
}

#if (FICL_WANT_FLOAT)
void
ficlStackPushFloat(ficlStack *stack, ficlFloat f)
{
	ficlCell c;

	c.f = f;
	*++stack->top = c;
}
#endif

/*
 * s t a c k R e s e t
 */
void
ficlStackReset(ficlStack *stack)
{
	stack->top = stack->base - 1;
}

/*
 * s t a c k R o l l
 * Roll nth stack entry to the top (counting from zero), if n is
 * >= 0. Drop other entries as needed to fill the hole.
 * If n < 0, roll top-of-stack to nth entry, pushing others
 * upward as needed to fill the hole.
 */
void
ficlStackRoll(ficlStack *stack, int n)
{
	ficlCell c;
	ficlCell *cell;

	if (n == 0)
		return;
	else if (n > 0) {
		cell = stack->top - n;
		c = *cell;

		for (; n > 0; --n, cell++) {
			*cell = cell[1];
		}

		*cell = c;
	} else {
		cell = stack->top;
		c = *cell;

		for (; n < 0; ++n, cell--) {
			*cell = cell[-1];
		}

		*cell = c;
	}
}

/*
 * s t a c k S e t T o p
 */
void
ficlStackSetTop(ficlStack *stack, ficlCell c)
{
	FICL_STACK_CHECK(stack, 1, 1);
	stack->top[0] = c;
}

void
ficlStackWalk(ficlStack *stack, ficlStackWalkFunction callback,
    void *context, ficlInteger bottomToTop)
{
	int i;
	int depth;
	ficlCell *cell;
	FICL_STACK_CHECK(stack, 0, 0);

	depth = ficlStackDepth(stack);
	cell = bottomToTop ? stack->base : stack->top;
	for (i = 0; i < depth; i++) {
		if (callback(context, cell) == FICL_FALSE)
			break;
		cell += bottomToTop ? 1 : -1;
	}
}
