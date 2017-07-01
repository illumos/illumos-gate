/*
 * v m . c
 * Forth Inspired Command Language - virtual machine methods
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 19 July 1997
 * $Id: vm.c,v 1.17 2010/09/13 18:43:04 asau Exp $
 */
/*
 * This file implements the virtual machine of Ficl. Each virtual
 * machine retains the state of an interpreter. A virtual machine
 * owns a pair of stacks for parameters and return addresses, as
 * well as a pile of state variables and the two dedicated registers
 * of the interpreter.
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

#if FICL_ROBUST >= 2
#define	FICL_VM_CHECK(vm)	\
	FICL_VM_ASSERT(vm, (*(vm->ip - 1)) == vm->runningWord)
#else
#define	FICL_VM_CHECK(vm)
#endif

/*
 * v m B r a n c h R e l a t i v e
 */
void
ficlVmBranchRelative(ficlVm *vm, int offset)
{
	vm->ip += offset;
}

/*
 * v m C r e a t e
 * Creates a virtual machine either from scratch (if vm is NULL on entry)
 * or by resizing and reinitializing an existing VM to the specified stack
 * sizes.
 */
ficlVm *
ficlVmCreate(ficlVm *vm, unsigned nPStack, unsigned nRStack)
{
	if (vm == NULL) {
		vm = (ficlVm *)ficlMalloc(sizeof (ficlVm));
		FICL_ASSERT(NULL, vm);
		memset(vm, 0, sizeof (ficlVm));
	}

	if (vm->dataStack)
		ficlStackDestroy(vm->dataStack);
	vm->dataStack = ficlStackCreate(vm, "data", nPStack);

	if (vm->returnStack)
		ficlStackDestroy(vm->returnStack);
	vm->returnStack = ficlStackCreate(vm, "return", nRStack);

#if FICL_WANT_FLOAT
	if (vm->floatStack)
		ficlStackDestroy(vm->floatStack);
	vm->floatStack = ficlStackCreate(vm, "float", nPStack);
#endif

	ficlVmReset(vm);
	return (vm);
}

/*
 * v m D e l e t e
 * Free all memory allocated to the specified VM and its subordinate
 * structures.
 */
void
ficlVmDestroy(ficlVm *vm)
{
	if (vm) {
		ficlFree(vm->dataStack);
		ficlFree(vm->returnStack);
#if FICL_WANT_FLOAT
		ficlFree(vm->floatStack);
#endif
		ficlFree(vm);
	}
}

/*
 * v m E x e c u t e
 * Sets up the specified word to be run by the inner interpreter.
 * Executes the word's code part immediately, but in the case of
 * colon definition, the definition itself needs the inner interpreter
 * to complete. This does not happen until control reaches ficlExec
 */
void
ficlVmExecuteWord(ficlVm *vm, ficlWord *pWord)
{
	ficlVmInnerLoop(vm, pWord);
}

static void
ficlVmOptimizeJumpToJump(ficlVm *vm, ficlIp ip)
{
	ficlIp destination;
	switch ((ficlInstruction)(*ip)) {
	case ficlInstructionBranchParenWithCheck:
		*ip = (ficlWord *)ficlInstructionBranchParen;
		goto RUNTIME_FIXUP;

	case ficlInstructionBranch0ParenWithCheck:
		*ip = (ficlWord *)ficlInstructionBranch0Paren;
RUNTIME_FIXUP:
		ip++;
		destination = ip + *(ficlInteger *)ip;
		switch ((ficlInstruction)*destination) {
		case ficlInstructionBranchParenWithCheck:
			/* preoptimize where we're jumping to */
			ficlVmOptimizeJumpToJump(vm, destination);
			/* FALLTHROUGH */
		case ficlInstructionBranchParen:
			destination++;
			destination += *(ficlInteger *)destination;
			*ip = (ficlWord *)(destination - ip);
		break;
		}
	}
}

/*
 * v m I n n e r L o o p
 * the mysterious inner interpreter...
 * This loop is the address interpreter that makes colon definitions
 * work. Upon entry, it assumes that the IP points to an entry in
 * a definition (the body of a colon word). It runs one word at a time
 * until something does vmThrow. The catcher for this is expected to exist
 * in the calling code.
 * vmThrow gets you out of this loop with a longjmp()
 */

#if FICL_ROBUST <= 1
	/* turn off stack checking for primitives */
#define	_CHECK_STACK(stack, top, pop, push)
#else

#define	_CHECK_STACK(stack, top, pop, push)	\
	ficlStackCheckNospill(stack, top, pop, push)

FICL_PLATFORM_INLINE void
ficlStackCheckNospill(ficlStack *stack, ficlCell *top, int popCells,
    int pushCells)
{
	/*
	 * Why save and restore stack->top?
	 * So the simple act of stack checking doesn't force a "register" spill,
	 * which might mask bugs (places where we needed to spill but didn't).
	 * --lch
	 */
	ficlCell *oldTop = stack->top;
	stack->top = top;
	ficlStackCheck(stack, popCells, pushCells);
	stack->top = oldTop;
}

#endif /* FICL_ROBUST <= 1 */

#define	CHECK_STACK(pop, push)		\
	_CHECK_STACK(vm->dataStack, dataTop, pop, push)
#define	CHECK_FLOAT_STACK(pop, push)	\
	_CHECK_STACK(vm->floatStack, floatTop, pop, push)
#define	CHECK_RETURN_STACK(pop, push)	\
	_CHECK_STACK(vm->returnStack, returnTop, pop, push)

#if FICL_WANT_FLOAT
#define	FLOAT_LOCAL_VARIABLE_SPILL	\
	vm->floatStack->top = floatTop;
#define	FLOAT_LOCAL_VARIABLE_REFILL	\
	floatTop = vm->floatStack->top;
#else
#define	FLOAT_LOCAL_VARIABLE_SPILL
#define	FLOAT_LOCAL_VARIABLE_REFILL
#endif  /* FICL_WANT_FLOAT */

#if FICL_WANT_LOCALS
#define	LOCALS_LOCAL_VARIABLE_SPILL	\
	vm->returnStack->frame = frame;
#define	LOCALS_LOCAL_VARIABLE_REFILL \
	frame = vm->returnStack->frame;
#else
#define	LOCALS_LOCAL_VARIABLE_SPILL
#define	LOCALS_LOCAL_VARIABLE_REFILL
#endif  /* FICL_WANT_FLOAT */

#define	LOCAL_VARIABLE_SPILL	\
		vm->ip = (ficlIp)ip;	\
		vm->dataStack->top = dataTop;	\
		vm->returnStack->top = returnTop;	\
		FLOAT_LOCAL_VARIABLE_SPILL \
		LOCALS_LOCAL_VARIABLE_SPILL

#define	LOCAL_VARIABLE_REFILL	\
		ip = (ficlInstruction *)vm->ip; \
		dataTop = vm->dataStack->top;	\
		returnTop = vm->returnStack->top;	\
		FLOAT_LOCAL_VARIABLE_REFILL	\
		LOCALS_LOCAL_VARIABLE_REFILL

void
ficlVmInnerLoop(ficlVm *vm, ficlWord *fw)
{
	register ficlInstruction *ip;
	register ficlCell *dataTop;
	register ficlCell *returnTop;
#if FICL_WANT_FLOAT
	register ficlCell *floatTop;
	ficlFloat f;
#endif  /* FICL_WANT_FLOAT */
#if FICL_WANT_LOCALS
	register ficlCell *frame;
#endif  /* FICL_WANT_LOCALS */
	jmp_buf *oldExceptionHandler;
	jmp_buf exceptionHandler;
	int except;
	int once;
	int count;
	ficlInstruction instruction;
	ficlInteger i;
	ficlUnsigned u;
	ficlCell c;
	ficlCountedString *s;
	ficlCell *cell;
	char *cp;

	once = (fw != NULL);
	if (once)
		count = 1;

	oldExceptionHandler = vm->exceptionHandler;
	/* This has to come before the setjmp! */
	vm->exceptionHandler = &exceptionHandler;
	except = setjmp(exceptionHandler);

	LOCAL_VARIABLE_REFILL;

	if (except) {
		LOCAL_VARIABLE_SPILL;
		vm->exceptionHandler = oldExceptionHandler;
		ficlVmThrow(vm, except);
	}

	for (;;) {
		if (once) {
			if (!count--)
				break;
			instruction = (ficlInstruction)((void *)fw);
		} else {
			instruction = *ip++;
			fw = (ficlWord *)instruction;
		}

AGAIN:
		switch (instruction) {
		case ficlInstructionInvalid:
			ficlVmThrowError(vm,
			    "Error: NULL instruction executed!");
		return;

		case ficlInstruction1:
		case ficlInstruction2:
		case ficlInstruction3:
		case ficlInstruction4:
		case ficlInstruction5:
		case ficlInstruction6:
		case ficlInstruction7:
		case ficlInstruction8:
		case ficlInstruction9:
		case ficlInstruction10:
		case ficlInstruction11:
		case ficlInstruction12:
		case ficlInstruction13:
		case ficlInstruction14:
		case ficlInstruction15:
		case ficlInstruction16:
			CHECK_STACK(0, 1);
			(++dataTop)->i = instruction;
		continue;

		case ficlInstruction0:
		case ficlInstructionNeg1:
		case ficlInstructionNeg2:
		case ficlInstructionNeg3:
		case ficlInstructionNeg4:
		case ficlInstructionNeg5:
		case ficlInstructionNeg6:
		case ficlInstructionNeg7:
		case ficlInstructionNeg8:
		case ficlInstructionNeg9:
		case ficlInstructionNeg10:
		case ficlInstructionNeg11:
		case ficlInstructionNeg12:
		case ficlInstructionNeg13:
		case ficlInstructionNeg14:
		case ficlInstructionNeg15:
		case ficlInstructionNeg16:
			CHECK_STACK(0, 1);
			(++dataTop)->i = ficlInstruction0 - instruction;
		continue;

		/*
		 * stringlit: Fetch the count from the dictionary, then push
		 * the address and count on the stack. Finally, update ip to
		 * point to the first aligned address after the string text.
		 */
		case ficlInstructionStringLiteralParen: {
			ficlUnsigned8 length;
			CHECK_STACK(0, 2);

			s = (ficlCountedString *)(ip);
			length = s->length;
			cp = s->text;
			(++dataTop)->p = cp;
			(++dataTop)->i = length;

			cp += length + 1;
			cp = ficlAlignPointer(cp);
			ip = (void *)cp;
		continue;
		}

		case ficlInstructionCStringLiteralParen:
			CHECK_STACK(0, 1);

			s = (ficlCountedString *)(ip);
			cp = s->text + s->length + 1;
			cp = ficlAlignPointer(cp);
			ip = (void *)cp;
			(++dataTop)->p = s;
		continue;

#if FICL_WANT_OPTIMIZE == FICL_OPTIMIZE_FOR_SIZE
#if FICL_WANT_FLOAT
FLOAT_PUSH_CELL_POINTER_DOUBLE_MINIPROC:
			*++floatTop = cell[1];
			/* intentional fall-through */
FLOAT_PUSH_CELL_POINTER_MINIPROC:
			*++floatTop = cell[0];
		continue;

FLOAT_POP_CELL_POINTER_MINIPROC:
			cell[0] = *floatTop--;
		continue;

FLOAT_POP_CELL_POINTER_DOUBLE_MINIPROC:
			cell[0] = *floatTop--;
			cell[1] = *floatTop--;
		continue;

#define	FLOAT_PUSH_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); goto FLOAT_PUSH_CELL_POINTER_DOUBLE_MINIPROC
#define	FLOAT_PUSH_CELL_POINTER(cp)		\
	cell = (cp); goto FLOAT_PUSH_CELL_POINTER_MINIPROC
#define	FLOAT_POP_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); goto FLOAT_POP_CELL_POINTER_DOUBLE_MINIPROC
#define	FLOAT_POP_CELL_POINTER(cp)		\
	cell = (cp); goto FLOAT_POP_CELL_POINTER_MINIPROC
#endif /* FICL_WANT_FLOAT */

		/*
		 * Think of these as little mini-procedures.
		 * --lch
		 */
PUSH_CELL_POINTER_DOUBLE_MINIPROC:
			*++dataTop = cell[1];
			/* intentional fall-through */
PUSH_CELL_POINTER_MINIPROC:
			*++dataTop = cell[0];
		continue;

POP_CELL_POINTER_MINIPROC:
			cell[0] = *dataTop--;
		continue;
POP_CELL_POINTER_DOUBLE_MINIPROC:
			cell[0] = *dataTop--;
			cell[1] = *dataTop--;
		continue;

#define	PUSH_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); goto PUSH_CELL_POINTER_DOUBLE_MINIPROC
#define	PUSH_CELL_POINTER(cp)		\
	cell = (cp); goto PUSH_CELL_POINTER_MINIPROC
#define	POP_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); goto POP_CELL_POINTER_DOUBLE_MINIPROC
#define	POP_CELL_POINTER(cp)		\
	cell = (cp); goto POP_CELL_POINTER_MINIPROC

BRANCH_MINIPROC:
			ip += *(ficlInteger *)ip;
		continue;

#define	BRANCH()	goto BRANCH_MINIPROC

EXIT_FUNCTION_MINIPROC:
			ip = (ficlInstruction *)((returnTop--)->p);
				continue;

#define	EXIT_FUNCTION	goto EXIT_FUNCTION_MINIPROC

#else /* FICL_WANT_SIZE */

#if FICL_WANT_FLOAT
#define	FLOAT_PUSH_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); *++floatTop = cell[1]; *++floatTop = *cell; continue
#define	FLOAT_PUSH_CELL_POINTER(cp)		\
	cell = (cp); *++floatTop = *cell; continue
#define	FLOAT_POP_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); *cell = *floatTop--; cell[1] = *floatTop--; continue
#define	FLOAT_POP_CELL_POINTER(cp)		\
	cell = (cp); *cell = *floatTop--; continue
#endif /* FICL_WANT_FLOAT */

#define	PUSH_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); *++dataTop = cell[1]; *++dataTop = *cell; continue
#define	PUSH_CELL_POINTER(cp)		\
	cell = (cp); *++dataTop = *cell; continue
#define	POP_CELL_POINTER_DOUBLE(cp)	\
	cell = (cp); *cell = *dataTop--; cell[1] = *dataTop--; continue
#define	POP_CELL_POINTER(cp)		\
	cell = (cp); *cell = *dataTop--; continue

#define	BRANCH()	ip += *(ficlInteger *)ip; continue
#define	EXIT_FUNCTION()	ip = (ficlInstruction *)((returnTop--)->p); continue

#endif /* FICL_WANT_SIZE */


		/*
		 * This is the runtime for (literal). It assumes that it is
		 * part of a colon definition, and that the next ficlCell
		 * contains a value to be pushed on the parameter stack at
		 * runtime. This code is compiled by "literal".
		 */

		case ficlInstructionLiteralParen:
			CHECK_STACK(0, 1);
			(++dataTop)->i = *ip++;
		continue;

		case ficlInstruction2LiteralParen:
			CHECK_STACK(0, 2);
			(++dataTop)->i = ip[1];
			(++dataTop)->i = ip[0];
			ip += 2;
		continue;

#if FICL_WANT_LOCALS
		/*
		 * Link a frame on the return stack, reserving nCells of space
		 * for locals - the value of nCells is the next ficlCell in
		 * the instruction stream.
		 * 1) Push frame onto returnTop
		 * 2) frame = returnTop
		 * 3) returnTop += nCells
		 */
		case ficlInstructionLinkParen: {
			ficlInteger nCells = *ip++;
			(++returnTop)->p = frame;
			frame = returnTop + 1;
			returnTop += nCells;
		continue;
		}

		/*
		 * Unink a stack frame previously created by stackLink
		 * 1) dataTop = frame
		 * 2) frame = pop()
		 */
		case ficlInstructionUnlinkParen:
			returnTop = frame - 1;
			frame = (returnTop--)->p;
		continue;

		/*
		 * Immediate - cfa of a local while compiling - when executed,
		 * compiles code to fetch the value of a local given the
		 * local's index in the word's pfa
		 */
#if FICL_WANT_FLOAT
		case ficlInstructionGetF2LocalParen:
			FLOAT_PUSH_CELL_POINTER_DOUBLE(frame + *ip++);

		case ficlInstructionGetFLocalParen:
			FLOAT_PUSH_CELL_POINTER(frame + *ip++);

		case ficlInstructionToF2LocalParen:
			FLOAT_POP_CELL_POINTER_DOUBLE(frame + *ip++);

		case ficlInstructionToFLocalParen:
			FLOAT_POP_CELL_POINTER(frame + *ip++);
#endif /* FICL_WANT_FLOAT */

		case ficlInstructionGet2LocalParen:
			PUSH_CELL_POINTER_DOUBLE(frame + *ip++);

		case ficlInstructionGetLocalParen:
			PUSH_CELL_POINTER(frame + *ip++);

		/*
		 * Immediate - cfa of a local while compiling - when executed,
		 * compiles code to store the value of a local given the
		 * local's index in the word's pfa
		 */

		case ficlInstructionTo2LocalParen:
			POP_CELL_POINTER_DOUBLE(frame + *ip++);

		case ficlInstructionToLocalParen:
			POP_CELL_POINTER(frame + *ip++);

		/*
		 * Silly little minor optimizations.
		 * --lch
		 */
		case ficlInstructionGetLocal0:
			PUSH_CELL_POINTER(frame);

		case ficlInstructionGetLocal1:
			PUSH_CELL_POINTER(frame + 1);

		case ficlInstructionGet2Local0:
			PUSH_CELL_POINTER_DOUBLE(frame);

		case ficlInstructionToLocal0:
			POP_CELL_POINTER(frame);

		case ficlInstructionToLocal1:
			POP_CELL_POINTER(frame + 1);

		case ficlInstructionTo2Local0:
			POP_CELL_POINTER_DOUBLE(frame);

#endif /* FICL_WANT_LOCALS */

		case ficlInstructionPlus:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i += i;
		continue;

		case ficlInstructionMinus:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i -= i;
		continue;

		case ficlInstruction1Plus:
			CHECK_STACK(1, 1);
			dataTop->i++;
		continue;

		case ficlInstruction1Minus:
			CHECK_STACK(1, 1);
			dataTop->i--;
		continue;

		case ficlInstruction2Plus:
			CHECK_STACK(1, 1);
			dataTop->i += 2;
		continue;

		case ficlInstruction2Minus:
			CHECK_STACK(1, 1);
			dataTop->i -= 2;
		continue;

		case ficlInstructionDup: {
			ficlInteger i = dataTop->i;
			CHECK_STACK(0, 1);
			(++dataTop)->i = i;
			continue;
		}

		case ficlInstructionQuestionDup:
			CHECK_STACK(1, 2);

			if (dataTop->i != 0) {
				dataTop[1] = dataTop[0];
				dataTop++;
			}

		continue;

		case ficlInstructionSwap: {
			ficlCell swap;
			CHECK_STACK(2, 2);
			swap = dataTop[0];
			dataTop[0] = dataTop[-1];
			dataTop[-1] = swap;
		}
		continue;

		case ficlInstructionDrop:
			CHECK_STACK(1, 0);
			dataTop--;
		continue;

		case ficlInstruction2Drop:
			CHECK_STACK(2, 0);
			dataTop -= 2;
		continue;

		case ficlInstruction2Dup:
			CHECK_STACK(2, 4);
			dataTop[1] = dataTop[-1];
			dataTop[2] = *dataTop;
			dataTop += 2;
		continue;

		case ficlInstructionOver:
			CHECK_STACK(2, 3);
			dataTop[1] = dataTop[-1];
			dataTop++;
		continue;

		case ficlInstruction2Over:
			CHECK_STACK(4, 6);
			dataTop[1] = dataTop[-3];
			dataTop[2] = dataTop[-2];
			dataTop += 2;
		continue;

		case ficlInstructionPick:
			CHECK_STACK(1, 0);
			i = dataTop->i;
			if (i < 0)
				continue;
			CHECK_STACK(i + 2, i + 3);
			*dataTop = dataTop[-i - 1];
		continue;

		/*
		 * Do stack rot.
		 * rot ( 1 2 3  -- 2 3 1 )
		 */
		case ficlInstructionRot:
			i = 2;
		goto ROLL;

		/*
		 * Do stack roll.
		 * roll ( n -- )
		 */
		case ficlInstructionRoll:
			CHECK_STACK(1, 0);
			i = (dataTop--)->i;

			if (i < 1)
				continue;

ROLL:
			CHECK_STACK(i+1, i+2);
			c = dataTop[-i];
			memmove(dataTop - i, dataTop - (i - 1),
			    i * sizeof (ficlCell));
			*dataTop = c;
		continue;

		/*
		 * Do stack -rot.
		 * -rot ( 1 2 3  -- 3 1 2 )
		 */
		case ficlInstructionMinusRot:
			i = 2;
		goto MINUSROLL;

		/*
		 * Do stack -roll.
		 * -roll ( n -- )
		 */
		case ficlInstructionMinusRoll:
			CHECK_STACK(1, 0);
			i = (dataTop--)->i;

			if (i < 1)
				continue;

MINUSROLL:
			CHECK_STACK(i+1, i+2);
			c = *dataTop;
			memmove(dataTop - (i - 1), dataTop - i,
			    i * sizeof (ficlCell));
			dataTop[-i] = c;

		continue;

		/*
		 * Do stack 2swap
		 * 2swap ( 1 2 3 4  -- 3 4 1 2 )
		 */
		case ficlInstruction2Swap: {
			ficlCell c2;
			CHECK_STACK(4, 4);

			c = *dataTop;
			c2 = dataTop[-1];

			*dataTop = dataTop[-2];
			dataTop[-1] = dataTop[-3];

			dataTop[-2] = c;
			dataTop[-3] = c2;
		continue;
		}

		case ficlInstructionPlusStore: {
			ficlCell *cell;
			CHECK_STACK(2, 0);
			cell = (ficlCell *)(dataTop--)->p;
			cell->i += (dataTop--)->i;
		continue;
		}

		case ficlInstructionQuadFetch: {
			ficlUnsigned32 *integer32;
			CHECK_STACK(1, 1);
			integer32 = (ficlUnsigned32 *)dataTop->i;
			dataTop->u = (ficlUnsigned)*integer32;
		continue;
		}

		case ficlInstructionQuadStore: {
			ficlUnsigned32 *integer32;
			CHECK_STACK(2, 0);
			integer32 = (ficlUnsigned32 *)(dataTop--)->p;
			*integer32 = (ficlUnsigned32)((dataTop--)->u);
		continue;
		}

		case ficlInstructionWFetch: {
			ficlUnsigned16 *integer16;
			CHECK_STACK(1, 1);
			integer16 = (ficlUnsigned16 *)dataTop->p;
			dataTop->u = ((ficlUnsigned)*integer16);
		continue;
		}

		case ficlInstructionWStore: {
			ficlUnsigned16 *integer16;
			CHECK_STACK(2, 0);
			integer16 = (ficlUnsigned16 *)(dataTop--)->p;
			*integer16 = (ficlUnsigned16)((dataTop--)->u);
		continue;
		}

		case ficlInstructionCFetch: {
			ficlUnsigned8 *integer8;
			CHECK_STACK(1, 1);
			integer8 = (ficlUnsigned8 *)dataTop->p;
			dataTop->u = ((ficlUnsigned)*integer8);
		continue;
		}

		case ficlInstructionCStore: {
			ficlUnsigned8 *integer8;
			CHECK_STACK(2, 0);
			integer8 = (ficlUnsigned8 *)(dataTop--)->p;
			*integer8 = (ficlUnsigned8)((dataTop--)->u);
		continue;
		}


		/*
		 * l o g i c   a n d   c o m p a r i s o n s
		 */

		case ficlInstruction0Equals:
			CHECK_STACK(1, 1);
			dataTop->i = FICL_BOOL(dataTop->i == 0);
		continue;

		case ficlInstruction0Less:
			CHECK_STACK(1, 1);
			dataTop->i = FICL_BOOL(dataTop->i < 0);
		continue;

		case ficlInstruction0Greater:
			CHECK_STACK(1, 1);
			dataTop->i = FICL_BOOL(dataTop->i > 0);
		continue;

		case ficlInstructionEquals:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i = FICL_BOOL(dataTop->i == i);
		continue;

		case ficlInstructionLess:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i = FICL_BOOL(dataTop->i < i);
		continue;

		case ficlInstructionULess:
			CHECK_STACK(2, 1);
			u = (dataTop--)->u;
			dataTop->i = FICL_BOOL(dataTop->u < u);
		continue;

		case ficlInstructionAnd:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i = dataTop->i & i;
		continue;

		case ficlInstructionOr:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i = dataTop->i | i;
		continue;

		case ficlInstructionXor:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i = dataTop->i ^ i;
		continue;

		case ficlInstructionInvert:
			CHECK_STACK(1, 1);
			dataTop->i = ~dataTop->i;
		continue;

		/*
		 * r e t u r n   s t a c k
		 */
		case ficlInstructionToRStack:
			CHECK_STACK(1, 0);
			CHECK_RETURN_STACK(0, 1);
			*++returnTop = *dataTop--;
		continue;

		case ficlInstructionFromRStack:
			CHECK_STACK(0, 1);
			CHECK_RETURN_STACK(1, 0);
			*++dataTop = *returnTop--;
		continue;

		case ficlInstructionFetchRStack:
			CHECK_STACK(0, 1);
			CHECK_RETURN_STACK(1, 1);
			*++dataTop = *returnTop;
		continue;

		case ficlInstruction2ToR:
			CHECK_STACK(2, 0);
			CHECK_RETURN_STACK(0, 2);
			*++returnTop = dataTop[-1];
			*++returnTop = dataTop[0];
			dataTop -= 2;
		continue;

		case ficlInstruction2RFrom:
			CHECK_STACK(0, 2);
			CHECK_RETURN_STACK(2, 0);
			*++dataTop = returnTop[-1];
			*++dataTop = returnTop[0];
			returnTop -= 2;
		continue;

		case ficlInstruction2RFetch:
			CHECK_STACK(0, 2);
			CHECK_RETURN_STACK(2, 2);
			*++dataTop = returnTop[-1];
			*++dataTop = returnTop[0];
		continue;

		/*
		 * f i l l
		 * CORE ( c-addr u char -- )
		 * If u is greater than zero, store char in each of u
		 * consecutive characters of memory beginning at c-addr.
		 */
		case ficlInstructionFill: {
			char c;
			char *memory;
			CHECK_STACK(3, 0);
			c = (char)(dataTop--)->i;
			u = (dataTop--)->u;
			memory = (char *)(dataTop--)->p;

			/*
			 * memset() is faster than the previous hand-rolled
			 * solution.  --lch
			 */
			memset(memory, c, u);
		continue;
		}

		/*
		 * l s h i f t
		 * l-shift CORE ( x1 u -- x2 )
		 * Perform a logical left shift of u bit-places on x1,
		 * giving x2. Put zeroes into the least significant bits
		 * vacated by the shift. An ambiguous condition exists if
		 * u is greater than or equal to the number of bits in a
		 * ficlCell.
		 *
		 * r-shift CORE ( x1 u -- x2 )
		 * Perform a logical right shift of u bit-places on x1,
		 * giving x2. Put zeroes into the most significant bits
		 * vacated by the shift. An ambiguous condition exists
		 * if u is greater than or equal to the number of bits
		 * in a ficlCell.
		 */
		case ficlInstructionLShift: {
			ficlUnsigned nBits;
			ficlUnsigned x1;
			CHECK_STACK(2, 1);

			nBits = (dataTop--)->u;
			x1 = dataTop->u;
			dataTop->u = x1 << nBits;
		continue;
		}

		case ficlInstructionRShift: {
			ficlUnsigned nBits;
			ficlUnsigned x1;
			CHECK_STACK(2, 1);

			nBits = (dataTop--)->u;
			x1 = dataTop->u;
			dataTop->u = x1 >> nBits;
			continue;
		}

		/*
		 * m a x   &   m i n
		 */
		case ficlInstructionMax: {
			ficlInteger n2;
			ficlInteger n1;
			CHECK_STACK(2, 1);

			n2 = (dataTop--)->i;
			n1 = dataTop->i;

			dataTop->i = ((n1 > n2) ? n1 : n2);
		continue;
		}

		case ficlInstructionMin: {
			ficlInteger n2;
			ficlInteger n1;
			CHECK_STACK(2, 1);

			n2 = (dataTop--)->i;
				n1 = dataTop->i;

			dataTop->i = ((n1 < n2) ? n1 : n2);
			continue;
		}

		/*
		 * m o v e
		 * CORE ( addr1 addr2 u -- )
		 * If u is greater than zero, copy the contents of u
		 * consecutive address units at addr1 to the u consecutive
		 * address units at addr2. After MOVE completes, the u
		 * consecutive address units at addr2 contain exactly
		 * what the u consecutive address units at addr1 contained
		 * before the move.
		 * NOTE! This implementation assumes that a char is the same
		 * size as an address unit.
		 */
		case ficlInstructionMove: {
			ficlUnsigned u;
			char *addr2;
			char *addr1;
			CHECK_STACK(3, 0);

			u = (dataTop--)->u;
			addr2 = (dataTop--)->p;
			addr1 = (dataTop--)->p;

			if (u == 0)
				continue;
			/*
			 * Do the copy carefully, so as to be
			 * correct even if the two ranges overlap
			 */
			/* Which ANSI C's memmove() does for you! Yay!  --lch */
			memmove(addr2, addr1, u);
		continue;
		}

		/*
		 * s t o d
		 * s-to-d CORE ( n -- d )
		 * Convert the number n to the double-ficlCell number d with
		 * the same numerical value.
		 */
		case ficlInstructionSToD: {
			ficlInteger s;
			CHECK_STACK(1, 2);

			s = dataTop->i;

			/* sign extend to 64 bits.. */
			(++dataTop)->i = (s < 0) ? -1 : 0;
		continue;
		}

		/*
		 * c o m p a r e
		 * STRING ( c-addr1 u1 c-addr2 u2 -- n )
		 * Compare the string specified by c-addr1 u1 to the string
		 * specified by c-addr2 u2. The strings are compared, beginning
		 * at the given addresses, character by character, up to the
		 * length of the shorter string or until a difference is found.
		 * If the two strings are identical, n is zero. If the two
		 * strings are identical up to the length of the shorter string,
		 * n is minus-one (-1) if u1 is less than u2 and one (1)
		 * otherwise. If the two strings are not identical up to the
		 * length of the shorter string, n is minus-one (-1) if the
		 * first non-matching character in the string specified by
		 * c-addr1 u1 has a lesser numeric value than the corresponding
		 * character in the string specified by c-addr2 u2 and
		 * one (1) otherwise.
		 */
		case ficlInstructionCompare:
			i = FICL_FALSE;
		goto COMPARE;


		case ficlInstructionCompareInsensitive:
			i = FICL_TRUE;
		goto COMPARE;

COMPARE:
		{
			char *cp1, *cp2;
			ficlUnsigned u1, u2, uMin;
			int n = 0;

			CHECK_STACK(4, 1);
			u2  = (dataTop--)->u;
			cp2 = (char *)(dataTop--)->p;
			u1  = (dataTop--)->u;
			cp1 = (char *)(dataTop--)->p;

			uMin = (u1 < u2)? u1 : u2;
			for (; (uMin > 0) && (n == 0); uMin--) {
				int c1 = (unsigned char)*cp1++;
				int c2 = (unsigned char)*cp2++;

				if (i) {
					c1 = tolower(c1);
					c2 = tolower(c2);
				}
				n = (c1 - c2);
			}

			if (n == 0)
				n = (int)(u1 - u2);

			if (n < 0)
				n = -1;
			else if (n > 0)
				n = 1;

			(++dataTop)->i = n;
		continue;
		}

		/*
		 * r a n d o m
		 * Ficl-specific
		 */
		case ficlInstructionRandom:
			(++dataTop)->i = random();
		continue;

		/*
		 * s e e d - r a n d o m
		 * Ficl-specific
		 */
		case ficlInstructionSeedRandom:
			srandom((dataTop--)->i);
		continue;

		case ficlInstructionGreaterThan: {
			ficlInteger x, y;
			CHECK_STACK(2, 1);
			y = (dataTop--)->i;
			x = dataTop->i;
			dataTop->i = FICL_BOOL(x > y);
		continue;

		case ficlInstructionUGreaterThan:
			CHECK_STACK(2, 1);
			u = (dataTop--)->u;
			dataTop->i = FICL_BOOL(dataTop->u > u);
		continue;

		}

		/*
		 * This function simply pops the previous instruction
		 * pointer and returns to the "next" loop. Used for exiting
		 * from within a definition. Note that exitParen is identical
		 * to semiParen - they are in two different functions so that
		 * "see" can correctly identify the end of a colon definition,
		 * even if it uses "exit".
		 */
		case ficlInstructionExitParen:
		case ficlInstructionSemiParen:
			EXIT_FUNCTION();

		/*
		 * The first time we run "(branch)", perform a "peephole
		 * optimization" to see if we're jumping to another
		 * unconditional jump.  If so, just jump directly there.
		 */
		case ficlInstructionBranchParenWithCheck:
			LOCAL_VARIABLE_SPILL;
			ficlVmOptimizeJumpToJump(vm, vm->ip - 1);
			LOCAL_VARIABLE_REFILL;
		goto BRANCH_PAREN;

		/*
		 * Same deal with branch0.
		 */
		case ficlInstructionBranch0ParenWithCheck:
			LOCAL_VARIABLE_SPILL;
			ficlVmOptimizeJumpToJump(vm, vm->ip - 1);
			LOCAL_VARIABLE_REFILL;
			/* intentional fall-through */

		/*
		 * Runtime code for "(branch0)"; pop a flag from the stack,
		 * branch if 0. fall through otherwise.
		 * The heart of "if" and "until".
		 */
		case ficlInstructionBranch0Paren:
			CHECK_STACK(1, 0);

			if ((dataTop--)->i) {
				/*
				 * don't branch, but skip over branch
				 * relative address
				 */
				ip += 1;
				continue;
			}
			/* otherwise, take branch (to else/endif/begin) */
			/* intentional fall-through! */

		/*
		 * Runtime for "(branch)" -- expects a literal offset in the
		 * next compilation address, and branches to that location.
		 */
		case ficlInstructionBranchParen:
BRANCH_PAREN:
			BRANCH();

		case ficlInstructionOfParen: {
			ficlUnsigned a, b;

			CHECK_STACK(2, 1);

			a = (dataTop--)->u;
			b = dataTop->u;

			if (a == b) {
				/* fall through */
				ip++;
				/* remove CASE argument */
				dataTop--;
			} else {
				/* take branch to next of or endcase */
				BRANCH();
			}

		continue;
		}

		case ficlInstructionDoParen: {
			ficlCell index, limit;

			CHECK_STACK(2, 0);

			index = *dataTop--;
			limit = *dataTop--;

			/* copy "leave" target addr to stack */
			(++returnTop)->i = *(ip++);
			*++returnTop = limit;
			*++returnTop = index;

		continue;
		}

		case ficlInstructionQDoParen: {
			ficlCell index, limit, leave;

			CHECK_STACK(2, 0);

			index = *dataTop--;
			limit = *dataTop--;

			leave.i = *ip;

			if (limit.u == index.u) {
				ip = leave.p;
			} else {
				ip++;
				*++returnTop = leave;
				*++returnTop = limit;
				*++returnTop = index;
			}

		continue;
		}

		case ficlInstructionLoopParen:
		case ficlInstructionPlusLoopParen: {
			ficlInteger index;
			ficlInteger limit;
			int direction = 0;

			index = returnTop->i;
			limit = returnTop[-1].i;

			if (instruction == ficlInstructionLoopParen)
				index++;
			else {
				ficlInteger increment;
				CHECK_STACK(1, 0);
				increment = (dataTop--)->i;
				index += increment;
				direction = (increment < 0);
			}

			if (direction ^ (index >= limit)) {
				/* nuke the loop indices & "leave" addr */
				returnTop -= 3;
				ip++;  /* fall through the loop */
			} else {	/* update index, branch to loop head */
				returnTop->i = index;
				BRANCH();
			}

		continue;
		}


		/*
		 * Runtime code to break out of a do..loop construct
		 * Drop the loop control variables; the branch address
		 * past "loop" is next on the return stack.
		 */
		case ficlInstructionLeave:
			/* almost unloop */
			returnTop -= 2;
			/* exit */
			EXIT_FUNCTION();

		case ficlInstructionUnloop:
			returnTop -= 3;
		continue;

		case ficlInstructionI:
			*++dataTop = *returnTop;
		continue;

		case ficlInstructionJ:
			*++dataTop = returnTop[-3];
		continue;

		case ficlInstructionK:
			*++dataTop = returnTop[-6];
		continue;

		case ficlInstructionDoesParen: {
			ficlDictionary *dictionary = ficlVmGetDictionary(vm);
			dictionary->smudge->code =
			    (ficlPrimitive)ficlInstructionDoDoes;
			dictionary->smudge->param[0].p = ip;
			ip = (ficlInstruction *)((returnTop--)->p);
		continue;
		}

		case ficlInstructionDoDoes: {
			ficlCell *cell;
			ficlIp tempIP;

			CHECK_STACK(0, 1);

			cell = fw->param;
			tempIP = (ficlIp)((*cell).p);
			(++dataTop)->p = (cell + 1);
			(++returnTop)->p = (void *)ip;
			ip = (ficlInstruction *)tempIP;
		continue;
		}

#if FICL_WANT_FLOAT
		case ficlInstructionF2Fetch:
			CHECK_FLOAT_STACK(0, 2);
			CHECK_STACK(1, 0);
			FLOAT_PUSH_CELL_POINTER_DOUBLE((dataTop--)->p);

		case ficlInstructionFFetch:
			CHECK_FLOAT_STACK(0, 1);
			CHECK_STACK(1, 0);
			FLOAT_PUSH_CELL_POINTER((dataTop--)->p);

		case ficlInstructionF2Store:
			CHECK_FLOAT_STACK(2, 0);
			CHECK_STACK(1, 0);
			FLOAT_POP_CELL_POINTER_DOUBLE((dataTop--)->p);

		case ficlInstructionFStore:
			CHECK_FLOAT_STACK(1, 0);
			CHECK_STACK(1, 0);
			FLOAT_POP_CELL_POINTER((dataTop--)->p);
#endif /* FICL_WANT_FLOAT */

		/*
		 * two-fetch CORE ( a-addr -- x1 x2 )
		 *
		 * Fetch the ficlCell pair x1 x2 stored at a-addr.
		 * x2 is stored at a-addr and x1 at the next consecutive
		 * ficlCell. It is equivalent to the sequence
		 * DUP ficlCell+ @ SWAP @ .
		 */
		case ficlInstruction2Fetch:
			CHECK_STACK(1, 2);
			PUSH_CELL_POINTER_DOUBLE((dataTop--)->p);

		/*
		 * fetch CORE ( a-addr -- x )
		 *
		 * x is the value stored at a-addr.
		 */
		case ficlInstructionFetch:
			CHECK_STACK(1, 1);
			PUSH_CELL_POINTER((dataTop--)->p);

		/*
		 * two-store    CORE ( x1 x2 a-addr -- )
		 * Store the ficlCell pair x1 x2 at a-addr, with x2 at a-addr
		 * and x1 at the next consecutive ficlCell. It is equivalent
		 * to the sequence SWAP OVER ! ficlCell+ !
		 */
		case ficlInstruction2Store:
			CHECK_STACK(3, 0);
			POP_CELL_POINTER_DOUBLE((dataTop--)->p);

		/*
		 * store	CORE ( x a-addr -- )
		 * Store x at a-addr.
		 */
		case ficlInstructionStore:
			CHECK_STACK(2, 0);
			POP_CELL_POINTER((dataTop--)->p);

		case ficlInstructionComma: {
			ficlDictionary *dictionary;
			CHECK_STACK(1, 0);

			dictionary = ficlVmGetDictionary(vm);
			ficlDictionaryAppendCell(dictionary, *dataTop--);
		continue;
		}

		case ficlInstructionCComma: {
			ficlDictionary *dictionary;
			char c;
			CHECK_STACK(1, 0);

			dictionary = ficlVmGetDictionary(vm);
			c = (char)(dataTop--)->i;
			ficlDictionaryAppendCharacter(dictionary, c);
		continue;
		}

		case ficlInstructionCells:
			CHECK_STACK(1, 1);
			dataTop->i *= sizeof (ficlCell);
		continue;

		case ficlInstructionCellPlus:
			CHECK_STACK(1, 1);
			dataTop->i += sizeof (ficlCell);
		continue;

		case ficlInstructionStar:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i *= i;
		continue;

		case ficlInstructionNegate:
			CHECK_STACK(1, 1);
			dataTop->i = - dataTop->i;
		continue;

		case ficlInstructionSlash:
			CHECK_STACK(2, 1);
			i = (dataTop--)->i;
			dataTop->i /= i;
		continue;

		/*
		 * slash-mod	CORE ( n1 n2 -- n3 n4 )
		 * Divide n1 by n2, giving the single-ficlCell remainder n3
		 * and the single-ficlCell quotient n4. An ambiguous condition
		 * exists if n2 is zero. If n1 and n2 differ in sign, the
		 * implementation-defined result returned will be the
		 * same as that returned by either the phrase
		 * >R S>D R> FM/MOD or the phrase >R S>D R> SM/REM.
		 * NOTE: Ficl complies with the second phrase
		 * (symmetric division)
		 */
		case ficlInstructionSlashMod: {
			ficl2Integer n1;
			ficlInteger n2;
			ficl2IntegerQR qr;

			CHECK_STACK(2, 2);
			n2    = dataTop[0].i;
			FICL_INTEGER_TO_2INTEGER(dataTop[-1].i, n1);

			qr = ficl2IntegerDivideSymmetric(n1, n2);
			dataTop[-1].i = qr.remainder;
			dataTop[0].i = FICL_2UNSIGNED_GET_LOW(qr.quotient);
		continue;
		}

		case ficlInstruction2Star:
			CHECK_STACK(1, 1);
			dataTop->i <<= 1;
		continue;

		case ficlInstruction2Slash:
			CHECK_STACK(1, 1);
			dataTop->i >>= 1;
		continue;

		case ficlInstructionStarSlash: {
			ficlInteger x, y, z;
			ficl2Integer prod;
			CHECK_STACK(3, 1);

			z = (dataTop--)->i;
			y = (dataTop--)->i;
			x = dataTop->i;

			prod = ficl2IntegerMultiply(x, y);
			dataTop->i = FICL_2UNSIGNED_GET_LOW(
			    ficl2IntegerDivideSymmetric(prod, z).quotient);
		continue;
		}

		case ficlInstructionStarSlashMod: {
			ficlInteger x, y, z;
			ficl2Integer prod;
			ficl2IntegerQR qr;

			CHECK_STACK(3, 2);

			z = (dataTop--)->i;
			y = dataTop[0].i;
			x = dataTop[-1].i;

			prod = ficl2IntegerMultiply(x, y);
			qr   = ficl2IntegerDivideSymmetric(prod, z);

			dataTop[-1].i = qr.remainder;
			dataTop[0].i = FICL_2UNSIGNED_GET_LOW(qr.quotient);
			continue;
		}

#if FICL_WANT_FLOAT
		case ficlInstructionF0:
			CHECK_FLOAT_STACK(0, 1);
			(++floatTop)->f = 0.0f;
		continue;

		case ficlInstructionF1:
			CHECK_FLOAT_STACK(0, 1);
			(++floatTop)->f = 1.0f;
		continue;

		case ficlInstructionFNeg1:
			CHECK_FLOAT_STACK(0, 1);
			(++floatTop)->f = -1.0f;
		continue;

		/*
		 * Floating point literal execution word.
		 */
		case ficlInstructionFLiteralParen:
			CHECK_FLOAT_STACK(0, 1);

			/*
			 * Yes, I'm using ->i here,
			 * but it's really a float.  --lch
			 */
			(++floatTop)->i = *ip++;
				continue;

		/*
		 * Do float addition r1 + r2.
		 * f+ ( r1 r2 -- r )
		 */
		case ficlInstructionFPlus:
			CHECK_FLOAT_STACK(2, 1);

			f = (floatTop--)->f;
			floatTop->f += f;
		continue;

		/*
		 * Do float subtraction r1 - r2.
		 * f- ( r1 r2 -- r )
		 */
		case ficlInstructionFMinus:
			CHECK_FLOAT_STACK(2, 1);

			f = (floatTop--)->f;
			floatTop->f -= f;
		continue;

		/*
		 * Do float multiplication r1 * r2.
		 * f* ( r1 r2 -- r )
		 */
		case ficlInstructionFStar:
			CHECK_FLOAT_STACK(2, 1);

			f = (floatTop--)->f;
			floatTop->f *= f;
		continue;

		/*
		 * Do float negation.
		 * fnegate ( r -- r )
		 */
		case ficlInstructionFNegate:
			CHECK_FLOAT_STACK(1, 1);

			floatTop->f = -(floatTop->f);
		continue;

		/*
		 * Do float division r1 / r2.
		 * f/ ( r1 r2 -- r )
		 */
		case ficlInstructionFSlash:
			CHECK_FLOAT_STACK(2, 1);

			f = (floatTop--)->f;
			floatTop->f /= f;
		continue;

		/*
		 * Do float + integer r + n.
		 * f+i ( r n -- r )
		 */
		case ficlInstructionFPlusI:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f += f;
		continue;

		/*
		 * Do float - integer r - n.
		 * f-i ( r n -- r )
		 */
		case ficlInstructionFMinusI:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f -= f;
		continue;

		/*
		 * Do float * integer r * n.
		 * f*i ( r n -- r )
		 */
		case ficlInstructionFStarI:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f *= f;
		continue;

		/*
		 * Do float / integer r / n.
		 * f/i ( r n -- r )
		 */
		case ficlInstructionFSlashI:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f /= f;
			continue;

		/*
		 * Do integer - float n - r.
		 * i-f ( n r -- r )
		 */
		case ficlInstructionIMinusF:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f = f - floatTop->f;
		continue;

		/*
		 * Do integer / float n / r.
		 * i/f ( n r -- r )
		 */
		case ficlInstructionISlashF:
			CHECK_FLOAT_STACK(1, 1);
			CHECK_STACK(1, 0);

			f = (ficlFloat)(dataTop--)->f;
			floatTop->f = f / floatTop->f;
		continue;

		/*
		 * Do integer to float conversion.
		 * int>float ( n -- r )
		 */
		case ficlInstructionIntToFloat:
			CHECK_STACK(1, 0);
			CHECK_FLOAT_STACK(0, 1);

			(++floatTop)->f = ((dataTop--)->f);
		continue;

		/*
		 * Do float to integer conversion.
		 * float>int ( r -- n )
		 */
		case ficlInstructionFloatToInt:
			CHECK_STACK(0, 1);
			CHECK_FLOAT_STACK(1, 0);

			(++dataTop)->i = ((floatTop--)->i);
		continue;

		/*
		 * Add a floating point number to contents of a variable.
		 * f+! ( r n -- )
		 */
		case ficlInstructionFPlusStore: {
			ficlCell *cell;

			CHECK_STACK(1, 0);
			CHECK_FLOAT_STACK(1, 0);

			cell = (ficlCell *)(dataTop--)->p;
			cell->f += (floatTop--)->f;
		continue;
		}

		/*
		 * Do float stack drop.
		 * fdrop ( r -- )
		 */
		case ficlInstructionFDrop:
			CHECK_FLOAT_STACK(1, 0);
			floatTop--;
		continue;

		/*
		 * Do float stack ?dup.
		 * f?dup ( r -- r )
		 */
		case ficlInstructionFQuestionDup:
			CHECK_FLOAT_STACK(1, 2);

			if (floatTop->f != 0)
				goto FDUP;

		continue;

		/*
		 * Do float stack dup.
		 * fdup ( r -- r r )
		 */
		case ficlInstructionFDup:
			CHECK_FLOAT_STACK(1, 2);

FDUP:
			floatTop[1] = floatTop[0];
			floatTop++;
			continue;

		/*
		 * Do float stack swap.
		 * fswap ( r1 r2 -- r2 r1 )
		 */
		case ficlInstructionFSwap:
			CHECK_FLOAT_STACK(2, 2);

			c = floatTop[0];
			floatTop[0] = floatTop[-1];
			floatTop[-1] = c;
		continue;

		/*
		 * Do float stack 2drop.
		 * f2drop ( r r -- )
		 */
		case ficlInstructionF2Drop:
			CHECK_FLOAT_STACK(2, 0);

			floatTop -= 2;
		continue;

		/*
		 * Do float stack 2dup.
		 * f2dup ( r1 r2 -- r1 r2 r1 r2 )
		 */
		case ficlInstructionF2Dup:
			CHECK_FLOAT_STACK(2, 4);

			floatTop[1] = floatTop[-1];
			floatTop[2] = *floatTop;
			floatTop += 2;
		continue;

		/*
		 * Do float stack over.
		 * fover ( r1 r2 -- r1 r2 r1 )
		 */
		case ficlInstructionFOver:
			CHECK_FLOAT_STACK(2, 3);

			floatTop[1] = floatTop[-1];
			floatTop++;
		continue;

		/*
		 * Do float stack 2over.
		 * f2over ( r1 r2 r3 -- r1 r2 r3 r1 r2 )
		 */
		case ficlInstructionF2Over:
			CHECK_FLOAT_STACK(4, 6);

			floatTop[1] = floatTop[-2];
			floatTop[2] = floatTop[-1];
			floatTop += 2;
		continue;

		/*
		 * Do float stack pick.
		 * fpick ( n -- r )
		 */
		case ficlInstructionFPick:
			CHECK_STACK(1, 0);
			c = *dataTop--;
			CHECK_FLOAT_STACK(c.i+2, c.i+3);

			floatTop[1] = floatTop[- c.i - 1];
		continue;

		/*
		 * Do float stack rot.
		 * frot ( r1 r2 r3  -- r2 r3 r1 )
		 */
		case ficlInstructionFRot:
			i = 2;
		goto FROLL;

		/*
		 * Do float stack roll.
		 * froll ( n -- )
		 */
		case ficlInstructionFRoll:
			CHECK_STACK(1, 0);
			i = (dataTop--)->i;

			if (i < 1)
				continue;

FROLL:
			CHECK_FLOAT_STACK(i+1, i+2);
			c = floatTop[-i];
			memmove(floatTop - i, floatTop - (i - 1),
			    i * sizeof (ficlCell));
			*floatTop = c;

		continue;

		/*
		 * Do float stack -rot.
		 * f-rot ( r1 r2 r3  -- r3 r1 r2 )
		 */
		case ficlInstructionFMinusRot:
			i = 2;
			goto FMINUSROLL;


		/*
		 * Do float stack -roll.
		 * f-roll ( n -- )
		 */
		case ficlInstructionFMinusRoll:
			CHECK_STACK(1, 0);
			i = (dataTop--)->i;

			if (i < 1)
				continue;

FMINUSROLL:
			CHECK_FLOAT_STACK(i+1, i+2);
			c = *floatTop;
			memmove(floatTop - (i - 1), floatTop - i,
			    i * sizeof (ficlCell));
			floatTop[-i] = c;

		continue;

		/*
		 * Do float stack 2swap
		 * f2swap ( r1 r2 r3 r4  -- r3 r4 r1 r2 )
		 */
		case ficlInstructionF2Swap: {
			ficlCell c2;
			CHECK_FLOAT_STACK(4, 4);

			c = *floatTop;
			c2 = floatTop[-1];

			*floatTop = floatTop[-2];
			floatTop[-1] = floatTop[-3];

			floatTop[-2] = c;
			floatTop[-3] = c2;
		continue;
		}

		/*
		 * Do float 0= comparison r = 0.0.
		 * f0= ( r -- T/F )
		 */
		case ficlInstructionF0Equals:
			CHECK_FLOAT_STACK(1, 0);
			CHECK_STACK(0, 1);

			(++dataTop)->i = FICL_BOOL((floatTop--)->f != 0.0f);
		continue;

		/*
		 * Do float 0< comparison r < 0.0.
		 * f0< ( r -- T/F )
		 */
		case ficlInstructionF0Less:
			CHECK_FLOAT_STACK(1, 0);
			CHECK_STACK(0, 1);

			(++dataTop)->i = FICL_BOOL((floatTop--)->f < 0.0f);
		continue;

		/*
		 * Do float 0> comparison r > 0.0.
		 * f0> ( r -- T/F )
		 */
		case ficlInstructionF0Greater:
			CHECK_FLOAT_STACK(1, 0);
			CHECK_STACK(0, 1);

			(++dataTop)->i = FICL_BOOL((floatTop--)->f > 0.0f);
		continue;

		/*
		 * Do float = comparison r1 = r2.
		 * f= ( r1 r2 -- T/F )
		 */
		case ficlInstructionFEquals:
			CHECK_FLOAT_STACK(2, 0);
			CHECK_STACK(0, 1);

			f = (floatTop--)->f;
			(++dataTop)->i = FICL_BOOL((floatTop--)->f == f);
		continue;

		/*
		 * Do float < comparison r1 < r2.
		 * f< ( r1 r2 -- T/F )
		 */
		case ficlInstructionFLess:
			CHECK_FLOAT_STACK(2, 0);
			CHECK_STACK(0, 1);

			f = (floatTop--)->f;
			(++dataTop)->i = FICL_BOOL((floatTop--)->f < f);
		continue;

		/*
		 * Do float > comparison r1 > r2.
		 * f> ( r1 r2 -- T/F )
		 */
		case ficlInstructionFGreater:
			CHECK_FLOAT_STACK(2, 0);
			CHECK_STACK(0, 1);

			f = (floatTop--)->f;
			(++dataTop)->i = FICL_BOOL((floatTop--)->f > f);
		continue;


		/*
		 * Move float to param stack (assumes they both fit in a
		 * single ficlCell) f>s
		 */
		case ficlInstructionFFrom:
			CHECK_FLOAT_STACK(1, 0);
			CHECK_STACK(0, 1);

			*++dataTop = *floatTop--;
		continue;

		case ficlInstructionToF:
			CHECK_FLOAT_STACK(0, 1);
			CHECK_STACK(1, 0);

			*++floatTop = *dataTop--;
		continue;

#endif /* FICL_WANT_FLOAT */

		/*
		 * c o l o n P a r e n
		 * This is the code that executes a colon definition. It
		 * assumes that the virtual machine is running a "next" loop
		 * (See the vm.c for its implementation of member function
		 * vmExecute()). The colon code simply copies the address of
		 * the first word in the list of words to interpret into IP
		 * after saving its old value. When we return to the "next"
		 * loop, the virtual machine will call the code for each
		 * word in turn.
		 */
		case ficlInstructionColonParen:
			(++returnTop)->p = (void *)ip;
			ip = (ficlInstruction *)(fw->param);
		continue;

		case ficlInstructionCreateParen:
			CHECK_STACK(0, 1);
			(++dataTop)->p = (fw->param + 1);
		continue;

		case ficlInstructionVariableParen:
			CHECK_STACK(0, 1);
			(++dataTop)->p = fw->param;
		continue;

		/*
		 * c o n s t a n t P a r e n
		 * This is the run-time code for "constant". It simply returns
		 * the contents of its word's first data ficlCell.
		 */

#if FICL_WANT_FLOAT
		case ficlInstructionF2ConstantParen:
			CHECK_FLOAT_STACK(0, 2);
			FLOAT_PUSH_CELL_POINTER_DOUBLE(fw->param);

		case ficlInstructionFConstantParen:
			CHECK_FLOAT_STACK(0, 1);
			FLOAT_PUSH_CELL_POINTER(fw->param);
#endif /* FICL_WANT_FLOAT */

		case ficlInstruction2ConstantParen:
			CHECK_STACK(0, 2);
			PUSH_CELL_POINTER_DOUBLE(fw->param);

		case ficlInstructionConstantParen:
			CHECK_STACK(0, 1);
			PUSH_CELL_POINTER(fw->param);

#if FICL_WANT_USER
		case ficlInstructionUserParen: {
			ficlInteger i = fw->param[0].i;
			(++dataTop)->p = &vm->user[i];
		continue;
		}
#endif

		default:
		/*
		 * Clever hack, or evil coding?  You be the judge.
		 *
		 * If the word we've been asked to execute is in fact
		 * an *instruction*, we grab the instruction, stow it
		 * in "i" (our local cache of *ip), and *jump* to the
		 * top of the switch statement.  --lch
		 */
			if (((ficlInstruction)fw->code >
			    ficlInstructionInvalid) &&
			    ((ficlInstruction)fw->code < ficlInstructionLast)) {
				instruction = (ficlInstruction)fw->code;
				goto AGAIN;
			}

			LOCAL_VARIABLE_SPILL;
			(vm)->runningWord = fw;
			fw->code(vm);
			LOCAL_VARIABLE_REFILL;
		continue;
		}
	}

	LOCAL_VARIABLE_SPILL;
	vm->exceptionHandler = oldExceptionHandler;
}

/*
 * v m G e t D i c t
 * Returns the address dictionary for this VM's system
 */
ficlDictionary *
ficlVmGetDictionary(ficlVm *vm)
{
	FICL_VM_ASSERT(vm, vm);
	return (vm->callback.system->dictionary);
}

/*
 * v m G e t S t r i n g
 * Parses a string out of the VM input buffer and copies up to the first
 * FICL_COUNTED_STRING_MAX characters to the supplied destination buffer, a
 * ficlCountedString. The destination string is NULL terminated.
 *
 * Returns the address of the first unused character in the dest buffer.
 */
char *
ficlVmGetString(ficlVm *vm, ficlCountedString *counted, char delimiter)
{
	ficlString s = ficlVmParseStringEx(vm, delimiter, 0);

	if (FICL_STRING_GET_LENGTH(s) > FICL_COUNTED_STRING_MAX) {
		FICL_STRING_SET_LENGTH(s, FICL_COUNTED_STRING_MAX);
	}

	strncpy(counted->text, FICL_STRING_GET_POINTER(s),
	    FICL_STRING_GET_LENGTH(s));
	counted->text[FICL_STRING_GET_LENGTH(s)] = '\0';
	counted->length = (ficlUnsigned8)FICL_STRING_GET_LENGTH(s);

	return (counted->text + FICL_STRING_GET_LENGTH(s) + 1);
}

/*
 * v m G e t W o r d
 * vmGetWord calls vmGetWord0 repeatedly until it gets a string with
 * non-zero length.
 */
ficlString
ficlVmGetWord(ficlVm *vm)
{
	ficlString s = ficlVmGetWord0(vm);

	if (FICL_STRING_GET_LENGTH(s) == 0) {
		ficlVmThrow(vm, FICL_VM_STATUS_RESTART);
	}

	return (s);
}

/*
 * v m G e t W o r d 0
 * Skip leading whitespace and parse a space delimited word from the tib.
 * Returns the start address and length of the word. Updates the tib
 * to reflect characters consumed, including the trailing delimiter.
 * If there's nothing of interest in the tib, returns zero. This function
 * does not use vmParseString because it uses isspace() rather than a
 * single  delimiter character.
 */
ficlString
ficlVmGetWord0(ficlVm *vm)
{
	char *trace = ficlVmGetInBuf(vm);
	char *stop = ficlVmGetInBufEnd(vm);
	ficlString s;
	ficlUnsigned length = 0;
	char c = 0;

	trace = ficlStringSkipSpace(trace, stop);
	FICL_STRING_SET_POINTER(s, trace);

	/* Please leave this loop this way; it makes Purify happier.  --lch */
	for (;;) {
		if (trace == stop)
			break;
		c = *trace;
		if (isspace((unsigned char)c))
			break;
		length++;
		trace++;
	}

	FICL_STRING_SET_LENGTH(s, length);

	/* skip one trailing delimiter */
	if ((trace != stop) && isspace((unsigned char)c))
		trace++;

	ficlVmUpdateTib(vm, trace);

	return (s);
}

/*
 * v m G e t W o r d T o P a d
 * Does vmGetWord and copies the result to the pad as a NULL terminated
 * string. Returns the length of the string. If the string is too long
 * to fit in the pad, it is truncated.
 */
int
ficlVmGetWordToPad(ficlVm *vm)
{
	ficlString s;
	char *pad = (char *)vm->pad;
	s = ficlVmGetWord(vm);

	if (FICL_STRING_GET_LENGTH(s) > FICL_PAD_SIZE)
		FICL_STRING_SET_LENGTH(s, FICL_PAD_SIZE);

	strncpy(pad, FICL_STRING_GET_POINTER(s), FICL_STRING_GET_LENGTH(s));
	pad[FICL_STRING_GET_LENGTH(s)] = '\0';
	return ((int)(FICL_STRING_GET_LENGTH(s)));
}

/*
 * v m P a r s e S t r i n g
 * Parses a string out of the input buffer using the delimiter
 * specified. Skips leading delimiters, marks the start of the string,
 * and counts characters to the next delimiter it encounters. It then
 * updates the vm input buffer to consume all these chars, including the
 * trailing delimiter.
 * Returns the address and length of the parsed string, not including the
 * trailing delimiter.
 */
ficlString
ficlVmParseString(ficlVm *vm, char delimiter)
{
	return (ficlVmParseStringEx(vm, delimiter, 1));
}

ficlString
ficlVmParseStringEx(ficlVm *vm, char delimiter, char skipLeadingDelimiters)
{
	ficlString s;
	char *trace = ficlVmGetInBuf(vm);
	char *stop = ficlVmGetInBufEnd(vm);
	char c;

	if (skipLeadingDelimiters) {
		while ((trace != stop) && (*trace == delimiter))
			trace++;
	}

	FICL_STRING_SET_POINTER(s, trace);    /* mark start of text */

	/* find next delimiter or end of line */
	for (c = *trace;
	    (trace != stop) && (c != delimiter) && (c != '\r') && (c != '\n');
	    c = *++trace) {
		;
	}

	/* set length of result */
	FICL_STRING_SET_LENGTH(s, trace - FICL_STRING_GET_POINTER(s));

	/* gobble trailing delimiter */
	if ((trace != stop) && (*trace == delimiter))
		trace++;

	ficlVmUpdateTib(vm, trace);
	return (s);
}


/*
 * v m P o p
 */
ficlCell
ficlVmPop(ficlVm *vm)
{
	return (ficlStackPop(vm->dataStack));
}

/*
 * v m P u s h
 */
void
ficlVmPush(ficlVm *vm, ficlCell c)
{
	ficlStackPush(vm->dataStack, c);
}

/*
 * v m P o p I P
 */
void
ficlVmPopIP(ficlVm *vm)
{
	vm->ip = (ficlIp)(ficlStackPopPointer(vm->returnStack));
}

/*
 * v m P u s h I P
 */
void
ficlVmPushIP(ficlVm *vm, ficlIp newIP)
{
	ficlStackPushPointer(vm->returnStack, (void *)vm->ip);
	vm->ip = newIP;
}

/*
 * v m P u s h T i b
 * Binds the specified input string to the VM and clears >IN (the index)
 */
void
ficlVmPushTib(ficlVm *vm, char *text, ficlInteger nChars, ficlTIB *pSaveTib)
{
	if (pSaveTib) {
		*pSaveTib = vm->tib;
	}
	vm->tib.text = text;
	vm->tib.end = text + nChars;
	vm->tib.index = 0;
}

void
ficlVmPopTib(ficlVm *vm, ficlTIB *pTib)
{
	if (pTib) {
		vm->tib = *pTib;
	}
}

/*
 * v m Q u i t
 */
void
ficlVmQuit(ficlVm *vm)
{
	ficlStackReset(vm->returnStack);
	vm->restart = 0;
	vm->ip = NULL;
	vm->runningWord = NULL;
	vm->state = FICL_VM_STATE_INTERPRET;
	vm->tib.text = NULL;
	vm->tib.end = NULL;
	vm->tib.index = 0;
	vm->pad[0] = '\0';
	vm->sourceId.i = 0;
}

/*
 * v m R e s e t
 */
void
ficlVmReset(ficlVm *vm)
{
	ficlVmQuit(vm);
	ficlStackReset(vm->dataStack);
#if FICL_WANT_FLOAT
	ficlStackReset(vm->floatStack);
#endif
	vm->base = 10;
}

/*
 * v m S e t T e x t O u t
 * Binds the specified output callback to the vm. If you pass NULL,
 * binds the default output function (ficlTextOut)
 */
void
ficlVmSetTextOut(ficlVm *vm, ficlOutputFunction textOut)
{
	vm->callback.textOut = textOut;
}

void
ficlVmTextOut(ficlVm *vm, char *text)
{
	ficlCallbackTextOut((ficlCallback *)vm, text);
}


void
ficlVmErrorOut(ficlVm *vm, char *text)
{
	ficlCallbackErrorOut((ficlCallback *)vm, text);
}


/*
 * v m T h r o w
 */
void
ficlVmThrow(ficlVm *vm, int except)
{
	if (vm->exceptionHandler)
		longjmp(*(vm->exceptionHandler), except);
}

void
ficlVmThrowError(ficlVm *vm, char *fmt, ...)
{
	va_list list;

	va_start(list, fmt);
	vsprintf(vm->pad, fmt, list);
	va_end(list);
	strcat(vm->pad, "\n");

	ficlVmErrorOut(vm, vm->pad);
	longjmp(*(vm->exceptionHandler), FICL_VM_STATUS_ERROR_EXIT);
}

void
ficlVmThrowErrorVararg(ficlVm *vm, char *fmt, va_list list)
{
	vsprintf(vm->pad, fmt, list);
	/*
	 * well, we can try anyway, we're certainly not
	 * returning to our caller!
	 */
	va_end(list);
	strcat(vm->pad, "\n");

	ficlVmErrorOut(vm, vm->pad);
	longjmp(*(vm->exceptionHandler), FICL_VM_STATUS_ERROR_EXIT);
}

/*
 * f i c l E v a l u a t e
 * Wrapper for ficlExec() which sets SOURCE-ID to -1.
 */
int
ficlVmEvaluate(ficlVm *vm, char *s)
{
	int returnValue;
	ficlCell id = vm->sourceId;
	ficlString string;
	vm->sourceId.i = -1;
	FICL_STRING_SET_FROM_CSTRING(string, s);
	returnValue = ficlVmExecuteString(vm, string);
	vm->sourceId = id;
	return (returnValue);
}

/*
 * f i c l E x e c
 * Evaluates a block of input text in the context of the
 * specified interpreter. Emits any requested output to the
 * interpreter's output function.
 *
 * Contains the "inner interpreter" code in a tight loop
 *
 * Returns one of the VM_XXXX codes defined in ficl.h:
 * VM_OUTOFTEXT is the normal exit condition
 * VM_ERREXIT means that the interpreter encountered a syntax error
 *      and the vm has been reset to recover (some or all
 *      of the text block got ignored
 * VM_USEREXIT means that the user executed the "bye" command
 *      to shut down the interpreter. This would be a good
 *      time to delete the vm, etc -- or you can ignore this
 *      signal.
 */
int
ficlVmExecuteString(ficlVm *vm, ficlString s)
{
	ficlSystem *system = vm->callback.system;
	ficlDictionary *dictionary = system->dictionary;

	int except;
	jmp_buf vmState;
	jmp_buf *oldState;
	ficlTIB saveficlTIB;

	FICL_VM_ASSERT(vm, vm);
	FICL_VM_ASSERT(vm, system->interpreterLoop[0]);

	ficlVmPushTib(vm, FICL_STRING_GET_POINTER(s),
	    FICL_STRING_GET_LENGTH(s), &saveficlTIB);

	/*
	 * Save and restore VM's jmp_buf to enable nested calls to ficlExec
	 */
	oldState = vm->exceptionHandler;

	/* This has to come before the setjmp! */
	vm->exceptionHandler = &vmState;
	except = setjmp(vmState);

	switch (except) {
	case 0:
		if (vm->restart) {
			vm->runningWord->code(vm);
			vm->restart = 0;
		} else {	/* set VM up to interpret text */
			ficlVmPushIP(vm, &(system->interpreterLoop[0]));
		}

		ficlVmInnerLoop(vm, 0);
	break;

	case FICL_VM_STATUS_RESTART:
		vm->restart = 1;
		except = FICL_VM_STATUS_OUT_OF_TEXT;
	break;

	case FICL_VM_STATUS_OUT_OF_TEXT:
		ficlVmPopIP(vm);
#if 0	/* we dont output prompt in loader */
		if ((vm->state != FICL_VM_STATE_COMPILE) &&
		    (vm->sourceId.i == 0))
			ficlVmTextOut(vm, FICL_PROMPT);
#endif
	break;

	case FICL_VM_STATUS_USER_EXIT:
	case FICL_VM_STATUS_INNER_EXIT:
	case FICL_VM_STATUS_BREAK:
	break;

	case FICL_VM_STATUS_QUIT:
		if (vm->state == FICL_VM_STATE_COMPILE) {
			ficlDictionaryAbortDefinition(dictionary);
#if FICL_WANT_LOCALS
			ficlDictionaryEmpty(system->locals,
			    system->locals->forthWordlist->size);
#endif
		}
		ficlVmQuit(vm);
	break;

	case FICL_VM_STATUS_ERROR_EXIT:
	case FICL_VM_STATUS_ABORT:
	case FICL_VM_STATUS_ABORTQ:
	default:		/* user defined exit code?? */
		if (vm->state == FICL_VM_STATE_COMPILE) {
			ficlDictionaryAbortDefinition(dictionary);
#if FICL_WANT_LOCALS
			ficlDictionaryEmpty(system->locals,
			    system->locals->forthWordlist->size);
#endif
		}
		ficlDictionaryResetSearchOrder(dictionary);
		ficlVmReset(vm);
	break;
	}

	vm->exceptionHandler = oldState;
	ficlVmPopTib(vm, &saveficlTIB);
	return (except);
}

/*
 * f i c l E x e c X T
 * Given a pointer to a ficlWord, push an inner interpreter and
 * execute the word to completion. This is in contrast with vmExecute,
 * which does not guarantee that the word will have completed when
 * the function returns (ie in the case of colon definitions, which
 * need an inner interpreter to finish)
 *
 * Returns one of the VM_XXXX exception codes listed in ficl.h. Normal
 * exit condition is VM_INNEREXIT, Ficl's private signal to exit the
 * inner loop under normal circumstances. If another code is thrown to
 * exit the loop, this function will re-throw it if it's nested under
 * itself or ficlExec.
 *
 * NOTE: this function is intended so that C code can execute ficlWords
 * given their address in the dictionary (xt).
 */
int
ficlVmExecuteXT(ficlVm *vm, ficlWord *pWord)
{
	int except;
	jmp_buf vmState;
	jmp_buf *oldState;
	ficlWord *oldRunningWord;

	FICL_VM_ASSERT(vm, vm);
	FICL_VM_ASSERT(vm, vm->callback.system->exitInnerWord);

	/*
	 * Save the runningword so that RESTART behaves correctly
	 * over nested calls.
	 */
	oldRunningWord = vm->runningWord;
	/*
	 * Save and restore VM's jmp_buf to enable nested calls
	 */
	oldState = vm->exceptionHandler;
	/* This has to come before the setjmp! */
	vm->exceptionHandler = &vmState;
	except = setjmp(vmState);

	if (except)
		ficlVmPopIP(vm);
	else
		ficlVmPushIP(vm, &(vm->callback.system->exitInnerWord));

	switch (except) {
	case 0:
		ficlVmExecuteWord(vm, pWord);
		ficlVmInnerLoop(vm, 0);
	break;

	case FICL_VM_STATUS_INNER_EXIT:
	case FICL_VM_STATUS_BREAK:
	break;

	case FICL_VM_STATUS_RESTART:
	case FICL_VM_STATUS_OUT_OF_TEXT:
	case FICL_VM_STATUS_USER_EXIT:
	case FICL_VM_STATUS_QUIT:
	case FICL_VM_STATUS_ERROR_EXIT:
	case FICL_VM_STATUS_ABORT:
	case FICL_VM_STATUS_ABORTQ:
	default:		/* user defined exit code?? */
		if (oldState) {
			vm->exceptionHandler = oldState;
			ficlVmThrow(vm, except);
		}
	break;
	}

	vm->exceptionHandler = oldState;
	vm->runningWord = oldRunningWord;
	return (except);
}

/*
 * f i c l P a r s e N u m b e r
 * Attempts to convert the NULL terminated string in the VM's pad to
 * a number using the VM's current base. If successful, pushes the number
 * onto the param stack and returns FICL_TRUE. Otherwise, returns FICL_FALSE.
 * (jws 8/01) Trailing decimal point causes a zero ficlCell to be pushed. (See
 * the standard for DOUBLE wordset.
 */
int
ficlVmParseNumber(ficlVm *vm, ficlString s)
{
	ficlInteger accumulator = 0;
	char isNegative = 0;
	char isDouble = 0;
	unsigned base = vm->base;
	char *trace = FICL_STRING_GET_POINTER(s);
	ficlUnsigned8 length = (ficlUnsigned8)FICL_STRING_GET_LENGTH(s);
	unsigned c;
	unsigned digit;

	if (length > 1) {
		switch (*trace) {
		case '-':
			trace++;
			length--;
			isNegative = 1;
		break;
		case '+':
			trace++;
			length--;
			isNegative = 0;
		break;
		default:
		break;
		}
	}

	/* detect & remove trailing decimal */
	if ((length > 0) && (trace[length - 1] == '.')) {
		isDouble = 1;
		length--;
	}

	if (length == 0)		/* detect "+", "-", ".", "+." etc */
		return (0);		/* false */

	while ((length--) && ((c = *trace++) != '\0')) {
		if (!isalnum(c))
			return (0);	/* false */

		digit = c - '0';

		if (digit > 9)
			digit = tolower(c) - 'a' + 10;

		if (digit >= base)
			return (0);	/* false */

		accumulator = accumulator * base + digit;
	}

	if (isNegative)
		accumulator = -accumulator;

	ficlStackPushInteger(vm->dataStack, accumulator);
	if (vm->state == FICL_VM_STATE_COMPILE)
		ficlPrimitiveLiteralIm(vm);

	if (isDouble) {			/* simple (required) DOUBLE support */
		if (isNegative)
			ficlStackPushInteger(vm->dataStack, -1);
		else
			ficlStackPushInteger(vm->dataStack, 0);
		if (vm->state == FICL_VM_STATE_COMPILE)
			ficlPrimitiveLiteralIm(vm);
	}

	return (1); /* true */
}

/*
 * d i c t C h e c k
 * Checks the dictionary for corruption and throws appropriate
 * errors.
 * Input: +n number of ADDRESS UNITS (not ficlCells) proposed to allot
 *        -n number of ADDRESS UNITS proposed to de-allot
 *         0 just do a consistency check
 */
void
ficlVmDictionarySimpleCheck(ficlVm *vm, ficlDictionary *dictionary, int cells)
{
#if FICL_ROBUST >= 1
	if ((cells >= 0) &&
	    (ficlDictionaryCellsAvailable(dictionary) *
	    (int)sizeof (ficlCell) < cells)) {
		ficlVmThrowError(vm, "Error: dictionary full");
	}

	if ((cells <= 0) &&
	    (ficlDictionaryCellsUsed(dictionary) *
	    (int)sizeof (ficlCell) < -cells)) {
		ficlVmThrowError(vm, "Error: dictionary underflow");
	}
#else /* FICL_ROBUST >= 1 */
	FICL_IGNORE(vm);
	FICL_IGNORE(dictionary);
	FICL_IGNORE(cells);
#endif /* FICL_ROBUST >= 1 */
}

void
ficlVmDictionaryCheck(ficlVm *vm, ficlDictionary *dictionary, int cells)
{
#if FICL_ROBUST >= 1
	ficlVmDictionarySimpleCheck(vm, dictionary, cells);

	if (dictionary->wordlistCount > FICL_MAX_WORDLISTS) {
		ficlDictionaryResetSearchOrder(dictionary);
		ficlVmThrowError(vm, "Error: search order overflow");
	} else if (dictionary->wordlistCount < 0) {
		ficlDictionaryResetSearchOrder(dictionary);
		ficlVmThrowError(vm, "Error: search order underflow");
	}
#else /* FICL_ROBUST >= 1 */
	FICL_IGNORE(vm);
	FICL_IGNORE(dictionary);
	FICL_IGNORE(cells);
#endif /* FICL_ROBUST >= 1 */
}

void
ficlVmDictionaryAllot(ficlVm *vm, ficlDictionary *dictionary, int n)
{
	FICL_VM_DICTIONARY_SIMPLE_CHECK(vm, dictionary, n);
	FICL_IGNORE(vm);
	ficlDictionaryAllot(dictionary, n);
}

void
ficlVmDictionaryAllotCells(ficlVm *vm, ficlDictionary *dictionary, int cells)
{
	FICL_VM_DICTIONARY_SIMPLE_CHECK(vm, dictionary, cells);
	FICL_IGNORE(vm);
	ficlDictionaryAllotCells(dictionary, cells);
}

/*
 * f i c l P a r s e W o r d
 * From the standard, section 3.4
 * b) Search the dictionary name space (see 3.4.2). If a definition name
 * matching the string is found:
 *  1.if interpreting, perform the interpretation semantics of the definition
 *  (see 3.4.3.2), and continue at a);
 *  2.if compiling, perform the compilation semantics of the definition
 *  (see 3.4.3.3), and continue at a).
 *
 * c) If a definition name matching the string is not found, attempt to
 * convert the string to a number (see 3.4.1.3). If successful:
 *  1.if interpreting, place the number on the data stack, and continue at a);
 *  2.if compiling, FICL_VM_STATE_COMPILE code that when executed will place
 *  the number on the stack (see 6.1.1780 LITERAL), and continue at a);
 *
 * d) If unsuccessful, an ambiguous condition exists (see 3.4.4).
 *
 * (jws 4/01) Modified to be a ficlParseStep
 */
int
ficlVmParseWord(ficlVm *vm, ficlString name)
{
	ficlDictionary *dictionary = ficlVmGetDictionary(vm);
	ficlWord *tempFW;

	FICL_VM_DICTIONARY_CHECK(vm, dictionary, 0);
	FICL_STACK_CHECK(vm->dataStack, 0, 0);

#if FICL_WANT_LOCALS
	if (vm->callback.system->localsCount > 0) {
		tempFW = ficlSystemLookupLocal(vm->callback.system, name);
	} else
#endif
		tempFW = ficlDictionaryLookup(dictionary, name);

	if (vm->state == FICL_VM_STATE_INTERPRET) {
		if (tempFW != NULL) {
			if (ficlWordIsCompileOnly(tempFW)) {
				ficlVmThrowError(vm,
				    "Error: FICL_VM_STATE_COMPILE only!");
			}

			ficlVmExecuteWord(vm, tempFW);
			return (1); /* true */
		}
	} else {	/* (vm->state == FICL_VM_STATE_COMPILE) */
		if (tempFW != NULL) {
			if (ficlWordIsImmediate(tempFW)) {
				ficlVmExecuteWord(vm, tempFW);
			} else {
				ficlCell c;
				c.p = tempFW;
				if (tempFW->flags & FICL_WORD_INSTRUCTION)
					ficlDictionaryAppendUnsigned(dictionary,
					    (ficlInteger)tempFW->code);
				else
					ficlDictionaryAppendCell(dictionary, c);
			}
			return (1); /* true */
		}
	}

	return (0); /* false */
}
