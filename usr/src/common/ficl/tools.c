/*
 * t o o l s . c
 * Forth Inspired Command Language - programming tools
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 20 June 2000
 * $Id: tools.c,v 1.12 2010/08/12 13:57:22 asau Exp $
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

/*
 * NOTES:
 * SEE needs information about the addresses of functions that
 * are the CFAs of colon definitions, constants, variables, DOES>
 * words, and so on. It gets this information from a table and supporting
 * functions in words.c.
 * fiColonParen fiDoDoes createParen fiVariableParen fiUserParen fiConstantParen
 *
 * Step and break debugger for Ficl
 * debug  ( xt -- )   Start debugging an xt
 * Set a breakpoint
 * Specify breakpoint default action
 */

#include "ficl.h"

extern void exit(int);

static void ficlPrimitiveStepIn(ficlVm *vm);
static void ficlPrimitiveStepOver(ficlVm *vm);
static void ficlPrimitiveStepBreak(ficlVm *vm);

void
ficlCallbackAssert(ficlCallback *callback, int expression,
    char *expressionString, char *filename, int line)
{
#if FICL_ROBUST >= 1
	if (!expression) {
		static char buffer[256];
		sprintf(buffer, "ASSERTION FAILED at %s:%d: \"%s\"\n",
		    filename, line, expressionString);
		ficlCallbackTextOut(callback, buffer);
		exit(-1);
	}
#else /* FICL_ROBUST >= 1 */
	FICL_IGNORE(callback);
	FICL_IGNORE(expression);
	FICL_IGNORE(expressionString);
	FICL_IGNORE(filename);
	FICL_IGNORE(line);
#endif /* FICL_ROBUST >= 1 */
}

/*
 * v m S e t B r e a k
 * Set a breakpoint at the current value of IP by
 * storing that address in a BREAKPOINT record
 */
static void
ficlVmSetBreak(ficlVm *vm, ficlBreakpoint *pBP)
{
	ficlWord *pStep = ficlSystemLookup(vm->callback.system, "step-break");
	FICL_VM_ASSERT(vm, pStep);

	pBP->address = vm->ip;
	pBP->oldXT = *vm->ip;
	*vm->ip = pStep;
}

/*
 * d e b u g P r o m p t
 */
static void
ficlDebugPrompt(ficlVm *vm, int debug)
{
	if (debug)
		setenv("prompt", "dbg> ", 1);
	else
		setenv("prompt", "${interpret}", 1);
}

#if 0
static int
isPrimitive(ficlWord *word)
{
	ficlWordKind wk = ficlWordClassify(word);
	return ((wk != COLON) && (wk != DOES));
}
#endif

/*
 * d i c t H a s h S u m m a r y
 * Calculate a figure of merit for the dictionary hash table based
 * on the average search depth for all the words in the dictionary,
 * assuming uniform distribution of target keys. The figure of merit
 * is the ratio of the total search depth for all keys in the table
 * versus a theoretical optimum that would be achieved if the keys
 * were distributed into the table as evenly as possible.
 * The figure would be worse if the hash table used an open
 * addressing scheme (i.e. collisions resolved by searching the
 * table for an empty slot) for a given size table.
 */
#if FICL_WANT_FLOAT
void
ficlPrimitiveHashSummary(ficlVm *vm)
{
	ficlDictionary *dictionary = ficlVmGetDictionary(vm);
	ficlHash *pFHash;
	ficlWord **hash;
	unsigned size;
	ficlWord *word;
	unsigned i;
	int nMax = 0;
	int nWords = 0;
	int nFilled;
	double avg = 0.0;
	double best;
	int nAvg, nRem, nDepth;

	FICL_VM_DICTIONARY_CHECK(vm, dictionary, 0);

	pFHash = dictionary->wordlists[dictionary->wordlistCount - 1];
	hash = pFHash->table;
	size = pFHash->size;
	nFilled = size;

	for (i = 0; i < size; i++) {
		int n = 0;
		word = hash[i];

		while (word) {
			++n;
			++nWords;
			word = word->link;
		}

		avg += (double)(n * (n+1)) / 2.0;

		if (n > nMax)
			nMax = n;
		if (n == 0)
			--nFilled;
	}

	/* Calc actual avg search depth for this hash */
	avg = avg / nWords;

	/* Calc best possible performance with this size hash */
	nAvg = nWords / size;
	nRem = nWords % size;
	nDepth = size * (nAvg * (nAvg+1))/2 + (nAvg+1)*nRem;
	best = (double)nDepth/nWords;

	sprintf(vm->pad, "%d bins, %2.0f%% filled, Depth: "
	    "Max=%d, Avg=%2.1f, Best=%2.1f, Score: %2.0f%%\n",
	    size, (double)nFilled * 100.0 / size, nMax,
	    avg, best, 100.0 * best / avg);

	ficlVmTextOut(vm, vm->pad);
}
#endif

/*
 * Here's the outer part of the decompiler. It's
 * just a big nested conditional that checks the
 * CFA of the word to decompile for each kind of
 * known word-builder code, and tries to do
 * something appropriate. If the CFA is not recognized,
 * just indicate that it is a primitive.
 */
static void
ficlPrimitiveSeeXT(ficlVm *vm)
{
	ficlWord *word;
	ficlWordKind kind;

	word = (ficlWord *)ficlStackPopPointer(vm->dataStack);
	kind = ficlWordClassify(word);

	switch (kind) {
	case FICL_WORDKIND_COLON:
		sprintf(vm->pad, ": %.*s\n", word->length, word->name);
		ficlVmTextOut(vm, vm->pad);
		ficlDictionarySee(ficlVmGetDictionary(vm), word,
		    &(vm->callback));
	break;
	case FICL_WORDKIND_DOES:
		ficlVmTextOut(vm, "does>\n");
		ficlDictionarySee(ficlVmGetDictionary(vm),
		    (ficlWord *)word->param->p, &(vm->callback));
	break;
	case FICL_WORDKIND_CREATE:
		ficlVmTextOut(vm, "create\n");
	break;
	case FICL_WORDKIND_VARIABLE:
		sprintf(vm->pad, "variable = %ld (%#lx)\n",
		    (long)word->param->i, (long unsigned)word->param->u);
		ficlVmTextOut(vm, vm->pad);
	break;
#if FICL_WANT_USER
	case FICL_WORDKIND_USER:
		sprintf(vm->pad, "user variable %ld (%#lx)\n",
		    (long)word->param->i, (long unsigned)word->param->u);
		ficlVmTextOut(vm, vm->pad);
	break;
#endif
	case FICL_WORDKIND_CONSTANT:
		sprintf(vm->pad, "constant = %ld (%#lx)\n",
		    (long)word->param->i, (long unsigned)word->param->u);
		ficlVmTextOut(vm, vm->pad);
	break;
	case FICL_WORDKIND_2CONSTANT:
		sprintf(vm->pad, "constant = %ld %ld (%#lx %#lx)\n",
		    (long)word->param[1].i, (long)word->param->i,
		    (long unsigned)word->param[1].u,
		    (long unsigned)word->param->u);
		ficlVmTextOut(vm, vm->pad);
	break;

	default:
		sprintf(vm->pad, "%.*s is a primitive\n", word->length,
		    word->name);
		ficlVmTextOut(vm, vm->pad);
	break;
	}

	if (word->flags & FICL_WORD_IMMEDIATE) {
		ficlVmTextOut(vm, "immediate\n");
	}

	if (word->flags & FICL_WORD_COMPILE_ONLY) {
		ficlVmTextOut(vm, "compile-only\n");
	}
}

static void
ficlPrimitiveSee(ficlVm *vm)
{
	ficlPrimitiveTick(vm);
	ficlPrimitiveSeeXT(vm);
}

/*
 * f i c l D e b u g X T
 * debug  ( xt -- )
 * Given an xt of a colon definition or a word defined by DOES>, set the
 * VM up to debug the word: push IP, set the xt as the next thing to execute,
 * set a breakpoint at its first instruction, and run to the breakpoint.
 * Note: the semantics of this word are equivalent to "step in"
 */
static void
ficlPrimitiveDebugXT(ficlVm *vm)
{
	ficlWord *xt = ficlStackPopPointer(vm->dataStack);
	ficlWordKind wk = ficlWordClassify(xt);

	ficlStackPushPointer(vm->dataStack, xt);
	ficlPrimitiveSeeXT(vm);

	switch (wk) {
	case FICL_WORDKIND_COLON:
	case FICL_WORDKIND_DOES:
		/*
		 * Run the colon code and set a breakpoint at the next
		 * instruction
		 */
		ficlVmExecuteWord(vm, xt);
		ficlVmSetBreak(vm, &(vm->callback.system->breakpoint));
	break;
	default:
		ficlVmExecuteWord(vm, xt);
	break;
	}
}

/*
 * s t e p I n
 * Ficl
 * Execute the next instruction, stepping into it if it's a colon definition
 * or a does> word. This is the easy kind of step.
 */
static void
ficlPrimitiveStepIn(ficlVm *vm)
{
	/*
	 * Do one step of the inner loop
	 */
	ficlVmExecuteWord(vm, *vm->ip++);

	/*
	 * Now set a breakpoint at the next instruction
	 */
	ficlVmSetBreak(vm, &(vm->callback.system->breakpoint));
}

/*
 * s t e p O v e r
 * Ficl
 * Execute the next instruction atomically. This requires some insight into
 * the memory layout of compiled code. Set a breakpoint at the next instruction
 * in this word, and run until we hit it
 */
static void
ficlPrimitiveStepOver(ficlVm *vm)
{
	ficlWord *word;
	ficlWordKind kind;
	ficlWord *pStep = ficlSystemLookup(vm->callback.system, "step-break");
	FICL_VM_ASSERT(vm, pStep);

	word = *vm->ip;
	kind = ficlWordClassify(word);

	switch (kind) {
	case FICL_WORDKIND_COLON:
	case FICL_WORDKIND_DOES:
		/*
		 * assume that the next ficlCell holds an instruction
		 * set a breakpoint there and return to the inner interpreter
		 */
		vm->callback.system->breakpoint.address = vm->ip + 1;
		vm->callback.system->breakpoint.oldXT =  vm->ip[1];
		vm->ip[1] = pStep;
	break;
	default:
		ficlPrimitiveStepIn(vm);
	break;
	}
}

/*
 * s t e p - b r e a k
 * Ficl
 * Handles breakpoints for stepped execution.
 * Upon entry, breakpoint contains the address and replaced instruction
 * of the current breakpoint.
 * Clear the breakpoint
 * Get a command from the console.
 * i (step in) - execute the current instruction and set a new breakpoint
 *    at the IP
 * o (step over) - execute the current instruction to completion and set
 *    a new breakpoint at the IP
 * g (go) - execute the current instruction and exit
 * q (quit) - abort current word
 * b (toggle breakpoint)
 */

extern char *ficlDictionaryInstructionNames[];

static void
ficlPrimitiveStepBreak(ficlVm *vm)
{
	ficlString command;
	ficlWord *word;
	ficlWord *pOnStep;
	int debug = 1;

	if (!vm->restart) {
		FICL_VM_ASSERT(vm, vm->callback.system->breakpoint.address);
		FICL_VM_ASSERT(vm, vm->callback.system->breakpoint.oldXT);

		/*
		 * Clear the breakpoint that caused me to run
		 * Restore the original instruction at the breakpoint,
		 * and restore the IP
		 */
		vm->ip = (ficlIp)(vm->callback.system->breakpoint.address);
		*vm->ip = vm->callback.system->breakpoint.oldXT;

		/*
		 * If there's an onStep, do it
		 */
		pOnStep = ficlSystemLookup(vm->callback.system, "on-step");
		if (pOnStep)
			ficlVmExecuteXT(vm, pOnStep);

		/*
		 * Print the name of the next instruction
		 */
		word = vm->callback.system->breakpoint.oldXT;

		if ((((ficlInstruction)word) > ficlInstructionInvalid) &&
		    (((ficlInstruction)word) < ficlInstructionLast))
			sprintf(vm->pad, "next: %s (instruction %ld)\n",
			    ficlDictionaryInstructionNames[(long)word],
			    (long)word);
		else {
			sprintf(vm->pad, "next: %s\n", word->name);
			if (strcmp(word->name, "interpret") == 0)
				debug = 0;
		}

		ficlVmTextOut(vm, vm->pad);
		ficlDebugPrompt(vm, debug);
	} else {
		vm->restart = 0;
	}

	command = ficlVmGetWord(vm);

	switch (command.text[0]) {
		case 'i':
			ficlPrimitiveStepIn(vm);
		break;

		case 'o':
			ficlPrimitiveStepOver(vm);
		break;

		case 'g':
		break;

		case 'l': {
			ficlWord *xt;
			xt = ficlDictionaryFindEnclosingWord(
			    ficlVmGetDictionary(vm), (ficlCell *)(vm->ip));
			if (xt) {
				ficlStackPushPointer(vm->dataStack, xt);
				ficlPrimitiveSeeXT(vm);
			} else {
				ficlVmTextOut(vm, "sorry - can't do that\n");
			}
			ficlVmThrow(vm, FICL_VM_STATUS_RESTART);
		break;
		}

		case 'q':
			ficlDebugPrompt(vm, 0);
			ficlVmThrow(vm, FICL_VM_STATUS_ABORT);
			break;
		case 'x': {
			/*
			 * Take whatever's left in the TIB and feed it to a
			 * subordinate ficlVmExecuteString
			 */
			int returnValue;
			ficlString s;
			ficlWord *oldRunningWord = vm->runningWord;

			FICL_STRING_SET_POINTER(s,
			    vm->tib.text + vm->tib.index);
			FICL_STRING_SET_LENGTH(s,
			    vm->tib.end - FICL_STRING_GET_POINTER(s));

			returnValue = ficlVmExecuteString(vm, s);

			if (returnValue == FICL_VM_STATUS_OUT_OF_TEXT) {
				returnValue = FICL_VM_STATUS_RESTART;
				vm->runningWord = oldRunningWord;
				ficlVmTextOut(vm, "\n");
			}
			if (returnValue == FICL_VM_STATUS_ERROR_EXIT)
				ficlDebugPrompt(vm, 0);

			ficlVmThrow(vm, returnValue);
			break;
		}

		default:
			ficlVmTextOut(vm,
			    "i -- step In\n"
			    "o -- step Over\n"
			    "g -- Go (execute to completion)\n"
			    "l -- List source code\n"
			    "q -- Quit (stop debugging and abort)\n"
			    "x -- eXecute the rest of the line "
			    "as Ficl words\n");
			ficlDebugPrompt(vm, 1);
			ficlVmThrow(vm, FICL_VM_STATUS_RESTART);
		break;
	}

	ficlDebugPrompt(vm, 0);
}

/*
 * b y e
 * TOOLS
 * Signal the system to shut down - this causes ficlExec to return
 * VM_USEREXIT. The rest is up to you.
 */
static void
ficlPrimitiveBye(ficlVm *vm)
{
	ficlVmThrow(vm, FICL_VM_STATUS_USER_EXIT);
}

/*
 * d i s p l a y S t a c k
 * TOOLS
 * Display the parameter stack (code for ".s")
 */

struct stackContext
{
	ficlVm *vm;
	ficlDictionary *dictionary;
	int count;
};

static ficlInteger
ficlStackDisplayCallback(void *c, ficlCell *cell)
{
	struct stackContext *context = (struct stackContext *)c;
	char buffer[80];

#ifdef _LP64
	snprintf(buffer, sizeof (buffer), "[0x%016lx %3d]: %20ld (0x%016lx)\n",
	    (unsigned long)cell, context->count++, (long)cell->i,
	    (unsigned long)cell->u);
#else
	snprintf(buffer, sizeof (buffer), "[0x%08x %3d]: %12d (0x%08x)\n",
	    (unsigned)cell, context->count++, cell->i, cell->u);
#endif

	ficlVmTextOut(context->vm, buffer);
	return (FICL_TRUE);
}

void
ficlStackDisplay(ficlStack *stack, ficlStackWalkFunction callback,
    void *context)
{
	ficlVm *vm = stack->vm;
	char buffer[128];
	struct stackContext myContext;

	FICL_STACK_CHECK(stack, 0, 0);

#ifdef _LP64
	sprintf(buffer, "[%s stack has %d entries, top at 0x%016lx]\n",
	    stack->name, ficlStackDepth(stack), (unsigned long)stack->top);
#else
	sprintf(buffer, "[%s stack has %d entries, top at 0x%08x]\n",
	    stack->name, ficlStackDepth(stack), (unsigned)stack->top);
#endif
	ficlVmTextOut(vm, buffer);

	if (callback == NULL) {
		myContext.vm = vm;
		myContext.count = 0;
		context = &myContext;
		callback = ficlStackDisplayCallback;
	}
	ficlStackWalk(stack, callback, context, FICL_FALSE);

#ifdef _LP64
	sprintf(buffer, "[%s stack base at 0x%016lx]\n", stack->name,
	    (unsigned long)stack->base);
#else
	sprintf(buffer, "[%s stack base at 0x%08x]\n", stack->name,
	    (unsigned)stack->base);
#endif
	ficlVmTextOut(vm, buffer);
}

void
ficlVmDisplayDataStack(ficlVm *vm)
{
	ficlStackDisplay(vm->dataStack, NULL, NULL);
}

static ficlInteger
ficlStackDisplaySimpleCallback(void *c, ficlCell *cell)
{
	struct stackContext *context = (struct stackContext *)c;
	char buffer[32];

	sprintf(buffer, "%s%ld", context->count ? " " : "", (long)cell->i);
	context->count++;
	ficlVmTextOut(context->vm, buffer);
	return (FICL_TRUE);
}

void
ficlVmDisplayDataStackSimple(ficlVm *vm)
{
	ficlStack *stack = vm->dataStack;
	char buffer[32];
	struct stackContext context;

	FICL_STACK_CHECK(stack, 0, 0);

	sprintf(buffer, "[%d] ", ficlStackDepth(stack));
	ficlVmTextOut(vm, buffer);

	context.vm = vm;
	context.count = 0;
	ficlStackWalk(stack, ficlStackDisplaySimpleCallback, &context,
	    FICL_TRUE);
}

static ficlInteger
ficlReturnStackDisplayCallback(void *c, ficlCell *cell)
{
	struct stackContext *context = (struct stackContext *)c;
	char buffer[128];

#ifdef _LP64
	sprintf(buffer, "[0x%016lx %3d] %20ld (0x%016lx)", (unsigned long)cell,
	    context->count++, cell->i, cell->u);
#else
	sprintf(buffer, "[0x%08x %3d] %12d (0x%08x)", (unsigned)cell,
	    context->count++, cell->i, cell->u);
#endif

	/*
	 * Attempt to find the word that contains the return
	 * stack address (as if it is part of a colon definition).
	 * If this works, also print the name of the word.
	 */
	if (ficlDictionaryIncludes(context->dictionary, cell->p)) {
		ficlWord *word;
		word = ficlDictionaryFindEnclosingWord(context->dictionary,
		    cell->p);
		if (word) {
			int offset = (ficlCell *)cell->p - &word->param[0];
			sprintf(buffer + strlen(buffer), ", %s + %d ",
			    word->name, offset);
		}
	}
	strcat(buffer, "\n");
	ficlVmTextOut(context->vm, buffer);
	return (FICL_TRUE);
}

void
ficlVmDisplayReturnStack(ficlVm *vm)
{
	struct stackContext context;
	context.vm = vm;
	context.count = 0;
	context.dictionary = ficlVmGetDictionary(vm);
	ficlStackDisplay(vm->returnStack, ficlReturnStackDisplayCallback,
	    &context);
}

/*
 * f o r g e t - w i d
 */
static void
ficlPrimitiveForgetWid(ficlVm *vm)
{
	ficlDictionary *dictionary = ficlVmGetDictionary(vm);
	ficlHash *hash;

	hash = (ficlHash *)ficlStackPopPointer(vm->dataStack);
	ficlHashForget(hash, dictionary->here);
}

/*
 * f o r g e t
 * TOOLS EXT  ( "<spaces>name" -- )
 * Skip leading space delimiters. Parse name delimited by a space.
 * Find name, then delete name from the dictionary along with all
 * words added to the dictionary after name. An ambiguous
 * condition exists if name cannot be found.
 *
 * If the Search-Order word set is present, FORGET searches the
 * compilation word list. An ambiguous condition exists if the
 * compilation word list is deleted.
 */
static void
ficlPrimitiveForget(ficlVm *vm)
{
	void *where;
	ficlDictionary *dictionary = ficlVmGetDictionary(vm);
	ficlHash *hash = dictionary->compilationWordlist;

	ficlPrimitiveTick(vm);
	where = ((ficlWord *)ficlStackPopPointer(vm->dataStack))->name;
	ficlHashForget(hash, where);
	dictionary->here = FICL_POINTER_TO_CELL(where);
}

/*
 * w o r d s
 */
#define	nCOLWIDTH	8

static void
ficlPrimitiveWords(ficlVm *vm)
{
	ficlDictionary *dictionary = ficlVmGetDictionary(vm);
	ficlHash *hash = dictionary->wordlists[dictionary->wordlistCount - 1];
	ficlWord *wp;
	int nChars = 0;
	int len;
	unsigned i;
	int nWords = 0;
	char *cp;
	char *pPad;
	int columns;

	cp = getenv("COLUMNS");
	/*
	 * using strtol for now. TODO: refactor number conversion from
	 * ficlPrimitiveToNumber() and use it instead.
	 */
	if (cp == NULL)
		columns = 80;
	else
		columns = strtol(cp, NULL, 0);

	/*
	 * the pad is fixed size area, it's better to allocate
	 * dedicated buffer space to deal with custom terminal sizes.
	 */
	pPad = malloc(columns + 1);
	if (pPad == NULL)
		ficlVmThrowError(vm, "Error: out of memory");

	pager_open();
	for (i = 0; i < hash->size; i++) {
		for (wp = hash->table[i]; wp != NULL; wp = wp->link, nWords++) {
			if (wp->length == 0) /* ignore :noname defs */
				continue;

			/* prevent line wrap due to long words */
			if (nChars + wp->length >= columns) {
				pPad[nChars++] = '\n';
				pPad[nChars] = '\0';
				nChars = 0;
				if (pager_output(pPad))
					goto pager_done;
			}

			cp = wp->name;
			nChars += sprintf(pPad + nChars, "%s", cp);

			if (nChars > columns - 10) {
				pPad[nChars++] = '\n';
				pPad[nChars] = '\0';
				nChars = 0;
				if (pager_output(pPad))
					goto pager_done;
			} else {
				len = nCOLWIDTH - nChars % nCOLWIDTH;
				while (len-- > 0)
					pPad[nChars++] = ' ';
			}

			if (nChars > columns - 10) {
				pPad[nChars++] = '\n';
				pPad[nChars] = '\0';
				nChars = 0;
				if (pager_output(pPad))
					goto pager_done;
			}
		}
	}

	if (nChars > 0) {
		pPad[nChars++] = '\n';
		pPad[nChars] = '\0';
		nChars = 0;
		ficlVmTextOut(vm, pPad);
	}

	sprintf(pPad, "Dictionary: %d words, %ld cells used of %u total\n",
	    nWords, (long)(dictionary->here - dictionary->base),
	    dictionary->size);
	pager_output(pPad);

pager_done:
	free(pPad);
	pager_close();
}

/*
 * l i s t E n v
 * Print symbols defined in the environment
 */
static void
ficlPrimitiveListEnv(ficlVm *vm)
{
	ficlDictionary *dictionary = vm->callback.system->environment;
	ficlHash *hash = dictionary->forthWordlist;
	ficlWord *word;
	unsigned i;
	int counter = 0;

	pager_open();
	for (i = 0; i < hash->size; i++) {
		for (word = hash->table[i]; word != NULL;
		    word = word->link, counter++) {
			sprintf(vm->pad, "%s\n", word->name);
			if (pager_output(vm->pad))
				goto pager_done;
		}
	}

	sprintf(vm->pad, "Environment: %d words, %ld cells used of %u total\n",
	    counter, (long)(dictionary->here - dictionary->base),
	    dictionary->size);
	pager_output(vm->pad);

pager_done:
	pager_close();
}

/*
 * This word lists the parse steps in order
 */
void
ficlPrimitiveParseStepList(ficlVm *vm)
{
	int i;
	ficlSystem *system = vm->callback.system;
	FICL_VM_ASSERT(vm, system);

	ficlVmTextOut(vm, "Parse steps:\n");
	ficlVmTextOut(vm, "lookup\n");

	for (i = 0; i < FICL_MAX_PARSE_STEPS; i++) {
		if (system->parseList[i] != NULL) {
			ficlVmTextOut(vm, system->parseList[i]->name);
			ficlVmTextOut(vm, "\n");
		} else
			break;
	}
}

/*
 * e n v C o n s t a n t
 * Ficl interface to ficlSystemSetEnvironment and ficlSetEnvD - allow Ficl
 * code to set environment constants...
 */
static void
ficlPrimitiveEnvConstant(ficlVm *vm)
{
	unsigned value;
	FICL_STACK_CHECK(vm->dataStack, 1, 0);

	ficlVmGetWordToPad(vm);
	value = ficlStackPopUnsigned(vm->dataStack);
	ficlDictionarySetConstant(ficlSystemGetEnvironment(vm->callback.system),
	    vm->pad, (ficlUnsigned)value);
}

static void
ficlPrimitiveEnv2Constant(ficlVm *vm)
{
	ficl2Integer value;

	FICL_STACK_CHECK(vm->dataStack, 2, 0);

	ficlVmGetWordToPad(vm);
	value = ficlStackPop2Integer(vm->dataStack);
	ficlDictionarySet2Constant(
	    ficlSystemGetEnvironment(vm->callback.system), vm->pad, value);
}


/*
 * f i c l C o m p i l e T o o l s
 * Builds wordset for debugger and TOOLS optional word set
 */
void
ficlSystemCompileTools(ficlSystem *system)
{
	ficlDictionary *dictionary = ficlSystemGetDictionary(system);
	ficlDictionary *environment = ficlSystemGetEnvironment(system);

	FICL_SYSTEM_ASSERT(system, dictionary);
	FICL_SYSTEM_ASSERT(system, environment);


	/*
	 * TOOLS and TOOLS EXT
	 */
	ficlDictionarySetPrimitive(dictionary, ".s", ficlVmDisplayDataStack,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, ".s-simple",
	    ficlVmDisplayDataStackSimple,  FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "bye", ficlPrimitiveBye,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "forget", ficlPrimitiveForget,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "see", ficlPrimitiveSee,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "words", ficlPrimitiveWords,
	    FICL_WORD_DEFAULT);

	/*
	 * Set TOOLS environment query values
	 */
	ficlDictionarySetConstant(environment, "tools", FICL_TRUE);
	ficlDictionarySetConstant(environment, "tools-ext", FICL_FALSE);

	/*
	 * Ficl extras
	 */
	ficlDictionarySetPrimitive(dictionary, "r.s", ficlVmDisplayReturnStack,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, ".env", ficlPrimitiveListEnv,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "env-constant",
	    ficlPrimitiveEnvConstant, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "env-2constant",
	    ficlPrimitiveEnv2Constant, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "debug-xt", ficlPrimitiveDebugXT,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "parse-order",
	    ficlPrimitiveParseStepList, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "step-break",
	    ficlPrimitiveStepBreak, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "forget-wid",
	    ficlPrimitiveForgetWid, FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dictionary, "see-xt", ficlPrimitiveSeeXT,
	    FICL_WORD_DEFAULT);

#if FICL_WANT_FLOAT
	ficlDictionarySetPrimitive(dictionary, ".hash",
	    ficlPrimitiveHashSummary, FICL_WORD_DEFAULT);
#endif
}
