/*
 * f i c l . c
 * Forth Inspired Command Language - external interface
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 19 July 1997
 * $Id: system.c,v 1.2 2010/09/10 10:35:54 asau Exp $
 */
/*
 * This is an ANS Forth interpreter written in C.
 * Ficl uses Forth syntax for its commands, but turns the Forth
 * model on its head in other respects.
 * Ficl provides facilities for interoperating
 * with programs written in C: C functions can be exported to Ficl,
 * and Ficl commands can be executed via a C calling interface. The
 * interpreter is re-entrant, so it can be used in multiple instances
 * in a multitasking system. Unlike Forth, Ficl's outer interpreter
 * expects a text block as input, and returns to the caller after each
 * text block, so the data pump is somewhere in external code in the
 * style of TCL.
 *
 * Code is written in ANSI C for portability.
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

/*
 * System statics
 * Each ficlSystem builds a global dictionary during its start
 * sequence. This is shared by all virtual machines of that system.
 * Therefore only one VM can update the dictionary
 * at a time. The system imports a locking function that
 * you can override in order to control update access to
 * the dictionary. The function is stubbed out by default,
 * but you can insert one: #define FICL_WANT_MULTITHREADED 1
 * and supply your own version of ficlDictionaryLock.
 */

ficlSystem *ficlSystemGlobal = NULL;

/*
 * f i c l S e t V e r s i o n E n v
 * Create a double ficlCell environment constant for the version ID
 */
static void
ficlSystemSetVersion(ficlSystem *system)
{
	int major = FICL_VERSION_MAJOR;
	int minor = FICL_VERSION_MINOR;
	ficl2Integer combined;
	ficlDictionary *environment = ficlSystemGetEnvironment(system);
	FICL_2INTEGER_SET(major, minor, combined);
	ficlDictionarySet2Constant(environment, "ficl-version", combined);
	ficlDictionarySetConstant(environment, "ficl-robust",  FICL_ROBUST);
}

/*
 * f i c l I n i t S y s t e m
 * Binds a global dictionary to the interpreter system.
 * You specify the address and size of the allocated area.
 * After that, Ficl manages it.
 * First step is to set up the static pointers to the area.
 * Then write the "precompiled" portion of the dictionary in.
 * The dictionary needs to be at least large enough to hold the
 * precompiled part. Try 1K cells minimum. Use "words" to find
 * out how much of the dictionary is used at any time.
 */
ficlSystem *
ficlSystemCreate(ficlSystemInformation *fsi)
{
	ficlInteger dictionarySize;
	ficlInteger environmentSize;
	ficlInteger stackSize;
	ficlSystem *system;
	ficlCallback callback;
	ficlSystemInformation fauxInfo;
	ficlDictionary *environment;

	if (fsi == NULL) {
		fsi = &fauxInfo;
		ficlSystemInformationInitialize(fsi);
	}

	callback.context = fsi->context;
	callback.textOut = fsi->textOut;
	callback.errorOut = fsi->errorOut;
	callback.system = NULL;
	callback.vm = NULL;

	FICL_ASSERT(&callback, sizeof (ficlInteger) >= sizeof (void *));
	FICL_ASSERT(&callback, sizeof (ficlUnsigned) >= sizeof (void *));
#if (FICL_WANT_FLOAT)
	FICL_ASSERT(&callback, sizeof (ficlFloat) <= sizeof (ficlInteger));
#endif

	system = ficlMalloc(sizeof (ficlSystem));

	FICL_ASSERT(&callback, system);

	memset(system, 0, sizeof (ficlSystem));

	dictionarySize = fsi->dictionarySize;
	if (dictionarySize <= 0)
		dictionarySize = FICL_DEFAULT_DICTIONARY_SIZE;

	environmentSize = fsi->environmentSize;
	if (environmentSize <= 0)
		environmentSize = FICL_DEFAULT_ENVIRONMENT_SIZE;

	stackSize = fsi->stackSize;
	if (stackSize < FICL_DEFAULT_STACK_SIZE)
		stackSize = FICL_DEFAULT_STACK_SIZE;

	system->dictionary = ficlDictionaryCreateHashed(system,
	    (unsigned)dictionarySize, FICL_HASH_SIZE);
	system->dictionary->forthWordlist->name = "forth-wordlist";

	environment = ficlDictionaryCreate(system, (unsigned)environmentSize);
	system->environment = environment;
	system->environment->forthWordlist->name = "environment";

	system->callback.textOut = fsi->textOut;
	system->callback.errorOut = fsi->errorOut;
	system->callback.context = fsi->context;
	system->callback.system = system;
	system->callback.vm = NULL;
	system->stackSize = stackSize;

#if FICL_WANT_LOCALS
	/*
	 * The locals dictionary is only searched while compiling,
	 * but this is where speed is most important. On the other
	 * hand, the dictionary gets emptied after each use of locals
	 * The need to balance search speed with the cost of the 'empty'
	 * operation led me to select a single-threaded list...
	 */
	system->locals = ficlDictionaryCreate(system,
	    (unsigned)FICL_MAX_LOCALS * FICL_CELLS_PER_WORD);
#endif /* FICL_WANT_LOCALS */

	/*
	 * Build the precompiled dictionary and load softwords. We need
	 * a temporary VM to do this - ficlNewVM links one to the head of
	 * the system VM list. ficlCompilePlatform (defined in win32.c,
	 * for example) adds platform specific words.
	 */
	ficlSystemCompileCore(system);
	ficlSystemCompilePrefix(system);

#if FICL_WANT_FLOAT
	ficlSystemCompileFloat(system);
#endif /* FICL_WANT_FLOAT */

#if FICL_WANT_PLATFORM
	ficlSystemCompilePlatform(system);
#endif /* FICL_WANT_PLATFORM */

	ficlSystemSetVersion(system);

	/*
	 * Establish the parse order. Note that prefixes precede numbers -
	 * this allows constructs like "0b101010" which might parse as a
	 * hex value otherwise.
	 */
	ficlSystemAddPrimitiveParseStep(system, "?word", ficlVmParseWord);
	ficlSystemAddPrimitiveParseStep(system, "?prefix", ficlVmParsePrefix);
	ficlSystemAddPrimitiveParseStep(system, "?number", ficlVmParseNumber);
#if FICL_WANT_FLOAT
	ficlSystemAddPrimitiveParseStep(system, "?float",
	    ficlVmParseFloatNumber);
#endif

	/*
	 * Now create a temporary VM to compile the softwords. Since all VMs
	 * are linked into the vmList of ficlSystem, we don't have to pass
	 * the VM to ficlCompileSoftCore -- it just hijacks whatever it finds
	 * in the VM list. Ficl 2.05: vmCreate no longer depends on the
	 * presence of INTERPRET in the dictionary, so a VM can be created
	 * before the dictionary is built. It just can't do much...
	 */
	ficlSystemCreateVm(system);
#define	ADD_COMPILE_FLAG(name)	\
	ficlDictionarySetConstant(environment, #name, name)
	ADD_COMPILE_FLAG(FICL_WANT_LZ4_SOFTCORE);
	ADD_COMPILE_FLAG(FICL_WANT_FILE);
	ADD_COMPILE_FLAG(FICL_WANT_FLOAT);
	ADD_COMPILE_FLAG(FICL_WANT_DEBUGGER);
	ADD_COMPILE_FLAG(FICL_WANT_EXTENDED_PREFIX);
	ADD_COMPILE_FLAG(FICL_WANT_USER);
	ADD_COMPILE_FLAG(FICL_WANT_LOCALS);
	ADD_COMPILE_FLAG(FICL_WANT_OOP);
	ADD_COMPILE_FLAG(FICL_WANT_SOFTWORDS);
	ADD_COMPILE_FLAG(FICL_WANT_MULTITHREADED);
	ADD_COMPILE_FLAG(FICL_WANT_OPTIMIZE);
	ADD_COMPILE_FLAG(FICL_WANT_VCALL);

	ADD_COMPILE_FLAG(FICL_PLATFORM_ALIGNMENT);

	ADD_COMPILE_FLAG(FICL_ROBUST);

#define	ADD_COMPILE_STRING(name)	\
	ficlDictionarySetConstantString(environment, #name, name)
	ADD_COMPILE_STRING(FICL_PLATFORM_ARCHITECTURE);
	ADD_COMPILE_STRING(FICL_PLATFORM_OS);

	ficlSystemCompileSoftCore(system);
	ficlSystemDestroyVm(system->vmList);

	if (ficlSystemGlobal == NULL)
		ficlSystemGlobal = system;

	return (system);
}

/*
 * f i c l T e r m S y s t e m
 * Tear the system down by deleting the dictionaries and all VMs.
 * This saves you from having to keep track of all that stuff.
 */
void
ficlSystemDestroy(ficlSystem *system)
{
	if (system->dictionary)
		ficlDictionaryDestroy(system->dictionary);
	system->dictionary = NULL;

	if (system->environment)
		ficlDictionaryDestroy(system->environment);
	system->environment = NULL;

#if FICL_WANT_LOCALS
	if (system->locals)
		ficlDictionaryDestroy(system->locals);
	system->locals = NULL;
#endif

	while (system->vmList != NULL) {
		ficlVm *vm = system->vmList;
		system->vmList = system->vmList->link;
		ficlVmDestroy(vm);
	}

	if (ficlSystemGlobal == system)
		ficlSystemGlobal = NULL;

	ficlFree(system);
	system = NULL;
}

/*
 * f i c l A d d P a r s e S t e p
 * Appends a parse step function to the end of the parse list (see
 * ficlParseStep notes in ficl.h for details). Returns 0 if successful,
 * nonzero if there's no more room in the list.
 */
int
ficlSystemAddParseStep(ficlSystem *system, ficlWord *word)
{
	int i;
	for (i = 0; i < FICL_MAX_PARSE_STEPS; i++) {
		if (system->parseList[i] == NULL) {
			system->parseList[i] = word;
			return (0);
		}
	}

	return (1);
}

/*
 * Compile a word into the dictionary that invokes the specified ficlParseStep
 * function. It is up to the user (as usual in Forth) to make sure the stack
 * preconditions are valid (there needs to be a counted string on top of the
 * stack) before using the resulting word.
 */
void
ficlSystemAddPrimitiveParseStep(ficlSystem *system, char *name,
    ficlParseStep pStep)
{
	ficlDictionary *dictionary = system->dictionary;
	ficlWord *word;
	ficlCell c;

	word = ficlDictionaryAppendPrimitive(dictionary, name,
	    ficlPrimitiveParseStepParen, FICL_WORD_DEFAULT);

	c.fn = (void (*)(void))pStep;
	ficlDictionaryAppendCell(dictionary, c);
	ficlSystemAddParseStep(system, word);
}

/*
 * f i c l N e w V M
 * Create a new virtual machine and link it into the system list
 * of VMs for later cleanup by ficlTermSystem.
 */
ficlVm *
ficlSystemCreateVm(ficlSystem *system)
{
	ficlVm *vm = ficlVmCreate(NULL, system->stackSize, system->stackSize);
	vm->link = system->vmList;

	memcpy(&(vm->callback), &(system->callback), sizeof (system->callback));
	vm->callback.vm = vm;
	vm->callback.system = system;

	system->vmList = vm;
	return (vm);
}

/*
 * f i c l F r e e V M
 * Removes the VM in question from the system VM list and deletes the
 * memory allocated to it. This is an optional call, since ficlTermSystem
 * will do this cleanup for you. This function is handy if you're going to
 * do a lot of dynamic creation of VMs.
 */
void
ficlSystemDestroyVm(ficlVm *vm)
{
	ficlSystem *system = vm->callback.system;
	ficlVm *pList = system->vmList;

	FICL_VM_ASSERT(vm, vm != NULL);

	if (system->vmList == vm) {
		system->vmList = system->vmList->link;
	} else
		for (; pList != NULL; pList = pList->link) {
			if (pList->link == vm) {
				pList->link = vm->link;
				break;
			}
		}

	if (pList)
		ficlVmDestroy(vm);
}

/*
 * f i c l L o o k u p
 * Look in the system dictionary for a match to the given name. If
 * found, return the address of the corresponding ficlWord. Otherwise
 * return NULL.
 */
ficlWord *
ficlSystemLookup(ficlSystem *system, char *name)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);
	return (ficlDictionaryLookup(system->dictionary, s));
}

/*
 * f i c l G e t D i c t
 * Returns the address of the system dictionary
 */
ficlDictionary *
ficlSystemGetDictionary(ficlSystem *system)
{
	return (system->dictionary);
}

/*
 * f i c l G e t E n v
 * Returns the address of the system environment space
 */
ficlDictionary *
ficlSystemGetEnvironment(ficlSystem *system)
{
	return (system->environment);
}

/*
 * f i c l G e t L o c
 * Returns the address of the system locals dictionary. This dictionary is
 * only used during compilation, and is shared by all VMs.
 */
#if FICL_WANT_LOCALS
ficlDictionary *
ficlSystemGetLocals(ficlSystem *system)
{
	return (system->locals);
}
#endif

/*
 * f i c l L o o k u p L o c
 * Same as dictLookup, but looks in system locals dictionary first...
 * Assumes locals dictionary has only one wordlist...
 */
#if FICL_WANT_LOCALS
ficlWord *
ficlSystemLookupLocal(ficlSystem *system, ficlString name)
{
	ficlWord *word = NULL;
	ficlDictionary *dictionary = system->dictionary;
	ficlHash *hash = ficlSystemGetLocals(system)->forthWordlist;
	int i;
	ficlUnsigned16 hashCode = ficlHashCode(name);

	FICL_SYSTEM_ASSERT(system, hash);
	FICL_SYSTEM_ASSERT(system, dictionary);

	ficlDictionaryLock(dictionary, FICL_TRUE);
	/*
	 * check the locals dictionary first...
	 */
	word = ficlHashLookup(hash, name, hashCode);

	/*
	 * If no joy, (!word) ------------------------------v
	 * iterate over the search list in the main dictionary
	 */
	for (i = (int)dictionary->wordlistCount - 1; (i >= 0) && (!word); --i) {
		hash = dictionary->wordlists[i];
		word = ficlHashLookup(hash, name, hashCode);
	}

	ficlDictionaryLock(dictionary, FICL_FALSE);
	return (word);
}
#endif
