/*
 * p r e f i x . c
 * Forth Inspired Command Language
 * Parser extensions for Ficl
 * Authors: Larry Hastings & John Sadler (john_sadler@alum.mit.edu)
 * Created: April 2001
 * $Id: prefix.c,v 1.8 2010/09/13 18:43:04 asau Exp $
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
 * (jws) revisions:
 * A prefix is a word in a dedicated wordlist (name stored in list_name below)
 * that is searched in a special way by the prefix parse step. When a prefix
 * matches the beginning of an incoming token, push the non-prefix part of the
 * token back onto the input stream and execute the prefix code.
 *
 * The parse step is called ficlParsePrefix.
 * Storing prefix entries in the dictionary greatly simplifies
 * the process of matching and dispatching prefixes, avoids the
 * need to clean up a dynamically allocated prefix list when the system
 * goes away, but still allows prefixes to be allocated at runtime.
 */

static char list_name[] = "<prefixes>";

/*
 * f i c l P a r s e P r e f i x
 * This is the parse step for prefixes - it checks an incoming word
 * to see if it starts with a prefix, and if so runs the corresponding
 * code against the remainder of the word and returns true.
 */
int
ficlVmParsePrefix(ficlVm *vm, ficlString s)
{
	int i;
	ficlHash *hash;
	ficlWord *word = ficlSystemLookup(vm->callback.system, list_name);

	/*
	 * Make sure we found the prefix dictionary - otherwise silently fail
	 * If forth-wordlist is not in the search order, we won't find the
	 * prefixes.
	 */
	if (!word)
		return (0); /* false */

	hash = (ficlHash *)(word->param[0].p);
	/*
	 * Walk the list looking for a match with the beginning of the
	 * incoming token
	 */
	for (i = 0; i < (int)hash->size; i++) {
		word = hash->table[i];
		while (word != NULL) {
			int n;
			n = word->length;
			/*
			 * If we find a match, adjust the TIB to give back
			 * the non-prefix characters and execute the prefix
			 * word.
			 */
			if (!ficlStrincmp(FICL_STRING_GET_POINTER(s),
			    word->name, (ficlUnsigned)n)) {
				/*
				 * (sadler) fixed off-by-one error when the
				 * token has no trailing space in the TIB
				 */
				ficlVmSetTibIndex(vm,
				    s.text + n - vm->tib.text);
				ficlVmExecuteWord(vm, word);

				return (1); /* true */
			}
			word = word->link;
		}
	}

	return (0); /* false */
}

static void
ficlPrimitiveTempBase(ficlVm *vm)
{
	int oldbase = vm->base;
	ficlString number = ficlVmGetWord0(vm);
	int base = ficlStackPopInteger(vm->dataStack);

	vm->base = base;
	if (!ficlVmParseNumber(vm, number))
		ficlVmThrowError(vm, "%.*s not recognized",
		    FICL_STRING_GET_LENGTH(number),
		    FICL_STRING_GET_POINTER(number));

	vm->base = oldbase;
}

/*
 * f i c l C o m p i l e P r e f i x
 * Build prefix support into the dictionary and the parser
 * Note: since prefixes always execute, they are effectively IMMEDIATE.
 * If they need to generate code in compile state you must add
 * this code explicitly.
 */
void
ficlSystemCompilePrefix(ficlSystem *system)
{
	ficlDictionary *dictionary = system->dictionary;
	ficlHash *hash;

	/*
	 * Create a named wordlist for prefixes to reside in...
	 * Since we're doing a special kind of search, make it
	 * a single bucket hashtable - hashing does not help here.
	 */
	hash = ficlDictionaryCreateWordlist(dictionary, 1);
	hash->name = list_name;
	ficlDictionaryAppendConstantPointer(dictionary, list_name, hash);

	/*
	 * Put __tempbase in the forth-wordlist
	 */
	ficlDictionarySetPrimitive(dictionary, "__tempbase",
	    ficlPrimitiveTempBase, FICL_WORD_DEFAULT);

	/*
	 * If you want to add some prefixes at compilation-time, copy this
	 * line to the top of this function:
	 *
	 * ficlHash *oldCompilationWordlist;
	 *
	 * then copy this code to the bottom, just above the return:
	 *
	 *
	 * oldCompilationWordlist = dictionary->compilationWordlist;
	 * dictionary->compilationWordlist = hash;
	 * ficlDictionarySetPrimitive(dictionary, YOUR WORD HERE,
	 * FICL_WORD_DEFAULT);
	 * dictionary->compilationWordlist = oldCompilationWordlist;
	 *
	 * and substitute in your own actual calls to
	 * ficlDictionarySetPrimitive() as needed.
	 *
	 * Or--better yet--do it in your own code, so you don't have
	 * to re-modify the Ficl source code every time we cut a new release!
	 */
}
