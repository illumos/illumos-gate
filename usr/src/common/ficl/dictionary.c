/*
 * d i c t . c
 * Forth Inspired Command Language - dictionary methods
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 19 July 1997
 * $Id: dictionary.c,v 1.2 2010/09/12 15:14:52 asau Exp $
 */
/*
 * This file implements the dictionary -- Ficl's model of
 * memory management. All Ficl words are stored in the
 * dictionary. A word is a named chunk of data with its
 * associated code. Ficl treats all words the same, even
 * precompiled ones, so your words become first-class
 * extensions of the language. You can even define new
 * control structures.
 *
 * 29 jun 1998 (sadler) added variable sized hash table support
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

#define	FICL_SAFE_CALLBACK_FROM_SYSTEM(system)		\
	(((system) != NULL) ? &((system)->callback) : NULL)
#define	FICL_SAFE_SYSTEM_FROM_DICTIONARY(dictionary)	\
	(((dictionary) != NULL) ? (dictionary)->system : NULL)
#define	FICL_DICTIONARY_ASSERT(dictionary, expression)	\
	FICL_SYSTEM_ASSERT(FICL_SAFE_SYSTEM_FROM_DICTIONARY(dictionary), \
	expression)

/*
 * d i c t A b o r t D e f i n i t i o n
 * Abort a definition in process: reclaim its memory and unlink it
 * from the dictionary list. Assumes that there is a smudged
 * definition in process...otherwise does nothing.
 * NOTE: this function is not smart enough to unlink a word that
 * has been successfully defined (ie linked into a hash). It
 * only works for defs in process. If the def has been unsmudged,
 * nothing happens.
 */
void
ficlDictionaryAbortDefinition(ficlDictionary *dictionary)
{
	ficlWord *word;
	ficlDictionaryLock(dictionary, FICL_TRUE);
	word = dictionary->smudge;

	if (word->flags & FICL_WORD_SMUDGED)
		dictionary->here = (ficlCell *)word->name;

	ficlDictionaryLock(dictionary, FICL_FALSE);
}

/*
 * d i c t A l i g n
 * Align the dictionary's free space pointer
 */
void
ficlDictionaryAlign(ficlDictionary *dictionary)
{
	dictionary->here = ficlAlignPointer(dictionary->here);
}

/*
 * d i c t A l l o t
 * Allocate or remove n chars of dictionary space, with
 * checks for underrun and overrun
 */
void
ficlDictionaryAllot(ficlDictionary *dictionary, int n)
{
	char *here = (char *)dictionary->here;
	here += n;
	dictionary->here = FICL_POINTER_TO_CELL(here);
}

/*
 * d i c t A l l o t C e l l s
 * Reserve space for the requested number of ficlCells in the
 * dictionary. If nficlCells < 0 , removes space from the dictionary.
 */
void
ficlDictionaryAllotCells(ficlDictionary *dictionary, int nficlCells)
{
	dictionary->here += nficlCells;
}

/*
 * d i c t A p p e n d C e l l
 * Append the specified ficlCell to the dictionary
 */
void
ficlDictionaryAppendCell(ficlDictionary *dictionary, ficlCell c)
{
	*dictionary->here++ = c;
}

/*
 * d i c t A p p e n d C h a r
 * Append the specified char to the dictionary
 */
void
ficlDictionaryAppendCharacter(ficlDictionary *dictionary, char c)
{
	char *here = (char *)dictionary->here;
	*here++ = c;
	dictionary->here = FICL_POINTER_TO_CELL(here);
}

/*
 * d i c t A p p e n d U N S
 * Append the specified ficlUnsigned to the dictionary
 */
void
ficlDictionaryAppendUnsigned(ficlDictionary *dictionary, ficlUnsigned u)
{
	ficlCell c;

	c.u = u;
	ficlDictionaryAppendCell(dictionary, c);
}

void *
ficlDictionaryAppendData(ficlDictionary *dictionary, void *data,
    ficlInteger length)
{
	char *here = (char *)dictionary->here;
	char *oldHere = here;
	char *from = (char *)data;

	if (length == 0) {
		ficlDictionaryAlign(dictionary);
		return ((char *)dictionary->here);
	}

	while (length) {
		*here++ = *from++;
		length--;
	}

	*here++ = '\0';

	dictionary->here = FICL_POINTER_TO_CELL(here);
	ficlDictionaryAlign(dictionary);
	return (oldHere);
}

/*
 * d i c t C o p y N a m e
 * Copy up to FICL_NAME_LENGTH characters of the name specified by s into
 * the dictionary starting at "here", then NULL-terminate the name,
 * point "here" to the next available byte, and return the address of
 * the beginning of the name. Used by dictAppendWord.
 * N O T E S :
 * 1. "here" is guaranteed to be aligned after this operation.
 * 2. If the string has zero length, align and return "here"
 */
char *
ficlDictionaryAppendString(ficlDictionary *dictionary, ficlString s)
{
	void *data = FICL_STRING_GET_POINTER(s);
	ficlInteger length = FICL_STRING_GET_LENGTH(s);

	if (length > FICL_NAME_LENGTH)
		length = FICL_NAME_LENGTH;

	return (ficlDictionaryAppendData(dictionary, data, length));
}

ficlWord *
ficlDictionaryAppendConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficlInteger value)
{
	ficlWord *word = ficlDictionaryAppendWord(dictionary, name,
	    (ficlPrimitive)instruction, FICL_WORD_DEFAULT);

	if (word != NULL)
		ficlDictionaryAppendUnsigned(dictionary, value);
	return (word);
}

ficlWord *
ficlDictionaryAppend2ConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficl2Integer value)
{
	ficlWord *word = ficlDictionaryAppendWord(dictionary, name,
	    (ficlPrimitive)instruction, FICL_WORD_DEFAULT);

	if (word != NULL) {
		ficlDictionaryAppendUnsigned(dictionary,
		    FICL_2UNSIGNED_GET_HIGH(value));
		ficlDictionaryAppendUnsigned(dictionary,
		    FICL_2UNSIGNED_GET_LOW(value));
	}
	return (word);
}

ficlWord *
ficlDictionaryAppendConstant(ficlDictionary *dictionary, char *name,
    ficlInteger value)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);
	return (ficlDictionaryAppendConstantInstruction(dictionary, s,
	    ficlInstructionConstantParen, value));
}

ficlWord *
ficlDictionaryAppend2Constant(ficlDictionary *dictionary, char *name,
    ficl2Integer value)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);
	return (ficlDictionaryAppend2ConstantInstruction(dictionary, s,
	    ficlInstruction2ConstantParen, value));
}

ficlWord *
ficlDictionarySetConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficlInteger value)
{
	ficlWord *word = ficlDictionaryLookup(dictionary, name);
	ficlCell c;

	if (word == NULL) {
		word = ficlDictionaryAppendConstantInstruction(dictionary,
		    name, instruction, value);
	} else {
		word->code = (ficlPrimitive)instruction;
		c.i = value;
		word->param[0] = c;
	}
	return (word);
}

ficlWord *
ficlDictionarySetConstant(ficlDictionary *dictionary, char *name,
    ficlInteger value)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);
	return (ficlDictionarySetConstantInstruction(dictionary, s,
	    ficlInstructionConstantParen, value));
}

ficlWord *
ficlDictionarySet2ConstantInstruction(ficlDictionary *dictionary, ficlString s,
    ficlInstruction instruction, ficl2Integer value)
{
	ficlWord *word;
	word = ficlDictionaryLookup(dictionary, s);

	/*
	 * only reuse the existing word if we're sure it has space for a
	 * 2constant
	 */
#if FICL_WANT_FLOAT
	if ((word != NULL) &&
	    ((((ficlInstruction)word->code) == ficlInstruction2ConstantParen) ||
	    (((ficlInstruction)word->code) == ficlInstructionF2ConstantParen)))
#else
	if ((word != NULL) &&
	    ((((ficlInstruction)word->code) == ficlInstruction2ConstantParen)))
#endif /* FICL_WANT_FLOAT */
	{
		word->code = (ficlPrimitive)instruction;
		word->param[0].u = FICL_2UNSIGNED_GET_HIGH(value);
		word->param[1].u = FICL_2UNSIGNED_GET_LOW(value);
	} else {
		word = ficlDictionaryAppend2ConstantInstruction(dictionary, s,
		    instruction, value);
	}

	return (word);
}

ficlWord *
ficlDictionarySet2Constant(ficlDictionary *dictionary, char *name,
    ficl2Integer value)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);

	return (ficlDictionarySet2ConstantInstruction(dictionary, s,
	    ficlInstruction2ConstantParen, value));
}

ficlWord *
ficlDictionarySetConstantString(ficlDictionary *dictionary, char *name,
    char *value)
{
	ficlString s;
	ficl2Integer valueAs2Integer;
	FICL_2INTEGER_SET(strlen(value), (intptr_t)value, valueAs2Integer);
	FICL_STRING_SET_FROM_CSTRING(s, name);

	return (ficlDictionarySet2ConstantInstruction(dictionary, s,
	    ficlInstruction2ConstantParen, valueAs2Integer));
}

/*
 * d i c t A p p e n d W o r d
 * Create a new word in the dictionary with the specified
 * ficlString, code, and flags. Does not require a NULL-terminated
 * name.
 */
ficlWord *
ficlDictionaryAppendWord(ficlDictionary *dictionary, ficlString name,
    ficlPrimitive code, ficlUnsigned8 flags)
{
	ficlUnsigned8 length = (ficlUnsigned8)FICL_STRING_GET_LENGTH(name);
	char *nameCopy;
	ficlWord *word;

	ficlDictionaryLock(dictionary, FICL_TRUE);

	/*
	 * NOTE: ficlDictionaryAppendString advances "here" as a side-effect.
	 * It must execute before word is initialized.
	 */
	nameCopy = ficlDictionaryAppendString(dictionary, name);
	word = (ficlWord *)dictionary->here;
	dictionary->smudge = word;
	word->hash = ficlHashCode(name);
	word->code = code;
	word->semiParen = ficlInstructionSemiParen;
	word->flags = (ficlUnsigned8)(flags | FICL_WORD_SMUDGED);
	word->length = length;
	word->name = nameCopy;

	/*
	 * Point "here" to first ficlCell of new word's param area...
	 */
	dictionary->here = word->param;

	if (!(flags & FICL_WORD_SMUDGED))
		ficlDictionaryUnsmudge(dictionary);

	ficlDictionaryLock(dictionary, FICL_FALSE);
	return (word);
}

/*
 * d i c t A p p e n d W o r d
 * Create a new word in the dictionary with the specified
 * name, code, and flags. Name must be NULL-terminated.
 */
ficlWord *
ficlDictionaryAppendPrimitive(ficlDictionary *dictionary, char *name,
    ficlPrimitive code, ficlUnsigned8 flags)
{
	ficlString s;
	FICL_STRING_SET_FROM_CSTRING(s, name);

	return (ficlDictionaryAppendWord(dictionary, s, code, flags));
}

ficlWord *
ficlDictionarySetPrimitive(ficlDictionary *dictionary, char *name,
    ficlPrimitive code, ficlUnsigned8 flags)
{
	ficlString s;
	ficlWord *word;

	FICL_STRING_SET_FROM_CSTRING(s, name);
	word = ficlDictionaryLookup(dictionary, s);

	if (word == NULL) {
		word = ficlDictionaryAppendPrimitive(dictionary, name,
		    code, flags);
	} else {
		word->code = (ficlPrimitive)code;
		word->flags = flags;
	}
	return (word);
}

ficlWord *
ficlDictionaryAppendInstruction(ficlDictionary *dictionary, char *name,
    ficlInstruction i, ficlUnsigned8 flags)
{
	return (ficlDictionaryAppendPrimitive(dictionary, name,
	    (ficlPrimitive)i, (ficlUnsigned8)(FICL_WORD_INSTRUCTION | flags)));
}

ficlWord *
ficlDictionarySetInstruction(ficlDictionary *dictionary, char *name,
    ficlInstruction i, ficlUnsigned8 flags)
{
	return (ficlDictionarySetPrimitive(dictionary, name,
	    (ficlPrimitive)i, (ficlUnsigned8)(FICL_WORD_INSTRUCTION | flags)));
}

/*
 * d i c t C e l l s A v a i l
 * Returns the number of empty ficlCells left in the dictionary
 */
int
ficlDictionaryCellsAvailable(ficlDictionary *dictionary)
{
	return (dictionary->size - ficlDictionaryCellsUsed(dictionary));
}

/*
 * d i c t C e l l s U s e d
 * Returns the number of ficlCells consumed in the dicionary
 */
int
ficlDictionaryCellsUsed(ficlDictionary *dictionary)
{
	return (dictionary->here - dictionary->base);
}

/*
 * d i c t C r e a t e
 * Create and initialize a dictionary with the specified number
 * of ficlCells capacity, and no hashing (hash size == 1).
 */
ficlDictionary *
ficlDictionaryCreate(ficlSystem *system, unsigned size)
{
	return (ficlDictionaryCreateHashed(system, size, 1));
}

ficlDictionary *
ficlDictionaryCreateHashed(ficlSystem *system, unsigned size,
    unsigned bucketCount)
{
	ficlDictionary *dictionary;
	size_t nAlloc;

	nAlloc =  sizeof (ficlDictionary) + (size * sizeof (ficlCell))
	    + sizeof (ficlHash) + (bucketCount - 1) * sizeof (ficlWord *);

	dictionary = ficlMalloc(nAlloc);
	FICL_SYSTEM_ASSERT(system, dictionary != NULL);

	dictionary->size = size;
	dictionary->system = system;

	ficlDictionaryEmpty(dictionary, bucketCount);
	return (dictionary);
}

/*
 * d i c t C r e a t e W o r d l i s t
 * Create and initialize an anonymous wordlist
 */
ficlHash *
ficlDictionaryCreateWordlist(ficlDictionary *dictionary, int bucketCount)
{
	ficlHash *hash;

	ficlDictionaryAlign(dictionary);
	hash = (ficlHash *)dictionary->here;
	ficlDictionaryAllot(dictionary,
	    sizeof (ficlHash) + (bucketCount - 1) * sizeof (ficlWord *));

	hash->size = bucketCount;
	ficlHashReset(hash);
	return (hash);
}

/*
 * d i c t D e l e t e
 * Free all memory allocated for the given dictionary
 */
void
ficlDictionaryDestroy(ficlDictionary *dictionary)
{
	FICL_DICTIONARY_ASSERT(dictionary, dictionary != NULL);
	ficlFree(dictionary);
}

/*
 * d i c t E m p t y
 * Empty the dictionary, reset its hash table, and reset its search order.
 * Clears and (re-)creates the hash table with the size specified by nHash.
 */
void
ficlDictionaryEmpty(ficlDictionary *dictionary, unsigned bucketCount)
{
	ficlHash *hash;

	dictionary->here = dictionary->base;

	ficlDictionaryAlign(dictionary);
	hash = (ficlHash *)dictionary->here;
	ficlDictionaryAllot(dictionary,
	    sizeof (ficlHash) + (bucketCount - 1) * sizeof (ficlWord *));

	hash->size = bucketCount;
	ficlHashReset(hash);

	dictionary->forthWordlist = hash;
	dictionary->smudge = NULL;
	ficlDictionaryResetSearchOrder(dictionary);
}

/*
 * i s A F i c l W o r d
 * Vet a candidate pointer carefully to make sure
 * it's not some chunk o' inline data...
 * It has to have a name, and it has to look
 * like it's in the dictionary address range.
 * NOTE: this excludes :noname words!
 */
int
ficlDictionaryIsAWord(ficlDictionary *dictionary, ficlWord *word)
{
	if ((((ficlInstruction)word) > ficlInstructionInvalid) &&
	    (((ficlInstruction)word) < ficlInstructionLast))
		return (1);

	if (!ficlDictionaryIncludes(dictionary, word))
		return (0);

	if (!ficlDictionaryIncludes(dictionary, word->name))
		return (0);

	if ((word->link != NULL) &&
	    !ficlDictionaryIncludes(dictionary, word->link))
		return (0);

	if ((word->length <= 0) || (word->name[word->length] != '\0'))
		return (0);

	if (strlen(word->name) != word->length)
		return (0);

	return (1);
}

/*
 * f i n d E n c l o s i n g W o r d
 * Given a pointer to something, check to make sure it's an address in the
 * dictionary. If so, search backwards until we find something that looks
 * like a dictionary header. If successful, return the address of the
 * ficlWord found. Otherwise return NULL. nSEARCH_CELLS sets the maximum
 * neighborhood this func will search before giving up
 */
#define	nSEARCH_CELLS	100

ficlWord *
ficlDictionaryFindEnclosingWord(ficlDictionary *dictionary, ficlCell *cell)
{
	ficlWord *word;
	int i;

	if (!ficlDictionaryIncludes(dictionary, (void *)cell))
		return (NULL);

	for (i = nSEARCH_CELLS; i > 0; --i, --cell) {
		word = (ficlWord *)
		    (cell + 1 - (sizeof (ficlWord) / sizeof (ficlCell)));
		if (ficlDictionaryIsAWord(dictionary, word))
			return (word);
	}

	return (NULL);
}

/*
 * d i c t I n c l u d e s
 * Returns FICL_TRUE iff the given pointer is within the address range of
 * the dictionary.
 */
int
ficlDictionaryIncludes(ficlDictionary *dictionary, void *p)
{
	return ((p >= (void *) &dictionary->base) &&
	    (p <  (void *)(&dictionary->base + dictionary->size)));
}

/*
 * d i c t L o o k u p
 * Find the ficlWord that matches the given name and length.
 * If found, returns the word's address. Otherwise returns NULL.
 * Uses the search order list to search multiple wordlists.
 */
ficlWord *
ficlDictionaryLookup(ficlDictionary *dictionary, ficlString name)
{
	ficlWord *word = NULL;
	ficlHash *hash;
	int i;
	ficlUnsigned16 hashCode = ficlHashCode(name);

	FICL_DICTIONARY_ASSERT(dictionary, dictionary != NULL);

	ficlDictionaryLock(dictionary, FICL_TRUE);

	for (i = (int)dictionary->wordlistCount - 1; (i >= 0) && (!word); --i) {
		hash = dictionary->wordlists[i];
		word = ficlHashLookup(hash, name, hashCode);
	}

	ficlDictionaryLock(dictionary, FICL_FALSE);
	return (word);
}

/*
 * s e e
 * TOOLS ( "<spaces>name" -- )
 * Display a human-readable representation of the named word's definition.
 * The source of the representation (object-code decompilation, source
 * block, etc.) and the particular form of the display is implementation
 * defined.
 */
/*
 * ficlSeeColon (for proctologists only)
 * Walks a colon definition, decompiling
 * on the fly. Knows about primitive control structures.
 */
char *ficlDictionaryInstructionNames[] =
{
#define	FICL_TOKEN(token, description)	description,
#define	FICL_INSTRUCTION_TOKEN(token, description, flags)	description,
#include "ficltokens.h"
#undef FICL_TOKEN
#undef FICL_INSTRUCTION_TOKEN
};

void
ficlDictionarySee(ficlDictionary *dictionary, ficlWord *word,
    ficlCallback *callback)
{
	char *trace;
	ficlCell *cell = word->param;
	ficlCell *param0 = cell;
	char buffer[128];

	for (; cell->i != ficlInstructionSemiParen; cell++) {
		ficlWord *word = (ficlWord *)(cell->p);

		trace = buffer;
		if ((void *)cell == (void *)buffer)
			*trace++ = '>';
		else
			*trace++ = ' ';
		trace += sprintf(trace, "%3ld   ", (long)(cell - param0));

		if (ficlDictionaryIsAWord(dictionary, word)) {
			ficlWordKind kind = ficlWordClassify(word);
			ficlCell c, c2;

			switch (kind) {
			case FICL_WORDKIND_INSTRUCTION:
				sprintf(trace, "%s (instruction %ld)",
				    ficlDictionaryInstructionNames[(long)word],
				    (long)word);
			break;
			case FICL_WORDKIND_INSTRUCTION_WITH_ARGUMENT:
				c = *++cell;
				sprintf(trace, "%s (instruction %ld), with "
				    "argument %ld (%#lx)",
				    ficlDictionaryInstructionNames[(long)word],
				    (long)word, (long)c.i, (unsigned long)c.u);
			break;
			case FICL_WORDKIND_INSTRUCTION_WORD:
				sprintf(trace,
				    "%s :: executes %s (instruction word %ld)",
				    word->name,
				    ficlDictionaryInstructionNames[
				    (long)word->code], (long)word->code);
			break;
			case FICL_WORDKIND_LITERAL:
				c = *++cell;
				if (ficlDictionaryIsAWord(dictionary, c.p) &&
				    (c.i >= ficlInstructionLast)) {
					ficlWord *word = (ficlWord *)c.p;
					sprintf(trace, "%.*s ( %#lx literal )",
					    word->length, word->name,
					    (unsigned long)c.u);
				} else
					sprintf(trace,
					    "literal %ld (%#lx)", (long)c.i,
					    (unsigned long)c.u);
			break;
			case FICL_WORDKIND_2LITERAL:
				c = *++cell;
				c2 = *++cell;
				sprintf(trace, "2literal %ld %ld (%#lx %#lx)",
				    (long)c2.i, (long)c.i, (unsigned long)c2.u,
				    (unsigned long)c.u);
			break;
#if FICL_WANT_FLOAT
			case FICL_WORDKIND_FLITERAL:
				c = *++cell;
				sprintf(trace, "fliteral %f (%#lx)",
				    (double)c.f, (unsigned long)c.u);
			break;
#endif /* FICL_WANT_FLOAT */
			case FICL_WORDKIND_STRING_LITERAL: {
				ficlCountedString *counted;
				counted = (ficlCountedString *)(void *)++cell;
				cell = (ficlCell *)
				    ficlAlignPointer(counted->text +
				    counted->length + 1) - 1;
				sprintf(trace, "s\" %.*s\"", counted->length,
				    counted->text);
			}
			break;
			case FICL_WORDKIND_CSTRING_LITERAL: {
				ficlCountedString *counted;
				counted = (ficlCountedString *)(void *)++cell;
				cell = (ficlCell *)
				    ficlAlignPointer(counted->text +
				    counted->length + 1) - 1;
				sprintf(trace, "c\" %.*s\"", counted->length,
				    counted->text);
			}
			break;
			case FICL_WORDKIND_BRANCH0:
				c = *++cell;
				sprintf(trace, "branch0 %ld",
				    (long)(cell + c.i - param0));
			break;
			case FICL_WORDKIND_BRANCH:
				c = *++cell;
				sprintf(trace, "branch %ld",
				    (long)(cell + c.i - param0));
			break;

			case FICL_WORDKIND_QDO:
				c = *++cell;
				sprintf(trace, "?do (leave %ld)",
				    (long)((ficlCell *)c.p - param0));
			break;
			case FICL_WORDKIND_DO:
				c = *++cell;
				sprintf(trace, "do (leave %ld)",
				    (long)((ficlCell *)c.p - param0));
			break;
			case FICL_WORDKIND_LOOP:
				c = *++cell;
				sprintf(trace, "loop (branch %ld)",
				    (long)(cell + c.i - param0));
			break;
			case FICL_WORDKIND_OF:
				c = *++cell;
				sprintf(trace, "of (branch %ld)",
				    (long)(cell + c.i - param0));
			break;
			case FICL_WORDKIND_PLOOP:
				c = *++cell;
				sprintf(trace, "+loop (branch %ld)",
				    (long)(cell + c.i - param0));
			break;
			default:
				sprintf(trace, "%.*s", word->length,
				    word->name);
			break;
			}
		} else {
			/* probably not a word - punt and print value */
			sprintf(trace, "%ld ( %#lx )", (long)cell->i,
			    (unsigned long)cell->u);
		}

		ficlCallbackTextOut(callback, buffer);
		ficlCallbackTextOut(callback, "\n");
	}

	ficlCallbackTextOut(callback, ";\n");
}

/*
 * d i c t R e s e t S e a r c h O r d e r
 * Initialize the dictionary search order list to sane state
 */
void
ficlDictionaryResetSearchOrder(ficlDictionary *dictionary)
{
	FICL_DICTIONARY_ASSERT(dictionary, dictionary);
	dictionary->compilationWordlist = dictionary->forthWordlist;
	dictionary->wordlistCount = 1;
	dictionary->wordlists[0] = dictionary->forthWordlist;
}

/*
 * d i c t S e t F l a g s
 * Changes the flags field of the most recently defined word:
 * Set all bits that are ones in the set parameter.
 */
void
ficlDictionarySetFlags(ficlDictionary *dictionary, ficlUnsigned8 set)
{
	FICL_DICTIONARY_ASSERT(dictionary, dictionary->smudge);
	dictionary->smudge->flags |= set;
}


/*
 * d i c t C l e a r F l a g s
 * Changes the flags field of the most recently defined word:
 * Clear all bits that are ones in the clear parameter.
 */
void
ficlDictionaryClearFlags(ficlDictionary *dictionary, ficlUnsigned8 clear)
{
	FICL_DICTIONARY_ASSERT(dictionary, dictionary->smudge);
	dictionary->smudge->flags &= ~clear;
}

/*
 * d i c t S e t I m m e d i a t e
 * Set the most recently defined word as IMMEDIATE
 */
void
ficlDictionarySetImmediate(ficlDictionary *dictionary)
{
	FICL_DICTIONARY_ASSERT(dictionary, dictionary->smudge);
	dictionary->smudge->flags |= FICL_WORD_IMMEDIATE;
}

/*
 * d i c t U n s m u d g e
 * Completes the definition of a word by linking it
 * into the main list
 */
void
ficlDictionaryUnsmudge(ficlDictionary *dictionary)
{
	ficlWord *word = dictionary->smudge;
	ficlHash *hash = dictionary->compilationWordlist;

	FICL_DICTIONARY_ASSERT(dictionary, hash);
	FICL_DICTIONARY_ASSERT(dictionary, word);

	/*
	 * :noname words never get linked into the list...
	 */
	if (word->length > 0)
		ficlHashInsertWord(hash, word);
	word->flags &= ~(FICL_WORD_SMUDGED);
}

/*
 * d i c t W h e r e
 * Returns the value of the HERE pointer -- the address
 * of the next free ficlCell in the dictionary
 */
ficlCell *
ficlDictionaryWhere(ficlDictionary *dictionary)
{
	return (dictionary->here);
}
