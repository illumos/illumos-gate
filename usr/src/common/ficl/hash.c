#include "ficl.h"

#define	FICL_ASSERT_PHASH(hash, expression)	FICL_ASSERT(NULL, expression)

/*
 * h a s h F o r g e t
 * Unlink all words in the hash that have addresses greater than or
 * equal to the address supplied. Implementation factor for FORGET
 * and MARKER.
 */
void
ficlHashForget(ficlHash *hash, void *where)
{
	ficlWord *pWord;
	unsigned i;

	FICL_ASSERT_PHASH(hash, hash);
	FICL_ASSERT_PHASH(hash, where);

	for (i = 0; i < hash->size; i++) {
		pWord = hash->table[i];

		while ((void *)pWord >= where) {
			pWord = pWord->link;
		}

		hash->table[i] = pWord;
	}
}

/*
 * h a s h H a s h C o d e
 *
 * Generate a 16 bit hashcode from a character string using a rolling
 * shift and add stolen from PJ Weinberger of Bell Labs fame. Case folds
 * the name before hashing it...
 * N O T E : If string has zero length, returns zero.
 */
ficlUnsigned16
ficlHashCode(ficlString s)
{
	/* hashPJW */
	ficlUnsigned8 *trace;
	ficlUnsigned16 code = (ficlUnsigned16)s.length;
	ficlUnsigned16 shift = 0;

	if (s.length == 0)
		return (0);

	/* changed to run without errors under Purify -- lch */
	for (trace = (ficlUnsigned8 *)s.text;
	    s.length && *trace; trace++, s.length--) {
		code = (ficlUnsigned16)((code << 4) + tolower(*trace));
		shift = (ficlUnsigned16)(code & 0xf000);
		if (shift) {
			code ^= (ficlUnsigned16)(shift >> 8);
			code ^= (ficlUnsigned16)shift;
		}
	}

	return ((ficlUnsigned16)code);
}

/*
 * h a s h I n s e r t W o r d
 * Put a word into the hash table using the word's hashcode as
 * an index (modulo the table size).
 */
void
ficlHashInsertWord(ficlHash *hash, ficlWord *word)
{
	ficlWord **pList;

	FICL_ASSERT_PHASH(hash, hash);
	FICL_ASSERT_PHASH(hash, word);

	if (hash->size == 1) {
		pList = hash->table;
	} else {
		pList = hash->table + (word->hash % hash->size);
	}

	word->link = *pList;
	*pList = word;
}

/*
 * h a s h L o o k u p
 * Find a name in the hash table given the hashcode and text of the name.
 * Returns the address of the corresponding ficlWord if found,
 * otherwise NULL.
 * Note: outer loop on link field supports inheritance in wordlists.
 * It's not part of ANS Forth - Ficl only. hashReset creates wordlists
 * with NULL link fields.
 */
ficlWord *
ficlHashLookup(ficlHash *hash, ficlString name, ficlUnsigned16 hashCode)
{
	ficlUnsigned nCmp = name.length;
	ficlWord *word;
	ficlUnsigned16 hashIdx;

	if (nCmp > FICL_NAME_LENGTH)
		nCmp = FICL_NAME_LENGTH;

	for (; hash != NULL; hash = hash->link) {
		if (hash->size > 1)
			hashIdx = (ficlUnsigned16)(hashCode % hash->size);
		else /* avoid the modulo op for single threaded lists */
			hashIdx = 0;

		for (word = hash->table[hashIdx]; word; word = word->link) {
			if ((word->length == name.length) &&
			    (!ficlStrincmp(name.text, word->name, nCmp)))
				return (word);
#if FICL_ROBUST
			FICL_ASSERT_PHASH(hash, word != word->link);
#endif
		}
	}

	return (NULL);
}

/*
 * h a s h R e s e t
 * Initialize a ficlHash to empty state.
 */
void
ficlHashReset(ficlHash *hash)
{
	unsigned i;

	FICL_ASSERT_PHASH(hash, hash);

	for (i = 0; i < hash->size; i++) {
		hash->table[i] = NULL;
	}

	hash->link = NULL;
	hash->name = NULL;
}
