/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "keytab.h"
#include "strngmem.h"
#include "getline.h"
#include "errmsg.h"
#include "hash.h"

/*
 * When allocating or reallocating the key-binding table, how
 * many entries should be added?
 */
#define KT_TABLE_INC 100

/*
 * Define the size of the hash table that is used to associate action
 * names with action functions. This should be a prime number.
 */
#define KT_HASH_SIZE 113

/*
 * Define a binary-symbol-table object.
 */
struct KeyTab {
  ErrMsg *err;            /* Information about the last error */
  int size;               /* The allocated dimension of table[] */
  int nkey;               /* The current number of members in the table */
  KeySym *table;          /* The table of lexically sorted key sequences */
  HashTable *actions;     /* The hash table of actions */
  StringMem *smem;        /* Memory for allocating strings */
};

static int _kt_extend_table(KeyTab *kt);
static int _kt_parse_keybinding_string(const char *keyseq,
				       char *binary, int *nc);
static int _kt_compare_strings(const char *s1, int n1, const char *s2, int n2);
static void _kt_assign_action(KeySym *sym, KtBinder binder, KtKeyFn *keyfn,
			      void *data);
static char _kt_backslash_escape(const char *string, const char **endp);
static int _kt_is_emacs_meta(const char *string);
static int _kt_is_emacs_ctrl(const char *string);
static KtKeyMatch _kt_locate_keybinding(KeyTab *kt, const char *binary_keyseq,
					int nc, int *first, int *last);

/*.......................................................................
 * Create a new key-binding symbol table.
 *
 * Output:
 *  return  KeyTab *  The new object, or NULL on error.
 */
KeyTab *_new_KeyTab(void)
{
  KeyTab *kt;  /* The object to be returned */
/*
 * Allocate the container.
 */
  kt = (KeyTab *) malloc(sizeof(KeyTab));
  if(!kt) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_KeyTab().
 */
  kt->err = NULL;
  kt->size = KT_TABLE_INC;
  kt->nkey = 0;
  kt->table = NULL;
  kt->actions = NULL;
  kt->smem = NULL;
/*
 * Allocate a place to record error messages.
 */
  kt->err = _new_ErrMsg();
  if(!kt->err)
    return _del_KeyTab(kt);
/*
 * Allocate the table.
 */
  kt->table = (KeySym *) malloc(sizeof(kt->table[0]) * kt->size);
  if(!kt->table) {
    errno = ENOMEM;
    return _del_KeyTab(kt);
  };
/*
 * Allocate a hash table of actions.
 */
  kt->actions = _new_HashTable(NULL, KT_HASH_SIZE, IGNORE_CASE, NULL, 0);
  if(!kt->actions)
    return _del_KeyTab(kt);
/*
 * Allocate a string allocation object. This allows allocation of
 * small strings without fragmenting the heap.
 */
  kt->smem = _new_StringMem(KT_TABLE_INC);
  if(!kt->smem)
    return _del_KeyTab(kt);
  return kt;
}

/*.......................................................................
 * Delete a KeyTab object.
 *
 * Input:
 *  kt   KeyTab *  The object to be deleted.
 * Output:
 *  return KeyTab *  The deleted object (always NULL).
 */
KeyTab *_del_KeyTab(KeyTab *kt)
{
  if(kt) {
    if(kt->table)
      free(kt->table);
    kt->actions = _del_HashTable(kt->actions);
    kt->smem = _del_StringMem(kt->smem, 1);
    kt->err = _del_ErrMsg(kt->err);
    free(kt);
  };
  return NULL;
}

/*.......................................................................
 * Increase the size of the table to accomodate more keys.
 *
 * Input:
 *  kt       KeyTab *  The table to be extended.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
static int _kt_extend_table(KeyTab *kt)
{
/*
 * Attempt to increase the size of the table.
 */
  KeySym *newtab = (KeySym *) realloc(kt->table, sizeof(kt->table[0]) *
				      (kt->size + KT_TABLE_INC));
/*
 * Failed?
 */
  if(!newtab) {
    _err_record_msg(kt->err, "Can't extend keybinding table", END_ERR_MSG);
    errno = ENOMEM;
    return 1;
  };
/*
 * Install the resized table.
 */
  kt->table = newtab;
  kt->size += KT_TABLE_INC;
  return 0;
}

/*.......................................................................
 * Add, update or remove a keybinding to the table.
 *
 * Input:
 *  kt           KeyTab *  The table to add the binding to.
 *  binder     KtBinder    The source of the binding.
 *  keyseq   const char *  The key-sequence to bind.
 *  action         char *  The action to associate with the key sequence, or
 *                         NULL to remove the action associated with the
 *                         key sequence.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
int _kt_set_keybinding(KeyTab *kt, KtBinder binder, const char *keyseq,
		       const char *action)
{
  KtKeyFn *keyfn; /* The action function */
  void *data;     /* The callback data of the action function */
/*
 * Check arguments.
 */
  if(kt==NULL || !keyseq) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * Lookup the function that implements the specified action.
 */
  if(!action) {
    keyfn = 0;
    data = NULL;
  } else {
    Symbol *sym = _find_HashSymbol(kt->actions, action);
    if(!sym) {
      _err_record_msg(kt->err, "Unknown key-binding action: ", action,
		      END_ERR_MSG);
      errno = EINVAL;
      return 1;
    };
    keyfn = (KtKeyFn *) sym->fn;
    data = sym->data;
  };
/*
 * Record the action in the table.
 */
  return _kt_set_keyfn(kt, binder, keyseq, keyfn, data);
}

/*.......................................................................
 * Add, update or remove a keybinding to the table, specifying an action
 * function directly.
 *
 * Input:
 *  kt       KeyTab *  The table to add the binding to.
 *  binder KtBinder    The source of the binding.
 *  keyseq     char *  The key-sequence to bind.
 *  keyfn   KtKeyFn *  The action function, or NULL to remove any existing
 *                     action function.
 *  data       void *  A pointer to anonymous data to be passed to keyfn
 *                     whenever it is called.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
int _kt_set_keyfn(KeyTab *kt, KtBinder binder, const char *keyseq,
		  KtKeyFn *keyfn, void *data)
{
  const char *kptr;  /* A pointer into keyseq[] */
  char *binary;      /* The binary version of keyseq[] */
  int nc;            /* The number of characters in binary[] */
  int first,last;    /* The first and last entries in the table which */
                     /*  minimally match. */
  int size;          /* The size to allocate for the binary string */
  int i;
/*
 * Check arguments.
 */
  if(kt==NULL || !keyseq) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * Work out a pessimistic estimate of how much space will be needed
 * for the binary copy of the string, noting that binary meta characters
 * embedded in the input string get split into two characters.
 */
  for(size=0,kptr = keyseq; *kptr; kptr++)
    size += IS_META_CHAR(*kptr) ? 2 : 1;
/*
 * Allocate a string that has the length of keyseq[].
 */
  binary = _new_StringMemString(kt->smem, size + 1);
  if(!binary) {
    errno = ENOMEM;
    _err_record_msg(kt->err, "Insufficient memory to record key sequence",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Convert control and octal character specifications to binary characters.
 */
  if(_kt_parse_keybinding_string(keyseq, binary, &nc)) {
    binary = _del_StringMemString(kt->smem, binary);
    return 1;
  };
/*
 * Lookup the position in the table at which to insert the binding.
 */
  switch(_kt_locate_keybinding(kt, binary, nc, &first, &last)) {
/*
 * If an exact match for the key-sequence is already in the table,
 * simply replace its binding function (or delete the entry if
 * the new binding is 0).
 */
  case KT_EXACT_MATCH:
    if(keyfn) {
      _kt_assign_action(kt->table + first, binder, keyfn, data);
    } else {
      _del_StringMemString(kt->smem, kt->table[first].keyseq);
      memmove(kt->table + first, kt->table + first + 1,
	      (kt->nkey - first - 1) * sizeof(kt->table[0]));
      kt->nkey--;
    };
    binary = _del_StringMemString(kt->smem, binary);
    break;
/*
 * If an ambiguous match has been found and we are installing a
 * callback, then our new key-sequence would hide all of the ambiguous
 * matches, so we shouldn't allow it.
 */
  case KT_AMBIG_MATCH:
    if(keyfn) {
      _err_record_msg(kt->err, "Can't bind \"", keyseq,
		      "\", because it is a prefix of another binding",
		      END_ERR_MSG);
      binary = _del_StringMemString(kt->smem, binary);
      errno = EPERM;
      return 1;
    };
    break;
/*
 * If the entry doesn't exist, create it.
 */
  case KT_NO_MATCH:
/*
 * Add a new binding?
 */
    if(keyfn) {
      KeySym *sym;
/*
 * We will need a new entry, extend the table if needed.
 */
      if(kt->nkey + 1 > kt->size) {
	if(_kt_extend_table(kt)) {
	  binary = _del_StringMemString(kt->smem, binary);
	  return 1;
	};
      };
/*
 * Make space to insert the new key-sequence before 'last'.
 */
      if(last < kt->nkey) {
	memmove(kt->table + last + 1, kt->table + last,
		(kt->nkey - last) * sizeof(kt->table[0]));
      };
/*
 * Insert the new binding in the vacated position.
 */
      sym = kt->table + last;
      sym->keyseq = binary;
      sym->nc = nc;
      for(i=0; i<KTB_NBIND; i++) {
	KtAction *action = sym->actions + i;
	action->fn = 0;
	action->data = NULL;
      };
      sym->binder = -1;
      _kt_assign_action(sym, binder, keyfn, data);
      kt->nkey++;
    };
    break;
  case KT_BAD_MATCH:
    binary = _del_StringMemString(kt->smem, binary);
    return 1;
    break;
  };
  return 0;
}

/*.......................................................................
 * Perform a min-match lookup of a key-binding.
 *
 * Input:
 *  kt          KeyTab *   The keybinding table to lookup in.
 *  binary_keyseq char *   The binary key-sequence to lookup.
 *  nc             int     the number of characters in keyseq[].
 * Input/Output:
 *  first,last     int *   If there is an ambiguous or exact match, the indexes
 *                         of the first and last symbols that minimally match
 *                         will be assigned to *first and *last respectively.
 *                         If there is no match, then first and last will
 *                         bracket the location where the symbol should be
 *                         inserted.
 * Output:
 *  return  KtKeyMatch     One of the following enumerators:
 *                          KT_EXACT_MATCH - An exact match was found.
 *                          KT_AMBIG_MATCH - An ambiguous match was found.
 *                          KT_NO_MATCH    - No match was found.
 *                          KT_BAD_MATCH   - An error occurred while searching.
 */
static KtKeyMatch _kt_locate_keybinding(KeyTab *kt, const char *binary_keyseq,
					int nc, int *first, int *last)
{
  int mid;     /* The index at which to bisect the table */
  int bot;     /* The lowest index of the table not searched yet */
  int top;     /* The highest index of the table not searched yet */
  int test;    /* The return value of strcmp() */
/*
 * Perform a binary search for the key-sequence.
 */
  bot = 0;
  top = kt->nkey - 1;
  while(top >= bot) {
    mid = (top + bot)/2;
    test = _kt_compare_strings(kt->table[mid].keyseq, kt->table[mid].nc,
			   binary_keyseq, nc);
    if(test > 0)
      top = mid - 1;
    else if(test < 0)
      bot = mid + 1;
    else {
      *first = *last = mid;
      return KT_EXACT_MATCH;
    };
  };
/*
 * An exact match wasn't found, but top is the index just below the
 * index where a match would be found, and bot is the index just above
 * where the match ought to be found.
 */
  *first = top;
  *last = bot;
/*
 * See if any ambiguous matches exist, and if so make *first and *last
 * refer to the first and last matches.
 */
  if(*last < kt->nkey && kt->table[*last].nc > nc &&
     _kt_compare_strings(kt->table[*last].keyseq, nc, binary_keyseq, nc)==0) {
    *first = *last;
    while(*last+1 < kt->nkey && kt->table[*last+1].nc > nc &&
	  _kt_compare_strings(kt->table[*last+1].keyseq, nc, binary_keyseq, nc)==0)
      (*last)++;
    return KT_AMBIG_MATCH;
  };
/*
 * No match.
 */
  return KT_NO_MATCH;
}

/*.......................................................................
 * Lookup the sub-array of key-bindings who's key-sequences minimally
 * match a given key-sequence.
 *
 * Input:
 *  kt          KeyTab *   The keybinding table to lookup in.
 *  binary_keyseq char *   The binary key-sequence to lookup.
 *  nc             int     the number of characters in keyseq[].
 * Input/Output:
 *  matches     KeySym **  The array of minimally matching symbols
 *                         can be found in (*matches)[0..nmatch-1], unless
 *                         no match was found, in which case *matches will
 *                         be set to NULL.
 *  nmatch         int     The number of ambiguously matching symbols. This
 *                         will be 0 if there is no match, 1 for an exact
 *                         match, and a number greater than 1 for an ambiguous
 *                         match.
 * Output:
 *  return  KtKeyMatch     One of the following enumerators:
 *                          KT_EXACT_MATCH - An exact match was found.
 *                          KT_AMBIG_MATCH - An ambiguous match was found.
 *                          KT_NO_MATCH    - No match was found.
 *                          KT_BAD_MATCH   - An error occurred while searching.
 */
KtKeyMatch _kt_lookup_keybinding(KeyTab *kt, const char *binary_keyseq,
				 int nc, KeySym **matches, int *nmatch)
{
  KtKeyMatch status;  /* The return status */
  int first,last;     /* The indexes of the first and last matching entry */
                      /* in the symbol table. */
/*
 * Check the arguments.
 */
  if(!kt || !binary_keyseq || !matches || !nmatch || nc < 0) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return KT_BAD_MATCH;
  };
/*
 * Lookup the indexes of the binding-table entries that bracket the
 * target key-sequence.
 */
  status = _kt_locate_keybinding(kt, binary_keyseq, nc, &first, &last);
/*
 * Translate the indexes into the corresponding subarray of matching
 * table entries.
 */
  switch(status) {
  case KT_EXACT_MATCH:
  case KT_AMBIG_MATCH:
    *matches = kt->table + first;
    *nmatch = last - first + 1;
    break;
  default:
    *matches = NULL;
    *nmatch = 0;
    break;
  };
  return status;
}

/*.......................................................................
 * Convert a keybinding string into a uniq binary representation.
 *
 * Control characters can be given directly in their binary form,
 * expressed as either ^ or C-, followed by the character, expressed in
 * octal, like \129 or via C-style backslash escapes, with the addition
 * of '\E' to denote the escape key. Similarly, meta characters can be
 * given directly in binary or expressed as M- followed by the character.
 * Meta characters are recorded as two characters in the binary output
 * string, the first being the escape key, and the second being the key
 * that was modified by the meta key. This means that binding to
 * \EA or ^[A or M-A are all equivalent.
 *
 * Input:
 *  keyseq   char *  The key sequence being added.
 * Input/Output:
 *  binary   char *  The binary version of the key sequence will be
 *                   assigned to binary[], which must have at least
 *                   as many characters as keyseq[] plus the number
 *                   of embedded binary meta characters.
 *  nc        int *  The number of characters assigned to binary[]
 *                   will be recorded in *nc.
 * Output:
 *  return    int    0 - OK.
 *                   1 - Error.
 */
static int _kt_parse_keybinding_string(const char *keyseq, char *binary,
				       int *nc)
{
  const char *iptr = keyseq;   /* Pointer into keyseq[] */
  char *optr = binary;         /* Pointer into binary[] */
  char c;                      /* An intermediate character */
/*
 * Parse the input characters until they are exhausted or the
 * output string becomes full.
 */
  while(*iptr) {
/*
 * Check for special characters.
 */
    switch(*iptr) {
    case '^':        /* A control character specification */
/*
 * Convert the caret expression into the corresponding control
 * character unless no character follows the caret, in which case
 * record a literal caret.
 */
      if(iptr[1]) {
/*
 * Get the next, possibly escaped, character.
 */
	if(iptr[1] == '\\') {
	  c = _kt_backslash_escape(iptr+2, &iptr);
	} else {
	  c = iptr[1];
	  iptr += 2;
	};
/*
 * Convert the character to a control character.
 */
	*optr++ = MAKE_CTRL(c);
      } else {
	*optr++ = *iptr++;
      };
      break;
/*
 * A backslash-escaped character?
 */
    case '\\':
/*
 * Convert the escape sequence to a binary character.
 */
      *optr++ = _kt_backslash_escape(iptr+1, &iptr);
      break;
/*
 * Possibly an emacs-style meta character?
 */
    case 'M':
      if(_kt_is_emacs_meta(iptr)) {
	*optr++ = GL_ESC_CHAR;
	iptr += 2;
      } else {
	*optr++ = *iptr++;
      };
      break;
/*
 * Possibly an emacs-style control character specification?
 */
    case 'C':
      if(_kt_is_emacs_ctrl(iptr)) {
	*optr++ = MAKE_CTRL(iptr[2]);
	iptr += 3;
      } else {
	*optr++ = *iptr++;
      };
      break;
    default:

/*
 * Convert embedded meta characters into an escape character followed
 * by the meta-unmodified character.
 */
      if(IS_META_CHAR(*iptr)) {
	*optr++ = GL_ESC_CHAR;
	*optr++ = META_TO_CHAR(*iptr);
	iptr++;
/*
 * To allow keysequences that start with printable characters to
 * be distinguished from the cursor-key keywords, prepend a backslash
 * to the former. This same operation is performed in gl_interpret_char()
 * before looking up a keysequence that starts with a printable character.
 */
      } else if(iptr==keyseq && !IS_CTRL_CHAR(*iptr) &&
		strcmp(keyseq, "up") != 0 && strcmp(keyseq, "down") != 0 &&
		strcmp(keyseq, "left") != 0 && strcmp(keyseq, "right") != 0) {
	*optr++ = '\\';
	*optr++ = *iptr++;
      } else {
	*optr++ = *iptr++;
      };
    };
  };
/*
 * How many characters were placed in the output array?
 */
  *nc = optr - binary;
  return 0;
}

/*.......................................................................
 * Add, remove or modify an action.
 *
 * Input:
 *  kt     KeyTab *  The key-binding table.
 *  action   char *  The name of the action.
 *  fn    KtKeyFn *  The function that implements the action, or NULL
 *                   to remove an existing action.
 *  data     void *  A pointer to arbitrary callback data to pass to the
 *                   action function whenever it is called.
 * Output:
 *  return    int    0 - OK.
 *                   1 - Error.
 */
int _kt_set_action(KeyTab *kt, const char *action, KtKeyFn *fn, void *data)
{
  Symbol *sym;   /* The symbol table entry of the action */
/*
 * Check the arguments.
 */
  if(!kt || !action) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * If no function was provided, delete an existing action.
 */
  if(!fn) {
    sym = _del_HashSymbol(kt->actions, action);
    return 0;
  };
/*
 * If the action already exists, replace its action function.
 */
  sym = _find_HashSymbol(kt->actions, action);
  if(sym) {
    sym->fn = (void (*)(void))fn;
    sym->data = data;
    return 0;
  };
/*
 * Add a new action.
 */
  if(!_new_HashSymbol(kt->actions, action, 0, (void (*)(void))fn, data, 0)) {
    _err_record_msg(kt->err, "Insufficient memory to record key-binding action",
		    END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Compare two strings of specified length which may contain embedded
 * ascii NUL's.
 *
 * Input:
 *  s1       char *  The first of the strings to be compared.
 *  n1        int    The length of the string in s1.
 *  s2       char *  The second of the strings to be compared.
 *  n2        int    The length of the string in s2.
 * Output:
 *  return    int    < 0 if(s1 < s2)
 *                     0 if(s1 == s2)
 *                   > 0 if(s1 > s2)
 */
static int _kt_compare_strings(const char *s1, int n1, const char *s2, int n2)
{
  int i;
/*
 * Find the first character where the two strings differ.
 */
  for(i=0; i<n1 && i<n2 && s1[i]==s2[i]; i++)
    ;
/*
 * Did we hit the end of either string before finding a difference?
 */
  if(i==n1 || i==n2) {
    if(n1 == n2)
      return 0;
    else if(n1==i)
      return -1;
    else
      return 1;
  };
/*
 * Compare the two characters that differed to determine which
 * string is greatest.
 */
  return s1[i] - s2[i];
}

/*.......................................................................
 * Assign a given action function to a binding table entry.
 *
 * Input:
 *  sym       KeySym *  The binding table entry to be modified.
 *  binder  KtBinder    The source of the binding.
 *  keyfn    KtKeyFn *  The action function.
 *  data        void *  A pointer to arbitrary callback data to pass to
 *                      the action function whenever it is called.
 */
static void _kt_assign_action(KeySym *sym, KtBinder binder, KtKeyFn *keyfn,
			      void *data)
{
  KtAction *action;   /* An action function/data pair */
  int i;
/*
 * Unknown binding source?
 */
  if(binder < 0 || binder >= KTB_NBIND)
    return;
/*
 * Record the action according to its source.
 */
  action = sym->actions + binder;
  action->fn = keyfn;
  action->data = data;
/*
 * Find the highest priority binding source that has supplied an
 * action. Note that the actions[] array is ordered in order of
 * descreasing priority, so the first entry that contains a function
 * is the one to use.
 */
  for(i=0; i<KTB_NBIND && !sym->actions[i].fn; i++)
    ;
/*
 * Record the index of this action for use during lookups.
 */
  sym->binder = i < KTB_NBIND ? i : -1;
  return;
}

/*.......................................................................
 * Remove all key bindings that came from a specified source.
 *
 * Input:
 *  kt        KeyTab *  The table of key bindings.
 *  binder  KtBinder    The source of the bindings to be cleared.
 */
void _kt_clear_bindings(KeyTab *kt, KtBinder binder)
{
  int oldkey;   /* The index of a key in the original binding table */
  int newkey;   /* The index of a key in the updated binding table */
/*
 * If there is no table, then no bindings exist to be deleted.
 */
  if(!kt)
    return;
/*
 * Clear bindings of the given source.
 */
  for(oldkey=0; oldkey<kt->nkey; oldkey++)
    _kt_assign_action(kt->table + oldkey, binder, 0, NULL);
/*
 * Delete entries that now don't have a binding from any source.
 */
  newkey = 0;
  for(oldkey=0; oldkey<kt->nkey; oldkey++) {
    KeySym *sym = kt->table + oldkey;
    if(sym->binder < 0) {
      _del_StringMemString(kt->smem, sym->keyseq);
    } else {
      if(oldkey != newkey)
	kt->table[newkey] = *sym;
      newkey++;
    };
  };
/*
 * Record the number of keys that were kept.
 */
  kt->nkey = newkey;
  return;
}

/*.......................................................................
 * Translate a backslash escape sequence to a binary character.
 *
 * Input:
 *  string  const char *   The characters that follow the backslash.
 * Input/Output:
 *  endp    const char **  If endp!=NULL, on return *endp will be made to
 *                         point to the character in string[] which follows
 *                         the escape sequence.
 * Output:
 *  return        char     The binary character.
 */
static char _kt_backslash_escape(const char *string, const char **endp)
{
  char c;  /* The output character */
/*
 * Is the backslash followed by one or more octal digits?
 */
  switch(*string) {
  case '0': case '1': case '2': case '3':
  case '4': case '5': case '6': case '7':
    c = strtol(string, (char **)&string, 8);
    break;
  case 'a':
    c = '\a';
    string++;
    break;
  case 'b':
    c = '\b';
    string++;
    break;
  case 'e': case 'E': /* Escape */
    c = GL_ESC_CHAR;
    string++;
    break;
  case 'f':
    c = '\f';
    string++;
    break;
  case 'n':
    c = '\n';
    string++;
    break;
  case 'r':
    c = '\r';
    string++;
    break;
  case 't':
    c = '\t';
    string++;
    break;
  case 'v':
    c = '\v';
    string++;
    break;
  case '\0':
    c = '\\';
    break;
  default:
    c = *string++;
    break;
  };
/*
 * Report the character which follows the escape sequence.
 */
  if(endp)
    *endp = string;
  return c;
}

/*.......................................................................
 * Return non-zero if the next two characters are M- and a third character
 * follows. Otherwise return 0.
 *
 * Input:
 *  string   const char *  The sub-string to scan.
 * Output:
 *  return          int    1 - The next two characters are M- and these
 *                             are followed by at least one character.
 *                         0 - The next two characters aren't M- or no
 *                             character follows a M- pair.
 */
static int _kt_is_emacs_meta(const char *string)
{
  return *string++ == 'M' && *string++ == '-' && *string;
}

/*.......................................................................
 * Return non-zero if the next two characters are C- and a third character
 * follows. Otherwise return 0.
 *
 * Input:
 *  string   const char *  The sub-string to scan.
 * Output:
 *  return          int    1 - The next two characters are C- and these
 *                             are followed by at least one character.
 *                         0 - The next two characters aren't C- or no
 *                             character follows a C- pair.
 */
static int _kt_is_emacs_ctrl(const char *string)
{
  return *string++ == 'C' && *string++ == '-' && *string;
}

/*.......................................................................
 * Merge an array of bindings with existing bindings.
 *
 * Input:
 *  kt                    KeyTab *  The table of key bindings.
 *  binder              KtBinder    The source of the bindings.
 *  bindings  const KtKeyBinding *  The array of bindings.
 *  n                        int    The number of bindings in bindings[].
 * Output:
 *  return                   int    0 - OK.
 *                                  1 - Error.
 */
int _kt_add_bindings(KeyTab *kt, KtBinder binder, const KtKeyBinding *bindings,
		     unsigned n)
{
  int i;
/*
 * Check the arguments.
 */
  if(!kt || !bindings) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * Install the array of bindings.
 */
  for(i=0; i<n; i++) {
    if(_kt_set_keybinding(kt, binder, bindings[i].keyseq, bindings[i].action))
      return 1;
  };
  return 0;
}

/*.......................................................................
 * Lookup the function that implements a given action.
 *
 * Input:
 *  kt          KeyTab *  The table of key bindings.
 *  action  const char *  The name of the action to look up.
 * Input/Output:
 *  fn         KtKeyFn ** If the action is found, the function that
 *                        implements it will be assigned to *fn. Note
 *                        that fn can be NULL.
 *  data          void ** If the action is found, the callback data
 *                        associated with the action function, will be
 *                        assigned to *data. Note that data can be NULL.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Action not found.
 */
int _kt_lookup_action(KeyTab *kt, const char *action,
		      KtKeyFn **fn, void **data)
{
  Symbol *sym;   /* The symbol table entry of the action */
/*
 * Check the arguments.
 */
  if(!kt || !action) {
    errno = EINVAL;
    if(kt)
      _err_record_msg(kt->err, "NULL argument(s)", END_ERR_MSG);
    return 1;
  };
/*
 * Lookup the symbol table entry of the action.
 */
  sym = _find_HashSymbol(kt->actions, action);
  if(!sym)
    return 1;
/*
 * Return the function and ccallback data associated with the action.
 */
  if(fn)
    *fn = (KtKeyFn *) sym->fn;
  if(data)
    *data = sym->data;
  return 0;
}

/*.......................................................................
 * Return extra information (ie. in addition to that provided by errno)
 * about the last error to occur in any of the public functions of this
 * module.
 *
 * Input:
 *  kt          KeyTab *  The table of key bindings.
 * Output:
 *  return  const char *  A pointer to the internal buffer in which
 *                        the error message is temporarily stored.
 */
const char *_kt_last_error(KeyTab *kt)
{
  return kt ? _err_get_msg(kt->err) : "NULL KeyTab argument";
}
