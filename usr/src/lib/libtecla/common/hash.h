#ifndef hash_h
#define hash_h

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

/*
 * The following macro can be used to prototype or define a
 * function that deletes the data of a symbol-table entry.
 *
 * Input:
 *  app_data void *  The _new_HashTable() app_data argument.
 *  code      int    The Symbol::code argument.
 *  sym_data void *  The Symbol::data argument to be deleted.
 * Output:
 *  return  void * The deleted data (always return NULL).
 */
#define SYM_DEL_FN(fn) void *(fn)(void *app_data, int code, void *sym_data)

/*
 * The following macro can be used to prototype or define a
 * function that deletes the application-data of a hash-table.
 *
 * Input:
 *  data    void * The _new_HashTable() 'app_data' argument to be
 *                 deleted.
 * Output:
 *  return  void * The deleted data (always return NULL).
 */
#define HASH_DEL_FN(fn) void *(fn)(void *app_data)

/*
 * The following is a container for recording the context
 * of a symbol in a manner that is independant of the particular
 * symbol-table implementation. Each hash-table entry contains
 * the following user supplied parameters:
 *
 * 1. An optional integral parameter 'code'. This is useful for
 *    enumerating a symbol or for describing what type of data
 *    or function is stored in the symbol.
 *
 * 2. An optional generic function pointer. This is useful for
 *    associating functions with names. The user is responsible
 *    for casting between the generic function type and the
 *    actual function type. The code field could be used to
 *    enumerate what type of function to cast to.
 *
 * 3. An optional generic pointer to a static or heap-allocated
 *    object. It is up to the user to cast this back to the
 *    appropriate object type. Again, the code field could be used
 *    to describe what type of object is stored there.
 *    If the object is dynamically allocated and should be discarded
 *    when the symbol is deleted from the symbol table, send a
 *    destructor function to have it deleted automatically.
 */
typedef struct {
  char *name;           /* The name of the symbol */
  int code;             /* Application supplied integral code */
  void (*fn)(void);     /* Application supplied generic function */
  void *data;           /* Application supplied context data */
  SYM_DEL_FN(*del_fn);  /* Data destructor function */
} Symbol;

/*
 * HashNode's and HashTable's are small objects. Separately allocating
 * many such objects would normally cause memory fragmentation. To
 * counter this, HashMemory objects are used. These contain
 * dedicated free-lists formed from large dynamically allocated arrays
 * of objects. One HashMemory object can be shared between multiple hash
 * tables (within a single thread).
 */
typedef struct HashMemory HashMemory;

  /* Create a free-list for allocation of hash tables and their nodes */

HashMemory *_new_HashMemory(int hash_count, int node_count);

  /* Delete a redundant free-list if not being used */

HashMemory *_del_HashMemory(HashMemory *mem, int force);

/*
 * Declare an alias for the private HashTable structure defined in
 * hash.c.
 */
typedef struct HashTable HashTable;

/*
 * Enumerate case-sensitivity options.
 */
typedef enum {
  IGNORE_CASE,     /* Ignore case when looking up symbols */
  HONOUR_CASE      /* Honor case when looking up symbols */
} HashCase;

  /* Create a new hash-table */

HashTable *_new_HashTable(HashMemory *mem, int size, HashCase hcase,
			  void *app_data, HASH_DEL_FN(*del_fn));

  /* Delete a reference to a hash-table */

HashTable *_del_HashTable(HashTable *hash);

  /* Add an entry to a hash table */

Symbol *_new_HashSymbol(HashTable *hash, const char *key, int code,
			void (*fn)(void), void *data, SYM_DEL_FN(*del_fn));

  /* Remove and delete all the entries in a given hash table */

int _clear_HashTable(HashTable *hash);

  /* Remove and delete a given hash-table entry */

Symbol *_del_HashSymbol(HashTable *hash, const char *key);

  /* Lookup a given hash-table entry */

Symbol *_find_HashSymbol(HashTable *hash, const char *key);

  /* Execute a given function on each entry of a hash table, returning */
  /*  before completion if the specified function returns non-zero. */

#define HASH_SCAN_FN(fn)  int (fn)(Symbol *sym, void *context)

int _scan_HashTable(HashTable *hash, HASH_SCAN_FN(*scan_fn), void *context);

#endif
