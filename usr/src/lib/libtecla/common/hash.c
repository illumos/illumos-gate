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

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "hash.h"
#include "strngmem.h"
#include "freelist.h"

/*
 * The following container object contains free-lists to be used
 * for allocation of HashTable containers and nodes.
 */
struct HashMemory {
  FreeList *hash_memory;    /* HashTable free-list */
  FreeList *node_memory;    /* HashNode free-list */
  StringMem *string_memory; /* Memory used to allocate hash strings */
};

/*
 * Define a hash symbol-table entry.
 * See symbol.h for the definition of the Symbol container type.
 */
typedef struct HashNode HashNode;
struct HashNode {
  Symbol symbol;       /* The symbol stored in the hash-entry */
  HashNode *next;      /* The next hash-table entry in a bucket list */
};

/*
 * Each hash-table bucket contains a linked list of entries that
 * hash to the same bucket.
 */
typedef struct {
  HashNode *head;   /* The head of the bucket hash-node list */
  int count;        /* The number of entries in the list */
} HashBucket;

/*
 * A hash-table consists of 'size' hash buckets.
 * Note that the HashTable typedef for this struct is contained in hash.h.
 */
struct HashTable {
  HashMemory *mem;         /* HashTable free-list */
  int internal_mem;        /* True if 'mem' was allocated by _new_HashTable() */
  int case_sensitive;      /* True if case is significant in lookup keys */
  int size;                /* The number of hash buckets */
  HashBucket *bucket;      /* An array of 'size' hash buckets */
  int (*keycmp)(const char *, const char *); /* Key comparison function */
  void *app_data;          /* Application-provided data */
  HASH_DEL_FN(*del_fn);    /* Application-provided 'app_data' destructor */
};

static HashNode *_del_HashNode(HashTable *hash, HashNode *node);
static HashNode *_new_HashNode(HashTable *hash, const char *name, int code,
		      void (*fn)(void), void *data, SYM_DEL_FN(*del_fn));
static HashNode *_find_HashNode(HashTable *hash, HashBucket *bucket,
				const char *name, HashNode **prev);
static HashBucket *_find_HashBucket(HashTable *hash, const char *name);
static int _ht_lower_strcmp(const char *node_key, const char *look_key);
static int _ht_strcmp(const char *node_key, const char *look_key);

/*.......................................................................
 * Allocate a free-list for use in allocating hash tables and their nodes.
 *
 * Input:
 *  list_count    int    The number of HashTable containers per free-list
 *                       block.
 *  node_count    int    The number of HashTable nodes per free-list block.
 * Output:
 *  return HashMemory *  The new free-list for use in allocating hash tables
 *                       and their nodes.
 */
HashMemory *_new_HashMemory(int hash_count, int node_count)
{
  HashMemory *mem;
/*
 * Allocate the free-list container.
 */
  mem = (HashMemory *) malloc(sizeof(HashMemory));
  if(!mem) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Initialize the container at least up to the point at which it can
 * safely be passed to _del_HashMemory().
 */
  mem->hash_memory = NULL;
  mem->node_memory = NULL;
  mem->string_memory = NULL;
/*
 * Allocate the two free-lists.
 */
  mem->hash_memory = _new_FreeList(sizeof(HashTable), hash_count);
  if(!mem->hash_memory)
    return _del_HashMemory(mem, 1);
  mem->node_memory = _new_FreeList(sizeof(HashNode), node_count);
  if(!mem->node_memory)
    return _del_HashMemory(mem, 1);
  mem->string_memory = _new_StringMem(64);
  if(!mem->string_memory)
    return _del_HashMemory(mem, 1);
/*
 * Return the free-list container.
 */
  return mem;
}

/*.......................................................................
 * Delete a HashTable free-list. An error will be displayed if the list is
 * still in use and the deletion will be aborted.
 *
 * Input:
 *  mem    HashMemory *  The free-list container to be deleted.
 *  force         int    If force==0 then _del_HashMemory() will complain
 *                        and refuse to delete the free-list if any
 *                        of nodes have not been returned to the free-list.
 *                       If force!=0 then _del_HashMemory() will not check
 *                        whether any nodes are still in use and will
 *                        always delete the list.
 * Output:
 *  return HashMemory *  Always NULL (even if the memory could not be
 *                       deleted).
 */
HashMemory *_del_HashMemory(HashMemory *mem, int force)
{
  if(mem) {
    if(!force && (_busy_FreeListNodes(mem->hash_memory) > 0 ||
		  _busy_FreeListNodes(mem->node_memory) > 0)) {
      errno = EBUSY;
      return NULL;
    };
    mem->hash_memory = _del_FreeList(mem->hash_memory, force);
    mem->node_memory = _del_FreeList(mem->node_memory, force);
    mem->string_memory = _del_StringMem(mem->string_memory, force);
    free(mem);
  };
  return NULL;
}

/*.......................................................................
 * Create a new hash table.
 *
 * Input:
 *  mem       HashMemory *  An optional free-list for use in allocating
 *                          HashTable containers and nodes. See explanation
 *                          in hash.h. If you are going to allocate more
 *                          than one hash table, then it will be more
 *                          efficient to allocate a single free-list for
 *                          all of them than to force each hash table
 *                          to allocate its own private free-list.
 *  size             int    The size of the hash table. Best performance
 *                          will be acheived if this is a prime number.
 *  hcase       HashCase    Specify how symbol case is considered when
 *                          looking up symbols, from:
 *                           IGNORE_CASE - Upper and lower case versions
 *                                         of a letter are treated as
 *                                         being identical.
 *                           HONOUR_CASE - Upper and lower case versions
 *                                         of a letter are treated as
 *                                         being distinct.
 *                          characters in a lookup name is significant.
 *  app_data        void *  Optional application data to be registered
 *                          to the table. This is presented to user
 *                          provided SYM_DEL_FN() symbol destructors along
 *                          with the symbol data.
 *  del_fn() HASH_DEL_FN(*) If you want app_data to be free'd when the
 *                          hash-table is destroyed, register a suitable
 *                          destructor function here.
 * Output:
 *  return HashTable *  The new hash table, or NULL on error.
 */
HashTable *_new_HashTable(HashMemory *mem, int size, HashCase hcase,
			 void *app_data, HASH_DEL_FN(*del_fn))
{
  HashTable *hash;         /* The table to be returned */
  int allocate_mem = !mem; /* True if mem should be internally allocated */
  int i;
/*
 * Check arguments.
 */
  if(size <= 0) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Allocate an internal free-list?
 */
  if(allocate_mem) {
    mem = _new_HashMemory(1, 100);
    if(!mem)
      return NULL;
  };
/*
 * Allocate the container.
 */
  hash = (HashTable *) _new_FreeListNode(mem->hash_memory);
  if(!hash) {
    errno = ENOMEM;
    if(allocate_mem)
      mem = _del_HashMemory(mem, 1);
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize
 * the container at least up to the point at which it can safely
 * be passed to _del_HashTable().
 */
  hash->mem = mem;
  hash->internal_mem = allocate_mem;
  hash->case_sensitive = hcase==HONOUR_CASE;
  hash->size = size;
  hash->bucket = NULL;
  hash->keycmp = hash->case_sensitive ? _ht_strcmp : _ht_lower_strcmp;
  hash->app_data = app_data;
  hash->del_fn = del_fn;
/*
 * Allocate the array of 'size' hash buckets.
 */
  hash->bucket = (HashBucket *) malloc(sizeof(HashBucket) * size);
  if(!hash->bucket) {
    errno = ENOMEM;
    return _del_HashTable(hash);
  };
/*
 * Initialize the bucket array.
 */
  for(i=0; i<size; i++) {
    HashBucket *b = hash->bucket + i;
    b->head = NULL;
    b->count = 0;
  };
/*
 * The table is ready for use - albeit currently empty.
 */
  return hash;
}

/*.......................................................................
 * Delete a hash-table.
 *
 * Input:
 *  hash   HashTable *  The hash table to be deleted.
 * Output:
 *  return HashTable *  The deleted hash table (always NULL).
 */
HashTable *_del_HashTable(HashTable *hash)
{
  if(hash) {
/*
 * Clear and delete the bucket array.
 */
    if(hash->bucket) {
      _clear_HashTable(hash);
      free(hash->bucket);
      hash->bucket = NULL;
    };
/*
 * Delete application data.
 */
    if(hash->del_fn)
      hash->del_fn(hash->app_data);
/*
 * If the hash table was allocated from an internal free-list, delete
 * it and the hash table by deleting the free-list. Otherwise just
 * return the hash-table to the external free-list.
 */
    if(hash->internal_mem)
      _del_HashMemory(hash->mem, 1);
    else
      hash = (HashTable *) _del_FreeListNode(hash->mem->hash_memory, hash);
  };
  return NULL;
}

/*.......................................................................
 * Create and install a new entry in a hash table. If an entry with the
 * same name already exists, replace its contents with the new data.
 *
 * Input:
 *  hash   HashTable *  The hash table to insert the symbol into.
 *  name  const char *  The name to tag the entry with.
 *  code         int    An application-specific code to be stored in
 *                      the entry.
 *  fn  void (*)(void)  An application-specific function to be stored
 *                      in the entry.
 *  data        void *  An application-specific pointer to data to be
 *                      associated with the entry, or NULL if not
 *                      relevant.
 *  del_fn SYM_DEL_FN(*) An optional destructor function. When the
 *                      symbol is deleted this function will be called
 *                      with the 'code' and 'data' arguments given
 *                      above. Any application data that was registered
 *                      to the table via the app_data argument of
 *                      _new_HashTable() will also be passed.
 * Output:
 *  return  HashNode *  The new entry, or NULL if there was insufficient
 *                      memory or the arguments were invalid.
 */
Symbol *_new_HashSymbol(HashTable *hash, const char *name, int code,
			void (*fn)(void), void *data, SYM_DEL_FN(*del_fn))
{
  HashBucket *bucket;  /* The hash-bucket associated with the name */
  HashNode *node;      /* The new node */
/*
 * Check arguments.
 */
  if(!hash || !name) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Get the hash bucket of the specified name.
 */
  bucket = _find_HashBucket(hash, name);
/*
 * See if a node with the same name already exists.
 */
  node = _find_HashNode(hash, bucket, name, NULL);
/*
 * If found, delete its contents by calling the user-supplied
 * destructor function, if provided.
 */
  if(node) {
    if(node->symbol.data && node->symbol.del_fn) {
      node->symbol.data = node->symbol.del_fn(hash->app_data, node->symbol.code,
					      node->symbol.data);
    };
/*
 * Allocate a new node if necessary.
 */
  } else {
    node = _new_HashNode(hash, name, code, fn, data, del_fn);
    if(!node)
      return NULL;
  };
/*
 * Install the node at the head of the hash-bucket list.
 */
  node->next = bucket->head;
  bucket->head = node;
  bucket->count++;
  return &node->symbol;
}

/*.......................................................................
 * Remove and delete a given hash-table entry.
 *
 * Input:
 *  hash   HashTable *  The hash table to find the symbol in.
 *  name  const char *  The name of the entry.
 * Output:
 *  return  HashNode *  The deleted hash node (always NULL).
 */
Symbol *_del_HashSymbol(HashTable *hash, const char *name)
{
  if(hash && name) {
    HashBucket *bucket = _find_HashBucket(hash, name);
    HashNode *prev;   /* The node preceding the located node */
    HashNode *node = _find_HashNode(hash, bucket, name, &prev);
/*
 * Node found?
 */
    if(node) {
/*
 * Remove the node from the bucket list.
 */
      if(prev) {
	prev->next = node->next;
      } else {
	bucket->head = node->next;
      };
/*
 * Record the loss of a node.
 */
      bucket->count--;
/*
 * Delete the node.
 */
      (void) _del_HashNode(hash, node);
    };
  };
  return NULL;
}

/*.......................................................................
 * Look up a symbol in the hash table.
 *
 * Input:
 *  hash   HashTable *   The table to look up the string in.
 *  name  const char *   The name of the symbol to look up.
 * Output:
 *  return    Symbol *   The located hash-table symbol, or NULL if not
 *                       found.
 */
Symbol *_find_HashSymbol(HashTable *hash, const char *name)
{
  HashBucket *bucket;  /* The hash-table bucket associated with name[] */
  HashNode *node;      /* The hash-table node of the requested symbol */
/*
 * Check arguments.
 */
  if(!hash)
    return NULL;
/*
 * Nothing to lookup?
 */
  if(!name)
    return NULL;
/*
 * Hash the name to a hash-table bucket.
 */
  bucket = _find_HashBucket(hash, name);
/*
 * Find the bucket entry that exactly matches the name.
 */
  node = _find_HashNode(hash, bucket, name, NULL);
  if(!node)
    return NULL;
  return &node->symbol;
}

/*.......................................................................
 * Private function used to allocate a hash-table node.
 * The caller is responsible for checking that the specified symbol
 * is unique and for installing the returned entry in the table.
 *
 * Input:
 *  hash     HashTable *  The table to allocate the node for.
 *  name    const char *  The name of the new entry.
 *  code           int    A user-supplied context code.
 *  fn  void (*)(void)    A user-supplied function pointer.
 *  data          void *  A user-supplied data pointer.
 *  del_fn  SYM_DEL_FN(*) An optional 'data' destructor function.
 * Output:
 *  return    HashNode *  The new node, or NULL on error.
 */
static HashNode *_new_HashNode(HashTable *hash, const char *name, int code,
			      void (*fn)(void), void *data, SYM_DEL_FN(*del_fn))
{
  HashNode *node;  /* The new node */
  size_t len;
/*
 * Allocate the new node from the free list.
 */
  node = (HashNode *) _new_FreeListNode(hash->mem->node_memory);
  if(!node)
    return NULL;
/*
 * Before attempting any operation that might fail, initialize the
 * contents of 'node' at least up to the point at which it can be
 * safely passed to _del_HashNode().
 */
  node->symbol.name = NULL;
  node->symbol.code = code;
  node->symbol.fn = fn;
  node->symbol.data = data;
  node->symbol.del_fn = del_fn;
  node->next = NULL;
/*
 * Allocate a copy of 'name'.
 */
  len = strlen(name) + 1;
  node->symbol.name = _new_StringMemString(hash->mem->string_memory, len);
  if(!node->symbol.name)
    return _del_HashNode(hash, node);
/*
 * If character-case is insignificant in the current table, convert the
 * name to lower case while copying it.
 */
  if(hash->case_sensitive) {
    strlcpy(node->symbol.name, name, len);
  } else {
    const char *src = name;
    char *dst = node->symbol.name;
    for( ; *src; src++,dst++)
      *dst = tolower(*src);
    *dst = '\0';
  };
  return node;
}

/*.......................................................................
 * Private function used to delete a hash-table node.
 * The node must have been removed from its list before calling this
 * function.
 *
 * Input:
 *  hash   HashTable *  The table for which the node was originally
 *                      allocated.
 *  node    HashNode *  The node to be deleted.
 * Output:
 *  return  HashNode *  The deleted node (always NULL).
 */
static HashNode *_del_HashNode(HashTable *hash, HashNode *node)
{
  if(node) {
    node->symbol.name = _del_StringMemString(hash->mem->string_memory,
					    node->symbol.name);
/*
 * Call the user-supplied data-destructor if provided.
 */
    if(node->symbol.data && node->symbol.del_fn)
      node->symbol.data = node->symbol.del_fn(hash->app_data,
					      node->symbol.code,
					      node->symbol.data);
/*
 * Return the node to the free-list.
 */
    node->next = NULL;
    node = (HashNode *) _del_FreeListNode(hash->mem->node_memory, node);
  };
  return NULL;
}

/*.......................................................................
 * Private function to locate the hash bucket associated with a given
 * name.
 *
 * This uses a hash-function described in the dragon-book
 * ("Compilers - Principles, Techniques and Tools", by Aho, Sethi and
 *  Ullman; pub. Adison Wesley) page 435.
 *
 * Input:
 *  hash    HashTable *   The table to look up the string in.
 *  name   const char *   The name of the symbol to look up.
 * Output:
 *  return HashBucket *   The located hash-bucket.
 */
static HashBucket *_find_HashBucket(HashTable *hash, const char *name)
{
  unsigned const char *kp;
  unsigned long h = 0L;
  if(hash->case_sensitive) {
    for(kp=(unsigned const char *) name; *kp; kp++)
      h = 65599UL * h + *kp;  /* 65599 is a prime close to 2^16 */
  } else {
    for(kp=(unsigned const char *) name; *kp; kp++)
      h = 65599UL * h + tolower((int)*kp);  /* 65599 is a prime close to 2^16 */
  };
  return hash->bucket + (h % hash->size);
}

/*.......................................................................
 * Search for a given name in the entries of a given bucket.
 *
 * Input:
 *  hash     HashTable *  The hash-table being searched.
 *  bucket  HashBucket *  The bucket to search (use _find_HashBucket()).
 *  name    const char *  The name to search for.
 * Output:
 *  prev      HashNode ** If prev!=NULL then the pointer to the node
 *                        preceding the located node in the list will
 *                        be recorded in *prev. This will be NULL either
 *                        if the name is not found or the located node is
 *                        at the head of the list of entries.
 * return     HashNode *  The located hash-table node, or NULL if not
 *                        found.
 */
static HashNode *_find_HashNode(HashTable *hash, HashBucket *bucket,
			       const char *name, HashNode **prev)
{
  HashNode *last;  /* The previously searched node */
  HashNode *node;  /* The node that is being searched */
/*
 * Search the list for a node containing the specified name.
 */
  for(last=NULL, node=bucket->head;
      node && hash->keycmp(node->symbol.name, name)!=0;
      last = node, node=node->next)
    ;
  if(prev)
    *prev = node ? last : NULL;
  return node;
}

/*.......................................................................
 * When hash->case_sensitive is zero this function is called
 * in place of strcmp(). In such cases the hash-table names are stored
 * as lower-case versions of the original strings so this function
 * performs the comparison against lower-case copies of the characters
 * of the string being compared.
 *
 * Input:
 *  node_key   const char *  The lower-case hash-node key being compared
 *                           against.
 *  look_key   const char *  The lookup key.
 * Output:
 *  return            int    <0 if node_key < look_key.
 *                            0 if node_key == look_key.
 *                           >0 if node_key > look_key.
 */
static int _ht_lower_strcmp(const char *node_key, const char *look_key)
{
  int cn;  /* The latest character from node_key[] */
  int cl;  /* The latest character from look_key[] */
  do {
    cn = *node_key++;
    cl = *look_key++;
  } while(cn && cn==tolower(cl));
  return cn - tolower(cl);
}

/*.......................................................................
 * This is a wrapper around strcmp for comparing hash-keys in a case
 * sensitive manner. The reason for having this wrapper, instead of using
 * strcmp() directly, is to make some C++ compilers happy. The problem
 * is that when the library is compiled with a C++ compiler, the
 * declaration of the comparison function is a C++ declaration, whereas
 * strcmp() is a pure C function and thus although it appears to have the
 * same declaration, the compiler disagrees.
 *
 * Input:
 *  node_key   char *  The lower-case hash-node key being compared against.
 *  look_key   char *  The lookup key.
 * Output:
 *  return      int    <0 if node_key < look_key.
 *                      0 if node_key == look_key.
 *                     >0 if node_key > look_key.
 */
static int _ht_strcmp(const char *node_key, const char *look_key)
{
  return strcmp(node_key, look_key);
}

/*.......................................................................
 * Empty a hash-table by deleting all of its entries.
 *
 * Input:
 *  hash    HashTable *  The hash table to clear.
 * Output:
 *  return        int    0 - OK.
 *                       1 - Invalid arguments.
 */
int _clear_HashTable(HashTable *hash)
{
  int i;
/*
 * Check the arguments.
 */
  if(!hash)
    return 1;
/*
 * Clear the contents of the bucket array.
 */
  for(i=0; i<hash->size; i++) {
    HashBucket *bucket = hash->bucket + i;
/*
 * Delete the list of active hash nodes from the bucket.
 */
    HashNode *node = bucket->head;
    while(node) {
      HashNode *next = node->next;
      (void) _del_HashNode(hash, node);
      node = next;
    };
/*
 * Mark the bucket as empty.
 */
    bucket->head = NULL;
    bucket->count = 0;
  };
  return 0;
}

/*.......................................................................
 * Execute a given function on each entry of a hash table, returning
 * before completion if the the specified function returns non-zero.
 *
 * Input:
 *  hash       HashTable *    The table to traverse.
 *  scan_fn HASH_SCAN_FN(*)   The function to call.
 *  context         void *    Optional caller-specific context data
 *                            to be passed to scan_fn().
 * Output:
 *  return           int      0 - OK.
 *                            1 - Either the arguments were invalid, or
 *                                scan_fn() returned non-zero at some
 *                                point.
 */
int _scan_HashTable(HashTable *hash, HASH_SCAN_FN(*scan_fn), void *context)
{
  int i;
/*
 * Check the arguments.
 */
  if(!hash || !scan_fn)
    return 1;
/*
 * Iterate through the buckets of the table.
 */
  for(i=0; i<hash->size; i++) {
    HashBucket *bucket = hash->bucket + i;
    HashNode *node;
/*
 * Iterate through the list of symbols that fall into bucket i,
 * passing each one to the caller-specified function.
 */
    for(node=bucket->head; node; node=node->next) {
      if(scan_fn(&node->symbol, context))
	return 1;
    };
  };
  return 0;
}
