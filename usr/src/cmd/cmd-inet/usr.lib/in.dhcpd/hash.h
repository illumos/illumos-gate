/*
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright 1988, 1991 by Carnegie Mellon University
 * All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of Carnegie Mellon University not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 */

#ifndef	_HASH_H
#define	_HASH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generalized hash table ADT
 *
 * Provides multiple, dynamically-allocated, variable-sized hash tables on
 * various data and keys.
 *
 * This package attempts to follow some of the coding conventions suggested
 * by Bob Sidebotham and the AFS Clean Code Committee.
 */

/*
 * The user must supply the following:
 *
 * 1. A comparison function which is declared as:
 *
 * int compare(data1, data2)
 * hash_datum *data1, *data2;
 *
 * This function must compare the desired fields of data1 and
 * data2 and return B_TRUE (1) if the data should be considered
 * equivalent (i.e. have the same key value) or B_FALSE (0)
 * otherwise. This function is called through a pointer passed to
 * the various hashtable functions (thus pointers to different
 * functions may be passed to effect different tests on different
 * hash tables).
 *
 * Internally, all the functions of this package always call the
 * compare function with the "key" parameter as the first parameter,
 * and a full data element as the second parameter. Thus, the key
 * and element arguments to functions such as hash_Lookup() may
 * actually be of different types and the programmer may provide a
 * compare function which compares the two different object types
 * as desired.
 *
 * Example:
 *
 * int compare(key, element)
 * char *key;
 * struct some_complex_structure *element;
 * {
 * 	return !strcmp(key, element->name);
 * }
 *
 * key = "John C. Doe"
 * element = &some_complex_structure
 * hash_Lookup(table, hashptr, hashlen, compare, key, free_rec, B_TRUE);
 *
 * 2. A hash function yielding an unsigned integer value to be used
 * as the hashcode (index into the hashtable).  Thus, the user
 * may hash on whatever data is desired and may use several
 * different hash functions for various different hash tables.
 * The actual hash table index will be the passed hashcode modulo
 * the hash table size.
 *
 * A generalized hash function, hash_HashFunction(), is included
 * with this package to make things a little easier.  It is not
 * guarenteed to use the best hash algorithm in existence. . . .
 *
 * 3. An ability to garbage collect data has been added. Timed garbage
 * collection of hash members is provided to relieve the interface and worker
 * threads of explicit data structure management. Expired data structures
 * are pruned during hash insertion and deletion, or by explicit calls
 * to Delete and Reap functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Various hash table definitions
 */

/*
 * Define "hash_datum" as a universal data type
 */
typedef void hash_datum;
typedef void *hash_handle;

typedef struct hash_memberstruct	hash_member;
typedef struct hash_bucketstruct	hash_bucket;
typedef struct hash_tblstruct		hash_tbl;
typedef struct hash_tblstruct_hdr	hash_tblhdr;

struct hash_memberstruct {
	hash_member	*next;		/* hash next pointer */
	hash_datum	*data;		/* hash data */
	time_t		h_time;		/* hash dynamic free time */
	int		h_count;	/* hash reference count */
	mutex_t		h_mtx;		/* hash mutex */
};

struct hash_tblstruct;
struct hash_bucketstruct {
	hash_member		*next;
	struct hash_tblstruct	*table;
	rwlock_t		rwlock;
};

struct hash_tblstruct_hdr {
	unsigned	size;
	unsigned	bucketnum;
	hash_member	*member;
};

struct hash_tblstruct {
	unsigned	size;
	unsigned	bucketnum;
	hash_member	*member;	/* Used for linear dump */
	boolean_t	(*dfree_data)(); /* Used for dynamic free */
	boolean_t	dfree_lck;	/* Use for dynamic free locking */
	time_t		dfree_time;	/* Unused time to dynamically free */
	hash_bucket	*table;		/* Dynamically Extend */
	hash_bucket	data[1];
};

extern unsigned	hash_Size(unsigned int);
extern hash_tbl	*hash_Init(unsigned, boolean_t (*)(), time_t, boolean_t);
extern void	hash_Reset(hash_tbl *, boolean_t (*)());
extern void *hash_Insert(hash_tbl *, void *, unsigned, int (*)(),
		    hash_datum *, hash_datum *);
extern hash_datum *hash_Lookup(hash_tbl *, void *, unsigned, int (*)(),
		    hash_datum *, boolean_t);
extern boolean_t hash_Delete(hash_tbl *, void *, unsigned, int (*)(),
		    hash_datum *, boolean_t (*)());
extern void	hash_Reap(hash_tbl *, boolean_t (*)());
extern void	hash_Age(void *);
extern void	hash_Dtime(void *, time_t);
extern int	hash_Refcount(void *);
extern int	hash_Htime(void *);
extern void	hash_Rele(void *, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _HASH_H */
