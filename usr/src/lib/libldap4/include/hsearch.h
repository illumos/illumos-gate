/*
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ident "@(#)hsearch.h	1.3 07/23/97 SMI"
typedef struct {	/* Hash table entry */
    char * key;
    char * data;
    int    dsize;
    int    modified;
    time_t timestamp;
} HASH_ENTRY;

typedef struct node {	/* Part of the linked list of entries */
	HASH_ENTRY item;
	struct node *next;
} NODE;

typedef enum {
    FIND,		/* Find, if present */
    ENTER,		/* Find; enter if not present */
    REPLACE,	/* replace */
    DELETE,		/* delete  */
} ACTION;

/* define everything that a hash table needs to drag around */
typedef struct hash_table {
	NODE **table;	/* The address of the hash table */
	unsigned int length;	/* Size of the hash table */
	unsigned int m;		/* Log base 2 of length */
	unsigned int count;		/*  nb entries in the hash table */
	mutex_t table_lock;	/* currently not used */
	int	 alloc_data;	/* true if data is allocated and copied in the hast table */
	int	 clean;	        /* to force cleanup of the hash table */
	int 	size;		/* Max size of the hast table, defaulted 5000	*/
} HASH_TABLE;

void hdestroy_s(HASH_TABLE **hash_table);
HASH_ENTRY *hsearch_s(HASH_TABLE *hash_table, HASH_ENTRY item, ACTION action);
HASH_ENTRY *hlist_s(HASH_TABLE *hash_table, int * i, NODE ** a);
HASH_TABLE *hcreate_s(size_t size, int alloc_data);

/* convenience functions for adding and find things */
int hadd_s(HASH_TABLE **hash_table, char *key, void *data, int size);
int hreplace_s(HASH_TABLE **hash_table, char *key, void *data, int size);
char *hfind_s(HASH_TABLE *hash_table, char *key);
int hdelete_s( HASH_TABLE *hash_table, char * key);
