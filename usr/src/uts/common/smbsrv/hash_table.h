/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_HASH_TABLE_H
#define	_SMBSRV_HASH_TABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * Interface definition for the hash table library. The hash table is a
 * user-specified array of pointers to items. Hash collisions are handled
 * using linked lists from the table entries. A handle is associated with
 * each table, which is used to maintain the hash table.
 *
 * +------+     +-------+    +----+    +----+
 * |handle|---> |index 0|--->|item|--->|item|--->
 * | ...  |     +-------+    +----+    +----+
 * | ...  |     |index 1|--->
 * +------+     +-------+    +----+    +----+    +----+
 *              |index 2|--->|item|--->|item|--->|item|--->
 *              +-------+    +----+    +----+    +----+
 *              | ...   |--->
 *              +-------+
 *              | ...   |--->
 *              +-------+
 *              |index n|--->
 *              +-------+
 *
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is the hash multiplier value.
 */
#define	HASH_MESH_VALUE		77

/*
 * Each entry (item) in the hash table has a linked-list pointer, a key,
 * a pointer to some user defined data (which may be null) and some flags.
 * The key is a user provided key and is used to position the item within
 * the table. The linked-list is used to store items whose hash values
 * collide. The data pointer is never dereferenced in the hash code so
 * it may be a null pointer.
 *
 * The item bit flags are:
 *
 * HTIF_DELETE:    Specifies that an item is marked for deletion (see
 *               ht_mark_delete and ht_clean_table).
 */
#define	HTIF_MARKED_DELETED	0x01
#define	HT_DELETE		HTIF_MARKED_DELETED

typedef struct ht_item {
	struct ht_item *hi_next;
	char *hi_key;
	void *hi_data;
	size_t hi_flags;
} HT_ITEM;

/*
 * HT_TABLE_ENTRY is an opaque structure (to the public) used to maintain
 * a pointer to the hash table and the number of items in the table entry.
 * This number shows number of both available items and those are marked
 * as deleted.
 */
typedef struct ht_table_entry {
	HT_ITEM *he_head;
	size_t he_count;
} HT_TABLE_ENTRY;

/*
 * The HT_HANDLE is an opaque handle that associates each request with
 * a hash table. A handle is generated when a hash table is created and
 * it is used to maintain all global data associated with the table.
 *
 * The handle bit flags are:
 *
 * HTHF_FIXED_KEY:    Specifies that keys are fixed length and should
 *                    not be assumed to be null terminated.
 */
#define	HTHF_FIXED_KEY		0x01

typedef struct ht_handle {
	HT_TABLE_ENTRY *ht_table;
	size_t ht_sequence;
	size_t ht_table_size;
	size_t ht_table_mask;
	size_t ht_key_size;
	size_t ht_total_items;	/* show total number of available items */
	size_t ht_flags;
	size_t (*ht_hash)(struct ht_handle *handle, const char *key);
	void (*ht_callback)(HT_ITEM *item);
	int (*ht_cmp)(const char *key1, const char *key2, size_t n);
} HT_HANDLE;

/*
 * Typedefs for the optional user-installable functions.
 */
typedef void (*HT_CALLBACK)(HT_ITEM *item);

/*
 * Compare function cast to make all compare
 * functions look like strncmp.
 */
typedef	int (*HT_CMP)(const char *, const char *, size_t);

/*
 * Iterator used with ht_findfirst and ht_findnext to walk through
 * all the items in a hash table. The iterator should be treated as
 * an opaque handle. The sequence number in the iterator is used
 * to maintain consistency with the table on which the iteration
 * is being performed. If the table sequence number changes, the
 * iterator becomes invalid.
 */
typedef struct ht_iterator {
	HT_HANDLE *hti_handle;
	HT_ITEM *hti_item;
	size_t hti_index;
	size_t hti_sequence;
} HT_ITERATOR;

/*
 * Public API to create and destroy hash tables, to change the hash
 * function and to find out how many items are in a hash table.
 */
extern HT_HANDLE *ht_create_table(size_t table_size, size_t key_size,
    size_t flags);
extern void ht_destroy_table(HT_HANDLE *handle);
extern void ht_set_cmpfn(HT_HANDLE *handle, HT_CMP cmpfn);
extern size_t ht_get_total_items(HT_HANDLE *handle);

/*
 * Public API to add, remove, replace or find specific items
 * in a hash table.
 */
extern HT_ITEM *ht_add_item(HT_HANDLE *handle, const char *key,
    const void *data);
extern HT_ITEM *ht_replace_item(HT_HANDLE *handle, const char *key,
    const void *data);
extern void *ht_remove_item(HT_HANDLE *handle, const char *key);
extern HT_ITEM *ht_find_item(HT_HANDLE *handle, const char *key);

/*
 * Public API to iterate over a hash table. A mechanism is provided to
 * mark items for deletion while searching the table so that the table
 * is not modified during the search. When the search is complete, all
 * of the marked items can be deleted by calling ht_clean_table. If
 * the item data has been dynamically allocated, a callback can be
 * registered to free the memory. The callback will be invoked with a
 * pointer to each item as it is removed from the hash table.
 */
extern HT_ITEM *ht_findfirst(HT_HANDLE *handle, HT_ITERATOR *iterator);
extern HT_ITEM *ht_findnext(HT_ITERATOR *iterator);
extern void ht_mark_delete(HT_HANDLE *handle, HT_ITEM *item);
extern void ht_clear_delete(HT_HANDLE *handle, HT_ITEM *item);
extern size_t ht_clean_table(HT_HANDLE *handle);
extern HT_CALLBACK ht_register_callback(HT_HANDLE *handle,
    HT_CALLBACK callback);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_HASH_TABLE_H */
