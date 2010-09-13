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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic hash table library. The hash table is an array of pointers
 * to items. Hash collisions are handled using linked lists from the
 * table entries. A handle is associated with each table, which is used
 * to maintain the hash table.
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

#include <stdlib.h>
#include <strings.h>
#include <smbsrv/hash_table.h>

static size_t ht_default_hash(HT_HANDLE *handle, const char *key);

/*
 * ht_is_power2
 *
 * Inline function to determine if a value is a power of two. This
 * function is used by the library to validate the table size when
 * a new table is created.
 *
 * Returns 1 if value given is power of two, otherwise returns 0.
 */
static size_t
ht_is_power2(size_t value)
{
	return (((value & (value - 1)) == 0)? 1 : 0);
}


/*
 * ht_create_table
 *
 * Create a hash table. The table size must be a positive integer and
 * must be a power of two. The key size must be a positive integer.
 * For null terminated keys, the key size does not need to include the
 * null terminating character. The type of key is indicated by the
 * flags (see hash_table.h).
 *
 * The handle and the table are are malloc'd using a single call, to
 * avoid two allocations. The table is located immediately after the
 * handle.
 *
 * On success a pointer to an opaque handle is returned. Otherwise a
 * null pointer is returned.
 */
HT_HANDLE *
ht_create_table(size_t table_size, size_t key_size, size_t flags)
{
	HT_HANDLE *ht;
	size_t msize;
	size_t i;

	if ((table_size == 0) || (key_size == 0))
		return (NULL);

	if (ht_is_power2(table_size) == 0)
		return (NULL);

	msize = sizeof (HT_HANDLE) + (sizeof (HT_TABLE_ENTRY) * table_size);

	if ((ht = (HT_HANDLE *)malloc(msize)) == 0)
		return (NULL);

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	ht->ht_table = (HT_TABLE_ENTRY *)((char *)ht + sizeof (HT_HANDLE));
	ht->ht_table_size = table_size;
	ht->ht_table_mask = table_size - 1;
	ht->ht_key_size = key_size;
	ht->ht_total_items = 0;
	ht->ht_flags = flags;
	ht->ht_hash = ht_default_hash;
	ht->ht_callback = 0;
	ht->ht_sequence = random();
	ht->ht_cmp = ((flags & HTHF_FIXED_KEY) == 0)
	    ? (HT_CMP)strncmp : (HT_CMP)memcmp;

	for (i = 0; i < table_size; i++)
		bzero(&ht->ht_table[i], sizeof (HT_TABLE_ENTRY));

	return (ht);
}


/*
 * ht_destroy_table
 *
 * Destroy a hash table. All entries in the table are removed, which
 * may invoke the callback if it's installed, and the memory is freed.
 */
void
ht_destroy_table(HT_HANDLE *handle)
{
	HT_ITEM *item;
	HT_ITERATOR iterator;

	if (handle == 0)
		return;

	/* To remove marked entries */
	(void) ht_clean_table(handle);
	while ((item = ht_findfirst(handle, &iterator)) != 0)
		(void) ht_remove_item(handle, item->hi_key);

	free(handle);
}


/*
 * ht_get_total_items
 *
 * Return the total number of items in the table. Returns -1 if the
 * handle is invalid.
 */
size_t
ht_get_total_items(HT_HANDLE *handle)
{
	if (handle == 0)
		return ((size_t)-1);

	return (handle->ht_total_items);
}


/*
 * ht_default_hash
 *
 * Default hash function to compute the table index (hash value) based
 * on the specified key. This will identify the location for the
 * corresponding item in the hash table. The handle and key pointers
 * should be validated before this function is called.
 *
 * Returns the table index location for the item.
 */
static size_t
ht_default_hash(HT_HANDLE *handle, const char *key)
{
	unsigned int hash_ndx = 0;
	size_t rval;

	if ((handle->ht_flags & HTHF_FIXED_KEY) == 0) {
		while (*key) {
			hash_ndx += *key;
			++key;
		}
	} else {
		int key_len = handle->ht_key_size;

		while (key_len--) {
			hash_ndx += *key;
			++key;
		}
	}

	rval = (hash_ndx * HASH_MESH_VALUE) & handle->ht_table_mask;
	return (rval);
}


/*
 * ht_set_cmpfn
 *
 * Replace the current compare function. As the this is function
 * for comparing items' key, it should not be called while there are
 * items in the table.
 */
void
ht_set_cmpfn(HT_HANDLE *handle, HT_CMP cmpfn)
{
	if (handle)
		handle->ht_cmp = cmpfn;
}

/*
 * ht_add_item
 *
 * Adds an item to a hash table. The hash table is identified by the
 * handle and the key is used to generate a hashed index. The data
 * item can be null; it is never dereferenced. We don't check for
 * duplicates. If duplicate keys are added to the table, the last
 * item added will be to the front of the duplicate list.
 *
 * The table sequence number may be modified here.
 *
 * If the item is successfully inserted, a pointer to the item object
 * is returned. Otherwise a null pointer is returned.
 */
HT_ITEM *
ht_add_item(HT_HANDLE *handle, const char *key, const void *data)
{
	size_t h_index, key_len;
	size_t msize;
	HT_ITEM *item;

	if (handle == 0 || key == 0)
		return (NULL);

	if (handle->ht_flags & HTHF_FIXED_KEY) {
		key_len = handle->ht_key_size;
	} else {
		key_len = strlen(key);

		if (key_len > handle->ht_key_size)
			return (NULL);

		/* Include the null terminator */
		++key_len;
	}

	msize = key_len + sizeof (HT_ITEM);

	if ((item = malloc(msize)) == 0)
		return (NULL);

	item->hi_key = (char *)item + sizeof (HT_ITEM);
	(void) memcpy(item->hi_key, key, key_len);
	item->hi_data = (void *)data;
	item->hi_flags = 0;

	h_index = handle->ht_hash(handle, key);

	/*
	 * Add to the front of the list.
	 */
	item->hi_next = handle->ht_table[h_index].he_head;
	handle->ht_table[h_index].he_head = item;

	handle->ht_table[h_index].he_count++;
	handle->ht_total_items++;
	handle->ht_sequence++;

	return (item);
}


/*
 * ht_replace_item
 *
 * Replace an item in a hash table. The item associated with key is removed
 * using ht_remove_item and a new item is added using ht_add_item. We rely
 * on parameter validation in ht_remove_item and ht_add_item.
 *
 * The table sequence number may be modified here.
 */
HT_ITEM *
ht_replace_item(HT_HANDLE *handle, const char *key, const void *data)
{
	(void) ht_remove_item(handle, key);

	return (ht_add_item(handle, key, data));
}


/*
 * ht_remove_item
 *
 * Remove an item from a hash table. If there are duplicate keys, then the
 * first key found will be deleted. Note that the data pointer is never
 * dereferenced.  If a callback is installed, it will be invoked and the
 * return value will be null. Otherwise, the data pointer supplied by the
 * application will be returned. If there is an error, a null pointer will
 * be returned.
 *
 * The table sequence number may be modified here.
 */
void *
ht_remove_item(HT_HANDLE *handle, const char *key)
{
	size_t h_index;
	HT_ITEM *cur, *prev;
	int key_len;
	void *data = 0;

	if (handle == 0 || key == 0)
		return (NULL);

	if ((handle->ht_flags & HTHF_FIXED_KEY) == 0)
		key_len = strlen(key) + 1;
	else
		key_len = handle->ht_key_size;

	h_index = handle->ht_hash(handle, key);

	cur = handle->ht_table[h_index].he_head;
	prev = 0;

	while (cur) {
		if (!(cur->hi_flags & HTIF_MARKED_DELETED) &&
		    (handle->ht_cmp(cur->hi_key, key, key_len) == 0)) {
			/* found key */
			if (prev == 0)
				handle->ht_table[h_index].he_head =
				    cur->hi_next;
			else
				prev->hi_next = cur->hi_next;

			if (handle->ht_callback)
				handle->ht_callback(cur);
			else
				data = cur->hi_data;

			/*
			 * Since the key and the item were allocated as
			 * a single chunk, we only need one free here.
			 */
			free(cur);

			handle->ht_table[h_index].he_count--;
			handle->ht_total_items--;
			handle->ht_sequence++;
			break;
		}

		prev = cur;
		cur = cur->hi_next;
	}

	return (data);
}

/*
 * ht_find_item
 *
 * Find an item in a hash table. If there are duplicate keys then the
 * first item found (which will be the last one added) will be returned.
 *
 * Returns a pointer to an item. Otherwise returns a null pointer to
 * indicate an error or that the key didn't match anything in the table.
 */
HT_ITEM *
ht_find_item(HT_HANDLE *handle, const char *key)
{
	size_t h_index;
	HT_ITEM *cur;
	int key_len;

	if (handle == 0 || key == 0)
		return (NULL);

	if ((handle->ht_flags & HTHF_FIXED_KEY) == 0)
		key_len = strlen(key) + 1;
	else
		key_len = handle->ht_key_size;

	h_index = handle->ht_hash(handle, key);
	cur = handle->ht_table[h_index].he_head;

	while (cur) {
		if (!(cur->hi_flags & HTIF_MARKED_DELETED) &&
		    (handle->ht_cmp(cur->hi_key, key, key_len) == 0))
			return (cur);

		cur = cur->hi_next;
	}

	return (NULL);
}


/*
 * ht_register_callback
 *
 * Register an application callback function that can be used to process
 * an item when it is removed from the table, i.e. free any memory
 * allocated for that data item.
 *
 * The previous callback function pointer, which may be null, before
 * registering the new one. This provides the caller with the option to
 * restore a previous callback as required.
 */
HT_CALLBACK
ht_register_callback(HT_HANDLE *handle, HT_CALLBACK callback)
{
	HT_CALLBACK old_callback;

	if (handle == 0)
		return (NULL);

	old_callback = handle->ht_callback;
	handle->ht_callback = callback;

	return (old_callback);
}


/*
 * ht_clean_table
 *
 * This function removes all the items that are marked for deletion. Note
 * that this will invoke the callback, if one has been installed. If this
 * call is used, the callback mechanism is the only way for an application
 * to free the item data if it was dynamically allocated.
 *
 * The table sequence number may be modified here.
 *
 * Returns 0 if the handle is valid; otherwise returns -1.
 */
size_t
ht_clean_table(HT_HANDLE *handle)
{
	size_t i;
	HT_ITEM *cur, *prev;

	if (handle == 0)
		return ((size_t)-1);

	for (i = 0; i < handle->ht_table_size; i++) {
		cur = handle->ht_table[i].he_head;
		prev = 0;

		while (cur) {
			if (cur->hi_flags & HTIF_MARKED_DELETED) {
				/*
				 * We have a marked item: remove it.
				 */
				if (prev == 0)
					handle->ht_table[i].he_head =
					    cur->hi_next;
				else
					prev->hi_next = cur->hi_next;

				if (handle->ht_callback)
					handle->ht_callback(cur);

				/*
				 * Since the key and the item were allocated as
				 * a single chunk, we only need one free here.
				 */
				free(cur);

				handle->ht_table[i].he_count--;
				handle->ht_sequence++;

				if (prev == 0)
					cur = handle->ht_table[i].he_head;
				else
					cur = prev->hi_next;
				continue;
			}

			prev = cur;
			cur = cur->hi_next;
		}
	}

	return (0);
}


/*
 * ht_mark_delete
 *
 * This function marks an item for deletion, which may be useful when
 * using findfirst/findnext to avoid modifying the table during the
 * table scan. Marked items can be removed later using ht_clean_table.
 */
void
ht_mark_delete(HT_HANDLE *handle, HT_ITEM *item)
{
	if (handle && item) {
		item->hi_flags |= HTIF_MARKED_DELETED;
		handle->ht_total_items--;
	}
}

/*
 * ht_clear_delete
 *
 * This function clear an item from marked for deletion list.
 */
void
ht_clear_delete(HT_HANDLE *handle, HT_ITEM *item)
{
	if (handle && item) {
		item->hi_flags &= ~HTIF_MARKED_DELETED;
		handle->ht_total_items++;
	}
}

/*
 * ht_bucket_search
 *
 * Returns first item which is not marked as deleted
 * in the specified bucket by 'head'
 */
static HT_ITEM *
ht_bucket_search(HT_ITEM *head)
{
	HT_ITEM *item = head;
	while ((item != 0) && (item->hi_flags & HTIF_MARKED_DELETED))
		item = item->hi_next;

	return (item);
}

/*
 * ht_findfirst
 *
 * This function is used to begin an iteration through the hash table.
 * The iterator is initialized and the first item in the table (as
 * determined by the hash algorithm) is returned. The current sequence
 * number is stored in the iterator to determine whether or not the
 * the table has changed between calls. If the table is empty, a null
 * pointer is returned.
 */
HT_ITEM *
ht_findfirst(HT_HANDLE *handle, HT_ITERATOR *iterator)
{
	HT_ITEM *item;
	size_t h_index;

	if (handle == 0 || iterator == 0 || handle->ht_total_items == 0)
		return (NULL);

	(void) memset(iterator, 0, sizeof (HT_ITERATOR));
	iterator->hti_handle = handle;
	iterator->hti_sequence = handle->ht_sequence;

	for (h_index = 0; h_index < handle->ht_table_size; ++h_index) {
		item = ht_bucket_search(handle->ht_table[h_index].he_head);
		if (item != 0) {
			iterator->hti_index = h_index;
			iterator->hti_item = item;
			return (item);
		}
	}

	return (NULL);
}

/*
 * ht_findnext
 *
 * Find the next item in the table for the given iterator. Iterators must
 * be initialized by ht_findfirst, which will also return the first item
 * in the table. If an item is available, a pointer to it is returned.
 * Otherwise a null pointer is returned. A null pointer may indicate:
 *
 *	- an invalid iterator (i.e. ht_findfirst has not been called)
 *	- the table has changed since the previous findfirst/findnext
 *	- the entire table has been traversed
 *
 * The caller can use ht_get_total_items to determine whether or not all
 * of the items in the table have been visited.
 */
HT_ITEM *
ht_findnext(HT_ITERATOR *iterator)
{
	HT_HANDLE *handle;
	HT_ITEM *item;
	size_t total;
	size_t index;

	if (iterator == 0 || iterator->hti_handle == 0 ||
	    iterator->hti_sequence == 0) {
		/* Invalid iterator */
		return (NULL);
	}

	handle = iterator->hti_handle;

	if (iterator->hti_item == 0 ||
	    iterator->hti_sequence != handle->ht_sequence) {
		/*
		 * No more items or the table has changed
		 * since the last call.
		 */
		return (NULL);
	}

	/*
	 * Check for another item in the current bucket.
	 */
	item = ht_bucket_search(iterator->hti_item->hi_next);
	if (item != 0) {
		iterator->hti_item = item;
		return (item);
	}

	/*
	 * Nothing else in the current bucket. Look for another
	 * bucket with something in it and return the head item.
	 */
	total = handle->ht_table_size;
	for (index = iterator->hti_index + 1; index < total; ++index) {
		item = ht_bucket_search(handle->ht_table[index].he_head);
		if (item != 0) {
			iterator->hti_index = index;
			iterator->hti_item = item;
			return (item);
		}
	}

	iterator->hti_index = 0;
	iterator->hti_item = 0;
	iterator->hti_sequence = 0;
	return (NULL);
}
