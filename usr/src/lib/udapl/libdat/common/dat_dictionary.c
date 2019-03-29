/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 *
 * MODULE: dat_dictionary.c
 *
 * PURPOSE: dictionary data structure
 *
 * $Id: dat_dictionary.c,v 1.11 2003/08/05 19:01:48 jlentini Exp $
 */


#include "dat_dictionary.h"


/*
 *
 * Structures
 *
 */

typedef struct DAT_DICTIONARY_NODE
{
    DAT_PROVIDER_INFO 		key;
    DAT_DICTIONARY_DATA		data;
    struct DAT_DICTIONARY_NODE 	*prev;
    struct DAT_DICTIONARY_NODE 	*next;
} DAT_DICTIONARY_NODE;


struct DAT_DICTIONARY
{
    DAT_DICTIONARY_NODE 	*head;
    DAT_DICTIONARY_NODE 	*tail;
    DAT_COUNT			size;
};

/*
 *
 * Function Declarations
 *
 */

static DAT_RETURN
dat_dictionary_key_dup(
    const DAT_PROVIDER_INFO 	*old_key,
    DAT_PROVIDER_INFO 		*new_key);

static DAT_BOOLEAN
dat_dictionary_key_is_equal(
    const DAT_PROVIDER_INFO 	*key_a,
    const DAT_PROVIDER_INFO 	*key_b);


/*
 *
 * External Functions
 *
 */


/*
 * Function: dat_dictionary_create
 */

DAT_RETURN
dat_dictionary_create(
    OUT DAT_DICTIONARY **pp_dictionary)
{
	DAT_DICTIONARY	*p_dictionary;
	DAT_RETURN status;

	dat_os_assert(NULL != pp_dictionary);

	status = DAT_SUCCESS;

	/* create the dictionary */
	p_dictionary = dat_os_alloc(sizeof (DAT_DICTIONARY));
	if (NULL == p_dictionary) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dat_os_memset(p_dictionary, '\0', sizeof (DAT_DICTIONARY));

	/* create the head node */
	p_dictionary->head = dat_os_alloc(sizeof (DAT_DICTIONARY_NODE));
	if (NULL == p_dictionary->head) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dat_os_memset(p_dictionary->head, '\0',
	    sizeof (DAT_DICTIONARY_NODE));

	/* create the tail node */
	p_dictionary->tail = dat_os_alloc(sizeof (DAT_DICTIONARY_NODE));
	if (NULL == p_dictionary->tail)	{
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	(void) dat_os_memset(p_dictionary->tail, '\0',
	    sizeof (DAT_DICTIONARY_NODE));

	p_dictionary->head->next = p_dictionary->tail;
	p_dictionary->tail->prev = p_dictionary->head;

	*pp_dictionary = p_dictionary;

bail:
	if (DAT_SUCCESS != status) {
		if (NULL != p_dictionary) {
			if (NULL != p_dictionary->head) {
				dat_os_free(p_dictionary->head,
				    sizeof (DAT_DICTIONARY_NODE));
			}

			if (NULL != p_dictionary->tail) {
				dat_os_free(p_dictionary->tail,
				    sizeof (DAT_DICTIONARY_NODE));
			}

			dat_os_free(p_dictionary, sizeof (DAT_DICTIONARY));
		}

	}

	return (status);
}


/*
 * Function: dat_dictionary_destroy
 */

DAT_RETURN
dat_dictionary_destroy(
    IN  DAT_DICTIONARY *p_dictionary)
{
	DAT_DICTIONARY_NODE *cur_node;

	dat_os_assert(NULL != p_dictionary);

	while (NULL != p_dictionary->head) {
		cur_node = p_dictionary->head;
		p_dictionary->head = cur_node->next;

		dat_os_free(cur_node, sizeof (DAT_DICTIONARY_NODE));
	}

	dat_os_free(p_dictionary, sizeof (DAT_DICTIONARY));

	return (DAT_SUCCESS);
}


/*
 * Function: dat_dictionary_size
 */

DAT_RETURN
dat_dictionary_size(
    IN  DAT_DICTIONARY *p_dictionary,
    OUT DAT_COUNT *p_size)
{
	dat_os_assert(NULL != p_dictionary);
	dat_os_assert(NULL != p_size);

	*p_size = p_dictionary->size;

	return (DAT_SUCCESS);
}


/*
 * Function: dat_dictionary_entry_create
 */

DAT_RETURN
dat_dictionary_entry_create(
    OUT DAT_DICTIONARY_ENTRY *p_entry)
{
	DAT_DICTIONARY_NODE 	*node;
	DAT_RETURN		dat_status;

	dat_os_assert(NULL != p_entry);

	dat_status = DAT_SUCCESS;

	node = dat_os_alloc(sizeof (DAT_DICTIONARY_NODE));
	if (NULL == node) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	*p_entry = node;

bail:
	return (dat_status);
}


/*
 * Function: dat_dictionary_entry_destroy
 */

DAT_RETURN
dat_dictionary_entry_destroy(
    OUT DAT_DICTIONARY_ENTRY entry)
{
	dat_os_free(entry, sizeof (DAT_DICTIONARY_NODE));
	return (DAT_SUCCESS);
}


/*
 * Function: dat_dictionary_insert
 */

DAT_RETURN
dat_dictionary_insert(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_ENTRY entry,
    IN  const DAT_PROVIDER_INFO *key,
    IN  DAT_DICTIONARY_DATA data)
{
	DAT_RETURN		dat_status;
	DAT_DICTIONARY_NODE *cur_node, *prev_node, *next_node;

	dat_os_assert(NULL != p_dictionary);
	dat_os_assert(NULL != entry);

	cur_node = entry;

	if (DAT_SUCCESS == dat_dictionary_search(p_dictionary, key, NULL)) {
		dat_status = DAT_ERROR(DAT_PROVIDER_ALREADY_REGISTERED, 0);
		goto bail;
	}

	dat_status = dat_dictionary_key_dup(key, &cur_node->key);
	if (DAT_SUCCESS != dat_status) {
		goto bail;
	}

	/* insert node at end of list to preserve registration order */
	prev_node = p_dictionary->tail->prev;
	next_node = p_dictionary->tail;

	cur_node->data = data;
	cur_node->next = next_node;
	cur_node->prev = prev_node;

	prev_node->next = cur_node;
	next_node->prev = cur_node;

	p_dictionary->size++;

bail:
	return (dat_status);
}


/*
 * Function: dat_dictionary_search
 */

DAT_RETURN
dat_dictionary_search(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  const DAT_PROVIDER_INFO *key,
    OUT DAT_DICTIONARY_DATA *p_data)
{
	DAT_DICTIONARY_NODE *cur_node;
	DAT_RETURN status;

	dat_os_assert(NULL != p_dictionary);

	status = DAT_ERROR(DAT_NAME_NOT_FOUND, 0);

	for (cur_node = p_dictionary->head->next;
		p_dictionary->tail != cur_node;
		cur_node = cur_node->next) {
		if (DAT_TRUE == dat_dictionary_key_is_equal(&cur_node->key,
		    key)) {
			if (NULL != p_data) {
				*p_data = cur_node->data;
			}

			status = DAT_SUCCESS;
			goto bail;
		}
	}

bail:
	return (status);
}


/*
 * Function: dat_dictionary_enumerate
 */

DAT_RETURN
dat_dictionary_enumerate(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_DATA array[],
    IN  DAT_COUNT array_size)
{
	DAT_DICTIONARY_NODE *cur_node;
	DAT_COUNT i;
	DAT_RETURN status;

	dat_os_assert(NULL != p_dictionary);
	dat_os_assert(NULL != array);

	status = DAT_SUCCESS;

	if (array_size < p_dictionary->size) {
		status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, 0);
		goto bail;
	}

	for (cur_node = p_dictionary->head->next, i = 0;
		p_dictionary->tail != cur_node;
		cur_node = cur_node->next, i++) {
		array[i] = cur_node->data;
	}

bail:
	return (status);
}


/*
 * Function: dat_dictionary_remove
 */

DAT_RETURN
dat_dictionary_remove(
    IN  DAT_DICTIONARY *p_dictionary,
    IN  DAT_DICTIONARY_ENTRY *p_entry,
    IN  const DAT_PROVIDER_INFO *key,
    OUT DAT_DICTIONARY_DATA *p_data)
{
	DAT_DICTIONARY_NODE *cur_node, *prev_node, *next_node;
	DAT_RETURN status;

	dat_os_assert(NULL != p_dictionary);
	dat_os_assert(NULL != p_entry);

	status = DAT_ERROR(DAT_NAME_NOT_FOUND, 0);

	for (cur_node = p_dictionary->head->next;
		p_dictionary->tail != cur_node;
		cur_node = cur_node->next) {
		if (DAT_TRUE == dat_dictionary_key_is_equal(&cur_node->key,
		    key)) {
			if (NULL != p_data) {
				*p_data = cur_node->data;
			}

			prev_node = cur_node->prev;
			next_node = cur_node->next;

			prev_node->next = next_node;
			next_node->prev = prev_node;

			*p_entry = cur_node;

			p_dictionary->size--;

			status = DAT_SUCCESS;
			goto bail;
		}
	}

bail:
	return (status);
}


/*
 *
 * Internal Function Definitions
 *
 */


/*
 * Function: dat_dictionary_key_create
 */

DAT_RETURN
dat_dictionary_key_dup(
    const DAT_PROVIDER_INFO 	*old_key,
    DAT_PROVIDER_INFO 		*new_key)
{
	dat_os_assert(NULL != old_key);
	dat_os_assert(NULL != new_key);

	(void) dat_os_strncpy(new_key->ia_name, old_key->ia_name,
	    DAT_NAME_MAX_LENGTH);
	new_key->dapl_version_major = old_key->dapl_version_major;
	new_key->dapl_version_minor = old_key->dapl_version_minor;
	new_key->is_thread_safe = old_key->is_thread_safe;

	return (DAT_SUCCESS);
}


/*
 * Function: dat_dictionary_key_is_equal
 */

DAT_BOOLEAN
dat_dictionary_key_is_equal(
    const DAT_PROVIDER_INFO	*key_a,
    const DAT_PROVIDER_INFO	*key_b)
{
	if ((dat_os_strlen(key_a->ia_name) == dat_os_strlen(key_b->ia_name)) &&
	    (!dat_os_strncmp(key_a->ia_name, key_b->ia_name,
		dat_os_strlen(key_a->ia_name))) &&
	    (key_a->dapl_version_major == key_b->dapl_version_major) &&
	    (key_a->dapl_version_minor == key_b->dapl_version_minor) &&
	    (key_a->is_thread_safe == key_b->is_thread_safe)) {
		return (DAT_TRUE);
	} else {
		return (DAT_FALSE);
	}
}
