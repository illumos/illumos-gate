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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of the driver
 * helper functions
 */

#include <oce_impl.h>

/*
 * inline function to get a list of pages from a dbuf
 *
 * dbuf - memory map from which to get the pa
 * pa_list - physical address array to fill
 * list_size - size of the array
 *
 * return none
 */

static void oce_list_del_node(OCE_LIST_NODE_T *prev_node,
    OCE_LIST_NODE_T *next_node);
static void oce_list_remove(OCE_LIST_NODE_T *list_node);
static void oce_list_insert_node(OCE_LIST_NODE_T  *list_node,
    OCE_LIST_NODE_T *prev_node, OCE_LIST_NODE_T *next_node);
/*
 * function to breakup a block of memory into pages and return the address
 * in an array
 *
 * dbuf - pointer to structure describing DMA-able memory
 * pa_list - [OUT] pointer to an array to return the PA of pages
 * list_size - number of entries in pa_list
 */
void
oce_page_list(oce_dma_buf_t *dbuf,
    struct phys_addr *pa_list, int list_size)
{
	int i = 0;
	uint64_t paddr = 0;

	ASSERT(dbuf != NULL);
	ASSERT(pa_list != NULL);

	paddr = DBUF_PA(dbuf);
	for (i = 0; i < list_size; i++) {
		pa_list[i].lo = ADDR_LO(paddr);
		pa_list[i].hi = ADDR_HI(paddr);
		paddr += PAGE_4K;
	}
} /* oce_page_list */

static inline void
oce_list_insert_node(OCE_LIST_NODE_T  *list_node, OCE_LIST_NODE_T *prev_node,
    OCE_LIST_NODE_T *next_node)
{
	next_node->prev = list_node;
	list_node->next = next_node;
	list_node->prev = prev_node;
	prev_node->next = list_node;
}

static inline void
oce_list_del_node(OCE_LIST_NODE_T *prev_node, OCE_LIST_NODE_T *next_node)
{
	next_node->prev = prev_node;
	prev_node->next = next_node;
}

static inline void
oce_list_remove(OCE_LIST_NODE_T *list_node)
{
	oce_list_del_node(list_node->prev, list_node->next);
	list_node->next = list_node->prev = NULL;
}

void
oce_list_create(OCE_LIST_T  *list_hdr, void *arg)
{
	list_hdr->head.next = list_hdr->head.prev = &list_hdr->head;
	mutex_init(&list_hdr->list_lock, NULL, MUTEX_DRIVER, arg);
	list_hdr->nitems = 0;
}

void
oce_list_destroy(OCE_LIST_T *list_hdr)
{
	ASSERT(list_hdr->nitems == 0);
	list_hdr->head.next = list_hdr->head.prev = NULL;
	mutex_destroy(&list_hdr->list_lock);

}

void
oce_list_insert_tail(OCE_LIST_T *list_hdr, OCE_LIST_NODE_T *list_node)
{
	OCE_LIST_NODE_T *head = &list_hdr->head;

	ASSERT(list_hdr != NULL);
	ASSERT(list_node != NULL);

	mutex_enter(&list_hdr->list_lock);
	oce_list_insert_node(list_node, head->prev, head);
	list_hdr->nitems++;
	mutex_exit(&list_hdr->list_lock);
}

void
oce_list_insert_head(OCE_LIST_T *list_hdr, OCE_LIST_NODE_T *list_node)
{
	OCE_LIST_NODE_T *head = &list_hdr->head;

	ASSERT(list_hdr != NULL);
	ASSERT(list_node != NULL);

	mutex_enter(&list_hdr->list_lock);
	oce_list_insert_node(list_node, head, head->next);
	list_hdr->nitems++;
	mutex_exit(&list_hdr->list_lock);
}

void *
oce_list_remove_tail(OCE_LIST_T *list_hdr)
{
	OCE_LIST_NODE_T *list_node;

	if (list_hdr == NULL) {
		return (NULL);
	}

	mutex_enter(&list_hdr->list_lock);

	if (list_hdr->nitems <= 0) {
		mutex_exit(&list_hdr->list_lock);
		return (NULL);
	}

	list_node = list_hdr->head.prev;
	oce_list_remove(list_node);
	list_hdr->nitems--;
	mutex_exit(&list_hdr->list_lock);
	return (list_node);
}

void *
oce_list_remove_head(OCE_LIST_T  *list_hdr)
{
	OCE_LIST_NODE_T *list_node;

	if (list_hdr == NULL) {
		return (NULL);
	}

	mutex_enter(&list_hdr->list_lock);

	if (list_hdr->nitems <= 0) {
		mutex_exit(&list_hdr->list_lock);
		return (NULL);
	}

	list_node = list_hdr->head.next;

	if (list_node != NULL) {
		oce_list_remove(list_node);
		list_hdr->nitems--;
	}

	mutex_exit(&list_hdr->list_lock);
	return (list_node);
}

boolean_t
oce_list_is_empty(OCE_LIST_T *list_hdr)
{
	if (list_hdr == NULL)
		return (B_TRUE);
	else
		return (list_hdr->nitems <= 0);
}

int
oce_list_items_avail(OCE_LIST_T *list_hdr)
{
	if (list_hdr == NULL)
		return (0);
	else
		return (list_hdr->nitems);
}

void
oce_list_remove_node(OCE_LIST_T  *list_hdr, OCE_LIST_NODE_T *list_node)
{
	mutex_enter(&list_hdr->list_lock);
	oce_list_remove(list_node);
	mutex_exit(&list_hdr->list_lock);
}
