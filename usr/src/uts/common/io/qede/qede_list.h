/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef _QEDE_LIST_H
#define _QEDE_LIST_H

typedef struct qede_list_s {
	struct qede_list_s *next;
	struct qede_list_s *prev;
}qede_list_t;

typedef struct qede_mem_list_entry {
	void *buf;
	size_t			size;
	qede_list_t	 	mem_entry;
} qede_mem_list_entry_t;

typedef struct qede_mem_list {
	qede_list_t	 	mem_list_head;
	kmutex_t		mem_list_lock;
} qede_mem_list_t;

typedef	struct phys_mem_entry {
	qede_list_t 		list_entry;
	ddi_dma_handle_t 	dma_handle;
	ddi_acc_handle_t 	dma_acc_handle;
	size_t 			size;
	void *virt_addr;
	void *paddr;
} qede_phys_mem_entry_t;

typedef struct qede_phys_mem_list {
	qede_list_t		head;
	kmutex_t		lock;
} qede_phys_mem_list_t;

typedef struct qede_mcast_list_entry {
	qede_list_t       mclist_entry;
	u8 *mac;
} qede_mcast_list_entry_t;

typedef struct qede_mcast_list {
	qede_list_t       head;
} qede_mcast_list_t;

typedef qede_list_t osal_list_t;
typedef qede_list_t osal_list_entry_t;

/*
 * Linked list helpers
 */
static inline void 
QEDE_INIT_LIST_HEAD(qede_list_t *list)
{
	list->next = list;
	list->prev = list;
}

#define	OSAL_LIST_INIT(_list_) QEDE_INIT_LIST_HEAD(_list_)

static inline void 
qede_list_add(qede_list_t *new,
    qede_list_t *prev,
    qede_list_t *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline bool 
qede_list_empty(qede_list_t *entry)
{
	return (entry->next == entry);
}

static inline void 
qede_list_del(qede_list_t *prev, qede_list_t *next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void 
QEDE_LIST_ADD(qede_list_t *new, qede_list_t *head)
{
	qede_list_add(new, head, head->next);
}

static inline void 
QEDE_LIST_ADD_TAIL(qede_list_t *new, qede_list_t *head)
{
	qede_list_add(new, head->prev, head);
}

static inline void 
QEDE_LIST_REMOVE(qede_list_t *entry, qede_list_t *head)
{
	qede_list_del(entry->prev, entry->next);
}

static inline void 
list_splice(const qede_list_t *list,
    qede_list_t *prev,
    qede_list_t *next)
{
	qede_list_t *first = list->next;
	qede_list_t *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void 
qede_list_splice(qede_list_t *list,
    qede_list_t *head)
{
	if (!qede_list_empty(list)) {
		list_splice(list, head, head->next);
	}
}

static inline void 
qede_list_splice_tail(qede_list_t *list,
    qede_list_t *head)
{
	if (!qede_list_empty(list)) {
		list_splice(list, head->prev, head);	
	}
}

#define	QEDE_LIST_IS_EMPTY		qede_list_empty
#define	QEDE_LIST_SPLICE		qede_list_splice
#define	QEDE_LIST_SPLICE_TAIL		qede_list_splice_tail
#define	QEDE_LIST_ENTRY			qede_list_entry
#define QEDE_LIST_FIRST_ENTRY		OSAL_LIST_FIRST_ENTRY
#define	QEDE_LIST_EMPTY			OSAL_LIST_IS_EMPTY
#define	QEDE_LIST_FOR_EACH_ENTRY(_entry_, _list_, _type_, _member_) \
	OSAL_LIST_FOR_EACH_ENTRY(_entry_, _list_, _member_, _type_)
#define	QEDE_LIST_FOR_EACH_ENTRY_SAFE	OSAL_LIST_FOR_EACH_ENTRY_SAFE

#endif  /* !_QEDE_LIST_H */

