/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_QUEUE_H
#define	_SYS_QUEUE_H

#include <sys/note.h>
#include <sys/stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file defines five types of data structures: singly-linked lists,
 * lists, simple queues, tail queues, and circular queues.
 *
 * A singly-linked list is headed by a single forward pointer. The
 * elements are singly linked for minimum space and pointer manipulation
 * overhead at the expense of O(n) removal for arbitrary elements. New
 * elements can be added to the list after an existing element or at the
 * head of the list.  Elements being removed from the head of the list
 * should use the explicit macro for this purpose for optimum
 * efficiency. A singly-linked list may only be traversed in the forward
 * direction.  Singly-linked lists are ideal for applications with large
 * datasets and few or no removals or for implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * A circle queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the list.
 * A circle queue may be traversed in either direction, but has a more
 * complex end of list detection.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

#ifdef QUEUE_MACRO_DEBUG
#warn Use QUEUE_MACRO_DEBUG_TRACE and/or QUEUE_MACRO_DEBUG_TRASH
#define	QUEUE_MACRO_DEBUG_TRACE
#define	QUEUE_MACRO_DEBUG_TRASH
#endif

#ifdef QUEUE_MACRO_DEBUG_TRACE
/* Store the last 2 places the queue element or head was altered */
struct qm_trace {
	unsigned long	lastline;
	unsigned long	prevline;
	const char	*lastfile;
	const char	*prevfile;
};

#define	TRACEBUF	struct qm_trace trace;
#define	TRACEBUF_INITIALIZER	{ __LINE__, 0, __FILE__, NULL },

#define	QMD_TRACE_HEAD(head) do {					\
	(head)->trace.prevline = (head)->trace.lastline;		\
	(head)->trace.prevfile = (head)->trace.lastfile;		\
	(head)->trace.lastline = __LINE__;				\
	(head)->trace.lastfile = __FILE__;				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	QMD_TRACE_ELEM(elem) do {					\
	(elem)->trace.prevline = (elem)->trace.lastline;		\
	(elem)->trace.prevfile = (elem)->trace.lastfile;		\
	(elem)->trace.lastline = __LINE__;				\
	(elem)->trace.lastfile = __FILE__;				\
	_NOTE(CONSTCOND)						\
} while (0)

#else	/* !QUEUE_MACRO_DEBUG_TRACE */
#define	QMD_TRACE_ELEM(elem)
#define	QMD_TRACE_HEAD(head)
#define	TRACEBUF
#define	TRACEBUF_INITIALIZER
#endif	/* QUEUE_MACRO_DEBUG_TRACE */

#ifdef QUEUE_MACRO_DEBUG_TRASH
#define	TRASHIT(x)		do {(x) = (void *)-1; } while (0)
#define	QMD_IS_TRASHED(x)	((x) == (void *)(intptr_t)-1)
#else	/* !QUEUE_MACRO_DEBUG_TRASH */
#define	TRASHIT(x)
#define	QMD_IS_TRASHED(x)	0
#endif	/* QUEUE_MACRO_DEBUG_TRASH */

#if defined(QUEUE_MACRO_DEBUG_TRACE) || defined(QUEUE_MACRO_DEBUG_TRASH)
#define	QMD_SAVELINK(name, link)	void **name = (void *)&(link)
#else	/* !QUEUE_MACRO_DEBUG_TRACE && !QUEUE_MACRO_DEBUG_TRASH */
#define	QMD_SAVELINK(name, link)
#endif	/* QUEUE_MACRO_DEBUG_TRACE || QUEUE_MACRO_DEBUG_TRASH */

#ifdef __cplusplus
/*
 * In C++ there can be structure lists and class lists:
 */
#define	QUEUE_TYPEOF(type) type
#else
#define	QUEUE_TYPEOF(type) struct type
#endif

/*
 * Singly-linked List definitions.
 */
#define	SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	SLIST_CLASS_HEAD(name, type)					\
struct name {								\
	class type *slh_first;	/* first element */			\
}

#define	SLIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

#define	SLIST_CLASS_ENTRY(type)						\
struct {								\
	class type *sle_next;		/* next element */		\
}

/*
 * Singly-linked List access methods.
 */
#define	SLIST_FIRST(head)	((head)->slh_first)
#define	SLIST_END(head)		NULL
#define	SLIST_NEXT(elm, field)	((elm)->field.sle_next)
#define	SLIST_EMPTY(head)	((head)->slh_first == SLIST_END(head))

#define	SLIST_FOREACH(var, head, field)					\
	for ((var) = SLIST_FIRST((head));				\
		(var) != SLIST_END(head);				\
		(var) = SLIST_NEXT((var), field))

#define	SLIST_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) != SLIST_END(head) ? (var) : SLIST_FIRST((head))); \
		(var) != SLIST_END(head);				\
		(var) = SLIST_NEXT((var), field))

#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
		(var) != SLIST_END(head) &&				\
		((tvar) = SLIST_NEXT((var), field), 1);			\
		(var) = (tvar))

#define	SLIST_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) != SLIST_END(head) ? (var) : SLIST_FIRST((head))); \
		(var) != SLIST_END(head) &&				\
		((tvar) = SLIST_NEXT((var), field), 1);			\
		(var) = (tvar))

/*
 * Singly-linked List functions.
 */
#define	SLIST_INIT(head) do {						\
	(head)->slh_first = SLIST_END(head);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_CONCAT(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *curelm = SLIST_FIRST(head1);		\
	if (curelm == SLIST_END(head1)) {				\
		if ((SLIST_FIRST(head1) = SLIST_FIRST(head2)) !=	\
		    SLIST_END(head1))					\
			SLIST_INIT(head2);				\
	} else if (SLIST_FIRST(head2) != SLIST_END(head2)) {		\
		while (SLIST_NEXT(curelm, field) != SLIST_END(head1))	\
			curelm = SLIST_NEXT(curelm, field);		\
		SLIST_NEXT(curelm, field) = SLIST_FIRST(head2);		\
		SLIST_INIT(head2);					\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_INSERT_AFTER(slistelm, elm, field) do {			\
	SLIST_NEXT((elm), field) = SLIST_NEXT((slistelm), field);	\
	SLIST_NEXT((slistelm), field) = (elm);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_INSERT_HEAD(head, elm, field) do {			\
	SLIST_NEXT((elm), field) = SLIST_FIRST((head));			\
	SLIST_FIRST((head)) = (elm);					\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_REMOVE_HEAD(head, field) do {				\
	SLIST_FIRST((head)) = SLIST_NEXT(SLIST_FIRST((head)), field);	\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_REMOVE_AFTER(slistelm, field) do {			\
	SLIST_NEXT((slistelm), field) =					\
	    SLIST_NEXT(SLIST_NEXT((slistelm), field), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_REMOVE(head, elm, type, field) do {			\
	QMD_SAVELINK(oldnext, SLIST_NEXT((elm), field));		\
	if (SLIST_FIRST((head)) == (elm)) {				\
		SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		QUEUE_TYPEOF(type) *curelm = SLIST_FIRST((head));	\
		while (SLIST_NEXT(curelm, field) != (elm))		\
			curelm = SLIST_NEXT(curelm, field);		\
		SLIST_REMOVE_AFTER(curelm, field);			\
	}								\
	TRASHIT(*oldnext);						\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SLIST_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = SLIST_FIRST(head1);		\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)

/*
 * Singly-linked Tail queue declarations.
 */
#define	STAILQ_HEAD(name, type)						\
struct name {								\
	struct type *stqh_first;	/* first element */		\
	struct type **stqh_last;	/* addr of last next element */	\
}

#define	STAILQ_CLASS_HEAD(name, type)					\
struct name {								\
	class type *stqh_first;	/* first element */			\
	class type **stqh_last;	/* addr of last next element */		\
}

#define	STAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).stqh_first }

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

#define	STAILQ_CLASS_ENTRY(type)					\
struct {								\
	class type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue access methods.
 */
#define	STAILQ_FIRST(head)	((head)->stqh_first)
#define	STAILQ_END(head)	NULL
#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)
#define	STAILQ_EMPTY(head)	((head)->stqh_first == STAILQ_END(head))

#define	STAILQ_FOREACH(var, head, field)				\
	for ((var) = STAILQ_FIRST(head);				\
	    (var) != STAILQ_END(head);					\
	    (var) = STAILQ_NEXT((var), field))

#define	STAILQ_FOREACH_FROM(var, head, field)				\
	for ((var) =							\
	    ((var) != STAILQ_END(head) ? (var) : STAILQ_FIRST((head))); \
	    (var) != STAILQ_END(head);					\
	    (var) = STAILQ_NEXT((var), field))

#define	STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = STAILQ_FIRST(head);				\
	    (var) != STAILQ_END(head) &&				\
	    ((tvar) = STAILQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

#define	STAILQ_FOREACH_FROM_SAFE(var, head, field, tvar)		\
	for ((var) =							\
	    ((var) != STAILQ_END(head) ? (var) : STAILQ_FIRST((head))); \
	    (var) != STAILQ_END(head) &&				\
	    ((tvar) = STAILQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

/*
 * Singly-linked Tail queue functions.
 */
#define	STAILQ_INIT(head) do {						\
	STAILQ_FIRST(head) = STAILQ_END(head);				\
	(head)->stqh_last = &STAILQ_FIRST((head));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_CONCAT(head1, head2) do {				\
	if (!STAILQ_EMPTY((head2))) {					\
		*(head1)->stqh_last = STAILQ_FIRST((head2));		\
		(head1)->stqh_last = (head2)->stqh_last;		\
		STAILQ_INIT((head2));					\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {		\
	if ((STAILQ_NEXT((elm), field) = STAILQ_NEXT((tqelm), field)) == NULL)\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_NEXT((tqelm), field) = (elm);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((STAILQ_NEXT((elm), field) = STAILQ_FIRST((head))) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_FIRST((head)) = (elm);					\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_INSERT_TAIL(head, elm, field) do {			\
	STAILQ_NEXT((elm), field) = NULL;				\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &STAILQ_NEXT((elm), field);			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_LAST(head, type, field)					\
	(STAILQ_EMPTY((head)) ? NULL :					\
	    container_of((head)->stqh_last,				\
	    QUEUE_TYPEOF(type), field.stqe_next))

#define	STAILQ_REMOVE_HEAD(head, field) do {				\
	if ((STAILQ_FIRST((head)) =					\
	    STAILQ_NEXT(STAILQ_FIRST((head)), field)) == NULL)		\
		(head)->stqh_last = &STAILQ_FIRST((head));		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	    STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_REMOVE(head, elm, type, field) do {			\
	QMD_SAVELINK(oldnext, (elm)->field.stqe_next);			\
	if (STAILQ_FIRST((head)) == (elm)) {				\
		STAILQ_REMOVE_HEAD((head), field);			\
	} else {							\
		QUEUE_TYPEOF(type) *curelm = STAILQ_FIRST(head);	\
		while (STAILQ_NEXT(curelm, field) != (elm))		\
			curelm = STAILQ_NEXT(curelm, field);		\
		STAILQ_REMOVE_AFTER(head, curelm, field);		\
	}								\
	TRASHIT(*oldnext);						\
	_NOTE(CONSTCOND)						\
} while (0)

#define	STAILQ_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = STAILQ_FIRST(head1);		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->stqh_last;		\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
	_NOTE(CONSTCOND)						\
} while (0)

/*
 * List definitions.
 */
#define	LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define	LIST_CLASS_HEAD(name, type)					\
struct name {								\
	class type *lh_first;	/* first element */			\
}

#define	LIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define	LIST_CLASS_ENTRY(type)						\
struct {								\
	class type *le_next;	/* next element */			\
	class type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#define	LIST_FIRST(head)		((head)->lh_first)
#define	LIST_END(head)			NULL
#define	LIST_EMPTY(head)		((head)->lh_first == LIST_END(head))
#define	LIST_NEXT(elm, field)		((elm)->field.le_next)
#define	LIST_PREV(elm, head, type, field)				\
	((elm)->field.le_prev == &LIST_FIRST((head)) ? NULL :		\
	container_of((elm)->field.le_prev, type, field.le_next))

#define	LIST_FOREACH(var, head, field)					\
	for ((var) = LIST_FIRST((head));				\
	    (var) != LIST_END(head);					\
	    (var) = LIST_NEXT((var), field))

#define	LIST_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) != LIST_END(head) ? (var) : LIST_FIRST((head));\
	    (var) != LIST_END(head);					\
	    (var) = LIST_NEXT((var), field))

#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) != LIST_END(head) &&				\
	    ((tvar) = LIST_NEXT((var), field), 1);			\
	    (var) = (tvar))

#define	LIST_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) != LIST_END(head) ? (var) : LIST_FIRST((head));\
	    (var) != LIST_END(head) &&				\
	    ((tvar) = LIST_NEXT((var), field), 1);			\
	    (var) = (tvar))

/*
 * List functions.
 */
#if defined(_KERNEL) && defined(QUEUEDEBUG)
#define	QUEUEDEBUG_LIST_INSERT_HEAD(head, elm, field)			\
	if ((head)->lh_first &&						\
	    (head)->lh_first->field.le_prev != &(head)->lh_first)	\
		panic("LIST_INSERT_HEAD %p %s:%d", (head), __FILE__, __LINE__);
#define	QUEUEDEBUG_LIST_OP(elm, field)					\
	if ((elm)->field.le_next &&					\
	    (elm)->field.le_next->field.le_prev !=			\
	    &(elm)->field.le_next)					\
		panic("LIST_* forw %p %s:%d", (elm), __FILE__, __LINE__);\
	if (*(elm)->field.le_prev != (elm))				\
		panic("LIST_* back %p %s:%d", (elm), __FILE__, __LINE__);
#define	QUEUEDEBUG_LIST_POSTREMOVE(elm, field)				\
	(elm)->field.le_next = (void *)1L;				\
	(elm)->field.le_prev = (void *)1L;
#else
#define	QUEUEDEBUG_LIST_INSERT_HEAD(head, elm, field)
#define	QUEUEDEBUG_LIST_OP(elm, field)
#define	QUEUEDEBUG_LIST_POSTREMOVE(elm, field)
#endif

#define	LIST_INIT(head) do {						\
	LIST_FIRST((head)) = LIST_END(head);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	LIST_INSERT_AFTER(listelm, elm, field) do {			\
	QUEUEDEBUG_LIST_OP((listelm), field)				\
	if ((LIST_NEXT((elm), field) = LIST_NEXT((listelm), field)) != NULL)\
		LIST_NEXT((listelm), field)->field.le_prev =		\
		    &LIST_NEXT((elm), field);				\
	LIST_NEXT((listelm), field) = (elm);				\
	(elm)->field.le_prev = &LIST_NEXT((listelm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	LIST_INSERT_BEFORE(listelm, elm, field) do {			\
	QUEUEDEBUG_LIST_OP((listelm), field)				\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	LIST_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &LIST_NEXT((elm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	LIST_INSERT_HEAD(head, elm, field) do {				\
	QUEUEDEBUG_LIST_INSERT_HEAD((head), (elm), field)		\
	if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)	\
		LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
	LIST_FIRST((head)) = (elm);					\
	(elm)->field.le_prev = &LIST_FIRST((head));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	LIST_REMOVE(elm, field) do {					\
	QUEUEDEBUG_LIST_OP((elm), field)				\
	if (LIST_NEXT((elm), field) != NULL)				\
		LIST_NEXT((elm), field)->field.le_prev =		\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = LIST_NEXT((elm), field);		\
	QUEUEDEBUG_LIST_POSTREMOVE((elm), field)			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	LIST_SWAP(head1, head2, type, field) do {                       \
	QUEUE_TYPEOF(type) *swap_tmp = LIST_FIRST(head1);               \
	LIST_FIRST((head1)) = LIST_FIRST((head2));                      \
	LIST_FIRST((head2)) = swap_tmp;                                 \
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)                   \
		swap_tmp->field.le_prev = &LIST_FIRST((head1));         \
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)                   \
		swap_tmp->field.le_prev = &LIST_FIRST((head2));         \
	_NOTE(CONSTCOND)						\
} while (0)

/*
 * Simple queue definitions.
 */
#define	SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;	/* first element */		\
	struct type **sqh_last;	/* addr of last next element */	\
}

#define	SIMPLEQ_CLASS_HEAD(name, type)					\
struct name {								\
	class type *sqh_first;	/* first element */		\
	class type **sqh_last;	/* addr of last next element */	\
}

#define	SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).sqh_first }

#define	SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;	/* next element */			\
}

#define	SIMPLEQ_CLASS_ENTRY(type)					\
struct {								\
	class type *sqe_next;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#define	SIMPLEQ_FIRST(head)		((head)->sqh_first)
#define	SIMPLEQ_END(head)		NULL
#define	SIMPLEQ_EMPTY(head)		((head)->sqh_first == SIMPLEQ_END(head))
#define	SIMPLEQ_NEXT(elm, field)	((elm)->field.sqe_next)

#define	SIMPLEQ_FOREACH(var, head, field)				\
	for ((var) = SIMPLEQ_FIRST((head));				\
	    (var) != SIMPLEQ_END(head);					\
	    (var) = SIMPLEQ_NEXT((var), field))

#define	SIMPLEQ_FOREACH_FROM(var, head, field)				\
	for ((var) =							\
	    ((var) != SIMPLEQ_END(head) ? (var) : SIMPLEQ_FIRST((head)));\
	    (var) != SIMPLEQ_END(head);					\
	    (var) = SIMPLEQ_NEXT((var), field))

#define	SIMPLEQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SIMPLEQ_FIRST((head));				\
	    (var) != SIMPLEQ_END(head) &&				\
	    ((tvar) = SIMPLEQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

#define	SIMPLEQ_FOREACH_FROM_SAFE(var, head, field, tvar)		\
	for ((var) =							\
	    ((var) != SIMPLEQ_END(head) ? (var) : SIMPLEQ_FIRST((head)));\
	    (var) != SIMPLEQ_END(head) &&				\
	    ((tvar) = SIMPLEQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#define	SIMPLEQ_INIT(head) do {						\
	SIMPLEQ_FIRST((head)) = NULL;					\
	(head)->sqh_last = &SIMPLEQ_FIRST((head));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if ((SIMPLEQ_NEXT((elm), field) = SIMPLEQ_FIRST((head))) == NULL)\
		(head)->sqh_last = &SIMPLEQ_NEXT((elm), field);		\
	SIMPLEQ_FIRST((head)) = (elm);					\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	SIMPLEQ_NEXT((elm), field) = NULL;				\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &SIMPLEQ_NEXT((elm), field);			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if ((SIMPLEQ_NEXT((elm), field) = SIMPLEQ_NEXT((listelm), field)) == \
	    NULL)							\
		(head)->sqh_last = &SIMPLEQ_NEXT((elm), field);		\
	SIMPLEQ_NEXT((listelm), field) = (elm);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_REMOVE_HEAD(head, field) do {				\
	if ((SIMPLEQ_FIRST((head)) =					\
	    SIMPLEQ_NEXT(SIMPLEQ_FIRST((head)), field)) == NULL)	\
		(head)->sqh_last = &SIMPLEQ_FIRST((head));		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((SIMPLEQ_NEXT((elm)) =					\
	    SIMPLEQ_NEXT(SIMPLEQ_NEXT((elm), field), field)) == NULL)	\
		(head)->sqh_last = &SIMPLEQ_NEXT((elm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_REMOVE(head, elm, type, field) do {			\
	if (SIMPLEQ_FIRST((head)) == (elm)) {				\
		SIMPLEQ_REMOVE_HEAD((head), field);			\
	} else {							\
		QUEUE_TYPEOF(type) *curelm = SIMPLEQ_FIRST((head));	\
		while (SIMPLEQ_NEXT(curelm, field) != (elm))		\
			curelm = SIMPLEQ_NEXT(curelm, field);		\
		SIMPLEQ_REMOVE_AFTER((head), curelm, field);		\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_CONCAT(head1, head2) do {				\
	if (!SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		SIMPLEQ_INIT((head2));					\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	SIMPLEQ_LAST(head, type, field)					\
	(SIMPLEQ_EMPTY((head)) ?					\
	    NULL :							\
	    ((QUEUE_TYPEOF(type) *)(void *)				\
	    ((char *)((head)->sqh_last) - offsetof(QUEUE_TYPEOF(type), field))))

/*
 * Tail queue definitions.
 */
#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;		/* first element */		\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}

#define	TAILQ_CLASS_HEAD(name, type)					\
struct name {								\
	class type *tqh_first;		/* first element */		\
	class type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}

#define	TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

#define	TAILQ_CLASS_ENTRY(type)						\
struct {								\
	class type *tqe_next;	/* next element */			\
	class type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

/*
 * Tail queue access methods.
 */
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#define	TAILQ_END(head)			NULL
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define	TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#define	TAILQ_PREV(elm, headname, field) \
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define	TAILQ_EMPTY(head)		((head)->tqh_first == TAILQ_END(head))


#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) != TAILQ_END((head)) ?			\
	    (var) : TAILQ_FIRST((head)));				\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

#define	TAILQ_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) != TAILQ_END((head)) ?			\
	    (var) : TAILQ_FIRST((head)));				\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_NEXT((var), field), 1);			\
	    (var) = (tvar))

#define	TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_PREV((var), headname, field))

#define	TAILQ_FOREACH_REVERSE_FROM(var, head, headname, field)		\
	for ((var) = ((var) != TAILQ_END((head)) ?			\
	    (var) : TAILQ_LAST((head), headname));			\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_PREV((var), headname, field))

#define	TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_PREV((var), headname, field), 1);		\
	    (var) = (tvar))

#define	TAILQ_FOREACH_REVERSE_FROM_SAFE(var, head, headname, field, tvar)\
	for ((var) = ((var) != TAILQ_END((head)) ?			\
	    (var) : TAILQ_LAST((head), headname));			\
	    (var) != TAILQ_END(head) &&					\
	    ((tvar) = TAILQ_PREV((var), headname, field), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#if defined(_KERNEL) && defined(QUEUEDEBUG)
#define	QUEUEDEBUG_TAILQ_INSERT_HEAD(head, elm, field)			\
	if ((head)->tqh_first &&					\
	    (head)->tqh_first->field.tqe_prev != &(head)->tqh_first)	\
		panic("TAILQ_INSERT_HEAD %p %s:%d", (void *)(head),	\
		    __FILE__, __LINE__);
#define	QUEUEDEBUG_TAILQ_INSERT_TAIL(head, elm, field)			\
	if (*(head)->tqh_last != NULL)					\
		panic("TAILQ_INSERT_TAIL %p %s:%d", (void *)(head),	\
		    __FILE__, __LINE__);
#define	QUEUEDEBUG_TAILQ_OP(elm, field)					\
	if ((elm)->field.tqe_next &&					\
	    (elm)->field.tqe_next->field.tqe_prev !=			\
	    &(elm)->field.tqe_next)					\
		panic("TAILQ_* forw %p %s:%d", (void *)(elm),		\
		    __FILE__, __LINE__);\
	if (*(elm)->field.tqe_prev != (elm))				\
		panic("TAILQ_* back %p %s:%d", (void *)(elm),		\
		    __FILE__, __LINE__);
#define	QUEUEDEBUG_TAILQ_PREREMOVE(head, elm, field)			\
	if ((elm)->field.tqe_next == NULL &&				\
	    (head)->tqh_last != &(elm)->field.tqe_next)			\
		panic("TAILQ_PREREMOVE head %p elm %p %s:%d",		\
		    (void *)(head), (void *)(elm), __FILE__, __LINE__);
#define	QUEUEDEBUG_TAILQ_POSTREMOVE(elm, field)				\
	(elm)->field.tqe_next = (void *)1L;				\
	(elm)->field.tqe_prev = (void *)1L;
#else
#define	QUEUEDEBUG_TAILQ_INSERT_HEAD(head, elm, field)
#define	QUEUEDEBUG_TAILQ_INSERT_TAIL(head, elm, field)
#define	QUEUEDEBUG_TAILQ_OP(elm, field)
#define	QUEUEDEBUG_TAILQ_PREREMOVE(head, elm, field)
#define	QUEUEDEBUG_TAILQ_POSTREMOVE(elm, field)
#endif

#define	TAILQ_INIT(head) do {						\
	TAILQ_FIRST((head)) = TAILQ_END((head));			\
	(head)->tqh_last = &TAILQ_FIRST((head));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_INSERT_HEAD(head, elm, field) do {			\
	QUEUEDEBUG_TAILQ_INSERT_HEAD((head), (elm), field)		\
	if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)	\
		TAILQ_FIRST((head))->field.tqe_prev =			\
		    &TAILQ_NEXT((elm), field);				\
	else								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	TAILQ_FIRST((head)) = (elm);					\
	(elm)->field.tqe_prev = &TAILQ_FIRST((head));			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_INSERT_TAIL(head, elm, field) do {			\
	QUEUEDEBUG_TAILQ_INSERT_TAIL((head), (elm), field)		\
	TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &TAILQ_NEXT((elm), field);			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	QUEUEDEBUG_TAILQ_OP((listelm), field)				\
	if ((TAILQ_NEXT((elm), field) = TAILQ_NEXT((listelm), field)) != NULL)\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    &TAILQ_NEXT((elm), field);				\
	else								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	TAILQ_NEXT((listelm), field) = (elm);				\
	(elm)->field.tqe_prev = &TAILQ_NEXT((listelm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	QUEUEDEBUG_TAILQ_OP((listelm), field)				\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	TAILQ_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);		\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_REMOVE(head, elm, field) do {				\
	QUEUEDEBUG_TAILQ_PREREMOVE((head), (elm), field)		\
	QUEUEDEBUG_TAILQ_OP((elm), field)				\
	if ((TAILQ_NEXT((elm), field)) != NULL)				\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);		\
	QUEUEDEBUG_TAILQ_POSTREMOVE((elm), field);			\
	_NOTE(CONSTCOND)						\
} while (0)

#define	TAILQ_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_first = TAILQ_FIRST((head1));		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->tqh_last;		\
	TAILQ_FIRST((head1)) = TAILQ_FIRST((head2));			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	TAILQ_FIRST((head2)) = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = TAILQ_FIRST((head1))) != NULL)		\
		swap_first->field.tqe_prev = &TAILQ_FIRST((head1));	\
	else								\
		(head1)->tqh_last = &TAILQ_FIRST((head1));		\
	if ((swap_first = TAILQ_FIRST((head2))) != NULL)		\
		swap_first->field.tqe_prev = &TAILQ_FIRST((head2));	\
	else								\
		(head2)->tqh_last = &TAILQ_FIRST((head2));		\
	_NOTE(CONSTCOND)						\
} while (0)

/*
 * Circular queue definitions. Do not use. We still keep the macros
 * for compatibility but because of pointer aliasing issues their use
 * is discouraged!
 */
#define	CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;		/* first element */	\
	struct type *cqh_last;		/* last element */		\
}

#define	CIRCLEQ_HEAD_INITIALIZER(head)					\
	{ (void *)&head, (void *)&head }

#define	CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;		/* next element */		\
	struct type *cqe_prev;		/* previous element */		\
}

/*
 * Circular queue access methods.
 */
#define	CIRCLEQ_EMPTY(head)		((head)->cqh_first == (void *)(head))
#define	CIRCLEQ_FIRST(head)		((head)->cqh_first)
#define	CIRCLEQ_LAST(head)		((head)->cqh_last)
#define	CIRCLEQ_NEXT(elm, field)	((elm)->field.cqe_next)
#define	CIRCLEQ_PREV(elm, field)	((elm)->field.cqe_prev)

#define	CIRCLEQ_LOOP_NEXT(head, elm, field)				\
	(((elm)->field.cqe_next == (void *)(head))			\
	    ? ((head)->cqh_first)					\
	    : (elm->field.cqe_next))
#define	CIRCLEQ_LOOP_PREV(head, elm, field)				\
	(((elm)->field.cqe_prev == (void *)(head))			\
	    ? ((head)->cqh_last)					\
	    : (elm->field.cqe_prev))

#define	CIRCLEQ_FOREACH(var, head, field)				\
	for ((var) = CIRCLEQ_FIRST((head));				\
		(var) != (void *)(head);				\
		(var) = CIRCLEQ_NEXT((var), field))

#define	CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for ((var) = CIRCLEQ_LAST((head));				\
		(var) != (void *)(head);				\
		(var) = CIRCLEQ_PREV((var), field))

/*
 * Circular queue functions.
 */
#define	CIRCLEQ_INIT(head) do {						\
	(head)->cqh_first = (void *)(head);				\
	(head)->cqh_last = (void *)(head);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm)->field.cqe_next;		\
	(elm)->field.cqe_prev = (listelm);				\
	if ((listelm)->field.cqe_next == (void *)(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->field.cqe_next->field.cqe_prev = (elm);	\
	(listelm)->field.cqe_next = (elm);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm);				\
	(elm)->field.cqe_prev = (listelm)->field.cqe_prev;		\
	if ((listelm)->field.cqe_prev == (void *)(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->field.cqe_prev->field.cqe_next = (elm);	\
	(listelm)->field.cqe_prev = (elm);				\
	_NOTE(CONSTCOND)						\
} while (0)

#define	CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.cqe_next = (head)->cqh_first;			\
	(elm)->field.cqe_prev = (void *)(head);				\
	if ((head)->cqh_last == (void *)(head))			\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->field.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
	_NOTE(CONSTCOND)						\
} while (0)

#define	CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.cqe_next = (void *)(head);				\
	(elm)->field.cqe_prev = (head)->cqh_last;			\
	if ((head)->cqh_first == (void *)(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->field.cqe_next = (elm);		\
	(head)->cqh_last = (elm);					\
	_NOTE(CONSTCOND)						\
} while (0)

#define	CIRCLEQ_REMOVE(head, elm, field) do {				\
	if ((elm)->field.cqe_next == (void *)(head))			\
		(head)->cqh_last = (elm)->field.cqe_prev;		\
	else								\
		(elm)->field.cqe_next->field.cqe_prev =			\
		    (elm)->field.cqe_prev;				\
	if ((elm)->field.cqe_prev == (void *)(head))			\
		(head)->cqh_first = (elm)->field.cqe_next;		\
	else								\
		(elm)->field.cqe_prev->field.cqe_next =			\
		    (elm)->field.cqe_next;				\
	_NOTE(CONSTCOND)						\
} while (0)

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_QUEUE_H */
