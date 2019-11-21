#ifndef PTR_LIST_H
#define PTR_LIST_H

#include <stdlib.h>
#include <stdbool.h>

/*
 * Generic pointer list manipulation code. 
 *
 * (C) Copyright Linus Torvalds 2003-2005
 */

/* Silly type-safety check ;) */
#define CHECK_TYPE(head,ptr)		(void)(&(ptr) == &(head)->list[0])
#define TYPEOF(head)			__typeof__(&(head)->list[0])
#define VRFY_PTR_LIST(head)		(void)(sizeof((head)->list[0]))

#define LIST_NODE_NR (13)

#define DECLARE_PTR_LIST(listname, type)	\
	struct listname {			\
		int nr:8;			\
		int rm:8;			\
		struct listname *prev;		\
		struct listname *next;		\
		type *list[LIST_NODE_NR];	\
	}

DECLARE_PTR_LIST(ptr_list, void);


void * undo_ptr_list_last(struct ptr_list **head);
void * delete_ptr_list_last(struct ptr_list **head);
int delete_ptr_list_entry(struct ptr_list **, void *, int);
int replace_ptr_list_entry(struct ptr_list **, void *old, void *new, int);
bool lookup_ptr_list_entry(const struct ptr_list *head, const void *entry);
extern void sort_list(struct ptr_list **, int (*)(const void *, const void *));

extern void concat_ptr_list(struct ptr_list *a, struct ptr_list **b);
extern void copy_ptr_list(struct ptr_list **h, struct ptr_list *t);
extern int ptr_list_size(struct ptr_list *);
extern bool ptr_list_empty(const struct ptr_list *head);
extern bool ptr_list_multiple(const struct ptr_list *head);
extern int linearize_ptr_list(struct ptr_list *, void **, int);
extern void *first_ptr_list(struct ptr_list *);
extern void *last_ptr_list(struct ptr_list *);
extern void *ptr_list_nth_entry(struct ptr_list *, unsigned int idx);
extern void pack_ptr_list(struct ptr_list **);

/*
 * Hey, who said that you can't do overloading in C?
 *
 * You just have to be creative, and use some gcc
 * extensions..
 */
extern void **__add_ptr_list(struct ptr_list **, void *);
extern void **__add_ptr_list_tag(struct ptr_list **, void *, unsigned long);

#define add_ptr_list(list, ptr) ({					\
		struct ptr_list** head = (struct ptr_list**)(list);	\
		CHECK_TYPE(*(list),ptr);				\
		(__typeof__(&(ptr))) __add_ptr_list(head, ptr);		\
	})
#define add_ptr_list_tag(list, ptr, tag) ({				\
		struct ptr_list** head = (struct ptr_list**)(list);	\
		CHECK_TYPE(*(list),ptr);				\
		(__typeof__(&(ptr))) __add_ptr_list_tag(head, ptr, tag);\
	})

extern void __free_ptr_list(struct ptr_list **);
#define free_ptr_list(list)	do {					\
		VRFY_PTR_LIST(*(list));					\
		__free_ptr_list((struct ptr_list **)(list));		\
	} while (0)


////////////////////////////////////////////////////////////////////////
// API
#define PREPARE_PTR_LIST(head, ptr) \
	DO_PREPARE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_UNTAG)

#define NEXT_PTR_LIST(ptr) \
	DO_NEXT(ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_UNTAG)

#define RESET_PTR_LIST(ptr) \
	DO_RESET(ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_UNTAG)

#define FINISH_PTR_LIST(ptr) \
	DO_FINISH(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define RECURSE_PTR_REVERSE(ptr, new)					\
	DO_REVERSE(ptr, __head##ptr, __list##ptr, __nr##ptr,		\
		   new, __head##new, __list##new, __nr##new, PTR_ENTRY_UNTAG)


#define FOR_EACH_PTR(head, ptr) \
	DO_FOR_EACH(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_NOTAG)

#define FOR_EACH_PTR_TAG(head, ptr) \
	DO_FOR_EACH(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_UNTAG)

#define END_FOR_EACH_PTR(ptr) \
	DO_END_FOR_EACH(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define FOR_EACH_PTR_REVERSE(head, ptr) \
	DO_FOR_EACH_REVERSE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_NOTAG)

#define FOR_EACH_PTR_REVERSE_TAG(head, ptr) \
	DO_FOR_EACH_REVERSE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_UNTAG)

#define END_FOR_EACH_PTR_REVERSE(ptr) \
	DO_END_FOR_EACH_REVERSE(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define THIS_ADDRESS(ptr) \
	DO_THIS_ADDRESS(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define INSERT_CURRENT(new, ptr) \
	DO_INSERT_CURRENT(new, __head##ptr, __list##ptr, __nr##ptr)

#define DELETE_CURRENT_PTR(ptr) \
	DO_DELETE_CURRENT(__head##ptr, __list##ptr, __nr##ptr)

#define REPLACE_CURRENT_PTR(ptr, new_ptr)				\
	do { *THIS_ADDRESS(ptr) = (new_ptr); } while (0)

// This replace the current element by a null-pointer.
// It's used when an element of the list must be removed
// but the address of the other elements must not be changed.
#define MARK_CURRENT_DELETED(ptr) \
	DO_MARK_CURRENT_DELETED(ptr, __list##ptr)

#define PACK_PTR_LIST(x) \
	pack_ptr_list((struct ptr_list **)(x))

#define CURRENT_TAG(ptr)	(3 & (unsigned long)*THIS_ADDRESS(ptr))
#define TAG_CURRENT(ptr,val)	update_tag(THIS_ADDRESS(ptr),val)

// backward compatibility for smatch
#define FOR_EACH_PTR_NOTAG(list, ptr)	FOR_EACH_PTR(list, ptr)
#define END_FOR_EACH_PTR_NOTAG(ptr)	END_FOR_EACH_PTR(ptr)

////////////////////////////////////////////////////////////////////////
// Implementation
#define PTR_UNTAG(p)		((void*)(~3UL & (unsigned long)(p)))
#define PTR_ENTRY_NOTAG(h,i)	((h)->list[i])
#define PTR_ENTRY_UNTAG(h,i)	PTR_UNTAG((h)->list[i])


#define PTR_NEXT(ptr, __head, __list, __nr, PTR_ENTRY)			\
	do {								\
		if (__nr < __list->nr) {				\
			ptr = PTR_ENTRY(__list,__nr);			\
			__nr++;						\
			break;						\
		}							\
		ptr = NULL;						\
		__nr = 0;						\
	} while ((__list = __list->next) != __head)			\

#define DO_PREPARE(head, ptr, __head, __list, __nr, PTR_ENTRY)		\
	do {								\
		__typeof__(head) __head = (head);			\
		__typeof__(head) __list = __head;			\
		int __nr = 0;						\
		ptr = NULL;						\
		if (__head) {						\
			PTR_NEXT(ptr, __head, __list, __nr, PTR_ENTRY);	\
		}							\

#define DO_NEXT(ptr, __head, __list, __nr, PTR_ENTRY)			\
		if (ptr) {						\
			PTR_NEXT(ptr, __head, __list, __nr, PTR_ENTRY);	\
		}

#define DO_RESET(ptr, __head, __list, __nr, PTR_ENTRY)			\
	do {								\
		__nr = 0;						\
		__list = __head;					\
		if (__head)						\
			PTR_NEXT(ptr, __head, __list, __nr, PTR_ENTRY);	\
	} while (0)

#define DO_FINISH(ptr, __head, __list, __nr)				\
		VRFY_PTR_LIST(__head); /* Sanity-check nesting */	\
	} while (0)

#define DO_FOR_EACH(head, ptr, __head, __list, __nr, PTR_ENTRY) do {	\
	__typeof__(head) __head = (head);				\
	__typeof__(head) __list = __head;				\
	int __nr;							\
	if (!__head)							\
		break;							\
	do {								\
		for (__nr = 0; __nr < __list->nr; __nr++) {		\
			ptr = PTR_ENTRY(__list,__nr);			\
			if (__list->rm && !ptr)				\
				continue;				\

#define DO_END_FOR_EACH(ptr, __head, __list, __nr)			\
		}							\
	} while ((__list = __list->next) != __head);			\
} while (0)

#define DO_FOR_EACH_REVERSE(head, ptr, __head, __list, __nr, PTR_ENTRY) do { \
	__typeof__(head) __head = (head);				\
	__typeof__(head) __list = __head;				\
	int __nr;							\
	if (!head)							\
		break;							\
	do {								\
		__list = __list->prev;					\
		__nr = __list->nr;					\
		while (--__nr >= 0) {					\
			ptr = PTR_ENTRY(__list,__nr);			\
			if (__list->rm && !ptr)				\
				continue;				\


#define DO_END_FOR_EACH_REVERSE(ptr, __head, __list, __nr)		\
		}							\
	} while (__list != __head);					\
} while (0)

#define DO_REVERSE(ptr, __head, __list, __nr, new, __newhead,		\
		   __newlist, __newnr, PTR_ENTRY) do {			\
	__typeof__(__head) __newhead = __head;				\
	__typeof__(__head) __newlist = __list;				\
	int __newnr = __nr;						\
	new = ptr;							\
	goto __inside##new;						\
	do {								\
		__newlist = __newlist->prev;				\
		__newnr = __newlist->nr;				\
	__inside##new:							\
		while (--__newnr >= 0) {				\
			new = PTR_ENTRY(__newlist,__newnr);		\

#define DO_THIS_ADDRESS(ptr, __head, __list, __nr)			\
	(&__list->list[__nr])


extern void split_ptr_list_head(struct ptr_list *);

#define DO_INSERT_CURRENT(new, __head, __list, __nr) do {		\
	TYPEOF(__head) __this, __last;					\
	if (__list->nr == LIST_NODE_NR) {				\
		split_ptr_list_head((struct ptr_list*)__list);		\
		if (__nr >= __list->nr) {				\
			__nr -= __list->nr;				\
			__list = __list->next;				\
		}							\
	}								\
	__this = __list->list + __nr;					\
	__last = __list->list + __list->nr - 1;				\
	while (__last >= __this) {					\
		__last[1] = __last[0];					\
		__last--;						\
	}								\
	*__this = (new);						\
	__list->nr++;							\
} while (0)

#define DO_DELETE_CURRENT(__head, __list, __nr) do {			\
	TYPEOF(__head) __this = __list->list + __nr;			\
	TYPEOF(__head) __last = __list->list + __list->nr - 1;		\
	while (__this < __last) {					\
		__this[0] = __this[1];					\
		__this++;						\
	}								\
	*__this = (void *)0xf0f0f0f0;					\
	__list->nr--; __nr--;						\
} while (0)


#define DO_MARK_CURRENT_DELETED(ptr, __list) do {			\
		REPLACE_CURRENT_PTR(ptr, NULL);				\
		__list->rm++;						\
	} while (0)


static inline void update_tag(void *p, unsigned long tag)
{
	unsigned long *ptr = p;
	*ptr = tag | (~3UL & *ptr);
}

static inline void *tag_ptr(void *ptr, unsigned long tag)
{
	return (void *)(tag | (unsigned long)ptr);
}

#endif /* PTR_LIST_H */
