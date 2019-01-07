#ifndef PTR_LIST_H
#define PTR_LIST_H

#include <stdlib.h>

/*
 * Generic pointer list manipulation code. 
 *
 * (C) Copyright Linus Torvalds 2003-2005
 */

/* Silly type-safety check ;) */
#define DECLARE_PTR_LIST(listname,type)	struct listname { type *list[1]; }
#define CHECK_TYPE(head,ptr)		(void)(&(ptr) == &(head)->list[0])
#define TYPEOF(head)			__typeof__(&(head)->list[0])
#define VRFY_PTR_LIST(head)		(void)(sizeof((head)->list[0]))

/*
 * The "unnecessary" statement expression is there to shut up a totally 
 * bogus gcc warning about unused expressions, brought on by the fact
 * that we cast the result to the proper type.
 */
#define MKTYPE(head,expr)		({ (TYPEOF(head))(expr); })

#define LIST_NODE_NR (29)

struct ptr_list {
	int nr:8;
	int rm:8;
	struct ptr_list *prev;
	struct ptr_list *next;
	void *list[LIST_NODE_NR];
};

#define ptr_list_empty(x) ((x) == NULL)

void * undo_ptr_list_last(struct ptr_list **head);
void * delete_ptr_list_last(struct ptr_list **head);
int delete_ptr_list_entry(struct ptr_list **, void *, int);
int replace_ptr_list_entry(struct ptr_list **, void *old, void *new, int);
extern void sort_list(struct ptr_list **, int (*)(const void *, const void *));

extern void **__add_ptr_list(struct ptr_list **, void *, unsigned long);
extern void concat_ptr_list(struct ptr_list *a, struct ptr_list **b);
extern void __free_ptr_list(struct ptr_list **);
extern int ptr_list_size(struct ptr_list *);
extern int linearize_ptr_list(struct ptr_list *, void **, int);

/*
 * Hey, who said that you can't do overloading in C?
 *
 * You just have to be creative, and use some gcc
 * extensions..
 */
#define add_ptr_list_tag(list,entry,tag) \
	MKTYPE(*(list), (CHECK_TYPE(*(list),(entry)),__add_ptr_list((struct ptr_list **)(list), (entry), (tag))))
#define add_ptr_list_notag(list,entry)										\
	MKTYPE(*(list), (CHECK_TYPE(*(list),(entry)),__add_ptr_list((struct ptr_list **)(list),			\
								    (void *)((unsigned long)(entry) & ~3UL), 	\
								    (unsigned long)(entry) & 3)))
#define add_ptr_list(list,entry) \
	add_ptr_list_tag(list,entry,0)
#define free_ptr_list(list) \
	do { VRFY_PTR_LIST(*(list)); __free_ptr_list((struct ptr_list **)(list)); } while (0)

#define PTR_ENTRY_NOTAG(h,i)	((h)->list[i])
#define PTR_ENTRY(h,i)	(void *)(~3UL & (unsigned long)PTR_ENTRY_NOTAG(h,i))

static inline void *first_ptr_list(struct ptr_list *list)
{
	struct ptr_list *head = list;

	if (!list)
		return NULL;

	while (list->nr == 0) {
		list = list->next;
		if (list == head)
			return NULL;
	}
	return PTR_ENTRY(list, 0);
}

static inline void *last_ptr_list(struct ptr_list *list)
{
	struct ptr_list *head = list;

	if (!list)
		return NULL;
	list = list->prev;
	while (list->nr == 0) {
		if (list == head)
			return NULL;
		list = list->prev;
	}
	return PTR_ENTRY(list, list->nr-1);
}

#define PTR_DEREF(__head, idx, PTR_ENTRY) ({						\
	struct ptr_list *__list = __head;						\
	while (__list && __list->nr == 0) {						\
		__list = __list->next;							\
		if (__list == __head)							\
			__list = NULL;							\
	}										\
	__list ? PTR_ENTRY(__list, idx) : NULL;						\
})

#define DO_PREPARE(head, ptr, __head, __list, __nr, PTR_ENTRY)				\
	do {										\
		struct ptr_list *__head = (struct ptr_list *) (head);			\
		struct ptr_list *__list = __head;					\
		int __nr = 0;								\
		CHECK_TYPE(head,ptr);							\
		ptr = PTR_DEREF(__head, 0, PTR_ENTRY);					\

#define DO_NEXT(ptr, __head, __list, __nr, PTR_ENTRY)					\
		if (ptr) {								\
			if (++__nr < __list->nr) {					\
				ptr = PTR_ENTRY(__list,__nr);				\
			} else {							\
				__list = __list->next;					\
				ptr = NULL;						\
				while (__list->nr == 0 && __list != __head)		\
					__list = __list->next;				\
				if (__list != __head) {					\
					__nr = 0;					\
					ptr = PTR_ENTRY(__list,0);			\
				}							\
			}								\
		}

#define DO_RESET(ptr, __head, __list, __nr, PTR_ENTRY)					\
	do {										\
		__nr = 0;								\
		__list = __head;							\
		if (__head) ptr = PTR_DEREF(__head, 0, PTR_ENTRY);			\
	} while (0)

#define DO_FINISH(ptr, __head, __list, __nr)						\
		(void)(__nr); /* Sanity-check nesting */				\
	} while (0)

#define PREPARE_PTR_LIST(head, ptr) \
	DO_PREPARE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY)

#define NEXT_PTR_LIST(ptr) \
	DO_NEXT(ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY)

#define RESET_PTR_LIST(ptr) \
	DO_RESET(ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY)

#define FINISH_PTR_LIST(ptr) \
	DO_FINISH(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define DO_FOR_EACH(head, ptr, __head, __list, __nr, PTR_ENTRY) do {			\
	struct ptr_list *__head = (struct ptr_list *) (head);				\
	struct ptr_list *__list = __head;						\
	CHECK_TYPE(head,ptr);								\
	if (__head) {									\
		do { int __nr;								\
			for (__nr = 0; __nr < __list->nr; __nr++) {			\
				do {							\
					ptr = PTR_ENTRY(__list,__nr);			\
					if (__list->rm && !ptr)				\
						continue;				\
					do {

#define DO_END_FOR_EACH(ptr, __head, __list, __nr)					\
					} while (0);					\
				} while (0);						\
			}								\
		} while ((__list = __list->next) != __head);				\
	}										\
} while (0)

#define DO_FOR_EACH_REVERSE(head, ptr, __head, __list, __nr, PTR_ENTRY) do {		\
	struct ptr_list *__head = (struct ptr_list *) (head);				\
	struct ptr_list *__list = __head;						\
	CHECK_TYPE(head,ptr);								\
	if (__head) {									\
		do { int __nr;								\
			__list = __list->prev;						\
			__nr = __list->nr;						\
			while (--__nr >= 0) {						\
				do {							\
					ptr = PTR_ENTRY(__list,__nr);			\
					if (__list->rm && !ptr)				\
						continue;				\
					do {


#define DO_END_FOR_EACH_REVERSE(ptr, __head, __list, __nr)				\
					} while (0);					\
				} while (0);						\
			}								\
		} while (__list != __head);						\
	}										\
} while (0)

#define DO_REVERSE(ptr, __head, __list, __nr, new, __newhead,				\
		   __newlist, __newnr, PTR_ENTRY) do { 					\
	struct ptr_list *__newhead = __head;						\
	struct ptr_list *__newlist = __list;						\
	int __newnr = __nr;								\
	new = ptr;									\
	goto __inside##new;								\
	if (1) {									\
		do {									\
			__newlist = __newlist->prev;					\
			__newnr = __newlist->nr;					\
	__inside##new:									\
			while (--__newnr >= 0) {					\
				do {							\
					new = PTR_ENTRY(__newlist,__newnr);		\
					do {

#define RECURSE_PTR_REVERSE(ptr, new)							\
	DO_REVERSE(ptr, __head##ptr, __list##ptr, __nr##ptr,				\
		   new, __head##new, __list##new, __nr##new, PTR_ENTRY)

#define DO_THIS_ADDRESS(ptr, __head, __list, __nr)					\
	((__typeof__(&(ptr))) (__list->list + __nr))

#define FOR_EACH_PTR(head, ptr) \
	DO_FOR_EACH(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY)

#define END_FOR_EACH_PTR(ptr) \
	DO_END_FOR_EACH(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define FOR_EACH_PTR_NOTAG(head, ptr) \
	DO_FOR_EACH(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_NOTAG)

#define END_FOR_EACH_PTR_NOTAG(ptr) END_FOR_EACH_PTR(ptr)

#define FOR_EACH_PTR_REVERSE(head, ptr) \
	DO_FOR_EACH_REVERSE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY)

#define END_FOR_EACH_PTR_REVERSE(ptr) \
	DO_END_FOR_EACH_REVERSE(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define FOR_EACH_PTR_REVERSE_NOTAG(head, ptr) \
	DO_FOR_EACH_REVERSE(head, ptr, __head##ptr, __list##ptr, __nr##ptr, PTR_ENTRY_NOTAG)

#define END_FOR_EACH_PTR_REVERSE_NOTAG(ptr) END_FOR_EACH_PTR_REVERSE(ptr)

#define THIS_ADDRESS(ptr) \
	DO_THIS_ADDRESS(ptr, __head##ptr, __list##ptr, __nr##ptr)

extern void split_ptr_list_head(struct ptr_list *);

#define DO_SPLIT(ptr, __head, __list, __nr) do {					\
	split_ptr_list_head(__list);							\
	if (__nr >= __list->nr) {							\
		__nr -= __list->nr;							\
		__list = __list->next;							\
	};										\
} while (0)

#define DO_INSERT_CURRENT(new, ptr, __head, __list, __nr) do {				\
	void **__this, **__last;							\
	if (__list->nr == LIST_NODE_NR)							\
		DO_SPLIT(ptr, __head, __list, __nr);					\
	__this = __list->list + __nr;							\
	__last = __list->list + __list->nr - 1;						\
	while (__last >= __this) {							\
		__last[1] = __last[0];							\
		__last--;								\
	}										\
	*__this = (new);								\
	__list->nr++;									\
} while (0)

#define INSERT_CURRENT(new, ptr) \
	DO_INSERT_CURRENT(new, ptr, __head##ptr, __list##ptr, __nr##ptr)

#define DO_DELETE_CURRENT(ptr, __head, __list, __nr) do {				\
	void **__this = __list->list + __nr;						\
	void **__last = __list->list + __list->nr - 1;					\
	while (__this < __last) {							\
		__this[0] = __this[1];							\
		__this++;								\
	}										\
	*__this = (void *)0xf0f0f0f0;							\
	__list->nr--; __nr--;								\
} while (0)

#define DELETE_CURRENT_PTR(ptr) \
	DO_DELETE_CURRENT(ptr, __head##ptr, __list##ptr, __nr##ptr)

#define REPLACE_CURRENT_PTR(ptr, new_ptr)						\
	do { *THIS_ADDRESS(ptr) = (new_ptr); } while (0)

#define DO_MARK_CURRENT_DELETED(ptr, __list) do {	\
		REPLACE_CURRENT_PTR(ptr, NULL);		\
		__list->rm++;				\
	} while (0)

#define MARK_CURRENT_DELETED(ptr) \
	DO_MARK_CURRENT_DELETED(ptr, __list##ptr)

extern void pack_ptr_list(struct ptr_list **);

#define PACK_PTR_LIST(x) pack_ptr_list((struct ptr_list **)(x))

static inline void update_tag(void *p, unsigned long tag)
{
	unsigned long *ptr = p;
	*ptr = tag | (~3UL & *ptr);
}

static inline void *tag_ptr(void *ptr, unsigned long tag)
{
	return (void *)(tag | (unsigned long)ptr);
}

#define CURRENT_TAG(ptr) (3 & (unsigned long)*THIS_ADDRESS(ptr))
#define TAG_CURRENT(ptr,val)	update_tag(THIS_ADDRESS(ptr),val)

#endif /* PTR_LIST_H */
