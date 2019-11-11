/*
 * sort_list: a stable sort for lists.
 *
 * Time complexity: O(n*log n)
 *   [assuming limited zero-element fragments]
 *
 * Space complexity: O(1).
 *
 * Stable: yes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib.h"
#include "allocate.h"

#undef PARANOIA
#undef COVERAGE

#ifdef PARANOIA
#include <assert.h>
#else
#define assert(x)
#endif

#ifdef COVERAGE
static unsigned char been_there[256];
#define BEEN_THERE(_c)					\
  do {							\
	if (!been_there[_c]) {				\
		been_there[_c] = 1;			\
		printf ("Been there: %c\n", _c);	\
	}						\
  } while (0)
#else
#define BEEN_THERE(_c) do { } while (0)
#endif

// Sort one fragment.  LIST_NODE_NR (==29) is a bit too high for my
// taste for something this simple.  But, hey, it's O(1).
//
// I would use libc qsort for this, but its comparison function
// gets a pointer indirection extra.
static void array_sort(void **ptr, int nr, int (*cmp)(const void *, const void *))
{
	int i;
	for (i = 1; i < nr; i++) {
		void *p = ptr[i];
		if (cmp(ptr[i-1],p) > 0) {
			int j = i;
			do {
				ptr[j] = ptr[j-1];
				if (!--j)
					break;
			} while (cmp(ptr[j-1], p) > 0);
			ptr[j] = p;
		}
	}
}

#ifdef PARANOIA
static void verify_seq_sorted (struct ptr_list *l, int n,
			       int (*cmp)(const void *, const void *))
{
	int i = 0;
	const void *a;
	struct ptr_list *head = l;

	while (l->nr == 0) {
		l = l->next;
		if (--n == 0)
			return;
		assert (l != head);
	}

	a = l->list[0];
	while (n > 0) {
		const void *b;
		if (++i >= l->nr) {
			i = 0;
			l = l->next;
			n--;
			assert (l != head || n == 0);
			continue;
		}
		b = l->list[i];
		assert (cmp (a, b) <= 0);
		a = b;
	}
}
#endif


#define FLUSH_TO(b)						\
  do {								\
	int nr = (b)->nr;					\
	assert (nbuf >= nr);					\
	memcpy ((b)->list, buffer, nr * sizeof (void *));	\
	nbuf -= nr;						\
	memmove (buffer, buffer + nr, nbuf * sizeof (void *));	\
  } while (0)

#define DUMP_TO(b)						\
  do {								\
        assert (nbuf <= (b)->nr);				\
	memcpy ((b)->list, buffer, nbuf * sizeof (void *));	\
  } while (0)


// Merge two already-sorted sequences of blocks:
//   (b1_1, ..., b1_n)  and  (b2_1, ..., b2_m)
// Since we may be moving blocks around, we return the new head
// of the merged list.
static struct ptr_list *
merge_block_seqs (struct ptr_list *b1, int n,
		  struct ptr_list *b2, int m,
		  int (*cmp)(const void *, const void *))
{
	int i1 = 0, i2 = 0;
	const void *buffer[2 * LIST_NODE_NR];
	int nbuf = 0;
	struct ptr_list *newhead = b1;

	// printf ("Merging %d blocks at %p with %d blocks at %p\n", n, b1, m, b2);

	// Skip empty blocks in b2.
	while (b2->nr == 0) {
		BEEN_THERE('F');
		b2 = b2->next;
		if (--m == 0) {
			BEEN_THERE('G');
			return newhead;
		}
	}

	// Do a quick skip in case entire blocks from b1 are
	// already less than smallest element in b2.
	while (b1->nr == 0 ||
	       cmp (PTR_ENTRY_NOTAG(b1, b1->nr - 1), PTR_ENTRY_NOTAG(b2,0)) < 0) {
		// printf ("Skipping whole block.\n");
		BEEN_THERE('H');
		b1 = b1->next;
		if (--n == 0) {
			BEEN_THERE('I');
			return newhead;	
		}
	}

	while (1) {
		const void *d1 = PTR_ENTRY_NOTAG(b1,i1);
		const void *d2 = PTR_ENTRY_NOTAG(b2,i2);

		assert (i1 >= 0 && i1 < b1->nr);
		assert (i2 >= 0 && i2 < b2->nr);
		assert (b1 != b2);
		assert (n > 0);
		assert (m > 0);

		if (cmp (d1, d2) <= 0) {
			BEEN_THERE('J');
			buffer[nbuf++] = d1;
			// Element from b1 is smaller
			if (++i1 >= b1->nr) {
				BEEN_THERE('L');
				FLUSH_TO(b1);
				do {
					b1 = b1->next;
					if (--n == 0) {
						BEEN_THERE('O');
						while (b1 != b2) {
							BEEN_THERE('P');
							FLUSH_TO(b1);
							b1 = b1->next;
						}
						assert (nbuf == i2);
						DUMP_TO(b2);
						return newhead;
					}
				} while (b1->nr == 0);
				i1 = 0;
			}
		} else {
			BEEN_THERE('K');
			// Element from b2 is smaller
			buffer[nbuf++] = d2;
			if (++i2 >= b2->nr) {
				struct ptr_list *l = b2;
				BEEN_THERE('M');
				// OK, we finished with b2.  Pull it out
				// and plug it in before b1.

				b2 = b2->next;
				b2->prev = l->prev;
				b2->prev->next = b2;
				l->next = b1;
				l->prev = b1->prev;
				l->next->prev = l;
				l->prev->next = l;

				if (b1 == newhead) {
					BEEN_THERE('N');
					newhead = l;
				}

				FLUSH_TO(l);
				b2 = b2->prev;
				do {
					b2 = b2->next;
					if (--m == 0) {
						BEEN_THERE('Q');
						assert (nbuf == i1);
						DUMP_TO(b1);
						return newhead;
					}
				} while (b2->nr == 0);
				i2 = 0;
			}
		}
	}
}


void sort_list(struct ptr_list **plist, int (*cmp)(const void *, const void *))
{
	struct ptr_list *head = *plist, *list = head;
	int blocks = 1;

	if (!head)
		return;

	// Sort all the sub-lists
	do {
		array_sort(list->list, list->nr, cmp);
#ifdef PARANOIA
		verify_seq_sorted (list, 1, cmp);
#endif
		list = list->next;
	} while (list != head);

	// Merge the damn things together
	while (1) {
		struct ptr_list *block1 = head;

		do {
			struct ptr_list *block2 = block1;
			struct ptr_list *next, *newhead;
			int i;

			for (i = 0; i < blocks; i++) {
				block2 = block2->next;
				if (block2 == head) {
					if (block1 == head) {
						BEEN_THERE('A');
						*plist = head;
						return;
					}
					BEEN_THERE('B');
					goto next_pass;
				}						
			}

			next = block2;
			for (i = 0; i < blocks; ) {
				next = next->next;
				i++;
				if (next == head) {
					BEEN_THERE('C');
					break;
				}
				BEEN_THERE('D');
			}

			newhead = merge_block_seqs (block1, blocks,
						    block2, i,
						    cmp);
#ifdef PARANOIA
			verify_seq_sorted (newhead, blocks + i, cmp);
#endif
			if (block1 == head) {
				BEEN_THERE('E');
				head = newhead;
			}
			block1 = next;
		} while (block1 != head);
	next_pass:
		blocks <<= 1;
	}
}
