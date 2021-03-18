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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/salib.h>

caddr_t memlistpage;

/* Always pts to the next free link in the headtable */
/* i.e. it is always memlistpage+tableoffset */
caddr_t tablep = NULL;
static int table_freespace;

/*
 *	Function prototypes
 */
extern void reset_alloc(void);

void
print_memlist(struct memlist *av)
{
	struct memlist *p = av;

	while (p != NULL) {
		printf("addr = 0x%x:0x%x, size = 0x%x:0x%x\n",
		    (uint_t)(p->ml_address >> 32), (uint_t)p->ml_address,
		    (uint_t)(p->ml_size >> 32), (uint_t)p->ml_size);
		p = p->ml_next;
	}

}

/* allocate room for n bytes, return 8-byte aligned address */
void *
getlink(uint_t n)
{
	void *p;
	extern int pagesize;

	if (memlistpage == NULL)
		reset_alloc();

	if (tablep == NULL) {
		/*
		 * Took the following 2 lines out of above test for
		 * memlistpage == null so we can initialize table_freespace
		 */
		table_freespace = pagesize - sizeof (struct bsys_mem);
		tablep = memlistpage + sizeof (struct bsys_mem);
		tablep = (caddr_t)roundup((uintptr_t)tablep, 8);
	}

	if (n == 0)
		return (NULL);

	n = roundup(n, 8);
	p = tablep;

	table_freespace -= n;
	tablep += n;
	if (table_freespace <= 0) {
		char buf[80];

		(void) sprintf(buf,
		    "Boot getlink(): no memlist space (need %d)\n", n);
		prom_panic(buf);
	}

	return (p);
}


/*
 * This is the number of memlist structures allocated in one shot. kept
 * to small number to reduce wastage of memory, it should not be too small
 * to slow down boot.
 */
#define		ALLOC_SZ	5
static struct memlist *free_memlist_ptr = NULL;

/*
 * Free memory lists are maintained as simple single linked lists.
 * get_memlist_struct returns a memlist structure without initializing
 * any of the fields.  It is caller's responsibility to do that.
 */

struct memlist *
get_memlist_struct(void)
{
	struct memlist *ptr;
	int i;

	if (free_memlist_ptr == NULL) {
		ptr = free_memlist_ptr = getlink(ALLOC_SZ *
		    sizeof (struct memlist));
		bzero(free_memlist_ptr, (ALLOC_SZ * sizeof (struct memlist)));
		for (i = 0; i < ALLOC_SZ; i++)
			ptr[i].ml_next = &ptr[i+1];
		ptr[i-1].ml_next = NULL;
	}
	ptr = free_memlist_ptr;
	free_memlist_ptr = ptr->ml_next;
	return (ptr);
}

/*
 * Return memlist structure to free list.
 */
void
add_to_freelist(struct memlist *ptr)
{
	struct memlist *tmp;

	if (free_memlist_ptr == NULL) {
		free_memlist_ptr = ptr;
	} else {
		for (tmp = free_memlist_ptr; tmp->ml_next; tmp = tmp->ml_next)
			;
		tmp->ml_next = ptr;
	}
}
