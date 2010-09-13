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
#include <sys/promif.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include <sys/salib.h>

/*
 * This file defines the interface from the prom and platform-dependent
 * form of the memory lists, to boot's more generic form of the memory
 * list.  For sun4u, the memory list properties are {hi, lo, size_hi, size_lo},
 * which is similar to boot's format, except boot's format is a linked
 * list, and the prom's is an array of these structures. Note that the
 * native property on sparc machines is identical to the property encoded
 * format, so no property decoding is required.
 *
 * Note that the format of the memory lists is really 4 encoded integers,
 * but the encoding is the same as that given in the following structure
 * on SPARC systems ...
 */

struct sun4u_prom_memlist {
	u_longlong_t	addr;
	u_longlong_t	size;
};

struct sun4u_prom_memlist scratch_memlist[200];

struct memlist *fill_memlists(char *name, char *prop, struct memlist *);
extern struct memlist *pfreelistp, *vfreelistp, *pinstalledp;

static struct memlist *reg_to_list(struct sun4u_prom_memlist *a, size_t size,
    struct memlist *old);
static void sort_reglist(struct sun4u_prom_memlist *ar, size_t size);
extern void kmem_init(void);

void
init_memlists(void)
{
	/* this list is a map of pmem actually installed */
	pinstalledp = fill_memlists("memory", "reg", pinstalledp);

	vfreelistp = fill_memlists("virtual-memory", "available", vfreelistp);
	pfreelistp = fill_memlists("memory", "available", pfreelistp);

	kmem_init();
}

struct memlist *
fill_memlists(char *name, char *prop, struct memlist *old)
{
	static pnode_t pmem = 0;
	static pnode_t pmmu = 0;
	pnode_t node;
	size_t links;
	struct memlist *al;
	struct sun4u_prom_memlist *pm = scratch_memlist;

	if (pmem == (pnode_t)0)  {

		/*
		 * Figure out the interesting phandles, one time
		 * only.
		 */

		ihandle_t ih;

		if ((ih = prom_mmu_ihandle()) == (ihandle_t)-1)
			prom_panic("Can't get mmu ihandle");
		pmmu = prom_getphandle(ih);

		if ((ih = prom_memory_ihandle()) == (ihandle_t)-1)
			prom_panic("Can't get memory ihandle");
		pmem = prom_getphandle(ih);
	}

	if (strcmp(name, "memory") == 0)
		node = pmem;
	else
		node = pmmu;

	/*
	 * Read memory node and calculate the number of entries
	 */
	if ((links = prom_getproplen(node, prop)) == -1)
		prom_panic("Cannot get list.\n");
	if (links > sizeof (scratch_memlist)) {
		prom_printf("%s list <%s> exceeds boot capabilities\n",
		    name, prop);
		prom_panic("fill_memlists - memlist size");
	}
	links = links / sizeof (struct sun4u_prom_memlist);


	(void) prom_getprop(node, prop, (caddr_t)pm);
	sort_reglist(pm, links);
	al = reg_to_list(pm, links, old);
	return (al);
}

/*
 *  Simple selection sort routine.
 *  Sorts platform dependent memory lists into ascending order
 */

static void
sort_reglist(struct sun4u_prom_memlist *ar, size_t n)
{
	int i, j, min;
	struct sun4u_prom_memlist temp;

	for (i = 0; i < n; i++) {
		min = i;

		for (j = i+1; j < n; j++)  {
			if (ar[j].addr < ar[min].addr)
				min = j;
		}

		if (i != min)  {
			/* Swap ar[i] and ar[min] */
			temp = ar[min];
			ar[min] = ar[i];
			ar[i] = temp;
		}
	}
}

/*
 *  This routine will convert our platform dependent memory list into
 *  struct memlists's.  And it will also coalesce adjacent  nodes if
 *  possible.
 */
static struct memlist *
reg_to_list(struct sun4u_prom_memlist *ar, size_t n, struct memlist *old)
{
	struct memlist *ptr, *head, *last;
	int i;
	u_longlong_t size = 0;
	u_longlong_t addr = 0;
	u_longlong_t start1, start2;
	int flag = 0;

	if (n == 0)
		return ((struct memlist *)0);

	/*
	 * if there was a memory list allocated before, free it first.
	 */
	if (old)
		(void) add_to_freelist(old);

	head = NULL;
	last = NULL;

	for (i = 0; i < n; i++) {
		start1 = ar[i].addr;
		start2 = ar[i+1].addr;
		if (i < n-1 && (start1 + ar[i].size == start2)) {
			size += ar[i].size;
			if (!flag) {
				addr = start1;
				flag++;
			}
			continue;
		} else if (flag) {
			/*
			 * catch the last one on the way out of
			 * this iteration
			 */
			size += ar[i].size;
		}

		ptr = (struct memlist *)get_memlist_struct();
		if (!head)
			head = ptr;
		if (last)
			last->ml_next = ptr;
		ptr->ml_address = flag ? addr : start1;
		ptr->ml_size = size ? size : ar[i].size;
		ptr->ml_prev = last;
		last = ptr;

		size = 0;
		flag = 0;
		addr = 0;
	}

	last->ml_next = NULL;
	return (head);
}
