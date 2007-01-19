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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include "multiboot.h"
#include "util.h"
#include "standalloc.h"
#include "debug.h"

#define	dprintf	if (debug & D_ALLOC) printf

/* memory lists */
struct memlist *pinstalledp, *pfreelistp, *vfreelistp, *pbooterp;
struct memlist *ppcimemp, *pramdiskp;

extern multiboot_info_t *mbi;
extern multiboot_header_t *mbh;
extern int verbosemode;

extern int map_phys(int, size_t, caddr_t, uint64_t);

/* scratch memory */
uint_t magic_phys = MAGIC_PHYS;
uint_t lomem_phys = 0x1000000;	/* try not to use memory below 16M */
uint64_t scratchmem_start, scratchmem_end;
uint64_t ramdisk_start, ramdisk_end;

static void
memlist_dump(struct memlist *listp)
{
	while (listp) {
		dprintf("(0x%x%x, 0x%x%x)",
		    (int)(listp->address >> 32), (int)listp->address,
		    (int)(listp->size >> 32), (int)listp->size);
		listp = listp->next;
	}
	dprintf("\n");
}

static struct memlist *
memlist_alloc()
{
	return ((struct memlist *)bkmem_alloc(sizeof (struct memlist)));
}

static void
memlist_free(struct memlist *buf)
{
	bkmem_free(buf, sizeof (struct memlist));
}

/* insert in the order of addresses */
static void
memlist_insert(struct memlist **listp, uint64_t addr, uint64_t size)
{
	struct memlist *entry;
	struct memlist *prev = 0, *next;

	/* find the location in list */
	next = *listp;
	while (next && next->address < addr) {
		prev = next;
		next = prev->next;
	}

	if (prev == 0) {
		entry = memlist_alloc();
		entry->address = addr;
		entry->size = size;
		entry->next = *listp;
		*listp = entry;
		return;
	}

	/* coalesce entries if possible */
	if (addr == prev->address + prev->size) {
		prev->size += size;
	} else {
		entry = memlist_alloc();
		entry->address = addr;
		entry->size = size;
		entry->next = next;
		prev->next = entry;
	}
}

/* delet memory chunks, assuming list sorted by address */
static int
memlist_remove(struct memlist **listp, uint64_t addr, uint64_t size)
{
	struct memlist *entry;
	struct memlist *prev = 0, *next;

	/* find the location in list */
	next = *listp;
	while (next && (next->address + next->size < addr)) {
		prev = next;
		next = prev->next;
	}

	if (next == 0 || (addr < next->address)) {
		dprintf("memlist_remove: addr 0x%x%x, size 0x%x%x"
		    " not contained in list\n",
		    (int)(addr >> 32), (int)addr,
		    (int)(size >> 32), (int)size);
		memlist_dump(*listp);
		return (-1);
	}

	if (addr > next->address) {
		uint64_t oldsize = next->size;
		next->size = addr - next->address;
		if ((next->address + oldsize) > (addr + size)) {
			entry = memlist_alloc();
			entry->address = addr + size;
			entry->size = next->address + oldsize - addr - size;
			entry->next = next->next;
			next->next = entry;
		}
	} else if ((next->address + next->size) > (addr + size)) {
		/* addr == next->address */
		next->address = addr + size;
		next->size -= size;
	} else {
		/* the entire chunk is deleted */
		if (prev == 0) {
			*listp = next->next;
		} else {
			prev->next = next->next;
		}
		memlist_free(next);
	}

	return (0);
}

/*
 * find and claim a memory chunk of given size, bypassing
 * scratch memory + room below 8MB
 */
static uint64_t
memlist_find(struct memlist **listp, uint_t size, int align)
{
	uint_t delta;
	uint64_t paddr;
	struct memlist *prev = 0, *next;

	/* find the chunk with sufficient size */
	next = *listp;
	while (next &&
	    (next->address < lomem_phys || (next->size < size + align - 1))) {
		prev = next;
		next = prev->next;
	}

	if (next == NULL)
		return (0);

	paddr = next->address;
	delta = (uint_t)paddr & (align - 1);
	if (delta)
		paddr += align - delta;
	(void) memlist_remove(listp, paddr, size);
	return (paddr);
}

static void
memlists_print()
{
	printf("Installed physical memory:\n");
	memlist_dump(pinstalledp);
	printf("BIOS reserved physical memory:\n");
	memlist_dump(ppcimemp);
	printf("Booter occupied memory (including modules):\n");
	memlist_dump(pbooterp);
	printf("Ramdisk memory:\n");
	memlist_dump(pramdiskp);
	printf("Available physical memory:\n");
	memlist_dump(pfreelistp);
	printf("Available virtual memory:\n");
	memlist_dump(vfreelistp);
}

void
setup_memlists(void)
{
	int i;
	uint64_t address, size;
	mb_memory_map_t *mmap;
	mb_module_t *mod;
	struct memlist *entry;

	/*
	 * initialize scratch memory so we can call bkmem_alloc
	 * to get memory for keeping track of memory lists
	 */
	reset_alloc();

	/*
	 * initialize RAM list (pinstalledp) and available pci memory
	 * PCI memory excludes memory below 1M (realmode)
	 */
	memlist_insert(&ppcimemp, 0x100000, 0xFFF00000ULL);
	for (mmap = (mb_memory_map_t *)mbi->mmap_addr;
	    (unsigned long) mmap < mbi->mmap_addr + mbi->mmap_length;
	    mmap = (mb_memory_map_t *)((unsigned long)mmap
	    + mmap->size + sizeof (mmap->size))) {
		address = ((uint64_t)mmap->base_addr_high << 32) +
		    (uint64_t)mmap->base_addr_low;
		size = ((uint64_t)mmap->length_high << 32) +
		    (uint64_t)mmap->length_low;

		switch (mmap->type) {
		case 1:		/* RAM */
			memlist_insert(&pinstalledp, address, size);
			memlist_insert(&pfreelistp, address, size);
			/*FALLTHROUGH*/
		default:	/* Take out of available pci memory space */
			(void) memlist_remove(&ppcimemp, address, size);
			break;
		}
	}

	/*
	 * initialize memory occupied by the booter
	 * make the boundary page aligned to simplify
	 * MMU stuff
	 */
	address = rounddown(mbh->load_addr, PAGESIZE);
	size = roundup(mbh->bss_end_addr, PAGESIZE) -
	    rounddown(mbh->load_addr, PAGESIZE);
	memlist_insert(&pbooterp, address, size);

	/* where the modules are in memory */
	for (i = 0, mod = (mb_module_t *)mbi->mods_addr;
	    i < mbi->mods_count; i++, mod++) {
		/* round up to page boundaries */
		address = rounddown(mod->mod_start, PAGESIZE);
		size = roundup(mod->mod_end, PAGESIZE) -
		    rounddown(mod->mod_start, PAGESIZE);

		/* assume first one is ramdisk */
		if (ramdisk_end == 0) {
			ramdisk_start = mod->mod_start;
			ramdisk_end = mod->mod_end;
			if (verbosemode) {
				printf("ramdisk is at 0x%llx-0x%llx\n",
				    ramdisk_start, ramdisk_end);
			}
			memlist_insert(&pramdiskp, address, size);
		} else {
			memlist_insert(&pbooterp, address, size);
		}
	}

	/* delete booter memory from pfreelistp */
	entry = pbooterp;
	while (entry) {
		address = entry->address;
		size = entry->size;
		(void) memlist_remove(&pfreelistp, address, size);
		entry = entry->next;
	}

	/* delete ramdisk memory */
	entry = pramdiskp;
	while (entry) {
		address = entry->address;
		size = entry->size;
		(void) memlist_remove(&pfreelistp, address, size);
		entry = entry->next;
	}

	/*
	 * initialize free virtual memory list
	 *	start withe the entire range
	 *	delete booter memory
	 */
	memlist_insert(&vfreelistp, 0, 0x100000000LL);
	entry = pbooterp;
	while (entry) {
		address = entry->address;
		size = entry->size;
		(void) memlist_remove(&vfreelistp, address, size);
		entry = entry->next;
	}

	if (debug & D_ALLOC)
		memlists_print();
}

/* resource allocate routines */
void
reset_alloc(void)
{
	if (verbosemode)
		printf("initialize scratch memory \n");

	/* reclaim existing scratch memory */
	if (scratchmem_end > scratchmem_start) {
		memlist_insert(&pfreelistp, scratchmem_start,
		    (uint64_t)magic_phys - scratchmem_start);
	}

	/* start allocating at 1MB */
	scratchmem_end = scratchmem_start = 0x100000;
}

/*
 * allocate memory with an identical physical and virtual address
 */
caddr_t
idmap_mem(uint32_t virthint, size_t bytes, int align)
{
	caddr_t addr = 0;

	/* sanity checks */
	if (bytes == 0)
		return ((caddr_t)0);

	if (virthint == 0) {
		addr = (caddr_t)(uintptr_t)
		    memlist_find(&pfreelistp, bytes, align);
	} else if (memlist_remove(
	    &pfreelistp, (uint64_t)virthint, (uint64_t)bytes) == 0) {
		addr = (caddr_t)virthint;
	}

	if (addr == 0) {
		printf("idmap_mem: failed to find phys 0x%lx bytes at 0x%x\n",
		    bytes, virthint);
		return (0);
	}

	/*
	 * For any piece of low (< kernelbase) physical memory, we
	 * either map it 1:1 or map it above kernelbase. Hence, the
	 * corresponding virtual memory is always available by design.
	 */
	if (memlist_remove(&vfreelistp,
	    (uint64_t)(uintptr_t)addr, (uint64_t)bytes) != 0) {
		printf("idmap_mem: failed to find virtual "
		    "0x%lx bytes at 0x%p\n", bytes, (void *)addr);
		(void) memlist_insert(&pfreelistp, (uint64_t)(uintptr_t)addr,
		    (uint64_t)bytes);
		return (0);
	}

	if (map_phys(0, bytes, addr, (uint64_t)(uintptr_t)addr) == -1) {
		printf("idmap_mem: failed to 1:1 map 0x%lx bytes at 0x%p\n",
		    bytes, (void *)addr);
		(void) memlist_insert(&pfreelistp, (uint64_t)(uintptr_t)addr,
		    (uint64_t)bytes);
		(void) memlist_insert(&vfreelistp, (uint64_t)(uintptr_t)addr,
		    (uint64_t)bytes);
		return (0);
	}

	return (addr);
}

/*
 * allocate memory with a physical mapping
 */
/*ARGSUSED*/
caddr_t
phys_alloc_mem(size_t bytes, int align)
{
	/* sanity checks */
	if (bytes == 0)
		return ((caddr_t)0);

	return ((caddr_t)(uintptr_t)memlist_find(&pfreelistp, bytes, align));
}

/*ARGSUSED*/
caddr_t
resalloc(enum RESOURCES type, size_t bytes, caddr_t virthint, int align)
{
	uint_t delta;
	caddr_t vaddr;
	uint64_t paddr;

	/* sanity checks */
	if (bytes == 0)
		return ((caddr_t)0);

	if (scratchmem_end == 0)
		prom_panic("scratch memory uninitialized\n");

	switch (type) {
	case RES_BOOTSCRATCH:

		/* scratch memory */
		vaddr = (caddr_t)(uintptr_t)scratchmem_end;
		bytes = roundup(bytes, PAGESIZE);
		scratchmem_end += bytes;
		if (scratchmem_end > magic_phys)
			prom_panic("scratch memory overflow!");
		return (vaddr);
		/*NOTREACHED*/

	case RES_CHILDVIRT:

		/* program memory */

		delta = (uint_t)virthint & (PAGESIZE - 1);
		if (delta)
			goto fail;	/* not page aligned */

		vaddr = virthint - delta;
		bytes += delta;
		bytes = roundup(bytes, PAGESIZE);

		if (memlist_remove(&vfreelistp,
		    (uint64_t)(uintptr_t)vaddr, (uint64_t)bytes))
			goto fail;	/* virtual memory not available */
		if (align == 0)
			align = 1;
		paddr = memlist_find(&pfreelistp, bytes, align);
		if (paddr == -1)
			goto fail;	/* out of physical memory */
		if (map_phys(0, bytes, vaddr, paddr) == -1)
			goto fail;
		return (vaddr);
		/*NOTREACHED*/
	}

fail:
	dprintf("resalloc of 0x%lx bytes at 0x%p failed",
		bytes, (void *)virthint);
	return (0);
}

void
resfree(caddr_t addr, size_t bytes)
{
	/* scratch memory is freed one one shot */
	if ((uint_t)addr < magic_phys)
		return;
	dprintf("resfree: 0x%p 0x%lx not implemented\n",
		(void *)addr, bytes);
}

int
get_progmemory(caddr_t vaddr, size_t size, int align)
{
	uint_t n = (uint_t)vaddr & (PAGESIZE - 1);

	if (n) {
		vaddr -= n;
		size += n;
	}

	if (resalloc(RES_CHILDVIRT, size, vaddr, align) != vaddr)
		return (-1);
	return (0);
}
