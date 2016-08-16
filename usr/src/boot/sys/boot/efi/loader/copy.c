/*
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Benno Rice under sponsorship from
 * the FreeBSD Foundation.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/multiboot2.h>

#include <stand.h>
#include <bootstrap.h>

#include <efi.h>
#include <efilib.h>
#include <assert.h>

#include "loader_efi.h"

/*
 * Verify the address is not in use by existing modules.
 */
static vm_offset_t
addr_verify(multiboot_tag_module_t *module, vm_offset_t addr, size_t size)
{
	vm_offset_t start, end;

	for (;module->mb_type == MULTIBOOT_TAG_TYPE_MODULE;
	    module = (multiboot_tag_module_t *)
	    roundup((uintptr_t)module + module->mb_size, MULTIBOOT_TAG_ALIGN)) {

		start = module->mb_mod_start;
		end = module->mb_mod_end;

		/* Does this module have address assigned? */
		if (start == 0)
			continue;

		if ((start <= addr) && (end >= addr)) {
			return (0);
		}
		if ((start >= addr) && (start <= addr + size)) {
			return (0);
		}
	}
	return (addr);
}

/*
 * Find memory map entry above 1MB, able to contain size bytes from addr.
 */
static vm_offset_t
memmap_find(EFI_MEMORY_DESCRIPTOR *map, size_t count, UINTN dsize,
    vm_offset_t addr, size_t size)
{
	int i;

	for (i = 0; i < count; i++, map = NextMemoryDescriptor(map, dsize)) {

		if (map->Type != EfiConventionalMemory)
			continue;

		/* We do not want address below 1MB. */
		if (map->PhysicalStart < 0x100000)
			continue;

		/* Do we fit into current entry? */
		if ((map->PhysicalStart <= addr) &&
		    (map->PhysicalStart +
		    (map->NumberOfPages << EFI_PAGE_SHIFT) >= addr + size)) {
			return (addr);
		}

		/* Do we fit into new entry? */
		if ((map->PhysicalStart > addr) &&
		    (map->NumberOfPages >= EFI_SIZE_TO_PAGES(size))) {
			return (map->PhysicalStart);
		}
	}
	return (0);
}

/*
 * Find usable address for loading. The address for the kernel is fixed, as
 * it is determined by kernel linker map (dboot PT_LOAD address).
 * For modules, we need to consult memory map, the module address has to be
 * aligned to page boundary and we have to fit into map entry.
 */
vm_offset_t
efi_physaddr(multiboot_tag_module_t *module, vm_offset_t addr,
    EFI_MEMORY_DESCRIPTOR *map, size_t count, UINTN dsize, size_t size)
{
	multiboot_tag_module_t *mp;
	vm_offset_t off;

	if (addr == 0)
		return (addr);

	mp = module;
	do {
		off = addr;
		/* Test proposed address */
		off = memmap_find(map, count, dsize, off, size);
		if (off != 0)
			off = addr_verify(module, off, size);
		if (off != 0)
			break;

		/* The module list is exhausted */
		if (mp->mb_type != MULTIBOOT_TAG_TYPE_MODULE)
			break;

		if (mp->mb_mod_start != 0) {
			addr = roundup2(mp->mb_mod_end + 1,
			    MULTIBOOT_MOD_ALIGN);
		}
		mp = (multiboot_tag_module_t *)
		    roundup((uintptr_t)mp + mp->mb_size, MULTIBOOT_TAG_ALIGN);
	} while (off == 0);

	return (off);
}

/*
 * Allocate pages for data to be loaded. As we can not expect AllocateAddress
 * to succeed, we allocate using AllocateMaxAddress from 4GB limit.
 * 4GB limit is because reportedly some 64bit systems are reported to have
 * issues with memory above 4GB. It should be quite enough anyhow.
 * Note: AllocateMaxAddress will only make sure we are below the specified
 * address, we can not make any assumptions about actual location or
 * about the order of the allocated blocks.
 */
vm_offset_t
efi_loadaddr(u_int type, void *data, vm_offset_t addr)
{
	EFI_PHYSICAL_ADDRESS paddr;
	struct stat st;
	size_t size;
	uint64_t pages;
	EFI_STATUS status;

	if (addr == 0)
		return (addr);	/* nothing to do */

	if (type == LOAD_ELF)
		return (0);	/* not supported */

	if (type == LOAD_MEM)
		size = *(size_t *)data;
	else {
		stat(data, &st);
		size = st.st_size;
	}

	pages = EFI_SIZE_TO_PAGES(size);
	/* 4GB upper limit */
	paddr = 0x0000000100000000;

	status = BS->AllocatePages(AllocateMaxAddress, EfiLoaderData,
	    pages, &paddr);

	if (EFI_ERROR(status)) {
		printf("failed to allocate %zu bytes for staging area: %lu\n",
		    size, EFI_ERROR_CODE(status));
		return (0);
	}

	return (paddr);
}

void
efi_free_loadaddr(vm_offset_t addr, size_t pages)
{
	(void) BS->FreePages(addr, pages);
}

void *
efi_translate(vm_offset_t ptr)
{
	return ((void *)ptr);
}

ssize_t
efi_copyin(const void *src, vm_offset_t dest, const size_t len)
{
	assert(dest < 0x100000000);
	bcopy(src, (void *)(uintptr_t)dest, len);
	return (len);
}

ssize_t
efi_copyout(const vm_offset_t src, void *dest, const size_t len)
{
	assert(src < 0x100000000);
	bcopy((void *)(uintptr_t)src, dest, len);
	return (len);
}


ssize_t
efi_readin(const int fd, vm_offset_t dest, const size_t len)
{
	return (read(fd, (void *)dest, len));
}

/*
 * Relocate chunks and return pointer to MBI.
 * This function is relocated before being called and we only have
 * memmove() available, as most likely moving chunks into the final
 * destination will destroy the rest of the loader code.
 *
 * In safe area we have relocator data, multiboot_tramp, efi_copy_finish,
 * memmove and stack.
 */
multiboot2_info_header_t *
efi_copy_finish(struct relocator *relocator)
{
	multiboot2_info_header_t *mbi;
	struct chunk *chunk, *c;
	struct chunk_head *head;
	bool done = false;
	void (*move)(void *s1, const void *s2, size_t n);

	move = (void *)relocator->rel_memmove;

	/* MBI is the last chunk in the list. */
	head = &relocator->rel_chunk_head;
	chunk = STAILQ_LAST(head, chunk, chunk_next);
	mbi = (multiboot2_info_header_t *)(uintptr_t)chunk->chunk_paddr;

	/*
	 * If chunk paddr == vaddr, the chunk is in place.
	 * If all chunks are in place, we are done.
	 */
	chunk = NULL;
	while (!done) {
		/* Advance to next item in list. */
		if (chunk != NULL)
			chunk = STAILQ_NEXT(chunk, chunk_next);

		/*
		 * First check if we have anything to do.
		 * We set chunk to NULL every time we move the data.
		 */
		done = true;
		STAILQ_FOREACH_FROM(chunk, head, chunk_next) {
			if (chunk->chunk_paddr != chunk->chunk_vaddr) {
				done = false;
				break;
			}
		}
		if (done)
			break;

		/*
		 * Make sure the destination is not conflicting
		 * with rest of the modules.
		 */
		STAILQ_FOREACH(c, head, chunk_next) {
			/* Moved already? */
			if (c->chunk_vaddr == c->chunk_paddr)
				continue;

			/* Is it the chunk itself? */
			if (c->chunk_vaddr == chunk->chunk_vaddr &&
			    c->chunk_size == chunk->chunk_size)
				continue;

			/*
			 * Check for overlaps.
			 */
			if ((c->chunk_vaddr >= chunk->chunk_paddr &&
			    c->chunk_vaddr <=
			    chunk->chunk_paddr + chunk->chunk_size) ||
			    (c->chunk_vaddr + c->chunk_size >=
			    chunk->chunk_paddr &&
			    c->chunk_vaddr + c->chunk_size <=
			    chunk->chunk_paddr + chunk->chunk_size)) {
				break;
			}
		}
		/* If there are no conflicts, move to place and restart. */
		if (c == NULL) {
			move((void *)(uintptr_t)chunk->chunk_paddr,
			    (void *)(uintptr_t)chunk->chunk_vaddr,
			    chunk->chunk_size);
			chunk->chunk_vaddr = chunk->chunk_paddr;
			chunk = NULL;
			continue;
		}
	}

	return (mbi);
}
