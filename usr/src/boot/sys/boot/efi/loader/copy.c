/*-
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
 * Allocate pages for data to be loaded. As we can not expect AllocateAddress
 * to succeed, we allocate using AllocateMaxAddress from 4GB limit.
 * 4GB limit is because reportedly some 64bit systems are reported to have
 * issues with memory above 4GB. It should be quite enough anyhow.
 * Note: AllocateMaxAddress will only make sure we are below the specified
 * address, we can not make any assumptions about actual location or
 * about the order of the allocated blocks.
 */
uint64_t
efi_loadaddr(u_int type, void *data, uint64_t addr)
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
efi_free_loadaddr(uint64_t addr, uint64_t pages)
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
	UINT64 size;
	int done = 0;
	void (*move)(void *s1, const void *s2, size_t n);

	move = (void *)relocator->rel_memmove;

	/* MBI is the last chunk in the list. */
	head = &relocator->rel_chunk_head;
	chunk = STAILQ_LAST(head, chunk, chunk_next);
	mbi = (multiboot2_info_header_t *)chunk->chunk_paddr;

	/*
	 * If chunk paddr == vaddr, the chunk is in place.
	 * If all chunks are in place, we are done.
	 */
	chunk = NULL;
	while (done == 0) {
		/* First check if we have anything to do. */
		if (chunk == NULL) {
			done = 1;
			STAILQ_FOREACH(chunk, head, chunk_next) {
				if (chunk->chunk_paddr != chunk->chunk_vaddr) {
					done = 0;
					break;
				}
			}
		}
		if (done == 1)
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
			if ((c->chunk_vaddr >= chunk->chunk_paddr &&
			    c->chunk_vaddr <=
			    chunk->chunk_paddr + chunk->chunk_size) ||
			    (c->chunk_vaddr + c->chunk_size >=
			    chunk->chunk_paddr &&
			    c->chunk_vaddr + c->chunk_size <=
			    chunk->chunk_paddr + chunk->chunk_size))
				break;
		}
		/* If there are no conflicts, move to place and restart. */
		if (c == NULL) {
			move((void *)chunk->chunk_paddr,
			    (void *)chunk->chunk_vaddr,
			    chunk->chunk_size);
			chunk->chunk_vaddr = chunk->chunk_paddr;
			chunk = NULL;
			continue;
		}
		chunk = STAILQ_NEXT(chunk, chunk_next);
	}

	return (mbi);
}
