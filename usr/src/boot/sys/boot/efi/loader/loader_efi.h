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

#ifndef	_LOADER_EFI_H
#define	_LOADER_EFI_H

#include <stand.h>
#include <efi.h>
#include <efilib.h>
#include <sys/multiboot2.h>
#include <sys/queue.h>
#include <bootstrap.h>

struct chunk {
	EFI_VIRTUAL_ADDRESS chunk_vaddr;
	EFI_PHYSICAL_ADDRESS chunk_paddr;
	UINT64 chunk_size;
	STAILQ_ENTRY(chunk) chunk_next;
};

STAILQ_HEAD(chunk_head, chunk);

struct relocator {
	UINT64 rel_stack;
	UINT64 rel_copy;
	UINT64 rel_memmove;
	struct chunk_head rel_chunk_head;
	struct chunk rel_chunklist[];
};

int	efi_autoload(void);

int	efi_getdev(void **, const char *, const char **);
char	*efi_fmtdev(void *);
int	efi_setcurrdev(struct env_var *, int, const void *);

ssize_t	efi_copyin(const void *, vm_offset_t, const size_t);
ssize_t	efi_copyout(const vm_offset_t, void *, const size_t);
ssize_t	efi_readin(const int, vm_offset_t, const size_t);
uint64_t efi_loadaddr(u_int, void *, uint64_t);
void efi_free_loadaddr(uint64_t, uint64_t);
void * efi_translate(vm_offset_t);

multiboot2_info_header_t *efi_copy_finish(struct relocator *);
void multiboot_tramp(uint32_t, struct relocator *, uint64_t);

void efi_addsmapdata(struct preloaded_file *);

#endif	/* _LOADER_EFI_H */
