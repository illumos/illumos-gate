/*
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

/*
 * MD primitives supporting placement of module data
 *
 * XXX should check load address/size against memory top.
 */
#include <stand.h>
#include <sys/param.h>
#include <sys/multiboot2.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include "libi386.h"
#include "btxv86.h"
#include "bootstrap.h"

/*
 * Verify the address is not in use by existing modules.
 */
static vm_offset_t
addr_verify(struct preloaded_file *fp, vm_offset_t addr, size_t size)
{
	vm_offset_t f_addr;

	while (fp != NULL) {
		f_addr = fp->f_addr;

		if ((f_addr <= addr) &&
		     (f_addr + fp->f_size >= addr)) {
			return (0);
		}
		if ((f_addr >= addr) && (f_addr <= addr + size)) {
			return (0);
		}
		fp = fp->f_next;
	}
	return (addr);
}

/*
 * Find smap entry above 1MB, able to contain size bytes from addr.
 */
static vm_offset_t
smap_find(struct bios_smap *smap, int smaplen, vm_offset_t addr, size_t size)
{
	int i;

	for (i = 0; i < smaplen; i++) {
		if (smap[i].type != SMAP_TYPE_MEMORY)
			continue;

		/* We do not want address below 1MB. */
		if (smap[i].base < 0x100000)
			continue;

		/* Do we fit into current entry? */
		if ((smap[i].base <= addr) &&
		    (smap[i].base + smap[i].length >= addr + size)) {
			return (addr);
		}

		/* Do we fit into new entry? */
		if ((smap[i].base > addr) && (smap[i].length >= size)) {
			return (smap[i].base);
		}
	}
	return (0);
}

/*
 * Find usable address for loading. The address for the kernel is fixed, as
 * it is determined by kernel linker map (dboot PT_LOAD address).
 * For modules, we need to consult smap, the module address has to be
 * aligned to page boundary and we have to fit into smap entry.
 */
vm_offset_t
i386_loadaddr(u_int type, void *data, vm_offset_t addr)
{
	struct stat st;
	size_t size, smaplen;
	struct preloaded_file *fp, *mfp;
	struct file_metadata *md;
	struct bios_smap *smap;
	vm_offset_t off;

	/*
	 * For now, assume we have memory for the kernel, the
	 * required map is [1MB..) This assumption should be safe with x86 BIOS.
	 */
	if (type == LOAD_KERN)
		return (addr);

	if (addr == 0)
		return (addr);	/* nothing to do */

	if (type == LOAD_ELF)
		return (0);	/* not supported */

	if (type == LOAD_MEM) {
		size = *(size_t *)data;
	} else {
		stat(data, &st);
		size = st.st_size;
	}

	/*
	 * Find our kernel, from it we will find the smap and the list of
	 * loaded modules.
	 */
	fp = file_findfile(NULL, NULL);
	if (fp == NULL)
		return (0);
	md = file_findmetadata(fp, MODINFOMD_SMAP);
	if (md == NULL)
		return (0);

	smap = (struct bios_smap *)md->md_data;
	smaplen = md->md_size / sizeof(struct bios_smap);

	/* Start from the end of the kernel. */
	mfp = fp;
	do {
		if (mfp == NULL) {
			off = roundup2(addr + 1, MULTIBOOT_MOD_ALIGN);
		} else {
			off = roundup2(mfp->f_addr + mfp->f_size + 1,
			    MULTIBOOT_MOD_ALIGN);
		}
		off = smap_find(smap, smaplen, off, size);
		off = addr_verify(fp, off, size);
		if (off != 0)
			break;

		if (mfp == NULL)
			break;
		mfp = mfp->f_next;
	} while (off == 0);

	return (off);
}

ssize_t
i386_copyin(const void *src, vm_offset_t dest, const size_t len)
{
	if (dest + len >= memtop) {
		errno = EFBIG;
		return (-1);
	}

	bcopy(src, PTOV(dest), len);
	return (len);
}

ssize_t
i386_copyout(const vm_offset_t src, void *dest, const size_t len)
{
	if (src + len >= memtop) {
		errno = EFBIG;
		return (-1);
	}

	bcopy(PTOV(src), dest, len);
	return (len);
}


ssize_t
i386_readin(const int fd, vm_offset_t dest, const size_t len)
{
	if (dest + len >= memtop_copyin) {
		errno = EFBIG;
		return (-1);
	}

	return (read(fd, PTOV(dest), len));
}
