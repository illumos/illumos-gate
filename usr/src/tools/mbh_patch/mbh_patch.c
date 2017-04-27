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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "sys/multiboot.h"
#include "sys/multiboot2.h"

static char *pname;
static char *fname;
static char *image;	/* pointer to the ELF file in memory */

#define	ELFSEEK(offset) ((void *)(image + offset))

/*
 * Find MB2 header tags for entry and patch it.
 * The first tag is right after header.
 */
static int
patch64_mb2(multiboot2_header_t *mbh2, int file_offset,
    Elf64_Addr ptload_start, Elf32_Off ptload_offset)
{
	multiboot_header_tag_t *tagp = mbh2->mb2_tags;
	multiboot_header_tag_address_t *mbaddr = NULL;
	multiboot_header_tag_entry_address_t *mbentry = NULL;

	/*
	 * Loop until we get end TAG or we have both tags.
	 */
	while (tagp->mbh_type != MULTIBOOT_HEADER_TAG_END &&
	    (mbaddr == NULL || mbentry == NULL)) {
		switch (tagp->mbh_type) {
		case MULTIBOOT_HEADER_TAG_ADDRESS:
			mbaddr = (multiboot_header_tag_address_t *)tagp;
			break;
		case MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
			mbentry = (multiboot_header_tag_entry_address_t *)tagp;
			break;
		}
		tagp = (multiboot_header_tag_t *)
		    ((uintptr_t)tagp +
		    P2ROUNDUP(tagp->mbh_size, MULTIBOOT_TAG_ALIGN));
	}

	if (mbaddr == NULL || mbentry == NULL) {
		(void) fprintf(stderr, "Missing multiboot2 %s tag\n",
		    (mbaddr == NULL)? "address" : "entry");
		return (1);
	}

	/* Patch it. */
	mbaddr->mbh_load_addr = ptload_start - ptload_offset;
	mbaddr->mbh_header_addr = mbaddr->mbh_load_addr + file_offset;
	mbentry->mbh_entry_addr = ptload_start;

#ifdef VERBOSE
	(void) printf("  ELF64 MB2 header patched\n");
	(void) printf("\tload_addr now:   0x%x\n", mbaddr->mbh_load_addr);
	(void) printf("\theader_addr now: 0x%x\n", mbaddr->mbh_header_addr);
	(void) printf("\tentry_addr now:  0x%x\n", mbentry->mbh_entry_addr);
#endif
	return (0);
}

/*
 * Patch the load address / entry address for MB1 and MB2 if present.
 * Find the physical load address of the 1st PT_LOAD segment.
 * Find the amount that e_entry exceeds that amount.
 * Now go back and subtract the excess from the p_paddr of the LOAD segment.
 */
static int
patch64(Elf64_Ehdr *eh)
{
	Elf64_Phdr		*phdr;
	caddr_t			phdrs = NULL;
	int			ndx, mem, mem2;
	multiboot_header_t	*mbh;
	multiboot2_header_t	*mbh2;

	/*
	 * Verify some ELF basics - this must be an executable with program
	 * headers.
	 */
	if (eh->e_type != ET_EXEC) {
		(void) fprintf(stderr, "%s: %s: not ET_EXEC, e_type = 0x%x\n",
		    pname, fname, eh->e_type);
		return (1);
	}
	if ((eh->e_phnum == 0) || (eh->e_phoff == 0)) {
		(void) fprintf(stderr, "%s: %s: no program headers\n", pname,
		    fname);
		return (1);
	}

	/*
	 * Get the program headers.
	 */
	if ((phdrs = ELFSEEK(eh->e_phoff)) == NULL) {
		(void) fprintf(stderr, "%s: %s: failed to get %d program "
		    "hdrs\n", pname, fname, eh->e_phnum);
		return (1);
	}

	/*
	 * Look for multiboot1 header.  It must be 32-bit aligned and
	 * completely contained in the 1st 8K of the file.
	 */
	for (mem = 0; mem < 8192 - sizeof (multiboot_header_t); mem += 4) {
		mbh = ELFSEEK(mem);
		if (mbh->magic == MB_HEADER_MAGIC)
			break;
	}

	if (mem >= 8192 - sizeof (multiboot_header_t)) {
		(void) fprintf(stderr, "%s: %s: Didn't find multiboot header\n",
		    pname, fname);
		return (1);
	}

	/*
	 * Look for multiboot2 header.  It must be 64-bit aligned and
	 * completely contained in the 1st 32K of the file.
	 * We do not require it to be present.
	 */
	ndx = 0;
	for (mem2 = 0;
	    mem2 <= MULTIBOOT_SEARCH - sizeof (multiboot2_header_t);
	    mem2 += MULTIBOOT_HEADER_ALIGN) {
		mbh2 = ELFSEEK(mem2);
		ndx = mbh2->mb2_header_length;
		if (mbh2->mb2_magic == MULTIBOOT2_HEADER_MAGIC)
			break;
		ndx = 0;
	}

	if (ndx == 0 || mem2 + ndx > MULTIBOOT_SEARCH) {
#ifdef VERBOSE
		(void) fprintf(stderr, "%s: %s: Didn't find multiboot2 "
		    "header\n", pname, fname);
#endif
		mbh2 = NULL;
	}

	/*
	 * Find the 1:1 mapped PT_LOAD section
	 */
	for (ndx = 0; ndx < eh->e_phnum; ndx++) {
		/*LINTED [ELF program header alignment]*/
		phdr = (Elf64_Phdr *)(phdrs + eh->e_phentsize * ndx);

		/*
		 * Find the low memory 1:1 PT_LOAD section!
		 */
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		if (phdr->p_paddr != phdr->p_vaddr)
			continue;

		/*
		 * Make sure the multiboot header is part of the first PT_LOAD
		 * segment, and that the executables entry point starts at the
		 * same segment.
		 */
		if ((mem < phdr->p_offset) ||
		    (mem >= (phdr->p_offset + phdr->p_filesz))) {
			(void) fprintf(stderr, "%s: %s: identity mapped "
			    "PT_LOAD wasn't 1st PT_LOAD\n", pname, fname);
			return (1);
		}
		if (eh->e_entry != phdr->p_paddr) {
			(void) fprintf(stderr, "%s: %s: entry != paddr\n",
			    pname, fname);
			return (1);
		}

		if (mbh2 != NULL && ((mem2 < phdr->p_offset) ||
		    (mem2 >= (phdr->p_offset + phdr->p_filesz)))) {
#ifdef VERBOSE
			(void) fprintf(stderr, "%s: %s: multiboot2 header not"
			    " in 1st PT_LOAD\n", pname, fname);
#endif
			mem2 = 0;
			mbh2 = NULL;
		}

		/*
		 * Patch the multiboot header fields to get entire file loaded.
		 * Grub uses the MB header for 64 bit loading.
		 */
		mbh->load_addr = phdr->p_paddr - phdr->p_offset;
		mbh->entry_addr = phdr->p_paddr;
		mbh->header_addr = mbh->load_addr + mem;
#ifdef VERBOSE
		(void) printf("  %s: ELF64 MB header patched\n", fname);
		(void) printf("\tload_addr now:   0x%x\n", mbh->load_addr);
		(void) printf("\tentry_addr now:  0x%x\n", mbh->entry_addr);
		(void) printf("\theader_addr now: 0x%x\n", mbh->header_addr);
#endif
		if (mbh2 != NULL)
			return (patch64_mb2(mbh2, mem2, phdr->p_paddr,
			    phdr->p_offset));
		return (0);
	}

	(void) fprintf(stderr, "%s: %s: Didn't find 1:1 mapped PT_LOAD "
	    "section\n", pname, fname);
	return (1);
}

int
main(int argc, char **argv)
{
	int	fd;
	uchar_t *ident;
	void	*hdr = NULL;
	struct	stat sb;

	/*
	 * We expect one argument -- the elf file.
	 */
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s <unix-elf-file>\n", argv[0]);
		return (1);
	}

	pname = strrchr(argv[0], '/');
	if (pname == NULL)
		pname = argv[0];
	else
		++pname;

	fname = argv[1];
	if ((fd = open(fname, O_RDWR)) < 0) {
		(void) fprintf(stderr, "%s: open(%s, O_RDWR) failed: %s\n",
		    pname, fname, strerror(errno));
		return (1);
	}

	if (fstat(fd, &sb) != 0) {
		(void) fprintf(stderr, "%s: fstat failed: %s\n",
		    pname, strerror(errno));
		return (1);
	}

	/* Make sure we have at least MULTIBOOT_SEARCH bytes. */
	if (sb.st_size < MULTIBOOT_SEARCH) {
		(void) fprintf(stderr, "%s: %s is too small for a kernel\n",
		    pname, fname);
		return (1);
	}

	/*
	 * mmap the 1st 32K -- MB1 header is within first 8k and MB2 header
	 * is within 32k.
	 */
	image = mmap(NULL, MULTIBOOT_SEARCH, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (image == MAP_FAILED) {
		(void) fprintf(stderr, "%s: mmap() of %s failed: %s\n",
		    pname, fname, strerror(errno));
		return (1);
	}

	ident = ELFSEEK(0);
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3) {
		(void) fprintf(stderr, "%s: %s: not an ELF file!\n", pname,
		    fname);
		return (1);
	}

	if (ident[EI_CLASS] == ELFCLASS64) {
		hdr = ELFSEEK(0);
		return (patch64(hdr));
	}
	if (ident[EI_CLASS] != ELFCLASS32) {
		(void) fprintf(stderr, "%s: Unknown ELF class 0x%x\n", pname,
		    ident[EI_CLASS]);
		return (1);
	}
	return (0);
}
