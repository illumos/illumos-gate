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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "sys/multiboot.h"

static char *pname;
static char *fname;
static char *image;	/* pointer to the ELF file in memory */

#define	ELFSEEK(offset) ((void *)(image + offset))

/*
 * patch the load address / entry address
 * Find the physical load address of the 1st PT_LOAD segment.
 * Find the amount that e_entry exceeds that amount.
 * Now go back and subtract the excess from the p_paddr of the LOAD segment.
 */
static void
patch64(Elf64_Ehdr *eh)
{
	Elf64_Phdr *phdr;
	caddr_t allphdrs;
	int i;
	int m;
	int extra;
	multiboot_header_t *mbh;

	allphdrs = NULL;

	if (eh->e_type != ET_EXEC) {
		(void) fprintf(stderr, "%s: not ET_EXEC, e_type = 0x%x\n",
		    pname, eh->e_type);
		exit(1);
	}
	if (eh->e_phnum == 0 || eh->e_phoff == 0) {
		(void) fprintf(stderr, "%s: no program headers\n", pname);
		exit(1);
	}

	/*
	 * Get the program headers.
	 */
	allphdrs = ELFSEEK(eh->e_phoff);
	if (allphdrs == NULL) {
		(void) fprintf(stderr, "%s: Failed to get %d program hdrs\n",
		    pname, eh->e_phnum);
		exit(1);
	}

	/*
	 * Look for multiboot header.  It must be 32-bit aligned and
	 * completely contained in the 1st 8K of the file.
	 */
	for (m = 0; m < 8192 - sizeof (multiboot_header_t); m += 4) {
		mbh = (void *)(image + m);
		if (mbh->magic == MB_HEADER_MAGIC)
			break;
	}

	if (m >= 8192 - sizeof (multiboot_header_t)) {
		(void) fprintf(stderr, "%s: Didn't find multiboot header\n",
		    pname);
		exit(1);
	}

	/*
	 * Find the 1:1 mapped PT_LOAD section
	 */
	for (i = 0; i < eh->e_phnum; i++) {
		/*LINTED [ELF program header alignment]*/
		phdr = (Elf64_Phdr *)(allphdrs + eh->e_phentsize * i);

		/*
		 * Find the low memory 1:1 PT_LOAD section!
		 */
		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		if (phdr->p_paddr != phdr->p_vaddr)
			continue;

		if (i != 0) {
			(void) fprintf(stderr, "%s: identity mapped PT_LOAD"
			    " wasn't 1st\n", pname);
			exit(1);
		}

		/*
		 * Patch the multiboot header fields to get entire
		 * file loaded, with entry aligned at extra.
		 */
		if (eh->e_entry != phdr->p_paddr) {
			(void) fprintf(stderr, "%s: entry != paddr\n", pname);
			exit(1);
		}

		/*
		 * Grub uses the MB header for 64 bit loading.
		 */
		mbh->load_addr = phdr->p_paddr - phdr->p_offset;
		mbh->entry_addr = phdr->p_paddr;
		mbh->header_addr = mbh->load_addr + m;
#ifdef VERBOSE
		(void) printf("%s ELF64 MB header patched by 0x%0x "
		    "bytes:\n", fname, extra);
		(void) printf("\tload_addr now 0x%x\n", mbh->load_addr);
		(void) printf("\tentry_addr now 0x%x\n", mbh->entry_addr);
		(void) printf("\theader_addr now 0x%x\n", mbh->header_addr);
#endif
		exit(0);
	}

	(void) fprintf(stderr, "%s: Didn't find 1:1 mapped PT_LOAD section\n",
	    pname);
	exit(1);
}


int
main(int argc, char **argv)
{
	int fd;
	uchar_t *ident;
	void *hdr = NULL;

	/*
	 * we expect one argument -- the elf file
	 */
	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s <unix-elf-file>\n", argv[0]);
		exit(1);
	}

	pname = strrchr(argv[0], '/');
	if (pname == NULL)
		pname = argv[0];
	else
		++pname;

	fname = argv[1];
	fd = open(fname, O_RDWR);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: open(%s, O_RDWR) failed\n",
		    pname, fname);
		exit(1);
	}

	/*
	 * mmap just the 1st 8K -- since that's where the GRUB
	 * multiboot header must be located.
	 */
	image = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (image == MAP_FAILED) {
		(void) fprintf(stderr, "%s: mmap() of %s failed\n",
		    pname, fname);
		exit(1);
	}

	ident = ELFSEEK(0);
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3) {
		(void) fprintf(stderr, "%s: not an ELF file!\n", pname);
		exit(1);
	}

	if (ident[EI_CLASS] == ELFCLASS64) {
		hdr = ELFSEEK(0);
		patch64(hdr);
	} else if (ident[EI_CLASS] != ELFCLASS32) {
		(void) fprintf(stderr, "%s: Unknown ELF class 0x%x\n", pname,
		    ident[EI_CLASS]);
		exit(1);
	}
	return (0);
}
