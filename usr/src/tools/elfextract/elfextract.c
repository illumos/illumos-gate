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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

static char *pname;
static char *fname;
static char *image;	/* pointer to the ELF file in memory */

#define	ELFSEEK(offset) ((void *)(image + offset))

/*
 * Extract the PT_LOAD bits and format them into a .s
 */
static void
extract32(Elf32_Ehdr *eh)
{
	Elf32_Phdr *phdr;
	caddr_t allphdrs;
	int i;
	int c;
	unsigned char *bytes;
	uint_t cnt = 10;

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
	 * Find the PT_LOAD section
	 */
	for (i = 0; i < eh->e_phnum; i++) {
		/*LINTED [ELF program header alignment]*/
		phdr = (Elf32_Phdr *)(allphdrs + eh->e_phentsize * i);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		bytes = ELFSEEK(phdr->p_offset);
		for (c = 0; c < phdr->p_filesz; ++c) {
			if (c % cnt == 0)
				(void) printf("\n	.byte	");
			else
				(void) printf(",");
			(void) printf("0x%x", bytes[c]);
		}
		for (; c < phdr->p_memsz; ++c) {
			if (c % cnt == 0) {
				(void) printf("\n	.byte	");
				cnt = 20;
			} else {
				(void) printf(", ");
			}
			(void) printf("0");
		}
		(void) printf("\n");
		return;
	}

	(void) fprintf(stderr, "%s: Failed finding PT_LOAD section\n", pname);
	exit(1);
}

static void
extract64(Elf64_Ehdr *eh)
{
	Elf64_Phdr *phdr;
	caddr_t allphdrs;
	int i;
	int c;
	unsigned char *bytes;
	uint_t cnt = 10;

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
	 * Find the PT_LOAD section
	 */
	for (i = 0; i < eh->e_phnum; i++) {
		/*LINTED [ELF program header alignment]*/
		phdr = (Elf64_Phdr *)(allphdrs + eh->e_phentsize * i);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_memsz == 0)
			continue;

		bytes = ELFSEEK(phdr->p_offset);
		for (c = 0; c < phdr->p_filesz; ++c) {
			if (c % cnt == 0)
				(void) printf("\n	.byte	");
			else
				(void) printf(",");
			(void) printf("0x%x", bytes[c]);
		}
		for (; c < phdr->p_memsz; ++c) {
			if (c % cnt == 0) {
				(void) printf("\n	.byte	");
				cnt = 20;
			} else {
				(void) printf(", ");
			}
			(void) printf("0");
		}
		(void) printf("\n");
		return;
	}

	(void) fprintf(stderr, "%s: Failed finding PT_LOAD section\n", pname);
	exit(1);
}

int
main(int argc, char **argv)
{
	int fd;
	uchar_t *ident;
	void *hdr = NULL;
	struct stat stats;
	ssize_t r;
	size_t pgsz;
	uint_t len;

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
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: open(%s, O_RDONLY) failed, %s\n",
		    pname, fname, strerror(errno));
		exit(1);
	}

	if (stat(fname, &stats) < 0) {
		(void) fprintf(stderr, "%s: stat(%s, ...) failed, %s\n",
		    pname, fname, strerror(errno));
		exit(1);
	}

	pgsz = getpagesize();
	len = (stats.st_size + (pgsz - 1)) & (~(pgsz - 1));

	/*
	 * mmap the file
	 */
	image = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (image == MAP_FAILED) {
		(void) fprintf(stderr, "%s: mmap() of %s failed, %s\n",
		    pname, fname, strerror(errno));
		exit(1);
	}

	ident = ELFSEEK(0);
	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3) {
		(void) fprintf(stderr, "%s: not an ELF file!\n", pname);
		exit(1);
	}

	if (ident[EI_CLASS] == ELFCLASS32) {
		hdr = ELFSEEK(0);
		extract32(hdr);
	} else if (ident[EI_CLASS] == ELFCLASS64) {
		hdr = ELFSEEK(0);
		extract64(hdr);
	} else {
		(void) fprintf(stderr, "%s: Wrong ELF class 0x%x\n", pname,
		    ident[EI_CLASS]);
		exit(1);
	}
	return (0);
}
