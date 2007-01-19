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
 * Copyright 1994, 2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#undef _KERNEL

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/exechdr.h>
#include <sys/elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int 		ofd,
			ifd;
	struct stat 	sbuf;
	void 		* elffile;
	unsigned int 	i,
			total,
			bytes;
	Elf32_Ehdr 	*ehdr;
	Elf32_Shdr 	*s;
	Elf32_Shdr 	*first_shdr = NULL,
			*nobits_shdr = NULL;

	if (argc < 3) {
		(void) printf("usage: mkbin elf_file binary_file \n");
		exit(1);
	}
	if ((ifd = open(argv[1], O_RDONLY)) ==  -1) {
		perror("open elf input");
		exit(2);
	}

	if ((ofd = open(argv[2], O_RDWR | O_TRUNC | O_CREAT, 0777)) ==  -1) {
		perror("open output binary");
		exit(3);
	}
	if (fstat(ifd, &sbuf) == -1) {
		perror("fstat");
		exit(1);
	}

	/*
	 * mmap in the whole file to work with it.
	 */
	if ((elffile = (void *)mmap(NULL, sbuf.st_size, PROT_READ,
			MAP_PRIVATE, ifd, 0)) == MAP_FAILED) {
		perror("mmap failed");
		exit(1);
	}
	ehdr = (Elf32_Ehdr *)elffile;

	if (*(int *)(ehdr->e_ident) != *(int *)(ELFMAG)) {
		perror("not elf file ");
		exit(5);
	}

	s = (Elf32_Shdr *)((char *)elffile + ehdr->e_shoff);
	/*
	 * find a pointer to the first allocated section header
	 * and the bss(NOBITS) section header.
	 */
	for (i = 0; i < ehdr->e_shnum; i++, s++) {
		if (!(s->sh_flags & SHF_ALLOC))
			continue;
		if (!first_shdr) {
			first_shdr = s;
			continue;
		}
		if (s->sh_type == SHT_NOBITS) {
			nobits_shdr = s;
			break;
		}
	}

	if ((first_shdr == NULL) || (nobits_shdr == NULL)) {
		(void) fprintf(stderr, "ERROR: Missing headers in elf file.\n");
		exit(1);
	}

	bytes = nobits_shdr->sh_offset - first_shdr->sh_offset;
	if (write(ofd, (char *)elffile + first_shdr->sh_offset,
			bytes) != bytes) {
		perror("write sections");
		exit(1);
	}
	total = bytes + nobits_shdr->sh_size;
	/*
	 * round up to the next 512k block
	 */
	if (total % 512 != 0)
		total += 512 - (total % 512);

	if (ftruncate(ofd, total) == -1) {
		perror("ftruncate");
		exit(1);
	}

	(void) close(ifd);
	(void) close(ofd);
	exit(0);
}
