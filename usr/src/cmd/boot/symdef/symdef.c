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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <errno.h>

/*
 * symdef is a very simplified version of nm.  It is used by upgrade and
 * create_ramdisk in situations where we can't guarantee that nm will be around.
 *
 * Two arguments are expected: a binary and a symbol name.  If the symbol is
 * found in the name table of the binary, 0 is returned.  If it is not found,
 * 1 is returned.  If an error occurs, a message is printed to stderr and -1
 * is returned.
 */


static void
usage(void)
{
	(void) fprintf(stderr, "USAGE: symdef file_name symbol\n");
}

int
main(int argc, char *argv[])
{
	int	fd = 0;
	int	rv = 1;
	uint_t	cnt, symcnt;
	Elf	*elfp = NULL;
	Elf_Scn	*scn = NULL;
	size_t	shstrndx;
	GElf_Ehdr	ehdr;
	GElf_Shdr	shdr;
	GElf_Sym	sym;
	Elf32_Word	shndx;
	Elf_Data	*symdata, *shndxdata;

	if (argc != 3) {
		usage();
		return (-1);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		(void) fprintf(stderr, "%s\n", strerror(errno));
		rv = -1;
		goto done;
	}
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "Elf library version out of date\n");
		rv = -1;
		goto done;
	}
	elfp = elf_begin(fd, ELF_C_READ, NULL);
	if ((elfp == NULL) || (elf_kind(elfp) != ELF_K_ELF) ||
	    ((gelf_getehdr(elfp, &ehdr)) == NULL) ||
	    (elf_getshstrndx(elfp, &shstrndx) == 0))
		goto done;

	while ((scn = elf_nextscn(elfp, scn)) != NULL) {
		if ((gelf_getshdr(scn, &shdr) == NULL) ||
		    ((shdr.sh_type != SHT_SYMTAB) &&
		    (shdr.sh_type != SHT_DYNSYM)) ||
		    ((symdata = elf_getdata(scn, NULL)) == NULL))
			continue;
		symcnt = shdr.sh_size / shdr.sh_entsize;
		shndxdata = NULL;
		for (cnt = 0; cnt < symcnt; cnt++) {
			if ((gelf_getsymshndx(symdata, shndxdata, cnt,
			    &sym, &shndx) != NULL) &&
			    (strcmp(argv[2], elf_strptr(elfp, shdr.sh_link,
			    sym.st_name)) == 0)) {
				rv = 0;
				goto done;
			}
		}
	}
done:
	if (elfp)
		(void) elf_end(elfp);
	if (fd != -1)
		(void) close(fd);
	return (rv);
}
