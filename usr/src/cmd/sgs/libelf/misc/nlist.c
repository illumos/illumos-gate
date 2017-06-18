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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "libelf.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <nlist.h>
#include "syms.h"
#include "gelf.h"

#undef n_name		/* This undef is to handle a #define in syms.h */
			/* which conflicts with the member nlist->n_name */
			/* as defined in nlist.h */


#define	SPACE 100		/* number of symbols read at a time */
#define	ISELF (strncmp(magic_buf, ELFMAG, SELFMAG) == 0)


int
end_elf_job(int fd, Elf * elfdes)
{
	(void) elf_end(elfdes);
	(void) close(fd);
	return (-1);
}


int
_elf_nlist(int fd, struct nlist * list)
{
	Elf	   *elfdes;	/* ELF descriptor */
	GElf_Ehdr  ehdr;	/* ELF Ehdr */
	GElf_Shdr  s_buf;	/* buffer storing section header */
	Elf_Data   *symdata;	/* buffer points to symbol table */
	Elf_Scn    *secidx = 0;	/* index of the section header table */
	GElf_Sym   sym;		/* buffer storing one symbol information */
	unsigned   strtab;	/* index of symbol name in string table */
	long	   count;	/* number of symbols */
	long	   ii;		/* loop control */

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) close(fd);
		return (-1);
	}
	elfdes = elf_begin(fd, ELF_C_READ, (Elf *)0);
	if (gelf_getehdr(elfdes, &ehdr) == 0)
		return (end_elf_job(fd, elfdes));

	while ((secidx = elf_nextscn(elfdes, secidx)) != 0) {
		if ((gelf_getshdr(secidx, &s_buf)) == 0)
			return (end_elf_job(fd, elfdes));
		if (s_buf.sh_type != SHT_SYMTAB) /* not symbol table */
			continue;
		symdata = elf_getdata(secidx, (Elf_Data *)0);
		if (symdata == 0)
			return (end_elf_job(fd, elfdes));
		if (symdata->d_size == 0)
			break;
		strtab = s_buf.sh_link;
		count = symdata->d_size / s_buf.sh_entsize;
		for (ii = 1; ii < count; ++ii) {
			struct nlist *p;
			register char *name;
			/* LINTED */
			(void) gelf_getsym(symdata, (int)ii, &sym);
			name = elf_strptr(elfdes, strtab, (size_t)sym.st_name);
			if (name == 0)
				continue;
			for (p = list; p->n_name && p->n_name[0]; ++p) {
				if (strcmp(p->n_name, name))
					continue;
				p->n_value = (long)sym.st_value;
				p->n_type = GELF_ST_TYPE(sym.st_info);
				p->n_scnum = sym.st_shndx;
				break;
			}
		}
		break;
		/*
		 * Currently there is only one symbol table section
		 * in an object file, but this restriction may be
		 * relaxed in the future.
		 */
	}
	(void) elf_end(elfdes);
	(void) close(fd);
	return (0);
}

int
nlist(const char * name, struct nlist * list)
{
	register struct nlist *p;
	char magic_buf[EI_NIDENT];
	int fd;

	for (p = list; p->n_name && p->n_name[0]; p++) { /* n_name can be ptr */
		p->n_type = 0;
		p->n_value = 0L;
		p->n_scnum = 0;
		p->n_sclass = 0;
		p->n_numaux = 0;
	}

	if ((fd = open(name, 0)) < 0)
		return (-1);
	if (read(fd, magic_buf, EI_NIDENT) == -1) {
		(void) close(fd);
		return (-1);
	}

	if (lseek(fd, 0L, 0) == -1L) {	/* rewind to beginning of object file */
		(void) close(fd);
		return (-1);
	}

#ifndef _LP64
	if (ISELF && (magic_buf[EI_CLASS] == ELFCLASS32))
#else
	if (ISELF)		/* 64-bit case handles both Elf32 and Elf64 */
#endif
		return (_elf_nlist(fd, list));
	else {
		(void) close(fd);
		return (-1);
	}
}
