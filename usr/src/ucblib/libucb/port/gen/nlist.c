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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "libelf.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <nlist.h>
#include <sys/file.h>
#include <string.h>

#if COFF_NLIST_SUPPORTED
#include "aouthdr.h"
#include "filehdr.h"
#include "scnhdr.h"
#include "reloc.h"
#endif /* COFF_NLIST_SUPPORTED */

#include "linenum.h"
#include "syms.h"

#undef  BADMAG
#define	BADMAG(x)	(!ISCOFF(x))

#ifndef FLEXNAMES
#define	FLEXNAMES 1
#endif
#undef n_name		/* this patch causes problems here */

#define	SPACE 100		/* number of symbols read at a time */
#define	ISELF (strncmp(magic_buf, ELFMAG, SELFMAG) == 0)

#if COFF_NLIST_SUPPORTED
static char sym_buf[SPACE * SYMESZ];
static int num_in_buf = 0;
static char *next_entry = (char *)0;
#endif /* COFF_NLIST_SUPPORTED */

static unsigned encode;		/* data encoding if an ELF file */
static unsigned fvers;		/* object file version if an ELF file */

/* forward declarations */
static int _elf_nlist(int, struct nlist *);
static int end_elf_job(int);
static Elf_Data *elf_read(int, long, size_t, size_t, Elf_Type);

#if COFF_NLIST_SUPPORTED
static int _coff_nlist(int, struct nlist *);
static void sym_close(int);
static int sym_read(int, struct syment *, int);
static int fill_sym_buf(int, int);
#endif /* COFF_NLIST_SUPPORTED */

int
nlist(const char *name, struct nlist *list)
{
	struct nlist *p;
	char magic_buf[EI_NIDENT+1];
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
	if (read(fd, magic_buf, (size_t)EI_NIDENT) == -1) {
		(void) close(fd);
		return (-1);
	}
	magic_buf[EI_NIDENT] = '\0';
	if (lseek(fd, 0L, 0) == -1L) { /* rewind to beginning of object file */
		(void) close(fd);
		return (-1);
	}

	if (ISELF) {
		/*
		 * right now can only handle 32-bit architectures
		 * XX64 work to come?  ELFCLASS64?
		 */
		if (magic_buf[EI_CLASS] != ELFCLASS32) {
			(void) close(fd);
			return (-1);
		}
		encode = (unsigned)magic_buf[EI_DATA];
		fvers = (unsigned)magic_buf[EI_VERSION];
		return (_elf_nlist(fd, list));
	}
	else
#if COFF_NLIST_SUPPORTED
		return (_coff_nlist(fd, list));
#else /* COFF_NLIST_SUPPORTED */
		return (-1);
#endif /* COFF_NLIST_SUPPORTED */
}

static int
_elf_nlist(int fd, struct nlist *list)
{
	Elf_Data   *symdata;	/* buffer points to symbol table */
	Elf_Data   *strdata;	/* buffer points to string table */
	Elf_Data   *secdata;	/* buffer points to section table */
	Elf32_Shdr *symhdr;	/* section table entry for symtab */
	Elf32_Shdr *strhdr;	/* section table entry for strtab */
	Elf32_Sym  *sym;	/* buffer storing one symbol information */
	Elf32_Sym  *sym_end;	/* end of symbol table */
	Elf32_Ehdr *ehdr;	/* file header */
	Elf_Data   *edata;	/* data buffer for ehdr */
	int	i;
	int	nreq;
	struct  nlist *inl;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return (end_elf_job(fd));

	/* count the number of symbols requested */
	for (inl = list, nreq = 0; inl->n_name && inl->n_name[0]; ++inl, nreq++)
		;

	/* read file header and section header table */
	if ((edata = elf_read(fd, 0L, elf32_fsize(ELF_T_EHDR, 1, fvers),
		sizeof (Elf32_Ehdr), ELF_T_EHDR)) == 0)
		return (end_elf_job(fd));

	ehdr = (Elf32_Ehdr *)edata->d_buf;

	if (ehdr->e_shoff == 0) {
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	if ((secdata = elf_read(fd, (long)ehdr->e_shoff,
		(size_t)(ehdr->e_shentsize * ehdr->e_shnum),
		(size_t)(ehdr->e_shnum * sizeof (Elf32_Ehdr)),
		ELF_T_SHDR)) == 0) {
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	/* find symbol table section */
	symhdr = (Elf32_Shdr *)secdata->d_buf;
	for (i = 0; i < (Elf32_Word)ehdr->e_shnum; i++, symhdr++)
		if (symhdr->sh_type == SHT_SYMTAB)
			break;

	if ((symhdr->sh_type != SHT_SYMTAB) ||
		(symhdr->sh_link >= ehdr->e_shnum)) {
		free(secdata->d_buf);
		free(secdata);
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	if ((symdata = elf_read(fd, (long)symhdr->sh_offset,
		(size_t)symhdr->sh_size,
		(size_t)((symhdr->sh_size / symhdr->sh_entsize) *
		sizeof (Elf32_Sym)), ELF_T_SYM)) == 0) {
		free(secdata->d_buf);
		free(secdata);
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	/* read string table */
	strhdr = (Elf32_Shdr *)secdata->d_buf;
	strhdr = strhdr + symhdr->sh_link;

	if (strhdr->sh_type != SHT_STRTAB) {
		free(symdata->d_buf);
		free(symdata);
		free(secdata->d_buf);
		free(secdata);
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	if ((strdata = elf_read(fd, strhdr->sh_offset, strhdr->sh_size,
		strhdr->sh_size, ELF_T_BYTE)) == 0) {
		free(symdata->d_buf);
		free(symdata);
		free(secdata->d_buf);
		free(secdata);
		free(edata->d_buf);
		free(edata);
		return (end_elf_job(fd));
	}

	((char *)strdata->d_buf)[0] = '\0';
	((char *)strdata->d_buf)[strhdr->sh_size-1] = '\0';

	sym = (Elf32_Sym *) (symdata->d_buf);
	sym_end = sym + symdata->d_size / sizeof (Elf32_Sym);
	for (; sym < sym_end; ++sym) {
		struct nlist *p;
		char *name;
		if (sym->st_name > strhdr->sh_size) {
			free(strdata->d_buf);
			free(strdata);
			free(symdata->d_buf);
			free(symdata);
			free(secdata->d_buf);
			free(secdata);
			free(edata->d_buf);
			free(edata);
			return (end_elf_job(fd));
		}
		name = (char *)strdata->d_buf + sym->st_name;
		if (name == 0)
			continue;
		for (p = list; p->n_name && p->n_name[0]; ++p) {
			if (strcmp(p->n_name, name)) {
				continue;
			}
			p->n_value = sym->st_value;
			p->n_type = ELF32_ST_TYPE(sym->st_info);
			p->n_scnum = sym->st_shndx;
			nreq--;
			break;
		}
	}
	/*
	 * Currently there is only one symbol table section
	 * in an object file, but this restriction may be
	 * relaxed in the future.
	 */
	(void) close(fd);
	free(secdata->d_buf);
	free(strdata->d_buf);
	free(symdata->d_buf);
	free(edata->d_buf);
	free(secdata);
	free(strdata);
	free(symdata);
	free(edata);
	return (nreq);
}

/*
 * allocate memory of size memsize and read size bytes
 * starting at offset from fd - the file data are
 * translated in place using the low-level libelf
 * translation routines
 */

static Elf_Data *
elf_read(int fd, long offset, size_t size, size_t memsize, Elf_Type dtype)
{
	Elf_Data *dsrc, *ddst;
	Elf_Data srcdata;
	size_t maxsize;
	char *p;

	dsrc = &srcdata;

	if (size == 0)
		return (0);

	if ((maxsize = memsize) < size)
		maxsize = size;


	if ((ddst = (Elf_Data *)malloc(sizeof (Elf_Data))) == 0)
		return (0);

	if ((p = malloc(maxsize)) == 0) {
		free(ddst);
		return (0);
	}

	if (lseek(fd, offset, 0L) == -1) {
		free(ddst);
		free(p);
		return (0);
	}

	if (read(fd, p, size) != size) {
		free(ddst);
		free(p);
		return (0);
	}

	dsrc->d_buf = p;
	dsrc->d_type = dtype;
	dsrc->d_size = size;
	dsrc->d_version = fvers;
	ddst->d_buf = p;
	ddst->d_size = memsize;
	ddst->d_version = EV_CURRENT;

	if (elf32_xlatetom(ddst, dsrc, encode) != ddst) {
		free(ddst);
		free(p);
		return (0);
	}

	return (ddst);
}

static int
end_elf_job(int fd)
{
	(void) close(fd);
	return (-1);
}

#if COFF_NLIST_SUPPORTED
static int
_coff_nlist(int fd, struct nlist *list)
{
	struct	filehdr	buf;
	struct	syment	sym;
	long n;
	int bufsiz = FILHSZ;
#if FLEXNAMES
	char *strtab = (char *)0;
	long strtablen;
#endif
	struct nlist *p, *inl;
	struct syment *q;
	long	sa;
	int 	nreq;

	if (read(fd, (char *)&buf, bufsiz) == -1) {
		(void) close(fd);
		return (-1);
	}

	if (BADMAG(buf.f_magic)) {
		(void) close(fd);
		return (-1);
	}
	sa = buf.f_symptr;	/* direct pointer to sym tab */
	if (lseek(fd, (long)sa, 0) == -1L) {
		(void) close(fd);
		return (-1);
	}
	q = &sym;
	n = buf.f_nsyms;	/* num. of sym tab entries */

	/* count the number of symbols requested */
	for (inl = list, nreq = 0; inl->n_name && inl->n_name[0]; ++inl, nreq++)
		;

	while (n) {
		if (sym_read(fd, &sym, SYMESZ) == -1) {
			sym_close(fd);
			return (-1);
		}
		n -= (q->n_numaux + 1L);
		for (p = list; p->n_name && p->n_name[0]; ++p) {
			if (p->n_value != 0L && p->n_sclass == C_EXT)
				continue;
			/*
			 * For 6.0, the name in an object file is
			 * either stored in the eight long character
			 * array, or in a string table at the end
			 * of the object file.  If the name is in the
			 * string table, the eight characters are
			 * thought of as a pair of longs, (n_zeroes
			 * and n_offset) the first of which is zero
			 * and the second is the offset of the name
			 * in the string table.
			 */
#if FLEXNAMES
			if (q->n_zeroes == 0L)	/* in string table */
			{
				if (strtab == (char *)0) /* need it */
				{
					long home = lseek(fd, 0L, 1);
					if (home == -1L) {
						sym_close(fd);
						return (-1);
					}
					if (lseek(fd, buf.f_symptr +
					    buf.f_nsyms * SYMESZ, 0) == -1 ||
					    read(fd, (char *)&strtablen,
					    sizeof (long)) != sizeof (long) ||
					    (strtab = (char *)malloc(
					    (unsigned)strtablen)) ==
					    (char *)0 ||
					    read(fd, strtab + sizeof (long),
					    strtablen - sizeof (long)) !=
					    strtablen - sizeof (long) ||
					    strtab[strtablen - 1] != '\0' ||
					    lseek(fd, home, 0) == -1) {
						(void) lseek(fd, home, 0);
						sym_close(fd);
						if (strtab != (char *)0)
							free(strtab);
						return (-1);
					}
				}
				if (q->n_offset < sizeof (long) ||
					q->n_offset >= strtablen) {
					sym_close(fd);
					if (strtab != (char *)0)
						free(strtab);
					return (-1);
				}
				if (strcmp(&strtab[q->n_offset],
					p->n_name)) {
					continue;
				}
			}
			else
#endif /* FLEXNAMES */
			{
				if (strncmp(q->_n._n_name,
					p->n_name, SYMNMLEN)) {
					continue;
				}
			}

			p->n_value = q->n_value;
			p->n_type = q->n_type;
			p->n_scnum = q->n_scnum;
			p->n_sclass = q->n_sclass;
			nreq--;
			break;
		}
	}
#if FLEXNAMES
	sym_close(fd);
	if (strtab != (char *)0)
		free(strtab);
#endif
	return (nreq);
}

static void
sym_close(int fd)
{
	num_in_buf = 0;
	next_entry = (char *)0;

	(void) close(fd);
}

/* buffered read of symbol table */
static int
sym_read(int fd, struct syment *sym, int size)
{
	long where = 0L;

	if ((where = lseek(fd, 0L, 1)) == -1L) {
		sym_close(fd);
		return (-1);
	}

	if (!num_in_buf) {
		if (fill_sym_buf(fd, size) == -1)
			return (-1);
	}
	(void) memcpy((char *)sym, next_entry, size);
	num_in_buf--;

	if (sym->n_numaux && !num_in_buf) {
		if (fill_sym_buf(fd, size) == -1)
			return (-1);
	}
	if ((lseek(fd, where + SYMESZ + (AUXESZ * sym->n_numaux), 0)) == -1L) {
		sym_close(fd);
		return (-1);
	}
	size += AUXESZ * sym->n_numaux;
	num_in_buf--;

	next_entry += size;
	return (0);
}

static int
fill_sym_buf(int fd, int size)
{
	if ((num_in_buf = read(fd, sym_buf, size * SPACE)) == -1)
		return (-1);
	num_in_buf /= size;
	next_entry = &(sym_buf[0]);
	return (0);
}
#endif /* COFF_NLIST_SUPPORTED */
