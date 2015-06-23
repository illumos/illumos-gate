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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__sparcv9) || defined(__amd64)

#define Elf_Ehdr	Elf64_Ehdr
#define Elf_Phdr	Elf64_Phdr
#define Elf_Shdr	Elf64_Shdr
#define Elf_Sym		Elf64_Sym
#define ELF_ST_BIND	ELF64_ST_BIND
#define ELF_ST_TYPE	ELF64_ST_TYPE

#else

#define Elf_Ehdr	Elf32_Ehdr
#define Elf_Phdr	Elf32_Phdr
#define Elf_Shdr	Elf32_Shdr
#define Elf_Sym		Elf32_Sym
#define ELF_ST_BIND	ELF32_ST_BIND
#define ELF_ST_TYPE	ELF32_ST_TYPE

#endif	/* __sparcv9 */

/* semi-permanent data established by __fex_sym_init */
static	prmap_t		*pm = NULL;		/* prmap_t array */
static	int			npm = 0;		/* number of entries in pm */

/* transient data modified by __fex_sym */
static	prmap_t		*lpm = NULL;	/* prmap_t found in last call */
static	Elf_Phdr	*ph = NULL;		/* program header array */
static	int			phsize = 0;		/* size of ph */
static	int			nph;			/* number of entries in ph */
static	char		*stbuf = NULL;	/* symbol and string table buffer */
static	int			stbufsize = 0;	/* size of stbuf */
static	int			stoffset;		/* offset of string table in stbuf */
static	int			nsyms;			/* number of symbols in stbuf */

/* get a current prmap_t list (must call this before each stack trace) */
void
__fex_sym_init()
{
	struct stat	statbuf;
	long		n;
	int			i;

	/* clear out the previous prmap_t list */
	if (pm != NULL)
		free(pm);
	pm = lpm = NULL;
	npm = 0;

	/* get the current prmap_t list */
	if (stat("/proc/self/map", &statbuf) < 0 || statbuf.st_size <= 0 ||
		(pm = (prmap_t*)malloc(statbuf.st_size)) == NULL)
		return;
	if ((i = open("/proc/self/map", O_RDONLY)) < 0)
	{
		free(pm);
		pm = NULL;
		return;
	}
	n = read(i, pm, statbuf.st_size);
	close(i);
	if (n != statbuf.st_size)
	{
		free(pm);
		pm = NULL;
	}
	else
		npm = (int) (n / sizeof(prmap_t));
}

/* read ELF program headers and symbols; return -1 on error, 0 otherwise */
static int
__fex_read_syms(int fd)
{
	Elf_Ehdr	h;
	Elf_Shdr	*sh;
	int			i, size;

	/* read the ELF header */
	if (read(fd, &h, sizeof(h)) != sizeof(h))
		return -1;
	if (h.e_ident[EI_MAG0] != ELFMAG0 ||
		h.e_ident[EI_MAG1] != ELFMAG1 ||
		h.e_ident[EI_MAG2] != ELFMAG2 ||
		h.e_ident[EI_MAG3] != ELFMAG3 ||
		h.e_phentsize != sizeof(Elf_Phdr) ||
		h.e_shentsize != sizeof(Elf_Shdr))
		return -1;

	/* get space for the program headers */
	size = h.e_phnum * h.e_phentsize;
	if (size > phsize)
	{
		if (ph)
			free(ph);
		phsize = nph = 0;
		if ((ph = (Elf_Phdr*)malloc(size)) == NULL)
			return -1;
		phsize = size;
	}

	/* read the program headers */
	if (lseek(fd, h.e_phoff, SEEK_SET) != h.e_phoff ||
		read(fd, ph, size) != (ssize_t)size)
	{
		nph = 0;
		return -1;
	}
	nph = h.e_phnum;

	/* read the section headers */
	size = h.e_shnum * h.e_shentsize;
	if ((sh = (Elf_Shdr*)malloc(size)) == NULL)
		return -1;
	if (lseek(fd, h.e_shoff, SEEK_SET) != h.e_shoff ||
		read(fd, sh, size) != (ssize_t)size)
	{
		free(sh);
		return -1;
	}

	/* find the symtab section header */
	for (i = 0; i < h.e_shnum; i++)
	{
		if (sh[i].sh_type == SHT_SYMTAB)
			break; /* assume there is only one */
	}
	if (i == h.e_shnum || sh[i].sh_size == 0 ||
		sh[i].sh_entsize != sizeof(Elf_Sym) ||
		sh[i].sh_link < 1 || sh[i].sh_link >= h.e_shnum ||
		sh[sh[i].sh_link].sh_type != SHT_STRTAB ||
		sh[sh[i].sh_link].sh_size == 0)
	{
		free(sh);
		return -1;
	}

	/* get space for the symbol and string tables */
	size = (int) (sh[i].sh_size + sh[sh[i].sh_link].sh_size);
	if (size > stbufsize)
	{
		if (stbuf)
			free(stbuf);
		stbufsize = nsyms = 0;
		if ((stbuf = (char*)malloc(size)) == NULL)
		{
			free(sh);
			return -1;
		}
		stbufsize = size;
	}

	/* read the symbol and string tables */
	if (lseek(fd, sh[i].sh_offset, SEEK_SET) != sh[i].sh_offset ||
		read(fd, stbuf, sh[i].sh_size) != sh[i].sh_size ||
		lseek(fd, sh[sh[i].sh_link].sh_offset, SEEK_SET) !=
			sh[sh[i].sh_link].sh_offset ||
		read(fd, stbuf + sh[i].sh_size, sh[sh[i].sh_link].sh_size) !=
			sh[sh[i].sh_link].sh_size)
	{
		free(sh);
		return (-1);
	}
	nsyms = (int) (sh[i].sh_size / sh[i].sh_entsize);
	stoffset = (int) sh[i].sh_size;

	free(sh);
	return (0);
}

/* find the symbol corresponding to the given text address;
   return NULL on error, symbol address otherwise */
char *
__fex_sym(char *a, char **name)
{
	Elf_Sym			*s;
	unsigned long	fo, va, value;
	int				fd, i, j, nm;
	char			fname[PRMAPSZ+20];

	/* see if the last prmap_t found contains the indicated address */
	if (lpm)
	{
		if (a >= (char*)lpm->pr_vaddr && a < (char*)lpm->pr_vaddr +
			lpm->pr_size)
			goto cont;
	}

	/* look for a prmap_t that contains the indicated address */
	for (i = 0; i < npm; i++)
	{
		if (a >= (char*)pm[i].pr_vaddr && a < (char*)pm[i].pr_vaddr +
			pm[i].pr_size)
			break;
	}
	if (i == npm)
		return NULL;

	/* get an open file descriptor for the mapped object */
	if (pm[i].pr_mapname[0] == '\0')
		return NULL;
	strcpy(fname, "/proc/self/object/");
	strncat(fname, pm[i].pr_mapname, PRMAPSZ);
	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return NULL;

	/* read the program headers and symbols */
	lpm = NULL;
	j = __fex_read_syms(fd);
	close(fd);
	if (j < 0)
		return NULL;
	lpm = &pm[i];

cont:
	/* compute the file offset corresponding to the mapped address */
	fo = (a - (char*)lpm->pr_vaddr) + lpm->pr_offset;

	/* find the program header containing the file offset */
	for (i = 0; i < nph; i++)
	{
		if (ph[i].p_type == PT_LOAD && fo >= ph[i].p_offset &&
			fo < ph[i].p_offset + ph[i].p_filesz)
			break;
	}
	if (i == nph)
		return NULL;

	/* compute the virtual address corresponding to the file offset */
	va = (fo - ph[i].p_offset) + ph[i].p_vaddr;

	/* find the symbol in this segment with the highest value
	   less than or equal to the virtual address */
	s = (Elf_Sym*)stbuf;
	value = nm = 0;
	for (j = 0; j < nsyms; j++)
	{
		if (s[j].st_name == 0 || s[j].st_shndx == SHN_UNDEF ||
			(ELF_ST_BIND(s[j].st_info) != STB_LOCAL &&
			ELF_ST_BIND(s[j].st_info) != STB_GLOBAL &&
			ELF_ST_BIND(s[j].st_info) != STB_WEAK) ||
			(ELF_ST_TYPE(s[j].st_info) != STT_NOTYPE &&
			ELF_ST_TYPE(s[j].st_info) != STT_OBJECT &&
			ELF_ST_TYPE(s[j].st_info) != STT_FUNC))
		{
			continue;
		}

		if (s[j].st_value < ph[i].p_vaddr || s[j].st_value >= ph[i].p_vaddr
			+ ph[i].p_memsz)
		{
			continue;
		}

		if (s[j].st_value < value || s[j].st_value > va)
			continue;

		value = s[j].st_value;
		nm = s[j].st_name;
	}
	if (nm == 0)
		return NULL;

	/* pass back the name and return the mapped address of the symbol */
	*name = stbuf + stoffset + nm;
	fo = (value - ph[i].p_vaddr) + ph[i].p_offset;
	return (char*)lpm->pr_vaddr + (fo - lpm->pr_offset);
}
