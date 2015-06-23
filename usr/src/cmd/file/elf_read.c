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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ELF files can exceed 2GB in size. A standard 32-bit program
 * like 'file' cannot read past 2GB, and will be unable to see
 * the ELF section headers that typically are at the end of the
 * object. The simplest solution to this problem would be to make
 * the 'file' command a 64-bit application. However, as a matter of
 * policy, we do not want to require this. A simple command like
 * 'file' should not carry such a requirement, especially as we
 * support 32-bit only hardware.
 *
 * An alternative solution is to build this code as 32-bit
 * large file aware. The usual way to do this is to define a pair
 * of preprocessor definitions:
 *
 *	_LARGEFILE64_SOURCE
 *		Map standard I/O routines to their largefile aware versions.
 *
 *	_FILE_OFFSET_BITS=64
 *		Map off_t to off64_t
 *
 * The problem with this solution is that libelf is not large file capable,
 * and the libelf header file will prevent compilation if
 * _FILE_OFFSET_BITS is set to 64.
 *
 * So, the solution used in this code is to define _LARGEFILE64_SOURCE
 * to get access to the 64-bit APIs, not to define _FILE_OFFSET_BITS, and to
 * use our own types in place of off_t, and size_t. We read all the file
 * data directly using pread64(), and avoid the use of libelf for anything
 * other than the xlate functionality.
 */
#define	_LARGEFILE64_SOURCE
#define	FILE_ELF_OFF_T	off64_t
#define	FILE_ELF_SIZE_T	uint64_t

#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <libelf.h>
#include <stdlib.h>
#include <limits.h>
#include <locale.h>
#include <string.h>
#include <errno.h>
#include <procfs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/elf.h>
#include <elfcap.h>
#include "file.h"
#include "elf_read.h"

extern const char *File;

static int get_class(void);
static int get_version(void);
static int get_format(void);
static int process_shdr(Elf_Info *);
static int process_phdr(Elf_Info *);
static int file_xlatetom(Elf_Type, char *);
static int xlatetom_nhdr(Elf_Nhdr *);
static int get_phdr(Elf_Info *, int);
static int get_shdr(Elf_Info *, int);

static Elf_Ehdr	EI_Ehdr;		/* Elf_Ehdr to be stored */
static Elf_Word	EI_Ehdr_shnum;		/* # section headers */
static Elf_Word	EI_Ehdr_phnum;		/* # program headers */
static Elf_Word	EI_Ehdr_shstrndx;	/* Index of section hdr string table */
static Elf_Shdr	EI_Shdr;		/* recent Elf_Shdr to be stored */
static Elf_Phdr	EI_Phdr;		/* recent Elf_Phdr to be stored */


static int
get_class(void)
{
	return (EI_Ehdr.e_ident[EI_CLASS]);
}

static int
get_version(void)
{
	/* do as what libelf:_elf_config() does */
	return (EI_Ehdr.e_ident[EI_VERSION] ?
	    EI_Ehdr.e_ident[EI_VERSION] : 1);
}

static int
get_format(void)
{
	return (EI_Ehdr.e_ident[EI_DATA]);
}

/*
 * file_xlatetom:	translate different headers from file
 * 			representation to memory representaion.
 */
#define	HDRSZ 512
static int
file_xlatetom(Elf_Type type, char *hdr)
{
	Elf_Data src, dst;
	char *hbuf[HDRSZ];
	int version, format;

	version = get_version();
	format = get_format();

	/* will convert only these types */
	if (type != ELF_T_EHDR && type != ELF_T_PHDR &&
	    type != ELF_T_SHDR && type != ELF_T_WORD &&
	    type != ELF_T_CAP)
		return (ELF_READ_FAIL);

	src.d_buf = (Elf_Void *)hdr;
	src.d_type = type;
	src.d_version = version;

	dst.d_buf = (Elf_Void *)&hbuf;
	dst.d_version = EV_CURRENT;

	src.d_size = elf_fsize(type, 1, version);
	dst.d_size = elf_fsize(type, 1, EV_CURRENT);
	if (elf_xlatetom(&dst, &src, format) == NULL)
		return (ELF_READ_FAIL);

	(void) memcpy(hdr, &hbuf, dst.d_size);
	return (ELF_READ_OKAY);
}

/*
 * xlatetom_nhdr:	There is no routine to convert Note header
 * 			so we convert each field of this header.
 */
static int
xlatetom_nhdr(Elf_Nhdr *nhdr)
{
	int r = ELF_READ_FAIL;

	r |= file_xlatetom(ELF_T_WORD, (char *)&nhdr->n_namesz);
	r |= file_xlatetom(ELF_T_WORD, (char *)&nhdr->n_descsz);
	r |= file_xlatetom(ELF_T_WORD, (char *)&nhdr->n_type);
	return (r);
}

/*
 * elf_read:	reads elf header, program, section headers to
 * 		collect all information needed for file(1)
 *		output and stores them in Elf_Info.
 */
int
elf_read(int fd, Elf_Info *EI)
{
	FILE_ELF_SIZE_T	size;
	int		ret = 1;

	Elf_Ehdr *ehdr = &EI_Ehdr;

	EI->elffd = fd;
	size = sizeof (Elf_Ehdr);

	if (pread64(EI->elffd, (void*)ehdr, size, 0) != size)
		ret = 0;


	if (file_xlatetom(ELF_T_EHDR, (char *)ehdr) == ELF_READ_FAIL)
		ret = 0;

	if (EI->file == NULL)
		return (ELF_READ_FAIL);

	/*
	 * Extended section or program indexes in use? If so, special
	 * values in the ELF header redirect us to get the real values
	 * from shdr[0].
	 */
	EI_Ehdr_shnum = EI_Ehdr.e_shnum;
	EI_Ehdr_phnum = EI_Ehdr.e_phnum;
	EI_Ehdr_shstrndx = EI_Ehdr.e_shstrndx;
	if (((EI_Ehdr_shnum == 0) || (EI_Ehdr_phnum == PN_XNUM)) &&
	    (EI_Ehdr.e_shoff != 0)) {
		if (get_shdr(EI, 0) == ELF_READ_FAIL)
			return (ELF_READ_FAIL);
		if (EI_Ehdr_shnum == 0)
			EI_Ehdr_shnum = EI_Shdr.sh_size;
		if ((EI_Ehdr_phnum == PN_XNUM) && (EI_Shdr.sh_info != 0))
			EI_Ehdr_phnum = EI_Shdr.sh_info;
		if (EI_Ehdr_shstrndx == SHN_XINDEX)
			EI_Ehdr_shstrndx = EI_Shdr.sh_link;
	}

	EI->type = ehdr->e_type;
	EI->machine = ehdr->e_machine;
	EI->flags = ehdr->e_flags;

	if (ret == 0) {
		(void) fprintf(stderr, gettext("%s: %s: can't "
		    "read ELF header\n"), File, EI->file);
		return (ELF_READ_FAIL);
	}
	if (process_phdr(EI) == ELF_READ_FAIL)
		return (ELF_READ_FAIL);

	/* We don't need section info for core files */
	if (ehdr->e_type != ET_CORE)
		if (process_shdr(EI) == ELF_READ_FAIL)
			return (ELF_READ_FAIL);

	return (ELF_READ_OKAY);
}

/*
 * get_phdr:	reads program header of specified index.
 */
static int
get_phdr(Elf_Info *EI, int inx)
{
	FILE_ELF_OFF_T	off = 0;
	FILE_ELF_SIZE_T	size;

	if (inx >= EI_Ehdr_phnum)
		return (ELF_READ_FAIL);

	size = sizeof (Elf_Phdr);
	off = (FILE_ELF_OFF_T)EI_Ehdr.e_phoff + (inx * size);
	if (pread64(EI->elffd, (void *)&EI_Phdr, size, off) != size)
		return (ELF_READ_FAIL);

	if (file_xlatetom(ELF_T_PHDR, (char *)&EI_Phdr) == ELF_READ_FAIL)
		return (ELF_READ_FAIL);

	return (ELF_READ_OKAY);
}

/*
 * get_shdr:	reads section header of specified index.
 */
static int
get_shdr(Elf_Info *EI, int inx)
{
	FILE_ELF_OFF_T	off = 0;
	FILE_ELF_SIZE_T	size;

	/*
	 * Prevent access to non-existent section headers.
	 *
	 * A value of 0 for e_shoff means that there is no section header
	 * array in the file. A value of 0 for e_shndx does not necessarily
	 * mean this - there can still be a 1-element section header array
	 * to support extended section or program header indexes that
	 * exceed the 16-bit fields used in the ELF header to represent them.
	 */
	if ((EI_Ehdr.e_shoff == 0) || ((inx > 0) && (inx >= EI_Ehdr_shnum)))
		return (ELF_READ_FAIL);

	size = sizeof (Elf_Shdr);
	off = (FILE_ELF_OFF_T)EI_Ehdr.e_shoff + (inx * size);

	if (pread64(EI->elffd, (void *)&EI_Shdr, size, off) != size)
		return (ELF_READ_FAIL);

	if (file_xlatetom(ELF_T_SHDR, (char *)&EI_Shdr) == ELF_READ_FAIL)
		return (ELF_READ_FAIL);

	return (ELF_READ_OKAY);
}

/*
 * process_phdr:	Read Program Headers and see if it is a core
 *			file of either new or (pre-restructured /proc)
 * 			type, read the name of the file that dumped this
 *			core, else see if this is a dynamically linked.
 */
static int
process_phdr(Elf_Info *EI)
{
	register int inx;

	Elf_Nhdr	Nhdr, *nhdr;	/* note header just read */
	Elf_Phdr	*phdr = &EI_Phdr;

	FILE_ELF_SIZE_T	nsz, nmsz, dsz;
	FILE_ELF_OFF_T	offset;
	int	class;
	int	ntype;
	char	*psinfo, *fname;

	nsz = sizeof (Elf_Nhdr);
	nhdr = &Nhdr;
	class = get_class();
	for (inx = 0; inx < EI_Ehdr_phnum; inx++) {
		if (get_phdr(EI, inx) == ELF_READ_FAIL)
			return (ELF_READ_FAIL);

		/* read the note if it is a core */
		if (phdr->p_type == PT_NOTE &&
		    EI_Ehdr.e_type == ET_CORE) {
			/*
			 * If the next segment is also a note, use it instead.
			 */
			if (get_phdr(EI, inx+1) == ELF_READ_FAIL)
				return (ELF_READ_FAIL);
			if (phdr->p_type != PT_NOTE) {
				/* read the first phdr back */
				if (get_phdr(EI, inx) == ELF_READ_FAIL)
					return (ELF_READ_FAIL);
			}
			offset = phdr->p_offset;
			if (pread64(EI->elffd, (void *)nhdr, nsz, offset)
			    != nsz)
				return (ELF_READ_FAIL);

			/* Translate the ELF note header */
			if (xlatetom_nhdr(nhdr) == ELF_READ_FAIL)
				return (ELF_READ_FAIL);

			ntype = nhdr->n_type;
			nmsz = nhdr->n_namesz;
			dsz = nhdr->n_descsz;

			offset += nsz + ((nmsz + 0x03) & ~0x3);
			if ((psinfo = malloc(dsz)) == NULL) {
				int err = errno;
				(void) fprintf(stderr, gettext("%s: malloc "
				    "failed: %s\n"), File, strerror(err));
				exit(1);
			}
			if (pread64(EI->elffd, psinfo, dsz, offset) != dsz)
				return (ELF_READ_FAIL);
			/*
			 * We want to print the string contained
			 * in psinfo->pr_fname[], where 'psinfo'
			 * is either an old NT_PRPSINFO structure
			 * or a new NT_PSINFO structure.
			 *
			 * Old core files have only type NT_PRPSINFO.
			 * New core files have type NT_PSINFO.
			 *
			 * These structures are also different by
			 * virtue of being contained in a core file
			 * of either 32-bit or 64-bit type.
			 *
			 * To further complicate matters, we ourself
			 * might be compiled either 32-bit or 64-bit.
			 *
			 * For these reason, we just *know* the offsets of
			 * pr_fname[] into the four different structures
			 * here, regardless of how we are compiled.
			 */
			if (class == ELFCLASS32) {
				/* 32-bit core file, 32-bit structures */
				if (ntype == NT_PSINFO)
					fname = psinfo + 88;
				else	/* old: NT_PRPSINFO */
					fname = psinfo + 84;
			} else if (class == ELFCLASS64) {
				/* 64-bit core file, 64-bit structures */
				if (ntype == NT_PSINFO)
					fname = psinfo + 136;
				else	/* old: NT_PRPSINFO */
					fname = psinfo + 120;
			}
			EI->core_type = (ntype == NT_PRPSINFO)?
			    EC_OLDCORE : EC_NEWCORE;
			(void) memcpy(EI->fname, fname, strlen(fname));
			free(psinfo);
		}
		if (phdr->p_type == PT_DYNAMIC) {
			EI->dynamic = B_TRUE;
		}
	}
	return (ELF_READ_OKAY);
}

/*
 * process_shdr:	Read Section Headers to attempt to get HW/SW
 *			capabilities by looking at the SUNW_cap
 *			section and set string in Elf_Info.
 *			Also look for symbol tables and debug
 *			information sections. Set the "stripped" field
 *			in Elf_Info with corresponding flags.
 */
static int
process_shdr(Elf_Info *EI)
{
	int 		capn, mac;
	int 		i, j, idx;
	FILE_ELF_OFF_T	cap_off;
	FILE_ELF_SIZE_T	csize;
	char		*strtab;
	size_t		strtab_sz;
	Elf_Cap 	Chdr;
	Elf_Shdr	*shdr = &EI_Shdr;


	csize = sizeof (Elf_Cap);
	mac = EI_Ehdr.e_machine;

	/* if there are no sections, return success anyway */
	if (EI_Ehdr.e_shoff == 0 && EI_Ehdr_shnum == 0)
		return (ELF_READ_OKAY);

	/* read section names from String Section */
	if (get_shdr(EI, EI_Ehdr_shstrndx) == ELF_READ_FAIL)
		return (ELF_READ_FAIL);

	if ((strtab = malloc(shdr->sh_size)) == NULL)
		return (ELF_READ_FAIL);

	if (pread64(EI->elffd, strtab, shdr->sh_size, shdr->sh_offset)
	    != shdr->sh_size)
		return (ELF_READ_FAIL);

	strtab_sz = shdr->sh_size;

	/* read all the sections and process them */
	for (idx = 1, i = 0; i < EI_Ehdr_shnum; idx++, i++) {
		char *shnam;

		if (get_shdr(EI, i) == ELF_READ_FAIL)
			return (ELF_READ_FAIL);

		if (shdr->sh_type == SHT_NULL) {
			idx--;
			continue;
		}

		cap_off = shdr->sh_offset;
		if (shdr->sh_type == SHT_SUNW_cap) {
			char capstr[128];

			if (shdr->sh_size == 0 || shdr->sh_entsize == 0) {
				(void) fprintf(stderr, ELF_ERR_ELFCAP1,
				    File, EI->file);
				return (ELF_READ_FAIL);
			}
			capn = (shdr->sh_size / shdr->sh_entsize);
			for (j = 0; j < capn; j++) {
				/*
				 * read cap and xlate the values
				 */
				if (pread64(EI->elffd, &Chdr, csize, cap_off)
				    != csize ||
				    file_xlatetom(ELF_T_CAP, (char *)&Chdr)
				    == 0) {
					(void) fprintf(stderr, ELF_ERR_ELFCAP2,
					    File, EI->file);
					return (ELF_READ_FAIL);
				}

				cap_off += csize;

				/*
				 * Each capatibility group is terminated with
				 * CA_SUNW_NULL.  Groups other than the first
				 * represent symbol capabilities, and aren't
				 * interesting here.
				 */
				if (Chdr.c_tag == CA_SUNW_NULL)
					break;

				(void) elfcap_tag_to_str(ELFCAP_STYLE_UC,
				    Chdr.c_tag, Chdr.c_un.c_val, capstr,
				    sizeof (capstr), ELFCAP_FMT_SNGSPACE,
				    mac);

				if ((*EI->cap_str != '\0') && (*capstr != '\0'))
					(void) strlcat(EI->cap_str, " ",
					    sizeof (EI->cap_str));

				(void) strlcat(EI->cap_str, capstr,
				    sizeof (EI->cap_str));
			}
		}

		/*
		 * Definition time:
		 *	- "not stripped" means that an executable file
		 *	contains a Symbol Table (.symtab)
		 *	- "stripped" means that an executable file
		 *	does not contain a Symbol Table.
		 * When strip -l or strip -x is run, it strips the
		 * debugging information (.line section name (strip -l),
		 * .line, .debug*, .stabs*, .dwarf* section names
		 * and SHT_SUNW_DEBUGSTR and SHT_SUNW_DEBUG
		 * section types (strip -x), however the Symbol
		 * Table will still be present.
		 * Therefore, if
		 *	- No Symbol Table present, then report
		 *		"stripped"
		 *	- Symbol Table present with debugging
		 *	information (line number or debug section names,
		 *	or SHT_SUNW_DEBUGSTR or SHT_SUNW_DEBUG section
		 *	types) then report:
		 *		"not stripped"
		 *	- Symbol Table present with no debugging
		 *	information (line number or debug section names,
		 *	or SHT_SUNW_DEBUGSTR or SHT_SUNW_DEBUG section
		 *	types) then report:
		 *		"not stripped, no debugging information
		 *		available"
		 */
		if ((EI->stripped & E_NOSTRIP) == E_NOSTRIP)
			continue;

		if (!(EI->stripped & E_SYMTAB) &&
		    (shdr->sh_type == SHT_SYMTAB)) {
			EI->stripped |= E_SYMTAB;
			continue;
		}

		if (shdr->sh_name >= strtab_sz)
			shnam = NULL;
		else
			shnam = &strtab[shdr->sh_name];

		if (!(EI->stripped & E_DBGINF) &&
		    ((shdr->sh_type == SHT_SUNW_DEBUG) ||
		    (shdr->sh_type == SHT_SUNW_DEBUGSTR) ||
		    (shnam != NULL && is_in_list(shnam)))) {
			EI->stripped |= E_DBGINF;
		}
	}
	free(strtab);

	return (ELF_READ_OKAY);
}
