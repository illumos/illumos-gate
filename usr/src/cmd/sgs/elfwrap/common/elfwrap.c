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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<libgen.h>
#include	<errno.h>
#include	<libelf.h>
#include	<stdio.h>
#include	<strings.h>
#include	<msg.h>
#include	<machdep.h>
#include	<_libelf.h>
#include	<_elfwrap.h>

/*
 * This module is compiled to support 32-bit and 64-bit class objects.  Define
 * the necessary interfaces for these classes.
 */
#if	defined(_ELF64)
#define	input	input64
#define	output	output64
#else
#define	input	input32
#define	output	output32
#endif

static StdSec_t	StdSecs[] = {
	{ MSG_ORIG(MSG_SCN_SYMTAB),	SHT_SYMTAB,	0 },
	{ MSG_ORIG(MSG_SCN_STRTAB),	SHT_STRTAB,	SHF_STRINGS},
	{ MSG_ORIG(MSG_SCN_SHSTRTAB),	SHT_STRTAB,	SHF_STRINGS},
	{ NULL,				0,		0 }
};

/*
 * Process all input files.  These contain the data that will be assigned to a
 * new ELF section.
 */
int
input(int argc, char **argv, const char *prog, const char *ofile,
    ObjDesc_t *odp)
{
	OutSec_t	outsec;
	StdSec_t	*stdsecs;
	size_t		ndx, cnt;
	int		ret = 0, fd = -1;

	/*
	 * Make sure we have access to read each input file, and prepare an
	 * output section descriptor for each.  Note, we assign section indexes
	 * starting at 1, as section index 0 is special, and is created by
	 * libelf.
	 */
	for (ndx = 1; argc; argc--, argv++, ndx++) {
		char		*file = *argv;
		struct stat	status;
		size_t		namesz;

		/*
		 * Close any previously opened file.
		 */
		if (fd != -1)
			(void) close(fd);

		/*
		 * Identify the section.
		 */
		outsec.os_name = basename(file);
		outsec.os_type = SHT_PROGBITS;
		outsec.os_flags = SHF_ALLOC;
		outsec.os_ndx = ndx;

		if ((fd = open(file, O_RDONLY)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    prog, file, strerror(err));
			ret = 1;
			continue;
		}
		if (fstat(fd, &status) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_FSTAT),
			    prog, file, strerror(err));
			ret = 1;
			continue;
		}

		if ((outsec.os_size = status.st_size) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_WARN_ZERO),
			    prog, file);
			continue;
		}

		if ((outsec.os_addr = mmap(0, outsec.os_size, PROT_READ,
		    MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_MMAP),
			    prog, file, strerror(err));
			ret = 1;
			continue;
		}

		if (alist_append(&(odp->od_outsecs), &outsec, sizeof (OutSec_t),
		    AL_CNT_WOSECS) == 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_ALLOC),
			    prog, file, strerror(err));
			return (1);
		}

		/*
		 * Each data section contributes:
		 *
		 * i.	its basename, prefixed with a "dot", to the .shstrtab.
		 * ii.	a section symbol.
		 * iii.	a data symbol, using the basename, with an
		 *	appended "_data" string.
		 * iv.	a data size symbol, using the basename with an
		 *	appended "_size" string.
		 */
		namesz = strlen(outsec.os_name) + 1;

		odp->od_symtabno += 3;
		odp->od_strtabsz += (namesz + MSG_STR_START_SIZE);
		odp->od_strtabsz += (namesz + MSG_STR_END_SIZE);
		odp->od_shstrtabsz += (namesz + MSG_STR_DOT_SIZE);
	}

	if (fd != -1)
		(void) close(fd);

	/*
	 * If an error occurred, or no input files contributed data, bail now.
	 */
	if (ret || (odp->od_outsecs == NULL))
		return (1);

	/*
	 * Create section descriptors for .symtab, .strtab, and .shstrtab.
	 */
	for (cnt = 0, stdsecs = &StdSecs[cnt]; stdsecs->ss_name; cnt++,
	    ndx++, stdsecs = &StdSecs[cnt]) {

		/*
		 * Identify the section.
		 */
		outsec.os_name = stdsecs->ss_name;
		outsec.os_type = stdsecs->ss_type;
		outsec.os_flags = stdsecs->ss_flags;
		outsec.os_ndx = ndx;
		outsec.os_size = 0;
		outsec.os_addr = 0;

		if (alist_append(&(odp->od_outsecs), &outsec, sizeof (OutSec_t),
		    AL_CNT_WOSECS) == 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_ALLOC),
			    prog, outsec.os_name, strerror(err));
			return (1);
		}

		/*
		 * Each standard section contributes:
		 *
		 * i.	its section name to the .shstrtab.
		 * ii.	a section symbol.
		 */
		odp->od_symtabno++;
		odp->od_shstrtabsz += (strlen(outsec.os_name) + 1);
	}

	/*
	 * The symbol table requires an initial NULL entry and a following
	 * FILE entry.  Both string tables require an initial NULL byte.
	 * The .strtab requires room for the output file name (STT_FILE).
	 */
	odp->od_symtabno += 2;
	odp->od_strtabsz += strlen(ofile) + 2;
	odp->od_shstrtabsz++;

	return (0);
}

/*
 * Having captured all input data, create the output file.
 */
int
output(const char *prog, int fd, const char *ofile, ushort_t mach,
    ObjDesc_t *odp)
{
	Aliste		off;
	Elf		*melf, *oelf;
	Ehdr		*ehdr;
	Sym		*symtab, *secsymtabent, *glbsymtabent;
	char		*strtab, *strtabent, *shstrtab, *shstrtabent;
	OutSec_t	*outsec, *outsymtab, *outstrtab, *outshstrtab;
	size_t		len;
	TargDesc_t	tdesc;

	/*
	 * Obtain any target specific ELF information.
	 */
	if (mach == 0)
		mach = M_MACH;

	switch (mach) {
#if	!defined(lint)
		case EM_SPARC:
			target_init_sparc(&tdesc);
			break;
		case EM_SPARCV9:
			target_init_sparcv9(&tdesc);
			break;
		case EM_386:
			target_init_i386(&tdesc);
			break;
		case EM_AMD64:
			target_init_amd64(&tdesc);
			break;
#else
		default:
			target_init(&tdesc);
			break;
#endif
	}
	/*
	 * Create a new ELF descriptor for the new output file.
	 */
	if ((oelf = elf_begin(fd, ELF_C_WRITE, 0)) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_BEGIN), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}

	/*
	 * Create and initialize the new ELF header.
	 */
	if ((ehdr = elf_newehdr(oelf)) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_NEWEHDR), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}

	/*
	 * Note, the ELF header is initialized to reflect the host running
	 * elfwrap(1) rather than the target.  Using host byte order allows
	 * elfwrap(1) to create the object data.  Prior to the final update,
	 * the output ELF header is modified to reflect the target, causing
	 * libelf to produce the output object using the correct byte order
	 * and other target information.
	 */
	ehdr->e_ident[EI_DATA] = M_DATA;
	ehdr->e_type = ET_REL;
	ehdr->e_version = EV_CURRENT;

	/*
	 * Create the required number of new sections, their associated section
	 * header, and an initial data buffer.
	 */
	for (ALIST_TRAVERSE(odp->od_outsecs, off, outsec)) {
		Elf_Scn		*scn;
		Elf_Data	*data;
		Shdr		*shdr;

		if ((scn = elf_newscn(oelf)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_NEWSCN),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}
		if ((shdr = elf_getshdr(scn)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETSHDR),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}

		/*
		 * Assign the section type and flags.
		 */
		shdr->sh_type = outsec->os_type;
		shdr->sh_flags = outsec->os_flags;

		if ((data = elf_newdata(scn)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_NEWDATA),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}

		switch (shdr->sh_type) {
		case SHT_PROGBITS:
			/*
			 * If this is a PROGBITS section, then the data
			 * originates from an input file.  Assign the data
			 * buffer to this input file and provide a default
			 * alignment.
			 */
			data->d_buf = outsec->os_addr;
			data->d_type = ELF_T_BYTE;
			data->d_size = outsec->os_size;
			data->d_align = tdesc.td_align;
			break;

		case SHT_SYMTAB:
			/*
			 * If this is the symbol table, use the symbol count to
			 * reserve sufficient space for the symbols we need.
			 */
			data->d_buf = 0;
			data->d_type = ELF_T_SYM;
			data->d_size = (odp->od_symtabno * tdesc.td_symsz);
			data->d_align = tdesc.td_align;
			break;

		case SHT_STRTAB:
			/*
			 * If this is a string table, use the table size to
			 * reserve sufficient space for the strings we need.
			 */
			data->d_buf = 0;
			data->d_type = ELF_T_BYTE;
			if (strcmp(outsec->os_name, MSG_ORIG(MSG_SCN_STRTAB)))
				data->d_size = odp->od_shstrtabsz;
			else
				data->d_size = odp->od_strtabsz;
			data->d_align = 1;
			break;
		}
	}

	/*
	 * Write the ELF data into a memory image.
	 */
	if ((elf_update(oelf, ELF_C_WRIMAGE)) == -1) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_UPDATE), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}

	/*
	 * Assign an ELF descriptor to the memory image.
	 */
	if ((melf = elf_begin(0, ELF_C_IMAGE, oelf)) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_BEGIN), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}

	/*
	 * Get the ELF header from the memory image.
	 */
	if ((ehdr = elf_getehdr(melf)) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETEHDR), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}

	/*
	 * Read the section header and data from the new sections of the
	 * memory image.
	 */
	for (ALIST_TRAVERSE(odp->od_outsecs, off, outsec)) {
		Elf_Scn		*scn;
		Shdr		*shdr;

		if ((scn = elf_getscn(melf, outsec->os_ndx)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETSCN),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}
		if ((outsec->os_shdr = shdr = elf_getshdr(scn)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETSHDR),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}
		if ((outsec->os_data = elf_getdata(scn, NULL)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA),
			    prog, outsec->os_name, elf_errmsg(elf_errno()));
			return (1);
		}

		if (shdr->sh_type == SHT_PROGBITS)
			continue;

		/*
		 * Remember the symbol table and string tables, so that they
		 * can be filled in later.
		 */
		if (shdr->sh_type == SHT_SYMTAB) {
			outsymtab = outsec;
			symtab = (Sym *)outsec->os_data->d_buf;
		} else if (shdr->sh_type == SHT_STRTAB) {
			if (strcmp(outsec->os_name, MSG_ORIG(MSG_SCN_STRTAB))) {
				outshstrtab = outsec;
				shstrtab = (char *)outsec->os_data->d_buf;
			} else {
				outstrtab = outsec;
				strtab = (char *)outsec->os_data->d_buf;
			}
		}
	}

	/*
	 * Update the ELF header with the .shstrtab index.
	 */
	ehdr->e_shstrndx = outshstrtab->os_ndx;

	/*
	 * Set up the string table entries, and skip the first byte.
	 */
	strtabent = strtab;
	strtabent++;

	shstrtabent = shstrtab;
	shstrtabent++;

	/*
	 * Skip the first symbol table entry.  Write a FILE entry, and set
	 * up for adding sections and data symbols.  Associate the symbol
	 * table with the string table.
	 */
	secsymtabent = symtab;
	secsymtabent++;
	secsymtabent->st_name = (strtabent - strtab);
	secsymtabent->st_info = ELF_ST_INFO(STB_LOCAL, STT_NOTYPE);
	secsymtabent->st_shndx = SHN_ABS;
	secsymtabent++;

	glbsymtabent = secsymtabent;
	glbsymtabent += alist_nitems(odp->od_outsecs);

	outsymtab->os_shdr->sh_link = outstrtab->os_ndx;

	/*
	 * Write the output file name to the .strtab.
	 */
	len = strlen(ofile) + 1;
	(void) memcpy(strtabent, ofile, len);
	strtabent += len;

	/*
	 * Rescan all the new sections, adding symbols and strings as required.
	 */
	for (ALIST_TRAVERSE(odp->od_outsecs, off, outsec)) {
		size_t	alen;

		/*
		 * Create a section symbol.
		 */
		secsymtabent->st_info = ELF_ST_INFO(STB_LOCAL, STT_SECTION);
		secsymtabent->st_shndx = outsec->os_ndx;
		secsymtabent++;

		/*
		 * Store the section name, (with an appended "." if the section
		 * name is derived from the input file name), and point the
		 * section header to this name.
		 */
		outsec->os_shdr->sh_name = (shstrtabent - shstrtab);

		if (outsec->os_shdr->sh_type == SHT_PROGBITS) {
			(void) memcpy(shstrtabent, MSG_ORIG(MSG_STR_DOT),
			    MSG_STR_DOT_SIZE);
			shstrtabent += MSG_STR_DOT_SIZE;
		}

		len = strlen(outsec->os_name) + 1;
		(void) memcpy(shstrtabent, outsec->os_name, len);
		shstrtabent += len;

		if (outsec->os_shdr->sh_type != SHT_PROGBITS)
			continue;

		/*
		 * Add a symbol pointing to this PROGBITS section.  The value
		 * is the base offset of this section, which can only be 0.
		 * The size of the symbol can be taken straight from the section
		 * header information (that libelf generated).
		 */
		glbsymtabent->st_name = (strtabent - strtab);
		glbsymtabent->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
		glbsymtabent->st_shndx = outsec->os_ndx;
		glbsymtabent->st_size = outsec->os_shdr->sh_size;
		glbsymtabent++;

		/*
		 * Store this symbol name (with an appended "_data") in the
		 * string table.
		 */
		len--;
		(void) memcpy(strtabent, outsec->os_name, len);
		strtabent += len;
		alen = (MSG_STR_START_SIZE + 1);
		(void) memcpy(strtabent, MSG_ORIG(MSG_STR_START), alen);
		strtabent += alen;

		/*
		 * Add a symbol indicating the size of this PROGBITS section.
		 */
		glbsymtabent->st_name = (strtabent - strtab);
		glbsymtabent->st_info = ELF_ST_INFO(STB_GLOBAL, STT_OBJECT);
		glbsymtabent->st_shndx = outsec->os_ndx;
		glbsymtabent->st_value = outsec->os_shdr->sh_size;
		glbsymtabent++;

		/*
		 * Store this symbol name (with an appended "_end") in the
		 * string table.
		 */
		(void) memcpy(strtabent, outsec->os_name, len);
		strtabent += len;
		alen = (MSG_STR_END_SIZE + 1);
		(void) memcpy(strtabent, MSG_ORIG(MSG_STR_END), alen);
		strtabent += alen;
	}

	/*
	 * Update the .symtab section header with the index of the first
	 * non-local symbol.  The only locals written are the section symbols.
	 */
	outsymtab->os_shdr->sh_info = (secsymtabent - symtab);

	/*
	 * Having updated the image following the byte order of elfwrap(), seed
	 * the ELF header with the appropriate target information.
	 */
	ehdr->e_ident[EI_CLASS] = tdesc.td_class;
	ehdr->e_ident[EI_DATA] = tdesc.td_data;
	ehdr->e_machine = tdesc.td_mach;

	/*
	 * If the output relocatable object is targeted to a machine with a
	 * different byte order than the host running elfwrap(1), swap the data
	 * to the target byte order.
	 */
	if ((_elf_sys_encoding() != ehdr->e_ident[EI_DATA]) &&
	    (_elf_swap_wrimage(melf) != 0)) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_SWAP_WRIMAGE), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}
	(void) elf_end(melf);

	/*
	 * Finally, write the updated memory image out to disc.
	 */
	if ((elf_update(oelf, ELF_C_WRITE)) == -1) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_UPDATE), prog,
		    elf_errmsg(elf_errno()));
		return (1);
	}
	(void) elf_end(oelf);

	return (0);
}
