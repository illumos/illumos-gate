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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	ELF_TARGET_ALL
#include <elf.h>

#include <sys/types.h>
#include <sys/sysmacros.h>

#include <unistd.h>
#include <strings.h>
#include <alloca.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <wait.h>
#include <assert.h>

#include <dt_impl.h>
#include <dt_provider.h>
#include <dt_string.h>

#define	ESHDR_NULL	0
#define	ESHDR_SHSTRTAB	1
#define	ESHDR_DOF	2
#define	ESHDR_STRTAB	3
#define	ESHDR_SYMTAB	4
#define	ESHDR_REL	5
#define	ESHDR_NUM	6

#define	PWRITE_SCN(index, data) \
	(lseek64(fd, (off64_t)elf_file.shdr[(index)].sh_offset, SEEK_SET) != \
	(off64_t)elf_file.shdr[(index)].sh_offset || \
	dt_write(dtp, fd, (data), elf_file.shdr[(index)].sh_size) != \
	elf_file.shdr[(index)].sh_size)

static const char DTRACE_SHSTRTAB32[] = "\0"
".shstrtab\0"		/* 1 */
".SUNW_dof\0"		/* 11 */
".strtab\0"		/* 21 */
".symtab\0"		/* 29 */
#ifdef __sparc
".rela.SUNW_dof";	/* 37 */
#else
".rel.SUNW_dof";	/* 37 */
#endif

static const char DTRACE_SHSTRTAB64[] = "\0"
".shstrtab\0"		/* 1 */
".SUNW_dof\0"		/* 11 */
".strtab\0"		/* 21 */
".symtab\0"		/* 29 */
".rela.SUNW_dof";	/* 37 */

static const char DOFSTR[] = "__SUNW_dof";
static const char DOFLAZYSTR[] = "___SUNW_dof";

typedef struct dof_elf32 {
	uint32_t de_nrel;	/* relocation count */
#ifdef __sparc
	Elf32_Rela *de_rel;	/* array of relocations for sparc */
#else
	Elf32_Rel *de_rel;	/* array of relocations for x86 */
#endif
	uint32_t de_nsym;	/* symbol count */
	Elf32_Sym *de_sym;	/* array of symbols */
	uint32_t de_strlen;	/* size of of string table */
	char *de_strtab;	/* string table */
	uint32_t de_global;	/* index of the first global symbol */
} dof_elf32_t;

static int
prepare_elf32(dtrace_hdl_t *dtp, const dof_hdr_t *dof, dof_elf32_t *dep)
{
	dof_sec_t *dofs, *s;
	dof_relohdr_t *dofrh;
	dof_relodesc_t *dofr;
	char *strtab;
	int i, j, nrel;
	size_t strtabsz = 1;
	uint32_t count = 0;
	size_t base;
	Elf32_Sym *sym;
#ifdef __sparc
	Elf32_Rela *rel;
#else
	Elf32_Rel *rel;
#endif

	/*LINTED*/
	dofs = (dof_sec_t *)((char *)dof + dof->dofh_secoff);

	/*
	 * First compute the size of the string table and the number of
	 * relocations present in the DOF.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		assert(strtab[0] == '\0');
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		count += s->dofs_size / s->dofs_entsize;
	}

	dep->de_strlen = strtabsz;
	dep->de_nrel = count;
	dep->de_nsym = count + 1; /* the first symbol is always null */

	if (dtp->dt_lazyload) {
		dep->de_strlen += sizeof (DOFLAZYSTR);
		dep->de_nsym++;
	} else {
		dep->de_strlen += sizeof (DOFSTR);
		dep->de_nsym++;
	}

	if ((dep->de_rel = calloc(dep->de_nrel,
	    sizeof (dep->de_rel[0]))) == NULL) {
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_sym = calloc(dep->de_nsym, sizeof (Elf32_Sym))) == NULL) {
		free(dep->de_rel);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_strtab = calloc(dep->de_strlen, 1)) == NULL) {
		free(dep->de_rel);
		free(dep->de_sym);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	count = 0;
	strtabsz = 1;
	dep->de_strtab[0] = '\0';
	rel = dep->de_rel;
	sym = dep->de_sym;
	dep->de_global = 1;

	/*
	 * The first symbol table entry must be zeroed and is always ignored.
	 */
	bzero(sym, sizeof (Elf32_Sym));
	sym++;

	/*
	 * Take a second pass through the DOF sections filling in the
	 * memory we allocated.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		bcopy(strtab + 1, dep->de_strtab + strtabsz, s->dofs_size);
		base = strtabsz;
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		nrel = s->dofs_size / s->dofs_entsize;

		s = &dofs[dofrh->dofr_tgtsec];

		for (j = 0; j < nrel; j++) {
#if defined(__i386) || defined(__amd64)
			rel->r_offset = s->dofs_offset +
			    dofr[j].dofr_offset;
			rel->r_info = ELF32_R_INFO(count + dep->de_global,
			    R_386_32);
#elif defined(__sparc)
			/*
			 * Add 4 bytes to hit the low half of this 64-bit
			 * big-endian address.
			 */
			rel->r_offset = s->dofs_offset +
			    dofr[j].dofr_offset + 4;
			rel->r_info = ELF32_R_INFO(count + dep->de_global,
			    R_SPARC_32);
#else
#error unknown ISA
#endif

			sym->st_name = base + dofr[j].dofr_name - 1;
			sym->st_value = 0;
			sym->st_size = 0;
			sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
			sym->st_other = 0;
			sym->st_shndx = SHN_UNDEF;

			rel++;
			sym++;
			count++;
		}
	}

	/*
	 * Add a symbol for the DOF itself. We use a different symbol for
	 * lazily and actively loaded DOF to make them easy to distinguish.
	 */
	sym->st_name = strtabsz;
	sym->st_value = 0;
	sym->st_size = dof->dofh_filesz;
	sym->st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->st_other = 0;
	sym->st_shndx = ESHDR_DOF;
	sym++;

	if (dtp->dt_lazyload) {
		bcopy(DOFLAZYSTR, dep->de_strtab + strtabsz,
		    sizeof (DOFLAZYSTR));
		strtabsz += sizeof (DOFLAZYSTR);
	} else {
		bcopy(DOFSTR, dep->de_strtab + strtabsz, sizeof (DOFSTR));
		strtabsz += sizeof (DOFSTR);
	}

	assert(count == dep->de_nrel);
	assert(strtabsz == dep->de_strlen);

	return (0);
}


typedef struct dof_elf64 {
	uint32_t de_nrel;
	Elf64_Rela *de_rel;
	uint32_t de_nsym;
	Elf64_Sym *de_sym;

	uint32_t de_strlen;
	char *de_strtab;

	uint32_t de_global;
} dof_elf64_t;

static int
prepare_elf64(dtrace_hdl_t *dtp, const dof_hdr_t *dof, dof_elf64_t *dep)
{
	dof_sec_t *dofs, *s;
	dof_relohdr_t *dofrh;
	dof_relodesc_t *dofr;
	char *strtab;
	int i, j, nrel;
	size_t strtabsz = 1;
	uint32_t count = 0;
	size_t base;
	Elf64_Sym *sym;
	Elf64_Rela *rel;

	/*LINTED*/
	dofs = (dof_sec_t *)((char *)dof + dof->dofh_secoff);

	/*
	 * First compute the size of the string table and the number of
	 * relocations present in the DOF.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		assert(strtab[0] == '\0');
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		count += s->dofs_size / s->dofs_entsize;
	}

	dep->de_strlen = strtabsz;
	dep->de_nrel = count;
	dep->de_nsym = count + 1; /* the first symbol is always null */

	if (dtp->dt_lazyload) {
		dep->de_strlen += sizeof (DOFLAZYSTR);
		dep->de_nsym++;
	} else {
		dep->de_strlen += sizeof (DOFSTR);
		dep->de_nsym++;
	}

	if ((dep->de_rel = calloc(dep->de_nrel,
	    sizeof (dep->de_rel[0]))) == NULL) {
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_sym = calloc(dep->de_nsym, sizeof (Elf64_Sym))) == NULL) {
		free(dep->de_rel);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	if ((dep->de_strtab = calloc(dep->de_strlen, 1)) == NULL) {
		free(dep->de_rel);
		free(dep->de_sym);
		return (dt_set_errno(dtp, EDT_NOMEM));
	}

	count = 0;
	strtabsz = 1;
	dep->de_strtab[0] = '\0';
	rel = dep->de_rel;
	sym = dep->de_sym;
	dep->de_global = 1;

	/*
	 * The first symbol table entry must be zeroed and is always ignored.
	 */
	bzero(sym, sizeof (Elf64_Sym));
	sym++;

	/*
	 * Take a second pass through the DOF sections filling in the
	 * memory we allocated.
	 */
	for (i = 0; i < dof->dofh_secnum; i++) {
		if (dofs[i].dofs_type != DOF_SECT_URELHDR)
			continue;

		/*LINTED*/
		dofrh = (dof_relohdr_t *)((char *)dof + dofs[i].dofs_offset);

		s = &dofs[dofrh->dofr_strtab];
		strtab = (char *)dof + s->dofs_offset;
		bcopy(strtab + 1, dep->de_strtab + strtabsz, s->dofs_size);
		base = strtabsz;
		strtabsz += s->dofs_size - 1;

		s = &dofs[dofrh->dofr_relsec];
		/*LINTED*/
		dofr = (dof_relodesc_t *)((char *)dof + s->dofs_offset);
		nrel = s->dofs_size / s->dofs_entsize;

		s = &dofs[dofrh->dofr_tgtsec];

		for (j = 0; j < nrel; j++) {
#if defined(__i386) || defined(__amd64)
			rel->r_offset = s->dofs_offset +
			    dofr[j].dofr_offset;
			rel->r_info = ELF64_R_INFO(count + dep->de_global,
			    R_AMD64_64);
#elif defined(__sparc)
			rel->r_offset = s->dofs_offset +
			    dofr[j].dofr_offset;
			rel->r_info = ELF64_R_INFO(count + dep->de_global,
			    R_SPARC_64);
#else
#error unknown ISA
#endif

			sym->st_name = base + dofr[j].dofr_name - 1;
			sym->st_value = 0;
			sym->st_size = 0;
			sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE);
			sym->st_other = 0;
			sym->st_shndx = SHN_UNDEF;

			rel++;
			sym++;
			count++;
		}
	}

	/*
	 * Add a symbol for the DOF itself. We use a different symbol for
	 * lazily and actively loaded DOF to make them easy to distinguish.
	 */
	sym->st_name = strtabsz;
	sym->st_value = 0;
	sym->st_size = dof->dofh_filesz;
	sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
	sym->st_other = 0;
	sym->st_shndx = ESHDR_DOF;
	sym++;

	if (dtp->dt_lazyload) {
		bcopy(DOFLAZYSTR, dep->de_strtab + strtabsz,
		    sizeof (DOFLAZYSTR));
		strtabsz += sizeof (DOFLAZYSTR);
	} else {
		bcopy(DOFSTR, dep->de_strtab + strtabsz, sizeof (DOFSTR));
		strtabsz += sizeof (DOFSTR);
	}

	assert(count == dep->de_nrel);
	assert(strtabsz == dep->de_strlen);

	return (0);
}

/*
 * Write out an ELF32 file prologue consisting of a header, section headers,
 * and a section header string table.  The DOF data will follow this prologue
 * and complete the contents of the given ELF file.
 */
static int
dump_elf32(dtrace_hdl_t *dtp, const dof_hdr_t *dof, int fd)
{
	struct {
		Elf32_Ehdr ehdr;
		Elf32_Shdr shdr[ESHDR_NUM];
	} elf_file;

	Elf32_Shdr *shp;
	Elf32_Off off;
	dof_elf32_t de;
	int ret = 0;
	uint_t nshdr;

	if (prepare_elf32(dtp, dof, &de) != 0)
		return (-1); /* errno is set for us */

	/*
	 * If there are no relocations, we only need enough sections for
	 * the shstrtab and the DOF.
	 */
	nshdr = de.de_nrel == 0 ? ESHDR_SYMTAB + 1 : ESHDR_NUM;

	bzero(&elf_file, sizeof (elf_file));

	elf_file.ehdr.e_ident[EI_MAG0] = ELFMAG0;
	elf_file.ehdr.e_ident[EI_MAG1] = ELFMAG1;
	elf_file.ehdr.e_ident[EI_MAG2] = ELFMAG2;
	elf_file.ehdr.e_ident[EI_MAG3] = ELFMAG3;
	elf_file.ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	elf_file.ehdr.e_ident[EI_CLASS] = ELFCLASS32;
#if defined(_BIG_ENDIAN)
	elf_file.ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#elif defined(_LITTLE_ENDIAN)
	elf_file.ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#endif
	elf_file.ehdr.e_type = ET_REL;
#if defined(__sparc)
	elf_file.ehdr.e_machine = EM_SPARC;
#elif defined(__i386) || defined(__amd64)
	elf_file.ehdr.e_machine = EM_386;
#endif
	elf_file.ehdr.e_version = EV_CURRENT;
	elf_file.ehdr.e_shoff = sizeof (Elf32_Ehdr);
	elf_file.ehdr.e_ehsize = sizeof (Elf32_Ehdr);
	elf_file.ehdr.e_phentsize = sizeof (Elf32_Phdr);
	elf_file.ehdr.e_shentsize = sizeof (Elf32_Shdr);
	elf_file.ehdr.e_shnum = nshdr;
	elf_file.ehdr.e_shstrndx = ESHDR_SHSTRTAB;
	off = sizeof (elf_file) + nshdr * sizeof (Elf32_Shdr);

	shp = &elf_file.shdr[ESHDR_SHSTRTAB];
	shp->sh_name = 1; /* DTRACE_SHSTRTAB32[1] = ".shstrtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = off;
	shp->sh_size = sizeof (DTRACE_SHSTRTAB32);
	shp->sh_addralign = sizeof (char);
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 8);

	shp = &elf_file.shdr[ESHDR_DOF];
	shp->sh_name = 11; /* DTRACE_SHSTRTAB32[11] = ".SUNW_dof" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_SUNW_dof;
	shp->sh_offset = off;
	shp->sh_size = dof->dofh_filesz;
	shp->sh_addralign = 8;
	off = shp->sh_offset + shp->sh_size;

	shp = &elf_file.shdr[ESHDR_STRTAB];
	shp->sh_name = 21; /* DTRACE_SHSTRTAB32[21] = ".strtab" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = off;
	shp->sh_size = de.de_strlen;
	shp->sh_addralign = sizeof (char);
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 4);

	shp = &elf_file.shdr[ESHDR_SYMTAB];
	shp->sh_name = 29; /* DTRACE_SHSTRTAB32[29] = ".symtab" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_SYMTAB;
	shp->sh_entsize = sizeof (Elf32_Sym);
	shp->sh_link = ESHDR_STRTAB;
	shp->sh_offset = off;
	shp->sh_info = de.de_global;
	shp->sh_size = de.de_nsym * sizeof (Elf32_Sym);
	shp->sh_addralign = 4;
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 4);

	if (de.de_nrel == 0) {
		if (dt_write(dtp, fd, &elf_file,
		    sizeof (elf_file)) != sizeof (elf_file) ||
		    PWRITE_SCN(ESHDR_SHSTRTAB, DTRACE_SHSTRTAB32) ||
		    PWRITE_SCN(ESHDR_STRTAB, de.de_strtab) ||
		    PWRITE_SCN(ESHDR_SYMTAB, de.de_sym) ||
		    PWRITE_SCN(ESHDR_DOF, dof)) {
			ret = dt_set_errno(dtp, errno);
		}
	} else {
		shp = &elf_file.shdr[ESHDR_REL];
		shp->sh_name = 37; /* DTRACE_SHSTRTAB32[37] = ".rel.SUNW_dof" */
		shp->sh_flags = SHF_ALLOC;
#ifdef __sparc
		shp->sh_type = SHT_RELA;
#else
		shp->sh_type = SHT_REL;
#endif
		shp->sh_entsize = sizeof (de.de_rel[0]);
		shp->sh_link = ESHDR_SYMTAB;
		shp->sh_info = ESHDR_DOF;
		shp->sh_offset = off;
		shp->sh_size = de.de_nrel * sizeof (de.de_rel[0]);
		shp->sh_addralign = 4;

		if (dt_write(dtp, fd, &elf_file,
		    sizeof (elf_file)) != sizeof (elf_file) ||
		    PWRITE_SCN(ESHDR_SHSTRTAB, DTRACE_SHSTRTAB32) ||
		    PWRITE_SCN(ESHDR_STRTAB, de.de_strtab) ||
		    PWRITE_SCN(ESHDR_SYMTAB, de.de_sym) ||
		    PWRITE_SCN(ESHDR_REL, de.de_rel) ||
		    PWRITE_SCN(ESHDR_DOF, dof)) {
			ret = dt_set_errno(dtp, errno);
		}
	}

	free(de.de_strtab);
	free(de.de_sym);
	free(de.de_rel);

	return (ret);
}

/*
 * Write out an ELF64 file prologue consisting of a header, section headers,
 * and a section header string table.  The DOF data will follow this prologue
 * and complete the contents of the given ELF file.
 */
static int
dump_elf64(dtrace_hdl_t *dtp, const dof_hdr_t *dof, int fd)
{
	struct {
		Elf64_Ehdr ehdr;
		Elf64_Shdr shdr[ESHDR_NUM];
	} elf_file;

	Elf64_Shdr *shp;
	Elf64_Off off;
	dof_elf64_t de;
	int ret = 0;
	uint_t nshdr;

	if (prepare_elf64(dtp, dof, &de) != 0)
		return (-1); /* errno is set for us */

	/*
	 * If there are no relocations, we only need enough sections for
	 * the shstrtab and the DOF.
	 */
	nshdr = de.de_nrel == 0 ? ESHDR_SYMTAB + 1 : ESHDR_NUM;

	bzero(&elf_file, sizeof (elf_file));

	elf_file.ehdr.e_ident[EI_MAG0] = ELFMAG0;
	elf_file.ehdr.e_ident[EI_MAG1] = ELFMAG1;
	elf_file.ehdr.e_ident[EI_MAG2] = ELFMAG2;
	elf_file.ehdr.e_ident[EI_MAG3] = ELFMAG3;
	elf_file.ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	elf_file.ehdr.e_ident[EI_CLASS] = ELFCLASS64;
#if defined(_BIG_ENDIAN)
	elf_file.ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#elif defined(_LITTLE_ENDIAN)
	elf_file.ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#endif
	elf_file.ehdr.e_type = ET_REL;
#if defined(__sparc)
	elf_file.ehdr.e_machine = EM_SPARCV9;
#elif defined(__i386) || defined(__amd64)
	elf_file.ehdr.e_machine = EM_AMD64;
#endif
	elf_file.ehdr.e_version = EV_CURRENT;
	elf_file.ehdr.e_shoff = sizeof (Elf64_Ehdr);
	elf_file.ehdr.e_ehsize = sizeof (Elf64_Ehdr);
	elf_file.ehdr.e_phentsize = sizeof (Elf64_Phdr);
	elf_file.ehdr.e_shentsize = sizeof (Elf64_Shdr);
	elf_file.ehdr.e_shnum = nshdr;
	elf_file.ehdr.e_shstrndx = ESHDR_SHSTRTAB;
	off = sizeof (elf_file) + nshdr * sizeof (Elf64_Shdr);

	shp = &elf_file.shdr[ESHDR_SHSTRTAB];
	shp->sh_name = 1; /* DTRACE_SHSTRTAB64[1] = ".shstrtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = off;
	shp->sh_size = sizeof (DTRACE_SHSTRTAB64);
	shp->sh_addralign = sizeof (char);
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 8);

	shp = &elf_file.shdr[ESHDR_DOF];
	shp->sh_name = 11; /* DTRACE_SHSTRTAB64[11] = ".SUNW_dof" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_SUNW_dof;
	shp->sh_offset = off;
	shp->sh_size = dof->dofh_filesz;
	shp->sh_addralign = 8;
	off = shp->sh_offset + shp->sh_size;

	shp = &elf_file.shdr[ESHDR_STRTAB];
	shp->sh_name = 21; /* DTRACE_SHSTRTAB64[21] = ".strtab" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = off;
	shp->sh_size = de.de_strlen;
	shp->sh_addralign = sizeof (char);
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 8);

	shp = &elf_file.shdr[ESHDR_SYMTAB];
	shp->sh_name = 29; /* DTRACE_SHSTRTAB64[29] = ".symtab" */
	shp->sh_flags = SHF_ALLOC;
	shp->sh_type = SHT_SYMTAB;
	shp->sh_entsize = sizeof (Elf64_Sym);
	shp->sh_link = ESHDR_STRTAB;
	shp->sh_offset = off;
	shp->sh_info = de.de_global;
	shp->sh_size = de.de_nsym * sizeof (Elf64_Sym);
	shp->sh_addralign = 8;
	off = P2ROUNDUP(shp->sh_offset + shp->sh_size, 8);

	if (de.de_nrel == 0) {
		if (dt_write(dtp, fd, &elf_file,
		    sizeof (elf_file)) != sizeof (elf_file) ||
		    PWRITE_SCN(ESHDR_SHSTRTAB, DTRACE_SHSTRTAB64) ||
		    PWRITE_SCN(ESHDR_STRTAB, de.de_strtab) ||
		    PWRITE_SCN(ESHDR_SYMTAB, de.de_sym) ||
		    PWRITE_SCN(ESHDR_DOF, dof)) {
			ret = dt_set_errno(dtp, errno);
		}
	} else {
		shp = &elf_file.shdr[ESHDR_REL];
		shp->sh_name = 37; /* DTRACE_SHSTRTAB64[37] = ".rel.SUNW_dof" */
		shp->sh_flags = SHF_ALLOC;
		shp->sh_type = SHT_RELA;
		shp->sh_entsize = sizeof (de.de_rel[0]);
		shp->sh_link = ESHDR_SYMTAB;
		shp->sh_info = ESHDR_DOF;
		shp->sh_offset = off;
		shp->sh_size = de.de_nrel * sizeof (de.de_rel[0]);
		shp->sh_addralign = 8;

		if (dt_write(dtp, fd, &elf_file,
		    sizeof (elf_file)) != sizeof (elf_file) ||
		    PWRITE_SCN(ESHDR_SHSTRTAB, DTRACE_SHSTRTAB64) ||
		    PWRITE_SCN(ESHDR_STRTAB, de.de_strtab) ||
		    PWRITE_SCN(ESHDR_SYMTAB, de.de_sym) ||
		    PWRITE_SCN(ESHDR_REL, de.de_rel) ||
		    PWRITE_SCN(ESHDR_DOF, dof)) {
			ret = dt_set_errno(dtp, errno);
		}
	}

	free(de.de_strtab);
	free(de.de_sym);
	free(de.de_rel);

	return (ret);
}

static int
dt_symtab_lookup(Elf_Data *data_sym, uintptr_t addr, uint_t shn, GElf_Sym *sym)
{
	int i, ret = -1;
	GElf_Sym s;

	for (i = 0; gelf_getsym(data_sym, i, sym) != NULL; i++) {
		if (GELF_ST_TYPE(sym->st_info) == STT_FUNC &&
		    shn == sym->st_shndx &&
		    sym->st_value <= addr &&
		    addr < sym->st_value + sym->st_size) {
			if (GELF_ST_BIND(sym->st_info) == STB_GLOBAL)
				return (0);

			ret = 0;
			s = *sym;
		}
	}

	if (ret == 0)
		*sym = s;
	return (ret);
}

#if defined(__sparc)

#define	DT_OP_RET		0x81c7e008
#define	DT_OP_NOP		0x01000000
#define	DT_OP_CALL		0x40000000

#define	DT_IS_MOV_O7(inst)	(((inst) & 0xffffe000) == 0x9e100000)
#define	DT_IS_RESTORE(inst)	(((inst) & 0xc1f80000) == 0x81e80000)
#define	DT_IS_RETL(inst)	(((inst) & 0xfff83fff) == 0x81c02008)

#define	DT_RS2(inst)		((inst) & 0x1f)
#define	DT_MAKE_RETL(reg)	(0x81c02008 | ((reg) << 14))

static int
dt_modtext(char *p, GElf_Rela *rela, uint32_t *off)
{
	uint32_t *ip;

	if ((rela->r_offset & (sizeof (uint32_t) - 1)) != 0)
		return (-1);

	/*LINTED*/
	ip = (uint32_t *)(p + rela->r_offset);

	/*
	 * We only know about some specific relocation types.
	 */
	if (GELF_R_TYPE(rela->r_info) != R_SPARC_WDISP30 &&
	    GELF_R_TYPE(rela->r_info) != R_SPARC_WPLT30)
		return (-1);

	/*
	 * We may have already processed this object file in an earlier
	 * linker invocation in which case we'd expect to see a ret/restore
	 * pair, a retl-like/mov pair or a nop; return success in that case.
	 */
	if (DT_IS_RESTORE(ip[1])) {
		if (ip[0] == DT_OP_RET) {
			return (0);
		}
	} else if (DT_IS_MOV_O7(ip[1])) {
		if (DT_IS_RETL(ip[0])) {
			return (0);
		}
	} else {
		if (ip[0] == DT_OP_NOP) {
			(*off) += sizeof (ip[0]);
			return (0);
		}
	}

	/*
	 * We only expect call instructions with a displacement of 0.
	 */
	if (ip[0] != DT_OP_CALL) {
		dt_dprintf("found %x instead of a call instruction at %llx\n",
		    ip[0], (u_longlong_t)rela->r_offset);
		return (-1);
	}

	/*
	 * If the call is followed by a restore, it's a tail call so change
	 * the call to a ret. If the call if followed by a mov of a register
	 * into %o7, it's a tail call in leaf context so change the call to
	 * a retl-like instruction that returns to that register value + 8
	 * (rather than the typical %o7 + 8). Otherwise we adjust the offset
	 * to land on what was once the delay slot of the call so we
	 * correctly get all the arguments.
	 */
	if (DT_IS_RESTORE(ip[1])) {
		ip[0] = DT_OP_RET;
	} else if (DT_IS_MOV_O7(ip[1])) {
		ip[0] = DT_MAKE_RETL(DT_RS2(ip[1]));
	} else {
		ip[0] = DT_OP_NOP;
		(*off) += sizeof (ip[0]);
	}

	return (0);
}

#elif defined(__i386) || defined(__amd64)

#define	DT_OP_NOP		0x90
#define	DT_OP_CALL		0xe8

static int
dt_modtext(char *p, GElf_Rela *rela, uint32_t *off)
{
	uint8_t *ip = (uint8_t *)(p + rela->r_offset - 1);

	/*
	 * On x86, the first byte of the instruction is the call opcode and
	 * the next four bytes are the 32-bit address; the relocation is for
	 * the address so we back up one byte to land on the opcode.
	 */
	(*off) -= 1;

	/*
	 * We only know about some specific relocation types. Luckily
	 * these types have the same values on both 32-bit and 64-bit
	 * x86 architectures.
	 */
	if (GELF_R_TYPE(rela->r_info) != R_386_PC32 &&
	    GELF_R_TYPE(rela->r_info) != R_386_PLT32)
		return (-1);

	/*
	 * We may have already processed this object file in an earlier
	 * linker invocation in which case we'd expect to see a bunch
	 * of nops; return success in that case.
	 */
	if (ip[0] == DT_OP_NOP && ip[1] == DT_OP_NOP && ip[2] == DT_OP_NOP &&
	    ip[3] == DT_OP_NOP && ip[4] == DT_OP_NOP)
		return (0);

	/*
	 * We only expect a call instrution with a 32-bit displacement.
	 */
	if (ip[0] != DT_OP_CALL) {
		dt_dprintf("found %x instead of a call instruction at %llx\n",
		    ip[0], (u_longlong_t)rela->r_offset);
		return (-1);
	}

	ip[0] = DT_OP_NOP;
	ip[1] = DT_OP_NOP;
	ip[2] = DT_OP_NOP;
	ip[3] = DT_OP_NOP;
	ip[4] = DT_OP_NOP;

	return (0);
}

#else
#error unknown ISA
#endif

/*PRINTFLIKE2*/
static int
dt_link_error(dtrace_hdl_t *dtp, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	dt_set_errmsg(dtp, NULL, NULL, NULL, 0, format, ap);
	va_end(ap);

	return (dt_set_errno(dtp, EDT_COMPILER));
}

static int
process_obj(dtrace_hdl_t *dtp, const char *obj)
{
	static const char dt_prefix[] = "__dtrace_";
	int fd, i, ndx, mod = 0;
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Scn *scn_rel, *scn_sym, *scn_tgt;
	Elf_Data *data_rel, *data_sym, *data_tgt;
	GElf_Shdr shdr_rel, shdr_sym, shdr_tgt;
	GElf_Sym rsym, fsym;
	GElf_Rela rela;
	GElf_Rel rel;
	char *s, *p;
	char pname[DTRACE_PROVNAMELEN];
	dt_provider_t *pvp;
	dt_probe_t *prp;
	uint32_t off, eclass, emachine1, emachine2;

	if ((fd = open64(obj, O_RDWR)) == -1) {
		return (dt_link_error(dtp, "failed to open %s: %s", obj,
		    strerror(errno)));
	}

	if (elf_version(EV_CURRENT) == EV_NONE ||
	    (elf = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL) {
		return (dt_link_error(dtp, "failed to process %s: %s", obj,
		    elf_errmsg(elf_errno())));
	}

	switch (elf_kind(elf)) {
	case ELF_K_ELF:
		break;
	case ELF_K_AR:
		return (dt_link_error(dtp, "archive files are not permitted %s;"
		    " use the contents of the archive instead", obj));
	default:
		return (dt_link_error(dtp, "invalid file type for %s", obj));
	}

	if (gelf_getehdr(elf, &ehdr) == NULL)
		return (dt_link_error(dtp, "corrupt object file %s", obj));

	if (dtp->dt_oflags & DTRACE_O_LP64) {
		eclass = ELFCLASS64;
#if defined(__sparc)
		emachine1 = emachine2 = EM_SPARCV9;
#elif defined(__i386) || defined(__amd64)
		emachine1 = emachine2 = EM_AMD64;
#endif
	} else {
		eclass = ELFCLASS32;
#if defined(__sparc)
		emachine1 = EM_SPARC;
		emachine2 = EM_SPARC32PLUS;
#elif defined(__i386) || defined(__amd64)
		emachine1 = emachine2 = EM_386;
#endif
	}

	if (ehdr.e_ident[EI_CLASS] != eclass)
		return (dt_link_error(dtp, "incorrect ELF class for object "
		    "file %s", obj));

	if (ehdr.e_machine != emachine1 && ehdr.e_machine != emachine2)
		return (dt_link_error(dtp, "incorrect ELF machine type for "
		    "object file %s", obj));

	scn_rel = NULL;
	while ((scn_rel = elf_nextscn(elf, scn_rel)) != NULL) {
		if (gelf_getshdr(scn_rel, &shdr_rel) == NULL)
			goto err;

		if (shdr_rel.sh_type != SHT_RELA && shdr_rel.sh_type != SHT_REL)
			continue;

		if ((data_rel = elf_getdata(scn_rel, NULL)) == NULL)
			goto err;

		if ((scn_sym = elf_getscn(elf, shdr_rel.sh_link)) == NULL ||
		    gelf_getshdr(scn_sym, &shdr_sym) == NULL ||
		    (data_sym = elf_getdata(scn_sym, NULL)) == NULL)
			goto err;

		if ((scn_tgt = elf_getscn(elf, shdr_rel.sh_info)) == NULL ||
		    gelf_getshdr(scn_tgt, &shdr_tgt) == NULL ||
		    (data_tgt = elf_getdata(scn_tgt, NULL)) == NULL)
			goto err;

		for (i = 0; i < shdr_rel.sh_size / shdr_rel.sh_entsize; i++) {

			if (shdr_rel.sh_type == SHT_RELA) {
				if (gelf_getrela(data_rel, i, &rela) == NULL)
					continue;
			} else {
				if (gelf_getrel(data_rel, i, &rel) == NULL)
					continue;
				rela.r_offset = rel.r_offset;
				rela.r_info = rel.r_info;
				rela.r_addend = 0;
			}

			ndx = GELF_R_SYM(rela.r_info);

			if (gelf_getsym(data_sym, ndx, &rsym) == NULL ||
			    (s = elf_strptr(elf, shdr_sym.sh_link,
			    rsym.st_name)) == NULL)
				goto err;

			if (strncmp(s, dt_prefix, sizeof (dt_prefix) - 1) != 0)
				continue;

			if (dt_symtab_lookup(data_sym, rela.r_offset,
			    shdr_rel.sh_info, &fsym) != 0)
				goto err;

			s += sizeof (dt_prefix) - 1;
			if ((p = strstr(s, "___")) == NULL ||
			    p - s >= sizeof (pname))
				goto err;

			(void) memcpy(pname, s, p - s);
			pname[p - s] = '\0';

			p = strhyphenate(p + 3); /* strlen("___") */

			if ((s = elf_strptr(elf, shdr_sym.sh_link,
			    fsym.st_name)) == NULL)
				goto err;

			if ((pvp = dt_provider_lookup(dtp, pname)) == NULL) {
				return (dt_link_error(dtp,
				    "no such provider %s", pname));
			}

			if ((prp = dt_probe_lookup(pvp, p)) == NULL) {
				return (dt_link_error(dtp,
				    "no such probe %s", p));
			}

			assert(fsym.st_value <= rela.r_offset);

			off = rela.r_offset - fsym.st_value;
			if (dt_modtext(data_tgt->d_buf, &rela, &off) != 0)
				goto err;

			if (dt_probe_define(pvp, prp, s, off) != 0)
				return (dt_set_errno(dtp, EDT_NOMEM));

			mod = 1;

			/*
			 * This symbol may already have been marked to
			 * be ignored by another relocation referencing
			 * the same symbol or if this object file has
			 * already been processed by an earlier link
			 * invocation.
			 */
			if (rsym.st_shndx != SHN_SUNW_IGNORE) {
				rsym.st_shndx = SHN_SUNW_IGNORE;
				(void) gelf_update_sym(data_sym, ndx, &rsym);
			}
		}
	}

	if (mod && elf_update(elf, ELF_C_WRITE) == -1)
		goto err;

	return (0);

err:
	return (dt_link_error(dtp,
	    "an error was encountered while processing %s", obj));
}

int
dtrace_program_link(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, uint_t dflags,
    const char *file, int objc, char *const objv[])
{
	char drti[PATH_MAX];
	dof_hdr_t *dof;
	int fd, status, i;
	char *cmd, tmp;
	size_t len;
	int ret = 0;

	for (i = 0; i < objc; i++) {
		if (process_obj(dtp, objv[i]) != 0)
			return (-1); /* errno is set for us */
	}

	if ((dof = dtrace_dof_create(dtp, pgp, dflags)) == NULL)
		return (-1); /* errno is set for us */

	/*
	 * Create a temporary file and then unlink it if we're going to
	 * combine it with drti.o later.  We can still refer to it in child
	 * processes as /dev/fd/<fd>.
	 */
	if ((fd = open64(file, O_RDWR | O_CREAT | O_TRUNC, 0666)) == -1) {
		return (dt_link_error(dtp,
		    "failed to open %s: %s", file, strerror(errno)));
	}

	/*
	 * If -xlinktype=DOF has been selected, just write out the DOF.
	 * Otherwise proceed to the default of generating and linking ELF.
	 */
	switch (dtp->dt_linktype) {
	case DT_LTYP_DOF:
		if (dt_write(dtp, fd, dof, dof->dofh_filesz) < dof->dofh_filesz)
			ret = errno;

		if (close(fd) != 0 && ret == 0)
			ret = errno;

		if (ret != 0) {
			return (dt_link_error(dtp,
			    "failed to write %s: %s", file, strerror(ret)));
		}

		return (0);

	case DT_LTYP_ELF:
		break; /* fall through to the rest of dtrace_program_link() */

	default:
		return (dt_link_error(dtp,
		    "invalid link type %u\n", dtp->dt_linktype));
	}


	if (!dtp->dt_lazyload)
		(void) unlink(file);

	if (dtp->dt_oflags & DTRACE_O_LP64)
		status = dump_elf64(dtp, dof, fd);
	else
		status = dump_elf32(dtp, dof, fd);

	if (status != 0 || lseek(fd, 0, SEEK_SET) != 0) {
		return (dt_link_error(dtp,
		    "failed to write %s: %s", file, strerror(errno)));
	}

	if (!dtp->dt_lazyload) {
		if (dtp->dt_oflags & DTRACE_O_LP64) {
			(void) snprintf(drti, sizeof (drti),
			    "%s/64/drti.o", _dtrace_libdir);
		} else {
			(void) snprintf(drti, sizeof (drti),
			    "%s/drti.o", _dtrace_libdir);
		}

		len = snprintf(&tmp, 1, "%s -o %s -r /dev/fd/%d %s",
		    dtp->dt_ld_path, file, fd, drti) + 1;

		cmd = alloca(len);

		(void) snprintf(cmd, len, "%s -o %s -r /dev/fd/%d %s",
		    dtp->dt_ld_path, file, fd, drti);

		if ((status = system(cmd)) == -1) {
			ret = dt_link_error(dtp, "failed to run %s: %s",
			    dtp->dt_ld_path, strerror(errno));
			goto done;
		}

		(void) close(fd); /* release temporary file */

		if (WIFSIGNALED(status)) {
			ret = dt_link_error(dtp,
			    "failed to link %s: %s failed due to signal %d",
			    file, dtp->dt_ld_path, WTERMSIG(status));
			goto done;
		}

		if (WEXITSTATUS(status) != 0) {
			ret = dt_link_error(dtp,
			    "failed to link %s: %s exited with status %d\n",
			    file, dtp->dt_ld_path, WEXITSTATUS(status));
			goto done;
		}
	} else {
		(void) close(fd);
	}

done:
	dtrace_dof_destroy(dtp, dof);
	return (ret);
}
