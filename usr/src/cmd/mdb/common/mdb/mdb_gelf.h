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

#ifndef	_MDB_GELF_H
#define	_MDB_GELF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_nv.h>
#include <mdb/mdb_io.h>

#include <sys/types.h>
#include <gelf.h>
#include <sys/machelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _MDB

#define	GST_FUZZY	0		/* lookup_by_addr matches closest sym */
#define	GST_EXACT	1		/* lookup_by_addr must be exact */

#define	GF_FILE		0		/* Open as ELF file image */
#define	GF_PROGRAM	1		/* Open as ELF program image */

typedef struct mdb_gelf_sect {
	GElf_Shdr gs_shdr;		/* ELF section header */
	const char *gs_name;		/* Section name */
	void *gs_data;			/* Section data */
} mdb_gelf_sect_t;

typedef struct mdb_gelf_file {
	GElf_Ehdr gf_ehdr;		/* ELF file header */
	GElf_Phdr *gf_phdrs;		/* Array of program headers */
	size_t gf_npload;		/* Number of sorted PT_LOAD phdrs */
	GElf_Phdr *gf_dynp;		/* Pointer to PT_DYNAMIC phdr */
	GElf_Dyn *gf_dyns;		/* Array of dynamic entries */
	size_t gf_ndyns;		/* Number of dynamic entries */
	size_t gf_shnum;		/* Number of section headers */
	size_t gf_shstrndx;		/* Index of section string table */
	size_t gf_phnum;		/* Number of program headers */
	mdb_gelf_sect_t *gf_sects;	/* Array of section structs */
	mdb_io_t *gf_io;		/* I/o backend for ELF file */
	int gf_mode;			/* Mode flag (see above) */
} mdb_gelf_file_t;

typedef struct mdb_gelf_symtab {
	mdb_nv_t gst_nv;		/* Name/value hash for name lookups */
	void *gst_asmap;		/* Sorted array of symbol pointers */
	size_t gst_aslen;		/* Number of entries in gst_asmap */
	size_t gst_asrsv;		/* Actual reserved size of gst_asmap */
	const GElf_Ehdr *gst_ehdr;	/* Associated ELF file ehdr */
	mdb_gelf_file_t *gst_file;	/* Associated ELF file */
	mdb_gelf_sect_t *gst_dsect;	/* Associated ELF data section */
	mdb_gelf_sect_t *gst_ssect;	/* Associated ELF string section */
	uint_t gst_id;			/* Next symbol ID to use if mutable */
	uint_t gst_tabid;		/* ID for symbol table */
} mdb_gelf_symtab_t;

typedef struct mdb_gelf_dsym {
	union {
		Elf32_Sym ds_s32;	/* 32-bit native symbol data */
		Elf64_Sym ds_s64;	/* 64-bit native symbol data */
	} ds_u;
	GElf_Sym ds_sym;		/* Generic ELF symbol data */
	mdb_var_t *ds_var;		/* Backpointer to nv element */
	uint_t ds_id;			/* Symbol id number */
} mdb_gelf_dsym_t;

extern int mdb_gelf_check(mdb_io_t *, Elf32_Ehdr *, GElf_Half);
extern mdb_gelf_file_t *mdb_gelf_create(mdb_io_t *, GElf_Half, int);
extern void mdb_gelf_destroy(mdb_gelf_file_t *);

extern void mdb_gelf_ehdr_to_gehdr(Ehdr *, GElf_Ehdr *);

typedef enum { GIO_READ, GIO_WRITE } mdb_gelf_rw_t;

extern ssize_t mdb_gelf_rw(mdb_gelf_file_t *, void *, size_t, uintptr_t,
    ssize_t (*)(mdb_io_t *, void *, size_t), mdb_gelf_rw_t);

extern mdb_gelf_symtab_t *mdb_gelf_symtab_create_file(mdb_gelf_file_t *,
    GElf_Word, uint_t);
extern mdb_gelf_symtab_t *mdb_gelf_symtab_create_file_by_name(mdb_gelf_file_t *,
    const char *, const char *, uint_t);

extern mdb_gelf_symtab_t *mdb_gelf_symtab_create_raw(const GElf_Ehdr *,
    const void *, void *, const void *, void *, uint_t);

extern mdb_gelf_symtab_t *mdb_gelf_symtab_create_dynamic(mdb_gelf_file_t *,
    uint_t);
extern mdb_gelf_symtab_t *mdb_gelf_symtab_create_mutable(void);

extern void mdb_gelf_symtab_destroy(mdb_gelf_symtab_t *);
extern size_t mdb_gelf_symtab_size(mdb_gelf_symtab_t *);

extern const char *mdb_gelf_sym_name(mdb_gelf_symtab_t *, const GElf_Sym *);
extern int mdb_gelf_sym_closer(const GElf_Sym *, const GElf_Sym *, uintptr_t);

extern int mdb_gelf_symtab_lookup_by_addr(mdb_gelf_symtab_t *,
    uintptr_t, uint_t, char *, size_t, GElf_Sym *, uint_t *);

extern int mdb_gelf_symtab_lookup_by_name(mdb_gelf_symtab_t *,
    const char *, GElf_Sym *, uint_t *);

extern int mdb_gelf_symtab_lookup_by_file(mdb_gelf_symtab_t *,
    const char *, const char *, GElf_Sym *, uint_t *);

extern void mdb_gelf_symtab_iter(mdb_gelf_symtab_t *, int (*)(void *,
    const GElf_Sym *, const char *, uint_t), void *);

extern void mdb_gelf_symtab_insert(mdb_gelf_symtab_t *,
    const char *, const GElf_Sym *);

extern void mdb_gelf_symtab_delete(mdb_gelf_symtab_t *,
    const char *, GElf_Sym *);

extern mdb_gelf_sect_t *mdb_gelf_sect_by_name(mdb_gelf_file_t *,
    const char *);

extern void *mdb_gelf_sect_load(mdb_gelf_file_t *, mdb_gelf_sect_t *);

#endif /* _MDB */

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_GELF_H */
