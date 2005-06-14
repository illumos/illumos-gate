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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GELF_H
#define	_GELF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>

#include <libelf.h>
#include <sys/link.h>

#ifdef	__cplusplus
extern "C" {
#endif


#if !defined(_INT64_TYPE)
#error "64-bit integer types are required by gelf."
#endif

/*
 * Class-independent ELF API for Elf utilities.  This is
 * for manipulating Elf32 and Elf64 specific information
 * in a format common to both classes.
 */

typedef Elf64_Addr	GElf_Addr;
typedef Elf64_Half	GElf_Half;
typedef Elf64_Off	GElf_Off;
typedef Elf64_Sword	GElf_Sword;
typedef Elf64_Sxword	GElf_Sxword;
typedef Elf64_Word	GElf_Word;
typedef Elf64_Xword	GElf_Xword;

typedef Elf64_Ehdr	GElf_Ehdr;
typedef	Elf64_Move	GElf_Move;
typedef Elf64_Phdr	GElf_Phdr;
typedef Elf64_Shdr	GElf_Shdr;
typedef Elf64_Sym	GElf_Sym;
typedef	Elf64_Syminfo	GElf_Syminfo;
typedef Elf64_Rela	GElf_Rela;
typedef Elf64_Rel	GElf_Rel;
typedef Elf64_Dyn	GElf_Dyn;
typedef Elf64_Cap	GElf_Cap;

/*
 * The processing of versioning information can stay the
 * same because both the Elf32 and Elf64 structures are
 * of equal sizes.
 */
typedef Elf64_Verdef	GElf_Verdef;
typedef Elf64_Verdaux	GElf_Verdaux;
typedef Elf64_Verneed	GElf_Verneed;
typedef Elf64_Vernaux	GElf_Vernaux;
typedef Elf64_Versym	GElf_Versym;

/*
 * move.m_info is encoded using the 64bit fields in Gelf.
 */
#define	GELF_M_SYM	ELF64_M_SYM
#define	GELF_M_SIZE	ELF64_M_SIZE

/*
 * sym.st_info field is same size for Elf32 and Elf64.
 */
#define	GELF_ST_BIND	ELF64_ST_BIND
#define	GELF_ST_TYPE	ELF64_ST_TYPE
#define	GELF_ST_INFO	ELF64_ST_INFO


/*
 * Elf64 r_info may have data field in type id's word,
 * so GELF_R_TYPE is defined as ELF64_R_TYPE_ID in order
 * to isolate the proper bits for the true type id.
 */
#define	GELF_R_TYPE		ELF64_R_TYPE_ID
#define	GELF_R_SYM		ELF64_R_SYM
#define	GELF_R_INFO		ELF64_R_INFO
#define	GELF_R_TYPE_DATA	ELF64_R_TYPE_DATA
#define	GELF_R_TYPE_ID		ELF64_R_TYPE_ID
#define	GELF_R_TYPE_INFO	ELF64_R_TYPE_INFO



int		gelf_getclass(Elf*);
size_t		gelf_fsize(Elf *, Elf_Type, size_t, uint_t);
GElf_Ehdr *	gelf_getehdr(Elf *, GElf_Ehdr *);
int		gelf_update_ehdr(Elf *, GElf_Ehdr *);
unsigned long	gelf_newehdr(Elf *, int);
GElf_Phdr *	gelf_getphdr(Elf *, int, GElf_Phdr *);
int		gelf_update_phdr(Elf *, int, GElf_Phdr *);
unsigned long	gelf_newphdr(Elf *, size_t);
GElf_Shdr *	gelf_getshdr(Elf_Scn *,  GElf_Shdr *);
int		gelf_update_shdr(Elf_Scn *, GElf_Shdr *);
Elf_Data *	gelf_xlatetof(Elf *, Elf_Data *, const Elf_Data *, uint_t);
Elf_Data *	gelf_xlatetom(Elf *, Elf_Data *, const Elf_Data *, uint_t);
GElf_Sym *	gelf_getsym(Elf_Data *, int, GElf_Sym *);
int		gelf_update_sym(Elf_Data *, int, GElf_Sym *);
GElf_Sym *	gelf_getsymshndx(Elf_Data *, Elf_Data *, int, GElf_Sym *,
		    Elf32_Word *);
int		gelf_update_symshndx(Elf_Data *, Elf_Data *, int, GElf_Sym *,
		    Elf32_Word);
GElf_Syminfo *	gelf_getsyminfo(Elf_Data *, int, GElf_Syminfo *);
int		gelf_update_syminfo(Elf_Data *, int, GElf_Syminfo *);
GElf_Move *	gelf_getmove(Elf_Data *, int, GElf_Move *);
int		gelf_update_move(Elf_Data *, int, GElf_Move *);
GElf_Dyn *	gelf_getdyn(Elf_Data *, int, GElf_Dyn *);
int		gelf_update_dyn(Elf_Data *, int, GElf_Dyn *);
GElf_Rela *	gelf_getrela(Elf_Data *, int, GElf_Rela *);
int		gelf_update_rela(Elf_Data *, int, GElf_Rela *);
GElf_Rel *	gelf_getrel(Elf_Data *, int, GElf_Rel *);
int		gelf_update_rel(Elf_Data *, int, GElf_Rel *);
long		gelf_checksum(Elf *);
GElf_Cap *	gelf_getcap(Elf_Data *, int, GElf_Cap *);
int		gelf_update_cap(Elf_Data *, int, GElf_Cap *);


#ifdef	__cplusplus
}
#endif

#endif	/* _GELF_H */
