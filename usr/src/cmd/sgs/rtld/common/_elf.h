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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__ELF_DOT_H
#define	__ELF_DOT_H

#include <sys/types.h>
#include <elf.h>
#include <_rtld.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common extern functions for ELF file class.
 */
extern	int	elf_reloc(Rt_map *, uint_t, int *);
extern	int	elf_reloc_error(Rt_map *, const char *, void *, uint_t);
extern	void	elf_plt_init(void *, caddr_t);
extern	int	elf_set_prot(Rt_map *, int);
extern	Rt_map	*elf_obj_file(Lm_list *, Aliste, const char *, int);
extern	Rt_map	*elf_obj_fini(Lm_list *, Rt_map *, int *);
extern	int	elf_copy_reloc(char *, Sym *, Rt_map *, void *, Sym *,
		    Rt_map *, const void *);
extern	Sym	*elf_find_sym(Slookup *, Rt_map **, uint_t *, int *);
extern	Sym	*elf_lazy_find_sym(Slookup *, Rt_map **, uint_t *, int *);
extern	Rt_map	*elf_lazy_load(Rt_map *, Slookup *, uint_t, const char *,
		    int *);
extern	Sym	*elf_lookup_filtee(Slookup *, Rt_map **, uint_t *, uint_t,
		    int *);
extern	Rt_map	*elf_new_lm(Lm_list *, const char *, const char *, Dyn *,
		    ulong_t, ulong_t, Aliste, ulong_t, ulong_t, ulong_t,
		    ulong_t, Mmap *, uint_t, int *);
extern	int	elf_rtld_load();

#if	defined(__sparcv9)
extern	void	elf_plt2_init(uint_t *, Rt_map *);
#endif

#if	defined(__i386)
extern	ulong_t	elf_reloc_relacount(ulong_t, ulong_t, ulong_t, ulong_t);
extern	int	elf_copy_gen(Rt_map *);
#endif

/*
 * Padinfo
 *
 * Used to track the which PLTpadd entries have been used and
 * to where they are bound.
 *
 * NOTE: these are only currently used for SparcV9
 */
typedef struct pltpadinfo {
	Addr	pp_addr;
	void	*pp_plt;
} Pltpadinfo;

/*
 * Private data for an ELF file class.
 */
typedef struct _rt_elf_private {
	void		*e_symtab;	/* symbol table */
	void		*e_sunwsymtab;	/* symtab augmented with local fcns */
	uint_t		*e_hash;	/* hash table */
	char		*e_strtab;	/* string table */
	void		*e_reloc;	/* relocation table */
	uint_t		*e_pltgot;	/* addrs for procedure linkage table */
	void		*e_dynplt;	/* dynamic plt table - used by prof */
	void		*e_jmprel;	/* plt relocations */
	ulong_t		e_sunwsortent;	/* size of sunw[sym|tls]sort entry */
	uint_t		*e_sunwsymsort;	/* sunwsymtab indices sorted by addr */
	ulong_t		e_sunwsymsortsz; /* size of sunwsymtab */
	ulong_t		e_sunwsymsz;	/* size of e_sunwsymtab */
	ulong_t		e_pltrelsize;	/* size of PLT relocation entries */
	ulong_t		e_relsz;	/* size of relocs */
	ulong_t		e_relent;	/* size of base reloc entry */
	ulong_t		e_movesz;	/* size of movetabs */
	ulong_t		e_moveent;	/* size of base movetab entry */
	ulong_t		e_tlsstatoff;	/* TLS offset into static block */
	void		*e_movetab;	/* movetable address */
	Phdr		*e_sunwbss;	/* program header for SUNWBSS */
	Phdr		*e_pttls;	/* PT_TLS */
	Phdr		*e_ptunwind;	/* PT_SUNW_UNWIND (amd64 specific) */
	ulong_t		e_syment;	/* size of symtab entry */
	ulong_t		e_entry;	/* entry point for file */
	Verneed		*e_verneed;	/* versions needed by this image and */
	int		e_verneednum;	/*	their associated count */
	Verdef		*e_verdef;	/* versions defined by this image and */
	int		e_verdefnum;	/*	their associated count */
	Versym 		*e_versym;	/* Per-symbol versions */
	ulong_t		e_syminent;	/* syminfo entry size */
	void		*e_pltpad;	/* PLTpad table */
	void		*e_pltpadend;	/* end of PLTpad table */
} Rt_elfp;

/*
 * Macros for getting to linker ELF private data.
 */
#define	ELFPRV(X)		((X)->rt_priv)
#define	SYMTAB(X)		(((Rt_elfp *)(X)->rt_priv)->e_symtab)
#define	SUNWSYMTAB(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsymtab)
#define	HASH(X)			(((Rt_elfp *)(X)->rt_priv)->e_hash)
#define	STRTAB(X)		(((Rt_elfp *)(X)->rt_priv)->e_strtab)
#define	REL(X)			(((Rt_elfp *)(X)->rt_priv)->e_reloc)
#define	PLTGOT(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltgot)
#define	MOVESZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_movesz)
#define	MOVEENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_moveent)
#define	MOVETAB(X)		(((Rt_elfp *)(X)->rt_priv)->e_movetab)
#define	DYNPLT(X)		(((Rt_elfp *)(X)->rt_priv)->e_dynplt)
#define	JMPREL(X)		(((Rt_elfp *)(X)->rt_priv)->e_jmprel)
#define	SUNWSYMSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsz)
#define	PTTLS(X)		(((Rt_elfp *)(X)->rt_priv)->e_pttls)
#define	PTUNWIND(X)		(((Rt_elfp *)(X)->rt_priv)->e_ptunwind)
#define	TLSSTATOFF(X)		(((Rt_elfp *)(X)->rt_priv)->e_tlsstatoff)
#define	PLTRELSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltrelsize)
#define	RELSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_relsz)
#define	RELENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_relent)
#define	SYMENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_syment)
#define	ENTRY(X)		(((Rt_elfp *)(X)->rt_priv)->e_entry)
#define	VERNEED(X)		(((Rt_elfp *)(X)->rt_priv)->e_verneed)
#define	VERNEEDNUM(X)		(((Rt_elfp *)(X)->rt_priv)->e_verneednum)
#define	VERDEF(X)		(((Rt_elfp *)(X)->rt_priv)->e_verdef)
#define	VERDEFNUM(X)		(((Rt_elfp *)(X)->rt_priv)->e_verdefnum)
#define	VERSYM(X)		(((Rt_elfp *)(X)->rt_priv)->e_versym)
#define	SUNWBSS(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwbss)
#define	SYMINENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_syminent)
#define	PLTPAD(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltpad)
#define	PLTPADEND(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltpadend)
#define	SUNWSORTENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsortent)
#define	SUNWSYMSORT(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsort)
#define	SUNWSYMSORTSZ(X)	(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsortsz)

#ifdef	__cplusplus
}
#endif

#endif	/* __ELF_DOT_H */
