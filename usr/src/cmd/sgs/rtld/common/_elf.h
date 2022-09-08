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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	__ELF_DOT_H
#define	__ELF_DOT_H

#include <sys/types.h>
#include <sys/mman.h>
#include <sgs.h>
#include <elf.h>
#include <_rtld.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common extern functions for ELF file class.
 */
extern	int	elf_config(Rt_map *);
extern	Rtc_obj	*elf_config_ent(const char *, Word, int, const char **);
extern	void	elf_config_flt(Lm_list *, const char *, const char *,
		    Alist **, Aliste);
#if	defined(__i386)
extern	int	elf_copy_gen(Rt_map *);
#endif
extern	int	elf_copy_reloc(char *, Sym *, Rt_map *, void *, Sym *,
		    Rt_map *, const void *);
extern	int	elf_find_sym(Slookup *, Sresult *, uint_t *, int *);
extern	int	elf_lazy_find_sym(Slookup *, Sresult *, uint_t *, int *);
extern	Rt_map	*elf_lazy_load(Rt_map *, Slookup *, uint_t, const char *,
		    uint_t, Grp_hdl **, int *);
extern	int	elf_lookup_filtee(Slookup *, Sresult *, uint_t *, uint_t,
		    int *);
extern	int	elf_mach_flags_check(Rej_desc *, Ehdr *);
extern	Rt_map	*elf_new_lmp(Lm_list *, Aliste, Fdesc *, Addr, size_t, void *,
		    Rt_map *, int *);
extern	Rt_map	*elf_obj_file(Lm_list *, Aliste, Rt_map *, const char *,
		    mmapobj_result_t *, mmapobj_result_t *, uint_t);
extern	Rt_map	*elf_obj_fini(Lm_list *, Rt_map *, Rt_map *, int *);
extern	void	elf_plt_init(void *, caddr_t);
#if	defined(__sparcv9)
extern	void	elf_plt2_init(uint_t *, Rt_map *);
#endif
extern	int	elf_reloc(Rt_map *, uint_t, int *, APlist **);
extern	void	elf_reloc_bad(Rt_map *, void *, uchar_t, ulong_t,
		    ulong_t);
extern	int	elf_reloc_error(Rt_map *, const char *, void *, uint_t);
extern	int	elf_rtld_load();
extern	long	elf_static_tls(Rt_map *, Sym *, void *, uchar_t, char *,
		    ulong_t, long);
extern	Fct	*elf_verify(caddr_t, size_t, Fdesc *, const char *, Rej_desc *);
extern	int	elf_verify_vers(const char *, Rt_map *, Rt_map *);

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
	Phdr		*e_pttls;	/* PT_TLS */
	Phdr		*e_ptunwind;	/* PT_SUNW_UNWIND (amd64 specific) */
	ulong_t		e_syment;	/* size of symtab entry */
	Verneed		*e_verneed;	/* versions needed by this image and */
	int		e_verneednum;	/*	their associated count */
	Verdef		*e_verdef;	/* versions defined by this image and */
	int		e_verdefnum;	/*	their associated count */
	Versym		*e_versym;	/* Per-symbol versions */
	ulong_t		e_syminent;	/* syminfo entry size */
	void		*e_pltpad;	/* PLTpad table */
	void		*e_pltpadend;	/* end of PLTpad table */
	Syscapset	e_capset;	/* capabilities set */
	Capinfo		*e_capinfo;	/* symbol capabilities information */
	uint_t		e_capchainent;	/* size of capabilities chain entry */
	uint_t		e_capchainsz;	/* size of capabilities chain data */
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
#define	JMPREL(X)		(((Rt_elfp *)(X)->rt_priv)->e_jmprel)
#define	SUNWSYMSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsz)
#define	PTTLS(X)		(((Rt_elfp *)(X)->rt_priv)->e_pttls)
#define	PTUNWIND(X)		(((Rt_elfp *)(X)->rt_priv)->e_ptunwind)
#define	TLSSTATOFF(X)		(((Rt_elfp *)(X)->rt_priv)->e_tlsstatoff)
#define	PLTRELSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltrelsize)
#define	RELSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_relsz)
#define	RELENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_relent)
#define	SYMENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_syment)
#define	VERNEED(X)		(((Rt_elfp *)(X)->rt_priv)->e_verneed)
#define	VERNEEDNUM(X)		(((Rt_elfp *)(X)->rt_priv)->e_verneednum)
#define	VERDEF(X)		(((Rt_elfp *)(X)->rt_priv)->e_verdef)
#define	VERDEFNUM(X)		(((Rt_elfp *)(X)->rt_priv)->e_verdefnum)
#define	VERSYM(X)		(((Rt_elfp *)(X)->rt_priv)->e_versym)
#define	SYMINENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_syminent)
#define	PLTPAD(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltpad)
#define	PLTPADEND(X)		(((Rt_elfp *)(X)->rt_priv)->e_pltpadend)
#define	SUNWSORTENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsortent)
#define	SUNWSYMSORT(X)		(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsort)
#define	SUNWSYMSORTSZ(X)	(((Rt_elfp *)(X)->rt_priv)->e_sunwsymsortsz)
#define	CAPSET(X)		(((Rt_elfp *)(X)->rt_priv)->e_capset)
#define	CAPINFO(X)		(((Rt_elfp *)(X)->rt_priv)->e_capinfo)
#define	CAPCHAINENT(X)		(((Rt_elfp *)(X)->rt_priv)->e_capchainent)
#define	CAPCHAINSZ(X)		(((Rt_elfp *)(X)->rt_priv)->e_capchainsz)

/*
 * Most of the above macros are used from ELF specific routines, however there
 * are a couple of instances where we need to ensure the file being processed
 * is ELF before dereferencing the macro.
 */
#define	THIS_IS_ELF(X)		(FCT(X) == &elf_fct)
#define	THIS_IS_NOT_ELF(X)	(FCT(X) != &elf_fct)

#ifdef	__cplusplus
}
#endif

#endif	/* __ELF_DOT_H */
