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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBLD_H
#define	_LIBLD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <libelf.h>
#include <sgs.h>
#include <_machelf.h>
#include <string_table.h>
#include <sys/avl.h>
#include <alist.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Default directory search path manipulation for the link-editor.  YLDIR
 * indicates which directory in LIBPATH is replaced by the -YL option to cc
 * and ld.  YUDIR indicates which directory is replaced by -YU.
 */
#define	YLDIR	1
#define	YUDIR	2

/*
 * Define a hash value that can never be returned from elf_hash().
 */
#define	SYM_NOHASH	(~(Word)0)

/*
 * Macro that can be used to represent both ORDER flags
 * in a section header.
 */
#define	ALL_SHF_ORDER	(SHF_ORDERED | SHF_LINK_ORDER)

/*
 * The linker merges (concatenates) sections with the same name and
 * compatible section header flags. When comparing these flags,
 * there are some that should not be included in the decision.
 * The ALL_SHF_IGNORE constant defines these flags.
 *
 * NOTE: SHF_MERGE|SHF_STRINGS:
 * The compiler is allowed to set the SHF_MERGE|SHF_STRINGS flags in
 * order to tell the linker that:
 *
 *      1) There is nothing in the section except null terminated strings.
 *	2) Those strings do not contain NULL bytes, except as termination.
 *	3) All references to these strings occur via standard relocation
 *		records.
 *
 * As a result, if two compatible sections both have these flags set, it is
 * OK to combine the strings they contain into a single merged string table
 * with duplicates removed and tail strings merged.
 *
 * This is a different meaning than the simple concatenating of sections
 * that the linker always does. It is a hint that an additional optimization
 * is possible, but not required. This means that sections that do not
 * share the same SHF_MERGE|SHF_STRINGS values can be concatenated,
 * but cannot have their duplicate strings combined. Hence, the
 * SHF_MERGE|SHF_STRINGS flags should be ignored when deciding whether
 * two sections can be concatenated.
 */
#define	ALL_SHF_IGNORE	(ALL_SHF_ORDER | SHF_GROUP | SHF_MERGE | SHF_STRINGS)

/*
 * Define symbol reference types for use in symbol resolution.
 */
typedef enum {
	REF_DYN_SEEN,			/* a .so symbol has been seen */
	REF_DYN_NEED,			/* a .so symbol satisfies a .o symbol */
	REF_REL_NEED,			/* a .o symbol */
	REF_NUM				/* the number of symbol references */
} Symref;


/*
 * GOT reference models
 */
typedef enum {
	GOT_REF_GENERIC,	/* generic symbol reference */
	GOT_REF_TLSIE,		/* TLS initial exec (gnu) reference */
	GOT_REF_TLSLD,		/* TLS local dynamic reference */
	GOT_REF_TLSGD		/* TLS general dynamic reference */
} Gotref;

typedef struct {
	Xword		gn_addend;	/* addend associated with GOT entry */
	Sword		gn_gotndx;	/* GOT table index */
	Gotref		gn_gotref;
} Gotndx;

/*
 * Got debugging structure.  The got index is defined as a signed value as we
 * do so much mucking around with negative and positive gots on SPARC, and sign
 * extension is necessary when building 64-bit objects.  On intel we explicitly
 * cast this variable to an unsigned value.
 */
typedef struct {
	Sym_desc *	gt_sym;
	Gotndx		gt_gndx;
} Gottable;


/*
 * Output file processing structure
 */
typedef Lword ofl_flag_t;
struct ofl_desc {
	char		*ofl_sgsid;	/* link-editor identification */
	const char	*ofl_name;	/* full file name */
	Elf		*ofl_elf;	/* elf_memory() elf descriptor */
	Elf		*ofl_welf;	/* ELF_C_WRITE elf descriptor */
	Ehdr		*ofl_dehdr;	/* default elf header, and new elf */
	Ehdr		*ofl_nehdr;	/*	header describing this file */
	Phdr		*ofl_phdr;	/* program header descriptor */
	Phdr		*ofl_tlsphdr;	/* TLS phdr */
	int		ofl_fd;		/* file descriptor */
	size_t		ofl_size;	/* image size */
	List		ofl_maps;	/* list of input mapfiles */
	List		ofl_segs;	/* list of segments */
	List		ofl_ents;	/* list of entrance descriptors */
	List		ofl_objs;	/* relocatable object file list */
	Word		ofl_objscnt;	/* 	and count */
	List		ofl_ars;	/* archive library list */
	Word		ofl_arscnt;	/* 	and count */
	List		ofl_sos;	/* shared object list */
	Word		ofl_soscnt;	/* 	and count */
	List		ofl_soneed;	/* list of implicitly required .so's */
	List		ofl_socntl;	/* list of .so control definitions */
	List		ofl_outrels;	/* list of output relocations */
	Word		ofl_outrelscnt;	/* 	and count */
	List		ofl_actrels;	/* list of relocations to perform */
	Word		ofl_actrelscnt;	/* 	and count */
	Word		ofl_entrelscnt;	/* no of relocations entered */
	List		ofl_copyrels;	/* list of copy relocations */
	List		ofl_ordered;	/* list of shf_ordered sections */
	List		ofl_syminfsyms;	/* list of interesting syms */
					/*	for syminfo processing */
	List		ofl_ismove;	/* list of .SUNW_move sections */
	List		ofl_mvrelisdescs; /* list of relocation input section */
					/* targeting to expanded area */
	List		ofl_parsym; 	/* list of Parsym_info */
	List		ofl_extrarels;	/* relocation sections which have */
					/*    a NULL sh_info */
	avl_tree_t	*ofl_groups;	/* pointer to head of Groups AVL tree */
	List		ofl_initarray;	/* list of init array func names */
	List		ofl_finiarray;	/* list of fini array func names */
	List		ofl_preiarray;	/* list of preinit array func names */
	List		ofl_rtldinfo;	/* list of rtldinfo syms */
	List		ofl_osgroups;	/* list of output GROUP sections */
	List		ofl_ostlsseg;	/* pointer to sections in TLS segment */
#if	defined(_ELF64)			/* for amd64 target only */
	List		ofl_unwind;	/* list of unwind output sections */
	Os_desc		*ofl_unwindhdr;	/* Unwind hdr */
#endif
	avl_tree_t	ofl_symavl;	/* pointer to head of Syms AVL tree */
	Sym_desc	**ofl_regsyms;	/* array of potential register */
	Word		ofl_regsymsno;	/*    symbols and array count */
	Word		ofl_regsymcnt;	/* no. of output register symbols */
	Word		ofl_lregsymcnt;	/* no. of local register symbols */
	Sym_desc	*ofl_dtracesym;	/* ld -zdtrace= */
	ofl_flag_t	ofl_flags;	/* various state bits, args etc. */
	ofl_flag_t	ofl_flags1;	/*	more flags */
	Xword		ofl_segorigin;	/* segment origin (start) */
	void		*ofl_entry;	/* entry point (-e and Sym_desc *) */
	char		*ofl_filtees;	/* shared objects we are a filter for */
	const char	*ofl_soname;	/* (-h option) output file name for */
					/*	dynamic structure */
	const char	*ofl_interp;	/* interpreter name used by exec() */
	char		*ofl_rpath;	/* run path to store in .dynamic */
	char		*ofl_config;	/* config path to store in .dynamic */
	List		ofl_ulibdirs;	/* user supplied library search list */
	List		ofl_dlibdirs;	/* default library search list */
	Word		ofl_vercnt;	/* number of versions to generate */
	List		ofl_verdesc;	/* list of version descriptors */
	size_t		ofl_verdefsz;	/* size of version definition section */
	size_t		ofl_verneedsz;	/* size of version needed section */
	Word		ofl_entercnt;	/* no. of global symbols entered */
	Word		ofl_globcnt;	/* no. of global symbols to output */
	Word		ofl_scopecnt;	/* no. of scoped symbols to output */
	Word		ofl_dynscopecnt; /* no. scoped syms in .SUNW_ldynsym */
	Word		ofl_elimcnt;	/* no. of eliminated symbols */
	Word		ofl_locscnt;	/* no. of local symbols in .symtab */
	Word		ofl_dynlocscnt;	/* no. local symbols in .SUNW_ldynsym */
	Word		ofl_dynsymsortcnt; /* no. ndx in .SUNW_dynsymsort */
	Word		ofl_dyntlssortcnt; /* no. ndx in .SUNW_dyntlssort */
	Word		ofl_dynshdrcnt;	/* no. of output section in .dynsym */
	Word		ofl_shdrcnt;	/* no. of output sections */
	Str_tbl		*ofl_shdrsttab;	/* Str_tbl for shdr strtab */
	Str_tbl		*ofl_strtab;	/* Str_tbl for symtab strtab */
	Str_tbl		*ofl_dynstrtab;	/* Str_tbl for dymsym strtab */
	Gotndx		*ofl_tlsldgotndx; /* index to LD TLS_index structure */
	Xword		ofl_relocsz;	/* size of output relocations */
	Xword		ofl_relocgotsz;	/* size of .got relocations */
	Xword		ofl_relocpltsz;	/* size of .plt relocations */
	Xword		ofl_relocbsssz;	/* size of .bss (copy) relocations */
	Xword		ofl_relocrelsz;	/* size of .rel[a] relocations */
	Word		ofl_relocincnt;	/* no. of input relocations */
	Word		ofl_reloccnt;	/* tot number of output relocations */
	Word		ofl_reloccntsub; /* tot numb of output relocations to */
					/*	skip (-zignore) */
	Word		ofl_relocrelcnt; /* tot number of relative */
					/*	relocations */
	Word		ofl_gotcnt;	/* no. of .got entries */
	Word		ofl_pltcnt;	/* no. of .plt entries */
	Word		ofl_pltpad;	/* no. of .plt padd entries */
	Word		ofl_hashbkts;	/* no. of hash buckets required */
	Is_desc		*ofl_isbss;	/* .bss input section (globals) */
	Is_desc		*ofl_islbss;	/* .lbss input section (globals) */
	Is_desc		*ofl_istlsbss;	/* .tlsbss input section (globals) */
	Is_desc		*ofl_issunwdata1; /* .data input section */
					/* 	partially expanded. */
	Is_desc		*ofl_issunwbss;	/* .SUNW_bss input section (globals) */
	Os_desc		*ofl_osdynamic;	/* .dynamic output section */
	Os_desc		*ofl_osdynsym;	/* .dynsym output section */
	Os_desc		*ofl_osldynsym;	/* .SUNW_ldynsym output section */
	Os_desc		*ofl_osdynstr;	/* .dynstr output section */
	Os_desc		*ofl_osdynsymsort; /* .SUNW_dynsymsort output section */
	Os_desc		*ofl_osdyntlssort; /* .SUNW_dyntlssort output section */
	Os_desc		*ofl_osgot;	/* .got output section */
	Os_desc		*ofl_oshash;	/* .hash output section */
	Os_desc		*ofl_osinitarray; /* .initarray output section */
	Os_desc		*ofl_osfiniarray; /* .finiarray output section */
	Os_desc		*ofl_ospreinitarray; /* .preinitarray output section */
	Os_desc		*ofl_osinterp;	/* .interp output section */
	Os_desc		*ofl_oscap;	/* .SUNW_cap output section */
	Os_desc		*ofl_osplt;	/* .plt output section */
	Os_desc		*ofl_osmove;	/* .SUNW_move output section */
	Os_desc		*ofl_osrelhead;	/* first relocation section */
	Os_desc		*ofl_osrel;	/* .rel[a] relocation section */
	Os_desc		*ofl_osshstrtab; /* .shstrtab output section */
	Os_desc		*ofl_osstrtab;	/* .strtab output section */
	Os_desc		*ofl_ossymtab;	/* .symtab output section */
	Os_desc		*ofl_ossymshndx; /* .symtab_shndx output section */
	Os_desc		*ofl_osdynshndx; /* .dynsym_shndx output section */
	Os_desc		*ofl_osldynshndx; /* .SUNW_ldynsym_shndx output sec */
	Os_desc		*ofl_osverdef;	/* .version definition output section */
	Os_desc		*ofl_osverneed;	/* .version needed output section */
	Os_desc		*ofl_osversym;	/* .version symbol ndx output section */
	Word		ofl_dtflags_1;	/* DT_FLAGS_1 entries */
	Word		ofl_dtflags;	/* DT_FLAGS entries */
	Os_desc		*ofl_ossyminfo;	/* .SUNW_syminfo output section */
	Half		ofl_sunwdata1ndx; /* section index for sunwdata1  */
					/* Ref. at perform_outreloc() in */
					/* libld/{mach}/machrel.c */
	Xword		*ofl_checksum;	/* DT_CHECKSUM value address */
	char		*ofl_depaudit;	/* dependency auditing required (-P) */
	char		*ofl_audit;	/* object auditing required (-p) */
	Alist		*ofl_symfltrs;	/* per-symbol filtees and their */
	Alist		*ofl_dtsfltrs;	/*	associated .dynamic/.dynstrs */
	Xword		ofl_hwcap_1;	/* hardware capabilities */
	Xword		ofl_sfcap_1;	/* software capabilities */
	Lm_list		*ofl_lml;	/* runtime link-map list */
	Gottable	*ofl_gottable;	/* debugging got information */
};

#define	FLG_OF_DYNAMIC	0x00000001	/* generate dynamic output module */
#define	FLG_OF_STATIC	0x00000002	/* generate static output module */
#define	FLG_OF_EXEC	0x00000004	/* generate an executable */
#define	FLG_OF_RELOBJ	0x00000008	/* generate a relocatable object */
#define	FLG_OF_SHAROBJ	0x00000010	/* generate a shared object */
#define	FLG_OF_BFLAG	0x00000020	/* do no special plt building: -b */
#define	FLG_OF_IGNENV	0x00000040	/* ignore LD_LIBRARY_PATH: -i */
#define	FLG_OF_STRIP	0x00000080	/* strip output: -s */
#define	FLG_OF_NOWARN	0x00000100	/* disable symbol warnings: -t */
#define	FLG_OF_NOUNDEF	0x00000200	/* allow no undefined symbols: -zdefs */
#define	FLG_OF_PURETXT	0x00000400	/* allow no text relocations: -ztext  */
#define	FLG_OF_GENMAP	0x00000800	/* generate a memory map: -m */
#define	FLG_OF_DYNLIBS	0x00001000	/* dynamic input allowed: -Bdynamic */
#define	FLG_OF_SYMBOLIC	0x00002000	/* bind global symbols: -Bsymbolic */
#define	FLG_OF_ADDVERS	0x00004000	/* add version stamp: -Qy */
#define	FLG_OF_NOLDYNSYM 0x00008000	/* -znoldynsym set */
#define	FLG_OF_SEGORDER	0x00010000	/* segment ordering is required */
#define	FLG_OF_SEGSORT	0x00020000	/* segment sorting is required */
#define	FLG_OF_TEXTREL	0x00040000	/* text relocations have been found */
#define	FLG_OF_MULDEFS	0x00080000	/* multiple symbols are allowed */
#define	FLG_OF_TLSPHDR	0x00100000	/* a TLS program header is required */
#define	FLG_OF_BLDGOT	0x00200000	/* build GOT table */
#define	FLG_OF_VERDEF	0x00400000	/* record version definitions */
#define	FLG_OF_VERNEED	0x00800000	/* record version dependencies */
#define	FLG_OF_NOVERSEC 0x01000000	/* don't record version sections */

#define	FLG_OF_PROCRED	0x04000000	/* process any symbol reductions by */
					/*	effecting the symbol table */
					/*	output and relocations */
#define	FLG_OF_SYMINFO	0x08000000	/* create a syminfo section */
#define	FLG_OF_AUX	0x10000000	/* ofl_filter is an auxiliary filter */
#define	FLG_OF_FATAL	0x20000000	/* fatal error during input */
#define	FLG_OF_WARN	0x40000000	/* warning during input processing. */
#define	FLG_OF_VERBOSE	0x80000000	/* -z verbose flag set */

#define	FLG_OF_MAPSYMB	0x000100000000	/* symbolic scope definition seen */
#define	FLG_OF_MAPGLOB	0x000200000000	/* global scope definition seen */
#define	FLG_OF_COMREL	0x000400000000	/* -z combreloc set, which enables */
					/*	DT_RELACNT tracking, */
#define	FLG_OF_NOCOMREL	0x000800000000	/* -z nocombreloc set */
#define	FLG_OF_AUTOLCL	0x001000000000	/* automatically reduce unspecified */
					/*	global symbols to locals */
#define	FLG_OF_AUTOELM	0x002000000000	/* automatically eliminate  */
					/*	unspecified global symbols */
#define	FLG_OF_REDLSYM	0x004000000000	/* reduce local symbols */

/*
 * In the flags1 arena, establish any options that are applicable to archive
 * extraction first, and associate a mask.  These values are recorded with any
 * archive descriptor so that they may be reset should the archive require a
 * rescan to try and resolve undefined symbols.
 */
#define	FLG_OF1_ALLEXRT	0x00000001	/* extract all members from an */
					/*	archive file */
#define	FLG_OF1_WEAKEXT	0x00000002	/* allow archive extraction to */
					/*	resolve weak references */
#define	MSK_OF1_ARCHIVE	0x00000003	/* archive flags mask */

#define	FLG_OF1_NOINTRP	0x00000008	/* -z nointerp flag set */
#define	FLG_OF1_ZDIRECT	0x00000010	/* -z direct flag set */
#define	FLG_OF1_NDIRECT	0x00000020	/* no-direct bindings specified */
#define	FLG_OF1_OVHWCAP	0x00000040	/* override any input hardware or */
#define	FLG_OF1_OVSFCAP	0x00000080	/*	software capabilities */
#define	FLG_OF1_RELDYN	0x00000100	/* process .dynamic in rel obj */

#define	FLG_OF1_IGNORE	0x00000800	/* ignore unused dependencies */

#define	FLG_OF1_TEXTOFF 0x00002000	/* text relocations are ok */
#define	FLG_OF1_ABSEXEC	0x00004000	/* -zabsexec set */
#define	FLG_OF1_LAZYLD	0x00008000	/* lazy loading of objects enabled */
#define	FLG_OF1_GRPPRM	0x00010000	/* dependencies are to have */
					/*	GROUPPERM enabled */
#define	FLG_OF1_OVRFLW	0x00020000	/* size exceeds 32-bit limitation */
					/*	of 32-bit libld */
#define	FLG_OF1_NOPARTI	0x00040000	/* -znopartial set */
#define	FLG_OF1_BSSOREL	0x00080000	/* output relocation against bss */
					/*	section */
#define	FLG_OF1_TLSOREL	0x00100000	/* output relocation against .tlsbss */
					/*	section */
#define	FLG_OF1_MEMORY	0x00200000	/* produce a memory model */
#define	FLG_OF1_RLXREL	0x00400000	/* -z relaxreloc flag set */
#define	FLG_OF1_ENCDIFF	0x00800000	/* Host running linker has different */
					/*	byte order than output object */
#define	FLG_OF1_VADDR	0x01000000	/* vaddr was explicitly set */
#define	FLG_OF1_EXTRACT	0x02000000	/* archive member has been extracted */
#define	FLG_OF1_RESCAN	0x04000000	/* any archives should be rescanned */
#define	FLG_OF1_IGNPRC	0x08000000	/* ignore processing required */
#define	FLG_OF1_NCSTTAB	0x10000000	/* -znocompstrtab set */
#define	FLG_OF1_DONE	0x20000000	/* link-editor processing complete */
#define	FLG_OF1_NONREG	0x40000000	/* non-regular file specified as */
					/*	the output file */
#define	FLG_OF1_ALNODIR	0x80000000	/* establish NODIRECT for all */
					/*	exported interfaces. */

/*
 * Test to see if the output file would allow the presence of
 * a .dynsym section.
 */
#define	OFL_ALLOW_DYNSYM(_ofl) (((_ofl)->ofl_flags & \
	(FLG_OF_DYNAMIC | FLG_OF_RELOBJ)) == FLG_OF_DYNAMIC)

/*
 * Test to see if the output file would allow the presence of
 * a .SUNW_ldynsym section. The requirements are that a .dynsym
 * is allowed, and -znoldynsym has not been specified. Note that
 * even if the answer is True (1), we will only generate one if there
 * are local symbols that require it.
 */
#define	OFL_ALLOW_LDYNSYM(_ofl) (((_ofl)->ofl_flags & \
	(FLG_OF_DYNAMIC | FLG_OF_RELOBJ | FLG_OF_NOLDYNSYM)) == FLG_OF_DYNAMIC)

/*
 * Test to see if relocation processing should be done. This is normally
 * true, but can be disabled via the '-z noreloc' option. Note that
 * relocatable objects are still relocated even if '-z noreloc' is present.
 */
#define	OFL_DO_RELOC(_ofl) (((_ofl)->ofl_flags & FLG_OF_RELOBJ) || \
	!((_ofl)->ofl_dtflags_1 & DF_1_NORELOC))

/*
 * Relocation (active & output) processing structure - transparent to common
 * code.
 *
 * Note that rel_raddend is primarily only of interest to RELA relocations,
 * and is set to 0 for REL. However, there is an exception: If FLG_REL_NADDEND
 * is set, then rel_raddend contains a replacement value for the implicit
 * addend found in the relocation target.
 */
struct rel_desc {
	Os_desc		*rel_osdesc;	/* output section reloc is against */
	Is_desc		*rel_isdesc;	/* input section reloc is against */
	const char	*rel_sname;	/* symbol name (may be "unknown") */
	Sym_desc	*rel_sym;	/* sym relocation is against */
	Sym_desc	*rel_usym;	/* strong sym if this is a weak pair */
	Mv_desc		*rel_move;	/* move table information */
	Word		rel_flags;	/* misc. flags for relocations */
	Word		rel_rtype;	/* relocation type */
	Xword		rel_roffset;	/* relocation offset */
	Sxword		rel_raddend;	/* addend from input relocation */
	Word		rel_typedata;	/* ELF_R_TYPE_DATA(info) */
};

/*
 * common flags used on the Rel_desc structure (defined in machrel.h).
 */
#define	FLG_REL_GOT	0x00000001	/* relocation against GOT */
#define	FLG_REL_PLT	0x00000002	/* relocation against PLT */
#define	FLG_REL_BSS	0x00000004	/* relocation against BSS */
#define	FLG_REL_LOAD	0x00000008	/* section loadable */
#define	FLG_REL_SCNNDX	0x00000010	/* use section index for symbol ndx */
#define	FLG_REL_CLVAL	0x00000020	/* clear VALUE for active relocation */
#define	FLG_REL_ADVAL	0x00000040	/* add VALUE for output relocation, */
					/*	only relevant to SPARC and */
					/*	R_SPARC_RELATIVE */
#define	FLG_REL_GOTCL	0x00000080	/* clear the GOT entry.  This is */
					/* relevant to RELA relocations, */
					/* not REL (i386) relocations */
#define	FLG_REL_MOVETAB	0x00000100	/* Relocation against .SUNW_move */
					/*	adjustments required before */
					/*	actual relocation */
#define	FLG_REL_NOINFO	0x00000200	/* Relocation comes from a section */
					/*	with a null sh_info field */
#define	FLG_REL_REG	0x00000400	/* Relocation target is reg sym */
#define	FLG_REL_FPTR	0x00000800	/* relocation against func. desc. */
#define	FLG_REL_RFPTR1	0x00001000	/* Relative relocation against */
					/*   1st part of FD */
#define	FLG_REL_RFPTR2	0x00002000	/* Relative relocation against */
					/*   2nd part of FD */
#define	FLG_REL_DISP	0x00004000	/* *disp* relocation */
#define	FLG_REL_STLS	0x00008000	/* IE TLS reference to */
					/*	static TLS GOT index */
#define	FLG_REL_DTLS	0x00010000	/* GD TLS reference relative to */
					/*	dynamic TLS GOT index */
#define	FLG_REL_MTLS	0x00020000	/* LD TLS reference against GOT */
#define	FLG_REL_STTLS	0x00040000	/* LE TLS reference directly */
					/*	to static tls index */
#define	FLG_REL_TLSFIX	0x00080000	/* relocation points to TLS instr. */
					/*	which needs updating */
#define	FLG_REL_RELA	0x00100000	/* descripter captures a Rela */
#define	FLG_REL_GOTFIX	0x00200000	/* relocation points to GOTOP instr. */
					/*	which needs updating */
#define	FLG_REL_NADDEND	0x00400000	/* Replace implicit addend in dest */
					/*	with value in rel_raddend */
					/*	Relevant to REL (i386) */
					/*	relocations, not to RELA. */

/*
 * Structure to hold a cache of Relocations.
 */
struct rel_cache {
	Rel_desc	*rc_end;
	Rel_desc	*rc_free;
};

/*
 * Symbol value descriptor.  For relocatable objects, each symbols value is
 * its offset within its associated section.  Therefore, to uniquely define
 * each symbol within a reloctable object, record and sort the sh_offset and
 * symbol value.  This information is used to seach for displacement
 * relocations as part of copy relocation validation.
 */
typedef struct {
	Addr		ssv_value;
	Sym_desc	*ssv_sdp;
} Ssv_desc;

/*
 * Input file processing structures.
 */
struct ifl_desc {			/* input file descriptor */
	const char	*ifl_name;	/* full file name */
	const char	*ifl_soname;	/* shared object name */
	dev_t		ifl_stdev;	/* device id and inode number for .so */
	ino_t		ifl_stino;	/*	multiple inclusion checks */
	Ehdr		*ifl_ehdr;	/* elf header describing this file */
	Elf		*ifl_elf;	/* elf descriptor for this file */
	Sym_desc	**ifl_oldndx;	/* original symbol table indices */
	Sym_desc	*ifl_locs;	/* symbol desc version of locals */
	Ssv_desc	*ifl_sortsyms;	/* sorted list of symbols by value */
	Word		ifl_locscnt;	/* no. of local symbols to process */
	Word		ifl_symscnt;	/* total no. of symbols to process */
	Word		ifl_sortcnt;	/* no. of sorted symbols to process */
	Word		ifl_shnum;	/* number of sections in file */
	Word		ifl_shstrndx;	/* index to .shstrtab */
	Word		ifl_vercnt;	/* number of versions in file */
	Is_desc		**ifl_isdesc;	/* isdesc[scn ndx] = Is_desc ptr */
	Sdf_desc	*ifl_sdfdesc;	/* control definition */
	Versym		*ifl_versym;	/* version symbol table array */
	Ver_index	*ifl_verndx;	/* verndx[ver ndx] = Ver_index */
	List		ifl_verdesc;	/* version descriptor list */
	List		ifl_relsect;	/* relocation section list */
	Alist		*ifl_groups;	/* SHT_GROUP section list */
	Half		ifl_neededndx;	/* index to NEEDED in .dyn section */
	Word		ifl_flags;	/* Explicit/implicit reference */
};

#define	FLG_IF_CMDLINE	0x00000001	/* full filename specified from the */
					/*	command line (no -l) */
#define	FLG_IF_NEEDED	0x00000002	/* shared object should be recorded */
#define	FLG_IF_DIRECT	0x00000004	/* establish direct bindings to this */
					/*	object */
#define	FLG_IF_EXTRACT	0x00000008	/* file extracted from an archive */
#define	FLG_IF_VERNEED	0x00000010	/* version dependency information is */
					/*	required */
#define	FLG_IF_DEPREQD	0x00000020	/* dependency is required to satisfy */
					/*	symbol references */
#define	FLG_IF_NEEDSTR	0x00000040	/* dependency specified by -Nn */
					/*	flag */
#define	FLG_IF_IGNORE	0x00000080	/* ignore unused dependencies */
#define	FLG_IF_NODIRECT	0x00000100	/* object contains symbols that */
					/*	cannot be directly bound to. */
#define	FLG_IF_LAZYLD	0x00000200	/* bindings to this object should be */
					/*	lazy loaded */
#define	FLG_IF_GRPPRM	0x00000400	/* this dependency should have the */
					/*	DF_P1_GROUPPERM flag set */
#define	FLG_IF_DISPPEND 0x00000800	/* displacement relocation done */
					/*	in the ld time. */
#define	FLG_IF_DISPDONE 0x00001000	/* displacement relocation done */
					/* 	at the run time */
#define	FLG_IF_MAPFILE	0x00002000	/* file is a mapfile */
#define	FLG_IF_HSTRTAB	0x00004000	/* file has a string section */
#define	FLG_IF_FILEREF	0x00008000	/* file contains a section which */
					/*	is included in the output */
					/*	allocatable image */
#define	FLG_IF_GNUVER	0x00010000	/* file used GNU-style versioning */

struct is_desc {			/* input section descriptor */
	const char	*is_name;	/* the section name */
	const char	*is_basename;	/* original section name (without */
					/*	.<sect>%<func> munging */
	Shdr		*is_shdr;	/* the elf section header */
	Ifl_desc	*is_file;	/* infile desc for this section */
	Os_desc		*is_osdesc;	/* new output section for this */
					/*	input section */
	Elf_Data	*is_indata;	/* input sections raw data */
	Is_desc		*is_symshndx;	/* related SHT_SYM_SHNDX section */
	Word		is_scnndx;	/* original section index in file */
	Word		is_txtndx;	/* Index for section.  Used to decide */
					/*	where to insert section when */
					/* 	reordering sections */
	Word		is_ident;	/* preserved IDENT used for ordered */
					/*	sections. */
	uint_t		is_namehash;	/* hash on section name */
	Half		is_key;		/* Used for SHF_ORDERED */
	Half		is_flags;	/* Various flags */
};

#define	FLG_IS_ORDERED	0x0001		/* This is a SHF_ORDERED section */
#define	FLG_IS_KEY	0x0002		/* This is a section pointed by */
					/* sh_info of a SHF_ORDERED section */
#define	FLG_IS_DISCARD	0x0004		/* section is to be discarded */
#define	FLG_IS_RELUPD	0x0008		/* symbol defined here may have moved */
#define	FLG_IS_SECTREF	0x0010		/* section has been referenced */
#define	FLG_IS_GDATADEF	0x0020		/* section contains global data sym */
#define	FLG_IS_EXTERNAL	0x0040		/* isp from an user file */
#define	FLG_IS_INSTRMRG	0x0080		/* Usable SHF_MERGE|SHF_STRINGS sec */
#define	FLG_IS_GNSTRMRG	0x0100		/* Generated mergeable string section */


/*
 * Map file and output file processing structures
 */
struct os_desc {			/* Output section descriptor */
	const char	*os_name;	/* the section name */
	Elf_Scn		*os_scn;	/* the elf section descriptor */
	Shdr		*os_shdr;	/* the elf section header */
	Os_desc		*os_relosdesc;	/* the output relocation section */
	List		os_relisdescs;	/* reloc input section descriptors */
					/*	for this output section */
	List		os_isdescs;	/* list of input sections in output */
	APlist		*os_mstrisdescs; /* FLG_IS_INSTRMRG input sections */
	Sort_desc	*os_sort;	/* used for sorting sections */
	Sg_desc		*os_sgdesc;	/* segment os_desc is placed on */
	Elf_Data	*os_outdata;	/* output sections raw data */
	List		os_comdats;	/* list of COMDAT sections present */
					/*	in current output section */
	Word		os_scnsymndx;	/* index in output symtab of section */
					/*	symbol for this section */
	Word		os_txtndx;	/* Index for section.  Used to decide */
					/*	where to insert section when */
					/* 	reordering sections */
	Xword		os_szoutrels;	/* size of output relocation section */
	uint_t		os_namehash;	/* hash on section name */
	uchar_t		os_flags;	/* various flags */
};

#define	FLG_OS_ORDER_KEY	0x01	/* include a sort key section */
#define	FLG_OS_OUTREL		0x02	/* output rel against this section */
#define	FLG_OS_SECTREF		0x04	/* isps are not affected by -zignore */

/*
 * For sorting sections.
 */
struct sort_desc {
	Is_desc		**st_order;
	Word		st_ordercnt;
	Is_desc		**st_before;
	Word		st_beforecnt;
	Is_desc		**st_after;
	Word		st_aftercnt;
};

struct sg_desc {			/* output segment descriptor */
	Phdr		sg_phdr;	/* segment header for output file */
	const char	*sg_name;	/* segment name */
	Xword		sg_round;	/* data rounding required (mapfile) */
	Xword		sg_length;	/* maximum segment length; if 0 */
					/*	segment is not specified */
	APlist		*sg_osdescs;	/* list of output section descriptors */
	APlist		*sg_secorder;	/* list specifying section ordering */
					/*	for the segment */
	Half		sg_flags;
	Sym_desc	*sg_sizesym;	/* size symbol for this segment */
	Xword		sg_addralign;	/* LCM of sh_addralign */
	Elf_Scn		*sg_fscn;	/* the SCN of the first section. */
};


#define	FLG_SG_VADDR	0x0001		/* vaddr segment attribute set */
#define	FLG_SG_PADDR	0x0002		/* paddr segment attribute set */
#define	FLG_SG_LENGTH	0x0004		/* length segment attribute set */
#define	FLG_SG_ALIGN	0x0008		/* align segment attribute set */
#define	FLG_SG_ROUND	0x0010		/* round segment attribute set */
#define	FLG_SG_FLAGS	0x0020		/* flags segment attribute set */
#define	FLG_SG_TYPE	0x0040		/* type segment attribute set */
#define	FLG_SG_ORDER	0x0080		/* has ordering been turned on for */
					/* 	this segment. */
					/*	i.e. ?[O] option in mapfile */
#define	FLG_SG_NOHDR	0x0100		/* don't map ELF or phdrs into */
					/* 	this segment */
#define	FLG_SG_EMPTY	0x0200		/* an empty segment specification */
					/*	no input sections will be */
					/*	associated to this section */
#define	FLG_SG_KEY	0x0400		/* include a key section */
#define	FLG_SG_DISABLED	0x0800		/* this segment is disabled */
#define	FLG_SG_PHREQ	0x1000		/* this segment requires a program */
					/* header */

struct sec_order {
	const char	*sco_secname;	/* section name to be ordered */
	Word		sco_index;	/* ordering index for section */
	Half		sco_flags;
};

#define	FLG_SGO_USED	0x0001		/* was ordering used? */

struct ent_desc {			/* input section entrance criteria */
	List		ec_files;	/* files from which to accept */
					/*	sections */
	const char	*ec_name;	/* name to match (NULL if none) */
	Word		ec_type;	/* section type */
	Word		ec_attrmask;	/* section attribute mask (AWX) */
	Word		ec_attrbits;	/* sections attribute bits */
	Sg_desc		*ec_segment;	/* output segment to enter if matched */
	Word		ec_ndx;		/* index to determine where section */
					/*	meeting this criteria should */
					/*	inserted. Used for reordering */
					/*	of sections. */
	Half		ec_flags;
};

#define	FLG_EC_USED	0x0001		/* entrance criteria met? */

/*
 *  Move supplementary structures
 *	Sorted by symbol local/global and then by name.
 */
typedef struct psym_info {
	Sym_desc	*psym_symd;	/* partially initialized symbol */
	Word 		psym_num;	/* number of move entires */
	Half 		psym_flag;	/* various flag */
	List 		psym_mvs;	/* the list of move entries */
} Psym_info;

#define	FLG_PSYM_OVERLAP	0x01	/* Overlapping */

/*
 * One structure is allocated for a move entry.
 */
typedef struct mv_itm {
	Xword		mv_start;	/* start position */
	Xword		mv_length;	/* The length of initialization */
	Half		mv_flag;	/* various flags */
	Is_desc		*mv_isp;	/* input desc. this entry is from */
	Move		*mv_ientry;	/* Input Move_entry */
	Word 		mv_oidx;	/* Output Move_entry index */
} Mv_itm;

#define	FLG_MV_OUTSECT	0x01	/* Will be in move section */

/*
 * Define a move descripter used within relocation structures.
 */
struct mv_desc {
	Move		*mvd_move;
	Sym_desc	*mvd_sym;
};

struct sym_desc {
	List		sd_GOTndxs;	/* list of associated GOT entries */
	Sym		*sd_sym;	/* pointer to symbol table entry */
	Sym		*sd_osym;	/* copy of the original symbol entry */
					/*	used only for local partial */
	Psym_info	*sd_psyminfo;	/* for partial symbols, maintain a */
					/*	pointer to parsym_info */
	const char	*sd_name;	/* symbols name */
	Ifl_desc	*sd_file;	/* file where symbol is taken */
	Is_desc		*sd_isc;	/* input section of symbol definition */
	Sym_aux		*sd_aux;	/* auxiliary global symbol info. */
	Word		sd_symndx;	/* index in output symbol table */
	Word		sd_shndx;	/* sect. index sym is associated w/ */
	Word		sd_flags;	/* state flags */
	Half		sd_flags1;	/* more symbol flags */
	Half		sd_ref;		/* reference definition of symbol */
};

/*
 * The auxiliary symbol descriptor contains the additional information (beyond
 * the symbol descriptor) required to process global symbols.  These symbols are
 * accessed via an internal symbol hash table where locality of reference is
 * important for performance.
 */
struct sym_aux {
	List 		sa_dfiles;	/* files where symbol is defined */
	Sym		sa_sym;		/* copy of symtab entry */
	const char	*sa_vfile;	/* first unavailable definition */
	Ifl_desc	*sa_bindto;	/* symbol to bind to - for translator */
	const char	*sa_rfile;	/* file with first symbol referenced */
	Word		sa_hash;	/* the pure hash value of symbol */
	Word		sa_PLTndx;	/* index into PLT for symbol */
	Word		sa_PLTGOTndx;	/* GOT entry indx for PLT indirection */
	Word		sa_linkndx;	/* index of associated symbol from */
					/*	ET_DYN file */
	Half		sa_symspec;	/* special symbol ids */
	Half		sa_overndx;	/* output file versioning index */
	Half		sa_dverndx;	/* dependency versioning index */
};


/*
 * Nodes used to track symbols in the global AVL symbol dictionary.
 */
struct sym_avlnode {
	avl_node_t	sav_node;	/* AVL node */
	Word		sav_hash;	/* symbol hash value */
	const char	*sav_name;	/* symbol name */
	Sym_desc	*sav_symdesc;	/* SymDesc entry */
};

/*
 * These are the ids for processing of `Special symbols'.  They are used
 * to set the sym->sd_aux->sa_symspec field.
 */
#define	SDAUX_ID_ETEXT	1		/* etext && _etext symbol */
#define	SDAUX_ID_EDATA	2		/* edata && _edata symbol */
#define	SDAUX_ID_END	3		/* end, _end, && _END_ symbol */
#define	SDAUX_ID_DYN	4		/* DYNAMIC && _DYNAMIC symbol */
#define	SDAUX_ID_PLT	5		/* _PROCEDURE_LINKAGE_TABLE_ symbol */
#define	SDAUX_ID_GOT	6		/* _GLOBAL_OFFSET_TABLE_ symbol */
#define	SDAUX_ID_START	7		/* START_ && _START_ symbol */

/*
 * Flags for sym_desc.sd_flags
 */
#define	FLG_SY_MVTOCOMM	0x00000001	/* assign symbol to common (.bss) */
					/*	this is a result of a */
					/*	copy reloc against sym */
#define	FLG_SY_GLOBREF	0x00000002	/* a global reference has been seen */
#define	FLG_SY_WEAKDEF	0x00000004	/* a weak definition has been used */
#define	FLG_SY_CLEAN	0x00000008	/* `Sym' entry points to original */
					/*	input file (read-only). */
#define	FLG_SY_UPREQD	0x00000010	/* symbol value update is required, */
					/*	either it's used as an entry */
					/*	point or for relocation, but */
					/*	it must be updated even if */
					/*	the -s flag is in effect */
#define	FLG_SY_NOTAVAIL	0x00000020	/* symbol is not available to the */
					/*	application either because it */
					/*	originates from an implicitly */
					/* 	referenced shared object, or */
					/*	because it is not part of a */
					/*	specified version. */
#define	FLG_SY_REDUCED	0x00000040	/* a global is reduced to local */
#define	FLG_SY_VERSPROM	0x00000080	/* version definition has been */
					/*	promoted to output file */
#define	FLG_SY_PROT	0x00000100	/* stv_protected visibility seen */

#define	FLG_SY_MAPREF	0x00000200	/* symbol reference generated by user */
					/*	from mapfile */
#define	FLG_SY_REFRSD	0x00000400	/* symbols sd_ref has been raised */
					/* 	due to a copy-relocs */
					/*	weak-strong pairing */
#define	FLG_SY_INTPOSE	0x00000800	/* symbol defines an interposer */
#define	FLG_SY_INVALID	0x00001000	/* unwanted/erroneous symbol */
#define	FLG_SY_SMGOT	0x00002000	/* small got index assigned to symbol */
					/*	sparc only */
#define	FLG_SY_PARENT	0x00004000	/* symbol to be found in parent */
					/*    only used with direct bindings */
#define	FLG_SY_LAZYLD	0x00008000	/* symbol to cause lazyloading of */
					/*	parent object */
#define	FLG_SY_ISDISC	0x00010000	/* symbol is a member of a DISCARDED */
					/*	section (COMDAT) */
#define	FLG_SY_PAREXPN	0x00020000	/* partially init. symbol to be */
					/*	expanded */
#define	FLG_SY_PLTPAD	0x00040000	/* pltpadding has been allocated for */
					/*	this symbol */
#define	FLG_SY_REGSYM	0x00080000	/* REGISTER symbol (sparc only) */
#define	FLG_SY_SOFOUND	0x00100000	/* compared against an SO definition */
#define	FLG_SY_EXTERN	0x00200000	/* symbol is external, allows -zdefs */
					/*    error suppression */
#define	FLG_SY_MAPUSED	0x00400000	/* mapfile symbol used (occurred */
					/*    within a relocatable object) */
#define	FLG_SY_COMMEXP	0x00800000	/* COMMON symbol which has been */
					/*	allocated */
#define	FLG_SY_CMDREF	0x01000000	/* symbol was referenced from the */
					/*	command line.  (ld -u <>, */
					/*	ld -zrtldinfo=<>, ...) */
#define	FLG_SY_SPECSEC	0x02000000	/* section index is reserved value */
					/*	ABS, COMMON, ... */
#define	FLG_SY_TENTSYM	0x04000000	/* tentative symbol */
#define	FLG_SY_VISIBLE	0x08000000	/* symbols visibility determined */
#define	FLG_SY_STDFLTR	0x10000000	/* symbol is a standard filter */
#define	FLG_SY_AUXFLTR	0x20000000	/* symbol is an auxiliary filter */
#define	FLG_SY_DYNSORT	0x40000000	/* req. in dyn[sym|tls]sort section */
#define	FLG_SY_NODYNSORT 0x80000000	/* excluded from dyn[sym_tls]sort sec */

/*
 * Sym_desc.sd_flags1
 */
#define	FLG_SY1_DEFAULT	0x00000001	/* global symbol, default */
#define	FLG_SY1_SINGLE	0x00000002	/* global symbol, singleton defined */
#define	FLG_SY1_PROTECT	0x00000004	/* global symbol, protected defined */
#define	FLG_SY1_EXPORT	0x00000008	/* global symbol, exported defined */

#define	MSK_SY1_GLOBAL \
	(FLG_SY1_DEFAULT | FLG_SY1_SINGLE | FLG_SY1_PROTECT | FLG_SY1_EXPORT)
					/* this mask indicates that the */
					/*    symbol has been explicitly */
					/*    defined within a mapfile */
					/*    definition, and is a candidate */
					/*    for versioning */

#define	FLG_SY1_HIDDEN	0x00000010	/* global symbol, reduce to local */
#define	FLG_SY1_ELIM	0x00000020	/* global symbol, eliminate */
#define	FLG_SY1_IGNORE	0x00000040	/* global symbol, ignored */

#define	MSK_SY1_LOCAL	(FLG_SY1_HIDDEN | FLG_SY1_ELIM | FLG_SY1_IGNORE)
					/* this mask allows all local state */
					/*    flags to be removed when the */
					/*    symbol is copy relocated */

#define	FLG_SY1_EXPDEF	0x00000100	/* symbol visibility defined */
					/*    explicitly */

#define	MSK_SY1_NOAUTO	(FLG_SY1_SINGLE | FLG_SY1_EXPORT | FLG_SY1_EXPDEF)
					/* this mask indicates that the */
					/*    symbol is not a  candidate for */
					/*    auto-reduction/elimination */

#define	FLG_SY1_MAPFILE 0x00000200	/* symbol attribute defined in a */
					/*    mapfile */
#define	FLG_SY1_DIR	0x00000400	/* global symbol, direct bindings */
#define	FLG_SY1_NDIR	0x00000800	/* global symbol, nondirect bindings */

/*
 * Create a mask for (sym.st_other & visibility) since the gABI does not yet
 * define a ELF*_ST_OTHER macro.
 */
#define	MSK_SYM_VISIBILITY	0x7

/*
 * Structure to manage the shared object definition lists.  There are two lists
 * that use this structure:
 *
 *  o	ofl_soneed; maintain the list of implicitly required dependencies
 *	(ie. shared objects needed by other shared objects).  These definitions
 *	may include RPATH's required to locate the dependencies, and any
 *	version requirements.
 *
 *  o	ofl_socntl; maintains the shared object control definitions.  These are
 *	provided by the user (via a mapfile) and are used to indicate any
 *	SONAME translations and verion control requirements.
 */
struct	sdf_desc {
	const char	*sdf_name;	/* the shared objects file name */
	const char	*sdf_soname;	/* the shared objects SONAME */
	char		*sdf_rpath;	/* library search path DT_RPATH */
	const char	*sdf_rfile;	/* referencing file for diagnostics */
	Ifl_desc	*sdf_file;	/* the final input file descriptor */
	List		sdf_vers;	/* list of versions that are required */
					/*	from this object */
	List		sdf_verneed;	/* list of VERNEEDS to create for */
					/*	this object (via SPECVERS or */
					/*	ADDVERS) */
	Word		sdf_flags;
};

#define	FLG_SDF_SONAME	0x02		/* An alternative SONAME is supplied */
#define	FLG_SDF_SELECT	0x04		/* version control selection required */
#define	FLG_SDF_VERIFY	0x08		/* version definition verification */
					/*	required */
#define	FLG_SDF_SPECVER	0x10		/* specify VERNEEDS */
#define	FLG_SDF_ADDVER	0x20		/* add VERNEED references */

/*
 * Structure to manage shared object version usage requirements.
 */
struct	sdv_desc {
	const char	*sdv_name;	/* version name */
	const char	*sdv_ref;	/* versions reference */
	Word		sdv_flags;	/* flags */
};

#define	FLG_SDV_MATCHED	0x01		/* VERDEF found and matched */

/*
 * Structures to manage versioning information.  Two versioning structures are
 * defined:
 *
 *   o	a version descriptor maintains a linked list of versions and their
 *	associated dependencies.  This is used to build the version definitions
 *	for an image being created (see map_symbol), and to determine the
 *	version dependency graph for any input files that are versioned.
 *
 *   o	a version index array contains each version of an input file that is
 *	being processed.  It informs us which versions are available for
 *	binding, and is used to generate any version dependency information.
 */
struct	ver_desc {
	const char	*vd_name;	/* version name */
	Word		vd_hash;	/* hash value of name */
	Ifl_desc	*vd_file;	/* file that defined version */
	Half		vd_ndx;		/* coordinates with symbol index */
	Half		vd_flags;	/* version information */
	List		vd_deps;	/* version dependencies */
	Ver_desc	*vd_ref;	/* dependency's first reference */
};

struct	ver_index {
	const char	*vi_name;	/* dependency version name */
	Half		vi_flags;	/* communicates availability */
	Ver_desc	*vi_desc;	/* cross reference to descriptor */
};

/*
 * Define any internal version descriptor flags ([vd|vi]_flags).  Note that the
 * first byte is reserved for user visible flags (refer VER_FLG's in link.h).
 */
#define	MSK_VER_USER	0x0f		/* mask for user visible flags */

#define	FLG_VER_AVAIL	0x10		/* version is available for binding */
#define	FLG_VER_REFER	0x20		/* version has been referenced */
#define	FLG_VER_SELECT	0x40		/* version has been selected by user */
#define	FLG_VER_CYCLIC	0x80		/* a member of cyclic dependency */


/*
 * isalist(1) descriptor - used to break an isalist string into its component
 * options.
 */
struct	isa_opt {
	char		*isa_name;	/* individual isa option name */
	size_t		isa_namesz;	/*	and associated size */
};

struct	isa_desc {
	char		*isa_list;	/* sysinfo(SI_ISALIST) list */
	size_t		isa_listsz;	/*	and associated size */
	Isa_opt		*isa_opt;	/* table of individual isa options */
	size_t		isa_optno;	/*	and associated number */
};

/*
 * uname(2) descriptor - used to break a utsname structure into its component
 * options (at least those that we're interested in).
 */
struct	uts_desc {
	char		*uts_osname;	/* operating system name */
	size_t		uts_osnamesz;	/*	and associated size */
	char		*uts_osrel;	/* operating system release */
	size_t		uts_osrelsz;	/*	and associated size */
};


/*
 * SHT_GROUP descriptor - used to track group sections at the global
 * level to resolve conflicts/determine which to keep.
 */
struct group_desc {
	const char	*gd_gsectname;	/* group section name */
	const char	*gd_symname;	/* symbol name */
	Word		*gd_data;	/* data for group section */
	size_t		gd_scnndx;	/* group section index */
	size_t		gd_cnt;		/* number of entries in group data */
	Word		gd_flags;
};

#define	GRP_FLG_DISCARD	0x0001		/* group is to be discarded */

/*
 * Indexes into the ld_support_funcs[] table.
 */
typedef enum {
	LDS_VERSION = 0,
	LDS_INPUT_DONE,
	LDS_START,
	LDS_ATEXIT,
	LDS_OPEN,
	LDS_FILE,
	LDS_INSEC,
	LDS_SEC,
	LDS_NUM
} Support_ndx;


/*
 * Structure to manage archive member caching.  Each archive has an archive
 * descriptor (Ar_desc) associated with it.  This contains pointers to the
 * archive symbol table (obtained by elf_getarsyms(3e)) and an auxiliary
 * structure (Ar_uax[]) that parallels this symbol table.  The member element
 * of this auxiliary table indicates whether the archive member associated with
 * the symbol offset has already been extracted (AREXTRACTED) or partially
 * processed (refer process_member()).
 */
typedef struct ar_mem {
	Elf		*am_elf;	/* elf descriptor for this member */
	char		*am_name;	/* members name */
	char		*am_path;	/* path (ie. lib(foo.o)) */
	Sym		*am_syms;	/* start of global symbols */
	char		*am_strs;	/* associated string table start */
	Xword		am_symn;	/* no. of global symbols */
} Ar_mem;

typedef struct ar_aux {
	Sym_desc	*au_syms;	/* internal symbol descriptor */
	Ar_mem		*au_mem;	/* associated member */
} Ar_aux;

#define	FLG_ARMEM_PROC	(Ar_mem *)-1

typedef struct ar_desc {
	const char	*ad_name;	/* archive file name */
	Elf		*ad_elf;	/* elf descriptor for the archive */
	Elf_Arsym	*ad_start;	/* archive symbol table start */
	Ar_aux		*ad_aux;	/* auxiliary symbol information */
	dev_t		ad_stdev;	/* device id and inode number for */
	ino_t		ad_stino;	/*	multiple inclusion checks */
	ofl_flag_t	ad_flags;	/* archive specific cmd line flags */
} Ar_desc;

/*
 * Define any archive descriptor flags.  NOTE, make sure they do not clash with
 * any output file descriptor archive extraction flags, as these are saved in
 * the same entry (see MSK_OF1_ARCHIVE).
 */
#define	FLG_ARD_EXTRACT	0x00010000	/* archive member has been extracted */

/*
 * Function Declarations.
 */
#if	defined(_ELF64)

#define	ld_create_outfile	ld64_create_outfile
#define	ld_ent_setup		ld64_ent_setup
#define	ld_init_strings		ld64_init_strings
#define	ld_init_target		ld64_init_target
#define	ld_make_sections	ld64_make_sections
#define	ld_main			ld64_main
#define	ld_ofl_cleanup		ld64_ofl_cleanup
#define	ld_process_open		ld64_process_open
#define	ld_reloc_init		ld64_reloc_init
#define	ld_reloc_process	ld64_reloc_process
#define	ld_sym_validate		ld64_sym_validate
#define	ld_update_outfile	ld64_update_outfile

#else

#define	ld_create_outfile	ld32_create_outfile
#define	ld_ent_setup		ld32_ent_setup
#define	ld_init_strings		ld32_init_strings
#define	ld_init_target		ld32_init_target
#define	ld_make_sections	ld32_make_sections
#define	ld_main			ld32_main
#define	ld_ofl_cleanup		ld32_ofl_cleanup
#define	ld_process_open		ld32_process_open
#define	ld_reloc_init		ld32_reloc_init
#define	ld_reloc_process	ld32_reloc_process
#define	ld_sym_validate		ld32_sym_validate
#define	ld_update_outfile	ld32_update_outfile

#endif

extern int		ld32_main(int, char **, Half);
extern int		ld64_main(int, char **, Half);

extern uintptr_t	ld_create_outfile(Ofl_desc *);
extern uintptr_t	ld_ent_setup(Ofl_desc *, Xword);
extern uintptr_t	ld_init_strings(Ofl_desc *);
extern int		ld_init_target(Lm_list *, Half mach);
extern uintptr_t	ld_make_sections(Ofl_desc *);
extern void		ld_ofl_cleanup(Ofl_desc *);
extern Ifl_desc		*ld_process_open(const char *, const char *, int *,
			    Ofl_desc *, Word, Rej_desc *);
extern uintptr_t	ld_reloc_init(Ofl_desc *);
extern uintptr_t	ld_reloc_process(Ofl_desc *);
extern uintptr_t	ld_sym_validate(Ofl_desc *);
extern uintptr_t	ld_update_outfile(Ofl_desc *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBLD_H */
