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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_LIBLD_H
#define	_LIBLD_H

#include <stdlib.h>
#include <libelf.h>
#include <sgs.h>
#include <_machelf.h>
#include <string_table.h>
#include <sys/avl.h>
#include <alist.h>
#include <elfcap.h>

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
 * Relocation descriptor cache
 */
struct rel_cache {
	APlist		*rc_list;	/* list of Rel_cachebuf */
	Word		rc_cnt;		/* 	and count */
};

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
	Sym_desc	*gt_sym;
	Gotndx		gt_gndx;
} Gottable;

/*
 * The link-editor caches the results of sloppy relocation processing
 * in a variable of type Rlxrel_cache. Symbols come for processing in sorted
 * order, so a single item cache suffices to eliminate duplicate lookups.
 *
 * When sloppy relocation processing fails, the Rlxrel_rej enum reports
 * the underlying reason.
 */
typedef enum {
	RLXREL_REJ_NONE = 0,	/* Replacement symbol was found */
	RLXREL_REJ_TARGET,	/* Target sec disallows relaxed relocations */
	RLXREL_REJ_SECTION,	/* Either there is no replacement section, */
				/* 	or its attributes are incompatible */
	RLXREL_REJ_SYMBOL,	/* Replacement symbol not found */
} Rlxrel_rej;

typedef struct sreloc_cache {
	Sym_desc	*sr_osdp;	/* Original symbol */
	Sym_desc	*sr_rsdp;	/* Replacement symbol */
	Rlxrel_rej	sr_rej;		/* Reason for failure if NULL sr_rsdp */
} Rlxrel_cache;

/*
 * Nodes in an ofl_wrap AVL tree
 *
 * wsn_name is the name of the symbol to be wrapped. wsn_wrapname is used
 * when we need to refer to the wrap symbol, and consists of the symbol
 * name with a __wrap_ prefix.
 */
typedef struct wrap_sym_node {
	avl_node_t	wsn_avlnode;	/* AVL book-keeping */
	const char	*wsn_name;	/* Symbol name: XXX */
	const char	*wsn_wrapname;	/* Wrap symbol name: __wrap_XXX */
} WrapSymNode;

/*
 * Capabilities structures, used to maintain a capabilities set.
 *
 * Capabilities can be defined within input relocatable objects, and can be
 * augmented or replaced by mapfile directives.  In addition, mapfile directives
 * can be used to exclude capabilities that would otherwise be carried over to
 * the output object.
 *
 * CA_SUNW_HW_1, CA_SUNW_SF_1 and CA_SUNW_HW_2 values are bitmasks.  A current
 * value, and an exclude value are maintained for each capability.
 *
 * There can be multiple CA_SUNW_PLAT and CA_SUNW_MACH entries and thus Alists
 * are used to collect these entries.  A current list for each capability is
 * maintained as Capstr entries, which provide for maintaining the strings
 * eventual index into a string table.  An exclude list is maintained as a
 * list of string pointers.
 */
typedef struct {
	elfcap_mask_t	cm_val;		/* bitmask value */
	elfcap_mask_t	cm_exc;		/* bits to exclude from final object */
} Capmask;

typedef struct {
	Alist		*cl_val;	/* string (Capstr) value */
	APlist		*cl_exc;	/* strings to exclude from final */
} Caplist;				/*	object */

typedef	struct {
	char		*cs_str;	/* platform or machine name */
	Word		cs_ndx;		/* the entries output Cap index */
} Capstr;

typedef	uint_t		oc_flag_t;
typedef	struct {
	Capmask		oc_hw_1;	/* CA_SUNW_HW_1 capabilities */
	Capmask		oc_sf_1;	/* CA_SUNW_SF_1 capabilities */
	Capmask		oc_hw_2;	/* CA_SUNW_HW_2 capabilities */
	Caplist		oc_plat;	/* CA_SUNW_PLAT capabilities */
	Caplist		oc_mach;	/* CA_SUNW_MACH capabilities */
	Capstr		oc_id;		/* CA_SUNW_ID capability */
	oc_flag_t	oc_flags;
} Objcapset;

#define	FLG_OCS_USRDEFID	0x1	/* user defined CA_SUNW_ID */

/*
 * Bitmasks for a single capability. Capabilities come from input objects,
 * augmented or replaced by mapfile directives. In addition, mapfile directives
 * can be used to exclude bits that would otherwise be set in the output object.
 */
typedef struct {
	elfcap_mask_t	cm_value;	/* Bitmask value */
	elfcap_mask_t	cm_exclude;	/* Bits to remove from final object */
} CapMask;

/*
 * Combine the bitmask in a CapMask with the exclusion mask and
 * return the resulting final value.
 */
#define	CAPMASK_VALUE(_cbmp) ((_cbmp)->cm_value & ~(_cbmp)->cm_exclude)

typedef struct {
	CapMask		c_hw_1;		/* CA_SUNW_HW_1 capabilities */
	CapMask		c_sf_1;		/* CA_SUNW_SF_1 capabilities */
	CapMask		c_hw_2;		/* CA_SUNW_HW_2 capabilities */
} Outcapset;


/*
 * Output file processing structure
 */
typedef Lword	ofl_flag_t;
typedef Word	ofl_guideflag_t;
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
	APlist		*ofl_maps;	/* list of input mapfiles */
	APlist		*ofl_segs;	/* list of segments */
	APlist		*ofl_segs_order; /* SEGMENT_ORDER segments */
	avl_tree_t	ofl_segs_avl;	/* O(log N) access to named segments */
	APlist		*ofl_ents;	/* list of entrance descriptors */
	avl_tree_t	ofl_ents_avl;	/* O(log N) access to named ent. desc */
	APlist		*ofl_objs;	/* relocatable object file list */
	Word		ofl_objscnt;	/* 	and count */
	APlist		*ofl_ars;	/* archive library list */
	Word		ofl_arscnt;	/* 	and count */
	int		ofl_ars_gsandx; /* archive group argv index. 0 means */
					/*	no current group, < 0 means */
					/*	error reported. >0 is cur ndx */
	Word		ofl_ars_gsndx;	/* current -zrescan-start ofl_ars ndx */
	APlist		*ofl_sos;	/* shared object list */
	Word		ofl_soscnt;	/* 	and count */
	APlist		*ofl_soneed;	/* list of implicitly required .so's */
	APlist		*ofl_socntl;	/* list of .so control definitions */
	Rel_cache	ofl_outrels;	/* list of output relocations */
	Rel_cache	ofl_actrels;	/* list of relocations to perform */
	APlist		*ofl_relaux;	/* Rel_aux cache for outrels/actrels */
	Word		ofl_entrelscnt;	/* no of relocations entered */
	Alist		*ofl_copyrels;	/* list of copy relocations */
	APlist		*ofl_ordered;	/* list of shf_ordered sections */
	APlist		*ofl_symdtent;	/* list of syminfo symbols that need */
					/*	to reference .dynamic entries */
	APlist		*ofl_ismove;	/* list of .SUNW_move sections */
	APlist		*ofl_ismoverel;	/* list of relocation input section */
					/* targeting to expanded area */
	APlist		*ofl_parsyms; 	/* list of partially initialized */
					/*	symbols (ie. move symbols) */
	APlist		*ofl_extrarels;	/* relocation sections which have */
					/*    a NULL sh_info */
	avl_tree_t	*ofl_groups;	/* pointer to head of Groups AVL tree */
	APlist		*ofl_initarray;	/* list of init array func names */
	APlist		*ofl_finiarray;	/* list of fini array func names */
	APlist		*ofl_preiarray;	/* list of preinit array func names */
	APlist		*ofl_rtldinfo;	/* list of rtldinfo syms */
	APlist		*ofl_osgroups;	/* list of output GROUP sections */
	APlist		*ofl_ostlsseg;	/* pointer to sections in TLS segment */
	APlist		*ofl_unwind;	/* list of unwind output sections */
	Os_desc		*ofl_unwindhdr;	/* Unwind hdr */
	avl_tree_t	ofl_symavl;	/* pointer to head of Syms AVL tree */
	Sym_desc	**ofl_regsyms;	/* array of potential register */
	Word		ofl_regsymsno;	/*    symbols and array count */
	Word		ofl_regsymcnt;	/* no. of output register symbols */
	Word		ofl_lregsymcnt;	/* no. of local register symbols */
	Sym_desc	*ofl_dtracesym;	/* ld -zdtrace= */
	ofl_flag_t	ofl_flags;	/* various state bits, args etc. */
	ofl_flag_t	ofl_flags1;	/*	more flags */
	void		*ofl_entry;	/* entry point (-e and Sym_desc *) */
	char		*ofl_filtees;	/* shared objects we are a filter for */
	const char	*ofl_soname;	/* (-h option) output file name for */
					/*	dynamic structure */
	const char	*ofl_interp;	/* interpreter name used by exec() */
	char		*ofl_rpath;	/* run path to store in .dynamic */
	char		*ofl_config;	/* config path to store in .dynamic */
	APlist		*ofl_ulibdirs;	/* user supplied library search list */
	APlist		*ofl_dlibdirs;	/* default library search list */
	Word		ofl_vercnt;	/* number of versions to generate */
	APlist		*ofl_verdesc;	/* list of version descriptors */
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
	Word		ofl_caploclcnt;	/* no. of local capabilities symbols */
	Word		ofl_capsymcnt;	/* no. of symbol capabilities entries */
					/*	required */
	Word		ofl_capchaincnt; /* no. of Capchain symbols */
	APlist		*ofl_capgroups;	/* list of capabilities groups */
	avl_tree_t	*ofl_capfamilies; /* capability family AVL tree */
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
	Is_desc		*ofl_isparexpn;	/* -z nopartial .data input section */
	Os_desc		*ofl_osdynamic;	/* .dynamic output section */
	Os_desc		*ofl_osdynsym;	/* .dynsym output section */
	Os_desc		*ofl_osldynsym;	/* .SUNW_ldynsym output section */
	Os_desc		*ofl_osdynstr;	/* .dynstr output section */
	Os_desc		*ofl_osdynsymsort; /* .SUNW_dynsymsort output section */
	Os_desc		*ofl_osdyntlssort; /* .SUNW_dyntlssort output section */
	Os_desc		*ofl_osgot;	/* .got output section */
	Os_desc		*ofl_oshash;	/* .hash output section */
	Os_desc		*ofl_osinitarray; /* .init_array output section */
	Os_desc		*ofl_osfiniarray; /* .fini_array output section */
	Os_desc		*ofl_ospreinitarray; /* .preinit_array output section */
	Os_desc		*ofl_osinterp;	/* .interp output section */
	Os_desc		*ofl_oscap;	/* .SUNW_cap output section */
	Os_desc		*ofl_oscapinfo;	/* .SUNW_capinfo output section */
	Os_desc		*ofl_oscapchain; /* .SUNW_capchain output section */
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
	Half		ofl_parexpnndx;	/* -z nopartial section index */
					/* Ref. at perform_outreloc() in */
					/* libld/{mach}/machrel.c */
	Xword		*ofl_checksum;	/* DT_CHECKSUM value address */
	char		*ofl_depaudit;	/* dependency auditing required (-P) */
	char		*ofl_audit;	/* object auditing required (-p) */
	Alist		*ofl_symfltrs;	/* per-symbol filtees and their */
	Alist		*ofl_dtsfltrs;	/*	associated .dynamic/.dynstrs */
	Objcapset	ofl_ocapset;	/* object capabilities */
	Lm_list		*ofl_lml;	/* runtime link-map list */
	Gottable	*ofl_gottable;	/* debugging got information */
	Rlxrel_cache	ofl_sr_cache;	/* Cache last result from */
					/*	sloppy_comdat_reloc() */
	APlist		*ofl_maptext;	/* mapfile added text sections */
	APlist		*ofl_mapdata;	/* mapfile added data sections */
	avl_tree_t	*ofl_wrap;	/* -z wrap symbols */
	ofl_guideflag_t	ofl_guideflags;	/* -z guide flags */
	APlist		*ofl_assdeflib;	/* -z assert-deflib exceptions */
	int		ofl_aslr;	/* -z aslr, -1 disable, 1 enable */
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
#define	FLG_OF_PURETXT	0x00000400	/* allow no text relocations: -ztext */
#define	FLG_OF_GENMAP	0x00000800	/* generate a memory map: -m */
#define	FLG_OF_DYNLIBS	0x00001000	/* dynamic input allowed: -Bdynamic */
#define	FLG_OF_SYMBOLIC	0x00002000	/* bind global symbols: -Bsymbolic */
#define	FLG_OF_ADDVERS	0x00004000	/* add version stamp: -Qy */
#define	FLG_OF_NOLDYNSYM 0x00008000	/* -znoldynsym set */
#define	FLG_OF_IS_ORDER	0x00010000	/* input section ordering within a */
					/*	segment is required */
#define	FLG_OF_EC_FILES	0x00020000	/* Ent_desc exist w/non-NULL ec_files */
#define	FLG_OF_TEXTREL	0x00040000	/* text relocations have been found */
#define	FLG_OF_MULDEFS	0x00080000	/* multiple symbols are allowed */
#define	FLG_OF_TLSPHDR	0x00100000	/* a TLS program header is required */
#define	FLG_OF_BLDGOT	0x00200000	/* build GOT table */
#define	FLG_OF_VERDEF	0x00400000	/* record version definitions */
#define	FLG_OF_VERNEED	0x00800000	/* record version dependencies */
#define	FLG_OF_NOVERSEC 0x01000000	/* don't record version sections */
#define	FLG_OF_KEY	0x02000000	/* file requires sort keys */
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
#define	FLG_OF_AUTOELM	0x002000000000	/* automatically eliminate */
					/*	unspecified global symbols */
#define	FLG_OF_REDLSYM	0x004000000000	/* reduce local symbols */
#define	FLG_OF_OS_ORDER	0x008000000000	/* output section ordering required */
#define	FLG_OF_OSABI	0x010000000000	/* tag object as ELFOSABI_SOLARIS */
#define	FLG_OF_ADJOSCNT	0x020000000000	/* adjust ofl_shdrcnt to accommodate */
					/*	discarded sections */
#define	FLG_OF_OTOSCAP	0x040000000000	/* convert object capabilities to */
					/*	symbol capabilities */
#define	FLG_OF_PTCAP	0x080000000000	/* PT_SUNWCAP required */
#define	FLG_OF_CAPSTRS	0x100000000000	/* capability strings are required */
#define	FLG_OF_EHFRAME	0x200000000000	/* output contains .eh_frame section */
#define	FLG_OF_FATWARN	0x400000000000	/* make warnings fatal */
#define	FLG_OF_ADEFLIB	0x800000000000	/* no libraries in default path */

/*
 * In the flags1 arena, establish any options that are applicable to archive
 * extraction first, and associate a mask.  These values are recorded with any
 * archive descriptor so that they may be reset should the archive require a
 * rescan to try and resolve undefined symbols.
 */
#define	FLG_OF1_ALLEXRT	0x0000000001	/* extract all members from an */
					/*	archive file */
#define	FLG_OF1_WEAKEXT	0x0000000002	/* allow archive extraction to */
					/*	resolve weak references */
#define	MSK_OF1_ARCHIVE	0x0000000003	/* archive flags mask */

#define	FLG_OF1_NOINTRP	0x0000000008	/* -z nointerp flag set */
#define	FLG_OF1_ZDIRECT	0x0000000010	/* -z direct flag set */
#define	FLG_OF1_NDIRECT	0x0000000020	/* no-direct bindings specified */
#define	FLG_OF1_DEFERRED 0x0000000040	/* deferred dependency recording */

#define	FLG_OF1_RELDYN	0x0000000100	/* process .dynamic in rel obj */
#define	FLG_OF1_NRLXREL	0x0000000200	/* -z norelaxreloc flag set */
#define	FLG_OF1_RLXREL	0x0000000400	/* -z relaxreloc flag set */
#define	FLG_OF1_IGNORE	0x0000000800	/* ignore unused dependencies */
#define	FLG_OF1_NOSGHND	0x0000001000	/* -z nosighandler flag set */
#define	FLG_OF1_TEXTOFF 0x0000002000	/* text relocations are ok */
#define	FLG_OF1_ABSEXEC	0x0000004000	/* -zabsexec set */
#define	FLG_OF1_LAZYLD	0x0000008000	/* lazy loading of objects enabled */
#define	FLG_OF1_GRPPRM	0x0000010000	/* dependencies are to have */
					/*	GROUPPERM enabled */

#define	FLG_OF1_NOPARTI	0x0000040000	/* -znopartial set */
#define	FLG_OF1_BSSOREL	0x0000080000	/* output relocation against bss */
					/*	section */
#define	FLG_OF1_TLSOREL	0x0000100000	/* output relocation against .tlsbss */
					/*	section */
#define	FLG_OF1_MEMORY	0x0000200000	/* produce a memory model */
#define	FLG_OF1_NGLBDIR	0x0000400000	/* no DT_1_DIRECT flag allowed */
#define	FLG_OF1_ENCDIFF	0x0000800000	/* host running linker has different */
					/*	byte order than output object */
#define	FLG_OF1_VADDR	0x0001000000	/* a segment defines explicit vaddr */
#define	FLG_OF1_EXTRACT	0x0002000000	/* archive member has been extracted */
#define	FLG_OF1_RESCAN	0x0004000000	/* any archives should be rescanned */
#define	FLG_OF1_IGNPRC	0x0008000000	/* ignore processing required */
#define	FLG_OF1_NCSTTAB	0x0010000000	/* -znocompstrtab set */
#define	FLG_OF1_DONE	0x0020000000	/* link-editor processing complete */
#define	FLG_OF1_NONREG	0x0040000000	/* non-regular file specified as */
					/*	the output file */
#define	FLG_OF1_ALNODIR	0x0080000000	/* establish NODIRECT for all */
					/*	exported interfaces. */
#define	FLG_OF1_OVHWCAP1 0x0100000000	/* override CA_SUNW_HW_1 capabilities */
#define	FLG_OF1_OVSFCAP1 0x0200000000	/* override CA_SUNW_SF_1 capabilities */
#define	FLG_OF1_OVHWCAP2 0x0400000000	/* override CA_SUNW_HW_2 capabilities */
#define	FLG_OF1_OVMACHCAP 0x0800000000	/* override CA_SUNW_MACH capability */
#define	FLG_OF1_OVPLATCAP 0x1000000000	/* override CA_SUNW_PLAT capability */
#define	FLG_OF1_OVIDCAP	0x2000000000	/* override CA_SUNW_ID capability */

/*
 * Guidance flags. The flags with the FLG_OFG_NO_ prefix are used to suppress
 * messages for a given category, and use the lower 28 bits of the word,
 * The upper nibble is reserved for other guidance status.
 */
#define	FLG_OFG_ENABLE		0x10000000	/* -z guidance option active */
#define	FLG_OFG_ISSUED		0x20000000	/* -z guidance message issued */

#define	FLG_OFG_NO_ALL		0x0fffffff	/* disable all guidance */
#define	FLG_OFG_NO_DEFS		0x00000001	/* specify all dependencies */
#define	FLG_OFG_NO_DB		0x00000002	/* use direct bindings */
#define	FLG_OFG_NO_LAZY		0x00000004	/* be explicit about lazyload */
#define	FLG_OFG_NO_MF		0x00000008	/* use v2 mapfile syntax */
#define	FLG_OFG_NO_TEXT		0x00000010	/* verify pure text segment */
#define	FLG_OFG_NO_UNUSED	0x00000020	/* remove unused dependency */

/*
 * Test to see if a guidance should be given for a given category
 * or not. _no_flag is one of the FLG_OFG_NO_xxx flags. Returns TRUE
 * if the guidance should be issued, and FALSE to remain silent.
 */
#define	OFL_GUIDANCE(_ofl, _no_flag) (((_ofl)->ofl_guideflags & \
	(FLG_OFG_ENABLE | (_no_flag))) == FLG_OFG_ENABLE)

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
 * Determine whether a static executable is being built.
 */
#define	OFL_IS_STATIC_EXEC(_ofl) (((_ofl)->ofl_flags & \
	(FLG_OF_STATIC | FLG_OF_EXEC)) == (FLG_OF_STATIC | FLG_OF_EXEC))

/*
 * Determine whether a static object is being built.  This macro is used
 * to select the appropriate string table, and symbol table that other
 * sections need to reference.
 */
#define	OFL_IS_STATIC_OBJ(_ofl) ((_ofl)->ofl_flags & \
	(FLG_OF_RELOBJ | FLG_OF_STATIC))

/*
 * Macros for counting symbol table entries.  These are used to size symbol
 * tables and associated sections (.syminfo, SUNW_capinfo, .hash, etc.) and
 * set required sh_info entries (the offset to the first global symbol).
 */
#define	SYMTAB_LOC_CNT(_ofl)		/* local .symtab entries */	\
	(2 +				/*    NULL and STT_FILE */	\
	(_ofl)->ofl_shdrcnt +		/*    section symbol */		\
	(_ofl)->ofl_caploclcnt +	/*    local capabilities */	\
	(_ofl)->ofl_scopecnt +		/*    scoped symbols */		\
	(_ofl)->ofl_locscnt)		/*    standard locals */
#define	SYMTAB_ALL_CNT(_ofl)		/* all .symtab entries */	\
	(SYMTAB_LOC_CNT(_ofl) +		/*    .symtab locals */		\
	(_ofl)->ofl_globcnt)		/*    standard globals */

#define	DYNSYM_LOC_CNT(_ofl)		/* local .dynsym entries */	\
	(1 +				/*    NULL */			\
	(_ofl)->ofl_dynshdrcnt +	/*    section symbols */	\
	(_ofl)->ofl_caploclcnt +	/*    local capabilities */	\
	(_ofl)->ofl_lregsymcnt)		/*    local register symbols */
#define	DYNSYM_ALL_CNT(_ofl)		/* all .dynsym entries */	\
	(DYNSYM_LOC_CNT(_ofl) +		/*    .dynsym locals */		\
	(_ofl)->ofl_globcnt)		/*    standard globals */

/*
 * Define a move descriptor used within relocation structures.
 */
typedef struct {
	Move		*mr_move;
	Sym_desc	*mr_sym;
} Mv_reloc;

/*
 * Relocation (active & output) processing structure - transparent to common
 * code. There can be millions of these structures in a large link, so it
 * is important to keep it small. You should only add new items to Rel_desc
 * if they are critical, apply to most relocations, and cannot be easily
 * computed from the other information.
 *
 * Items that can be derived should be implemented as a function that accepts
 * a Rel_desc argument, and returns the desired data. ld_reloc_sym_name() is
 * an example of this.
 *
 * Lesser used relocation data is kept in an auxiliary block, Rel_aux,
 * that is only allocated as necessary. In exchange for adding one pointer
 * of overhead to Rel_desc (rel_aux), most relocations are reduced in size
 * by the size of Rel_aux. This strategy relies on the data in Rel_aux
 * being rarely needed --- otherwise it will backfire badly.
 *
 * Note that rel_raddend is primarily only of interest to RELA relocations,
 * and is set to 0 for REL. However, there is an exception: If FLG_REL_NADDEND
 * is set, then rel_raddend contains a replacement value for the implicit
 * addend found in the relocation target.
 *
 * Fields should be ordered from largest to smallest, to minimize packing
 * holes in the struct layout.
 */
struct rel_desc {
	Is_desc		*rel_isdesc;	/* input section reloc is against */
	Sym_desc	*rel_sym;	/* sym relocation is against */
	Rel_aux		*rel_aux;	/* NULL, or auxiliary data */
	Xword		rel_roffset;	/* relocation offset */
	Sxword		rel_raddend;	/* addend from input relocation */
	Word		rel_flags;	/* misc. flags for relocations */
	Word		rel_rtype;	/* relocation type */
};

/*
 * Data that would be kept in Rel_desc if the size of that structure was
 * not an issue. This auxiliary block is only allocated as needed,
 * and must only contain rarely needed items. The goal is for the vast
 * majority of Rel_desc structs to not have an auxiliary block.
 *
 * When a Rel_desc does not have an auxiliary block, a default value
 * is assumed for each auxiliary item:
 *
 * -	ra_osdesc:
 *	Output section to which relocation applies. The default
 *	value for this is the output section associated with the
 *	input section (rel_isdesc->is_osdesc), or NULL if there
 *	is no associated input section.
 *
 * -	ra_usym:
 *	If the symbol associated with a relocation is part of a weak/strong
 *	pair, then ra_usym contains the strong symbol and rel_sym the weak.
 *	Otherwise, the default value is the same value as rel_sym.
 *
 * -	ra_move:
 *	Move table data. The default value is NULL.
 *
 * -	ra_typedata:
 *	ELF_R_TYPE_DATA(info). This value applies only to a small
 *	subset of 64-bit sparc relocations, and is otherwise 0. The
 *	default value is 0.
 *
 * If any value in Rel_aux is non-default, then an auxiliary block is
 * necessary, and each field contains its actual value. If all the auxiliary
 * values are default, no Rel_aux is needed, and the RELAUX_GET_xxx()
 * macros below are able to supply the proper default.
 *
 * To set a Rel_aux value, use the ld_reloc_set_aux_XXX() functions.
 * These functions are written to avoid unnecessary auxiliary allocations,
 * and know the rules for each item.
 */
struct rel_aux {
	Os_desc		*ra_osdesc;	/* output section reloc is against */
	Sym_desc	*ra_usym;	/* strong sym if this is a weak pair */
	Mv_reloc	*ra_move;	/* move table information */
	Word		ra_typedata;	/* ELF_R_TYPE_DATA(info) */
};

/*
 * Test a given auxiliary value to determine if it has the default value
 * for that item, as described above. If all the auxiliary items have
 * their default values, no auxiliary place is necessary to represent them.
 * If any one of them is non-default, the auxiliary block is needed.
 */
#define	RELAUX_ISDEFAULT_MOVE(_rdesc, _mv) (_mv == NULL)
#define	RELAUX_ISDEFAULT_USYM(_rdesc, _usym) ((_rdesc)->rel_sym == _usym)
#define	RELAUX_ISDEFAULT_OSDESC(_rdesc, _osdesc) \
	((((_rdesc)->rel_isdesc == NULL) && (_osdesc == NULL)) || \
	((_rdesc)->rel_isdesc && ((_rdesc)->rel_isdesc->is_osdesc == _osdesc)))
#define	RELAUX_ISDEFAULT_TYPEDATA(_rdesc, _typedata) (_typedata == 0)

/*
 * Retrieve the value of an auxiliary relocation item, preserving the illusion
 * that every relocation descriptor has an auxiliary block attached. The
 * real implementation is that an auxiliary block is only present if one or
 * more auxiliary items have non-default values. These macros return the true
 * value if an auxiliary block is present, and the default value for the
 * item otherwise.
 */
#define	RELAUX_GET_MOVE(_rdesc) \
	((_rdesc)->rel_aux ? (_rdesc)->rel_aux->ra_move : NULL)
#define	RELAUX_GET_USYM(_rdesc) \
	((_rdesc)->rel_aux ? (_rdesc)->rel_aux->ra_usym : (_rdesc)->rel_sym)
#define	RELAUX_GET_OSDESC(_rdesc) \
	((_rdesc)->rel_aux ? (_rdesc)->rel_aux->ra_osdesc : \
	((_rdesc)->rel_isdesc ? (_rdesc)->rel_isdesc->is_osdesc : NULL))
#define	RELAUX_GET_TYPEDATA(_rdesc) \
	((_rdesc)->rel_aux ? (_rdesc)->rel_aux->ra_typedata : 0)

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
#define	FLG_REL_RELA	0x00100000	/* descriptor captures a Rela */
#define	FLG_REL_GOTFIX	0x00200000	/* relocation points to GOTOP instr. */
					/*	which needs updating */
#define	FLG_REL_NADDEND	0x00400000	/* Replace implicit addend in dest */
					/*	with value in rel_raddend */
					/*	Relevant to REL (i386) */
					/*	relocations, not to RELA. */

/*
 * We often need the name of the symbol contained in a relocation descriptor
 * for diagnostic or error output. This is usually the symbol name, but
 * we substitute a constructed name in some cases. Hence, the name is
 * generated on the fly by a private function within libld. This is the
 * prototype for that function.
 */
typedef const char *(* rel_desc_sname_func_t)(Rel_desc *);

/*
 * Header for a relocation descriptor cache buffer.
 */
struct rel_cachebuf {
	Rel_desc	*rc_end;
	Rel_desc	*rc_free;
	Rel_desc	rc_arr[1];
};

/*
 * Header for a relocation auxiliary descriptor cache buffer.
 */
struct rel_aux_cachebuf {
	Rel_aux		*rac_end;
	Rel_aux		*rac_free;
	Rel_aux		rac_arr[1];
};

/*
 * Convenience macro for traversing every relocation descriptor found within
 * a given relocation cache, transparently handling the cache buffers and
 * skipping any unallocated descriptors within the buffers.
 *
 * entry:
 *	_rel_cache - Relocate descriptor cache (Rel_cache) to traverse
 *	_idx - Aliste index variable for use by the macro
 *	_rcbp - Cache buffer pointer, for use by the macro
 *	_orsp - Rel_desc pointer, which will take on the value of a different
 *		relocation descriptor in the cache in each iteration.
 *
 * The caller must not assign new values to _idx, _rcbp, or _orsp within
 * the scope of REL_CACHE_TRAVERSE.
 */
#define	REL_CACHE_TRAVERSE(_rel_cache, _idx, _rcbp, _orsp) \
	for (APLIST_TRAVERSE((_rel_cache)->rc_list, _idx, _rcbp)) \
		for (_orsp = _rcbp->rc_arr; _orsp < _rcbp->rc_free; _orsp++)

/*
 * Symbol value descriptor.  For relocatable objects, each symbols value is
 * its offset within its associated section.  Therefore, to uniquely define
 * each symbol within a relocatable object, record and sort the sh_offset and
 * symbol value.  This information is used to search for displacement
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
	Half		ifl_neededndx;	/* index to NEEDED in .dyn section */
	Word		ifl_flags;	/* explicit/implicit reference */
	Is_desc		**ifl_isdesc;	/* isdesc[scn ndx] = Is_desc ptr */
	Sdf_desc	*ifl_sdfdesc;	/* control definition */
	Versym		*ifl_versym;	/* version symbol table array */
	Ver_index	*ifl_verndx;	/* verndx[ver ndx] = Ver_index */
	APlist		*ifl_verdesc;	/* version descriptor list */
	APlist		*ifl_relsect;	/* relocation section list */
	Alist		*ifl_groups;	/* SHT_GROUP section list */
	Cap_desc	*ifl_caps;	/* capabilities descriptor */
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
					/*	cannot be directly bound to */
#define	FLG_IF_LAZYLD	0x00000200	/* dependency should be lazy loaded */
#define	FLG_IF_GRPPRM	0x00000400	/* dependency establishes a group */
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
#define	FLG_IF_ORDERED	0x00020000	/* ordered section processing */
					/*	required */
#define	FLG_IF_OTOSCAP	0x00040000	/* convert object capabilities to */
					/*	symbol capabilities */
#define	FLG_IF_DEFERRED	0x00080000	/* dependency is deferred */
#define	FLG_IF_RTLDINF	0x00100000	/* dependency has DT_SUNW_RTLTINF set */
#define	FLG_IF_GROUPS	0x00200000	/* input file has groups to process */

/*
 * Symbol states that require the generation of a DT_POSFLAG_1 .dynamic entry.
 */
#define	MSK_IF_POSFLAG1	(FLG_IF_LAZYLD | FLG_IF_GRPPRM | FLG_IF_DEFERRED)

/*
 * Symbol states that require an associated Syminfo entry.
 */
#define	MSK_IF_SYMINFO	(FLG_IF_LAZYLD | FLG_IF_DIRECT | FLG_IF_DEFERRED)


struct is_desc {			/* input section descriptor */
	const char	*is_name;	/* original section name */
	const char	*is_sym_name;	/* NULL, or name string to use for */
					/*	related STT_SECTION symbols */
	Shdr		*is_shdr;	/* the elf section header */
	Ifl_desc	*is_file;	/* infile desc for this section */
	Os_desc		*is_osdesc;	/* new output section for this */
					/*	input section */
	Elf_Data	*is_indata;	/* input sections raw data */
	Is_desc		*is_symshndx;	/* related SHT_SYM_SHNDX section */
	Is_desc		*is_comdatkeep;	/* If COMDAT section is discarded, */
					/* 	this is section that was kept */
	Word		is_scnndx;	/* original section index in file */
	Word		is_ordndx;	/* index for section.  Used to decide */
					/*	where to insert section when */
					/* 	reordering sections */
	Word		is_keyident;	/* key for SHF_{ORDERED|LINK_ORDER} */
					/*	processing and ident used for */
					/*	 placing/ordering sections */
	Word		is_flags;	/* Various flags */
};

#define	FLG_IS_ORDERED	0x0001		/* this is a SHF_ORDERED section */
#define	FLG_IS_KEY	0x0002		/* section requires sort keys */
#define	FLG_IS_DISCARD	0x0004		/* section is to be discarded */
#define	FLG_IS_RELUPD	0x0008		/* symbol defined here may have moved */
#define	FLG_IS_SECTREF	0x0010		/* section has been referenced */
#define	FLG_IS_GDATADEF	0x0020		/* section contains global data sym */
#define	FLG_IS_EXTERNAL	0x0040		/* isp from a user file */
#define	FLG_IS_INSTRMRG	0x0080		/* Usable SHF_MERGE|SHF_STRINGS sec */
#define	FLG_IS_GNSTRMRG	0x0100		/* Generated mergeable string section */

#define	FLG_IS_PLACE	0x0400		/* section requires to be placed */
#define	FLG_IS_COMDAT	0x0800		/* section is COMDAT */
#define	FLG_IS_EHFRAME	0x1000		/* section is .eh_frame */

/*
 * Output sections contain lists of input sections that are assigned to them.
 * These items fall into 4 categories:
 *	BEFORE - Ordered sections that specify SHN_BEFORE, in input order.
 *	ORDERED - Ordered sections that are sorted using unsorted sections
 *		as the sort key.
 *	DEFAULT - Sections that are placed into the output section
 *		in input order.
 *	AFTER - Ordered sections that specify SHN_AFTER, in input order.
 */
#define	OS_ISD_BEFORE	0
#define	OS_ISD_ORDERED	1
#define	OS_ISD_DEFAULT	2
#define	OS_ISD_AFTER	3
#define	OS_ISD_NUM	4
typedef APlist *os_isdecs_arr[OS_ISD_NUM];

/*
 * Convenience macro for traversing every input section associated
 * with a given output section. The primary benefit of this macro
 * is that it preserves a precious level of code indentation in the
 * code that uses it.
 */
#define	OS_ISDESCS_TRAVERSE(_list_idx, _osp, _idx, _isp) \
	for (_list_idx = 0; _list_idx < OS_ISD_NUM; _list_idx++) \
		for (APLIST_TRAVERSE(_osp->os_isdescs[_list_idx], _idx, _isp))


/*
 * Map file and output file processing structures
 */
struct os_desc {			/* Output section descriptor */
	const char	*os_name;	/* the section name */
	Elf_Scn		*os_scn;	/* the elf section descriptor */
	Shdr		*os_shdr;	/* the elf section header */
	Os_desc		*os_relosdesc;	/* the output relocation section */
	APlist		*os_relisdescs;	/* reloc input section descriptors */
					/*	for this output section */
	os_isdecs_arr	os_isdescs;	/* lists of input sections in output */
	APlist		*os_mstrisdescs; /* FLG_IS_INSTRMRG input sections */
	Sg_desc		*os_sgdesc;	/* segment os_desc is placed on */
	Elf_Data	*os_outdata;	/* output sections raw data */
	avl_tree_t	*os_comdats;	/* AVL tree of COMDAT input sections */
					/*	associated to output section */
	Word		os_identndx;	/* section identifier for input */
					/*	section processing, followed */
					/*	by section symbol index */
	Word		os_ordndx;	/* index for section.  Used to decide */
					/*	where to insert section when */
					/* 	reordering sections */
	Xword		os_szoutrels;	/* size of output relocation section */
	uint_t		os_namehash;	/* hash on section name */
	uchar_t		os_flags;	/* various flags */
};

#define	FLG_OS_KEY		0x01	/* section requires sort keys */
#define	FLG_OS_OUTREL		0x02	/* output rel against this section */
#define	FLG_OS_SECTREF		0x04	/* isps are not affected by -zignore */
#define	FLG_OS_EHFRAME		0x08	/* section is .eh_frame */

/*
 * The sg_id field of the segment descriptor is used to establish the default
 * order for program headers and segments in the output object. Segments are
 * ordered according to the following SGID values that classify them based on
 * their attributes. The initial set of built in segments are in this order,
 * and new mapfile defined segments are inserted into these groups. Within a
 * given SGID group, the position of new segments depends on the syntax
 * version of the mapfile that creates them. Version 1 (original sysv)
 * mapfiles place the new segment at the head of their group (reverse creation
 * order). The newer syntax places them at the end, following the others
 * (creation order).
 *
 * Note that any new segments must always be added after PT_PHDR and
 * PT_INTERP (refer Generic ABI, Page 5-4).
 */
#define	SGID_PHDR	0	/* PT_PHDR */
#define	SGID_INTERP	1	/* PT_INTERP */
#define	SGID_SUNWCAP	2	/* PT_SUNWCAP */
#define	SGID_TEXT	3	/* PT_LOAD */
#define	SGID_DATA	4	/* PT_LOAD */
#define	SGID_BSS	5	/* PT_LOAD */
#if	defined(_ELF64)
#define	SGID_LRODATA	6	/* PT_LOAD (amd64-only) */
#define	SGID_LDATA	7	/* PT_LOAD (amd64-only) */
#endif
#define	SGID_TEXT_EMPTY	8	/* PT_LOAD, reserved (?E in version 1 syntax) */
#define	SGID_NULL_EMPTY	9	/* PT_NULL, reserved (?E in version 1 syntax) */
#define	SGID_DYN	10	/* PT_DYNAMIC */
#define	SGID_DTRACE	11	/* PT_SUNWDTRACE */
#define	SGID_TLS	12	/* PT_TLS */
#define	SGID_UNWIND	13	/* PT_SUNW_UNWIND */
#define	SGID_SUNWSTACK	14	/* PT_SUNWSTACK */
#define	SGID_NOTE	15	/* PT_NOTE */
#define	SGID_NULL	16	/* PT_NULL,  mapfile defined empty phdr slots */
				/*	for use by post processors */
#define	SGID_EXTRA	17	/* PT_NULL (final catchall) */

typedef Half sg_flags_t;
struct sg_desc {			/* output segment descriptor */
	Word		sg_id;		/* segment identifier (for sorting) */
	Phdr		sg_phdr;	/* segment header for output file */
	const char	*sg_name;	/* segment name for PT_LOAD, PT_NOTE, */
					/*	and PT_NULL, otherwise NULL */
	Xword		sg_round;	/* data rounding required (mapfile) */
	Xword		sg_length;	/* maximum segment length; if 0 */
					/*	segment is not specified */
	APlist		*sg_osdescs;	/* list of output section descriptors */
	APlist		*sg_is_order;	/* list of entry criteria */
					/*	giving input section order */
	Alist		*sg_os_order;	/* list specifying output section */
					/*	ordering for the segment */
	sg_flags_t	sg_flags;
	APlist		*sg_sizesym;	/* size symbols for this segment */
	Xword		sg_align;	/* LCM of sh_addralign */
	Elf_Scn		*sg_fscn;	/* the SCN of the first section. */
	avl_node_t	sg_avlnode;	/* AVL book-keeping */
};

#define	FLG_SG_P_VADDR		0x0001	/* p_vaddr segment attribute set */
#define	FLG_SG_P_PADDR		0x0002	/* p_paddr segment attribute set */
#define	FLG_SG_LENGTH		0x0004	/* length segment attribute set */
#define	FLG_SG_P_ALIGN		0x0008	/* p_align segment attribute set */
#define	FLG_SG_ROUND		0x0010	/* round segment attribute set */
#define	FLG_SG_P_FLAGS		0x0020	/* p_flags segment attribute set */
#define	FLG_SG_P_TYPE		0x0040	/* p_type segment attribute set */
#define	FLG_SG_IS_ORDER		0x0080	/* input section ordering is required */
					/* 	for this segment. */
#define	FLG_SG_NOHDR		0x0100	/* don't map ELF or phdrs into */
					/*	this segment */
#define	FLG_SG_EMPTY		0x0200	/* an empty segment specification */
					/*	no input sections will be */
					/*	associated to this section */
#define	FLG_SG_KEY		0x0400	/* segment requires sort keys */
#define	FLG_SG_NODISABLE	0x0800	/* FLG_SG_DISABLED is not allowed on */
					/*	this segment */
#define	FLG_SG_DISABLED		0x1000	/* this segment is disabled */
#define	FLG_SG_PHREQ		0x2000	/* this segment requires a program */
					/* header */
#define	FLG_SG_ORDERED		0x4000	/* SEGMENT_ORDER segment */

struct sec_order {
	const char	*sco_secname;	/* section name to be ordered */
	Half		sco_flags;
};

#define	FLG_SGO_USED	0x0001		/* was ordering used? */

typedef Half ec_flags_t;
struct ent_desc {			/* input section entrance criteria */
	const char	*ec_name;	/* entrace criteria name, or NULL */
	Alist		*ec_files;	/* files from which to accept */
					/*	sections */
	const char	*ec_is_name;	/* input section name to match */
					/*	(NULL if none) */
	Word		ec_type;	/* section type */
	Word		ec_attrmask;	/* section attribute mask (AWX) */
	Word		ec_attrbits;	/* sections attribute bits */
	Sg_desc		*ec_segment;	/* output segment to enter if matched */
	Word		ec_ordndx;	/* index to determine where section */
					/*	meeting this criteria should */
					/*	inserted. Used for reordering */
					/*	of sections. */
	ec_flags_t	ec_flags;
	avl_node_t	ec_avlnode;	/* AVL book-keeping */
};

#define	FLG_EC_BUILTIN	0x0001		/* built in descriptor */
#define	FLG_EC_USED	0x0002		/* entrance criteria met? */
#define	FLG_EC_CATCHALL	0x0004		/* Catches any section */

/*
 * Ent_desc_file is the type of element maintained in the ec_files Alist
 * of an entrance criteria descriptor. Each item maintains one file
 * path, and a set of flags that specify the type of comparison it implies,
 * and other information about it. The comparison type is maintained in
 * the bottom byte of the flags.
 */
#define	TYP_ECF_MASK		0x00ff  /* Comparison type mask */
#define	TYP_ECF_PATH		0	/* Compare to file path */
#define	TYP_ECF_BASENAME	1	/* Compare to file basename */
#define	TYP_ECF_OBJNAME		2	/* Compare to regular file basename, */
					/*	 or to archive member name */
#define	TYP_ECF_NUM		3

#define	FLG_ECF_ARMEMBER	0x0100	/* name includes archive member */

typedef struct {
	Word		edf_flags;	/* Type of comparison */
	const char	*edf_name;	/* String to compare to */
	size_t		edf_name_len;	/* strlen(edf_name) */
} Ent_desc_file;

/*
 * One structure is allocated for a move entry, and associated to the symbol
 * against which a move is targeted.
 */
typedef struct {
	Move		*md_move;	/* original Move entry */
	Xword		md_start;	/* start position */
	Xword		md_len;		/* length of initialization */
	Word 		md_oidx;	/* output Move entry index */
} Mv_desc;

/*
 * Symbol descriptor.
 */
typedef	Lword		sd_flag_t;
struct sym_desc {
	Alist		*sd_GOTndxs;	/* list of associated GOT entries */
	Sym		*sd_sym;	/* pointer to symbol table entry */
	Sym		*sd_osym;	/* copy of the original symbol entry */
					/*	used only for local partial */
	Alist		*sd_move;	/* move information associated with a */
					/*	partially initialized symbol */
	const char	*sd_name;	/* symbols name */
	Ifl_desc	*sd_file;	/* file where symbol is taken */
	Is_desc		*sd_isc;	/* input section of symbol definition */
	Sym_aux		*sd_aux;	/* auxiliary global symbol info. */
	Word		sd_symndx;	/* index in output symbol table */
	Word		sd_shndx;	/* sect. index sym is associated w/ */
	sd_flag_t	sd_flags;	/* state flags */
	Half		sd_ref;		/* reference definition of symbol */
};

/*
 * The auxiliary symbol descriptor contains the additional information (beyond
 * the symbol descriptor) required to process global symbols.  These symbols are
 * accessed via an internal symbol hash table where locality of reference is
 * important for performance.
 */
struct sym_aux {
	APlist 		*sa_dfiles;	/* files where symbol is defined */
	Sym		sa_sym;		/* copy of symtab entry */
	const char	*sa_vfile;	/* first unavailable definition */
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
	Sym_desc	*sav_sdp;	/* symbol descriptor */
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

#define	FLG_SY_DEFAULT	0x0000100000000	/* global symbol, default */
#define	FLG_SY_SINGLE	0x0000200000000	/* global symbol, singleton defined */
#define	FLG_SY_PROTECT	0x0000400000000	/* global symbol, protected defined */
#define	FLG_SY_EXPORT	0x0000800000000	/* global symbol, exported defined */

#define	MSK_SY_GLOBAL \
	(FLG_SY_DEFAULT | FLG_SY_SINGLE | FLG_SY_PROTECT | FLG_SY_EXPORT)
					/* this mask indicates that the */
					/*    symbol has been explicitly */
					/*    defined within a mapfile */
					/*    definition, and is a candidate */
					/*    for versioning */

#define	FLG_SY_HIDDEN	0x0001000000000	/* global symbol, reduce to local */
#define	FLG_SY_ELIM	0x0002000000000	/* global symbol, eliminate */
#define	FLG_SY_IGNORE	0x0004000000000	/* global symbol, ignored */

#define	MSK_SY_LOCAL	(FLG_SY_HIDDEN | FLG_SY_ELIM | FLG_SY_IGNORE)
					/* this mask allows all local state */
					/*    flags to be removed when the */
					/*    symbol is copy relocated */

#define	FLG_SY_EXPDEF	0x0008000000000	/* symbol visibility defined */
					/*    explicitly */

#define	MSK_SY_NOAUTO	(FLG_SY_SINGLE | FLG_SY_EXPORT | FLG_SY_EXPDEF)
					/* this mask indicates that the */
					/*    symbol is not a candidate for */
					/*    auto-reduction/elimination */

#define	FLG_SY_MAPFILE	0x0010000000000	/* symbol attribute defined in a */
					/*    mapfile */
#define	FLG_SY_DIR	0x0020000000000	/* global symbol, direct bindings */
#define	FLG_SY_NDIR	0x0040000000000	/* global symbol, nondirect bindings */
#define	FLG_SY_OVERLAP	0x0080000000000	/* move entry overlap detected */
#define	FLG_SY_CAP	0x0100000000000	/* symbol is associated with */
					/*    capabilities */
#define	FLG_SY_DEFERRED	0x0200000000000	/* symbol should not be bound to */
					/*	during BIND_NOW relocations */

/*
 * A symbol can only be truly hidden if it is not a capabilities symbol.
 */
#define	SYM_IS_HIDDEN(_sdp) \
	(((_sdp)->sd_flags & (FLG_SY_HIDDEN | FLG_SY_CAP)) == FLG_SY_HIDDEN)

/*
 * Create a mask for (sym.st_other & visibility) since the gABI does not yet
 * define a ELF*_ST_OTHER macro.
 */
#define	MSK_SYM_VISIBILITY	0x7

/*
 * Structure to manage the shared object definition lists.  There are two lists
 * that use this structure:
 *
 *  -	ofl_soneed; maintain the list of implicitly required dependencies
 *	(ie. shared objects needed by other shared objects).  These definitions
 *	may include RPATH's required to locate the dependencies, and any
 *	version requirements.
 *
 *  -	ofl_socntl; maintains the shared object control definitions.  These are
 *	provided by the user (via a mapfile) and are used to indicate any
 *	version control requirements.
 */
struct	sdf_desc {
	const char	*sdf_name;	/* the shared objects file name */
	char		*sdf_rpath;	/* library search path DT_RPATH */
	const char	*sdf_rfile;	/* referencing file for diagnostics */
	Ifl_desc	*sdf_file;	/* the final input file descriptor */
	Alist		*sdf_vers;	/* list of versions that are required */
					/*	from this object */
	Alist		*sdf_verneed;	/* list of VERNEEDS to create for */
					/*	object via mapfile ADDVERS */
	Word		sdf_flags;
};

#define	FLG_SDF_SELECT	0x01		/* version control selection required */
#define	FLG_SDF_VERIFY	0x02		/* version definition verification */
					/*	required */
#define	FLG_SDF_ADDVER	0x04		/* add VERNEED references */

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
 *   -	a version descriptor maintains a linked list of versions and their
 *	associated dependencies.  This is used to build the version definitions
 *	for an image being created (see map_symbol), and to determine the
 *	version dependency graph for any input files that are versioned.
 *
 *   -	a version index array contains each version of an input file that is
 *	being processed.  It informs us which versions are available for
 *	binding, and is used to generate any version dependency information.
 */
struct	ver_desc {
	const char	*vd_name;	/* version name */
	Ifl_desc	*vd_file;	/* file that defined version */
	Word		vd_hash;	/* hash value of name */
	Half		vd_ndx;		/* coordinates with symbol index */
	Half		vd_flags;	/* version information */
	APlist		*vd_deps;	/* version dependencies */
	Ver_desc	*vd_ref;	/* dependency's first reference */
};

struct	ver_index {
	const char	*vi_name;	/* dependency version name */
	Half		vi_flags;	/* communicates availability */
	Half		vi_overndx;	/* index assigned to this version in */
					/*	output object Verneed section */
	Ver_desc	*vi_desc;	/* cross reference to descriptor */
};

/*
 * Define any internal version descriptor flags ([vd|vi]_flags).  Note that the
 * first byte is reserved for user visible flags (refer VER_FLG's in link.h).
 */
#define	MSK_VER_USER	0x0f		/* mask for user visible flags */

#define	FLG_VER_AVAIL	0x10		/* version is available for binding */
#define	FLG_VER_REFER	0x20		/* version has been referenced */
#define	FLG_VER_CYCLIC	0x40		/* a member of cyclic dependency */

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
 * level to resolve conflicts and determine which to keep.
 */
struct group_desc {
	Is_desc		*gd_isc;	/* input section descriptor */
	Is_desc		*gd_oisc;	/* overriding input section */
					/*	descriptor when discarded */
	const char	*gd_name;	/* group name (signature symbol) */
	Word		*gd_data;	/* data for group section */
	size_t		gd_cnt;		/* number of entries in group data */
};

/*
 * Indexes into the ld_support_funcs[] table.
 */
typedef enum {
	LDS_VERSION = 0,	/* Must be first and have value 0 */
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
	const char	*am_name;	/* members name */
	const char	*am_path;	/* path (ie. lib(foo.o)) */
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

/* Mapfile versions supported by libld */
#define	MFV_NONE	0	/* Not a valid version */
#define	MFV_SYSV	1	/* Original System V syntax */
#define	MFV_SOLARIS	2	/* Solaris mapfile syntax */
#define	MFV_NUM		3	/* # of mapfile versions */


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
#define	ld_process_mem		ld64_process_mem
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
#define	ld_process_mem		ld32_process_mem
#define	ld_reloc_init		ld32_reloc_init
#define	ld_reloc_process	ld32_reloc_process
#define	ld_sym_validate		ld32_sym_validate
#define	ld_update_outfile	ld32_update_outfile

#endif

extern int		ld_getopt(Lm_list *, int, int, char **);

extern int		ld32_main(int, char **, Half);
extern int		ld64_main(int, char **, Half);

extern uintptr_t	ld_create_outfile(Ofl_desc *);
extern uintptr_t	ld_ent_setup(Ofl_desc *, Xword);
extern uintptr_t	ld_init_strings(Ofl_desc *);
extern int		ld_init_target(Lm_list *, Half mach);
extern uintptr_t	ld_make_sections(Ofl_desc *);
extern void		ld_ofl_cleanup(Ofl_desc *);
extern Ifl_desc		*ld_process_mem(const char *, const char *, char *,
			    size_t, Ofl_desc *, Rej_desc *);
extern uintptr_t	ld_reloc_init(Ofl_desc *);
extern uintptr_t	ld_reloc_process(Ofl_desc *);
extern uintptr_t	ld_sym_validate(Ofl_desc *);
extern uintptr_t	ld_update_outfile(Ofl_desc *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBLD_H */
