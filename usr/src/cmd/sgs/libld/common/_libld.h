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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Local include file for ld library.
 */

#ifndef	_LIBLD_DOT_H
#define	_LIBLD_DOT_H

#include <libld.h>
#include <_libelf.h>
#include <debug.h>
#include <conv.h>
#include <msg.h>
#include <reloc_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * In order to allow for cross linking, we need to be able to build
 * libld with support for multiple targets within a single object.
 * This is done using a global variable (ld_targ) of type Target to
 * access target-specific code for the current target via indirection.
 */

/*
 * Machine information for target
 */
typedef struct {
	Half		m_mach;		/* ELF machine code for target */
	Half		m_machplus;	/* Alt ELF machine code for target */
					/*	Used for EM_SPARC32PLUS */
	Word		m_flagsplus;	/* ELF header flags used to identify */
					/*	a machplus object */
	uchar_t		m_class;	/* Target ELFCLASS */
	uchar_t		m_data;		/* Target byte order */

	Xword		m_segm_align;	/* segment alignment */
	Xword		m_segm_origin;	/* Default 1st segment origin */
	Xword		m_segm_aorigin;	/* Alternative 1st segment origin */
	Word		m_dataseg_perm;	/* data segment permission mask */
	Word		m_stack_perm;	/* ABI default stack permission mask */
	Word		m_word_align;	/* alignment to use for Word sections */
	const char	*m_def_interp;	/* Def. interpreter for dyn objects */

	/* Relocation type codes */
	Word		m_r_arrayaddr;
	Word		m_r_copy;
	Word		m_r_glob_dat;
	Word		m_r_jmp_slot;
	Word		m_r_num;
	Word		m_r_none;
	Word		m_r_relative;
	Word		m_r_register;

	/* Relocation related constants */
	Word		m_rel_dt_count;	/* Either DT_REL or DT_RELA */
	Word		m_rel_dt_ent;	/* Either DT_RELENT or DT_RELAENT */
	Word		m_rel_dt_size;	/* Either DT_RELSZ or DT_RELASZ */
	Word		m_rel_dt_type;	/* Either DT_RELCOUNT or DT_RELACOUNT */
	Word		m_rel_sht_type;	/* Either SHT_REL or SHT_RELA */

	/* GOT related constants */
	Word		m_got_entsize;
	Word		m_got_xnumber;	/* reserved # of got ents */

	/* PLT related constants */
	Word		m_plt_align;
	Word		m_plt_entsize;
	Word		m_plt_reservsz;
	Word		m_plt_shf_flags;

	/* Section type of .eh_frame/.eh_frame_hdr sections */
	Word		m_sht_unwind;

	Word		m_dt_register;
} Target_mach;


/*
 * Section identifiers, used to order sections in output object
 */
typedef struct {
	Word		id_array;
	Word		id_bss;
	Word		id_cap;
	Word		id_capinfo;
	Word		id_capchain;
	Word		id_data;
	Word		id_dynamic;
	Word		id_dynsort;
	Word		id_dynstr;
	Word		id_dynsym;
	Word		id_dynsym_ndx;
	Word		id_got;
	Word		id_gotdata;
	Word		id_hash;
	Word		id_interp;
	Word		id_lbss;
	Word		id_ldynsym;
	Word		id_note;
	Word		id_null;
	Word		id_plt;
	Word		id_rel;
	Word		id_strtab;
	Word		id_syminfo;
	Word		id_symtab;
	Word		id_symtab_ndx;
	Word		id_text;
	Word		id_tls;
	Word		id_tlsbss;
	Word		id_unknown;
	Word		id_unwind;
	Word		id_unwindhdr;
	Word		id_user;
	Word		id_version;
} Target_machid;

/*
 * Target_nullfunc supplies machine code for generating a
 *
 *	void (*)(void)
 *
 * unnamed function. Such a function can be called, and returns
 * immediately without doing any work. This is used to back FUNC
 * symbol definitions added with a mapfile.
 *
 * The machine instructions are specified as an array of bytes rather
 * than a larger integer type in order to avoid byte order issues that
 * can otherwise occur in cross linking.
 */
typedef struct {
	const uchar_t	*nf_template;	/* Array of machine inst. bytes */
	size_t		nf_size;	/* # bytes in nf_template */
} Target_nullfunc;

/*
 * Target_fill supplies machine code for fill bytes in executable output
 * sections. Normally, libelf fills the gaps caused by alignment and size
 * requirements of the constituent input sections with 0. Depending on the
 * target architecture, it may be desirable to instead fill with executable
 * NOP instructions. There are two reasons to do this:
 *
 *  -	So that .init/.fini sections will not contain unexecutable gaps
 *	that cause the executing program to trap and die.
 *
 *  -	To eliminate confusing garbage instructions between sections containing
 *	executable code when viewed with a disassembler.
 *
 * The ff_execfill function is allowed to be NULL if the underlying target
 * does not require a special fill for executable sections.
 */
typedef struct {
	_elf_execfill_func_t	*ff_execfill;
} Target_fillfunc;

/*
 * Target_machrel holds pointers to the reloc_table and machrel functions
 * for a given target machine.
 *
 * The following function pointers are allowed to be NULL, if the
 * underlying target does not require the specified operation. All
 * other functions must be supplied:
 *
 *	mr_assign_got
 *	mr_reloc_register
 *	mr_reloc_GOTOP
 *	mr_allocate_got
 */
typedef struct {
	const Rel_entry	*mr_reloc_table;

	Word		(* mr_init_rel)(Rel_desc *, Word *, void *);
	void 		(* mr_mach_eflags)(Ehdr *, Ofl_desc *);
	void		(* mr_mach_make_dynamic)(Ofl_desc *, size_t *);
	void		(* mr_mach_update_odynamic)(Ofl_desc *, Dyn **);
	Xword		(* mr_calc_plt_addr)(Sym_desc *, Ofl_desc *);
	uintptr_t	(* mr_perform_outreloc)(Rel_desc *, Ofl_desc *,
			    Boolean *);
	uintptr_t	(* mr_do_activerelocs)(Ofl_desc *);
	uintptr_t	(* mr_add_outrel)(Word, Rel_desc *, Ofl_desc *);
	uintptr_t	(* mr_reloc_register)(Rel_desc *, Is_desc *,
			    Ofl_desc *);
	uintptr_t	(* mr_reloc_local)(Rel_desc *, Ofl_desc *);
	uintptr_t	(* mr_reloc_GOTOP)(Boolean, Rel_desc *, Ofl_desc *);
	uintptr_t	(* mr_reloc_TLS)(Boolean, Rel_desc *, Ofl_desc *);
	uintptr_t	(* mr_assign_got)(Ofl_desc *, Sym_desc *);

	Gotndx		*(* mr_find_got_ndx)(Alist *, Gotref, Ofl_desc *,
			    Rel_desc *);
	Xword		(* mr_calc_got_offset)(Rel_desc *, Ofl_desc *);
	uintptr_t	(* mr_assign_got_ndx)(Alist **, Gotndx *, Gotref,
			    Ofl_desc *, Rel_desc *, Sym_desc *);
	void		(* mr_assign_plt_ndx)(Sym_desc *, Ofl_desc *);
	uintptr_t	(* mr_allocate_got)(Ofl_desc *);
	uintptr_t	(* mr_fillin_gotplt)(Ofl_desc *);
} Target_machrel;


/*
 * Target_machsym holds pointers to the machsym functions
 * for a given target machine.
 *
 * These fields are allowed to be NULL for targets that do not require
 * special handling of register symbols. Register symbols are used by
 * sparc targets. If any of these fields are non-NULL, all of them are
 * required to be present (use empty stub routines if necessary).
 */
typedef struct {
	int		(* ms_reg_check)(Sym_desc *, Sym *, const char *,
			    Ifl_desc *, Ofl_desc *);
	int		(* ms_mach_sym_typecheck)(Sym_desc *, Sym *,
			    Ifl_desc *, Ofl_desc *);
	const char	*(* ms_is_regsym)(Ofl_desc *, Ifl_desc *, Sym *,
			    const char *, int, Word, const char *, sd_flag_t *);
	Sym_desc	*(* ms_reg_find)(Sym * sym, Ofl_desc * ofl);
	int		(* ms_reg_enter)(Sym_desc *, Ofl_desc *);
} Target_machsym;

typedef struct {
	Target_mach	t_m;
	Target_machid	t_id;
	Target_nullfunc	t_nf;
	Target_fillfunc	t_ff;
	Target_machrel	t_mr;
	Target_machsym	t_ms;
} Target;

/*
 * Structure to manage the update of weak symbols from their associated alias.
 */
typedef	struct wk_desc {
	Sym		*wk_symtab;	/* the .symtab entry */
	Sym		*wk_dynsym;	/* the .dynsym entry */
	Sym_desc	*wk_weak;	/* the original weak symbol */
	Sym_desc	*wk_alias;	/* the real symbol */
} Wk_desc;

/*
 * Structure to manage the support library interfaces.
 */
typedef struct func_list {
	const char	*fl_obj;	/* name of support object */
					/*	function is from */
	void		(*fl_fptr)();	/* function pointer */
	uint_t		fl_version;	/* ld_version() level */
} Func_list;

typedef	struct support_list {
	const char	*sup_name;	/* ld_support function name */
	Alist		*sup_funcs;	/* list of support functions */
} Support_list;

/*
 * Structure to manage a sorted output relocation list.
 *
 *	rl_key1		->	pointer to needed ndx
 *	rl_key2		->	pointer to symbol relocation is against
 *	rl_key3		->	virtual offset of relocation
 */
typedef struct reloc_list {
	Sym_desc	*rl_key2;
	Xword		rl_key3;
	Rel_desc	*rl_rsp;
	Half		rl_key1;
} Reloc_list;


typedef struct sym_s_list {
	Word		sl_hval;
	Sym_desc	*sl_sdp;
} Sym_s_list;

/*
 * ld heap management structure
 */
typedef struct _ld_heap Ld_heap;
struct _ld_heap {
	Ld_heap		*lh_next;
	void		*lh_free;
	void		*lh_end;
};

#define	HEAPBLOCK	0x800000	/* default allocation block size */
#define	HEAPALIGN	0x8		/* heap blocks alignment requirement */

/*
 * Dynamic per-symbol filtee string table descriptor.  This associates filtee
 * strings that will be created in the .dynstr, with .dynamic entries.
 */
typedef struct {
	const char	*dft_str;	/* dynstr string */
	Word		dft_flag;	/* auxiliary/filtee type */
	Half		dft_ndx;	/* eventual ndx into .dynamic */
} Dfltr_desc;

/*
 * Per-symbol filtee descriptor.  This associates symbol definitions with
 * their filtees.
 */
typedef struct {
	Sym_desc	*sft_sdp;	/* symbol descriptor */
	Aliste		sft_idx;	/* index into dtstr descriptor */
} Sfltr_desc;

/*
 * Capabilities descriptor, and capabilities group descriptor, used to track
 * the symbol capabilities of any input files and the output file.
 *
 * A relocatable object input file may contain one or more symbol capabilities
 * groups.  The Cap_desc structures keep track of all unique groups that are
 * collected for the output file.  Relocatable objects that contain an object
 * capabilities group, and the -z symbolcap option is in effect, have their
 * object group translated to a symbol capabilities group.
 *
 * Individual capabilities groups are maintained with the Cap_group descriptor.
 * A group can consist of one or more capabilities definitions.  One or more
 * symbols can be associated with each group.
 *
 * For the output file, capabilities families are used to track the symbols of
 * a given family, each symbol being associated with a different group.  This
 * collection of data is used to create the final Capinfo structure, and for
 * dynamic objects, the Capchain structure.
 *
 * For example, an object may contain two capabilities groups:
 *
 *	CA_SUNW_MACH - sun4u		CA_SUNW_MACH - sun4v
 *
 * Two symbols can be associated with each group:
 *
 *	foo%sun4u			foo%sun4v
 *	bar%sun4u			bar%sun4v
 *
 * Two families are maintained, and include the generic, or lead, instance of
 * the capabilities members:
 *
 *	foo,  foo%sun4u,  foo%sun4v
 *	bar,  bar%sun4u,  bar%sun4v
 */
struct cap_desc {
	APlist		*ca_groups;	/* capabilities groups (Cap_group) */
	APlist		*ca_syms;	/* copies of symbols that are being */
					/*	translated from object to */
};					/*	symbol capabilities */

typedef struct {
	Objcapset	cg_set;		/* unpacked SHT_SUNW_cap elements */
	APlist		*cg_secs;	/* sections, and hence files, that */
					/*	use this descriptor */
	Word		cg_num;		/* number of comparable elements in */
					/*	the group */
	Word		cg_ndx;		/* final capability group index */
} Cap_group;

/*
 * A Capabilities family node, extends a symbol node, and provides for tracking
 * capabilities families.  A family is defined by its lead symbol (for example,
 * a generic, non-capabilities aware foo()), and one or more capabilities
 * members (for example, capabilities instances foo%sun4u(), foo%sun4v(), etc.).
 *
 * Each member associates a symbol with its group using a Cap_sym structure.
 */
typedef struct {
	Sym_avlnode	cn_symavlnode;
	APlist		*cn_members;
	APlist		*cn_aliases;
} Cap_avlnode;

typedef struct {
	Sym_desc	*cs_sdp;	/* capabilities symbol descriptor */
	Cap_group	*cs_group;	/* associated capabilities group */
} Cap_sym;

/*
 * Define Alist initialization sizes.
 */
#define	AL_CNT_IFL_GROUPS	20	/* ifl_groups */
#define	AL_CNT_IFL_RELSECS	6	/* ifl_relsect */

#define	AL_CNT_CAP_DESCS	4	/* symbol capabilities descriptors */
#define	AL_CNT_CAP_SYMS		20	/* capabilities symbols */
#define	AL_CNT_CAP_SECS		10	/* capabilities sections */
#define	AL_CNT_CAP_NAMES	10	/* Objcapset platform and machine */
					/*	names */
#define	AL_CNT_CAP_MEMS		10	/* capability family members */
#define	AL_CNT_CAP_PAIRS	10	/* capability symbol pairs */
#define	AL_CNT_CAP_ALIASES	2	/* capability lead symbol aliases */

#define	AL_CNT_OFL_DTSFLTRS	4	/* ofl_dtsfltrs */
#define	AL_CNT_OFL_SYMFLTRS	20	/* ofl_symfltrs */
#define	AL_CNT_OFL_MAPSECS	10	/* ofl_map{text|data} */
#define	AL_CNT_OFL_OBJS		50	/* ofl_objs */
#define	AL_CNT_OFL_LIBS		10	/* ofl_sos */
#define	AL_CNT_OFL_LIBDIRS	10	/* ofl_[ud]libdirs */
#define	AL_CNT_OFL_MAPFILES	6	/* ofl_maps */
#define	AL_CNT_OFL_ENTRANCE	10	/* ofl_ents */
#define	AL_CNT_OFL_RELS		4	/* ofl_outrels */
#define	AL_CNT_OFL_COPYRELS	10	/* ofl_copyrels */
#define	AL_CNT_OFL_ARRAYS	10	/* ofl_{init|fini|prei}array */
#define	AL_CNT_OFL_OSGROUPS	10	/* ofl_osgroups */
#define	AL_CNT_OFL_OSTLSSEG	4	/* ofl_ostlsseg */
#define	AL_CNT_OFL_ORDERED	4	/* ofl_ordered */
#define	AL_CNT_OFL_SYMINFOSYMS	50	/* ofl_syminfsyms */
#define	AL_CNT_OFL_MOVE		10	/* ofl_ismove */
#define	AL_CNT_OFL_UNWIND	1	/* ofl_unwind */
#define	AL_CNT_OFL_PARSYMS	10	/* ofl_parsyms */

#define	AL_CNT_OS_MSTRISDESCS	10	/* os_mstrisdescs */
#define	AL_CNT_OS_RELISDESCS	100	/* os_relisdescs */
#define	AL_CNT_OS_COMDATS	20	/* os_comdats */
#define	AL_CNT_OS_ISDESCS_BA	4	/* os_isdesc: BEFORE|AFTER */
#define	AL_CNT_OS_ISDESCS	60	/* os_isdesc: ORDERED|DEFAULT */

#define	AL_CNT_SG_IS_ORDER	40	/* sg_is_order */
#define	AL_CNT_SG_OSDESC	40	/* sg_osdescs */
#define	AL_CNT_SG_SECORDER	40	/* sg_secorder */
#define	AL_CNT_SG_SIZESYM	1	/* sg_sizesym */

#define	AL_CNT_SDP_GOT		1	/* sd_GOTndxs */
#define	AL_CNT_SDP_MOVE		1	/* sd_move */
#define	AL_CNT_SDP_DFILES	1	/* sa_dfiles */

#define	AL_CNT_SDF_VERSIONS	2	/* sdf_{vers|verneed} */

#define	AL_CNT_EC_FILES		1	/* ec_files */

#define	AL_CNT_VERDESCS		20	/* version desc */
#define	AL_CNT_WEAK		20	/* weak desc */
#define	AL_CNT_SUPPORT		2	/* support libraries */
#define	AL_CNT_STRMRGREL	500	/* ld_make_strmerge() reloc alist cnt */
#define	AL_CNT_STRMRGSYM	20	/* ld_make_strmerge() sym alist cnt */
#define	AL_CNT_SEGMENTS		20	/* ofl_segs */

#define	AL_CNT_ASSDEFLIB	4	/* ofl_assdeflib exceptions count */

/*
 * Return codes for {tls|got}_fixups() routines
 */
typedef enum {
	FIX_ERROR,	/* fatal error - time to punt */
	FIX_DONE,	/* relocation done - no further processing required */
	FIX_RELOC	/* do_reloc() relocation processing required */
} Fixupret;

#ifndef	FILENAME_MAX
#define	FILENAME_MAX	BUFSIZ		/* maximum length of a path name */
#endif

/*
 * We pad the end of the .dynstr section with a block of DYNSTR_EXTRA_PAD
 * bytes, and we insert DYNAMIC_EXTRA_ELTS unused items into the
 * .dynamic section (with value DT_NULL). This provides the resources needed
 * to add and/or alter string items in the .dynamic section, such as runpath.
 */
#define	DYNSTR_EXTRA_PAD	512
#define	DYNAMIC_EXTRA_ELTS	10

/*
 * Default relocation cache allocation unit. This number should be small
 * enough to not hurt memory use significantly, but large enough to avoid
 * the need for too many subsequent allocations.
 */
#define	REL_CACHEBUF_ALLOC	3000
#define	RELAUX_CACHEBUF_ALLOC	1500

/*
 * Given a symbol of a type that is allowed within a .SUNW_dynsymsort or
 * .SUNW_dyntlssort section, examine the symbol attributes to determine
 * if this particular symbol should be included or not.
 *
 * entry:
 *	The symbol must have an allowed type: Either a type verified by
 *	dynsymsort_symtype[] or STT_TLS.
 *
 *	_sdp - Pointer to symbol descriptor
 *	_sym - Pointer to symbol referenced by _sdp.
 *
 *	_sym is derivable from _sdp: _sdp->sd_sym
 *	However, most callers assign it to a local variable for efficiency,
 *	and this macro allows such a variable to be used within. If you
 *	don't have such a variable, supply _sdp->sd_sym.
 *
 * The tests used require some explanation:
 *
 *	(_sdp->sd_flags & FLG_SY_DYNSORT)
 *		Some special symbols are kept even if they don't meet the
 *		usual requirements. These symbols have the FLG_SY_DYNSORT
 *		bit set. If this bit isn't set then we look at the other
 *		attributes.
 *
 *	(((_sdp->sd_ref != REF_DYN_NEED) &&
 *		(_sdp->sd_sym->st_shndx != SHN_UNDEF))
 *	|| (_sdp->sd_flags & FLG_SY_MVTOCOMM))
 *		We do not want to include symbols that are not defined within
 *		the object we are creating. REF_DYN_NEED corresponds to those
 *		UNDEF items. However, if the symbol is the target of a copy
 *		relocation, then it effectively becomes defined within the
 *		object after all. FLG_SY_MVTOCOMM indicates a copy relocation,
 *		and prevents us from culling those exceptions.
 *
 *	(_sym->st_size != 0)
 *		Symbols with 0 length are labels injected by the compilers
 *		or the linker for purposes of code generation, and do
 *		not directly correspond to actual code. In fact, most of the
 *		symbols we mark with FLG_SY_DYNSORT need that flag set because
 *		they have size 0. This size test filters out the others.
 *
 *	!(_sdp->sd_flags & FLG_SY_NODYNSORT)
 *		Some symbols are not kept, even though they do meet the usual
 *		requirements. These symbols have FLG_SY_NODYNSORT set.
 *		For example, if there are weak and non-weak versions of a given
 *		symbol, we only want to keep one of them. So, we set
 *		FLG_SY_NODYNSORT on the one we don't want.
 */
#define	DYNSORT_TEST_ATTR(_sdp, _sym) \
	((_sdp->sd_flags & FLG_SY_DYNSORT) || \
	((((_sdp->sd_ref != REF_DYN_NEED) && \
		(_sdp->sd_sym->st_shndx != SHN_UNDEF)) || \
		(_sdp->sd_flags & FLG_SY_MVTOCOMM)) && \
	(_sym->st_size != 0) && \
	!(_sdp->sd_flags & FLG_SY_NODYNSORT)))

/*
 * We use output section descriptor counters to add up the number of
 * symbol indexes to put in the .SUNW_dynsort and .SUNW_dyntlssort sections.
 * Non-TLS symbols are counted by ofl->ofl_dynsymsortcnt, while TLS symbols are
 * counted by ofl->ofl_dyntlssortcnt. This computation is done inline in
 * several places. The DYNSORT_COUNT macro allows us to generate this from
 * a single description.
 *
 * entry:
 *	_sdp, _sym - As per DYNSORT_TEST_ATTR
 *	_type - Type of symbol (STT_*)
 *	_inc_or_dec_op - Either ++, or --. This specifies the operation
 *		to be applied to the counter, and determines whether we
 *		are adding, or removing, a symbol from .SUNW_dynsymsort.
 *
 * Note that _type is derivable from _sym: ELF_ST_TYPE(_sdp->sd_sym->st_info).
 * Most callers already have it in a variable, so this allows us to use that
 * variable. If you don't have such a variable, use ELF_ST_TYPE() as shown.
 */
#define	DYNSORT_COUNT(_sdp, _sym, _type, _inc_or_dec_op) \
{ \
	Word *_cnt_var; \
	\
	if (dynsymsort_symtype[_type]) {	/* Non-TLS counter */ \
		_cnt_var = &ofl->ofl_dynsymsortcnt; \
	} else if ((_type) == STT_TLS) {	/* TLS counter */ \
		_cnt_var = &ofl->ofl_dyntlssortcnt; \
	} else {				/* Don't count this symbol */ \
		_cnt_var = NULL; \
	} \
	if ((_cnt_var != NULL) && DYNSORT_TEST_ATTR(_sdp, _sym)) \
		(*_cnt_var)_inc_or_dec_op;	/* Increment/Decrement */ \
}

/*
 * The OFL_SWAP_RELOC macros are used to determine whether
 * relocation processing needs to swap the data being relocated.
 * It is an optimization to ld_swap_reloc_data(), as it avoids
 * the function call in the case where the linker host and the
 * target have the same byte order.
 */
#define	OFL_SWAP_RELOC_DATA(_ofl, _rel) \
	(((_ofl)->ofl_flags1 & FLG_OF1_ENCDIFF) && \
	ld_swap_reloc_data(_ofl, _rel))

/*
 * Define an AVL node for maintaining input section descriptors. AVL trees of
 * these descriptors are used to process group and COMDAT section.
 *
 * Pure COMDAT uses the input section name as the search key, while
 * SHT_GROUP sections use the name of a special signature symbol. We
 * support both by using the isd_name field to carry the name. An alternative
 * design would be to use a separate type for each use, saving the cost
 * of the unneeded pointer for pure COMDAT. We favor a single implementation
 * because we believe that SHT_GROUP comdat will be more common going forward,
 * particularly in the largest objects produced by C++ where SHT_GROUP is
 * needed to manage the complex section relationships. In contrast, we think
 * that pure COMDAT is both more rare, and used in smaller objects where the
 * cost of an extra pointer per node is relatively unimportant.
 */
typedef struct {
	avl_node_t	isd_avl;	/* avl book-keeping (see SGSOFFSETOF) */
	Is_desc		*isd_isp;	/* input section descriptor */
	const char	*isd_name;	/* name used as search key */
	uint_t		isd_hash;	/* input section name hash value */
} Isd_node;

/*
 * Type used to break down an input file path into its component parts,
 * as used by ld_place_section() to compare an input file path to
 * entrance criteria ec_files file strings.
 *
 * We define a path in the usual Unix '/' separated manner, augmented
 * with an optional archive member suffix enclosed in parenthesis:
 *
 *	/dir/.../dir/basename(armember)
 *
 * The basename is the final path component, and includes the archive
 * member, if present. The meaning of "object name" depends on whether or
 * not the file comes from an archive or not. If not an archive, it is the
 * same as the basename. If an archive, it is the name of the archive member
 * from within the file.
 *
 * Variables of this type are initialized with ld_place_path_info_init().
 */
typedef struct {
	const char	*ppi_path;	/* Full path */
	const char	*ppi_bname;	/* basename(ppi_path) */
	const char	*ppi_oname;	/* object name: Not NULL terminated */
	Boolean		ppi_isar;	/* TRUE if path has archive member */
	size_t		ppi_path_len;	/* strlen(ppi_path) */
	size_t		ppi_bname_len;	/* strlen(ppi_bname) */
	size_t		ppi_oname_len;	/* strlen(ppi_oname) */
} Place_path_info;

/*
 * Local data items.
 */
extern char		*Plibpath;
extern char		*Llibdir;
extern char		*Ulibdir;
extern Ld_heap		*ld_heap;
extern APlist		*lib_support;
extern int		demangle_flag;
extern const Msg	reject[];
extern int		Verbose;
extern const int	ldynsym_symtype[];
extern const int	dynsymsort_symtype[];

/*
 * Local functions.
 */
extern char		*add_string(char *, char *);
extern const char	*demangle(const char *);
extern int		cap_names_match(Alist *, Alist *);

extern void		lds_atexit(Ofl_desc *, int);

extern void		libld_free(void *);
extern void		*libld_malloc(size_t);
extern void		*libld_realloc(void *, size_t);

extern int		isdavl_compare(const void *, const void *);

extern Sdf_desc		*sdf_add(const char *, APlist **);
extern Sdf_desc		*sdf_find(const char *, APlist *);

#if	defined(_ELF64)

#define	ld_add_actrel		ld64_add_actrel
#define	ld_add_libdir		ld64_add_libdir
#define	ld_adj_movereloc	ld64_adj_movereloc
#define	ld_am_I_partial		ld64_am_I_partial
#define	ld_ar_member		ld64_ar_member
#define	ld_ar_setup		ld64_ar_setup
#define	ld_assign_got_TLS	ld64_assign_got_TLS
#define	ld_bswap_Word		ld64_bswap_Word
#define	ld_bswap_Xword		ld64_bswap_Xword
#define	ld_cap_add_family	ld64_cap_add_family
#define	ld_cap_move_symtoobj	ld64_cap_move_symtoobj
#define	ld_disp_errmsg		ld64_disp_errmsg
#define	ld_ent_check		ld64_ent_check
#define	ld_ent_lookup		ld64_ent_lookup
#define	ld_eprintf		ld64_eprintf
#define	ld_exit			ld64_exit
#define	ld_find_library		ld64_find_library
#define	ld_finish_libs		ld64_finish_libs
#define	ld_get_group		ld64_get_group
#define	ld_group_process	ld64_group_process
#define	ld_lib_setup		ld64_lib_setup
#define	ld_init_sighandler	ld64_init_sighandler
#define	ld_lcm			ld64_lcm
#define	ld_make_bss		ld64_make_bss
#define	ld_make_data		ld64_make_data
#define	ld_make_got		ld64_make_got
#define	ld_make_parexpn_data	ld64_make_parexpn_data
#define	ld_make_sunwmove	ld64_make_sunmove
#define	ld_make_text		ld64_make_text
#define	ld_map_out		ld64_map_out
#define	ld_map_parse		ld64_map_parse
#define	ld_map_post_process	ld64_map_post_process
#define	ld_open_outfile		ld64_open_outfile
#define	ld_os_first_isdesc	ld64_os_first_isdesc
#define	ld_place_path_info_init	ld64_place_path_info_init
#define	ld_place_section	ld64_place_section
#define	ld_process_archive	ld64_process_archive
#define	ld_process_files	ld64_process_files
#define	ld_process_flags	ld64_process_flags
#define	ld_process_ifl		ld64_process_ifl
#define	ld_process_move		ld64_process_move
#define	ld_process_open		ld64_process_open
#define	ld_process_ordered	ld64_process_ordered
#define	ld_process_sym_reloc	ld64_process_sym_reloc
#define	ld_reloc_enter		ld64_reloc_enter
#define	ld_reloc_GOT_relative	ld64_reloc_GOT_relative
#define	ld_reloc_plt		ld64_reloc_plt
#define	ld_reloc_remain_entry	ld64_reloc_remain_entry
#define	ld_reloc_set_aux_osdesc	ld64_reloc_set_aux_osdesc
#define	ld_reloc_set_aux_usym	ld64_reloc_set_aux_usym
#define	ld_reloc_sym_name	ld64_reloc_sym_name
#define	ld_reloc_targval_get	ld64_reloc_targval_get
#define	ld_reloc_targval_set	ld64_reloc_targval_set
#define	ld_sec_validate		ld64_sec_validate
#define	ld_seg_lookup		ld64_seg_lookup
#define	ld_sort_ordered		ld64_sort_ordered
#define	ld_stt_section_sym_name	ld64_stt_section_sym_name
#define	ld_sunw_ldmach		ld64_sunw_ldmach
#define	ld_sup_atexit		ld64_sup_atexit
#define	ld_sup_open		ld64_sup_open
#define	ld_sup_file		ld64_sup_file
#define	ld_sup_loadso		ld64_sup_loadso
#define	ld_sup_input_done	ld64_sup_input_done
#define	ld_sup_input_section	ld64_sup_input_section
#define	ld_sup_section		ld64_sup_section
#define	ld_sup_start		ld64_sup_start
#define	ld_swap_reloc_data	ld64_swap_reloc_data
#define	ld_sym_add_u		ld64_sym_add_u
#define	ld_sym_adjust_vis	ld64_sym_adjust_vis
#define	ld_sym_avl_comp		ld64_sym_avl_comp
#define	ld_sym_copy		ld64_sym_copy
#define	ld_sym_enter		ld64_sym_enter
#define	ld_sym_find		ld64_sym_find
#define	ld_sym_nodirect		ld64_sym_nodirect
#define	ld_sym_process		ld64_sym_process
#define	ld_sym_resolve		ld64_sym_resolve
#define	ld_sym_spec		ld64_sym_spec
#define	ld_targ			ld64_targ
#define	ld_targ_init_sparc	ld64_targ_init_sparc
#define	ld_targ_init_x86	ld64_targ_init_x86
#define	ld_unwind_make_hdr	ld64_unwind_make_hdr
#define	ld_unwind_populate_hdr	ld64_unwind_populate_hdr
#define	ld_unwind_register	ld64_unwind_register
#define	ld_vers_base		ld64_vers_base
#define	ld_vers_check_defs	ld64_vers_check_defs
#define	ld_vers_check_need	ld64_vers_check_need
#define	ld_vers_def_process	ld64_vers_def_process
#define	ld_vers_desc		ld64_vers_desc
#define	ld_vers_find		ld64_vers_find
#define	ld_vers_need_process	ld64_vers_need_process
#define	ld_vers_promote		ld64_vers_promote
#define	ld_vers_sym_process	ld64_vers_sym_process
#define	ld_vers_verify		ld64_vers_verify
#define	ld_wrap_enter		ld64_wrap_enter

#else

#define	ld_add_actrel		ld32_add_actrel
#define	ld_add_libdir		ld32_add_libdir
#define	ld_adj_movereloc	ld32_adj_movereloc
#define	ld_am_I_partial		ld32_am_I_partial
#define	ld_ar_member		ld32_ar_member
#define	ld_ar_setup		ld32_ar_setup
#define	ld_assign_got_TLS	ld32_assign_got_TLS
#define	ld_bswap_Word		ld32_bswap_Word
#define	ld_bswap_Xword		ld32_bswap_Xword
#define	ld_cap_add_family	ld32_cap_add_family
#define	ld_cap_move_symtoobj	ld32_cap_move_symtoobj
#define	ld_disp_errmsg		ld32_disp_errmsg
#define	ld_ent_check		ld32_ent_check
#define	ld_ent_lookup		ld32_ent_lookup
#define	ld_eprintf		ld32_eprintf
#define	ld_exit			ld32_exit
#define	ld_find_library		ld32_find_library
#define	ld_finish_libs		ld32_finish_libs
#define	ld_get_group		ld32_get_group
#define	ld_group_process	ld32_group_process
#define	ld_lib_setup		ld32_lib_setup
#define	ld_init_sighandler	ld32_init_sighandler
#define	ld_lcm			ld32_lcm
#define	ld_make_bss		ld32_make_bss
#define	ld_make_data		ld32_make_data
#define	ld_make_got		ld32_make_got
#define	ld_make_parexpn_data	ld32_make_parexpn_data
#define	ld_make_sunwmove	ld32_make_sunmove
#define	ld_make_text		ld32_make_text
#define	ld_map_out		ld32_map_out
#define	ld_map_parse		ld32_map_parse
#define	ld_map_post_process	ld32_map_post_process
#define	ld_open_outfile		ld32_open_outfile
#define	ld_os_first_isdesc	ld32_os_first_isdesc
#define	ld_place_path_info_init	ld32_place_path_info_init
#define	ld_place_section	ld32_place_section
#define	ld_process_archive	ld32_process_archive
#define	ld_process_files	ld32_process_files
#define	ld_process_flags	ld32_process_flags
#define	ld_process_ifl		ld32_process_ifl
#define	ld_process_move		ld32_process_move
#define	ld_process_open		ld32_process_open
#define	ld_process_ordered	ld32_process_ordered
#define	ld_process_sym_reloc	ld32_process_sym_reloc
#define	ld_reloc_enter		ld32_reloc_enter
#define	ld_reloc_GOT_relative	ld32_reloc_GOT_relative
#define	ld_reloc_plt		ld32_reloc_plt
#define	ld_reloc_remain_entry	ld32_reloc_remain_entry
#define	ld_reloc_set_aux_osdesc	ld32_reloc_set_aux_osdesc
#define	ld_reloc_set_aux_usym	ld32_reloc_set_aux_usym
#define	ld_reloc_sym_name	ld32_reloc_sym_name
#define	ld_reloc_targval_get	ld32_reloc_targval_get
#define	ld_reloc_targval_set	ld32_reloc_targval_set
#define	ld_sec_validate		ld32_sec_validate
#define	ld_seg_lookup		ld32_seg_lookup
#define	ld_sort_ordered		ld32_sort_ordered
#define	ld_stt_section_sym_name	ld32_stt_section_sym_name
#define	ld_sunw_ldmach		ld32_sunw_ldmach
#define	ld_sup_atexit		ld32_sup_atexit
#define	ld_sup_open		ld32_sup_open
#define	ld_sup_file		ld32_sup_file
#define	ld_sup_loadso		ld32_sup_loadso
#define	ld_sup_input_done	ld32_sup_input_done
#define	ld_sup_input_section	ld32_sup_input_section
#define	ld_sup_section		ld32_sup_section
#define	ld_sup_start		ld32_sup_start
#define	ld_swap_reloc_data	ld32_swap_reloc_data
#define	ld_sym_add_u		ld32_sym_add_u
#define	ld_sym_adjust_vis	ld32_sym_adjust_vis
#define	ld_sym_avl_comp		ld32_sym_avl_comp
#define	ld_sym_copy		ld32_sym_copy
#define	ld_sym_enter		ld32_sym_enter
#define	ld_sym_find		ld32_sym_find
#define	ld_sym_nodirect		ld32_sym_nodirect
#define	ld_sym_process		ld32_sym_process
#define	ld_sym_resolve		ld32_sym_resolve
#define	ld_sym_spec		ld32_sym_spec
#define	ld_targ			ld32_targ
#define	ld_targ_init_sparc	ld32_targ_init_sparc
#define	ld_targ_init_x86	ld32_targ_init_x86
#define	ld_unwind_make_hdr	ld32_unwind_make_hdr
#define	ld_unwind_populate_hdr	ld32_unwind_populate_hdr
#define	ld_unwind_register	ld32_unwind_register
#define	ld_vers_base		ld32_vers_base
#define	ld_vers_check_defs	ld32_vers_check_defs
#define	ld_vers_check_need	ld32_vers_check_need
#define	ld_vers_def_process	ld32_vers_def_process
#define	ld_vers_desc		ld32_vers_desc
#define	ld_vers_find		ld32_vers_find
#define	ld_vers_need_process	ld32_vers_need_process
#define	ld_vers_promote		ld32_vers_promote
#define	ld_vers_sym_process	ld32_vers_sym_process
#define	ld_vers_verify		ld32_vers_verify
#define	ld_wrap_enter		ld32_wrap_enter

#endif

extern void		dbg_cleanup(void);
extern int		dbg_setup(Ofl_desc *, const char *, int);

extern uintptr_t	ld_add_actrel(Word, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_add_libdir(Ofl_desc *, const char *);
extern void 		ld_adj_movereloc(Ofl_desc *, Rel_desc *);
extern Sym_desc * 	ld_am_I_partial(Rel_desc *, Xword);
extern void		ld_ar_member(Ar_desc *, Elf_Arsym *, Ar_aux *,
			    Ar_mem *);
extern Ar_desc		*ld_ar_setup(const char *, Elf *, Ofl_desc *);
extern uintptr_t	ld_assign_got_TLS(Boolean, Rel_desc *, Ofl_desc *,
			    Sym_desc *, Gotndx *, Gotref, Word, Word,
			    Word, Word);

extern Word		ld_bswap_Word(Word);
extern Xword		ld_bswap_Xword(Xword);

extern uintptr_t	ld_cap_add_family(Ofl_desc *, Sym_desc *, Sym_desc *,
			    Cap_group *, APlist **);
extern void		ld_cap_move_symtoobj(Ofl_desc *);

extern void		ld_disp_errmsg(const char *, Rel_desc *, Ofl_desc *);

extern void		ld_ent_check(Ofl_desc *);
extern Ent_desc		*ld_ent_lookup(Ofl_desc *, const char *name,
			    avl_index_t *where);
extern void		ld_eprintf(Ofl_desc *, Error, const char *, ...);
extern int		ld_exit(Ofl_desc *);

extern uintptr_t	ld_find_library(const char *, Ofl_desc *);
extern uintptr_t	ld_finish_libs(Ofl_desc *);

extern const char	*ld_stt_section_sym_name(Is_desc *);

extern Group_desc	*ld_get_group(Ofl_desc *, Is_desc *);
extern uintptr_t	ld_group_process(Is_desc *, Ofl_desc *);

extern uintptr_t	ld_lib_setup(Ofl_desc *);

extern void		ld_init_sighandler(Ofl_desc *);

extern Xword		ld_lcm(Xword, Xword);

extern uintptr_t	ld_make_bss(Ofl_desc *, Xword, Xword, uint_t);
extern Is_desc		*ld_make_data(Ofl_desc *, size_t);
extern uintptr_t	ld_make_got(Ofl_desc *);
extern uintptr_t	ld_make_parexpn_data(Ofl_desc *, size_t, Xword);
extern uintptr_t	ld_make_sunwmove(Ofl_desc *, int);
extern Is_desc		*ld_make_text(Ofl_desc *, size_t);
extern void		ld_map_out(Ofl_desc *);
extern Boolean		ld_map_parse(const char *, Ofl_desc *);
extern Boolean		ld_map_post_process(Ofl_desc *);

extern uintptr_t	ld_open_outfile(Ofl_desc *);

extern Is_desc		*ld_os_first_isdesc(Os_desc *);
extern Place_path_info	*ld_place_path_info_init(Ofl_desc *, Ifl_desc *,
			    Place_path_info *);
extern Os_desc		*ld_place_section(Ofl_desc *, Is_desc *,
			    Place_path_info *path_info,  int, const char *);
extern Boolean		ld_process_archive(const char *, int, Ar_desc *,
			    Ofl_desc *);
extern uintptr_t	ld_process_files(Ofl_desc *, int, char **);
extern uintptr_t	ld_process_flags(Ofl_desc *, int, char **);
extern uintptr_t	ld_process_ifl(const char *, const char *, int, Elf *,
			    Word, Ofl_desc *, Rej_desc *, Ifl_desc **);
extern uintptr_t	ld_process_move(Ofl_desc *);
extern uintptr_t	ld_process_open(const char *, const char *, int *,
			    Ofl_desc *, Word, Rej_desc *, Ifl_desc **);
extern uintptr_t	ld_process_ordered(Ofl_desc *, Ifl_desc *,
			    Place_path_info *path_info,  Word);
extern uintptr_t	ld_process_sym_reloc(Ofl_desc *, Rel_desc *, Rel *,
			    Is_desc *, const char *, Word);

extern Rel_desc		*ld_reloc_enter(Ofl_desc *, Rel_cache *, Rel_desc *,
			    Word);
extern uintptr_t	ld_reloc_GOT_relative(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_reloc_plt(Rel_desc *, Ofl_desc *);
extern void		ld_reloc_remain_entry(Rel_desc *, Os_desc *,
			    Ofl_desc *, Boolean *);
extern Boolean		ld_reloc_set_aux_osdesc(Ofl_desc *, Rel_desc *,
			    Os_desc *);
extern Boolean		ld_reloc_set_aux_usym(Ofl_desc *, Rel_desc *,
			    Sym_desc *);

extern const char	*ld_reloc_sym_name(Rel_desc *);
extern int		ld_reloc_targval_get(Ofl_desc *, Rel_desc *,
			    uchar_t *, Xword *);
extern int		ld_reloc_targval_set(Ofl_desc *, Rel_desc *,
			    uchar_t *, Xword);

extern Sg_desc		*ld_seg_lookup(Ofl_desc *, const char *,
			    avl_index_t *where);
extern void		ld_sec_validate(Ofl_desc *);
extern uintptr_t	ld_sort_ordered(Ofl_desc *);
extern Half		ld_sunw_ldmach();
extern void		ld_sup_atexit(Ofl_desc *, int);
extern void		ld_sup_open(Ofl_desc *, const char **, const char **,
			    int *, int, Elf **, Elf *ref, size_t,
			    const Elf_Kind);
extern void		ld_sup_file(Ofl_desc *, const char *, const Elf_Kind,
			    int flags, Elf *);
extern uintptr_t	ld_sup_loadso(Ofl_desc *, const char *);
extern void		ld_sup_input_done(Ofl_desc *);
extern void		ld_sup_section(Ofl_desc *, const char *, Shdr *, Word,
			    Elf_Data *, Elf *);
extern uintptr_t	ld_sup_input_section(Ofl_desc*, Ifl_desc *,
			    const char *, Shdr **, Word, Elf_Scn *, Elf *);
extern void		ld_sup_start(Ofl_desc *, const Half, const char *);
extern int		ld_swap_reloc_data(Ofl_desc *, Rel_desc *);
extern Sym_desc		*ld_sym_add_u(const char *, Ofl_desc *, Msg);
extern void		ld_sym_adjust_vis(Sym_desc *, Ofl_desc *);
extern int		ld_sym_avl_comp(const void *, const void *);
extern uintptr_t	ld_sym_copy(Sym_desc *);
extern Sym_desc		*ld_sym_enter(const char *, Sym *, Word, Ifl_desc *,
			    Ofl_desc *, Word, Word, sd_flag_t, avl_index_t *);
extern Sym_desc		*ld_sym_find(const char *, Word, avl_index_t *,
			    Ofl_desc *);
extern uintptr_t	ld_sym_nodirect(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	ld_sym_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	ld_sym_resolve(Sym_desc *, Sym *, Ifl_desc *,
			    Ofl_desc *, int, Word, sd_flag_t);
extern uintptr_t	ld_sym_spec(Ofl_desc *);

extern Target		ld_targ;
extern const Target	*ld_targ_init_sparc(void);
extern const Target	*ld_targ_init_x86(void);

extern uintptr_t	ld_unwind_make_hdr(Ofl_desc *);
extern uintptr_t	ld_unwind_populate_hdr(Ofl_desc *);
extern uintptr_t	ld_unwind_register(Os_desc *, Ofl_desc *);

extern Ver_desc		*ld_vers_base(Ofl_desc *);
extern uintptr_t	ld_vers_check_defs(Ofl_desc *);
extern uintptr_t	ld_vers_check_need(Ofl_desc *);
extern uintptr_t	ld_vers_def_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern Ver_desc		*ld_vers_desc(const char *, Word, APlist **);
extern Ver_desc		*ld_vers_find(const char *, Word, APlist *);
extern uintptr_t	ld_vers_need_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern void		ld_vers_promote(Sym_desc *, Word, Ifl_desc *,
			    Ofl_desc *);
extern int		ld_vers_sym_process(Ofl_desc *, Is_desc *, Ifl_desc *);
extern int		ld_vers_verify(Ofl_desc *);
extern WrapSymNode	*ld_wrap_enter(Ofl_desc *, const char *);

extern uintptr_t	add_regsym(Sym_desc *, Ofl_desc *);
extern Word		hashbkts(Word);
extern Xword		lcm(Xword, Xword);

/*
 * Most platforms have both a 32 and 64-bit variant (e.g. EM_SPARC and
 * EM_SPARCV9). To support this, there many files in libld that are built
 * twice, once for ELFCLASS64 (_ELF64), and once for ELFCLASS32. In these
 * files, we sometimes want to supply one value for the ELFCLASS32 case
 * and another for ELFCLASS64. The LD_TARG_BYCLASS macro is used to do
 * this. It is called with both both alternatives, and yields the one
 * that applies to the current compilation environment.
 */
#ifdef	_ELF64
#define	LD_TARG_BYCLASS(_ec32, _ec64) (_ec64)
#else
#define	LD_TARG_BYCLASS(_ec32, _ec64) (_ec32)
#endif


#ifdef	__cplusplus
}
#endif

#endif /* _LIBLD_DOT_H */
