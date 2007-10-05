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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Local include file for ld library.
 */

#ifndef	_LIBLD_DOT_H
#define	_LIBLD_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libld.h>
#include <_libelf.h>
#include <debug.h>
#include <conv.h>
#include <msg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Types of segment index.
 */
typedef enum {
	LD_PHDR,	LD_INTERP,	LD_SUNWCAP,	LD_TEXT,
	LD_DATA,	LD_BSS,
#if	defined(__x86) && defined(_ELF64)
	LD_LRODATA,	LD_LDATA,
#endif
	LD_DYN,		LD_DTRACE,	 LD_SUNWBSS,	LD_TLS,
#if	defined(__x86) && defined(_ELF64)
	LD_UNWIND,
#endif
	LD_NOTE,	LD_EXTRA,
	LD_NUM
} Segment_ndx;

/*
 * Types of bss sections
 */
typedef enum {
	MAKE_BSS,
	MAKE_LBSS,
	MAKE_TLS
} Bss_Type;

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
	List		sup_funcs;	/* list of support functions */
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
	Sym_desc *	sl_sdp;
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

#define	HEAPBLOCK	0x68000		/* default allocation block size */
#define	HEAPALIGN	0x8		/* heap blocks alignment requirement */

/*
 * Dynamic per-symbol filtee string table descriptor.  This associates filtee
 * strings that will be created in the .dynstr, with .dynamic entries.
 */
typedef struct {
	char		*dft_str;	/* dynstr string */
	Word		dft_flag;	/* auxiliary/filtee type */
	Half		dft_ndx;	/* eventual ndx into .dynamic */
} Dfltr_desc;

/*
 * Per-symbol filtee descriptor.  This associates symbol definitions with
 * their filtees.
 */
typedef struct {
	Sym_desc	*sft_sdp;	/* symbol descriptor */
	Aliste		sft_off;	/* offset into dtstr descriptor */
} Sfltr_desc;

/*
 * Define Alist initialization sizes.
 */
#define	AL_CNT_DFLTR	4		/* ofl_dtsfltrs initial alist count */
#define	AL_CNT_GROUP	20		/* ifl_groups initial alist count */
#define	AL_CNT_SFLTR	20		/* ofl_symfltrs initial alist count */
#define	AL_CNT_OSDESC	40		/* sg_osdescs initial alist count */
#define	AL_CNT_SECORDER	40		/* sg_secorder initial alist count */

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
 * Relocation buckets are sized based on the number of input relocations and
 * the following constants.
 */
#define	REL_HAIDESCNO	1000		/* high water mark active buckets */
#define	REL_LAIDESCNO	50		/* low water mark active buckets */
#define	REL_HOIDESCNO	500		/* high water mark output buckets */
#define	REL_LOIDESCNO	10		/* low water mark output buckets */

extern char		*Plibpath;
extern char		*Llibdir;
extern char		*Ulibdir;
extern Ld_heap		*ld_heap;
extern List		lib_support;
extern int		demangle_flag;
extern const Msg	reject[];
extern int		Verbose;
extern const int	ldynsym_symtype[STT_NUM];
extern const int	dynsymsort_symtype[STT_NUM];

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
 *	((_sdp->sd_ref != REF_DYN_NEED) || (_sdp->sd_flags & FLG_SY_MVTOCOMM))
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
	(((_sdp->sd_ref != REF_DYN_NEED) || \
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
 * For backward compatibility provide a /dev/zero file descriptor.
 */
extern int		dz_fd;

/*
 * Local functions.
 */
extern char		*add_string(char *, char *);
extern const char	*demangle(const char *);

extern void		lds_atexit(Ofl_desc *, int);

extern void		libld_free(void *);
extern void		*libld_malloc(size_t);
extern void		*libld_realloc(void *, size_t);

extern Listnode		*list_appendc(List *, const void *);
extern Listnode		*list_insertc(List *, const void *, Listnode *);
extern Listnode		*list_prependc(List *, const void *);
extern Listnode		*list_where(List *, Word num);

extern Sdf_desc		*sdf_add(const char *, List *);
extern Sdf_desc		*sdf_find(const char *, List *);

#if	defined(_ELF64)

#define	ld_add_actrel		ld64_add_actrel
#define	ld_add_libdir		ld64_add_libdir
#define	ld_add_outrel		ld64_add_outrel
#define	ld_adj_movereloc	ld64_adj_movereloc
#define	ld_am_I_partial		ld64_am_I_partial
#define	ld_ar_member		ld64_ar_member
#define	ld_ar_setup		ld64_ar_setup
#if	defined(__sparc)
#define	ld_allocate_got		ld64_allocate_got
#endif
#define	ld_assign_got		ld64_assign_got
#define	ld_assign_got_ndx	ld64_assign_got_ndx
#define	ld_assign_got_TLS	ld64_assign_got_TLS
#define	ld_assign_plt_ndx	ld64_assign_plt_ndx
#define	ld_byteswap_Xword	ld64_byteswap_Xword
#define	ld_calc_got_offset	ld64_calc_got_offset
#define	ld_calc_plt_addr	ld64_calc_plt_addr
#define	ld_disp_errmsg		ld64_disp_errmsg
#define	ld_do_activerelocs	ld64_do_activerelocs
#define	ld_ent_check		ld64_ent_check
#define	ld_exit			ld64_exit
#define	ld_fillin_gotplt	ld64_fillin_gotplt
#define	ld_find_gotndx		ld64_find_gotndx
#define	ld_find_library		ld64_find_library
#define	ld_finish_libs		ld64_finish_libs
#define	ld_get_group		ld64_get_group
#define	ld_lib_setup		ld64_lib_setup
#define	ld_init			ld64_init
#define	ld_init_rel		ld64_init_rel
#define	ld_is_regsym		ld64_is_regsym
#define	ld_lcm			ld64_lcm
#define	ld_mach_update_odynamic	ld64_mach_update_odynamic
#define	ld_mach_eflags		ld64_mach_eflags
#define	ld_mach_make_dynamic	ld64_mach_make_dynamic
#define	ld_mach_sym_typecheck	ld64_mach_sym_typecheck
#define	ld_make_bss		ld64_make_bss
#define	ld_make_data		ld64_make_data
#define	ld_make_got		ld64_make_got
#define	ld_make_sunwbss		ld64_make_sunwbss
#define	ld_make_sunwdata	ld64_make_sunwdata
#define	ld_make_sunwmove	ld64_make_sunmove
#define	ld_make_text		ld64_make_text
#define	ld_map_out		ld64_map_out
#define	ld_map_parse		ld64_map_parse
#define	ld_open_outfile		ld64_open_outfile
#define	ld_perform_outreloc	ld64_perform_outreloc
#define	ld_place_section	ld64_place_section
#define	ld_process_archive	ld64_process_archive
#define	ld_process_files	ld64_process_files
#define	ld_process_flags	ld64_process_flags
#define	ld_process_ifl		ld64_process_ifl
#define	ld_process_ordered	ld64_process_ordered
#define	ld_process_sym_reloc	ld64_process_sym_reloc
#define	ld_reloc_local		ld64_reloc_local
#define	ld_reloc_GOT_relative	ld64_reloc_GOT_relative
#define	ld_reloc_GOTOP		ld64_reloc_GOTOP
#define	ld_reloc_plt		ld64_reloc_plt
#define	ld_reloc_register	ld64_reloc_register
#define	ld_reloc_remain_entry	ld64_reloc_remain_entry
#define	ld_reloc_TLS		ld64_reloc_TLS
#define	ld_reg_check		ld64_reg_check
#define	ld_reg_enter		ld64_reg_enter
#define	ld_reg_find		ld64_reg_find
#define	ld_sec_validate		ld64_sec_validate
#define	ld_sort_ordered		ld64_sort_ordered
#define	ld_sort_seg_list	ld64_sort_seg_list
#define	ld_sunwmove_preprocess	ld64_sunwmove_preprocess
#define	ld_sup_atexit		ld64_sup_atexit
#define	ld_sup_open		ld64_sup_open
#define	ld_sup_file		ld64_sup_file
#define	ld_sup_loadso		ld64_sup_loadso
#define	ld_sup_input_done	ld64_sup_input_done
#define	ld_sup_input_section	ld64_sup_input_section
#define	ld_sup_section		ld64_sup_section
#define	ld_sup_start		ld64_sup_start
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

#else

#define	ld_add_actrel		ld32_add_actrel
#define	ld_add_libdir		ld32_add_libdir
#define	ld_add_outrel		ld32_add_outrel
#define	ld_adj_movereloc	ld32_adj_movereloc
#define	ld_am_I_partial		ld32_am_I_partial
#define	ld_ar_member		ld32_ar_member
#define	ld_ar_setup		ld32_ar_setup
#if	defined(__sparc)
#define	ld_allocate_got		ld32_allocate_got
#endif
#define	ld_assign_got		ld32_assign_got
#define	ld_assign_got_ndx	ld32_assign_got_ndx
#define	ld_assign_got_TLS	ld32_assign_got_TLS
#define	ld_assign_plt_ndx	ld32_assign_plt_ndx
#define	ld_byteswap_Xword	ld32_byteswap_Xword
#define	ld_calc_got_offset	ld32_calc_got_offset
#define	ld_calc_plt_addr	ld32_calc_plt_addr
#define	ld_disp_errmsg		ld32_disp_errmsg
#define	ld_do_activerelocs	ld32_do_activerelocs
#define	ld_ent_check		ld32_ent_check
#define	ld_exit			ld32_exit
#define	ld_fillin_gotplt	ld32_fillin_gotplt
#define	ld_find_gotndx		ld32_find_gotndx
#define	ld_find_library		ld32_find_library
#define	ld_finish_libs		ld32_finish_libs
#define	ld_get_group		ld32_get_group
#define	ld_lib_setup		ld32_lib_setup
#define	ld_init			ld32_init
#define	ld_init_rel		ld32_init_rel
#define	ld_is_regsym		ld32_is_regsym
#define	ld_lcm			ld32_lcm
#define	ld_mach_update_odynamic	ld32_mach_update_odynamic
#define	ld_mach_eflags		ld32_mach_eflags
#define	ld_mach_make_dynamic	ld32_mach_make_dynamic
#define	ld_mach_sym_typecheck	ld32_mach_sym_typecheck
#define	ld_make_bss		ld32_make_bss
#define	ld_make_data		ld32_make_data
#define	ld_make_got		ld32_make_got
#define	ld_make_sunwbss		ld32_make_sunwbss
#define	ld_make_sunwdata	ld32_make_sunwdata
#define	ld_make_sunwmove	ld32_make_sunmove
#define	ld_make_text		ld32_make_text
#define	ld_map_out		ld32_map_out
#define	ld_map_parse		ld32_map_parse
#define	ld_open_outfile		ld32_open_outfile
#define	ld_perform_outreloc	ld32_perform_outreloc
#define	ld_place_section	ld32_place_section
#define	ld_process_archive	ld32_process_archive
#define	ld_process_files	ld32_process_files
#define	ld_process_flags	ld32_process_flags
#define	ld_process_ifl		ld32_process_ifl
#define	ld_process_ordered	ld32_process_ordered
#define	ld_process_sym_reloc	ld32_process_sym_reloc
#define	ld_reloc_local		ld32_reloc_local
#define	ld_reloc_GOT_relative	ld32_reloc_GOT_relative
#define	ld_reloc_GOTOP		ld32_reloc_GOTOP
#define	ld_reloc_plt		ld32_reloc_plt
#define	ld_reloc_register	ld32_reloc_register
#define	ld_reloc_remain_entry	ld32_reloc_remain_entry
#define	ld_reloc_TLS		ld32_reloc_TLS
#define	ld_reg_check		ld32_reg_check
#define	ld_reg_enter		ld32_reg_enter
#define	ld_reg_find		ld32_reg_find
#define	ld_sec_validate		ld32_sec_validate
#define	ld_sort_ordered		ld32_sort_ordered
#define	ld_sort_seg_list	ld32_sort_seg_list
#define	ld_sunwmove_preprocess	ld32_sunwmove_preprocess
#define	ld_sup_atexit		ld32_sup_atexit
#define	ld_sup_open		ld32_sup_open
#define	ld_sup_file		ld32_sup_file
#define	ld_sup_loadso		ld32_sup_loadso
#define	ld_sup_input_done	ld32_sup_input_done
#define	ld_sup_input_section	ld32_sup_input_section
#define	ld_sup_section		ld32_sup_section
#define	ld_sup_start		ld32_sup_start
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

#endif

extern uintptr_t	dbg_setup(const char *, Dbg_desc *, const char **, int);

extern uintptr_t	ld_add_actrel(Word, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_add_libdir(Ofl_desc *, const char *);
extern uintptr_t	ld_add_outrel(Word, Rel_desc *, Ofl_desc *);
extern void 		ld_adj_movereloc(Ofl_desc *, Rel_desc *);
extern Sym_desc * 	ld_am_I_partial(Rel_desc *, Xword);
extern void		ld_ar_member(Ar_desc *, Elf_Arsym *, Ar_aux *,
			    Ar_mem *);
extern Ar_desc		*ld_ar_setup(const char *, Elf *, Ofl_desc *);
#if	defined(__sparc)
extern uintptr_t	ld_allocate_got(Ofl_desc *);
#endif
extern uintptr_t	ld_assign_got(Ofl_desc *, Sym_desc *);
extern uintptr_t	ld_assign_got_ndx(List *, Gotndx *, Gotref, Ofl_desc *,
			    Rel_desc *, Sym_desc *);
extern uintptr_t	ld_assign_got_TLS(Boolean, Rel_desc *, Ofl_desc *,
			    Sym_desc *, Gotndx *, Gotref, Word, Word,
			    Word, Word);
extern void		ld_assign_plt_ndx(Sym_desc *, Ofl_desc *);

extern Xword		ld_byteswap_Xword(Xword);
extern Xword		ld_calc_got_offset(Rel_desc *, Ofl_desc *);
extern Xword		ld_calc_plt_addr(Sym_desc *, Ofl_desc *);

extern void		ld_disp_errmsg(const char *, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_do_activerelocs(Ofl_desc *);

extern void		ld_ent_check(Ofl_desc *);
extern int		ld_exit(Ofl_desc *);

extern uintptr_t	ld_fillin_gotplt(Ofl_desc *);
extern Gotndx *		ld_find_gotndx(List *, Gotref, Ofl_desc *, Rel_desc *);
extern uintptr_t	ld_find_library(const char *, Ofl_desc *);
extern uintptr_t	ld_finish_libs(Ofl_desc *);

extern Group_desc *	ld_get_group(Ofl_desc *, Is_desc *);

extern uintptr_t	ld_lib_setup(Ofl_desc *);

extern void		ld_init(Ofl_desc *);
extern Word		ld_init_rel(Rel_desc *, void *);
extern const char	*ld_is_regsym(Ofl_desc *, Ifl_desc *, Sym *,
			    const char *, int, Word, const char *, Word *);

extern Xword		ld_lcm(Xword, Xword);

extern void		ld_mach_update_odynamic(Ofl_desc *, Dyn **);
extern void		ld_mach_eflags(Ehdr *, Ofl_desc *);
extern void		ld_mach_make_dynamic(Ofl_desc *, size_t *);
extern int		ld_mach_sym_typecheck(Sym_desc *, Sym *, Ifl_desc *,
			    Ofl_desc *);
extern uintptr_t	ld_make_bss(Ofl_desc *, Xword, Xword, Bss_Type);
extern Is_desc		*ld_make_data(Ofl_desc *, size_t);
extern uintptr_t	ld_make_got(Ofl_desc *);
extern uintptr_t	ld_make_sunwbss(Ofl_desc *, size_t, Xword);
extern uintptr_t	ld_make_sunwdata(Ofl_desc *, size_t, Xword);
extern uintptr_t	ld_make_sunwmove(Ofl_desc *, int);
extern Is_desc		*ld_make_text(Ofl_desc *, size_t);
extern void		ld_map_out(Ofl_desc *);
extern uintptr_t	ld_map_parse(const char *, Ofl_desc *);

extern uintptr_t	ld_open_outfile(Ofl_desc *);

extern uintptr_t	ld_perform_outreloc(Rel_desc *, Ofl_desc *);
extern Os_desc *	ld_place_section(Ofl_desc *, Is_desc *, int, Word);
extern uintptr_t	ld_process_archive(const char *, int, Ar_desc *,
			    Ofl_desc *);
extern uintptr_t	ld_process_files(Ofl_desc *, int, char **);
extern uintptr_t	ld_process_flags(Ofl_desc *, int, char **);
extern Ifl_desc		*ld_process_ifl(const char *, const char *, int, Elf *,
			    Word, Ofl_desc *, Rej_desc *);
extern uintptr_t	ld_process_ordered(Ifl_desc *, Ofl_desc *, Word, Word);
extern uintptr_t	ld_process_sym_reloc(Ofl_desc *, Rel_desc *, Rel *,
			    Is_desc *, const char *);

extern uintptr_t	ld_reloc_local(Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_reloc_GOT_relative(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_reloc_GOTOP(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_reloc_plt(Rel_desc *, Ofl_desc *);
extern uintptr_t	ld_reloc_register(Rel_desc *, Is_desc *, Ofl_desc *);
extern void		ld_reloc_remain_entry(Rel_desc *, Os_desc *,
			    Ofl_desc *);
extern uintptr_t	ld_reloc_TLS(Boolean, Rel_desc *, Ofl_desc *);

extern int		ld_reg_check(Sym_desc *, Sym *, const char *,
			    Ifl_desc *, Ofl_desc *);
extern int		ld_reg_enter(Sym_desc *, Ofl_desc *);
extern Sym_desc *	ld_reg_find(Sym *, Ofl_desc *);

extern void		ld_sec_validate(Ofl_desc *);
extern uintptr_t	ld_sort_ordered(Ofl_desc *);
extern uintptr_t	ld_sort_seg_list(Ofl_desc *);
extern uintptr_t	ld_sunwmove_preprocess(Ofl_desc *);
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
extern Sym_desc		*ld_sym_add_u(const char *, Ofl_desc *, Msg);
extern void		ld_sym_adjust_vis(Sym_desc *, Ofl_desc *);
extern int		ld_sym_avl_comp(const void *, const void *);
extern uintptr_t	ld_sym_copy(Sym_desc *);
extern Sym_desc		*ld_sym_enter(const char *, Sym *, Word, Ifl_desc *,
			    Ofl_desc *, Word, Word, Word, Half, avl_index_t *);
extern Sym_desc		*ld_sym_find(const char *, Word, avl_index_t *,
			    Ofl_desc *);
extern uintptr_t	ld_sym_nodirect(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	ld_sym_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	ld_sym_resolve(Sym_desc *, Sym *, Ifl_desc *,
			    Ofl_desc *, int, Word, Word);
extern uintptr_t	ld_sym_spec(Ofl_desc *);

extern Ver_desc		*ld_vers_base(Ofl_desc *);
extern uintptr_t	ld_vers_check_defs(Ofl_desc *);
extern uintptr_t	ld_vers_check_need(Ofl_desc *);
extern uintptr_t	ld_vers_def_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern Ver_desc		*ld_vers_desc(const char *, Word, List *);
extern Ver_desc		*ld_vers_find(const char *, Word, List *);
extern uintptr_t	ld_vers_need_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern void		ld_vers_promote(Sym_desc *, Word, Ifl_desc *,
			    Ofl_desc *);
extern int		ld_vers_sym_process(Lm_list *, Is_desc *, Ifl_desc *);
extern int		ld_vers_verify(Ofl_desc *);

extern uintptr_t	add_regsym(Sym_desc *, Ofl_desc *);
extern void		*alist_append(Alist **, const void *, size_t, int);
extern Word		hashbkts(Word);
extern Xword		lcm(Xword, Xword);
extern Listnode *	list_where(List *, Word);

#if	defined(__x86) && defined(_ELF64)
extern uintptr_t	append_amd64_unwind(Os_desc *, Ofl_desc *);
extern uintptr_t	make_amd64_unwindhdr(Ofl_desc *);
extern uintptr_t	populate_amd64_unwindhdr(Ofl_desc *);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _LIBLD_DOT_H */
