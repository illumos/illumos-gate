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

#ifndef	_DEBUG_H
#define	_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global include file for linker debugging.
 *
 * ld(1) and ld.so carry out all diagnostic debugging calls via dlopen'ing
 * the library liblddbg.so.  Thus debugging is always enabled.  The utility
 * elfdump() is explicitly dependent upon this library.  There are two
 * categories of routines defined in this library:
 *
 *  o	Debugging routines that have specific linker knowledge, and test the
 *	class of debugging allowable before proceeding, start with the `Dbg_'
 *	prefix.
 *
 *  o	Lower level routines that provide generic ELF structure interpretation
 *	start with the `Elf_' prefix.  These latter routines are the only
 *	routines used by the elfdump() utility.
 */

#include <libelf.h>
#include <sgs.h>
#include <libld.h>
#include <rtld.h>
#include <machdep.h>
#include <gelf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define any interface flags.  These flags direct the debugging routine to
 * generate different diagnostics, thus the strings themselves are maintained
 * in this library.
 */
#define	DBG_SUP_ENVIRON		1
#define	DBG_SUP_CMDLINE		2
#define	DBG_SUP_DEFAULT		3

#define	DBG_CONF_IGNORE		1	/* configuration processing errors */
#define	DBG_CONF_VERSION	2
#define	DBG_CONF_PRCFAIL	3
#define	DBG_CONF_CORRUPT	4

#define	DBG_ORDER_INFO_RANGE	1	/* sh_link out of range */
#define	DBG_ORDER_INFO_ORDER	2	/* sh_info also ordered */
#define	DBG_ORDER_LINK_OUTRANGE	3	/* sh_link out of range */
#define	DBG_ORDER_FLAGS		4	/* sh_flags do not match */
#define	DBG_ORDER_CYCLIC	5	/* sh_link cyclic */
#define	DBG_ORDER_LINK_ERROR	6	/* sh_link (one) has an error */

#define	DBG_INIT_SORT		1	/* calling init from sorted order */
#define	DBG_INIT_PEND		2	/* calling pending init */
#define	DBG_INIT_DYN		3	/* dynamically triggered init */
#define	DBG_INIT_DONE		4	/* init completed */

#define	DBG_DLSYM_DEF		0
#define	DBG_DLSYM_NEXT		1
#define	DBG_DLSYM_DEFAULT	2
#define	DBG_DLSYM_SELF		3
#define	DBG_DLSYM_PROBE		4

#define	DBG_DLCLOSE_NULL	0
#define	DBG_DLCLOSE_IGNORE	1
#define	DBG_DLCLOSE_RESCAN	2

#define	DBG_WAIT_INIT		1
#define	DBG_WAIT_FINI		2
#define	DBG_WAIT_SYMBOL		3

#define	DBG_SYM_REDUCE_GLOBAL	1	/* reporting global symbols to local */
#define	DBG_SYM_REDUCE_RETAIN	2	/* reporting non reduced local syms */

#define	DBG_DEP_CREATE		1	/* Group handle operations */
#define	DBG_DEP_ADD		2
#define	DBG_DEP_DELETE		3
#define	DBG_DEP_REMOVE		4
#define	DBG_DEP_REMAIN		5
#define	DBG_DEP_ORPHAN		6
#define	DBG_DEP_REINST		7

#define	DBG_BINFO_FOUND		0x0001	/* information regarding binding */
#define	DBG_BINFO_DIRECT	0x0002	/* bound directly */
#define	DBG_BINFO_COPYREF	0x0004	/* bound to copy relocated reference */
#define	DBG_BINFO_FILTEE	0x0008	/* bound to filtee */
#define	DBG_BINFO_INTERPOSE	0x0010	/* bound to an identified interposer */
#define	DBG_BINFO_PLTADDR	0x0020	/* bound to executables undefined plt */
#define	DBG_BINFO_MSK		0xffff

#define	DBG_CAP_INITIAL		0
#define	DBG_CAP_IGNORE		1
#define	DBG_CAP_OLD		2
#define	DBG_CAP_NEW		3
#define	DBG_CAP_RESOLVED	4

#define	DBG_REL_START		1
#define	DBG_REL_FINISH		2
#define	DBG_REL_NONE		3

/*
 * Define our setup entry point.
 */
extern	uint_t		Dbg_setup(const char *);
extern	void		Dbg_set(uint_t);

/*
 * Define a user macro to invoke debugging.  The `dbg_mask' variable acts as a
 * suitable flag, and can be set to collect the return value from Dbg_setup().
 */
extern	uint_t		dbg_mask;

#define	DBG_CALL(func)	if (dbg_mask) func

/*
 * Most debugging tokens are interpreted within liblddbg, and thus any flags
 * within dbg_mask are only meaningful to this library.  The following flags
 * may be set by the Dbg_setup() by can be interpreted by the caller.
 */
#define	DBG_G_SNAME	0x10000000	/* prepend simple name */
#define	DBG_G_FNAME	0x20000000	/* prepend full name */
#define	DBG_G_CLASS	0x40000000	/* prepend ELF class */

/*
 * Print routine, this must be supplied by the application.
 */
/*PRINTFLIKE1*/
extern	void		dbg_print(const char *, ...);


/*
 * External interface routines.  These are linker specific.
 */
#ifdef _ELF64
#define	Dbg_cap_hw_1		Dbg_cap_hw_164
#define	Dbg_cap_mapfile		Dbg_cap_mapfile64
#define	Dbg_cap_sec_entry	Dbg_cap_sec_entry64
#define	Dbg_file_analyze	Dbg_file_analyze64
#define	Dbg_file_aout		Dbg_file_aout64
#define	Dbg_file_archive	Dbg_file_archive64
#define	Dbg_file_bind_entry	Dbg_file_bind_entry64
#define	Dbg_file_config_dis	Dbg_file_config_dis64
#define	Dbg_file_config_obj	Dbg_file_config_obj64
#define	Dbg_file_delete		Dbg_file_delete64
#define	Dbg_file_dlclose	Dbg_file_dlclose64
#define	Dbg_file_dldump		Dbg_file_dldump64
#define	Dbg_file_dlopen		Dbg_file_dlopen64
#define	Dbg_file_elf		Dbg_file_elf64
#define	Dbg_file_filtee		Dbg_file_filtee64
#define	Dbg_file_filter		Dbg_file_filter64
#define	Dbg_file_fixname	Dbg_file_fixname64
#define	Dbg_file_generic	Dbg_file_generic64
#define	Dbg_file_hdl_action	Dbg_file_hdl_action64
#define	Dbg_file_hdl_collect	Dbg_file_hdl_collect64
#define	Dbg_file_hdl_title	Dbg_file_hdl_title64
#define	Dbg_file_ldso		Dbg_file_ldso64
#define	Dbg_file_lazyload	Dbg_file_lazyload64
#define	Dbg_file_needed		Dbg_file_needed64
#define	Dbg_file_nl		Dbg_file_nl64
#define	Dbg_file_output		Dbg_file_output64
#define	Dbg_file_preload	Dbg_file_preload64
#define	Dbg_file_prot		Dbg_file_prot64
#define	Dbg_file_reuse		Dbg_file_reuse64
#define	Dbg_file_skip		Dbg_file_skip64
#define	Dbg_got_display		Dbg_got_display64
#define	Dbg_map_atsign		Dbg_map_atsign64
#define	Dbg_map_cap		Dbg_map_cap64
#define	Dbg_map_dash		Dbg_map_dash64
#define	Dbg_map_ent		Dbg_map_ent64
#define	Dbg_map_equal		Dbg_map_equal64
#define	Dbg_map_parse		Dbg_map_parse64
#define	Dbg_map_pipe		Dbg_map_pipe64
#define	Dbg_map_seg		Dbg_map_seg64
#define	Dbg_map_size_new	Dbg_map_size_new64
#define	Dbg_map_size_old	Dbg_map_size_old64
#define	Dbg_map_sort_fini	Dbg_map_sort_fini64
#define	Dbg_map_sort_orig	Dbg_map_sort_orig64
#define	Dbg_map_symbol		Dbg_map_symbol64
#define	Dbg_map_version		Dbg_map_version64
#define	Dbg_move_mventry	Dbg_move_mventry64
#define	Dbg_move_mventry2	Dbg_move_mventry264
#define	Dbg_move_outsctadj	Dbg_move_outsctadj64
#define	Dbg_reloc_discard	Dbg_reloc_discard64
#define	Dbg_reloc_error		Dbg_reloc_error64
#define	Dbg_reloc_generate	Dbg_reloc_generate64
#define	Dbg_reloc_in		Dbg_reloc_in64
#define	Dbg_reloc_out		Dbg_reloc_out64
#define	Dbg_reloc_proc		Dbg_reloc_proc64
#define	Dbg_reloc_ars_entry	Dbg_reloc_ars_entry64
#define	Dbg_reloc_ors_entry	Dbg_reloc_ors_entry64
#define	Dbg_reloc_doact		Dbg_reloc_doact64
#define	Dbg_reloc_dooutrel	Dbg_reloc_dooutrel64
#define	Dbg_reloc_reg_apply	Dbg_reloc_reg_apply64
#define	Dbg_reloc_transition	Dbg_reloc_transition64
#define	Dbg_sec_added		Dbg_sec_added64
#define	Dbg_sec_created		Dbg_sec_created64
#define	Dbg_sec_discarded	Dbg_sec_discarded64
#define	Dbg_sec_group		Dbg_sec_group64
#define	Dbg_sec_group_discarded	Dbg_sec_group_discarded64
#define	Dbg_sec_in		Dbg_sec_in64
#define	Dbg_sec_order_list	Dbg_sec_order_list64
#define	Dbg_sec_order_error	Dbg_sec_order_error64
#define	Dbg_sec_strtab		Dbg_sec_strtab64
#define	Dbg_seg_entry		Dbg_seg_entry64
#define	Dbg_seg_list		Dbg_seg_list64
#define	Dbg_seg_os		Dbg_seg_os64
#define	Dbg_seg_title		Dbg_seg_title64
#define	Dbg_statistics_ar	Dbg_statistics_ar64
#define	Dbg_statistics_ld	Dbg_statistics_ld64
#define	Dbg_syminfo_entry	Dbg_syminfo_entry64
#define	Dbg_syminfo_entry_title	Dbg_syminfo_entry_title64
#define	Dbg_syminfo_title	Dbg_syminfo_title64
#define	Dbg_syms_ar_checking	Dbg_syms_ar_checking64
#define	Dbg_syms_ar_entry	Dbg_syms_ar_entry64
#define	Dbg_syms_ar_resolve	Dbg_syms_ar_resolve64
#define	Dbg_syms_created	Dbg_syms_created64
#define	Dbg_syms_discarded	Dbg_syms_discarded64
#define	Dbg_syms_entered	Dbg_syms_entered64
#define	Dbg_syms_entry		Dbg_syms_entry64
#define	Dbg_syms_global		Dbg_syms_global64
#define	Dbg_syms_ignore		Dbg_syms_ignore64
#define	Dbg_syms_new		Dbg_syms_new64
#define	Dbg_syms_nl		Dbg_syms_nl64
#define	Dbg_syms_old		Dbg_syms_old64
#define	Dbg_syms_process	Dbg_syms_process64
#define	Dbg_syms_reduce		Dbg_syms_reduce64
#define	Dbg_syms_reloc		Dbg_syms_reloc64
#define	Dbg_syms_resolved	Dbg_syms_resolved64
#define	Dbg_syms_resolving1	Dbg_syms_resolving164
#define	Dbg_syms_resolving2	Dbg_syms_resolving264
#define	Dbg_syms_sec_entry	Dbg_syms_sec_entry64
#define	Dbg_syms_sec_title	Dbg_syms_sec_title64
#define	Dbg_syms_spec_title	Dbg_syms_spec_title64
#define	Dbg_syms_up_title	Dbg_syms_up_title64
#define	Dbg_syms_updated	Dbg_syms_updated64
#define	Dbg_syms_dlsym		Dbg_syms_dlsym64
#define	Dbg_syms_lookup_aout	Dbg_syms_lookup_aout64
#define	Dbg_syms_lookup		Dbg_syms_lookup64
#define	Dbg_tls_modactivity	Dbg_tls_modactivity64
#define	Dbg_tls_static_block	Dbg_tls_static_block64
#define	Dbg_unused_sec		Dbg_unused_sec64
#define	Dbg_audit_interface	Dbg_audit_interface64
#define	Dbg_audit_lib		Dbg_audit_lib64
#define	Dbg_audit_object	Dbg_audit_object64
#define	Dbg_audit_symval	Dbg_audit_symval64
#define	Dbg_audit_version	Dbg_audit_version64
#define	Dbg_ver_avail_entry	Dbg_ver_avail_entry64
#define	Dbg_ver_desc_entry	Dbg_ver_desc_entry64
#endif	/* _ELF64 */

extern	void		Dbg_args_files(int, char *);
extern	void		Dbg_args_flags(int, int);
extern	void		Dbg_bind_global(const char *, caddr_t, caddr_t, Xword,
			    Pltbindtype, const char *, caddr_t, caddr_t,
			    const char *, uint_t);
extern	void		Dbg_bind_plt_summary(Half, Word, Word, Word,
			    Word, Word, Word);
extern	void		Dbg_bind_profile(uint_t, uint_t);
extern	void		Dbg_bind_weak(const char *, caddr_t, caddr_t,
			    const char *);
extern	void		Dbg_cap_hw_candidate(const char *);
extern	void		Dbg_cap_hw_filter(const char *, const char *);
extern	void		Dbg_cap_hw_1(Xword, Half);
extern	void		Dbg_cap_mapfile(Xword, Xword, Half);
extern	void		Dbg_cap_sec_entry(uint_t, Xword, Xword, Half);
extern	void		Dbg_cap_sec_title(const char *);
extern	void		Dbg_ent_print(Half, List * len, Boolean);
extern	void		Dbg_file_analyze(Rt_map *);
extern	void		Dbg_file_aout(const char *, ulong_t, ulong_t, ulong_t);
extern	void		Dbg_file_archive(const char *, int);
extern	void		Dbg_file_ar_rescan(void);
extern	void		Dbg_file_bind_entry(Bnd_desc *);
extern	void		Dbg_file_cntl(Lm_list *, Aliste, Aliste);
extern	void		Dbg_file_config_dis(const char *, int);
extern	void		Dbg_file_config_obj(const char *, const char *,
			    const char *);
extern	void		Dbg_file_delete(const char *);
extern	void		Dbg_file_dlclose(const char *, int);
extern	void		Dbg_file_dldump(const char *, const char *, int);
extern	void		Dbg_file_dlopen(const char *, const char *, int);
extern	void		Dbg_file_del_rescan(void);
extern	void		Dbg_file_elf(const char *, ulong_t, ulong_t, ulong_t,
			    ulong_t, Lmid_t, Aliste);
extern	void		Dbg_file_filtee(const char *, const char *, int);
extern	void		Dbg_file_filter(const char *, const char *, int);
extern	void		Dbg_file_fixname(const char *, const char *);
extern	void		Dbg_file_generic(Ifl_desc *);
extern	void		Dbg_file_hdl_action(Grp_hdl *, Rt_map *, int);
extern	void		Dbg_file_hdl_collect(Grp_hdl *, const char *);
extern	void		Dbg_file_hdl_title(int);
extern	void		Dbg_file_lazyload(const char *, const char *,
			    const char *);
extern	void		Dbg_file_ldso(const char *, ulong_t, ulong_t, ulong_t,
			    ulong_t);
extern	void		Dbg_file_mode_promote(const char *, int);
extern	void		Dbg_file_needed(const char *, const char *);
extern	void		Dbg_file_nl(void);
extern	void		Dbg_file_output(Ofl_desc *);
extern	void		Dbg_file_preload(const char *);
extern	void		Dbg_file_prot(const char *, int);
extern	void		Dbg_file_reuse(const char *, const char *);
extern	void		Dbg_file_rejected(Rej_desc *);
extern	void		Dbg_file_skip(const char *, const char *);
extern	void		Dbg_got_display(Gottable *, Ofl_desc *);
extern	void		Dbg_libs_audit(const char *, const char *);
extern	void		Dbg_libs_ignore(const char *);
extern	void		Dbg_libs_init(List *, List *);
extern	void		Dbg_libs_l(const char *, const char *);
extern	void		Dbg_libs_path(const char *, Half, const char *);
extern	void		Dbg_libs_req(const char *, const char *, const char *);
extern	void		Dbg_libs_update(List *, List *);
extern	void		Dbg_libs_yp(const char *);
extern	void		Dbg_libs_ylu(const char *, const char *, int);
extern	void		Dbg_libs_find(const char *);
extern	void		Dbg_libs_found(const char *, int);
extern	void		Dbg_map_atsign(Boolean);
extern	void		Dbg_map_dash(const char *, Sdf_desc *);
extern	void		Dbg_map_ent(Boolean, Ent_desc *, Ofl_desc *);
extern	void		Dbg_map_equal(Boolean);
extern	void		Dbg_map_parse(const char *);
extern	void		Dbg_map_pipe(Sg_desc *, const char *, const Word);
extern	void		Dbg_map_seg(Half, int, Sg_desc *);
extern	void		Dbg_map_size_new(const char *);
extern	void		Dbg_map_size_old(Ehdr *, Sym_desc *);
extern	void		Dbg_map_sort_fini(Sg_desc *);
extern	void		Dbg_map_sort_orig(Sg_desc *);
extern	void		Dbg_map_symbol(Ehdr *, Sym_desc *);
extern	void		Dbg_map_version(const char *, const char *, int);
extern 	void		Dbg_move_adjexpandreloc(ulong_t, const char *);
extern 	void		Dbg_move_adjmovereloc(ulong_t, ulong_t, const char *);
extern	void		Dbg_move_data(const char *);
extern 	void		Dbg_move_expanding(Move *, Addr);
extern 	void		Dbg_move_input1(const char *);
extern 	void		Dbg_move_mventry(int, Move *, Sym_desc *);
extern 	void		Dbg_move_mventry2(Move *, Word, char *);
extern 	void		Dbg_move_outmove(const uchar_t *);
extern 	void		Dbg_move_outsctadj(Sym_desc *);
extern 	void		Dbg_move_parexpn(const char *, const char *);
#if	defined(_ELF64)
extern	void		Dbg_pltpad_bindto64(const char *, const char *, Addr);
extern	void		Dbg_pltpad_boundto64(const char *, Addr, const char *,
			    const char *);
#endif
extern	void		Dbg_reloc_apply(unsigned long long, unsigned long long);
extern	void		Dbg_reloc_discard(Half, Rel_desc *);
extern	void		Dbg_reloc_error(Half, Word, void *, const char *,
			    const char *);
extern	void		Dbg_reloc_generate(Os_desc *, Word);
extern	void		Dbg_reloc_reg_apply(unsigned long long,
			    unsigned long long);
extern	void		Dbg_reloc_in(Half, Word, void *, const char *,
			    const char *);
extern	void		Dbg_reloc_out(Half, Word, void *, const char *,
			    const char *);
extern	void		Dbg_reloc_proc(Os_desc *, Is_desc *, Is_desc *);
extern	void		Dbg_reloc_ars_entry(Half, Rel_desc *);
extern	void		Dbg_reloc_ors_entry(Half, Rel_desc *);
extern	void		Dbg_reloc_doactiverel(void);
extern	void		Dbg_reloc_doact(Half, Word, Xword, Xword, const char *,
			    Os_desc *);
extern	void		Dbg_reloc_dooutrel(GElf_Word);
extern	void		Dbg_reloc_copy(const char *, const char *,
			    const char *, int);
extern	void		Dbg_reloc_run(const char *, uint_t, int, int);
extern	void		Dbg_reloc_transition(Half, Word, Word, Xword,
			    const char *);
extern	void		Dbg_sec_added(Os_desc *, Sg_desc *);
extern	void		Dbg_sec_created(Os_desc *, Sg_desc *);
extern	void		Dbg_sec_discarded(Is_desc *, Is_desc *);
extern	void		Dbg_sec_group(Is_desc *);
extern	void		Dbg_sec_group_discarded(Is_desc *);
extern	void		Dbg_sec_in(Is_desc *);
extern	void		Dbg_sec_order_list(Ofl_desc *, int);
extern	void		Dbg_sec_order_error(Ifl_desc *, Word, int);
extern	void		Dbg_sec_strtab(Os_desc *, Str_tbl *);
extern	void		Dbg_seg_entry(Half, int, Sg_desc *);
extern	void		Dbg_seg_list(Half, List *);
extern	void		Dbg_seg_os(Ofl_desc *, Os_desc *, int);
extern	void		Dbg_seg_title(void);
extern	void		Dbg_support_action(const char *, const char *,
			    Support_ndx, const char *);
extern	void		Dbg_support_load(const char *, const char *);
extern	void		Dbg_support_req(const char *, int);
extern	void		Dbg_syms_ar_checking(Xword, Elf_Arsym *, const char *);
extern	void		Dbg_syms_ar_entry(Xword, Elf_Arsym *);
extern	void		Dbg_syms_ar_resolve(Xword, Elf_Arsym *, const char *,
			    int);
extern	void		Dbg_syms_ar_title(const char *, int);
extern	void		Dbg_syms_created(const char *);
extern	void		Dbg_syms_discarded(Sym_desc *, Is_desc *);
extern	void		Dbg_syms_entered(Ehdr *, Sym *, Sym_desc *);
extern	void		Dbg_syms_entry(Xword, Sym_desc *);
extern	void		Dbg_syms_global(Xword, const char *);
extern	void		Dbg_syms_ignore(Ehdr *, Sym_desc *);
extern	void		Dbg_syms_lazy_rescan(const char *);
extern	void		Dbg_syms_new(Ehdr *, Sym *, Sym_desc *);
extern	void		Dbg_syms_nl(void);
extern	void		Dbg_syms_old(Ehdr *, Sym_desc *);
extern	void		Dbg_syms_process(Ifl_desc *);
extern	void		Dbg_syms_reduce(int, Ehdr *, Sym_desc *, int,
			    const char *);
extern	void		Dbg_syms_reloc(Ehdr *, Sym_desc *);
extern	void		Dbg_syms_resolved(Ehdr *, Sym_desc *);
extern	void		Dbg_syms_resolving1(Xword, const char *, int, int);
extern	void		Dbg_syms_resolving2(Ehdr *, Sym *, Sym *, Sym_desc *,
			    Ifl_desc *);
extern	void		Dbg_syms_sec_entry(int, Sg_desc *, Os_desc *);
extern	void		Dbg_syms_sec_title(void);
extern	void		Dbg_syms_spec_title(void);
extern	void		Dbg_syms_up_title(Ehdr *);
extern	void		Dbg_syms_updated(Ehdr *, Sym_desc *, const char *);
extern	void		Dbg_syms_dlsym(const char *, const char *, const char *,
			    int);
extern	void		Dbg_syms_lookup_aout(const char *);
extern	void		Dbg_syms_lookup(const char *, const char *,
			    const char *);
extern	void		Dbg_scc_title(int);
extern	void		Dbg_scc_entry(uint_t, const char *);
extern	void		Dbg_tls_modactivity(void *, uint_t);
extern	void		Dbg_tls_static_block(void *, ulong_t);
extern	void		Dbg_audit_interface(const char *, const char *);
extern	void		Dbg_audit_lib(const char *);
extern	void		Dbg_audit_object(const char *, const char *);
extern	void		Dbg_audit_symval(const char *, const char *,
			    const char *, Addr, Addr);
extern	void		Dbg_audit_version(const char *, ulong_t);
extern	void		Dbg_statistics_ar(Ofl_desc *);
extern	void		Dbg_statistics_ld(Ofl_desc *);
extern	void		Dbg_syminfo_entry(int, Syminfo *, Sym *,
			    const char *, Dyn *);
extern	void		Dbg_syminfo_title(void);
extern	void		Dbg_unused_file(const char *, int);
extern	void		Dbg_unused_rtldinfo(const char *, const char *);
extern	void		Dbg_unused_sec(Is_desc *);
extern	void		Dbg_unused_unref(const char *, const char *);
extern	void		Dbg_util_broadcast(const char *);
extern	void		Dbg_util_call_array(const char *, void *,
			    uint_t, uint_t);
extern	void		Dbg_util_call_fini(const char *);
extern	void		Dbg_util_call_init(const char *, int);
extern	void		Dbg_util_call_main(const char *);
extern	void		Dbg_util_dbnotify(rd_event_e, r_state_e);
extern	void		Dbg_util_intoolate(const char *);
extern	void		Dbg_util_nl(void);
extern	void		Dbg_util_no_init(const char *);
extern	void		Dbg_util_str(const char *);
extern	void		Dbg_util_wait(int, const char *, const char *);
extern	void		Dbg_ver_avail_entry(Ver_index *, const char *);
extern	void		Dbg_ver_avail_title(const char *);
extern	void		Dbg_ver_desc_entry(Ver_desc *);
extern	void		Dbg_ver_def_title(const char *);
extern	void		Dbg_ver_need_title(const char *);
extern	void		Dbg_ver_need_entry(Half, const char *, const char *);
extern	void		Dbg_ver_nointerface(const char *);
extern	void		Dbg_ver_symbol(const char *);

/*
 * External interface routines. These are not linker specific and provide
 * generic routines for interpreting elf structures.
 */
#ifdef _ELF64
#define	Elf_phdr_entry		Gelf_phdr_entry
#define	Elf_shdr_entry		Gelf_shdr_entry
#define	Elf_sym_table_entry	Gelf_sym_table_entry
#else	/* elf32 */
extern	void		Elf_phdr_entry(Half, Elf32_Phdr *);
extern	void		Elf_shdr_entry(Half, Elf32_Shdr *);
extern	void		Elf_sym_table_entry(const char *, Elf32_Ehdr *,
			    Elf32_Sym *, Elf32_Word, const char *,
			    const char *);
#endif /* _ELF64 */

/*
 * These are used by both the Elf32 and Elf64 sides.
 */
extern	const char	*Gelf_sym_dem(const char *);

extern	void		Gelf_cap_print(GElf_Cap *, int, Half);
extern	void		Gelf_cap_title(void);
extern	void		Gelf_phdr_entry(Half, GElf_Phdr *);
extern	void		Gelf_shdr_entry(Half, GElf_Shdr *);
extern	void		Gelf_sym_table_entry(const char *, GElf_Ehdr *,
			    GElf_Sym *, GElf_Word, const char *, const char *);
extern	void		Gelf_elf_data_title(void);
extern	void		Gelf_syminfo_entry(int, GElf_Syminfo *, const char *,
			    const char *);
extern	void		Gelf_sym_table_title(GElf_Ehdr *, const char *,
			    const char *);
extern	void		Gelf_ver_def_title(void);
extern	void		Gelf_ver_need_title(void);
extern	void		Gelf_ver_line_1(const char *, const char *,
			    const char *, const char *);
extern	void		Gelf_ver_line_2(const char *, const char *);
extern	void		Gelf_ver_line_3(const char *, const char *,
			    const char *);

extern	void		Gelf_dyn_print(GElf_Dyn *, int ndx, const char *, Half);
extern	void		Gelf_dyn_title(void);
extern	void		Gelf_elf_header(GElf_Ehdr *, GElf_Shdr *);
extern	void		Gelf_got_title(uchar_t);
extern	void		Gelf_got_entry(GElf_Ehdr *, Sword, GElf_Addr,
			    GElf_Xword, GElf_Word, void *, const char *);
extern	void		Gelf_reloc_entry(const char *, GElf_Half, GElf_Word,
			    GElf_Rela *, const char *, const char *);
extern	void		Gelf_syminfo_title(void);

#ifdef	__cplusplus
}
#endif

#endif /* _DEBUG_H */
