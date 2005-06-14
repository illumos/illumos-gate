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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Local include file for ld library.
 */

#ifndef	_LIBLD_DOT_H
#define	_LIBLD_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libld.h>
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
	LD_DATA,	LD_BSS,		LD_DYN,		LD_DTRACE,
	LD_NOTE,	LD_SUNWBSS,	LD_TLS,
#if defined(__x86) && defined(_ELF64)
	LD_UNWIND,
#endif
	LD_EXTRA,
	LD_NUM
} Segment_ndx;

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

#define	AL_CNT_DFLTR	4

/*
 * Per-symbol filtee descriptor.  This associates symbol definitions with
 * their filtees.
 */
typedef struct {
	Sym_desc	*sft_sdp;	/* symbol descriptor */
	Aliste		sft_off;	/* offset into dtstr descriptor */
} Sfltr_desc;

#define	AL_CNT_SFLTR	20

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
 * Relocation buckets are sized based on the number of input relocations and
 * the following constants.
 */
#define	REL_HAIDESCNO	1000		/* high water mark active buckets */
#define	REL_LAIDESCNO	50		/* low water mark active buckets */
#define	REL_HOIDESCNO	500		/* high water mark output buckets */
#define	REL_LOIDESCNO	10		/* low water mark output buckets */

extern Ofl_desc		Ofl;
extern char		*Plibpath;
extern char		*Llibdir;
extern char		*Ulibdir;
extern Ehdr		def_ehdr;
extern Ld_heap		*ld_heap;
extern List		lib_support;
extern const Msg	reject[];
extern uint_t		dbg_mask;

extern int		Verbose;

/*
 * For backward compatibility provide a /dev/zero file descriptor.
 */
extern int		dz_fd;

/*
 * Local functions.
 */
extern uintptr_t	add_actrel(Word, Rel_desc *, Ofl_desc *);
extern uintptr_t	add_libdir(Ofl_desc *, const char *);
extern uintptr_t	add_outrel(Word, Rel_desc *, Ofl_desc *);
extern uintptr_t	add_regsym(Sym_desc *, Ofl_desc *);
extern void 		adj_movereloc(Ofl_desc *, Rel_desc *);
extern void		*alist_append(Alist **, const void *, size_t, int);
extern Sym_desc * 	am_I_partial(Rel_desc *, Xword);
extern Ar_desc *	ar_setup(const char *, Elf *, Ofl_desc *);
extern void		ar_member(Ar_desc *, Elf_Arsym *, Ar_aux *, Ar_mem *);
#if	defined(sparc)
extern uintptr_t	allocate_got(Ofl_desc *);
extern uintptr_t	assign_got(Sym_desc *);
#endif
extern uintptr_t	assign_gotndx(List *, Gotndx *, Gotref, Ofl_desc *,
			    Rel_desc *, Sym_desc *);
extern void		assign_plt_ndx(Sym_desc *, Ofl_desc *);
extern Xword		calc_got_offset(Rel_desc *, Ofl_desc *);
extern Xword		calc_plt_addr(Sym_desc *, Ofl_desc *);
extern int		dbg_setup(const char *);
extern const char	*demangle(const char *);
extern void		disp_errmsg(const char *, Rel_desc *, Ofl_desc *);
extern uintptr_t	do_activerelocs(Ofl_desc *);
extern void		ent_check(Ofl_desc *);
extern uintptr_t	fillin_gotplt1(Ofl_desc *);
extern Addr		fillin_gotplt2(Ofl_desc *);
extern Gotndx *		find_gotndx(List *, Gotref, Ofl_desc *, Rel_desc *);
extern uintptr_t	find_library(const char *, Ofl_desc *);
extern Group_desc *	get_group_desc(Ofl_desc *, Is_desc *);
extern Word		hashbkts(Word);
extern Xword		lcm(Xword, Xword);
extern int		ldexit(void);
extern void		ldmap_out(Ofl_desc *);
extern uintptr_t	lib_setup(Ofl_desc *);
extern Listnode *	list_where(List *, Word);
extern void		init();
extern Word		init_rel(Rel_desc *, void *);
extern const char	*is_regsym(Ifl_desc *, Sym *, const char *, int, Word,
			    const char *, Word *);
extern void		mach_eflags(Ehdr *, Ofl_desc *);
extern void		mach_make_dynamic(Ofl_desc *, size_t *);
extern void		mach_update_odynamic(Ofl_desc *, Dyn **);
extern int		mach_sym_typecheck(Sym_desc *, Sym *, Ifl_desc *,
			    Ofl_desc *);
extern uintptr_t	make_bss(Ofl_desc *, Xword, Xword, uint_t);
extern uintptr_t	make_got(Ofl_desc *);
extern uintptr_t	make_reloc(Ofl_desc *, Os_desc *);
extern uintptr_t	make_sunwbss(Ofl_desc *, size_t, Xword);
extern uintptr_t	make_sunwdata(Ofl_desc *, size_t, Xword);
extern uintptr_t	make_sunwmove(Ofl_desc *, int);
extern uintptr_t	map_parse(const char *, Ofl_desc *);
extern uintptr_t	perform_outreloc(Rel_desc *, Ofl_desc *);
extern Os_desc *	place_section(Ofl_desc *, Is_desc *, int, Word);
extern uintptr_t	process_archive(const char *, int, Ar_desc *,
			    Ofl_desc *);
extern uintptr_t	process_flags(Ofl_desc *, int, char **);
extern uintptr_t	process_files(Ofl_desc *, int, char **);
extern Ifl_desc *	process_ifl(const char *, const char *, int, Elf *,
			    Half, Ofl_desc *, Rej_desc *);
extern uintptr_t	process_ordered(Ifl_desc *, Ofl_desc *, Word, Word);
extern uintptr_t	process_section(const char *, Ifl_desc *, Shdr *,
			    Elf_Scn *, Word, int, Ofl_desc *);
extern uintptr_t	process_sym_reloc(Ofl_desc *, Rel_desc *, Rel *,
			    Is_desc *, const char *);
extern int		reg_check(Sym_desc *, Sym *, const char *, Ifl_desc *,
			    Ofl_desc *);
extern int		reg_enter(Sym_desc *, Ofl_desc *);
extern Sym_desc *	reg_find(Sym *, Ofl_desc *);
extern uintptr_t	reloc_local(Rel_desc *, Ofl_desc *);
extern uintptr_t	reloc_plt(Rel_desc *, Ofl_desc *);
extern uintptr_t	reloc_register(Rel_desc *, Is_desc *, Ofl_desc *);
extern uintptr_t	reloc_relobj(Boolean, Rel_desc *, Ofl_desc *);
extern void		reloc_remain_entry(Rel_desc *, Os_desc *, Ofl_desc *);
extern uintptr_t	reloc_GOT_relative(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	reloc_GOTOP(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	reloc_TLS(Boolean, Rel_desc *, Ofl_desc *);
extern uintptr_t	sort_ordered(Ofl_desc *);
extern uintptr_t	sort_seg_list(Ofl_desc *);
extern void		sym_adjust_vis(Sym_desc *, Ofl_desc *);
extern int		sym_avl_comp(const void *, const void *);
extern uintptr_t	sym_copy(Sym_desc *);
extern uintptr_t	sym_nodirect(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	sym_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	sym_resolve(Sym_desc *, Sym *, Ifl_desc *, Ofl_desc *,
				int, Word, Word);
extern uintptr_t	sym_spec(Ofl_desc *);
extern uintptr_t	vers_def_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern uintptr_t	vers_need_process(Is_desc *, Ifl_desc *, Ofl_desc *);
extern int		vers_sym_process(Is_desc *, Ifl_desc *);
extern uintptr_t	vers_check_need(Ofl_desc *);
extern void		vers_promote(Sym_desc *, Word, Ifl_desc *, Ofl_desc *);
extern int		vers_verify(Ofl_desc *);

/*
 * AMD64 - 64-bit specific functions
 */
#if defined(__x86) && defined(_ELF64)
extern uintptr_t	make_amd64_unwindhdr(Ofl_desc *);
extern uintptr_t	process_amd64_unwind(const char *, Ifl_desc *, Shdr *,
			    Elf_Scn *, Word, int, Ofl_desc *);
extern uintptr_t	populate_amd64_unwindhdr(Ofl_desc *);
extern uintptr_t	append_amd64_unwind(Os_desc *, Ofl_desc *);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _LIBLD_DOT_H */
