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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<dlfcn.h>
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

#if	!(defined(_ELF64))

void
Dbg_syms_lookup_aout(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AOUT), Dbg_demangle_name(name));
}

#endif

void
Dbg_syms_lookup(Rt_map *lmp, const char *name, const char *type)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_LOOKUP), Dbg_demangle_name(name),
	    NAME(lmp), type);
}

void
Dbg_syms_ignore_gnuver(Rt_map *lmp, const char *name, Word symndx,
    Versym verndx)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_IGNGNUVER), Dbg_demangle_name(name),
	    EC_WORD(symndx), EC_HALF(verndx), NAME(lmp));
}

void
Dbg_syms_dlsym(Rt_map *clmp, const char *sym, int *in_nfavl, const char *next,
    int flag)
{
	const char	*str, *retry, *from = NAME(clmp);
	Lm_list		*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	/*
	 * The core functionality of dlsym() can be called twice.  The first
	 * attempt can be affected by path names that exist in the "not-found"
	 * AVL tree.  Should a "not-found" path name be found, a second attempt
	 * is made to locate the required file (in_nfavl is NULL).  This fall-
	 * back provides for file system changes while a process executes.
	 */
	if (in_nfavl)
		retry = MSG_ORIG(MSG_STR_EMPTY);
	else
		retry = MSG_INTL(MSG_STR_RETRY);

	switch (flag) {
	case DBG_DLSYM_NEXT:
		str = MSG_ORIG(MSG_SYM_NEXT);
		break;
	case DBG_DLSYM_DEFAULT:
		str = MSG_ORIG(MSG_SYM_DEFAULT);
		break;
	case DBG_DLSYM_SELF:
		str = MSG_ORIG(MSG_SYM_SELF);
		break;
	case DBG_DLSYM_PROBE:
		str = MSG_ORIG(MSG_SYM_PROBE);
		break;
	case DBG_DLSYM_SINGLETON:
		str = MSG_ORIG(MSG_SYM_SINGLETON);
		break;
	default:
		str = MSG_ORIG(MSG_STR_EMPTY);
	}

	Dbg_util_nl(lml, DBG_NL_STD);
	if (next == 0)
		dbg_print(lml, MSG_INTL(MSG_SYM_DLSYM_1),
		    Dbg_demangle_name(sym), from, retry, str);
	else
		dbg_print(lml, MSG_INTL(MSG_SYM_DLSYM_2),
		    Dbg_demangle_name(sym), from, next, retry, str);
}

void
Dbg_syms_lazy_rescan(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_LAZY_RESCAN), Dbg_demangle_name(name));
}

void
Dbg_syms_ar_title(Lm_list *lml, const char *file, int again)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_AR_FILE), file,
	    again ? MSG_INTL(MSG_STR_AGAIN) : MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_syms_ar_entry(Lm_list *lml, Xword ndx, Elf_Arsym *arsym)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_ENTRY), EC_XWORD(ndx),
	    Dbg_demangle_name(arsym->as_name));
}

void
Dbg_syms_ar_checking(Lm_list *lml, Xword ndx, Elf_Arsym *arsym,
    const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_CHECK), EC_XWORD(ndx),
	    Dbg_demangle_name(arsym->as_name), name);
}

void
Dbg_syms_ar_resolve(Lm_list *lml, Xword ndx, Elf_Arsym *arsym,
    const char *fname, int flag)
{
	const char	*fmt;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	if (flag)
		fmt = MSG_INTL(MSG_SYM_AR_FORCEDEXRT);
	else
		fmt = MSG_INTL(MSG_SYM_AR_RESOLVE);

	dbg_print(lml, fmt, EC_XWORD(ndx), Dbg_demangle_name(arsym->as_name),
	    fname);
}

void
Dbg_syms_spec_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_SPECIAL));
}

void
Dbg_syms_discarded(Lm_list *lml, Sym_desc *sdp)
{
	const char	*file;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_UNUSED))
		return;
	if (DBG_NOTDETAIL())
		return;

	if ((sdp->sd_file == NULL) || ((file = sdp->sd_file->ifl_name) == NULL))
		file = MSG_INTL(MSG_STR_UNKNOWN);

	if (sdp->sd_isc) {
		const char	*sec;

		if ((sec = sdp->sd_isc->is_basename) == 0)
			sec = sdp->sd_isc->is_name;
		dbg_print(lml, MSG_INTL(MSG_SYM_DISCARD_SEC),
		    Dbg_demangle_name(sdp->sd_name), sec, file);
	} else
		dbg_print(lml, MSG_INTL(MSG_SYM_DISCARD_FILE),
		    Dbg_demangle_name(sdp->sd_name), file);
}

void
Dbg_syms_dup_discarded(Lm_list *lml, Word ndx, Sym_desc *sdp)
{
	const char	*file;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_UNUSED))
		return;
	if (DBG_NOTDETAIL())
		return;

	if ((sdp->sd_file == NULL) || ((file = sdp->sd_file->ifl_name) == NULL))
		file = MSG_INTL(MSG_STR_UNKNOWN);

	dbg_print(lml, MSG_INTL(MSG_SYM_DISCARD_DUP), EC_WORD(ndx),
	    Dbg_demangle_name(sdp->sd_name), file);
}

void
Dbg_syms_entered(Ofl_desc *ofl, Sym *sym, Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_INTL(MSG_STR_ENTERED),
	    ofl->ofl_dehdr->e_machine, sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_process(Lm_list *lml, Ifl_desc *ifl)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_PROCESS), ifl->ifl_name,
	    conv_ehdr_type(ifl->ifl_ehdr->e_type, 0, &inv_buf));
}

void
Dbg_syms_entry(Lm_list *lml, Word ndx, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_BASIC), EC_WORD(ndx),
	    Dbg_demangle_name(sdp->sd_name));
}

void
Dbg_syms_global(Lm_list *lml, Word ndx, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_ADDING), EC_WORD(ndx),
	    Dbg_demangle_name(name));
}

void
Dbg_syms_sec_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_INDEX));
}

void
Dbg_syms_sec_entry(Lm_list *lml, Word ndx, Sg_desc *sgp, Os_desc *osp)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_SECTION), EC_WORD(ndx), osp->os_name,
	    (*sgp->sg_name ? sgp->sg_name : MSG_INTL(MSG_STR_NULL)));
}

void
Dbg_syms_up_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_FINAL));
	Elf_syms_table_title(lml, ELF_DBG_LD);
}

void
Dbg_syms_ignore(Ofl_desc *ofl, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_IGNORE),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym, 0, 0, NULL,
	    MSG_INTL(MSG_STR_UNUSED));
}

void
Dbg_syms_old(Ofl_desc *ofl, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_OLD),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL, sdp->sd_name);
}

void
Dbg_syms_new(Ofl_desc *ofl, Sym *sym, Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_NEW),
	    ofl->ofl_dehdr->e_machine, sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_updated(Ofl_desc *ofl, Sym_desc *sdp, const char *name)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_UPDATE), name);

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_ORIG(MSG_STR_EMPTY),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_created(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_CREATE), Dbg_demangle_name(name));
}

void
Dbg_syms_resolving(Ofl_desc *ofl, Word ndx, const char *name, int row,
    int col, Sym *osym, Sym *nsym, Sym_desc *sdp, Ifl_desc *ifl)
{
	Lm_list	*lml = ofl->ofl_lml;
	Half	mach = ofl->ofl_dehdr->e_machine;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_RESOLVING), EC_WORD(ndx),
	    Dbg_demangle_name(name), row, col);

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_OLD),
	    mach, osym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    sdp->sd_file->ifl_name);

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_NEW),
	    mach, nsym, 0, 0, NULL, ifl->ifl_name);
}

void
Dbg_syms_resolved(Ofl_desc *ofl, Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD,
	    MSG_INTL(MSG_STR_RESOLVED), ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_reloc(Ofl_desc *ofl, Sym_desc *sdp)
{
	static Boolean	symbol_title = TRUE;
	Conv_inv_buf_t	inv_buf;
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	if (symbol_title) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_SYM_BSS));

		symbol_title = FALSE;
	}
	dbg_print(lml, MSG_INTL(MSG_SYM_UPDATE),
	    Dbg_demangle_name(sdp->sd_name));

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_ORIG(MSG_SYM_COPY),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_reduce(Ofl_desc *ofl, int which, Sym_desc *sdp, int idx,
    const char *sname)
{
	static Boolean	sym_reduce_title = TRUE;
	static Boolean	sym_retain_title = TRUE;
	Boolean		isfromglobal = (which == DBG_SYM_REDUCE_GLOBAL);
	Boolean		isfromretain = (which == DBG_SYM_REDUCE_RETAIN);
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_VERSIONS))
		return;

	if (sym_reduce_title && isfromglobal) {
		sym_reduce_title = FALSE;
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_SYM_REDUCED));
	} else if (sym_retain_title && isfromretain) {
		sym_retain_title = FALSE;
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_SYM_RETAINING));
	}

	if ((sdp->sd_flags1 & FLG_SY1_ELIM) && isfromglobal)
		dbg_print(lml, MSG_INTL(MSG_SYM_ELIMINATING),
		    Dbg_demangle_name(sdp->sd_name));
	else if (isfromglobal)
		dbg_print(lml, MSG_INTL(MSG_SYM_REDUCING),
		    Dbg_demangle_name(sdp->sd_name));
	else
		dbg_print(lml, MSG_INTL(MSG_SYM_NOTELIMINATE),
		    Dbg_demangle_name(sdp->sd_name), sname, idx);

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_ORIG(MSG_SYM_LOCAL),
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    sdp->sd_file->ifl_name);
}

void
Dbg_syms_dup_sort_addr(Lm_list *lml, const char *secname, const char *symname1,
    const char *symname2, Addr addr)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS) || DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_DUPSORTADDR), secname,
	    symname1, symname2, EC_ADDR(addr));
}

void
Dbg_syminfo_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYMINFO_INFO));
	Elf_syminfo_title(lml);
}

void
Dbg_syminfo_entry(Lm_list *lml, Word ndx, Syminfo *sip, Sym *sym,
    const char *strtab, Dyn *dyn)
{
	const char	*needed;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sip->si_boundto < SYMINFO_BT_LOWRESERVE)
		needed = strtab + dyn[sip->si_boundto].d_un.d_val;
	else
		needed = 0;

	Elf_syminfo_entry(lml, ndx, sip,
	    Dbg_demangle_name(strtab + sym->st_name), needed);
}

/*
 * Symbol table output can differ slightly depending on the caller.  However,
 * the final diagnostic is maintained here so hat the various message strings
 * remain consistent
 *
 * elfdump:   index    value       size     type bind oth ver shndx       name
 * ld:                 value       size     type bind oth ver shndx
 */
void
Elf_syms_table_title(Lm_list *lml, int caller)
{
	if (caller == ELF_DBG_ELFDUMP) {
		if (DBG_NOTLONG())
			dbg_print(lml, MSG_INTL(MSG_SYM_EFS_TITLE));
		else
			dbg_print(lml, MSG_INTL(MSG_SYM_EFL_TITLE));
		return;
	}

	if (caller == ELF_DBG_LD) {
		if (DBG_NOTLONG())
			dbg_print(lml, MSG_INTL(MSG_SYM_LDS_TITLE));
		else
			dbg_print(lml, MSG_INTL(MSG_SYM_LDL_TITLE));
		return;
	}
}

void
Elf_syms_table_entry(Lm_list *lml, int caller, const char *prestr, Half mach,
    Sym *sym, Versym verndx, int gnuver, const char *sec, const char *poststr)
{
	Conv_inv_buf_t	inv_buf1, inv_buf2, inv_buf3;
	Conv_inv_buf_t	inv_buf4, inv_buf5, inv_buf6;
	uchar_t		type = ELF_ST_TYPE(sym->st_info);
	uchar_t		bind = ELF_ST_BIND(sym->st_info);
	const char	*msg;

	if ((caller == ELF_DBG_ELFDUMP) ||
	    (caller == ELF_DBG_LD)) {
		if (DBG_NOTLONG())
			msg = MSG_INTL(MSG_SYM_EFS_ENTRY);
		else
			msg = MSG_INTL(MSG_SYM_EFL_ENTRY);

		dbg_print(lml, msg, prestr,
		    conv_sym_value(mach, type, sym->st_value, &inv_buf1),
		    sym->st_size, conv_sym_info_type(mach, type, 0, &inv_buf2),
		    conv_sym_info_bind(bind, 0, &inv_buf3),
		    conv_sym_other(sym->st_other, &inv_buf4),
		    conv_ver_index(verndx, gnuver, &inv_buf5),
		    sec ? sec : conv_sym_shndx(sym->st_shndx, &inv_buf6),
		    Elf_demangle_name(poststr));
	}
}
