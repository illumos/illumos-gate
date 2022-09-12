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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2022 Oxide Computer Company
 */

#include	<stdio.h>
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

void
Dbg_syms_lookup(Rt_map *lmp, const char *name, const char *type)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_LOOKUP), Dbg_demangle_name(name),
	    NAME(lmp), type);
}

static	const Msg captype[DBG_CAP_HW_3 + 1] = {
	MSG_CAP_SYM_DEFAULT,		/* MSG_INTL(MSG_CAP_SYM_DEFAULT) */
	MSG_CAP_SYM_USED,		/* MSG_INTL(MSG_CAP_SYM_USED) */
	MSG_CAP_SYM_CANDIDATE,		/* MSG_INTL(MSG_CAP_SYM_CANDIDATE) */
	MSG_CAP_SYM_REJECTED,		/* MSG_INTL(MSG_CAP_SYM_REJECTED) */
	MSG_CAP_SYM_HW_1,		/* MSG_INTL(MSG_CAP_SYM_HW_1) */
	MSG_CAP_SYM_SF_1,		/* MSG_INTL(MSG_CAP_SYM_SF_1) */
	MSG_CAP_SYM_HW_2,		/* MSG_INTL(MSG_CAP_SYM_HW_2) */
	MSG_CAP_SYM_PLAT,		/* MSG_INTL(MSG_CAP_SYM_PLAT) */
	MSG_CAP_SYM_MACH,		/* MSG_INTL(MSG_CAP_SYM_MACH) */
	MSG_CAP_SYM_HW_3		/* MSG_INTL(MSG_CAP_SYM_HW_3) */
};

void
Dbg_syms_cap_lookup(Rt_map *lmp, uint_t type, const char *name, uint_t ndx,
    Half mach, Syscapset *scapset)
{
	Lm_list			*lml = LIST(lmp);
	const char		*str = NULL;
	Conv_cap_val_buf_t	cap_val_buf;

	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_SYMBOLS))
		return;

	switch (type) {
	case DBG_CAP_HW_1:
		str = conv_cap_val_hw1(scapset->sc_hw_1, mach, 0,
		    &cap_val_buf.cap_val_hw1_buf);
		break;
	case DBG_CAP_SF_1:
		str = conv_cap_val_sf1(scapset->sc_sf_1, mach, 0,
		    &cap_val_buf.cap_val_sf1_buf);
		break;
	case DBG_CAP_HW_2:
		str = conv_cap_val_hw2(scapset->sc_hw_2, mach, 0,
		    &cap_val_buf.cap_val_hw2_buf);
		break;
	case DBG_CAP_MACH:
		str = scapset->sc_mach;
		break;
	case DBG_CAP_PLAT:
		str = scapset->sc_plat;
		break;
	case DBG_CAP_HW_3:
		str = conv_cap_val_hw3(scapset->sc_hw_3, mach, 0,
		    &cap_val_buf.cap_val_hw3_buf);
		break;
	}

	dbg_print(lml, MSG_INTL(captype[type]), Dbg_demangle_name(name),
	    ndx, str);
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
Dbg_syms_lazy_rescan(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_LAZY_RESCAN), Dbg_demangle_name(name));
}

void
Dbg_syms_ar_title(Lm_list *lml, const char *file, Boolean again)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_FILE), file,
	    again ? MSG_INTL(MSG_STR_AGAIN) : MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_syms_ar_skip(Lm_list *lml, const char *archive, Elf_Arsym *arsym)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_SKIP), archive,
	    Dbg_demangle_name(arsym->as_name));
}

void
Dbg_syms_ar_checking(Lm_list *lml, const char *fname, const char *objname,
    Elf_Arsym *arsym)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_CHECK), fname, objname,
	    Dbg_demangle_name(arsym->as_name));
}

void
Dbg_syms_ar_resolve(Lm_list *lml, const char *fname, const char *objname,
    Elf_Arsym *arsym)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_RESOLVE), fname, objname,
	    Dbg_demangle_name(arsym->as_name));
}

void
Dbg_syms_ar_force(Lm_list *lml, const char *fname, const char *objname)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_AR_FORCE), fname, objname);
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
	dbg_isec_name_buf_t	buf;
	char			*alloc_mem;
	const char		*file;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_UNUSED))
		return;
	if (DBG_NOTDETAIL())
		return;

	if ((sdp->sd_file == NULL) || ((file = sdp->sd_file->ifl_name) == NULL))
		file = MSG_INTL(MSG_STR_UNKNOWN);

	if (sdp->sd_isc) {
		dbg_print(lml, MSG_INTL(MSG_SYM_DISCARD_SEC),
		    Dbg_demangle_name(sdp->sd_name),
		    dbg_fmt_isec_name(sdp->sd_isc, buf, &alloc_mem), file);
		if (alloc_mem != NULL)
			free(alloc_mem);
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine, sym,
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
	    conv_ehdr_type(ifl->ifl_ehdr->e_ident[EI_OSABI],
	    ifl->ifl_ehdr->e_type, 0, &inv_buf));
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
Dbg_syms_cap_convert(Ofl_desc *ofl, Word ndx, const char *name, Sym *sym)
{
	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_SYMBOLS))
		return;

	dbg_print(ofl->ofl_lml, MSG_INTL(MSG_SYM_CAP_ORIG), EC_WORD(ndx),
	    Dbg_demangle_name(name));

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD,
	    MSG_INTL(MSG_STR_ORIGINAL), ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, sym, 0, 0, NULL,
	    MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_syms_cap_local(Ofl_desc *ofl, Word ndx, const char *name, Sym *sym,
    Sym_desc *sdp)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_CAP | DBG_C_SYMBOLS))
		return;

	dbg_print(ofl->ofl_lml, MSG_INTL(MSG_SYM_CAP_LOCAL), EC_WORD(ndx),
	    Dbg_demangle_name(name));

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD,
	    MSG_INTL(MSG_STR_ENTERED), ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_wrap(Lm_list *lml, Word ndx, const char *orig_name, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_WRAP), EC_WORD(ndx),
	    Dbg_demangle_name(orig_name), Dbg_demangle_name(name));
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, 0, 0, NULL, MSG_INTL(MSG_STR_UNUSED));
}

void
Dbg_syms_old(Ofl_desc *ofl, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_OLD),
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0,
	    0, NULL, sdp->sd_name);
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine, sym,
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
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
	uchar_t	osabi = ofl->ofl_dehdr->e_ident[EI_OSABI];
	Half	mach = ofl->ofl_dehdr->e_machine;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;

	dbg_print(lml, MSG_INTL(MSG_SYM_RESOLVING), EC_WORD(ndx),
	    Dbg_demangle_name(name), row, col);

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_OLD),
	    osabi, mach, osym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0,
	    0, NULL, sdp->sd_file->ifl_name);

	Elf_syms_table_entry(ofl->ofl_lml, ELF_DBG_LD, MSG_INTL(MSG_STR_NEW),
	    osabi, mach, nsym, 0, 0, NULL, ifl->ifl_name);
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
	    MSG_INTL(MSG_STR_RESOLVED), ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
	    conv_def_tag(sdp->sd_ref, &inv_buf));
}

void
Dbg_syms_copy_reloc(Ofl_desc *ofl, Sym_desc *sdp, Word align)
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

	/*
	 * Copy relocation symbols come in pairs, the original reference
	 * (within a dependency), and the new destination (within the .bss of
	 * the executable).  The latter is accompanied with a computed
	 * alignment.
	 */
	if (align) {
		dbg_print(lml, MSG_INTL(MSG_SYM_COPY_DST),
		    Dbg_demangle_name(sdp->sd_name), EC_WORD(align));
	} else {
		dbg_print(lml, MSG_INTL(MSG_SYM_COPY_REF),
		    Dbg_demangle_name(sdp->sd_name));
	}

	if (DBG_NOTDETAIL())
		return;

	Elf_syms_table_entry(lml, ELF_DBG_LD, MSG_ORIG(MSG_SYM_COPY),
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
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

	if ((sdp->sd_flags & FLG_SY_ELIM) && isfromglobal)
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
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    sdp->sd_sym, sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, 0, NULL,
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
Elf_syms_table_entry(Lm_list *lml, int caller, const char *prestr,
    uchar_t osabi, Half mach, Sym *sym, Versym verndx, int gnuver,
    const char *sec, const char *poststr)
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

		if (sec == NULL)
			sec = conv_sym_shndx(osabi, mach, sym->st_shndx,
			    CONV_FMT_DECIMAL, &inv_buf6);

		dbg_print(lml, msg, prestr,
		    conv_sym_value(mach, type, sym->st_value, &inv_buf1),
		    sym->st_size, conv_sym_info_type(mach, type, 0, &inv_buf2),
		    conv_sym_info_bind(bind, 0, &inv_buf3),
		    conv_sym_other(sym->st_other, &inv_buf4),
		    conv_ver_index(verndx, gnuver, &inv_buf5),
		    sec, Elf_demangle_name(poststr));
	}
}

void
Dbg_syms_cap_title(Ofl_desc *ofl)
{
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SYM_CAPABILITIES));
	Elf_syms_table_title(lml, ELF_DBG_LD);
}
