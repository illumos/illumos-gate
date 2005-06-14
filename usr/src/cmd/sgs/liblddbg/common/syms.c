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
 *	Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<dlfcn.h>
#include	<strings.h>
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Print out a single `symbol table node' entry.
 */
#if	!defined(_ELF64)
void
Gelf_sym_table_title(GElf_Ehdr *ehdr, const char *index, const char *name)
{
	if ((int)ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
		if (DBG_NOTLONG())
			dbg_print(MSG_ORIG(MSG_SYM_TITLE_64), index, name);
		else
			dbg_print(MSG_ORIG(MSG_SYM_L_TITLE_64), index, name);
	} else {
		if (DBG_NOTLONG())
			dbg_print(MSG_ORIG(MSG_SYM_TITLE), index, name);
		else
			dbg_print(MSG_ORIG(MSG_SYM_L_TITLE), index, name);
	}
}
void
Elf_sym_table_entry(const char *prestr, Elf32_Ehdr *ehdr, Elf32_Sym *sym,
    Elf32_Word verndx, const char *sec, const char *poststr)
{
	const char *msg;

	if (DBG_NOTLONG())
		msg = MSG_ORIG(MSG_SYM_ENTRY);
	else
		msg = MSG_ORIG(MSG_SYM_L_ENTRY);

	dbg_print(msg, prestr,
	    conv_sym_value_str(ehdr->e_machine, ELF32_ST_TYPE(sym->st_info),
	    EC_XWORD(sym->st_value)), EC_XWORD(sym->st_size),
	    conv_info_type_str(ehdr->e_machine, ELF32_ST_TYPE(sym->st_info)),
	    conv_info_bind_str(ELF32_ST_BIND(sym->st_info)),
	    conv_sym_stother(sym->st_other), EC_WORD(verndx),
	    sec ? sec : conv_shndx_str(sym->st_shndx),
	    _Dbg_sym_dem(poststr));
}

void
Gelf_sym_table_entry(const char *prestr, GElf_Ehdr *ehdr, GElf_Sym *sym,
    GElf_Word verndx, const char *sec, const char *poststr)
{
	const char *msg;

	if ((int)ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_SYM_ENTRY_64);
		else
			msg = MSG_ORIG(MSG_SYM_L_ENTRY_64);
	} else {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_SYM_ENTRY);
		else
			msg = MSG_ORIG(MSG_SYM_L_ENTRY);
	}

	dbg_print(msg, prestr, conv_sym_value_str(ehdr->e_machine,
	    GELF_ST_TYPE(sym->st_info), EC_XWORD(sym->st_value)),
	    EC_XWORD(sym->st_size),
	    conv_info_type_str(ehdr->e_machine, GELF_ST_TYPE(sym->st_info)),
	    conv_info_bind_str(GELF_ST_BIND(sym->st_info)),
	    conv_sym_stother(sym->st_other), EC_WORD(verndx),
	    sec ? sec : conv_shndx_str(sym->st_shndx),
	    _Dbg_sym_dem(poststr));
}

void
Gelf_syminfo_title()
{
	dbg_print(MSG_INTL(MSG_SYMI_TITLE2));
}

void
Gelf_syminfo_entry(int ndx, GElf_Syminfo *sip, const char *sname,
    const char *needed)
{
	const char	*bind_str;
	char		flags[16], index[32], bind_index[32] = " ";
	int		flgndx = 0;
	Half		symflags;

	symflags = sip->si_flags;

	if (symflags & SYMINFO_FLG_DIRECT) {
		if (sip->si_boundto == SYMINFO_BT_SELF)
			bind_str = MSG_INTL(MSG_SYMI_SELF);
		else if (sip->si_boundto == SYMINFO_BT_PARENT)
			bind_str = MSG_INTL(MSG_SYMI_PARENT);
		else {
			bind_str = needed;
			(void) sprintf(bind_index, MSG_ORIG(MSG_FMT_INDEX),
				sip->si_boundto);
		}
		flags[flgndx++] = 'D';
		symflags &= ~SYMINFO_FLG_DIRECT;

	} else if (symflags & (SYMINFO_FLG_FILTER | SYMINFO_FLG_AUXILIARY)) {
		bind_str = needed;
		(void) sprintf(bind_index, MSG_ORIG(MSG_FMT_INDEX),
		    sip->si_boundto);

		if (symflags & SYMINFO_FLG_FILTER) {
			flags[flgndx++] = 'F';
			symflags &= ~SYMINFO_FLG_FILTER;
		}
		if (symflags & SYMINFO_FLG_AUXILIARY) {
			flags[flgndx++] = 'A';
			symflags &= ~SYMINFO_FLG_AUXILIARY;
		}
	} else if (sip->si_boundto == SYMINFO_BT_EXTERN) {
		bind_str = MSG_INTL(MSG_SYMI_EXTERN);
	} else
		bind_str = MSG_ORIG(MSG_STR_EMPTY);

	if (symflags & SYMINFO_FLG_DIRECTBIND) {
		flags[flgndx++] = 'B';
		symflags &= ~SYMINFO_FLG_DIRECTBIND;
	}
	if (symflags & SYMINFO_FLG_COPY) {
		flags[flgndx++] = 'C';
		symflags &= ~SYMINFO_FLG_COPY;
	}
	if (symflags & SYMINFO_FLG_LAZYLOAD) {
		flags[flgndx++] = 'L';
		symflags &= ~SYMINFO_FLG_LAZYLOAD;
	}
	if (symflags & SYMINFO_FLG_NOEXTDIRECT) {
		flags[flgndx++] = 'N';
		symflags &= ~SYMINFO_FLG_NOEXTDIRECT;
	}

	/*
	 * Did we account for all of the flags?
	 */
	if (symflags)
		(void) sprintf(&flags[flgndx], " 0x%x", symflags);
	else
		flags[flgndx] = '\0';

	(void) sprintf(index, MSG_ORIG(MSG_FMT_INDEX), ndx);
	dbg_print(MSG_ORIG(MSG_SYMI_FMT), index, flags, bind_index, bind_str,
	    _Dbg_sym_dem(sname));
}


const char *
Gelf_sym_dem(const char *name)
{
	return (conv_sym_dem(name));
}

const char *
_Dbg_sym_dem(const char *name)
{
	if (DBG_NOTCLASS(DBG_DEMANGLE))
		return (name);

	return (conv_sym_dem(name));
}

void
Dbg_syms_ar_title(const char *file, int again)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_AR_FILE), file,
	    again ? MSG_INTL(MSG_STR_AGAIN) : MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_syms_lazy_rescan(const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS | DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_LAZY_RESCAN), _Dbg_sym_dem(name));
}

#endif /* !defined(_ELF64) */

void
Dbg_syms_ar_entry(Xword ndx, Elf_Arsym *arsym)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_AR_ENTRY), EC_XWORD(ndx),
	    _Dbg_sym_dem(arsym->as_name));
}

void
Dbg_syms_ar_checking(Xword ndx, Elf_Arsym *arsym, const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_AR_CHECK), EC_XWORD(ndx),
	    _Dbg_sym_dem(arsym->as_name), name);
}

void
Dbg_syms_ar_resolve(Xword ndx, Elf_Arsym *arsym, const char *fname, int flag)
{
	const char	*fmt;

	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	if (flag)
		fmt = MSG_INTL(MSG_SYM_AR_FORCEDEXRT);
	else
		fmt = MSG_INTL(MSG_SYM_AR_RESOLVE);

	dbg_print(fmt, EC_XWORD(ndx), _Dbg_sym_dem(arsym->as_name), fname);
}

void
Dbg_syms_spec_title()
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_SPECIAL));
}

void
Dbg_syms_discarded(Sym_desc *sdp, Is_desc *disp)
{
	const char	*sectname;
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	if ((sectname = disp->is_basename) == 0)
		sectname = disp->is_name;

	dbg_print(MSG_INTL(MSG_SYM_DISCARDED), _Dbg_sym_dem(sdp->sd_name),
		sectname, disp->is_file->ifl_name);
}


void
Dbg_syms_entered(Ehdr *ehdr, Sym *sym, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_ENTERED), ehdr, sym, sdp->sd_aux ?
	    sdp->sd_aux->sa_overndx : 0, NULL, conv_deftag_str(sdp->sd_ref));
}

void
Dbg_syms_process(Ifl_desc *ifl)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_PROCESS), ifl->ifl_name,
	    conv_etype_str(ifl->ifl_ehdr->e_type));
}

void
Dbg_syms_entry(Xword ndx, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_BASIC), EC_XWORD(ndx),
	    _Dbg_sym_dem(sdp->sd_name));
}

void
Dbg_syms_global(Xword ndx, const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_ADDING), EC_XWORD(ndx), _Dbg_sym_dem(name));
}

void
Dbg_syms_sec_title()
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_INDEX));
}

void
Dbg_syms_sec_entry(int ndx, Sg_desc *sgp, Os_desc *osp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_SYM_SECTION), ndx, osp->os_name,
		(*sgp->sg_name ? sgp->sg_name : MSG_INTL(MSG_STR_NULL)));
}

void
Dbg_syms_up_title(Ehdr *ehdr)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_FINAL));
	/* LINTED */
	Gelf_sym_table_title((GElf_Ehdr *)ehdr,
	    MSG_ORIG(MSG_STR_EMPTY), MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_syms_ignore(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_IGNORE), ehdr, sdp->sd_sym,
	    0, NULL, MSG_INTL(MSG_STR_UNUSED));
}

void
Dbg_syms_old(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_OLD), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL, sdp->sd_name);
}

void
Dbg_syms_new(Ehdr *ehdr, Sym *sym, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_NEW), ehdr, sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    conv_deftag_str(sdp->sd_ref));
}

void
Dbg_syms_updated(Ehdr *ehdr, Sym_desc *sdp, const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_UPDATE), name);

	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_ORIG(MSG_STR_EMPTY), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    conv_deftag_str(sdp->sd_ref));
}

void
Dbg_syms_created(const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_CREATE), _Dbg_sym_dem(name));
}

void
Dbg_syms_resolving1(Xword ndx, const char *name, int row, int col)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_RESOLVING), EC_XWORD(ndx),
	    _Dbg_sym_dem(name), row, col);
}

void
Dbg_syms_resolving2(Ehdr *ehdr, Sym *osym, Sym *nsym, Sym_desc *sdp,
	Ifl_desc *ifl)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_OLD), ehdr, osym, sdp->sd_aux ?
	    sdp->sd_aux->sa_overndx : 0, NULL, sdp->sd_file->ifl_name);
	Elf_sym_table_entry(MSG_INTL(MSG_STR_NEW), ehdr, nsym, 0, NULL,
	    ifl->ifl_name);
}

void
Dbg_syms_resolved(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_INTL(MSG_STR_RESOLVED), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    conv_deftag_str(sdp->sd_ref));
}

void
Dbg_syms_nl()
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

static Boolean	symbol_title = TRUE;

static void
_Dbg_syms_reloc_title()
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYM_BSS));

	symbol_title = FALSE;
}
void
Dbg_syms_reloc(Ehdr *ehdr, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	if (symbol_title)
		_Dbg_syms_reloc_title();
	dbg_print(MSG_INTL(MSG_SYM_UPDATE), _Dbg_sym_dem(sdp->sd_name));

	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_ORIG(MSG_SYM_COPY), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    conv_deftag_str(sdp->sd_ref));
}

void
Dbg_syms_lookup_aout(const char *name)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_AOUT), _Dbg_sym_dem(name));
}

void
Dbg_syms_lookup(const char *name, const char *file, const char *type)
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	dbg_print(MSG_INTL(MSG_SYM_LOOKUP), _Dbg_sym_dem(name), file, type);
}

void
Dbg_syms_dlsym(const char *sym, const char *from, const char *next, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;

	if (flag == DBG_DLSYM_NEXT)
		str = MSG_ORIG(MSG_SYM_NEXT);
	else if (flag == DBG_DLSYM_DEFAULT)
		str = MSG_ORIG(MSG_SYM_DEFAULT);
	else if (flag == DBG_DLSYM_SELF)
		str = MSG_ORIG(MSG_SYM_SELF);
	else if (flag == DBG_DLSYM_PROBE)
		str = MSG_ORIG(MSG_SYM_PROBE);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	if (next == 0)
		dbg_print(MSG_INTL(MSG_SYM_DLSYM_1), _Dbg_sym_dem(sym),
		    from, str);
	else
		dbg_print(MSG_INTL(MSG_SYM_DLSYM_2), _Dbg_sym_dem(sym),
		    from, next, str);
}

void
Dbg_syms_reduce(int which, Ehdr *ehdr, Sym_desc *sdp,
    int idx, const char *sname)
{
	static Boolean	sym_reduce_title = TRUE;
	static Boolean	sym_retain_title = TRUE;
	Boolean		isfromglobal = (which == DBG_SYM_REDUCE_GLOBAL);
	Boolean		isfromretain = (which == DBG_SYM_REDUCE_RETAIN);

	if (DBG_NOTCLASS(DBG_SYMBOLS | DBG_VERSIONS))
		return;

	if (sym_reduce_title && isfromglobal) {
		sym_reduce_title = FALSE;
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_SYM_REDUCED));
	} else if (sym_retain_title && isfromretain) {
		sym_retain_title = FALSE;
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_SYM_RETAINING));
	}

	if ((sdp->sd_flags1 & FLG_SY1_ELIM) && isfromglobal)
		dbg_print(MSG_INTL(MSG_SYM_ELIMINATING),
		    _Dbg_sym_dem(sdp->sd_name));
	else if (isfromglobal)
		dbg_print(MSG_INTL(MSG_SYM_REDUCING),
		    _Dbg_sym_dem(sdp->sd_name));
	else
		dbg_print(MSG_INTL(MSG_SYM_NOTELIMINATE),
		    _Dbg_sym_dem(sdp->sd_name), sname, idx);

	if (DBG_NOTDETAIL())
		return;

	Elf_sym_table_entry(MSG_ORIG(MSG_SYM_LOCAL), ehdr, sdp->sd_sym,
	    sdp->sd_aux ? sdp->sd_aux->sa_overndx : 0, NULL,
	    sdp->sd_file->ifl_name);
}


void
Dbg_syminfo_title()
{
	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SYMI_TITLE1));
	Gelf_syminfo_title();
}

void
Dbg_syminfo_entry(int ndx, Syminfo *sip, Sym *sym, const char *strtab,
	Dyn *dyn)
{
	const char	*needed;

	if (DBG_NOTCLASS(DBG_SYMBOLS))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sip->si_boundto < SYMINFO_BT_LOWRESERVE)
		needed = strtab + dyn[sip->si_boundto].d_un.d_val;
	else
		needed = 0;

	Gelf_syminfo_entry(ndx, (GElf_Syminfo *)sip,
	    _Dbg_sym_dem(strtab + sym->st_name), needed);
}
