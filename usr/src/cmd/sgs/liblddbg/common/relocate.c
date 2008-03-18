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

#include	<sys/elf_SPARC.h>
#include	<debug.h>
#include	<libld.h>
#include	<conv.h>
#include	"_debug.h"
#include	"msg.h"

void
Dbg_reloc_apply_reg(Lm_list *lml, int caller, Half mach, Xword off, Xword value)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Print the actual relocation being applied to the specified output
	 * section, the offset represents the actual relocation address, and the
	 * value is the new data being written to that address.
	 */
	Elf_reloc_apply_reg(lml, caller, mach, off, value);
}

void
Dbg_reloc_apply_val(Lm_list *lml, int caller, Xword off, Xword value)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Print the actual relocation being applied to the specified output
	 * section, the offset represents the actual relocation address, and the
	 * value is the new data being written to that address.
	 */
	Elf_reloc_apply_val(lml, caller, off, value);
}

void
Dbg_reloc_error(Lm_list *lml, int caller, Half mach, Word type, void *reloc,
    const char *sname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_reloc_entry_1(lml, caller, MSG_INTL(MSG_STR_IN), mach, type, reloc,
	    NULL, sname, MSG_INTL(MSG_REL_BADROFFSET));
}

void
Dbg_reloc_run(Rt_map *lmp, uint_t rtype, int info, int dtype)
{
	Lm_list		*lml = LIST(lmp);
	const char	*str, *name = NAME(lmp);

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;

	if (dtype == DBG_REL_FINISH) {
		if (info)
			str = MSG_ORIG(MSG_STR_EMPTY);
		else
			str = MSG_INTL(MSG_REL_FAIL);
	} else {
		if (info)
			str = MSG_INTL(MSG_REL_PLT);
		else
			str = MSG_ORIG(MSG_STR_EMPTY);
	}

	if (dtype == DBG_REL_START) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_REL_START), name, str);

		if (DBG_NOTDETAIL())
			return;

		Elf_reloc_title(lml, ELF_DBG_RTLD, rtype);

	} else {
		if (dtype == DBG_REL_NONE) {
			dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(lml, MSG_INTL(MSG_REL_NONE), name, str);
		} else
			dbg_print(lml, MSG_INTL(MSG_REL_FINISH), name,
			    str);

		Dbg_util_nl(lml, DBG_NL_STD);
	}
}

void
Dbg_reloc_copy(Rt_map *dlmp, Rt_map *nlmp, const char *name, int zero)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (zero)
		str = MSG_INTL(MSG_STR_COPYZERO);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(LIST(dlmp), MSG_INTL(MSG_REL_COPY), NAME(dlmp), NAME(nlmp),
	    name, str);
}

void
Dbg_reloc_generate(Lm_list *lml, Os_desc *osp, Word type)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_REL_GENERATE), osp->os_name);

	if (DBG_NOTDETAIL())
		return;

	Elf_reloc_title(lml, ELF_DBG_LD, type);
}

void
Dbg_reloc_proc(Lm_list *lml, Os_desc *osp, Is_desc *isp, Is_desc *risp)
{
	const char	*str1, *str2;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;

	if (osp && osp->os_name)
		str1 = osp->os_name;
	else
		str1 =	MSG_INTL(MSG_STR_NULL);

	if (isp && isp->is_file)
		str2 = isp->is_file->ifl_name;
	else if (risp && risp->is_file)
		str2 = risp->is_file->ifl_name;
	else
		str2 = MSG_INTL(MSG_STR_NULL);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_REL_COLLECT), str1, str2);

	if (DBG_NOTDETAIL())
		return;

	Elf_reloc_title(lml, ELF_DBG_LD, risp->is_shdr->sh_type);
}

void
Dbg_reloc_doact_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_REL_ACTIVE));
	Elf_reloc_title(lml, ELF_DBG_LD, 0);
}

void
Dbg_reloc_doact(Lm_list *lml, int caller, Half mach, Word type, Word rtype,
    Xword off, Xword value, const char *symname, Os_desc *osp)
{
	Conv_inv_buf_t	inv_buf;
	const char	*secname;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (osp) {
		secname = osp->os_name;
		off += osp->os_shdr->sh_offset;
	} else
		secname = MSG_ORIG(MSG_STR_EMPTY);

	Elf_reloc_entry_2(lml, caller, MSG_ORIG(MSG_STR_EMPTY), type,
	    conv_reloc_type(mach, rtype, 0, &inv_buf),
	    off, value, secname, symname, MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_dooutrel(Lm_list *lml, Word type)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_REL_CREATING));
	Elf_reloc_title(lml, ELF_DBG_LD, type);
}

void
Dbg_reloc_discard(Lm_list *lml, Half mach, Rel_desc *rsp)
{
	Conv_inv_buf_t	inv_buf;
	Is_desc		*isp;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	isp = rsp->rel_isdesc;
	dbg_print(lml, MSG_INTL(MSG_REL_DISCARDED), isp->is_basename,
	    isp->is_file->ifl_name,
	    conv_reloc_type(mach, rsp->rel_rtype, 0, &inv_buf),
	    EC_OFF(rsp->rel_roffset));
}

void
Dbg_reloc_transition(Lm_list *lml, Half mach, Word rtype, Rel_desc *rsp)
{
	Conv_inv_buf_t	inv_buf1, inv_buf2;
	Is_desc		*isp;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;

	isp = rsp->rel_isdesc;
	dbg_print(lml, MSG_INTL(MSG_REL_TRANSITION),
	    conv_reloc_type(mach, rsp->rel_rtype, 0, &inv_buf1),
	    isp->is_basename, isp->is_file->ifl_name,
	    EC_OFF(rsp->rel_roffset), rsp->rel_sname,
	    conv_reloc_type(mach, rtype, 0, &inv_buf2));
}

void
Dbg_reloc_out(Ofl_desc *ofl, int caller, Word type, void *reloc,
    const char *secname, const char *symname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_reloc_entry_1(ofl->ofl_lml, caller, MSG_ORIG(MSG_STR_EMPTY),
	    ofl->ofl_dehdr->e_machine, type, reloc, secname, symname,
	    MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_in(Lm_list *lml, int caller, Half mach, Word type, void *reloc,
    const char *secname, const char *symname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	Elf_reloc_entry_1(lml, caller, MSG_INTL(MSG_STR_IN), mach, type, reloc,
	    secname, symname, MSG_ORIG(MSG_STR_EMPTY));
}

/*
 * Used by ld when '-z relaxreloc' is in use and a relocation
 * is redirected to a kept section.
 *
 * entry:
 *	lml - Link map control list
 *	sdp - The replacement symbol to be used with the relocation,
 *		which references the kept section.
 */
void
Dbg_reloc_sloppycomdat(Lm_list *lml, const char *secname, Sym_desc *sdp)
{
	const char *nfname;

	if (DBG_NOTCLASS(DBG_C_RELOC) || DBG_NOTDETAIL())
		return;

	nfname = (sdp && sdp->sd_file && sdp->sd_file->ifl_name)
	    ? sdp->sd_file->ifl_name : MSG_INTL(MSG_STR_NULL);

	dbg_print(lml, MSG_INTL(MSG_REL_SLOPPYCOMDAT), secname, nfname);
}

/*
 * Print a output relocation structure (Rel_desc).
 */
void
Dbg_reloc_ors_entry(Lm_list *lml, int caller, Word type, Half mach,
    Rel_desc *orsp)
{
	Conv_inv_buf_t	inv_buf;
	const char	*secname, *symname;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (orsp->rel_flags & (FLG_REL_GOT | FLG_REL_RFPTR1 | FLG_REL_RFPTR2))
		secname = MSG_ORIG(MSG_SCN_GOT);
	else if (orsp->rel_flags & FLG_REL_PLT)
		secname = MSG_ORIG(MSG_SCN_PLT);
	else if (orsp->rel_flags & FLG_REL_BSS)
		secname = MSG_ORIG(MSG_SCN_BSS);
	else if (orsp->rel_osdesc)
		secname = orsp->rel_osdesc->os_name;
	else
		secname = MSG_INTL(MSG_STR_NULL);

	/*
	 * Register symbols can be relocated/initialized to a constant, which
	 * is a special case where the symbol index is 0.
	 */
	if (orsp->rel_sym != NULL)
		symname = orsp->rel_sym->sd_name;
	else
		symname = MSG_ORIG(MSG_STR_EMPTY);

	Elf_reloc_entry_2(lml, caller, MSG_INTL(MSG_STR_OUT), type,
	    conv_reloc_type(mach, orsp->rel_rtype, 0, &inv_buf),
	    orsp->rel_roffset, orsp->rel_raddend, secname, symname,
	    MSG_ORIG(MSG_STR_EMPTY));
}

/*
 * Print a Active relocation structure (Rel_desc).
 */
void
Dbg_reloc_ars_entry(Lm_list *lml, int caller, Word type, Half mach,
    Rel_desc *arsp)
{
	Conv_inv_buf_t	inv_buf;
	const char	*secname;

	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (arsp->rel_flags & (FLG_REL_GOT | FLG_REL_FPTR))
		secname = MSG_ORIG(MSG_SCN_GOT);
	else
		secname = arsp->rel_osdesc->os_name;

	Elf_reloc_entry_2(lml, caller, MSG_INTL(MSG_STR_ACT), type,
	    conv_reloc_type(mach, arsp->rel_rtype, 0, &inv_buf),
	    arsp->rel_roffset, arsp->rel_raddend, secname,
	    arsp->rel_sym->sd_name, MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_entry(Lm_list *lml, const char *prestr, Half mach, Word type,
    void *reloc, const char *secname, const char *symname, const char *poststr)
{
	/*
	 * Register relocations can use a constant initializer, in which case
	 * the associated symbol is 0.
	 */
	if (symname == NULL)
		symname = MSG_ORIG(MSG_STR_EMPTY);

	Elf_reloc_entry_1(lml, ELF_DBG_LD, prestr, mach, type, reloc, secname,
	    symname, poststr);
}

#if	defined(_ELF64)

void
Dbg64_pltpad_to(Lm_list *lml, const char *file, Addr pltpad,
    const char *dfile, const char *symname)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_BND_PLTPAD_TO), EC_ADDR(pltpad), file,
	    dfile, symname);
}

void
Dbg64_pltpad_from(Lm_list *lml, const char *file, const char *sname,
    Addr pltpad)
{
	if (DBG_NOTCLASS(DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_BND_PLTPAD_FROM), EC_ADDR(pltpad), file,
	    Dbg_demangle_name(sname));
}

#endif

/*
 * Relocation output can differ depending on the caller and the type of
 * relocation record.  However, the final diagnostic is maintained here so
 * that the various message strings remain consistent.
 *
 * elfdump:
 *               type       offset     addend    section   symbol
 *               X          X          X         X         X              (Rela)
 *
 *               type       offset               section   symbol
 *               X          X                    X         X              (Rel)
 *
 * Note, it could be argued that the section name output with elfdump(1) is
 * unnecessary, as the table itself is identified with a title that reveals
 * the section name.  However, the output does provide for grep(1)'ing for
 * individual entries and obtaining the section name with this type of input.
 *
 * ld.so.1:
 *   (prestr)    type       offset     addend    symbol
 *                                     value
 *       in      X          X          X         X                        (Rela)
 *    apply                 X          X
 *
 *   (prestr)    type       offset     value     symbol
 *       in      X          X                    X                        (Rel)
 *    apply                 X          X
 *
 * ld:
 *   (prestr)    type       offset     addend    section   symbol
 *       in      X          X          X         X         X              (Rela)
 *      act      X          X                    X         X
 *      out      X          X                    X         X
 *
 *   (prestr)    type       offset               section   symbol
 *       in      X          X                    X         X              (Rel)
 *      act      X          X                    X         X
 *      out      X          X                    X         X
 *
 * Both Rela and Rel active relocations are printed as:
 *
 *               type       offset     value     section   symbol
 *               X          X          X         X         X
 */
void
Elf_reloc_title(Lm_list *lml, int caller, Word type)
{
	if (caller == ELF_DBG_ELFDUMP) {
		if (type == SHT_RELA) {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_EFSA_TITLE));
			else
				dbg_print(lml, MSG_INTL(MSG_REL_EFLA_TITLE));
		} else {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_EFSN_TITLE));
			else
				dbg_print(lml, MSG_INTL(MSG_REL_EFLN_TITLE));
		}
		return;
	}
	if (caller == ELF_DBG_RTLD) {
		if (type == SHT_RELA) {
			dbg_print(lml, MSG_INTL(MSG_REL_RTA_TITLE));
			dbg_print(lml, MSG_INTL(MSG_REL_RTV_TITLE));
		} else
			dbg_print(lml, MSG_INTL(MSG_REL_RTN_TITLE));
		return;
	}
	if (caller == ELF_DBG_LD) {
		if (type == 0) {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_LDSV_TITLE));
			else
				dbg_print(lml, MSG_INTL(MSG_REL_LDLV_TITLE));
			return;
		}
		if (type == SHT_RELA) {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_LDSA_TITLE));
			else
				dbg_print(lml, MSG_INTL(MSG_REL_LDLA_TITLE));
		} else {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_LDSN_TITLE));
			else
				dbg_print(lml, MSG_INTL(MSG_REL_LDLN_TITLE));
		}
	}
}

void
Elf_reloc_entry_2(Lm_list *lml, int caller, const char *prestr, Word type,
    const char *typestr, Addr off, Sxword add, const char *secname,
    const char *symname, const char *poststr)
{
	if (symname)
		symname = Elf_demangle_name(symname);
	else
		symname = MSG_ORIG(MSG_STR_EMPTY);

	if (caller == ELF_DBG_ELFDUMP) {
		if (type == SHT_RELA) {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_EFSA_ENTRY),
				    typestr, EC_OFF(off), EC_SXWORD(add),
				    secname, symname);
			else
				dbg_print(lml, MSG_INTL(MSG_REL_EFLA_ENTRY),
				    typestr, EC_OFF(off), EC_SXWORD(add),
				    secname, symname);
		} else {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_EFSN_ENTRY),
				    typestr, EC_OFF(off), secname, symname);
			else
				dbg_print(lml, MSG_INTL(MSG_REL_EFLN_ENTRY),
				    typestr, EC_OFF(off), secname, symname);
		}
		return;
	}
	if (caller == ELF_DBG_RTLD) {
		if (type == SHT_RELA)
			dbg_print(lml, MSG_INTL(MSG_REL_RTA_ENTRY), prestr,
			    typestr, EC_OFF(off), EC_SXWORD(add), symname,
			    poststr);
		else
			dbg_print(lml, MSG_INTL(MSG_REL_RTN_ENTRY), prestr,
			    typestr, EC_OFF(off), symname, poststr);
		return;
	}
	if (caller == ELF_DBG_LD) {
		if (type == SHT_RELA) {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_LDSA_ENTRY),
				    prestr, typestr, EC_OFF(off),
				    EC_SXWORD(add), secname, symname, poststr);
			else
				dbg_print(lml, MSG_INTL(MSG_REL_LDLA_ENTRY),
				    prestr, typestr, EC_OFF(off),
				    EC_SXWORD(add), secname, symname, poststr);
		} else {
			if (DBG_NOTLONG())
				dbg_print(lml, MSG_INTL(MSG_REL_LDSN_ENTRY),
				    prestr, typestr, EC_OFF(off), secname,
				    symname, poststr);
			else
				dbg_print(lml, MSG_INTL(MSG_REL_LDLN_ENTRY),
				    prestr, typestr, EC_OFF(off), secname,
				    symname, poststr);
		}
	}
}

void
Elf_reloc_entry_1(Lm_list *lml, int caller, const char *prestr, Half mach,
    Word type, void *reloc, const char *secname, const char *symname,
    const char *poststr)
{
	Conv_inv_buf_t	inv_buf;
	Addr		off;
	Sxword		add;
	const char	*str;

	if (type == SHT_RELA) {
		Rela	*rela = (Rela *)reloc;

		str = conv_reloc_type(mach, ELF_R_TYPE(rela->r_info, mach),
		    0, &inv_buf);
		off = rela->r_offset;
		add = rela->r_addend;
	} else {
		Rel	*rel = (Rel *)reloc;

		str = conv_reloc_type(mach, ELF_R_TYPE(rel->r_info, mach),
		    0, &inv_buf);
		off = rel->r_offset;
		add = 0;
	}
	Elf_reloc_entry_2(lml, caller, prestr, type, str, off, add, secname,
	    symname, poststr);
}

/*
 * Display any applied relocations.  Presently, these are only called from
 * ld.so.1, but the interfaces are maintained here to insure consistency with
 * other relocation diagnostics.
 */
void
Elf_reloc_apply_val(Lm_list *lml, int caller, Xword offset, Xword value)
{
	if (caller == ELF_DBG_RTLD)
		dbg_print(lml, MSG_INTL(MSG_REL_RT_APLVAL), EC_XWORD(offset),
		    EC_XWORD(value));
}
void
Elf_reloc_apply_reg(Lm_list *lml, int caller, Half mach, Xword offset,
    Xword value)
{
	Conv_inv_buf_t inv_buf;

	if (caller == ELF_DBG_RTLD)
		dbg_print(lml, MSG_INTL(MSG_REL_RT_APLREG),
		    conv_sym_value(mach, STT_SPARC_REGISTER,
		    offset, &inv_buf), EC_XWORD(value));
}
