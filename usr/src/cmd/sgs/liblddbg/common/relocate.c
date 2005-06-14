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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"
#include	<sys/elf_SPARC.h>


void _gelf_reloc_entry(const char *prestr, GElf_Half mach,
    GElf_Word type, void *reloc,
    const char *sec, const char *name, const char *com);

void
Dbg_reloc_generate(Os_desc * osp, Word relshtype)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_REL_GENERATE), osp->os_name);
	if (DBG_NOTDETAIL())
		return;
	if (relshtype == SHT_RELA)
		dbg_print(MSG_ORIG(MSG_REL_RELA_TITLE_2));
	else
		dbg_print(MSG_ORIG(MSG_REL_REL_TITLE_2));
}

void
Dbg_reloc_proc(Os_desc *osp, Is_desc *isp, Is_desc *risp)
{
	const char	*str1, *str2;

	if (DBG_NOTCLASS(DBG_RELOC))
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

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_REL_COLLECT), str1, str2);
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Determine the relocation titles from the sections type.
	 */
	if (risp->is_shdr->sh_type == SHT_RELA)
		dbg_print(MSG_ORIG(MSG_REL_RELA_TITLE_2));
	else
		dbg_print(MSG_ORIG(MSG_REL_REL_TITLE_2));
}

#if	!defined(_ELF64)
void
Dbg_reloc_doactiverel()
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_REL_ACTIVE));
	dbg_print(MSG_ORIG(MSG_REL_TITLE_1));
}
#endif /* !defined(_ELF64) */

void
Dbg_reloc_doact(Half mach, Word rtype, Xword off, Xword value, const char *sym,
    Os_desc *osp)
{
	const char	*sec;
	const char	*msg;

	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	if (DBG_NOTLONG())
		msg = MSG_ORIG(MSG_REL_ARGS_6);
	else
		msg = MSG_ORIG(MSG_REL_L_ARGS_6);

	if (osp) {
		sec = osp->os_name;
		off += osp->os_shdr->sh_offset;
	} else
		sec = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(msg, MSG_ORIG(MSG_STR_EMPTY),
	    conv_reloc_type_str(mach, rtype), EC_OFF(off), EC_XWORD(value),
	    sec, _Dbg_sym_dem(sym), MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_dooutrel(GElf_Word type)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_REL_CREATING));

	if (type == SHT_RELA)
		dbg_print(MSG_ORIG(MSG_REL_RELA_TITLE_2));
	else
		dbg_print(MSG_ORIG(MSG_REL_REL_TITLE_2));
}

void
Dbg_reloc_discard(Half mach, Rel_desc *rsp)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_REL_DISCARDED), rsp->rel_isdesc->is_basename,
		rsp->rel_isdesc->is_file->ifl_name,
		conv_reloc_type_str(mach, rsp->rel_rtype),
		EC_OFF(rsp->rel_roffset));
}

void
Dbg_reloc_transition(Half mach, Word oldrtype, Word newrtype, Xword off,
	const char *sym)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	dbg_print(MSG_INTL(MSG_REL_TRANS), EC_OFF(off),
		conv_reloc_type_str(mach, oldrtype) + M_R_STR_LEN,
		conv_reloc_type_str(mach, newrtype) + M_R_STR_LEN,
		sym);
}

void
Dbg_reloc_reg_apply(unsigned long long off, unsigned long long value)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	dbg_print(MSG_ORIG(MSG_REL_REGSYM),
#if	defined(_ELF64)
		conv_sym_value_str(EM_SPARCV9, STT_SPARC_REGISTER, off),
#else
		conv_sym_value_str(EM_SPARC, STT_SPARC_REGISTER, off),
#endif
		value);
}

#if	!defined(_ELF64)
void
Dbg_reloc_apply(unsigned long long off, unsigned long long value)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Print the actual relocation being applied to the specified output
	 * section, the offset represents the actual relocation address, and the
	 * value is the new data being written to that address).
	 */
	dbg_print(MSG_ORIG(MSG_REL_ARGS_2), off, value);
}
#endif	/* !defined(_ELF64) */

void
Dbg_reloc_out(Half mach, Word type, void *rel, const char *name,
	const char *relsectname)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	_gelf_reloc_entry(MSG_ORIG(MSG_STR_EMPTY), mach, type, rel,
	    relsectname, _Dbg_sym_dem(name), MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_in(Half mach, Word type, void *rel, const char *name,
    const char *iname)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	_gelf_reloc_entry(MSG_INTL(MSG_STR_IN), mach, type, rel,
	    (iname ? iname : MSG_ORIG(MSG_STR_EMPTY)),
	    (name ? _Dbg_sym_dem(name) : MSG_ORIG(MSG_STR_EMPTY)),
	    MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_reloc_error(Half mach, Word type, void *rel, const char *name,
    const char *com)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	_gelf_reloc_entry(MSG_INTL(MSG_STR_ERROR), mach, type, rel,
	    MSG_ORIG(MSG_STR_EMPTY),
	    (name ? _Dbg_sym_dem(name) : MSG_ORIG(MSG_STR_EMPTY)),
	    (com ? com : MSG_ORIG(MSG_STR_EMPTY)));
}

/*
 * Print a output relocation structure(Rel_desc).
 */
void
Dbg_reloc_ors_entry(Half mach, Rel_desc *orsp)
{
	const char	*os_name;
	const char	*sym_name;
	const char 	*msg;

	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	if (DBG_NOTLONG())
		msg = MSG_ORIG(MSG_REL_ARGS_5);
	else
		msg = MSG_ORIG(MSG_REL_L_ARGS_5);

	if (orsp->rel_flags & (FLG_REL_GOT | FLG_REL_RFPTR1 | FLG_REL_RFPTR2))
		os_name = MSG_ORIG(MSG_SCN_GOT);
	else if (orsp->rel_flags & FLG_REL_PLT)
		os_name = MSG_ORIG(MSG_SCN_PLT);
	else if (orsp->rel_flags & FLG_REL_BSS)
		os_name = MSG_ORIG(MSG_SCN_BSS);
	else if (orsp->rel_osdesc)
		os_name = orsp->rel_osdesc->os_name;
	else
		os_name = MSG_INTL(MSG_STR_NULL);

	/*
	 * Register symbols can be relocated/initialized
	 * to a constant, which is a special case where
	 * the symbol index is 0.
	 */
	if (orsp->rel_sym != NULL)
		sym_name = orsp->rel_sym->sd_name;
	else
		sym_name = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(msg, MSG_INTL(MSG_STR_OUT),
	    conv_reloc_type_str(mach, orsp->rel_rtype),
	    EC_OFF(orsp->rel_roffset), os_name,
	    _Dbg_sym_dem(sym_name), MSG_ORIG(MSG_STR_EMPTY));
}

/*
 * Print a Active relocation structure (Rel_desc).
 */
void
Dbg_reloc_ars_entry(Half mach, Rel_desc *arsp)
{
	const char	*os_name;
	const char	*msg;

	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	if (DBG_NOTLONG())
		msg = MSG_ORIG(MSG_REL_ARGS_5);
	else
		msg = MSG_ORIG(MSG_REL_L_ARGS_5);

	if (arsp->rel_flags & (FLG_REL_GOT | FLG_REL_FPTR))
		os_name = MSG_ORIG(MSG_SCN_GOT);
	else
		os_name = arsp->rel_osdesc->os_name;

	dbg_print(msg, MSG_INTL(MSG_STR_ACT),
	    conv_reloc_type_str(mach, arsp->rel_rtype),
	    EC_OFF(arsp->rel_roffset), os_name,
	    _Dbg_sym_dem(arsp->rel_sym->sd_name), MSG_ORIG(MSG_STR_EMPTY));
}

#if	!defined(_ELF64)
void
Dbg_reloc_run(const char *file, uint_t rel, int info, int type)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_RELOC))
		return;

	if (type == DBG_REL_FINISH) {
		if (info)
			str = MSG_ORIG(MSG_STR_EMPTY);
		else
			str = MSG_INTL(MSG_REL_RELOC_FAIL);
	} else {
		if (info)
			str = MSG_INTL(MSG_REL_RELOC_PLT);
		else
			str = MSG_ORIG(MSG_STR_EMPTY);
	}

	if (type == DBG_REL_START) {
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_REL_RELOC_START), file, str);

		if (DBG_NOTDETAIL())
			return;

		if (rel == SHT_RELA) {
			dbg_print(MSG_ORIG(MSG_REL_RELA_TITLE_3));
			dbg_print(MSG_ORIG(MSG_REL_RELA_TITLE_4));
		} else
			dbg_print(MSG_ORIG(MSG_REL_REL_TITLE_3));
	} else {
		if (type == DBG_REL_NONE) {
			dbg_print(MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(MSG_INTL(MSG_REL_RELOC_NONE), file, str);
		} else
			dbg_print(MSG_INTL(MSG_REL_RELOC_FINISH), file, str);

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	}
}

void
Dbg_reloc_copy(const char *dname, const char *rname, const char *sname,
    int zero)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (zero)
		str = MSG_INTL(MSG_STR_COPYZERO);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(MSG_INTL(MSG_REL_COPY), dname, rname, sname, str);
}

/*
 * Print a relocation entry. This can either be an input or output
 * relocation record, and specifies the relocation section for which is
 * associated.
 */
void
Gelf_reloc_entry(const char *prestr, GElf_Half mach, GElf_Word type,
    GElf_Rela *rel, const char *sec, const char *name)
{
	const char *msg;

	if (type == SHT_RELA) {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_REL_ARGS_6);
		else
			msg = MSG_ORIG(MSG_REL_L_ARGS_6);
	} else {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_REL_ARGS_5);
		else
			msg = MSG_ORIG(MSG_REL_L_ARGS_5);
	}

	if (type == SHT_RELA)
		dbg_print(msg, prestr,
		    conv_reloc_type_str(mach, (uint_t)GELF_R_TYPE(rel->r_info)),
			EC_ADDR(rel->r_offset), EC_XWORD(rel->r_addend),
			sec, _Dbg_sym_dem(name), MSG_ORIG(MSG_STR_EMPTY));
	else
		dbg_print(msg, prestr,
		    conv_reloc_type_str(mach, (uint_t)GELF_R_TYPE(rel->r_info)),
			EC_ADDR(rel->r_offset), sec, _Dbg_sym_dem(name),
			MSG_ORIG(MSG_STR_EMPTY));
}

void
_gelf_reloc_entry(const char *prestr, GElf_Half mach, GElf_Word type,
    void *reloc, const char *sec, const char *name, const char *com)
{
	const char *msg;

	/*
	 * Register relocations can use a constant initialzer,
	 * in which case the associated symbol is 0.
	 */
	if (name == NULL)
		name = MSG_ORIG(MSG_STR_EMPTY);

	if (type == SHT_RELA) {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_REL_ARGS_6);
		else
			msg = MSG_ORIG(MSG_REL_L_ARGS_6);
	} else {
		if (DBG_NOTLONG())
			msg = MSG_ORIG(MSG_REL_ARGS_5);
		else
			msg = MSG_ORIG(MSG_REL_L_ARGS_5);
	}

	if ((mach == EM_SPARCV9) || (mach == EM_AMD64)) {
		Elf64_Rela * rel = (Elf64_Rela *)reloc;

		if (type == SHT_RELA) {
			dbg_print(msg, prestr,
			    conv_reloc_type_str(mach,
				(uint_t)ELF64_R_TYPE(rel->r_info)),
			    EC_ADDR(rel->r_offset),
			    EC_XWORD(rel->r_addend),
			    sec, name, com);
		} else {
			dbg_print(msg, prestr,
			    conv_reloc_type_str(mach,
				(uint_t)ELF64_R_TYPE(rel->r_info)),
			    EC_ADDR(rel->r_offset), sec, name, com);
		}
	} else {
		Elf32_Rela * rel = (Elf32_Rela *)reloc;

		if (type == SHT_RELA) {
			dbg_print(msg, prestr,
			    conv_reloc_type_str(mach,
				ELF32_R_TYPE(rel->r_info)),
			    EC_ADDR(rel->r_offset), EC_XWORD(rel->r_addend),
			    sec, name, com);
		} else {
			dbg_print(msg, prestr,
			    conv_reloc_type_str(mach,
				ELF32_R_TYPE(rel->r_info)),
			    EC_ADDR(rel->r_offset), sec, name, com);
		}
	}
}
#endif	/* !defined(_ELF64) */

#if	defined(_ELF64)
void
Dbg_pltpad_boundto64(const char *file, Addr pltpad, const char *dfile,
	const char *symname)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	dbg_print(MSG_INTL(MSG_REL_PADBOUNDTO), file, EC_ADDR(pltpad),
	    dfile, symname);
}

void
Dbg_pltpad_bindto64(const char *file, const char *sname, Addr pltpad)
{
	if (DBG_NOTCLASS(DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;
	dbg_print(MSG_INTL(MSG_REL_PADBINDTO), file, _Dbg_sym_dem(sname),
	    EC_ADDR(pltpad));
}
#endif
