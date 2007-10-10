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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Module sections. Initialize special sections
 */
#include	<string.h>
#include	<strings.h>
#include	<stdio.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

static void
remove_local(Ofl_desc *ofl, Sym_desc *sdp, int allow_ldynsym)
{
	Sym	*sym = sdp->sd_sym;
	uchar_t	type = ELF_ST_TYPE(sym->st_info);
	/* LINTED - only used for assert() */
	int	err;

	if ((ofl->ofl_flags1 & FLG_OF1_REDLSYM) == 0) {
		ofl->ofl_locscnt--;
		err = st_delstring(ofl->ofl_strtab, sdp->sd_name);
		assert(err != -1);

		if (allow_ldynsym && ldynsym_symtype[type]) {
			ofl->ofl_dynlocscnt--;
			err = st_delstring(ofl->ofl_dynstrtab, sdp->sd_name);
			assert(err != -1);
			/* Remove from sort section? */
			DYNSORT_COUNT(sdp, sym, type, --);
		}
	}
	sdp->sd_flags |= FLG_SY_ISDISC;
}

static void
remove_scoped(Ofl_desc *ofl, Sym_desc *sdp, int allow_ldynsym)
{
	Sym	*sym = sdp->sd_sym;
	uchar_t	type = ELF_ST_TYPE(sym->st_info);
	/* LINTED - only used for assert() */
	int	err;

	ofl->ofl_scopecnt--;
	ofl->ofl_elimcnt++;

	err = st_delstring(ofl->ofl_strtab, sdp->sd_name);
	assert(err != -1);

	if (allow_ldynsym && ldynsym_symtype[type]) {
		ofl->ofl_dynscopecnt--;
		err = st_delstring(ofl->ofl_dynstrtab, sdp->sd_name);
		assert(err != -1);
		/* Remove from sort section? */
		DYNSORT_COUNT(sdp, sym, type, --);
	}
	sdp->sd_flags1 |= FLG_SY1_ELIM;
}

#pragma inline(remove_local)
#pragma inline(remove_scoped)

/*
 * If -zignore is in effect, scan all input sections to see if there are any
 * which haven't been referenced (and hence can be discarded).  If sections are
 * to be discarded, rescan the output relocations and the symbol table and
 * remove the relocations and symbol entries that are no longer required.
 *
 * Note:  It's possible that a section which is being discarded has contributed
 *	  to the GOT table or the PLT table.  However, we can't at this point
 *	  eliminate the corresponding entries.  This is because there could well
 *	  be other sections referencing those same entries, but we don't have
 *	  the infrastructure to determine this.  So, keep the PLT and GOT
 *	  entries in the table in case someone wants them.
 * Note:  The section to be affected needs to be allocatable.
 *	  So even if -zignore is in effect, if the section is not allocatable,
 *	  we do not eliminate it.
 */
static uintptr_t
ignore_section_processing(Ofl_desc *ofl)
{
	Listnode	*lnp;
	Ifl_desc	*ifl;
	Rel_cache	*rcp;
	int		allow_ldynsym;

	allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);

	for (LIST_TRAVERSE(&ofl->ofl_objs, lnp, ifl)) {
		uint_t	num, discard;

		/*
		 * Diagnose (-D unused) a completely unreferenced file.
		 */
		if ((ifl->ifl_flags & FLG_IF_FILEREF) == 0)
			DBG_CALL(Dbg_unused_file(ofl->ofl_lml,
			    ifl->ifl_name, 0, 0));
		if (((ofl->ofl_flags1 & FLG_OF1_IGNPRC) == 0) ||
		    ((ifl->ifl_flags & FLG_IF_IGNORE) == 0))
			continue;

		/*
		 * Before scanning the whole symbol table to determine if
		 * symbols should be discard - quickly (relatively) scan the
		 * sections to determine if any are to be discarded.
		 */
		discard = 0;
		if (ifl->ifl_flags & FLG_IF_FILEREF) {
			for (num = 1; num < ifl->ifl_shnum; num++) {
				Is_desc	*isp = ifl->ifl_isdesc[num];
				Os_desc *osp;
				Sg_desc	*sgp;

				if (((isp = ifl->ifl_isdesc[num]) != 0) &&
				    ((isp->is_flags & FLG_IS_SECTREF) == 0) &&
				    ((osp = isp->is_osdesc) != 0) &&
				    ((sgp = osp->os_sgdesc) != 0) &&
				    (sgp->sg_phdr.p_type == PT_LOAD)) {
					discard++;
					break;
				}
			}
		}

		/*
		 * No sections are to be 'ignored'
		 */
		if ((discard == 0) && (ifl->ifl_flags & FLG_IF_FILEREF))
			continue;

		/*
		 * We know that we have discarded sections.  Scan the symbol
		 * table for this file to determine if symbols need to be
		 * discarded that are associated with the 'ignored' sections.
		 */
		for (num = 1; num < ifl->ifl_symscnt; num++) {
			Sym_desc	*sdp;
			Sym		*symp;
			Os_desc		*osp;
			/* LINTED - only used for assert() */
			int		err;
			uchar_t		type;

			sdp = ifl->ifl_oldndx[num];
			symp = sdp->sd_sym;
			type = ELF_ST_TYPE(symp->st_info);

			/*
			 * If the whole file is being eliminated, remove the
			 * local file symbol, and any COMMON symbols (which
			 * aren't associated with a section) provided they
			 * haven't been referenced by a relocation.
			 */
			if ((ofl->ofl_flags1 & FLG_OF1_IGNORE) &&
			    ((ifl->ifl_flags & FLG_IF_FILEREF) == 0) &&
			    ((type == STT_FILE) ||
			    ((symp->st_shndx == SHN_COMMON) &&
			    ((sdp->sd_flags & FLG_SY_UPREQD) == 0)))) {
				remove_local(ofl, sdp, allow_ldynsym);
				continue;
			}

			/*
			 * Skip any undefined, reserved section symbols, already
			 * discarded or eliminated symbols.  Also skip any
			 * symbols that don't originate from a section, or
			 * aren't defined from the file being examined.
			 */
			if ((symp->st_shndx == SHN_UNDEF) ||
			    (symp->st_shndx >= SHN_LORESERVE) ||
			    (type == STT_SECTION) ||
			    (sdp->sd_flags & FLG_SY_ISDISC) ||
			    (sdp->sd_flags1 & FLG_SY1_ELIM) ||
			    (sdp->sd_isc == 0) || (sdp->sd_file != ifl))
				continue;

			/*
			 * If any references were made against the section
			 * the symbol is being defined in - skip it.
			 */
			if ((sdp->sd_isc->is_flags & FLG_IS_SECTREF) ||
			    ((ifl->ifl_flags & FLG_IF_FILEREF) &&
			    ((osp = sdp->sd_isc->is_osdesc) != 0) &&
			    (osp->os_sgdesc->sg_phdr.p_type != PT_LOAD)))
				continue;

			/*
			 * Finish processing any local symbols.
			 */
			if (ELF_ST_BIND(symp->st_info) == STB_LOCAL) {
				if (ofl->ofl_flags1 & FLG_OF1_IGNORE)
					remove_local(ofl, sdp, allow_ldynsym);

				DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml,
				    sdp, sdp->sd_isc));
				continue;
			}

			/*
			 * Global symbols can only be eliminated when an objects
			 * interfaces (versioning/scoping) is defined.
			 */
			if (sdp->sd_flags1 & FLG_SY1_HIDDEN) {
				if (ofl->ofl_flags1 & FLG_OF1_IGNORE)
					remove_scoped(ofl, sdp, allow_ldynsym);

				DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml,
				    sdp, sdp->sd_isc));
				continue;
			}
		}
	}

	if ((ofl->ofl_flags1 & FLG_OF1_IGNPRC) == 0)
		return (1);

	/*
	 * Scan all output relocations searching for those against discarded or
	 * ignored sections.  If one is found, decrement the total outrel count.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_outrels, lnp, rcp)) {
		Rel_desc	*orsp;
		Os_desc		*relosp;

		/* LINTED */
		for (orsp = (Rel_desc *)(rcp + 1);
		    orsp < rcp->rc_free; orsp++) {
			Is_desc		*_isdesc = orsp->rel_isdesc;
			uint_t		flags, entsize;
			Shdr		*shdr;
			Ifl_desc	*ifl;

			if ((_isdesc == 0) ||
			    ((_isdesc->is_flags & (FLG_IS_SECTREF))) ||
			    ((ifl = _isdesc->is_file) == 0) ||
			    ((ifl->ifl_flags & FLG_IF_IGNORE) == 0) ||
			    ((shdr = _isdesc->is_shdr) == 0) ||
			    ((shdr->sh_flags & SHF_ALLOC) == 0))
				continue;

			flags = orsp->rel_flags;

			if (flags & (FLG_REL_GOT | FLG_REL_BSS |
			    FLG_REL_NOINFO | FLG_REL_PLT))
				continue;

			relosp = orsp->rel_osdesc;

			if (orsp->rel_flags & FLG_REL_RELA)
				entsize = sizeof (Rela);
			else
				entsize = sizeof (Rel);

			assert(relosp->os_szoutrels > 0);
			relosp->os_szoutrels -= entsize;

			if (!(flags & FLG_REL_PLT))
				ofl->ofl_reloccntsub++;

			if (orsp->rel_rtype == M_R_RELATIVE)
				ofl->ofl_relocrelcnt--;
		}
	}
	return (1);
}

/*
 * Allocate Elf_Data, Shdr, and Is_desc structures for a new
 * section.
 *
 * entry:
 *	ofl - Output file descriptor
 *	shtype - SHT_ type code for section.
 *	shname - String giving the name for the new section.
 *	entcnt - # of items contained in the data part of the new section.
 *		This value is multiplied against the known element size
 *		for the section type to determine the size of the data
 *		area for the section. It is only meaningful in cases where
 *		the section type has a non-zero element size. In other cases,
 *		the caller must set the size fields in the *ret_data and
 *		*ret_shdr structs manually.
 *	ret_isec, ret_shdr, ret_data - Address of pointers to
 *		receive address of newly allocated structs.
 *
 * exit:
 *	On error, returns S_ERROR. On success, returns (1), and the
 *	ret_ pointers have been updated to point at the new structures,
 *	which has been filled in. To finish the task, the caller must
 *	update any fields within the supplied descriptors that differ
 *	from its needs, and then call ld_place_section().
 */
static uintptr_t
new_section(Ofl_desc *ofl, Word shtype, const char *shname, Xword entcnt,
	Is_desc **ret_isec, Shdr **ret_shdr, Elf_Data **ret_data)
{
	typedef struct sec_info {
		Word d_type;
		Word align;	/* Used in both data and section header */
		Word sh_flags;
		Word sh_entsize;
	} SEC_INFO_T;

	const SEC_INFO_T	*sec_info;

	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

	/*
	 * For each type of section, we have a distinct set of
	 * SEC_INFO_T values. This macro defines a static structure
	 * containing those values and generates code to set the sec_info
	 * pointer to refer to it. The pointer in sec_info remains valid
	 * outside of the declaration scope because the info_s struct is static.
	 */
#define	SET_SEC_INFO(d_type, d_align, sh_flags, sh_entsize) \
	{ \
		static const SEC_INFO_T info_s = { d_type, d_align, sh_flags, \
		    sh_entsize}; \
		sec_info = &info_s; \
	}

	switch (shtype) {
	case SHT_PROGBITS:
		/*
		 * SHT_PROGBITS sections contain are used for many
		 * different sections. Alignments and flags differ.
		 * Some have a standard entsize, and others don't.
		 * We set some defaults here, but there is no expectation
		 * that they are correct or complete for any specific
		 * purpose. The caller must provide the correct values.
		 */
		SET_SEC_INFO(ELF_T_BYTE, M_WORD_ALIGN, SHF_ALLOC, 0)
		break;

	case SHT_SYMTAB:
		SET_SEC_INFO(ELF_T_SYM, M_WORD_ALIGN, 0, sizeof (Sym))
		break;

	case SHT_DYNSYM:
	case SHT_SUNW_LDYNSYM:
		SET_SEC_INFO(ELF_T_SYM, M_WORD_ALIGN, SHF_ALLOC, sizeof (Sym))
		break;

	case SHT_STRTAB:
		/*
		 * A string table may or may not be allocable, depending
		 * on context, so we leave that flag unset and leave it to
		 * the caller to add it if necessary.
		 *
		 * String tables do not have a standard entsize, so
		 * we set it to 0.
		 */
		SET_SEC_INFO(ELF_T_BYTE, 1, SHF_STRINGS, 0)
		break;

	case SHT_RELA:
		/*
		 * Relocations with an addend (Everything except 32-bit X86).
		 * The caller is expected to set all section header flags.
		 */
		SET_SEC_INFO(ELF_T_RELA, M_WORD_ALIGN, 0, sizeof (Rela))
		break;

	case SHT_REL:
		/*
		 * Relocations without an addend (32-bit X86 only).
		 * The caller is expected to set all section header flags.
		 */
		SET_SEC_INFO(ELF_T_REL, M_WORD_ALIGN, 0, sizeof (Rel))
		break;

	case SHT_HASH:
	case SHT_SUNW_symsort:
	case SHT_SUNW_tlssort:
		SET_SEC_INFO(ELF_T_WORD, M_WORD_ALIGN, SHF_ALLOC, sizeof (Word))
		break;

	case SHT_DYNAMIC:
		/*
		 * A dynamic section may or may not be allocable, depending
		 * on context, so we leave that flag unset and leave it to
		 * the caller to add it if necessary.
		 */
		SET_SEC_INFO(ELF_T_DYN, M_WORD_ALIGN, SHF_WRITE, sizeof (Dyn))
		break;

	case SHT_NOBITS:
		/*
		 * SHT_NOBITS is used for BSS-type sections. The size and
		 * alignment depend on the specific use and must be adjusted
		 * by the caller.
		 */
		SET_SEC_INFO(ELF_T_BYTE, 0, SHF_ALLOC | SHF_WRITE, 0)
		break;

	case SHT_INIT_ARRAY:
	case SHT_FINI_ARRAY:
	case SHT_PREINIT_ARRAY:
		SET_SEC_INFO(ELF_T_ADDR, sizeof (Addr), SHF_ALLOC | SHF_WRITE,
		    sizeof (Addr))
		break;

	case SHT_SYMTAB_SHNDX:
		/*
		 * Note that these sections are created to be associated
		 * with both symtab and dynsym symbol tables. However, they
		 * are non-allocable in all cases, because the runtime
		 * linker has no need for this information. It is purely
		 * informational, used by elfdump(1), debuggers, etc.
		 */
		SET_SEC_INFO(ELF_T_WORD, M_WORD_ALIGN, 0, sizeof (Word));
		break;

	case SHT_SUNW_cap:
		SET_SEC_INFO(ELF_T_CAP, M_WORD_ALIGN, SHF_ALLOC, sizeof (Cap));
		break;

	case SHT_SUNW_move:
		/*
		 * The sh_info field of the SHT_*_syminfo section points
		 * to the header index of the associated .dynamic section,
		 * so we also set SHF_INFO_LINK.
		 */
		SET_SEC_INFO(ELF_T_BYTE, sizeof (Lword),
		    SHF_ALLOC | SHF_WRITE, sizeof (Move));
		break;

	case SHT_SUNW_syminfo:
		/*
		 * The sh_info field of the SHT_*_syminfo section points
		 * to the header index of the associated .dynamic section,
		 * so we also set SHF_INFO_LINK.
		 */
		SET_SEC_INFO(ELF_T_BYTE, M_WORD_ALIGN,
		    SHF_ALLOC | SHF_INFO_LINK, sizeof (Syminfo));
		break;

	case SHT_SUNW_verneed:
	case SHT_SUNW_verdef:
		/*
		 * The info for verneed and versym happen to be the same.
		 * The entries in these sections are not of uniform size,
		 * so we set the entsize to 0.
		 */
		SET_SEC_INFO(ELF_T_BYTE, M_WORD_ALIGN, SHF_ALLOC, 0);
		break;

	case SHT_SUNW_versym:
		SET_SEC_INFO(ELF_T_BYTE, M_WORD_ALIGN, SHF_ALLOC,
		    sizeof (Versym));
		break;

	default:
		/* Should not happen: fcn called with unknown section type */
		assert(0);
		return (S_ERROR);
	}
#undef	SET_SEC_INFO

	size = entcnt * sec_info->sh_entsize;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = sec_info->d_type;
	data->d_size = size;
	data->d_align = sec_info->align;
	data->d_version = ofl->ofl_dehdr->e_version;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = shtype;
	shdr->sh_size = size;
	shdr->sh_flags = sec_info->sh_flags;
	shdr->sh_addralign = sec_info->align;
	shdr->sh_entsize = sec_info->sh_entsize;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = shname;
	isec->is_shdr = shdr;
	isec->is_indata = data;


	*ret_isec = isec;
	*ret_shdr = shdr;
	*ret_data = data;
	return (1);
}

/*
 * Build a .bss section for allocation of tentative definitions.  Any `static'
 * .bss definitions would have been associated to their own .bss sections and
 * thus collected from the input files.  `global' .bss definitions are tagged
 * as COMMON and do not cause any associated .bss section elements to be
 * generated.  Here we add up all these COMMON symbols and generate the .bss
 * section required to represent them.
 */
uintptr_t
ld_make_bss(Ofl_desc *ofl, Xword size, Xword align, Bss_Type which)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;
	uint_t		ident;
	Xword		rsize = (Xword)ofl->ofl_relocbsssz;

	/*
	 * Allocate header structs. We will set the name ourselves below,
	 * and there is no entcnt for a BSS. So, the shname and entcnt
	 * arguments are 0.
	 */
	if (new_section(ofl, SHT_NOBITS, NULL, 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = (size_t)size;
	data->d_align = (size_t)align;

	shdr->sh_size = size;
	shdr->sh_addralign = align;

	if (which == MAKE_TLS) {
		isec->is_name = MSG_ORIG(MSG_SCN_TBSS);
		ident = M_ID_TLSBSS;
		ofl->ofl_istlsbss = isec;
		shdr->sh_flags |= SHF_TLS;

	} else if (which == MAKE_BSS) {
		isec->is_name = MSG_ORIG(MSG_SCN_BSS);
		ofl->ofl_isbss = isec;
		ident = M_ID_BSS;

#if	defined(__x86) && defined(_ELF64)
	} else if (which == MAKE_LBSS) {
		isec->is_name = MSG_ORIG(MSG_SCN_LBSS);
		ofl->ofl_islbss = isec;
		ident = M_ID_LBSS;
		shdr->sh_flags |= SHF_AMD64_LARGE;
#endif
	}

	/*
	 * Retain this .bss input section as this will be where global
	 * symbol references are added.
	 */
	if ((osp = ld_place_section(ofl, isec, ident, 0)) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * If relocations exist against .*bss section, a
	 * section symbol must be created for the section in
	 * the .dynsym symbol table.
	 */
	if (!(osp->os_flags & FLG_OS_OUTREL)) {
		Word	flagtotest;
		if (which == MAKE_TLS)
			flagtotest = FLG_OF1_TLSOREL;
		else
			flagtotest = FLG_OF1_BSSOREL;

		if (ofl->ofl_flags1 & flagtotest) {
			ofl->ofl_dynshdrcnt++;
			osp->os_flags |= FLG_OS_OUTREL;
		}
	}

	osp->os_szoutrels = rsize;

	return (1);
}


/*
 * Build a SHT_{INIT|FINI|PREINIT}ARRAY section (specified via
 * ld -z *array=name
 */
static uintptr_t
make_array(Ofl_desc *ofl, Word shtype, const char *sectname, List *list)
{
	uint_t		entcount;
	Listnode	*lnp;
	Elf_Data	*data;
	Is_desc		*isec;
	Shdr		*shdr;
	Sym_desc	*sdp;
	Rel_desc	reld;
	Rela		reloc;
	Os_desc		*osp;
	uintptr_t	ret = 1;

	if (list->head == NULL)
		return (1);

	entcount = 0;
	for (LIST_TRAVERSE(list, lnp, sdp))
		entcount++;

	if (new_section(ofl, shtype, sectname, entcount, &isec, &shdr, &data) ==
	    S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_calloc(sizeof (Addr), entcount)) == 0)
		return (S_ERROR);

	if (ld_place_section(ofl, isec, M_ID_ARRAY, 0) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	osp = isec->is_osdesc;

	if ((ofl->ofl_osinitarray == 0) && (shtype == SHT_INIT_ARRAY))
		ofl->ofl_osinitarray = osp;
	if ((ofl->ofl_ospreinitarray == 0) && (shtype == SHT_PREINIT_ARRAY))
		ofl->ofl_ospreinitarray = osp;
	else if ((ofl->ofl_osfiniarray == 0) && (shtype == SHT_FINI_ARRAY))
		ofl->ofl_osfiniarray = osp;

	/*
	 * Create relocations against this section to initialize it to the
	 * function addresses.
	 */
	reld.rel_osdesc = osp;
	reld.rel_isdesc = isec;
	reld.rel_move = 0;
	reld.rel_flags = FLG_REL_LOAD;

	/*
	 * Fabricate the relocation information (as if a relocation record had
	 * been input - see init_rel()).
	 */
	reld.rel_rtype = M_R_ARRAYADDR;
	reld.rel_roffset = 0;
	reld.rel_raddend = 0;
	reld.rel_typedata = 0;

	/*
	 * Create a minimal relocation record to satisfy process_sym_reloc()
	 * debugging requirements.
	 */
	reloc.r_offset = 0;
	reloc.r_info = ELF_R_INFO(0, M_R_ARRAYADDR);
	reloc.r_addend = 0;

	DBG_CALL(Dbg_reloc_generate(ofl->ofl_lml, osp, M_REL_SHT_TYPE));
	for (LIST_TRAVERSE(list, lnp, sdp)) {
		reld.rel_sname = sdp->sd_name;
		reld.rel_sym = sdp;

		if (ld_process_sym_reloc(ofl, &reld, (Rel *)&reloc, isec,
		    MSG_INTL(MSG_STR_COMMAND)) == S_ERROR) {
			ret = S_ERROR;
			continue;
		}

		reld.rel_roffset += (Xword)sizeof (Addr);
		reloc.r_offset = reld.rel_roffset;
	}

	return (ret);
}

/*
 * Build a comment section (-Qy option).
 */
static uintptr_t
make_comment(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_COMMENT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_buf = (void *)ofl->ofl_sgsid;
	data->d_size = strlen(ofl->ofl_sgsid) + 1;
	data->d_align = 1;

	shdr->sh_size = (Xword)data->d_size;
	shdr->sh_flags = 0;
	shdr->sh_addralign = 1;

	return ((uintptr_t)ld_place_section(ofl, isec, M_ID_NOTE, 0));
}

/*
 * Make the dynamic section.  Calculate the size of any strings referenced
 * within this structure, they will be added to the global string table
 * (.dynstr).  This routine should be called before make_dynstr().
 */
static uintptr_t
make_dynamic(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Os_desc		*osp;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		cnt = 0;
	Listnode	*lnp;
	Ifl_desc	*ifl;
	Sym_desc	*sdp;
	size_t		size;
	Word		flags = ofl->ofl_flags;
	int		unused = 0;

	if (new_section(ofl, SHT_DYNAMIC, MSG_ORIG(MSG_SCN_DYNAMIC), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/* new_section() does not set SHF_ALLOC. Add it if needed */
	if (!(flags & FLG_OF_RELOBJ))
		shdr->sh_flags |= SHF_ALLOC;

	osp = ofl->ofl_osdynamic = ld_place_section(ofl, isec, M_ID_DYNAMIC, 0);

	/*
	 * Reserve entries for any needed dependencies.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_sos, lnp, ifl)) {
		Sdf_desc *	sdf;

		if (!(ifl->ifl_flags & (FLG_IF_NEEDED | FLG_IF_NEEDSTR)))
			continue;

		/*
		 * If this dependency didn't satisfy any symbol references,
		 * generate a debugging diagnostic (ld(1) -Dunused can be used
		 * to display these).  If this is a standard needed dependency,
		 * and -z ignore is in effect, drop the dependency.  Explicitly
		 * defined dependencies (i.e., -N dep) don't get dropped, and
		 * are flagged as being required to simplify update_odynamic()
		 * processing.
		 */
		if ((ifl->ifl_flags & FLG_IF_NEEDSTR) ||
		    ((ifl->ifl_flags & FLG_IF_DEPREQD) == 0)) {
			if (unused++ == 0)
				DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));
			DBG_CALL(Dbg_unused_file(ofl->ofl_lml, ifl->ifl_soname,
			    (ifl->ifl_flags & FLG_IF_NEEDSTR), 0));

			if (ifl->ifl_flags & FLG_IF_NEEDSTR)
				ifl->ifl_flags |= FLG_IF_DEPREQD;
			else if (ifl->ifl_flags & FLG_IF_IGNORE)
				continue;
		}

		/*
		 * If this object has an accompanying shared object definition
		 * determine if an alternative shared object name has been
		 * specified.
		 */
		if (((sdf = ifl->ifl_sdfdesc) != 0) &&
		    (sdf->sdf_flags & FLG_SDF_SONAME))
			ifl->ifl_soname = sdf->sdf_soname;

		/*
		 * If this object is a lazyload reserve a DT_POSFLAG1 entry.
		 */
		if (ifl->ifl_flags & (FLG_IF_LAZYLD | FLG_IF_GRPPRM))
			cnt++;

		if (st_insert(ofl->ofl_dynstrtab, ifl->ifl_soname) == -1)
			return (S_ERROR);
		cnt++;

		/*
		 * If the needed entry contains the $ORIGIN token make sure
		 * the associated DT_1_FLAGS entry is created.
		 */
		if (strstr(ifl->ifl_soname, MSG_ORIG(MSG_STR_ORIGIN))) {
			ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
			ofl->ofl_dtflags |= DF_ORIGIN;
		}
	}

	if (unused)
		DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));

	/*
	 * Reserve entries for any per-symbol auxiliary/filter strings.
	 */
	if (ofl->ofl_dtsfltrs) {
		/* LINTED */
		Dfltr_desc *	dftp;
		Aliste		off;

		for (ALIST_TRAVERSE(ofl->ofl_dtsfltrs, off, dftp))
			cnt++;
	}

	/*
	 * Reserve entries for any _init() and _fini() section addresses.
	 */
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_INIT_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		sdp->sd_flags |= FLG_SY_UPREQD;
		cnt++;
	}
	if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_FINI_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && (sdp->sd_ref == REF_REL_NEED) &&
	    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
		sdp->sd_flags |= FLG_SY_UPREQD;
		cnt++;
	}

	/*
	 * Reserve entries for any soname, filter name (shared libs only),
	 * run-path pointers, cache names and audit requirements..
	 */
	if (ofl->ofl_soname) {
		cnt++;
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_soname) == -1)
			return (S_ERROR);
	}
	if (ofl->ofl_filtees) {
		cnt++;
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_filtees) == -1)
			return (S_ERROR);

		/*
		 * If the filtees entry contains the $ORIGIN token make sure
		 * the associated DT_1_FLAGS entry is created.
		 */
		if (strstr(ofl->ofl_filtees, MSG_ORIG(MSG_STR_ORIGIN))) {
			ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
			ofl->ofl_dtflags |= DF_ORIGIN;
		}
	}
	if (ofl->ofl_rpath) {
		cnt += 2;	/* DT_RPATH & DT_RUNPATH */
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_rpath) == -1)
			return (S_ERROR);

		/*
		 * If the rpath entry contains the $ORIGIN token make sure
		 * the associated DT_1_FLAGS entry is created.
		 */
		if (strstr(ofl->ofl_rpath, MSG_ORIG(MSG_STR_ORIGIN))) {
			ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
			ofl->ofl_dtflags |= DF_ORIGIN;
		}
	}
	if (ofl->ofl_config) {
		cnt++;
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_config) == -1)
			return (S_ERROR);

		/*
		 * If the config entry contains the $ORIGIN token make sure
		 * the associated DT_1_FLAGS entry is created.
		 */
		if (strstr(ofl->ofl_config, MSG_ORIG(MSG_STR_ORIGIN))) {
			ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
			ofl->ofl_dtflags |= DF_ORIGIN;
		}
	}
	if (ofl->ofl_depaudit) {
		cnt++;
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_depaudit) == -1)
			return (S_ERROR);
	}
	if (ofl->ofl_audit) {
		cnt++;
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_audit) == -1)
			return (S_ERROR);
	}


	/*
	 * The following DT_* entries do not apply to relocatable objects
	 */
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		/*
		 * Reserve entries for the HASH, STRTAB, STRSZ, SYMTAB, SYMENT,
		 * and CHECKSUM.
		 */
		cnt += 6;

		/*
		 * If we are including local functions at the head of
		 * the dynsym, then also reserve entries for DT_SUNW_SYMTAB
		 * and DT_SUNW_SYMSZ.
		 */
		if (OFL_ALLOW_LDYNSYM(ofl))
			cnt += 2;

		if ((ofl->ofl_dynsymsortcnt > 0) ||
		    (ofl->ofl_dyntlssortcnt > 0))
			cnt++;		/* DT_SUNW_SORTENT */

		if (ofl->ofl_dynsymsortcnt > 0)
			cnt += 2;	/* DT_SUNW_[SYMSORT|SYMSORTSZ] */

		if (ofl->ofl_dyntlssortcnt > 0)
			cnt += 2;	/* DT_SUNW_[TLSSORT|TLSSORTSZ] */

		if ((flags & (FLG_OF_VERDEF | FLG_OF_NOVERSEC)) ==
		    FLG_OF_VERDEF)
			cnt += 2;		/* DT_VERDEF & DT_VERDEFNUM */

		if ((flags & (FLG_OF_VERNEED | FLG_OF_NOVERSEC)) ==
		    FLG_OF_VERNEED)
			cnt += 2;		/* DT_VERNEED & DT_VERNEEDNUM */

		if ((ofl->ofl_flags1 & FLG_OF1_RELCNT) &&
		    ofl->ofl_relocrelcnt)	/* RELACOUNT */
			cnt++;

		if (flags & FLG_OF_TEXTREL)	/* TEXTREL */
			cnt++;

		if (ofl->ofl_osfiniarray)	/* FINI_ARRAY & FINI_ARRAYSZ */
			cnt += 2;

		if (ofl->ofl_osinitarray)	/* INIT_ARRAY & INIT_ARRAYSZ */
			cnt += 2;

		if (ofl->ofl_ospreinitarray)	/* PREINIT_ARRAY & */
			cnt += 2;		/*	PREINIT_ARRAYSZ */

		/*
		 * If we have plt's reserve a PLT, PLTSZ, PLTREL and JMPREL.
		 */
		if (ofl->ofl_pltcnt)
			cnt += 3;

		/*
		 * If pltpadding is needed (Sparcv9)
		 */
		if (ofl->ofl_pltpad)
			cnt += 2;		/* DT_PLTPAD & DT_PLTPADSZ */

		/*
		 * If we have any relocations reserve a REL, RELSZ and
		 * RELENT entry.
		 */
		if (ofl->ofl_relocsz)
			cnt += 3;

		/*
		 * If a syminfo section is required create SYMINFO, SYMINSZ,
		 * and SYMINENT entries.
		 */
		if (ofl->ofl_flags & FLG_OF_SYMINFO)
			cnt += 3;

		/*
		 * If there are any partially initialized sections allocate
		 * MOVEENT, MOVESZ and MOVETAB.
		 */
		if (ofl->ofl_osmove)
			cnt += 3;

		/*
		 * Allocate one DT_REGISTER entry for every register symbol.
		 */
		cnt += ofl->ofl_regsymcnt;

		/*
		 * Reserve a entry for each '-zrtldinfo=...' specified
		 * on the command line.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_rtldinfo, lnp, sdp))
			cnt++;

		/*
		 * These two entries should only be placed in a segment
		 * which is writable.  If it's a read-only segment
		 * (due to mapfile magic, e.g. libdl.so.1) then don't allocate
		 * these entries.
		 */
		if ((osp->os_sgdesc) &&
		    (osp->os_sgdesc->sg_phdr.p_flags & PF_W)) {
			cnt++;			/* FEATURE_1 */

			if (ofl->ofl_osinterp)
				cnt++;		/* DEBUG */
		}

		/*
		 * Any hardware/software capabilities?
		 */
		if (ofl->ofl_oscap)
			cnt++;			/* SUNW_CAP */
	}

	if (flags & FLG_OF_SYMBOLIC)
		cnt++;				/* SYMBOLIC */

	/*
	 * Account for Architecture dependent .dynamic entries, and defaults.
	 */
	ld_mach_make_dynamic(ofl, &cnt);

	/*
	 * DT_FLAGS, DT_FLAGS_1, DT_SUNW_STRPAD, and DT_NULL. Also,
	 * allow room for the unused extra DT_NULLs. These are included
	 * to allow an ELF editor room to add items later.
	 */
	cnt += 4 + DYNAMIC_EXTRA_ELTS;

	/*
	 * Determine the size of the section from the number of entries.
	 */
	size = cnt * (size_t)shdr->sh_entsize;

	shdr->sh_size = (Xword)size;
	data->d_size = size;

	return ((uintptr_t)ofl->ofl_osdynamic);
}

/*
 * Build the GOT section and its associated relocation entries.
 */
uintptr_t
ld_make_got(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = (size_t)ofl->ofl_gotcnt * M_GOT_ENTSIZE;
	size_t		rsize = (size_t)ofl->ofl_relocgotsz;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_GOT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;

	shdr->sh_flags |= SHF_WRITE;
	shdr->sh_size = (Xword)size;
	shdr->sh_entsize = M_GOT_ENTSIZE;

	if ((ofl->ofl_osgot = ld_place_section(ofl, isec, M_ID_GOT, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	ofl->ofl_osgot->os_szoutrels = (Xword)rsize;

	return (1);
}

/*
 * Build an interpreter section.
 */
static uintptr_t
make_interp(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	const char	*iname = ofl->ofl_interp;
	size_t		size;

	/*
	 * If -z nointerp is in effect, don't create an interpreter section.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_NOINTRP)
		return (1);

	/*
	 * We always build an .interp section for dynamic executables.  However
	 * if the user has specifically specified an interpreter we'll build
	 * this section for any output (presumably the user knows what they are
	 * doing. refer ABI section 5-4, and ld.1 man page use of -I).
	 */
	if (((ofl->ofl_flags & (FLG_OF_DYNAMIC | FLG_OF_EXEC |
	    FLG_OF_RELOBJ)) != (FLG_OF_DYNAMIC | FLG_OF_EXEC)) && !iname)
		return (1);

	/*
	 * In the case of a dynamic executable supply a default interpreter
	 * if a specific interpreter has not been specified.
	 */
	if (iname == 0) {
		if (ofl->ofl_dehdr->e_machine == EM_SPARCV9)
			iname = ofl->ofl_interp =
			    MSG_ORIG(MSG_PTH_RTLD_SPARCV9);
		else if (ofl->ofl_dehdr->e_machine == EM_AMD64)
			iname = ofl->ofl_interp =
			    MSG_ORIG(MSG_PTH_RTLD_AMD64);
		else
			iname = ofl->ofl_interp = MSG_ORIG(MSG_PTH_RTLD);
	}

	size = strlen(iname) + 1;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_INTERP), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;
	shdr->sh_size = (Xword)size;
	data->d_align = shdr->sh_addralign = 1;

	ofl->ofl_osinterp = ld_place_section(ofl, isec, M_ID_INTERP, 0);
	return ((uintptr_t)ofl->ofl_osinterp);
}

/*
 * Build a hardware/software capabilities section.
 */
static uintptr_t
make_cap(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osec;
	Cap		*cap;
	size_t		size = 0;

	/*
	 * Determine how many entries are required.
	 */
	if (ofl->ofl_hwcap_1)
		size++;
	if (ofl->ofl_sfcap_1)
		size++;
	if (size == 0)
		return (1);
	size++;				/* Add CA_SUNW_NULL */

	if (new_section(ofl, SHT_SUNW_cap, MSG_ORIG(MSG_SCN_SUNWCAP), size,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_malloc(shdr->sh_size)) == 0)
		return (S_ERROR);

	cap = (Cap *)data->d_buf;
	if (ofl->ofl_hwcap_1) {
		cap->c_tag = CA_SUNW_HW_1;
		cap->c_un.c_val = ofl->ofl_hwcap_1;
		cap++;
	}
	if (ofl->ofl_sfcap_1) {
		cap->c_tag = CA_SUNW_SF_1;
		cap->c_un.c_val = ofl->ofl_sfcap_1;
		cap++;
	}
	cap->c_tag = CA_SUNW_NULL;
	cap->c_un.c_val = 0;

	/*
	 * If we're not creating a relocatable object, save the output section
	 * to trigger the creation of an associated program header.
	 */
	osec = ld_place_section(ofl, isec, M_ID_CAP, 0);
	if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)
		ofl->ofl_oscap = osec;

	return ((uintptr_t)osec);
}

/*
 * Build the PLT section and its associated relocation entries.
 */
static uintptr_t
make_plt(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = (size_t)M_PLT_RESERVSZ +
	    (((size_t)ofl->ofl_pltcnt + (size_t)ofl->ofl_pltpad) *
	    M_PLT_ENTSIZE);
	size_t		rsize = (size_t)ofl->ofl_relocpltsz;

#if	defined(__sparc)
	/*
	 * Account for the NOP at the end of the plt.
	 */
	size += sizeof (Word);
#endif

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_PLT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;
	data->d_align = M_PLT_ALIGN;

	shdr->sh_flags = M_PLT_SHF_FLAGS;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_PLT_ALIGN;
	shdr->sh_entsize = M_PLT_ENTSIZE;

	if ((ofl->ofl_osplt = ld_place_section(ofl, isec, M_ID_PLT, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	ofl->ofl_osplt->os_szoutrels = (Xword)rsize;

	return (1);
}

/*
 * Make the hash table.  Only built for dynamic executables and shared
 * libraries, and provides hashed lookup into the global symbol table
 * (.dynsym) for the run-time linker to resolve symbol lookups.
 */
static uintptr_t
make_hash(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;
	Word		nsyms = ofl->ofl_globcnt;
	size_t		cnt;

	/*
	 * Allocate section header structures. We set entcnt to 0
	 * because it's going to change after we place this section.
	 */
	if (new_section(ofl, SHT_HASH, MSG_ORIG(MSG_SCN_HASH), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/*
	 * Place the section first since it will affect the local symbol
	 * count.
	 */
	if ((ofl->ofl_oshash = ld_place_section(ofl, isec, M_ID_HASH, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * Calculate the number of output hash buckets.
	 */
	ofl->ofl_hashbkts = findprime(nsyms);

	/*
	 * The size of the hash table is determined by
	 *
	 *	i.	the initial nbucket and nchain entries (2)
	 *	ii.	the number of buckets (calculated above)
	 *	iii.	the number of chains (this is based on the number of
	 *		symbols in the .dynsym array + NULL symbol).
	 */
	cnt = 2 + ofl->ofl_hashbkts + (ofl->ofl_dynshdrcnt +
	    ofl->ofl_globcnt + ofl->ofl_lregsymcnt + 1);
	size = cnt * shdr->sh_entsize;

	/*
	 * Finalize the section header and data buffer initialization.
	 */
	if ((data->d_buf = libld_calloc(size, 1)) == 0)
		return (S_ERROR);
	data->d_size = size;
	shdr->sh_size = (Xword)size;

	return (1);
}

/*
 * Generate the standard symbol table.  Contains all locals and globals,
 * and resides in a non-allocatable section (ie. it can be stripped).
 */
static uintptr_t
make_symtab(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Is_desc		*xisec = 0;
	size_t		size;
	Word		symcnt;

	/*
	 * Create the section headers. Note that we supply an ent_cnt
	 * of 0. We won't know the count until the section has been placed.
	 */
	if (new_section(ofl, SHT_SYMTAB, MSG_ORIG(MSG_SCN_SYMTAB), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/*
	 * Place the section first since it will affect the local symbol
	 * count.
	 */
	if ((ofl->ofl_ossymtab = ld_place_section(ofl, isec, M_ID_SYMTAB, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * At this point we've created all but the 'shstrtab' section.
	 * Determine if we have to use 'Extended Sections'.  If so - then
	 * also create a SHT_SYMTAB_SHNDX section.
	 */
	if ((ofl->ofl_shdrcnt + 1) >= SHN_LORESERVE) {
		Shdr		*xshdr;
		Elf_Data	*xdata;

		if (new_section(ofl, SHT_SYMTAB_SHNDX,
		    MSG_ORIG(MSG_SCN_SYMTAB_SHNDX), 0, &xisec,
		    &xshdr, &xdata) == S_ERROR)
			return (S_ERROR);

		if ((ofl->ofl_ossymshndx = ld_place_section(ofl, xisec,
		    M_ID_SYMTAB_NDX, 0)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}
	/*
	 * Calculated number of symbols, which need to be augmented by
	 * the null first entry, the FILE symbol, and the .shstrtab entry.
	 */
	symcnt = (size_t)(3 + ofl->ofl_shdrcnt + ofl->ofl_scopecnt +
	    ofl->ofl_locscnt + ofl->ofl_globcnt);
	size = symcnt * shdr->sh_entsize;

	/*
	 * Finalize the section header and data buffer initialization.
	 */
	data->d_size = size;
	shdr->sh_size = (Xword)size;

	/*
	 * If we created a SHT_SYMTAB_SHNDX - then set it's sizes too.
	 */
	if (xisec) {
		size_t	xsize = symcnt * sizeof (Word);

		xisec->is_indata->d_size = xsize;
		xisec->is_shdr->sh_size = (Xword)xsize;
	}

	return (1);
}


/*
 * Build a dynamic symbol table. These tables reside in the text
 * segment of a dynamic executable or shared library.
 *
 *	.SUNW_ldynsym contains local function symbols
 *	.dynsym contains only globals symbols
 *
 * The two tables are created adjacent to each other, with .SUNW_ldynsym
 * coming first.
 */
static uintptr_t
make_dynsym(Ofl_desc *ofl)
{
	Shdr		*shdr, *lshdr;
	Elf_Data	*data, *ldata;
	Is_desc		*isec, *lisec;
	size_t		size;
	Xword		cnt;
	int		allow_ldynsym;

	/*
	 * Unless explicitly disabled, always produce a .SUNW_ldynsym section
	 * when it is allowed by the file type, even if the resulting
	 * table only ends up with a single STT_FILE in it. There are
	 * two reasons: (1) It causes the generation of the DT_SUNW_SYMTAB
	 * entry in the .dynamic section, which is something we would
	 * like to encourage, and (2) Without it, we cannot generate
	 * the associated .SUNW_dyn[sym|tls]sort sections, which are of
	 * value to DTrace.
	 *
	 * In practice, it is extremely rare for an object not to have
	 * local symbols for .SUNW_ldynsym, so 99% of the time, we'd be
	 * doing it anyway.
	 */
	allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);

	/*
	 * Create the section headers. Note that we supply an ent_cnt
	 * of 0. We won't know the count until the section has been placed.
	 */
	if (allow_ldynsym && new_section(ofl, SHT_SUNW_LDYNSYM,
	    MSG_ORIG(MSG_SCN_LDYNSYM), 0, &lisec, &lshdr, &ldata) == S_ERROR)
		return (S_ERROR);

	if (new_section(ofl, SHT_DYNSYM, MSG_ORIG(MSG_SCN_DYNSYM), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/*
	 * Place the section(s) first since it will affect the local symbol
	 * count.
	 */
	if (allow_ldynsym &&
	    ((ofl->ofl_osldynsym = ld_place_section(ofl, lisec,
	    M_ID_LDYNSYM, 0)) == (Os_desc *)S_ERROR))
		return (S_ERROR);
	if ((ofl->ofl_osdynsym = ld_place_section(ofl, isec, M_ID_DYNSYM, 0))
	    == (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * One extra section header entry for the 'null' entry.
	 */
	cnt = 1 + ofl->ofl_dynshdrcnt + ofl->ofl_globcnt + ofl->ofl_lregsymcnt;
	size = (size_t)cnt * shdr->sh_entsize;

	/*
	 * Finalize the section header and data buffer initialization.
	 */
	data->d_size = size;
	shdr->sh_size = (Xword)size;

	/*
	 * An ldynsym contains local function symbols. It is not
	 * used for linking, but if present, serves to allow better
	 * stack traces to be generated in contexts where the symtab
	 * is not available. (dladdr(), or stripped executable/library files).
	 */
	if (allow_ldynsym) {
		cnt = 1 + ofl->ofl_dynlocscnt + ofl->ofl_dynscopecnt;
		size = (size_t)cnt * shdr->sh_entsize;

		ldata->d_size = size;
		lshdr->sh_size = (Xword)size;
	}

	return (1);
}

/*
 * Build .SUNW_dynsymsort and/or .SUNW_dyntlssort sections. These are
 * index sections for the .SUNW_ldynsym/.dynsym pair that present data
 * and function symbols sorted by address.
 */
static uintptr_t
make_dynsort(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;


	/* Only do it if the .SUNW_ldynsym section is present */
	if (!OFL_ALLOW_LDYNSYM(ofl))
		return (1);

	/* .SUNW_dynsymsort */
	if (ofl->ofl_dynsymsortcnt > 0) {
		if (new_section(ofl, SHT_SUNW_symsort,
		    MSG_ORIG(MSG_SCN_DYNSYMSORT), ofl->ofl_dynsymsortcnt,
		    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

		if ((ofl->ofl_osdynsymsort = ld_place_section(ofl, isec,
		    M_ID_DYNSORT, 0)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	/* .SUNW_dyntlssort */
	if (ofl->ofl_dyntlssortcnt > 0) {
		if (new_section(ofl, SHT_SUNW_tlssort,
		    MSG_ORIG(MSG_SCN_DYNTLSSORT),
		    ofl->ofl_dyntlssortcnt, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

		if ((ofl->ofl_osdyntlssort = ld_place_section(ofl, isec,
		    M_ID_DYNSORT, 0)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	return (1);
}

/*
 * Helper routine for make_dynsym_shndx. Builds a
 * a SHT_SYMTAB_SHNDX for .dynsym or .SUNW_ldynsym, without knowing
 * which one it is.
 */
static uintptr_t
make_dyn_shndx(Ofl_desc *ofl, const char *shname, Os_desc *symtab,
    Os_desc **ret_os)
{
	Is_desc		*isec;
	Is_desc		*dynsymisp;
	Shdr		*shdr, *dynshdr;
	Elf_Data	*data;

	dynsymisp = (Is_desc *)symtab->os_isdescs.head->data;
	dynshdr = dynsymisp->is_shdr;

	if (new_section(ofl, SHT_SYMTAB_SHNDX, shname,
	    (dynshdr->sh_size / dynshdr->sh_entsize),
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((*ret_os = ld_place_section(ofl, isec,
	    M_ID_DYNSYM_NDX, 0)) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	assert(*ret_os);

	return (1);
}

/*
 * Build a SHT_SYMTAB_SHNDX for the .dynsym, and .SUNW_ldynsym
 */
static uintptr_t
make_dynsym_shndx(Ofl_desc *ofl)
{
	/*
	 * If there is a .SUNW_ldynsym, generate a section for its extended
	 * index section as well.
	 */
	if (OFL_ALLOW_LDYNSYM(ofl)) {
		if (make_dyn_shndx(ofl, MSG_ORIG(MSG_SCN_LDYNSYM_SHNDX),
		    ofl->ofl_osldynsym, &ofl->ofl_osldynshndx) == S_ERROR)
			return (S_ERROR);
	}

	/* The Generate a section for the dynsym */
	if (make_dyn_shndx(ofl, MSG_ORIG(MSG_SCN_DYNSYM_SHNDX),
	    ofl->ofl_osdynsym, &ofl->ofl_osdynshndx) == S_ERROR)
		return (S_ERROR);

	return (1);
}


/*
 * Build a string table for the section headers.
 */
static uintptr_t
make_shstrtab(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

	if (new_section(ofl, SHT_STRTAB, MSG_ORIG(MSG_SCN_SHSTRTAB),
	    0, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/*
	 * Place the section first, as it may effect the number of section
	 * headers to account for.
	 */
	if ((ofl->ofl_osshstrtab = ld_place_section(ofl, isec, M_ID_NOTE, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	size = st_getstrtab_sz(ofl->ofl_shdrsttab);
	assert(size > 0);

	data->d_size = size;
	shdr->sh_size = (Xword)size;

	return (1);
}

/*
 * Build a string section for the standard symbol table.
 */
static uintptr_t
make_strtab(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

	/*
	 * This string table consists of all the global and local symbols.
	 * Account for null bytes at end of the file name and the beginning
	 * of section.
	 */
	if (st_insert(ofl->ofl_strtab, ofl->ofl_name) == -1)
		return (S_ERROR);

	size = st_getstrtab_sz(ofl->ofl_strtab);
	assert(size > 0);

	if (new_section(ofl, SHT_STRTAB, MSG_ORIG(MSG_SCN_STRTAB),
	    0, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/* Set the size of the data area */
	data->d_size = size;
	shdr->sh_size = (Xword)size;

	ofl->ofl_osstrtab = ld_place_section(ofl, isec, M_ID_STRTAB, 0);
	return ((uintptr_t)ofl->ofl_osstrtab);
}

/*
 * Build a string table for the dynamic symbol table.
 */
static uintptr_t
make_dynstr(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

	/*
	 * If producing a .SUNW_ldynsym, account for the initial STT_FILE
	 * symbol that precedes the scope reduced global symbols.
	 */
	if (OFL_ALLOW_LDYNSYM(ofl)) {
		if (st_insert(ofl->ofl_dynstrtab, ofl->ofl_name) == -1)
			return (S_ERROR);
		ofl->ofl_dynscopecnt++;
	}


	/*
	 * Account for any local, named register symbols.  These locals are
	 * required for reference from DT_REGISTER .dynamic entries.
	 */
	if (ofl->ofl_regsyms) {
		int	ndx;

		for (ndx = 0; ndx < ofl->ofl_regsymsno; ndx++) {
			Sym_desc *	sdp;

			if ((sdp = ofl->ofl_regsyms[ndx]) == 0)
				continue;

			if (((sdp->sd_flags1 & FLG_SY1_HIDDEN) == 0) &&
			    (ELF_ST_BIND(sdp->sd_sym->st_info) != STB_LOCAL))
				continue;

			if (sdp->sd_sym->st_name == 0)
				continue;

			if (st_insert(ofl->ofl_dynstrtab, sdp->sd_name) == -1)
				return (S_ERROR);
		}
	}

	/*
	 * Reserve entries for any per-symbol auxiliary/filter strings.
	 */
	if (ofl->ofl_dtsfltrs) {
		Dfltr_desc *	dftp;
		Aliste		off;

		for (ALIST_TRAVERSE(ofl->ofl_dtsfltrs, off, dftp))
			if (st_insert(ofl->ofl_dynstrtab, dftp->dft_str) == -1)
				return (S_ERROR);
	}

	size = st_getstrtab_sz(ofl->ofl_dynstrtab);
	assert(size > 0);

	if (new_section(ofl, SHT_STRTAB, MSG_ORIG(MSG_SCN_DYNSTR),
	    0, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/* Make it allocable if necessary */
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
		shdr->sh_flags |= SHF_ALLOC;

	/* Set the size of the data area */
	data->d_size = size + DYNSTR_EXTRA_PAD;

	shdr->sh_size = (Xword)size;

	ofl->ofl_osdynstr = ld_place_section(ofl, isec, M_ID_DYNSTR, 0);
	return ((uintptr_t)ofl->ofl_osdynstr);
}

/*
 * Generate an output relocation section which will contain the relocation
 * information to be applied to the `osp' section.
 *
 * If (osp == NULL) then we are creating the coalesced relocation section
 * for an executable and/or a shared object.
 */
static uintptr_t
make_reloc(Ofl_desc *ofl, Os_desc *osp)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;
	Xword		sh_flags;
	char 		*sectname;
	Os_desc		*rosp;
	Word		relsize;
	const char	*rel_prefix;

	/* LINTED */
	if (M_REL_SHT_TYPE == SHT_REL) {
		/* REL */
		relsize = sizeof (Rel);
		rel_prefix = MSG_ORIG(MSG_SCN_REL);
	} else {
		/* RELA */
		relsize = sizeof (Rela);
		rel_prefix = MSG_ORIG(MSG_SCN_RELA);
	}

	if (osp) {
		size = osp->os_szoutrels;
		sh_flags = osp->os_shdr->sh_flags;
		if ((sectname = libld_malloc(strlen(rel_prefix) +
		    strlen(osp->os_name) + 1)) == 0)
			return (S_ERROR);
		(void) strcpy(sectname, rel_prefix);
		(void) strcat(sectname, osp->os_name);
	} else if (ofl->ofl_flags1 & FLG_OF1_RELCNT) {
		size = (ofl->ofl_reloccnt - ofl->ofl_reloccntsub) * relsize;
		sh_flags = SHF_ALLOC;
		sectname = (char *)MSG_ORIG(MSG_SCN_SUNWRELOC);
	} else {
		size = ofl->ofl_relocrelsz;
		sh_flags = SHF_ALLOC;
		sectname = (char *)rel_prefix;
	}

	/*
	 * Keep track of total size of 'output relocations' (to be stored
	 * in .dynamic)
	 */
	/* LINTED */
	ofl->ofl_relocsz += (Xword)size;

	if (new_section(ofl, M_REL_SHT_TYPE, sectname, 0, &isec, &shdr, &data)
	    == S_ERROR)
		return (S_ERROR);

	data->d_size = size;

	shdr->sh_size = (Xword)size;
	if (OFL_ALLOW_DYNSYM(ofl) && (sh_flags & SHF_ALLOC))
		shdr->sh_flags = SHF_ALLOC;

	if (osp) {
		/*
		 * The sh_info field of the SHT_REL* sections points to the
		 * section the relocations are to be applied to.
		 */
		shdr->sh_flags |= SHF_INFO_LINK;
	}

	/*
	 * Associate this relocation section to the section its going to
	 * relocate.
	 */
	if ((rosp = ld_place_section(ofl, isec, M_ID_REL, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	if (osp) {
		Listnode	*lnp;
		Is_desc		*risp;

		/*
		 * We associate the input relocation sections - with
		 * the newly created output relocation section.
		 *
		 * This is used primarily so that we can update
		 * SHT_GROUP[sect_no] entries to point to the
		 * created output relocation sections.
		 */
		for (LIST_TRAVERSE(&(osp->os_relisdescs), lnp, risp)) {
			risp->is_osdesc = rosp;

			/*
			 * If the input relocation section had the SHF_GROUP
			 * flag set - propagate it to the output relocation
			 * section.
			 */
			if (risp->is_shdr->sh_flags & SHF_GROUP) {
				rosp->os_shdr->sh_flags |= SHF_GROUP;
				break;
			}
		}
		osp->os_relosdesc = rosp;
	} else
		ofl->ofl_osrel = rosp;

	/*
	 * If this is the first relocation section we've encountered save it
	 * so that the .dynamic entry can be initialized accordingly.
	 */
	if (ofl->ofl_osrelhead == (Os_desc *)0)
		ofl->ofl_osrelhead = rosp;

	return (1);
}

/*
 * Generate version needed section.
 */
static uintptr_t
make_verneed(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * verneed sections do not have a constant element size, so the
	 * value of ent_cnt specified here (0) is meaningless.
	 */
	if (new_section(ofl, SHT_SUNW_verneed, MSG_ORIG(MSG_SCN_SUNWVERSION),
	    0, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/* During version processing we calculated the total size. */
	data->d_size = ofl->ofl_verneedsz;
	shdr->sh_size = (Xword)ofl->ofl_verneedsz;

	ofl->ofl_osverneed = ld_place_section(ofl, isec, M_ID_VERSION, 0);
	return ((uintptr_t)ofl->ofl_osverneed);
}

/*
 * Generate a version definition section.
 *
 *  o	the SHT_SUNW_verdef section defines the versions that exist within this
 *	image.
 */
static uintptr_t
make_verdef(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Ver_desc	*vdp;

	/*
	 * Reserve a string table entry for the base version dependency (other
	 * dependencies have symbol representations, which will already be
	 * accounted for during symbol processing).
	 */
	vdp = (Ver_desc *)ofl->ofl_verdesc.head->data;

	if (ofl->ofl_flags & FLG_OF_DYNAMIC) {
		if (st_insert(ofl->ofl_dynstrtab, vdp->vd_name) == -1)
			return (S_ERROR);
	} else {
		if (st_insert(ofl->ofl_strtab, vdp->vd_name) == -1)
			return (S_ERROR);
	}

	/*
	 * verdef sections do not have a constant element size, so the
	 * value of ent_cnt specified here (0) is meaningless.
	 */
	if (new_section(ofl, SHT_SUNW_verdef, MSG_ORIG(MSG_SCN_SUNWVERSION),
	    0, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/* During version processing we calculated the total size. */
	data->d_size = ofl->ofl_verdefsz;
	shdr->sh_size = (Xword)ofl->ofl_verdefsz;

	ofl->ofl_osverdef = ld_place_section(ofl, isec, M_ID_VERSION, 0);
	return ((uintptr_t)ofl->ofl_osverdef);
}

/*
 * Common function used to build both the SHT_SUNW_versym
 * section and the SHT_SUNW_syminfo section.  Each of these sections
 * provides additional symbol information.
 */
static Os_desc *
make_sym_sec(Ofl_desc *ofl, const char *sectname, Word stype, int ident)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * We don't know the size of this section yet, so set it to 0.
	 * It gets filled in after the dynsym is sized.
	 */
	if (new_section(ofl, stype, sectname, 0, &isec, &shdr, &data) ==
	    S_ERROR)
		return ((Os_desc *)S_ERROR);

	return (ld_place_section(ofl, isec, ident, 0));
}

/*
 * Build a .sunwbss section for allocation of tentative definitions.
 */
uintptr_t
ld_make_sunwbss(Ofl_desc *ofl, size_t size, Xword align)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Allocate header structs. We will set the name ourselves below,
	 * and there is no entcnt for a BSS. So, the shname and entcnt
	 * arguments are 0.
	 */
	if (new_section(ofl, SHT_NOBITS, MSG_ORIG(MSG_SCN_SUNWBSS), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;
	data->d_align = align;

	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = align;

	/*
	 * Retain this .sunwbss input section as this will be where global
	 * symbol references are added.
	 */
	ofl->ofl_issunwbss = isec;
	if (ld_place_section(ofl, isec, 0, 0) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	return (1);
}

/*
 * This routine is called when -z nopartial is in effect.
 */
uintptr_t
ld_make_sunwdata(Ofl_desc *ofl, size_t size, Xword align)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_SUNWDATA1), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	shdr->sh_flags |= SHF_WRITE;
	data->d_size = size;
	shdr->sh_size = (Xword)size;
	if (align != 0) {
		data->d_align = align;
		shdr->sh_addralign = align;
	}

	if ((data->d_buf = libld_calloc(size, 1)) == 0)
		return (S_ERROR);

	/*
	 * Retain this .sunwdata1 input section as this will
	 * be where global
	 * symbol references are added.
	 */
	ofl->ofl_issunwdata1 = isec;
	if ((osp = ld_place_section(ofl, isec, M_ID_DATA, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	if (!(osp->os_flags & FLG_OS_OUTREL)) {
		ofl->ofl_dynshdrcnt++;
		osp->os_flags |= FLG_OS_OUTREL;
	}
	return (1);
}

/*
 * Make .sunwmove section
 */
uintptr_t
ld_make_sunwmove(Ofl_desc *ofl, int mv_nums)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Listnode	*lnp1;
	Psym_info	*psym;
	int 		cnt = 1;


	if (new_section(ofl, SHT_SUNW_move, MSG_ORIG(MSG_SCN_SUNWMOVE),
	    mv_nums, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_calloc(data->d_size, 1)) == 0)
		return (S_ERROR);

	/*
	 * Copy move entries
	 */
	for (LIST_TRAVERSE(&ofl->ofl_parsym, lnp1, psym)) {
		Listnode *	lnp2;
		Mv_itm *	mvitm;

		if (psym->psym_symd->sd_flags & FLG_SY_PAREXPN)
			continue;
		for (LIST_TRAVERSE(&(psym->psym_mvs), lnp2, mvitm)) {
			if ((mvitm->mv_flag & FLG_MV_OUTSECT) == 0)
				continue;
			mvitm->mv_oidx = cnt;
			cnt++;
		}
	}
	if ((ofl->ofl_osmove = ld_place_section(ofl, isec, 0, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	return (1);
}


/*
 * The following sections are built after all input file processing and symbol
 * validation has been carried out.  The order is important (because the
 * addition of a section adds a new symbol there is a chicken and egg problem
 * of maintaining the appropriate counts).  By maintaining a known order the
 * individual routines can compensate for later, known, additions.
 */
uintptr_t
ld_make_sections(Ofl_desc *ofl)
{
	Word		flags = ofl->ofl_flags;
	Listnode	*lnp1;
	Sg_desc		*sgp;

	/*
	 * Generate any special sections.
	 */
	if (flags & FLG_OF_ADDVERS)
		if (make_comment(ofl) == S_ERROR)
			return (S_ERROR);

	if (make_interp(ofl) == S_ERROR)
		return (S_ERROR);

	if (make_cap(ofl) == S_ERROR)
		return (S_ERROR);

	if (make_array(ofl, SHT_INIT_ARRAY, MSG_ORIG(MSG_SCN_INITARRAY),
	    &ofl->ofl_initarray) == S_ERROR)
		return (S_ERROR);

	if (make_array(ofl, SHT_FINI_ARRAY, MSG_ORIG(MSG_SCN_FINIARRAY),
	    &ofl->ofl_finiarray) == S_ERROR)
		return (S_ERROR);

	if (make_array(ofl, SHT_PREINIT_ARRAY, MSG_ORIG(MSG_SCN_PREINITARRAY),
	    &ofl->ofl_preiarray) == S_ERROR)
		return (S_ERROR);

	/*
	 * Make the .plt section.  This occurs after any other relocation
	 * sections are generated (see reloc_init()) to ensure that the
	 * associated relocation section is after all the other relocation
	 * sections.
	 */
	if ((ofl->ofl_pltcnt) || (ofl->ofl_pltpad))
		if (make_plt(ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Determine whether any sections or files are not referenced.  Under
	 * -Dunused a diagnostic for any unused components is generated, under
	 * -zignore the component is removed from the final output.
	 */
	if (DBG_ENABLED || (ofl->ofl_flags1 & FLG_OF1_IGNPRC)) {
		if (ignore_section_processing(ofl) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Add any necessary versioning information.
	 */
	if ((flags & (FLG_OF_VERNEED | FLG_OF_NOVERSEC)) == FLG_OF_VERNEED) {
		if (make_verneed(ofl) == S_ERROR)
			return (S_ERROR);
	}
	if ((flags & (FLG_OF_VERDEF | FLG_OF_NOVERSEC)) == FLG_OF_VERDEF) {
		if (make_verdef(ofl) == S_ERROR)
			return (S_ERROR);
		if ((ofl->ofl_osversym = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWVERSYM), SHT_SUNW_versym,
		    M_ID_VERSION)) == (Os_desc*)S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Create a syminfo section if necessary.
	 */
	if (ofl->ofl_flags & FLG_OF_SYMINFO) {
		if ((ofl->ofl_ossyminfo = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWSYMINFO), SHT_SUNW_syminfo,
		    M_ID_SYMINFO)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	if (ofl->ofl_flags1 & FLG_OF1_RELCNT) {
		/*
		 * If -zcombreloc is enabled then all relocations (except for
		 * the PLT's) are coalesced into a single relocation section.
		 */
		if (ofl->ofl_reloccnt) {
			if (make_reloc(ofl, NULL) == S_ERROR)
				return (S_ERROR);
		}
	} else {
		/*
		 * Create the required output relocation sections.  Note, new
		 * sections may be added to the section list that is being
		 * traversed.  These insertions can move the elements of the
		 * Alist such that a section descriptor is re-read.  Recursion
		 * is prevented by maintaining a previous section pointer and
		 * insuring that this pointer isn't re-examined.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_segs, lnp1, sgp)) {
			Os_desc	**ospp, *posp = 0;
			Aliste	off;

			for (ALIST_TRAVERSE(sgp->sg_osdescs, off, ospp)) {
				Os_desc	*osp = *ospp;

				if ((osp != posp) && osp->os_szoutrels &&
				    (osp != ofl->ofl_osplt)) {
					if (make_reloc(ofl, osp) == S_ERROR)
						return (S_ERROR);
				}
				posp = osp;
			}
		}

		/*
		 * If we're not building a combined relocation section, then
		 * build a .rel[a] section as required.
		 */
		if (ofl->ofl_relocrelsz) {
			if (make_reloc(ofl, NULL) == S_ERROR)
				return (S_ERROR);
		}
	}

	/*
	 * The PLT relocations are always in their own section, and we try to
	 * keep them at the end of the PLT table.  We do this to keep the hot
	 * "data" PLT's at the head of the table nearer the .dynsym & .hash.
	 */
	if (ofl->ofl_osplt && ofl->ofl_relocpltsz) {
		if (make_reloc(ofl, ofl->ofl_osplt) == S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Finally build the symbol and section header sections.
	 */
	if (flags & FLG_OF_DYNAMIC) {
		if (make_dynamic(ofl) == S_ERROR)
			return (S_ERROR);
		if (make_dynstr(ofl) == S_ERROR)
			return (S_ERROR);
		/*
		 * There is no use for .hash and .dynsym sections in a
		 * relocatable object.
		 */
		if (!(flags & FLG_OF_RELOBJ)) {
			if (make_hash(ofl) == S_ERROR)
				return (S_ERROR);
			if (make_dynsym(ofl) == S_ERROR)
				return (S_ERROR);
#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
			if (make_amd64_unwindhdr(ofl) == S_ERROR)
				return (S_ERROR);
#endif
			if (make_dynsort(ofl) == S_ERROR)
				return (S_ERROR);
		}
	}

	if (!(flags & FLG_OF_STRIP) || (flags & FLG_OF_RELOBJ) ||
	    ((flags & FLG_OF_STATIC) && ofl->ofl_osversym)) {
		/*
		 * Do we need to make a SHT_SYMTAB_SHNDX section
		 * for the dynsym.  If so - do it now.
		 */
		if (ofl->ofl_osdynsym &&
		    ((ofl->ofl_shdrcnt + 3) >= SHN_LORESERVE)) {
			if (make_dynsym_shndx(ofl) == S_ERROR)
				return (S_ERROR);
		}

		if (make_strtab(ofl) == S_ERROR)
			return (S_ERROR);
		if (make_symtab(ofl) == S_ERROR)
			return (S_ERROR);
	} else {
		/*
		 * Do we need to make a SHT_SYMTAB_SHNDX section
		 * for the dynsym.  If so - do it now.
		 */
		if (ofl->ofl_osdynsym &&
		    ((ofl->ofl_shdrcnt + 1) >= SHN_LORESERVE)) {
			if (make_dynsym_shndx(ofl) == S_ERROR)
				return (S_ERROR);
		}
	}

	if (make_shstrtab(ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Now that we've created all of our sections adjust the size
	 * of SHT_SUNW_versym & SHT_SUNW_syminfo which are dependent on
	 * the symbol table sizes.
	 */
	if (ofl->ofl_osversym || ofl->ofl_ossyminfo) {
		Shdr		*shdr;
		Is_desc		*isec;
		Elf_Data	*data;
		size_t		size;
		ulong_t		cnt;
		Os_desc		*osp;

		if (flags & (FLG_OF_RELOBJ | FLG_OF_STATIC)) {
			osp = ofl->ofl_ossymtab;
		} else {
			osp = ofl->ofl_osdynsym;
		}
		isec = (Is_desc *)osp->os_isdescs.head->data;
		cnt = (isec->is_shdr->sh_size / isec->is_shdr->sh_entsize);

		if (ofl->ofl_osversym) {
			osp = ofl->ofl_osversym;
			isec = (Is_desc *)osp->os_isdescs.head->data;
			data = isec->is_indata;
			shdr = osp->os_shdr;
			size = cnt * shdr->sh_entsize;
			shdr->sh_size = (Xword)size;
			data->d_size = size;
		}
		if (ofl->ofl_ossyminfo) {
			osp = ofl->ofl_ossyminfo;
			isec = (Is_desc *)osp->os_isdescs.head->data;
			data = isec->is_indata;
			shdr = osp->os_shdr;
			size = cnt * shdr->sh_entsize;
			shdr->sh_size = (Xword)size;
			data->d_size = size;
		}
	}

	return (1);
}

/*
 * Build an additional data section - used to back OBJT symbol definitions
 * added with a mapfile.
 */
Is_desc *
ld_make_data(Ofl_desc *ofl, size_t size)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_DATA), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return ((Is_desc *)S_ERROR);

	data->d_size = size;
	shdr->sh_size = (Xword)size;
	shdr->sh_flags |= SHF_WRITE;

	if (ld_place_section(ofl, isec, M_ID_DATA, 0) == (Os_desc *)S_ERROR)
		return ((Is_desc *)S_ERROR);

	return (isec);
}

/*
 * Define a set of templates for generating "void (*)(void)" function
 * definitions.
 */
#if	defined(__i386) || defined(__amd64)
#if	defined(__lint)
static const uchar_t ret_template[] = { 0 };
#else	/* __lint */
#if	defined(_ELF64)
#define	ret_template	ret64_template
#else
#define	ret_template	ret32_template
#endif

static const uchar_t ret32_template[] = {
/* 0x00 */	0xc3				/* ret */
};

static const uchar_t ret64_template[] = {
/* 0x00 */	0x55,				/* pushq  %rbp */
/* 0x01 */	0x48, 0x8b, 0xec,		/* movq   %rsp,%rbp */
/* 0x04 */	0x48, 0x8b, 0xe5,		/* movq   %rbp,%rsp */
/* 0x07 */	0x5d,				/* popq   %rbp */
/* 0x08 */	0xc3				/* ret */
};
#endif	/* __lint */

#elif	defined(__sparc)
static const uchar_t ret_template[] = {
/* 0x00 */	0x81, 0xc3, 0xe0, 0x08,		/* retl */
/* 0x04 */	0x01, 0x00, 0x00, 0x00		/* nop */
};
#else
#error	unsupported architecture!
#endif

/*
 * Build an additional text section - used to back FUNC symbol definitions
 * added with a mapfile.
 */
Is_desc *
ld_make_text(Ofl_desc *ofl, size_t size)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Insure the size is sufficient to contain the minimum return
	 * instruction.
	 */
	if (size < sizeof (ret_template))
		size = sizeof (ret_template);

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_TEXT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return ((Is_desc *)S_ERROR);

	data->d_size = size;
	shdr->sh_size = (Xword)size;
	shdr->sh_flags |= SHF_EXECINSTR;

	/* Fill the buffer with the appropriate return instruction. */
	if ((data->d_buf = libld_calloc(size, 1)) == 0)
		return ((Is_desc *)S_ERROR);
	(void) memcpy(data->d_buf, ret_template, sizeof (ret_template));

	if (ld_place_section(ofl, isec, M_ID_TEXT, 0) == (Os_desc *)S_ERROR)
		return ((Is_desc *)S_ERROR);

	return (isec);
}
