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
 * Module sections. Initialize special sections
 */

#define	ELF_TARGET_AMD64

#include	<string.h>
#include	<strings.h>
#include	<stdio.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

inline static void
remove_local(Ofl_desc *ofl, Sym_desc *sdp, int allow_ldynsym)
{
	Sym	*sym = sdp->sd_sym;
	uchar_t	type = ELF_ST_TYPE(sym->st_info);
	/* LINTED - only used for assert() */
	int	err;

	if ((ofl->ofl_flags & FLG_OF_REDLSYM) == 0) {
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

inline static void
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
	sdp->sd_flags |= FLG_SY_ELIM;
}

inline static void
ignore_sym(Ofl_desc *ofl, Ifl_desc *ifl, Sym_desc *sdp, int allow_ldynsym)
{
	Os_desc	*osp;
	Is_desc	*isp = sdp->sd_isc;
	uchar_t	bind = ELF_ST_BIND(sdp->sd_sym->st_info);

	if (bind == STB_LOCAL) {
		uchar_t	type = ELF_ST_TYPE(sdp->sd_sym->st_info);

		/*
		 * Skip section symbols, these were never collected in the
		 * first place.
		 */
		if (type == STT_SECTION)
			return;

		/*
		 * Determine if the whole file is being removed.  Remove any
		 * file symbol, and any symbol that is not associated with a
		 * section, provided the symbol has not been identified as
		 * (update) required.
		 */
		if (((ifl->ifl_flags & FLG_IF_FILEREF) == 0) &&
		    ((type == STT_FILE) || ((isp == NULL) &&
		    ((sdp->sd_flags & FLG_SY_UPREQD) == 0)))) {
			DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
			if (ifl->ifl_flags & FLG_IF_IGNORE)
				remove_local(ofl, sdp, allow_ldynsym);
			return;
		}

	} else {
		/*
		 * Global symbols can only be eliminated when the interfaces of
		 * an object have been defined via versioning/scoping.
		 */
		if (!SYM_IS_HIDDEN(sdp))
			return;

		/*
		 * Remove any unreferenced symbols that are not associated with
		 * a section.
		 */
		if ((isp == NULL) && ((sdp->sd_flags & FLG_SY_UPREQD) == 0)) {
			DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
			if (ifl->ifl_flags & FLG_IF_IGNORE)
				remove_scoped(ofl, sdp, allow_ldynsym);
			return;
		}
	}

	/*
	 * Do not discard any symbols that are associated with non-allocable
	 * segments.
	 */
	if (isp && ((isp->is_flags & FLG_IS_SECTREF) == 0) &&
	    ((osp = isp->is_osdesc) != 0) &&
	    (osp->os_sgdesc->sg_phdr.p_type == PT_LOAD)) {
		DBG_CALL(Dbg_syms_discarded(ofl->ofl_lml, sdp));
		if (ifl->ifl_flags & FLG_IF_IGNORE) {
			if (bind == STB_LOCAL)
				remove_local(ofl, sdp, allow_ldynsym);
			else
				remove_scoped(ofl, sdp, allow_ldynsym);
		}
	}
}

static Boolean
isdesc_discarded(Is_desc *isp)
{
	Ifl_desc	*ifl = isp->is_file;
	Os_desc		*osp = isp->is_osdesc;
	Word		ptype = osp->os_sgdesc->sg_phdr.p_type;

	if (isp->is_flags & FLG_IS_DISCARD)
		return (TRUE);

	/*
	 * If the file is discarded, it will take
	 * the section with it.
	 */
	if (ifl &&
	    (((ifl->ifl_flags & FLG_IF_FILEREF) == 0) ||
	    ((ptype == PT_LOAD) &&
	    ((isp->is_flags & FLG_IS_SECTREF) == 0) &&
	    (isp->is_shdr->sh_size > 0))) &&
	    (ifl->ifl_flags & FLG_IF_IGNORE))
		return (TRUE);

	return (FALSE);
}

/*
 * There are situations where we may count output sections (ofl_shdrcnt)
 * that are subsequently eliminated from the output object. Whether or
 * not this happens cannot be known until all input has been seen and
 * section elimination code has run. However, the situations where this
 * outcome is possible are known, and are flagged by setting FLG_OF_ADJOSCNT.
 *
 * If FLG_OF_ADJOSCNT is set, this routine makes a pass over the output
 * sections. If an unused output section is encountered, we decrement
 * ofl->ofl_shdrcnt and remove the section name from the .shstrtab string
 * table (ofl->ofl_shdrsttab).
 *
 * This code must be kept in sync with the similar code
 * found in outfile.c:ld_create_outfile().
 */
static void
adjust_os_count(Ofl_desc *ofl)
{
	Sg_desc		*sgp;
	Is_desc		*isp;
	Os_desc		*osp;
	Aliste		idx1;

	if ((ofl->ofl_flags & FLG_OF_ADJOSCNT) == 0)
		return;

	/*
	 * For each output section, look at the input sections to find at least
	 * one input section that has not been eliminated. If none are found,
	 * the -z ignore processing above has eliminated that output section.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
		Aliste	idx2;

		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
			Aliste	idx3;
			int	keep = 0, os_isdescs_idx;

			OS_ISDESCS_TRAVERSE(os_isdescs_idx, osp, idx3, isp) {
				/*
				 * We have found a kept input section,
				 * so the output section will be created.
				 */
				if (!isdesc_discarded(isp)) {
					keep = 1;
					break;
				}
			}
			/*
			 * If no section of this name was kept, decrement
			 * the count and remove the name from .shstrtab.
			 */
			if (keep == 0) {
				/* LINTED - only used for assert() */
				int err;

				ofl->ofl_shdrcnt--;
				err = st_delstring(ofl->ofl_shdrsttab,
				    osp->os_name);
				assert(err != -1);
			}
		}
	}
}

/*
 * If -zignore has been in effect, scan all input files to determine if the
 * file, or sections from the file, have been referenced.  If not, the file or
 * some of the files sections can be discarded. If sections are to be
 * discarded, rescan the output relocations and the symbol table and remove
 * the relocations and symbol entries that are no longer required.
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
	Sg_desc		*sgp;
	Is_desc		*isp;
	Os_desc		*osp;
	Ifl_desc	*ifl;
	Rel_cachebuf	*rcbp;
	Rel_desc	*rsp;
	int		allow_ldynsym = OFL_ALLOW_LDYNSYM(ofl);
	Aliste		idx1;

	for (APLIST_TRAVERSE(ofl->ofl_objs, idx1, ifl)) {
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
				if (((isp = ifl->ifl_isdesc[num]) != NULL) &&
				    ((isp->is_flags & FLG_IS_SECTREF) == 0) &&
				    ((osp = isp->is_osdesc) != NULL) &&
				    ((sgp = osp->os_sgdesc) != NULL) &&
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

			/*
			 * If the symbol definition has been resolved to another
			 * file, or the symbol has already been discarded or
			 * eliminated, skip it.
			 */
			sdp = ifl->ifl_oldndx[num];
			if ((sdp->sd_file != ifl) ||
			    (sdp->sd_flags &
			    (FLG_SY_ISDISC | FLG_SY_INVALID | FLG_SY_ELIM)))
				continue;

			/*
			 * Complete the investigation of the symbol.
			 */
			ignore_sym(ofl, ifl, sdp, allow_ldynsym);
		}
	}

	/*
	 * If we were only here to solicit debugging diagnostics, we're done.
	 */
	if ((ofl->ofl_flags1 & FLG_OF1_IGNPRC) == 0)
		return (1);

	/*
	 * Scan all output relocations searching for those against discarded or
	 * ignored sections.  If one is found, decrement the total outrel count.
	 */
	REL_CACHE_TRAVERSE(&ofl->ofl_outrels, idx1, rcbp, rsp) {
		Is_desc		*isc = rsp->rel_isdesc;
		uint_t		flags, entsize;
		Shdr		*shdr;

		if ((isc == NULL) || ((isc->is_flags & (FLG_IS_SECTREF))) ||
		    ((ifl = isc->is_file) == NULL) ||
		    ((ifl->ifl_flags & FLG_IF_IGNORE) == 0) ||
		    ((shdr = isc->is_shdr) == NULL) ||
		    ((shdr->sh_flags & SHF_ALLOC) == 0))
			continue;

		flags = rsp->rel_flags;

		if (flags & (FLG_REL_GOT | FLG_REL_BSS |
		    FLG_REL_NOINFO | FLG_REL_PLT))
			continue;

		osp = RELAUX_GET_OSDESC(rsp);

		if (rsp->rel_flags & FLG_REL_RELA)
			entsize = sizeof (Rela);
		else
			entsize = sizeof (Rel);

		assert(osp->os_szoutrels > 0);
		osp->os_szoutrels -= entsize;

		if (!(flags & FLG_REL_PLT))
			ofl->ofl_reloccntsub++;

		if (rsp->rel_rtype == ld_targ.t_m.m_r_relative)
			ofl->ofl_relocrelcnt--;
	}

	/*
	 * As a result of our work here, the number of output sections may
	 * have decreased. Trigger a call to adjust_os_count().
	 */
	ofl->ofl_flags |= FLG_OF_ADJOSCNT;

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
 *	which have been filled in. To finish the task, the caller must
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
	 *
	 * We can't determine the value of M_WORD_ALIGN at compile time, so
	 * a different variant is used for those cases.
	 */
#define	SET_SEC_INFO(d_type, d_align, sh_flags, sh_entsize) \
	{ \
		static const SEC_INFO_T info_s = { d_type, d_align, sh_flags, \
		    sh_entsize}; \
		sec_info = &info_s; \
	}
#define	SET_SEC_INFO_WORD_ALIGN(d_type, sh_flags, sh_entsize) \
	{ \
		static SEC_INFO_T info_s = { d_type, 0, sh_flags, \
		    sh_entsize}; \
		info_s.align = ld_targ.t_m.m_word_align; \
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
		SET_SEC_INFO_WORD_ALIGN(ELF_T_BYTE, SHF_ALLOC, 0)
		break;

	case SHT_SYMTAB:
		SET_SEC_INFO_WORD_ALIGN(ELF_T_SYM, 0, sizeof (Sym))
		break;

	case SHT_DYNSYM:
		SET_SEC_INFO_WORD_ALIGN(ELF_T_SYM, SHF_ALLOC, sizeof (Sym))
		break;

	case SHT_SUNW_LDYNSYM:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO_WORD_ALIGN(ELF_T_SYM, SHF_ALLOC, sizeof (Sym))
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
		SET_SEC_INFO_WORD_ALIGN(ELF_T_RELA, 0, sizeof (Rela))
		break;

	case SHT_REL:
		/*
		 * Relocations without an addend (32-bit X86 only).
		 * The caller is expected to set all section header flags.
		 */
		SET_SEC_INFO_WORD_ALIGN(ELF_T_REL, 0, sizeof (Rel))
		break;

	case SHT_HASH:
		SET_SEC_INFO_WORD_ALIGN(ELF_T_WORD, SHF_ALLOC, sizeof (Word))
		break;

	case SHT_SUNW_symsort:
	case SHT_SUNW_tlssort:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO_WORD_ALIGN(ELF_T_WORD, SHF_ALLOC, sizeof (Word))
		break;

	case SHT_DYNAMIC:
		/*
		 * A dynamic section may or may not be allocable, and may or
		 * may not be writable, depending on context, so we leave the
		 * flags unset and leave it to the caller to add them if
		 * necessary.
		 */
		SET_SEC_INFO_WORD_ALIGN(ELF_T_DYN, 0, sizeof (Dyn))
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
		SET_SEC_INFO_WORD_ALIGN(ELF_T_WORD, 0, sizeof (Word));
		break;

	case SHT_SUNW_cap:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO_WORD_ALIGN(ELF_T_CAP, SHF_ALLOC, sizeof (Cap));
		break;

	case SHT_SUNW_capchain:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO_WORD_ALIGN(ELF_T_WORD, SHF_ALLOC,
		    sizeof (Capchain));
		break;

	case SHT_SUNW_capinfo:
		ofl->ofl_flags |= FLG_OF_OSABI;
#if	_ELF64
		SET_SEC_INFO(ELF_T_XWORD, sizeof (Xword), SHF_ALLOC,
		    sizeof (Capinfo));
#else
		SET_SEC_INFO(ELF_T_WORD, sizeof (Word), SHF_ALLOC,
		    sizeof (Capinfo));
#endif
		break;

	case SHT_SUNW_move:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO(ELF_T_BYTE, sizeof (Lword),
		    SHF_ALLOC | SHF_WRITE, sizeof (Move));
		break;

	case SHT_SUNW_syminfo:
		ofl->ofl_flags |= FLG_OF_OSABI;
		/*
		 * The sh_info field of the SHT_*_syminfo section points
		 * to the header index of the associated .dynamic section,
		 * so we also set SHF_INFO_LINK.
		 */
		SET_SEC_INFO_WORD_ALIGN(ELF_T_BYTE,
		    SHF_ALLOC | SHF_INFO_LINK, sizeof (Syminfo));
		break;

	case SHT_SUNW_verneed:
	case SHT_SUNW_verdef:
		ofl->ofl_flags |= FLG_OF_OSABI;
		/*
		 * The info for verneed and versym happen to be the same.
		 * The entries in these sections are not of uniform size,
		 * so we set the entsize to 0.
		 */
		SET_SEC_INFO_WORD_ALIGN(ELF_T_BYTE, SHF_ALLOC, 0);
		break;

	case SHT_SUNW_versym:
		ofl->ofl_flags |= FLG_OF_OSABI;
		SET_SEC_INFO_WORD_ALIGN(ELF_T_BYTE, SHF_ALLOC,
		    sizeof (Versym));
		break;

	default:
		/* Should not happen: fcn called with unknown section type */
		assert(0);
		return (S_ERROR);
	}
#undef	SET_SEC_INFO
#undef	SET_SEC_INFO_WORD_ALIGN

	size = entcnt * sec_info->sh_entsize;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == NULL)
		return (S_ERROR);
	data->d_type = sec_info->d_type;
	data->d_size = size;
	data->d_align = sec_info->align;
	data->d_version = ofl->ofl_dehdr->e_version;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == NULL)
		return (S_ERROR);
	shdr->sh_type = shtype;
	shdr->sh_size = size;
	shdr->sh_flags = sec_info->sh_flags;
	shdr->sh_addralign = sec_info->align;
	shdr->sh_entsize = sec_info->sh_entsize;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == NULL)
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
 * Use an existing input section as a template to create a new
 * input section with the same values as the original, other than
 * the size of the data area which is supplied by the caller.
 *
 * entry:
 *	ofl - Output file descriptor
 *	ifl - Input file section to use as a template
 *	size - Size of data area for new section
 *	ret_isec, ret_shdr, ret_data - Address of pointers to
 *		receive address of newly allocated structs.
 *
 * exit:
 *	On error, returns S_ERROR. On success, returns (1), and the
 *	ret_ pointers have been updated to point at the new structures,
 *	which have been filled in. To finish the task, the caller must
 *	update any fields within the supplied descriptors that differ
 *	from its needs, and then call ld_place_section().
 */
static uintptr_t
new_section_from_template(Ofl_desc *ofl, Is_desc *tmpl_isp, size_t size,
	Is_desc **ret_isec, Shdr **ret_shdr, Elf_Data **ret_data)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == NULL)
		return (S_ERROR);
	data->d_type = tmpl_isp->is_indata->d_type;
	data->d_size = size;
	data->d_align = tmpl_isp->is_shdr->sh_addralign;
	data->d_version = ofl->ofl_dehdr->e_version;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_malloc(sizeof (Shdr))) == NULL)
		return (S_ERROR);
	*shdr = *tmpl_isp->is_shdr;
	shdr->sh_addr = 0;
	shdr->sh_offset = 0;
	shdr->sh_size = size;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == NULL)
		return (S_ERROR);
	isec->is_name = tmpl_isp->is_name;
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
ld_make_bss(Ofl_desc *ofl, Xword size, Xword align, uint_t ident)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;
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

	if (ident == ld_targ.t_id.id_tlsbss) {
		isec->is_name = MSG_ORIG(MSG_SCN_TBSS);
		ofl->ofl_istlsbss = isec;
		shdr->sh_flags |= SHF_TLS;

	} else if (ident == ld_targ.t_id.id_bss) {
		isec->is_name = MSG_ORIG(MSG_SCN_BSS);
		ofl->ofl_isbss = isec;

#if	defined(_ELF64)
	} else if ((ld_targ.t_m.m_mach == EM_AMD64) &&
	    (ident == ld_targ.t_id.id_lbss)) {
		isec->is_name = MSG_ORIG(MSG_SCN_LBSS);
		ofl->ofl_islbss = isec;
		shdr->sh_flags |= SHF_AMD64_LARGE;
#endif
	}

	/*
	 * Retain this .*bss input section as this will be where global symbol
	 * references are added.
	 */
	if ((osp = ld_place_section(ofl, isec, NULL, ident, NULL)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * If relocations exist against a .*bss section, a section symbol must
	 * be created for the section in the .dynsym symbol table.
	 */
	if (!(osp->os_flags & FLG_OS_OUTREL)) {
		ofl_flag_t	flagtotest;

		if (ident == ld_targ.t_id.id_tlsbss)
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
 * ld -z *array=name).
 */
static uintptr_t
make_array(Ofl_desc *ofl, Word shtype, const char *sectname, APlist *alp)
{
	uint_t		entcount;
	Aliste		idx;
	Elf_Data	*data;
	Is_desc		*isec;
	Shdr		*shdr;
	Sym_desc	*sdp;
	Rel_desc	reld;
	Rela		reloc;
	Os_desc		*osp;
	uintptr_t	ret = 1;

	if (alp == NULL)
		return (1);

	entcount = 0;
	for (APLIST_TRAVERSE(alp, idx, sdp))
		entcount++;

	if (new_section(ofl, shtype, sectname, entcount, &isec, &shdr, &data) ==
	    S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_calloc(sizeof (Addr), entcount)) == NULL)
		return (S_ERROR);

	if (ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_array, NULL) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	osp = isec->is_osdesc;

	if ((ofl->ofl_osinitarray == NULL) && (shtype == SHT_INIT_ARRAY))
		ofl->ofl_osinitarray = osp;
	if ((ofl->ofl_ospreinitarray == NULL) && (shtype == SHT_PREINIT_ARRAY))
		ofl->ofl_ospreinitarray = osp;
	else if ((ofl->ofl_osfiniarray == NULL) && (shtype == SHT_FINI_ARRAY))
		ofl->ofl_osfiniarray = osp;

	/*
	 * Create relocations against this section to initialize it to the
	 * function addresses.
	 */
	reld.rel_isdesc = isec;
	reld.rel_aux = NULL;
	reld.rel_flags = FLG_REL_LOAD;

	/*
	 * Fabricate the relocation information (as if a relocation record had
	 * been input - see init_rel()).
	 */
	reld.rel_rtype = ld_targ.t_m.m_r_arrayaddr;
	reld.rel_roffset = 0;
	reld.rel_raddend = 0;

	/*
	 * Create a minimal relocation record to satisfy process_sym_reloc()
	 * debugging requirements.
	 */
	reloc.r_offset = 0;
	reloc.r_info = ELF_R_INFO(0, ld_targ.t_m.m_r_arrayaddr);
	reloc.r_addend = 0;

	DBG_CALL(Dbg_reloc_generate(ofl->ofl_lml, osp,
	    ld_targ.t_m.m_rel_sht_type));
	for (APLIST_TRAVERSE(alp, idx, sdp)) {
		reld.rel_sym = sdp;

		if (ld_process_sym_reloc(ofl, &reld, (Rel *)&reloc, isec,
		    MSG_INTL(MSG_STR_COMMAND), 0) == S_ERROR) {
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

	return ((uintptr_t)ld_place_section(ofl, isec, NULL,
	    ld_targ.t_id.id_note, NULL));
}

/*
 * Make the dynamic section.  Calculate the size of any strings referenced
 * within this structure, they will be added to the global string table
 * (.dynstr).  This routine should be called before make_dynstr().
 *
 * This routine must be maintained in parallel with update_odynamic()
 * in update.c
 */
static uintptr_t
make_dynamic(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Os_desc		*osp;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		cnt = 0;
	Aliste		idx;
	Ifl_desc	*ifl;
	Sym_desc	*sdp;
	size_t		size;
	Str_tbl		*strtbl;
	ofl_flag_t	flags = ofl->ofl_flags;
	int		not_relobj = !(flags & FLG_OF_RELOBJ);
	int		unused = 0;

	/*
	 * Select the required string table.
	 */
	if (OFL_IS_STATIC_OBJ(ofl))
		strtbl = ofl->ofl_strtab;
	else
		strtbl = ofl->ofl_dynstrtab;

	/*
	 * Only a limited subset of DT_ entries apply to relocatable
	 * objects. See the comment at the head of update_odynamic() in
	 * update.c for details.
	 */
	if (new_section(ofl, SHT_DYNAMIC, MSG_ORIG(MSG_SCN_DYNAMIC), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	/*
	 * new_section() does not set SHF_ALLOC.  If we're building anything
	 * besides a relocatable object, then the .dynamic section should
	 * reside in allocatable memory.
	 */
	if (not_relobj)
		shdr->sh_flags |= SHF_ALLOC;

	/*
	 * new_section() does not set SHF_WRITE.  If we're building an object
	 * that specifies an interpretor, then a DT_DEBUG entry is created,
	 * which is initialized to the applications link-map list at runtime.
	 */
	if (ofl->ofl_osinterp)
		shdr->sh_flags |= SHF_WRITE;

	osp = ofl->ofl_osdynamic =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_dynamic, NULL);

	/*
	 * Reserve entries for any needed dependencies.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_sos, idx, ifl)) {
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

			/*
			 * Guidance: Remove unused dependency.
			 *
			 * If -z ignore is in effect, this warning is not
			 * needed because we will quietly remove the unused
			 * dependency.
			 */
			if (OFL_GUIDANCE(ofl, FLG_OFG_NO_UNUSED) &&
			    ((ifl->ifl_flags & FLG_IF_IGNORE) == 0))
				ld_eprintf(ofl, ERR_GUIDANCE,
				    MSG_INTL(MSG_GUIDE_UNUSED),
				    ifl->ifl_soname);

			if (ifl->ifl_flags & FLG_IF_NEEDSTR)
				ifl->ifl_flags |= FLG_IF_DEPREQD;
			else if (ifl->ifl_flags & FLG_IF_IGNORE)
				continue;
		}

		/*
		 * If this object requires a DT_POSFLAG_1 entry, reserve it.
		 */
		if ((ifl->ifl_flags & MSK_IF_POSFLAG1) && not_relobj)
			cnt++;

		if (st_insert(strtbl, ifl->ifl_soname) == -1)
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

	if (not_relobj) {
		/*
		 * Reserve entries for any per-symbol auxiliary/filter strings.
		 */
		cnt += alist_nitems(ofl->ofl_dtsfltrs);

		/*
		 * Reserve entries for _init() and _fini() section addresses.
		 */
		if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_INIT_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) &&
		    (sdp->sd_ref == REF_REL_NEED) &&
		    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
			sdp->sd_flags |= FLG_SY_UPREQD;
			cnt++;
		}
		if (((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_FINI_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) &&
		    (sdp->sd_ref == REF_REL_NEED) &&
		    (sdp->sd_sym->st_shndx != SHN_UNDEF)) {
			sdp->sd_flags |= FLG_SY_UPREQD;
			cnt++;
		}

		/*
		 * Reserve entries for any soname, filter name (shared libs
		 * only), run-path pointers, cache names and audit requirements.
		 */
		if (ofl->ofl_soname) {
			cnt++;
			if (st_insert(strtbl, ofl->ofl_soname) == -1)
				return (S_ERROR);
		}
		if (ofl->ofl_filtees) {
			cnt++;
			if (st_insert(strtbl, ofl->ofl_filtees) == -1)
				return (S_ERROR);

			/*
			 * If the filtees entry contains the $ORIGIN token
			 * make sure the associated DT_1_FLAGS entry is created.
			 */
			if (strstr(ofl->ofl_filtees,
			    MSG_ORIG(MSG_STR_ORIGIN))) {
				ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
				ofl->ofl_dtflags |= DF_ORIGIN;
			}
		}
	}

	if (ofl->ofl_rpath) {
		cnt += 2;	/* DT_RPATH & DT_RUNPATH */
		if (st_insert(strtbl, ofl->ofl_rpath) == -1)
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

	if (not_relobj) {
		Aliste	idx;
		Sg_desc	*sgp;

		if (ofl->ofl_config) {
			cnt++;
			if (st_insert(strtbl, ofl->ofl_config) == -1)
				return (S_ERROR);

			/*
			 * If the config entry contains the $ORIGIN token
			 * make sure the associated DT_1_FLAGS entry is created.
			 */
			if (strstr(ofl->ofl_config, MSG_ORIG(MSG_STR_ORIGIN))) {
				ofl->ofl_dtflags_1 |= DF_1_ORIGIN;
				ofl->ofl_dtflags |= DF_ORIGIN;
			}
		}
		if (ofl->ofl_depaudit) {
			cnt++;
			if (st_insert(strtbl, ofl->ofl_depaudit) == -1)
				return (S_ERROR);
		}
		if (ofl->ofl_audit) {
			cnt++;
			if (st_insert(strtbl, ofl->ofl_audit) == -1)
				return (S_ERROR);
		}

		/*
		 * Reserve entries for the DT_HASH, DT_STRTAB, DT_STRSZ,
		 * DT_SYMTAB, DT_SYMENT, and DT_CHECKSUM.
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

		if ((flags & FLG_OF_COMREL) && ofl->ofl_relocrelcnt)
			cnt++;			/* DT_RELACOUNT */

		if (flags & FLG_OF_TEXTREL)	/* DT_TEXTREL */
			cnt++;

		if (ofl->ofl_osfiniarray)	/* DT_FINI_ARRAY */
			cnt += 2;		/*    DT_FINI_ARRAYSZ */

		if (ofl->ofl_osinitarray)	/* DT_INIT_ARRAY */
			cnt += 2;		/*    DT_INIT_ARRAYSZ */

		if (ofl->ofl_ospreinitarray)	/* DT_PREINIT_ARRAY & */
			cnt += 2;		/*    DT_PREINIT_ARRAYSZ */

		/*
		 * If we have plt's reserve a DT_PLTRELSZ, DT_PLTREL and
		 * DT_JMPREL.
		 */
		if (ofl->ofl_pltcnt)
			cnt += 3;

		/*
		 * If plt padding is needed (Sparcv9).
		 */
		if (ofl->ofl_pltpad)
			cnt += 2;		/* DT_PLTPAD & DT_PLTPADSZ */

		/*
		 * If we have any relocations reserve a DT_REL, DT_RELSZ and
		 * DT_RELENT entry.
		 */
		if (ofl->ofl_relocsz)
			cnt += 3;

		/*
		 * If a syminfo section is required create DT_SYMINFO,
		 * DT_SYMINSZ, and DT_SYMINENT entries.
		 */
		if (flags & FLG_OF_SYMINFO)
			cnt += 3;

		/*
		 * If there are any partially initialized sections allocate
		 * DT_MOVETAB, DT_MOVESZ and DT_MOVEENT.
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
		for (APLIST_TRAVERSE(ofl->ofl_rtldinfo, idx, sdp))
			cnt++;

		/*
		 * The following entry should only be placed in a segment that
		 * is writable.
		 */
		if (((sgp = osp->os_sgdesc) != NULL) &&
		    (sgp->sg_phdr.p_flags & PF_W) && ofl->ofl_osinterp)
			cnt++;		/* DT_DEBUG */

		/*
		 * Capabilities require a .dynamic entry for the .SUNW_cap
		 * section.
		 */
		if (ofl->ofl_oscap)
			cnt++;			/* DT_SUNW_CAP */

		/*
		 * Symbol capabilities require a .dynamic entry for the
		 * .SUNW_capinfo section.
		 */
		if (ofl->ofl_oscapinfo)
			cnt++;			/* DT_SUNW_CAPINFO */

		/*
		 * Capabilities chain information requires a .SUNW_capchain
		 * entry (DT_SUNW_CAPCHAIN), entry size (DT_SUNW_CAPCHAINENT),
		 * and total size (DT_SUNW_CAPCHAINSZ).
		 */
		if (ofl->ofl_oscapchain)
			cnt += 3;

		if (flags & FLG_OF_SYMBOLIC)
			cnt++;			/* DT_SYMBOLIC */
	}

	/*
	 * Account for Architecture dependent .dynamic entries, and defaults.
	 */
	(*ld_targ.t_mr.mr_mach_make_dynamic)(ofl, &cnt);

	/*
	 * DT_FLAGS, DT_FLAGS_1, DT_SUNW_STRPAD, and DT_NULL. Also,
	 * allow room for the unused extra DT_NULLs. These are included
	 * to allow an ELF editor room to add items later.
	 */
	cnt += 4 + DYNAMIC_EXTRA_ELTS;

	/*
	 * DT_SUNW_LDMACH. Used to hold the ELF machine code of the
	 * linker that produced the output object. This information
	 * allows us to determine whether a given object was linked
	 * natively, or by a linker running on a different type of
	 * system. This information can be valuable if one suspects
	 * that a problem might be due to alignment or byte order issues.
	 */
	cnt++;

	/*
	 * Determine the size of the section from the number of entries.
	 */
	size = cnt * (size_t)shdr->sh_entsize;

	shdr->sh_size = (Xword)size;
	data->d_size = size;

	/*
	 * There are several tags that are specific to the Solaris osabi
	 * range which we unconditionally put into any dynamic section
	 * we create (e.g. DT_SUNW_STRPAD or DT_SUNW_LDMACH). As such,
	 * any Solaris object with a dynamic section should be tagged as
	 * ELFOSABI_SOLARIS.
	 */
	ofl->ofl_flags |= FLG_OF_OSABI;

	return ((uintptr_t)ofl->ofl_osdynamic);
}

/*
 * Build the GOT section and its associated relocation entries.
 */
uintptr_t
ld_make_got(Ofl_desc *ofl)
{
	Elf_Data	*data;
	Shdr	*shdr;
	Is_desc	*isec;
	size_t	size = (size_t)ofl->ofl_gotcnt * ld_targ.t_m.m_got_entsize;
	size_t	rsize = (size_t)ofl->ofl_relocgotsz;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_GOT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;

	shdr->sh_flags |= SHF_WRITE;
	shdr->sh_size = (Xword)size;
	shdr->sh_entsize = ld_targ.t_m.m_got_entsize;

	ofl->ofl_osgot = ld_place_section(ofl, isec, NULL,
	    ld_targ.t_id.id_got, NULL);
	if (ofl->ofl_osgot == (Os_desc *)S_ERROR)
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
	 * An .interp section is always created for a dynamic executable.
	 * A user can define the interpreter to use.  This definition overrides
	 * the default that would be recorded in an executable, and triggers
	 * the creation of an .interp section in any other object.  Presumably
	 * the user knows what they are doing.  Refer to the generic ELF ABI
	 * section 5-4, and the ld(1) -I option.
	 */
	if (((ofl->ofl_flags & (FLG_OF_DYNAMIC | FLG_OF_EXEC |
	    FLG_OF_RELOBJ)) != (FLG_OF_DYNAMIC | FLG_OF_EXEC)) && !iname)
		return (1);

	/*
	 * In the case of a dynamic executable, supply a default interpreter
	 * if the user has not specified their own.
	 */
	if (iname == NULL)
		iname = ofl->ofl_interp = ld_targ.t_m.m_def_interp;

	size = strlen(iname) + 1;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_INTERP), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;
	shdr->sh_size = (Xword)size;
	data->d_align = shdr->sh_addralign = 1;

	ofl->ofl_osinterp =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_interp, NULL);
	return ((uintptr_t)ofl->ofl_osinterp);
}

/*
 * Common function used to build the SHT_SUNW_versym section, SHT_SUNW_syminfo
 * section, and SHT_SUNW_capinfo section.  Each of these sections provide
 * additional symbol information, and their size parallels the associated
 * symbol table.
 */
static Os_desc *
make_sym_sec(Ofl_desc *ofl, const char *sectname, Word stype, int ident)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * We don't know the size of this section yet, so set it to 0.  The
	 * size gets filled in after the associated symbol table is sized.
	 */
	if (new_section(ofl, stype, sectname, 0, &isec, &shdr, &data) ==
	    S_ERROR)
		return ((Os_desc *)S_ERROR);

	return (ld_place_section(ofl, isec, NULL, ident, NULL));
}

/*
 * Determine whether a symbol capability is redundant because the object
 * capabilities are more restrictive.
 */
inline static int
is_cap_redundant(Objcapset *ocapset, Objcapset *scapset)
{
	Alist		*oalp, *salp;
	elfcap_mask_t	omsk, smsk;

	/*
	 * Inspect any platform capabilities.  If the object defines platform
	 * capabilities, then the object will only be loaded for those
	 * platforms.  A symbol capability set that doesn't define the same
	 * platforms is redundant, and a symbol capability that does not provide
	 * at least one platform name that matches a platform name in the object
	 * capabilities will never execute (as the object wouldn't have been
	 * loaded).
	 */
	oalp = ocapset->oc_plat.cl_val;
	salp = scapset->oc_plat.cl_val;
	if (oalp && ((salp == NULL) || cap_names_match(oalp, salp)))
		return (1);

	/*
	 * If the symbol capability set defines platforms, and the object
	 * doesn't, then the symbol set is more restrictive.
	 */
	if (salp && (oalp == NULL))
		return (0);

	/*
	 * Next, inspect any machine name capabilities.  If the object defines
	 * machine name capabilities, then the object will only be loaded for
	 * those machines.  A symbol capability set that doesn't define the same
	 * machine names is redundant, and a symbol capability that does not
	 * provide at least one machine name that matches a machine name in the
	 * object capabilities will never execute (as the object wouldn't have
	 * been loaded).
	 */
	oalp = ocapset->oc_plat.cl_val;
	salp = scapset->oc_plat.cl_val;
	if (oalp && ((salp == NULL) || cap_names_match(oalp, salp)))
		return (1);

	/*
	 * If the symbol capability set defines machine names, and the object
	 * doesn't, then the symbol set is more restrictive.
	 */
	if (salp && (oalp == NULL))
		return (0);

	/*
	 * Next, inspect any hardware capabilities.  If the objects hardware
	 * capabilities are greater than or equal to that of the symbols
	 * capabilities, then the symbol capability set is redundant.  If the
	 * symbols hardware capabilities are greater that the objects, then the
	 * symbol set is more restrictive.
	 *
	 * Note that this is a somewhat arbitrary definition, as each capability
	 * bit is independent of the others, and some of the higher order bits
	 * could be considered to be less important than lower ones.  However,
	 * this is the only reasonable non-subjective definition.
	 */
	omsk = ocapset->oc_hw_2.cm_val;
	smsk = scapset->oc_hw_2.cm_val;
	if ((omsk > smsk) || (omsk && (omsk == smsk)))
		return (1);
	if (omsk < smsk)
		return (0);

	/*
	 * Finally, inspect the remaining hardware capabilities.
	 */
	omsk = ocapset->oc_hw_1.cm_val;
	smsk = scapset->oc_hw_1.cm_val;
	if ((omsk > smsk) || (omsk && (omsk == smsk)))
		return (1);

	return (0);
}

/*
 * Capabilities values might have been assigned excluded values.  These
 * excluded values should be removed before calculating any capabilities
 * sections size.
 */
static void
capmask_value(Lm_list *lml, Word type, Capmask *capmask, int *title)
{
	/*
	 * First determine whether any bits should be excluded.
	 */
	if ((capmask->cm_val & capmask->cm_exc) == 0)
		return;

	DBG_CALL(Dbg_cap_post_title(lml, title));

	DBG_CALL(Dbg_cap_val_entry(lml, DBG_STATE_CURRENT, type,
	    capmask->cm_val, ld_targ.t_m.m_mach));
	DBG_CALL(Dbg_cap_val_entry(lml, DBG_STATE_EXCLUDE, type,
	    capmask->cm_exc, ld_targ.t_m.m_mach));

	capmask->cm_val &= ~capmask->cm_exc;

	DBG_CALL(Dbg_cap_val_entry(lml, DBG_STATE_RESOLVED, type,
	    capmask->cm_val, ld_targ.t_m.m_mach));
}

static void
capstr_value(Lm_list *lml, Word type, Caplist *caplist, int *title)
{
	Aliste	idx1, idx2;
	char	*estr;
	Capstr	*capstr;
	Boolean	found = FALSE;

	/*
	 * First determine whether any strings should be excluded.
	 */
	for (APLIST_TRAVERSE(caplist->cl_exc, idx1, estr)) {
		for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
			if (strcmp(estr, capstr->cs_str) == 0) {
				found = TRUE;
				break;
			}
		}
	}

	if (found == FALSE)
		return;

	/*
	 * Traverse the current strings, then delete the excluded strings,
	 * and finally display the resolved strings.
	 */
	if (DBG_ENABLED) {
		Dbg_cap_post_title(lml, title);
		for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
			Dbg_cap_ptr_entry(lml, DBG_STATE_CURRENT, type,
			    capstr->cs_str);
		}
	}
	for (APLIST_TRAVERSE(caplist->cl_exc, idx1, estr)) {
		for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
			if (strcmp(estr, capstr->cs_str) == 0) {
				DBG_CALL(Dbg_cap_ptr_entry(lml,
				    DBG_STATE_EXCLUDE, type, capstr->cs_str));
				alist_delete(caplist->cl_val, &idx2);
				break;
			}
		}
	}
	if (DBG_ENABLED) {
		for (ALIST_TRAVERSE(caplist->cl_val, idx2, capstr)) {
			Dbg_cap_ptr_entry(lml, DBG_STATE_RESOLVED, type,
			    capstr->cs_str);
		}
	}
}

/*
 * Build a capabilities section.
 */
#define	CAP_UPDATE(cap, capndx, tag, val)	\
	cap->c_tag = tag; \
	cap->c_un.c_val = val; \
	cap++, capndx++;

static uintptr_t
make_cap(Ofl_desc *ofl, Word shtype, const char *shname, int ident)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Cap		*cap;
	size_t		size = 0;
	Word		capndx = 0;
	Str_tbl		*strtbl;
	Objcapset	*ocapset = &ofl->ofl_ocapset;
	Aliste		idx1;
	Capstr		*capstr;
	int		title = 0;

	/*
	 * Determine which string table to use for any CA_SUNW_MACH,
	 * CA_SUNW_PLAT, or CA_SUNW_ID strings.
	 */
	if (OFL_IS_STATIC_OBJ(ofl))
		strtbl = ofl->ofl_strtab;
	else
		strtbl = ofl->ofl_dynstrtab;

	/*
	 * If symbol capabilities have been requested, but none have been
	 * created, warn the user.  This scenario can occur if none of the
	 * input relocatable objects defined any object capabilities.
	 */
	if ((ofl->ofl_flags & FLG_OF_OTOSCAP) && (ofl->ofl_capsymcnt == 0))
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_CAP_NOSYMSFOUND));

	/*
	 * If symbol capabilities have been collected, but no symbols are left
	 * referencing these capabilities, promote the capability groups back
	 * to an object capability definition.
	 */
	if ((ofl->ofl_flags & FLG_OF_OTOSCAP) && ofl->ofl_capsymcnt &&
	    (ofl->ofl_capfamilies == NULL)) {
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_CAP_NOSYMSFOUND));
		ld_cap_move_symtoobj(ofl);
		ofl->ofl_capsymcnt = 0;
		ofl->ofl_capgroups = NULL;
		ofl->ofl_flags &= ~FLG_OF_OTOSCAP;
	}

	/*
	 * Remove any excluded capabilities.
	 */
	capstr_value(ofl->ofl_lml, CA_SUNW_PLAT, &ocapset->oc_plat, &title);
	capstr_value(ofl->ofl_lml, CA_SUNW_MACH, &ocapset->oc_mach, &title);
	capmask_value(ofl->ofl_lml, CA_SUNW_HW_2, &ocapset->oc_hw_2, &title);
	capmask_value(ofl->ofl_lml, CA_SUNW_HW_1, &ocapset->oc_hw_1, &title);
	capmask_value(ofl->ofl_lml, CA_SUNW_SF_1, &ocapset->oc_sf_1, &title);

	/*
	 * Determine how many entries are required for any object capabilities.
	 */
	size += alist_nitems(ocapset->oc_plat.cl_val);
	size += alist_nitems(ocapset->oc_mach.cl_val);
	if (ocapset->oc_hw_2.cm_val)
		size++;
	if (ocapset->oc_hw_1.cm_val)
		size++;
	if (ocapset->oc_sf_1.cm_val)
		size++;

	/*
	 * Only identify a capabilities group if the group has content.  If a
	 * capabilities identifier exists, and no other capabilities have been
	 * supplied, remove the identifier.  This scenario could exist if a
	 * user mistakenly defined a lone identifier, or if an identified group
	 * was overridden so as to clear the existing capabilities and the
	 * identifier was not also cleared.
	 */
	if (ocapset->oc_id.cs_str) {
		if (size)
			size++;
		else
			ocapset->oc_id.cs_str = NULL;
	}
	if (size)
		size++;			/* Add CA_SUNW_NULL */

	/*
	 * Determine how many entries are required for any symbol capabilities.
	 */
	if (ofl->ofl_capsymcnt) {
		/*
		 * If there are no object capabilities, a CA_SUNW_NULL entry
		 * is required before any symbol capabilities.
		 */
		if (size == 0)
			size++;
		size += ofl->ofl_capsymcnt;
	}

	if (size == 0)
		return (NULL);

	if (new_section(ofl, shtype, shname, size, &isec,
	    &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_malloc(shdr->sh_size)) == NULL)
		return (S_ERROR);

	cap = (Cap *)data->d_buf;

	/*
	 * Fill in any object capabilities.  If there is an identifier, then the
	 * identifier comes first.  The remaining items follow in precedence
	 * order, although the order isn't important for runtime verification.
	 */
	if (ocapset->oc_id.cs_str) {
		ofl->ofl_flags |= FLG_OF_CAPSTRS;
		if (st_insert(strtbl, ocapset->oc_id.cs_str) == -1)
			return (S_ERROR);
		ocapset->oc_id.cs_ndx = capndx;
		CAP_UPDATE(cap, capndx, CA_SUNW_ID, 0);
	}
	if (ocapset->oc_plat.cl_val) {
		ofl->ofl_flags |= (FLG_OF_PTCAP | FLG_OF_CAPSTRS);

		/*
		 * Insert any platform name strings in the appropriate string
		 * table.  The capability value can't be filled in yet, as the
		 * final offset of the strings isn't known until later.
		 */
		for (ALIST_TRAVERSE(ocapset->oc_plat.cl_val, idx1, capstr)) {
			if (st_insert(strtbl, capstr->cs_str) == -1)
				return (S_ERROR);
			capstr->cs_ndx = capndx;
			CAP_UPDATE(cap, capndx, CA_SUNW_PLAT, 0);
		}
	}
	if (ocapset->oc_mach.cl_val) {
		ofl->ofl_flags |= (FLG_OF_PTCAP | FLG_OF_CAPSTRS);

		/*
		 * Insert the machine name strings in the appropriate string
		 * table.  The capability value can't be filled in yet, as the
		 * final offset of the strings isn't known until later.
		 */
		for (ALIST_TRAVERSE(ocapset->oc_mach.cl_val, idx1, capstr)) {
			if (st_insert(strtbl, capstr->cs_str) == -1)
				return (S_ERROR);
			capstr->cs_ndx = capndx;
			CAP_UPDATE(cap, capndx, CA_SUNW_MACH, 0);
		}
	}
	if (ocapset->oc_hw_2.cm_val) {
		ofl->ofl_flags |= FLG_OF_PTCAP;
		CAP_UPDATE(cap, capndx, CA_SUNW_HW_2, ocapset->oc_hw_2.cm_val);
	}
	if (ocapset->oc_hw_1.cm_val) {
		ofl->ofl_flags |= FLG_OF_PTCAP;
		CAP_UPDATE(cap, capndx, CA_SUNW_HW_1, ocapset->oc_hw_1.cm_val);
	}
	if (ocapset->oc_sf_1.cm_val) {
		ofl->ofl_flags |= FLG_OF_PTCAP;
		CAP_UPDATE(cap, capndx, CA_SUNW_SF_1, ocapset->oc_sf_1.cm_val);
	}
	CAP_UPDATE(cap, capndx, CA_SUNW_NULL, 0);

	/*
	 * Fill in any symbol capabilities.
	 */
	if (ofl->ofl_capgroups) {
		Cap_group	*cgp;

		for (APLIST_TRAVERSE(ofl->ofl_capgroups, idx1, cgp)) {
			Objcapset	*scapset = &cgp->cg_set;
			Aliste		idx2;
			Is_desc		*isp;

			cgp->cg_ndx = capndx;

			if (scapset->oc_id.cs_str) {
				ofl->ofl_flags |= FLG_OF_CAPSTRS;
				/*
				 * Insert the identifier string in the
				 * appropriate string table.  The capability
				 * value can't be filled in yet, as the final
				 * offset of the string isn't known until later.
				 */
				if (st_insert(strtbl,
				    scapset->oc_id.cs_str) == -1)
					return (S_ERROR);
				scapset->oc_id.cs_ndx = capndx;
				CAP_UPDATE(cap, capndx, CA_SUNW_ID, 0);
			}

			if (scapset->oc_plat.cl_val) {
				ofl->ofl_flags |= FLG_OF_CAPSTRS;

				/*
				 * Insert the platform name string in the
				 * appropriate string table.  The capability
				 * value can't be filled in yet, as the final
				 * offset of the string isn't known until later.
				 */
				for (ALIST_TRAVERSE(scapset->oc_plat.cl_val,
				    idx2, capstr)) {
					if (st_insert(strtbl,
					    capstr->cs_str) == -1)
						return (S_ERROR);
					capstr->cs_ndx = capndx;
					CAP_UPDATE(cap, capndx,
					    CA_SUNW_PLAT, 0);
				}
			}
			if (scapset->oc_mach.cl_val) {
				ofl->ofl_flags |= FLG_OF_CAPSTRS;

				/*
				 * Insert the machine name string in the
				 * appropriate string table.  The capability
				 * value can't be filled in yet, as the final
				 * offset of the string isn't known until later.
				 */
				for (ALIST_TRAVERSE(scapset->oc_mach.cl_val,
				    idx2, capstr)) {
					if (st_insert(strtbl,
					    capstr->cs_str) == -1)
						return (S_ERROR);
					capstr->cs_ndx = capndx;
					CAP_UPDATE(cap, capndx,
					    CA_SUNW_MACH, 0);
				}
			}
			if (scapset->oc_hw_2.cm_val) {
				CAP_UPDATE(cap, capndx, CA_SUNW_HW_2,
				    scapset->oc_hw_2.cm_val);
			}
			if (scapset->oc_hw_1.cm_val) {
				CAP_UPDATE(cap, capndx, CA_SUNW_HW_1,
				    scapset->oc_hw_1.cm_val);
			}
			if (scapset->oc_sf_1.cm_val) {
				CAP_UPDATE(cap, capndx, CA_SUNW_SF_1,
				    scapset->oc_sf_1.cm_val);
			}
			CAP_UPDATE(cap, capndx, CA_SUNW_NULL, 0);

			/*
			 * If any object capabilities are available, determine
			 * whether these symbol capabilities are less
			 * restrictive, and hence redundant.
			 */
			if (((ofl->ofl_flags & FLG_OF_PTCAP) == 0) ||
			    (is_cap_redundant(ocapset, scapset) == 0))
				continue;

			/*
			 * Indicate any files that provide redundant symbol
			 * capabilities.
			 */
			for (APLIST_TRAVERSE(cgp->cg_secs, idx2, isp)) {
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_CAP_REDUNDANT),
				    isp->is_file->ifl_name,
				    EC_WORD(isp->is_scnndx), isp->is_name);
			}
		}
	}

	/*
	 * If capabilities strings are required, the sh_info field of the
	 * section header will be set to the associated string table.
	 */
	if (ofl->ofl_flags & FLG_OF_CAPSTRS)
		shdr->sh_flags |= SHF_INFO_LINK;

	/*
	 * Place these capabilities in the output file.
	 */
	if ((ofl->ofl_oscap = ld_place_section(ofl, isec,
	    NULL, ident, NULL)) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * If symbol capabilities are required, then a .SUNW_capinfo section is
	 * also created.  This table will eventually be sized to match the
	 * associated symbol table.
	 */
	if (ofl->ofl_capfamilies) {
		if ((ofl->ofl_oscapinfo = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWCAPINFO), SHT_SUNW_capinfo,
		    ld_targ.t_id.id_capinfo)) == (Os_desc *)S_ERROR)
			return (S_ERROR);

		/*
		 * If we're generating a dynamic object, capabilities family
		 * members are maintained in a .SUNW_capchain section.
		 */
		if (ofl->ofl_capchaincnt &&
		    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)) {
			if (new_section(ofl, SHT_SUNW_capchain,
			    MSG_ORIG(MSG_SCN_SUNWCAPCHAIN),
			    ofl->ofl_capchaincnt, &isec, &shdr,
			    &data) == S_ERROR)
				return (S_ERROR);

			ofl->ofl_oscapchain = ld_place_section(ofl, isec,
			    NULL, ld_targ.t_id.id_capchain, NULL);
			if (ofl->ofl_oscapchain == (Os_desc *)S_ERROR)
				return (S_ERROR);

		}
	}
	return (1);
}
#undef	CAP_UPDATE

/*
 * Build the PLT section and its associated relocation entries.
 */
static uintptr_t
make_plt(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = ld_targ.t_m.m_plt_reservsz +
	    (((size_t)ofl->ofl_pltcnt + (size_t)ofl->ofl_pltpad) *
	    ld_targ.t_m.m_plt_entsize);
	size_t		rsize = (size_t)ofl->ofl_relocpltsz;

	/*
	 * On sparc, account for the NOP at the end of the plt.
	 */
	if (ld_targ.t_m.m_mach == LD_TARG_BYCLASS(EM_SPARC, EM_SPARCV9))
		size += sizeof (Word);

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_PLT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	data->d_size = size;
	data->d_align = ld_targ.t_m.m_plt_align;

	shdr->sh_flags = ld_targ.t_m.m_plt_shf_flags;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = ld_targ.t_m.m_plt_align;
	shdr->sh_entsize = ld_targ.t_m.m_plt_entsize;

	ofl->ofl_osplt = ld_place_section(ofl, isec, NULL,
	    ld_targ.t_id.id_plt, NULL);
	if (ofl->ofl_osplt == (Os_desc *)S_ERROR)
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
	ofl->ofl_oshash =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_hash, NULL);
	if (ofl->ofl_oshash == (Os_desc *)S_ERROR)
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
	 *		symbols in the .dynsym array).
	 */
	cnt = 2 + ofl->ofl_hashbkts + DYNSYM_ALL_CNT(ofl);
	size = cnt * shdr->sh_entsize;

	/*
	 * Finalize the section header and data buffer initialization.
	 */
	if ((data->d_buf = libld_calloc(size, 1)) == NULL)
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
	if ((ofl->ofl_ossymtab = ld_place_section(ofl, isec, NULL,
	    ld_targ.t_id.id_symtab, NULL)) == (Os_desc *)S_ERROR)
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

		if ((ofl->ofl_ossymshndx = ld_place_section(ofl, xisec, NULL,
		    ld_targ.t_id.id_symtab_ndx, NULL)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Calculated number of symbols, which need to be augmented by
	 * the (yet to be created) .shstrtab entry.
	 */
	symcnt = (size_t)(1 + SYMTAB_ALL_CNT(ofl));
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
	    ((ofl->ofl_osldynsym = ld_place_section(ofl, lisec, NULL,
	    ld_targ.t_id.id_ldynsym, NULL)) == (Os_desc *)S_ERROR))
		return (S_ERROR);
	ofl->ofl_osdynsym =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_dynsym, NULL);
	if (ofl->ofl_osdynsym == (Os_desc *)S_ERROR)
		return (S_ERROR);

	cnt = DYNSYM_ALL_CNT(ofl);
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

		if ((ofl->ofl_osdynsymsort = ld_place_section(ofl, isec, NULL,
		    ld_targ.t_id.id_dynsort, NULL)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	/* .SUNW_dyntlssort */
	if (ofl->ofl_dyntlssortcnt > 0) {
		if (new_section(ofl, SHT_SUNW_tlssort,
		    MSG_ORIG(MSG_SCN_DYNTLSSORT),
		    ofl->ofl_dyntlssortcnt, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

		if ((ofl->ofl_osdyntlssort = ld_place_section(ofl, isec, NULL,
		    ld_targ.t_id.id_dynsort, NULL)) == (Os_desc *)S_ERROR)
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

	dynsymisp = ld_os_first_isdesc(symtab);
	dynshdr = dynsymisp->is_shdr;

	if (new_section(ofl, SHT_SYMTAB_SHNDX, shname,
	    (dynshdr->sh_size / dynshdr->sh_entsize),
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((*ret_os = ld_place_section(ofl, isec, NULL,
	    ld_targ.t_id.id_dynsym_ndx, NULL)) == (Os_desc *)S_ERROR)
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
	ofl->ofl_osshstrtab =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_note, NULL);
	if (ofl->ofl_osshstrtab == (Os_desc *)S_ERROR)
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

	ofl->ofl_osstrtab =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_strtab, NULL);
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
			Sym_desc	*sdp;

			if ((sdp = ofl->ofl_regsyms[ndx]) == NULL)
				continue;

			if (!SYM_IS_HIDDEN(sdp) &&
			    (ELF_ST_BIND(sdp->sd_sym->st_info) != STB_LOCAL))
				continue;

			if (sdp->sd_sym->st_name == NULL)
				continue;

			if (st_insert(ofl->ofl_dynstrtab, sdp->sd_name) == -1)
				return (S_ERROR);
		}
	}

	/*
	 * Reserve entries for any per-symbol auxiliary/filter strings.
	 */
	if (ofl->ofl_dtsfltrs != NULL) {
		Dfltr_desc	*dftp;
		Aliste		idx;

		for (ALIST_TRAVERSE(ofl->ofl_dtsfltrs, idx, dftp))
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

	ofl->ofl_osdynstr =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_dynstr, NULL);
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
	if (ld_targ.t_m.m_rel_sht_type == SHT_REL) {
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
	} else if (ofl->ofl_flags & FLG_OF_COMREL) {
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

	if (new_section(ofl, ld_targ.t_m.m_rel_sht_type, sectname, 0, &isec,
	    &shdr, &data) == S_ERROR)
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

	rosp = ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_rel, NULL);
	if (rosp == (Os_desc *)S_ERROR)
		return (S_ERROR);

	/*
	 * Associate this relocation section to the section its going to
	 * relocate.
	 */
	if (osp) {
		Aliste	idx;
		Is_desc	*risp;

		/*
		 * This is used primarily so that we can update
		 * SHT_GROUP[sect_no] entries to point to the
		 * created output relocation sections.
		 */
		for (APLIST_TRAVERSE(osp->os_relisdescs, idx, risp)) {
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

	ofl->ofl_osverneed =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_version, NULL);
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
	Str_tbl		*strtab;

	/*
	 * Reserve a string table entry for the base version dependency (other
	 * dependencies have symbol representations, which will already be
	 * accounted for during symbol processing).
	 */
	vdp = (Ver_desc *)ofl->ofl_verdesc->apl_data[0];

	if (OFL_IS_STATIC_OBJ(ofl))
		strtab = ofl->ofl_strtab;
	else
		strtab = ofl->ofl_dynstrtab;

	if (st_insert(strtab, vdp->vd_name) == -1)
		return (S_ERROR);

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

	ofl->ofl_osverdef =
	    ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_version, NULL);
	return ((uintptr_t)ofl->ofl_osverdef);
}

/*
 * This routine is called when -z nopartial is in effect.
 */
uintptr_t
ld_make_parexpn_data(Ofl_desc *ofl, size_t size, Xword align)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_DATA), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	shdr->sh_flags |= SHF_WRITE;
	data->d_size = size;
	shdr->sh_size = (Xword)size;
	if (align != 0) {
		data->d_align = align;
		shdr->sh_addralign = align;
	}

	if ((data->d_buf = libld_calloc(size, 1)) == NULL)
		return (S_ERROR);

	/*
	 * Retain handle to this .data input section. Variables using move
	 * sections (partial initialization) will be redirected here when
	 * such global references are added and '-z nopartial' is in effect.
	 */
	ofl->ofl_isparexpn = isec;
	osp = ld_place_section(ofl, isec, NULL, ld_targ.t_id.id_data, NULL);
	if (osp == (Os_desc *)S_ERROR)
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
	Aliste		idx;
	Sym_desc	*sdp;
	int 		cnt = 1;


	if (new_section(ofl, SHT_SUNW_move, MSG_ORIG(MSG_SCN_SUNWMOVE),
	    mv_nums, &isec, &shdr, &data) == S_ERROR)
		return (S_ERROR);

	if ((data->d_buf = libld_calloc(data->d_size, 1)) == NULL)
		return (S_ERROR);

	/*
	 * Copy move entries
	 */
	for (APLIST_TRAVERSE(ofl->ofl_parsyms, idx, sdp)) {
		Aliste		idx2;
		Mv_desc		*mdp;

		if (sdp->sd_flags & FLG_SY_PAREXPN)
			continue;

		for (ALIST_TRAVERSE(sdp->sd_move, idx2, mdp))
			mdp->md_oidx = cnt++;
	}

	if ((ofl->ofl_osmove = ld_place_section(ofl, isec, NULL, 0, NULL)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	return (1);
}

/*
 * Given a relocation descriptor that references a string table
 * input section, locate the string referenced and return a pointer
 * to it.
 */
static const char *
strmerge_get_reloc_str(Ofl_desc *ofl, Rel_desc *rsp)
{
	Sym_desc *sdp = rsp->rel_sym;
	Xword	 str_off;

	/*
	 * In the case of an STT_SECTION symbol, the addend of the
	 * relocation gives the offset into the string section. For
	 * other symbol types, the symbol value is the offset.
	 */

	if (ELF_ST_TYPE(sdp->sd_sym->st_info) != STT_SECTION) {
		str_off = sdp->sd_sym->st_value;
	} else if ((rsp->rel_flags & FLG_REL_RELA) == FLG_REL_RELA) {
		/*
		 * For SHT_RELA, the addend value is found in the
		 * rel_raddend field of the relocation.
		 */
		str_off = rsp->rel_raddend;
	} else {	/* REL and STT_SECTION */
		/*
		 * For SHT_REL, the "addend" is not part of the relocation
		 * record. Instead, it is found at the relocation target
		 * address.
		 */
		uchar_t *addr = (uchar_t *)((uintptr_t)rsp->rel_roffset +
		    (uintptr_t)rsp->rel_isdesc->is_indata->d_buf);

		if (ld_reloc_targval_get(ofl, rsp, addr, &str_off) == 0)
			return (0);
	}

	return (str_off + (char *)sdp->sd_isc->is_indata->d_buf);
}

/*
 * First pass over the relocation records for string table merging.
 * Build lists of relocations and symbols that will need modification,
 * and insert the strings they reference into the mstrtab string table.
 *
 * entry:
 *	ofl, osp - As passed to ld_make_strmerge().
 *	mstrtab - String table to receive input strings. This table
 *		must be in its first (initialization) pass and not
 *		yet cooked (st_getstrtab_sz() not yet called).
 *	rel_alpp - APlist to receive pointer to any relocation
 *		descriptors with STT_SECTION symbols that reference
 *		one of the input sections being merged.
 *	sym_alpp - APlist to receive pointer to any symbols that reference
 *		one of the input sections being merged.
 *	rcp - Pointer to cache of relocation descriptors to examine.
 *		Either &ofl->ofl_actrels (active relocations)
 *		or &ofl->ofl_outrels (output relocations).
 *
 * exit:
 *	On success, rel_alpp and sym_alpp are updated, and
 *	any strings in the mergeable input sections referenced by
 *	a relocation has been entered into mstrtab. True (1) is returned.
 *
 *	On failure, False (0) is returned.
 */
static int
strmerge_pass1(Ofl_desc *ofl, Os_desc *osp, Str_tbl *mstrtab,
    APlist **rel_alpp, APlist **sym_alpp, Rel_cache *rcp)
{
	Aliste		idx;
	Rel_cachebuf	*rcbp;
	Sym_desc	*sdp;
	Sym_desc	*last_sdp = NULL;
	Rel_desc	*rsp;
	const char	*name;

	REL_CACHE_TRAVERSE(rcp, idx, rcbp, rsp) {
		sdp = rsp->rel_sym;
		if ((sdp->sd_isc == NULL) || ((sdp->sd_isc->is_flags &
		    (FLG_IS_DISCARD | FLG_IS_INSTRMRG)) != FLG_IS_INSTRMRG) ||
		    (sdp->sd_isc->is_osdesc != osp))
			continue;

		/*
		 * Remember symbol for use in the third pass. There is no
		 * reason to save a given symbol more than once, so we take
		 * advantage of the fact that relocations to a given symbol
		 * tend to cluster in the list. If this is the same symbol
		 * we saved last time, don't bother.
		 */
		if (last_sdp != sdp) {
			if (aplist_append(sym_alpp, sdp, AL_CNT_STRMRGSYM) ==
			    NULL)
				return (0);
			last_sdp = sdp;
		}

		/* Enter the string into our new string table */
		name = strmerge_get_reloc_str(ofl, rsp);
		if (st_insert(mstrtab, name) == -1)
			return (0);

		/*
		 * If this is an STT_SECTION symbol, then the second pass
		 * will need to modify this relocation, so hang on to it.
		 */
		if ((ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) &&
		    (aplist_append(rel_alpp, rsp, AL_CNT_STRMRGREL) == NULL))
			return (0);
	}

	return (1);
}

/*
 * If the output section has any SHF_MERGE|SHF_STRINGS input sections,
 * replace them with a single merged/compressed input section.
 *
 * entry:
 *	ofl - Output file descriptor
 *	osp - Output section descriptor
 *	rel_alpp, sym_alpp, - Address of 2 APlists, to be used
 *		for internal processing. On the initial call to
 *		ld_make_strmerge, these list pointers must be NULL.
 *		The caller is encouraged to pass the same lists back for
 *		successive calls to this function without freeing
 *		them in between calls. This causes a single pair of
 *		memory allocations to be reused multiple times.
 *
 * exit:
 *	If section merging is possible, it is done. If no errors are
 *	encountered, True (1) is returned. On error, S_ERROR.
 *
 *	The contents of rel_alpp and sym_alpp on exit are
 *	undefined. The caller can free them, or pass them back to a subsequent
 *	call to this routine, but should not examine their contents.
 */
static uintptr_t
ld_make_strmerge(Ofl_desc *ofl, Os_desc *osp, APlist **rel_alpp,
    APlist **sym_alpp)
{
	Str_tbl		*mstrtab;	/* string table for string merge secs */
	Is_desc		*mstrsec;	/* Generated string merge section */
	Is_desc		*isp;
	Shdr		*mstr_shdr;
	Elf_Data	*mstr_data;
	Sym_desc	*sdp;
	Rel_desc	*rsp;
	Aliste		idx;
	size_t		data_size;
	int		st_setstring_status;
	size_t		stoff;

	/* If string table compression is disabled, there's nothing to do */
	if ((ofl->ofl_flags1 & FLG_OF1_NCSTTAB) != 0)
		return (1);

	/*
	 * Pass over the mergeable input sections, and if they haven't
	 * all been discarded, create a string table.
	 */
	mstrtab = NULL;
	for (APLIST_TRAVERSE(osp->os_mstrisdescs, idx, isp)) {
		if (isdesc_discarded(isp))
			continue;

		/*
		 * Input sections of 0 size are dubiously valid since they do
		 * not even contain the NUL string.  Ignore them.
		 */
		if (isp->is_shdr->sh_size == 0)
			continue;

		/*
		 * We have at least one non-discarded section.
		 * Create a string table descriptor.
		 */
		if ((mstrtab = st_new(FLG_STNEW_COMPRESS)) == NULL)
			return (S_ERROR);
		break;
	}

	/* If no string table was created, we have no mergeable sections */
	if (mstrtab == NULL)
		return (1);

	/*
	 * This routine has to make 3 passes:
	 *
	 *	1) Examine all relocations, insert strings from relocations
	 *		to the mergeable input sections into the string table.
	 *	2) Modify the relocation values to be correct for the
	 *		new merged section.
	 *	3) Modify the symbols used by the relocations to reference
	 *		the new section.
	 *
	 * These passes cannot be combined:
	 *	- The string table code works in two passes, and all
	 *		strings have to be loaded in pass one before the
	 *		offset of any strings can be determined.
	 *	- Multiple relocations reference a single symbol, so the
	 *		symbol cannot be modified until all relocations are
	 *		fixed.
	 *
	 * The number of relocations related to section merging is usually
	 * a mere fraction of the overall active and output relocation lists,
	 * and the number of symbols is usually a fraction of the number
	 * of related relocations. We therefore build APlists for the
	 * relocations and symbols in the first pass, and then use those
	 * lists to accelerate the operation of pass 2 and 3.
	 *
	 * Reinitialize the lists to a completely empty state.
	 */
	aplist_reset(*rel_alpp);
	aplist_reset(*sym_alpp);

	/*
	 * Pass 1:
	 *
	 * Every relocation related to this output section (and the input
	 * sections that make it up) is found in either the active, or the
	 * output relocation list, depending on whether the relocation is to
	 * be processed by this invocation of the linker, or inserted into the
	 * output object.
	 *
	 * Build lists of relocations and symbols that will need modification,
	 * and insert the strings they reference into the mstrtab string table.
	 */
	if (strmerge_pass1(ofl, osp, mstrtab, rel_alpp, sym_alpp,
	    &ofl->ofl_actrels) == 0)
		goto return_s_error;
	if (strmerge_pass1(ofl, osp, mstrtab, rel_alpp, sym_alpp,
	    &ofl->ofl_outrels) == 0)
		goto return_s_error;

	/*
	 * Get the size of the new input section. Requesting the
	 * string table size "cooks" the table, and finalizes its contents.
	 */
	data_size = st_getstrtab_sz(mstrtab);

	/* Create a new input section to hold the merged strings */
	if (new_section_from_template(ofl, isp, data_size,
	    &mstrsec, &mstr_shdr, &mstr_data) == S_ERROR)
		goto return_s_error;
	mstrsec->is_flags |= FLG_IS_GNSTRMRG;

	/*
	 * Allocate a data buffer for the new input section.
	 * Then, associate the buffer with the string table descriptor.
	 */
	if ((mstr_data->d_buf = libld_malloc(data_size)) == NULL)
		goto return_s_error;
	if (st_setstrbuf(mstrtab, mstr_data->d_buf, data_size) == -1)
		goto return_s_error;

	/* Add the new section to the output image */
	if (ld_place_section(ofl, mstrsec, NULL, osp->os_identndx, NULL) ==
	    (Os_desc *)S_ERROR)
		goto return_s_error;

	/*
	 * Pass 2:
	 *
	 * Revisit the relocation descriptors with STT_SECTION symbols
	 * that were saved by the first pass. Update each relocation
	 * record so that the offset it contains is for the new section
	 * instead of the original.
	 */
	for (APLIST_TRAVERSE(*rel_alpp, idx, rsp)) {
		const char	*name;

		/* Put the string into the merged string table */
		name = strmerge_get_reloc_str(ofl, rsp);
		st_setstring_status = st_setstring(mstrtab, name, &stoff);
		if (st_setstring_status == -1) {
			/*
			 * A failure to insert at this point means that
			 * something is corrupt. This isn't a resource issue.
			 */
			assert(st_setstring_status != -1);
			goto return_s_error;
		}

		/*
		 * Alter the relocation to access the string at the
		 * new offset in our new string table.
		 *
		 * For SHT_RELA platforms, it suffices to simply
		 * update the rel_raddend field of the relocation.
		 *
		 * For SHT_REL platforms, the new "addend" value
		 * needs to be written at the address being relocated.
		 * However, we can't alter the input sections which
		 * are mapped readonly, and the output image has not
		 * been created yet. So, we defer this operation,
		 * using the rel_raddend field of the relocation
		 * which is normally 0 on a REL platform, to pass the
		 * new "addend" value to ld_perform_outreloc() or
		 * ld_do_activerelocs(). The FLG_REL_NADDEND flag
		 * tells them that this is the case.
		 */
		if ((rsp->rel_flags & FLG_REL_RELA) == 0)   /* REL */
			rsp->rel_flags |= FLG_REL_NADDEND;
		rsp->rel_raddend = (Sxword)stoff;

		/*
		 * Generate a symbol name string for STT_SECTION symbols
		 * that might reference our merged section. This shows up
		 * in debug output and helps show how the relocation has
		 * changed from its original input section to our merged one.
		 */
		if (ld_stt_section_sym_name(mstrsec) == NULL)
			goto return_s_error;
	}

	/*
	 * Pass 3:
	 *
	 * Modify the symbols referenced by the relocation descriptors
	 * so that they reference the new input section containing the
	 * merged strings instead of the original input sections.
	 */
	for (APLIST_TRAVERSE(*sym_alpp, idx, sdp)) {
		/*
		 * If we've already processed this symbol, don't do it
		 * twice. strmerge_pass1() uses a heuristic (relocations to
		 * the same symbol clump together) to avoid inserting a
		 * given symbol more than once, but repeat symbols in
		 * the list can occur.
		 */
		if ((sdp->sd_isc->is_flags & FLG_IS_INSTRMRG) == 0)
			continue;

		if (ELF_ST_TYPE(sdp->sd_sym->st_info) != STT_SECTION) {
			/*
			 * This is not an STT_SECTION symbol, so its
			 * value is the offset of the string within the
			 * input section. Update the address to reflect
			 * the address in our new merged section.
			 */
			const char *name = sdp->sd_sym->st_value +
			    (char *)sdp->sd_isc->is_indata->d_buf;

			st_setstring_status =
			    st_setstring(mstrtab, name, &stoff);
			if (st_setstring_status == -1) {
				/*
				 * A failure to insert at this point means
				 * something is corrupt. This isn't a
				 * resource issue.
				 */
				assert(st_setstring_status != -1);
				goto return_s_error;
			}

			if (ld_sym_copy(sdp) == S_ERROR)
				goto return_s_error;
			sdp->sd_sym->st_value = (Word)stoff;
		}

		/* Redirect the symbol to our new merged section */
		sdp->sd_isc = mstrsec;
	}

	/*
	 * There are no references left to the original input string sections.
	 * Mark them as discarded so they don't go into the output image.
	 * At the same time, add up the sizes of the replaced sections.
	 */
	data_size = 0;
	for (APLIST_TRAVERSE(osp->os_mstrisdescs, idx, isp)) {
		if (isp->is_flags & (FLG_IS_DISCARD | FLG_IS_GNSTRMRG))
			continue;

		data_size += isp->is_indata->d_size;

		isp->is_flags |= FLG_IS_DISCARD;
		DBG_CALL(Dbg_sec_discarded(ofl->ofl_lml, isp, mstrsec));
	}

	/* Report how much space we saved in the output section */
	DBG_CALL(Dbg_sec_genstr_compress(ofl->ofl_lml, osp->os_name, data_size,
	    mstr_data->d_size));

	st_destroy(mstrtab);
	return (1);

return_s_error:
	st_destroy(mstrtab);
	return (S_ERROR);
}

/*
 * Update a data buffers size.  A number of sections have to be created, and
 * the sections header contributes to the size of the eventual section.  Thus,
 * a section may be created, and once all associated sections have been created,
 * we return to establish the required section size.
 */
inline static void
update_data_size(Os_desc *osp, ulong_t cnt)
{
	Is_desc		*isec = ld_os_first_isdesc(osp);
	Elf_Data	*data = isec->is_indata;
	Shdr		*shdr = osp->os_shdr;
	size_t		size = cnt * shdr->sh_entsize;

	shdr->sh_size = (Xword)size;
	data->d_size = size;
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
	ofl_flag_t	flags = ofl->ofl_flags;
	Sg_desc		*sgp;

	/*
	 * Generate any special sections.
	 */
	if (flags & FLG_OF_ADDVERS)
		if (make_comment(ofl) == S_ERROR)
			return (S_ERROR);

	if (make_interp(ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Create a capabilities section if required.
	 */
	if (make_cap(ofl, SHT_SUNW_cap, MSG_ORIG(MSG_SCN_SUNWCAP),
	    ld_targ.t_id.id_cap) == S_ERROR)
		return (S_ERROR);

	/*
	 * Create any init/fini array sections.
	 */
	if (make_array(ofl, SHT_INIT_ARRAY, MSG_ORIG(MSG_SCN_INITARRAY),
	    ofl->ofl_initarray) == S_ERROR)
		return (S_ERROR);

	if (make_array(ofl, SHT_FINI_ARRAY, MSG_ORIG(MSG_SCN_FINIARRAY),
	    ofl->ofl_finiarray) == S_ERROR)
		return (S_ERROR);

	if (make_array(ofl, SHT_PREINIT_ARRAY, MSG_ORIG(MSG_SCN_PREINITARRAY),
	    ofl->ofl_preiarray) == S_ERROR)
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
	 * If we have detected a situation in which previously placed
	 * output sections may have been discarded, perform the necessary
	 * readjustment.
	 */
	if (ofl->ofl_flags & FLG_OF_ADJOSCNT)
		adjust_os_count(ofl);

	/*
	 * Do any of the output sections contain input sections that
	 * are candidates for string table merging? For each such case,
	 * we create a replacement section, insert it, and discard the
	 * originals.
	 *
	 * rel_alpp and sym_alpp are used by ld_make_strmerge()
	 * for its internal processing. We are responsible for the
	 * initialization and cleanup, and ld_make_strmerge() handles the rest.
	 * This allows us to reuse a single pair of memory buffers, allocated
	 * for this processing, for all the output sections.
	 */
	if ((ofl->ofl_flags1 & FLG_OF1_NCSTTAB) == 0) {
		int	error_seen = 0;
		APlist	*rel_alpp = NULL;
		APlist	*sym_alpp = NULL;
		Aliste	idx1;

		for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
			Os_desc	*osp;
			Aliste	idx2;

			for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp))
				if ((osp->os_mstrisdescs != NULL) &&
				    (ld_make_strmerge(ofl, osp,
				    &rel_alpp, &sym_alpp) ==
				    S_ERROR)) {
					error_seen = 1;
					break;
				}
		}
		if (rel_alpp != NULL)
			libld_free(rel_alpp);
		if (sym_alpp != NULL)
			libld_free(sym_alpp);
		if (error_seen != 0)
			return (S_ERROR);
	}

	/*
	 * Add any necessary versioning information.
	 */
	if (!(flags & FLG_OF_NOVERSEC)) {
		if ((flags & FLG_OF_VERNEED) &&
		    (make_verneed(ofl) == S_ERROR))
			return (S_ERROR);
		if ((flags & FLG_OF_VERDEF) &&
		    (make_verdef(ofl) == S_ERROR))
			return (S_ERROR);
		if ((flags & (FLG_OF_VERNEED | FLG_OF_VERDEF)) &&
		    ((ofl->ofl_osversym = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWVERSYM), SHT_SUNW_versym,
		    ld_targ.t_id.id_version)) == (Os_desc*)S_ERROR))
			return (S_ERROR);
	}

	/*
	 * Create a syminfo section if necessary.
	 */
	if (flags & FLG_OF_SYMINFO) {
		if ((ofl->ofl_ossyminfo = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWSYMINFO), SHT_SUNW_syminfo,
		    ld_targ.t_id.id_syminfo)) == (Os_desc *)S_ERROR)
			return (S_ERROR);
	}

	if (flags & FLG_OF_COMREL) {
		/*
		 * If -zcombreloc is enabled then all relocations (except for
		 * the PLT's) are coalesced into a single relocation section.
		 */
		if (ofl->ofl_reloccnt) {
			if (make_reloc(ofl, NULL) == S_ERROR)
				return (S_ERROR);
		}
	} else {
		Aliste	idx1;

		/*
		 * Create the required output relocation sections.  Note, new
		 * sections may be added to the section list that is being
		 * traversed.  These insertions can move the elements of the
		 * Alist such that a section descriptor is re-read.  Recursion
		 * is prevented by maintaining a previous section pointer and
		 * insuring that this pointer isn't re-examined.
		 */
		for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
			Os_desc	*osp, *posp = 0;
			Aliste	idx2;

			for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
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

		/*
		 * A number of sections aren't necessary within a relocatable
		 * object, even if -dy has been used.
		 */
		if (!(flags & FLG_OF_RELOBJ)) {
			if (make_hash(ofl) == S_ERROR)
				return (S_ERROR);
			if (make_dynstr(ofl) == S_ERROR)
				return (S_ERROR);
			if (make_dynsym(ofl) == S_ERROR)
				return (S_ERROR);
			if (ld_unwind_make_hdr(ofl) == S_ERROR)
				return (S_ERROR);
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
	 * Now that we've created all output sections, adjust the size of the
	 * SHT_SUNW_versym and SHT_SUNW_syminfo section, which are dependent on
	 * the associated symbol table sizes.
	 */
	if (ofl->ofl_osversym || ofl->ofl_ossyminfo) {
		ulong_t		cnt;
		Is_desc		*isp;
		Os_desc		*osp;

		if (OFL_IS_STATIC_OBJ(ofl))
			osp = ofl->ofl_ossymtab;
		else
			osp = ofl->ofl_osdynsym;

		isp = ld_os_first_isdesc(osp);
		cnt = (isp->is_shdr->sh_size / isp->is_shdr->sh_entsize);

		if (ofl->ofl_osversym)
			update_data_size(ofl->ofl_osversym, cnt);

		if (ofl->ofl_ossyminfo)
			update_data_size(ofl->ofl_ossyminfo, cnt);
	}

	/*
	 * Now that we've created all output sections, adjust the size of the
	 * SHT_SUNW_capinfo, which is dependent on the associated symbol table
	 * size.
	 */
	if (ofl->ofl_oscapinfo) {
		ulong_t	cnt;

		/*
		 * Symbol capabilities symbols are placed directly after the
		 * STT_FILE symbol, section symbols, and any register symbols.
		 * Effectively these are the first of any series of demoted
		 * (scoped) symbols.
		 */
		if (OFL_IS_STATIC_OBJ(ofl))
			cnt = SYMTAB_ALL_CNT(ofl);
		else
			cnt = DYNSYM_ALL_CNT(ofl);

		update_data_size(ofl->ofl_oscapinfo, cnt);
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

	if (aplist_append(&ofl->ofl_mapdata, isec, AL_CNT_OFL_MAPSECS) == NULL)
		return ((Is_desc *)S_ERROR);

	return (isec);
}

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
	if (size < ld_targ.t_nf.nf_size)
		size = ld_targ.t_nf.nf_size;

	if (new_section(ofl, SHT_PROGBITS, MSG_ORIG(MSG_SCN_TEXT), 0,
	    &isec, &shdr, &data) == S_ERROR)
		return ((Is_desc *)S_ERROR);

	data->d_size = size;
	shdr->sh_size = (Xword)size;
	shdr->sh_flags |= SHF_EXECINSTR;

	/*
	 * Fill the buffer with the appropriate return instruction.
	 * Note that there is no need to swap bytes on a non-native,
	 * link, as the data being copied is given in bytes.
	 */
	if ((data->d_buf = libld_calloc(size, 1)) == NULL)
		return ((Is_desc *)S_ERROR);
	(void) memcpy(data->d_buf, ld_targ.t_nf.nf_template,
	    ld_targ.t_nf.nf_size);

	/*
	 * If size was larger than required, and the target supplies
	 * a fill function, use it to fill the balance. If there is no
	 * fill function, we accept the 0-fill supplied by libld_calloc().
	 */
	if ((ld_targ.t_ff.ff_execfill != NULL) && (size > ld_targ.t_nf.nf_size))
		ld_targ.t_ff.ff_execfill(data->d_buf, ld_targ.t_nf.nf_size,
		    size - ld_targ.t_nf.nf_size);

	if (aplist_append(&ofl->ofl_maptext, isec, AL_CNT_OFL_MAPSECS) == NULL)
		return ((Is_desc *)S_ERROR);

	return (isec);
}

void
ld_comdat_validate(Ofl_desc *ofl, Ifl_desc *ifl)
{
	int i;

	for (i = 0; i < ifl->ifl_shnum; i++) {
		Is_desc *isp = ifl->ifl_isdesc[i];
		int types = 0;
		char buf[1024] = "";
		Group_desc *gr = NULL;

		if ((isp == NULL) || (isp->is_flags & FLG_IS_COMDAT) == 0)
			continue;

		if (isp->is_shdr->sh_type == SHT_SUNW_COMDAT) {
			types++;
			(void) strlcpy(buf, MSG_ORIG(MSG_STR_SUNW_COMDAT),
			    sizeof (buf));
		}

		if (strncmp(MSG_ORIG(MSG_SCN_GNU_LINKONCE), isp->is_name,
		    MSG_SCN_GNU_LINKONCE_SIZE) == 0) {
			types++;
			if (types > 1)
				(void) strlcat(buf, ", ", sizeof (buf));
			(void) strlcat(buf, MSG_ORIG(MSG_SCN_GNU_LINKONCE),
			    sizeof (buf));
		}

		if ((isp->is_shdr->sh_flags & SHF_GROUP) &&
		    ((gr = ld_get_group(ofl, isp)) != NULL) &&
		    (gr->gd_data[0] & GRP_COMDAT)) {
			types++;
			if (types > 1)
				(void) strlcat(buf, ", ", sizeof (buf));
			(void) strlcat(buf, MSG_ORIG(MSG_STR_GROUP),
			    sizeof (buf));
		}

		if (types > 1)
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_SCN_MULTICOMDAT), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), isp->is_name, buf);
	}
}
