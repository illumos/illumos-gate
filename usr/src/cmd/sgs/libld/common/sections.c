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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Module sections. Initialize special sections
 */
#include	<string.h>
#include	<strings.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<link.h>
#include	"debug.h"
#include	"msg.h"
#include	"_libld.h"


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
uintptr_t
ignore_section_processing(Ofl_desc *ofl)
{
	Listnode	*lnp;
	Ifl_desc	*ifl;
	Rel_cache	*rcp;

	for (LIST_TRAVERSE(&ofl->ofl_objs, lnp, ifl)) {
		uint_t	num, discard;

		/*
		 * Diagnose (-D unused) a completely unreferenced file.
		 */
		if ((ifl->ifl_flags & FLG_IF_FILEREF) == 0)
			DBG_CALL(Dbg_unused_file(ifl->ifl_name, 0, 0));
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
				Is_desc	*isp;
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

			sdp = ifl->ifl_oldndx[num];
			symp = sdp->sd_sym;

			/*
			 * If the whole file is being eliminated, remove the
			 * local file symbol, and any COMMON symbols (which
			 * aren't associated with a section) provided they
			 * haven't been referenced by a relocation.
			 */
			if ((ofl->ofl_flags1 & FLG_OF1_IGNORE) &&
			    ((ifl->ifl_flags & FLG_IF_FILEREF) == 0) &&
			    ((ELF_ST_TYPE(symp->st_info) == STT_FILE) ||
			    ((symp->st_shndx == SHN_COMMON) &&
			    ((sdp->sd_flags & FLG_SY_UPREQD) == 0)))) {
				if ((ofl->ofl_flags1 & FLG_OF1_REDLSYM) == 0) {
					ofl->ofl_locscnt--;
					err = st_delstring(ofl->ofl_strtab,
					    sdp->sd_name);
					assert(err != -1);
				}
				sdp->sd_flags |= FLG_SY_ISDISC;
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
			    (ELF_ST_TYPE(symp->st_info) == STT_SECTION) ||
			    (sdp->sd_flags & FLG_SY_ISDISC) ||
			    (sdp->sd_flags1 & FLG_SY1_ELIM) ||
			    (sdp->sd_isc == 0) || (sdp->sd_file != ifl))
				continue;

			/*
			 * If any references were made against the section
			 * the symbol is being defined in - skip it.
			 */
			if ((sdp->sd_isc->is_flags & FLG_IS_SECTREF) ||
			    (((ifl->ifl_flags & FLG_IF_FILEREF) &&
			    ((osp = sdp->sd_isc->is_osdesc) != 0) &&
			    (osp->os_sgdesc->sg_phdr.p_type != PT_LOAD))))
				continue;

			/*
			 * Finish processing any local symbols.
			 */
			if (ELF_ST_BIND(symp->st_info) == STB_LOCAL) {
				if (ofl->ofl_flags1 & FLG_OF1_IGNORE) {
					if ((ofl->ofl_flags1 &
					    FLG_OF1_REDLSYM) == 0) {
						ofl->ofl_locscnt--;

						err = st_delstring(
						    ofl->ofl_strtab,
						    sdp->sd_name);
						assert(err != -1);
					}
					sdp->sd_flags |= FLG_SY_ISDISC;
				}
				DBG_CALL(Dbg_syms_discarded(sdp, sdp->sd_isc));
				continue;
			}

			/*
			 * Global symbols can only be eliminated when an objects
			 * interfaces (versioning/scoping) is defined.
			 */
			if (sdp->sd_flags1 & FLG_SY1_LOCL) {
				if (ofl->ofl_flags1 & FLG_OF1_IGNORE) {
					ofl->ofl_scopecnt--;
					ofl->ofl_elimcnt++;

					err = st_delstring(ofl->ofl_strtab,
					    sdp->sd_name);
					assert(err != -1);

					sdp->sd_flags1 |= FLG_SY1_ELIM;
				}
				DBG_CALL(Dbg_syms_discarded(sdp, sdp->sd_isc));
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
 * Build a .bss section for allocation of tentative definitions.  Any `static'
 * .bss definitions would have been associated to their own .bss sections and
 * thus collected from the input files.  `global' .bss definitions are tagged
 * as COMMON and do not cause any associated .bss section elements to be
 * generated.  Here we add up all these COMMON symbols and generate the .bss
 * section required to represent them.
 */
uintptr_t
make_bss(Ofl_desc *ofl, Xword size, Xword align, Bss_Type which)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;
	uint_t		ident;
	Xword		rsize = (Xword)ofl->ofl_relocbsssz;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = (size_t)size;
	data->d_align = (size_t)align;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_NOBITS;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr->sh_size = size;
	shdr->sh_addralign = align;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);

	isec->is_shdr = shdr;
	isec->is_indata = data;

	if (which == MAKE_TLS) {
		isec->is_name = MSG_ORIG(MSG_SCN_TBSS);
		ident = M_ID_TLSBSS;
		ofl->ofl_istlsbss = isec;
		shdr->sh_flags |= SHF_TLS;
	} else if (which == MAKE_BSS) {
		isec->is_name = MSG_ORIG(MSG_SCN_BSS);
		ofl->ofl_isbss = isec;
		ident = M_ID_BSS;

#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
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
	if ((osp = place_section(ofl, isec, ident, 0)) == (Os_desc *)S_ERROR)
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
uintptr_t
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

	if (list->head == NULL)
		return (1);

	entcount = 0;
	for (LIST_TRAVERSE(list, lnp, sdp))
		entcount++;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if (((data = libld_calloc(sizeof (Elf_Data), 1)) == 0) ||
	    ((data->d_buf = libld_calloc(sizeof (Addr), entcount)) == 0))
		return (S_ERROR);

	data->d_type = ELF_T_ADDR;
	data->d_size = sizeof (Addr) * entcount;
	data->d_align = sizeof (Addr);
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = shtype;
	shdr->sh_size = (Xword)data->d_size;
	shdr->sh_entsize = sizeof (Addr);
	shdr->sh_addralign = (Xword)data->d_align;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = sectname;
	isec->is_shdr = shdr;
	isec->is_indata = data;

	if (place_section(ofl, isec, M_ID_ARRAY, 0) == (Os_desc *)S_ERROR)
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

	DBG_CALL(Dbg_reloc_generate(osp, M_REL_SHT_TYPE));
	for (LIST_TRAVERSE(list, lnp, sdp)) {
		reld.rel_sname = sdp->sd_name;
		reld.rel_sym = sdp;

		if (process_sym_reloc(ofl, &reld, (Rel *)&reloc, isec,
		    MSG_INTL(MSG_STR_COMMAND)) == S_ERROR)
			return (S_ERROR);

		reld.rel_roffset += (Xword)sizeof (Addr);
		reloc.r_offset = reld.rel_roffset;
	}

	return (1);
}

/*
 * Build a comment section (-Qy option).
 */
uintptr_t
make_comment(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_buf = (void *)ofl->ofl_sgsid;
	data->d_size = strlen(ofl->ofl_sgsid) + 1;
	data->d_align = 1;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_size = (Xword)data->d_size;
	shdr->sh_addralign = 1;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_COMMENT);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	return ((uintptr_t)place_section(ofl, isec, M_ID_NOTE, 0));
}

/*
 * Make the dynamic section.  Calculate the size of any strings referenced
 * within this structure, they will be added to the global string table
 * (.dynstr).  This routine should be called before make_dynstr().
 */
uintptr_t
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

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_DYNAMIC;
	shdr->sh_flags = SHF_WRITE;
	if (!(flags & FLG_OF_RELOBJ))
		shdr->sh_flags |= SHF_ALLOC;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = (Xword)elf_fsize(ELF_T_DYN, 1, ofl->ofl_libver);
	if (shdr->sh_entsize == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_FSIZE), ofl->ofl_name);
		return (S_ERROR);
	}


	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_DYN;
	data->d_size = 0;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) ==
	    (Is_desc *)0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_DYNAMIC);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	osp = ofl->ofl_osdynamic = place_section(ofl, isec, M_ID_DYNAMIC, 0);

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
				DBG_CALL(Dbg_util_nl());
			DBG_CALL(Dbg_unused_file(ifl->ifl_soname,
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
		DBG_CALL(Dbg_util_nl());

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
	if (((sdp = sym_find(MSG_ORIG(MSG_SYM_INIT_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && sdp->sd_ref == REF_REL_NEED) {
		sdp->sd_flags |= FLG_SY_UPREQD;
		cnt++;
	}
	if (((sdp = sym_find(MSG_ORIG(MSG_SYM_FINI_U),
	    SYM_NOHASH, 0, ofl)) != NULL) && sdp->sd_ref == REF_REL_NEED) {
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
		 * Allocate one DT_REGISTER entry for ever register symbol.
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
	 * Account for Architecture dependent .dynamic entries, and defaults
	 */
	mach_make_dynamic(ofl, &cnt);

	cnt += 3;				/* DT_FLAGS, DT_FLAGS_1, */
						/*   and DT_NULL */

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
make_got(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = (size_t)ofl->ofl_gotcnt * M_GOT_ENTSIZE;
	size_t		rsize = (size_t)ofl->ofl_relocgotsz;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = M_GOT_ENTSIZE;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_GOT);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	if ((ofl->ofl_osgot = place_section(ofl, isec, M_ID_GOT, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	ofl->ofl_osgot->os_szoutrels = (Xword)rsize;

	return (1);
}

/*
 * Build an interp section.
 */
uintptr_t
make_interp(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	const char	*iname = ofl->ofl_interp;
	size_t		size;

	/*
	 * We always build an .interp section for dynamic executables.  However
	 * if the user has specifically specified an interpretor we'll build
	 * this section for any output (presumably the user knows what they are
	 * doing. refer ABI section 5-4, and ld.1 man page use of -I).
	 */
	if (((ofl->ofl_flags & (FLG_OF_DYNAMIC | FLG_OF_EXEC |
	    FLG_OF_RELOBJ)) != (FLG_OF_DYNAMIC | FLG_OF_EXEC)) && !iname)
		return (1);

	/*
	 * In the case of a dynamic executable supply a default interpretor
	 * if a specific interpreter has not been specified.
	 */
	if (!iname) {
		if (ofl->ofl_e_machine == EM_SPARCV9)
			iname = ofl->ofl_interp =
				MSG_ORIG(MSG_PTH_RTLD_SPARCV9);
		else if (ofl->ofl_e_machine == EM_AMD64)
			iname = ofl->ofl_interp =
				MSG_ORIG(MSG_PTH_RTLD_AMD64);
		else
			iname = ofl->ofl_interp = MSG_ORIG(MSG_PTH_RTLD);
	}

	size = strlen(iname) + 1;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_size = (Xword)size;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_INTERP);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	ofl->ofl_osinterp = place_section(ofl, isec, M_ID_INTERP, 0);
	return ((uintptr_t)ofl->ofl_osinterp);
}

/*
 * Build a hardware/software capabilities section.
 */
uintptr_t
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

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_CAP;
	data->d_version = ofl->ofl_libver;
	data->d_align = M_WORD_ALIGN;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_SUNW_cap;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = (Xword)elf_fsize(ELF_T_CAP, 1, ofl->ofl_libver);
	if (shdr->sh_entsize == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_FSIZE), ofl->ofl_name);
		return (S_ERROR);
	}

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWCAP);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Determine the size of the section, and create the data.
	 */
	size = size * (size_t)shdr->sh_entsize;
	shdr->sh_size = (Xword)size;
	data->d_size = size;
	if ((data->d_buf = libld_malloc(size)) == 0)
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
	 * to trigger the creation of an associated  a program header.
	 */
	osec = place_section(ofl, isec, M_ID_CAP, 0);
	if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)
		ofl->ofl_oscap = osec;

	return ((uintptr_t)osec);
}

/*
 * Build the PLT section and its associated relocation entries.
 */
uintptr_t
make_plt(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = (size_t)M_PLT_RESERVSZ +
				(((size_t)ofl->ofl_pltcnt +
				(size_t)ofl->ofl_pltpad) * M_PLT_ENTSIZE);
	size_t		rsize = (size_t)ofl->ofl_relocpltsz;

#if defined(sparc)
	/*
	 * Account for the NOP at the end of the plt.
	 */
	size += sizeof (Word);
#endif

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = M_PLT_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = M_PLT_SHF_FLAGS;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_PLT_ALIGN;
	shdr->sh_entsize = M_PLT_ENTSIZE;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == (Is_desc *)0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_PLT);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	if ((ofl->ofl_osplt = place_section(ofl, isec, M_ID_PLT, 0)) ==
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
uintptr_t
make_hash(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;
	Word		nsyms = ofl->ofl_globcnt;
	size_t		cnt;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_WORD;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_HASH;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = (Xword)elf_fsize(ELF_T_WORD, 1, ofl->ofl_libver);
	if (shdr->sh_entsize == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_FSIZE), ofl->ofl_name);
		return (S_ERROR);
	}

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_HASH);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Place the section first since it will affect the local symbol
	 * count.
	 */
	if ((ofl->ofl_oshash = place_section(ofl, isec, M_ID_HASH, 0)) ==
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
uintptr_t
make_symtab(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Is_desc		*xisec = 0;
	size_t		size;
	Word		symcnt;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_SYM;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_SYMTAB;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = (Xword)elf_fsize(ELF_T_SYM, 1, ofl->ofl_libver);
	if (shdr->sh_entsize == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_FSIZE), ofl->ofl_name);
		return (S_ERROR);
	}

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SYMTAB);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Place the section first since it will affect the local symbol
	 * count.
	 */
	if ((ofl->ofl_ossymtab = place_section(ofl, isec, M_ID_SYMTAB, 0)) ==
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

		if ((xdata = libld_calloc(sizeof (Elf_Data), 1)) == 0)
			return (S_ERROR);
		xdata->d_type = ELF_T_WORD;
		xdata->d_align = M_WORD_ALIGN;
		xdata->d_version = ofl->ofl_libver;
		if ((xshdr = libld_calloc(sizeof (Shdr), 1)) == 0)
			return (S_ERROR);
		xshdr->sh_type = SHT_SYMTAB_SHNDX;
		xshdr->sh_addralign = M_WORD_ALIGN;
		xshdr->sh_entsize = sizeof (Word);
		if ((xisec = libld_calloc(1, sizeof (Is_desc))) == 0)
			return (S_ERROR);
		xisec->is_name = MSG_ORIG(MSG_SCN_SYMTAB_SHNDX);
		xisec->is_shdr = xshdr;
		xisec->is_indata = xdata;
		if ((ofl->ofl_ossymshndx = place_section(ofl, xisec,
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
 * Build a dynamic symbol table.  Contains only globals symbols and resides
 * in the text segment of a dynamic executable or shared library.
 */
uintptr_t
make_dynsym(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;
	Xword		cnt;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_SYM;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_DYNSYM;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = (Xword)elf_fsize(ELF_T_SYM, 1, ofl->ofl_libver);
	if (shdr->sh_entsize == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_FSIZE), ofl->ofl_name);
		return (S_ERROR);
	}

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_DYNSYM);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Place the section first since it will affect the local symbol
	 * count.
	 */
	if ((ofl->ofl_osdynsym = place_section(ofl, isec, M_ID_DYNSYM, 0)) ==
	    (Os_desc *)S_ERROR)
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

	return (1);
}

/*
 * Build a SHT_SYMTAB_SHNDX for the .dynsym
 */
uintptr_t
make_dynsym_shndx(Ofl_desc *ofl)
{
	Is_desc		*isec;
	Is_desc		*dynsymisp;
	Shdr		*shdr, *dynshdr;
	Elf_Data	*data;

	/*
	 * Allocate the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_WORD;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_SYMTAB_SHNDX;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = sizeof (Word);

	/*
	 * Allocate the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_DYNSYM_SHNDX);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	if ((ofl->ofl_osdynshndx = place_section(ofl, isec,
	    M_ID_DYNSYM_NDX, 0)) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	assert(ofl->ofl_osdynsym);
	dynsymisp = (Is_desc *)ofl->ofl_osdynsym->os_isdescs.head->data;
	dynshdr = dynsymisp->is_shdr;
	shdr->sh_size = (Xword)((dynshdr->sh_size / dynshdr->sh_entsize) *
		sizeof (Word));
	data->d_size = shdr->sh_size;

	return (1);
}


/*
 * Build a string table for the section headers.
 */
uintptr_t
make_shstrtab(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

	/*
	 * Allocate the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_align = 1;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags |= SHF_STRINGS;
	shdr->sh_addralign = 1;

	/*
	 * Allocate the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SHSTRTAB);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Place the section first, as it may effect the number of section
	 * headers to account for.
	 */
	if ((ofl->ofl_osshstrtab = place_section(ofl, isec, M_ID_NOTE, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	size = st_getstrtab_sz(ofl->ofl_shdrsttab);
	assert(size > 0);

	assert(size > 0);

	data->d_size = size;
	shdr->sh_size = (Xword)size;

	return (1);
}

/*
 * Build a string section for the standard symbol table.
 */
uintptr_t
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

	/*
	 * Allocate the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_size = size;
	data->d_type = ELF_T_BYTE;
	data->d_align = 1;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = 1;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags |= SHF_STRINGS;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_STRTAB);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	ofl->ofl_osstrtab = place_section(ofl, isec, M_ID_STRTAB, 0);
	return ((uintptr_t)ofl->ofl_osstrtab);
}

/*
 * Build a string table for the dynamic symbol table.
 */
uintptr_t
make_dynstr(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;

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

			if (((sdp->sd_flags1 & FLG_SY1_LOCL) == 0) &&
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

	/*
	 * Allocate the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = 1;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
		shdr->sh_flags = SHF_ALLOC;

	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags |= SHF_STRINGS;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = 1;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_DYNSTR);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	ofl->ofl_osdynstr = place_section(ofl, isec, M_ID_DYNSTR, 0);
	return ((uintptr_t)ofl->ofl_osdynstr);
}

/*
 * Generate an output relocation section which will contain the relocation
 * information to be applied to the `osp' section.
 *
 * If (osp == NULL) then we are creating the coalesced relocation section
 * for an executable and/or a shared object.
 */
uintptr_t
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

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = M_REL_ELF_TYPE;
	data->d_size = size;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = M_REL_SHT_TYPE;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = relsize;

	if ((ofl->ofl_flags & FLG_OF_DYNAMIC) &&
	    !(ofl->ofl_flags & FLG_OF_RELOBJ) &&
	    (sh_flags & SHF_ALLOC))
		shdr->sh_flags = SHF_ALLOC;

	if (osp) {
		/*
		 * The sh_info field of the SHT_REL* sections points to the
		 * section the relocations are to be applied to.
		 */
		shdr->sh_flags |= SHF_INFO_LINK;
	}


	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_shdr = shdr;
	isec->is_indata = data;
	isec->is_name = sectname;


	/*
	 * Associate this relocation section to the section its going to
	 * relocate.
	 */
	if ((rosp = place_section(ofl, isec, M_ID_REL, 0)) ==
	    (Os_desc *)S_ERROR)
		return (S_ERROR);

	if (osp) {
		Listnode *	lnp;
		Is_desc *	risp;
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
			 * If the input relocation section had
			 * the SHF_GROUP flag set - propogate it to
			 * the output relocation section.
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
uintptr_t
make_verneed(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size = ofl->ofl_verneedsz;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = (Word)SHT_SUNW_verneed;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_WORD_ALIGN;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWVERSION);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	ofl->ofl_osverneed = place_section(ofl, isec, M_ID_VERSION, 0);
	return ((uintptr_t)ofl->ofl_osverneed);
}

/*
 * Generate a version definition section.
 *
 *  o	the SHT_SUNW_verdef section defines the versions that exist within this
 *	image.
 */
uintptr_t
make_verdef(Ofl_desc *ofl)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Ver_desc	*vdp;
	size_t		size;

	/*
	 * Reserve a string table entry for the base version dependency (other
	 * dependencies have symbol representations, which will already be
	 * accounted for during symbol processing).
	 */
	vdp = (Ver_desc *)ofl->ofl_verdesc.head->data;
	size = strlen(vdp->vd_name) + 1;

	if (ofl->ofl_flags & FLG_OF_DYNAMIC) {
		if (st_insert(ofl->ofl_dynstrtab, vdp->vd_name) == -1)
			return (S_ERROR);
	} else {
		if (st_insert(ofl->ofl_strtab, vdp->vd_name) == -1)
			return (S_ERROR);
	}

	/*
	 * During version processing we calculated the total number of entries.
	 * Allocate and initialize the Elf_Data structure.
	 */
	size = ofl->ofl_verdefsz;

	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = (Word)SHT_SUNW_verdef;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = M_WORD_ALIGN;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWVERSION);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	ofl->ofl_osverdef = place_section(ofl, isec, M_ID_VERSION, 0);
	return ((uintptr_t)ofl->ofl_osverdef);
}

/*
 * Common function used to build both the SHT_SUNW_versym
 * section and the SHT_SUNW_syminfo section.  Each of these sections
 * provides additional symbol information.
 */
Os_desc *
make_sym_sec(Ofl_desc *ofl, const char *sectname, Word entsize,
    Word stype, int ident)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Allocate and initialize the Elf_Data structures for the symbol index
	 * array.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return ((Os_desc *)S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_align = M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return ((Os_desc *)S_ERROR);
	shdr->sh_type = (Word)stype;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_addralign = M_WORD_ALIGN;
	shdr->sh_entsize = entsize;

	if (stype == SHT_SUNW_syminfo) {
		/*
		 * The sh_info field of the SHT_*_syminfo section points
		 * to the header index of the associated .dynamic section.
		 */
		shdr->sh_flags |= SHF_INFO_LINK;
	}

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return ((Os_desc *)S_ERROR);
	isec->is_name = sectname;
	isec->is_shdr = shdr;
	isec->is_indata = data;

	return (place_section(ofl, isec, ident, 0));
}

/*
 * Build a .sunwbss section for allocation of tentative definitions.
 */
uintptr_t
make_sunwbss(Ofl_desc *ofl, size_t size, Xword align)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	data->d_align = align;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_NOBITS;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr->sh_size = (Xword)size;
	shdr->sh_addralign = align;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWBSS);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Retain this .sunwbss input section as this will be where global
	 * symbol references are added.
	 */
	ofl->ofl_issunwbss = isec;
	if (place_section(ofl, isec, 0, 0) == (Os_desc *)S_ERROR)
		return (S_ERROR);

	return (1);
}

/*
 * This routine is called when -z nopartial is in effect.
 */
uintptr_t
make_sunwdata(Ofl_desc *ofl, size_t size, Xword align)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	Os_desc		*osp;

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	data->d_size = size;
	if ((data->d_buf = libld_calloc(size, 1)) == 0)
		return (S_ERROR);
	data->d_align = (size_t)M_WORD_ALIGN;
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr->sh_size = (Xword)size;
	if (align == 0)
		shdr->sh_addralign = M_WORD_ALIGN;
	else
		shdr->sh_addralign = align;

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWDATA1);
	isec->is_shdr = shdr;
	isec->is_indata = data;

	/*
	 * Retain this .sunwdata1 input section as this will
	 * be where global
	 * symbol references are added.
	 */
	ofl->ofl_issunwdata1 = isec;
	if ((osp = place_section(ofl, isec, M_ID_DATA, 0)) ==
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
make_sunwmove(Ofl_desc *ofl, int mv_nums)
{
	Shdr		*shdr;
	Elf_Data	*data;
	Is_desc		*isec;
	size_t		size;
	Listnode	*lnp1;
	Psym_info	*psym;
	int 		cnt = 1;

	/*
	 * Generate the move input sections and output sections
	 */
	size = mv_nums * sizeof (Move);

	/*
	 * Allocate and initialize the Elf_Data structure.
	 */
	if ((data = libld_calloc(sizeof (Elf_Data), 1)) == 0)
		return (S_ERROR);
	data->d_type = ELF_T_BYTE;
	if ((data->d_buf = libld_calloc(size, 1)) == 0)
		return (S_ERROR);
	data->d_size = size;
	data->d_align = sizeof (Lword);
	data->d_version = ofl->ofl_libver;

	/*
	 * Allocate and initialize the Shdr structure.
	 */
	if ((shdr = libld_calloc(sizeof (Shdr), 1)) == 0)
		return (S_ERROR);
	shdr->sh_link = 0;
	shdr->sh_info = 0;
	shdr->sh_type = SHT_SUNW_move;
	shdr->sh_size = (Xword)size;
	shdr->sh_flags = SHF_ALLOC | SHF_WRITE;
	shdr->sh_addralign = sizeof (Lword);
	shdr->sh_entsize = sizeof (Move);

	/*
	 * Allocate and initialize the Is_desc structure.
	 */
	if ((isec = libld_calloc(1, sizeof (Is_desc))) == 0)
		return (S_ERROR);
	isec->is_name = MSG_ORIG(MSG_SCN_SUNWMOVE);
	isec->is_shdr = shdr;
	isec->is_indata = data;
	isec->is_file = 0;

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
	if ((ofl->ofl_osmove = place_section(ofl, isec, 0, 0)) ==
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
make_sections(Ofl_desc *ofl)
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
	if (dbg_mask || (ofl->ofl_flags1 & FLG_OF1_IGNPRC)) {
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
		    MSG_ORIG(MSG_SCN_SUNWVERSYM), sizeof (Versym),
		    SHT_SUNW_versym, M_ID_VERSION)) == (Os_desc*)S_ERROR)
			return (S_ERROR);
	}

	/*
	 * Create a syminfo section is necessary.
	 */
	if (ofl->ofl_flags & FLG_OF_SYMINFO) {
		if ((ofl->ofl_ossyminfo = make_sym_sec(ofl,
		    MSG_ORIG(MSG_SCN_SUNWSYMINFO), sizeof (Syminfo),
		    SHT_SUNW_syminfo, M_ID_SYMINFO)) == (Os_desc *)S_ERROR)
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
		size_t	reloc_size = 0;

		/*
		 * Create the required output relocation sections.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_segs, lnp1, sgp)) {
			Os_desc		*osp;
			Listnode	*lnp2;

			for (LIST_TRAVERSE(&(sgp->sg_osdescs), lnp2, osp)) {
				if (osp->os_szoutrels &&
				    (osp != ofl->ofl_osplt)) {
					if (make_reloc(ofl, osp) == S_ERROR)
						return (S_ERROR);
					reloc_size += reloc_size;
				}
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
		Shdr *		shdr;
		Is_desc *	isec;
		Elf_Data *	data;
		size_t		size;
		ulong_t		cnt;

		if ((flags & FLG_OF_RELOBJ) || (flags & FLG_OF_STATIC))
			isec = (Is_desc *)ofl->ofl_ossymtab->
				os_isdescs.head->data;
		else
			isec = (Is_desc *)ofl->ofl_osdynsym->
				os_isdescs.head->data;
		cnt = isec->is_shdr->sh_size / isec->is_shdr->sh_entsize;

		if (ofl->ofl_osversym) {
			isec = (Is_desc *)ofl->ofl_osversym->os_isdescs.
				head->data;
			data = isec->is_indata;
			shdr = ofl->ofl_osversym->os_shdr;
			size = cnt * shdr->sh_entsize;
			shdr->sh_size = (Xword)size;
			data->d_size = size;
		}
		if (ofl->ofl_ossyminfo) {
			isec = (Is_desc *)ofl->ofl_ossyminfo->os_isdescs.
				head->data;
			data = isec->is_indata;
			shdr = ofl->ofl_ossyminfo->os_shdr;
			size = cnt * shdr->sh_entsize;
			shdr->sh_size = (Xword)size;
			data->d_size = size;
		}
	}

	return (1);
}
