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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Processing of relocatable objects and shared objects.
 */
#include	<stdio.h>
#include	<string.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<link.h>
#include	<limits.h>
#include	<sys/stat.h>
#include	<sys/systeminfo.h>
#include	<debug.h>
#include	<msg.h>
#include	<_libld.h>


/*
 * Decide if we can link against this input file.
 */
static int
ifl_verify(Ehdr * ehdr, Ofl_desc * ofl, Rej_desc * rej)
{
	/*
	 * Check the validity of the elf header information for compatibility
	 * with this machine and our own internal elf library.
	 */
	if ((ehdr->e_machine != M_MACH) &&
	    ((ehdr->e_machine != M_MACHPLUS) &&
	    ((ehdr->e_flags & M_FLAGSPLUS) == 0))) {
		rej->rej_type = SGS_REJ_MACH;
		rej->rej_info = (uint_t)ehdr->e_machine;
		return (0);
	}
	if (ehdr->e_ident[EI_DATA] != M_DATA) {
		rej->rej_type = SGS_REJ_DATA;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_DATA];
		return (0);
	}
	if (ehdr->e_version > ofl->ofl_libver) {
		rej->rej_type = SGS_REJ_VERSION;
		rej->rej_info = (uint_t)ehdr->e_version;
		return (0);
	}
	return (1);
}


/*
 * Check sanity of file header and allocate an infile descriptor
 * for the file being processed.
 */
Ifl_desc *
ifl_setup(const char *name, Ehdr *ehdr, Elf *elf, Half flags, Ofl_desc *ofl,
    Rej_desc *rej)
{
	Ifl_desc	*ifl;
	List		*list;
	Rej_desc	_rej = { 0 };

	if (ifl_verify(ehdr, ofl, &_rej) == 0) {
		_rej.rej_name = name;
		DBG_CALL(Dbg_file_rejected(&_rej));
		if (rej->rej_type == 0) {
			*rej = _rej;
			rej->rej_name = strdup(_rej.rej_name);
		}
		return (0);
	}

	if ((ifl = libld_calloc(1, sizeof (Ifl_desc))) == 0)
		return ((Ifl_desc *)S_ERROR);
	ifl->ifl_name = name;
	ifl->ifl_ehdr = ehdr;
	ifl->ifl_elf = elf;
	ifl->ifl_flags = flags;

	/*
	 * Is this file using 'extended Section Indexes'.  If so, use the
	 * e_shnum & e_shstrndx which can be found at:
	 *
	 *	e_shnum == Shdr[0].sh_size
	 *	e_shstrndx == Shdr[0].sh_link
	 */
	if ((ehdr->e_shnum == 0) && (ehdr->e_shoff != 0)) {
		Elf_Scn	*scn;
		Shdr	*shdr0;

		if ((scn = elf_getscn(elf, 0)) == NULL) {
			eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSCN), name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return ((Ifl_desc *)S_ERROR);
		}
		if ((shdr0 = elf_getshdr(scn)) == NULL) {
			eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR), name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return ((Ifl_desc *)S_ERROR);
		}
		ifl->ifl_shnum = (Word)shdr0->sh_size;
		if (ehdr->e_shstrndx == SHN_XINDEX)
			ifl->ifl_shstrndx = shdr0->sh_link;
		else
			ifl->ifl_shstrndx = ehdr->e_shstrndx;
	} else {
		ifl->ifl_shnum = ehdr->e_shnum;
		ifl->ifl_shstrndx = ehdr->e_shstrndx;
	}

	if ((ifl->ifl_isdesc = libld_calloc(ifl->ifl_shnum,
	    sizeof (Is_desc *))) == 0)
		return ((Ifl_desc *)S_ERROR);

	/*
	 * Record this new input file on the shared object or relocatable
	 * object input file list.
	 */
	if (ifl->ifl_ehdr->e_type == ET_DYN) {
		list = &ofl->ofl_sos;
	} else {
		list = &ofl->ofl_objs;
	}

	if (list_appendc(list, ifl) == 0)
		return ((Ifl_desc *)S_ERROR);
	return (ifl);
}

/*
 * Process a generic section.  The appropriate section information is added
 * to the files input descriptor list.
 */
uintptr_t
process_section(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	Is_desc	*isp;

	/*
	 * Create a new input section descriptor.  If this is a NOBITS
	 * section elf_getdata() will still create a data buffer (the buffer
	 * will be null and the size will reflect the actual memory size).
	 */
	if ((isp = libld_calloc(sizeof (Is_desc), 1)) == 0)
		return (S_ERROR);
	isp->is_shdr = shdr;
	isp->is_file = ifl;
	isp->is_name = name;
	isp->is_scnndx = ndx;
	/* LINTED */
	isp->is_key = (Half)ident;
	if ((isp->is_indata = elf_getdata(scn, NULL)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETDATA), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	if ((shdr->sh_flags & SHF_EXCLUDE) &&
	    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)) {
		isp->is_flags |= FLG_IS_DISCARD;
	}

	/*
	 * Add the new input section to the files input section list and
	 * to the output section list (some sections like .strtab and
	 * .shstrtab are not added to the output section list).
	 *
	 * If the section has the SHF_ORDERED flag on, do the place_section()
	 * after all input sections from this file are read in.
	 */
	ifl->ifl_isdesc[ndx] = isp;
	if (ident && (shdr->sh_flags & ALL_SHF_ORDER) == 0)
		return ((uintptr_t)place_section(ofl, isp, ident, 0));

	if (ident && (shdr->sh_flags & ALL_SHF_ORDER)) {
		isp->is_flags |= FLG_IS_ORDERED;
		isp->is_ident = ident;
		if ((ndx != 0) && (ndx == shdr->sh_link) &&
		    (shdr->sh_flags & SHF_ORDERED))
			return ((uintptr_t)place_section(ofl, isp, ident, 0));
	}

	return (1);
}

/*
 * Determine the software capabilities of the object being built from the
 * capabilities of the input relocatable objects.   One software capability
 * is presently recognized, and represented with the following (sys/elf.h):
 *
 *   SF1_SUNW_FPKNWN	use/non-use of frame pointer is known, and
 *   SF1_SUNW_FPUSED    the frame pointer is in use.
 *
 * The resolution of the present fame pointer state, and the capabilities
 * provided by a new input relocatable object are:
 *
 *                              new input relocatable object
 *
 *      present      |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |    <unknown>
 *       state       |  SF1_SUNW_FPUSED  |                   |
 *  ---------------------------------------------------------------------------
 *  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN
 *  SF1_SUNW_FPUSED  |  SF1_SUNW_FPUSED  |                   |  SF1_SUNW_FPUSED
 *  ---------------------------------------------------------------------------
 *  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN
 *                   |                   |                   |
 *  ---------------------------------------------------------------------------
 *     <unknown>     |  SF1_SUNW_FPKNWN  |  SF1_SUNW_FPKNWN  |    <unknown>
 *                   |  SF1_SUNW_FPUSED  |                   |
 */
static void
sf1_cap(Ofl_desc *ofl, Xword val, Ifl_desc *ifl, const char *name)
{
	Xword	badval;

	/*
	 * If a mapfile has established definitions to override any input
	 * capabilities, ignore any new input capabilities.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_OVSFCAP) {
		Dbg_cap_sec_entry(DBG_CAP_IGNORE, CA_SUNW_SF_1, val, M_MACH);
		return;
	}

	/*
	 * If this object doesn't specify any capabilities, ignore it, and
	 * leave the state as is.
	 */
	if (val == 0)
		return;

	/*
	 * Make sure we only accept known software capabilities.  Note, that
	 * an F1_SUNW_FPUSED by itself is viewed as bad practice.
	 */
	if ((badval = (val & ~SF1_SUNW_MASK)) != 0) {
		eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, name, EC_XWORD(badval));
		val &= SF1_SUNW_MASK;
	}
	if (val == SF1_SUNW_FPUSED) {
		eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, name, EC_XWORD(val));
		return;
	}

	Dbg_cap_sec_entry(DBG_CAP_OLD, CA_SUNW_SF_1, ofl->ofl_sfcap_1, M_MACH);
	Dbg_cap_sec_entry(DBG_CAP_NEW, CA_SUNW_SF_1, val, M_MACH);

	/*
	 * Determine the resolution of the present frame pointer and the
	 * new input relocatable objects frame pointer.
	 */
	if ((ofl->ofl_sfcap_1 & (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)) ==
	    (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)) {
		/*
		 * If the new relocatable object isn't using a frame pointer,
		 * reduce the present state to unused.
		 */
		if ((val & (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)) !=
		    (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED))
			ofl->ofl_sfcap_1 &= ~SF1_SUNW_FPUSED;

	} else if ((ofl->ofl_sfcap_1 & SF1_SUNW_FPKNWN) == 0) {
		/*
		 * If the present state is unknown, take the new relocatable
		 * object frame pointer usage.
		 */
		ofl->ofl_sfcap_1 = val;
	}

	Dbg_cap_sec_entry(DBG_CAP_RESOLVED, CA_SUNW_SF_1, ofl->ofl_sfcap_1,
	    M_MACH);
}

/*
 * Determine the hardware capabilities of the object being built from the
 * capabilities of the input relocatable objects.  There's really little to
 * do here, other than to offer diagnostics, hardware capabilities are simply
 * additive.
 */
static void
hw1_cap(Ofl_desc *ofl, Xword val)
{
	/*
	 * If a mapfile has established definitions to override any input
	 * capabilities, ignore any new input capabilities.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_OVHWCAP) {
		Dbg_cap_sec_entry(DBG_CAP_IGNORE, CA_SUNW_HW_1, val, M_MACH);
		return;
	}

	/*
	 * If this object doesn't specify any capabilities, ignore it, and
	 * leave the state as is.
	 */
	if (val == 0)
		return;

	Dbg_cap_sec_entry(DBG_CAP_OLD, CA_SUNW_HW_1, ofl->ofl_hwcap_1, M_MACH);
	Dbg_cap_sec_entry(DBG_CAP_NEW, CA_SUNW_HW_1, val, M_MACH);

	ofl->ofl_hwcap_1 |= val;

	Dbg_cap_sec_entry(DBG_CAP_RESOLVED, CA_SUNW_HW_1, ofl->ofl_hwcap_1,
	    M_MACH);
}

/*
 * Process a hardware/software capabilities section.  Traverse the section
 * updating the global capabilities variables as necessary.
 */
static void
process_cap(const char *name, Ifl_desc *ifl, Is_desc *cisp, Ofl_desc *ofl)
{
	Cap *	cdata;

	Dbg_cap_sec_title(ofl->ofl_name);

	for (cdata = (Cap *)cisp->is_indata->d_buf;
	    cdata->c_tag != CA_SUNW_NULL; cdata++) {
		switch (cdata->c_tag) {
			case CA_SUNW_HW_1:
				hw1_cap(ofl, cdata->c_un.c_val);
				break;
			case CA_SUNW_SF_1:
				sf1_cap(ofl, cdata->c_un.c_val, ifl, name);
				break;
			default:
				eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_UNKCAP),
				    ifl->ifl_name, name, cdata->c_tag);
		}
	}
}

/*
 * Simply process the section so that we have pointers to the data for use
 * in later routines, however don't add the section to the output section
 * list as we will be creating our own replacement sections later (ie.
 * symtab and relocation).
 */
uintptr_t
/* ARGSUSED5 */
process_input(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
	Word ndx, int ident, Ofl_desc *ofl)
{
	return (process_section(name, ifl, shdr, scn, ndx, M_ID_NULL, ofl));
}

/*
 * Keep a running count of relocation entries from input relocatable objects for
 * sizing relocation buckets later.  If we're building an executable, save any
 * relocations from shared objects to determine if any copy relocation symbol
 * has a displacement relocation against it.
 */
uintptr_t
/* ARGSUSED5 */
process_reloc(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
	Word ndx, int ident, Ofl_desc *ofl)
{
	if (process_section(name, ifl,
	    shdr, scn, ndx, M_ID_NULL, ofl) == S_ERROR)
		return (S_ERROR);

	if (ifl->ifl_ehdr->e_type == ET_REL) {
		if (shdr->sh_entsize && (shdr->sh_entsize <= shdr->sh_size))
			/* LINTED */
			ofl->ofl_relocincnt +=
			    (Word)(shdr->sh_size / shdr->sh_entsize);
	} else if (ofl->ofl_flags & FLG_OF_EXEC) {
		if (list_appendc(&ifl->ifl_relsect, ifl->ifl_isdesc[ndx]) == 0)
			return (S_ERROR);
	}
	return (1);
}


/*
 * Process a string table section.  A valid section contains an initial and
 * final null byte.
 */
uintptr_t
process_strtab(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
	Word ndx, int ident, Ofl_desc *ofl)
{
	char		*data;
	size_t		size;
	Is_desc		*isp;
	uintptr_t	error;

	/*
	 * Never include .stab.excl sections in any output file.
	 * If the -s flag has been specified strip any .stab sections.
	 */
	if (((ofl->ofl_flags & FLG_OF_STRIP) && ident &&
	    (strncmp(name, MSG_ORIG(MSG_SCN_STAB), MSG_SCN_STAB_SIZE) == 0)) ||
	    (strcmp(name, MSG_ORIG(MSG_SCN_STABEXCL)) == 0) && ident)
		return (1);

	/*
	 * If we got here to process a .shstrtab or .dynstr table, `ident' will
	 * be null.  Otherwise make sure we don't have a .strtab section as this
	 * should not be added to the output section list either.
	 */
	if ((ident != M_ID_NULL) &&
	    (strcmp(name, MSG_ORIG(MSG_SCN_STRTAB)) == 0))
		ident = M_ID_NULL;

	error = process_section(name, ifl, shdr, scn, ndx, ident, ofl);
	if ((error == 0) || (error == S_ERROR))
		return (error);

	/*
	 * String tables should start and end with a NULL byte.  Note, it has
	 * been known for the assembler to create empty string tables, so check
	 * the size before attempting to verify the data itself.
	 */
	isp = ifl->ifl_isdesc[ndx];
	size = isp->is_indata->d_size;
	if (size) {
		data = isp->is_indata->d_buf;
		if (data[0] != '\0' || data[size - 1] != '\0')
			eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_MALSTR),
			    ifl->ifl_name, name);
	} else
		isp->is_indata->d_buf = (void *)MSG_ORIG(MSG_STR_EMPTY);

	ifl->ifl_flags |= FLG_IF_HSTRTAB;
	return (1);
}

/*
 * Invalid sections produce a warning and are skipped.
 */
uintptr_t
/* ARGSUSED3 */
invalid_section(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_INVALSEC), ifl->ifl_name, name,
		conv_sectyp_str(ofl->ofl_e_machine, (unsigned)shdr->sh_type));
	return (1);
}

/*
 * Process a progbits section.
 */
uintptr_t
process_progbits(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	int stab_index = 0;

	/*
	 * Never include .stab.excl sections in any output file.
	 * If the -s flag has been specified strip any .stab sections.
	 */
	if (ident && (strncmp(name, MSG_ORIG(MSG_SCN_STAB),
	    MSG_SCN_STAB_SIZE) == 0)) {
		if ((ofl->ofl_flags & FLG_OF_STRIP) ||
		    (strcmp((name + MSG_SCN_STAB_SIZE),
			MSG_ORIG(MSG_SCN_EXCL)) == 0))
			return (1);

		if (strcmp((name + MSG_SCN_STAB_SIZE),
		    MSG_ORIG(MSG_SCN_INDEX)) == 0)
			stab_index = 1;
	}

	if ((ofl->ofl_flags & FLG_OF_STRIP) && ident) {
		if ((strncmp(name, MSG_ORIG(MSG_SCN_DEBUG),
		    MSG_SCN_DEBUG_SIZE) == 0) ||
		    (strcmp(name, MSG_ORIG(MSG_SCN_LINE)) == 0))
			return (1);
	}

	/*
	 * Update the ident to reflect the type of section we've got.
	 *
	 * If there is any .plt or .got section to generate we'll be creating
	 * our own version, so don't allow any input sections of these types to
	 * be added to the output section list (why a relocatable object would
	 * have a .plt or .got is a mystery, but stranger things have occurred).
	 */
	if (ident) {
		if (shdr->sh_flags & SHF_TLS)
			ident = M_ID_TLS;
		else if ((shdr->sh_flags & ~ALL_SHF_IGNORE) ==
		    (SHF_ALLOC | SHF_EXECINSTR))
			ident = M_ID_TEXT;
		else if (shdr->sh_flags & SHF_ALLOC) {
			if ((strcmp(name, MSG_ORIG(MSG_SCN_PLT)) == 0) ||
			    (strcmp(name, MSG_ORIG(MSG_SCN_GOT)) == 0))
				ident = M_ID_NULL;
			else if (stab_index) {
				/*
				 * This is a work-around for x86 compilers that
				 * have set SHF_ALLOC for the .stab.index
				 * section.
				 *
				 * Because of this, make sure that the
				 * .stab.index does not end up as the last
				 * section in the text segment.  Older linkers
				 * can produce segmentation violations when they
				 * strip (ld -s) against a shared object whose
				 * last section in the text segment is a .stab.
				 */
				ident = M_ID_INTERP;
			} else
				ident = M_ID_DATA;
		} else
			ident = M_ID_NOTE;
	}
	return (process_section(name, ifl, shdr, scn, ndx, ident, ofl));
}

/*
 * Handles the SHT_SUNW_{DEBUG,DEBUGSTR) sections.
 */
uintptr_t
process_debug(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	/*
	 * Debug information is discarded when the 'ld -s' flag is invoked.
	 */
	if (ofl->ofl_flags & FLG_OF_STRIP) {
		return (1);
	}
	return (process_progbits(name, ifl, shdr, scn, ndx, ident, ofl));
}


/*
 * Process a nobits section.
 */
uintptr_t
process_nobits(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	if (ident) {
		if (shdr->sh_flags & SHF_TLS)
			ident = M_ID_TLSBSS;
		else
			ident = M_ID_BSS;
	}
	return (process_section(name, ifl, shdr, scn, ndx, ident, ofl));
}

/*
 * Process a SHT_*_ARRAY section.
 */
uintptr_t
process_array(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	Os_desc	*osp;
	Is_desc	*isp;

	if (ident)
		ident = M_ID_ARRAY;

	if (process_section(name, ifl, shdr, scn, ndx, ident, ofl) == S_ERROR)
		return (S_ERROR);

	if (((isp = ifl->ifl_isdesc[ndx]) == 0) ||
	    ((osp = isp->is_osdesc) == 0))
		return (0);

	if ((shdr->sh_type == SHT_FINI_ARRAY) &&
	    (ofl->ofl_osfiniarray == 0))
		ofl->ofl_osfiniarray = osp;
	else if ((shdr->sh_type == SHT_INIT_ARRAY) &&
	    (ofl->ofl_osinitarray == 0))
		ofl->ofl_osinitarray = osp;
	else if ((shdr->sh_type == SHT_PREINIT_ARRAY) &&
	    (ofl->ofl_ospreinitarray == 0))
		ofl->ofl_ospreinitarray = osp;

	return (1);
}

/*
 * Process a SHT_SYMTAB_SHNDX section.
 */
uintptr_t
process_sym_shndx(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	if (process_input(name, ifl, shdr, scn, ndx, ident, ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Have we already seen the related SYMTAB - if so verify it now.
	 */
	if (shdr->sh_link < ndx) {
		Is_desc	*isp = ifl->ifl_isdesc[shdr->sh_link];

		if ((isp == 0) || ((isp->is_shdr->sh_type != SHT_SYMTAB) &&
		    (isp->is_shdr->sh_type != SHT_DYNSYM))) {
			eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVSHLINK),
				ifl->ifl_name, name, EC_XWORD(shdr->sh_link));
			return (S_ERROR);
		}
		isp->is_symshndx = ifl->ifl_isdesc[ndx];
	}
	return (1);
}

/*
 * Final processing for SHT_SYMTAB_SHNDX section.
 */
uintptr_t
/* ARGSUSED2 */
sym_shndx_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	if (isc->is_shdr->sh_link > isc->is_scnndx) {
		Is_desc	*isp = ifl->ifl_isdesc[isc->is_shdr->sh_link];

		if ((isp == 0) || ((isp->is_shdr->sh_type != SHT_SYMTAB) &&
		    (isp->is_shdr->sh_type != SHT_DYNSYM))) {
			eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVSHLINK),
				isc->is_file->ifl_name, isc->is_name,
				EC_XWORD(isc->is_shdr->sh_link));
			return (S_ERROR);
		}
		isp->is_symshndx = isc;
	}
	return (1);
}

/*
 * Process .dynamic section from a relocatable object.
 *
 * Note: That the .dynamic section is only considered interesting when
 *	 dlopen()ing a relocatable object (thus FLG_OF1_RELDYN can only get
 *	 set when libld is called from ld.so.1).
 */
/*ARGSUSED*/
uintptr_t
process_rel_dynamic(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	Dyn		*dyn;
	Elf_Scn		*strscn;
	Elf_Data	*dp;
	char		*str;

	/*
	 * Process .dynamic sections from relocatable objects ?
	 */
	if ((ofl->ofl_flags1 & FLG_OF1_RELDYN) == 0)
		return (1);

	/*
	 * Find the string section associated with the .dynamic section.
	 */
	if ((strscn = elf_getscn(ifl->ifl_elf, shdr->sh_link)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSCN), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	dp = elf_getdata(strscn, NULL);
	str = (char *)dp->d_buf;

	/*
	 * And get the .dynamic data
	 */
	dp = elf_getdata(scn, NULL);

	for (dyn = (Dyn *)dp->d_buf; dyn->d_tag != DT_NULL; dyn++) {
		Ifl_desc *	_ifl;

		switch (dyn->d_tag) {
		case DT_NEEDED:
		case DT_USED:
			if ((_ifl = libld_calloc(1, sizeof (Ifl_desc))) == 0)
				return (S_ERROR);
			_ifl->ifl_name = MSG_ORIG(MSG_STR_DYNAMIC);
			_ifl->ifl_soname = str + (size_t)dyn->d_un.d_val;
			_ifl->ifl_flags = FLG_IF_NEEDSTR;
			if (list_appendc(&ofl->ofl_sos, _ifl) == 0)
				return (S_ERROR);
			break;
		case DT_RPATH:
		case DT_RUNPATH:
			if ((ofl->ofl_rpath = add_string(ofl->ofl_rpath,
			    (str + (size_t)dyn->d_un.d_val))) ==
			    (const char *)S_ERROR)
				return (S_ERROR);
			break;
		}
	}
	return (1);
}

/*
 * Expand implicit references.  Dependencies can be specified in terms of the
 * $ORIGIN, $PLATFORM, $OSREL and $OSNAME tokens, either from their needed name,
 * or via a runpath.  In addition runpaths may also specify the $ISALIST token.
 *
 * Probably the most common reference to explict dependencies (via -L) will be
 * sufficient to find any associated implicit dependencies, but just in case we
 * expand any occurrence of these known tokens here.
 *
 * Note, if any errors occur we simply return the original name.
 *
 * This code is remarkably similar to expand() in rtld/common/paths.c.
 */
static char		*platform = 0;
static size_t		platform_sz = 0;
static Isa_desc		*isa = 0;
static Uts_desc		*uts = 0;

static char *
expand(const char *parent, const char *name, char **next)
{
	char		_name[PATH_MAX], *nptr, *_next;
	const char	*optr;
	size_t		nrem = PATH_MAX - 1;
	int		expanded = 0, _expanded, isaflag = 0;

	optr = name;
	nptr = _name;

	while (*optr) {
		if (nrem == 0)
			return ((char *)name);

		if (*optr != '$') {
			*nptr++ = *optr++, nrem--;
			continue;
		}

		_expanded = 0;

		if (strncmp(optr, MSG_ORIG(MSG_STR_ORIGIN),
		    MSG_STR_ORIGIN_SIZE) == 0) {
			char *eptr;

			/*
			 * For $ORIGIN, expansion is really just a concatenation
			 * of the parents directory name.  For example, an
			 * explict dependency foo/bar/lib1.so with a dependency
			 * on $ORIGIN/lib2.so would be expanded to
			 * foo/bar/lib2.so.
			 */
			if ((eptr = strrchr(parent, '/')) == 0) {
				*nptr++ = '.';
				nrem--;
			} else {
				size_t	len = eptr - parent;

				if (len >= nrem)
					return ((char *)name);

				(void) strncpy(nptr, parent, len);
				nptr = nptr + len;
				nrem -= len;
			}
			optr += MSG_STR_ORIGIN_SIZE;
			expanded = _expanded = 1;

		} else if (strncmp(optr, MSG_ORIG(MSG_STR_PLATFORM),
		    MSG_STR_PLATFORM_SIZE) == 0) {
			/*
			 * Establish the platform from sysconf - like uname -i.
			 */
			if ((platform == 0) && (platform_sz == 0)) {
				char	info[SYS_NMLN];
				long	size;

				size = sysinfo(SI_PLATFORM, info, SYS_NMLN);
				if ((size != -1) &&
				    (platform = libld_malloc((size_t)size))) {
					(void) strcpy(platform, info);
					platform_sz = (size_t)size - 1;
				} else
					platform_sz = 1;
			}
			if (platform != 0) {
				if (platform_sz >= nrem)
					return ((char *)name);

				(void) strncpy(nptr, platform, platform_sz);
				nptr = nptr + platform_sz;
				nrem -= platform_sz;

				optr += MSG_STR_PLATFORM_SIZE;
				expanded = _expanded = 1;
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_STR_OSNAME),
		    MSG_STR_OSNAME_SIZE) == 0) {
			/*
			 * Establish the os name - like uname -s.
			 */
			if (uts == 0)
				uts = conv_uts();

			if (uts && uts->uts_osnamesz) {
				if (uts->uts_osnamesz >= nrem)
					return ((char *)name);

				(void) strncpy(nptr, uts->uts_osname,
				    uts->uts_osnamesz);
				nptr = nptr + uts->uts_osnamesz;
				nrem -= uts->uts_osnamesz;

				optr += MSG_STR_OSNAME_SIZE;
				expanded = _expanded = 1;
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_STR_OSREL),
		    MSG_STR_OSREL_SIZE) == 0) {
			/*
			 * Establish the os release - like uname -r.
			 */
			if (uts == 0)
				uts = conv_uts();

			if (uts && uts->uts_osrelsz) {
				if (uts->uts_osrelsz >= nrem)
					return ((char *)name);

				(void) strncpy(nptr, uts->uts_osrel,
				    uts->uts_osrelsz);
				nptr = nptr + uts->uts_osrelsz;
				nrem -= uts->uts_osrelsz;

				optr += MSG_STR_OSREL_SIZE;
				expanded = _expanded = 1;
			}

		} else if ((strncmp(optr, MSG_ORIG(MSG_STR_ISALIST),
		    MSG_STR_ISALIST_SIZE) == 0) && next && (isaflag++ == 0)) {
			/*
			 * Establish instruction sets from sysconf.  Note that
			 * this is only meaningful from runpaths.
			 */
			if (isa == 0)
				isa = conv_isalist();

			if (isa && isa->isa_listsz &&
			    (nrem > isa->isa_opt->isa_namesz)) {
				size_t		mlen, tlen, hlen = optr - name;
				size_t		no;
				char		*lptr;
				Isa_opt		*opt = isa->isa_opt;

				(void) strncpy(nptr, opt->isa_name,
				    opt->isa_namesz);
				nptr = nptr + opt->isa_namesz;
				nrem -= opt->isa_namesz;

				optr += MSG_STR_ISALIST_SIZE;
				expanded = _expanded = 1;

				tlen = strlen(optr);

				/*
				 * As ISALIST expands to a number of elements,
				 * establish a new list to return to the caller.
				 * This will contain the present path being
				 * processed redefined for each isalist option,
				 * plus the original remaining list entries.
				 */
				mlen = ((hlen + tlen) * (isa->isa_optno - 1)) +
				    isa->isa_listsz - opt->isa_namesz;
				if (*next)
				    mlen += strlen(*next);
				if ((_next = lptr = libld_malloc(mlen)) == 0)
					return (0);

				for (no = 1, opt++; no < isa->isa_optno;
				    no++, opt++) {
					(void) strncpy(lptr, name, hlen);
					lptr = lptr + hlen;
					(void) strncpy(lptr, opt->isa_name,
					    opt->isa_namesz);
					lptr = lptr + opt->isa_namesz;
					(void) strncpy(lptr, optr, tlen);
					lptr = lptr + tlen;
					*lptr++ = ':';
				}
				if (*next)
					(void) strcpy(lptr, *next);
				else
					*--lptr = '\0';
			}
		}

		/*
		 * If no expansion occurred skip the $ and continue.
		 */
		if (_expanded == 0)
			*nptr++ = *optr++, nrem--;
	}

	/*
	 * If any ISALIST processing has occurred not only do we return the
	 * expanded node we're presently working on, but we must also update the
	 * remaining list so that it is effectively prepended with this node
	 * expanded to all remaining isalist options.  Note that we can only
	 * handle one ISALIST per node.  For more than one ISALIST to be
	 * processed we'd need a better algorithm than above to replace the
	 * newly generated list.  Whether we want to encourage the number of
	 * pathname permutations this would provide is another question. So, for
	 * now if more than one ISALIST is encountered we return the original
	 * node untouched.
	 */
	if (isaflag) {
		if (isaflag == 1)
			*next = _next;
		else
			return ((char *)name);
	}

	*nptr = '\0';

	if (expanded) {
		if ((nptr = libld_malloc(strlen(_name) + 1)) == 0)
			return ((char *)name);
		(void) strcpy(nptr, _name);
		return (nptr);
	}
	return ((char *)name);
}

/*
 * Process a dynamic section.  If we are processing an explicit shared object
 * then we need to determine if it has a recorded SONAME, if so, this name will
 * be recorded in the output file being generated as the NEEDED entry rather
 * than the shared objects filename itself.
 * If the mode of the link-edit indicates that no undefined symbols should
 * remain, then we also need to build up a list of any additional shared object
 * dependencies this object may have.  In this case save any NEEDED entries
 * together with any associated run-path specifications.  This information is
 * recorded on the `ofl_soneed' list and will be analyzed after all explicit
 * file processing has been completed (refer finish_libs()).
 */
uintptr_t
process_dynamic(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	Dyn		*data, *dyn;
	char		*str, *rpath = NULL;
	const char	*soname, *needed;
	Sdf_desc	*sdf;
	Listnode	*lnp;

	data = (Dyn *)isc->is_indata->d_buf;
	str = (char *)ifl->ifl_isdesc[isc->is_shdr->sh_link]->is_indata->d_buf;

	/*
	 * First loop through the dynamic section looking for a run path.
	 */
	if (ofl->ofl_flags & (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)) {
		for (dyn = data; dyn->d_tag != DT_NULL; dyn++) {
			if ((dyn->d_tag != DT_RPATH) &&
			    (dyn->d_tag != DT_RUNPATH))
				continue;
			if ((rpath = str + (size_t)dyn->d_un.d_val) == NULL)
				continue;
			break;
		}
	}

	/*
	 * Now look for any needed dependencies (which may use the rpath)
	 * or a new SONAME.
	 */
	for (dyn = data; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_SONAME) {
			if ((soname = str + (size_t)dyn->d_un.d_val) == NULL)
				continue;

			/*
			 * Update the input file structure with this new name.
			 */
			ifl->ifl_soname = soname;

		} else if ((dyn->d_tag == DT_NEEDED) ||
		    (dyn->d_tag == DT_USED)) {
			if (!(ofl->ofl_flags &
			    (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)))
				continue;
			if ((needed = str + (size_t)dyn->d_un.d_val) == NULL)
				continue;

			/*
			 * Determine if this needed entry is already recorded on
			 * the shared object needed list, if not create a new
			 * definition for later processing (see finish_libs()).
			 */
			needed = expand(ifl->ifl_name, needed, (char **)0);

			if ((sdf = sdf_find(needed, &ofl->ofl_soneed)) == 0) {
				if ((sdf = sdf_add(needed,
				    &ofl->ofl_soneed)) == (Sdf_desc *)S_ERROR)
					return (S_ERROR);
				sdf->sdf_rfile = ifl->ifl_name;
			}

			/*
			 * Record the runpath (Note that we take the first
			 * runpath which is exactly what ld.so.1 would do during
			 * its dependency processing).
			 */
			if (rpath && (sdf->sdf_rpath == 0))
				sdf->sdf_rpath = rpath;

		} else if (dyn->d_tag == DT_FLAGS_1) {
			if (dyn->d_un.d_val & (DF_1_INITFIRST | DF_1_INTERPOSE))
				ifl->ifl_flags &= ~FLG_IF_LAZYLD;
			if (dyn->d_un.d_val & DF_1_DISPRELPND)
				ifl->ifl_flags |= FLG_IF_DISPPEND;
			if (dyn->d_un.d_val & DF_1_DISPRELDNE)
				ifl->ifl_flags |= FLG_IF_DISPDONE;
			if (dyn->d_un.d_val & DF_1_NODIRECT)
				ifl->ifl_flags |= FLG_IF_NODIRECT;

		} else if ((dyn->d_tag == DT_AUDIT) &&
		    (ifl->ifl_flags & FLG_IF_NEEDED)) {
			/*
			 * Record audit string as DT_DEPAUDIT.
			 */
			if ((ofl->ofl_depaudit = add_string(ofl->ofl_depaudit,
			    (str + (size_t)dyn->d_un.d_val))) ==
			    (const char *)S_ERROR)
				return (S_ERROR);

		} else if (dyn->d_tag == DT_SUNW_RTLDINF) {
			/*
			 * If a library has the SUNW_RTLDINF .dynamic entry
			 * then we must not permit lazyloading of this library.
			 * This is because critical startup information (TLS
			 * routines) are provided as part of these interfaces
			 * and we must have them as part of process startup.
			 */
			ifl->ifl_flags &= ~FLG_IF_LAZYLD;
		}
	}

	/*
	 * Perform some SONAME sanity checks.
	 */
	if (ifl->ifl_flags & FLG_IF_NEEDED) {
		Ifl_desc *	sifl;

		/*
		 * Determine if anyone else will cause the same SONAME to be
		 * used (this is either caused by two different files having the
		 * same SONAME, or by one file SONAME actually matching another
		 * file basename (if no SONAME is specified within a shared
		 * library its basename will be used)). Probably rare, but some
		 * idiot will do it.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_sos, lnp, sifl)) {
			if ((strcmp(ifl->ifl_soname, sifl->ifl_soname) == 0) &&
			    (ifl != sifl)) {
				const char	*hint, *iflb, *siflb;

				/*
				 * Determine the basename of each file. Perhaps
				 * there are multiple copies of the same file
				 * being brought in using different -L search
				 * paths, and if so give an extra hint in the
				 * error message.
				 */
				iflb = strrchr(ifl->ifl_name, '/');
				if (iflb == NULL)
					iflb = ifl->ifl_name;
				else
					iflb++;

				siflb = strrchr(sifl->ifl_name, '/');
				if (siflb == NULL)
					siflb = sifl->ifl_name;
				else
					siflb++;

				if (strcmp(iflb, siflb) == 0)
					hint = MSG_INTL(MSG_REC_CNFLTHINT);
				else
					hint = MSG_ORIG(MSG_STR_EMPTY);

				eprintf(ERR_FATAL, MSG_INTL(MSG_REC_OBJCNFLT),
				    sifl->ifl_name, ifl->ifl_name,
				    sifl->ifl_soname, hint);
				ofl->ofl_flags |= FLG_OF_FATAL;
				return (0);
			}
		}

		/*
		 * If the SONAME is the same as the name the user wishes to
		 * record when building a dynamic library (refer -h option),
		 * we also have a name clash.
		 */
		if (ofl->ofl_soname &&
		    (strcmp(ofl->ofl_soname, ifl->ifl_soname) == 0)) {
			eprintf(ERR_FATAL, MSG_INTL(MSG_REC_OPTCNFLT),
			    ifl->ifl_name, ifl->ifl_soname);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
	}
	return (1);
}


/*
 * Process a relocation entry. At this point all input sections from this
 * input file have been assigned an input section descriptor which is saved
 * in the `ifl_isdesc' array.
 */
uintptr_t
rel_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	Word 	rndx;
	Is_desc	*risc;
	Os_desc	*osp;
	Shdr	*shdr = isc->is_shdr;

	/*
	 * Make sure this is a valid relocation we can handle.
	 */
	if (shdr->sh_type != M_REL_SHT_TYPE) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVALSEC), ifl->ifl_name,
		    isc->is_name, conv_sectyp_str(ofl->ofl_e_machine,
		    (unsigned)shdr->sh_type));
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	/*
	 * From the relocation section header information determine which
	 * section needs the actual relocation.  Determine which output section
	 * this input section has been assigned to and add to its relocation
	 * list.  Note that the relocation section may be null if it is not
	 * required (ie. .debug, .stabs, etc).
	 */
	rndx = shdr->sh_info;
	if (rndx >= ifl->ifl_shnum) {
		/*
		 * Broken input file.
		 */
		eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
			ifl->ifl_name, isc->is_name, EC_XWORD(rndx));
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	if (rndx == 0) {
		if (list_appendc(&ofl->ofl_extrarels, isc) == 0)
			return (S_ERROR);
	} else if ((risc = ifl->ifl_isdesc[rndx]) != 0) {
		/*
		 * Discard relocations if they are against a section
		 * which has been discarded.
		 */
		if (risc->is_flags & FLG_IS_DISCARD)
			return (1);
		if ((osp = risc->is_osdesc) == 0) {
			if (risc->is_shdr->sh_type == SHT_SUNW_move) {
				/*
				 * This section is processed later
				 * in sunwmove_preprocess() and
				 * reloc_init().
				 */
				if (list_appendc(&ofl->ofl_mvrelisdescs,
				    isc) == 0)
					return (S_ERROR);
				return (1);
			}
			eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_INVRELOC1),
				ifl->ifl_name, isc->is_name, risc->is_name);
			return (0);
		}
		if (list_appendc(&osp->os_relisdescs, isc) == 0)
			return (S_ERROR);
	}
	return (1);
}

/*
 * SHF_EXCLUDE flags is set for this section.
 */
static uintptr_t
process_exclude(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, Ofl_desc *ofl)
{
	/*
	 * Sections SHT_SYMTAB and SHT_DYNDYM, even if SHF_EXCLUDE is on, might
	 * be needed for ld processing.  These sections need to be in the
	 * internal table.  Later it will be determined whether they can be
	 * eliminated or not.
	 */
	if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM)
		return (0);

	/*
	 * Other checks
	 */
	if (shdr->sh_flags & SHF_ALLOC) {
		/*
		 * A conflict, issue an warning message, and ignore the section.
		 */
		eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_EXCLUDE),
		    ifl->ifl_name, name);
		return (0);
	}

	/*
	 * This sections is not going to the output file.
	 */
	return (process_section(name, ifl, shdr, scn, ndx, 0, ofl));
}

/*
 * Section processing state table.  `Initial' describes the required initial
 * procedure to be called (if any), `Final' describes the final processing
 * procedure (ie. things that can only be done when all required sections
 * have been collected).
 */
static uintptr_t (*Initial[SHT_NUM][2])() = {

/*			ET_REL			ET_DYN			*/

/* SHT_NULL	*/	invalid_section,	invalid_section,
/* SHT_PROGBITS	*/	process_progbits,	process_progbits,
/* SHT_SYMTAB	*/	process_input,		process_input,
/* SHT_STRTAB	*/	process_strtab,		process_strtab,
/* SHT_RELA	*/	process_reloc,		process_reloc,
/* SHT_HASH	*/	invalid_section,	NULL,
/* SHT_DYNAMIC	*/	process_rel_dynamic,	process_section,
/* SHT_NOTE	*/	process_section,	NULL,
/* SHT_NOBITS	*/	process_nobits,		process_nobits,
/* SHT_REL	*/	process_reloc,		process_reloc,
/* SHT_SHLIB	*/	process_section,	invalid_section,
/* SHT_DYNSYM	*/	invalid_section,	process_input,
/* SHT_UNKNOWN12 */	process_progbits,	process_progbits,
/* SHT_UNKNOWN13 */	process_progbits,	process_progbits,
/* SHT_INIT_ARRAY */	process_array,		NULL,
/* SHT_FINI_ARRAY */	process_array,		NULL,
/* SHT_PREINIT_ARRAY */	process_array,		NULL,
/* SHT_GROUP */		process_section,	invalid_section,
/* SHT_SYMTAB_SHNDX */	process_sym_shndx,	NULL
};

static uintptr_t (*Final[SHT_NUM][2])() = {

/* SHT_NULL	*/	NULL,			NULL,
/* SHT_PROGBITS	*/	NULL,			NULL,
/* SHT_SYMTAB	*/	sym_process,		sym_process,
/* SHT_STRTAB	*/	NULL,			NULL,
/* SHT_RELA	*/	rel_process,		NULL,
/* SHT_HASH	*/	NULL,			NULL,
/* SHT_DYNAMIC	*/	NULL,			process_dynamic,
/* SHT_NOTE	*/	NULL,			NULL,
/* SHT_NOBITS	*/	NULL,			NULL,
/* SHT_REL	*/	rel_process,		NULL,
/* SHT_SHLIB	*/	NULL,			NULL,
/* SHT_DYNSYM	*/	NULL,			sym_process,
/* SHT_UNKNOWN12 */	NULL,			NULL,
/* SHT_UNKNOWN13 */	NULL,			NULL,
/* SHT_INIT_ARRAY */	NULL,			NULL,
/* SHT_FINI_ARRAY */	NULL,			NULL,
/* SHT_PREINIT_ARRAY */	NULL,			NULL,
/* SHT_GROUP */		NULL,			NULL,
/* SHT_SYMTAB_SHNDX */	sym_shndx_process,	NULL
};

#define	MAXNDXSIZE	10

/*
 * Process an elf file.  Each section is compared against the section state
 * table to determine whether it should be processed (saved), ignored, or
 * is invalid for the type of input file being processed.
 */
uintptr_t
process_elf(Ifl_desc *ifl, Elf *elf, Ofl_desc *ofl)
{
	Elf_Scn		*scn;
	Shdr		*shdr;
	Word		ndx, sndx;
	char		*str, *name, _name[MAXNDXSIZE];
	Word		row, column;
	int		ident;
	uintptr_t	error;
	Is_desc		*vdfisp, *vndisp, *vsyisp, *sifisp, * capisp;
	Sdf_desc	*sdf;
	Word		ordered_shndx = 0; /* index to first ordered section */
	Word		ordered_cnt = 0;

	/*
	 * First process the .shstrtab section so that later sections can
	 * reference their name.
	 */
	lds_file(ifl->ifl_name, elf_kind(elf), ifl->ifl_flags, elf);

	sndx = ifl->ifl_shstrndx;
	if ((scn = elf_getscn(elf, (size_t)sndx)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSCN), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	if ((shdr = elf_getshdr(scn)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	if ((name = elf_strptr(elf, (size_t)sndx, (size_t)shdr->sh_name)) ==
	    NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_STRPTR), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	if (lds_input_section(name, &shdr, sndx, ifl->ifl_name,
	    scn, elf, ofl) == S_ERROR)
		return (S_ERROR);

	/*
	 * Reset the name since the shdr->sh_name could have been changed as
	 * part of lds_input_section().  If there is no name, fabricate one
	 * using the section index.
	 */
	if (shdr->sh_name == 0) {
		(void) snprintf(_name, MAXNDXSIZE, MSG_ORIG(MSG_FMT_INDEX),
		    EC_XWORD(sndx));
		if ((name = libld_malloc(strlen(_name) + 1)) == 0)
			return (S_ERROR);
		(void) strcpy(name, _name);

	} else if ((name = elf_strptr(elf, (size_t)sndx,
	    (size_t)shdr->sh_name)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_STRPTR), ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	error = process_strtab(name, ifl, shdr, scn, sndx, FALSE, ofl);
	if ((error == 0) || (error == S_ERROR))
		return (error);
	str = ifl->ifl_isdesc[sndx]->is_indata->d_buf;

	/*
	 * Determine the state table column from the input file type.  Note,
	 * shared library sections are not added to the output section list.
	 */
	if (ifl->ifl_ehdr->e_type == ET_DYN) {
		column = 1;
		ofl->ofl_soscnt++;
		ident = M_ID_NULL;
	} else {
		column = 0;
		ofl->ofl_objscnt++;
		ident = M_ID_UNKNOWN;
	}

	DBG_CALL(Dbg_file_generic(ifl));
	ndx = 0;
	vdfisp = vndisp = vsyisp = sifisp = capisp = 0;
	scn = NULL;
	while (scn = elf_nextscn(elf, scn)) {
		ndx++;
		/*
		 * As we've already processed the .shstrtab don't do it again.
		 */
		if (ndx == sndx)
			continue;

		if ((shdr = elf_getshdr(scn)) == NULL) {
			eprintf(ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR),
			    ifl->ifl_name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
		name = str + (size_t)(shdr->sh_name);

		if (lds_input_section(name, &shdr, ndx, ifl->ifl_name, scn,
		    elf, ofl) == S_ERROR)
			return (S_ERROR);

		/*
		 * Reset the name since the shdr->sh_name could have been
		 * changed as part of lds_input_section().  If there is no name,
		 * fabricate one using the section index.
		 */
		if (shdr->sh_name == 0) {
			(void) snprintf(_name, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(ndx));
			if ((name = libld_malloc(strlen(_name) + 1)) == 0)
				return (S_ERROR);
			(void) strcpy(name, _name);
		} else
			name = str + (size_t)(shdr->sh_name);

		row = shdr->sh_type;

		/*
		 * If the section has the SHF_EXCLUDE flag on, and we're not
		 * generating a relocatable object, exclude the section.
		 */
		if (((shdr->sh_flags & SHF_EXCLUDE) != 0) &&
		    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)) {
			if ((error = process_exclude(name, ifl, shdr, scn,
			    ndx, ofl)) == S_ERROR)
				return (S_ERROR);
			if (error == 1)
				continue;
		}

		/*
		 * If this is a standard section type process it via the
		 * appropriate action routine.
		 */
		if (row < SHT_NUM) {
			if (Initial[row][column] != NULL) {
				if (Initial[row][column](name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
			}
		} else {
			/*
			 * If this section is below SHT_LOSUNW then we don't
			 * really know what to do with it, issue a warning
			 * message but do the basic section processing anyway.
			 */
			if (row < (Word)SHT_LOSUNW)
				eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_INVALSEC),
				    ifl->ifl_name, name,
				    conv_sectyp_str(ofl->ofl_e_machine,
				    (unsigned)shdr->sh_type));

			/*
			 * Handle sections greater than SHT_LOSUNW.
			 */
			switch (row) {
			case SHT_SUNW_dof:
				if (process_section(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_cap:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				capisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_DEBUGSTR:
			case SHT_SUNW_DEBUG:
				if (process_debug(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_move:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_syminfo:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				sifisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_ANNOTATE:
			case SHT_SUNW_COMDAT:
				if (process_progbits(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_verdef:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				vdfisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_verneed:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				vndisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_versym:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_NULL, ofl) == S_ERROR)
					return (S_ERROR);
				vsyisp = ifl->ifl_isdesc[ndx];
				break;
#if	defined(sparc)
			case SHT_SPARC_GOTDATA:
				if (process_section(name, ifl, shdr, scn,
				    ndx, M_ID_GOTDATA, ofl) == S_ERROR)
					return (S_ERROR);
				break;
#endif
#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
			case SHT_AMD64_UNWIND:
				if (column == 0) {
					/*
					 * column == ET_REL
					 */
					if (process_amd64_unwind(name, ifl,
					    shdr, scn, ndx, M_ID_NULL,
					    ofl) == S_ERROR)
						return (S_ERROR);
				}
				break;
#endif
			default:
				if (ident != M_ID_NULL)
					ident = M_ID_USER;
				if (process_section(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			}
		}

		/*
		 * If we have any sections that require ORDERED processing,
		 * remember the index of the first ordered section.  This let's
		 * us know if we need an ORDERED place_section pass, and if so,
		 * where to start.
		 */
		if (ifl->ifl_isdesc[ndx] &&
		    (ifl->ifl_isdesc[ndx]->is_shdr->sh_flags & ALL_SHF_ORDER)) {
			ordered_cnt++;
			if (ordered_shndx == 0)
				ordered_shndx = ndx;
		}
	}

	/*
	 * Now that all of sections have been placed, scan through any sections
	 * which have special ordering requirements and place them now.
	 */
	if (ordered_shndx) {
		Word	cnt;

		for (ndx = ordered_shndx, cnt = 0;
		    (ndx < ifl->ifl_shnum) && (cnt < ordered_cnt); ndx++) {
			Is_desc	*isp;
			/* LINTED */
			Os_desc	*osp;

			if (((isp = ifl->ifl_isdesc[ndx]) == 0) ||
			    ((isp->is_shdr->sh_flags & ALL_SHF_ORDER) == 0))
				continue;

			/*
			 * If this is an ordered section, process it.
			 */
			cnt++;
			if ((osp = (Os_desc *)process_ordered(ifl, ofl, ndx,
			    ifl->ifl_shnum)) == (Os_desc *)S_ERROR)
				return (S_ERROR);

#if	(defined(__i386) || defined(__amd64)) && defined(_ELF64)
			/*
			 * If this section is 'ordered' then it was not
			 * caught in the previous 'place_section' operation.
			 *
			 * So - now that we have a OSP section for
			 * the unwind info - record it.
			 */
			if (osp &&
			    (osp->os_shdr->sh_type == SHT_AMD64_UNWIND) &&
			    (append_amd64_unwind(osp, ofl) == S_ERROR))
				return (S_ERROR);
#endif
		}
	}

	/*
	 * If this is an explict shared object determine if the user has
	 * specified a control definition.  This descriptor may specify which
	 * version definitions can be used from this object (it may also update
	 * the dependency to USED and supply an alternative SONAME).
	 */
	sdf = 0;
	if (column && (ifl->ifl_flags & FLG_IF_NEEDED)) {
		const char	*base;

		/*
		 * Use the basename of the input file (typically this is the
		 * compilation environment name, ie. libfoo.so).
		 */
		if ((base = strrchr(ifl->ifl_name, '/')) == NULL)
			base = ifl->ifl_name;
		else
			base++;

		if ((sdf = sdf_find(base, &ofl->ofl_socntl)) != 0) {
			sdf->sdf_file = ifl;
			ifl->ifl_sdfdesc = sdf;
		}
	}

	/*
	 * Process any hardware/software capabilities sections.  Only propagate
	 * capabilities for input relocatable objects.  If the object doesn't
	 * contain any capabilities, any capability state that has already been
	 * gathered will prevail.
	 */
	if (capisp && (ifl->ifl_ehdr->e_type == ET_REL))
		process_cap(name, ifl, capisp, ofl);

	/*
	 * Process any version dependencies.  These will establish shared object
	 * `needed' entries in the same manner as will be generated from the
	 * .dynamic's NEEDED entries.
	 */
	if (vndisp && (ofl->ofl_flags & (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)))
		if (vers_need_process(vndisp, ifl, ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Before processing any symbol resolution or relocations process any
	 * version sections.
	 */
	if (vsyisp)
		(void) vers_sym_process(vsyisp, ifl);

	if (ifl->ifl_versym &&
	    (vdfisp || (sdf && (sdf->sdf_flags & FLG_SDF_SELECT))))
		if (vers_def_process(vdfisp, ifl, ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Having collected the appropriate sections carry out any additional
	 * processing if necessary.
	 */
	for (ndx = 0; ndx < ifl->ifl_shnum; ndx++) {
		Is_desc *	isp;

		if ((isp = ifl->ifl_isdesc[ndx]) == 0)
			continue;
		row = isp->is_shdr->sh_type;

		if ((isp->is_flags & FLG_IS_DISCARD) == 0)
			lds_section(isp->is_name, isp->is_shdr, ndx,
				isp->is_indata, elf);

		/*
		 * If this is a ST_SUNW_move section from a
		 * a relocatable file, keep the input section.
		 */
		if ((row == SHT_SUNW_move) && (column == 0)) {
			if (list_appendc(&(ofl->ofl_ismove), isp) == 0)
				return (S_ERROR);
		}

		/*
		 * If this is a standard section type process it via the
		 * appropriate action routine.
		 */
		if (row < SHT_NUM) {
			if (Final[row][column] != NULL)
				if (Final[row][column](isp, ifl, ofl) ==
				    S_ERROR)
					return (S_ERROR);
		}
	}

	/*
	 * After processing any symbol resolution, and if this dependency
	 * indicates it contains symbols that can't be directly bound to,
	 * set the symbols appropriately.
	 */
	if (sifisp && ((ifl->ifl_flags & (FLG_IF_NEEDED | FLG_IF_NODIRECT)) ==
	    (FLG_IF_NEEDED | FLG_IF_NODIRECT)))
		(void) sym_nodirect(sifisp, ifl, ofl);

	return (1);
}

/*
 * Process the current input file.  There are basically three types of files
 * that come through here:
 *
 *  o	files explicitly defined on the command line (ie. foo.o or bar.so),
 *	in this case only the `name' field is valid.
 *
 *  o	libraries determined from the -l command line option (ie. -lbar),
 *	in this case the `soname' field contains the basename of the located
 *	file.
 *
 * Any shared object specified via the above two conventions must be recorded
 * as a needed dependency.
 *
 *  o	libraries specified as dependencies of those libraries already obtained
 *	via the command line (ie. bar.so has a DT_NEEDED entry of fred.so.1),
 *	in this case the `soname' field contains either a full pathname (if the
 *	needed entry contained a `/'), or the basename of the located file.
 *	These libraries are processed to verify symbol binding but are not
 *	recorded as dependencies of the output file being generated.
 */
Ifl_desc *
process_ifl(const char *name, const char *soname, int fd, Elf *elf,
    Half flags, Ofl_desc * ofl, Rej_desc * rej)
{
	Ifl_desc	*ifl;
	Ehdr		*ehdr;
	Listnode	*lnp;
	uintptr_t	error = 0;
	struct stat	status;
	Ar_desc		*adp;
	Rej_desc	_rej;

	/*
	 * If this file was not extracted from an archive obtain its device
	 * information.  This will be used to determine if the file has already
	 * been processed (rather than simply comparing filenames, the device
	 * information provides a quicker comparison and detects linked files).
	 */
	if (!(flags & FLG_IF_EXTRACT))
		(void) fstat(fd, &status);
	else {
		status.st_dev = 0;
		status.st_ino = 0;
	}

	switch (elf_kind(elf)) {
	case ELF_K_AR:
		/*
		 * Determine if we've already come across this archive file.
		 */
		if (!(flags & FLG_IF_EXTRACT)) {
			for (LIST_TRAVERSE(&ofl->ofl_ars, lnp, adp)) {
				if ((adp->ad_stdev != status.st_dev) ||
				    (adp->ad_stino != status.st_ino))
					continue;

				/*
				 * We've seen this file before so reuse the
				 * original archive descriptor and discard the
				 * new elf descriptor.
				 */
				DBG_CALL(Dbg_file_reuse(name, adp->ad_name));
				(void) elf_end(elf);
				return ((Ifl_desc *)process_archive(name, fd,
				    adp, ofl));
			}
		}

		/*
		 * As we haven't processed this file before establish a new
		 * archive descriptor.
		 */
		adp = ar_setup(name, elf, ofl);
		if ((adp == 0) || (adp == (Ar_desc *)S_ERROR))
			return ((Ifl_desc *)adp);
		adp->ad_stdev = status.st_dev;
		adp->ad_stino = status.st_ino;

		lds_file(name, ELF_K_AR, flags, elf);

		return ((Ifl_desc *)process_archive(name, fd, adp, ofl));

	case ELF_K_ELF:
		/*
		 * Obtain the elf header so that we can determine what type of
		 * elf ELF_K_ELF file this is.
		 */
		if ((ehdr = elf_getehdr(elf)) == NULL) {
			int	_class = gelf_getclass(elf);

			/*
			 * Failure could occur for a number of reasons at this
			 * point.  Typically the files class is incorrect (ie.
			 * user is building 64-bit but managed to pint at 32-bit
			 * libraries).  However any number of elf errors can
			 * also occur, such as from a truncated or corrupt file.
			 * Here we try and get the best error message possible.
			 */
			if (M_CLASS != _class) {
				_rej.rej_type = SGS_REJ_CLASS;
				_rej.rej_info = (uint_t)_class;
			} else {
				_rej.rej_type = SGS_REJ_STR;
				_rej.rej_str = elf_errmsg(-1);
			}
			_rej.rej_name = name;
			DBG_CALL(Dbg_file_rejected(&_rej));
			if (rej->rej_type == 0) {
				*rej = _rej;
				rej->rej_name = strdup(_rej.rej_name);
			}
			return (0);
		}

		/*
		 * Determine if we've already come across this file.
		 */
		if (!(flags & FLG_IF_EXTRACT)) {
			List *	lst;

			if (ehdr->e_type == ET_REL)
				lst = &ofl->ofl_objs;
			else
				lst = &ofl->ofl_sos;

			/*
			 * Traverse the appropriate file list and determine if
			 * a dev/inode match is found.
			 */
			for (LIST_TRAVERSE(lst, lnp, ifl)) {
				/*
				 * Ifl_desc generated via -Nneed, therefore no
				 * actual file behind it.
				 */
				if (ifl->ifl_flags & FLG_IF_NEEDSTR)
					continue;

				if ((ifl->ifl_stino != status.st_ino) ||
				    (ifl->ifl_stdev != status.st_dev))
					continue;

				/*
				 * Disregard (skip) this image.
				 */
				DBG_CALL(Dbg_file_skip(name, ifl->ifl_name));
				(void) elf_end(elf);

				/*
				 * If the file was explicitly defined on the
				 * command line (this is always the case for
				 * relocatable objects, and is true for shared
				 * objects when they weren't specified via -l or
				 * were dragged in as an implicit dependency),
				 * then warn the user.
				 */
				if ((flags & FLG_IF_CMDLINE) ||
				    (ifl->ifl_flags & FLG_IF_CMDLINE)) {
					const char	*errmsg;

					/*
					 * Determine whether this is the same
					 * file name as originally encountered
					 * so as to provide the most
					 * descriptive diagnostic.
					 */
					if (strcmp(name, ifl->ifl_name) == 0)
					    errmsg = MSG_INTL(MSG_FIL_MULINC_1);
					else
					    errmsg = MSG_INTL(MSG_FIL_MULINC_2);

					eprintf(ERR_WARNING, errmsg, name,
					    ifl->ifl_name);
				}
				return (ifl);
			}
		}

		/*
		 * At this point, we know we need the file.  Establish an input
		 * file descriptor and continue processing.
		 */
		ifl = ifl_setup(name, ehdr, elf, flags, ofl, rej);
		if ((ifl == 0) || (ifl == (Ifl_desc *)S_ERROR))
			return (ifl);
		ifl->ifl_stdev = status.st_dev;
		ifl->ifl_stino = status.st_ino;

		/*
		 * If -zignore is in effect, mark this file as a potential
		 * candidate (the files use isn't actually determined until
		 * symbol resolution and relocation processing are completed).
		 */
		if (ofl->ofl_flags1 & FLG_OF1_IGNORE)
			ifl->ifl_flags |= FLG_IF_IGNORE;

		switch (ehdr->e_type) {
		case ET_REL:
			mach_eflags(ehdr, ofl);
			error = process_elf(ifl, elf, ofl);
			break;
		case ET_DYN:
			if ((ofl->ofl_flags & FLG_OF_STATIC) ||
			    !(ofl->ofl_flags & FLG_OF_DYNLIBS)) {
				eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_SOINSTAT),
				    name);
				ofl->ofl_flags |= FLG_OF_FATAL;
				return (0);
			}

			/*
			 * Record any additional shared object information.
			 * If no soname is specified (eg. this file was
			 * derived from a explicit filename declaration on the
			 * command line, ie. bar.so) use the pathname.
			 * This entry may be overridden if the files dynamic
			 * section specifies an DT_SONAME value.
			 */
			if (soname == NULL)
				ifl->ifl_soname = ifl->ifl_name;
			else
				ifl->ifl_soname = soname;

			/*
			 * If direct bindings, lazy loading, or group
			 * permissions need to be established, mark this object.
			 */
			if (ofl->ofl_flags1 & FLG_OF1_ZDIRECT)
				ifl->ifl_flags |= FLG_IF_DIRECT;
			if (ofl->ofl_flags1 & FLG_OF1_LAZYLD)
				ifl->ifl_flags |= FLG_IF_LAZYLD;
			if (ofl->ofl_flags1 & FLG_OF1_GRPPRM)
				ifl->ifl_flags |= FLG_IF_GRPPRM;
			error = process_elf(ifl, elf, ofl);

			/*
			 * At this point we know if this file will be
			 * lazyloaded, or whether bindings to it must be direct.
			 * In either case, a syminfo section is required.
			 */
			if (ifl->ifl_flags & (FLG_IF_LAZYLD | FLG_IF_DIRECT))
				ofl->ofl_flags |= FLG_OF_SYMINFO;

			break;
		default:
			(void) elf_errno();
			_rej.rej_type = SGS_REJ_UNKFILE;
			_rej.rej_name = name;
			DBG_CALL(Dbg_file_rejected(&_rej));
			if (rej->rej_type == 0) {
				*rej = _rej;
				rej->rej_name = strdup(_rej.rej_name);
			}
			return (0);
		}
		break;
	default:
		(void) elf_errno();
		_rej.rej_type = SGS_REJ_UNKFILE;
		_rej.rej_name = name;
		DBG_CALL(Dbg_file_rejected(&_rej));
		if (rej->rej_type == 0) {
			*rej = _rej;
			rej->rej_name = strdup(_rej.rej_name);
		}
		return (0);
	}
	if ((error == 0) || (error == S_ERROR))
		return ((Ifl_desc *)error);
	else
		return (ifl);
}

/*
 * Having successfully opened a file, set up the necessary elf structures to
 * process it further.  This small section of processing is slightly different
 * from the elf initialization required to process a relocatable object from an
 * archive (see libs.c: process_archive()).
 */
Ifl_desc *
process_open(const char *path, size_t dlen, int fd, Ofl_desc *ofl, Half flags,
    Rej_desc * rej)
{
	Elf *	elf;

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_BEGIN), path);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	return (process_ifl(&path[0], &path[dlen], fd, elf, flags, ofl, rej));
}

/*
 * Process a required library (i.e. the dependency of a shared object).
 * Combine the directory and filename, check the resultant path size, and try
 * opening the pathname.
 */
Ifl_desc *
process_req_lib(Sdf_desc *sdf, const char *dir, const char *file,
    Ofl_desc * ofl, Rej_desc * rej)
{
	size_t		dlen, plen;
	int		fd;
	char		path[PATH_MAX];
	const char	*_dir = dir;

	/*
	 * Determine the sizes of the directory and filename to insure we don't
	 * exceed our buffer.
	 */
	if ((dlen = strlen(dir)) == 0) {
		_dir = MSG_ORIG(MSG_STR_DOT);
		dlen = 1;
	}
	dlen++;
	plen = dlen + strlen(file) + 1;
	if (plen > PATH_MAX) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_FIL_PTHTOLONG), _dir, file);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	/*
	 * Build the entire pathname and try and open the file.
	 */
	(void) strcpy(path, _dir);
	(void) strcat(path, MSG_ORIG(MSG_STR_SLASH));
	(void) strcat(path, file);
	DBG_CALL(Dbg_libs_req(sdf->sdf_name, sdf->sdf_rfile, path));

	if ((fd = open(path, O_RDONLY)) == -1)
		return (0);
	else {
		Ifl_desc	*ifl;
		char		*_path;

		if ((_path = libld_malloc(strlen(path) + 1)) == 0)
			return ((Ifl_desc *)S_ERROR);
		(void) strcpy(_path, path);
		ifl = process_open(_path, dlen, fd, ofl, NULL, rej);
		(void) close(fd);
		return (ifl);
	}
}

/*
 * Finish any library processing.  Walk the list of so's that have been listed
 * as "included" by shared objects we have previously processed.  Examine them,
 * without adding them as explicit dependents of this program, in order to
 * complete our symbol definition process.  The search path rules are:
 *
 *  o	use any user supplied paths, i.e. LD_LIBRARY_PATH and -L, then
 *
 *  o	use any RPATH defined within the parent shared object, then
 *
 *  o	use the default directories, i.e. LIBPATH or -YP.
 */
uintptr_t
finish_libs(Ofl_desc *ofl)
{
	Listnode	*lnp1;
	Sdf_desc	*sdf;
	Rej_desc	rej = { 0 };

	/*
	 * Make sure we are back in dynamic mode.
	 */
	ofl->ofl_flags |= FLG_OF_DYNLIBS;

	for (LIST_TRAVERSE(&ofl->ofl_soneed, lnp1, sdf)) {
		Listnode	*lnp2;
		const char	*path;
		int		fd;
		Ifl_desc	*ifl;
		const char	*file = sdf->sdf_name;

		/*
		 * See if this file has already been processed.  At the time
		 * this implicit dependency was determined there may still have
		 * been more explict dependencies to process.  (Note, if we ever
		 * do parse the command line three times we would be able to
		 * do all this checking when processing the dynamic section).
		 */
		if (sdf->sdf_file)
			continue;

		for (LIST_TRAVERSE(&ofl->ofl_sos, lnp2, ifl)) {
			if (!(ifl->ifl_flags & FLG_IF_NEEDSTR) &&
			    (strcmp(file, ifl->ifl_soname) == 0)) {
				sdf->sdf_file = ifl;
				break;
			}
		}
		if (sdf->sdf_file)
			continue;

		/*
		 * If the current element embeds a "/", then it's to be taken
		 * "as is", with no searching involved.
		 */
		for (path = file; *path; path++)
			if (*path == '/')
				break;
		if (*path) {
			DBG_CALL(Dbg_libs_req(sdf->sdf_name, sdf->sdf_rfile,
			    file));
			if ((fd = open(file, O_RDONLY)) == -1) {
				eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_NOTFOUND),
				    file, sdf->sdf_rfile);
			} else {
				Rej_desc	_rej = { 0 };

				ifl = process_open(file, sizeof (file) + 1,
				    fd, ofl, NULL, &_rej);
				(void) close(fd);

				if (ifl == (Ifl_desc *)S_ERROR) {
					return (S_ERROR);
				}
				if (_rej.rej_type) {
					eprintf(ERR_WARNING,
					    MSG_INTL(reject[_rej.rej_type]),
					    _rej.rej_name ? rej.rej_name :
					    MSG_INTL(MSG_STR_UNKNOWN),
					    conv_reject_str(&_rej));
				} else
					sdf->sdf_file = ifl;
			}
			continue;
		}

		/*
		 * Now search for this file in any user defined directories.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_ulibdirs, lnp2, path)) {
			Rej_desc	_rej = { 0 };

			ifl = process_req_lib(sdf, path, file, ofl, &_rej);
			if (ifl == (Ifl_desc *)S_ERROR) {
				return (S_ERROR);
			}
			if (_rej.rej_type) {
				if (rej.rej_type == 0) {
					rej = _rej;
					rej.rej_name = strdup(_rej.rej_name);
				}
			}
			if (ifl) {
				sdf->sdf_file = ifl;
				break;
			}
		}
		if (sdf->sdf_file)
			continue;

		/*
		 * Next use the local rules defined within the parent shared
		 * object.
		 */
		if (sdf->sdf_rpath != NULL) {
			char	*rpath, *next;

			rpath = libld_malloc(strlen(sdf->sdf_rpath) + 1);
			if (rpath == 0)
				return (S_ERROR);
			(void) strcpy(rpath, sdf->sdf_rpath);
			DBG_CALL(Dbg_libs_path(rpath, LA_SER_RUNPATH,
			    sdf->sdf_rfile));
			if ((path = strtok_r(rpath,
			    MSG_ORIG(MSG_STR_COLON), &next)) != NULL) {
				do {
					Rej_desc	_rej = { 0 };

					path = expand(sdf->sdf_rfile, path,
					    &next);

					ifl = process_req_lib(sdf, path,
						file, ofl, &_rej);
					if (ifl == (Ifl_desc *)S_ERROR) {
						return (S_ERROR);
					}
					if (_rej.rej_type) {
						if (rej.rej_type == 0) {
						    rej = _rej;
						    rej.rej_name =
							strdup(_rej.rej_name);
						}
					}
					if (ifl) {
						sdf->sdf_file = ifl;
						break;
					}
				} while ((path = strtok_r(NULL,
				    MSG_ORIG(MSG_STR_COLON), &next)) != NULL);
			}
		}
		if (sdf->sdf_file)
			continue;

		/*
		 * Finally try the default library search directories.
		 */
		for (LIST_TRAVERSE(&ofl->ofl_dlibdirs, lnp2, path)) {
			Rej_desc	_rej = { 0 };

			ifl = process_req_lib(sdf, path, file, ofl, &rej);
			if (ifl == (Ifl_desc *)S_ERROR) {
				return (S_ERROR);
			}
			if (_rej.rej_type) {
				if (rej.rej_type == 0) {
					rej = _rej;
					rej.rej_name = strdup(_rej.rej_name);
				}
			}
			if (ifl) {
				sdf->sdf_file = ifl;
				break;
			}
		}
		if (sdf->sdf_file)
			continue;

		/*
		 * If we've got this far we haven't found the shared object.
		 * If an object was found, but was rejected for some reason,
		 * print a diagnostic to that effect, otherwise generate a
		 * generic "not found" diagnostic.
		 */
		if (rej.rej_type) {
			eprintf(ERR_WARNING, MSG_INTL(reject[rej.rej_type]),
			    rej.rej_name ? rej.rej_name :
			    MSG_INTL(MSG_STR_UNKNOWN), conv_reject_str(&rej));
		} else {
			eprintf(ERR_WARNING, MSG_INTL(MSG_FIL_NOTFOUND), file,
			    sdf->sdf_rfile);
		}
	}

	/*
	 * Finally, now that all objects have been input, make sure any version
	 * requirements have been met.
	 */
	return (vers_verify(ofl));
}
