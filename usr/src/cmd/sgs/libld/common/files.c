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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Processing of relocatable objects and shared objects.
 */

#define	ELF_TARGET_AMD64
#define	ELF_TARGET_SPARC

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
ifl_verify(Ehdr *ehdr, Ofl_desc *ofl, Rej_desc *rej)
{
	/*
	 * Check the validity of the elf header information for compatibility
	 * with this machine and our own internal elf library.
	 */
	if ((ehdr->e_machine != ld_targ.t_m.m_mach) &&
	    ((ehdr->e_machine != ld_targ.t_m.m_machplus) &&
	    ((ehdr->e_flags & ld_targ.t_m.m_flagsplus) == 0))) {
		rej->rej_type = SGS_REJ_MACH;
		rej->rej_info = (uint_t)ehdr->e_machine;
		return (0);
	}
	if (ehdr->e_ident[EI_DATA] != ld_targ.t_m.m_data) {
		rej->rej_type = SGS_REJ_DATA;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_DATA];
		return (0);
	}
	if (ehdr->e_version > ofl->ofl_dehdr->e_version) {
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
static Ifl_desc *
ifl_setup(const char *name, Ehdr *ehdr, Elf *elf, Word flags, Ofl_desc *ofl,
    Rej_desc *rej)
{
	Ifl_desc	*ifl;
	List		*list;
	Rej_desc	_rej = { 0 };

	if (ifl_verify(ehdr, ofl, &_rej) == 0) {
		_rej.rej_name = name;
		DBG_CALL(Dbg_file_rejected(ofl->ofl_lml, &_rej,
		    ld_targ.t_m.m_mach));
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
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSCN), name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return ((Ifl_desc *)S_ERROR);
		}
		if ((shdr0 = elf_getshdr(scn)) == NULL) {
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSHDR), name);
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
static uintptr_t
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
	isp->is_flags = FLG_IS_EXTERNAL;
	isp->is_keyident = ident;

	if ((isp->is_indata = elf_getdata(scn, NULL)) == NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_GETDATA),
		    ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	if ((shdr->sh_flags & SHF_EXCLUDE) &&
	    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0)) {
		isp->is_flags |= FLG_IS_DISCARD;
	}

	/*
	 * Add the new input section to the files input section list and
	 * flag whether the section needs placing in an output section.  This
	 * placement is deferred until all input section processing has been
	 * completed, as SHT_GROUP sections can provide information that will
	 * affect how other sections within the file should be placed.
	 */
	ifl->ifl_isdesc[ndx] = isp;

	if (ident) {
		if (shdr->sh_flags & ALL_SHF_ORDER) {
			isp->is_flags |= FLG_IS_ORDERED;
			ifl->ifl_flags |= FLG_IF_ORDERED;
		}
		isp->is_flags |= FLG_IS_PLACE;
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
		Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_IGNORE, CA_SUNW_SF_1,
		    val, ld_targ.t_m.m_mach);
		return;
	}

#if	!defined(_ELF64)
	if (ifl->ifl_ehdr->e_type == ET_REL) {
		/*
		 * The SF1_SUNW_ADDR32 is only meaningful when building a 64-bit
		 * object.  Warn the user, and remove the setting, if we're
		 * building a 32-bit object.
		 */
		if (val & SF1_SUNW_ADDR32) {
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_FIL_INADDR32SF1), ifl->ifl_name, name);
			val &= ~SF1_SUNW_ADDR32;
		}
	}
#endif
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
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, name, EC_XWORD(badval));
		val &= SF1_SUNW_MASK;
	}
	if ((val & (SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)) == SF1_SUNW_FPUSED) {
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, name, EC_XWORD(val));
		return;
	}

	/*
	 * If the input file is not a relocatable object, then we're only here
	 * to warn the user of any questionable capabilities.
	 */
	if (ifl->ifl_ehdr->e_type != ET_REL) {
#if	defined(_ELF64)
		/*
		 * If we're building a 64-bit executable, and we come across a
		 * dependency that requires a restricted address space, then
		 * that dependencies requirement can only be satisfied if the
		 * executable triggers the restricted address space.  This is a
		 * warning rather than a fatal error, as the possibility exists
		 * that an appropriate dependency will be provided at runtime.
		 * The runtime linker will refuse to use this dependency.
		 */
		if ((val & SF1_SUNW_ADDR32) && (ofl->ofl_flags & FLG_OF_EXEC) &&
		    ((ofl->ofl_sfcap_1 & SF1_SUNW_ADDR32) == 0)) {
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_FIL_EXADDR32SF1), ifl->ifl_name, name);
		}
#endif
		return;
	}

	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_OLD, CA_SUNW_SF_1,
	    ofl->ofl_sfcap_1, ld_targ.t_m.m_mach);
	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_NEW, CA_SUNW_SF_1,
	    val, ld_targ.t_m.m_mach);

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

	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_RESOLVED, CA_SUNW_SF_1,
	    ofl->ofl_sfcap_1, ld_targ.t_m.m_mach);
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
		Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_IGNORE, CA_SUNW_HW_1,
		    val, ld_targ.t_m.m_mach);
		return;
	}

	/*
	 * If this object doesn't specify any capabilities, ignore it, and
	 * leave the state as is.
	 */
	if (val == 0)
		return;

	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_OLD, CA_SUNW_HW_1,
	    ofl->ofl_hwcap_1, ld_targ.t_m.m_mach);
	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_NEW, CA_SUNW_HW_1, val,
	    ld_targ.t_m.m_mach);

	ofl->ofl_hwcap_1 |= val;

	Dbg_cap_sec_entry(ofl->ofl_lml, DBG_CAP_RESOLVED, CA_SUNW_HW_1,
	    ofl->ofl_hwcap_1, ld_targ.t_m.m_mach);
}

/*
 * Process a hardware/software capabilities section.  Traverse the section
 * updating the global capabilities variables as necessary.
 */
static void
process_cap(Ifl_desc *ifl, Is_desc *cisp, Ofl_desc *ofl)
{
	Cap	*cdata;
	Word	ndx, cnum;

	DBG_CALL(Dbg_cap_sec_title(ofl->ofl_lml, ifl->ifl_name));

	/*
	 * The capabilities are supposed to be terminated with a CA_SUNW_NULL
	 * entry.  However, the compilers have been known to not follow this
	 * convention.  Use the section information to determine the number
	 * of capabilities, and skip any CA_SUNW_NULL entries.
	 */
	cdata = (Cap *)cisp->is_indata->d_buf;
	cnum = (Word)(cisp->is_shdr->sh_size / cisp->is_shdr->sh_entsize);

	for (ndx = 0; ndx < cnum; cdata++, ndx++) {
		switch (cdata->c_tag) {
			case CA_SUNW_HW_1:
				/*
				 * Only the hardware capabilities that are
				 * defined in a relocatable object become part
				 * of the hardware capabilities in the output
				 * file.
				 */
				if (ifl->ifl_ehdr->e_type == ET_REL)
					hw1_cap(ofl, cdata->c_un.c_val);
				break;
			case CA_SUNW_SF_1:
				/*
				 * Only the software capabilities that are
				 * defined in a relocatable object become part
				 * of the software capabilities in the output
				 * file.  However, check the validity of the
				 * software capabilities of any dependencies.
				 */
				sf1_cap(ofl, cdata->c_un.c_val, ifl,
				    cisp->is_name);
				break;
			case CA_SUNW_NULL:
				break;
			default:
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_FIL_UNKCAP),
				    ifl->ifl_name, cisp->is_name, cdata->c_tag);
		}
	}
}

/*
 * Simply process the section so that we have pointers to the data for use
 * in later routines, however don't add the section to the output section
 * list as we will be creating our own replacement sections later (ie.
 * symtab and relocation).
 */
static uintptr_t
/* ARGSUSED5 */
process_input(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	return (process_section(name, ifl, shdr, scn, ndx,
	    ld_targ.t_id.id_null, ofl));
}

/*
 * Keep a running count of relocation entries from input relocatable objects for
 * sizing relocation buckets later.  If we're building an executable, save any
 * relocations from shared objects to determine if any copy relocation symbol
 * has a displacement relocation against it.
 */
static uintptr_t
/* ARGSUSED5 */
process_reloc(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	if (process_section(name, ifl,
	    shdr, scn, ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
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
static uintptr_t
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
	if ((ident != ld_targ.t_id.id_null) &&
	    (strcmp(name, MSG_ORIG(MSG_SCN_STRTAB)) == 0))
		ident = ld_targ.t_id.id_null;

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
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_FIL_MALSTR), ifl->ifl_name, name);
	} else
		isp->is_indata->d_buf = (void *)MSG_ORIG(MSG_STR_EMPTY);

	ifl->ifl_flags |= FLG_IF_HSTRTAB;
	return (1);
}

/*
 * Invalid sections produce a warning and are skipped.
 */
static uintptr_t
/* ARGSUSED3 */
invalid_section(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	Conv_inv_buf_t inv_buf;

	eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_FIL_INVALSEC),
	    ifl->ifl_name, name, conv_sec_type(ifl->ifl_ehdr->e_machine,
	    shdr->sh_type, 0, &inv_buf));
	return (1);
}

/*
 * Process a progbits section.
 */
static uintptr_t
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
			ident = ld_targ.t_id.id_tls;
		else if ((shdr->sh_flags & ~ALL_SHF_IGNORE) ==
		    (SHF_ALLOC | SHF_EXECINSTR))
			ident = ld_targ.t_id.id_text;
		else if (shdr->sh_flags & SHF_ALLOC) {
			if ((strcmp(name, MSG_ORIG(MSG_SCN_PLT)) == 0) ||
			    (strcmp(name, MSG_ORIG(MSG_SCN_GOT)) == 0))
				ident = ld_targ.t_id.id_null;
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
				ident = ld_targ.t_id.id_interp;
			} else
				ident = ld_targ.t_id.id_data;
		} else
			ident = ld_targ.t_id.id_note;
	}
	return (process_section(name, ifl, shdr, scn, ndx, ident, ofl));
}

/*
 * Handles the SHT_SUNW_{DEBUG,DEBUGSTR) sections.
 */
static uintptr_t
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
static uintptr_t
process_nobits(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	if (ident) {
		if (shdr->sh_flags & SHF_TLS)
			ident = ld_targ.t_id.id_tlsbss;
#if	defined(_ELF64)
		else if ((shdr->sh_flags & SHF_AMD64_LARGE) &&
		    (ld_targ.t_m.m_mach == EM_AMD64))
			ident = ld_targ.t_id.id_lbss;
#endif
		else
			ident = ld_targ.t_id.id_bss;
	}
	return (process_section(name, ifl, shdr, scn, ndx, ident, ofl));
}

/*
 * Process a SHT_*_ARRAY section.
 */
static uintptr_t
process_array(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	uintptr_t	error;

	if (ident)
		ident = ld_targ.t_id.id_array;

	error = process_section(name, ifl, shdr, scn, ndx, ident, ofl);
	if ((error == 0) || (error == S_ERROR))
		return (error);

	return (1);
}

static uintptr_t
/* ARGSUSED1 */
array_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	Os_desc	*osp;
	Shdr	*shdr;

	if ((isc == NULL) || ((osp = isc->is_osdesc) == NULL))
		return (0);

	shdr = isc->is_shdr;

	if ((shdr->sh_type == SHT_FINI_ARRAY) &&
	    (ofl->ofl_osfiniarray == NULL))
		ofl->ofl_osfiniarray = osp;
	else if ((shdr->sh_type == SHT_INIT_ARRAY) &&
	    (ofl->ofl_osinitarray == NULL))
		ofl->ofl_osinitarray = osp;
	else if ((shdr->sh_type == SHT_PREINIT_ARRAY) &&
	    (ofl->ofl_ospreinitarray == NULL))
		ofl->ofl_ospreinitarray = osp;

	return (1);
}

/*
 * Process a SHT_SYMTAB_SHNDX section.
 */
static uintptr_t
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
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK), ifl->ifl_name, name,
			    EC_XWORD(shdr->sh_link));
			return (S_ERROR);
		}
		isp->is_symshndx = ifl->ifl_isdesc[ndx];
	}
	return (1);
}

/*
 * Final processing for SHT_SYMTAB_SHNDX section.
 */
static uintptr_t
/* ARGSUSED2 */
sym_shndx_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	if (isc->is_shdr->sh_link > isc->is_scnndx) {
		Is_desc	*isp = ifl->ifl_isdesc[isc->is_shdr->sh_link];

		if ((isp == 0) || ((isp->is_shdr->sh_type != SHT_SYMTAB) &&
		    (isp->is_shdr->sh_type != SHT_DYNSYM))) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK), isc->is_file->ifl_name,
			    isc->is_name, EC_XWORD(isc->is_shdr->sh_link));
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
static uintptr_t
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
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
		    ifl->ifl_name);
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
		Ifl_desc	*difl;

		switch (dyn->d_tag) {
		case DT_NEEDED:
		case DT_USED:
			if (((difl =
			    libld_calloc(1, sizeof (Ifl_desc))) == 0) ||
			    (list_appendc(&ofl->ofl_sos, difl) == 0))
				return (S_ERROR);

			difl->ifl_name = MSG_ORIG(MSG_STR_DYNAMIC);
			difl->ifl_soname = str + (size_t)dyn->d_un.d_val;
			difl->ifl_flags = FLG_IF_NEEDSTR;
			break;
		case DT_RPATH:
		case DT_RUNPATH:
			if ((ofl->ofl_rpath = add_string(ofl->ofl_rpath,
			    (str + (size_t)dyn->d_un.d_val))) ==
			    (const char *)S_ERROR)
				return (S_ERROR);
			break;
		case DT_VERSYM:
			/*
			 * The Solaris ld does not put DT_VERSYM in the
			 * dynamic section. If the object has DT_VERSYM,
			 * then it must have been produced by the GNU ld,
			 * and is using the GNU style of versioning.
			 */
			ifl->ifl_flags |= FLG_IF_GNUVER;
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
 * Probably the most common reference to explicit dependencies (via -L) will be
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
			 * explicit dependency foo/bar/lib1.so with a dependency
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
 * The Solaris ld does not put DT_VERSYM in the dynamic section, but the
 * GNU ld does, and it is used by the runtime linker to implement their
 * versioning scheme. Use this fact to determine if the sharable object
 * was produced by the GNU ld rather than the Solaris one, and to set
 * FLG_IF_GNUVER if so. This needs to be done before the symbols are
 * processed, since the answer determines whether we interpret the
 * symbols versions according to Solaris or GNU rules.
 */
/*ARGSUSED*/
static uintptr_t
process_dynamic_isgnu(const char *name, Ifl_desc *ifl, Shdr *shdr,
    Elf_Scn *scn, Word ndx, int ident, Ofl_desc *ofl)
{
	Dyn		*dyn;
	Elf_Data	*dp;
	uintptr_t	error;

	error = process_section(name, ifl, shdr, scn, ndx, ident, ofl);
	if ((error == 0) || (error == S_ERROR))
		return (error);

	/* Get the .dynamic data */
	dp = elf_getdata(scn, NULL);

	for (dyn = (Dyn *)dp->d_buf; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_VERSYM) {
			ifl->ifl_flags |= FLG_IF_GNUVER;
			break;
		}
	}
	return (1);
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
static uintptr_t
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
		Ifl_desc	*sifl;

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

				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_REC_OBJCNFLT), sifl->ifl_name,
				    ifl->ifl_name, sifl->ifl_soname, hint);
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
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_REC_OPTCNFLT), ifl->ifl_name,
			    MSG_INTL(MSG_MARG_SONAME), ifl->ifl_soname);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
	}
	return (1);
}

/*
 * Process a group section.
 */
static uintptr_t
process_group(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	uintptr_t	error;

	error = process_section(name, ifl, shdr, scn, ndx, ident, ofl);
	if ((error == 0) || (error == S_ERROR))
		return (error);

	/*
	 * Indicate that this input file has groups to process.  Groups are
	 * processed after all input sections have been processed.
	 */
	ifl->ifl_flags |= FLG_IS_GROUPS;

	return (1);
}

/*
 * Process a relocation entry. At this point all input sections from this
 * input file have been assigned an input section descriptor which is saved
 * in the `ifl_isdesc' array.
 */
static uintptr_t
rel_process(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	Word 	rndx;
	Is_desc	*risc;
	Os_desc	*osp;
	Shdr	*shdr = isc->is_shdr;
	Conv_inv_buf_t inv_buf;

	/*
	 * Make sure this is a valid relocation we can handle.
	 */
	if (shdr->sh_type != ld_targ.t_m.m_rel_sht_type) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_FIL_INVALSEC),
		    ifl->ifl_name, isc->is_name,
		    conv_sec_type(ifl->ifl_ehdr->e_machine,
		    shdr->sh_type, 0, &inv_buf));
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
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
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
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVRELOC1), ifl->ifl_name,
			    isc->is_name, risc->is_name);
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
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_FIL_EXCLUDE),
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
/* SHT_DYNAMIC	*/	process_rel_dynamic,	process_dynamic_isgnu,
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
/* SHT_GROUP */		process_group,		invalid_section,
/* SHT_SYMTAB_SHNDX */	process_sym_shndx,	NULL
};

static uintptr_t (*Final[SHT_NUM][2])() = {

/* SHT_NULL	*/	NULL,			NULL,
/* SHT_PROGBITS	*/	NULL,			NULL,
/* SHT_SYMTAB	*/	ld_sym_process,		ld_sym_process,
/* SHT_STRTAB	*/	NULL,			NULL,
/* SHT_RELA	*/	rel_process,		NULL,
/* SHT_HASH	*/	NULL,			NULL,
/* SHT_DYNAMIC	*/	NULL,			process_dynamic,
/* SHT_NOTE	*/	NULL,			NULL,
/* SHT_NOBITS	*/	NULL,			NULL,
/* SHT_REL	*/	rel_process,		NULL,
/* SHT_SHLIB	*/	NULL,			NULL,
/* SHT_DYNSYM	*/	NULL,			ld_sym_process,
/* SHT_UNKNOWN12 */	NULL,			NULL,
/* SHT_UNKNOWN13 */	NULL,			NULL,
/* SHT_INIT_ARRAY */	array_process,		NULL,
/* SHT_FINI_ARRAY */	array_process,		NULL,
/* SHT_PREINIT_ARRAY */	array_process,		NULL,
/* SHT_GROUP */		NULL,			NULL,
/* SHT_SYMTAB_SHNDX */	sym_shndx_process,	NULL
};

#define	MAXNDXSIZE	10

/*
 * Process an elf file.  Each section is compared against the section state
 * table to determine whether it should be processed (saved), ignored, or
 * is invalid for the type of input file being processed.
 */
static uintptr_t
process_elf(Ifl_desc *ifl, Elf *elf, Ofl_desc *ofl)
{
	Elf_Scn		*scn;
	Shdr		*shdr;
	Word		ndx, sndx, ordndx = 0, ordcnt = 0;
	char		*str, *name, _name[MAXNDXSIZE];
	Word		row, column;
	int		ident;
	uintptr_t	error;
	Is_desc		*vdfisp, *vndisp, *vsyisp, *sifisp, *capisp;
	Sdf_desc	*sdf;

	/*
	 * First process the .shstrtab section so that later sections can
	 * reference their name.
	 */
	ld_sup_file(ofl, ifl->ifl_name, elf_kind(elf), ifl->ifl_flags, elf);

	sndx = ifl->ifl_shstrndx;
	if ((scn = elf_getscn(elf, (size_t)sndx)) == NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
		    ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	if ((shdr = elf_getshdr(scn)) == NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR),
		    ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}
	if ((name = elf_strptr(elf, (size_t)sndx, (size_t)shdr->sh_name)) ==
	    NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_STRPTR),
		    ifl->ifl_name);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	if (ld_sup_input_section(ofl, ifl, name, &shdr, sndx, scn,
	    elf) == S_ERROR)
		return (S_ERROR);

	/*
	 * Reset the name since the shdr->sh_name could have been changed as
	 * part of ld_sup_input_section().  If there is no name, fabricate one
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
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_STRPTR),
		    ifl->ifl_name);
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
		ident = ld_targ.t_id.id_null;
	} else {
		column = 0;
		ofl->ofl_objscnt++;
		ident = ld_targ.t_id.id_unknown;
	}

	DBG_CALL(Dbg_file_generic(ofl->ofl_lml, ifl));
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
			eprintf(ofl->ofl_lml, ERR_ELF,
			    MSG_INTL(MSG_ELF_GETSHDR), ifl->ifl_name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (0);
		}
		name = str + (size_t)(shdr->sh_name);

		if (ld_sup_input_section(ofl, ifl, name, &shdr, ndx, scn,
		    elf) == S_ERROR)
			return (S_ERROR);

		/*
		 * Reset the name since the shdr->sh_name could have been
		 * changed as part of ld_sup_input_section().  If there is no
		 * name, fabricate one using the section index.
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
			if (row < (Word)SHT_LOSUNW) {
				Conv_inv_buf_t inv_buf;

				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_FIL_INVALSEC), ifl->ifl_name,
				    name,
				    conv_sec_type(ifl->ifl_ehdr->e_machine,
				    shdr->sh_type, 0, &inv_buf));
			}

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
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
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
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_syminfo:
				if (process_section(name, ifl, shdr, scn,
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				sifisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_ANNOTATE:
				if (process_progbits(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_COMDAT:
				if (process_progbits(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				ifl->ifl_isdesc[ndx]->is_flags |= FLG_IS_COMDAT;
				break;
			case SHT_SUNW_verdef:
				if (process_section(name, ifl, shdr, scn,
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				vdfisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_verneed:
				if (process_section(name, ifl, shdr, scn,
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				vndisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_versym:
				if (process_section(name, ifl, shdr, scn,
				    ndx, ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				vsyisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SPARC_GOTDATA:
				/*
				 * SHT_SPARC_GOTDATA (0x70000000) is in the
				 * SHT_LOPROC - SHT_HIPROC range reserved
				 * for processor-specific semantics. It is
				 * only meaningful for sparc targets.
				 */
				if (ld_targ.t_m.m_mach !=
				    LD_TARG_BYCLASS(EM_SPARC, EM_SPARCV9))
					goto do_default;
				if (process_section(name, ifl, shdr, scn,
				    ndx, ld_targ.t_id.id_gotdata, ofl) ==
				    S_ERROR)
					return (S_ERROR);
				break;
#if	defined(_ELF64)
			case SHT_AMD64_UNWIND:
				/*
				 * SHT_AMD64_UNWIND (0x70000001) is in the
				 * SHT_LOPROC - SHT_HIPROC range reserved
				 * for processor-specific semantics. It is
				 * only meaningful for amd64 targets.
				 */
				if (ld_targ.t_m.m_mach != EM_AMD64)
					goto do_default;

				/*
				 * Target is x86, so this really is
				 * SHT_AMD64_UNWIND
				 */
				if (column == 0) {
					/*
					 * column == ET_REL
					 */
					if (process_section(name, ifl, shdr,
					    scn, ndx, ld_targ.t_id.id_unwind,
					    ofl) == S_ERROR)
						return (S_ERROR);
				}
				break;
#endif
			default:
			do_default:
				if (ident != ld_targ.t_id.id_null)
					ident = ld_targ.t_id.id_user;
				if (process_section(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			}
		}
	}

	/*
	 * Now that all input sections have been analyzed, and prior to placing
	 * any input sections to their output sections, process any groups.
	 * Groups can contribute COMDAT items, which may get discarded as part
	 * of placement.  In addition, COMDAT names may require transformation
	 * to indicate different output section placement.
	 */
	if (ifl->ifl_flags & FLG_IS_GROUPS) {
		for (ndx = 1; ndx < ifl->ifl_shnum; ndx++) {
			Is_desc	*isp;

			if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
			    (isp->is_shdr->sh_type != SHT_GROUP))
				continue;

			if (ld_group_process(isp, ofl) == S_ERROR)
				return (S_ERROR);
		}
	}

	/*
	 * Now that all of input sections have been processed, place them
	 * in the appropriate output sections.
	 */
	for (ndx = 1; ndx < ifl->ifl_shnum; ndx++) {
		Is_desc	*isp;
		Shdr	*shdr;

		if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
		    ((isp->is_flags & FLG_IS_PLACE) == 0))
			continue;

		shdr = isp->is_shdr;

		/*
		 * Place all non-ordered sections within their appropriate
		 * output section.
		 *
		 * Ordered sections are sorted based on the relative ordering
		 * of the section pointed to by the sh_info entry.  An ordered
		 * section, whose sh_link points to itself, must also be placed
		 * in the output image so as to control the ordered processing
		 * that follows (see FLG_IF_ORDERED below).
		 */
		if (((isp->is_flags & FLG_IS_ORDERED) == 0) ||
		    ((ndx == shdr->sh_link) &&
		    (shdr->sh_flags & SHF_ORDERED))) {
			if (ld_place_section(ofl, isp,
			    isp->is_keyident, 0) == (Os_desc *)S_ERROR)
				return (S_ERROR);
		}

		/*
		 * If a section requires ordered processing, keep track of the
		 * section index and count to optimize later section traversal.
		 */
		if (isp->is_flags & FLG_IS_ORDERED) {
			ordcnt++;
			if (ordndx == 0)
				ordndx = ndx;
		}
	}

	/*
	 * Some sections have special ordering requirements, that are based off
	 * of the section pointed to by their sh_info entry.  This controlling
	 * section will have been placed (above), and thus any ordered sections
	 * can now be processed.
	 */
	if (ifl->ifl_flags & FLG_IF_ORDERED) {
		Word	cnt = 0;

		for (ndx = ordndx;
		    (ndx < ifl->ifl_shnum) && (cnt < ordcnt); ndx++) {
			Is_desc	*isp;

			if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
			    ((isp->is_flags & FLG_IS_ORDERED) == 0))
				continue;

			if (ld_process_ordered(ifl, ofl, ndx,
			    ifl->ifl_shnum) == S_ERROR)
				return (S_ERROR);
		}
	}

	/*
	 * If this is an explicit shared object determine if the user has
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
	 * Process any hardware/software capabilities sections.  Only the
	 * capabilities for input relocatable objects are propagated.  If the
	 * relocatable objects don't contain any capabilities, any capability
	 * state that has already been gathered will prevail.
	 */
	if (capisp)
		process_cap(ifl, capisp, ofl);

	/*
	 * Process any version dependencies.  These will establish shared object
	 * `needed' entries in the same manner as will be generated from the
	 * .dynamic's NEEDED entries.
	 */
	if (vndisp && (ofl->ofl_flags & (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)))
		if (ld_vers_need_process(vndisp, ifl, ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Before processing any symbol resolution or relocations process any
	 * version sections.
	 */
	if (vsyisp)
		(void) ld_vers_sym_process(ofl->ofl_lml, vsyisp, ifl);

	if (ifl->ifl_versym &&
	    (vdfisp || (sdf && (sdf->sdf_flags & FLG_SDF_SELECT))))
		if (ld_vers_def_process(vdfisp, ifl, ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Having collected the appropriate sections carry out any additional
	 * processing if necessary.
	 */
	for (ndx = 0; ndx < ifl->ifl_shnum; ndx++) {
		Is_desc	*isp;

		if ((isp = ifl->ifl_isdesc[ndx]) == 0)
			continue;
		row = isp->is_shdr->sh_type;

		if ((isp->is_flags & FLG_IS_DISCARD) == 0)
			ld_sup_section(ofl, isp->is_name, isp->is_shdr, ndx,
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
			if (Final[row][column] != NULL) {
				if (Final[row][column](isp, ifl,
				    ofl) == S_ERROR)
					return (S_ERROR);
			}
#if	defined(_ELF64)
		} else if ((row == SHT_AMD64_UNWIND) && (column == 0)) {
			Os_desc	*osp = isp->is_osdesc;

			/*
			 * SHT_AMD64_UNWIND (0x70000001) is in the SHT_LOPROC -
			 * SHT_HIPROC range reserved for processor-specific
			 * semantics, and is only meaningful for amd64 targets.
			 *
			 * Only process unwind contents from relocatable
			 * objects.
			 */
			if (osp && (ld_targ.t_m.m_mach == EM_AMD64) &&
			    (ld_targ.t_uw.uw_append_unwind != NULL) &&
			    ((*ld_targ.t_uw.uw_append_unwind)(osp, ofl) ==
			    S_ERROR))
				return (S_ERROR);
#endif
		}
	}

	/*
	 * After processing any symbol resolution, and if this dependency
	 * indicates it contains symbols that can't be directly bound to,
	 * set the symbols appropriately.
	 */
	if (sifisp && ((ifl->ifl_flags & (FLG_IF_NEEDED | FLG_IF_NODIRECT)) ==
	    (FLG_IF_NEEDED | FLG_IF_NODIRECT)))
		(void) ld_sym_nodirect(sifisp, ifl, ofl);

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
ld_process_ifl(const char *name, const char *soname, int fd, Elf *elf,
    Word flags, Ofl_desc *ofl, Rej_desc *rej)
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
	if (fd && ((flags & FLG_IF_EXTRACT) == 0))
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
				 * new elf descriptor.  Note that a file
				 * descriptor is unnecessary, as the file is
				 * already available in memory.
				 */
				DBG_CALL(Dbg_file_reuse(ofl->ofl_lml, name,
				    adp->ad_name));
				(void) elf_end(elf);
				return ((Ifl_desc *)ld_process_archive(name, -1,
				    adp, ofl));
			}
		}

		/*
		 * As we haven't processed this file before establish a new
		 * archive descriptor.
		 */
		adp = ld_ar_setup(name, elf, ofl);
		if ((adp == 0) || (adp == (Ar_desc *)S_ERROR))
			return ((Ifl_desc *)adp);
		adp->ad_stdev = status.st_dev;
		adp->ad_stino = status.st_ino;

		ld_sup_file(ofl, name, ELF_K_AR, flags, elf);

		/*
		 * Indicate that the ELF descriptor no longer requires a file
		 * descriptor by reading the entire file.  The file is already
		 * read via the initial mmap(2) behind elf_begin(3elf), thus
		 * this operation is effectively a no-op.  However, a side-
		 * effect is that the internal file descriptor, maintained in
		 * the ELF descriptor, is set to -1.  This setting will not
		 * be compared with any file descriptor that is passed to
		 * elf_begin(), should this archive, or one of the archive
		 * members, be processed again from the command line or
		 * because of a -z rescan.
		 */
		if (elf_cntl(elf, ELF_C_FDREAD) == -1) {
			eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_CNTL),
			    name);
			ofl->ofl_flags |= FLG_OF_FATAL;
			return (NULL);
		}

		return ((Ifl_desc *)ld_process_archive(name, -1, adp, ofl));

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
			if (ld_targ.t_m.m_class != _class) {
				_rej.rej_type = SGS_REJ_CLASS;
				_rej.rej_info = (uint_t)_class;
			} else {
				_rej.rej_type = SGS_REJ_STR;
				_rej.rej_str = elf_errmsg(-1);
			}
			_rej.rej_name = name;
			DBG_CALL(Dbg_file_rejected(ofl->ofl_lml, &_rej,
			    ld_targ.t_m.m_mach));
			if (rej->rej_type == 0) {
				*rej = _rej;
				rej->rej_name = strdup(_rej.rej_name);
			}
			return (NULL);
		}

		/*
		 * Determine if we've already come across this file.
		 */
		if (!(flags & FLG_IF_EXTRACT)) {
			List	*lst;

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
				DBG_CALL(Dbg_file_skip(ofl->ofl_lml,
				    ifl->ifl_name, name));
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
					errmsg =
					    (strcmp(name, ifl->ifl_name) == 0) ?
					    MSG_INTL(MSG_FIL_MULINC_1) :
					    MSG_INTL(MSG_FIL_MULINC_2);
					eprintf(ofl->ofl_lml, ERR_WARNING,
					    errmsg, name, ifl->ifl_name);
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
			(*ld_targ.t_mr.mr_mach_eflags)(ehdr, ofl);
			error = process_elf(ifl, elf, ofl);
			break;
		case ET_DYN:
			if ((ofl->ofl_flags & FLG_OF_STATIC) ||
			    !(ofl->ofl_flags & FLG_OF_DYNLIBS)) {
				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_FIL_SOINSTAT), name);
				ofl->ofl_flags |= FLG_OF_FATAL;
				return (NULL);
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
			DBG_CALL(Dbg_file_rejected(ofl->ofl_lml, &_rej,
			    ld_targ.t_m.m_mach));
			if (rej->rej_type == 0) {
				*rej = _rej;
				rej->rej_name = strdup(_rej.rej_name);
			}
			return (NULL);
		}
		break;
	default:
		(void) elf_errno();
		_rej.rej_type = SGS_REJ_UNKFILE;
		_rej.rej_name = name;
		DBG_CALL(Dbg_file_rejected(ofl->ofl_lml, &_rej,
		    ld_targ.t_m.m_mach));
		if (rej->rej_type == 0) {
			*rej = _rej;
			rej->rej_name = strdup(_rej.rej_name);
		}
		return (NULL);
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
 * archive (see libs.c: ld_process_archive()).
 */
Ifl_desc *
ld_process_open(const char *opath, const char *ofile, int *fd, Ofl_desc *ofl,
    Word flags, Rej_desc *rej)
{
	Elf		*elf;
	const char	*npath = opath;
	const char	*nfile = ofile;

	if ((elf = elf_begin(*fd, ELF_C_READ, NULL)) == NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_BEGIN), npath);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (NULL);
	}

	/*
	 * Determine whether the support library wishes to process this open.
	 * The support library may return:
	 *   .	a different ELF descriptor (in which case they should have
	 *	closed the original)
	 *   .	a different file descriptor (in which case they should have
	 *	closed the original)
	 *   .	a different path and file name (presumably associated with
	 *	a different file descriptor)
	 *
	 * A file descriptor of -1, or and ELF descriptor of zero indicates
	 * the file should be ignored.
	 */
	ld_sup_open(ofl, &npath, &nfile, fd, flags, &elf, NULL, 0,
	    elf_kind(elf));

	if ((*fd == -1) || (elf == NULL))
		return (NULL);

	return (ld_process_ifl(npath, nfile, *fd, elf, flags, ofl, rej));
}

/*
 * Having successfully mapped a file, set up the necessary elf structures to
 * process it further.  This routine is patterned after ld_process_open() and
 * is only called by ld.so.1(1) to process a relocatable object.
 */
Ifl_desc *
ld_process_mem(const char *path, const char *file, char *addr, size_t size,
    Ofl_desc *ofl, Rej_desc *rej)
{
	Elf	*elf;

	if ((elf = elf_memory(addr, size)) == NULL) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_MEMORY), path);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	return (ld_process_ifl(path, file, 0, elf, 0, ofl, rej));
}

/*
 * Process a required library (i.e. the dependency of a shared object).
 * Combine the directory and filename, check the resultant path size, and try
 * opening the pathname.
 */
static Ifl_desc *
process_req_lib(Sdf_desc *sdf, const char *dir, const char *file,
    Ofl_desc *ofl, Rej_desc *rej)
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
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_FIL_PTHTOLONG),
		    _dir, file);
		ofl->ofl_flags |= FLG_OF_FATAL;
		return (0);
	}

	/*
	 * Build the entire pathname and try and open the file.
	 */
	(void) strcpy(path, _dir);
	(void) strcat(path, MSG_ORIG(MSG_STR_SLASH));
	(void) strcat(path, file);
	DBG_CALL(Dbg_libs_req(ofl->ofl_lml, sdf->sdf_name,
	    sdf->sdf_rfile, path));

	if ((fd = open(path, O_RDONLY)) == -1)
		return (0);
	else {
		Ifl_desc	*ifl;
		char		*_path;

		if ((_path = libld_malloc(strlen(path) + 1)) == 0)
			return ((Ifl_desc *)S_ERROR);
		(void) strcpy(_path, path);
		ifl = ld_process_open(_path, &_path[dlen], &fd, ofl, 0, rej);
		if (fd != -1)
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
ld_finish_libs(Ofl_desc *ofl)
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
		char		*path, *slash = NULL;
		int		fd;
		Ifl_desc	*ifl;
		char		*file = (char *)sdf->sdf_name;

		/*
		 * See if this file has already been processed.  At the time
		 * this implicit dependency was determined there may still have
		 * been more explicit dependencies to process.  Note, if we ever
		 * do parse the command line three times we would be able to
		 * do all this checking when processing the dynamic section.
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
		 * If the current path name element embeds a "/", then it's to
		 * be taken "as is", with no searching involved.  Process all
		 * "/" occurrences, so that we can deduce the base file name.
		 */
		for (path = file; *path; path++) {
			if (*path == '/')
				slash = path;
		}
		if (slash) {
			DBG_CALL(Dbg_libs_req(ofl->ofl_lml, sdf->sdf_name,
			    sdf->sdf_rfile, file));
			if ((fd = open(file, O_RDONLY)) == -1) {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_FIL_NOTFOUND), file,
				    sdf->sdf_rfile);
			} else {
				Rej_desc	_rej = { 0 };

				ifl = ld_process_open(file, ++slash, &fd, ofl,
				    0, &_rej);
				if (fd != -1)
					(void) close(fd);
				if (ifl == (Ifl_desc *)S_ERROR)
					return (S_ERROR);

				if (_rej.rej_type) {
					Conv_reject_desc_buf_t rej_buf;

					eprintf(ofl->ofl_lml, ERR_WARNING,
					    MSG_INTL(reject[_rej.rej_type]),
					    _rej.rej_name ? rej.rej_name :
					    MSG_INTL(MSG_STR_UNKNOWN),
					    conv_reject_desc(&_rej, &rej_buf,
					    ld_targ.t_m.m_mach));
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
			DBG_CALL(Dbg_libs_path(ofl->ofl_lml, rpath,
			    LA_SER_RUNPATH, sdf->sdf_rfile));
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
					if ((_rej.rej_type) &&
					    (rej.rej_type == 0)) {
						rej = _rej;
						rej.rej_name =
						    strdup(_rej.rej_name);
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
			Conv_reject_desc_buf_t rej_buf;

			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(reject[rej.rej_type]),
			    rej.rej_name ? rej.rej_name :
			    MSG_INTL(MSG_STR_UNKNOWN),
			    conv_reject_desc(&rej, &rej_buf,
			    ld_targ.t_m.m_mach));
		} else {
			eprintf(ofl->ofl_lml, ERR_WARNING,
			    MSG_INTL(MSG_FIL_NOTFOUND), file, sdf->sdf_rfile);
		}
	}

	/*
	 * Finally, now that all objects have been input, make sure any version
	 * requirements have been met.
	 */
	return (ld_vers_verify(ofl));
}
