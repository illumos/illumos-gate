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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
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

	if ((ifl = libld_calloc(1, sizeof (Ifl_desc))) == NULL)
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
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
			    name);
			return ((Ifl_desc *)S_ERROR);
		}
		if ((shdr0 = elf_getshdr(scn)) == NULL) {
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR),
			    name);
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
	    sizeof (Is_desc *))) == NULL)
		return ((Ifl_desc *)S_ERROR);

	/*
	 * Record this new input file on the shared object or relocatable
	 * object input file list.
	 */
	if (ifl->ifl_ehdr->e_type == ET_DYN) {
		if (aplist_append(&ofl->ofl_sos, ifl, AL_CNT_OFL_LIBS) == NULL)
			return ((Ifl_desc *)S_ERROR);
	} else {
		if (aplist_append(&ofl->ofl_objs, ifl, AL_CNT_OFL_OBJS) == NULL)
			return ((Ifl_desc *)S_ERROR);
	}

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
	if ((isp = libld_calloc(sizeof (Is_desc), 1)) == NULL)
		return (S_ERROR);
	isp->is_shdr = shdr;
	isp->is_file = ifl;
	isp->is_name = name;
	isp->is_scnndx = ndx;
	isp->is_flags = FLG_IS_EXTERNAL;
	isp->is_keyident = ident;

	if ((isp->is_indata = elf_getdata(scn, NULL)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETDATA),
		    ifl->ifl_name);
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
sf1_cap(Ofl_desc *ofl, Xword val, Ifl_desc *ifl, Is_desc *cisp)
{
#define	FP_FLAGS	(SF1_SUNW_FPKNWN | SF1_SUNW_FPUSED)

	Xword	badval;

	/*
	 * If a mapfile has established definitions to override any object
	 * capabilities, ignore any new object capabilities.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_OVSFCAP1) {
		DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_IGNORED,
		    CA_SUNW_SF_1, val, ld_targ.t_m.m_mach));
		return;
	}

#if	!defined(_ELF64)
	if (ifl && (ifl->ifl_ehdr->e_type == ET_REL)) {
		/*
		 * The SF1_SUNW_ADDR32 is only meaningful when building a 64-bit
		 * object.  Warn the user, and remove the setting, if we're
		 * building a 32-bit object.
		 */
		if (val & SF1_SUNW_ADDR32) {
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_FIL_INADDR32SF1), ifl->ifl_name,
			    EC_WORD(cisp->is_scnndx), cisp->is_name);
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
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, EC_WORD(cisp->is_scnndx), cisp->is_name,
		    EC_XWORD(badval));
		val &= SF1_SUNW_MASK;
	}
	if ((val & FP_FLAGS) == SF1_SUNW_FPUSED) {
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_BADSF1),
		    ifl->ifl_name, EC_WORD(cisp->is_scnndx), cisp->is_name,
		    EC_XWORD(val));
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
		    ((ofl->ofl_ocapset.oc_sf_1.cm_val &
		    SF1_SUNW_ADDR32) == 0)) {
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_FIL_EXADDR32SF1), ifl->ifl_name,
			    EC_WORD(cisp->is_scnndx), cisp->is_name);
		}
#endif
		return;
	}

	if (DBG_ENABLED) {
		Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_CURRENT, CA_SUNW_SF_1,
		    ofl->ofl_ocapset.oc_sf_1.cm_val, ld_targ.t_m.m_mach);
		Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_NEW, CA_SUNW_SF_1,
		    val, ld_targ.t_m.m_mach);
	}

	/*
	 * Determine the resolution of the present frame pointer and the
	 * new input relocatable objects frame pointer.
	 */
	if ((ofl->ofl_ocapset.oc_sf_1.cm_val & FP_FLAGS) == FP_FLAGS) {
		/*
		 * If the new relocatable object isn't using a frame pointer,
		 * reduce the present state to unused.
		 */
		if ((val & FP_FLAGS) != FP_FLAGS)
			ofl->ofl_ocapset.oc_sf_1.cm_val &= ~SF1_SUNW_FPUSED;

		/*
		 * Having processed the frame pointer bits, remove them from
		 * the value so they don't get OR'd in below.
		 */
		val &= ~FP_FLAGS;

	} else if ((ofl->ofl_ocapset.oc_sf_1.cm_val & SF1_SUNW_FPKNWN) == 0) {
		/*
		 * If the present frame pointer state is unknown, mask it out
		 * and allow the values from the new relocatable object
		 * to overwrite them.
		 */
		ofl->ofl_ocapset.oc_sf_1.cm_val &= ~FP_FLAGS;
	} else {
		/* Do not take the frame pointer flags from the object */
		val &= ~FP_FLAGS;
	}

	ofl->ofl_ocapset.oc_sf_1.cm_val |= val;

	DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_RESOLVED,
	    CA_SUNW_SF_1, ofl->ofl_ocapset.oc_sf_1.cm_val, ld_targ.t_m.m_mach));

#undef FP_FLAGS
}

/*
 * Determine the hardware capabilities of the object being built from the
 * capabilities of the input relocatable objects.  There's really little to
 * do here, other than to offer diagnostics, hardware capabilities are simply
 * additive.
 */
static void
hw_cap(Ofl_desc *ofl, Xword tag, Xword val)
{
	elfcap_mask_t	*hwcap;
	ofl_flag_t	flags1;

	if (tag == CA_SUNW_HW_1) {
		hwcap = &ofl->ofl_ocapset.oc_hw_1.cm_val;
		flags1 = FLG_OF1_OVHWCAP1;
	} else {
		hwcap = &ofl->ofl_ocapset.oc_hw_2.cm_val;
		flags1 = FLG_OF1_OVHWCAP2;
	}

	/*
	 * If a mapfile has established definitions to override any object
	 * capabilities, ignore any new object capabilities.
	 */
	if (ofl->ofl_flags1 & flags1) {
		DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_IGNORED,
		    tag, val, ld_targ.t_m.m_mach));
		return;
	}

	/*
	 * If this object doesn't specify any capabilities, ignore it, and
	 * leave the state as is.
	 */
	if (val == 0)
		return;

	if (DBG_ENABLED) {
		Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_CURRENT, CA_SUNW_HW_1,
		    ofl->ofl_ocapset.oc_hw_1.cm_val, ld_targ.t_m.m_mach);
		Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_NEW, CA_SUNW_HW_1,
		    val, ld_targ.t_m.m_mach);
	}

	*hwcap |= val;

	DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml, DBG_STATE_RESOLVED, tag,
	    *hwcap, ld_targ.t_m.m_mach));
}

/*
 * Promote a machine capability or platform capability to the output file.
 * Multiple instances of these names can be defined.
 */
static void
str_cap(Ofl_desc *ofl, char *pstr, ofl_flag_t flags, Xword tag, Caplist *list)
{
	Capstr		*capstr;
	Aliste		idx;
	Boolean		found = FALSE;

	/*
	 * If a mapfile has established definitions to override this capability,
	 * ignore any new capability.
	 */
	if (ofl->ofl_flags1 & flags) {
		DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml, DBG_STATE_IGNORED,
		    tag, pstr));
		return;
	}

	for (ALIST_TRAVERSE(list->cl_val, idx, capstr)) {
		DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
		    DBG_STATE_CURRENT, tag, capstr->cs_str));
		if (strcmp(capstr->cs_str, pstr) == 0)
			found = TRUE;
	}

	DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml, DBG_STATE_NEW, tag, pstr));

	if (found == FALSE) {
		if ((capstr = alist_append(&list->cl_val, NULL,
		    sizeof (Capstr), AL_CNT_CAP_NAMES)) == NULL) {
			ofl->ofl_flags |= FLG_OF_FATAL;
			return;
		}
		capstr->cs_str = pstr;
	}

	if (DBG_ENABLED) {
		for (ALIST_TRAVERSE(list->cl_val, idx, capstr)) {
			DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
			    DBG_STATE_RESOLVED, tag, capstr->cs_str));
		}
	}
}

/*
 * Promote a capability identifier to the output file.  A capability group can
 * only have one identifier, and thus only the first identifier seen from any
 * input relocatable objects is retained.  An explicit user defined identifier,
 * rather than an an identifier fabricated by ld(1) with -z symbcap processing,
 * takes precedence.  Note, a user may have defined an identifier via a mapfile,
 * in which case the mapfile identifier is retained.
 */
static void
id_cap(Ofl_desc *ofl, char *pstr, oc_flag_t flags)
{
	Objcapset	*ocapset = &ofl->ofl_ocapset;

	if (ocapset->oc_id.cs_str) {
		DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml, DBG_STATE_CURRENT,
		    CA_SUNW_ID, ocapset->oc_id.cs_str));

		if ((ocapset->oc_flags & FLG_OCS_USRDEFID) ||
		    ((flags & FLG_OCS_USRDEFID) == 0)) {
			DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
			    DBG_STATE_IGNORED, CA_SUNW_ID, pstr));
			return;
		}
	}

	DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml, DBG_STATE_NEW,
	    CA_SUNW_ID, pstr));

	ocapset->oc_id.cs_str = pstr;
	ocapset->oc_flags |= flags;

	DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml, DBG_STATE_RESOLVED,
	    CA_SUNW_ID, pstr));
}

/*
 * Promote a capabilities group to the object capabilities.  This catches a
 * corner case.  An object capabilities file can be converted to symbol
 * capabilities with -z symbolcap.  However, if the user has indicated that all
 * the symbols should be demoted, we'd be left with a symbol capabilities file,
 * with no associated symbols.  Catch this case by promoting the symbol
 * capabilities back to object capabilities.
 */
void
ld_cap_move_symtoobj(Ofl_desc *ofl)
{
	Cap_group	*cgp;
	Aliste		idx1;

	for (APLIST_TRAVERSE(ofl->ofl_capgroups, idx1, cgp)) {
		Objcapset	*scapset = &cgp->cg_set;
		Capstr		*capstr;
		Aliste		idx2;

		if (scapset->oc_id.cs_str) {
			if (scapset->oc_flags & FLG_OCS_USRDEFID)
				id_cap(ofl, scapset->oc_id.cs_str,
				    scapset->oc_flags);
		}
		if (scapset->oc_plat.cl_val) {
			for (ALIST_TRAVERSE(scapset->oc_plat.cl_val, idx2,
			    capstr)) {
				str_cap(ofl, capstr->cs_str, FLG_OF1_OVPLATCAP,
				    CA_SUNW_PLAT, &ofl->ofl_ocapset.oc_plat);
			}
		}
		if (scapset->oc_mach.cl_val) {
			for (ALIST_TRAVERSE(scapset->oc_mach.cl_val, idx2,
			    capstr)) {
				str_cap(ofl, capstr->cs_str, FLG_OF1_OVMACHCAP,
				    CA_SUNW_MACH, &ofl->ofl_ocapset.oc_mach);
			}
		}
		if (scapset->oc_hw_2.cm_val)
			hw_cap(ofl, CA_SUNW_HW_2, scapset->oc_hw_2.cm_val);

		if (scapset->oc_hw_1.cm_val)
			hw_cap(ofl, CA_SUNW_HW_1, scapset->oc_hw_1.cm_val);

		if (scapset->oc_sf_1.cm_val)
			sf1_cap(ofl, scapset->oc_sf_1.cm_val, NULL, NULL);
	}
}

/*
 * Determine whether a capabilities group already exists that describes this
 * new capabilities group.
 *
 * Note, a capability group identifier, CA_SUNW_ID, isn't used as part of the
 * comparison.  This attribute simply assigns a diagnostic name to the group,
 * and in the case of multiple identifiers, the first will be taken.
 */
static Cap_group *
get_cap_group(Objcapset *ocapset, Word cnum, Ofl_desc *ofl, Is_desc *isp)
{
	Aliste		idx;
	Cap_group	*cgp;
	Word		ccnum = cnum;

	/*
	 * If the new capabilities contains a CA_SUNW_ID, drop the count of the
	 * number of comparable items.
	 */
	if (ocapset->oc_id.cs_str)
		ccnum--;

	/*
	 * Traverse the existing symbols capabilities groups.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_capgroups, idx, cgp)) {
		Word	onum = cgp->cg_num;
		Alist	*calp, *oalp;

		if (cgp->cg_set.oc_id.cs_str)
			onum--;

		if (onum != ccnum)
			continue;

		if (cgp->cg_set.oc_hw_1.cm_val != ocapset->oc_hw_1.cm_val)
			continue;
		if (cgp->cg_set.oc_sf_1.cm_val != ocapset->oc_sf_1.cm_val)
			continue;
		if (cgp->cg_set.oc_hw_2.cm_val != ocapset->oc_hw_2.cm_val)
			continue;

		calp = cgp->cg_set.oc_plat.cl_val;
		oalp = ocapset->oc_plat.cl_val;
		if ((calp == NULL) && oalp)
			continue;
		if (calp && ((oalp == NULL) || cap_names_match(calp, oalp)))
			continue;

		calp = cgp->cg_set.oc_mach.cl_val;
		oalp = ocapset->oc_mach.cl_val;
		if ((calp == NULL) && oalp)
			continue;
		if (calp && ((oalp == NULL) || cap_names_match(calp, oalp)))
			continue;

		/*
		 * If a matching group is found, then this new group has
		 * already been supplied by a previous file, and hence the
		 * existing group can be used.  Record this new input section,
		 * from which we can also derive the input file name, on the
		 * existing groups input sections.
		 */
		if (aplist_append(&(cgp->cg_secs), isp,
		    AL_CNT_CAP_SECS) == NULL)
			return (NULL);
		return (cgp);
	}

	/*
	 * If a capabilities group is not found, create a new one.
	 */
	if (((cgp = libld_calloc(sizeof (Cap_group), 1)) == NULL) ||
	    (aplist_append(&(ofl->ofl_capgroups), cgp,
	    AL_CNT_CAP_DESCS) == NULL))
		return (NULL);

	/*
	 * If we're converting object capabilities to symbol capabilities and
	 * no CA_SUNW_ID is defined, fabricate one.  This identifier is appended
	 * to all symbol names that are converted into capabilities symbols,
	 * see ld_sym_process().
	 */
	if ((isp->is_file->ifl_flags & FLG_IF_OTOSCAP) &&
	    (ocapset->oc_id.cs_str == NULL)) {
		size_t	len;

		/*
		 * Create an identifier using the group number together with a
		 * default template.  We allocate a buffer large enough for any
		 * possible number of items (way more than we need).
		 */
		len = MSG_STR_CAPGROUPID_SIZE + CONV_INV_BUFSIZE;
		if ((ocapset->oc_id.cs_str = libld_malloc(len)) == NULL)
			return (NULL);

		(void) snprintf(ocapset->oc_id.cs_str, len,
		    MSG_ORIG(MSG_STR_CAPGROUPID),
		    aplist_nitems(ofl->ofl_capgroups));
		cnum++;
	}

	cgp->cg_set = *ocapset;
	cgp->cg_num = cnum;

	/*
	 * Null the callers alist's as they've effectively been transferred
	 * to this new Cap_group.
	 */
	ocapset->oc_plat.cl_val = ocapset->oc_mach.cl_val = NULL;

	/*
	 * Keep track of which input section, and hence input file, established
	 * this group.
	 */
	if (aplist_append(&(cgp->cg_secs), isp, AL_CNT_CAP_SECS) == NULL)
		return (NULL);

	/*
	 * Keep track of the number of symbol capabilities entries that will be
	 * required in the output file.  Each group requires a terminating
	 * CA_SUNW_NULL.
	 */
	ofl->ofl_capsymcnt += (cnum + 1);
	return (cgp);
}

/*
 * Capture symbol capability family information.  This data structure is focal
 * in maintaining all symbol capability relationships, and provides for the
 * eventual creation of a capabilities information section, and possibly a
 * capabilities chain section.
 *
 * Capabilities families are lead by a CAPINFO_SUNW_GLOB symbol.  This symbol
 * provides the visible global symbol that is referenced by all external
 * callers.  This symbol may have aliases.  For example, a weak/global symbol
 * pair, such as memcpy()/_memcpy() may lead the same capabilities family.
 * Each family contains one or more local symbol members.  These members provide
 * the capabilities specific functions, and are associated to a capabilities
 * group.  For example, the capability members memcpy%sun4u and memcpy%sun4v
 * might be associated with the memcpy() capability family.
 *
 * This routine is called when a relocatable object that provides object
 * capabilities is transformed into a symbol capabilities object, using the
 * -z symbolcap option.
 *
 * This routine is also called to collect the SUNW_capinfo section information
 * of a relocatable object that contains symbol capability definitions.
 */
uintptr_t
ld_cap_add_family(Ofl_desc *ofl, Sym_desc *lsdp, Sym_desc *csdp, Cap_group *cgp,
    APlist **csyms)
{
	Cap_avlnode	qcav, *cav;
	avl_tree_t	*avlt;
	avl_index_t	where = 0;
	Cap_sym		*mcsp;
	Aliste		idx;

	/*
	 * Make sure the capability families have an initialized AVL tree.
	 */
	if ((avlt = ofl->ofl_capfamilies) == NULL) {
		if ((avlt = libld_calloc(sizeof (avl_tree_t), 1)) == NULL)
			return (S_ERROR);
		avl_create(avlt, &ld_sym_avl_comp, sizeof (Cap_avlnode),
		    SGSOFFSETOF(Cap_avlnode, cn_symavlnode.sav_node));
		ofl->ofl_capfamilies = avlt;

		/*
		 * When creating a dynamic object, capability family members
		 * are maintained in a .SUNW_capchain, the first entry of
		 * which is the version number of the chain.
		 */
		ofl->ofl_capchaincnt = 1;
	}

	/*
	 * Determine whether a family already exists, and if not, create one
	 * using the lead family symbol.
	 */
	qcav.cn_symavlnode.sav_hash = (Word)elf_hash(lsdp->sd_name);
	qcav.cn_symavlnode.sav_name = lsdp->sd_name;

	if ((cav = avl_find(avlt, &qcav, &where)) == NULL) {
		if ((cav = libld_calloc(sizeof (Cap_avlnode), 1)) == NULL)
			return (S_ERROR);
		cav->cn_symavlnode.sav_hash = qcav.cn_symavlnode.sav_hash;
		cav->cn_symavlnode.sav_name = qcav.cn_symavlnode.sav_name;
		cav->cn_symavlnode.sav_sdp = lsdp;

		avl_insert(avlt, cav, where);

		/*
		 * When creating a dynamic object, capability family members
		 * are maintained in a .SUNW_capchain, each family starts with
		 * this lead symbol, and is terminated with a 0 element.
		 */
		ofl->ofl_capchaincnt += 2;
	}

	/*
	 * If no group information is provided then this request is to add a
	 * lead capability symbol, or lead symbol alias.  If this is the lead
	 * symbol there's nothing more to do.  Otherwise save the alias.
	 */
	if (cgp == NULL) {
		if ((lsdp != csdp) && (aplist_append(&cav->cn_aliases, csdp,
		    AL_CNT_CAP_ALIASES) == NULL))
			return (S_ERROR);

		return (0);
	}

	/*
	 * Determine whether a member of the same group as this new member is
	 * already defined within this family.  If so, we have a multiply
	 * defined symbol.
	 */
	for (APLIST_TRAVERSE(cav->cn_members, idx, mcsp)) {
		Sym_desc	*msdp;

		if (cgp != mcsp->cs_group)
			continue;

		/*
		 * Diagnose that a multiple symbol definition exists.
		 */
		msdp = mcsp->cs_sdp;

		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_CAP_MULDEF),
		    demangle(lsdp->sd_name));
		ld_eprintf(ofl, ERR_NONE, MSG_INTL(MSG_CAP_MULDEFSYMS),
		    msdp->sd_file->ifl_name, msdp->sd_name,
		    csdp->sd_file->ifl_name, csdp->sd_name);
	}

	/*
	 * Add this capabilities symbol member to the family.
	 */
	if (((mcsp = libld_malloc(sizeof (Cap_sym))) == NULL) ||
	    (aplist_append(&cav->cn_members, mcsp, AL_CNT_CAP_MEMS) == NULL))
		return (S_ERROR);

	mcsp->cs_sdp = csdp;
	mcsp->cs_group = cgp;

	/*
	 * When creating a dynamic object, capability family members are
	 * maintained in a .SUNW_capchain.  Account for this family member.
	 */
	ofl->ofl_capchaincnt++;

	/*
	 * If this input file is undergoing object capabilities to symbol
	 * capabilities conversion, then this member is a new local symbol
	 * that has been generated from an original global symbol.  Keep track
	 * of this symbol so that the output file symbol table can be populated
	 * with these new symbol entries.
	 */
	if (csyms && (aplist_append(csyms, mcsp, AL_CNT_CAP_SYMS) == NULL))
		return (S_ERROR);

	return (0);
}

/*
 * Process a SHT_SUNW_cap capabilities section.
 */
static uintptr_t
process_cap(Ofl_desc *ofl, Ifl_desc *ifl, Is_desc *cisp)
{
	Objcapset	ocapset = { 0 };
	Cap_desc	*cdp;
	Cap		*data, *cdata;
	char		*strs;
	Word		ndx, cnum;
	int		objcapndx, descapndx, symcapndx;
	int		nulls, capstrs = 0;

	/*
	 * Determine the capabilities data and size.
	 */
	cdata = (Cap *)cisp->is_indata->d_buf;
	cnum = (Word)(cisp->is_shdr->sh_size / cisp->is_shdr->sh_entsize);

	if ((cdata == NULL) || (cnum == 0))
		return (0);

	DBG_CALL(Dbg_cap_sec_title(ofl->ofl_lml, ifl->ifl_name));

	/*
	 * Traverse the section to determine what capabilities groups are
	 * available.
	 *
	 * A capabilities section can contain one or more, CA_SUNW_NULL
	 * terminated groups.
	 *
	 *  -	The first group defines the object capabilities.
	 *  -	Additional groups define symbol capabilities.
	 *  -	Since the initial group is always reserved for object
	 *	capabilities, any object with symbol capabilities must also
	 *	have an object capabilities group.  If the object has no object
	 *	capabilities, an empty object group is defined, consisting of a
	 *	CA_SUNW_NULL element in index [0].
	 *  -	If any capabilities require references to a named string, then
	 *	the section header sh_info points to the associated string
	 *	table.
	 *  -	If an object contains symbol capability groups, then the
	 *	section header sh_link points to the associated capinfo table.
	 */
	objcapndx = 0;
	descapndx = symcapndx = -1;
	nulls = 0;

	for (ndx = 0, data = cdata; ndx < cnum; ndx++, data++) {
		switch (data->c_tag) {
		case CA_SUNW_NULL:
			/*
			 * If this is the first CA_SUNW_NULL entry, and no
			 * capabilities group has been found, then this object
			 * does not define any object capabilities.
			 */
			if (nulls++ == 0) {
				if (ndx == 0)
					objcapndx = -1;
			} else if ((symcapndx == -1) && (descapndx != -1))
				symcapndx = descapndx;

			break;

		case CA_SUNW_PLAT:
		case CA_SUNW_MACH:
		case CA_SUNW_ID:
			capstrs++;
			/* FALLTHROUGH */

		case CA_SUNW_HW_1:
		case CA_SUNW_SF_1:
		case CA_SUNW_HW_2:
			/*
			 * If this is the start of a new group, save it.
			 */
			if (descapndx == -1)
				descapndx = ndx;
			break;

		default:
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_UNKCAP),
			    ifl->ifl_name, EC_WORD(cisp->is_scnndx),
			    cisp->is_name, data->c_tag);
		}
	}

	/*
	 * If a string capabilities entry has been found, the capabilities
	 * section must reference the associated string table.
	 */
	if (capstrs) {
		Word	info = cisp->is_shdr->sh_info;

		if ((info == 0) || (info > ifl->ifl_shnum)) {
			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
			    ifl->ifl_name, EC_WORD(cisp->is_scnndx),
			    cisp->is_name, EC_XWORD(info));
			return (S_ERROR);
		}
		strs = (char *)ifl->ifl_isdesc[info]->is_indata->d_buf;
	}

	/*
	 * The processing of capabilities groups is as follows:
	 *
	 *  -	if a relocatable object provides only object capabilities, and
	 *	the -z symbolcap option is in effect, then the object
	 *	capabilities are transformed into symbol capabilities and the
	 *	symbol capabilities are carried over to the output file.
	 *  -	in all other cases, any capabilities present in an input
	 *	relocatable object are carried from the input object to the
	 *	output without any transformation or conversion.
	 *
	 * Capture any object capabilities that are to be carried over to the
	 * output file.
	 */
	if ((objcapndx == 0) &&
	    ((symcapndx != -1) || ((ofl->ofl_flags & FLG_OF_OTOSCAP) == 0))) {
		for (ndx = 0, data = cdata; ndx < cnum; ndx++, data++) {
			/*
			 * Object capabilities end at the first null.
			 */
			if (data->c_tag == CA_SUNW_NULL)
				break;

			/*
			 * Only the object software capabilities that are
			 * defined in a relocatable object become part of the
			 * object software capabilities in the output file.
			 * However, check the validity of any object software
			 * capabilities of any dependencies.
			 */
			if (data->c_tag == CA_SUNW_SF_1) {
				sf1_cap(ofl, data->c_un.c_val, ifl, cisp);
				continue;
			}

			/*
			 * The remaining capability types must come from a
			 * relocatable object in order to contribute to the
			 * output.
			 */
			if (ifl->ifl_ehdr->e_type != ET_REL)
				continue;

			switch (data->c_tag) {
			case CA_SUNW_HW_1:
			case CA_SUNW_HW_2:
				hw_cap(ofl, data->c_tag, data->c_un.c_val);
				break;

			case CA_SUNW_PLAT:
				str_cap(ofl, strs + data->c_un.c_ptr,
				    FLG_OF1_OVPLATCAP, CA_SUNW_PLAT,
				    &ofl->ofl_ocapset.oc_plat);
				break;

			case CA_SUNW_MACH:
				str_cap(ofl, strs + data->c_un.c_ptr,
				    FLG_OF1_OVMACHCAP, CA_SUNW_MACH,
				    &ofl->ofl_ocapset.oc_mach);
				break;

			case CA_SUNW_ID:
				id_cap(ofl, strs + data->c_un.c_ptr,
				    FLG_OCS_USRDEFID);
				break;

			default:
				assert(0);	/* Unknown capability type */
			}
		}

		/*
		 * If there are no symbol capabilities, or this objects
		 * capabilities aren't being transformed into a symbol
		 * capabilities, then we're done.
		 */
		if ((symcapndx == -1) &&
		    ((ofl->ofl_flags & FLG_OF_OTOSCAP) == 0))
			return (1);
	}

	/*
	 * If these capabilities don't originate from a relocatable object
	 * there's no further processing required.
	 */
	if (ifl->ifl_ehdr->e_type != ET_REL)
		return (1);

	/*
	 * If this object only defines an object capabilities group, and the
	 * -z symbolcap option is in effect, then all global function symbols
	 * and initialized global data symbols are renamed and assigned to the
	 * transformed symbol capabilities group.
	 */
	if ((objcapndx == 0) &&
	    (symcapndx == -1) && (ofl->ofl_flags & FLG_OF_OTOSCAP))
		ifl->ifl_flags |= FLG_IF_OTOSCAP;

	/*
	 * Allocate a capabilities descriptor to collect the capabilities data
	 * for this input file.  Allocate a mirror of the raw capabilities data
	 * that points to the individual symbol capabilities groups.  An APlist
	 * is used, although it will be sparsely populated, as the list provides
	 * a convenient mechanism for traversal later.
	 */
	if (((cdp = libld_calloc(sizeof (Cap_desc), 1)) == NULL) ||
	    (aplist_append(&(cdp->ca_groups), NULL, cnum) == NULL))
		return (S_ERROR);

	/*
	 * Clear the allocated APlist data array, and assign the number of
	 * items as the total number of array items.
	 */
	(void) memset(&cdp->ca_groups->apl_data[0], 0,
	    (cnum * sizeof (void *)));
	cdp->ca_groups->apl_nitems = cnum;

	ifl->ifl_caps = cdp;

	/*
	 * Traverse the capabilities data, unpacking the data into a
	 * capabilities set.  Process each capabilities set as a unique group.
	 */
	descapndx = -1;
	nulls = 0;

	for (ndx = 0, data = cdata; ndx < cnum; ndx++, data++) {
		Capstr	*capstr;

		switch (data->c_tag) {
		case CA_SUNW_NULL:
			nulls++;

			/*
			 * Process the capabilities group that this null entry
			 * terminates.  The capabilities group that is returned
			 * will either point to this file's data, or to a
			 * matching capabilities group that has already been
			 * processed.
			 *
			 * Note, if this object defines object capabilities,
			 * the first group descriptor points to these object
			 * capabilities.  It is only necessary to save this
			 * descriptor when object capabilities are being
			 * transformed into symbol capabilities (-z symbolcap).
			 */
			if (descapndx != -1) {
				if ((nulls > 1) ||
				    (ifl->ifl_flags & FLG_IF_OTOSCAP)) {
					APlist	*alp = cdp->ca_groups;

					if ((alp->apl_data[descapndx] =
					    get_cap_group(&ocapset,
					    (ndx - descapndx), ofl,
					    cisp)) == NULL)
						return (S_ERROR);
				}

				/*
				 * Clean up the capabilities data in preparation
				 * for processing additional groups.  If the
				 * collected capabilities strings were used to
				 * establish a new output group, they will have
				 * been saved in get_cap_group().  If these
				 * descriptors still exist, then an existing
				 * descriptor has been used to associate with
				 * this file, and these string descriptors can
				 * be freed.
				 */
				ocapset.oc_hw_1.cm_val =
				    ocapset.oc_sf_1.cm_val =
				    ocapset.oc_hw_2.cm_val = 0;
				if (ocapset.oc_plat.cl_val) {
					free((void *)ocapset.oc_plat.cl_val);
					ocapset.oc_plat.cl_val = NULL;
				}
				if (ocapset.oc_mach.cl_val) {
					free((void *)ocapset.oc_mach.cl_val);
					ocapset.oc_mach.cl_val = NULL;
				}
				descapndx = -1;
			}
			continue;

		case CA_SUNW_HW_1:
			ocapset.oc_hw_1.cm_val = data->c_un.c_val;
			DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_HW_1,
			    ocapset.oc_hw_1.cm_val, ld_targ.t_m.m_mach));
			break;

		case CA_SUNW_SF_1:
			ocapset.oc_sf_1.cm_val = data->c_un.c_val;
			DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_SF_1,
			    ocapset.oc_sf_1.cm_val, ld_targ.t_m.m_mach));
			break;

		case CA_SUNW_HW_2:
			ocapset.oc_hw_2.cm_val = data->c_un.c_val;
			DBG_CALL(Dbg_cap_val_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_HW_2,
			    ocapset.oc_hw_2.cm_val, ld_targ.t_m.m_mach));
			break;

		case CA_SUNW_PLAT:
			if ((capstr = alist_append(&ocapset.oc_plat.cl_val,
			    NULL, sizeof (Capstr), AL_CNT_CAP_NAMES)) == NULL)
				return (S_ERROR);
			capstr->cs_str = strs + data->c_un.c_ptr;
			DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_PLAT, capstr->cs_str));
			break;

		case CA_SUNW_MACH:
			if ((capstr = alist_append(&ocapset.oc_mach.cl_val,
			    NULL, sizeof (Capstr), AL_CNT_CAP_NAMES)) == NULL)
				return (S_ERROR);
			capstr->cs_str = strs + data->c_un.c_ptr;
			DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_MACH, capstr->cs_str));
			break;

		case CA_SUNW_ID:
			ocapset.oc_id.cs_str = strs + data->c_un.c_ptr;
			DBG_CALL(Dbg_cap_ptr_entry(ofl->ofl_lml,
			    DBG_STATE_ORIGINAL, CA_SUNW_ID,
			    ocapset.oc_id.cs_str));
			break;
		}

		/*
		 * Save the start of this new group.
		 */
		if (descapndx == -1)
			descapndx = ndx;
	}
	return (1);
}

/*
 * Capture any symbol capabilities symbols.  An object file that contains symbol
 * capabilities has an associated .SUNW_capinfo section.  This section
 * identifies which symbols are associated to which capabilities, together with
 * their associated lead symbol.  Each of these symbol pairs are recorded for
 * processing later.
 */
static uintptr_t
process_capinfo(Ofl_desc *ofl, Ifl_desc *ifl, Is_desc *isp)
{
	Cap_desc	*cdp = ifl->ifl_caps;
	Capinfo		*capinfo = isp->is_indata->d_buf;
	Shdr		*shdr = isp->is_shdr;
	Word		cndx, capinfonum;

	capinfonum = (Word)(shdr->sh_size / shdr->sh_entsize);

	if ((cdp == NULL) || (capinfo == NULL) || (capinfonum == 0))
		return (0);

	for (cndx = 1, capinfo++; cndx < capinfonum; cndx++, capinfo++) {
		Sym_desc	*sdp, *lsdp;
		Word		lndx;
		uchar_t		gndx;

		if ((gndx = (uchar_t)ELF_C_GROUP(*capinfo)) == 0)
			continue;
		lndx = (Word)ELF_C_SYM(*capinfo);

		/*
		 * Catch any anomalies.  A capabilities symbol should be valid,
		 * and the capabilities lead symbol should also be global.
		 * Note, ld(1) -z symbolcap would create local capabilities
		 * symbols, but we don't enforce this so as to give the
		 * compilation environment a little more freedom.
		 */
		if ((sdp = ifl->ifl_oldndx[cndx]) == NULL) {
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_CAPINFO_INVALSYM), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), isp->is_name, cndx,
			    MSG_INTL(MSG_STR_UNKNOWN));
			continue;
		}
		if ((lndx == 0) || (lndx >= ifl->ifl_symscnt) ||
		    ((lsdp = ifl->ifl_oldndx[lndx]) == NULL) ||
		    (ELF_ST_BIND(lsdp->sd_sym->st_info) != STB_GLOBAL)) {
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_CAPINFO_INVALLEAD), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), isp->is_name, cndx, lsdp ?
			    demangle(lsdp->sd_name) : MSG_INTL(MSG_STR_UNKNOWN),
			    lndx);
			continue;
		}

		/*
		 * Indicate that this is a capabilities symbol.
		 */
		sdp->sd_flags |= FLG_SY_CAP;

		/*
		 * Save any global capability symbols.  Global capability
		 * symbols are identified with a CAPINFO_SUNW_GLOB group id.
		 * The lead symbol for this global capability symbol is either
		 * the symbol itself, or an alias.
		 */
		if (gndx == CAPINFO_SUNW_GLOB) {
			if (ld_cap_add_family(ofl, lsdp, sdp,
			    NULL, NULL) == S_ERROR)
				return (S_ERROR);
			continue;
		}

		/*
		 * Track the number of non-global capabilities symbols, as these
		 * are used to size any symbol tables.  If we're generating a
		 * dynamic object, this symbol will be added to the dynamic
		 * symbol table, therefore ensure there is space in the dynamic
		 * string table.
		 */
		ofl->ofl_caploclcnt++;
		if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) &&
		    (st_insert(ofl->ofl_dynstrtab, sdp->sd_name) == -1))
			return (S_ERROR);

		/*
		 * As we're tracking this local symbol as a capabilities symbol,
		 * reduce the local symbol count to compensate.
		 */
		ofl->ofl_locscnt--;

		/*
		 * Determine whether the associated lead symbol indicates
		 * NODYNSORT.  If so, remove this local entry from the
		 * SUNW_dynsort section too.  NODYNSORT tagging can only be
		 * obtained from a mapfile symbol definition, and thus any
		 * global definition that has this tagging has already been
		 * instantiated and this instance resolved to it.
		 */
		if (lsdp->sd_flags & FLG_SY_NODYNSORT) {
			Sym	*lsym = lsdp->sd_sym;
			uchar_t ltype = ELF_ST_TYPE(lsym->st_info);

			DYNSORT_COUNT(lsdp, lsym, ltype, --);
			lsdp->sd_flags |= FLG_SY_NODYNSORT;
		}

		/*
		 * Track this family member, together with its associated group.
		 */
		if (ld_cap_add_family(ofl, lsdp, sdp,
		    cdp->ca_groups->apl_data[gndx], NULL) == S_ERROR)
			return (S_ERROR);
	}

	return (0);
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
		if (aplist_append(&ifl->ifl_relsect, ifl->ifl_isdesc[ndx],
		    AL_CNT_IFL_RELSECS) == NULL)
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
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_FIL_MALSTR), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), name);
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

	ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_INVALSEC),
	    ifl->ifl_name, EC_WORD(ndx), name,
	    conv_sec_type(ifl->ifl_ehdr->e_ident[EI_OSABI],
	    ifl->ifl_ehdr->e_machine, shdr->sh_type, 0, &inv_buf));
	return (1);
}

/*
 * Compare an input section name to a given string, taking the ELF '%'
 * section naming convention into account. If an input section name
 * contains a '%' character, the '%' and all following characters are
 * ignored in the comparison.
 *
 * entry:
 *	is_name - Name of input section
 *	match_name - Name to compare to
 *	match_len - strlen(match_name)
 *
 * exit:
 *	Returns True (1) if the names match, and False (0) otherwise.
 */
inline static int
is_name_cmp(const char *is_name, const char *match_name, size_t match_len)
{
	/*
	 * If the start of is_name is not a match for name,
	 * the match fails.
	 */
	if (strncmp(is_name, match_name, match_len) != 0)
		return (0);

	/*
	 * The prefix matched. The next character must be either '%', or
	 * NULL, in order for a match to be true.
	 */
	is_name += match_len;
	return ((*is_name == '\0') || (*is_name == '%'));
}

/*
 * Helper routine for process_progbits() to process allocable sections.
 *
 * entry:
 *	name, ifl, shdr, ndx, ident, ofl - As passed to process_progbits().
 *	is_stab_index - TRUE if section is .index.
 *	is_flags - Additional flags to be added to the input section.
 *
 * exit:
 *	The allocable section has been processed. *ident and *is_flags
 *	are updated as necessary to reflect the changes. Returns TRUE
 *	for success, FALSE for failure.
 */
/*ARGSUSED*/
inline static Boolean
process_progbits_alloc(const char *name, Ifl_desc *ifl, Shdr *shdr,
    Word ndx, int *ident, Ofl_desc *ofl, Boolean is_stab_index,
    Word *is_flags)
{
	Boolean done = FALSE;

	if (name[0] == '.') {
		switch (name[1]) {
		case 'e':
			if (!is_name_cmp(name, MSG_ORIG(MSG_SCN_EHFRAME),
			    MSG_SCN_EHFRAME_SIZE))
				break;

			*ident = ld_targ.t_id.id_unwind;
			*is_flags |= FLG_IS_EHFRAME;
			done = TRUE;

			/*
			 * Historically, the section containing the logic to
			 * unwind stack frames -- the .eh_frame section -- was
			 * of type SHT_PROGBITS.  Apparently the most
			 * aesthetically galling aspect of this was not the
			 * .eh_frame section's dubious purpose or its filthy
			 * implementation, but rather its section type; with the
			 * introduction of the AMD64 ABI, a new section header
			 * type (SHT_AMD64_UNWIND) was introduced for (and
			 * dedicated to) this section.  When both the Sun
			 * compilers and the GNU compilers had been modified to
			 * generate this new section type, the linker became
			 * much more pedantic about .eh_frame: it refused to
			 * link an AMD64 object that contained a .eh_frame with
			 * the legacy SHT_PROGBITS.  That this was too fussy is
			 * evidenced by searching the net for the error message
			 * that it generated ("section type is SHT_PROGBITS:
			 * expected SHT_AMD64_UNWIND"), which reveals a myriad
			 * of problems, including legacy objects, hand-coded
			 * assembly and otherwise cross-platform objects
			 * created on other platforms (the GNU toolchain was
			 * only modified to create the new section type on
			 * Solaris and derivatives).  We therefore always accept
			 * a .eh_frame of SHT_PROGBITS -- regardless of
			 * m_sht_unwind.
			 */
			break;
		case 'g':
			if (is_name_cmp(name, MSG_ORIG(MSG_SCN_GOT),
			    MSG_SCN_GOT_SIZE)) {
				*ident = ld_targ.t_id.id_null;
				done = TRUE;
				break;
			}
			if ((ld_targ.t_m.m_sht_unwind == SHT_PROGBITS) &&
			    is_name_cmp(name, MSG_ORIG(MSG_SCN_GCC_X_TBL),
			    MSG_SCN_GCC_X_TBL_SIZE)) {
				*ident = ld_targ.t_id.id_unwind;
				done = TRUE;
				break;
			}
			break;
		case 'p':
			if (is_name_cmp(name, MSG_ORIG(MSG_SCN_PLT),
			    MSG_SCN_PLT_SIZE)) {
				*ident = ld_targ.t_id.id_null;
				done = TRUE;
			}
			break;
		}
	}
	if (!done) {
		if (is_stab_index) {
			/*
			 * This is a work-around for x86 compilers that have
			 * set SHF_ALLOC for the .stab.index section.
			 *
			 * Because of this, make sure that the .stab.index
			 * does not end up as the last section in the text
			 * segment. Older linkers can produce segmentation
			 * violations when they strip (ld -s) against a
			 * shared object whose last section in the text
			 * segment is a .stab.
			 */
			*ident = ld_targ.t_id.id_interp;
		} else {
			*ident = ld_targ.t_id.id_data;
		}
	}

	return (TRUE);
}

/*
 * Process a progbits section.
 */
static uintptr_t
process_progbits(const char *name, Ifl_desc *ifl, Shdr *shdr, Elf_Scn *scn,
    Word ndx, int ident, Ofl_desc *ofl)
{
	Boolean		is_stab_index = FALSE;
	Word		is_flags = 0;
	uintptr_t	r;

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
			is_stab_index = TRUE;
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
	 *
	 * If there are any unwind sections, and this is a platform that uses
	 * SHT_PROGBITS for unwind sections, then set their ident to reflect
	 * that.
	 */
	if (ident) {
		if (shdr->sh_flags & SHF_TLS) {
			ident = ld_targ.t_id.id_tls;
		} else if ((shdr->sh_flags & ~ALL_SHF_IGNORE) ==
		    (SHF_ALLOC | SHF_EXECINSTR)) {
			ident = ld_targ.t_id.id_text;
		} else if (shdr->sh_flags & SHF_ALLOC) {
			if (process_progbits_alloc(name, ifl, shdr, ndx,
			    &ident, ofl, is_stab_index, &is_flags) == FALSE)
				return (S_ERROR);
		} else {
			ident = ld_targ.t_id.id_note;
		}
	}

	r = process_section(name, ifl, shdr, scn, ndx, ident, ofl);

	/*
	 * On success, process_section() creates an input section descriptor.
	 * Now that it exists, we can add any pending input section flags.
	 */
	if ((is_flags != 0) && (r == 1))
		ifl->ifl_isdesc[ndx]->is_flags |= is_flags;

	return (r);
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

		if ((isp == NULL) || ((isp->is_shdr->sh_type != SHT_SYMTAB) &&
		    (isp->is_shdr->sh_type != SHT_DYNSYM))) {
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK), ifl->ifl_name,
			    EC_WORD(ndx), name, EC_XWORD(shdr->sh_link));
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

		if ((isp == NULL) || ((isp->is_shdr->sh_type != SHT_SYMTAB) &&
		    (isp->is_shdr->sh_type != SHT_DYNSYM))) {
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVSHLINK), isc->is_file->ifl_name,
			    EC_WORD(isc->is_scnndx), isc->is_name,
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
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
		    ifl->ifl_name);
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
			if (((difl = libld_calloc(1,
			    sizeof (Ifl_desc))) == NULL) ||
			    (aplist_append(&ofl->ofl_sos, difl,
			    AL_CNT_OFL_LIBS) == NULL))
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
 * $ORIGIN, $MACHINE, $PLATFORM, $OSREL and $OSNAME tokens, either from their
 * needed name, or via a runpath.  In addition runpaths may also specify the
 * $ISALIST token.
 *
 * Probably the most common reference to explicit dependencies (via -L) will be
 * sufficient to find any associated implicit dependencies, but just in case we
 * expand any occurrence of these known tokens here.
 *
 * Note, if any errors occur we simply return the original name.
 *
 * This code is remarkably similar to expand() in rtld/common/paths.c.
 */
static char		*machine = NULL;
static size_t		machine_sz = 0;
static char		*platform = NULL;
static size_t		platform_sz = 0;
static Isa_desc		*isa = NULL;
static Uts_desc		*uts = NULL;

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
			if ((eptr = strrchr(parent, '/')) == NULL) {
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

		} else if (strncmp(optr, MSG_ORIG(MSG_STR_MACHINE),
		    MSG_STR_MACHINE_SIZE) == 0) {
			/*
			 * Establish the machine from sysconf - like uname -i.
			 */
			if ((machine == NULL) && (machine_sz == 0)) {
				char	info[SYS_NMLN];
				long	size;

				size = sysinfo(SI_MACHINE, info, SYS_NMLN);
				if ((size != -1) &&
				    (machine = libld_malloc((size_t)size))) {
					(void) strcpy(machine, info);
					machine_sz = (size_t)size - 1;
				} else
					machine_sz = 1;
			}
			if (machine) {
				if (machine_sz >= nrem)
					return ((char *)name);

				(void) strncpy(nptr, machine, machine_sz);
				nptr = nptr + machine_sz;
				nrem -= machine_sz;

				optr += MSG_STR_MACHINE_SIZE;
				expanded = _expanded = 1;
			}

		} else if (strncmp(optr, MSG_ORIG(MSG_STR_PLATFORM),
		    MSG_STR_PLATFORM_SIZE) == 0) {
			/*
			 * Establish the platform from sysconf - like uname -i.
			 */
			if ((platform == NULL) && (platform_sz == 0)) {
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
			if (platform) {
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
			if (uts == NULL)
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
			if (uts == NULL)
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
			if (isa == NULL)
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
				if ((_next = lptr = libld_malloc(mlen)) == NULL)
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
		if ((nptr = libld_malloc(strlen(_name) + 1)) == NULL)
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
	Boolean		no_undef;

	data = (Dyn *)isc->is_indata->d_buf;
	str = (char *)ifl->ifl_isdesc[isc->is_shdr->sh_link]->is_indata->d_buf;

	/* Determine if we need to examine the runpaths and NEEDED entries */
	no_undef = (ofl->ofl_flags & (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)) ||
	    OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS);

	/*
	 * First loop through the dynamic section looking for a run path.
	 */
	if (no_undef) {
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
			Sdf_desc	*sdf;

			if (!no_undef)
				continue;
			if ((needed = str + (size_t)dyn->d_un.d_val) == NULL)
				continue;

			/*
			 * Determine if this needed entry is already recorded on
			 * the shared object needed list, if not create a new
			 * definition for later processing (see finish_libs()).
			 */
			needed = expand(ifl->ifl_name, needed, NULL);

			if ((sdf = sdf_find(needed, ofl->ofl_soneed)) == NULL) {
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
			if (rpath && (sdf->sdf_rpath == NULL))
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

			/*
			 * If we are building an executable, and this
			 * dependency is tagged as an interposer, then
			 * assume that it is required even if symbol
			 * resolution uncovers no evident use.
			 *
			 * If we are building a shared object, then an
			 * interposer dependency has no special meaning, and we
			 * treat it as a regular dependency. By definition, all
			 * interposers must be visible to the runtime linker
			 * at initialization time, and cannot be added later.
			 */
			if ((dyn->d_un.d_val & DF_1_INTERPOSE) &&
			    (ofl->ofl_flags & FLG_OF_EXEC))
				ifl->ifl_flags |= FLG_IF_DEPREQD;

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
			 * If this dependency has the DT_SUNW_RTLDINF .dynamic
			 * entry, then ensure no specialized dependency
			 * processing is in effect.  This tag identifies libc,
			 * which provides critical startup information (TLS
			 * routines, threads initialization, etc.) that must
			 * be exercised as part of process initialization.
			 */
			ifl->ifl_flags &= ~MSK_IF_POSFLAG1;

			/*
			 * libc is not subject to the usual guidance checks
			 * for lazy loading. It cannot be lazy loaded, libld
			 * ignores the request, and rtld would ignore the
			 * setting if it were present.
			 */
			ifl->ifl_flags |= FLG_IF_RTLDINF;
		}
	}

	/*
	 * Perform some SONAME sanity checks.
	 */
	if (ifl->ifl_flags & FLG_IF_NEEDED) {
		Ifl_desc	*sifl;
		Aliste		idx;

		/*
		 * Determine if anyone else will cause the same SONAME to be
		 * used (this is either caused by two different files having the
		 * same SONAME, or by one file SONAME actually matching another
		 * file basename (if no SONAME is specified within a shared
		 * library its basename will be used)). Probably rare, but some
		 * idiot will do it.
		 */
		for (APLIST_TRAVERSE(ofl->ofl_sos, idx, sifl)) {
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

				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_REC_OBJCNFLT), sifl->ifl_name,
				    ifl->ifl_name, sifl->ifl_soname, hint);
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
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_REC_OPTCNFLT), ifl->ifl_name,
			    MSG_INTL(MSG_MARG_SONAME), ifl->ifl_soname);
			return (0);
		}
	}
	return (1);
}

/*
 * Process a progbits section from a relocatable object (ET_REL).
 * This is used on non-amd64 objects to recognize .eh_frame sections.
 */
/*ARGSUSED1*/
static uintptr_t
process_progbits_final(Is_desc *isc, Ifl_desc *ifl, Ofl_desc *ofl)
{
	if (isc->is_osdesc && (isc->is_flags & FLG_IS_EHFRAME) &&
	    (ld_unwind_register(isc->is_osdesc, ofl) == S_ERROR))
		return (S_ERROR);

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
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVALSEC),
		    ifl->ifl_name, EC_WORD(isc->is_scnndx), isc->is_name,
		    conv_sec_type(ifl->ifl_ehdr->e_ident[EI_OSABI],
		    ifl->ifl_ehdr->e_machine, shdr->sh_type, 0, &inv_buf));
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
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_INVSHINFO),
		    ifl->ifl_name, EC_WORD(isc->is_scnndx), isc->is_name,
		    EC_XWORD(rndx));
		return (0);
	}
	if (rndx == 0) {
		if (aplist_append(&ofl->ofl_extrarels, isc,
		    AL_CNT_OFL_RELS) == NULL)
			return (S_ERROR);

	} else if ((risc = ifl->ifl_isdesc[rndx]) != NULL) {
		/*
		 * Discard relocations if they are against a section
		 * which has been discarded.
		 */
		if (risc->is_flags & FLG_IS_DISCARD)
			return (1);

		if ((osp = risc->is_osdesc) == NULL) {
			if (risc->is_shdr->sh_type == SHT_SUNW_move) {
				/*
				 * This section is processed later in
				 * process_movereloc().
				 */
				if (aplist_append(&ofl->ofl_ismoverel,
				    isc, AL_CNT_OFL_MOVE) == NULL)
					return (S_ERROR);
				return (1);
			}
			ld_eprintf(ofl, ERR_FATAL,
			    MSG_INTL(MSG_FIL_INVRELOC1), ifl->ifl_name,
			    EC_WORD(isc->is_scnndx), isc->is_name,
			    EC_WORD(risc->is_scnndx), risc->is_name);
			return (0);
		}
		if (aplist_append(&osp->os_relisdescs, isc,
		    AL_CNT_OS_RELISDESCS) == NULL)
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
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_FIL_EXCLUDE),
		    ifl->ifl_name, EC_WORD(ndx), name);
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
typedef uintptr_t	(* initial_func_t)(const char *, Ifl_desc *, Shdr *,
			    Elf_Scn *, Word, int, Ofl_desc *);

static initial_func_t Initial[SHT_NUM][2] = {
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

typedef uintptr_t	(* final_func_t)(Is_desc *, Ifl_desc *, Ofl_desc *);

static final_func_t Final[SHT_NUM][2] = {
/*			ET_REL			ET_DYN			*/

/* SHT_NULL	*/	NULL,			NULL,
/* SHT_PROGBITS	*/	process_progbits_final,	NULL,
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
	char		*str, *name;
	Word		row, column;
	int		ident;
	uintptr_t	error;
	Is_desc		*vdfisp, *vndisp, *vsyisp, *sifisp;
	Is_desc		*capinfoisp, *capisp;
	Sdf_desc	*sdf;
	Place_path_info	path_info_buf, *path_info;

	/*
	 * Path information buffer used by ld_place_section() and related
	 * routines. This information is used to evaluate entrance criteria
	 * with non-empty file matching lists (ec_files).
	 */
	path_info = ld_place_path_info_init(ofl, ifl, &path_info_buf);

	/*
	 * First process the .shstrtab section so that later sections can
	 * reference their name.
	 */
	ld_sup_file(ofl, ifl->ifl_name, elf_kind(elf), ifl->ifl_flags, elf);

	sndx = ifl->ifl_shstrndx;
	if ((scn = elf_getscn(elf, (size_t)sndx)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSCN),
		    ifl->ifl_name);
		return (0);
	}
	if ((shdr = elf_getshdr(scn)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR),
		    ifl->ifl_name);
		return (0);
	}
	if ((name = elf_strptr(elf, (size_t)sndx, (size_t)shdr->sh_name)) ==
	    NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_STRPTR),
		    ifl->ifl_name);
		return (0);
	}

	if (ld_sup_input_section(ofl, ifl, name, &shdr, sndx, scn,
	    elf) == S_ERROR)
		return (S_ERROR);

	/*
	 * Reset the name since the shdr->sh_name could have been changed as
	 * part of ld_sup_input_section().
	 */
	if ((name = elf_strptr(elf, (size_t)sndx, (size_t)shdr->sh_name)) ==
	    NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_STRPTR),
		    ifl->ifl_name);
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
	vdfisp = vndisp = vsyisp = sifisp = capinfoisp = capisp = NULL;
	scn = NULL;
	while (scn = elf_nextscn(elf, scn)) {
		ndx++;

		/*
		 * As we've already processed the .shstrtab don't do it again.
		 */
		if (ndx == sndx)
			continue;

		if ((shdr = elf_getshdr(scn)) == NULL) {
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETSHDR),
			    ifl->ifl_name);
			return (0);
		}
		name = str + (size_t)(shdr->sh_name);

		if (ld_sup_input_section(ofl, ifl, name, &shdr, ndx, scn,
		    elf) == S_ERROR)
			return (S_ERROR);

		/*
		 * Reset the name since the shdr->sh_name could have been
		 * changed as part of ld_sup_input_section().
		 */
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

				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_FIL_INVALSEC), ifl->ifl_name,
				    EC_WORD(ndx), name, conv_sec_type(
				    ifl->ifl_ehdr->e_ident[EI_OSABI],
				    ifl->ifl_ehdr->e_machine,
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
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				capisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_capinfo:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				capinfoisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_DEBUGSTR:
			case SHT_SUNW_DEBUG:
				if (process_debug(name, ifl, shdr, scn,
				    ndx, ident, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_move:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				break;
			case SHT_SUNW_syminfo:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
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
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				vdfisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_verneed:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
					return (S_ERROR);
				vndisp = ifl->ifl_isdesc[ndx];
				break;
			case SHT_SUNW_versym:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_null, ofl) == S_ERROR)
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
				if (process_section(name, ifl, shdr, scn, ndx,
				    ld_targ.t_id.id_gotdata, ofl) == S_ERROR)
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
					ifl->ifl_isdesc[ndx]->is_flags |=
					    FLG_IS_EHFRAME;
				}
				break;
#endif
			default:
			do_default:
				if (process_section(name, ifl, shdr, scn, ndx,
				    ((ident == ld_targ.t_id.id_null) ?
				    ident : ld_targ.t_id.id_user), ofl) ==
				    S_ERROR)
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
	 * Now that all of the input sections have been processed, place
	 * them in the appropriate output sections.
	 */
	for (ndx = 1; ndx < ifl->ifl_shnum; ndx++) {
		Is_desc	*isp;

		if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
		    ((isp->is_flags & FLG_IS_PLACE) == 0))
			continue;

		/*
		 * Place all non-ordered sections within their appropriate
		 * output section.
		 */
		if ((isp->is_flags & FLG_IS_ORDERED) == 0) {
			if (ld_place_section(ofl, isp, path_info,
			    isp->is_keyident, NULL) == (Os_desc *)S_ERROR)
				return (S_ERROR);
			continue;
		}

		/*
		 * Count the number of ordered sections and retain the first
		 * ordered section index. This will be used to optimize the
		 * ordered section loop that immediately follows this one.
		 */
		ordcnt++;
		if (ordndx == 0)
			ordndx = ndx;
	}

	/*
	 * Having placed all the non-ordered sections, it is now
	 * safe to place SHF_ORDERED/SHF_LINK_ORDER sections.
	 */
	if (ifl->ifl_flags & FLG_IF_ORDERED) {
		for (ndx = ordndx; ndx < ifl->ifl_shnum; ndx++) {
			Is_desc	*isp;

			if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
			    ((isp->is_flags &
			    (FLG_IS_PLACE | FLG_IS_ORDERED)) !=
			    (FLG_IS_PLACE | FLG_IS_ORDERED)))
				continue;

			/* ld_process_ordered() calls ld_place_section() */
			if (ld_process_ordered(ofl, ifl, path_info, ndx) ==
			    S_ERROR)
				return (S_ERROR);

			/* If we've done them all, stop searching */
			if (--ordcnt == 0)
				break;
		}
	}

	/*
	 * If this is a shared object explicitly specified on the command
	 * line (as opposed to being a dependency of such an object),
	 * determine if the user has specified a control definition. This
	 * descriptor may specify which version definitions can be used
	 * from this object. It may also update the dependency to USED and
	 * supply an alternative SONAME.
	 */
	sdf = NULL;
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

		if ((sdf = sdf_find(base, ofl->ofl_socntl)) != NULL) {
			sdf->sdf_file = ifl;
			ifl->ifl_sdfdesc = sdf;
		}
	}

	/*
	 * Before symbol processing, process any capabilities.  Capabilities
	 * can reference a string table, which is why this processing is
	 * carried out after the initial section processing.  Capabilities,
	 * together with -z symbolcap, can require the conversion of global
	 * symbols to local symbols.
	 */
	if (capisp && (process_cap(ofl, ifl, capisp) == S_ERROR))
		return (S_ERROR);

	/*
	 * Process any version dependencies.  These will establish shared object
	 * `needed' entries in the same manner as will be generated from the
	 * .dynamic's NEEDED entries.
	 */
	if (vndisp && ((ofl->ofl_flags & (FLG_OF_NOUNDEF | FLG_OF_SYMBOLIC)) ||
	    OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS)))
		if (ld_vers_need_process(vndisp, ifl, ofl) == S_ERROR)
			return (S_ERROR);

	/*
	 * Before processing any symbol resolution or relocations process any
	 * version sections.
	 */
	if (vsyisp)
		(void) ld_vers_sym_process(ofl, vsyisp, ifl);

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

		if ((isp = ifl->ifl_isdesc[ndx]) == NULL)
			continue;
		row = isp->is_shdr->sh_type;

		if ((isp->is_flags & FLG_IS_DISCARD) == 0)
			ld_sup_section(ofl, isp->is_name, isp->is_shdr, ndx,
			    isp->is_indata, elf);

		/*
		 * If this is a SHT_SUNW_move section from a relocatable file,
		 * keep track of the section for later processing.
		 */
		if ((row == SHT_SUNW_move) && (column == 0)) {
			if (aplist_append(&(ofl->ofl_ismove), isp,
			    AL_CNT_OFL_MOVE) == NULL)
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
			    (ld_unwind_register(osp, ofl) == S_ERROR))
				return (S_ERROR);
#endif
		}
	}

	/*
	 * Following symbol processing, if this relocatable object input file
	 * provides symbol capabilities, tag the associated symbols so that
	 * the symbols can be re-assigned to the new capabilities symbol
	 * section that will be created for the output file.
	 */
	if (capinfoisp && (ifl->ifl_ehdr->e_type == ET_REL) &&
	    (process_capinfo(ofl, ifl, capinfoisp) == S_ERROR))
		return (S_ERROR);

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
 *  -	files explicitly defined on the command line (ie. foo.o or bar.so),
 *	in this case only the `name' field is valid.
 *
 *  -	libraries determined from the -l command line option (ie. -lbar),
 *	in this case the `soname' field contains the basename of the located
 *	file.
 *
 * Any shared object specified via the above two conventions must be recorded
 * as a needed dependency.
 *
 *  -	libraries specified as dependencies of those libraries already obtained
 *	via the command line (ie. bar.so has a DT_NEEDED entry of fred.so.1),
 *	in this case the `soname' field contains either a full pathname (if the
 *	needed entry contained a `/'), or the basename of the located file.
 *	These libraries are processed to verify symbol binding but are not
 *	recorded as dependencies of the output file being generated.
 *
 * entry:
 *	name - File name
 *	soname - SONAME for needed sharable library, as described above
 *	fd - Open file descriptor
 *	elf - Open ELF handle
 *	flags - FLG_IF_ flags applicable to file
 *	ofl - Output file descriptor
 *	rej - Rejection descriptor used to record rejection reason
 *	ifl_ret - NULL, or address of pointer to receive reference to
 *		resulting input descriptor for file. If ifl_ret is non-NULL,
 *		the file cannot be an archive or it will be rejected.
 *
 * exit:
 *	If a error occurs in examining the file, S_ERROR is returned.
 *	If the file can be examined, but is not suitable, *rej is updated,
 *	and 0 is returned. If the file is acceptable, 1 is returned, and if
 *	ifl_ret is non-NULL, *ifl_ret is set to contain the pointer to the
 *	resulting input descriptor.
 */
uintptr_t
ld_process_ifl(const char *name, const char *soname, int fd, Elf *elf,
    Word flags, Ofl_desc *ofl, Rej_desc *rej, Ifl_desc **ifl_ret)
{
	Ifl_desc	*ifl;
	Ehdr		*ehdr;
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
		 * If the caller has supplied a non-NULL ifl_ret, then
		 * we cannot process archives, for there will be no
		 * input file descriptor for us to return. In this case,
		 * reject the attempt.
		 */
		if (ifl_ret != NULL) {
			_rej.rej_type = SGS_REJ_ARCHIVE;
			_rej.rej_name = name;
			DBG_CALL(Dbg_file_rejected(ofl->ofl_lml, &_rej,
			    ld_targ.t_m.m_mach));
			if (rej->rej_type == 0) {
				*rej = _rej;
				rej->rej_name = strdup(_rej.rej_name);
			}
			return (0);
		}

		/*
		 * Determine if we've already come across this archive file.
		 */
		if (!(flags & FLG_IF_EXTRACT)) {
			Aliste	idx;

			for (APLIST_TRAVERSE(ofl->ofl_ars, idx, adp)) {
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
				if (!ld_process_archive(name, -1, adp, ofl))
					return (S_ERROR);
				return (1);
			}
		}

		/*
		 * As we haven't processed this file before establish a new
		 * archive descriptor.
		 */
		adp = ld_ar_setup(name, elf, ofl);
		if ((adp == NULL) || (adp == (Ar_desc *)S_ERROR))
			return ((uintptr_t)adp);
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
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_CNTL),
			    name);
			return (0);
		}

		if (!ld_process_archive(name, -1, adp, ofl))
			return (S_ERROR);
		return (1);

	case ELF_K_ELF:
		/*
		 * Obtain the elf header so that we can determine what type of
		 * elf ELF_K_ELF file this is.
		 */
		if ((ehdr = elf_getehdr(elf)) == NULL) {
			int	_class = gelf_getclass(elf);

			/*
			 * This can fail for a number of reasons. Typically
			 * the object class is incorrect (ie. user is building
			 * 64-bit but managed to point at 32-bit libraries).
			 * Other ELF errors can include a truncated or corrupt
			 * file. Try to get the best error message possible.
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
			return (0);
		}

		/*
		 * Determine if we've already come across this file.
		 */
		if (!(flags & FLG_IF_EXTRACT)) {
			APlist	*apl;
			Aliste	idx;

			if (ehdr->e_type == ET_REL)
				apl = ofl->ofl_objs;
			else
				apl = ofl->ofl_sos;

			/*
			 * Traverse the appropriate file list and determine if
			 * a dev/inode match is found.
			 */
			for (APLIST_TRAVERSE(apl, idx, ifl)) {
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
					ld_eprintf(ofl, ERR_WARNING,
					    errmsg, name, ifl->ifl_name);
				}
				if (ifl_ret)
					*ifl_ret = ifl;
				return (1);
			}
		}

		/*
		 * At this point, we know we need the file.  Establish an input
		 * file descriptor and continue processing.
		 */
		ifl = ifl_setup(name, ehdr, elf, flags, ofl, rej);
		if ((ifl == NULL) || (ifl == (Ifl_desc *)S_ERROR))
			return ((uintptr_t)ifl);
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
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_FIL_SOINSTAT), name);
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
			 * If direct bindings, lazy loading, group permissions,
			 * or deferred dependencies need to be established, mark
			 * this object.
			 */
			if (ofl->ofl_flags1 & FLG_OF1_ZDIRECT)
				ifl->ifl_flags |= FLG_IF_DIRECT;
			if (ofl->ofl_flags1 & FLG_OF1_LAZYLD)
				ifl->ifl_flags |= FLG_IF_LAZYLD;
			if (ofl->ofl_flags1 & FLG_OF1_GRPPRM)
				ifl->ifl_flags |= FLG_IF_GRPPRM;
			if (ofl->ofl_flags1 & FLG_OF1_DEFERRED)
				ifl->ifl_flags |=
				    (FLG_IF_LAZYLD | FLG_IF_DEFERRED);

			error = process_elf(ifl, elf, ofl);

			/*
			 * Determine whether this dependency requires a syminfo.
			 */
			if (ifl->ifl_flags & MSK_IF_SYMINFO)
				ofl->ofl_flags |= FLG_OF_SYMINFO;

			/*
			 * Guidance: Use -z lazyload/nolazyload.
			 * libc is exempt from this advice, because it cannot
			 * be lazy loaded, and requests to do so are ignored.
			 */
			if (OFL_GUIDANCE(ofl, FLG_OFG_NO_LAZY) &&
			    ((ifl->ifl_flags & FLG_IF_RTLDINF) == 0)) {
				ld_eprintf(ofl, ERR_GUIDANCE,
				    MSG_INTL(MSG_GUIDE_LAZYLOAD));
				ofl->ofl_guideflags |= FLG_OFG_NO_LAZY;
			}

			/*
			 * Guidance: Use -B direct/nodirect or
			 * -z direct/nodirect.
			 */
			if (OFL_GUIDANCE(ofl, FLG_OFG_NO_DB)) {
				ld_eprintf(ofl, ERR_GUIDANCE,
				    MSG_INTL(MSG_GUIDE_DIRECT));
				ofl->ofl_guideflags |= FLG_OFG_NO_DB;
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
			return (0);
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
		return (0);
	}
	if ((error == 0) || (error == S_ERROR))
		return (error);

	if (ifl_ret)
		*ifl_ret = ifl;
	return (1);
}

/*
 * Having successfully opened a file, set up the necessary elf structures to
 * process it further.  This small section of processing is slightly different
 * from the elf initialization required to process a relocatable object from an
 * archive (see libs.c: ld_process_archive()).
 */
uintptr_t
ld_process_open(const char *opath, const char *ofile, int *fd, Ofl_desc *ofl,
    Word flags, Rej_desc *rej, Ifl_desc **ifl_ret)
{
	Elf		*elf;
	const char	*npath = opath;
	const char	*nfile = ofile;

	if ((elf = elf_begin(*fd, ELF_C_READ, NULL)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_BEGIN), npath);
		return (0);
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
		return (0);

	return (ld_process_ifl(npath, nfile, *fd, elf, flags, ofl, rej,
	    ifl_ret));
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
	Elf		*elf;
	uintptr_t	open_ret;
	Ifl_desc	*ifl;

	if ((elf = elf_memory(addr, size)) == NULL) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_MEMORY), path);
		return (0);
	}

	open_ret = ld_process_ifl(path, file, 0, elf, 0, ofl, rej, &ifl);
	if (open_ret != 1)
		return ((Ifl_desc *) open_ret);
	return (ifl);
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
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_FIL_PTHTOLONG),
		    _dir, file);
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
		uintptr_t	open_ret;
		Ifl_desc	*ifl;
		char		*_path;

		if ((_path = libld_malloc(strlen(path) + 1)) == NULL)
			return ((Ifl_desc *)S_ERROR);
		(void) strcpy(_path, path);
		open_ret = ld_process_open(_path, &_path[dlen], &fd, ofl,
		    0, rej, &ifl);
		if (fd != -1)
			(void) close(fd);
		if (open_ret != 1)
			return ((Ifl_desc *)open_ret);
		return (ifl);
	}
}

/*
 * Finish any library processing.  Walk the list of so's that have been listed
 * as "included" by shared objects we have previously processed.  Examine them,
 * without adding them as explicit dependents of this program, in order to
 * complete our symbol definition process.  The search path rules are:
 *
 *  -	use any user supplied paths, i.e. LD_LIBRARY_PATH and -L, then
 *
 *  -	use any RPATH defined within the parent shared object, then
 *
 *  -	use the default directories, i.e. LIBPATH or -YP.
 */
uintptr_t
ld_finish_libs(Ofl_desc *ofl)
{
	Aliste		idx1;
	Sdf_desc	*sdf;
	Rej_desc	rej = { 0 };

	/*
	 * Make sure we are back in dynamic mode.
	 */
	ofl->ofl_flags |= FLG_OF_DYNLIBS;

	for (APLIST_TRAVERSE(ofl->ofl_soneed, idx1, sdf)) {
		Aliste		idx2;
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

		for (APLIST_TRAVERSE(ofl->ofl_sos, idx2, ifl)) {
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
				ld_eprintf(ofl, ERR_WARNING,
				    MSG_INTL(MSG_FIL_NOTFOUND), file,
				    sdf->sdf_rfile);
			} else {
				uintptr_t	open_ret;
				Rej_desc	_rej = { 0 };

				open_ret = ld_process_open(file, ++slash,
				    &fd, ofl, 0, &_rej, &ifl);
				if (fd != -1)
					(void) close(fd);
				if (open_ret == S_ERROR)
					return (S_ERROR);

				if (_rej.rej_type) {
					Conv_reject_desc_buf_t rej_buf;

					ld_eprintf(ofl, ERR_WARNING,
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
		for (APLIST_TRAVERSE(ofl->ofl_ulibdirs, idx2, path)) {
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
			if (rpath == NULL)
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
		for (APLIST_TRAVERSE(ofl->ofl_dlibdirs, idx2, path)) {
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

			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(reject[rej.rej_type]),
			    rej.rej_name ? rej.rej_name :
			    MSG_INTL(MSG_STR_UNKNOWN),
			    conv_reject_desc(&rej, &rej_buf,
			    ld_targ.t_m.m_mach));
		} else {
			ld_eprintf(ofl, ERR_WARNING,
			    MSG_INTL(MSG_FIL_NOTFOUND), file, sdf->sdf_rfile);
		}
	}

	/*
	 * Finally, now that all objects have been input, make sure any version
	 * requirements have been met.
	 */
	return (ld_vers_verify(ofl));
}
