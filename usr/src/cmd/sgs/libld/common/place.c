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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * Map file parsing and input section to output segment mapping.
 */
#include	<stdio.h>
#include	<string.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Each time a section is placed, the function set_addralign()
 * is called.  This function performs:
 *
 * -	if the section is from an external file, check if this is empty or not.
 *	If not, we know the segment this section will belong needs a program
 *	header. (Of course, the program is needed only if this section falls
 *	into a loadable segment.)
 * -	compute the Least Common Multiplier for setting the segment alignment.
 */
static void
set_addralign(Ofl_desc *ofl, Os_desc *osp, Is_desc *isp)
{
	Shdr	*shdr = isp->is_shdr;

	/* A discarded section has no influence on the output */
	if (isp->is_flags & FLG_IS_DISCARD)
		return;

	/*
	 * If this section has data or will be assigned data
	 * later, mark this segment not-empty.
	 */
	if ((shdr->sh_size != 0) ||
	    ((isp->is_flags & FLG_IS_EXTERNAL) == 0))
		osp->os_sgdesc->sg_flags |= FLG_SG_PHREQ;

	if ((ofl->ofl_dtflags_1 & DF_1_NOHDR) &&
	    (osp->os_sgdesc->sg_phdr).p_type != PT_LOAD)
		return;

	osp->os_sgdesc->sg_align =
	    ld_lcm(osp->os_sgdesc->sg_align, shdr->sh_addralign);
}

/*
 * Return the first input descriptor for a given output descriptor,
 * or NULL if there are none.
 */

Is_desc *
ld_os_first_isdesc(Os_desc *osp)
{
	int i;

	for (i = 0; i < OS_ISD_NUM; i++) {
		APlist *ap_isdesc = osp->os_isdescs[i];

		if (aplist_nitems(ap_isdesc) > 0)
			return ((Is_desc *)ap_isdesc->apl_data[0]);
	}

	return (NULL);
}

/*
 * Attach an input section to an output section
 *
 * entry:
 *	ofl - File descriptor
 *	osp - Output section descriptor
 *	isp - Input section descriptor
 *	mapfile_sort - True (1) if segment supports mapfile specified ordering
 *		of otherwise unordered input sections, and False (0) otherwise.
 *
 * exit:
 *	- The input section has been attached to the output section
 *	- If the input section is a candidate for string table merging,
 *		then it is appended to the output section's list of merge
 *		candidates (os_mstridescs).
 *
 *	On success, returns True (1). On failure, False (0).
 */
static int
os_attach_isp(Ofl_desc *ofl, Os_desc *osp, Is_desc *isp, int mapfile_sort)
{
	Aliste	init_arritems;
	int	os_isdescs_idx, do_append = 1;

	if ((isp->is_flags & FLG_IS_ORDERED) == 0) {
		init_arritems = AL_CNT_OS_ISDESCS;
		os_isdescs_idx = OS_ISD_DEFAULT;

		/*
		 * If section ordering was specified for an unordered section
		 * via the mapfile, then search in the OS_ISD_DEFAULT list
		 * and insert it in the specified position. Ordered sections
		 * are placed in ascending order before unordered sections
		 * (sections with an is_ordndx value of zero).
		 *
		 * If no mapfile ordering was specified, we append it in
		 * the usual way below.
		 */
		if (mapfile_sort && (isp->is_ordndx > 0)) {
			APlist *ap_isdesc = osp->os_isdescs[OS_ISD_DEFAULT];
			Aliste	idx2;
			Is_desc	*isp2;

			for (APLIST_TRAVERSE(ap_isdesc, idx2, isp2)) {
				if (isp2->is_ordndx &&
				    (isp2->is_ordndx <= isp->is_ordndx))
						continue;

				if (aplist_insert(
				    &osp->os_isdescs[OS_ISD_DEFAULT],
				    isp, init_arritems, idx2) == NULL)
					return (0);
				do_append = 0;
				break;
			}
		}
	} else {		/* Ordered section (via shdr flags) */
		Word shndx;

		/* SHF_ORDERED uses sh_info, SHF_LINK_ORDERED uses sh_link */
		shndx = (isp->is_shdr->sh_flags & SHF_ORDERED) ?
		    isp->is_shdr->sh_info : isp->is_shdr->sh_link;

		if (shndx == SHN_BEFORE) {
			init_arritems = AL_CNT_OS_ISDESCS_BA;
			os_isdescs_idx = OS_ISD_BEFORE;
		} else if (shndx == SHN_AFTER) {
			init_arritems = AL_CNT_OS_ISDESCS_BA;
			os_isdescs_idx = OS_ISD_AFTER;
		} else {
			init_arritems = AL_CNT_OS_ISDESCS;
			os_isdescs_idx = OS_ISD_ORDERED;
		}
	}

	/*
	 * If we didn't insert a section into the default list using
	 * mapfile specified ordering above, then append the input
	 * section to the appropriate list.
	 */
	if (do_append && aplist_append(&(osp->os_isdescs[os_isdescs_idx]),
	    isp, init_arritems) == NULL)
		return (0);
	isp->is_osdesc = osp;

	/*
	 * A section can be merged if the following are true:
	 * -	The SHF_MERGE|SHF_STRINGS flags must be set
	 * -	String table compression must not be disabled (-znocompstrtab)
	 * -	Mapfile ordering must not have been used.
	 * -	The section must not be ordered via section header flags.
	 * -	It must not be the generated section being built to
	 *	replace the sections on this list.
	 */
	if (((isp->is_shdr->sh_flags & (SHF_MERGE | SHF_STRINGS)) !=
	    (SHF_MERGE | SHF_STRINGS)) ||
	    ((ofl->ofl_flags1 & FLG_OF1_NCSTTAB) != 0) ||
	    !do_append ||
	    ((isp->is_flags & (FLG_IS_ORDERED | FLG_IS_GNSTRMRG)) != 0))
		return (1);

	/*
	 * Skip sections with (sh_entsize > 1) or (sh_addralign > 1).
	 *
	 * sh_entsize:
	 *	We are currently only able to merge string tables containing
	 *	strings with 1-byte (char) characters. Support for wide
	 *	characters will require our string table compression code
	 *	to be extended to handle larger character sizes.
	 *
	 * sh_addralign:
	 *	Alignments greater than 1 would require our string table
	 *	compression code to insert null bytes to move each
	 *	string to the required alignment.
	 */
	if ((isp->is_shdr->sh_entsize > 1) ||
	    (isp->is_shdr->sh_addralign > 1)) {
		DBG_CALL(Dbg_sec_unsup_strmerge(ofl->ofl_lml, isp));
		return (1);
	}

	if (aplist_append(&osp->os_mstrisdescs, isp,
	    AL_CNT_OS_MSTRISDESCS) == NULL)
		return (0);

	/*
	 * The SHF_MERGE|SHF_STRINGS flags tell us that the program that
	 * created the section intended it to be mergeable. The
	 * FLG_IS_INSTRMRG flag says that we have done validity testing
	 * and decided that it is safe to act on that hint.
	 */
	isp->is_flags |= FLG_IS_INSTRMRG;

	return (1);
}

/*
 * Determine whether this input COMDAT section already exists for the associated
 * output section.  If so, then discard this input section.  Otherwise, this
 * must be the first COMDAT section, thus it is kept for future comparisons.
 */
static uintptr_t
add_comdat(Ofl_desc *ofl, Os_desc *osp, Is_desc *isp)
{
	Isd_node	isd, *isdp;
	avl_tree_t	*avlt;
	avl_index_t	where;
	Group_desc	*gr;

	/*
	 * Sections to which COMDAT groups apply are FLG_IS_COMDAT but are
	 * discarded separately by the group logic so should never be
	 * discarded here.
	 */
	if ((isp->is_shdr->sh_flags & SHF_GROUP) &&
	    ((gr = ld_get_group(ofl, isp)) != NULL) &&
	    (gr->gd_data[0] & GRP_COMDAT))
		return (1);

	/*
	 * Create a COMDAT avl tree for this output section if required.
	 */
	if ((avlt = osp->os_comdats) == NULL) {
		if ((avlt = libld_calloc(sizeof (avl_tree_t), 1)) == NULL)
			return (S_ERROR);
		avl_create(avlt, isdavl_compare, sizeof (Isd_node),
		    SGSOFFSETOF(Isd_node, isd_avl));
		osp->os_comdats = avlt;
	}

	/*
	 * A standard COMDAT section uses the section name as search key.
	 */
	isd.isd_name = isp->is_name;
	isd.isd_hash = sgs_str_hash(isd.isd_name);

	if ((isdp = avl_find(avlt, &isd, &where)) != NULL) {
		isp->is_osdesc = osp;

		/*
		 * If this section hasn't already been identified as discarded,
		 * generate a suitable diagnostic.
		 */
		if ((isp->is_flags & FLG_IS_DISCARD) == 0) {
			isp->is_flags |= FLG_IS_DISCARD;
			isp->is_comdatkeep = isdp->isd_isp;
			DBG_CALL(Dbg_sec_discarded(ofl->ofl_lml, isp,
			    isdp->isd_isp));
		}

		/*
		 * A discarded section does not require assignment to an output
		 * section.  However, if relaxed relocations have been enabled
		 * (either from -z relaxreloc, or asserted with .gnu.linkonce
		 * processing), then this section must still be assigned to an
		 * output section so that the sloppy relocation logic will have
		 * the information necessary to do its work.
		 */
		return (0);
	}

	/*
	 * This is a new COMDAT section - so keep it.
	 */
	if ((isdp = libld_calloc(sizeof (Isd_node), 1)) == NULL)
		return (S_ERROR);

	isdp->isd_name = isd.isd_name;
	isdp->isd_hash = isd.isd_hash;
	isdp->isd_isp = isp;

	avl_insert(avlt, isdp, where);
	return (1);
}

/*
 * Determine whether a GNU group COMDAT section name follows the convention
 *
 *	section-name.symbol-name
 *
 * Each section within the input file is compared to see if the full section
 * name matches the beginning of the COMDAT section, with a following '.'.
 * A pointer to the symbol name, starting with the '.' is returned so that the
 * caller can strip off the required section name.
 */
static char *
gnu_comdat_sym(Ifl_desc *ifl, Is_desc *gisp)
{
	size_t	ndx;

	for (ndx = 1; ndx < ifl->ifl_shnum; ndx++) {
		Is_desc	*isp;
		size_t	ssize;

		if (((isp = ifl->ifl_isdesc[ndx]) == NULL) ||
		    (isp == gisp) || (isp->is_name == NULL))
			continue;

		/*
		 * It's questionable whether this size should be cached in the
		 * Is_desc.  However, this seems an infrequent operation and
		 * adding Is_desc members can escalate memory usage for large
		 * link-edits.  For now, size the section name dynamically.
		 */
		ssize = strlen(isp->is_name);
		if ((strncmp(isp->is_name, gisp->is_name, ssize) == 0) &&
		    (gisp->is_name[ssize] == '.'))
			return ((char *)&gisp->is_name[ssize]);
	}
	return (NULL);
}

/*
 * GNU .gnu.linkonce sections follow a naming convention that indicates the
 * required association with an output section.  Determine whether this input
 * section follows the convention, and if so return the appropriate output
 * section name.
 *
 *	.gnu.linkonce.b.*    ->	.bss
 *	.gnu.linkonce.d.*    ->	.data
 *	.gnu.linkonce.l.*    ->	.ldata
 *	.gnu.linkonce.lb.*   ->	.lbss
 *	.gnu.linkonce.lr.*   ->	.lrodata
 *	.gnu.linkonce.r.*    ->	.rodata
 *	.gnu.linkonce.s.*    ->	.sdata
 *	.gnu.linkonce.s2.*   ->	.sdata2
 *	.gnu.linkonce.sb.*   ->	.sbss
 *	.gnu.linkonce.sb2.*  ->	.sbss2
 *	.gnu.linkonce.t.*    ->	.text
 *	.gnu.linkonce.tb.*   ->	.tbss
 *	.gnu.linkonce.td.*   ->	.tdata
 *	.gnu.linkonce.wi.*   ->	.debug_info
 */
#define	NSTR_CH1(ch) (*(nstr + 1) == (ch))
#define	NSTR_CH2(ch) (*(nstr + 2) == (ch))
#define	NSTR_CH3(ch) (*(nstr + 3) == (ch))

static const char *
gnu_linkonce_sec(const char *ostr)
{
	const char	*nstr = &ostr[MSG_SCN_GNU_LINKONCE_SIZE];

	switch (*nstr) {
	case 'b':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_BSS));
		break;
	case 'd':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_DATA));
		break;
	case 'l':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_LDATA));
		else if (NSTR_CH1('b') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_LBSS));
		else if (NSTR_CH1('r') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_LRODATA));
		break;
	case 'r':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_RODATA));
		break;
	case 's':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_SDATA));
		else if (NSTR_CH1('2') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_SDATA2));
		else if (NSTR_CH1('b') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_SBSS));
		else if (NSTR_CH1('b') && NSTR_CH2('2') && NSTR_CH3('.'))
			return (MSG_ORIG(MSG_SCN_SBSS2));
		break;
	case 't':
		if (NSTR_CH1('.'))
			return (MSG_ORIG(MSG_SCN_TEXT));
		else if (NSTR_CH1('b') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_TBSS));
		else if (NSTR_CH1('d') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_TDATA));
		break;
	case 'w':
		if (NSTR_CH1('i') && NSTR_CH2('.'))
			return (MSG_ORIG(MSG_SCN_DEBUG_INFO));
		break;
	default:
		break;
	}

	/*
	 * No special name match found.
	 */
	return (ostr);
}
#undef	NSTR_CH1
#undef	NSTR_CH2
#undef	NSTR_CH3

/*
 * The GNU link-editor maps sections generated by the GNU compiler separately
 * due to -ffunction-sections, -fdata-sections or for other reasons into the
 * "normal" section represented.
 *
 * Sections are named .<main>.<symbol> where <main> is the usual section to
 * which it should be mapped, and <symbol> is providing the unique name for
 * the original section.  Both parts of the name may contain periods, in cases
 * where the unique part of the name contains a '.' and/or the section it
 * contributes to does (such as .data.rel.ro)
 *
 * .rodata.str* and .rodata.cst* are mapped to .rodata.
 *
 * As a further complication, the GNU link-editor may or may not merge
 * .ctors.* and .dtors.* into init_array and fini_array, rather than ctors and
 * dtors.  We do not implement this at this time.
 *
 * The GNU link editor may also arrange for sections with .local in their name
 * to be mapped as above, but grouped together.  We do not implement this (and
 * do not merge them at all, to make this clear)
 *
 * This table is processed in order.  Longer mappings must come first.
 */
static struct split_sec_mapping {
	char *leader;
	char *section;
	boolean_t precise;
} split_sec_mapping[] = {
	{ ".bss.",			".bss",			B_FALSE },
	{ ".ctors.",			".ctors",		B_FALSE },
	{ ".data.rel.local.",		".data.rel.local",	B_FALSE },
	{ ".data.rel.local",		".data.rel.local",	B_TRUE },
	{ ".data.rel.ro.local.",	".data.rel.ro",		B_FALSE },
	{ ".data.rel.ro.",		".data.rel.ro",		B_FALSE },
	{ ".data.rel.ro",		".data.rel.ro",		B_TRUE },
	{ ".data.rel.",			".data.rel",		B_FALSE },
	{ ".data.rel",			".data.rel",		B_TRUE },
	{ ".data.",			".data",		B_FALSE },
	{ ".dtors.",			".dtors",		B_FALSE },
	{ ".fini_array.",		".fini_array",		B_FALSE },
	{ ".init_array.",		".init_array",		B_FALSE },
	{ ".lbss.",			".lbss",		B_FALSE },
	{ ".ldata.",			".ldata",		B_FALSE },
	{ ".lrodata.",			".lrodata",		B_FALSE },
	/* This intentionally applies to .rodata.cstN and .rodata.strN, too */
	{ ".rodata.",			".rodata",		B_FALSE },
	{ ".sbss2.",			".sbss2",		B_FALSE },
	{ ".sbss.",			".sbss",		B_FALSE },
	{ ".sdata2.",			".sdata2",		B_FALSE },
	{ ".sdata.",			".sdata",		B_FALSE },
	{ ".tbss.",			".tbss",		B_FALSE },
	{ ".tdata.",			".tdata",		B_FALSE },
	{ ".text.",			".text",		B_FALSE },
	{ NULL,				NULL,			B_FALSE }
};

static const char *
gnu_split_sec(const char *ostr)
{
	struct split_sec_mapping *mp;

	for (mp = split_sec_mapping; mp->leader != NULL; mp++) {
		if (mp->precise) {
			if (strcmp(ostr, mp->leader) == 0)
				return (mp->section);
		} else if (strncmp(ostr, mp->leader, strlen(mp->leader)) == 0) {
			return (mp->section);
		}
	}

	return (ostr);
}

/*
 * Initialize a path info buffer for use with ld_place_section().
 *
 * entry:
 *	ofl - Output descriptor
 *	ifl - Descriptor for input file, or NULL if there is none.
 *	info - Address of buffer to be initialized.
 *
 * exit:
 *	If this is an input file, and if the entrance criteria list
 *	contains at least one criteria that has a non-empty file string
 *	match list (ec_files), then the block pointed at by info is
 *	initialized, and info is returned.
 *
 *	If there is no input file, and/or no entrance criteria containing
 *	a non-empty ec_files list, then NULL is returned. This is not
 *	an error --- the NULL is simply an optimization, understood by
 *	ld_place_path(), that allows it to skip unnecessary work.
 */
Place_path_info *
ld_place_path_info_init(Ofl_desc *ofl, Ifl_desc *ifl, Place_path_info *info)
{
	/*
	 * Return NULL if there is no input file (internally generated section)
	 * or if the entrance criteria list does not contain any items that will
	 * need to be compared to the path (all the ec_files lists are empty).
	 */
	if ((ifl == NULL) || !(ofl->ofl_flags & FLG_OF_EC_FILES))
		return (NULL);

	info->ppi_path = ifl->ifl_name;
	info->ppi_path_len = strlen(info->ppi_path);
	info->ppi_isar = (ifl->ifl_flags & FLG_IF_EXTRACT) != 0;

	/*
	 * The basename is the final segment of the path, equivalent to
	 * the path itself if there are no '/' delimiters.
	 */
	info->ppi_bname = strrchr(info->ppi_path, '/');
	if (info->ppi_bname == NULL)
		info->ppi_bname = info->ppi_path;
	else
		info->ppi_bname++;	/* Skip leading '/' */
	info->ppi_bname_len =
	    info->ppi_path_len - (info->ppi_bname - info->ppi_path);

	/*
	 * For an archive, the object name is the member name, which is
	 * enclosed in () at the end of the name string. Otherwise, it is
	 * the same as the basename.
	 */
	if (info->ppi_isar) {
		info->ppi_oname = strrchr(info->ppi_bname, '(');
		/* There must be an archive member suffix delimited by parens */
		assert((info->ppi_bname[info->ppi_bname_len - 1] == ')') &&
		    (info->ppi_oname != NULL));
		info->ppi_oname++;	/* skip leading '(' */
		info->ppi_oname_len = info->ppi_bname_len -
		    (info->ppi_oname - info->ppi_bname + 1);
	} else {
		info->ppi_oname = info->ppi_bname;
		info->ppi_oname_len = info->ppi_bname_len;
	}

	return (info);
}

/*
 * Compare an input section path to the file comparison list the given
 * entrance criteria.
 *
 * entry:
 *	path_info - A non-NULL Place_path_info block for the file
 *		containing the input section, initialized by
 *		ld_place_path_info_init()
 *	enp - Entrance criteria with a non-empty ec_files list of file
 *		comparisons to be carried out.
 *
 * exit:
 *	Return TRUE if a match is seen, and FALSE otherwise.
 */
static Boolean
eval_ec_files(Place_path_info *path_info, Ent_desc *enp)
{
	Aliste		idx;
	Ent_desc_file	*edfp;
	size_t		cmp_len;
	const char	*cmp_str;

	for (ALIST_TRAVERSE(enp->ec_files, idx, edfp)) {
		Word	type = edfp->edf_flags & TYP_ECF_MASK;

		/*
		 * Determine the starting character, and # of characters,
		 * from the file path to compare against this entrance criteria
		 * file string.
		 */
		if (type == TYP_ECF_OBJNAME) {
			cmp_str = path_info->ppi_oname;
			cmp_len = path_info->ppi_oname_len;
		} else {
			int ar_stat_diff = path_info->ppi_isar !=
			    ((edfp->edf_flags & FLG_ECF_ARMEMBER) != 0);

			/*
			 * If the entrance criteria specifies an archive member
			 * and the file does not, then there can be no match.
			 */

			if (ar_stat_diff && !path_info->ppi_isar)
				continue;

			if (type == TYP_ECF_PATH) {
				cmp_str = path_info->ppi_path;
				cmp_len = path_info->ppi_path_len;
			} else {	/* TYP_ECF_BASENAME */
				cmp_str = path_info->ppi_bname;
				cmp_len = path_info->ppi_bname_len;
			}

			/*
			 * If the entrance criteria does not specify an archive
			 * member and the file does, then a match just requires
			 * the paths (without the archive member) to match.
			 * Reduce the length to not include the ar member or
			 * the '(' that precedes it.
			 */
			if (ar_stat_diff && path_info->ppi_isar)
				cmp_len = path_info->ppi_oname - cmp_str - 1;
		}

		/*
		 * Compare the resulting string to the one from the
		 * entrance criteria.
		 */
		if ((cmp_len == edfp->edf_name_len) &&
		    (strncmp(edfp->edf_name, cmp_str, cmp_len) == 0))
			return (TRUE);
	}

	return (FALSE);
}

/*
 * Replace the section header for the given input section with a new section
 * header of the specified type. All values in the replacement header other
 * than the type retain their previous values.
 *
 * entry:
 *	isp - Input section to replace
 *	sh_type - New section type to apply
 *
 * exit:
 *	Returns the pointer to the new section header on success, and
 *	NULL for failure.
 */
static Shdr *
isp_convert_type(Is_desc *isp, Word sh_type)
{
	Shdr	*shdr;

	if ((shdr = libld_malloc(sizeof (Shdr))) == NULL)
		return (NULL);
	*shdr = *isp->is_shdr;
	isp->is_shdr = shdr;
	shdr->sh_type = sh_type;
	return (shdr);
}

/*
 * Issue a fatal warning for the given .eh_frame section, which
 * cannot be merged with the existing .eh_frame output section.
 */
static void
eh_frame_muldef(Ofl_desc *ofl, Is_desc *isp)
{
	Sg_desc	*sgp;
	Is_desc *isp1;
	Os_desc	*osp;
	Aliste	idx1, idx2, idx3;

	/*
	 * Locate the .eh_frame output section, and use the first section
	 * assigned to it in the error message. The user can then compare
	 * the two sections to determine what attribute prevented the merge.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
			if ((osp->os_flags & FLG_OS_EHFRAME) == 0)
				continue;

			for (idx3 = 0; idx3 < OS_ISD_NUM; idx3++) {
				APlist *lst = osp->os_isdescs[idx3];

				if (aplist_nitems(lst) == 0)
					continue;

				isp1 = lst->apl_data[0];
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_UPD_MULEHFRAME),
				    isp1->is_file->ifl_name,
				    EC_WORD(isp1->is_scnndx), isp1->is_name,
				    isp->is_file->ifl_name,
				    EC_WORD(isp->is_scnndx), isp->is_name);
				return;
			}
		}
	}
}

/*
 * Place a section into the appropriate segment and output section.
 *
 * entry:
 *	ofl - File descriptor
 *	isp - Input section descriptor of section to be placed.
 *	path_info - NULL, or pointer to Place_path_info buffer initialized
 *		by ld_place_path_info_init() for the file associated to isp,
 *		for use in processing entrance criteria with non-empty
 *		file matching string list (ec_files)
 *	ident - Section identifier, used to order sections relative to
 *		others within the output segment.
 *	alt_os_name - If non-NULL, the name of the output section to place
 *		isp into. If NULL, input sections go to an output section
 *		with the same name as the input section.
 */
Os_desc *
ld_place_section(Ofl_desc *ofl, Is_desc *isp, Place_path_info *path_info,
    int ident, const char *alt_os_name)
{
	Ent_desc	*enp;
	Sg_desc		*sgp;
	Os_desc		*osp;
	Aliste		idx1, iidx;
	int		os_ndx;
	Shdr		*shdr = isp->is_shdr;
	Xword		shflagmask, shflags = shdr->sh_flags;
	Ifl_desc	*ifl = isp->is_file;
	char		*oname, *sname;
	uint_t		onamehash;
	Boolean		is_ehframe = (isp->is_flags & FLG_IS_EHFRAME) != 0;

	/*
	 * Define any sections that must be thought of as referenced.  These
	 * sections may not be referenced externally in a manner ld(1) can
	 * discover, but they must be retained (ie. not removed by -zignore).
	 */
	static const Msg RefSecs[] = {
		MSG_SCN_INIT,		/* MSG_ORIG(MSG_SCN_INIT) */
		MSG_SCN_FINI,		/* MSG_ORIG(MSG_SCN_FINI) */
		MSG_SCN_EX_RANGES,	/* MSG_ORIG(MSG_SCN_EX_RANGES) */
		MSG_SCN_EX_SHARED,	/* MSG_ORIG(MSG_SCN_EX_SHARED) */
		MSG_SCN_CTORS,		/* MSG_ORIG(MSG_SCN_CTORS) */
		MSG_SCN_DTORS,		/* MSG_ORIG(MSG_SCN_DTORS) */
		MSG_SCN_EHFRAME,	/* MSG_ORIG(MSG_SCN_EHFRAME) */
		MSG_SCN_EHFRAME_HDR,	/* MSG_ORIG(MSG_SCN_EHFRAME_HDR) */
		MSG_SCN_JCR,		/* MSG_ORIG(MSG_SCN_JCR) */
		0
	};

	DBG_CALL(Dbg_sec_in(ofl->ofl_lml, isp));

	/*
	 * If this section identifies group members, or this section indicates
	 * that it is a member of a group, determine whether the section is
	 * still required.
	 */
	if ((shflags & SHF_GROUP) || (shdr->sh_type == SHT_GROUP)) {
		Group_desc	*gdesc;

		if ((gdesc = ld_get_group(ofl, isp)) != NULL) {
			DBG_CALL(Dbg_sec_group(ofl->ofl_lml, isp, gdesc));

			/*
			 * If this group has been replaced by another group,
			 * then this section needs to be discarded.
			 */
			if (gdesc->gd_oisc) {
				isp->is_flags |= FLG_IS_DISCARD;

				/*
				 * Since we're discarding the section, we
				 * can skip assigning it to an output section.
				 * The exception is that if the user
				 * specifies -z relaxreloc, then
				 * we need to assign the output section so
				 * that the sloppy relocation logic will have
				 * the information necessary to do its work.
				 */
				if (!(ofl->ofl_flags1 & FLG_OF1_RLXREL))
					return (NULL);
			}
		}

		/*
		 * SHT_GROUP sections can only be included into relocatable
		 * objects.
		 */
		if (shdr->sh_type == SHT_GROUP) {
			if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) {
				isp->is_flags |= FLG_IS_DISCARD;
				return (NULL);
			}
		}
	}

	/*
	 * Always assign SHF_TLS sections to the DATA segment (and then the
	 * PT_TLS embedded inside of there).
	 */
	if (shflags & SHF_TLS)
		shflags |= SHF_WRITE;

	/*
	 * Traverse the entrance criteria list searching for a segment that
	 * matches the input section we have.  If an entrance criterion is set
	 * then there must be an exact match.  If we complete the loop without
	 * finding a segment, then sgp will be NULL.
	 */
	sgp = NULL;
	for (APLIST_TRAVERSE(ofl->ofl_ents, idx1, enp)) {

		/* Disabled segments are not available for assignment */
		if (enp->ec_segment->sg_flags & FLG_SG_DISABLED)
			continue;

		/*
		 * If an entrance criteria doesn't have any of its fields
		 * set, it will match any section it is tested against.
		 * We set the FLG_EC_CATCHALL flag on these, primarily because
		 * it helps readers of our debug output to understand what
		 * the criteria means --- otherwise the user would just see
		 * that every field is 0, but might not understand the
		 * significance of that.
		 *
		 * Given that we set this flag, we can use it here as an
		 * optimization to short circuit all of the tests in this
		 * loop. Note however, that if we did not do this, the end
		 * result would be the same --- the empty criteria will sail
		 * past the following tests and reach the end of the loop.
		 */
		if (enp->ec_flags & FLG_EC_CATCHALL) {
			sgp = enp->ec_segment;
			break;
		}

		if (enp->ec_type && (enp->ec_type != shdr->sh_type))
			continue;
		if (enp->ec_attrmask &&
		    /* LINTED */
		    (enp->ec_attrmask & enp->ec_attrbits) !=
		    (enp->ec_attrmask & shflags))
			continue;
		if (enp->ec_is_name &&
		    (strcmp(enp->ec_is_name, isp->is_name) != 0))
			continue;

		if ((alist_nitems(enp->ec_files) > 0) &&
		    ((path_info == NULL) || !eval_ec_files(path_info, enp)))
			continue;

		/* All entrance criteria tests passed */
		sgp = enp->ec_segment;
		break;
	}

	/*
	 * The final entrance criteria record is a FLG_EC_CATCHALL that points
	 * at the final predefined segment "extra", and this final segment is
	 * tagged FLG_SG_NODISABLE. Therefore, the above loop must always find
	 * a segment.
	 */
	assert(sgp != NULL);

	/*
	 * Transfer the input section sorting key from the entrance criteria
	 * to the input section. A non-zero value means that the section
	 * will be sorted on this key amoung the other sections that have a
	 * non-zero key. These sorted sections are collectively placed at the
	 * head of the output section.
	 *
	 * If the sort key is 0, the section is placed after the sorted
	 * sections in the order they are encountered.
	 */
	isp->is_ordndx = enp->ec_ordndx;

	/* Remember that this entrance criteria has placed a section */
	enp->ec_flags |= FLG_EC_USED;

	/*
	 * If our caller has supplied an alternative name for the output
	 * section, then we defer to their request. Otherwise, the default
	 * is to use the same name as that of the input section being placed.
	 *
	 * The COMDAT, SHT_GROUP and GNU name translations that follow have
	 * the potential to alter this initial name.
	 */
	oname = (char *)((alt_os_name == NULL) ? isp->is_name : alt_os_name);

	/*
	 * Solaris section names may follow the convention:
	 *
	 *	section-name%symbol-name
	 *
	 * This convention has been used to order the layout of sections within
	 * segments for objects built with the compilers -xF option.  However,
	 * the final object should not contain individual section headers for
	 * all such input sections, instead the symbol name is stripped from the
	 * name to establish the final output section name.
	 *
	 * This convention has also been followed for COMDAT and sections
	 * identified though SHT_GROUP data.
	 *
	 * Strip out the % from the section name for:
	 *	- Non-relocatable objects
	 *	- Relocatable objects if input section sorting is
	 *	  in force for the segment in question.
	 */
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) ||
	    (sgp->sg_flags & FLG_SG_IS_ORDER)) {
		if ((sname = strchr(isp->is_name, '%')) != NULL) {
			size_t	size = sname - isp->is_name;

			if ((oname = libld_malloc(size + 1)) == NULL)
				return ((Os_desc *)S_ERROR);
			(void) strncpy(oname, isp->is_name, size);
			oname[size] = '\0';
			DBG_CALL(Dbg_sec_redirected(ofl->ofl_lml, isp, oname));
		}
	}

	/*
	 * When building relocatable objects, we must not redirect COMDAT
	 * section names into their outputs, such that our output object may
	 * be successfully used as an input object also requiring COMDAT
	 * processing
	 */

	/*
	 * GNU section names may follow the convention:
	 *
	 *	.gnu.linkonce.*
	 *
	 * The .gnu.linkonce is a section naming convention that indicates a
	 * COMDAT requirement.  Determine whether this section follows the GNU
	 * pattern, and if so, determine whether this section should be
	 * discarded or retained.  The comparison of is_name[1] with 'g'
	 * is an optimization to skip using strncmp() too much. This is safe,
	 * because we know the name is not NULL, and therefore must have
	 * at least one character plus a NULL termination.
	 */
	if ((isp->is_name == oname) && (isp->is_name[1] == 'g') &&
	    (strncmp(MSG_ORIG(MSG_SCN_GNU_LINKONCE), isp->is_name,
	    MSG_SCN_GNU_LINKONCE_SIZE) == 0)) {
		if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) {
			if ((oname = (char *)gnu_linkonce_sec(isp->is_name)) !=
			    isp->is_name) {
				DBG_CALL(Dbg_sec_redirected(ofl->ofl_lml, isp,
				    oname));
			}
		}

		/*
		 * Explicitly identify this section type as COMDAT.  Also,
		 * enable relaxed relocation processing, as this is typically
		 * a requirement with .gnu.linkonce sections.
		 */
		isp->is_flags |= FLG_IS_COMDAT;
		if ((ofl->ofl_flags1 & FLG_OF1_NRLXREL) == 0)
			ofl->ofl_flags1 |= FLG_OF1_RLXREL;
		DBG_CALL(Dbg_sec_gnu_comdat(ofl->ofl_lml, isp, TRUE,
		    (ofl->ofl_flags1 & FLG_OF1_RLXREL) != 0));
	}

	/*
	 * GNU section names may also follow the convention:
	 *
	 *	section-name.symbol-name
	 *
	 * This convention is used when defining SHT_GROUP sections of type
	 * COMDAT.  Thus, any group processing will have discovered any group
	 * sections, and this identification can be triggered by a pattern
	 * match section names.
	 */
	if ((isp->is_name == oname) && (isp->is_flags & FLG_IS_COMDAT) &&
	    ((sname = gnu_comdat_sym(ifl, isp)) != NULL)) {
		size_t	size = sname - isp->is_name;

		if ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) {
			if ((oname = libld_malloc(size + 1)) == NULL)
				return ((Os_desc *)S_ERROR);
			(void) strncpy(oname, isp->is_name, size);
			oname[size] = '\0';
			DBG_CALL(Dbg_sec_redirected(ofl->ofl_lml, isp, oname));
		}

		/*
		 * Enable relaxed relocation processing, as this is
		 * typically a requirement with GNU COMDAT sections.
		 */
		if ((ofl->ofl_flags1 & FLG_OF1_NRLXREL) == 0) {
			ofl->ofl_flags1 |= FLG_OF1_RLXREL;
			DBG_CALL(Dbg_sec_gnu_comdat(ofl->ofl_lml, isp,
			    FALSE, TRUE));
		}
	}

	/*
	 * GNU section names named section-name.symbol-name which are not
	 * members of COMDAT groups are merged according to the behaviour of
	 * the GNU link-editor.
	 *
	 * See the description of gnu_split_sec().
	 */
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) &&
	    (isp->is_name == oname) &&
	    ((oname = (char *)gnu_split_sec(oname)) != isp->is_name)) {
		DBG_CALL(Dbg_sec_redirected(ofl->ofl_lml, isp, oname));
	}

	/*
	 * Assign a hash value now that the output section name has been
	 * finalized.
	 */
	onamehash = sgs_str_hash(oname);

	/*
	 * Determine if output section ordering is turned on. If so, return
	 * the appropriate ordering index for the section. This information
	 * is derived from the Sg_desc->sg_os_order list that was built
	 * up from the Mapfile.
	 *
	 * A value of 0 for os_ndx means that the section is not sorted
	 * (i.e. is not found in the sg_os_order). The items in sg_os_order
	 * are in the desired sort order, so adding 1 to their alist index
	 * gives a suitable index for sorting.
	 */
	os_ndx = 0;
	if (alist_nitems(sgp->sg_os_order) > 0) {
		Sec_order	*scop;

		for (ALIST_TRAVERSE(sgp->sg_os_order, idx1, scop)) {
			if (strcmp(scop->sco_secname, oname) == 0) {
				scop->sco_flags |= FLG_SGO_USED;
				os_ndx = idx1 + 1;
				break;
			}
		}
	}

	/*
	 * Mask of section header flags to ignore when matching sections. We
	 * are more strict with relocatable objects, ignoring only the order
	 * flags, and keeping sections apart if they differ otherwise. This
	 * follows the policy that sections in a relative object should only
	 * be merged if their flags are the same, and avoids destroying
	 * information prematurely. For final products however, we ignore all
	 * flags that do not prevent a merge.
	 */
	shflagmask =
	    (ofl->ofl_flags & FLG_OF_RELOBJ) ? ALL_SHF_ORDER : ALL_SHF_IGNORE;

	/*
	 * Traverse the input section list for the output section we have been
	 * assigned. If we find a matching section simply add this new section.
	 */
	iidx = 0;
	for (APLIST_TRAVERSE(sgp->sg_osdescs, idx1, osp)) {
		Shdr	*os_shdr = osp->os_shdr;

		/*
		 * An input section matches an output section if:
		 * -	The ident values match
		 * -	The names match
		 * -	Not a GROUP section
		 * - 	Not a DTrace dof section
		 * -	Section types match
		 * -	Matching section flags, after screening out the
		 *	shflagmask flags.
		 *
		 * Section types are considered to match if any one of
		 * the following are true:
		 * -	The type codes are the same
		 * -	Both are .eh_frame sections (regardless of type code)
		 * -	The input section is COMDAT, and the output section
		 *	is SHT_PROGBITS.
		 */
		if ((ident == osp->os_identndx) &&
		    (ident != ld_targ.t_id.id_rel) &&
		    (onamehash == osp->os_namehash) &&
		    (shdr->sh_type != SHT_GROUP) &&
		    (shdr->sh_type != SHT_SUNW_dof) &&
		    ((shdr->sh_type == os_shdr->sh_type) ||
		    (is_ehframe && (osp->os_flags & FLG_OS_EHFRAME)) ||
		    ((shdr->sh_type == SHT_SUNW_COMDAT) &&
		    (os_shdr->sh_type == SHT_PROGBITS))) &&
		    ((shflags & ~shflagmask) ==
		    (os_shdr->sh_flags & ~shflagmask)) &&
		    (strcmp(oname, osp->os_name) == 0)) {
			uintptr_t	err;

			/*
			 * Process any COMDAT section, keeping the first and
			 * discarding all others.
			 */
			if ((isp->is_flags & FLG_IS_COMDAT) &&
			    ((err = add_comdat(ofl, osp, isp)) != 1))
				return ((Os_desc *)err);

			/*
			 * Set alignment
			 */
			set_addralign(ofl, osp, isp);

			/*
			 * If this section is a non-empty TLS section indicate
			 * that a PT_TLS program header is required.
			 */
			if ((shflags & SHF_TLS) && shdr->sh_size &&
			    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0))
				ofl->ofl_flags |= FLG_OF_TLSPHDR;

			/*
			 * Insert the input section descriptor on the proper
			 * output section descriptor list.
			 *
			 * If this segment requires input section ordering,
			 * honor any mapfile specified ordering for otherwise
			 * unordered sections by setting the mapfile_sort
			 * argument of os_attach_isp() to True.
			 */

			if (os_attach_isp(ofl, osp, isp,
			    (sgp->sg_flags & FLG_SG_IS_ORDER) != 0) == 0)
				return ((Os_desc *)S_ERROR);

			/*
			 * If this input section and file is associated to an
			 * artificially referenced output section, make sure
			 * they are marked as referenced also. This ensures
			 * that this input section and file isn't eliminated
			 * when -zignore is in effect.
			 *
			 * See -zignore comments when creating a new output
			 * section below.
			 */
			if (((ifl &&
			    (ifl->ifl_flags & FLG_IF_IGNORE)) || DBG_ENABLED) &&
			    (osp->os_flags & FLG_OS_SECTREF)) {
				isp->is_flags |= FLG_IS_SECTREF;
				if (ifl)
					ifl->ifl_flags |= FLG_IF_FILEREF;
			}

			DBG_CALL(Dbg_sec_added(ofl->ofl_lml, osp, sgp));
			return (osp);
		}

		/*
		 * Do we need to worry about section ordering?
		 */
		if (os_ndx) {
			if (osp->os_ordndx) {
				if (os_ndx < osp->os_ordndx)
					/* insert section here. */
					break;
				else {
					iidx = idx1 + 1;
					continue;
				}
			} else {
				/* insert section here. */
				break;
			}
		} else if (osp->os_ordndx) {
			iidx = idx1 + 1;
			continue;
		}

		/*
		 * If the new sections identifier is less than that of the
		 * present input section we need to insert the new section
		 * at this point.
		 */
		if (ident < osp->os_identndx)
			break;

		iidx = idx1 + 1;
	}

	/*
	 * We are adding a new output section.  Update the section header
	 * count and associated string size.
	 *
	 * If the input section triggering this output section has been marked
	 * for discard, and if no other non-discarded input section comes along
	 * to join it, then we will over count. We cannot know if this will
	 * happen or not until all input is seen. Set FLG_OF_AJDOSCNT to
	 * trigger a final count readjustment.
	 */
	if (isp->is_flags & FLG_IS_DISCARD)
		ofl->ofl_flags |= FLG_OF_ADJOSCNT;
	ofl->ofl_shdrcnt++;
	if (st_insert(ofl->ofl_shdrsttab, oname) == -1)
		return ((Os_desc *)S_ERROR);

	/*
	 * Create a new output section descriptor.
	 */
	if ((osp = libld_calloc(sizeof (Os_desc), 1)) == NULL)
		return ((Os_desc *)S_ERROR);
	if ((osp->os_shdr = libld_calloc(sizeof (Shdr), 1)) == NULL)
		return ((Os_desc *)S_ERROR);

	/*
	 * Convert COMDAT section to PROGBITS as this the first section of the
	 * output section.  Save any COMDAT section for later processing, as
	 * additional COMDAT sections that match this section need discarding.
	 */
	if ((shdr->sh_type == SHT_SUNW_COMDAT) &&
	    ((shdr = isp_convert_type(isp, SHT_PROGBITS)) == NULL))
		return ((Os_desc *)S_ERROR);
	if ((isp->is_flags & FLG_IS_COMDAT) &&
	    (add_comdat(ofl, osp, isp) == S_ERROR))
		return ((Os_desc *)S_ERROR);

	if (is_ehframe) {
		/*
		 * Executable or sharable objects can have at most a single
		 * .eh_frame section. Detect attempts to create more than
		 * one. This occurs if the input sections have incompatible
		 * attributes.
		 */
		if ((ofl->ofl_flags & FLG_OF_EHFRAME) &&
		    !(ofl->ofl_flags & FLG_OF_RELOBJ)) {
			eh_frame_muldef(ofl, isp);
			return ((Os_desc *)S_ERROR);
		}
		ofl->ofl_flags |= FLG_OF_EHFRAME;

		/*
		 * For .eh_frame sections, we always set the type to be the
		 * type specified by the ABI.  This allows .eh_frame sections
		 * of type SHT_PROGBITS to be correctly merged with .eh_frame
		 * sections of the ABI-defined type (e.g. SHT_AMD64_UNWIND),
		 * with the output being of the ABI-defined type.
		 */
		osp->os_shdr->sh_type = ld_targ.t_m.m_sht_unwind;
	} else {
		osp->os_shdr->sh_type = shdr->sh_type;
	}

	osp->os_shdr->sh_flags = shdr->sh_flags;
	osp->os_shdr->sh_entsize = shdr->sh_entsize;
	osp->os_name = oname;
	osp->os_namehash = onamehash;
	osp->os_ordndx = os_ndx;
	osp->os_sgdesc = sgp;
	if (is_ehframe)
		osp->os_flags |= FLG_OS_EHFRAME;

	if (ifl && (shdr->sh_type == SHT_PROGBITS)) {
		/*
		 * Try to preserve the intended meaning of sh_link/sh_info.
		 * See the translate_link() in update.c.
		 */
		osp->os_shdr->sh_link = shdr->sh_link;
		if (shdr->sh_flags & SHF_INFO_LINK)
			osp->os_shdr->sh_info = shdr->sh_info;
	}

	/*
	 * When -zignore is in effect, user supplied sections and files that are
	 * not referenced from other sections, are eliminated from the object
	 * being produced.  Some sections, although unreferenced, are special,
	 * and must not be eliminated.  Determine if this new output section is
	 * one of those special sections, and if so mark it artificially as
	 * referenced.  Any input section and file associated to this output
	 * section is also be marked as referenced, and thus won't be eliminated
	 * from the final output.
	 */
	if (ifl && ((ofl->ofl_flags1 & FLG_OF1_IGNPRC) || DBG_ENABLED)) {
		const Msg	*refsec;

		for (refsec = RefSecs; *refsec; refsec++) {
			if (strcmp(osp->os_name, MSG_ORIG(*refsec)) == 0) {
				osp->os_flags |= FLG_OS_SECTREF;

				if ((ifl->ifl_flags & FLG_IF_IGNORE) ||
				    DBG_ENABLED) {
					isp->is_flags |= FLG_IS_SECTREF;
					ifl->ifl_flags |= FLG_IF_FILEREF;
				}
				break;
			}
		}
	}

	/*
	 * Sections of type SHT_GROUP are added to the ofl->ofl_osgroups list,
	 * so that they can be updated as a group later.
	 */
	if ((shdr->sh_type == SHT_GROUP) &&
	    ((isp->is_flags & FLG_IS_DISCARD) == 0) &&
	    (aplist_append(&ofl->ofl_osgroups, osp,
	    AL_CNT_OFL_OSGROUPS) == NULL))
		return ((Os_desc *)S_ERROR);

	/*
	 * If this section is a non-empty TLS section indicate that a PT_TLS
	 * program header is required.
	 */
	if ((shflags & SHF_TLS) && shdr->sh_size &&
	    ((ofl->ofl_flags & FLG_OF_RELOBJ) == 0))
		ofl->ofl_flags |= FLG_OF_TLSPHDR;

	/*
	 * If a non-allocatable section is going to be put into a loadable
	 * segment then turn on the allocate bit for this section and warn the
	 * user that we have done so.  This could only happen through the use
	 * of a mapfile.
	 */
	if ((sgp->sg_phdr.p_type == PT_LOAD) &&
	    ((osp->os_shdr->sh_flags & SHF_ALLOC) == 0)) {
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_SCN_NONALLOC),
		    ofl->ofl_name, osp->os_name, sgp->sg_name);
		osp->os_shdr->sh_flags |= SHF_ALLOC;
	}

	/*
	 * Retain this sections identifier for future comparisons when placing
	 * a section (after all sections have been processed this variable will
	 * be used to hold the sections symbol index as we don't need to retain
	 * the identifier any more).
	 */
	osp->os_identndx = ident;

	/*
	 * Set alignment.
	 */
	set_addralign(ofl, osp, isp);

	if (os_attach_isp(ofl, osp, isp, 0) == 0)
		return ((Os_desc *)S_ERROR);

	DBG_CALL(Dbg_sec_created(ofl->ofl_lml, osp, sgp));

	/*
	 * Insert the new section at the offset given by iidx.  If no position
	 * for it was identified above, this will be index 0, causing the new
	 * section to be prepended to the beginning of the section list.
	 * Otherwise, it is the index following the section that was identified.
	 */
	if (aplist_insert(&sgp->sg_osdescs, osp, AL_CNT_SG_OSDESC,
	    iidx) == NULL)
		return ((Os_desc *)S_ERROR);
	return (osp);
}
