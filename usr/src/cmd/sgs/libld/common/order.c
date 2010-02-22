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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Processing of SHF_ORDERED sections.
 */
#include	<stdio.h>
#include	<fcntl.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Section Ordering History/Background:
 *
 * There are two forms of section ordering, SHF_ORDERED, and SHF_LINK_ORDER.
 *
 * SHF_ORDERED was invented at Sun in order to support the PowerPC port
 * of Solaris 2.6, which used it for sorting tag words which describe
 * the state of callee saves registers for given PC ranges. It was defined
 * in the OS specific ELF section flag range. Some other values were defined
 * at the same time:
 *	SHF_EXCLUDE - Section is to be excluded from executables or shared
 *		objects, and only kept in relocatable object output.
 *	SHN_BEFORE/SHN_AFTER - Sections are placed before/after all other
 *		sections, in the order they are encountered by the linker.
 * Although initially conceived to support the PowerPC, the functionality
 * was implemented for all platforms, and was later used to manage C++
 * exceptions and stack unwinding. The PowerPC port was discontinued after
 * one release, but SHF_ORDERED lives on.
 *
 * SHF_LINK_ORDER was invented later by the wider ELF community, and is
 * therefore assigned a value in the generic ELF section flag range. It is
 * essentially a simpler version of SHF_ORDERED, dispensing with some
 * unnecessary features. The Solaris implementation of SHF_LINK_ORDER uses
 * SHF_EXCLUDE, and SHF_BEFORE/SHN_AFTER as well, but it appears that these
 * are still Solaris-only extensions not used by other implementations.
 * SHF_LINK_ORDER has superseded SHF_ORDERED. The older mechanism is
 * supported for the benefit of old pre-existing objects.
 *
 * -----
 *
 * SHF_ORDERED offers two distinct and separate abilities:
 *
 *	(1) To specify the output section
 *	(2) To optionally be sorted relative to other sorted sections,
 *		using a non-sorted section as a sort key.
 *
 * To  do this, it uses both the sh_link, and sh_info fields:
 *
 *    sh_link
 *	Specifies the output section to receive this input section.
 *	The sh_link field of an SHF_ORDERED section forms a linked list of
 *	sections, all of which must have identical section header flags
 *	(including SHF_ORDERED). The list is terminated by a final section
 *	with a sh_link that points at itself. All input sections in this list
 *	are assigned to the output section of the final section in the list.
 *	Hence, if a section points at itself, the effect is that it gets
 *	assigned to an output section in the usual default manner (i.e. an
 *	output section with the same name as the input). However, it can
 *	point at any arbitrary other section. This is a way to put a section
 *	with one name into an output section with a different name. It should
 *	be noted that this is of little value overall, because the link-editor
 *	already supports a more general feature for directing input sections
 *	to output sections: An input section named .text%foo will be sent to
 *	an output section named ".text", and this works for all sections,
 *	not just ordered ones.
 *
 *    sh_info
 *	If sh_info is in the range (1 <= value < shnum), then this input section
 *	is added to the group of sorted sections. The section referenced by
 *	sh_info must be unsorted, and is used as the sort key.
 *
 *	If sh_info is SHN_BEFORE or SHN_AFTER, it is put in the pre/post group,
 *	in the order it arrives (the before/after classes are not sorted).
 *
 *	If sh_info is "invalid" (typically 0), then this section is added to
 *	the group of non-sorted sections, and goes into the output file in the
 *	order it arrives. This is not a valuable feature, as the same effect
 *	can be achieved more simply by not setting SHF_ORDERED at all.
 *
 * SHF_LINK_ORDER is a simplification of SHF_ORDERED. It uses sh_link to specify
 * the section to use as a sort key and sh_info is set to 0. The standard
 * ".text%foo" mechanism is used to direct input sections to output sections,
 * and unordered sections indicate that by not setting SHF_LINK_ORDER.
 */


/*
 * A "keyshndx" is the section index for the unordered section that should
 * be used as a sort key for a ordered section. Verify that the given
 * keyshndx is valid.
 *
 * exit:
 *	Returns 0 if the keyshndx is valid. A non-zero DBG_ORDER_ code is
 *	returned if the keyshndx is not valid to describe the problem.
 */
inline static Word
is_keyshndx_ok(Ifl_desc *ifl, Word keyshndx)
{
	if ((keyshndx == SHN_BEFORE) || (keyshndx == SHN_AFTER))
		return (0);

	/*
	 * Validate the key range.
	 */
	if ((keyshndx == 0) || (keyshndx >= ifl->ifl_shnum))
		return (DBG_ORDER_LINK_OUTRANGE);

	/*
	 * The section pointed to by keyshndx should not be an ordered section.
	 * Strictly speaking, we could test for SHF_ORDERED here instead of
	 * ALL_SHF_ORDER as the two ordering flags are not supposed to be
	 * mixed. Using ALL_SHF_ORDER costs the same and ensures that such
	 * mixing doesn't go undetected.
	 */
	if (ifl->ifl_isdesc[keyshndx]->is_shdr->sh_flags & ALL_SHF_ORDER)
		return (DBG_ORDER_INFO_ORDER);

	return (0);
}

/*
 * The sh_link field of an SHF_ORDERED section forms a linked list of
 * sections. The list is terminated by a final section with a sh_link
 * that points at itself. Given the index of an SHF_ORDERED section, find
 * the index of the final section in the list.
 *
 * entry:
 *	ofl - Output file descriptor
 *	ifl - Input file descriptor
 *	ndx - Section index of SHF_ORDERED section
 *	alt_os_name - Address of pointer to string. If the final section
 *		name is different than the section given by ndx, *alt_os_name
 *		will be updated with the name of the final section. The caller
 *		should initialize *alt_os_name to NULL before calling
 *		this routine.
 *
 * exit:
 *	On success: If the final section is different than the section
 *	given by ndx, then *alt_os_name is set to its name. TRUE is returned.
 *
 *	On failure, FALSE is returned.
 */
static Boolean
validate_shf_ordered_dest(Ofl_desc *ofl, Ifl_desc *ifl, Word ndx,
    const char **alt_os_name)
{
	Word	shnum = ifl->ifl_shnum;
	Word	isp1_ndx, isp2_ndx;
	Is_desc	*isp1, *isp2;
	int	error = 0;
	size_t	iter = 0;

	/*
	 * Traverse the list until we find the termination, or encounter
	 * an invalid condition in the object that prevents ordering.
	 */
	isp1_ndx = ndx;
	isp1 = ifl->ifl_isdesc[ndx];
	do {
		/*
		 * Obtain index of next section in list. Ensure it is in range.
		 */
		isp2_ndx = isp1->is_shdr->sh_link;
		if ((isp2_ndx == 0) || (isp2_ndx >= shnum)) {
			error = DBG_ORDER_LINK_OUTRANGE;
			break;
		}
		isp2 = ifl->ifl_isdesc[isp2_ndx];

		/* The section flags must match exactly */
		if (isp1->is_shdr->sh_flags != isp2->is_shdr->sh_flags) {
			/*
			 * The case where the next section in the list does
			 * not have the same ordered flag set as the original
			 * ordered section gets a unique error code. This
			 * provides more accurate/useful debugging diagnostics.
			 */
			error = ((isp2->is_flags & FLG_IS_ORDERED) == 0) ?
			    DBG_ORDER_LINK_ERROR : DBG_ORDER_FLAGS;
			break;
		}

		/*
		 * The sh_info field specifies the section index of an
		 * unorderd section which will be used as a sort key.
		 * Ensure it is in range. If not, we terminate the list
		 * at the current node instead of continuing on.
		 */
		if ((error = is_keyshndx_ok(ifl, isp2->is_shdr->sh_info)) != 0)
			break;

		/* If the section points at itself, it terminates the list */
		if (isp1_ndx == isp2_ndx)
			break;

		/*
		 * Advance to next section in list
		 */
		isp1_ndx = isp2_ndx;
		isp1 = isp2;

		/*
		 * If we loop more times than the input file has sections,
		 * we have encountered a malformed object in which the list
		 * of SHF_ORDERED sections has a cycle. This can only happen
		 * if the compiler generating the object has a bad bug.
		 */
		if (++iter >= shnum) {
			error = DBG_ORDER_CYCLIC;
			break;
		}
	/* CONSTANTCONDITION */
	} while (1);

	/*
	 * If we have found a problem, issue a debug diagnostic and map
	 * the output section to 0. This indicates that the section should
	 * remove the ordering flag and treat it as a standard section.
	 */
	if (error != 0) {
		isp2_ndx = 0;
		DBG_CALL(Dbg_sec_order_error(ofl->ofl_lml, ifl, ndx, error));
	}

	/* Report success */
	if (isp2_ndx != 0) {
		/*
		 * If the destination section is different than the input
		 * section, then set *alt_os_name to the destination name.
		 */
		if (isp2_ndx != ndx)
			*alt_os_name = ifl->ifl_isdesc[isp2_ndx]->is_name;
		return (TRUE);
	}

	/* If we get here, there is no valid destination */
	return (FALSE);
}

/*
 * Called when an ordered section has a problem that prevents ordering.
 * The order flag is removed, and then the section is placed as an
 * unsorted section.
 */
static uintptr_t
place_unordered(Ofl_desc *ofl, Is_desc *isp, Place_path_info *path_info)
{
	isp->is_flags &= ~FLG_IS_ORDERED;
	if (isp->is_osdesc == NULL)
		return ((uintptr_t)ld_place_section(ofl, isp, path_info,
		    isp->is_keyident, NULL));
	return ((uintptr_t)isp->is_osdesc);
}

/*
 * Process ordered input section. Called from process_elf() after
 * all the non-ordered sections have been placed.
 *
 * entry:
 *	ofl - Output file descriptor
 *	ifl - Input file descriptor
 *	ndx - Section index of SHF_ORDERED section
 *
 * exit:
 */
uintptr_t
ld_process_ordered(Ofl_desc *ofl, Ifl_desc *ifl, Place_path_info *path_info,
    Word ndx)
{
	Is_desc		*isp2, *isp = ifl->ifl_isdesc[ndx];
	Xword		shflags = isp->is_shdr->sh_flags;
	const char	*alt_os_name = NULL;
	Word		keyshndx;
	Os_desc		*osp;
	int		error = 0;

	/*
	 * Obtain the sort key section index for this ordered section.
	 * SHF_ORDERED uses sh_info, while SHF_LINK_ORDER uses sh_link.
	 * In order for this function to be called, one of SHF_ORDERED
	 * or SHF_LINK_ORDER must be set. Testing for one implies the
	 * state of the other.
	 */
	keyshndx = (shflags & SHF_ORDERED) ?
	    isp->is_shdr->sh_info : isp->is_shdr->sh_link;

	/*
	 * Validate the sort key section index. If something is wrong,
	 * fall back to treating it as a non-ordered section.
	 */
	if ((error = is_keyshndx_ok(ifl, keyshndx)) != 0) {
		DBG_CALL(Dbg_sec_order_error(ofl->ofl_lml, ifl, ndx, error));
		return (place_unordered(ofl, isp, path_info));
	}

	/*
	 * If SHF_ORDERED is in effect, validate the destination section
	 * name given by sh_link, and set alt_os_name to the name of the
	 * destination if it differs from the section being processed.
	 */
	if ((shflags & SHF_ORDERED) &&
	    (validate_shf_ordered_dest(ofl, ifl, ndx, &alt_os_name) == FALSE))
		return (place_unordered(ofl, isp, path_info));

	/*
	 * Place the section into its output section. It's possible that this
	 * section is discarded (possibly because it's defined COMDAT), in
	 * which case we're done.
	 */
	if ((osp = isp->is_osdesc) == NULL) {
		osp = ld_place_section(ofl, isp, path_info, isp->is_keyident,
		    alt_os_name);
		if ((osp == (Os_desc *)S_ERROR) || (osp == NULL))
			return ((uintptr_t)osp);
	}

	/*
	 * If the output section is not yet on the ordered list, place it on
	 * the list.
	 */
	if (aplist_test(&ofl->ofl_ordered, osp, AL_CNT_OFL_ORDERED) ==
	    ALE_ALLOCFAIL)
		return ((uintptr_t)S_ERROR);

	/*
	 * Output section has been found - set up its sorting information.
	 */
	if ((keyshndx != SHN_BEFORE) && (keyshndx != SHN_AFTER)) {
		Os_desc		*osp2;

		isp2 = ifl->ifl_isdesc[keyshndx];
		if (isp2->is_flags & FLG_IS_DISCARD) {
			eprintf(ofl->ofl_lml, ERR_FATAL,
			    MSG_INTL(MSG_FIL_BADORDREF), ifl->ifl_name,
			    EC_WORD(isp->is_scnndx), isp->is_name,
			    EC_WORD(isp2->is_scnndx), isp2->is_name);
			return (S_ERROR);
		}

		/*
		 * Indicate that this ordered input section will require a
		 * sort key.  Propagate the key requirement through to the
		 * associated output section, segment and file, to trigger
		 * the sort key creation.  See ld_sec_validate();
		 */
		isp2->is_flags |= FLG_IS_KEY;

		osp2 = isp2->is_osdesc;
		osp2->os_flags |= FLG_OS_KEY;
		osp2->os_sgdesc->sg_flags |= FLG_SG_KEY;

		ofl->ofl_flags |= FLG_OF_KEY;
	}

	return ((uintptr_t)osp);
}

/*
 * Traverse all segments looking for section ordering information that hasn't
 * been used.  If found give a warning message to the user.  Also, check if
 * there are any ordered key sections, and if so set up sort key values.
 */
void
ld_sec_validate(Ofl_desc *ofl)
{
	Aliste		idx1;
	Sg_desc		*sgp;
	Word 		key = 1;

	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
		Sec_order	*scop;
		Os_desc		*osp;
		Aliste		idx2;

		for (ALIST_TRAVERSE(sgp->sg_os_order, idx2, scop)) {
			if ((scop->sco_flags & FLG_SGO_USED) == 0) {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_MAP_SECORDER),
				    sgp->sg_name, scop->sco_secname);
			}
		}
		if ((sgp->sg_flags & FLG_SG_KEY) == 0)
			continue;

		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
			Aliste	idx3;
			Is_desc	*isp;

			if ((osp->os_flags & FLG_OS_KEY) == 0)
				continue;

			/*
			 * The input sections used as sort keys are required
			 * to be unordered, so we only have to look at the
			 * DEFAULT list of input sections.
			 */
			for (APLIST_TRAVERSE(osp->os_isdescs[OS_ISD_DEFAULT],
			    idx3, isp)) {
				if (isp->is_flags & FLG_IS_KEY)
					isp->is_keyident = key++;
			}
		}
	}
}

static int
comp(const void *ss1, const void *ss2)
{
	Is_desc		*s1 = *((Is_desc **)ss1);
	Is_desc		*s2 = *((Is_desc **)ss2);
	Is_desc		*i1, *i2;
	Word		ndx1, ndx2;

	if (s1->is_shdr->sh_flags & SHF_ORDERED)
		ndx1 = s1->is_shdr->sh_info;
	else
		ndx1 = s1->is_shdr->sh_link;

	if (s2->is_shdr->sh_flags & SHF_ORDERED)
		ndx2 = s2->is_shdr->sh_info;
	else
		ndx2 = s2->is_shdr->sh_link;

	i1 = s1->is_file->ifl_isdesc[ndx1];
	i2 = s2->is_file->ifl_isdesc[ndx2];

	if (i1->is_keyident > i2->is_keyident)
		return (1);
	if (i1->is_keyident < i2->is_keyident)
		return (-1);
	return (0);
}

/*
 * Sort ordered input sections
 */
uintptr_t
ld_sort_ordered(Ofl_desc *ofl)
{
	Aliste	idx1;
	Os_desc *osp;

	DBG_CALL(Dbg_sec_order_list(ofl, 0));

	for (APLIST_TRAVERSE(ofl->ofl_ordered, idx1, osp)) {
		APlist	*ap_list = osp->os_isdescs[OS_ISD_ORDERED];
		Aliste	apl_nitems = aplist_nitems(ap_list);

		/*
		 * If this output section has a non-empty list of ordered
		 * input sections, sort their APlist in place into their
		 * final order.
		 */
		if (apl_nitems != 0)
			qsort((char *)ap_list->apl_data, apl_nitems,
			    sizeof (Is_desc *), comp);
	}
	DBG_CALL(Dbg_sec_order_list(ofl, 1));
	return (0);
}
