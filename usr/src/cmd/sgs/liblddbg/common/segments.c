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

#include	<stdio.h>
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Print out a single `segment descriptor' entry.
 */
void
Dbg_seg_desc_entry(Lm_list *lml, uchar_t osabi, Half mach, int ndx,
    Sg_desc *sgp, Boolean space_nl)
{
	Conv_seg_flags_buf_t	seg_flags_buf;
	Aliste			idx;
	Sym_desc		*sdp;

	if (space_nl)
		Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_ORIG(MSG_SEG_DESC), ndx);
	if (sgp->sg_name)
		dbg_print(lml, MSG_ORIG(MSG_SEG_NAME), sgp->sg_name);

	dbg_print(lml, MSG_ORIG(MSG_SEG_FLAGS),
	    conv_seg_flags(sgp->sg_flags, &seg_flags_buf));

	Elf_phdr(lml, osabi, mach, &sgp->sg_phdr);

	if (sgp->sg_flags & FLG_SG_P_ALIGN)
		dbg_print(lml, MSG_ORIG(MSG_SEG_ALIGN),
		    EC_ADDR(sgp->sg_align));

	if (sgp->sg_flags & FLG_SG_LENGTH)
		dbg_print(lml, MSG_ORIG(MSG_SEG_LENGTH),
		    EC_ADDR(sgp->sg_length));

	if (sgp->sg_flags & FLG_SG_ROUND)
		dbg_print(lml, MSG_ORIG(MSG_SEG_ROUND),
		    EC_ADDR(sgp->sg_round));

	if (aplist_nitems(sgp->sg_sizesym) > 0) {
		dbg_print(lml, MSG_ORIG(MSG_SEG_SIZESYM_TITLE));
		for (APLIST_TRAVERSE(sgp->sg_sizesym, idx, sdp))
			if (sdp->sd_name)
				dbg_print(lml, MSG_ORIG(MSG_SEG_SIZESYM),
				    Dbg_demangle_name(sdp->sd_name));
	}
	if (aplist_nitems(sgp->sg_is_order) > 0) {
		Aliste		idx;
		Ent_desc	*enp;

		dbg_print(lml, MSG_ORIG(MSG_SEG_IS_ORDER_TITLE));
		for (APLIST_TRAVERSE(sgp->sg_is_order, idx, enp))
			dbg_print(lml, MSG_ORIG(MSG_SEG_LIST_ITEM),
			    enp->ec_name);
	}
	if (alist_nitems(sgp->sg_os_order) > 0) {
		Aliste		idx;
		Sec_order	*scop;

		dbg_print(lml, MSG_ORIG(MSG_SEG_OS_ORDER_TITLE));
		for (ALIST_TRAVERSE(sgp->sg_os_order, idx, scop))
			dbg_print(lml, MSG_ORIG(MSG_SEG_LIST_ITEM),
			    scop->sco_secname);
	}
	if (space_nl)
		Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_seg_title(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SEG_DESC_INUSE));
}

void
Dbg_seg_entry(Ofl_desc *ofl, int ndx, Sg_desc *sgp)
{
	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	Dbg_seg_desc_entry(ofl->ofl_lml, ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, ndx, sgp, TRUE);
}

/*
 * Print out the available segment descriptors.
 */
void
Dbg_seg_list(Lm_list *lml, uchar_t osabi, Half mach, APlist *apl)
{
	Aliste		idx;
	Sg_desc		*sgp;
	int		ndx = 0;

	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SEG_DESC_AVAIL));
	for (APLIST_TRAVERSE(apl, idx, sgp))
		Dbg_seg_desc_entry(lml, osabi, mach, ndx++, sgp, TRUE);
}

/*
 * Print the output section information.  This includes the section header
 * information and the output elf buffer information.  If the detail flag is
 * set, traverse the input sections displaying all the input buffers that
 * have been concatenated to form this output buffer.
 */
void
Dbg_seg_os(Ofl_desc *ofl, Os_desc *osp, int ndx)
{
	Conv_inv_buf_t	inv_buf;
	Lm_list		*lml = ofl->ofl_lml;
	Aliste		idx;
	Is_desc		*isp;
	Elf_Data	*data;
	Shdr		*shdr;
	const char	*empty = MSG_ORIG(MSG_STR_EMPTY);
	int		os_isdescs_idx;

	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	dbg_print(lml, MSG_ORIG(MSG_SEC_NAME), ndx, osp->os_name);
	Elf_shdr(lml, ofl->ofl_dehdr->e_ident[EI_OSABI],
	    ofl->ofl_dehdr->e_machine, osp->os_shdr);
	dbg_print(lml, MSG_INTL(MSG_EDATA_TITLE));

	shdr = osp->os_shdr;
	data = osp->os_outdata;
	dbg_print(lml, MSG_INTL(MSG_EDATA_ENTRY), MSG_INTL(MSG_STR_OUT),
	    EC_ADDR(shdr->sh_addr), conv_elfdata_type(data->d_type, &inv_buf),
	    EC_XWORD(data->d_size), EC_OFF(data->d_off),
	    EC_XWORD(data->d_align), empty, empty, empty);

	if (DBG_NOTDETAIL())
		return;

	OS_ISDESCS_TRAVERSE(os_isdescs_idx, osp, idx, isp) {
		dbg_isec_name_buf_t	buf;
		char			*alloc_mem;
		const char		*file, *str;
		Addr			addr;

		data = isp->is_indata;

		if (isp->is_flags & FLG_IS_DISCARD) {
			str = MSG_INTL(MSG_EDATA_IGNSCN);
			addr = 0;
		} else {
			str = empty;
			addr = (Addr)(shdr->sh_addr + data->d_off);
		}

		if (isp->is_file && isp->is_file->ifl_name)
			file = isp->is_file->ifl_name;
		else
			file = empty;

		dbg_print(lml, MSG_INTL(MSG_EDATA_ENTRY), MSG_INTL(MSG_STR_IN),
		    EC_ADDR(addr), conv_elfdata_type(data->d_type, &inv_buf),
		    EC_XWORD(data->d_size), EC_OFF(data->d_off),
		    EC_XWORD(data->d_align), file,
		    dbg_fmt_isec_name(isp, buf, &alloc_mem), str);
		if (alloc_mem != NULL)
			free(alloc_mem);
	}
}
