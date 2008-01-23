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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"


/*
 * Print out a single `segment descriptor' entry.
 */
void
Dbg_seg_desc_entry(Lm_list *lml, Half mach, int ndx, Sg_desc *sgp)
{
	Conv_seg_flags_buf_t	seg_flags_buf;
	const char		*str;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_ORIG(MSG_SEG_NAME), ndx, str);

	Elf_phdr(lml, mach, &sgp->sg_phdr);

	dbg_print(lml, MSG_ORIG(MSG_SEG_LENGTH), EC_ADDR(sgp->sg_length));
	dbg_print(lml, MSG_ORIG(MSG_SEG_FLAGS),
	    conv_seg_flags(sgp->sg_flags, &seg_flags_buf));

	if (sgp->sg_sizesym && sgp->sg_sizesym->sd_name)
		dbg_print(lml, MSG_ORIG(MSG_SEG_SIZESYM),
		    Dbg_demangle_name(sgp->sg_sizesym->sd_name));

	if (sgp->sg_secorder) {
		Aliste		idx;
		Sec_order	*scop;

		dbg_print(lml, MSG_ORIG(MSG_SEG_ORDER));
		for (APLIST_TRAVERSE(sgp->sg_secorder, idx, scop))
			dbg_print(lml, MSG_ORIG(MSG_SEG_SECTION),
			    scop->sco_secname, EC_WORD(scop->sco_index));
	}
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

	Dbg_seg_desc_entry(ofl->ofl_lml, ofl->ofl_dehdr->e_machine, ndx, sgp);
}

/*
 * Print out the available segment descriptors.
 */
void
Dbg_seg_list(Lm_list *lml, Half mach, List *lsg)
{
	Listnode	*lnp;
	Sg_desc		*sgp;
	int		ndx = 0;

	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_SEG_DESC_AVAIL));
	for (LIST_TRAVERSE(lsg, lnp, sgp))
		Dbg_seg_desc_entry(lml, mach, ndx++, sgp);
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
	Listnode	*lnp;
	Is_desc		*isp;
	Elf_Data	*data;
	Shdr		*shdr;

	if (DBG_NOTCLASS(DBG_C_SEGMENTS))
		return;

	dbg_print(lml, MSG_ORIG(MSG_SEC_NAME), ndx, osp->os_name);
	Elf_shdr(lml, ofl->ofl_dehdr->e_machine, osp->os_shdr);
	dbg_print(lml, MSG_INTL(MSG_EDATA_TITLE));

	shdr = osp->os_shdr;
	data = osp->os_outdata;
	dbg_print(lml, MSG_INTL(MSG_EDATA_ENTRY), MSG_INTL(MSG_STR_OUT),
	    EC_ADDR(shdr->sh_addr), conv_elfdata_type(data->d_type, &inv_buf),
	    EC_XWORD(data->d_size), EC_OFF(data->d_off),
	    EC_XWORD(data->d_align), MSG_ORIG(MSG_STR_EMPTY),
	    MSG_ORIG(MSG_STR_EMPTY));

	if (DBG_NOTDETAIL())
		return;

	for (LIST_TRAVERSE(&(osp->os_isdescs), lnp, isp)) {
		const char	*file, *str;
		Addr		addr;

		data = isp->is_indata;

		if (isp->is_flags & FLG_IS_DISCARD) {
			str = MSG_INTL(MSG_EDATA_IGNSCN);
			addr = 0;
		} else {
			str = MSG_ORIG(MSG_STR_EMPTY);
			addr = (Addr)(shdr->sh_addr + data->d_off);
		}

		if (isp->is_file && isp->is_file->ifl_name)
			file = isp->is_file->ifl_name;
		else
			file = MSG_ORIG(MSG_STR_EMPTY);

		dbg_print(lml, MSG_INTL(MSG_EDATA_ENTRY), MSG_INTL(MSG_STR_IN),
		    EC_ADDR(addr), conv_elfdata_type(data->d_type, &inv_buf),
		    EC_XWORD(data->d_size), EC_OFF(data->d_off),
		    EC_XWORD(data->d_align), file, str);
	}
}
