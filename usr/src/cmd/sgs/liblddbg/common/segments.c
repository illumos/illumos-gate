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
 *	Copyright (c) 2000 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"


/*
 * Print out a single `segment descriptor' entry.
 */
void
_Dbg_seg_desc_entry(Half mach, int ndx, Sg_desc *sgp)
{
	const char	*str;

	if (sgp->sg_name && *sgp->sg_name)
		str = sgp->sg_name;
	else
		str = MSG_INTL(MSG_STR_NULL);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_ORIG(MSG_SEG_NAME), ndx, str);

	Elf_phdr_entry(mach, &sgp->sg_phdr);

	dbg_print(MSG_ORIG(MSG_SEG_LENGTH), EC_ADDR(sgp->sg_length));
	dbg_print(MSG_ORIG(MSG_SEG_FLAGS), conv_segaflg_str(sgp->sg_flags));
	if (sgp->sg_sizesym && sgp->sg_sizesym->sd_name)
		dbg_print(MSG_ORIG(MSG_SEG_SIZESYM),
		    _Dbg_sym_dem(sgp->sg_sizesym->sd_name));
	if (sgp->sg_secorder.head) {
		Listnode *	lnp;
		Sec_order *	scop;

		dbg_print(MSG_ORIG(MSG_SEG_ORDER));
		for (LIST_TRAVERSE(&sgp->sg_secorder, lnp, scop)) {
			dbg_print(MSG_ORIG(MSG_SEG_SECTION), scop->sco_secname,
			    EC_WORD(scop->sco_index));
		}
	}
}

void
Dbg_seg_title()
{
	if (DBG_NOTCLASS(DBG_SEGMENTS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SEG_DESC_INUSE));
}

void
Dbg_seg_entry(Half mach, int ndx, Sg_desc *sgp)
{
	if (DBG_NOTCLASS(DBG_SEGMENTS))
		return;

	_Dbg_seg_desc_entry(mach, ndx, sgp);
}

/*
 * Print out the available segment descriptors.
 */
void
Dbg_seg_list(Half mach, List *lsg)
{
	Listnode	*lnp;
	Sg_desc		*sgp;
	int		ndx = 0;

	if (DBG_NOTCLASS(DBG_SEGMENTS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_SEG_DESC_AVAIL));
	for (LIST_TRAVERSE(lsg, lnp, sgp))
		_Dbg_seg_desc_entry(mach, ndx++, sgp);
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
	Listnode	*lnp;
	Is_desc		*isp;

	if (DBG_NOTCLASS(DBG_SEGMENTS))
		return;

	dbg_print(MSG_ORIG(MSG_SEC_NAME), ndx, osp->os_name);
	Elf_shdr_entry(ofl->ofl_e_machine, osp->os_shdr);
	Gelf_elf_data_title();
	_Dbg_elf_data_out(osp);

	if (DBG_NOTDETAIL())
		return;

	for (LIST_TRAVERSE(&(osp->os_isdescs), lnp, isp))
		_Dbg_elf_data_in(osp, isp);
}
