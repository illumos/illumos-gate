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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include	<stdio.h>
#include	<string.h>
#include	"msg.h"
#include	"_libld.h"


/*
 * Print a virtual address map of input and output sections together with
 * multiple symbol definitions (if they exist).
 */
static Boolean	symbol_title = TRUE;

static void
sym_muldef_title()
{
	(void) printf(MSG_INTL(MSG_ENT_MUL_FMT_TIL_0),
	    MSG_INTL(MSG_ENT_MUL_TIL_0));
	(void) printf(MSG_INTL(MSG_ENT_MUL_FMT_TIL_1),
	    MSG_INTL(MSG_ENT_MUL_ITM_SYM),
	    MSG_INTL(MSG_ENT_MUL_ITM_DEF_0),
	    MSG_INTL(MSG_ENT_MUL_ITM_DEF_1));
	symbol_title = FALSE;
}

void
ld_map_out(Ofl_desc *ofl)
{
	Sg_desc		*sgp;
	Is_desc		*isp;
	Sym_avlnode	*sav;
	Aliste		idx1;

	(void) printf(MSG_INTL(MSG_ENT_MAP_FMT_TIL_1),
	    MSG_INTL(MSG_ENT_MAP_TITLE_1));
	if (ofl->ofl_flags & FLG_OF_RELOBJ)
		(void) printf(MSG_INTL(MSG_ENT_MAP_FMT_TIL_2),
		    MSG_INTL(MSG_ENT_ITM_OUTPUT),
		    MSG_INTL(MSG_ENT_ITM_INPUT),
		    MSG_INTL(MSG_ENT_ITM_NEW),
		    MSG_INTL(MSG_ENT_ITM_SECTION),
		    MSG_INTL(MSG_ENT_ITM_SECTION),
		    MSG_INTL(MSG_ENT_ITM_DISPMNT),
		    MSG_INTL(MSG_ENT_ITM_SIZE));
	else
		(void) printf(MSG_INTL(MSG_ENT_MAP_FMT_TIL_3),
		    MSG_INTL(MSG_ENT_ITM_OUTPUT),
		    MSG_INTL(MSG_ENT_ITM_INPUT),
		    MSG_INTL(MSG_ENT_ITM_VIRTUAL),
		    MSG_INTL(MSG_ENT_ITM_SECTION),
		    MSG_INTL(MSG_ENT_ITM_SECTION),
		    MSG_INTL(MSG_ENT_ITM_ADDRESS),
		    MSG_INTL(MSG_ENT_ITM_SIZE));

	for (APLIST_TRAVERSE(ofl->ofl_segs, idx1, sgp)) {
		Os_desc	*osp;
		Aliste	idx2;

		if (sgp->sg_phdr.p_type != PT_LOAD)
			continue;

		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx2, osp)) {
			int	os_isdescs_idx;
			Aliste	idx3;

			(void) printf(MSG_INTL(MSG_ENT_MAP_ENTRY_1),
			    osp->os_name, EC_ADDR(osp->os_shdr->sh_addr),
			    EC_XWORD(osp->os_shdr->sh_size));

			OS_ISDESCS_TRAVERSE(os_isdescs_idx, osp, idx3, isp) {
				Addr	addr;

				/*
				 * Although there seems little point in printing
				 * discarded (empty) sections, especially as
				 * diagnostics under -Dsegments,details are more
				 * informative, continue printing them.  There
				 * are user scripts, fragile to say the least,
				 * that grep(1) through load-map output to
				 * discover object requirements.  These scripts
				 * don't grep for all input sections types (ie.
				 * .picdata), and have become dependent on null
				 * sections (ie. .text) existing in the
				 * load-map output.
				 */
				if (isp->is_flags & FLG_IS_DISCARD) {
					addr = 0;
				} else {
					addr = (Addr)
					    _elf_getxoff(isp->is_indata);
					if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
						addr += isp->is_osdesc->
						    os_shdr->sh_addr;
				}

				(void) printf(MSG_INTL(MSG_ENT_MAP_ENTRY_2),
				    isp->is_name, EC_ADDR(addr),
				    EC_XWORD(isp->is_shdr->sh_size),
				    ((isp->is_file != NULL) ?
				    (char *)(isp->is_file->ifl_name) :
				    MSG_INTL(MSG_STR_NULL)));
			}
		}
	}

	if (ofl->ofl_flags & FLG_OF_RELOBJ)
		return;

	/*
	 * Check for any multiply referenced symbols (ie. symbols that have
	 * been overridden from a shared library).
	 */
	for (sav = avl_first(&ofl->ofl_symavl); sav;
	    sav = AVL_NEXT(&ofl->ofl_symavl, sav)) {
		Sym_desc	*sdp = sav->sav_sdp;
		const char	*name = sdp->sd_name, *ducp, *adcp;
		APlist		*dfiles;
		Aliste		idx;

		if (((dfiles = sdp->sd_aux->sa_dfiles) == NULL) ||
		    (aplist_nitems(dfiles) == 1))
			continue;

		/*
		 * Files that define a symbol are saved on the `sa_dfiles' list.
		 * Ignore symbols that aren't needed, and any special symbols
		 * that the link editor may produce (symbols of type ABS and
		 * COMMON are not recorded in the first place, however functions
		 * like _init() and _fini() commonly have multiple occurrences).
		 */
		if ((sdp->sd_ref == REF_DYN_SEEN) ||
		    (sdp->sd_aux->sa_symspec) ||
		    (strcmp(MSG_ORIG(MSG_SYM_FINI_U), name) == 0) ||
		    (strcmp(MSG_ORIG(MSG_SYM_INIT_U), name) == 0) ||
		    (strcmp(MSG_ORIG(MSG_SYM_LIBVER_U), name) == 0))
			continue;

		if (symbol_title)
			sym_muldef_title();

		ducp = sdp->sd_file->ifl_name;
		(void) printf(MSG_INTL(MSG_ENT_MUL_ENTRY_1), demangle(name),
		    ducp);
		for (APLIST_TRAVERSE(dfiles, idx, adcp)) {
			/*
			 * Ignore the referenced symbol.
			 */
			if (strcmp(adcp, ducp) != 0)
				(void) printf(MSG_INTL(MSG_ENT_MUL_ENTRY_2),
				    adcp);
		}
	}
}

/*
 * Traverse the entrance criteria list searching for those sections that haven't
 * been met and print error message.  (only in the case of reordering)
 */
void
ld_ent_check(Ofl_desc * ofl)
{
	Ent_desc	*enp;
	Aliste		ndx;

	/*
	 *  Try to give as much information to the user about the specific
	 *  line in the mapfile.  If the line contains a file name then
	 *  output the filename too.  Hence we have two warning lines -
	 *  one for criterias where a filename is used and the other
	 *  for those without a filename.
	 */
	for (APLIST_TRAVERSE(ofl->ofl_ents, ndx, enp)) {
		/*
		 * No warning if any of the following hold:
		 * -	The segment has no entrance criteria requiring
		 *	input section sorting (FLG_SG_IS_ORDER not set).
		 * -	The entrance criteria was used to place a section.
		 * -	The specific entrance criteria does not require sorting
		 */
		if (((enp->ec_segment->sg_flags & FLG_SG_IS_ORDER) == 0) ||
		    (enp->ec_flags & FLG_EC_USED) || (enp->ec_ordndx == 0))
			continue;


		if (alist_nitems(enp->ec_files) > 0) {
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_ENT_NOSEC_1),
			    enp->ec_segment->sg_name, enp->ec_is_name);
		} else {
			ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_ENT_NOSEC_2),
			    enp->ec_segment->sg_name, enp->ec_is_name);
		}
	}
}
