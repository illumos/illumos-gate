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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
ld_map_out(Ofl_desc * ofl)
{
	Listnode *	lnp1, * lnp2, * lnp3;
	Sg_desc *	sgp;
	Is_desc *	isp;
	Sym_avlnode	*sav;

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

	for (LIST_TRAVERSE(&ofl->ofl_segs, lnp1, sgp)) {
		Os_desc	*osp;
		Aliste	idx;

		if (sgp->sg_phdr.p_type != PT_LOAD)
			continue;

		for (APLIST_TRAVERSE(sgp->sg_osdescs, idx, osp)) {

			(void) printf(MSG_INTL(MSG_ENT_MAP_ENTRY_1),
			    osp->os_name, EC_ADDR(osp->os_shdr->sh_addr),
			    EC_XWORD(osp->os_shdr->sh_size));

			for (LIST_TRAVERSE(&(osp->os_isdescs), lnp3, isp)) {
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
		Sym_desc	*sdp;
		const char	*name, *ducp, *adcp;
		List		*dfiles;

		sdp = sav->sav_symdesc;
		name = sdp->sd_name;
		dfiles = &sdp->sd_aux->sa_dfiles;

		/*
		 * Files that define a symbol are saved on the
		 * `sa_dfiles' list, if the head and tail of
		 * this list differ there must have been more
		 * than one symbol definition.  Ignore symbols
		 * that aren't needed, and any special symbols
		 * that the link editor may produce (symbols of
		 * type ABS and COMMON are not recorded in the
		 * first place, however functions like _init()
		 * and _fini() commonly have multiple
		 * occurrances).
		 */
		if ((sdp->sd_ref == REF_DYN_SEEN) ||
		    (dfiles->head == dfiles->tail) ||
		    (sdp->sd_aux && sdp->sd_aux->sa_symspec) ||
		    (strcmp(MSG_ORIG(MSG_SYM_FINI_U), name) == 0) ||
		    (strcmp(MSG_ORIG(MSG_SYM_INIT_U), name) == 0) ||
		    (strcmp(MSG_ORIG(MSG_SYM_LIBVER_U), name) == 0))
			continue;

		if (symbol_title)
			sym_muldef_title();

		ducp = sdp->sd_file->ifl_name;
		(void) printf(MSG_INTL(MSG_ENT_MUL_ENTRY_1), demangle(name),
		    ducp);
		for (LIST_TRAVERSE(dfiles, lnp2, adcp)) {
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
	Listnode *	lnp;
	Ent_desc *	enp;

	/*
	 *  Try to give as much information to the user about the specific
	 *  line in the mapfile.  If the line contains a file name then
	 *  output the filename too.  Hence we have two warning lines -
	 *  one for criterias where a filename is used and the other
	 *  for those without a filename.
	 */
	for (LIST_TRAVERSE(&ofl->ofl_ents, lnp, enp)) {
		if ((enp->ec_segment->sg_flags & FLG_SG_ORDER) &&
		    !(enp->ec_flags & FLG_EC_USED) && enp->ec_ndx) {
			Listnode *	_lnp = enp->ec_files.head;

			if ((_lnp != NULL) && (_lnp->data != NULL) &&
			    (char *)(_lnp->data) != NULL) {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_ENT_NOSEC_1),
				    enp->ec_segment->sg_name, enp->ec_name,
				    (const char *)(_lnp->data));
			} else {
				eprintf(ofl->ofl_lml, ERR_WARNING,
				    MSG_INTL(MSG_ENT_NOSEC_2),
				    enp->ec_segment->sg_name, enp->ec_name);
			}
		}
	}
}
