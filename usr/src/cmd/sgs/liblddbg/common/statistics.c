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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"

void
Dbg_statistics_ld(Ofl_desc *ofl)
{
	if (DBG_NOTCLASS(DBG_STATISTICS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_STATS_GENERAL));

	if (ofl->ofl_objscnt || ofl->ofl_soscnt || ofl->ofl_arscnt) {
		dbg_print(MSG_INTL(MSG_STATS_FILES),
		    EC_XWORD(ofl->ofl_objscnt), EC_XWORD(ofl->ofl_soscnt),
		    EC_XWORD(ofl->ofl_arscnt));
	}

	if (ofl->ofl_locscnt || ofl->ofl_globcnt) {
		dbg_print(MSG_INTL(MSG_STATS_SYMBOLS_OUT),
		    EC_XWORD(ofl->ofl_globcnt), EC_XWORD(ofl->ofl_locscnt));
	}
	if (ofl->ofl_entercnt || ofl->ofl_scopecnt || ofl->ofl_elimcnt) {
		dbg_print(MSG_INTL(MSG_STATS_SYMBOLS_IN),
		    EC_XWORD(ofl->ofl_entercnt), EC_XWORD(ofl->ofl_scopecnt),
		    EC_XWORD(ofl->ofl_elimcnt));
	}

	if (ofl->ofl_outrelscnt) {
		dbg_print(MSG_INTL(MSG_STATS_RELOCS_OUT),
		    EC_XWORD(ofl->ofl_outrelscnt));
	}
	if (ofl->ofl_entrelscnt || ofl->ofl_actrelscnt) {
		dbg_print(MSG_INTL(MSG_STATS_RELOCS_IN),
		    EC_XWORD(ofl->ofl_entrelscnt),
		    EC_XWORD(ofl->ofl_actrelscnt));
	}
}

void
Dbg_statistics_ar(Ofl_desc *ofl)
{
	Listnode	*lnp;
	Ar_desc		*adp;
	Elf_Arsym	*arsym;
	Ar_aux		*aux;

	if (DBG_NOTCLASS(DBG_STATISTICS | DBG_UNUSED))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	for (LIST_TRAVERSE(&ofl->ofl_ars, lnp, adp)) {
		size_t	poffset = 0;
		uint_t	count = 0, used = 0;

		if ((adp->ad_flags & FLG_ARD_EXTRACT) == 0) {
			Dbg_unused_file(adp->ad_name, 0);
			continue;
		}

		if (DBG_NOTCLASS(DBG_STATISTICS))
			continue;

		arsym = adp->ad_start;
		aux = adp->ad_aux;
		while (arsym->as_off) {
			/*
			 * Assume that symbols from the same member file are
			 * adjacent within the archive symbol table.
			 */
			if (poffset != arsym->as_off) {
				count++;
				poffset = arsym->as_off;
				if (aux->au_mem == FLG_ARMEM_PROC)
					used++;
			}
			aux++, arsym++;
		}
		if ((count == 0) || (used == 0))
			continue;
#ifndef	UDIV_NOT_SUPPORTED
		dbg_print(MSG_INTL(MSG_STATS_AR), adp->ad_name, count, used,
		    ((used * 100) / count));
#endif
	}
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}
