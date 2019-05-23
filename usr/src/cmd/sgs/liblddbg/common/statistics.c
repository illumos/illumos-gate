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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<stdio.h>
#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"

static const char *
fmt_human_units(size_t bytes, char *buf, size_t bufsize)
{
	static int	unit_arr[] = { 'K', 'M', 'G', 'T' };

	int		i, unit_ch;
	size_t		unit_bytes = bytes;

	/* Convert to human readable units */
	for (i = 0; i < sizeof (unit_arr) / sizeof (unit_arr[0]); i++) {
		if (unit_bytes < 1024)
			break;
		unit_ch = unit_arr[i];
		unit_bytes /= 1024;
	}
	if (unit_bytes == bytes)
		buf[0] = '\0';
	else
		(void) snprintf(buf, bufsize, MSG_ORIG(MSG_FMT_MEMUNIT),
		    EC_XWORD(unit_bytes), unit_ch);

	return (buf);
}

/*
 * Generate a relocation cache statistics line for the active or
 * output relocation cache.
 *
 * entry:
 *	ofl - output file descriptor
 *	alp - One of ofl->ofl_actrels or ofl->ofl_outrels.
 */
static void
rel_cache_statistics(Ofl_desc *ofl, const char *title, APlist *alp)
{
	Lm_list		*lml = ofl->ofl_lml;
	size_t		desc_cnt = 0, desc_used = 0, bytes;
	Aliste		idx;
	Rel_cachebuf	*rcp;
	char		unit_buf[CONV_INV_BUFSIZE + 10];

	/* Sum the total memory allocated across all the buffers */
	for (APLIST_TRAVERSE(alp, idx, rcp)) {
		desc_cnt += rcp->rc_end - rcp->rc_arr;
		desc_used += rcp->rc_free - rcp->rc_arr;
	}
	bytes = desc_cnt * sizeof (Rel_desc);

	dbg_print(lml, MSG_INTL(MSG_STATS_REL_CACHE), title,
	    EC_WORD(aplist_nitems(alp)),
	    EC_XWORD(desc_used), EC_XWORD(desc_cnt),
	    (desc_cnt == 0) ? 100 : EC_WORD((desc_used * 100) / desc_cnt),
	    EC_XWORD(bytes),
	    fmt_human_units(bytes, unit_buf, sizeof (unit_buf)));
}


/*
 * Generate a statistics line for the auxiliary relocation descriptor cache.
 *
 * entry:
 *	ofl - output file descriptor
 */
static void
rel_aux_cache_statistics(Ofl_desc *ofl)
{
	Rel_aux_cachebuf	*racp;
	Lm_list	*lml = ofl->ofl_lml;
	size_t	desc_cnt = 0, desc_used = 0, bytes;
	Aliste	idx;
	char	unit_buf[CONV_INV_BUFSIZE + 10];

	/* Sum the total memory allocated across all the buffers */
	for (APLIST_TRAVERSE(ofl->ofl_relaux, idx, racp)) {
		desc_cnt += racp->rac_end - racp->rac_arr;
		desc_used += racp->rac_free - racp->rac_arr;
	}
	bytes = desc_cnt * sizeof (Rel_desc);

	dbg_print(lml, MSG_INTL(MSG_STATS_REL_ACACHE),
	    EC_WORD(aplist_nitems(ofl->ofl_relaux)),
	    EC_XWORD(desc_used), EC_XWORD(desc_cnt),
	    (desc_cnt == 0) ? 100 : EC_WORD((desc_used * 100) / desc_cnt),
	    EC_XWORD(bytes),
	    fmt_human_units(bytes, unit_buf, sizeof (unit_buf)));
}


void
Dbg_statistics_ld(Ofl_desc *ofl)
{
	Lm_list	*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_STATS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_STATS_GENERAL));

	if (ofl->ofl_objscnt || ofl->ofl_soscnt || ofl->ofl_arscnt) {
		dbg_print(lml, MSG_INTL(MSG_STATS_FILES),
		    EC_XWORD(ofl->ofl_objscnt), EC_XWORD(ofl->ofl_soscnt),
		    EC_XWORD(ofl->ofl_arscnt));
	}

	if (ofl->ofl_locscnt || ofl->ofl_globcnt) {
		dbg_print(lml, MSG_INTL(MSG_STATS_SYMBOLS_OUT),
		    EC_XWORD(ofl->ofl_globcnt), EC_XWORD(ofl->ofl_locscnt));
	}
	if (ofl->ofl_entercnt || ofl->ofl_scopecnt || ofl->ofl_elimcnt) {
		dbg_print(lml, MSG_INTL(MSG_STATS_SYMBOLS_IN),
		    EC_XWORD(ofl->ofl_entercnt), EC_XWORD(ofl->ofl_scopecnt),
		    EC_XWORD(ofl->ofl_elimcnt));
	}

	dbg_print(lml, MSG_INTL(MSG_STATS_REL_OUT),
	    EC_XWORD(ofl->ofl_outrels.rc_cnt));

	dbg_print(lml, MSG_INTL(MSG_STATS_REL_IN),
	    EC_XWORD(ofl->ofl_entrelscnt), EC_XWORD(ofl->ofl_actrels.rc_cnt));

	dbg_print(lml, MSG_INTL(MSG_STATS_REL_TICACHE));
	rel_cache_statistics(ofl, MSG_INTL(MSG_STATS_REL_TIOUT),
	    ofl->ofl_outrels.rc_list);
	rel_cache_statistics(ofl, MSG_INTL(MSG_STATS_REL_TIACT),
	    ofl->ofl_actrels.rc_list);
	rel_aux_cache_statistics(ofl);
}

void
Dbg_statistics_ar(Ofl_desc *ofl)
{
	Aliste		idx;
	Ar_desc		*adp;
	Elf_Arsym	*arsym;
	Ar_aux		*aux;
	Lm_list		*lml = ofl->ofl_lml;

	if (DBG_NOTCLASS(DBG_C_STATS | DBG_C_UNUSED))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	for (APLIST_TRAVERSE(ofl->ofl_ars, idx, adp)) {
		size_t	poffset = 0;
		uint_t	count = 0, used = 0;

		if ((adp->ad_flags & FLG_ARD_EXTRACT) == 0) {
			Dbg_unused_file(lml, adp->ad_name, 0, 0);
			continue;
		}

		if (DBG_NOTCLASS(DBG_C_STATS))
			continue;

		arsym = adp->ad_start;
		aux = adp->ad_aux;
		while ((arsym != NULL) && (arsym->as_off != NULL)) {
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

		dbg_print(lml, MSG_INTL(MSG_STATS_AR), adp->ad_name, count,
		    used, ((used * 100) / count));
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}
