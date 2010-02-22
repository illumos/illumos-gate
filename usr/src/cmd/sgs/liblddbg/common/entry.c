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

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Print out a single `entry descriptor' entry.
 */
void
Dbg_ent_entry(Lm_list *lml, uchar_t osabi, Half mach, Ent_desc *enp)
{
	union {
		Conv_inv_buf_t			inv;
		Conv_sec_flags_buf_t		sec_flags;
		Conv_ent_flags_buf_t		ent_flags;
		Conv_ent_files_flags_buf_t	ent_files_flags;
	} buf;
	Aliste			idx;
	Ent_desc_file		*edfp;

	if (enp->ec_name != NULL)
		dbg_print(lml, MSG_ORIG(MSG_ECR_NAME), enp->ec_name);

	dbg_print(lml, MSG_ORIG(MSG_ECR_FLAGS),
	    conv_ent_flags(enp->ec_flags, &buf.ent_flags));

	dbg_print(lml, MSG_ORIG(MSG_ECR_IS_NAME),
	    (enp->ec_is_name ? enp->ec_is_name : MSG_INTL(MSG_STR_NULL)),
	    conv_sec_flags(osabi, mach, enp->ec_attrmask, 0, &buf.sec_flags));

	dbg_print(lml, MSG_ORIG(MSG_ECR_SEGMENT),
	    (enp->ec_segment->sg_name ? enp->ec_segment->sg_name :
	    MSG_INTL(MSG_STR_NULL)),
	    conv_sec_flags(osabi, mach, enp->ec_attrbits, 0, &buf.sec_flags));

	dbg_print(lml, MSG_ORIG(MSG_ECR_NDX), EC_WORD(enp->ec_ordndx),
	    conv_sec_type(osabi, mach, enp->ec_type, 0, &buf.inv));

	if (enp->ec_files) {
		dbg_print(lml, MSG_ORIG(MSG_ECR_FILES));
		for (ALIST_TRAVERSE(enp->ec_files, idx, edfp))
			dbg_print(lml, MSG_ORIG(MSG_ECR_FILE),
			    conv_ent_files_flags(edfp->edf_flags, 0,
			    &buf.ent_files_flags), edfp->edf_name);
	}
}

/*
 * Print out all `entrance descriptor' entries.
 */
void
Dbg_ent_print(Lm_list *lml, uchar_t osabi, Half mach, APlist *alp)
{
	Ent_desc	*enp;
	Aliste		ndx;

	if (DBG_NOTCLASS(DBG_C_ENTRY))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_ECR_TITLE));

	for (APLIST_TRAVERSE(alp, ndx, enp)) {
		dbg_print(lml, MSG_INTL(MSG_ECR_DESC), EC_WORD(ndx));
		Dbg_ent_entry(lml, osabi, mach, enp);
	}
}
