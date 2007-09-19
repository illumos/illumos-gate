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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Print out a single `entry descriptor' entry.
 */
void
Dbg_ent_entry(Lm_list *lml, Half mach, Ent_desc *enp)
{
	Conv_inv_buf_t		inv_buf;
	Conv_sec_flags_buf_t	sec_flags_buf;
	Listnode		*lnp;
	char			*cp;

	dbg_print(lml, MSG_ORIG(MSG_ECR_NAME),
	    (enp->ec_name ? enp->ec_name : MSG_INTL(MSG_STR_NULL)),
	    conv_sec_flags(enp->ec_attrmask, 0, &sec_flags_buf));

	dbg_print(lml, MSG_ORIG(MSG_ECR_SEGMENT),
	    (enp->ec_segment->sg_name ? enp->ec_segment->sg_name :
	    MSG_INTL(MSG_STR_NULL)),
	    conv_sec_flags(enp->ec_attrbits, 0, &sec_flags_buf));

	dbg_print(lml, MSG_ORIG(MSG_ECR_NDX), EC_WORD(enp->ec_ndx),
	    conv_sec_type(mach, enp->ec_type, 0, &inv_buf));

	if (enp->ec_files.head) {
		dbg_print(lml, MSG_ORIG(MSG_ECR_FILES));
		for (LIST_TRAVERSE(&(enp->ec_files), lnp, cp))
			dbg_print(lml, MSG_ORIG(MSG_ECR_FILE), cp);
	}
}

/*
 * Print out all `entrance descriptor' entries.
 */
void
Dbg_ent_print(Lm_list *lml, Half mach, List *len, Boolean dmode)
{
	Listnode	*lnp;
	Ent_desc	*enp;
	int		ndx = 1;

	if (DBG_NOTCLASS(DBG_C_ENTRY))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_ECR_TITLE),
	    (dmode ? MSG_INTL(MSG_ECR_DYNAMIC) : MSG_INTL(MSG_ECR_STATIC)));

	for (LIST_TRAVERSE(len, lnp, enp)) {
		dbg_print(lml, MSG_INTL(MSG_ECR_DESC), ndx++);
		Dbg_ent_entry(lml, mach, enp);
	}
}
