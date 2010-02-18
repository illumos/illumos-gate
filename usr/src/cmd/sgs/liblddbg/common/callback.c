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

void
Dbg_cb_iphdr_enter(Lm_list *lml, u_longlong_t cnt_map, u_longlong_t cnt_unmap)
{
	if (DBG_NOTCLASS(DBG_C_CALLBACK))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_ENTER));
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_MAPCNT), cnt_map, cnt_unmap);
}

void
Dbg_cb_iphdr_callback(Lm_list *lml, struct dl_phdr_info *info)
{
	if (DBG_NOTCLASS(DBG_C_CALLBACK))
		return;

	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_CALLBACK));
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_NAME), info->dlpi_name);
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_ADDR), EC_ADDR(info->dlpi_addr));
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_PHDR),
	    EC_ADDR(CAST_PTRINT(Addr, info->dlpi_phdr)),
	    EC_WORD(info->dlpi_phnum));

}

void
Dbg_cb_iphdr_mapchange(Lm_list *lml, u_longlong_t cnt_map,
    u_longlong_t cnt_unmap)
{
	if (DBG_NOTCLASS(DBG_C_CALLBACK))
		return;

	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_MAPCNG));
	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_MAPCNT), cnt_map, cnt_unmap);
}

void
Dbg_cb_iphdr_unmap_ret(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_CALLBACK))
		return;

	dbg_print(lml, MSG_INTL(MSG_CB_IPHDR_UNMAP));
}
