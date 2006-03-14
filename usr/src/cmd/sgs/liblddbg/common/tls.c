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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<link.h>
#include	<libc_int.h>
#include	<rtld.h>
#include	<debug.h>
#include	"msg.h"
#include	"_debug.h"

static void
Dbg_tls_modent(Lm_list *lml, TLS_modinfo * tmodent)
{
	dbg_print(lml, MSG_INTL(MSG_TLS_STMODENT1),
	    EC_XWORD((uintptr_t)tmodent->tm_tlsblock),
	    EC_XWORD(tmodent->tm_stattlsoffset), EC_XWORD(tmodent->tm_flags));
	dbg_print(lml, MSG_INTL(MSG_TLS_STMODENT2),
	    EC_XWORD(tmodent->tm_filesz), EC_XWORD(tmodent->tm_memsz),
	    EC_XWORD(tmodent->tm_modid));
}

void
Dbg_tls_static_block(Lm_list *lml, void *vtlsmodlist, ulong_t tlsstatsize)
{
	uint_t		i;
	TLS_modinfo **	tlsmodlist;

	if (DBG_NOTCLASS(DBG_C_TLS))
		return;

	tlsmodlist = (TLS_modinfo **)vtlsmodlist;
	Dbg_util_nl(lml, DBG_NL_STD);

	for (i = 0; tlsmodlist[i]; i++) {
		dbg_print(lml, MSG_INTL(MSG_TLS_STATBLOCK1), i,
		    tlsmodlist[i]->tm_modname);
		Dbg_tls_modent(lml, tlsmodlist[i]);
	}
	dbg_print(lml, MSG_INTL(MSG_TLS_STATBLOCK2), EC_XWORD(tlsstatsize));
}

void
Dbg_tls_modactivity(Lm_list *lml, void *vtlsmodent, uint_t flag)
{
	const char	*str;
	TLS_modinfo	*tlsmodent;

	if (DBG_NOTCLASS(DBG_C_TLS))
		return;

	if (flag == TM_FLG_MODADD)
		str = MSG_INTL(MSG_TLS_ADD);
	else
		str = MSG_INTL(MSG_TLS_REMOVE);

	tlsmodent = (TLS_modinfo *)vtlsmodent;
	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_TLS_MODACT), str, tlsmodent->tm_modname);
	Dbg_tls_modent(lml, tlsmodent);
}
