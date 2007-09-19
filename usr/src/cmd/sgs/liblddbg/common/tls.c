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

#include	<link.h>
#include	<libc_int.h>
#include	<rtld.h>
#include	<strings.h>
#include	<debug.h>
#include	"msg.h"
#include	"_debug.h"

#define	FLAGSZ	CONV_EXPN_FIELD_DEF_PREFIX_SIZE + \
		MSG_TLS_FLAG_STATIC_SIZE + CONV_EXPN_FIELD_DEF_SEP_SIZE + \
		CONV_INV_BUFSIZE + CONV_EXPN_FIELD_DEF_SUFFIX_SIZE

static void
Dbg_tls_modent(Lm_list *lml, TLS_modinfo * tmodent)
{
	static char	flagstr[FLAGSZ];
	static Val_desc	vda[] = {
		{ TM_FLG_STATICTLS,	MSG_ORIG(MSG_TLS_FLAG_STATIC) },
		{ 0,			0 }
	};
	static CONV_EXPN_FIELD_ARG conv_arg = { flagstr,
		sizeof (flagstr), vda };

	ulong_t	flags;

	if ((flags = tmodent->tm_flags) != 0) {
		conv_arg.oflags = conv_arg.rflags = flags;
		(void) conv_expn_field(&conv_arg, 0);
	} else {
		flagstr[0] = '\0';
	}

	dbg_print(lml, MSG_INTL(MSG_TLS_MODENT1),
	    EC_XWORD((uintptr_t)tmodent->tm_tlsblock),
	    EC_XWORD(tmodent->tm_stattlsoffset), EC_XWORD(tmodent->tm_flags),
	    flagstr);
	dbg_print(lml, MSG_INTL(MSG_TLS_MODENT2),
	    EC_XWORD(tmodent->tm_filesz), EC_XWORD(tmodent->tm_memsz),
	    EC_XWORD(tmodent->tm_modid));
}

void
Dbg_tls_static_block(Lm_list *lml, void *list, ulong_t size, ulong_t resv)
{
	if (DBG_NOTCLASS(DBG_C_TLS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);

	if (list) {
		ulong_t		ndx;
		TLS_modinfo	**tlsmodlist;

		tlsmodlist = (TLS_modinfo **)list;

		for (ndx = 0; tlsmodlist[ndx]; ndx++) {
			dbg_print(lml, MSG_INTL(MSG_TLS_STATBLOCK1), ndx,
			    tlsmodlist[ndx]->tm_modname);
			Dbg_tls_modent(lml, tlsmodlist[ndx]);
			Dbg_util_nl(lml, DBG_NL_STD);
		}
	}
	dbg_print(lml, MSG_INTL(MSG_TLS_STATBLOCK2), EC_XWORD(size),
	    EC_XWORD(resv));
}

void
Dbg_tls_static_resv(Rt_map *lmp, ulong_t size, ulong_t resv)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_TLS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_TLS_STATBLOCK3), TLSMODID(lmp), NAME(lmp),
	    EC_XWORD(size), EC_XWORD(resv));
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
