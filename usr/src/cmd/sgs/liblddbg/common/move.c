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
 *	Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Debug functions
 */

#if	!defined(_ELF64)
void
Dbg_move_adjexpandreloc(ulong_t offset, const char *name)
{
	if (DBG_NOTCLASS(DBG_MOVE|DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_MV_ADJEXPAND1), _Dbg_sym_dem(name),
	    EC_XWORD(offset));
}

void
Dbg_move_adjmovereloc(ulong_t offset1, ulong_t offset2, const char *name)
{
	if (DBG_NOTCLASS(DBG_MOVE|DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_MV_ADJMOVE1), _Dbg_sym_dem(name),
	    EC_XWORD(offset1), EC_XWORD(offset2));
}
#endif	/* !defined(_ELF64) */

void
Dbg_move_outsctadj(Sym_desc * sdp)
{
	if (DBG_NOTCLASS(DBG_MOVE|DBG_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_MV_OUTSCTADJ1), _Dbg_sym_dem(sdp->sd_name));
}

#if	!defined(_ELF64)
void
Dbg_move_parexpn(const char *name, const char *reason)
{
	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_MV_EXPAND0), name, reason);
	dbg_print(MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_outmove(const unsigned char *name)
{
	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_MV_OUTMOVE0), name);
	dbg_print(MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_expanding(Move *mv, Addr addr)
{
	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_MV_EXPAND1), EC_ADDR(addr),
	    EC_LWORD(mv->m_value));
}


void
Dbg_move_input1(const char *name)
{
	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_MOVE_INPUT1), name);
	dbg_print(MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_data(const char *name)
{
	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_MV_MOVEDATA), _Dbg_sym_dem(name));
	dbg_print(MSG_INTL(MSG_MOVE_TITLE2));
}
#endif	/* !defined(_ELF64) */

void
Dbg_move_mventry(int which, Move *mv, Sym_desc *s)
{
	const char *str;

	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (which)
		str = MSG_INTL(MSG_MOVE_MVENTRY2);
	else
		str = MSG_INTL(MSG_MOVE_MVENTRY1);

	dbg_print(str, EC_XWORD(mv->m_poffset), EC_LWORD(mv->m_value),
		mv->m_repeat, mv->m_stride, s->sd_name);
}

void
Dbg_move_mventry2(Move *mv, Word st_name, char *name)
{
	const char *sname;

	if (st_name)
		sname = (const char *)name;
	else
		sname = MSG_INTL(MSG_STR_UNKNOWN);

	if (DBG_NOTCLASS(DBG_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;
	dbg_print(MSG_INTL(MSG_MOVE_MVENTRY1),
		EC_XWORD(mv->m_poffset),
		EC_LWORD(mv->m_value),
		mv->m_repeat,
		mv->m_stride,
		sname);
}
