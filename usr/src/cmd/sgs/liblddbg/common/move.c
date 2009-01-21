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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

void
Dbg_move_data(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_FILE), NAME(lmp));
	dbg_print(lml, MSG_INTL(MSG_MOVE_TITLE2));
}

void
Dbg_move_adjexpandreloc(Lm_list *lml, Xword offset, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_MOVE | DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_ADJEXPAND), Dbg_demangle_name(name),
	    EC_XWORD(offset));
}

void
Dbg_move_adjmovereloc(Lm_list *lml, Xword offset1, Xword offset2,
    const char *name)
{
	if (DBG_NOTCLASS(DBG_C_MOVE | DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_ADJMOVE), Dbg_demangle_name(name),
	    EC_XWORD(offset1), EC_XWORD(offset2));
}

void
Dbg_move_outsctadj(Lm_list *lml, Sym_desc *sdp)
{
	if (DBG_NOTCLASS(DBG_C_MOVE | DBG_C_RELOC))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_OUTSCTADJ),
	    Dbg_demangle_name(sdp->sd_name));
}

void
Dbg_move_parexpn(Lm_list *lml, const char *name, const char *reason)
{
	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MOVE_PAREXPN), name, reason);
	dbg_print(lml, MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_outmove(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MOVE_OUTMOVE), name);
	dbg_print(lml, MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_expand(Lm_list *lml, Move *mv, Addr addr)
{
	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_EXPAND), EC_ADDR(addr),
	    EC_LWORD(mv->m_value));
}

void
Dbg_move_input(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_MOVE_INPUT), name);
	dbg_print(lml, MSG_INTL(MSG_MOVE_TITLE1));
}

void
Dbg_move_entry1(Lm_list *lml, int which, Move *mv, Sym_desc *s)
{
	const char *str;

	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (which)
		str = MSG_INTL(MSG_MOVE_ENTRYIN);
	else
		str = MSG_INTL(MSG_MOVE_ENTRYOUT);

	dbg_print(lml, str, EC_XWORD(mv->m_poffset), EC_LWORD(mv->m_value),
	    mv->m_repeat, mv->m_stride, s->sd_name);
}

void
Dbg_move_entry2(Lm_list *lml, Move *mv, Word st_name, const char *name)
{
	const char *sname;

	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (st_name)
		sname = name;
	else
		sname = MSG_INTL(MSG_STR_UNKNOWN);

	dbg_print(lml, MSG_INTL(MSG_MOVE_ENTRYIN), EC_XWORD(mv->m_poffset),
	    EC_LWORD(mv->m_value), mv->m_repeat, mv->m_stride, sname);
}

void
Dbg_move_bad(Lm_list *lml, ulong_t num, const char *name, Addr addr)
{
	if (DBG_NOTCLASS(DBG_C_MOVE))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_MOVE_BAD), EC_XWORD(num), name,
	    EC_ADDR(addr));
}
