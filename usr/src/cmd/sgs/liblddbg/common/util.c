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

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

/*
 * Generic new line generator.
 */
void
Dbg_util_nl()
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

/*
 * If any run-time linker debugging is being carried out always indicate the
 * fact and specify the point at which we transfer control to the main program.
 */
void
Dbg_util_call_main(const char *name)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_TRANS), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_call_init(const char *name, int flag)
{
	const char *str;

	if (DBG_NOTCLASS(DBG_INIT))
		return;

	if (flag == DBG_INIT_SORT)
		str = MSG_INTL(MSG_UTL_SORT);
	else if (flag == DBG_INIT_PEND)
		str = MSG_INTL(MSG_UTL_PEND);
	else if (flag == DBG_INIT_DYN)
		str = MSG_INTL(MSG_UTL_DYN);
	else
		str = MSG_INTL(MSG_UTL_DONE);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_INIT), str, name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_no_init(const char *name)
{
	if (DBG_NOTCLASS(DBG_INIT))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_NOINIT), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_intoolate(const char *name)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_INTOOLATE), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_dbnotify(rd_event_e event, r_state_e state)
{
	const char	*estr;
	const char	*sstr;

	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	switch (event) {
	case RD_PREINIT:
		estr = MSG_ORIG(MSG_UTL_EVNT_PREINIT);
		sstr = MSG_INTL(MSG_STR_NULL);
		break;
	case RD_POSTINIT:
		estr = MSG_ORIG(MSG_UTL_EVNT_POSTINIT);
		sstr = MSG_INTL(MSG_STR_NULL);
		break;
	case RD_DLACTIVITY:
		estr = MSG_ORIG(MSG_UTL_EVNT_DLACT);
		switch (state) {
		case RT_CONSISTENT:
			sstr = MSG_ORIG(MSG_UTL_STA_CONSIST);
			break;
		case RT_ADD:
			sstr = MSG_ORIG(MSG_UTL_STA_ADD);
			break;
		case RT_DELETE:
			sstr = MSG_ORIG(MSG_UTL_STA_DELETE);
			break;
		default:
			sstr = MSG_INTL(MSG_STR_NULL);
			break;
		}
		break;
	default:
		sstr = MSG_INTL(MSG_STR_NULL);
		estr = MSG_INTL(MSG_STR_UNKNOWN);
		break;
	}

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_DBNOTIFY), estr, sstr);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_call_array(const char *libname, void *addr, uint_t ndx,
	uint_t shtype)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_INIT))
		return;

	if (shtype == SHT_INIT_ARRAY)
		str = MSG_ORIG(MSG_SCN_INITARRAY);
	else if (shtype == SHT_FINI_ARRAY)
		str = MSG_ORIG(MSG_SCN_FINIARRAY);
	else
		str = MSG_ORIG(MSG_SCN_PREINITARRAY);
	dbg_print(MSG_INTL(MSG_UTL_ARRAY), str, ndx, EC_ADDR(addr), libname);
}

void
Dbg_util_call_fini(const char *name)
{
	if (DBG_NOTCLASS(DBG_INIT))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_FINI), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_str(const char *name)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_ORIG(MSG_FMT_STR), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_scc_title(int sec)
{
	const char	*_sec;

	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sec)
		_sec = MSG_INTL(MSG_UTL_SCC_SUBI);
	else
		_sec = MSG_INTL(MSG_UTL_SCC_SUBF);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_SCC_TITLE), _sec);
}

void
Dbg_util_scc_entry(uint_t idx, const char *name)
{
	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_UTL_SCC_ENTRY), idx, name);
}

void
Dbg_util_broadcast(const char *name)
{
	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_BROAD), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_util_wait(int what, const char *cname, const char *dname)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (what == DBG_WAIT_INIT)
		str = MSG_ORIG(MSG_SCN_INIT);
	else if (what == DBG_WAIT_FINI)
		str = MSG_ORIG(MSG_SCN_FINI);
	else
		str = MSG_INTL(MSG_STR_SYMBOL);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_UTL_WAIT), str, cname, dname);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

static	int ectoggle = 0;

void
Dbg_util_edge_in(Rt_map *clmp, uint_t flags, Rt_map *dlmp, int ndx, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	if ((clmp == 0) || (ectoggle == 0))
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	if (clmp == 0) {
		dbg_print(MSG_INTL(MSG_UTL_EDGE_TITLE), str);
		dbg_print(MSG_INTL(MSG_UTL_EDGE_START), ndx, NAME(dlmp));
	} else
		dbg_print(MSG_INTL(MSG_UTL_EDGE_IN), ndx, NAME(dlmp),
		    NAME(clmp), conv_bindent_str(flags));

	ectoggle = 1;
}

void
Dbg_util_edge_out(const char *cname, int ndx, const char *dname)
{
	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_INTL(MSG_UTL_EDGE_OUT), ndx, cname, dname);
}

void
Dbg_util_collect(const char *name, int ndx, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	if (ectoggle == 1) {
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		ectoggle = 0;
	}
	dbg_print(MSG_INTL(MSG_UTL_COLLECT), ndx, name, str);
}
