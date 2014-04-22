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

/*
 * If any run-time linker debugging is being carried out always indicate the
 * fact and specify the point at which we transfer control to the main program.
 */
void
Dbg_util_call_main(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);

	Dbg_util_nl(lml, DBG_NL_FRC);
	dbg_print(lml, MSG_INTL(MSG_UTL_TRANS), NAME(lmp));
	Dbg_util_nl(lml, DBG_NL_FRC);
}

void
Dbg_util_call_init(Rt_map *lmp, int flag)
{
	Lm_list		*lml = LIST(lmp);
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;

	if (flag == DBG_INIT_SORT)
		str = MSG_INTL(MSG_UTL_SORT);
	else if (flag == DBG_INIT_PEND)
		str = MSG_INTL(MSG_UTL_PEND);
	else if (flag == DBG_INIT_DYN)
		str = MSG_INTL(MSG_UTL_DYN);
	else
		str = MSG_INTL(MSG_UTL_DONE);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_UTL_INIT), str, NAME(lmp));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_util_intoolate(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_UTL_INTOOLATE), NAME(lmp));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_util_dbnotify(Lm_list *lml, rd_event_e event, r_state_e state)
{
	const char	*estr;
	const char	*sstr;

	if (DBG_NOTCLASS(DBG_C_FILES))
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

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_UTL_DBNOTIFY), estr, sstr);
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_util_call_array(Rt_map *lmp, void *addr, int ndx, Word shtype)
{
	Lm_list		*lml = LIST(lmp);
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;

	if (shtype == SHT_INIT_ARRAY)
		str = MSG_ORIG(MSG_SCN_INITARRAY);
	else if (shtype == SHT_FINI_ARRAY)
		str = MSG_ORIG(MSG_SCN_FINIARRAY);
	else
		str = MSG_ORIG(MSG_SCN_PREINITARRAY);

	dbg_print(lml, MSG_INTL(MSG_UTL_ARRAY), str, ndx, EC_NATPTR(addr),
	    NAME(lmp));
}

void
Dbg_util_call_fini(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_UTL_FINI), NAME(lmp));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_util_str(Lm_list *lml, const char *str)
{
	Dbg_util_nl(lml, DBG_NL_STD);
	Dbg_util_nl(lml, DBG_NL_FRC);
	dbg_print(lml, MSG_ORIG(MSG_FMT_STR), str);
	Dbg_util_nl(lml, DBG_NL_FRC);
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_util_scc_title(Lm_list *lml, int sec)
{
	const char	*_sec;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (sec)
		_sec = MSG_INTL(MSG_UTL_SCC_SUBI);
	else
		_sec = MSG_INTL(MSG_UTL_SCC_SUBF);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_UTL_SCC_TITLE), _sec);
}

void
Dbg_util_scc_entry(Rt_map *lmp, uint_t idx)
{
	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(LIST(lmp), MSG_ORIG(MSG_UTL_SCC_ENTRY), idx, NAME(lmp));
}

static	int ectoggle = 0;

void
Dbg_util_edge_in(Lm_list *lml, Rt_map *clmp, uint_t flags, Rt_map *dlmp,
    int ndx, int flag)
{
	Conv_bnd_type_buf_t	bnd_type_buf;
	const char		*str;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	if ((clmp == 0) || (ectoggle == 0))
		Dbg_util_nl(lml, DBG_NL_STD);
	if (clmp == 0) {
		if (flag & RT_SORT_INTPOSE)
			dbg_print(lml, MSG_INTL(MSG_UTL_EDGE_TITLE_I), str);
		else
			dbg_print(lml, MSG_INTL(MSG_UTL_EDGE_TITLE_S), str);

		dbg_print(lml, MSG_INTL(MSG_UTL_EDGE_START), ndx, NAME(dlmp));
	} else
		dbg_print(lml, MSG_INTL(MSG_UTL_EDGE_IN), ndx, NAME(dlmp),
		    NAME(clmp), conv_bnd_type(flags, &bnd_type_buf));

	ectoggle = 1;
}

void
Dbg_util_edge_out(Rt_map *clmp, Rt_map *dlmp)
{
	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(LIST(clmp), MSG_INTL(MSG_UTL_EDGE_OUT), SORTVAL(clmp),
	    NAME(clmp), NAME(dlmp));
}

void
Dbg_util_collect(Rt_map *lmp, int ndx, int flag)
{
	Lm_list		*lml = LIST(lmp);
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	if (ectoggle == 1) {
		Dbg_util_nl(lml, DBG_NL_STD);
		ectoggle = 0;
	}
	dbg_print(lml, MSG_INTL(MSG_UTL_COLLECT), ndx, NAME(lmp), str);
}

static const Msg	tags[] = {
	MSG_CI_NULL,		/* MSG_ORIG(MSG_CI_NULL) */
	MSG_CI_VERSION,		/* MSG_ORIG(MSG_CI_VERSION) */
	MSG_CI_ATEXIT,		/* MSG_ORIG(MSG_CI_ATEXIT) */
	MSG_CI_LCMESSAGES,	/* MSG_ORIG(MSG_CI_LCMESSAGES) */
	MSG_CI_BIND_GUARD,	/* MSG_ORIG(MSG_CI_BIND_GUARD) */
	MSG_CI_BIND_CLEAR,	/* MSG_ORIG(MSG_CI_BIND_CLEAR) */
	MSG_CI_THR_SELF,	/* MSG_ORIG(MSG_CI_THR_SELF) */
	MSG_CI_TLS_MODADD,	/* MSG_ORIG(MSG_CI_TLS_MODADD) */
	MSG_CI_TLS_MODREM,	/* MSG_ORIG(MSG_CI_TLS_MODREM) */
	MSG_CI_TLS_STATMOD,	/* MSG_ORIG(MSG_CI_TLS_STATMOD) */
	MSG_CI_THRINIT,		/* MSG_ORIG(MSG_CI_THRINIT) */
	MSG_CI_CRITICAL		/* MSG_ORIG(MSG_CI_CRITICAL) */
};

void
Dbg_util_lcinterface(Rt_map *lmp, int tag, char *val)
{
	const char	*str;
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTDETAIL())
		return;

	if (tag < CI_MAX)
		str = MSG_ORIG(tags[tag]);
	else
		str = conv_invalid_val(&inv_buf, tag, 0);

	dbg_print(LIST(lmp), MSG_INTL(MSG_UTL_LCINTERFACE), NAME(lmp), str,
	    EC_NATPTR(val));
}

void
Dbg_unused_lcinterface(Rt_map *nlmp, Rt_map *olmp, int tag)
{
	const char	*str;
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_UNUSED))
		return;

	if (tag < CI_MAX)
		str = MSG_ORIG(tags[tag]);
	else
		str = conv_invalid_val(&inv_buf, tag, 0);

	dbg_print(LIST(nlmp), MSG_INTL(MSG_USD_LCINTERFACE), NAME(nlmp), str,
	    NAME(olmp));
}

/*
 * Generic new line generator.  To prevent multiple newlines from being
 * generated, a flag is maintained in the global debug descriptor.  This flag
 * is cleared by the callers dbg_print() function to indicate that a newline
 * (actually, any line) has been printed.  Multiple newlines can be generated
 * using the DBG_NL_FRC flag.
 */
void
Dbg_util_nl(Lm_list *lml, int flag)
{
	if ((flag == DBG_NL_STD) && (dbg_desc->d_extra & DBG_E_STDNL))
		return;

	dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));

	if (flag == DBG_NL_STD)
		dbg_desc->d_extra |= DBG_E_STDNL;
}

/*
 * Define name demanglers.
 */
const char *
Dbg_demangle_name(const char *name)
{
	if (DBG_NOTCLASS(DBG_C_DEMANGLE))
		return (name);

	return (conv_demangle_name(name));
}

const char *
Elf_demangle_name(const char *name)
{
	if (DBG_ISDEMANGLE())
		return (conv_demangle_name(name));
	return (name);
}
