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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	"msg.h"
#include	"_debug.h"

void
Dbg_support_req(Lm_list *lml, const char *define, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SUPPORT))
		return;

	switch (flag) {
	case DBG_SUP_ENVIRON:
		str = MSG_INTL(MSG_SUP_REQ_ENV);
		break;
	case DBG_SUP_CMDLINE:
		str = MSG_INTL(MSG_SUP_REQ_CMD);
		break;
	default:
		str = MSG_ORIG(MSG_STR_EMPTY);
		break;
	}

	dbg_print(lml, MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(lml, MSG_INTL(MSG_SUP_REQ), define, str);
}

void
Dbg_support_load(Lm_list *lml, const char *obj, const char *func)
{
	if (DBG_NOTCLASS(DBG_C_SUPPORT))
		return;

	dbg_print(lml, MSG_INTL(MSG_SUP_ROUTINE), obj, func);
}

void
Dbg_support_vnone(Lm_list *lml, const char *obj)
{
	if (DBG_NOTCLASS(DBG_C_SUPPORT))
		return;

	dbg_print(lml, MSG_INTL(MSG_SUP_VNONE), obj);
}

void
Dbg_support_action(Lm_list *lml, const char *obj, const char *func,
    Support_ndx ndx, const char *name)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_SUPPORT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (ndx == LDS_START)
		str = MSG_INTL(MSG_SUP_OUTFILE);
	else if ((ndx == LDS_OPEN) || (ndx == LDS_FILE))
		str = MSG_INTL(MSG_SUP_INFILE);
	else if (ndx == LDS_INSEC)
		str = MSG_INTL(MSG_SUP_INSEC);
	else if (ndx == LDS_SEC)
		str = MSG_INTL(MSG_SUP_SEC);

	if ((ndx == LDS_ATEXIT) || (ndx == LDS_VERSION) ||
	    (ndx == LDS_INPUT_DONE))
		dbg_print(lml, MSG_INTL(MSG_SUP_CALLING_1), func, obj);
	else
		dbg_print(lml, MSG_INTL(MSG_SUP_CALLING_2), func, obj,
		    str, name);
}
