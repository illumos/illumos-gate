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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <inj.h>
#include <inj_err.h>
#include <assert.h>

const char *
inj_item2str(inj_itemtype_t item)
{
	static const char *const names[] = { "event", "fmri", "auth", "list" };

	return (item >= 0 &&
	    item < sizeof (names) / sizeof (char *) ? names[item] : "???");
}

inj_memtype_t
inj_item2mem(inj_itemtype_t item)
{
	static const inj_memtype_t mems[] = {
		MEMTYPE_EVENT, MEMTYPE_FMRI, MEMTYPE_AUTH, MEMTYPE_LIST
	};

	assert(item >= 0 && item < sizeof (mems) / sizeof (inj_memtype_t));
	return (mems[item]);
}

/*
 * Convert a *subset* of inj_memtype_t's to inj_itemtype_t's.
 */
inj_itemtype_t
inj_mem2item(inj_memtype_t mem)
{
	switch (mem) {
	case MEMTYPE_EVENT:
		return (ITEMTYPE_EVENT);
	case MEMTYPE_FMRI:
		return (ITEMTYPE_FMRI);
	case MEMTYPE_AUTH:
		return (ITEMTYPE_AUTH);
	case MEMTYPE_LIST:
		return (ITEMTYPE_LIST);
	default:
		return (-1);
	}
}

const char *
inj_mem2str(inj_memtype_t mem)
{
	static const char *names[] = {
		"UNKNOWN",
		"int8", "int16", "int32", "int64",
		"uint8", "uint16", "uint32", "uint64",
		"bool", "string", "enum",
		"event", "fmri", "auth"
	};

	return (mem >= 0 &&
	    mem < sizeof (names) / sizeof (char *) ? names[mem] : "???");
}
