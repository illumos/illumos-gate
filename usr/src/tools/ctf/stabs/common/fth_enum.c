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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Used to dump enums in forth mode.
 *
 * Enums are simple - there is no member-specific mode for them.  We get
 * the header op at the start, and we save the type id for dumping later.
 * If we get the members op, we've been invoked in member-specific mode,
 * which is a syntax error for an enum.  When we ge the trailer op, we
 * dump all of the members and the trailer thus concluding the enum.
 */

#include "forth.h"

static ctf_id_t	fth_enum_curtid;
static int	fth_enum_curnmems;

static int
fth_enum_header(ctf_id_t tid)
{
	fth_enum_curtid = tid;

	(void) fprintf(out, "\n");

	return (0);
}

/*ARGSUSED*/
static int
fth_enum_members(char *memfilter, char *format)
{
	return (parse_warn("Member-specific mode cannot be used for "
	    " enums"));
}

/*ARGSUSED2*/
static int
fth_enum_cb(const char *name, int value, void *arg)
{
	(void) fprintf(out, "here ,\" %s\" %x\n", name, value);
	fth_enum_curnmems++;

	return (0);
}

static int
fth_enum_trailer(void)
{
	if (ctf_enum_iter(ctf, fth_enum_curtid, fth_enum_cb, NULL) != 0)
		return (-1);

	(void) fprintf(out, "%x c-enum .%s\n", fth_enum_curnmems, fth_curtype);

	fth_enum_curnmems = 0;

	return (0);
}

fth_type_ops_t fth_enum_ops = {
	fth_enum_header,
	fth_enum_members,
	fth_enum_trailer
};
