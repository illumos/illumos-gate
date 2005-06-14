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

#include "mdinclude.h"

extern int		active_sets;
md_set_io_t		md_setio[MD_MAXSETS];

/* IO array status: io_state */
static const mdb_bitmask_t io_state_bits[] = {
	{ "MD_SET_ACTIVE", MD_SET_ACTIVE, MD_SET_ACTIVE },
	{ "MD_SET_RELEASE", MD_SET_RELEASE, MD_SET_RELEASE },
	{ NULL, 0, 0 }
};


void
set_io_help(void)
{
	mdb_printf("::set_io [-s name] [-a num] [-m num]\n");
	mdb_printf("-a num  - print out num elements in the md_set_io array\n");
	mdb_printf("-s name - print out the information for set named name\n");
	mdb_printf("-m num  - only print out element num\n");
}

/* ARGSUSED */
int
set_io(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	GElf_Sym	setiosym;
	uint64_t	i;
	size_t		offset = 0;
	uint64_t	opt_a = 0;		/* up to active_sets */
	char		*opt_s = (char *)NULL;	/* a named set */
	uint64_t	opt_m = 0;		/* array element */
	int		setno = 0;
	int		argnum = 0;

	argnum = mdb_getopts(argc, argv,
		'a', MDB_OPT_UINT64, &opt_a,
		's', MDB_OPT_STR, &opt_s,
		'm', MDB_OPT_UINT64, &opt_m, NULL);

	if (argnum != argc) {
		mdb_printf("invalid arguments\n");
		return (DCMD_USAGE);
	}

	if ((opt_s != 0) && (opt_m != 0)) {
		mdb_printf("-s and -m cannot both be specified\n");
		return (DCMD_USAGE);
	}

	snarf_sets();

	if (opt_a == 0)
		opt_a = active_sets;

	/* find the array */
	if (mdb_lookup_by_name("md_set_io", &setiosym) == -1) {
		mdb_warn("SVM - no set io counts set\n");
		return (DCMD_ERR);
	}

	if (md_verbose) {
		mdb_printf("Base address for the md_set_io array: %p\n",
		    setiosym.st_value);
	}
	if (opt_s != NULL) {
		setno = findset(opt_s);
		if (setno == -1) {
			mdb_warn("no such set: %s\n", opt_s);
			return (DCMD_ERR);
		}
		opt_m = setno;
	}

	if (opt_m > 0) {
		mdb_printf("%lld]\t%ld\t%ld", opt_m,
		    md_setio[opt_m].io_cnt, md_setio[opt_m].io_state);
		mdb_printf("\t%hb\n", io_state_bits);
		return (DCMD_OK);
	}

	if (opt_a == 0) {
		mdb_warn("No active set!\n");
		return (DCMD_ERR);
	}

	for (i = 0; i < opt_a; i++) {
		if (mdb_vread(&md_setio[i], sizeof (md_set_io_t),
		    setiosym.st_value + offset) == -1) {
			mdb_warn("failed to read md_set_io_t at 0x%x\n",
			    setiosym.st_value + offset);
		}
		mdb_printf("%lld]\t%ld\t%ld", i, md_setio[i].io_cnt,
		    md_setio[i].io_state);
		mdb_printf("\t%hb", io_state_bits);
		if (md_verbose) {
			mdb_printf(" - io_cnt: %p",
			    setiosym.st_value + offset + sizeof (kmutex_t) +
			    sizeof (kcondvar_t));
			mdb_printf(" %d", sizeof (md_set_io_t));
		}
		mdb_printf("\n");
		offset += sizeof (md_set_io_t);
	}
	return (DCMD_OK);
}
