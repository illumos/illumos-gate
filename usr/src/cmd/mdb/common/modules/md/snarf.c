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

/* array of the sets */
md_set_t	mdset[MD_MAXSETS];
mddb_set_t	set_dbs[MD_MAXSETS];
/* for the addresses of each set above */
uintptr_t	mdset_addrs[MD_MAXSETS];

unit_t		md_nunits = 0;
set_t		md_nsets = 0;
int		snarfed = 0;
int		active_sets = 0;

/*
 * routines to snarf the metaset information
 *
 * usage: ::dumpsetaddr [-s setname]
 */
/* ARGSUSED */
int
dumpsetaddr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int	i;
	int	setno;
	char	*s_opt = (char *)NULL;

	if (mdb_getopts(argc, argv, 's', MDB_OPT_STR, &s_opt,
	    NULL) != argc) {
		/* left over arguments ?? */
		return (DCMD_USAGE);
	}

	if (!snarfed) {
		mdb_warn("No sets read in yet - try ::metaset\n");
		return (DCMD_ERR);
	}
	if (argc == 0) {	/* dump all sets */
		for (i = 0; i < md_nsets; i++) {
			if (mdset_addrs[i] != (uintptr_t)0)
				mdb_printf("%d %p\n", i, mdset_addrs[i]);
		}
	} else {
		setno = findset(s_opt);
		if (setno == -1) {
			mdb_warn("no such set: %s\n", s_opt);
			return (DCMD_ERR);
		}
		if (mdset_addrs[setno] != (uintptr_t)0)
			mdb_printf("%d %p\n", setno,
			    mdset_addrs[setno]);
	}
	return (DCMD_OK);
}


/*
 * Function: snarf_ui_anchor
 * Purpose:  to read in the s_ui part of a metaset.
 * Returns:  <n> - number of configured metadevices
 *           -1  - not configured
 */
int
snarf_ui_anchor(int i)
{
	int	j;
	int	num_found = 0;
	void	**ptr = mdset[i].s_ui;
	void	*addr;

	for (j = 0; j < md_nunits; j++) {
		if (mdb_vread(&addr, sizeof (void *), (uintptr_t)ptr) == -1) {
			ptr++;
			continue;
		}
		if (addr != NULL) {
			num_found++;
		}
		ptr++;
	}
	return (num_found);
}

/*
 * Function: snarf_sets
 * Purpose:  Entry point into the module that reads the kernel's version
 *           of the SVM configuration.
 *           First of all populates the mdset array and then for each
 *           component that makes up an "md_set_t" reads it in, via calls
 *           to other functions.
 */
int
snarf_sets(void)
{
	GElf_Sym	setsym;
	GElf_Sym	nmdsym;
	GElf_Sym	mdsetsym;
	int		i;
	size_t		offset = 0;

	if (snarfed)
		return (DCMD_OK);

	/* find the SVM hook - md_set */
	if (mdb_lookup_by_name("md_set", &setsym) == -1) {
		mdb_warn("SVM is not configured on this machine\n");
		return (DCMD_ERR);
	}
	/* find out how many metadevices are configured per set */
	if (mdb_lookup_by_name("md_nunits", &nmdsym) == -1) {
		mdb_warn("unable to find md_nunits\n");
		return (DCMD_ERR);
	}
	if (mdb_vread(&md_nunits, sizeof (unit_t), nmdsym.st_value) == -1) {
		mdb_warn("failed to read md_nunits at %p\n", nmdsym.st_value);
		return (DCMD_ERR);
	}

	if (mdb_lookup_by_name("md_nsets", &mdsetsym) == -1) {
		mdb_warn("unable to find md_nsets\n");
		return (DCMD_ERR);
	}
	if (mdb_vread(&md_nsets, sizeof (set_t), mdsetsym.st_value) == -1) {
		mdb_warn("failed to read md_nsets at %p\n", mdsetsym.st_value);
		return (DCMD_ERR);
	}

	if (md_verbose) {
		mdb_printf("mdset array addr: 0x%lx size is: 0x%lx\n",
		    (uintptr_t)setsym.st_value, sizeof (md_set_t));
	}

	offset = setsym.st_value;

	for (i = 0; i < md_nsets; i++) {
		if (mdb_vread(&mdset[i], sizeof (md_set_t), offset) == -1) {
			mdb_warn("failed to read md_set_t at 0x%lx\n",
			    (uintptr_t)(setsym.st_value + offset));
		}
		/* Should check the status flags */
		if (mdset[i].s_status & MD_SET_NM_LOADED) {
			if (md_verbose)
				mdb_printf("Set %d (0x%lx) has a name space\n",
				    i, (uintptr_t)(setsym.st_value + offset));
		} else {
			offset += sizeof (md_set_t);
			continue;
		}

		if (mdb_vread(&set_dbs[i], sizeof (mddb_set_t),
		    (uintptr_t)mdset[i].s_db) == -1) {
			if (mdset[i].s_db != 0) {
				mdb_warn("failed to read mddb_set_t at 0x%p\n",
				    mdset[i].s_db);
				return (DCMD_ERR);
			} else {
				mdb_warn("%d - no set configured\n", i);
				return (DCMD_ERR);
			}
		}
		active_sets++;

		mdset_addrs[i] = (uintptr_t)(offset);

		(void) snarf_ui_anchor(i);

		/* have the set now read in the various bits and pieces */
		offset += sizeof (md_set_t);
	}
	snarfed = 1;

	if (md_verbose) {
		mdb_printf("Number of active sets: %d\n", active_sets);
		mdb_printf("Max number of metadevices: %u\n", md_nunits);
		mdb_printf("Max number of sets: %u\n", md_nsets);
	}
	return (DCMD_OK);
}
