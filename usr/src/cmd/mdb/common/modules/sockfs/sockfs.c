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
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

/*
 * Look up the symbol name for the given sockparams list and walk
 * all the entries.
 */
static boolean_t
sockparams_walk_list(const char *symname, int argc, const mdb_arg_t *argv)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name(symname, &sym)) {
		mdb_warn("can't find symbol %s", symname);
		return (B_FALSE);
	}

	if (mdb_pwalk_dcmd("list", "sockfs`sockparams", argc, argv,
	    sym.st_value) != 0) {
		mdb_warn("can't walk %s", symname);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * dcmd to print sockparams info.
 *
 * If no address is given then the default is to print all sockparams on the
 * global list (i.e., installed with soconfig(8)). To also print the ephemeral
 * entries the '-e' flag should be used. Only ephemeral entries can be printed
 * by specifying the '-E' flag.
 */
static int
sockparams_prt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct sockparams sp;
	char strdev[MAXPATHLEN];
	char sockmod[MODMAXNAMELEN];

	if ((flags & DCMD_ADDRSPEC) == 0) {
		uint_t opt_e = 0;
		uint_t opt_E = 0;

		/*
		 * Determine what lists should be printed
		 */
		if (mdb_getopts(argc, argv,
		    'e', MDB_OPT_SETBITS, 1, &opt_e,
		    'E', MDB_OPT_SETBITS, 1, &opt_E, NULL) != argc)
			return (DCMD_USAGE);

		if (!opt_E) {
			if (!sockparams_walk_list("sphead", argc, argv))
				return (DCMD_ERR);
		}

		if (opt_e || opt_E) {
			if (!sockparams_walk_list("sp_ephem_list", argc, argv))
				return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	/*
	 * If we are piping the output, then just print out the address,
	 * otherwise summarize the sockparams info.
	 */
	if ((flags & DCMD_PIPE_OUT) != 0) {
		mdb_printf("%#lr\n", addr);
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-?s %3s %3s %3s %15s %15s %6s %6s\n",
		    "ADDR", "FAM", "TYP", "PRO", "STRDEV", "SOCKMOD", "REFS",
		    "FLGS");
	}

	if (mdb_vread(&sp, sizeof (sp), addr) == -1) {
		mdb_warn("failed to read sockparams at %0?p", addr);
		return (DCMD_ERR);
	}

	if ((sp.sp_sdev_info.sd_devpath == NULL) ||
	    (mdb_readstr(strdev, sizeof (strdev),
	    (uintptr_t)sp.sp_sdev_info.sd_devpath) <= 0))
		strcpy(strdev, "-");
	if (mdb_readstr(sockmod, sizeof (sockmod),
	    (uintptr_t)sp.sp_smod_name) <= 0)
		strcpy(sockmod, "");

	mdb_printf("%0?p %3u %3u %3u %15s %15s %6u %#6x\n",
	    addr,
	    sp.sp_family, sp.sp_type, sp.sp_protocol,
	    strdev, sockmod, sp.sp_refcnt,
	    sp.sp_flags);


	return (DCMD_OK);
}

/*
 * Help function
 */
void
sockparams_help(void)
{
	mdb_printf("Print sockparams information for a give sockparams ptr.\n"
	    "Without the address, list available sockparams. Default "
	    "behavior is to list only entries that were installed by the "
	    "admin (via soconfig(8)).\n\n"
	    "Options:\n"
	    "	-e:\t\tlist ephemeral sockparams\n"
	    "	-E:\t\tonly list ephemeral sockparams\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "sockparams", "[-eE]", "print sockparams", sockparams_prt,
	    sockparams_help },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, NULL };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
