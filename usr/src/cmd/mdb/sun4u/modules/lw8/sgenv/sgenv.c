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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>
#include <sys/kstat.h>
#include <sys/mdb_modapi.h>

#include <sys/sgenv.h>


/*
 * This dcmd returns the values of the tunable variables in the Serengeti
 * environmental driver (SGENV).
 */
/*ARGSUSED*/
static int
sgenv_parameters(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int	mbox_wait_time;
	int	debug_flag;

	int	err;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_printf("SGENV tunable parameters:\n");
	mdb_printf("=========================\n");

	err = mdb_readvar(&mbox_wait_time, "sgenv_max_mbox_wait_time");
	if (err != -1) {
		mdb_printf("sgenv_max_mbox_wait_time    = %d seconds\n",
			mbox_wait_time);
	}

	err = mdb_readvar(&debug_flag, "sgenv_debug");
	if (err != -1) {
		mdb_printf("sgenv_debug                 = 0x%x\n", debug_flag);
	}

	return (DCMD_OK);
}


/*
 * This dcmd prints the values of some of the module specific
 * variables in the Serengeti environmental driver (SGENV).
 */
/*ARGSUSED*/
static int
sgenv_variables(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t		env_cache_snapshot_size;
	int		env_cache_updated;
	int		env_writer_count;

	int		board_cache_updated;
	int		board_count_snapshot;
	int		board_count;
	int		board_writer_count;

	int		mbox_error_count;

	int	rv;

	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_printf("\nSGENV module variables:\n");
	mdb_printf("=======================\n");

	mdb_printf("\nEnvironmental variables:\n");
	mdb_printf("------------------------\n");
	rv = mdb_readvar(&env_cache_updated, "env_cache_updated");
	if (rv == sizeof (env_cache_updated)) {
		mdb_printf("env_cache_updated\t\t= %s\n",
			(env_cache_updated ? "TRUE": "FALSE"));
	}

	rv = mdb_readvar(&env_writer_count, "env_writer_count");
	if (rv == sizeof (env_writer_count)) {
		mdb_printf("env_writer_count\t\t= %d\n", env_writer_count);
	}

	rv = mdb_readvar(&env_cache_snapshot_size, "env_cache_snapshot_size");
	if (rv == sizeof (env_cache_snapshot_size)) {
		mdb_printf("env_cache_snapshot_size\t\t= %d\n",
			env_cache_snapshot_size);
	}

	mdb_printf("\nBoard info variables:\n");
	mdb_printf("---------------------\n");
	rv = mdb_readvar(&board_cache_updated, "board_cache_updated");
	if (rv == sizeof (board_cache_updated)) {
		mdb_printf("board_cache_updated\t\t= %s\n",
			(board_cache_updated ? "TRUE": "FALSE"));
	}

	rv = mdb_readvar(&board_writer_count, "board_writer_count");
	if (rv == sizeof (board_writer_count)) {
		mdb_printf("board_writer_count\t\t= %d\n", board_writer_count);
	}

	rv = mdb_readvar(&board_count, "board_count");
	if (rv == sizeof (board_count)) {
		mdb_printf("board_count\t\t\t= %d\n", board_count);
	}

	rv = mdb_readvar(&board_count_snapshot, "board_count_snapshot");
	if (rv == sizeof (board_count_snapshot)) {
		mdb_printf("board_count_snapshot\t\t= %d\n",
			board_count_snapshot);
	}

	mdb_printf("\nError variables:\n");
	mdb_printf("----------------\n");
	rv = mdb_readvar(&mbox_error_count, "sgenv_mbox_error_count");
	if (rv == sizeof (mbox_error_count)) {
		mdb_printf("mbox_error_count\t\t= %d\n", mbox_error_count);
	}

	mdb_printf("\n");

	return (DCMD_OK);
}

/*ARGSUSED2*/
int
sgenv_env_sensor(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	env_sensor_t    value;

	int	rv;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("sgenv_env_sensor: requires an address");
		return (DCMD_ERR);
	}

	rv = mdb_vread(&value, sizeof (env_sensor_t), addr);
	if (rv != sizeof (env_sensor_t)) {
		mdb_warn("sgenv_env_sensor: Failed read on "
			"address %ll#r", addr);
		return (DCMD_ERR);
	}
	mdb_printf("---------- struct_env_sensor @ %ll#r ----------\n", addr);

	mdb_printf("sd_id: %29ll#x\n", value.sd_id);
	mdb_printf("sd_value: %26lld\n", value.sd_value);
	mdb_printf("sd_lo: %29lld\n", value.sd_lo);
	mdb_printf("sd_hi: %29lld\n", value.sd_hi);
	mdb_printf("sd_lo_warn: %24lld\n", value.sd_lo_warn);
	mdb_printf("sd_hi_warn: %24lld\n", value.sd_hi_warn);
	mdb_printf("sd_status: %25ll#x\n", value.sd_status);

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {{
		"sgenv_parameters",
		NULL,
		"print environmental driver tunable parameters",
		sgenv_parameters
	}, {
		"sgenv_variables",
		NULL,
		"print environmental driver variables",
		sgenv_variables
	}, {
		"sgenv_env_sensor",
		NULL,
		"print contents of environmental sesnor",
		sgenv_env_sensor },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
