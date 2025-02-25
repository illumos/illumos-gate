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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * MDB Regression Test Module
 *
 * This module contains dcmds and walkers that exercise various aspects of
 * MDB and the MDB Module API.  It can be manually loaded and executed to
 * verify that MDB is still working properly.
 */

#include <mdb/mdb_modapi.h>
#define	_MDB
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>
#undef _MDB

static int
cd_init(mdb_walk_state_t *wsp)
{
	wsp->walk_addr = 0xf;
	return (WALK_NEXT);
}

static int
cd_step(mdb_walk_state_t *wsp)
{
	int status = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

	if (wsp->walk_addr-- == 0)
		return (WALK_DONE);

	return (status);
}

/*ARGSUSED*/
static int
cmd_praddr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags != (DCMD_ADDRSPEC|DCMD_LOOP|DCMD_PIPE)) &&
	    (flags != (DCMD_ADDRSPEC|DCMD_LOOP|DCMD_PIPE|DCMD_LOOPFIRST))) {
		mdb_warn("ERROR: praddr invoked with flags = 0x%x\n", flags);
		return (DCMD_ERR);
	}

	if (argc != 0) {
		mdb_warn("ERROR: praddr invoked with argc = %lu\n", argc);
		return (DCMD_ERR);
	}

	mdb_printf("%lr\n", addr);
	return (DCMD_OK);
}

static int
compare(const void *lp, const void *rp)
{
	uintptr_t lhs = *((const uintptr_t *)lp);
	uintptr_t rhs = *((const uintptr_t *)rp);
	return (lhs - rhs);
}

/*ARGSUSED*/
static int
cmd_qsort(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_pipe_t p;
	size_t i;

	if (flags != (DCMD_ADDRSPEC | DCMD_LOOP |
	    DCMD_LOOPFIRST | DCMD_PIPE | DCMD_PIPE_OUT)) {
		mdb_warn("ERROR: qsort invoked with flags = 0x%x\n", flags);
		return (DCMD_ERR);
	}

	if (argc != 0) {
		mdb_warn("ERROR: qsort invoked with argc = %lu\n", argc);
		return (DCMD_ERR);
	}

	mdb_get_pipe(&p);

	if (p.pipe_data == NULL || p.pipe_len != 16) {
		mdb_warn("ERROR: qsort got bad results from mdb_get_pipe\n");
		return (DCMD_ERR);
	}

	if (p.pipe_data[0] != addr) {
		mdb_warn("ERROR: qsort pipe_data[0] != addr\n");
		return (DCMD_ERR);
	}

	qsort(p.pipe_data, p.pipe_len, sizeof (uintptr_t), compare);
	mdb_set_pipe(&p);

	for (i = 0; i < 16; i++) {
		if (p.pipe_data[i] != i) {
			mdb_warn("ERROR: qsort got bad data in slot %lu\n", i);
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_runtest(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_walker_t w = { "count", "count", cd_init, cd_step, NULL };
	int state, i;

	mdb_printf("- adding countdown walker\n");
	if (mdb_add_walker(&w) != 0) {
		mdb_warn("ERROR: failed to add walker");
		return (DCMD_ERR);
	}

	mdb_printf("- executing countdown pipeline\n");
	if (mdb_eval("::walk mdb_test`count |::mdb_test`qsort |::praddr")) {
		mdb_warn("ERROR: failed to eval command");
		return (DCMD_ERR);
	}

	mdb_printf("- removing countdown walker\n");
	if (mdb_remove_walker("count") != 0) {
		mdb_warn("ERROR: failed to remove walker");
		return (DCMD_ERR);
	}

	state = mdb_get_state();
	mdb_printf("- kernel=%d state=%d\n", mdb_prop_kernel, state);

	if (mdb_prop_kernel && (state == MDB_STATE_DEAD ||
	    state == MDB_STATE_RUNNING)) {
		mdb_printf("- exercising pipelines\n");
		for (i = 0; i < 100; i++) {
			if (mdb_eval("::walk proc p | ::map *. | ::grep .==0 "
			    "| ::map <p | ::ps") != 0) {
				mdb_warn("ERROR: failed to eval pipeline");
				return (DCMD_ERR);
			}
		}
	}

	return (DCMD_OK);
}

static int
cmd_vread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t nbytes;
	ssize_t rbytes;
	void *buf;

	if (!(flags & DCMD_ADDRSPEC) || argc != 1)
		return (DCMD_USAGE);

	nbytes = (size_t)mdb_argtoull(argv);

	buf = mdb_alloc(nbytes, UM_SLEEP | UM_GC);
	rbytes = mdb_vread(buf, nbytes, addr);

	if (rbytes >= 0) {
		mdb_printf("mdb_vread of %lu bytes returned %ld\n",
		    nbytes, rbytes);
	} else
		mdb_warn("mdb_vread returned %ld", rbytes);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_pread(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t nbytes;
	ssize_t rbytes;
	void *buf;

	if (!(flags & DCMD_ADDRSPEC) || argc != 1)
		return (DCMD_USAGE);

	nbytes = (size_t)mdb_argtoull(argv);

	buf = mdb_alloc(nbytes, UM_SLEEP | UM_GC);
	rbytes = mdb_pread(buf, nbytes, mdb_get_dot());

	if (rbytes >= 0) {
		mdb_printf("mdb_pread of %lu bytes returned %ld\n",
		    nbytes, rbytes);
	} else
		mdb_warn("mdb_pread returned %ld", rbytes);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_readsym(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t nbytes;
	ssize_t rbytes;
	void *buf;

	if ((flags & DCMD_ADDRSPEC) || argc != 2 ||
	    argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	nbytes = (size_t)mdb_argtoull(&argv[1]);

	buf = mdb_alloc(nbytes, UM_SLEEP | UM_GC);
	rbytes = mdb_readsym(buf, nbytes, argv->a_un.a_str);

	if (rbytes >= 0) {
		mdb_printf("mdb_readsym of %lu bytes returned %ld\n",
		    nbytes, rbytes);
	} else
		mdb_warn("mdb_readsym returned %ld", rbytes);

	return (DCMD_OK);
}

static int
cmd_call_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *dcmd;

	if (argc < 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	dcmd = argv->a_un.a_str;
	argv++;
	argc--;

	if (mdb_call_dcmd(dcmd, addr, flags, argc, argv) == -1) {
		mdb_warn("failed to execute %s", dcmd);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_getsetdot(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	mdb_set_dot(0x12345678feedbeefULL);

	if (mdb_get_dot() != 0x12345678feedbeefULL) {
		mdb_warn("mdb_get_dot() returned wrong value!\n");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * kmdb doesn't export some of the symbols used by these tests - namely mdb and
 * mdb_iob_.*.  We therefore can't use these tests with kmdb.
 */
#ifndef _KMDB
static void
do_nputs_tests(const char *banner, uint_t flags,
    size_t rows, size_t cols, size_t ocols)
{
	uint_t oflags;
	int i;

	oflags = mdb_iob_getflags(mdb.m_out) &
	    (MDB_IOB_AUTOWRAP | MDB_IOB_INDENT);

	mdb_printf("%s:\n", banner);
	for (i = 0; i < 8; i++)
		mdb_printf("0123456789");
	mdb_printf("\n");

	mdb_iob_clrflags(mdb.m_out, MDB_IOB_AUTOWRAP | MDB_IOB_INDENT);
	mdb_iob_setflags(mdb.m_out, flags);
	mdb_iob_resize(mdb.m_out, rows, cols);

	for (i = 0; i < 50; i++)
		mdb_printf(" xx");
	mdb_printf("\n");

	mdb_iob_clrflags(mdb.m_out, flags);
	mdb_iob_setflags(mdb.m_out, oflags);
	mdb_iob_resize(mdb.m_out, rows, ocols);
}

/*ARGSUSED*/
static int
cmd_nputs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t rows = mdb.m_out->iob_rows;
	size_t cols = mdb.m_out->iob_cols;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = cols;

	do_nputs_tests("tests with (~WRAP, ~INDENT)",
	    0, rows, addr, cols);

	do_nputs_tests("tests with (WRAP, ~INDENT)",
	    MDB_IOB_AUTOWRAP, rows, addr, cols);

	do_nputs_tests("tests with (~WRAP, INDENT)",
	    MDB_IOB_INDENT, rows, addr, cols);

	do_nputs_tests("tests with (WRAP, INDENT)",
	    MDB_IOB_AUTOWRAP | MDB_IOB_INDENT, rows, addr, cols);

	return (DCMD_OK);
}
#endif

/*ARGSUSED*/
static int
cmd_printf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 2 || argv[0].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (argv[1].a_type == MDB_TYPE_STRING)
		mdb_printf(argv[0].a_un.a_str, argv[1].a_un.a_str);
	else
		mdb_printf(argv[0].a_un.a_str, argv[1].a_un.a_val);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
cmd_abort(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_printf("hello"); /* stuff something in stdout's buffer */
	return (*((volatile int *)NULL));
}

static const mdb_dcmd_t dcmds[] = {
	{ "runtest", NULL, "run MDB regression tests", cmd_runtest },
	{ "qsort", NULL, "qsort addresses", cmd_qsort },
	{ "praddr", NULL, "print addresses", cmd_praddr },
	{ "vread", ":nbytes", "call mdb_vread", cmd_vread },
	{ "pread", ":nbytes", "call mdb_pread", cmd_pread },
	{ "readsym", "symbol nbytes", "call mdb_readsym", cmd_readsym },
	{ "call_dcmd", "dcmd [ args ... ]", "call dcmd", cmd_call_dcmd },
	{ "getsetdot", NULL, "test get and set dot", cmd_getsetdot },
#ifndef _KMDB
	{ "nputs", "?", "test iob nputs engine", cmd_nputs },
#endif
	{ "printf", "fmt arg", "test printf engine", cmd_printf },
	{ "abort", NULL, "test unexpected dcmd abort", cmd_abort },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "countdown", "count down from 16 to 0", cd_init, cd_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
