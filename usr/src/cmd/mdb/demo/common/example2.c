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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>
#include <sys/proc.h>

/*
 * Initialize the proc_t walker by either using the given starting address,
 * or reading the value of the kernel's practive pointer.  We also allocate
 * a proc_t for storage, and save this using the walk_data pointer.
 */
static int
sp_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "practive") == -1) {
		mdb_warn("failed to read 'practive'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (proc_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a proc_t into our private storage, and then invoke
 * the callback function.  We terminate when we reach a NULL p_next pointer.
 */
static int
sp_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (proc_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read proc at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)(((proc_t *)wsp->walk_data)->p_next);
	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a proc_t in sp_walk_init, we must free it now.
 */
static void
sp_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (proc_t));
}

static int
simple_ps(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct pid pid;
	proc_t p;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no proc_t address was specified on the command line, we can
	 * print out all processes by invoking the walker, using this
	 * dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("simple_proc", "simple_ps",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'simple_proc'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%5s %s\n", "PID", "COMM");

	/*
	 * For each process, we just need to read the proc_t struct, read
	 * the pid struct addressed by p_pidp, and then print out the pid
	 * and the command name.
	 */
	if (mdb_vread(&p, sizeof (p), addr) == sizeof (p)) {

		if (mdb_vread(&pid, sizeof (pid),
		    (uintptr_t)p.p_pidp) == sizeof (pid))
			mdb_printf("%5d %s\n", pid.pid_id, p.p_user.u_comm);
		else
			mdb_warn("failed to read struct pid at %p", p.p_pidp);
	} else
		mdb_warn("failed to read process at %p", addr);

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "simple_ps", NULL, "simple process list", simple_ps },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "simple_proc", "walk list of proc_t structures",
		sp_walk_init, sp_walk_step, sp_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
