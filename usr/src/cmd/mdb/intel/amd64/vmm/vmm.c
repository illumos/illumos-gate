/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Pluribus Networks Inc.
 */

#include <sys/param.h>

#include <mdb/mdb_modapi.h>
#include <sys/cpuvar.h>
#include <sys/varargs.h>
#include <sys/vmm.h>
#include <sys/vmm_impl.h>

/*
 * VMM trace debug walker/dcmd code
 */

/*
 * Initialize the vmm_trace_dmsg_t walker by either using the given starting
 * address, or reading the value of the kernel's vmm_debug_rbuf pointer.
 * We also allocate a vmm_trace_dmsg_t for storage, and save this using the
 * walk_data pointer.
 */
static int
vmm_dmsg_walk_i(mdb_walk_state_t *wsp)
{
	uintptr_t rbuf_addr;
	vmm_trace_rbuf_t rbuf;

	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&rbuf_addr, "vmm_debug_rbuf") == -1) {
			mdb_warn("failed to read 'vmm_debug_rbuf'");
			return (WALK_ERR);
		}

		if (mdb_vread(&rbuf, sizeof (vmm_trace_rbuf_t), rbuf_addr)
		    == -1) {
			mdb_warn("failed to read vmm_trace_rbuf_t at %p",
			    rbuf_addr);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)(vmm_trace_dmsg_t *)rbuf.dmsgh;
	}

	/*
	 * Save ptr to head of ring buffer to prevent looping.
	 */
	wsp->walk_arg = (void *)wsp->walk_addr;
	wsp->walk_data = mdb_alloc(sizeof (vmm_trace_dmsg_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a vmm_trace_dmsg_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL next
 * pointer.
 */
static int
vmm_dmsg_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (vmm_trace_dmsg_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read vmm_trace_dmsg_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((vmm_trace_dmsg_t *)wsp->walk_data)->next);

	/*
	 * If we've looped then we're done.
	 */
	if (wsp->walk_addr == (uintptr_t)wsp->walk_arg)
		wsp->walk_addr = NULL;

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a vmm_trace_dmsg_t in vmm_dmsg_walk_i, we must
 * free it now.
 */
static void
vmm_dmsg_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (vmm_trace_dmsg_t));
}

/*
 * This routine is used by the vmm_dmsg_dump dcmd to dump content of
 * VMM trace ring buffer.
 */
int
vmm_dmsg_dump(vmm_trace_dmsg_t *addr, int print_pathname, uint_t *printed)
{
	vmm_trace_dmsg_t	dmsg, *dmsgh = addr;
	char			merge[1024];

	while (addr != NULL) {
		if (mdb_vread(&dmsg, sizeof (dmsg), (uintptr_t)addr) !=
		    sizeof (dmsg)) {
			mdb_warn("failed to read message pointer in kernel");
			return (DCMD_ERR);
		}

		(void) mdb_snprintf(merge, sizeof (merge),
		    "[%Y:%03d:%03d:%03d] : %s",
		    dmsg.timestamp.tv_sec,
		    (int)dmsg.timestamp.tv_nsec/1000000,
		    (int)(dmsg.timestamp.tv_nsec/1000)%1000,
		    (int)dmsg.timestamp.tv_nsec%1000,
		    dmsg.buf);

		mdb_printf("%s", merge);

		if (printed != NULL) {
			(*printed)++;
		}

		if (((addr = dmsg.next) == NULL) || (dmsg.next == dmsgh)) {
			break;
		}
	}

	return (DCMD_OK);
}

/*
 * 1. Process flag passed to vmm_dmsg_dump dcmd.
 * 2. Obtain VMM trace ring buffer pointer.
 * 3. Pass VMM trace ring buffer pointer to vmm_dmsg_dump()
 *    to dump content of VMM trace ring buffer.
 */
int
vmm_rbuf_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vmm_trace_rbuf_t	rbuf;
	uint_t		printed = 0; /* have we printed anything? */
	int		print_pathname = FALSE;
	int		rval = DCMD_OK;

	if (argc > 1) {
		return (DCMD_USAGE);
	}

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &print_pathname) != argc) {
		return (DCMD_USAGE);
	}

	/*
	 * If ring buffer address not provided try to obtain
	 * it using vmm_debug_rbuf global.
	 */
	if ((addr == NULL) || !(flags & DCMD_ADDRSPEC)) {
		if (mdb_readvar(&addr, "vmm_debug_rbuf") == -1) {
			mdb_warn("Failed to read 'vmm_debug_rbuf'.");
			return (DCMD_ERR);
		}
	}

	if (mdb_vread(&rbuf, sizeof (rbuf), addr) != sizeof (rbuf)) {
		mdb_warn("Failed to read ring buffer in kernel.");
		return (DCMD_ERR);
	}

	if (rbuf.dmsgh == NULL) {
		mdb_printf("The vmm trace ring buffer is empty.\n");
		return (DCMD_OK);
	}

	rval = vmm_dmsg_dump((vmm_trace_dmsg_t *)rbuf.dmsgh,
	    print_pathname, &printed);

	if (rval != DCMD_OK) {
		return (rval);
	}

	if (printed == 0) {
		mdb_warn("Failed to read vmm trace ring buffer.");
		return (DCMD_ERR);
	}

	return (rval);
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "vmm_dmsg_dump", "[-a]", "Dump vmm trace debug messages",
	    vmm_rbuf_dump },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "vmm_dmsg",
	    "walk ring buffer containing vmm trace debug messages",
	    vmm_dmsg_walk_i, vmm_dmsg_walk_s, vmm_dmsg_walk_f },
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
