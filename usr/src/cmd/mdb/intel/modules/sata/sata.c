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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/modctl.h>
#include <note.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddidmareq.h>
#include <sys/devops.h>
#include <time.h>
#include <sys/varargs.h>
#include <sys/sata/sata_hba.h>

/*
 * SATA trace debug walker/dcmd code
 */

/*
 * Initialize the sata_trace_dmsg_t walker by either using the given starting
 * address, or reading the value of the kernel's sata_debug_rbuf pointer.
 * We also allocate a sata_trace_dmsg_t for storage, and save this using the
 * walk_data pointer.
 */
static int
sata_dmsg_walk_i(mdb_walk_state_t *wsp)
{
	uintptr_t rbuf_addr;
	sata_trace_rbuf_t rbuf;

	if (wsp->walk_addr == NULL) {
		if (mdb_readvar(&rbuf_addr, "sata_debug_rbuf") == -1) {
			mdb_warn("failed to read 'sata_debug_rbuf'");
			return (WALK_ERR);
		}

		if (mdb_vread(&rbuf, sizeof (sata_trace_rbuf_t), rbuf_addr)
		    == -1) {
			mdb_warn("failed to read sata_trace_rbuf_t at %p",
			    rbuf_addr);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)(sata_trace_dmsg_t *)rbuf.dmsgh;
	}

	/*
	 * Save ptr to head of ring buffer to prevent looping.
	 */
	wsp->walk_arg = (void *)wsp->walk_addr;
	wsp->walk_data = mdb_alloc(sizeof (sata_trace_dmsg_t), UM_SLEEP);
	return (WALK_NEXT);
}

/*
 * At each step, read a sata_trace_dmsg_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL next
 * pointer.
 */
static int
sata_dmsg_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (sata_trace_dmsg_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read sata_trace_dmsg_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((sata_trace_dmsg_t *)wsp->walk_data)->next);

	/*
	 * If we've looped then we're done.
	 */
	if (wsp->walk_addr == (uintptr_t)wsp->walk_arg)
		wsp->walk_addr = NULL;

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a sata_trace_dmsg_t in sata_dmsg_walk_i, we must
 * free it now.
 */
static void
sata_dmsg_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (sata_trace_dmsg_t));
}

/*
 * This routine is used by the sata_dmsg_dump dcmd to dump content of
 * SATA trace ring buffer.
 */
int
sata_dmsg_dump(sata_trace_dmsg_t *addr, int print_pathname, uint_t *printed)
{
	sata_trace_dmsg_t	dmsg, *dmsgh = addr;
	struct dev_info		dev;
	char			drivername[MODMAXNAMELEN];
	char			pathname[MAXPATHLEN];
	char			merge[1024];

	while (addr != NULL) {
		if (mdb_vread(&dmsg, sizeof (dmsg), (uintptr_t)addr) !=
		    sizeof (dmsg)) {
			mdb_warn("failed to read message pointer in kernel");
			return (DCMD_ERR);
		}

		if (dmsg.dip != NULL) {
			if ((mdb_vread(&dev, sizeof (struct dev_info),
			    (uintptr_t)dmsg.dip)) == -1) {
				(void) mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] : %s",
				    dmsg.timestamp.tv_sec,
				    (int)dmsg.timestamp.tv_nsec/1000000,
				    (int)(dmsg.timestamp.tv_nsec/1000)%1000,
				    (int)dmsg.timestamp.tv_nsec%1000,
				    dmsg.buf);
			} else {
				(void) mdb_devinfo2driver((uintptr_t)dmsg.dip,
				    drivername, sizeof (drivername));
				(void) mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] %s%d: %s",
				    dmsg.timestamp.tv_sec,
				    (int)dmsg.timestamp.tv_nsec/1000000,
				    (int)(dmsg.timestamp.tv_nsec/1000)%1000,
				    (int)dmsg.timestamp.tv_nsec%1000,
				    drivername,
				    dev.devi_instance,
				    dmsg.buf);

				if (print_pathname == TRUE) {
					(void) mdb_ddi_pathname(
					    (uintptr_t)dmsg.dip, pathname,
					    sizeof (pathname));
					mdb_printf("[%s]", pathname);
				}
			}
		} else {
			(void) mdb_snprintf(merge, sizeof (merge),
			    "[%Y:%03d:%03d:%03d] : %s",
			    dmsg.timestamp.tv_sec,
			    (int)dmsg.timestamp.tv_nsec/1000000,
			    (int)(dmsg.timestamp.tv_nsec/1000)%1000,
			    (int)dmsg.timestamp.tv_nsec%1000,
			    dmsg.buf);
		}

		mdb_printf("%s\n", merge);

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
 * 1. Process flag passed to sata_dmsg_dump dcmd.
 * 2. Obtain SATA trace ring buffer pointer.
 * 3. Pass SATA trace ring buffer pointer to sata_dmsg_dump()
 *    to dump content of SATA trace ring buffer.
 */
int
sata_rbuf_dump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sata_trace_rbuf_t	rbuf;
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
	 * it using sata_debug_rbuf global.
	 */
	if ((addr == NULL) || !(flags & DCMD_ADDRSPEC)) {
		if (mdb_readvar(&addr, "sata_debug_rbuf") == -1) {
			mdb_warn("Failed to read 'sata_debug_rbuf'.");
			return (DCMD_ERR);
		}
	}

	if (mdb_vread(&rbuf, sizeof (rbuf), addr) != sizeof (rbuf)) {
		mdb_warn("Failed to read ring buffer in kernel.");
		return (DCMD_ERR);
	}

	if (rbuf.dmsgh == NULL) {
		mdb_printf("The sata trace ring buffer is empty.\n");
		return (DCMD_OK);
	}

	rval = sata_dmsg_dump((sata_trace_dmsg_t *)rbuf.dmsgh,
	    print_pathname, &printed);

	if (rval != DCMD_OK) {
		return (rval);
	}

	if (printed == 0) {
		mdb_warn("Failed to read sata trace ring buffer.");
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
	{ "sata_dmsg_dump", "[-a]", "Dump sata trace debug messages",
	    sata_rbuf_dump },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "sata_dmsg",
	    "walk ring buffer containing sata trace debug messages",
	    sata_dmsg_walk_i, sata_dmsg_walk_s, sata_dmsg_walk_f },
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
