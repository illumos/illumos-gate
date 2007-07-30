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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>
#include <sys/stream.h>
#include <sys/note.h>
#include <sys/wrsmd.h>

#define	WRSMDSTATE_TO_SHORTSTR(x) (				\
	(x == WRSMD_STATE_NEW) ? "NEW" :				\
	(x == WRSMD_STATE_INPROGRESS) ? "INPROGRESS" :		\
	(x == WRSMD_STATE_DELETING) ? "DELETING" :		\
	(x == WRSMD_STATE_W_SCONNTMO) ? "W_SCONNTMO" :		\
	(x == WRSMD_STATE_W_ACCEPT) ? "W_ACCEPT" :		\
	(x == WRSMD_STATE_W_ACK) ? "W_ACK"  :			\
	(x == WRSMD_STATE_W_READY) ? "W_READY" :			\
	(x == WRSMD_STATE_W_FQE) ? "W_FQE" :			\
	(x == WRSMD_STATE_S_REQ_CONNECT) ? "S_REQ_CONNECT" :	\
	(x == WRSMD_STATE_S_NEWCONN) ? "S_NEWCONN" :		\
	(x == WRSMD_STATE_S_CONNXFER_ACCEPT) ? "S_CONNXFER_ACCEPT" : \
	(x == WRSMD_STATE_S_CONNXFER_ACK) ? "S_CONNXFER_ACK" :	\
	(x == WRSMD_STATE_S_XFER) ? "S_XFER" :			\
	(x == WRSMD_STATE_S_DELETE) ? "S_DELETE" :		\
	(x == WRSMD_STATE_S_SCONN) ? "S_SCONN" : "unknown")




/*
 * wrsmd_dev
 */


/*
 * Initialize the wrsmd_dev walker by either using the given starting
 * address, or reading the value of the kernel's wrsmddev pointer.
 */
static int
wrsmd_dev_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "wrsmddev") == -1) {
		mdb_warn("failed to read 'wrsmddev'");
		return (WALK_ERR);
	}

	wsp->walk_data = NULL;
	return (WALK_NEXT);
}

/*
 * At each step, read a wrsmd_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL next
 * pointer.
 */
static int
wrsmd_dev_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsmd_t wrsmd;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&wrsmd, sizeof (wrsmd), wsp->walk_addr) !=
	    sizeof (wrsmd)) {
		mdb_warn("failed to read wrsmd_t at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &wrsmd, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)wrsmd.wrsmd_nextp;

	return (status);
}


/*
 * print list of valid nodes in wrsmd
 */
void
wrsmd_print_nodes(wrsmd_t *wrsmd)
{
	int i;
	wrsmd_dest_t dest;
	wrsmd_dqe_t dqe;
	wrsmd_fqe_t fqe;

	mdb_printf("Remote Destinations:\n");
	mdb_printf("%7s  %34s  %6s  %6s  %8s\n",
	    "rsmaddr",
	    "____________state/estate___________",
	    "dstate",
	    "refcnt",
	    "pkts-q'd?");

	for (i = 0; i < RSM_MAX_DESTADDR; i++) {
		if (wrsmd->wrsmd_desttbl[i]) {
			if (mdb_vread(&dest, sizeof (dest),
			    (uintptr_t)wrsmd->wrsmd_desttbl[i]) !=
			    sizeof (dest)) {
				mdb_warn("failed to read wrsmd_dest_t at %p",
				    wrsmd->wrsmd_desttbl[i]);
				return;
			}

			mdb_printf("%7d  %17s/%17s  %6d  %6d  %8s\n",
			    dest.rd_rsm_addr,
			    WRSMDSTATE_TO_SHORTSTR(dest.rd_state),
			    WRSMDSTATE_TO_SHORTSTR(dest.rd_estate),
			    dest.rd_dstate,
			    dest.rd_refcnt,
			    dest.rd_queue_h ? "yes" : "no");
			mdb_printf("		exportseg "
			    "handle & segid: 0x%16p %8d\n",
			    dest.rd_lxferhand,
			    dest.rd_lxfersegid);
			mdb_printf("		importseg "
			    "handle & segid: 0x%16p %8d\n",
			    dest.rd_rxferhand,
			    dest.rd_rxfersegid);
			mdb_printf("		loaned-bufs %u\n",
			    dest.rd_nlb);

			if (mdb_vread(&fqe, sizeof (wrsmd_fqe_t),
			    (uintptr_t)dest.rd_fqr_n) != sizeof (wrsmd_fqe_t)) {
				mdb_warn("failed to read fqe at %p",
				    dest.rd_fqr_n);
			} else {
				mdb_printf("		available fqes? %s\n",
				    (dest.rd_cached_fqr_cnt ||
				    (fqe.s.fq_seqnum == (dest.rd_fqr_seq &
				    WRSMD_FQE_SEQ_MASK))) ? "yes" : "no");
			}

			if (mdb_vread(&dqe, sizeof (wrsmd_dqe_t),
			    (uintptr_t)dest.rd_dqr_n) != sizeof (wrsmd_dqe_t)) {
				mdb_warn("failed to read dqe at %p",
				    dest.rd_dqr_n);
			} else {
				mdb_printf("		available dqes? %s\n",
				    (dqe.s.dq_seqnum == (dest.rd_dqr_seq &
				    WRSMD_DQE_SEQ_MASK)) ? "yes" : "no");
			}
		}
	}

	mdb_printf("\n");
}



/*
 * dcmd for printing out information about a Wildcat RSM controller
 * (wrsmd_t).
 */
static int
wrsmd_dev(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	wrsmd_t wrsmd;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsmd_t address was specified on the command line,
	 * we can print out all wrsmd wrsmd (controllers) by invoking the
	 * walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsmd_dev", "wrsmd_dev",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsmd_dev_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (mdb_vread(&wrsmd, sizeof (wrsmd), addr) != sizeof (wrsmd)) {
		mdb_warn("failed to read wrsmd_t at %p", addr);
		return (DCMD_OK);
	}

	/*
	 * print interesting information
	 */
	mdb_printf("\nDevice Instance (Controller Id): %3d\n",
	    wrsmd.wrsmd_ctlr_id);
	mdb_printf("--------------------------------------\n");
	mdb_printf("RSM address: %d\n",
	    wrsmd.wrsmd_rsm_addr);
	mdb_printf("attached streams: %d\n",
	    wrsmd.wrsmd_attached_streams);

	mdb_printf("ipackets %lu ierrors %u opackets %lu oerrors %u\n",
	    wrsmd.wrsmd_ipackets,
	    wrsmd.wrsmd_ierrors,
	    wrsmd.wrsmd_opackets,
	    wrsmd.wrsmd_oerrors);

	mdb_printf("collisions %u  xfers %u xfer_pkts %u syncdqes %u\n",
	    wrsmd.wrsmd_collisions,
	    wrsmd.wrsmd_xfers,
	    wrsmd.wrsmd_xfer_pkts,
	    wrsmd.wrsmd_syncdqes);

	mdb_printf("lbufs %u nlbufs %u pullup %u pullup_fail %u\n",
	    wrsmd.wrsmd_lbufs,
	    wrsmd.wrsmd_nlbufs,
	    wrsmd.wrsmd_pullup,
	    wrsmd.wrsmd_pullup_fail);

	mdb_printf("starts %u start_xfers %u fqetmo_hint %u fqetmo_drops %u "
	    "maxq_drops %u\n",
	    wrsmd.wrsmd_starts,
	    wrsmd.wrsmd_start_xfers,
	    wrsmd.wrsmd_fqetmo_hint,
	    wrsmd.wrsmd_fqetmo_drops,
	    wrsmd.wrsmd_maxq_drops);

	mdb_printf("errs %u in_bytes %lu out_bytes %lu\n",
	    wrsmd.wrsmd_errs,
	    wrsmd.wrsmd_in_bytes,
	    wrsmd.wrsmd_out_bytes);

	wrsmd_print_nodes(&wrsmd);

	mdb_printf("\n");
	return (DCMD_OK);
}




/*
 * setup info
 */

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "wrsmd_dev", NULL, "wrsmd device information",
	    wrsmd_dev },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "wrsmd_dev", "walk list of wrsmd device structures",
		wrsmd_dev_walk_init, wrsmd_dev_walk_step, NULL },
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
