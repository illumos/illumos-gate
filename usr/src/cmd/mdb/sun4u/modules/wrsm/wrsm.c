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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mdb_modapi.h>
#include <sys/wrsm.h>
#include <sys/wrsm_common.h>
#include <sys/wrsm_config.h>
#include <sys/wrsm_sess_impl.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_nc_impl.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>


#define	AVAIL_STATE_STR(x) \
	((x == wrsm_disabled) ? "disabled" : \
	(x == wrsm_pending) ? "pending" : \
	(x == wrsm_installed) ? "installed" : \
	(x == wrsm_installed_up) ? "installed_up" : \
	(x == wrsm_enabled) ? "enabled" : \
	"unknown")

#define	SESS_STATE_STR(x) \
	((x == SESS_STATE_UNREACH) ? "unreach" : \
	(x == SESS_STATE_DOWN) ? "down" : \
	(x == SESS_STATE_ESTAB) ? "enabling" : \
	(x == SESS_STATE_UP) ? "up" : \
	"unknown")

#define	ROUTE_STATE_STR(x) \
	((x == ncslice_use_current) ? "use_current" : \
	(x == ncslice_use_new_route) ? "use_new_route" : \
	(x == ncslice_remove_route) ? "remove_route" : \
	(x == ncslice_use_errloopback) ? "use_errloopback" : \
	(x == ncslice_no_route) ? "no_route" : \
	"unknown")


#define	EXPORTSEG_STATE_STR(x) \
	((x == memseg_unpublished) ? "unpublished" : \
	(x == memseg_wait_for_disconnects) ? "wait_disconnects" : \
	(x == memseg_published) ? "published" : \
	"unknown")


#define	LINKSTATE_STR(x) \
	((x == lc_up) ? "up" : \
	(x == lc_down) ? "down" : \
	(x == lc_not_there) ? "not_there" : \
	(x == sc_wait_up) ? "wait_up" : \
	(x == sc_wait_down) ? "wait_down" : \
	(x == sc_wait_errdown) ? "wait_errdown" : \
	"unknown")


/*
 * wrsm_ctlr
 */


/*
 * Initialize the wrsm_ctlr walker by either using the given starting
 * address, or reading the value of the kernel's wrsm_networks pointer.
 */
static int
wrsm_ctlr_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "wrsm_networks") == -1) {
		mdb_warn("failed to read 'wrsm_networks'");
		return (WALK_ERR);
	}

	wsp->walk_data = NULL;
	return (WALK_NEXT);
}

/*
 * At each step, read a wrsm_network_t into our private storage, and then
 * invoke the callback function.  We terminate when we reach a NULL next
 * pointer.
 */
static int
wrsm_ctlr_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsm_network_t net;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&net, sizeof (net), wsp->walk_addr) != sizeof (net)) {
		mdb_warn("failed to read wrsm_network at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, &net, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)net.next;

	return (status);
}

/*
 * print list of valid nodes in wrsm_network_t
 */
void
wrsm_print_nodes(wrsm_network_t *net)
{
	int i;

	mdb_printf("known RSM addresses: ");

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (net->nodes[i]) {
			mdb_printf("%d ", i);
		    }
	}

	mdb_printf("\n");
}

/*
 * dcmd for printing out information about a Wildcat RSM controller
 * (wrsm_network_t).
 */
static int
wrsm_ctlr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	wrsm_network_t net;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsm_network_t address was specified on the command line,
	 * we can print out all wrsm networks (controllers) by invoking the
	 * walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsm_ctlr", "wrsm_ctlr",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsm_ctlr_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (mdb_vread(&net, sizeof (net), addr) != sizeof (net)) {
		mdb_warn("failed to read wrsm_network_t at %p", addr);
		return (DCMD_OK);
	}

	/*
	 * print interesting information
	 */
	mdb_printf("\nController: %3d\n", net.rsm_ctlr_id);
	mdb_printf("---------------\n");
	mdb_printf("availability: %s\nlocal RSM address: %3d\n",
	    AVAIL_STATE_STR(net.availability),
	    net.cnodeid);

	mdb_printf("exported ncslices:");
	for (i = 0; i < WRSM_NODE_NCSLICES; i++) {
		if (net.exported_ncslices.id[i]) {
			mdb_printf(" 0x%x", net.exported_ncslices.id[i]);
			if (i == 0) {
				mdb_printf(" (small)");
			} else {
				mdb_printf(" (large)");
			}
		}
	}
	mdb_printf("\n");
	wrsm_print_nodes(&net);

	mdb_printf("\n");
	return (DCMD_OK);
}




/*
 * wrsm_expseg
 */


typedef struct {
	boolean_t walkall;
	exportseg_t *all_exportsegs_hash[WRSM_PTR_HASH_SIZE];
	exportseg_t *hash_next;
	int hash_index;
} wrsm_expseg_walk_data_t;


/*
 * Initialize the wrsm_expseg walker by either using the given starting
 * address, or reading the value of the kernel's wrsm_networks pointer.  We
 * also allocate and initialize a wrsm_expseg_walk_data_t, and save this
 * using the walk_data pointer.
 */
static int
wrsm_expseg_walk_init(mdb_walk_state_t *wsp)
{
	wrsm_expseg_walk_data_t *expseg_walk_data;
	boolean_t walkall = B_FALSE;

	if (wsp->walk_addr == NULL) {
		walkall = B_TRUE;
		if (mdb_readvar(&wsp->walk_addr, "wrsm_networks") == -1) {
			mdb_warn("failed to read 'wrsm_networks'");
			return (WALK_ERR);
		}

		if (wsp->walk_addr == NULL)
			return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (wrsm_expseg_walk_data_t), UM_SLEEP);
	expseg_walk_data = (wrsm_expseg_walk_data_t *)wsp->walk_data;
	expseg_walk_data->walkall = walkall;

	if (mdb_readsym(&(expseg_walk_data->all_exportsegs_hash),
	    sizeof (expseg_walk_data->all_exportsegs_hash),
	    "all_exportsegs_hash") !=
	    sizeof (expseg_walk_data->all_exportsegs_hash)) {
		mdb_warn("symbol 'all_exportsegs_hash' not found");
		mdb_free(expseg_walk_data, sizeof (wrsm_expseg_walk_data_t));
		return (WALK_ERR);
	}

	expseg_walk_data->hash_index = -1;
	expseg_walk_data->hash_next = NULL;

	return (WALK_NEXT);
}

/*
 * At each step, find the next exportseg_t structure in the
 * all_exportsegs_hash hash that belongs to the current network.  We
 * terminate when we reach the end of the hash and there are no more
 * networks to process.
 */
static int
wrsm_expseg_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsm_network_t net;
	wrsm_expseg_walk_data_t *expseg_walk_data;
	exportseg_t expseg;
	exportseg_t *hash_next;

	expseg_walk_data = (wrsm_expseg_walk_data_t *)wsp->walk_data;
	hash_next = expseg_walk_data->hash_next;

	/* find next exportseg in hash */
	while (hash_next == NULL) {
		do {
			expseg_walk_data->hash_index++;
			if (expseg_walk_data->hash_index ==
			    WRSM_PTR_HASH_SIZE) {
				break;
			}
			hash_next = expseg_walk_data->
			    all_exportsegs_hash[expseg_walk_data->hash_index];

		} while (hash_next == NULL);

		if (hash_next == NULL) {
			/*
			 * At end of all_exportsegs_hash.
			 */
			if (!expseg_walk_data->walkall) {
				/*
				 * only processing current network's exportsegs
				 */
				return (WALK_DONE);
			}

			/*
			 * Get next network, then refresh copy of hash.
			 */
			if (mdb_vread(&net, sizeof (net),
			    wsp->walk_addr) != sizeof (net)) {
				mdb_warn("failed to read wrsm_network "
				    "at %p", wsp->walk_addr);
				return (WALK_DONE);
			}
			if (net.next == NULL) {
				/* no more networks to process */
				return (WALK_DONE);
			}
			if (mdb_readsym(
			    &(expseg_walk_data->all_exportsegs_hash),
			    sizeof (expseg_walk_data->all_exportsegs_hash),
			    "all_exportsegs_hash") !=
			    sizeof (expseg_walk_data->all_exportsegs_hash)) {
				mdb_warn("symbol 'all_exportsegs_hash' "
				    "not found");
				return (WALK_ERR);
			}

			wsp->walk_addr = (uintptr_t)net.next;
			expseg_walk_data->hash_index = -1;
			return (WALK_NEXT);
		}
	}

	if (mdb_vread(&expseg, sizeof (expseg), (uintptr_t)hash_next) !=
	    sizeof (expseg)) {
		mdb_warn("failed to read exportseg_t at %p", hash_next);
		return (WALK_ERR);
	}
	expseg_walk_data->hash_next = expseg.all_next;

	/*
	 * if exportseg doesn't belong to current network, skip
	 */
	if (expseg.network != (wrsm_network_t *)wsp->walk_addr) {
		return (WALK_NEXT);
	}

	/*
	 * found exportseg belonging to current network
	 */

	status = wsp->walk_callback((uintptr_t)hash_next, &expseg,
	    wsp->walk_cbdata);

	return (status);
}


/*
 * The walker's fini function is invoked at the end of each walk.
 * Free the memory pointed to by wsp->walk_data.
 */
static void
wrsm_expseg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (wrsm_expseg_walk_data_t));
}


/*
 * dcmd for printing out information about an exportseg_t
 */
static int
wrsm_expseg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	exportseg_t expseg;
	wrsm_network_t net;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsm_expseg_t address was specified on the command line, we
	 * can print out all wrsm expsegs in all wrsm networks (controllers)
	 * by invoking the walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsm_expseg", "wrsm_expseg",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsm_expseg_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%4s  %18s  %18s  %16s  %8s  %s\n",
		    "ctlr",
		    "handle",
		    "size",
		    "state",
		    "segid",
		    "importing RSMaddrs");
	}

	if (mdb_vread(&expseg, sizeof (expseg), addr) != sizeof (expseg)) {
		mdb_warn("failed to read wrsm_exportseg_t at %p", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&net, sizeof (net), (uintptr_t)expseg.network) !=
	    sizeof (net)) {
		mdb_warn("failed to read wrsm_network_t at %p", expseg.network);
		return (DCMD_OK);
	}


	/*
	 * print interesting information
	 */
	mdb_printf("%4d  0x%016p  0x%016p  %16s  %8u  ",
	    net.rsm_ctlr_id,
	    addr,
	    expseg.size,
	    EXPORTSEG_STATE_STR(expseg.state),
	    expseg.state == memseg_unpublished ? -1 : expseg.segid);

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (expseg.nodes[i].inuse)
			mdb_printf("%d ", i);
	}
	mdb_printf("\n");

	return (DCMD_OK);
}




/*
 * wrsm_impseg
 */


typedef struct {
	boolean_t walkall;
	importseg_t *all_importsegs_hash[WRSM_PTR_HASH_SIZE];
	importseg_t *hash_next;
	int hash_index;
} wrsm_impseg_walk_data_t;


/*
 * Initialize the wrsm_impseg walker by either using the given starting
 * address, or reading the value of the kernel's wrsm_networks pointer.  We
 * also allocate and initialize a wrsm_impseg_walk_data_t, and save this
 * using the walk_data pointer.
 */
static int
wrsm_impseg_walk_init(mdb_walk_state_t *wsp)
{
	wrsm_impseg_walk_data_t *impseg_walk_data;
	boolean_t walkall = B_FALSE;

	if (wsp->walk_addr == NULL) {
		walkall = B_TRUE;
		if (mdb_readvar(&wsp->walk_addr, "wrsm_networks") == -1) {
			mdb_warn("failed to read 'wrsm_networks'");
			return (WALK_ERR);
		}

		if (wsp->walk_addr == NULL)
			return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (wrsm_impseg_walk_data_t), UM_SLEEP);
	impseg_walk_data = (wrsm_impseg_walk_data_t *)wsp->walk_data;
	impseg_walk_data->walkall = walkall;

	if (mdb_readsym(&(impseg_walk_data->all_importsegs_hash),
	    sizeof (impseg_walk_data->all_importsegs_hash),
	    "all_importsegs_hash") !=
	    sizeof (impseg_walk_data->all_importsegs_hash)) {
		mdb_warn("symbol 'all_importsegs_hash' not found");
		mdb_free(impseg_walk_data, sizeof (wrsm_impseg_walk_data_t));
		return (WALK_ERR);
	}

	impseg_walk_data->hash_index = -1;
	impseg_walk_data->hash_next = NULL;

	return (WALK_NEXT);
}

/*
 * At each step, find the next importseg_t structure in the
 * all_importsegs_hash hash that belongs to the current network.  We
 * terminate when we reach the end of the hash and there are no more
 * networks to process.
 */
static int
wrsm_impseg_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsm_network_t net;
	wrsm_impseg_walk_data_t *impseg_walk_data;
	importseg_t impseg;
	importseg_t *hash_next;

	impseg_walk_data = (wrsm_impseg_walk_data_t *)wsp->walk_data;
	hash_next = impseg_walk_data->hash_next;

	/* find next importseg in hash */
	while (hash_next == NULL) {
		do {
			impseg_walk_data->hash_index++;
			if (impseg_walk_data->hash_index ==
			    WRSM_PTR_HASH_SIZE) {
				break;
			}
			hash_next = impseg_walk_data->
			    all_importsegs_hash[impseg_walk_data->hash_index];

		} while (hash_next == NULL);

		if (hash_next == NULL) {
			/*
			 * At end of all_importsegs_hash.
			 */
			if (!impseg_walk_data->walkall) {
				/*
				 * only processing current network's importsegs
				 */
				return (WALK_DONE);
			}

			/*
			 * Get next network, then refresh copy of hash.
			 */
			if (mdb_vread(&net, sizeof (net),
			    wsp->walk_addr) != sizeof (net)) {
				mdb_warn("failed to read wrsm_network "
				    "at %p", wsp->walk_addr);
				return (WALK_DONE);
			}
			if (net.next == NULL) {
				/* no more networks to process */
				return (WALK_DONE);
			}
			if (mdb_readsym(
			    &(impseg_walk_data->all_importsegs_hash),
			    sizeof (impseg_walk_data->all_importsegs_hash),
			    "all_importsegs_hash") !=
			    sizeof (impseg_walk_data->all_importsegs_hash)) {
				mdb_warn("symbol 'all_importsegs_hash' "
				    "not found");
				return (WALK_ERR);
			}

			wsp->walk_addr = (uintptr_t)net.next;
			impseg_walk_data->hash_index = -1;
			return (WALK_NEXT);
		}
	}

	if (mdb_vread(&impseg, sizeof (impseg), (uintptr_t)hash_next) !=
	    sizeof (impseg)) {
		mdb_warn("failed to read importseg_t at %p", hash_next);
		return (WALK_ERR);
	}
	impseg_walk_data->hash_next = impseg.all_next;

	/*
	 * if importseg doesn't belong to current network, skip
	 */
	if (impseg.network != (wrsm_network_t *)wsp->walk_addr) {
		return (WALK_NEXT);
	}

	/*
	 * found next importseg belonging to current network
	 */

	status = wsp->walk_callback((uintptr_t)hash_next, &impseg,
	    wsp->walk_cbdata);

	return (status);
}


/*
 * The walker's fini function is invoked at the end of each walk.
 * Free the memory pointed to by wsp->walk_data.
 */
static void
wrsm_impseg_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (wrsm_impseg_walk_data_t));
}


/*
 * dcmd for printing out information about an importseg_t
 */
static int
wrsm_impseg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	importseg_t impseg;
	wrsm_network_t net;
	iseginfo_t iseginfo;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsm_impseg_t address was specified on the command line, we
	 * can print out all wrsm impsegs in all wrsm networks (controllers)
	 * by invoking the walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsm_impseg", "wrsm_impseg",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsm_impseg_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%4s  %18s  %8s  %7s  %18s  %9s  %8s\n",
		    "ctlr",
		    "handle",
		    "segid",
		    "RSMaddr",
		    "size",
		    "published",
		    "mappings");
	}

	if (mdb_vread(&impseg, sizeof (impseg), addr) != sizeof (impseg)) {
		mdb_warn("failed to read wrsm_importseg_t at %p", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&net, sizeof (net), (uintptr_t)impseg.network) !=
	    sizeof (net)) {
		mdb_warn("failed to read wrsm_network_t at %p", impseg.network);
		return (DCMD_OK);
	}

	if (mdb_vread(&iseginfo, sizeof (iseginfo),
	    (uintptr_t)impseg.iseginfo) != sizeof (iseginfo)) {
		mdb_warn("failed to read iseginfo_t at %p", impseg.iseginfo);
		return (DCMD_OK);
	}

	/*
	 * print interesting information
	 */
	mdb_printf("%4d  0x%016p  %8u  %7d  0x%016p  %9s  %8s\n",
	    net.rsm_ctlr_id,
	    addr,
	    iseginfo.segid,
	    iseginfo.cnodeid,
	    iseginfo.size,
	    impseg.unpublished ? "no" : "yes",
	    impseg.have_mappings ? "yes" : "no");

	return (DCMD_OK);
}






/*
 * wrsm_wci
 */


typedef struct {
	boolean_t walkall;
} wrsm_wci_walk_data_t;


/*
 * Initialize the wrsm_wci walker by either using the given starting
 * address, or reading the value of the kernel's wrsm_networks pointer.  We
 * also allocate a wrsm_wci_walk_data_t for storage, and save this using
 * the walk_data pointer.
 */
static int
wrsm_wci_walk_init(mdb_walk_state_t *wsp)
{
	wrsm_wci_walk_data_t *wci_walk_data;
	boolean_t walkall = B_FALSE;

	if (wsp->walk_addr == NULL) {
		walkall = B_TRUE;
		    if (mdb_readvar(&wsp->walk_addr, "wrsm_networks") == -1) {
			mdb_warn("failed to read 'wrsm_networks'");
			return (WALK_ERR);
		}
	}

	wsp->walk_data = mdb_alloc(sizeof (wrsm_wci_walk_data_t), UM_SLEEP);
	wci_walk_data = (wrsm_wci_walk_data_t *)wsp->walk_data;

	wci_walk_data->walkall = walkall;

	return (WALK_NEXT);
}

/*
 * At each step, read a wrsm_network_t into our private storage, and then
 * invoke the callback function for each wci for which there is a softstate
 * structure in that network.  We terminate when we reach a NULL
 * wrsm_network_t pointer.
 */
static int
wrsm_wci_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsm_network_t net;
	wrsm_nr_t nr;
	wrsm_ncwci_t wci;
	wrsm_ncwci_t *next;
	wrsm_wci_walk_data_t *wci_walk_data;

	wci_walk_data = (wrsm_wci_walk_data_t *)wsp->walk_data;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&net, sizeof (net), wsp->walk_addr) != sizeof (net)) {
		mdb_warn("failed to read wrsm_network at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	if (mdb_vread(&nr, sizeof (nr), (uintptr_t)net.nr) != sizeof (nr)) {
		mdb_warn("failed to read wrsm_nr_t at %p", net.nr);
		return (WALK_DONE);
	}

	next = nr.wcis;
	while (next) {
		if (mdb_vread(&wci, sizeof (wci), (uintptr_t)next) !=
		    sizeof (wci)) {
			mdb_warn("failed to read wsm_ncwci_t at %p", next);
			break;
		}

		if (wci.lcwci) {
			status = wsp->walk_callback((uintptr_t)wci.lcwci,
			    NULL, wsp->walk_cbdata);
		}
		next = wci.next;
	}

	if (wci_walk_data->walkall && net.next) {
		wsp->walk_addr = (uintptr_t)net.next;
		return (status);
	} else {
		return (WALK_DONE);
	}
}


/*
 * The walker's fini function is invoked at the end of each walk.
 * Free the memory pointed to by wsp->walk_data.
 */
static void
wrsm_wci_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (wrsm_wci_walk_data_t));
}


/*
 * dcmd for printing out information about a wrsm_wci_t.
 */
static int
wrsm_wci(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	wrsm_softstate_t wci;
	wrsm_network_t net;
	wrsm_ncwci_t ncwci;
	int rsm_ctlr_id = -1;
	int i;

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsm_softstate_t address was specified on the command
	 * line, we can print out all wrsm wcis in all wrsm networks
	 * (controllers) by invoking the walker, using this dcmd itself as
	 * the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsm_wci", "wrsm_wci",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsm_wci_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}



	if (mdb_vread(&wci, sizeof (wci), addr) != sizeof (wci)) {
		mdb_warn("failed to read wrsm_softstate_t at %p", addr);
		return (DCMD_OK);
	}

	/*
	 * get controller id if this wci is part of a network
	 */
	if (mdb_vread(&ncwci, sizeof (ncwci), (uintptr_t)wci.nc) ==
	    sizeof (ncwci)) {

		if (mdb_vread(&net, sizeof (net), (uintptr_t)ncwci.network) !=
		    sizeof (net)) {
			mdb_warn("failed to read wrsm_network_t at %p",
			    ncwci.network);
			return (DCMD_OK);
		}
		rsm_ctlr_id = net.rsm_ctlr_id;
	}



	/*
	 * print interesting information
	 */

	mdb_printf("\nController: %d\nInstance: %d\nExt Safari Portid: %d\n",
	    rsm_ctlr_id,
	    wci.instance,
	    wci.portid);

	mdb_printf("%4s  %8s\n",
	    "link#",
	    "state");

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
		mdb_printf("%5d  %8s\n",
		i,
		LINKSTATE_STR(wci.links[i].link_req_state));
	}

	return (DCMD_OK);
}





/*
 * wrsm_node
 */


typedef struct {
	boolean_t walkall;
} wrsm_node_walk_data_t;


/*
 * Initialize the wrsm_node walker by either using the given starting
 * address, or reading the value of the kernel's wrsm_networks pointer.  We
 * also allocate a wrsm_node_walk_data_t for storage, and save this using
 * the walk_data pointer.
 */
static int
wrsm_node_walk_init(mdb_walk_state_t *wsp)
{
	wrsm_node_walk_data_t *node_walk_data;
	boolean_t walkall = B_FALSE;

	if (wsp->walk_addr == NULL) {
		walkall = B_TRUE;
		    if (mdb_readvar(&wsp->walk_addr, "wrsm_networks") == -1) {
			mdb_warn("failed to read 'wrsm_networks'");
			return (WALK_ERR);
		}

		if (wsp->walk_addr == NULL)
			return (WALK_DONE);
	}

	wsp->walk_data = mdb_alloc(sizeof (wrsm_node_walk_data_t), UM_SLEEP);
	node_walk_data = (wrsm_node_walk_data_t *)wsp->walk_data;

	node_walk_data->walkall = walkall;

	return (WALK_NEXT);
}

/*
 * At each step, read a wrsm_network_t into our private storage, and then
 * invoke the callback function for each valid node in that network.  We
 * terminate when we reach a NULL wrsm_network_t pointer.
 */
static int
wrsm_node_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	wrsm_network_t net;
	wrsm_node_walk_data_t *node_walk_data;
	int cnodeid = 0;

	node_walk_data = (wrsm_node_walk_data_t *)wsp->walk_data;

	if (mdb_vread(&net, sizeof (net), wsp->walk_addr) != sizeof (net)) {
		mdb_warn("failed to read wrsm_network at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	while (cnodeid < WRSM_MAX_CNODES) {
		if (net.nodes[cnodeid] != NULL) {
			status = wsp->walk_callback(
			    (uintptr_t)net.nodes[cnodeid],
			    NULL, wsp->walk_cbdata);
		}
		cnodeid++;
	}

	if (node_walk_data->walkall && net.next) {
		wsp->walk_addr = (uintptr_t)net.next;
		return (status);
	} else {
		return (WALK_DONE);
	}
}


/*
 * The walker's fini function is invoked at the end of each walk.
 * Free the memory pointed to by wsp->walk_data.
 */
static void
wrsm_node_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (wrsm_node_walk_data_t));
}


/*
 * dcmd for printing out information about a wrsm_node_t.
 */
static int
wrsm_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	wrsm_node_t node;
	wrsm_net_member_t config;		/* node config info */
	wrsm_network_t net;
	wrsm_session_t sess;
	wrsm_node_routeinfo_t routeinfo;	/* routing config for node */

	if (argc != 0)
		return (DCMD_USAGE);

	/*
	 * If no wrsm_node_t address was specified on the command line, we
	 * can print out all wrsm nodes in all wrsm networks (controllers)
	 * by invoking the walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("wrsm_node", "wrsm_node",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'wrsm_node_walk'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	/*
	 * If this is the first invocation of the command, print a nice
	 * header line for the output that will follow.
	 */
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%4s  %7s  %12s  %6s  %8s  %15s  %s\n",
		"", "", "", "have", "", "", "");
		mdb_printf("%4s  %7s  %12s  %6s  %8s  %15s  %s\n",
		    "ctlr",
		    "RSMaddr",
		    "availability", "route?", "session", "route state",
		    "hostname");
	}

	if (mdb_vread(&node, sizeof (node), addr) != sizeof (node)) {
		mdb_warn("failed to read wrsm_node_t at %p", addr);
		return (DCMD_OK);
	}

	if (mdb_vread(&config, sizeof (config), (uintptr_t)node.config) !=
	    sizeof (config)) {
		mdb_warn("failed to read wrsm_net_member_t at %p", node.config);
		return (DCMD_OK);
	}

	if (mdb_vread(&net, sizeof (net), (uintptr_t)node.network) !=
	    sizeof (net)) {
		mdb_warn("failed to read wrsm_network_t at %p", node.network);
		return (DCMD_OK);
	}

	if (mdb_vread(&sess, sizeof (sess), (uintptr_t)net.session) !=
	    sizeof (sess)) {
		mdb_warn("failed to read wrsm_session_t at %p", net.session);
		return (DCMD_OK);
	}

	if (mdb_vread(&routeinfo, sizeof (routeinfo),
	    (uintptr_t)node.routeinfo) != sizeof (routeinfo)) {
		mdb_warn("failed to read wrsm_node_routeinfo_t at %p",
		    node.routeinfo);
		return (DCMD_OK);
	}


	/*
	 * print interesting information
	 */
	mdb_printf("%4d  %7d  %12s  %6s  %8s  %15s  %s\n",
	    net.rsm_ctlr_id,
	    config.cnodeid,
	    AVAIL_STATE_STR(node.availability),
	    node.state ? "yes" : "no",
	    SESS_STATE_STR(sess.node[config.cnodeid].state),
	    ROUTE_STATE_STR(routeinfo.route_state),
	    config.hostname);

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
	{ "wrsm_ctlr", NULL, "wrsm controller structure information",
	    wrsm_ctlr },
	{ "wrsm_node", NULL, "wrsm node structure information",
	    wrsm_node },
	{ "wrsm_expseg", NULL, "wrsm expseg structure information",
	    wrsm_expseg },
	{ "wrsm_impseg", NULL, "wrsm impseg structure information",
	    wrsm_impseg },
	{ "wrsm_wci", NULL, "wrsm WCI structure information",
	    wrsm_wci },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "wrsm_ctlr", "walk list of wrsm controller structures",
		wrsm_ctlr_walk_init, wrsm_ctlr_walk_step, NULL },
	{ "wrsm_node", "walk wrsm node structures in controller",
		wrsm_node_walk_init, wrsm_node_walk_step, wrsm_node_walk_fini },
	{ "wrsm_expseg", "walk wrsm expseg structures in controller",
		wrsm_expseg_walk_init, wrsm_expseg_walk_step,
		wrsm_expseg_walk_fini },
	{ "wrsm_impseg", "walk wrsm impseg structures in controller",
		wrsm_impseg_walk_init, wrsm_impseg_walk_step,
		wrsm_impseg_walk_fini },
	{ "wrsm_wci", "walk wrsm WCI structures in controller",
		wrsm_wci_walk_init, wrsm_wci_walk_step, wrsm_wci_walk_fini },
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
