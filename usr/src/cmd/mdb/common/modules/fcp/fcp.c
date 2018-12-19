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
 * Copyright (c) 2018, Joyent, Inc.
 */


#include <sys/mdb_modapi.h>
#include <sys/mutex.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/sunndi.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/ulp/fcpvar.h>

static struct fcp_port	port;
static struct fcp_tgt	tgt;
static struct fcp_lun	lun;
static uint32_t	tgt_hash_index;


/*
 * Leadville fcp walker/dcmd code
 */

static int
fcp_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL &&
	    mdb_readvar(&wsp->walk_addr, "fcp_port_head") == -1) {
		mdb_warn("failed to read 'fcp_port_head'");
		return (WALK_ERR);
	}

	wsp->walk_data = mdb_alloc(sizeof (struct fcp_port), UM_SLEEP);
	return (WALK_NEXT);
}

static int
fcp_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_port),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read fcp_port at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_port *)wsp->walk_data)->port_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
fcp_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_port));
}


static int
fcp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct fcp_port		pinfo;

	if (argc != 0) {
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("fcp", "fcp",
		    argc, argv) == -1) {
			mdb_warn("failed to walk 'fcp_port_head'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	mdb_printf("FCP structure at %p\n", addr);

	/*
	 * For each port, we just need to read the fc_fca_port_t struct, read
	 * the port_handle
	 */
	if (mdb_vread(&pinfo, sizeof (struct fcp_port), addr) !=
	    sizeof (struct fcp_port)) {
		mdb_warn("failed to read fcp_port at %p", addr);
		return (DCMD_OK);
	}

	mdb_printf("  mutex             : 0x%-08x\n", pinfo.port_mutex);
	mdb_printf("  ipkt_list         : 0x%p\n", pinfo.port_ipkt_list);
	mdb_printf("  state             : 0x%-08x\n", pinfo.port_state);
	mdb_printf("  phys_state        : 0x%-08x\n", pinfo.port_phys_state);
	mdb_printf("  top               : %u\n", pinfo.port_topology);
	mdb_printf("  sid               : 0x%-06x\n", pinfo.port_id);
	mdb_printf("  reset_list        : 0x%p\n", pinfo.port_reset_list);
	mdb_printf("  link_cnt          : %u\n", pinfo.port_link_cnt);
	mdb_printf("  deadline          : %d\n", pinfo.port_deadline);
	mdb_printf("  port wwn          : "
	    "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
	    pinfo.port_pwwn.raw_wwn[0], pinfo.port_pwwn.raw_wwn[1],
	    pinfo.port_pwwn.raw_wwn[2], pinfo.port_pwwn.raw_wwn[3],
	    pinfo.port_pwwn.raw_wwn[4], pinfo.port_pwwn.raw_wwn[5],
	    pinfo.port_pwwn.raw_wwn[6], pinfo.port_pwwn.raw_wwn[7]);
	mdb_printf("  node wwn          : "
	    "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
	    pinfo.port_nwwn.raw_wwn[0], pinfo.port_nwwn.raw_wwn[1],
	    pinfo.port_nwwn.raw_wwn[2], pinfo.port_nwwn.raw_wwn[3],
	    pinfo.port_nwwn.raw_wwn[4], pinfo.port_nwwn.raw_wwn[5],
	    pinfo.port_nwwn.raw_wwn[6], pinfo.port_nwwn.raw_wwn[7]);
	mdb_printf("  handle            : 0x%p\n", pinfo.port_fp_handle);
	mdb_printf("  cmd_mutex         : 0x%-08x\n", pinfo.port_pkt_mutex);
	mdb_printf("  ncmds             : %u\n", pinfo.port_npkts);
	mdb_printf("  pkt_head          : 0x%p\n", pinfo.port_pkt_head);
	mdb_printf("  pkt_tail          : 0x%p\n", pinfo.port_pkt_tail);
	mdb_printf("  ipkt_cnt          : %d\n", pinfo.port_ipkt_cnt);
	mdb_printf("  instance          : %u\n", pinfo.port_instance);
	mdb_printf("  max_exch          : %u\n", pinfo.port_max_exch);
	mdb_printf("  cmds_aborted      : 0x%-08x\n",
	    pinfo.port_reset_action);
	mdb_printf("  cmds_dma_flags    : 0x%-08x\n",
	    pinfo.port_cmds_dma_flags);
	mdb_printf("  fcp_dma           : 0x%-08x\n", pinfo.port_fcp_dma);
	mdb_printf("  priv_pkt_len      : %u\n", pinfo.port_priv_pkt_len);
	mdb_printf("  data_dma_attr     : 0x%-08x\n",
	    pinfo.port_data_dma_attr);
	mdb_printf("  cmd_dma_attr      : 0x%-08x\n",
	    pinfo.port_cmd_dma_attr);
	mdb_printf("  resp_dma_attr     : 0x%-08x\n",
	    pinfo.port_resp_dma_attr);
	mdb_printf("  dma_acc_attr      : 0x%-08x\n",
	    pinfo.port_dma_acc_attr);
	mdb_printf("  tran              : 0x%p\n", pinfo.port_tran);
	mdb_printf("  dip               : 0x%p\n", pinfo.port_dip);
	mdb_printf("  reset_notify_listf: 0x%p\n",
	    pinfo.port_reset_notify_listf);
	mdb_printf("  event_defs        : 0x%p\n", pinfo.port_ndi_event_defs);
	mdb_printf("  event_hdl         : 0x%p\n", pinfo.port_ndi_event_hdl);
	mdb_printf("  events            : 0x%p\n", pinfo.port_ndi_events);
	mdb_printf("  tgt_hash_table    : 0x%p\n", pinfo.port_tgt_hash_table);
	mdb_printf("  mpxio             : %d\n", pinfo.port_mpxio);

	mdb_printf("\n");

	return (DCMD_OK);
}


/*
 * Leadville cmds walker/dcmd code
 */

static int
cmds_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Can not perform global walk");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fcp_lun, so read it to get the fcp_pkt
	 * lists's head
	 */

	if (mdb_vread(&lun, sizeof (struct fcp_lun), wsp->walk_addr) !=
	    sizeof (struct fcp_lun)) {
		mdb_warn("Unable to read in the fcp_lun structure address\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(lun.lun_pkt_head);
	wsp->walk_data = mdb_alloc(sizeof (struct fcp_pkt), UM_SLEEP);

	return (WALK_NEXT);
}

static int
cmds_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_pkt),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read fcp_pkt at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_pkt *)wsp->walk_data)->cmd_forw);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
cmds_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_pkt));
}


/*
 * Leadville luns walker/dcmd code
 */

static int
luns_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Can not perform global walk");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fcp_tgt, so read it to get the fcp_lun
	 * lists's head
	 */

	if (mdb_vread(&tgt, sizeof (struct fcp_tgt), wsp->walk_addr) !=
	    sizeof (struct fcp_tgt)) {
		mdb_warn("Unable to read in the fcp_tgt structure address\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(tgt.tgt_lun);
	wsp->walk_data = mdb_alloc(sizeof (struct fcp_lun), UM_SLEEP);

	return (WALK_NEXT);
}

static int
luns_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_lun),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read fcp_pkt at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_lun *)wsp->walk_data)->lun_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
luns_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_lun));
}


/*
 * Leadville targets walker/dcmd code
 */

static int
targets_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("Can not perform global walk\n");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fcp_port, so read it to get the port_tgt
	 * table's head
	 */

	if (mdb_vread(&port, sizeof (struct fcp_port), wsp->walk_addr) !=
	    sizeof (struct fcp_port)) {
		mdb_warn("Unable to read in the port structure address\n");
		return (WALK_ERR);
	}

	tgt_hash_index = 0;

	while (tgt_hash_index < FCP_NUM_HASH &&
	    port.port_tgt_hash_table[tgt_hash_index] == NULL) {
		tgt_hash_index++;
	}

	wsp->walk_addr = (uintptr_t)(port.port_tgt_hash_table[tgt_hash_index]);

	wsp->walk_data = mdb_alloc(sizeof (struct fcp_tgt), UM_SLEEP);

	return (WALK_NEXT);
}

static int
targets_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if ((wsp->walk_addr == NULL) &&
	    (tgt_hash_index >= (FCP_NUM_HASH - 1))) {
		return (WALK_DONE);
	}

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_tgt),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read fcp_tgt at %p", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_tgt *)wsp->walk_data)->tgt_next);

	if (wsp->walk_addr == NULL) {
		/*
		 * locate the next hash list
		 */

		tgt_hash_index++;

		while (tgt_hash_index < FCP_NUM_HASH &&
		    port.port_tgt_hash_table[tgt_hash_index] == NULL)
			tgt_hash_index++;

		if (tgt_hash_index == FCP_NUM_HASH) {
			/* You're done */
			return (status);
		}

		wsp->walk_addr =
		    (uintptr_t)(port.port_tgt_hash_table[tgt_hash_index]);
	}

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
targets_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_tgt));
}


/*
 * Leadville fcp_ipkt walker/dcmd code
 */

static int
ipkt_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("The address of a fcp_port"
		    " structure must be given\n");
		return (WALK_ERR);
	}

	/*
	 * Input should be a fcp_port, so read it to get the ipkt
	 * list's head
	 */

	if (mdb_vread(&port, sizeof (struct fcp_port), wsp->walk_addr) !=
	    sizeof (struct fcp_port)) {
		mdb_warn("Failed to read in the fcp_port"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(port.port_ipkt_list);
	wsp->walk_data = mdb_alloc(sizeof (struct fcp_ipkt), UM_SLEEP);

	return (WALK_NEXT);
}

static int
ipkt_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_ipkt),
	    wsp->walk_addr) == -1) {
		mdb_warn("Failed to read in the fcp_ipkt"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_ipkt *)wsp->walk_data)->ipkt_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
ipkt_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_ipkt));
}

/*
 * Leadville fcp_pkt walker/dcmd code
 */

static int
pkt_walk_i(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("The address of a fcp_port"
		    " structure must be given\n");
		return (WALK_ERR);
	}

	/*
	 * Input should be an fcp_port, so read it to get the pkt
	 * list's head
	 */

	if (mdb_vread(&port, sizeof (struct fcp_port), wsp->walk_addr) !=
	    sizeof (struct fcp_port)) {
		mdb_warn("Failed to read in the fcp_port"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)(port.port_pkt_head);
	wsp->walk_data = mdb_alloc(sizeof (struct fcp_pkt), UM_SLEEP);

	return (WALK_NEXT);
}

static int
pkt_walk_s(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct fcp_pkt),
	    wsp->walk_addr) == -1) {
		mdb_warn("Failed to read in the fcp_pkt"
		    " at 0x%p\n", wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((struct fcp_pkt *)wsp->walk_data)->cmd_next);

	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.
 */
static void
pkt_walk_f(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct fcp_pkt));
}

/*
 * MDB module linkage information:
 *
 * We declare a list of structures describing our dcmds, a list of structures
 * describing our walkers, and a function named _mdb_init to return a pointer
 * to our module information.
 */

static const mdb_dcmd_t dcmds[] = {
	{ "fcp", NULL, "Leadville fcp instances", fcp },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "fcp", "Walk list of Leadville fcp instances",
		fcp_walk_i, fcp_walk_s, fcp_walk_f },
	{ "cmds", "Walk list of SCSI commands in fcp's per-lun queue",
		cmds_walk_i, cmds_walk_s, cmds_walk_f },
	{ "luns", "Walk list of LUNs in an fcp target",
		luns_walk_i, luns_walk_s, luns_walk_f },
	{ "targets", "Walk list of fcp targets attached to the local port",
		targets_walk_i, targets_walk_s, targets_walk_f },
	{ "fcp_ipkt", "Walk list of internal packets queued on a local port",
		ipkt_walk_i, ipkt_walk_s, ipkt_walk_f},
	{ "fcp_pkt", "Walk list of packets queued on a local port",
		pkt_walk_i, pkt_walk_s, pkt_walk_f},
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
