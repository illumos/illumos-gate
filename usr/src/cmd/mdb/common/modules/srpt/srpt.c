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

#include <sys/dditypes.h>
#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/lpif.h>
#include <srp.h>
#include <srpt_impl.h>

/*
 * byteswap macros since ntohl not available in kernel mdb
 */
#if defined(_LITTLE_ENDIAN)
#define	SRPT_BSWAP_32(x)	(((uint32_t)(x) << 24) | \
				(((uint32_t)(x) << 8) & 0xff0000) | \
				(((uint32_t)(x) >> 8) & 0xff00) | \
				((uint32_t)(x)  >> 24))
#define	SRPT_BSWAP_16(x)	((((x) & 0xff) << 8) | ((x) >> 8))
#else
#define	SRPT_BSWAP_32(x) (x)
#define	SRPT_BSWAP_16(x) (x)
#endif /* _LITTLE_ENDIAN */

/*
 * Walker to list the addresses of all the active I/O Controllers
 */
static int
srpt_ioc_walk_init(mdb_walk_state_t *wsp)
{
	srpt_ctxt_t	*srpt;
	uintptr_t	srpt_global_addr, list_addr;

	if (mdb_readvar(&srpt, "srpt_ctxt") == -1) {
		mdb_warn("failed to read srpt soft state");
		return (WALK_ERR);
	}

	srpt_global_addr = (uintptr_t)srpt;

	list_addr = srpt_global_addr + offsetof(srpt_ctxt_t, sc_ioc_list);

	wsp->walk_addr = list_addr;

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("list walk failed");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
srpt_list_walk_step(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Walker to list the target services per I/O Controller. The I/O Controller is
 * provided as input.
 */
static int
srpt_tgt_walk_init(mdb_walk_state_t *wsp)
{
	srpt_ioc_t	srpt_ioc;

	/*
	 * Input should be a srpt_ioc_t, read it to get the
	 * srpt_target_port_t
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("<srpt_ioc_t addr>::walk srpt_target\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&srpt_ioc, sizeof (srpt_ioc_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read in the srpt_ioc\n ");
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)srpt_ioc.ioc_tgt_port;
	wsp->walk_data = mdb_alloc(sizeof (srpt_target_port_t), UM_SLEEP);
	return (WALK_NEXT);
}

static int
srpt_tgt_walk_step(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		return (WALK_DONE);
	}

	(void) wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* Currently there is only one target per IOC */
	return (WALK_DONE);

}

static void
srpt_tgt_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (srpt_target_port_t));
}

/*
 * Walker to list the channels per SRP target service. The target port is
 * provided as input.
 */
static int
srpt_channel_walk_init(mdb_walk_state_t *wsp)
{
	/*
	 * Input should be a srpt_target_port_t, read it to get the
	 * list of channels
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("<srpt_target_port_t addr>::walk srpt_channel\n");
		return (WALK_ERR);
	}

	wsp->walk_addr += offsetof(srpt_target_port_t, tp_ch_list);

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("Could not walk tp_ch_list");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Walker to list the SCSI sessions per target. The target is
 * provided as input.
 */
static int
srpt_scsi_session_walk_init(mdb_walk_state_t *wsp)
{
	/*
	 * Input should be a srpt_target_port_t, read it to get the
	 * srpt_session_t
	 */
	if (wsp->walk_addr == 0) {
		mdb_warn("<srpt_target_port_t addr>::walk srpt_scsi_session\n");
		return (WALK_ERR);
	}

	wsp->walk_addr += offsetof(srpt_target_port_t, tp_sess_list);

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("target session list walk failed");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Walker to list the tasks in a session.  The session is
 * provided as input.
 */
static int
srpt_task_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("<srpt_session_t addr>::walk srpt_tasks\n");
		return (WALK_ERR);
	}

	wsp->walk_addr += offsetof(srpt_session_t, ss_task_list);

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("session task list walk failed");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/* ARGSUSED */
static int
srpt_print_ioc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	srpt_ioc_t	ioc;
	char		mask[9];
	int		i;

	if (addr == 0) {
		mdb_warn("address of srpt_ioc should be specified\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&ioc, sizeof (srpt_ioc_t), addr) == -1) {
		mdb_warn("failed to read srpt_ioc at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("IOC %p\n", addr);
	mdb_printf("    guid: %x\n", ioc.ioc_guid);
	mdb_printf("    target port: %p\n", ioc.ioc_tgt_port);
	mdb_printf("    srq handle: %p\n", ioc.ioc_srq_hdl);
	mdb_printf("    current srq size: %u\n", ioc.ioc_num_iu_entries);
	mdb_printf("	max srq size: %d\n", ioc.ioc_srq_attr.srq_wr_sz);
	mdb_printf("    iu pool: %p\n", ioc.ioc_iu_pool);
	mdb_printf("    profile send qdepth: %d\n",
	    SRPT_BSWAP_16(ioc.ioc_profile.ioc_send_msg_qdepth));
	mdb_printf("    profile rmda read qdepth: %d\n",
	    ioc.ioc_profile.ioc_rdma_read_qdepth);
	mdb_printf("    profile send msg size: %d\n",
	    SRPT_BSWAP_32(ioc.ioc_profile.ioc_send_msg_sz));
	mdb_printf("    profile rmda xfer size: %d\n",
	    SRPT_BSWAP_32(ioc.ioc_profile.ioc_rdma_xfer_sz));
	for (i = 0; i < 8; i++) {
		if (ioc.ioc_profile.ioc_ctrl_opcap_mask & 1<<i) {
			mask[i] = 'x';
		} else {
			mask[i] = '-';
		}
	}
	mask[i] = '\0';
	mdb_printf("    profile opcap mask: %s\n", mask);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "srpt_print_ioc", ":", "Print information about an SRPT IOC",
	    srpt_print_ioc, NULL},
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "srpt_ioc", "Walk active IO controllers",
	    srpt_ioc_walk_init, srpt_list_walk_step, NULL},
	{ "srpt_tgt", "Walk the targets",
	    srpt_tgt_walk_init, srpt_tgt_walk_step, srpt_tgt_walk_fini},
	{ "srpt_channel", "Walk the channels",
	    srpt_channel_walk_init, srpt_list_walk_step, NULL},
	{ "srpt_scsi_session", "Walk the scsi sessions",
	    srpt_scsi_session_walk_init, srpt_list_walk_step, NULL},
	{ "srpt_tasks", "Walk the tasks in a scsi session",
	    srpt_task_walk_init, srpt_list_walk_step, NULL},
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
