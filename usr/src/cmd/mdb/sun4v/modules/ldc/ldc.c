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
 */

/*
 * This module provides debugging tools for the LDoms channels (ldc)
 */

#include <sys/mdb_modapi.h>
#include <sys/ldc.h>
#include <sys/ldc_impl.h>
#include <sys/hypervisor_api.h>

#define	ALLBITS	(u_longlong_t)-1

const mdb_bitmask_t ldc_mode_bits[] = {
	{ "raw   ", ALLBITS, LDC_MODE_RAW },
	{ "unrel ", ALLBITS, LDC_MODE_UNRELIABLE },
	{ "rel   ", ALLBITS, LDC_MODE_RELIABLE },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_status_bits[] = {
	{ "init  ", ALLBITS, LDC_INIT },
	{ "open  ", ALLBITS, LDC_OPEN },
	{ "ready ", ALLBITS, LDC_READY },
	{ "up    ", ALLBITS, LDC_UP },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_tstate_bits[] = {
	{ "txq", TS_TXQ_RDY, TS_TXQ_RDY },
	{ "rxq", TS_RXQ_RDY, TS_RXQ_RDY },
	{ "hv_qconf", TS_QCONF_RDY, TS_QCONF_RDY },
	{ "cnex_reg", TS_CNEX_RDY, TS_CNEX_RDY },
	{ "hv_link_rdy", TS_LINK_READY, TS_LINK_READY },
	{ "ver_done", TS_VER_DONE, TS_VER_DONE },
	{ "hs_done", TS_HSHAKE_DONE, TS_HSHAKE_DONE },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_hstate_bits[] = {
	{ "snt_ver", TS_SENT_VER, TS_SENT_VER },
	{ "snt_rts", TS_SENT_RTS, TS_SENT_RTS },
	{ "rcv_rtr", TS_RCVD_RTR, TS_RCVD_RTR },
	{ "snt_rdx", TS_SENT_RDX, TS_SENT_RDX },
	{ "rcv_ver", TS_RCVD_VER, TS_RCVD_VER },
	{ "rcv_rts", TS_RCVD_RTS, TS_RCVD_RTS },
	{ "snt_rtr", TS_SENT_RTR, TS_SENT_RTR },
	{ "rcv_rdx", TS_RCVD_RDX, TS_RCVD_RDX },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_class_bits[] = {
	{ "generic ", ALLBITS, LDC_DEV_GENERIC },
	{ "blk     ", ALLBITS, LDC_DEV_BLK },
	{ "blk_svc ", ALLBITS, LDC_DEV_BLK_SVC },
	{ "net     ", ALLBITS, LDC_DEV_NT },
	{ "net_svc ", ALLBITS, LDC_DEV_NT_SVC },
	{ "serial  ", ALLBITS, LDC_DEV_SERIAL },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_intrstate_bits[] = {
	{ "none   ", ALLBITS, LDC_INTR_NONE },
	{ "active ", ALLBITS, LDC_INTR_ACTIVE },
	{ "pending", ALLBITS, LDC_INTR_PEND },
	{ NULL, 0, 0}
};

const mdb_bitmask_t ldc_linkstate_bits[] = {
	{ "down ", ALLBITS, LDC_CHANNEL_DOWN },
	{ "reset", ALLBITS, LDC_CHANNEL_RESET },
	{ "up   ", ALLBITS, LDC_CHANNEL_UP },
	{ NULL, 0, 0}
};

const mdb_bitmask_t msg_type_bits[] = {
	{ "ctrl", ALLBITS, LDC_CTRL },
	{ "data", ALLBITS, LDC_DATA },
	{ "err ", ALLBITS, LDC_ERR },
	{ NULL, 0, 0}
};

const mdb_bitmask_t msg_stype_bits[] = {
	{ "info ", ALLBITS, LDC_INFO },
	{ "ack  ", ALLBITS, LDC_ACK },
	{ "nack ", ALLBITS, LDC_NACK },
	{ NULL, 0, 0}
};

const mdb_bitmask_t msg_ctrl_bits[] = {
	{ "ver ", ALLBITS, LDC_VER },
	{ "rts ", ALLBITS, LDC_RTS },
	{ "rtr ", ALLBITS, LDC_RTR },
	{ "rdx ", ALLBITS, LDC_RDX },
	{ NULL, 0, 0}
};

const mdb_bitmask_t mhdl_status_bits[] = {
	{ "unbound", ALLBITS, LDC_UNBOUND },
	{ "bound  ", LDC_BOUND, LDC_BOUND },
	{ "mapped ", LDC_MAPPED, LDC_MAPPED },
	{ NULL, 0, 0}
};

const mdb_bitmask_t mhdl_type_bits[] = {
	{ "shadow ", ALLBITS, LDC_SHADOW_MAP },
	{ "direct ", ALLBITS, LDC_DIRECT_MAP },
	{ "io     ", ALLBITS, LDC_IO_MAP },
	{ NULL, 0, 0}
};

const mdb_bitmask_t mhdl_perm_bits[] = {
	{ "r-- ", ALLBITS, LDC_MEM_R },
	{ "-w- ", ALLBITS, LDC_MEM_W },
	{ "--x ", ALLBITS, LDC_MEM_X },
	{ "rw- ", ALLBITS, LDC_MEM_RW },
	{ "rwx ", ALLBITS, LDC_MEM_RWX },
	{ NULL, 0, 0}
};


/*
 * Print LDC channel information
 */
int
ldcinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE;
	ldc_chan_t	ldcp;

	/*
	 * If no ldc_chan_t address was specified on the command line,
	 * we can print out all ldc channels by invoking the
	 * walker, using this dcmd itself as the callback.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("ldcinfo", "ldcinfo", argc, argv) == -1) {
			mdb_warn("failed to walk 'ldcinfo'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}


	if (mdb_vread(&ldcp, sizeof (ldcp), addr) != sizeof (ldcp)) {
		mdb_warn("failed to read ldc_chan_t at %p", addr);
		return (DCMD_ERR);
	}


	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%-5s %-13s  %-6s  %-8s  %-6s  %-6s  %-6s  %-8s\n",
		    "ID", "ADDR", "MODE", "DEVCLASS", "STATUS", "TSTATE",
		    "HSTATE", "HV_LINK");
	}

	mdb_printf("0x%-3x 0x%p  %b  %b  %b  0x%-4x  0x%-4x  %b\n",
	    ldcp.id, addr, ldcp.mode, ldc_mode_bits,
	    ldcp.devclass, ldc_class_bits,
	    ldcp.status, ldc_status_bits, ldcp.tstate, ldcp.hstate,
	    ldcp.link_state, ldc_linkstate_bits);

	if (verbose) {
		mdb_printf("Link State: %b\n", ldcp.tstate, ldc_tstate_bits);
		mdb_printf("Hshake State: %b\n", ldcp.hstate, ldc_hstate_bits);
		mdb_printf("Callback: %a(0x%p) - %s\n",
		    ldcp.cb, ldcp.cb_arg,
		    (ldcp.cb_enabled == 1) ? "enabled" : "disabled");
		mdb_printf("Tx Info: 0x%p len=0x%lx hd=0x%lx tl=0x%lx "
		    "intr=%b\n", ldcp.tx_q_va, ldcp.tx_q_entries, ldcp.tx_head,
		    ldcp.tx_tail, ldcp.tx_intr_state, ldc_intrstate_bits);
		mdb_printf("Rx Info: 0x%p len=0x%lx intr=%b\n",
		    ldcp.rx_q_va, ldcp.rx_q_entries,
		    ldcp.rx_intr_state, ldc_intrstate_bits);
		if (ldcp.mode == LDC_MODE_RELIABLE) {
			mdb_printf("Rx Dq Info: 0x%p len=0x%lx hd=0x%lx "
			    "tl=0x%lx ackhd=0x%lx", ldcp.rx_dq_va,
			    ldcp.rx_dq_entries, ldcp.rx_dq_head,
			    ldcp.rx_dq_tail, ldcp.rx_ack_head);
			mdb_printf("Stream: buf=0x%p off=0x%lx remains=0x%lx\n",
			    ldcp.stream_bufferp, ldcp.stream_offset,
			    ldcp.stream_remains);
		}
		if (ldcp.mtbl != NULL || ldcp.mhdl_list != NULL)
			mdb_printf("Memory: mtbl=0x%p mhdl_list=0x%p\n",
			    ldcp.mtbl, ldcp.mhdl_list);
		if (ldcp.exp_dring_list != NULL || ldcp.imp_dring_list != NULL)
			mdb_printf("Desc Ring: exported=0x%p imported=0x%p\n",
			    ldcp.exp_dring_list, ldcp.imp_dring_list);
		mdb_printf("\n");
	}
	return (DCMD_OK);
}


/*
 * ldcinfo walker initialization
 */
int
ldc_walk_init(mdb_walk_state_t *wsp)
{
	ldc_soft_state_t	softstate;

	/* Must have a start addr.  */
	if (wsp->walk_addr == (uintptr_t)NULL) {
		if (mdb_readvar(&wsp->walk_addr, "ldcssp") == -1) {
			mdb_warn("failed to read 'ldcssp'");
			return (WALK_ERR);
		}

		if (wsp->walk_addr == (uintptr_t)NULL)
			return (WALK_DONE);

		if (mdb_vread(&softstate, sizeof (softstate), wsp->walk_addr)
		    != sizeof (softstate)) {
			mdb_warn("failed to read softstate %p", wsp->walk_addr);
			return (WALK_ERR);
		}

		wsp->walk_addr = (uintptr_t)softstate.chan_list;
	}

	return (WALK_NEXT);
}

/*
 * ldcinfo walker step routine.
 */
int
ldc_walk_step(mdb_walk_state_t *wsp)
{
	int			status;
	ldc_chan_t		ldcp;

	if (wsp->walk_addr == (uintptr_t)NULL)
		return (WALK_DONE);

	if (mdb_vread(&ldcp, sizeof (ldc_chan_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read at %p", wsp->walk_addr);

		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &ldcp,
	    wsp->walk_cbdata);
	wsp->walk_addr = (uintptr_t)ldcp.next;

	return (status);
}


/*
 * dcmd to print ldc packet information
 *
 * arg0 - count (number of pkts to print)
 */
int
ldcmsg(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ldc_msg_t	msg;
	uint64_t	count = 1;
	int		i;

	/*
	 * If no ldc_msg_t address was specified on the command line,
	 * print usage.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	/* chk if we need to print more that one pkt */
	if (argc != 0) {
		const mdb_arg_t *arg = &argv[0];

		if (arg->a_type == MDB_TYPE_IMMEDIATE)
			count = arg->a_un.a_val;
		else
			count = (uint64_t)mdb_strtoull(arg->a_un.a_str);
	}

	/* print header */
	mdb_printf("%-13s %-10s %-4s %-5s %-4s %-11s %-4s %-10s\n",
	    "ADDR", "SEQID", "TYPE", "STYPE", "CTRL", "ENVELOPE",
	    "SIZE", "ACKID");

	/* print pkt */
	for (i = 0; i < count; i++) {

		if (mdb_vread(&msg, sizeof (msg), addr) != sizeof (msg)) {
			mdb_warn("failed to read ldc_msg_t at %p", addr);
			return (DCMD_ERR);
		}

		mdb_printf("0x%p 0x%-8x %b %b", addr, msg.seqid,
		    msg.type, msg_type_bits, msg.stype, msg_stype_bits);

		if (msg.type == LDC_CTRL)
			mdb_printf(" %b ", msg.ctrl, msg_ctrl_bits);
		else
			mdb_printf(" %-4s ", "--");

		mdb_printf("%-5s %-5s",
		    ((msg.env & LDC_FRAG_START) != 0) ? "start" : "--",
		    ((msg.env & LDC_FRAG_STOP) != 0) ? "stop" : "--");

		/* print size */
		if (msg.type == LDC_DATA && msg.stype == LDC_INFO)
			mdb_printf(" 0x%-2x ", (msg.env & LDC_LEN_MASK));
		else
			mdb_printf(" %-4s ", "--");

		/* print ackid if data/ack */
		if (msg.type == LDC_DATA && msg.stype == LDC_ACK)
			mdb_printf("0x%-8x\n", msg.ackid);
		else
			mdb_printf("%-10s\n", "--");

		/* next packet */
		addr = addr + LDC_PACKET_SIZE;
	}

	return (DCMD_OK);
}


/*
 * Print LDC map table information
 */
int
ldcmtbl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE;
	ldc_mtbl_t	mtbl;
	ldc_mte_slot_t	mte;
	uintptr_t	mteaddr;
	int		i;

	/*
	 * If no ldc_mtbl_t address was specified on the command line,
	 * print usage.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	if (mdb_vread(&mtbl, sizeof (mtbl), addr) != sizeof (mtbl)) {
		mdb_warn("failed to read ldc_mtbl_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("Map Table: addr=0x%p total=%ld free=%ld tbl_base=0x%p\n",
	    addr, mtbl.num_entries, mtbl.num_avail, mtbl.table);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc) {
		return (DCMD_USAGE);
	}
	if (!verbose)
		return (DCMD_OK);

	/* print table header */
	mdb_printf("\n%-4s  %-13s %-2s %-2s %-2s %-2s %-2s %-2s %-2s %-5s\n",
	    "IDX", "RA_PFN", "CW", "CR", "IW", "IR", "X", "W", "R", "PGSZC");

	/* print each table entry */
	mteaddr = (uintptr_t)mtbl.table;
	for (i = 0; i < mtbl.num_entries; i++) {
		if (mdb_vread(&mte, sizeof (mte), mteaddr) != sizeof (mte)) {
			return (DCMD_ABORT);
		}

		/* skip empty entries */
		if (mte.entry.ll != 0) {
			mdb_printf("%-4d  0x%-11x %-2d %-2d %-2d %-2d "
			    "%-2d %-2d %-2d 0x%-2x\n",
			    i, mte.entry.mte_bit.rpfn, mte.entry.mte_bit.cw,
			    mte.entry.mte_bit.cr, mte.entry.mte_bit.iw,
			    mte.entry.mte_bit.ir, mte.entry.mte_bit.x,
			    mte.entry.mte_bit.w, mte.entry.mte_bit.r,
			    mte.entry.mte_bit.pgszc);
		}
		mteaddr = mteaddr + sizeof (ldc_mte_slot_t);
	}
	return (DCMD_OK);
}



/*
 * Print LDC channel memory handle information
 */
int
ldcmhdl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ldc_mhdl_t	mhdl;
	ldc_memseg_t	memseg;
	uint64_t	count = 1;
	int		i;

	/*
	 * If no ldc_msg_t address was specified on the command line,
	 * print usage.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		return (DCMD_USAGE);
	}

	/* chk if we need to print more that one pkt */
	if (argc != 0) {
		const mdb_arg_t *arg = &argv[0];

		if (arg->a_type == MDB_TYPE_IMMEDIATE)
			count = arg->a_un.a_val;
		else
			count = (uint64_t)mdb_strtoull(arg->a_un.a_str);
	}

	mdb_printf("%-13s  %-7s %-7s %-4s %-13s %-13s %-10s\n",
	    "ADDR", "STATUS", "MAPTYPE", "PERM", "MEMSEG", "VADDR", "SIZE");

	/* print pkt */
	for (i = 0; i < count; i++) {

		if (mdb_vread(&mhdl, sizeof (mhdl), addr) != sizeof (mhdl)) {
			mdb_warn("failed to read ldc_mhdl_t at %p", addr);
			return (DCMD_ERR);
		}

		mdb_printf("0x%p  %b %b %b 0x%p ",
		    addr, mhdl.status, mhdl_status_bits,
		    mhdl.mtype, mhdl_type_bits, mhdl.perm, mhdl_perm_bits,
		    mhdl.memseg);

		if (mhdl.memseg != NULL) {
			if (mdb_vread(&memseg, sizeof (memseg),
			    (uintptr_t)mhdl.memseg) != sizeof (memseg)) {
				mdb_warn("failed to read ldc_memseg_t at %p",
				    mhdl.memseg);
				return (DCMD_ERR);
			}

			mdb_printf("0x%p 0x%-8lx\n", memseg.vaddr, memseg.size);
		} else {
			mdb_printf("\n");
		}

		if ((addr = (uintptr_t)mhdl.next) == (uintptr_t)NULL)
			break;
	}

	return (DCMD_OK);
}


/*
 * MDB module linkage information:
 */
static const mdb_dcmd_t dcmds[] = {
	{ "ldcinfo", "?[-v]",  "LDom channel information", ldcinfo },
	{ "ldcmsg",  ":[cnt]", "LDom channel message", ldcmsg },
	{ "ldcmtbl", ":[-v]",  "LDom channel map table", ldcmtbl },
	{ "ldcmhdl", ":[cnt]", "LDom channel memory handles", ldcmhdl },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "ldcinfo", "List all LDom channels",
	    ldc_walk_init, ldc_walk_step, NULL },
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
