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

#include <sys/mdb_modapi.h>
#include <sys/types.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_flow_impl.h>
#include <sys/mac_soft_ring.h>

#define	STRSIZE	64
#define	MAC_RX_SRS_SIZE	 (MAX_RINGS_PER_GROUP * sizeof (uintptr_t))

#define	LAYERED_WALKER_FOR_FLOW	"flow_entry_cache"
#define	LAYERED_WALKER_FOR_SRS	"mac_srs_cache"
#define	LAYERED_WALKER_FOR_RING	"mac_ring_cache"

/* arguments passed to mac_flow dee-command */
#define	MAC_FLOW_NONE	0x01
#define	MAC_FLOW_ATTR	0x02
#define	MAC_FLOW_PROP	0x04
#define	MAC_FLOW_RX	0x08
#define	MAC_FLOW_TX	0x10
#define	MAC_FLOW_USER	0x20
#define	MAC_FLOW_STATS	0x40
#define	MAC_FLOW_MISC	0x80

/* arguments passed to mac_srs dee-command */
#define	MAC_SRS_RX	0x01
#define	MAC_SRS_TX	0x02

static char *
mac_flow_proto2str(uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return ("tcp");
	case IPPROTO_UDP:
		return ("udp");
	case IPPROTO_SCTP:
		return ("sctp");
	case IPPROTO_ICMP:
		return ("icmp");
	case IPPROTO_ICMPV6:
		return ("icmpv6");
	default:
		return ("--");
	}
}

static char *
mac_flow_priority2str(mac_priority_level_t prio)
{
	switch (prio) {
	case MPL_LOW:
		return ("low");
	case MPL_MEDIUM:
		return ("medium");
	case MPL_HIGH:
		return ("high");
	case MPL_RESET:
		return ("reset");
	default:
		return ("--");
	}
}

/*
 *  Convert bandwidth in bps to a string in mpbs.
 */
static char *
mac_flow_bw2str(uint64_t bw, char *buf, ssize_t len)
{
	int kbps, mbps;

	kbps = (bw % 1000000)/1000;
	mbps = bw/1000000;
	if ((mbps == 0) && (kbps != 0))
		mdb_snprintf(buf, len, "0.%03u", kbps);
	else
		mdb_snprintf(buf, len, "%5u", mbps);
	return (buf);
}

static void
mac_flow_print_header(uint_t args)
{
	switch (args) {
	case MAC_FLOW_NONE:
		mdb_printf("%<u>%?s %-32s %-6s %?s %?s %-20s%</u>\n",
		    "ADDR", "FLOW NAME", "LINKID", "MCIP", "MIP",
		    "MIP NAME");
		break;
	case MAC_FLOW_ATTR:
		mdb_printf("%<u>%?s %-32s %-7s %6s "
		    "%-9s %s%</u>\n",
		    "ADDR", "FLOW NAME", "PROTO", "PORT",
		    "DSFLD:MSK", "IPADDR");
		break;
	case MAC_FLOW_PROP:
		mdb_printf("%<u>%?s %-32s %8s %9s%</u>\n",
		    "ADDR", "FLOW NAME", "MAXBW(M)", "PRIORITY");
		break;
	case MAC_FLOW_MISC:
		mdb_printf("%<u>%?s %-32s %10s %10s "
		    "%32s %s%</u>\n",
		    "ADDR", "FLOW NAME", "TYPE", "FLAGS",
		    "MATCH_FN", "ZONE");
		break;
	case MAC_FLOW_RX:
		mdb_printf("%<u>%?s %-24s %-30s %?s "
		    "%?s %7s %s%</u>\n",
		    "ADDR", "FLOW NAME", "CB_FUNC", "CB_ARG1",
		    "CB_ARG2", "SRS_CNT", "RX_SRS");
		break;
	case MAC_FLOW_TX:
		mdb_printf("%<u>%?s %-32s %?s %</u>\n",
		    "ADDR", "FLOW NAME", "TX_SRS");
		break;
	case MAC_FLOW_STATS:
		mdb_printf("%<u>%?s %-32s %?s %?s%</u>\n",
		    "ADDR", "FLOW NAME", "RBYTES", "OBYTES");
		break;
	}
}

/*
 * Display selected fields of the flow_entry_t structure
 */
static int
mac_flow_dcmd_output(uintptr_t addr, uint_t flags, uint_t args)
{
	static const mdb_bitmask_t flow_type_bits[] = {
		{"P", FLOW_PRIMARY_MAC, FLOW_PRIMARY_MAC},
		{"V", FLOW_VNIC_MAC, FLOW_VNIC_MAC},
		{"M", FLOW_MCAST, FLOW_MCAST},
		{"O", FLOW_OTHER, FLOW_OTHER},
		{"U", FLOW_USER, FLOW_USER},
		{"V", FLOW_VNIC, FLOW_VNIC},
		{"NS", FLOW_NO_STATS, FLOW_NO_STATS},
		{ NULL, 0, 0 }
	};
#define	FLOW_MAX_TYPE	(sizeof (flow_type_bits) / sizeof (mdb_bitmask_t))

	static const mdb_bitmask_t flow_flag_bits[] = {
		{"Q", FE_QUIESCE, FE_QUIESCE},
		{"W", FE_WAITER, FE_WAITER},
		{"T", FE_FLOW_TAB, FE_FLOW_TAB},
		{"G", FE_G_FLOW_HASH, FE_G_FLOW_HASH},
		{"I", FE_INCIPIENT, FE_INCIPIENT},
		{"C", FE_CONDEMNED, FE_CONDEMNED},
		{"NU", FE_UF_NO_DATAPATH, FE_UF_NO_DATAPATH},
		{"NC", FE_MC_NO_DATAPATH, FE_MC_NO_DATAPATH},
		{ NULL, 0, 0 }
	};
#define	FLOW_MAX_FLAGS	(sizeof (flow_flag_bits) / sizeof (mdb_bitmask_t))
	flow_entry_t		fe;
	mac_client_impl_t	mcip;
	mac_impl_t		mip;

	if (mdb_vread(&fe, sizeof (fe), addr) == -1) {
		mdb_warn("failed to read struct flow_entry_s at %p", addr);
		return (DCMD_ERR);
	}
	if (args & MAC_FLOW_USER) {
		args &= ~MAC_FLOW_USER;
		if (fe.fe_type & FLOW_MCAST) {
			if (DCMD_HDRSPEC(flags))
				mac_flow_print_header(args);
			return (DCMD_OK);
		}
	}
	if (DCMD_HDRSPEC(flags))
		mac_flow_print_header(args);
	bzero(&mcip, sizeof (mcip));
	bzero(&mip, sizeof (mip));
	if (fe.fe_mcip != NULL && mdb_vread(&mcip, sizeof (mcip),
	    (uintptr_t)fe.fe_mcip) == sizeof (mcip)) {
		(void) mdb_vread(&mip, sizeof (mip), (uintptr_t)mcip.mci_mip);
	}
	switch (args) {
	case MAC_FLOW_NONE: {
		mdb_printf("%?p %-32s %6d %?p "
		    "%?p %-20s\n",
		    addr, fe.fe_flow_name, fe.fe_link_id, fe.fe_mcip,
		    mcip.mci_mip, mip.mi_name);
		break;
	}
	case MAC_FLOW_ATTR: {
		struct 	in_addr	in4;
		uintptr_t	desc_addr;
		flow_desc_t	fdesc;

		desc_addr = addr + OFFSETOF(flow_entry_t, fe_flow_desc);
		if (mdb_vread(&fdesc, sizeof (fdesc), desc_addr) == -1) {
			mdb_warn("failed to read struct flow_description at %p",
			    desc_addr);
			return (DCMD_ERR);
		}
		mdb_printf("%?p %-32s "
		    "%-7s %6d"
		    "%4d:%-4d ",
		    addr, fe.fe_flow_name,
		    mac_flow_proto2str(fdesc.fd_protocol), fdesc.fd_local_port,
		    fdesc.fd_dsfield, fdesc.fd_dsfield_mask);
		if (fdesc.fd_ipversion == IPV4_VERSION) {
			IN6_V4MAPPED_TO_INADDR(&fdesc.fd_local_addr, &in4);
			mdb_printf("%I", in4.s_addr);
		} else if (fdesc.fd_ipversion == IPV6_VERSION) {
			mdb_printf("%N", &fdesc.fd_local_addr);
		} else {
			mdb_printf("%s", "--");
		}
		mdb_printf("\n");
		break;
	}
	case MAC_FLOW_PROP: {
		uintptr_t	prop_addr;
		char		bwstr[STRSIZE];
		mac_resource_props_t	fprop;

		prop_addr = addr + OFFSETOF(flow_entry_t, fe_resource_props);
		if (mdb_vread(&fprop, sizeof (fprop), prop_addr) == -1) {
			mdb_warn("failed to read struct mac_resoource_props "
			    "at %p", prop_addr);
			return (DCMD_ERR);
		}
		mdb_printf("%?p %-32s "
		    "%8s %9s\n",
		    addr, fe.fe_flow_name,
		    mac_flow_bw2str(fprop.mrp_maxbw, bwstr, STRSIZE),
		    mac_flow_priority2str(fprop.mrp_priority));
		break;
	}
	case MAC_FLOW_MISC: {
		char		flow_flags[2 * FLOW_MAX_FLAGS];
		char		flow_type[2 * FLOW_MAX_TYPE];
		GElf_Sym 	sym;
		char		func_name[MDB_SYM_NAMLEN] = "";
		uintptr_t	func, match_addr;

		match_addr = addr + OFFSETOF(flow_entry_t, fe_match);
		(void) mdb_vread(&func, sizeof (func), match_addr);
		(void) mdb_lookup_by_addr(func, MDB_SYM_EXACT, func_name,
		    MDB_SYM_NAMLEN, &sym);
		mdb_snprintf(flow_flags, 2 * FLOW_MAX_FLAGS, "%hb",
		    fe.fe_flags, flow_flag_bits);
		mdb_snprintf(flow_type, 2 * FLOW_MAX_TYPE, "%hb",
		    fe.fe_type, flow_type_bits);
		mdb_printf("%?p %-32s %10s %10s "
		    "%32s %-d\n",
		    addr, fe.fe_flow_name, flow_type, flow_flags,
		    func_name, fe.fe_zoneid);
		break;
	}
	case MAC_FLOW_RX: {
		uintptr_t	rx_srs[MAX_RINGS_PER_GROUP] = {0};
		char 		cb_fn[MDB_SYM_NAMLEN] = "";
		uintptr_t	cb_fnaddr, fnaddr, rxaddr;
		int		i;
		GElf_Sym 	sym;

		rxaddr = addr + OFFSETOF(flow_entry_t, fe_rx_srs);
		(void) mdb_vread(rx_srs, MAC_RX_SRS_SIZE, rxaddr);
		fnaddr = addr + OFFSETOF(flow_entry_t, fe_cb_fn);
		(void) mdb_vread(&cb_fnaddr, sizeof (cb_fnaddr), fnaddr);
		(void) mdb_lookup_by_addr(cb_fnaddr, MDB_SYM_EXACT, cb_fn,
		    MDB_SYM_NAMLEN, &sym);
		mdb_printf("%?p %-24s %-30s %?p "
		    "%?p %7d ",
		    addr, fe.fe_flow_name, cb_fn, fe.fe_cb_arg1,
		    fe.fe_cb_arg2, fe.fe_rx_srs_cnt);
		for (i = 0; i < MAX_RINGS_PER_GROUP; i++) {
			if (rx_srs[i] == 0)
				continue;
			mdb_printf("%p ", rx_srs[i]);
		}
		mdb_printf("\n");
		break;
	}
	case MAC_FLOW_TX: {
		uintptr_t	tx_srs = 0, txaddr;

		txaddr = addr + OFFSETOF(flow_entry_t, fe_tx_srs);
		(void) mdb_vread(&tx_srs, sizeof (uintptr_t), txaddr);
		mdb_printf("%?p %-32s %?p\n",
		    addr, fe.fe_flow_name, fe.fe_tx_srs);
		break;
	}
	case MAC_FLOW_STATS: {
		mdb_printf("%?p %-32s %16llu %16llu\n",
		    addr, fe.fe_flow_name, fe.fe_flowstats.fs_rbytes,
		    fe.fe_flowstats.fs_obytes);
		break;
	}
	}
	return (DCMD_OK);
}

/*
 * Parse the arguments passed to the dcmd and print all or one flow_entry_t
 * structures
 */
static int
mac_flow_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t	args = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_flow", "mac_flow", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_flow'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if ((mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, MAC_FLOW_ATTR, &args,
	    'p', MDB_OPT_SETBITS, MAC_FLOW_PROP, &args,
	    'm', MDB_OPT_SETBITS, MAC_FLOW_MISC, &args,
	    'r', MDB_OPT_SETBITS, MAC_FLOW_RX, &args,
	    't', MDB_OPT_SETBITS, MAC_FLOW_TX, &args,
	    's', MDB_OPT_SETBITS, MAC_FLOW_STATS, &args,
	    'u', MDB_OPT_SETBITS, MAC_FLOW_USER, &args) != argc)) {
		return (DCMD_USAGE);
	}
	if (argc > 2 || (argc == 2 && !(args & MAC_FLOW_USER)))
		return (DCMD_USAGE);
	/*
	 * If no arguments was specified or just "-u" was specified then
	 * we default to printing basic information of flows.
	 */
	if (args == 0 || args == MAC_FLOW_USER)
		args |= MAC_FLOW_NONE;

	return (mac_flow_dcmd_output(addr, flags, args));
}

static void
mac_flow_help(void)
{
	mdb_printf("If an address is specified, then flow_entry structure at "
	    "that address is printed. Otherwise all the flows in the system "
	    "are printed.\n");
	mdb_printf("Options:\n"
	    "\t-u\tdisplay user defined link & vnic flows.\n"
	    "\t-a\tdisplay flow attributes\n"
	    "\t-p\tdisplay flow properties\n"
	    "\t-r\tdisplay rx side information\n"
	    "\t-t\tdisplay tx side information\n"
	    "\t-s\tdisplay flow statistics\n"
	    "\t-m\tdisplay miscellaneous flow information\n\n");
	mdb_printf("%<u>Interpreting Flow type and Flow flags output.%</u>\n");
	mdb_printf("Flow Types:\n");
	mdb_printf("\t  P --> FLOW_PRIMARY_MAC\n");
	mdb_printf("\t  V --> FLOW_VNIC_MAC\n");
	mdb_printf("\t  M --> FLOW_MCAST\n");
	mdb_printf("\t  O --> FLOW_OTHER\n");
	mdb_printf("\t  U --> FLOW_USER\n");
	mdb_printf("\t NS --> FLOW_NO_STATS\n\n");
	mdb_printf("Flow Flags:\n");
	mdb_printf("\t  Q --> FE_QUIESCE\n");
	mdb_printf("\t  W --> FE_WAITER\n");
	mdb_printf("\t  T --> FE_FLOW_TAB\n");
	mdb_printf("\t  G --> FE_G_FLOW_HASH\n");
	mdb_printf("\t  I --> FE_INCIPIENT\n");
	mdb_printf("\t  C --> FE_CONDEMNED\n");
	mdb_printf("\t NU --> FE_UF_NO_DATAPATH\n");
	mdb_printf("\t NC --> FE_MC_NO_DATAPATH\n");
}

/*
 * called once by the debugger when the mac_flow walk begins.
 */
static int
mac_flow_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_FLOW, wsp) == -1) {
		mdb_warn("failed to walk 'mac_flow'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Common walker step funciton for flow_entry_t, mac_soft_ring_set_t and
 * mac_ring_t.
 *
 * Steps through each flow_entry_t and calls the callback function. If the
 * user executed ::walk mac_flow, it just prints the address or if the user
 * executed ::mac_flow it displays selected fields of flow_entry_t structure
 * by calling "mac_flow_dcmd"
 */
static int
mac_common_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	return (status);
}

static char *
mac_srs_txmode2str(mac_tx_srs_mode_t mode)
{
	switch (mode) {
	case SRS_TX_DEFAULT:
		return ("default");
	case SRS_TX_SERIALIZE:
		return ("serialize");
	case SRS_TX_FANOUT:
		return ("fanout");
	case SRS_TX_BW:
		return ("bw");
	case SRS_TX_BW_FANOUT:
		return ("bw fanout");
	}
	return ("--");
}

static void
mac_srs_help(void)
{
	mdb_printf("If an address is specified, then mac_soft_ring_set "
	    "structure at that address is printed. Otherwise all the "
	    "SRS in the system are printed.\n");
	mdb_printf("Options:\n"
	    "\t-r\tdisplay recieve side SRS structures\n"
	    "\t-t\tdisplay transmit side SRS structures\n");
}

static int
mac_srs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t			args = 0;
	mac_soft_ring_set_t	srs;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_srs", "mac_srs", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_srs'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if ((mdb_getopts(argc, argv,
	    'r', MDB_OPT_SETBITS, MAC_SRS_RX, &args,
	    't', MDB_OPT_SETBITS, MAC_SRS_TX, &args) != argc)) {
		return (DCMD_USAGE);
	}
	if (argc > 1)
		return (DCMD_USAGE);

	if (mdb_vread(&srs, sizeof (srs), addr) == -1) {
		mdb_warn("failed to read struct mac_soft_ring_set_s at %p",
		    addr);
		return (DCMD_ERR);
	}

	switch (args) {
	case MAC_SRS_RX: {
		GElf_Sym 	sym;
		char		func_name[MDB_SYM_NAMLEN] = "";
		char		l_proc_name[MDB_SYM_NAMLEN] = "";
		uintptr_t	func, lproc, funcaddr, lprocaddr, rxaddr;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<u>%?s %8s %-8s "
			    "%8s %-20s %-s%</u>\n",
			    "ADDR", "MBLK_CNT", "Q_BYTES",
			    "POLL_CNT", "SR_FUNC", "SR_LOWER_FUNC");
		}
		if (srs.srs_type & SRST_TX)
			return (DCMD_OK);
		rxaddr = addr + OFFSETOF(mac_soft_ring_set_t, srs_rx);
		funcaddr = rxaddr + OFFSETOF(mac_srs_rx_t, sr_func);
		lprocaddr = rxaddr + OFFSETOF(mac_srs_rx_t, sr_lower_proc);
		(void) mdb_vread(&func, sizeof (func), funcaddr);
		(void) mdb_vread(&lproc, sizeof (lproc), lprocaddr);
		(void) mdb_lookup_by_addr(func, MDB_SYM_EXACT, func_name,
		    MDB_SYM_NAMLEN, &sym);
		(void) mdb_lookup_by_addr(lproc, MDB_SYM_EXACT, l_proc_name,
		    MDB_SYM_NAMLEN, &sym);
		mdb_printf("%?p %-8d %-8d "
		    "%-8d %-20s %-s\n",
		    addr, srs.srs_count, srs.srs_size,
		    srs.srs_rx.sr_poll_count, func_name, l_proc_name);
		break;
	}
	case MAC_SRS_TX: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<u>%?s %-10s %-5s %-7s %-7s "
			    "%-7s %-7s %-7s%</u>\n",
			    "ADDR", "TX_MODE", "WOKEN", "DROP", "BLOCK",
			    "UNBLOCK", "MBLK", "SR_CNT");
		}
		if (!(srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-10s "
		    "%-5d %-7d "
		    "%-7d %-7d "
		    "%-7d %-7d\n",
		    addr, mac_srs_txmode2str(srs.srs_tx.st_mode),
		    srs.srs_tx.st_woken_up, srs.srs_tx.st_drop_count,
		    srs.srs_tx.st_blocked_cnt, srs.srs_tx.st_unblocked_cnt,
		    srs.srs_count, srs.srs_oth_ring_count);
		break;
	}
	default: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<u>%?s %?s %?s %?s %-3s "
			    "%-8s %-8s %-7s %</u>\n",
			    "ADDR", "MCIP", "FLENT", "RING", "DIR",
			    "TYPE", "STATE", "SR_CNT");
		}
		mdb_printf("%?p %?p %?p %?p "
		    "%-3s "
		    "%08x %08x %-7d \n",
		    addr, srs.srs_mcip, srs.srs_flent, srs.srs_ring,
		    (srs.srs_type & SRST_TX ? "TX" : "RX"),
		    srs.srs_type, srs.srs_state, srs.srs_soft_ring_count);
		break;
	}
	}
	return (DCMD_OK);
}

static int
mac_srs_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_SRS, wsp) == -1) {
		mdb_warn("failed to walk 'mac_srs'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static char *
mac_ring_state2str(mac_ring_state_t state)
{
	switch (state) {
	case MR_FREE:
		return ("free");
	case MR_NEWLY_ADDED:
		return ("new");
	case MR_INUSE:
		return ("inuse");
	}
	return ("--");
}

static char *
mac_ring_classify2str(mac_classify_type_t classify)
{
	switch (classify) {
	case MAC_NO_CLASSIFIER:
		return ("no");
	case MAC_SW_CLASSIFIER:
		return ("sw");
	case MAC_HW_CLASSIFIER:
		return ("hw");
	}
	return ("--");
}

static int
mac_ring_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mac_ring_t		ring;
	mac_group_t		group;
	flow_entry_t		flent;
	mac_soft_ring_set_t	srs;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_ring", "mac_ring", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_ring'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (mdb_vread(&ring, sizeof (ring), addr) == -1) {
		mdb_warn("failed to read struct mac_ring_s at %p", addr);
		return (DCMD_ERR);
	}
	bzero(&flent, sizeof (flent));
	if (mdb_vread(&srs, sizeof (srs), (uintptr_t)ring.mr_srs) != -1) {
		(void) mdb_vread(&flent, sizeof (flent),
		    (uintptr_t)srs.srs_flent);
	}
	(void) mdb_vread(&group, sizeof (group), (uintptr_t)ring.mr_gh);
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %4s %5s %4s %?s "
		    "%5s %?s %?s %s %</u>\n",
		    "ADDR", "TYPE", "STATE", "FLAG", "GROUP",
		    "CLASS", "MIP", "SRS", "FLOW NAME");
	}
	mdb_printf("%?p %-4s "
	    "%5s %04x "
	    "%?p %-5s "
	    "%?p %?p %s\n",
	    addr, ((ring.mr_type == 1)? "RX" : "TX"),
	    mac_ring_state2str(ring.mr_state), ring.mr_flag,
	    ring.mr_gh, mac_ring_classify2str(ring.mr_classify_type),
	    group.mrg_mh, ring.mr_srs, flent.fe_flow_name);
	return (DCMD_OK);
}

static int
mac_ring_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_RING, wsp) == -1) {
		mdb_warn("failed to walk `mac_ring`");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static void
mac_ring_help(void)
{
	mdb_printf("If an address is specified, then mac_ring_t "
	    "structure at that address is printed. Otherwise all the "
	    "hardware rings in the system are printed.\n");
}

/* Supported dee-commands */
static const mdb_dcmd_t dcmds[] = {
	{"mac_flow", "?[-u] [-aprtsm]", "display Flow Entry structures",
	    mac_flow_dcmd, mac_flow_help},
	{"mac_srs", "?[-rt]", "display MAC Soft Ring Set structures",
	    mac_srs_dcmd, mac_srs_help},
	{"mac_ring", "?", "display MAC ring (hardware) structures",
	    mac_ring_dcmd, mac_ring_help},
	{ NULL }
};

/* Supported walkers */
static const mdb_walker_t walkers[] = {
	{"mac_flow", "walk list of flow entry structures", mac_flow_walk_init,
	    mac_common_walk_step, NULL, NULL},
	{"mac_srs", "walk list of mac soft ring set structures",
	    mac_srs_walk_init, mac_common_walk_step, NULL, NULL},
	{"mac_ring", "walk list of mac ring structures", mac_ring_walk_init,
	    mac_common_walk_step, NULL, NULL},
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
