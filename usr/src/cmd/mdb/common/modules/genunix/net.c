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

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <sys/tihdr.h>
#include <inet/led.h>
#include <inet/common.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>
#include <inet/tcp.h>
#include <sys/stream.h>
#include <sys/vfs.h>
#include <sys/stropts.h>
#include <sys/tpicommon.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/cred_impl.h>
#include <inet/udp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/mi.h>
#include <fs/sockfs/socktpi_impl.h>
#include <net/bridge_impl.h>
#include <io/trill_impl.h>
#include <sys/mac_impl.h>

#define	ADDR_V6_WIDTH	23
#define	ADDR_V4_WIDTH	15

#define	NETSTAT_ALL	0x01
#define	NETSTAT_VERBOSE	0x02
#define	NETSTAT_ROUTE	0x04
#define	NETSTAT_V4	0x08
#define	NETSTAT_V6	0x10
#define	NETSTAT_UNIX	0x20

#define	NETSTAT_FIRST	0x80000000u

typedef struct netstat_cb_data_s {
	uint_t	opts;
	conn_t	conn;
	int	af;
} netstat_cb_data_t;

int
icmp_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
icmp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_ICMP];
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

int
tcp_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
tcp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_TCP];
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

int
udp_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
udp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_UDP];
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

/*
 * Print an IPv4 address and port number in a compact and easy to read format
 * The arguments are in network byte order
 */
static void
net_ipv4addrport_pr(const in6_addr_t *nipv6addr, in_port_t nport)
{
	uint32_t naddr = V4_PART_OF_V6((*nipv6addr));

	mdb_nhconvert(&nport, &nport, sizeof (nport));
	mdb_printf("%*I.%-5hu", ADDR_V4_WIDTH, naddr, nport);
}

/*
 * Print an IPv6 address and port number in a compact and easy to read format
 * The arguments are in network byte order
 */
static void
net_ipv6addrport_pr(const in6_addr_t *naddr, in_port_t nport)
{
	mdb_nhconvert(&nport, &nport, sizeof (nport));
	mdb_printf("%*N.%-5hu", ADDR_V6_WIDTH, naddr, nport);
}

static int
net_tcp_active(const tcp_t *tcp)
{
	return (tcp->tcp_state >= TCPS_ESTABLISHED);
}

static int
net_tcp_ipv4(const tcp_t *tcp)
{
	return ((tcp->tcp_connp->conn_ipversion == IPV4_VERSION) ||
	    (IN6_IS_ADDR_UNSPECIFIED(&tcp->tcp_connp->conn_laddr_v6) &&
	    (tcp->tcp_state <= TCPS_LISTEN)));
}

static int
net_tcp_ipv6(const tcp_t *tcp)
{
	return (tcp->tcp_connp->conn_ipversion == IPV6_VERSION);
}

static int
net_udp_active(const udp_t *udp)
{
	return ((udp->udp_state == TS_IDLE) ||
	    (udp->udp_state == TS_DATA_XFER));
}

static int
net_udp_ipv4(const udp_t *udp)
{
	return ((udp->udp_connp->conn_ipversion == IPV4_VERSION) ||
	    (IN6_IS_ADDR_UNSPECIFIED(&udp->udp_connp->conn_laddr_v6) &&
	    (udp->udp_state <= TS_IDLE)));
}

static int
net_udp_ipv6(const udp_t *udp)
{
	return (udp->udp_connp->conn_ipversion == IPV6_VERSION);
}

int
sonode_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		GElf_Sym sym;
		struct socklist *slp;

		if (mdb_lookup_by_obj("sockfs", "socklist", &sym) == -1) {
			mdb_warn("failed to lookup sockfs`socklist");
			return (WALK_ERR);
		}

		slp = (struct socklist *)(uintptr_t)sym.st_value;

		if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
		    (uintptr_t)&slp->sl_list) == -1) {
			mdb_warn("failed to read address of initial sonode "
			    "at %p", &slp->sl_list);
			return (WALK_ERR);
		}
	}

	wsp->walk_data = mdb_alloc(sizeof (struct sotpi_sonode), UM_SLEEP);
	return (WALK_NEXT);
}

int
sonode_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	struct sotpi_sonode *stp;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct sotpi_sonode),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read sonode at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	stp = wsp->walk_data;

	wsp->walk_addr = (uintptr_t)stp->st_info.sti_next_so;
	return (status);
}

void
sonode_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct sotpi_sonode));
}

struct mi_walk_data {
	uintptr_t mi_wd_miofirst;
	MI_O mi_wd_miodata;
};

int
mi_walk_init(mdb_walk_state_t *wsp)
{
	struct mi_walk_data *wdp;

	if (wsp->walk_addr == NULL) {
		mdb_warn("mi doesn't support global walks\n");
		return (WALK_ERR);
	}

	wdp = mdb_alloc(sizeof (struct mi_walk_data), UM_SLEEP);

	/* So that we do not immediately return WALK_DONE below */
	wdp->mi_wd_miofirst = NULL;

	wsp->walk_data = wdp;
	return (WALK_NEXT);
}

int
mi_walk_step(mdb_walk_state_t *wsp)
{
	struct mi_walk_data *wdp = wsp->walk_data;
	MI_OP miop = &wdp->mi_wd_miodata;
	int status;

	/* Always false in the first iteration */
	if ((wsp->walk_addr == (uintptr_t)NULL) ||
	    (wsp->walk_addr == wdp->mi_wd_miofirst)) {
		return (WALK_DONE);
	}

	if (mdb_vread(miop, sizeof (MI_O), wsp->walk_addr) == -1) {
		mdb_warn("failed to read MI object at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* Only true in the first iteration */
	if (wdp->mi_wd_miofirst == NULL) {
		wdp->mi_wd_miofirst = wsp->walk_addr;
		status = WALK_NEXT;
	} else {
		status = wsp->walk_callback(wsp->walk_addr + sizeof (MI_O),
		    &miop[1], wsp->walk_cbdata);
	}

	wsp->walk_addr = (uintptr_t)miop->mi_o_next;
	return (status);
}

void
mi_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mi_walk_data));
}

typedef struct mi_payload_walk_arg_s {
	const char *mi_pwa_walker;	/* Underlying walker */
	const off_t mi_pwa_head_off;	/* Offset for mi_o_head_t * in stack */
	const size_t mi_pwa_size;	/* size of mi payload */
	const uint_t mi_pwa_flags;	/* device and/or module */
} mi_payload_walk_arg_t;

#define	MI_PAYLOAD_DEVICE	0x1
#define	MI_PAYLOAD_MODULE	0x2

int
mi_payload_walk_init(mdb_walk_state_t *wsp)
{
	const mi_payload_walk_arg_t *arg = wsp->walk_arg;

	if (mdb_layered_walk(arg->mi_pwa_walker, wsp) == -1) {
		mdb_warn("can't walk '%s'", arg->mi_pwa_walker);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
mi_payload_walk_step(mdb_walk_state_t *wsp)
{
	const mi_payload_walk_arg_t *arg = wsp->walk_arg;
	uintptr_t kaddr;

	kaddr = wsp->walk_addr + arg->mi_pwa_head_off;

	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read address of mi head at %p for %s",
		    kaddr, arg->mi_pwa_walker);
		return (WALK_ERR);
	}

	if (kaddr == 0) {
		/* Empty list */
		return (WALK_DONE);
	}

	if (mdb_pwalk("genunix`mi", wsp->walk_callback,
	    wsp->walk_cbdata, kaddr) == -1) {
		mdb_warn("failed to walk genunix`mi");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

const mi_payload_walk_arg_t mi_icmp_arg = {
	"icmp_stacks", OFFSETOF(icmp_stack_t, is_head), sizeof (icmp_t),
	MI_PAYLOAD_DEVICE | MI_PAYLOAD_MODULE
};

int
sonode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *optf = NULL;
	const char *optt = NULL;
	const char *optp = NULL;
	int family, type, proto;
	int filter = 0;
	struct sonode so;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`sonode", "genunix`sonode", argc,
		    argv) == -1) {
			mdb_warn("failed to walk sonode");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'f', MDB_OPT_STR, &optf,
	    't', MDB_OPT_STR, &optt,
	    'p', MDB_OPT_STR, &optp,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (optf != NULL) {
		if (strcmp("inet", optf) == 0)
			family = AF_INET;
		else if (strcmp("inet6", optf) == 0)
			family = AF_INET6;
		else if (strcmp("unix", optf) == 0)
			family = AF_UNIX;
		else
			family = mdb_strtoull(optf);
		filter = 1;
	}

	if (optt != NULL) {
		if (strcmp("stream", optt) == 0)
			type = SOCK_STREAM;
		else if (strcmp("dgram", optt) == 0)
			type = SOCK_DGRAM;
		else if (strcmp("raw", optt) == 0)
			type = SOCK_RAW;
		else
			type = mdb_strtoull(optt);
		filter = 1;
	}

	if (optp != NULL) {
		proto = mdb_strtoull(optp);
		filter = 1;
	}

	if (DCMD_HDRSPEC(flags) && !filter) {
		mdb_printf("%<u>%-?s Family Type Proto State Mode Flag "
		    "AccessVP%</u>\n", "Sonode:");
	}

	if (mdb_vread(&so, sizeof (so), addr) == -1) {
		mdb_warn("failed to read sonode at %p", addr);
		return (DCMD_ERR);
	}

	if ((optf != NULL) && (so.so_family != family))
		return (DCMD_OK);

	if ((optt != NULL) && (so.so_type != type))
		return (DCMD_OK);

	if ((optp != NULL) && (so.so_protocol != proto))
		return (DCMD_OK);

	if (filter) {
		mdb_printf("%0?p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p ", addr);

	switch (so.so_family) {
	case AF_UNIX:
		mdb_printf("unix  ");
		break;
	case AF_INET:
		mdb_printf("inet  ");
		break;
	case AF_INET6:
		mdb_printf("inet6 ");
		break;
	default:
		mdb_printf("%6hi", so.so_family);
	}

	switch (so.so_type) {
	case SOCK_STREAM:
		mdb_printf(" strm");
		break;
	case SOCK_DGRAM:
		mdb_printf(" dgrm");
		break;
	case SOCK_RAW:
		mdb_printf(" raw ");
		break;
	default:
		mdb_printf(" %4hi", so.so_type);
	}

	mdb_printf(" %5hi %05x %04x %04hx\n",
	    so.so_protocol, so.so_state, so.so_mode,
	    so.so_flag);

	return (DCMD_OK);
}

#define	MI_PAYLOAD	0x1
#define	MI_DEVICE	0x2
#define	MI_MODULE	0x4

int
mi(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opts = 0;
	MI_O	mio;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv,
	    'p', MDB_OPT_SETBITS, MI_PAYLOAD, &opts,
	    'd', MDB_OPT_SETBITS, MI_DEVICE, &opts,
	    'm', MDB_OPT_SETBITS, MI_MODULE, &opts,
	    NULL) != argc)
		return (DCMD_USAGE);

	if ((opts & (MI_DEVICE | MI_MODULE)) == (MI_DEVICE | MI_MODULE)) {
		mdb_warn("at most one filter, d for devices or m "
		    "for modules, may be specified\n");
		return (DCMD_USAGE);
	}

	if ((opts == 0) && (DCMD_HDRSPEC(flags))) {
		mdb_printf("%<u>%-?s %-?s %-?s IsDev Dev%</u>\n",
		    "MI_O", "Next", "Prev");
	}

	if (mdb_vread(&mio, sizeof (mio), addr) == -1) {
		mdb_warn("failed to read mi object MI_O at %p", addr);
		return (DCMD_ERR);
	}

	if (opts != 0) {
		if (mio.mi_o_isdev == B_FALSE) {
			/* mio is a module */
			if (!(opts & MI_MODULE) && (opts & MI_DEVICE))
				return (DCMD_OK);
		} else {
			/* mio is a device */
			if (!(opts & MI_DEVICE) && (opts & MI_MODULE))
				return (DCMD_OK);
		}

		if (opts & MI_PAYLOAD)
			mdb_printf("%p\n", addr + sizeof (MI_O));
		else
			mdb_printf("%p\n", addr);
		return (DCMD_OK);
	}

	mdb_printf("%0?p %0?p %0?p ", addr, mio.mi_o_next, mio.mi_o_prev);

	if (mio.mi_o_isdev == B_FALSE)
		mdb_printf("FALSE");
	else
		mdb_printf("TRUE ");

	mdb_printf(" %0?p\n", mio.mi_o_dev);

	return (DCMD_OK);
}

static int
ns_to_stackid(uintptr_t kaddr)
{
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), kaddr) == -1) {
		mdb_warn("failed to read netstack_t %p", kaddr);
		return (0);
	}
	return (nss.netstack_stackid);
}



static void
netstat_tcp_verbose_pr(const tcp_t *tcp)
{
	mdb_printf("       %5i %08x %08x %5i %08x %08x %5li %5i\n",
	    tcp->tcp_swnd, tcp->tcp_snxt, tcp->tcp_suna, tcp->tcp_rwnd,
	    tcp->tcp_rack, tcp->tcp_rnxt, tcp->tcp_rto, tcp->tcp_mss);
}

/*ARGSUSED*/
static int
netstat_tcp_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	netstat_cb_data_t *ncb = cb_data;
	uint_t opts = ncb->opts;
	int af = ncb->af;
	uintptr_t tcp_kaddr;
	conn_t *connp = &ncb->conn;
	tcp_t tcps, *tcp;

	if (mdb_vread(connp, sizeof (conn_t), kaddr) == -1) {
		mdb_warn("failed to read conn_t at %p", kaddr);
		return (WALK_ERR);
	}

	tcp_kaddr = (uintptr_t)connp->conn_tcp;
	if (mdb_vread(&tcps, sizeof (tcp_t), tcp_kaddr) == -1) {
		mdb_warn("failed to read tcp_t at %p", tcp_kaddr);
		return (WALK_ERR);
	}

	tcp = &tcps;
	connp->conn_tcp = tcp;
	tcp->tcp_connp = connp;

	if (!((opts & NETSTAT_ALL) || net_tcp_active(tcp)) ||
	    (af == AF_INET && !net_tcp_ipv4(tcp)) ||
	    (af == AF_INET6 && !net_tcp_ipv6(tcp))) {
		return (WALK_NEXT);
	}

	mdb_printf("%0?p %2i ", tcp_kaddr, tcp->tcp_state);
	if (af == AF_INET) {
		net_ipv4addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv4addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	} else if (af == AF_INET6) {
		net_ipv6addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv6addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	}
	mdb_printf(" %5i", ns_to_stackid((uintptr_t)connp->conn_netstack));
	mdb_printf(" %4i\n", connp->conn_zoneid);
	if (opts & NETSTAT_VERBOSE)
		netstat_tcp_verbose_pr(tcp);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
netstat_udp_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	netstat_cb_data_t *ncb = cb_data;
	uint_t opts = ncb->opts;
	int af = ncb->af;
	udp_t udp;
	conn_t *connp = &ncb->conn;
	char *state;
	uintptr_t udp_kaddr;

	if (mdb_vread(connp, sizeof (conn_t), kaddr) == -1) {
		mdb_warn("failed to read conn_t at %p", kaddr);
		return (WALK_ERR);
	}

	udp_kaddr = (uintptr_t)connp->conn_udp;
	if (mdb_vread(&udp, sizeof (udp_t), udp_kaddr) == -1) {
		mdb_warn("failed to read conn_udp at %p", udp_kaddr);
		return (WALK_ERR);
	}

	/* Need to do these reassignments for the net_udp_*() routines below. */
	connp->conn_udp = &udp;
	udp.udp_connp = connp;

	if (!((opts & NETSTAT_ALL) || net_udp_active(&udp)) ||
	    (af == AF_INET && !net_udp_ipv4(&udp)) ||
	    (af == AF_INET6 && !net_udp_ipv6(&udp))) {
		return (WALK_NEXT);
	}

	if (udp.udp_state == TS_UNBND)
		state = "UNBOUND";
	else if (udp.udp_state == TS_IDLE)
		state = "IDLE";
	else if (udp.udp_state == TS_DATA_XFER)
		state = "CONNECTED";
	else
		state = "UNKNOWN";

	mdb_printf("%0?p %10s ", udp_kaddr, state);
	if (af == AF_INET) {
		net_ipv4addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv4addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	} else if (af == AF_INET6) {
		net_ipv6addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv6addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	}
	mdb_printf(" %5i", ns_to_stackid((uintptr_t)connp->conn_netstack));
	mdb_printf(" %4i\n", connp->conn_zoneid);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
netstat_icmp_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	netstat_cb_data_t *ncb = cb_data;
	int af = ncb->af;
	icmp_t icmp;
	conn_t *connp = &ncb->conn;
	char *state;

	if (mdb_vread(connp, sizeof (conn_t), kaddr) == -1) {
		mdb_warn("failed to read conn_t at %p", kaddr);
		return (WALK_ERR);
	}

	if (mdb_vread(&icmp, sizeof (icmp_t),
	    (uintptr_t)connp->conn_icmp) == -1) {
		mdb_warn("failed to read conn_icmp at %p",
		    (uintptr_t)connp->conn_icmp);
		return (WALK_ERR);
	}

	connp->conn_icmp = &icmp;
	icmp.icmp_connp = connp;

	if ((af == AF_INET && connp->conn_ipversion != IPV4_VERSION) ||
	    (af == AF_INET6 && connp->conn_ipversion != IPV6_VERSION)) {
		return (WALK_NEXT);
	}

	if (icmp.icmp_state == TS_UNBND)
		state = "UNBOUND";
	else if (icmp.icmp_state == TS_IDLE)
		state = "IDLE";
	else if (icmp.icmp_state == TS_DATA_XFER)
		state = "CONNECTED";
	else
		state = "UNKNOWN";

	mdb_printf("%0?p %10s ", (uintptr_t)connp->conn_icmp, state);
	if (af == AF_INET) {
		net_ipv4addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv4addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	} else if (af == AF_INET6) {
		net_ipv6addrport_pr(&connp->conn_laddr_v6, connp->conn_lport);
		mdb_printf(" ");
		net_ipv6addrport_pr(&connp->conn_faddr_v6, connp->conn_fport);
	}
	mdb_printf(" %5i", ns_to_stackid((uintptr_t)connp->conn_netstack));
	mdb_printf(" %4i\n", connp->conn_zoneid);

	return (WALK_NEXT);
}

/*
 * print the address of a unix domain socket
 *
 * so is the address of a AF_UNIX struct sonode in mdb's address space
 * soa is the address of the struct soaddr to print
 *
 * returns 0 on success, -1 otherwise
 */
static int
netstat_unix_name_pr(const struct sotpi_sonode *st, const struct soaddr *soa)
{
	const struct sonode *so = &st->st_sonode;
	const char none[] = " (none)";

	if ((so->so_state & SS_ISBOUND) && (soa->soa_len != 0)) {
		if (st->st_info.sti_faddr_noxlate) {
			mdb_printf("%-14s ", " (socketpair)");
		} else {
			if (soa->soa_len > sizeof (sa_family_t)) {
				char addr[MAXPATHLEN + 1];

				if (mdb_readstr(addr, sizeof (addr),
				    (uintptr_t)&soa->soa_sa->sa_data) == -1) {
					mdb_warn("failed to read unix address "
					    "at %p", &soa->soa_sa->sa_data);
					return (-1);
				}

				mdb_printf("%-14s ", addr);
			} else {
				mdb_printf("%-14s ", none);
			}
		}
	} else {
		mdb_printf("%-14s ", none);
	}

	return (0);
}

/* based on sockfs_snapshot */
/*ARGSUSED*/
static int
netstat_unix_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	const struct sotpi_sonode *st = walk_data;
	const struct sonode *so = &st->st_sonode;
	const struct sotpi_info *sti = &st->st_info;

	if (so->so_count == 0)
		return (WALK_NEXT);

	if (so->so_family != AF_UNIX) {
		mdb_warn("sonode of family %hi at %p\n", so->so_family, kaddr);
		return (WALK_ERR);
	}

	mdb_printf("%-?p ", kaddr);

	switch (sti->sti_serv_type) {
	case T_CLTS:
		mdb_printf("%-10s ", "dgram");
		break;
	case T_COTS:
		mdb_printf("%-10s ", "stream");
		break;
	case T_COTS_ORD:
		mdb_printf("%-10s ", "stream-ord");
		break;
	default:
		mdb_printf("%-10i ", sti->sti_serv_type);
	}

	if ((so->so_state & SS_ISBOUND) &&
	    (sti->sti_ux_laddr.soua_magic == SOU_MAGIC_EXPLICIT)) {
		mdb_printf("%0?p ", sti->sti_ux_laddr.soua_vp);
	} else {
		mdb_printf("%0?p ", NULL);
	}

	if ((so->so_state & SS_ISCONNECTED) &&
	    (sti->sti_ux_faddr.soua_magic == SOU_MAGIC_EXPLICIT)) {
		mdb_printf("%0?p ", sti->sti_ux_faddr.soua_vp);
	} else {
		mdb_printf("%0?p ", NULL);
	}

	if (netstat_unix_name_pr(st, &sti->sti_laddr) == -1)
		return (WALK_ERR);

	if (netstat_unix_name_pr(st, &sti->sti_faddr) == -1)
		return (WALK_ERR);

	mdb_printf("%4i\n", so->so_zoneid);

	return (WALK_NEXT);
}

static void
netstat_tcp_verbose_header_pr(void)
{
	mdb_printf("       %<u>%-5s %-8s %-8s %-5s %-8s %-8s %5s %5s%</u>\n",
	    "Swind", "Snext", "Suna", "Rwind", "Rack", "Rnext", "Rto", "Mss");
}

static void
get_ifname(const ire_t *ire, char *intf)
{
	ill_t ill;

	*intf = '\0';
	if (ire->ire_ill != NULL) {
		if (mdb_vread(&ill, sizeof (ill),
		    (uintptr_t)ire->ire_ill) == -1)
			return;
		(void) mdb_readstr(intf, MIN(LIFNAMSIZ, ill.ill_name_length),
		    (uintptr_t)ill.ill_name);
	}
}

const in6_addr_t ipv6_all_ones =
	{ 0xffffffffU, 0xffffffffU, 0xffffffffU, 0xffffffffU };

static void
get_ireflags(const ire_t *ire, char *flags)
{
	(void) strcpy(flags, "U");
	/* RTF_INDIRECT wins over RTF_GATEWAY - don't display both */
	if (ire->ire_flags & RTF_INDIRECT)
		(void) strcat(flags, "I");
	else if (ire->ire_type & IRE_OFFLINK)
		(void) strcat(flags, "G");

	/* IRE_IF_CLONE wins over RTF_HOST - don't display both */
	if (ire->ire_type & IRE_IF_CLONE)
		(void) strcat(flags, "C");
	else if (ire->ire_ipversion == IPV4_VERSION) {
		if (ire->ire_mask == IP_HOST_MASK)
			(void) strcat(flags, "H");
	} else {
		if (IN6_ARE_ADDR_EQUAL(&ire->ire_mask_v6, &ipv6_all_ones))
			(void) strcat(flags, "H");
	}

	if (ire->ire_flags & RTF_DYNAMIC)
		(void) strcat(flags, "D");
	if (ire->ire_type == IRE_BROADCAST)
		(void) strcat(flags, "b");
	if (ire->ire_type == IRE_MULTICAST)
		(void) strcat(flags, "m");
	if (ire->ire_type == IRE_LOCAL)
		(void) strcat(flags, "L");
	if (ire->ire_type == IRE_NOROUTE)
		(void) strcat(flags, "N");
	if (ire->ire_flags & RTF_MULTIRT)
		(void) strcat(flags, "M");
	if (ire->ire_flags & RTF_SETSRC)
		(void) strcat(flags, "S");
	if (ire->ire_flags & RTF_REJECT)
		(void) strcat(flags, "R");
	if (ire->ire_flags & RTF_BLACKHOLE)
		(void) strcat(flags, "B");
}

static int
netstat_irev4_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	const ire_t *ire = walk_data;
	uint_t *opts = cb_data;
	ipaddr_t gate;
	char flags[10], intf[LIFNAMSIZ + 1];

	if (ire->ire_ipversion != IPV4_VERSION)
		return (WALK_NEXT);

	/* Skip certain IREs by default */
	if (!(*opts & NETSTAT_ALL) &&
	    (ire->ire_type &
	    (IRE_BROADCAST|IRE_LOCAL|IRE_MULTICAST|IRE_NOROUTE|IRE_IF_CLONE)))
		return (WALK_NEXT);

	if (*opts & NETSTAT_FIRST) {
		*opts &= ~NETSTAT_FIRST;
		mdb_printf("%<u>%s Table: IPv4%</u>\n",
		    (*opts & NETSTAT_VERBOSE) ? "IRE" : "Routing");
		if (*opts & NETSTAT_VERBOSE) {
			mdb_printf("%<u>%-?s %-*s %-*s %-*s Device Mxfrg Rtt  "
			    " Ref Flg Out   In/Fwd%</u>\n",
			    "Address", ADDR_V4_WIDTH, "Destination",
			    ADDR_V4_WIDTH, "Mask", ADDR_V4_WIDTH, "Gateway");
		} else {
			mdb_printf("%<u>%-?s %-*s %-*s Flags Ref  Use   "
			    "Interface%</u>\n",
			    "Address", ADDR_V4_WIDTH, "Destination",
			    ADDR_V4_WIDTH, "Gateway");
		}
	}

	gate = ire->ire_gateway_addr;

	get_ireflags(ire, flags);

	get_ifname(ire, intf);

	if (*opts & NETSTAT_VERBOSE) {
		mdb_printf("%?p %-*I %-*I %-*I %-6s %5u%c %4u %3u %-3s %5u "
		    "%u\n", kaddr, ADDR_V4_WIDTH, ire->ire_addr, ADDR_V4_WIDTH,
		    ire->ire_mask, ADDR_V4_WIDTH, gate, intf,
		    0, ' ',
		    ire->ire_metrics.iulp_rtt, ire->ire_refcnt, flags,
		    ire->ire_ob_pkt_count, ire->ire_ib_pkt_count);
	} else {
		mdb_printf("%?p %-*I %-*I %-5s %4u %5u %s\n", kaddr,
		    ADDR_V4_WIDTH, ire->ire_addr, ADDR_V4_WIDTH, gate, flags,
		    ire->ire_refcnt,
		    ire->ire_ob_pkt_count + ire->ire_ib_pkt_count, intf);
	}

	return (WALK_NEXT);
}

int
ip_mask_to_plen_v6(const in6_addr_t *v6mask)
{
	int plen;
	int i;
	uint32_t val;

	for (i = 3; i >= 0; i--)
		if (v6mask->s6_addr32[i] != 0)
			break;
	if (i < 0)
		return (0);
	plen = 32 + 32 * i;
	val = v6mask->s6_addr32[i];
	while (!(val & 1)) {
		val >>= 1;
		plen--;
	}

	return (plen);
}

static int
netstat_irev6_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	const ire_t *ire = walk_data;
	uint_t *opts = cb_data;
	const in6_addr_t *gatep;
	char deststr[ADDR_V6_WIDTH + 5];
	char flags[10], intf[LIFNAMSIZ + 1];
	int masklen;

	if (ire->ire_ipversion != IPV6_VERSION)
		return (WALK_NEXT);

	/* Skip certain IREs by default */
	if (!(*opts & NETSTAT_ALL) &&
	    (ire->ire_type &
	    (IRE_BROADCAST|IRE_LOCAL|IRE_MULTICAST|IRE_NOROUTE|IRE_IF_CLONE)))
		return (WALK_NEXT);

	if (*opts & NETSTAT_FIRST) {
		*opts &= ~NETSTAT_FIRST;
		mdb_printf("\n%<u>%s Table: IPv6%</u>\n",
		    (*opts & NETSTAT_VERBOSE) ? "IRE" : "Routing");
		if (*opts & NETSTAT_VERBOSE) {
			mdb_printf("%<u>%-?s %-*s %-*s If    PMTU   Rtt   Ref "
			    "Flags Out    In/Fwd%</u>\n",
			    "Address", ADDR_V6_WIDTH+4, "Destination/Mask",
			    ADDR_V6_WIDTH, "Gateway");
		} else {
			mdb_printf("%<u>%-?s %-*s %-*s Flags Ref Use    If"
			    "%</u>\n",
			    "Address", ADDR_V6_WIDTH+4, "Destination/Mask",
			    ADDR_V6_WIDTH, "Gateway");
		}
	}

	gatep = &ire->ire_gateway_addr_v6;

	masklen = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	(void) mdb_snprintf(deststr, sizeof (deststr), "%N/%d",
	    &ire->ire_addr_v6, masklen);

	get_ireflags(ire, flags);

	get_ifname(ire, intf);

	if (*opts & NETSTAT_VERBOSE) {
		mdb_printf("%?p %-*s %-*N %-5s %5u%c %5u %3u %-5s %6u %u\n",
		    kaddr, ADDR_V6_WIDTH+4, deststr, ADDR_V6_WIDTH, gatep,
		    intf, 0, ' ',
		    ire->ire_metrics.iulp_rtt, ire->ire_refcnt,
		    flags, ire->ire_ob_pkt_count, ire->ire_ib_pkt_count);
	} else {
		mdb_printf("%?p %-*s %-*N %-5s %3u %6u %s\n", kaddr,
		    ADDR_V6_WIDTH+4, deststr, ADDR_V6_WIDTH, gatep, flags,
		    ire->ire_refcnt,
		    ire->ire_ob_pkt_count + ire->ire_ib_pkt_count, intf);
	}

	return (WALK_NEXT);
}

static void
netstat_header_v4(int proto)
{
	if (proto == IPPROTO_TCP)
		mdb_printf("%<u>%-?s ", "TCPv4");
	else if (proto == IPPROTO_UDP)
		mdb_printf("%<u>%-?s ", "UDPv4");
	else if (proto == IPPROTO_ICMP)
		mdb_printf("%<u>%-?s ", "ICMPv4");
	mdb_printf("State %6s%*s %6s%*s %-5s %-4s%</u>\n",
	    "", ADDR_V4_WIDTH, "Local Address",
	    "", ADDR_V4_WIDTH, "Remote Address", "Stack", "Zone");
}

static void
netstat_header_v6(int proto)
{
	if (proto == IPPROTO_TCP)
		mdb_printf("%<u>%-?s ", "TCPv6");
	else if (proto == IPPROTO_UDP)
		mdb_printf("%<u>%-?s ", "UDPv6");
	else if (proto == IPPROTO_ICMP)
		mdb_printf("%<u>%-?s ", "ICMPv6");
	mdb_printf("State %6s%*s %6s%*s %-5s %-4s%</u>\n",
	    "", ADDR_V6_WIDTH, "Local Address",
	    "", ADDR_V6_WIDTH, "Remote Address", "Stack", "Zone");
}

static int
netstat_print_conn(const char *cache, int proto, mdb_walk_cb_t cbfunc,
    void *cbdata)
{
	netstat_cb_data_t *ncb = cbdata;

	if ((ncb->opts & NETSTAT_VERBOSE) && proto == IPPROTO_TCP)
		netstat_tcp_verbose_header_pr();
	if (mdb_walk(cache, cbfunc, cbdata) == -1) {
		mdb_warn("failed to walk %s", cache);
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static int
netstat_print_common(const char *cache, int proto, mdb_walk_cb_t cbfunc,
    void *cbdata)
{
	netstat_cb_data_t *ncb = cbdata;
	int af = ncb->af;
	int status = DCMD_OK;

	if (af != AF_INET6) {
		ncb->af = AF_INET;
		netstat_header_v4(proto);
		status = netstat_print_conn(cache, proto, cbfunc, cbdata);
	}
	if (status == DCMD_OK && af != AF_INET) {
		ncb->af = AF_INET6;
		netstat_header_v6(proto);
		status = netstat_print_conn(cache, proto, cbfunc, cbdata);
	}
	ncb->af = af;
	return (status);
}

/*ARGSUSED*/
int
netstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opts = 0;
	const char *optf = NULL;
	const char *optP = NULL;
	netstat_cb_data_t *cbdata;
	int status;
	int af = 0;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, NETSTAT_ALL, &opts,
	    'f', MDB_OPT_STR, &optf,
	    'P', MDB_OPT_STR, &optP,
	    'r', MDB_OPT_SETBITS, NETSTAT_ROUTE, &opts,
	    'v', MDB_OPT_SETBITS, NETSTAT_VERBOSE, &opts,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (optP != NULL) {
		if ((strcmp("tcp", optP) != 0) && (strcmp("udp", optP) != 0) &&
		    (strcmp("icmp", optP) != 0))
			return (DCMD_USAGE);
		if (opts & NETSTAT_ROUTE)
			return (DCMD_USAGE);
	}

	if (optf == NULL)
		opts |= NETSTAT_V4 | NETSTAT_V6 | NETSTAT_UNIX;
	else if (strcmp("inet", optf) == 0)
		opts |= NETSTAT_V4;
	else if (strcmp("inet6", optf) == 0)
		opts |= NETSTAT_V6;
	else if (strcmp("unix", optf) == 0)
		opts |= NETSTAT_UNIX;
	else
		return (DCMD_USAGE);

	if (opts & NETSTAT_ROUTE) {
		if (!(opts & (NETSTAT_V4|NETSTAT_V6)))
			return (DCMD_USAGE);
		if (opts & NETSTAT_V4) {
			opts |= NETSTAT_FIRST;
			if (mdb_walk("ip`ire", netstat_irev4_cb, &opts) == -1) {
				mdb_warn("failed to walk ip`ire");
				return (DCMD_ERR);
			}
		}
		if (opts & NETSTAT_V6) {
			opts |= NETSTAT_FIRST;
			if (mdb_walk("ip`ire", netstat_irev6_cb, &opts) == -1) {
				mdb_warn("failed to walk ip`ire");
				return (DCMD_ERR);
			}
		}
		return (DCMD_OK);
	}

	if ((opts & NETSTAT_UNIX) && (optP == NULL)) {
		/* Print Unix Domain Sockets */
		mdb_printf("%<u>%-?s %-10s %-?s %-?s %-14s %-14s %s%</u>\n",
		    "AF_UNIX", "Type", "Vnode", "Conn", "Local Addr",
		    "Remote Addr", "Zone");

		if (mdb_walk("genunix`sonode", netstat_unix_cb, NULL) == -1) {
			mdb_warn("failed to walk genunix`sonode");
			return (DCMD_ERR);
		}
		if (!(opts & (NETSTAT_V4 | NETSTAT_V6)))
			return (DCMD_OK);
	}

	cbdata = mdb_alloc(sizeof (netstat_cb_data_t), UM_SLEEP);
	cbdata->opts = opts;
	if ((optf != NULL) && (opts & NETSTAT_V4))
		af = AF_INET;
	else if ((optf != NULL) && (opts & NETSTAT_V6))
		af = AF_INET6;

	cbdata->af = af;
	if ((optP == NULL) || (strcmp("tcp", optP) == 0)) {
		status = netstat_print_common("tcp_conn_cache", IPPROTO_TCP,
		    netstat_tcp_cb, cbdata);
		if (status != DCMD_OK)
			goto out;
	}

	if ((optP == NULL) || (strcmp("udp", optP) == 0)) {
		status = netstat_print_common("udp_conn_cache", IPPROTO_UDP,
		    netstat_udp_cb, cbdata);
		if (status != DCMD_OK)
			goto out;
	}

	if ((optP == NULL) || (strcmp("icmp", optP) == 0)) {
		status = netstat_print_common("rawip_conn_cache", IPPROTO_ICMP,
		    netstat_icmp_cb, cbdata);
		if (status != DCMD_OK)
			goto out;
	}
out:
	mdb_free(cbdata, sizeof (netstat_cb_data_t));
	return (status);
}

/*
 * "::dladm show-bridge" support
 */
typedef struct {
	uint_t opt_l;
	uint_t opt_f;
	uint_t opt_t;
	const char *name;
	clock_t lbolt;
	boolean_t found;
	uint_t nlinks;
	uint_t nfwd;

	/*
	 * These structures are kept inside the 'args' for allocation reasons.
	 * They're all large data structures (over 1K), and may cause the stack
	 * to explode.  mdb and kmdb will fail in these cases, and thus we
	 * allocate them from the heap.
	 */
	trill_inst_t ti;
	bridge_link_t bl;
	mac_impl_t mi;
} show_bridge_args_t;

static void
show_vlans(const uint8_t *vlans)
{
	int i, bit;
	uint8_t val;
	int rstart = -1, rnext = -1;

	for (i = 0; i < BRIDGE_VLAN_ARR_SIZE; i++) {
		val = vlans[i];
		if (i == 0)
			val &= ~1;
		while ((bit = mdb_ffs(val)) != 0) {
			bit--;
			val &= ~(1 << bit);
			bit += i * sizeof (*vlans) * NBBY;
			if (bit != rnext) {
				if (rnext != -1 && rstart + 1 != rnext)
					mdb_printf("-%d", rnext - 1);
				if (rstart != -1)
					mdb_printf(",");
				mdb_printf("%d", bit);
				rstart = bit;
			}
			rnext = bit + 1;
		}
	}
	if (rnext != -1 && rstart + 1 != rnext)
		mdb_printf("-%d", rnext - 1);
	mdb_printf("\n");
}

/*
 * This callback is invoked by a walk of the links attached to a bridge.  If
 * we're showing link details, then they're printed here.  If not, then we just
 * count up the links for the bridge summary.
 */
static int
do_bridge_links(uintptr_t addr, const void *data, void *ptr)
{
	show_bridge_args_t *args = ptr;
	const bridge_link_t *blp = data;
	char macaddr[ETHERADDRL * 3];
	const char *name;

	args->nlinks++;

	if (!args->opt_l)
		return (WALK_NEXT);

	if (mdb_vread(&args->mi, sizeof (args->mi),
	    (uintptr_t)blp->bl_mh) == -1) {
		mdb_warn("cannot read mac data at %p", blp->bl_mh);
		name = "?";
	} else  {
		name = args->mi.mi_name;
	}

	mdb_mac_addr(blp->bl_local_mac, ETHERADDRL, macaddr,
	    sizeof (macaddr));

	mdb_printf("%-?p %-16s %-17s %03X %-4d ", addr, name, macaddr,
	    blp->bl_flags, blp->bl_pvid);

	if (blp->bl_trilldata == NULL) {
		switch (blp->bl_state) {
		case BLS_BLOCKLISTEN:
			name = "BLOCK";
			break;
		case BLS_LEARNING:
			name = "LEARN";
			break;
		case BLS_FORWARDING:
			name = "FWD";
			break;
		default:
			name = "?";
		}
		mdb_printf("%-5s ", name);
		show_vlans(blp->bl_vlans);
	} else {
		show_vlans(blp->bl_afs);
	}

	return (WALK_NEXT);
}

/*
 * It seems a shame to duplicate this code, but merging it with the link
 * printing code above is more trouble than it would be worth.
 */
static void
print_link_name(show_bridge_args_t *args, uintptr_t addr, char sep)
{
	const char *name;

	if (mdb_vread(&args->bl, sizeof (args->bl), addr) == -1) {
		mdb_warn("cannot read bridge link at %p", addr);
		return;
	}

	if (mdb_vread(&args->mi, sizeof (args->mi),
	    (uintptr_t)args->bl.bl_mh) == -1) {
		name = "?";
	} else  {
		name = args->mi.mi_name;
	}

	mdb_printf("%s%c", name, sep);
}

static int
do_bridge_fwd(uintptr_t addr, const void *data, void *ptr)
{
	show_bridge_args_t *args = ptr;
	const bridge_fwd_t *bfp = data;
	char macaddr[ETHERADDRL * 3];
	int i;
#define	MAX_FWD_LINKS	16
	bridge_link_t *links[MAX_FWD_LINKS];
	uint_t nlinks;

	args->nfwd++;

	if (!args->opt_f)
		return (WALK_NEXT);

	if ((nlinks = bfp->bf_nlinks) > MAX_FWD_LINKS)
		nlinks = MAX_FWD_LINKS;

	if (mdb_vread(links, sizeof (links[0]) * nlinks,
	    (uintptr_t)bfp->bf_links) == -1) {
		mdb_warn("cannot read bridge forwarding links at %p",
		    bfp->bf_links);
		return (WALK_ERR);
	}

	mdb_mac_addr(bfp->bf_dest, ETHERADDRL, macaddr, sizeof (macaddr));

	mdb_printf("%-?p %-17s ", addr, macaddr);
	if (bfp->bf_flags & BFF_LOCALADDR)
		mdb_printf("%-7s", "[self]");
	else
		mdb_printf("t-%-5d", args->lbolt - bfp->bf_lastheard);
	mdb_printf(" %-7u ", bfp->bf_refs);

	if (bfp->bf_trill_nick != 0) {
		mdb_printf("%d\n", bfp->bf_trill_nick);
	} else {
		for (i = 0; i < bfp->bf_nlinks; i++) {
			print_link_name(args, (uintptr_t)links[i],
			    i == bfp->bf_nlinks - 1 ? '\n' : ' ');
		}
	}

	return (WALK_NEXT);
}

static int
do_show_bridge(uintptr_t addr, const void *data, void *ptr)
{
	show_bridge_args_t *args = ptr;
	bridge_inst_t bi;
	const bridge_inst_t *bip;
	trill_node_t tn;
	trill_sock_t tsp;
	trill_nickinfo_t tni;
	char bname[MAXLINKNAMELEN];
	char macaddr[ETHERADDRL * 3];
	char *cp;
	uint_t nnicks;
	int i;

	if (data != NULL) {
		bip = data;
	} else {
		if (mdb_vread(&bi, sizeof (bi), addr) == -1) {
			mdb_warn("cannot read bridge instance at %p", addr);
			return (WALK_ERR);
		}
		bip = &bi;
	}

	(void) strncpy(bname, bip->bi_name, sizeof (bname) - 1);
	bname[MAXLINKNAMELEN - 1] = '\0';
	cp = bname + strlen(bname);
	if (cp > bname && cp[-1] == '0')
		cp[-1] = '\0';

	if (args->name != NULL && strcmp(args->name, bname) != 0)
		return (WALK_NEXT);

	args->found = B_TRUE;
	args->nlinks = args->nfwd = 0;

	if (args->opt_l) {
		mdb_printf("%-?s %-16s %-17s %3s %-4s ", "ADDR", "LINK",
		    "MAC-ADDR", "FLG", "PVID");
		if (bip->bi_trilldata == NULL)
			mdb_printf("%-5s %s\n", "STATE", "VLANS");
		else
			mdb_printf("%s\n", "FWD-VLANS");
	}

	if (!args->opt_f && !args->opt_t &&
	    mdb_pwalk("list", do_bridge_links, args,
	    addr + offsetof(bridge_inst_t, bi_links)) != DCMD_OK)
		return (WALK_ERR);

	if (args->opt_f)
		mdb_printf("%-?s %-17s %-7s %-7s %s\n", "ADDR", "DEST", "TIME",
		    "REFS", "OUTPUT");

	if (!args->opt_l && !args->opt_t &&
	    mdb_pwalk("avl", do_bridge_fwd, args,
	    addr + offsetof(bridge_inst_t, bi_fwd)) != DCMD_OK)
		return (WALK_ERR);

	nnicks = 0;
	if (bip->bi_trilldata != NULL && !args->opt_l && !args->opt_f) {
		if (mdb_vread(&args->ti, sizeof (args->ti),
		    (uintptr_t)bip->bi_trilldata) == -1) {
			mdb_warn("cannot read trill instance at %p",
			    bip->bi_trilldata);
			return (WALK_ERR);
		}
		if (args->opt_t)
			mdb_printf("%-?s %-5s %-17s %s\n", "ADDR",
			    "NICK", "NEXT-HOP", "LINK");
		for (i = 0; i < RBRIDGE_NICKNAME_MAX; i++) {
			if (args->ti.ti_nodes[i] == NULL)
				continue;
			if (args->opt_t) {
				if (mdb_vread(&tn, sizeof (tn),
				    (uintptr_t)args->ti.ti_nodes[i]) == -1) {
					mdb_warn("cannot read trill node %d at "
					    "%p", i, args->ti.ti_nodes[i]);
					return (WALK_ERR);
				}
				if (mdb_vread(&tni, sizeof (tni),
				    (uintptr_t)tn.tn_ni) == -1) {
					mdb_warn("cannot read trill node info "
					    "%d at %p", i, tn.tn_ni);
					return (WALK_ERR);
				}
				mdb_mac_addr(tni.tni_adjsnpa, ETHERADDRL,
				    macaddr, sizeof (macaddr));
				if (tni.tni_nick == args->ti.ti_nick) {
					(void) strcpy(macaddr, "[self]");
				}
				mdb_printf("%-?p %-5u %-17s ",
				    args->ti.ti_nodes[i], tni.tni_nick,
				    macaddr);
				if (tn.tn_tsp != NULL) {
					if (mdb_vread(&tsp, sizeof (tsp),
					    (uintptr_t)tn.tn_tsp) == -1) {
						mdb_warn("cannot read trill "
						    "socket info at %p",
						    tn.tn_tsp);
						return (WALK_ERR);
					}
					if (tsp.ts_link != NULL) {
						print_link_name(args,
						    (uintptr_t)tsp.ts_link,
						    '\n');
						continue;
					}
				}
				mdb_printf("--\n");
			} else {
				nnicks++;
			}
		}
	} else {
		if (args->opt_t)
			mdb_printf("bridge is not running TRILL\n");
	}

	if (!args->opt_l && !args->opt_f && !args->opt_t) {
		mdb_printf("%-?p %-7s %-16s %-7u %-7u", addr,
		    bip->bi_trilldata == NULL ? "stp" : "trill", bname,
		    args->nlinks, args->nfwd);
		if (bip->bi_trilldata != NULL)
			mdb_printf(" %-7u %u\n", nnicks, args->ti.ti_nick);
		else
			mdb_printf(" %-7s %s\n", "--", "--");
	}
	return (WALK_NEXT);
}

static int
dladm_show_bridge(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	show_bridge_args_t *args;
	GElf_Sym sym;
	int i;

	args = mdb_zalloc(sizeof (*args), UM_SLEEP);

	i = mdb_getopts(argc, argv,
	    'l', MDB_OPT_SETBITS, 1, &args->opt_l,
	    'f', MDB_OPT_SETBITS, 1, &args->opt_f,
	    't', MDB_OPT_SETBITS, 1, &args->opt_t,
	    NULL);

	argc -= i;
	argv += i;

	if (argc > 1 || (argc == 1 && argv[0].a_type != MDB_TYPE_STRING)) {
		mdb_free(args, sizeof (*args));
		return (DCMD_USAGE);
	}
	if (argc == 1)
		args->name = argv[0].a_un.a_str;

	if ((args->lbolt = mdb_get_lbolt()) == -1) {
		mdb_warn("failed to read lbolt");
		goto err;
	}

	if (flags & DCMD_ADDRSPEC) {
		if (args->name != NULL) {
			mdb_printf("bridge name and address are mutually "
			    "exclusive\n");
			goto err;
		}
		if (!args->opt_l && !args->opt_f && !args->opt_t)
			mdb_printf("%-?s %-7s %-16s %-7s %-7s\n", "ADDR",
			    "PROTECT", "NAME", "NLINKS", "NFWD");
		if (do_show_bridge(addr, NULL, args) != WALK_NEXT)
			goto err;
		mdb_free(args, sizeof (*args));
		return (DCMD_OK);
	} else {
		if ((args->opt_l || args->opt_f || args->opt_t) &&
		    args->name == NULL) {
			mdb_printf("need bridge name or address with -[lft]\n");
			goto err;
		}
		if (mdb_lookup_by_obj("bridge", "inst_list", &sym) == -1) {
			mdb_warn("failed to find 'bridge`inst_list'");
			goto err;
		}
		if (!args->opt_l && !args->opt_f && !args->opt_t)
			mdb_printf("%-?s %-7s %-16s %-7s %-7s %-7s %s\n",
			    "ADDR", "PROTECT", "NAME", "NLINKS", "NFWD",
			    "NNICKS", "NICK");
		if (mdb_pwalk("list", do_show_bridge, args,
		    (uintptr_t)sym.st_value) != DCMD_OK)
			goto err;
		if (!args->found && args->name != NULL) {
			mdb_printf("bridge instance %s not found\n",
			    args->name);
			goto err;
		}
		mdb_free(args, sizeof (*args));
		return (DCMD_OK);
	}

err:
	mdb_free(args, sizeof (*args));
	return (DCMD_ERR);
}

/*
 * Support for the "::dladm" dcmd
 */
int
dladm(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc < 1 || argv[0].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	/*
	 * This could be a bit more elaborate, once we support more of the
	 * dladm show-* subcommands.
	 */
	argc--;
	argv++;
	if (strcmp(argv[-1].a_un.a_str, "show-bridge") == 0)
		return (dladm_show_bridge(addr, flags, argc, argv));

	return (DCMD_USAGE);
}

void
dladm_help(void)
{
	mdb_printf("Subcommands:\n"
	    "  show-bridge [-flt] [<name>]\n"
	    "\t     Show bridge information; -l for links and -f for "
	    "forwarding\n"
	    "\t     entries, and -t for TRILL nicknames.  Address is required "
	    "if name\n"
	    "\t     is not specified.\n");
}
