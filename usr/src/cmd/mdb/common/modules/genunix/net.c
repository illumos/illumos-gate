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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <inet/arp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/mi.h>

#define	ADDR_V6_WIDTH	23
#define	ADDR_V4_WIDTH	15

#define	NETSTAT_ALL	0x01
#define	NETSTAT_VERBOSE	0x02
#define	NETSTAT_ROUTE	0x04
#define	NETSTAT_V4	0x08
#define	NETSTAT_V6	0x10
#define	NETSTAT_UNIX	0x20

#define	NETSTAT_FIRST	0x80000000u


/* Walkers for various *_stack_t */
int
ar_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
ar_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_ARP];
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

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
	return ((tcp->tcp_ipversion == IPV4_VERSION) ||
	    (IN6_IS_ADDR_UNSPECIFIED(&tcp->tcp_ip_src_v6) &&
	    (tcp->tcp_state <= TCPS_LISTEN)));
}

static int
net_tcp_ipv6(const tcp_t *tcp)
{
	return (tcp->tcp_ipversion == IPV6_VERSION);
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
	return ((udp->udp_ipversion == IPV4_VERSION) ||
	    (IN6_IS_ADDR_UNSPECIFIED(&udp->udp_v6src) &&
	    (udp->udp_state <= TS_IDLE)));
}

static int
net_udp_ipv6(const udp_t *udp)
{
	return (udp->udp_ipversion == IPV6_VERSION);
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

	wsp->walk_data = mdb_alloc(sizeof (struct sonode), UM_SLEEP);
	return (WALK_NEXT);
}

int
sonode_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	struct sonode *sonodep;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(wsp->walk_data, sizeof (struct sonode),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read sonode at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	sonodep = wsp->walk_data;

	wsp->walk_addr = (uintptr_t)sonodep->so_next;
	return (status);
}

void
sonode_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct sonode));
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

const mi_payload_walk_arg_t mi_ar_arg = {
	"ar_stacks", OFFSETOF(arp_stack_t, as_head), sizeof (ar_t),
	MI_PAYLOAD_DEVICE | MI_PAYLOAD_MODULE
};

const mi_payload_walk_arg_t mi_icmp_arg = {
	"icmp_stacks", OFFSETOF(icmp_stack_t, is_head), sizeof (icmp_t),
	MI_PAYLOAD_DEVICE | MI_PAYLOAD_MODULE
};

const mi_payload_walk_arg_t mi_ill_arg = {
	"ip_stacks", OFFSETOF(ip_stack_t, ips_ip_g_head), sizeof (ill_t),
	MI_PAYLOAD_MODULE
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

	mdb_printf(" %5hi %05x %04x %04hx %0?p\n",
	    so.so_protocol, so.so_state, so.so_mode,
	    so.so_flag, so.so_accessvp);

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
netstat_tcp_cb(uintptr_t kaddr, const void *walk_data, void *cb_data, int af)
{
	const uintptr_t opts = (uintptr_t)cb_data;
	uintptr_t tcp_kaddr;
	conn_t conns, *connp;
	tcp_t tcps, *tcp;

	if (mdb_vread(&conns, sizeof (conn_t), kaddr) == -1) {
		mdb_warn("failed to read conn_t at %p", kaddr);
		return (WALK_ERR);
	}
	connp = &conns;

	tcp_kaddr = (uintptr_t)connp->conn_tcp;
	if (mdb_vread(&tcps, sizeof (tcp_t), tcp_kaddr) == -1) {
		mdb_warn("failed to read tcp_t at %p", kaddr);
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
		net_ipv4addrport_pr(&tcp->tcp_ip_src_v6, tcp->tcp_lport);
		mdb_printf(" ");
		net_ipv4addrport_pr(&tcp->tcp_remote_v6, tcp->tcp_fport);
	} else if (af == AF_INET6) {
		net_ipv6addrport_pr(&tcp->tcp_ip_src_v6, tcp->tcp_lport);
		mdb_printf(" ");
		net_ipv6addrport_pr(&tcp->tcp_remote_v6, tcp->tcp_fport);
	}
	mdb_printf(" %4i", ns_to_stackid((uintptr_t)connp->conn_netstack));

	mdb_printf(" %4i\n", connp->conn_zoneid);

	if (opts & NETSTAT_VERBOSE)
		netstat_tcp_verbose_pr(tcp);

	return (WALK_NEXT);
}

static int
netstat_tcpv4_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	return (netstat_tcp_cb(kaddr, walk_data, cb_data, AF_INET));
}

static int
netstat_tcpv6_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	return (netstat_tcp_cb(kaddr, walk_data, cb_data, AF_INET6));
}

/*ARGSUSED*/
static int
netstat_udp_cb(uintptr_t kaddr, const void *walk_data, void *cb_data, int af)
{
	const uintptr_t opts = (uintptr_t)cb_data;
	udp_t udp;
	conn_t conns;

	if (mdb_vread(&conns, sizeof (conn_t), kaddr) == -1) {
		mdb_warn("failed to read conn_t at %p", kaddr);
		return (WALK_ERR);
	}

	if (mdb_vread(&udp, sizeof (udp_t),
	    (uintptr_t)conns.conn_udp) == -1) {
		mdb_warn("failed to read conn_udp at %p",
		    (uintptr_t)conns.conn_udp);
		return (WALK_ERR);
	}

	if (!((opts & NETSTAT_ALL) || net_udp_active(&udp)) ||
	    (af == AF_INET && !net_udp_ipv4(&udp)) ||
	    (af == AF_INET6 && !net_udp_ipv6(&udp))) {
		return (WALK_NEXT);
	}

	mdb_printf("%0?p %2i ", kaddr, udp.udp_state);
	if (af == AF_INET) {
		net_ipv4addrport_pr(&udp.udp_v6src, udp.udp_port);
		mdb_printf(" ");
		net_ipv4addrport_pr(&udp.udp_v6dst, udp.udp_dstport);
	} else if (af == AF_INET6) {
		net_ipv6addrport_pr(&udp.udp_v6src, udp.udp_port);
		mdb_printf(" ");
		net_ipv6addrport_pr(&udp.udp_v6dst, udp.udp_dstport);
	}
	mdb_printf(" %4i", ns_to_stackid((uintptr_t)conns.conn_netstack));

	mdb_printf(" %4i\n", conns.conn_zoneid);

	return (WALK_NEXT);
}

static int
netstat_udpv4_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	return (netstat_udp_cb(kaddr, walk_data, cb_data, AF_INET));
}

static int
netstat_udpv6_cb(uintptr_t kaddr, const void *walk_data, void *cb_data)
{
	return (netstat_udp_cb(kaddr, walk_data, cb_data, AF_INET6));
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
netstat_unix_name_pr(const struct sonode *so, const struct soaddr *soa)
{
	const char none[] = " (none)";

	if ((so->so_state & SS_ISBOUND) && (soa->soa_len != 0)) {
		if (so->so_state & SS_FADDR_NOXLATE) {
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
	const struct sonode *so = walk_data;

	if (so->so_accessvp == NULL)
		return (WALK_NEXT);

	if (so->so_family != AF_UNIX) {
		mdb_warn("sonode of family %hi at %p\n", so->so_family, kaddr);
		return (WALK_ERR);
	}

	mdb_printf("%-?p ", kaddr);

	switch (so->so_serv_type) {
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
		mdb_printf("%-10i ", so->so_serv_type);
	}

	if ((so->so_state & SS_ISBOUND) &&
	    (so->so_ux_laddr.soua_magic == SOU_MAGIC_EXPLICIT)) {
		mdb_printf("%0?p ", so->so_ux_laddr.soua_vp);
	} else {
		mdb_printf("%0?p ", NULL);
	}

	if ((so->so_state & SS_ISCONNECTED) &&
	    (so->so_ux_faddr.soua_magic == SOU_MAGIC_EXPLICIT)) {
		mdb_printf("%0?p ", so->so_ux_faddr.soua_vp);
	} else {
		mdb_printf("%0?p ", NULL);
	}

	if (netstat_unix_name_pr(so, &so->so_laddr) == -1)
		return (WALK_ERR);

	if (netstat_unix_name_pr(so, &so->so_faddr) == -1)
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
	if (ire->ire_type == IRE_CACHE) {
		queue_t stq;

		if (mdb_vread(&stq, sizeof (stq), (uintptr_t)ire->ire_stq) ==
		    -1)
			return;
		if (mdb_vread(&ill, sizeof (ill), (uintptr_t)stq.q_ptr) == -1)
			return;
		(void) mdb_readstr(intf, MIN(LIFNAMSIZ, ill.ill_name_length),
		    (uintptr_t)ill.ill_name);
	} else if (ire->ire_ipif != NULL) {
		ipif_t ipif;
		char *cp;

		if (mdb_vread(&ipif, sizeof (ipif),
		    (uintptr_t)ire->ire_ipif) == -1)
			return;
		if (mdb_vread(&ill, sizeof (ill), (uintptr_t)ipif.ipif_ill) ==
		    -1)
			return;
		(void) mdb_readstr(intf, MIN(LIFNAMSIZ, ill.ill_name_length),
		    (uintptr_t)ill.ill_name);
		if (ipif.ipif_id != 0) {
			cp = intf + strlen(intf);
			(void) mdb_snprintf(cp, LIFNAMSIZ + 1 - (cp - intf),
			    ":%u", ipif.ipif_id);
		}
	}
}

static void
get_v4flags(const ire_t *ire, char *flags)
{
	(void) strcpy(flags, "U");
	if (ire->ire_type == IRE_DEFAULT || ire->ire_type == IRE_PREFIX ||
	    ire->ire_type == IRE_HOST || ire->ire_type == IRE_HOST_REDIRECT)
		(void) strcat(flags, "G");
	if (ire->ire_mask == IP_HOST_MASK)
		(void) strcat(flags, "H");
	if (ire->ire_type == IRE_HOST_REDIRECT)
		(void) strcat(flags, "D");
	if (ire->ire_type == IRE_CACHE)
		(void) strcat(flags, "A");
	if (ire->ire_type == IRE_BROADCAST)
		(void) strcat(flags, "B");
	if (ire->ire_type == IRE_LOCAL)
		(void) strcat(flags, "L");
	if (ire->ire_flags & RTF_MULTIRT)
		(void) strcat(flags, "M");
	if (ire->ire_flags & RTF_SETSRC)
		(void) strcat(flags, "S");
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

	if (!(*opts & NETSTAT_ALL) && (ire->ire_type == IRE_CACHE ||
	    ire->ire_type == IRE_BROADCAST || ire->ire_type == IRE_LOCAL))
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

	gate = (ire->ire_type & (IRE_INTERFACE|IRE_LOOPBACK|IRE_BROADCAST)) ?
	    ire->ire_src_addr : ire->ire_gateway_addr;

	get_v4flags(ire, flags);

	get_ifname(ire, intf);

	if (*opts & NETSTAT_VERBOSE) {
		mdb_printf("%?p %-*I %-*I %-*I %-6s %5u%c %4u %3u %-3s %5u "
		    "%u\n", kaddr, ADDR_V4_WIDTH, ire->ire_addr, ADDR_V4_WIDTH,
		    ire->ire_mask, ADDR_V4_WIDTH, gate, intf,
		    ire->ire_max_frag, ire->ire_frag_flag ? '*' : ' ',
		    ire->ire_uinfo.iulp_rtt, ire->ire_refcnt, flags,
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

	if (!(*opts & NETSTAT_ALL) && ire->ire_type == IRE_CACHE)
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

	gatep = (ire->ire_type & (IRE_INTERFACE|IRE_LOOPBACK)) ?
	    &ire->ire_src_addr_v6 : &ire->ire_gateway_addr_v6;

	masklen = ip_mask_to_plen_v6(&ire->ire_mask_v6);
	(void) mdb_snprintf(deststr, sizeof (deststr), "%N/%d",
	    &ire->ire_addr_v6, masklen);

	(void) strcpy(flags, "U");
	if (ire->ire_type == IRE_DEFAULT || ire->ire_type == IRE_PREFIX ||
	    ire->ire_type == IRE_HOST || ire->ire_type == IRE_HOST_REDIRECT)
		(void) strcat(flags, "G");
	if (masklen == IPV6_ABITS)
		(void) strcat(flags, "H");
	if (ire->ire_type == IRE_HOST_REDIRECT)
		(void) strcat(flags, "D");
	if (ire->ire_type == IRE_CACHE)
		(void) strcat(flags, "A");
	if (ire->ire_type == IRE_LOCAL)
		(void) strcat(flags, "L");
	if (ire->ire_flags & RTF_MULTIRT)
		(void) strcat(flags, "M");
	if (ire->ire_flags & RTF_SETSRC)
		(void) strcat(flags, "S");

	get_ifname(ire, intf);

	if (*opts & NETSTAT_VERBOSE) {
		mdb_printf("%?p %-*s %-*N %-5s %5u%c %5u %3u %-5s %6u %u\n",
		    kaddr, ADDR_V6_WIDTH+4, deststr, ADDR_V6_WIDTH, gatep,
		    intf, ire->ire_max_frag, ire->ire_frag_flag ? '*' : ' ',
		    ire->ire_uinfo.iulp_rtt, ire->ire_refcnt,
		    flags, ire->ire_ob_pkt_count, ire->ire_ib_pkt_count);
	} else {
		mdb_printf("%?p %-*s %-*N %-5s %3u %6u %s\n", kaddr,
		    ADDR_V6_WIDTH+4, deststr, ADDR_V6_WIDTH, gatep, flags,
		    ire->ire_refcnt,
		    ire->ire_ob_pkt_count + ire->ire_ib_pkt_count, intf);
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
netstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opts = 0;
	const char *optf = NULL;
	const char *optP = NULL;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, NETSTAT_ALL, &opts,
	    'f', MDB_OPT_STR, &optf,
	    'P', MDB_OPT_STR, &optP,
	    'r', MDB_OPT_SETBITS, NETSTAT_ROUTE, &opts,
	    'v', MDB_OPT_SETBITS, NETSTAT_VERBOSE, &opts,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (optP != NULL) {
		if ((strcmp("tcp", optP) != 0) && (strcmp("udp", optP) != 0))
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

	if ((optP == NULL) || (strcmp("tcp", optP) == 0)) {
		if ((optf == NULL) || (strcmp("inet", optf) == 0)) {
			/* Print TCPv4 connection */
			mdb_printf("%<u>%-?s St %*s       %*s       "
			    "%s%       %s%</u>\n",
			    "TCPv4", ADDR_V4_WIDTH, "Local Address",
			    ADDR_V4_WIDTH, "Remote Address", "Stack", "Zone");

			if (opts & NETSTAT_VERBOSE)
				netstat_tcp_verbose_header_pr();

			if (mdb_walk("tcp_conn_cache", netstat_tcpv4_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk tcp_conn_cache");
				return (DCMD_ERR);
			}
		}

		if ((optf == NULL) || (strcmp("inet6", optf) == 0)) {
			/* Print TCPv6 connection */
			mdb_printf("%<u>%-?s St %*s       %*s       "
			    "%s       %s%\n%</u>",
			    "TCPv6", ADDR_V6_WIDTH, "Local Address",
			    ADDR_V6_WIDTH, "Remote Address", "Stack", "Zone");

			if (opts & NETSTAT_VERBOSE)
				netstat_tcp_verbose_header_pr();

			if (mdb_walk("tcp_conn_cache", netstat_tcpv6_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk tcp_conn_cache");
				return (DCMD_ERR);
			}
		}
	}

	if ((optP == NULL) || (strcmp("udp", optP) == 0)) {
		if ((optf == NULL) || (strcmp("inet", optf) == 0)) {
			/* Print UDPv4 connection */
			mdb_printf("%<u>%-?s St %*s       %*s       "
			    "%s       %s%\n%</u>",
			    "UDPv4", ADDR_V4_WIDTH, "Local Address",
			    ADDR_V4_WIDTH, "Remote Address", "Stack", "Zone");

			if (mdb_walk("udp_conn_cache", netstat_udpv4_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk udp_conn_cache");
				return (DCMD_ERR);
			}

		}

		if ((optf == NULL) || (strcmp("inet6", optf) == 0)) {
			/* Print UDPv6 connection */
			mdb_printf("%<u>%-?s St %*s       %*s       "
			    "%s       %s%\n%</u>",
			    "UDPv6", ADDR_V6_WIDTH, "Local Address",
			    ADDR_V6_WIDTH, "Remote Address", "Stack", "Zone");

			if (mdb_walk("udp_conn_cache", netstat_udpv6_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk udp_conn_cache");
				return (DCMD_ERR);
			}
		}
	}

	if (((optf == NULL) || (strcmp("unix", optf) == 0)) && (optP == NULL)) {
		/* Print Unix Domain Sockets */
		mdb_printf("%<u>%-?s %-10s %-?s %-?s %-14s %-14s %s%</u>\n",
		    "AF_UNIX", "Type", "Vnode", "Conn", "Local Addr",
		    "Remote Addr", "Zone");

		if (mdb_walk("genunix`sonode", netstat_unix_cb, NULL) == -1) {
			mdb_warn("failed to walk genunix`sonode");
			return (DCMD_ERR);
		}
	}

	return (DCMD_OK);
}
