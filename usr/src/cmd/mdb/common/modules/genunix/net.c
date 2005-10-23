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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#define	MIH2MIO(mihp) (&(mihp)->mh_o)

#define	ADDR_V6_WIDTH	23
#define	ADDR_V4_WIDTH	15

#define	NETSTAT_ALL	0x1
#define	NETSTAT_VERBOSE	0x2

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

	status = wsp->walk_callback(wsp->walk_addr, miop, wsp->walk_cbdata);

	/* Only true in the first iteration */
	if (wdp->mi_wd_miofirst == NULL)
		wdp->mi_wd_miofirst = wsp->walk_addr;

	wsp->walk_addr = (uintptr_t)miop->mi_o_next;
	return (status);
}

void
mi_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct mi_walk_data));
}

typedef struct mi_payload_walk_data_s {
	uintptr_t mi_pwd_first;
	void *mi_pwd_data;
} mi_payload_walk_data_t;

static void
delete_mi_payload_walk_data(mi_payload_walk_data_t *pwdp, size_t payload_size)
{
	mdb_free(pwdp->mi_pwd_data, payload_size);
	mdb_free(pwdp, sizeof (mi_payload_walk_data_t));
}

typedef struct mi_payload_walk_arg_s {
	const char *mi_pwa_obj;		/* load object of mi_o_head_t * */
	const char *mi_pwa_sym;		/* symbol name of mi_o_head_t * */
	const size_t mi_pwa_size;	/* size of mi payload */
	const uint_t mi_pwa_flags;	/* device and/or module */
} mi_payload_walk_arg_t;

#define	MI_PAYLOAD_DEVICE	0x1
#define	MI_PAYLOAD_MODULE	0x2

int
mi_payload_walk_init(mdb_walk_state_t *wsp)
{
	const mi_payload_walk_arg_t *arg = wsp->walk_arg;
	mi_payload_walk_data_t *pwdp;
	GElf_Sym sym;
	mi_head_t *mihp;

	/* Determine the address to start or end the walk with */
	if (mdb_lookup_by_obj(arg->mi_pwa_obj, arg->mi_pwa_sym, &sym) == -1) {
		mdb_warn("failed to lookup %s`%s",
		    arg->mi_pwa_obj, arg->mi_pwa_sym);
		return (WALK_ERR);
	}

	if (mdb_vread(&mihp, sizeof (mihp), (uintptr_t)sym.st_value) == -1) {
		mdb_warn("failed to read address of global MI Head "
		    "mi_o_head_t at %p", (uintptr_t)sym.st_value);
		return (WALK_ERR);
	}

	pwdp = mdb_alloc(sizeof (mi_payload_walk_data_t), UM_SLEEP);
	pwdp->mi_pwd_data = mdb_alloc(arg->mi_pwa_size, UM_SLEEP);
	wsp->walk_data = pwdp;

	if (wsp->walk_addr == NULL) {
		/* Do not immediately return WALK_DONE below */
		pwdp->mi_pwd_first = NULL;
		/* We determined where to begin */
		wsp->walk_addr = (uintptr_t)MIH2MIO(mihp);
	} else {
		/* Do not cycle through all of the MI_O objects */
		pwdp->mi_pwd_first = (uintptr_t)MIH2MIO(mihp);
		/* We were given where to begin */
		wsp->walk_addr = (uintptr_t)((MI_OP)wsp->walk_addr - 1);
	}

	if (mdb_layered_walk("genunix`mi", wsp) == -1) {
		mdb_warn("failed to walk genunix`mi");
		delete_mi_payload_walk_data(pwdp, arg->mi_pwa_size);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
mi_payload_walk_step(mdb_walk_state_t *wsp)
{
	const mi_payload_walk_arg_t *arg = wsp->walk_arg;
	mi_payload_walk_data_t *pwdp = wsp->walk_data;
	void *payload = pwdp->mi_pwd_data;
	uintptr_t payload_kaddr = (uintptr_t)((MI_OP)wsp->walk_addr + 1);
	const MI_O *mio = wsp->walk_layer;

	/* If this is a local walk, prevent cycling */
	if (wsp->walk_addr == pwdp->mi_pwd_first)
		return (WALK_DONE);

	/*
	 * This was a global walk, prevent reading this payload as the
	 * initial MI_O is the head of the list and is not the header
	 * to a valid payload
	 */
	if (pwdp->mi_pwd_first == NULL) {
		pwdp->mi_pwd_first = wsp->walk_addr;
		return (WALK_NEXT);
	}

	if (mio->mi_o_isdev == B_FALSE) {
		/* mio is a module */
		if (!(arg->mi_pwa_flags & MI_PAYLOAD_MODULE))
			return (WALK_NEXT);
	} else {
		/* mio is a device */
		if (!(arg->mi_pwa_flags & MI_PAYLOAD_DEVICE))
			return (WALK_NEXT);
	}

	if (mdb_vread(payload, arg->mi_pwa_size, payload_kaddr) == -1) {
		mdb_warn("failed to read payload at %p", payload_kaddr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(payload_kaddr, payload, wsp->walk_cbdata));
}

void
mi_payload_walk_fini(mdb_walk_state_t *wsp)
{
	const mi_payload_walk_arg_t *arg = wsp->walk_arg;

	delete_mi_payload_walk_data(wsp->walk_data, arg->mi_pwa_size);
}

const mi_payload_walk_arg_t mi_ar_arg = {
	"arp", "ar_g_head", sizeof (ar_t),
	MI_PAYLOAD_DEVICE | MI_PAYLOAD_MODULE
};

const mi_payload_walk_arg_t mi_icmp_arg = {
	"icmp", "icmp_g_head", sizeof (icmp_t),
	MI_PAYLOAD_DEVICE | MI_PAYLOAD_MODULE
};

const mi_payload_walk_arg_t mi_ill_arg =
	{ "ip", "ip_g_head", sizeof (ill_t), MI_PAYLOAD_MODULE };

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
	static size_t itc_size = 0;
	uintptr_t tcp_kaddr;
	conn_t *connp;
	tcp_t *tcp;

	if (itc_size == 0) {
		mdb_ctf_id_t id;

		if (mdb_ctf_lookup_by_name("itc_t", &id) != 0) {
			mdb_warn("failed to lookup type 'itc_t'");
			return (WALK_ERR);
		}
		itc_size = mdb_ctf_type_size(id);
	}

	connp = (conn_t *)mdb_alloc(itc_size, UM_SLEEP | UM_GC);

	if (mdb_vread(connp, itc_size, kaddr) == -1) {
		mdb_warn("failed to read connection info at %p", kaddr);
		return (WALK_ERR);
	}

	tcp_kaddr = (uintptr_t)connp->conn_tcp;
	tcp = (tcp_t *)((uintptr_t)connp + (tcp_kaddr - kaddr));

	if ((uintptr_t)tcp < (uintptr_t)connp ||
	    (uintptr_t)(tcp + 1) > (uintptr_t)connp + itc_size ||
	    (uintptr_t)tcp->tcp_connp != kaddr) {
		mdb_warn("conn_tcp %p is invalid", tcp_kaddr);
		return (WALK_NEXT);
	}
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
	conn_t connp;

	if (mdb_vread(&udp, sizeof (udp_t), kaddr) == -1) {
		mdb_warn("failed to read udp at %p", kaddr);
		return (WALK_ERR);
	}

	if (mdb_vread(&connp, sizeof (conn_t),
	    (uintptr_t)udp.udp_connp) == -1) {
		mdb_warn("failed to read udp_connp at %p",
		    (uintptr_t)udp.udp_connp);
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
	mdb_printf(" %4i\n", connp.conn_zoneid);

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

/*ARGSUSED*/
int
netstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opts = 0;
	const char *optf = NULL;
	const char *optP = NULL;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, NETSTAT_ALL, &opts,
	    'v', MDB_OPT_SETBITS, NETSTAT_VERBOSE, &opts,
	    'f', MDB_OPT_STR, &optf,
	    'P', MDB_OPT_STR, &optP,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (optP != NULL) {
		if ((strcmp("tcp", optP) != 0) && (strcmp("udp", optP) != 0))
			return (DCMD_USAGE);

	}

	if (optf != NULL) {
		if ((strcmp("inet", optf) != 0) &&
		    (strcmp("inet6", optf) != 0) &&
		    (strcmp("unix", optf) != 0))
			return (DCMD_USAGE);
	}

	if ((optP == NULL) || (strcmp("tcp", optP) == 0)) {
		if ((optf == NULL) || (strcmp("inet", optf) == 0)) {
			/* Print TCPv4 connection */
			mdb_printf(
			    "%<u>%-?s St %*s       %*s       %s%</u>\n",
			    "TCPv4", ADDR_V4_WIDTH, "Local Address",
			    ADDR_V4_WIDTH, "Remote Address", "Zone");

			if (opts & NETSTAT_VERBOSE)
				netstat_tcp_verbose_header_pr();

			if (mdb_walk("ipcl_tcpconn_cache", netstat_tcpv4_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk ipcl_tcpconn_cache");
				return (DCMD_ERR);
			}
		}

		if ((optf == NULL) || (strcmp("inet6", optf) == 0)) {
			/* Print TCPv6 connection */
			mdb_printf(
			    "%<u>%-?s St %*s       %*s       %s\n%</u>",
			    "TCPv6", ADDR_V6_WIDTH, "Local Address",
			    ADDR_V6_WIDTH, "Remote Address", "Zone");

			if (opts & NETSTAT_VERBOSE)
				netstat_tcp_verbose_header_pr();

			if (mdb_walk("ipcl_tcpconn_cache", netstat_tcpv6_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk ipcl_tcpconn_cache");
				return (DCMD_ERR);
			}
		}
	}

	if ((optP == NULL) || (strcmp("udp", optP) == 0)) {
		if ((optf == NULL) || (strcmp("inet", optf) == 0)) {
			/* Print UDPv4 connection */
			mdb_printf(
			    "%<u>%-?s St %*s       %*s       %s\n%</u>",
			    "UDPv4", ADDR_V4_WIDTH, "Local Address",
			    ADDR_V4_WIDTH, "Remote Address", "Zone");

			if (mdb_walk("udp_cache", netstat_udpv4_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk genunix`udp");
				return (DCMD_ERR);
			}

		}

		if ((optf == NULL) || (strcmp("inet6", optf) == 0)) {
			/* Print UDPv6 connection */
			mdb_printf(
			    "%<u>%-?s St %*s       %*s       %s\n%</u>",
			    "UDPv6", ADDR_V6_WIDTH, "Local Address",
			    ADDR_V6_WIDTH, "Remote Address", "Zone");

			if (mdb_walk("udp_cache", netstat_udpv6_cb,
			    (void *)(uintptr_t)opts) == -1) {
				mdb_warn("failed to walk genunix`udp");
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
