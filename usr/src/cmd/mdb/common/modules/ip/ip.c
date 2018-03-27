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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/avl_impl.h>
#include <net/if_types.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <inet/mib2.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>
#include <inet/mi.h>
#include <sys/squeue_impl.h>
#include <sys/modhash_impl.h>
#include <inet/ip_ndp.h>
#include <inet/ip_if.h>
#include <ilb.h>
#include <ilb/ilb_impl.h>
#include <ilb/ilb_stack.h>
#include <ilb/ilb_nat.h>
#include <ilb/ilb_conn.h>
#include <sys/dlpi.h>
#include <sys/zone.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#define	ADDR_WIDTH 11
#define	L2MAXADDRSTRLEN	255
#define	MAX_SAP_LEN	255
#define	DEFCOLS		80

typedef struct {
	const char *bit_name;	/* name of bit */
	const char *bit_descr;	/* description of bit's purpose */
} bitname_t;

static const bitname_t squeue_states[] = {
	{ "SQS_PROC",		"being processed" },
	{ "SQS_WORKER",		"... by a worker thread" },
	{ "SQS_ENTER",		"... by an squeue_enter() thread" },
	{ "SQS_FAST",		"... in fast-path mode" },
	{ "SQS_USER", 		"A non interrupt user" },
	{ "SQS_BOUND",		"worker thread bound to CPU" },
	{ "SQS_PROFILE",	"profiling enabled" },
	{ "SQS_REENTER",	"re-entered thred" },
	{ NULL }
};

typedef struct illif_walk_data {
	ill_g_head_t ill_g_heads[MAX_G_HEADS];
	int ill_list;
	ill_if_t ill_if;
} illif_walk_data_t;

typedef struct ncec_walk_data_s {
	struct ndp_g_s	ncec_ip_ndp;
	int		ncec_hash_tbl_index;
	ncec_t 		ncec;
} ncec_walk_data_t;

typedef struct ncec_cbdata_s {
	uintptr_t ncec_addr;
	int	  ncec_ipversion;
} ncec_cbdata_t;

typedef struct nce_cbdata_s {
	int		nce_ipversion;
	char		nce_ill_name[LIFNAMSIZ];
} nce_cbdata_t;

typedef struct ire_cbdata_s {
	int		ire_ipversion;
	boolean_t	verbose;
} ire_cbdata_t;

typedef struct zi_cbdata_s {
	const char	*zone_name;
	ip_stack_t	*ipst;
	boolean_t	shared_ip_zone;
} zi_cbdata_t;

typedef struct th_walk_data {
	uint_t		thw_non_zero_only;
	boolean_t	thw_match;
	uintptr_t	thw_matchkey;
	uintptr_t	thw_ipst;
	clock_t		thw_lbolt;
} th_walk_data_t;

typedef struct ipcl_hash_walk_data_s {
	conn_t		*conn;
	int		connf_tbl_index;
	uintptr_t	hash_tbl;
	int		hash_tbl_size;
} ipcl_hash_walk_data_t;

typedef struct ill_walk_data_s {
	ill_t 		ill;
} ill_walk_data_t;

typedef struct ill_cbdata_s {
	uintptr_t ill_addr;
	int	  ill_ipversion;
	ip_stack_t *ill_ipst;
	boolean_t verbose;
} ill_cbdata_t;

typedef struct ipif_walk_data_s {
	ipif_t 		ipif;
} ipif_walk_data_t;

typedef struct ipif_cbdata_s {
	ill_t		ill;
	int		ipif_ipversion;
	boolean_t 	verbose;
} ipif_cbdata_t;

typedef struct hash_walk_arg_s {
	off_t	tbl_off;
	off_t	size_off;
} hash_walk_arg_t;

static hash_walk_arg_t udp_hash_arg = {
	OFFSETOF(ip_stack_t, ips_ipcl_udp_fanout),
	OFFSETOF(ip_stack_t, ips_ipcl_udp_fanout_size)
};

static hash_walk_arg_t conn_hash_arg = {
	OFFSETOF(ip_stack_t, ips_ipcl_conn_fanout),
	OFFSETOF(ip_stack_t, ips_ipcl_conn_fanout_size)
};

static hash_walk_arg_t bind_hash_arg = {
	OFFSETOF(ip_stack_t, ips_ipcl_bind_fanout),
	OFFSETOF(ip_stack_t, ips_ipcl_bind_fanout_size)
};

static hash_walk_arg_t proto_hash_arg = {
	OFFSETOF(ip_stack_t, ips_ipcl_proto_fanout_v4),
	0
};

static hash_walk_arg_t proto_v6_hash_arg = {
	OFFSETOF(ip_stack_t, ips_ipcl_proto_fanout_v6),
	0
};

typedef struct ip_list_walk_data_s {
	off_t 	nextoff;
} ip_list_walk_data_t;

typedef struct ip_list_walk_arg_s {
	off_t	off;
	size_t	size;
	off_t	nextp_off;
} ip_list_walk_arg_t;

static ip_list_walk_arg_t ipif_walk_arg = {
	OFFSETOF(ill_t, ill_ipif),
	sizeof (ipif_t),
	OFFSETOF(ipif_t, ipif_next)
};

static ip_list_walk_arg_t srcid_walk_arg = {
	OFFSETOF(ip_stack_t, ips_srcid_head),
	sizeof (srcid_map_t),
	OFFSETOF(srcid_map_t, sm_next)
};

static int iphdr(uintptr_t, uint_t, int, const mdb_arg_t *);
static int ip6hdr(uintptr_t, uint_t, int, const mdb_arg_t *);

static int ill(uintptr_t, uint_t, int, const mdb_arg_t *);
static void ill_help(void);
static int ill_walk_init(mdb_walk_state_t *);
static int ill_walk_step(mdb_walk_state_t *);
static int ill_format(uintptr_t, const void *, void *);
static void ill_header(boolean_t);

static int ipif(uintptr_t, uint_t, int, const mdb_arg_t *);
static void ipif_help(void);
static int ipif_walk_init(mdb_walk_state_t *);
static int ipif_walk_step(mdb_walk_state_t *);
static int ipif_format(uintptr_t, const void *, void *);
static void ipif_header(boolean_t);

static int ip_list_walk_init(mdb_walk_state_t *);
static int ip_list_walk_step(mdb_walk_state_t *);
static void ip_list_walk_fini(mdb_walk_state_t *);
static int srcid_walk_step(mdb_walk_state_t *);

static int ire_format(uintptr_t addr, const void *, void *);
static int ncec_format(uintptr_t addr, const ncec_t *ncec, int ipversion);
static int ncec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv);
static int ncec_walk_step(mdb_walk_state_t *wsp);
static int ncec_stack_walk_init(mdb_walk_state_t *wsp);
static int ncec_stack_walk_step(mdb_walk_state_t *wsp);
static void ncec_stack_walk_fini(mdb_walk_state_t *wsp);
static int ncec_cb(uintptr_t addr, const ncec_walk_data_t *iw,
    ncec_cbdata_t *id);
static char *nce_l2_addr(const nce_t *, const ill_t *);

static int ipcl_hash_walk_init(mdb_walk_state_t *);
static int ipcl_hash_walk_step(mdb_walk_state_t *);
static void ipcl_hash_walk_fini(mdb_walk_state_t *);

static int conn_status_walk_step(mdb_walk_state_t *);
static int conn_status(uintptr_t, uint_t, int, const mdb_arg_t *);
static void conn_status_help(void);

static int srcid_status(uintptr_t, uint_t, int, const mdb_arg_t *);

static int ilb_stacks_walk_step(mdb_walk_state_t *);
static int ilb_rules_walk_init(mdb_walk_state_t *);
static int ilb_rules_walk_step(mdb_walk_state_t *);
static int ilb_servers_walk_init(mdb_walk_state_t *);
static int ilb_servers_walk_step(mdb_walk_state_t *);
static int ilb_nat_src_walk_init(mdb_walk_state_t *);
static int ilb_nat_src_walk_step(mdb_walk_state_t *);
static int ilb_conn_walk_init(mdb_walk_state_t *);
static int ilb_conn_walk_step(mdb_walk_state_t *);
static int ilb_sticky_walk_init(mdb_walk_state_t *);
static int ilb_sticky_walk_step(mdb_walk_state_t *);
static void ilb_common_walk_fini(mdb_walk_state_t *);

/*
 * Given the kernel address of an ip_stack_t, return the stackid
 */
static int
ips_to_stackid(uintptr_t kaddr)
{
	ip_stack_t ipss;
	netstack_t nss;

	if (mdb_vread(&ipss, sizeof (ipss), kaddr) == -1) {
		mdb_warn("failed to read ip_stack_t %p", kaddr);
		return (0);
	}
	kaddr = (uintptr_t)ipss.ips_netstack;
	if (mdb_vread(&nss, sizeof (nss), kaddr) == -1) {
		mdb_warn("failed to read netstack_t %p", kaddr);
		return (0);
	}
	return (nss.netstack_stackid);
}

/* ARGSUSED */
static int
zone_to_ips_cb(uintptr_t addr, const void *zi_arg, void *zi_cb_arg)
{
	zi_cbdata_t *zi_cb = zi_cb_arg;
	zone_t zone;
	char zone_name[ZONENAME_MAX];
	netstack_t ns;

	if (mdb_vread(&zone, sizeof (zone_t), addr) == -1) {
		mdb_warn("can't read zone at %p", addr);
		return (WALK_ERR);
	}

	(void) mdb_readstr(zone_name, ZONENAME_MAX, (uintptr_t)zone.zone_name);

	if (strcmp(zi_cb->zone_name, zone_name) != 0)
		return (WALK_NEXT);

	zi_cb->shared_ip_zone = (!(zone.zone_flags & ZF_NET_EXCL) &&
	    (strcmp(zone_name, "global") != 0));

	if (mdb_vread(&ns, sizeof (netstack_t), (uintptr_t)zone.zone_netstack)
	    == -1) {
		mdb_warn("can't read netstack at %p", zone.zone_netstack);
		return (WALK_ERR);
	}

	zi_cb->ipst = ns.netstack_ip;
	return (WALK_DONE);
}

static ip_stack_t *
zone_to_ips(const char *zone_name)
{
	zi_cbdata_t zi_cb;

	if (zone_name == NULL)
		return (NULL);

	zi_cb.zone_name = zone_name;
	zi_cb.ipst = NULL;
	zi_cb.shared_ip_zone = B_FALSE;

	if (mdb_walk("zone", (mdb_walk_cb_t)zone_to_ips_cb, &zi_cb) == -1) {
		mdb_warn("failed to walk zone");
		return (NULL);
	}

	if (zi_cb.shared_ip_zone) {
		mdb_warn("%s is a Shared-IP zone, try '-s global' instead\n",
		    zone_name);
		return (NULL);
	}

	if (zi_cb.ipst == NULL) {
		mdb_warn("failed to find zone %s\n", zone_name);
		return (NULL);
	}

	return (zi_cb.ipst);
}

/*
 * Generic network stack walker initialization function.  It is used by all
 * other netwrok stack walkers.
 */
int
ns_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Generic network stack walker stepping function.  It is used by all other
 * network stack walkers.  The which parameter differentiates the different
 * walkers.
 */
int
ns_walk_step(mdb_walk_state_t *wsp, int which)
{
	uintptr_t kaddr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[which];

	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
}

/*
 * IP network stack walker stepping function.
 */
int
ip_stacks_walk_step(mdb_walk_state_t *wsp)
{
	return (ns_walk_step(wsp, NS_IP));
}

/*
 * TCP network stack walker stepping function.
 */
int
tcp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	return (ns_walk_step(wsp, NS_TCP));
}

/*
 * SCTP network stack walker stepping function.
 */
int
sctp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	return (ns_walk_step(wsp, NS_SCTP));
}

/*
 * UDP network stack walker stepping function.
 */
int
udp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	return (ns_walk_step(wsp, NS_UDP));
}

/*
 * Initialization function for the per CPU TCP stats counter walker of a given
 * TCP stack.
 */
int
tcps_sc_walk_init(mdb_walk_state_t *wsp)
{
	tcp_stack_t tcps;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	if (mdb_vread(&tcps, sizeof (tcps), wsp->walk_addr) == -1) {
		mdb_warn("failed to read tcp_stack_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if (tcps.tcps_sc_cnt == 0)
		return (WALK_DONE);

	/*
	 * Store the tcp_stack_t pointer in walk_data.  The stepping function
	 * used it to calculate if the end of the counter has reached.
	 */
	wsp->walk_data = (void *)wsp->walk_addr;
	wsp->walk_addr = (uintptr_t)tcps.tcps_sc;
	return (WALK_NEXT);
}

/*
 * Stepping function for the per CPU TCP stats counterwalker.
 */
int
tcps_sc_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	tcp_stack_t tcps;
	tcp_stats_cpu_t *stats;
	char *next, *end;

	if (mdb_vread(&tcps, sizeof (tcps), (uintptr_t)wsp->walk_data) == -1) {
		mdb_warn("failed to read tcp_stack_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if (mdb_vread(&stats, sizeof (stats), wsp->walk_addr) == -1) {
		mdb_warn("failed ot read tcp_stats_cpu_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback((uintptr_t)stats, &stats, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	next = (char *)wsp->walk_addr + sizeof (tcp_stats_cpu_t *);
	end = (char *)tcps.tcps_sc + tcps.tcps_sc_cnt *
	    sizeof (tcp_stats_cpu_t *);
	if (next >= end)
		return (WALK_DONE);
	wsp->walk_addr = (uintptr_t)next;
	return (WALK_NEXT);
}

int
th_hash_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	list_node_t *next;

	if (wsp->walk_addr == NULL) {
		if (mdb_lookup_by_obj("ip", "ip_thread_list", &sym) == 0) {
			wsp->walk_addr = sym.st_value;
		} else {
			mdb_warn("unable to locate ip_thread_list\n");
			return (WALK_ERR);
		}
	}

	if (mdb_vread(&next, sizeof (next),
	    wsp->walk_addr + offsetof(list_t, list_head) +
	    offsetof(list_node_t, list_next)) == -1 ||
	    next == NULL) {
		mdb_warn("non-DEBUG image; cannot walk th_hash list\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("can't walk 'list'");
		return (WALK_ERR);
	} else {
		return (WALK_NEXT);
	}
}

int
th_hash_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * Called with walk_addr being the address of ips_ill_g_heads
 */
int
illif_stack_walk_init(mdb_walk_state_t *wsp)
{
	illif_walk_data_t *iw;

	if (wsp->walk_addr == NULL) {
		mdb_warn("illif_stack supports only local walks\n");
		return (WALK_ERR);
	}

	iw = mdb_alloc(sizeof (illif_walk_data_t), UM_SLEEP);

	if (mdb_vread(iw->ill_g_heads, MAX_G_HEADS * sizeof (ill_g_head_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read 'ips_ill_g_heads' at %p",
		    wsp->walk_addr);
		mdb_free(iw, sizeof (illif_walk_data_t));
		return (WALK_ERR);
	}

	iw->ill_list = 0;
	wsp->walk_addr = (uintptr_t)iw->ill_g_heads[0].ill_g_list_head;
	wsp->walk_data = iw;

	return (WALK_NEXT);
}

int
illif_stack_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	illif_walk_data_t *iw = wsp->walk_data;
	int list = iw->ill_list;

	if (mdb_vread(&iw->ill_if, sizeof (ill_if_t), addr) == -1) {
		mdb_warn("failed to read ill_if_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)iw->ill_if.illif_next;

	if (wsp->walk_addr ==
	    (uintptr_t)iw->ill_g_heads[list].ill_g_list_head) {

		if (++list >= MAX_G_HEADS)
			return (WALK_DONE);

		iw->ill_list = list;
		wsp->walk_addr =
		    (uintptr_t)iw->ill_g_heads[list].ill_g_list_head;
		return (WALK_NEXT);
	}

	return (wsp->walk_callback(addr, iw, wsp->walk_cbdata));
}

void
illif_stack_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (illif_walk_data_t));
}

typedef struct illif_cbdata {
	uint_t ill_flags;
	uintptr_t ill_addr;
	int ill_printlist;	/* list to be printed (MAX_G_HEADS for all) */
	boolean_t ill_printed;
} illif_cbdata_t;

static int
illif_cb(uintptr_t addr, const illif_walk_data_t *iw, illif_cbdata_t *id)
{
	const char *version;

	if (id->ill_printlist < MAX_G_HEADS &&
	    id->ill_printlist != iw->ill_list)
		return (WALK_NEXT);

	if (id->ill_flags & DCMD_ADDRSPEC && id->ill_addr != addr)
		return (WALK_NEXT);

	if (id->ill_flags & DCMD_PIPE_OUT) {
		mdb_printf("%p\n", addr);
		return (WALK_NEXT);
	}

	switch (iw->ill_list) {
		case IP_V4_G_HEAD:	version = "v4";	break;
		case IP_V6_G_HEAD:	version = "v6";	break;
		default:		version = "??"; break;
	}

	mdb_printf("%?p %2s %?p %10d %?p %s\n",
	    addr, version, addr + offsetof(ill_if_t, illif_avl_by_ppa),
	    iw->ill_if.illif_avl_by_ppa.avl_numnodes,
	    iw->ill_if.illif_ppa_arena, iw->ill_if.illif_name);

	id->ill_printed = TRUE;

	return (WALK_NEXT);
}

int
ip_stacks_common_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("ip_stacks", wsp) == -1) {
		mdb_warn("can't walk 'ip_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
illif_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;

	kaddr = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ill_g_heads);

	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr);
		return (WALK_ERR);
	}

	if (mdb_pwalk("illif_stack", wsp->walk_callback,
	    wsp->walk_cbdata, kaddr) == -1) {
		mdb_warn("couldn't walk 'illif_stack' for ips_ill_g_heads %p",
		    kaddr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
illif(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	illif_cbdata_t id;
	ill_if_t ill_if;
	const char *opt_P = NULL;
	int printlist = MAX_G_HEADS;

	if (mdb_getopts(argc, argv,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			printlist = IP_V4_G_HEAD;
		} else if (strcmp("v6", opt_P) == 0) {
			printlist = IP_V6_G_HEAD;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	if (DCMD_HDRSPEC(flags) && (flags & DCMD_PIPE_OUT) == 0) {
		mdb_printf("%<u>%?s %2s %?s %10s %?s %-10s%</u>\n",
		    "ADDR", "IP", "AVLADDR", "NUMNODES", "ARENA", "NAME");
	}

	id.ill_flags = flags;
	id.ill_addr = addr;
	id.ill_printlist = printlist;
	id.ill_printed = FALSE;

	if (mdb_walk("illif", (mdb_walk_cb_t)illif_cb, &id) == -1) {
		mdb_warn("can't walk ill_if_t structures");
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_ADDRSPEC) || opt_P != NULL || id.ill_printed)
		return (DCMD_OK);

	/*
	 * If an address is specified and the walk doesn't find it,
	 * print it anyway.
	 */
	if (mdb_vread(&ill_if, sizeof (ill_if_t), addr) == -1) {
		mdb_warn("failed to read ill_if_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p %2s %?p %10d %?p %s\n",
	    addr, "??", addr + offsetof(ill_if_t, illif_avl_by_ppa),
	    ill_if.illif_avl_by_ppa.avl_numnodes,
	    ill_if.illif_ppa_arena, ill_if.illif_name);

	return (DCMD_OK);
}

static void
illif_help(void)
{
	mdb_printf("Options:\n");
	mdb_printf("\t-P v4 | v6"
	    "\tfilter interface structures for the specified protocol\n");
}

int
nce_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("nce_cache", wsp) == -1) {
		mdb_warn("can't walk 'nce_cache'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nce_walk_step(mdb_walk_state_t *wsp)
{
	nce_t nce;

	if (mdb_vread(&nce, sizeof (nce), wsp->walk_addr) == -1) {
		mdb_warn("can't read nce at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	return (wsp->walk_callback(wsp->walk_addr, &nce, wsp->walk_cbdata));
}

static int
nce_format(uintptr_t addr, const nce_t *ncep, void *nce_cb_arg)
{
	nce_cbdata_t *nce_cb = nce_cb_arg;
	ill_t ill;
	char ill_name[LIFNAMSIZ];
	ncec_t ncec;

	if (mdb_vread(&ncec, sizeof (ncec),
	    (uintptr_t)ncep->nce_common) == -1) {
		mdb_warn("can't read ncec at %p", ncep->nce_common);
		return (WALK_NEXT);
	}
	if (nce_cb->nce_ipversion != 0 &&
	    ncec.ncec_ipversion != nce_cb->nce_ipversion)
		return (WALK_NEXT);

	if (mdb_vread(&ill, sizeof (ill), (uintptr_t)ncep->nce_ill) == -1) {
		mdb_snprintf(ill_name, sizeof (ill_name), "--");
	} else {
		(void) mdb_readstr(ill_name,
		    MIN(LIFNAMSIZ, ill.ill_name_length),
		    (uintptr_t)ill.ill_name);
	}

	if (nce_cb->nce_ill_name[0] != '\0' &&
	    strncmp(nce_cb->nce_ill_name, ill_name, LIFNAMSIZ) != 0)
		return (WALK_NEXT);

	if (ncec.ncec_ipversion == IPV6_VERSION) {

		mdb_printf("%?p %5s %-18s %?p %6d %N\n",
		    addr, ill_name,
		    nce_l2_addr(ncep, &ill),
		    ncep->nce_fp_mp,
		    ncep->nce_refcnt,
		    &ncep->nce_addr);

	} else {
		struct in_addr nceaddr;

		IN6_V4MAPPED_TO_INADDR(&ncep->nce_addr, &nceaddr);
		mdb_printf("%?p %5s %-18s %?p %6d %I\n",
		    addr, ill_name,
		    nce_l2_addr(ncep, &ill),
		    ncep->nce_fp_mp,
		    ncep->nce_refcnt,
		    nceaddr.s_addr);
	}

	return (WALK_NEXT);
}

int
dce_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = (void *)wsp->walk_addr;

	if (mdb_layered_walk("dce_cache", wsp) == -1) {
		mdb_warn("can't walk 'dce_cache'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
dce_walk_step(mdb_walk_state_t *wsp)
{
	dce_t dce;

	if (mdb_vread(&dce, sizeof (dce), wsp->walk_addr) == -1) {
		mdb_warn("can't read dce at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* If ip_stack_t is specified, skip DCEs that don't belong to it. */
	if ((wsp->walk_data != NULL) && (wsp->walk_data != dce.dce_ipst))
		return (WALK_NEXT);

	return (wsp->walk_callback(wsp->walk_addr, &dce, wsp->walk_cbdata));
}

int
ire_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = (void *)wsp->walk_addr;

	if (mdb_layered_walk("ire_cache", wsp) == -1) {
		mdb_warn("can't walk 'ire_cache'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
ire_walk_step(mdb_walk_state_t *wsp)
{
	ire_t ire;

	if (mdb_vread(&ire, sizeof (ire), wsp->walk_addr) == -1) {
		mdb_warn("can't read ire at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	/* If ip_stack_t is specified, skip IREs that don't belong to it. */
	if ((wsp->walk_data != NULL) && (wsp->walk_data != ire.ire_ipst))
		return (WALK_NEXT);

	return (wsp->walk_callback(wsp->walk_addr, &ire, wsp->walk_cbdata));
}

/* ARGSUSED */
int
ire_next_walk_init(mdb_walk_state_t *wsp)
{
	return (WALK_NEXT);
}

int
ire_next_walk_step(mdb_walk_state_t *wsp)
{
	ire_t ire;
	int status;


	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&ire, sizeof (ire), wsp->walk_addr) == -1) {
		mdb_warn("can't read ire at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(wsp->walk_addr, &ire,
	    wsp->walk_cbdata);

	if (status != WALK_NEXT)
		return (status);

	wsp->walk_addr = (uintptr_t)ire.ire_next;
	return (status);
}

static int
ire_format(uintptr_t addr, const void *ire_arg, void *ire_cb_arg)
{
	const ire_t *irep = ire_arg;
	ire_cbdata_t *ire_cb = ire_cb_arg;
	boolean_t verbose = ire_cb->verbose;
	ill_t ill;
	char ill_name[LIFNAMSIZ];
	boolean_t condemned = irep->ire_generation == IRE_GENERATION_CONDEMNED;

	static const mdb_bitmask_t tmasks[] = {
		{ "BROADCAST",	IRE_BROADCAST,		IRE_BROADCAST	},
		{ "DEFAULT",	IRE_DEFAULT,		IRE_DEFAULT	},
		{ "LOCAL",	IRE_LOCAL,		IRE_LOCAL	},
		{ "LOOPBACK",	IRE_LOOPBACK,		IRE_LOOPBACK	},
		{ "PREFIX",	IRE_PREFIX,		IRE_PREFIX	},
		{ "MULTICAST",	IRE_MULTICAST,		IRE_MULTICAST	},
		{ "NOROUTE",	IRE_NOROUTE,		IRE_NOROUTE	},
		{ "IF_NORESOLVER", IRE_IF_NORESOLVER,	IRE_IF_NORESOLVER },
		{ "IF_RESOLVER", IRE_IF_RESOLVER,	IRE_IF_RESOLVER	},
		{ "IF_CLONE",	IRE_IF_CLONE,		IRE_IF_CLONE	},
		{ "HOST",	IRE_HOST,		IRE_HOST	},
		{ NULL,		0,			0		}
	};

	static const mdb_bitmask_t fmasks[] = {
		{ "UP",		RTF_UP,			RTF_UP		},
		{ "GATEWAY",	RTF_GATEWAY,		RTF_GATEWAY	},
		{ "HOST",	RTF_HOST,		RTF_HOST	},
		{ "REJECT",	RTF_REJECT,		RTF_REJECT	},
		{ "DYNAMIC",	RTF_DYNAMIC,		RTF_DYNAMIC	},
		{ "MODIFIED",	RTF_MODIFIED,		RTF_MODIFIED	},
		{ "DONE",	RTF_DONE,		RTF_DONE	},
		{ "MASK",	RTF_MASK,		RTF_MASK	},
		{ "CLONING",	RTF_CLONING,		RTF_CLONING	},
		{ "XRESOLVE",	RTF_XRESOLVE,		RTF_XRESOLVE	},
		{ "LLINFO",	RTF_LLINFO,		RTF_LLINFO	},
		{ "STATIC",	RTF_STATIC,		RTF_STATIC	},
		{ "BLACKHOLE",	RTF_BLACKHOLE,		RTF_BLACKHOLE	},
		{ "PRIVATE",	RTF_PRIVATE,		RTF_PRIVATE	},
		{ "PROTO2",	RTF_PROTO2,		RTF_PROTO2	},
		{ "PROTO1",	RTF_PROTO1,		RTF_PROTO1	},
		{ "MULTIRT",	RTF_MULTIRT,		RTF_MULTIRT	},
		{ "SETSRC",	RTF_SETSRC,		RTF_SETSRC	},
		{ "INDIRECT",	RTF_INDIRECT,		RTF_INDIRECT	},
		{ NULL,		0,			0		}
	};

	if (ire_cb->ire_ipversion != 0 &&
	    irep->ire_ipversion != ire_cb->ire_ipversion)
		return (WALK_NEXT);

	if (mdb_vread(&ill, sizeof (ill), (uintptr_t)irep->ire_ill) == -1) {
		mdb_snprintf(ill_name, sizeof (ill_name), "--");
	} else {
		(void) mdb_readstr(ill_name,
		    MIN(LIFNAMSIZ, ill.ill_name_length),
		    (uintptr_t)ill.ill_name);
	}

	if (irep->ire_ipversion == IPV6_VERSION && verbose) {

		mdb_printf("%<b>%?p%</b>%3s %40N <%hb%s>\n"
		    "%?s %40N\n"
		    "%?s %40d %4d <%hb> %s\n",
		    addr, condemned ? "(C)" : "", &irep->ire_setsrc_addr_v6,
		    irep->ire_type, tmasks,
		    (irep->ire_testhidden ? ", HIDDEN" : ""),
		    "", &irep->ire_addr_v6,
		    "", ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid,
		    irep->ire_flags, fmasks, ill_name);

	} else if (irep->ire_ipversion == IPV6_VERSION) {

		mdb_printf("%?p%3s %30N %30N %5d %4d %s\n",
		    addr, condemned ? "(C)" : "", &irep->ire_setsrc_addr_v6,
		    &irep->ire_addr_v6,
		    ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid, ill_name);

	} else if (verbose) {

		mdb_printf("%<b>%?p%</b>%3s %40I <%hb%s>\n"
		    "%?s %40I\n"
		    "%?s %40d %4d <%hb> %s\n",
		    addr, condemned ? "(C)" : "", irep->ire_setsrc_addr,
		    irep->ire_type, tmasks,
		    (irep->ire_testhidden ? ", HIDDEN" : ""),
		    "", irep->ire_addr,
		    "", ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid, irep->ire_flags, fmasks, ill_name);

	} else {

		mdb_printf("%?p%3s %30I %30I %5d %4d %s\n", addr,
		    condemned ? "(C)" : "", irep->ire_setsrc_addr,
		    irep->ire_addr, ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid, ill_name);
	}

	return (WALK_NEXT);
}

/*
 * There are faster ways to do this.  Given the interactive nature of this
 * use I don't think its worth much effort.
 */
static unsigned short
ipcksum(void *p, int len)
{
	int32_t	sum = 0;

	while (len > 1) {
		/* alignment */
		sum += *(uint16_t *)p;
		p = (char *)p + sizeof (uint16_t);
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)
		sum += (uint16_t)*(unsigned char *)p;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (~sum);
}

static const mdb_bitmask_t tcp_flags[] = {
	{ "SYN",	TH_SYN,		TH_SYN	},
	{ "ACK",	TH_ACK,		TH_ACK	},
	{ "FIN",	TH_FIN,		TH_FIN	},
	{ "RST",	TH_RST,		TH_RST	},
	{ "PSH",	TH_PUSH,	TH_PUSH	},
	{ "ECE",	TH_ECE,		TH_ECE	},
	{ "CWR",	TH_CWR,		TH_CWR	},
	{ NULL,		0,		0	}
};

/* TCP option length */
#define	TCPOPT_HEADER_LEN	2
#define	TCPOPT_MAXSEG_LEN	4
#define	TCPOPT_WS_LEN		3
#define	TCPOPT_TSTAMP_LEN	10
#define	TCPOPT_SACK_OK_LEN	2

static void
tcphdr_print_options(uint8_t *opts, uint32_t opts_len)
{
	uint8_t *endp;
	uint32_t len, val;

	mdb_printf("%<b>Options:%</b>");
	endp = opts + opts_len;
	while (opts < endp) {
		len = endp - opts;
		switch (*opts) {
		case TCPOPT_EOL:
			mdb_printf(" EOL");
			opts++;
			break;

		case TCPOPT_NOP:
			mdb_printf(" NOP");
			opts++;
			break;

		case TCPOPT_MAXSEG: {
			uint16_t mss;

			if (len < TCPOPT_MAXSEG_LEN ||
			    opts[1] != TCPOPT_MAXSEG_LEN) {
				mdb_printf(" <Truncated MSS>\n");
				return;
			}
			mdb_nhconvert(&mss, opts + TCPOPT_HEADER_LEN,
			    sizeof (mss));
			mdb_printf(" MSS=%u", mss);
			opts += TCPOPT_MAXSEG_LEN;
			break;
		}

		case TCPOPT_WSCALE:
			if (len < TCPOPT_WS_LEN || opts[1] != TCPOPT_WS_LEN) {
				mdb_printf(" <Truncated WS>\n");
				return;
			}
			mdb_printf(" WS=%u", opts[2]);
			opts += TCPOPT_WS_LEN;
			break;

		case TCPOPT_TSTAMP: {
			if (len < TCPOPT_TSTAMP_LEN ||
			    opts[1] != TCPOPT_TSTAMP_LEN) {
				mdb_printf(" <Truncated TS>\n");
				return;
			}

			opts += TCPOPT_HEADER_LEN;
			mdb_nhconvert(&val, opts, sizeof (val));
			mdb_printf(" TS_VAL=%u,", val);

			opts += sizeof (val);
			mdb_nhconvert(&val, opts, sizeof (val));
			mdb_printf("TS_ECHO=%u", val);

			opts += sizeof (val);
			break;
		}

		case TCPOPT_SACK_PERMITTED:
			if (len < TCPOPT_SACK_OK_LEN ||
			    opts[1] != TCPOPT_SACK_OK_LEN) {
				mdb_printf(" <Truncated SACK_OK>\n");
				return;
			}
			mdb_printf(" SACK_OK");
			opts += TCPOPT_SACK_OK_LEN;
			break;

		case TCPOPT_SACK: {
			uint32_t sack_len;

			if (len <= TCPOPT_HEADER_LEN || len < opts[1] ||
			    opts[1] <= TCPOPT_HEADER_LEN) {
				mdb_printf(" <Truncated SACK>\n");
				return;
			}
			sack_len = opts[1] - TCPOPT_HEADER_LEN;
			opts += TCPOPT_HEADER_LEN;

			mdb_printf(" SACK=");
			while (sack_len > 0) {
				if (opts + 2 * sizeof (val) > endp) {
					mdb_printf("<Truncated SACK>\n");
					opts = endp;
					break;
				}

				mdb_nhconvert(&val, opts, sizeof (val));
				mdb_printf("<%u,", val);
				opts += sizeof (val);
				mdb_nhconvert(&val, opts, sizeof (val));
				mdb_printf("%u>", val);
				opts += sizeof (val);

				sack_len -= 2 * sizeof (val);
			}
			break;
		}

		default:
			mdb_printf(" Opts=<val=%u,len=%u>", *opts,
			    opts[1]);
			opts += opts[1];
			break;
		}
	}
	mdb_printf("\n");
}

static void
tcphdr_print(struct tcphdr *tcph)
{
	in_port_t	sport, dport;
	tcp_seq		seq, ack;
	uint16_t	win, urp;

	mdb_printf("%<b>TCP header%</b>\n");

	mdb_nhconvert(&sport, &tcph->th_sport, sizeof (sport));
	mdb_nhconvert(&dport, &tcph->th_dport, sizeof (dport));
	mdb_nhconvert(&seq, &tcph->th_seq, sizeof (seq));
	mdb_nhconvert(&ack, &tcph->th_ack, sizeof (ack));
	mdb_nhconvert(&win, &tcph->th_win, sizeof (win));
	mdb_nhconvert(&urp, &tcph->th_urp, sizeof (urp));

	mdb_printf("%<u>%6s %6s %10s %10s %4s %5s %5s %5s %-15s%</u>\n",
	    "SPORT", "DPORT", "SEQ", "ACK", "HLEN", "WIN", "CSUM", "URP",
	    "FLAGS");
	mdb_printf("%6hu %6hu %10u %10u %4d %5hu %5hu %5hu <%b>\n",
	    sport, dport, seq, ack, tcph->th_off << 2, win,
	    tcph->th_sum, urp, tcph->th_flags, tcp_flags);
	mdb_printf("0x%04x 0x%04x 0x%08x 0x%08x\n\n",
	    sport, dport, seq, ack);
}

/* ARGSUSED */
static int
tcphdr(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	struct tcphdr	tcph;
	uint32_t	opt_len;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&tcph, sizeof (tcph), addr) == -1) {
		mdb_warn("failed to read TCP header at %p", addr);
		return (DCMD_ERR);
	}
	tcphdr_print(&tcph);

	/* If there are options, print them out also. */
	opt_len = (tcph.th_off << 2) - TCP_MIN_HEADER_LENGTH;
	if (opt_len > 0) {
		uint8_t *opts, *opt_buf;

		opt_buf = mdb_alloc(opt_len, UM_SLEEP);
		opts = (uint8_t *)addr + sizeof (tcph);
		if (mdb_vread(opt_buf, opt_len, (uintptr_t)opts) == -1) {
			mdb_warn("failed to read TCP options at %p", opts);
			return (DCMD_ERR);
		}
		tcphdr_print_options(opt_buf, opt_len);
		mdb_free(opt_buf, opt_len);
	}

	return (DCMD_OK);
}

static void
udphdr_print(struct udphdr *udph)
{
	in_port_t	sport, dport;
	uint16_t	hlen;

	mdb_printf("%<b>UDP header%</b>\n");

	mdb_nhconvert(&sport, &udph->uh_sport, sizeof (sport));
	mdb_nhconvert(&dport, &udph->uh_dport, sizeof (dport));
	mdb_nhconvert(&hlen, &udph->uh_ulen, sizeof (hlen));

	mdb_printf("%<u>%14s %14s %5s %6s%</u>\n",
	    "SPORT", "DPORT", "LEN", "CSUM");
	mdb_printf("%5hu (0x%04x) %5hu (0x%04x) %5hu 0x%04hx\n\n", sport, sport,
	    dport, dport, hlen, udph->uh_sum);
}

/* ARGSUSED */
static int
udphdr(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	struct udphdr	udph;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&udph, sizeof (udph), addr) == -1) {
		mdb_warn("failed to read UDP header at %p", addr);
		return (DCMD_ERR);
	}
	udphdr_print(&udph);
	return (DCMD_OK);
}

static void
sctphdr_print(sctp_hdr_t *sctph)
{
	in_port_t sport, dport;

	mdb_printf("%<b>SCTP header%</b>\n");
	mdb_nhconvert(&sport, &sctph->sh_sport, sizeof (sport));
	mdb_nhconvert(&dport, &sctph->sh_dport, sizeof (dport));

	mdb_printf("%<u>%14s %14s %10s %10s%</u>\n",
	    "SPORT", "DPORT", "VTAG", "CHKSUM");
	mdb_printf("%5hu (0x%04x) %5hu (0x%04x) %10u 0x%08x\n\n", sport, sport,
	    dport, dport, sctph->sh_verf, sctph->sh_chksum);
}

/* ARGSUSED */
static int
sctphdr(uintptr_t addr, uint_t flags, int ac, const mdb_arg_t *av)
{
	sctp_hdr_t sctph;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&sctph, sizeof (sctph), addr) == -1) {
		mdb_warn("failed to read SCTP header at %p", addr);
		return (DCMD_ERR);
	}

	sctphdr_print(&sctph);
	return (DCMD_OK);
}

static int
transport_hdr(int proto, uintptr_t addr)
{
	mdb_printf("\n");
	switch (proto) {
	case IPPROTO_TCP: {
		struct tcphdr tcph;

		if (mdb_vread(&tcph, sizeof (tcph), addr) == -1) {
			mdb_warn("failed to read TCP header at %p", addr);
			return (DCMD_ERR);
		}
		tcphdr_print(&tcph);
		break;
	}
	case IPPROTO_UDP:  {
		struct udphdr udph;

		if (mdb_vread(&udph, sizeof (udph), addr) == -1) {
			mdb_warn("failed to read UDP header at %p", addr);
			return (DCMD_ERR);
		}
		udphdr_print(&udph);
		break;
	}
	case IPPROTO_SCTP: {
		sctp_hdr_t sctph;

		if (mdb_vread(&sctph, sizeof (sctph), addr) == -1) {
			mdb_warn("failed to read SCTP header at %p", addr);
			return (DCMD_ERR);
		}
		sctphdr_print(&sctph);
		break;
	}
	default:
		break;
	}

	return (DCMD_OK);
}

static const mdb_bitmask_t ip_flags[] = {
	{ "DF",	IPH_DF, IPH_DF	},
	{ "MF", IPH_MF,	IPH_MF	},
	{ NULL, 0,	0	}
};

/* ARGSUSED */
static int
iphdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE, force = FALSE;
	ipha_t		iph[1];
	uint16_t	ver, totlen, hdrlen, ipid, off, csum;
	uintptr_t	nxt_proto;
	char		exp_csum[8];

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'f', MDB_OPT_SETBITS, TRUE, &force, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(iph, sizeof (*iph), addr) == -1) {
		mdb_warn("failed to read IPv4 header at %p", addr);
		return (DCMD_ERR);
	}

	ver = (iph->ipha_version_and_hdr_length & 0xf0) >> 4;
	if (ver != IPV4_VERSION) {
		if (ver == IPV6_VERSION) {
			return (ip6hdr(addr, flags, argc, argv));
		} else if (!force) {
			mdb_warn("unknown IP version: %d\n", ver);
			return (DCMD_ERR);
		}
	}

	mdb_printf("%<b>IPv4 header%</b>\n");
	mdb_printf("%-34s %-34s\n"
	    "%<u>%-4s %-4s %-5s %-5s %-6s %-5s %-5s %-6s %-8s %-6s%</u>\n",
	    "SRC", "DST",
	    "HLEN", "TOS", "LEN", "ID", "OFFSET", "TTL", "PROTO", "CHKSUM",
	    "EXP-CSUM", "FLGS");

	hdrlen = (iph->ipha_version_and_hdr_length & 0x0f) << 2;
	mdb_nhconvert(&totlen, &iph->ipha_length, sizeof (totlen));
	mdb_nhconvert(&ipid, &iph->ipha_ident, sizeof (ipid));
	mdb_nhconvert(&off, &iph->ipha_fragment_offset_and_flags, sizeof (off));
	if (hdrlen == IP_SIMPLE_HDR_LENGTH) {
		if ((csum = ipcksum(iph, sizeof (*iph))) != 0)
			csum = ~(~csum + ~iph->ipha_hdr_checksum);
		else
			csum = iph->ipha_hdr_checksum;
		mdb_snprintf(exp_csum, 8, "%u", csum);
	} else {
		mdb_snprintf(exp_csum, 8, "<n/a>");
	}

	mdb_printf("%-34I %-34I%\n"
	    "%-4d %-4d %-5hu %-5hu %-6hu %-5hu %-5hu %-6u %-8s <%5hb>\n",
	    iph->ipha_src, iph->ipha_dst,
	    hdrlen, iph->ipha_type_of_service, totlen, ipid,
	    (off << 3) & 0xffff, iph->ipha_ttl, iph->ipha_protocol,
	    iph->ipha_hdr_checksum, exp_csum, off, ip_flags);

	if (verbose) {
		nxt_proto = addr + hdrlen;
		return (transport_hdr(iph->ipha_protocol, nxt_proto));
	} else {
		return (DCMD_OK);
	}
}

/* ARGSUSED */
static int
ip6hdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		verbose = FALSE, force = FALSE;
	ip6_t		iph[1];
	int		ver, class, flow;
	uint16_t	plen;
	uintptr_t	nxt_proto;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'f', MDB_OPT_SETBITS, TRUE, &force, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(iph, sizeof (*iph), addr) == -1) {
		mdb_warn("failed to read IPv6 header at %p", addr);
		return (DCMD_ERR);
	}

	ver = (iph->ip6_vfc & 0xf0) >> 4;
	if (ver != IPV6_VERSION) {
		if (ver == IPV4_VERSION) {
			return (iphdr(addr, flags, argc, argv));
		} else if (!force) {
			mdb_warn("unknown IP version: %d\n", ver);
			return (DCMD_ERR);
		}
	}

	mdb_printf("%<b>IPv6 header%</b>\n");
	mdb_printf("%<u>%-26s %-26s %4s %7s %5s %3s %3s%</u>\n",
	    "SRC", "DST", "TCLS", "FLOW-ID", "PLEN", "NXT", "HOP");

	class = (iph->ip6_vcf & IPV6_FLOWINFO_TCLASS) >> 20;
	mdb_nhconvert(&class, &class, sizeof (class));
	flow = iph->ip6_vcf & IPV6_FLOWINFO_FLOWLABEL;
	mdb_nhconvert(&flow, &flow, sizeof (flow));
	mdb_nhconvert(&plen, &iph->ip6_plen, sizeof (plen));

	mdb_printf("%-26N %-26N %4d %7d %5hu %3d %3d\n",
	    &iph->ip6_src, &iph->ip6_dst,
	    class, flow, plen, iph->ip6_nxt, iph->ip6_hlim);

	if (verbose) {
		nxt_proto = addr + sizeof (ip6_t);
		return (transport_hdr(iph->ip6_nxt, nxt_proto));
	} else {
		return (DCMD_OK);
	}
}

int
nce(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nce_t nce;
	nce_cbdata_t nce_cb;
	int ipversion = 0;
	const char *opt_P = NULL, *opt_ill = NULL;

	if (mdb_getopts(argc, argv,
	    'i', MDB_OPT_STR, &opt_ill,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %5s %18s %?s %s %s %</u>\n",
		    "ADDR", "INTF", "LLADDR", "FP_MP", "REFCNT",
		    "NCE_ADDR");
	}

	bzero(&nce_cb, sizeof (nce_cb));
	if (opt_ill != NULL) {
		strcpy(nce_cb.nce_ill_name, opt_ill);
	}
	nce_cb.nce_ipversion = ipversion;

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&nce, sizeof (nce_t), addr);
		(void) nce_format(addr, &nce, &nce_cb);
	} else if (mdb_walk("nce", (mdb_walk_cb_t)nce_format, &nce_cb) == -1) {
		mdb_warn("failed to walk ire table");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/* ARGSUSED */
static int
dce_format(uintptr_t addr, const dce_t *dcep, void *dce_cb_arg)
{
	static const mdb_bitmask_t dmasks[] = {
		{ "D",	DCEF_DEFAULT,		DCEF_DEFAULT },
		{ "P",	DCEF_PMTU,		DCEF_PMTU },
		{ "U",	DCEF_UINFO,		DCEF_UINFO },
		{ "S",	DCEF_TOO_SMALL_PMTU,	DCEF_TOO_SMALL_PMTU },
		{ NULL,	0,			0		}
	};
	char flagsbuf[2 * A_CNT(dmasks)];
	int ipversion = *(int *)dce_cb_arg;
	boolean_t condemned = dcep->dce_generation == DCE_GENERATION_CONDEMNED;

	if (ipversion != 0 && ipversion != dcep->dce_ipversion)
		return (WALK_NEXT);

	mdb_snprintf(flagsbuf, sizeof (flagsbuf), "%b", dcep->dce_flags,
	    dmasks);

	switch (dcep->dce_ipversion) {
	case IPV4_VERSION:
		mdb_printf("%<u>%?p%3s %8s %8d %30I %</u>\n", addr, condemned ?
		    "(C)" : "", flagsbuf, dcep->dce_pmtu, &dcep->dce_v4addr);
		break;
	case IPV6_VERSION:
		mdb_printf("%<u>%?p%3s %8s %8d %30N %</u>\n", addr, condemned ?
		    "(C)" : "", flagsbuf, dcep->dce_pmtu, &dcep->dce_v6addr);
		break;
	default:
		mdb_printf("%<u>%?p%3s %8s %8d %30s %</u>\n", addr, condemned ?
		    "(C)" : "", flagsbuf, dcep->dce_pmtu, "");
	}

	return (WALK_NEXT);
}

int
dce(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dce_t dce;
	const char *opt_P = NULL;
	const char *zone_name = NULL;
	ip_stack_t *ipst = NULL;
	int ipversion = 0;

	if (mdb_getopts(argc, argv,
	    's', MDB_OPT_STR, &zone_name,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	/* Follow the specified zone name to find a ip_stack_t*. */
	if (zone_name != NULL) {
		ipst = zone_to_ips(zone_name);
		if (ipst == NULL)
			return (DCMD_USAGE);
	}

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s%3s %8s %8s %30s %</u>\n",
		    "ADDR", "", "FLAGS", "PMTU", "DST_ADDR");
	}

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&dce, sizeof (dce_t), addr);
		(void) dce_format(addr, &dce, &ipversion);
	} else if (mdb_pwalk("dce", (mdb_walk_cb_t)dce_format, &ipversion,
	    (uintptr_t)ipst) == -1) {
		mdb_warn("failed to walk dce cache");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

int
ire(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	ire_t ire;
	ire_cbdata_t ire_cb;
	int ipversion = 0;
	const char *opt_P = NULL;
	const char *zone_name = NULL;
	ip_stack_t *ipst = NULL;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    's', MDB_OPT_STR, &zone_name,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	/* Follow the specified zone name to find a ip_stack_t*. */
	if (zone_name != NULL) {
		ipst = zone_to_ips(zone_name);
		if (ipst == NULL)
			return (DCMD_USAGE);
	}

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {

		if (verbose) {
			mdb_printf("%?s %40s %-20s%\n"
			    "%?s %40s %-20s%\n"
			    "%<u>%?s %40s %4s %-20s %s%</u>\n",
			    "ADDR", "SRC", "TYPE",
			    "", "DST", "MARKS",
			    "", "STACK", "ZONE", "FLAGS", "INTF");
		} else {
			mdb_printf("%<u>%?s %30s %30s %5s %4s %s%</u>\n",
			    "ADDR", "SRC", "DST", "STACK", "ZONE", "INTF");
		}
	}

	ire_cb.verbose = (verbose == TRUE);
	ire_cb.ire_ipversion = ipversion;

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&ire, sizeof (ire_t), addr);
		(void) ire_format(addr, &ire, &ire_cb);
	} else if (mdb_pwalk("ire", (mdb_walk_cb_t)ire_format, &ire_cb,
	    (uintptr_t)ipst) == -1) {
		mdb_warn("failed to walk ire table");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static size_t
mi_osize(const queue_t *q)
{
	/*
	 * The code in common/inet/mi.c allocates an extra word to store the
	 * size of the allocation.  An mi_o_s is thus a size_t plus an mi_o_s.
	 */
	struct mi_block {
		size_t mi_nbytes;
		struct mi_o_s mi_o;
	} m;

	if (mdb_vread(&m, sizeof (m), (uintptr_t)q->q_ptr -
	    sizeof (m)) == sizeof (m))
		return (m.mi_nbytes - sizeof (m));

	return (0);
}

static void
ip_ill_qinfo(const queue_t *q, char *buf, size_t nbytes)
{
	char name[32];
	ill_t ill;

	if (mdb_vread(&ill, sizeof (ill),
	    (uintptr_t)q->q_ptr) == sizeof (ill) &&
	    mdb_readstr(name, sizeof (name), (uintptr_t)ill.ill_name) > 0)
		(void) mdb_snprintf(buf, nbytes, "if: %s", name);
}

void
ip_qinfo(const queue_t *q, char *buf, size_t nbytes)
{
	size_t size = mi_osize(q);

	if (size == sizeof (ill_t))
		ip_ill_qinfo(q, buf, nbytes);
}

uintptr_t
ip_rnext(const queue_t *q)
{
	size_t size = mi_osize(q);
	ill_t ill;

	if (size == sizeof (ill_t) && mdb_vread(&ill, sizeof (ill),
	    (uintptr_t)q->q_ptr) == sizeof (ill))
		return ((uintptr_t)ill.ill_rq);

	return (NULL);
}

uintptr_t
ip_wnext(const queue_t *q)
{
	size_t size = mi_osize(q);
	ill_t ill;

	if (size == sizeof (ill_t) && mdb_vread(&ill, sizeof (ill),
	    (uintptr_t)q->q_ptr) == sizeof (ill))
		return ((uintptr_t)ill.ill_wq);

	return (NULL);
}

/*
 * Print the core fields in an squeue_t.  With the "-v" argument,
 * provide more verbose output.
 */
static int
squeue(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	unsigned int	i;
	unsigned int	verbose = FALSE;
	const int	SQUEUE_STATEDELT = (int)(sizeof (uintptr_t) + 9);
	boolean_t	arm;
	squeue_t	squeue;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("genunix`squeue_cache", "ip`squeue",
		    argc, argv) == -1) {
			mdb_warn("failed to walk squeue cache");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL)
	    != argc)
		return (DCMD_USAGE);

	if (!DCMD_HDRSPEC(flags) && verbose)
		mdb_printf("\n\n");

	if (DCMD_HDRSPEC(flags) || verbose) {
		mdb_printf("%?s %-5s %-3s %?s %?s %?s\n",
		    "ADDR", "STATE", "CPU",
		    "FIRST", "LAST", "WORKER");
	}

	if (mdb_vread(&squeue, sizeof (squeue_t), addr) == -1) {
		mdb_warn("cannot read squeue_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %05x %3d %0?p %0?p %0?p\n",
	    addr, squeue.sq_state, squeue.sq_bind,
	    squeue.sq_first, squeue.sq_last, squeue.sq_worker);

	if (!verbose)
		return (DCMD_OK);

	arm = B_TRUE;
	for (i = 0; squeue_states[i].bit_name != NULL; i++) {
		if (((squeue.sq_state) & (1 << i)) == 0)
			continue;

		if (arm) {
			mdb_printf("%*s|\n", SQUEUE_STATEDELT, "");
			mdb_printf("%*s+-->  ", SQUEUE_STATEDELT, "");
			arm = B_FALSE;
		} else
			mdb_printf("%*s      ", SQUEUE_STATEDELT, "");

		mdb_printf("%-12s %s\n", squeue_states[i].bit_name,
		    squeue_states[i].bit_descr);
	}

	return (DCMD_OK);
}

static void
ip_squeue_help(void)
{
	mdb_printf("Print the core information for a given NCA squeue_t.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-v\tbe verbose (more descriptive)\n");
}

/*
 * This is called by ::th_trace (via a callback) when walking the th_hash
 * list.  It calls modent to find the entries.
 */
/* ARGSUSED */
static int
modent_summary(uintptr_t addr, const void *data, void *private)
{
	th_walk_data_t *thw = private;
	const struct mod_hash_entry *mhe = data;
	th_trace_t th;

	if (mdb_vread(&th, sizeof (th), (uintptr_t)mhe->mhe_val) == -1) {
		mdb_warn("failed to read th_trace_t %p", mhe->mhe_val);
		return (WALK_ERR);
	}

	if (th.th_refcnt == 0 && thw->thw_non_zero_only)
		return (WALK_NEXT);

	if (!thw->thw_match) {
		mdb_printf("%?p %?p %?p %8d %?p\n", thw->thw_ipst, mhe->mhe_key,
		    mhe->mhe_val, th.th_refcnt, th.th_id);
	} else if (thw->thw_matchkey == (uintptr_t)mhe->mhe_key) {
		int i, j, k;
		tr_buf_t *tr;

		mdb_printf("Object %p in IP stack %p:\n", mhe->mhe_key,
		    thw->thw_ipst);
		i = th.th_trace_lastref;
		mdb_printf("\tThread %p refcnt %d:\n", th.th_id,
		    th.th_refcnt);
		for (j = TR_BUF_MAX; j > 0; j--) {
			tr = th.th_trbuf + i;
			if (tr->tr_depth == 0 || tr->tr_depth > TR_STACK_DEPTH)
				break;
			mdb_printf("\t  T%+ld:\n", tr->tr_time -
			    thw->thw_lbolt);
			for (k = 0; k < tr->tr_depth; k++)
				mdb_printf("\t\t%a\n", tr->tr_stack[k]);
			if (--i < 0)
				i = TR_BUF_MAX - 1;
		}
	}
	return (WALK_NEXT);
}

/*
 * This is called by ::th_trace (via a callback) when walking the th_hash
 * list.  It calls modent to find the entries.
 */
/* ARGSUSED */
static int
th_hash_summary(uintptr_t addr, const void *data, void *private)
{
	const th_hash_t *thh = data;
	th_walk_data_t *thw = private;

	thw->thw_ipst = (uintptr_t)thh->thh_ipst;
	return (mdb_pwalk("modent", modent_summary, private,
	    (uintptr_t)thh->thh_hash));
}

/*
 * Print or summarize the th_trace_t structures.
 */
static int
th_trace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	th_walk_data_t thw;

	(void) memset(&thw, 0, sizeof (thw));

	if (mdb_getopts(argc, argv,
	    'n', MDB_OPT_SETBITS, TRUE, &thw.thw_non_zero_only,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		/*
		 * No address specified.  Walk all of the th_hash_t in the
		 * system, and summarize the th_trace_t entries in each.
		 */
		mdb_printf("%?s %?s %?s %8s %?s\n",
		    "IPSTACK", "OBJECT", "TRACE", "REFCNT", "THREAD");
		thw.thw_match = B_FALSE;
	} else {
		thw.thw_match = B_TRUE;
		thw.thw_matchkey = addr;

		if ((thw.thw_lbolt = (clock_t)mdb_get_lbolt()) == -1) {
			mdb_warn("failed to read lbolt");
			return (DCMD_ERR);
		}
	}
	if (mdb_pwalk("th_hash", th_hash_summary, &thw, NULL) == -1) {
		mdb_warn("can't walk th_hash entries");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static void
th_trace_help(void)
{
	mdb_printf("If given an address of an ill_t, ipif_t, ire_t, or ncec_t, "
	    "print the\n"
	    "corresponding th_trace_t structure in detail.  Otherwise, if no "
	    "address is\n"
	    "given, then summarize all th_trace_t structures.\n\n");
	mdb_printf("Options:\n"
	    "\t-n\tdisplay only entries with non-zero th_refcnt\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "conn_status", ":",
	    "display connection structures from ipcl hash tables",
	    conn_status, conn_status_help },
	{ "srcid_status", ":",
	    "display connection structures from ipcl hash tables",
	    srcid_status },
	{ "ill", "?[-v] [-P v4 | v6] [-s exclusive-ip-zone-name]",
	    "display ill_t structures", ill, ill_help },
	{ "illif", "?[-P v4 | v6]",
	    "display or filter IP Lower Level InterFace structures", illif,
	    illif_help },
	{ "iphdr", ":[-vf]", "display an IPv4 header", iphdr },
	{ "ip6hdr", ":[-vf]", "display an IPv6 header", ip6hdr },
	{ "ipif", "?[-v] [-P v4 | v6]", "display ipif structures",
	    ipif, ipif_help },
	{ "ire", "?[-v] [-P v4|v6] [-s exclusive-ip-zone-name]",
	    "display Internet Route Entry structures", ire },
	{ "nce", "?[-P v4|v6] [-i <interface>]",
	    "display interface-specific Neighbor Cache structures", nce },
	{ "ncec", "?[-P v4 | v6]", "display Neighbor Cache Entry structures",
	    ncec },
	{ "dce", "?[-P v4|v6] [-s exclusive-ip-zone-name]",
	    "display Destination Cache Entry structures", dce },
	{ "squeue", ":[-v]", "print core squeue_t info", squeue,
	    ip_squeue_help },
	{ "tcphdr", ":", "display a TCP header", tcphdr },
	{ "udphdr", ":", "display an UDP header", udphdr },
	{ "sctphdr", ":", "display an SCTP header", sctphdr },
	{ "th_trace", "?[-n]", "display th_trace_t structures", th_trace,
	    th_trace_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "conn_status", "walk list of conn_t structures",
		ip_stacks_common_walk_init, conn_status_walk_step, NULL },
	{ "illif", "walk list of ill interface types for all stacks",
		ip_stacks_common_walk_init, illif_walk_step, NULL },
	{ "illif_stack", "walk list of ill interface types",
		illif_stack_walk_init, illif_stack_walk_step,
		illif_stack_walk_fini },
	{ "ill", "walk active ill_t structures for all stacks",
		ill_walk_init, ill_walk_step, NULL },
	{ "ipif", "walk list of ipif structures for all stacks",
		ipif_walk_init, ipif_walk_step, NULL },
	{ "ipif_list", "walk the linked list of ipif structures "
		"for a given ill",
		ip_list_walk_init, ip_list_walk_step,
		ip_list_walk_fini, &ipif_walk_arg },
	{ "srcid", "walk list of srcid_map structures for all stacks",
		ip_stacks_common_walk_init, srcid_walk_step, NULL },
	{ "srcid_list", "walk list of srcid_map structures for a stack",
		ip_list_walk_init, ip_list_walk_step, ip_list_walk_fini,
		&srcid_walk_arg },
	{ "ire", "walk active ire_t structures",
		ire_walk_init, ire_walk_step, NULL },
	{ "ire_next", "walk ire_t structures in the ctable",
		ire_next_walk_init, ire_next_walk_step, NULL },
	{ "nce", "walk active nce_t structures",
		nce_walk_init, nce_walk_step, NULL },
	{ "dce", "walk active dce_t structures",
		dce_walk_init, dce_walk_step, NULL },
	{ "ip_stacks", "walk all the ip_stack_t",
		ns_walk_init, ip_stacks_walk_step, NULL },
	{ "tcp_stacks", "walk all the tcp_stack_t",
		ns_walk_init, tcp_stacks_walk_step, NULL },
	{ "sctp_stacks", "walk all the sctp_stack_t",
		ns_walk_init, sctp_stacks_walk_step, NULL },
	{ "udp_stacks", "walk all the udp_stack_t",
		ns_walk_init, udp_stacks_walk_step, NULL },
	{ "th_hash", "walk all the th_hash_t entries",
		th_hash_walk_init, th_hash_walk_step, NULL },
	{ "ncec", "walk list of ncec structures for all stacks",
		ip_stacks_common_walk_init, ncec_walk_step, NULL },
	{ "ncec_stack", "walk list of ncec structures",
		ncec_stack_walk_init, ncec_stack_walk_step,
		ncec_stack_walk_fini},
	{ "udp_hash", "walk list of conn_t structures in ips_ipcl_udp_fanout",
		ipcl_hash_walk_init, ipcl_hash_walk_step,
		ipcl_hash_walk_fini, &udp_hash_arg},
	{ "conn_hash", "walk list of conn_t structures in ips_ipcl_conn_fanout",
		ipcl_hash_walk_init, ipcl_hash_walk_step,
		ipcl_hash_walk_fini, &conn_hash_arg},
	{ "bind_hash", "walk list of conn_t structures in ips_ipcl_bind_fanout",
		ipcl_hash_walk_init, ipcl_hash_walk_step,
		ipcl_hash_walk_fini, &bind_hash_arg},
	{ "proto_hash", "walk list of conn_t structures in "
	    "ips_ipcl_proto_fanout",
		ipcl_hash_walk_init, ipcl_hash_walk_step,
		ipcl_hash_walk_fini, &proto_hash_arg},
	{ "proto_v6_hash", "walk list of conn_t structures in "
	    "ips_ipcl_proto_fanout_v6",
		ipcl_hash_walk_init, ipcl_hash_walk_step,
		ipcl_hash_walk_fini, &proto_v6_hash_arg},
	{ "ilb_stacks", "walk all ilb_stack_t",
		ns_walk_init, ilb_stacks_walk_step, NULL },
	{ "ilb_rules", "walk ilb rules in a given ilb_stack_t",
		ilb_rules_walk_init, ilb_rules_walk_step, NULL },
	{ "ilb_servers", "walk server in a given ilb_rule_t",
		ilb_servers_walk_init, ilb_servers_walk_step, NULL },
	{ "ilb_nat_src", "walk NAT source table of a given ilb_stack_t",
		ilb_nat_src_walk_init, ilb_nat_src_walk_step,
		ilb_common_walk_fini },
	{ "ilb_conns", "walk NAT table of a given ilb_stack_t",
		ilb_conn_walk_init, ilb_conn_walk_step, ilb_common_walk_fini },
	{ "ilb_stickys", "walk sticky table of a given ilb_stack_t",
		ilb_sticky_walk_init, ilb_sticky_walk_step,
		ilb_common_walk_fini },
	{ "tcps_sc", "walk all the per CPU stats counters of a tcp_stack_t",
		tcps_sc_walk_init, tcps_sc_walk_step, NULL },
	{ NULL }
};

static const mdb_qops_t ip_qops = { ip_qinfo, ip_rnext, ip_wnext };
static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("ip", "ipwinit", &sym) == 0)
		mdb_qops_install(&ip_qops, (uintptr_t)sym.st_value);

	return (&modinfo);
}

void
_mdb_fini(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("ip", "ipwinit", &sym) == 0)
		mdb_qops_remove(&ip_qops, (uintptr_t)sym.st_value);
}

static char *
ncec_state(int ncec_state)
{
	switch (ncec_state) {
	case ND_UNCHANGED:
		return ("unchanged");
	case ND_INCOMPLETE:
		return ("incomplete");
	case ND_REACHABLE:
		return ("reachable");
	case ND_STALE:
		return ("stale");
	case ND_DELAY:
		return ("delay");
	case ND_PROBE:
		return ("probe");
	case ND_UNREACHABLE:
		return ("unreach");
	case ND_INITIAL:
		return ("initial");
	default:
		return ("??");
	}
}

static char *
ncec_l2_addr(const ncec_t *ncec, const ill_t *ill)
{
	uchar_t *h;
	static char addr_buf[L2MAXADDRSTRLEN];

	if (ncec->ncec_lladdr == NULL) {
		return ("None");
	}

	if (ill->ill_net_type == IRE_IF_RESOLVER) {

		if (ill->ill_phys_addr_length == 0)
			return ("None");
		h = mdb_zalloc(ill->ill_phys_addr_length, UM_SLEEP);
		if (mdb_vread(h, ill->ill_phys_addr_length,
		    (uintptr_t)ncec->ncec_lladdr) == -1) {
			mdb_warn("failed to read hwaddr at %p",
			    ncec->ncec_lladdr);
			return ("Unknown");
		}
		mdb_mac_addr(h, ill->ill_phys_addr_length,
		    addr_buf, sizeof (addr_buf));
	} else {
		return ("None");
	}
	mdb_free(h, ill->ill_phys_addr_length);
	return (addr_buf);
}

static char *
nce_l2_addr(const nce_t *nce, const ill_t *ill)
{
	uchar_t *h;
	static char addr_buf[L2MAXADDRSTRLEN];
	mblk_t mp;
	size_t mblen;

	if (nce->nce_dlur_mp == NULL)
		return ("None");

	if (ill->ill_net_type == IRE_IF_RESOLVER) {
		if (mdb_vread(&mp, sizeof (mblk_t),
		    (uintptr_t)nce->nce_dlur_mp) == -1) {
			mdb_warn("failed to read nce_dlur_mp at %p",
			    nce->nce_dlur_mp);
			return ("None");
		}
		if (ill->ill_phys_addr_length == 0)
			return ("None");
		mblen = mp.b_wptr - mp.b_rptr;
		if (mblen > (sizeof (dl_unitdata_req_t) + MAX_SAP_LEN) ||
		    ill->ill_phys_addr_length > MAX_SAP_LEN ||
		    (NCE_LL_ADDR_OFFSET(ill) +
		    ill->ill_phys_addr_length) > mblen) {
			return ("Unknown");
		}
		h = mdb_zalloc(mblen, UM_SLEEP);
		if (mdb_vread(h, mblen, (uintptr_t)(mp.b_rptr)) == -1) {
			mdb_warn("failed to read hwaddr at %p",
			    mp.b_rptr + NCE_LL_ADDR_OFFSET(ill));
			return ("Unknown");
		}
		mdb_mac_addr(h + NCE_LL_ADDR_OFFSET(ill),
		    ill->ill_phys_addr_length, addr_buf, sizeof (addr_buf));
	} else {
		return ("None");
	}
	mdb_free(h, mblen);
	return (addr_buf);
}

static void
ncec_header(uint_t flags)
{
	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {

		mdb_printf("%<u>%?s %-20s %-10s %-8s %-5s %s%</u>\n",
		    "ADDR", "HW_ADDR", "STATE", "FLAGS", "ILL", "IP ADDR");
	}
}

int
ncec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ncec_t ncec;
	ncec_cbdata_t id;
	int ipversion = 0;
	const char *opt_P = NULL;

	if (mdb_getopts(argc, argv,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	if (flags & DCMD_ADDRSPEC) {

		if (mdb_vread(&ncec, sizeof (ncec_t), addr) == -1) {
			mdb_warn("failed to read ncec at %p\n", addr);
			return (DCMD_ERR);
		}
		if (ipversion != 0 && ncec.ncec_ipversion != ipversion) {
			mdb_printf("IP Version mismatch\n");
			return (DCMD_ERR);
		}
		ncec_header(flags);
		return (ncec_format(addr, &ncec, ipversion));

	} else {
		id.ncec_addr = addr;
		id.ncec_ipversion = ipversion;
		ncec_header(flags);
		if (mdb_walk("ncec", (mdb_walk_cb_t)ncec_cb, &id) == -1) {
			mdb_warn("failed to walk ncec table\n");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static int
ncec_format(uintptr_t addr, const ncec_t *ncec, int ipversion)
{
	static const mdb_bitmask_t ncec_flags[] = {
		{ "P",	NCE_F_NONUD,		NCE_F_NONUD },
		{ "R",	NCE_F_ISROUTER,		NCE_F_ISROUTER	},
		{ "N",	NCE_F_NONUD,		NCE_F_NONUD	},
		{ "A",	NCE_F_ANYCAST,		NCE_F_ANYCAST	},
		{ "C",	NCE_F_CONDEMNED,	NCE_F_CONDEMNED	},
		{ "U",	NCE_F_UNSOL_ADV,	NCE_F_UNSOL_ADV },
		{ "B",	NCE_F_BCAST,		NCE_F_BCAST	},
		{ NULL,	0,			0		}
	};
#define	NCE_MAX_FLAGS	(sizeof (ncec_flags) / sizeof (mdb_bitmask_t))
	struct in_addr nceaddr;
	ill_t ill;
	char ill_name[LIFNAMSIZ];
	char flagsbuf[NCE_MAX_FLAGS];

	if (mdb_vread(&ill, sizeof (ill), (uintptr_t)ncec->ncec_ill) == -1) {
		mdb_warn("failed to read ncec_ill at %p",
		    ncec->ncec_ill);
		return (DCMD_ERR);
	}

	(void) mdb_readstr(ill_name, MIN(LIFNAMSIZ, ill.ill_name_length),
	    (uintptr_t)ill.ill_name);

	mdb_snprintf(flagsbuf, sizeof (flagsbuf), "%hb",
	    ncec->ncec_flags, ncec_flags);

	if (ipversion != 0 && ncec->ncec_ipversion != ipversion)
		return (DCMD_OK);

	if (ncec->ncec_ipversion == IPV4_VERSION) {
		IN6_V4MAPPED_TO_INADDR(&ncec->ncec_addr, &nceaddr);
		mdb_printf("%?p %-20s %-10s "
		    "%-8s "
		    "%-5s %I\n",
		    addr, ncec_l2_addr(ncec, &ill),
		    ncec_state(ncec->ncec_state),
		    flagsbuf,
		    ill_name, nceaddr.s_addr);
	} else {
		mdb_printf("%?p %-20s %-10s %-8s %-5s %N\n",
		    addr,  ncec_l2_addr(ncec, &ill),
		    ncec_state(ncec->ncec_state),
		    flagsbuf,
		    ill_name, &ncec->ncec_addr);
	}

	return (DCMD_OK);
}

static uintptr_t
ncec_get_next_hash_tbl(uintptr_t start, int *index, struct ndp_g_s ndp)
{
	uintptr_t addr = start;
	int i = *index;

	while (addr == NULL) {

		if (++i >= NCE_TABLE_SIZE)
			break;
		addr = (uintptr_t)ndp.nce_hash_tbl[i];
	}
	*index = i;
	return (addr);
}

static int
ncec_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr4, kaddr6;

	kaddr4 = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ndp4);
	kaddr6 = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ndp6);

	if (mdb_vread(&kaddr4, sizeof (kaddr4), kaddr4) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr4);
		return (WALK_ERR);
	}
	if (mdb_vread(&kaddr6, sizeof (kaddr6), kaddr6) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr6);
		return (WALK_ERR);
	}
	if (mdb_pwalk("ncec_stack", wsp->walk_callback, wsp->walk_cbdata,
	    kaddr4) == -1) {
		mdb_warn("couldn't walk 'ncec_stack' for ips_ndp4 %p",
		    kaddr4);
		return (WALK_ERR);
	}
	if (mdb_pwalk("ncec_stack", wsp->walk_callback,
	    wsp->walk_cbdata, kaddr6) == -1) {
		mdb_warn("couldn't walk 'ncec_stack' for ips_ndp6 %p",
		    kaddr6);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static uintptr_t
ipcl_hash_get_next_connf_tbl(ipcl_hash_walk_data_t *iw)
{
	struct connf_s connf;
	uintptr_t addr = NULL, next;
	int index = iw->connf_tbl_index;

	do {
		next = iw->hash_tbl + index * sizeof (struct connf_s);
		if (++index >= iw->hash_tbl_size) {
			addr = NULL;
			break;
		}
		if (mdb_vread(&connf, sizeof (struct connf_s), next) == -1)  {
			mdb_warn("failed to read conn_t at %p", next);
			return (NULL);
		}
		addr = (uintptr_t)connf.connf_head;
	} while (addr == NULL);
	iw->connf_tbl_index = index;
	return (addr);
}

static int
ipcl_hash_walk_init(mdb_walk_state_t *wsp)
{
	const hash_walk_arg_t *arg = wsp->walk_arg;
	ipcl_hash_walk_data_t *iw;
	uintptr_t tbladdr;
	uintptr_t sizeaddr;

	iw = mdb_alloc(sizeof (ipcl_hash_walk_data_t), UM_SLEEP);
	iw->conn = mdb_alloc(sizeof (conn_t), UM_SLEEP);
	tbladdr = wsp->walk_addr + arg->tbl_off;
	sizeaddr = wsp->walk_addr + arg->size_off;

	if (mdb_vread(&iw->hash_tbl, sizeof (uintptr_t), tbladdr) == -1) {
		mdb_warn("can't read fanout table addr at %p", tbladdr);
		mdb_free(iw->conn, sizeof (conn_t));
		mdb_free(iw, sizeof (ipcl_hash_walk_data_t));
		return (WALK_ERR);
	}
	if (arg->tbl_off == OFFSETOF(ip_stack_t, ips_ipcl_proto_fanout_v4) ||
	    arg->tbl_off == OFFSETOF(ip_stack_t, ips_ipcl_proto_fanout_v6)) {
		iw->hash_tbl_size = IPPROTO_MAX;
	} else {
		if (mdb_vread(&iw->hash_tbl_size, sizeof (int),
		    sizeaddr) == -1) {
			mdb_warn("can't read fanout table size addr at %p",
			    sizeaddr);
			mdb_free(iw->conn, sizeof (conn_t));
			mdb_free(iw, sizeof (ipcl_hash_walk_data_t));
			return (WALK_ERR);
		}
	}
	iw->connf_tbl_index = 0;
	wsp->walk_addr = ipcl_hash_get_next_connf_tbl(iw);
	wsp->walk_data = iw;

	if (wsp->walk_addr != NULL)
		return (WALK_NEXT);
	else
		return (WALK_DONE);
}

static int
ipcl_hash_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	ipcl_hash_walk_data_t *iw = wsp->walk_data;
	conn_t *conn = iw->conn;
	int ret = WALK_DONE;

	while (addr != NULL) {
		if (mdb_vread(conn, sizeof (conn_t), addr) == -1) {
			mdb_warn("failed to read conn_t at %p", addr);
			return (WALK_ERR);
		}
		ret = wsp->walk_callback(addr, iw, wsp->walk_cbdata);
		if (ret != WALK_NEXT)
			break;
		addr = (uintptr_t)conn->conn_next;
	}
	if (ret == WALK_NEXT) {
		wsp->walk_addr = ipcl_hash_get_next_connf_tbl(iw);

		if (wsp->walk_addr != NULL)
			return (WALK_NEXT);
		else
			return (WALK_DONE);
	}

	return (ret);
}

static void
ipcl_hash_walk_fini(mdb_walk_state_t *wsp)
{
	ipcl_hash_walk_data_t *iw = wsp->walk_data;

	mdb_free(iw->conn, sizeof (conn_t));
	mdb_free(iw, sizeof (ipcl_hash_walk_data_t));
}

/*
 * Called with walk_addr being the address of ips_ndp{4,6}
 */
static int
ncec_stack_walk_init(mdb_walk_state_t *wsp)
{
	ncec_walk_data_t *nw;

	if (wsp->walk_addr == NULL) {
		mdb_warn("ncec_stack requires ndp_g_s address\n");
		return (WALK_ERR);
	}

	nw = mdb_alloc(sizeof (ncec_walk_data_t), UM_SLEEP);

	if (mdb_vread(&nw->ncec_ip_ndp, sizeof (struct ndp_g_s),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read 'ip_ndp' at %p",
		    wsp->walk_addr);
		mdb_free(nw, sizeof (ncec_walk_data_t));
		return (WALK_ERR);
	}

	/*
	 * ncec_get_next_hash_tbl() starts at ++i , so initialize index to -1
	 */
	nw->ncec_hash_tbl_index = -1;
	wsp->walk_addr = ncec_get_next_hash_tbl(NULL,
	    &nw->ncec_hash_tbl_index, nw->ncec_ip_ndp);
	wsp->walk_data = nw;

	return (WALK_NEXT);
}

static int
ncec_stack_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	ncec_walk_data_t *nw = wsp->walk_data;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&nw->ncec, sizeof (ncec_t), addr) == -1) {
		mdb_warn("failed to read ncec_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)nw->ncec.ncec_next;

	wsp->walk_addr = ncec_get_next_hash_tbl(wsp->walk_addr,
	    &nw->ncec_hash_tbl_index, nw->ncec_ip_ndp);

	return (wsp->walk_callback(addr, nw, wsp->walk_cbdata));
}

static void
ncec_stack_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ncec_walk_data_t));
}

/* ARGSUSED */
static int
ncec_cb(uintptr_t addr, const ncec_walk_data_t *iw, ncec_cbdata_t *id)
{
	ncec_t ncec;

	if (mdb_vread(&ncec, sizeof (ncec_t), addr) == -1) {
		mdb_warn("failed to read ncec at %p", addr);
		return (WALK_NEXT);
	}
	(void) ncec_format(addr, &ncec, id->ncec_ipversion);
	return (WALK_NEXT);
}

static int
ill_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("illif", wsp) == -1) {
		mdb_warn("can't walk 'illif'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
ill_walk_step(mdb_walk_state_t *wsp)
{
	ill_if_t ill_if;

	if (mdb_vread(&ill_if, sizeof (ill_if_t), wsp->walk_addr) == -1) {
		mdb_warn("can't read ill_if_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)(wsp->walk_addr +
	    offsetof(ill_if_t, illif_avl_by_ppa));
	if (mdb_pwalk("avl", wsp->walk_callback, wsp->walk_cbdata,
	    wsp->walk_addr) == -1) {
		mdb_warn("can't walk 'avl'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
ill_cb(uintptr_t addr, const ill_walk_data_t *iw, ill_cbdata_t *id)
{
	ill_t ill;

	if (mdb_vread(&ill, sizeof (ill_t), (uintptr_t)addr) == -1) {
		mdb_warn("failed to read ill at %p", addr);
		return (WALK_NEXT);
	}

	/* If ip_stack_t is specified, skip ILLs that don't belong to it. */
	if (id->ill_ipst != NULL && ill.ill_ipst != id->ill_ipst)
		return (WALK_NEXT);

	return (ill_format((uintptr_t)addr, &ill, id));
}

static void
ill_header(boolean_t verbose)
{
	if (verbose) {
		mdb_printf("%-?s %-8s %3s %-10s %-?s %-?s %-10s%</u>\n",
		    "ADDR", "NAME", "VER", "TYPE", "WQ", "IPST", "FLAGS");
		mdb_printf("%-?s %4s%4s %-?s\n",
		    "PHYINT", "CNT", "", "GROUP");
		mdb_printf("%<u>%80s%</u>\n", "");
	} else {
		mdb_printf("%<u>%-?s %-8s %-3s %-10s %4s %-?s %-10s%</u>\n",
		    "ADDR", "NAME", "VER", "TYPE", "CNT", "WQ", "FLAGS");
	}
}

static int
ill_format(uintptr_t addr, const void *illptr, void *ill_cb_arg)
{
	ill_t *ill = (ill_t *)illptr;
	ill_cbdata_t *illcb = ill_cb_arg;
	boolean_t verbose = illcb->verbose;
	phyint_t phyi;
	static const mdb_bitmask_t fmasks[] = {
		{ "R",		PHYI_RUNNING,		PHYI_RUNNING	},
		{ "P",		PHYI_PROMISC,		PHYI_PROMISC	},
		{ "V",		PHYI_VIRTUAL,		PHYI_VIRTUAL	},
		{ "I",		PHYI_IPMP,		PHYI_IPMP	},
		{ "f",		PHYI_FAILED,		PHYI_FAILED	},
		{ "S",		PHYI_STANDBY,		PHYI_STANDBY	},
		{ "i",		PHYI_INACTIVE,		PHYI_INACTIVE	},
		{ "O",		PHYI_OFFLINE,		PHYI_OFFLINE	},
		{ "T", 		ILLF_NOTRAILERS,	ILLF_NOTRAILERS },
		{ "A",		ILLF_NOARP,		ILLF_NOARP	},
		{ "M",		ILLF_MULTICAST,		ILLF_MULTICAST	},
		{ "F",		ILLF_ROUTER,		ILLF_ROUTER	},
		{ "D",		ILLF_NONUD,		ILLF_NONUD	},
		{ "X",		ILLF_NORTEXCH,		ILLF_NORTEXCH	},
		{ NULL,		0,			0		}
	};
	static const mdb_bitmask_t v_fmasks[] = {
		{ "RUNNING",	PHYI_RUNNING,		PHYI_RUNNING	},
		{ "PROMISC",	PHYI_PROMISC,		PHYI_PROMISC	},
		{ "VIRTUAL",	PHYI_VIRTUAL,		PHYI_VIRTUAL	},
		{ "IPMP",	PHYI_IPMP,		PHYI_IPMP	},
		{ "FAILED",	PHYI_FAILED,		PHYI_FAILED	},
		{ "STANDBY",	PHYI_STANDBY,		PHYI_STANDBY	},
		{ "INACTIVE",	PHYI_INACTIVE,		PHYI_INACTIVE	},
		{ "OFFLINE",	PHYI_OFFLINE,		PHYI_OFFLINE	},
		{ "NOTRAILER",	ILLF_NOTRAILERS,	ILLF_NOTRAILERS },
		{ "NOARP",	ILLF_NOARP,		ILLF_NOARP	},
		{ "MULTICAST",	ILLF_MULTICAST,		ILLF_MULTICAST	},
		{ "ROUTER",	ILLF_ROUTER,		ILLF_ROUTER	},
		{ "NONUD",	ILLF_NONUD,		ILLF_NONUD	},
		{ "NORTEXCH",	ILLF_NORTEXCH,		ILLF_NORTEXCH	},
		{ NULL,		0,			0		}
	};
	char ill_name[LIFNAMSIZ];
	int cnt;
	char *typebuf;
	char sbuf[DEFCOLS];
	int ipver = illcb->ill_ipversion;

	if (ipver != 0) {
		if ((ipver == IPV4_VERSION && ill->ill_isv6) ||
		    (ipver == IPV6_VERSION && !ill->ill_isv6)) {
			return (WALK_NEXT);
		}
	}
	if (mdb_vread(&phyi, sizeof (phyint_t),
	    (uintptr_t)ill->ill_phyint) == -1) {
		mdb_warn("failed to read ill_phyint at %p",
		    (uintptr_t)ill->ill_phyint);
		return (WALK_NEXT);
	}
	(void) mdb_readstr(ill_name, MIN(LIFNAMSIZ, ill->ill_name_length),
	    (uintptr_t)ill->ill_name);

	switch (ill->ill_type) {
	case 0:
		typebuf = "LOOPBACK";
		break;
	case IFT_ETHER:
		typebuf = "ETHER";
		break;
	case IFT_OTHER:
		typebuf = "OTHER";
		break;
	default:
		typebuf = NULL;
		break;
	}
	cnt = ill->ill_refcnt + ill->ill_ire_cnt + ill->ill_nce_cnt +
	    ill->ill_ilm_cnt + ill->ill_ncec_cnt;
	mdb_printf("%-?p %-8s %-3s ",
	    addr, ill_name, ill->ill_isv6 ? "v6" : "v4");
	if (typebuf != NULL)
		mdb_printf("%-10s ", typebuf);
	else
		mdb_printf("%-10x ", ill->ill_type);
	if (verbose) {
		mdb_printf("%-?p %-?p %-llb\n",
		    ill->ill_wq, ill->ill_ipst,
		    ill->ill_flags | phyi.phyint_flags, v_fmasks);
		mdb_printf("%-?p %4d%4s %-?p\n",
		    ill->ill_phyint, cnt, "", ill->ill_grp);
		mdb_snprintf(sbuf, sizeof (sbuf), "%*s %3s",
		    sizeof (uintptr_t) * 2, "", "");
		mdb_printf("%s|\n%s+--> %3d %-18s "
		    "references from active threads\n",
		    sbuf, sbuf, ill->ill_refcnt, "ill_refcnt");
		mdb_printf("%*s %7d %-18s ires referencing this ill\n",
		    strlen(sbuf), "", ill->ill_ire_cnt, "ill_ire_cnt");
		mdb_printf("%*s %7d %-18s nces referencing this ill\n",
		    strlen(sbuf), "", ill->ill_nce_cnt, "ill_nce_cnt");
		mdb_printf("%*s %7d %-18s ncecs referencing this ill\n",
		    strlen(sbuf), "", ill->ill_ncec_cnt, "ill_ncec_cnt");
		mdb_printf("%*s %7d %-18s ilms referencing this ill\n",
		    strlen(sbuf), "", ill->ill_ilm_cnt, "ill_ilm_cnt");
	} else {
		mdb_printf("%4d %-?p %-llb\n",
		    cnt, ill->ill_wq,
		    ill->ill_flags | phyi.phyint_flags, fmasks);
	}
	return (WALK_NEXT);
}

static int
ill(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ill_t ill_data;
	ill_cbdata_t id;
	int ipversion = 0;
	const char *zone_name = NULL;
	const char *opt_P = NULL;
	uint_t verbose = FALSE;
	ip_stack_t *ipst = NULL;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    's', MDB_OPT_STR, &zone_name,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	/* Follow the specified zone name to find a ip_stack_t*. */
	if (zone_name != NULL) {
		ipst = zone_to_ips(zone_name);
		if (ipst == NULL)
			return (DCMD_USAGE);
	}

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	id.verbose = verbose;
	id.ill_addr = addr;
	id.ill_ipversion = ipversion;
	id.ill_ipst = ipst;

	ill_header(verbose);
	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&ill_data, sizeof (ill_t), addr) == -1) {
			mdb_warn("failed to read ill at %p\n", addr);
			return (DCMD_ERR);
		}
		(void) ill_format(addr, &ill_data, &id);
	} else {
		if (mdb_walk("ill", (mdb_walk_cb_t)ill_cb, &id) == -1) {
			mdb_warn("failed to walk ills\n");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static void
ill_help(void)
{
	mdb_printf("Prints the following fields: ill ptr, name, "
	    "IP version, count, ill type and ill flags.\n"
	    "The count field is a sum of individual refcnts and is expanded "
	    "with the -v option.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-P v4 | v6"
	    "\tfilter ill structures for the specified protocol\n");
}

static int
ip_list_walk_init(mdb_walk_state_t *wsp)
{
	const ip_list_walk_arg_t *arg = wsp->walk_arg;
	ip_list_walk_data_t *iw;
	uintptr_t addr = (uintptr_t)(wsp->walk_addr + arg->off);

	if (wsp->walk_addr == NULL) {
		mdb_warn("only local walks supported\n");
		return (WALK_ERR);
	}
	if (mdb_vread(&wsp->walk_addr, sizeof (uintptr_t),
	    addr) == -1) {
		mdb_warn("failed to read list head at %p", addr);
		return (WALK_ERR);
	}
	iw = mdb_alloc(sizeof (ip_list_walk_data_t), UM_SLEEP);
	iw->nextoff = arg->nextp_off;
	wsp->walk_data = iw;

	return (WALK_NEXT);
}

static int
ip_list_walk_step(mdb_walk_state_t *wsp)
{
	ip_list_walk_data_t *iw = wsp->walk_data;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);
	wsp->walk_addr = addr + iw->nextoff;
	if (mdb_vread(&wsp->walk_addr, sizeof (uintptr_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read list node at %p", addr);
		return (WALK_ERR);
	}
	return (wsp->walk_callback(addr, iw, wsp->walk_cbdata));
}

static void
ip_list_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ip_list_walk_data_t));
}

static int
ipif_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("ill", wsp) == -1) {
		mdb_warn("can't walk 'ills'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
ipif_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("ipif_list", wsp->walk_callback, wsp->walk_cbdata,
	    wsp->walk_addr) == -1) {
		mdb_warn("can't walk 'ipif_list'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
ipif_cb(uintptr_t addr, const ipif_walk_data_t *iw, ipif_cbdata_t *id)
{
	ipif_t ipif;

	if (mdb_vread(&ipif, sizeof (ipif_t), (uintptr_t)addr) == -1) {
		mdb_warn("failed to read ipif at %p", addr);
		return (WALK_NEXT);
	}
	if (mdb_vread(&id->ill, sizeof (ill_t),
	    (uintptr_t)ipif.ipif_ill) == -1) {
		mdb_warn("failed to read ill at %p", ipif.ipif_ill);
		return (WALK_NEXT);
	}
	(void) ipif_format((uintptr_t)addr, &ipif, id);
	return (WALK_NEXT);
}

static void
ipif_header(boolean_t verbose)
{
	if (verbose) {
		mdb_printf("%-?s %-10s %-3s %-?s %-8s %-30s\n",
		    "ADDR", "NAME", "CNT", "ILL", "STFLAGS", "FLAGS");
		mdb_printf("%s\n%s\n",
		    "LCLADDR", "BROADCAST");
		mdb_printf("%<u>%80s%</u>\n", "");
	} else {
		mdb_printf("%-?s %-10s %6s %-?s %-8s %-30s\n",
		    "ADDR", "NAME", "CNT", "ILL", "STFLAGS", "FLAGS");
		mdb_printf("%s\n%<u>%80s%</u>\n", "LCLADDR", "");
	}
}

#ifdef _BIG_ENDIAN
#define	ip_ntohl_32(x)	((x) & 0xffffffff)
#else
#define	ip_ntohl_32(x)	(((uint32_t)(x) << 24) | \
			(((uint32_t)(x) << 8) & 0xff0000) | \
			(((uint32_t)(x) >> 8) & 0xff00) | \
			((uint32_t)(x)  >> 24))
#endif

int
mask_to_prefixlen(int af, const in6_addr_t *addr)
{
	int len = 0;
	int i;
	uint_t mask = 0;

	if (af == AF_INET6) {
		for (i = 0; i < 4; i++) {
			if (addr->s6_addr32[i] == 0xffffffff) {
				len += 32;
			} else {
				mask = addr->s6_addr32[i];
				break;
			}
		}
	} else {
		mask = V4_PART_OF_V6((*addr));
	}
	if (mask > 0)
		len += (33 - mdb_ffs(ip_ntohl_32(mask)));
	return (len);
}

static int
ipif_format(uintptr_t addr, const void *ipifptr, void *ipif_cb_arg)
{
	const ipif_t *ipif = ipifptr;
	ipif_cbdata_t *ipifcb = ipif_cb_arg;
	boolean_t verbose = ipifcb->verbose;
	char ill_name[LIFNAMSIZ];
	char buf[LIFNAMSIZ];
	int cnt;
	static const mdb_bitmask_t sfmasks[] = {
		{ "CO",		IPIF_CONDEMNED,		IPIF_CONDEMNED},
		{ "CH",		IPIF_CHANGING,		IPIF_CHANGING},
		{ "SL",		IPIF_SET_LINKLOCAL,	IPIF_SET_LINKLOCAL},
		{ NULL,		0,			0		}
	};
	static const mdb_bitmask_t fmasks[] = {
		{ "UP",		IPIF_UP,		IPIF_UP		},
		{ "UNN",	IPIF_UNNUMBERED,	IPIF_UNNUMBERED},
		{ "DHCP",	IPIF_DHCPRUNNING,	IPIF_DHCPRUNNING},
		{ "PRIV",	IPIF_PRIVATE,		IPIF_PRIVATE},
		{ "NOXMT",	IPIF_NOXMIT,		IPIF_NOXMIT},
		{ "NOLCL",	IPIF_NOLOCAL,		IPIF_NOLOCAL},
		{ "DEPR",	IPIF_DEPRECATED,	IPIF_DEPRECATED},
		{ "PREF",	IPIF_PREFERRED,		IPIF_PREFERRED},
		{ "TEMP",	IPIF_TEMPORARY,		IPIF_TEMPORARY},
		{ "ACONF",	IPIF_ADDRCONF,		IPIF_ADDRCONF},
		{ "ANY",	IPIF_ANYCAST,		IPIF_ANYCAST},
		{ "NFAIL",	IPIF_NOFAILOVER,	IPIF_NOFAILOVER},
		{ NULL,		0,			0		}
	};
	char flagsbuf[2 * A_CNT(fmasks)];
	char bitfields[A_CNT(fmasks)];
	char sflagsbuf[A_CNT(sfmasks)];
	char sbuf[DEFCOLS], addrstr[INET6_ADDRSTRLEN];
	int ipver = ipifcb->ipif_ipversion;
	int af;

	if (ipver != 0) {
		if ((ipver == IPV4_VERSION && ipifcb->ill.ill_isv6) ||
		    (ipver == IPV6_VERSION && !ipifcb->ill.ill_isv6)) {
			return (WALK_NEXT);
		}
	}
	if ((mdb_readstr(ill_name, MIN(LIFNAMSIZ,
	    ipifcb->ill.ill_name_length),
	    (uintptr_t)ipifcb->ill.ill_name)) == -1) {
		mdb_warn("failed to read ill_name of ill %p\n", ipifcb->ill);
		return (WALK_NEXT);
	}
	if (ipif->ipif_id != 0) {
		mdb_snprintf(buf, LIFNAMSIZ, "%s:%d",
		    ill_name, ipif->ipif_id);
	} else {
		mdb_snprintf(buf, LIFNAMSIZ, "%s", ill_name);
	}
	mdb_snprintf(bitfields, sizeof (bitfields), "%s",
	    ipif->ipif_addr_ready ? ",ADR" : "",
	    ipif->ipif_was_up ? ",WU" : "",
	    ipif->ipif_was_dup ? ",WD" : "");
	mdb_snprintf(flagsbuf, sizeof (flagsbuf), "%llb%s",
	    ipif->ipif_flags, fmasks, bitfields);
	mdb_snprintf(sflagsbuf, sizeof (sflagsbuf), "%b",
	    ipif->ipif_state_flags, sfmasks);

	cnt = ipif->ipif_refcnt;

	if (ipifcb->ill.ill_isv6) {
		mdb_snprintf(addrstr, sizeof (addrstr), "%N",
		    &ipif->ipif_v6lcl_addr);
		af = AF_INET6;
	} else {
		mdb_snprintf(addrstr, sizeof (addrstr), "%I",
		    V4_PART_OF_V6((ipif->ipif_v6lcl_addr)));
		af = AF_INET;
	}

	if (verbose) {
		mdb_printf("%-?p %-10s %3d %-?p %-8s %-30s\n",
		    addr, buf, cnt, ipif->ipif_ill,
		    sflagsbuf, flagsbuf);
		mdb_snprintf(sbuf, sizeof (sbuf), "%*s %12s",
		    sizeof (uintptr_t) * 2, "", "");
		mdb_printf("%s |\n%s +---> %4d %-15s "
		    "Active consistent reader cnt\n",
		    sbuf, sbuf, ipif->ipif_refcnt, "ipif_refcnt");
		mdb_printf("%-s/%d\n",
		    addrstr, mask_to_prefixlen(af, &ipif->ipif_v6net_mask));
		if (ipifcb->ill.ill_isv6) {
			mdb_printf("%-N\n", &ipif->ipif_v6brd_addr);
		} else {
			mdb_printf("%-I\n",
			    V4_PART_OF_V6((ipif->ipif_v6brd_addr)));
		}
	} else {
		mdb_printf("%-?p %-10s %6d %-?p %-8s %-30s\n",
		    addr, buf, cnt, ipif->ipif_ill,
		    sflagsbuf, flagsbuf);
		mdb_printf("%-s/%d\n",
		    addrstr, mask_to_prefixlen(af, &ipif->ipif_v6net_mask));
	}

	return (WALK_NEXT);
}

static int
ipif(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ipif_t ipif;
	ipif_cbdata_t id;
	int ipversion = 0;
	const char *opt_P = NULL;
	uint_t verbose = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    'P', MDB_OPT_STR, &opt_P, NULL) != argc)
		return (DCMD_USAGE);

	if (opt_P != NULL) {
		if (strcmp("v4", opt_P) == 0) {
			ipversion = IPV4_VERSION;
		} else if (strcmp("v6", opt_P) == 0) {
			ipversion = IPV6_VERSION;
		} else {
			mdb_warn("invalid protocol '%s'\n", opt_P);
			return (DCMD_USAGE);
		}
	}

	id.verbose = verbose;
	id.ipif_ipversion = ipversion;

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&ipif, sizeof (ipif_t), addr) == -1) {
			mdb_warn("failed to read ipif at %p\n", addr);
			return (DCMD_ERR);
		}
		ipif_header(verbose);
		if (mdb_vread(&id.ill, sizeof (ill_t),
		    (uintptr_t)ipif.ipif_ill) == -1) {
			mdb_warn("failed to read ill at %p", ipif.ipif_ill);
			return (WALK_NEXT);
		}
		return (ipif_format(addr, &ipif, &id));
	} else {
		ipif_header(verbose);
		if (mdb_walk("ipif", (mdb_walk_cb_t)ipif_cb, &id) == -1) {
			mdb_warn("failed to walk ipifs\n");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static void
ipif_help(void)
{
	mdb_printf("Prints the following fields: ipif ptr, name, "
	    "count, ill ptr, state flags and ipif flags.\n"
	    "The count field is a sum of individual refcnts and is expanded "
	    "with the -v option.\n"
	    "The flags field shows the following:"
	    "\n\tUNN -> UNNUMBERED, DHCP -> DHCPRUNNING, PRIV -> PRIVATE, "
	    "\n\tNOXMT -> NOXMIT, NOLCL -> NOLOCAL, DEPR -> DEPRECATED, "
	    "\n\tPREF -> PREFERRED, TEMP -> TEMPORARY, ACONF -> ADDRCONF, "
	    "\n\tANY -> ANYCAST, NFAIL -> NOFAILOVER, "
	    "\n\tADR -> ipif_addr_ready, MU -> ipif_multicast_up, "
	    "\n\tWU -> ipif_was_up, WD -> ipif_was_dup, "
	    "JA -> ipif_joined_allhosts.\n\n");
	mdb_printf("Options:\n");
	mdb_printf("\t-P v4 | v6"
	    "\tfilter ipif structures on ills for the specified protocol\n");
}

static int
conn_status_walk_fanout(uintptr_t addr, mdb_walk_state_t *wsp,
    const char *walkname)
{
	if (mdb_pwalk(walkname, wsp->walk_callback, wsp->walk_cbdata,
	    addr) == -1) {
		mdb_warn("couldn't walk '%s' at %p", walkname, addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
conn_status_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;

	(void) conn_status_walk_fanout(addr, wsp, "udp_hash");
	(void) conn_status_walk_fanout(addr, wsp, "conn_hash");
	(void) conn_status_walk_fanout(addr, wsp, "bind_hash");
	(void) conn_status_walk_fanout(addr, wsp, "proto_hash");
	(void) conn_status_walk_fanout(addr, wsp, "proto_v6_hash");
	return (WALK_NEXT);
}

/* ARGSUSED */
static int
conn_status_cb(uintptr_t addr, const void *walk_data,
    void *private)
{
	netstack_t nss;
	char src_addrstr[INET6_ADDRSTRLEN];
	char rem_addrstr[INET6_ADDRSTRLEN];
	const ipcl_hash_walk_data_t *iw = walk_data;
	conn_t c, *conn = &c;

	if (iw != NULL)
		conn = iw->conn;
	else if (mdb_vread(conn, sizeof (conn_t), addr) == -1) {
		mdb_warn("failed to read conn_t at %p", addr);
		return (WALK_ERR);
	}
	if (mdb_vread(&nss, sizeof (nss),
	    (uintptr_t)conn->conn_netstack) == -1) {
		mdb_warn("failed to read netstack_t %p",
		    conn->conn_netstack);
		return (WALK_ERR);
	}
	mdb_printf("%-?p %-?p %?d %?d\n", addr, conn->conn_wq,
	    nss.netstack_stackid, conn->conn_zoneid);

	if (conn->conn_family == AF_INET6) {
		mdb_snprintf(src_addrstr, sizeof (rem_addrstr), "%N",
		    &conn->conn_laddr_v6);
		mdb_snprintf(rem_addrstr, sizeof (rem_addrstr), "%N",
		    &conn->conn_faddr_v6);
	} else {
		mdb_snprintf(src_addrstr, sizeof (src_addrstr), "%I",
		    V4_PART_OF_V6((conn->conn_laddr_v6)));
		mdb_snprintf(rem_addrstr, sizeof (rem_addrstr), "%I",
		    V4_PART_OF_V6((conn->conn_faddr_v6)));
	}
	mdb_printf("%s:%-5d\n%s:%-5d\n",
	    src_addrstr, conn->conn_lport, rem_addrstr, conn->conn_fport);
	return (WALK_NEXT);
}

static void
conn_header(void)
{
	mdb_printf("%-?s %-?s %?s %?s\n%s\n%s\n",
	    "ADDR", "WQ", "STACK", "ZONE", "SRC:PORT", "DEST:PORT");
	mdb_printf("%<u>%80s%</u>\n", "");
}

/*ARGSUSED*/
static int
conn_status(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	conn_header();
	if (flags & DCMD_ADDRSPEC) {
		(void) conn_status_cb(addr, NULL, NULL);
	} else {
		if (mdb_walk("conn_status", (mdb_walk_cb_t)conn_status_cb,
		    NULL) == -1) {
			mdb_warn("failed to walk conn_fanout");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static void
conn_status_help(void)
{
	mdb_printf("Prints conn_t structures from the following hash tables: "
	    "\n\tips_ipcl_udp_fanout\n\tips_ipcl_bind_fanout"
	    "\n\tips_ipcl_conn_fanout\n\tips_ipcl_proto_fanout_v4"
	    "\n\tips_ipcl_proto_fanout_v6\n");
}

static int
srcid_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("srcid_list", wsp->walk_callback, wsp->walk_cbdata,
	    wsp->walk_addr) == -1) {
		mdb_warn("can't walk 'srcid_list'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/* ARGSUSED */
static int
srcid_status_cb(uintptr_t addr, const void *walk_data,
    void *private)
{
	srcid_map_t smp;

	if (mdb_vread(&smp, sizeof (srcid_map_t), addr) == -1) {
		mdb_warn("failed to read srcid_map at %p", addr);
		return (WALK_ERR);
	}
	mdb_printf("%-?p %3d %4d %6d %N\n",
	    addr, smp.sm_srcid, smp.sm_zoneid, smp.sm_refcnt,
	    &smp.sm_addr);
	return (WALK_NEXT);
}

static void
srcid_header(void)
{
	mdb_printf("%-?s %3s %4s %6s %s\n",
	    "ADDR", "ID", "ZONE", "REFCNT", "IPADDR");
	mdb_printf("%<u>%80s%</u>\n", "");
}

/*ARGSUSED*/
static int
srcid_status(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	srcid_header();
	if (flags & DCMD_ADDRSPEC) {
		(void) srcid_status_cb(addr, NULL, NULL);
	} else {
		if (mdb_walk("srcid", (mdb_walk_cb_t)srcid_status_cb,
		    NULL) == -1) {
			mdb_warn("failed to walk srcid_map");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

static int
ilb_stacks_walk_step(mdb_walk_state_t *wsp)
{
	return (ns_walk_step(wsp, NS_ILB));
}

static int
ilb_rules_walk_init(mdb_walk_state_t *wsp)
{
	ilb_stack_t ilbs;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	if (mdb_vread(&ilbs, sizeof (ilbs), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_stack_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if ((wsp->walk_addr = (uintptr_t)ilbs.ilbs_rule_head) != NULL)
		return (WALK_NEXT);
	else
		return (WALK_DONE);
}

static int
ilb_rules_walk_step(mdb_walk_state_t *wsp)
{
	ilb_rule_t rule;
	int status;

	if (mdb_vread(&rule, sizeof (rule), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_rule_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(wsp->walk_addr, &rule, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);
	if ((wsp->walk_addr = (uintptr_t)rule.ir_next) == NULL)
		return (WALK_DONE);
	else
		return (WALK_NEXT);
}

static int
ilb_servers_walk_init(mdb_walk_state_t *wsp)
{
	ilb_rule_t rule;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	if (mdb_vread(&rule, sizeof (rule), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_rule_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	if ((wsp->walk_addr = (uintptr_t)rule.ir_servers) != NULL)
		return (WALK_NEXT);
	else
		return (WALK_DONE);
}

static int
ilb_servers_walk_step(mdb_walk_state_t *wsp)
{
	ilb_server_t server;
	int status;

	if (mdb_vread(&server, sizeof (server), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_server_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(wsp->walk_addr, &server, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);
	if ((wsp->walk_addr = (uintptr_t)server.iser_next) == NULL)
		return (WALK_DONE);
	else
		return (WALK_NEXT);
}

/*
 * Helper structure for ilb_nat_src walker.  It stores the current index of the
 * nat src table.
 */
typedef struct {
	ilb_stack_t ilbs;
	int idx;
} ilb_walk_t;

/* Copy from list.c */
#define	list_object(a, node)	((void *)(((char *)node) - (a)->list_offset))

static int
ilb_nat_src_walk_init(mdb_walk_state_t *wsp)
{
	int i;
	ilb_walk_t *ns_walk;
	ilb_nat_src_entry_t *entry = NULL;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	ns_walk = mdb_alloc(sizeof (ilb_walk_t), UM_SLEEP);
	if (mdb_vread(&ns_walk->ilbs, sizeof (ns_walk->ilbs),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_stack_t at %p", wsp->walk_addr);
		mdb_free(ns_walk, sizeof (ilb_walk_t));
		return (WALK_ERR);
	}

	if (ns_walk->ilbs.ilbs_nat_src == NULL) {
		mdb_free(ns_walk, sizeof (ilb_walk_t));
		return (WALK_DONE);
	}

	wsp->walk_data = ns_walk;
	for (i = 0; i < ns_walk->ilbs.ilbs_nat_src_hash_size; i++) {
		list_t head;
		char  *khead;

		/* Read in the nsh_head in the i-th element of the array. */
		khead = (char *)ns_walk->ilbs.ilbs_nat_src + i *
		    sizeof (ilb_nat_src_hash_t);
		if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_nat_src at %p\n", khead);
			return (WALK_ERR);
		}

		/*
		 * Note that list_next points to a kernel address and we need
		 * to compare list_next with the kernel address of the list
		 * head.  So we need to calculate the address manually.
		 */
		if ((char *)head.list_head.list_next != khead +
		    offsetof(list_t, list_head)) {
			entry = list_object(&head, head.list_head.list_next);
			break;
		}
	}

	if (entry == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)entry;
	ns_walk->idx = i;
	return (WALK_NEXT);
}

static int
ilb_nat_src_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	ilb_nat_src_entry_t entry, *next_entry;
	ilb_walk_t *ns_walk;
	ilb_stack_t *ilbs;
	list_t head;
	char *khead;
	int i;

	if (mdb_vread(&entry, sizeof (ilb_nat_src_entry_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_nat_src_entry_t at %p",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	status = wsp->walk_callback(wsp->walk_addr, &entry, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	ns_walk = (ilb_walk_t *)wsp->walk_data;
	ilbs = &ns_walk->ilbs;
	i = ns_walk->idx;

	/* Read in the nsh_head in the i-th element of the array. */
	khead = (char *)ilbs->ilbs_nat_src + i * sizeof (ilb_nat_src_hash_t);
	if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
		mdb_warn("failed to read ilbs_nat_src at %p\n", khead);
		return (WALK_ERR);
	}

	/*
	 * Check if there is still entry in the current list.
	 *
	 * Note that list_next points to a kernel address and we need to
	 * compare list_next with the kernel address of the list head.
	 * So we need to calculate the address manually.
	 */
	if ((char *)entry.nse_link.list_next != khead + offsetof(list_t,
	    list_head)) {
		wsp->walk_addr = (uintptr_t)list_object(&head,
		    entry.nse_link.list_next);
		return (WALK_NEXT);
	}

	/* Start with the next bucket in the array. */
	next_entry = NULL;
	for (i++; i < ilbs->ilbs_nat_src_hash_size; i++) {
		khead = (char *)ilbs->ilbs_nat_src + i *
		    sizeof (ilb_nat_src_hash_t);
		if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_nat_src at %p\n", khead);
			return (WALK_ERR);
		}

		if ((char *)head.list_head.list_next != khead +
		    offsetof(list_t, list_head)) {
			next_entry = list_object(&head,
			    head.list_head.list_next);
			break;
		}
	}

	if (next_entry == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)next_entry;
	ns_walk->idx = i;
	return (WALK_NEXT);
}

static void
ilb_common_walk_fini(mdb_walk_state_t *wsp)
{
	ilb_walk_t *walk;

	walk = (ilb_walk_t *)wsp->walk_data;
	if (walk == NULL)
		return;
	mdb_free(walk, sizeof (ilb_walk_t *));
}

static int
ilb_conn_walk_init(mdb_walk_state_t *wsp)
{
	int i;
	ilb_walk_t *conn_walk;
	ilb_conn_hash_t head;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	conn_walk = mdb_alloc(sizeof (ilb_walk_t), UM_SLEEP);
	if (mdb_vread(&conn_walk->ilbs, sizeof (conn_walk->ilbs),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_stack_t at %p", wsp->walk_addr);
		mdb_free(conn_walk, sizeof (ilb_walk_t));
		return (WALK_ERR);
	}

	if (conn_walk->ilbs.ilbs_c2s_conn_hash == NULL) {
		mdb_free(conn_walk, sizeof (ilb_walk_t));
		return (WALK_DONE);
	}

	wsp->walk_data = conn_walk;
	for (i = 0; i < conn_walk->ilbs.ilbs_conn_hash_size; i++) {
		char *khead;

		/* Read in the nsh_head in the i-th element of the array. */
		khead = (char *)conn_walk->ilbs.ilbs_c2s_conn_hash + i *
		    sizeof (ilb_conn_hash_t);
		if (mdb_vread(&head, sizeof (ilb_conn_hash_t),
		    (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_c2s_conn_hash at %p\n",
			    khead);
			return (WALK_ERR);
		}

		if (head.ilb_connp != NULL)
			break;
	}

	if (head.ilb_connp == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)head.ilb_connp;
	conn_walk->idx = i;
	return (WALK_NEXT);
}

static int
ilb_conn_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	ilb_conn_t conn;
	ilb_walk_t *conn_walk;
	ilb_stack_t *ilbs;
	ilb_conn_hash_t head;
	char *khead;
	int i;

	if (mdb_vread(&conn, sizeof (ilb_conn_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_conn_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &conn, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	conn_walk = (ilb_walk_t *)wsp->walk_data;
	ilbs = &conn_walk->ilbs;
	i = conn_walk->idx;

	/* Check if there is still entry in the current list. */
	if (conn.conn_c2s_next != NULL) {
		wsp->walk_addr = (uintptr_t)conn.conn_c2s_next;
		return (WALK_NEXT);
	}

	/* Start with the next bucket in the array. */
	for (i++; i < ilbs->ilbs_conn_hash_size; i++) {
		khead = (char *)ilbs->ilbs_c2s_conn_hash + i *
		    sizeof (ilb_conn_hash_t);
		if (mdb_vread(&head, sizeof (ilb_conn_hash_t),
		    (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_c2s_conn_hash at %p\n",
			    khead);
			return (WALK_ERR);
		}

		if (head.ilb_connp != NULL)
			break;
	}

	if (head.ilb_connp == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)head.ilb_connp;
	conn_walk->idx = i;
	return (WALK_NEXT);
}

static int
ilb_sticky_walk_init(mdb_walk_state_t *wsp)
{
	int i;
	ilb_walk_t *sticky_walk;
	ilb_sticky_t *st = NULL;

	if (wsp->walk_addr == NULL)
		return (WALK_ERR);

	sticky_walk = mdb_alloc(sizeof (ilb_walk_t), UM_SLEEP);
	if (mdb_vread(&sticky_walk->ilbs, sizeof (sticky_walk->ilbs),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_stack_t at %p", wsp->walk_addr);
		mdb_free(sticky_walk, sizeof (ilb_walk_t));
		return (WALK_ERR);
	}

	if (sticky_walk->ilbs.ilbs_sticky_hash == NULL) {
		mdb_free(sticky_walk, sizeof (ilb_walk_t));
		return (WALK_DONE);
	}

	wsp->walk_data = sticky_walk;
	for (i = 0; i < sticky_walk->ilbs.ilbs_sticky_hash_size; i++) {
		list_t head;
		char *khead;

		/* Read in the nsh_head in the i-th element of the array. */
		khead = (char *)sticky_walk->ilbs.ilbs_sticky_hash + i *
		    sizeof (ilb_sticky_hash_t);
		if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_sticky_hash at %p\n",
			    khead);
			return (WALK_ERR);
		}

		/*
		 * Note that list_next points to a kernel address and we need
		 * to compare list_next with the kernel address of the list
		 * head.  So we need to calculate the address manually.
		 */
		if ((char *)head.list_head.list_next != khead +
		    offsetof(list_t, list_head)) {
			st = list_object(&head, head.list_head.list_next);
			break;
		}
	}

	if (st == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)st;
	sticky_walk->idx = i;
	return (WALK_NEXT);
}

static int
ilb_sticky_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	ilb_sticky_t st, *st_next;
	ilb_walk_t *sticky_walk;
	ilb_stack_t *ilbs;
	list_t head;
	char *khead;
	int i;

	if (mdb_vread(&st, sizeof (ilb_sticky_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ilb_sticky_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &st, wsp->walk_cbdata);
	if (status != WALK_NEXT)
		return (status);

	sticky_walk = (ilb_walk_t *)wsp->walk_data;
	ilbs = &sticky_walk->ilbs;
	i = sticky_walk->idx;

	/* Read in the nsh_head in the i-th element of the array. */
	khead = (char *)ilbs->ilbs_sticky_hash + i * sizeof (ilb_sticky_hash_t);
	if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
		mdb_warn("failed to read ilbs_sticky_hash at %p\n", khead);
		return (WALK_ERR);
	}

	/*
	 * Check if there is still entry in the current list.
	 *
	 * Note that list_next points to a kernel address and we need to
	 * compare list_next with the kernel address of the list head.
	 * So we need to calculate the address manually.
	 */
	if ((char *)st.list.list_next != khead + offsetof(list_t,
	    list_head)) {
		wsp->walk_addr = (uintptr_t)list_object(&head,
		    st.list.list_next);
		return (WALK_NEXT);
	}

	/* Start with the next bucket in the array. */
	st_next = NULL;
	for (i++; i < ilbs->ilbs_nat_src_hash_size; i++) {
		khead = (char *)ilbs->ilbs_sticky_hash + i *
		    sizeof (ilb_sticky_hash_t);
		if (mdb_vread(&head, sizeof (list_t), (uintptr_t)khead) == -1) {
			mdb_warn("failed to read ilbs_sticky_hash at %p\n",
			    khead);
			return (WALK_ERR);
		}

		if ((char *)head.list_head.list_next != khead +
		    offsetof(list_t, list_head)) {
			st_next = list_object(&head,
			    head.list_head.list_next);
			break;
		}
	}

	if (st_next == NULL)
		return (WALK_DONE);

	wsp->walk_addr = (uintptr_t)st_next;
	sticky_walk->idx = i;
	return (WALK_NEXT);
}
