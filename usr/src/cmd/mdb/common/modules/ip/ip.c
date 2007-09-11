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

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/avl_impl.h>
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

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#define	ADDR_WIDTH 11

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

typedef struct th_walk_data {
	uint_t		thw_non_zero_only;
	boolean_t	thw_match;
	uintptr_t	thw_matchkey;
	uintptr_t	thw_ipst;
	clock_t		thw_lbolt;
} th_walk_data_t;

static int iphdr(uintptr_t, uint_t, int, const mdb_arg_t *);
static int ip6hdr(uintptr_t, uint_t, int, const mdb_arg_t *);

static int ire_format(uintptr_t addr, const ire_t *irep, uint_t *verbose);

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

int
ip_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

int
ip_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	netstack_t nss;

#ifdef DEBUG
	mdb_printf("DEBUG: ip_stacks_walk_step: addr %p\n", wsp->walk_addr);
#endif
	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	kaddr = (uintptr_t)nss.netstack_modules[NS_IP];

#ifdef DEBUG
	mdb_printf("DEBUG: ip_stacks_walk_step: ip_stack_t at %p\n", kaddr);
#endif
	return (wsp->walk_callback(kaddr, wsp->walk_layer, wsp->walk_cbdata));
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
illif_walk_init(mdb_walk_state_t *wsp)
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

#ifdef DEBUG
	mdb_printf("DEBUG: illif_walk_step: addr %p\n", wsp->walk_addr);
#endif

	kaddr = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ill_g_heads);

	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr);
		return (WALK_ERR);
	}
#ifdef DEBUG
	mdb_printf("DEBUG: illif_walk_step: ips_ill_g_heads %p\n", kaddr);
#endif

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
ire_walk_init(mdb_walk_state_t *wsp)
{
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

	return (wsp->walk_callback(wsp->walk_addr, &ire, wsp->walk_cbdata));
}

int
ire_ctable_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("ip_stacks", wsp) == -1) {
		mdb_warn("can't walk 'ip_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
ire_ctable_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t kaddr;
	irb_t *irb;
	int verbose = 0;
	uint32_t cache_table_size;
	int i;

#ifdef DEBUG
	mdb_printf("DEBUG: ire_ctable_walk_step: addr %p\n", wsp->walk_addr);
#endif

	kaddr = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ip_cache_table_size);

	if (mdb_vread(&cache_table_size, sizeof (uint32_t), kaddr) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr);
		return (WALK_ERR);
	}
#ifdef DEBUG
	mdb_printf("DEBUG: ire_ctable_walk_step: ips_ip_cache_table_size %u\n",
	    cache_table_size);
#endif

	kaddr = wsp->walk_addr + OFFSETOF(ip_stack_t, ips_ip_cache_table);
	if (mdb_vread(&kaddr, sizeof (kaddr), kaddr) == -1) {
		mdb_warn("can't read ips_ip_cache_table at %p", kaddr);
		return (WALK_ERR);
	}
#ifdef DEBUG
	mdb_printf("DEBUG: ire_ctable_walk_step: ips_ip_cache_table %p\n",
	    kaddr);
#endif

	irb = mdb_alloc(sizeof (irb_t) * cache_table_size, UM_SLEEP|UM_GC);
	if (mdb_vread(irb, sizeof (irb_t) * cache_table_size, kaddr) == -1) {
		mdb_warn("can't read irb at %p", kaddr);
		return (WALK_ERR);
	}
	for (i = 0; i < cache_table_size; i++) {
		kaddr = (uintptr_t)irb[i].irb_ire;
#ifdef DEBUG
		mdb_printf("DEBUG: ire_ctable_walk_step: %d ire %p\n",
		    i, kaddr);
#endif

		if (mdb_pwalk("ire_next", (mdb_walk_cb_t)ire_format, &verbose,
		    kaddr) == -1) {
			mdb_warn("can't walk 'ire_next' for ire %p", kaddr);
			return (WALK_ERR);
		}
	}
	return (WALK_NEXT);
}

/* ARGSUSED */
int
ire_next_walk_init(mdb_walk_state_t *wsp)
{
#ifdef DEBUG
	mdb_printf("DEBUG: ire_next_walk_init: addr %p\n", wsp->walk_addr);
#endif
	return (WALK_NEXT);
}

int
ire_next_walk_step(mdb_walk_state_t *wsp)
{
	ire_t ire;
	int status;

#ifdef DEBUG
	mdb_printf("DEBUG: ire_next_walk_step: addr %p\n", wsp->walk_addr);
#endif

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
#ifdef DEBUG
	mdb_printf("DEBUG: ire_ctable_walk_step: next %p\n", wsp->walk_addr);
#endif
	return (status);
}

static int
ire_format(uintptr_t addr, const ire_t *irep, uint_t *verbose)
{
	static const mdb_bitmask_t tmasks[] = {
		{ "BROADCAST",	IRE_BROADCAST,		IRE_BROADCAST	},
		{ "DEFAULT",	IRE_DEFAULT,		IRE_DEFAULT	},
		{ "LOCAL",	IRE_LOCAL,		IRE_LOCAL	},
		{ "LOOPBACK",	IRE_LOOPBACK,		IRE_LOOPBACK	},
		{ "PREFIX",	IRE_PREFIX,		IRE_PREFIX	},
		{ "CACHE",	IRE_CACHE,		IRE_CACHE	},
		{ "IF_NORESOLVER", IRE_IF_NORESOLVER,	IRE_IF_NORESOLVER },
		{ "IF_RESOLVER", IRE_IF_RESOLVER,	IRE_IF_RESOLVER	},
		{ "HOST",	IRE_HOST,		IRE_HOST	},
		{ "HOST_REDIRECT", IRE_HOST_REDIRECT,	IRE_HOST_REDIRECT },
		{ NULL,		0,			0		}
	};

	static const mdb_bitmask_t mmasks[] = {
		{ "CONDEMNED",	IRE_MARK_CONDEMNED,	IRE_MARK_CONDEMNED },
		{ "NORECV",	IRE_MARK_NORECV,	IRE_MARK_NORECV	},
		{ "HIDDEN",	IRE_MARK_HIDDEN,	IRE_MARK_HIDDEN	},
		{ "NOADD",	IRE_MARK_NOADD,		IRE_MARK_NOADD	},
		{ "TEMPORARY",	IRE_MARK_TEMPORARY,	IRE_MARK_TEMPORARY },
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
		{ NULL,		0,			0		}
	};

	if (irep->ire_ipversion == 6 && *verbose) {

		mdb_printf("%<b>%?p%</b> %40N <%hb>\n"
		    "%?s %40N <%hb>\n"
		    "%?s %40d %4d <%hb>\n",
		    addr, &irep->ire_src_addr_v6, irep->ire_type, tmasks,
		    "", &irep->ire_addr_v6, (ushort_t)irep->ire_marks, mmasks,
		    "", ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid,
		    irep->ire_flags, fmasks);

	} else if (irep->ire_ipversion == 6) {

		mdb_printf("%?p %30N %30N %5d %4d\n",
		    addr, &irep->ire_src_addr_v6,
		    &irep->ire_addr_v6,
		    ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid);

	} else if (*verbose) {

		mdb_printf("%<b>%?p%</b> %40I <%hb>\n"
		    "%?s %40I <%hb>\n"
		    "%?s %40d <%hb>\n",
		    addr, irep->ire_src_addr, irep->ire_type, tmasks,
		    "", irep->ire_addr, (ushort_t)irep->ire_marks, mmasks,
		    "", ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid, irep->ire_flags, fmasks);

	} else {

		mdb_printf("%?p %30I %30I %5d %4d\n", addr, irep->ire_src_addr,
		    irep->ire_addr, ips_to_stackid((uintptr_t)irep->ire_ipst),
		    irep->ire_zoneid);
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

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&tcph, sizeof (tcph), addr) == -1) {
		mdb_warn("failed to read TCP header at %p", addr);
		return (DCMD_ERR);
	}
	tcphdr_print(&tcph);
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
ire(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t verbose = FALSE;
	ire_t ire;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {

		if (verbose) {
			mdb_printf("%?s %40s %-20s%\n"
			    "%?s %40s %-20s%\n"
			    "%<u>%?s %40s %4s %-20s%</u>\n",
			    "ADDR", "SRC", "TYPE",
			    "", "DST", "MARKS",
			    "", "STACK", "ZONE", "FLAGS");
		} else {
			mdb_printf("%<u>%?s %30s %30s %5s %4s%</u>\n",
			    "ADDR", "SRC", "DST", "STACK", "ZONE");
		}
	}

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&ire, sizeof (ire_t), addr);
		(void) ire_format(addr, &ire, &verbose);
	} else if (mdb_walk("ire", (mdb_walk_cb_t)ire_format, &verbose) == -1) {
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
		if (mdb_readvar(&thw.thw_lbolt,
		    mdb_prop_postmortem ? "panic_lbolt" : "lbolt") == -1) {
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
	mdb_printf("If given an address of an ill_t, ipif_t, ire_t, or nce_t, "
	    "print the\n"
	    "corresponding th_trace_t structure in detail.  Otherwise, if no "
	    "address is\n"
	    "given, then summarize all th_trace_t structures.\n\n");
	mdb_printf("Options:\n"
	    "\t-n\tdisplay only entries with non-zero th_refcnt\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "illif", "?[-P v4 | v6]",
	    "display or filter IP Lower Level InterFace structures", illif,
	    illif_help },
	{ "iphdr", ":[-vf]", "display an IPv4 header", iphdr },
	{ "ip6hdr", ":[-vf]", "display an IPv6 header", ip6hdr },
	{ "ire", "?[-v]", "display Internet Route Entry structures", ire },
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
	{ "illif", "walk list of ill interface types for all stacks",
		illif_walk_init, illif_walk_step, NULL },
	{ "illif_stack", "walk list of ill interface types",
		illif_stack_walk_init, illif_stack_walk_step,
		illif_stack_walk_fini },
	{ "ire", "walk active ire_t structures",
		ire_walk_init, ire_walk_step, NULL },
	{ "ire_ctable", "walk ire_t structures in the ctable",
		ire_ctable_walk_init, ire_ctable_walk_step, NULL },
	{ "ire_next", "walk ire_t structures in the ctable",
		ire_next_walk_init, ire_next_walk_step, NULL },
	{ "ip_stacks", "walk all the ip_stack_t",
		ip_stacks_walk_init, ip_stacks_walk_step, NULL },
	{ "th_hash", "walk all the th_hash_t entries",
		th_hash_walk_init, th_hash_walk_step, NULL },
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
