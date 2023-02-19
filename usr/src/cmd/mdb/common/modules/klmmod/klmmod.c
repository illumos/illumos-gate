/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/vnode.h>
#include <stddef.h>
#include <nfs/rnode.h>
#include <limits.h>
#include <nfs/lm.h>
#include <sys/flock_impl.h>
#include <mdb/mdb_ks.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>
#include <rpcsvc/nsm_addr.h>

#include "klm/nlm_impl.h"

#define	NLM_MAXNAMELEN	256
#define	NLM_MAXADDRSTR	64

/*
 * ****************************************************************
 * Helper functions
 */

/*
 * Helper to get printable IP address into a buffer.
 * Used by nlm_host_dcmd
 */
static int
nlm_netbuf_str(char *buf, size_t bufsz, const struct netbuf *nb)
{
	struct sockaddr_storage sa;
	struct sockaddr_in *s_in;
	struct sockaddr_in6 *s_in6;
	uint_t salen = nb->len;
	in_port_t port;

	if (salen < sizeof (sa_family_t))
		return (-1);
	if (salen > sizeof (sa))
		salen = sizeof (sa);
	if (mdb_vread(&sa, salen, (uintptr_t)nb->buf) < 0)
		return (-1);

	switch (sa.ss_family) {
	case AF_INET:
		s_in = (struct sockaddr_in *)(void *)&sa;
		mdb_nhconvert(&port, &s_in->sin_port, sizeof (port));
		mdb_snprintf(buf, bufsz, "%I/%d",
		    s_in->sin_addr.s_addr, port);
		break;

	case AF_INET6:
		s_in6 = (struct sockaddr_in6 *)(void *)&sa;
		mdb_nhconvert(&port, &s_in6->sin6_port, sizeof (port));
		mdb_snprintf(buf, bufsz, "%N/%d",
		    &(s_in6->sin6_addr), port);
		break;

	default:
		mdb_printf("AF_%d", sa.ss_family);
		break;
	}

	return (0);
}

/*
 * Get the name for an enum value
 */
static void
get_enum(char *obuf, size_t size, const char *type_str, int val,
    const char *prefix)
{
	mdb_ctf_id_t type_id;
	const char *cp;

	if (mdb_ctf_lookup_by_name(type_str, &type_id) != 0)
		goto errout;
	if (mdb_ctf_type_resolve(type_id, &type_id) != 0)
		goto errout;
	if ((cp = mdb_ctf_enum_name(type_id, val)) == NULL)
		goto errout;
	if (prefix != NULL) {
		size_t len = strlen(prefix);
		if (strncmp(cp, prefix, len) == 0)
			cp += len;
	}
	(void) strlcpy(obuf, cp, size);
	return;

errout:
	mdb_snprintf(obuf, size, "? (%d)", val);
}

static const mdb_bitmask_t
host_flag_bits[] = {
	{
		"MONITORED",
		NLM_NH_MONITORED,
		NLM_NH_MONITORED },
	{
		"RECLAIM",
		NLM_NH_RECLAIM,
		NLM_NH_RECLAIM },
	{
		"INIDLE",
		NLM_NH_INIDLE,
		NLM_NH_INIDLE },
	{
		"SUSPEND",
		NLM_NH_SUSPEND,
		NLM_NH_SUSPEND },
	{
		NULL, 0, 0 }
};

/*
 * ****************************************************************
 * NLM zones (top level)
 */

/*
 * nlm_zone walker implementation
 */

int
nlm_zone_walk_init(mdb_walk_state_t *wsp)
{

	/*
	 * Technically, this is "cheating" with the knowledge that
	 * the TAILQ_HEAD link is at the beginning of this object.
	 */
	if (wsp->walk_addr == 0 && mdb_readsym(&wsp->walk_addr,
	    sizeof (wsp->walk_addr), "nlm_zones_list") == -1) {
		mdb_warn("failed to read 'nlm_zones_list'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nlm_zone_walk_step(mdb_walk_state_t *wsp)
{
	struct nlm_globals g;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&g, sizeof (g), addr) < 0) {
		mdb_warn("failed to read nlm_globals at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&g, nlm_link);
	return (wsp->walk_callback(addr, &g, wsp->walk_cbdata));
}

/*
 * nlm_zone dcmd implementation
 */

static void nlm_zone_print(uintptr_t, const struct nlm_globals *, uint_t);

void
nlm_zone_help(void)
{
	mdb_printf("-v		verbose information\n");
}

int
nlm_zone_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_globals g;
	char enum_val[32];
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("requires addr of nlm_zone");
		return (DCMD_ERR);
	}

	if (mdb_vread(&g, sizeof (g), addr) == -1) {
		mdb_warn("failed to read nlm_globals at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_v == FALSE) {
		nlm_zone_print(addr, &g, flags);
		return (DCMD_OK);
	}

	/*
	 * Print verbose format
	 */
	mdb_printf("%<b>%<u>NLM zone globals (%p):%</u>%</b>\n", addr);
	mdb_printf(" Lockd PID: %u\n", g.lockd_pid);
	get_enum(enum_val, sizeof (enum_val),
	    "nlm_run_status_t", g.run_status, "NLM_S_");
	mdb_printf("Run status: %d (%s)\n", g.run_status, enum_val);
	mdb_printf(" NSM state: %d\n", g.nsm_state);

	return (DCMD_OK);
}

/*
 * Shared by nlm_zone_dcmd and nlm_list_zone_cb
 * Print a zone (nlm_globals) summary line.
 */
static void
nlm_zone_print(uintptr_t addr, const struct nlm_globals *g, uint_t flags)
{

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(
		    "%<b>%<u>%?-s  %-16s %</u>%</b>\n",
		    "nlm_globals", "pid");
	}

	mdb_printf("%-?p %6d\n", addr, (int)g->lockd_pid);
}

/*
 * ****************************************************************
 * NLM hosts (under zones)
 */

/*
 * nlm_host walker implementation
 */

int
nlm_host_walk_init(mdb_walk_state_t *wsp)
{
	static int avl_off = -1;

	if (wsp->walk_addr == 0) {
		mdb_printf("requires address of struct nlm_globals\n");
		return (WALK_ERR);
	}

	/*
	 * Need the address of the nlm_hosts_tree AVL head
	 * within the nlm_globals, for the AVL walker.
	 */
	if (avl_off < 0) {
		avl_off = mdb_ctf_offsetof_by_name(
		    "struct nlm_globals", "nlm_hosts_tree");
	}
	if (avl_off < 0) {
		mdb_warn("cannot lookup: nlm_globals .nlm_hosts_tree");
		return (WALK_ERR);
	}
	wsp->walk_addr += avl_off;

	if (mdb_layered_walk("avl", wsp) == -1) {
		mdb_warn("failed to walk nlm_globals .nlm_hosts_tree");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nlm_host_walk_step(mdb_walk_state_t *wsp)
{
	struct nlm_host nh;
	uintptr_t addr = wsp->walk_addr;

	if (mdb_vread(&nh, sizeof (nh), addr) < 0) {
		mdb_warn("failed to read nlm_host at %p", addr);
		return (WALK_ERR);
	}

	/* layered walk avl */
	return (wsp->walk_callback(wsp->walk_addr, &nh,
	    wsp->walk_cbdata));
}

/*
 * nlm_host dcmd implementation
 */

static void nlm_host_print(uintptr_t, const struct nlm_host *,
    char *, char *, uint_t);

void
nlm_host_help(void)
{
	mdb_printf("-v       verbose information\n");
}

int
nlm_host_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_host nh;
	char hname[NLM_MAXNAMELEN];
	char haddr[NLM_MAXADDRSTR];
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("requires addr of nlm_host");
		return (DCMD_ERR);
	}

	/* Get the nlm_host */
	if (mdb_vread(&nh, sizeof (nh), addr) == -1) {
		mdb_warn("failed to read nlm_host at %p", addr);
		return (DCMD_ERR);
	}

	/* Get its name and address */
	if (mdb_readstr(hname, sizeof (hname),
	    (uintptr_t)nh.nh_name) < 0)
		strlcpy(hname, "?", sizeof (hname));
	if (nlm_netbuf_str(haddr, sizeof (haddr), &nh.nh_addr) < 0)
		strlcpy(haddr, "?", sizeof (haddr));

	if (opt_v == FALSE) {
		nlm_host_print(addr, &nh, hname, haddr, flags);
		return (DCMD_OK);
	}

	/*
	 * Print verbose format
	 */

	mdb_printf("%<b>%<u>NLM host (%p):%</u>%</b>\n", addr);

	mdb_printf("Refcnt: %u\n", nh.nh_refs);
	mdb_printf(" Sysid: %d\n", (int)nh.nh_sysid);
	mdb_printf("  Name: %s\n", hname);
	mdb_printf("  Addr: %s\n", haddr);
	mdb_printf(" State: %d\n", nh.nh_state);
	mdb_printf(" Flags: 0x%x <%b>\n",
	    nh.nh_flags, nh.nh_flags, host_flag_bits);
	mdb_printf("Vholds: %?p\n", nh.nh_vholds_list.tqh_first);

	return (DCMD_OK);
}

/*
 * Shared by nlm_host_dcmd and nlm_list_host_cb
 * Print an nlm_host summary line.
 */
static void
nlm_host_print(uintptr_t addr, const struct nlm_host *nh,
    char *hname, char *haddr, uint_t flags)
{
	int hname_width = 20;

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-?s %-*s%10s %6s ", "nlm_host",
		    hname_width, "name", "refs", "sysid");
		mdb_printf("%s%</u>%</b>\n", "net_addr");
	}

	mdb_printf("%?p %-*s%10i %6hi %s\n",
	    addr, hname_width, hname,
	    nh->nh_refs, nh->nh_sysid, haddr);
}

/*
 * ****************************************************************
 * NLM vholds (under hosts)
 */

/*
 * nlm_vhold walker implementation
 */

int
nlm_vhold_walk_init(mdb_walk_state_t *wsp)
{
	struct nlm_vhold_list head;
	uintptr_t addr;
	static int head_off = -1;

	if (wsp->walk_addr == 0) {
		mdb_printf("requires address of struct nlm_host\n");
		return (WALK_ERR);
	}

	/* Get offset of the list head and read it. */
	if (head_off < 0) {
		head_off = mdb_ctf_offsetof_by_name(
		    "struct nlm_host", "nh_vholds_list");
	}
	if (head_off < 0) {
		mdb_warn("cannot lookup: nlm_host .nh_vholds_list");
		return (WALK_ERR);
	}

	addr = wsp->walk_addr + head_off;
	if (mdb_vread(&head, sizeof (head), addr) < 0) {
		mdb_warn("cannot read nlm_host at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)head.tqh_first;
	return (WALK_NEXT);
}

int
nlm_vhold_walk_step(mdb_walk_state_t *wsp)
{
	struct nlm_vhold nv;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&nv, sizeof (nv), addr) < 0) {
		mdb_warn("failed to read nlm_vhold at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)nv.nv_link.tqe_next;
	return (wsp->walk_callback(addr, &nv, wsp->walk_cbdata));
}

/*
 * nlm_vhold dcmd implementation
 */

static void nlm_vhold_print(uintptr_t, const struct nlm_vhold *, uint_t);

void
nlm_vhold_help(void)
{
	mdb_printf("-v       verbose information\n");
}

int
nlm_vhold_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_vhold nv;
	char path_buf[MAXPATHLEN];
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("requires addr of nlm_vhold");
		return (DCMD_ERR);
	}

	if (mdb_vread(&nv, sizeof (nv), addr) == -1) {
		mdb_warn("failed to read nlm_vhold at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_v == FALSE) {
		nlm_vhold_print(addr, &nv, flags);
		return (DCMD_OK);
	}

	/*
	 * Print verbose format
	 */

	if (nv.nv_vp == NULL || mdb_vnode2path((uintptr_t)nv.nv_vp,
	    path_buf, sizeof (path_buf)) != 0)
		strlcpy(path_buf, "?", sizeof (path_buf));

	mdb_printf("%<b>%<u>NLM vhold (%p):%</u>%</b>\n", addr);

	mdb_printf("Refcnt: %u\n", nv.nv_refcnt);
	mdb_printf(" Vnode: %?p (%s)\n", nv.nv_vp, path_buf);
	mdb_printf(" Slreq: %?p\n", nv.nv_slreqs.tqh_first);

	return (DCMD_OK);
}

/*
 * Shared by nlm_vhold_dcmd and nlm_list_vnode_cb
 * Print an nlm_vhold summary line.
 */
static void
nlm_vhold_print(uintptr_t addr, const struct nlm_vhold *nv, uint_t flags)
{

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-?s %10s %-?s %-?s%</u>%</b>\n",
		    "nlm_vhold", "refcnt", "vnode", "slreq");
	}

	mdb_printf("%?p %10i %?p %?-p\n",
	    addr, nv->nv_refcnt, nv->nv_vp,
	    nv->nv_slreqs.tqh_first);
}

/*
 * ****************************************************************
 * NLM slreqs (under vhold)
 */

/*
 * nlm_slreq walker implementation
 */

int
nlm_slreq_walk_init(mdb_walk_state_t *wsp)
{
	struct nlm_slreq_list head;
	uintptr_t addr;
	static int head_off = -1;

	if (wsp->walk_addr == 0) {
		mdb_printf("requires address of struct nlm_vhold\n");
		return (WALK_ERR);
	}

	/* Get offset of the list head and read it. */
	if (head_off < 0) {
		head_off = mdb_ctf_offsetof_by_name(
		    "struct nlm_vhold", "nv_slreqs");
	}
	if (head_off < 0) {
		mdb_warn("cannot lookup: nlm_vhold .nv_slreqs");
		return (WALK_ERR);
	}

	addr = wsp->walk_addr + head_off;
	if (mdb_vread(&head, sizeof (head), addr) < 0) {
		mdb_warn("cannot read nlm_vhold at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)head.tqh_first;
	return (WALK_NEXT);
}

int
nlm_slreq_walk_step(mdb_walk_state_t *wsp)
{
	struct nlm_slreq nsr;
	uintptr_t addr = wsp->walk_addr;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&nsr, sizeof (nsr), addr) < 0) {
		mdb_warn("failed to read nlm_slreq at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)nsr.nsr_link.tqe_next;
	return (wsp->walk_callback(addr, &nsr, wsp->walk_cbdata));
}

/*
 * nlm_slreq dcmd implementation
 */

static void nlm_slreq_print(uintptr_t, const struct nlm_slreq *, uint_t);

void
nlm_slreq_help(void)
{
	mdb_printf("-v       verbose information\n");
}

int
nlm_slreq_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_slreq nsr;
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_warn("requires addr of nlm_slreq");
		return (DCMD_ERR);
	}

	if (mdb_vread(&nsr, sizeof (nsr), addr) == -1) {
		mdb_warn("failed to read nlm_slreq at %p", addr);
		return (DCMD_ERR);
	}

	if (opt_v == FALSE) {
		nlm_slreq_print(addr, &nsr, flags);
		return (DCMD_OK);
	}

	/*
	 * Print verbose format
	 */

	mdb_printf("%<b>%<u>NLM slreq (%p):%</u>%</b>\n", addr);

	mdb_printf(" type: %d (%s)\n", nsr.nsr_fl.l_type,
	    (nsr.nsr_fl.l_type == F_RDLCK) ? "RD" :
	    (nsr.nsr_fl.l_type == F_WRLCK) ? "WR" : "??");
	mdb_printf("sysid: %d\n", nsr.nsr_fl.l_sysid);
	mdb_printf("  pid: %d\n", nsr.nsr_fl.l_pid);
	mdb_printf("start: %lld\n", nsr.nsr_fl.l_start);
	mdb_printf("  len: %lld\n", nsr.nsr_fl.l_len);

	return (DCMD_OK);
}

/*
 * Shared by nlm_slreq_dcmd and nlm_list_slreq_cb
 * Print an nlm_slreq summary line.
 */
static void
nlm_slreq_print(uintptr_t addr, const struct nlm_slreq *nsr, uint_t flags)
{

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-?s %4s %5s %3s %6s %6s%</u>%</b>\n",
		    "nlm_slreq", "type", "sysid", "pid", "start", "len");
	}

	mdb_printf(
	    "%?p %4d %5d %3d %6lld %6lld\n",
	    addr,
	    nsr->nsr_fl.l_type,
	    nsr->nsr_fl.l_sysid,
	    nsr->nsr_fl.l_pid,
	    nsr->nsr_fl.l_start,
	    nsr->nsr_fl.l_len);
}

/*
 * ****************************************************************
 */

/*
 * nlm_list dcmd implementation
 *
 * This is a fancy command command to walk the whole NLM
 * data hierarchy, skipping uninteresting elements.
 */

#define	NLM_LIST_DEPTH_HOSTS	1	/* just hosts */
#define	NLM_LIST_DEPTH_VHOLDS	2	/* host and vholds */
#define	NLM_LIST_DEPTH_SLREQS	3	/* sleeping lock requests */
#define	NLM_LIST_DEPTH_DEFAULT	3	/* default: show all */

struct nlm_list_arg {
	uint_t	opt_v;
	uint_t	opt_a;
	uint_t	depth;
	int	sysid;
	char	*host;
	uint_t	zone_flags;
	uint_t	host_flags;
	uint_t	vhold_flags;
	uint_t	slreq_flags;
	char	namebuf[NLM_MAXNAMELEN];
	char	addrbuf[NLM_MAXADDRSTR];
};

static int nlm_list_zone_cb(uintptr_t, const void *, void *);
static int nlm_list_host_cb(uintptr_t, const void *, void *);
static int nlm_list_vhold_cb(uintptr_t, const void *, void *);
static int nlm_list_slreq_cb(uintptr_t, const void *, void *);

void
nlm_list_help(void)
{
	mdb_printf("-v		verbose information\n");
	mdb_printf("-a		include idle hosts\n");
	mdb_printf("-d depth	recursion depth (zones, hosts, ...)\n");
	mdb_printf("-h host	filter by host name\n");
	mdb_printf("-s sysid	filter by sysid (0tnnn for decimal)\n");
}

int
nlm_list_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_list_arg *arg;
	uintptr_t depth = NLM_LIST_DEPTH_DEFAULT;
	char *host = NULL;
	char *sysid = NULL;

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	arg = mdb_zalloc(sizeof (*arg), UM_SLEEP | UM_GC);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &arg->opt_v,
	    'a', MDB_OPT_SETBITS, TRUE, &arg->opt_a,
	    'd', MDB_OPT_UINTPTR, &depth,
	    'h', MDB_OPT_STR, &host,
	    's', MDB_OPT_STR, &sysid,
	    NULL) != argc)
		return (DCMD_USAGE);

	arg->depth = (uint_t)depth;
	arg->sysid = -1;
	if (host != NULL)
		arg->host = host;
	if (sysid != NULL) {
		arg->sysid = (int)mdb_strtoull(sysid);
		if (arg->sysid < 1) {
			mdb_warn("invalid sysid");
			arg->sysid = -1;
		}
	}

	/* Specifying host or sysid id implies -a */
	if (arg->host != NULL || arg->sysid >= 0)
		arg->opt_a = TRUE;

	arg->zone_flags = (DCMD_LOOP | DCMD_LOOPFIRST);
	if (mdb_pwalk("nlm_zone", nlm_list_zone_cb, arg, 0)) {
		mdb_warn("cannot walk nlm_zone list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/* Called for each zone's nlm_globals */
static int
nlm_list_zone_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_list_arg *arg = cb_data;
	const struct nlm_globals *g = data;

	/* Add zone filtering? */

	/*
	 * Summary line for a struct nlm_globals
	 */
	nlm_zone_print(addr, g, 0);
	arg->zone_flags &= ~DCMD_LOOPFIRST;

	if (arg->depth >= NLM_LIST_DEPTH_HOSTS) {
		(void) mdb_inc_indent(2);
		arg->host_flags = (DCMD_LOOP | DCMD_LOOPFIRST);
		if (mdb_pwalk("nlm_host", nlm_list_host_cb, arg, addr) != 0) {
			mdb_warn("failed to walk hosts for zone %p", addr);
			/* keep going */
		}
		(void) mdb_dec_indent(2);
	}

	return (WALK_NEXT);
}

/* Called for each nlm_host */
static int
nlm_list_host_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_list_arg *arg = cb_data;
	const struct nlm_host *nh = data;

	/* Get the host name and net addr. */
	if (mdb_readstr(arg->namebuf, NLM_MAXNAMELEN,
	    (uintptr_t)nh->nh_name) < 0)
		(void) strlcpy(arg->namebuf, "?", sizeof (char));
	if (nlm_netbuf_str(arg->addrbuf, NLM_MAXADDRSTR, &nh->nh_addr) < 0)
		(void) strlcpy(arg->addrbuf, "?", sizeof (char));

	/* Filter out uninteresting hosts */
	if (arg->opt_a == 0 && nh->nh_refs == 0)
		return (WALK_NEXT);
	if (arg->sysid != -1 && arg->sysid != (nh->nh_sysid & LM_SYSID_MAX))
		return (WALK_NEXT);
	if (arg->host != NULL && strcmp(arg->host, arg->namebuf) != 0)
		return (WALK_NEXT);

	/*
	 * Summary line for struct nlm_host
	 */
	nlm_host_print(addr, nh, arg->namebuf, arg->addrbuf,
	    arg->host_flags);
	arg->host_flags &= ~DCMD_LOOPFIRST;

	if (arg->depth >= NLM_LIST_DEPTH_VHOLDS) {
		(void) mdb_inc_indent(2);
		arg->vhold_flags = (DCMD_LOOP | DCMD_LOOPFIRST);
		if (mdb_pwalk("nlm_vhold", nlm_list_vhold_cb, arg, addr)) {
			mdb_warn("failed to walk vholds for host %p", addr);
			/* keep going */
		}
		(void) mdb_dec_indent(2);
	}

	/*
	 * We printed some hosts, so tell nlm_list_zone_cb to
	 * print its header line again.
	 */
	arg->zone_flags |= DCMD_LOOPFIRST;

	return (WALK_NEXT);
}

/* Called for each nlm_vhold */
static int
nlm_list_vhold_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_list_arg *arg = cb_data;
	const struct nlm_vhold *nv = data;

	/* Filter out uninteresting vholds */
	if (arg->opt_a == 0 && nv->nv_refcnt == 0)
		return (WALK_NEXT);

	/*
	 * Summary line for struct nlm_vhold
	 */
	nlm_vhold_print(addr, nv, arg->vhold_flags);
	arg->vhold_flags &= ~DCMD_LOOPFIRST;

	if (arg->depth >= NLM_LIST_DEPTH_SLREQS) {
		(void) mdb_inc_indent(2);
		arg->slreq_flags = (DCMD_LOOP | DCMD_LOOPFIRST);
		if (mdb_pwalk("nlm_slreq", nlm_list_slreq_cb, arg, addr)) {
			mdb_warn("failed to walk slreqs for vhold %p", addr);
			/* keep going */
		}
		(void) mdb_dec_indent(2);
	}

	/*
	 * We printed some vholds, so tell nlm_list_host_cb to
	 * print its header line again.
	 */
	arg->host_flags |= DCMD_LOOPFIRST;

	return (WALK_NEXT);
}

/* Called for each nlm_slreq */
static int
nlm_list_slreq_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_list_arg *arg = cb_data;
	const struct nlm_slreq *nv = data;

	/*
	 * Summary line for struct nlm_slreq
	 */
	nlm_slreq_print(addr, nv, arg->slreq_flags);
	arg->slreq_flags &= ~DCMD_LOOPFIRST;

	/*
	 * We printed some slreqs, so tell nlm_list_vhold_cb to
	 * print its header line again.
	 */
	arg->vhold_flags |= DCMD_LOOPFIRST;

	return (WALK_NEXT);
}

/*
 * ****************************************************************
 */

/*
 * nlm_lockson dcmd implementation
 * Walk the lock_graph, filtered by sysid
 */

struct nlm_locks_arg {
	/* dcmd options */
	uint_t	opt_v;
	int	sysid;
	char	*host;
	/* callback vars */
	uint_t	flags;
	int	lg_sysid;
	char	namebuf[NLM_MAXNAMELEN];
	char	addrbuf[NLM_MAXADDRSTR];
	char	pathbuf[PATH_MAX];
};

static int nlm_locks_zone_cb(uintptr_t, const void *, void *);
static int nlm_locks_host_cb(uintptr_t, const void *, void *);
static int nlm_lockson_cb(uintptr_t, const void *, void *c);

void
nlm_lockson_help(void)
{
	mdb_printf("-v		verbose information\n");
	mdb_printf("-h host	filter by host name\n");
	mdb_printf("-s sysid	filter by sysid (0tnnn for decimal)\n");
}

int
nlm_lockson_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_locks_arg *arg;
	char *host = NULL;
	char *sysid = NULL;

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	arg = mdb_zalloc(sizeof (*arg), UM_SLEEP | UM_GC);

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &arg->opt_v,
	    'h', MDB_OPT_STR, &host,
	    's', MDB_OPT_STR, &sysid,
	    NULL) != argc)
		return (DCMD_USAGE);

	arg->sysid = -1;
	if (host != NULL)
		arg->host = host;
	if (sysid != NULL) {
		arg->sysid = (int)mdb_strtoull(sysid);
		if (arg->sysid < 1) {
			mdb_warn("invalid sysid");
			arg->sysid = -1;
		}
	}

	if (mdb_pwalk("nlm_zone", nlm_locks_zone_cb, arg, 0)) {
		mdb_warn("cannot walk nlm_zone list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/* Called for each zone's nlm_globals */
static int
nlm_locks_zone_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_locks_arg *arg = cb_data;
	(void) data;

	/*
	 * No filtering here. Don't even print zone addr.
	 * Just run the host list walker.
	 */
	if (mdb_pwalk("nlm_host", nlm_locks_host_cb, arg, addr) != 0) {
		mdb_warn("failed to walk hosts for zone %p", addr);
		/* keep going */
	}

	return (WALK_NEXT);
}

/* Called for each nlm_host */
static int
nlm_locks_host_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_locks_arg *arg = cb_data;
	const struct nlm_host *nh = data;

	/* Get the host name and net addr. */
	if (mdb_readstr(arg->namebuf, NLM_MAXNAMELEN,
	    (uintptr_t)nh->nh_name) < 0)
		(void) strlcpy(arg->namebuf, "?", sizeof (char));
	if (nlm_netbuf_str(arg->addrbuf, NLM_MAXADDRSTR, &nh->nh_addr) < 0)
		(void) strlcpy(arg->addrbuf, "?", sizeof (char));

	/* Filter out uninteresting hosts */
	if (arg->sysid != -1 && arg->sysid != (nh->nh_sysid & LM_SYSID_MAX))
		return (WALK_NEXT);
	if (arg->host != NULL && strcmp(arg->host, arg->namebuf) != 0)
		return (WALK_NEXT);

	/*
	 * Summary line for struct nlm_host
	 */
	nlm_host_print(addr, nh, arg->namebuf, arg->addrbuf, 0);

	/*
	 * We run the lock_graph walker for every sysid, and the callback
	 * uses arg->lg_sysid to filter graph elements.  Set that from
	 * the host we're visiting now.
	 */
	arg->lg_sysid = (int)nh->nh_sysid;
	arg->flags = (DCMD_LOOP | DCMD_LOOPFIRST);
	if (mdb_pwalk("lock_graph", nlm_lockson_cb, arg, 0) < 0) {
		mdb_warn("failed to walk lock_graph");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
nlm_lockson_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_locks_arg *arg = cb_data;
	const lock_descriptor_t *ld = data;
	proc_t p;
	int local, sysid;
	int host_width = 16;
	char *s;

	local = ld->l_flock.l_sysid & LM_SYSID_CLIENT;
	sysid = ld->l_flock.l_sysid & LM_SYSID_MAX;

	if (arg->lg_sysid != sysid)
		return (WALK_NEXT);

	if (DCMD_HDRSPEC(arg->flags)) {
		mdb_printf("%<b>%<u>%-?s %-*s %5s(x) %-?s %-6s %-*s %-*s type",
		    "lock_addr", host_width, "host", "sysid", "vnode", "pid",
		    MAXCOMLEN, "cmd", arg->opt_v ? 9 : 5, "state");

		if (arg->opt_v)
			mdb_printf("%-11s srvstat %-10s", "(width)", "path");

		mdb_printf("%</u>%</b>\n");
	}
	arg->flags &= ~DCMD_LOOPFIRST;

	mdb_printf("%?p %-*s %5hi(%c) %?p %-6i %-*s ",
	    addr, host_width, arg->namebuf,
	    sysid, local ? 'L' : 'R', ld->l_vnode,
	    ld->l_flock.l_pid, MAXCOMLEN,
	    ld->l_flock.l_pid == 0 ? "<kernel>"
	    : !local ? "<remote>"
	    : mdb_pid2proc(ld->l_flock.l_pid, &p) == 0 ? "<defunct>"
	    : p.p_user.u_comm);

	if (arg->opt_v) {
		switch (ld->l_status) {
		case FLK_INITIAL_STATE:
			s = "init";
			break;
		case FLK_START_STATE:
			s = "execute";
			break;
		case FLK_ACTIVE_STATE:
			s = "active";
			break;
		case FLK_SLEEPING_STATE:
			s = "blocked";
			break;
		case FLK_GRANTED_STATE:
			s = "granted";
			break;
		case FLK_INTERRUPTED_STATE:
			s = "interrupt";
			break;
		case FLK_CANCELLED_STATE:
			s = "cancel";
			break;
		case FLK_DEAD_STATE:
			s = "done";
			break;
		default:
			s = "??";
			break;
		}
		mdb_printf("%-9s", s);
	} else {
		mdb_printf("%-5i", ld->l_status);
	}

	mdb_printf(" %-2s", ld->l_type == F_RDLCK ? "RD"
	    : ld->l_type == F_WRLCK ? "WR" : "??");


	if (!arg->opt_v) {
		mdb_printf("\n");
		return (WALK_NEXT);
	}

	switch (GET_NLM_STATE(ld)) {
	case FLK_NLM_UP:
		s = "up";
		break;
	case FLK_NLM_SHUTTING_DOWN:
		s = "halting";
		break;
	case FLK_NLM_DOWN:
		s = "down";
		break;
	case FLK_NLM_UNKNOWN:
		s = "unknown";
		break;
	default:
		s = "??";
		break;
	}

	mdb_printf("(%5i:%-5i) %-7s ", ld->l_start, ld->l_len, s);
	if (mdb_vnode2path((uintptr_t)ld->l_vnode,
	    arg->pathbuf, PATH_MAX) == -1)
		strlcpy(arg->pathbuf, "??", PATH_MAX);
	mdb_printf("%s\n", arg->pathbuf);

	return (WALK_NEXT);
}


static const mdb_walker_t walkers[] = {
	{
		"nlm_zone", "nlm_zone walker",
		nlm_zone_walk_init, nlm_zone_walk_step
	},
	{
		"nlm_host", "nlm_host walker",
		nlm_host_walk_init, nlm_host_walk_step
	},
	{
		"nlm_vhold", "nlm_vhold walker",
		nlm_vhold_walk_init, nlm_vhold_walk_step
	},
	{
		"nlm_slreq", "nlm_slreq walker",
		nlm_slreq_walk_init, nlm_slreq_walk_step
	},
	{NULL, NULL, NULL, NULL}
};

static const mdb_dcmd_t dcmds[] = {
	{
		"nlm_zone", "?[-v]",
		"dump per-zone nlm_globals",
		nlm_zone_dcmd, nlm_zone_help
	},
	{
		"nlm_host", "?[-v]",
		"dump nlm_host structures (hosts/sysids)",
		nlm_host_dcmd, nlm_host_help
	},
	{
		"nlm_vhold", "?[-v]",
		"dump nlm_vhold structures (vnode holds)",
		nlm_vhold_dcmd, nlm_vhold_help
	},
	{
		"nlm_slreq", "?[-v]",
		"dump nlm_slreq structures (sleeping lock requests)",
		nlm_slreq_dcmd, nlm_slreq_help
	},
	{
		"nlm_list", "[-v][-a][-d depth][-h host][-s 0tSysID]",
		"list all zones, optionally filter hosts ",
		nlm_list_dcmd, nlm_list_help
	},
	{
		"nlm_lockson", "[-v] [-h host] [-s 0tSysID]",
		"dump NLM locks from host (or sysid)",
		nlm_lockson_dcmd, nlm_lockson_help
	},
	{NULL, NULL, NULL, NULL}
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
