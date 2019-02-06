/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/socket.h>
#include <net/if.h>
#define	SOL2
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <net/sppptun.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sppp/sppp.h>
#include <sppptun/sppptun_impl.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <stdio.h>

/* ****************** sppp ****************** */

static int
sppp_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_readvar(&wsp->walk_addr, "sps_list") == -1) {
		mdb_warn("failed to read sps_list");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
sppp_walk_step(mdb_walk_state_t *wsp)
{
	spppstr_t sps;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&sps, sizeof (sps), wsp->walk_addr) == -1) {
		mdb_warn("can't read spppstr_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = (wsp->walk_callback(wsp->walk_addr, &sps, wsp->walk_cbdata));

	wsp->walk_addr = (uintptr_t)sps.sps_nextmn;
	return (status);
}

static int
sps_format(uintptr_t addr, const spppstr_t *sps, uint_t *qfmt)
{
	sppa_t ppa;
	queue_t upq;
	uintptr_t upaddr, illaddr;
	ill_t ill;
	ipif_t ipif;

	mdb_printf("%?p ", addr);
	if (*qfmt)
		mdb_printf("%?p ", sps->sps_rq);
	if (sps->sps_ppa == NULL) {
		mdb_printf("?       unset     ");
	} else if (mdb_vread(&ppa, sizeof (ppa), (uintptr_t)sps->sps_ppa) ==
	    -1) {
		mdb_printf("?      ?%p ", sps->sps_ppa);
	} else {
		mdb_printf("%-6d sppp%-5d ", ppa.ppa_zoneid, ppa.ppa_ppa_id);
	}
	if (IS_SPS_CONTROL(sps)) {
		mdb_printf("Control\n");
	} else if (IS_SPS_PIOATTACH(sps)) {
		mdb_printf("Stats\n");
	} else if (sps->sps_dlstate == DL_UNATTACHED) {
		mdb_printf("Unknown\n");
	} else if (sps->sps_dlstate != DL_IDLE) {
		mdb_printf("DLPI Unbound\n");
	} else {
		upaddr = (uintptr_t)sps->sps_rq;
		upq.q_ptr = NULL;
		illaddr = 0;
		while (upaddr != 0) {
			if (mdb_vread(&upq, sizeof (upq), upaddr) == -1) {
				upq.q_ptr = NULL;
				break;
			}
			if ((upaddr = (uintptr_t)upq.q_next) != 0)
				illaddr = (uintptr_t)upq.q_ptr;
		}
		if (illaddr != 0) {
			if (mdb_vread(&ill, sizeof (ill), illaddr) == -1 ||
			    mdb_vread(&ipif, sizeof (ipif),
			    (uintptr_t)ill.ill_ipif) == -1) {
				illaddr = 0;
			}
		}

		switch (sps->sps_req_sap) {
		case ETHERTYPE_IP:
			mdb_printf("DLPI IPv4 ");
			if (*qfmt) {
				mdb_printf("\n");
			} else if (illaddr == 0) {
				mdb_printf("(no addresses)\n");
			} else {
				/*
				 * SCCS oddity here -- % <capital> %
				 * suffers from keyword replacement.
				 * Avoid that by using ANSI string
				 * pasting.
				 */
				mdb_printf("%I:%I" "%s\n",
				    ipif.ipif_lcl_addr, ipif.ipif_pp_dst_addr,
				    (ipif.ipif_next ? " ..." : ""));
			}
			break;
		case ETHERTYPE_IPV6:
			mdb_printf("DLPI IPv6 ");
			if (*qfmt) {
				mdb_printf("\n");
				break;
			}
			if (illaddr == 0) {
				mdb_printf("(no addresses)\n");
				break;
			}
			mdb_printf("%N\n%?s%21s", &ipif.ipif_v6lcl_addr,
			    "", "");
			mdb_printf("%N\n", &ipif.ipif_v6pp_dst_addr);
			break;
		case ETHERTYPE_ALLSAP:
			mdb_printf("DLPI Snoop\n");
			break;
		default:
			mdb_printf("DLPI SAP 0x%04X\n", sps->sps_req_sap);
			break;
		}
	}

	return (WALK_NEXT);
}

static int
sppp(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t qfmt = FALSE;
	spppstr_t sps;

	if (mdb_getopts(argc, argv, 'q', MDB_OPT_SETBITS, TRUE, &qfmt, NULL) !=
	    argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		if (qfmt) {
			mdb_printf("%<u>%?s %?s %-6s %-9s %s%</u>\n", "Address",
			    "RecvQ", "ZoneID", "Interface", "Type");
		} else {
			mdb_printf("%<u>%?s %-6s %-9s %s%</u>\n", "Address",
			    "ZoneID", "Interface", "Type");
		}
	}

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&sps, sizeof (sps), addr);
		(void) sps_format(addr, &sps, &qfmt);
	} else if (mdb_walk("sppp", (mdb_walk_cb_t)sps_format, &qfmt) == -1) {
		mdb_warn("failed to walk sps_list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
sppa_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_readvar(&wsp->walk_addr, "ppa_list") == -1) {
		mdb_warn("failed to read ppa_list");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
sppa_walk_step(mdb_walk_state_t *wsp)
{
	sppa_t ppa;
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&ppa, sizeof (ppa), wsp->walk_addr) == -1) {
		mdb_warn("can't read spppstr_t at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = (wsp->walk_callback(wsp->walk_addr, &ppa, wsp->walk_cbdata));

	wsp->walk_addr = (uintptr_t)ppa.ppa_nextppa;
	return (status);
}

/* ARGSUSED */
static int
ppa_format(uintptr_t addr, const sppa_t *ppa, uint_t *qfmt)
{
	mdb_printf("%?p %-6d sppp%-5d %?p %?p\n", addr, ppa->ppa_zoneid,
	    ppa->ppa_ppa_id, ppa->ppa_ctl, ppa->ppa_lower_wq);

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
sppa(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t qfmt = FALSE;
	sppa_t ppa;

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %-6s %-9s %?s %?s%</u>\n", "Address",
		    "ZoneID", "Interface", "Control", "LowerQ");
	}

	if (flags & DCMD_ADDRSPEC) {
		(void) mdb_vread(&ppa, sizeof (ppa), addr);
		(void) ppa_format(addr, &ppa, &qfmt);
	} else if (mdb_walk("sppa", (mdb_walk_cb_t)ppa_format, &qfmt) == -1) {
		mdb_warn("failed to walk ppa_list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static void
sppp_qinfo(const queue_t *q, char *buf, size_t nbytes)
{
	spppstr_t sps;
	sppa_t ppa;

	if (mdb_vread(&sps, sizeof (sps), (uintptr_t)q->q_ptr) ==
	    sizeof (sps)) {
		if (sps.sps_ppa == NULL ||
		    mdb_vread(&ppa, sizeof (ppa), (uintptr_t)sps.sps_ppa) ==
		    -1) {
			(void) mdb_snprintf(buf, nbytes, "minor %d",
			    sps.sps_mn_id);
		} else {
			(void) mdb_snprintf(buf, nbytes, "sppp%d",
			    ppa.ppa_ppa_id);
		}
	}
}

static uintptr_t
sppp_rnext(const queue_t *q)
{
	spppstr_t sps;

	if (mdb_vread(&sps, sizeof (sps), (uintptr_t)q->q_ptr) == sizeof (sps))
		return ((uintptr_t)sps.sps_rq);

	return (0);
}

static uintptr_t
sppp_wnext(const queue_t *q)
{
	spppstr_t sps;
	sppa_t ppa;

	if (mdb_vread(&sps, sizeof (sps), (uintptr_t)q->q_ptr) != sizeof (sps))
		return (0);

	if (sps.sps_ppa != NULL &&
	    mdb_vread(&ppa, sizeof (ppa), (uintptr_t)sps.sps_ppa) ==
	    sizeof (ppa))
		return ((uintptr_t)ppa.ppa_lower_wq);

	return (0);
}

/* ****************** sppptun ****************** */

struct tcl_walk_data {
	size_t tcl_nslots;
	size_t walkpos;
	tuncl_t *tcl_slots[1];
};

static void
tuncl_walk_fini(mdb_walk_state_t *wsp)
{
	struct tcl_walk_data *twd;

	if (wsp != NULL && wsp->walk_addr != 0) {
		twd = (struct tcl_walk_data *)wsp->walk_addr;
		mdb_free(twd, sizeof (*twd) + ((twd->tcl_nslots - 1) *
		    sizeof (twd->tcl_slots[0])));
		wsp->walk_addr = 0;
	}
}

static int
tuncl_walk_init(mdb_walk_state_t *wsp)
{
	size_t tcl_nslots;
	tuncl_t **tcl_slots;
	struct tcl_walk_data *twd;

	if (wsp == NULL)
		return (WALK_ERR);

	if (wsp->walk_addr != 0)
		tuncl_walk_fini(wsp);

	if (mdb_readvar(&tcl_nslots, "tcl_nslots") == -1) {
		mdb_warn("failed to read tcl_nslots");
		return (WALK_ERR);
	}

	if (tcl_nslots == 0)
		return (WALK_DONE);

	if (mdb_readvar(&tcl_slots, "tcl_slots") == -1) {
		mdb_warn("failed to read tcl_slots");
		return (WALK_ERR);
	}

	twd = (struct tcl_walk_data *)mdb_alloc(sizeof (*twd) +
	    (tcl_nslots - 1) * sizeof (*tcl_slots), UM_NOSLEEP);
	if (twd == NULL)
		return (WALK_ERR);
	twd->tcl_nslots = tcl_nslots;
	twd->walkpos = 0;
	wsp->walk_addr = (uintptr_t)twd;

	if (mdb_vread(twd->tcl_slots, tcl_nslots * sizeof (twd->tcl_slots[0]),
	    (uintptr_t)tcl_slots) == -1) {
		mdb_warn("can't read tcl_slots at %p", tcl_slots);
		tuncl_walk_fini(wsp);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
tuncl_walk_step(mdb_walk_state_t *wsp)
{
	tuncl_t tcl;
	int status;
	struct tcl_walk_data *twd;
	uintptr_t addr;

	if (wsp == NULL || wsp->walk_addr == 0)
		return (WALK_DONE);

	twd = (struct tcl_walk_data *)wsp->walk_addr;

	while (twd->walkpos < twd->tcl_nslots &&
	    twd->tcl_slots[twd->walkpos] == NULL)
		twd->walkpos++;
	if (twd->walkpos >= twd->tcl_nslots)
		return (WALK_DONE);

	addr = (uintptr_t)twd->tcl_slots[twd->walkpos];
	if (mdb_vread(&tcl, sizeof (tcl), addr) == -1) {
		mdb_warn("can't read tuncl_t at %p", addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(addr, &tcl, wsp->walk_cbdata);

	twd->walkpos++;
	return (status);
}

/* ARGSUSED */
static int
tuncl_format(uintptr_t addr, const tuncl_t *tcl, uint_t *qfmt)
{
	mdb_printf("%?p %-6d %?p %?p", addr, tcl->tcl_zoneid, tcl->tcl_data_tll,
	    tcl->tcl_ctrl_tll);
	mdb_printf(" %-2d %04X %04X ", tcl->tcl_style,
	    tcl->tcl_lsessid, tcl->tcl_rsessid);
	if (tcl->tcl_flags & TCLF_DAEMON) {
		mdb_printf("<daemon>\n");
	} else {
		mdb_printf("sppp%d\n", tcl->tcl_unit);
	}

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
tuncl(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t qfmt = FALSE;
	tuncl_t tcl;

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %-6s %?s %?s Ty LSes RSes %s%</u>\n",
		    "Address", "ZoneID", "Data", "Control", "Interface");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&tcl, sizeof (tcl), addr) == -1)
			mdb_warn("failed to read tuncl_t at %p", addr);
		else
			tuncl_format(addr, &tcl, &qfmt);
	} else if (mdb_walk("tuncl", (mdb_walk_cb_t)tuncl_format, &qfmt) ==
	    -1) {
		mdb_warn("failed to walk tcl_slots");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

struct tll_walk_data {
	void *listhead;
	void *next;
};

static void
tunll_walk_fini(mdb_walk_state_t *wsp)
{
	struct tll_walk_data *twd;

	if (wsp != NULL && wsp->walk_addr != 0) {
		twd = (struct tll_walk_data *)wsp->walk_addr;
		mdb_free(twd, sizeof (*twd));
		wsp->walk_addr = 0;
	}
}

static int
tunll_walk_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	struct tll_walk_data *twd;
	struct qelem tunll_list;

	if (wsp->walk_addr != 0)
		tunll_walk_fini(wsp);

	if (mdb_lookup_by_obj("sppptun", "tunll_list", &sym) != 0) {
		mdb_warn("failed to find tunll_list");
		return (WALK_ERR);
	}

	if (mdb_vread(&tunll_list, sizeof (tunll_list),
	    (uintptr_t)sym.st_value) == -1) {
		mdb_warn("can't read tunll_list at %p",
		    (uintptr_t)sym.st_value);
		return (WALK_ERR);
	}

	twd = (struct tll_walk_data *)mdb_alloc(sizeof (*twd), UM_NOSLEEP);
	if (twd == NULL)
		return (WALK_ERR);
	twd->listhead = (void *)(uintptr_t)sym.st_value;
	twd->next = (void *)tunll_list.q_forw;
	wsp->walk_addr = (uintptr_t)twd;

	return (WALK_NEXT);
}

static int
tunll_walk_step(mdb_walk_state_t *wsp)
{
	struct tll_walk_data *twd;
	tunll_t tll;
	int status;
	uintptr_t addr;

	if (wsp == NULL || wsp->walk_addr == 0)
		return (WALK_DONE);

	twd = (struct tll_walk_data *)wsp->walk_addr;
	if (twd->next == NULL || twd->next == twd->listhead)
		return (WALK_DONE);

	/* LINTED */
	addr = (uintptr_t)TO_TLL(twd->next);
	if (mdb_vread(&tll, sizeof (tll), addr) == -1) {
		mdb_warn("can't read tunll_t at %p", addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(addr, &tll, wsp->walk_cbdata);

	twd->next = (void *)tll.tll_next;
	return (status);
}

/* ARGSUSED */
static int
tunll_format(uintptr_t addr, const tunll_t *tll, uint_t *qfmt)
{
	mdb_printf("%?p %-6d %-14s %?p", addr, tll->tll_zoneid, tll->tll_name,
	    tll->tll_defcl);
	if (tll->tll_style == PTS_PPPOE) {
		mdb_printf(" %x:%x:%x:%x:%x:%x",
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[0],
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[1],
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[2],
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[3],
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[4],
		    tll->tll_lcladdr.pta_pppoe.ptma_mac[5]);
	}
	mdb_printf("\n");

	return (WALK_NEXT);
}

/* ARGSUSED */
static int
tunll(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t qfmt = FALSE;
	tunll_t tll;

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %-6s %-14s %?s %s%</u>\n", "Address",
		    "ZoneID", "Interface Name", "Daemon", "Local Address");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&tll, sizeof (tll), addr) == -1)
			mdb_warn("failed to read tunll_t at %p", addr);
		else
			tunll_format(addr, &tll, &qfmt);
	} else if (mdb_walk("tunll", (mdb_walk_cb_t)tunll_format, &qfmt) ==
	    -1) {
		mdb_warn("failed to walk tunll_list");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

union tun_state {
	uint32_t tunflags;
	tuncl_t tcl;
	tunll_t tll;
};

static int
tun_state_read(void *ptr, union tun_state *ts)
{
	/*
	 * First, get the flags on this structure.  This is either a
	 * tuncl_t or a tunll_t.
	 */
	if (mdb_vread(&ts->tunflags, sizeof (ts->tunflags), (uintptr_t)ptr) ==
	    sizeof (ts->tunflags)) {
		if (ts->tunflags & TCLF_ISCLIENT) {
			if (mdb_vread(&ts->tcl, sizeof (ts->tcl),
			    (uintptr_t)ptr) == sizeof (ts->tcl)) {
				return (0);
			}
		} else {
			if (mdb_vread(&ts->tll, sizeof (ts->tll),
			    (uintptr_t)ptr) == sizeof (ts->tll)) {
				return (0);
			}
		}
	}
	return (-1);
}

static void
sppptun_qinfo(const queue_t *q, char *buf, size_t nbytes)
{
	union tun_state ts;

	if (tun_state_read(q->q_ptr, &ts) == -1)
		return;

	if (ts.tcl.tcl_flags & TCLF_ISCLIENT)
		mdb_snprintf(buf, nbytes, "sppp%d client %04X",
		    ts.tcl.tcl_unit, ts.tcl.tcl_lsessid);
	else
		mdb_snprintf(buf, nbytes, "%s", ts.tll.tll_name);
}

static uintptr_t
sppptun_rnext(const queue_t *q)
{
	union tun_state ts;

	if (tun_state_read(q->q_ptr, &ts) == -1)
		return (0);

	if (ts.tcl.tcl_flags & TCLF_ISCLIENT) {
		return ((uintptr_t)ts.tcl.tcl_rq);
	} else {
		/* Not quite right, but ... */
		return ((uintptr_t)ts.tll.tll_defcl);
	}
}

static uintptr_t
sppptun_wnext(const queue_t *q)
{
	union tun_state ts;

	if (tun_state_read(q->q_ptr, &ts) == -1)
		return (0);

	if (ts.tcl.tcl_flags & TCLF_ISCLIENT) {
		if (ts.tcl.tcl_data_tll == NULL)
			return (0);
		if (mdb_vread(&ts.tll, sizeof (ts.tll),
		    (uintptr_t)ts.tcl.tcl_data_tll) != sizeof (ts.tll)) {
			return (0);
		}
	}
	return ((uintptr_t)ts.tll.tll_wq);
}

static const mdb_dcmd_t dcmds[] = {
	{ "sppp", "[-q]", "display PPP stream state structures", sppp },
	{ "sppa", "", "display PPP attachment state structures", sppa },
	{ "tuncl", "", "display sppptun client stream state structures",
	    tuncl },
	{ "tunll", "", "display sppptun lower stream state structures",
	    tunll },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "sppp", "walk active spppstr_t structures",
	    sppp_walk_init, sppp_walk_step, NULL },
	{ "sppa", "walk active sppa_t structures",
	    sppa_walk_init, sppa_walk_step, NULL },
	{ "tuncl", "walk active tuncl_t structures",
	    tuncl_walk_init, tuncl_walk_step, tuncl_walk_fini },
	{ "tunll", "walk active tunll_t structures",
	    tunll_walk_init, tunll_walk_step, tunll_walk_fini },
	{ NULL }
};

static const mdb_qops_t sppp_qops = { sppp_qinfo, sppp_rnext, sppp_wnext };
static const mdb_qops_t sppptun_qops = {
	sppptun_qinfo, sppptun_rnext, sppptun_wnext
};
static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("sppp", "sppp_uwinit", &sym) == 0)
		mdb_qops_install(&sppp_qops, (uintptr_t)sym.st_value);

	if (mdb_lookup_by_obj("sppptun", "sppptun_uwinit", &sym) == 0)
		mdb_qops_install(&sppptun_qops, (uintptr_t)sym.st_value);

	return (&modinfo);
}

void
_mdb_fini(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("sppptun", "sppptun_uwinit", &sym) == 0)
		mdb_qops_remove(&sppptun_qops, (uintptr_t)sym.st_value);

	if (mdb_lookup_by_obj("sppp", "sppp_uwinit", &sym) == 0)
		mdb_qops_remove(&sppp_qops, (uintptr_t)sym.st_value);
}
