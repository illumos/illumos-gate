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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/hook.h>
#include <sys/hook_event.h>
#include <inet/led.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/arp.h>
#include <inet/arp_impl.h>
#include <inet/ip.h>
#include <netinet/arp.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

typedef struct {
	uint32_t	act_cmd;
	char		*act_name;
	char		*act_type;
} arp_cmd_tbl;

/*
 * Table of ARP commands and structure types used for messages between ARP and
 * IP.
 */
static const arp_cmd_tbl act_list[] = {
	{ AR_ENTRY_ADD,		"AR_ENTRY_ADD",		"arp`area_t" },
	{ AR_ENTRY_DELETE,	"AR_ENTRY_DELETE",	"arp`ared_t" },
	{ AR_ENTRY_QUERY,	"AR_ENTRY_QUERY",	"arp`areq_t" },
	{ AR_ENTRY_SQUERY,	"AR_ENTRY_SQUERY",	"arp`area_t" },
	{ AR_MAPPING_ADD,	"AR_MAPPING_ADD",	"arp`arma_t" },
	{ AR_CLIENT_NOTIFY,	"AR_CLIENT_NOTIFY",	"arp`arcn_t" },
	{ AR_INTERFACE_UP,	"AR_INTERFACE_UP",	"arp`arc_t" },
	{ AR_INTERFACE_DOWN,	"AR_INTERFACE_DOWN",	"arp`arc_t" },
	{ AR_INTERFACE_ON,	"AR_INTERFACE_ON",	"arp`arc_t" },
	{ AR_INTERFACE_OFF,	"AR_INTERFACE_OFF",	"arp`arc_t" },
	{ AR_DLPIOP_DONE,	"AR_DLPIOP_DONE",	"arp`arc_t" },
	{ AR_ARP_CLOSING,	"AR_ARP_CLOSING",	"arp`arc_t" },
	{ AR_ARP_EXTEND,	"AR_ARP_EXTEND",	"arp`arc_t" },
	{ 0,			"unknown command",	"arp`arc_t" }
};

/*
 * State information kept during walk over ACE hash table and unhashed mask
 * list.
 */
typedef struct ace_walk_data {
	ace_t *awd_hash_tbl[ARP_HASH_SIZE];
	ace_t *awd_masks;
	int awd_idx;
} ace_walk_data_t;

/*
 * Given the kernel address of an arl_t, return the stackid
 */
static int
arl_to_stackid(uintptr_t addr)
{
	arl_t arl;
	queue_t rq;
	ar_t ar;
	arp_stack_t ass;
	netstack_t nss;

	if (mdb_vread(&arl, sizeof (arl), addr) == -1) {
		mdb_warn("failed to read arl_t %p", addr);
		return (0);
	}

	addr = (uintptr_t)arl.arl_rq;
	if (mdb_vread(&rq, sizeof (rq), addr) == -1) {
		mdb_warn("failed to read queue_t %p", addr);
		return (0);
	}

	addr = (uintptr_t)rq.q_ptr;
	if (mdb_vread(&ar, sizeof (ar), addr) == -1) {
		mdb_warn("failed to read ar_t %p", addr);
		return (0);
	}

	addr = (uintptr_t)ar.ar_as;
	if (mdb_vread(&ass, sizeof (ass), addr) == -1) {
		mdb_warn("failed to read arp_stack_t %p", addr);
		return (0);
	}
	addr = (uintptr_t)ass.as_netstack;
	if (mdb_vread(&nss, sizeof (nss), addr) == -1) {
		mdb_warn("failed to read netstack_t %p", addr);
		return (0);
	}
	return (nss.netstack_stackid);
}

static int
arp_stacks_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("netstack", wsp) == -1) {
		mdb_warn("can't walk 'netstack'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
arp_stacks_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	netstack_t nss;

	if (mdb_vread(&nss, sizeof (nss), wsp->walk_addr) == -1) {
		mdb_warn("can't read netstack at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	addr = (uintptr_t)nss.netstack_modules[NS_ARP];

	return (wsp->walk_callback(addr, wsp->walk_layer, wsp->walk_cbdata));
}

static int
arl_stack_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("arl_stack supports only local walks\n");
		return (WALK_ERR);
	}

	addr = wsp->walk_addr + OFFSETOF(arp_stack_t, as_arl_head);
	if (mdb_vread(&wsp->walk_addr, sizeof (wsp->walk_addr),
	    addr) == -1) {
		mdb_warn("failed to read 'arl_g_head'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static int
arl_stack_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	arl_t arl;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&arl, sizeof (arl), addr) == -1) {
		mdb_warn("failed to read arl_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)arl.arl_next;

	return ((*wsp->walk_callback)(addr, &arl, wsp->walk_cbdata));
}

static int
arl_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("arp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'arp_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
arl_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("arl_stack", wsp->walk_callback,
		wsp->walk_cbdata, wsp->walk_addr) == -1) {
		mdb_warn("couldn't walk 'arl_stack' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Called with walk_addr being the address of arp_stack_t
 */
static int
ace_stack_walk_init(mdb_walk_state_t *wsp)
{
	ace_walk_data_t *aw;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("ace_stack supports only local walks\n");
		return (WALK_ERR);
	}

	aw = mdb_alloc(sizeof (ace_walk_data_t), UM_SLEEP);

	addr = wsp->walk_addr + OFFSETOF(arp_stack_t, as_ce_hash_tbl);
	if (mdb_vread(aw->awd_hash_tbl, sizeof (aw->awd_hash_tbl),
	    addr) == -1) {
		mdb_warn("failed to read 'as_ce_hash_tbl'");
		mdb_free(aw, sizeof (ace_walk_data_t));
		return (WALK_ERR);
	}

	addr = wsp->walk_addr + OFFSETOF(arp_stack_t, as_ce_mask_entries);
	if (mdb_vread(&aw->awd_masks, sizeof (aw->awd_masks),
	    addr) == -1) {
		mdb_warn("failed to read 'as_ce_mask_entries'");
		mdb_free(aw, sizeof (ace_walk_data_t));
		return (WALK_ERR);
	}

	/* The step routine will start off by incrementing to index 0 */
	aw->awd_idx = -1;
	wsp->walk_addr = 0;
	wsp->walk_data = aw;

	return (WALK_NEXT);
}

static int
ace_stack_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	ace_walk_data_t *aw = wsp->walk_data;
	ace_t ace;

	/*
	 * If we're at the end of the previous list, then find the start of the
	 * next list to process.
	 */
	while (wsp->walk_addr == NULL) {
		if (aw->awd_idx == ARP_HASH_SIZE)
			return (WALK_DONE);
		if (++aw->awd_idx == ARP_HASH_SIZE) {
			wsp->walk_addr = (uintptr_t)aw->awd_masks;
		} else {
			wsp->walk_addr =
			    (uintptr_t)aw->awd_hash_tbl[aw->awd_idx];
		}
	}

	addr = wsp->walk_addr;
	if (mdb_vread(&ace, sizeof (ace), addr) == -1) {
		mdb_warn("failed to read ace_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)ace.ace_next;

	return (wsp->walk_callback(addr, &ace, wsp->walk_cbdata));
}

static void
ace_stack_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (ace_walk_data_t));
}

static int
ace_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk("arp_stacks", wsp) == -1) {
		mdb_warn("can't walk 'arp_stacks'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
ace_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_pwalk("ace_stack", wsp->walk_callback,
		wsp->walk_cbdata, wsp->walk_addr) == -1) {
		mdb_warn("couldn't walk 'ace_stack' at %p", wsp->walk_addr);
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}


/* Common routine to produce an 'ar' text description */
static void
ar_describe(const ar_t *ar, char *buf, size_t nbytes, boolean_t addmac)
{
	if (ar->ar_arl == NULL) {
		queue_t wq, ipq;
		ill_t ill;
		char name[LIFNAMSIZ];
		GElf_Sym sym;
		boolean_t nextip;

		if (mdb_vread(&wq, sizeof (wq), (uintptr_t)ar->ar_wq) == -1 ||
		    mdb_vread(&ipq, sizeof (ipq), (uintptr_t)wq.q_next) == -1)
			return;

		nextip =
		    (mdb_lookup_by_obj("ip", "ipwinit", &sym) == 0 &&
		    (uintptr_t)sym.st_value == (uintptr_t)ipq.q_qinfo);

		if (!ar->ar_on_ill_stream) {
			(void) strcpy(buf, nextip ? "Client" : "Unknown");
			return;
		}

		if (!nextip ||
		    mdb_vread(&ill, sizeof (ill), (uintptr_t)ipq.q_ptr) == -1 ||
		    mdb_readstr(name, sizeof (name),
		    (uintptr_t)ill.ill_name) == -1) {
			return;
		}
		(void) mdb_snprintf(buf, nbytes, "IP %s", name);
	} else {
		arl_t arl;
		arlphy_t ap;
		ssize_t retv;
		uint32_t alen;
		uchar_t macaddr[ARP_MAX_ADDR_LEN];

		if (mdb_vread(&arl, sizeof (arl), (uintptr_t)ar->ar_arl) == -1)
			return;
		retv = mdb_snprintf(buf, nbytes, "ARP %s ", arl.arl_name);
		if (retv >= nbytes || !addmac)
			return;
		if (mdb_vread(&ap, sizeof (ap), (uintptr_t)arl.arl_phy) == -1)
			return;
		alen = ap.ap_hw_addrlen;
		if (ap.ap_hw_addr == NULL || alen == 0 ||
		    alen > sizeof (macaddr))
			return;
		if (mdb_vread(macaddr, alen, (uintptr_t)ap.ap_hw_addr) == -1)
			return;
		mdb_mac_addr(macaddr, alen, buf + retv, nbytes - retv);
	}
}

/* ARGSUSED2 */
static int
ar_cb(uintptr_t addr, const void *arptr, void *dummy)
{
	const ar_t *ar = arptr;
	char ardesc[sizeof ("ARP  ") + LIFNAMSIZ];

	ar_describe(ar, ardesc, sizeof (ardesc), B_FALSE);
	mdb_printf("%?p %?p %?p %s\n", addr, ar->ar_wq, ar->ar_arl, ardesc);
	return (WALK_NEXT);
}

/*
 * Print out ARP client structures.
 */
/* ARGSUSED2 */
static int
ar_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ar_t ar;

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%?s %?s %?s %s%</u>\n",
		    "AR", "WQ", "ARL", "TYPE");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&ar, sizeof (ar), addr) == -1) {
			mdb_warn("failed to read ar_t at %p", addr);
			return (DCMD_ERR);
		}
		(void) ar_cb(addr, &ar, NULL);
	} else {
		if (mdb_walk("ar", ar_cb, NULL) == -1) {
			mdb_warn("cannot walk ar_t structures");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

/* ARGSUSED2 */
static int
arl_cb(uintptr_t addr, const void *arlptr, void *dummy)
{
	const arl_t *arl = arlptr;
	arlphy_t ap;
	uchar_t macaddr[ARP_MAX_ADDR_LEN];
	char macstr[ARP_MAX_ADDR_LEN*3];
	char flags[4];
	const char *primstr;

	mdb_printf("%?p  ", addr);
	if (arl->arl_dlpi_pending == DL_PRIM_INVAL)
		mdb_printf("%16s", "--");
	else if ((primstr = mdb_dlpi_prim(arl->arl_dlpi_pending)) != NULL)
		mdb_printf("%16s", primstr);
	else
		mdb_printf("%16x", arl->arl_dlpi_pending);

	if (mdb_vread(&ap, sizeof (ap), (uintptr_t)arl->arl_phy) == -1 ||
	    ap.ap_hw_addrlen == 0 || ap.ap_hw_addrlen > sizeof (macaddr)) {
		(void) strcpy(macstr, "--");
	} else if (mdb_vread(macaddr, ap.ap_hw_addrlen,
	    (uintptr_t)ap.ap_hw_addr) == -1) {
		(void) strcpy(macstr, "?");
	} else {
		mdb_mac_addr(macaddr, ap.ap_hw_addrlen, macstr,
		    sizeof (macstr));
	}

	/* Print both the link-layer state and the NOARP flag */
	flags[0] = '\0';
	if (arl->arl_flags & ARL_F_NOARP)
		(void) strcat(flags, "N");
	switch (arl->arl_state) {
	case ARL_S_DOWN:
		(void) strcat(flags, "d");
		break;
	case ARL_S_PENDING:
		(void) strcat(flags, "P");
		break;
	case ARL_S_UP:
		(void) strcat(flags, "U");
		break;
	default:
		(void) strcat(flags, "?");
		break;
	}
	mdb_printf("  %8d  %-3s  %-9s  %-17s %5d\n",
	    mdb_mblk_count(arl->arl_dlpi_deferred), flags, arl->arl_name,
	    macstr, arl_to_stackid((uintptr_t)addr));
	return (WALK_NEXT);
}

/*
 * Print out ARP link-layer elements.
 */
/* ARGSUSED2 */
static int
arl_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	arl_t arl;

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%?s  %16s  %8s  %3s  %9s  %-17s %5s%</u>\n",
		    "ARL", "DLPI REQ", "DLPI CNT", "FLG", "INTERFACE",
		    "HWADDR", "STACK");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&arl, sizeof (arl), addr) == -1) {
			mdb_warn("failed to read arl_t at %p", addr);
			return (DCMD_ERR);
		}
		(void) arl_cb(addr, &arl, NULL);
	} else {
		if (mdb_walk("arl", arl_cb, NULL) == -1) {
			mdb_warn("cannot walk arl_t structures");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

/* ARGSUSED2 */
static int
ace_cb(uintptr_t addr, const void *aceptr, void *dummy)
{
	const ace_t *ace = aceptr;
	uchar_t macaddr[ARP_MAX_ADDR_LEN];
	char macstr[ARP_MAX_ADDR_LEN*3];
	/* The %b format isn't compact enough for long listings */
	static const char ace_flags[] = "SPDRMLdA ofya";
	const char *cp;
	char flags[sizeof (ace_flags)], *fp;
	int flg;
	in_addr_t inaddr, mask;
	char addrstr[sizeof ("255.255.255.255/32")];

	/* Walk the list of flags and produce a string */
	cp = ace_flags;
	fp = flags;
	for (flg = 1; *cp != '\0'; flg <<= 1, cp++) {
		if ((flg & ace->ace_flags) && *cp != ' ')
			*fp++ = *cp;
	}
	*fp = '\0';

	/* If it's not resolved, then it has no hardware address */
	if (!(ace->ace_flags & ACE_F_RESOLVED) ||
	    ace->ace_hw_addr_length == 0 ||
	    ace->ace_hw_addr_length > sizeof (macaddr)) {
		(void) strcpy(macstr, "--");
	} else if (mdb_vread(macaddr, ace->ace_hw_addr_length,
	    (uintptr_t)ace->ace_hw_addr) == -1) {
		(void) strcpy(macstr, "?");
	} else {
		mdb_mac_addr(macaddr, ace->ace_hw_addr_length, macstr,
		    sizeof (macstr));
	}

	/*
	 * Nothing other than IP uses ARP these days, so we don't try very hard
	 * here to switch out on ARP protocol type.  (Note that ARP protocol
	 * types are roughly Ethertypes, but are allocated separately at IANA.)
	 */
	if (ace->ace_proto != IP_ARP_PROTO_TYPE) {
		(void) mdb_snprintf(addrstr, sizeof (addrstr),
		    "Unknown proto %x", ace->ace_proto);
	} else if (mdb_vread(&inaddr, sizeof (inaddr),
	    (uintptr_t)ace->ace_proto_addr) != -1 &&
	    mdb_vread(&mask, sizeof (mask), (uintptr_t)ace->ace_proto_mask) !=
	    -1) {
		/*
		 * If it's the standard host mask, then print it normally.
		 * Otherwise, use "/n" notation.
		 */
		if (mask == (in_addr_t)~0) {
			(void) mdb_snprintf(addrstr, sizeof (addrstr), "%I",
			    inaddr);
		} else {
			(void) mdb_snprintf(addrstr, sizeof (addrstr), "%I/%d",
			    inaddr, mask == 0 ? 0 : 33 - mdb_ffs(mask));
		}
	} else {
		(void) strcpy(addrstr, "?");
	}
	mdb_printf("%?p  %-18s  %-8s  %-17s %5d\n", addr, addrstr, flags,
	    macstr, arl_to_stackid((uintptr_t)ace->ace_arl));
	return (WALK_NEXT);
}

/*
 * Print out ARP cache entry (ace_t) elements.
 */
/* ARGSUSED2 */
static int
ace_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ace_t ace;

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%?s  %-18s  %-8s  %-17s %5s%</u>\n",
		    "ACE", "PROTOADDR", "FLAGS", "HWADDR", "STACK");
	}

	if (flags & DCMD_ADDRSPEC) {
		if (mdb_vread(&ace, sizeof (ace), addr) == -1) {
			mdb_warn("failed to read ace_t at %p", addr);
			return (DCMD_ERR);
		}
		(void) ace_cb(addr, &ace, NULL);
	} else {
		if (mdb_walk("ace", ace_cb, NULL) == -1) {
			mdb_warn("cannot walk ace_t structures");
			return (DCMD_ERR);
		}
	}
	return (DCMD_OK);
}

/*
 * Print an ARP hardware and protocol address pair; used when printing an ARP
 * message.
 */
static void
print_arp(char field_id, const uchar_t *buf, const arh_t *arh, uint16_t ptype)
{
	char macstr[ARP_MAX_ADDR_LEN*3];
	in_addr_t inaddr;

	if (arh->arh_hlen == 0)
		(void) strcpy(macstr, "(none)");
	else
		mdb_mac_addr(buf, arh->arh_hlen, macstr, sizeof (macstr));
	mdb_printf("%?s  ar$%cha %s\n", "", field_id, macstr);
	if (arh->arh_plen == 0) {
		mdb_printf("%?s  ar$%cpa (none)\n", "", field_id);
	} else if (ptype == IP_ARP_PROTO_TYPE) {
		mdb_printf("%?s  ar$%cpa (unknown)\n", "", field_id);
	} else if (arh->arh_plen == sizeof (in_addr_t)) {
		(void) memcpy(&inaddr, buf + arh->arh_hlen, sizeof (inaddr));
		mdb_printf("%?s  ar$%cpa %I\n", "", field_id, inaddr);
	} else {
		mdb_printf("%?s  ar$%cpa (malformed IP)\n", "", field_id);
	}
}

/*
 * Decode an ARP message and display it.
 */
/* ARGSUSED2 */
static int
arphdr_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct {
		arh_t arh;
		uchar_t addrs[4 * ARP_MAX_ADDR_LEN];
	} arp;
	size_t blen;
	uint16_t htype, ptype, op;
	const char *cp;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("address required to print ARP header\n");
		return (DCMD_ERR);
	}

	if (mdb_vread(&arp.arh, sizeof (arp.arh), addr) == -1) {
		mdb_warn("unable to read ARP header at %p", addr);
		return (DCMD_ERR);
	}
	mdb_nhconvert(&htype, arp.arh.arh_hardware, sizeof (htype));
	mdb_nhconvert(&ptype, arp.arh.arh_proto, sizeof (ptype));
	mdb_nhconvert(&op, arp.arh.arh_operation, sizeof (op));

	switch (htype) {
	case ARPHRD_ETHER:
		cp = "Ether";
		break;
	case ARPHRD_IEEE802:
		cp = "IEEE802";
		break;
	case ARPHRD_IB:
		cp = "InfiniBand";
		break;
	default:
		cp = "Unknown";
		break;
	}
	mdb_printf("%?p: ar$hrd %x (%s)\n", addr, htype, cp);
	mdb_printf("%?s  ar$pro %x (%s)\n", "", ptype,
	    ptype == IP_ARP_PROTO_TYPE ? "IP" : "Unknown");

	switch (op) {
	case ARPOP_REQUEST:
		cp = "ares_op$REQUEST";
		break;
	case ARPOP_REPLY:
		cp = "ares_op$REPLY";
		break;
	case REVARP_REQUEST:
		cp = "arev_op$REQUEST";
		break;
	case REVARP_REPLY:
		cp = "arev_op$REPLY";
		break;
	default:
		cp = "Unknown";
		break;
	}
	mdb_printf("%?s  ar$op %d (%s)\n", "", op, cp);

	/*
	 * Note that we go to some length to attempt to print out the fixed
	 * header data before trying to decode the variable-length data.  This
	 * is done to maximize the amount of useful information shown when the
	 * buffer is truncated or otherwise corrupt.
	 */
	blen = 2 * (arp.arh.arh_hlen + arp.arh.arh_plen);
	if (mdb_vread(&arp.addrs, blen, addr + sizeof (arp.arh)) == -1) {
		mdb_warn("unable to read ARP body at %p", addr);
		return (DCMD_ERR);
	}

	print_arp('s', arp.addrs, &arp.arh, ptype);
	print_arp('t', arp.addrs + arp.arh.arh_hlen + arp.arh.arh_plen,
	    &arp.arh, ptype);
	return (DCMD_OK);
}

/*
 * Print out an arp command formatted in a reasonable manner.  This implements
 * the type switch used by ARP.
 *
 * It could also dump the data that follows the header (using offset and length
 * in the various structures), but it currently does not.
 */
/* ARGSUSED2 */
static int
arpcmd_cmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	arc_t arc;
	const arp_cmd_tbl *tp;
	mdb_arg_t subargv;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("address required to print ARP command\n");
		return (DCMD_ERR);
	}
	if (mdb_vread(&arc, sizeof (arc), addr) == -1) {
		mdb_warn("unable to read arc_t at %p", addr);
		return (DCMD_ERR);
	}
	for (tp = act_list; tp->act_cmd != 0; tp++)
		if (tp->act_cmd == arc.arc_cmd)
			break;
	mdb_printf("%p %s (%s) = ", addr, tp->act_name, tp->act_type);
	subargv.a_type = MDB_TYPE_STRING;
	subargv.a_un.a_str = tp->act_type;
	if (mdb_call_dcmd("print", addr, DCMD_ADDRSPEC, 1, &subargv) == -1)
		return (DCMD_ERR);
	else
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

	if (mdb_vread(&m, sizeof (m), (uintptr_t)q->q_ptr - sizeof (m)) != -1)
		return (m.mi_nbytes - sizeof (m));

	return (0);
}

/*
 * This is called when ::stream is used and an ARP module is seen on the
 * stream.  Determine what sort of ARP usage is involved and show an
 * appropriate message.
 */
static void
arp_qinfo(const queue_t *qp, char *buf, size_t nbytes)
{
	size_t size = mi_osize(qp);
	ar_t ar;

	if (size != sizeof (ar_t))
		return;
	if (mdb_vread(&ar, sizeof (ar), (uintptr_t)qp->q_ptr) == -1)
		return;
	ar_describe(&ar, buf, nbytes, B_TRUE);
}

static uintptr_t
arp_rnext(const queue_t *q)
{
	size_t size = mi_osize(q);
	ar_t ar;

	if (size == sizeof (ar_t) && mdb_vread(&ar, sizeof (ar),
	    (uintptr_t)q->q_ptr) != -1)
		return ((uintptr_t)ar.ar_rq);

	return (NULL);
}

static uintptr_t
arp_wnext(const queue_t *q)
{
	size_t size = mi_osize(q);
	ar_t ar;

	if (size == sizeof (ar_t) && mdb_vread(&ar, sizeof (ar),
	    (uintptr_t)q->q_ptr) != -1)
		return ((uintptr_t)ar.ar_wq);

	return (NULL);
}

static const mdb_dcmd_t dcmds[] = {
	{ "ar", "?", "display ARP client streams for all stacks",
	    ar_cmd, NULL },
	{ "arl", "?", "display ARP link layers for all stacks", arl_cmd, NULL },
	{ "ace", "?", "display ARP cache entries for all stacks",
	    ace_cmd, NULL },
	{ "arphdr", ":", "display an ARP header", arphdr_cmd, NULL },
	{ "arpcmd", ":", "display an ARP command", arpcmd_cmd, NULL },
	{ NULL }
};

/* Note: ar_t walker is in genunix.c and net.c; generic MI walker */
static const mdb_walker_t walkers[] = {
	{ "arl", "walk list of arl_t links for all stacks",
	    arl_walk_init, arl_walk_step, NULL },
	{ "arl_stack", "walk list of arl_t links",
	    arl_stack_walk_init, arl_stack_walk_step, NULL },
	{ "ace", "walk list of ace_t entries for all stacks",
	    ace_walk_init, ace_walk_step, NULL },
	{ "ace_stack", "walk list of ace_t entries",
	    ace_stack_walk_init, ace_stack_walk_step, ace_stack_walk_fini },
	{ "arp_stacks", "walk all the arp_stack_t",
	    arp_stacks_walk_init, arp_stacks_walk_step, NULL },
	{ NULL }
};

static const mdb_qops_t arp_qops = { arp_qinfo, arp_rnext, arp_wnext };
static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("arp", "winit", &sym) == 0)
		mdb_qops_install(&arp_qops, (uintptr_t)sym.st_value);

	return (&modinfo);
}

void
_mdb_fini(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_obj("arp", "winit", &sym) == 0)
		mdb_qops_remove(&arp_qops, (uintptr_t)sym.st_value);
}
