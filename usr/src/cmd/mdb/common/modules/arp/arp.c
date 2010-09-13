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
 * removed all the ace/arl related stuff. The only thing that remains
 * is code for dealing with ioctls and printing out arp header that
 * should probably be moved into the ip/mdb module.
 */

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

static const mdb_dcmd_t dcmds[] = {
	{ "arphdr", ":", "display an ARP header", arphdr_cmd, NULL },
	{ NULL }
};

/* Note: ar_t walker is in genunix.c and net.c; generic MI walker */
static const mdb_walker_t walkers[] = {
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

void
_mdb_fini(void)
{
}
