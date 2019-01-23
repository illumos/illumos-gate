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
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/zone.h>
#include <inet/iptun.h>
#include <sys/byteorder.h>
#include <limits.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <net/trill.h>

#include "at.h"
#include "snoop.h"

static headerlen_fn_t ether_header_len, fddi_header_len, tr_header_len,
    ib_header_len, ipnet_header_len, ipv4_header_len, ipv6_header_len;
static interpreter_fn_t interpret_ether, interpret_fddi, interpret_tr,
    interpret_ib, interpret_ipnet, interpret_iptun;
static void addr_copy_swap(struct ether_addr *, struct ether_addr *);
static int tr_machdr_len(char *, int *, int *);

interface_t *interface;
interface_t INTERFACES[] = {

	/* IEEE 802.3 CSMA/CD network */
	{ DL_CSMACD, 1550, 12, 2, ETHERTYPE_IP, ETHERTYPE_IPV6,
	    ether_header_len, interpret_ether, B_TRUE },

	/* Ethernet Bus */
	{ DL_ETHER, 1550, 12, 2, ETHERTYPE_IP, ETHERTYPE_IPV6,
	    ether_header_len, interpret_ether, B_TRUE },

	/* Fiber Distributed data interface */
	{ DL_FDDI, 4500, 19, 2, ETHERTYPE_IP, ETHERTYPE_IPV6,
	    fddi_header_len, interpret_fddi, B_FALSE },

	/* Token Ring interface */
	{ DL_TPR, 17800, 0, 2, ETHERTYPE_IP, ETHERTYPE_IPV6,
	    tr_header_len, interpret_tr, B_FALSE },

	/* Infiniband */
	{ DL_IB, 4096, 0, 2, ETHERTYPE_IP, ETHERTYPE_IPV6,
	    ib_header_len, interpret_ib, B_TRUE },

	/* ipnet */
	{ DL_IPNET, INT_MAX, 1, 1, IPV4_VERSION, IPV6_VERSION,
	    ipnet_header_len, interpret_ipnet, B_TRUE },

	/* IPv4 tunnel */
	{ DL_IPV4, 0, 9, 1, IPPROTO_ENCAP, IPPROTO_IPV6,
	    ipv4_header_len, interpret_iptun, B_FALSE },

	/* IPv6 tunnel */
	{ DL_IPV6, 0, 40, 1, IPPROTO_ENCAP, IPPROTO_IPV6,
	    ipv6_header_len, interpret_iptun, B_FALSE },

	/* 6to4 tunnel */
	{ DL_6TO4, 0, 9, 1, IPPROTO_ENCAP, IPPROTO_IPV6,
	    ipv4_header_len, interpret_iptun, B_FALSE },

	{ (uint_t)-1, 0, 0, 0, 0, 0, NULL, B_FALSE }
};

/* externals */
extern char *dlc_header;
extern int pi_frame;
extern int pi_time_hour;
extern int pi_time_min;
extern int pi_time_sec;
extern int pi_time_usec;

char *printether();
char *print_ethertype();
static char *print_etherinfo();

char *print_fc();
char *print_smttype();
char *print_smtclass();

struct ether_addr ether_broadcast = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char *data;			/* current data buffer */
static int datalen;			/* current data buffer length */
static const struct ether_addr all_isis_rbridges = ALL_ISIS_RBRIDGES;

uint_t
interpret_ether(int flags, char *header, int elen, int origlen)
{
	struct ether_header *e = (struct ether_header *)header;
	uchar_t *off, *ieeestart;
	int len;
	int ieee8023 = 0;
	extern char *dst_name;
	int ethertype;
	struct ether_vlan_extinfo *evx = NULL;
	int blen = MAX(origlen, ETHERMTU);
	boolean_t trillpkt = B_FALSE;
	uint16_t tci = 0;

	if (data != NULL && datalen != 0 && datalen < blen) {
		free(data);
		data = NULL;
		datalen = 0;
	}
	if (!data) {
		data = (char *)malloc(blen);
		if (!data)
			pr_err("Warning: malloc failure");
		datalen = blen;
	}
inner_pkt:
	if (origlen < 14) {
		if (flags & F_SUM) {
			(void) sprintf(get_sum_line(),
			    "RUNT (short packet - %d bytes)",
			    origlen);
		}
		if (flags & F_DTAIL)
			show_header("RUNT:  ", "Short packet", origlen);
		return (elen);
	}
	if (elen < 14)
		return (elen);

	if (memcmp(&e->ether_dhost, &ether_broadcast,
	    sizeof (struct ether_addr)) == 0)
		dst_name = "(broadcast)";
	else if (e->ether_dhost.ether_addr_octet[0] & 1)
		dst_name = "(multicast)";

	ethertype = ntohs(e->ether_type);

	/*
	 * The 14 byte ether header screws up alignment
	 * of the rest of the packet for 32 bit aligned
	 * architectures like SPARC. Alas, we have to copy
	 * the rest of the packet in order to align it.
	 */
	len = elen - sizeof (struct ether_header);
	off = (uchar_t *)(e + 1);

	if (ethertype == ETHERTYPE_VLAN) {
		if (origlen < sizeof (struct ether_vlan_header)) {
			if (flags & F_SUM) {
				(void) sprintf(get_sum_line(),
				    "RUNT (short VLAN packet - %d bytes)",
				    origlen);
			}
			if (flags & F_DTAIL) {
				show_header("RUNT:  ", "Short VLAN packet",
				    origlen);
			}
			return (elen);
		}
		if (len < sizeof (struct ether_vlan_extinfo))
			return (elen);

		evx = (struct ether_vlan_extinfo *)off;
		off += sizeof (struct ether_vlan_extinfo);
		len -= sizeof (struct ether_vlan_extinfo);

		ethertype = ntohs(evx->ether_type);
		tci = ntohs(evx->ether_tci);
	}

	if (ethertype <= 1514) {
		/*
		 * Fake out the IEEE 802.3 packets.
		 * Should be DSAP=0xAA, SSAP=0xAA, control=0x03
		 * then three padding bytes of zero (OUI),
		 * followed by a normal ethernet-type packet.
		 */
		ieee8023 = ethertype;
		ieeestart = off;
		if (off[0] == 0xAA && off[1] == 0xAA) {
			ethertype = ntohs(*(ushort_t *)(off + 6));
			off += 8;
			len -= 8;
		} else {
			ethertype = 0;
			off += 3;
			len -= 3;
		}
	}

	if (flags & F_SUM) {
		/*
		 * Set the flag that says don't display VLAN information.
		 * If it needs to change, that will be done later if the
		 * packet is VLAN tagged and if snoop is in its default
		 * summary mode.
		 */
		set_vlan_id(0);
		if (evx == NULL) {
			if (ethertype == 0 && ieee8023 > 0) {
				(void) sprintf(get_sum_line(),
				    "ETHER 802.3 SSAP %02X DSAP %02X, "
				    "size=%d bytes", ieeestart[0], ieeestart[1],
				    origlen);
			} else {
				(void) sprintf(get_sum_line(),
				    "ETHER Type=%04X (%s), size=%d bytes",
				    ethertype, print_ethertype(ethertype),
				    origlen);
			}
		} else {
			if (ethertype == 0 && ieee8023 > 0) {
				(void) sprintf(get_sum_line(),
				    "ETHER 802.3 SSAP %02X DSAP %02X, "
				    "VLAN ID=%hu, size=%d bytes", ieeestart[0],
				    ieeestart[1], VLAN_ID(tci), origlen);
			} else {
				(void) sprintf(get_sum_line(),
				    "ETHER Type=%04X (%s), VLAN ID=%hu, "
				    "size=%d bytes", ethertype,
				    print_ethertype(ethertype), VLAN_ID(tci),
				    origlen);
			}

			if (!(flags & F_ALLSUM))
				set_vlan_id(VLAN_ID(tci));
		}
	}

	if (flags & F_DTAIL) {
		show_header("ETHER:  ", "Ether Header", elen);
		show_space();
		if (!trillpkt) {
			(void) sprintf(get_line(0, 0),
			    "Packet %d arrived at %d:%02d:%d.%05d",
			    pi_frame,
			    pi_time_hour, pi_time_min, pi_time_sec,
			    pi_time_usec / 10);
			(void) sprintf(get_line(0, 0),
			    "Packet size = %d bytes",
			    elen, elen);
		}
		(void) sprintf(get_line(0, 6),
		    "Destination = %s, %s",
		    printether(&e->ether_dhost),
		    print_etherinfo(&e->ether_dhost));
		(void) sprintf(get_line(6, 6),
		    "Source      = %s, %s",
		    printether(&e->ether_shost),
		    print_etherinfo(&e->ether_shost));
		if (evx != NULL) {
			(void) sprintf(get_line(0, 0),
			    "VLAN ID     = %hu", VLAN_ID(tci));
			(void) sprintf(get_line(0, 0),
			    "VLAN Priority = %hu", VLAN_PRI(tci));
		}
		if (ieee8023 > 0) {
			(void) sprintf(get_line(12, 2),
			    "IEEE 802.3 length = %d bytes", ieee8023);
			/* Print LLC only for non-TCP/IP packets */
			if (ethertype == 0) {
				(void) snprintf(get_line(0, 0),
				    get_line_remain(),
				    "SSAP = %02X, DSAP = %02X, CTRL = %02X",
				    ieeestart[0], ieeestart[1], ieeestart[2]);
			}
		}
		if (ethertype != 0 || ieee8023 == 0)
			(void) sprintf(get_line(12, 2),
			    "Ethertype = %04X (%s)",
			    ethertype, print_ethertype(ethertype));
		show_space();
	}

	/*
	 * We cannot trust the length field in the header to be correct.
	 * But we should continue to process the packet.  Then user can
	 * notice something funny in the header.
	 * Go to the next protocol layer only if data have been
	 * copied.
	 */
	if (len > 0 && (off + len <= (uchar_t *)e + elen)) {
		(void) memmove(data, off, len);

		if (!trillpkt && ethertype == ETHERTYPE_TRILL) {
			ethertype = interpret_trill(flags, &e, data, &len);
			/* Decode inner Ethernet frame */
			if (ethertype != 0) {
				evx = NULL;
				trillpkt = B_TRUE;
				(void) memmove(data, e, len);
				e = (struct ether_header *)data;
				origlen = len;
				elen = len;
				goto inner_pkt;
			}
		}

		switch (ethertype) {
		case ETHERTYPE_IP:
			(void) interpret_ip(flags, (struct ip *)data, len);
			break;
		/* Just in case it is decided to add this type */
		case ETHERTYPE_IPV6:
			(void) interpret_ipv6(flags, (ip6_t *)data, len);
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			interpret_arp(flags, (struct arphdr *)data, len);
			break;
		case ETHERTYPE_PPPOED:
		case ETHERTYPE_PPPOES:
			(void) interpret_pppoe(flags, (poep_t *)data, len);
			break;
		case ETHERTYPE_AARP:    /* AppleTalk */
			interpret_aarp(flags, data, len);
			break;
		case ETHERTYPE_AT:
			interpret_at(flags, (struct ddp_hdr *)data, len);
			break;
		case 0:
			if (ieee8023 == 0)
				break;
			switch (ieeestart[0]) {
			case 0xFE:
				interpret_isis(flags, data, len,
				    memcmp(&e->ether_dhost, &all_isis_rbridges,
				    sizeof (struct ether_addr)) == 0);
				break;
			case 0x42:
				interpret_bpdu(flags, data, len);
				break;
			}
			break;
		}
	}

	return (elen);
}

/*
 * Return the length of the ethernet header.  In the case
 * where we have a VLAN tagged packet, return the length of
 * the ethernet header plus the length of the VLAN tag.
 *
 * INPUTS:  e  -  A buffer pointer.  Passing a NULL pointer
 *                is not allowed, e must be non-NULL.
 * OUTPUTS:  Return the size of an untagged ethernet header
 *           if the packet is not VLAN tagged, and the size
 *           of an untagged ethernet header plus the size of
 *           a VLAN header otherwise.
 */
uint_t
ether_header_len(char *e, size_t msgsize)
{
	uint16_t ether_type = 0;

	if (msgsize < sizeof (struct ether_header))
		return (0);

	e += (offsetof(struct ether_header, ether_type));

	GETINT16(ether_type, e);

	if (ether_type == (uint16_t)ETHERTYPE_VLAN) {
		return (sizeof (struct ether_vlan_header));
	} else {
		return (sizeof (struct ether_header));
	}
}


/*
 * Table of Ethertypes.
 * Some of the more popular entries
 * are at the beginning of the table
 * to reduce search time.
 */
struct ether_type {
	int   e_type;
	char *e_name;
} ether_type [] = {
ETHERTYPE_IP, "IP",
ETHERTYPE_ARP, "ARP",
ETHERTYPE_REVARP, "RARP",
ETHERTYPE_IPV6, "IPv6",
ETHERTYPE_PPPOED, "PPPoE Discovery",
ETHERTYPE_PPPOES, "PPPoE Session",
ETHERTYPE_TRILL, "TRILL",
/* end of popular entries */
ETHERTYPE_PUP,	"Xerox PUP",
0x0201, "Xerox PUP",
0x0400, "Nixdorf",
0x0600, "Xerox NS IDP",
0x0601, "XNS Translation",
0x0801, "X.75 Internet",
0x0802, "NBS Internet",
0x0803, "ECMA Internet",
0x0804, "CHAOSnet",
0x0805, "X.25 Level 3",
0x0807, "XNS Compatibility",
0x081C, "Symbolics Private",
0x0888, "Xyplex",
0x0889, "Xyplex",
0x088A, "Xyplex",
0x0900, "Ungermann-Bass network debugger",
0x0A00, "Xerox IEEE802.3 PUP",
0x0A01, "Xerox IEEE802.3 PUP Address Translation",
0x0BAD, "Banyan Systems",
0x0BAF, "Banyon VINES Echo",
0x1000, "Berkeley Trailer negotiation",
0x1000,	"IP trailer (0)",
0x1001,	"IP trailer (1)",
0x1002,	"IP trailer (2)",
0x1003,	"IP trailer (3)",
0x1004,	"IP trailer (4)",
0x1005,	"IP trailer (5)",
0x1006,	"IP trailer (6)",
0x1007,	"IP trailer (7)",
0x1008,	"IP trailer (8)",
0x1009,	"IP trailer (9)",
0x100a,	"IP trailer (10)",
0x100b,	"IP trailer (11)",
0x100c,	"IP trailer (12)",
0x100d,	"IP trailer (13)",
0x100e,	"IP trailer (14)",
0x100f,	"IP trailer (15)",
0x1234, "DCA - Multicast",
0x1600, "VALID system protocol",
0x1989, "Aviator",
0x3C00, "3Com NBP virtual circuit datagram",
0x3C01, "3Com NBP System control datagram",
0x3C02, "3Com NBP Connect request (virtual cct)",
0x3C03, "3Com NBP Connect response",
0x3C04, "3Com NBP Connect complete",
0x3C05, "3Com NBP Close request (virtual cct)",
0x3C06, "3Com NBP Close response",
0x3C07, "3Com NBP Datagram (like XNS IDP)",
0x3C08, "3Com NBP Datagram broadcast",
0x3C09, "3Com NBP Claim NetBIOS name",
0x3C0A, "3Com NBP Delete Netbios name",
0x3C0B, "3Com NBP Remote adaptor status request",
0x3C0C, "3Com NBP Remote adaptor response",
0x3C0D, "3Com NBP Reset",
0x4242, "PCS Basic Block Protocol",
0x4321, "THD - Diddle",
0x5208, "BBN Simnet Private",
0x6000, "DEC unass, experimental",
0x6001, "DEC Dump/Load",
0x6002, "DEC Remote Console",
0x6003, "DECNET Phase IV, DNA Routing",
0x6004, "DEC LAT",
0x6005, "DEC Diagnostic",
0x6006, "DEC customer protocol",
0x6007, "DEC Local Area VAX Cluster (LAVC)",
0x6008, "DEC unass (AMBER?)",
0x6009, "DEC unass (MUMPS?)",
0x6010, "3Com",
0x6011, "3Com",
0x6012, "3Com",
0x6013, "3Com",
0x6014, "3Com",
0x7000, "Ungermann-Bass download",
0x7001, "Ungermann-Bass NIUs",
0x7002, "Ungermann-Bass diagnostic/loopback",
0x7003, "Ungermann-Bass ? (NMC to/from UB Bridge)",
0x7005, "Ungermann-Bass Bridge Spanning Tree",
0x7007, "OS/9 Microware",
0x7009, "OS/9 Net?",
0x7020, "Sintrom",
0x7021, "Sintrom",
0x7022, "Sintrom",
0x7023, "Sintrom",
0x7024, "Sintrom",
0x7025, "Sintrom",
0x7026, "Sintrom",
0x7027, "Sintrom",
0x7028, "Sintrom",
0x7029, "Sintrom",
0x8003, "Cronus VLN",
0x8004, "Cronus Direct",
0x8005, "HP Probe protocol",
0x8006, "Nestar",
0x8008, "AT&T/Stanford Univ",
0x8010, "Excelan",
0x8013, "SGI diagnostic",
0x8014, "SGI network games",
0x8015, "SGI reserved",
0x8016, "SGI XNS NameServer, bounce server",
0x8019, "Apollo DOMAIN",
0x802E, "Tymshare",
0x802F, "Tigan,",
0x8036, "Aeonic Systems",
0x8037, "IPX (Novell Netware)",
0x8038, "DEC LanBridge Management",
0x8039, "DEC unass (DSM/DTP?)",
0x803A, "DEC unass (Argonaut Console?)",
0x803B, "DEC unass (VAXELN?)",
0x803C, "DEC unass (NMSV? DNA Naming Service?)",
0x803D, "DEC Ethernet CSMA/CD Encryption Protocol",
0x803E, "DEC unass (DNA Time Service?)",
0x803F, "DEC LAN Traffic Monitor Protocol",
0x8040, "DEC unass (NetBios Emulator?)",
0x8041, "DEC unass (MS/DOS?, Local Area System Transport?)",
0x8042, "DEC unass",
0x8044, "Planning Research Corp.",
0x8046, "AT&T",
0x8047, "AT&T",
0x8049, "ExperData",
0x805B, "VMTP",
0x805C, "Stanford V Kernel, version 6.0",
0x805D, "Evans & Sutherland",
0x8060, "Little Machines",
0x8062, "Counterpoint",
0x8065, "University of Mass. at Amherst",
0x8066, "University of Mass. at Amherst",
0x8067, "Veeco Integrated Automation",
0x8068, "General Dynamics",
0x8069, "AT&T",
0x806A, "Autophon",
0x806C, "ComDesign",
0x806D, "Compugraphic Corp",
0x806E, "Landmark",
0x806F, "Landmark",
0x8070, "Landmark",
0x8071, "Landmark",
0x8072, "Landmark",
0x8073, "Landmark",
0x8074, "Landmark",
0x8075, "Landmark",
0x8076, "Landmark",
0x8077, "Landmark",
0x807A, "Matra",
0x807B, "Dansk Data Elektronik",
0x807C, "Merit Internodal",
0x807D, "Vitalink",
0x807E, "Vitalink",
0x807F, "Vitalink",
0x8080, "Vitalink TransLAN III Management",
0x8081, "Counterpoint",
0x8082, "Counterpoint",
0x8083, "Counterpoint",
0x8088, "Xyplex",
0x8089, "Xyplex",
0x808A, "Xyplex",
0x809B, "EtherTalk (AppleTalk over Ethernet)",
0x809C, "Datability",
0x809D, "Datability",
0x809E, "Datability",
0x809F, "Spider Systems",
0x80A3, "Nixdorf",
0x80A4, "Siemens Gammasonics",
0x80C0, "DCA Data Exchange Cluster",
0x80C6, "Pacer Software",
0x80C7, "Applitek Corp",
0x80C8, "Intergraph",
0x80C9, "Intergraph",
0x80CB, "Intergraph",
0x80CC, "Intergraph",
0x80CA, "Intergraph",
0x80CD, "Harris Corp",
0x80CE, "Harris Corp",
0x80CF, "Taylor Instrument",
0x80D0, "Taylor Instrument",
0x80D1, "Taylor Instrument",
0x80D2, "Taylor Instrument",
0x80D3, "Rosemount Corp",
0x80D4, "Rosemount Corp",
0x80D5, "IBM SNA Services over Ethernet",
0x80DD, "Varian Associates",
0x80DE, "TRFS",
0x80DF, "TRFS",
0x80E0, "Allen-Bradley",
0x80E1, "Allen-Bradley",
0x80E2, "Allen-Bradley",
0x80E3, "Allen-Bradley",
0x80E4, "Datability",
0x80F2, "Retix",
0x80F3, "AARP (Appletalk)",
0x80F4, "Kinetics",
0x80F5, "Kinetics",
0x80F7, "Apollo",
0x80FF, "Wellfleet Communications",
0x8102, "Wellfleet Communications",
0x8107, "Symbolics Private",
0x8108, "Symbolics Private",
0x8109, "Symbolics Private",
0x812B, "Talaris",
0x8130, "Waterloo",
0x8131, "VG Lab",
0x8137, "Novell (old) NetWare IPX",
0x8138, "Novell",
0x814C, "SNMP over Ethernet",
0x817D, "XTP",
0x81D6, "Lantastic",
0x8888, "HP LanProbe test?",
0x9000, "Loopback",
0x9001, "3Com, XNS Systems Management",
0x9002, "3Com, TCP/IP Systems Management",
0x9003, "3Com, loopback detection",
0xAAAA, "DECNET	(VAX 6220 DEBNI)",
0xFF00, "BBN VITAL-LanBridge cache wakeups",
0,	"",
};

char *
print_fc(uint_t type)
{

	switch (type) {
		case 0x50: return ("LLC");
		case 0x4f: return ("SMT NSA");
		case 0x41: return ("SMT Info");
		default: return ("Unknown");
	}
}

char *
print_smtclass(uint_t type)
{
	switch (type) {
		case 0x01: return ("NIF");
		case 0x02: return ("SIF Conf");
		case 0x03: return ("SIF Oper");
		case 0x04: return ("ECF");
		case 0x05: return ("RAF");
		case 0x06: return ("RDF");
		case 0x07: return ("SRF");
		case 0x08: return ("PMF Get");
		case 0x09: return ("PMF Change");
		case 0x0a: return ("PMF Add");
		case 0x0b: return ("PMF Remove");
		case 0xff: return ("ESF");
		default: return ("Unknown");
	}

}
char *
print_smttype(uint_t type)
{
	switch (type) {
		case 0x01: return ("Announce");
		case 0x02: return ("Request");
		case 0x03: return ("Response");
		default: return ("Unknown");
	}

}
char *
print_ethertype(int type)
{
	int i;

	for (i = 0; ether_type[i].e_type; i++)
		if (type == ether_type[i].e_type)
			return (ether_type[i].e_name);
	if (type < 1500)
		return ("LLC/802.3");

	return ("Unknown");
}

#define	MAX_RDFLDS	14		/* changed to 14 from 8 as per IEEE */
#define	TR_FN_ADDR	0x80		/* dest addr is functional */
#define	TR_SR_ADDR	0x80		/* MAC utilizes source route */
#define	ACFCDASA_LEN	14		/* length of AC|FC|DA|SA */
#define	TR_MAC_MASK	0xc0
#define	TR_AC		0x00		/* Token Ring access control */
#define	TR_LLC_FC	0x40		/* Token Ring llc frame control */
#define	LSAP_SNAP	0xaa
#define	LLC_SNAP_HDR_LEN	8
#define	LLC_HDR1_LEN	3		/* DON'T use sizeof(struct llc_hdr1) */
#define	CNTL_LLC_UI	0x03		/* un-numbered information packet */

/*
 * Source Routing Route Information field.
 */
struct tr_ri {
#if defined(_BIT_FIELDS_HTOL)
	uchar_t rt:3;			/* routing type */
	uchar_t len:5;			/* length */
	uchar_t dir:1;			/* direction bit */
	uchar_t mtu:3;			/* largest frame */
	uchar_t res:4;			/* reserved */
#elif defined(_BIT_FIELDS_LTOH)
	uchar_t len:5;			/* length */
	uchar_t rt:3;			/* routing type */
	uchar_t res:4;			/* reserved */
	uchar_t mtu:3;			/* largest frame */
	uchar_t dir:1;			/* direction bit */
#endif
/*
 * In little endian machine, the ring field has to be stored in a
 * ushort_t type.  This implies that it is not possible to have a
 * layout of bit field to represent bridge and ring.
 *
 * If the compiler uses _BIT_FIELDS_HTOL and it is a big endian
 * machine, the following bit field definition will work.
 *
 *	struct tr_rd {
 *		ushort_t bridge:4;
 *		ushort_t ring:12;
 *	} rd[MAX_RDFLDS];
 *
 * If the compiler uses _BIT_FIELDS_LTOH and it is a big endian
 * machine, the definition can be changed to
 *
 *	struct tr_rd {
 *		ushort_t bridge:4;
 *		ushort_t ring:12;
 *	} rd[MAX_RDFLDS];
 *
 * With little endian machine, we need to use 2 macroes.  For
 * simplicity, since the macroes work for both big and little
 * endian machines, we will not use bit fields for the
 * definition.
 */
#define	bridge(route)	(ntohs((ushort_t)(route)) & 0x0F)
#define	ring(route)	(ntohs((ushort_t)(route)) >> 4)

	ushort_t rd[MAX_RDFLDS];	/* route designator fields */
};

struct tr_header {
	uchar_t		ac;
	uchar_t		fc;
	struct ether_addr dhost;
	struct ether_addr shost;
	struct tr_ri	ri;
};

struct llc_snap_hdr {
	uchar_t  d_lsap;		/* destination service access point */
	uchar_t  s_lsap;		/* source link service access point */
	uchar_t  control;		/* short control field */
	uchar_t  org[3];		/* Ethernet style organization field */
	ushort_t type;			/* Ethernet style type field */
};

struct ether_addr tokenbroadcastaddr2 = {
	0xc0, 0x00, 0xff, 0xff, 0xff, 0xff
};

int Mtutab[] = {516, 1470, 2052, 4472, 8144, 11407, 17800};

char *
print_sr(struct tr_ri *rh)
{
	int hops, ii;
	static char line[512];

	sprintf(line, "TR Source Route dir=%d, mtu=%d",
	    rh->dir, Mtutab[rh->mtu]);

	hops = (int)(rh->len - 2) / (int)2;

	if (hops) {
		sprintf(line+strlen(line), ", Route: ");
		for (ii = 0; ii < hops; ii++) {
			if (! bridge(rh->rd[ii])) {
				sprintf(line+strlen(line), "(%d)",
				    ring(rh->rd[ii]));
			} else {
				sprintf(line+strlen(line), "(%d)%d",
				    ring(rh->rd[ii]), bridge(rh->rd[ii]));
			}
		}
	}
	return (&line[0]);
}

uint_t
interpret_tr(int flags, caddr_t e, int elen, int origlen)
{
	struct tr_header *mh;
	struct tr_ri *rh;
	uchar_t fc;
	struct llc_snap_hdr *snaphdr;
	char *off;
	int maclen, len;
	boolean_t data_copied = B_FALSE;
	extern char *dst_name, *src_name;
	int ethertype;
	int is_llc = 0, is_snap = 0, source_routing = 0;
	int blen = MAX(origlen, 17800);

	if (data != NULL && datalen != 0 && datalen < blen) {
		free(data);
		data = NULL;
		datalen = 0;
	}
	if (!data) {
		data = (char *)malloc(blen);
		if (!data)
			pr_err("Warning: malloc failure");
		datalen = blen;
	}

	if (origlen < ACFCDASA_LEN) {
		if (flags & F_SUM) {
			(void) sprintf(get_sum_line(),
			    "RUNT (short packet - %d bytes)",
			    origlen);
		}
		if (flags & F_DTAIL)
			show_header("RUNT:  ", "Short packet", origlen);
		return (elen);
	}
	if (elen < ACFCDASA_LEN)
		return (elen);

	mh = (struct tr_header *)e;
	rh = (struct tr_ri *)&mh->ri;
	fc = mh->fc;

	if (is_llc = tr_machdr_len(e, &maclen, &source_routing)) {
		snaphdr = (struct llc_snap_hdr *)(e + maclen);
		if (snaphdr->d_lsap == LSAP_SNAP &&
		    snaphdr->s_lsap == LSAP_SNAP &&
		    snaphdr->control == CNTL_LLC_UI) {
			is_snap = 1;
		}
	}

	if (memcmp(&mh->dhost, &ether_broadcast,
	    sizeof (struct ether_addr)) == 0)
		dst_name = "(broadcast)";
	else if (memcmp(&mh->dhost, &tokenbroadcastaddr2,
	    sizeof (struct ether_addr)) == 0)
		dst_name = "(mac broadcast)";
	else if (mh->dhost.ether_addr_octet[0] & TR_FN_ADDR)
		dst_name = "(functional)";

	if (is_snap)
		ethertype = ntohs(snaphdr->type);
	else {
		src_name =  print_etherinfo(&mh->shost);
		dst_name =  print_etherinfo(&mh->dhost);
	}

	/*
	 * The 14 byte ether header screws up alignment
	 * of the rest of the packet for 32 bit aligned
	 * architectures like SPARC. Alas, we have to copy
	 * the rest of the packet in order to align it.
	 */
	if (is_llc) {
		if (is_snap) {
			len = elen - (maclen + LLC_SNAP_HDR_LEN);
			off = (char *)(e + maclen + LLC_SNAP_HDR_LEN);
		} else {
			len = elen - (maclen + LLC_HDR1_LEN);
			off = (char *)(e + maclen + LLC_HDR1_LEN);
		}
	} else {
		len = elen - maclen;
		off = (char *)(e + maclen);
	}

	if (len > 0 && (off + len <= (char *)e + elen)) {
		(void) memcpy(data, off, len);
		data_copied = B_TRUE;
	}

	if (flags & F_SUM) {
		if (source_routing)
			sprintf(get_sum_line(), print_sr(rh));

		if (is_llc) {
			if (is_snap) {
				(void) sprintf(get_sum_line(), "TR LLC w/SNAP "
				    "Type=%04X (%s), size=%d bytes",
				    ethertype,
				    print_ethertype(ethertype),
				    origlen);
			} else {
				(void) sprintf(get_sum_line(), "TR LLC, but no "
				    "SNAP encoding, size = %d bytes",
				    origlen);
			}
		} else {
			(void) sprintf(get_sum_line(),
			    "TR MAC FC=%02X (%s), size = %d bytes",
			    fc, print_fc(fc), origlen);
		}
	}

	if (flags & F_DTAIL) {
		show_header("TR:  ", "TR Header", elen);
		show_space();
		(void) sprintf(get_line(0, 0),
		    "Packet %d arrived at %d:%02d:%d.%05d",
		    pi_frame,
		    pi_time_hour, pi_time_min, pi_time_sec,
		    pi_time_usec / 10);
		(void) sprintf(get_line(0, 0),
		    "Packet size = %d bytes",
		    elen);
		(void) sprintf(get_line(0, 1),
		    "Frame Control = %02x (%s)",
		    fc, print_fc(fc));
		(void) sprintf(get_line(2, 6),
		    "Destination = %s, %s",
		    printether(&mh->dhost),
		    print_etherinfo(&mh->dhost));
		(void) sprintf(get_line(8, 6),
		    "Source      = %s, %s",
		    printether(&mh->shost),
		    print_etherinfo(&mh->shost));

		if (source_routing)
			sprintf(get_line(ACFCDASA_LEN, rh->len), print_sr(rh));

		if (is_llc) {
			(void) sprintf(get_line(maclen, 1),
			    "Dest   Service Access Point = %02x",
			    snaphdr->d_lsap);
			(void) sprintf(get_line(maclen+1, 1),
			    "Source Service Access Point = %02x",
			    snaphdr->s_lsap);
			(void) sprintf(get_line(maclen+2, 1),
			    "Control = %02x",
			    snaphdr->control);
			if (is_snap) {
				(void) sprintf(get_line(maclen+3, 3),
				    "SNAP Protocol Id = %02x%02x%02x",
				    snaphdr->org[0], snaphdr->org[1],
				    snaphdr->org[2]);
			}
		}

		if (is_snap) {
			(void) sprintf(get_line(maclen+6, 2),
			    "SNAP Type = %04X (%s)",
			    ethertype, print_ethertype(ethertype));
		}

		show_space();
	}

	/* go to the next protocol layer */
	if (is_snap && data_copied) {
		switch (ethertype) {
		case ETHERTYPE_IP:
			(void) interpret_ip(flags, (struct ip *)data, len);
			break;
		/* Just in case it is decided to add this type */
		case ETHERTYPE_IPV6:
			(void) interpret_ipv6(flags, (ip6_t *)data, len);
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			interpret_arp(flags, (struct arphdr *)data, len);
			break;
		case ETHERTYPE_AARP:	/* AppleTalk */
			interpret_aarp(flags, data, len);
			break;
		case ETHERTYPE_AT:
			interpret_at(flags, (struct ddp_hdr *)data, len);
			break;
		default:
			break;
		}
	}

	return (elen);
}


/*
 *	stuffs length of mac and ri fields into *lenp
 *	returns:
 *		0: mac frame
 *		1: llc frame
 */
static int
tr_machdr_len(char *e, int *lenp, int *source_routing)
{
	struct tr_header *mh;
	struct tr_ri *rh;
	uchar_t fc;

	mh = (struct tr_header *)e;
	rh = (struct tr_ri *)&mh->ri;
	fc = mh->fc;

	if (mh->shost.ether_addr_octet[0] & TR_SR_ADDR) {
		*lenp = ACFCDASA_LEN + rh->len;
		*source_routing = 1;
	} else {
		*lenp = ACFCDASA_LEN;
		*source_routing = 0;
	}

	if ((fc & TR_MAC_MASK) == 0)
		return (0);		/* it's a MAC frame */
	else
		return (1);		/* it's an LLC frame */
}

uint_t
tr_header_len(char *e, size_t msgsize)
{
	struct llc_snap_hdr *snaphdr;
	int len = 0, source_routing;

	if (tr_machdr_len(e, &len, &source_routing) == 0)
		return (len);		/* it's a MAC frame */

	if (msgsize < sizeof (struct llc_snap_hdr))
		return (0);

	snaphdr = (struct llc_snap_hdr *)(e + len);
	if (snaphdr->d_lsap == LSAP_SNAP &&
	    snaphdr->s_lsap == LSAP_SNAP &&
	    snaphdr->control == CNTL_LLC_UI)
		len += LLC_SNAP_HDR_LEN;	/* it's a SNAP frame */
	else
		len += LLC_HDR1_LEN;

	return (len);
}

struct fddi_header {
	uchar_t fc;
	struct ether_addr dhost, shost;
	uchar_t dsap, ssap, ctl, proto_id[3];
	ushort_t	type;
};

uint_t
interpret_fddi(int flags, caddr_t e, int elen, int origlen)
{
	struct fddi_header fhdr, *f = &fhdr;
	char *off;
	int len;
	boolean_t data_copied = B_FALSE;
	extern char *dst_name, *src_name;
	int ethertype;
	int is_llc = 0, is_smt = 0, is_snap = 0;
	int blen = MAX(origlen, 4500);

	if (data != NULL && datalen != 0 && datalen < blen) {
		free(data);
		data = NULL;
		datalen = 0;
	}
	if (!data) {
		data = (char *)malloc(blen);
		if (!data)
			pr_err("Warning: malloc failure");
		datalen = blen;
	}

	if (origlen < 13) {
		if (flags & F_SUM) {
			(void) sprintf(get_sum_line(),
			    "RUNT (short packet - %d bytes)",
			    origlen);
		}
		if (flags & F_DTAIL)
			show_header("RUNT:  ", "Short packet", origlen);
		return (elen);
	}
	if (elen < 13)
		return (elen);

	(void) memcpy(&f->fc, e, sizeof (f->fc));
	addr_copy_swap(&f->dhost, (struct ether_addr *)(e+1));
	addr_copy_swap(&f->shost, (struct ether_addr *)(e+7));

	if ((f->fc&0x50) == 0x50) {
		is_llc = 1;
		(void) memcpy(&f->dsap, e+13, sizeof (f->dsap));
		(void) memcpy(&f->ssap, e+14, sizeof (f->ssap));
		(void) memcpy(&f->ctl, e+15, sizeof (f->ctl));
		if (f->dsap == 0xaa && f->ssap == 0xaa) {
			is_snap = 1;
			(void) memcpy(&f->proto_id, e+16, sizeof (f->proto_id));
			(void) memcpy(&f->type, e+19, sizeof (f->type));
		}
	} else {
		if ((f->fc&0x41) == 0x41 || (f->fc&0x4f) == 0x4f) {
			is_smt = 1;
		}
	}


	if (memcmp(&f->dhost, &ether_broadcast,
	    sizeof (struct ether_addr)) == 0)
		dst_name = "(broadcast)";
	else if (f->dhost.ether_addr_octet[0] & 0x01)
		dst_name = "(multicast)";

	if (is_snap)
		ethertype = ntohs(f->type);
	else {
		src_name = 	print_etherinfo(&f->shost);
		dst_name =  print_etherinfo(&f->dhost);
	}

	/*
	 * The 14 byte ether header screws up alignment
	 * of the rest of the packet for 32 bit aligned
	 * architectures like SPARC. Alas, we have to copy
	 * the rest of the packet in order to align it.
	 */
	if (is_llc) {
		if (is_snap) {
			len = elen - 21;
			off = (char *)(e + 21);
		} else {
			len = elen - 16;
			off = (char *)(e + 16);
		}
	} else {
		len = elen - 13;
		off = (char *)(e + 13);
	}

	if (len > 0 && (off + len <= (char *)e + elen)) {
		(void) memcpy(data, off, len);
		data_copied = B_TRUE;
	}

	if (flags & F_SUM) {
		if (is_llc) {
			if (is_snap) {
				(void) sprintf(get_sum_line(),
				    "FDDI LLC Type=%04X (%s), size = %d bytes",
				    ethertype,
				    print_ethertype(ethertype),
				    origlen);
			} else {
				(void) sprintf(get_sum_line(), "LLC, but no "
				    "SNAP encoding, size = %d bytes",
				    origlen);
			}
		} else if (is_smt) {
			(void) sprintf(get_sum_line(), "SMT Type=%02X (%s), "
			    "Class = %02X (%s), size = %d bytes",
			    *(uchar_t *)(data+1), print_smttype(*(data+1)),
			    *data, print_smtclass(*data), origlen);
		} else {
			(void) sprintf(get_sum_line(),
			    "FC=%02X (%s), size = %d bytes",
			    f->fc, print_fc(f->fc), origlen);
		}
	}

	if (flags & F_DTAIL) {
		show_header("FDDI:  ", "FDDI Header", elen);
		show_space();
		(void) sprintf(get_line(0, 0),
		    "Packet %d arrived at %d:%02d:%d.%05d",
		    pi_frame,
		    pi_time_hour, pi_time_min, pi_time_sec,
		    pi_time_usec / 10);
		(void) sprintf(get_line(0, 0),
		    "Packet size = %d bytes",
		    elen, elen);
		(void) sprintf(get_line(0, 6),
		    "Destination = %s, %s",
		    printether(&f->dhost),
		    print_etherinfo(&f->dhost));
		(void) sprintf(get_line(6, 6),
		    "Source      = %s, %s",
		    printether(&f->shost),
		    print_etherinfo(&f->shost));

		if (is_llc) {
			(void) sprintf(get_line(12, 2),
			    "Frame Control = %02x (%s)",
			    f->fc, print_fc(f->fc));
			(void) sprintf(get_line(12, 2),
			    "Dest   Service Access Point = %02x",
			    f->dsap);
			(void) sprintf(get_line(12, 2),
			    "Source Service Access Point = %02x",
			    f->ssap);
			(void) sprintf(get_line(12, 2),
			    "Control = %02x",
			    f->ctl);
			if (is_snap) {
				(void) sprintf(get_line(12, 2),
				    "Protocol Id = %02x%02x%02x",
				    f->proto_id[0], f->proto_id[1],
				    f->proto_id[2]);
			}
		} else if (is_smt) {
			(void) sprintf(get_line(12, 2),
			    "Frame Control = %02x (%s)",
			    f->fc, print_fc(f->fc));
			(void) sprintf(get_line(12, 2),
			    "Class = %02x (%s)",
			    (uchar_t)*data, print_smtclass(*data));
			(void) sprintf(get_line(12, 2),
			    "Type = %02x (%s)",
			    *(uchar_t *)(data+1), print_smttype(*(data+1)));
		} else {
			(void) sprintf(get_line(12, 2),
			    "FC=%02X (%s), size = %d bytes",
			    f->fc, print_fc(f->fc), origlen);
		}

		if (is_snap) {
			(void) sprintf(get_line(12, 2),
			    "LLC Type = %04X (%s)",
			    ethertype, print_ethertype(ethertype));
		}

		show_space();
	}

	/* go to the next protocol layer */
	if (is_llc && is_snap && f->ctl == 0x03 && data_copied) {
		switch (ethertype) {
		case ETHERTYPE_IP:
			(void) interpret_ip(flags, (struct ip *)data, len);
			break;
		/* Just in case it is decided to add this type */
		case ETHERTYPE_IPV6:
			(void) interpret_ipv6(flags, (ip6_t *)data, len);
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			interpret_arp(flags, (struct arphdr *)data, len);
			break;
		default:
			break;
		}

	}

	return (elen);
}

uint_t
fddi_header_len(char *e, size_t msgsize)
{
	struct fddi_header fhdr, *f = &fhdr;

	if (msgsize < sizeof (struct fddi_header))
		return (0);

	(void) memcpy(&f->fc, e, sizeof (f->fc));
	(void) memcpy(&f->dhost, e+1, sizeof (struct ether_addr));
	(void) memcpy(&f->shost, e+7, sizeof (struct ether_addr));

	if ((f->fc&0x50) == 0x50) {
		(void) memcpy(&f->dsap, e+13, sizeof (f->dsap));
		(void) memcpy(&f->ssap, e+14, sizeof (f->ssap));
		(void) memcpy(&f->ctl, e+15, sizeof (f->ctl));
		if (f->dsap == 0xaa && f->ssap == 0xaa) {
			return (21);
		}
		return (16);
	} else {
		if ((f->fc&0x41) == 0x41 || (f->fc&0x4f) == 0x4f) {
			return (13);
		}
	}
	/* Return the default FDDI header length. */
	return (13);
}

/*
 * Print the given Ethernet address
 */
char *
printether(struct ether_addr *p)
{
	static char buf[256];

	sprintf(buf, "%x:%x:%x:%x:%x:%x",
	    p->ether_addr_octet[0],
	    p->ether_addr_octet[1],
	    p->ether_addr_octet[2],
	    p->ether_addr_octet[3],
	    p->ether_addr_octet[4],
	    p->ether_addr_octet[5]);

	return (buf);
}

/*
 * Table of Ethernet Address Assignments
 * Some of the more popular entries
 * are at the beginning of the table
 * to reduce search time.  Note that the
 * e-block's are stored in host byte-order.
 */
struct block_type {
	int	e_block;
	char	*e_name;
} ether_block [] = {
0x080020,	"Sun",
0x0000C6,	"HP",
0x08002B,	"DEC",
0x00000F,	"NeXT",
0x00000C,	"Cisco",
0x080069,	"Silicon Graphics",
0x000069,	"Silicon Graphics",
0x0000A7,	"Network Computing Devices (NCD	X-terminal)",
0x08005A,	"IBM",
0x0000AC,	"Apollo",
0x0180C2,	"Standard MAC Group Address",
/* end of popular entries */
0x000002,	"BBN",
0x000010,	"Sytek",
0x000011,	"Tektronix",
0x000018,	"Webster (?)",
0x00001B,	"Novell",
0x00001D,	"Cabletron",
0x000020,	"DIAB (Data Industrier AB)",
0x000021,	"SC&C",
0x000022,	"Visual Technology",
0x000029,	"IMC",
0x00002A,	"TRW",
0x00003D,	"AT&T",
0x000049,	"Apricot Ltd.",
0x000055,	"AT&T",
0x00005A,	"S & Koch",
0x00005A,	"Xerox 806 (unregistered)",
0x00005E,	"U.S. Department of Defense (IANA)",
0x000065,	"Network General",
0x00006B,	"MIPS",
0x000077,	"MIPS",
0x000079,	"NetWare (?)",
0x00007A,	"Ardent",
0x00007B,	"Research Machines",
0x00007D,	"Harris (3M) (old)",
0x000080,	"Imagen(?)",
0x000081,	"Synoptics",
0x000084,	"Aquila (?)",
0x000086,	"Gateway (?)",
0x000089,	"Cayman Systems	Gatorbox",
0x000093,	"Proteon",
0x000094,	"Asante",
0x000098,	"Cross Com",
0x00009F,	"Ameristar Technology",
0x0000A2,	"Wellfleet",
0x0000A3,	"Network Application Technology",
0x0000A4,	"Acorn",
0x0000A6,	"Network General",
0x0000A7,	"Network Computing Devices (NCD	X-terminal)",
0x0000A9,	"Network Systems",
0x0000AA,	"Xerox",
0x0000B3,	"CIMLinc",
0x0000B5,	"Datability Terminal Server",
0x0000B7,	"Dove Fastnet",
0x0000BC,	"Allen-Bradley",
0x0000C0,	"Western Digital",
0x0000C8,	"Altos",
0x0000C9,	"Emulex Terminal Server",
0x0000D0,	"Develcon Electronics, Ltd.",
0x0000D1,	"Adaptec Inc. Nodem product",
0x0000D7,	"Dartmouth College (NED Router)",
0x0000DD,	"Gould",
0x0000DE,	"Unigraph",
0x0000E2,	"Acer Counterpoint",
0x0000E8,	"Accton Technology Corporation",
0x0000EE,	"Network Designers Limited(?)",
0x0000EF,	"Alantec",
0x0000F3,	"Gandalf",
0x0000FD,	"High Level Hardware (Orion, UK)",
0x000143,	"IEEE 802",
0x001700,	"Kabel",
0x004010,	"Sonic",
0x00608C,	"3Com",
0x00800F,	"SMC",
0x008019,	"Dayna Communications Etherprint product",
0x00802D,	"Xylogics, Inc.	Annex terminal servers",
0x008035,	"Technology Works",
0x008087,	"Okidata",
0x00808C,	"Frontier Software Development",
0x0080C7,	"Xircom Inc.",
0x0080D0,	"Computer Products International",
0x0080D3,	"Shiva Appletalk-Ethernet interface",
0x0080D4,	"Chase Limited",
0x0080F1,	"Opus",
0x00AA00,	"Intel",
0x00B0D0,	"Computer Products International",
0x00DD00,	"Ungermann-Bass",
0x00DD01,	"Ungermann-Bass",
0x00EFE5,	"IBM (3Com card)",
0x020406,	"BBN",
0x026060,	"3Com",
0x026086,	"Satelcom MegaPac (UK)",
0x02E6D3,	"Bus-Tech, Inc. (BTI)",
0x080001,	"Computer Vision",
0x080002,	"3Com (Formerly Bridge)",
0x080003,	"ACC (Advanced Computer Communications)",
0x080005,	"Symbolics",
0x080007,	"Apple",
0x080008,	"BBN",
0x080009,	"Hewlett-Packard",
0x08000A,	"Nestar Systems",
0x08000B,	"Unisys",
0x08000D,	"ICL",
0x08000E,	"NCR",
0x080010,	"AT&T",
0x080011,	"Tektronix, Inc.",
0x080017,	"NSC",
0x08001A,	"Data General",
0x08001B,	"Data General",
0x08001E,	"Apollo",
0x080022,	"NBI",
0x080025,	"CDC",
0x080026,	"Norsk Data (Nord)",
0x080027,	"PCS Computer Systems GmbH",
0x080028,	"TI Explorer",
0x08002E,	"Metaphor",
0x08002F,	"Prime Computer",
0x080036,	"Intergraph CAE stations",
0x080037,	"Fujitsu-Xerox",
0x080038,	"Bull",
0x080039,	"Spider Systems",
0x08003B,	"Torus Systems",
0x08003E,	"Motorola VME bus processor module",
0x080041,	"DCA Digital Comm. Assoc.",
0x080046,	"Sony",
0x080047,	"Sequent",
0x080049,	"Univation",
0x08004C,	"Encore",
0x08004E,	"BICC",
0x080056,	"Stanford University",
0x080057,	"Evans & Sutherland (?)",
0x080067,	"Comdesign",
0x080068,	"Ridge",
0x08006A,	"ATTst (?)",
0x08006E,	"Excelan",
0x080075,	"DDE (Danish Data Elektronik A/S)",
0x080077,	"TSL (now Retix)",
0x08007C,	"Vitalink TransLAN III",
0x080080,	"XIOS",
0x080081,	"Crosfield Electronics",
0x080086,	"Imagen/QMS",
0x080087,	"Xyplex	terminal server",
0x080089,	"Kinetics AppleTalk-Ethernet interface",
0x08008B,	"Pyramid",
0x08008D,	"XyVision",
0x080090,	"Retix Inc Bridge",
0x10005A,	"IBM",
0x1000D4,	"DEC",
0x400003,	"NetWare",
0x800010,	"AT&T",
0xAA0004,	"DEC (DECNET)",
0xC00000,	"SMC",
0,		"",
};

/*
 * The oui argument should be in host byte-order to conform with
 * the above array's values.
 */
char *
ether_ouiname(uint32_t oui)
{
	uint_t i;

	for (i = 0; ether_block[i].e_block != 0; i++)
		if (oui == ether_block[i].e_block)
			return (ether_block[i].e_name);

	return (NULL);
}

/*
 * Print the additional Ethernet address info
 */
static char *
print_etherinfo(struct ether_addr *eaddr)
{
	uint_t addr = 0;
	char *p = (char *)&addr + 1;
	char *ename;

	(void) memcpy(p, eaddr, 3);

	if (memcmp(eaddr, &ether_broadcast, sizeof (struct ether_addr)) == 0)
		return ("(broadcast)");

	addr = ntohl(addr);	/* make it right for little-endians */
	ename = ether_ouiname(addr);

	if (ename != NULL)
		return (ename);
	else
		return ((eaddr->ether_addr_octet[0] & 1) ? "(multicast)" : "");
}

static uchar_t	endianswap[] = {
	0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
	0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
	0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
	0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
	0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
	0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
	0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
	0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
	0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
	0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
	0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
	0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
	0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
	0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
	0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
	0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
	0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
	0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
	0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
	0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
	0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
	0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
	0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
	0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
	0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
	0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
	0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
	0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
	0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
	0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
	0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
	0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
};

static void
addr_copy_swap(struct ether_addr *pd, struct ether_addr *ps)
{
	pd->ether_addr_octet[0] = endianswap[ps->ether_addr_octet[0]];
	pd->ether_addr_octet[1] = endianswap[ps->ether_addr_octet[1]];
	pd->ether_addr_octet[2] = endianswap[ps->ether_addr_octet[2]];
	pd->ether_addr_octet[3] = endianswap[ps->ether_addr_octet[3]];
	pd->ether_addr_octet[4] = endianswap[ps->ether_addr_octet[4]];
	pd->ether_addr_octet[5] = endianswap[ps->ether_addr_octet[5]];
}

/* ARGSUSED */
uint_t
ib_header_len(char *hdr, size_t msgsize)
{
	return (IPOIB_HDRSIZE);
}

static uint_t
interpret_ib(int flags, char *header, int elen, int origlen)
{
	struct ipoib_header *hdr = (struct ipoib_header *)header;
	char *off;
	int len;
	unsigned short ethertype;
	int blen = MAX(origlen, 4096);

	if (data != NULL && datalen != 0 && datalen < blen) {
		free(data);
		data = NULL;
		datalen = 0;
	}
	if (data == NULL) {
		data = malloc(blen);
		if (data == NULL)
			pr_err("Warning: malloc failure");
		datalen = blen;
	}
	if (origlen < IPOIB_HDRSIZE) {
		if (flags & F_SUM)
			(void) snprintf(get_sum_line(), MAXLINE,
			    "RUNT (short packet - %d bytes)", origlen);
		if (flags & F_DTAIL)
			show_header("RUNT:  ", "Short packet", origlen);
		return (elen);
	}
	if (elen < IPOIB_HDRSIZE)
		return (elen);

	/*
	 * It is not possible to understand just by looking
	 * at the header whether this was a broad/multi cast
	 * packet; thus dst_name is not updated.
	 */
	ethertype = ntohs(hdr->ipoib_type);
	len = elen - IPOIB_HDRSIZE;
	off = (char *)(hdr + 1);
	(void) memcpy(data, off, len);

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "IPIB Type=%04X (%s), size = %d bytes",
		    ethertype,
		    print_ethertype(ethertype),
		    origlen);
	}

	if (flags & F_DTAIL) {
		show_header("IPIB:  ", "IPIB Header", elen);
		show_space();
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Packet %d arrived at %d:%02d:%d.%02d",
		    pi_frame, pi_time_hour, pi_time_min,
		    pi_time_sec, pi_time_usec / 10000);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "Packet size = %d bytes", elen, elen);
		(void) snprintf(get_line(0, 2), get_line_remain(),
		    "Ethertype = %04X (%s)", ethertype,
		    print_ethertype(ethertype));
		show_space();
	}

	/* Go to the next protocol layer */
	switch (ethertype) {
		case ETHERTYPE_IP:
			(void) interpret_ip(flags, (struct ip *)data, len);
			break;
		case ETHERTYPE_IPV6:
			(void) interpret_ipv6(flags, (ip6_t *)data, len);
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			interpret_arp(flags, (struct arphdr *)data, len);
			break;
	}

	return (elen);
}

/* ARGSUSED */
uint_t
ipnet_header_len(char *hdr, size_t msgsize)
{
	return (sizeof (dl_ipnetinfo_t));
}

#define	MAX_UINT64_STR	22
static uint_t
interpret_ipnet(int flags, char *header, int elen, int origlen)
{
	dl_ipnetinfo_t dl;
	size_t len = elen - sizeof (dl_ipnetinfo_t);
	char *off = (char *)header + sizeof (dl_ipnetinfo_t);
	int blen = MAX(origlen, 8252);
	char szone[MAX_UINT64_STR];
	char dzone[MAX_UINT64_STR];

	(void) memcpy(&dl, header, sizeof (dl));
	if (data != NULL && datalen != 0 && datalen < blen) {
		free(data);
		data = NULL;
		datalen = 0;
	}
	if (data == NULL) {
		data = (char *)malloc(blen);
		if (!data)
			pr_err("Warning: malloc failure");
		datalen = blen;
	}

	if (dl.dli_zsrc == ALL_ZONES)
		sprintf(szone, "Unknown");
	else
		sprintf(szone, "%lu", BE_32(dl.dli_zsrc));

	if (dl.dli_zdst == ALL_ZONES)
		sprintf(dzone, "Unknown");
	else
		sprintf(dzone, "%lu", BE_32(dl.dli_zdst));

	if (flags & F_SUM) {
		(void) snprintf(get_sum_line(), MAXLINE,
		    "IPNET src zone %s dst zone %s", szone, dzone);
	}

	if (flags & F_DTAIL) {
		show_header("IPNET:  ", "IPNET Header", elen);
		show_space();
		(void) sprintf(get_line(0, 0),
		    "Packet %d arrived at %d:%02d:%d.%05d",
		    pi_frame,
		    pi_time_hour, pi_time_min, pi_time_sec,
		    pi_time_usec / 10);
		(void) sprintf(get_line(0, 0),
		    "Packet size = %d bytes",
		    elen);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "dli_version = %d", dl.dli_version);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    "dli_family = %d", dl.dli_family);
		(void) snprintf(get_line(0, 2), get_line_remain(),
		    "dli_zsrc = %s", szone);
		(void) snprintf(get_line(0, 2), get_line_remain(),
		    "dli_zdst = %s", dzone);
		show_space();
	}
	memcpy(data, off, len);

	switch (dl.dli_family) {
	case AF_INET:
		(void) interpret_ip(flags, (struct ip *)data, len);
		break;
	case AF_INET6:
		(void) interpret_ipv6(flags, (ip6_t *)data, len);
		break;
	default:
		break;
	}

	return (0);
}

uint_t
ipv4_header_len(char *hdr, size_t msgsize)
{
	return (msgsize < sizeof (ipha_t) ? 0 : IPH_HDR_LENGTH((ipha_t *)hdr));
}

/*
 * The header length needs to include all potential extension headers, as the
 * caller expects to use this length as an offset to the inner network layer
 * header to be used as a filter offset.  IPsec headers aren't passed up here,
 * and neither are fragmentation headers.
 */
uint_t
ipv6_header_len(char *hdr, size_t msgsize)
{
	ip6_t		*ip6hdr = (ip6_t *)hdr;
	ip6_hbh_t	*exthdr;
	uint_t		hdrlen = sizeof (ip6_t), exthdrlen;
	char		*pptr;
	uint8_t		nxt;

	if (msgsize < sizeof (ip6_t))
		return (0);

	nxt = ip6hdr->ip6_nxt;
	pptr = (char *)(ip6hdr + 1);

	while (nxt != IPPROTO_ENCAP && nxt != IPPROTO_IPV6) {
		switch (nxt) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
			if (msgsize < hdrlen + sizeof (ip6_hbh_t))
				return (0);
			exthdr = (ip6_hbh_t *)pptr;
			exthdrlen = 8 + exthdr->ip6h_len * 8;
			hdrlen += exthdrlen;
			pptr += exthdrlen;
			nxt = exthdr->ip6h_nxt;
			break;
		default:
			/*
			 * This is garbage, there's no way to know where the
			 * inner IP header is.
			 */
			return (0);
		}
	}

	return (hdrlen);
}

/* ARGSUSED */
uint_t
interpret_iptun(int flags, char *header, int elen, int origlen)
{
	(void) interpret_ip(flags, (struct ip *)header, elen);
	return (elen);
}
