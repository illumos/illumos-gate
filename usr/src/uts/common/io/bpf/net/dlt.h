/*	$NetBSD: dlt.h,v 1.11 2006/02/27 14:22:26 drochner Exp $	*/

/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)bpf.h	8.2 (Berkeley) 1/9/95
 * @(#) Header: bpf.h,v 1.36 97/06/12 14:29:53 leres Exp  (LBL)
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NET_DLT_H_
#define	_NET_DLT_H_

/*
 * Data-link level type codes.
 */
#define	DLT_NULL	0	/* no link-layer encapsulation */
#define	DLT_EN10MB	1	/* Ethernet (10Mb) */
#define	DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define	DLT_AX25	3	/* Amateur Radio AX.25 */
#define	DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define	DLT_CHAOS	5	/* Chaos */
#define	DLT_IEEE802	6	/* IEEE 802 Networks */
#define	DLT_ARCNET	7	/* ARCNET */
#define	DLT_SLIP	8	/* Serial Line IP */
#define	DLT_PPP		9	/* Point-to-point Protocol */
#define	DLT_FDDI	10	/* FDDI */
#define	DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define	DLT_RAW		12	/* raw IP */
#define	DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define	DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */
#define	DLT_HIPPI	15	/* HIPPI */
#define	DLT_HDLC	16	/* HDLC framing */

#define	DLT_PFSYNC	18	/* Packet filter state syncing */
#define	DLT_ATM_CLIP	19	/* Linux Classical-IP over ATM */
#define	DLT_ENC		109	/* Encapsulated packets for IPsec */
#define	DLT_LINUX_SLL	113	/* Linux cooked sockets */
#define	DLT_LTALK	114	/* Apple LocalTalk hardware */
#define	DLT_PFLOG	117	/* Packet filter logging, by pcap people */
#define	DLT_CISCO_IOS	118	/* Registered for Cisco-internal use */

/* Axent Raptor / Symantec Enterprise Firewall */
#define	DLT_SYMANTEC_FIREWALL	99

#define	DLT_C_HDLC		104	/* Cisco HDLC */
#define	DLT_IEEE802_11		105	/* IEEE 802.11 wireless */
#define	DLT_FRELAY		107	/* Frame Relay */
#define	DLT_LOOP		108	/* OpenBSD DLT_LOOP */
#define	DLT_ECONET		115	/* Acorn Econet */
#define	DLT_PRISM_HEADER	119	/* 802.11 header plus Prism II info. */
#define	DLT_AIRONET_HEADER 	120	/* 802.11 header plus Aironet info. */
#define	DLT_HHDLC		121	/* Reserved for Siemens HiPath HDLC */
#define	DLT_IP_OVER_FC		122	/* RFC 2625 IP-over-Fibre Channel */
#define	DLT_SUNATM		123	/* Solaris+SunATM */
#define	DLT_RIO			124	/* RapidIO */
#define	DLT_PCI_EXP		125	/* PCI Express */
#define	DLT_AURORA		126	/* Xilinx Aurora link layer */
#define	DLT_IEEE802_11_RADIO 	127	/* 802.11 header plus radio info. */
#define	DLT_TZSP		128	/* Tazmen Sniffer Protocol */
#define	DLT_ARCNET_LINUX	129	/* ARCNET */
#define	DLT_JUNIPER_MLPPP	130	/* Juniper-private data link types. */
#define	DLT_JUNIPER_MLFR	131
#define	DLT_JUNIPER_ES		132
#define	DLT_JUNIPER_GGSN	133
#define	DLT_JUNIPER_MFR		134
#define	DLT_JUNIPER_ATM2	135
#define	DLT_JUNIPER_SERVICES	136
#define	DLT_JUNIPER_ATM1	137
#define	DLT_APPLE_IP_OVER_IEEE1394	138	/* Apple IP-over-IEEE 1394 */

/* Various SS7 encapsulations */
#define	DLT_MTP2_WITH_PHDR	139	/* pseudo-header with various info, */
					/* followed by MTP2 */
#define	DLT_MTP2		140	/* MTP2, no pseudo-header */
#define	DLT_MTP3		141	/* MTP3, no pseudo-header or MTP2 */
#define	DLT_SCCP		142	/* SCCP, no pseudo-header or MTP2 */
					/* or MTP3 */

#define	DLT_DOCSIS		143	/* Reserved for DOCSIS MAC frames. */
#define	DLT_LINUX_IRDA		144	/* Linux-IrDA packets */

/* Reserved for IBM SP switch and IBM Next Federation switch. */
#define	DLT_IBM_SP		145
#define	DLT_IBM_SN		146

#define	DLT_IEEE802_11_RADIO_AVS	163	/* 802.11 plus AVS header */
#define	DLT_JUNIPER_MONITOR	164	/* Juniper-private data link type */
#define	DLT_BACNET_MS_TP	165
#define	DLT_PPP_PPPD		166	/* Another PPP variant (Linux? */

#define	DLT_JUNIPER_PPPOE	167
#define	DLT_JUNIPER_PPPOE_ATM	168
#define	DLT_JUNIPER_PIC_PEER	174
#define	DLT_JUNIPER_ETHER	178
#define	DLT_JUNIPER_PPP		179
#define	DLT_JUNIPER_FRELAY	180
#define	DLT_JUNIPER_CHDLC	181

#define	DLT_GPRS_LLC		169	/* GPRS LLC */
#define	DLT_GPF_T		170	/* GPF-T (ITU-T G.7041/Y.1303) */
#define	DLT_GPF_F		171	/* GPF-F (ITU-T G.7041/Y.1303) */

#define	DLT_GCOM_T1E1		172
#define	DLT_GCOM_SERIAL		173

/* "EndaceRecordFormat" */
#define	DLT_ERF_ETH		175	/* Ethernet */
#define	DLT_ERF_POS		176	/* Packet-over-SONET */

#define	DLT_LINUX_LAPD		177	/* Raw LAPD for vISDN */

#define	DLT_IPNET		226	/* MAC client view on Solaris */
/*
 * A number reserved for private user use is currently assigned, pending
 * a real one from tcpdump.org. A description of the link layer frame
 * is a requisite for this.
 */
#define	DLT_IPOIB		162	/* Infiniband (IPoIB) on Solaris */

/*
 * NetBSD-specific generic "raw" link type.  The upper 16-bits indicate
 * that this is the generic raw type, and the lower 16-bits are the
 * address family we're dealing with.
 */
#define	DLT_RAWAF_MASK		0x02240000
#define	DLT_RAWAF(af)		(DLT_RAWAF_MASK | (af))
#define	DLT_RAWAF_AF(x)		((x) & 0x0000ffff)
#define	DLT_IS_RAWAF(x)		(((x) & 0xffff0000) == DLT_RAWAF_MASK)

/*
 * Solaris specific function to map DLPI DL_ data link types to BPF DLT_
 */
extern int bpf_dl_to_dlt(int);
extern int bpf_dl_hdrsize(int);

#endif /* !_NET_DLT_H_ */
