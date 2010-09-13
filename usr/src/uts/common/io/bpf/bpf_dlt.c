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

#include <sys/types.h>
#include <sys/dlpi.h>
#include <net/if.h>
#include <net/dlt.h>

/*
 * This table provides a mapping of the DLPI data link types used in
 * Solaris to the BPF data link types. Providing this translation in
 * the kernel allows libpcap to be downloaded and used without any
 * need for change.
 *
 * Note that this table is not necessarily sorted.
 */
static uint_t dl_to_dlt[][3] = {
	{ DL_CSMACD,	DLT_EN10MB,	14 },	/* IEEE 802.3 CSMA/CD */
	{ DL_TPB,	DLT_NULL,	0 },	/* IEEE 802.4 Token Bus */
	{ DL_TPR,	DLT_IEEE802,	0 },	/* IEEE 802.5 Token Ring */
	{ DL_METRO,	DLT_NULL,	0 },	/* IEEE 802.6 Metro Net */
	{ DL_ETHER,	DLT_EN10MB,	14 },	/* Ethernet Bus */
	{ DL_HDLC,	DLT_C_HDLC,	0 },	/* Cisco HDLC protocol */
	{ DL_CHAR,	DLT_NULL,	0 },	/* Character Synchr. proto */
	{ DL_CTCA,	DLT_NULL,	0 },	/* IBM Channel-to-Channel */
	{ DL_FDDI,	DLT_FDDI,	24 },	/* Fiber Distributed data */
	{ DL_FC,	DLT_NULL,	0 },	/* Fibre Channel interface */
	{ DL_ATM,	DLT_SUNATM,	0 },	/* ATM */
	{ DL_IPATM,	DLT_ATM_CLIP,	0 },	/* ATM CLIP */
	{ DL_X25,	DLT_NULL,	0 },	/* X.25 LAPB interface */
	{ DL_ISDN,	DLT_NULL,	0 },	/* ISDN interface */
	{ DL_HIPPI,	DLT_HIPPI,	0 },	/* HIPPI interface */
	{ DL_100VG,	DLT_EN10MB,	14 },	/* 100 Based VG Ethernet */
	{ DL_100VGTPR,	DLT_IEEE802,	0 },	/* 100 Based VG Token Ring */
	{ DL_ETH_CSMA,	DLT_EN10MB,	14 },	/* ISO 8802/3 and Ethernet */
	{ DL_100BT,	DLT_EN10MB,	14 },	/* 100 Base T */
	{ DL_IB,	DLT_IPOIB,	44 },	/* Solaris IPoIB (infini.) */
	{ DL_FRAME,	DLT_FRELAY,	0 },	/* Frame Relay LAPF */
	{ DL_MPFRAME,	DLT_NULL,	0 },	/* Multi-protocol Frame Relay */
	{ DL_ASYNC,	DLT_NULL,	0 },	/* Character Asynch. Protocol */
	{ DL_IPX25,	DLT_NULL,	0 },	/* X.25 Classical IP */
	{ DL_LOOP,	DLT_NULL,	0 },	/* software loopback */
	{ DL_IPV4,	DLT_RAW,	0 },	/* IPv4 Tunnel Link */
	{ DL_IPV6,	DLT_RAW,	0 },	/* IPv6 Tunnel Link */
	{ SUNW_DL_VNI,	DLT_NULL,	0 },	/* Virtual network interface */
	{ DL_WIFI,	DLT_IEEE802_11,	0 },	/* IEEE 802.11 */
	{ DL_IPNET,	DLT_IPNET,	24 },	/* Solaris IP Observability */
	{ DL_OTHER,	DLT_NULL,	0 },	/* Mediums not listed above */
	{ 0,		0 }
};

/*
 * Given a data link type number used with DLPI on Solaris, return
 * the equivalent data link type number for use with BPF.
 */
int
bpf_dl_to_dlt(int dl)
{
	int i;

	for (i = 0; i < sizeof (dl_to_dlt) / sizeof (dl_to_dlt[0]); i++)
		if (dl_to_dlt[i][0] == dl)
			return (dl_to_dlt[i][1]);
	return (0);
}

/*
 * Given a DLPI data link type for Solaris, return the expected header
 * size of the link layer.
 */
int
bpf_dl_hdrsize(int dl)
{
	int i;

	for (i = 0; i < sizeof (dl_to_dlt) / sizeof (dl_to_dlt[0]); i++)
		if (dl_to_dlt[i][0] == dl)
			return (dl_to_dlt[i][2]);
	return (0);
}
