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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VGEN_STATS_H
#define	_VGEN_STATS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vgen_stats {

	/* Link Input/Output stats */
	uint64_t	ipackets;	/* # rx packets */
	uint64_t	ierrors;	/* # rx error */
	uint64_t	opackets;	/* # tx packets */
	uint64_t	oerrors;	/* # tx error */

	/* MIB II variables */
	uint64_t	rbytes;		/* # bytes received */
	uint64_t	obytes;		/* # bytes transmitted */
	uint32_t	multircv;	/* # multicast packets received */
	uint32_t	multixmt;	/* # multicast packets for xmit */
	uint32_t	brdcstrcv;	/* # broadcast packets received */
	uint32_t	brdcstxmt;	/* # broadcast packets for xmit */
	uint32_t	norcvbuf;	/* # rcv packets discarded */
	uint32_t	noxmtbuf;	/* # xmit packets discarded */

	/* Tx Statistics */
	uint32_t	tx_no_desc;	/* # out of transmit descriptors */
	uint32_t	tx_qfull;	/* pkts dropped due to qfull in vsw */
	uint32_t	tx_pri_fail;	/* # tx priority packet failures */
	uint64_t	tx_pri_packets;	/* # priority packets transmitted */
	uint64_t	tx_pri_bytes;	/* # priority bytes transmitted */

	/* Rx Statistics */
	uint32_t	rx_allocb_fail;	/* # rx buf allocb() failures */
	uint32_t	rx_vio_allocb_fail; /* # vio_allocb() failures */
	uint32_t	rx_lost_pkts;	/* # rx lost packets */
	uint32_t	rx_pri_fail;	/* # rx priority packet failures */
	uint64_t	rx_pri_packets;	/* # priority packets received */
	uint64_t	rx_pri_bytes;	/* # priority bytes received */

	/* Callback statistics */
	uint32_t	callbacks;		/* # callbacks */
	uint32_t	dring_data_acks;	/* # dring data acks recvd  */
	uint32_t	dring_stopped_acks;	/* # dring stopped acks recvd */
	uint32_t	dring_data_msgs;	/* # dring data msgs sent */

} vgen_stats_t;

typedef struct vgen_kstats {
	/*
	 * Link Input/Output stats
	 */
	kstat_named_t	ipackets;
	kstat_named_t	ipackets64;
	kstat_named_t	ierrors;
	kstat_named_t	opackets;
	kstat_named_t	opackets64;
	kstat_named_t	oerrors;

	/*
	 * required by kstat for MIB II objects(RFC 1213)
	 */
	kstat_named_t	rbytes; 	/* MIB - ifInOctets */
	kstat_named_t	rbytes64;
	kstat_named_t	obytes; 	/* MIB - ifOutOctets */
	kstat_named_t	obytes64;
	kstat_named_t	multircv; 	/* MIB - ifInNUcastPkts */
	kstat_named_t	multixmt; 	/* MIB - ifOutNUcastPkts */
	kstat_named_t	brdcstrcv;	/* MIB - ifInNUcastPkts */
	kstat_named_t	brdcstxmt;	/* MIB - ifOutNUcastPkts */
	kstat_named_t	norcvbuf; 	/* MIB - ifInDiscards */
	kstat_named_t	noxmtbuf; 	/* MIB - ifOutDiscards */

	/* Tx Statistics */
	kstat_named_t	tx_no_desc;	/* # out of transmit descriptors */
	kstat_named_t	tx_qfull;	/* pkts dropped due to qfull in vsw */
	kstat_named_t	tx_pri_fail;	/* # tx priority packet failures */
	kstat_named_t	tx_pri_packets;	/* # priority packets transmitted */
	kstat_named_t	tx_pri_bytes;	/* # priority bytes transmitted */

	/* Rx Statistics */
	kstat_named_t	rx_allocb_fail;	/* # rx buf allocb failures */
	kstat_named_t	rx_vio_allocb_fail; /* # vio_allocb() failures */
	kstat_named_t	rx_lost_pkts;	/* # rx lost packets */
	kstat_named_t	rx_pri_fail;	/* # rx priority packet failures */
	kstat_named_t	rx_pri_packets;	/* # priority packets received */
	kstat_named_t	rx_pri_bytes;	/* # priority bytes received */

	/* Callback statistics */
	kstat_named_t	callbacks;		/* # callbacks */
	kstat_named_t	dring_data_acks;	/* # dring data acks recvd  */
	kstat_named_t	dring_stopped_acks;	/* # dring stopped acks recvd */
	kstat_named_t	dring_data_msgs;	/* # dring data msgs sent */

} vgen_kstats_t;

kstat_t *vgen_setup_kstats(char *ks_mod, int instance,
    char *ks_name, vgen_stats_t *statsp);
void vgen_destroy_kstats(kstat_t *ksp);
int vgen_kstat_update(kstat_t *ksp, int rw);

#ifdef __cplusplus
}
#endif

#endif	/* _VGEN_STATS_H */
