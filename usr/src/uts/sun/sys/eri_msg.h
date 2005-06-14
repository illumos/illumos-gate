/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_ERI_MSG_H
#define	_SYS_ERI_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * All strings used by eri messaging functions
 */

#if defined(DEBUG)
#ifdef	LATER
static  char *par_detect_fault_msg = "Parallel Detection Fault";
static  char *autoneg_speed_bad_msg = "Autonegotiated speed is bad";
static  char *phy_speed_bad_msg = "The current Phy/xcvr speed is not valid";
static  char *no_phy_msg = "No Phy/xcvr found";
static  char *unk_phy_msg = "Non supported Phy/Xcvr, Vendor Id: %x";
static  char *lucent_phy_msg = "Lucent Phy, Vendor Id: %x";
static  char *link_up_msg = "Link Up";
static  char *link_status_msg = "%s %4d Mbps %s-Duplex Link Up";
#endif
#if	0
static	char *link_down_msg =
	"No response from Ethernet network : Link down -- cable problem?";
#endif
static  char *mif_write_fail_msg = "MIF Write failure";
#endif

/*
 * All strings used by eri messaging functions
 */
static  char *loopback_val_default = "Loopback Value: Error In Value.";
static  char *loopback_cmd_default = "Loopback Command: Error In Value.";
static  char *lmac_addr_msg = "Using local MAC address";
static  char *lether_addr_msg = "Local Ethernet address = %s";
static  char *busy_msg = "Driver is BUSY with upper layer";
static  char *attach_fail_msg = "Attach entry point failed";

#if defined(DEBUG)
static  char *attach_bad_cmd_msg = "Attach entry point rcv'd a bad command";
static  char *burst_size_msg = "Could not identify the burst size";
static  char *detach_bad_cmd_msg = "Detach entry point rcv'd a bad command";
static  char *add_intr_fail_msg = "ddi_add_intr(9F) failed";
static  char *create_minor_node_fail_msg = "ddi_create_minor_node(9F) failed";
#ifdef	LATER
static  char *mregs_4config_fail_msg =
	"ddi_regs_map_setup(9F) for config space failed";
#endif
static  char *mregs_4global_reg_fail_msg =
	"ddi_regs_map_setup(9F) for global reg failed";
#endif

static  char *mregs_4soft_reset_fail_msg =
	"ddi_regs_map_setup(9F) for soft reset failed";
static  char *disable_erx_msg = "Can not disable Rx.";
static  char *disable_etx_msg = "Can not disable Tx.";
static  char *unk_tx_descr_sze_msg = "Unknown Tx descriptor size %x.";
static  char *unk_rx_descr_sze_msg = "Unknown Rx descriptor size %x.";
static  char *disable_txmac_msg = "Txmac could not be disabled.";
static  char *disable_rxmac_msg = "Rxmac could not be disabled.";
static  char *alloc_tx_dmah_msg = "Can not allocate Tx dma handle.";
static  char *alloc_rx_dmah_msg = "Can not allocate Rx dma handle.";
static  char *config_space_fatal_msg =
	"Configuration space failed in routine.";
static  char *link_down_msg =
	"No response from Ethernet network : Link down -- cable problem?";
static  char *kstat_create_fail_msg = "kstat_create failed";
static  char *param_reg_fail_msg = "param_register failed";

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ERI_MSG_H */
