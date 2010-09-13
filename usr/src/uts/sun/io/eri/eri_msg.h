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

#ifndef	_SYS_ERI_MSG_H
#define	_SYS_ERI_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
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
static  char *kstat_create_fail_msg = "kstat_create failed";
static  char *param_reg_fail_msg = "param_register failed";

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ERI_MSG_H */
