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
#ifndef	_SYS_SCSI_ADAPTERS_SCSI_VHCI_TPGS_H
#define	_SYS_SCSI_ADAPTERS_SCSI_VHCI_TPGS_H

/*
 * max number of retries for std failover to complete where the ping
 * command is failing due to transport errors or commands being rejected by
 * std.
 * STD_FO_MAX_RETRIES takes into account the case where CMD_CMPLTs but
 * std takes time to complete the failover.
 */
#define	STD_FO_MAX_CMD_RETRIES	3

#define	STD_ACTIVE_OPTIMIZED    0x0
#define	STD_ACTIVE_NONOPTIMIZED 0x1
#define	STD_STANDBY		0x2
#define	STD_UNAVAILABLE		0x3
#define	STD_TRANSITIONING	0xf

#define	STD_SCSI_ASC_STATE_TRANS	0x04
#define	STD_SCSI_ASCQ_STATE_TRANS_FAIL  0x0A
#define	STD_SCSI_ASC_STATE_CHG		0x2A
#define	STD_SCSI_ASCQ_STATE_CHG_SUCC	0x06
#define	STD_SCSI_ASCQ_STATE_CHG_FAILED	0x07
#define	STD_SCSI_ASC_INVAL_PARAM_LIST	0x26
#define	STD_SCSI_ASC_INVAL_CMD_OPCODE	0x20
#define	STD_LOGICAL_UNIT_NOT_ACCESSIBLE	0x04
#define	STD_TGT_PORT_STANDBY		0x0B
#define	STD_TGT_PORT_UNAVAILABLE	0x0C

extern int vhci_tpgs_get_target_fo_mode(struct scsi_device *sd, int *mode,
    int *state, int *xlf_capable, int *preferred);

#endif /* _SYS_SCSI_ADAPTERS_SCSI_VHCI_TPGS_H */
