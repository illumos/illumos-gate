/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Nexenta Systems, Inc.
 */

#ifndef _SYS_SCSI_SCSI_NAMES_H_
#define	_SYS_SCSI_SCSI_NAMES_H_

#ifdef __cplusplus
extern "C" {
#endif

/* SCSI Name Strings */
#define	SNS_EUI		"eui"
#define	SNS_IQN		"iqn"
#define	SNS_MAC		"mac"
#define	SNS_NAA		"naa"
#define	SNS_WWN		"wwn"

/* SCSI Name String maximum length definitions */
#define	SNS_EUI_16	16
#define	SNS_IQN_223	223
#define	SNS_MAC_12	12
#define	SNS_NAA_16	16
#define	SNS_NAA_32	32
#define	SNS_WWN_16	16

#define	SNS_EUI_LEN_MAX		sizeof (SNS_EUI) + SNS_EUI_16
#define	SNS_IQN_LEN_MAX		SNS_IQN_223
#define	SNS_MAC_LEN_MAX		sizeof (SNS_MAC) + SNS_MAC_12
#define	SNS_NAA_LEN_MAX		sizeof (SNS_NAA) + SNS_NAA_32
#define	SNS_WWN_LEN_MAX		sizeof (SNS_WWN) + SNS_WWN_16

#define	SNS_LEN_MAX		SNS_IQN_LEN_MAX

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_SCSI_SCSI_NAMES_H_ */
