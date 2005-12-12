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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IB_DM_ATTR_H
#define	_SYS_IB_MGT_IB_DM_ATTR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ib_dm_attr.h
 *
 * This file contains definitions for Device Management data structures
 * defined in the IB specification (Section 16.3).
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Device management Methods */
#define	IB_DM_DEVMGT_METHOD_GET			0x01
#define	IB_DM_DEVMGT_METHOD_SET			0x02
#define	IB_DM_DEVMGT_METHOD_GET_RESP		0x81
#define	IB_DM_DEVMGT_METHOD_TRAP		0x05
#define	IB_DM_DEVMGT_METHOD_TRAP_REPRESS	0x07

/* Device Class version */
#define	IB_DM_CLASS_VERSION_1			0x1

/* Device Management Status field */
#define	IB_DM_DEVMGT_MAD_STAT_NORESP		0x0100
#define	IB_DM_DEVMGT_MAD_STAT_NOSVC_ENTRIES	0x0200
#define	IB_DM_DEVMGT_MAD_STAT_GEN_FAILURE	0x8000

/* Device Management attributes */
#define	IB_DM_ATTR_CLASSPORTINFO		0x1
#define	IB_DM_ATTR_NOTICE			0x2
#define	IB_DM_ATTR_IO_UNITINFO			0x10
#define	IB_DM_ATTR_IOC_CTRL_PROFILE		0x11
#define	IB_DM_ATTR_SERVICE_ENTRIES		0x12
#define	IB_DM_ATTR_DIAG_TIMEOUT			0x20
#define	IB_DM_ATTR_PREPARE_TO_TEST		0x21
#define	IB_DM_ATTR_TEST_DEV_ONCE		0x22
#define	IB_DM_ATTR_TEST_DEV_LOOP		0x23
#define	IB_DM_ATTR_DIAG_CODE			0x24

/* IOUnitInfo DM attribute (Section 16.3.3.3 in vol1a) definition */
#define	IB_DM_MAX_IOCS_IN_IOU			256

typedef struct ib_dm_io_unitinfo_s {
	/* Incremented, with rollover, by any change in the controller list */
	uint16_t	iou_changeid;
	uint8_t		iou_num_ctrl_slots;	/* # controllers in the IOU */

	/*
	 * Bit 0 : Option ROM present
	 * Bit 1 : Diag Device ID
	 */
	uint8_t		iou_flag;

	/*
	 *  List of nibbles representing a slot in the IOU
	 *  Contains iou_num_ctrl_slots valid entries
	 *  0x0 = IOC not installed
	 *  0x1 = IOC present
	 *  0xf = Slot does not exist
	 *  Note: Bits 7-4 of the first byte represent slot 1 and
	 *	bits 3-0 of first byte represents slot 2, bits 7-4 of
	 *	second byte represents slot 3, and so on
	 */
	uint8_t	iou_ctrl_list[128];
} ib_dm_io_unitinfo_t;

/* values for iou_flag */
#define	IB_DM_IOU_OPTIONROM_ABSENT	0x0
#define	IB_DM_IOU_OPTIONROM_PRESENT	0x1

/* masks for iou_flag */
#define	IB_DM_IOU_OPTIONROM_MASK	0x1
#define	IB_DM_IOU_DEVICEID_MASK		0x2

#define	IB_DM_IOC_ID_STRING_LEN		64	/* see ioc_id_string later */
#define	IB_DM_VENDORID_MASK		0xFFFFFF00
#define	IB_DM_VENDORID_SHIFT		8

typedef struct ib_dm_ioc_ctrl_profile_s {
	ib_guid_t	ioc_guid;		/* GUID of the IOC */
	uint32_t	ioc_vendorid;		/* Vendor ID of the IOC */
	uint32_t	ioc_deviceid;		/* Device ID/Product ID */
	uint16_t	ioc_device_ver;		/* Device Version */
	uint16_t	ioc_rsvd1;		/* RESERVED */
	uint32_t	ioc_subsys_vendorid;	/* Subsystem vendor ID */
	uint32_t	ioc_subsys_id;		/* Subsystem ID */
	uint16_t	ioc_io_class;		/* I/O Class */
	uint16_t	ioc_io_subclass;	/* I/O Sub Class */
	uint16_t	ioc_protocol;		/* Type of protocol */
	uint16_t	ioc_protocol_ver;	/* Protocol version */
	uint16_t	ioc_rsvd2;		/* RESERVED */
	uint16_t	ioc_rsvd3;		/* RESERVED */
	uint16_t	ioc_send_msg_qdepth;	/* Send message Q depth */
	uint8_t		ioc_rsvd4;		/* RESERVED */
	uint8_t		ioc_rdma_read_qdepth;	/* RDMA read Q depth */
	uint32_t	ioc_send_msg_sz;	/* Send message Size */
	uint32_t	ioc_rdma_xfer_sz;	/* RDMA transfer size */
	uint8_t		ioc_ctrl_opcap_mask;	/* Ctrl operations */
						/* capability mask */
	uint8_t		ioc_rsvd5;		/* RESERVED */
	uint8_t		ioc_service_entries;	/* Number of service entries */
	uint8_t		ioc_rsvd6[9];		/* RESERVED */
	uint8_t		ioc_id_string[IB_DM_IOC_ID_STRING_LEN];
						/* ID string, UTF-8 format */
} ib_dm_ioc_ctrl_profile_t;

/* I/O class definitions as defined in the I/O annex A0 Table 4 */
#define	IB_DM_IO_CLASS_VENDOR_SPECIFIC		0xFFFF
#define	IB_DM_IO_CLASS_NONE			0x00FF
#define	IB_DM_IO_CLASS_STORAGE			0x10FF
#define	IB_DM_IO_CLASS_NETWORK			0x20FF
#define	IB_DM_IO_CLASS_VEDIO_MULTIMEDIA		0x40FF
#define	IB_DM_IO_CLASS_UNKNOWN_OR_MULTIPLE	0xF0FF
#define	IB_DM_IO_SUBCLASS_VENDOR_SPECIFIC	0xFFFF

/* Controller Capability Mask values */
#define	IB_DM_CTRL_CAP_MASK_ST			0x0
#define	IB_DM_CTRL_CAP_MASK_SF			0x1
#define	IB_DM_CTRL_CAP_MASK_RT			0x2
#define	IB_DM_CTRL_CAP_MASK_RF			0x3
#define	IB_DM_CTRL_CAP_MASK_WT			0x4
#define	IB_DM_CTRL_CAP_MASK_WF			0x5
#define	IB_DM_CTRL_CAP_MASK_AT			0x6
#define	IB_DM_CTRL_CAP_MASK_AF			0x7

/* Controller Service Capability Mask */
#define	IB_DM_CTRL_SRVC_MASK_CS			0x0
#define	IB_DM_CTRL_SRVC_MASK_SBWP		0x1
#define	IB_DM_CTRL_SRVC_MASK_NBWP		0x2

/* Definition for service entry table 219, 16.3.3.5 */
#define	IB_DM_MAX_SVC_ENTS_PER_REQ		4
#define	IB_DM_MAX_SVC_NAME_LEN			40
#define	IB_DM_MAX_SVC_ENTRIES			0x100

typedef struct ib_dm_srv_s {
	/* Service name string in UTF-8 format */
	uint8_t		srv_name[IB_DM_MAX_SVC_NAME_LEN];
	ib_svc_id_t	srv_id;			/* Service Identifier   */
} ib_dm_srv_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_MGT_IB_DM_ATTR_H */
