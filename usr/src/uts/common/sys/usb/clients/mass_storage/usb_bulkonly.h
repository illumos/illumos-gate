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

#ifndef _SYS_USB_BULKONLY_H
#define	_SYS_USB_BULKONLY_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * usb_bulkonly.h: This header file provides the data structures
 * and variable definitions for the mass storage bulk only protocol.
 * (See Universal Serial Bus Mass Storage Class Bulk-Only Transport rev 1.0)
 */

/* Reset value to be passed */
#define	BULK_ONLY_RESET			0xFF
/* Bulk Class specific req  */
/* Bulk Class specific GET_Max_LUN bmRequest value */
#define	BULK_ONLY_GET_MAXLUN_BMREQ \
	(USB_DEV_REQ_DEV_TO_HOST | USB_DEV_REQ_TYPE_CLASS | \
		USB_DEV_REQ_RCPT_IF)
/* Bulk Class specific GET_Max_LUN bRequest value */
#define	BULK_ONLY_GET_MAXLUN_REQ	0xFE

/*
 * Command Block Wrapper:
 *	The CBW is used to transfer commands to the device.
 */
#define	CBW_SIGNATURE	0x43425355	/* "USBC" */
#define	CBW_DIR_IN	0x80		/* CBW from device to the host */
#define	CBW_DIR_OUT	0x00		/* CBW from host to the device */
#define	CBW_CDB_LEN	16		/* CDB Len to 10 byte cmds */

#define	USB_BULK_CBWCMD_LEN	0x1F

#define	CBW_MSB(x)	((x) & 0xFF)		/* Swap msb */
#define	CBW_MID1(x)	((x) >> 8 & 0xFF)
#define	CBW_MID2(x)	((x) >> 16 & 0xFF)
#define	CBW_LSB(x)	((x) >> 24 & 0xFF)

/*
 * Command Status Wrapper:
 *	The device shall not execute any subsequent command until the
 *	associated CSW from the previous command has been successfully
 *	transported.
 *
 *	All CSW transfers shall be ordered withe LSB first.
 */
typedef	struct usb_bulk_csw {
	uchar_t	csw_dCSWSignature0;	/* Signature */
	uchar_t	csw_dCSWSignature1;
	uchar_t	csw_dCSWSignature2;
	uchar_t	csw_dCSWSignature3;
	uchar_t	csw_dCSWTag3;		/* random tag */
	uchar_t	csw_dCSWTag2;
	uchar_t	csw_dCSWTag1;
	uchar_t	csw_dCSWTag0;
	uchar_t	csw_dCSWDataResidue0;	/* data not transferred */
	uchar_t	csw_dCSWDataResidue1;
	uchar_t	csw_dCSWDataResidue2;
	uchar_t	csw_dCSWDataResidue3;
	uchar_t	csw_bCSWStatus;		/* command status */
} usb_bulk_csw_t;

#define	CSW_SIGNATURE	0x53425355	/* "SBSU" */

#define	CSW_STATUS_GOOD		0x0	/* Good status */
#define	CSW_STATUS_FAILED	0x1	/* Command failed */
#define	CSW_STATUS_PHASE_ERROR	0x2	/* Phase error */
#define	CSW_LEN			0xD	/* CSW Command Len */

/* Vendor specific command needed for specific Bulk Only devices */
#define	IOMEGA_CMD_CARTRIDGE_PROTECT	0x0C

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_BULKONLY_H */
