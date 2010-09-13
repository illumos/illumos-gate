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

/*
 * Definitions and data structures for application to exchange request
 * with driver
 */
#ifndef _SYS_USB_WUSB_CA_H
#define	_SYS_USB_WUSB_CA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/wusba_io.h>
#include <sys/usb/usba/wusba.h>

/* Refer to WUSB AM Spec 4.3 */
#define	WUSB_CBAF_GET_ASSOCIATION_INFORMATION	0x01
#define	WUSB_CBAF_GET_ASSOCIATION_REQUEST	0x02
#define	WUSB_CBAF_SET_ASSOCIATION_RESPONSE	0x03

#define	WUSB_CBAF_DEFAULT_STATE			0x01
#define	WUSB_CBAF_ADDRESS_STATE			0x02
#define	WUSB_CBAF_CONFIG_STATE			0x03

#define	WUSB_CBAF_RETRIEVE_HOST_INFO		0x0000
#define	WUSB_CBAF_ASSOCIATE_WUSB		0x0001

#define	WUSB_ASSO_INFO_SIZE			5
#define	WUSB_ASSO_REQUEST_SIZE			10
#define	WUSB_HOST_INFO_SIZE			106
#define	WUSB_DEVICE_INFO_SIZE			108
#define	WUSB_CC_DATA_SIZE			78
#define	WUSB_CC_FAILURE_SIZE			28

typedef struct __association_information {
	uint16_t		Length;
	uint8_t			NumAssociationRequests;
	uint16_t		Flag;
} wusb_cbaf_asso_info_t;

typedef struct __association_request {
	uint8_t			AssociationDataIndex;
	uint8_t			Reserved;
	uint16_t		AssociationTypeId;
	uint16_t		AssociationSubTypeId;
	uint32_t		AssociationTypeInfoSize;
} wusb_cbaf_asso_req_t;

typedef struct __host_info {
	uint16_t		AssociationTypeId;
	uint16_t		AssociationSubTypeId;
	uint8_t			CHID[16];
	uint16_t		LangID;
	char			HostFriendlyName[64];
} wusb_cbaf_host_info_t;

typedef struct __device_info {
	uint32_t		Length;
	uint8_t			CDID[16];
	uint16_t		BandGroups;
	uint16_t		LangID;
	char			DeviceFriendlyName[64];
} wusb_cbaf_device_info_t;

typedef struct __cc_data {
	uint16_t		AssociationTypeId;
	uint16_t		AssociationSubTypeId;
	uint32_t		Length;
	wusb_cc_t		CC;
	uint16_t		BandGroups;
} wusb_cbaf_cc_data_t;

typedef struct __cc_fail {
	uint16_t		AssociationTypeId;
	uint16_t		AssociationSubTypeId;
	uint32_t		Length;
	uint32_t		AssociationStatus;
} wusb_cbaf_cc_fail_t;


/* WUSB CBAF ioctl command */
#define	CBAF_IOCTL_GET_ASSO_INFO		0x0001
#define	CBAF_IOCTL_GET_ASSO_REQS		0x0002
#define	CBAF_IOCTL_SET_HOST_INFO		0x0003
#define	CBAF_IOCTL_GET_DEVICE_INFO		0x0004
#define	CBAF_IOCTL_SET_CONNECTION		0x0005
#define	CBAF_IOCTL_SET_FAILURE			0x0006

#define	CBAF_ASSO_FAILURE_DEFAULT		0x0001
#define	CBAF_ASSO_FAILURE_MALFORMED_REQUEST	0x0002
#define	CBAF_ASSO_FAILURE_TYPE_NOT_SUPPORTED	0x0003

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_WUSB_CA_H */
