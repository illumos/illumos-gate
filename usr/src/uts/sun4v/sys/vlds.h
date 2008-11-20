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

#ifndef	_SYS_VLDS_H_
#define	_SYS_VLDS_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LDOMS Domain Services Device Driver
 */

/*
 * ioctl info for vlds device
 */

#define	VLDSIOC		('d' << 16 | 's' << 8)

#define	VLDS_SVC_REG	(VLDSIOC | 1)	/* Register DS Service */
#define	VLDS_UNREG_HDL	(VLDSIOC | 2)	/* Unregister DS Service by Handle */
#define	VLDS_HDL_LOOKUP	(VLDSIOC | 3)	/* Lookup DS Handle(s) by Service id */
#define	VLDS_DMN_LOOKUP	(VLDSIOC | 4)	/* Lookup DS Domain id by Handle */
#define	VLDS_SEND_MSG	(VLDSIOC | 5)	/* Send DS Message by Handle */
#define	VLDS_RECV_MSG	(VLDSIOC | 6)	/* Receive DS Message by Handle */
#define	VLDS_HDL_ISREADY (VLDSIOC | 7)	/* Handle ready for data transfers */
#define	VLDS_DOM_NAM2HDL (VLDSIOC | 8)	/* Domain Name to Handle translation */
#define	VLDS_DOM_HDL2NAM (VLDSIOC | 9)	/* Handle ready for data transfers */

/* vlds_reg_flags */
#define	VLDS_REG_CLIENT		0x01	/* Register as client */
#define	VLDS_REGCB_VALID	0x02	/* User supplied Register callback */
#define	VLDS_UNREGCB_VALID	0x04	/* User supplied Unregister callback */
#define	VLDS_DATACB_VALID	0x08	/* User supplied Data callback */
#define	VLDS_ANYCB_VALID	(VLDS_REGCB_VALID | VLDS_UNREGCB_VALID | \
				    VLDS_DATACB_VALID)

#define	VLDS_MAX_VERS		20	/* Max no. of vlds_ver_t entries */

/*
 * The following are declared so that they are size-invariant.
 */

/* String arguments to ioctl */
typedef struct vlds_string_arg {
	uint64_t	vlds_strp;
	uint64_t	vlds_strlen;
} vlds_string_t;

/* Version array (used by VLDS_SVC_REG) */
typedef struct vlds_ver {
	uint16_t	vlds_major;
	uint16_t	vlds_minor;
} vlds_ver_t;

/* Capability structure (used by VLDS_SVC_REG) */
typedef struct vlds_cap {
	vlds_string_t	vlds_service;
	uint64_t	vlds_nver;
	uint64_t	vlds_versp;
} vlds_cap_t;

/*
 * VLDS_SVC_REG
 */
typedef struct vlds_svc_reg_arg {
	uint64_t	vlds_hdlp;	/* DS Service Handle ptr. (returned) */
	uint64_t	vlds_capp;	/* DS Capability Structure ptr. */
	uint64_t	vlds_reg_flags;	/* DS reg flags */
} vlds_svc_reg_arg_t;

/*
 * VLDS_UNREG_HDL
 */
typedef struct vlds_unreg_hdl_arg {
	uint64_t	vlds_hdl;	/* DS Service Handle */
} vlds_unreg_hdl_arg_t;

/*
 * VLDS_DMN_LOOKUP
 */
typedef struct vlds_dmn_lookup_arg {
	uint64_t	vlds_hdl;	/* DS Service Handle */
	uint64_t	vlds_dhdlp;	/* DS Domain hdl ptr. (returned) */
} vlds_dmn_lookup_arg_t;

/*
 * VLDS_HDL_LOOKUP
 */
typedef struct vlds_hdl_lookup_arg {
	vlds_string_t	vlds_service;	/* DS Service Name */
	uint64_t	vlds_isclient;	/* DS Client flag */
	uint64_t	vlds_hdlsp;	/* DS Handle array ptr */
	uint64_t	vlds_maxhdls;	/* DS Max no. of hdls to return */
	uint64_t	vlds_nhdlsp;	/* DS No. of hdls returned */
} vlds_hdl_lookup_arg_t;

/*
 * VLDS_SEND_MSG
 */
typedef struct vlds_send_msg_arg {
	uint64_t	vlds_hdl;	/* DS Service Handle */
	uint64_t	vlds_bufp;	/* buffer */
	uint64_t	vlds_buflen;	/* message length/buffer size */
} vlds_send_msg_arg_t;

/*
 * VLDS_RECV_MSG
 */
typedef struct vlds_recv_msg_arg {
	uint64_t	vlds_hdl;	/* DS Service Handle */
	uint64_t	vlds_bufp;	/* buffer */
	uint64_t	vlds_buflen;	/* message length/buffer size */
	uint64_t	vlds_msglenp;	/* ptr to returned message length */
} vlds_recv_msg_arg_t;

/*
 * VLDS_HDL_ISREADY
 */
typedef struct vlds_hdl_isready_arg {
	uint64_t	vlds_hdl;	/* DS Service Handle */
	uint64_t	vlds_isreadyp;	/* Ptr to isready flag */
} vlds_hdl_isready_arg_t;

/*
 * VLDS_DOM_NAM2HDL
 */
typedef struct vlds_dom_nam2hdl_arg {
	vlds_string_t	vlds_domain_name; /* Domain Name string */
	uint64_t	vlds_dhdlp;	/* ptr to returned Domain Handle */
} vlds_dom_nam2hdl_arg_t;

/*
 * VLDS_DOM_HDL2NAM
 */
typedef struct vlds_dom_hdl2nam_arg {
	uint64_t	vlds_dhdl;	/* Domain Handle */
	vlds_string_t	vlds_domain_name; /* returned Domain Name string */
} vlds_dom_hdl2nam_arg_t;

/*
 * Machine Description Constants for vlds driver.
 */
#define	VLDS_MD_VIRT_DEV_NAME	"virtual-device"
#define	VLDS_MD_VIRT_ROOT_NAME	"virtual-domain-service"
#define	VLDS_MD_DOMAIN_HDL	"vlds-domain-handle"
#define	VLDS_MD_DOMAIN_NAME	"vlds-domain-name"
#define	VLDS_MD_VIRT_PORT_NAME	"virtual-device-port"
#define	VLDS_MD_REM_DOMAIN_HDL	"vlds-remote-domain-handle"
#define	VLDS_MD_REM_DOMAIN_NAME	"vlds-remote-domain-name"

/*
 * VLDS Sysevent defines.
 * VLDS System Event Channel names are of the form:
 *    sun.com:vlds:pid<pid_number>
 */
#define	VLDS_SYSEV_CHAN_FMT		"sun.com:vlds:pid%06d"
#define	VLDS_SYSEV_MAX_CHAN_NAME	32

#define	EC_VLDS		"EC_vlds"	/* LDOMS Domain Services event class */

/*
 * EC_VLDS subclass definitions - supporting attributes (name/value pairs) are
 * found in sys/sysevent/vlds.h
 */
#define	ESC_VLDS_REGISTER	"ESC_VLDS_register"
#define	ESC_VLDS_UNREGISTER	"ESC_VLDS_unregister"
#define	ESC_VLDS_DATA		"ESC_VLDS_data"

/*
 * Event type EC_VLDS
 *	Event Class	- EC_VLDS
 *	Event Sub-Class	- ESC_VLDS_REGISTER
 *	Event Publisher	- SUNW:kern:[ds_module_name]
 *	Attribute Name	- VLDS_HDL
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value	- [Domain Service Handle]
 *	Attribute Name	- VLDS_VER_MAJOR
 *	Attribute Type	- SE_DATA_TYPE_UINT16
 *	Attribute Value	- [major version of the DS interface]
 *	Attribute Name	- VLDS_VER_MINOR
 *	Attribute Type	- SE_DATA_TYPE_UINT16
 *	Attribute Value	- [minor version of the DS interface]
 *	Attribute Name	- VLDS_DOMAIN_HDL
 *	Attribute Type	- SE_DATA_TYPE_UINT64
 *	Attribute Value	- [Domain handle of registered service]
 *	Attribute Name	- VLDS_SERVICE_ID
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [Service name of registered service]
 *	Attribute Name	- VLDS_ISCLIENT
 *	Attribute Type	- SE_DATA_TYPE_BOOLEAN_VALUE
 *	Attribute Value	- [Service is client or provider]
 *
 *	Event Class	- EC_VLDS
 *	Event Sub-Class	- ESC_VLDS_UNREGISTER
 *	Event Publisher	- SUNW:kern:[ds_module_name]
 *	Attribute Name	- VLDS_HDL
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value	- [Domain Service Handle]
 *
 *	Event Class	- EC_VLDS
 *	Event Sub-Class	- ESC_VLDS_DATA
 *	Event Publisher	- SUNW:kern:[ds_module_name]
 *	Attribute Name	- VLDS_HDL
 *	Attribute Type  - SE_DATA_TYPE_UINT64
 *	Attribute Value	- [Domain Service Handle]
 *	Attribute Name	- VLDS_DATA
 *	Attribute Type  - SE_DATA_TYPE_BYTE_ARRAY
 *	Attribute Value	- [Data array passed to user]
 */

#define	VLDS_HDL	"vlds_hdl"		/* service handle */
#define	VLDS_VER_MAJOR	"vlds_ver_major"	/* major version */
#define	VLDS_VER_MINOR	"vlds_ver_minor"	/* minor version */
#define	VLDS_DOMAIN_HDL	"vlds_domain_hdl"	/* domain handle */
#define	VLDS_SERVICE_ID	"vlds_service_id"	/* service id */
#define	VLDS_ISCLIENT	"vlds_isclient"		/* service is client */
#define	VLDS_DATA	"vlds_data"		/* data buffer */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VLDS_H_ */
