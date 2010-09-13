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
#ifndef	_FCOEIO_H_
#define	_FCOEIO_H_

#include <sys/ethernet.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl cmd definitions
 */
#define	FCOEIO_CMD			('G'<< 8 | 2009)
#define	FCOEIO_SUB_CMD			('X' << 8)

/*
 * fcoe ioctl sub-command
 */
#define	FCOEIO_CREATE_FCOE_PORT			(FCOEIO_SUB_CMD + 0x01)
#define	FCOEIO_DELETE_FCOE_PORT			(FCOEIO_SUB_CMD + 0x02)
#define	FCOEIO_GET_FCOE_PORT_LIST		(FCOEIO_SUB_CMD + 0x03)

/*
 * define common-used constants
 */
#define	FCOE_MAX_MAC_NAME_LEN	32

/*
 * fcoeio_xfer definitions
 */
#define	FCOEIO_XFER_NONE		0x00
#define	FCOEIO_XFER_READ		0x01
#define	FCOEIO_XFER_WRITE		0x02
#define	FCOEIO_XFER_RW		(FCOEIO_XFER_READ | FCOEIO_XFER_WRITE)

/*
 * fcoeio_errno definitions
 */
typedef enum {
	FCOEIOE_INVAL_ARG = 5,
	FCOEIOE_BUSY,
	FCOEIOE_ALREADY,
	FCOEIOE_PWWN_CONFLICTED,
	FCOEIOE_NWWN_CONFLICTED,
	FCOEIOE_CREATE_MAC,
	FCOEIOE_OPEN_MAC,
	FCOEIOE_CREATE_PORT,
	FCOEIOE_NEED_JUMBO_FRAME,
	FCOEIOE_MAC_NOT_FOUND,
	FCOEIOE_OFFLINE_FAILURE,
	FCOEIOE_MORE_DATA
} fcoeio_stat_t;

/* Biggest buffer length, can hold up to 1024 port instances */
#define	FCOEIO_MAX_BUF_LEN	0x10000

typedef struct fcoeio {
	uint16_t	fcoeio_xfer;		/* direction */
	uint16_t	fcoeio_cmd;		/* sub command */
	uint16_t	fcoeio_flags;		/* flags */
	uint16_t	fcoeio_cmd_flags;	/* command specific flags */
	uint32_t	fcoeio_ilen;		/* Input buffer length */
	uint32_t	fcoeio_olen;		/* Output buffer length */
	uint32_t	fcoeio_alen;		/* Auxillary buffer length */
	fcoeio_stat_t	fcoeio_status;		/* FC internal error status */
	uint64_t	fcoeio_ibuf;		/* Input buffer */
	uint64_t	fcoeio_obuf;		/* Output buffer */
	uint64_t	fcoeio_abuf;		/* Auxillary buffer */
} fcoeio_t;

/*
 * Client port type
 */
typedef enum {
	FCOE_CLIENT_INITIATOR = 0,
	FCOE_CLIENT_TARGET
} fcoe_cli_type_t;

/*
 * Command for FCOEIO_CREATE_FCOET_PORT
 */
#define	FCOE_WWN_SIZE		8
typedef struct fcoeio_create_port_param {
	uchar_t		fcp_pwwn[FCOE_WWN_SIZE];
	uchar_t		fcp_nwwn[FCOE_WWN_SIZE];
	uint32_t	fcp_nwwn_provided;
	uint32_t	fcp_pwwn_provided;
	uint32_t	fcp_force_promisc;
	fcoe_cli_type_t	fcp_port_type;
	datalink_id_t	fcp_mac_linkid;
	uint32_t	fcp_rsvd0;
} fcoeio_create_port_param_t;

typedef struct fcoeio_delete_port_param {
	datalink_id_t	fdp_mac_linkid;
	uint32_t	fdp_rsvd0;
} fcoeio_delete_port_param_t;

/*
 * FCOE port instance
 */
typedef struct fcoe_port_instance {
	uchar_t			fpi_pwwn[FCOE_WWN_SIZE];
	datalink_id_t		fpi_mac_linkid;
	uint32_t		fpi_rsvd0;
	uint8_t			fpi_mac_factory_addr[ETHERADDRL];
	uint16_t		fpi_mac_promisc;
	uint8_t			fpi_mac_current_addr[ETHERADDRL];
	uint16_t		fpi_rsvd1;
	fcoe_cli_type_t		fpi_port_type;
	uint32_t		fpi_mtu_size;
} fcoe_port_instance_t;

/*
 * FCOE port instance list
 */
typedef struct fcoe_port_list {
	uint64_t		numPorts;
	fcoe_port_instance_t	ports[1];
} fcoe_port_list_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _FCOEIO_H_ */
