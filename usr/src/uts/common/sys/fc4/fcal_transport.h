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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FC4_FCAL_TRANSPORT_H
#define	_SYS_FC4_FCAL_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fc4/fcal.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * fc_devdata_t definitions
 *
 * See fc.h for TYPE field definitions
 */
typedef int fc_devdata_t;

/*
 * fc_ioclass_t definitions.
 */
typedef enum {
	FC_CLASS_OUTBOUND,
	FC_CLASS_INBOUND,
	FC_CLASS_SIMPLE,
	FC_CLASS_IO_WRITE,
	FC_CLASS_IO_READ,
	FC_CLASS_OFFLINE,
	FC_CLASS_UNSOLICITED
} fc_ioclass_t;

/*
 * fc_transport() sleep parameter
 */
typedef enum {
	FCAL_SLEEP,			/* sleep on queue full */
	FCAL_NOSLEEP			/* do not sleep on queue full */
} fcal_sleep_t;

typedef struct fcal_packet {
	void		*fcal_pkt_cookie; /* identifies which FC device */
	struct fcal_packet	*fcal_pkt_next;
	void		(*fcal_pkt_comp)(struct fcal_packet *);
	void		*fcal_pkt_private;
	uint_t		fcal_pkt_flags;		/* flags */
	uint_t		fcal_cmd_state;
	uint_t		fcal_pkt_status;	/* SOC Status when complete */
	uint_t		fcal_diag_status;	/* used only for diagnostics */
	union {
		soc_request_t	req;
		longlong_t	l;
	} w;

#define	fcal_socal_request	w.req

	fc_frame_header_t	fcal_resp_hdr;
	uint_t		fcal_magic;
	ushort_t	fcal_ncmds;
} fcal_packet_t;

/*
 *	Fibre channel packet flags
 */
#define	FCFLAG_NOINTR		1	/* run this command without intr */
#define	FCFLAG_COMPLETE		2	/* command has completed */
#define	FCFLAG_RESP_HEADER	4	/* valid response frame header */
#define	FCFLAG_ABORTING		8	/* this packet is being aborted */
#define	FCFLAG_ABORTED		0x10	/* the abort completed */

/*
 * definitions for the cmd_state
 */
#define	FCAL_CMD_IN_TRANSPORT	0x1	/* command in transport */
#define	FCAL_CMD_COMPLETE	0x4	/* command complete */
#define	FCAL_CMPLT_CALLED	0x10	/* Completion routine called */

#define	FCALP_MAGIC	0x4750703

typedef struct fcal_transport {
	void			*fcal_handle; 	/* identifies which FC dev */
	ddi_dma_lim_t		*fcal_dmalimp;
	ddi_iblock_cookie_t	fcal_iblock;
	ddi_dma_attr_t		*fcal_dmaattr;
	ddi_device_acc_attr_t	*fcal_accattr;
	caddr_t			fcal_loginparms;	/* from soc+ xram */
	la_wwn_t		fcal_n_wwn;	/* node Worldwide name */
	la_wwn_t		fcal_p_wwn;	/* port Worldwide name */
	uint_t			fcal_portno;	/* which port */
	uint_t			fcal_cmdmax;	/* max number of exchanges */
	kmutex_t		fcal_mtx;
	kcondvar_t		fcal_cv;
	struct fcal_transport_ops	*fcal_ops;
} fcal_transport_t;

typedef struct fcal_transport_ops {
	uint_t			(*fcal_transport)(fcal_packet_t *fcalpkt,
						fcal_sleep_t sleep, int
						req_q_no);
	uint_t			(*fcal_transport_poll)(fcal_packet_t *fcalpkt,
						uint_t	 timeout,
						int req_q_no);
	uint_t			(*fcal_lilp_map)(void *fcal_handle,
						uint_t	 port,
						uint32_t bufid,
						uint_t	 poll);
	uint_t			(*fcal_force_lip)(void *fcal_handle,
						uint_t	 port,
						uint_t	 poll,
						uint_t	 lip_req);
	uint_t			(*fcal_abort_cmd)(void *fcal_handle,
						uint_t	port,
						fcal_packet_t *fcalpkt,
						uint_t	 poll);
	uint_t			(*fcal_els)(void *fcal_handle,
						uint_t	 port,
						uint_t	 els_code,
						uint_t	 dest,
						void (*callback)(),
						void *arg,
						caddr_t reqpayload,
						caddr_t *rsppayload,
						uint_t	 poll);
	uint_t			(*fcal_bypass_dev)(void *fcal_handle,
						uint_t	 port,
						uint_t	 dest);
	void			(*fcal_force_reset)(void *fcal_handle,
						uint_t	 port,
						uint_t	reset);
	void			(*fcal_add_ulp)(void *fcal_handle,
						uint_t	 port,
						uchar_t type,
						void (*ulp_statec_callback)(),
						void (*ulp_els_callback)(),
						void (*ulp_data_callback)(),
						void *arg);
	void			(*fcal_remove_ulp)(void *fcal_handle,
						uint_t port,
						uchar_t type,
						void *arg);
	void			(*fcal_take_core)(void *fcal_handle);
} fcal_transport_ops_t;

/*
 * additional pseudo-status codes for login
 */
#define	FCAL_STATUS_LOGIN_TIMEOUT	0x80000001
#define	FCAL_STATUS_CQFULL		0x80000002
#define	FCAL_STATUS_TRANSFAIL		0x80000003
#define	FCAL_STATUS_RESETFAIL		0x80000004

/*
 * interface and transport function return values
 */
#define	FCAL_SUCCESS		0x000
#define	FCAL_TIMEOUT		0x001
#define	FCAL_ALLOC_FAILED	0x002
#define	FCAL_OLD_PORT		0x003
#define	FCAL_LINK_ERROR		0x004
#define	FCAL_OFFLINE		0x005
#define	FCAL_ABORTED		0x006
#define	FCAL_ABORT_FAILED	0x007
#define	FCAL_BAD_ABORT		0x008
#define	FCAL_BAD_PARAMS		0x009
#define	FCAL_OVERRUN		0x00a
#define	FCAL_NO_TRANSPORT	0x00b
#define	FCAL_TRANSPORT_SUCCESS	0x000
#define	FCAL_TRANSPORT_FAILURE	0x101
#define	FCAL_BAD_PACKET		0x102
#define	FCAL_TRANSPORT_UNAVAIL	0x103
#define	FCAL_TRANSPORT_QFULL	0x104
#define	FCAL_TRANSPORT_TIMEOUT	0x105

#define	FCAL_FAILURE 		0xffffffff
/*
 * fc_uc_register() return values
 */
typedef void * fc_uc_cookie_t;

/*
 * fc_transport() iotype parameter
 */
typedef enum {
	FC_TYPE_UNCATEGORIZED,
	FC_TYPE_DATA,
	FC_TYPE_UNSOL_CONTROL,
	FC_TYPE_SOLICITED_CONTROL,
	FC_TYPE_UNSOL_DATA,
	FC_TYPE_XFER_RDY,
	FC_TYPE_COMMAND,
	FC_TYPE_RESPONSE
} fc_iotype_t;

/*
 * State changes related to the N-port interface communicated from below
 */
#define	FCAL_STATE_RESET	((int)0xffffffffu)
						/* port reset, all cmds lost */

#define	FCAL_LILP_MAGIC		0x1107
#define	FCAL_BADLILP_MAGIC	0x1105
#define	FCAL_NO_LIP		0x0
#define	FCAL_FORCE_LIP		0x1

typedef struct fcal_lilp_map {
	ushort_t	lilp_magic;
	ushort_t	lilp_myalpa;
	uchar_t		lilp_length;
	uchar_t		lilp_alpalist[127];
} fcal_lilp_map_t;
#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FC4_FCAL_TRANSPORT_H */
