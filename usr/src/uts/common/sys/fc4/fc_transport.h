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

#ifndef	_SYS_FC4_FC_TRANSPORT_H
#define	_SYS_FC4_FC_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fc4/fc.h>

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
 * This data structure is used by a Fiber Channel Adaptor driver client to
 * request a Fiber Channel transaction.
 */

typedef struct fc_packet {
			/*
			 * identifies which FC device
			 *
			 * In our case it is a pointer to the
			 * port_status structure. This structure
			 * contains the physical port (0 or 1).
			 */
	void		*fc_pkt_cookie;	/* identifies which FC device */

	void		(*fc_pkt_comp)(struct fc_packet *);
	void		*fc_pkt_private;
	int32_t		fc_pkt_flags;		/* flags */
	int32_t		fc_pkt_timeout;		/* Max time to complete */
	fc_ioclass_t	fc_pkt_io_class;	/* fc io class */
	fc_devdata_t	fc_pkt_io_devdata;	/* FC IO Device Data. */
	fc_dataseg_t	*fc_pkt_cmd;		/* Outbound packet */
	fc_dataseg_t	*fc_pkt_rsp;		/* Inbound  Packet */
	fc_dataseg_t	**fc_pkt_datap;		/* List of Data Packets */

	/*
	 * SOC status from soc status field in Response que.
	 */
	unsigned int	fc_pkt_status;		/* SOC Status when complete */
	int		fc_pkt_statistics;	/* not used */

	fc_frame_header_t	*fc_frame_cmd,	/* used for command */
				*fc_frame_resp;	/* used for response */

	struct fc_packet	*fc_pkt_next,	/* Chain of FC packet reqs. */
				*fc_pkt_prev;
} fc_packet_t;

/*
 *	Fibre channel packet flags
 */
#define	FCFLAG_NOINTR		1	/* run this command without intr */
#define	FCFLAG_COMPLETE		2	/* command has completed */

/*
 * fc_transport() return values
 */
enum {
	FC_TRANSPORT_SUCCESS,		/* success */
	FC_TRANSPORT_FAILURE,		/* failure */
	FC_TRANSPORT_TIMEOUT,		/* timeout while polling */
	FC_TRANSPORT_QFULL,		/* queue full */
	FC_TRANSPORT_UNAVAIL		/* temp. unavailable, e.g., offline */
};


/*
 * pkt_status return values
 */
#define	FC_STATUS_OK			0
#define	FC_STATUS_P_RJT			2
#define	FC_STATUS_F_RJT			3
#define	FC_STATUS_P_BSY			4
#define	FC_STATUS_F_BSY			5
#define	FC_STATUS_ERR_OFFLINE		0x11
#define	FC_STATUS_TIMEOUT		0x12
#define	FC_STATUS_ERR_OVERRUN		0x13
#define	FC_STATUS_UNKNOWN_CQ_TYPE	0x20
#define	FC_STATUS_BAD_SEG_CNT		0x21
#define	FC_STATUS_MAX_XCHG_EXCEEDED	0x22
#define	FC_STATUS_BAD_XID		0x23
#define	FC_STATUS_XCHG_BUSY		0x24
#define	FC_STATUS_BAD_POOL_ID		0x25
#define	FC_STATUS_INSUFFICIENT_CQES	0x26
#define	FC_STATUS_ALLOC_FAIL		0x27
#define	FC_STATUS_BAD_SID		0x28
#define	FC_STATUS_NO_SEQ_INIT		0x29
#define	FC_STATUS_ERROR			0x80
#define	FC_STATUS_ONLINE_TIMEOUT	0x81
/*
 * additional pseudo-status codes for login
 */
#define	FC_STATUS_LOGIN_TIMEOUT		0x80000001u
#define	FC_STATUS_CQFULL		0x80000002u
#define	FC_STATUS_TRANSFAIL		0x80000003u
#define	FC_STATUS_RESETFAIL		0x80000004u

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
 * fc_transport() sleep parameter
 */
typedef enum {
	FC_SLEEP,			/* sleep on queue full */
	FC_NOSLEEP			/* do not sleep on queue full */
} fc_sleep_t;


/*
 * State changes related to the N-port interface communicated from below
 */
typedef enum {
	FC_STATE_ONLINE,		/* port has gone online */
	FC_STATE_OFFLINE,		/* port has gone offline */
	FC_STATE_RESET			/* port reset, all cmds lost */
} fc_statec_t;

typedef void * fc_statec_cookie_t;

/*
 * This structure is allocated by Fiber Channel Adaptor at INITCHILD time,
 * and is  communicated to the child by ddi_set_driver_private().
 * It defines the vectors by which the child obtains soc
 * driver services, and all other information the child
 * may need about its parent.
 */

typedef struct fc_transport {
	void			*fc_cookie;	/* Which FC dev. */
	ddi_dma_lim_t		*fc_dmalimp;	/* FC ddi_dma_lim_t ptr. */
	ddi_dma_attr_t		*fc_dma_attrp;	/* FC ddi_dma_attr_t ptr. */
	ddi_iblock_cookie_t	fc_iblock;	/* iblock for mutexes */
	kmutex_t		fc_mtx;		/* Locks for transport */
	kcondvar_t		fc_cv;

	/*
	 * Transport a command across the interface.
	 */
	int		(*fc_transport)(
				struct fc_packet	*fc,
				fc_sleep_t		sleep);

	/*
	 * Reset the transport.
	 */
	int		(*fc_reset)(
				struct fc_packet	*fc);

	/*
	 * Allocate an fc_packet structure.
	 */
	fc_packet_t	*(*fc_pkt_alloc)(
				void			*cookie,
				fc_sleep_t		sleep);

	/*
	 * Free an fc_packet structure.
	 */
	void		(*fc_pkt_free)(
				void			*cookie,
				struct fc_packet	*pkt);

	/*
	 * Register a routine to handle state changes on the interface
	 *
	 * The arg parameter, along with an fc_statec_t parameter, will
	 * be passed to the callback routine on all state changes
	 * after initialization.
	 */
	fc_statec_cookie_t
			(*fc_statec_register)(
			void	*cookie,
			void	(*callback)(void *, fc_statec_t),
			void	*arg);

	/*
	 * Unregister a routine to handle state changes
	 */
	void	(*fc_statec_unregister)(
			void	*cookie,
			fc_statec_cookie_t statec_cookie);

	/*
	 * Run the interface in polling mode.  This allows interface
	 * state changes, etc. to be processed when system interrupts
	 * are disabled.  This is used mostly for error recovery.
	 * Too bad Fibre Channel doesn't have a common error policy for
	 * all protocols so that we could do error recovery at
	 * the lowest level instead of having kludges like this...
	 */
	void	(*fc_interface_poll)(
			void	*cookie);

	/*
	 * Unsolicited Command Interface
	 *
	 * This interface operates with the presumption that the
	 * higher level driver (child) will process unsolicited
	 * commands that pertain to its protocol such as FCP or FCIP.
	 */

	/*
	 * Register a callback to be called in the event of an
	 * unsolicited command received by the soc for this child.
	 * No information is passed regarding the event, just that
	 * one occurred.  The arg parameter to passed to the
	 * callback function as its parameter.
	 */
	fc_uc_cookie_t
			(*fc_uc_register)(
			void			*cookie,
			fc_devdata_t		devdata,
			void			(*callback)(void *),
			void			*arg);

	/*
	 * Unregister a callback routine
	 */
	void	(*fc_uc_unregister)(
			void			*cookie,
			fc_uc_cookie_t		uc_cookie);

	/*
	 * Return information about the unsolicited command
	 * event in pkt.  The pkt must be a fully allocated
	 * fc_packet structure, with a valid cmd dataseg
	 * pointer, in which the received cmd payload will
	 * be placed.  The length of the allocated dataseg should
	 * be greater than or equal to the length of the received
	 * command payload, otherwise the entire command cannot
	 * be copied into the data segment.  This function
	 * returns -1 in the event of an error, or the
	 * actual length of the received command payload.
	 */
	int	(*fc_uc_get_pkt)(
			void			*cookie,
			struct fc_packet	*pkt);

} fc_transport_t;


#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FC4_FC_TRANSPORT_H */
