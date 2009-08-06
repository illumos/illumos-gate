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

#ifndef	_FCTL_H
#define	_FCTL_H


#include <sys/note.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These are the legal values for the fp_state member of the fc_local_port_t
 * struct. These values are understood by ULPs, FCA drivers, and fp/fctl.
 *
 * The link state value is kept the least significant byte, and the link speed
 * value is kept in the next most significant byte:
 *
 *  +------------+------------+
 *  | link speed | link state |
 *  +------------+------------+
 */
/* Values for the link state (least significant byte as above) */
#define	FC_STATE_OFFLINE		0x0000	/* Link is offline or not */
						/* initialized. */
#define	FC_STATE_ONLINE			0x0001	/* Link is up, the topology */
						/* is given in fp_topology. */
#define	FC_STATE_LOOP			0x0002	/* Link is up, the topology */
						/* is a private loop. */
#define	FC_STATE_NAMESERVICE		0x0003	/* Not really used */
#define	FC_STATE_RESET			0x0004
#define	FC_STATE_RESET_REQUESTED	0x0005
#define	FC_STATE_LIP			0x0006
#define	FC_STATE_LIP_LBIT_SET		0x0007
#define	FC_STATE_DEVICE_CHANGE		0x0008	/* For ULPs */
#define	FC_STATE_TARGET_PORT_RESET	0x0009

/* Values for the link speed (next least significant byte as above) */
#define	FC_STATE_1GBIT_SPEED		0x0100	/* 1 Gbit/sec */
#define	FC_STATE_2GBIT_SPEED		0x0400	/* 2 Gbit/sec */
#define	FC_STATE_4GBIT_SPEED		0x0500	/* 4 Gbit/sec */
#define	FC_STATE_10GBIT_SPEED		0x0600	/* 10 Gbit/sec */
#define	FC_STATE_8GBIT_SPEED		0x0700	/* 8 Gbit/sec */
#define	FC_STATE_16GBIT_SPEED		0x0800	/* 16 Gbit/sec */
#define	FC_STATE_FULL_SPEED		FC_STATE_1GBIT_SPEED
#define	FC_STATE_DOUBLE_SPEED		FC_STATE_2GBIT_SPEED

/* pi_port_state, used only when binding port */
#define	FC_STATE_FCA_IS_NODMA		0x80000000

/*
 * Macros to discriminate between the link state byte and the link speed
 * byte in fp_state (also good for improved code obfuscation and job security
 * even during a good economy).
 */
#define	FC_PORT_SPEED_MASK(state)	((state) & 0xFF00)
#define	FC_PORT_STATE_MASK(state)	((state) & 0xFF)


/*
 * Notify flags passed between ULPs and FCAs
 *
 *	3 bytes			1 byte
 *  +-----------------------+---------------+
 *  | Flag specific values  |  Notify flag  |
 *  +-----------------------+---------------+
 */
#define	FC_NOTIFY_RECOVERY_DONE		0x01
#define	FC_NOTIFY_TARGET_MODE		0x02
#define	FC_NOTIFY_NO_TARGET_MODE	0x03
#define	FC_NOTIFY_RECOVERY_CLEANUP	0x04
#define	FC_NOTIFY_THROTTLE		0x80

#define	FC_NOTIFY_FLAG_MASK(cmd)	((cmd) & 0xFF)
#define	FC_NOTIFY_VALUE_MASK(cmd)	((cmd) & 0xFFFFFF00)
#define	FC_NOTIFY_GET_FLAG(cmd)		FC_NOTIFY_FLAG_MASK(cmd)
#define	FC_NOTIFY_GET_VALUE(cmd)	(FC_NOTIFY_VALUE_MASK(cmd) >> 8)

/*
 * pkt_tran_flags definitions
 */
#define	FC_TRAN_CLASS(flag)		((flag) & 0xF0)
#define	FC_TRAN_INTR			0x01
#define	FC_TRAN_NO_INTR			0x02
#define	FC_TRAN_HI_PRIORITY		0x04
#define	FC_TRAN_DUMPING			0x08
#define	FC_TRAN_CLASS1			0x10
#define	FC_TRAN_CLASS2			0x20
#define	FC_TRAN_CLASS3			0x30
#define	FC_TRAN_CLASS_INVALID		0xF0
#define	FC_TRAN_IMMEDIATE_CB		0x100


/*
 * pkt_tran_type definitions
 */
#define	FC_PKT_NOP			0
#define	FC_PKT_INBOUND			1
#define	FC_PKT_OUTBOUND			2
#define	FC_PKT_EXCHANGE			3
#define	FC_PKT_FCP_READ			4
#define	FC_PKT_FCP_WRITE		5
#define	FC_PKT_IP_WRITE			6
#define	FC_PKT_BROADCAST		7


#define	FC_TRACE_LOG_MASK		0xF00000
#define	FC_TRACE_LOG_MSG		0x100000
#define	FC_TRACE_LOG_CONSOLE		0x200000
#define	FC_TRACE_LOG_CONSOLE_MSG	0x400000
#define	FC_TRACE_LOG_BUF		0x080000


/*
 * The fc_packet_t represents an FC Exchange and is the primary unit of
 * information exchange between FC driver modules.
 */
typedef struct fc_packet {
	uint16_t		pkt_tran_flags;		/* transport flag */
	uint16_t		pkt_tran_type;		/* transport type */
	uint32_t		pkt_timeout;		/* time-out length */
	uint32_t		pkt_cmdlen;		/* command length */
	uint32_t		pkt_rsplen;		/* response length */
	uint32_t		pkt_datalen;		/* data length */
	caddr_t			pkt_cmd;		/* command */
	caddr_t			pkt_resp;		/* response */
	caddr_t			pkt_data;		/* data */
	struct buf		*pkt_data_buf;		/* reserved */
	void			(*pkt_ulp_comp)(struct fc_packet *);
							/* framework private */
	opaque_t		pkt_ulp_private;	/* caller's private */
	void			(*pkt_comp)(struct fc_packet *); /* callback */
	struct fc_remote_port	*pkt_pd;		/* port device */
	ddi_dma_handle_t	pkt_cmd_dma;		/* command DMA */
	ddi_acc_handle_t	pkt_cmd_acc;		/* command access */
	ddi_dma_cookie_t	*pkt_cmd_cookie;	/* command cookie */
	ddi_dma_handle_t	pkt_resp_dma;		/* response DMA */
	ddi_acc_handle_t	pkt_resp_acc;		/* response access */
	ddi_dma_cookie_t	*pkt_resp_cookie;	/* response cookie */
	ddi_dma_handle_t	pkt_data_dma;		/* data DMA */
	ddi_acc_handle_t	pkt_data_acc;		/* data access */
	ddi_dma_cookie_t	*pkt_data_cookie;	/* data cookie */
	uint_t			pkt_cmd_cookie_cnt;
	uint_t			pkt_resp_cookie_cnt;
	uint_t			pkt_data_cookie_cnt;	/* of a window */
	fc_frame_hdr_t		pkt_cmd_fhdr;		/* command frame hdr */
	opaque_t		pkt_fca_private;	/* FCA private */
	uchar_t			pkt_state;		/* packet state */
	uchar_t			pkt_action;		/* packet action */
	uchar_t			pkt_expln;		/* reason explanation */
	uint32_t		pkt_reason;		/* expln of state */
	uint64_t		pkt_ena;		/* ENA in case of err */
	fc_frame_hdr_t		pkt_resp_fhdr;		/* response frame hdr */
	uint32_t		pkt_data_resid;		/* data resid length */
	uint32_t		pkt_resp_resid;		/* resp resid length */
	opaque_t		pkt_fca_device;		/* FCA device ptr */
	opaque_t		pkt_ub_resp_token;	/* UB resp token */
	opaque_t		pkt_session;		/* reserved */
	opaque_t		pkt_security1;		/* reserved */
	opaque_t		pkt_security2;		/* reserved */
	opaque_t		pkt_qos1;		/* reserved */
	opaque_t		pkt_qos2;		/* reserved */
	opaque_t		pkt_ulp_rsvd1;		/* ULP reserved */

	/*
	 * The pkt_ulp_rscn_infop (aka pkt_ulp_rsvd1) field is used to carry
	 * the rscn info (of type fc_ulp_rscn_info_t) down to the transport so
	 * that the transport can determine (in some cases) whether or not the
	 * requested operation was aware of the latest state change
	 * notification.
	 *
	 * If not NULL, then the pkt_ulp_rscn_infop (aka pkt_ulp_rsvd1) may
	 * point to an fc_ulp_rscn_info_t struct that contains the rscn count
	 * information for this fc_packet_t.
	 */
#define	pkt_ulp_rscn_infop	pkt_ulp_rsvd1		/* tracks rscn counts */

	opaque_t		pkt_ulp_rsvd2;		/* ULP reserved */
	opaque_t		pkt_fctl_rsvd1;		/* Transport reserved */
	opaque_t		pkt_fctl_rsvd2;		/* Transport reserved */
	opaque_t		pkt_fca_rsvd1;		/* FCA reserved */
	opaque_t		pkt_fca_rsvd2;		/* FCA reserved */
	uint64_t		pkt_rsvd;		/* should be last */
} fc_packet_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("not messed with after transport", fc_packet))
#endif	/* __lint */


typedef struct fca_hba_fru_details {
	uint32_t    port_index;
	uint64_t    high;
	uint64_t    low;
} fca_hba_fru_details_t;

/*
 * HBA/Port attributes tracked for the T11 FC-HBA specification
 */
#define	FC_HBA_PORTSPEED_UNKNOWN	0    /* Unknown - transceiver incable */
					    /* of reporting */
#define	FC_HBA_PORTSPEED_1GBIT		1    /* 1 GBit/sec */
#define	FC_HBA_PORTSPEED_2GBIT		2    /* 2 GBit/sec */
#define	FC_HBA_PORTSPEED_10GBIT		4    /* 10 GBit/sec */
#define	FC_HBA_PORTSPEED_4GBIT		8    /* 4 GBit/sec */
#define	FC_HBA_PORTSPEED_8GBIT		16   /* 8 GBit/sec */
#define	FC_HBA_PORTSPEED_16GBIT		32   /* 16 GBit/sec */
#define	FC_HBA_PORTSPEED_NOT_NEGOTIATED	(1<<15)	  /* Speed not established */

#define	FCHBA_MANUFACTURER_LEN		64
#define	FCHBA_SERIAL_NUMBER_LEN		64
#define	FCHBA_MODEL_LEN			256
#define	FCHBA_MODEL_DESCRIPTION_LEN	256
#define	FCHBA_HARDWARE_VERSION_LEN	256
#define	FCHBA_DRIVER_VERSION_LEN	256
#define	FCHBA_OPTION_ROM_VERSION_LEN	256
#define	FCHBA_FIRMWARE_VERSION_LEN	256
#define	FCHBA_DRIVER_NAME_LEN		256
#define	FCHBA_SYMB_NAME_LEN		255

typedef struct fca_port_attrs {
	char		manufacturer[FCHBA_MANUFACTURER_LEN];
	char		serial_number[FCHBA_SERIAL_NUMBER_LEN];
	char		model[FCHBA_MODEL_LEN];
	char		model_description[FCHBA_MODEL_DESCRIPTION_LEN];
	char		hardware_version[FCHBA_HARDWARE_VERSION_LEN];
	char		driver_version[FCHBA_DRIVER_VERSION_LEN];
	char		option_rom_version[FCHBA_OPTION_ROM_VERSION_LEN];
	char		firmware_version[FCHBA_FIRMWARE_VERSION_LEN];
	char		driver_name[FCHBA_DRIVER_NAME_LEN];
	uint32_t	vendor_specific_id;
	uint32_t	supported_cos;
	uint32_t	supported_speed;
	uint32_t	max_frame_size;
	fca_hba_fru_details_t	hba_fru_details;
	uchar_t		sym_node_name[FCHBA_SYMB_NAME_LEN];
	uchar_t		sym_port_name[FCHBA_SYMB_NAME_LEN];
} fca_port_attrs_t;



typedef struct unsolicited_buffer {
	uchar_t		ub_class;
	uchar_t		ub_resvd1;
	ushort_t	ub_resp_flags;		/* ULP-specific flags */
	ushort_t	ub_resp_key;		/* ULP-specific key */
	ushort_t	ub_resvd2;
	uint32_t	ub_bufsize;
	caddr_t		ub_buffer;
	void		*ub_port_private;
	void		*ub_fca_private;
	opaque_t	ub_port_handle;
	opaque_t	ub_resp_token;		/* Response token */
	uint64_t	ub_token;
	fc_frame_hdr_t	ub_frame;
} fc_unsol_buf_t;

#define	FC_UB_RESP_LOGIN_REQUIRED	0x4000

typedef struct fc_trace_dmsg {
	int			id_size;	/* message size */
	int			id_flag;	/* for future */
	timespec_t		id_time;	/* timestamp */
	caddr_t			id_buf;		/* message buffer */
	struct fc_trace_dmsg	*id_next;	/* next message in queue */
} fc_trace_dmsg_t;

#define	FC_TRACE_LOGQ_V2		0x1

typedef struct fc_trace_logq {
	kmutex_t	il_lock;	/* lock to avoid clutter */
	int		il_hiwat;	/* maximum queue size */
	int		il_flags;
	int		il_size;	/* current size */
	int		il_afail;	/* count of allocation failures */
	int		il_lfail;	/* general logging failures */
	int		il_id;		/* message Id */
	fc_trace_dmsg_t	*il_msgh;	/* messages head */
	fc_trace_dmsg_t	*il_msgt;	/* messages tail */
} fc_trace_logq_t;


/*
 * Values for the pd_type field in the fc_remote_port_t struct below.
 * (Also used in map_type and changelist determination)
 */
#define	PORT_DEVICE_NOCHANGE		0x0 /* Event occurred on link, but */
					    /* no change on the remote port */
#define	PORT_DEVICE_NEW			0x1 /* Newly created remote port, or */
					    /* port has come back after being */
					    /* marked as PORT_DEVICE_OLD */
#define	PORT_DEVICE_OLD			0x2 /* RSCN or Reset has occurred, */
					    /* the remote port may come back */
#define	PORT_DEVICE_CHANGED		0x3 /* D_ID, PWWN, or other change */
					    /* has occurred (hot swap?) */
#define	PORT_DEVICE_DELETE		0x4 /* Not used? */
#define	PORT_DEVICE_USER_LOGIN		0x5 /* only for changelist->map_type */
#define	PORT_DEVICE_USER_LOGOUT		0x6 /* only for changelist->map_type */
#define	PORT_DEVICE_USER_CREATE		0x7 /* only for changelist->map_type */
#define	PORT_DEVICE_USER_DELETE		0x8 /* only for changelist->map_type */
#define	PORT_DEVICE_REPORTLUN_CHANGED	0x9 /* only for changelist->map_type */

/*
 * Flags used for fc_portmap->map_type
 */

#define	PORT_DEVICE_DUPLICATE_MAP_ENTRY 0x00000001 /* map entry has another */
						/* entry for this target */
						/* later in the list */
#define	PORT_DEVICE_NO_SKIP_DEVICE_DISCOVERY	0x00000002


/*
 * Logging and Debugging support
 */
void fc_trace_debug(fc_trace_logq_t *logq, caddr_t name, int dflag, int dlevel,
    int errno, const char *fmt, ...);

fc_trace_logq_t *fc_trace_alloc_logq(int maxsize);
void fc_trace_free_logq(fc_trace_logq_t *logq);
void fc_trace_logmsg(fc_trace_logq_t *logq, caddr_t buf, int level);
caddr_t fc_trace_msg(int fc_trace_error);

/*
 * Common utility routines
 */

void fc_wwn_to_str(la_wwn_t *wwn, caddr_t string);
void fc_str_to_wwn(caddr_t string, la_wwn_t *wwn);

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per request", unsolicited_buffer))
#endif	/* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _FCTL_H */
