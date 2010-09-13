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
#ifndef	_FCOE_COMMON_H_
#define	_FCOE_COMMON_H_

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * Interface return value
 */
#define	FCOE_SUCCESS		 0
#define	FCOE_FAILURE		-1
#define	FCOE_BUSY		-2
#define	FCOE_NOT_SUPPORTED	-3
#define	FCOE_BAD_FRAME		-4

/*
 * FCOE port speed
 */
#define	FCOE_PORT_SPEED_1G	1000000000
#define	FCOE_PORT_SPEED_10G	10000000000

/*
 * FC Frame header size: 24 bytes
 */
#define	FCFH_SIZE		(sizeof (fcoe_fc_frame_header_t))

/*
 * FLOGI
 */
#define	FLOGI_REQ_PAYLOAD_SIZE	116
#define	FLOGI_ACC_PAYLOAD_SIZE	116

#define	FCOE_MIN_MTU_SIZE	2500
#define	FCOE_MAX_FC_FRAME_SIZE	2136

/*
 * 24 byte FC frame header
 * For all data structures that have endian problems, we will use only
 * one type: uint8_t. We need associate the data structure pointer with
 * one buffer directly.
 */
typedef struct fcoe_fc_frame_header {
	uint8_t hdr_r_ctl[1];
	uint8_t hdr_d_id[3];

	uint8_t hdr_cs_ctl[1];
	uint8_t hdr_s_id[3];

	uint8_t hdr_type[1];
	uint8_t hdr_f_ctl[3];

	uint8_t hdr_seq_id[1];
	uint8_t hdr_df_ctl[1];
	uint8_t hdr_seq_cnt[2];

	uint8_t hdr_oxid[2];
	uint8_t hdr_rxid[2];

	uint8_t hdr_param[4];
} fcoe_fc_frame_header_t;

/*
 * Solicited frame:   allocted by FCOET/FOCEI,  free-ed by FCOE
 * Unsolicited frame: allocated by FCOE,        free-ed by FCOET/FCOEI
 */
struct fcoe_port;
typedef struct fcoe_frame {
	uint32_t		 frm_flags;
	void			*frm_netb;

	/*
	 * frm_hdr will be cleared by fcoe explicitly
	 */
	fcoe_fc_frame_header_t	*frm_hdr;
	uint8_t			*frm_ofh1;
	uint8_t			*frm_ofh2;
	uint8_t			*frm_fc_frame;

	/*
	 * fcoe client need clear FC payload explicitly,
	 * except for RD/WR data frames
	 */
	uint8_t			*frm_payload;
	uint32_t		 frm_fc_frame_size;
	uint32_t		 frm_payload_size;
	uint32_t		 frm_alloc_size;
	struct fcoe_port	*frm_eport;
	void			*frm_fcoe_private;
	void			*frm_client_private;
	clock_t			 frm_clock;
} fcoe_frame_t;

/*
 * FCOE HBA
 */
typedef struct fcoe_port {
	uint32_t	   eport_flags;
	void		  *eport_fcoe_private;
	void		  *eport_client_private;
	uint8_t		   eport_portwwn[8];
	uint8_t		   eport_nodewwn[8];
	uint32_t	   eport_max_fc_frame_size;
	uint32_t	   eport_mtu;
	uint64_t	   eport_link_speed;
	uint8_t		   eport_efh_dst[ETHERADDRL];

	void		 (*eport_tx_frame)(fcoe_frame_t *frame);
	fcoe_frame_t	*(*eport_alloc_frame)(struct fcoe_port *eport,
	    uint32_t this_fc_frame_size, void *netb);
	void		 (*eport_release_frame)(fcoe_frame_t *frame);
	void		*(*eport_alloc_netb)(struct fcoe_port *eport,
	    uint32_t this_fc_frame_size, uint8_t **ppfc);
	void		 (*eport_free_netb)(void *netb);
	void		 (*eport_deregister_client)(struct fcoe_port *eport);
	int		 (*eport_ctl)(struct fcoe_port *eport,
	    int cmd, void *arg);
	int		 (*eport_set_mac_address)(struct fcoe_port *eport,
	    uint8_t *addr, boolean_t fc_assigned);
} fcoe_port_t;

/*
 * FCOE only supports two kinds of topology: direct P2P, fabric P2P.
 */
#define	EPORT_FLAG_IS_DIRECT_P2P	0x01
#define	EPORT_FLAG_TGT_MODE		0x02
#define	EPORT_FLAG_INI_MODE		0x04
#define	EPORT_FLAG_MAC_IN_USE		0x08

#define	FCOE_NOTIFY_EPORT_LINK_UP	0x01
#define	FCOE_NOTIFY_EPORT_LINK_DOWN	0x02
#define	FCOE_NOTIFY_EPORT_ADDR_CHG	0x03

#define	FCOE_PORT_CTL_CMDS		0x3000
#define	FCOE_CMD_PORT_ONLINE		(FCOE_PORT_CTL_CMDS | 0x01)
#define	FCOE_CMD_PORT_OFFLINE		(FCOE_PORT_CTL_CMDS | 0x02)

/*
 * FCoE version control
 */
typedef enum fcoe_ver
{
	FCOE_VER_1 = 0xAA01,
	FCOE_VER_2,
	FCOE_VER_3,
	FCOE_VER_4,
	FCOE_VER_5
} fcoe_ver_e;

#define	FCOE_VER_NOW FCOE_VER_1
extern const fcoe_ver_e fcoe_ver_now;

typedef struct fcoe_client {
	fcoe_ver_e	 ect_fcoe_ver;
	uint32_t	 ect_eport_flags;
	uint32_t	 ect_max_fc_frame_size;
	uint32_t	 ect_private_frame_struct_size;
	uint32_t	 ect_channelid;
	void		*ect_client_port_struct;
	void		 (*ect_rx_frame)(fcoe_frame_t *frame);
	void		 (*ect_port_event)(fcoe_port_t *eport, uint32_t event);
	void		 (*ect_release_sol_frame)(fcoe_frame_t *frame);
} fcoe_client_t;

/*
 * Define common-used conversion or calculation macros
 */
#define	FCOE_V2B_1(x_v, x_b)				\
	{						\
		((uint8_t *)(x_b))[0] = 0xFF & (x_v);	\
	}

#define	FCOE_V2B_2(x_v, x_b)					\
	{							\
		((uint8_t *)(x_b))[1] = 0xFF & (x_v);		\
		((uint8_t *)(x_b))[0] = 0xFF & ((x_v) >> 8);	\
	}

#define	FCOE_V2B_3(x_v, x_b)					\
	{							\
		((uint8_t *)(x_b))[2] = 0xFF & (x_v);		\
		((uint8_t *)(x_b))[1] = 0xFF & ((x_v) >> 8);	\
		((uint8_t *)(x_b))[0] = 0xFF & ((x_v) >> 16);	\
	}

#define	FCOE_V2B_4(x_v, x_b)					\
	{							\
		((uint8_t *)(x_b))[3] = 0xFF & (x_v);		\
		((uint8_t *)(x_b))[2] = 0xFF & ((x_v) >> 8);	\
		((uint8_t *)(x_b))[1] = 0xFF & ((x_v) >> 16);	\
		((uint8_t *)(x_b))[0] = 0xFF & ((x_v) >> 24);	\
	}

#define	FCOE_V2B_8(x_v, x_b)					\
	{							\
		((uint8_t *)(x_b))[7] = 0xFF & (x_v);		\
		((uint8_t *)(x_b))[6] = 0xFF & ((x_v) >> 8);	\
		((uint8_t *)(x_b))[5] = 0xFF & ((x_v) >> 16);	\
		((uint8_t *)(x_b))[4] = 0xFF & ((x_v) >> 24);	\
		((uint8_t *)(x_b))[3] = 0xFF & ((x_v) >> 32);	\
		((uint8_t *)(x_b))[2] = 0xFF & ((x_v) >> 40);	\
		((uint8_t *)(x_b))[1] = 0xFF & ((x_v) >> 48);	\
		((uint8_t *)(x_b))[0] = 0xFF & ((x_v) >> 56);	\
	}

#define	FCOE_B2V_1(x_b)				\
	((((uint8_t *)(x_b))[0]) & 0xFF)

#define	FCOE_B2V_2(x_b)						\
	((((uint8_t *)(x_b))[1] | ((uint8_t *)(x_b))[0] << 8) & 0xFFFF)

#define	FCOE_B2V_3(x_b)						\
	((((uint8_t *)(x_b))[2] | ((uint8_t *)(x_b))[1] << 8 |	\
	((uint8_t *)(x_b))[0] << 16) & 0xFFFFFF)

#define	FCOE_B2V_4(x_b)						\
	((((uint8_t *)(x_b))[3] | ((uint8_t *)(x_b))[2] << 8 |	\
	((uint8_t *)(x_b))[1] << 16 |				\
	((uint8_t *)(x_b))[0] << 24) & 0xFFFFFFFF)

#define	FCOE_B2V_8(x_b)						\
	((((uint8_t *)(x_b))[7] | ((uint8_t *)(x_b))[6] << 8 |	\
	((uint8_t *)(x_b))[5] << 16 |				\
	((uint8_t *)(x_b))[4] << 24 |				\
	((uint8_t *)(x_b))[3] << 32 |				\
	((uint8_t *)(x_b))[2] << 40 |				\
	((uint8_t *)(x_b))[1] << 48 |				\
	((uint8_t *)(x_b))[0] << 56) & 0xFFFFFFFFFFFFFFFF)

/*
 * Get FC frame header's element
 */
#define	FRM_R_CTL(x_frm)	(FCOE_B2V_1((x_frm)->frm_hdr->hdr_r_ctl))
#define	FRM_D_ID(x_frm)		(FCOE_B2V_3((x_frm)->frm_hdr->hdr_d_id))
#define	FRM_S_ID(x_frm)		(FCOE_B2V_3((x_frm)->frm_hdr->hdr_s_id))
#define	FRM_TYPE(x_frm)		(FCOE_B2V_1((x_frm)->frm_hdr->hdr_type))
#define	FRM_F_CTL(x_frm)	(FCOE_B2V_3((x_frm)->frm_hdr->hdr_f_ctl))
#define	FRM_SEQ_ID(x_frm)	(FCOE_B2V_1((x_frm)->frm_hdr->hdr_seq_id))
#define	FRM_DF_CTL(x_frm)	(FCOE_B2V_1((x_frm)->frm_hdr->hdr_df_ctl))
#define	FRM_SEQ_CNT(x_frm)	(FCOE_B2V_2((x_frm)->frm_hdr->hdr_seq_cnt))
#define	FRM_OXID(x_frm)		(FCOE_B2V_2((x_frm)->frm_hdr->hdr_oxid))
#define	FRM_RXID(x_frm)		(FCOE_B2V_2((x_frm)->frm_hdr->hdr_rxid))
#define	FRM_PARAM(x_frm)	(FCOE_B2V_4((x_frm)->frm_hdr->hdr_param))

/*
 * Set FC frame header's element
 */
#define	FFM_R_CTL(x_v, x_frm)	FCOE_V2B_1((x_v), (x_frm)->frm_hdr->hdr_r_ctl)
#define	FFM_D_ID(x_v, x_frm)	FCOE_V2B_3((x_v), (x_frm)->frm_hdr->hdr_d_id)
#define	FFM_S_ID(x_v, x_frm)	FCOE_V2B_3((x_v), (x_frm)->frm_hdr->hdr_s_id)
#define	FFM_TYPE(x_v, x_frm)	FCOE_V2B_1((x_v), (x_frm)->frm_hdr->hdr_type)
#define	FFM_F_CTL(x_v, x_frm)	FCOE_V2B_3((x_v), (x_frm)->frm_hdr->hdr_f_ctl)
#define	FFM_SEQ_ID(x_v, x_frm)	FCOE_V2B_1((x_v), (x_frm)->frm_hdr->hdr_seq_id)
#define	FFM_DF_CTL(x_v, x_frm)	FCOE_V2B_1((x_v), (x_frm)->frm_hdr->hdr_df_ctl)
#define	FFM_SEQ_CNT(x_v, x_frm)	FCOE_V2B_2((x_v), (x_frm)->frm_hdr->hdr_seq_cnt)
#define	FFM_OXID(x_v, x_frm)	FCOE_V2B_2((x_v), (x_frm)->frm_hdr->hdr_oxid)
#define	FFM_RXID(x_v, x_frm)	FCOE_V2B_2((x_v), (x_frm)->frm_hdr->hdr_rxid)
#define	FFM_PARAM(x_v, x_frm)	FCOE_V2B_4((x_v), (x_frm)->frm_hdr->hdr_param)

/*
 * frame header checking
 */
#define	FRM_IS_LAST_FRAME(x_frm)		(FRM_F_CTL(x_frm) & (1 << 19))
#define	FRM_SENDER_IS_XCH_RESPONDER(x_frm)	(FRM_F_CTL(x_frm) & (1 << 23))

/*
 * FCOET/FCOEI will only call this fcoe function explicitly, all others
 * should be called through vectors in struct fcoe_port.
 * FCOE client call this to register one port to FCOE, FCOE need initialize
 * and return the corresponding fcoe_port.
 */
extern fcoe_port_t *fcoe_register_client(fcoe_client_t *client);

#define	EPORT_CLT_TYPE(eport)				\
	(((eport)->eport_flags & EPORT_FLAG_INI_MODE) ? \
	FCOE_CLIENT_INITIATOR : FCOE_CLIENT_TARGET)

#define	FCOE_SET_DEFAULT_OUI(x_oui)	\
	(x_oui)[0] = 0x0e; (x_oui)[1] = 0xfc; (x_oui)[2] = 0x00;
#define	FCOE_SET_DEFAULT_FPORT_ADDR(x_addr)	\
	FCOE_SET_DEFAULT_OUI(x_addr)		\
	(x_addr)[3] = 0xff; (x_addr)[4] = 0xff; (x_addr)[5] = 0xfe;

/*
 * FC payload size
 */
#define	FCOE_DEFAULT_FCP_DATA_PAYLOAD_SIZE	2048
#define	FCOE_MIN_FCP_DATA_PAYLOAD_SIZE		1024

typedef struct fcoe_fcp_cmnd {
	uint8_t ffc_lun[8];
	uint8_t ffc_ref_num[1];

	/*
	 * least 3 bits
	 */
	uint8_t ffc_attribute[1];

	/*
	 * Magnagement flags
	 */
	uint8_t ffc_management_flags[1];

	/*
	 * additional cdb len and read/write flag
	 */
	uint8_t ffc_addlen_rdwr[1];

	uint8_t ffc_cdb[16];
	uint8_t ffc_fcp_dl[4];
} fcoe_fcp_cmnd_t;

typedef struct fcoe_fcp_rsp {
	uint8_t ffr_rsvd[8];

	/*
	 * see SAM-4
	 */
	uint8_t ffr_retry_delay_timer[2];
	uint8_t ffr_flags[1];
	uint8_t ffr_scsi_status[1];
	uint8_t ffr_resid[4];
	uint8_t ffr_sns_len[4];
	uint8_t ffr_rsp_len[4];
	/*
	 * Followed by sense data when available
	 */
} fcoe_fcp_rsp_t;

typedef struct fcoe_fcp_xfer_rdy {
	uint8_t fxr_data_ro[4];
	uint8_t fxr_burst_len[4];
	uint8_t fxr_rsvd[4];
} fcoe_fcp_xfer_rdy_t;

/*
 * FCOE project global functions
 */
#if !defined(__FUNCTION__)
#define	__FUNCTION__ ((caddr_t)__func__)
#endif

#define	FCOE_STR_LEN 32

/*
 * timestamp (golbal variable in sys/systm.h)
 */
#define	CURRENT_CLOCK		(ddi_get_lbolt())
#define	FCOE_SEC2TICK(x_sec)	(drv_usectohz((x_sec) * 1000000))

/*
 * Form/convert mod_hash_key from/to xch ID
 */
#define	FMHK(x_xid)		(mod_hash_key_t)(uintptr_t)(x_xid)
#define	CMHK(x_key)		(uint16_t)(uintptr_t)(x_key)

typedef void (*TQ_FUNC_P)(void *);
extern void fcoe_trace(caddr_t ident, const char *fmt, ...);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _FCOE_COMMON_H_ */
