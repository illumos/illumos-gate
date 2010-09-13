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

#ifndef	_FC_FCAIF_H
#define	_FC_FCAIF_H


#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Version for FCA vectors
 */
#define	FCTL_FCA_MODREV_1	1
#define	FCTL_FCA_MODREV_2	2
#define	FCTL_FCA_MODREV_3	3
#define	FCTL_FCA_MODREV_4	4
#define	FCTL_FCA_MODREV_5	5

/*
 * State change codes
 */
#define	FC_SC_OFFLINE		0
#define	FC_SC_ONLINE		1

/*
 * pm_cmd_flag definitions
 */
#define	FC_FCA_PM_NOP		0x00
#define	FC_FCA_PM_READ		0x01
#define	FC_FCA_PM_WRITE		0x02
#define	FC_FCA_PM_RW		(FC_FCA_PM_READ | FC_FCA_PM_WRITE)

/*
 *  Command codes for fca_reset()
 */
#define	FC_FCA_LINK_RESET	0x01
#define	FC_FCA_CORE		0x02
#define	FC_FCA_RESET_CORE	0x03
#define	FC_FCA_RESET		0x04

/*
 * fca_port_manage() command codes
 */
#define	FC_PORT_BYPASS		0x01
#define	FC_PORT_UNBYPASS	0x02
#define	FC_PORT_DIAG		0x03
#define	FC_PORT_ERR_STATS	0x04
#define	FC_PORT_GET_FW_REV	0x05
#define	FC_PORT_GET_FCODE_REV	0x06
#define	FC_PORT_GET_DUMP_SIZE	0x07
#define	FC_PORT_FORCE_DUMP	0x08
#define	FC_PORT_GET_DUMP	0x09
#define	FC_PORT_LOOPBACK	0x0A
#define	FC_PORT_LINK_STATE	0x0B
#define	FC_PORT_INITIALIZE	0x0C
#define	FC_PORT_DOWNLOAD_FW	0x0D
#define	FC_PORT_RLS		0x0E
#define	FC_PORT_DOWNLOAD_FCODE	0x0F
#define	FC_PORT_GET_NODE_ID	0x10
#define	FC_PORT_SET_NODE_ID	0x11
#define	FC_PORT_GET_P2P_INFO	0x12

/*
 * FCA capability strings
 */
#define	FC_NODE_WWN			"FCA node WWN"
#define	FC_LOGIN_PARAMS			"FCA login parameters"
#define	FC_CAP_UNSOL_BUF		"number of unsolicited bufs"
#define	FC_CAP_PAYLOAD_SIZE		"exchange payload max"
#define	FC_CAP_POST_RESET_BEHAVIOR	"port reset behavior"
#define	FC_CAP_NOSTREAM_ON_UNALIGN_BUF	"no dma streaming on unaligned buf"
#define	FC_CAP_FCP_DMA			"FCP cmd response in DVMA space"

typedef struct fc_fca_bind {
	int 			port_num;
	opaque_t 		port_handle;
	void (*port_statec_cb) (opaque_t port_handle, uint32_t state);
	void (*port_unsol_cb) (opaque_t port_handle,
		fc_unsol_buf_t *buf, uint32_t type);
	la_wwn_t		port_nwwn;	/* virtual port pwwn */
	la_wwn_t		port_pwwn;	/* virtual port nwwn */
	int			port_npiv;	/* virtual port flag */
} fc_fca_bind_info_t;

typedef struct fc_fca_rnid {
	int		status;
	fc_rnid_t	params;
}fc_fca_rnid_t;

typedef struct fc_fca_port_info {
	uchar_t			pi_topology;	/* Unused */
	uint32_t		pi_error;
	uint32_t		pi_port_state;
	fc_portid_t		pi_s_id;	/* Unused */
	fc_hardaddr_t		pi_hard_addr;	/* Hard address */
	la_els_logi_t		pi_login_params;
	fc_fca_rnid_t		pi_rnid_params;
	fca_port_attrs_t	pi_attrs;
} fc_fca_port_info_t;

typedef struct fc_fca_pm {
	uint32_t	pm_cmd_code;	/* port manage command */
	uint32_t	pm_cmd_flags;	/* READ/WRITE */
	size_t		pm_cmd_len;	/* cmd buffer length */
	caddr_t		pm_cmd_buf;	/* cmd buffer */
	size_t		pm_data_len;	/* data buffer length */
	caddr_t		pm_data_buf;	/* data buffer */
	size_t		pm_stat_len;	/* status buffer length */
	caddr_t		pm_stat_buf;	/* status buffer */
} fc_fca_pm_t;

typedef struct fc_fca_p2p_info {
	uint32_t	fca_d_id;	/* HBA port D_ID */
	uint32_t	d_id;		/* Remote port D_ID */
	la_wwn_t	pwwn;		/* Remote port PWWN */
	la_wwn_t	nwwn;		/* Remote port NWWN */
} fc_fca_p2p_info_t;

typedef struct fca_tran {
	int				fca_version;
	int				fca_numports;
	int				fca_pkt_size;
	uint32_t			fca_cmd_max;
	ddi_dma_lim_t			*fca_dma_lim;
	ddi_iblock_cookie_t		*fca_iblock;
	ddi_dma_attr_t			*fca_dma_attr;
	ddi_dma_attr_t			*fca_dma_fcp_cmd_attr;
	ddi_dma_attr_t			*fca_dma_fcp_rsp_attr;
	ddi_dma_attr_t			*fca_dma_fcp_data_attr;
	ddi_dma_attr_t			*fca_dma_fcip_cmd_attr;
	ddi_dma_attr_t			*fca_dma_fcip_rsp_attr;
	ddi_dma_attr_t			*fca_dma_fcsm_cmd_attr;
	ddi_dma_attr_t			*fca_dma_fcsm_rsp_attr;
	ddi_device_acc_attr_t		*fca_acc_attr;
	int				fca_num_npivports;
		/* number of virtual ports supported, 0 means unsupported */
	la_wwn_t			fca_perm_pwwn;
		/* permanent port wwn for the port */

	opaque_t (*fca_bind_port) (dev_info_t *dip,
	    fc_fca_port_info_t *port_info, fc_fca_bind_info_t *bind_info);

	void (*fca_unbind_port) (opaque_t fca_handle);

	int (*fca_init_pkt) (opaque_t fca_handle, fc_packet_t *pkt, int sleep);

	int (*fca_un_init_pkt) (opaque_t fca_handle, fc_packet_t *pkt);

	int (*fca_els_send) (opaque_t fca_handle, fc_packet_t *pkt);

	int (*fca_get_cap) (opaque_t fca_handle, char *cap, void *ptr);

	int (*fca_set_cap) (opaque_t fca_handle, char *cap, void *ptr);

	int (*fca_getmap) (opaque_t fca_handle, fc_lilpmap_t *map);

	int (*fca_transport) (opaque_t fca_handle, fc_packet_t *pkt);

	int (*fca_ub_alloc) (opaque_t fca_handle, uint64_t *tokens,
	    uint32_t ub_size, uint32_t *ub_count, uint32_t type);

	int (*fca_ub_free) (opaque_t fca_handle, uint32_t count,
	    uint64_t tokens[]);

	int (*fca_ub_release) (opaque_t fca_handle, uint32_t count,
	    uint64_t tokens[]);

	int (*fca_abort) (opaque_t fca_handle, fc_packet_t *pkt, int flags);

	int (*fca_reset) (opaque_t fca_handle, uint32_t cmd);

	int (*fca_port_manage) (opaque_t fca_port, fc_fca_pm_t *arg);

	opaque_t (*fca_get_device) (opaque_t fca_port, fc_portid_t d_id);

	int (*fca_notify) (opaque_t fca_handle, uint32_t cmd);

} fc_fca_tran_t;

void fc_fca_init(struct dev_ops *fca_devops_p);
int fc_fca_attach(dev_info_t *, fc_fca_tran_t *);
int fc_fca_detach(dev_info_t *fca_dip);
int fc_fca_update_errors(fc_packet_t *pkt);
int fc_fca_error(int fc_errno, char **errmsg);
int fc_fca_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln);

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per fca_bind", fc_fca_port_info))
_NOTE(SCHEME_PROTECTS_DATA("unique per fca_bind", fc_fca_bind))
_NOTE(SCHEME_PROTECTS_DATA("stable data", fca_tran))
#endif /* __lint */

#ifdef	__cplusplus
}
#endif

#endif	/* _FC_FCAIF_H */
