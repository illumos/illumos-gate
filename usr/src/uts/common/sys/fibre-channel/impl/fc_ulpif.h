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

#ifndef	_FC_ULPIF_H
#define	_FC_ULPIF_H



#include <sys/note.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * fctl does not support downward compatibility. When there is any change of
 * non-private structure or non-static interface in fctl, the module revision
 * number needs to be bumped up here, and for each ulp, the module revision
 * number in fc_ulp_modinfo needs to be updated.
 */
#define	FCTL_ULP_MODREV_1		1
#define	FCTL_ULP_MODREV_2		2
#define	FCTL_ULP_MODREV_3		3
#define	FCTL_ULP_MODREV_4		4

/*
 * Flag definitions to fc_ulp_get_portmap function.
 */
#define	FC_ULP_PLOGI_DONTCARE		0
#define	FC_ULP_PLOGI_PRESERVE		1

#define	FC_ULP_DEVICE_OFFLINE		0
#define	FC_ULP_DEVICE_ONLINE		1

/*
 * fc_ulp_port_reset() command codes
 */
#define	FC_RESET_PORT			0x01
#define	FC_RESET_ADAPTER		0x02
#define	FC_RESET_DUMP			0x03
#define	FC_RESET_CRASH			0x04

/*
 * port attach callback commands
 */
typedef enum fc_attach_cmd {
	FC_CMD_ATTACH,
	FC_CMD_RESUME,
	FC_CMD_POWER_UP
} fc_attach_cmd_t;

/*
 * port detach callback commands
 */
typedef enum fc_detach_cmd {
	FC_CMD_DETACH,
	FC_CMD_SUSPEND,
	FC_CMD_POWER_DOWN
} fc_detach_cmd_t;

typedef struct fc_portmap {
	int			map_state;
	int			map_flags;		/* Status flags */
	int			map_type;		/* OLD, NEW, CHANGED */
	uint32_t		map_fc4_types[8];	/* fc4 types */
	la_wwn_t    		map_pwwn;
	la_wwn_t		map_nwwn;
	fc_portid_t		map_did;
	fc_hardaddr_t		map_hard_addr;
	opaque_t		map_pd;			/* port device */
	fc_ulp_rscn_info_t	map_rscn_info;		/* xport's RSCN info */
} fc_portmap_t;

typedef struct ulp_port_info {
	struct modlinkage 	*port_linkage;
	dev_info_t		*port_dip;
	opaque_t		port_handle;
	ddi_dma_attr_t		*port_data_dma_attr;
	ddi_dma_attr_t		*port_cmd_dma_attr;
	ddi_dma_attr_t		*port_resp_dma_attr;
	ddi_device_acc_attr_t 	*port_acc_attr;
	int			port_fca_pkt_size;
	int			port_fca_max_exch;
	uint32_t		port_state;
	uint32_t		port_flags;
	la_wwn_t		port_pwwn;		/* port WWN */
	la_wwn_t		port_nwwn;		/* node WWN */
	fc_reset_action_t	port_reset_action;	/* FCA reset action */
	fc_dma_behavior_t	port_dma_behavior;	/* FCA DMA behavior */
	fc_fcp_dma_t		port_fcp_dma;		/* FCP DVMA space */
} fc_ulp_port_info_t;

typedef struct ulp_modinfo {
	opaque_t	ulp_handle;		/* not really needed */
	uint32_t	ulp_rev;		/* ULP revision */
	uchar_t		ulp_type;		/* FC-4 type */
	char 		*ulp_name;		/* ULP Name */
	int		ulp_statec_mask;	/* state change mask */
	int		(*ulp_port_attach) (opaque_t ulp_handle,
			    struct ulp_port_info *, fc_attach_cmd_t cmd,
			    uint32_t s_id);
	int		(*ulp_port_detach) (opaque_t ulp_handle,
			    struct ulp_port_info *, fc_detach_cmd_t cmd);
	int		(*ulp_port_ioctl) (opaque_t ulp_handle,
			    opaque_t port_handle, dev_t dev, int cmd,
			    intptr_t data, int mode, cred_t *credp,
			    int *rval, uint32_t claimed);
	int		(*ulp_els_callback) (opaque_t ulp_handle,
			    opaque_t port_handle, fc_unsol_buf_t *payload,
			    uint32_t claimed);
	int		(*ulp_data_callback) (opaque_t ulp_handle,
			    opaque_t port_handle, fc_unsol_buf_t *buf,
			    uint32_t claimed);
	void		(*ulp_statec_callback) (opaque_t ulp_handle,
			    opaque_t port_handle, uint32_t statec,
			    uint32_t port_flags, fc_portmap_t changelist[],
			    uint32_t listlen, uint32_t s_id);
} fc_ulp_modinfo_t;

#if	!defined(__lint)
_NOTE(SCHEME_PROTECTS_DATA("unique for attach", ulp_port_info))
_NOTE(SCHEME_PROTECTS_DATA("stable data", ulp_modinfo))
_NOTE(SCHEME_PROTECTS_DATA("unique per request", fc_portmap))
#endif	/* __lint */

int fc_ulp_add(fc_ulp_modinfo_t *ulp_info);
int fc_ulp_remove(fc_ulp_modinfo_t *ulp_info);
int fc_ulp_init_packet(opaque_t port_handle, fc_packet_t *pkt, int sleep);
int fc_ulp_uninit_packet(opaque_t port_handle, fc_packet_t *pkt);
int fc_ulp_getportmap(opaque_t port_handle, fc_portmap_t **map,
    uint32_t *len, int flag);
int fc_ulp_login(opaque_t port_handle, fc_packet_t **ulp_pkt,
    uint32_t listlen);
opaque_t fc_ulp_get_remote_port(opaque_t port_handle, la_wwn_t *pwwn,
    int *error, int create);
int fc_ulp_port_ns(opaque_t port_handle, opaque_t pd, fc_ns_cmd_t *ns_req);
int fc_ulp_transport(opaque_t port_handle, fc_packet_t *pkt);
int fc_ulp_issue_els(opaque_t port_handle, fc_packet_t *pkt);
int fc_ulp_uballoc(opaque_t port_handle, uint32_t *count,
    uint32_t size, uint32_t type, uint64_t *tokens);
int fc_ulp_ubfree(opaque_t port_handle, uint32_t count,
    uint64_t *tokens);
int fc_ulp_ubrelease(opaque_t port_handle, uint32_t count,
    uint64_t *tokens);
int fc_ulp_abort(opaque_t port_handle, fc_packet_t *pkt, int flags);
int fc_ulp_linkreset(opaque_t port_handle, la_wwn_t *pwwn, int sleep);
int fc_ulp_port_reset(opaque_t port_handle, uint32_t cmd);
int fc_ulp_get_port_login_params(opaque_t port_handle,
    la_els_logi_t *login_params);
int fc_ulp_get_port_instance(opaque_t port_handle);
opaque_t fc_ulp_get_port_handle(int instance);
int fc_ulp_error(int fc_errno, char **errmsg);
int fc_ulp_pkt_error(fc_packet_t *pkt, char **state, char **reason,
    char **action, char **expln);
int fc_ulp_is_name_present(caddr_t ulp_name);
int fc_ulp_get_pwwn_by_did(opaque_t port_handle, fc_portid_t d_id,
    la_wwn_t *pwwn);
int fc_ulp_pwwn_to_portmap(opaque_t port_handle, la_wwn_t *bytes,
    fc_portmap_t *map);
opaque_t fc_ulp_get_fca_device(opaque_t port_handle, fc_portid_t d_id);
int fc_ulp_port_notify(opaque_t port_handle, uint32_t cmd);
void fc_ulp_disable_relogin(opaque_t *fc_port, la_wwn_t *pwwn);
void fc_ulp_enable_relogin(opaque_t *fc_port, la_wwn_t *pwwn);
int fc_ulp_busy_port(opaque_t port_handle);
void fc_ulp_idle_port(opaque_t port_handle);
void fc_ulp_copy_portmap(fc_portmap_t *map, opaque_t pd);
int fc_ulp_get_adapter_paths(char *pathList, int count);
uint32_t fc_ulp_get_rscn_count(opaque_t port_handle);
void fc_ulp_hold_remote_port(opaque_t port_handle);
int fc_ulp_get_npiv_port_list(opaque_t port_handle, char *pathList);
int fc_ulp_get_npiv_port_num(opaque_t port_handle);
void fc_ulp_log_device_event(opaque_t port_handle, int type);

#ifdef	__cplusplus
}
#endif

#endif	/* _FC_ULPIF_H */
