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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_EOIB_ENX_IMPL_H
#define	_SYS_IB_EOIB_ENX_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/ib/ibtl/ibti.h>
#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/ib_pkt_hdrs.h>
#include <sys/ib/ibtl/impl/ibtl_ibnex.h>
#include <sys/ib/mgt/sm_attr.h>

#include <sys/ib/clients/eoib/fip.h>
#include <sys/ib/clients/eoib/eib.h>

/*
 * Driver specific constants
 */
#define	ENX_E_SUCCESS		0
#define	ENX_E_FAILURE		-1
#define	ENX_MAX_LINE		128
#define	ENX_GRH_SZ		(sizeof (ib_grh_t))

/*
 * Debug messages
 */
#define	ENX_MSGS_CRIT		0x01
#define	ENX_MSGS_ERR		0x02
#define	ENX_MSGS_WARN		0x04
#define	ENX_MSGS_DEBUG		0x08
#define	ENX_MSGS_ARGS		0x10
#define	ENX_MSGS_VERBOSE	0x20
#define	ENX_MSGS_DEFAULT	(ENX_MSGS_CRIT | ENX_MSGS_ERR | ENX_MSGS_WARN)

#define	ENX_LOGSZ_DEFAULT	0x20000

#define	ENX_DPRINTF_CRIT	eibnx_dprintf_crit
#define	ENX_DPRINTF_ERR		eibnx_dprintf_err
#define	ENX_DPRINTF_WARN	eibnx_dprintf_warn
#ifdef ENX_DEBUG
#define	ENX_DPRINTF_DEBUG	eibnx_dprintf_debug
#define	ENX_DPRINTF_ARGS	eibnx_dprintf_args
#define	ENX_DPRINTF_VERBOSE	eibnx_dprintf_verbose
#else
#define	ENX_DPRINTF_DEBUG	0 &&
#define	ENX_DPRINTF_ARGS	0 &&
#define	ENX_DPRINTF_VERBOSE	0 &&
#endif

/*
 *  EoIB Nexus service threads
 */
#define	ENX_PORT_MONITOR	"eibnx_port_%d_monitor"
#define	ENX_NODE_CREATOR	"eibnx_node_creator"

/*
 * Default period (us) for unicast solicitations to discovered gateways.
 * EoIB specification requires that hosts send solicitation atleast every
 * 4 * GW_ADV_PERIOD.
 */
#define	ENX_DFL_SOLICIT_PERIOD_USEC	32000000

/*
 * Portinfo list per HCA
 */
typedef struct eibnx_port_s {
	struct eibnx_port_s 	*po_next;
	ibt_hca_portinfo_t	*po_pi;
	uint_t			po_pi_size;
} eibnx_port_t;

/*
 * HCA details
 */
typedef struct eibnx_hca_s {
	struct eibnx_hca_s 	*hc_next;
	ib_guid_t		hc_guid;
	ibt_hca_hdl_t		hc_hdl;
	ibt_pd_hdl_t		hc_pd;
	eibnx_port_t		*hc_port;
} eibnx_hca_t;

/*
 * The port_monitor thread in EoIB nexus driver only sends two types of
 * packets: multicast solicitation the first time around, and periodic
 * unicast solicitations later to gateways that have been discovered. So
 * we need a couple of send wqes for the multicast solicitation and
 * probably as many send wqes as the number of gateways that may be
 * discovered from each port, for sending the unicast solicitations.
 * For unicast solicitations though, the UD destination needs to be set
 * up at the time we receive the advertisement from the gateway, using
 * ibt_modify_reply_ud_dest(), so we'll assign one send wqe for each
 * gateway that we discover.  This means that we need to acquire these
 * send wqe entries during rx processing in the completion handler, which
 * means we must avoid sleeping in trying to acquire the swqe. Therefore,
 * we'll pre-allocate these unicast solication send wqes to be atleast
 * twice the number of recv wqes.
 *
 * The receive packets expected by the EoIB nexus driver are the multicast
 * and unicast messages on the SOLICIT and ADVERTISE groups. These
 * shouldn't be too many, and should be tuned as we gain experience on
 * the traffic pattern.  We'll start with 16.
 */
#define	ENX_NUM_SWQE			46
#define	ENX_NUM_RWQE			16
#define	ENX_CQ_SIZE			(ENX_NUM_SWQE + ENX_NUM_RWQE + 2)

/*
 * qe_type values
 */
#define	ENX_QETYP_RWQE			0x1
#define	ENX_QETYP_SWQE			0x2

/*
 * qe_flags bitmasks (protected by qe_lock). None of the
 * flag values may be zero.
 */
#define	ENX_QEFL_INUSE			0x01
#define	ENX_QEFL_POSTED			0x02
#define	ENX_QEFL_RELONCOMP		0x04

/*
 * Recv and send workq entries
 */
typedef struct eibnx_wqe_s {
	uint_t			qe_type;
	uint_t			qe_bufsz;
	ibt_wr_ds_t		qe_sgl;
	ibt_all_wr_t		qe_wr;
	kmutex_t		qe_lock;
	uint_t			qe_flags;
} eibnx_wqe_t;

/*
 * Tx descriptor
 */
typedef struct eibnx_tx_s {
	ib_vaddr_t		tx_vaddr;
	ibt_mr_hdl_t		tx_mr;
	ibt_lkey_t		tx_lkey;
	eibnx_wqe_t		tx_wqe[ENX_NUM_SWQE];
} eibnx_tx_t;

/*
 * Rx descriptor
 */
typedef struct eibnx_rx_s {
	ib_vaddr_t		rx_vaddr;
	ibt_mr_hdl_t		rx_mr;
	ibt_lkey_t		rx_lkey;
	eibnx_wqe_t		rx_wqe[ENX_NUM_RWQE];
} eibnx_rx_t;

/*
 * Details about the address of each gateway we discover.
 */
typedef struct eibnx_gw_addr_s {
	ibt_adds_vect_t		*ga_vect;
	ib_gid_t		ga_gid;
	ib_qpn_t		ga_qpn;
	ib_qkey_t		ga_qkey;
	ib_pkey_t		ga_pkey;
} eibnx_gw_addr_t;

/*
 * States for each GW
 */
#define	ENX_GW_STATE_UNAVAILABLE	1	/* GW nackd availability */
#define	ENX_GW_STATE_AVAILABLE		2	/* GW mcasted availability */
#define	ENX_GW_STATE_READY_TO_LOGIN	3	/* GW ucasted availability */

typedef struct eibnx_gw_info_s {
	struct eibnx_gw_info_s	*gw_next;
	eibnx_wqe_t		*gw_swqe;
	uint_t			gw_state;

	kmutex_t		gw_adv_lock;
	uint_t			gw_adv_flag;
	int64_t			gw_adv_last_lbolt;
	int64_t			gw_adv_timeout_ticks;

	eibnx_gw_addr_t		gw_addr;

	ib_guid_t		gw_system_guid;
	ib_guid_t		gw_guid;

	uint32_t		gw_adv_period;
	uint32_t		gw_ka_period;
	uint32_t		gw_vnic_ka_period;
	ib_qpn_t		gw_ctrl_qpn;

	ib_lid_t		gw_lid;
	uint16_t		gw_portid;
	uint16_t		gw_num_net_vnics;

	uint8_t			gw_is_host_adm_vnics;
	uint8_t			gw_sl;
	uint8_t			gw_n_rss_qpn;
	uint8_t			gw_flag_ucast_advt;
	uint8_t			gw_flag_available;

	uint8_t			gw_system_name[EIB_GW_SYSNAME_LEN];
	uint8_t			gw_port_name[EIB_GW_PORTNAME_LEN];
	uint8_t			gw_vendor_id[EIB_GW_VENDOR_LEN];
} eibnx_gw_info_t;

/*
 * Values for gw_adv_flag (non-zero only)
 */
#define	ENX_GW_DEAD		1
#define	ENX_GW_ALIVE		2
#define	ENX_GW_AWARE		3

/*
 * Currently, we only expect the advertisement type of packets
 * from the gw. But we do get login acks from the gateway also
 * here in the nexus, so we'll need an identifier for that.
 */
typedef enum {
	FIP_GW_ADVERTISE_MCAST = 0,
	FIP_GW_ADVERTISE_UCAST,
	FIP_VNIC_LOGIN_ACK
} eibnx_gw_pkt_type_t;

/*
 * Currently, the only gw response handled by the eibnx driver
 * are the ucast/mcast advertisements.  Information collected from
 * both these responses may be packed into a eibnx_gw_info_t.
 * In the future, if we decide to handle other types of responses
 * from the gw, we could simply add the new types to the union.
 */
typedef struct eibnx_gw_msg_s {
	eibnx_gw_pkt_type_t	gm_type;
	union {
		eibnx_gw_info_t	gm_info;
	} u;
} eibnx_gw_msg_t;

/*
 * List to hold the devinfo nodes of eoib instances
 */
typedef struct eibnx_child_s {
	struct eibnx_child_s	*ch_next;
	dev_info_t		*ch_dip;
	eibnx_gw_info_t		*ch_gwi;
	char			*ch_node_name;
} eibnx_child_t;

/*
 * Event bitmasks for the port-monitor to wait on. None of these flags
 * may be zero.
 */
#define	ENX_EVENT_LINK_UP		0x01
#define	ENX_EVENT_MCGS_AVAILABLE	0x02
#define	ENX_EVENT_TIMED_OUT		0x04
#define	ENX_EVENT_DIE			0x08
#define	ENX_EVENT_COMPLETION		0x10

/*
 * MCG Query/Join status
 */
#define	ENX_MCGS_FOUND			0x1
#define	ENX_MCGS_JOINED			0x2

/*
 * Information that each port-monitor thread cares about
 */
typedef struct eibnx_thr_info_s {
	struct eibnx_thr_info_s	*ti_next;
	uint_t			ti_progress;

	/*
	 * Our kernel thread id
	 */
	kt_did_t		ti_kt_did;

	/*
	 * HCA, port and protection domain information
	 */
	ib_guid_t		ti_hca_guid;
	ibt_hca_hdl_t		ti_hca;
	ibt_pd_hdl_t		ti_pd;
	ibt_hca_portinfo_t	*ti_pi;
	char			*ti_ident;

	/*
	 * Well-known multicast groups for solicitations
	 * and advertisements.
	 */
	kmutex_t		ti_mcg_lock;
	uint_t			ti_mcg_status;
	ibt_mcg_info_t		*ti_advertise_mcg;
	ibt_mcg_info_t		*ti_solicit_mcg;
	uint_t			ti_mcast_done;

	/*
	 * Completion queue stuff
	 */
	ibt_cq_hdl_t		ti_cq_hdl;
	uint_t			ti_cq_sz;
	ibt_wc_t		*ti_wc;
	ddi_softint_handle_t    ti_softint_hdl;

	/*
	 * Channel related
	 */
	ibt_channel_hdl_t	ti_chan;
	ib_qpn_t		ti_qpn;

	/*
	 * Transmit/Receive stuff
	 */
	eibnx_tx_t		ti_snd;
	eibnx_rx_t		ti_rcv;

	/*
	 * GW related stuff
	 */
	kmutex_t		ti_gw_lock;
	eibnx_gw_info_t		*ti_gw;

	/*
	 * Devinfo nodes for the eoib children
	 */
	kmutex_t		ti_child_lock;
	eibnx_child_t		*ti_child;

	/*
	 * Events that we wait on and/or handle
	 */
	kmutex_t		ti_event_lock;
	kcondvar_t		ti_event_cv;
	uint_t			ti_event;
} eibnx_thr_info_t;

/*
 * Workq entry for creation of eoib nodes
 */
typedef struct eibnx_nodeq_s {
	struct eibnx_nodeq_s	*nc_next;
	eibnx_thr_info_t	*nc_info;
	eibnx_gw_info_t		*nc_gwi;
} eibnx_nodeq_t;

/*
 * Bus config status flags.  The in-prog is protected by
 * nx_lock, and the rest of the flags (currently only
 * buscfg-complete) is protected by the in-prog bit itself.
 */
#define	NX_FL_BUSOP_INPROG		0x1
#define	NX_FL_BUSCFG_COMPLETE		0x2
#define	NX_FL_BUSOP_MASK		0x3

/*
 * EoIB nexus per-instance state
 */
typedef struct eibnx_s {
	dev_info_t		*nx_dip;
	ibt_clnt_hdl_t		nx_ibt_hdl;

	kmutex_t		nx_lock;
	eibnx_hca_t		*nx_hca;
	eibnx_thr_info_t	*nx_thr_info;
	boolean_t		nx_monitors_up;

	kmutex_t		nx_nodeq_lock;
	kcondvar_t		nx_nodeq_cv;
	eibnx_nodeq_t		*nx_nodeq;
	kt_did_t		nx_nodeq_kt_did;
	uint_t			nx_nodeq_thr_die;

	kmutex_t		nx_busop_lock;
	kcondvar_t		nx_busop_cv;
	uint_t			nx_busop_flags;
} eibnx_t;


/*
 * Event tags for EoIB Nexus events delivered to EoIB instances
 */
#define	ENX_EVENT_TAG_GW_INFO_UPDATE		0
#define	ENX_EVENT_TAG_GW_AVAILABLE		1
#define	ENX_EVENT_TAG_LOGIN_ACK			2

/*
 * FUNCTION PROTOTYPES FOR CROSS-FILE LINKAGE
 */

/*
 * Threads and Event Handlers
 */
void eibnx_port_monitor(eibnx_thr_info_t *);
void eibnx_subnet_notices_handler(void *, ib_gid_t, ibt_subnet_event_code_t,
    ibt_subnet_event_t *);
void eibnx_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
boolean_t eibnx_is_gw_dead(eibnx_gw_info_t *);
void eibnx_create_eoib_node(void);
void eibnx_comp_intr(ibt_cq_hdl_t, void *);
uint_t eibnx_comp_handler(caddr_t, caddr_t);

/*
 * IBT related functions
 */
int eibnx_ibt_init(eibnx_t *);
int eibnx_find_mgroups(eibnx_thr_info_t *);
int eibnx_setup_cq(eibnx_thr_info_t *);
int eibnx_setup_ud_channel(eibnx_thr_info_t *);
int eibnx_setup_bufs(eibnx_thr_info_t *);
int eibnx_setup_cq_handler(eibnx_thr_info_t *);
int eibnx_join_mcgs(eibnx_thr_info_t *);
int eibnx_rejoin_mcgs(eibnx_thr_info_t *);
int eibnx_ibt_fini(eibnx_t *);

void eibnx_rb_find_mgroups(eibnx_thr_info_t *);
void eibnx_rb_setup_cq(eibnx_thr_info_t *);
void eibnx_rb_setup_ud_channel(eibnx_thr_info_t *);
void eibnx_rb_setup_bufs(eibnx_thr_info_t *);
void eibnx_rb_setup_cq_handler(eibnx_thr_info_t *);
void eibnx_rb_join_mcgs(eibnx_thr_info_t *);

eibnx_hca_t *eibnx_prepare_hca(ib_guid_t);
int eibnx_cleanup_hca(eibnx_hca_t *);

/*
 * FIP packetizing related functions
 */
int eibnx_fip_solicit_mcast(eibnx_thr_info_t *);
int eibnx_fip_solicit_ucast(eibnx_thr_info_t *, clock_t *);
int eibnx_fip_parse_pkt(uint8_t *, eibnx_gw_msg_t *);

/*
 * Queue and List related routines
 */
eibnx_wqe_t *eibnx_acquire_swqe(eibnx_thr_info_t *, int);
void eibnx_return_swqe(eibnx_wqe_t *);
void eibnx_return_rwqe(eibnx_thr_info_t *, eibnx_wqe_t *);
void eibnx_release_swqe(eibnx_wqe_t *);

void eibnx_enqueue_child(eibnx_thr_info_t *, eibnx_gw_info_t *, char *,
    dev_info_t *);
int eibnx_update_child(eibnx_thr_info_t *, eibnx_gw_info_t *, dev_info_t *);
dev_info_t *eibnx_find_child_dip_by_inst(eibnx_thr_info_t *, int);
dev_info_t *eibnx_find_child_dip_by_gw(eibnx_thr_info_t *, uint16_t);

eibnx_gw_info_t *eibnx_find_gw_in_gwlist(eibnx_thr_info_t *, eibnx_gw_info_t *);
eibnx_gw_info_t *eibnx_add_gw_to_gwlist(eibnx_thr_info_t *, eibnx_gw_info_t *,
    ibt_wc_t *, uint8_t *);
void eibnx_replace_gw_in_gwlist(eibnx_thr_info_t *, eibnx_gw_info_t *,
    eibnx_gw_info_t *, ibt_wc_t *, uint8_t *, boolean_t *);
void eibnx_queue_for_creation(eibnx_thr_info_t *, eibnx_gw_info_t *);

/*
 * Logging and Error reporting routines
 */
void eibnx_debug_init(void);
void eibnx_debug_fini(void);
void eibnx_dprintf_crit(const char *fmt, ...);
void eibnx_dprintf_err(const char *fmt, ...);
void eibnx_dprintf_warn(const char *fmt, ...);
#ifdef ENX_DEBUG
void eibnx_dprintf_debug(const char *fmt, ...);
void eibnx_dprintf_args(const char *fmt, ...);
void eibnx_dprintf_verbose(const char *fmt, ...);
#endif

/*
 * Miscellaneous
 */
void eibnx_cleanup_port_nodes(eibnx_thr_info_t *);
void eibnx_create_node_props(dev_info_t *, eibnx_thr_info_t *,
    eibnx_gw_info_t *);
int eibnx_name_child(dev_info_t *, char *, size_t);
void eibnx_busop_inprog_enter(eibnx_t *);
void eibnx_busop_inprog_exit(eibnx_t *);
eibnx_thr_info_t *eibnx_start_port_monitor(eibnx_hca_t *, eibnx_port_t *);
void eibnx_stop_port_monitor(eibnx_thr_info_t *);
void eibnx_terminate_monitors(void);
int eibnx_configure_node(eibnx_thr_info_t *, eibnx_gw_info_t *, dev_info_t **);
int eibnx_unconfigure_node(eibnx_thr_info_t *, eibnx_gw_info_t *);
int eibnx_locate_node_name(char *, eibnx_thr_info_t **, eibnx_gw_info_t **);
int eibnx_locate_unconfigured_node(eibnx_thr_info_t **, eibnx_gw_info_t **);

/*
 * Devctl cbops (currently dummy)
 */
int eibnx_devctl_open(dev_t *, int, int, cred_t *);
int eibnx_devctl_close(dev_t, int, int, cred_t *);
int eibnx_devctl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * External variable references
 */
extern pri_t minclsyspri;
extern eibnx_t *enx_global_ss;
extern ib_gid_t enx_solicit_mgid;
extern ib_gid_t enx_advertise_mgid;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_EOIB_ENX_IMPL_H */
