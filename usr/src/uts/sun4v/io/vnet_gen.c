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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/machsystm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/ldc.h>
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <net/if.h>
#include <sys/vnet.h>
#include <sys/vio_mailbox.h>
#include <sys/vio_common.h>
#include <sys/vnet_common.h>
#include <sys/vnet_mailbox.h>
#include <sys/vio_util.h>
#include <sys/vnet_gen.h>
#include <sys/atomic.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/intr.h>
#include <sys/pattr.h>
#include <sys/vlan.h>

/*
 * Implementation of the mac provider functionality for vnet using the
 * generic(default) transport layer of sun4v Logical Domain Channels(LDC).
 */

/* Entry Points */
int vgen_init(void *vnetp, uint64_t regprop, dev_info_t *vnetdip,
    const uint8_t *macaddr, void **vgenhdl);
int vgen_init_mdeg(void *arg);
void vgen_uninit(void *arg);
int vgen_dds_tx(void *arg, void *dmsg);
int vgen_enable_intr(void *arg);
int vgen_disable_intr(void *arg);
mblk_t *vgen_rx_poll(void *arg, int bytes_to_pickup);
static int vgen_start(void *arg);
static void vgen_stop(void *arg);
static mblk_t *vgen_tx(void *arg, mblk_t *mp);
static int vgen_multicst(void *arg, boolean_t add,
	const uint8_t *mca);
static int vgen_promisc(void *arg, boolean_t on);
static int vgen_unicst(void *arg, const uint8_t *mca);
static int vgen_stat(void *arg, uint_t stat, uint64_t *val);
static void vgen_ioctl(void *arg, queue_t *q, mblk_t *mp);
#ifdef	VNET_IOC_DEBUG
static int vgen_force_link_state(vgen_port_t *portp, int link_state);
#endif

/* Port/LDC Configuration */
static int vgen_read_mdprops(vgen_t *vgenp);
static void vgen_update_md_prop(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex);
static void vgen_read_pri_eth_types(vgen_t *vgenp, md_t *mdp,
	mde_cookie_t node);
static void vgen_mtu_read(vgen_t *vgenp, md_t *mdp, mde_cookie_t node,
	uint32_t *mtu);
static void vgen_linkprop_read(vgen_t *vgenp, md_t *mdp, mde_cookie_t node,
	boolean_t *pls);
static void vgen_detach_ports(vgen_t *vgenp);
static void vgen_port_detach(vgen_port_t *portp);
static void vgen_port_list_insert(vgen_port_t *portp);
static void vgen_port_list_remove(vgen_port_t *portp);
static vgen_port_t *vgen_port_lookup(vgen_portlist_t *plistp,
	int port_num);
static int vgen_mdeg_reg(vgen_t *vgenp);
static void vgen_mdeg_unreg(vgen_t *vgenp);
static int vgen_mdeg_cb(void *cb_argp, mdeg_result_t *resp);
static int vgen_mdeg_port_cb(void *cb_argp, mdeg_result_t *resp);
static int vgen_add_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex);
static int vgen_port_read_props(vgen_port_t *portp, vgen_t *vgenp, md_t *mdp,
	mde_cookie_t mdex);
static int vgen_remove_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex);
static int vgen_port_attach(vgen_port_t *portp);
static void vgen_port_detach_mdeg(vgen_port_t *portp);
static int vgen_update_port(vgen_t *vgenp, md_t *curr_mdp,
	mde_cookie_t curr_mdex, md_t *prev_mdp, mde_cookie_t prev_mdex);
static uint64_t	vgen_port_stat(vgen_port_t *portp, uint_t stat);
static void vgen_port_reset(vgen_port_t *portp);
static void vgen_reset_vsw_port(vgen_t *vgenp);
static int vgen_ldc_reset(vgen_ldc_t *ldcp, vgen_caller_t caller);
static void vgen_ldc_up(vgen_ldc_t *ldcp);
static int vgen_ldc_attach(vgen_port_t *portp, uint64_t ldc_id);
static void vgen_ldc_detach(vgen_ldc_t *ldcp);
static void vgen_port_init(vgen_port_t *portp);
static void vgen_port_uninit(vgen_port_t *portp);
static int vgen_ldc_init(vgen_ldc_t *ldcp);
static void vgen_ldc_uninit(vgen_ldc_t *ldcp);
static uint64_t	vgen_ldc_stat(vgen_ldc_t *ldcp, uint_t stat);

/* I/O Processing */
static int vgen_portsend(vgen_port_t *portp, mblk_t *mp);
static int vgen_ldcsend(void *arg, mblk_t *mp);
static void vgen_ldcsend_pkt(void *arg, mblk_t *mp);
static uint_t vgen_ldc_cb(uint64_t event, caddr_t arg);
static void vgen_tx_watchdog(void *arg);

/*  Dring Configuration */
static int vgen_create_dring(vgen_ldc_t *ldcp);
static void vgen_destroy_dring(vgen_ldc_t *ldcp);
static int vgen_map_dring(vgen_ldc_t *ldcp, void *pkt);
static void vgen_unmap_dring(vgen_ldc_t *ldcp);
static int vgen_mapin_avail(vgen_ldc_t *ldcp);

/* VIO Message Processing */
static int vgen_handshake(vgen_ldc_t *ldcp);
static int vgen_handshake_done(vgen_ldc_t *ldcp);
static vgen_ldc_t *vh_nextphase(vgen_ldc_t *ldcp);
static int vgen_handshake_phase2(vgen_ldc_t *ldcp);
static int vgen_handshake_phase3(vgen_ldc_t *ldcp);
static void vgen_setup_handshake_params(vgen_ldc_t *ldcp);
static int vgen_send_version_negotiate(vgen_ldc_t *ldcp);
static int vgen_send_attr_info(vgen_ldc_t *ldcp);
static int vgen_send_rx_dring_reg(vgen_ldc_t *ldcp);
static int vgen_send_tx_dring_reg(vgen_ldc_t *ldcp);
static void vgen_init_dring_reg_msg(vgen_ldc_t *ldcp, vio_dring_reg_msg_t *msg,
	uint8_t option);
static int vgen_send_rdx_info(vgen_ldc_t *ldcp);
static int vgen_send_dringdata(vgen_ldc_t *ldcp, uint32_t start, int32_t end);
static int vgen_send_mcast_info(vgen_ldc_t *ldcp);
static int vgen_handle_version_negotiate(vgen_ldc_t *ldcp,
	vio_msg_tag_t *tagp);
static int vgen_handle_attr_msg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_attr_info(vgen_ldc_t *ldcp, vnet_attr_msg_t *msg);
static int vgen_handle_attr_ack(vgen_ldc_t *ldcp, vnet_attr_msg_t *msg);
static int vgen_handle_dring_reg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_dring_reg_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_dring_reg_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_rdx_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_mcast_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_handle_ctrlmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_pkt_data_nop(void *arg1, void *arg2, uint32_t msglen);
static int vgen_handle_datamsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
	uint32_t msglen);
static void vgen_handle_errmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static int vgen_dds_rx(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_handle_evt_up(vgen_ldc_t *ldcp);
static int vgen_process_reset(vgen_ldc_t *ldcp, int flags);
static int vgen_check_sid(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);
static void vgen_hwatchdog(void *arg);
static void vgen_set_vnet_proto_ops(vgen_ldc_t *ldcp);
static void vgen_reset_vnet_proto_ops(vgen_ldc_t *ldcp);
static void vgen_link_update(vgen_t *vgenp, link_state_t link_state);

/* VLANs */
static void vgen_vlan_read_ids(void *arg, int type, md_t *mdp,
	mde_cookie_t node, uint16_t *pvidp, uint16_t **vidspp,
	uint16_t *nvidsp, uint16_t *default_idp);
static void vgen_vlan_create_hash(vgen_port_t *portp);
static void vgen_vlan_destroy_hash(vgen_port_t *portp);
static void vgen_vlan_add_ids(vgen_port_t *portp);
static void vgen_vlan_remove_ids(vgen_port_t *portp);
static boolean_t vgen_vlan_lookup(mod_hash_t *vlan_hashp, uint16_t vid);
static boolean_t vgen_frame_lookup_vid(vnet_t *vnetp, struct ether_header *ehp,
	uint16_t *vidp);
static mblk_t *vgen_vlan_frame_fixtag(vgen_port_t *portp, mblk_t *mp,
	boolean_t is_tagged, uint16_t vid);
static void vgen_vlan_unaware_port_reset(vgen_port_t *portp);
static void vgen_reset_vlan_unaware_ports(vgen_t *vgenp);

/* Exported functions */
int vgen_handle_evt_read(vgen_ldc_t *ldcp, vgen_caller_t caller);
int vgen_handle_evt_reset(vgen_ldc_t *ldcp, vgen_caller_t caller);
void vgen_handle_pkt_data(void *arg1, void *arg2, uint32_t msglen);
void vgen_destroy_rxpools(void *arg);

/* Externs */
extern void vnet_dds_rx(void *arg, void *dmsg);
extern void vnet_dds_cleanup_hio(vnet_t *vnetp);
extern int vnet_mtu_update(vnet_t *vnetp, uint32_t mtu);
extern void vnet_link_update(vnet_t *vnetp, link_state_t link_state);
extern int vgen_sendmsg(vgen_ldc_t *ldcp, caddr_t msg,  size_t msglen,
    boolean_t caller_holds_lock);
extern void vgen_stop_msg_thread(vgen_ldc_t *ldcp);
extern int vgen_create_tx_dring(vgen_ldc_t *ldcp);
extern void vgen_destroy_tx_dring(vgen_ldc_t *ldcp);
extern int vgen_map_rx_dring(vgen_ldc_t *ldcp, void *pkt);
extern void vgen_unmap_rx_dring(vgen_ldc_t *ldcp);
extern int vgen_create_rx_dring(vgen_ldc_t *ldcp);
extern void vgen_destroy_rx_dring(vgen_ldc_t *ldcp);
extern int vgen_map_tx_dring(vgen_ldc_t *ldcp, void *pkt);
extern void vgen_unmap_tx_dring(vgen_ldc_t *ldcp);
extern int vgen_map_data(vgen_ldc_t *ldcp, void *pkt);
extern int vgen_handle_dringdata_shm(void *arg1, void *arg2);
extern int vgen_handle_dringdata(void *arg1, void *arg2);
extern int vgen_dringsend_shm(void *arg, mblk_t *mp);
extern int vgen_dringsend(void *arg, mblk_t *mp);
extern void vgen_ldc_msg_worker(void *arg);
extern int vgen_send_dringack_shm(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp,
    uint32_t start, int32_t end, uint8_t pstate);
extern mblk_t *vgen_poll_rcv_shm(vgen_ldc_t *ldcp, int bytes_to_pickup);
extern mblk_t *vgen_poll_rcv(vgen_ldc_t *ldcp, int bytes_to_pickup);
extern int vgen_check_datamsg_seq(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp);

#define	VGEN_PRI_ETH_DEFINED(vgenp)	((vgenp)->pri_num_types != 0)

#define	LDC_LOCK(ldcp)	\
				mutex_enter(&((ldcp)->cblock));\
				mutex_enter(&((ldcp)->rxlock));\
				mutex_enter(&((ldcp)->wrlock));\
				mutex_enter(&((ldcp)->txlock));\
				mutex_enter(&((ldcp)->tclock));
#define	LDC_UNLOCK(ldcp)	\
				mutex_exit(&((ldcp)->tclock));\
				mutex_exit(&((ldcp)->txlock));\
				mutex_exit(&((ldcp)->wrlock));\
				mutex_exit(&((ldcp)->rxlock));\
				mutex_exit(&((ldcp)->cblock));

#define	VGEN_VER_EQ(ldcp, major, minor)	\
	((ldcp)->local_hparams.ver_major == (major) &&	\
	    (ldcp)->local_hparams.ver_minor == (minor))

#define	VGEN_VER_LT(ldcp, major, minor)	\
	(((ldcp)->local_hparams.ver_major < (major)) ||	\
	    ((ldcp)->local_hparams.ver_major == (major) &&	\
	    (ldcp)->local_hparams.ver_minor < (minor)))

#define	VGEN_VER_GTEQ(ldcp, major, minor)	\
	(((ldcp)->local_hparams.ver_major > (major)) ||	\
	    ((ldcp)->local_hparams.ver_major == (major) &&	\
	    (ldcp)->local_hparams.ver_minor >= (minor)))

/*
 * Property names
 */
static char macaddr_propname[] = "mac-address";
static char rmacaddr_propname[] = "remote-mac-address";
static char channel_propname[] = "channel-endpoint";
static char reg_propname[] = "reg";
static char port_propname[] = "port";
static char swport_propname[] = "switch-port";
static char id_propname[] = "id";
static char vdev_propname[] = "virtual-device";
static char vnet_propname[] = "network";
static char pri_types_propname[] = "priority-ether-types";
static char vgen_pvid_propname[] = "port-vlan-id";
static char vgen_vid_propname[] = "vlan-id";
static char vgen_dvid_propname[] = "default-vlan-id";
static char port_pvid_propname[] = "remote-port-vlan-id";
static char port_vid_propname[] = "remote-vlan-id";
static char vgen_mtu_propname[] = "mtu";
static char vgen_linkprop_propname[] = "linkprop";

/*
 * VIO Protocol Version Info:
 *
 * The version specified below represents the version of protocol currently
 * supported in the driver. It means the driver can negotiate with peers with
 * versions <= this version. Here is a summary of the feature(s) that are
 * supported at each version of the protocol:
 *
 * 1.0			Basic VIO protocol.
 * 1.1			vDisk protocol update (no virtual network update).
 * 1.2			Support for priority frames (priority-ether-types).
 * 1.3			VLAN and HybridIO support.
 * 1.4			Jumbo Frame support.
 * 1.5			Link State Notification support with optional support
 *			for Physical Link information.
 * 1.6			Support for RxDringData mode.
 */
static vgen_ver_t vgen_versions[VGEN_NUM_VER] =  { {1, 6} };

/* Tunables */
uint32_t vgen_hwd_interval = 5;		/* handshake watchdog freq in sec */
uint32_t vgen_ldcwr_retries = 10;	/* max # of ldc_write() retries */
uint32_t vgen_ldcup_retries = 5;	/* max # of ldc_up() retries */
uint32_t vgen_ldccl_retries = 5;	/* max # of ldc_close() retries */
uint32_t vgen_tx_delay = 0x30;		/* delay when tx descr not available */
uint32_t vgen_ldc_mtu = VGEN_LDC_MTU;		/* ldc mtu */
uint32_t vgen_txwd_interval = VGEN_TXWD_INTERVAL; /* watchdog freq in msec */
uint32_t vgen_txwd_timeout = VGEN_TXWD_TIMEOUT;   /* tx timeout in msec */

/*
 * Max # of channel resets allowed during handshake.
 */
uint32_t vgen_ldc_max_resets = 5;

/*
 * See comments in vsw.c for details on the dring modes supported.
 * In RxDringData mode, # of buffers is determined by multiplying the # of
 * descriptors with the factor below. Note that the factor must be > 1; i.e,
 * the # of buffers must always be > # of descriptors. This is needed because,
 * while the shared memory buffers are sent up the stack on the receiver, the
 * sender needs additional buffers that can be used for further transmits.
 * See vgen_create_rx_dring() for details.
 */
uint32_t vgen_nrbufs_factor = 2;

/*
 * Retry delay used while destroying rx mblk pools. Used in both Dring modes.
 */
int vgen_rxpool_cleanup_delay = 100000;	/* 100ms */

/*
 * Delay when rx descr not ready; used in TxDring mode only.
 */
uint32_t vgen_recv_delay = 1;

/*
 * Retry when rx descr not ready; used in TxDring mode only.
 */
uint32_t vgen_recv_retries = 10;

/*
 * Max # of packets accumulated prior to sending them up. It is best
 * to keep this at 60% of the number of receive buffers. Used in TxDring mode
 * by the msg worker thread. Used in RxDringData mode while in interrupt mode
 * (not used in polled mode).
 */
uint32_t vgen_chain_len = (VGEN_NRBUFS * 0.6);

/*
 * Internal tunables for receive buffer pools, that is,  the size and number of
 * mblks for each pool. At least 3 sizes must be specified if these are used.
 * The sizes must be specified in increasing order. Non-zero value of the first
 * size will be used as a hint to use these values instead of the algorithm
 * that determines the sizes based on MTU. Used in TxDring mode only.
 */
uint32_t vgen_rbufsz1 = 0;
uint32_t vgen_rbufsz2 = 0;
uint32_t vgen_rbufsz3 = 0;
uint32_t vgen_rbufsz4 = 0;

uint32_t vgen_nrbufs1 = VGEN_NRBUFS;
uint32_t vgen_nrbufs2 = VGEN_NRBUFS;
uint32_t vgen_nrbufs3 = VGEN_NRBUFS;
uint32_t vgen_nrbufs4 = VGEN_NRBUFS;

/*
 * In the absence of "priority-ether-types" property in MD, the following
 * internal tunable can be set to specify a single priority ethertype.
 */
uint64_t vgen_pri_eth_type = 0;

/*
 * Number of transmit priority buffers that are preallocated per device.
 * This number is chosen to be a small value to throttle transmission
 * of priority packets. Note: Must be a power of 2 for vio_create_mblks().
 */
uint32_t vgen_pri_tx_nmblks = 64;

uint32_t	vgen_vlan_nchains = 4;	/* # of chains in vlan id hash table */

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to 'virtual-device' nodes (i.e. vnet nodes) identified
 * by their 'name' and 'cfg-handle' properties.
 */
static md_prop_match_t vdev_prop_match[] = {
	{ MDET_PROP_STR,    "name"   },
	{ MDET_PROP_VAL,    "cfg-handle" },
	{ MDET_LIST_END,    NULL    }
};

static mdeg_node_match_t vdev_match = { "virtual-device",
						vdev_prop_match };

/* MD update matching structure */
static md_prop_match_t	vport_prop_match[] = {
	{ MDET_PROP_VAL,	"id" },
	{ MDET_LIST_END,	NULL }
};

static mdeg_node_match_t vport_match = { "virtual-device-port",
					vport_prop_match };

/* Template for matching a particular vnet instance */
static mdeg_prop_spec_t vgen_prop_template[] = {
	{ MDET_PROP_STR,	"name",		"network" },
	{ MDET_PROP_VAL,	"cfg-handle",	NULL },
	{ MDET_LIST_END,	NULL,		NULL }
};

#define	VGEN_SET_MDEG_PROP_INST(specp, val)	(specp)[1].ps_val = (val)

static int vgen_mdeg_port_cb(void *cb_argp, mdeg_result_t *resp);

#ifdef	VNET_IOC_DEBUG
#define	VGEN_M_CALLBACK_FLAGS	(MC_IOCTL)
#else
#define	VGEN_M_CALLBACK_FLAGS	(0)
#endif

static mac_callbacks_t vgen_m_callbacks = {
	VGEN_M_CALLBACK_FLAGS,
	vgen_stat,
	vgen_start,
	vgen_stop,
	vgen_promisc,
	vgen_multicst,
	vgen_unicst,
	vgen_tx,
	NULL,
	vgen_ioctl,
	NULL,
	NULL
};

/* Externs */
extern pri_t	maxclsyspri;
extern proc_t	p0;
extern uint32_t	vnet_ethermtu;
extern uint16_t	vnet_default_vlan_id;
extern uint32_t vnet_num_descriptors;

#ifdef DEBUG

#define	DEBUG_PRINTF	vgen_debug_printf

extern int vnet_dbglevel;

void vgen_debug_printf(const char *fname, vgen_t *vgenp,
	vgen_ldc_t *ldcp, const char *fmt, ...);

/* -1 for all LDCs info, or ldc_id for a specific LDC info */
int vgendbg_ldcid = -1;

/* Flags to simulate error conditions for debugging */
int vgen_inject_err_flag = 0;


boolean_t
vgen_inject_error(vgen_ldc_t *ldcp, int error)
{
	if ((vgendbg_ldcid == ldcp->ldc_id) &&
	    (vgen_inject_err_flag & error)) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

#endif

/*
 * vgen_init() is called by an instance of vnet driver to initialize the
 * corresponding generic transport layer. This layer uses Logical Domain
 * Channels (LDCs) to communicate with the virtual switch in the service domain
 * and also with peer vnets in other guest domains in the system.
 *
 * Arguments:
 *   vnetp:   an opaque pointer to the vnet instance
 *   regprop: frame to be transmitted
 *   vnetdip: dip of the vnet device
 *   macaddr: mac address of the vnet device
 *
 * Returns:
 *	Sucess:  a handle to the vgen instance (vgen_t)
 *	Failure: NULL
 */
int
vgen_init(void *vnetp, uint64_t regprop, dev_info_t *vnetdip,
    const uint8_t *macaddr, void **vgenhdl)
{
	vgen_t	*vgenp;
	int	instance;
	int	rv;
	char	qname[TASKQ_NAMELEN];

	if ((vnetp == NULL) || (vnetdip == NULL))
		return (DDI_FAILURE);

	instance = ddi_get_instance(vnetdip);

	DBG1(NULL, NULL, "vnet(%d): enter\n", instance);

	vgenp = kmem_zalloc(sizeof (vgen_t), KM_SLEEP);

	vgenp->vnetp = vnetp;
	vgenp->instance = instance;
	vgenp->regprop = regprop;
	vgenp->vnetdip = vnetdip;
	bcopy(macaddr, &(vgenp->macaddr), ETHERADDRL);
	vgenp->phys_link_state = LINK_STATE_UNKNOWN;

	/* allocate multicast table */
	vgenp->mctab = kmem_zalloc(VGEN_INIT_MCTAB_SIZE *
	    sizeof (struct ether_addr), KM_SLEEP);
	vgenp->mccount = 0;
	vgenp->mcsize = VGEN_INIT_MCTAB_SIZE;

	mutex_init(&vgenp->lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&vgenp->vgenports.rwlock, NULL, RW_DRIVER, NULL);

	(void) snprintf(qname, TASKQ_NAMELEN, "rxpool_taskq%d",
	    instance);
	if ((vgenp->rxp_taskq = ddi_taskq_create(vnetdip, qname, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "!vnet%d: Unable to create rx pool task queue",
		    instance);
		goto vgen_init_fail;
	}

	rv = vgen_read_mdprops(vgenp);
	if (rv != 0) {
		goto vgen_init_fail;
	}
	*vgenhdl = (void *)vgenp;

	DBG1(NULL, NULL, "vnet(%d): exit\n", instance);
	return (DDI_SUCCESS);

vgen_init_fail:
	rw_destroy(&vgenp->vgenports.rwlock);
	mutex_destroy(&vgenp->lock);
	kmem_free(vgenp->mctab, VGEN_INIT_MCTAB_SIZE *
	    sizeof (struct ether_addr));
	if (VGEN_PRI_ETH_DEFINED(vgenp)) {
		kmem_free(vgenp->pri_types,
		    sizeof (uint16_t) * vgenp->pri_num_types);
		(void) vio_destroy_mblks(vgenp->pri_tx_vmp);
	}
	if (vgenp->rxp_taskq != NULL) {
		ddi_taskq_destroy(vgenp->rxp_taskq);
		vgenp->rxp_taskq = NULL;
	}
	KMEM_FREE(vgenp);
	return (DDI_FAILURE);
}

int
vgen_init_mdeg(void *arg)
{
	vgen_t	*vgenp = (vgen_t *)arg;

	/* register with MD event generator */
	return (vgen_mdeg_reg(vgenp));
}

/*
 * Called by vnet to undo the initializations done by vgen_init().
 * The handle provided by generic transport during vgen_init() is the argument.
 */
void
vgen_uninit(void *arg)
{
	vgen_t	*vgenp = (vgen_t *)arg;

	if (vgenp == NULL) {
		return;
	}

	DBG1(vgenp, NULL, "enter\n");

	/* Unregister with MD event generator */
	vgen_mdeg_unreg(vgenp);

	mutex_enter(&vgenp->lock);

	/*
	 * Detach all ports from the device; note that the device should have
	 * been unplumbed by this time (See vnet_unattach() for the sequence)
	 * and thus vgen_stop() has already been invoked on all the ports.
	 */
	vgen_detach_ports(vgenp);

	/*
	 * We now destroy the taskq used to clean up rx mblk pools that
	 * couldn't be destroyed when the ports/channels were detached.
	 * We implicitly wait for those tasks to complete in
	 * ddi_taskq_destroy().
	 */
	if (vgenp->rxp_taskq != NULL) {
		ddi_taskq_destroy(vgenp->rxp_taskq);
		vgenp->rxp_taskq = NULL;
	}

	/* Free multicast table */
	kmem_free(vgenp->mctab, vgenp->mcsize * sizeof (struct ether_addr));

	/* Free pri_types table */
	if (VGEN_PRI_ETH_DEFINED(vgenp)) {
		kmem_free(vgenp->pri_types,
		    sizeof (uint16_t) * vgenp->pri_num_types);
		(void) vio_destroy_mblks(vgenp->pri_tx_vmp);
	}

	mutex_exit(&vgenp->lock);
	rw_destroy(&vgenp->vgenports.rwlock);
	mutex_destroy(&vgenp->lock);

	DBG1(vgenp, NULL, "exit\n");
	KMEM_FREE(vgenp);
}

/* enable transmit/receive for the device */
int
vgen_start(void *arg)
{
	vgen_port_t	*portp = (vgen_port_t *)arg;
	vgen_t		*vgenp = portp->vgenp;

	DBG1(vgenp, NULL, "enter\n");
	mutex_enter(&portp->lock);
	vgen_port_init(portp);
	portp->flags |= VGEN_STARTED;
	mutex_exit(&portp->lock);
	DBG1(vgenp, NULL, "exit\n");

	return (DDI_SUCCESS);
}

/* stop transmit/receive */
void
vgen_stop(void *arg)
{
	vgen_port_t	*portp = (vgen_port_t *)arg;
	vgen_t		*vgenp = portp->vgenp;

	DBG1(vgenp, NULL, "enter\n");

	mutex_enter(&portp->lock);
	if (portp->flags & VGEN_STARTED) {
		vgen_port_uninit(portp);
		portp->flags &= ~(VGEN_STARTED);
	}
	mutex_exit(&portp->lock);
	DBG1(vgenp, NULL, "exit\n");

}

/* vgen transmit function */
static mblk_t *
vgen_tx(void *arg, mblk_t *mp)
{
	vgen_port_t	*portp;
	int		status;

	portp = (vgen_port_t *)arg;
	status = vgen_portsend(portp, mp);
	if (status != VGEN_SUCCESS) {
		/* failure */
		return (mp);
	}
	/* success */
	return (NULL);
}

/*
 * This function provides any necessary tagging/untagging of the frames
 * that are being transmitted over the port. It first verifies the vlan
 * membership of the destination(port) and drops the packet if the
 * destination doesn't belong to the given vlan.
 *
 * Arguments:
 *   portp:     port over which the frames should be transmitted
 *   mp:        frame to be transmitted
 *   is_tagged:
 *              B_TRUE: indicates frame header contains the vlan tag already.
 *              B_FALSE: indicates frame is untagged.
 *   vid:       vlan in which the frame should be transmitted.
 *
 * Returns:
 *              Sucess: frame(mblk_t *) after doing the necessary tag/untag.
 *              Failure: NULL
 */
static mblk_t *
vgen_vlan_frame_fixtag(vgen_port_t *portp, mblk_t *mp, boolean_t is_tagged,
    uint16_t vid)
{
	vgen_t		*vgenp;
	boolean_t	dst_tagged;
	int		rv;

	vgenp = portp->vgenp;

	/*
	 * If the packet is going to a vnet:
	 *   Check if the destination vnet is in the same vlan.
	 *   Check the frame header if tag or untag is needed.
	 *
	 * We do not check the above conditions if the packet is going to vsw:
	 *   vsw must be present implicitly in all the vlans that a vnet device
	 *   is configured into; even if vsw itself is not assigned to those
	 *   vlans as an interface. For instance, the packet might be destined
	 *   to another vnet(indirectly through vsw) or to an external host
	 *   which is in the same vlan as this vnet and vsw itself may not be
	 *   present in that vlan. Similarly packets going to vsw must be
	 *   always tagged(unless in the default-vlan) if not already tagged,
	 *   as we do not know the final destination. This is needed because
	 *   vsw must always invoke its switching function only after tagging
	 *   the packet; otherwise after switching function determines the
	 *   destination we cannot figure out if the destination belongs to the
	 *   the same vlan that the frame originated from and if it needs tag/
	 *   untag. Note that vsw will tag the packet itself when it receives
	 *   it over the channel from a client if needed. However, that is
	 *   needed only in the case of vlan unaware clients such as obp or
	 *   earlier versions of vnet.
	 *
	 */
	if (portp != vgenp->vsw_portp) {
		/*
		 * Packet going to a vnet. Check if the destination vnet is in
		 * the same vlan. Then check the frame header if tag/untag is
		 * needed.
		 */
		rv = vgen_vlan_lookup(portp->vlan_hashp, vid);
		if (rv == B_FALSE) {
			/* drop the packet */
			freemsg(mp);
			return (NULL);
		}

		/* is the destination tagged or untagged in this vlan? */
		(vid == portp->pvid) ? (dst_tagged = B_FALSE) :
		    (dst_tagged = B_TRUE);

		if (is_tagged == dst_tagged) {
			/* no tagging/untagging needed */
			return (mp);
		}

		if (is_tagged == B_TRUE) {
			/* frame is tagged; destination needs untagged */
			mp = vnet_vlan_remove_tag(mp);
			return (mp);
		}

		/* (is_tagged == B_FALSE): fallthru to tag tx packet: */
	}

	/*
	 * Packet going to a vnet needs tagging.
	 * OR
	 * If the packet is going to vsw, then it must be tagged in all cases:
	 * unknown unicast, broadcast/multicast or to vsw interface.
	 */

	if (is_tagged == B_FALSE) {
		mp = vnet_vlan_insert_tag(mp, vid);
	}

	return (mp);
}

/* transmit packets over the given port */
static int
vgen_portsend(vgen_port_t *portp, mblk_t *mp)
{
	vgen_ldc_t		*ldcp;
	int			status;
	int			rv = VGEN_SUCCESS;
	vgen_t			*vgenp;
	vnet_t			*vnetp;
	boolean_t		is_tagged;
	boolean_t		dec_refcnt = B_FALSE;
	uint16_t		vlan_id;
	struct ether_header	*ehp;

	if (portp == NULL) {
		return (VGEN_FAILURE);
	}

	vgenp = portp->vgenp;
	vnetp = vgenp->vnetp;

	if (portp->use_vsw_port) {
		(void) atomic_inc_32(&vgenp->vsw_port_refcnt);
		portp = portp->vgenp->vsw_portp;
		ASSERT(portp != NULL);
		dec_refcnt = B_TRUE;
	}

	/*
	 * Determine the vlan id that the frame belongs to.
	 */
	ehp = (struct ether_header *)mp->b_rptr;
	is_tagged = vgen_frame_lookup_vid(vnetp, ehp, &vlan_id);

	if (vlan_id == vnetp->default_vlan_id) {

		/* Frames in default vlan must be untagged */
		ASSERT(is_tagged == B_FALSE);

		/*
		 * If the destination is a vnet-port verify it belongs to the
		 * default vlan; otherwise drop the packet. We do not need
		 * this check for vsw-port, as it should implicitly belong to
		 * this vlan; see comments in vgen_vlan_frame_fixtag().
		 */
		if (portp != vgenp->vsw_portp &&
		    portp->pvid != vnetp->default_vlan_id) {
			freemsg(mp);
			goto portsend_ret;
		}

	} else {	/* frame not in default-vlan */

		mp = vgen_vlan_frame_fixtag(portp, mp, is_tagged, vlan_id);
		if (mp == NULL) {
			goto portsend_ret;
		}

	}

	ldcp = portp->ldcp;
	status = ldcp->tx(ldcp, mp);

	if (status != VGEN_TX_SUCCESS) {
		rv = VGEN_FAILURE;
	}

portsend_ret:
	if (dec_refcnt == B_TRUE) {
		(void) atomic_dec_32(&vgenp->vsw_port_refcnt);
	}
	return (rv);
}

/*
 * Wrapper function to transmit normal and/or priority frames over the channel.
 */
static int
vgen_ldcsend(void *arg, mblk_t *mp)
{
	vgen_ldc_t		*ldcp = (vgen_ldc_t *)arg;
	int			status;
	struct ether_header	*ehp;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	uint32_t		num_types;
	uint16_t		*types;
	int			i;

	ASSERT(VGEN_PRI_ETH_DEFINED(vgenp));

	num_types = vgenp->pri_num_types;
	types = vgenp->pri_types;
	ehp = (struct ether_header *)mp->b_rptr;

	for (i = 0; i < num_types; i++) {

		if (ehp->ether_type == types[i]) {
			/* priority frame, use pri tx function */
			vgen_ldcsend_pkt(ldcp, mp);
			return (VGEN_SUCCESS);
		}

	}

	if (ldcp->tx_dringdata == NULL) {
		freemsg(mp);
		return (VGEN_SUCCESS);
	}

	status  = ldcp->tx_dringdata(ldcp, mp);
	return (status);
}

/*
 * This function transmits the frame in the payload of a raw data
 * (VIO_PKT_DATA) message. Thus, it provides an Out-Of-Band path to
 * send special frames with high priorities, without going through
 * the normal data path which uses descriptor ring mechanism.
 */
static void
vgen_ldcsend_pkt(void *arg, mblk_t *mp)
{
	vgen_ldc_t		*ldcp = (vgen_ldc_t *)arg;
	vio_raw_data_msg_t	*pkt;
	mblk_t			*bp;
	mblk_t			*nmp = NULL;
	vio_mblk_t		*vmp;
	caddr_t			dst;
	uint32_t		mblksz;
	uint32_t		size;
	uint32_t		nbytes;
	int			rv;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t		*statsp = &ldcp->stats;

	/* drop the packet if ldc is not up or handshake is not done */
	if (ldcp->ldc_status != LDC_UP) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vgenp, ldcp, "status(%d), dropping packet\n",
		    ldcp->ldc_status);
		goto send_pkt_exit;
	}

	if (ldcp->hphase != VH_DONE) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vgenp, ldcp, "hphase(%x), dropping packet\n",
		    ldcp->hphase);
		goto send_pkt_exit;
	}

	size = msgsize(mp);

	/* frame size bigger than available payload len of raw data msg ? */
	if (size > (size_t)(ldcp->msglen - VIO_PKT_DATA_HDRSIZE)) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vgenp, ldcp, "invalid size(%d)\n", size);
		goto send_pkt_exit;
	}

	if (size < ETHERMIN)
		size = ETHERMIN;

	/* alloc space for a raw data message */
	vmp = vio_allocb(vgenp->pri_tx_vmp);
	if (vmp == NULL) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vgenp, ldcp, "vio_allocb failed\n");
		goto send_pkt_exit;
	} else {
		nmp = vmp->mp;
	}
	pkt = (vio_raw_data_msg_t *)nmp->b_rptr;

	/* copy frame into the payload of raw data message */
	dst = (caddr_t)pkt->data;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblksz = MBLKL(bp);
		bcopy(bp->b_rptr, dst, mblksz);
		dst += mblksz;
	}

	vmp->state = VIO_MBLK_HAS_DATA;

	/* setup the raw data msg */
	pkt->tag.vio_msgtype = VIO_TYPE_DATA;
	pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt->tag.vio_subtype_env = VIO_PKT_DATA;
	pkt->tag.vio_sid = ldcp->local_sid;
	nbytes = VIO_PKT_DATA_HDRSIZE + size;

	/* send the msg over ldc */
	rv = vgen_sendmsg(ldcp, (caddr_t)pkt, nbytes, B_FALSE);
	if (rv != VGEN_SUCCESS) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vgenp, ldcp, "Error sending priority frame\n");
		if (rv == ECONNRESET) {
			(void) vgen_handle_evt_reset(ldcp, VGEN_OTHER);
		}
		goto send_pkt_exit;
	}

	/* update stats */
	(void) atomic_inc_64(&statsp->tx_pri_packets);
	(void) atomic_add_64(&statsp->tx_pri_bytes, size);

send_pkt_exit:
	if (nmp != NULL)
		freemsg(nmp);
	freemsg(mp);
}

/*
 * enable/disable a multicast address
 * note that the cblock of the ldc channel connected to the vsw is used for
 * synchronization of the mctab.
 */
int
vgen_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	vgen_t			*vgenp;
	vnet_mcast_msg_t	mcastmsg;
	vio_msg_tag_t		*tagp;
	vgen_port_t		*portp;
	vgen_ldc_t		*ldcp;
	struct ether_addr	*addrp;
	int			rv = DDI_FAILURE;
	uint32_t		i;

	portp = (vgen_port_t *)arg;
	vgenp = portp->vgenp;

	if (portp->is_vsw_port != B_TRUE) {
		return (DDI_SUCCESS);
	}

	addrp = (struct ether_addr *)mca;
	tagp = &mcastmsg.tag;
	bzero(&mcastmsg, sizeof (mcastmsg));

	ldcp = portp->ldcp;
	if (ldcp == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&ldcp->cblock);

	if (ldcp->hphase == VH_DONE) {
		/*
		 * If handshake is done, send a msg to vsw to add/remove
		 * the multicast address. Otherwise, we just update this
		 * mcast address in our table and the table will be sync'd
		 * with vsw when handshake completes.
		 */
		tagp->vio_msgtype = VIO_TYPE_CTRL;
		tagp->vio_subtype = VIO_SUBTYPE_INFO;
		tagp->vio_subtype_env = VNET_MCAST_INFO;
		tagp->vio_sid = ldcp->local_sid;
		bcopy(mca, &(mcastmsg.mca), ETHERADDRL);
		mcastmsg.set = add;
		mcastmsg.count = 1;
		if (vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (mcastmsg),
		    B_FALSE) != VGEN_SUCCESS) {
			DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
			rv = DDI_FAILURE;
			goto vgen_mcast_exit;
		}
	}

	if (add) {

		/* expand multicast table if necessary */
		if (vgenp->mccount >= vgenp->mcsize) {
			struct ether_addr	*newtab;
			uint32_t		newsize;


			newsize = vgenp->mcsize * 2;

			newtab = kmem_zalloc(newsize *
			    sizeof (struct ether_addr), KM_NOSLEEP);
			if (newtab == NULL)
				goto vgen_mcast_exit;
			bcopy(vgenp->mctab, newtab, vgenp->mcsize *
			    sizeof (struct ether_addr));
			kmem_free(vgenp->mctab,
			    vgenp->mcsize * sizeof (struct ether_addr));

			vgenp->mctab = newtab;
			vgenp->mcsize = newsize;
		}

		/* add address to the table */
		vgenp->mctab[vgenp->mccount++] = *addrp;

	} else {

		/* delete address from the table */
		for (i = 0; i < vgenp->mccount; i++) {
			if (ether_cmp(addrp, &(vgenp->mctab[i])) == 0) {

				/*
				 * If there's more than one address in this
				 * table, delete the unwanted one by moving
				 * the last one in the list over top of it;
				 * otherwise, just remove it.
				 */
				if (vgenp->mccount > 1) {
					vgenp->mctab[i] =
					    vgenp->mctab[vgenp->mccount-1];
				}
				vgenp->mccount--;
				break;
			}
		}
	}

	rv = DDI_SUCCESS;

vgen_mcast_exit:

	mutex_exit(&ldcp->cblock);
	return (rv);
}

/* set or clear promiscuous mode on the device */
static int
vgen_promisc(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(arg, on))
	return (DDI_SUCCESS);
}

/* set the unicast mac address of the device */
static int
vgen_unicst(void *arg, const uint8_t *mca)
{
	_NOTE(ARGUNUSED(arg, mca))
	return (DDI_SUCCESS);
}

/* get device statistics */
int
vgen_stat(void *arg, uint_t stat, uint64_t *val)
{
	vgen_port_t	*portp = (vgen_port_t *)arg;

	*val = vgen_port_stat(portp, stat);
	return (0);
}

/* vgen internal functions */
/* detach all ports from the device */
static void
vgen_detach_ports(vgen_t *vgenp)
{
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	plistp = &(vgenp->vgenports);
	WRITE_ENTER(&plistp->rwlock);
	while ((portp = plistp->headp) != NULL) {
		vgen_port_detach(portp);
	}
	RW_EXIT(&plistp->rwlock);
}

/*
 * detach the given port.
 */
static void
vgen_port_detach(vgen_port_t *portp)
{
	vgen_t		*vgenp;
	int		port_num;

	vgenp = portp->vgenp;
	port_num = portp->port_num;

	DBG1(vgenp, NULL, "port(%d):enter\n", port_num);

	/*
	 * If this port is connected to the vswitch, then
	 * potentially there could be ports that may be using
	 * this port to transmit packets. To address this do
	 * the following:
	 *	- First set vgenp->vsw_portp to NULL, so that
	 *	  its not used after that.
	 *	- Then wait for the refcnt to go down to 0.
	 *	- Now we can safely detach this port.
	 */
	if (vgenp->vsw_portp == portp) {
		vgenp->vsw_portp = NULL;
		while (vgenp->vsw_port_refcnt > 0) {
			delay(drv_usectohz(vgen_tx_delay));
		}
		(void) atomic_swap_32(&vgenp->vsw_port_refcnt, 0);
	}

	if (portp->vhp != NULL) {
		vio_net_resource_unreg(portp->vhp);
		portp->vhp = NULL;
	}

	vgen_vlan_destroy_hash(portp);

	/* remove it from port list */
	vgen_port_list_remove(portp);

	/* detach channels from this port */
	vgen_ldc_detach(portp->ldcp);

	if (portp->num_ldcs != 0) {
		kmem_free(portp->ldc_ids, portp->num_ldcs * sizeof (uint64_t));
		portp->num_ldcs = 0;
	}

	mutex_destroy(&portp->lock);
	KMEM_FREE(portp);

	DBG1(vgenp, NULL, "port(%d):exit\n", port_num);
}

/* add a port to port list */
static void
vgen_port_list_insert(vgen_port_t *portp)
{
	vgen_portlist_t	*plistp;
	vgen_t		*vgenp;

	vgenp = portp->vgenp;
	plistp = &(vgenp->vgenports);

	if (plistp->headp == NULL) {
		plistp->headp = portp;
	} else {
		plistp->tailp->nextp = portp;
	}
	plistp->tailp = portp;
	portp->nextp = NULL;
}

/* remove a port from port list */
static void
vgen_port_list_remove(vgen_port_t *portp)
{
	vgen_port_t	*prevp;
	vgen_port_t	*nextp;
	vgen_portlist_t	*plistp;
	vgen_t		*vgenp;

	vgenp = portp->vgenp;

	plistp = &(vgenp->vgenports);

	if (plistp->headp == NULL)
		return;

	if (portp == plistp->headp) {
		plistp->headp = portp->nextp;
		if (portp == plistp->tailp)
			plistp->tailp = plistp->headp;
	} else {
		for (prevp = plistp->headp;
		    ((nextp = prevp->nextp) != NULL) && (nextp != portp);
		    prevp = nextp)
			;
		if (nextp == portp) {
			prevp->nextp = portp->nextp;
		}
		if (portp == plistp->tailp)
			plistp->tailp = prevp;
	}
}

/* lookup a port in the list based on port_num */
static vgen_port_t *
vgen_port_lookup(vgen_portlist_t *plistp, int port_num)
{
	vgen_port_t *portp = NULL;

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {
		if (portp->port_num == port_num) {
			break;
		}
	}

	return (portp);
}

static void
vgen_port_init(vgen_port_t *portp)
{
	/* Add the port to the specified vlans */
	vgen_vlan_add_ids(portp);

	/* Bring up the channel */
	(void) vgen_ldc_init(portp->ldcp);
}

static void
vgen_port_uninit(vgen_port_t *portp)
{
	vgen_ldc_uninit(portp->ldcp);

	/* remove the port from vlans it has been assigned to */
	vgen_vlan_remove_ids(portp);
}

/*
 * Scan the machine description for this instance of vnet
 * and read its properties. Called only from vgen_init().
 * Returns: 0 on success, 1 on failure.
 */
static int
vgen_read_mdprops(vgen_t *vgenp)
{
	vnet_t		*vnetp = vgenp->vnetp;
	md_t		*mdp = NULL;
	mde_cookie_t	rootnode;
	mde_cookie_t	*listp = NULL;
	uint64_t	cfgh;
	char		*name;
	int		rv = 1;
	int		num_nodes = 0;
	int		num_devs = 0;
	int		listsz = 0;
	int		i;

	if ((mdp = md_get_handle()) == NULL) {
		return (rv);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = (mde_cookie_t *)kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);

	/* search for all "virtual_device" nodes */
	num_devs = md_scan_dag(mdp, rootnode,
	    md_find_name(mdp, vdev_propname),
	    md_find_name(mdp, "fwd"), listp);
	if (num_devs <= 0) {
		goto vgen_readmd_exit;
	}

	/*
	 * Now loop through the list of virtual-devices looking for
	 * devices with name "network" and for each such device compare
	 * its instance with what we have from the 'reg' property to
	 * find the right node in MD and then read all its properties.
	 */
	for (i = 0; i < num_devs; i++) {

		if (md_get_prop_str(mdp, listp[i], "name", &name) != 0) {
			goto vgen_readmd_exit;
		}

		/* is this a "network" device? */
		if (strcmp(name, vnet_propname) != 0)
			continue;

		if (md_get_prop_val(mdp, listp[i], "cfg-handle", &cfgh) != 0) {
			goto vgen_readmd_exit;
		}

		/* is this the required instance of vnet? */
		if (vgenp->regprop != cfgh)
			continue;

		/*
		 * Read the 'linkprop' property to know if this vnet
		 * device should get physical link updates from vswitch.
		 */
		vgen_linkprop_read(vgenp, mdp, listp[i],
		    &vnetp->pls_update);

		/*
		 * Read the mtu. Note that we set the mtu of vnet device within
		 * this routine itself, after validating the range.
		 */
		vgen_mtu_read(vgenp, mdp, listp[i], &vnetp->mtu);
		if (vnetp->mtu < ETHERMTU || vnetp->mtu > VNET_MAX_MTU) {
			vnetp->mtu = ETHERMTU;
		}
		vgenp->max_frame_size = vnetp->mtu +
		    sizeof (struct ether_header) + VLAN_TAGSZ;

		/* read priority ether types */
		vgen_read_pri_eth_types(vgenp, mdp, listp[i]);

		/* read vlan id properties of this vnet instance */
		vgen_vlan_read_ids(vgenp, VGEN_LOCAL, mdp, listp[i],
		    &vnetp->pvid, &vnetp->vids, &vnetp->nvids,
		    &vnetp->default_vlan_id);

		rv = 0;
		break;
	}

vgen_readmd_exit:

	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);
	return (rv);
}

/*
 * Read vlan id properties of the given MD node.
 * Arguments:
 *   arg:          device argument(vnet device or a port)
 *   type:         type of arg; VGEN_LOCAL(vnet device) or VGEN_PEER(port)
 *   mdp:          machine description
 *   node:         md node cookie
 *
 * Returns:
 *   pvidp:        port-vlan-id of the node
 *   vidspp:       list of vlan-ids of the node
 *   nvidsp:       # of vlan-ids in the list
 *   default_idp:  default-vlan-id of the node(if node is vnet device)
 */
static void
vgen_vlan_read_ids(void *arg, int type, md_t *mdp, mde_cookie_t node,
    uint16_t *pvidp, uint16_t **vidspp, uint16_t *nvidsp,
    uint16_t *default_idp)
{
	vgen_t		*vgenp;
	vnet_t		*vnetp;
	vgen_port_t	*portp;
	char		*pvid_propname;
	char		*vid_propname;
	uint_t		nvids;
	uint32_t	vids_size;
	int		rv;
	int		i;
	uint64_t	*data;
	uint64_t	val;
	int		size;
	int		inst;

	if (type == VGEN_LOCAL) {

		vgenp = (vgen_t *)arg;
		vnetp = vgenp->vnetp;
		pvid_propname = vgen_pvid_propname;
		vid_propname = vgen_vid_propname;
		inst = vnetp->instance;

	} else if (type == VGEN_PEER) {

		portp = (vgen_port_t *)arg;
		vgenp = portp->vgenp;
		vnetp = vgenp->vnetp;
		pvid_propname = port_pvid_propname;
		vid_propname = port_vid_propname;
		inst = portp->port_num;

	} else {
		return;
	}

	if (type == VGEN_LOCAL && default_idp != NULL) {
		rv = md_get_prop_val(mdp, node, vgen_dvid_propname, &val);
		if (rv != 0) {
			DWARN(vgenp, NULL, "prop(%s) not found",
			    vgen_dvid_propname);

			*default_idp = vnet_default_vlan_id;
		} else {
			*default_idp = val & 0xFFF;
			DBG2(vgenp, NULL, "%s(%d): (%d)\n", vgen_dvid_propname,
			    inst, *default_idp);
		}
	}

	rv = md_get_prop_val(mdp, node, pvid_propname, &val);
	if (rv != 0) {
		DWARN(vgenp, NULL, "prop(%s) not found", pvid_propname);
		*pvidp = vnet_default_vlan_id;
	} else {

		*pvidp = val & 0xFFF;
		DBG2(vgenp, NULL, "%s(%d): (%d)\n",
		    pvid_propname, inst, *pvidp);
	}

	rv = md_get_prop_data(mdp, node, vid_propname, (uint8_t **)&data,
	    &size);
	if (rv != 0) {
		DBG2(vgenp, NULL, "prop(%s) not found", vid_propname);
		size = 0;
	} else {
		size /= sizeof (uint64_t);
	}
	nvids = size;

	if (nvids != 0) {
		DBG2(vgenp, NULL, "%s(%d): ", vid_propname, inst);
		vids_size = sizeof (uint16_t) * nvids;
		*vidspp = kmem_zalloc(vids_size, KM_SLEEP);
		for (i = 0; i < nvids; i++) {
			(*vidspp)[i] = data[i] & 0xFFFF;
			DBG2(vgenp, NULL, " %d ", (*vidspp)[i]);
		}
		DBG2(vgenp, NULL, "\n");
	}

	*nvidsp = nvids;
}

/*
 * Create a vlan id hash table for the given port.
 */
static void
vgen_vlan_create_hash(vgen_port_t *portp)
{
	char		hashname[MAXNAMELEN];

	(void) snprintf(hashname, MAXNAMELEN, "port%d-vlan-hash",
	    portp->port_num);

	portp->vlan_nchains = vgen_vlan_nchains;
	portp->vlan_hashp = mod_hash_create_idhash(hashname,
	    portp->vlan_nchains, mod_hash_null_valdtor);
}

/*
 * Destroy the vlan id hash table in the given port.
 */
static void
vgen_vlan_destroy_hash(vgen_port_t *portp)
{
	if (portp->vlan_hashp != NULL) {
		mod_hash_destroy_hash(portp->vlan_hashp);
		portp->vlan_hashp = NULL;
		portp->vlan_nchains = 0;
	}
}

/*
 * Add a port to the vlans specified in its port properites.
 */
static void
vgen_vlan_add_ids(vgen_port_t *portp)
{
	int		rv;
	int		i;

	rv = mod_hash_insert(portp->vlan_hashp,
	    (mod_hash_key_t)VLAN_ID_KEY(portp->pvid),
	    (mod_hash_val_t)B_TRUE);
	ASSERT(rv == 0);

	for (i = 0; i < portp->nvids; i++) {
		rv = mod_hash_insert(portp->vlan_hashp,
		    (mod_hash_key_t)VLAN_ID_KEY(portp->vids[i]),
		    (mod_hash_val_t)B_TRUE);
		ASSERT(rv == 0);
	}
}

/*
 * Remove a port from the vlans it has been assigned to.
 */
static void
vgen_vlan_remove_ids(vgen_port_t *portp)
{
	int		rv;
	int		i;
	mod_hash_val_t	vp;

	rv = mod_hash_remove(portp->vlan_hashp,
	    (mod_hash_key_t)VLAN_ID_KEY(portp->pvid),
	    (mod_hash_val_t *)&vp);
	ASSERT(rv == 0);

	for (i = 0; i < portp->nvids; i++) {
		rv = mod_hash_remove(portp->vlan_hashp,
		    (mod_hash_key_t)VLAN_ID_KEY(portp->vids[i]),
		    (mod_hash_val_t *)&vp);
		ASSERT(rv == 0);
	}
}

/*
 * Lookup the vlan id of the given tx frame. If it is a vlan-tagged frame,
 * then the vlan-id is available in the tag; otherwise, its vlan id is
 * implicitly obtained from the port-vlan-id of the vnet device.
 * The vlan id determined is returned in vidp.
 * Returns: B_TRUE if it is a tagged frame; B_FALSE if it is untagged.
 */
static boolean_t
vgen_frame_lookup_vid(vnet_t *vnetp, struct ether_header *ehp, uint16_t *vidp)
{
	struct ether_vlan_header	*evhp;

	/* If it's a tagged frame, get the vlan id from vlan header */
	if (ehp->ether_type == ETHERTYPE_VLAN) {

		evhp = (struct ether_vlan_header *)ehp;
		*vidp = VLAN_ID(ntohs(evhp->ether_tci));
		return (B_TRUE);
	}

	/* Untagged frame, vlan-id is the pvid of vnet device */
	*vidp = vnetp->pvid;
	return (B_FALSE);
}

/*
 * Find the given vlan id in the hash table.
 * Return: B_TRUE if the id is found; B_FALSE if not found.
 */
static boolean_t
vgen_vlan_lookup(mod_hash_t *vlan_hashp, uint16_t vid)
{
	int		rv;
	mod_hash_val_t	vp;

	rv = mod_hash_find(vlan_hashp, VLAN_ID_KEY(vid), (mod_hash_val_t *)&vp);

	if (rv != 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * This function reads "priority-ether-types" property from md. This property
 * is used to enable support for priority frames. Applications which need
 * guaranteed and timely delivery of certain high priority frames to/from
 * a vnet or vsw within ldoms, should configure this property by providing
 * the ether type(s) for which the priority facility is needed.
 * Normal data frames are delivered over a ldc channel using the descriptor
 * ring mechanism which is constrained by factors such as descriptor ring size,
 * the rate at which the ring is processed at the peer ldc end point, etc.
 * The priority mechanism provides an Out-Of-Band path to send/receive frames
 * as raw pkt data (VIO_PKT_DATA) messages over the channel, avoiding the
 * descriptor ring path and enables a more reliable and timely delivery of
 * frames to the peer.
 */
static void
vgen_read_pri_eth_types(vgen_t *vgenp, md_t *mdp, mde_cookie_t node)
{
	int		rv;
	uint16_t	*types;
	uint64_t	*data;
	int		size;
	int		i;
	size_t		mblk_sz;

	rv = md_get_prop_data(mdp, node, pri_types_propname,
	    (uint8_t **)&data, &size);
	if (rv != 0) {
		/*
		 * Property may not exist if we are running pre-ldoms1.1 f/w.
		 * Check if 'vgen_pri_eth_type' has been set in that case.
		 */
		if (vgen_pri_eth_type != 0) {
			size = sizeof (vgen_pri_eth_type);
			data = &vgen_pri_eth_type;
		} else {
			DBG2(vgenp, NULL,
			    "prop(%s) not found", pri_types_propname);
			size = 0;
		}
	}

	if (size == 0) {
		vgenp->pri_num_types = 0;
		return;
	}

	/*
	 * we have some priority-ether-types defined;
	 * allocate a table of these types and also
	 * allocate a pool of mblks to transmit these
	 * priority packets.
	 */
	size /= sizeof (uint64_t);
	vgenp->pri_num_types = size;
	vgenp->pri_types = kmem_zalloc(size * sizeof (uint16_t), KM_SLEEP);
	for (i = 0, types = vgenp->pri_types; i < size; i++) {
		types[i] = data[i] & 0xFFFF;
	}
	mblk_sz = (VIO_PKT_DATA_HDRSIZE + vgenp->max_frame_size + 7) & ~7;
	(void) vio_create_mblks(vgen_pri_tx_nmblks, mblk_sz, NULL,
	    &vgenp->pri_tx_vmp);
}

static void
vgen_mtu_read(vgen_t *vgenp, md_t *mdp, mde_cookie_t node, uint32_t *mtu)
{
	int		rv;
	uint64_t	val;
	char		*mtu_propname;

	mtu_propname = vgen_mtu_propname;

	rv = md_get_prop_val(mdp, node, mtu_propname, &val);
	if (rv != 0) {
		DWARN(vgenp, NULL, "prop(%s) not found", mtu_propname);
		*mtu = vnet_ethermtu;
	} else {

		*mtu = val & 0xFFFF;
		DBG2(vgenp, NULL, "%s(%d): (%d)\n", mtu_propname,
		    vgenp->instance, *mtu);
	}
}

static void
vgen_linkprop_read(vgen_t *vgenp, md_t *mdp, mde_cookie_t node,
    boolean_t *pls)
{
	int		rv;
	uint64_t	val;
	char		*linkpropname;

	linkpropname = vgen_linkprop_propname;

	rv = md_get_prop_val(mdp, node, linkpropname, &val);
	if (rv != 0) {
		DWARN(vgenp, NULL, "prop(%s) not found", linkpropname);
		*pls = B_FALSE;
	} else {

		*pls = (val & 0x1) ?  B_TRUE : B_FALSE;
		DBG2(vgenp, NULL, "%s(%d): (%d)\n", linkpropname,
		    vgenp->instance, *pls);
	}
}

/* register with MD event generator */
static int
vgen_mdeg_reg(vgen_t *vgenp)
{
	mdeg_prop_spec_t	*pspecp;
	mdeg_node_spec_t	*parentp;
	uint_t			templatesz;
	int			rv;
	mdeg_handle_t		dev_hdl = 0;
	mdeg_handle_t		port_hdl = 0;

	templatesz = sizeof (vgen_prop_template);
	pspecp = kmem_zalloc(templatesz, KM_NOSLEEP);
	if (pspecp == NULL) {
		return (DDI_FAILURE);
	}
	parentp = kmem_zalloc(sizeof (mdeg_node_spec_t), KM_NOSLEEP);
	if (parentp == NULL) {
		kmem_free(pspecp, templatesz);
		return (DDI_FAILURE);
	}

	bcopy(vgen_prop_template, pspecp, templatesz);

	/*
	 * NOTE: The instance here refers to the value of "reg" property and
	 * not the dev_info instance (ddi_get_instance()) of vnet.
	 */
	VGEN_SET_MDEG_PROP_INST(pspecp, vgenp->regprop);

	parentp->namep = "virtual-device";
	parentp->specp = pspecp;

	/* save parentp in vgen_t */
	vgenp->mdeg_parentp = parentp;

	/*
	 * Register an interest in 'virtual-device' nodes with a
	 * 'name' property of 'network'
	 */
	rv = mdeg_register(parentp, &vdev_match, vgen_mdeg_cb, vgenp, &dev_hdl);
	if (rv != MDEG_SUCCESS) {
		DERR(vgenp, NULL, "mdeg_register failed\n");
		goto mdeg_reg_fail;
	}

	/* Register an interest in 'port' nodes */
	rv = mdeg_register(parentp, &vport_match, vgen_mdeg_port_cb, vgenp,
	    &port_hdl);
	if (rv != MDEG_SUCCESS) {
		DERR(vgenp, NULL, "mdeg_register failed\n");
		goto mdeg_reg_fail;
	}

	/* save mdeg handle in vgen_t */
	vgenp->mdeg_dev_hdl = dev_hdl;
	vgenp->mdeg_port_hdl = port_hdl;

	return (DDI_SUCCESS);

mdeg_reg_fail:
	if (dev_hdl != 0) {
		(void) mdeg_unregister(dev_hdl);
	}
	KMEM_FREE(parentp);
	kmem_free(pspecp, templatesz);
	vgenp->mdeg_parentp = NULL;
	return (DDI_FAILURE);
}

/* unregister with MD event generator */
static void
vgen_mdeg_unreg(vgen_t *vgenp)
{
	if (vgenp->mdeg_dev_hdl != 0) {
		(void) mdeg_unregister(vgenp->mdeg_dev_hdl);
		vgenp->mdeg_dev_hdl = 0;
	}
	if (vgenp->mdeg_port_hdl != 0) {
		(void) mdeg_unregister(vgenp->mdeg_port_hdl);
		vgenp->mdeg_port_hdl = 0;
	}

	if (vgenp->mdeg_parentp != NULL) {
		kmem_free(vgenp->mdeg_parentp->specp,
		    sizeof (vgen_prop_template));
		KMEM_FREE(vgenp->mdeg_parentp);
		vgenp->mdeg_parentp = NULL;
	}
}

/* mdeg callback function for the port node */
static int
vgen_mdeg_port_cb(void *cb_argp, mdeg_result_t *resp)
{
	int		idx;
	int		vsw_idx = -1;
	uint64_t	val;
	vgen_t		*vgenp;

	if ((resp == NULL) || (cb_argp == NULL)) {
		return (MDEG_FAILURE);
	}

	vgenp = (vgen_t *)cb_argp;
	DBG1(vgenp, NULL, "enter\n");

	mutex_enter(&vgenp->lock);

	DBG1(vgenp, NULL, "ports: removed(%x), "
	"added(%x), updated(%x)\n", resp->removed.nelem,
	    resp->added.nelem, resp->match_curr.nelem);

	for (idx = 0; idx < resp->removed.nelem; idx++) {
		(void) vgen_remove_port(vgenp, resp->removed.mdp,
		    resp->removed.mdep[idx]);
	}

	if (vgenp->vsw_portp == NULL) {
		/*
		 * find vsw_port and add it first, because other ports need
		 * this when adding fdb entry (see vgen_port_init()).
		 */
		for (idx = 0; idx < resp->added.nelem; idx++) {
			if (!(md_get_prop_val(resp->added.mdp,
			    resp->added.mdep[idx], swport_propname, &val))) {
				if (val == 0) {
					/*
					 * This port is connected to the
					 * vsw on service domain.
					 */
					vsw_idx = idx;
					if (vgen_add_port(vgenp,
					    resp->added.mdp,
					    resp->added.mdep[idx]) !=
					    DDI_SUCCESS) {
						cmn_err(CE_NOTE, "vnet%d Could "
						    "not initialize virtual "
						    "switch port.",
						    vgenp->instance);
						mutex_exit(&vgenp->lock);
						return (MDEG_FAILURE);
					}
					break;
				}
			}
		}
		if (vsw_idx == -1) {
			DWARN(vgenp, NULL, "can't find vsw_port\n");
			mutex_exit(&vgenp->lock);
			return (MDEG_FAILURE);
		}
	}

	for (idx = 0; idx < resp->added.nelem; idx++) {
		if ((vsw_idx != -1) && (vsw_idx == idx)) /* skip vsw_port */
			continue;

		/* If this port can't be added just skip it. */
		(void) vgen_add_port(vgenp, resp->added.mdp,
		    resp->added.mdep[idx]);
	}

	for (idx = 0; idx < resp->match_curr.nelem; idx++) {
		(void) vgen_update_port(vgenp, resp->match_curr.mdp,
		    resp->match_curr.mdep[idx],
		    resp->match_prev.mdp,
		    resp->match_prev.mdep[idx]);
	}

	mutex_exit(&vgenp->lock);
	DBG1(vgenp, NULL, "exit\n");
	return (MDEG_SUCCESS);
}

/* mdeg callback function for the vnet node */
static int
vgen_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	vgen_t		*vgenp;
	vnet_t		*vnetp;
	md_t		*mdp;
	mde_cookie_t	node;
	uint64_t	inst;
	char		*node_name = NULL;

	if ((resp == NULL) || (cb_argp == NULL)) {
		return (MDEG_FAILURE);
	}

	vgenp = (vgen_t *)cb_argp;
	vnetp = vgenp->vnetp;

	DBG1(vgenp, NULL, "added %d : removed %d : curr matched %d"
	    " : prev matched %d", resp->added.nelem, resp->removed.nelem,
	    resp->match_curr.nelem, resp->match_prev.nelem);

	mutex_enter(&vgenp->lock);

	/*
	 * We get an initial callback for this node as 'added' after
	 * registering with mdeg. Note that we would have already gathered
	 * information about this vnet node by walking MD earlier during attach
	 * (in vgen_read_mdprops()). So, there is a window where the properties
	 * of this node might have changed when we get this initial 'added'
	 * callback. We handle this as if an update occured and invoke the same
	 * function which handles updates to the properties of this vnet-node
	 * if any. A non-zero 'match' value indicates that the MD has been
	 * updated and that a 'network' node is present which may or may not
	 * have been updated. It is up to the clients to examine their own
	 * nodes and determine if they have changed.
	 */
	if (resp->added.nelem != 0) {

		if (resp->added.nelem != 1) {
			cmn_err(CE_NOTE, "!vnet%d: number of nodes added "
			    "invalid: %d\n", vnetp->instance,
			    resp->added.nelem);
			goto vgen_mdeg_cb_err;
		}

		mdp = resp->added.mdp;
		node = resp->added.mdep[0];

	} else if (resp->match_curr.nelem != 0) {

		if (resp->match_curr.nelem != 1) {
			cmn_err(CE_NOTE, "!vnet%d: number of nodes updated "
			    "invalid: %d\n", vnetp->instance,
			    resp->match_curr.nelem);
			goto vgen_mdeg_cb_err;
		}

		mdp = resp->match_curr.mdp;
		node = resp->match_curr.mdep[0];

	} else {
		goto vgen_mdeg_cb_err;
	}

	/* Validate name and instance */
	if (md_get_prop_str(mdp, node, "name", &node_name) != 0) {
		DERR(vgenp, NULL, "unable to get node name\n");
		goto vgen_mdeg_cb_err;
	}

	/* is this a virtual-network device? */
	if (strcmp(node_name, vnet_propname) != 0) {
		DERR(vgenp, NULL, "%s: Invalid node name: %s\n", node_name);
		goto vgen_mdeg_cb_err;
	}

	if (md_get_prop_val(mdp, node, "cfg-handle", &inst)) {
		DERR(vgenp, NULL, "prop(cfg-handle) not found\n");
		goto vgen_mdeg_cb_err;
	}

	/* is this the right instance of vnet? */
	if (inst != vgenp->regprop) {
		DERR(vgenp, NULL,  "Invalid cfg-handle: %lx\n", inst);
		goto vgen_mdeg_cb_err;
	}

	vgen_update_md_prop(vgenp, mdp, node);

	mutex_exit(&vgenp->lock);
	return (MDEG_SUCCESS);

vgen_mdeg_cb_err:
	mutex_exit(&vgenp->lock);
	return (MDEG_FAILURE);
}

/*
 * Check to see if the relevant properties in the specified node have
 * changed, and if so take the appropriate action.
 */
static void
vgen_update_md_prop(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex)
{
	uint16_t	pvid;
	uint16_t	*vids;
	uint16_t	nvids;
	vnet_t		*vnetp = vgenp->vnetp;
	uint32_t	mtu;
	boolean_t	pls_update;
	enum		{ MD_init = 0x1,
			    MD_vlans = 0x2,
			    MD_mtu = 0x4,
			    MD_pls = 0x8 } updated;
	int		rv;

	updated = MD_init;

	/* Read the vlan ids */
	vgen_vlan_read_ids(vgenp, VGEN_LOCAL, mdp, mdex, &pvid, &vids,
	    &nvids, NULL);

	/* Determine if there are any vlan id updates */
	if ((pvid != vnetp->pvid) ||		/* pvid changed? */
	    (nvids != vnetp->nvids) ||		/* # of vids changed? */
	    ((nvids != 0) && (vnetp->nvids != 0) &&	/* vids changed? */
	    bcmp(vids, vnetp->vids, sizeof (uint16_t) * nvids))) {
		updated |= MD_vlans;
	}

	/* Read mtu */
	vgen_mtu_read(vgenp, mdp, mdex, &mtu);
	if (mtu != vnetp->mtu) {
		if (mtu >= ETHERMTU && mtu <= VNET_MAX_MTU) {
			updated |= MD_mtu;
		} else {
			cmn_err(CE_NOTE, "!vnet%d: Unable to process mtu update"
			    " as the specified value:%d is invalid\n",
			    vnetp->instance, mtu);
		}
	}

	/*
	 * Read the 'linkprop' property.
	 */
	vgen_linkprop_read(vgenp, mdp, mdex, &pls_update);
	if (pls_update != vnetp->pls_update) {
		updated |= MD_pls;
	}

	/* Now process the updated props */

	if (updated & MD_vlans) {

		/* save the new vlan ids */
		vnetp->pvid = pvid;
		if (vnetp->nvids != 0) {
			kmem_free(vnetp->vids,
			    sizeof (uint16_t) * vnetp->nvids);
			vnetp->nvids = 0;
		}
		if (nvids != 0) {
			vnetp->nvids = nvids;
			vnetp->vids = vids;
		}

		/* reset vlan-unaware peers (ver < 1.3) and restart handshake */
		vgen_reset_vlan_unaware_ports(vgenp);

	} else {

		if (nvids != 0) {
			kmem_free(vids, sizeof (uint16_t) * nvids);
		}
	}

	if (updated & MD_mtu) {

		DBG2(vgenp, NULL, "curr_mtu(%d) new_mtu(%d)\n",
		    vnetp->mtu, mtu);

		rv = vnet_mtu_update(vnetp, mtu);
		if (rv == 0) {
			vgenp->max_frame_size = mtu +
			    sizeof (struct ether_header) + VLAN_TAGSZ;
		}
	}

	if (updated & MD_pls) {
		/* enable/disable physical link state updates */
		vnetp->pls_update = pls_update;
		mutex_exit(&vgenp->lock);

		/* reset vsw-port to re-negotiate with the updated prop. */
		vgen_reset_vsw_port(vgenp);

		mutex_enter(&vgenp->lock);
	}
}

/* add a new port to the device */
static int
vgen_add_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex)
{
	vgen_port_t	*portp;
	int		rv;

	portp = kmem_zalloc(sizeof (vgen_port_t), KM_SLEEP);

	rv = vgen_port_read_props(portp, vgenp, mdp, mdex);
	if (rv != DDI_SUCCESS) {
		KMEM_FREE(portp);
		return (DDI_FAILURE);
	}

	rv = vgen_port_attach(portp);
	if (rv != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/* read properties of the port from its md node */
static int
vgen_port_read_props(vgen_port_t *portp, vgen_t *vgenp, md_t *mdp,
    mde_cookie_t mdex)
{
	uint64_t		port_num;
	uint64_t		*ldc_ids;
	uint64_t		macaddr;
	uint64_t		val;
	int			num_ldcs;
	int			i;
	int			addrsz;
	int			num_nodes = 0;
	int			listsz = 0;
	mde_cookie_t		*listp = NULL;
	uint8_t			*addrp;
	struct ether_addr	ea;

	/* read "id" property to get the port number */
	if (md_get_prop_val(mdp, mdex, id_propname, &port_num)) {
		DWARN(vgenp, NULL, "prop(%s) not found\n", id_propname);
		return (DDI_FAILURE);
	}

	/*
	 * Find the channel endpoint node(s) under this port node.
	 */
	if ((num_nodes = md_node_count(mdp)) <= 0) {
		DWARN(vgenp, NULL, "invalid number of nodes found (%d)",
		    num_nodes);
		return (DDI_FAILURE);
	}

	/* allocate space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_NOSLEEP);
	if (listp == NULL)
		return (DDI_FAILURE);

	num_ldcs = md_scan_dag(mdp, mdex,
	    md_find_name(mdp, channel_propname),
	    md_find_name(mdp, "fwd"), listp);

	if (num_ldcs <= 0) {
		DWARN(vgenp, NULL, "can't find %s nodes", channel_propname);
		kmem_free(listp, listsz);
		return (DDI_FAILURE);
	}

	if (num_ldcs > 1) {
		DWARN(vgenp, NULL, "Port %d: Number of channels %d > 1\n",
		    port_num, num_ldcs);
	}

	ldc_ids = kmem_zalloc(num_ldcs * sizeof (uint64_t), KM_NOSLEEP);
	if (ldc_ids == NULL) {
		kmem_free(listp, listsz);
		return (DDI_FAILURE);
	}

	for (i = 0; i < num_ldcs; i++) {
		/* read channel ids */
		if (md_get_prop_val(mdp, listp[i], id_propname, &ldc_ids[i])) {
			DWARN(vgenp, NULL, "prop(%s) not found\n",
			    id_propname);
			kmem_free(listp, listsz);
			kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
			return (DDI_FAILURE);
		}
		DBG2(vgenp, NULL, "ldc_id 0x%llx", ldc_ids[i]);
	}

	kmem_free(listp, listsz);

	if (md_get_prop_data(mdp, mdex, rmacaddr_propname, &addrp,
	    &addrsz)) {
		DWARN(vgenp, NULL, "prop(%s) not found\n", rmacaddr_propname);
		kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
		return (DDI_FAILURE);
	}

	if (addrsz < ETHERADDRL) {
		DWARN(vgenp, NULL, "invalid address size (%d)\n", addrsz);
		kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));
		return (DDI_FAILURE);
	}

	macaddr = *((uint64_t *)addrp);

	DBG2(vgenp, NULL, "remote mac address 0x%llx\n", macaddr);

	for (i = ETHERADDRL - 1; i >= 0; i--) {
		ea.ether_addr_octet[i] = macaddr & 0xFF;
		macaddr >>= 8;
	}

	if (!(md_get_prop_val(mdp, mdex, swport_propname, &val))) {
		if (val == 0) {
			/* This port is connected to the vswitch */
			portp->is_vsw_port = B_TRUE;
		} else {
			portp->is_vsw_port = B_FALSE;
		}
	}

	/* now update all properties into the port */
	portp->vgenp = vgenp;
	portp->port_num = port_num;
	ether_copy(&ea, &portp->macaddr);
	portp->ldc_ids = kmem_zalloc(sizeof (uint64_t) * num_ldcs, KM_SLEEP);
	bcopy(ldc_ids, portp->ldc_ids, sizeof (uint64_t) * num_ldcs);
	portp->num_ldcs = num_ldcs;

	/* read vlan id properties of this port node */
	vgen_vlan_read_ids(portp, VGEN_PEER, mdp, mdex, &portp->pvid,
	    &portp->vids, &portp->nvids, NULL);

	kmem_free(ldc_ids, num_ldcs * sizeof (uint64_t));

	return (DDI_SUCCESS);
}

/* remove a port from the device */
static int
vgen_remove_port(vgen_t *vgenp, md_t *mdp, mde_cookie_t mdex)
{
	uint64_t	port_num;
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	/* read "id" property to get the port number */
	if (md_get_prop_val(mdp, mdex, id_propname, &port_num)) {
		DWARN(vgenp, NULL, "prop(%s) not found\n", id_propname);
		return (DDI_FAILURE);
	}

	plistp = &(vgenp->vgenports);

	WRITE_ENTER(&plistp->rwlock);
	portp = vgen_port_lookup(plistp, (int)port_num);
	if (portp == NULL) {
		DWARN(vgenp, NULL, "can't find port(%lx)\n", port_num);
		RW_EXIT(&plistp->rwlock);
		return (DDI_FAILURE);
	}

	vgen_port_detach_mdeg(portp);
	RW_EXIT(&plistp->rwlock);

	return (DDI_SUCCESS);
}

/* attach a port to the device based on mdeg data */
static int
vgen_port_attach(vgen_port_t *portp)
{
	vgen_portlist_t		*plistp;
	vgen_t			*vgenp;
	uint64_t		*ldcids;
	mac_register_t		*macp;
	vio_net_res_type_t	type;
	int			rv;

	ASSERT(portp != NULL);
	vgenp = portp->vgenp;
	ldcids = portp->ldc_ids;

	DBG2(vgenp, NULL, "port_num(%d), ldcid(%lx)\n",
	    portp->port_num, ldcids[0]);

	mutex_init(&portp->lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * attach the channel under the port using its channel id;
	 * note that we only support one channel per port for now.
	 */
	if (vgen_ldc_attach(portp, ldcids[0]) == DDI_FAILURE) {
		vgen_port_detach(portp);
		return (DDI_FAILURE);
	}

	/* create vlan id hash table */
	vgen_vlan_create_hash(portp);

	if (portp->is_vsw_port == B_TRUE) {
		/* This port is connected to the switch port */
		(void) atomic_swap_32(&portp->use_vsw_port, B_FALSE);
		type = VIO_NET_RES_LDC_SERVICE;
	} else {
		(void) atomic_swap_32(&portp->use_vsw_port, B_TRUE);
		type = VIO_NET_RES_LDC_GUEST;
	}

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		vgen_port_detach(portp);
		return (DDI_FAILURE);
	}
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = portp;
	macp->m_dip = vgenp->vnetdip;
	macp->m_src_addr = (uint8_t *)&(vgenp->macaddr);
	macp->m_callbacks = &vgen_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;

	mutex_enter(&portp->lock);
	rv = vio_net_resource_reg(macp, type, vgenp->macaddr,
	    portp->macaddr, &portp->vhp, &portp->vcb);
	mutex_exit(&portp->lock);
	mac_free(macp);

	if (rv == 0) {
		/* link it into the list of ports */
		plistp = &(vgenp->vgenports);
		WRITE_ENTER(&plistp->rwlock);
		vgen_port_list_insert(portp);
		RW_EXIT(&plistp->rwlock);

		if (portp->is_vsw_port == B_TRUE) {
			/* We now have the vswitch port attached */
			vgenp->vsw_portp = portp;
			(void) atomic_swap_32(&vgenp->vsw_port_refcnt, 0);
		}
	} else {
		DERR(vgenp, NULL, "vio_net_resource_reg failed for portp=0x%p",
		    portp);
		vgen_port_detach(portp);
	}

	DBG1(vgenp, NULL, "exit: port_num(%d)\n", portp->port_num);
	return (DDI_SUCCESS);
}

/* detach a port from the device based on mdeg data */
static void
vgen_port_detach_mdeg(vgen_port_t *portp)
{
	vgen_t *vgenp = portp->vgenp;

	DBG1(vgenp, NULL, "enter: port_num(%d)\n", portp->port_num);

	mutex_enter(&portp->lock);

	/* stop the port if needed */
	if (portp->flags & VGEN_STARTED) {
		vgen_port_uninit(portp);
		portp->flags &= ~(VGEN_STARTED);
	}

	mutex_exit(&portp->lock);
	vgen_port_detach(portp);

	DBG1(vgenp, NULL, "exit: port_num(%d)\n", portp->port_num);
}

static int
vgen_update_port(vgen_t *vgenp, md_t *curr_mdp, mde_cookie_t curr_mdex,
    md_t *prev_mdp, mde_cookie_t prev_mdex)
{
	uint64_t	cport_num;
	uint64_t	pport_num;
	vgen_portlist_t	*plistp;
	vgen_port_t	*portp;
	boolean_t	updated_vlans = B_FALSE;
	uint16_t	pvid;
	uint16_t	*vids;
	uint16_t	nvids;

	/*
	 * For now, we get port updates only if vlan ids changed.
	 * We read the port num and do some sanity check.
	 */
	if (md_get_prop_val(curr_mdp, curr_mdex, id_propname, &cport_num)) {
		DWARN(vgenp, NULL, "prop(%s) not found\n", id_propname);
		return (DDI_FAILURE);
	}

	if (md_get_prop_val(prev_mdp, prev_mdex, id_propname, &pport_num)) {
		DWARN(vgenp, NULL, "prop(%s) not found\n", id_propname);
		return (DDI_FAILURE);
	}
	if (cport_num != pport_num)
		return (DDI_FAILURE);

	plistp = &(vgenp->vgenports);

	READ_ENTER(&plistp->rwlock);

	portp = vgen_port_lookup(plistp, (int)cport_num);
	if (portp == NULL) {
		DWARN(vgenp, NULL, "can't find port(%lx)\n", cport_num);
		RW_EXIT(&plistp->rwlock);
		return (DDI_FAILURE);
	}

	/* Read the vlan ids */
	vgen_vlan_read_ids(portp, VGEN_PEER, curr_mdp, curr_mdex, &pvid, &vids,
	    &nvids, NULL);

	/* Determine if there are any vlan id updates */
	if ((pvid != portp->pvid) ||		/* pvid changed? */
	    (nvids != portp->nvids) ||		/* # of vids changed? */
	    ((nvids != 0) && (portp->nvids != 0) &&	/* vids changed? */
	    bcmp(vids, portp->vids, sizeof (uint16_t) * nvids))) {
		updated_vlans = B_TRUE;
	}

	if (updated_vlans == B_FALSE) {
		RW_EXIT(&plistp->rwlock);
		return (DDI_FAILURE);
	}

	/* remove the port from vlans it has been assigned to */
	vgen_vlan_remove_ids(portp);

	/* save the new vlan ids */
	portp->pvid = pvid;
	if (portp->nvids != 0) {
		kmem_free(portp->vids, sizeof (uint16_t) * portp->nvids);
		portp->nvids = 0;
	}
	if (nvids != 0) {
		portp->vids = kmem_zalloc(sizeof (uint16_t) * nvids, KM_SLEEP);
		bcopy(vids, portp->vids, sizeof (uint16_t) * nvids);
		portp->nvids = nvids;
		kmem_free(vids, sizeof (uint16_t) * nvids);
	}

	/* add port to the new vlans */
	vgen_vlan_add_ids(portp);

	/* reset the port if it is vlan unaware (ver < 1.3) */
	vgen_vlan_unaware_port_reset(portp);

	RW_EXIT(&plistp->rwlock);

	return (DDI_SUCCESS);
}

static uint64_t
vgen_port_stat(vgen_port_t *portp, uint_t stat)
{
	return (vgen_ldc_stat(portp->ldcp, stat));
}

/* attach the channel corresponding to the given ldc_id to the port */
static int
vgen_ldc_attach(vgen_port_t *portp, uint64_t ldc_id)
{
	vgen_t		*vgenp;
	vgen_ldc_t	*ldcp;
	ldc_attr_t	attr;
	int		status;
	ldc_status_t	istatus;
	char		kname[MAXNAMELEN];
	int		instance;
	enum	{AST_init = 0x0, AST_ldc_alloc = 0x1,
		AST_mutex_init = 0x2, AST_ldc_init = 0x4,
		AST_ldc_reg_cb = 0x8 } attach_state;

	attach_state = AST_init;
	vgenp = portp->vgenp;

	ldcp = kmem_zalloc(sizeof (vgen_ldc_t), KM_NOSLEEP);
	if (ldcp == NULL) {
		goto ldc_attach_failed;
	}
	ldcp->ldc_id = ldc_id;
	ldcp->portp = portp;

	attach_state |= AST_ldc_alloc;

	mutex_init(&ldcp->txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->cblock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->tclock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->wrlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->rxlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->pollq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->msg_thr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->msg_thr_cv, NULL, CV_DRIVER, NULL);

	attach_state |= AST_mutex_init;

	attr.devclass = LDC_DEV_NT;
	attr.instance = vgenp->instance;
	attr.mode = LDC_MODE_UNRELIABLE;
	attr.mtu = vgen_ldc_mtu;
	status = ldc_init(ldc_id, &attr, &ldcp->ldc_handle);
	if (status != 0) {
		DWARN(vgenp, ldcp, "ldc_init failed,rv (%d)\n", status);
		goto ldc_attach_failed;
	}
	attach_state |= AST_ldc_init;

	status = ldc_reg_callback(ldcp->ldc_handle, vgen_ldc_cb, (caddr_t)ldcp);
	if (status != 0) {
		DWARN(vgenp, ldcp, "ldc_reg_callback failed, rv (%d)\n",
		    status);
		goto ldc_attach_failed;
	}
	/*
	 * allocate a message for ldc_read()s, big enough to hold ctrl and
	 * data msgs, including raw data msgs used to recv priority frames.
	 */
	ldcp->msglen = VIO_PKT_DATA_HDRSIZE + vgenp->max_frame_size;
	ldcp->ldcmsg = kmem_alloc(ldcp->msglen, KM_SLEEP);
	attach_state |= AST_ldc_reg_cb;

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	ASSERT(istatus == LDC_INIT);
	ldcp->ldc_status = istatus;

	/* Setup kstats for the channel */
	instance = vgenp->instance;
	(void) sprintf(kname, "vnetldc0x%lx", ldcp->ldc_id);
	ldcp->ksp = vgen_setup_kstats("vnet", instance, kname, &ldcp->stats);
	if (ldcp->ksp == NULL) {
		goto ldc_attach_failed;
	}

	/* initialize vgen_versions supported */
	bcopy(vgen_versions, ldcp->vgen_versions, sizeof (ldcp->vgen_versions));
	vgen_reset_vnet_proto_ops(ldcp);

	/* Link this channel to the port */
	portp->ldcp = ldcp;

	ldcp->link_state = LINK_STATE_UNKNOWN;
#ifdef	VNET_IOC_DEBUG
	ldcp->link_down_forced = B_FALSE;
#endif
	ldcp->flags |= CHANNEL_ATTACHED;
	return (DDI_SUCCESS);

ldc_attach_failed:
	if (attach_state & AST_ldc_reg_cb) {
		(void) ldc_unreg_callback(ldcp->ldc_handle);
		kmem_free(ldcp->ldcmsg, ldcp->msglen);
	}

	if (attach_state & AST_ldc_init) {
		(void) ldc_fini(ldcp->ldc_handle);
	}
	if (attach_state & AST_mutex_init) {
		mutex_destroy(&ldcp->tclock);
		mutex_destroy(&ldcp->txlock);
		mutex_destroy(&ldcp->cblock);
		mutex_destroy(&ldcp->wrlock);
		mutex_destroy(&ldcp->rxlock);
		mutex_destroy(&ldcp->pollq_lock);
	}
	if (attach_state & AST_ldc_alloc) {
		KMEM_FREE(ldcp);
	}
	return (DDI_FAILURE);
}

/* detach a channel from the port */
static void
vgen_ldc_detach(vgen_ldc_t *ldcp)
{
	vgen_port_t	*portp;
	vgen_t		*vgenp;

	ASSERT(ldcp != NULL);

	portp = ldcp->portp;
	vgenp = portp->vgenp;

	if (ldcp->ldc_status != LDC_INIT) {
		DWARN(vgenp, ldcp, "ldc_status is not INIT\n");
	}

	if (ldcp->flags & CHANNEL_ATTACHED) {
		ldcp->flags &= ~(CHANNEL_ATTACHED);

		(void) ldc_unreg_callback(ldcp->ldc_handle);
		(void) ldc_fini(ldcp->ldc_handle);

		kmem_free(ldcp->ldcmsg, ldcp->msglen);
		vgen_destroy_kstats(ldcp->ksp);
		ldcp->ksp = NULL;
		mutex_destroy(&ldcp->tclock);
		mutex_destroy(&ldcp->txlock);
		mutex_destroy(&ldcp->cblock);
		mutex_destroy(&ldcp->wrlock);
		mutex_destroy(&ldcp->rxlock);
		mutex_destroy(&ldcp->pollq_lock);
		mutex_destroy(&ldcp->msg_thr_lock);
		cv_destroy(&ldcp->msg_thr_cv);

		KMEM_FREE(ldcp);
	}
}

/* enable transmit/receive on the channel */
static int
vgen_ldc_init(vgen_ldc_t *ldcp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	ldc_status_t	istatus;
	int		rv;
	enum		{ ST_init = 0x0, ST_ldc_open = 0x1,
			    ST_cb_enable = 0x2} init_state;
	int		flag = 0;

	init_state = ST_init;

	DBG1(vgenp, ldcp, "enter\n");
	LDC_LOCK(ldcp);

	rv = ldc_open(ldcp->ldc_handle);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_open failed: rv(%d)\n", rv);
		goto ldcinit_failed;
	}
	init_state |= ST_ldc_open;

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	if (istatus != LDC_OPEN && istatus != LDC_READY) {
		DWARN(vgenp, ldcp, "status(%d) is not OPEN/READY\n", istatus);
		goto ldcinit_failed;
	}
	ldcp->ldc_status = istatus;

	rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_ENABLE);
	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_set_cb_mode failed: rv(%d)\n", rv);
		goto ldcinit_failed;
	}

	init_state |= ST_cb_enable;

	vgen_ldc_up(ldcp);

	(void) ldc_status(ldcp->ldc_handle, &istatus);
	if (istatus == LDC_UP) {
		DWARN(vgenp, ldcp, "status(%d) is UP\n", istatus);
	}

	ldcp->ldc_status = istatus;

	ldcp->hphase = VH_PHASE0;
	ldcp->hstate = 0;
	ldcp->flags |= CHANNEL_STARTED;

	vgen_setup_handshake_params(ldcp);

	/* if channel is already UP - start handshake */
	if (istatus == LDC_UP) {
		vgen_t *vgenp = LDC_TO_VGEN(ldcp);
		if (ldcp->portp != vgenp->vsw_portp) {
			/*
			 * As the channel is up, use this port from now on.
			 */
			(void) atomic_swap_32(
			    &ldcp->portp->use_vsw_port, B_FALSE);
		}

		/* Initialize local session id */
		ldcp->local_sid = ddi_get_lbolt();

		/* clear peer session id */
		ldcp->peer_sid = 0;

		mutex_exit(&ldcp->tclock);
		mutex_exit(&ldcp->txlock);
		mutex_exit(&ldcp->wrlock);
		mutex_exit(&ldcp->rxlock);
		rv = vgen_handshake(vh_nextphase(ldcp));
		mutex_exit(&ldcp->cblock);
		if (rv != 0) {
			flag = (rv == ECONNRESET) ? VGEN_FLAG_EVT_RESET :
			    VGEN_FLAG_NEED_LDCRESET;
			(void) vgen_process_reset(ldcp, flag);
		}
	} else {
		LDC_UNLOCK(ldcp);
	}

	return (DDI_SUCCESS);

ldcinit_failed:
	if (init_state & ST_cb_enable) {
		(void) ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
	}
	if (init_state & ST_ldc_open) {
		(void) ldc_close(ldcp->ldc_handle);
	}
	LDC_UNLOCK(ldcp);
	DBG1(vgenp, ldcp, "exit\n");
	return (DDI_FAILURE);
}

/* stop transmit/receive on the channel */
static void
vgen_ldc_uninit(vgen_ldc_t *ldcp)
{
	vgen_t *vgenp = LDC_TO_VGEN(ldcp);

	DBG1(vgenp, ldcp, "enter\n");

	LDC_LOCK(ldcp);

	if ((ldcp->flags & CHANNEL_STARTED) == 0) {
		LDC_UNLOCK(ldcp);
		DWARN(vgenp, ldcp, "CHANNEL_STARTED flag is not set\n");
		return;
	}

	LDC_UNLOCK(ldcp);

	while (atomic_cas_uint(&ldcp->reset_in_progress, 0, 1) != 0) {
		delay(drv_usectohz(VGEN_LDC_UNINIT_DELAY));
	}

	(void) vgen_process_reset(ldcp, VGEN_FLAG_UNINIT);

	DBG1(vgenp, ldcp, "exit\n");
}

/*
 * Create a descriptor ring, that will be exported to the peer for mapping.
 */
static int
vgen_create_dring(vgen_ldc_t *ldcp)
{
	vgen_hparams_t	*lp = &ldcp->local_hparams;
	int		rv;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		rv = vgen_create_rx_dring(ldcp);
	} else {
		rv = vgen_create_tx_dring(ldcp);
	}

	return (rv);
}

/*
 * Destroy the descriptor ring.
 */
static void
vgen_destroy_dring(vgen_ldc_t *ldcp)
{
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		vgen_destroy_rx_dring(ldcp);
	} else {
		vgen_destroy_tx_dring(ldcp);
	}
}

/*
 * Map the descriptor ring exported by the peer.
 */
static int
vgen_map_dring(vgen_ldc_t *ldcp, void *pkt)
{
	int		rv;
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		/*
		 * In RxDringData mode, dring that we map in
		 * becomes our transmit descriptor ring.
		 */
		rv = vgen_map_tx_dring(ldcp, pkt);
	} else {

		/*
		 * In TxDring mode, dring that we map in
		 * becomes our receive descriptor ring.
		 */
		rv = vgen_map_rx_dring(ldcp, pkt);
	}

	return (rv);
}

/*
 * Unmap the descriptor ring exported by the peer.
 */
static void
vgen_unmap_dring(vgen_ldc_t *ldcp)
{
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		vgen_unmap_tx_dring(ldcp);
	} else {
		vgen_unmap_rx_dring(ldcp);
	}
}

void
vgen_destroy_rxpools(void *arg)
{
	vio_mblk_pool_t	*poolp = (vio_mblk_pool_t *)arg;
	vio_mblk_pool_t	*npoolp;

	while (poolp != NULL) {
		npoolp =  poolp->nextp;
		while (vio_destroy_mblks(poolp) != 0) {
			delay(drv_usectohz(vgen_rxpool_cleanup_delay));
		}
		poolp = npoolp;
	}
}

/* get channel statistics */
static uint64_t
vgen_ldc_stat(vgen_ldc_t *ldcp, uint_t stat)
{
	vgen_stats_t	*statsp;
	uint64_t	val;

	val = 0;
	statsp = &ldcp->stats;
	switch (stat) {

	case MAC_STAT_MULTIRCV:
		val = statsp->multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = statsp->brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		val = statsp->multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		val = statsp->brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		val = statsp->norcvbuf;
		break;

	case MAC_STAT_IERRORS:
		val = statsp->ierrors;
		break;

	case MAC_STAT_NOXMTBUF:
		val = statsp->noxmtbuf;
		break;

	case MAC_STAT_OERRORS:
		val = statsp->oerrors;
		break;

	case MAC_STAT_COLLISIONS:
		break;

	case MAC_STAT_RBYTES:
		val = statsp->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		val = statsp->ipackets;
		break;

	case MAC_STAT_OBYTES:
		val = statsp->obytes;
		break;

	case MAC_STAT_OPACKETS:
		val = statsp->opackets;
		break;

	/* stats not relevant to ldc, return 0 */
	case MAC_STAT_IFSPEED:
	case ETHER_STAT_ALIGN_ERRORS:
	case ETHER_STAT_FCS_ERRORS:
	case ETHER_STAT_FIRST_COLLISIONS:
	case ETHER_STAT_MULTI_COLLISIONS:
	case ETHER_STAT_DEFER_XMTS:
	case ETHER_STAT_TX_LATE_COLLISIONS:
	case ETHER_STAT_EX_COLLISIONS:
	case ETHER_STAT_MACXMT_ERRORS:
	case ETHER_STAT_CARRIER_ERRORS:
	case ETHER_STAT_TOOLONG_ERRORS:
	case ETHER_STAT_XCVR_ADDR:
	case ETHER_STAT_XCVR_ID:
	case ETHER_STAT_XCVR_INUSE:
	case ETHER_STAT_CAP_1000FDX:
	case ETHER_STAT_CAP_1000HDX:
	case ETHER_STAT_CAP_100FDX:
	case ETHER_STAT_CAP_100HDX:
	case ETHER_STAT_CAP_10FDX:
	case ETHER_STAT_CAP_10HDX:
	case ETHER_STAT_CAP_ASMPAUSE:
	case ETHER_STAT_CAP_PAUSE:
	case ETHER_STAT_CAP_AUTONEG:
	case ETHER_STAT_ADV_CAP_1000FDX:
	case ETHER_STAT_ADV_CAP_1000HDX:
	case ETHER_STAT_ADV_CAP_100FDX:
	case ETHER_STAT_ADV_CAP_100HDX:
	case ETHER_STAT_ADV_CAP_10FDX:
	case ETHER_STAT_ADV_CAP_10HDX:
	case ETHER_STAT_ADV_CAP_ASMPAUSE:
	case ETHER_STAT_ADV_CAP_PAUSE:
	case ETHER_STAT_ADV_CAP_AUTONEG:
	case ETHER_STAT_LP_CAP_1000FDX:
	case ETHER_STAT_LP_CAP_1000HDX:
	case ETHER_STAT_LP_CAP_100FDX:
	case ETHER_STAT_LP_CAP_100HDX:
	case ETHER_STAT_LP_CAP_10FDX:
	case ETHER_STAT_LP_CAP_10HDX:
	case ETHER_STAT_LP_CAP_ASMPAUSE:
	case ETHER_STAT_LP_CAP_PAUSE:
	case ETHER_STAT_LP_CAP_AUTONEG:
	case ETHER_STAT_LINK_ASMPAUSE:
	case ETHER_STAT_LINK_PAUSE:
	case ETHER_STAT_LINK_AUTONEG:
	case ETHER_STAT_LINK_DUPLEX:
	default:
		val = 0;
		break;

	}
	return (val);
}

/*
 * LDC channel is UP, start handshake process with peer.
 */
static void
vgen_handle_evt_up(vgen_ldc_t *ldcp)
{
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	DBG1(vgenp, ldcp, "enter\n");

	ASSERT(MUTEX_HELD(&ldcp->cblock));

	if (ldcp->portp != vgenp->vsw_portp) {
		/*
		 * As the channel is up, use this port from now on.
		 */
		(void) atomic_swap_32(&ldcp->portp->use_vsw_port, B_FALSE);
	}

	/* Initialize local session id */
	ldcp->local_sid = ddi_get_lbolt();

	/* clear peer session id */
	ldcp->peer_sid = 0;

	/* Initiate Handshake process with peer ldc endpoint */
	(void) vgen_handshake(vh_nextphase(ldcp));

	DBG1(vgenp, ldcp, "exit\n");
}

/*
 * LDC channel is Reset, terminate connection with peer and try to
 * bring the channel up again.
 */
int
vgen_handle_evt_reset(vgen_ldc_t *ldcp, vgen_caller_t caller)
{
	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		ASSERT(MUTEX_HELD(&ldcp->cblock));
	}

	/* Set the flag to indicate reset is in progress */
	if (atomic_cas_uint(&ldcp->reset_in_progress, 0, 1) != 0) {
		/* another thread is already in the process of resetting */
		return (EBUSY);
	}

	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		mutex_exit(&ldcp->cblock);
	}

	(void) vgen_process_reset(ldcp, VGEN_FLAG_EVT_RESET);

	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		mutex_enter(&ldcp->cblock);
	}

	return (0);
}

/* Interrupt handler for the channel */
static uint_t
vgen_ldc_cb(uint64_t event, caddr_t arg)
{
	_NOTE(ARGUNUSED(event))
	vgen_ldc_t	*ldcp;
	vgen_t		*vgenp;
	ldc_status_t	istatus;
	vgen_stats_t	*statsp;
	uint_t		ret = LDC_SUCCESS;

	ldcp = (vgen_ldc_t *)arg;
	vgenp = LDC_TO_VGEN(ldcp);
	statsp = &ldcp->stats;

	DBG1(vgenp, ldcp, "enter\n");

	mutex_enter(&ldcp->cblock);
	statsp->callbacks++;
	if ((ldcp->ldc_status == LDC_INIT) || (ldcp->ldc_handle == 0)) {
		DWARN(vgenp, ldcp, "status(%d) is LDC_INIT\n",
		    ldcp->ldc_status);
		mutex_exit(&ldcp->cblock);
		return (LDC_SUCCESS);
	}

	/*
	 * NOTE: not using switch() as event could be triggered by
	 * a state change and a read request. Also the ordering	of the
	 * check for the event types is deliberate.
	 */
	if (event & LDC_EVT_UP) {
		if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
			DWARN(vgenp, ldcp, "ldc_status err\n");
			/* status couldn't be determined */
			ret = LDC_FAILURE;
			goto ldc_cb_ret;
		}
		ldcp->ldc_status = istatus;
		if (ldcp->ldc_status != LDC_UP) {
			DWARN(vgenp, ldcp, "LDC_EVT_UP received "
			    " but ldc status is not UP(0x%x)\n",
			    ldcp->ldc_status);
			/* spurious interrupt, return success */
			goto ldc_cb_ret;
		}
		DWARN(vgenp, ldcp, "event(%lx) UP, status(%d)\n",
		    event, ldcp->ldc_status);

		vgen_handle_evt_up(ldcp);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);
	}

	/* Handle RESET/DOWN before READ event */
	if (event & (LDC_EVT_RESET | LDC_EVT_DOWN)) {
		if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
			DWARN(vgenp, ldcp, "ldc_status error\n");
			/* status couldn't be determined */
			ret = LDC_FAILURE;
			goto ldc_cb_ret;
		}
		ldcp->ldc_status = istatus;
		DWARN(vgenp, ldcp, "event(%lx) RESET/DOWN, status(%d)\n",
		    event, ldcp->ldc_status);

		(void) vgen_handle_evt_reset(ldcp, VGEN_LDC_CB);

		/*
		 * As the channel is down/reset, ignore READ event
		 * but print a debug warning message.
		 */
		if (event & LDC_EVT_READ) {
			DWARN(vgenp, ldcp,
			    "LDC_EVT_READ set along with RESET/DOWN\n");
			event &= ~LDC_EVT_READ;
		}
	}

	if (event & LDC_EVT_READ) {
		DBG2(vgenp, ldcp, "event(%lx) READ, status(%d)\n",
		    event, ldcp->ldc_status);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);

		if (ldcp->msg_thread != NULL) {
			/*
			 * If the receive thread is enabled, then
			 * wakeup the receive thread to process the
			 * LDC messages.
			 */
			mutex_exit(&ldcp->cblock);
			mutex_enter(&ldcp->msg_thr_lock);
			if (!(ldcp->msg_thr_flags & VGEN_WTHR_DATARCVD)) {
				ldcp->msg_thr_flags |= VGEN_WTHR_DATARCVD;
				cv_signal(&ldcp->msg_thr_cv);
			}
			mutex_exit(&ldcp->msg_thr_lock);
			mutex_enter(&ldcp->cblock);
		} else  {
			(void) vgen_handle_evt_read(ldcp, VGEN_LDC_CB);
		}
	}

ldc_cb_ret:
	mutex_exit(&ldcp->cblock);
	DBG1(vgenp, ldcp, "exit\n");
	return (ret);
}

int
vgen_handle_evt_read(vgen_ldc_t *ldcp, vgen_caller_t caller)
{
	int		rv;
	uint64_t	*ldcmsg;
	size_t		msglen;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vio_msg_tag_t	*tagp;
	ldc_status_t	istatus;
	boolean_t	has_data;

	DBG1(vgenp, ldcp, "enter\n");

	if (caller == VGEN_LDC_CB) {
		ASSERT(MUTEX_HELD(&ldcp->cblock));
	} else if (caller == VGEN_MSG_THR) {
		mutex_enter(&ldcp->cblock);
	} else {
		return (EINVAL);
	}

	ldcmsg = ldcp->ldcmsg;

vgen_evtread:
	do {
		msglen = ldcp->msglen;
		rv = ldc_read(ldcp->ldc_handle, (caddr_t)ldcmsg, &msglen);

		if (rv != 0) {
			DWARN(vgenp, ldcp, "ldc_read() failed "
			    "rv(%d) len(%d)\n", rv, msglen);
			if (rv == ECONNRESET)
				goto vgen_evtread_error;
			break;
		}
		if (msglen == 0) {
			DBG2(vgenp, ldcp, "ldc_read NODATA");
			break;
		}
		DBG2(vgenp, ldcp, "ldc_read msglen(%d)", msglen);

		tagp = (vio_msg_tag_t *)ldcmsg;

		if (ldcp->peer_sid) {
			/*
			 * check sid only after we have received peer's sid
			 * in the version negotiate msg.
			 */
#ifdef DEBUG
			if (vgen_inject_error(ldcp, VGEN_ERR_HSID)) {
				/* simulate bad sid condition */
				tagp->vio_sid = 0;
				vgen_inject_err_flag &= ~(VGEN_ERR_HSID);
			}
#endif
			rv = vgen_check_sid(ldcp, tagp);
			if (rv != VGEN_SUCCESS) {
				/*
				 * If sid mismatch is detected,
				 * reset the channel.
				 */
				DWARN(vgenp, ldcp, "vgen_check_sid() failed\n");
				goto vgen_evtread_error;
			}
		}

		switch (tagp->vio_msgtype) {
		case VIO_TYPE_CTRL:
			rv = vgen_handle_ctrlmsg(ldcp, tagp);
			if (rv != 0) {
				DWARN(vgenp, ldcp, "vgen_handle_ctrlmsg()"
				    " failed rv(%d)\n", rv);
			}
			break;

		case VIO_TYPE_DATA:
			rv = vgen_handle_datamsg(ldcp, tagp, msglen);
			if (rv != 0) {
				DWARN(vgenp, ldcp, "vgen_handle_datamsg()"
				    " failed rv(%d)\n", rv);
			}
			break;

		case VIO_TYPE_ERR:
			vgen_handle_errmsg(ldcp, tagp);
			break;

		default:
			DWARN(vgenp, ldcp, "Unknown VIO_TYPE(%x)\n",
			    tagp->vio_msgtype);
			break;
		}

		/*
		 * If an error is encountered, stop processing and
		 * handle the error.
		 */
		if (rv != 0) {
			goto vgen_evtread_error;
		}

	} while (msglen);

	/* check once more before exiting */
	rv = ldc_chkq(ldcp->ldc_handle, &has_data);
	if ((rv == 0) && (has_data == B_TRUE)) {
		DTRACE_PROBE1(vgen_chkq, vgen_ldc_t *, ldcp);
		goto vgen_evtread;
	}

vgen_evtread_error:
	if (rv != 0) {
		/*
		 * We handle the error and then return the error value. If we
		 * are running in the context of the msg worker, the error
		 * tells the worker thread to exit, as the channel would have
		 * been reset.
		 */
		if (rv == ECONNRESET) {
			if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
				DWARN(vgenp, ldcp, "ldc_status err\n");
			} else {
				ldcp->ldc_status = istatus;
			}
			(void) vgen_handle_evt_reset(ldcp, caller);
		} else {
			DWARN(vgenp, ldcp, "Calling vgen_ldc_reset()...\n");
			(void) vgen_ldc_reset(ldcp, caller);
		}
	}

	if (caller == VGEN_MSG_THR) {
		mutex_exit(&ldcp->cblock);
	}

	DBG1(vgenp, ldcp, "exit\n");
	return (rv);
}

/* vgen handshake functions */

/* change the hphase for the channel to the next phase */
static vgen_ldc_t *
vh_nextphase(vgen_ldc_t *ldcp)
{
	if (ldcp->hphase == VH_PHASE4) {
		ldcp->hphase = VH_DONE;
	} else {
		ldcp->hphase++;
	}
	return (ldcp);
}

/* send version negotiate message to the peer over ldc */
static int
vgen_send_version_negotiate(vgen_ldc_t *ldcp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vio_ver_msg_t	vermsg;
	vio_msg_tag_t	*tagp = &vermsg.tag;
	int		rv;

	bzero(&vermsg, sizeof (vermsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_VER_INFO;
	tagp->vio_sid = ldcp->local_sid;

	/* get version msg payload from ldcp->local */
	vermsg.ver_major = ldcp->local_hparams.ver_major;
	vermsg.ver_minor = ldcp->local_hparams.ver_minor;
	vermsg.dev_class = ldcp->local_hparams.dev_class;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (vermsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		return (rv);
	}

	ldcp->hstate |= VER_INFO_SENT;
	DBG2(vgenp, ldcp, "VER_INFO_SENT ver(%d,%d)\n",
	    vermsg.ver_major, vermsg.ver_minor);

	return (VGEN_SUCCESS);
}

/* send attr info message to the peer over ldc */
static int
vgen_send_attr_info(vgen_ldc_t *ldcp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vnet_attr_msg_t	attrmsg;
	vio_msg_tag_t	*tagp = &attrmsg.tag;
	int		rv;

	bzero(&attrmsg, sizeof (attrmsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_ATTR_INFO;
	tagp->vio_sid = ldcp->local_sid;

	/* get attr msg payload from ldcp->local */
	attrmsg.mtu = ldcp->local_hparams.mtu;
	attrmsg.addr = ldcp->local_hparams.addr;
	attrmsg.addr_type = ldcp->local_hparams.addr_type;
	attrmsg.xfer_mode = ldcp->local_hparams.xfer_mode;
	attrmsg.ack_freq = ldcp->local_hparams.ack_freq;
	attrmsg.physlink_update = ldcp->local_hparams.physlink_update;
	attrmsg.options = ldcp->local_hparams.dring_mode;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (attrmsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		return (rv);
	}

	ldcp->hstate |= ATTR_INFO_SENT;
	DBG2(vgenp, ldcp, "ATTR_INFO_SENT\n");

	return (VGEN_SUCCESS);
}

/*
 * Send descriptor ring register message to the peer over ldc.
 * Invoked in RxDringData mode.
 */
static int
vgen_send_rx_dring_reg(vgen_ldc_t *ldcp)
{
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_reg_msg_t	*msg;
	vio_dring_reg_ext_msg_t	*emsg;
	int			rv;
	uint8_t			*buf;
	uint_t			msgsize;

	msgsize = VNET_DRING_REG_EXT_MSG_SIZE(ldcp->rx_data_ncookies);
	msg = kmem_zalloc(msgsize, KM_SLEEP);

	/* Initialize the common part of dring reg msg */
	vgen_init_dring_reg_msg(ldcp, msg, VIO_RX_DRING_DATA);

	/* skip over dring cookies at the tail of common section */
	buf = (uint8_t *)msg->cookie;
	ASSERT(msg->ncookies == 1);
	buf += (msg->ncookies * sizeof (ldc_mem_cookie_t));

	/* Now setup the extended part, specific to RxDringData mode */
	emsg = (vio_dring_reg_ext_msg_t *)buf;

	/* copy data_ncookies in the msg */
	emsg->data_ncookies = ldcp->rx_data_ncookies;

	/* copy data area size in the msg */
	emsg->data_area_size = ldcp->rx_data_sz;

	/* copy data area cookies in the msg */
	bcopy(ldcp->rx_data_cookie, (ldc_mem_cookie_t *)emsg->data_cookie,
	    sizeof (ldc_mem_cookie_t) * ldcp->rx_data_ncookies);

	rv = vgen_sendmsg(ldcp, (caddr_t)msg, msgsize, B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		kmem_free(msg, msgsize);
		return (rv);
	}

	ldcp->hstate |= DRING_INFO_SENT;
	DBG2(vgenp, ldcp, "DRING_INFO_SENT \n");

	kmem_free(msg, msgsize);
	return (VGEN_SUCCESS);
}

/*
 * Send descriptor ring register message to the peer over ldc.
 * Invoked in TxDring mode.
 */
static int
vgen_send_tx_dring_reg(vgen_ldc_t *ldcp)
{
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vio_dring_reg_msg_t	msg;
	int			rv;

	bzero(&msg, sizeof (msg));

	/*
	 * Initialize only the common part of dring reg msg in TxDring mode.
	 */
	vgen_init_dring_reg_msg(ldcp, &msg, VIO_TX_DRING);

	rv = vgen_sendmsg(ldcp, (caddr_t)&msg, sizeof (msg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		return (rv);
	}

	ldcp->hstate |= DRING_INFO_SENT;
	DBG2(vgenp, ldcp, "DRING_INFO_SENT \n");

	return (VGEN_SUCCESS);
}

static int
vgen_send_rdx_info(vgen_ldc_t *ldcp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vio_rdx_msg_t	rdxmsg;
	vio_msg_tag_t	*tagp = &rdxmsg.tag;
	int		rv;

	bzero(&rdxmsg, sizeof (rdxmsg));

	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_RDX;
	tagp->vio_sid = ldcp->local_sid;

	rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (rdxmsg), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		DWARN(vgenp, ldcp, "vgen_sendmsg failed\n");
		return (rv);
	}

	ldcp->hstate |= RDX_INFO_SENT;
	DBG2(vgenp, ldcp, "RDX_INFO_SENT\n");

	return (VGEN_SUCCESS);
}

/* send multicast addr info message to vsw */
static int
vgen_send_mcast_info(vgen_ldc_t *ldcp)
{
	vnet_mcast_msg_t	mcastmsg;
	vnet_mcast_msg_t	*msgp;
	vio_msg_tag_t		*tagp;
	vgen_t			*vgenp;
	struct ether_addr	*mca;
	int			rv;
	int			i;
	uint32_t		size;
	uint32_t		mccount;
	uint32_t		n;

	msgp = &mcastmsg;
	tagp = &msgp->tag;
	vgenp = LDC_TO_VGEN(ldcp);

	mccount = vgenp->mccount;
	i = 0;

	do {
		tagp->vio_msgtype = VIO_TYPE_CTRL;
		tagp->vio_subtype = VIO_SUBTYPE_INFO;
		tagp->vio_subtype_env = VNET_MCAST_INFO;
		tagp->vio_sid = ldcp->local_sid;

		n = ((mccount >= VNET_NUM_MCAST) ? VNET_NUM_MCAST : mccount);
		size = n * sizeof (struct ether_addr);

		mca = &(vgenp->mctab[i]);
		bcopy(mca, (msgp->mca), size);
		msgp->set = B_TRUE;
		msgp->count = n;

		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msgp),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			DWARN(vgenp, ldcp, "vgen_sendmsg err(%d)\n", rv);
			return (rv);
		}

		mccount -= n;
		i += n;

	} while (mccount);

	return (VGEN_SUCCESS);
}

/*
 * vgen_dds_rx -- post DDS messages to vnet.
 */
static int
vgen_dds_rx(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vio_dds_msg_t	*dmsg = (vio_dds_msg_t *)tagp;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	if (dmsg->dds_class != DDS_VNET_NIU) {
		DWARN(vgenp, ldcp, "Unknown DDS class, dropping");
		return (EBADMSG);
	}
	vnet_dds_rx(vgenp->vnetp, dmsg);
	return (0);
}

/*
 * vgen_dds_tx -- an interface called by vnet to send DDS messages.
 */
int
vgen_dds_tx(void *arg, void *msg)
{
	vgen_t		*vgenp = arg;
	vio_dds_msg_t	*dmsg = msg;
	vgen_portlist_t	*plistp = &vgenp->vgenports;
	vgen_ldc_t	*ldcp;
	int		rv = EIO;

	READ_ENTER(&plistp->rwlock);
	ldcp = vgenp->vsw_portp->ldcp;
	if ((ldcp == NULL) || (ldcp->hphase != VH_DONE)) {
		goto vgen_dsend_exit;
	}

	dmsg->tag.vio_sid = ldcp->local_sid;
	rv = vgen_sendmsg(ldcp, (caddr_t)dmsg, sizeof (vio_dds_msg_t), B_FALSE);
	if (rv != VGEN_SUCCESS) {
		rv = EIO;
	} else {
		rv = 0;
	}

vgen_dsend_exit:
	RW_EXIT(&plistp->rwlock);
	return (rv);

}

/* Initiate Phase 2 of handshake */
static int
vgen_handshake_phase2(vgen_ldc_t *ldcp)
{
	int	rv;

#ifdef DEBUG
	if (vgen_inject_error(ldcp, VGEN_ERR_HSTATE)) {
		/* simulate out of state condition */
		vgen_inject_err_flag &= ~(VGEN_ERR_HSTATE);
		rv = vgen_send_rdx_info(ldcp);
		return (rv);
	}
	if (vgen_inject_error(ldcp, VGEN_ERR_HTIMEOUT)) {
		/* simulate timeout condition */
		vgen_inject_err_flag &= ~(VGEN_ERR_HTIMEOUT);
		return (VGEN_SUCCESS);
	}
#endif
	rv = vgen_send_attr_info(ldcp);
	if (rv != VGEN_SUCCESS) {
		return (rv);
	}

	return (VGEN_SUCCESS);
}

static int
vgen_handshake_phase3(vgen_ldc_t *ldcp)
{
	int		rv;
	vgen_hparams_t	*lp = &ldcp->local_hparams;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t	*statsp = &ldcp->stats;

	/* dring mode has been negotiated in attr phase; save in stats */
	statsp->dring_mode = lp->dring_mode;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {	/* RxDringData mode */
		ldcp->rx_dringdata = vgen_handle_dringdata_shm;
		ldcp->tx_dringdata = vgen_dringsend_shm;
		if (!VGEN_PRI_ETH_DEFINED(vgenp)) {
			/*
			 * If priority frames are not in use, we don't need a
			 * separate wrapper function for 'tx', so we set it to
			 * 'tx_dringdata'. If priority frames are configured,
			 * we leave the 'tx' pointer as is (initialized in
			 * vgen_set_vnet_proto_ops()).
			 */
			ldcp->tx = ldcp->tx_dringdata;
		}
	} else {					/* TxDring mode */
		ldcp->msg_thread = thread_create(NULL,
		    2 * DEFAULTSTKSZ, vgen_ldc_msg_worker, ldcp, 0,
		    &p0, TS_RUN, maxclsyspri);
	}

	rv = vgen_create_dring(ldcp);
	if (rv != VGEN_SUCCESS) {
		return (rv);
	}

	/* update local dring_info params */
	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		bcopy(&(ldcp->rx_dring_cookie),
		    &(ldcp->local_hparams.dring_cookie),
		    sizeof (ldc_mem_cookie_t));
		ldcp->local_hparams.dring_ncookies = ldcp->rx_dring_ncookies;
		ldcp->local_hparams.num_desc = ldcp->num_rxds;
		ldcp->local_hparams.desc_size =
		    sizeof (vnet_rx_dringdata_desc_t);
		rv = vgen_send_rx_dring_reg(ldcp);
	} else {
		bcopy(&(ldcp->tx_dring_cookie),
		    &(ldcp->local_hparams.dring_cookie),
		    sizeof (ldc_mem_cookie_t));
		ldcp->local_hparams.dring_ncookies = ldcp->tx_dring_ncookies;
		ldcp->local_hparams.num_desc = ldcp->num_txds;
		ldcp->local_hparams.desc_size = sizeof (vnet_public_desc_t);
		rv = vgen_send_tx_dring_reg(ldcp);
	}

	if (rv != VGEN_SUCCESS) {
		return (rv);
	}

	return (VGEN_SUCCESS);
}

/*
 * Set vnet-protocol-version dependent functions based on version.
 */
static void
vgen_set_vnet_proto_ops(vgen_ldc_t *ldcp)
{
	vgen_hparams_t	*lp = &ldcp->local_hparams;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	/*
	 * Setup the appropriate dring data processing routine and any
	 * associated thread based on the version.
	 *
	 * In versions < 1.6, we only support TxDring mode. In this mode, the
	 * msg worker thread processes all types of VIO msgs (ctrl and data).
	 *
	 * In versions >= 1.6, we also support RxDringData mode. In this mode,
	 * all msgs including dring data messages are handled directly by the
	 * callback (intr) thread. The dring data msgs (msgtype: VIO_TYPE_DATA,
	 * subtype: VIO_SUBTYPE_INFO, subtype_env: VIO_DRING_DATA) can also be
	 * disabled while the polling thread is active, in which case the
	 * polling thread processes the rcv descriptor ring.
	 *
	 * However, for versions >= 1.6, we can force to only use TxDring mode.
	 * This could happen if RxDringData mode has been disabled (see
	 * below) on this guest or on the peer guest. This info is determined
	 * as part of attr exchange phase of handshake. Hence, we setup these
	 * pointers for v1.6 after attr msg phase completes during handshake.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 6)) {	/* Ver >= 1.6 */
		/*
		 * Set data dring mode for vgen_send_attr_info().
		 */
		if (vgen_mapin_avail(ldcp) == B_TRUE) {
			lp->dring_mode = (VIO_RX_DRING_DATA | VIO_TX_DRING);
		} else {
			lp->dring_mode = VIO_TX_DRING;
		}
	} else {				/* Ver <= 1.5 */
		lp->dring_mode = VIO_TX_DRING;
	}

	if (VGEN_VER_GTEQ(ldcp, 1, 5)) {
		vgen_port_t	*portp = ldcp->portp;
		vnet_t		*vnetp = vgenp->vnetp;
		/*
		 * If the version negotiated with vswitch is >= 1.5 (link
		 * status update support), set the required bits in our
		 * attributes if this vnet device has been configured to get
		 * physical link state updates.
		 */
		if (portp == vgenp->vsw_portp && vnetp->pls_update == B_TRUE) {
			lp->physlink_update = PHYSLINK_UPDATE_STATE;
		} else {
			lp->physlink_update = PHYSLINK_UPDATE_NONE;
		}
	}

	if (VGEN_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * If the version negotiated with peer is >= 1.4(Jumbo Frame
		 * Support), set the mtu in our attributes to max_frame_size.
		 */
		lp->mtu = vgenp->max_frame_size;
	} else  if (VGEN_VER_EQ(ldcp, 1, 3)) {
		/*
		 * If the version negotiated with peer is == 1.3 (Vlan Tag
		 * Support) set the attr.mtu to ETHERMAX + VLAN_TAGSZ.
		 */
		lp->mtu = ETHERMAX + VLAN_TAGSZ;
	} else {
		vgen_port_t	*portp = ldcp->portp;
		vnet_t		*vnetp = vgenp->vnetp;
		/*
		 * Pre-1.3 peers expect max frame size of ETHERMAX.
		 * We can negotiate that size with those peers provided the
		 * following conditions are true:
		 * - Only pvid is defined for our peer and there are no vids.
		 * - pvids are equal.
		 * If the above conditions are true, then we can send/recv only
		 * untagged frames of max size ETHERMAX.
		 */
		if (portp->nvids == 0 && portp->pvid == vnetp->pvid) {
			lp->mtu = ETHERMAX;
		}
	}

	if (VGEN_VER_GTEQ(ldcp, 1, 2)) {	/* Versions >= 1.2 */
		/*
		 * Starting v1.2 we support priority frames; so set the
		 * dring processing routines and xfer modes based on the
		 * version. Note that the dring routines could be changed after
		 * attribute handshake phase for versions >= 1.6 (See
		 * vgen_handshake_phase3())
		 */
		ldcp->tx_dringdata = vgen_dringsend;
		ldcp->rx_dringdata = vgen_handle_dringdata;

		if (VGEN_PRI_ETH_DEFINED(vgenp)) {
			/*
			 * Enable priority routines and pkt mode only if
			 * at least one pri-eth-type is specified in MD.
			 */
			ldcp->tx = vgen_ldcsend;
			ldcp->rx_pktdata = vgen_handle_pkt_data;

			/* set xfer mode for vgen_send_attr_info() */
			lp->xfer_mode = VIO_PKT_MODE | VIO_DRING_MODE_V1_2;
		} else {
			/* No priority eth types defined in MD */
			ldcp->tx = ldcp->tx_dringdata;
			ldcp->rx_pktdata = vgen_handle_pkt_data_nop;

			/* Set xfer mode for vgen_send_attr_info() */
			lp->xfer_mode = VIO_DRING_MODE_V1_2;
		}
	} else { /* Versions prior to 1.2  */
		vgen_reset_vnet_proto_ops(ldcp);
	}
}

/*
 * Reset vnet-protocol-version dependent functions to pre-v1.2.
 */
static void
vgen_reset_vnet_proto_ops(vgen_ldc_t *ldcp)
{
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	ldcp->tx = ldcp->tx_dringdata = vgen_dringsend;
	ldcp->rx_dringdata = vgen_handle_dringdata;
	ldcp->rx_pktdata = vgen_handle_pkt_data_nop;

	/* set xfer mode for vgen_send_attr_info() */
	lp->xfer_mode = VIO_DRING_MODE_V1_0;
}

static void
vgen_vlan_unaware_port_reset(vgen_port_t *portp)
{
	vgen_ldc_t	*ldcp = portp->ldcp;
	vgen_t		*vgenp = portp->vgenp;
	vnet_t		*vnetp = vgenp->vnetp;
	boolean_t	need_reset = B_FALSE;

	mutex_enter(&ldcp->cblock);

	/*
	 * If the peer is vlan_unaware(ver < 1.3), reset channel and terminate
	 * the connection. See comments in vgen_set_vnet_proto_ops().
	 */
	if (ldcp->hphase == VH_DONE && VGEN_VER_LT(ldcp, 1, 3) &&
	    (portp->nvids != 0 || portp->pvid != vnetp->pvid)) {
		need_reset = B_TRUE;
	}
	mutex_exit(&ldcp->cblock);

	if (need_reset == B_TRUE) {
		(void) vgen_ldc_reset(ldcp, VGEN_OTHER);
	}
}

static void
vgen_port_reset(vgen_port_t *portp)
{
	(void) vgen_ldc_reset(portp->ldcp, VGEN_OTHER);
}

static void
vgen_reset_vlan_unaware_ports(vgen_t *vgenp)
{
	vgen_port_t	*portp;
	vgen_portlist_t	*plistp;

	plistp = &(vgenp->vgenports);
	READ_ENTER(&plistp->rwlock);

	for (portp = plistp->headp; portp != NULL; portp = portp->nextp) {

		vgen_vlan_unaware_port_reset(portp);

	}

	RW_EXIT(&plistp->rwlock);
}

static void
vgen_reset_vsw_port(vgen_t *vgenp)
{
	vgen_port_t	*portp;

	if ((portp = vgenp->vsw_portp) != NULL) {
		vgen_port_reset(portp);
	}
}

static void
vgen_setup_handshake_params(vgen_ldc_t *ldcp)
{
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	/*
	 * clear local handshake params and initialize.
	 */
	bzero(&(ldcp->local_hparams), sizeof (ldcp->local_hparams));

	/* set version to the highest version supported */
	ldcp->local_hparams.ver_major =
	    ldcp->vgen_versions[0].ver_major;
	ldcp->local_hparams.ver_minor =
	    ldcp->vgen_versions[0].ver_minor;
	ldcp->local_hparams.dev_class = VDEV_NETWORK;

	/* set attr_info params */
	ldcp->local_hparams.mtu = vgenp->max_frame_size;
	ldcp->local_hparams.addr =
	    vnet_macaddr_strtoul(vgenp->macaddr);
	ldcp->local_hparams.addr_type = ADDR_TYPE_MAC;
	ldcp->local_hparams.xfer_mode = VIO_DRING_MODE_V1_0;
	ldcp->local_hparams.ack_freq = 0;	/* don't need acks */
	ldcp->local_hparams.physlink_update = PHYSLINK_UPDATE_NONE;

	/* reset protocol version specific function pointers */
	vgen_reset_vnet_proto_ops(ldcp);
	ldcp->local_hparams.dring_ident = 0;
	ldcp->local_hparams.dring_ready = B_FALSE;

	/* clear peer_hparams */
	bzero(&(ldcp->peer_hparams), sizeof (ldcp->peer_hparams));
	ldcp->peer_hparams.dring_ready = B_FALSE;
}

/*
 * Process Channel Reset. We tear down the resources (timers, threads,
 * descriptor rings etc) associated with the channel and reinitialize the
 * channel based on the flags.
 *
 * Arguments:
 *    ldcp:	The channel being processed.
 *
 *    flags:
 *	VGEN_FLAG_EVT_RESET:
 *		A ECONNRESET error occured while doing ldc operations such as
 *		ldc_read() or ldc_write(); the channel is already reset and it
 *		needs to be handled.
 *	VGEN_FLAG_NEED_LDCRESET:
 *		Some other errors occured and the error handling code needs to
 *		explicitly reset the channel and restart handshake with the
 *		peer. The error could be either in ldc operations or other
 *		parts of the code such as timeouts or mdeg events etc.
 *	VGEN_FLAG_UNINIT:
 *		The channel is being torn down; no need to bring up the channel
 *		after resetting.
 */
static int
vgen_process_reset(vgen_ldc_t *ldcp, int flags)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_port_t	*portp = ldcp->portp;
	vgen_hparams_t  *lp = &ldcp->local_hparams;
	boolean_t	is_vsw_port = B_FALSE;
	boolean_t	link_update = B_FALSE;
	ldc_status_t	istatus;
	int		rv;
	uint_t		retries = 0;
	timeout_id_t	htid = 0;
	timeout_id_t	wd_tid = 0;

	if (portp == vgenp->vsw_portp) { /* vswitch port ? */
		is_vsw_port = B_TRUE;
	}

	/*
	 * Report that the channel is being reset; it ensures that any HybridIO
	 * configuration is torn down before we reset the channel if it is not
	 * already reset (flags == VGEN_FLAG_NEED_LDCRESET).
	 */
	if (is_vsw_port == B_TRUE) {
		vio_net_report_err_t rep_err = portp->vcb.vio_net_report_err;
		rep_err(portp->vhp, VIO_NET_RES_DOWN);
	}

again:
	mutex_enter(&ldcp->cblock);

	/* Clear hstate and hphase */
	ldcp->hstate = 0;
	ldcp->hphase = VH_PHASE0;
	if (flags == VGEN_FLAG_NEED_LDCRESET || flags == VGEN_FLAG_UNINIT) {
		DWARN(vgenp, ldcp, "Doing Channel Reset...\n");
		(void) ldc_down(ldcp->ldc_handle);
		(void) ldc_status(ldcp->ldc_handle, &istatus);
		DWARN(vgenp, ldcp, "Reset Done, ldc_status(%d)\n", istatus);
		ldcp->ldc_status = istatus;

		if (flags == VGEN_FLAG_UNINIT) {
			/* disable further callbacks */
			rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
			if (rv != 0) {
				DWARN(vgenp, ldcp, "ldc_set_cb_mode failed\n");
			}
		}

	} else {
		/* flags == VGEN_FLAG_EVT_RESET */
		DWARN(vgenp, ldcp, "ldc status(%d)\n", ldcp->ldc_status);
	}

	/*
	 * As the connection is now reset, mark the channel
	 * link_state as 'down' and notify the stack if needed.
	 */
	if (ldcp->link_state != LINK_STATE_DOWN) {
		ldcp->link_state = LINK_STATE_DOWN;

		if (is_vsw_port == B_TRUE) { /* vswitch port ? */
			/*
			 * As the channel link is down, mark physical link also
			 * as down. After the channel comes back up and
			 * handshake completes, we will get an update on the
			 * physlink state from vswitch (if this device has been
			 * configured to get phys link updates).
			 */
			vgenp->phys_link_state = LINK_STATE_DOWN;
			link_update = B_TRUE;

		}
	}

	if (ldcp->htid != 0) {
		htid = ldcp->htid;
		ldcp->htid = 0;
	}

	if (ldcp->wd_tid != 0) {
		wd_tid = ldcp->wd_tid;
		ldcp->wd_tid = 0;
	}

	mutex_exit(&ldcp->cblock);

	/* Update link state to the stack */
	if (link_update == B_TRUE) {
		vgen_link_update(vgenp, ldcp->link_state);
	}

	/*
	 * As the channel is being reset, redirect traffic to the peer through
	 * vswitch, until the channel becomes ready to be used again.
	 */
	if (is_vsw_port == B_FALSE && vgenp->vsw_portp != NULL) {
		(void) atomic_swap_32(&portp->use_vsw_port, B_TRUE);
	}

	/* Cancel handshake watchdog timeout */
	if (htid) {
		(void) untimeout(htid);
	}

	/* Cancel transmit watchdog timeout */
	if (wd_tid) {
		(void) untimeout(wd_tid);
	}

	/* Stop the msg worker thread */
	if (lp->dring_mode == VIO_TX_DRING && curthread != ldcp->msg_thread) {
		vgen_stop_msg_thread(ldcp);
	}

	/* Grab all locks while we tear down tx/rx resources */
	LDC_LOCK(ldcp);

	/* Destroy the local dring which is exported to the peer */
	vgen_destroy_dring(ldcp);

	/* Unmap the remote dring which is imported from the peer */
	vgen_unmap_dring(ldcp);

	/*
	 * Bring up the channel and restart handshake
	 * only if the channel is not being torn down.
	 */
	if (flags != VGEN_FLAG_UNINIT) {

		/* Setup handshake parameters to restart a new handshake */
		vgen_setup_handshake_params(ldcp);

		/* Bring the channel up */
		vgen_ldc_up(ldcp);

		if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
			DWARN(vgenp, ldcp, "ldc_status err\n");
		} else {
			ldcp->ldc_status = istatus;
		}

		/* If the channel is UP, start handshake */
		if (ldcp->ldc_status == LDC_UP) {

			if (is_vsw_port == B_FALSE) {
				/*
				 * Channel is up; use this port from now on.
				 */
				(void) atomic_swap_32(&portp->use_vsw_port,
				    B_FALSE);
			}

			/* Initialize local session id */
			ldcp->local_sid = ddi_get_lbolt();

			/* clear peer session id */
			ldcp->peer_sid = 0;

			/*
			 * Initiate Handshake process with peer ldc endpoint by
			 * sending version info vio message. If that fails we
			 * go back to the top of this function to process the
			 * error again. Note that we can be in this loop for
			 * 'vgen_ldc_max_resets' times, after which the channel
			 * is not brought up.
			 */
			mutex_exit(&ldcp->tclock);
			mutex_exit(&ldcp->txlock);
			mutex_exit(&ldcp->wrlock);
			mutex_exit(&ldcp->rxlock);
			rv = vgen_handshake(vh_nextphase(ldcp));
			mutex_exit(&ldcp->cblock);
			if (rv != 0) {
				if (rv == ECONNRESET) {
					flags = VGEN_FLAG_EVT_RESET;
				} else {
					flags = VGEN_FLAG_NEED_LDCRESET;
				}

				/*
				 * We still hold 'reset_in_progress'; so we can
				 * just loop back to the top to restart error
				 * processing.
				 */
				goto again;
			}
		} else {
			LDC_UNLOCK(ldcp);
		}

	} else {	/* flags == VGEN_FLAG_UNINIT */

		/* Close the channel - retry on EAGAIN */
		while ((rv = ldc_close(ldcp->ldc_handle)) == EAGAIN) {
			if (++retries > vgen_ldccl_retries) {
				break;
			}
			drv_usecwait(VGEN_LDC_CLOSE_DELAY);
		}
		if (rv != 0) {
			cmn_err(CE_NOTE,
			    "!vnet%d: Error(%d) closing the channel(0x%lx)\n",
			    vgenp->instance, rv, ldcp->ldc_id);
		}

		ldcp->ldc_reset_count = 0;
		ldcp->ldc_status = LDC_INIT;
		ldcp->flags &= ~(CHANNEL_STARTED);

		LDC_UNLOCK(ldcp);
	}

	/* Done processing channel reset; clear the atomic flag */
	ldcp->reset_in_progress = 0;
	return (0);
}

/*
 * Initiate handshake with the peer by sending various messages
 * based on the handshake-phase that the channel is currently in.
 */
static int
vgen_handshake(vgen_ldc_t *ldcp)
{
	uint32_t	hphase = ldcp->hphase;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	int		rv = 0;
	timeout_id_t	htid;

	switch (hphase) {

	case VH_PHASE1:

		/*
		 * start timer, for entire handshake process, turn this timer
		 * off if all phases of handshake complete successfully and
		 * hphase goes to VH_DONE(below) or channel is reset due to
		 * errors or vgen_ldc_uninit() is invoked(vgen_stop).
		 */
		ASSERT(ldcp->htid == 0);
		ldcp->htid = timeout(vgen_hwatchdog, (caddr_t)ldcp,
		    drv_usectohz(vgen_hwd_interval * MICROSEC));

		/* Phase 1 involves negotiating the version */
		rv = vgen_send_version_negotiate(ldcp);
		break;

	case VH_PHASE2:
		rv = vgen_handshake_phase2(ldcp);
		break;

	case VH_PHASE3:
		rv = vgen_handshake_phase3(ldcp);
		break;

	case VH_PHASE4:
		rv = vgen_send_rdx_info(ldcp);
		break;

	case VH_DONE:

		ldcp->ldc_reset_count = 0;

		DBG1(vgenp, ldcp, "Handshake Done\n");

		/*
		 * The channel is up and handshake is done successfully. Now we
		 * can mark the channel link_state as 'up'. We also notify the
		 * stack if the channel is connected to vswitch.
		 */
		ldcp->link_state = LINK_STATE_UP;

		if (ldcp->portp == vgenp->vsw_portp) {
			/*
			 * If this channel(port) is connected to vsw,
			 * need to sync multicast table with vsw.
			 */
			rv = vgen_send_mcast_info(ldcp);
			if (rv != VGEN_SUCCESS)
				break;

			if (vgenp->pls_negotiated == B_FALSE) {
				/*
				 * We haven't negotiated with vswitch to get
				 * physical link state updates. We can update
				 * update the stack at this point as the
				 * channel to vswitch is up and the handshake
				 * is done successfully.
				 *
				 * If we have negotiated to get physical link
				 * state updates, then we won't notify the
				 * the stack here; we do that as soon as
				 * vswitch sends us the initial phys link state
				 * (see vgen_handle_physlink_info()).
				 */
				mutex_exit(&ldcp->cblock);
				vgen_link_update(vgenp, ldcp->link_state);
				mutex_enter(&ldcp->cblock);
			}
		}

		if (ldcp->htid != 0) {
			htid = ldcp->htid;
			ldcp->htid = 0;

			mutex_exit(&ldcp->cblock);
			(void) untimeout(htid);
			mutex_enter(&ldcp->cblock);
		}

		/*
		 * Check if mac layer should be notified to restart
		 * transmissions. This can happen if the channel got
		 * reset and while tx_blocked is set.
		 */
		mutex_enter(&ldcp->tclock);
		if (ldcp->tx_blocked) {
			vio_net_tx_update_t vtx_update =
			    ldcp->portp->vcb.vio_net_tx_update;

			ldcp->tx_blocked = B_FALSE;
			vtx_update(ldcp->portp->vhp);
		}
		mutex_exit(&ldcp->tclock);

		/* start transmit watchdog timer */
		ldcp->wd_tid = timeout(vgen_tx_watchdog, (caddr_t)ldcp,
		    drv_usectohz(vgen_txwd_interval * 1000));

		break;

	default:
		break;
	}

	return (rv);
}

/*
 * Check if the current handshake phase has completed successfully and
 * return the status.
 */
static int
vgen_handshake_done(vgen_ldc_t *ldcp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	uint32_t	hphase = ldcp->hphase;
	int		status = 0;

	switch (hphase) {

	case VH_PHASE1:
		/*
		 * Phase1 is done, if version negotiation
		 * completed successfully.
		 */
		status = ((ldcp->hstate & VER_NEGOTIATED) ==
		    VER_NEGOTIATED);
		break;

	case VH_PHASE2:
		/*
		 * Phase 2 is done, if attr info
		 * has been exchanged successfully.
		 */
		status = ((ldcp->hstate & ATTR_INFO_EXCHANGED) ==
		    ATTR_INFO_EXCHANGED);
		break;

	case VH_PHASE3:
		/*
		 * Phase 3 is done, if dring registration
		 * has been exchanged successfully.
		 */
		status = ((ldcp->hstate & DRING_INFO_EXCHANGED) ==
		    DRING_INFO_EXCHANGED);
		break;

	case VH_PHASE4:
		/* Phase 4 is done, if rdx msg has been exchanged */
		status = ((ldcp->hstate & RDX_EXCHANGED) ==
		    RDX_EXCHANGED);
		break;

	default:
		break;
	}

	if (status == 0) {
		return (VGEN_FAILURE);
	}
	DBG2(vgenp, ldcp, "PHASE(%d)\n", hphase);
	return (VGEN_SUCCESS);
}

/*
 * Link State Update Notes:
 * The link state of the channel connected to vswitch is reported as the link
 * state of the vnet device, by default. If the channel is down or reset, then
 * the link state is marked 'down'. If the channel is 'up' *and* handshake
 * between the vnet and vswitch is successful, then the link state is marked
 * 'up'. If physical network link state is desired, then the vnet device must
 * be configured to get physical link updates and the 'linkprop' property
 * in the virtual-device MD node indicates this. As part of attribute exchange
 * the vnet device negotiates with the vswitch to obtain physical link state
 * updates. If it successfully negotiates, vswitch sends an initial physlink
 * msg once the handshake is done and further whenever the physical link state
 * changes. Currently we don't have mac layer interfaces to report two distinct
 * link states - virtual and physical. Thus, if the vnet has been configured to
 * get physical link updates, then the link status will be reported as 'up'
 * only when both the virtual and physical links are up.
 */
static void
vgen_link_update(vgen_t *vgenp, link_state_t link_state)
{
	vnet_link_update(vgenp->vnetp, link_state);
}

/*
 * Handle a version info msg from the peer or an ACK/NACK from the peer
 * to a version info msg that we sent.
 */
static int
vgen_handle_version_negotiate(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t		*vgenp;
	vio_ver_msg_t	*vermsg = (vio_ver_msg_t *)tagp;
	int		ack = 0;
	int		failed = 0;
	int		idx;
	vgen_ver_t	*versions = ldcp->vgen_versions;
	int		rv = 0;

	vgenp = LDC_TO_VGEN(ldcp);
	DBG1(vgenp, ldcp, "enter\n");
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		/*  Cache sid of peer if this is the first time */
		if (ldcp->peer_sid == 0) {
			DBG2(vgenp, ldcp, "Caching peer_sid(%x)\n",
			    tagp->vio_sid);
			ldcp->peer_sid = tagp->vio_sid;
		}

		if (ldcp->hphase != VH_PHASE1) {
			/*
			 * If we are not already in VH_PHASE1, reset to
			 * pre-handshake state, and initiate handshake
			 * to the peer too.
			 */
			return (EINVAL);
		}

		ldcp->hstate |= VER_INFO_RCVD;

		/* save peer's requested values */
		ldcp->peer_hparams.ver_major = vermsg->ver_major;
		ldcp->peer_hparams.ver_minor = vermsg->ver_minor;
		ldcp->peer_hparams.dev_class = vermsg->dev_class;

		if ((vermsg->dev_class != VDEV_NETWORK) &&
		    (vermsg->dev_class != VDEV_NETWORK_SWITCH)) {
			/* unsupported dev_class, send NACK */

			DWARN(vgenp, ldcp, "Version Negotiation Failed\n");

			tagp->vio_subtype = VIO_SUBTYPE_NACK;
			tagp->vio_sid = ldcp->local_sid;
			/* send reply msg back to peer */
			rv = vgen_sendmsg(ldcp, (caddr_t)tagp,
			    sizeof (*vermsg), B_FALSE);
			if (rv != VGEN_SUCCESS) {
				return (rv);
			}
			return (VGEN_FAILURE);
		}

		DBG2(vgenp, ldcp, "VER_INFO_RCVD, ver(%d,%d)\n",
		    vermsg->ver_major,  vermsg->ver_minor);

		idx = 0;

		for (;;) {

			if (vermsg->ver_major > versions[idx].ver_major) {

				/* nack with next lower version */
				tagp->vio_subtype = VIO_SUBTYPE_NACK;
				vermsg->ver_major = versions[idx].ver_major;
				vermsg->ver_minor = versions[idx].ver_minor;
				break;
			}

			if (vermsg->ver_major == versions[idx].ver_major) {

				/* major version match - ACK version */
				tagp->vio_subtype = VIO_SUBTYPE_ACK;
				ack = 1;

				/*
				 * lower minor version to the one this endpt
				 * supports, if necessary
				 */
				if (vermsg->ver_minor >
				    versions[idx].ver_minor) {
					vermsg->ver_minor =
					    versions[idx].ver_minor;
					ldcp->peer_hparams.ver_minor =
					    versions[idx].ver_minor;
				}
				break;
			}

			idx++;

			if (idx == VGEN_NUM_VER) {

				/* no version match - send NACK */
				tagp->vio_subtype = VIO_SUBTYPE_NACK;
				vermsg->ver_major = 0;
				vermsg->ver_minor = 0;
				failed = 1;
				break;
			}

		}

		tagp->vio_sid = ldcp->local_sid;

		/* send reply msg back to peer */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*vermsg),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}

		if (ack) {
			ldcp->hstate |= VER_ACK_SENT;
			DBG2(vgenp, ldcp, "VER_ACK_SENT, ver(%d,%d) \n",
			    vermsg->ver_major, vermsg->ver_minor);
		}
		if (failed) {
			DWARN(vgenp, ldcp, "Negotiation Failed\n");
			return (VGEN_FAILURE);
		}
		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {

			/*  VER_ACK_SENT and VER_ACK_RCVD */

			/* local and peer versions match? */
			ASSERT((ldcp->local_hparams.ver_major ==
			    ldcp->peer_hparams.ver_major) &&
			    (ldcp->local_hparams.ver_minor ==
			    ldcp->peer_hparams.ver_minor));

			vgen_set_vnet_proto_ops(ldcp);

			/* move to the next phase */
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}

		break;

	case VIO_SUBTYPE_ACK:

		if (ldcp->hphase != VH_PHASE1) {
			/*  This should not happen. */
			DWARN(vgenp, ldcp, "Invalid Phase(%u)\n", ldcp->hphase);
			return (VGEN_FAILURE);
		}

		/* SUCCESS - we have agreed on a version */
		ldcp->local_hparams.ver_major = vermsg->ver_major;
		ldcp->local_hparams.ver_minor = vermsg->ver_minor;
		ldcp->hstate |= VER_ACK_RCVD;

		DBG2(vgenp, ldcp, "VER_ACK_RCVD, ver(%d,%d) \n",
		    vermsg->ver_major,  vermsg->ver_minor);

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {

			/*  VER_ACK_SENT and VER_ACK_RCVD */

			/* local and peer versions match? */
			ASSERT((ldcp->local_hparams.ver_major ==
			    ldcp->peer_hparams.ver_major) &&
			    (ldcp->local_hparams.ver_minor ==
			    ldcp->peer_hparams.ver_minor));

			vgen_set_vnet_proto_ops(ldcp);

			/* move to the next phase */
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}
		break;

	case VIO_SUBTYPE_NACK:

		if (ldcp->hphase != VH_PHASE1) {
			/*  This should not happen.  */
			DWARN(vgenp, ldcp, "VER_NACK_RCVD Invalid "
			"Phase(%u)\n", ldcp->hphase);
			return (VGEN_FAILURE);
		}

		DBG2(vgenp, ldcp, "VER_NACK_RCVD next ver(%d,%d)\n",
		    vermsg->ver_major, vermsg->ver_minor);

		/* check if version in NACK is zero */
		if (vermsg->ver_major == 0 && vermsg->ver_minor == 0) {
			/*
			 * Version Negotiation has failed.
			 */
			DWARN(vgenp, ldcp, "Version Negotiation Failed\n");
			return (VGEN_FAILURE);
		}

		idx = 0;

		for (;;) {

			if (vermsg->ver_major > versions[idx].ver_major) {
				/* select next lower version */

				ldcp->local_hparams.ver_major =
				    versions[idx].ver_major;
				ldcp->local_hparams.ver_minor =
				    versions[idx].ver_minor;
				break;
			}

			if (vermsg->ver_major == versions[idx].ver_major) {
				/* major version match */

				ldcp->local_hparams.ver_major =
				    versions[idx].ver_major;

				ldcp->local_hparams.ver_minor =
				    versions[idx].ver_minor;
				break;
			}

			idx++;

			if (idx == VGEN_NUM_VER) {
				/*
				 * no version match.
				 * Version Negotiation has failed.
				 */
				DWARN(vgenp, ldcp,
				    "Version Negotiation Failed\n");
				return (VGEN_FAILURE);
			}

		}

		rv = vgen_send_version_negotiate(ldcp);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}

		break;
	}

	DBG1(vgenp, ldcp, "exit\n");
	return (VGEN_SUCCESS);
}

static int
vgen_handle_attr_info(vgen_ldc_t *ldcp, vnet_attr_msg_t *msg)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t	*lp = &ldcp->local_hparams;
	vgen_hparams_t	*rp = &ldcp->peer_hparams;
	uint32_t	mtu;
	uint8_t		dring_mode;

	ldcp->hstate |= ATTR_INFO_RCVD;

	/* save peer's values */
	rp->mtu = msg->mtu;
	rp->addr = msg->addr;
	rp->addr_type = msg->addr_type;
	rp->xfer_mode = msg->xfer_mode;
	rp->ack_freq = msg->ack_freq;
	rp->dring_mode = msg->options;

	/*
	 * Process address type, ack frequency and transfer mode attributes.
	 */
	if ((msg->addr_type != ADDR_TYPE_MAC) ||
	    (msg->ack_freq > 64) ||
	    (msg->xfer_mode != lp->xfer_mode)) {
		return (VGEN_FAILURE);
	}

	/*
	 * Process dring mode attribute.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 6)) {
		/*
		 * Versions >= 1.6:
		 * Though we are operating in v1.6 mode, it is possible that
		 * RxDringData mode has been disabled either on this guest or
		 * on the peer guest. If so, we revert to pre v1.6 behavior of
		 * TxDring mode. But this must be agreed upon in both
		 * directions of attr exchange. We first determine the mode
		 * that can be negotiated.
		 */
		if ((msg->options & VIO_RX_DRING_DATA) != 0 &&
		    vgen_mapin_avail(ldcp) == B_TRUE) {
			/*
			 * We are capable of handling RxDringData AND the peer
			 * is also capable of it; we enable RxDringData mode on
			 * this channel.
			 */
			dring_mode = VIO_RX_DRING_DATA;
		} else if ((msg->options & VIO_TX_DRING) != 0) {
			/*
			 * If the peer is capable of TxDring mode, we
			 * negotiate TxDring mode on this channel.
			 */
			dring_mode = VIO_TX_DRING;
		} else {
			/*
			 * We support only VIO_TX_DRING and VIO_RX_DRING_DATA
			 * modes. We don't support VIO_RX_DRING mode.
			 */
			return (VGEN_FAILURE);
		}

		/*
		 * If we have received an ack for the attr info that we sent,
		 * then check if the dring mode matches what the peer had ack'd
		 * (saved in local hparams). If they don't match, we fail the
		 * handshake.
		 */
		if (ldcp->hstate & ATTR_ACK_RCVD) {
			if (msg->options != lp->dring_mode) {
				/* send NACK */
				return (VGEN_FAILURE);
			}
		} else {
			/*
			 * Save the negotiated dring mode in our attr
			 * parameters, so it gets sent in the attr info from us
			 * to the peer.
			 */
			lp->dring_mode = dring_mode;
		}

		/* save the negotiated dring mode in the msg to be replied */
		msg->options = dring_mode;
	}

	/*
	 * Process MTU attribute.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * Versions >= 1.4:
		 * Validate mtu of the peer is at least ETHERMAX. Then, the mtu
		 * is negotiated down to the minimum of our mtu and peer's mtu.
		 */
		if (msg->mtu < ETHERMAX) {
			return (VGEN_FAILURE);
		}

		mtu = MIN(msg->mtu, vgenp->max_frame_size);

		/*
		 * If we have received an ack for the attr info
		 * that we sent, then check if the mtu computed
		 * above matches the mtu that the peer had ack'd
		 * (saved in local hparams). If they don't
		 * match, we fail the handshake.
		 */
		if (ldcp->hstate & ATTR_ACK_RCVD) {
			if (mtu != lp->mtu) {
				/* send NACK */
				return (VGEN_FAILURE);
			}
		} else {
			/*
			 * Save the mtu computed above in our
			 * attr parameters, so it gets sent in
			 * the attr info from us to the peer.
			 */
			lp->mtu = mtu;
		}

		/* save the MIN mtu in the msg to be replied */
		msg->mtu = mtu;

	} else {
		/* versions < 1.4, mtu must match */
		if (msg->mtu != lp->mtu) {
			return (VGEN_FAILURE);
		}
	}

	return (VGEN_SUCCESS);
}

static int
vgen_handle_attr_ack(vgen_ldc_t *ldcp, vnet_attr_msg_t *msg)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	/*
	 * Process dring mode attribute.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 6)) {
		/*
		 * Versions >= 1.6:
		 * The ack msg sent by the peer contains the negotiated dring
		 * mode between our capability (that we had sent in our attr
		 * info) and the peer's capability.
		 */
		if (ldcp->hstate & ATTR_ACK_SENT) {
			/*
			 * If we have sent an ack for the attr info msg from
			 * the peer, check if the dring mode that was
			 * negotiated then (saved in local hparams) matches the
			 * mode that the peer has ack'd. If they don't match,
			 * we fail the handshake.
			 */
			if (lp->dring_mode != msg->options) {
				return (VGEN_FAILURE);
			}
		} else {
			if ((msg->options & lp->dring_mode) == 0) {
				/*
				 * Peer ack'd with a mode that we don't
				 * support; we fail the handshake.
				 */
				return (VGEN_FAILURE);
			}
			if ((msg->options & (VIO_TX_DRING|VIO_RX_DRING_DATA))
			    == (VIO_TX_DRING|VIO_RX_DRING_DATA)) {
				/*
				 * Peer must ack with only one negotiated mode.
				 * Otherwise fail handshake.
				 */
				return (VGEN_FAILURE);
			}

			/*
			 * Save the negotiated mode, so we can validate it when
			 * we receive attr info from the peer.
			 */
			lp->dring_mode = msg->options;
		}
	}

	/*
	 * Process Physical Link Update attribute.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 5) &&
	    ldcp->portp == vgenp->vsw_portp) {
		/*
		 * Versions >= 1.5:
		 * If the vnet device has been configured to get
		 * physical link state updates, check the corresponding
		 * bits in the ack msg, if the peer is vswitch.
		 */
		if (((lp->physlink_update & PHYSLINK_UPDATE_STATE_MASK) ==
		    PHYSLINK_UPDATE_STATE) &&
		    ((msg->physlink_update & PHYSLINK_UPDATE_STATE_MASK) ==
		    PHYSLINK_UPDATE_STATE_ACK)) {
			vgenp->pls_negotiated = B_TRUE;
		} else {
			vgenp->pls_negotiated = B_FALSE;
		}
	}

	/*
	 * Process MTU attribute.
	 */
	if (VGEN_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * Versions >= 1.4:
		 * The ack msg sent by the peer contains the minimum of
		 * our mtu (that we had sent in our attr info) and the
		 * peer's mtu.
		 *
		 * If we have sent an ack for the attr info msg from
		 * the peer, check if the mtu that was computed then
		 * (saved in local hparams) matches the mtu that the
		 * peer has ack'd. If they don't match, we fail the
		 * handshake.
		 */
		if (ldcp->hstate & ATTR_ACK_SENT) {
			if (lp->mtu != msg->mtu) {
				return (VGEN_FAILURE);
			}
		} else {
			/*
			 * If the mtu ack'd by the peer is > our mtu
			 * fail handshake. Otherwise, save the mtu, so
			 * we can validate it when we receive attr info
			 * from our peer.
			 */
			if (msg->mtu > lp->mtu) {
				return (VGEN_FAILURE);
			}
			if (msg->mtu <= lp->mtu) {
				lp->mtu = msg->mtu;
			}
		}
	}

	return (VGEN_SUCCESS);
}


/*
 * Handle an attribute info msg from the peer or an ACK/NACK from the peer
 * to an attr info msg that we sent.
 */
static int
vgen_handle_attr_msg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vnet_attr_msg_t	*msg = (vnet_attr_msg_t *)tagp;
	int		rv = 0;

	DBG1(vgenp, ldcp, "enter\n");
	if (ldcp->hphase != VH_PHASE2) {
		DWARN(vgenp, ldcp, "Rcvd ATTR_INFO subtype(%d),"
		" Invalid Phase(%u)\n",
		    tagp->vio_subtype, ldcp->hphase);
		return (VGEN_FAILURE);
	}
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		rv = vgen_handle_attr_info(ldcp, msg);
		if (rv == VGEN_SUCCESS) {
			tagp->vio_subtype = VIO_SUBTYPE_ACK;
		} else {
			tagp->vio_subtype = VIO_SUBTYPE_NACK;
		}
		tagp->vio_sid = ldcp->local_sid;

		/* send reply msg back to peer */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (*msg),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}

		if (tagp->vio_subtype == VIO_SUBTYPE_NACK) {
			DWARN(vgenp, ldcp, "ATTR_NACK_SENT");
			break;
		}

		ldcp->hstate |= ATTR_ACK_SENT;
		DBG2(vgenp, ldcp, "ATTR_ACK_SENT \n");
		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}

		break;

	case VIO_SUBTYPE_ACK:

		rv = vgen_handle_attr_ack(ldcp, msg);
		if (rv == VGEN_FAILURE) {
			break;
		}

		ldcp->hstate |= ATTR_ACK_RCVD;
		DBG2(vgenp, ldcp, "ATTR_ACK_RCVD \n");

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}
		break;

	case VIO_SUBTYPE_NACK:

		DBG2(vgenp, ldcp, "ATTR_NACK_RCVD \n");
		return (VGEN_FAILURE);
	}
	DBG1(vgenp, ldcp, "exit\n");
	return (VGEN_SUCCESS);
}

static int
vgen_handle_dring_reg_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int		rv = 0;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	DBG2(vgenp, ldcp, "DRING_INFO_RCVD");
	ldcp->hstate |= DRING_INFO_RCVD;

	if (VGEN_VER_GTEQ(ldcp, 1, 6) &&
	    (lp->dring_mode != ((vio_dring_reg_msg_t *)tagp)->options)) {
		/*
		 * The earlier version of Solaris vnet driver doesn't set the
		 * option (VIO_TX_DRING in its case) correctly in its dring reg
		 * message. We workaround that here by doing the check only
		 * for versions >= v1.6.
		 */
		DWARN(vgenp, ldcp,
		    "Rcvd dring reg option (%d), negotiated mode (%d)\n",
		    ((vio_dring_reg_msg_t *)tagp)->options, lp->dring_mode);
		return (VGEN_FAILURE);
	}

	/*
	 * Map dring exported by the peer.
	 */
	rv = vgen_map_dring(ldcp, (void *)tagp);
	if (rv != VGEN_SUCCESS) {
		return (rv);
	}

	/*
	 * Map data buffers exported by the peer if we are in RxDringData mode.
	 */
	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		rv = vgen_map_data(ldcp, (void *)tagp);
		if (rv != VGEN_SUCCESS) {
			vgen_unmap_dring(ldcp);
			return (rv);
		}
	}

	if (ldcp->peer_hparams.dring_ready == B_FALSE) {
		ldcp->peer_hparams.dring_ready = B_TRUE;
	}

	return (VGEN_SUCCESS);
}

static int
vgen_handle_dring_reg_ack(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	DBG2(vgenp, ldcp, "DRING_ACK_RCVD");
	ldcp->hstate |= DRING_ACK_RCVD;

	if (lp->dring_ready) {
		return (VGEN_SUCCESS);
	}

	/* save dring_ident acked by peer */
	lp->dring_ident = ((vio_dring_reg_msg_t *)tagp)->dring_ident;

	/* local dring is now ready */
	lp->dring_ready = B_TRUE;

	return (VGEN_SUCCESS);
}

/*
 * Handle a descriptor ring register msg from the peer or an ACK/NACK from
 * the peer to a dring register msg that we sent.
 */
static int
vgen_handle_dring_reg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	int		rv = 0;
	int		msgsize;
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	DBG1(vgenp, ldcp, "enter\n");
	if (ldcp->hphase < VH_PHASE2) {
		/* dring_info can be rcvd in any of the phases after Phase1 */
		DWARN(vgenp, ldcp,
		    "Rcvd DRING_INFO Subtype (%d), Invalid Phase(%u)\n",
		    tagp->vio_subtype, ldcp->hphase);
		return (VGEN_FAILURE);
	}

	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		rv = vgen_handle_dring_reg_info(ldcp, tagp);
		if (rv == VGEN_SUCCESS) {
			tagp->vio_subtype = VIO_SUBTYPE_ACK;
		} else {
			tagp->vio_subtype = VIO_SUBTYPE_NACK;
		}

		tagp->vio_sid = ldcp->local_sid;

		if (lp->dring_mode == VIO_RX_DRING_DATA) {
			msgsize =
			    VNET_DRING_REG_EXT_MSG_SIZE(ldcp->tx_data_ncookies);
		} else {
			msgsize = sizeof (vio_dring_reg_msg_t);
		}

		/* send reply msg back to peer */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, msgsize,
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}

		if (tagp->vio_subtype == VIO_SUBTYPE_NACK) {
			DWARN(vgenp, ldcp, "DRING_NACK_SENT");
			return (VGEN_FAILURE);
		}

		ldcp->hstate |= DRING_ACK_SENT;
		DBG2(vgenp, ldcp, "DRING_ACK_SENT");

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}
		break;

	case VIO_SUBTYPE_ACK:

		rv = vgen_handle_dring_reg_ack(ldcp, tagp);
		if (rv == VGEN_FAILURE) {
			return (rv);
		}

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}

		break;

	case VIO_SUBTYPE_NACK:

		DWARN(vgenp, ldcp, "DRING_NACK_RCVD");
		return (VGEN_FAILURE);
	}
	DBG1(vgenp, ldcp, "exit\n");
	return (VGEN_SUCCESS);
}

/*
 * Handle a rdx info msg from the peer or an ACK/NACK
 * from the peer to a rdx info msg that we sent.
 */
static int
vgen_handle_rdx_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int	rv = 0;
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	DBG1(vgenp, ldcp, "enter\n");
	if (ldcp->hphase != VH_PHASE4) {
		DWARN(vgenp, ldcp,
		    "Rcvd RDX_INFO Subtype (%d), Invalid Phase(%u)\n",
		    tagp->vio_subtype, ldcp->hphase);
		return (VGEN_FAILURE);
	}
	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:

		DBG2(vgenp, ldcp, "RDX_INFO_RCVD \n");
		ldcp->hstate |= RDX_INFO_RCVD;

		tagp->vio_subtype = VIO_SUBTYPE_ACK;
		tagp->vio_sid = ldcp->local_sid;
		/* send reply msg back to peer */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp, sizeof (vio_rdx_msg_t),
		    B_FALSE);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}

		ldcp->hstate |= RDX_ACK_SENT;
		DBG2(vgenp, ldcp, "RDX_ACK_SENT \n");

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}

		break;

	case VIO_SUBTYPE_ACK:

		ldcp->hstate |= RDX_ACK_RCVD;

		DBG2(vgenp, ldcp, "RDX_ACK_RCVD \n");

		if (vgen_handshake_done(ldcp) == VGEN_SUCCESS) {
			rv = vgen_handshake(vh_nextphase(ldcp));
			if (rv != 0) {
				return (rv);
			}
		}
		break;

	case VIO_SUBTYPE_NACK:

		DBG2(vgenp, ldcp, "RDX_NACK_RCVD \n");
		return (VGEN_FAILURE);
	}
	DBG1(vgenp, ldcp, "exit\n");
	return (VGEN_SUCCESS);
}

/* Handle ACK/NACK from vsw to a set multicast msg that we sent */
static int
vgen_handle_mcast_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vnet_mcast_msg_t	*msgp = (vnet_mcast_msg_t *)tagp;
	struct ether_addr	*addrp;
	int			count;
	int			i;

	DBG1(vgenp, ldcp, "enter\n");
	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:

		/* vnet shouldn't recv set mcast msg, only vsw handles it */
		DWARN(vgenp, ldcp, "rcvd SET_MCAST_INFO \n");
		break;

	case VIO_SUBTYPE_ACK:

		/* success adding/removing multicast addr */
		DBG1(vgenp, ldcp, "rcvd SET_MCAST_ACK \n");
		break;

	case VIO_SUBTYPE_NACK:

		DWARN(vgenp, ldcp, "rcvd SET_MCAST_NACK \n");
		if (!(msgp->set)) {
			/* multicast remove request failed */
			break;
		}

		/* multicast add request failed */
		for (count = 0; count < msgp->count; count++) {
			addrp = &(msgp->mca[count]);

			/* delete address from the table */
			for (i = 0; i < vgenp->mccount; i++) {
				if (ether_cmp(addrp,
				    &(vgenp->mctab[i])) == 0) {
					if (vgenp->mccount > 1) {
						int t = vgenp->mccount - 1;
						vgenp->mctab[i] =
						    vgenp->mctab[t];
					}
					vgenp->mccount--;
					break;
				}
			}
		}
		break;

	}
	DBG1(vgenp, ldcp, "exit\n");

	return (VGEN_SUCCESS);
}

/*
 * Physical link information message from the peer. Only vswitch should send
 * us this message; if the vnet device has been configured to get physical link
 * state updates. Note that we must have already negotiated this with the
 * vswitch during attribute exchange phase of handshake.
 */
static int
vgen_handle_physlink_info(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vnet_physlink_msg_t	*msgp = (vnet_physlink_msg_t *)tagp;
	link_state_t		link_state;
	int			rv;

	if (ldcp->portp != vgenp->vsw_portp) {
		/*
		 * drop the message and don't process; as we should
		 * receive physlink_info message from only vswitch.
		 */
		return (VGEN_SUCCESS);
	}

	if (vgenp->pls_negotiated == B_FALSE) {
		/*
		 * drop the message and don't process; as we should receive
		 * physlink_info message only if physlink update is enabled for
		 * the device and negotiated with vswitch.
		 */
		return (VGEN_SUCCESS);
	}

	switch (tagp->vio_subtype) {

	case VIO_SUBTYPE_INFO:

		if ((msgp->physlink_info & VNET_PHYSLINK_STATE_MASK) ==
		    VNET_PHYSLINK_STATE_UP) {
			link_state = LINK_STATE_UP;
		} else {
			link_state = LINK_STATE_DOWN;
		}

		if (vgenp->phys_link_state != link_state) {
			vgenp->phys_link_state = link_state;
			mutex_exit(&ldcp->cblock);

			/* Now update the stack */
			vgen_link_update(vgenp, link_state);

			mutex_enter(&ldcp->cblock);
		}

		tagp->vio_subtype = VIO_SUBTYPE_ACK;
		tagp->vio_sid = ldcp->local_sid;

		/* send reply msg back to peer */
		rv = vgen_sendmsg(ldcp, (caddr_t)tagp,
		    sizeof (vnet_physlink_msg_t), B_FALSE);
		if (rv != VGEN_SUCCESS) {
			return (rv);
		}
		break;

	case VIO_SUBTYPE_ACK:

		/* vnet shouldn't recv physlink acks */
		DWARN(vgenp, ldcp, "rcvd PHYSLINK_ACK \n");
		break;

	case VIO_SUBTYPE_NACK:

		/* vnet shouldn't recv physlink nacks */
		DWARN(vgenp, ldcp, "rcvd PHYSLINK_NACK \n");
		break;

	}
	DBG1(vgenp, ldcp, "exit\n");

	return (VGEN_SUCCESS);
}

/* handler for control messages received from the peer ldc end-point */
static int
vgen_handle_ctrlmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int	rv = 0;
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	DBG1(vgenp, ldcp, "enter\n");
	switch (tagp->vio_subtype_env) {

	case VIO_VER_INFO:
		rv = vgen_handle_version_negotiate(ldcp, tagp);
		break;

	case VIO_ATTR_INFO:
		rv = vgen_handle_attr_msg(ldcp, tagp);
		break;

	case VIO_DRING_REG:
		rv = vgen_handle_dring_reg(ldcp, tagp);
		break;

	case VIO_RDX:
		rv = vgen_handle_rdx_info(ldcp, tagp);
		break;

	case VNET_MCAST_INFO:
		rv = vgen_handle_mcast_info(ldcp, tagp);
		break;

	case VIO_DDS_INFO:
		/*
		 * If we are in the process of resetting the vswitch channel,
		 * drop the dds message. A new handshake will be initiated
		 * when the channel comes back up after the reset and dds
		 * negotiation can then continue.
		 */
		if (ldcp->reset_in_progress == 1) {
			break;
		}
		rv = vgen_dds_rx(ldcp, tagp);
		break;

	case VNET_PHYSLINK_INFO:
		rv = vgen_handle_physlink_info(ldcp, tagp);
		break;
	}

	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}

/* handler for error messages received from the peer ldc end-point */
static void
vgen_handle_errmsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	_NOTE(ARGUNUSED(ldcp, tagp))
}

/*
 * This function handles raw pkt data messages received over the channel.
 * Currently, only priority-eth-type frames are received through this mechanism.
 * In this case, the frame(data) is present within the message itself which
 * is copied into an mblk before sending it up the stack.
 */
void
vgen_handle_pkt_data(void *arg1, void *arg2, uint32_t msglen)
{
	vgen_ldc_t		*ldcp = (vgen_ldc_t *)arg1;
	vio_raw_data_msg_t	*pkt	= (vio_raw_data_msg_t *)arg2;
	uint32_t		size;
	mblk_t			*mp;
	vio_mblk_t		*vmp;
	vio_net_rx_cb_t		vrx_cb = NULL;
	vgen_t			*vgenp = LDC_TO_VGEN(ldcp);
	vgen_stats_t		*statsp = &ldcp->stats;
	vgen_hparams_t		*lp = &ldcp->local_hparams;
	uint_t			dring_mode = lp->dring_mode;

	ASSERT(MUTEX_HELD(&ldcp->cblock));

	mutex_exit(&ldcp->cblock);

	size = msglen - VIO_PKT_DATA_HDRSIZE;
	if (size < ETHERMIN || size > lp->mtu) {
		(void) atomic_inc_32(&statsp->rx_pri_fail);
		mutex_enter(&ldcp->cblock);
		return;
	}

	vmp = vio_multipool_allocb(&ldcp->vmp, size);
	if (vmp == NULL) {
		mp = allocb(size, BPRI_MED);
		if (mp == NULL) {
			(void) atomic_inc_32(&statsp->rx_pri_fail);
			DWARN(vgenp, ldcp, "allocb failure, "
			    "unable to process priority frame\n");
			mutex_enter(&ldcp->cblock);
			return;
		}
	} else {
		mp = vmp->mp;
	}

	/* copy the frame from the payload of raw data msg into the mblk */
	bcopy(pkt->data, mp->b_rptr, size);
	mp->b_wptr = mp->b_rptr + size;

	if (vmp != NULL) {
		vmp->state = VIO_MBLK_HAS_DATA;
	}

	/* update stats */
	(void) atomic_inc_64(&statsp->rx_pri_packets);
	(void) atomic_add_64(&statsp->rx_pri_bytes, size);

	/*
	 * If polling is currently enabled, add the packet to the priority
	 * packets list and return. It will be picked up by the polling thread.
	 */
	if (dring_mode == VIO_RX_DRING_DATA) {
		mutex_enter(&ldcp->rxlock);
	} else {
		mutex_enter(&ldcp->pollq_lock);
	}

	if (ldcp->polling_on == B_TRUE) {
		if (ldcp->rx_pri_tail != NULL) {
			ldcp->rx_pri_tail->b_next = mp;
		} else {
			ldcp->rx_pri_head = ldcp->rx_pri_tail = mp;
		}
	} else {
		vrx_cb = ldcp->portp->vcb.vio_net_rx_cb;
	}

	if (dring_mode == VIO_RX_DRING_DATA) {
		mutex_exit(&ldcp->rxlock);
	} else {
		mutex_exit(&ldcp->pollq_lock);
	}

	if (vrx_cb != NULL) {
		vrx_cb(ldcp->portp->vhp, mp);
	}

	mutex_enter(&ldcp->cblock);
}

/*
 * dummy pkt data handler function for vnet protocol version 1.0
 */
static void
vgen_handle_pkt_data_nop(void *arg1, void *arg2, uint32_t msglen)
{
	_NOTE(ARGUNUSED(arg1, arg2, msglen))
}

/* handler for data messages received from the peer ldc end-point */
static int
vgen_handle_datamsg(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp, uint32_t msglen)
{
	int		rv = 0;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);
	vgen_hparams_t	*lp = &ldcp->local_hparams;

	DBG1(vgenp, ldcp, "enter\n");

	if (ldcp->hphase != VH_DONE) {
		return (0);
	}

	/*
	 * We check the data msg seqnum. This is needed only in TxDring mode.
	 */
	if (lp->dring_mode == VIO_TX_DRING &&
	    tagp->vio_subtype == VIO_SUBTYPE_INFO) {
		rv = vgen_check_datamsg_seq(ldcp, tagp);
		if (rv != 0) {
			return (rv);
		}
	}

	switch (tagp->vio_subtype_env) {
	case VIO_DRING_DATA:
		rv = ldcp->rx_dringdata((void *)ldcp, (void *)tagp);
		break;

	case VIO_PKT_DATA:
		ldcp->rx_pktdata((void *)ldcp, (void *)tagp, msglen);
		break;
	default:
		break;
	}

	DBG1(vgenp, ldcp, "exit rv(%d)\n", rv);
	return (rv);
}


static int
vgen_ldc_reset(vgen_ldc_t *ldcp, vgen_caller_t caller)
{
	int	rv;

	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		ASSERT(MUTEX_HELD(&ldcp->cblock));
	}

	/* Set the flag to indicate reset is in progress */
	if (atomic_cas_uint(&ldcp->reset_in_progress, 0, 1) != 0) {
		/* another thread is already in the process of resetting */
		return (EBUSY);
	}

	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		mutex_exit(&ldcp->cblock);
	}

	rv = vgen_process_reset(ldcp, VGEN_FLAG_NEED_LDCRESET);

	if (caller == VGEN_LDC_CB || caller == VGEN_MSG_THR) {
		mutex_enter(&ldcp->cblock);
	}

	return (rv);
}

static void
vgen_ldc_up(vgen_ldc_t *ldcp)
{
	int		rv;
	uint32_t	retries = 0;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	ASSERT(MUTEX_HELD(&ldcp->cblock));

	/*
	 * If the channel has been reset max # of times, without successfully
	 * completing handshake, stop and do not bring the channel up.
	 */
	if (ldcp->ldc_reset_count == vgen_ldc_max_resets) {
		cmn_err(CE_WARN, "!vnet%d: exceeded number of permitted"
		    " handshake attempts (%d) on channel %ld",
		    vgenp->instance, vgen_ldc_max_resets, ldcp->ldc_id);
		return;
	}
	ldcp->ldc_reset_count++;

	do {
		rv = ldc_up(ldcp->ldc_handle);
		if ((rv != 0) && (rv == EWOULDBLOCK)) {
			drv_usecwait(VGEN_LDC_UP_DELAY);
		}
		if (retries++ >= vgen_ldcup_retries)
			break;
	} while (rv == EWOULDBLOCK);

	if (rv != 0) {
		DWARN(vgenp, ldcp, "ldc_up err rv(%d)\n", rv);
	}
}

int
vgen_enable_intr(void *arg)
{
	uint32_t		end_ix;
	vio_dring_msg_t		msg;
	vgen_port_t		*portp = (vgen_port_t *)arg;
	vgen_ldc_t		*ldcp = portp->ldcp;
	vgen_hparams_t		*lp = &ldcp->local_hparams;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		mutex_enter(&ldcp->rxlock);

		ldcp->polling_on = B_FALSE;
		/*
		 * We send a stopped message to peer (sender) as we are turning
		 * off polled mode. This effectively restarts data interrupts
		 * by allowing the peer to send further dring data msgs to us.
		 */
		end_ix = ldcp->next_rxi;
		DECR_RXI(end_ix, ldcp);
		msg.dring_ident = ldcp->peer_hparams.dring_ident;
		(void) vgen_send_dringack_shm(ldcp, (vio_msg_tag_t *)&msg,
		    VNET_START_IDX_UNSPEC, end_ix, VIO_DP_STOPPED);

		mutex_exit(&ldcp->rxlock);
	} else {
		mutex_enter(&ldcp->pollq_lock);
		ldcp->polling_on = B_FALSE;
		mutex_exit(&ldcp->pollq_lock);
	}

	return (0);
}

int
vgen_disable_intr(void *arg)
{
	vgen_port_t		*portp = (vgen_port_t *)arg;
	vgen_ldc_t		*ldcp = portp->ldcp;
	vgen_hparams_t		*lp = &ldcp->local_hparams;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		mutex_enter(&ldcp->rxlock);
		ldcp->polling_on = B_TRUE;
		mutex_exit(&ldcp->rxlock);
	} else {
		mutex_enter(&ldcp->pollq_lock);
		ldcp->polling_on = B_TRUE;
		mutex_exit(&ldcp->pollq_lock);
	}

	return (0);
}

mblk_t *
vgen_rx_poll(void *arg, int bytes_to_pickup)
{
	vgen_port_t		*portp = (vgen_port_t *)arg;
	vgen_ldc_t		*ldcp = portp->ldcp;
	vgen_hparams_t		*lp = &ldcp->local_hparams;
	mblk_t			*mp = NULL;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		mp = vgen_poll_rcv_shm(ldcp, bytes_to_pickup);
	} else {
		mp = vgen_poll_rcv(ldcp, bytes_to_pickup);
	}

	return (mp);
}

/* transmit watchdog timeout handler */
static void
vgen_tx_watchdog(void *arg)
{
	vgen_ldc_t	*ldcp;
	vgen_t		*vgenp;
	int		rv;
	boolean_t	tx_blocked;
	clock_t		tx_blocked_lbolt;

	ldcp = (vgen_ldc_t *)arg;
	vgenp = LDC_TO_VGEN(ldcp);

	tx_blocked = ldcp->tx_blocked;
	tx_blocked_lbolt = ldcp->tx_blocked_lbolt;

	if (vgen_txwd_timeout &&
	    (tx_blocked == B_TRUE) &&
	    ((ddi_get_lbolt() - tx_blocked_lbolt) >
	    drv_usectohz(vgen_txwd_timeout * 1000))) {
		/*
		 * Something is wrong; the peer is not picking up the packets
		 * in the transmit dring. We now go ahead and reset the channel
		 * to break out of this condition.
		 */
		DWARN(vgenp, ldcp, "transmit timeout lbolt(%lx), "
		    "tx_blocked_lbolt(%lx)\n",
		    ddi_get_lbolt(), tx_blocked_lbolt);

#ifdef DEBUG
		if (vgen_inject_error(ldcp, VGEN_ERR_TXTIMEOUT)) {
			/* tx timeout triggered for debugging */
			vgen_inject_err_flag &= ~(VGEN_ERR_TXTIMEOUT);
		}
#endif

		/*
		 * Clear tid before invoking vgen_ldc_reset(). Otherwise,
		 * it will result in a deadlock when vgen_process_reset() tries
		 * to untimeout() on seeing a non-zero tid, but it is being
		 * invoked by the timer itself in this case.
		 */
		mutex_enter(&ldcp->cblock);
		if (ldcp->wd_tid == 0) {
			/* Cancelled by vgen_process_reset() */
			mutex_exit(&ldcp->cblock);
			return;
		}
		ldcp->wd_tid = 0;
		mutex_exit(&ldcp->cblock);

		/*
		 * Now reset the channel.
		 */
		rv = vgen_ldc_reset(ldcp, VGEN_OTHER);
		if (rv == 0) {
			/*
			 * We have successfully reset the channel. If we are
			 * in tx flow controlled state, clear it now and enable
			 * transmit in the upper layer.
			 */
			if (ldcp->tx_blocked) {
				vio_net_tx_update_t vtx_update =
				    ldcp->portp->vcb.vio_net_tx_update;

				ldcp->tx_blocked = B_FALSE;
				vtx_update(ldcp->portp->vhp);
			}
		}

		/*
		 * Channel has been reset by us or some other thread is already
		 * in the process of resetting. In either case, we return
		 * without restarting the timer. When handshake completes and
		 * the channel is ready for data transmit/receive we start a
		 * new watchdog timer.
		 */
		return;
	}

restart_timer:
	/* Restart the timer */
	mutex_enter(&ldcp->cblock);
	if (ldcp->wd_tid == 0) {
		/* Cancelled by vgen_process_reset() */
		mutex_exit(&ldcp->cblock);
		return;
	}
	ldcp->wd_tid = timeout(vgen_tx_watchdog, (caddr_t)ldcp,
	    drv_usectohz(vgen_txwd_interval * 1000));
	mutex_exit(&ldcp->cblock);
}

/* Handshake watchdog timeout handler */
static void
vgen_hwatchdog(void *arg)
{
	vgen_ldc_t	*ldcp = (vgen_ldc_t *)arg;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	DWARN(vgenp, ldcp, "handshake timeout phase(%x) state(%x)\n",
	    ldcp->hphase, ldcp->hstate);

	mutex_enter(&ldcp->cblock);
	if (ldcp->htid == 0) {
		/* Cancelled by vgen_process_reset() */
		mutex_exit(&ldcp->cblock);
		return;
	}
	ldcp->htid = 0;
	mutex_exit(&ldcp->cblock);

	/*
	 * Something is wrong; handshake with the peer seems to be hung. We now
	 * go ahead and reset the channel to break out of this condition.
	 */
	(void) vgen_ldc_reset(ldcp, VGEN_OTHER);
}

/* Check if the session id in the received message is valid */
static int
vgen_check_sid(vgen_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vgen_t	*vgenp = LDC_TO_VGEN(ldcp);

	if (tagp->vio_sid != ldcp->peer_sid) {
		DWARN(vgenp, ldcp, "sid mismatch: expected(%x), rcvd(%x)\n",
		    ldcp->peer_sid, tagp->vio_sid);
		return (VGEN_FAILURE);
	}
	else
		return (VGEN_SUCCESS);
}

/*
 * Initialize the common part of dring registration
 * message; used in both TxDring and RxDringData modes.
 */
static void
vgen_init_dring_reg_msg(vgen_ldc_t *ldcp, vio_dring_reg_msg_t *msg,
    uint8_t option)
{
	vio_msg_tag_t		*tagp;

	tagp = &msg->tag;
	tagp->vio_msgtype = VIO_TYPE_CTRL;
	tagp->vio_subtype = VIO_SUBTYPE_INFO;
	tagp->vio_subtype_env = VIO_DRING_REG;
	tagp->vio_sid = ldcp->local_sid;

	/* get dring info msg payload from ldcp->local */
	bcopy(&(ldcp->local_hparams.dring_cookie), &(msg->cookie[0]),
	    sizeof (ldc_mem_cookie_t));
	msg->ncookies = ldcp->local_hparams.dring_ncookies;
	msg->num_descriptors = ldcp->local_hparams.num_desc;
	msg->descriptor_size = ldcp->local_hparams.desc_size;

	msg->options = option;

	/*
	 * dring_ident is set to 0. After mapping the dring, peer sets this
	 * value and sends it in the ack, which is saved in
	 * vgen_handle_dring_reg().
	 */
	msg->dring_ident = 0;
}

static int
vgen_mapin_avail(vgen_ldc_t *ldcp)
{
	int		rv;
	ldc_info_t	info;
	uint64_t	mapin_sz_req;
	uint64_t	dblk_sz;
	vgen_t		*vgenp = LDC_TO_VGEN(ldcp);

	rv = ldc_info(ldcp->ldc_handle, &info);
	if (rv != 0) {
		return (B_FALSE);
	}

	dblk_sz = RXDRING_DBLK_SZ(vgenp->max_frame_size);
	mapin_sz_req = (VGEN_RXDRING_NRBUFS * dblk_sz);

	if (info.direct_map_size_max >= mapin_sz_req) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

#if DEBUG

/*
 * Print debug messages - set to 0xf to enable all msgs
 */
void
vgen_debug_printf(const char *fname, vgen_t *vgenp,
    vgen_ldc_t *ldcp, const char *fmt, ...)
{
	char	buf[256];
	char	*bufp = buf;
	va_list	ap;

	if ((vgenp != NULL) && (vgenp->vnetp != NULL)) {
		(void) sprintf(bufp, "vnet%d:",
		    ((vnet_t *)(vgenp->vnetp))->instance);
		bufp += strlen(bufp);
	}
	if (ldcp != NULL) {
		(void) sprintf(bufp, "ldc(%ld):", ldcp->ldc_id);
		bufp += strlen(bufp);
	}
	(void) sprintf(bufp, "%s: ", fname);
	bufp += strlen(bufp);

	va_start(ap, fmt);
	(void) vsprintf(bufp, fmt, ap);
	va_end(ap);

	if ((ldcp == NULL) ||(vgendbg_ldcid == -1) ||
	    (vgendbg_ldcid == ldcp->ldc_id)) {
		cmn_err(CE_CONT, "%s\n", buf);
	}
}
#endif

#ifdef	VNET_IOC_DEBUG

static void
vgen_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;
	vgen_port_t	*portp;
	enum		ioc_reply {
			IOC_INVAL = -1,		/* bad, NAK with EINVAL */
			IOC_ACK			/* OK, just send ACK    */
	}		status;
	int		rv;

	iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	iocp->ioc_error = 0;
	portp = (vgen_port_t *)arg;

	if (portp == NULL) {
		status = IOC_INVAL;
		goto vgen_ioc_exit;
	}

	mutex_enter(&portp->lock);

	switch (iocp->ioc_cmd) {

	case VNET_FORCE_LINK_DOWN:
	case VNET_FORCE_LINK_UP:
		rv = vgen_force_link_state(portp, iocp->ioc_cmd);
		(rv == 0) ? (status = IOC_ACK) : (status = IOC_INVAL);
		break;

	default:
		status = IOC_INVAL;
		break;

	}

	mutex_exit(&portp->lock);

vgen_ioc_exit:

	switch (status) {
	default:
	case IOC_INVAL:
		/* Error, reply with a NAK and EINVAL error */
		miocnak(q, mp, 0, EINVAL);
		break;
	case IOC_ACK:
		/* OK, reply with an ACK */
		miocack(q, mp, 0, 0);
		break;
	}
}

static int
vgen_force_link_state(vgen_port_t *portp, int cmd)
{
	ldc_status_t	istatus;
	int		rv;
	vgen_ldc_t	*ldcp = portp->ldcp;
	vgen_t		*vgenp = portp->vgenp;

	mutex_enter(&ldcp->cblock);

	switch (cmd) {

	case VNET_FORCE_LINK_DOWN:
		(void) ldc_down(ldcp->ldc_handle);
		ldcp->link_down_forced = B_TRUE;
		break;

	case VNET_FORCE_LINK_UP:
		vgen_ldc_up(ldcp);
		ldcp->link_down_forced = B_FALSE;

		if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
			DWARN(vgenp, ldcp, "ldc_status err\n");
		} else {
			ldcp->ldc_status = istatus;
		}

		/* if channel is already UP - restart handshake */
		if (ldcp->ldc_status == LDC_UP) {
			vgen_handle_evt_up(ldcp);
		}
		break;

	}

	mutex_exit(&ldcp->cblock);

	return (0);
}

#else

static void
vgen_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	vgen_port_t	*portp;

	portp = (vgen_port_t *)arg;

	if (portp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	miocnak(q, mp, 0, ENOTSUP);
}

#endif
