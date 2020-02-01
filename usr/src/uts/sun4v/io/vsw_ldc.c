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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/strsun.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <net/if.h>
#include <sys/varargs.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/taskq.h>
#include <sys/note.h>
#include <sys/mach_descrip.h>
#include <sys/mdeg.h>
#include <sys/ldc.h>
#include <sys/vsw_fdb.h>
#include <sys/vsw.h>
#include <sys/vio_mailbox.h>
#include <sys/vnet_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/vio_util.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include <sys/callb.h>
#include <sys/vlan.h>

/* Port add/deletion/etc routines */
static	void vsw_port_delete(vsw_port_t *port);
static	int vsw_ldc_attach(vsw_port_t *port, uint64_t ldc_id);
static	void vsw_ldc_detach(vsw_ldc_t *ldcp);
static	int vsw_ldc_init(vsw_ldc_t *ldcp);
static	void vsw_ldc_uninit(vsw_ldc_t *ldcp);
static	void vsw_ldc_drain(vsw_ldc_t *ldcp);
static	void vsw_drain_port_taskq(vsw_port_t *port);
static	void vsw_marker_task(void *);
static	int vsw_plist_del_node(vsw_t *, vsw_port_t *port);
void vsw_detach_ports(vsw_t *vswp);
int vsw_port_add(vsw_t *vswp, md_t *mdp, mde_cookie_t *node);
mcst_addr_t *vsw_del_addr(uint8_t devtype, void *arg, uint64_t addr);
int vsw_port_detach(vsw_t *vswp, int p_instance);
int vsw_portsend(vsw_port_t *port, mblk_t *mp);
int vsw_port_attach(vsw_port_t *portp);
vsw_port_t *vsw_lookup_port(vsw_t *vswp, int p_instance);
void vsw_vlan_unaware_port_reset(vsw_port_t *portp);
void vsw_hio_port_reset(vsw_port_t *portp, boolean_t immediate);
void vsw_reset_ports(vsw_t *vswp);
void vsw_port_reset(vsw_port_t *portp);
void vsw_physlink_update_ports(vsw_t *vswp);
static	void vsw_port_physlink_update(vsw_port_t *portp);

/* Interrupt routines */
static	uint_t vsw_ldc_cb(uint64_t cb, caddr_t arg);

/* Handshake routines */
static	void vsw_ldc_reinit(vsw_ldc_t *);
static	void vsw_conn_task(void *);
static	int vsw_check_flag(vsw_ldc_t *, int, uint64_t);
static	void vsw_next_milestone(vsw_ldc_t *);
static	int vsw_supported_version(vio_ver_msg_t *);
static	void vsw_set_vnet_proto_ops(vsw_ldc_t *ldcp);
static	void vsw_reset_vnet_proto_ops(vsw_ldc_t *ldcp);
void vsw_process_conn_evt(vsw_ldc_t *, uint16_t);

/* Data processing routines */
void vsw_process_pkt(void *);
static void vsw_dispatch_ctrl_task(vsw_ldc_t *, void *, vio_msg_tag_t *, int);
static void vsw_process_ctrl_pkt(void *);
static void vsw_process_ctrl_ver_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_attr_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_mcst_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_reg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_unreg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_rdx_pkt(vsw_ldc_t *, void *);
static void vsw_process_physlink_msg(vsw_ldc_t *, void *);
static void vsw_process_data_pkt(vsw_ldc_t *, void *, vio_msg_tag_t *,
	uint32_t);
static void vsw_process_pkt_data_nop(void *, void *, uint32_t);
static void vsw_process_pkt_data(void *, void *, uint32_t);
static void vsw_process_data_ibnd_pkt(vsw_ldc_t *, void *);
static void vsw_process_err_pkt(vsw_ldc_t *, void *, vio_msg_tag_t *);
static void vsw_process_evt_read(vsw_ldc_t *ldcp);
static void vsw_ldc_rcv(vsw_ldc_t *ldcp);

/* Switching/data transmit routines */
static	int vsw_descrsend(vsw_ldc_t *, mblk_t *);
static void vsw_ldcsend_pkt(vsw_ldc_t *ldcp, mblk_t *mp);
static int vsw_ldcsend(vsw_ldc_t *ldcp, mblk_t *mp, uint32_t retries);
static int vsw_ldctx_pri(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count);
static int vsw_ldctx(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count);

/* Packet creation routines */
static void vsw_send_ver(void *);
static void vsw_send_attr(vsw_ldc_t *);
static void vsw_send_dring_info(vsw_ldc_t *);
static void vsw_send_rdx(vsw_ldc_t *);
static void vsw_send_physlink_msg(vsw_ldc_t *ldcp, link_state_t plink_state);

/* Dring routines */
static void vsw_create_privring(vsw_ldc_t *);
static dring_info_t *vsw_map_dring(vsw_ldc_t *ldcp, void *pkt);
static void vsw_unmap_dring(vsw_ldc_t *ldcp);
static void vsw_destroy_dring(vsw_ldc_t *ldcp);
static void vsw_free_lane_resources(vsw_ldc_t *, uint64_t);
static int vsw_map_data(vsw_ldc_t *ldcp, dring_info_t *dp, void *pkt);
static void vsw_set_lane_attr(vsw_t *, lane_t *);
dring_info_t *vsw_map_dring_cmn(vsw_ldc_t *ldcp,
    vio_dring_reg_msg_t *dring_pkt);
static int vsw_mapin_avail(vsw_ldc_t *ldcp);

/* tx/msg/rcv thread routines */
static void vsw_stop_tx_thread(vsw_ldc_t *ldcp);
static void vsw_ldc_tx_worker(void *arg);

/* Misc support routines */
static void vsw_save_lmacaddr(vsw_t *vswp, uint64_t macaddr);
static int vsw_get_same_dest_list(struct ether_header *ehp,
    mblk_t **rhead, mblk_t **rtail, mblk_t **mpp);
static mblk_t *vsw_dupmsgchain(mblk_t *mp);

/* Debugging routines */
static void dump_flags(uint64_t);
static void display_state(void);
static void display_lane(lane_t *);
static void display_ring(dring_info_t *);

/*
 * Functions imported from other files.
 */
extern int vsw_set_hw(vsw_t *, vsw_port_t *, int);
extern void vsw_unset_hw(vsw_t *, vsw_port_t *, int);
extern int vsw_add_rem_mcst(vnet_mcast_msg_t *mcst_pkt, vsw_port_t *port);
extern void vsw_del_mcst_port(vsw_port_t *port);
extern int vsw_add_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg);
extern int vsw_del_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg);
extern void vsw_fdbe_add(vsw_t *vswp, void *port);
extern void vsw_fdbe_del(vsw_t *vswp, struct ether_addr *eaddr);
extern void vsw_create_vlans(void *arg, int type);
extern void vsw_destroy_vlans(void *arg, int type);
extern void vsw_vlan_add_ids(void *arg, int type);
extern void vsw_vlan_remove_ids(void *arg, int type);
extern boolean_t vsw_frame_lookup_vid(void *arg, int caller,
	struct ether_header *ehp, uint16_t *vidp);
extern mblk_t *vsw_vlan_frame_pretag(void *arg, int type, mblk_t *mp);
extern uint32_t vsw_vlan_frame_untag(void *arg, int type, mblk_t **np,
	mblk_t **npt);
extern boolean_t vsw_vlan_lookup(mod_hash_t *vlan_hashp, uint16_t vid);
extern void vsw_hio_start(vsw_t *vswp, vsw_ldc_t *ldcp);
extern void vsw_hio_stop(vsw_t *vswp, vsw_ldc_t *ldcp);
extern void vsw_process_dds_msg(vsw_t *vswp, vsw_ldc_t *ldcp, void *msg);
extern void vsw_hio_stop_port(vsw_port_t *portp);
extern void vsw_publish_macaddr(vsw_t *vswp, vsw_port_t *portp);
extern int vsw_mac_client_init(vsw_t *vswp, vsw_port_t *port, int type);
extern void vsw_mac_client_cleanup(vsw_t *vswp, vsw_port_t *port, int type);
extern void vsw_destroy_rxpools(void *arg);
extern void vsw_stop_msg_thread(vsw_ldc_t *ldcp);
extern int vsw_send_msg(vsw_ldc_t *, void *, int, boolean_t);
extern int vsw_dringsend(vsw_ldc_t *, mblk_t *);
extern int vsw_reclaim_dring(dring_info_t *dp, int start);
extern int vsw_dring_find_free_desc(dring_info_t *, vsw_private_desc_t **,
    int *);
extern vio_dring_reg_msg_t *vsw_create_tx_dring_info(vsw_ldc_t *);
extern int vsw_setup_tx_dring(vsw_ldc_t *ldcp, dring_info_t *dp);
extern void vsw_destroy_tx_dring(vsw_ldc_t *ldcp);
extern dring_info_t *vsw_map_rx_dring(vsw_ldc_t *ldcp, void *pkt);
extern void vsw_unmap_rx_dring(vsw_ldc_t *ldcp);
extern void vsw_ldc_msg_worker(void *arg);
extern void vsw_process_dringdata(void *, void *);
extern vio_dring_reg_msg_t *vsw_create_rx_dring_info(vsw_ldc_t *);
extern void vsw_destroy_rx_dring(vsw_ldc_t *ldcp);
extern dring_info_t *vsw_map_tx_dring(vsw_ldc_t *ldcp, void *pkt);
extern void vsw_unmap_tx_dring(vsw_ldc_t *ldcp);
extern void vsw_ldc_rcv_worker(void *arg);
extern void vsw_stop_rcv_thread(vsw_ldc_t *ldcp);
extern int vsw_dringsend_shm(vsw_ldc_t *, mblk_t *);
extern void vsw_process_dringdata_shm(void *, void *);

/*
 * Tunables used in this file.
 */
extern int vsw_num_handshakes;
extern int vsw_ldc_tx_delay;
extern int vsw_ldc_tx_retries;
extern int vsw_ldc_retries;
extern int vsw_ldc_delay;
extern boolean_t vsw_ldc_rxthr_enabled;
extern boolean_t vsw_ldc_txthr_enabled;
extern uint32_t vsw_num_descriptors;
extern uint8_t  vsw_dring_mode;
extern uint32_t vsw_max_tx_qcount;
extern boolean_t vsw_obp_ver_proto_workaround;
extern uint32_t vsw_publish_macaddr_count;
extern uint32_t vsw_nrbufs_factor;

#define	LDC_ENTER_LOCK(ldcp)	\
				mutex_enter(&((ldcp)->ldc_cblock));\
				mutex_enter(&((ldcp)->ldc_rxlock));\
				mutex_enter(&((ldcp)->ldc_txlock));
#define	LDC_EXIT_LOCK(ldcp)	\
				mutex_exit(&((ldcp)->ldc_txlock));\
				mutex_exit(&((ldcp)->ldc_rxlock));\
				mutex_exit(&((ldcp)->ldc_cblock));

#define	VSW_VER_EQ(ldcp, major, minor)	\
	((ldcp)->lane_out.ver_major == (major) &&	\
	    (ldcp)->lane_out.ver_minor == (minor))

#define	VSW_VER_LT(ldcp, major, minor)	\
	(((ldcp)->lane_out.ver_major < (major)) ||	\
	    ((ldcp)->lane_out.ver_major == (major) &&	\
	    (ldcp)->lane_out.ver_minor < (minor)))

#define	VSW_VER_GTEQ(ldcp, major, minor)	\
	(((ldcp)->lane_out.ver_major > (major)) ||	\
	    ((ldcp)->lane_out.ver_major == (major) &&	\
	    (ldcp)->lane_out.ver_minor >= (minor)))

#define	VSW_VER_LTEQ(ldcp, major, minor)	\
	(((ldcp)->lane_out.ver_major < (major)) ||	\
	    ((ldcp)->lane_out.ver_major == (major) &&	\
	    (ldcp)->lane_out.ver_minor <= (minor)))

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
static	ver_sup_t	vsw_versions[] = { {1, 6} };

/*
 * For the moment the state dump routines have their own
 * private flag.
 */
#define	DUMP_STATE	0

#if DUMP_STATE

#define	DUMP_TAG(tag) \
{			\
	D1(NULL, "DUMP_TAG: type 0x%llx", (tag).vio_msgtype); \
	D1(NULL, "DUMP_TAG: stype 0x%llx", (tag).vio_subtype);	\
	D1(NULL, "DUMP_TAG: senv 0x%llx", (tag).vio_subtype_env);	\
}

#define	DUMP_TAG_PTR(tag) \
{			\
	D1(NULL, "DUMP_TAG: type 0x%llx", (tag)->vio_msgtype); \
	D1(NULL, "DUMP_TAG: stype 0x%llx", (tag)->vio_subtype);	\
	D1(NULL, "DUMP_TAG: senv 0x%llx", (tag)->vio_subtype_env);	\
}

#define	DUMP_FLAGS(flags) dump_flags(flags);
#define	DISPLAY_STATE()	display_state()

#else

#define	DUMP_TAG(tag)
#define	DUMP_TAG_PTR(tag)
#define	DUMP_FLAGS(state)
#define	DISPLAY_STATE()

#endif	/* DUMP_STATE */

/*
 * Attach the specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
int
vsw_port_attach(vsw_port_t *port)
{
	vsw_t			*vswp = port->p_vswp;
	vsw_port_list_t		*plist = &vswp->plist;
	vsw_port_t		*p, **pp;
	int			nids = port->num_ldcs;
	uint64_t		*ldcids;
	int			rv;

	D1(vswp, "%s: enter : port %d", __func__, port->p_instance);

	/* port already exists? */
	READ_ENTER(&plist->lockrw);
	for (p = plist->head; p != NULL; p = p->p_next) {
		if (p->p_instance == port->p_instance) {
			DWARN(vswp, "%s: port instance %d already attached",
			    __func__, p->p_instance);
			RW_EXIT(&plist->lockrw);
			return (1);
		}
	}
	RW_EXIT(&plist->lockrw);

	mutex_init(&port->tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&port->mca_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&port->maccl_rwlock, NULL, RW_DRIVER, NULL);

	mutex_init(&port->state_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&port->state_cv, NULL, CV_DRIVER, NULL);
	port->state = VSW_PORT_INIT;

	D2(vswp, "%s: %d nids", __func__, nids);
	ldcids = port->ldc_ids;
	D2(vswp, "%s: ldcid (%llx)", __func__, (uint64_t)ldcids[0]);
	if (vsw_ldc_attach(port, (uint64_t)ldcids[0]) != 0) {
		DERR(vswp, "%s: ldc_attach failed", __func__);
		goto exit_error;
	}

	if (vswp->switching_setup_done == B_TRUE) {
		/*
		 * If the underlying network device has been setup,
		 * then open a mac client and porgram the mac address
		 * for this port.
		 */
		rv = vsw_mac_client_init(vswp, port, VSW_VNETPORT);
		if (rv != 0) {
			goto exit_error;
		}
	}

	/* create the fdb entry for this port/mac address */
	vsw_fdbe_add(vswp, port);

	vsw_create_vlans(port, VSW_VNETPORT);

	WRITE_ENTER(&plist->lockrw);

	/* link it into the list of ports for this vsw instance */
	pp = (vsw_port_t **)(&plist->head);
	port->p_next = *pp;
	*pp = port;
	plist->num_ports++;

	RW_EXIT(&plist->lockrw);

	/*
	 * Initialise the port and any ldc's under it.
	 */
	(void) vsw_ldc_init(port->ldcp);

	/* announce macaddr of vnet to the physical switch */
	if (vsw_publish_macaddr_count != 0) {	/* enabled */
		vsw_publish_macaddr(vswp, port);
	}

	D1(vswp, "%s: exit", __func__);
	return (0);

exit_error:

	cv_destroy(&port->state_cv);
	mutex_destroy(&port->state_lock);

	rw_destroy(&port->maccl_rwlock);
	mutex_destroy(&port->tx_lock);
	mutex_destroy(&port->mca_lock);
	kmem_free(port, sizeof (vsw_port_t));
	return (1);
}

/*
 * Detach the specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
int
vsw_port_detach(vsw_t *vswp, int p_instance)
{
	vsw_port_t	*port = NULL;
	vsw_port_list_t	*plist = &vswp->plist;

	D1(vswp, "%s: enter: port id %d", __func__, p_instance);

	WRITE_ENTER(&plist->lockrw);

	if ((port = vsw_lookup_port(vswp, p_instance)) == NULL) {
		RW_EXIT(&plist->lockrw);
		return (1);
	}

	if (vsw_plist_del_node(vswp, port)) {
		RW_EXIT(&plist->lockrw);
		return (1);
	}

	/* cleanup any HybridIO for this port */
	vsw_hio_stop_port(port);

	/*
	 * No longer need to hold writer lock on port list now
	 * that we have unlinked the target port from the list.
	 */
	RW_EXIT(&plist->lockrw);

	/* Cleanup and close the mac client */
	vsw_mac_client_cleanup(vswp, port, VSW_VNETPORT);

	/* Remove the fdb entry for this port/mac address */
	vsw_fdbe_del(vswp, &(port->p_macaddr));
	vsw_destroy_vlans(port, VSW_VNETPORT);

	/* Remove any multicast addresses.. */
	vsw_del_mcst_port(port);

	vsw_port_delete(port);

	D1(vswp, "%s: exit: p_instance(%d)", __func__, p_instance);
	return (0);
}

/*
 * Detach all active ports.
 */
void
vsw_detach_ports(vsw_t *vswp)
{
	vsw_port_list_t		*plist = &vswp->plist;
	vsw_port_t		*port = NULL;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&plist->lockrw);

	while ((port = plist->head) != NULL) {
		(void) vsw_plist_del_node(vswp, port);

		/* cleanup any HybridIO for this port */
		vsw_hio_stop_port(port);

		/* Cleanup and close the mac client */
		vsw_mac_client_cleanup(vswp, port, VSW_VNETPORT);

		/* Remove the fdb entry for this port/mac address */
		vsw_fdbe_del(vswp, &(port->p_macaddr));
		vsw_destroy_vlans(port, VSW_VNETPORT);

		/* Remove any multicast addresses.. */
		vsw_del_mcst_port(port);

		/*
		 * No longer need to hold the lock on the port list
		 * now that we have unlinked the target port from the
		 * list.
		 */
		RW_EXIT(&plist->lockrw);
		vsw_port_delete(port);
		WRITE_ENTER(&plist->lockrw);
	}
	RW_EXIT(&plist->lockrw);

	D1(vswp, "%s: exit", __func__);
}

/*
 * Delete the specified port.
 */
static void
vsw_port_delete(vsw_port_t *port)
{
	vsw_t			*vswp = port->p_vswp;

	D1(vswp, "%s: enter : port id %d", __func__, port->p_instance);

	vsw_ldc_uninit(port->ldcp);

	/*
	 * Wait for any pending ctrl msg tasks which reference this
	 * port to finish.
	 */
	vsw_drain_port_taskq(port);

	/*
	 * Wait for any active callbacks to finish
	 */
	vsw_ldc_drain(port->ldcp);

	vsw_ldc_detach(port->ldcp);

	rw_destroy(&port->maccl_rwlock);
	mutex_destroy(&port->mca_lock);
	mutex_destroy(&port->tx_lock);

	cv_destroy(&port->state_cv);
	mutex_destroy(&port->state_lock);

	if (port->num_ldcs != 0) {
		kmem_free(port->ldc_ids, port->num_ldcs * sizeof (uint64_t));
		port->num_ldcs = 0;
	}

	if (port->nvids != 0) {
		kmem_free(port->vids, sizeof (vsw_vlanid_t) * port->nvids);
	}

	kmem_free(port, sizeof (vsw_port_t));

	D1(vswp, "%s: exit", __func__);
}

/*
 * Attach a logical domain channel (ldc) under a specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_ldc_attach(vsw_port_t *port, uint64_t ldc_id)
{
	vsw_t		*vswp = port->p_vswp;
	vsw_ldc_t	*ldcp = NULL;
	ldc_attr_t	attr;
	ldc_status_t	istatus;
	int		status = DDI_FAILURE;
	char		kname[MAXNAMELEN];
	enum		{ PROG_init = 0x0,
			    PROG_callback = 0x1,
			    PROG_tx_thread = 0x2}
			progress;

	progress = PROG_init;

	D1(vswp, "%s: enter", __func__);

	ldcp = kmem_zalloc(sizeof (vsw_ldc_t), KM_NOSLEEP);
	if (ldcp == NULL) {
		DERR(vswp, "%s: kmem_zalloc failed", __func__);
		return (1);
	}
	ldcp->ldc_id = ldc_id;

	mutex_init(&ldcp->ldc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->ldc_rxlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->ldc_cblock, NULL, MUTEX_DRIVER, NULL);
	ldcp->msg_thr_flags = 0;
	mutex_init(&ldcp->msg_thr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->msg_thr_cv, NULL, CV_DRIVER, NULL);
	ldcp->rcv_thr_flags = 0;
	mutex_init(&ldcp->rcv_thr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->rcv_thr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&ldcp->drain_cv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->drain_cv, NULL, CV_DRIVER, NULL);

	/* required for handshake with peer */
	ldcp->local_session = (uint64_t)ddi_get_lbolt();
	ldcp->peer_session = 0;
	ldcp->session_status = 0;
	ldcp->hss_id = 1;	/* Initial handshake session id */
	ldcp->hphase = VSW_MILESTONE0;

	(void) atomic_swap_32(&port->p_hio_capable, B_FALSE);

	/* only set for outbound lane, inbound set by peer */
	vsw_set_lane_attr(vswp, &ldcp->lane_out);

	attr.devclass = LDC_DEV_NT_SVC;
	attr.instance = ddi_get_instance(vswp->dip);
	attr.mode = LDC_MODE_UNRELIABLE;
	attr.mtu = VSW_LDC_MTU;
	status = ldc_init(ldc_id, &attr, &ldcp->ldc_handle);
	if (status != 0) {
		DERR(vswp, "%s(%lld): ldc_init failed, rv (%d)",
		    __func__, ldc_id, status);
		goto ldc_attach_fail;
	}

	if (vsw_ldc_txthr_enabled) {
		ldcp->tx_thr_flags = 0;
		ldcp->tx_mhead = ldcp->tx_mtail = NULL;

		mutex_init(&ldcp->tx_thr_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ldcp->tx_thr_cv, NULL, CV_DRIVER, NULL);
		ldcp->tx_thread = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    vsw_ldc_tx_worker, ldcp, 0, &p0, TS_RUN, maxclsyspri);

		progress |= PROG_tx_thread;
		if (ldcp->tx_thread == NULL) {
			DWARN(vswp, "%s(%lld): Failed to create worker thread",
			    __func__, ldc_id);
			goto ldc_attach_fail;
		}
	}

	status = ldc_reg_callback(ldcp->ldc_handle, vsw_ldc_cb, (caddr_t)ldcp);
	if (status != 0) {
		DERR(vswp, "%s(%lld): ldc_reg_callback failed, rv (%d)",
		    __func__, ldc_id, status);
		(void) ldc_fini(ldcp->ldc_handle);
		goto ldc_attach_fail;
	}
	/*
	 * allocate a message for ldc_read()s, big enough to hold ctrl and
	 * data msgs, including raw data msgs used to recv priority frames.
	 */
	ldcp->msglen = VIO_PKT_DATA_HDRSIZE + vswp->max_frame_size;
	ldcp->ldcmsg = kmem_alloc(ldcp->msglen, KM_SLEEP);

	progress |= PROG_callback;

	mutex_init(&ldcp->status_lock, NULL, MUTEX_DRIVER, NULL);

	if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
		DERR(vswp, "%s: ldc_status failed", __func__);
		mutex_destroy(&ldcp->status_lock);
		goto ldc_attach_fail;
	}

	ldcp->ldc_status = istatus;
	ldcp->ldc_port = port;
	ldcp->ldc_vswp = vswp;

	vsw_reset_vnet_proto_ops(ldcp);

	(void) sprintf(kname, "%sldc0x%lx", DRV_NAME, ldcp->ldc_id);
	ldcp->ksp = vgen_setup_kstats(DRV_NAME, vswp->instance,
	    kname, &ldcp->ldc_stats);
	if (ldcp->ksp == NULL) {
		DERR(vswp, "%s: kstats setup failed", __func__);
		goto ldc_attach_fail;
	}

	/* link it into this port */
	port->ldcp = ldcp;

	D1(vswp, "%s: exit", __func__);
	return (0);

ldc_attach_fail:

	if (progress & PROG_callback) {
		(void) ldc_unreg_callback(ldcp->ldc_handle);
		kmem_free(ldcp->ldcmsg, ldcp->msglen);
	}

	if (progress & PROG_tx_thread) {
		if (ldcp->tx_thread != NULL) {
			vsw_stop_tx_thread(ldcp);
		}
		mutex_destroy(&ldcp->tx_thr_lock);
		cv_destroy(&ldcp->tx_thr_cv);
	}
	if (ldcp->ksp != NULL) {
		vgen_destroy_kstats(ldcp->ksp);
	}
	mutex_destroy(&ldcp->msg_thr_lock);
	mutex_destroy(&ldcp->rcv_thr_lock);
	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_rxlock);
	mutex_destroy(&ldcp->ldc_cblock);
	mutex_destroy(&ldcp->drain_cv_lock);
	cv_destroy(&ldcp->msg_thr_cv);
	cv_destroy(&ldcp->rcv_thr_cv);
	cv_destroy(&ldcp->drain_cv);

	kmem_free(ldcp, sizeof (vsw_ldc_t));

	return (1);
}

/*
 * Detach a logical domain channel (ldc) belonging to a
 * particular port.
 */
static void
vsw_ldc_detach(vsw_ldc_t *ldcp)
{
	int		rv;
	vsw_t		*vswp = ldcp->ldc_port->p_vswp;
	int		retries = 0;

	D2(vswp, "%s: detaching channel %lld", __func__, ldcp->ldc_id);

	/* Stop msg/rcv thread */
	if (ldcp->rcv_thread != NULL) {
		vsw_stop_rcv_thread(ldcp);
	} else if (ldcp->msg_thread != NULL) {
		vsw_stop_msg_thread(ldcp);
	}
	kmem_free(ldcp->ldcmsg, ldcp->msglen);

	/* Stop the tx thread */
	if (ldcp->tx_thread != NULL) {
		vsw_stop_tx_thread(ldcp);
		mutex_destroy(&ldcp->tx_thr_lock);
		cv_destroy(&ldcp->tx_thr_cv);
		if (ldcp->tx_mhead != NULL) {
			freemsgchain(ldcp->tx_mhead);
			ldcp->tx_mhead = ldcp->tx_mtail = NULL;
			ldcp->tx_cnt = 0;
		}
	}

	/* Destory kstats */
	vgen_destroy_kstats(ldcp->ksp);

	/*
	 * Before we can close the channel we must release any mapped
	 * resources (e.g. drings).
	 */
	vsw_free_lane_resources(ldcp, INBOUND);
	vsw_free_lane_resources(ldcp, OUTBOUND);

	/*
	 * Close the channel, retry on EAAGIN.
	 */
	while ((rv = ldc_close(ldcp->ldc_handle)) == EAGAIN) {
		if (++retries > vsw_ldc_retries) {
			break;
		}
		drv_usecwait(vsw_ldc_delay);
	}
	if (rv != 0) {
		cmn_err(CE_NOTE,
		    "!vsw%d: Error(%d) closing the channel(0x%lx)\n",
		    vswp->instance, rv, ldcp->ldc_id);
	}

	(void) ldc_fini(ldcp->ldc_handle);

	ldcp->ldc_status = LDC_INIT;
	ldcp->ldc_handle = 0;
	ldcp->ldc_vswp = NULL;

	mutex_destroy(&ldcp->msg_thr_lock);
	mutex_destroy(&ldcp->rcv_thr_lock);
	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_rxlock);
	mutex_destroy(&ldcp->ldc_cblock);
	mutex_destroy(&ldcp->drain_cv_lock);
	mutex_destroy(&ldcp->status_lock);
	cv_destroy(&ldcp->msg_thr_cv);
	cv_destroy(&ldcp->rcv_thr_cv);
	cv_destroy(&ldcp->drain_cv);

	kmem_free(ldcp, sizeof (vsw_ldc_t));
}

/*
 * Open and attempt to bring up the channel. Note that channel
 * can only be brought up if peer has also opened channel.
 *
 * Returns 0 if can open and bring up channel, otherwise
 * returns 1.
 */
static int
vsw_ldc_init(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	ldc_status_t	istatus = 0;
	int		rv;

	D1(vswp, "%s: enter", __func__);

	LDC_ENTER_LOCK(ldcp);

	/* don't start at 0 in case clients don't like that */
	ldcp->next_ident = 1;

	rv = ldc_open(ldcp->ldc_handle);
	if (rv != 0) {
		DERR(vswp, "%s: ldc_open failed: id(%lld) rv(%d)",
		    __func__, ldcp->ldc_id, rv);
		LDC_EXIT_LOCK(ldcp);
		return (1);
	}

	if (ldc_status(ldcp->ldc_handle, &istatus) != 0) {
		DERR(vswp, "%s: unable to get status", __func__);
		LDC_EXIT_LOCK(ldcp);
		return (1);

	} else if (istatus != LDC_OPEN && istatus != LDC_READY) {
		DERR(vswp, "%s: id (%lld) status(%d) is not OPEN/READY",
		    __func__, ldcp->ldc_id, istatus);
		LDC_EXIT_LOCK(ldcp);
		return (1);
	}

	mutex_enter(&ldcp->status_lock);
	ldcp->ldc_status = istatus;
	mutex_exit(&ldcp->status_lock);

	rv = ldc_up(ldcp->ldc_handle);
	if (rv != 0) {
		/*
		 * Not a fatal error for ldc_up() to fail, as peer
		 * end point may simply not be ready yet.
		 */
		D2(vswp, "%s: ldc_up err id(%lld) rv(%d)", __func__,
		    ldcp->ldc_id, rv);
		LDC_EXIT_LOCK(ldcp);
		return (1);
	}

	/*
	 * ldc_up() call is non-blocking so need to explicitly
	 * check channel status to see if in fact the channel
	 * is UP.
	 */
	mutex_enter(&ldcp->status_lock);
	if (ldc_status(ldcp->ldc_handle, &ldcp->ldc_status) != 0) {
		DERR(vswp, "%s: unable to get status", __func__);
		mutex_exit(&ldcp->status_lock);
		LDC_EXIT_LOCK(ldcp);
		return (1);

	}

	if (ldcp->ldc_status == LDC_UP) {
		D2(vswp, "%s: channel %ld now UP (%ld)", __func__,
		    ldcp->ldc_id, istatus);
		mutex_exit(&ldcp->status_lock);
		LDC_EXIT_LOCK(ldcp);

		vsw_process_conn_evt(ldcp, VSW_CONN_UP);
		return (0);
	}

	mutex_exit(&ldcp->status_lock);
	LDC_EXIT_LOCK(ldcp);

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/* disable callbacks on the channel */
static void
vsw_ldc_uninit(vsw_ldc_t *ldcp)
{
	vsw_t	*vswp = ldcp->ldc_vswp;
	int	rv;

	D1(vswp, "vsw_ldc_uninit: enter: id(%lx)\n", ldcp->ldc_id);

	LDC_ENTER_LOCK(ldcp);

	rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
	if (rv != 0) {
		cmn_err(CE_NOTE, "!vsw_ldc_uninit(%ld): error disabling "
		    "interrupts (rv = %d)\n", ldcp->ldc_id, rv);
	}

	mutex_enter(&ldcp->status_lock);
	ldcp->ldc_status = LDC_INIT;
	mutex_exit(&ldcp->status_lock);

	LDC_EXIT_LOCK(ldcp);

	D1(vswp, "vsw_ldc_uninit: exit: id(%lx)", ldcp->ldc_id);
}

/*
 * Wait until the callback(s) associated with the ldcs under the specified
 * port have completed.
 *
 * Prior to this function being invoked each channel under this port
 * should have been quiesced via ldc_set_cb_mode(DISABLE).
 *
 * A short explaination of what we are doing below..
 *
 * The simplest approach would be to have a reference counter in
 * the ldc structure which is increment/decremented by the callbacks as
 * they use the channel. The drain function could then simply disable any
 * further callbacks and do a cv_wait for the ref to hit zero. Unfortunately
 * there is a tiny window here - before the callback is able to get the lock
 * on the channel it is interrupted and this function gets to execute. It
 * sees that the ref count is zero and believes its free to delete the
 * associated data structures.
 *
 * We get around this by taking advantage of the fact that before the ldc
 * framework invokes a callback it sets a flag to indicate that there is a
 * callback active (or about to become active). If when we attempt to
 * unregister a callback when this active flag is set then the unregister
 * will fail with EWOULDBLOCK.
 *
 * If the unregister fails we do a cv_timedwait. We will either be signaled
 * by the callback as it is exiting (note we have to wait a short period to
 * allow the callback to return fully to the ldc framework and it to clear
 * the active flag), or by the timer expiring. In either case we again attempt
 * the unregister. We repeat this until we can succesfully unregister the
 * callback.
 *
 * The reason we use a cv_timedwait rather than a simple cv_wait is to catch
 * the case where the callback has finished but the ldc framework has not yet
 * cleared the active flag. In this case we would never get a cv_signal.
 */
static void
vsw_ldc_drain(vsw_ldc_t *ldcp)
{
	vsw_t	*vswp = ldcp->ldc_port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	/*
	 * If we can unregister the channel callback then we
	 * know that there is no callback either running or
	 * scheduled to run for this channel so move on to next
	 * channel in the list.
	 */
	mutex_enter(&ldcp->drain_cv_lock);

	/* prompt active callbacks to quit */
	ldcp->drain_state = VSW_LDC_DRAINING;

	if ((ldc_unreg_callback(ldcp->ldc_handle)) == 0) {
		D2(vswp, "%s: unreg callback for chan %ld", __func__,
		    ldcp->ldc_id);
		mutex_exit(&ldcp->drain_cv_lock);
	} else {
		/*
		 * If we end up here we know that either 1) a callback
		 * is currently executing, 2) is about to start (i.e.
		 * the ldc framework has set the active flag but
		 * has not actually invoked the callback yet, or 3)
		 * has finished and has returned to the ldc framework
		 * but the ldc framework has not yet cleared the
		 * active bit.
		 *
		 * Wait for it to finish.
		 */
		while (ldc_unreg_callback(ldcp->ldc_handle) == EWOULDBLOCK) {
			(void) cv_timedwait(&ldcp->drain_cv,
			    &ldcp->drain_cv_lock, ddi_get_lbolt() + hz);
		}

		mutex_exit(&ldcp->drain_cv_lock);
		D2(vswp, "%s: unreg callback for chan %ld after "
		    "timeout", __func__, ldcp->ldc_id);
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * Wait until all tasks which reference this port have completed.
 *
 * Prior to this function being invoked each channel under this port
 * should have been quiesced via ldc_set_cb_mode(DISABLE).
 */
static void
vsw_drain_port_taskq(vsw_port_t *port)
{
	vsw_t		*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	/*
	 * Mark the port as in the process of being detached, and
	 * dispatch a marker task to the queue so we know when all
	 * relevant tasks have completed.
	 */
	mutex_enter(&port->state_lock);
	port->state = VSW_PORT_DETACHING;

	if ((vswp->taskq_p == NULL) ||
	    (ddi_taskq_dispatch(vswp->taskq_p, vsw_marker_task,
	    port, DDI_NOSLEEP) != DDI_SUCCESS)) {
		cmn_err(CE_NOTE, "!vsw%d: unable to dispatch marker task",
		    vswp->instance);
		mutex_exit(&port->state_lock);
		return;
	}

	/*
	 * Wait for the marker task to finish.
	 */
	while (port->state != VSW_PORT_DETACHABLE)
		cv_wait(&port->state_cv, &port->state_lock);

	mutex_exit(&port->state_lock);

	D1(vswp, "%s: exit", __func__);
}

static void
vsw_marker_task(void *arg)
{
	vsw_port_t	*port = arg;
	vsw_t		*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&port->state_lock);

	/*
	 * No further tasks should be dispatched which reference
	 * this port so ok to mark it as safe to detach.
	 */
	port->state = VSW_PORT_DETACHABLE;

	cv_signal(&port->state_cv);

	mutex_exit(&port->state_lock);

	D1(vswp, "%s: exit", __func__);
}

vsw_port_t *
vsw_lookup_port(vsw_t *vswp, int p_instance)
{
	vsw_port_list_t *plist = &vswp->plist;
	vsw_port_t	*port;

	for (port = plist->head; port != NULL; port = port->p_next) {
		if (port->p_instance == p_instance) {
			D2(vswp, "vsw_lookup_port: found p_instance\n");
			return (port);
		}
	}

	return (NULL);
}

void
vsw_vlan_unaware_port_reset(vsw_port_t *portp)
{
	vsw_ldc_t	*ldcp = portp->ldcp;

	mutex_enter(&ldcp->ldc_cblock);

	/*
	 * If the peer is vlan_unaware(ver < 1.3), reset channel and terminate
	 * the connection. See comments in vsw_set_vnet_proto_ops().
	 */
	if (ldcp->hphase == VSW_MILESTONE4 && VSW_VER_LT(ldcp, 1, 3) &&
	    portp->nvids != 0) {
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
	}

	mutex_exit(&ldcp->ldc_cblock);
}

void
vsw_hio_port_reset(vsw_port_t *portp, boolean_t immediate)
{
	vsw_ldc_t	*ldcp = portp->ldcp;

	mutex_enter(&ldcp->ldc_cblock);

	/*
	 * If the peer is HybridIO capable (ver >= 1.3), reset channel
	 * to trigger re-negotiation, which inturn trigger HybridIO
	 * setup/cleanup.
	 */
	if ((ldcp->hphase == VSW_MILESTONE4) &&
	    (portp->p_hio_capable == B_TRUE)) {
		if (immediate == B_TRUE) {
			(void) ldc_down(ldcp->ldc_handle);
		} else {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
		}
	}

	mutex_exit(&ldcp->ldc_cblock);
}

void
vsw_port_reset(vsw_port_t *portp)
{
	vsw_ldc_t	*ldcp = portp->ldcp;

	mutex_enter(&ldcp->ldc_cblock);

	/*
	 * reset channel and terminate the connection.
	 */
	vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);

	mutex_exit(&ldcp->ldc_cblock);
}

void
vsw_reset_ports(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*portp;

	READ_ENTER(&plist->lockrw);
	for (portp = plist->head; portp != NULL; portp = portp->p_next) {
		if ((portp->p_hio_capable) && (portp->p_hio_enabled)) {
			vsw_hio_stop_port(portp);
		}
		vsw_port_reset(portp);
	}
	RW_EXIT(&plist->lockrw);
}

static void
vsw_send_physlink_msg(vsw_ldc_t *ldcp, link_state_t plink_state)
{
	vnet_physlink_msg_t	msg;
	vnet_physlink_msg_t	*msgp = &msg;
	uint32_t		physlink_info = 0;

	if (plink_state == LINK_STATE_UP) {
		physlink_info |= VNET_PHYSLINK_STATE_UP;
	} else {
		physlink_info |= VNET_PHYSLINK_STATE_DOWN;
	}

	msgp->tag.vio_msgtype = VIO_TYPE_CTRL;
	msgp->tag.vio_subtype = VIO_SUBTYPE_INFO;
	msgp->tag.vio_subtype_env = VNET_PHYSLINK_INFO;
	msgp->tag.vio_sid = ldcp->local_session;
	msgp->physlink_info = physlink_info;

	(void) vsw_send_msg(ldcp, msgp, sizeof (msg), B_TRUE);
}

static void
vsw_port_physlink_update(vsw_port_t *portp)
{
	vsw_ldc_t	*ldcp;
	vsw_t		*vswp;

	vswp = portp->p_vswp;
	ldcp = portp->ldcp;

	mutex_enter(&ldcp->ldc_cblock);

	/*
	 * If handshake has completed successfully and if the vnet device
	 * has negotiated to get physical link state updates, send a message
	 * with the current state.
	 */
	if (ldcp->hphase == VSW_MILESTONE4 && ldcp->pls_negotiated == B_TRUE) {
		vsw_send_physlink_msg(ldcp, vswp->phys_link_state);
	}

	mutex_exit(&ldcp->ldc_cblock);
}

void
vsw_physlink_update_ports(vsw_t *vswp)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*portp;

	READ_ENTER(&plist->lockrw);
	for (portp = plist->head; portp != NULL; portp = portp->p_next) {
		vsw_port_physlink_update(portp);
	}
	RW_EXIT(&plist->lockrw);
}

/*
 * Search for and remove the specified port from the port
 * list. Returns 0 if able to locate and remove port, otherwise
 * returns 1.
 */
static int
vsw_plist_del_node(vsw_t *vswp, vsw_port_t *port)
{
	vsw_port_list_t *plist = &vswp->plist;
	vsw_port_t	*curr_p, *prev_p;

	if (plist->head == NULL)
		return (1);

	curr_p = prev_p = plist->head;

	while (curr_p != NULL) {
		if (curr_p == port) {
			if (prev_p == curr_p) {
				plist->head = curr_p->p_next;
			} else {
				prev_p->p_next = curr_p->p_next;
			}
			plist->num_ports--;
			break;
		} else {
			prev_p = curr_p;
			curr_p = curr_p->p_next;
		}
	}
	return (0);
}

/*
 * Interrupt handler for ldc messages.
 */
static uint_t
vsw_ldc_cb(uint64_t event, caddr_t arg)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t  *)arg;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s: enter: ldcid (%lld)\n", __func__, ldcp->ldc_id);

	mutex_enter(&ldcp->ldc_cblock);
	ldcp->ldc_stats.callbacks++;

	mutex_enter(&ldcp->status_lock);
	if ((ldcp->ldc_status == LDC_INIT) || (ldcp->ldc_handle == 0)) {
		mutex_exit(&ldcp->status_lock);
		mutex_exit(&ldcp->ldc_cblock);
		return (LDC_SUCCESS);
	}
	mutex_exit(&ldcp->status_lock);

	if (event & LDC_EVT_UP) {
		/*
		 * Channel has come up.
		 */
		D2(vswp, "%s: id(%ld) event(%llx) UP: status(%ld)",
		    __func__, ldcp->ldc_id, event, ldcp->ldc_status);

		vsw_process_conn_evt(ldcp, VSW_CONN_UP);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);
	}

	if (event & LDC_EVT_READ) {
		/*
		 * Data available for reading.
		 */
		D2(vswp, "%s: id(ld) event(%llx) data READ",
		    __func__, ldcp->ldc_id, event);

		vsw_process_evt_read(ldcp);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);

		goto vsw_cb_exit;
	}

	if (event & (LDC_EVT_DOWN | LDC_EVT_RESET)) {
		D2(vswp, "%s: id(%ld) event (%lx) DOWN/RESET: status(%ld)",
		    __func__, ldcp->ldc_id, event, ldcp->ldc_status);

		vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
	}

	/*
	 * Catch either LDC_EVT_WRITE which we don't support or any
	 * unknown event.
	 */
	if (event &
	    ~(LDC_EVT_UP | LDC_EVT_RESET | LDC_EVT_DOWN | LDC_EVT_READ)) {
		DERR(vswp, "%s: id(%ld) Unexpected event=(%llx) status(%ld)",
		    __func__, ldcp->ldc_id, event, ldcp->ldc_status);
	}

vsw_cb_exit:
	mutex_exit(&ldcp->ldc_cblock);

	/*
	 * Let the drain function know we are finishing if it
	 * is waiting.
	 */
	mutex_enter(&ldcp->drain_cv_lock);
	if (ldcp->drain_state == VSW_LDC_DRAINING)
		cv_signal(&ldcp->drain_cv);
	mutex_exit(&ldcp->drain_cv_lock);

	return (LDC_SUCCESS);
}

/*
 * Reinitialise data structures associated with the channel.
 */
static void
vsw_ldc_reinit(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	vsw_port_t	*port;

	D1(vswp, "%s: enter", __func__);

	port = ldcp->ldc_port;

	D2(vswp, "%s: in 0x%llx : out 0x%llx", __func__,
	    ldcp->lane_in.lstate, ldcp->lane_out.lstate);

	vsw_free_lane_resources(ldcp, INBOUND);
	vsw_free_lane_resources(ldcp, OUTBOUND);

	ldcp->lane_in.lstate = 0;
	ldcp->lane_out.lstate = 0;

	/*
	 * Remove parent port from any multicast groups
	 * it may have registered with. Client must resend
	 * multicast add command after handshake completes.
	 */
	vsw_del_mcst_port(port);

	ldcp->peer_session = 0;
	ldcp->session_status = 0;
	ldcp->hcnt = 0;
	ldcp->hphase = VSW_MILESTONE0;

	vsw_reset_vnet_proto_ops(ldcp);

	D1(vswp, "%s: exit", __func__);
}

/*
 * Process a connection event.
 */
void
vsw_process_conn_evt(vsw_ldc_t *ldcp, uint16_t evt)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	vsw_conn_evt_t	*conn = NULL;

	D1(vswp, "%s: enter", __func__);

	/*
	 * Check if either a reset or restart event is pending
	 * or in progress. If so just return.
	 *
	 * A VSW_CONN_RESET event originates either with a LDC_RESET_EVT
	 * being received by the callback handler, or a ECONNRESET error
	 * code being returned from a ldc_read() or ldc_write() call.
	 *
	 * A VSW_CONN_RESTART event occurs when some error checking code
	 * decides that there is a problem with data from the channel,
	 * and that the handshake should be restarted.
	 */
	if (((evt == VSW_CONN_RESET) || (evt == VSW_CONN_RESTART)) &&
	    (ldstub((uint8_t *)&ldcp->reset_active)))
		return;

	/*
	 * If it is an LDC_UP event we first check the recorded
	 * state of the channel. If this is UP then we know that
	 * the channel moving to the UP state has already been dealt
	 * with and don't need to dispatch a  new task.
	 *
	 * The reason for this check is that when we do a ldc_up(),
	 * depending on the state of the peer, we may or may not get
	 * a LDC_UP event. As we can't depend on getting a LDC_UP evt
	 * every time we do ldc_up() we explicitly check the channel
	 * status to see has it come up (ldc_up() is asynch and will
	 * complete at some undefined time), and take the appropriate
	 * action.
	 *
	 * The flip side of this is that we may get a LDC_UP event
	 * when we have already seen that the channel is up and have
	 * dealt with that.
	 */
	mutex_enter(&ldcp->status_lock);
	if (evt == VSW_CONN_UP) {
		if ((ldcp->ldc_status == LDC_UP) || (ldcp->reset_active != 0)) {
			mutex_exit(&ldcp->status_lock);
			return;
		}
	}
	mutex_exit(&ldcp->status_lock);

	/*
	 * The transaction group id allows us to identify and discard
	 * any tasks which are still pending on the taskq and refer
	 * to the handshake session we are about to restart or reset.
	 * These stale messages no longer have any real meaning.
	 */
	(void) atomic_inc_32(&ldcp->hss_id);

	ASSERT(vswp->taskq_p != NULL);

	if ((conn = kmem_zalloc(sizeof (vsw_conn_evt_t), KM_NOSLEEP)) == NULL) {
		cmn_err(CE_WARN, "!vsw%d: unable to allocate memory for"
		    " connection event", vswp->instance);
		goto err_exit;
	}

	conn->evt = evt;
	conn->ldcp = ldcp;

	if (ddi_taskq_dispatch(vswp->taskq_p, vsw_conn_task, conn,
	    DDI_NOSLEEP) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!vsw%d: Can't dispatch connection task",
		    vswp->instance);

		kmem_free(conn, sizeof (vsw_conn_evt_t));
		goto err_exit;
	}

	D1(vswp, "%s: exit", __func__);
	return;

err_exit:
	/*
	 * Have mostly likely failed due to memory shortage. Clear the flag so
	 * that future requests will at least be attempted and will hopefully
	 * succeed.
	 */
	if ((evt == VSW_CONN_RESET) || (evt == VSW_CONN_RESTART))
		ldcp->reset_active = 0;
}

/*
 * Deal with events relating to a connection. Invoked from a taskq.
 */
static void
vsw_conn_task(void *arg)
{
	vsw_conn_evt_t	*conn = (vsw_conn_evt_t *)arg;
	vsw_ldc_t	*ldcp = NULL;
	vsw_port_t	*portp;
	vsw_t		*vswp = NULL;
	uint16_t	evt;
	ldc_status_t	curr_status;

	ldcp = conn->ldcp;
	evt = conn->evt;
	vswp = ldcp->ldc_vswp;
	portp = ldcp->ldc_port;

	D1(vswp, "%s: enter", __func__);

	/* can safely free now have copied out data */
	kmem_free(conn, sizeof (vsw_conn_evt_t));

	if (ldcp->rcv_thread != NULL) {
		vsw_stop_rcv_thread(ldcp);
	} else if (ldcp->msg_thread != NULL) {
		vsw_stop_msg_thread(ldcp);
	}

	mutex_enter(&ldcp->status_lock);
	if (ldc_status(ldcp->ldc_handle, &curr_status) != 0) {
		cmn_err(CE_WARN, "!vsw%d: Unable to read status of "
		    "channel %ld", vswp->instance, ldcp->ldc_id);
		mutex_exit(&ldcp->status_lock);
		return;
	}

	/*
	 * If we wish to restart the handshake on this channel, then if
	 * the channel is UP we bring it DOWN to flush the underlying
	 * ldc queue.
	 */
	if ((evt == VSW_CONN_RESTART) && (curr_status == LDC_UP))
		(void) ldc_down(ldcp->ldc_handle);

	if ((portp->p_hio_capable) && (portp->p_hio_enabled)) {
		vsw_hio_stop(vswp, ldcp);
	}

	/*
	 * re-init all the associated data structures.
	 */
	vsw_ldc_reinit(ldcp);

	/*
	 * Bring the channel back up (note it does no harm to
	 * do this even if the channel is already UP, Just
	 * becomes effectively a no-op).
	 */
	(void) ldc_up(ldcp->ldc_handle);

	/*
	 * Check if channel is now UP. This will only happen if
	 * peer has also done a ldc_up().
	 */
	if (ldc_status(ldcp->ldc_handle, &curr_status) != 0) {
		cmn_err(CE_WARN, "!vsw%d: Unable to read status of "
		    "channel %ld", vswp->instance, ldcp->ldc_id);
		mutex_exit(&ldcp->status_lock);
		return;
	}

	ldcp->ldc_status = curr_status;

	/* channel UP so restart handshake by sending version info */
	if (curr_status == LDC_UP) {
		if (ldcp->hcnt++ > vsw_num_handshakes) {
			cmn_err(CE_WARN, "!vsw%d: exceeded number of permitted"
			    " handshake attempts (%d) on channel %ld",
			    vswp->instance, ldcp->hcnt, ldcp->ldc_id);
			mutex_exit(&ldcp->status_lock);
			return;
		}

		if (vsw_obp_ver_proto_workaround == B_FALSE &&
		    (ddi_taskq_dispatch(vswp->taskq_p, vsw_send_ver, ldcp,
		    DDI_NOSLEEP) != DDI_SUCCESS)) {
			cmn_err(CE_WARN, "!vsw%d: Can't dispatch version task",
			    vswp->instance);

			/*
			 * Don't count as valid restart attempt if couldn't
			 * send version msg.
			 */
			if (ldcp->hcnt > 0)
				ldcp->hcnt--;
		}
	}

	/*
	 * Mark that the process is complete by clearing the flag.
	 *
	 * Note is it possible that the taskq dispatch above may have failed,
	 * most likely due to memory shortage. We still clear the flag so
	 * future attempts will at least be attempted and will hopefully
	 * succeed.
	 */
	if ((evt == VSW_CONN_RESET) || (evt == VSW_CONN_RESTART))
		ldcp->reset_active = 0;

	mutex_exit(&ldcp->status_lock);

	D1(vswp, "%s: exit", __func__);
}

/*
 * returns 0 if legal for event signified by flag to have
 * occured at the time it did. Otherwise returns 1.
 */
int
vsw_check_flag(vsw_ldc_t *ldcp, int dir, uint64_t flag)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	uint64_t	state;
	uint64_t	phase;

	if (dir == INBOUND)
		state = ldcp->lane_in.lstate;
	else
		state = ldcp->lane_out.lstate;

	phase = ldcp->hphase;

	switch (flag) {
	case VSW_VER_INFO_RECV:
		if (phase > VSW_MILESTONE0) {
			DERR(vswp, "vsw_check_flag (%d): VER_INFO_RECV"
			    " when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		}
		break;

	case VSW_VER_ACK_RECV:
	case VSW_VER_NACK_RECV:
		if (!(state & VSW_VER_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious VER_ACK or "
			    "VER_NACK when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		} else
			state &= ~VSW_VER_INFO_SENT;
		break;

	case VSW_ATTR_INFO_RECV:
		if ((phase < VSW_MILESTONE1) || (phase >= VSW_MILESTONE2)) {
			DERR(vswp, "vsw_check_flag (%d): ATTR_INFO_RECV"
			    " when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		}
		break;

	case VSW_ATTR_ACK_RECV:
	case VSW_ATTR_NACK_RECV:
		if (!(state & VSW_ATTR_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious ATTR_ACK"
			    " or ATTR_NACK when in state %d\n",
			    ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		} else
			state &= ~VSW_ATTR_INFO_SENT;
		break;

	case VSW_DRING_INFO_RECV:
		if (phase < VSW_MILESTONE1) {
			DERR(vswp, "vsw_check_flag (%d): DRING_INFO_RECV"
			    " when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		}
		break;

	case VSW_DRING_ACK_RECV:
	case VSW_DRING_NACK_RECV:
		if (!(state & VSW_DRING_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious DRING_ACK "
			    " or DRING_NACK when in state %d\n",
			    ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		} else
			state &= ~VSW_DRING_INFO_SENT;
		break;

	case VSW_RDX_INFO_RECV:
		if (phase < VSW_MILESTONE3) {
			DERR(vswp, "vsw_check_flag (%d): RDX_INFO_RECV"
			    " when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		}
		break;

	case VSW_RDX_ACK_RECV:
	case VSW_RDX_NACK_RECV:
		if (!(state & VSW_RDX_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious RDX_ACK or "
			    "RDX_NACK when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		} else
			state &= ~VSW_RDX_INFO_SENT;
		break;

	case VSW_MCST_INFO_RECV:
		if (phase < VSW_MILESTONE3) {
			DERR(vswp, "vsw_check_flag (%d): VSW_MCST_INFO_RECV"
			    " when in state %d\n", ldcp->ldc_id, phase);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return (1);
		}
		break;

	default:
		DERR(vswp, "vsw_check_flag (%lld): unknown flag (%llx)",
		    ldcp->ldc_id, flag);
		return (1);
	}

	if (dir == INBOUND)
		ldcp->lane_in.lstate = state;
	else
		ldcp->lane_out.lstate = state;

	D1(vswp, "vsw_check_flag (chan %lld): exit", ldcp->ldc_id);

	return (0);
}

void
vsw_next_milestone(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	vsw_port_t	*portp = ldcp->ldc_port;
	lane_t		*lane_out = &ldcp->lane_out;
	lane_t		*lane_in = &ldcp->lane_in;

	D1(vswp, "%s (chan %lld): enter (phase %ld)", __func__,
	    ldcp->ldc_id, ldcp->hphase);

	DUMP_FLAGS(lane_in->lstate);
	DUMP_FLAGS(lane_out->lstate);

	switch (ldcp->hphase) {

	case VSW_MILESTONE0:
		/*
		 * If we haven't started to handshake with our peer,
		 * start to do so now.
		 */
		if (lane_out->lstate == 0) {
			D2(vswp, "%s: (chan %lld) starting handshake "
			    "with peer", __func__, ldcp->ldc_id);
			vsw_process_conn_evt(ldcp, VSW_CONN_UP);
		}

		/*
		 * Only way to pass this milestone is to have successfully
		 * negotiated version info.
		 */
		if ((lane_in->lstate & VSW_VER_ACK_SENT) &&
		    (lane_out->lstate & VSW_VER_ACK_RECV)) {

			D2(vswp, "%s: (chan %lld) leaving milestone 0",
			    __func__, ldcp->ldc_id);

			vsw_set_vnet_proto_ops(ldcp);

			/*
			 * Next milestone is passed when attribute
			 * information has been successfully exchanged.
			 */
			ldcp->hphase = VSW_MILESTONE1;
			vsw_send_attr(ldcp);

		}
		break;

	case VSW_MILESTONE1:
		/*
		 * Only way to pass this milestone is to have successfully
		 * negotiated attribute information, in both directions.
		 */
		if (!((lane_in->lstate & VSW_ATTR_ACK_SENT) &&
		    (lane_out->lstate & VSW_ATTR_ACK_RECV))) {
			break;
		}

		ldcp->hphase = VSW_MILESTONE2;

		/*
		 * If the peer device has said it wishes to
		 * use descriptor rings then we send it our ring
		 * info, otherwise we just set up a private ring
		 * which we use an internal buffer
		 */
		if ((VSW_VER_GTEQ(ldcp, 1, 2) &&
		    (lane_in->xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    (VSW_VER_LT(ldcp, 1, 2) &&
		    (lane_in->xfer_mode == VIO_DRING_MODE_V1_0))) {
			vsw_send_dring_info(ldcp);
			break;
		}

		/*
		 * The peer doesn't operate in dring mode; we
		 * can simply fallthru to the RDX phase from
		 * here.
		 */
		/*FALLTHRU*/

	case VSW_MILESTONE2:
		/*
		 * If peer has indicated in its attribute message that
		 * it wishes to use descriptor rings then the only way
		 * to pass this milestone is for us to have received
		 * valid dring info.
		 *
		 * If peer is not using descriptor rings then just fall
		 * through.
		 */
		if ((VSW_VER_GTEQ(ldcp, 1, 2) &&
		    (lane_in->xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    (VSW_VER_LT(ldcp, 1, 2) &&
		    (lane_in->xfer_mode ==
		    VIO_DRING_MODE_V1_0))) {
			if (!(lane_in->lstate & VSW_DRING_ACK_SENT))
				break;
		}

		D2(vswp, "%s: (chan %lld) leaving milestone 2",
		    __func__, ldcp->ldc_id);

		ldcp->hphase = VSW_MILESTONE3;
		vsw_send_rdx(ldcp);
		break;

	case VSW_MILESTONE3:
		/*
		 * Pass this milestone when all paramaters have been
		 * successfully exchanged and RDX sent in both directions.
		 *
		 * Mark the relevant lane as available to transmit data. In
		 * RxDringData mode, lane_in is associated with transmit and
		 * lane_out is associated with receive. It is the reverse in
		 * TxDring mode.
		 */
		if ((lane_out->lstate & VSW_RDX_ACK_SENT) &&
		    (lane_in->lstate & VSW_RDX_ACK_RECV)) {

			D2(vswp, "%s: (chan %lld) leaving milestone 3",
			    __func__, ldcp->ldc_id);
			D2(vswp, "%s: ** handshake complete (0x%llx : "
			    "0x%llx) **", __func__, lane_in->lstate,
			    lane_out->lstate);
			if (lane_out->dring_mode == VIO_RX_DRING_DATA) {
				lane_in->lstate |= VSW_LANE_ACTIVE;
			} else {
				lane_out->lstate |= VSW_LANE_ACTIVE;
			}
			ldcp->hphase = VSW_MILESTONE4;
			ldcp->hcnt = 0;
			DISPLAY_STATE();
			/* Start HIO if enabled and capable */
			if ((portp->p_hio_enabled) && (portp->p_hio_capable)) {
				D2(vswp, "%s: start HybridIO setup", __func__);
				vsw_hio_start(vswp, ldcp);
			}

			if (ldcp->pls_negotiated == B_TRUE) {
				/*
				 * The vnet device has negotiated to get phys
				 * link updates. Now that the handshake with
				 * the vnet device is complete, send an initial
				 * update with the current physical link state.
				 */
				vsw_send_physlink_msg(ldcp,
				    vswp->phys_link_state);
			}

		} else {
			D2(vswp, "%s: still in milestone 3 (0x%llx : 0x%llx)",
			    __func__, lane_in->lstate,
			    lane_out->lstate);
		}
		break;

	case VSW_MILESTONE4:
		D2(vswp, "%s: (chan %lld) in milestone 4", __func__,
		    ldcp->ldc_id);
		break;

	default:
		DERR(vswp, "%s: (chan %lld) Unknown Phase %x", __func__,
		    ldcp->ldc_id, ldcp->hphase);
	}

	D1(vswp, "%s (chan %lld): exit (phase %ld)", __func__, ldcp->ldc_id,
	    ldcp->hphase);
}

/*
 * Check if major version is supported.
 *
 * Returns 0 if finds supported major number, and if necessary
 * adjusts the minor field.
 *
 * Returns 1 if can't match major number exactly. Sets mjor/minor
 * to next lowest support values, or to zero if no other values possible.
 */
static int
vsw_supported_version(vio_ver_msg_t *vp)
{
	int	i;

	D1(NULL, "vsw_supported_version: enter");

	for (i = 0; i < VSW_NUM_VER; i++) {
		if (vsw_versions[i].ver_major == vp->ver_major) {
			/*
			 * Matching or lower major version found. Update
			 * minor number if necessary.
			 */
			if (vp->ver_minor > vsw_versions[i].ver_minor) {
				D2(NULL, "%s: adjusting minor value from %d "
				    "to %d", __func__, vp->ver_minor,
				    vsw_versions[i].ver_minor);
				vp->ver_minor = vsw_versions[i].ver_minor;
			}

			return (0);
		}

		/*
		 * If the message contains a higher major version number, set
		 * the message's major/minor versions to the current values
		 * and return false, so this message will get resent with
		 * these values.
		 */
		if (vsw_versions[i].ver_major < vp->ver_major) {
			D2(NULL, "%s: adjusting major and minor "
			    "values to %d, %d\n",
			    __func__, vsw_versions[i].ver_major,
			    vsw_versions[i].ver_minor);
			vp->ver_major = vsw_versions[i].ver_major;
			vp->ver_minor = vsw_versions[i].ver_minor;
			return (1);
		}
	}

	/* No match was possible, zero out fields */
	vp->ver_major = 0;
	vp->ver_minor = 0;

	D1(NULL, "vsw_supported_version: exit");

	return (1);
}

/*
 * Set vnet-protocol-version dependent functions based on version.
 */
static void
vsw_set_vnet_proto_ops(vsw_ldc_t *ldcp)
{
	vsw_t	*vswp = ldcp->ldc_vswp;
	lane_t	*lp = &ldcp->lane_out;

	/*
	 * Setup the appropriate dring data processing routine and any
	 * associated thread based on the version.
	 *
	 * In versions < 1.6, we support only TxDring mode. In this mode, the
	 * msg worker thread processes all types of VIO msgs (ctrl and data).
	 *
	 * In versions >= 1.6, we also support RxDringData mode. In this mode,
	 * the rcv worker thread processes dring data messages (msgtype:
	 * VIO_TYPE_DATA, subtype: VIO_SUBTYPE_INFO, env: VIO_DRING_DATA). The
	 * rest of the data messages (including acks) and ctrl messages are
	 * handled directly by the callback (intr) thread.
	 *
	 * However, for versions >= 1.6, we could still fallback to TxDring
	 * mode. This could happen if RxDringData mode has been disabled (see
	 * below) on this guest or on the peer guest. This info is determined
	 * as part of attr exchange phase of handshake. Hence, we setup these
	 * pointers for v1.6 after attr msg phase completes during handshake.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 6)) {
		/*
		 * Set data dring mode for vsw_send_attr(). We setup msg worker
		 * thread in TxDring mode or rcv worker thread in RxDringData
		 * mode when attr phase of handshake completes.
		 */
		if (vsw_mapin_avail(ldcp) == B_TRUE) {
			lp->dring_mode = (VIO_RX_DRING_DATA | VIO_TX_DRING);
		} else {
			lp->dring_mode = VIO_TX_DRING;
		}
	} else {
		lp->dring_mode = VIO_TX_DRING;
	}

	/*
	 * Setup the MTU for attribute negotiation based on the version.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * If the version negotiated with peer is >= 1.4(Jumbo Frame
		 * Support), set the mtu in our attributes to max_frame_size.
		 */
		lp->mtu = vswp->max_frame_size;
	} else if (VSW_VER_EQ(ldcp, 1, 3)) {
		/*
		 * If the version negotiated with peer is == 1.3 (Vlan Tag
		 * Support) set the attr.mtu to ETHERMAX + VLAN_TAGSZ.
		 */
		lp->mtu = ETHERMAX + VLAN_TAGSZ;
	} else {
		vsw_port_t	*portp = ldcp->ldc_port;
		/*
		 * Pre-1.3 peers expect max frame size of ETHERMAX.
		 * We can negotiate that size with those peers provided only
		 * pvid is defined for our peer and there are no vids. Then we
		 * can send/recv only untagged frames of max size ETHERMAX.
		 * Note that pvid of the peer can be different, as vsw has to
		 * serve the vnet in that vlan even if itself is not assigned
		 * to that vlan.
		 */
		if (portp->nvids == 0) {
			lp->mtu = ETHERMAX;
		}
	}

	/*
	 * Setup version dependent data processing functions.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 2)) {
		/* Versions >= 1.2 */

		if (VSW_PRI_ETH_DEFINED(vswp)) {
			/*
			 * enable priority routines and pkt mode only if
			 * at least one pri-eth-type is specified in MD.
			 */
			ldcp->tx = vsw_ldctx_pri;
			ldcp->rx_pktdata = vsw_process_pkt_data;

			/* set xfer mode for vsw_send_attr() */
			lp->xfer_mode = VIO_PKT_MODE | VIO_DRING_MODE_V1_2;
		} else {
			/* no priority eth types defined in MD */

			ldcp->tx = vsw_ldctx;
			ldcp->rx_pktdata = vsw_process_pkt_data_nop;

			/* set xfer mode for vsw_send_attr() */
			lp->xfer_mode = VIO_DRING_MODE_V1_2;
		}

	} else {
		/* Versions prior to 1.2  */

		vsw_reset_vnet_proto_ops(ldcp);
	}
}

/*
 * Reset vnet-protocol-version dependent functions to v1.0.
 */
static void
vsw_reset_vnet_proto_ops(vsw_ldc_t *ldcp)
{
	lane_t	*lp = &ldcp->lane_out;

	ldcp->tx = vsw_ldctx;
	ldcp->rx_pktdata = vsw_process_pkt_data_nop;

	/* set xfer mode for vsw_send_attr() */
	lp->xfer_mode = VIO_DRING_MODE_V1_0;
}

static void
vsw_process_evt_read(vsw_ldc_t *ldcp)
{
	if (ldcp->msg_thread != NULL) {
		/*
		 * TxDring mode; wakeup message worker
		 * thread to process the VIO messages.
		 */
		mutex_exit(&ldcp->ldc_cblock);
		mutex_enter(&ldcp->msg_thr_lock);
		if (!(ldcp->msg_thr_flags & VSW_WTHR_DATARCVD)) {
			ldcp->msg_thr_flags |= VSW_WTHR_DATARCVD;
			cv_signal(&ldcp->msg_thr_cv);
		}
		mutex_exit(&ldcp->msg_thr_lock);
		mutex_enter(&ldcp->ldc_cblock);
	} else {
		/*
		 * We invoke vsw_process_pkt() in the context of the LDC
		 * callback (vsw_ldc_cb()) during handshake, until the dring
		 * mode is negotiated. After the dring mode is negotiated, the
		 * msgs are processed by the msg worker thread (above case) if
		 * the dring mode is TxDring. Otherwise (in RxDringData mode)
		 * we continue to process the msgs directly in the callback
		 * context.
		 */
		vsw_process_pkt(ldcp);
	}
}

/*
 * Main routine for processing messages received over LDC.
 */
void
vsw_process_pkt(void *arg)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t  *)arg;
	vsw_t		*vswp = ldcp->ldc_vswp;
	size_t		msglen;
	vio_msg_tag_t	*tagp;
	uint64_t	*ldcmsg;
	int		rv = 0;


	D1(vswp, "%s enter: ldcid (%lld)\n", __func__, ldcp->ldc_id);

	ASSERT(MUTEX_HELD(&ldcp->ldc_cblock));

	ldcmsg = ldcp->ldcmsg;
	/*
	 * If channel is up read messages until channel is empty.
	 */
	do {
		msglen = ldcp->msglen;
		rv = ldc_read(ldcp->ldc_handle, (caddr_t)ldcmsg, &msglen);

		if (rv != 0) {
			DERR(vswp, "%s :ldc_read err id(%lld) rv(%d) len(%d)\n",
			    __func__, ldcp->ldc_id, rv, msglen);
		}

		/* channel has been reset */
		if (rv == ECONNRESET) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
			break;
		}

		if (msglen == 0) {
			D2(vswp, "%s: ldc_read id(%lld) NODATA", __func__,
			    ldcp->ldc_id);
			break;
		}

		D2(vswp, "%s: ldc_read id(%lld): msglen(%d)", __func__,
		    ldcp->ldc_id, msglen);

		/*
		 * Figure out what sort of packet we have gotten by
		 * examining the msg tag, and then switch it appropriately.
		 */
		tagp = (vio_msg_tag_t *)ldcmsg;

		switch (tagp->vio_msgtype) {
		case VIO_TYPE_CTRL:
			vsw_dispatch_ctrl_task(ldcp, ldcmsg, tagp, msglen);
			break;
		case VIO_TYPE_DATA:
			vsw_process_data_pkt(ldcp, ldcmsg, tagp, msglen);
			break;
		case VIO_TYPE_ERR:
			vsw_process_err_pkt(ldcp, ldcmsg, tagp);
			break;
		default:
			DERR(vswp, "%s: Unknown tag(%lx) ", __func__,
			    "id(%lx)\n", tagp->vio_msgtype, ldcp->ldc_id);
			break;
		}
	} while (msglen);

	D1(vswp, "%s exit: ldcid (%lld)\n", __func__, ldcp->ldc_id);
}

/*
 * Dispatch a task to process a VIO control message.
 */
static void
vsw_dispatch_ctrl_task(vsw_ldc_t *ldcp, void *cpkt, vio_msg_tag_t *tagp,
    int msglen)
{
	vsw_ctrl_task_t		*ctaskp = NULL;
	vsw_port_t		*port = ldcp->ldc_port;
	vsw_t			*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	/*
	 * We need to handle RDX ACK messages in-band as once they
	 * are exchanged it is possible that we will get an
	 * immediate (legitimate) data packet.
	 */
	if ((tagp->vio_subtype_env == VIO_RDX) &&
	    (tagp->vio_subtype == VIO_SUBTYPE_ACK)) {

		if (vsw_check_flag(ldcp, INBOUND, VSW_RDX_ACK_RECV))
			return;

		ldcp->lane_in.lstate |= VSW_RDX_ACK_RECV;
		D2(vswp, "%s (%ld) handling RDX_ACK in place "
		    "(ostate 0x%llx : hphase %d)", __func__,
		    ldcp->ldc_id, ldcp->lane_in.lstate, ldcp->hphase);
		vsw_next_milestone(ldcp);
		return;
	}

	ctaskp = kmem_alloc(sizeof (vsw_ctrl_task_t), KM_NOSLEEP);

	if (ctaskp == NULL) {
		DERR(vswp, "%s: unable to alloc space for ctrl msg", __func__);
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
		return;
	}

	ctaskp->ldcp = ldcp;
	bcopy((def_msg_t *)cpkt, &ctaskp->pktp, msglen);
	ctaskp->hss_id = ldcp->hss_id;

	/*
	 * Dispatch task to processing taskq if port is not in
	 * the process of being detached.
	 */
	mutex_enter(&port->state_lock);
	if (port->state == VSW_PORT_INIT) {
		if ((vswp->taskq_p == NULL) ||
		    (ddi_taskq_dispatch(vswp->taskq_p, vsw_process_ctrl_pkt,
		    ctaskp, DDI_NOSLEEP) != DDI_SUCCESS)) {
			mutex_exit(&port->state_lock);
			DERR(vswp, "%s: unable to dispatch task to taskq",
			    __func__);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
			return;
		}
	} else {
		kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
		DWARN(vswp, "%s: port %d detaching, not dispatching "
		    "task", __func__, port->p_instance);
	}

	mutex_exit(&port->state_lock);

	D2(vswp, "%s: dispatched task to taskq for chan %d", __func__,
	    ldcp->ldc_id);
	D1(vswp, "%s: exit", __func__);
}

/*
 * Process a VIO ctrl message. Invoked from taskq.
 */
static void
vsw_process_ctrl_pkt(void *arg)
{
	vsw_ctrl_task_t	*ctaskp = (vsw_ctrl_task_t *)arg;
	vsw_ldc_t	*ldcp = ctaskp->ldcp;
	vsw_t		*vswp = ldcp->ldc_vswp;
	vio_msg_tag_t	tag;
	uint16_t	env;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	bcopy(&ctaskp->pktp, &tag, sizeof (vio_msg_tag_t));
	env = tag.vio_subtype_env;

	/* stale pkt check */
	if (ctaskp->hss_id < ldcp->hss_id) {
		DWARN(vswp, "%s: discarding stale packet belonging to earlier"
		    " (%ld) handshake session", __func__, ctaskp->hss_id);
		kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
		return;
	}

	/* session id check */
	if (ldcp->session_status & VSW_PEER_SESSION) {
		if (ldcp->peer_session != tag.vio_sid) {
			DERR(vswp, "%s (chan %d): invalid session id (%llx)",
			    __func__, ldcp->ldc_id, tag.vio_sid);
			kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return;
		}
	}

	/*
	 * Switch on vio_subtype envelope, then let lower routines
	 * decide if its an INFO, ACK or NACK packet.
	 */
	switch (env) {
	case VIO_VER_INFO:
		vsw_process_ctrl_ver_pkt(ldcp, &ctaskp->pktp);
		break;
	case VIO_DRING_REG:
		vsw_process_ctrl_dring_reg_pkt(ldcp, &ctaskp->pktp);
		break;
	case VIO_DRING_UNREG:
		vsw_process_ctrl_dring_unreg_pkt(ldcp, &ctaskp->pktp);
		break;
	case VIO_ATTR_INFO:
		vsw_process_ctrl_attr_pkt(ldcp, &ctaskp->pktp);
		break;
	case VNET_MCAST_INFO:
		vsw_process_ctrl_mcst_pkt(ldcp, &ctaskp->pktp);
		break;
	case VIO_RDX:
		vsw_process_ctrl_rdx_pkt(ldcp, &ctaskp->pktp);
		break;
	case VIO_DDS_INFO:
		vsw_process_dds_msg(vswp, ldcp, &ctaskp->pktp);
		break;

	case VNET_PHYSLINK_INFO:
		vsw_process_physlink_msg(ldcp, &ctaskp->pktp);
		break;
	default:
		DERR(vswp, "%s: unknown vio_subtype_env (%x)\n", __func__, env);
	}

	kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Version negotiation. We can end up here either because our peer
 * has responded to a handshake message we have sent it, or our peer
 * has initiated a handshake with us. If its the former then can only
 * be ACK or NACK, if its the later can only be INFO.
 *
 * If its an ACK we move to the next stage of the handshake, namely
 * attribute exchange. If its a NACK we see if we can specify another
 * version, if we can't we stop.
 *
 * If it is an INFO we reset all params associated with communication
 * in that direction over this channel (remember connection is
 * essentially 2 independent simplex channels).
 */
void
vsw_process_ctrl_ver_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vio_ver_msg_t	*ver_pkt;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a ctrl/version packet so
	 * cast it into the correct structure.
	 */
	ver_pkt = (vio_ver_msg_t *)pkt;

	switch (ver_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "vsw_process_ctrl_ver_pkt: VIO_SUBTYPE_INFO\n");

		/*
		 * Record the session id, which we will use from now
		 * until we see another VER_INFO msg. Even then the
		 * session id in most cases will be unchanged, execpt
		 * if channel was reset.
		 */
		if ((ldcp->session_status & VSW_PEER_SESSION) &&
		    (ldcp->peer_session != ver_pkt->tag.vio_sid)) {
			DERR(vswp, "%s: updating session id for chan %lld "
			    "from %llx to %llx", __func__, ldcp->ldc_id,
			    ldcp->peer_session, ver_pkt->tag.vio_sid);
		}

		ldcp->peer_session = ver_pkt->tag.vio_sid;
		ldcp->session_status |= VSW_PEER_SESSION;

		/* Legal message at this time ? */
		if (vsw_check_flag(ldcp, INBOUND, VSW_VER_INFO_RECV))
			return;

		/*
		 * First check the device class. Currently only expect
		 * to be talking to a network device. In the future may
		 * also talk to another switch.
		 */
		if (ver_pkt->dev_class != VDEV_NETWORK) {
			DERR(vswp, "%s: illegal device class %d", __func__,
			    ver_pkt->dev_class);

			ver_pkt->tag.vio_sid = ldcp->local_session;
			ver_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)ver_pkt);

			(void) vsw_send_msg(ldcp, (void *)ver_pkt,
			    sizeof (vio_ver_msg_t), B_TRUE);

			ldcp->lane_in.lstate |= VSW_VER_NACK_SENT;
			vsw_next_milestone(ldcp);
			return;
		} else {
			ldcp->dev_class = ver_pkt->dev_class;
		}

		/*
		 * Now check the version.
		 */
		if (vsw_supported_version(ver_pkt) == 0) {
			/*
			 * Support this major version and possibly
			 * adjusted minor version.
			 */

			D2(vswp, "%s: accepted ver %d:%d", __func__,
			    ver_pkt->ver_major, ver_pkt->ver_minor);

			/* Store accepted values */
			ldcp->lane_in.ver_major = ver_pkt->ver_major;
			ldcp->lane_in.ver_minor = ver_pkt->ver_minor;

			ver_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;

			ldcp->lane_in.lstate |= VSW_VER_ACK_SENT;

			if (vsw_obp_ver_proto_workaround == B_TRUE) {
				/*
				 * Send a version info message
				 * using the accepted version that
				 * we are about to ack. Also note that
				 * we send our ver info before we ack.
				 * Otherwise, as soon as receiving the
				 * ack, obp sends attr info msg, which
				 * breaks vsw_check_flag() invoked
				 * from vsw_process_ctrl_attr_pkt();
				 * as we also need VSW_VER_ACK_RECV to
				 * be set in lane_out.lstate, before
				 * we can receive attr info.
				 */
				vsw_send_ver(ldcp);
			}
		} else {
			/*
			 * NACK back with the next lower major/minor
			 * pairing we support (if don't suuport any more
			 * versions then they will be set to zero.
			 */

			D2(vswp, "%s: replying with ver %d:%d", __func__,
			    ver_pkt->ver_major, ver_pkt->ver_minor);

			/* Store updated values */
			ldcp->lane_in.ver_major = ver_pkt->ver_major;
			ldcp->lane_in.ver_minor = ver_pkt->ver_minor;

			ver_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			ldcp->lane_in.lstate |= VSW_VER_NACK_SENT;
		}

		DUMP_TAG_PTR((vio_msg_tag_t *)ver_pkt);
		ver_pkt->tag.vio_sid = ldcp->local_session;
		(void) vsw_send_msg(ldcp, (void *)ver_pkt,
		    sizeof (vio_ver_msg_t), B_TRUE);

		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK\n", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_VER_ACK_RECV))
			return;

		/* Store updated values */
		ldcp->lane_out.ver_major = ver_pkt->ver_major;
		ldcp->lane_out.ver_minor = ver_pkt->ver_minor;

		ldcp->lane_out.lstate |= VSW_VER_ACK_RECV;
		vsw_next_milestone(ldcp);

		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK\n", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_VER_NACK_RECV))
			return;

		/*
		 * If our peer sent us a NACK with the ver fields set to
		 * zero then there is nothing more we can do. Otherwise see
		 * if we support either the version suggested, or a lesser
		 * one.
		 */
		if ((ver_pkt->ver_major == 0) && (ver_pkt->ver_minor == 0)) {
			DERR(vswp, "%s: peer unable to negotiate any "
			    "further.", __func__);
			ldcp->lane_out.lstate |= VSW_VER_NACK_RECV;
			vsw_next_milestone(ldcp);
			return;
		}

		/*
		 * Check to see if we support this major version or
		 * a lower one. If we don't then maj/min will be set
		 * to zero.
		 */
		(void) vsw_supported_version(ver_pkt);
		if ((ver_pkt->ver_major == 0) && (ver_pkt->ver_minor == 0)) {
			/* Nothing more we can do */
			DERR(vswp, "%s: version negotiation failed.\n",
			    __func__);
			ldcp->lane_out.lstate |= VSW_VER_NACK_RECV;
			vsw_next_milestone(ldcp);
		} else {
			/* found a supported major version */
			ldcp->lane_out.ver_major = ver_pkt->ver_major;
			ldcp->lane_out.ver_minor = ver_pkt->ver_minor;

			D2(vswp, "%s: resending with updated values (%x, %x)",
			    __func__, ver_pkt->ver_major, ver_pkt->ver_minor);

			ldcp->lane_out.lstate |= VSW_VER_INFO_SENT;
			ver_pkt->tag.vio_sid = ldcp->local_session;
			ver_pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;

			DUMP_TAG_PTR((vio_msg_tag_t *)ver_pkt);

			(void) vsw_send_msg(ldcp, (void *)ver_pkt,
			    sizeof (vio_ver_msg_t), B_TRUE);

			vsw_next_milestone(ldcp);

		}
		break;

	default:
		DERR(vswp, "%s: unknown vio_subtype %x\n", __func__,
		    ver_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld): exit\n", __func__, ldcp->ldc_id);
}

static int
vsw_process_attr_info(vsw_ldc_t *ldcp, vnet_attr_msg_t *msg)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	vsw_port_t		*port = ldcp->ldc_port;
	struct ether_addr	ea;
	uint64_t		macaddr = 0;
	lane_t			*lane_out = &ldcp->lane_out;
	lane_t			*lane_in = &ldcp->lane_in;
	uint32_t		mtu;
	int			i;
	uint8_t			dring_mode;

	D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

	if (vsw_check_flag(ldcp, INBOUND, VSW_ATTR_INFO_RECV)) {
		return (1);
	}

	if ((msg->xfer_mode != VIO_DESC_MODE) &&
	    (msg->xfer_mode != lane_out->xfer_mode)) {
		D2(NULL, "%s: unknown mode %x\n", __func__, msg->xfer_mode);
		return (1);
	}

	/* Only support MAC addresses at moment. */
	if ((msg->addr_type != ADDR_TYPE_MAC) || (msg->addr == 0)) {
		D2(NULL, "%s: invalid addr_type %x, or address 0x%llx\n",
		    __func__, msg->addr_type, msg->addr);
		return (1);
	}

	/*
	 * MAC address supplied by device should match that stored
	 * in the vsw-port OBP node. Need to decide what to do if they
	 * don't match, for the moment just warn but don't fail.
	 */
	vnet_macaddr_ultostr(msg->addr, ea.ether_addr_octet);
	if (ether_cmp(&ea, &port->p_macaddr) != 0) {
		DERR(NULL, "%s: device supplied address "
		    "0x%llx doesn't match node address 0x%llx\n",
		    __func__, msg->addr, port->p_macaddr);
	}

	/*
	 * Ack freq only makes sense in pkt mode, in shared
	 * mode the ring descriptors say whether or not to
	 * send back an ACK.
	 */
	if ((VSW_VER_GTEQ(ldcp, 1, 2) &&
	    (msg->xfer_mode & VIO_DRING_MODE_V1_2)) ||
	    (VSW_VER_LT(ldcp, 1, 2) &&
	    (msg->xfer_mode == VIO_DRING_MODE_V1_0))) {
		if (msg->ack_freq > 0) {
			D2(NULL, "%s: non zero ack freq in SHM mode\n",
			    __func__);
			return (1);
		}
	}

	/*
	 * Process dring mode attribute.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 6)) {
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
		    vsw_mapin_avail(ldcp) == B_TRUE) {
			/*
			 * The peer is capable of handling RxDringData AND we
			 * are also capable of it; we enable RxDringData mode
			 * on this channel.
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
			return (1);
		}

		/*
		 * If we have received an ack for the attr info that we sent,
		 * then check if the dring mode matches what the peer had ack'd
		 * (saved in lane_out). If they don't match, we fail the
		 * handshake.
		 */
		if (lane_out->lstate & VSW_ATTR_ACK_RECV) {
			if (msg->options != lane_out->dring_mode) {
				/* send NACK */
				return (1);
			}
		} else {
			/*
			 * Save the negotiated dring mode in our attr
			 * parameters, so it gets sent in the attr info from us
			 * to the peer.
			 */
			lane_out->dring_mode = dring_mode;
		}

		/* save the negotiated dring mode in the msg to be replied */
		msg->options = dring_mode;
	}

	/*
	 * Process MTU attribute.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * Versions >= 1.4:
		 * Validate mtu of the peer is at least ETHERMAX. Then, the mtu
		 * is negotiated down to the minimum of our mtu and peer's mtu.
		 */
		if (msg->mtu < ETHERMAX) {
			return (1);
		}

		mtu = MIN(msg->mtu, vswp->max_frame_size);

		/*
		 * If we have received an ack for the attr info
		 * that we sent, then check if the mtu computed
		 * above matches the mtu that the peer had ack'd
		 * (saved in local hparams). If they don't
		 * match, we fail the handshake.
		 */
		if (lane_out->lstate & VSW_ATTR_ACK_RECV) {
			if (mtu != lane_out->mtu) {
				/* send NACK */
				return (1);
			}
		} else {
			/*
			 * Save the mtu computed above in our
			 * attr parameters, so it gets sent in
			 * the attr info from us to the peer.
			 */
			lane_out->mtu = mtu;
		}

		/* save the MIN mtu in the msg to be replied */
		msg->mtu = mtu;
	} else {
		/* Versions < 1.4, mtu must match */
		if (msg->mtu != lane_out->mtu) {
			D2(NULL, "%s: invalid MTU (0x%llx)\n",
			    __func__, msg->mtu);
			return (1);
		}
	}

	/*
	 * Otherwise store attributes for this lane and update
	 * lane state.
	 */
	lane_in->mtu = msg->mtu;
	lane_in->addr = msg->addr;
	lane_in->addr_type = msg->addr_type;
	lane_in->xfer_mode = msg->xfer_mode;
	lane_in->ack_freq = msg->ack_freq;
	lane_in->physlink_update = msg->physlink_update;
	lane_in->dring_mode = msg->options;

	/*
	 * Check if the client has requested physlink state updates.
	 * If there is a physical device bound to this vswitch (L2
	 * mode), set the ack bits to indicate it is supported.
	 * Otherwise, set the nack bits.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 5)) {	/* Protocol ver >= 1.5 */

		/* Does the vnet need phys link state updates ? */
		if ((lane_in->physlink_update &
		    PHYSLINK_UPDATE_STATE_MASK) ==
		    PHYSLINK_UPDATE_STATE) {

			if (vswp->smode & VSW_LAYER2) {
				/* is a net-dev assigned to us ? */
				msg->physlink_update =
				    PHYSLINK_UPDATE_STATE_ACK;
				ldcp->pls_negotiated = B_TRUE;
			} else {
				/* not in L2 mode */
				msg->physlink_update =
				    PHYSLINK_UPDATE_STATE_NACK;
				ldcp->pls_negotiated = B_FALSE;
			}

		} else {
			msg->physlink_update =
			    PHYSLINK_UPDATE_NONE;
			ldcp->pls_negotiated = B_FALSE;
		}

	} else {
		/*
		 * physlink_update bits are ignored
		 * if set by clients < v1.5 protocol.
		 */
		msg->physlink_update = PHYSLINK_UPDATE_NONE;
		ldcp->pls_negotiated = B_FALSE;
	}

	macaddr = lane_in->addr;
	for (i = ETHERADDRL - 1; i >= 0; i--) {
		port->p_macaddr.ether_addr_octet[i] = macaddr & 0xFF;
		macaddr >>= 8;
	}

	/*
	 * Setup device specific xmit routines. Note this could be changed
	 * further in vsw_send_dring_info() for versions >= 1.6 if operating in
	 * RxDringData mode.
	 */
	mutex_enter(&port->tx_lock);

	if ((VSW_VER_GTEQ(ldcp, 1, 2) &&
	    (lane_in->xfer_mode & VIO_DRING_MODE_V1_2)) ||
	    (VSW_VER_LT(ldcp, 1, 2) &&
	    (lane_in->xfer_mode == VIO_DRING_MODE_V1_0))) {
		D2(vswp, "%s: mode = VIO_DRING_MODE", __func__);
		port->transmit = vsw_dringsend;
	} else if (lane_in->xfer_mode == VIO_DESC_MODE) {
		D2(vswp, "%s: mode = VIO_DESC_MODE", __func__);
		vsw_create_privring(ldcp);
		port->transmit = vsw_descrsend;
		lane_out->xfer_mode = VIO_DESC_MODE;
	}

	/*
	 * HybridIO is supported only vnet, not by OBP.
	 * So, set hio_capable to true only when in DRING mode.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 3) &&
	    (lane_in->xfer_mode != VIO_DESC_MODE)) {
		(void) atomic_swap_32(&port->p_hio_capable, B_TRUE);
	} else {
		(void) atomic_swap_32(&port->p_hio_capable, B_FALSE);
	}

	mutex_exit(&port->tx_lock);

	return (0);
}

static int
vsw_process_attr_ack(vsw_ldc_t *ldcp, vnet_attr_msg_t *msg)
{
	vsw_t	*vswp = ldcp->ldc_vswp;
	lane_t	*lane_out = &ldcp->lane_out;
	lane_t	*lane_in = &ldcp->lane_in;

	D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

	if (vsw_check_flag(ldcp, OUTBOUND, VSW_ATTR_ACK_RECV)) {
		return (1);
	}

	/*
	 * Process dring mode attribute.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 6)) {
		/*
		 * Versions >= 1.6:
		 * The ack msg sent by the peer contains the negotiated dring
		 * mode between our capability (that we had sent in our attr
		 * info) and the peer's capability.
		 */
		if (lane_in->lstate & VSW_ATTR_ACK_SENT) {
			/*
			 * If we have sent an ack for the attr info msg from
			 * the peer, check if the dring mode that was
			 * negotiated then (saved in lane_out) matches the
			 * mode that the peer has ack'd. If they don't match,
			 * we fail the handshake.
			 */
			if (lane_out->dring_mode != msg->options) {
				return (1);
			}
		} else {
			if ((msg->options & lane_out->dring_mode) == 0) {
				/*
				 * Peer ack'd with a mode that we don't
				 * support; we fail the handshake.
				 */
				return (1);
			}
			if ((msg->options & (VIO_TX_DRING|VIO_RX_DRING_DATA))
			    == (VIO_TX_DRING|VIO_RX_DRING_DATA)) {
				/*
				 * Peer must ack with only one negotiated mode.
				 * Otherwise fail handshake.
				 */
				return (1);
			}

			/*
			 * Save the negotiated mode, so we can validate it when
			 * we receive attr info from the peer.
			 */
			lane_out->dring_mode = msg->options;
		}
	}

	/*
	 * Process MTU attribute.
	 */
	if (VSW_VER_GTEQ(ldcp, 1, 4)) {
		/*
		 * Versions >= 1.4:
		 * The ack msg sent by the peer contains the minimum of
		 * our mtu (that we had sent in our attr info) and the
		 * peer's mtu.
		 *
		 * If we have sent an ack for the attr info msg from
		 * the peer, check if the mtu that was computed then
		 * (saved in lane_out params) matches the mtu that the
		 * peer has ack'd. If they don't match, we fail the
		 * handshake.
		 */
		if (lane_in->lstate & VSW_ATTR_ACK_SENT) {
			if (lane_out->mtu != msg->mtu) {
				return (1);
			}
		} else {
			/*
			 * If the mtu ack'd by the peer is > our mtu
			 * fail handshake. Otherwise, save the mtu, so
			 * we can validate it when we receive attr info
			 * from our peer.
			 */
			if (msg->mtu <= lane_out->mtu) {
				lane_out->mtu = msg->mtu;
			} else {
				return (1);
			}
		}
	}

	return (0);
}

/*
 * Process an attribute packet. We can end up here either because our peer
 * has ACK/NACK'ed back to an earlier ATTR msg we had sent it, or our
 * peer has sent us an attribute INFO message
 *
 * If its an ACK we then move to the next stage of the handshake which
 * is to send our descriptor ring info to our peer. If its a NACK then
 * there is nothing more we can (currently) do.
 *
 * If we get a valid/acceptable INFO packet (and we have already negotiated
 * a version) we ACK back and set channel state to ATTR_RECV, otherwise we
 * NACK back and reset channel state to INACTIV.
 *
 * FUTURE: in time we will probably negotiate over attributes, but for
 * the moment unacceptable attributes are regarded as a fatal error.
 *
 */
void
vsw_process_ctrl_attr_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vnet_attr_msg_t	*attr_pkt;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lane_out = &ldcp->lane_out;
	lane_t		*lane_in = &ldcp->lane_in;
	int		rv;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a ctrl/attr packet so
	 * cast it into the correct structure.
	 */
	attr_pkt = (vnet_attr_msg_t *)pkt;

	switch (attr_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:

		rv = vsw_process_attr_info(ldcp, attr_pkt);
		if (rv != 0) {
			vsw_free_lane_resources(ldcp, INBOUND);
			attr_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;
			ldcp->lane_in.lstate |= VSW_ATTR_NACK_SENT;
		} else {
			attr_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
			lane_in->lstate |= VSW_ATTR_ACK_SENT;
		}
		attr_pkt->tag.vio_sid = ldcp->local_session;
		DUMP_TAG_PTR((vio_msg_tag_t *)attr_pkt);
		(void) vsw_send_msg(ldcp, (void *)attr_pkt,
		    sizeof (vnet_attr_msg_t), B_TRUE);
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:

		rv = vsw_process_attr_ack(ldcp, attr_pkt);
		if (rv != 0) {
			return;
		}
		lane_out->lstate |= VSW_ATTR_ACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_ATTR_NACK_RECV))
			return;

		lane_out->lstate |= VSW_ATTR_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: unknown vio_subtype %x\n", __func__,
		    attr_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
}

static int
vsw_process_dring_reg_info(vsw_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	int		rv;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_out;
	dring_info_t	*dp = NULL;

	D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

	rv = vsw_check_flag(ldcp, INBOUND, VSW_DRING_INFO_RECV);
	if (rv != 0) {
		return (1);
	}

	if (VSW_VER_GTEQ(ldcp, 1, 6) &&
	    (lp->dring_mode != ((vio_dring_reg_msg_t *)tagp)->options)) {
		/*
		 * The earlier version of Solaris vnet driver doesn't set the
		 * option (VIO_TX_DRING in its case) correctly in its dring reg
		 * message. We workaround that here by doing the check only
		 * for versions >= v1.6.
		 */
		DWARN(vswp, "%s(%lld): Rcvd dring reg option (%d), "
		    "negotiated mode (%d)\n", __func__, ldcp->ldc_id,
		    ((vio_dring_reg_msg_t *)tagp)->options, lp->dring_mode);
		return (1);
	}

	/*
	 * Map dring exported by the peer.
	 */
	dp = vsw_map_dring(ldcp, (void *)tagp);
	if (dp == NULL) {
		return (1);
	}

	/*
	 * Map data buffers exported by the peer if we are in RxDringData mode.
	 */
	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		rv = vsw_map_data(ldcp, dp, (void *)tagp);
		if (rv != 0) {
			vsw_unmap_dring(ldcp);
			return (1);
		}
	}

	return (0);
}

static int
vsw_process_dring_reg_ack(vsw_ldc_t *ldcp, vio_msg_tag_t *tagp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	dring_info_t	*dp;

	D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

	if (vsw_check_flag(ldcp, OUTBOUND, VSW_DRING_ACK_RECV)) {
		return (1);
	}

	dp = ldcp->lane_out.dringp;

	/* save dring_ident acked by peer */
	dp->ident = ((vio_dring_reg_msg_t *)tagp)->dring_ident;

	return (0);
}

/*
 * Process a dring info packet. We can end up here either because our peer
 * has ACK/NACK'ed back to an earlier DRING msg we had sent it, or our
 * peer has sent us a dring INFO message.
 *
 * If we get a valid/acceptable INFO packet (and we have already negotiated
 * a version) we ACK back and update the lane state, otherwise we NACK back.
 *
 * FUTURE: nothing to stop client from sending us info on multiple dring's
 * but for the moment we will just use the first one we are given.
 *
 */
void
vsw_process_ctrl_dring_reg_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	int		rv;
	int		msgsize;
	dring_info_t	*dp;
	vio_msg_tag_t	*tagp = (vio_msg_tag_t *)pkt;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lane_out = &ldcp->lane_out;
	lane_t		*lane_in = &ldcp->lane_in;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	switch (tagp->vio_subtype) {
	case VIO_SUBTYPE_INFO:
		rv = vsw_process_dring_reg_info(ldcp, tagp);
		if (rv != 0) {
			vsw_free_lane_resources(ldcp, INBOUND);
			tagp->vio_subtype = VIO_SUBTYPE_NACK;
			lane_in->lstate |= VSW_DRING_NACK_SENT;
		} else {
			tagp->vio_subtype = VIO_SUBTYPE_ACK;
			lane_in->lstate |= VSW_DRING_ACK_SENT;
		}
		tagp->vio_sid = ldcp->local_session;
		DUMP_TAG_PTR(tagp);
		if (lane_out->dring_mode == VIO_RX_DRING_DATA) {
			dp = lane_in->dringp;
			msgsize =
			    VNET_DRING_REG_EXT_MSG_SIZE(dp->data_ncookies);
		} else {
			msgsize = sizeof (vio_dring_reg_msg_t);
		}
		(void) vsw_send_msg(ldcp, (void *)tagp, msgsize, B_TRUE);
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		rv = vsw_process_dring_reg_ack(ldcp, tagp);
		if (rv != 0) {
			return;
		}
		lane_out->lstate |= VSW_DRING_ACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_DRING_NACK_RECV))
			return;

		lane_out->lstate |= VSW_DRING_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
		    tagp->vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
}

/*
 * Process a request from peer to unregister a dring.
 *
 * For the moment we just restart the handshake if our
 * peer endpoint attempts to unregister a dring.
 */
void
vsw_process_ctrl_dring_unreg_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	vio_dring_unreg_msg_t	*dring_pkt;

	/*
	 * We know this is a ctrl/dring packet so
	 * cast it into the correct structure.
	 */
	dring_pkt = (vio_dring_unreg_msg_t *)pkt;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	switch (dring_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		DWARN(vswp, "%s: restarting handshake..", __func__);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		DWARN(vswp, "%s: restarting handshake..", __func__);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		DWARN(vswp, "%s: restarting handshake..", __func__);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
		    dring_pkt->tag.vio_subtype);
	}

	vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

#define	SND_MCST_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	(void) vsw_send_msg(ldcp, (void *)pkt, \
			sizeof (vnet_mcast_msg_t), B_TRUE);

/*
 * Process a multicast request from a vnet.
 *
 * Vnet's specify a multicast address that they are interested in. This
 * address is used as a key into the hash table which forms the multicast
 * forwarding database (mFDB).
 *
 * The table keys are the multicast addresses, while the table entries
 * are pointers to lists of ports which wish to receive packets for the
 * specified multicast address.
 *
 * When a multicast packet is being switched we use the address as a key
 * into the hash table, and then walk the appropriate port list forwarding
 * the pkt to each port in turn.
 *
 * If a vnet is no longer interested in a particular multicast grouping
 * we simply find the correct location in the hash table and then delete
 * the relevant port from the port list.
 *
 * To deal with the case whereby a port is being deleted without first
 * removing itself from the lists in the hash table, we maintain a list
 * of multicast addresses the port has registered an interest in, within
 * the port structure itself. We then simply walk that list of addresses
 * using them as keys into the hash table and remove the port from the
 * appropriate lists.
 */
static void
vsw_process_ctrl_mcst_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vnet_mcast_msg_t	*mcst_pkt;
	vsw_port_t		*port = ldcp->ldc_port;
	vsw_t			*vswp = ldcp->ldc_vswp;
	int			i;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a ctrl/mcast packet so
	 * cast it into the correct structure.
	 */
	mcst_pkt = (vnet_mcast_msg_t *)pkt;

	switch (mcst_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		/*
		 * Check if in correct state to receive a multicast
		 * message (i.e. handshake complete). If not reset
		 * the handshake.
		 */
		if (vsw_check_flag(ldcp, INBOUND, VSW_MCST_INFO_RECV))
			return;

		/*
		 * Before attempting to add or remove address check
		 * that they are valid multicast addresses.
		 * If not, then NACK back.
		 */
		for (i = 0; i < mcst_pkt->count; i++) {
			if ((mcst_pkt->mca[i].ether_addr_octet[0] & 01) != 1) {
				DERR(vswp, "%s: invalid multicast address",
				    __func__);
				SND_MCST_NACK(ldcp, mcst_pkt);
				return;
			}
		}

		/*
		 * Now add/remove the addresses. If this fails we
		 * NACK back.
		 */
		if (vsw_add_rem_mcst(mcst_pkt, port) != 0) {
			SND_MCST_NACK(ldcp, mcst_pkt);
			return;
		}

		mcst_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
		mcst_pkt->tag.vio_sid = ldcp->local_session;

		DUMP_TAG_PTR((vio_msg_tag_t *)mcst_pkt);

		(void) vsw_send_msg(ldcp, (void *)mcst_pkt,
		    sizeof (vnet_mcast_msg_t), B_TRUE);
		break;

	case VIO_SUBTYPE_ACK:
		DWARN(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		/*
		 * We shouldn't ever get a multicast ACK message as
		 * at the moment we never request multicast addresses
		 * to be set on some other device. This may change in
		 * the future if we have cascading switches.
		 */
		if (vsw_check_flag(ldcp, OUTBOUND, VSW_MCST_ACK_RECV))
			return;

				/* Do nothing */
		break;

	case VIO_SUBTYPE_NACK:
		DWARN(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		/*
		 * We shouldn't get a multicast NACK packet for the
		 * same reasons as we shouldn't get a ACK packet.
		 */
		if (vsw_check_flag(ldcp, OUTBOUND, VSW_MCST_NACK_RECV))
			return;

				/* Do nothing */
		break;

	default:
		DERR(vswp, "%s: unknown vio_subtype %x\n", __func__,
		    mcst_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

static void
vsw_process_ctrl_rdx_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vio_rdx_msg_t	*rdx_pkt;
	vsw_t		*vswp = ldcp->ldc_vswp;

	/*
	 * We know this is a ctrl/rdx packet so
	 * cast it into the correct structure.
	 */
	rdx_pkt = (vio_rdx_msg_t *)pkt;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	switch (rdx_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_RDX_INFO_RECV))
			return;

		rdx_pkt->tag.vio_sid = ldcp->local_session;
		rdx_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;

		DUMP_TAG_PTR((vio_msg_tag_t *)rdx_pkt);

		ldcp->lane_out.lstate |= VSW_RDX_ACK_SENT;

		(void) vsw_send_msg(ldcp, (void *)rdx_pkt,
		    sizeof (vio_rdx_msg_t), B_TRUE);

		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		/*
		 * Should be handled in-band by callback handler.
		 */
		DERR(vswp, "%s: Unexpected VIO_SUBTYPE_ACK", __func__);
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, INBOUND, VSW_RDX_NACK_RECV))
			return;

		ldcp->lane_in.lstate |= VSW_RDX_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
		    rdx_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

static void
vsw_process_physlink_msg(vsw_ldc_t *ldcp, void *pkt)
{
	vnet_physlink_msg_t	*msgp;
	vsw_t			*vswp = ldcp->ldc_vswp;

	msgp = (vnet_physlink_msg_t *)pkt;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	switch (msgp->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:

		/* vsw shouldn't recv physlink info */
		DWARN(vswp, "%s: Unexpected VIO_SUBTYPE_INFO", __func__);
		break;

	case VIO_SUBTYPE_ACK:

		D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);
		break;

	case VIO_SUBTYPE_NACK:

		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
		    msgp->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

static void
vsw_process_data_pkt(vsw_ldc_t *ldcp, void *dpkt, vio_msg_tag_t *tagp,
    uint32_t msglen)
{
	uint16_t	env = tagp->vio_subtype_env;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_out;
	uint8_t		dring_mode = lp->dring_mode;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/* session id check */
	if (ldcp->session_status & VSW_PEER_SESSION) {
		if (ldcp->peer_session != tagp->vio_sid) {
			DERR(vswp, "%s (chan %d): invalid session id (%llx)",
			    __func__, ldcp->ldc_id, tagp->vio_sid);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return;
		}
	}

	/*
	 * It is an error for us to be getting data packets
	 * before the handshake has completed.
	 */
	if (ldcp->hphase != VSW_MILESTONE4) {
		DERR(vswp, "%s: got data packet before handshake complete "
		    "hphase %d (%x: %x)", __func__, ldcp->hphase,
		    ldcp->lane_in.lstate, ldcp->lane_out.lstate);
		DUMP_FLAGS(ldcp->lane_in.lstate);
		DUMP_FLAGS(ldcp->lane_out.lstate);
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
		return;
	}
	if (dring_mode == VIO_TX_DRING) {
		/*
		 * To reduce the locking contention, release the ldc_cblock
		 * here and re-acquire it once we are done receiving packets.
		 * We do this only in TxDring mode to allow further callbaks to
		 * continue while the msg worker thread processes the messages.
		 * In RxDringData mode, we process the messages in the callback
		 * itself and wake up rcv worker thread to process only data
		 * info messages.
		 */
		mutex_exit(&ldcp->ldc_cblock);
		mutex_enter(&ldcp->ldc_rxlock);
	}

	/*
	 * Switch on vio_subtype envelope, then let lower routines
	 * decide if its an INFO, ACK or NACK packet.
	 */
	if (env == VIO_DRING_DATA) {
		ldcp->rx_dringdata(ldcp, dpkt);
	} else if (env == VIO_PKT_DATA) {
		ldcp->rx_pktdata(ldcp, dpkt, msglen);
	} else if (env == VIO_DESC_DATA) {
		vsw_process_data_ibnd_pkt(ldcp, dpkt);
	} else {
		DERR(vswp, "%s: unknown vio_subtype_env (%x)\n",
		    __func__, env);
	}

	if (dring_mode == VIO_TX_DRING) {
		mutex_exit(&ldcp->ldc_rxlock);
		mutex_enter(&ldcp->ldc_cblock);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * dummy pkt data handler function for vnet protocol version 1.0
 */
static void
vsw_process_pkt_data_nop(void *arg1, void *arg2, uint32_t msglen)
{
	_NOTE(ARGUNUSED(arg1, arg2, msglen))
}

/*
 * This function handles raw pkt data messages received over the channel.
 * Currently, only priority-eth-type frames are received through this mechanism.
 * In this case, the frame(data) is present within the message itself which
 * is copied into an mblk before switching it.
 */
static void
vsw_process_pkt_data(void *arg1, void *arg2, uint32_t msglen)
{
	vsw_ldc_t		*ldcp = (vsw_ldc_t *)arg1;
	vio_raw_data_msg_t	*dpkt = (vio_raw_data_msg_t *)arg2;
	uint32_t		size;
	mblk_t			*mp;
	vio_mblk_t		*vmp;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vgen_stats_t		*statsp = &ldcp->ldc_stats;
	lane_t			*lp = &ldcp->lane_out;

	size = msglen - VIO_PKT_DATA_HDRSIZE;
	if (size < ETHERMIN || size > lp->mtu) {
		(void) atomic_inc_32(&statsp->rx_pri_fail);
		DWARN(vswp, "%s(%lld) invalid size(%d)\n", __func__,
		    ldcp->ldc_id, size);
		return;
	}

	vmp = vio_multipool_allocb(&ldcp->vmp, size + VLAN_TAGSZ);
	if (vmp == NULL) {
		mp = allocb(size + VLAN_TAGSZ, BPRI_MED);
		if (mp == NULL) {
			(void) atomic_inc_32(&statsp->rx_pri_fail);
			DWARN(vswp, "%s(%lld) allocb failure, "
			    "unable to process priority frame\n", __func__,
			    ldcp->ldc_id);
			return;
		}
	} else {
		mp = vmp->mp;
	}

	/* skip over the extra space for vlan tag */
	mp->b_rptr += VLAN_TAGSZ;

	/* copy the frame from the payload of raw data msg into the mblk */
	bcopy(dpkt->data, mp->b_rptr, size);
	mp->b_wptr = mp->b_rptr + size;

	if (vmp != NULL) {
		vmp->state = VIO_MBLK_HAS_DATA;
	}

	/* update stats */
	(void) atomic_inc_64(&statsp->rx_pri_packets);
	(void) atomic_add_64(&statsp->rx_pri_bytes, size);

	/*
	 * VLAN_TAGSZ of extra space has been pre-alloc'd if tag is needed.
	 */
	(void) vsw_vlan_frame_pretag(ldcp->ldc_port, VSW_VNETPORT, mp);

	/* switch the frame to destination */
	vswp->vsw_switch_frame(vswp, mp, VSW_VNETPORT, ldcp->ldc_port, NULL);
}

/*
 * Process an in-band descriptor message (most likely from
 * OBP).
 */
static void
vsw_process_data_ibnd_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vnet_ibnd_desc_t	*ibnd_desc;
	dring_info_t		*dp = NULL;
	vsw_private_desc_t	*priv_addr = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	mblk_t			*mp = NULL;
	size_t			nbytes = 0;
	size_t			off = 0;
	uint64_t		idx = 0;
	uint32_t		num = 1, len, datalen = 0;
	uint64_t		ncookies = 0;
	int			i, rv;
	int			j = 0;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	ibnd_desc = (vnet_ibnd_desc_t *)pkt;

	switch (ibnd_desc->hdr.tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D1(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		if (vsw_check_flag(ldcp, INBOUND, VSW_DRING_INFO_RECV))
			return;

		/*
		 * Data is padded to align on a 8 byte boundary,
		 * nbytes is actual data length, i.e. minus that
		 * padding.
		 */
		datalen = ibnd_desc->nbytes;

		D2(vswp, "%s(%lld): processing inband desc : "
		    ": datalen 0x%lx", __func__, ldcp->ldc_id, datalen);

		ncookies = ibnd_desc->ncookies;

		/*
		 * allocb(9F) returns an aligned data block. We
		 * need to ensure that we ask ldc for an aligned
		 * number of bytes also.
		 */
		nbytes = datalen;
		if (nbytes & 0x7) {
			off = 8 - (nbytes & 0x7);
			nbytes += off;
		}

		/* alloc extra space for VLAN_TAG */
		mp = allocb(datalen + 8, BPRI_MED);
		if (mp == NULL) {
			DERR(vswp, "%s(%lld): allocb failed",
			    __func__, ldcp->ldc_id);
			ldcp->ldc_stats.rx_allocb_fail++;
			return;
		}

		/* skip over the extra space for VLAN_TAG */
		mp->b_rptr += 8;

		rv = ldc_mem_copy(ldcp->ldc_handle, (caddr_t)mp->b_rptr,
		    0, &nbytes, ibnd_desc->memcookie, (uint64_t)ncookies,
		    LDC_COPY_IN);

		if (rv != 0) {
			DERR(vswp, "%s(%d): unable to copy in data from "
			    "%d cookie(s)", __func__, ldcp->ldc_id, ncookies);
			freemsg(mp);
			ldcp->ldc_stats.ierrors++;
			return;
		}

		D2(vswp, "%s(%d): copied in %ld bytes using %d cookies",
		    __func__, ldcp->ldc_id, nbytes, ncookies);

		/* point to the actual end of data */
		mp->b_wptr = mp->b_rptr + datalen;
		ldcp->ldc_stats.ipackets++;
		ldcp->ldc_stats.rbytes += datalen;

		/*
		 * We ACK back every in-band descriptor message we process
		 */
		ibnd_desc->hdr.tag.vio_subtype = VIO_SUBTYPE_ACK;
		ibnd_desc->hdr.tag.vio_sid = ldcp->local_session;
		(void) vsw_send_msg(ldcp, (void *)ibnd_desc,
		    sizeof (vnet_ibnd_desc_t), B_TRUE);

		/*
		 * there is extra space alloc'd for VLAN_TAG
		 */
		(void) vsw_vlan_frame_pretag(ldcp->ldc_port, VSW_VNETPORT, mp);

		/* send the packet to be switched */
		vswp->vsw_switch_frame(vswp, mp, VSW_VNETPORT,
		    ldcp->ldc_port, NULL);

		break;

	case VIO_SUBTYPE_ACK:
		D1(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		/* Verify the ACK is valid */
		idx = ibnd_desc->hdr.desc_handle;

		if (idx >= vsw_num_descriptors) {
			cmn_err(CE_WARN, "!vsw%d: corrupted ACK received "
			    "(idx %ld)", vswp->instance, idx);
			return;
		}

		if ((dp = ldcp->lane_out.dringp) == NULL) {
			DERR(vswp, "%s: no dring found", __func__);
			return;
		}

		len = dp->num_descriptors;
		/*
		 * If the descriptor we are being ACK'ed for is not the
		 * one we expected, then pkts were lost somwhere, either
		 * when we tried to send a msg, or a previous ACK msg from
		 * our peer. In either case we now reclaim the descriptors
		 * in the range from the last ACK we received up to the
		 * current ACK.
		 */
		if (idx != dp->last_ack_recv) {
			DWARN(vswp, "%s: dropped pkts detected, (%ld, %ld)",
			    __func__, dp->last_ack_recv, idx);
			num = idx >= dp->last_ack_recv ?
			    idx - dp->last_ack_recv + 1:
			    (len - dp->last_ack_recv + 1) + idx;
		}

		/*
		 * When we sent the in-band message to our peer we
		 * marked the copy in our private ring as READY. We now
		 * check that the descriptor we are being ACK'ed for is in
		 * fact READY, i.e. it is one we have shared with our peer.
		 *
		 * If its not we flag an error, but still reset the descr
		 * back to FREE.
		 */
		for (i = dp->last_ack_recv; j < num; i = (i + 1) % len, j++) {
			priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;
			mutex_enter(&priv_addr->dstate_lock);
			if (priv_addr->dstate != VIO_DESC_READY) {
				DERR(vswp, "%s: (%ld) desc at index %ld not "
				    "READY (0x%lx)", __func__,
				    ldcp->ldc_id, idx, priv_addr->dstate);
				DERR(vswp, "%s: bound %d: ncookies %ld : "
				    "datalen %ld", __func__,
				    priv_addr->bound, priv_addr->ncookies,
				    priv_addr->datalen);
			}
			D2(vswp, "%s: (%lld) freeing descp at %lld", __func__,
			    ldcp->ldc_id, idx);
			/* release resources associated with sent msg */
			priv_addr->datalen = 0;
			priv_addr->dstate = VIO_DESC_FREE;
			mutex_exit(&priv_addr->dstate_lock);
		}
		/* update to next expected value */
		dp->last_ack_recv = (idx + 1) % dp->num_descriptors;

		break;

	case VIO_SUBTYPE_NACK:
		DERR(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		/*
		 * We should only get a NACK if our peer doesn't like
		 * something about a message we have sent it. If this
		 * happens we just release the resources associated with
		 * the message. (We are relying on higher layers to decide
		 * whether or not to resend.
		 */

		/* limit check */
		idx = ibnd_desc->hdr.desc_handle;

		if (idx >= vsw_num_descriptors) {
			DERR(vswp, "%s: corrupted NACK received (idx %lld)",
			    __func__, idx);
			return;
		}

		if ((dp = ldcp->lane_out.dringp) == NULL) {
			DERR(vswp, "%s: no dring found", __func__);
			return;
		}

		priv_addr = (vsw_private_desc_t *)dp->priv_addr;

		/* move to correct location in ring */
		priv_addr += idx;

		/* release resources associated with sent msg */
		mutex_enter(&priv_addr->dstate_lock);
		priv_addr->datalen = 0;
		priv_addr->dstate = VIO_DESC_FREE;
		mutex_exit(&priv_addr->dstate_lock);

		break;

	default:
		DERR(vswp, "%s(%lld): Unknown vio_subtype %x\n", __func__,
		    ldcp->ldc_id, ibnd_desc->hdr.tag.vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
}

static void
vsw_process_err_pkt(vsw_ldc_t *ldcp, void *epkt, vio_msg_tag_t *tagp)
{
	_NOTE(ARGUNUSED(epkt))

	vsw_t		*vswp = ldcp->ldc_vswp;
	uint16_t	env = tagp->vio_subtype_env;

	D1(vswp, "%s (%lld): enter\n", __func__, ldcp->ldc_id);

	/*
	 * Error vio_subtypes have yet to be defined. So for
	 * the moment we can't do anything.
	 */
	D2(vswp, "%s: (%x) vio_subtype env", __func__, env);

	D1(vswp, "%s (%lld): exit\n", __func__, ldcp->ldc_id);
}

/* transmit the packet over the given port */
int
vsw_portsend(vsw_port_t *port, mblk_t *mp)
{
	mblk_t		*mpt;
	int		count;
	vsw_ldc_t	*ldcp = port->ldcp;
	int		status = 0;

	count = vsw_vlan_frame_untag(port, VSW_VNETPORT, &mp, &mpt);
	if (count != 0) {
		status = ldcp->tx(ldcp, mp, mpt, count);
	}
	return (status);
}

/*
 * Break up frames into 2 seperate chains: normal and
 * priority, based on the frame type. The number of
 * priority frames is also counted and returned.
 *
 * Params:
 *	vswp:	pointer to the instance of vsw
 *	np:	head of packet chain to be broken
 *	npt:	tail of packet chain to be broken
 *
 * Returns:
 *	np:	head of normal data packets
 *	npt:	tail of normal data packets
 *	hp:	head of high priority packets
 *	hpt:	tail of high priority packets
 */
static uint32_t
vsw_get_pri_packets(vsw_t *vswp, mblk_t **np, mblk_t **npt,
    mblk_t **hp, mblk_t **hpt)
{
	mblk_t			*tmp = NULL;
	mblk_t			*smp = NULL;
	mblk_t			*hmp = NULL;	/* high prio pkts head */
	mblk_t			*hmpt = NULL;	/* high prio pkts tail */
	mblk_t			*nmp = NULL;	/* normal pkts head */
	mblk_t			*nmpt = NULL;	/* normal pkts tail */
	uint32_t		count = 0;
	int			i;
	struct ether_header	*ehp;
	uint32_t		num_types;
	uint16_t		*types;

	tmp = *np;
	while (tmp != NULL) {

		smp = tmp;
		tmp = tmp->b_next;
		smp->b_next = NULL;
		smp->b_prev = NULL;

		ehp = (struct ether_header *)smp->b_rptr;
		num_types = vswp->pri_num_types;
		types = vswp->pri_types;
		for (i = 0; i < num_types; i++) {
			if (ehp->ether_type == types[i]) {
				/* high priority frame */

				if (hmp != NULL) {
					hmpt->b_next = smp;
					hmpt = smp;
				} else {
					hmp = hmpt = smp;
				}
				count++;
				break;
			}
		}
		if (i == num_types) {
			/* normal data frame */

			if (nmp != NULL) {
				nmpt->b_next = smp;
				nmpt = smp;
			} else {
				nmp = nmpt = smp;
			}
		}
	}

	*hp = hmp;
	*hpt = hmpt;
	*np = nmp;
	*npt = nmpt;

	return (count);
}

/*
 * Wrapper function to transmit normal and/or priority frames over the channel.
 */
static int
vsw_ldctx_pri(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count)
{
	vsw_ldc_t		*ldcp = (vsw_ldc_t *)arg;
	mblk_t			*tmp;
	mblk_t			*smp;
	mblk_t			*hmp;	/* high prio pkts head */
	mblk_t			*hmpt;	/* high prio pkts tail */
	mblk_t			*nmp;	/* normal pkts head */
	mblk_t			*nmpt;	/* normal pkts tail */
	uint32_t		n = 0;
	vsw_t			*vswp = ldcp->ldc_vswp;

	ASSERT(VSW_PRI_ETH_DEFINED(vswp));
	ASSERT(count != 0);

	nmp = mp;
	nmpt = mpt;

	/* gather any priority frames from the chain of packets */
	n = vsw_get_pri_packets(vswp, &nmp, &nmpt, &hmp, &hmpt);

	/* transmit priority frames */
	tmp = hmp;
	while (tmp != NULL) {
		smp = tmp;
		tmp = tmp->b_next;
		smp->b_next = NULL;
		vsw_ldcsend_pkt(ldcp, smp);
	}

	count -= n;

	if (count == 0) {
		/* no normal data frames to process */
		return (0);
	}

	return (vsw_ldctx(ldcp, nmp, nmpt, count));
}

/*
 * Wrapper function to transmit normal frames over the channel.
 */
static int
vsw_ldctx(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t *)arg;
	mblk_t		*tmp = NULL;

	ASSERT(count != 0);
	/*
	 * If the TX thread is enabled, then queue the
	 * ordinary frames and signal the tx thread.
	 */
	if (ldcp->tx_thread != NULL) {

		mutex_enter(&ldcp->tx_thr_lock);

		if ((ldcp->tx_cnt + count) >= vsw_max_tx_qcount) {
			/*
			 * If we reached queue limit,
			 * do not queue new packets,
			 * drop them.
			 */
			ldcp->ldc_stats.tx_qfull += count;
			mutex_exit(&ldcp->tx_thr_lock);
			freemsgchain(mp);
			goto exit;
		}
		if (ldcp->tx_mhead == NULL) {
			ldcp->tx_mhead = mp;
			ldcp->tx_mtail = mpt;
			cv_signal(&ldcp->tx_thr_cv);
		} else {
			ldcp->tx_mtail->b_next = mp;
			ldcp->tx_mtail = mpt;
		}
		ldcp->tx_cnt += count;
		mutex_exit(&ldcp->tx_thr_lock);
	} else {
		while (mp != NULL) {
			tmp = mp->b_next;
			mp->b_next = mp->b_prev = NULL;
			(void) vsw_ldcsend(ldcp, mp, 1);
			mp = tmp;
		}
	}

exit:
	return (0);
}

/*
 * This function transmits the frame in the payload of a raw data
 * (VIO_PKT_DATA) message. Thus, it provides an Out-Of-Band path to
 * send special frames with high priorities, without going through
 * the normal data path which uses descriptor ring mechanism.
 */
static void
vsw_ldcsend_pkt(vsw_ldc_t *ldcp, mblk_t *mp)
{
	vio_raw_data_msg_t	*pkt;
	mblk_t			*bp;
	mblk_t			*nmp = NULL;
	vio_mblk_t		*vmp;
	caddr_t			dst;
	uint32_t		mblksz;
	uint32_t		size;
	uint32_t		nbytes;
	int			rv;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vgen_stats_t		*statsp = &ldcp->ldc_stats;

	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == 0)) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vswp, "%s(%lld) status(%d) lstate(0x%llx), dropping "
		    "packet\n", __func__, ldcp->ldc_id, ldcp->ldc_status,
		    ldcp->lane_out.lstate);
		goto send_pkt_exit;
	}

	size = msgsize(mp);

	/* frame size bigger than available payload len of raw data msg ? */
	if (size > (size_t)(ldcp->msglen - VIO_PKT_DATA_HDRSIZE)) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vswp, "%s(%lld) invalid size(%d)\n", __func__,
		    ldcp->ldc_id, size);
		goto send_pkt_exit;
	}

	if (size < ETHERMIN)
		size = ETHERMIN;

	/* alloc space for a raw data message */
	vmp = vio_allocb(vswp->pri_tx_vmp);
	if (vmp == NULL) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vswp, "vio_allocb failed\n");
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
	pkt->tag.vio_sid = ldcp->local_session;
	nbytes = VIO_PKT_DATA_HDRSIZE + size;

	/* send the msg over ldc */
	rv = vsw_send_msg(ldcp, (void *)pkt, nbytes, B_TRUE);
	if (rv != 0) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vswp, "%s(%lld) Error sending priority frame\n", __func__,
		    ldcp->ldc_id);
		goto send_pkt_exit;
	}

	/* update stats */
	(void) atomic_inc_64(&statsp->tx_pri_packets);
	(void) atomic_add_64(&statsp->tx_pri_packets, size);

send_pkt_exit:
	if (nmp != NULL)
		freemsg(nmp);
	freemsg(mp);
}

/*
 * Transmit the packet over the given LDC channel.
 *
 * The 'retries' argument indicates how many times a packet
 * is retried before it is dropped. Note, the retry is done
 * only for a resource related failure, for all other failures
 * the packet is dropped immediately.
 */
static int
vsw_ldcsend(vsw_ldc_t *ldcp, mblk_t *mp, uint32_t retries)
{
	int		i;
	int		rc;
	int		status = 0;
	vsw_port_t	*port = ldcp->ldc_port;
	dring_info_t	*dp = NULL;
	lane_t		*lp = &ldcp->lane_out;

	for (i = 0; i < retries; ) {
		/*
		 * Send the message out using the appropriate
		 * transmit function which will free mblock when it
		 * is finished with it.
		 */
		mutex_enter(&port->tx_lock);
		if (port->transmit != NULL) {
			status = (*port->transmit)(ldcp, mp);
		}
		if (status == LDC_TX_SUCCESS) {
			mutex_exit(&port->tx_lock);
			break;
		}
		i++;	/* increment the counter here */

		/* If its the last retry, then update the oerror */
		if ((i == retries) && (status == LDC_TX_NORESOURCES)) {
			ldcp->ldc_stats.oerrors++;
		}
		mutex_exit(&port->tx_lock);

		if (status != LDC_TX_NORESOURCES) {
			/*
			 * No retrying required for errors un-related
			 * to resources.
			 */
			break;
		}
		if (((dp = ldcp->lane_out.dringp) != NULL) &&
		    ((VSW_VER_GTEQ(ldcp, 1, 2) &&
		    (ldcp->lane_out.xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    ((VSW_VER_LT(ldcp, 1, 2) &&
		    (ldcp->lane_out.xfer_mode == VIO_DRING_MODE_V1_0))))) {

			/* Need to reclaim in TxDring mode. */
			if (lp->dring_mode == VIO_TX_DRING) {
				rc = vsw_reclaim_dring(dp, dp->end_idx);
			}

		} else {
			/*
			 * If there is no dring or the xfer_mode is
			 * set to DESC_MODE(ie., OBP), then simply break here.
			 */
			break;
		}

		/*
		 * Delay only if none were reclaimed
		 * and its not the last retry.
		 */
		if ((rc == 0) && (i < retries)) {
			delay(drv_usectohz(vsw_ldc_tx_delay));
		}
	}
	freemsg(mp);
	return (status);
}

/*
 * Send an in-band descriptor message over ldc.
 */
static int
vsw_descrsend(vsw_ldc_t *ldcp, mblk_t *mp)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	vnet_ibnd_desc_t	ibnd_msg;
	vsw_private_desc_t	*priv_desc = NULL;
	dring_info_t		*dp = NULL;
	size_t			n, size = 0;
	caddr_t			bufp;
	mblk_t			*bp;
	int			idx, i;
	int			status = LDC_TX_SUCCESS;
	static int		warn_msg = 1;
	lane_t			*lp = &ldcp->lane_out;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	ASSERT(mp != NULL);

	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == 0)) {
		DERR(vswp, "%s(%lld) status(%d) state (0x%llx), dropping pkt",
		    __func__, ldcp->ldc_id, ldcp->ldc_status,
		    ldcp->lane_out.lstate);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * The dring here is as an internal buffer,
	 * rather than a transfer channel.
	 */
	if ((dp = ldcp->lane_out.dringp) == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane",
		    __func__, ldcp->ldc_id);
		DERR(vswp, "%s(%lld) status(%d) state (0x%llx)", __func__,
		    ldcp->ldc_id, ldcp->ldc_status, ldcp->lane_out.lstate);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)lp->mtu) {
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * Find a free descriptor in our buffer ring
	 */
	if (vsw_dring_find_free_desc(dp, &priv_desc, &idx) != 0) {
		if (warn_msg) {
			DERR(vswp, "%s(%lld): no descriptor available for ring "
			    "at 0x%llx", __func__, ldcp->ldc_id, dp);
			warn_msg = 0;
		}

		/* nothing more we can do */
		status = LDC_TX_NORESOURCES;
		goto vsw_descrsend_free_exit;
	} else {
		D2(vswp, "%s(%lld): free private descriptor found at pos "
		    "%ld addr 0x%x\n", __func__, ldcp->ldc_id, idx, priv_desc);
		warn_msg = 1;
	}

	/* copy data into the descriptor */
	bufp = priv_desc->datap;
	for (bp = mp, n = 0; bp != NULL; bp = bp->b_cont) {
		n = MBLKL(bp);
		bcopy(bp->b_rptr, bufp, n);
		bufp += n;
	}

	priv_desc->datalen = (size < (size_t)ETHERMIN) ? ETHERMIN : size;

	/* create and send the in-band descp msg */
	ibnd_msg.hdr.tag.vio_msgtype = VIO_TYPE_DATA;
	ibnd_msg.hdr.tag.vio_subtype = VIO_SUBTYPE_INFO;
	ibnd_msg.hdr.tag.vio_subtype_env = VIO_DESC_DATA;
	ibnd_msg.hdr.tag.vio_sid = ldcp->local_session;

	/*
	 * Copy the mem cookies describing the data from the
	 * private region of the descriptor ring into the inband
	 * descriptor.
	 */
	for (i = 0; i < priv_desc->ncookies; i++) {
		bcopy(&priv_desc->memcookie[i], &ibnd_msg.memcookie[i],
		    sizeof (ldc_mem_cookie_t));
	}

	ibnd_msg.hdr.desc_handle = idx;
	ibnd_msg.ncookies = priv_desc->ncookies;
	ibnd_msg.nbytes = size;

	ldcp->ldc_stats.opackets++;
	ldcp->ldc_stats.obytes += size;

	(void) vsw_send_msg(ldcp, (void *)&ibnd_msg,
	    sizeof (vnet_ibnd_desc_t), B_TRUE);

vsw_descrsend_free_exit:

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
	return (status);
}

static void
vsw_send_ver(void *arg)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t *)arg;
	vsw_t		*vswp = ldcp->ldc_vswp;
	lane_t		*lp = &ldcp->lane_out;
	vio_ver_msg_t	ver_msg;

	D1(vswp, "%s enter", __func__);

	ver_msg.tag.vio_msgtype = VIO_TYPE_CTRL;
	ver_msg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	ver_msg.tag.vio_subtype_env = VIO_VER_INFO;
	ver_msg.tag.vio_sid = ldcp->local_session;

	if (vsw_obp_ver_proto_workaround == B_FALSE) {
		ver_msg.ver_major = vsw_versions[0].ver_major;
		ver_msg.ver_minor = vsw_versions[0].ver_minor;
	} else {
		/* use the major,minor that we've ack'd */
		lane_t	*lpi = &ldcp->lane_in;
		ver_msg.ver_major = lpi->ver_major;
		ver_msg.ver_minor = lpi->ver_minor;
	}
	ver_msg.dev_class = VDEV_NETWORK_SWITCH;

	lp->lstate |= VSW_VER_INFO_SENT;
	lp->ver_major = ver_msg.ver_major;
	lp->ver_minor = ver_msg.ver_minor;

	DUMP_TAG(ver_msg.tag);

	(void) vsw_send_msg(ldcp, &ver_msg, sizeof (vio_ver_msg_t), B_TRUE);

	D1(vswp, "%s (%d): exit", __func__, ldcp->ldc_id);
}

static void
vsw_send_attr(vsw_ldc_t *ldcp)
{
	vsw_t			*vswp = ldcp->ldc_vswp;
	lane_t			*lp = &ldcp->lane_out;
	vnet_attr_msg_t		attr_msg;

	D1(vswp, "%s (%ld) enter", __func__, ldcp->ldc_id);

	/*
	 * Subtype is set to INFO by default
	 */
	attr_msg.tag.vio_msgtype = VIO_TYPE_CTRL;
	attr_msg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	attr_msg.tag.vio_subtype_env = VIO_ATTR_INFO;
	attr_msg.tag.vio_sid = ldcp->local_session;

	/* payload copied from default settings for lane */
	attr_msg.mtu = lp->mtu;
	attr_msg.addr_type = lp->addr_type;
	attr_msg.xfer_mode = lp->xfer_mode;
	attr_msg.ack_freq = lp->xfer_mode;
	attr_msg.options = lp->dring_mode;

	READ_ENTER(&vswp->if_lockrw);
	attr_msg.addr = vnet_macaddr_strtoul((vswp->if_addr).ether_addr_octet);
	RW_EXIT(&vswp->if_lockrw);

	ldcp->lane_out.lstate |= VSW_ATTR_INFO_SENT;

	DUMP_TAG(attr_msg.tag);

	(void) vsw_send_msg(ldcp, &attr_msg, sizeof (vnet_attr_msg_t), B_TRUE);

	D1(vswp, "%s (%ld) exit", __func__, ldcp->ldc_id);
}

static void
vsw_send_dring_info(vsw_ldc_t *ldcp)
{
	int		msgsize;
	void		*msg;
	vsw_t		*vswp = ldcp->ldc_vswp;
	vsw_port_t	*port = ldcp->ldc_port;
	lane_t		*lp = &ldcp->lane_out;
	vgen_stats_t	*statsp = &ldcp->ldc_stats;

	D1(vswp, "%s: (%ld) enter", __func__, ldcp->ldc_id);

	/* dring mode has been negotiated in attr phase; save in stats */
	statsp->dring_mode = lp->dring_mode;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		/*
		 * Change the transmit routine for RxDringData mode.
		 */
		port->transmit = vsw_dringsend_shm;
		msg = (void *) vsw_create_rx_dring_info(ldcp);
		if (msg == NULL) {
			return;
		}
		msgsize =
		    VNET_DRING_REG_EXT_MSG_SIZE(lp->dringp->data_ncookies);
		ldcp->rcv_thread = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    vsw_ldc_rcv_worker, ldcp, 0, &p0, TS_RUN, maxclsyspri);
		ldcp->rx_dringdata = vsw_process_dringdata_shm;
	} else {
		msg = (void *) vsw_create_tx_dring_info(ldcp);
		if (msg == NULL) {
			return;
		}
		msgsize = sizeof (vio_dring_reg_msg_t);
		ldcp->msg_thread = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    vsw_ldc_msg_worker, ldcp, 0, &p0, TS_RUN, maxclsyspri);
		ldcp->rx_dringdata = vsw_process_dringdata;
	}

	lp->lstate |= VSW_DRING_INFO_SENT;
	DUMP_TAG_PTR((vio_msg_tag_t *)msg);
	(void) vsw_send_msg(ldcp, msg, msgsize, B_TRUE);
	kmem_free(msg, msgsize);

	D1(vswp, "%s: (%ld) exit", __func__, ldcp->ldc_id);
}

static void
vsw_send_rdx(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	vio_rdx_msg_t	rdx_msg;

	D1(vswp, "%s (%ld) enter", __func__, ldcp->ldc_id);

	rdx_msg.tag.vio_msgtype = VIO_TYPE_CTRL;
	rdx_msg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	rdx_msg.tag.vio_subtype_env = VIO_RDX;
	rdx_msg.tag.vio_sid = ldcp->local_session;

	ldcp->lane_in.lstate |= VSW_RDX_INFO_SENT;

	DUMP_TAG(rdx_msg.tag);

	(void) vsw_send_msg(ldcp, &rdx_msg, sizeof (vio_rdx_msg_t), B_TRUE);

	D1(vswp, "%s (%ld) exit", __func__, ldcp->ldc_id);
}

/*
 * Remove the specified address from the list of address maintained
 * in this port node.
 */
mcst_addr_t *
vsw_del_addr(uint8_t devtype, void *arg, uint64_t addr)
{
	vsw_t		*vswp = NULL;
	vsw_port_t	*port = NULL;
	mcst_addr_t	*prev_p = NULL;
	mcst_addr_t	*curr_p = NULL;

	D1(NULL, "%s: enter : devtype %d : addr 0x%llx",
	    __func__, devtype, addr);

	if (devtype == VSW_VNETPORT) {
		port = (vsw_port_t *)arg;
		mutex_enter(&port->mca_lock);
		prev_p = curr_p = port->mcap;
	} else {
		vswp = (vsw_t *)arg;
		mutex_enter(&vswp->mca_lock);
		prev_p = curr_p = vswp->mcap;
	}

	while (curr_p != NULL) {
		if (curr_p->addr == addr) {
			D2(NULL, "%s: address found", __func__);
			/* match found */
			if (prev_p == curr_p) {
				/* list head */
				if (devtype == VSW_VNETPORT)
					port->mcap = curr_p->nextp;
				else
					vswp->mcap = curr_p->nextp;
			} else {
				prev_p->nextp = curr_p->nextp;
			}
			break;
		} else {
			prev_p = curr_p;
			curr_p = curr_p->nextp;
		}
	}

	if (devtype == VSW_VNETPORT)
		mutex_exit(&port->mca_lock);
	else
		mutex_exit(&vswp->mca_lock);

	D1(NULL, "%s: exit", __func__);

	return (curr_p);
}

/*
 * Create a ring consisting of just a private portion and link
 * it into the list of rings for the outbound lane.
 *
 * These type of rings are used primarily for temporary data
 * storage (i.e. as data buffers).
 */
void
vsw_create_privring(vsw_ldc_t *ldcp)
{
	dring_info_t		*dp;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	dp = kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);
	mutex_init(&dp->dlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dp->restart_lock, NULL, MUTEX_DRIVER, NULL);
	ldcp->lane_out.dringp = dp;

	/* no public section */
	dp->pub_addr = NULL;
	dp->priv_addr = kmem_zalloc(
	    (sizeof (vsw_private_desc_t) * vsw_num_descriptors), KM_SLEEP);
	dp->num_descriptors = vsw_num_descriptors;

	if (vsw_setup_tx_dring(ldcp, dp)) {
		DERR(vswp, "%s: setup of ring failed", __func__);
		vsw_destroy_tx_dring(ldcp);
		return;
	}

	/* haven't used any descriptors yet */
	dp->end_idx = 0;
	dp->restart_reqd = B_TRUE;

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Set the default lane attributes. These are copied into
 * the attr msg we send to our peer. If they are not acceptable
 * then (currently) the handshake ends.
 */
static void
vsw_set_lane_attr(vsw_t *vswp, lane_t *lp)
{
	bzero(lp, sizeof (lane_t));

	READ_ENTER(&vswp->if_lockrw);
	ether_copy(&(vswp->if_addr), &(lp->addr));
	RW_EXIT(&vswp->if_lockrw);

	lp->mtu = vswp->max_frame_size;
	lp->addr_type = ADDR_TYPE_MAC;
	lp->xfer_mode = VIO_DRING_MODE_V1_0;
	lp->ack_freq = 0;	/* for shared mode */
	lp->seq_num = VNET_ISS;
}

/*
 * Map the descriptor ring exported by the peer.
 */
static dring_info_t *
vsw_map_dring(vsw_ldc_t *ldcp, void *pkt)
{
	dring_info_t	*dp = NULL;
	lane_t		*lp = &ldcp->lane_out;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		/*
		 * In RxDringData mode, dring that we map in
		 * becomes our transmit descriptor ring.
		 */
		dp =  vsw_map_tx_dring(ldcp, pkt);
	} else {
		/*
		 * In TxDring mode, dring that we map in
		 * becomes our receive descriptor ring.
		 */
		dp =  vsw_map_rx_dring(ldcp, pkt);
	}
	return (dp);
}

/*
 * Common dring mapping function used in both TxDring and RxDringData modes.
 */
dring_info_t *
vsw_map_dring_cmn(vsw_ldc_t *ldcp, vio_dring_reg_msg_t *dring_pkt)
{
	int		rv;
	dring_info_t	*dp;
	ldc_mem_info_t	minfo;
	vsw_t		*vswp = ldcp->ldc_vswp;

	/*
	 * If the dring params are unacceptable then we NACK back.
	 */
	if ((dring_pkt->num_descriptors == 0) ||
	    (dring_pkt->descriptor_size == 0) ||
	    (dring_pkt->ncookies != 1)) {
		DERR(vswp, "%s (%lld): invalid dring info",
		    __func__, ldcp->ldc_id);
		return (NULL);
	}

	dp = kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);

	dp->num_descriptors = dring_pkt->num_descriptors;
	dp->descriptor_size = dring_pkt->descriptor_size;
	dp->options = dring_pkt->options;
	dp->dring_ncookies = dring_pkt->ncookies;

	/*
	 * Note: should only get one cookie. Enforced in
	 * the ldc layer.
	 */
	bcopy(&dring_pkt->cookie[0], &dp->dring_cookie[0],
	    sizeof (ldc_mem_cookie_t));

	rv = ldc_mem_dring_map(ldcp->ldc_handle, &dp->dring_cookie[0],
	    dp->dring_ncookies, dp->num_descriptors, dp->descriptor_size,
	    LDC_DIRECT_MAP, &(dp->dring_handle));
	if (rv != 0) {
		goto fail;
	}

	rv = ldc_mem_dring_info(dp->dring_handle, &minfo);
	if (rv != 0) {
		goto fail;
	}
	/* store the address of the ring */
	dp->pub_addr = minfo.vaddr;

	/* cache the dring mtype */
	dp->dring_mtype = minfo.mtype;

	/* no private section as we are importing */
	dp->priv_addr = NULL;

	/*
	 * Using simple mono increasing int for ident at the moment.
	 */
	dp->ident = ldcp->next_ident;
	ldcp->next_ident++;

	/*
	 * Acknowledge it; we send back a unique dring identifier that
	 * the sending side will use in future to refer to this
	 * descriptor ring.
	 */
	dring_pkt->dring_ident = dp->ident;

	return (dp);
fail:
	if (dp->dring_handle != 0) {
		(void) ldc_mem_dring_unmap(dp->dring_handle);
	}
	kmem_free(dp, sizeof (*dp));
	return (NULL);
}

/*
 * Unmap the descriptor ring exported by the peer.
 */
static void
vsw_unmap_dring(vsw_ldc_t *ldcp)
{
	lane_t	*lane_out = &ldcp->lane_out;

	if (lane_out->dring_mode == VIO_RX_DRING_DATA) {
		vsw_unmap_tx_dring(ldcp);
	} else {
		vsw_unmap_rx_dring(ldcp);
	}
}

/*
 * Map the shared memory data buffer area exported by the peer.
 * Used in RxDringData mode only.
 */
static int
vsw_map_data(vsw_ldc_t *ldcp, dring_info_t *dp, void *pkt)
{
	int			rv;
	vio_dring_reg_ext_msg_t	*emsg;
	vio_dring_reg_msg_t	*msg = pkt;
	uint8_t			*buf = (uint8_t *)msg->cookie;
	vsw_t			*vswp = ldcp->ldc_vswp;
	ldc_mem_info_t		minfo;

	/* skip over dring cookies */
	ASSERT(msg->ncookies == 1);
	buf += (msg->ncookies * sizeof (ldc_mem_cookie_t));

	emsg = (vio_dring_reg_ext_msg_t *)buf;
	if (emsg->data_ncookies > VNET_DATA_AREA_COOKIES) {
		return (1);
	}

	/* save # of data area cookies */
	dp->data_ncookies = emsg->data_ncookies;

	/* save data area size */
	dp->data_sz = emsg->data_area_size;

	/* allocate ldc mem handle for data area */
	rv = ldc_mem_alloc_handle(ldcp->ldc_handle, &dp->data_handle);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldc_mem_alloc_handle failed\n");
		DWARN(vswp, "%s (%lld) ldc_mem_alloc_handle() failed: %d\n",
		    __func__, ldcp->ldc_id, rv);
		return (1);
	}

	/* map the data area */
	rv = ldc_mem_map(dp->data_handle, emsg->data_cookie,
	    emsg->data_ncookies, LDC_DIRECT_MAP, LDC_MEM_R,
	    (caddr_t *)&dp->data_addr, NULL);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldc_mem_map failed\n");
		DWARN(vswp, "%s (%lld) ldc_mem_map() failed: %d\n",
		    __func__, ldcp->ldc_id, rv);
		return (1);
	}

	/* get the map info */
	rv = ldc_mem_info(dp->data_handle, &minfo);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldc_mem_info failed\n");
		DWARN(vswp, "%s (%lld) ldc_mem_info() failed: %d\n",
		    __func__, ldcp->ldc_id, rv);
		return (1);
	}

	if (minfo.mtype != LDC_DIRECT_MAP) {
		DWARN(vswp, "%s (%lld) mtype(%d) is not direct map\n",
		    __func__, ldcp->ldc_id, minfo.mtype);
		return (1);
	}

	/* allocate memory for data area cookies */
	dp->data_cookie = kmem_zalloc(emsg->data_ncookies *
	    sizeof (ldc_mem_cookie_t), KM_SLEEP);

	/* save data area cookies */
	bcopy(emsg->data_cookie, dp->data_cookie,
	    emsg->data_ncookies * sizeof (ldc_mem_cookie_t));

	return (0);
}

/*
 * Reset and free all the resources associated with the channel.
 */
static void
vsw_free_lane_resources(vsw_ldc_t *ldcp, uint64_t dir)
{
	lane_t	*lp;

	D1(ldcp->ldc_vswp, "%s (%lld): enter", __func__, ldcp->ldc_id);

	if (dir == INBOUND) {
		D2(ldcp->ldc_vswp, "%s: freeing INBOUND lane"
		    " of channel %lld", __func__, ldcp->ldc_id);
		lp = &ldcp->lane_in;
	} else {
		D2(ldcp->ldc_vswp, "%s: freeing OUTBOUND lane"
		    " of channel %lld", __func__, ldcp->ldc_id);
		lp = &ldcp->lane_out;
	}

	lp->lstate = VSW_LANE_INACTIV;
	lp->seq_num = VNET_ISS;

	if (dir == INBOUND) {
		/* Unmap the remote dring which is imported from the peer */
		vsw_unmap_dring(ldcp);
	} else {
		/* Destroy the local dring which is exported to the peer */
		vsw_destroy_dring(ldcp);
	}

	D1(ldcp->ldc_vswp, "%s (%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Destroy the descriptor ring.
 */
static void
vsw_destroy_dring(vsw_ldc_t *ldcp)
{
	lane_t	*lp = &ldcp->lane_out;

	if (lp->dring_mode == VIO_RX_DRING_DATA) {
		vsw_destroy_rx_dring(ldcp);
	} else {
		vsw_destroy_tx_dring(ldcp);
	}
}

/*
 * vsw_ldc_tx_worker -- A per LDC worker thread to transmit data.
 * This thread is woken up by the vsw_portsend to transmit
 * packets.
 */
static void
vsw_ldc_tx_worker(void *arg)
{
	callb_cpr_t	cprinfo;
	vsw_ldc_t *ldcp = (vsw_ldc_t *)arg;
	vsw_t *vswp = ldcp->ldc_vswp;
	mblk_t *mp;
	mblk_t *tmp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	CALLB_CPR_INIT(&cprinfo, &ldcp->tx_thr_lock, callb_generic_cpr,
	    "vnet_tx_thread");
	mutex_enter(&ldcp->tx_thr_lock);
	while (!(ldcp->tx_thr_flags & VSW_WTHR_STOP)) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * Wait until the data is received or a stop
		 * request is received.
		 */
		while (!(ldcp->tx_thr_flags & VSW_WTHR_STOP) &&
		    (ldcp->tx_mhead == NULL)) {
			cv_wait(&ldcp->tx_thr_cv, &ldcp->tx_thr_lock);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &ldcp->tx_thr_lock)

		/*
		 * First process the stop request.
		 */
		if (ldcp->tx_thr_flags & VSW_WTHR_STOP) {
			D2(vswp, "%s(%lld):tx thread stopped\n",
			    __func__, ldcp->ldc_id);
			break;
		}
		mp = ldcp->tx_mhead;
		ldcp->tx_mhead = ldcp->tx_mtail = NULL;
		ldcp->tx_cnt = 0;
		mutex_exit(&ldcp->tx_thr_lock);
		D2(vswp, "%s(%lld):calling vsw_ldcsend\n",
		    __func__, ldcp->ldc_id);
		while (mp != NULL) {
			tmp = mp->b_next;
			mp->b_next = mp->b_prev = NULL;
			(void) vsw_ldcsend(ldcp, mp, vsw_ldc_tx_retries);
			mp = tmp;
		}
		mutex_enter(&ldcp->tx_thr_lock);
	}

	/*
	 * Update the run status and wakeup the thread that
	 * has sent the stop request.
	 */
	ldcp->tx_thr_flags &= ~VSW_WTHR_STOP;
	ldcp->tx_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
	thread_exit();
}

/* vsw_stop_tx_thread -- Co-ordinate with receive thread to stop it */
static void
vsw_stop_tx_thread(vsw_ldc_t *ldcp)
{
	kt_did_t	tid = 0;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the receive thread stops.
	 */
	mutex_enter(&ldcp->tx_thr_lock);
	if (ldcp->tx_thread != NULL) {
		tid = ldcp->tx_thread->t_did;
		ldcp->tx_thr_flags |= VSW_WTHR_STOP;
		cv_signal(&ldcp->tx_thr_cv);
	}
	mutex_exit(&ldcp->tx_thr_lock);

	if (tid != 0) {
		thread_join(tid);
	}

	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
}

static int
vsw_mapin_avail(vsw_ldc_t *ldcp)
{
	int		rv;
	ldc_info_t	info;
	uint64_t	mapin_sz_req;
	uint64_t	dblk_sz;
	vsw_t		*vswp = ldcp->ldc_vswp;

	rv = ldc_info(ldcp->ldc_handle, &info);
	if (rv != 0) {
		return (B_FALSE);
	}

	dblk_sz = RXDRING_DBLK_SZ(vswp->max_frame_size);
	mapin_sz_req = (VSW_RXDRING_NRBUFS * dblk_sz);

	if (info.direct_map_size_max >= mapin_sz_req) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Debugging routines
 */
static void
display_state(void)
{
	vsw_t		*vswp;
	vsw_port_list_t	*plist;
	vsw_port_t	*port;
	vsw_ldc_t	*ldcp;
	extern vsw_t	*vsw_head;

	cmn_err(CE_NOTE, "***** system state *****");

	for (vswp = vsw_head; vswp; vswp = vswp->next) {
		plist = &vswp->plist;
		READ_ENTER(&plist->lockrw);
		cmn_err(CE_CONT, "vsw instance %d has %d ports attached\n",
		    vswp->instance, plist->num_ports);

		for (port = plist->head; port != NULL; port = port->p_next) {
			cmn_err(CE_CONT, "port %d : %d ldcs attached\n",
			    port->p_instance, port->num_ldcs);
			ldcp = port->ldcp;
			cmn_err(CE_CONT, "chan %lu : dev %d : "
			    "status %d : phase %u\n",
			    ldcp->ldc_id, ldcp->dev_class,
			    ldcp->ldc_status, ldcp->hphase);
			cmn_err(CE_CONT, "chan %lu : lsession %lu : "
			    "psession %lu\n", ldcp->ldc_id,
			    ldcp->local_session, ldcp->peer_session);

			cmn_err(CE_CONT, "Inbound lane:\n");
			display_lane(&ldcp->lane_in);
			cmn_err(CE_CONT, "Outbound lane:\n");
			display_lane(&ldcp->lane_out);
		}
		RW_EXIT(&plist->lockrw);
	}
	cmn_err(CE_NOTE, "***** system state *****");
}

static void
display_lane(lane_t *lp)
{
	dring_info_t	*drp = lp->dringp;

	cmn_err(CE_CONT, "ver 0x%x:0x%x : state %lx : mtu 0x%lx\n",
	    lp->ver_major, lp->ver_minor, lp->lstate, lp->mtu);
	cmn_err(CE_CONT, "addr_type %d : addr 0x%lx : xmode %d\n",
	    lp->addr_type, lp->addr, lp->xfer_mode);
	cmn_err(CE_CONT, "dringp 0x%lx\n", (uint64_t)lp->dringp);

	cmn_err(CE_CONT, "Dring info:\n");
	cmn_err(CE_CONT, "\tnum_desc %u : dsize %u\n",
	    drp->num_descriptors, drp->descriptor_size);
	cmn_err(CE_CONT, "\thandle 0x%lx\n", drp->dring_handle);
	cmn_err(CE_CONT, "\tpub_addr 0x%lx : priv_addr 0x%lx\n",
	    (uint64_t)drp->pub_addr, (uint64_t)drp->priv_addr);
	cmn_err(CE_CONT, "\tident 0x%lx : end_idx %lu\n",
	    drp->ident, drp->end_idx);
	display_ring(drp);
}

static void
display_ring(dring_info_t *dringp)
{
	uint64_t		i;
	uint64_t		priv_count = 0;
	uint64_t		pub_count = 0;
	vnet_public_desc_t	*pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;

	for (i = 0; i < vsw_num_descriptors; i++) {
		if (dringp->pub_addr != NULL) {
			pub_addr = (vnet_public_desc_t *)dringp->pub_addr + i;

			if (pub_addr->hdr.dstate == VIO_DESC_FREE)
				pub_count++;
		}

		if (dringp->priv_addr != NULL) {
			priv_addr = (vsw_private_desc_t *)dringp->priv_addr + i;

			if (priv_addr->dstate == VIO_DESC_FREE)
				priv_count++;
		}
	}
	cmn_err(CE_CONT, "\t%lu elements: %lu priv free: %lu pub free\n",
	    i, priv_count, pub_count);
}

static void
dump_flags(uint64_t state)
{
	int	i;

	typedef struct flag_name {
		int	flag_val;
		char	*flag_name;
	} flag_name_t;

	flag_name_t	flags[] = {
		VSW_VER_INFO_SENT, "VSW_VER_INFO_SENT",
		VSW_VER_INFO_RECV, "VSW_VER_INFO_RECV",
		VSW_VER_ACK_RECV, "VSW_VER_ACK_RECV",
		VSW_VER_ACK_SENT, "VSW_VER_ACK_SENT",
		VSW_VER_NACK_RECV, "VSW_VER_NACK_RECV",
		VSW_VER_NACK_SENT, "VSW_VER_NACK_SENT",
		VSW_ATTR_INFO_SENT, "VSW_ATTR_INFO_SENT",
		VSW_ATTR_INFO_RECV, "VSW_ATTR_INFO_RECV",
		VSW_ATTR_ACK_SENT, "VSW_ATTR_ACK_SENT",
		VSW_ATTR_ACK_RECV, "VSW_ATTR_ACK_RECV",
		VSW_ATTR_NACK_SENT, "VSW_ATTR_NACK_SENT",
		VSW_ATTR_NACK_RECV, "VSW_ATTR_NACK_RECV",
		VSW_DRING_INFO_SENT, "VSW_DRING_INFO_SENT",
		VSW_DRING_INFO_RECV, "VSW_DRING_INFO_RECV",
		VSW_DRING_ACK_SENT, "VSW_DRING_ACK_SENT",
		VSW_DRING_ACK_RECV, "VSW_DRING_ACK_RECV",
		VSW_DRING_NACK_SENT, "VSW_DRING_NACK_SENT",
		VSW_DRING_NACK_RECV, "VSW_DRING_NACK_RECV",
		VSW_RDX_INFO_SENT, "VSW_RDX_INFO_SENT",
		VSW_RDX_INFO_RECV, "VSW_RDX_INFO_RECV",
		VSW_RDX_ACK_SENT, "VSW_RDX_ACK_SENT",
		VSW_RDX_ACK_RECV, "VSW_RDX_ACK_RECV",
		VSW_RDX_NACK_SENT, "VSW_RDX_NACK_SENT",
		VSW_RDX_NACK_RECV, "VSW_RDX_NACK_RECV",
		VSW_MCST_INFO_SENT, "VSW_MCST_INFO_SENT",
		VSW_MCST_INFO_RECV, "VSW_MCST_INFO_RECV",
		VSW_MCST_ACK_SENT, "VSW_MCST_ACK_SENT",
		VSW_MCST_ACK_RECV, "VSW_MCST_ACK_RECV",
		VSW_MCST_NACK_SENT, "VSW_MCST_NACK_SENT",
		VSW_MCST_NACK_RECV, "VSW_MCST_NACK_RECV",
		VSW_LANE_ACTIVE, "VSW_LANE_ACTIVE"};

	DERR(NULL, "DUMP_FLAGS: %llx\n", state);
	for (i = 0; i < sizeof (flags)/sizeof (flag_name_t); i++) {
		if (state & flags[i].flag_val)
			DERR(NULL, "DUMP_FLAGS %s", flags[i].flag_name);
	}
}
