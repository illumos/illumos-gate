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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/mac.h>
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

/* Port add/deletion/etc routines */
static	int vsw_port_delete(vsw_port_t *port);
static	int vsw_ldc_attach(vsw_port_t *port, uint64_t ldc_id);
static	int vsw_ldc_detach(vsw_port_t *port, uint64_t ldc_id);
static	int vsw_init_ldcs(vsw_port_t *port);
static	int vsw_uninit_ldcs(vsw_port_t *port);
static	int vsw_ldc_init(vsw_ldc_t *ldcp);
static	int vsw_ldc_uninit(vsw_ldc_t *ldcp);
static	int vsw_drain_ldcs(vsw_port_t *port);
static	int vsw_drain_port_taskq(vsw_port_t *port);
static	void vsw_marker_task(void *);
static	int vsw_plist_del_node(vsw_t *, vsw_port_t *port);
int vsw_detach_ports(vsw_t *vswp);
int vsw_port_add(vsw_t *vswp, md_t *mdp, mde_cookie_t *node);
mcst_addr_t *vsw_del_addr(uint8_t devtype, void *arg, uint64_t addr);
int vsw_port_detach(vsw_t *vswp, int p_instance);
int vsw_portsend(vsw_port_t *port, mblk_t *mp, mblk_t *mpt, uint32_t count);
int vsw_port_attach(vsw_t *vswp, int p_instance,
	uint64_t *ldcids, int nids, struct ether_addr *macaddr);
vsw_port_t *vsw_lookup_port(vsw_t *vswp, int p_instance);


/* Interrupt routines */
static	uint_t vsw_ldc_cb(uint64_t cb, caddr_t arg);

/* Handshake routines */
static	void vsw_ldc_reinit(vsw_ldc_t *);
static	void vsw_process_conn_evt(vsw_ldc_t *, uint16_t);
static	void vsw_conn_task(void *);
static	int vsw_check_flag(vsw_ldc_t *, int, uint64_t);
static	void vsw_next_milestone(vsw_ldc_t *);
static	int vsw_supported_version(vio_ver_msg_t *);
static	void vsw_set_vnet_proto_ops(vsw_ldc_t *ldcp);
static	void vsw_reset_vnet_proto_ops(vsw_ldc_t *ldcp);

/* Data processing routines */
static void vsw_process_pkt(void *);
static void vsw_dispatch_ctrl_task(vsw_ldc_t *, void *, vio_msg_tag_t *);
static void vsw_process_ctrl_pkt(void *);
static void vsw_process_ctrl_ver_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_attr_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_mcst_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_reg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_unreg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_rdx_pkt(vsw_ldc_t *, void *);
static void vsw_process_data_pkt(vsw_ldc_t *, void *, vio_msg_tag_t *,
	uint32_t);
static void vsw_process_data_dring_pkt(vsw_ldc_t *, void *);
static void vsw_process_pkt_data_nop(void *, void *, uint32_t);
static void vsw_process_pkt_data(void *, void *, uint32_t);
static void vsw_process_data_ibnd_pkt(vsw_ldc_t *, void *);
static void vsw_process_err_pkt(vsw_ldc_t *, void *, vio_msg_tag_t *);

/* Switching/data transmit routines */
static	int vsw_dringsend(vsw_ldc_t *, mblk_t *);
static	int vsw_descrsend(vsw_ldc_t *, mblk_t *);
static void vsw_ldcsend_pkt(vsw_ldc_t *ldcp, mblk_t *mp);
static int vsw_ldcsend(vsw_ldc_t *ldcp, mblk_t *mp, uint32_t retries);
static int vsw_ldctx_pri(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count);
static int vsw_ldctx(void *arg, mblk_t *mp, mblk_t *mpt, uint32_t count);

/* Packet creation routines */
static void vsw_send_ver(void *);
static void vsw_send_attr(vsw_ldc_t *);
static vio_dring_reg_msg_t *vsw_create_dring_info_pkt(vsw_ldc_t *);
static void vsw_send_dring_info(vsw_ldc_t *);
static void vsw_send_rdx(vsw_ldc_t *);
static int vsw_send_msg(vsw_ldc_t *, void *, int, boolean_t);

/* Dring routines */
static dring_info_t *vsw_create_dring(vsw_ldc_t *);
static void vsw_create_privring(vsw_ldc_t *);
static int vsw_setup_ring(vsw_ldc_t *ldcp, dring_info_t *dp);
static int vsw_dring_find_free_desc(dring_info_t *, vsw_private_desc_t **,
    int *);
static dring_info_t *vsw_ident2dring(lane_t *, uint64_t);
static int vsw_reclaim_dring(dring_info_t *dp, int start);

static void vsw_set_lane_attr(vsw_t *, lane_t *);
static int vsw_check_attr(vnet_attr_msg_t *, vsw_ldc_t *);
static int vsw_dring_match(dring_info_t *dp, vio_dring_reg_msg_t *msg);
static int vsw_mem_cookie_match(ldc_mem_cookie_t *, ldc_mem_cookie_t *);
static int vsw_check_dring_info(vio_dring_reg_msg_t *);

/* Rcv/Tx thread routines */
static void vsw_stop_tx_thread(vsw_ldc_t *ldcp);
static void vsw_ldc_tx_worker(void *arg);
static void vsw_stop_rx_thread(vsw_ldc_t *ldcp);
static void vsw_ldc_rx_worker(void *arg);

/* Misc support routines */
static	caddr_t vsw_print_ethaddr(uint8_t *addr, char *ebuf);
static void vsw_free_lane_resources(vsw_ldc_t *, uint64_t);
static int vsw_free_ring(dring_info_t *);
static void vsw_save_lmacaddr(vsw_t *vswp, uint64_t macaddr);
static int vsw_get_same_dest_list(struct ether_header *ehp,
    mblk_t **rhead, mblk_t **rtail, mblk_t **mpp);
static mblk_t *vsw_dupmsgchain(mblk_t *mp);
static void vsw_mac_rx(vsw_t *vswp, int caller, mac_resource_handle_t mrh,
    mblk_t *mp, mblk_t *mpt, vsw_macrx_flags_t flags);

/* Debugging routines */
static void dump_flags(uint64_t);
static void display_state(void);
static void display_lane(lane_t *);
static void display_ring(dring_info_t *);

/*
 * Functions imported from other files.
 */
extern int vsw_set_hw(vsw_t *, vsw_port_t *, int);
extern int vsw_unset_hw(vsw_t *, vsw_port_t *, int);
extern void vsw_reconfig_hw(vsw_t *);
extern int vsw_add_fdb(vsw_t *vswp, vsw_port_t *port);
extern int vsw_del_fdb(vsw_t *vswp, vsw_port_t *port);
extern int vsw_add_rem_mcst(vnet_mcast_msg_t *mcst_pkt, vsw_port_t *port);
extern void vsw_del_mcst_port(vsw_port_t *port);
extern int vsw_add_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg);
extern int vsw_del_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg);

#define	VSW_NUM_VMPOOLS		3	/* number of vio mblk pools */
#define	VSW_PORT_REF_DELAY	30	/* delay for port ref_cnt to become 0 */

/*
 * Tunables used in this file.
 */
extern int vsw_num_handshakes;
extern int vsw_wretries;
extern int vsw_desc_delay;
extern int vsw_read_attempts;
extern int vsw_ldc_tx_delay;
extern int vsw_ldc_tx_retries;
extern boolean_t vsw_ldc_rxthr_enabled;
extern boolean_t vsw_ldc_txthr_enabled;
extern uint32_t vsw_ntxds;
extern uint32_t vsw_max_tx_qcount;
extern uint32_t vsw_chain_len;
extern uint32_t vsw_mblk_size1;
extern uint32_t vsw_mblk_size2;
extern uint32_t vsw_mblk_size3;
extern uint32_t vsw_num_mblks1;
extern uint32_t vsw_num_mblks2;
extern uint32_t vsw_num_mblks3;
extern boolean_t vsw_obp_ver_proto_workaround;

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

/* supported versions */
static	ver_sup_t	vsw_versions[] = { {1, 2} };

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
vsw_port_attach(vsw_t *vswp, int p_instance, uint64_t *ldcids, int nids,
struct ether_addr *macaddr)
{
	vsw_port_list_t		*plist = &vswp->plist;
	vsw_port_t		*port, **prev_port;
	int			i;

	D1(vswp, "%s: enter : port %d", __func__, p_instance);

	/* port already exists? */
	READ_ENTER(&plist->lockrw);
	for (port = plist->head; port != NULL; port = port->p_next) {
		if (port->p_instance == p_instance) {
			DWARN(vswp, "%s: port instance %d already attached",
			    __func__, p_instance);
			RW_EXIT(&plist->lockrw);
			return (1);
		}
	}
	RW_EXIT(&plist->lockrw);

	port = kmem_zalloc(sizeof (vsw_port_t), KM_SLEEP);
	port->p_vswp = vswp;
	port->p_instance = p_instance;
	port->p_ldclist.num_ldcs = 0;
	port->p_ldclist.head = NULL;
	port->addr_set = VSW_ADDR_UNSET;

	rw_init(&port->p_ldclist.lockrw, NULL, RW_DRIVER, NULL);

	mutex_init(&port->tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&port->mca_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&port->state_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&port->state_cv, NULL, CV_DRIVER, NULL);
	port->state = VSW_PORT_INIT;

	if (nids > VSW_PORT_MAX_LDCS) {
		D2(vswp, "%s: using first of %d ldc ids",
		    __func__, nids);
		nids = VSW_PORT_MAX_LDCS;
	}

	D2(vswp, "%s: %d nids", __func__, nids);
	for (i = 0; i < nids; i++) {
		D2(vswp, "%s: ldcid (%llx)", __func__, (uint64_t)ldcids[i]);
		if (vsw_ldc_attach(port, (uint64_t)ldcids[i]) != 0) {
			DERR(vswp, "%s: ldc_attach failed", __func__);

			rw_destroy(&port->p_ldclist.lockrw);

			cv_destroy(&port->state_cv);
			mutex_destroy(&port->state_lock);

			mutex_destroy(&port->tx_lock);
			mutex_destroy(&port->mca_lock);
			kmem_free(port, sizeof (vsw_port_t));
			return (1);
		}
	}

	ether_copy(macaddr, &port->p_macaddr);

	if (vswp->switching_setup_done == B_TRUE) {
		/*
		 * If the underlying physical device has been setup,
		 * program the mac address of this port in it.
		 * Otherwise, port macaddr will be set after the physical
		 * device is successfully setup by the timeout handler.
		 */
		mutex_enter(&vswp->hw_lock);
		(void) vsw_set_hw(vswp, port, VSW_VNETPORT);
		mutex_exit(&vswp->hw_lock);
	}

	WRITE_ENTER(&plist->lockrw);

	/* create the fdb entry for this port/mac address */
	(void) vsw_add_fdb(vswp, port);

	/* link it into the list of ports for this vsw instance */
	prev_port = (vsw_port_t **)(&plist->head);
	port->p_next = *prev_port;
	*prev_port = port;
	plist->num_ports++;

	RW_EXIT(&plist->lockrw);

	/*
	 * Initialise the port and any ldc's under it.
	 */
	(void) vsw_init_ldcs(port);

	D1(vswp, "%s: exit", __func__);
	return (0);
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

	/* Remove the fdb entry for this port/mac address */
	(void) vsw_del_fdb(vswp, port);

	/* Remove any multicast addresses.. */
	vsw_del_mcst_port(port);

	/*
	 * No longer need to hold writer lock on port list now
	 * that we have unlinked the target port from the list.
	 */
	RW_EXIT(&plist->lockrw);

	/* Remove address if was programmed into HW. */
	mutex_enter(&vswp->hw_lock);

	/*
	 * Port's address may not have been set in hardware. This could
	 * happen if the underlying physical device is not yet available and
	 * vsw_setup_switching_timeout() may be in progress.
	 * We remove its addr from hardware only if it has been set before.
	 */
	if (port->addr_set != VSW_ADDR_UNSET)
		(void) vsw_unset_hw(vswp, port, VSW_VNETPORT);

	if (vswp->recfg_reqd)
		vsw_reconfig_hw(vswp);

	mutex_exit(&vswp->hw_lock);

	if (vsw_port_delete(port)) {
		return (1);
	}

	D1(vswp, "%s: exit: p_instance(%d)", __func__, p_instance);
	return (0);
}

/*
 * Detach all active ports.
 *
 * Returns 0 on success, 1 on failure.
 */
int
vsw_detach_ports(vsw_t *vswp)
{
	vsw_port_list_t 	*plist = &vswp->plist;
	vsw_port_t		*port = NULL;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&plist->lockrw);

	while ((port = plist->head) != NULL) {
		if (vsw_plist_del_node(vswp, port)) {
			DERR(vswp, "%s: Error deleting port %d"
			    " from port list", __func__, port->p_instance);
			RW_EXIT(&plist->lockrw);
			return (1);
		}

		/* Remove address if was programmed into HW. */
		mutex_enter(&vswp->hw_lock);
		(void) vsw_unset_hw(vswp, port, VSW_VNETPORT);
		mutex_exit(&vswp->hw_lock);

		/* Remove the fdb entry for this port/mac address */
		(void) vsw_del_fdb(vswp, port);

		/* Remove any multicast addresses.. */
		vsw_del_mcst_port(port);

		/*
		 * No longer need to hold the lock on the port list
		 * now that we have unlinked the target port from the
		 * list.
		 */
		RW_EXIT(&plist->lockrw);
		if (vsw_port_delete(port)) {
			DERR(vswp, "%s: Error deleting port %d",
			    __func__, port->p_instance);
			return (1);
		}
		WRITE_ENTER(&plist->lockrw);
	}
	RW_EXIT(&plist->lockrw);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Delete the specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_port_delete(vsw_port_t *port)
{
	vsw_ldc_list_t 		*ldcl;
	vsw_t			*vswp = port->p_vswp;

	D1(vswp, "%s: enter : port id %d", __func__, port->p_instance);

	(void) vsw_uninit_ldcs(port);

	/*
	 * Wait for any pending ctrl msg tasks which reference this
	 * port to finish.
	 */
	if (vsw_drain_port_taskq(port))
		return (1);

	/*
	 * Wait for port reference count to hit zero.
	 */
	while (port->ref_cnt != 0) {
		delay(drv_usectohz(VSW_PORT_REF_DELAY));
	}

	/*
	 * Wait for any active callbacks to finish
	 */
	if (vsw_drain_ldcs(port))
		return (1);

	ldcl = &port->p_ldclist;
	WRITE_ENTER(&ldcl->lockrw);
	while (ldcl->num_ldcs > 0) {
		if (vsw_ldc_detach(port, ldcl->head->ldc_id) != 0) {
			cmn_err(CE_WARN, "!vsw%d: unable to detach ldc %ld",
			    vswp->instance, ldcl->head->ldc_id);
			RW_EXIT(&ldcl->lockrw);
			return (1);
		}
	}
	RW_EXIT(&ldcl->lockrw);

	rw_destroy(&port->p_ldclist.lockrw);

	mutex_destroy(&port->mca_lock);
	mutex_destroy(&port->tx_lock);
	cv_destroy(&port->state_cv);
	mutex_destroy(&port->state_lock);

	kmem_free(port, sizeof (vsw_port_t));

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Attach a logical domain channel (ldc) under a specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_ldc_attach(vsw_port_t *port, uint64_t ldc_id)
{
	vsw_t 		*vswp = port->p_vswp;
	vsw_ldc_list_t *ldcl = &port->p_ldclist;
	vsw_ldc_t 	*ldcp = NULL;
	ldc_attr_t 	attr;
	ldc_status_t	istatus;
	int 		status = DDI_FAILURE;
	int		rv;
	char		kname[MAXNAMELEN];
	enum		{ PROG_init = 0x0, PROG_mblks = 0x1,
			    PROG_callback = 0x2, PROG_rx_thread = 0x4,
			    PROG_tx_thread = 0x8}
			progress;

	progress = PROG_init;

	D1(vswp, "%s: enter", __func__);

	ldcp = kmem_zalloc(sizeof (vsw_ldc_t), KM_NOSLEEP);
	if (ldcp == NULL) {
		DERR(vswp, "%s: kmem_zalloc failed", __func__);
		return (1);
	}
	ldcp->ldc_id = ldc_id;

	/* Allocate pools of receive mblks */
	rv = vio_init_multipools(&ldcp->vmp, VSW_NUM_VMPOOLS,
	    vsw_mblk_size1, vsw_mblk_size2, vsw_mblk_size3,
	    vsw_num_mblks1, vsw_num_mblks2, vsw_num_mblks3);
	if (rv) {
		DWARN(vswp, "%s: unable to create free mblk pools for"
		    " channel %ld (rv %d)", __func__, ldc_id, rv);
		kmem_free(ldcp, sizeof (vsw_ldc_t));
		return (1);
	}

	progress |= PROG_mblks;

	mutex_init(&ldcp->ldc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->ldc_rxlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->ldc_cblock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->drain_cv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->drain_cv, NULL, CV_DRIVER, NULL);
	rw_init(&ldcp->lane_in.dlistrw, NULL, RW_DRIVER, NULL);
	rw_init(&ldcp->lane_out.dlistrw, NULL, RW_DRIVER, NULL);

	/* required for handshake with peer */
	ldcp->local_session = (uint64_t)ddi_get_lbolt();
	ldcp->peer_session = 0;
	ldcp->session_status = 0;
	ldcp->hss_id = 1;	/* Initial handshake session id */

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

	if (vsw_ldc_rxthr_enabled) {
		ldcp->rx_thr_flags = 0;

		mutex_init(&ldcp->rx_thr_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ldcp->rx_thr_cv, NULL, CV_DRIVER, NULL);
		ldcp->rx_thread = thread_create(NULL, 2 * DEFAULTSTKSZ,
		    vsw_ldc_rx_worker, ldcp, 0, &p0, TS_RUN, maxclsyspri);

		progress |= PROG_rx_thread;
		if (ldcp->rx_thread == NULL) {
			DWARN(vswp, "%s(%lld): Failed to create worker thread",
			    __func__, ldc_id);
			goto ldc_attach_fail;
		}
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
	ldcp->msglen = VIO_PKT_DATA_HDRSIZE + ETHERMAX;
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

	/* link it into the list of channels for this port */
	WRITE_ENTER(&ldcl->lockrw);
	ldcp->ldc_next = ldcl->head;
	ldcl->head = ldcp;
	ldcl->num_ldcs++;
	RW_EXIT(&ldcl->lockrw);

	D1(vswp, "%s: exit", __func__);
	return (0);

ldc_attach_fail:

	if (progress & PROG_callback) {
		(void) ldc_unreg_callback(ldcp->ldc_handle);
		kmem_free(ldcp->ldcmsg, ldcp->msglen);
	}

	if (progress & PROG_rx_thread) {
		if (ldcp->rx_thread != NULL) {
			vsw_stop_rx_thread(ldcp);
		}
		mutex_destroy(&ldcp->rx_thr_lock);
		cv_destroy(&ldcp->rx_thr_cv);
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
	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_rxlock);
	mutex_destroy(&ldcp->ldc_cblock);
	mutex_destroy(&ldcp->drain_cv_lock);

	cv_destroy(&ldcp->drain_cv);

	rw_destroy(&ldcp->lane_in.dlistrw);
	rw_destroy(&ldcp->lane_out.dlistrw);

	if (progress & PROG_mblks) {
		vio_destroy_multipools(&ldcp->vmp, &vswp->rxh);
	}
	kmem_free(ldcp, sizeof (vsw_ldc_t));

	return (1);
}

/*
 * Detach a logical domain channel (ldc) belonging to a
 * particular port.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_ldc_detach(vsw_port_t *port, uint64_t ldc_id)
{
	vsw_t 		*vswp = port->p_vswp;
	vsw_ldc_t 	*ldcp, *prev_ldcp;
	vsw_ldc_list_t	*ldcl = &port->p_ldclist;
	int 		rv;

	prev_ldcp = ldcl->head;
	for (; (ldcp = prev_ldcp) != NULL; prev_ldcp = ldcp->ldc_next) {
		if (ldcp->ldc_id == ldc_id) {
			break;
		}
	}

	/* specified ldc id not found */
	if (ldcp == NULL) {
		DERR(vswp, "%s: ldcp = NULL", __func__);
		return (1);
	}

	D2(vswp, "%s: detaching channel %lld", __func__, ldcp->ldc_id);

	/* Stop the receive thread */
	if (ldcp->rx_thread != NULL) {
		vsw_stop_rx_thread(ldcp);
		mutex_destroy(&ldcp->rx_thr_lock);
		cv_destroy(&ldcp->rx_thr_cv);
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
	 * If the close fails we are in serious trouble, as won't
	 * be able to delete the parent port.
	 */
	if ((rv = ldc_close(ldcp->ldc_handle)) != 0) {
		DERR(vswp, "%s: error %d closing channel %lld",
		    __func__, rv, ldcp->ldc_id);
		return (1);
	}

	(void) ldc_fini(ldcp->ldc_handle);

	ldcp->ldc_status = LDC_INIT;
	ldcp->ldc_handle = NULL;
	ldcp->ldc_vswp = NULL;


	/*
	 * Most likely some mblks are still in use and
	 * have not been returned to the pool. These mblks are
	 * added to the pool that is maintained in the device instance.
	 * Another attempt will be made to destroy the pool
	 * when the device detaches.
	 */
	vio_destroy_multipools(&ldcp->vmp, &vswp->rxh);

	/* unlink it from the list */
	prev_ldcp = ldcp->ldc_next;
	ldcl->num_ldcs--;

	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_rxlock);
	mutex_destroy(&ldcp->ldc_cblock);
	cv_destroy(&ldcp->drain_cv);
	mutex_destroy(&ldcp->drain_cv_lock);
	mutex_destroy(&ldcp->status_lock);
	rw_destroy(&ldcp->lane_in.dlistrw);
	rw_destroy(&ldcp->lane_out.dlistrw);

	kmem_free(ldcp, sizeof (vsw_ldc_t));

	return (0);
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
	vsw_t 		*vswp = ldcp->ldc_vswp;
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
static int
vsw_ldc_uninit(vsw_ldc_t *ldcp)
{
	vsw_t	*vswp = ldcp->ldc_vswp;
	int	rv;

	D1(vswp, "vsw_ldc_uninit: enter: id(%lx)\n", ldcp->ldc_id);

	LDC_ENTER_LOCK(ldcp);

	rv = ldc_set_cb_mode(ldcp->ldc_handle, LDC_CB_DISABLE);
	if (rv != 0) {
		DERR(vswp, "vsw_ldc_uninit(%lld): error disabling "
		    "interrupts (rv = %d)\n", ldcp->ldc_id, rv);
		LDC_EXIT_LOCK(ldcp);
		return (1);
	}

	mutex_enter(&ldcp->status_lock);
	ldcp->ldc_status = LDC_INIT;
	mutex_exit(&ldcp->status_lock);

	LDC_EXIT_LOCK(ldcp);

	D1(vswp, "vsw_ldc_uninit: exit: id(%lx)", ldcp->ldc_id);

	return (0);
}

static int
vsw_init_ldcs(vsw_port_t *port)
{
	vsw_ldc_list_t	*ldcl = &port->p_ldclist;
	vsw_ldc_t	*ldcp;

	READ_ENTER(&ldcl->lockrw);
	ldcp =  ldcl->head;
	for (; ldcp  != NULL; ldcp = ldcp->ldc_next) {
		(void) vsw_ldc_init(ldcp);
	}
	RW_EXIT(&ldcl->lockrw);

	return (0);
}

static int
vsw_uninit_ldcs(vsw_port_t *port)
{
	vsw_ldc_list_t	*ldcl = &port->p_ldclist;
	vsw_ldc_t	*ldcp;

	D1(NULL, "vsw_uninit_ldcs: enter\n");

	READ_ENTER(&ldcl->lockrw);
	ldcp =  ldcl->head;
	for (; ldcp  != NULL; ldcp = ldcp->ldc_next) {
		(void) vsw_ldc_uninit(ldcp);
	}
	RW_EXIT(&ldcl->lockrw);

	D1(NULL, "vsw_uninit_ldcs: exit\n");

	return (0);
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
static int
vsw_drain_ldcs(vsw_port_t *port)
{
	vsw_ldc_list_t	*ldcl = &port->p_ldclist;
	vsw_ldc_t	*ldcp;
	vsw_t		*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	READ_ENTER(&ldcl->lockrw);

	ldcp = ldcl->head;

	for (; ldcp  != NULL; ldcp = ldcp->ldc_next) {
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
			continue;
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
			while (ldc_unreg_callback(ldcp->ldc_handle)
			    == EWOULDBLOCK)
				(void) cv_timedwait(&ldcp->drain_cv,
				    &ldcp->drain_cv_lock, lbolt + hz);

			mutex_exit(&ldcp->drain_cv_lock);
			D2(vswp, "%s: unreg callback for chan %ld after "
			    "timeout", __func__, ldcp->ldc_id);
		}
	}
	RW_EXIT(&ldcl->lockrw);

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Wait until all tasks which reference this port have completed.
 *
 * Prior to this function being invoked each channel under this port
 * should have been quiesced via ldc_set_cb_mode(DISABLE).
 */
static int
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
		DERR(vswp, "%s: unable to dispatch marker task",
		    __func__);
		mutex_exit(&port->state_lock);
		return (1);
	}

	/*
	 * Wait for the marker task to finish.
	 */
	while (port->state != VSW_PORT_DETACHABLE)
		cv_wait(&port->state_cv, &port->state_lock);

	mutex_exit(&port->state_lock);

	D1(vswp, "%s: exit", __func__);

	return (0);
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
	vsw_t 		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s: enter: ldcid (%lld)\n", __func__, ldcp->ldc_id);

	mutex_enter(&ldcp->ldc_cblock);
	ldcp->ldc_stats.callbacks++;

	mutex_enter(&ldcp->status_lock);
	if ((ldcp->ldc_status == LDC_INIT) || (ldcp->ldc_handle == NULL)) {
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

		if (ldcp->rx_thread != NULL) {
			/*
			 * If the receive thread is enabled, then
			 * wakeup the receive thread to process the
			 * LDC messages.
			 */
			mutex_exit(&ldcp->ldc_cblock);
			mutex_enter(&ldcp->rx_thr_lock);
			if (!(ldcp->rx_thr_flags & VSW_WTHR_DATARCVD)) {
				ldcp->rx_thr_flags |= VSW_WTHR_DATARCVD;
				cv_signal(&ldcp->rx_thr_cv);
			}
			mutex_exit(&ldcp->rx_thr_lock);
			mutex_enter(&ldcp->ldc_cblock);
		} else {
			vsw_process_pkt(ldcp);
		}

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
	vsw_ldc_list_t	*ldcl;

	D1(vswp, "%s: enter", __func__);

	port = ldcp->ldc_port;
	ldcl = &port->p_ldclist;

	READ_ENTER(&ldcl->lockrw);

	D2(vswp, "%s: in 0x%llx : out 0x%llx", __func__,
	    ldcp->lane_in.lstate, ldcp->lane_out.lstate);

	vsw_free_lane_resources(ldcp, INBOUND);
	vsw_free_lane_resources(ldcp, OUTBOUND);
	RW_EXIT(&ldcl->lockrw);

	ldcp->lane_in.lstate = 0;
	ldcp->lane_out.lstate = 0;

	/*
	 * Remove parent port from any multicast groups
	 * it may have registered with. Client must resend
	 * multicast add command after handshake completes.
	 */
	(void) vsw_del_fdb(vswp, port);

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
 *
 * Note - care must be taken to ensure that this function is
 * not called with the dlistrw lock held.
 */
static void
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
	vsw_t		*vswp = NULL;
	uint16_t	evt;
	ldc_status_t	curr_status;

	ldcp = conn->ldcp;
	evt = conn->evt;
	vswp = ldcp->ldc_vswp;

	D1(vswp, "%s: enter", __func__);

	/* can safely free now have copied out data */
	kmem_free(conn, sizeof (vsw_conn_evt_t));

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

	D1(vswp, "%s (chan %lld): enter (phase %ld)", __func__,
	    ldcp->ldc_id, ldcp->hphase);

	DUMP_FLAGS(ldcp->lane_in.lstate);
	DUMP_FLAGS(ldcp->lane_out.lstate);

	switch (ldcp->hphase) {

	case VSW_MILESTONE0:
		/*
		 * If we haven't started to handshake with our peer,
		 * start to do so now.
		 */
		if (ldcp->lane_out.lstate == 0) {
			D2(vswp, "%s: (chan %lld) starting handshake "
			    "with peer", __func__, ldcp->ldc_id);
			vsw_process_conn_evt(ldcp, VSW_CONN_UP);
		}

		/*
		 * Only way to pass this milestone is to have successfully
		 * negotiated version info.
		 */
		if ((ldcp->lane_in.lstate & VSW_VER_ACK_SENT) &&
		    (ldcp->lane_out.lstate & VSW_VER_ACK_RECV)) {

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
		 * negotiated attribute information.
		 */
		if (ldcp->lane_in.lstate & VSW_ATTR_ACK_SENT) {

			ldcp->hphase = VSW_MILESTONE2;

			/*
			 * If the peer device has said it wishes to
			 * use descriptor rings then we send it our ring
			 * info, otherwise we just set up a private ring
			 * which we use an internal buffer
			 */
			if ((VSW_VER_EQ(ldcp, 1, 2) &&
			    (ldcp->lane_in.xfer_mode & VIO_DRING_MODE_V1_2)) ||
			    (VSW_VER_LT(ldcp, 1, 2) &&
			    (ldcp->lane_in.xfer_mode ==
			    VIO_DRING_MODE_V1_0))) {
				vsw_send_dring_info(ldcp);
			}
		}
		break;

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
		if ((VSW_VER_EQ(ldcp, 1, 2) &&
		    (ldcp->lane_in.xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    (VSW_VER_LT(ldcp, 1, 2) &&
		    (ldcp->lane_in.xfer_mode ==
		    VIO_DRING_MODE_V1_0))) {
			if (!(ldcp->lane_in.lstate & VSW_DRING_ACK_SENT))
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
		 * Mark outbound lane as available to transmit data.
		 */
		if ((ldcp->lane_out.lstate & VSW_RDX_ACK_SENT) &&
		    (ldcp->lane_in.lstate & VSW_RDX_ACK_RECV)) {

			D2(vswp, "%s: (chan %lld) leaving milestone 3",
			    __func__, ldcp->ldc_id);
			D2(vswp, "%s: ** handshake complete (0x%llx : "
			    "0x%llx) **", __func__, ldcp->lane_in.lstate,
			    ldcp->lane_out.lstate);
			ldcp->lane_out.lstate |= VSW_LANE_ACTIVE;
			ldcp->hphase = VSW_MILESTONE4;
			ldcp->hcnt = 0;
			DISPLAY_STATE();
		} else {
			D2(vswp, "%s: still in milestone 3 (0x%llx : 0x%llx)",
			    __func__, ldcp->lane_in.lstate,
			    ldcp->lane_out.lstate);
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

	if (VSW_VER_EQ(ldcp, 1, 2)) {
		/* Version 1.2 */

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

/*
 * Main routine for processing messages received over LDC.
 */
static void
vsw_process_pkt(void *arg)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t  *)arg;
	vsw_t 		*vswp = ldcp->ldc_vswp;
	size_t		msglen;
	vio_msg_tag_t	*tagp;
	uint64_t	*ldcmsg;
	int 		rv = 0;


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
			vsw_dispatch_ctrl_task(ldcp, ldcmsg, tagp);
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
vsw_dispatch_ctrl_task(vsw_ldc_t *ldcp, void *cpkt, vio_msg_tag_t *tagp)
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
	bcopy((def_msg_t *)cpkt, &ctaskp->pktp, sizeof (def_msg_t));
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
			DERR(vswp, "%s: unable to dispatch task to taskq",
			    __func__);
			kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
			mutex_exit(&port->state_lock);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return;
		}
	} else {
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
	vsw_t 		*vswp = ldcp->ldc_vswp;
	vio_msg_tag_t	tag;
	uint16_t	env;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	bcopy(&ctaskp->pktp, &tag, sizeof (vio_msg_tag_t));
	env = tag.vio_subtype_env;

	/* stale pkt check */
	if (ctaskp->hss_id < ldcp->hss_id) {
		DWARN(vswp, "%s: discarding stale packet belonging to earlier"
		    " (%ld) handshake session", __func__, ctaskp->hss_id);
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
	vsw_t 		*vswp = ldcp->ldc_vswp;

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
	vnet_attr_msg_t		*attr_pkt;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vsw_port_t		*port = ldcp->ldc_port;
	uint64_t		macaddr = 0;
	int			i;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a ctrl/attr packet so
	 * cast it into the correct structure.
	 */
	attr_pkt = (vnet_attr_msg_t *)pkt;

	switch (attr_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		if (vsw_check_flag(ldcp, INBOUND, VSW_ATTR_INFO_RECV))
			return;

		/*
		 * If the attributes are unacceptable then we NACK back.
		 */
		if (vsw_check_attr(attr_pkt, ldcp)) {

			DERR(vswp, "%s (chan %d): invalid attributes",
			    __func__, ldcp->ldc_id);

			vsw_free_lane_resources(ldcp, INBOUND);

			attr_pkt->tag.vio_sid = ldcp->local_session;
			attr_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)attr_pkt);
			ldcp->lane_in.lstate |= VSW_ATTR_NACK_SENT;
			(void) vsw_send_msg(ldcp, (void *)attr_pkt,
			    sizeof (vnet_attr_msg_t), B_TRUE);

			vsw_next_milestone(ldcp);
			return;
		}

		/*
		 * Otherwise store attributes for this lane and update
		 * lane state.
		 */
		ldcp->lane_in.mtu = attr_pkt->mtu;
		ldcp->lane_in.addr = attr_pkt->addr;
		ldcp->lane_in.addr_type = attr_pkt->addr_type;
		ldcp->lane_in.xfer_mode = attr_pkt->xfer_mode;
		ldcp->lane_in.ack_freq = attr_pkt->ack_freq;

		macaddr = ldcp->lane_in.addr;
		for (i = ETHERADDRL - 1; i >= 0; i--) {
			port->p_macaddr.ether_addr_octet[i] = macaddr & 0xFF;
			macaddr >>= 8;
		}

		/* create the fdb entry for this port/mac address */
		(void) vsw_add_fdb(vswp, port);

		/* setup device specifc xmit routines */
		mutex_enter(&port->tx_lock);
		if ((VSW_VER_EQ(ldcp, 1, 2) &&
		    (ldcp->lane_in.xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    (VSW_VER_LT(ldcp, 1, 2) &&
		    (ldcp->lane_in.xfer_mode == VIO_DRING_MODE_V1_0))) {
			D2(vswp, "%s: mode = VIO_DRING_MODE", __func__);
			port->transmit = vsw_dringsend;
		} else if (ldcp->lane_in.xfer_mode == VIO_DESC_MODE) {
			D2(vswp, "%s: mode = VIO_DESC_MODE", __func__);
			vsw_create_privring(ldcp);
			port->transmit = vsw_descrsend;
			ldcp->lane_out.xfer_mode = VIO_DESC_MODE;
		}
		mutex_exit(&port->tx_lock);

		attr_pkt->tag.vio_sid = ldcp->local_session;
		attr_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;

		DUMP_TAG_PTR((vio_msg_tag_t *)attr_pkt);

		ldcp->lane_in.lstate |= VSW_ATTR_ACK_SENT;

		(void) vsw_send_msg(ldcp, (void *)attr_pkt,
		    sizeof (vnet_attr_msg_t), B_TRUE);

		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_ATTR_ACK_RECV))
			return;

		ldcp->lane_out.lstate |= VSW_ATTR_ACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_ATTR_NACK_RECV))
			return;

		ldcp->lane_out.lstate |= VSW_ATTR_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: unknown vio_subtype %x\n", __func__,
		    attr_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
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
	vio_dring_reg_msg_t	*dring_pkt;
	vsw_t			*vswp = ldcp->ldc_vswp;
	ldc_mem_info_t		minfo;
	dring_info_t		*dp, *dbp;
	int			dring_found = 0;

	/*
	 * We know this is a ctrl/dring packet so
	 * cast it into the correct structure.
	 */
	dring_pkt = (vio_dring_reg_msg_t *)pkt;

	D1(vswp, "%s(%lld) enter", __func__, ldcp->ldc_id);

	switch (dring_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s: VIO_SUBTYPE_INFO", __func__);

		if (vsw_check_flag(ldcp, INBOUND, VSW_DRING_INFO_RECV))
			return;

		/*
		 * If the dring params are unacceptable then we NACK back.
		 */
		if (vsw_check_dring_info(dring_pkt)) {

			DERR(vswp, "%s (%lld): invalid dring info",
			    __func__, ldcp->ldc_id);

			vsw_free_lane_resources(ldcp, INBOUND);

			dring_pkt->tag.vio_sid = ldcp->local_session;
			dring_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)dring_pkt);

			ldcp->lane_in.lstate |= VSW_DRING_NACK_SENT;

			(void) vsw_send_msg(ldcp, (void *)dring_pkt,
			    sizeof (vio_dring_reg_msg_t), B_TRUE);

			vsw_next_milestone(ldcp);
			return;
		}

		/*
		 * Otherwise, attempt to map in the dring using the
		 * cookie. If that succeeds we send back a unique dring
		 * identifier that the sending side will use in future
		 * to refer to this descriptor ring.
		 */
		dp = kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);

		dp->num_descriptors = dring_pkt->num_descriptors;
		dp->descriptor_size = dring_pkt->descriptor_size;
		dp->options = dring_pkt->options;
		dp->ncookies = dring_pkt->ncookies;

		/*
		 * Note: should only get one cookie. Enforced in
		 * the ldc layer.
		 */
		bcopy(&dring_pkt->cookie[0], &dp->cookie[0],
		    sizeof (ldc_mem_cookie_t));

		D2(vswp, "%s: num_desc %ld : desc_size %ld", __func__,
		    dp->num_descriptors, dp->descriptor_size);
		D2(vswp, "%s: options 0x%lx: ncookies %ld", __func__,
		    dp->options, dp->ncookies);

		if ((ldc_mem_dring_map(ldcp->ldc_handle, &dp->cookie[0],
		    dp->ncookies, dp->num_descriptors, dp->descriptor_size,
		    LDC_SHADOW_MAP, &(dp->handle))) != 0) {

			DERR(vswp, "%s: dring_map failed\n", __func__);

			kmem_free(dp, sizeof (dring_info_t));
			vsw_free_lane_resources(ldcp, INBOUND);

			dring_pkt->tag.vio_sid = ldcp->local_session;
			dring_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)dring_pkt);

			ldcp->lane_in.lstate |= VSW_DRING_NACK_SENT;
			(void) vsw_send_msg(ldcp, (void *)dring_pkt,
			    sizeof (vio_dring_reg_msg_t), B_TRUE);

			vsw_next_milestone(ldcp);
			return;
		}

		if ((ldc_mem_dring_info(dp->handle, &minfo)) != 0) {

			DERR(vswp, "%s: dring_addr failed\n", __func__);

			kmem_free(dp, sizeof (dring_info_t));
			vsw_free_lane_resources(ldcp, INBOUND);

			dring_pkt->tag.vio_sid = ldcp->local_session;
			dring_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)dring_pkt);

			ldcp->lane_in.lstate |= VSW_DRING_NACK_SENT;
			(void) vsw_send_msg(ldcp, (void *)dring_pkt,
			    sizeof (vio_dring_reg_msg_t), B_TRUE);

			vsw_next_milestone(ldcp);
			return;
		} else {
			/* store the address of the pub part of ring */
			dp->pub_addr = minfo.vaddr;
		}

		/* no private section as we are importing */
		dp->priv_addr = NULL;

		/*
		 * Using simple mono increasing int for ident at
		 * the moment.
		 */
		dp->ident = ldcp->next_ident;
		ldcp->next_ident++;

		dp->end_idx = 0;
		dp->next = NULL;

		/*
		 * Link it onto the end of the list of drings
		 * for this lane.
		 */
		if (ldcp->lane_in.dringp == NULL) {
			D2(vswp, "%s: adding first INBOUND dring", __func__);
			ldcp->lane_in.dringp = dp;
		} else {
			dbp = ldcp->lane_in.dringp;

			while (dbp->next != NULL)
				dbp = dbp->next;

			dbp->next = dp;
		}

		/* acknowledge it */
		dring_pkt->tag.vio_sid = ldcp->local_session;
		dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
		dring_pkt->dring_ident = dp->ident;

		(void) vsw_send_msg(ldcp, (void *)dring_pkt,
		    sizeof (vio_dring_reg_msg_t), B_TRUE);

		ldcp->lane_in.lstate |= VSW_DRING_ACK_SENT;
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_DRING_ACK_RECV))
			return;

		/*
		 * Peer is acknowledging our dring info and will have
		 * sent us a dring identifier which we will use to
		 * refer to this ring w.r.t. our peer.
		 */
		dp = ldcp->lane_out.dringp;
		if (dp != NULL) {
			/*
			 * Find the ring this ident should be associated
			 * with.
			 */
			if (vsw_dring_match(dp, dring_pkt)) {
				dring_found = 1;

			} else while (dp != NULL) {
				if (vsw_dring_match(dp, dring_pkt)) {
					dring_found = 1;
					break;
				}
				dp = dp->next;
			}

			if (dring_found == 0) {
				DERR(NULL, "%s: unrecognised ring cookie",
				    __func__);
				vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
				return;
			}

		} else {
			DERR(vswp, "%s: DRING ACK received but no drings "
			    "allocated", __func__);
			vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);
			return;
		}

		/* store ident */
		dp->ident = dring_pkt->dring_ident;
		ldcp->lane_out.lstate |= VSW_DRING_ACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_DRING_NACK_RECV))
			return;

		ldcp->lane_out.lstate |= VSW_DRING_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
		    dring_pkt->tag.vio_subtype);
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
vsw_process_data_pkt(vsw_ldc_t *ldcp, void *dpkt, vio_msg_tag_t *tagp,
	uint32_t msglen)
{
	uint16_t	env = tagp->vio_subtype_env;
	vsw_t		*vswp = ldcp->ldc_vswp;

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

	/*
	 * To reduce the locking contention, release the
	 * ldc_cblock here and re-acquire it once we are done
	 * receiving packets.
	 */
	mutex_exit(&ldcp->ldc_cblock);
	mutex_enter(&ldcp->ldc_rxlock);

	/*
	 * Switch on vio_subtype envelope, then let lower routines
	 * decide if its an INFO, ACK or NACK packet.
	 */
	if (env == VIO_DRING_DATA) {
		vsw_process_data_dring_pkt(ldcp, dpkt);
	} else if (env == VIO_PKT_DATA) {
		ldcp->rx_pktdata(ldcp, dpkt, msglen);
	} else if (env == VIO_DESC_DATA) {
		vsw_process_data_ibnd_pkt(ldcp, dpkt);
	} else {
		DERR(vswp, "%s: unknown vio_subtype_env (%x)\n", __func__, env);
	}

	mutex_exit(&ldcp->ldc_rxlock);
	mutex_enter(&ldcp->ldc_cblock);

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

#define	SND_DRING_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	(void) vsw_send_msg(ldcp, (void *)pkt, \
			sizeof (vio_dring_msg_t), B_TRUE);

static void
vsw_process_data_dring_pkt(vsw_ldc_t *ldcp, void *dpkt)
{
	vio_dring_msg_t		*dring_pkt;
	vnet_public_desc_t	*pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;
	dring_info_t		*dp = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	mblk_t			*mp = NULL;
	mblk_t			*bp = NULL;
	mblk_t			*bpt = NULL;
	size_t			nbytes = 0;
	uint64_t		ncookies = 0;
	uint64_t		chain = 0;
	uint64_t		len;
	uint32_t		pos, start, datalen;
	uint32_t		range_start, range_end;
	int32_t			end, num, cnt = 0;
	int			i, rv, msg_rv = 0;
	boolean_t		ack_needed = B_FALSE;
	boolean_t		prev_desc_ack = B_FALSE;
	int			read_attempts = 0;
	struct ether_header	*ehp;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/*
	 * We know this is a data/dring packet so
	 * cast it into the correct structure.
	 */
	dring_pkt = (vio_dring_msg_t *)dpkt;

	/*
	 * Switch on the vio_subtype. If its INFO then we need to
	 * process the data. If its an ACK we need to make sure
	 * it makes sense (i.e did we send an earlier data/info),
	 * and if its a NACK then we maybe attempt a retry.
	 */
	switch (dring_pkt->tag.vio_subtype) {
	case VIO_SUBTYPE_INFO:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_INFO", __func__, ldcp->ldc_id);

		READ_ENTER(&ldcp->lane_in.dlistrw);
		if ((dp = vsw_ident2dring(&ldcp->lane_in,
		    dring_pkt->dring_ident)) == NULL) {
			RW_EXIT(&ldcp->lane_in.dlistrw);

			DERR(vswp, "%s(%lld): unable to find dring from "
			    "ident 0x%llx", __func__, ldcp->ldc_id,
			    dring_pkt->dring_ident);

			SND_DRING_NACK(ldcp, dring_pkt);
			return;
		}

		start = pos = dring_pkt->start_idx;
		end = dring_pkt->end_idx;
		len = dp->num_descriptors;

		range_start = range_end = pos;

		D2(vswp, "%s(%lld): start index %ld : end %ld\n",
		    __func__, ldcp->ldc_id, start, end);

		if (end == -1) {
			num = -1;
		} else if (end >= 0) {
			num = end >= pos ? end - pos + 1: (len - pos + 1) + end;

			/* basic sanity check */
			if (end > len) {
				RW_EXIT(&ldcp->lane_in.dlistrw);
				DERR(vswp, "%s(%lld): endpoint %lld outside "
				    "ring length %lld", __func__,
				    ldcp->ldc_id, end, len);

				SND_DRING_NACK(ldcp, dring_pkt);
				return;
			}
		} else {
			RW_EXIT(&ldcp->lane_in.dlistrw);
			DERR(vswp, "%s(%lld): invalid endpoint %lld",
			    __func__, ldcp->ldc_id, end);
			SND_DRING_NACK(ldcp, dring_pkt);
			return;
		}

		while (cnt != num) {
vsw_recheck_desc:
			if ((rv = ldc_mem_dring_acquire(dp->handle,
			    pos, pos)) != 0) {
				RW_EXIT(&ldcp->lane_in.dlistrw);
				DERR(vswp, "%s(%lld): unable to acquire "
				    "descriptor at pos %d: err %d",
				    __func__, pos, ldcp->ldc_id, rv);
				SND_DRING_NACK(ldcp, dring_pkt);
				ldcp->ldc_stats.ierrors++;
				return;
			}

			pub_addr = (vnet_public_desc_t *)dp->pub_addr + pos;

			/*
			 * When given a bounded range of descriptors
			 * to process, its an error to hit a descriptor
			 * which is not ready. In the non-bounded case
			 * (end_idx == -1) this simply indicates we have
			 * reached the end of the current active range.
			 */
			if (pub_addr->hdr.dstate != VIO_DESC_READY) {
				/* unbound - no error */
				if (end == -1) {
					if (read_attempts == vsw_read_attempts)
						break;

					delay(drv_usectohz(vsw_desc_delay));
					read_attempts++;
					goto vsw_recheck_desc;
				}

				/* bounded - error - so NACK back */
				RW_EXIT(&ldcp->lane_in.dlistrw);
				DERR(vswp, "%s(%lld): descriptor not READY "
				    "(%d)", __func__, ldcp->ldc_id,
				    pub_addr->hdr.dstate);
				SND_DRING_NACK(ldcp, dring_pkt);
				return;
			}

			DTRACE_PROBE1(read_attempts, int, read_attempts);

			range_end = pos;

			/*
			 * If we ACK'd the previous descriptor then now
			 * record the new range start position for later
			 * ACK's.
			 */
			if (prev_desc_ack) {
				range_start = pos;

				D2(vswp, "%s(%lld): updating range start to be "
				    "%d", __func__, ldcp->ldc_id, range_start);

				prev_desc_ack = B_FALSE;
			}

			/*
			 * Data is padded to align on 8 byte boundary,
			 * datalen is actual data length, i.e. minus that
			 * padding.
			 */
			datalen = pub_addr->nbytes;

			/*
			 * Does peer wish us to ACK when we have finished
			 * with this descriptor ?
			 */
			if (pub_addr->hdr.ack)
				ack_needed = B_TRUE;

			D2(vswp, "%s(%lld): processing desc %lld at pos"
			    " 0x%llx : dstate 0x%lx : datalen 0x%lx",
			    __func__, ldcp->ldc_id, pos, pub_addr,
			    pub_addr->hdr.dstate, datalen);

			/*
			 * Mark that we are starting to process descriptor.
			 */
			pub_addr->hdr.dstate = VIO_DESC_ACCEPTED;

			/*
			 * Ensure that we ask ldc for an aligned
			 * number of bytes.
			 */
			nbytes = (datalen + VNET_IPALIGN + 7) & ~7;

			mp = vio_multipool_allocb(&ldcp->vmp, nbytes);
			if (mp == NULL) {
				ldcp->ldc_stats.rx_vio_allocb_fail++;
				/*
				 * No free receive buffers available, so
				 * fallback onto allocb(9F). Make sure that
				 * we get a data buffer which is a multiple
				 * of 8 as this is required by ldc_mem_copy.
				 */
				DTRACE_PROBE(allocb);
				if ((mp = allocb(datalen + VNET_IPALIGN + 8,
				    BPRI_MED)) == NULL) {
					DERR(vswp, "%s(%ld): allocb failed",
					    __func__, ldcp->ldc_id);
					pub_addr->hdr.dstate = VIO_DESC_DONE;
					(void) ldc_mem_dring_release(dp->handle,
					    pos, pos);
					ldcp->ldc_stats.ierrors++;
					ldcp->ldc_stats.rx_allocb_fail++;
					break;
				}
			}

			ncookies = pub_addr->ncookies;
			rv = ldc_mem_copy(ldcp->ldc_handle,
			    (caddr_t)mp->b_rptr, 0, &nbytes,
			    pub_addr->memcookie, ncookies, LDC_COPY_IN);

			if (rv != 0) {
				DERR(vswp, "%s(%d): unable to copy in data "
				    "from %d cookies in desc %d (rv %d)",
				    __func__, ldcp->ldc_id, ncookies, pos, rv);
				freemsg(mp);

				pub_addr->hdr.dstate = VIO_DESC_DONE;
				(void) ldc_mem_dring_release(dp->handle,
				    pos, pos);
				ldcp->ldc_stats.ierrors++;
				break;
			} else {
				D2(vswp, "%s(%d): copied in %ld bytes"
				    " using %d cookies", __func__,
				    ldcp->ldc_id, nbytes, ncookies);
			}

			/* adjust the read pointer to skip over the padding */
			mp->b_rptr += VNET_IPALIGN;

			/* point to the actual end of data */
			mp->b_wptr = mp->b_rptr + datalen;

			/* update statistics */
			ehp = (struct ether_header *)mp->b_rptr;
			if (IS_BROADCAST(ehp))
				ldcp->ldc_stats.brdcstrcv++;
			else if (IS_MULTICAST(ehp))
				ldcp->ldc_stats.multircv++;

			ldcp->ldc_stats.ipackets++;
			ldcp->ldc_stats.rbytes += datalen;

			/* build a chain of received packets */
			if (bp == NULL) {
				/* first pkt */
				bp = mp;
				bp->b_next = bp->b_prev = NULL;
				bpt = bp;
				chain = 1;
			} else {
				mp->b_next = mp->b_prev = NULL;
				bpt->b_next = mp;
				bpt = mp;
				chain++;
			}

			/* mark we are finished with this descriptor */
			pub_addr->hdr.dstate = VIO_DESC_DONE;

			(void) ldc_mem_dring_release(dp->handle, pos, pos);

			/*
			 * Send an ACK back to peer if requested.
			 */
			if (ack_needed) {
				ack_needed = B_FALSE;

				dring_pkt->start_idx = range_start;
				dring_pkt->end_idx = range_end;

				DERR(vswp, "%s(%lld): processed %d %d, ACK"
				    " requested", __func__, ldcp->ldc_id,
				    dring_pkt->start_idx, dring_pkt->end_idx);

				dring_pkt->dring_process_state = VIO_DP_ACTIVE;
				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
				dring_pkt->tag.vio_sid = ldcp->local_session;

				msg_rv = vsw_send_msg(ldcp, (void *)dring_pkt,
				    sizeof (vio_dring_msg_t), B_FALSE);

				/*
				 * Check if ACK was successfully sent. If not
				 * we break and deal with that below.
				 */
				if (msg_rv != 0)
					break;

				prev_desc_ack = B_TRUE;
				range_start = pos;
			}

			/* next descriptor */
			pos = (pos + 1) % len;
			cnt++;

			/*
			 * Break out of loop here and stop processing to
			 * allow some other network device (or disk) to
			 * get access to the cpu.
			 */
			if (chain > vsw_chain_len) {
				D3(vswp, "%s(%lld): switching chain of %d "
				    "msgs", __func__, ldcp->ldc_id, chain);
				break;
			}
		}
		RW_EXIT(&ldcp->lane_in.dlistrw);

		/*
		 * If when we attempted to send the ACK we found that the
		 * channel had been reset then now handle this. We deal with
		 * it here as we cannot reset the channel while holding the
		 * dlistrw lock, and we don't want to acquire/release it
		 * continuously in the above loop, as a channel reset should
		 * be a rare event.
		 */
		if (msg_rv == ECONNRESET) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
			break;
		}

		/* send the chain of packets to be switched */
		if (bp != NULL) {
			DTRACE_PROBE1(vsw_rcv_msgs, int, chain);
			D3(vswp, "%s(%lld): switching chain of %d msgs",
			    __func__, ldcp->ldc_id, chain);
			vswp->vsw_switch_frame(vswp, bp, VSW_VNETPORT,
			    ldcp->ldc_port, NULL);
		}

		DTRACE_PROBE1(msg_cnt, int, cnt);

		/*
		 * We are now finished so ACK back with the state
		 * set to STOPPING so our peer knows we are finished
		 */
		dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
		dring_pkt->tag.vio_sid = ldcp->local_session;

		dring_pkt->dring_process_state = VIO_DP_STOPPED;

		DTRACE_PROBE(stop_process_sent);

		/*
		 * We have not processed any more descriptors beyond
		 * the last one we ACK'd.
		 */
		if (prev_desc_ack)
			range_start = range_end;

		dring_pkt->start_idx = range_start;
		dring_pkt->end_idx = range_end;

		D2(vswp, "%s(%lld) processed : %d : %d, now stopping",
		    __func__, ldcp->ldc_id, dring_pkt->start_idx,
		    dring_pkt->end_idx);

		(void) vsw_send_msg(ldcp, (void *)dring_pkt,
		    sizeof (vio_dring_msg_t), B_TRUE);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_ACK", __func__, ldcp->ldc_id);
		/*
		 * Verify that the relevant descriptors are all
		 * marked as DONE
		 */
		READ_ENTER(&ldcp->lane_out.dlistrw);
		if ((dp = vsw_ident2dring(&ldcp->lane_out,
		    dring_pkt->dring_ident)) == NULL) {
			RW_EXIT(&ldcp->lane_out.dlistrw);
			DERR(vswp, "%s: unknown ident in ACK", __func__);
			return;
		}

		start = end = 0;
		start = dring_pkt->start_idx;
		end = dring_pkt->end_idx;
		len = dp->num_descriptors;


		mutex_enter(&dp->dlock);
		dp->last_ack_recv = end;
		ldcp->ldc_stats.dring_data_acks++;
		mutex_exit(&dp->dlock);

		(void) vsw_reclaim_dring(dp, start);

		/*
		 * If our peer is stopping processing descriptors then
		 * we check to make sure it has processed all the descriptors
		 * we have updated. If not then we send it a new message
		 * to prompt it to restart.
		 */
		if (dring_pkt->dring_process_state == VIO_DP_STOPPED) {
			DTRACE_PROBE(stop_process_recv);
			D2(vswp, "%s(%lld): got stopping msg : %d : %d",
			    __func__, ldcp->ldc_id, dring_pkt->start_idx,
			    dring_pkt->end_idx);

			/*
			 * Check next descriptor in public section of ring.
			 * If its marked as READY then we need to prompt our
			 * peer to start processing the ring again.
			 */
			i = (end + 1) % len;
			pub_addr = (vnet_public_desc_t *)dp->pub_addr + i;
			priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;

			/*
			 * Hold the restart lock across all of this to
			 * make sure that its not possible for us to
			 * decide that a msg needs to be sent in the future
			 * but the sending code having already checked is
			 * about to exit.
			 */
			mutex_enter(&dp->restart_lock);
			ldcp->ldc_stats.dring_stopped_acks++;
			mutex_enter(&priv_addr->dstate_lock);
			if (pub_addr->hdr.dstate == VIO_DESC_READY) {

				mutex_exit(&priv_addr->dstate_lock);

				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;
				dring_pkt->tag.vio_sid = ldcp->local_session;

				dring_pkt->start_idx = (end + 1) % len;
				dring_pkt->end_idx = -1;

				D2(vswp, "%s(%lld) : sending restart msg:"
				    " %d : %d", __func__, ldcp->ldc_id,
				    dring_pkt->start_idx, dring_pkt->end_idx);

				msg_rv = vsw_send_msg(ldcp, (void *)dring_pkt,
				    sizeof (vio_dring_msg_t), B_FALSE);
				ldcp->ldc_stats.dring_data_msgs++;

			} else {
				mutex_exit(&priv_addr->dstate_lock);
				dp->restart_reqd = B_TRUE;
			}
			mutex_exit(&dp->restart_lock);
		}
		RW_EXIT(&ldcp->lane_out.dlistrw);

		/* only do channel reset after dropping dlistrw lock */
		if (msg_rv == ECONNRESET)
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);

		break;

	case VIO_SUBTYPE_NACK:
		DWARN(vswp, "%s(%lld): VIO_SUBTYPE_NACK",
		    __func__, ldcp->ldc_id);
		/*
		 * Something is badly wrong if we are getting NACK's
		 * for our data pkts. So reset the channel.
		 */
		vsw_process_conn_evt(ldcp, VSW_CONN_RESTART);

		break;

	default:
		DERR(vswp, "%s(%lld): Unknown vio_subtype %x\n", __func__,
		    ldcp->ldc_id, dring_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
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
	vsw_t			*vswp = ldcp->ldc_vswp;
	vgen_stats_t		*statsp = &ldcp->ldc_stats;

	size = msglen - VIO_PKT_DATA_HDRSIZE;
	if (size < ETHERMIN || size > ETHERMAX) {
		(void) atomic_inc_32(&statsp->rx_pri_fail);
		DWARN(vswp, "%s(%lld) invalid size(%d)\n", __func__,
		    ldcp->ldc_id, size);
		return;
	}

	mp = vio_multipool_allocb(&ldcp->vmp, size);
	if (mp == NULL) {
		mp = allocb(size, BPRI_MED);
		if (mp == NULL) {
			(void) atomic_inc_32(&statsp->rx_pri_fail);
			DWARN(vswp, "%s(%lld) allocb failure, "
			    "unable to process priority frame\n", __func__,
			    ldcp->ldc_id);
			return;
		}
	}

	/* copy the frame from the payload of raw data msg into the mblk */
	bcopy(dpkt->data, mp->b_rptr, size);
	mp->b_wptr = mp->b_rptr + size;

	/* update stats */
	(void) atomic_inc_64(&statsp->rx_pri_packets);
	(void) atomic_add_64(&statsp->rx_pri_bytes, size);

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

		mp = allocb(datalen, BPRI_MED);
		if (mp == NULL) {
			DERR(vswp, "%s(%lld): allocb failed",
			    __func__, ldcp->ldc_id);
			ldcp->ldc_stats.rx_allocb_fail++;
			return;
		}

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

		/* send the packet to be switched */
		vswp->vsw_switch_frame(vswp, mp, VSW_VNETPORT,
		    ldcp->ldc_port, NULL);

		break;

	case VIO_SUBTYPE_ACK:
		D1(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		/* Verify the ACK is valid */
		idx = ibnd_desc->hdr.desc_handle;

		if (idx >= vsw_ntxds) {
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

		if (idx >= vsw_ntxds) {
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
vsw_portsend(vsw_port_t *port, mblk_t *mp, mblk_t *mpt, uint32_t count)
{
	vsw_ldc_list_t 	*ldcl = &port->p_ldclist;
	vsw_ldc_t 	*ldcp;
	int		status = 0;

	READ_ENTER(&ldcl->lockrw);
	/*
	 * Note for now, we have a single channel.
	 */
	ldcp = ldcl->head;
	if (ldcp == NULL) {
		DERR(port->p_vswp, "vsw_portsend: no ldc: dropping packet\n");
		freemsgchain(mp);
		RW_EXIT(&ldcl->lockrw);
		return (1);
	}

	status = ldcp->tx(ldcp, mp, mpt, count);

	RW_EXIT(&ldcl->lockrw);

	return (status);
}

/*
 * Break up frames into 2 seperate chains: normal and
 * priority, based on the frame type. The number of
 * priority frames is also counted and returned.
 *
 * Params:
 * 	vswp:	pointer to the instance of vsw
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
	vsw_ldc_t 		*ldcp = (vsw_ldc_t *)arg;
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
	vsw_ldc_t 	*ldcp = (vsw_ldc_t *)arg;
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
	caddr_t			dst;
	uint32_t		mblksz;
	uint32_t		size;
	uint32_t		nbytes;
	int			rv;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vgen_stats_t		*statsp = &ldcp->ldc_stats;

	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == NULL)) {
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
	nmp = vio_allocb(vswp->pri_tx_vmp);
	if (nmp == NULL) {
		(void) atomic_inc_32(&statsp->tx_pri_fail);
		DWARN(vswp, "vio_allocb failed\n");
		goto send_pkt_exit;
	}
	pkt = (vio_raw_data_msg_t *)nmp->b_rptr;

	/* copy frame into the payload of raw data message */
	dst = (caddr_t)pkt->data;
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblksz = MBLKL(bp);
		bcopy(bp->b_rptr, dst, mblksz);
		dst += mblksz;
	}

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
	int i;
	int rc;
	int status = 0;
	vsw_port_t *port = ldcp->ldc_port;
	dring_info_t *dp = NULL;


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
		READ_ENTER(&ldcp->lane_out.dlistrw);
		if (((dp = ldcp->lane_out.dringp) != NULL) &&
		    ((VSW_VER_EQ(ldcp, 1, 2) &&
		    (ldcp->lane_out.xfer_mode & VIO_DRING_MODE_V1_2)) ||
		    ((VSW_VER_LT(ldcp, 1, 2) &&
		    (ldcp->lane_out.xfer_mode == VIO_DRING_MODE_V1_0))))) {
			rc = vsw_reclaim_dring(dp, dp->end_idx);
		} else {
			/*
			 * If there is no dring or the xfer_mode is
			 * set to DESC_MODE(ie., OBP), then simply break here.
			 */
			RW_EXIT(&ldcp->lane_out.dlistrw);
			break;
		}
		RW_EXIT(&ldcp->lane_out.dlistrw);

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
 * Send packet out via descriptor ring to a logical device.
 */
static int
vsw_dringsend(vsw_ldc_t *ldcp, mblk_t *mp)
{
	vio_dring_msg_t		dring_pkt;
	dring_info_t		*dp = NULL;
	vsw_private_desc_t	*priv_desc = NULL;
	vnet_public_desc_t	*pub = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	mblk_t			*bp;
	size_t			n, size;
	caddr_t			bufp;
	int			idx;
	int			status = LDC_TX_SUCCESS;
	struct ether_header	*ehp = (struct ether_header *)mp->b_rptr;

	D1(vswp, "%s(%lld): enter\n", __func__, ldcp->ldc_id);

	/* TODO: make test a macro */
	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == NULL)) {
		DWARN(vswp, "%s(%lld) status(%d) lstate(0x%llx), dropping "
		    "packet\n", __func__, ldcp->ldc_id, ldcp->ldc_status,
		    ldcp->lane_out.lstate);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * Note - using first ring only, this may change
	 * in the future.
	 */
	READ_ENTER(&ldcp->lane_out.dlistrw);
	if ((dp = ldcp->lane_out.dringp) == NULL) {
		RW_EXIT(&ldcp->lane_out.dlistrw);
		DERR(vswp, "%s(%lld): no dring for outbound lane on"
		    " channel %d", __func__, ldcp->ldc_id, ldcp->ldc_id);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)ETHERMAX) {
		RW_EXIT(&ldcp->lane_out.dlistrw);
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * Find a free descriptor
	 *
	 * Note: for the moment we are assuming that we will only
	 * have one dring going from the switch to each of its
	 * peers. This may change in the future.
	 */
	if (vsw_dring_find_free_desc(dp, &priv_desc, &idx) != 0) {
		D2(vswp, "%s(%lld): no descriptor available for ring "
		    "at 0x%llx", __func__, ldcp->ldc_id, dp);

		/* nothing more we can do */
		status = LDC_TX_NORESOURCES;
		ldcp->ldc_stats.tx_no_desc++;
		goto vsw_dringsend_free_exit;
	} else {
		D2(vswp, "%s(%lld): free private descriptor found at pos %ld "
		    "addr 0x%llx\n", __func__, ldcp->ldc_id, idx, priv_desc);
	}

	/* copy data into the descriptor */
	bufp = priv_desc->datap;
	bufp += VNET_IPALIGN;
	for (bp = mp, n = 0; bp != NULL; bp = bp->b_cont) {
		n = MBLKL(bp);
		bcopy(bp->b_rptr, bufp, n);
		bufp += n;
	}

	priv_desc->datalen = (size < (size_t)ETHERMIN) ? ETHERMIN : size;

	pub = priv_desc->descp;
	pub->nbytes = priv_desc->datalen;

	/* update statistics */
	if (IS_BROADCAST(ehp))
		ldcp->ldc_stats.brdcstxmt++;
	else if (IS_MULTICAST(ehp))
		ldcp->ldc_stats.multixmt++;
	ldcp->ldc_stats.opackets++;
	ldcp->ldc_stats.obytes += priv_desc->datalen;

	mutex_enter(&priv_desc->dstate_lock);
	pub->hdr.dstate = VIO_DESC_READY;
	mutex_exit(&priv_desc->dstate_lock);

	/*
	 * Determine whether or not we need to send a message to our
	 * peer prompting them to read our newly updated descriptor(s).
	 */
	mutex_enter(&dp->restart_lock);
	if (dp->restart_reqd) {
		dp->restart_reqd = B_FALSE;
		ldcp->ldc_stats.dring_data_msgs++;
		mutex_exit(&dp->restart_lock);

		/*
		 * Send a vio_dring_msg to peer to prompt them to read
		 * the updated descriptor ring.
		 */
		dring_pkt.tag.vio_msgtype = VIO_TYPE_DATA;
		dring_pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
		dring_pkt.tag.vio_subtype_env = VIO_DRING_DATA;
		dring_pkt.tag.vio_sid = ldcp->local_session;

		/* Note - for now using first ring */
		dring_pkt.dring_ident = dp->ident;

		/*
		 * If last_ack_recv is -1 then we know we've not
		 * received any ack's yet, so this must be the first
		 * msg sent, so set the start to the begining of the ring.
		 */
		mutex_enter(&dp->dlock);
		if (dp->last_ack_recv == -1) {
			dring_pkt.start_idx = 0;
		} else {
			dring_pkt.start_idx =
			    (dp->last_ack_recv + 1) % dp->num_descriptors;
		}
		dring_pkt.end_idx = -1;
		mutex_exit(&dp->dlock);

		D3(vswp, "%s(%lld): dring 0x%llx : ident 0x%llx\n", __func__,
		    ldcp->ldc_id, dp, dring_pkt.dring_ident);
		D3(vswp, "%s(%lld): start %lld : end %lld :\n",
		    __func__, ldcp->ldc_id, dring_pkt.start_idx,
		    dring_pkt.end_idx);

		RW_EXIT(&ldcp->lane_out.dlistrw);

		(void) vsw_send_msg(ldcp, (void *)&dring_pkt,
		    sizeof (vio_dring_msg_t), B_TRUE);

		return (status);

	} else {
		mutex_exit(&dp->restart_lock);
		D2(vswp, "%s(%lld): updating descp %d", __func__,
		    ldcp->ldc_id, idx);
	}

vsw_dringsend_free_exit:

	RW_EXIT(&ldcp->lane_out.dlistrw);

	D1(vswp, "%s(%lld): exit\n", __func__, ldcp->ldc_id);
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

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	ASSERT(mp != NULL);

	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
	    (ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == NULL)) {
		DERR(vswp, "%s(%lld) status(%d) state (0x%llx), dropping pkt",
		    __func__, ldcp->ldc_id, ldcp->ldc_status,
		    ldcp->lane_out.lstate);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * only expect single dring to exist, which we use
	 * as an internal buffer, rather than a transfer channel.
	 */
	READ_ENTER(&ldcp->lane_out.dlistrw);
	if ((dp = ldcp->lane_out.dringp) == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane",
		    __func__, ldcp->ldc_id);
		DERR(vswp, "%s(%lld) status(%d) state (0x%llx)", __func__,
		    ldcp->ldc_id, ldcp->ldc_status, ldcp->lane_out.lstate);
		RW_EXIT(&ldcp->lane_out.dlistrw);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)ETHERMAX) {
		RW_EXIT(&ldcp->lane_out.dlistrw);
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		ldcp->ldc_stats.oerrors++;
		return (LDC_TX_FAILURE);
	}

	/*
	 * Find a free descriptor in our buffer ring
	 */
	if (vsw_dring_find_free_desc(dp, &priv_desc, &idx) != 0) {
		RW_EXIT(&ldcp->lane_out.dlistrw);
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

	RW_EXIT(&ldcp->lane_out.dlistrw);

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

	READ_ENTER(&vswp->if_lockrw);
	attr_msg.addr = vnet_macaddr_strtoul((vswp->if_addr).ether_addr_octet);
	RW_EXIT(&vswp->if_lockrw);

	ldcp->lane_out.lstate |= VSW_ATTR_INFO_SENT;

	DUMP_TAG(attr_msg.tag);

	(void) vsw_send_msg(ldcp, &attr_msg, sizeof (vnet_attr_msg_t), B_TRUE);

	D1(vswp, "%s (%ld) exit", __func__, ldcp->ldc_id);
}

/*
 * Create dring info msg (which also results in the creation of
 * a dring).
 */
static vio_dring_reg_msg_t *
vsw_create_dring_info_pkt(vsw_ldc_t *ldcp)
{
	vio_dring_reg_msg_t	*mp;
	dring_info_t		*dp;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "vsw_create_dring_info_pkt enter\n");

	/*
	 * If we can't create a dring, obviously no point sending
	 * a message.
	 */
	if ((dp = vsw_create_dring(ldcp)) == NULL)
		return (NULL);

	mp = kmem_zalloc(sizeof (vio_dring_reg_msg_t), KM_SLEEP);

	mp->tag.vio_msgtype = VIO_TYPE_CTRL;
	mp->tag.vio_subtype = VIO_SUBTYPE_INFO;
	mp->tag.vio_subtype_env = VIO_DRING_REG;
	mp->tag.vio_sid = ldcp->local_session;

	/* payload */
	mp->num_descriptors = dp->num_descriptors;
	mp->descriptor_size = dp->descriptor_size;
	mp->options = dp->options;
	mp->ncookies = dp->ncookies;
	bcopy(&dp->cookie[0], &mp->cookie[0], sizeof (ldc_mem_cookie_t));

	mp->dring_ident = 0;

	D1(vswp, "vsw_create_dring_info_pkt exit\n");

	return (mp);
}

static void
vsw_send_dring_info(vsw_ldc_t *ldcp)
{
	vio_dring_reg_msg_t	*dring_msg;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s: (%ld) enter", __func__, ldcp->ldc_id);

	dring_msg = vsw_create_dring_info_pkt(ldcp);
	if (dring_msg == NULL) {
		cmn_err(CE_WARN, "!vsw%d: %s: error creating msg",
		    vswp->instance, __func__);
		return;
	}

	ldcp->lane_out.lstate |= VSW_DRING_INFO_SENT;

	DUMP_TAG_PTR((vio_msg_tag_t *)dring_msg);

	(void) vsw_send_msg(ldcp, dring_msg,
	    sizeof (vio_dring_reg_msg_t), B_TRUE);

	kmem_free(dring_msg, sizeof (vio_dring_reg_msg_t));

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
 * Generic routine to send message out over ldc channel.
 *
 * It is possible that when we attempt to write over the ldc channel
 * that we get notified that it has been reset. Depending on the value
 * of the handle_reset flag we either handle that event here or simply
 * notify the caller that the channel was reset.
 */
static int
vsw_send_msg(vsw_ldc_t *ldcp, void *msgp, int size, boolean_t handle_reset)
{
	int			rv;
	size_t			msglen = size;
	vio_msg_tag_t		*tag = (vio_msg_tag_t *)msgp;
	vsw_t			*vswp = ldcp->ldc_vswp;
	vio_dring_msg_t		*dmsg;
	vio_raw_data_msg_t	*rmsg;
	vnet_ibnd_desc_t	*imsg;
	boolean_t		data_msg = B_FALSE;

	D1(vswp, "vsw_send_msg (%lld) enter : sending %d bytes",
	    ldcp->ldc_id, size);

	D2(vswp, "send_msg: type 0x%llx", tag->vio_msgtype);
	D2(vswp, "send_msg: stype 0x%llx", tag->vio_subtype);
	D2(vswp, "send_msg: senv 0x%llx", tag->vio_subtype_env);

	mutex_enter(&ldcp->ldc_txlock);

	if (tag->vio_subtype == VIO_SUBTYPE_INFO) {
		if (tag->vio_subtype_env == VIO_DRING_DATA) {
			dmsg = (vio_dring_msg_t *)tag;
			dmsg->seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		} else if (tag->vio_subtype_env == VIO_PKT_DATA) {
			rmsg = (vio_raw_data_msg_t *)tag;
			rmsg->seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		} else if (tag->vio_subtype_env == VIO_DESC_DATA) {
			imsg = (vnet_ibnd_desc_t *)tag;
			imsg->hdr.seq_num = ldcp->lane_out.seq_num;
			data_msg = B_TRUE;
		}
	}

	do {
		msglen = size;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msgp, &msglen);
	} while (rv == EWOULDBLOCK && --vsw_wretries > 0);

	if (rv == 0 && data_msg == B_TRUE) {
		ldcp->lane_out.seq_num++;
	}

	if ((rv != 0) || (msglen != size)) {
		DERR(vswp, "vsw_send_msg:ldc_write failed: chan(%lld) rv(%d) "
		    "size (%d) msglen(%d)\n", ldcp->ldc_id, rv, size, msglen);
		ldcp->ldc_stats.oerrors++;
	}

	mutex_exit(&ldcp->ldc_txlock);

	/*
	 * If channel has been reset we either handle it here or
	 * simply report back that it has been reset and let caller
	 * decide what to do.
	 */
	if (rv == ECONNRESET) {
		DWARN(vswp, "%s (%lld) channel reset", __func__, ldcp->ldc_id);

		/*
		 * N.B - must never be holding the dlistrw lock when
		 * we do a reset of the channel.
		 */
		if (handle_reset) {
			vsw_process_conn_evt(ldcp, VSW_CONN_RESET);
		}
	}

	return (rv);
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
 * Creates a descriptor ring (dring) and links it into the
 * link of outbound drings for this channel.
 *
 * Returns NULL if creation failed.
 */
static dring_info_t *
vsw_create_dring(vsw_ldc_t *ldcp)
{
	vsw_private_desc_t	*priv_addr = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	ldc_mem_info_t		minfo;
	dring_info_t		*dp, *tp;
	int			i;

	dp = (dring_info_t *)kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);

	mutex_init(&dp->dlock, NULL, MUTEX_DRIVER, NULL);

	/* create public section of ring */
	if ((ldc_mem_dring_create(vsw_ntxds,
	    VSW_PUB_SIZE, &dp->handle)) != 0) {

		DERR(vswp, "vsw_create_dring(%lld): ldc dring create "
		    "failed", ldcp->ldc_id);
		goto create_fail_exit;
	}

	ASSERT(dp->handle != NULL);

	/*
	 * Get the base address of the public section of the ring.
	 */
	if ((ldc_mem_dring_info(dp->handle, &minfo)) != 0) {
		DERR(vswp, "vsw_create_dring(%lld): dring info failed\n",
		    ldcp->ldc_id);
		goto dring_fail_exit;
	} else {
		ASSERT(minfo.vaddr != 0);
		dp->pub_addr = minfo.vaddr;
	}

	dp->num_descriptors = vsw_ntxds;
	dp->descriptor_size = VSW_PUB_SIZE;
	dp->options = VIO_TX_DRING;
	dp->ncookies = 1;	/* guaranteed by ldc */

	/*
	 * create private portion of ring
	 */
	dp->priv_addr = (vsw_private_desc_t *)kmem_zalloc(
	    (sizeof (vsw_private_desc_t) * vsw_ntxds), KM_SLEEP);

	if (vsw_setup_ring(ldcp, dp)) {
		DERR(vswp, "%s: unable to setup ring", __func__);
		goto dring_fail_exit;
	}

	/* haven't used any descriptors yet */
	dp->end_idx = 0;
	dp->last_ack_recv = -1;

	/* bind dring to the channel */
	if ((ldc_mem_dring_bind(ldcp->ldc_handle, dp->handle,
	    LDC_SHADOW_MAP, LDC_MEM_RW,
	    &dp->cookie[0], &dp->ncookies)) != 0) {
		DERR(vswp, "vsw_create_dring: unable to bind to channel "
		    "%lld", ldcp->ldc_id);
		goto dring_fail_exit;
	}

	mutex_init(&dp->restart_lock, NULL, MUTEX_DRIVER, NULL);
	dp->restart_reqd = B_TRUE;

	/*
	 * Only ever create rings for outgoing lane. Link it onto
	 * end of list.
	 */
	WRITE_ENTER(&ldcp->lane_out.dlistrw);
	if (ldcp->lane_out.dringp == NULL) {
		D2(vswp, "vsw_create_dring: adding first outbound ring");
		ldcp->lane_out.dringp = dp;
	} else {
		tp = ldcp->lane_out.dringp;
		while (tp->next != NULL)
			tp = tp->next;

		tp->next = dp;
	}
	RW_EXIT(&ldcp->lane_out.dlistrw);

	return (dp);

dring_fail_exit:
	(void) ldc_mem_dring_destroy(dp->handle);

create_fail_exit:
	if (dp->priv_addr != NULL) {
		priv_addr = dp->priv_addr;
		for (i = 0; i < vsw_ntxds; i++) {
			if (priv_addr->memhandle != NULL)
				(void) ldc_mem_free_handle(
				    priv_addr->memhandle);
			priv_addr++;
		}
		kmem_free(dp->priv_addr,
		    (sizeof (vsw_private_desc_t) * vsw_ntxds));
	}
	mutex_destroy(&dp->dlock);

	kmem_free(dp, sizeof (dring_info_t));
	return (NULL);
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
	dring_info_t		*dp, *tp;
	vsw_t			*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	dp = kmem_zalloc(sizeof (dring_info_t), KM_SLEEP);

	mutex_init(&dp->dlock, NULL, MUTEX_DRIVER, NULL);

	/* no public section */
	dp->pub_addr = NULL;

	dp->priv_addr = kmem_zalloc(
	    (sizeof (vsw_private_desc_t) * vsw_ntxds), KM_SLEEP);

	dp->num_descriptors = vsw_ntxds;

	if (vsw_setup_ring(ldcp, dp)) {
		DERR(vswp, "%s: setup of ring failed", __func__);
		kmem_free(dp->priv_addr,
		    (sizeof (vsw_private_desc_t) * vsw_ntxds));
		mutex_destroy(&dp->dlock);
		kmem_free(dp, sizeof (dring_info_t));
		return;
	}

	/* haven't used any descriptors yet */
	dp->end_idx = 0;

	mutex_init(&dp->restart_lock, NULL, MUTEX_DRIVER, NULL);
	dp->restart_reqd = B_TRUE;

	/*
	 * Only ever create rings for outgoing lane. Link it onto
	 * end of list.
	 */
	WRITE_ENTER(&ldcp->lane_out.dlistrw);
	if (ldcp->lane_out.dringp == NULL) {
		D2(vswp, "%s: adding first outbound privring", __func__);
		ldcp->lane_out.dringp = dp;
	} else {
		tp = ldcp->lane_out.dringp;
		while (tp->next != NULL)
			tp = tp->next;

		tp->next = dp;
	}
	RW_EXIT(&ldcp->lane_out.dlistrw);

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Setup the descriptors in the dring. Returns 0 on success, 1 on
 * failure.
 */
int
vsw_setup_ring(vsw_ldc_t *ldcp, dring_info_t *dp)
{
	vnet_public_desc_t	*pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;
	vsw_t			*vswp = ldcp->ldc_vswp;
	uint64_t		*tmpp;
	uint64_t		offset = 0;
	uint32_t		ncookies = 0;
	static char		*name = "vsw_setup_ring";
	int			i, j, nc, rv;

	priv_addr = dp->priv_addr;
	pub_addr = dp->pub_addr;

	/* public section may be null but private should never be */
	ASSERT(priv_addr != NULL);

	/*
	 * Allocate the region of memory which will be used to hold
	 * the data the descriptors will refer to.
	 */
	dp->data_sz = (vsw_ntxds * VSW_RING_EL_DATA_SZ);
	dp->data_addr = kmem_alloc(dp->data_sz, KM_SLEEP);

	D2(vswp, "%s: allocated %lld bytes at 0x%llx\n", name,
	    dp->data_sz, dp->data_addr);

	tmpp = (uint64_t *)dp->data_addr;
	offset = VSW_RING_EL_DATA_SZ / sizeof (tmpp);

	/*
	 * Initialise some of the private and public (if they exist)
	 * descriptor fields.
	 */
	for (i = 0; i < vsw_ntxds; i++) {
		mutex_init(&priv_addr->dstate_lock, NULL, MUTEX_DRIVER, NULL);

		if ((ldc_mem_alloc_handle(ldcp->ldc_handle,
		    &priv_addr->memhandle)) != 0) {
			DERR(vswp, "%s: alloc mem handle failed", name);
			goto setup_ring_cleanup;
		}

		priv_addr->datap = (void *)tmpp;

		rv = ldc_mem_bind_handle(priv_addr->memhandle,
		    (caddr_t)priv_addr->datap, VSW_RING_EL_DATA_SZ,
		    LDC_SHADOW_MAP, LDC_MEM_R|LDC_MEM_W,
		    &(priv_addr->memcookie[0]), &ncookies);
		if (rv != 0) {
			DERR(vswp, "%s(%lld): ldc_mem_bind_handle failed "
			    "(rv %d)", name, ldcp->ldc_id, rv);
			goto setup_ring_cleanup;
		}
		priv_addr->bound = 1;

		D2(vswp, "%s: %d: memcookie 0 : addr 0x%llx : size 0x%llx",
		    name, i, priv_addr->memcookie[0].addr,
		    priv_addr->memcookie[0].size);

		if (ncookies >= (uint32_t)(VSW_MAX_COOKIES + 1)) {
			DERR(vswp, "%s(%lld) ldc_mem_bind_handle returned "
			    "invalid num of cookies (%d) for size 0x%llx",
			    name, ldcp->ldc_id, ncookies, VSW_RING_EL_DATA_SZ);

			goto setup_ring_cleanup;
		} else {
			for (j = 1; j < ncookies; j++) {
				rv = ldc_mem_nextcookie(priv_addr->memhandle,
				    &(priv_addr->memcookie[j]));
				if (rv != 0) {
					DERR(vswp, "%s: ldc_mem_nextcookie "
					    "failed rv (%d)", name, rv);
					goto setup_ring_cleanup;
				}
				D3(vswp, "%s: memcookie %d : addr 0x%llx : "
				    "size 0x%llx", name, j,
				    priv_addr->memcookie[j].addr,
				    priv_addr->memcookie[j].size);
			}

		}
		priv_addr->ncookies = ncookies;
		priv_addr->dstate = VIO_DESC_FREE;

		if (pub_addr != NULL) {

			/* link pub and private sides */
			priv_addr->descp = pub_addr;

			pub_addr->ncookies = priv_addr->ncookies;

			for (nc = 0; nc < pub_addr->ncookies; nc++) {
				bcopy(&priv_addr->memcookie[nc],
				    &pub_addr->memcookie[nc],
				    sizeof (ldc_mem_cookie_t));
			}

			pub_addr->hdr.dstate = VIO_DESC_FREE;
			pub_addr++;
		}

		/*
		 * move to next element in the dring and the next
		 * position in the data buffer.
		 */
		priv_addr++;
		tmpp += offset;
	}

	return (0);

setup_ring_cleanup:
	priv_addr = dp->priv_addr;

	for (j = 0; j < i; j++) {
		(void) ldc_mem_unbind_handle(priv_addr->memhandle);
		(void) ldc_mem_free_handle(priv_addr->memhandle);

		mutex_destroy(&priv_addr->dstate_lock);

		priv_addr++;
	}
	kmem_free(dp->data_addr, dp->data_sz);

	return (1);
}

/*
 * Searches the private section of a ring for a free descriptor,
 * starting at the location of the last free descriptor found
 * previously.
 *
 * Returns 0 if free descriptor is available, and updates state
 * of private descriptor to VIO_DESC_READY,  otherwise returns 1.
 *
 * FUTURE: might need to return contiguous range of descriptors
 * as dring info msg assumes all will be contiguous.
 */
static int
vsw_dring_find_free_desc(dring_info_t *dringp,
		vsw_private_desc_t **priv_p, int *idx)
{
	vsw_private_desc_t	*addr = NULL;
	int			num = vsw_ntxds;
	int			ret = 1;

	D1(NULL, "%s enter\n", __func__);

	ASSERT(dringp->priv_addr != NULL);

	D2(NULL, "%s: searching ring, dringp 0x%llx : start pos %lld",
	    __func__, dringp, dringp->end_idx);

	addr = (vsw_private_desc_t *)dringp->priv_addr + dringp->end_idx;

	mutex_enter(&addr->dstate_lock);
	if (addr->dstate == VIO_DESC_FREE) {
		addr->dstate = VIO_DESC_READY;
		*priv_p = addr;
		*idx = dringp->end_idx;
		dringp->end_idx = (dringp->end_idx + 1) % num;
		ret = 0;

	}
	mutex_exit(&addr->dstate_lock);

	/* ring full */
	if (ret == 1) {
		D2(NULL, "%s: no desp free: started at %d", __func__,
		    dringp->end_idx);
	}

	D1(NULL, "%s: exit\n", __func__);

	return (ret);
}

/*
 * Map from a dring identifier to the ring itself. Returns
 * pointer to ring or NULL if no match found.
 *
 * Should be called with dlistrw rwlock held as reader.
 */
static dring_info_t *
vsw_ident2dring(lane_t *lane, uint64_t ident)
{
	dring_info_t	*dp = NULL;

	if ((dp = lane->dringp) == NULL) {
		return (NULL);
	} else {
		if (dp->ident == ident)
			return (dp);

		while (dp != NULL) {
			if (dp->ident == ident)
				break;
			dp = dp->next;
		}
	}

	return (dp);
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

	lp->mtu = VSW_MTU;
	lp->addr_type = ADDR_TYPE_MAC;
	lp->xfer_mode = VIO_DRING_MODE_V1_0;
	lp->ack_freq = 0;	/* for shared mode */
	lp->seq_num = VNET_ISS;
}

/*
 * Verify that the attributes are acceptable.
 *
 * FUTURE: If some attributes are not acceptable, change them
 * our desired values.
 */
static int
vsw_check_attr(vnet_attr_msg_t *pkt, vsw_ldc_t *ldcp)
{
	int			ret = 0;
	struct ether_addr	ea;
	vsw_port_t		*port = ldcp->ldc_port;
	lane_t			*lp = &ldcp->lane_out;


	D1(NULL, "vsw_check_attr enter\n");

	if ((pkt->xfer_mode != VIO_DESC_MODE) &&
	    (pkt->xfer_mode != lp->xfer_mode)) {
		D2(NULL, "vsw_check_attr: unknown mode %x\n", pkt->xfer_mode);
		ret = 1;
	}

	/* Only support MAC addresses at moment. */
	if ((pkt->addr_type != ADDR_TYPE_MAC) || (pkt->addr == 0)) {
		D2(NULL, "vsw_check_attr: invalid addr_type %x, "
		    "or address 0x%llx\n", pkt->addr_type, pkt->addr);
		ret = 1;
	}

	/*
	 * MAC address supplied by device should match that stored
	 * in the vsw-port OBP node. Need to decide what to do if they
	 * don't match, for the moment just warn but don't fail.
	 */
	vnet_macaddr_ultostr(pkt->addr, ea.ether_addr_octet);
	if (ether_cmp(&ea, &port->p_macaddr) != 0) {
		DERR(NULL, "vsw_check_attr: device supplied address "
		    "0x%llx doesn't match node address 0x%llx\n",
		    pkt->addr, port->p_macaddr);
	}

	/*
	 * Ack freq only makes sense in pkt mode, in shared
	 * mode the ring descriptors say whether or not to
	 * send back an ACK.
	 */
	if ((VSW_VER_EQ(ldcp, 1, 2) &&
	    (ldcp->lane_in.xfer_mode & VIO_DRING_MODE_V1_2)) ||
	    (VSW_VER_LT(ldcp, 1, 2) &&
	    (ldcp->lane_in.xfer_mode == VIO_DRING_MODE_V1_0))) {
		if (pkt->ack_freq > 0) {
			D2(NULL, "vsw_check_attr: non zero ack freq "
			    " in SHM mode\n");
			ret = 1;
		}
	}

	/*
	 * Note: for the moment we only support ETHER
	 * frames. This may change in the future.
	 */
	if ((pkt->mtu > VSW_MTU) || (pkt->mtu <= 0)) {
		D2(NULL, "vsw_check_attr: invalid MTU (0x%llx)\n",
		    pkt->mtu);
		ret = 1;
	}

	D1(NULL, "vsw_check_attr exit\n");

	return (ret);
}

/*
 * Returns 1 if there is a problem, 0 otherwise.
 */
static int
vsw_check_dring_info(vio_dring_reg_msg_t *pkt)
{
	_NOTE(ARGUNUSED(pkt))

	int	ret = 0;

	D1(NULL, "vsw_check_dring_info enter\n");

	if ((pkt->num_descriptors == 0) ||
	    (pkt->descriptor_size == 0) ||
	    (pkt->ncookies != 1)) {
		DERR(NULL, "vsw_check_dring_info: invalid dring msg");
		ret = 1;
	}

	D1(NULL, "vsw_check_dring_info exit\n");

	return (ret);
}

/*
 * Returns 1 if two memory cookies match. Otherwise returns 0.
 */
static int
vsw_mem_cookie_match(ldc_mem_cookie_t *m1, ldc_mem_cookie_t *m2)
{
	if ((m1->addr != m2->addr) ||
	    (m2->size != m2->size)) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * Returns 1 if ring described in reg message matches that
 * described by dring_info structure. Otherwise returns 0.
 */
static int
vsw_dring_match(dring_info_t *dp, vio_dring_reg_msg_t *msg)
{
	if ((msg->descriptor_size != dp->descriptor_size) ||
	    (msg->num_descriptors != dp->num_descriptors) ||
	    (msg->ncookies != dp->ncookies) ||
	    !(vsw_mem_cookie_match(&msg->cookie[0], &dp->cookie[0]))) {
		return (0);
	} else {
		return (1);
	}

}

static caddr_t
vsw_print_ethaddr(uint8_t *a, char *ebuf)
{
	(void) sprintf(ebuf, "%x:%x:%x:%x:%x:%x",
	    a[0], a[1], a[2], a[3], a[4], a[5]);
	return (ebuf);
}

/*
 * Reset and free all the resources associated with
 * the channel.
 */
static void
vsw_free_lane_resources(vsw_ldc_t *ldcp, uint64_t dir)
{
	dring_info_t		*dp, *dpp;
	lane_t			*lp = NULL;
	int			rv = 0;

	ASSERT(ldcp != NULL);

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

	if (lp->dringp) {
		if (dir == INBOUND) {
			WRITE_ENTER(&lp->dlistrw);
			dp = lp->dringp;
			while (dp != NULL) {
				dpp = dp->next;
				if (dp->handle != NULL)
					(void) ldc_mem_dring_unmap(dp->handle);
				kmem_free(dp, sizeof (dring_info_t));
				dp = dpp;
			}
			RW_EXIT(&lp->dlistrw);
		} else {
			/*
			 * unbind, destroy exported dring, free dring struct
			 */
			WRITE_ENTER(&lp->dlistrw);
			dp = lp->dringp;
			rv = vsw_free_ring(dp);
			RW_EXIT(&lp->dlistrw);
		}
		if (rv == 0) {
			lp->dringp = NULL;
		}
	}

	D1(ldcp->ldc_vswp, "%s (%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Free ring and all associated resources.
 *
 * Should be called with dlistrw rwlock held as writer.
 */
static int
vsw_free_ring(dring_info_t *dp)
{
	vsw_private_desc_t	*paddr = NULL;
	dring_info_t		*dpp;
	int			i, rv = 1;

	while (dp != NULL) {
		mutex_enter(&dp->dlock);
		dpp = dp->next;
		if (dp->priv_addr != NULL) {
			/*
			 * First unbind and free the memory handles
			 * stored in each descriptor within the ring.
			 */
			for (i = 0; i < vsw_ntxds; i++) {
				paddr = (vsw_private_desc_t *)
				    dp->priv_addr + i;
				if (paddr->memhandle != NULL) {
					if (paddr->bound == 1) {
						rv = ldc_mem_unbind_handle(
						    paddr->memhandle);

						if (rv != 0) {
							DERR(NULL, "error "
							"unbinding handle for "
							"ring 0x%llx at pos %d",
							    dp, i);
							mutex_exit(&dp->dlock);
							return (rv);
						}
						paddr->bound = 0;
					}

					rv = ldc_mem_free_handle(
					    paddr->memhandle);
					if (rv != 0) {
						DERR(NULL, "error freeing "
						    "handle for ring 0x%llx "
						    "at pos %d", dp, i);
						mutex_exit(&dp->dlock);
						return (rv);
					}
					paddr->memhandle = NULL;
				}
				mutex_destroy(&paddr->dstate_lock);
			}
			kmem_free(dp->priv_addr,
			    (sizeof (vsw_private_desc_t) * vsw_ntxds));
		}

		/*
		 * Now unbind and destroy the ring itself.
		 */
		if (dp->handle != NULL) {
			(void) ldc_mem_dring_unbind(dp->handle);
			(void) ldc_mem_dring_destroy(dp->handle);
		}

		if (dp->data_addr != NULL) {
			kmem_free(dp->data_addr, dp->data_sz);
		}

		mutex_exit(&dp->dlock);
		mutex_destroy(&dp->dlock);
		mutex_destroy(&dp->restart_lock);
		kmem_free(dp, sizeof (dring_info_t));

		dp = dpp;
	}
	return (0);
}

/*
 * vsw_ldc_rx_worker -- A per LDC worker thread to receive data.
 * This thread is woken up by the LDC interrupt handler to process
 * LDC packets and receive data.
 */
static void
vsw_ldc_rx_worker(void *arg)
{
	callb_cpr_t	cprinfo;
	vsw_ldc_t *ldcp = (vsw_ldc_t *)arg;
	vsw_t *vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	CALLB_CPR_INIT(&cprinfo, &ldcp->rx_thr_lock, callb_generic_cpr,
	    "vsw_rx_thread");
	mutex_enter(&ldcp->rx_thr_lock);
	ldcp->rx_thr_flags |= VSW_WTHR_RUNNING;
	while (!(ldcp->rx_thr_flags & VSW_WTHR_STOP)) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		/*
		 * Wait until the data is received or a stop
		 * request is received.
		 */
		while (!(ldcp->rx_thr_flags &
		    (VSW_WTHR_DATARCVD | VSW_WTHR_STOP))) {
			cv_wait(&ldcp->rx_thr_cv, &ldcp->rx_thr_lock);
		}
		CALLB_CPR_SAFE_END(&cprinfo, &ldcp->rx_thr_lock)

		/*
		 * First process the stop request.
		 */
		if (ldcp->rx_thr_flags & VSW_WTHR_STOP) {
			D2(vswp, "%s(%lld):Rx thread stopped\n",
			    __func__, ldcp->ldc_id);
			break;
		}
		ldcp->rx_thr_flags &= ~VSW_WTHR_DATARCVD;
		mutex_exit(&ldcp->rx_thr_lock);
		D1(vswp, "%s(%lld):calling vsw_process_pkt\n",
		    __func__, ldcp->ldc_id);
		mutex_enter(&ldcp->ldc_cblock);
		vsw_process_pkt(ldcp);
		mutex_exit(&ldcp->ldc_cblock);
		mutex_enter(&ldcp->rx_thr_lock);
	}

	/*
	 * Update the run status and wakeup the thread that
	 * has sent the stop request.
	 */
	ldcp->rx_thr_flags &= ~VSW_WTHR_RUNNING;
	cv_signal(&ldcp->rx_thr_cv);
	CALLB_CPR_EXIT(&cprinfo);
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
	thread_exit();
}

/* vsw_stop_rx_thread -- Co-ordinate with receive thread to stop it */
static void
vsw_stop_rx_thread(vsw_ldc_t *ldcp)
{
	vsw_t *vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the receive thread stops.
	 */
	mutex_enter(&ldcp->rx_thr_lock);
	if (ldcp->rx_thr_flags & VSW_WTHR_RUNNING) {
		ldcp->rx_thr_flags |= VSW_WTHR_STOP;
		cv_signal(&ldcp->rx_thr_cv);
		while (ldcp->rx_thr_flags & VSW_WTHR_RUNNING) {
			cv_wait(&ldcp->rx_thr_cv, &ldcp->rx_thr_lock);
		}
	}
	mutex_exit(&ldcp->rx_thr_lock);
	ldcp->rx_thread = NULL;
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
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
	ldcp->tx_thr_flags |= VSW_WTHR_RUNNING;
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
	ldcp->tx_thr_flags &= ~VSW_WTHR_RUNNING;
	cv_signal(&ldcp->tx_thr_cv);
	CALLB_CPR_EXIT(&cprinfo);
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
	thread_exit();
}

/* vsw_stop_tx_thread -- Co-ordinate with receive thread to stop it */
static void
vsw_stop_tx_thread(vsw_ldc_t *ldcp)
{
	vsw_t *vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld):enter\n", __func__, ldcp->ldc_id);
	/*
	 * Send a stop request by setting the stop flag and
	 * wait until the receive thread stops.
	 */
	mutex_enter(&ldcp->tx_thr_lock);
	if (ldcp->tx_thr_flags & VSW_WTHR_RUNNING) {
		ldcp->tx_thr_flags |= VSW_WTHR_STOP;
		cv_signal(&ldcp->tx_thr_cv);
		while (ldcp->tx_thr_flags & VSW_WTHR_RUNNING) {
			cv_wait(&ldcp->tx_thr_cv, &ldcp->tx_thr_lock);
		}
	}
	mutex_exit(&ldcp->tx_thr_lock);
	ldcp->tx_thread = NULL;
	D1(vswp, "%s(%lld):exit\n", __func__, ldcp->ldc_id);
}

/* vsw_reclaim_dring -- reclaim descriptors */
static int
vsw_reclaim_dring(dring_info_t *dp, int start)
{
	int i, j, len;
	vsw_private_desc_t *priv_addr;
	vnet_public_desc_t *pub_addr;

	pub_addr = (vnet_public_desc_t *)dp->pub_addr;
	priv_addr = (vsw_private_desc_t *)dp->priv_addr;
	len = dp->num_descriptors;

	D2(NULL, "%s: start index %ld\n", __func__, start);

	j = 0;
	for (i = start; j < len; i = (i + 1) % len, j++) {
		pub_addr = (vnet_public_desc_t *)dp->pub_addr + i;
		priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;

		mutex_enter(&priv_addr->dstate_lock);
		if (pub_addr->hdr.dstate != VIO_DESC_DONE) {
			mutex_exit(&priv_addr->dstate_lock);
			break;
		}
		pub_addr->hdr.dstate = VIO_DESC_FREE;
		priv_addr->dstate = VIO_DESC_FREE;
		/* clear all the fields */
		priv_addr->datalen = 0;
		pub_addr->hdr.ack = 0;
		mutex_exit(&priv_addr->dstate_lock);

		D3(NULL, "claiming descp:%d pub state:0x%llx priv state 0x%llx",
		    i, pub_addr->hdr.dstate, priv_addr->dstate);
	}
	return (j);
}

/*
 * Debugging routines
 */
static void
display_state(void)
{
	vsw_t		*vswp;
	vsw_port_list_t	*plist;
	vsw_port_t 	*port;
	vsw_ldc_list_t	*ldcl;
	vsw_ldc_t 	*ldcp;
	extern vsw_t 	*vsw_head;

	cmn_err(CE_NOTE, "***** system state *****");

	for (vswp = vsw_head; vswp; vswp = vswp->next) {
		plist = &vswp->plist;
		READ_ENTER(&plist->lockrw);
		cmn_err(CE_CONT, "vsw instance %d has %d ports attached\n",
		    vswp->instance, plist->num_ports);

		for (port = plist->head; port != NULL; port = port->p_next) {
			ldcl = &port->p_ldclist;
			cmn_err(CE_CONT, "port %d : %d ldcs attached\n",
			    port->p_instance, ldcl->num_ldcs);
			READ_ENTER(&ldcl->lockrw);
			ldcp = ldcl->head;
			for (; ldcp != NULL; ldcp = ldcp->ldc_next) {
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
			RW_EXIT(&ldcl->lockrw);
		}
		RW_EXIT(&plist->lockrw);
	}
	cmn_err(CE_NOTE, "***** system state *****");
}

static void
display_lane(lane_t *lp)
{
	dring_info_t	*drp;

	cmn_err(CE_CONT, "ver 0x%x:0x%x : state %lx : mtu 0x%lx\n",
	    lp->ver_major, lp->ver_minor, lp->lstate, lp->mtu);
	cmn_err(CE_CONT, "addr_type %d : addr 0x%lx : xmode %d\n",
	    lp->addr_type, lp->addr, lp->xfer_mode);
	cmn_err(CE_CONT, "dringp 0x%lx\n", (uint64_t)lp->dringp);

	cmn_err(CE_CONT, "Dring info:\n");
	for (drp = lp->dringp; drp != NULL; drp = drp->next) {
		cmn_err(CE_CONT, "\tnum_desc %u : dsize %u\n",
		    drp->num_descriptors, drp->descriptor_size);
		cmn_err(CE_CONT, "\thandle 0x%lx\n", drp->handle);
		cmn_err(CE_CONT, "\tpub_addr 0x%lx : priv_addr 0x%lx\n",
		    (uint64_t)drp->pub_addr, (uint64_t)drp->priv_addr);
		cmn_err(CE_CONT, "\tident 0x%lx : end_idx %lu\n",
		    drp->ident, drp->end_idx);
		display_ring(drp);
	}
}

static void
display_ring(dring_info_t *dringp)
{
	uint64_t		i;
	uint64_t		priv_count = 0;
	uint64_t		pub_count = 0;
	vnet_public_desc_t	*pub_addr = NULL;
	vsw_private_desc_t	*priv_addr = NULL;

	for (i = 0; i < vsw_ntxds; i++) {
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
