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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * Function prototypes.
 */
static	int vsw_attach(dev_info_t *, ddi_attach_cmd_t);
static	int vsw_detach(dev_info_t *, ddi_detach_cmd_t);
static	int vsw_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	void vsw_get_md_properties(vsw_t *vswp);
static	int vsw_get_physaddr(vsw_t *);
static	int vsw_setup_layer2(vsw_t *);
static	int vsw_setup_layer3(vsw_t *);

/* MAC Ring table functions. */
static void vsw_mac_ring_tbl_init(vsw_t *vswp);
static void vsw_mac_ring_tbl_destroy(vsw_t *vswp);
static void vsw_queue_worker(vsw_mac_ring_t *rrp);
static void vsw_queue_stop(vsw_queue_t *vqp);
static vsw_queue_t *vsw_queue_create();
static void vsw_queue_destroy(vsw_queue_t *vqp);

/* MAC layer routines */
static mac_resource_handle_t vsw_mac_ring_add_cb(void *arg,
		mac_resource_t *mrp);
static	int vsw_get_hw_maddr(vsw_t *);
static	int vsw_set_hw(vsw_t *, vsw_port_t *);
static	int vsw_set_hw_promisc(vsw_t *, vsw_port_t *);
static	int vsw_unset_hw(vsw_t *, vsw_port_t *);
static	int vsw_unset_hw_promisc(vsw_t *, vsw_port_t *);
static	int vsw_reconfig_hw(vsw_t *);
static int vsw_mac_attach(vsw_t *vswp);
static void vsw_mac_detach(vsw_t *vswp);

static void vsw_rx_queue_cb(void *, mac_resource_handle_t, mblk_t *);
static void vsw_rx_cb(void *, mac_resource_handle_t, mblk_t *);
static mblk_t *vsw_tx_msg(vsw_t *, mblk_t *);
static int vsw_mac_register(vsw_t *);
static int vsw_mac_unregister(vsw_t *);
static int vsw_m_stat(void *, uint_t, uint64_t *);
static void vsw_m_stop(void *arg);
static int vsw_m_start(void *arg);
static int vsw_m_unicst(void *arg, const uint8_t *);
static int vsw_m_multicst(void *arg, boolean_t, const uint8_t *);
static int vsw_m_promisc(void *arg, boolean_t);
static mblk_t *vsw_m_tx(void *arg, mblk_t *);

/* MDEG routines */
static	void vsw_mdeg_register(vsw_t *vswp);
static	void vsw_mdeg_unregister(vsw_t *vswp);
static	int vsw_mdeg_cb(void *cb_argp, mdeg_result_t *);

/* Port add/deletion routines */
static	int vsw_port_add(vsw_t *vswp, md_t *mdp, mde_cookie_t *node);
static	int vsw_port_attach(vsw_t *vswp, int p_instance,
	uint64_t *ldcids, int nids, struct ether_addr *macaddr);
static	int vsw_detach_ports(vsw_t *vswp);
static	int vsw_port_detach(vsw_t *vswp, int p_instance);
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
static	vsw_port_t *vsw_lookup_port(vsw_t *vswp, int p_instance);
static	int vsw_plist_del_node(vsw_t *, vsw_port_t *port);

/* Interrupt routines */
static	uint_t vsw_ldc_cb(uint64_t cb, caddr_t arg);

/* Handshake routines */
static	void vsw_restart_ldc(vsw_ldc_t *);
static	void vsw_restart_handshake(vsw_ldc_t *);
static	void vsw_handle_reset(vsw_ldc_t *);
static	int vsw_check_flag(vsw_ldc_t *, int, uint64_t);
static	void vsw_next_milestone(vsw_ldc_t *);
static	int vsw_supported_version(vio_ver_msg_t *);

/* Data processing routines */
static void vsw_process_pkt(void *);
static void vsw_dispatch_ctrl_task(vsw_ldc_t *, void *, vio_msg_tag_t);
static void vsw_process_ctrl_pkt(void *);
static void vsw_process_ctrl_ver_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_attr_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_mcst_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_reg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_dring_unreg_pkt(vsw_ldc_t *, void *);
static void vsw_process_ctrl_rdx_pkt(vsw_ldc_t *, void *);
static void vsw_process_data_pkt(vsw_ldc_t *, void *, vio_msg_tag_t);
static void vsw_process_data_dring_pkt(vsw_ldc_t *, void *);
static void vsw_process_data_raw_pkt(vsw_ldc_t *, void *);
static void vsw_process_data_ibnd_pkt(vsw_ldc_t *, void *);
static void vsw_process_err_pkt(vsw_ldc_t *, void *, vio_msg_tag_t);

/* Switching/data transmit routines */
static	void vsw_switch_l2_frame(vsw_t *vswp, mblk_t *mp, int caller,
	    vsw_port_t *port, mac_resource_handle_t);
static	void vsw_switch_l3_frame(vsw_t *vswp, mblk_t *mp, int caller,
	    vsw_port_t *port, mac_resource_handle_t);
static	int vsw_forward_all(vsw_t *vswp, mblk_t *mp, int caller,
	    vsw_port_t *port);
static	int vsw_forward_grp(vsw_t *vswp, mblk_t *mp, int caller,
	    vsw_port_t *port);
static	int vsw_portsend(vsw_port_t *, mblk_t *);
static	int vsw_dringsend(vsw_ldc_t *, mblk_t *);
static	int vsw_descrsend(vsw_ldc_t *, mblk_t *);

/* Packet creation routines */
static void vsw_send_ver(void *);
static void vsw_send_attr(vsw_ldc_t *);
static vio_dring_reg_msg_t *vsw_create_dring_info_pkt(vsw_ldc_t *);
static void vsw_send_dring_info(vsw_ldc_t *);
static void vsw_send_rdx(vsw_ldc_t *);

static void vsw_send_msg(vsw_ldc_t *, void *, int);

/* Forwarding database (FDB) routines */
static	int vsw_add_fdb(vsw_t *vswp, vsw_port_t *port);
static	int vsw_del_fdb(vsw_t *vswp, vsw_port_t *port);
static	vsw_port_t *vsw_lookup_fdb(vsw_t *vswp, struct ether_header *);
static	int vsw_add_rem_mcst(vnet_mcast_msg_t *, vsw_port_t *);
static	int vsw_add_mcst(vsw_t *, uint8_t, uint64_t, void *);
static	int vsw_del_mcst(vsw_t *, uint8_t, uint64_t, void *);
static	void vsw_del_addr(uint8_t, void *, uint64_t);
static	void vsw_del_mcst_port(vsw_port_t *);
static	void vsw_del_mcst_vsw(vsw_t *);

/* Dring routines */
static dring_info_t *vsw_create_dring(vsw_ldc_t *);
static void vsw_create_privring(vsw_ldc_t *);
static int vsw_setup_ring(vsw_ldc_t *ldcp, dring_info_t *dp);
static int vsw_dring_find_free_desc(dring_info_t *, vsw_private_desc_t **,
    int *);
static dring_info_t *vsw_ident2dring(lane_t *, uint64_t);

static void vsw_set_lane_attr(vsw_t *, lane_t *);
static int vsw_check_attr(vnet_attr_msg_t *, vsw_port_t *);
static int vsw_dring_match(dring_info_t *dp, vio_dring_reg_msg_t *msg);
static int vsw_mem_cookie_match(ldc_mem_cookie_t *, ldc_mem_cookie_t *);
static int vsw_check_dring_info(vio_dring_reg_msg_t *);

/* Misc support routines */
static	caddr_t vsw_print_ethaddr(uint8_t *addr, char *ebuf);
static void vsw_free_lane_resources(vsw_ldc_t *, uint64_t);
static int vsw_free_ring(dring_info_t *);


/* Debugging routines */
static void dump_flags(uint64_t);
static void display_state(void);
static void display_lane(lane_t *);
static void display_ring(dring_info_t *);

int	vsw_num_handshakes = 3;		/* # of handshake attempts */
int	vsw_wretries = 100;		/* # of write attempts */
int	vsw_chain_len = 150;		/* max # of mblks in msg chain */
int	vsw_desc_delay = 0;		/* delay in us */
int	vsw_read_attempts = 5;		/* # of reads of descriptor */

uint32_t	vsw_mblk_size = VSW_MBLK_SIZE;
uint32_t	vsw_num_mblks = VSW_NUM_MBLKS;


/*
 * mode specific frame switching function
 */
void		(*vsw_switch_frame)(vsw_t *, mblk_t *, int, vsw_port_t *,
			mac_resource_handle_t);

static	mac_callbacks_t	vsw_m_callbacks = {
	0,
	vsw_m_stat,
	vsw_m_start,
	vsw_m_stop,
	vsw_m_promisc,
	vsw_m_multicst,
	vsw_m_unicst,
	vsw_m_tx,
	NULL,
	NULL,
	NULL
};

static	struct	cb_ops	vsw_cb_ops = {
	nulldev,			/* cb_open */
	nulldev,			/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read */
	nodev,				/* cb_write */
	nodev,				/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_chpoll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* cb_stream */
	D_MP,				/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static	struct	dev_ops	vsw_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	vsw_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vsw_attach,		/* devo_attach */
	vsw_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&vsw_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	ddi_power		/* devo_power */
};

extern	struct	mod_ops	mod_driverops;
static struct modldrv vswmodldrv = {
	&mod_driverops,
	"sun4v Virtual Switch Driver %I%",
	&vsw_ops,
};

#define	LDC_ENTER_LOCK(ldcp)	\
				mutex_enter(&((ldcp)->ldc_cblock));\
				mutex_enter(&((ldcp)->ldc_txlock));
#define	LDC_EXIT_LOCK(ldcp)	\
				mutex_exit(&((ldcp)->ldc_txlock));\
				mutex_exit(&((ldcp)->ldc_cblock));

/* Driver soft state ptr  */
static void	*vsw_state;

/*
 * Linked list of "vsw_t" structures - one per instance.
 */
vsw_t		*vsw_head = NULL;
krwlock_t	vsw_rw;

/*
 * Property names
 */
static char vdev_propname[] = "virtual-device";
static char vsw_propname[] = "virtual-network-switch";
static char physdev_propname[] = "vsw-phys-dev";
static char smode_propname[] = "vsw-switch-mode";
static char macaddr_propname[] = "local-mac-address";
static char remaddr_propname[] = "remote-mac-address";
static char ldcids_propname[] = "ldc-ids";
static char chan_propname[] = "channel-endpoint";
static char id_propname[] = "id";
static char reg_propname[] = "reg";

/* supported versions */
static	ver_sup_t	vsw_versions[] = { {1, 0} };

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to 'virtual-device-port' nodes identified by their
 * 'id' property.
 */
static md_prop_match_t vport_prop_match[] = {
	{ MDET_PROP_VAL,    "id"   },
	{ MDET_LIST_END,    NULL    }
};

static mdeg_node_match_t vport_match = { "virtual-device-port",
						vport_prop_match };

/*
 * Specification of an MD node passed to the MDEG to filter any
 * 'vport' nodes that do not belong to the specified node. This
 * template is copied for each vsw instance and filled in with
 * the appropriate 'cfg-handle' value before being passed to the MDEG.
 */
static mdeg_prop_spec_t vsw_prop_template[] = {
	{ MDET_PROP_STR,    "name",		vsw_propname },
	{ MDET_PROP_VAL,    "cfg-handle",	NULL	},
	{ MDET_LIST_END,    NULL,		NULL	}
};

#define	VSW_SET_MDEG_PROP_INST(specp, val)	(specp)[1].ps_val = (val);

/*
 * From /etc/system enable/disable thread per ring. This is a mode
 * selection that is done a vsw driver attach time.
 */
boolean_t vsw_multi_ring_enable = B_FALSE;
int vsw_mac_rx_rings = VSW_MAC_RX_RINGS;

/*
 * Print debug messages - set to 0x1f to enable all msgs
 * or 0x0 to turn all off.
 */
int vswdbg = 0x0;

/*
 * debug levels:
 * 0x01:	Function entry/exit tracing
 * 0x02:	Internal function messages
 * 0x04:	Verbose internal messages
 * 0x08:	Warning messages
 * 0x10:	Error messages
 */

static void
vswdebug(vsw_t *vswp, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	if (vswp == NULL)
		cmn_err(CE_CONT, "%s\n", buf);
	else
		cmn_err(CE_CONT, "vsw%d: %s\n", vswp->instance, buf);
}

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

#ifdef DEBUG

#define	D1		\
if (vswdbg & 0x01)	\
	vswdebug

#define	D2		\
if (vswdbg & 0x02)	\
	vswdebug

#define	D3		\
if (vswdbg & 0x04)	\
	vswdebug

#define	DWARN		\
if (vswdbg & 0x08)	\
	vswdebug

#define	DERR		\
if (vswdbg & 0x10)	\
	vswdebug

#else

#define	DERR		if (0)	vswdebug
#define	DWARN		if (0)	vswdebug
#define	D1		if (0)	vswdebug
#define	D2		if (0)	vswdebug
#define	D3		if (0)	vswdebug

#endif	/* DEBUG */

static struct modlinkage modlinkage = {
	MODREV_1,
	&vswmodldrv,
	NULL
};

int
_init(void)
{
	int status;

	rw_init(&vsw_rw, NULL, RW_DRIVER, NULL);

	status = ddi_soft_state_init(&vsw_state, sizeof (vsw_t), 1);
	if (status != 0) {
		return (status);
	}

	mac_init_ops(&vsw_ops, "vsw");
	status = mod_install(&modlinkage);
	if (status != 0) {
		ddi_soft_state_fini(&vsw_state);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status != 0)
		return (status);
	mac_fini_ops(&vsw_ops);
	ddi_soft_state_fini(&vsw_state);

	rw_destroy(&vsw_rw);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
vsw_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	vsw_t		*vswp;
	int		instance, i;
	char		hashname[MAXNAMELEN];
	char		qname[TASKQ_NAMELEN];
	int		rv = 1;
	enum		{ PROG_init = 0x00,
				PROG_if_lock = 0x01,
				PROG_fdb = 0x02,
				PROG_mfdb = 0x04,
				PROG_report_dev = 0x08,
				PROG_plist = 0x10,
				PROG_taskq = 0x20}
			progress;

	progress = PROG_init;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	case DDI_PM_RESUME:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vsw_state, instance) != DDI_SUCCESS) {
		DERR(NULL, "vsw%d: ddi_soft_state_zalloc failed", instance);
		return (DDI_FAILURE);
	}
	vswp = ddi_get_soft_state(vsw_state, instance);

	if (vswp == NULL) {
		DERR(NULL, "vsw%d: ddi_get_soft_state failed", instance);
		goto vsw_attach_fail;
	}

	vswp->dip = dip;
	vswp->instance = instance;
	ddi_set_driver_private(dip, (caddr_t)vswp);

	rw_init(&vswp->if_lockrw, NULL, RW_DRIVER, NULL);
	progress |= PROG_if_lock;

	/*
	 * Get the various properties such as physical device name
	 * (vsw-phys-dev), switch mode etc from the MD.
	 */
	vsw_get_md_properties(vswp);

	/* setup the unicast forwarding database  */
	(void) snprintf(hashname, MAXNAMELEN, "vsw_unicst_table-%d",
							vswp->instance);
	D2(vswp, "creating unicast hash table (%s)...", hashname);
	vswp->fdb = mod_hash_create_ptrhash(hashname, VSW_NCHAINS,
		mod_hash_null_valdtor, sizeof (void *));

	progress |= PROG_fdb;

	/* setup the multicast fowarding database */
	(void) snprintf(hashname, MAXNAMELEN, "vsw_mcst_table-%d",
							vswp->instance);
	D2(vswp, "creating multicast hash table %s)...", hashname);
	rw_init(&vswp->mfdbrw, NULL, RW_DRIVER, NULL);
	vswp->mfdb = mod_hash_create_ptrhash(hashname, VSW_NCHAINS,
			mod_hash_null_valdtor, sizeof (void *));

	progress |= PROG_mfdb;

	/*
	 * create lock protecting list of multicast addresses
	 * which could come via m_multicst() entry point when plumbed.
	 */
	mutex_init(&vswp->mca_lock, NULL, MUTEX_DRIVER, NULL);
	vswp->mcap = NULL;

	ddi_report_dev(vswp->dip);

	progress |= PROG_report_dev;

	WRITE_ENTER(&vsw_rw);
	vswp->next = vsw_head;
	vsw_head = vswp;
	RW_EXIT(&vsw_rw);

	/* setup the port list */
	rw_init(&vswp->plist.lockrw, NULL, RW_DRIVER, NULL);
	vswp->plist.head = NULL;

	progress |= PROG_plist;

	/*
	 * Create the taskq which will process all the VIO
	 * control messages.
	 */
	(void) snprintf(qname, TASKQ_NAMELEN, "vsw_taskq%d", vswp->instance);
	if ((vswp->taskq_p = ddi_taskq_create(vswp->dip, qname, 1,
					TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "Unable to create task queue");
		goto vsw_attach_fail;
	}

	progress |= PROG_taskq;

	/* select best switching mode */
	for (i = 0; i < vswp->smode_num; i++) {
		vswp->smode_idx = i;
		switch (vswp->smode[i]) {
		case VSW_LAYER2:
		case VSW_LAYER2_PROMISC:
			rv = vsw_setup_layer2(vswp);
			break;

		case VSW_LAYER3:
			rv = vsw_setup_layer3(vswp);
			break;

		default:
			DERR(vswp, "unknown switch mode");
			rv = 1;
			break;
		}

		if (rv == 0)
			break;
	}

	if (rv == 1) {
		cmn_err(CE_WARN, "Unable to setup switching mode");
		goto vsw_attach_fail;
	}

	D2(vswp, "Operating in mode %d", vswp->smode[vswp->smode_idx]);

	/*
	 * Register with the MAC layer as a network device so
	 * we can be plumbed if desired.
	 *
	 * Do this in both layer 2 and layer 3 mode.
	 */
	vswp->if_state &= ~VSW_IF_UP;
	if (vswp->mdprops & (VSW_MD_MACADDR | VSW_DEV_MACADDR)) {
		if (vsw_mac_register(vswp) != 0) {
			cmn_err(CE_WARN, "Unable to register as provider "
				" with MAC layer, continuing with attach");
		}
	}

	/* prevent auto-detaching */
	if (ddi_prop_update_int(DDI_DEV_T_NONE, vswp->dip,
				DDI_NO_AUTODETACH, 1) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "Unable to set \"%s\" property for "
			"instance %u", DDI_NO_AUTODETACH, instance);
	}

	/*
	 * Now we have everything setup, register for MD change
	 * events.
	 */
	vsw_mdeg_register(vswp);

	return (DDI_SUCCESS);

vsw_attach_fail:
	DERR(NULL, "vsw_attach: failed");

	if (progress & PROG_taskq)
		ddi_taskq_destroy(vswp->taskq_p);

	if (progress & PROG_plist)
		rw_destroy(&vswp->plist.lockrw);

	if (progress & PROG_report_dev) {
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&vswp->mca_lock);
	}

	if (progress & PROG_mfdb) {
		mod_hash_destroy_hash(vswp->mfdb);
		vswp->mfdb = NULL;
		rw_destroy(&vswp->mfdbrw);
	}

	if (progress & PROG_fdb) {
		mod_hash_destroy_hash(vswp->fdb);
		vswp->fdb = NULL;
	}

	if (progress & PROG_if_lock)
		rw_destroy(&vswp->if_lockrw);

	ddi_soft_state_free(vsw_state, instance);
	return (DDI_FAILURE);
}

static int
vsw_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vio_mblk_pool_t		*poolp, *npoolp;
	vsw_t			**vswpp, *vswp;
	int 			instance;

	instance = ddi_get_instance(dip);
	vswp = ddi_get_soft_state(vsw_state, instance);

	if (vswp == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	D2(vswp, "detaching instance %d", instance);

	if (vswp->mdprops & (VSW_MD_MACADDR | VSW_DEV_MACADDR)) {
		if (vsw_mac_unregister(vswp) != 0) {
			cmn_err(CE_WARN, "Unable to detach from MAC layer");
			return (DDI_FAILURE);
		}
		rw_destroy(&vswp->if_lockrw);
	}

	vsw_mdeg_unregister(vswp);

	/* remove mac layer callback */
	if ((vswp->mh != NULL) && (vswp->mrh != NULL)) {
		mac_rx_remove(vswp->mh, vswp->mrh);
		vswp->mrh = NULL;
	}

	if (vsw_detach_ports(vswp) != 0) {
		cmn_err(CE_WARN, "Unable to detach ports");
		return (DDI_FAILURE);
	}

	/*
	 * Now that the ports have been deleted, stop and close
	 * the physical device.
	 */
	if (vswp->mh != NULL) {
		if (vswp->mstarted)
			mac_stop(vswp->mh);
		if (vswp->mresources)
			mac_resource_set(vswp->mh, NULL, NULL);
		mac_close(vswp->mh);

		vswp->mh = NULL;
		vswp->txinfo = NULL;
	}

	/*
	 * Destroy any free pools that may still exist.
	 */
	poolp = vswp->rxh;
	while (poolp != NULL) {
		npoolp = vswp->rxh = poolp->nextp;
		if (vio_destroy_mblks(poolp) != 0) {
			vswp->rxh = poolp;
			return (DDI_FAILURE);
		}
		poolp = npoolp;
	}

	/*
	 * Remove this instance from any entries it may be on in
	 * the hash table by using the list of addresses maintained
	 * in the vsw_t structure.
	 */
	vsw_del_mcst_vsw(vswp);

	vswp->mcap = NULL;
	mutex_destroy(&vswp->mca_lock);

	/*
	 * By now any pending tasks have finished and the underlying
	 * ldc's have been destroyed, so its safe to delete the control
	 * message taskq.
	 */
	if (vswp->taskq_p != NULL)
		ddi_taskq_destroy(vswp->taskq_p);

	/*
	 * At this stage all the data pointers in the hash table
	 * should be NULL, as all the ports have been removed and will
	 * have deleted themselves from the port lists which the data
	 * pointers point to. Hence we can destroy the table using the
	 * default destructors.
	 */
	D2(vswp, "vsw_detach: destroying hash tables..");
	mod_hash_destroy_hash(vswp->fdb);
	vswp->fdb = NULL;

	WRITE_ENTER(&vswp->mfdbrw);
	mod_hash_destroy_hash(vswp->mfdb);
	vswp->mfdb = NULL;
	RW_EXIT(&vswp->mfdbrw);
	rw_destroy(&vswp->mfdbrw);

	ddi_remove_minor_node(dip, NULL);

	rw_destroy(&vswp->plist.lockrw);
	WRITE_ENTER(&vsw_rw);
	for (vswpp = &vsw_head; *vswpp; vswpp = &(*vswpp)->next) {
		if (*vswpp == vswp) {
			*vswpp = vswp->next;
			break;
		}
	}
	RW_EXIT(&vsw_rw);
	ddi_soft_state_free(vsw_state, instance);

	return (DDI_SUCCESS);
}

static int
vsw_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))

	vsw_t	*vswp = NULL;
	dev_t	dev = (dev_t)arg;
	int	instance;

	instance = getminor(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((vswp = ddi_get_soft_state(vsw_state, instance)) == NULL) {
			*result = NULL;
			return (DDI_FAILURE);
		}
		*result = vswp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		*result = NULL;
		return (DDI_FAILURE);
	}
}

/*
 * Get the properties from our MD node.
 */
static void
vsw_get_md_properties(vsw_t *vswp)
{
	md_t		*mdp = NULL;
	int		num_nodes = 0;
	int		len = 0, listsz = 0;
	int		num_vdev = 0;
	int		i, idx;
	boolean_t	found_node = B_FALSE;
	char		*smode = NULL;
	char		*curr_mode = NULL;
	char		*physname = NULL;
	char		*node_name = NULL;
	char		*dev;
	uint64_t 	macaddr = 0;
	uint64_t	md_inst, obp_inst;
	mde_cookie_t	*listp = NULL;
	mde_cookie_t	rootnode;

	D1(vswp, "%s: enter", __func__);

	/*
	 * Further down we compare the obp 'reg' property to the
	 * 'cfg-handle' property in the vsw MD node to determine
	 * if the node refers to this particular instance. So if
	 * we can't read the obp value then there is no point
	 * in proceeding further.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, vswp->dip,
			DDI_PROP_DONTPASS, reg_propname) != 1) {
		cmn_err(CE_WARN, "Unable to read %s property "
			"from OBP device node", reg_propname);
		return;
	}

	obp_inst = ddi_prop_get_int(DDI_DEV_T_ANY, vswp->dip,
		DDI_PROP_DONTPASS, reg_propname, 0);

	D2(vswp, "%s: obp_inst 0x%llx", __func__, obp_inst);

	if ((mdp = md_get_handle()) == NULL) {
		DERR(vswp, "%s: unable to init MD", __func__);
		return;
	}

	if ((num_nodes = md_node_count(mdp)) <= 0) {
		DERR(vswp, "%s: invalid number of  nodes found %d",
			__func__, num_nodes);
		(void) md_fini_handle(mdp);
		return;
	}

	D2(vswp, "%s: %d nodes in total in MD", __func__, num_nodes);

	/* allocate enough space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);

	/* Get the list of virtual devices */
	num_vdev = md_scan_dag(mdp, rootnode,
		md_find_name(mdp, vdev_propname),
		md_find_name(mdp, "fwd"), listp);

	if (num_vdev <= 0) {
		DERR(vswp, "%s: didn't find any virtual-device nodes in MD",
			__func__);
		goto md_prop_exit;
	}

	D2(vswp, "%s: %d virtual-device nodes found", __func__, num_vdev);

	/* Look for the virtual switch nodes in the list */
	for (idx = 0; idx < num_vdev; idx++) {
		if (md_get_prop_str(mdp, listp[idx],
				"name", &node_name) != 0) {
			DERR(vswp, "%s: unable to get node name", __func__);
			continue;

		}

		if (strcmp(node_name, vsw_propname) == 0) {
			/* Virtual switch node */
			if (md_get_prop_val(mdp, listp[idx],
				"cfg-handle", &md_inst) != 0) {
				DERR(vswp, "%s: unable to get cfg-handle from"
					" node %d", __func__, idx);
				goto md_prop_exit;
			} else if (md_inst == obp_inst) {
				D2(vswp, "%s: found matching node (%d)"
					" 0x%llx == 0x%llx", __func__, idx,
					md_inst, obp_inst);
				found_node = B_TRUE;
				break;
			}
		}
	}

	if (!found_node) {
		DWARN(vswp, "%s: couldn't find correct vsw node", __func__);
		goto md_prop_exit;
	}

	/*
	 * Now, having found the correct node, get the various properties.
	 */

	if (md_get_prop_data(mdp, listp[idx], physdev_propname,
				(uint8_t **)(&physname), &len) != 0) {
		cmn_err(CE_WARN, "%s: unable to get name(s) of physical "
			"device(s) from MD", __func__);
	} else if ((strlen(physname) + 1) > LIFNAMSIZ) {
		cmn_err(CE_WARN, "%s is too long a device name", physname);
	} else {
		(void) strncpy(vswp->physname, physname, strlen(physname) + 1);
		vswp->mdprops |= VSW_MD_PHYSNAME;
		D2(vswp, "%s: using first device specified (%s)",
			__func__, vswp->physname);
	}

#ifdef DEBUG
	/*
	 * As a temporary measure to aid testing we check to see if there
	 * is a vsw.conf file present. If there is we use the value of the
	 * vsw_physname property in the file as the name of the physical
	 * device, overriding the value from the MD.
	 *
	 * There may be multiple devices listed, but for the moment
	 * we just use the first one.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, vswp->dip, 0,
		"vsw_physname", &dev) == DDI_PROP_SUCCESS) {
		if ((strlen(dev) + 1) > LIFNAMSIZ) {
			cmn_err(CE_WARN, "%s is too long a device name", dev);
		} else {
			cmn_err(CE_NOTE, "%s: using device name (%s) from "
				"config file", __func__, dev);

			(void) strncpy(vswp->physname, dev, strlen(dev) + 1);
			vswp->mdprops |= VSW_MD_PHYSNAME;
		}

		ddi_prop_free(dev);

	}
#endif

	/* mac address for vswitch device itself */
	if (md_get_prop_val(mdp, listp[idx],
			macaddr_propname, &macaddr) != 0) {
		cmn_err(CE_WARN, "!Unable to get MAC address from MD");

		/*
		 * Fallback to using the mac address of the physical
		 * device.
		 */
		if (vsw_get_physaddr(vswp) == 0) {
			cmn_err(CE_NOTE, "!Using MAC address from physical "
				"device (%s)", vswp->physname);
		}
	} else {
		READ_ENTER(&vswp->if_lockrw);
		for (i = ETHERADDRL - 1; i >= 0; i--) {
			vswp->if_addr.ether_addr_octet[i] = macaddr & 0xFF;
			macaddr >>= 8;
		}
		RW_EXIT(&vswp->if_lockrw);
		vswp->mdprops |= VSW_MD_MACADDR;
	}

	/*
	 * Get the switch-mode property. The modes are listed in
	 * decreasing order of preference, i.e. prefered mode is
	 * first item in list.
	 */
	len = 0;
	vswp->smode_num = 0;
	if (md_get_prop_data(mdp, listp[idx], smode_propname,
				(uint8_t **)(&smode), &len) != 0) {
		/*
		 * Unable to get switch-mode property from MD, nothing
		 * more we can do.
		 */
		cmn_err(CE_WARN, "!unable to get switch mode property");
		goto md_prop_exit;
	}

	curr_mode = smode;
	/*
	 * Modes of operation:
	 * 'switched'	 - layer 2 switching, underlying HW in
	 *			programmed mode.
	 * 'promiscuous' - layer 2 switching, underlying HW in
	 *			promiscuous mode.
	 * 'routed'	 - layer 3 (i.e. IP) routing, underlying HW
	 *			in non-promiscuous mode.
	 */
	while ((curr_mode < (smode + len)) && (vswp->smode_num < NUM_SMODES)) {
		D2(vswp, "%s: curr_mode = [%s]", __func__, curr_mode);
		if (strcmp(curr_mode, "switched") == 0) {
			vswp->smode[vswp->smode_num++] = VSW_LAYER2;
		} else if (strcmp(curr_mode, "promiscuous") == 0) {
			vswp->smode[vswp->smode_num++] = VSW_LAYER2_PROMISC;
		} else if (strcmp(curr_mode, "routed") == 0) {
			vswp->smode[vswp->smode_num++] = VSW_LAYER3;
		} else {
			cmn_err(CE_WARN, "Unknown switch mode %s, setting to"
				" default switched mode", curr_mode);
			vswp->smode[vswp->smode_num++] = VSW_LAYER2;
		}
		curr_mode += strlen(curr_mode) + 1;
	}

	D2(vswp, "%d switching modes specified", vswp->smode_num);

	if (vswp->smode_num > 0)
		vswp->mdprops |= VSW_MD_SMODE;

md_prop_exit:
	(void) md_fini_handle(mdp);

	kmem_free(listp, listsz);

	D1(vswp, "%s: exit", __func__);
}

/*
 * Get the mac address of the physical device.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_get_physaddr(vsw_t *vswp)
{
	mac_handle_t	mh;
	char		drv[LIFNAMSIZ];
	uint_t		ddi_instance;

	D1(vswp, "%s: enter", __func__);

	if (ddi_parse(vswp->physname, drv, &ddi_instance) != DDI_SUCCESS)
		return (1);

	if (mac_open(vswp->physname, ddi_instance, &mh) != 0) {
		cmn_err(CE_WARN, "!mac_open %s failed", vswp->physname);
		return (1);
	}

	READ_ENTER(&vswp->if_lockrw);
	mac_unicst_get(mh, vswp->if_addr.ether_addr_octet);
	RW_EXIT(&vswp->if_lockrw);

	mac_close(mh);

	vswp->mdprops |= VSW_DEV_MACADDR;

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Check to see if the card supports the setting of multiple unicst
 * addresses.
 *
 * Returns 0 if card supports the programming of multiple unicast addresses
 * and there are free address slots available, otherwise returns 1.
 */
static int
vsw_get_hw_maddr(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	if (vswp->mh == NULL) {
		return (1);
	}

	if (!mac_capab_get(vswp->mh, MAC_CAPAB_MULTIADDRESS, &vswp->maddr)) {
		DWARN(vswp, "Unable to get capabilities of"
			" underlying device (%s)", vswp->physname);
		return (1);
	}

	if (vswp->maddr.maddr_naddrfree == 0) {
		cmn_err(CE_WARN,
			"!device %s has no free unicast address slots",
			vswp->physname);
		return (1);
	}

	D2(vswp, "%s: %d addrs : %d free", __func__,
		vswp->maddr.maddr_naddr, vswp->maddr.maddr_naddrfree);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Setup for layer 2 switching.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_setup_layer2(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	vsw_switch_frame = vsw_switch_l2_frame;

	/*
	 * Attempt to link into the MAC layer so we can get
	 * and send packets out over the physical adapter.
	 */
	if (vswp->mdprops & VSW_MD_PHYSNAME) {
		if (vsw_mac_attach(vswp) != 0) {
			/*
			 * Registration with the MAC layer has failed,
			 * so return 1 so that can fall back to next
			 * prefered switching method.
			 */
			cmn_err(CE_WARN, "!Unable to join as MAC layer "
				"client");
			return (1);
		}

		if (vswp->smode[vswp->smode_idx] == VSW_LAYER2) {
			/*
			 * Verify that underlying device can support multiple
			 * unicast mac addresses, and has free capacity.
			 */
			if (vsw_get_hw_maddr(vswp) != 0) {
				cmn_err(CE_WARN, "!unable to setup switching");
				vsw_mac_detach(vswp);
				return (1);
			}
		}

	} else {
		/*
		 * No physical device name found in MD which is
		 * required for layer 2.
		 */
		cmn_err(CE_WARN, "!no physical device name specified");
		return (1);
	}

	D1(vswp, "%s: exit", __func__);

	return (0);
}

static int
vsw_setup_layer3(vsw_t *vswp)
{
	D1(vswp, "%s: enter", __func__);

	D2(vswp, "%s: operating in layer 3 mode", __func__);
	vsw_switch_frame = vsw_switch_l3_frame;

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Link into the MAC layer to gain access to the services provided by
 * the underlying physical device driver (which should also have
 * registered with the MAC layer).
 *
 * Only when in layer 2 mode.
 */
static int
vsw_mac_attach(vsw_t *vswp)
{
	char	drv[LIFNAMSIZ];
	uint_t	ddi_instance;

	D1(vswp, "%s: enter", __func__);

	vswp->mh = NULL;
	vswp->mrh = NULL;
	vswp->mstarted = B_FALSE;
	vswp->mresources = B_FALSE;

	ASSERT(vswp->mdprops & VSW_MD_PHYSNAME);

	if (ddi_parse(vswp->physname, drv, &ddi_instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "invalid device name: %s", vswp->physname);
		goto mac_fail_exit;
	}
	if ((mac_open(vswp->physname, ddi_instance, &vswp->mh)) != 0) {
		cmn_err(CE_WARN, "mac_open %s failed", vswp->physname);
		goto mac_fail_exit;
	}

	ASSERT(vswp->mh != NULL);

	D2(vswp, "vsw_mac_attach: using device %s", vswp->physname);

	if (vsw_multi_ring_enable) {
		vsw_mac_ring_tbl_init(vswp);

		/*
		 * Register our receive callback.
		 */
		vswp->mrh = mac_rx_add(vswp->mh,
			vsw_rx_queue_cb, (void *)vswp);

		/*
		 * Register our mac resource callback.
		 */
		mac_resource_set(vswp->mh, vsw_mac_ring_add_cb, (void *)vswp);
		vswp->mresources = B_TRUE;

		/*
		 * Get the ring resources available to us from
		 * the mac below us.
		 */
		mac_resources(vswp->mh);
	} else {
		/*
		 * Just register our rx callback function
		 */
		vswp->mrh = mac_rx_add(vswp->mh, vsw_rx_cb, (void *)vswp);
	}

	ASSERT(vswp->mrh != NULL);

	/* Get the MAC tx fn */
	vswp->txinfo = mac_tx_get(vswp->mh);

	/* start the interface */
	if (mac_start(vswp->mh) != 0) {
		cmn_err(CE_WARN, "could not start mac interface");
		goto mac_fail_exit;
	}

	vswp->mstarted = B_TRUE;

	D1(vswp, "%s: exit", __func__);
	return (0);

mac_fail_exit:
	vsw_mac_detach(vswp);

	D1(vswp, "%s: exit", __func__);
	return (1);
}

static void
vsw_mac_detach(vsw_t *vswp)
{
	D1(vswp, "vsw_mac_detach: enter");

	ASSERT(vswp != NULL);
	ASSERT(vswp->mh != NULL);

	if (vsw_multi_ring_enable) {
		vsw_mac_ring_tbl_destroy(vswp);
	}

	if (vswp->mstarted)
		mac_stop(vswp->mh);
	if (vswp->mrh != NULL)
		mac_rx_remove(vswp->mh, vswp->mrh);
	if (vswp->mresources)
		mac_resource_set(vswp->mh, NULL, NULL);
	mac_close(vswp->mh);

	vswp->mrh = NULL;
	vswp->mh = NULL;
	vswp->txinfo = NULL;
	vswp->mstarted = B_FALSE;

	D1(vswp, "vsw_mac_detach: exit");
}

/*
 * Depending on the mode specified, the capabilites and capacity
 * of the underlying device setup the physical device.
 *
 * If in layer 3 mode, then do nothing.
 *
 * If in layer 2 programmed mode attempt to program the unicast address
 * associated with the port into the physical device. If this is not
 * possible due to resource exhaustion or simply because the device does
 * not support multiple unicast addresses then if required fallback onto
 * putting the card into promisc mode.
 *
 * If in promisc mode then simply set the card into promisc mode.
 *
 * Returns 0 success, 1 on failure.
 */
static int
vsw_set_hw(vsw_t *vswp, vsw_port_t *port)
{
	mac_multi_addr_t	mac_addr;
	void			*mah;
	int			err;

	D1(vswp, "%s: enter", __func__);

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER3)
		return (0);

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC) {
		return (vsw_set_hw_promisc(vswp, port));
	}

	if (vswp->maddr.maddr_handle == NULL)
		return (1);

	mah = vswp->maddr.maddr_handle;

	/*
	 * Attempt to program the unicast address into the HW.
	 */
	mac_addr.mma_addrlen = ETHERADDRL;
	ether_copy(&port->p_macaddr, &mac_addr.mma_addr);

	err = vswp->maddr.maddr_add(mah, &mac_addr);
	if (err != 0) {
		cmn_err(CE_WARN, "!failed to program addr "
			"%x:%x:%x:%x:%x:%x for port %d into device %s "
			": err %d", port->p_macaddr.ether_addr_octet[0],
			port->p_macaddr.ether_addr_octet[1],
			port->p_macaddr.ether_addr_octet[2],
			port->p_macaddr.ether_addr_octet[3],
			port->p_macaddr.ether_addr_octet[4],
			port->p_macaddr.ether_addr_octet[5],
			port->p_instance, vswp->physname, err);

		/*
		 * Mark that attempt should be made to re-config sometime
		 * in future if a port is deleted.
		 */
		vswp->recfg_reqd = B_TRUE;

		/*
		 * Only 1 mode specified, nothing more to do.
		 */
		if (vswp->smode_num == 1)
			return (err);

		/*
		 * If promiscuous was next mode specified try to
		 * set the card into that mode.
		 */
		if ((vswp->smode_idx <= (vswp->smode_num - 2)) &&
			(vswp->smode[vswp->smode_idx + 1]
					== VSW_LAYER2_PROMISC)) {
			vswp->smode_idx += 1;
			return (vsw_set_hw_promisc(vswp, port));
		}
		return (err);
	}

	port->addr_slot = mac_addr.mma_slot;
	port->addr_set = VSW_ADDR_HW;

	D2(vswp, "programmed addr %x:%x:%x:%x:%x:%x for port %d "
		"into slot %d of device %s",
		port->p_macaddr.ether_addr_octet[0],
		port->p_macaddr.ether_addr_octet[1],
		port->p_macaddr.ether_addr_octet[2],
		port->p_macaddr.ether_addr_octet[3],
		port->p_macaddr.ether_addr_octet[4],
		port->p_macaddr.ether_addr_octet[5],
		port->p_instance, port->addr_slot, vswp->physname);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * If in layer 3 mode do nothing.
 *
 * If in layer 2 switched mode remove the address from the physical
 * device.
 *
 * If in layer 2 promiscuous mode disable promisc mode.
 *
 * Returns 0 on success.
 */
static int
vsw_unset_hw(vsw_t *vswp, vsw_port_t *port)
{
	int		err;
	void		*mah;

	D1(vswp, "%s: enter", __func__);

	if (vswp->smode[vswp->smode_idx] == VSW_LAYER3)
		return (0);

	if (port->addr_set == VSW_ADDR_PROMISC) {
		return (vsw_unset_hw_promisc(vswp, port));
	}

	if (port->addr_set == VSW_ADDR_HW) {
		if (vswp->mh == NULL)
			return (1);

		if (vswp->maddr.maddr_handle == NULL)
			return (1);

		mah = vswp->maddr.maddr_handle;

		err = vswp->maddr.maddr_remove(mah, port->addr_slot);
		if (err != 0) {
			cmn_err(CE_WARN, "!Unable to remove addr "
				"%x:%x:%x:%x:%x:%x for port %d from device %s"
				" : (err %d)",
				port->p_macaddr.ether_addr_octet[0],
				port->p_macaddr.ether_addr_octet[1],
				port->p_macaddr.ether_addr_octet[2],
				port->p_macaddr.ether_addr_octet[3],
				port->p_macaddr.ether_addr_octet[4],
				port->p_macaddr.ether_addr_octet[5],
				port->p_instance, vswp->physname, err);
			return (err);
		}

		port->addr_set = VSW_ADDR_UNSET;

		D2(vswp, "removed addr %x:%x:%x:%x:%x:%x for "
			"port %d from device %s",
			port->p_macaddr.ether_addr_octet[0],
			port->p_macaddr.ether_addr_octet[1],
			port->p_macaddr.ether_addr_octet[2],
			port->p_macaddr.ether_addr_octet[3],
			port->p_macaddr.ether_addr_octet[4],
			port->p_macaddr.ether_addr_octet[5],
			port->p_instance, vswp->physname);
	}

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Set network card into promisc mode.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_set_hw_promisc(vsw_t *vswp, vsw_port_t *port)
{
	D1(vswp, "%s: enter", __func__);

	if (vswp->mh == NULL)
		return (1);

	if (vswp->promisc_cnt++ == 0) {
		if (mac_promisc_set(vswp->mh, B_TRUE, MAC_DEVPROMISC) != 0) {
			vswp->promisc_cnt--;
			return (1);
		}
		cmn_err(CE_NOTE, "!switching device %s into promiscuous mode",
				vswp->physname);
	}
	port->addr_set = VSW_ADDR_PROMISC;

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Turn off promiscuous mode on network card.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_unset_hw_promisc(vsw_t *vswp, vsw_port_t *port)
{
	vsw_port_list_t 	*plist = &vswp->plist;

	D1(vswp, "%s: enter", __func__);

	if (vswp->mh == NULL)
		return (1);

	ASSERT(port->addr_set == VSW_ADDR_PROMISC);

	if (--vswp->promisc_cnt == 0) {
		if (mac_promisc_set(vswp->mh, B_FALSE, MAC_DEVPROMISC) != 0) {
			vswp->promisc_cnt++;
			return (1);
		}

		/*
		 * We are exiting promisc mode either because we were
		 * only in promisc mode because we had failed over from
		 * switched mode due to HW resource issues, or the user
		 * wanted the card in promisc mode for all the ports and
		 * the last port is now being deleted. Tweak the message
		 * accordingly.
		 */
		if (plist->num_ports != 0) {
			cmn_err(CE_NOTE, "!switching device %s back to "
				"programmed mode", vswp->physname);
		} else {
			cmn_err(CE_NOTE, "!switching device %s out of "
				"promiscuous mode", vswp->physname);
		}
	}
	port->addr_set = VSW_ADDR_UNSET;

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Determine whether or not we are operating in our prefered
 * mode and if not whether the physical resources now allow us
 * to operate in it.
 *
 * Should only be invoked after port which is being deleted has been
 * removed from the port list.
 */
static int
vsw_reconfig_hw(vsw_t *vswp)
{
	vsw_port_list_t 	*plist = &vswp->plist;
	mac_multi_addr_t	mac_addr;
	vsw_port_t		*tp;
	void			*mah;
	int			rv = 0;
	int			s_idx;

	D1(vswp, "%s: enter", __func__);

	if (vswp->maddr.maddr_handle == NULL)
		return (1);

	/*
	 * Check if there are now sufficient HW resources to
	 * attempt a re-config.
	 */
	if (plist->num_ports > vswp->maddr.maddr_naddrfree)
		return (1);

	/*
	 * If we are in layer 2 (i.e. switched) or would like to be
	 * in layer 2 then check if any ports need to be programmed
	 * into the HW.
	 *
	 * This can happen in two cases - switched was specified as
	 * the prefered mode of operation but we exhausted the HW
	 * resources and so failed over to the next specifed mode,
	 * or switched was the only mode specified so after HW
	 * resources were exhausted there was nothing more we
	 * could do.
	 */
	if (vswp->smode_idx > 0)
		s_idx = vswp->smode_idx - 1;
	else
		s_idx = vswp->smode_idx;

	if (vswp->smode[s_idx] == VSW_LAYER2) {
		mah = vswp->maddr.maddr_handle;

		D2(vswp, "%s: attempting reconfig..", __func__);

		/*
		 * Scan the port list for any port whose address has not
		 * be programmed in HW - there should be a max of one.
		 */
		for (tp = plist->head; tp != NULL; tp = tp->p_next) {
			if (tp->addr_set != VSW_ADDR_HW) {
				mac_addr.mma_addrlen = ETHERADDRL;
				ether_copy(&tp->p_macaddr, &mac_addr.mma_addr);

				rv = vswp->maddr.maddr_add(mah, &mac_addr);
				if (rv != 0) {
					DWARN(vswp, "Error setting addr in "
						"HW for port %d err %d",
						tp->p_instance, rv);
					goto reconfig_err_exit;
				}
				tp->addr_slot = mac_addr.mma_slot;

				D2(vswp, "re-programmed port %d "
					"addr %x:%x:%x:%x:%x:%x into slot %d"
					" of device %s", tp->p_instance,
					tp->p_macaddr.ether_addr_octet[0],
					tp->p_macaddr.ether_addr_octet[1],
					tp->p_macaddr.ether_addr_octet[2],
					tp->p_macaddr.ether_addr_octet[3],
					tp->p_macaddr.ether_addr_octet[4],
					tp->p_macaddr.ether_addr_octet[5],
					tp->addr_slot, vswp->physname);

				/*
				 * If up to now we had to put the card into
				 * promisc mode to see this address, we
				 * can now safely disable promisc mode.
				 */
				if (tp->addr_set == VSW_ADDR_PROMISC)
					(void) vsw_unset_hw_promisc(vswp, tp);

				tp->addr_set = VSW_ADDR_HW;
			}
		}

		/* no further re-config needed */
		vswp->recfg_reqd = B_FALSE;

		vswp->smode_idx = s_idx;

		return (0);
	}

reconfig_err_exit:
	return (rv);
}

static void
vsw_mac_ring_tbl_entry_init(vsw_t *vswp, vsw_mac_ring_t *ringp)
{
	ringp->ring_state = VSW_MAC_RING_FREE;
	ringp->ring_arg = NULL;
	ringp->ring_blank = NULL;
	ringp->ring_vqp = NULL;
	ringp->ring_vswp = vswp;
}

static void
vsw_mac_ring_tbl_init(vsw_t *vswp)
{
	int		i;

	mutex_init(&vswp->mac_ring_lock, NULL, MUTEX_DRIVER, NULL);

	vswp->mac_ring_tbl_sz = vsw_mac_rx_rings;
	vswp->mac_ring_tbl  =
		kmem_alloc(vsw_mac_rx_rings * sizeof (vsw_mac_ring_t),
		KM_SLEEP);

	for (i = 0; i < vswp->mac_ring_tbl_sz; i++)
		vsw_mac_ring_tbl_entry_init(vswp, &vswp->mac_ring_tbl[i]);
}

static void
vsw_mac_ring_tbl_destroy(vsw_t *vswp)
{
	int	i;

	mutex_enter(&vswp->mac_ring_lock);
	for (i = 0; i < vswp->mac_ring_tbl_sz; i++) {
		if (vswp->mac_ring_tbl[i].ring_state != VSW_MAC_RING_FREE) {
			/*
			 * Destroy the queue.
			 */
			vsw_queue_stop(vswp->mac_ring_tbl[i].ring_vqp);
			vsw_queue_destroy(vswp->mac_ring_tbl[i].ring_vqp);

			/*
			 * Re-initialize the structure.
			 */
			vsw_mac_ring_tbl_entry_init(vswp,
				&vswp->mac_ring_tbl[i]);
		}
	}
	mutex_exit(&vswp->mac_ring_lock);

	mutex_destroy(&vswp->mac_ring_lock);
	kmem_free(vswp->mac_ring_tbl,
		vswp->mac_ring_tbl_sz * sizeof (vsw_mac_ring_t));
	vswp->mac_ring_tbl_sz = 0;
}

/*
 * Handle resource add callbacks from the driver below.
 */
static mac_resource_handle_t
vsw_mac_ring_add_cb(void *arg, mac_resource_t *mrp)
{
	vsw_t		*vswp = (vsw_t *)arg;
	mac_rx_fifo_t	*mrfp = (mac_rx_fifo_t *)mrp;
	vsw_mac_ring_t	*ringp;
	vsw_queue_t	*vqp;
	int		i;

	ASSERT(vswp != NULL);
	ASSERT(mrp != NULL);
	ASSERT(vswp->mac_ring_tbl != NULL);

	D1(vswp, "%s: enter", __func__);

	/*
	 * Check to make sure we have the correct resource type.
	 */
	if (mrp->mr_type != MAC_RX_FIFO)
		return (NULL);

	/*
	 * Find a open entry in the ring table.
	 */
	mutex_enter(&vswp->mac_ring_lock);
	for (i = 0; i < vswp->mac_ring_tbl_sz; i++) {
		ringp = &vswp->mac_ring_tbl[i];

		/*
		 * Check for an empty slot, if found, then setup queue
		 * and thread.
		 */
		if (ringp->ring_state == VSW_MAC_RING_FREE) {
			/*
			 * Create the queue for this ring.
			 */
			vqp = vsw_queue_create();

			/*
			 * Initialize the ring data structure.
			 */
			ringp->ring_vqp = vqp;
			ringp->ring_arg = mrfp->mrf_arg;
			ringp->ring_blank = mrfp->mrf_blank;
			ringp->ring_state = VSW_MAC_RING_INUSE;

			/*
			 * Create the worker thread.
			 */
			vqp->vq_worker = thread_create(NULL, 0,
				vsw_queue_worker, ringp, 0, &p0,
				TS_RUN, minclsyspri);
			if (vqp->vq_worker == NULL) {
				vsw_queue_destroy(vqp);
				vsw_mac_ring_tbl_entry_init(vswp, ringp);
				ringp = NULL;
			}

			mutex_exit(&vswp->mac_ring_lock);
			D1(vswp, "%s: exit", __func__);
			return ((mac_resource_handle_t)ringp);
		}
	}
	mutex_exit(&vswp->mac_ring_lock);

	/*
	 * No slots in the ring table available.
	 */
	D1(vswp, "%s: exit", __func__);
	return (NULL);
}

static void
vsw_queue_stop(vsw_queue_t *vqp)
{
	mutex_enter(&vqp->vq_lock);

	if (vqp->vq_state == VSW_QUEUE_RUNNING) {
		vqp->vq_state = VSW_QUEUE_STOP;
		cv_signal(&vqp->vq_cv);

		while (vqp->vq_state != VSW_QUEUE_DRAINED)
			cv_wait(&vqp->vq_cv, &vqp->vq_lock);
	}

	mutex_exit(&vqp->vq_lock);
}

static vsw_queue_t *
vsw_queue_create()
{
	vsw_queue_t *vqp;

	vqp = kmem_zalloc(sizeof (vsw_queue_t), KM_SLEEP);

	mutex_init(&vqp->vq_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vqp->vq_cv, NULL, CV_DRIVER, NULL);
	vqp->vq_first = NULL;
	vqp->vq_last = NULL;
	vqp->vq_state = VSW_QUEUE_STOP;

	return (vqp);
}

static void
vsw_queue_destroy(vsw_queue_t *vqp)
{
	cv_destroy(&vqp->vq_cv);
	mutex_destroy(&vqp->vq_lock);
	kmem_free(vqp, sizeof (vsw_queue_t));
}

static void
vsw_queue_worker(vsw_mac_ring_t *rrp)
{
	mblk_t		*mp;
	vsw_queue_t	*vqp = rrp->ring_vqp;
	vsw_t		*vswp = rrp->ring_vswp;

	mutex_enter(&vqp->vq_lock);

	ASSERT(vqp->vq_state == VSW_QUEUE_STOP);

	/*
	 * Set the state to running, since the thread is now active.
	 */
	vqp->vq_state = VSW_QUEUE_RUNNING;

	while (vqp->vq_state == VSW_QUEUE_RUNNING) {
		/*
		 * Wait for work to do or the state has changed
		 * to not running.
		 */
		while ((vqp->vq_state == VSW_QUEUE_RUNNING) &&
				(vqp->vq_first == NULL)) {
			cv_wait(&vqp->vq_cv, &vqp->vq_lock);
		}

		/*
		 * Process packets that we received from the interface.
		 */
		if (vqp->vq_first != NULL) {
			mp = vqp->vq_first;

			vqp->vq_first = NULL;
			vqp->vq_last = NULL;

			mutex_exit(&vqp->vq_lock);

			/* switch the chain of packets received */
			vsw_switch_frame(vswp, mp, VSW_PHYSDEV, NULL, NULL);

			mutex_enter(&vqp->vq_lock);
		}
	}

	/*
	 * We are drained and signal we are done.
	 */
	vqp->vq_state = VSW_QUEUE_DRAINED;
	cv_signal(&vqp->vq_cv);

	/*
	 * Exit lock and drain the remaining packets.
	 */
	mutex_exit(&vqp->vq_lock);

	/*
	 * Exit the thread
	 */
	thread_exit();
}

/*
 * static void
 * vsw_rx_queue_cb() - Receive callback routine when
 *	vsw_multi_ring_enable is non-zero.  Queue the packets
 *	to a packet queue for a worker thread to process.
 */
static void
vsw_rx_queue_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	vsw_mac_ring_t	*ringp = (vsw_mac_ring_t *)mrh;
	vsw_t		*vswp = (vsw_t *)arg;
	vsw_queue_t	*vqp;
	mblk_t		*bp, *last;

	ASSERT(mrh != NULL);
	ASSERT(vswp != NULL);
	ASSERT(mp != NULL);

	D1(vswp, "%s: enter", __func__);

	/*
	 * Find the last element in the mblk chain.
	 */
	bp = mp;
	do {
		last = bp;
		bp = bp->b_next;
	} while (bp != NULL);

	/* Get the queue for the packets */
	vqp = ringp->ring_vqp;

	/*
	 * Grab the lock such we can queue the packets.
	 */
	mutex_enter(&vqp->vq_lock);

	if (vqp->vq_state != VSW_QUEUE_RUNNING) {
		freemsg(mp);
		goto vsw_rx_queue_cb_exit;
	}

	/*
	 * Add the mblk chain to the queue.  If there
	 * is some mblks in the queue, then add the new
	 * chain to the end.
	 */
	if (vqp->vq_first == NULL)
		vqp->vq_first = mp;
	else
		vqp->vq_last->b_next = mp;

	vqp->vq_last = last;

	/*
	 * Signal the worker thread that there is work to
	 * do.
	 */
	cv_signal(&vqp->vq_cv);

	/*
	 * Let go of the lock and exit.
	 */
vsw_rx_queue_cb_exit:
	mutex_exit(&vqp->vq_lock);
	D1(vswp, "%s: exit", __func__);
}

/*
 * receive callback routine. Invoked by MAC layer when there
 * are pkts being passed up from physical device.
 *
 * PERF: It may be more efficient when the card is in promisc
 * mode to check the dest address of the pkts here (against
 * the FDB) rather than checking later. Needs to be investigated.
 */
static void
vsw_rx_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	_NOTE(ARGUNUSED(mrh))

	vsw_t		*vswp = (vsw_t *)arg;

	ASSERT(vswp != NULL);

	D1(vswp, "vsw_rx_cb: enter");

	/* switch the chain of packets received */
	vsw_switch_frame(vswp, mp, VSW_PHYSDEV, NULL, NULL);

	D1(vswp, "vsw_rx_cb: exit");
}

/*
 * Send a message out over the physical device via the MAC layer.
 *
 * Returns any mblks that it was unable to transmit.
 */
static mblk_t *
vsw_tx_msg(vsw_t *vswp, mblk_t *mp)
{
	const mac_txinfo_t	*mtp;
	mblk_t			*nextp;

	if (vswp->mh == NULL) {
		DERR(vswp, "vsw_tx_msg: dropping pkts: no tx routine avail");
		return (mp);
	} else {
		for (;;) {
			nextp = mp->b_next;
			mp->b_next = NULL;

			mtp = vswp->txinfo;
			if ((mp = mtp->mt_fn(mtp->mt_arg, mp)) != NULL) {
				mp->b_next = nextp;
				break;
			}

			if ((mp = nextp) == NULL)
				break;

		}

	}

	return (mp);
}

/*
 * Register with the MAC layer as a network device, so we
 * can be plumbed if necessary.
 */
static int
vsw_mac_register(vsw_t *vswp)
{
	mac_register_t	*macp;
	int		rv;

	D1(vswp, "%s: enter", __func__);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		return (EINVAL);
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = vswp;
	macp->m_dip = vswp->dip;
	macp->m_src_addr = (uint8_t *)&vswp->if_addr;
	macp->m_callbacks = &vsw_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;
	rv = mac_register(macp, &vswp->if_mh);
	mac_free(macp);
	if (rv == 0)
		vswp->if_state |= VSW_IF_REG;

	D1(vswp, "%s: exit", __func__);

	return (rv);
}

static int
vsw_mac_unregister(vsw_t *vswp)
{
	int		rv = 0;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&vswp->if_lockrw);

	if (vswp->if_state & VSW_IF_REG) {
		rv = mac_unregister(vswp->if_mh);
		if (rv != 0) {
			DWARN(vswp, "%s: unable to unregister from MAC "
				"framework", __func__);

			RW_EXIT(&vswp->if_lockrw);
			D1(vswp, "%s: fail exit", __func__);
			return (rv);
		}

		/* mark i/f as down and unregistered */
		vswp->if_state &= ~(VSW_IF_UP | VSW_IF_REG);
	}
	RW_EXIT(&vswp->if_lockrw);

	vswp->mdprops &= ~(VSW_MD_MACADDR | VSW_DEV_MACADDR);

	D1(vswp, "%s: exit", __func__);

	return (rv);
}

static int
vsw_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	vsw_t			*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	if (vswp->mh == NULL)
		return (EINVAL);

	/* return stats from underlying device */
	*val = mac_stat_get(vswp->mh, stat);
	return (0);
}

static void
vsw_m_stop(void *arg)
{
	vsw_t		*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&vswp->if_lockrw);
	vswp->if_state &= ~VSW_IF_UP;
	RW_EXIT(&vswp->if_lockrw);

	D1(vswp, "%s: exit (state = %d)", __func__, vswp->if_state);
}

static int
vsw_m_start(void *arg)
{
	vsw_t		*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&vswp->if_lockrw);
	vswp->if_state |= VSW_IF_UP;
	RW_EXIT(&vswp->if_lockrw);

	D1(vswp, "%s: exit (state = %d)", __func__, vswp->if_state);
	return (0);
}

/*
 * Change the local interface address.
 */
static int
vsw_m_unicst(void *arg, const uint8_t *macaddr)
{
	vsw_t		*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&vswp->if_lockrw);
	ether_copy(macaddr, &vswp->if_addr);
	RW_EXIT(&vswp->if_lockrw);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

static int
vsw_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	vsw_t		*vswp = (vsw_t *)arg;
	mcst_addr_t	*mcst_p = NULL;
	uint64_t	addr = 0x0;
	int		i, ret = 0;

	D1(vswp, "%s: enter", __func__);

	/*
	 * Convert address into form that can be used
	 * as hash table key.
	 */
	for (i = 0; i < ETHERADDRL; i++) {
		addr = (addr << 8) | mca[i];
	}

	D2(vswp, "%s: addr = 0x%llx", __func__, addr);

	if (add) {
		D2(vswp, "%s: adding multicast", __func__);
		if (vsw_add_mcst(vswp, VSW_LOCALDEV, addr, NULL) == 0) {
			/*
			 * Update the list of multicast addresses
			 * contained within the vsw_t structure to
			 * include this new one.
			 */
			mcst_p = kmem_zalloc(sizeof (mcst_addr_t), KM_NOSLEEP);
			if (mcst_p == NULL) {
				DERR(vswp, "%s unable to alloc mem", __func__);
				return (1);
			}
			mcst_p->addr = addr;

			mutex_enter(&vswp->mca_lock);
			mcst_p->nextp = vswp->mcap;
			vswp->mcap = mcst_p;
			mutex_exit(&vswp->mca_lock);

			/*
			 * Call into the underlying driver to program the
			 * address into HW.
			 */
			if (vswp->mh != NULL) {
				ret = mac_multicst_add(vswp->mh, mca);
				if (ret != 0) {
					cmn_err(CE_WARN, "!unable to add "
						"multicast address");
					goto vsw_remove_addr;
				}
			}
		} else {
			cmn_err(CE_WARN, "!unable to add multicast address");
		}
		return (ret);
	}

vsw_remove_addr:

	D2(vswp, "%s: removing multicast", __func__);
	/*
	 * Remove the address from the hash table..
	 */
	if (vsw_del_mcst(vswp, VSW_LOCALDEV, addr, NULL) == 0) {

		/*
		 * ..and then from the list maintained in the
		 * vsw_t structure.
		 */
		vsw_del_addr(VSW_LOCALDEV, vswp, addr);

		if (vswp->mh != NULL)
			(void) mac_multicst_remove(vswp->mh, mca);
	}

	D1(vswp, "%s: exit", __func__);

	return (0);
}

static int
vsw_m_promisc(void *arg, boolean_t on)
{
	vsw_t		*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&vswp->if_lockrw);
	if (on)
		vswp->if_state |= VSW_IF_PROMISC;
	else
		vswp->if_state &= ~VSW_IF_PROMISC;
	RW_EXIT(&vswp->if_lockrw);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

static mblk_t *
vsw_m_tx(void *arg, mblk_t *mp)
{
	vsw_t		*vswp = (vsw_t *)arg;

	D1(vswp, "%s: enter", __func__);

	vsw_switch_frame(vswp, mp, VSW_LOCALDEV, NULL, NULL);

	D1(vswp, "%s: exit", __func__);

	return (NULL);
}

/*
 * Register for machine description (MD) updates.
 */
static void
vsw_mdeg_register(vsw_t *vswp)
{
	mdeg_prop_spec_t	*pspecp;
	mdeg_node_spec_t	*inst_specp;
	mdeg_handle_t		mdeg_hdl;
	size_t			templatesz;
	int			inst, rv;

	D1(vswp, "%s: enter", __func__);

	inst = ddi_prop_get_int(DDI_DEV_T_ANY, vswp->dip,
		DDI_PROP_DONTPASS, reg_propname, -1);
	if (inst == -1) {
		DERR(vswp, "%s: unable to get %s property",
						__func__, reg_propname);
		return;
	}

	D2(vswp, "%s: instance %d registering with mdeg", __func__, inst);

	/*
	 * Allocate and initialize a per-instance copy
	 * of the global property spec array that will
	 * uniquely identify this vsw instance.
	 */
	templatesz = sizeof (vsw_prop_template);
	pspecp = kmem_zalloc(templatesz, KM_SLEEP);

	bcopy(vsw_prop_template, pspecp, templatesz);

	VSW_SET_MDEG_PROP_INST(pspecp, inst);

	/* initialize the complete prop spec structure */
	inst_specp = kmem_zalloc(sizeof (mdeg_node_spec_t), KM_SLEEP);
	inst_specp->namep = "virtual-device";
	inst_specp->specp = pspecp;

	/* perform the registration */
	rv = mdeg_register(inst_specp, &vport_match, vsw_mdeg_cb,
	    (void *)vswp, &mdeg_hdl);

	if (rv != MDEG_SUCCESS) {
		DERR(vswp, "%s: mdeg_register failed (%d)\n", __func__, rv);
		kmem_free(inst_specp, sizeof (mdeg_node_spec_t));
		kmem_free(pspecp, templatesz);
		return;
	}

	/* save off data that will be needed later */
	vswp->inst_spec = inst_specp;
	vswp->mdeg_hdl = mdeg_hdl;

	D1(vswp, "%s: exit", __func__);
}

static void
vsw_mdeg_unregister(vsw_t *vswp)
{
	D1(vswp, "vsw_mdeg_unregister: enter");

	(void) mdeg_unregister(vswp->mdeg_hdl);

	if (vswp->inst_spec->specp != NULL) {
		(void) kmem_free(vswp->inst_spec->specp,
			sizeof (vsw_prop_template));
		vswp->inst_spec->specp = NULL;
	}

	if (vswp->inst_spec != NULL) {
		(void) kmem_free(vswp->inst_spec,
			sizeof (mdeg_node_spec_t));
		vswp->inst_spec = NULL;
	}

	D1(vswp, "vsw_mdeg_unregister: exit");
}

static int
vsw_mdeg_cb(void *cb_argp, mdeg_result_t *resp)
{
	vsw_t		*vswp;
	int		idx;
	md_t		*mdp;
	mde_cookie_t	node;
	uint64_t	inst;

	if (resp == NULL)
		return (MDEG_FAILURE);

	vswp = (vsw_t *)cb_argp;

	D1(vswp, "%s: added %d : removed %d : matched %d",
		__func__, resp->added.nelem, resp->removed.nelem,
		resp->match_prev.nelem);

	/* process added ports */
	for (idx = 0; idx < resp->added.nelem; idx++) {
		mdp = resp->added.mdp;
		node = resp->added.mdep[idx];

		D2(vswp, "%s: adding node(%d) 0x%lx", __func__, idx, node);

		if (vsw_port_add(vswp, mdp, &node) != 0) {
			cmn_err(CE_WARN, "Unable to add new port (0x%lx)",
					node);
		}
	}

	/* process removed ports */
	for (idx = 0; idx < resp->removed.nelem; idx++) {
		mdp = resp->removed.mdp;
		node = resp->removed.mdep[idx];

		if (md_get_prop_val(mdp, node, id_propname, &inst)) {
			DERR(vswp, "%s: prop(%s) not found port(%d)",
				__func__, id_propname, idx);
			continue;
		}

		D2(vswp, "%s: removing node(%d) 0x%lx", __func__, idx, node);

		if (vsw_port_detach(vswp, inst) != 0) {
			cmn_err(CE_WARN, "Unable to remove port %ld", inst);
		}
	}

	/*
	 * Currently no support for updating already active ports.
	 * So, ignore the match_curr and match_priv arrays for now.
	 */

	D1(vswp, "%s: exit", __func__);

	return (MDEG_SUCCESS);
}

/*
 * Add a new port to the system.
 *
 * Returns 0 on success, 1 on failure.
 */
int
vsw_port_add(vsw_t *vswp, md_t *mdp, mde_cookie_t *node)
{
	uint64_t		ldc_id;
	uint8_t			*addrp;
	int			i, addrsz;
	int			num_nodes = 0, nchan = 0;
	int			listsz = 0;
	mde_cookie_t		*listp = NULL;
	struct ether_addr	ea;
	uint64_t		macaddr;
	uint64_t		inst = 0;
	vsw_port_t		*port;

	if (md_get_prop_val(mdp, *node, id_propname, &inst)) {
		DWARN(vswp, "%s: prop(%s) not found", __func__,
			id_propname);
		return (1);
	}

	/*
	 * Find the channel endpoint node(s) (which should be under this
	 * port node) which contain the channel id(s).
	 */
	if ((num_nodes = md_node_count(mdp)) <= 0) {
		DERR(vswp, "%s: invalid number of nodes found (%d)",
			__func__, num_nodes);
		return (1);
	}

	/* allocate enough space for node list */
	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	nchan = md_scan_dag(mdp, *node,
		md_find_name(mdp, chan_propname),
		md_find_name(mdp, "fwd"), listp);

	if (nchan <= 0) {
		DWARN(vswp, "%s: no %s nodes found", __func__, chan_propname);
		kmem_free(listp, listsz);
		return (1);
	}

	D2(vswp, "%s: %d %s nodes found", __func__, nchan, chan_propname);

	/* use property from first node found */
	if (md_get_prop_val(mdp, listp[0], id_propname, &ldc_id)) {
		DWARN(vswp, "%s: prop(%s) not found\n", __func__,
			id_propname);
		kmem_free(listp, listsz);
		return (1);
	}

	/* don't need list any more */
	kmem_free(listp, listsz);

	D2(vswp, "%s: ldc_id 0x%llx", __func__, ldc_id);

	/* read mac-address property */
	if (md_get_prop_data(mdp, *node, remaddr_propname,
					&addrp, &addrsz)) {
		DWARN(vswp, "%s: prop(%s) not found",
				__func__, remaddr_propname);
		return (1);
	}

	if (addrsz < ETHERADDRL) {
		DWARN(vswp, "%s: invalid address size", __func__);
		return (1);
	}

	macaddr = *((uint64_t *)addrp);
	D2(vswp, "%s: remote mac address 0x%llx", __func__, macaddr);

	for (i = ETHERADDRL - 1; i >= 0; i--) {
		ea.ether_addr_octet[i] = macaddr & 0xFF;
		macaddr >>= 8;
	}

	if (vsw_port_attach(vswp, (int)inst, &ldc_id, 1, &ea) != 0) {
		DERR(vswp, "%s: failed to attach port", __func__);
		return (1);
	}

	port = vsw_lookup_port(vswp, (int)inst);

	/* just successfuly created the port, so it should exist */
	ASSERT(port != NULL);

	return (0);
}

/*
 * Attach the specified port.
 *
 * Returns 0 on success, 1 on failure.
 */
static int
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

	mutex_init(&port->ref_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&port->ref_cv, NULL, CV_DRIVER, NULL);

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

			cv_destroy(&port->ref_cv);
			mutex_destroy(&port->ref_lock);

			cv_destroy(&port->state_cv);
			mutex_destroy(&port->state_lock);

			mutex_destroy(&port->tx_lock);
			mutex_destroy(&port->mca_lock);
			kmem_free(port, sizeof (vsw_port_t));
			return (1);
		}
	}

	ether_copy(macaddr, &port->p_macaddr);

	WRITE_ENTER(&plist->lockrw);

	/* create the fdb entry for this port/mac address */
	(void) vsw_add_fdb(vswp, port);

	(void) vsw_set_hw(vswp, port);

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
static int
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

	/* Remove address if was programmed into HW. */
	(void) vsw_unset_hw(vswp, port);

	/* Remove the fdb entry for this port/mac address */
	(void) vsw_del_fdb(vswp, port);

	/* Remove any multicast addresses.. */
	vsw_del_mcst_port(port);

	/*
	 * No longer need to hold writer lock on port list now
	 * that we have unlinked the target port from the list.
	 */
	RW_EXIT(&plist->lockrw);

	READ_ENTER(&plist->lockrw);

	if (vswp->recfg_reqd)
		(void) vsw_reconfig_hw(vswp);

	RW_EXIT(&plist->lockrw);

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
static int
vsw_detach_ports(vsw_t *vswp)
{
	vsw_port_list_t 	*plist = &vswp->plist;
	vsw_port_t		*port = NULL;

	D1(vswp, "%s: enter", __func__);

	WRITE_ENTER(&plist->lockrw);

	while ((port = plist->head) != NULL) {
		if (vsw_plist_del_node(vswp, port)) {
			DERR(vswp, "%s: Error deleting port %d"
				" from port list", __func__,
				port->p_instance);
			RW_EXIT(&plist->lockrw);
			return (1);
		}

		/* Remove address if was programmed into HW. */
		(void) vsw_unset_hw(vswp, port);

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
	mutex_enter(&port->ref_lock);
	while (port->ref_cnt != 0)
		cv_wait(&port->ref_cv, &port->ref_lock);
	mutex_exit(&port->ref_lock);

	/*
	 * Wait for any active callbacks to finish
	 */
	if (vsw_drain_ldcs(port))
		return (1);

	ldcl = &port->p_ldclist;
	WRITE_ENTER(&ldcl->lockrw);
	while (ldcl->num_ldcs > 0) {
		if (vsw_ldc_detach(port, ldcl->head->ldc_id) != 0) {;
			cmn_err(CE_WARN, "unable to detach ldc %ld",
					ldcl->head->ldc_id);
			RW_EXIT(&ldcl->lockrw);
			return (1);
		}
	}
	RW_EXIT(&ldcl->lockrw);

	rw_destroy(&port->p_ldclist.lockrw);

	mutex_destroy(&port->mca_lock);
	mutex_destroy(&port->tx_lock);
	cv_destroy(&port->ref_cv);
	mutex_destroy(&port->ref_lock);

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
	enum		{ PROG_init = 0x0, PROG_mblks = 0x1,
				PROG_callback = 0x2}
			progress;

	progress = PROG_init;

	D1(vswp, "%s: enter", __func__);

	ldcp = kmem_zalloc(sizeof (vsw_ldc_t), KM_NOSLEEP);
	if (ldcp == NULL) {
		DERR(vswp, "%s: kmem_zalloc failed", __func__);
		return (1);
	}
	ldcp->ldc_id = ldc_id;

	/* allocate pool of receive mblks */
	rv = vio_create_mblks(vsw_num_mblks, vsw_mblk_size, &(ldcp->rxh));
	if (rv) {
		DWARN(vswp, "%s: unable to create free mblk pool for"
			" channel %ld (rv %d)", __func__, ldc_id, rv);
		kmem_free(ldcp, sizeof (vsw_ldc_t));
		return (1);
	}

	progress |= PROG_mblks;

	mutex_init(&ldcp->ldc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->ldc_cblock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->drain_cv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ldcp->drain_cv, NULL, CV_DRIVER, NULL);

	/* required for handshake with peer */
	ldcp->local_session = (uint64_t)ddi_get_lbolt();
	ldcp->peer_session = 0;
	ldcp->session_status = 0;

	mutex_init(&ldcp->hss_lock, NULL, MUTEX_DRIVER, NULL);
	ldcp->hss_id = 1;	/* Initial handshake session id */

	/* only set for outbound lane, inbound set by peer */
	mutex_init(&ldcp->lane_in.seq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->lane_out.seq_lock, NULL, MUTEX_DRIVER, NULL);
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

	status = ldc_reg_callback(ldcp->ldc_handle, vsw_ldc_cb, (caddr_t)ldcp);
	if (status != 0) {
		DERR(vswp, "%s(%lld): ldc_reg_callback failed, rv (%d)",
		    __func__, ldc_id, status);
		(void) ldc_fini(ldcp->ldc_handle);
		goto ldc_attach_fail;
	}

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

	/* link it into the list of channels for this port */
	WRITE_ENTER(&ldcl->lockrw);
	ldcp->ldc_next = ldcl->head;
	ldcl->head = ldcp;
	ldcl->num_ldcs++;
	RW_EXIT(&ldcl->lockrw);

	D1(vswp, "%s: exit", __func__);
	return (0);

ldc_attach_fail:
	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_cblock);

	cv_destroy(&ldcp->drain_cv);

	if (progress & PROG_callback) {
		(void) ldc_unreg_callback(ldcp->ldc_handle);
	}

	if ((progress & PROG_mblks) && (ldcp->rxh != NULL)) {
		if (vio_destroy_mblks(ldcp->rxh) != 0) {
			/*
			 * Something odd has happened, as the destroy
			 * will only fail if some mblks have been allocated
			 * from the pool already (which shouldn't happen)
			 * and have not been returned.
			 *
			 * Add the pool pointer to a list maintained in
			 * the device instance. Another attempt will be made
			 * to free the pool when the device itself detaches.
			 */
			cmn_err(CE_WARN, "Creation of ldc channel %ld failed"
				" and cannot destroy associated mblk pool",
				ldc_id);
			ldcp->rxh->nextp =  vswp->rxh;
			vswp->rxh = ldcp->rxh;
		}
	}
	mutex_destroy(&ldcp->drain_cv_lock);
	mutex_destroy(&ldcp->hss_lock);

	mutex_destroy(&ldcp->lane_in.seq_lock);
	mutex_destroy(&ldcp->lane_out.seq_lock);
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

	if (ldcp->rxh != NULL) {
		if (vio_destroy_mblks(ldcp->rxh)) {
			/*
			 * Mostly likely some mblks are still in use and
			 * have not been returned to the pool. Add the pool
			 * to the list maintained in the device instance.
			 * Another attempt will be made to destroy the pool
			 * when the device detaches.
			 */
			ldcp->rxh->nextp =  vswp->rxh;
			vswp->rxh = ldcp->rxh;
		}
	}

	/* unlink it from the list */
	prev_ldcp = ldcp->ldc_next;
	ldcl->num_ldcs--;

	mutex_destroy(&ldcp->ldc_txlock);
	mutex_destroy(&ldcp->ldc_cblock);
	cv_destroy(&ldcp->drain_cv);
	mutex_destroy(&ldcp->drain_cv_lock);
	mutex_destroy(&ldcp->hss_lock);
	mutex_destroy(&ldcp->lane_in.seq_lock);
	mutex_destroy(&ldcp->lane_out.seq_lock);
	mutex_destroy(&ldcp->status_lock);

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
	istatus = ldcp->ldc_status;
	if (ldc_status(ldcp->ldc_handle, &ldcp->ldc_status) != 0) {
		DERR(vswp, "%s: unable to get status", __func__);
		mutex_exit(&ldcp->status_lock);
		LDC_EXIT_LOCK(ldcp);
		return (1);

	}
	mutex_exit(&ldcp->status_lock);
	LDC_EXIT_LOCK(ldcp);

	if ((istatus != LDC_UP) && (ldcp->ldc_status == LDC_UP)) {
		D2(vswp, "%s: channel %ld now UP (%ld)", __func__,
			ldcp->ldc_id, istatus);
		vsw_restart_handshake(ldcp);
	}

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

static vsw_port_t *
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
	ldc_status_t	lstatus;
	int		rv;

	D1(vswp, "%s: enter: ldcid (%lld)\n", __func__, ldcp->ldc_id);

	mutex_enter(&ldcp->ldc_cblock);

	if ((ldcp->ldc_status == LDC_INIT) || (ldcp->ldc_handle == NULL)) {
		mutex_exit(&ldcp->ldc_cblock);
		return (LDC_SUCCESS);
	}

	mutex_enter(&ldcp->status_lock);
	lstatus = ldcp->ldc_status;
	rv = ldc_status(ldcp->ldc_handle, &ldcp->ldc_status);
	mutex_exit(&ldcp->status_lock);
	if (rv != 0) {
		cmn_err(CE_WARN, "Unable to read channel state");
		goto vsw_cb_exit;
	}

	if (event & LDC_EVT_UP) {
		/*
		 * Channel has come up, get the state and then start
		 * the handshake.
		 */
		D2(vswp, "%s: id(%ld) event(%llx) UP: status(%ld)",
			__func__, ldcp->ldc_id, event, lstatus);
		D2(vswp, "%s: UP: old status %ld : cur status %ld",
			__func__, lstatus, ldcp->ldc_status);
		if ((ldcp->ldc_status != lstatus) &&
					(ldcp->ldc_status == LDC_UP)) {
				vsw_restart_handshake(ldcp);
		}

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);
	}

	if (event & LDC_EVT_READ) {
		/*
		 * Data available for reading.
		 */
		D2(vswp, "%s: id(ld) event(%llx) data READ",
				__func__, ldcp->ldc_id, event);

		vsw_process_pkt(ldcp);

		ASSERT((event & (LDC_EVT_RESET | LDC_EVT_DOWN)) == 0);

		goto vsw_cb_exit;
	}

	if (event & (LDC_EVT_DOWN | LDC_EVT_RESET)) {
		D2(vswp, "%s: id(%ld) event(%llx) DOWN/RESET",
					__func__, ldcp->ldc_id, event);

		/* attempt to restart the connection */
		vsw_restart_ldc(ldcp);

		/*
		 * vsw_restart_ldc() will attempt to bring the channel
		 * back up. Check here to see if that succeeded.
		 */
		mutex_enter(&ldcp->status_lock);
		lstatus = ldcp->ldc_status;
		rv = ldc_status(ldcp->ldc_handle, &ldcp->ldc_status);
		mutex_exit(&ldcp->status_lock);
		if (rv != 0) {
			DERR(vswp, "%s: unable to read status for channel %ld",
				__func__, ldcp->ldc_id);
			goto vsw_cb_exit;
		}

		D2(vswp, "%s: id(%ld) event(%llx) DOWN/RESET event:"
			" old status %ld : cur status %ld", __func__,
			ldcp->ldc_id, event, lstatus, ldcp->ldc_status);

		/*
		 * If channel was not previously UP then (re)start the
		 * handshake.
		 */
		if ((ldcp->ldc_status == LDC_UP) && (lstatus != LDC_UP)) {
			D2(vswp, "%s: channel %ld now UP, restarting "
				"handshake", __func__, ldcp->ldc_id);
			vsw_restart_handshake(ldcp);
		}
	}

	/*
	 * Catch either LDC_EVT_WRITE which we don't support or any
	 * unknown event.
	 */
	if (event & ~(LDC_EVT_UP | LDC_EVT_RESET
					| LDC_EVT_DOWN | LDC_EVT_READ)) {

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
 * Restart the connection with our peer. Free any existing
 * data structures and then attempt to bring channel back
 * up.
 */
static void
vsw_restart_ldc(vsw_ldc_t *ldcp)
{
	int		rv;
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

	rv = ldc_up(ldcp->ldc_handle);
	if (rv != 0) {
		/*
		 * Not a fatal error for ldc_up() to fail, as peer
		 * end point may simply not be ready yet.
		 */
		D2(vswp, "%s: ldc_up err id(%lld) rv(%d)", __func__,
			ldcp->ldc_id, rv);
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * (Re)start a handshake with our peer by sending them
 * our version info.
 */
static void
vsw_restart_handshake(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "vsw_restart_handshake: enter");

	if (ldcp->hphase != VSW_MILESTONE0) {
		vsw_restart_ldc(ldcp);
	}

	/*
	 * We now increment the transaction group id. This allows
	 * us to identify and disard any tasks which are still pending
	 * on the taskq and refer to the handshake session we are about
	 * to restart. These stale messages no longer have any real
	 * meaning.
	 */
	mutex_enter(&ldcp->hss_lock);
	ldcp->hss_id++;
	mutex_exit(&ldcp->hss_lock);

	if (ldcp->hcnt++ > vsw_num_handshakes) {
		cmn_err(CE_WARN, "exceeded number of permitted "
			"handshake attempts (%d) on channel %ld",
			ldcp->hcnt, ldcp->ldc_id);
		return;
	}

	if ((vswp->taskq_p == NULL) ||
		(ddi_taskq_dispatch(vswp->taskq_p, vsw_send_ver, ldcp,
			DDI_NOSLEEP) != DDI_SUCCESS)) {
		cmn_err(CE_WARN, "Can't dispatch version handshake task");
	}

	D1(vswp, "vsw_restart_handshake: exit");
}

/*
 * Deal appropriately with a ECONNRESET event encountered in a ldc_*
 * call.
 */
static void
vsw_handle_reset(vsw_ldc_t *ldcp)
{
	vsw_t		*vswp = ldcp->ldc_vswp;
	ldc_status_t	lstatus;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&ldcp->status_lock);
	lstatus = ldcp->ldc_status;
	if (ldc_status(ldcp->ldc_handle, &ldcp->ldc_status) != 0) {
		DERR(vswp, "%s: unable to read status for channel %ld",
			__func__, ldcp->ldc_id);
		mutex_exit(&ldcp->status_lock);
		return;
	}
	mutex_exit(&ldcp->status_lock);

	/*
	 * Check the channel's previous recorded state to
	 * determine if this is the first ECONNRESET event
	 * we've gotten for this particular channel (i.e. was
	 * previously up but is no longer). If so, terminate
	 * the channel.
	 */
	if ((ldcp->ldc_status != LDC_UP) && (lstatus == LDC_UP)) {
		vsw_restart_ldc(ldcp);
	}

	/*
	 * vsw_restart_ldc() will also attempt to bring channel
	 * back up. Check here if that succeeds.
	 */
	mutex_enter(&ldcp->status_lock);
	lstatus = ldcp->ldc_status;
	if (ldc_status(ldcp->ldc_handle, &ldcp->ldc_status) != 0) {
		DERR(vswp, "%s: unable to read status for channel %ld",
			__func__, ldcp->ldc_id);
		mutex_exit(&ldcp->status_lock);
		return;
	}
	mutex_exit(&ldcp->status_lock);

	/*
	 * If channel is now up and no one else (i.e. the callback routine)
	 * has dealt with it then we restart the handshake here.
	 */
	if ((lstatus != LDC_UP) && (ldcp->ldc_status == LDC_UP)) {
		vsw_restart_handshake(ldcp);
	}

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
			vsw_restart_handshake(ldcp);
			return (1);
		}
		break;

	case VSW_VER_ACK_RECV:
	case VSW_VER_NACK_RECV:
		if (!(state & VSW_VER_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious VER_ACK"
				" or VER_NACK when in state %d\n",
				ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		} else
			state &= ~VSW_VER_INFO_SENT;
		break;

	case VSW_ATTR_INFO_RECV:
		if ((phase < VSW_MILESTONE1) || (phase >= VSW_MILESTONE2)) {
			DERR(vswp, "vsw_check_flag (%d): ATTR_INFO_RECV"
				" when in state %d\n", ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		}
		break;

	case VSW_ATTR_ACK_RECV:
	case VSW_ATTR_NACK_RECV:
		if (!(state & VSW_ATTR_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious ATTR_ACK"
				" or ATTR_NACK when in state %d\n",
				ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		} else
			state &= ~VSW_ATTR_INFO_SENT;
		break;

	case VSW_DRING_INFO_RECV:
		if (phase < VSW_MILESTONE1) {
			DERR(vswp, "vsw_check_flag (%d): DRING_INFO_RECV"
				" when in state %d\n", ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		}
		break;

	case VSW_DRING_ACK_RECV:
	case VSW_DRING_NACK_RECV:
		if (!(state & VSW_DRING_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious DRING_ACK"
				" or DRING_NACK when in state %d\n",
				ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		} else
			state &= ~VSW_DRING_INFO_SENT;
		break;

	case VSW_RDX_INFO_RECV:
		if (phase < VSW_MILESTONE3) {
			DERR(vswp, "vsw_check_flag (%d): RDX_INFO_RECV"
				" when in state %d\n", ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		}
		break;

	case VSW_RDX_ACK_RECV:
	case VSW_RDX_NACK_RECV:
		if (!(state & VSW_RDX_INFO_SENT)) {
			DERR(vswp, "vsw_check_flag (%d): spurious RDX_ACK"
				" or RDX_NACK when in state %d\n",
				ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
			return (1);
		} else
			state &= ~VSW_RDX_INFO_SENT;
		break;

	case VSW_MCST_INFO_RECV:
		if (phase < VSW_MILESTONE3) {
			DERR(vswp, "vsw_check_flag (%d): VSW_MCST_INFO_RECV"
				" when in state %d\n", ldcp->ldc_id, phase);
			vsw_restart_handshake(ldcp);
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
			vsw_restart_handshake(ldcp);
		}

		/*
		 * Only way to pass this milestone is to have successfully
		 * negotiated version info.
		 */
		if ((ldcp->lane_in.lstate & VSW_VER_ACK_SENT) &&
			(ldcp->lane_out.lstate & VSW_VER_ACK_RECV)) {

			D2(vswp, "%s: (chan %lld) leaving milestone 0",
				__func__, ldcp->ldc_id);

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
			if (ldcp->lane_in.xfer_mode == VIO_DRING_MODE)
				vsw_send_dring_info(ldcp);
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
		if ((ldcp->lane_in.xfer_mode == VIO_DRING_MODE) &&
			(!(ldcp->lane_in.lstate & VSW_DRING_ACK_SENT)))
			break;

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
		if ((ldcp->lane_in.lstate & VSW_RDX_ACK_SENT) &&
			(ldcp->lane_out.lstate & VSW_RDX_ACK_RECV)) {

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
			D2(vswp, "%s: still in milestone 3 (0x%llx :"
				" 0x%llx", __func__, ldcp->lane_in.lstate,
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
				D2(NULL, "%s: adjusting minor value"
					" from %d to %d", __func__,
					vp->ver_minor,
					vsw_versions[i].ver_minor);
				vp->ver_minor = vsw_versions[i].ver_minor;
			}

			return (0);
		}

		if (vsw_versions[i].ver_major < vp->ver_major) {
			if (vp->ver_minor > vsw_versions[i].ver_minor) {
				D2(NULL, "%s: adjusting minor value"
					" from %d to %d", __func__,
					vp->ver_minor,
					vsw_versions[i].ver_minor);
				vp->ver_minor = vsw_versions[i].ver_minor;
			}
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
 * Main routine for processing messages received over LDC.
 */
static void
vsw_process_pkt(void *arg)
{
	vsw_ldc_t	*ldcp = (vsw_ldc_t  *)arg;
	vsw_t 		*vswp = ldcp->ldc_vswp;
	size_t		msglen;
	vio_msg_tag_t	tag;
	def_msg_t	dmsg;
	int 		rv = 0;


	D1(vswp, "%s enter: ldcid (%lld)\n", __func__, ldcp->ldc_id);

	/*
	 * If channel is up read messages until channel is empty.
	 */
	do {
		msglen = sizeof (dmsg);
		rv = ldc_read(ldcp->ldc_handle, (caddr_t)&dmsg, &msglen);

		if (rv != 0) {
			DERR(vswp, "%s :ldc_read err id(%lld) rv(%d) "
				"len(%d)\n", __func__, ldcp->ldc_id,
							rv, msglen);
		}

		/* channel has been reset */
		if (rv == ECONNRESET) {
			vsw_handle_reset(ldcp);
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
		bcopy(&dmsg, &tag, sizeof (vio_msg_tag_t));

		switch (tag.vio_msgtype) {
		case VIO_TYPE_CTRL:
			vsw_dispatch_ctrl_task(ldcp, &dmsg, tag);
			break;
		case VIO_TYPE_DATA:
			vsw_process_data_pkt(ldcp, &dmsg, tag);
			break;
		case VIO_TYPE_ERR:
			vsw_process_err_pkt(ldcp, &dmsg, tag);
			break;
		default:
			DERR(vswp, "%s: Unknown tag(%lx) ", __func__,
				"id(%lx)\n", tag.vio_msgtype, ldcp->ldc_id);
			break;
		}
	} while (msglen);

	D1(vswp, "%s exit: ldcid (%lld)\n", __func__, ldcp->ldc_id);
}

/*
 * Dispatch a task to process a VIO control message.
 */
static void
vsw_dispatch_ctrl_task(vsw_ldc_t *ldcp, void *cpkt, vio_msg_tag_t tag)
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
	if ((tag.vio_subtype_env == VIO_RDX) &&
		(tag.vio_subtype == VIO_SUBTYPE_ACK)) {

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_RDX_ACK_RECV))
			return;

		ldcp->lane_out.lstate |= VSW_RDX_ACK_RECV;
		D2(vswp, "%s (%ld) handling RDX_ACK in place "
			"(ostate 0x%llx : hphase %d)", __func__,
			ldcp->ldc_id, ldcp->lane_out.lstate, ldcp->hphase);
		vsw_next_milestone(ldcp);
		return;
	}

	ctaskp = kmem_alloc(sizeof (vsw_ctrl_task_t), KM_NOSLEEP);

	if (ctaskp == NULL) {
		DERR(vswp, "%s: unable to alloc space for ctrl"
			" msg", __func__);
		vsw_restart_handshake(ldcp);
		return;
	}

	ctaskp->ldcp = ldcp;
	bcopy((def_msg_t *)cpkt, &ctaskp->pktp, sizeof (def_msg_t));
	mutex_enter(&ldcp->hss_lock);
	ctaskp->hss_id = ldcp->hss_id;
	mutex_exit(&ldcp->hss_lock);

	/*
	 * Dispatch task to processing taskq if port is not in
	 * the process of being detached.
	 */
	mutex_enter(&port->state_lock);
	if (port->state == VSW_PORT_INIT) {
		if ((vswp->taskq_p == NULL) ||
			(ddi_taskq_dispatch(vswp->taskq_p,
			vsw_process_ctrl_pkt, ctaskp, DDI_NOSLEEP)
							!= DDI_SUCCESS)) {
			DERR(vswp, "%s: unable to dispatch task to taskq",
				__func__);
			kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
			mutex_exit(&port->state_lock);
			vsw_restart_handshake(ldcp);
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
	mutex_enter(&ldcp->hss_lock);
	if (ctaskp->hss_id < ldcp->hss_id) {
		DWARN(vswp, "%s: discarding stale packet belonging to"
			" earlier (%ld) handshake session", __func__,
			ctaskp->hss_id);
		mutex_exit(&ldcp->hss_lock);
		return;
	}
	mutex_exit(&ldcp->hss_lock);

	/* session id check */
	if (ldcp->session_status & VSW_PEER_SESSION) {
		if (ldcp->peer_session != tag.vio_sid) {
			DERR(vswp, "%s (chan %d): invalid session id (%llx)",
				__func__, ldcp->ldc_id, tag.vio_sid);
			kmem_free(ctaskp, sizeof (vsw_ctrl_task_t));
			vsw_restart_handshake(ldcp);
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
		DERR(vswp, "%s : unknown vio_subtype_env (%x)\n",
							__func__, env);
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

			vsw_send_msg(ldcp, (void *)ver_pkt,
					sizeof (vio_ver_msg_t));

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
		vsw_send_msg(ldcp, (void *)ver_pkt, sizeof (vio_ver_msg_t));

		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK\n", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_VER_ACK_RECV))
			return;

		/* Store updated values */
		ldcp->lane_in.ver_major = ver_pkt->ver_major;
		ldcp->lane_in.ver_minor = ver_pkt->ver_minor;


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
				__func__, ver_pkt->ver_major,
				ver_pkt->ver_minor);

			ldcp->lane_out.lstate |= VSW_VER_INFO_SENT;
			ver_pkt->tag.vio_sid = ldcp->local_session;
			ver_pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;

			DUMP_TAG_PTR((vio_msg_tag_t *)ver_pkt);

			vsw_send_msg(ldcp, (void *)ver_pkt,
					sizeof (vio_ver_msg_t));

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
		if (vsw_check_attr(attr_pkt, ldcp->ldc_port)) {

			DERR(vswp, "%s (chan %d): invalid attributes",
				__func__, ldcp->ldc_id);

			vsw_free_lane_resources(ldcp, INBOUND);

			attr_pkt->tag.vio_sid = ldcp->local_session;
			attr_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)attr_pkt);
			ldcp->lane_in.lstate |= VSW_ATTR_NACK_SENT;
			vsw_send_msg(ldcp, (void *)attr_pkt,
					sizeof (vnet_attr_msg_t));

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
		if (ldcp->lane_in.xfer_mode == VIO_DRING_MODE) {
			D2(vswp, "%s: mode = VIO_DRING_MODE", __func__);
			port->transmit = vsw_dringsend;
		} else if (ldcp->lane_in.xfer_mode == VIO_DESC_MODE) {
			D2(vswp, "%s: mode = VIO_DESC_MODE", __func__);
			vsw_create_privring(ldcp);
			port->transmit = vsw_descrsend;
		}
		mutex_exit(&port->tx_lock);

		attr_pkt->tag.vio_sid = ldcp->local_session;
		attr_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;

		DUMP_TAG_PTR((vio_msg_tag_t *)attr_pkt);

		ldcp->lane_in.lstate |= VSW_ATTR_ACK_SENT;

		vsw_send_msg(ldcp, (void *)attr_pkt,
					sizeof (vnet_attr_msg_t));

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

			vsw_send_msg(ldcp, (void *)dring_pkt,
					sizeof (vio_dring_reg_msg_t));

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
			dp->ncookies, dp->num_descriptors,
			dp->descriptor_size, LDC_SHADOW_MAP,
			&(dp->handle))) != 0) {

			DERR(vswp, "%s: dring_map failed\n", __func__);

			kmem_free(dp, sizeof (dring_info_t));
			vsw_free_lane_resources(ldcp, INBOUND);

			dring_pkt->tag.vio_sid = ldcp->local_session;
			dring_pkt->tag.vio_subtype = VIO_SUBTYPE_NACK;

			DUMP_TAG_PTR((vio_msg_tag_t *)dring_pkt);

			ldcp->lane_in.lstate |= VSW_DRING_NACK_SENT;
			vsw_send_msg(ldcp, (void *)dring_pkt,
				sizeof (vio_dring_reg_msg_t));

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
			vsw_send_msg(ldcp, (void *)dring_pkt,
				sizeof (vio_dring_reg_msg_t));

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

		vsw_send_msg(ldcp, (void *)dring_pkt,
				sizeof (vio_dring_reg_msg_t));

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
				vsw_restart_handshake(ldcp);
				return;
			}

		} else {
			DERR(vswp, "%s: DRING ACK received but no drings "
				"allocated", __func__);
			vsw_restart_handshake(ldcp);
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
		vsw_restart_handshake(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		DWARN(vswp, "%s: restarting handshake..", __func__);
		vsw_restart_handshake(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		DWARN(vswp, "%s: restarting handshake..", __func__);
		vsw_restart_handshake(ldcp);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
			dring_pkt->tag.vio_subtype);
		vsw_restart_handshake(ldcp);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

#define	SND_MCST_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	vsw_send_msg(ldcp, (void *)pkt, sizeof (vnet_mcast_msg_t));

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

		vsw_send_msg(ldcp, (void *)mcst_pkt,
					sizeof (vnet_mcast_msg_t));
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

		if (vsw_check_flag(ldcp, INBOUND, VSW_RDX_INFO_RECV))
			return;

		rdx_pkt->tag.vio_sid = ldcp->local_session;
		rdx_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;

		DUMP_TAG_PTR((vio_msg_tag_t *)rdx_pkt);

		ldcp->lane_in.lstate |= VSW_RDX_ACK_SENT;

		vsw_send_msg(ldcp, (void *)rdx_pkt,
				sizeof (vio_rdx_msg_t));

		vsw_next_milestone(ldcp);
		break;

	case VIO_SUBTYPE_ACK:
		/*
		 * Should be handled in-band by callback handler.
		 */
		DERR(vswp, "%s: Unexpected VIO_SUBTYPE_ACK", __func__);
		vsw_restart_handshake(ldcp);
		break;

	case VIO_SUBTYPE_NACK:
		D2(vswp, "%s: VIO_SUBTYPE_NACK", __func__);

		if (vsw_check_flag(ldcp, OUTBOUND, VSW_RDX_NACK_RECV))
			return;

		ldcp->lane_out.lstate |= VSW_RDX_NACK_RECV;
		vsw_next_milestone(ldcp);
		break;

	default:
		DERR(vswp, "%s: Unknown vio_subtype %x\n", __func__,
			rdx_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

static void
vsw_process_data_pkt(vsw_ldc_t *ldcp, void *dpkt, vio_msg_tag_t tag)
{
	uint16_t	env = tag.vio_subtype_env;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "%s(%lld): enter", __func__, ldcp->ldc_id);

	/* session id check */
	if (ldcp->session_status & VSW_PEER_SESSION) {
		if (ldcp->peer_session != tag.vio_sid) {
			DERR(vswp, "%s (chan %d): invalid session id (%llx)",
				__func__, ldcp->ldc_id, tag.vio_sid);
			vsw_restart_handshake(ldcp);
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
		vsw_restart_handshake(ldcp);
		return;
	}

	/*
	 * Switch on vio_subtype envelope, then let lower routines
	 * decide if its an INFO, ACK or NACK packet.
	 */
	if (env == VIO_DRING_DATA) {
		vsw_process_data_dring_pkt(ldcp, dpkt);
	} else if (env == VIO_PKT_DATA) {
		vsw_process_data_raw_pkt(ldcp, dpkt);
	} else if (env == VIO_DESC_DATA) {
		vsw_process_data_ibnd_pkt(ldcp, dpkt);
	} else {
		DERR(vswp, "%s : unknown vio_subtype_env (%x)\n",
							__func__, env);
	}

	D1(vswp, "%s(%lld): exit", __func__, ldcp->ldc_id);
}

#define	SND_DRING_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	vsw_send_msg(ldcp, (void *)pkt, sizeof (vio_dring_msg_t));

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
	size_t			off = 0;
	uint64_t		ncookies = 0;
	uint64_t		chain = 0;
	uint64_t		j, len;
	uint32_t		pos, start, datalen;
	uint32_t		range_start, range_end;
	int32_t			end, num, cnt = 0;
	int			i, rv;
	boolean_t		ack_needed = B_FALSE;
	boolean_t		prev_desc_ack = B_FALSE;
	int			read_attempts = 0;

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

		if ((dp = vsw_ident2dring(&ldcp->lane_in,
				dring_pkt->dring_ident)) == NULL) {

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
			num = end >= pos ?
				end - pos + 1: (len - pos + 1) + end;

			/* basic sanity check */
			if (end > len) {
				DERR(vswp, "%s(%lld): endpoint %lld outside "
					"ring length %lld", __func__,
					ldcp->ldc_id, end, len);

				SND_DRING_NACK(ldcp, dring_pkt);
				return;
			}
		} else {
			DERR(vswp, "%s(%lld): invalid endpoint %lld",
				__func__, ldcp->ldc_id, end);
			SND_DRING_NACK(ldcp, dring_pkt);
			return;
		}

		while (cnt != num) {
vsw_recheck_desc:
			if ((rv = ldc_mem_dring_acquire(dp->handle,
							pos, pos)) != 0) {
				DERR(vswp, "%s(%lld): unable to acquire "
					"descriptor at pos %d: err %d",
					__func__, pos, ldcp->ldc_id, rv);
				SND_DRING_NACK(ldcp, dring_pkt);
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

				D2(vswp, "%s(%lld): updating range start "
					"to be %d", __func__, ldcp->ldc_id,
					range_start);

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

			mp = vio_allocb(ldcp->rxh);
			if (mp == NULL) {
				/*
				 * No free receive buffers available, so
				 * fallback onto allocb(9F). Make sure that
				 * we get a data buffer which is a multiple
				 * of 8 as this is required by ldc_mem_copy.
				 */
				DTRACE_PROBE(allocb);
				mp = allocb(datalen + VNET_IPALIGN + 8,
								BPRI_MED);
			}

			/*
			 * Ensure that we ask ldc for an aligned
			 * number of bytes.
			 */
			nbytes = datalen + VNET_IPALIGN;
			if (nbytes & 0x7) {
				off = 8 - (nbytes & 0x7);
				nbytes += off;
			}

			ncookies = pub_addr->ncookies;
			rv = ldc_mem_copy(ldcp->ldc_handle,
				(caddr_t)mp->b_rptr, 0, &nbytes,
				pub_addr->memcookie, ncookies,
				LDC_COPY_IN);

			if (rv != 0) {
				DERR(vswp, "%s(%d): unable to copy in "
					"data from %d cookies in desc %d"
					" (rv %d)", __func__, ldcp->ldc_id,
					ncookies, pos, rv);
				freemsg(mp);

				pub_addr->hdr.dstate = VIO_DESC_DONE;
				(void) ldc_mem_dring_release(dp->handle,
								pos, pos);
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

			/* build a chain of received packets */
			if (bp == NULL) {
				/* first pkt */
				bp = mp;
				bp->b_next = bp->b_prev = NULL;
				bpt = bp;
				chain = 1;
			} else {
				mp->b_next = NULL;
				mp->b_prev = bpt;
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
					dring_pkt->start_idx,
					dring_pkt->end_idx);

				dring_pkt->dring_process_state = VIO_DP_ACTIVE;
				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_ACK;
				dring_pkt->tag.vio_sid = ldcp->local_session;
				vsw_send_msg(ldcp, (void *)dring_pkt,
					sizeof (vio_dring_msg_t));

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
			/* send the chain of packets to be switched */
			if (chain > vsw_chain_len) {
				D3(vswp, "%s(%lld): switching chain of %d "
					"msgs", __func__, ldcp->ldc_id, chain);
				vsw_switch_frame(vswp, bp, VSW_VNETPORT,
							ldcp->ldc_port, NULL);
				bp = NULL;
				break;
			}
		}

		/* send the chain of packets to be switched */
		if (bp != NULL) {
			D3(vswp, "%s(%lld): switching chain of %d msgs",
					__func__, ldcp->ldc_id, chain);
			vsw_switch_frame(vswp, bp, VSW_VNETPORT,
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

		vsw_send_msg(ldcp, (void *)dring_pkt,
					sizeof (vio_dring_msg_t));
		break;

	case VIO_SUBTYPE_ACK:
		D2(vswp, "%s(%lld): VIO_SUBTYPE_ACK", __func__, ldcp->ldc_id);
		/*
		 * Verify that the relevant descriptors are all
		 * marked as DONE
		 */
		if ((dp = vsw_ident2dring(&ldcp->lane_out,
			dring_pkt->dring_ident)) == NULL) {
			DERR(vswp, "%s: unknown ident in ACK", __func__);
			return;
		}

		pub_addr = (vnet_public_desc_t *)dp->pub_addr;
		priv_addr = (vsw_private_desc_t *)dp->priv_addr;

		start = end = 0;
		start = dring_pkt->start_idx;
		end = dring_pkt->end_idx;
		len = dp->num_descriptors;

		j = num = 0;
		/* calculate # descriptors taking into a/c wrap around */
		num = end >= start ? end - start + 1: (len - start + 1) + end;

		D2(vswp, "%s(%lld): start index %ld : end %ld : num %ld\n",
			__func__, ldcp->ldc_id, start, end, num);

		mutex_enter(&dp->dlock);
		dp->last_ack_recv = end;
		mutex_exit(&dp->dlock);

		for (i = start; j < num; i = (i + 1) % len, j++) {
			pub_addr = (vnet_public_desc_t *)dp->pub_addr + i;
			priv_addr = (vsw_private_desc_t *)dp->priv_addr + i;

			/*
			 * If the last descriptor in a range has the ACK
			 * bit set then we will get two messages from our
			 * peer relating to it. The normal ACK msg and then
			 * a subsequent STOP msg. The first message will have
			 * resulted in the descriptor being reclaimed and
			 * its state set to FREE so when we encounter a non
			 * DONE descriptor we need to check to see if its
			 * because we have just reclaimed it.
			 */
			mutex_enter(&priv_addr->dstate_lock);
			if (pub_addr->hdr.dstate == VIO_DESC_DONE) {
				/* clear all the fields */
				bzero(priv_addr->datap, priv_addr->datalen);
				priv_addr->datalen = 0;

				pub_addr->hdr.dstate = VIO_DESC_FREE;
				pub_addr->hdr.ack = 0;

				priv_addr->dstate = VIO_DESC_FREE;
				mutex_exit(&priv_addr->dstate_lock);

				D3(vswp, "clearing descp %d : pub state "
					"0x%llx : priv state 0x%llx", i,
					pub_addr->hdr.dstate,
					priv_addr->dstate);

			} else {
				mutex_exit(&priv_addr->dstate_lock);

				if (dring_pkt->dring_process_state !=
							VIO_DP_STOPPED) {
					DERR(vswp, "%s: descriptor %lld at pos "
						" 0x%llx not DONE (0x%lx)\n",
						__func__, i, pub_addr,
						pub_addr->hdr.dstate);
					return;
				}
			}
		}

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
			mutex_enter(&priv_addr->dstate_lock);
			if (pub_addr->hdr.dstate == VIO_DESC_READY) {

				mutex_exit(&priv_addr->dstate_lock);

				dring_pkt->tag.vio_subtype = VIO_SUBTYPE_INFO;
				dring_pkt->tag.vio_sid = ldcp->local_session;

				mutex_enter(&ldcp->lane_out.seq_lock);
				dring_pkt->seq_num = ldcp->lane_out.seq_num++;
				mutex_exit(&ldcp->lane_out.seq_lock);

				dring_pkt->start_idx = (end + 1) % len;
				dring_pkt->end_idx = -1;

				D2(vswp, "%s(%lld) : sending restart msg:"
					" %d : %d", __func__, ldcp->ldc_id,
					dring_pkt->start_idx,
					dring_pkt->end_idx);

				vsw_send_msg(ldcp, (void *)dring_pkt,
						sizeof (vio_dring_msg_t));
			} else {
				mutex_exit(&priv_addr->dstate_lock);
				dp->restart_reqd = B_TRUE;
			}
			mutex_exit(&dp->restart_lock);
		}
		break;

	case VIO_SUBTYPE_NACK:
		DWARN(vswp, "%s(%lld): VIO_SUBTYPE_NACK",
						__func__, ldcp->ldc_id);
		/*
		 * Something is badly wrong if we are getting NACK's
		 * for our data pkts. So reset the channel.
		 */
		vsw_restart_handshake(ldcp);

		break;

	default:
		DERR(vswp, "%s(%lld): Unknown vio_subtype %x\n", __func__,
			ldcp->ldc_id, dring_pkt->tag.vio_subtype);
	}

	D1(vswp, "%s(%lld) exit", __func__, ldcp->ldc_id);
}

/*
 * VIO_PKT_DATA (a.k.a raw data mode )
 *
 * Note - currently not supported. Do nothing.
 */
static void
vsw_process_data_raw_pkt(vsw_ldc_t *ldcp, void *dpkt)
{
	_NOTE(ARGUNUSED(dpkt))

	D1(NULL, "%s (%lld): enter\n", __func__, ldcp->ldc_id);

	DERR(NULL, "%s (%lld): currently  not supported",
						__func__, ldcp->ldc_id);

	D1(NULL, "%s (%lld): exit\n", __func__, ldcp->ldc_id);
}

#define	SND_IBND_DESC_NACK(ldcp, pkt) \
	pkt->tag.vio_subtype = VIO_SUBTYPE_NACK; \
	pkt->tag.vio_sid = ldcp->local_session; \
	vsw_send_msg(ldcp, (void *)pkt, sizeof (vio_ibnd_desc_t));

/*
 * Process an in-band descriptor message (most likely from
 * OBP).
 */
static void
vsw_process_data_ibnd_pkt(vsw_ldc_t *ldcp, void *pkt)
{
	vio_ibnd_desc_t		*ibnd_desc;
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

	ibnd_desc = (vio_ibnd_desc_t *)pkt;

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
			return;
		}

		rv = ldc_mem_copy(ldcp->ldc_handle, (caddr_t)mp->b_rptr,
			0, &nbytes, ibnd_desc->memcookie, (uint64_t)ncookies,
			LDC_COPY_IN);

		if (rv != 0) {
			DERR(vswp, "%s(%d): unable to copy in data from "
				"%d cookie(s)", __func__,
				ldcp->ldc_id, ncookies);
			freemsg(mp);
			return;
		} else {
			D2(vswp, "%s(%d): copied in %ld bytes using %d "
				"cookies", __func__, ldcp->ldc_id, nbytes,
				ncookies);
		}

		/* point to the actual end of data */
		mp->b_wptr = mp->b_rptr + datalen;

		/*
		 * We ACK back every in-band descriptor message we process
		 */
		ibnd_desc->hdr.tag.vio_subtype = VIO_SUBTYPE_ACK;
		ibnd_desc->hdr.tag.vio_sid = ldcp->local_session;
		vsw_send_msg(ldcp, (void *)ibnd_desc,
				sizeof (vio_ibnd_desc_t));

		/* send the packet to be switched */
		vsw_switch_frame(vswp, mp, VSW_VNETPORT,
					ldcp->ldc_port, NULL);

		break;

	case VIO_SUBTYPE_ACK:
		D1(vswp, "%s: VIO_SUBTYPE_ACK", __func__);

		/* Verify the ACK is valid */
		idx = ibnd_desc->hdr.desc_handle;

		if (idx >= VSW_RING_NUM_EL) {
			cmn_err(CE_WARN, "%s: corrupted ACK received "
				"(idx %ld)", __func__, idx);
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
			bzero(priv_addr->datap, priv_addr->datalen);
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

		if (idx >= VSW_RING_NUM_EL) {
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
		bzero(priv_addr->datap, priv_addr->datalen);
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
vsw_process_err_pkt(vsw_ldc_t *ldcp, void *epkt, vio_msg_tag_t tag)
{
	_NOTE(ARGUNUSED(epkt))

	vsw_t		*vswp = ldcp->ldc_vswp;
	uint16_t	env = tag.vio_subtype_env;

	D1(vswp, "%s (%lld): enter\n", __func__, ldcp->ldc_id);

	/*
	 * Error vio_subtypes have yet to be defined. So for
	 * the moment we can't do anything.
	 */
	D2(vswp, "%s: (%x) vio_subtype env", __func__, env);

	D1(vswp, "%s (%lld): exit\n", __func__, ldcp->ldc_id);
}

/*
 * Switch the given ethernet frame when operating in layer 2 mode.
 *
 * vswp: pointer to the vsw instance
 * mp: pointer to chain of ethernet frame(s) to be switched
 * caller: identifies the source of this frame as:
 * 		1. VSW_VNETPORT - a vsw port (connected to a vnet).
 *		2. VSW_PHYSDEV - the physical ethernet device
 *		3. VSW_LOCALDEV - vsw configured as a virtual interface
 * arg: argument provided by the caller.
 *		1. for VNETPORT - pointer to the corresponding vsw_port_t.
 *		2. for PHYSDEV - NULL
 *		3. for LOCALDEV - pointer to to this vsw_t(self)
 */
void
vsw_switch_l2_frame(vsw_t *vswp, mblk_t *mp, int caller,
			vsw_port_t *arg, mac_resource_handle_t mrh)
{
	struct ether_header	*ehp;
	vsw_port_t		*port = NULL;
	mblk_t			*bp, *ret_m;
	mblk_t			*nmp = NULL;
	vsw_port_list_t		*plist = &vswp->plist;

	D1(vswp, "%s: enter (caller %d)", __func__, caller);

	/*
	 * PERF: rather than breaking up the chain here, scan it
	 * to find all mblks heading to same destination and then
	 * pass that sub-chain to the lower transmit functions.
	 */

	/* process the chain of packets */
	bp = mp;
	while (bp) {
		mp = bp;
		bp = bp->b_next;
		mp->b_next = mp->b_prev = NULL;
		ehp = (struct ether_header *)mp->b_rptr;

		D2(vswp, "%s: mblk data buffer %lld : actual data size %lld",
			__func__, MBLKSIZE(mp), MBLKL(mp));

		READ_ENTER(&vswp->if_lockrw);
		if (ether_cmp(&ehp->ether_dhost, &vswp->if_addr) == 0) {
			/*
			 * If destination is VSW_LOCALDEV (vsw as an eth
			 * interface) and if the device is up & running,
			 * send the packet up the stack on this host.
			 * If the virtual interface is down, drop the packet.
			 */
			if (caller != VSW_LOCALDEV) {
				if (vswp->if_state & VSW_IF_UP) {
					RW_EXIT(&vswp->if_lockrw);
					mac_rx(vswp->if_mh, mrh, mp);
				} else {
					RW_EXIT(&vswp->if_lockrw);
					/* Interface down, drop pkt */
					freemsg(mp);
				}
			} else {
				RW_EXIT(&vswp->if_lockrw);
				freemsg(mp);
			}
			continue;
		}
		RW_EXIT(&vswp->if_lockrw);

		READ_ENTER(&plist->lockrw);
		port = vsw_lookup_fdb(vswp, ehp);
		if (port) {
			/*
			 * Mark the port as in-use.
			 */
			mutex_enter(&port->ref_lock);
			port->ref_cnt++;
			mutex_exit(&port->ref_lock);
			RW_EXIT(&plist->lockrw);

			/*
			 * If plumbed and in promisc mode then copy msg
			 * and send up the stack.
			 */
			READ_ENTER(&vswp->if_lockrw);
			if (VSW_U_P(vswp->if_state)) {
				RW_EXIT(&vswp->if_lockrw);
				nmp = copymsg(mp);
				if (nmp)
					mac_rx(vswp->if_mh, mrh, nmp);
			} else {
				RW_EXIT(&vswp->if_lockrw);
			}

			/*
			 * If the destination is in FDB, the packet
			 * should be forwarded to the correponding
			 * vsw_port (connected to a vnet device -
			 * VSW_VNETPORT)
			 */
			(void) vsw_portsend(port, mp);

			/*
			 * Decrement use count in port and check if
			 * should wake delete thread.
			 */
			mutex_enter(&port->ref_lock);
			port->ref_cnt--;
			if (port->ref_cnt == 0)
				cv_signal(&port->ref_cv);
			mutex_exit(&port->ref_lock);
		} else {
			RW_EXIT(&plist->lockrw);
			/*
			 * Destination not in FDB.
			 *
			 * If the destination is broadcast or
			 * multicast forward the packet to all
			 * (VNETPORTs, PHYSDEV, LOCALDEV),
			 * except the caller.
			 */
			if (IS_BROADCAST(ehp)) {
				D3(vswp, "%s: BROADCAST pkt", __func__);
				(void) vsw_forward_all(vswp, mp,
								caller, arg);
			} else if (IS_MULTICAST(ehp)) {
				D3(vswp, "%s: MULTICAST pkt", __func__);
				(void) vsw_forward_grp(vswp, mp,
							caller, arg);
			} else {
				/*
				 * If the destination is unicast, and came
				 * from either a logical network device or
				 * the switch itself when it is plumbed, then
				 * send it out on the physical device and also
				 * up the stack if the logical interface is
				 * in promiscious mode.
				 *
				 * NOTE:  The assumption here is that if we
				 * cannot find the destination in our fdb, its
				 * a unicast address, and came from either a
				 * vnet or down the stack (when plumbed) it
				 * must be destinded for an ethernet device
				 * outside our ldoms.
				 */
				if (caller == VSW_VNETPORT) {
					READ_ENTER(&vswp->if_lockrw);
					if (VSW_U_P(vswp->if_state)) {
						RW_EXIT(&vswp->if_lockrw);
						nmp = copymsg(mp);
						if (nmp)
							mac_rx(vswp->if_mh,
								mrh, nmp);
					} else {
						RW_EXIT(&vswp->if_lockrw);
					}
					if ((ret_m = vsw_tx_msg(vswp, mp))
								!= NULL) {
						DERR(vswp, "%s: drop mblks to "
							"phys dev", __func__);
						freemsg(ret_m);
					}

				} else if (caller == VSW_PHYSDEV) {
					/*
					 * Pkt seen because card in promisc
					 * mode. Send up stack if plumbed in
					 * promisc mode, else drop it.
					 */
					READ_ENTER(&vswp->if_lockrw);
					if (VSW_U_P(vswp->if_state)) {
						RW_EXIT(&vswp->if_lockrw);
						mac_rx(vswp->if_mh, mrh, mp);
					} else {
						RW_EXIT(&vswp->if_lockrw);
						freemsg(mp);
					}

				} else if (caller == VSW_LOCALDEV) {
					/*
					 * Pkt came down the stack, send out
					 * over physical device.
					 */
					if ((ret_m = vsw_tx_msg(vswp, mp))
								!= NULL) {
						DERR(vswp, "%s: drop mblks to "
							"phys dev", __func__);
						freemsg(ret_m);
					}
				}
			}
		}
	}
	D1(vswp, "%s: exit\n", __func__);
}

/*
 * Switch ethernet frame when in layer 3 mode (i.e. using IP
 * layer to do the routing).
 *
 * There is a large amount of overlap between this function and
 * vsw_switch_l2_frame. At some stage we need to revisit and refactor
 * both these functions.
 */
void
vsw_switch_l3_frame(vsw_t *vswp, mblk_t *mp, int caller,
			vsw_port_t *arg, mac_resource_handle_t mrh)
{
	struct ether_header	*ehp;
	vsw_port_t		*port = NULL;
	mblk_t			*bp = NULL;
	vsw_port_list_t		*plist = &vswp->plist;

	D1(vswp, "%s: enter (caller %d)", __func__, caller);

	/*
	 * In layer 3 mode should only ever be switching packets
	 * between IP layer and vnet devices. So make sure thats
	 * who is invoking us.
	 */
	if ((caller != VSW_LOCALDEV) && (caller != VSW_VNETPORT)) {
		DERR(vswp, "%s: unexpected caller (%d)", __func__, caller);
		freemsgchain(mp);
		return;
	}

	/* process the chain of packets */
	bp = mp;
	while (bp) {
		mp = bp;
		bp = bp->b_next;
		mp->b_next = mp->b_prev = NULL;
		ehp = (struct ether_header *)mp->b_rptr;

		D2(vswp, "%s: mblk data buffer %lld : actual data size %lld",
			__func__, MBLKSIZE(mp), MBLKL(mp));

		READ_ENTER(&plist->lockrw);
		port = vsw_lookup_fdb(vswp, ehp);
		if (port) {
			/*
			 * Mark port as in-use.
			 */
			mutex_enter(&port->ref_lock);
			port->ref_cnt++;
			mutex_exit(&port->ref_lock);
			RW_EXIT(&plist->lockrw);

			D2(vswp, "%s: sending to target port", __func__);
			(void) vsw_portsend(port, mp);

			/*
			 * Finished with port so decrement ref count and
			 * check if should wake delete thread.
			 */
			mutex_enter(&port->ref_lock);
			port->ref_cnt--;
			if (port->ref_cnt == 0)
				cv_signal(&port->ref_cv);
			mutex_exit(&port->ref_lock);
		} else {
			RW_EXIT(&plist->lockrw);
			/*
			 * Destination not in FDB
			 *
			 * If the destination is broadcast or
			 * multicast forward the packet to all
			 * (VNETPORTs, PHYSDEV, LOCALDEV),
			 * except the caller.
			 */
			if (IS_BROADCAST(ehp)) {
				D2(vswp, "%s: BROADCAST pkt", __func__);
				(void) vsw_forward_all(vswp, mp,
								caller, arg);
			} else if (IS_MULTICAST(ehp)) {
				D2(vswp, "%s: MULTICAST pkt", __func__);
				(void) vsw_forward_grp(vswp, mp,
							caller, arg);
			} else {
				/*
				 * Unicast pkt from vnet that we don't have
				 * an FDB entry for, so must be destinded for
				 * the outside world. Attempt to send up to the
				 * IP layer to allow it to deal with it.
				 */
				if (caller == VSW_VNETPORT) {
					READ_ENTER(&vswp->if_lockrw);
					if (vswp->if_state & VSW_IF_UP) {
						RW_EXIT(&vswp->if_lockrw);
						D2(vswp, "%s: sending up",
							__func__);
						mac_rx(vswp->if_mh, mrh, mp);
					} else {
						RW_EXIT(&vswp->if_lockrw);
						/* Interface down, drop pkt */
						D2(vswp, "%s I/F down",
								__func__);
						freemsg(mp);
					}
				}
			}
		}
	}

	D1(vswp, "%s: exit", __func__);
}

/*
 * Forward the ethernet frame to all ports (VNETPORTs, PHYSDEV, LOCALDEV),
 * except the caller (port on which frame arrived).
 */
static int
vsw_forward_all(vsw_t *vswp, mblk_t *mp, int caller, vsw_port_t *arg)
{
	vsw_port_list_t	*plist = &vswp->plist;
	vsw_port_t	*portp;
	mblk_t		*nmp = NULL;
	mblk_t		*ret_m = NULL;
	int		skip_port = 0;

	D1(vswp, "vsw_forward_all: enter\n");

	/*
	 * Broadcast message from inside ldoms so send to outside
	 * world if in either of layer 2 modes.
	 */
	if (((vswp->smode[vswp->smode_idx] == VSW_LAYER2) ||
		(vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC)) &&
		((caller == VSW_LOCALDEV) || (caller == VSW_VNETPORT))) {

		nmp = dupmsg(mp);
		if (nmp) {
			if ((ret_m = vsw_tx_msg(vswp, nmp)) != NULL) {
				DERR(vswp, "%s: dropping pkt(s) "
				"consisting of %ld bytes of data for"
				" physical device", __func__, MBLKL(ret_m));
			freemsg(ret_m);
			}
		}
	}

	if (caller == VSW_VNETPORT)
		skip_port = 1;

	/*
	 * Broadcast message from other vnet (layer 2 or 3) or outside
	 * world (layer 2 only), send up stack if plumbed.
	 */
	if ((caller == VSW_PHYSDEV) || (caller == VSW_VNETPORT)) {
		READ_ENTER(&vswp->if_lockrw);
		if (vswp->if_state & VSW_IF_UP) {
			RW_EXIT(&vswp->if_lockrw);
			nmp = copymsg(mp);
			if (nmp)
				mac_rx(vswp->if_mh, NULL, nmp);
		} else {
			RW_EXIT(&vswp->if_lockrw);
		}
	}

	/* send it to all VNETPORTs */
	READ_ENTER(&plist->lockrw);
	for (portp = plist->head; portp != NULL; portp = portp->p_next) {
		D2(vswp, "vsw_forward_all: port %d", portp->p_instance);
		/*
		 * Caution ! - don't reorder these two checks as arg
		 * will be NULL if the caller is PHYSDEV. skip_port is
		 * only set if caller is VNETPORT.
		 */
		if ((skip_port) && (portp == arg))
			continue;
		else {
			nmp = dupmsg(mp);
			if (nmp) {
				(void) vsw_portsend(portp, nmp);
			} else {
				DERR(vswp, "vsw_forward_all: nmp NULL");
			}
		}
	}
	RW_EXIT(&plist->lockrw);

	freemsg(mp);

	D1(vswp, "vsw_forward_all: exit\n");
	return (0);
}

/*
 * Forward pkts to any devices or interfaces which have registered
 * an interest in them (i.e. multicast groups).
 */
static int
vsw_forward_grp(vsw_t *vswp, mblk_t *mp, int caller, vsw_port_t *arg)
{
	struct ether_header	*ehp = (struct ether_header *)mp->b_rptr;
	mfdb_ent_t		*entp = NULL;
	mfdb_ent_t		*tpp = NULL;
	vsw_port_t 		*port;
	uint64_t		key = 0;
	mblk_t			*nmp = NULL;
	mblk_t			*ret_m = NULL;
	boolean_t		check_if = B_TRUE;

	/*
	 * Convert address to hash table key
	 */
	KEY_HASH(key, ehp->ether_dhost);

	D1(vswp, "%s: key 0x%llx", __func__, key);

	/*
	 * If pkt came from either a vnet or down the stack (if we are
	 * plumbed) and we are in layer 2 mode, then we send the pkt out
	 * over the physical adapter, and then check to see if any other
	 * vnets are interested in it.
	 */
	if (((vswp->smode[vswp->smode_idx] == VSW_LAYER2) ||
		(vswp->smode[vswp->smode_idx] == VSW_LAYER2_PROMISC)) &&
		((caller == VSW_VNETPORT) || (caller == VSW_LOCALDEV))) {
		nmp = dupmsg(mp);
		if (nmp) {
			if ((ret_m = vsw_tx_msg(vswp, nmp)) != NULL) {
				DERR(vswp, "%s: dropping pkt(s) "
					"consisting of %ld bytes of "
					"data for physical device",
					__func__, MBLKL(ret_m));
				freemsg(ret_m);
			}
		}
	}

	READ_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)key,
				(mod_hash_val_t *)&entp) != 0) {
		D3(vswp, "%s: no table entry found for addr 0x%llx",
								__func__, key);
	} else {
		/*
		 * Send to list of devices associated with this address...
		 */
		for (tpp = entp; tpp != NULL; tpp = tpp->nextp) {

			/* dont send to ourselves */
			if ((caller == VSW_VNETPORT) &&
				(tpp->d_addr == (void *)arg)) {
				port = (vsw_port_t *)tpp->d_addr;
				D3(vswp, "%s: not sending to ourselves"
					" : port %d", __func__,
					port->p_instance);
				continue;

			} else if ((caller == VSW_LOCALDEV) &&
				(tpp->d_type == VSW_LOCALDEV)) {
				D3(vswp, "%s: not sending back up stack",
					__func__);
				continue;
			}

			if (tpp->d_type == VSW_VNETPORT) {
				port = (vsw_port_t *)tpp->d_addr;
				D3(vswp, "%s: sending to port %ld for "
					" addr 0x%llx", __func__,
					port->p_instance, key);

				nmp = dupmsg(mp);
				if (nmp)
					(void) vsw_portsend(port, nmp);
			} else {
				if (vswp->if_state & VSW_IF_UP) {
					nmp = copymsg(mp);
					if (nmp)
						mac_rx(vswp->if_mh, NULL, nmp);
					check_if = B_FALSE;
					D3(vswp, "%s: sending up stack"
						" for addr 0x%llx", __func__,
						key);
				}
			}
		}
	}

	RW_EXIT(&vswp->mfdbrw);

	/*
	 * If the pkt came from either a vnet or from physical device,
	 * and if we havent already sent the pkt up the stack then we
	 * check now if we can/should (i.e. the interface is plumbed
	 * and in promisc mode).
	 */
	if ((check_if) &&
		((caller == VSW_VNETPORT) || (caller == VSW_PHYSDEV))) {
		READ_ENTER(&vswp->if_lockrw);
		if (VSW_U_P(vswp->if_state)) {
			RW_EXIT(&vswp->if_lockrw);
			D3(vswp, "%s: (caller %d) finally sending up stack"
				" for addr 0x%llx", __func__, caller, key);
			nmp = copymsg(mp);
			if (nmp)
				mac_rx(vswp->if_mh, NULL, nmp);
		} else {
			RW_EXIT(&vswp->if_lockrw);
		}
	}

	freemsg(mp);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/* transmit the packet over the given port */
static int
vsw_portsend(vsw_port_t *port, mblk_t *mp)
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
		freemsg(mp);
		RW_EXIT(&ldcl->lockrw);
		return (1);
	}

	/*
	 * Send the message out using the appropriate
	 * transmit function which will free mblock when it
	 * is finished with it.
	 */
	mutex_enter(&port->tx_lock);
	if (port->transmit != NULL)
		status = (*port->transmit)(ldcp, mp);
	else {
		freemsg(mp);
	}
	mutex_exit(&port->tx_lock);

	RW_EXIT(&ldcl->lockrw);

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

	D1(vswp, "%s(%lld): enter\n", __func__, ldcp->ldc_id);

	/* TODO: make test a macro */
	if ((!(ldcp->lane_out.lstate & VSW_LANE_ACTIVE)) ||
		(ldcp->ldc_status != LDC_UP) || (ldcp->ldc_handle == NULL)) {
		DWARN(vswp, "%s(%lld) status(%d) lstate(0x%llx), dropping "
			"packet\n", __func__, ldcp->ldc_id, ldcp->ldc_status,
			ldcp->lane_out.lstate);
		freemsg(mp);
		return (LDC_TX_FAILURE);
	}

	/*
	 * Note - using first ring only, this may change
	 * in the future.
	 */
	if ((dp = ldcp->lane_out.dringp) == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane on"
			" channel %d", __func__, ldcp->ldc_id, ldcp->ldc_id);
		freemsg(mp);
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)ETHERMAX) {
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		freemsg(mp);
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
		goto vsw_dringsend_free_exit;
	} else {
		D2(vswp, "%s(%lld): free private descriptor found at pos "
			"%ld addr 0x%llx\n", __func__, ldcp->ldc_id, idx,
			priv_desc);
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

		mutex_enter(&ldcp->lane_out.seq_lock);
		dring_pkt.seq_num = ldcp->lane_out.seq_num++;
		mutex_exit(&ldcp->lane_out.seq_lock);

		/*
		 * If last_ack_recv is -1 then we know we've not
		 * received any ack's yet, so this must be the first
		 * msg sent, so set the start to the begining of the ring.
		 */
		mutex_enter(&dp->dlock);
		if (dp->last_ack_recv == -1) {
			dring_pkt.start_idx = 0;
		} else {
			dring_pkt.start_idx = (dp->last_ack_recv + 1) %
						dp->num_descriptors;
		}
		dring_pkt.end_idx = -1;
		mutex_exit(&dp->dlock);

		D3(vswp, "%s(%lld): dring 0x%llx : ident 0x%llx\n", __func__,
			ldcp->ldc_id, dp, dring_pkt.dring_ident);
		D3(vswp, "%s(%lld): start %lld : end %lld : seq %lld\n",
			__func__, ldcp->ldc_id, dring_pkt.start_idx,
			dring_pkt.end_idx, dring_pkt.seq_num);

		vsw_send_msg(ldcp, (void *)&dring_pkt,
						sizeof (vio_dring_msg_t));
	} else {
		mutex_exit(&dp->restart_lock);
		D2(vswp, "%s(%lld): updating descp %d", __func__,
			ldcp->ldc_id, idx);
	}

vsw_dringsend_free_exit:

	/* free the message block */
	freemsg(mp);

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
	vio_ibnd_desc_t		ibnd_msg;
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
		freemsg(mp);
		return (LDC_TX_FAILURE);
	}

	/*
	 * only expect single dring to exist, which we use
	 * as an internal buffer, rather than a transfer channel.
	 */
	if ((dp = ldcp->lane_out.dringp) == NULL) {
		DERR(vswp, "%s(%lld): no dring for outbound lane",
			__func__, ldcp->ldc_id);
		DERR(vswp, "%s(%lld) status(%d) state (0x%llx)",
			__func__, ldcp->ldc_id, ldcp->ldc_status,
			ldcp->lane_out.lstate);
		freemsg(mp);
		return (LDC_TX_FAILURE);
	}

	size = msgsize(mp);
	if (size > (size_t)ETHERMAX) {
		DERR(vswp, "%s(%lld) invalid size (%ld)\n", __func__,
		    ldcp->ldc_id, size);
		freemsg(mp);
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
			"%ld addr 0x%x\n", __func__, ldcp->ldc_id, idx,
			priv_desc);
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

	mutex_enter(&ldcp->lane_out.seq_lock);
	ibnd_msg.hdr.seq_num = ldcp->lane_out.seq_num++;
	mutex_exit(&ldcp->lane_out.seq_lock);

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

	vsw_send_msg(ldcp, (void *)&ibnd_msg, sizeof (vio_ibnd_desc_t));

vsw_descrsend_free_exit:

	/* free the allocated message blocks */
	freemsg(mp);

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

	ver_msg.ver_major = vsw_versions[0].ver_major;
	ver_msg.ver_minor = vsw_versions[0].ver_minor;
	ver_msg.dev_class = VDEV_NETWORK_SWITCH;

	lp->lstate |= VSW_VER_INFO_SENT;
	lp->ver_major = ver_msg.ver_major;
	lp->ver_minor = ver_msg.ver_minor;

	DUMP_TAG(ver_msg.tag);

	vsw_send_msg(ldcp, &ver_msg, sizeof (vio_ver_msg_t));

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
	bcopy(&(vswp->if_addr), &(attr_msg.addr), ETHERADDRL);
	RW_EXIT(&vswp->if_lockrw);

	ldcp->lane_out.lstate |= VSW_ATTR_INFO_SENT;

	DUMP_TAG(attr_msg.tag);

	vsw_send_msg(ldcp, &attr_msg, sizeof (vnet_attr_msg_t));

	D1(vswp, "%s (%ld) enter", __func__, ldcp->ldc_id);
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
		cmn_err(CE_WARN, "vsw_send_dring_info: error creating msg");
		return;
	}

	ldcp->lane_out.lstate |= VSW_DRING_INFO_SENT;

	DUMP_TAG_PTR((vio_msg_tag_t *)dring_msg);

	vsw_send_msg(ldcp, dring_msg,
		sizeof (vio_dring_reg_msg_t));

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

	ldcp->lane_out.lstate |= VSW_RDX_INFO_SENT;

	DUMP_TAG(rdx_msg.tag);

	vsw_send_msg(ldcp, &rdx_msg, sizeof (vio_rdx_msg_t));

	D1(vswp, "%s (%ld) exit", __func__, ldcp->ldc_id);
}

/*
 * Generic routine to send message out over ldc channel.
 */
static void
vsw_send_msg(vsw_ldc_t *ldcp, void *msgp, int size)
{
	int		rv;
	size_t		msglen = size;
	vio_msg_tag_t	*tag = (vio_msg_tag_t *)msgp;
	vsw_t		*vswp = ldcp->ldc_vswp;

	D1(vswp, "vsw_send_msg (%lld) enter : sending %d bytes",
			ldcp->ldc_id, size);

	D2(vswp, "send_msg: type 0x%llx", tag->vio_msgtype);
	D2(vswp, "send_msg: stype 0x%llx", tag->vio_subtype);
	D2(vswp, "send_msg: senv 0x%llx", tag->vio_subtype_env);

	mutex_enter(&ldcp->ldc_txlock);
	do {
		msglen = size;
		rv = ldc_write(ldcp->ldc_handle, (caddr_t)msgp, &msglen);
	} while (rv == EWOULDBLOCK && --vsw_wretries > 0);

	if ((rv != 0) || (msglen != size)) {
		DERR(vswp, "vsw_send_msg:ldc_write failed: chan(%lld) "
			"rv(%d) size (%d) msglen(%d)\n", ldcp->ldc_id,
			rv, size, msglen);
	}
	mutex_exit(&ldcp->ldc_txlock);

	/* channel has been reset */
	if (rv == ECONNRESET) {
		vsw_handle_reset(ldcp);
	}

	D1(vswp, "vsw_send_msg (%lld) exit : sent %d bytes",
			ldcp->ldc_id, msglen);
}

/*
 * Add an entry into FDB, for the given mac address and port_id.
 * Returns 0 on success, 1 on failure.
 *
 * Lock protecting FDB must be held by calling process.
 */
static int
vsw_add_fdb(vsw_t *vswp, vsw_port_t *port)
{
	uint64_t	addr = 0;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(addr, port->p_macaddr);

	D2(vswp, "%s: key = 0x%llx", __func__, addr);

	/*
	 * Note: duplicate keys will be rejected by mod_hash.
	 */
	if (mod_hash_insert(vswp->fdb, (mod_hash_key_t)addr,
				(mod_hash_val_t)port) != 0) {
		DERR(vswp, "%s: unable to add entry into fdb.", __func__);
		return (1);
	}

	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Remove an entry from FDB.
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_del_fdb(vsw_t *vswp, vsw_port_t *port)
{
	uint64_t	addr = 0;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(addr, port->p_macaddr);

	D2(vswp, "%s: key = 0x%llx", __func__, addr);

	(void) mod_hash_destroy(vswp->fdb, (mod_hash_val_t)addr);

	D1(vswp, "%s: enter", __func__);

	return (0);
}

/*
 * Search fdb for a given mac address.
 * Returns pointer to the entry if found, else returns NULL.
 */
static vsw_port_t *
vsw_lookup_fdb(vsw_t *vswp, struct ether_header *ehp)
{
	uint64_t	key = 0;
	vsw_port_t	*port = NULL;

	D1(vswp, "%s: enter", __func__);

	KEY_HASH(key, ehp->ether_dhost);

	D2(vswp, "%s: key = 0x%llx", __func__, key);

	if (mod_hash_find(vswp->fdb, (mod_hash_key_t)key,
				(mod_hash_val_t *)&port) != 0) {
		return (NULL);
	}

	D1(vswp, "%s: exit", __func__);

	return (port);
}

/*
 * Add or remove multicast address(es).
 *
 * Returns 0 on success, 1 on failure.
 */
static int
vsw_add_rem_mcst(vnet_mcast_msg_t *mcst_pkt, vsw_port_t *port)
{
	mcst_addr_t		*mcst_p = NULL;
	vsw_t			*vswp = port->p_vswp;
	uint64_t		addr = 0x0;
	int			i, ret;

	D1(vswp, "%s: enter", __func__);

	D2(vswp, "%s: %d addresses", __func__, mcst_pkt->count);

	if (vswp->mh == NULL)
		return (1);

	for (i = 0; i < mcst_pkt->count; i++) {
		/*
		 * Convert address into form that can be used
		 * as hash table key.
		 */
		KEY_HASH(addr, mcst_pkt->mca[i]);

		/*
		 * Add or delete the specified address/port combination.
		 */
		if (mcst_pkt->set == 0x1) {
			D3(vswp, "%s: adding multicast address 0x%llx for "
				"port %ld", __func__, addr, port->p_instance);
			if (vsw_add_mcst(vswp, VSW_VNETPORT, addr, port) == 0) {
				/*
				 * Update the list of multicast
				 * addresses contained within the
				 * port structure to include this new
				 * one.
				 */
				mcst_p = kmem_alloc(sizeof (mcst_addr_t),
								KM_NOSLEEP);
				if (mcst_p == NULL) {
					DERR(vswp, "%s: unable to alloc mem",
						__func__);
					return (1);
				}

				mcst_p->nextp = NULL;
				mcst_p->addr = addr;

				mutex_enter(&port->mca_lock);
				mcst_p->nextp = port->mcap;
				port->mcap = mcst_p;
				mutex_exit(&port->mca_lock);

				/*
				 * Program the address into HW. If the addr
				 * has already been programmed then the MAC
				 * just increments a ref counter (which is
				 * used when the address is being deleted)
				 */
				ret = mac_multicst_add(vswp->mh,
						(uchar_t *)&mcst_pkt->mca[i]);
				if (ret) {
					cmn_err(CE_WARN, "!unable to add "
						"multicast address");
					(void) vsw_del_mcst(vswp, VSW_VNETPORT,
						addr, port);
					vsw_del_addr(VSW_VNETPORT, port, addr);
					return (ret);
				}

			} else {
				DERR(vswp, "%s: error adding multicast "
					"address 0x%llx for port %ld",
					__func__, addr, port->p_instance);
				return (1);
			}
		} else {
			/*
			 * Delete an entry from the multicast hash
			 * table and update the address list
			 * appropriately.
			 */
			if (vsw_del_mcst(vswp, VSW_VNETPORT, addr, port) == 0) {
				D3(vswp, "%s: deleting multicast address "
					"0x%llx for port %ld", __func__, addr,
					port->p_instance);

				vsw_del_addr(VSW_VNETPORT, port, addr);

				/*
				 * Remove the address from HW. The address
				 * will actually only be removed once the ref
				 * count within the MAC layer has dropped to
				 * zero. I.e. we can safely call this fn even
				 * if other ports are interested in this
				 * address.
				 */
				(void) mac_multicst_remove(vswp->mh,
						(uchar_t *)&mcst_pkt->mca[i]);

			} else {
				DERR(vswp, "%s: error deleting multicast "
					"addr 0x%llx for port %ld",
					__func__, addr, port->p_instance);
				return (1);
			}
		}
	}
	D1(vswp, "%s: exit", __func__);
	return (0);
}

/*
 * Add a new multicast entry.
 *
 * Search hash table based on address. If match found then
 * update associated val (which is chain of ports), otherwise
 * create new key/val (addr/port) pair and insert into table.
 */
static int
vsw_add_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg)
{
	int		dup = 0;
	int		rv = 0;
	mfdb_ent_t	*ment = NULL;
	mfdb_ent_t	*tmp_ent = NULL;
	mfdb_ent_t	*new_ent = NULL;
	void		*tgt = NULL;

	if (devtype == VSW_VNETPORT) {
		/*
		 * Being invoked from a vnet.
		 */
		ASSERT(arg != NULL);
		tgt = arg;
		D2(NULL, "%s: port %d : address 0x%llx", __func__,
			((vsw_port_t *)arg)->p_instance, addr);
	} else {
		/*
		 * We are being invoked via the m_multicst mac entry
		 * point.
		 */
		D2(NULL, "%s: address 0x%llx", __func__, addr);
		tgt = (void *)vswp;
	}

	WRITE_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)addr,
				(mod_hash_val_t *)&ment) != 0) {

		/* address not currently in table */
		ment = kmem_alloc(sizeof (mfdb_ent_t), KM_SLEEP);
		ment->d_addr = (void *)tgt;
		ment->d_type = devtype;
		ment->nextp = NULL;

		if (mod_hash_insert(vswp->mfdb, (mod_hash_key_t)addr,
			(mod_hash_val_t)ment) != 0) {
			DERR(vswp, "%s: hash table insertion failed", __func__);
			kmem_free(ment, sizeof (mfdb_ent_t));
			rv = 1;
		} else {
			D2(vswp, "%s: added initial entry for 0x%llx to "
				"table", __func__, addr);
		}
	} else {
		/*
		 * Address in table. Check to see if specified port
		 * is already associated with the address. If not add
		 * it now.
		 */
		tmp_ent = ment;
		while (tmp_ent != NULL) {
			if (tmp_ent->d_addr == (void *)tgt) {
				if (devtype == VSW_VNETPORT) {
					DERR(vswp, "%s: duplicate port entry "
						"found for portid %ld and key "
						"0x%llx", __func__,
						((vsw_port_t *)arg)->p_instance,
						addr);
				} else {
					DERR(vswp, "%s: duplicate entry found"
						"for key 0x%llx",
						__func__, addr);
				}
				rv = 1;
				dup = 1;
				break;
			}
			tmp_ent = tmp_ent->nextp;
		}

		/*
		 * Port not on list so add it to end now.
		 */
		if (0 == dup) {
			D2(vswp, "%s: added entry for 0x%llx to table",
				__func__, addr);
			new_ent = kmem_alloc(sizeof (mfdb_ent_t), KM_SLEEP);
			new_ent->d_addr = (void *)tgt;
			new_ent->d_type = devtype;
			new_ent->nextp = NULL;

			tmp_ent = ment;
			while (tmp_ent->nextp != NULL)
				tmp_ent = tmp_ent->nextp;

			tmp_ent->nextp = new_ent;
		}
	}

	RW_EXIT(&vswp->mfdbrw);
	return (rv);
}

/*
 * Remove a multicast entry from the hashtable.
 *
 * Search hash table based on address. If match found, scan
 * list of ports associated with address. If specified port
 * found remove it from list.
 */
static int
vsw_del_mcst(vsw_t *vswp, uint8_t devtype, uint64_t addr, void *arg)
{
	mfdb_ent_t	*ment = NULL;
	mfdb_ent_t	*curr_p, *prev_p;
	void		*tgt = NULL;

	D1(vswp, "%s: enter", __func__);

	if (devtype == VSW_VNETPORT) {
		tgt = (vsw_port_t *)arg;
		D2(vswp, "%s: removing port %d from mFDB for address"
			" 0x%llx", __func__, ((vsw_port_t *)tgt)->p_instance,
			addr);
	} else {
		D2(vswp, "%s: removing entry", __func__);
		tgt = (void *)vswp;
	}

	WRITE_ENTER(&vswp->mfdbrw);
	if (mod_hash_find(vswp->mfdb, (mod_hash_key_t)addr,
				(mod_hash_val_t *)&ment) != 0) {
		D2(vswp, "%s: address 0x%llx not in table", __func__, addr);
		RW_EXIT(&vswp->mfdbrw);
		return (1);
	}

	prev_p = curr_p = ment;

	while (curr_p != NULL) {
		if (curr_p->d_addr == (void *)tgt) {
			if (devtype == VSW_VNETPORT) {
				D2(vswp, "%s: port %d found", __func__,
					((vsw_port_t *)tgt)->p_instance);
			} else {
				D2(vswp, "%s: instance found", __func__);
			}

			if (prev_p == curr_p) {
				/*
				 * head of list, if no other element is in
				 * list then destroy this entry, otherwise
				 * just replace it with updated value.
				 */
				ment = curr_p->nextp;
				kmem_free(curr_p, sizeof (mfdb_ent_t));
				if (ment == NULL) {
					(void) mod_hash_destroy(vswp->mfdb,
							(mod_hash_val_t)addr);
				} else {
					(void) mod_hash_replace(vswp->mfdb,
							(mod_hash_key_t)addr,
							(mod_hash_val_t)ment);
				}
			} else {
				/*
				 * Not head of list, no need to do
				 * replacement, just adjust list pointers.
				 */
				prev_p->nextp = curr_p->nextp;
				kmem_free(curr_p, sizeof (mfdb_ent_t));
			}
			break;
		}

		prev_p = curr_p;
		curr_p = curr_p->nextp;
	}

	RW_EXIT(&vswp->mfdbrw);

	D1(vswp, "%s: exit", __func__);

	return (0);
}

/*
 * Port is being deleted, but has registered an interest in one
 * or more multicast groups. Using the list of addresses maintained
 * within the port structure find the appropriate entry in the hash
 * table and remove this port from the list of interested ports.
 */
static void
vsw_del_mcst_port(vsw_port_t *port)
{
	mcst_addr_t	*mcst_p = NULL;
	vsw_t		*vswp = port->p_vswp;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&port->mca_lock);
	while (port->mcap != NULL) {
		(void) vsw_del_mcst(vswp, VSW_VNETPORT,
					port->mcap->addr, port);

		mcst_p = port->mcap->nextp;
		kmem_free(port->mcap, sizeof (mcst_addr_t));
		port->mcap = mcst_p;
	}
	mutex_exit(&port->mca_lock);

	D1(vswp, "%s: exit", __func__);
}

/*
 * This vsw instance is detaching, but has registered an interest in one
 * or more multicast groups. Using the list of addresses maintained
 * within the vsw structure find the appropriate entry in the hash
 * table and remove this instance from the list of interested ports.
 */
static void
vsw_del_mcst_vsw(vsw_t *vswp)
{
	mcst_addr_t	*next_p = NULL;

	D1(vswp, "%s: enter", __func__);

	mutex_enter(&vswp->mca_lock);

	while (vswp->mcap != NULL) {
		DERR(vswp, "%s: deleting addr 0x%llx",
			__func__, vswp->mcap->addr);
		(void) vsw_del_mcst(vswp, VSW_LOCALDEV,
				vswp->mcap->addr, NULL);

		next_p = vswp->mcap->nextp;
		kmem_free(vswp->mcap, sizeof (mcst_addr_t));
		vswp->mcap = next_p;
	}

	vswp->mcap = NULL;
	mutex_exit(&vswp->mca_lock);

	D1(vswp, "%s: exit", __func__);
}


/*
 * Remove the specified address from the list of address maintained
 * in this port node.
 */
static void
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
			kmem_free(curr_p, sizeof (mcst_addr_t));
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
	if ((ldc_mem_dring_create(VSW_RING_NUM_EL,
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

	dp->num_descriptors = VSW_RING_NUM_EL;
	dp->descriptor_size = VSW_PUB_SIZE;
	dp->options = VIO_TX_DRING;
	dp->ncookies = 1;	/* guaranteed by ldc */

	/*
	 * create private portion of ring
	 */
	dp->priv_addr = (vsw_private_desc_t *)kmem_zalloc(
		(sizeof (vsw_private_desc_t) * VSW_RING_NUM_EL), KM_SLEEP);

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
	if (ldcp->lane_out.dringp == NULL) {
		D2(vswp, "vsw_create_dring: adding first outbound ring");
		ldcp->lane_out.dringp = dp;
	} else {
		tp = ldcp->lane_out.dringp;
		while (tp->next != NULL)
			tp = tp->next;

		tp->next = dp;
	}

	return (dp);

dring_fail_exit:
	(void) ldc_mem_dring_destroy(dp->handle);

create_fail_exit:
	if (dp->priv_addr != NULL) {
		priv_addr = dp->priv_addr;
		for (i = 0; i < VSW_RING_NUM_EL; i++) {
			if (priv_addr->memhandle != NULL)
				(void) ldc_mem_free_handle(
						priv_addr->memhandle);
			priv_addr++;
		}
		kmem_free(dp->priv_addr,
			(sizeof (vsw_private_desc_t) * VSW_RING_NUM_EL));
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

	dp->priv_addr = kmem_zalloc((sizeof (vsw_private_desc_t) *
					VSW_RING_NUM_EL), KM_SLEEP);

	dp->num_descriptors = VSW_RING_NUM_EL;

	if (vsw_setup_ring(ldcp, dp)) {
		DERR(vswp, "%s: setup of ring failed", __func__);
		kmem_free(dp->priv_addr,
			(sizeof (vsw_private_desc_t) * VSW_RING_NUM_EL));
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
	if (ldcp->lane_out.dringp == NULL) {
		D2(vswp, "%s: adding first outbound privring", __func__);
		ldcp->lane_out.dringp = dp;
	} else {
		tp = ldcp->lane_out.dringp;
		while (tp->next != NULL)
			tp = tp->next;

		tp->next = dp;
	}

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
	dp->data_sz = (VSW_RING_NUM_EL * VSW_RING_EL_DATA_SZ);
	dp->data_addr = kmem_alloc(dp->data_sz, KM_SLEEP);

	D2(vswp, "%s: allocated %lld bytes at 0x%llx\n", name,
		dp->data_sz, dp->data_addr);

	tmpp = (uint64_t *)dp->data_addr;
	offset = VSW_RING_EL_DATA_SZ / sizeof (tmpp);

	/*
	 * Initialise some of the private and public (if they exist)
	 * descriptor fields.
	 */
	for (i = 0; i < VSW_RING_NUM_EL; i++) {
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
				name, ldcp->ldc_id, ncookies,
				VSW_RING_EL_DATA_SZ);

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
	int			num = VSW_RING_NUM_EL;
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
	lp->xfer_mode = VIO_DRING_MODE;
	lp->ack_freq = 0;	/* for shared mode */

	mutex_enter(&lp->seq_lock);
	lp->seq_num = VNET_ISS;
	mutex_exit(&lp->seq_lock);
}

/*
 * Verify that the attributes are acceptable.
 *
 * FUTURE: If some attributes are not acceptable, change them
 * our desired values.
 */
static int
vsw_check_attr(vnet_attr_msg_t *pkt, vsw_port_t *port)
{
	int	ret = 0;

	D1(NULL, "vsw_check_attr enter\n");

	/*
	 * Note we currently only support in-band descriptors
	 * and descriptor rings, not packet based transfer (VIO_PKT_MODE)
	 */
	if ((pkt->xfer_mode != VIO_DESC_MODE) &&
			(pkt->xfer_mode != VIO_DRING_MODE)) {
		D2(NULL, "vsw_check_attr: unknown mode %x\n",
			pkt->xfer_mode);
		ret = 1;
	}

	/* Only support MAC addresses at moment. */
	if ((pkt->addr_type != ADDR_TYPE_MAC) || (pkt->addr == 0)) {
		D2(NULL, "vsw_check_attr: invalid addr_type %x, "
			"or address 0x%llx\n", pkt->addr_type,
			pkt->addr);
		ret = 1;
	}

	/*
	 * MAC address supplied by device should match that stored
	 * in the vsw-port OBP node. Need to decide what to do if they
	 * don't match, for the moment just warn but don't fail.
	 */
	if (bcmp(&pkt->addr, &port->p_macaddr, ETHERADDRL) != 0) {
		DERR(NULL, "vsw_check_attr: device supplied address "
			"0x%llx doesn't match node address 0x%llx\n",
			pkt->addr, port->p_macaddr);
	}

	/*
	 * Ack freq only makes sense in pkt mode, in shared
	 * mode the ring descriptors say whether or not to
	 * send back an ACK.
	 */
	if ((pkt->xfer_mode == VIO_DRING_MODE) &&
				(pkt->ack_freq > 0)) {
		D2(NULL, "vsw_check_attr: non zero ack freq "
			" in SHM mode\n");
		ret = 1;
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
	mutex_enter(&lp->seq_lock);
	lp->seq_num = VNET_ISS;
	mutex_exit(&lp->seq_lock);
	if (lp->dringp) {
		if (dir == INBOUND) {
			dp = lp->dringp;
			while (dp != NULL) {
				dpp = dp->next;
				if (dp->handle != NULL)
					(void) ldc_mem_dring_unmap(dp->handle);
				kmem_free(dp, sizeof (dring_info_t));
				dp = dpp;
			}
		} else {
			/*
			 * unbind, destroy exported dring, free dring struct
			 */
			dp = lp->dringp;
			rv = vsw_free_ring(dp);
		}
		if (rv == 0) {
			lp->dringp = NULL;
		}
	}

	D1(ldcp->ldc_vswp, "%s (%lld): exit", __func__, ldcp->ldc_id);
}

/*
 * Free ring and all associated resources.
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
			for (i = 0; i < VSW_RING_NUM_EL; i++) {
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
							"handle for ring "
							"0x%llx at pos %d",
							dp, i);
						mutex_exit(&dp->dlock);
						return (rv);
					}
					paddr->memhandle = NULL;
				}
				mutex_destroy(&paddr->dstate_lock);
			}
			kmem_free(dp->priv_addr, (sizeof (vsw_private_desc_t)
					* VSW_RING_NUM_EL));
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
					"psession %lu\n",
					ldcp->ldc_id,
					ldcp->local_session,
					ldcp->peer_session);

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

	for (i = 0; i < VSW_RING_NUM_EL; i++) {
		if (dringp->pub_addr != NULL) {
			pub_addr = (vnet_public_desc_t *)dringp->pub_addr + i;

			if (pub_addr->hdr.dstate == VIO_DESC_FREE)
				pub_count++;
		}

		if (dringp->priv_addr != NULL) {
			priv_addr =
				(vsw_private_desc_t *)dringp->priv_addr + i;

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
