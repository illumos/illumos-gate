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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/callb.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/modhash.h>
#include <sys/debug.h>
#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <net/if.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_ether.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <sys/atomic.h>
#include <sys/vnet.h>
#include <sys/vlan.h>
#include <sys/vnet_mailbox.h>
#include <sys/vnet_common.h>
#include <sys/dds.h>
#include <sys/strsubr.h>
#include <sys/taskq.h>

/*
 * Function prototypes.
 */

/* DDI entrypoints */
static int vnetdevinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vnetattach(dev_info_t *, ddi_attach_cmd_t);
static int vnetdetach(dev_info_t *, ddi_detach_cmd_t);

/* MAC entrypoints  */
static int vnet_m_stat(void *, uint_t, uint64_t *);
static int vnet_m_start(void *);
static void vnet_m_stop(void *);
static int vnet_m_promisc(void *, boolean_t);
static int vnet_m_multicst(void *, boolean_t, const uint8_t *);
static int vnet_m_unicst(void *, const uint8_t *);
mblk_t *vnet_m_tx(void *, mblk_t *);
static void vnet_m_ioctl(void *arg, queue_t *q, mblk_t *mp);
#ifdef	VNET_IOC_DEBUG
static void vnet_force_link_state(vnet_t *vnetp, queue_t *q, mblk_t *mp);
#endif
static boolean_t vnet_m_capab(void *arg, mac_capab_t cap, void *cap_data);
static void vnet_get_ring(void *arg, mac_ring_type_t rtype, const int g_index,
	const int r_index, mac_ring_info_t *infop, mac_ring_handle_t r_handle);
static void vnet_get_group(void *arg, mac_ring_type_t type, const int index,
	mac_group_info_t *infop, mac_group_handle_t handle);
static int vnet_rx_ring_start(mac_ring_driver_t rdriver, uint64_t mr_gen_num);
static void vnet_rx_ring_stop(mac_ring_driver_t rdriver);
static int vnet_rx_ring_stat(mac_ring_driver_t rdriver, uint_t stat,
	uint64_t *val);
static int vnet_tx_ring_start(mac_ring_driver_t rdriver, uint64_t mr_gen_num);
static void vnet_tx_ring_stop(mac_ring_driver_t rdriver);
static int vnet_tx_ring_stat(mac_ring_driver_t rdriver, uint_t stat,
	uint64_t *val);
static int vnet_ring_enable_intr(void *arg);
static int vnet_ring_disable_intr(void *arg);
static mblk_t *vnet_rx_poll(void *arg, int bytes_to_pickup);
static int vnet_addmac(void *arg, const uint8_t *mac_addr);
static int vnet_remmac(void *arg, const uint8_t *mac_addr);

/* vnet internal functions */
static int vnet_unattach(vnet_t *vnetp);
static void vnet_ring_grp_init(vnet_t *vnetp);
static void vnet_ring_grp_uninit(vnet_t *vnetp);
static int vnet_mac_register(vnet_t *);
static int vnet_read_mac_address(vnet_t *vnetp);
static int vnet_bind_vgenring(vnet_res_t *vresp);
static void vnet_unbind_vgenring(vnet_res_t *vresp);
static int vnet_bind_hwrings(vnet_t *vnetp);
static void vnet_unbind_hwrings(vnet_t *vnetp);
static int vnet_bind_rings(vnet_res_t *vresp);
static void vnet_unbind_rings(vnet_res_t *vresp);
static int vnet_hio_stat(void *, uint_t, uint64_t *);
static int vnet_hio_start(void *);
static void vnet_hio_stop(void *);
mblk_t *vnet_hio_tx(void *, mblk_t *);

/* Forwarding database (FDB) routines */
static void vnet_fdb_create(vnet_t *vnetp);
static void vnet_fdb_destroy(vnet_t *vnetp);
static vnet_res_t *vnet_fdbe_find(vnet_t *vnetp, struct ether_addr *addrp);
static void vnet_fdbe_find_cb(mod_hash_key_t key, mod_hash_val_t val);
void vnet_fdbe_add(vnet_t *vnetp, vnet_res_t *vresp);
static void vnet_fdbe_del(vnet_t *vnetp, vnet_res_t *vresp);

static void vnet_rx_frames_untag(uint16_t pvid, mblk_t **mp);
static void vnet_rx(vio_net_handle_t vrh, mblk_t *mp);
static void vnet_tx_update(vio_net_handle_t vrh);
static void vnet_res_start_task(void *arg);
static void vnet_start_resources(vnet_t *vnetp);
static void vnet_stop_resources(vnet_t *vnetp);
static void vnet_dispatch_res_task(vnet_t *vnetp);
static void vnet_res_start_task(void *arg);
static void vnet_handle_res_err(vio_net_handle_t vrh, vio_net_err_val_t err);
static void vnet_add_resource(vnet_t *vnetp, vnet_res_t *vresp);
static vnet_res_t *vnet_rem_resource(vnet_t *vnetp, vnet_res_t *vresp);
static void vnet_tx_notify_thread(void *);

/* Exported to vnet_gen */
int vnet_mtu_update(vnet_t *vnetp, uint32_t mtu);
void vnet_link_update(vnet_t *vnetp, link_state_t link_state);
void vnet_dds_cleanup_hio(vnet_t *vnetp);

static kstat_t *vnet_hio_setup_kstats(char *ks_mod, char *ks_name,
    vnet_res_t *vresp);
static int vnet_hio_update_kstats(kstat_t *ksp, int rw);
static void vnet_hio_get_stats(vnet_res_t *vresp, vnet_hio_stats_t *statsp);
static void vnet_hio_destroy_kstats(kstat_t *ksp);

/* Exported to to vnet_dds */
int vnet_send_dds_msg(vnet_t *vnetp, void *dmsg);
int vnet_hio_mac_init(vnet_t *vnetp, char *ifname);
void vnet_hio_mac_cleanup(vnet_t *vnetp);

/* Externs that are imported from vnet_gen */
extern int vgen_init(void *vnetp, uint64_t regprop, dev_info_t *vnetdip,
    const uint8_t *macaddr, void **vgenhdl);
extern int vgen_init_mdeg(void *arg);
extern void vgen_uninit(void *arg);
extern int vgen_dds_tx(void *arg, void *dmsg);
extern int vgen_enable_intr(void *arg);
extern int vgen_disable_intr(void *arg);
extern mblk_t *vgen_rx_poll(void *arg, int bytes_to_pickup);

/* Externs that are imported from vnet_dds */
extern void vdds_mod_init(void);
extern void vdds_mod_fini(void);
extern int vdds_init(vnet_t *vnetp);
extern void vdds_cleanup(vnet_t *vnetp);
extern void vdds_process_dds_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg);
extern void vdds_cleanup_hybrid_res(void *arg);
extern void vdds_cleanup_hio(vnet_t *vnetp);

extern pri_t	minclsyspri;

#define	DRV_NAME	"vnet"
#define	VNET_FDBE_REFHOLD(p)						\
{									\
	atomic_inc_32(&(p)->refcnt);					\
	ASSERT((p)->refcnt != 0);					\
}

#define	VNET_FDBE_REFRELE(p)						\
{									\
	ASSERT((p)->refcnt != 0);					\
	atomic_dec_32(&(p)->refcnt);					\
}

#ifdef	VNET_IOC_DEBUG
#define	VNET_M_CALLBACK_FLAGS	(MC_IOCTL | MC_GETCAPAB)
#else
#define	VNET_M_CALLBACK_FLAGS	(MC_GETCAPAB)
#endif

static mac_callbacks_t vnet_m_callbacks = {
	VNET_M_CALLBACK_FLAGS,
	vnet_m_stat,
	vnet_m_start,
	vnet_m_stop,
	vnet_m_promisc,
	vnet_m_multicst,
	NULL,	/* m_unicst entry must be NULL while rx rings are exposed */
	NULL,	/* m_tx entry must be NULL while tx rings are exposed */
	NULL,
	vnet_m_ioctl,
	vnet_m_capab,
	NULL
};

static mac_callbacks_t vnet_hio_res_callbacks = {
	0,
	vnet_hio_stat,
	vnet_hio_start,
	vnet_hio_stop,
	NULL,
	NULL,
	NULL,
	vnet_hio_tx,
	NULL,
	NULL,
	NULL
};

/*
 * Linked list of "vnet_t" structures - one per instance.
 */
static vnet_t	*vnet_headp = NULL;
static krwlock_t vnet_rw;

/* Tunables */
uint32_t vnet_num_descriptors = VNET_NUM_DESCRIPTORS;

/*
 * Configure tx serialization in mac layer for the vnet device. This tunable
 * should be enabled to improve performance only if HybridIO is configured for
 * the vnet device.
 */
boolean_t vnet_mac_tx_serialize = B_FALSE;

/* Configure enqueing at Rx soft rings in mac layer for the vnet device */
boolean_t vnet_mac_rx_queuing = B_TRUE;

/*
 * Set this to non-zero to enable additional internal receive buffer pools
 * based on the MTU of the device for better performance at the cost of more
 * memory consumption. This is turned off by default, to use allocb(9F) for
 * receive buffer allocations of sizes > 2K.
 */
boolean_t vnet_jumbo_rxpools = B_FALSE;

/* # of chains in fdb hash table */
uint32_t	vnet_fdb_nchains = VNET_NFDB_HASH;

/* Internal tunables */
uint32_t	vnet_ethermtu = 1500;	/* mtu of the device */

/*
 * Default vlan id. This is only used internally when the "default-vlan-id"
 * property is not present in the MD device node. Therefore, this should not be
 * used as a tunable; if this value is changed, the corresponding variable
 * should be updated to the same value in vsw and also other vnets connected to
 * the same vsw.
 */
uint16_t	vnet_default_vlan_id = 1;

/* delay in usec to wait for all references on a fdb entry to be dropped */
uint32_t vnet_fdbe_refcnt_delay = 10;

static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/* mac_open() retry delay in usec */
uint32_t vnet_mac_open_delay = 100;	/* 0.1 ms */

/* max # of mac_open() retries */
uint32_t vnet_mac_open_retries = 100;

/*
 * Property names
 */
static char macaddr_propname[] = "local-mac-address";

/*
 * This is the string displayed by modinfo(1m).
 */
static char vnet_ident[] = "vnet driver";
extern struct mod_ops mod_driverops;
static struct cb_ops cb_vnetops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_MP)		/* cb_flag */
};

static struct dev_ops vnetops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vnetattach,		/* devo_attach */
	vnetdetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_vnetops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	vnet_ident,		/* ID string */
	&vnetops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

#ifdef DEBUG

#define	DEBUG_PRINTF	debug_printf

/*
 * Print debug messages - set to 0xf to enable all msgs
 */
int vnet_dbglevel = 0x8;

static void
debug_printf(const char *fname, void *arg, const char *fmt, ...)
{
	char    buf[512];
	va_list ap;
	vnet_t *vnetp = (vnet_t *)arg;
	char    *bufp = buf;

	if (vnetp == NULL) {
		(void) sprintf(bufp, "%s: ", fname);
		bufp += strlen(bufp);
	} else {
		(void) sprintf(bufp, "vnet%d:%s: ", vnetp->instance, fname);
		bufp += strlen(bufp);
	}
	va_start(ap, fmt);
	(void) vsprintf(bufp, fmt, ap);
	va_end(ap);
	cmn_err(CE_CONT, "%s\n", buf);
}

#endif

/* _init(9E): initialize the loadable module */
int
_init(void)
{
	int status;

	DBG1(NULL, "enter\n");

	mac_init_ops(&vnetops, "vnet");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&vnetops);
	}
	vdds_mod_init();
	DBG1(NULL, "exit(%d)\n", status);
	return (status);
}

/* _fini(9E): prepare the module for unloading. */
int
_fini(void)
{
	int		status;

	DBG1(NULL, "enter\n");

	status = mod_remove(&modlinkage);
	if (status != 0)
		return (status);
	mac_fini_ops(&vnetops);
	vdds_mod_fini();

	DBG1(NULL, "exit(%d)\n", status);
	return (status);
}

/* _info(9E): return information about the loadable module */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * attach(9E): attach a device to the system.
 * called once for each instance of the device on the system.
 */
static int
vnetattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	vnet_t			*vnetp;
	int			status;
	int			instance;
	uint64_t		reg;
	char			qname[TASKQ_NAMELEN];
	vnet_attach_progress_t	attach_progress;

	attach_progress = AST_init;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	case DDI_PM_RESUME:
	default:
		goto vnet_attach_fail;
	}

	instance = ddi_get_instance(dip);
	DBG1(NULL, "instance(%d) enter\n", instance);

	/* allocate vnet_t and mac_t structures */
	vnetp = kmem_zalloc(sizeof (vnet_t), KM_SLEEP);
	vnetp->dip = dip;
	vnetp->instance = instance;
	rw_init(&vnetp->vrwlock, NULL, RW_DRIVER, NULL);
	rw_init(&vnetp->vsw_fp_rw, NULL, RW_DRIVER, NULL);
	attach_progress |= AST_vnet_alloc;

	vnet_ring_grp_init(vnetp);
	attach_progress |= AST_ring_init;

	status = vdds_init(vnetp);
	if (status != 0) {
		goto vnet_attach_fail;
	}
	attach_progress |= AST_vdds_init;

	/* setup links to vnet_t from both devinfo and mac_t */
	ddi_set_driver_private(dip, (caddr_t)vnetp);

	/* read the mac address */
	status = vnet_read_mac_address(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}
	attach_progress |= AST_read_macaddr;

	reg = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", -1);
	if (reg == -1) {
		goto vnet_attach_fail;
	}
	vnetp->reg = reg;

	vnet_fdb_create(vnetp);
	attach_progress |= AST_fdbh_alloc;

	(void) snprintf(qname, TASKQ_NAMELEN, "vres_taskq%d", instance);
	if ((vnetp->taskqp = ddi_taskq_create(dip, qname, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "!vnet%d: Unable to create task queue",
		    instance);
		goto vnet_attach_fail;
	}
	attach_progress |= AST_taskq_create;

	/* add to the list of vnet devices */
	WRITE_ENTER(&vnet_rw);
	vnetp->nextp = vnet_headp;
	vnet_headp = vnetp;
	RW_EXIT(&vnet_rw);

	attach_progress |= AST_vnet_list;

	/*
	 * Initialize the generic vnet plugin which provides communication via
	 * sun4v LDC (logical domain channel) based resources. This involves 2
	 * steps; first, vgen_init() is invoked to read the various properties
	 * of the vnet device from its MD node (including its mtu which is
	 * needed to mac_register()) and obtain a handle to the vgen layer.
	 * After mac_register() is done and we have a mac handle, we then
	 * invoke vgen_init_mdeg() which registers with the the MD event
	 * generator (mdeg) framework to allow LDC resource notifications.
	 * Note: this sequence also allows us to report the correct default #
	 * of pseudo rings (2TX and 3RX) in vnet_m_capab() which gets invoked
	 * in the context of mac_register(); and avoids conflicting with
	 * dynamic pseudo rx rings which get added/removed as a result of mdeg
	 * events in vgen.
	 */
	status = vgen_init(vnetp, reg, vnetp->dip,
	    (uint8_t *)vnetp->curr_macaddr, &vnetp->vgenhdl);
	if (status != DDI_SUCCESS) {
		DERR(vnetp, "vgen_init() failed\n");
		goto vnet_attach_fail;
	}
	attach_progress |= AST_vgen_init;

	status = vnet_mac_register(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}
	vnetp->link_state = LINK_STATE_UNKNOWN;
	attach_progress |= AST_macreg;

	status = vgen_init_mdeg(vnetp->vgenhdl);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}
	attach_progress |= AST_init_mdeg;

	vnetp->attach_progress = attach_progress;

	DBG1(NULL, "instance(%d) exit\n", instance);
	return (DDI_SUCCESS);

vnet_attach_fail:
	vnetp->attach_progress = attach_progress;
	status = vnet_unattach(vnetp);
	ASSERT(status == 0);
	return (DDI_FAILURE);
}

/*
 * detach(9E): detach a device from the system.
 */
static int
vnetdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vnet_t		*vnetp;
	int		instance;

	instance = ddi_get_instance(dip);
	DBG1(NULL, "instance(%d) enter\n", instance);

	vnetp = ddi_get_driver_private(dip);
	if (vnetp == NULL) {
		goto vnet_detach_fail;
	}

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
	default:
		goto vnet_detach_fail;
	}

	if (vnet_unattach(vnetp) != 0) {
		goto vnet_detach_fail;
	}

	return (DDI_SUCCESS);

vnet_detach_fail:
	return (DDI_FAILURE);
}

/*
 * Common routine to handle vnetattach() failure and vnetdetach(). Note that
 * the only reason this function could fail is if mac_unregister() fails.
 * Otherwise, this function must ensure that all resources are freed and return
 * success.
 */
static int
vnet_unattach(vnet_t *vnetp)
{
	vnet_attach_progress_t	attach_progress;

	attach_progress = vnetp->attach_progress;

	/*
	 * Disable the mac device in the gldv3 subsystem. This can fail, in
	 * particular if there are still any open references to this mac
	 * device; in which case we just return failure without continuing to
	 * detach further.
	 * If it succeeds, we then invoke vgen_uninit() which should unregister
	 * any pseudo rings registered with the mac layer. Note we keep the
	 * AST_macreg flag on, so we can unregister with the mac layer at
	 * the end of this routine.
	 */
	if (attach_progress & AST_macreg) {
		if (mac_disable(vnetp->mh) != 0) {
			return (1);
		}
	}

	/*
	 * Now that we have disabled the device, we must finish all other steps
	 * and successfully return from this function; otherwise we will end up
	 * leaving the device in a broken/unusable state.
	 *
	 * First, release any hybrid resources assigned to this vnet device.
	 */
	if (attach_progress & AST_vdds_init) {
		vdds_cleanup(vnetp);
		attach_progress &= ~AST_vdds_init;
	}

	/*
	 * Uninit vgen. This stops further mdeg callbacks to this vnet
	 * device and/or its ports; and detaches any existing ports.
	 */
	if (attach_progress & (AST_vgen_init|AST_init_mdeg)) {
		vgen_uninit(vnetp->vgenhdl);
		attach_progress &= ~AST_vgen_init;
		attach_progress &= ~AST_init_mdeg;
	}

	/* Destroy the taskq. */
	if (attach_progress & AST_taskq_create) {
		ddi_taskq_destroy(vnetp->taskqp);
		attach_progress &= ~AST_taskq_create;
	}

	/* Destroy fdb. */
	if (attach_progress & AST_fdbh_alloc) {
		vnet_fdb_destroy(vnetp);
		attach_progress &= ~AST_fdbh_alloc;
	}

	/* Remove from the device list */
	if (attach_progress & AST_vnet_list) {
		vnet_t		**vnetpp;
		/* unlink from instance(vnet_t) list */
		WRITE_ENTER(&vnet_rw);
		for (vnetpp = &vnet_headp; *vnetpp;
		    vnetpp = &(*vnetpp)->nextp) {
			if (*vnetpp == vnetp) {
				*vnetpp = vnetp->nextp;
				break;
			}
		}
		RW_EXIT(&vnet_rw);
		attach_progress &= ~AST_vnet_list;
	}

	if (attach_progress & AST_ring_init) {
		vnet_ring_grp_uninit(vnetp);
		attach_progress &= ~AST_ring_init;
	}

	if (attach_progress & AST_macreg) {
		VERIFY(mac_unregister(vnetp->mh) == 0);
		vnetp->mh = NULL;
		attach_progress &= ~AST_macreg;
	}

	if (attach_progress & AST_vnet_alloc) {
		rw_destroy(&vnetp->vrwlock);
		rw_destroy(&vnetp->vsw_fp_rw);
		attach_progress &= ~AST_vnet_list;
		KMEM_FREE(vnetp);
	}

	return (0);
}

/* enable the device for transmit/receive */
static int
vnet_m_start(void *arg)
{
	vnet_t		*vnetp = arg;

	DBG1(vnetp, "enter\n");

	WRITE_ENTER(&vnetp->vrwlock);
	vnetp->flags |= VNET_STARTED;
	vnet_start_resources(vnetp);
	RW_EXIT(&vnetp->vrwlock);

	DBG1(vnetp, "exit\n");
	return (VNET_SUCCESS);

}

/* stop transmit/receive for the device */
static void
vnet_m_stop(void *arg)
{
	vnet_t		*vnetp = arg;

	DBG1(vnetp, "enter\n");

	WRITE_ENTER(&vnetp->vrwlock);
	if (vnetp->flags & VNET_STARTED) {
		/*
		 * Set the flags appropriately; this should prevent starting of
		 * any new resources that are added(see vnet_res_start_task()),
		 * while we release the vrwlock in vnet_stop_resources() before
		 * stopping each resource.
		 */
		vnetp->flags &= ~VNET_STARTED;
		vnetp->flags |= VNET_STOPPING;
		vnet_stop_resources(vnetp);
		vnetp->flags &= ~VNET_STOPPING;
	}
	RW_EXIT(&vnetp->vrwlock);

	DBG1(vnetp, "exit\n");
}

/* set the unicast mac address of the device */
static int
vnet_m_unicst(void *arg, const uint8_t *macaddr)
{
	_NOTE(ARGUNUSED(macaddr))

	vnet_t *vnetp = arg;

	DBG1(vnetp, "enter\n");
	/*
	 * NOTE: setting mac address dynamically is not supported.
	 */
	DBG1(vnetp, "exit\n");

	return (VNET_FAILURE);
}

/* enable/disable a multicast address */
static int
vnet_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	_NOTE(ARGUNUSED(add, mca))

	vnet_t		*vnetp = arg;
	vnet_res_t	*vresp;
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;
	int		rv = VNET_SUCCESS;

	DBG1(vnetp, "enter\n");

	READ_ENTER(&vnetp->vsw_fp_rw);
	if (vnetp->vsw_fp == NULL) {
		RW_EXIT(&vnetp->vsw_fp_rw);
		return (EAGAIN);
	}
	VNET_FDBE_REFHOLD(vnetp->vsw_fp);
	RW_EXIT(&vnetp->vsw_fp_rw);

	vresp = vnetp->vsw_fp;
	macp = &vresp->macreg;
	cbp = macp->m_callbacks;
	rv = cbp->mc_multicst(macp->m_driver, add, mca);

	VNET_FDBE_REFRELE(vnetp->vsw_fp);

	DBG1(vnetp, "exit(%d)\n", rv);
	return (rv);
}

/* set or clear promiscuous mode on the device */
static int
vnet_m_promisc(void *arg, boolean_t on)
{
	_NOTE(ARGUNUSED(on))

	vnet_t *vnetp = arg;
	DBG1(vnetp, "enter\n");
	/*
	 * NOTE: setting promiscuous mode is not supported, just return success.
	 */
	DBG1(vnetp, "exit\n");
	return (VNET_SUCCESS);
}

/*
 * Transmit a chain of packets. This function provides switching functionality
 * based on the destination mac address to reach other guests (within ldoms) or
 * external hosts.
 */
mblk_t *
vnet_tx_ring_send(void *arg, mblk_t *mp)
{
	vnet_pseudo_tx_ring_t	*tx_ringp;
	vnet_tx_ring_stats_t	*statsp;
	vnet_t			*vnetp;
	vnet_res_t		*vresp;
	mblk_t			*next;
	mblk_t			*resid_mp;
	mac_register_t		*macp;
	struct ether_header	*ehp;
	boolean_t		is_unicast;
	boolean_t		is_pvid;	/* non-default pvid ? */
	boolean_t		hres;		/* Hybrid resource ? */
	void			*tx_arg;
	size_t			size;

	tx_ringp = (vnet_pseudo_tx_ring_t *)arg;
	statsp = &tx_ringp->tx_ring_stats;
	vnetp = (vnet_t *)tx_ringp->vnetp;
	DBG1(vnetp, "enter\n");
	ASSERT(mp != NULL);

	is_pvid = (vnetp->pvid != vnetp->default_vlan_id) ? B_TRUE : B_FALSE;

	while (mp != NULL) {

		next = mp->b_next;
		mp->b_next = NULL;

		/* update stats */
		size = msgsize(mp);

		/*
		 * Find fdb entry for the destination
		 * and hold a reference to it.
		 */
		ehp = (struct ether_header *)mp->b_rptr;
		vresp = vnet_fdbe_find(vnetp, &ehp->ether_dhost);
		if (vresp != NULL) {

			/*
			 * Destination found in FDB.
			 * The destination is a vnet device within ldoms
			 * and directly reachable, invoke the tx function
			 * in the fdb entry.
			 */
			macp = &vresp->macreg;
			resid_mp = macp->m_callbacks->mc_tx(macp->m_driver, mp);

			/* tx done; now release ref on fdb entry */
			VNET_FDBE_REFRELE(vresp);

			if (resid_mp != NULL) {
				/* m_tx failed */
				mp->b_next = next;
				break;
			}
		} else {
			is_unicast = !(IS_BROADCAST(ehp) ||
			    (IS_MULTICAST(ehp)));
			/*
			 * Destination is not in FDB.
			 * If the destination is broadcast or multicast,
			 * then forward the packet to vswitch.
			 * If a Hybrid resource avilable, then send the
			 * unicast packet via hybrid resource, otherwise
			 * forward it to vswitch.
			 */
			READ_ENTER(&vnetp->vsw_fp_rw);

			if ((is_unicast) && (vnetp->hio_fp != NULL)) {
				vresp = vnetp->hio_fp;
				hres = B_TRUE;
			} else {
				vresp = vnetp->vsw_fp;
				hres = B_FALSE;
			}
			if (vresp == NULL) {
				/*
				 * no fdb entry to vsw? drop the packet.
				 */
				RW_EXIT(&vnetp->vsw_fp_rw);
				freemsg(mp);
				mp = next;
				continue;
			}

			/* ref hold the fdb entry to vsw */
			VNET_FDBE_REFHOLD(vresp);

			RW_EXIT(&vnetp->vsw_fp_rw);

			/*
			 * In the case of a hybrid resource we need to insert
			 * the tag for the pvid case here; unlike packets that
			 * are destined to a vnet/vsw in which case the vgen
			 * layer does the tagging before sending it over ldc.
			 */
			if (hres == B_TRUE) {
				/*
				 * Determine if the frame being transmitted
				 * over the hybrid resource is untagged. If so,
				 * insert the tag before transmitting.
				 */
				if (is_pvid == B_TRUE &&
				    ehp->ether_type != htons(ETHERTYPE_VLAN)) {

					mp = vnet_vlan_insert_tag(mp,
					    vnetp->pvid);
					if (mp == NULL) {
						VNET_FDBE_REFRELE(vresp);
						mp = next;
						continue;
					}

				}

				macp = &vresp->macreg;
				tx_arg = tx_ringp;
			} else {
				macp = &vresp->macreg;
				tx_arg = macp->m_driver;
			}
			resid_mp = macp->m_callbacks->mc_tx(tx_arg, mp);

			/* tx done; now release ref on fdb entry */
			VNET_FDBE_REFRELE(vresp);

			if (resid_mp != NULL) {
				/* m_tx failed */
				mp->b_next = next;
				break;
			}
		}

		statsp->obytes += size;
		statsp->opackets++;
		mp = next;
	}

	DBG1(vnetp, "exit\n");
	return (mp);
}

/* get statistics from the device */
int
vnet_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	vnet_t *vnetp = arg;
	vnet_res_t	*vresp;
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;
	uint64_t val_total = 0;

	DBG1(vnetp, "enter\n");

	/*
	 * get the specified statistic from each transport and return the
	 * aggregate val.  This obviously only works for counters.
	 */
	if ((IS_MAC_STAT(stat) && !MAC_STAT_ISACOUNTER(stat)) ||
	    (IS_MACTYPE_STAT(stat) && !ETHER_STAT_ISACOUNTER(stat))) {
		return (ENOTSUP);
	}

	READ_ENTER(&vnetp->vrwlock);
	for (vresp = vnetp->vres_list; vresp != NULL; vresp = vresp->nextp) {
		macp = &vresp->macreg;
		cbp = macp->m_callbacks;
		if (cbp->mc_getstat(macp->m_driver, stat, val) == 0)
			val_total += *val;
	}
	RW_EXIT(&vnetp->vrwlock);

	*val = val_total;

	DBG1(vnetp, "exit\n");
	return (0);
}

static void
vnet_ring_grp_init(vnet_t *vnetp)
{
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	vnet_pseudo_tx_group_t	*tx_grp;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	int			i;

	tx_grp = &vnetp->tx_grp[0];
	tx_ringp = kmem_zalloc(sizeof (vnet_pseudo_tx_ring_t) *
	    VNET_NUM_PSEUDO_TXRINGS, KM_SLEEP);
	for (i = 0; i < VNET_NUM_PSEUDO_TXRINGS; i++) {
		tx_ringp[i].state |= VNET_TXRING_SHARED;
	}
	tx_grp->rings = tx_ringp;
	tx_grp->ring_cnt = VNET_NUM_PSEUDO_TXRINGS;
	mutex_init(&tx_grp->flowctl_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tx_grp->flowctl_cv, NULL, CV_DRIVER, NULL);
	tx_grp->flowctl_thread = thread_create(NULL, 0,
	    vnet_tx_notify_thread, tx_grp, 0, &p0, TS_RUN, minclsyspri);

	rx_grp = &vnetp->rx_grp[0];
	rx_grp->max_ring_cnt = MAX_RINGS_PER_GROUP;
	rw_init(&rx_grp->lock, NULL, RW_DRIVER, NULL);
	rx_ringp = kmem_zalloc(sizeof (vnet_pseudo_rx_ring_t) *
	    rx_grp->max_ring_cnt, KM_SLEEP);

	/*
	 * Setup the first 3 Pseudo RX Rings that are reserved;
	 * 1 for LDC resource to vswitch + 2 for RX rings of Hybrid resource.
	 */
	rx_ringp[0].state |= VNET_RXRING_INUSE|VNET_RXRING_LDC_SERVICE;
	rx_ringp[0].index = 0;
	rx_ringp[1].state |= VNET_RXRING_INUSE|VNET_RXRING_HYBRID;
	rx_ringp[1].index = 1;
	rx_ringp[2].state |= VNET_RXRING_INUSE|VNET_RXRING_HYBRID;
	rx_ringp[2].index = 2;

	rx_grp->ring_cnt = VNET_NUM_PSEUDO_RXRINGS_DEFAULT;
	rx_grp->rings = rx_ringp;

	for (i = VNET_NUM_PSEUDO_RXRINGS_DEFAULT;
	    i < rx_grp->max_ring_cnt; i++) {
		rx_ringp = &rx_grp->rings[i];
		rx_ringp->state = VNET_RXRING_FREE;
		rx_ringp->index = i;
	}
}

static void
vnet_ring_grp_uninit(vnet_t *vnetp)
{
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_tx_group_t	*tx_grp;
	kt_did_t		tid = 0;

	tx_grp = &vnetp->tx_grp[0];

	/* Inform tx_notify_thread to exit */
	mutex_enter(&tx_grp->flowctl_lock);
	if (tx_grp->flowctl_thread != NULL) {
		tid = tx_grp->flowctl_thread->t_did;
		tx_grp->flowctl_done = B_TRUE;
		cv_signal(&tx_grp->flowctl_cv);
	}
	mutex_exit(&tx_grp->flowctl_lock);
	if (tid != 0)
		thread_join(tid);

	if (tx_grp->rings != NULL) {
		ASSERT(tx_grp->ring_cnt == VNET_NUM_PSEUDO_TXRINGS);
		kmem_free(tx_grp->rings, sizeof (vnet_pseudo_tx_ring_t) *
		    tx_grp->ring_cnt);
		tx_grp->rings = NULL;
	}

	rx_grp = &vnetp->rx_grp[0];
	if (rx_grp->rings != NULL) {
		ASSERT(rx_grp->max_ring_cnt == MAX_RINGS_PER_GROUP);
		ASSERT(rx_grp->ring_cnt == VNET_NUM_PSEUDO_RXRINGS_DEFAULT);
		kmem_free(rx_grp->rings, sizeof (vnet_pseudo_rx_ring_t) *
		    rx_grp->max_ring_cnt);
		rx_grp->rings = NULL;
	}
}

static vnet_pseudo_rx_ring_t *
vnet_alloc_pseudo_rx_ring(vnet_t *vnetp)
{
	vnet_pseudo_rx_group_t  *rx_grp;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	int			index;

	rx_grp = &vnetp->rx_grp[0];
	WRITE_ENTER(&rx_grp->lock);

	if (rx_grp->ring_cnt == rx_grp->max_ring_cnt) {
		/* no rings available */
		RW_EXIT(&rx_grp->lock);
		return (NULL);
	}

	for (index = VNET_NUM_PSEUDO_RXRINGS_DEFAULT;
	    index < rx_grp->max_ring_cnt; index++) {
		rx_ringp = &rx_grp->rings[index];
		if (rx_ringp->state == VNET_RXRING_FREE) {
			rx_ringp->state |= VNET_RXRING_INUSE;
			rx_grp->ring_cnt++;
			break;
		}
	}

	RW_EXIT(&rx_grp->lock);
	return (rx_ringp);
}

static void
vnet_free_pseudo_rx_ring(vnet_t *vnetp, vnet_pseudo_rx_ring_t *ringp)
{
	vnet_pseudo_rx_group_t  *rx_grp;

	ASSERT(ringp->index >= VNET_NUM_PSEUDO_RXRINGS_DEFAULT);
	rx_grp = &vnetp->rx_grp[0];
	WRITE_ENTER(&rx_grp->lock);

	if (ringp->state != VNET_RXRING_FREE) {
		ringp->state = VNET_RXRING_FREE;
		ringp->handle = NULL;
		rx_grp->ring_cnt--;
	}

	RW_EXIT(&rx_grp->lock);
}

/* wrapper function for mac_register() */
static int
vnet_mac_register(vnet_t *vnetp)
{
	mac_register_t	*macp;
	int		err;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		return (DDI_FAILURE);
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = vnetp;
	macp->m_dip = vnetp->dip;
	macp->m_src_addr = vnetp->curr_macaddr;
	macp->m_callbacks = &vnet_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = vnetp->mtu;
	macp->m_margin = VLAN_TAGSZ;

	macp->m_v12n = MAC_VIRT_LEVEL1;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &vnetp->mh);
	mac_free(macp);
	return (err == 0 ? DDI_SUCCESS : DDI_FAILURE);
}

/* read the mac address of the device */
static int
vnet_read_mac_address(vnet_t *vnetp)
{
	uchar_t 	*macaddr;
	uint32_t 	size;
	int 		rv;

	rv = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, vnetp->dip,
	    DDI_PROP_DONTPASS, macaddr_propname, &macaddr, &size);
	if ((rv != DDI_PROP_SUCCESS) || (size != ETHERADDRL)) {
		DWARN(vnetp, "prop_lookup failed(%s) err(%d)\n",
		    macaddr_propname, rv);
		return (DDI_FAILURE);
	}
	bcopy(macaddr, (caddr_t)vnetp->vendor_addr, ETHERADDRL);
	bcopy(macaddr, (caddr_t)vnetp->curr_macaddr, ETHERADDRL);
	ddi_prop_free(macaddr);

	return (DDI_SUCCESS);
}

static void
vnet_fdb_create(vnet_t *vnetp)
{
	char		hashname[MAXNAMELEN];

	(void) snprintf(hashname, MAXNAMELEN, "vnet%d-fdbhash",
	    vnetp->instance);
	vnetp->fdb_nchains = vnet_fdb_nchains;
	vnetp->fdb_hashp = mod_hash_create_ptrhash(hashname, vnetp->fdb_nchains,
	    mod_hash_null_valdtor, sizeof (void *));
}

static void
vnet_fdb_destroy(vnet_t *vnetp)
{
	/* destroy fdb-hash-table */
	if (vnetp->fdb_hashp != NULL) {
		mod_hash_destroy_hash(vnetp->fdb_hashp);
		vnetp->fdb_hashp = NULL;
		vnetp->fdb_nchains = 0;
	}
}

/*
 * Add an entry into the fdb.
 */
void
vnet_fdbe_add(vnet_t *vnetp, vnet_res_t *vresp)
{
	uint64_t	addr = 0;
	int		rv;

	KEY_HASH(addr, vresp->rem_macaddr);

	/*
	 * If the entry being added corresponds to LDC_SERVICE resource,
	 * that is, vswitch connection, it is added to the hash and also
	 * the entry is cached, an additional reference count reflects
	 * this. The HYBRID resource is not added to the hash, but only
	 * cached, as it is only used for sending out packets for unknown
	 * unicast destinations.
	 */
	(vresp->type == VIO_NET_RES_LDC_SERVICE) ?
	    (vresp->refcnt = 1) : (vresp->refcnt = 0);

	/*
	 * Note: duplicate keys will be rejected by mod_hash.
	 */
	if (vresp->type != VIO_NET_RES_HYBRID) {
		rv = mod_hash_insert(vnetp->fdb_hashp, (mod_hash_key_t)addr,
		    (mod_hash_val_t)vresp);
		if (rv != 0) {
			DWARN(vnetp, "Duplicate macaddr key(%lx)\n", addr);
			return;
		}
	}

	if (vresp->type == VIO_NET_RES_LDC_SERVICE) {
		/* Cache the fdb entry to vsw-port */
		WRITE_ENTER(&vnetp->vsw_fp_rw);
		if (vnetp->vsw_fp == NULL)
			vnetp->vsw_fp = vresp;
		RW_EXIT(&vnetp->vsw_fp_rw);
	} else if (vresp->type == VIO_NET_RES_HYBRID) {
		/* Cache the fdb entry to hybrid resource */
		WRITE_ENTER(&vnetp->vsw_fp_rw);
		if (vnetp->hio_fp == NULL)
			vnetp->hio_fp = vresp;
		RW_EXIT(&vnetp->vsw_fp_rw);
	}
}

/*
 * Remove an entry from fdb.
 */
static void
vnet_fdbe_del(vnet_t *vnetp, vnet_res_t *vresp)
{
	uint64_t	addr = 0;
	int		rv;
	uint32_t	refcnt;
	vnet_res_t	*tmp;

	KEY_HASH(addr, vresp->rem_macaddr);

	/*
	 * Remove the entry from fdb hash table.
	 * This prevents further references to this fdb entry.
	 */
	if (vresp->type != VIO_NET_RES_HYBRID) {
		rv = mod_hash_remove(vnetp->fdb_hashp, (mod_hash_key_t)addr,
		    (mod_hash_val_t *)&tmp);
		if (rv != 0) {
			/*
			 * As the resources are added to the hash only
			 * after they are started, this can occur if
			 * a resource unregisters before it is ever started.
			 */
			return;
		}
	}

	if (vresp->type == VIO_NET_RES_LDC_SERVICE) {
		WRITE_ENTER(&vnetp->vsw_fp_rw);

		ASSERT(tmp == vnetp->vsw_fp);
		vnetp->vsw_fp = NULL;

		RW_EXIT(&vnetp->vsw_fp_rw);
	} else if (vresp->type == VIO_NET_RES_HYBRID) {
		WRITE_ENTER(&vnetp->vsw_fp_rw);

		vnetp->hio_fp = NULL;

		RW_EXIT(&vnetp->vsw_fp_rw);
	}

	/*
	 * If there are threads already ref holding before the entry was
	 * removed from hash table, then wait for ref count to drop to zero.
	 */
	(vresp->type == VIO_NET_RES_LDC_SERVICE) ?
	    (refcnt = 1) : (refcnt = 0);
	while (vresp->refcnt > refcnt) {
		delay(drv_usectohz(vnet_fdbe_refcnt_delay));
	}
}

/*
 * Search fdb for a given mac address. If an entry is found, hold
 * a reference to it and return the entry; else returns NULL.
 */
static vnet_res_t *
vnet_fdbe_find(vnet_t *vnetp, struct ether_addr *addrp)
{
	uint64_t	key = 0;
	vnet_res_t	*vresp;
	int		rv;

	KEY_HASH(key, addrp->ether_addr_octet);

	rv = mod_hash_find_cb(vnetp->fdb_hashp, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&vresp, vnet_fdbe_find_cb);

	if (rv != 0)
		return (NULL);

	return (vresp);
}

/*
 * Callback function provided to mod_hash_find_cb(). After finding the fdb
 * entry corresponding to the key (macaddr), this callback will be invoked by
 * mod_hash_find_cb() to atomically increment the reference count on the fdb
 * entry before returning the found entry.
 */
static void
vnet_fdbe_find_cb(mod_hash_key_t key, mod_hash_val_t val)
{
	_NOTE(ARGUNUSED(key))
	VNET_FDBE_REFHOLD((vnet_res_t *)val);
}

/*
 * Frames received that are tagged with the pvid of the vnet device must be
 * untagged before sending up the stack. This function walks the chain of rx
 * frames, untags any such frames and returns the updated chain.
 *
 * Arguments:
 *    pvid:  pvid of the vnet device for which packets are being received
 *    mp:    head of pkt chain to be validated and untagged
 *
 * Returns:
 *    mp:    head of updated chain of packets
 */
static void
vnet_rx_frames_untag(uint16_t pvid, mblk_t **mp)
{
	struct ether_vlan_header	*evhp;
	mblk_t				*bp;
	mblk_t				*bpt;
	mblk_t				*bph;
	mblk_t				*bpn;

	bpn = bph = bpt = NULL;

	for (bp = *mp; bp != NULL; bp = bpn) {

		bpn = bp->b_next;
		bp->b_next = bp->b_prev = NULL;

		evhp = (struct ether_vlan_header *)bp->b_rptr;

		if (ntohs(evhp->ether_tpid) == ETHERTYPE_VLAN &&
		    VLAN_ID(ntohs(evhp->ether_tci)) == pvid) {

			bp = vnet_vlan_remove_tag(bp);
			if (bp == NULL) {
				continue;
			}

		}

		/* build a chain of processed packets */
		if (bph == NULL) {
			bph = bpt = bp;
		} else {
			bpt->b_next = bp;
			bpt = bp;
		}

	}

	*mp = bph;
}

static void
vnet_rx(vio_net_handle_t vrh, mblk_t *mp)
{
	vnet_res_t		*vresp = (vnet_res_t *)vrh;
	vnet_t			*vnetp = vresp->vnetp;
	vnet_pseudo_rx_ring_t	*ringp;

	if ((vnetp == NULL) || (vnetp->mh == 0)) {
		freemsgchain(mp);
		return;
	}

	ringp = vresp->rx_ringp;
	mac_rx_ring(vnetp->mh, ringp->handle, mp, ringp->gen_num);
}

void
vnet_tx_update(vio_net_handle_t vrh)
{
	vnet_res_t		*vresp = (vnet_res_t *)vrh;
	vnet_t			*vnetp = vresp->vnetp;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	vnet_pseudo_tx_group_t	*tx_grp;
	int			i;

	if (vnetp == NULL || vnetp->mh == NULL) {
		return;
	}

	/*
	 * Currently, the tx hwring API (used to access rings that belong to
	 * a Hybrid IO resource) does not provide us a per ring flow ctrl
	 * update; also the pseudo rings are shared by the ports/ldcs in the
	 * vgen layer. Thus we can't figure out which pseudo ring is being
	 * re-enabled for transmits. To work around this, when we get a tx
	 * restart notification from below, we simply propagate that to all
	 * the tx pseudo rings registered with the mac layer above.
	 *
	 * There are a couple of side effects with this approach, but they are
	 * not harmful, as outlined below:
	 *
	 * A) We might send an invalid ring_update() for a ring that is not
	 * really flow controlled. This will not have any effect in the mac
	 * layer and packets will continue to be transmitted on that ring.
	 *
	 * B) We might end up clearing the flow control in the mac layer for
	 * a ring that is still flow controlled in the underlying resource.
	 * This will result in the mac layer restarting	transmit, only to be
	 * flow controlled again on that ring.
	 */
	tx_grp = &vnetp->tx_grp[0];
	for (i = 0; i < tx_grp->ring_cnt; i++) {
		tx_ringp = &tx_grp->rings[i];
		mac_tx_ring_update(vnetp->mh, tx_ringp->handle);
	}
}

/*
 * vnet_tx_notify_thread:
 *
 * vnet_tx_ring_update() callback function wakes up this thread when
 * it gets called. This thread will call mac_tx_ring_update() to
 * notify upper mac of flow control getting relieved. Note that
 * vnet_tx_ring_update() cannot call mac_tx_ring_update() directly
 * because vnet_tx_ring_update() is called from lower mac with
 * mi_rw_lock held and mac_tx_ring_update() would also try to grab
 * the same lock.
 */
static void
vnet_tx_notify_thread(void *arg)
{
	callb_cpr_t		cprinfo;
	vnet_pseudo_tx_group_t	*tx_grp = (vnet_pseudo_tx_group_t *)arg;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	vnet_t			*vnetp;
	int			i;

	CALLB_CPR_INIT(&cprinfo, &tx_grp->flowctl_lock, callb_generic_cpr,
	    "vnet_tx_notify_thread");

	mutex_enter(&tx_grp->flowctl_lock);
	while (!tx_grp->flowctl_done) {
		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&tx_grp->flowctl_cv, &tx_grp->flowctl_lock);
		CALLB_CPR_SAFE_END(&cprinfo, &tx_grp->flowctl_lock);

		for (i = 0; i < tx_grp->ring_cnt; i++) {
			tx_ringp = &tx_grp->rings[i];
			if (tx_ringp->woken_up) {
				tx_ringp->woken_up = B_FALSE;
				vnetp = tx_ringp->vnetp;
				mac_tx_ring_update(vnetp->mh, tx_ringp->handle);
			}
		}
	}
	/*
	 * The tx_grp is being destroyed, exit the thread.
	 */
	tx_grp->flowctl_thread = NULL;
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

void
vnet_tx_ring_update(void *arg1, uintptr_t arg2)
{
	vnet_t			*vnetp = (vnet_t *)arg1;
	vnet_pseudo_tx_group_t	*tx_grp;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	int			i;

	tx_grp = &vnetp->tx_grp[0];
	for (i = 0; i < tx_grp->ring_cnt; i++) {
		tx_ringp = &tx_grp->rings[i];
		if (tx_ringp->hw_rh == (mac_ring_handle_t)arg2) {
			mutex_enter(&tx_grp->flowctl_lock);
			tx_ringp->woken_up = B_TRUE;
			cv_signal(&tx_grp->flowctl_cv);
			mutex_exit(&tx_grp->flowctl_lock);
			break;
		}
	}
}

/*
 * Update the new mtu of vnet into the mac layer. First check if the device has
 * been plumbed and if so fail the mtu update. Returns 0 on success.
 */
int
vnet_mtu_update(vnet_t *vnetp, uint32_t mtu)
{
	int	rv;

	if (vnetp == NULL || vnetp->mh == NULL) {
		return (EINVAL);
	}

	WRITE_ENTER(&vnetp->vrwlock);

	if (vnetp->flags & VNET_STARTED) {
		RW_EXIT(&vnetp->vrwlock);
		cmn_err(CE_NOTE, "!vnet%d: Unable to process mtu "
		    "update as the device is plumbed\n",
		    vnetp->instance);
		return (EBUSY);
	}

	/* update mtu in the mac layer */
	rv = mac_maxsdu_update(vnetp->mh, mtu);
	if (rv != 0) {
		RW_EXIT(&vnetp->vrwlock);
		cmn_err(CE_NOTE,
		    "!vnet%d: Unable to update mtu with mac layer\n",
		    vnetp->instance);
		return (EIO);
	}

	vnetp->mtu = mtu;

	RW_EXIT(&vnetp->vrwlock);

	return (0);
}

/*
 * Update the link state of vnet to the mac layer.
 */
void
vnet_link_update(vnet_t *vnetp, link_state_t link_state)
{
	if (vnetp == NULL || vnetp->mh == NULL) {
		return;
	}

	WRITE_ENTER(&vnetp->vrwlock);
	if (vnetp->link_state == link_state) {
		RW_EXIT(&vnetp->vrwlock);
		return;
	}
	vnetp->link_state = link_state;
	RW_EXIT(&vnetp->vrwlock);

	mac_link_update(vnetp->mh, link_state);
}

/*
 * vio_net_resource_reg -- An interface called to register a resource
 *	with vnet.
 *	macp -- a GLDv3 mac_register that has all the details of
 *		a resource and its callbacks etc.
 *	type -- resource type.
 *	local_macaddr -- resource's MAC address. This is used to
 *			 associate a resource with a corresponding vnet.
 *	remote_macaddr -- remote side MAC address. This is ignored for
 *			  the Hybrid resources.
 *	vhp -- A handle returned to the caller.
 *	vcb -- A set of callbacks provided to the callers.
 */
int vio_net_resource_reg(mac_register_t *macp, vio_net_res_type_t type,
    ether_addr_t local_macaddr, ether_addr_t rem_macaddr, vio_net_handle_t *vhp,
    vio_net_callbacks_t *vcb)
{
	vnet_t		*vnetp;
	vnet_res_t	*vresp;

	vresp = kmem_zalloc(sizeof (vnet_res_t), KM_SLEEP);
	ether_copy(local_macaddr, vresp->local_macaddr);
	ether_copy(rem_macaddr, vresp->rem_macaddr);
	vresp->type = type;
	bcopy(macp, &vresp->macreg, sizeof (mac_register_t));

	DBG1(NULL, "Resource Registerig type=0%X\n", type);

	READ_ENTER(&vnet_rw);
	vnetp = vnet_headp;
	while (vnetp != NULL) {
		if (VNET_MATCH_RES(vresp, vnetp)) {
			vresp->vnetp = vnetp;

			/* Setup kstats for hio resource */
			if (vresp->type == VIO_NET_RES_HYBRID) {
				vresp->ksp = vnet_hio_setup_kstats(DRV_NAME,
				    "hio", vresp);
				if (vresp->ksp == NULL) {
					cmn_err(CE_NOTE, "!vnet%d: Cannot "
					    "create kstats for hio resource",
					    vnetp->instance);
				}
			}
			vnet_add_resource(vnetp, vresp);
			break;
		}
		vnetp = vnetp->nextp;
	}
	RW_EXIT(&vnet_rw);
	if (vresp->vnetp == NULL) {
		DWARN(NULL, "No vnet instance");
		kmem_free(vresp, sizeof (vnet_res_t));
		return (ENXIO);
	}

	*vhp = vresp;
	vcb->vio_net_rx_cb = vnet_rx;
	vcb->vio_net_tx_update = vnet_tx_update;
	vcb->vio_net_report_err = vnet_handle_res_err;

	/* Bind the resource to pseudo ring(s) */
	if (vnet_bind_rings(vresp) != 0) {
		(void) vnet_rem_resource(vnetp, vresp);
		vnet_hio_destroy_kstats(vresp->ksp);
		KMEM_FREE(vresp);
		return (1);
	}

	/* Dispatch a task to start resources */
	vnet_dispatch_res_task(vnetp);
	return (0);
}

/*
 * vio_net_resource_unreg -- An interface to unregister a resource.
 */
void
vio_net_resource_unreg(vio_net_handle_t vhp)
{
	vnet_res_t	*vresp = (vnet_res_t *)vhp;
	vnet_t		*vnetp = vresp->vnetp;

	DBG1(NULL, "Resource Registerig hdl=0x%p", vhp);

	ASSERT(vnetp != NULL);
	/*
	 * Remove the resource from fdb; this ensures
	 * there are no references to the resource.
	 */
	vnet_fdbe_del(vnetp, vresp);

	vnet_unbind_rings(vresp);

	/* Now remove the resource from the list */
	(void) vnet_rem_resource(vnetp, vresp);

	vnet_hio_destroy_kstats(vresp->ksp);
	KMEM_FREE(vresp);
}

static void
vnet_add_resource(vnet_t *vnetp, vnet_res_t *vresp)
{
	WRITE_ENTER(&vnetp->vrwlock);
	vresp->nextp = vnetp->vres_list;
	vnetp->vres_list = vresp;
	RW_EXIT(&vnetp->vrwlock);
}

static vnet_res_t *
vnet_rem_resource(vnet_t *vnetp, vnet_res_t *vresp)
{
	vnet_res_t	*vrp;

	WRITE_ENTER(&vnetp->vrwlock);
	if (vresp == vnetp->vres_list) {
		vnetp->vres_list = vresp->nextp;
	} else {
		vrp = vnetp->vres_list;
		while (vrp->nextp != NULL) {
			if (vrp->nextp == vresp) {
				vrp->nextp = vresp->nextp;
				break;
			}
			vrp = vrp->nextp;
		}
	}
	vresp->vnetp = NULL;
	vresp->nextp = NULL;

	RW_EXIT(&vnetp->vrwlock);

	return (vresp);
}

/*
 * vnet_dds_rx -- an interface called by vgen to DDS messages.
 */
void
vnet_dds_rx(void *arg, void *dmsg)
{
	vnet_t *vnetp = arg;
	vdds_process_dds_msg(vnetp, dmsg);
}

/*
 * vnet_send_dds_msg -- An interface provided to DDS to send
 *	DDS messages. This simply sends meessages via vgen.
 */
int
vnet_send_dds_msg(vnet_t *vnetp, void *dmsg)
{
	int rv;

	if (vnetp->vgenhdl != NULL) {
		rv = vgen_dds_tx(vnetp->vgenhdl, dmsg);
	}
	return (rv);
}

/*
 * vnet_cleanup_hio -- an interface called by vgen to cleanup hio resources.
 */
void
vnet_dds_cleanup_hio(vnet_t *vnetp)
{
	vdds_cleanup_hio(vnetp);
}

/*
 * vnet_handle_res_err -- A callback function called by a resource
 *	to report an error. For example, vgen can call to report
 *	an LDC down/reset event. This will trigger cleanup of associated
 *	Hybrid resource.
 */
/* ARGSUSED */
static void
vnet_handle_res_err(vio_net_handle_t vrh, vio_net_err_val_t err)
{
	vnet_res_t *vresp = (vnet_res_t *)vrh;
	vnet_t *vnetp = vresp->vnetp;

	if (vnetp == NULL) {
		return;
	}
	if ((vresp->type != VIO_NET_RES_LDC_SERVICE) &&
	    (vresp->type != VIO_NET_RES_HYBRID)) {
		return;
	}

	vdds_cleanup_hio(vnetp);
}

/*
 * vnet_dispatch_res_task -- A function to dispatch tasks start resources.
 */
static void
vnet_dispatch_res_task(vnet_t *vnetp)
{
	int rv;

	/*
	 * Dispatch the task. It could be the case that vnetp->flags does
	 * not have VNET_STARTED set. This is ok as vnet_rest_start_task()
	 * can abort the task when the task is started. See related comments
	 * in vnet_m_stop() and vnet_stop_resources().
	 */
	rv = ddi_taskq_dispatch(vnetp->taskqp, vnet_res_start_task,
	    vnetp, DDI_NOSLEEP);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "vnet%d:Can't dispatch start resource task",
		    vnetp->instance);
	}
}

/*
 * vnet_res_start_task -- A taskq callback function that starts a resource.
 */
static void
vnet_res_start_task(void *arg)
{
	vnet_t *vnetp = arg;

	WRITE_ENTER(&vnetp->vrwlock);
	if (vnetp->flags & VNET_STARTED) {
		vnet_start_resources(vnetp);
	}
	RW_EXIT(&vnetp->vrwlock);
}

/*
 * vnet_start_resources -- starts all resources associated with
 *	a vnet.
 */
static void
vnet_start_resources(vnet_t *vnetp)
{
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;
	vnet_res_t	*vresp;
	int rv;

	DBG1(vnetp, "enter\n");

	ASSERT(RW_WRITE_HELD(&vnetp->vrwlock));

	for (vresp = vnetp->vres_list; vresp != NULL; vresp = vresp->nextp) {
		/* skip if it is already started */
		if (vresp->flags & VNET_STARTED) {
			continue;
		}
		macp = &vresp->macreg;
		cbp = macp->m_callbacks;
		rv = cbp->mc_start(macp->m_driver);
		if (rv == 0) {
			/*
			 * Successfully started the resource, so now
			 * add it to the fdb.
			 */
			vresp->flags |= VNET_STARTED;
			vnet_fdbe_add(vnetp, vresp);
		}
	}

	DBG1(vnetp, "exit\n");

}

/*
 * vnet_stop_resources -- stop all resources associated with a vnet.
 */
static void
vnet_stop_resources(vnet_t *vnetp)
{
	vnet_res_t	*vresp;
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;

	DBG1(vnetp, "enter\n");

	ASSERT(RW_WRITE_HELD(&vnetp->vrwlock));

	for (vresp = vnetp->vres_list; vresp != NULL; ) {
		if (vresp->flags & VNET_STARTED) {
			/*
			 * Release the lock while invoking mc_stop() of the
			 * underlying resource. We hold a reference to this
			 * resource to prevent being removed from the list in
			 * vio_net_resource_unreg(). Note that new resources
			 * can be added to the head of the list while the lock
			 * is released, but they won't be started, as
			 * VNET_STARTED flag has been cleared for the vnet
			 * device in vnet_m_stop(). Also, while the lock is
			 * released a resource could be removed from the list
			 * in vio_net_resource_unreg(); but that is ok, as we
			 * re-acquire the lock and only then access the forward
			 * link (vresp->nextp) to continue with the next
			 * resource.
			 */
			vresp->flags &= ~VNET_STARTED;
			vresp->flags |= VNET_STOPPING;
			macp = &vresp->macreg;
			cbp = macp->m_callbacks;
			VNET_FDBE_REFHOLD(vresp);
			RW_EXIT(&vnetp->vrwlock);

			cbp->mc_stop(macp->m_driver);

			WRITE_ENTER(&vnetp->vrwlock);
			vresp->flags &= ~VNET_STOPPING;
			VNET_FDBE_REFRELE(vresp);
		}
		vresp = vresp->nextp;
	}
	DBG1(vnetp, "exit\n");
}

/*
 * Setup kstats for the HIO statistics.
 * NOTE: the synchronization for the statistics is the
 * responsibility of the caller.
 */
kstat_t *
vnet_hio_setup_kstats(char *ks_mod, char *ks_name, vnet_res_t *vresp)
{
	kstat_t *ksp;
	vnet_t *vnetp = vresp->vnetp;
	vnet_hio_kstats_t *hiokp;
	size_t size;

	ASSERT(vnetp != NULL);
	size = sizeof (vnet_hio_kstats_t) / sizeof (kstat_named_t);
	ksp = kstat_create(ks_mod, vnetp->instance, ks_name, "net",
	    KSTAT_TYPE_NAMED, size, 0);
	if (ksp == NULL) {
		return (NULL);
	}

	hiokp = (vnet_hio_kstats_t *)ksp->ks_data;
	kstat_named_init(&hiokp->ipackets,		"ipackets",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->ierrors,		"ierrors",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->opackets,		"opackets",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->oerrors,		"oerrors",
	    KSTAT_DATA_ULONG);


	/* MIB II kstat variables */
	kstat_named_init(&hiokp->rbytes,		"rbytes",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->obytes,		"obytes",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->multircv,		"multircv",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->multixmt,		"multixmt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->brdcstrcv,		"brdcstrcv",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->brdcstxmt,		"brdcstxmt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->norcvbuf,		"norcvbuf",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&hiokp->noxmtbuf,		"noxmtbuf",
	    KSTAT_DATA_ULONG);

	ksp->ks_update = vnet_hio_update_kstats;
	ksp->ks_private = (void *)vresp;
	kstat_install(ksp);
	return (ksp);
}

/*
 * Destroy kstats.
 */
static void
vnet_hio_destroy_kstats(kstat_t *ksp)
{
	if (ksp != NULL)
		kstat_delete(ksp);
}

/*
 * Update the kstats.
 */
static int
vnet_hio_update_kstats(kstat_t *ksp, int rw)
{
	vnet_t *vnetp;
	vnet_res_t *vresp;
	vnet_hio_stats_t statsp;
	vnet_hio_kstats_t *hiokp;

	vresp = (vnet_res_t *)ksp->ks_private;
	vnetp = vresp->vnetp;

	bzero(&statsp, sizeof (vnet_hio_stats_t));

	READ_ENTER(&vnetp->vsw_fp_rw);
	if (vnetp->hio_fp == NULL) {
		/* not using hio resources, just return */
		RW_EXIT(&vnetp->vsw_fp_rw);
		return (0);
	}
	VNET_FDBE_REFHOLD(vnetp->hio_fp);
	RW_EXIT(&vnetp->vsw_fp_rw);
	vnet_hio_get_stats(vnetp->hio_fp, &statsp);
	VNET_FDBE_REFRELE(vnetp->hio_fp);

	hiokp = (vnet_hio_kstats_t *)ksp->ks_data;

	if (rw == KSTAT_READ) {
		/* Link Input/Output stats */
		hiokp->ipackets.value.ul	= (uint32_t)statsp.ipackets;
		hiokp->ipackets64.value.ull	= statsp.ipackets;
		hiokp->ierrors.value.ul		= statsp.ierrors;
		hiokp->opackets.value.ul	= (uint32_t)statsp.opackets;
		hiokp->opackets64.value.ull	= statsp.opackets;
		hiokp->oerrors.value.ul		= statsp.oerrors;

		/* MIB II kstat variables */
		hiokp->rbytes.value.ul		= (uint32_t)statsp.rbytes;
		hiokp->rbytes64.value.ull	= statsp.rbytes;
		hiokp->obytes.value.ul		= (uint32_t)statsp.obytes;
		hiokp->obytes64.value.ull	= statsp.obytes;
		hiokp->multircv.value.ul	= statsp.multircv;
		hiokp->multixmt.value.ul	= statsp.multixmt;
		hiokp->brdcstrcv.value.ul	= statsp.brdcstrcv;
		hiokp->brdcstxmt.value.ul	= statsp.brdcstxmt;
		hiokp->norcvbuf.value.ul	= statsp.norcvbuf;
		hiokp->noxmtbuf.value.ul	= statsp.noxmtbuf;
	} else {
		return (EACCES);
	}

	return (0);
}

static void
vnet_hio_get_stats(vnet_res_t *vresp, vnet_hio_stats_t *statsp)
{
	mac_register_t		*macp;
	mac_callbacks_t		*cbp;
	uint64_t		val;
	int			stat;

	/*
	 * get the specified statistics from the underlying nxge.
	 */
	macp = &vresp->macreg;
	cbp = macp->m_callbacks;
	for (stat = MAC_STAT_MIN; stat < MAC_STAT_OVERFLOWS; stat++) {
		if (cbp->mc_getstat(macp->m_driver, stat, &val) == 0) {
			switch (stat) {
			case MAC_STAT_IPACKETS:
				statsp->ipackets = val;
				break;

			case MAC_STAT_IERRORS:
				statsp->ierrors = val;
				break;

			case MAC_STAT_OPACKETS:
				statsp->opackets = val;
				break;

			case MAC_STAT_OERRORS:
				statsp->oerrors = val;
				break;

			case MAC_STAT_RBYTES:
				statsp->rbytes = val;
				break;

			case MAC_STAT_OBYTES:
				statsp->obytes = val;
				break;

			case MAC_STAT_MULTIRCV:
				statsp->multircv = val;
				break;

			case MAC_STAT_MULTIXMT:
				statsp->multixmt = val;
				break;

			case MAC_STAT_BRDCSTRCV:
				statsp->brdcstrcv = val;
				break;

			case MAC_STAT_BRDCSTXMT:
				statsp->brdcstxmt = val;
				break;

			case MAC_STAT_NOXMTBUF:
				statsp->noxmtbuf = val;
				break;

			case MAC_STAT_NORCVBUF:
				statsp->norcvbuf = val;
				break;

			default:
				/*
				 * parameters not interested.
				 */
				break;
			}
		}
	}
}

static boolean_t
vnet_m_capab(void *arg, mac_capab_t cap, void *cap_data)
{
	vnet_t	*vnetp = (vnet_t *)arg;

	if (vnetp == NULL) {
		return (0);
	}

	switch (cap) {

	case MAC_CAPAB_RINGS: {

		mac_capab_rings_t *cap_rings = cap_data;
		/*
		 * Rings Capability Notes:
		 * We advertise rings to make use of the rings framework in
		 * gldv3 mac layer, to improve the performance. This is
		 * specifically needed when a Hybrid resource (with multiple
		 * tx/rx hardware rings) is assigned to a vnet device. We also
		 * leverage this for the normal case when no Hybrid resource is
		 * assigned.
		 *
		 * Ring Allocation:
		 * - TX path:
		 * We expose a pseudo ring group with 2 pseudo tx rings (as
		 * currently HybridIO exports only 2 rings) In the normal case,
		 * transmit traffic that comes down to the driver through the
		 * mri_tx (vnet_tx_ring_send()) entry point goes through the
		 * distributed switching algorithm in vnet and gets transmitted
		 * over a port/LDC in the vgen layer to either the vswitch or a
		 * peer vnet. If and when a Hybrid resource is assigned to the
		 * vnet, we obtain the tx ring information of the Hybrid device
		 * (nxge) and map the pseudo rings 1:1 to the 2 hw tx rings.
		 * Traffic being sent over the Hybrid resource by the mac layer
		 * gets spread across both hw rings, as they are mapped to the
		 * 2 pseudo tx rings in vnet.
		 *
		 * - RX path:
		 * We expose a pseudo ring group with 3 pseudo rx rings (static
		 * rings) initially. The first (default) pseudo rx ring is
		 * reserved for the resource that connects to the vswitch
		 * service. The next 2 rings are reserved for a Hybrid resource
		 * that may be assigned to the vnet device. If and when a
		 * Hybrid resource is assigned to the vnet, we obtain the rx
		 * ring information of the Hybrid device (nxge) and map these
		 * pseudo rings 1:1 to the 2 hw rx rings. For each additional
		 * resource that connects to a peer vnet, we dynamically
		 * allocate a pseudo rx ring and map it to that resource, when
		 * the resource gets added; and the pseudo rx ring is
		 * dynamically registered with the upper mac layer. We do the
		 * reverse and unregister the ring with the mac layer when
		 * the resource gets removed.
		 *
		 * Synchronization notes:
		 * We don't need any lock to protect members of ring structure,
		 * specifically ringp->hw_rh, in either the TX or the RX ring,
		 * as explained below.
		 * - TX ring:
		 * ring->hw_rh is initialized only when a Hybrid resource is
		 * associated; and gets referenced only in vnet_hio_tx(). The
		 * Hybrid resource itself is available in fdb only after tx
		 * hwrings are found and mapped; i.e, in vio_net_resource_reg()
		 * we call vnet_bind_rings() first and then call
		 * vnet_start_resources() which adds an entry to fdb. For
		 * traffic going over LDC resources, we don't reference
		 * ring->hw_rh at all.
		 * - RX ring:
		 * For rings mapped to Hybrid resource ring->hw_rh is
		 * initialized and only then do we add the rx callback for
		 * the underlying Hybrid resource; we disable callbacks before
		 * we unmap ring->hw_rh. For rings mapped to LDC resources, we
		 * stop the rx callbacks (in vgen) before we remove ring->hw_rh
		 * (vio_net_resource_unreg()).
		 * Also, we access ring->hw_rh in vnet_rx_ring_stat().
		 * Note that for rings mapped to Hybrid resource, though the
		 * rings are statically registered with the mac layer, its
		 * hardware ring mapping (ringp->hw_rh) can be torn down in
		 * vnet_unbind_hwrings() while the kstat operation is in
		 * progress. To protect against this, we hold a reference to
		 * the resource in FDB; this ensures that the thread in
		 * vio_net_resource_unreg() waits for the reference to be
		 * dropped before unbinding the ring.
		 *
		 * We don't need to do this for rings mapped to LDC resources.
		 * These rings are registered/unregistered dynamically with
		 * the mac layer and so any attempt to unregister the ring
		 * while kstat operation is in progress will block in
		 * mac_group_rem_ring(). Thus implicitly protects the
		 * resource (ringp->hw_rh) from disappearing.
		 */

		if (cap_rings->mr_type == MAC_RING_TYPE_RX) {
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;

			/*
			 * The ring_cnt for rx grp is initialized in
			 * vnet_ring_grp_init(). Later, the ring_cnt gets
			 * updated dynamically whenever LDC resources are added
			 * or removed.
			 */
			cap_rings->mr_rnum = vnetp->rx_grp[0].ring_cnt;
			cap_rings->mr_rget = vnet_get_ring;

			cap_rings->mr_gnum = VNET_NUM_PSEUDO_GROUPS;
			cap_rings->mr_gget = vnet_get_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
		} else {
			cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;

			/*
			 * The ring_cnt for tx grp is initialized in
			 * vnet_ring_grp_init() and remains constant, as we
			 * do not support dymanic tx rings for now.
			 */
			cap_rings->mr_rnum = vnetp->tx_grp[0].ring_cnt;
			cap_rings->mr_rget = vnet_get_ring;

			/*
			 * Transmit rings are not grouped; i.e, the number of
			 * transmit ring groups advertised should be set to 0.
			 */
			cap_rings->mr_gnum = 0;

			cap_rings->mr_gget = vnet_get_group;
			cap_rings->mr_gaddring = NULL;
			cap_rings->mr_gremring = NULL;
		}
		return (B_TRUE);

	}

	default:
		break;

	}

	return (B_FALSE);
}

/*
 * Callback funtion for MAC layer to get ring information.
 */
static void
vnet_get_ring(void *arg, mac_ring_type_t rtype, const int g_index,
    const int r_index, mac_ring_info_t *infop, mac_ring_handle_t r_handle)
{
	vnet_t	*vnetp = arg;

	switch (rtype) {

	case MAC_RING_TYPE_RX: {

		vnet_pseudo_rx_group_t	*rx_grp;
		vnet_pseudo_rx_ring_t	*rx_ringp;
		mac_intr_t		*mintr;

		/* We advertised only one RX group */
		ASSERT(g_index == 0);
		rx_grp = &vnetp->rx_grp[g_index];

		/* Check the current # of rings in the rx group */
		ASSERT((r_index >= 0) && (r_index < rx_grp->max_ring_cnt));

		/* Get the ring based on the index */
		rx_ringp = &rx_grp->rings[r_index];

		rx_ringp->handle = r_handle;
		/*
		 * Note: we don't need to save the incoming r_index in rx_ring,
		 * as vnet_ring_grp_init() would have initialized the index for
		 * each ring in the array.
		 */
		rx_ringp->grp = rx_grp;
		rx_ringp->vnetp = vnetp;

		mintr = &infop->mri_intr;
		mintr->mi_handle = (mac_intr_handle_t)rx_ringp;
		mintr->mi_enable = (mac_intr_enable_t)vnet_ring_enable_intr;
		mintr->mi_disable = (mac_intr_disable_t)vnet_ring_disable_intr;

		infop->mri_driver = (mac_ring_driver_t)rx_ringp;
		infop->mri_start = vnet_rx_ring_start;
		infop->mri_stop = vnet_rx_ring_stop;
		infop->mri_stat = vnet_rx_ring_stat;

		/* Set the poll function, as this is an rx ring */
		infop->mri_poll = vnet_rx_poll;
		/*
		 * MAC_RING_RX_ENQUEUE bit needed to be set for nxge
		 * which was not sending packet chains in interrupt
		 * context. For such drivers, packets are queued in
		 * Rx soft rings so that we get a chance to switch
		 * into a polling mode under backlog. This bug (not
		 * sending packet chains) has now been fixed. Once
		 * the performance impact is measured, this change
		 * will be removed.
		 */
		infop->mri_flags = (vnet_mac_rx_queuing ?
		    MAC_RING_RX_ENQUEUE : 0);
		break;
	}

	case MAC_RING_TYPE_TX: {
		vnet_pseudo_tx_group_t	*tx_grp;
		vnet_pseudo_tx_ring_t	*tx_ringp;

		/*
		 * No need to check grp index; mac layer passes -1 for it.
		 */
		tx_grp = &vnetp->tx_grp[0];

		/* Check the # of rings in the tx group */
		ASSERT((r_index >= 0) && (r_index < tx_grp->ring_cnt));

		/* Get the ring based on the index */
		tx_ringp = &tx_grp->rings[r_index];

		tx_ringp->handle = r_handle;
		tx_ringp->index = r_index;
		tx_ringp->grp = tx_grp;
		tx_ringp->vnetp = vnetp;

		infop->mri_driver = (mac_ring_driver_t)tx_ringp;
		infop->mri_start = vnet_tx_ring_start;
		infop->mri_stop = vnet_tx_ring_stop;
		infop->mri_stat = vnet_tx_ring_stat;

		/* Set the transmit function, as this is a tx ring */
		infop->mri_tx = vnet_tx_ring_send;
		/*
		 * MAC_RING_TX_SERIALIZE bit needs to be set while
		 * hybridIO is enabled to workaround tx lock
		 * contention issues in nxge.
		 */
		infop->mri_flags = (vnet_mac_tx_serialize ?
		    MAC_RING_TX_SERIALIZE : 0);
		break;
	}

	default:
		break;
	}
}

/*
 * Callback funtion for MAC layer to get group information.
 */
static void
vnet_get_group(void *arg, mac_ring_type_t type, const int index,
	mac_group_info_t *infop, mac_group_handle_t handle)
{
	vnet_t	*vnetp = (vnet_t *)arg;

	switch (type) {

	case MAC_RING_TYPE_RX:
	{
		vnet_pseudo_rx_group_t	*rx_grp;

		/* We advertised only one RX group */
		ASSERT(index == 0);

		rx_grp = &vnetp->rx_grp[index];
		rx_grp->handle = handle;
		rx_grp->index = index;
		rx_grp->vnetp = vnetp;

		infop->mgi_driver = (mac_group_driver_t)rx_grp;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = vnet_addmac;
		infop->mgi_remmac = vnet_remmac;
		infop->mgi_count = rx_grp->ring_cnt;

		break;
	}

	case MAC_RING_TYPE_TX:
	{
		vnet_pseudo_tx_group_t	*tx_grp;

		/* We advertised only one TX group */
		ASSERT(index == 0);

		tx_grp = &vnetp->tx_grp[index];
		tx_grp->handle = handle;
		tx_grp->index = index;
		tx_grp->vnetp = vnetp;

		infop->mgi_driver = (mac_group_driver_t)tx_grp;
		infop->mgi_start = NULL;
		infop->mgi_stop = NULL;
		infop->mgi_addmac = NULL;
		infop->mgi_remmac = NULL;
		infop->mgi_count = VNET_NUM_PSEUDO_TXRINGS;

		break;
	}

	default:
		break;

	}
}

static int
vnet_rx_ring_start(mac_ring_driver_t arg, uint64_t mr_gen_num)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)arg;
	int			err;

	/*
	 * If this ring is mapped to a LDC resource, simply mark the state to
	 * indicate the ring is started and return.
	 */
	if ((rx_ringp->state &
	    (VNET_RXRING_LDC_SERVICE|VNET_RXRING_LDC_GUEST)) != 0) {
		rx_ringp->gen_num = mr_gen_num;
		rx_ringp->state |= VNET_RXRING_STARTED;
		return (0);
	}

	ASSERT((rx_ringp->state & VNET_RXRING_HYBRID) != 0);

	/*
	 * This must be a ring reserved for a hwring. If the hwring is not
	 * bound yet, simply mark the state to indicate the ring is started and
	 * return. If and when a hybrid resource is activated for this vnet
	 * device, we will bind the hwring and start it then. If a hwring is
	 * already bound, start it now.
	 */
	if (rx_ringp->hw_rh == NULL) {
		rx_ringp->gen_num = mr_gen_num;
		rx_ringp->state |= VNET_RXRING_STARTED;
		return (0);
	}

	err = mac_hwring_activate(rx_ringp->hw_rh);
	if (err == 0) {
		rx_ringp->gen_num = mr_gen_num;
		rx_ringp->state |= VNET_RXRING_STARTED;
	} else {
		err = ENXIO;
	}

	return (err);
}

static void
vnet_rx_ring_stop(mac_ring_driver_t arg)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)arg;

	/*
	 * If this ring is mapped to a LDC resource, simply mark the state to
	 * indicate the ring is now stopped and return.
	 */
	if ((rx_ringp->state &
	    (VNET_RXRING_LDC_SERVICE|VNET_RXRING_LDC_GUEST)) != 0) {
		rx_ringp->state &= ~VNET_RXRING_STARTED;
		return;
	}

	ASSERT((rx_ringp->state & VNET_RXRING_HYBRID) != 0);

	/*
	 * This must be a ring reserved for a hwring. If the hwring is not
	 * bound yet, simply mark the state to indicate the ring is stopped and
	 * return. If a hwring is already bound, stop it now.
	 */
	if (rx_ringp->hw_rh == NULL) {
		rx_ringp->state &= ~VNET_RXRING_STARTED;
		return;
	}

	mac_hwring_quiesce(rx_ringp->hw_rh);
	rx_ringp->state &= ~VNET_RXRING_STARTED;
}

static int
vnet_rx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)rdriver;
	vnet_t			*vnetp = (vnet_t *)rx_ringp->vnetp;
	vnet_res_t		*vresp;
	mac_register_t		*macp;
	mac_callbacks_t		*cbp;

	/*
	 * Refer to vnet_m_capab() function for detailed comments on ring
	 * synchronization.
	 */
	if ((rx_ringp->state & VNET_RXRING_HYBRID) != 0) {
		READ_ENTER(&vnetp->vsw_fp_rw);
		if (vnetp->hio_fp == NULL) {
			RW_EXIT(&vnetp->vsw_fp_rw);
			return (0);
		}

		VNET_FDBE_REFHOLD(vnetp->hio_fp);
		RW_EXIT(&vnetp->vsw_fp_rw);
		(void) mac_hwring_getstat(rx_ringp->hw_rh, stat, val);
		VNET_FDBE_REFRELE(vnetp->hio_fp);
		return (0);
	}

	ASSERT((rx_ringp->state &
	    (VNET_RXRING_LDC_SERVICE|VNET_RXRING_LDC_GUEST)) != 0);
	vresp = (vnet_res_t *)rx_ringp->hw_rh;
	macp = &vresp->macreg;
	cbp = macp->m_callbacks;

	cbp->mc_getstat(macp->m_driver, stat, val);

	return (0);
}

/* ARGSUSED */
static int
vnet_tx_ring_start(mac_ring_driver_t arg, uint64_t mr_gen_num)
{
	vnet_pseudo_tx_ring_t	*tx_ringp = (vnet_pseudo_tx_ring_t *)arg;

	tx_ringp->state |= VNET_TXRING_STARTED;
	return (0);
}

static void
vnet_tx_ring_stop(mac_ring_driver_t arg)
{
	vnet_pseudo_tx_ring_t	*tx_ringp = (vnet_pseudo_tx_ring_t *)arg;

	tx_ringp->state &= ~VNET_TXRING_STARTED;
}

static int
vnet_tx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	vnet_pseudo_tx_ring_t	*tx_ringp = (vnet_pseudo_tx_ring_t *)rdriver;
	vnet_tx_ring_stats_t	*statsp;

	statsp = &tx_ringp->tx_ring_stats;

	switch (stat) {
	case MAC_STAT_OPACKETS:
		*val = statsp->opackets;
		break;

	case MAC_STAT_OBYTES:
		*val = statsp->obytes;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Disable polling for a ring and enable its interrupt.
 */
static int
vnet_ring_enable_intr(void *arg)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)arg;
	vnet_res_t		*vresp;

	if (rx_ringp->hw_rh == NULL) {
		/*
		 * Ring enable intr func is being invoked, but the ring is
		 * not bound to any underlying resource ? This must be a ring
		 * reserved for Hybrid resource and no such resource has been
		 * assigned to this vnet device yet. We simply return success.
		 */
		ASSERT((rx_ringp->state & VNET_RXRING_HYBRID) != 0);
		return (0);
	}

	/*
	 * The rx ring has been bound to either a LDC or a Hybrid resource.
	 * Call the appropriate function to enable interrupts for the ring.
	 */
	if (rx_ringp->state & VNET_RXRING_HYBRID) {
		return (mac_hwring_enable_intr(rx_ringp->hw_rh));
	} else {
		vresp = (vnet_res_t *)rx_ringp->hw_rh;
		return (vgen_enable_intr(vresp->macreg.m_driver));
	}
}

/*
 * Enable polling for a ring and disable its interrupt.
 */
static int
vnet_ring_disable_intr(void *arg)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)arg;
	vnet_res_t		*vresp;

	if (rx_ringp->hw_rh == NULL) {
		/*
		 * Ring disable intr func is being invoked, but the ring is
		 * not bound to any underlying resource ? This must be a ring
		 * reserved for Hybrid resource and no such resource has been
		 * assigned to this vnet device yet. We simply return success.
		 */
		ASSERT((rx_ringp->state & VNET_RXRING_HYBRID) != 0);
		return (0);
	}

	/*
	 * The rx ring has been bound to either a LDC or a Hybrid resource.
	 * Call the appropriate function to disable interrupts for the ring.
	 */
	if (rx_ringp->state & VNET_RXRING_HYBRID) {
		return (mac_hwring_disable_intr(rx_ringp->hw_rh));
	} else {
		vresp = (vnet_res_t *)rx_ringp->hw_rh;
		return (vgen_disable_intr(vresp->macreg.m_driver));
	}
}

/*
 * Poll 'bytes_to_pickup' bytes of message from the rx ring.
 */
static mblk_t *
vnet_rx_poll(void *arg, int bytes_to_pickup)
{
	vnet_pseudo_rx_ring_t	*rx_ringp = (vnet_pseudo_rx_ring_t *)arg;
	mblk_t			*mp = NULL;
	vnet_res_t		*vresp;
	vnet_t			*vnetp = rx_ringp->vnetp;

	if (rx_ringp->hw_rh == NULL) {
		return (NULL);
	}

	if (rx_ringp->state & VNET_RXRING_HYBRID) {
		mp = mac_hwring_poll(rx_ringp->hw_rh, bytes_to_pickup);
		/*
		 * Packets received over a hybrid resource need additional
		 * processing to remove the tag, for the pvid case. The
		 * underlying resource is not aware of the vnet's pvid and thus
		 * packets are received with the vlan tag in the header; unlike
		 * packets that are received over a ldc channel in which case
		 * the peer vnet/vsw would have already removed the tag.
		 */
		if (vnetp->pvid != vnetp->default_vlan_id) {
			vnet_rx_frames_untag(vnetp->pvid, &mp);
		}
	} else {
		vresp = (vnet_res_t *)rx_ringp->hw_rh;
		mp = vgen_rx_poll(vresp->macreg.m_driver, bytes_to_pickup);
	}
	return (mp);
}

/* ARGSUSED */
void
vnet_hio_rx_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
	boolean_t loopback)
{
	vnet_t			*vnetp = (vnet_t *)arg;
	vnet_pseudo_rx_ring_t	*ringp = (vnet_pseudo_rx_ring_t *)mrh;

	/*
	 * Packets received over a hybrid resource need additional processing
	 * to remove the tag, for the pvid case. The underlying resource is
	 * not aware of the vnet's pvid and thus packets are received with the
	 * vlan tag in the header; unlike packets that are received over a ldc
	 * channel in which case the peer vnet/vsw would have already removed
	 * the tag.
	 */
	if (vnetp->pvid != vnetp->default_vlan_id) {
		vnet_rx_frames_untag(vnetp->pvid, &mp);
		if (mp == NULL) {
			return;
		}
	}
	mac_rx_ring(vnetp->mh, ringp->handle, mp, ringp->gen_num);
}

static int
vnet_addmac(void *arg, const uint8_t *mac_addr)
{
	vnet_pseudo_rx_group_t  *rx_grp = (vnet_pseudo_rx_group_t *)arg;
	vnet_t			*vnetp;

	vnetp = rx_grp->vnetp;

	if (bcmp(mac_addr, vnetp->curr_macaddr, ETHERADDRL) == 0) {
		return (0);
	}

	cmn_err(CE_CONT, "!vnet%d: %s: Multiple macaddr unsupported\n",
	    vnetp->instance, __func__);
	return (EINVAL);
}

static int
vnet_remmac(void *arg, const uint8_t *mac_addr)
{
	vnet_pseudo_rx_group_t  *rx_grp = (vnet_pseudo_rx_group_t *)arg;
	vnet_t			*vnetp;

	vnetp = rx_grp->vnetp;

	if (bcmp(mac_addr, vnetp->curr_macaddr, ETHERADDRL) == 0) {
		return (0);
	}

	cmn_err(CE_CONT, "!vnet%d: %s: Invalid macaddr: %s\n",
	    vnetp->instance, __func__, ether_sprintf((void *)mac_addr));
	return (EINVAL);
}

int
vnet_hio_mac_init(vnet_t *vnetp, char *ifname)
{
	mac_handle_t		mh;
	mac_client_handle_t	mch = NULL;
	mac_unicast_handle_t	muh = NULL;
	mac_diag_t		diag;
	mac_register_t		*macp;
	char			client_name[MAXNAMELEN];
	int			rv;
	uint16_t		mac_flags = MAC_UNICAST_TAG_DISABLE |
	    MAC_UNICAST_STRIP_DISABLE | MAC_UNICAST_PRIMARY;
	vio_net_callbacks_t	vcb;
	ether_addr_t		rem_addr =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint32_t		retries = 0;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		return (EAGAIN);
	}

	do {
		rv = mac_open_by_linkname(ifname, &mh);
		if (rv == 0) {
			break;
		}
		if (rv != ENOENT || (retries++ >= vnet_mac_open_retries)) {
			mac_free(macp);
			return (rv);
		}
		drv_usecwait(vnet_mac_open_delay);
	} while (rv == ENOENT);

	vnetp->hio_mh = mh;

	(void) snprintf(client_name, MAXNAMELEN, "vnet%d-%s", vnetp->instance,
	    ifname);
	rv = mac_client_open(mh, &mch, client_name, MAC_OPEN_FLAGS_EXCLUSIVE);
	if (rv != 0) {
		goto fail;
	}
	vnetp->hio_mch = mch;

	rv = mac_unicast_add(mch, vnetp->curr_macaddr, mac_flags, &muh, 0,
	    &diag);
	if (rv != 0) {
		goto fail;
	}
	vnetp->hio_muh = muh;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = vnetp;
	macp->m_dip = NULL;
	macp->m_src_addr = NULL;
	macp->m_callbacks = &vnet_hio_res_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ETHERMTU;

	rv = vio_net_resource_reg(macp, VIO_NET_RES_HYBRID,
	    vnetp->curr_macaddr, rem_addr, &vnetp->hio_vhp, &vcb);
	if (rv != 0) {
		goto fail;
	}
	mac_free(macp);

	/* add the recv callback */
	mac_rx_set(vnetp->hio_mch, vnet_hio_rx_cb, vnetp);

	return (0);

fail:
	mac_free(macp);
	vnet_hio_mac_cleanup(vnetp);
	return (1);
}

void
vnet_hio_mac_cleanup(vnet_t *vnetp)
{
	if (vnetp->hio_vhp != NULL) {
		vio_net_resource_unreg(vnetp->hio_vhp);
		vnetp->hio_vhp = NULL;
	}

	if (vnetp->hio_muh != NULL) {
		(void) mac_unicast_remove(vnetp->hio_mch, vnetp->hio_muh);
		vnetp->hio_muh = NULL;
	}

	if (vnetp->hio_mch != NULL) {
		mac_client_close(vnetp->hio_mch, 0);
		vnetp->hio_mch = NULL;
	}

	if (vnetp->hio_mh != NULL) {
		mac_close(vnetp->hio_mh);
		vnetp->hio_mh = NULL;
	}
}

/* Bind pseudo rings to hwrings */
static int
vnet_bind_hwrings(vnet_t *vnetp)
{
	mac_ring_handle_t	hw_rh[VNET_NUM_HYBRID_RINGS];
	mac_perim_handle_t	mph1;
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	vnet_pseudo_tx_group_t	*tx_grp;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	int			hw_ring_cnt;
	int			i;
	int			rv;

	mac_perim_enter_by_mh(vnetp->hio_mh, &mph1);

	/* Get the list of the underlying RX rings. */
	hw_ring_cnt = mac_hwrings_get(vnetp->hio_mch, &vnetp->rx_hwgh, hw_rh,
	    MAC_RING_TYPE_RX);

	/* We expect the the # of hw rx rings to match VNET_NUM_HYBRID_RINGS */
	if (hw_ring_cnt != VNET_NUM_HYBRID_RINGS) {
		cmn_err(CE_WARN,
		    "!vnet%d: vnet_bind_hwrings: bad rx hw_ring_cnt(%d)\n",
		    vnetp->instance, hw_ring_cnt);
		goto fail;
	}

	if (vnetp->rx_hwgh != NULL) {
		/*
		 * Quiesce the HW ring and the mac srs on the ring. Note
		 * that the HW ring will be restarted when the pseudo ring
		 * is started. At that time all the packets will be
		 * directly passed up to the pseudo RX ring and handled
		 * by mac srs created over the pseudo RX ring.
		 */
		mac_rx_client_quiesce(vnetp->hio_mch);
		mac_srs_perm_quiesce(vnetp->hio_mch, B_TRUE);
	}

	/*
	 * Bind the pseudo rings to the hwrings and start the hwrings.
	 * Note we don't need to register these with the upper mac, as we have
	 * statically exported these pseudo rxrings which are reserved for
	 * rxrings of Hybrid resource.
	 */
	rx_grp = &vnetp->rx_grp[0];
	for (i = 0; i < VNET_NUM_HYBRID_RINGS; i++) {
		/* Pick the rxrings reserved for Hybrid resource */
		rx_ringp = &rx_grp->rings[i + VNET_HYBRID_RXRING_INDEX];

		/* Store the hw ring handle */
		rx_ringp->hw_rh = hw_rh[i];

		/* Bind the pseudo ring to the underlying hwring */
		mac_hwring_setup(rx_ringp->hw_rh,
		    (mac_resource_handle_t)rx_ringp, NULL);

		/* Start the hwring if needed */
		if (rx_ringp->state & VNET_RXRING_STARTED) {
			rv = mac_hwring_activate(rx_ringp->hw_rh);
			if (rv != 0) {
				mac_hwring_teardown(rx_ringp->hw_rh);
				rx_ringp->hw_rh = NULL;
				goto fail;
			}
		}
	}

	/* Get the list of the underlying TX rings. */
	hw_ring_cnt = mac_hwrings_get(vnetp->hio_mch, &vnetp->tx_hwgh, hw_rh,
	    MAC_RING_TYPE_TX);

	/* We expect the # of hw tx rings to match VNET_NUM_HYBRID_RINGS */
	if (hw_ring_cnt != VNET_NUM_HYBRID_RINGS) {
		cmn_err(CE_WARN,
		    "!vnet%d: vnet_bind_hwrings: bad tx hw_ring_cnt(%d)\n",
		    vnetp->instance, hw_ring_cnt);
		goto fail;
	}

	/*
	 * Now map the pseudo txrings to the hw txrings. Note we don't need
	 * to register these with the upper mac, as we have statically exported
	 * these rings. Note that these rings will continue to be used for LDC
	 * resources to peer vnets and vswitch (shared ring).
	 */
	tx_grp = &vnetp->tx_grp[0];
	for (i = 0; i < tx_grp->ring_cnt; i++) {
		tx_ringp = &tx_grp->rings[i];
		tx_ringp->hw_rh = hw_rh[i];
		tx_ringp->state |= VNET_TXRING_HYBRID;
	}
	tx_grp->tx_notify_handle =
	    mac_client_tx_notify(vnetp->hio_mch, vnet_tx_ring_update, vnetp);

	mac_perim_exit(mph1);
	return (0);

fail:
	mac_perim_exit(mph1);
	vnet_unbind_hwrings(vnetp);
	return (1);
}

/* Unbind pseudo rings from hwrings */
static void
vnet_unbind_hwrings(vnet_t *vnetp)
{
	mac_perim_handle_t	mph1;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_tx_group_t	*tx_grp;
	vnet_pseudo_tx_ring_t	*tx_ringp;
	int			i;

	mac_perim_enter_by_mh(vnetp->hio_mh, &mph1);

	tx_grp = &vnetp->tx_grp[0];
	for (i = 0; i < VNET_NUM_HYBRID_RINGS; i++) {
		tx_ringp = &tx_grp->rings[i];
		if (tx_ringp->state & VNET_TXRING_HYBRID) {
			tx_ringp->state &= ~VNET_TXRING_HYBRID;
			tx_ringp->hw_rh = NULL;
		}
	}
	(void) mac_client_tx_notify(vnetp->hio_mch, NULL,
	    tx_grp->tx_notify_handle);

	rx_grp = &vnetp->rx_grp[0];
	for (i = 0; i < VNET_NUM_HYBRID_RINGS; i++) {
		rx_ringp = &rx_grp->rings[i + VNET_HYBRID_RXRING_INDEX];
		if (rx_ringp->hw_rh != NULL) {
			/* Stop the hwring */
			mac_hwring_quiesce(rx_ringp->hw_rh);

			/* Teardown the hwring */
			mac_hwring_teardown(rx_ringp->hw_rh);
			rx_ringp->hw_rh = NULL;
		}
	}

	if (vnetp->rx_hwgh != NULL) {
		vnetp->rx_hwgh = NULL;
		/*
		 * First clear the permanent-quiesced flag of the RX srs then
		 * restart the HW ring and the mac srs on the ring.
		 */
		mac_srs_perm_quiesce(vnetp->hio_mch, B_FALSE);
		mac_rx_client_restart(vnetp->hio_mch);
	}

	mac_perim_exit(mph1);
}

/* Bind pseudo ring to a LDC resource */
static int
vnet_bind_vgenring(vnet_res_t *vresp)
{
	vnet_t			*vnetp;
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	mac_perim_handle_t	mph1;
	int			rv;
	int			type;

	vnetp = vresp->vnetp;
	type = vresp->type;
	rx_grp = &vnetp->rx_grp[0];

	if (type == VIO_NET_RES_LDC_SERVICE) {
		/*
		 * Ring Index 0 is the default ring in the group and is
		 * reserved for LDC_SERVICE in vnet_ring_grp_init(). This ring
		 * is allocated statically and is reported to the mac layer
		 * in vnet_m_capab(). So, all we need to do here, is save a
		 * reference to the associated vresp.
		 */
		rx_ringp = &rx_grp->rings[0];
		rx_ringp->hw_rh = (mac_ring_handle_t)vresp;
		vresp->rx_ringp = (void *)rx_ringp;
		return (0);
	}
	ASSERT(type == VIO_NET_RES_LDC_GUEST);

	mac_perim_enter_by_mh(vnetp->mh, &mph1);

	rx_ringp = vnet_alloc_pseudo_rx_ring(vnetp);
	if (rx_ringp == NULL) {
		cmn_err(CE_WARN, "!vnet%d: Failed to allocate pseudo rx ring",
		    vnetp->instance);
		goto fail;
	}

	/* Store the LDC resource itself as the ring handle */
	rx_ringp->hw_rh = (mac_ring_handle_t)vresp;

	/*
	 * Save a reference to the ring in the resource for lookup during
	 * unbind. Note this is only done for LDC resources. We don't need this
	 * in the case of a Hybrid resource (see vnet_bind_hwrings()), as its
	 * rx rings are mapped to reserved pseudo rx rings (index 1 and 2).
	 */
	vresp->rx_ringp = (void *)rx_ringp;
	rx_ringp->state |= VNET_RXRING_LDC_GUEST;

	/* Register the pseudo ring with upper-mac */
	rv = mac_group_add_ring(rx_grp->handle, rx_ringp->index);
	if (rv != 0) {
		rx_ringp->state &= ~VNET_RXRING_LDC_GUEST;
		rx_ringp->hw_rh = NULL;
		vnet_free_pseudo_rx_ring(vnetp, rx_ringp);
		goto fail;
	}

	mac_perim_exit(mph1);
	return (0);
fail:
	mac_perim_exit(mph1);
	return (1);
}

/* Unbind pseudo ring from a LDC resource */
static void
vnet_unbind_vgenring(vnet_res_t *vresp)
{
	vnet_t			*vnetp;
	vnet_pseudo_rx_group_t	*rx_grp;
	vnet_pseudo_rx_ring_t	*rx_ringp;
	mac_perim_handle_t	mph1;
	int			type;

	vnetp = vresp->vnetp;
	type = vresp->type;
	rx_grp = &vnetp->rx_grp[0];

	if (vresp->rx_ringp == NULL) {
		return;
	}

	if (type == VIO_NET_RES_LDC_SERVICE) {
		/*
		 * Ring Index 0 is the default ring in the group and is
		 * reserved for LDC_SERVICE in vnet_ring_grp_init(). This ring
		 * is allocated statically and is reported to the mac layer
		 * in vnet_m_capab(). So, all we need to do here, is remove its
		 * reference to the associated vresp.
		 */
		rx_ringp = &rx_grp->rings[0];
		rx_ringp->hw_rh = NULL;
		vresp->rx_ringp = NULL;
		return;
	}
	ASSERT(type == VIO_NET_RES_LDC_GUEST);

	mac_perim_enter_by_mh(vnetp->mh, &mph1);

	rx_ringp = (vnet_pseudo_rx_ring_t *)vresp->rx_ringp;
	vresp->rx_ringp = NULL;

	if (rx_ringp != NULL && (rx_ringp->state & VNET_RXRING_LDC_GUEST)) {
		/* Unregister the pseudo ring with upper-mac */
		mac_group_rem_ring(rx_grp->handle, rx_ringp->handle);

		rx_ringp->hw_rh = NULL;
		rx_ringp->state &= ~VNET_RXRING_LDC_GUEST;

		/* Free the pseudo rx ring */
		vnet_free_pseudo_rx_ring(vnetp, rx_ringp);
	}

	mac_perim_exit(mph1);
}

static void
vnet_unbind_rings(vnet_res_t *vresp)
{
	switch (vresp->type) {

	case VIO_NET_RES_LDC_SERVICE:
	case VIO_NET_RES_LDC_GUEST:
		vnet_unbind_vgenring(vresp);
		break;

	case VIO_NET_RES_HYBRID:
		vnet_unbind_hwrings(vresp->vnetp);
		break;

	default:
		break;

	}
}

static int
vnet_bind_rings(vnet_res_t *vresp)
{
	int	rv;

	switch (vresp->type) {

	case VIO_NET_RES_LDC_SERVICE:
	case VIO_NET_RES_LDC_GUEST:
		rv = vnet_bind_vgenring(vresp);
		break;

	case VIO_NET_RES_HYBRID:
		rv = vnet_bind_hwrings(vresp->vnetp);
		break;

	default:
		rv = 1;
		break;

	}

	return (rv);
}

/* ARGSUSED */
int
vnet_hio_stat(void *arg, uint_t stat, uint64_t *val)
{
	vnet_t	*vnetp = (vnet_t *)arg;

	*val = mac_stat_get(vnetp->hio_mh, stat);
	return (0);
}

/*
 * The start() and stop() routines for the Hybrid resource below, are just
 * dummy functions. This is provided to avoid resource type specific code in
 * vnet_start_resources() and vnet_stop_resources(). The starting and stopping
 * of the Hybrid resource happens in the context of the mac_client interfaces
 * that are invoked in vnet_hio_mac_init() and vnet_hio_mac_cleanup().
 */
/* ARGSUSED */
static int
vnet_hio_start(void *arg)
{
	return (0);
}

/* ARGSUSED */
static void
vnet_hio_stop(void *arg)
{
}

mblk_t *
vnet_hio_tx(void *arg, mblk_t *mp)
{
	vnet_pseudo_tx_ring_t	*tx_ringp;
	mblk_t			*nextp;
	mblk_t			*ret_mp;

	tx_ringp = (vnet_pseudo_tx_ring_t *)arg;
	for (;;) {
		nextp = mp->b_next;
		mp->b_next = NULL;

		ret_mp = mac_hwring_tx(tx_ringp->hw_rh, mp);
		if (ret_mp != NULL) {
			ret_mp->b_next = nextp;
			mp = ret_mp;
			break;
		}

		if ((mp = nextp) == NULL)
			break;
	}
	return (mp);
}

#ifdef	VNET_IOC_DEBUG

/*
 * The ioctl entry point is used only for debugging for now. The ioctl commands
 * can be used to force the link state of the channel connected to vsw.
 */
static void
vnet_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	struct iocblk	*iocp;
	vnet_t		*vnetp;

	iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	iocp->ioc_error = 0;
	vnetp = (vnet_t *)arg;

	if (vnetp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {

	case VNET_FORCE_LINK_DOWN:
	case VNET_FORCE_LINK_UP:
		vnet_force_link_state(vnetp, q, mp);
		break;

	default:
		iocp->ioc_error = EINVAL;
		miocnak(q, mp, 0, iocp->ioc_error);
		break;

	}
}

static void
vnet_force_link_state(vnet_t *vnetp, queue_t *q, mblk_t *mp)
{
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;
	vnet_res_t	*vresp;

	READ_ENTER(&vnetp->vsw_fp_rw);

	vresp = vnetp->vsw_fp;
	if (vresp == NULL) {
		RW_EXIT(&vnetp->vsw_fp_rw);
		return;
	}

	macp = &vresp->macreg;
	cbp = macp->m_callbacks;
	cbp->mc_ioctl(macp->m_driver, q, mp);

	RW_EXIT(&vnetp->vsw_fp_rw);
}

#else

static void
vnet_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	vnet_t		*vnetp;

	vnetp = (vnet_t *)arg;

	if (vnetp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	/* ioctl support only for debugging */
	miocnak(q, mp, 0, ENOTSUP);
}

#endif
