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

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
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
#include <sys/mac.h>
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

/* vnet internal functions */
static int vnet_mac_register(vnet_t *);
static int vnet_read_mac_address(vnet_t *vnetp);

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
int vnet_mtu_update(vnet_t *vnetp, uint32_t mtu);

/* Exported to to vnet_dds */
int vnet_send_dds_msg(vnet_t *vnetp, void *dmsg);

/* Externs that are imported from vnet_gen */
extern int vgen_init(void *vnetp, uint64_t regprop, dev_info_t *vnetdip,
    const uint8_t *macaddr, void **vgenhdl);
extern int vgen_uninit(void *arg);
extern int vgen_dds_tx(void *arg, void *dmsg);

/* Externs that are imported from vnet_dds */
extern void vdds_mod_init(void);
extern void vdds_mod_fini(void);
extern int vdds_init(vnet_t *vnetp);
extern void vdds_cleanup(vnet_t *vnetp);
extern void vdds_process_dds_msg(vnet_t *vnetp, vio_dds_msg_t *dmsg);
extern void vdds_cleanup_hybrid_res(void *arg);

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

static mac_callbacks_t vnet_m_callbacks = {
	0,
	vnet_m_stat,
	vnet_m_start,
	vnet_m_stop,
	vnet_m_promisc,
	vnet_m_multicst,
	vnet_m_unicst,
	vnet_m_tx,
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
uint32_t vnet_ntxds = VNET_NTXDS;	/* power of 2 transmit descriptors */
uint32_t vnet_ldcwd_interval = VNET_LDCWD_INTERVAL; /* watchdog freq in msec */
uint32_t vnet_ldcwd_txtimeout = VNET_LDCWD_TXTIMEOUT;  /* tx timeout in msec */
uint32_t vnet_ldc_mtu = VNET_LDC_MTU;		/* ldc mtu */

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
	int status;

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
	vnet_t		*vnetp;
	int		status;
	int		instance;
	uint64_t	reg;
	char		qname[TASKQ_NAMELEN];
	enum	{ AST_init = 0x0, AST_vnet_alloc = 0x1,
		AST_mac_alloc = 0x2, AST_read_macaddr = 0x4,
		AST_vgen_init = 0x8, AST_fdbh_alloc = 0x10,
		AST_vdds_init = 0x20, AST_taskq_create = 0x40,
		AST_vnet_list = 0x80 } attach_state;

	attach_state = AST_init;

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
	attach_state |= AST_vnet_alloc;

	status = vdds_init(vnetp);
	if (status != 0) {
		goto vnet_attach_fail;
	}
	attach_state |= AST_vdds_init;

	/* setup links to vnet_t from both devinfo and mac_t */
	ddi_set_driver_private(dip, (caddr_t)vnetp);

	/* read the mac address */
	status = vnet_read_mac_address(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}
	attach_state |= AST_read_macaddr;

	reg = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", -1);
	if (reg == -1) {
		goto vnet_attach_fail;
	}
	vnetp->reg = reg;

	vnet_fdb_create(vnetp);
	attach_state |= AST_fdbh_alloc;

	(void) snprintf(qname, TASKQ_NAMELEN, "vnet_taskq%d", instance);
	if ((vnetp->taskqp = ddi_taskq_create(dip, qname, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "!vnet%d: Unable to create task queue",
		    instance);
		goto vnet_attach_fail;
	}
	attach_state |= AST_taskq_create;

	/* add to the list of vnet devices */
	WRITE_ENTER(&vnet_rw);
	vnetp->nextp = vnet_headp;
	vnet_headp = vnetp;
	RW_EXIT(&vnet_rw);

	attach_state |= AST_vnet_list;

	/*
	 * Initialize the generic vnet plugin which provides
	 * communication via sun4v LDC (logical domain channel) based
	 * resources. It will register the LDC resources as and when
	 * they become available.
	 */
	status = vgen_init(vnetp, reg, vnetp->dip,
	    (uint8_t *)vnetp->curr_macaddr, &vnetp->vgenhdl);
	if (status != DDI_SUCCESS) {
		DERR(vnetp, "vgen_init() failed\n");
		goto vnet_attach_fail;
	}
	attach_state |= AST_vgen_init;

	/* register with MAC layer */
	status = vnet_mac_register(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}

	DBG1(NULL, "instance(%d) exit\n", instance);
	return (DDI_SUCCESS);

vnet_attach_fail:

	if (attach_state & AST_vnet_list) {
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
	}

	if (attach_state & AST_vdds_init) {
		vdds_cleanup(vnetp);
	}
	if (attach_state & AST_taskq_create) {
		ddi_taskq_destroy(vnetp->taskqp);
	}
	if (attach_state & AST_fdbh_alloc) {
		vnet_fdb_destroy(vnetp);
	}
	if (attach_state & AST_vgen_init) {
		(void) vgen_uninit(vnetp->vgenhdl);
	}
	if (attach_state & AST_vnet_alloc) {
		rw_destroy(&vnetp->vrwlock);
		rw_destroy(&vnetp->vsw_fp_rw);
		KMEM_FREE(vnetp);
	}
	return (DDI_FAILURE);
}

/*
 * detach(9E): detach a device from the system.
 */
static int
vnetdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	vnet_t		*vnetp;
	vnet_t		**vnetpp;
	int		instance;
	int		rv;

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

	(void) vdds_cleanup(vnetp);
	rv = vgen_uninit(vnetp->vgenhdl);
	if (rv != DDI_SUCCESS) {
		goto vnet_detach_fail;
	}

	/*
	 * Unregister from the MAC subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure.
	 */
	if (mac_unregister(vnetp->mh) != 0)
		goto vnet_detach_fail;

	/* unlink from instance(vnet_t) list */
	WRITE_ENTER(&vnet_rw);
	for (vnetpp = &vnet_headp; *vnetpp; vnetpp = &(*vnetpp)->nextp) {
		if (*vnetpp == vnetp) {
			*vnetpp = vnetp->nextp;
			break;
		}
	}
	RW_EXIT(&vnet_rw);

	ddi_taskq_destroy(vnetp->taskqp);
	/* destroy fdb */
	vnet_fdb_destroy(vnetp);

	rw_destroy(&vnetp->vrwlock);
	rw_destroy(&vnetp->vsw_fp_rw);
	KMEM_FREE(vnetp);

	return (DDI_SUCCESS);

vnet_detach_fail:
	return (DDI_FAILURE);
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
		vnet_stop_resources(vnetp);
		vnetp->flags &= ~VNET_STARTED;
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

	vnet_t *vnetp = arg;
	vnet_res_t	*vresp;
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;
	int rv = VNET_SUCCESS;

	DBG1(vnetp, "enter\n");

	READ_ENTER(&vnetp->vrwlock);
	for (vresp = vnetp->vres_list; vresp != NULL; vresp = vresp->nextp) {
		if (vresp->type == VIO_NET_RES_LDC_SERVICE) {
			macp = &vresp->macreg;
			cbp = macp->m_callbacks;
			rv = cbp->mc_multicst(macp->m_driver, add, mca);
		}
	}
	RW_EXIT(&vnetp->vrwlock);

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
vnet_m_tx(void *arg, mblk_t *mp)
{
	vnet_t			*vnetp;
	vnet_res_t		*vresp;
	mblk_t			*next;
	mblk_t			*resid_mp;
	mac_register_t		*macp;
	struct ether_header	*ehp;
	boolean_t		is_unicast;
	boolean_t		is_pvid;	/* non-default pvid ? */
	boolean_t		hres;		/* Hybrid resource ? */

	vnetp = (vnet_t *)arg;
	DBG1(vnetp, "enter\n");
	ASSERT(mp != NULL);

	is_pvid = (vnetp->pvid != vnetp->default_vlan_id) ? B_TRUE : B_FALSE;

	while (mp != NULL) {

		next = mp->b_next;
		mp->b_next = NULL;

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
			}

			macp = &vresp->macreg;
			resid_mp = macp->m_callbacks->mc_tx(macp->m_driver, mp);

			/* tx done; now release ref on fdb entry */
			VNET_FDBE_REFRELE(vresp);

			if (resid_mp != NULL) {
				/* m_tx failed */
				mp->b_next = next;
				break;
			}
		}

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
	vnet_res_t	*vresp = (vnet_res_t *)vrh;
	vnet_t		*vnetp = vresp->vnetp;

	if ((vnetp == NULL) || (vnetp->mh == 0)) {
		freemsgchain(mp);
		return;
	}

	/*
	 * Packets received over a hybrid resource need additional processing
	 * to remove the tag, for the pvid case. The underlying resource is
	 * not aware of the vnet's pvid and thus packets are received with the
	 * vlan tag in the header; unlike packets that are received over a ldc
	 * channel in which case the peer vnet/vsw would have already removed
	 * the tag.
	 */
	if (vresp->type == VIO_NET_RES_HYBRID &&
	    vnetp->pvid != vnetp->default_vlan_id) {

		vnet_rx_frames_untag(vnetp->pvid, &mp);
		if (mp == NULL) {
			return;
		}
	}

	mac_rx(vnetp->mh, NULL, mp);
}

void
vnet_tx_update(vio_net_handle_t vrh)
{
	vnet_res_t *vresp = (vnet_res_t *)vrh;
	vnet_t *vnetp = vresp->vnetp;

	if ((vnetp != NULL) && (vnetp->mh != NULL)) {
		mac_tx_update(vnetp->mh);
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
	vnet_t	*vnetp;
	vnet_res_t *vresp;

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
			WRITE_ENTER(&vnetp->vrwlock);
			vresp->vnetp = vnetp;
			vresp->nextp = vnetp->vres_list;
			vnetp->vres_list = vresp;
			RW_EXIT(&vnetp->vrwlock);
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
	vnet_res_t *vresp = (vnet_res_t *)vhp;
	vnet_t *vnetp = vresp->vnetp;
	vnet_res_t *vrp;

	DBG1(NULL, "Resource Registerig hdl=0x%p", vhp);

	ASSERT(vnetp != NULL);
	vnet_fdbe_del(vnetp, vresp);

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
	KMEM_FREE(vresp);
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
	int rv;

	if (vnetp == NULL) {
		return;
	}
	if ((vresp->type != VIO_NET_RES_LDC_SERVICE) &&
	    (vresp->type != VIO_NET_RES_HYBRID)) {
		return;
	}
	rv = ddi_taskq_dispatch(vnetp->taskqp, vdds_cleanup_hybrid_res,
	    vnetp, DDI_NOSLEEP);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "vnet%d:Failed to dispatch task to cleanup hybrid resource",
		    vnetp->instance);
	}
}

/*
 * vnet_dispatch_res_task -- A function to dispatch tasks start resources.
 */
static void
vnet_dispatch_res_task(vnet_t *vnetp)
{
	int rv;

	WRITE_ENTER(&vnetp->vrwlock);
	if (vnetp->flags & VNET_STARTED) {
		rv = ddi_taskq_dispatch(vnetp->taskqp, vnet_res_start_task,
		    vnetp, DDI_NOSLEEP);
		if (rv != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "vnet%d:Can't dispatch start resource task",
			    vnetp->instance);
		}
	}
	RW_EXIT(&vnetp->vrwlock);
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
	vnet_res_t	*nvresp;
	mac_register_t	*macp;
	mac_callbacks_t	*cbp;

	DBG1(vnetp, "enter\n");

	for (vresp = vnetp->vres_list; vresp != NULL; ) {
		nvresp = vresp->nextp;
		if (vresp->flags & VNET_STARTED) {
			macp = &vresp->macreg;
			cbp = macp->m_callbacks;
			cbp->mc_stop(macp->m_driver);
			vresp->flags &= ~VNET_STARTED;
		}
		vresp = nvresp;
	}
	DBG1(vnetp, "exit\n");
}
