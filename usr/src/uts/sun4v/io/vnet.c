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
static void vnet_add_vptl(vnet_t *vnetp, vp_tl_t *vp_tlp);
static void vnet_del_vptl(vnet_t *vnetp, vp_tl_t *vp_tlp);
static vp_tl_t *vnet_get_vptl(vnet_t *vnetp, const char *devname);

/* Forwarding database (FDB) routines */
static void vnet_fdb_create(vnet_t *vnetp);
static void vnet_fdb_destroy(vnet_t *vnetp);
static vnet_fdbe_t *vnet_fdbe_find(vnet_t *vnetp, struct ether_addr *eaddr);
static void vnet_fdbe_find_cb(mod_hash_key_t key, mod_hash_val_t val);
void vnet_fdbe_add(vnet_t *vnetp, struct ether_addr *macaddr,
	uint8_t type, mac_tx_t m_tx, void *port);
void vnet_fdbe_del(vnet_t *vnetp, struct ether_addr *eaddr);
void vnet_fdbe_modify(vnet_t *vnetp, struct ether_addr *macaddr,
	void *portp, boolean_t flag);

void vnet_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp);
void vnet_tx_update(void *arg);

/* externs */
extern int vgen_init(vnet_t *vnetp, dev_info_t *vnetdip, const uint8_t *macaddr,
	mac_register_t **vgenmacp);
extern int vgen_uninit(void *arg);

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

/*
 * Property names
 */
static char macaddr_propname[] = "local-mac-address";

/*
 * This is the string displayed by modinfo(1m).
 */
static char vnet_ident[] = "vnet driver v%I%";
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
	(struct bus_ops *)NULL	/* devo_bus_ops */
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
	vp_tl_t		*vp_tlp;
	int		instance;
	int		status;
	mac_register_t	*vgenmacp = NULL;
	enum	{ AST_init = 0x0, AST_vnet_alloc = 0x1,
		AST_mac_alloc = 0x2, AST_read_macaddr = 0x4,
		AST_vgen_init = 0x8, AST_vptl_alloc = 0x10,
		AST_fdbh_alloc = 0x20 } attach_state;

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
	attach_state |= AST_vnet_alloc;

	/* setup links to vnet_t from both devinfo and mac_t */
	ddi_set_driver_private(dip, (caddr_t)vnetp);
	vnetp->dip = dip;
	vnetp->instance = instance;

	/* read the mac address */
	status = vnet_read_mac_address(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}
	attach_state |= AST_read_macaddr;

	/*
	 * Initialize the generic vnet proxy transport. This is the first
	 * and default transport used by vnet. The generic transport
	 * is provided by using sun4v LDC (logical domain channel). On success,
	 * vgen_init() provides a pointer to mac_t of generic transport.
	 * Currently, this generic layer provides network connectivity to other
	 * vnets within ldoms and also to remote hosts oustide ldoms through
	 * the virtual switch (vsw) device on domain0. In the future, when
	 * physical adapters that are able to share their resources (such as
	 * dma channels) with guest domains become available, the vnet device
	 * will use hardware specific driver to communicate directly over the
	 * physical device to reach remote hosts without going through vswitch.
	 */
	status = vgen_init(vnetp, vnetp->dip, (uint8_t *)vnetp->curr_macaddr,
	    &vgenmacp);
	if (status != DDI_SUCCESS) {
		DERR(vnetp, "vgen_init() failed\n");
		goto vnet_attach_fail;
	}
	rw_init(&vnetp->trwlock, NULL, RW_DRIVER, NULL);
	attach_state |= AST_vgen_init;

	vp_tlp = kmem_zalloc(sizeof (vp_tl_t), KM_SLEEP);
	vp_tlp->macp = vgenmacp;
	(void) snprintf(vp_tlp->name, MAXNAMELEN, "%s%u", "vgen", instance);
	(void) strcpy(vnetp->vgen_name, vp_tlp->name);

	/* add generic transport to the list of vnet proxy transports */
	vnet_add_vptl(vnetp, vp_tlp);
	attach_state |= AST_vptl_alloc;

	vnet_fdb_create(vnetp);
	attach_state |= AST_fdbh_alloc;

	/* register with MAC layer */
	status = vnet_mac_register(vnetp);
	if (status != DDI_SUCCESS) {
		goto vnet_attach_fail;
	}

	/* add to the list of vnet devices */
	WRITE_ENTER(&vnet_rw);
	vnetp->nextp = vnet_headp;
	vnet_headp = vnetp;
	RW_EXIT(&vnet_rw);

	DBG1(NULL, "instance(%d) exit\n", instance);
	return (DDI_SUCCESS);

vnet_attach_fail:
	if (attach_state & AST_fdbh_alloc) {
		vnet_fdb_destroy(vnetp);
	}
	if (attach_state & AST_vptl_alloc) {
		WRITE_ENTER(&vnetp->trwlock);
		vnet_del_vptl(vnetp, vp_tlp);
		RW_EXIT(&vnetp->trwlock);
	}
	if (attach_state & AST_vgen_init) {
		(void) vgen_uninit(vgenmacp->m_driver);
		rw_destroy(&vnetp->trwlock);
	}
	if (attach_state & AST_vnet_alloc) {
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
	vp_tl_t		*vp_tlp;
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

	/* uninit and free vnet proxy transports */
	WRITE_ENTER(&vnetp->trwlock);
	while ((vp_tlp = vnetp->tlp) != NULL) {
		if (strcmp(vnetp->vgen_name, vp_tlp->name) == 0) {
			/* uninitialize generic transport */
			rv = vgen_uninit(vp_tlp->macp->m_driver);
			if (rv != DDI_SUCCESS) {
				RW_EXIT(&vnetp->trwlock);
				goto vnet_detach_fail;
			}
		}
		vnet_del_vptl(vnetp, vp_tlp);
	}
	RW_EXIT(&vnetp->trwlock);

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

	/* destroy fdb */
	vnet_fdb_destroy(vnetp);

	rw_destroy(&vnetp->trwlock);
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
	vp_tl_t		*vp_tlp;
	mac_register_t	*vp_macp;
	mac_callbacks_t	*cbp;

	DBG1(vnetp, "enter\n");

	/*
	 * NOTE:
	 * Currently, we only have generic transport. m_start() invokes
	 * vgen_start() which enables ports/channels in vgen and
	 * initiates handshake with peer vnets and vsw. In the future when we
	 * have support for hardware specific transports, this information
	 * needs to be propagted back to vnet from vgen and we need to revisit
	 * this code (see comments in vnet_attach()).
	 *
	 */
	WRITE_ENTER(&vnetp->trwlock);
	for (vp_tlp = vnetp->tlp; vp_tlp != NULL; vp_tlp = vp_tlp->nextp) {
		vp_macp = vp_tlp->macp;
		cbp = vp_macp->m_callbacks;
		cbp->mc_start(vp_macp->m_driver);
	}
	RW_EXIT(&vnetp->trwlock);

	DBG1(vnetp, "exit\n");
	return (VNET_SUCCESS);

}

/* stop transmit/receive for the device */
static void
vnet_m_stop(void *arg)
{
	vnet_t		*vnetp = arg;
	vp_tl_t		*vp_tlp;
	mac_register_t	*vp_macp;
	mac_callbacks_t	*cbp;

	DBG1(vnetp, "enter\n");

	WRITE_ENTER(&vnetp->trwlock);
	for (vp_tlp = vnetp->tlp; vp_tlp != NULL; vp_tlp = vp_tlp->nextp) {
		vp_macp = vp_tlp->macp;
		cbp = vp_macp->m_callbacks;
		cbp->mc_stop(vp_macp->m_driver);
	}
	RW_EXIT(&vnetp->trwlock);

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
	vp_tl_t		*vp_tlp;
	mac_register_t	*vp_macp;
	mac_callbacks_t	*cbp;
	int rv = VNET_SUCCESS;

	DBG1(vnetp, "enter\n");
	READ_ENTER(&vnetp->trwlock);
	for (vp_tlp = vnetp->tlp; vp_tlp != NULL; vp_tlp = vp_tlp->nextp) {
		if (strcmp(vnetp->vgen_name, vp_tlp->name) == 0) {
			vp_macp = vp_tlp->macp;
			cbp = vp_macp->m_callbacks;
			rv = cbp->mc_multicst(vp_macp->m_driver, add, mca);
			break;
		}
	}
	RW_EXIT(&vnetp->trwlock);
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
	vnet_fdbe_t		*fp;
	mblk_t			*next;
	mblk_t 			*resid_mp;
	struct ether_header 	*ehp;

	vnetp = (vnet_t *)arg;
	DBG1(vnetp, "enter\n");
	ASSERT(mp != NULL);

	while (mp != NULL) {

		next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Find fdb entry for the destination
		 * and hold a reference to it.
		 */
		ehp = (struct ether_header *)mp->b_rptr;
		fp = vnet_fdbe_find(vnetp, &ehp->ether_dhost);
		if (fp != NULL) {

			/*
			 * Destination found in FDB.
			 * The destination is a vnet device within ldoms
			 * and directly reachable, invoke the tx function
			 * in the fdb entry.
			 */
			resid_mp = fp->m_tx(fp->txarg, mp);

			/* tx done; now release ref on fdb entry */
			VNET_FDBE_REFRELE(fp);

			if (resid_mp != NULL) {
				/* m_tx failed */
				mp->b_next = next;
				break;
			}
		} else {
			/*
			 * Destination is not in FDB.
			 * If the destination is broadcast/multicast
			 * or an unknown unicast address, forward the
			 * packet to vsw, using the cached fdb entry
			 * to vsw.
			 */
			READ_ENTER(&vnetp->vsw_fp_rw);

			fp = vnetp->vsw_fp;
			if (fp == NULL) {
				/*
				 * no fdb entry to vsw? drop the packet.
				 */
				RW_EXIT(&vnetp->vsw_fp_rw);
				freemsg(mp);
				mp = next;
				continue;
			}

			/* ref hold the fdb entry to vsw */
			VNET_FDBE_REFHOLD(fp);

			RW_EXIT(&vnetp->vsw_fp_rw);

			resid_mp = fp->m_tx(fp->txarg, mp);

			/* tx done; now release ref on fdb entry */
			VNET_FDBE_REFRELE(fp);

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
	vp_tl_t	*vp_tlp;
	mac_register_t	*vp_macp;
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
	READ_ENTER(&vnetp->trwlock);
	for (vp_tlp = vnetp->tlp; vp_tlp != NULL; vp_tlp = vp_tlp->nextp) {
		vp_macp = vp_tlp->macp;
		cbp = vp_macp->m_callbacks;
		if (cbp->mc_getstat(vp_macp->m_driver, stat, val) == 0)
			val_total += *val;
	}
	RW_EXIT(&vnetp->trwlock);

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
	macp->m_max_sdu = vnet_ethermtu;
	macp->m_margin = VLAN_TAGSZ;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &vnetp->mh);
	mac_free(macp);
	return (err == 0 ? DDI_SUCCESS : DDI_FAILURE);
}

/* add vp_tl to the list */
static void
vnet_add_vptl(vnet_t *vnetp, vp_tl_t *vp_tlp)
{
	vp_tl_t *ttlp;

	WRITE_ENTER(&vnetp->trwlock);
	if (vnetp->tlp == NULL) {
		vnetp->tlp = vp_tlp;
	} else {
		ttlp = vnetp->tlp;
		while (ttlp->nextp)
			ttlp = ttlp->nextp;
		ttlp->nextp = vp_tlp;
	}
	RW_EXIT(&vnetp->trwlock);
}

/* remove vp_tl from the list */
static void
vnet_del_vptl(vnet_t *vnetp, vp_tl_t *vp_tlp)
{
	vp_tl_t *ttlp, **pretlp;
	boolean_t found = B_FALSE;

	pretlp = &vnetp->tlp;
	ttlp = *pretlp;
	while (ttlp) {
		if (ttlp == vp_tlp) {
			found = B_TRUE;
			(*pretlp) = ttlp->nextp;
			ttlp->nextp = NULL;
			break;
		}
		pretlp = &(ttlp->nextp);
		ttlp = *pretlp;
	}

	if (found) {
		KMEM_FREE(vp_tlp);
	}
}

/* get vp_tl corresponding to the given name */
static vp_tl_t *
vnet_get_vptl(vnet_t *vnetp, const char *name)
{
	vp_tl_t *tlp;

	tlp = vnetp->tlp;
	while (tlp) {
		if (strcmp(tlp->name, name) == 0) {
			return (tlp);
		}
		tlp = tlp->nextp;
	}
	DWARN(vnetp, "can't find vp_tl with name (%s)\n", name);
	return (NULL);
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
vnet_fdbe_add(vnet_t *vnetp, struct ether_addr *macaddr, uint8_t type,
	mac_tx_t m_tx, void *port)
{
	uint64_t	addr = 0;
	vnet_fdbe_t	*fp;
	int		rv;

	KEY_HASH(addr, macaddr);

	fp = kmem_zalloc(sizeof (vnet_fdbe_t), KM_SLEEP);
	fp->txarg = port;
	fp->type = type;
	fp->m_tx = m_tx;

	/*
	 * If the entry being added corresponds to vsw-port, we cache that
	 * entry and keep a permanent reference to it. This is done to avoid
	 * searching this entry when we need to transmit a frame with an
	 * unknown unicast destination, in vnet_m_tx().
	 */
	(fp->type == VNET_VSWPORT) ? (fp->refcnt = 1) : (fp->refcnt = 0);

	/*
	 * Note: duplicate keys will be rejected by mod_hash.
	 */
	rv = mod_hash_insert(vnetp->fdb_hashp, (mod_hash_key_t)addr,
	    (mod_hash_val_t)fp);
	if (rv != 0) {
		DWARN(vnetp, "Duplicate macaddr key(%lx)\n", addr);
		KMEM_FREE(fp);
		return;
	}

	if (type == VNET_VSWPORT) {
		/* Cache the fdb entry to vsw-port */
		WRITE_ENTER(&vnetp->vsw_fp_rw);
		if (vnetp->vsw_fp == NULL)
			vnetp->vsw_fp = fp;
		RW_EXIT(&vnetp->vsw_fp_rw);
	}
}

/*
 * Remove an entry from fdb.
 */
void
vnet_fdbe_del(vnet_t *vnetp, struct ether_addr *eaddr)
{
	uint64_t	addr = 0;
	vnet_fdbe_t	*fp;
	int		rv;
	uint32_t	refcnt;

	KEY_HASH(addr, eaddr);

	/*
	 * Remove the entry from fdb hash table.
	 * This prevents further references to this fdb entry.
	 */
	rv = mod_hash_remove(vnetp->fdb_hashp, (mod_hash_key_t)addr,
	    (mod_hash_val_t *)&fp);
	ASSERT(rv == 0);

	if (fp->type == VNET_VSWPORT) {
		WRITE_ENTER(&vnetp->vsw_fp_rw);

		ASSERT(fp == vnetp->vsw_fp);
		vnetp->vsw_fp = NULL;

		RW_EXIT(&vnetp->vsw_fp_rw);
	}

	/*
	 * If there are threads already ref holding before the entry was
	 * removed from hash table, then wait for ref count to drop to zero.
	 */
	(fp->type == VNET_VSWPORT) ? (refcnt = 1) : (refcnt = 0);
	while (fp->refcnt > refcnt) {
		delay(drv_usectohz(vnet_fdbe_refcnt_delay));
	}

	kmem_free(fp, sizeof (*fp));
}

/*
 * Modify the fdb entry for the given macaddr,
 * to use the specified port for transmits.
 */
void
vnet_fdbe_modify(vnet_t *vnetp, struct ether_addr *macaddr, void *portp,
	boolean_t flag)
{
	vnet_fdbe_t	*fp;
	uint64_t	addr = 0;
	int		rv;
	uint32_t	refcnt;

	KEY_HASH(addr, macaddr);

	/*
	 * Remove the entry from fdb hash table.
	 * This prevents further references to this fdb entry.
	 */
	rv = mod_hash_remove(vnetp->fdb_hashp, (mod_hash_key_t)addr,
	    (mod_hash_val_t *)&fp);
	ASSERT(rv == 0);

	/* fdb entry of vsw port must never be modified */
	ASSERT(fp->type == VNET_VNETPORT);

	/*
	 * If there are threads already ref holding before the entry was
	 * removed from hash table, then wait for reference count to drop to
	 * zero. Note: flag indicates the context of caller. If we are in the
	 * context of transmit routine, there is a reference held by the caller
	 * too, in which case, wait for the refcnt to drop to 1.
	 */
	(flag == B_TRUE) ? (refcnt = 1) : (refcnt = 0);
	while (fp->refcnt > refcnt) {
		delay(drv_usectohz(vnet_fdbe_refcnt_delay));
	}

	/* update the portp in fdb entry with the new value */
	fp->txarg = portp;

	/* Reinsert the updated fdb entry into the table */
	rv = mod_hash_insert(vnetp->fdb_hashp, (mod_hash_key_t)addr,
	    (mod_hash_val_t)fp);
	ASSERT(rv == 0);
}

/*
 * Search fdb for a given mac address. If an entry is found, hold
 * a reference to it and return the entry; else returns NULL.
 */
static vnet_fdbe_t *
vnet_fdbe_find(vnet_t *vnetp, struct ether_addr *addrp)
{
	uint64_t	key = 0;
	vnet_fdbe_t	*fp;
	int		rv;

	KEY_HASH(key, addrp);

	rv = mod_hash_find_cb(vnetp->fdb_hashp, (mod_hash_key_t)key,
	    (mod_hash_val_t *)&fp, vnet_fdbe_find_cb);

	if (rv != 0)
		return (NULL);

	return (fp);
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
	VNET_FDBE_REFHOLD((vnet_fdbe_t *)val);
}

void
vnet_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	vnet_t *vnetp = arg;
	mac_rx(vnetp->mh, mrh, mp);
}

void
vnet_tx_update(void *arg)
{
	vnet_t *vnetp = arg;
	mac_tx_update(vnetp->mh);
}
