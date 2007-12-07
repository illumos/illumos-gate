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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/vnet.h>

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
static void vnet_fdb_alloc(vnet_t *vnetp);
static void vnet_fdb_free(vnet_t *vnetp);
static fdb_t *vnet_lookup_fdb(fdb_fanout_t *fdbhp, uint8_t *macaddr);

/* exported functions */
void vnet_add_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx, void *txarg);
void vnet_del_fdb(void *arg, uint8_t *macaddr);
void vnet_modify_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx,
	void *txarg, boolean_t upgrade);
void vnet_add_def_rte(void *arg, mac_tx_t m_tx, void *txarg);
void vnet_del_def_rte(void *arg);
void vnet_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp);
void vnet_tx_update(void *arg);

/* externs */
extern int vgen_init(void *vnetp, dev_info_t *vnetdip, const uint8_t *macaddr,
	mac_register_t **vgenmacp);
extern int vgen_uninit(void *arg);

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
uint32_t vnet_nfdb_hash = VNET_NFDB_HASH;	/* size of fdb hash table */

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

	vnet_fdb_alloc(vnetp);
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
		vnet_fdb_free(vnetp);
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

	vnet_fdb_free(vnetp);

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
	vnet_t *vnetp;
	mblk_t *next;
	uint32_t fdbhash;
	fdb_t *fdbp;
	fdb_fanout_t *fdbhp;
	struct ether_header *ehp;
	uint8_t *macaddr;
	mblk_t *resid_mp;

	vnetp = (vnet_t *)arg;
	DBG1(vnetp, "enter\n");
	ASSERT(mp != NULL);

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		/* get the destination mac address in the eth header */
		ehp = (struct ether_header *)mp->b_rptr;
		macaddr = (uint8_t *)&ehp->ether_dhost;

		/* Calculate hash value and fdb fanout */
		fdbhash = MACHASH(macaddr, vnetp->nfdb_hash);
		fdbhp = &(vnetp->fdbhp[fdbhash]);

		READ_ENTER(&fdbhp->rwlock);
		fdbp = vnet_lookup_fdb(fdbhp, macaddr);
		if (fdbp) {
			/*
			 * If the destination is in FDB, the destination is
			 * a vnet device within ldoms and directly reachable,
			 * invoke the tx function in the fdb entry.
			 */
			resid_mp = fdbp->m_tx(fdbp->txarg, mp);
			if (resid_mp != NULL) {
				/* m_tx failed */
				mp->b_next = next;
				RW_EXIT(&fdbhp->rwlock);
				break;
			}
			RW_EXIT(&fdbhp->rwlock);
		} else {
			/* destination is not in FDB */
			RW_EXIT(&fdbhp->rwlock);
			/*
			 * If the destination is broadcast/multicast
			 * or an unknown unicast address, forward the
			 * packet to vsw, using the last slot in fdb which is
			 * reserved for default route.
			 */
			fdbhp = &(vnetp->fdbhp[vnetp->nfdb_hash]);
			READ_ENTER(&fdbhp->rwlock);
			fdbp = fdbhp->headp;
			if (fdbp) {
				resid_mp = fdbp->m_tx(fdbp->txarg, mp);
				if (resid_mp != NULL) {
					/* m_tx failed */
					mp->b_next = next;
					RW_EXIT(&fdbhp->rwlock);
					break;
				}
			} else {
				/* drop the packet */
				freemsg(mp);
			}
			RW_EXIT(&fdbhp->rwlock);
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
	macp->m_max_sdu = ETHERMTU;

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


/*
 * Functions below are called only by generic transport to add/remove/modify
 * entries in forwarding database. See comments in vgen_port_init(vnet_gen.c).
 */

/* add an entry into the forwarding database */
void
vnet_add_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx, void *txarg)
{
	vnet_t *vnetp = (vnet_t *)arg;
	uint32_t fdbhash;
	fdb_t *fdbp;
	fdb_fanout_t *fdbhp;

	/* Calculate hash value and fdb fanout */
	fdbhash = MACHASH(macaddr, vnetp->nfdb_hash);
	fdbhp = &(vnetp->fdbhp[fdbhash]);

	WRITE_ENTER(&fdbhp->rwlock);

	fdbp = kmem_zalloc(sizeof (fdb_t), KM_NOSLEEP);
	if (fdbp == NULL) {
		RW_EXIT(&fdbhp->rwlock);
		return;
	}
	bcopy(macaddr, (caddr_t)fdbp->macaddr, ETHERADDRL);
	fdbp->m_tx = m_tx;
	fdbp->txarg = txarg;
	fdbp->nextp = fdbhp->headp;
	fdbhp->headp = fdbp;

	RW_EXIT(&fdbhp->rwlock);
}

/* delete an entry from the forwarding database */
void
vnet_del_fdb(void *arg, uint8_t *macaddr)
{
	vnet_t *vnetp = (vnet_t *)arg;
	uint32_t fdbhash;
	fdb_t *fdbp;
	fdb_t **pfdbp;
	fdb_fanout_t *fdbhp;

	/* Calculate hash value and fdb fanout */
	fdbhash = MACHASH(macaddr, vnetp->nfdb_hash);
	fdbhp = &(vnetp->fdbhp[fdbhash]);

	WRITE_ENTER(&fdbhp->rwlock);

	for (pfdbp = &fdbhp->headp; (fdbp  = *pfdbp) != NULL;
	    pfdbp = &fdbp->nextp) {
		if (bcmp(fdbp->macaddr, macaddr, ETHERADDRL) == 0) {
			/* Unlink it from the list */
			*pfdbp = fdbp->nextp;
			KMEM_FREE(fdbp);
			break;
		}
	}

	RW_EXIT(&fdbhp->rwlock);
}

/* modify an existing entry in the forwarding database */
void
vnet_modify_fdb(void *arg, uint8_t *macaddr, mac_tx_t m_tx, void *txarg,
	boolean_t upgrade)
{
	vnet_t *vnetp = (vnet_t *)arg;
	uint32_t fdbhash;
	fdb_t *fdbp;
	fdb_fanout_t *fdbhp;

	/* Calculate hash value and fdb fanout */
	fdbhash = MACHASH(macaddr, vnetp->nfdb_hash);
	fdbhp = &(vnetp->fdbhp[fdbhash]);

	if (upgrade == B_TRUE) {
		/*
		 * Caller already holds the lock as a reader. This can
		 * occur if this function is invoked in the context
		 * of transmit routine - vnet_m_tx(), where the lock
		 * is held as a reader before calling the transmit
		 * function of an fdb entry (fdbp->m_tx).
		 * See comments in vgen_ldcsend() in vnet_gen.c
		 */
		if (!rw_tryupgrade(&fdbhp->rwlock)) {
			RW_EXIT(&fdbhp->rwlock);
			WRITE_ENTER(&fdbhp->rwlock);
		}
	} else {
		/* Caller does not hold the lock */
		WRITE_ENTER(&fdbhp->rwlock);
	}

	for (fdbp = fdbhp->headp; fdbp != NULL; fdbp = fdbp->nextp) {
		if (bcmp(fdbp->macaddr, macaddr, ETHERADDRL) == 0) {
			/* change the entry to have new tx params */
			fdbp->m_tx = m_tx;
			fdbp->txarg = txarg;
			break;
		}
	}

	if (upgrade == B_TRUE) {
		/* restore the caller as a reader */
		rw_downgrade(&fdbhp->rwlock);
	} else {
		RW_EXIT(&fdbhp->rwlock);
	}
}

/* allocate the forwarding database */
static void
vnet_fdb_alloc(vnet_t *vnetp)
{
	int		i;
	uint32_t	nfdbh = 0;

	nfdbh = vnet_nfdb_hash;
	if ((nfdbh < VNET_NFDB_HASH) || (nfdbh > VNET_NFDB_HASH_MAX)) {
		vnetp->nfdb_hash = VNET_NFDB_HASH;
	} else {
		vnetp->nfdb_hash = nfdbh;
	}

	/* allocate fdb hash table, with an extra slot for default route */
	vnetp->fdbhp = kmem_zalloc(sizeof (fdb_fanout_t) *
	    (vnetp->nfdb_hash + 1), KM_SLEEP);

	for (i = 0; i <= vnetp->nfdb_hash; i++) {
		rw_init(&vnetp->fdbhp[i].rwlock, NULL, RW_DRIVER, NULL);
	}
}

/* free the forwarding database */
static void
vnet_fdb_free(vnet_t *vnetp)
{
	int i;

	for (i = 0; i <= vnetp->nfdb_hash; i++) {
		rw_destroy(&vnetp->fdbhp[i].rwlock);
	}

	/*
	 * deallocate fdb hash table, including an extra slot for default
	 * route.
	 */
	kmem_free(vnetp->fdbhp, sizeof (fdb_fanout_t) * (vnetp->nfdb_hash + 1));
	vnetp->fdbhp = NULL;
}

/* look up an fdb entry based on the mac address, caller holds lock */
static fdb_t *
vnet_lookup_fdb(fdb_fanout_t *fdbhp, uint8_t *macaddr)
{
	fdb_t *fdbp = NULL;

	for (fdbp = fdbhp->headp; fdbp != NULL; fdbp = fdbp->nextp) {
		if (bcmp(fdbp->macaddr, macaddr, ETHERADDRL) == 0) {
			break;
		}
	}

	return (fdbp);
}

/* add default route entry into the forwarding database */
void
vnet_add_def_rte(void *arg, mac_tx_t m_tx, void *txarg)
{
	vnet_t *vnetp = (vnet_t *)arg;
	fdb_t *fdbp;
	fdb_fanout_t *fdbhp;

	/*
	 * The last hash list is reserved for default route entry,
	 * and for now, we have only one entry in this list.
	 */
	fdbhp = &(vnetp->fdbhp[vnetp->nfdb_hash]);

	WRITE_ENTER(&fdbhp->rwlock);

	if (fdbhp->headp) {
		DWARN(vnetp, "default rte already exists\n");
		RW_EXIT(&fdbhp->rwlock);
		return;
	}
	fdbp = kmem_zalloc(sizeof (fdb_t), KM_NOSLEEP);
	if (fdbp == NULL) {
		RW_EXIT(&fdbhp->rwlock);
		return;
	}
	bzero(fdbp->macaddr, ETHERADDRL);
	fdbp->m_tx = m_tx;
	fdbp->txarg = txarg;
	fdbp->nextp = NULL;
	fdbhp->headp = fdbp;

	RW_EXIT(&fdbhp->rwlock);
}

/* delete default route entry from the forwarding database */
void
vnet_del_def_rte(void *arg)
{
	vnet_t *vnetp = (vnet_t *)arg;
	fdb_t *fdbp;
	fdb_fanout_t *fdbhp;

	/*
	 * The last hash list is reserved for default route entry,
	 * and for now, we have only one entry in this list.
	 */
	fdbhp = &(vnetp->fdbhp[vnetp->nfdb_hash]);

	WRITE_ENTER(&fdbhp->rwlock);

	if (fdbhp->headp == NULL) {
		RW_EXIT(&fdbhp->rwlock);
		return;
	}
	fdbp = fdbhp->headp;
	KMEM_FREE(fdbp);
	fdbhp->headp = NULL;

	RW_EXIT(&fdbhp->rwlock);
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
