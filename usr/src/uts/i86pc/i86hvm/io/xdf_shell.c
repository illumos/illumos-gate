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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <io/xdf_shell.h>
#include <sys/dkio.h>
#include <sys/scsi/scsi_types.h>

/*
 * General Notes
 *
 * We don't support disks with bad block mappins.  We have this
 * limitation because the underlying xdf driver doesn't support
 * bad block remapping.  If there is a need to support this feature
 * it should be added directly to the xdf driver and we should just
 * pass requests strait on through and let it handle the remapping.
 * Also, it's probably worth pointing out that most modern disks do bad
 * block remapping internally in the hardware so there's actually less
 * of a chance of us ever discovering bad blocks.  Also, in most cases
 * this driver (and the xdf driver) will only be used with virtualized
 * devices, so one might wonder why a virtual device would ever actually
 * experience bad blocks.  To wrap this up, you might be wondering how
 * these bad block mappings get created and how they are managed.  Well,
 * there are two tools for managing bad block mappings, format(1M) and
 * addbadsec(1M).  Format(1M) can be used to do a surface scan of a disk
 * to attempt to find bad block and create mappings for them.  Format(1M)
 * and addbadsec(1M) can also be used to edit existing mappings that may
 * be saved on the disk.
 *
 * The underlying PV driver that this driver passes on requests to is the
 * xdf driver.  Since in most cases the xdf driver doesn't deal with
 * physical disks it has it's own algorithm for assigning a physical
 * geometry to a virtual disk (ie, cylinder count, head count, etc.)
 * The default values chosen by the xdf driver may not match those
 * assigned to a disk by a hardware disk emulator in an HVM environment.
 * This is a problem since these physical geometry attributes affect
 * things like the partition table, backup label location, etc.  So
 * to emulate disk devices correctly we need to know the physical geometry
 * that was assigned to a disk at the time of it's initalization.
 * Normally in an HVM environment this information will passed to
 * the BIOS and operating system from the hardware emulator that is
 * emulating the disk devices.  In the case of a solaris dom0+xvm
 * this would be qemu.  So to work around this issue, this driver will
 * query the emulated hardware to get the assigned physical geometry
 * and then pass this geometry onto the xdf driver so that it can use it.
 * But really, this information is essentially metadata about the disk
 * that should be kept with the disk image itself.  (Assuming or course
 * that a disk image is the actual backingstore for this emulated device.)
 * This metadata should also be made available to PV drivers via a common
 * mechanism, probably the xenstore.  The fact that this metadata isn't
 * available outside of HVM domains means that it's difficult to move
 * disks between HVM and PV domains, since a fully PV domain will have no
 * way of knowing what the correct geometry of the target device is.
 * (Short of reading the disk, looking for things like partition tables
 * and labels, and taking a best guess at what the geometry was when
 * the disk was initialized.  Unsuprisingly, qemu actually does this.)
 *
 * This driver has to map xdf shell device instances into their corresponding
 * xdf device instances.  We have to do this to ensure that when a user
 * accesses a emulated xdf shell device we map those accesses to the proper
 * paravirtualized device.  Basically what we need to know is how multiple
 * 'disk' entries in a domU configuration file get mapped to emulated
 * xdf shell devices and to xdf devices.  The 'disk' entry to xdf instance
 * mappings we know because those are done within the Solaris xvdi code
 * and the xpvd nexus driver.  But the config to emulated devices mappings
 * are handled entirely within the xen management tool chain and the
 * hardware emulator.  Since all the tools that establish these mappings
 * live in dom0, dom0 should really supply us with this information,
 * probably via the xenstore.  Unfortunatly it doesn't so, since there's
 * no good way to determine this mapping dynamically, this driver uses
 * a hard coded set of static mappings.  These mappings are hardware
 * emulator specific because each different hardware emulator could have
 * a different device tree with different xdf shell device paths.  This
 * means that if we want to continue to use this static mapping approach
 * to allow Solaris to run on different hardware emulators we'll have
 * to analyze each of those emulators to determine what paths they
 * use and hard code those paths into this driver.  yech.  This metadata
 * really needs to be supplied to us by dom0.
 *
 * This driver access underlying xdf nodes.  Unfortunatly, devices
 * must create minor nodes during attach, and for disk devices to create
 * minor nodes, they have to look at the label on the disk, so this means
 * that disk drivers must be able to access a disk contents during
 * attach.  That means that this disk driver must be able to access
 * underlying xdf nodes during attach.  Unfortunatly, due to device tree
 * locking restrictions, we cannot have an attach operation occuring on
 * this device and then attempt to access another device which may
 * cause another attach to occur in a different device tree branch
 * since this could result in deadlock.  Hence, this driver can only
 * access xdf device nodes that we know are attached, and it can't use
 * any ddi interfaces to access those nodes if those interfaces could
 * trigger an attach of the xdf device.  So this driver works around
 * these restrictions by talking directly to xdf devices via
 * xdf_hvm_hold().  This interface takes a pathname to an xdf device,
 * and if that device is already attached then it returns the a held dip
 * pointer for that device node.  This prevents us from getting into
 * deadlock situations, but now we need a mechanism to ensure that all
 * the xdf device nodes this driver might access are attached before
 * this driver tries to access them.  This is accomplished via the
 * hvmboot_rootconf() callback which is invoked just before root is
 * mounted.  hvmboot_rootconf() will attach xpvd and tell it to configure
 * all xdf device visible to the system.  All these xdf device nodes
 * will also be marked with the "ddi-no-autodetach" property so that
 * once they are configured, the will not be automatically unconfigured.
 * The only way that they could be unconfigured is if the administrator
 * explicitly attempts to unload required modules via rem_drv(1M)
 * or modunload(1M).
 */

/*
 * 16 paritions + fdisk (see xdf.h)
 */
#define	XDFS_DEV2UNIT(dev)	XDF_INST((getminor((dev))))
#define	XDFS_DEV2PART(dev)	XDF_PART((getminor((dev))))

#define	OTYP_VALID(otyp)	((otyp == OTYP_BLK) ||			\
					(otyp == OTYP_CHR) ||		\
					(otyp == OTYP_LYR))

#define	XDFS_NODES		4

#define	XDFS_HVM_MODE(sp)	(XDFS_HVM_STATE(sp)->xdfs_hs_mode)
#define	XDFS_HVM_DIP(sp)	(XDFS_HVM_STATE(sp)->xdfs_hs_dip)
#define	XDFS_HVM_PATH(sp)	(XDFS_HVM_STATE(sp)->xdfs_hs_path)
#define	XDFS_HVM_STATE(sp)						\
		((xdfs_hvm_state_t *)(&((char *)(sp))[XDFS_HVM_STATE_OFFSET]))
#define	XDFS_HVM_STATE_OFFSET	(xdfs_ss_size - sizeof (xdfs_hvm_state_t))
#define	XDFS_HVM_SANE(sp)						\
		ASSERT(XDFS_HVM_MODE(sp));				\
		ASSERT(XDFS_HVM_DIP(sp) != NULL);			\
		ASSERT(XDFS_HVM_PATH(sp) != NULL);


typedef struct xdfs_hvm_state {
	boolean_t	xdfs_hs_mode;
	dev_info_t	*xdfs_hs_dip;
	char		*xdfs_hs_path;
} xdfs_hvm_state_t;

/* local function and structure prototypes */
static int xdfs_iodone(struct buf *);
static boolean_t xdfs_isopen_part(xdfs_state_t *, int);
static boolean_t xdfs_isopen(xdfs_state_t *);
static cmlb_tg_ops_t xdfs_lb_ops;

/*
 * Globals
 */
major_t			xdfs_major;
#define			xdfs_hvm_dev_ops (xdfs_c_hvm_dev_ops)
#define			xdfs_hvm_cb_ops (xdfs_hvm_dev_ops->devo_cb_ops)

/*
 * Private globals
 */
volatile boolean_t	xdfs_pv_disable = B_FALSE;
static void		*xdfs_ssp;
static size_t		xdfs_ss_size;

/*
 * Private helper functions
 */
static boolean_t
xdfs_tgt_hold(xdfs_state_t *xsp)
{
	mutex_enter(&xsp->xdfss_mutex);
	ASSERT(xsp->xdfss_tgt_holds >= 0);
	if (!xsp->xdfss_tgt_attached) {
		mutex_exit(&xsp->xdfss_mutex);
		return (B_FALSE);
	}
	xsp->xdfss_tgt_holds++;
	mutex_exit(&xsp->xdfss_mutex);
	return (B_TRUE);
}

static void
xdfs_tgt_release(xdfs_state_t *xsp)
{
	mutex_enter(&xsp->xdfss_mutex);
	ASSERT(xsp->xdfss_tgt_attached);
	ASSERT(xsp->xdfss_tgt_holds > 0);
	if (--xsp->xdfss_tgt_holds == 0)
		cv_broadcast(&xsp->xdfss_cv);
	mutex_exit(&xsp->xdfss_mutex);
}

/*ARGSUSED*/
static int
xdfs_lb_getinfo(dev_info_t *dip, int cmd, void *arg, void *tg_cookie)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv;

	if (xsp == NULL)
		return (ENXIO);

	if (!xdfs_tgt_hold(xsp))
		return (ENXIO);

	if (cmd == TG_GETVIRTGEOM) {
		cmlb_geom_t	pgeom, *vgeomp;
		diskaddr_t	capacity;

		/*
		 * The native xdf driver doesn't support this ioctl.
		 * Intead of passing it on, emulate it here so that the
		 * results look the same as what we get for a real xdf
		 * shell device.
		 *
		 * Get the real size of the device
		 */
		if ((rv = xdf_lb_getinfo(xsp->xdfss_tgt_dip,
		    TG_GETPHYGEOM, &pgeom, tg_cookie)) != 0)
			goto out;
		capacity = pgeom.g_capacity;

		/*
		 * If the controller returned us something that doesn't
		 * really fit into an Int 13/function 8 geometry
		 * result, just fail the ioctl.  See PSARC 1998/313.
		 */
		if (capacity >= (63 * 254 * 1024)) {
			rv = EINVAL;
			goto out;
		}

		vgeomp = (cmlb_geom_t *)arg;
		vgeomp->g_capacity	= capacity;
		vgeomp->g_nsect		= 63;
		vgeomp->g_nhead		= 254;
		vgeomp->g_ncyl		= capacity / (63 * 254);
		vgeomp->g_acyl		= 0;
		vgeomp->g_secsize	= 512;
		vgeomp->g_intrlv	= 1;
		vgeomp->g_rpm		= 3600;
		rv = 0;
		goto out;
	}

	rv = xdf_lb_getinfo(xsp->xdfss_tgt_dip, cmd, arg, tg_cookie);

out:
	xdfs_tgt_release(xsp);
	return (rv);
}

static boolean_t
xdfs_isopen_part(xdfs_state_t *xsp, int part)
{
	int otyp;

	ASSERT(MUTEX_HELD(&xsp->xdfss_mutex));
	for (otyp = 0; (otyp < OTYPCNT); otyp++) {
		if (xsp->xdfss_otyp_count[otyp][part] != 0) {
			ASSERT(xsp->xdfss_tgt_attached);
			ASSERT(xsp->xdfss_tgt_holds >= 0);
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

static boolean_t
xdfs_isopen(xdfs_state_t *xsp)
{
	int part;

	ASSERT(MUTEX_HELD(&xsp->xdfss_mutex));
	for (part = 0; part < XDF_PEXT; part++) {
		if (xdfs_isopen_part(xsp, part))
			return (B_TRUE);
	}
	return (B_FALSE);
}

static int
xdfs_iodone(struct buf *bp)
{
	struct buf	*bp_orig = bp->b_chain;

	/* Propegate back the io results */
	bp_orig->b_resid = bp->b_resid;
	bioerror(bp_orig, geterror(bp));
	biodone(bp_orig);

	freerbuf(bp);
	return (0);
}

static int
xdfs_cmlb_attach(xdfs_state_t *xsp)
{
	return (cmlb_attach(xsp->xdfss_dip, &xdfs_lb_ops,
	    xsp->xdfss_tgt_is_cd ? DTYPE_RODIRECT : DTYPE_DIRECT,
	    xdf_is_rm(xsp->xdfss_tgt_dip),
	    B_TRUE,
	    xdfs_c_cmlb_node_type(xsp),
	    xdfs_c_cmlb_alter_behavior(xsp),
	    xsp->xdfss_cmlbhandle, 0));
}

static boolean_t
xdfs_tgt_probe(xdfs_state_t *xsp, dev_info_t *tgt_dip)
{
	cmlb_geom_t		pgeom;
	int			tgt_instance = ddi_get_instance(tgt_dip);

	ASSERT(MUTEX_HELD(&xsp->xdfss_mutex));
	ASSERT(!xdfs_isopen(xsp));
	ASSERT(!xsp->xdfss_tgt_attached);

	xsp->xdfss_tgt_dip = tgt_dip;
	xsp->xdfss_tgt_holds = 0;
	xsp->xdfss_tgt_dev = makedevice(ddi_driver_major(tgt_dip),
	    XDF_MINOR(tgt_instance, 0));
	ASSERT((xsp->xdfss_tgt_dev & XDF_PMASK) == 0);
	xsp->xdfss_tgt_is_cd = xdf_is_cd(tgt_dip);

	/*
	 * GROSS HACK ALERT!  GROSS HACK ALERT!
	 *
	 * Before we can initialize the cmlb layer, we have to tell the
	 * underlying xdf device what it's physical geometry should be.
	 * See the block comments at the top of this file for more info.
	 */
	if (!xsp->xdfss_tgt_is_cd &&
	    ((xdfs_c_getpgeom(xsp->xdfss_dip, &pgeom) != 0) ||
	    (xdf_hvm_setpgeom(xsp->xdfss_tgt_dip, &pgeom) != 0)))
		return (B_FALSE);

	/*
	 * Force the xdf front end driver to connect to the backend.  From
	 * the solaris device tree perspective, the xdf driver devinfo node
	 * is already in the ATTACHED state.  (Otherwise xdf_hvm_hold()
	 * would not have returned a dip.)  But this doesn't mean that the
	 * xdf device has actually established a connection to it's back
	 * end driver.  For us to be able to access the xdf device it needs
	 * to be connected.
	 */
	if (!xdf_hvm_connect(xsp->xdfss_tgt_dip)) {
		cmn_err(CE_WARN, "pv driver failed to connect: %s",
		    xsp->xdfss_pv);
		return (B_FALSE);
	}

	if (xsp->xdfss_tgt_is_cd && !xdf_media_req_supported(tgt_dip)) {
		/*
		 * Unfortunatly, the dom0 backend driver doesn't support
		 * important media request operations like eject, so fail
		 * the probe (this should cause us to fall back to emulated
		 * hvm device access, which does support things like eject).
		 */
		return (B_FALSE);
	}

	/* create kstat for iostat(1M) */
	if (xdf_kstat_create(xsp->xdfss_tgt_dip, (char *)xdfs_c_name,
	    tgt_instance) != 0)
		return (B_FALSE);

	/*
	 * Now we need to mark ourselves as attached and drop xdfss_mutex.
	 * We do this because the final steps in the attach process will
	 * need to access the underlying disk to read the label and
	 * possibly the devid.
	 */
	xsp->xdfss_tgt_attached = B_TRUE;
	mutex_exit(&xsp->xdfss_mutex);

	if (!xsp->xdfss_tgt_is_cd && xdfs_c_bb_check(xsp)) {
		cmn_err(CE_WARN, "pv disks with bad blocks are unsupported: %s",
		    xsp->xdfss_hvm);
		mutex_enter(&xsp->xdfss_mutex);
		xdf_kstat_delete(xsp->xdfss_tgt_dip);
		xsp->xdfss_tgt_attached = B_FALSE;
		return (B_FALSE);
	}

	/*
	 * Initalize cmlb.  Note that for partition information cmlb
	 * will access the underly xdf disk device directly via
	 * xdfs_lb_rdwr() and xdfs_lb_getinfo().  There are no
	 * layered driver handles associated with this access because
	 * it is a direct disk access that doesn't go through
	 * any of the device nodes exported by the xdf device (since
	 * all exported device nodes only reflect the portion of
	 * the device visible via the partition/slice that the node
	 * is associated with.)  So while not observable via the LDI,
	 * this direct disk access is ok since we're actually holding
	 * the target device.
	 */
	if (xdfs_cmlb_attach(xsp) != 0) {
		mutex_enter(&xsp->xdfss_mutex);
		xdf_kstat_delete(xsp->xdfss_tgt_dip);
		xsp->xdfss_tgt_attached = B_FALSE;
		return (B_FALSE);
	}

	/* setup devid string */
	xsp->xdfss_tgt_devid = NULL;
	if (!xsp->xdfss_tgt_is_cd)
		xdfs_c_devid_setup(xsp);

	(void) cmlb_validate(xsp->xdfss_cmlbhandle, 0, 0);

	/* Have the system report any newly created device nodes */
	ddi_report_dev(xsp->xdfss_dip);

	mutex_enter(&xsp->xdfss_mutex);
	return (B_TRUE);
}

static boolean_t
xdfs_tgt_detach(xdfs_state_t *xsp)
{
	ASSERT(MUTEX_HELD(&xsp->xdfss_mutex));
	ASSERT(xsp->xdfss_tgt_attached);
	ASSERT(xsp->xdfss_tgt_holds >= 0);

	if ((xdfs_isopen(xsp)) || (xsp->xdfss_tgt_holds != 0))
		return (B_FALSE);

	ddi_devid_unregister(xsp->xdfss_dip);
	if (xsp->xdfss_tgt_devid != NULL)
		ddi_devid_free(xsp->xdfss_tgt_devid);

	xdf_kstat_delete(xsp->xdfss_tgt_dip);
	xsp->xdfss_tgt_attached = B_FALSE;
	return (B_TRUE);
}

/*
 * Xdf_shell interfaces that may be called from outside this file.
 */
void
xdfs_minphys(struct buf *bp)
{
	xdfmin(bp);
}

/*
 * Cmlb ops vector, allows the cmlb module to directly access the entire
 * xdf disk device without going through any partitioning layers.
 */
int
xdfs_lb_rdwr(dev_info_t *dip, uchar_t cmd, void *bufaddr,
    diskaddr_t start, size_t count, void *tg_cookie)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv;

	if (xsp == NULL)
		return (ENXIO);

	if (!xdfs_tgt_hold(xsp))
		return (ENXIO);

	rv = xdf_lb_rdwr(xsp->xdfss_tgt_dip,
	    cmd, bufaddr, start, count, tg_cookie);

	xdfs_tgt_release(xsp);
	return (rv);
}

/*
 * Driver PV and HVM cb_ops entry points
 */
/*ARGSUSED*/
static int
xdfs_open(dev_t *dev_p, int flag, int otyp, cred_t *credp)
{
	ldi_ident_t	li;
	dev_t		dev = *dev_p;
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	dev_t		tgt_devt = xsp->xdfss_tgt_dev | part;
	int		err = 0;

	if ((otyp < 0) || (otyp >= OTYPCNT))
		return (EINVAL);

	if (XDFS_HVM_MODE(xsp)) {
		if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
			return (ENOTSUP);
		return (xdfs_hvm_cb_ops->cb_open(dev_p, flag, otyp, credp));
	}

	/* allocate an ldi handle */
	VERIFY(ldi_ident_from_dev(*dev_p, &li) == 0);

	mutex_enter(&xsp->xdfss_mutex);

	/*
	 * We translate all device opens (chr, blk, and lyr) into
	 * block device opens.  Why?  Because for all the opens that
	 * come through this driver, we only keep around one LDI handle.
	 * So that handle can only be of one open type.  The reason
	 * that we choose the block interface for this is that to use
	 * the block interfaces for a device the system needs to allocate
	 * buf_ts, which are associated with system memory which can act
	 * as a cache for device data.  So normally when a block device
	 * is closed the system will ensure that all these pages get
	 * flushed out of memory.  But if we were to open the device
	 * as a character device, then when we went to close the underlying
	 * device (even if we had invoked the block interfaces) any data
	 * remaining in memory wouldn't necessairly be flushed out
	 * before the device was closed.
	 */
	if (xsp->xdfss_tgt_lh[part] == NULL) {
		ASSERT(!xdfs_isopen_part(xsp, part));

		err = ldi_open_by_dev(&tgt_devt, OTYP_BLK, flag, credp,
		    &xsp->xdfss_tgt_lh[part], li);

		if (err != 0) {
			mutex_exit(&xsp->xdfss_mutex);
			ldi_ident_release(li);
			return (err);
		}

		/* Disk devices really shouldn't clone */
		ASSERT(tgt_devt == (xsp->xdfss_tgt_dev | part));
	} else {
		ldi_handle_t lh_tmp;

		ASSERT(xdfs_isopen_part(xsp, part));

		/* do ldi open/close to get flags and cred check */
		err = ldi_open_by_dev(&tgt_devt, OTYP_BLK, flag, credp,
		    &lh_tmp, li);
		if (err != 0) {
			mutex_exit(&xsp->xdfss_mutex);
			ldi_ident_release(li);
			return (err);
		}

		/* Disk devices really shouldn't clone */
		ASSERT(tgt_devt == (xsp->xdfss_tgt_dev | part));
		(void) ldi_close(lh_tmp, flag, credp);
	}
	ldi_ident_release(li);

	xsp->xdfss_otyp_count[otyp][part]++;

	mutex_exit(&xsp->xdfss_mutex);
	return (0);
}

/*ARGSUSED*/
static int
xdfs_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		err = 0;

	ASSERT((otyp >= 0) && otyp < OTYPCNT);

	/* Sanity check the dev_t associated with this request. */
	ASSERT(getmajor(dev) == xdfs_major);
	if (getmajor(dev) != xdfs_major)
		return (ENXIO);

	if (XDFS_HVM_MODE(xsp)) {
		if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
			return (ENOTSUP);
		return (xdfs_hvm_cb_ops->cb_close(dev, flag, otyp, credp));
	}

	/*
	 * Sanity check that that the device is actually open.  On debug
	 * kernels we'll panic and on non-debug kernels we'll return failure.
	 */
	mutex_enter(&xsp->xdfss_mutex);
	ASSERT(xdfs_isopen_part(xsp, part));
	if (!xdfs_isopen_part(xsp, part)) {
		mutex_exit(&xsp->xdfss_mutex);
		return (ENXIO);
	}

	ASSERT(xsp->xdfss_tgt_lh[part] != NULL);
	ASSERT(xsp->xdfss_otyp_count[otyp][part] > 0);
	if (otyp == OTYP_LYR) {
		xsp->xdfss_otyp_count[otyp][part]--;
	} else {
		xsp->xdfss_otyp_count[otyp][part] = 0;
	}

	if (!xdfs_isopen_part(xsp, part)) {
		err = ldi_close(xsp->xdfss_tgt_lh[part], flag, credp);
		xsp->xdfss_tgt_lh[part] = NULL;
	}

	mutex_exit(&xsp->xdfss_mutex);

	return (err);
}

int
xdfs_strategy(struct buf *bp)
{
	dev_t		dev = bp->b_edev;
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	dev_t		tgt_devt;
	struct buf	*bp_clone;

	/* Sanity check the dev_t associated with this request. */
	ASSERT(getmajor(dev) == xdfs_major);
	if (getmajor(dev) != xdfs_major)
		goto err;

	if (XDFS_HVM_MODE(xsp)) {
		if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
			return (ENOTSUP);
		return (xdfs_hvm_cb_ops->cb_strategy(bp));
	}

	/*
	 * Sanity checks that the dev_t associated with the buf we were
	 * passed corresponds to an open partition.  On debug kernels we'll
	 * panic and on non-debug kernels we'll return failure.
	 */
	mutex_enter(&xsp->xdfss_mutex);
	ASSERT(xdfs_isopen_part(xsp, part));
	if (!xdfs_isopen_part(xsp, part)) {
		mutex_exit(&xsp->xdfss_mutex);
		goto err;
	}
	mutex_exit(&xsp->xdfss_mutex);

	/* clone this buffer */
	tgt_devt = xsp->xdfss_tgt_dev | part;
	bp_clone = bioclone(bp, 0, bp->b_bcount, tgt_devt, bp->b_blkno,
	    xdfs_iodone, NULL, KM_SLEEP);
	bp_clone->b_chain = bp;

	/*
	 * If we're being invoked on behalf of the physio() call in
	 * xdfs_dioctl_rwcmd() then b_private will be set to
	 * XB_SLICE_NONE and we need to propegate this flag into the
	 * cloned buffer so that the xdf driver will see it.
	 */
	if (bp->b_private == (void *)XB_SLICE_NONE)
		bp_clone->b_private = (void *)XB_SLICE_NONE;

	/*
	 * Pass on the cloned buffer.  Note that we don't bother to check
	 * for failure because the xdf strategy routine will have to
	 * invoke biodone() if it wants to return an error, which means
	 * that the xdfs_iodone() callback will get invoked and it
	 * will propegate the error back up the stack and free the cloned
	 * buffer.
	 */
	ASSERT(xsp->xdfss_tgt_lh[part] != NULL);
	return (ldi_strategy(xsp->xdfss_tgt_lh[part], bp_clone));

err:
	bioerror(bp, ENXIO);
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return (0);
}

static int
xdfs_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (!XDFS_HVM_MODE(xsp))
		return (ldi_dump(xsp->xdfss_tgt_lh[part], addr, blkno, nblk));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
		return (ENOTSUP);
	return (xdfs_hvm_cb_ops->cb_dump(dev, addr, blkno, nblk));
}

/*ARGSUSED*/
static int
xdfs_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (!XDFS_HVM_MODE(xsp))
		return (ldi_read(xsp->xdfss_tgt_lh[part], uio, credp));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
		return (ENOTSUP);
	return (xdfs_hvm_cb_ops->cb_read(dev, uio, credp));
}

/*ARGSUSED*/
static int
xdfs_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (!XDFS_HVM_MODE(xsp))
		return (ldi_write(xsp->xdfss_tgt_lh[part], uio, credp));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
		return (ENOTSUP);
	return (xdfs_hvm_cb_ops->cb_write(dev, uio, credp));
}

/*ARGSUSED*/
static int
xdfs_aread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (!XDFS_HVM_MODE(xsp))
		return (ldi_aread(xsp->xdfss_tgt_lh[part], aio, credp));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL) ||
	    (xdfs_hvm_cb_ops->cb_strategy == NULL) ||
	    (xdfs_hvm_cb_ops->cb_strategy == nodev) ||
	    (xdfs_hvm_cb_ops->cb_aread == NULL))
		return (ENOTSUP);
	return (xdfs_hvm_cb_ops->cb_aread(dev, aio, credp));
}

/*ARGSUSED*/
static int
xdfs_awrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (!XDFS_HVM_MODE(xsp))
		return (ldi_awrite(xsp->xdfss_tgt_lh[part], aio, credp));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL) ||
	    (xdfs_hvm_cb_ops->cb_strategy == NULL) ||
	    (xdfs_hvm_cb_ops->cb_strategy == nodev) ||
	    (xdfs_hvm_cb_ops->cb_awrite == NULL))
		return (ENOTSUP);
	return (xdfs_hvm_cb_ops->cb_awrite(dev, aio, credp));
}

static int
xdfs_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp,
    int *rvalp)
{
	int		instance = XDFS_DEV2UNIT(dev);
	int		part = XDFS_DEV2PART(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv;
	boolean_t	done;

	if (XDFS_HVM_MODE(xsp)) {
		if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL))
			return (ENOTSUP);
		return (xdfs_hvm_cb_ops->cb_ioctl(
		    dev, cmd, arg, flag, credp, rvalp));
	}

	rv = xdfs_c_ioctl(xsp, dev, part, cmd, arg, flag, credp, rvalp, &done);
	if (done)
		return (rv);
	return (ldi_ioctl(xsp->xdfss_tgt_lh[part],
	    cmd, arg, flag, credp, rvalp));
}

static int
xdfs_hvm_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	void		*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	ASSERT(XDFS_HVM_MODE(xsp));

	if ((xdfs_hvm_dev_ops == NULL) || (xdfs_hvm_cb_ops == NULL) ||
	    (xdfs_hvm_cb_ops->cb_prop_op == NULL) ||
	    (xdfs_hvm_cb_ops->cb_prop_op == nodev) ||
	    (xdfs_hvm_cb_ops->cb_prop_op == nulldev))
		return (DDI_PROP_NOT_FOUND);

	return (xdfs_hvm_cb_ops->cb_prop_op(dev, dip, prop_op,
	    flags, name, valuep, lengthp));
}

static int
xdfs_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv;
	dev_info_t	*tgt_dip;
	dev_t		tgt_devt;

	/*
	 * Sanity check that if a dev_t or dip were specified that they
	 * correspond to this device driver.  On debug kernels we'll
	 * panic and on non-debug kernels we'll return failure.
	 */
	ASSERT(ddi_driver_major(dip) == xdfs_major);
	ASSERT((dev == DDI_DEV_T_ANY) || (getmajor(dev) == xdfs_major));
	if ((ddi_driver_major(dip) != xdfs_major) ||
	    ((dev != DDI_DEV_T_ANY) && (getmajor(dev) != xdfs_major)))
		return (DDI_PROP_NOT_FOUND);

	/*
	 * This property lookup might be associated with a device node
	 * that is not yet attached, if so pass it onto ddi_prop_op().
	 */
	if (xsp == NULL)
		return (ddi_prop_op(dev, dip, prop_op, flags,
		    name, valuep, lengthp));

	/* If we're accessing the device in hvm mode, pass this request on */
	if (XDFS_HVM_MODE(xsp))
		return (xdfs_hvm_prop_op(dev, dip, prop_op,
		    flags, name, valuep, lengthp));

	/*
	 * Make sure we only lookup static properties.
	 *
	 * If there are static properties of the underlying xdf driver
	 * that we want to mirror, then we'll have to explicity look them
	 * up and define them during attach.  There are a few reasons
	 * for this.  Most importantly, most static properties are typed
	 * and all dynamic properties are untyped, ie, for dynamic
	 * properties the caller must know the type of the property and
	 * how to interpret the value of the property.  the prop_op drivedr
	 * entry point is only designed for returning dynamic/untyped
	 * properties, so if we were to attempt to lookup and pass back
	 * static properties of the underlying device here then we would
	 * be losing the type information for those properties.  Another
	 * reason we don't want to pass on static property requests is that
	 * static properties are enumerable in the device tree, where as
	 * dynamic ones are not.
	 */
	flags |= DDI_PROP_DYNAMIC;

	/*
	 * We can't use the ldi here to access the underlying device because
	 * the ldi actually opens the device, and that open might fail if the
	 * device has already been opened with the FEXCL flag.  If we used
	 * the ldi here, it would also be possible for some other caller to
	 * try open the device with the FEXCL flag and get a failure back
	 * because we have it open to do a property query.  Instad we'll
	 * grab a hold on the target dip.
	 */
	if (!xdfs_tgt_hold(xsp))
		return (DDI_PROP_NOT_FOUND);

	/* figure out dip the dev_t we're going to pass on down */
	tgt_dip = xsp->xdfss_tgt_dip;
	if (dev == DDI_DEV_T_ANY) {
		tgt_devt = DDI_DEV_T_ANY;
	} else {
		tgt_devt = xsp->xdfss_tgt_dev | XDFS_DEV2PART(dev);
	}

	/*
	 * Cdev_prop_op() is not a public interface, and normally the caller
	 * is required to make sure that the target driver actually implements
	 * this interface before trying to invoke it.  In this case we know
	 * that we're always accessing the xdf driver and it does have this
	 * interface defined, so we can skip the check.
	 */
	rv = cdev_prop_op(tgt_devt, tgt_dip,
	    prop_op, flags, name, valuep, lengthp);

	xdfs_tgt_release(xsp);
	return (rv);
}

/*
 * Driver PV and HVM dev_ops entry points
 */
/*ARGSUSED*/
static int
xdfs_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t		dev = (dev_t)arg;
	int		instance = XDFS_DEV2UNIT(dev);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			if (xsp == NULL)
				return (DDI_FAILURE);
			if (XDFS_HVM_MODE(xsp))
				*result = XDFS_HVM_DIP(xsp);
			else
				*result = (void *)xsp->xdfss_dip;
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(intptr_t)instance;
			break;
		default:
			return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
xdfs_hvm_probe(dev_info_t *dip, char *path)
{
	int		instance = ddi_get_instance(dip);
	int		rv = DDI_PROBE_SUCCESS;
	void		*xsp;

	ASSERT(path != NULL);
	cmn_err(CE_WARN, "PV access to device disabled: %s", path);

	(void) ddi_soft_state_zalloc(xdfs_ssp, instance);
	VERIFY((xsp = ddi_get_soft_state(xdfs_ssp, instance)) != NULL);

	if ((xdfs_hvm_dev_ops == NULL) ||
	    (xdfs_hvm_dev_ops->devo_probe == NULL) ||
	    ((rv = xdfs_hvm_dev_ops->devo_probe(dip)) == DDI_PROBE_FAILURE)) {
		ddi_soft_state_free(xdfs_ssp, instance);
		cmn_err(CE_WARN, "HVM probe of device failed: %s", path);
		kmem_free(path, MAXPATHLEN);
		return (DDI_PROBE_FAILURE);
	}

	XDFS_HVM_MODE(xsp) = B_TRUE;
	XDFS_HVM_DIP(xsp) = dip;
	XDFS_HVM_PATH(xsp) = path;

	return (rv);
}

static int
xdfs_probe(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp;
	dev_info_t	*tgt_dip;
	char		*path;
	int		i, pv_disable;

	/* if we've already probed the device then there's nothing todo */
	if (ddi_get_soft_state(xdfs_ssp, instance))
		return (DDI_PROBE_PARTIAL);

	/* Figure out our pathname */
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);

	/* see if we should disable pv access mode */
	pv_disable = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_NOTPROM, "pv_disable", 0);

	if (xdfs_pv_disable || pv_disable)
		return (xdfs_hvm_probe(dip, path));

	/*
	 * This xdf shell device layers on top of an xdf device.  So the first
	 * thing we need to do is determine which xdf device instance this
	 * xdf shell instance should be layered on top of.
	 */
	for (i = 0; xdfs_c_h2p_map[i].xdfs_h2p_hvm != NULL; i++) {
		if (strcmp(xdfs_c_h2p_map[i].xdfs_h2p_hvm, path) == 0)
			break;
	}

	if ((xdfs_c_h2p_map[i].xdfs_h2p_hvm == NULL) ||
	    ((tgt_dip = xdf_hvm_hold(xdfs_c_h2p_map[i].xdfs_h2p_pv)) == NULL)) {
		/*
		 * UhOh.  We either don't know what xdf instance this xdf
		 * shell device should be mapped to or the xdf node assocaited
		 * with this instance isnt' attached.  in either case fall
		 * back to hvm access.
		 */
		return (xdfs_hvm_probe(dip, path));
	}

	/* allocate and initialize our state structure */
	(void) ddi_soft_state_zalloc(xdfs_ssp, instance);
	xsp = ddi_get_soft_state(xdfs_ssp, instance);
	mutex_init(&xsp->xdfss_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&xsp->xdfss_cv, NULL, CV_DEFAULT, NULL);
	mutex_enter(&xsp->xdfss_mutex);

	xsp->xdfss_dip = dip;
	xsp->xdfss_pv = xdfs_c_h2p_map[i].xdfs_h2p_pv;
	xsp->xdfss_hvm = xdfs_c_h2p_map[i].xdfs_h2p_hvm;
	xsp->xdfss_tgt_attached = B_FALSE;
	cmlb_alloc_handle((cmlb_handle_t *)&xsp->xdfss_cmlbhandle);

	if (!xdfs_tgt_probe(xsp, tgt_dip)) {
		mutex_exit(&xsp->xdfss_mutex);
		cmlb_free_handle(&xsp->xdfss_cmlbhandle);
		ddi_soft_state_free(xdfs_ssp, instance);
		ddi_release_devi(tgt_dip);
		return (xdfs_hvm_probe(dip, path));
	}
	mutex_exit(&xsp->xdfss_mutex);

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers).
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);

	return (DDI_PROBE_SUCCESS);
}

static int
xdfs_hvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	void		*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv = DDI_FAILURE;

	XDFS_HVM_SANE(xsp);

	if ((xdfs_hvm_dev_ops == NULL) ||
	    (xdfs_hvm_dev_ops->devo_attach == NULL) ||
	    ((rv = xdfs_hvm_dev_ops->devo_attach(dip, cmd)) != DDI_SUCCESS)) {
		cmn_err(CE_WARN, "HVM attach of device failed: %s",
		    XDFS_HVM_PATH(xsp));
		kmem_free(XDFS_HVM_PATH(xsp), MAXPATHLEN);
		ddi_soft_state_free(xdfs_ssp, instance);
		return (rv);
	}

	return (DDI_SUCCESS);
}

/*
 * Autoconfiguration Routines
 */
static int
xdfs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (xsp == NULL)
		return (DDI_FAILURE);
	if (XDFS_HVM_MODE(xsp))
		return (xdfs_hvm_attach(dip, cmd));
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	xdfs_c_attach(xsp);
	return (DDI_SUCCESS);
}

static int
xdfs_hvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	void		*xsp = ddi_get_soft_state(xdfs_ssp, instance);
	int		rv;

	XDFS_HVM_SANE(xsp);

	if ((xdfs_hvm_dev_ops == NULL) ||
	    (xdfs_hvm_dev_ops->devo_detach == NULL))
		return (DDI_FAILURE);

	if ((rv = xdfs_hvm_dev_ops->devo_detach(dip, cmd)) != DDI_SUCCESS)
		return (rv);

	kmem_free(XDFS_HVM_PATH(xsp), MAXPATHLEN);
	ddi_soft_state_free(xdfs_ssp, instance);
	return (DDI_SUCCESS);
}

static int
xdfs_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (XDFS_HVM_MODE(xsp))
		return (xdfs_hvm_detach(dip, cmd));
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&xsp->xdfss_mutex);
	if (!xdfs_tgt_detach(xsp)) {
		mutex_exit(&xsp->xdfss_mutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&xsp->xdfss_mutex);

	cmlb_detach(xsp->xdfss_cmlbhandle, 0);
	cmlb_free_handle(&xsp->xdfss_cmlbhandle);
	ddi_release_devi(xsp->xdfss_tgt_dip);
	ddi_soft_state_free(xdfs_ssp, instance);
	ddi_prop_remove_all(dip);
	return (DDI_SUCCESS);
}

static int
xdfs_hvm_power(dev_info_t *dip, int component, int level)
{
	int		instance = ddi_get_instance(dip);
	void		*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	XDFS_HVM_SANE(xsp);

	if ((xdfs_hvm_dev_ops == NULL) ||
	    (xdfs_hvm_dev_ops->devo_power == NULL))
		return (DDI_FAILURE);
	return (xdfs_hvm_dev_ops->devo_power(dip, component, level));
}

static int
xdfs_power(dev_info_t *dip, int component, int level)
{
	int		instance = ddi_get_instance(dip);
	xdfs_state_t	*xsp = ddi_get_soft_state(xdfs_ssp, instance);

	if (XDFS_HVM_MODE(xsp))
		return (xdfs_hvm_power(dip, component, level));
	return (nodev());
}

/*
 * Cmlb ops vector
 */
static cmlb_tg_ops_t xdfs_lb_ops = {
	TG_DK_OPS_VERSION_1,
	xdfs_lb_rdwr,
	xdfs_lb_getinfo
};

/*
 * Device driver ops vector
 */
static struct cb_ops xdfs_cb_ops = {
	xdfs_open,		/* open */
	xdfs_close,		/* close */
	xdfs_strategy,		/* strategy */
	nodev,			/* print */
	xdfs_dump,		/* dump */
	xdfs_read,		/* read */
	xdfs_write,		/* write */
	xdfs_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	xdfs_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_64BIT | D_MP | D_NEW,	/* Driver comaptibility flag */
	CB_REV,			/* cb_rev */
	xdfs_aread,		/* async read */
	xdfs_awrite		/* async write */
};

struct dev_ops xdfs_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	xdfs_getinfo,		/* info */
	nulldev,		/* identify */
	xdfs_probe,		/* probe */
	xdfs_attach,		/* attach */
	xdfs_detach,		/* detach */
	nodev,			/* reset */
	&xdfs_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	xdfs_power,		/* power */
	ddi_quiesce_not_supported, /* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver. */
	NULL,			/* Module description.  Set by _init() */
	&xdfs_ops,		/* Driver ops. */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int rval;

	xdfs_major = ddi_name_to_major((char *)xdfs_c_name);
	if (xdfs_major == (major_t)-1)
		return (EINVAL);

	/*
	 * Determine the size of our soft state structure.  The base
	 * size of the structure is the larger of the hvm clients state
	 * structure, or our shell state structure.  Then we'll align
	 * the end of the structure to a pointer boundry and append
	 * a xdfs_hvm_state_t structure.  This way the xdfs_hvm_state_t
	 * structure is always present and we can use it to determine the
	 * current device access mode (hvm or shell).
	 */
	xdfs_ss_size = MAX(xdfs_c_hvm_ss_size, sizeof (xdfs_state_t));
	xdfs_ss_size = P2ROUNDUP(xdfs_ss_size, sizeof (uintptr_t));
	xdfs_ss_size += sizeof (xdfs_hvm_state_t);

	/*
	 * In general ide usually supports 4 disk devices, this same
	 * limitation also applies to software emulating ide devices.
	 * so by default we pre-allocate 4 xdf shell soft state structures.
	 */
	if ((rval = ddi_soft_state_init(&xdfs_ssp,
	    xdfs_ss_size, XDFS_NODES)) != 0)
		return (rval);
	*xdfs_c_hvm_ss = xdfs_ssp;

	/* Install our module */
	if (modldrv.drv_linkinfo == NULL)
		modldrv.drv_linkinfo = (char *)xdfs_c_linkinfo;
	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&xdfs_ssp);
		return (rval);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	if (modldrv.drv_linkinfo == NULL)
		modldrv.drv_linkinfo = (char *)xdfs_c_linkinfo;
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	rval;
	if ((rval = mod_remove(&modlinkage)) != 0)
		return (rval);
	ddi_soft_state_fini(&xdfs_ssp);
	return (0);
}
