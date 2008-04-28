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

#include <sys/scsi/scsi_types.h>
#include <sys/modctl.h>
#include <sys/cmlb.h>
#include <sys/types.h>
#include <sys/xpv_support.h>
#include <sys/xendev.h>
#include <sys/gnttab.h>
#include <public/xen.h>
#include <public/grant_table.h>
#include <io/xdf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/dktp/dadev.h>
#include <sys/dktp/dadkio.h>
#include <sys/dktp/tgdk.h>
#include <sys/dktp/bbh.h>
#include <sys/dktp/cmdk.h>
#include <sys/dktp/altsctr.h>

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
 * mechamisn, probably the xenstore.  The fact that this metadata isn't
 * available outside of HVM domains means that it's difficult to move
 * disks between HVM and PV domains, since a fully PV domain will have no
 * way of knowing what the correct geometry of the target device is.
 * (Short of reading the disk, looking for things like partition tables
 * and labels, and taking a best guess at what the geometry was when
 * the disk was initialized.  Unsuprisingly, qemu actually does this.)
 *
 * This driver has to map cmdk device instances into their corresponding
 * xdf device instances.  We have to do this to ensure that when a user
 * accesses a emulated cmdk device we map those accesses to the proper
 * paravirtualized device.  Basically what we need to know is how multiple
 * 'disk' entries in a domU configuration file get mapped to emulated
 * cmdk devices and to xdf devices.  The 'disk' entry to xdf instance
 * mappings we know because those are done within the Solaris xvdi code
 * and the xpvd nexus driver.  But the config to emulated devices mappings
 * are handled entirely within the xen management tool chain and the
 * hardware emulator.  Since all the tools that establish these mappings
 * live in dom0, dom0 should really supply us with this information,
 * probably via the xenstore.  Unfortunatly it doesn't so, since there's
 * no good way to determine this mapping dynamically, this driver uses
 * a hard coded set of static mappings.  These mappings are hardware
 * emulator specific because each different hardware emulator could have
 * a different device tree with different cmdk device paths.  This
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
#define	XDF_DEV2UNIT(dev)	XDF_INST((getminor((dev))))
#define	XDF_DEV2PART(dev)	XDF_PART((getminor((dev))))

#define	OTYP_VALID(otyp)	((otyp == OTYP_BLK) || \
					(otyp == OTYP_CHR) || \
					(otyp == OTYP_LYR))

#define	PV_CMDK_NODES		4

typedef struct hvm_to_pv {
	char	*h2p_hvm_path;
	char	*h2p_pv_path;
} hvm_to_pv_t;

/*
 */
static hvm_to_pv_t pv_cmdk_h2p_xen_qemu[] = {
	/*
	 * The paths mapping here are very specific to xen and qemu.  When a
	 * domU is booted under xen in HVM mode, qemu is normally used to
	 * emulate up to four ide disks.  These disks always have the four
	 * path listed below.  To configure an emulated ide device, the
	 * xen domain configuration file normally has an entry that looks
	 * like this:
	 *	disk = [ 'file:/foo.img,hda,w' ]
	 *
	 * The part we're interested in is the 'hda', which we'll call the
	 * xen disk device name here.  The xen management tools (which parse
	 * the xen domain configuration file and launch qemu) makes the
	 * following assumptions about this value:
	 *	hda == emulated ide disk 0 (ide bus 0, master)
	 *	hdb == emulated ide disk 1 (ide bus 0, slave)
	 *	hdc == emulated ide disk 2 (ide bus 1, master)
	 *	hdd == emulated ide disk 3 (ide bus 1, slave)
	 *
	 * (Uncoincidentally, these xen disk device names actually map to
	 * the /dev filesystem names of ide disk devices in Linux.  So in
	 * Linux /dev/hda is the first ide disk.)  So for the first part of
	 * our mapping we've just hardcoded the cmdk paths that we know
	 * qemu will use.
	 *
	 * To understand the second half of the mapping (ie, the xdf device
	 * that each emulated cmdk device should be mapped two) we need to
	 * know the solaris device node address that will be assigned to
	 * each xdf device.  (The device node address is the decimal
	 * number that comes after the "xdf@" in the device path.)
	 *
	 * So the question becomes, how do we know what the xenstore device
	 * id for emulated disk will be?  Well, it turns out that since the
	 * xen management tools expect the disk device names to be Linux
	 * device names, those same management tools assign each disk a
	 * device id that matches the dev_t of the corresponding device
	 * under Linux.  (Big shocker.)  This xen device name-to-id mapping
	 * is currently all hard coded here:
	 *	xen.hg/tools/python/xen/util/blkif.py`blkdev_name_to_number()
	 *
	 * So looking at the code above we can see the following xen disk
	 * device name to xenstore device id mappings:
	 *	'hda' == 0t768  == ((3  * 256) + (0 * 64))
	 *	'hdb' == 0t832  == ((3  * 256) + (1 * 64))
	 *	'hdc' == 0t5632 == ((22 * 256) + (0 * 64))
	 *	'hdd' == 0t5696 == ((22 * 256) + (1 * 64))
	 */
	{ "/pci@0,0/pci-ide@1,1/ide@0/cmdk@0,0", "/xpvd/xdf@768" },
	{ "/pci@0,0/pci-ide@1,1/ide@0/cmdk@1,0", "/xpvd/xdf@832" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/cmdk@0,0", "/xpvd/xdf@5632" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/cmdk@1,0", "/xpvd/xdf@5696" },
	{ NULL, 0 }
};

typedef struct pv_cmdk {
	dev_info_t	*dk_dip;
	cmlb_handle_t	dk_cmlbhandle;
	ddi_devid_t	dk_devid;
	kmutex_t	dk_mutex;
	dev_info_t	*dk_xdf_dip;
	dev_t		dk_xdf_dev;
	int		dk_xdf_otyp_count[OTYPCNT][XDF_PEXT];
	ldi_handle_t	dk_xdf_lh[XDF_PEXT];
} pv_cmdk_t;

/*
 * Globals
 */
static void *pv_cmdk_state;
static major_t pv_cmdk_major;
static hvm_to_pv_t *pv_cmdk_h2p;

/*
 * Function prototypes for xdf callback functions
 */
extern int xdf_lb_getinfo(dev_info_t *, int, void *, void *);
extern int xdf_lb_rdwr(dev_info_t *, uchar_t, void *, diskaddr_t, size_t,
    void *);

static boolean_t
pv_cmdk_isopen_part(struct pv_cmdk *dkp, int part)
{
	int otyp;

	ASSERT(MUTEX_HELD(&dkp->dk_mutex));

	for (otyp = 0; (otyp < OTYPCNT); otyp++) {
		if (dkp->dk_xdf_otyp_count[otyp][part] != 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Cmlb ops vectors, allows the cmlb module to directly access the entire
 * pv_cmdk disk device without going through any partitioning layers.
 */
/*ARGSUSED*/
static int
pv_cmdk_lb_rdwr(dev_info_t *dip, uchar_t cmd, void *bufaddr,
    diskaddr_t start, size_t count, void *tg_cookie)
{
	int		instance = ddi_get_instance(dip);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	if (dkp == NULL)
		return (ENXIO);

	return (xdf_lb_rdwr(dkp->dk_xdf_dip, cmd, bufaddr, start, count,
	    tg_cookie));
}

/*ARGSUSED*/
static int
pv_cmdk_lb_getinfo(dev_info_t *dip, int cmd, void *arg, void *tg_cookie)
{
	int		instance = ddi_get_instance(dip);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	int		err;

	if (dkp == NULL)
		return (ENXIO);

	if (cmd == TG_GETVIRTGEOM) {
		cmlb_geom_t	pgeom, *vgeomp;
		diskaddr_t	capacity;

		/*
		 * The native xdf driver doesn't support this ioctl.
		 * Intead of passing it on, emulate it here so that the
		 * results look the same as what we get for a real cmdk
		 * device.
		 *
		 * Get the real size of the device
		 */
		if ((err = xdf_lb_getinfo(dkp->dk_xdf_dip,
		    TG_GETPHYGEOM, &pgeom, tg_cookie)) != 0)
			return (err);
		capacity = pgeom.g_capacity;

		/*
		 * If the controller returned us something that doesn't
		 * really fit into an Int 13/function 8 geometry
		 * result, just fail the ioctl.  See PSARC 1998/313.
		 */
		if (capacity >= (63 * 254 * 1024))
			return (EINVAL);

		vgeomp = (cmlb_geom_t *)arg;
		vgeomp->g_capacity	= capacity;
		vgeomp->g_nsect		= 63;
		vgeomp->g_nhead		= 254;
		vgeomp->g_ncyl		= capacity / (63 * 254);
		vgeomp->g_acyl		= 0;
		vgeomp->g_secsize	= 512;
		vgeomp->g_intrlv	= 1;
		vgeomp->g_rpm		= 3600;
		return (0);
	}

	return (xdf_lb_getinfo(dkp->dk_xdf_dip, cmd, arg, tg_cookie));
}

static cmlb_tg_ops_t pv_cmdk_lb_ops = {
	TG_DK_OPS_VERSION_1,
	pv_cmdk_lb_rdwr,
	pv_cmdk_lb_getinfo
};

/*
 * devid management functions
 */

/*
 * pv_cmdk_get_modser() is basically a local copy of
 * cmdk_get_modser() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 */
static int
pv_cmdk_get_modser(struct pv_cmdk *dkp, int ioccmd, char *buf, int len)
{
	struct scsi_device	*scsi_device;
	opaque_t		ctlobjp;
	dadk_ioc_string_t	strarg;
	char			*s;
	char			ch;
	boolean_t		ret;
	int			i;
	int			tb;

	strarg.is_buf = buf;
	strarg.is_size = len;
	scsi_device = ddi_get_driver_private(dkp->dk_dip);
	ctlobjp = scsi_device->sd_address.a_hba_tran;
	if (CTL_IOCTL(ctlobjp,
	    ioccmd, (uintptr_t)&strarg, FNATIVE | FKIOCTL) != 0)
		return (0);

	/*
	 * valid model/serial string must contain a non-zero non-space
	 * trim trailing spaces/NULL
	 */
	ret = B_FALSE;
	s = buf;
	for (i = 0; i < strarg.is_size; i++) {
		ch = *s++;
		if (ch != ' ' && ch != '\0')
			tb = i + 1;
		if (ch != ' ' && ch != '\0' && ch != '0')
			ret = B_TRUE;
	}

	if (ret == B_FALSE)
		return (0);

	return (tb);
}

/*
 * pv_cmdk_devid_modser() is basically a copy of cmdk_devid_modser()
 * that has been modified to use local pv cmdk driver functions.
 *
 * Build a devid from the model and serial number
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
pv_cmdk_devid_modser(struct pv_cmdk *dkp)
{
	int	rc = DDI_FAILURE;
	char	*hwid;
	int	modlen;
	int	serlen;

	/*
	 * device ID is a concatenation of model number, '=', serial number.
	 */
	hwid = kmem_alloc(CMDK_HWIDLEN, KM_SLEEP);
	modlen = pv_cmdk_get_modser(dkp, DIOCTL_GETMODEL, hwid, CMDK_HWIDLEN);
	if (modlen == 0)
		goto err;

	hwid[modlen++] = '=';
	serlen = pv_cmdk_get_modser(dkp, DIOCTL_GETSERIAL,
	    hwid + modlen, CMDK_HWIDLEN - modlen);
	if (serlen == 0)
		goto err;

	hwid[modlen + serlen] = 0;

	/* Initialize the device ID, trailing NULL not included */
	rc = ddi_devid_init(dkp->dk_dip, DEVID_ATA_SERIAL, modlen + serlen,
	    hwid, (ddi_devid_t *)&dkp->dk_devid);
	if (rc != DDI_SUCCESS)
		goto err;

	kmem_free(hwid, CMDK_HWIDLEN);
	return (DDI_SUCCESS);

err:
	kmem_free(hwid, CMDK_HWIDLEN);
	return (DDI_FAILURE);
}

/*
 * pv_cmdk_devid_read() is basically a local copy of
 * cmdk_devid_read() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 *
 * Read a devid from on the first block of the last track of
 * the last cylinder.  Make sure what we read is a valid devid.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
pv_cmdk_devid_read(struct pv_cmdk *dkp)
{
	diskaddr_t	blk;
	struct dk_devid *dkdevidp;
	uint_t		*ip, chksum;
	int		i;

	if (cmlb_get_devid_block(dkp->dk_cmlbhandle, &blk, 0) != 0)
		return (DDI_FAILURE);

	dkdevidp = kmem_zalloc(NBPSCTR, KM_SLEEP);
	if (pv_cmdk_lb_rdwr(dkp->dk_dip,
	    TG_READ, dkdevidp, blk, NBPSCTR, NULL) != 0)
		goto err;

	/* Validate the revision */
	if ((dkdevidp->dkd_rev_hi != DK_DEVID_REV_MSB) ||
	    (dkdevidp->dkd_rev_lo != DK_DEVID_REV_LSB))
		goto err;

	/* Calculate the checksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];
	if (DKD_GETCHKSUM(dkdevidp) != chksum)
		goto err;

	/* Validate the device id */
	if (ddi_devid_valid((ddi_devid_t)dkdevidp->dkd_devid) != DDI_SUCCESS)
		goto err;

	/* keep a copy of the device id */
	i = ddi_devid_sizeof((ddi_devid_t)dkdevidp->dkd_devid);
	dkp->dk_devid = kmem_alloc(i, KM_SLEEP);
	bcopy(dkdevidp->dkd_devid, dkp->dk_devid, i);
	kmem_free(dkdevidp, NBPSCTR);
	return (DDI_SUCCESS);

err:
	kmem_free(dkdevidp, NBPSCTR);
	return (DDI_FAILURE);
}

/*
 * pv_cmdk_devid_fabricate() is basically a local copy of
 * cmdk_devid_fabricate() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 *
 * Create a devid and write it on the first block of the last track of
 * the last cylinder.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
pv_cmdk_devid_fabricate(struct pv_cmdk *dkp)
{
	ddi_devid_t	devid = NULL; /* devid made by ddi_devid_init  */
	struct dk_devid	*dkdevidp = NULL; /* devid struct stored on disk */
	diskaddr_t	blk;
	uint_t		*ip, chksum;
	int		i;

	if (cmlb_get_devid_block(dkp->dk_cmlbhandle, &blk, 0) != 0)
		return (DDI_FAILURE);

	if (ddi_devid_init(dkp->dk_dip, DEVID_FAB, 0, NULL, &devid) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	/* allocate a buffer */
	dkdevidp = (struct dk_devid *)kmem_zalloc(NBPSCTR, KM_SLEEP);

	/* Fill in the revision */
	dkdevidp->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevidp->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* Copy in the device id */
	i = ddi_devid_sizeof(devid);
	if (i > DK_DEVID_SIZE)
		goto err;
	bcopy(devid, dkdevidp->dkd_devid, i);

	/* Calculate the chksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];

	/* Fill in the checksum */
	DKD_FORMCHKSUM(chksum, dkdevidp);

	if (pv_cmdk_lb_rdwr(dkp->dk_dip,
	    TG_WRITE, dkdevidp, blk, NBPSCTR, NULL) != 0)
		goto err;

	kmem_free(dkdevidp, NBPSCTR);

	dkp->dk_devid = devid;
	return (DDI_SUCCESS);

err:
	if (dkdevidp != NULL)
		kmem_free(dkdevidp, NBPSCTR);
	if (devid != NULL)
		ddi_devid_free(devid);
	return (DDI_FAILURE);
}

/*
 * pv_cmdk_devid_setup() is basically a local copy ofcmdk_devid_setup()
 * that has been modified to use local pv cmdk driver functions.
 *
 * Create and register the devid.
 * There are 4 different ways we can get a device id:
 *    1. Already have one - nothing to do
 *    2. Build one from the drive's model and serial numbers
 *    3. Read one from the disk (first sector of last track)
 *    4. Fabricate one and write it on the disk.
 * If any of these succeeds, register the deviceid
 */
static void
pv_cmdk_devid_setup(struct pv_cmdk *dkp)
{
	int	rc;

	/* Try options until one succeeds, or all have failed */

	/* 1. All done if already registered */

	if (dkp->dk_devid != NULL)
		return;

	/* 2. Build a devid from the model and serial number */
	rc = pv_cmdk_devid_modser(dkp);
	if (rc != DDI_SUCCESS) {
		/* 3. Read devid from the disk, if present */
		rc = pv_cmdk_devid_read(dkp);

		/* 4. otherwise make one up and write it on the disk */
		if (rc != DDI_SUCCESS)
			rc = pv_cmdk_devid_fabricate(dkp);
	}

	/* If we managed to get a devid any of the above ways, register it */
	if (rc == DDI_SUCCESS)
		(void) ddi_devid_register(dkp->dk_dip, dkp->dk_devid);
}

/*
 * Local Functions
 */
static int
pv_cmdk_iodone(struct buf *bp)
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
pv_cmdkstrategy(struct buf *bp)
{
	dev_t		dev = bp->b_edev;
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	dev_t		xdf_devt;
	struct buf	*bp_clone;

	/*
	 * Sanity checks that the dev_t associated with the buf we were
	 * passed actually corresponds us and that the partition we're
	 * trying to access is actually open.  On debug kernels we'll
	 * panic and on non-debug kernels we'll return failure.
	 */
	ASSERT(getmajor(dev) == pv_cmdk_major);
	if (getmajor(dev) != pv_cmdk_major)
		goto err;

	mutex_enter(&dkp->dk_mutex);
	ASSERT(pv_cmdk_isopen_part(dkp, part));
	if (!pv_cmdk_isopen_part(dkp, part)) {
		mutex_exit(&dkp->dk_mutex);
		goto err;
	}
	mutex_exit(&dkp->dk_mutex);

	/* clone this buffer */
	xdf_devt = dkp->dk_xdf_dev | part;
	bp_clone = bioclone(bp, 0, bp->b_bcount, xdf_devt, bp->b_blkno,
	    pv_cmdk_iodone, NULL, KM_SLEEP);
	bp_clone->b_chain = bp;

	/*
	 * If we're being invoked on behalf of the physio() call in
	 * pv_cmdk_dioctl_rwcmd() then b_private will be set to
	 * XB_SLICE_NONE and we need to propegate this flag into the
	 * cloned buffer so that the xdf driver will see it.
	 */
	if (bp->b_private == (void *)XB_SLICE_NONE)
		bp_clone->b_private = (void *)XB_SLICE_NONE;

	/*
	 * Pass on the cloned buffer.  Note that we don't bother to check
	 * for failure because the xdf strategy routine will have to
	 * invoke biodone() if it wants to return an error, which means
	 * that the pv_cmdk_iodone() callback will get invoked and it
	 * will propegate the error back up the stack and free the cloned
	 * buffer.
	 */
	ASSERT(dkp->dk_xdf_lh[part] != NULL);
	return (ldi_strategy(dkp->dk_xdf_lh[part], bp_clone));

err:
	bioerror(bp, ENXIO);
	bp->b_resid = bp->b_bcount;
	biodone(bp);
	return (0);
}

/*ARGSUSED*/
static int
pv_cmdkread(dev_t dev, struct uio *uio, cred_t *credp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	return (ldi_read(dkp->dk_xdf_lh[part], uio, credp));
}

/*ARGSUSED*/
static int
pv_cmdkwrite(dev_t dev, struct uio *uio, cred_t *credp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	return (ldi_write(dkp->dk_xdf_lh[part], uio, credp));
}

/*ARGSUSED*/
static int
pv_cmdkaread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	return (ldi_aread(dkp->dk_xdf_lh[part], aio, credp));
}

/*ARGSUSED*/
static int
pv_cmdkawrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	return (ldi_awrite(dkp->dk_xdf_lh[part], aio, credp));
}

static int
pv_cmdkdump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	return (ldi_dump(dkp->dk_xdf_lh[part], addr, blkno, nblk));
}

/*
 * pv_rwcmd_copyin() is a duplicate of rwcmd_copyin().
 */
static int
pv_rwcmd_copyin(struct dadkio_rwcmd *rwcmdp, caddr_t inaddr, int flag)
{
	switch (ddi_model_convert_from(flag)) {
		case DDI_MODEL_ILP32: {
			struct dadkio_rwcmd32 cmd32;

			if (ddi_copyin(inaddr, &cmd32,
			    sizeof (struct dadkio_rwcmd32), flag)) {
				return (EFAULT);
			}

			rwcmdp->cmd = cmd32.cmd;
			rwcmdp->flags = cmd32.flags;
			rwcmdp->blkaddr = (daddr_t)cmd32.blkaddr;
			rwcmdp->buflen = cmd32.buflen;
			rwcmdp->bufaddr = (caddr_t)(intptr_t)cmd32.bufaddr;
			/*
			 * Note: we do not convert the 'status' field,
			 * as it should not contain valid data at this
			 * point.
			 */
			bzero(&rwcmdp->status, sizeof (rwcmdp->status));
			break;
		}
		case DDI_MODEL_NONE: {
			if (ddi_copyin(inaddr, rwcmdp,
			    sizeof (struct dadkio_rwcmd), flag)) {
				return (EFAULT);
			}
		}
	}
	return (0);
}

/*
 * pv_rwcmd_copyout() is a duplicate of rwcmd_copyout().
 */
static int
pv_rwcmd_copyout(struct dadkio_rwcmd *rwcmdp, caddr_t outaddr, int flag)
{
	switch (ddi_model_convert_from(flag)) {
		case DDI_MODEL_ILP32: {
			struct dadkio_rwcmd32 cmd32;

			cmd32.cmd = rwcmdp->cmd;
			cmd32.flags = rwcmdp->flags;
			cmd32.blkaddr = rwcmdp->blkaddr;
			cmd32.buflen = rwcmdp->buflen;
			ASSERT64(((uintptr_t)rwcmdp->bufaddr >> 32) == 0);
			cmd32.bufaddr = (caddr32_t)(uintptr_t)rwcmdp->bufaddr;

			cmd32.status.status = rwcmdp->status.status;
			cmd32.status.resid = rwcmdp->status.resid;
			cmd32.status.failed_blk_is_valid =
			    rwcmdp->status.failed_blk_is_valid;
			cmd32.status.failed_blk = rwcmdp->status.failed_blk;
			cmd32.status.fru_code_is_valid =
			    rwcmdp->status.fru_code_is_valid;
			cmd32.status.fru_code = rwcmdp->status.fru_code;

			bcopy(rwcmdp->status.add_error_info,
			    cmd32.status.add_error_info, DADKIO_ERROR_INFO_LEN);

			if (ddi_copyout(&cmd32, outaddr,
			    sizeof (struct dadkio_rwcmd32), flag))
				return (EFAULT);
			break;
		}
		case DDI_MODEL_NONE: {
			if (ddi_copyout(rwcmdp, outaddr,
			    sizeof (struct dadkio_rwcmd), flag))
			return (EFAULT);
		}
	}
	return (0);
}

static void
pv_cmdkmin(struct buf *bp)
{
	if (bp->b_bcount > DK_MAXRECSIZE)
		bp->b_bcount = DK_MAXRECSIZE;
}

static int
pv_cmdk_dioctl_rwcmd(dev_t dev, intptr_t arg, int flag)
{
	struct dadkio_rwcmd	*rwcmdp;
	struct iovec		aiov;
	struct uio		auio;
	struct buf		*bp;
	int			rw, status;

	rwcmdp = kmem_alloc(sizeof (struct dadkio_rwcmd), KM_SLEEP);
	status = pv_rwcmd_copyin(rwcmdp, (caddr_t)arg, flag);

	if (status != 0)
		goto out;

	switch (rwcmdp->cmd) {
		case DADKIO_RWCMD_READ:
		case DADKIO_RWCMD_WRITE:
			break;
		default:
			status = EINVAL;
			goto out;
	}

	bzero((caddr_t)&aiov, sizeof (struct iovec));
	aiov.iov_base = rwcmdp->bufaddr;
	aiov.iov_len = rwcmdp->buflen;

	bzero((caddr_t)&auio, sizeof (struct uio));
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = (offset_t)rwcmdp->blkaddr * (offset_t)XB_BSIZE;
	auio.uio_resid = rwcmdp->buflen;
	auio.uio_segflg = (flag & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;

	/*
	 * Tell the xdf driver that this I/O request is using an absolute
	 * offset.
	 */
	bp = getrbuf(KM_SLEEP);
	bp->b_private = (void *)XB_SLICE_NONE;

	rw = ((rwcmdp->cmd == DADKIO_RWCMD_WRITE) ? B_WRITE : B_READ);
	status = physio(pv_cmdkstrategy, bp, dev, rw, pv_cmdkmin, &auio);

	biofini(bp);
	kmem_free(bp, sizeof (buf_t));

	if (status == 0)
		status = pv_rwcmd_copyout(rwcmdp, (caddr_t)arg, flag);

out:
	kmem_free(rwcmdp, sizeof (struct dadkio_rwcmd));
	return (status);
}

static int
pv_cmdkioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp,
    int *rvalp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	int		err;

	switch (cmd) {
	default:
		return (ldi_ioctl(dkp->dk_xdf_lh[part],
		    cmd, arg, flag, credp, rvalp));
	case DKIOCGETWCE:
	case DKIOCSETWCE:
		return (EIO);
	case DKIOCADDBAD: {
		/*
		 * This is for ata/ide bad block handling.  It is supposed
		 * to cause the driver to re-read the bad block list and
		 * alternate map after it has been updated.  Our driver
		 * will refuse to attach to any disk which has a bad blocks
		 * list defined, so there really isn't much to do here.
		 */
		return (0);
	}
	case DKIOCGETDEF: {
		/*
		 * I can't actually find any code that utilizes this ioctl,
		 * hence we're leaving it explicitly unimplemented.
		 */
		ASSERT("ioctl cmd unsupported by pv_cmdk: DKIOCGETDEF");
		return (EIO);
	}
	case DIOCTL_RWCMD: {
		/*
		 * This just seems to just be an alternate interface for
		 * reading and writing the disk.  Great, another way to
		 * do the same thing...
		 */
		return (pv_cmdk_dioctl_rwcmd(dev, arg, flag));
	}
	case DKIOCINFO: {
		dev_info_t	*dip = dkp->dk_dip;
		struct dk_cinfo	info;

		/* Pass on the ioctl request, save the response */
		if ((err = ldi_ioctl(dkp->dk_xdf_lh[part],
		    cmd, (intptr_t)&info, FKIOCTL, credp, rvalp)) != 0)
			return (err);

		/* Update controller info */
		info.dki_cnum = ddi_get_instance(ddi_get_parent(dip));
		(void) strlcpy(info.dki_cname,
		    ddi_get_name(ddi_get_parent(dip)), sizeof (info.dki_cname));

		/* Update unit info. */
		if (info.dki_ctype == DKC_VBD)
			info.dki_ctype = DKC_DIRECT;
		info.dki_unit = instance;
		(void) strlcpy(info.dki_dname,
		    ddi_driver_name(dip), sizeof (info.dki_dname));
		info.dki_addr = 1;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), flag))
			return (EFAULT);
		return (0);
	}
	} /* switch (cmd) */
	/*NOTREACHED*/
}

/*ARGSUSED*/
static int
pv_cmdkopen(dev_t *dev_p, int flag, int otyp, cred_t *credp)
{
	ldi_ident_t	li;
	dev_t		dev = *dev_p;
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	dev_t		xdf_devt = dkp->dk_xdf_dev | part;
	int		err = 0;

	if ((otyp < 0) || (otyp >= OTYPCNT))
		return (EINVAL);

	/* allocate an ldi handle */
	VERIFY(ldi_ident_from_dev(*dev_p, &li) == 0);

	mutex_enter(&dkp->dk_mutex);

	/*
	 * We translate all device opens (chr, blk, and lyr) into
	 * block device opens.  Why?  Because for all the opens that
	 * come through this driver, we only keep around one LDI handle.
	 * So that handle can only be of one open type.  The reason
	 * that we choose the block interface for this is that to use
	 * the block interfaces for a device the system needs to allocatex
	 * buf_ts, which are associated with system memory which can act
	 * as a cache for device data.  So normally when a block device
	 * is closed the system will ensure that all these pages get
	 * flushed out of memory.  But if we were to open the device
	 * as a character device, then when we went to close the underlying
	 * device (even if we had invoked the block interfaces) any data
	 * remaining in memory wouldn't necessairly be flushed out
	 * before the device was closed.
	 */
	if (dkp->dk_xdf_lh[part] == NULL) {
		ASSERT(!pv_cmdk_isopen_part(dkp, part));

		err = ldi_open_by_dev(&xdf_devt, OTYP_BLK, flag, credp,
		    &dkp->dk_xdf_lh[part], li);

		if (err != 0) {
			mutex_exit(&dkp->dk_mutex);
			ldi_ident_release(li);
			return (err);
		}

		/* Disk devices really shouldn't clone */
		ASSERT(xdf_devt == (dkp->dk_xdf_dev | part));
	} else {
		ldi_handle_t lh_tmp;

		ASSERT(pv_cmdk_isopen_part(dkp, part));

		/* do ldi open/close to get flags and cred check */
		err = ldi_open_by_dev(&xdf_devt, OTYP_BLK, flag, credp,
		    &lh_tmp, li);
		if (err != 0) {
			mutex_exit(&dkp->dk_mutex);
			ldi_ident_release(li);
			return (err);
		}

		/* Disk devices really shouldn't clone */
		ASSERT(xdf_devt == (dkp->dk_xdf_dev | part));
		(void) ldi_close(lh_tmp, flag, credp);
	}
	ldi_ident_release(li);

	dkp->dk_xdf_otyp_count[otyp][part]++;

	mutex_exit(&dkp->dk_mutex);
	return (0);
}

/*ARGSUSED*/
static int
pv_cmdkclose(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		instance = XDF_DEV2UNIT(dev);
	int		part = XDF_DEV2PART(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	int		err = 0;

	ASSERT((otyp >= 0) && otyp < OTYPCNT);

	/*
	 * Sanity check that that the dev_t specified corresponds to this
	 * driver and that the device is actually open.  On debug kernels we'll
	 * panic and on non-debug kernels we'll return failure.
	 */
	ASSERT(getmajor(dev) == pv_cmdk_major);
	if (getmajor(dev) != pv_cmdk_major)
		return (ENXIO);

	mutex_enter(&dkp->dk_mutex);
	ASSERT(pv_cmdk_isopen_part(dkp, part));
	if (!pv_cmdk_isopen_part(dkp, part)) {
		mutex_exit(&dkp->dk_mutex);
		return (ENXIO);
	}

	ASSERT(dkp->dk_xdf_lh[part] != NULL);
	ASSERT(dkp->dk_xdf_otyp_count[otyp][part] > 0);
	if (otyp == OTYP_LYR) {
		dkp->dk_xdf_otyp_count[otyp][part]--;
	} else {
		dkp->dk_xdf_otyp_count[otyp][part] = 0;
	}

	if (!pv_cmdk_isopen_part(dkp, part)) {
		err = ldi_close(dkp->dk_xdf_lh[part], flag, credp);
		dkp->dk_xdf_lh[part] = NULL;
	}

	mutex_exit(&dkp->dk_mutex);

	return (err);
}

static int
pv_cmdk_getpgeom(dev_info_t *dip, cmlb_geom_t *pgeom)
{
	struct scsi_device	*scsi_device;
	struct tgdk_geom	tgdk_geom;
	opaque_t		ctlobjp;
	int			err;

	scsi_device = ddi_get_driver_private(dip);
	ctlobjp = scsi_device->sd_address.a_hba_tran;
	if ((err = CTL_IOCTL(ctlobjp,
	    DIOCTL_GETPHYGEOM, (uintptr_t)&tgdk_geom, FKIOCTL)) != 0)
		return (err);

	/* This driver won't work if this isn't true */
	ASSERT(tgdk_geom.g_secsiz == XB_BSIZE);

	pgeom->g_ncyl = tgdk_geom.g_cyl;
	pgeom->g_acyl = tgdk_geom.g_acyl;
	pgeom->g_nhead = tgdk_geom.g_head;
	pgeom->g_nsect = tgdk_geom.g_sec;
	pgeom->g_secsize = tgdk_geom.g_secsiz;
	pgeom->g_capacity = tgdk_geom.g_cap;
	pgeom->g_intrlv = 1;
	pgeom->g_rpm = 3600;
	return (0);
}

/*
 * pv_cmdk_bb_check() checks for the existance of bad blocks mappings in
 * the alternate partition/slice.  Returns B_FALSE is there are no bad
 * block mappins found, and B_TRUE is there are bad block mappins found.
 */
static boolean_t
pv_cmdk_bb_check(struct pv_cmdk *dkp)
{
	struct alts_parttbl	*ap;
	diskaddr_t		nblocks, blk;
	uint32_t		altused, altbase, altlast;
	uint16_t		vtoctag;
	int			alts;

	/* find slice with V_ALTSCTR tag */
	for (alts = 0; alts < NDKMAP; alts++) {

		if (cmlb_partinfo(dkp->dk_cmlbhandle, alts,
		    &nblocks, &blk, NULL, &vtoctag, 0) != 0) {
			/* no partition table exists */
			return (B_FALSE);
		}

		if ((vtoctag == V_ALTSCTR) && (nblocks > 1))
			break;
	}
	if (alts >= NDKMAP)
		return (B_FALSE); /* no V_ALTSCTR slice defined */

	/* read in ALTS label block */
	ap = (struct alts_parttbl *)kmem_zalloc(NBPSCTR, KM_SLEEP);
	if (pv_cmdk_lb_rdwr(dkp->dk_dip,
	    TG_READ, ap, blk, NBPSCTR, NULL) != 0)
		goto err;

	altused = ap->alts_ent_used;	/* number of BB entries */
	altbase = ap->alts_ent_base;	/* blk offset from begin slice */
	altlast = ap->alts_ent_end;	/* blk offset to last block */

	if ((altused == 0) || (altbase < 1) ||
	    (altbase > altlast) || (altlast >= nblocks))
		goto err;

	/* we found bad block mappins */
	kmem_free(ap, NBPSCTR);
	return (B_TRUE);

err:
	kmem_free(ap, NBPSCTR);
	return (B_FALSE);
}

/*
 * Autoconfiguration Routines
 */
static int
pv_cmdkattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	dev_info_t		*xdf_dip = NULL;
	struct pv_cmdk		*dkp;
	cmlb_geom_t		pgeom;
	char			*path;
	int			i;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * This cmdk device layers on top of an xdf device.  So the first
	 * thing we need to do is determine which xdf device instance this
	 * cmdk instance should be layered on top of.
	 */
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);
	for (i = 0; pv_cmdk_h2p[i].h2p_hvm_path != NULL; i++) {
		if (strcmp(pv_cmdk_h2p[i].h2p_hvm_path, path) == 0)
			break;
	}
	kmem_free(path, MAXPATHLEN);

	if (pv_cmdk_h2p[i].h2p_hvm_path == NULL) {
		/*
		 * UhOh.  We don't know what xdf instance this cmdk device
		 * should be mapped to.
		 */
		return (DDI_FAILURE);
	}

	/* Check if this device exists */
	xdf_dip = xdf_hvm_hold(pv_cmdk_h2p[i].h2p_pv_path);
	if (xdf_dip == NULL)
		return (DDI_FAILURE);

	/* allocate and initialize our state structure */
	(void) ddi_soft_state_zalloc(pv_cmdk_state, instance);
	dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	mutex_init(&dkp->dk_mutex, NULL, MUTEX_DRIVER, NULL);
	dkp->dk_dip = dip;
	dkp->dk_xdf_dip = xdf_dip;
	dkp->dk_xdf_dev = makedevice(ddi_driver_major(xdf_dip),
	    XDF_MINOR(ddi_get_instance(xdf_dip), 0));

	ASSERT((dkp->dk_xdf_dev & XDF_PMASK) == 0);

	/*
	 * GROSS HACK ALERT!  GROSS HACK ALERT!
	 *
	 * Before we can initialize the cmlb layer, we have to tell the
	 * underlying xdf device what it's physical geometry should be.
	 * See the block comments at the top of this file for more info.
	 */
	if ((pv_cmdk_getpgeom(dip, &pgeom) != 0) ||
	    (xdf_hvm_setpgeom(dkp->dk_xdf_dip, &pgeom) != 0)) {
		ddi_release_devi(dkp->dk_xdf_dip);
		mutex_destroy(&dkp->dk_mutex);
		ddi_soft_state_free(pv_cmdk_state, instance);
		return (DDI_FAILURE);
	}

	/* create kstat for iostat(1M) */
	if (xdf_kstat_create(dkp->dk_xdf_dip, "cmdk", instance) != 0) {
		ddi_release_devi(dkp->dk_xdf_dip);
		mutex_destroy(&dkp->dk_mutex);
		ddi_soft_state_free(pv_cmdk_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Force the xdf front end driver to connect to the backend.  From
	 * the solaris device tree perspective, the xdf driver devinfo node
	 * is already in the ATTACHED state.  (Otherwise xdf_hvm_hold()
	 * would not have returned a dip.)  But this doesn't mean that the
	 * xdf device has actually established a connection to it's back
	 * end driver.  For us to be able to access the xdf device it needs
	 * to be connected.  There are two ways to force the xdf driver to
	 * connect to the backend device.
	 */
	if (xdf_hvm_connect(dkp->dk_xdf_dip) != 0) {
		cmn_err(CE_WARN,
		    "pv driver failed to connect: %s",
		    pv_cmdk_h2p[i].h2p_pv_path);
		xdf_kstat_delete(dkp->dk_xdf_dip);
		ddi_release_devi(dkp->dk_xdf_dip);
		mutex_destroy(&dkp->dk_mutex);
		ddi_soft_state_free(pv_cmdk_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Initalize cmlb.  Note that for partition information cmlb
	 * will access the underly xdf disk device directly via
	 * pv_cmdk_lb_rdwr() and pv_cmdk_lb_getinfo().  There are no
	 * layered driver handles associated with this access because
	 * it is a direct disk access that doesn't go through
	 * any of the device nodes exported by the xdf device (since
	 * all exported device nodes only reflect the portion of
	 * the device visible via the partition/slice that the node
	 * is associated with.)  So while not observable via the LDI,
	 * this direct disk access is ok since we're actually holding
	 * the target device.
	 */
	cmlb_alloc_handle((cmlb_handle_t *)&dkp->dk_cmlbhandle);
	if (cmlb_attach(dkp->dk_dip, &pv_cmdk_lb_ops,
	    DTYPE_DIRECT,		/* device_type */
	    0,				/* not removable */
	    0,				/* not hot pluggable */
	    DDI_NT_BLOCK,
	    CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT,	/* mimic cmdk */
	    dkp->dk_cmlbhandle, 0) != 0) {
		cmlb_free_handle(&dkp->dk_cmlbhandle);
		xdf_kstat_delete(dkp->dk_xdf_dip);
		ddi_release_devi(dkp->dk_xdf_dip);
		mutex_destroy(&dkp->dk_mutex);
		ddi_soft_state_free(pv_cmdk_state, instance);
		return (DDI_FAILURE);
	}

	if (pv_cmdk_bb_check(dkp)) {
		cmn_err(CE_WARN,
		    "pv cmdk disks with bad blocks are unsupported: %s",
		    pv_cmdk_h2p[i].h2p_hvm_path);

		cmlb_detach(dkp->dk_cmlbhandle, 0);
		cmlb_free_handle(&dkp->dk_cmlbhandle);
		xdf_kstat_delete(dkp->dk_xdf_dip);
		ddi_release_devi(dkp->dk_xdf_dip);
		mutex_destroy(&dkp->dk_mutex);
		ddi_soft_state_free(pv_cmdk_state, instance);
		return (DDI_FAILURE);
	}

	/* setup devid string */
	pv_cmdk_devid_setup(dkp);

	/* Calling validate will create minor nodes according to disk label */
	(void) cmlb_validate(dkp->dk_cmlbhandle, 0, 0);

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers).
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);

	/* Have the system report any newly created device nodes */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
pv_cmdkdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(MUTEX_NOT_HELD(&dkp->dk_mutex));

	ddi_devid_unregister(dip);
	if (dkp->dk_devid)
		ddi_devid_free(dkp->dk_devid);
	cmlb_detach(dkp->dk_cmlbhandle, 0);
	cmlb_free_handle(&dkp->dk_cmlbhandle);
	mutex_destroy(&dkp->dk_mutex);
	xdf_kstat_delete(dkp->dk_xdf_dip);
	ddi_release_devi(dkp->dk_xdf_dip);
	ddi_soft_state_free(pv_cmdk_state, instance);
	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pv_cmdk_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t		dev = (dev_t)arg;
	int		instance = XDF_DEV2UNIT(dev);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			if (dkp == NULL)
				return (DDI_FAILURE);
			*result = (void *)dkp->dk_dip;
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
pv_cmdk_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	struct pv_cmdk	*dkp = ddi_get_soft_state(pv_cmdk_state, instance);
	dev_info_t	*xdf_dip;
	dev_t		xdf_devt;
	int		err;

	/*
	 * Sanity check that if a dev_t or dip were specified that they
	 * correspond to this device driver.  On debug kernels we'll
	 * panic and on non-debug kernels we'll return failure.
	 */
	ASSERT(ddi_driver_major(dip) == pv_cmdk_major);
	ASSERT((dev == DDI_DEV_T_ANY) || (getmajor(dev) == pv_cmdk_major));
	if ((ddi_driver_major(dip) != pv_cmdk_major) ||
	    ((dev != DDI_DEV_T_ANY) && (getmajor(dev) != pv_cmdk_major)))
		return (DDI_PROP_NOT_FOUND);

	/*
	 * This property lookup might be associated with a device node
	 * that is not yet attached, if so pass it onto ddi_prop_op().
	 */
	if (dkp == NULL)
		return (ddi_prop_op(dev, dip, prop_op, flags,
		    name, valuep, lengthp));

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
	 * the ldi here, it would also be possible for some other caller
	 * to try open the device with the FEXCL flag and get a failure
	 * back because we have it open to do a property query.
	 *
	 * Instad we'll grab a hold on the target dip and query the
	 * property directly.
	 */
	mutex_enter(&dkp->dk_mutex);

	if ((xdf_dip = dkp->dk_xdf_dip) == NULL) {
		mutex_exit(&dkp->dk_mutex);
		return (DDI_PROP_NOT_FOUND);
	}
	e_ddi_hold_devi(xdf_dip);

	/* figure out the dev_t we're going to pass on down */
	if (dev == DDI_DEV_T_ANY) {
		xdf_devt = DDI_DEV_T_ANY;
	} else {
		xdf_devt = dkp->dk_xdf_dev | XDF_DEV2PART(dev);
	}

	mutex_exit(&dkp->dk_mutex);

	/*
	 * Cdev_prop_op() is not a public interface, and normally the caller
	 * is required to make sure that the target driver actually implements
	 * this interface before trying to invoke it.  In this case we know
	 * that we're always accessing the xdf driver and it does have this
	 * interface defined, so we can skip the check.
	 */
	err = cdev_prop_op(xdf_devt, xdf_dip,
	    prop_op, flags, name, valuep, lengthp);
	ddi_release_devi(xdf_dip);
	return (err);
}

/*
 * Device driver ops vector
 */
static struct cb_ops pv_cmdk_cb_ops = {
	pv_cmdkopen,		/* open */
	pv_cmdkclose,		/* close */
	pv_cmdkstrategy,	/* strategy */
	nodev,			/* print */
	pv_cmdkdump,		/* dump */
	pv_cmdkread,		/* read */
	pv_cmdkwrite,		/* write */
	pv_cmdkioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	pv_cmdk_prop_op,	/* cb_prop_op */
	0,			/* streamtab  */
	D_64BIT | D_MP | D_NEW,	/* Driver comaptibility flag */
	CB_REV,			/* cb_rev */
	pv_cmdkaread,		/* async read */
	pv_cmdkawrite		/* async write */
};

struct dev_ops pv_cmdk_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	pv_cmdk_getinfo,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pv_cmdkattach,		/* attach */
	pv_cmdkdetach,		/* detach */
	nodev,			/* reset */
	&pv_cmdk_cb_ops,	/* driver operations */
	(struct bus_ops *)0	/* bus operations */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"PV Common Direct Access Disk",
	&pv_cmdk_ops,		/* driver ops		*/
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int rval;

	if ((pv_cmdk_major = ddi_name_to_major("cmdk")) == (major_t)-1)
		return (EINVAL);

	/*
	 * In general ide usually supports 4 disk devices, this same
	 * limitation also applies to software emulating ide devices.
	 * so by default we pre-allocate 4 cmdk soft state structures.
	 */
	if ((rval = ddi_soft_state_init(&pv_cmdk_state,
	    sizeof (struct pv_cmdk), PV_CMDK_NODES)) != 0)
		return (rval);

	/*
	 * Currently we only support qemu as the backing hardware emulator
	 * for cmdk devices.
	 */
	pv_cmdk_h2p = pv_cmdk_h2p_xen_qemu;

	/* Install our module */
	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pv_cmdk_state);
		return (rval);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	rval;
	if ((rval = mod_remove(&modlinkage)) != 0)
		return (rval);
	ddi_soft_state_fini(&pv_cmdk_state);
	return (0);
}
