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

#include <sys/types.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/file.h>

#include "ata_common.h"
#include "ata_disk.h"

/*
 * this typedef really should be in dktp/cmpkt.h
 */
typedef struct cmpkt cmpkt_t;


/*
 * DADA entry points
 */

static int ata_disk_abort(opaque_t ctl_data, cmpkt_t *pktp);
static int ata_disk_reset(opaque_t ctl_data, int level);
static int ata_disk_ioctl(opaque_t ctl_data, int cmd, intptr_t a, int flag);
static cmpkt_t *ata_disk_pktalloc(opaque_t ctl_data, int (*callback)(caddr_t),
    caddr_t arg);
static void ata_disk_pktfree(opaque_t ctl_data, cmpkt_t *pktp);
static cmpkt_t	*ata_disk_memsetup(opaque_t ctl_data, cmpkt_t *pktp,
    struct buf *bp, int (*callback)(caddr_t), caddr_t arg);
static void ata_disk_memfree(opaque_t ctl_data, cmpkt_t *pktp);
static cmpkt_t	*ata_disk_iosetup(opaque_t ctl_data, cmpkt_t *pktp);
static int ata_disk_transport(opaque_t ctl_data, cmpkt_t *pktp);

/*
 * DADA packet callbacks
 */

static void ata_disk_complete(ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp,
    int do_callback);
static int ata_disk_intr(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_intr_dma(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_intr_pio_in(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_intr_pio_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start_dma_in(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start_dma_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start_pio_in(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start_pio_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);

/*
 * Local Function prototypes
 */

static int ata_disk_eject(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static void ata_disk_fake_inquiry(ata_drv_t *ata_drvp);
static void ata_disk_get_resid(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_initialize_device_parameters(ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp);
static int ata_disk_lock(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_set_multiple(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp);
static void ata_disk_pio_xfer_data_in(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp);
static void ata_disk_pio_xfer_data_out(ata_ctl_t *ata_ctlp,
    ata_pkt_t *ata_pktp);
static void ata_disk_set_standby_timer(ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp);
static int ata_disk_recalibrate(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_standby(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_start_common(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_state(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_disk_unlock(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp);
static int ata_get_capacity(ata_drv_t *ata_drvp, uint64_t *capacity);
static void ata_fix_large_disk_geometry(ata_drv_t *ata_drvp);
static uint64_t	ata_calculate_28bits_capacity(ata_drv_t *ata_drvp);
static uint64_t	ata_calculate_48bits_capacity(ata_drv_t *ata_drvp);
static int ata_copy_dk_ioc_string(intptr_t arg, char *source, int length,
    int flag);
static void ata_set_write_cache(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp);
static int ata_disk_update_fw(gtgt_t *gtgtp, ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp, caddr_t fwfile, uint_t size,
    uint8_t type, int flag);
static int ata_disk_set_feature_spinup(ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp);
static int ata_disk_id_update(ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp);


/*
 * Local static data
 */

uint_t	ata_disk_init_dev_parm_wait = 4 * 1000000;
uint_t	ata_disk_set_mult_wait = 4 * 1000000;
int	ata_disk_do_standby_timer = TRUE;

/* timeout value for device update firmware */
int	ata_disk_updatefw_time = 60;

/*
 * ata_write_cache == 1  force write cache on.
 * ata_write_cache == 0  do not modify write cache.  firmware defaults kept.
 * ata_write_cache == -1 force write cache off.
 */
int	ata_write_cache = 1;


static struct ctl_objops ata_disk_objops = {
	ata_disk_pktalloc,
	ata_disk_pktfree,
	ata_disk_memsetup,
	ata_disk_memfree,
	ata_disk_iosetup,
	ata_disk_transport,
	ata_disk_reset,
	ata_disk_abort,
	nulldev,
	nulldev,
	ata_disk_ioctl,
	0, 0
};



/*
 *
 * initialize the ata_disk sub-system
 *
 */

/*ARGSUSED*/
int
ata_disk_attach(
	ata_ctl_t *ata_ctlp)
{
	ADBG_TRACE(("ata_disk_init entered\n"));
	return (TRUE);
}



/*
 *
 * destroy the ata_disk sub-system
 *
 */

/*ARGSUSED*/
void
ata_disk_detach(
	ata_ctl_t *ata_ctlp)
{
	ADBG_TRACE(("ata_disk_destroy entered\n"));
}


/*
 * Test whether the disk can support Logical Block Addressing
 */

int
ata_test_lba_support(struct ata_id *aidp)
{
#ifdef __old_version__
	/*
	 * determine if the drive supports LBA mode
	 */
	if (aidp->ai_cap & ATAC_LBA_SUPPORT)
		return (TRUE);
#else
	/*
	 * Determine if the drive supports LBA mode
	 * LBA mode is mandatory on ATA-3 (or newer) drives but is
	 * optional on ATA-2 (or older) drives. On ATA-2 drives
	 * the ai_majorversion word should be 0xffff or 0x0000
	 * (version not reported).
	 */
	if (aidp->ai_majorversion != 0xffff &&
	    aidp->ai_majorversion >= (1 << 3)) {
		/* ATA-3 or better */
		return (TRUE);
	} else if (aidp->ai_cap & ATAC_LBA_SUPPORT) {
		/* ATA-2 LBA capability bit set */
		return (TRUE);
	} else {
		return (FALSE);
	}
#endif
}

/*
 * ATA-6 drives do not provide geometry information, so words
 * ai_heads, ai_sectors and ai_fixcyls may not be valid
 */
static void
ata_fixup_ata6_geometry(struct ata_id *aidp)
{
	/* check cylinders, heads, and sectors for valid values */
	if (aidp->ai_heads != 0 && aidp->ai_heads != 0xffff &&
	    aidp->ai_sectors != 0 && aidp->ai_sectors != 0xffff &&
	    aidp->ai_fixcyls != 0)
		return;		/* assume valid geometry - do nothing */

	/*
	 * Pre-set standard geometry values - they are not necessarily
	 * optimal for a given capacity
	 */
	aidp->ai_heads = 0x10;
	aidp->ai_sectors = 0x3f;
	aidp->ai_fixcyls = 1;
	/*
	 * The fixcyls value will get fixed up later in
	 * ata_fix_large_disk_geometry.
	 */
}

/*
 *
 * initialize the soft-structure for an ATA (non-PACKET) drive and
 * then configure the drive with the correct modes and options.
 *
 */

int
ata_disk_init_drive(
	ata_drv_t *ata_drvp)
{
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;
	struct ata_id	*aidp = &ata_drvp->ad_id;
	struct ctl_obj	*ctlobjp;
	struct scsi_device	*devp;
	int		len;
	int		val;
	int		mode;
	short		*chs;
	char		buf[80];

	ADBG_TRACE(("ata_disk_init_drive entered\n"));

	/* ATA disks don't support LUNs */

	if (ata_drvp->ad_lun != 0)
		return (FALSE);

	/*
	 * set up drive structure
	 * ATA-6 drives do not provide geometry information, so words
	 * ai_heads, ai_sectors and ai_fixcyls may not be valid - they
	 * will be fixed later
	 */

	ata_drvp->ad_phhd = aidp->ai_heads;
	ata_drvp->ad_phsec = aidp->ai_sectors;
	ata_drvp->ad_drvrhd   = aidp->ai_heads;
	ata_drvp->ad_drvrsec  = aidp->ai_sectors;
	ata_drvp->ad_drvrcyl  = aidp->ai_fixcyls;
	ata_drvp->ad_acyl = 0;

	if (ata_test_lba_support(&ata_drvp->ad_id))
		ata_drvp->ad_drive_bits |= ATDH_LBA;

	/* Get capacity and check for 48-bit mode */
	mode = ata_get_capacity(ata_drvp, &ata_drvp->ad_capacity);
	if (mode == AD_EXT48) {
		ata_drvp->ad_flags |= AD_EXT48;
	}

	/* straighten out the geometry */
	(void) sprintf(buf, "SUNW-ata-%p-d%d-chs", (void *) ata_ctlp->ac_data,
	    ata_drvp->ad_targ+1);
	if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    buf, (caddr_t)&chs, &len) == DDI_PROP_SUCCESS) {
		/*
		 * if the number of sectors and heads in bios matches the
		 * physical geometry, then so should the number of cylinders
		 * this is to prevent the 1023 limit in the older bios's
		 * causing loss of space.
		 */
		if (chs[1] == (ata_drvp->ad_drvrhd - 1) &&
		    chs[2] == ata_drvp->ad_drvrsec) {
			/* Set chs[0] to zero-based number of cylinders. */
			chs[0] = aidp->ai_fixcyls - 1;
		} else if (!(ata_drvp->ad_drive_bits & ATDH_LBA)) {
			/*
			 * if the the sector/heads do not match that of the
			 * bios and the drive does not support LBA. We go ahead
			 * and advertise the bios geometry but use the physical
			 * geometry for sector translation.
			 */
			cmn_err(CE_WARN, "!Disk 0x%p,%d: BIOS geometry "
			    "different from physical, and no LBA support.",
			    (void *)ata_ctlp->ac_data, ata_drvp->ad_targ);
		}

		/*
		 * chs[0,1] are zero-based; make them one-based.
		 */
		ata_drvp->ad_drvrcyl = chs[0] + 1;
		ata_drvp->ad_drvrhd = chs[1] + 1;
		ata_drvp->ad_drvrsec = chs[2];
		kmem_free(chs, len);
	} else {
		/*
		 * Property not present; this means that boot.bin has
		 * determined that the drive supports Int13 LBA.  Note
		 * this, but just return a geometry with a large
		 * cylinder count; this will be the signal for dadk to
		 * fail DKIOCG_VIRTGEOM.
		 * ad_drvr* are already set; just recalculate ad_drvrcyl
		 * from capacity.
		 */

		ata_drvp->ad_flags |= AD_INT13LBA;
		if (ata_drvp->ad_capacity != 0) {
			ata_drvp->ad_drvrcyl = ata_drvp->ad_capacity /
			    (ata_drvp->ad_drvrhd * ata_drvp->ad_drvrsec);
		} else {
			/*
			 * Something's wrong; return something sure to
			 * fail the "cyls < 1024" test.  This will
			 * never make it out of the DKIOCG_VIRTGEOM
			 * call, so its total bogosity won't matter.
			 */
			ata_drvp->ad_drvrcyl = 1025;
			ata_drvp->ad_drvrhd = 1;
			ata_drvp->ad_drvrsec = 1;
		}
	}

	/* fix geometry for disks > 31GB, if needed */
	ata_fix_large_disk_geometry(ata_drvp);

	/*
	 * set up the scsi_device and ctl_obj structures
	 */
	devp = kmem_zalloc(scsi_device_size(), KM_SLEEP);
	ata_drvp->ad_device = devp;
	ctlobjp = &ata_drvp->ad_ctl_obj;

	devp->sd_inq = &ata_drvp->ad_inquiry;
	devp->sd_address.a_hba_tran = (scsi_hba_tran_t *)ctlobjp;
	devp->sd_address.a_target = (ushort_t)ata_drvp->ad_targ;
	devp->sd_address.a_lun = (uchar_t)ata_drvp->ad_lun;
	mutex_init(&devp->sd_mutex, NULL, MUTEX_DRIVER, NULL);
	ata_drvp->ad_flags |= AD_MUTEX_INIT;

	/*
	 * DADA ops vectors and cookie
	 */
	ctlobjp->c_ops  = (struct ctl_objops *)&ata_disk_objops;

	/*
	 * this is filled in with gtgtp by ata_disk_bus_ctl(INITCHILD)
	 */
	ctlobjp->c_data = NULL;

	ctlobjp->c_ext  = &(ctlobjp->c_extblk);
	ctlobjp->c_extblk.c_ctldip = ata_ctlp->ac_dip;
	ctlobjp->c_extblk.c_targ   = ata_drvp->ad_targ;
	ctlobjp->c_extblk.c_blksz  = NBPSCTR;

	/*
	 * Get highest block factor supported by the drive.
	 * Some drives report 0 if read/write multiple not supported,
	 * adjust their blocking factor to 1.
	 */
	ata_drvp->ad_block_factor = aidp->ai_mult1 & 0xff;

	/*
	 * If a block factor property exists, use the smaller of the
	 * property value and the highest value the drive can support.
	 */
	(void) sprintf(buf, "drive%d_block_factor", ata_drvp->ad_targ);
	val = ddi_prop_get_int(DDI_DEV_T_ANY, ata_ctlp->ac_dip, 0, buf,
	    ata_drvp->ad_block_factor);

	ata_drvp->ad_block_factor = (short)min(val, ata_drvp->ad_block_factor);

	if (ata_drvp->ad_block_factor == 0)
		ata_drvp->ad_block_factor = 1;

	if (!ata_disk_setup_parms(ata_ctlp, ata_drvp)) {
		ata_drvp->ad_device = NULL;
		kmem_free(devp, scsi_device_size());
		return (FALSE);
	}

	ata_disk_fake_inquiry(ata_drvp);

	return (TRUE);
}

/*
 * Test if a disk supports 48-bit (extended mode) addressing and
 * get disk capacity.
 * Return value:
 *	AD_EXT48 if 48-bit mode is available, 0 otherwise,
 *	capacity in sectors.
 * There are several indicators for 48-bit addressing.  If any of
 * them is missing, assume 28-bit (non-extended) addressing.
 */

static int
ata_get_capacity(ata_drv_t *ata_drvp, uint64_t *capacity)
{
	struct ata_id	*aidp = &ata_drvp->ad_id;
	uint64_t	cap28;	/* capacity in 28-bit mode */
	uint64_t	cap48;	/* capacity in 48-bit mode */

	/*
	 * First compute capacity in 28-bit mode, using 28-bit capacity
	 * words in IDENTIFY DEVICE response words
	 */
	cap28 = ata_calculate_28bits_capacity(ata_drvp);
	*capacity = cap28;

	if (!IS_ATA_VERSION_SUPPORTED(aidp, 6) &&
	    !(ata_drvp->ad_flags & AD_BLLBA48))
		return (0);

	/* Check that 48 bit addressing is supported & enabled */
	/* words 83 and 86 */
	if (!(aidp->ai_cmdset83 & ATACS_EXT48))
		return (0);
	if (!(aidp->ai_features86 & ATACS_EXT48))
		return (0);

	/*
	 * Drive supports ATA-6.  Since ATA-6 drives may not provide
	 * geometry info, pre-set standard geometry values
	 */
	ata_fixup_ata6_geometry(aidp);

	/* Compute 48-bit capacity */
	cap48 = ata_calculate_48bits_capacity(ata_drvp);

	/*
	 * If capacity is smaller then the maximum capacity addressable
	 * in 28-bit mode, just use 28-bit capacity value.
	 * We will use 28-bit addressing read/write commands.
	 */
	if (cap48 <= MAX_28BIT_CAPACITY)
		return (0);

	/*
	 * Capacity is too big for 28-bits addressing. But, to make
	 * sure that the drive implements ATA-6 correctly, the
	 * final check: cap28 should be MAX for 28-bit addressing.
	 * If it's not, we shouldn't use 48-bit mode, so return
	 * the capacity reported in 28-bit capacity words.
	 */
	if (cap28 != MAX_28BIT_CAPACITY)
		return (0);		/* not max, use 28-bit value */

	/*
	 * All is well so return 48-bit capacity indicator
	 */
	ADBG_INIT(("ATA: using 48-bit mode for capacity %llx blocks\n",
	    (unsigned long long)cap48));

	*capacity = cap48;
	return (AD_EXT48);
}

/*
 * With the advent of disks that hold more than 31 GB, we run into a
 * limitation in the sizes of the fields that describe the geometry.
 * The cylinders, heads, and sectors-per-track are each described by a
 * 16-bit number -- both in the structure returned from IDENTIFY
 * DEVICE and in the structure returned from the DIOCTL_GETGEOM or
 * DIOCTL_GETPHYGEOM ioctl.
 *
 * The typical disk has 32 heads per cylinder and 63 sectors per
 * track.  A 16 bit field can contain up to 65535.  So the largest
 * disk that can be described in these fields is 65535 * 32 * 63 * 512
 * (bytes/sector), or about 31.5 GB.  The cylinder count gets truncated
 * when stored in a narrow field, so a 40GB disk appears to have only
 * 8 GB!
 *
 * The solution (for the time being at least) is to lie about the
 * geometry.  If the number of cylinders is too large to fit in 16
 * bits, we will halve the cylinders and double the heads, repeating
 * until we can fit the geometry into 3 shorts.
 * FUTURE ENHANCEMENT: If this ever isn't enough, we could
 * add another step to double sectors/track as well.
 */

static void
ata_fix_large_disk_geometry(
	ata_drv_t *ata_drvp)
{
	struct ata_id	*aidp = &ata_drvp->ad_id;

	/* no hope for large disks if LBA not supported */
	if (!(ata_drvp->ad_drive_bits & ATDH_LBA))
		return;

	/*
	 * Fix up the geometry to be returned by DIOCTL_GETGEOM.
	 * If number of cylinders > USHRT_MAX, double heads and
	 * halve cylinders until everything fits.
	 */
	while (ata_drvp->ad_drvrcyl > USHRT_MAX) {
		int tempheads;

		/* is there room in 16 bits to double the heads? */
		tempheads = 2 * ata_drvp->ad_drvrhd;
		if (tempheads > USHRT_MAX) {
			/*
			 * No room to double the heads.
			 * I give up, there's no way to represent this.
			 * Limit disk size.
			 */
			cmn_err(CE_WARN, "Disk is too large: "
			    "Model %s, Serial# %s Approximating...\n",
			    aidp->ai_model, aidp->ai_drvser);
			ata_drvp->ad_drvrcyl = USHRT_MAX;
			break;
		}

		/* OK, so double the heads and halve the cylinders */
		ata_drvp->ad_drvrcyl /= 2;
		ata_drvp->ad_drvrhd *= 2;
	}
}

/*
 * Calculate capacity using 28-bit capacity words from IDENTIFY DEVICE
 * return words
 */
uint64_t
ata_calculate_28bits_capacity(ata_drv_t *ata_drvp)
{
	/*
	 * Asked x3t13 for advice; this implements Hale Landis'
	 * response, minus the "use ATA_INIT_DEVPARMS".
	 * See "capacity.notes".
	 */

	/* some local shorthand/renaming to clarify the meaning */

	ushort_t curcyls_w54, curhds_w55, cursect_w56;
	uint32_t curcap_w57_58;

	if ((ata_drvp->ad_drive_bits & ATDH_LBA) != 0) {
		return ((uint64_t)(ata_drvp->ad_id.ai_addrsec[0] +
		    ata_drvp->ad_id.ai_addrsec[1] * 0x10000));
	}

	/*
	 * If we're not LBA, then first try to validate "current" values.
	 */

	curcyls_w54 = ata_drvp->ad_id.ai_curcyls;
	curhds_w55 = ata_drvp->ad_id.ai_curheads;
	cursect_w56 = ata_drvp->ad_id.ai_cursectrk;
	curcap_w57_58 = ata_drvp->ad_id.ai_cursccp[0] +
	    ata_drvp->ad_id.ai_cursccp[1] * 0x10000;

	if (((ata_drvp->ad_id.ai_validinfo & 1) == 1) &&
	    (curhds_w55 >= 1) && (curhds_w55 <= 16) &&
	    (cursect_w56 >= 1) && (cursect_w56 <= 63) &&
	    (curcap_w57_58 == curcyls_w54 * curhds_w55 * cursect_w56)) {
		return ((uint64_t)curcap_w57_58);
	}

	/*
	 * At this point, Hale recommends ATA_INIT_DEVPARMS.
	 * I don't want to do that, so simply use 1/3/6 as
	 * a final fallback, and continue to assume the BIOS
	 * has done whatever INIT_DEVPARMS are necessary.
	 */

	return ((uint64_t)(ata_drvp->ad_id.ai_fixcyls *
	    ata_drvp->ad_id.ai_heads * ata_drvp->ad_id.ai_sectors));
}

/*
 * Calculate capacity using 48-bits capacity words from IDENTIFY DEVICE
 * return words
 */
uint64_t
ata_calculate_48bits_capacity(ata_drv_t *ata_drvp)
{
	uint64_t cap48 = 0;
	int i;

	for (i = 3;  i >= 0;  --i) {
		cap48 <<= 16;
		cap48 += ata_drvp->ad_id.ai_addrsecxt[i];
	}
	return (cap48);
}


/*
 *
 * Setup the drives Read/Write Multiple Blocking factor and the
 * current translation geometry. Necessary during attach and after
 * Software Resets.
 *
 */

int
ata_disk_setup_parms(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp)
{

	/*
	 * program geometry info back to the drive
	 */
	if (!ata_disk_initialize_device_parameters(ata_ctlp, ata_drvp)) {
		return (FALSE);
	}

	/*
	 * Determine the blocking factor
	 */
	if (ata_drvp->ad_block_factor > 1) {
		/*
		 * Program the block factor into the drive. If this
		 * fails, then go back to using a block size of 1.
		 */
		if (!ata_disk_set_multiple(ata_ctlp, ata_drvp))
			ata_drvp->ad_block_factor = 1;
	}


	if (ata_drvp->ad_block_factor > 1) {
		ata_drvp->ad_rd_cmd = ATC_RDMULT;
		ata_drvp->ad_wr_cmd = ATC_WRMULT;
	} else {
		ata_drvp->ad_rd_cmd = ATC_RDSEC;
		ata_drvp->ad_wr_cmd = ATC_WRSEC;
	}

	ata_drvp->ad_bytes_per_block = ata_drvp->ad_block_factor << SCTRSHFT;

	ADBG_INIT(("set block factor for drive %d to %d\n",
	    ata_drvp->ad_targ, ata_drvp->ad_block_factor));

	if (ata_disk_do_standby_timer)
		ata_disk_set_standby_timer(ata_ctlp, ata_drvp);

	ata_set_write_cache(ata_ctlp, ata_drvp);

	return (TRUE);
}


/*
 * Take the timeout value specified in the "standby" property
 * and convert from seconds to the magic parm expected by the
 * the drive. Then issue the IDLE command to set the drive's
 * internal standby timer.
 */

static void
ata_disk_set_standby_timer(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp)
{
	uchar_t	parm;
	int	timeout = ata_ctlp->ac_standby_time;

	/*
	 * take the timeout value, specificed in seconds, and
	 * encode it into the proper command parm
	 */

	/*
	 * don't change it if no property specified or if
	 * the specified value is out of range
	 */
	if (timeout < 0 || timeout > (12 * 60 * 60))
		return;

	/* 1 to 1200 seconds (20 minutes) == N * 5 seconds */
	if (timeout <= (240 * 5))
		parm = (timeout + 4) / 5;

	/* 20 to 21 minutes == 21 minutes */
	else if (timeout <= (21 * 60))
		parm = 252;

	/* 21 minutes to 21 minutes 15 seconds == 21:15 */
	else if (timeout <= ((21 * 60) + 15))
		parm = 255;

	/* 21:15 to 330 minutes == N * 30 minutes */
	else if (timeout <= (11 * 30 * 60))
		parm = 240 + ((timeout + (30 * 60) - 1)/ (30 * 60));

	/* > 330 minutes == 8 to 12 hours */
	else
		parm = 253;

	(void) ata_command(ata_ctlp, ata_drvp, TRUE, FALSE, 5 * 1000000,
	    ATC_IDLE, 0, parm, 0, 0, 0, 0);
}



/*
 *
 * destroy an ata disk drive
 *
 */

void
ata_disk_uninit_drive(
	ata_drv_t *ata_drvp)
{
	struct scsi_device *devp = ata_drvp->ad_device;

	ADBG_TRACE(("ata_disk_uninit_drive entered\n"));

	if (devp) {
		if (ata_drvp->ad_flags & AD_MUTEX_INIT)
			mutex_destroy(&devp->sd_mutex);
		ata_drvp->ad_device = NULL;
		kmem_free(devp, scsi_device_size());
	}
}




/*
 *
 * DADA compliant bus_ctl entry point
 *
 */

/*ARGSUSED*/
int
ata_disk_bus_ctl(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o,
    void *a, void *v)
{
	ADBG_TRACE(("ata_disk_bus_ctl entered\n"));

	switch (o) {

	case DDI_CTLOPS_REPORTDEV:
	{
		int	targ;

		targ = ddi_prop_get_int(DDI_DEV_T_ANY, r, DDI_PROP_DONTPASS,
		    "target", 0);
		cmn_err(CE_CONT, "?%s%d at %s%d target %d lun %d\n",
		    ddi_driver_name(r), ddi_get_instance(r),
		    ddi_driver_name(d), ddi_get_instance(d), targ, 0);
		return (DDI_SUCCESS);
	}
	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t	*cdip = (dev_info_t *)a;
		ata_drv_t	*ata_drvp;
		ata_ctl_t	*ata_ctlp;
		ata_tgt_t	*ata_tgtp;
		struct scsi_device *devp;
		struct ctl_obj	*ctlobjp;
		gtgt_t		*gtgtp;
		char		 name[MAXNAMELEN];

		/*
		 * save time by picking up ptr to drive struct left
		 * by ata_bus_ctl - isn't that convenient.
		 */
		ata_drvp = ddi_get_driver_private(cdip);
		ata_ctlp = ata_drvp->ad_ctlp;

		/* set up pointers to child dip */

		devp = ata_drvp->ad_device;
		/*
		 * If sd_dev is set, it means that the target has already
		 * being initialized. The cdip is a duplicate node from
		 * reexpansion of driver.conf. Fail INITCHILD here.
		 */
		if ((devp == NULL) || (devp->sd_dev != NULL)) {
			return (DDI_FAILURE);
		}
		devp->sd_dev = cdip;

		ctlobjp = &ata_drvp->ad_ctl_obj;
		ctlobjp->c_extblk.c_devdip = cdip;

		/*
		 * Create the "ata" property for use by the target driver
		 */
		if (!ata_prop_create(cdip, ata_drvp, "ata")) {
			return (DDI_FAILURE);
		}

		gtgtp = ghd_target_init(d, cdip, &ata_ctlp->ac_ccc,
		    sizeof (ata_tgt_t), ata_ctlp,
		    ata_drvp->ad_targ, ata_drvp->ad_lun);

		/* gt_tgt_private points to ata_tgt_t */
		ata_tgtp = GTGTP2ATATGTP(gtgtp);
		ata_tgtp->at_drvp = ata_drvp;
		ata_tgtp->at_dma_attr = ata_pciide_dma_attr;
		ata_tgtp->at_dma_attr.dma_attr_maxxfer =
		    ata_ctlp->ac_max_transfer << SCTRSHFT;

		/* gtgtp is the opaque arg to all my entry points */
		ctlobjp->c_data = gtgtp;

		/* create device name */

		(void) sprintf(name, "%x,%x", ata_drvp->ad_targ,
		    ata_drvp->ad_lun);
		ddi_set_name_addr(cdip, name);
		ddi_set_driver_private(cdip, devp);

		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *cdip = (dev_info_t *)a;
		struct	scsi_device *devp;
		struct	ctl_obj *ctlobjp;
		gtgt_t	*gtgtp;

		devp = ddi_get_driver_private(cdip);
		ctlobjp = (struct ctl_obj *)devp->sd_address.a_hba_tran;
		gtgtp = ctlobjp->c_data;

		ghd_target_free(d, cdip, &GTGTP2ATAP(gtgtp)->ac_ccc, gtgtp);

		ddi_set_driver_private(cdip, NULL);
		ddi_set_name_addr(cdip, NULL);
		return (DDI_SUCCESS);
	}

	default:
		return (DDI_FAILURE);
	}
}


/*
 *
 * DADA abort entry point - not currently used by dadk
 *
 */

/* ARGSUSED */
static int
ata_disk_abort(opaque_t ctl_data, cmpkt_t *pktp)
{
	ADBG_TRACE(("ata_disk_abort entered\n"));

	/* XXX - Note that this interface is currently not used by dadk */

	/*
	 *  GHD abort functions take a pointer to a scsi_address
	 *  and so they're unusable here.  The ata driver used to
	 *  return DDI_SUCCESS here without doing anything.  Its
	 *  seems that DDI_FAILURE is more appropriate.
	 */

	return (DDI_FAILURE);
}



/*
 *
 * DADA reset entry point - not currently used by dadk
 * (except in debug versions of driver)
 *
 */

/* ARGSUSED */
static int
ata_disk_reset(opaque_t ctl_data, int level)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_drv_t	*ata_drvp = GTGTP2ATADRVP(gtgtp);
	int		rc;

	ADBG_TRACE(("ata_disk_reset entered\n"));

	/* XXX - Note that this interface is currently not used by dadk */

	switch (level) {
	case RESET_TARGET:
		rc = ghd_tran_reset_target(&ata_drvp->ad_ctlp->ac_ccc, gtgtp,
		    NULL);
		break;
	case RESET_ALL:
		rc = ghd_tran_reset_bus(&ata_drvp->ad_ctlp->ac_ccc, gtgtp,
		    NULL);
		break;
	default:
		rc = 0;
	}

	return (rc ? DDI_SUCCESS : DDI_FAILURE);
}



/*
 *
 * DADA ioctl entry point
 *
 */

/* ARGSUSED */
static int
ata_disk_ioctl(opaque_t ctl_data, int cmd, intptr_t arg, int flag)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_ctl_t	*ata_ctlp = GTGTP2ATAP(gtgtp);
	ata_drv_t	*ata_drvp = GTGTP2ATADRVP(gtgtp);
	int		rc, rc2;
	struct tgdk_geom tgdk;
	int		wce;
	struct ata_id	*aidp = &ata_drvp->ad_id;
	dk_updatefw_t	updatefw;
#ifdef _MULTI_DATAMODEL
	dk_updatefw_32_t updatefw32;
#endif
	dk_disk_id_t	dk_disk_id;
	char		buf[80];
	int		i;


	ADBG_TRACE(("ata_disk_ioctl entered, cmd = %d\n", cmd));

	switch (cmd) {

	case DIOCTL_GETGEOM:
	case DIOCTL_GETPHYGEOM:
		tgdk.g_cyl = ata_drvp->ad_drvrcyl;
		tgdk.g_head = ata_drvp->ad_drvrhd;
		tgdk.g_sec = ata_drvp->ad_drvrsec;
		tgdk.g_acyl = ata_drvp->ad_acyl;
		tgdk.g_secsiz = 512;
		tgdk.g_cap = (diskaddr_t)tgdk.g_cyl * tgdk.g_head * tgdk.g_sec;
		if (ddi_copyout(&tgdk, (caddr_t)arg, sizeof (tgdk), flag))
			return (EFAULT);
		return (0);

	case DCMD_UPDATE_GEOM:
	/*
	 * ??? fix this to issue IDENTIFY DEVICE ???
	 * might not be necessary since I don't know of any ATA/IDE that
	 * can change its geometry. On the other hand, ATAPI devices like the
	 * LS-120 or PD/CD can change their geometry when new media is inserted
	 */
		return (0);

	/* copy the model number into the caller's buffer */
	case DIOCTL_GETMODEL:
		rc = ata_copy_dk_ioc_string(arg, aidp->ai_model,
		    sizeof (aidp->ai_model), flag);
		return (rc);

	/* copy the serial number into the caller's buffer */
	case DIOCTL_GETSERIAL:
		rc = ata_copy_dk_ioc_string(arg, aidp->ai_drvser,
		    sizeof (aidp->ai_drvser), flag);
		return (rc);

	case DIOCTL_GETWCE:
		/*
		 * WCE is only supported in ATAPI-4 or higher, for
		 * lower rev devices, must assume write cache is
		 * enabled.
		 * NOTE: Since there is currently no Solaris mechanism
		 * to change the state of the Write Cache Enable feature,
		 * this code just checks the value of the WCE bit
		 * obtained at device init time.  If a mechanism
		 * is added to the driver to change WCE, this code
		 * must be updated appropriately.
		 */
		wce = (aidp->ai_majorversion == 0xffff) ||
		    ((aidp->ai_majorversion & ATAC_MAJVER_4) == 0) ||
		    (aidp->ai_features85 & ATAC_FEATURES85_WCE) != 0;

		if (ddi_copyout(&wce, (caddr_t)arg, sizeof (wce), flag) != 0)
			return (EFAULT);

		return (0);

	case DCMD_GET_STATE:
		rc = ata_queue_cmd(ata_disk_state, NULL, ata_ctlp, ata_drvp,
		    gtgtp);
		break;

	case DCMD_LOCK:
	case DKIOCLOCK:
		rc = ata_queue_cmd(ata_disk_lock, NULL, ata_ctlp, ata_drvp,
		    gtgtp);
		break;

	case DCMD_UNLOCK:
	case DKIOCUNLOCK:
		rc = ata_queue_cmd(ata_disk_unlock, NULL, ata_ctlp, ata_drvp,
		    gtgtp);
		break;

	case DCMD_START_MOTOR:
	case CDROMSTART:
		rc = ata_queue_cmd(ata_disk_recalibrate, NULL, ata_ctlp,
		    ata_drvp, gtgtp);
		break;

	case DCMD_STOP_MOTOR:
	case CDROMSTOP:
		rc = ata_queue_cmd(ata_disk_standby, NULL, ata_ctlp, ata_drvp,
		    gtgtp);
		break;

	case DKIOCEJECT:
	case CDROMEJECT:
		rc = ata_queue_cmd(ata_disk_eject, NULL, ata_ctlp, ata_drvp,
		    gtgtp);
		break;

	case DKIOC_UPDATEFW:

		/*
		 * Call DOWNLOAD MICROCODE command to update device
		 * firmware.
		 *
		 * return value:
		 *   normal	0	Download microcode success
		 *   error	EFAULT	Bad address
		 *		ENXIO	No such device or address
		 *		EINVAL	Invalid argument
		 *		ENOMEM	Not enough core
		 *		ENOTSUP	Operation not supported
		 *		EIO	I/O error
		 *		EPERM	Not owner
		 */

		/*
		 * The following code deals with handling 32-bit request
		 * in 64-bit kernel.
		 */
#ifdef _MULTI_DATAMODEL
		if (ddi_model_convert_from(flag & FMODELS) ==
		    DDI_MODEL_ILP32) {
			if (ddi_copyin((void *)arg, &updatefw32,
			    sizeof (dk_updatefw_32_t), flag))
				return (EFAULT);

			updatefw.dku_ptrbuf =
			    (caddr_t)(uintptr_t)updatefw32.dku_ptrbuf;
			updatefw.dku_size = updatefw32.dku_size;
			updatefw.dku_type = updatefw32.dku_type;
		} else {
			if (ddi_copyin((void *)arg, &updatefw,
			    sizeof (dk_updatefw_t), flag))
				return (EFAULT);
		}
#else
		if (ddi_copyin((void *)arg, &updatefw,
		    sizeof (dk_updatefw_t), flag))
			return (EFAULT);
#endif
		rc = ata_disk_update_fw(gtgtp, ata_ctlp, ata_drvp,
		    updatefw.dku_ptrbuf, updatefw.dku_size,
		    updatefw.dku_type, flag);

		/*
		 * According to ATA8-ACS spec, the new microcode should
		 * become effective immediately after the transfer of the
		 * last data segment has completed, so here we will call
		 * IDENTIFY DEVICE command immediately to update
		 * ata_id content when success.
		 */
		if (rc == 0) {
			rc2 = ata_queue_cmd(ata_disk_id_update, NULL,
			    ata_ctlp, ata_drvp, gtgtp);
			if (rc2 != TRUE) {
				return (ENXIO);
			} else {
				/*
				 * Check whether the content of the IDENTIFY
				 * DEVICE data is incomplete, if yes, it's
				 * because the device supports the Power-up
				 * in Standby feature set, and we will first
				 * check word 2, and then decide whether need
				 * to call set feature to spin-up the device,
				 * and then call IDENTIFY DEVICE command again.
				 */
				aidp = &ata_drvp->ad_id;
				if (aidp->ai_config & ATA_ID_INCMPT) {
					if (aidp->ai_resv0 == 0x37c8 ||
					    aidp->ai_resv0 == 0x738c) {
						/* Spin-up the device */
						(void) ata_queue_cmd(
						    ata_disk_set_feature_spinup,
						    NULL,
						    ata_ctlp,
						    ata_drvp,
						    gtgtp);
					}

					/* Try to update ata_id again */
					rc2 = ata_queue_cmd(
					    ata_disk_id_update,
					    NULL,
					    ata_ctlp,
					    ata_drvp,
					    gtgtp);
					if (rc2 != TRUE) {
						return (ENXIO);
					} else {
						aidp = &ata_drvp->ad_id;
						if (aidp->ai_config &
						    ATA_ID_INCMPT)
							return (ENXIO);
					}
				}

				/*
				 * Dump the drive information.
				 */
				ATAPRT(("?\tUpdate firmware of %s device at "
				    "targ %d, lun %d lastlun 0x%x\n",
				    (ATAPIDRV(ata_drvp) ? "ATAPI":"IDE"),
				    ata_drvp->ad_targ, ata_drvp->ad_lun,
				    aidp->ai_lastlun));

				(void) strncpy(buf, aidp->ai_model,
				    sizeof (aidp->ai_model));
				buf[sizeof (aidp->ai_model)] = '\0';
				for (i = sizeof (aidp->ai_model) - 1;
				    buf[i] == ' '; i--)
					buf[i] = '\0';
				ATAPRT(("?\tmodel %s\n", buf));

				(void) strncpy(buf, aidp->ai_fw,
				    sizeof (aidp->ai_fw));
				buf[sizeof (aidp->ai_fw)] = '\0';
				for (i = sizeof (aidp->ai_fw) - 1;
				    buf[i] == ' '; i--)
					buf[i] = '\0';
				ATAPRT(("?\tfw %s\n", buf));
			}
		}
		return (rc);

	case DKIOC_GETDISKID:
		bzero(&dk_disk_id, sizeof (dk_disk_id_t));

		dk_disk_id.dkd_dtype = DKD_ATA_TYPE;

		/* Get the model number */
		(void) strncpy(dk_disk_id.disk_id.ata_disk_id.dkd_amodel,
		    aidp->ai_model, sizeof (aidp->ai_model));

		/* Get the firmware revision */
		(void) strncpy(dk_disk_id.disk_id.ata_disk_id.dkd_afwver,
		    aidp->ai_fw, sizeof (aidp->ai_fw));

		/* Get the serial number */
		(void) strncpy(dk_disk_id.disk_id.ata_disk_id.dkd_aserial,
		    aidp->ai_drvser, sizeof (aidp->ai_drvser));

		if (ddi_copyout(&dk_disk_id, (void *)arg,
		    sizeof (dk_disk_id_t), flag))
			return (EFAULT);
		else
			return (0);

	default:
		ADBG_WARN(("ata_disk_ioctl: unsupported cmd 0x%x\n", cmd));
		return (ENOTTY);
	}

	if (rc)
		return (0);
	return (ENXIO);

}


#ifdef ___not___used___
/*
 * Issue an ATA command to the drive using the packet already
 * allocated by the target driver
 */

int
ata_disk_do_ioctl(int (*func)(ata_ctl_t *, ata_drv_t *, ata_pkt_t *),
    void *arg, ata_ctl_t *ata_ctlp, gtgt_t *gtgtp, cmpkt_t *pktp)
{
	gcmd_t	  *gcmdp = CPKT2GCMD(pktp);
	ata_pkt_t *ata_pktp = GCMD2APKT(gcmdp);
	int	   rc;

	ata_pktp->ap_start = func;
	ata_pktp->ap_intr = NULL;
	ata_pktp->ap_complete = NULL;
	ata_pktp->ap_v_addr = (caddr_t)arg;

	/*
	 * add it to the queue, when it gets to the front the
	 * ap_start function is called.
	 */
	rc = ghd_transport(&ata_ctlp->ac_ccc, gcmdp, gcmdp->cmd_gtgtp,
	    0, TRUE, NULL);

	if (rc != TRAN_ACCEPT) {
		/* this should never, ever happen */
		return (ENXIO);
	}

	if (ata_pktp->ap_flags & AP_ERROR)
		return (ENXIO);
	return (0);
}
#endif



/*
 *
 * DADA pktalloc entry point
 *
 */

/* ARGSUSED */
static cmpkt_t *
ata_disk_pktalloc(opaque_t ctl_data, int (*callback)(caddr_t), caddr_t arg)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_drv_t	*ata_drvp = GTGTP2ATADRVP(gtgtp);
	cmpkt_t		*pktp;
	ata_pkt_t	*ata_pktp;
	gcmd_t		*gcmdp;

	ADBG_TRACE(("ata_disk_pktalloc entered\n"));

	/*
	 * Allocate and  init the GHD gcmd_t structure and the
	 * DADA cmpkt and the ata_pkt
	 */
	if ((gcmdp = ghd_gcmd_alloc(gtgtp,
	    (sizeof (cmpkt_t) + sizeof (ata_pkt_t)),
	    (callback == DDI_DMA_SLEEP))) == NULL) {
		return ((cmpkt_t *)NULL);
	}
	ASSERT(gcmdp != NULL);

	ata_pktp = GCMD2APKT(gcmdp);
	ASSERT(ata_pktp != NULL);

	pktp = (cmpkt_t *)(ata_pktp + 1);

	pktp->cp_ctl_private = (void *)gcmdp;
	ata_pktp->ap_gcmdp = gcmdp;
	gcmdp->cmd_pktp = (void *)pktp;

	/*
	 * At this point the structures are linked like this:
	 *
	 *	(struct cmpkt) <--> (struct gcmd) <--> (struct ata_pkt)
	 */

	/* callback functions */

	ata_pktp->ap_start = ata_disk_start;
	ata_pktp->ap_intr = ata_disk_intr;
	ata_pktp->ap_complete = ata_disk_complete;

	/* other ata_pkt setup */

	ata_pktp->ap_bytes_per_block = ata_drvp->ad_bytes_per_block;

	/* cmpkt setup */

	pktp->cp_cdblen = 1;
	pktp->cp_cdbp   = (opaque_t)&ata_pktp->ap_cdb;
	pktp->cp_scbp   = (opaque_t)&ata_pktp->ap_scb;
	pktp->cp_scblen = 1;

	return (pktp);
}



/*
 *
 * DADA pktfree entry point
 *
 */

/* ARGSUSED */
static void
ata_disk_pktfree(opaque_t ctl_data, cmpkt_t *pktp)
{
	ata_pkt_t *ata_pktp = CPKT2APKT(pktp);

	ADBG_TRACE(("ata_disk_pktfree entered\n"));

	/* check not free already */

	ASSERT(!(ata_pktp->ap_flags & AP_FREE));
	ata_pktp->ap_flags = AP_FREE;

	ghd_gcmd_free(CPKT2GCMD(pktp));
}


/*
 *
 * DADA memsetup entry point
 *
 */

/* ARGSUSED */
static cmpkt_t *
ata_disk_memsetup(
	opaque_t ctl_data,
	cmpkt_t *pktp,
	struct buf *bp,
	int (*callback)(caddr_t),
	caddr_t arg)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_pkt_t	*ata_pktp = CPKT2APKT(pktp);
	gcmd_t		*gcmdp = APKT2GCMD(ata_pktp);
	int		flags;

	ADBG_TRACE(("ata_disk_memsetup entered\n"));

	ata_pktp->ap_sg_cnt = 0;

	if (bp->b_bcount == 0) {
		ata_pktp->ap_v_addr = NULL;
		return (pktp);
	}

	if (GTGTP2ATADRVP(gtgtp)->ad_pciide_dma != ATA_DMA_ON)
		goto skip_dma_setup;

	if (ata_dma_disabled)
		goto skip_dma_setup;

	/*
	 * The PCI-IDE DMA engine is brain-damaged and can't
	 * DMA non-aligned buffers.
	 */
	if (!(bp->b_flags & B_PAGEIO) &&
	    ((uintptr_t)bp->b_un.b_addr) & PCIIDE_PRDE_ADDR_MASK) {
		goto skip_dma_setup;
	}

	/*
	 * It also insists that the byte count must be even.
	 */
	if (bp->b_bcount & 1)
		goto skip_dma_setup;

	/* check direction for data transfer */
	if (bp->b_flags & B_READ) {
		flags = DDI_DMA_READ | DDI_DMA_PARTIAL;
	} else {
		flags = DDI_DMA_WRITE | DDI_DMA_PARTIAL;
	}

	/*
	 * Bind the DMA handle to the buf
	 */
	if (ghd_dma_buf_bind_attr(&GTGTP2ATAP(gtgtp)->ac_ccc, gcmdp, bp, flags,
	    callback, arg, &GTGTP2ATATGTP(gtgtp)->at_dma_attr)) {
		ata_pktp->ap_v_addr = 0;
		return (pktp);
	}

skip_dma_setup:
	bp_mapin(bp);
	ata_pktp->ap_v_addr = bp->b_un.b_addr;
	return (pktp);
}



/*
 *
 * DADA memfree entry point
 *
 */

/*
 * 1157317 sez that drivers shouldn't call bp_mapout(), as either
 * biodone() or biowait() will end up doing it, but after they
 * call bp->b_iodone(), which is a necessary sequence for
 * Online Disk Suite.  However, the DDI group wants to rethink
 * bp_mapin()/bp_mapout() and how they should behave in the
 * presence of layered drivers, etc.  For the moment, fix
 * the OLDS problem by removing the bp_mapout() call.
 */

#define	BUG_1157317

/* ARGSUSED */
static void
ata_disk_memfree(opaque_t ctl_data, cmpkt_t *pktp)
{
	gcmd_t	*gcmdp = CPKT2GCMD(pktp);

	ADBG_TRACE(("ata_disk_memfree entered\n"));

	if (gcmdp->cmd_dma_handle)
		ghd_dmafree_attr(gcmdp);
#if !defined(BUG_1157317)
	else
		bp_mapout(pktp->cp_bp);
#endif
}



/*
 *
 * DADA iosetup entry point
 *
 */

static cmpkt_t *
ata_disk_iosetup(opaque_t ctl_data, cmpkt_t *pktp)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_drv_t	*ata_drvp = GTGTP2ATADRVP(gtgtp);
	ata_pkt_t	*ata_pktp = CPKT2APKT(pktp);
	gcmd_t		*gcmdp = APKT2GCMD(ata_pktp);
	uint_t		sec_count;
	daddr_t		start_sec;
	uint_t		byte_count;

	ADBG_TRACE(("ata_disk_iosetup entered\n"));

	/*
	 * Check for DCMD_FLUSH_CACHE (which does no I/O) and
	 * just do basic setup.
	 */
	if (pktp->cp_passthru == NULL &&
	    ata_pktp->ap_cdb == DCMD_FLUSH_CACHE) {
		ata_pktp->ap_cmd = ATC_FLUSH_CACHE;
		ata_pktp->ap_flags = 0;
		ata_pktp->ap_count = 0;
		ata_pktp->ap_startsec = 0;
		ata_pktp->ap_sg_cnt = 0;
		ata_pktp->ap_pciide_dma = FALSE;
		return (pktp);
	}

	/* check for error retry */
	if (ata_pktp->ap_flags & AP_ERROR) {
		/*
		 * this is a temporary work-around for dadk calling
		 * iosetup for retry. The correct
		 * solution is changing dadk to not to call iosetup
		 * for a retry.
		 * We do not apply the work-around for pio mode since
		 * that does not involve moving dma windows and reducing the
		 * sector count would work for pio mode on a retry
		 * for now.
		 */
		if (gcmdp->cmd_dma_handle != NULL) {
			ata_pktp->ap_flags = 0;
			return (NULL);
		}

		ata_pktp->ap_bytes_per_block = NBPSCTR;
		sec_count = 1;

		/*
		 * Since we are retrying the last read or write operation,
		 * restore the old values of the ap_v_addr and ap_resid.
		 * This assumes CTL_IOSETUP is called again on retry; if not,
		 * this needs to be done in CTL_TRANSPORT.
		 */
		if (ata_pktp->ap_flags & (AP_READ | AP_WRITE)) {
			ata_pktp->ap_v_addr = ata_pktp->ap_v_addr_sav;
			ata_pktp->ap_resid = ata_pktp->ap_resid_sav;
		}
	} else {
		/*
		 * Limit request to ac_max_transfer sectors.
		 * The value is specified by the user in the
		 * max_transfer property. It must be in the range 1 to 256.
		 * When max_transfer is 0x100 it is bigger than 8 bits.
		 * The spec says 0 represents 256 so it should be OK.
		 */
		sec_count = min((pktp->cp_bytexfer >> SCTRSHFT),
		    ata_drvp->ad_ctlp->ac_max_transfer);
		/*
		 * Save the current values of ap_v_addr and ap_resid
		 * in case a retry operation happens. During a retry
		 * operation we need to restore these values.
		 */
		ata_pktp->ap_v_addr_sav = ata_pktp->ap_v_addr;
		ata_pktp->ap_resid_sav = ata_pktp->ap_resid;
	}

	/* reset flags */
	ata_pktp->ap_flags = 0;

#ifdef	DADKIO_RWCMD_READ
	start_sec = pktp->cp_passthru ? RWCMDP(pktp)->blkaddr : pktp->cp_srtsec;
#else
	start_sec = pktp->cp_srtsec;
#endif

	/*
	 * Setup the PCIDE Bus Master Scatter/Gather list
	 */
	ata_pktp->ap_sg_cnt = 0;
	ata_pktp->ap_pciide_dma = FALSE;
	if (gcmdp->cmd_dma_handle != NULL && sec_count != 0) {
		byte_count = sec_count << SCTRSHFT;
		if ((ghd_dmaget_attr(&GTGTP2ATAP(gtgtp)->ac_ccc, gcmdp,
		    byte_count, ATA_DMA_NSEGS, &byte_count) == FALSE) ||
		    (byte_count == 0)) {
			ADBG_ERROR(("ata_disk_iosetup: byte count zero\n"));
			return (NULL);
		}
		sec_count = byte_count >> SCTRSHFT;
	}

	/*
	 * In the non-48-bit mode addressing (CHS and LBA28) the sector
	 * count is a 8-bit value and the sector count 0 represents 256
	 * sectors.
	 * In the extended addressing (LBA48) the sector count is a 16-bit
	 * value, so max_transfer 0x100 cannot be truncated to 8-bits
	 * because this would represent a zero sector count.
	 */
	ata_pktp->ap_count = (ushort_t)sec_count;
	if (!(ata_drvp->ad_flags & AD_EXT48)) {
		ata_pktp->ap_count &= 0xff;
	}
	ata_pktp->ap_startsec = start_sec;

#ifdef	DADKIO_RWCMD_READ
	if (pktp->cp_passthru) {
		switch (RWCMDP(pktp)->cmd) {
		case DADKIO_RWCMD_READ:
			if (ata_pktp->ap_sg_cnt) {
				ata_pktp->ap_cmd = ATC_READ_DMA;
				ata_pktp->ap_pciide_dma = TRUE;
				ata_pktp->ap_start = ata_disk_start_dma_in;
				ata_pktp->ap_intr = ata_disk_intr_dma;
			} else {
				ata_pktp->ap_cmd = ATC_RDSEC;
				ata_pktp->ap_start = ata_disk_start_pio_in;
				ata_pktp->ap_intr = ata_disk_intr_pio_in;
			}
			ata_pktp->ap_flags |= AP_READ;
			break;
		case DADKIO_RWCMD_WRITE:
			if (ata_pktp->ap_sg_cnt) {
				ata_pktp->ap_cmd = ATC_WRITE_DMA;
				ata_pktp->ap_pciide_dma = TRUE;
				ata_pktp->ap_start = ata_disk_start_dma_out;
				ata_pktp->ap_intr = ata_disk_intr_dma;
			} else {
				ata_pktp->ap_cmd = ATC_WRSEC;
				ata_pktp->ap_start = ata_disk_start_pio_out;
				ata_pktp->ap_intr = ata_disk_intr_pio_out;
			}
			ata_pktp->ap_flags |= AP_WRITE;
			break;
		}

		byte_count = RWCMDP(pktp)->buflen;
		pktp->cp_bytexfer = byte_count;
		pktp->cp_resid = byte_count;
		ata_pktp->ap_resid = byte_count;

		/*
		 * since we're not using READ/WRITE MULTIPLE, we
		 * should set bytes_per_block to one sector
		 * XXX- why wasn't this in the old driver??
		 */
		ata_pktp->ap_bytes_per_block = NBPSCTR;
	} else
#endif
	{
		byte_count = sec_count << SCTRSHFT;
		pktp->cp_bytexfer = byte_count;
		pktp->cp_resid = byte_count;
		ata_pktp->ap_resid = byte_count;

		/* setup the task file registers */

		switch (ata_pktp->ap_cdb) {
		case DCMD_READ:
			if (ata_pktp->ap_sg_cnt) {
				ata_pktp->ap_cmd = ATC_READ_DMA;
				ata_pktp->ap_pciide_dma = TRUE;
				ata_pktp->ap_start = ata_disk_start_dma_in;
				ata_pktp->ap_intr = ata_disk_intr_dma;
			} else {
				ata_pktp->ap_cmd = ata_drvp->ad_rd_cmd;
				ata_pktp->ap_start = ata_disk_start_pio_in;
				ata_pktp->ap_intr = ata_disk_intr_pio_in;
			}
			ata_pktp->ap_flags |= AP_READ;
			break;

		case DCMD_WRITE:
			if (ata_pktp->ap_sg_cnt) {
				ata_pktp->ap_cmd = ATC_WRITE_DMA;
				ata_pktp->ap_pciide_dma = TRUE;
				ata_pktp->ap_start = ata_disk_start_dma_out;
				ata_pktp->ap_intr = ata_disk_intr_dma;
			} else {
				ata_pktp->ap_cmd = ata_drvp->ad_wr_cmd;
				ata_pktp->ap_start = ata_disk_start_pio_out;
				ata_pktp->ap_intr = ata_disk_intr_pio_out;
			}
			ata_pktp->ap_flags |= AP_WRITE;
			break;

		default:
			ADBG_WARN(("ata_disk_iosetup: unknown command 0x%x\n",
			    ata_pktp->ap_cdb));
			pktp = NULL;
			break;
		}
	}

	/* If 48-bit mode is used, convert command to 48-bit mode cmd */
	if (pktp != NULL && ata_drvp->ad_flags & AD_EXT48) {
		switch (ata_pktp->ap_cmd) {
		case ATC_RDSEC:
			ata_pktp->ap_cmd = ATC_RDSEC_EXT;
			break;
		case ATC_WRSEC:
			ata_pktp->ap_cmd = ATC_WRSEC_EXT;
			break;
		case ATC_RDMULT:
			ata_pktp->ap_cmd = ATC_RDMULT_EXT;
			break;
		case ATC_WRMULT:
			ata_pktp->ap_cmd = ATC_WRMULT_EXT;
			break;
		case ATC_READ_DMA:
			ata_pktp->ap_cmd = ATC_RDDMA_EXT;
			break;
		case ATC_WRITE_DMA:
			ata_pktp->ap_cmd = ATC_WRDMA_EXT;
			break;
		}
	}

	return (pktp);
}



/*
 *
 * DADA transport entry point
 *
 */

static int
ata_disk_transport(opaque_t ctl_data, cmpkt_t *pktp)
{
	gtgt_t		*gtgtp = (gtgt_t *)ctl_data;
	ata_drv_t	*ata_drvp = GTGTP2ATADRVP(gtgtp);
	ata_ctl_t	*ata_ctlp = ata_drvp->ad_ctlp;
	ata_pkt_t	*ata_pktp = CPKT2APKT(pktp);
	int		rc;
	int		polled = FALSE;

	ADBG_TRACE(("ata_disk_transport entered\n"));

	/* check for polling pkt */

	if (pktp->cp_flags & CPF_NOINTR) {
		polled = TRUE;
	}

	/* call ghd transport routine */

	rc = ghd_transport(&ata_ctlp->ac_ccc, APKT2GCMD(ata_pktp),
	    gtgtp, pktp->cp_time, polled, NULL);

	/* see if pkt was not accepted */

	if (rc == TRAN_BUSY)
		return (CTL_SEND_BUSY);

	if (rc == TRAN_ACCEPT)
		return (CTL_SEND_SUCCESS);

	return (CTL_SEND_FAILURE);
}


/*
 *
 * routines to load the cylinder/head/sector/count
 * task file registers.
 *
 */
static void
ata_disk_load_regs_lba28(ata_pkt_t *ata_pktp, ata_drv_t *ata_drvp)
{
	ata_ctl_t	*ata_ctlp = ata_drvp->ad_ctlp;
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	uint_t		lba;	/* LBA of first sector */

	lba = ata_pktp->ap_startsec;

	ddi_put8(io_hdl1, ata_ctlp->ac_count, ata_pktp->ap_count);
	ddi_put8(io_hdl1, ata_ctlp->ac_sect, lba);
	lba >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, lba);
	lba >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, lba);
	lba >>= 8;
	/*
	 * dev/head register can use only 4 bits
	 * must also include drive selector.
	 */
	lba = (lba & 0xf) | ata_drvp->ad_drive_bits;
	ddi_put8(io_hdl1,  ata_ctlp->ac_drvhd, lba);
}

/*
 * In 48-bit extended mode, the sector count is 16 bits wide, and the
 * LBA is 48 bits wide, as follows:
 * register	most recent	previous
 * name		value		value
 * --------	----------	---------
 * sector cnt	count(7:0)	count(15:8)
 * sector num	lba(7:0)	lba(31:24)
 * cyl low	lba(15:8)	lba(39:32)
 * cyl hi	lba(23:16)	lba(47:40)
 * device/head	111D0000	N/A
 *               ^ ^
 *               | |
 *               | +-- drive number
 *               |
 *               +-- indicates LBA
 *	The other two 1 bits are historical and are not used in 48bit
 *	extended mode.
 */
/*
 * WARNING:
 * dada framework passes starting sector as daddr_t type, thus
 * limiting reachable disk space in 32-bit x86 architecture to 1 terabyte.
 * Therefore high 16 bits of the 48-bits address can be and
 * are currently ignored.
 */
static void
ata_disk_load_regs_lba48(ata_pkt_t *ata_pktp, ata_drv_t *ata_drvp)
{
	ata_ctl_t	*ata_ctlp = ata_drvp->ad_ctlp;
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	uint16_t	seccnt;		/* 16-bit sector count */
	uint_t		lbalow;		/* low-order 24 bits of LBA */
	uint_t		lbahi;		/* high-order 24 bits of LBA */

	seccnt = ata_pktp->ap_count;
	/* high-order 8 bits of lbalow never get used */
	lbalow = ata_pktp->ap_startsec;
	lbahi = ata_pktp->ap_startsec >> 24;

	ddi_put8(io_hdl1, ata_ctlp->ac_count, seccnt >> 8);
	ddi_put8(io_hdl1, ata_ctlp->ac_count, seccnt);
	/* Send the high-order half first */
	ddi_put8(io_hdl1, ata_ctlp->ac_sect, lbahi);
	lbahi >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, lbahi);
	lbahi >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, lbahi);
	/* Send the low-order half */
	ddi_put8(io_hdl1, ata_ctlp->ac_sect, lbalow);
	lbalow >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, lbalow);
	lbalow >>= 8;
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, lbalow);
	ddi_put8(io_hdl1,  ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits);
}

static void
ata_disk_load_regs_chs(ata_pkt_t *ata_pktp, ata_drv_t *ata_drvp)
{
	ata_ctl_t		*ata_ctlp = ata_drvp->ad_ctlp;
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	uint_t			resid;
	uint_t			cyl;
	uchar_t			head;
	uchar_t			drvheads;
	uchar_t			drvsectors;

	drvheads = ata_drvp->ad_phhd;
	drvsectors = ata_drvp->ad_phsec;

	resid = ata_pktp->ap_startsec / drvsectors;
	head = (resid % drvheads) & 0xf;
	cyl = resid / drvheads;
	/* automatically truncate to char */
	ddi_put8(io_hdl1, ata_ctlp->ac_sect,
	    (ata_pktp->ap_startsec % drvsectors) + 1);
	ddi_put8(io_hdl1, ata_ctlp->ac_count, ata_pktp->ap_count);
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, (cyl >> 8));
	/* lcyl gets truncated to 8 bits */
	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, cyl);
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits | head);
}


/*
 *
 * packet start callback routines
 *
 */

/* ARGSUSED */
static int
ata_disk_start_common(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;

	ADBG_TRACE(("ata_disk_start_common entered\n"));

	ADBG_TRANSPORT(("ata_disk_start:\tpkt = 0x%p, pkt flags = 0x%x\n",
	    ata_pktp, ata_pktp->ap_flags));
	ADBG_TRANSPORT(("\tcommand=0x%x, sect=0x%lx\n",
	    ata_pktp->ap_cmd, ata_pktp->ap_startsec));
	ADBG_TRANSPORT(("\tcount=0x%x, drvhd = 0x%x\n",
	    ata_pktp->ap_count, ata_drvp->ad_drive_bits));

	/*
	 * If AC_BSY_WAIT is set, wait for controller to not be busy,
	 * before issuing a command.  If AC_BSY_WAIT is not set,
	 * skip the wait.  This is important for laptops that do
	 * suspend/resume but do not correctly wait for the busy bit to
	 * drop after a resume.
	 *
	 * NOTE: this test for ATS_BSY is also needed if/when we
	 * implement the overlapped/queued command protocols. Currently,
	 * the overlap/queued feature is not supported so the test is
	 * conditional.
	 */
	if (ata_ctlp->ac_timing_flags & AC_BSY_WAIT) {
		if (!ata_wait(io_hdl2,  ata_ctlp->ac_ioaddr2,
		    0, ATS_BSY, 5000000)) {
			ADBG_ERROR(("ata_disk_start: BUSY\n"));
			return (FALSE);
		}
	}

	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/*
	 * make certain the drive selected
	 */
	if (!ata_wait(io_hdl2,  ata_ctlp->ac_ioaddr2,
	    ATS_DRDY, ATS_BSY, 5 * 1000000)) {
		ADBG_ERROR(("ata_disk_start: select failed\n"));
		return (FALSE);
	}

	if (ata_pktp->ap_cmd == ATC_LOAD_FW) {

		/* the sector count is 16 bits wide */
		ddi_put8(io_hdl1, ata_ctlp->ac_count, ata_pktp->ap_count);
		ddi_put8(io_hdl1, ata_ctlp->ac_sect, ata_pktp->ap_count >> 8);
		ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, ata_pktp->ap_startsec);
		ddi_put8(io_hdl1, ata_ctlp->ac_hcyl,
		    ata_pktp->ap_startsec >> 8);

		/* put subcommand for DOWNLOAD MICROCODE */
		ddi_put8(io_hdl1, ata_ctlp->ac_feature, ata_pktp->ap_bcount);
	} else {

		/*
		 * We use different methods for loading the task file
		 * registers, depending on whether the disk
		 * uses LBA or CHS addressing and whether 48-bit
		 * extended addressing is to be used.
		 */
		if (!(ata_drvp->ad_drive_bits & ATDH_LBA))
			ata_disk_load_regs_chs(ata_pktp, ata_drvp);
		else if (ata_drvp->ad_flags & AD_EXT48)
			ata_disk_load_regs_lba48(ata_pktp, ata_drvp);
		else
			ata_disk_load_regs_lba28(ata_pktp, ata_drvp);
		ddi_put8(io_hdl1, ata_ctlp->ac_feature, 0);
	}

	/*
	 * Always make certain interrupts are enabled. It's been reported
	 * (but not confirmed) that some notebook computers don't
	 * clear the interrupt disable bit after being resumed. The
	 * easiest way to fix this is to always clear the disable bit
	 * before every command.
	 */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, ATDC_D3);
	return (TRUE);
}


/*
 *
 * Start a non-data ATA command (not DMA and not PIO):
 *
 */

static int
ata_disk_start(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 rc;

	rc = ata_disk_start_common(ata_ctlp, ata_drvp, ata_pktp);

	if (!rc)
		return (ATA_FSM_RC_BUSY);

	/*
	 * This next one sets the controller in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	return (ATA_FSM_RC_OKAY);
}



static int
ata_disk_start_dma_in(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 rc;

	rc = ata_disk_start_common(ata_ctlp, ata_drvp, ata_pktp);

	if (!rc)
		return (ATA_FSM_RC_BUSY);

	/*
	 * Copy the Scatter/Gather list to the controller's
	 * Physical Region Descriptor Table
	 */
	ata_pciide_dma_setup(ata_ctlp, ata_pktp->ap_sg_list,
	    ata_pktp->ap_sg_cnt);

	/*
	 * reset the PCIIDE Controller's interrupt and error status bits
	 */
	(void) ata_pciide_status_clear(ata_ctlp);

	/*
	 * This next one sets the drive in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the drive's busy bit to settle */
	ata_nsecwait(400);

	ata_pciide_dma_start(ata_ctlp, PCIIDE_BMICX_RWCON_WRITE_TO_MEMORY);

	return (ATA_FSM_RC_OKAY);
}



static int
ata_disk_start_dma_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 rc;

	rc = ata_disk_start_common(ata_ctlp, ata_drvp, ata_pktp);

	if (!rc)
		return (ATA_FSM_RC_BUSY);

	/*
	 * Copy the Scatter/Gather list to the controller's
	 * Physical Region Descriptor Table
	 */
	ata_pciide_dma_setup(ata_ctlp, ata_pktp->ap_sg_list,
	    ata_pktp->ap_sg_cnt);

	/*
	 * reset the PCIIDE Controller's interrupt and error status bits
	 */
	(void) ata_pciide_status_clear(ata_ctlp);

	/*
	 * This next one sets the drive in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the drive's busy bit to settle */
	ata_nsecwait(400);

	ata_pciide_dma_start(ata_ctlp, PCIIDE_BMICX_RWCON_READ_FROM_MEMORY);

	return (ATA_FSM_RC_OKAY);
}





/*
 *
 * Start a PIO data-in ATA command:
 *
 */

static int
ata_disk_start_pio_in(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 rc;

	rc = ata_disk_start_common(ata_ctlp, ata_drvp, ata_pktp);

	if (!rc)
		return (ATA_FSM_RC_BUSY);
	/*
	 * This next one sets the controller in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	return (ATA_FSM_RC_OKAY);
}




/*
 *
 * Start a PIO data-out ATA command:
 *
 */

static int
ata_disk_start_pio_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	int		 rc;

	ata_pktp->ap_wrt_count = 0;

	rc = ata_disk_start_common(ata_ctlp, ata_drvp, ata_pktp);

	if (!rc)
		return (ATA_FSM_RC_BUSY);
	/*
	 * This next one sets the controller in motion
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, ata_pktp->ap_cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/*
	 * Wait for the drive to assert DRQ to send the first chunk
	 * of data. Have to busy wait because there's no interrupt for
	 * the first chunk. This sucks (a lot of cycles) if the
	 * drive responds too slowly or if the wait loop granularity
	 * is too large. It's really bad if the drive is defective and
	 * the loop times out.
	 */

	if (!ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2,
	    ATS_DRQ, ATS_BSY, /* okay */
	    ATS_ERR, ATS_BSY, /* cmd failed */
	    ATS_DF, ATS_BSY, /* drive failed */
	    4000000)) {
		ADBG_WARN(("ata_disk_start_pio_out: no DRQ\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		return (ATA_FSM_RC_INTR);
	}

	/*
	 * Tell the upper layer to fake a hardware interrupt which
	 * actually causes the first segment to be written to the drive.
	 */
	return (ATA_FSM_RC_INTR);
}



/*
 *
 * packet complete callback routine
 *
 */

static void
ata_disk_complete(ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp, int do_callback)
{
	struct ata_id   *aidp = &ata_drvp->ad_id;
	cmpkt_t	*pktp;

	ADBG_TRACE(("ata_disk_complete entered\n"));
	ADBG_TRANSPORT(("ata_disk_complete: pkt = 0x%p\n", ata_pktp));

	pktp = APKT2CPKT(ata_pktp);

	/* update resid */

	pktp->cp_resid = ata_pktp->ap_resid;

	if (ata_pktp->ap_flags & AP_ERROR) {

		pktp->cp_reason = CPS_CHKERR;

		if (ata_pktp->ap_error & ATE_BBK_ICRC) {
			if (IS_ATA_VERSION_GE(aidp, 4))
				ata_pktp->ap_scb = DERR_ICRC;
			else
				ata_pktp->ap_scb = DERR_BBK;
		} else if (ata_pktp->ap_error & ATE_UNC)
			ata_pktp->ap_scb = DERR_UNC;
		else if (ata_pktp->ap_error & ATE_IDNF)
			ata_pktp->ap_scb = DERR_IDNF;
		else if (ata_pktp->ap_error & ATE_TKONF)
			ata_pktp->ap_scb = DERR_TKONF;
		else if (ata_pktp->ap_error & ATE_AMNF)
			ata_pktp->ap_scb = DERR_AMNF;
		else if (ata_pktp->ap_status & ATS_BSY)
			ata_pktp->ap_scb = DERR_BUSY;
		else if (ata_pktp->ap_status & ATS_DF)
			ata_pktp->ap_scb = DERR_DWF;
		else /* any unknown error	*/
			ata_pktp->ap_scb = DERR_ABORT;
	} else if (ata_pktp->ap_flags & (AP_ABORT|AP_TIMEOUT|AP_BUS_RESET)) {

		pktp->cp_reason = CPS_CHKERR;
		ata_pktp->ap_scb = DERR_ABORT;
	} else {
		pktp->cp_reason = CPS_SUCCESS;
		ata_pktp->ap_scb = DERR_SUCCESS;
	}

	/* callback */
	if (do_callback)
		(*pktp->cp_callback)(pktp);
}


/*
 *
 * Interrupt callbacks
 *
 */


/*
 *
 * ATA command, no data
 *
 */

/* ARGSUSED */
static int
ata_disk_intr(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	uchar_t		 status;

	ADBG_TRACE(("ata_disk_intr entered\n"));
	ADBG_TRANSPORT(("ata_disk_intr: pkt = 0x%p\n", ata_pktp));

	status = ata_get_status_clear_intr(ata_ctlp, ata_pktp);

	ASSERT((status & (ATS_BSY | ATS_DRQ)) == 0);

	/*
	 * check for errors
	 */

	if (status & (ATS_DF | ATS_ERR)) {
		ADBG_WARN(("ata_disk_intr: status 0x%x error 0x%x\n", status,
		    ddi_get8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_error)));
		ata_pktp->ap_flags |= AP_ERROR;
	}

	if (ata_pktp->ap_flags & AP_ERROR) {
		ata_pktp->ap_status = ddi_get8(ata_ctlp->ac_iohandle2,
		    ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(ata_ctlp->ac_iohandle1,
		    ata_ctlp->ac_error);
	}

	/* tell the upper layer this request is complete */
	return (ATA_FSM_RC_FINI);
}


/*
 *
 * ATA command, PIO data in
 *
 */

/* ARGSUSED */
static int
ata_disk_intr_pio_in(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	uchar_t		 status;

	ADBG_TRACE(("ata_disk_pio_in entered\n"));
	ADBG_TRANSPORT(("ata_disk_pio_in: pkt = 0x%p\n", ata_pktp));

	/*
	 * first make certain DRQ is asserted (and no errors)
	 */
	(void) ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2,
	    ATS_DRQ, ATS_BSY, ATS_ERR, ATS_BSY, ATS_DF, ATS_BSY, 4000000);

	status = ata_get_status_clear_intr(ata_ctlp, ata_pktp);

	if (status & ATS_BSY) {
		ADBG_WARN(("ata_disk_pio_in: BUSY\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
		return (ATA_FSM_RC_BUSY);
	}

	/*
	 * record any errors
	 */
	if ((status & (ATS_DRQ | ATS_DF | ATS_ERR)) != ATS_DRQ) {
		ADBG_WARN(("ata_disk_pio_in: status 0x%x error 0x%x\n",
		    status, ddi_get8(io_hdl1, ata_ctlp->ac_error)));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
	}

	/*
	 * read the next chunk of data (if any)
	 */
	if (status & ATS_DRQ) {
		ata_disk_pio_xfer_data_in(ata_ctlp, ata_pktp);
	}

	/*
	 * If that was the last chunk, wait for the device to clear DRQ
	 */
	if (ata_pktp->ap_resid == 0) {
		if (ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2,
		    0, (ATS_DRQ | ATS_BSY), 4000000)) {
			/* tell the upper layer this request is complete */
			return (ATA_FSM_RC_FINI);
		}

		ADBG_WARN(("ata_disk_pio_in: DRQ stuck\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
	}

	/*
	 * check for errors
	 */
	if (ata_pktp->ap_flags & AP_ERROR) {
		return (ATA_FSM_RC_FINI);
	}

	/*
	 * If the read command isn't done yet,
	 * wait for the next interrupt.
	 */
	ADBG_TRACE(("ata_disk_pio_in: partial\n"));
	return (ATA_FSM_RC_OKAY);
}



/*
 *
 * ATA command, PIO data out
 *
 */

/* ARGSUSED */
static int
ata_disk_intr_pio_out(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	int		 tmp_count = ata_pktp->ap_wrt_count;
	uchar_t		 status;

	/*
	 * clear the IRQ
	 */
	status = ata_get_status_clear_intr(ata_ctlp, ata_pktp);

	ADBG_TRACE(("ata_disk_intr_pio_out entered\n"));
	ADBG_TRANSPORT(("ata_disk_intr_pio_out: pkt = 0x%p\n", ata_pktp));

	ASSERT(!(status & ATS_BSY));


	/*
	 * check for errors
	 */

	if (status & (ATS_DF | ATS_ERR)) {
		ADBG_WARN(("ata_disk_intr_pio_out: status 0x%x error 0x%x\n",
		    status, ddi_get8(io_hdl1, ata_ctlp->ac_error)));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
		/* tell the upper layer this request is complete */
		return (ATA_FSM_RC_FINI);
	}


	/*
	 * last write was okay, bump the ptr and
	 * decr the resid count
	 */
	ata_pktp->ap_v_addr += tmp_count;
	ata_pktp->ap_resid -= tmp_count;

	/*
	 * check for final interrupt on write command
	 */
	if (ata_pktp->ap_resid == 0) {
		/* tell the upper layer this request is complete */
		return (ATA_FSM_RC_FINI);
	}

	/*
	 * Perform the next data transfer
	 *
	 * First make certain DRQ is asserted and no error status.
	 * (I'm not certain but I think some drives might deassert BSY
	 * before asserting DRQ. This extra ata_wait3() will
	 * compensate for such drives).
	 *
	 */
	(void) ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2,
	    ATS_DRQ, ATS_BSY, ATS_ERR, ATS_BSY, ATS_DF, ATS_BSY, 4000000);

	status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);

	if (status & ATS_BSY) {
		/* this should never happen */
		ADBG_WARN(("ata_disk_intr_pio_out: BUSY\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
		return (ATA_FSM_RC_BUSY);
	}

	/*
	 * bailout if any errors
	 */
	if ((status & (ATS_DRQ | ATS_DF | ATS_ERR)) != ATS_DRQ) {
		ADBG_WARN(("ata_disk_pio_out: status 0x%x error 0x%x\n",
		    status, ddi_get8(io_hdl1, ata_ctlp->ac_error)));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
		return (ATA_FSM_RC_FINI);
	}

	/*
	 * write  the next chunk of data
	 */
	ADBG_TRACE(("ata_disk_intr_pio_out: write xfer\n"));
	ata_disk_pio_xfer_data_out(ata_ctlp, ata_pktp);

	/*
	 * Wait for the next interrupt before checking the transfer
	 * status and adjusting the transfer count.
	 *
	 */
	return (ATA_FSM_RC_OKAY);
}


/*
 *
 * ATA command, DMA data in/out
 *
 */

static int
ata_disk_intr_dma(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	uchar_t		 status;

	ADBG_TRACE(("ata_disk_intr_dma entered\n"));
	ADBG_TRANSPORT(("ata_disk_intr_dma: pkt = 0x%p\n", ata_pktp));

	/*
	 * halt the DMA engine
	 */
	ata_pciide_dma_stop(ata_ctlp);

	/*
	 * wait for the device to clear DRQ
	 */
	if (!ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2,
	    0, (ATS_DRQ | ATS_BSY), 4000000)) {
		ADBG_WARN(("ata_disk_intr_dma: DRQ stuck\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
		return (ATA_FSM_RC_BUSY);
	}

	/*
	 * get the status and clear the IRQ, and check for DMA error
	 */
	status = ata_get_status_clear_intr(ata_ctlp, ata_pktp);

	/*
	 * check for drive errors
	 */

	if (status & (ATS_DF | ATS_ERR)) {
		ADBG_WARN(("ata_disk_intr_dma: status 0x%x error 0x%x\n",
		    status, ddi_get8(io_hdl1, ata_ctlp->ac_error)));
		ata_pktp->ap_flags |= AP_ERROR;
		ata_pktp->ap_status = ddi_get8(io_hdl2, ata_ctlp->ac_altstatus);
		ata_pktp->ap_error = ddi_get8(io_hdl1, ata_ctlp->ac_error);
	}

	/*
	 * If there was a drive or DMA error, compute a resid count
	 */
	if (ata_pktp->ap_flags & AP_ERROR) {
		/*
		 * grab the last sector address from the drive regs
		 * and use that to compute the resid
		 */
		ata_disk_get_resid(ata_ctlp, ata_drvp, ata_pktp);
	} else {
		ata_pktp->ap_resid = 0;
	}

	/* tell the upper layer this request is complete */
	return (ATA_FSM_RC_FINI);
}


/*
 *
 * Low level PIO routine that transfers data from the drive
 *
 */

static void
ata_disk_pio_xfer_data_in(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 count;

	count = min(ata_pktp->ap_resid, ata_pktp->ap_bytes_per_block);

	ADBG_TRANSPORT(("ata_disk_pio_xfer_data_in: 0x%x bytes, addr = 0x%p\n",
	    count, ata_pktp->ap_v_addr));

	/*
	 * read count bytes
	 */

	ASSERT(count != 0);

	ddi_rep_get16(io_hdl1, (ushort_t *)ata_pktp->ap_v_addr,
	    ata_ctlp->ac_data, (count >> 1), DDI_DEV_NO_AUTOINCR);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/*
	 * this read command completed okay, bump the ptr and
	 * decr the resid count now.
	 */
	ata_pktp->ap_v_addr += count;
	ata_pktp->ap_resid -= count;
}


/*
 *
 * Low level PIO routine that transfers data to the drive
 *
 */

static void
ata_disk_pio_xfer_data_out(ata_ctl_t *ata_ctlp, ata_pkt_t *ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	int		 count;

	count = min(ata_pktp->ap_resid, ata_pktp->ap_bytes_per_block);

	ADBG_TRANSPORT(("ata_disk_pio_xfer_data_out: 0x%x bytes, addr = 0x%p\n",
	    count, ata_pktp->ap_v_addr));

	/*
	 * read or write count bytes
	 */

	ASSERT(count != 0);

	ddi_rep_put16(io_hdl1, (ushort_t *)ata_pktp->ap_v_addr,
	    ata_ctlp->ac_data, (count >> 1), DDI_DEV_NO_AUTOINCR);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/*
	 * save the count here so I can correctly adjust
	 * the ap_v_addr and ap_resid values at the next
	 * interrupt.
	 */
	ata_pktp->ap_wrt_count = count;
}


/*
 *
 * ATA Initialize Device Parameters (aka Set Params) command
 *
 * If the drive was put in some sort of CHS extended/logical geometry
 * mode by the BIOS, this function will reset it to its "native"
 * CHS geometry. This ensures that we don't run into any sort of
 * 1024 cylinder (or 65535 cylinder) limitation that may have been
 * created by a BIOS (or users) that chooses a bogus translated geometry.
 */

static int
ata_disk_initialize_device_parameters(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp)
{
	int		 rc;

	rc = ata_command(ata_ctlp, ata_drvp, FALSE, FALSE,
	    ata_disk_init_dev_parm_wait,
	    ATC_SETPARAM,
	    0,			/* feature n/a */
	    ata_drvp->ad_phsec,	/* max sector (1-based) */
	    0,			/* sector n/a */
	    (ata_drvp->ad_phhd -1),	/* max head (0-based) */
	    0,			/* cyl_low n/a */
	    0);			/* cyl_hi n/a */

	if (rc)
		return (TRUE);

	ADBG_ERROR(("ata_init_dev_parms: failed\n"));
	return (FALSE);
}



/*
 *
 * create fake inquiry data for DADA interface
 *
 */

static void
ata_disk_fake_inquiry(ata_drv_t *ata_drvp)
{
	struct ata_id *ata_idp = &ata_drvp->ad_id;
	struct scsi_inquiry *inqp = &ata_drvp->ad_inquiry;

	ADBG_TRACE(("ata_disk_fake_inquiry entered\n"));

	if (ata_idp->ai_config & ATA_ID_REM_DRV) /* ide removable bit */
		inqp->inq_rmb = 1;		/* scsi removable bit */

	(void) strncpy(inqp->inq_vid, "Gen-ATA ", sizeof (inqp->inq_vid));
	inqp->inq_dtype = DTYPE_DIRECT;
	inqp->inq_qual = DPQ_POSSIBLE;

	(void) strncpy(inqp->inq_pid, ata_idp->ai_model,
	    sizeof (inqp->inq_pid));
	(void) strncpy(inqp->inq_revision, ata_idp->ai_fw,
	    sizeof (inqp->inq_revision));
}

#define	LOOP_COUNT	10000


/*
 *
 * ATA Set Multiple Mode
 *
 */

static int
ata_disk_set_multiple(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp)
{
	int		 rc;

	rc = ata_command(ata_ctlp, ata_drvp, TRUE, FALSE,
	    ata_disk_set_mult_wait,
	    ATC_SETMULT,
	    0,			/* feature n/a */
	    ata_drvp->ad_block_factor, /* count */
	    0,			/* sector n/a */
	    0,			/* head n/a */
	    0,			/* cyl_low n/a */
	    0);			/* cyl_hi n/a */

	if (rc) {
		return (TRUE);
	}

	ADBG_ERROR(("ata_disk_set_multiple: failed\n"));
	return (FALSE);
}


/*
 *
 * ATA Identify Device command
 *
 */

int
ata_disk_id(ddi_acc_handle_t io_hdl1, caddr_t ioaddr1, ddi_acc_handle_t io_hdl2,
    caddr_t ioaddr2, struct ata_id *ata_idp)
{
	int	rc;

	ADBG_TRACE(("ata_disk_id entered\n"));

	rc = ata_id_common(ATC_ID_DEVICE, TRUE, io_hdl1, ioaddr1, io_hdl2,
	    ioaddr2, ata_idp);

	if (!rc)
		return (FALSE);

	/*
	 * If the disk is a CF/Microdrive that works under ATA mode
	 * through CF<->ATA adapters, identify it as an ATA device
	 * and a non removable media.
	 */
	if (ata_idp->ai_config == ATA_ID_COMPACT_FLASH) {
		ata_idp->ai_config = ATA_ID_CF_TO_ATA;
	}

	if ((ata_idp->ai_config & ATAC_ATA_TYPE_MASK) != ATAC_ATA_TYPE)
		return (FALSE);

	if (ata_idp->ai_heads == 0 || ata_idp->ai_sectors == 0) {
		return (FALSE);
	}

	return (TRUE);
}

static daddr_t
ata_last_block_xferred_chs(ata_drv_t *ata_drvp)
{
	ata_ctl_t	*ata_ctlp = ata_drvp->ad_ctlp;
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	uchar_t		 drvheads = ata_drvp->ad_phhd;
	uchar_t		 drvsectors = ata_drvp->ad_phsec;
	uchar_t		 sector;
	uchar_t		 head;
	uchar_t		 low_cyl;
	uchar_t		 hi_cyl;
	daddr_t		 lbastop;

	sector = ddi_get8(io_hdl1, ata_ctlp->ac_sect);
	head = ddi_get8(io_hdl1, ata_ctlp->ac_drvhd) & 0xf;
	low_cyl = ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);
	hi_cyl = ddi_get8(io_hdl1, ata_ctlp->ac_hcyl);

	lbastop = low_cyl;
	lbastop |= (uint_t)hi_cyl << 8;
	lbastop *= (uint_t)drvheads;
	lbastop += (uint_t)head;
	lbastop *= (uint_t)drvsectors;
	lbastop += (uint_t)sector - 1;
	return (lbastop);
}

static daddr_t
ata_last_block_xferred_lba28(ata_ctl_t *ata_ctlp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	daddr_t		lbastop;

	lbastop = ddi_get8(io_hdl1, ata_ctlp->ac_drvhd) & 0xf;
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_hcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_sect);
	return (lbastop);
}

static daddr_t
ata_last_block_xferred_lba48(ata_ctl_t *ata_ctlp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	daddr_t		lbastop;

	/* turn on HOB and read the high-order 24 bits */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, (ATDC_D3 | ATDC_HOB));
	lbastop = ddi_get8(io_hdl1, ata_ctlp->ac_hcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_sect);
	lbastop <<= 8;

	/* Turn off HOB and read the low-order 24-bits */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, (ATDC_D3));
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_hcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_lcyl);
	lbastop <<= 8;
	lbastop += ddi_get8(io_hdl1, ata_ctlp->ac_sect);
	return (lbastop);
}


/*
 *
 * Need to compute a value for ap_resid so that cp_resid can
 * be set by ata_disk_complete(). The cp_resid var is actually
 * misnamed. It's actually the offset to the block in which the
 * error occurred not the number of bytes transferred to the device.
 * At least that's how dadk actually uses the cp_resid when reporting
 * an error. In other words the sector that had the error and the
 * number of bytes transferred don't always indicate the same offset.
 * On top of that, when doing DMA transfers there's actually no
 * way to determine how many bytes have been transferred by the DMA
 * engine. On the other hand, the drive will report which sector
 * it faulted on. Using that address this routine computes the
 * number of residual bytes beyond that point which probably weren't
 * written to the drive (the drive is allowed to re-order sector
 * writes but on an ATA disk there's no way to deal with that
 * complication; in other words, the resid value calculated by
 * this routine is as good as we can manage).
 */

static void
ata_disk_get_resid(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	uint_t		 lba_start;
	uint_t		 lba_stop;
	uint_t		 resid_bytes;
	uint_t		 resid_sectors;

	lba_start = ata_pktp->ap_startsec;

	if (ata_drvp->ad_flags & AD_EXT48)
		lba_stop = ata_last_block_xferred_lba48(ata_ctlp);
	else if (ata_drvp->ad_drive_bits & ATDH_LBA)
		lba_stop = ata_last_block_xferred_lba28(ata_ctlp);
	else /* CHS mode */
		lba_stop = ata_last_block_xferred_chs(ata_drvp);

	resid_sectors = lba_start + ata_pktp->ap_count - lba_stop;
	resid_bytes = resid_sectors << SCTRSHFT;

	ADBG_TRACE(("ata_disk_get_resid start 0x%x cnt 0x%x stop 0x%x\n",
	    lba_start, ata_pktp->ap_count, lba_stop));
	ata_pktp->ap_resid = resid_bytes;
}



/*
 * Removable media commands *
 */



/*
 * get the media status
 *
 * NOTE: the error handling case probably isn't correct but it
 * will have to do until someone gives me a drive to test this on.
 */
static int
ata_disk_state(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	int	*statep = (int *)ata_pktp->ap_v_addr;
	uchar_t	 err;

	ADBG_TRACE(("ata_disk_state\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 5 * 1000000,
	    ATC_DOOR_LOCK, 0, 0, 0, 0, 0, 0)) {
		*statep = DKIO_INSERTED;
		return (ATA_FSM_RC_FINI);
	}

	err = ddi_get8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_error);
	if (err & ATE_NM)
		*statep = DKIO_EJECTED;
	else
		*statep = DKIO_NONE;

	return (ATA_FSM_RC_FINI);
}

/*
 * eject the media
 */

static int
ata_disk_eject(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ADBG_TRACE(("ata_disk_eject\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 5 * 1000000,
	    ATC_EJECT, 0, 0, 0, 0, 0, 0)) {
		return (ATA_FSM_RC_FINI);
	}
	ata_pktp->ap_flags |= AP_ERROR;
	return (ATA_FSM_RC_FINI);
}

/*
 * lock the drive
 *
 */
static int
ata_disk_lock(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ADBG_TRACE(("ata_disk_lock\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 5 * 1000000,
	    ATC_DOOR_LOCK, 0, 0, 0, 0, 0, 0)) {
		return (ATA_FSM_RC_FINI);
	}
	ata_pktp->ap_flags |= AP_ERROR;
	return (ATA_FSM_RC_FINI);
}


/*
 * unlock the drive
 *
 */
static int
ata_disk_unlock(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ADBG_TRACE(("ata_disk_unlock\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 5 * 1000000,
	    ATC_DOOR_UNLOCK, 0, 0, 0, 0, 0, 0)) {
		return (ATA_FSM_RC_FINI);
	}
	ata_pktp->ap_flags |= AP_ERROR;
	return (ATA_FSM_RC_FINI);
}


/*
 * put the drive into standby mode
 */
static int
ata_disk_standby(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ADBG_TRACE(("ata_disk_standby\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 5 * 1000000,
	    ATC_STANDBY_IM, 0, 0, 0, 0, 0, 0)) {
		return (ATA_FSM_RC_FINI);
	}
	ata_pktp->ap_flags |= AP_ERROR;
	return (ATA_FSM_RC_FINI);
}


/*
 * Recalibrate
 *
 * Note the extra long timeout value. This is necessary in case
 * the drive was in standby mode and needs to spin up the media.
 *
 */
static int
ata_disk_recalibrate(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
    ata_pkt_t *ata_pktp)
{
	ADBG_TRACE(("ata_disk_recalibrate\n"));
	if (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, 31 * 1000000,
	    ATC_RECAL, 0, 0, 0, 0, 0, 0)) {
		return (ATA_FSM_RC_FINI);
	}
	ata_pktp->ap_flags |= AP_ERROR;
	return (ATA_FSM_RC_FINI);
}

/*
 * Copy a string of bytes that were obtained by Identify Device into a
 * string buffer provided by the caller.
 *
 * 1. Determine the amount to copy.  This is the lesser of the
 *    length of the source string or the space available in the user's
 *    buffer.
 * 2. The true length of the source string is always returned to the
 *    caller in the size field of the argument.
 * 3. Copy the string, add a terminating NUL character at the end.
 */

static int
ata_copy_dk_ioc_string(intptr_t arg, char *source, int length, int flag)
{
	STRUCT_DECL(dadk_ioc_string, ds_arg);
	int			destsize;
	char			nulchar;
	caddr_t			outp;

	/*
	 * The ioctls that use this routine are only available to
	 * the kernel.
	 */
	if ((flag & FKIOCTL) == 0)
		return (EFAULT);

	STRUCT_INIT(ds_arg, flag & FMODELS);

	/* 1. determine size of user's buffer */
	if (ddi_copyin((caddr_t)arg, STRUCT_BUF(ds_arg), STRUCT_SIZE(ds_arg),
	    flag))
		return (EFAULT);
	destsize = STRUCT_FGET(ds_arg, is_size);
	if (destsize > length + 1)
		destsize = length + 1;

	/*
	 * 2. Return the copied length to the caller.  Note: for
	 * convenience, we actually copy the entire structure back out, not
	 * just the length.  We don't change the is_buf field, so this
	 * shouldn't break anything.
	 */
	STRUCT_FSET(ds_arg, is_size, length);
	if (ddi_copyout(STRUCT_BUF(ds_arg), (caddr_t)arg, STRUCT_SIZE(ds_arg),
	    flag))
		return (EFAULT);

	/* 3. copy the string and add a NULL terminator */
	outp = STRUCT_FGETP(ds_arg, is_buf);
	if (ddi_copyout(source, outp, destsize - 1, flag))
		return (EFAULT);
	nulchar = '\0';
	if (ddi_copyout(&nulchar, outp + (destsize - 1), 1, flag))
		return (EFAULT);
	return (0);
}

/*
 * Sun branded drives are shipped write cache disabled.  The default is to
 * force write write caching on.
 */
static void
ata_set_write_cache(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp)
{
	char *path;

	if (!(IS_WRITE_CACHE_SUPPORTED(ata_drvp->ad_id)))
		return;

	if (ata_write_cache == 1) {
		if (ata_set_feature(ata_ctlp, ata_drvp, FC_WRITE_CACHE_ON, 0)
		    == FALSE) {
			path = kmem_alloc(MAXPATHLEN + 1, KM_NOSLEEP);
			if (path != NULL) {
				cmn_err(CE_WARN,
				    "%s unable to enable write cache targ=%d",
				    ddi_pathname(ata_ctlp->ac_dip, path),
				    ata_drvp->ad_targ);
				kmem_free(path, MAXPATHLEN + 1);
			}
		}
	} else if (ata_write_cache == -1) {
		if (ata_set_feature(ata_ctlp, ata_drvp, FC_WRITE_CACHE_OFF, 0)
		    == FALSE) {
			path = kmem_alloc(MAXPATHLEN + 1, KM_NOSLEEP);
			if (path != NULL) {
				cmn_err(CE_WARN,
				    "%s unable to disable write cache targ=%d",
				    ddi_pathname(ata_ctlp->ac_dip, path),
				    ata_drvp->ad_targ);
				kmem_free(path, MAXPATHLEN + 1);
			}
		}
	}
}

/*
 * Call set feature to spin-up the device.
 */
static int
ata_disk_set_feature_spinup(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	int rc;

	ADBG_TRACE(("ata_disk_set_feature_spinup entered\n"));

	rc = ata_set_feature(ata_ctlp, ata_drvp, 0x07, 0);
	if (!rc)
		ata_pktp->ap_flags |= AP_ERROR;

	return (ATA_FSM_RC_FINI);
}

/*
 * Update device ata_id content - IDENTIFY DEVICE command.
 */
static int
ata_disk_id_update(
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	caddr_t		 ioaddr1 = ata_ctlp->ac_ioaddr1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	caddr_t		 ioaddr2 = ata_ctlp->ac_ioaddr2;
	struct ata_id *aidp = &ata_drvp->ad_id;
	int rc;

	ADBG_TRACE(("ata_disk_id_update entered\n"));

	/*
	 * select the appropriate drive and LUN
	 */
	ddi_put8(io_hdl1, (uchar_t *)ioaddr1 + AT_DRVHD,
	    ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/*
	 * make certain the drive is selected, and wait for not busy
	 */
	if (!ata_wait(io_hdl2, ioaddr2, ATS_DRDY, ATS_BSY, 5 * 1000000)) {
		ADBG_ERROR(("ata_disk_id_update: select failed\n"));
		ata_pktp->ap_flags |= AP_ERROR;
		return (ATA_FSM_RC_FINI);
	}

	rc = ata_disk_id(io_hdl1, ioaddr1, io_hdl2, ioaddr2, aidp);

	if (!rc) {
		ata_pktp->ap_flags |= AP_ERROR;
	} else {
		swab(aidp->ai_drvser, aidp->ai_drvser,
		    sizeof (aidp->ai_drvser));
		swab(aidp->ai_fw, aidp->ai_fw,
		    sizeof (aidp->ai_fw));
		swab(aidp->ai_model, aidp->ai_model,
		    sizeof (aidp->ai_model));
	}

	return (ATA_FSM_RC_FINI);
}

/*
 * Update device firmware.
 */
static int
ata_disk_update_fw(gtgt_t *gtgtp, ata_ctl_t *ata_ctlp,
    ata_drv_t *ata_drvp, caddr_t fwfile,
    uint_t size, uint8_t type, int flag)
{
	ata_pkt_t	*ata_pktp;
	gcmd_t		*gcmdp = NULL;
	caddr_t		fwfile_memp = NULL, tmp_fwfile_memp;
	uint_t		total_sec_count, sec_count, start_sec = 0;
	uint8_t		cmd_type;
	int		rc;

	/*
	 * First check whether DOWNLOAD MICROCODE command is supported
	 */
	if (!(ata_drvp->ad_id.ai_cmdset83 & 0x1)) {
		ADBG_ERROR(("drive doesn't support download "
		    "microcode command\n"));
		return (ENOTSUP);
	}

	switch (type) {
	case FW_TYPE_TEMP:
		cmd_type = ATCM_FW_TEMP;
		break;

	case FW_TYPE_PERM:
		cmd_type = ATCM_FW_PERM;
		break;

	default:
		return (EINVAL);
	}

	/* Temporary subcommand is obsolete in ATA/ATAPI-8 version */
	if (cmd_type == ATCM_FW_TEMP) {
		if (ata_drvp->ad_id.ai_majorversion & ATAC_MAJVER_8) {
			ADBG_ERROR(("Temporary use is obsolete in "
			    "ATA/ATAPI-8 version\n"));
			return (ENOTSUP);
		}
	}

	total_sec_count = size >> SCTRSHFT;
	if (total_sec_count > MAX_FWFILE_SIZE_ONECMD) {
		if (cmd_type == ATCM_FW_TEMP) {
			ADBG_ERROR(("firmware size: %x sectors is too large\n",
			    total_sec_count));
			return (EINVAL);
		} else {
			ADBG_WARN(("firmware size: %x sectors is larger than"
			    " one command, need to use the multicommand"
			    " subcommand\n", total_sec_count));

			cmd_type = ATCM_FW_MULTICMD;
			if (!(ata_drvp->ad_id.ai_padding2[15] & 0x10)) {
				ADBG_ERROR(("This drive doesn't support "
				    "the multicommand subcommand\n"));
				return (ENOTSUP);
			}
		}
	}

	fwfile_memp = kmem_zalloc(size, KM_SLEEP);

	if (ddi_copyin(fwfile, fwfile_memp, size, flag)) {
		ADBG_ERROR(("ata_disk_update_fw copyin failed\n"));
		rc = EFAULT;
		goto done;
	}

	tmp_fwfile_memp = fwfile_memp;

	for (; total_sec_count > 0; ) {
		if ((gcmdp == NULL) && !(gcmdp =
		    ghd_gcmd_alloc(gtgtp, sizeof (*ata_pktp), TRUE))) {
			ADBG_ERROR(("ata_disk_update_fw alloc failed\n"));
			rc = ENOMEM;
			goto done;
		}

		/* set the back ptr from the ata_pkt to the gcmd_t */
		ata_pktp = GCMD2APKT(gcmdp);
		ata_pktp->ap_gcmdp = gcmdp;
		ata_pktp->ap_hd = ata_drvp->ad_drive_bits;
		ata_pktp->ap_bytes_per_block = ata_drvp->ad_bytes_per_block;

		/* use PIO mode to update disk firmware */
		ata_pktp->ap_start = ata_disk_start_pio_out;
		ata_pktp->ap_intr = ata_disk_intr_pio_out;
		ata_pktp->ap_complete = NULL;

		ata_pktp->ap_cmd = ATC_LOAD_FW;
		/* use ap_bcount to set subcommand code */
		ata_pktp->ap_bcount = (size_t)cmd_type;
		ata_pktp->ap_pciide_dma = FALSE;
		ata_pktp->ap_sg_cnt = 0;

		sec_count = min(total_sec_count, MAX_FWFILE_SIZE_ONECMD);
		ata_pktp->ap_flags = 0;

		ata_pktp->ap_count = (ushort_t)sec_count;
		ata_pktp->ap_startsec = start_sec;
		ata_pktp->ap_v_addr = tmp_fwfile_memp;
		ata_pktp->ap_resid = sec_count << SCTRSHFT;

		/* add it to the queue, and use POLL mode */
		rc = ghd_transport(&ata_ctlp->ac_ccc, gcmdp, gcmdp->cmd_gtgtp,
		    ata_disk_updatefw_time, TRUE, NULL);

		if (rc != TRAN_ACCEPT) {
			/* this should never, ever happen */
			rc = ENOTSUP;
			goto done;
		}

		if (ata_pktp->ap_flags & AP_ERROR) {
			if (ata_pktp->ap_error & ATE_ABORT) {
				rc = ENOTSUP;
			} else
				rc = EIO;
			goto done;

		} else {
			total_sec_count -= sec_count;
			tmp_fwfile_memp += sec_count << SCTRSHFT;
			start_sec += sec_count;
		}
	}

	rc = 0;
done:
	if (gcmdp != NULL)
		ghd_gcmd_free(gcmdp);

	kmem_free(fwfile_memp, size);

	return (rc);
}
