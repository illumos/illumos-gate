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

/*
 * SCSI FMA implementation
 */

#include <sys/scsi/scsi_types.h>
#include <sys/sunmdi.h>
#include <sys/va_list.h>

#include <sys/ddi_impldefs.h>

/* consolidation private interface to generate dev scheme ereport */
extern void fm_dev_ereport_postv(dev_info_t *dip, dev_info_t *eqdip,
    const char *devpath, const char *minor_name, const char *devid,
    const char *error_class, uint64_t ena, int sflag, va_list ap);
extern char *mdi_pi_pathname_by_instance(int);

#define	FM_SCSI_CLASS	"scsi"
#define	ERPT_CLASS_SZ   sizeof (FM_SCSI_CLASS) + 1 + DDI_MAX_ERPT_CLASS + 1

/*
 * scsi_fm_init: Initialize fma capabilities and register with IO
 * fault services.
 */
void
scsi_fm_init(struct scsi_device *sd)
{
	dev_info_t	*dip = sd->sd_dev;

	/*
	 * fm-capable in driver.conf can be used to set fm_capabilities.
	 * If fm-capable is not defined, then the last argument passed to
	 * ddi_prop_get_int will be returned as the capabilities.
	 *
	 * NOTE: by default scsi_fm_capable sets DDI_FM_EREPORT_CAPABLE.
	 */
	sd->sd_fm_capable = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "fm-capable",
	    scsi_fm_capable);

	/*
	 * Register capabilities with IO Fault Services. The capabilities
	 * set above may not be supported by the parent nexus, in that
	 * case some/all capability bits may be cleared.
	 *
	 * NOTE: iblock cookies are not important because scsi HBAs
	 * always interrupt below LOCK_LEVEL.
	 */
	if (sd->sd_fm_capable != DDI_FM_NOT_CAPABLE)
		ddi_fm_init(dip, &sd->sd_fm_capable, NULL);
}

/*
 * scsi_fm_fini: un-register with IO fault services.
 */
void
scsi_fm_fini(struct scsi_device *sd)
{
	dev_info_t	*dip = sd->sd_dev;

	if (sd->sd_fm_capable != DDI_FM_NOT_CAPABLE)
		ddi_fm_fini(dip);
}

/*
 *
 * scsi_fm_erepot_post - Post an ereport.
 */
void
scsi_fm_ereport_post(struct scsi_device *sd, int path_instance,
    const char *error_class, uint64_t ena, char *devid, int sflag, ...)
{
	char		class[ERPT_CLASS_SZ];
	dev_info_t	*dip = sd->sd_dev;
	char		*devpath, *minor_name;
	va_list		ap;

	/* Add "scsi." as a prefix to the class */
	(void) snprintf(class, ERPT_CLASS_SZ, "%s.%s",
	    FM_SCSI_CLASS, error_class);

	/*
	 * Get the path: If pkt_path_instance is non-zero then the packet was
	 * sent to scsi_vhci. We return the pathinfo path_string associated
	 * with the path_instance path - which refers to the actual hardware.
	 */
	if (path_instance)
		devpath = mdi_pi_pathname_by_instance(path_instance);
	else
		devpath = NULL;

	/*
	 * Set the minor_name to NULL. The block location of a media error
	 * is described by the 'lba' property. We use the 'lba' instead of
	 * the partition (minor_name) because the defect stays in the same
	 * place even when a repartition operation may result in the defect
	 * showing up in a different partition (minor_name). To support
	 * retire at the block/partition level, the user level retire agent
	 * should map the 'lba' to the current effected partition.
	 */
	minor_name = NULL;

	/*
	 * NOTE: If there is a 'linked' ena to be had, it should likely come
	 * from the buf structure via the scsi_pkt pkt->pkt_bp.
	 */

	/* Post the ereport */
	va_start(ap, sflag);
	fm_dev_ereport_postv(dip, dip, devpath, minor_name, devid,
	    class, ena, sflag, ap);
	va_end(ap);
}
