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

#include <sys/scsi/targets/sddef.h>

/*
 * We're emulating (and possibly layering on top of) sd devices, so xdf
 * disk unit mappings must match up with sd disk unit mappings'.
 */
#if !defined(XDF_PSHIFT)
#error "can't find definition for xdf unit mappings - XDF_PSHIFT"
#endif /* XDF_PSHIFT */

#if !defined(SDUNIT_SHIFT)
#error "can't find definition for cmdk unit mappings - SDUNIT_SHIFT"
#endif /* SDUNIT_SHIFT */

#if ((XDF_PSHIFT - SDUNIT_SHIFT) != 0)
#error "sd and xdf unit mappings don't match."
#endif /* ((XDF_PSHIFT - SDUNIT_SHIFT) != 0) */

extern const struct dev_ops	sd_ops;
extern void			*sd_state;

/*
 * Globals required by xdf_shell.c
 */
const char		*xdfs_c_name = "sd";
const char		*xdfs_c_linkinfo = "PV SCSI Disk Driver";
void			**xdfs_c_hvm_ss = &sd_state;
const size_t		xdfs_c_hvm_ss_size = sizeof (struct sd_lun);
const struct dev_ops	*xdfs_c_hvm_dev_ops = &sd_ops;

const xdfs_h2p_map_t xdfs_c_h2p_map[] = {
	{ "/pci@0,0/pci-ide@1,1/ide@0/sd@0,0", "/xpvd/xdf@768" },
	{ "/pci@0,0/pci-ide@1,1/ide@0/sd@1,0", "/xpvd/xdf@832" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/sd@0,0", "/xpvd/xdf@5632" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/sd@1,0", "/xpvd/xdf@5696" },
	{ NULL, 0 }
};

/*ARGSUSED*/
int
xdfs_c_ioctl(xdfs_state_t *xsp, dev_t dev, int part,
    int cmd, intptr_t arg, int flag, cred_t *credp, int *rvalp, boolean_t *done)
{
	dev_info_t	*dip = xsp->xdfss_dip;
	int		instance = ddi_get_instance(dip);
	int		rv;

	*done = B_TRUE;
	switch (cmd) {
	case DKIOCINFO: {
		struct dk_cinfo	info;

		/* Pass on the ioctl request, save the response */
		if ((rv = ldi_ioctl(xsp->xdfss_tgt_lh[part],
		    cmd, (intptr_t)&info, FKIOCTL, credp, rvalp)) != 0)
			return (rv);

		/* Update controller info */
		info.dki_cnum = ddi_get_instance(ddi_get_parent(dip));
		(void) strlcpy(info.dki_cname,
		    ddi_get_name(ddi_get_parent(dip)), sizeof (info.dki_cname));

		/* Update unit info. */
		if (info.dki_ctype == DKC_VBD) {
			/*
			 * Normally a real scsi device would report the
			 * controller type as DKC_SCSI_CCS.  But we don't
			 * emulate a real scsi controller.  (Which becomes
			 * apparent if anyone tries to issue us a uscsi(7i)
			 * command.) So instead of reporting DKC_SCSI_CCS,
			 * we report DKC_UNKNOWN.
			 */
			info.dki_ctype = DKC_UNKNOWN;
		}
		info.dki_unit = instance;
		(void) strlcpy(info.dki_dname,
		    ddi_driver_name(dip), sizeof (info.dki_dname));
		info.dki_addr = 1;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), flag))
			return (EFAULT);

		return (0);
	}
	default:
		*done = B_FALSE;
		return (0);
	} /* switch (cmd) */
	/*NOTREACHED*/
}

/*ARGSUSED*/
void
xdfs_c_devid_setup(xdfs_state_t *xsp)
{
	/*
	 * Currently we only support cdrom devices, which don't have
	 * devids associated with them.
	 */
	ASSERT("cdrom devices don't have a devid");
}

/*ARGSUSED*/
int
xdfs_c_getpgeom(dev_info_t *dip, cmlb_geom_t *pgeom)
{
	/*
	 * Currently we only support cdrom devices, which don't have
	 * a physical geometry, so this routine should never get
	 * invoked.
	 */
	ASSERT("cdrom devices don't have any physical geometry");
	return (-1);
}

/*ARGSUSED*/
boolean_t
xdfs_c_bb_check(xdfs_state_t *xsp)
{
	/*
	 * Currently we only support cdrom devices, which don't have
	 * bad blocks, so this routine should never get invoked.
	 */
	ASSERT("cdrom devices don't support bad block mappings");
	return (B_TRUE);
}

char *
xdfs_c_cmlb_node_type(xdfs_state_t *xsp)
{
	return (xsp->xdfss_tgt_is_cd ? DDI_NT_CD_CHAN : DDI_NT_BLOCK_CHAN);
}

/*ARGSUSED*/
int
xdfs_c_cmlb_alter_behavior(xdfs_state_t *xsp)
{
	return (0);
}

void
xdfs_c_attach(xdfs_state_t *xsp)
{
	dev_info_t	*dip = xsp->xdfss_dip;
	int		dtype = DTYPE_DIRECT;

	if (xsp->xdfss_tgt_is_cd) {
		dtype = DTYPE_RODIRECT;
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "removable-media", NULL, 0);
	}

	/*
	 * We use ndi_* instead of ddi_* because it will result in
	 * INQUIRY_DEVICE_TYPE being a hardware property instead
	 * or a driver property
	 */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    INQUIRY_DEVICE_TYPE, dtype);
}
