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
 * Blacklist special file
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/open.h>
#include <sys/policy.h>
#include <sys/fm/protocol.h>
#include <sys/bl.h>

static dev_info_t *bl_dip;	/* private copy of devinfo pointer */

static int
bl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	bl_dip = dip;
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
bl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(bl_dip, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
bl_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rc = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = bl_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		break;

	default:
		*result = NULL;
		rc = DDI_FAILURE;
	}

	return (rc);
}

/*ARGSUSED*/
static int
bl_open(dev_t *devp, int flag, int otyp, struct cred *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (secpolicy_blacklist(credp) != 0)
		return (EPERM);

	return (0);
}

/*ARGSUSED*/
static int
bl_ioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cred, int *rvalp)
{
	bl_req_t blr;
	nvlist_t *fmri;
	const char *scheme;
	char class[128];
	char *buf;
	int err;

#ifdef _SYSCALL32
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		bl_req32_t blr32;

		if (copyin((void *)data, &blr32, sizeof (bl_req32_t)) != 0)
			return (EFAULT);

		blr.bl_fmri = (caddr_t)(uintptr_t)blr32.bl_fmri;
		blr.bl_fmrisz = blr32.bl_fmrisz;

		blr.bl_class = (caddr_t)(uintptr_t)blr32.bl_class;
	} else
#endif
	{
		if (copyin((void *)data, &blr, sizeof (bl_req_t)) != 0)
			return (EFAULT);
	}

	if (blr.bl_fmri == NULL || blr.bl_fmrisz > BL_FMRI_MAX_BUFSIZE ||
	    blr.bl_class == NULL)
		return (EINVAL);

	if (copyinstr(blr.bl_class, class, sizeof (class), NULL) != 0)
		return (EFAULT);

	buf = kmem_zalloc(blr.bl_fmrisz, KM_SLEEP);
	if (copyin(blr.bl_fmri, buf, blr.bl_fmrisz) != 0) {
		kmem_free(buf, blr.bl_fmrisz);
		return (EFAULT);
	}

	err = nvlist_unpack(buf, blr.bl_fmrisz, &fmri, KM_SLEEP);
	kmem_free(buf, blr.bl_fmrisz);
	if (err != 0)
		return (err);

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, (char **)&scheme) != 0) {
		nvlist_free(fmri);
		return (EINVAL);
	}

	switch (cmd) {
	case BLIOC_INSERT:
	case BLIOC_DELETE:
		err = blacklist(cmd, scheme, fmri, class);
		break;
	default:
		err = ENOTSUP;
	}

	nvlist_free(fmri);
	return (err);

}

static struct cb_ops bl_cb_ops = {
	bl_open,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	bl_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP | D_64BIT	/* Driver compatibility flag */
};

static struct dev_ops bl_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt  */
	bl_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	bl_attach,		/* devo_attach */
	bl_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&bl_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "blacklist driver", &bl_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
