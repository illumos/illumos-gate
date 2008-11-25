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
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>

#include <sys/amd_iommu.h>
#include "amd_iommu_impl.h"
#include "amd_iommu_acpi.h"


#define	AMD_IOMMU_MINOR2INST(x)	(x)
#define	AMD_IOMMU_INST2MINOR(x)	(x)
#define	AMD_IOMMU_NODETYPE	"ddi_iommu"
#define	AMD_IOMMU_MINOR_NAME	"amd-iommu"

static int amd_iommu_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int amd_iommu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int amd_iommu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int amd_iommu_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int amd_iommu_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int amd_iommu_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);

static struct cb_ops amd_iommu_cb_ops = {
	amd_iommu_open,		/* cb_open */
	amd_iommu_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	amd_iommu_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_str */
	D_NEW | D_MP,		/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops amd_iommu_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	amd_iommu_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	amd_iommu_attach,	/* devo_attach */
	amd_iommu_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&amd_iommu_cb_ops,	/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	nulldev			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"AMD IOMMU 0.1",
	&amd_iommu_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

amd_iommu_debug_t amd_iommu_debug;
kmutex_t amd_iommu_global_lock;
const char *amd_iommu_modname = "amd_iommu";
amd_iommu_alias_t **amd_iommu_alias;
amd_iommu_page_table_hash_t amd_iommu_page_table_hash;
static void *amd_iommu_statep;
int amd_iommu_64bit_bug;
int amd_iommu_unity_map;
int amd_iommu_no_RW_perms;
int amd_iommu_no_unmap;
int amd_iommu_pageva_inval_all;
int amd_iommu_disable;		/* disable IOMMU */
char *amd_iommu_disable_list;	/* list of drivers bypassing IOMMU */

int
_init(void)
{
	int error = ENOTSUP;

#if defined(_LP64) && !defined(__xpv)

	error = ddi_soft_state_init(&amd_iommu_statep,
	    sizeof (struct amd_iommu_state), 1);
	if (error) {
		cmn_err(CE_WARN, "%s: _init: failed to init soft state.",
		    amd_iommu_modname);
		return (error);
	}

	amd_iommu_read_boot_props();

	if (amd_iommu_acpi_init() != DDI_SUCCESS) {
		if (amd_iommu_debug) {
			cmn_err(CE_WARN, "%s: _init: ACPI init failed.",
			    amd_iommu_modname);
		}
		ddi_soft_state_fini(&amd_iommu_statep);
		return (ENOTSUP);
	}

	if (amd_iommu_page_table_hash_init(&amd_iommu_page_table_hash)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: _init: Page table hash init failed.",
		    amd_iommu_modname);
		amd_iommu_acpi_fini();
		ddi_soft_state_fini(&amd_iommu_statep);
		amd_iommu_statep = NULL;
		return (EFAULT);
	}

	error = mod_install(&modlinkage);
	if (error) {
		cmn_err(CE_WARN, "%s: _init: mod_install failed.",
		    amd_iommu_modname);
		amd_iommu_page_table_hash_fini(&amd_iommu_page_table_hash);
		amd_iommu_acpi_fini();
		ddi_soft_state_fini(&amd_iommu_statep);
		amd_iommu_statep = NULL;
		return (error);
	}
	error = 0;
#endif

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	amd_iommu_page_table_hash_fini(&amd_iommu_page_table_hash);
	amd_iommu_acpi_fini();
	ddi_soft_state_fini(&amd_iommu_statep);
	amd_iommu_statep = NULL;
	if (amd_iommu_disable_list) {
		kmem_free(amd_iommu_disable_list,
		    strlen(amd_iommu_disable_list) + 1);
	}

	return (0);
}

/*ARGSUSED*/
static int
amd_iommu_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct amd_iommu_state *statep;

	ASSERT(result);

	*result = NULL;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		statep = ddi_get_soft_state(amd_iommu_statep,
		    AMD_IOMMU_MINOR2INST(getminor((dev_t)arg)));
		if (statep) {
			*result = statep->aioms_devi;
			return (DDI_SUCCESS);
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)
		    AMD_IOMMU_MINOR2INST(getminor((dev_t)arg));
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
amd_iommu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	struct amd_iommu_state *statep;

	ASSERT(instance >= 0);
	ASSERT(driver);

	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(amd_iommu_statep, instance)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Unable to allocate soft state for "
			    "%s%d", driver, instance);
			return (DDI_FAILURE);
		}

		statep = ddi_get_soft_state(amd_iommu_statep, instance);
		if (statep == NULL) {
			cmn_err(CE_WARN, "Unable to get soft state for "
			    "%s%d", driver, instance);
			ddi_soft_state_free(amd_iommu_statep, instance);
			return (DDI_FAILURE);
		}

		if (ddi_create_minor_node(dip, AMD_IOMMU_MINOR_NAME, S_IFCHR,
		    AMD_IOMMU_INST2MINOR(instance), AMD_IOMMU_NODETYPE,
		    0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Unable to create minor node for "
			    "%s%d", driver, instance);
			ddi_remove_minor_node(dip, NULL);
			ddi_soft_state_free(amd_iommu_statep, instance);
			return (DDI_FAILURE);
		}

		statep->aioms_devi = dip;
		statep->aioms_instance = instance;
		statep->aioms_iommu_start = NULL;
		statep->aioms_iommu_end = NULL;

		amd_iommu_lookup_conf_props(dip);

		if (amd_iommu_disable_list) {
			cmn_err(CE_NOTE, "AMD IOMMU disabled for the following"
			    " drivers:\n%s", amd_iommu_disable_list);
		}

		if (amd_iommu_disable) {
			cmn_err(CE_NOTE, "AMD IOMMU disabled by user");
		} else if (amd_iommu_setup(dip, statep) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Unable to initialize AMD IOMMU "
			    "%s%d", driver, instance);
			ddi_remove_minor_node(dip, NULL);
			ddi_soft_state_free(amd_iommu_statep, instance);
			return (DDI_FAILURE);
		}

		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
amd_iommu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	const char *driver = ddi_driver_name(dip);
	struct amd_iommu_state *statep;

	ASSERT(instance >= 0);
	ASSERT(driver);

	switch (cmd) {
	case DDI_DETACH:
		statep = ddi_get_soft_state(amd_iommu_statep, instance);
		if (statep == NULL) {
			cmn_err(CE_WARN, "%s%d: Cannot get soft state",
			    driver, instance);
			return (DDI_FAILURE);
		}
		return (DDI_FAILURE);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
amd_iommu_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int instance = AMD_IOMMU_MINOR2INST(getminor(*devp));
	struct amd_iommu_state *statep;
	const char *f = "amd_iommu_open";

	if (instance < 0) {
		cmn_err(CE_WARN, "%s: invalid instance %d",
		    f, instance);
		return (ENXIO);
	}

	if (!(flag & (FREAD|FWRITE))) {
		cmn_err(CE_WARN, "%s: invalid flags %d", f, flag);
		return (EINVAL);
	}

	if (otyp != OTYP_CHR) {
		cmn_err(CE_WARN, "%s: invalid otyp %d", f, otyp);
		return (EINVAL);
	}

	statep = ddi_get_soft_state(amd_iommu_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "%s: cannot get soft state: instance %d",
		    f, instance);
		return (ENXIO);
	}

	ASSERT(statep->aioms_instance == instance);

	return (0);
}

/*ARGSUSED*/
static int
amd_iommu_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance = AMD_IOMMU_MINOR2INST(getminor(dev));
	struct amd_iommu_state *statep;
	const char *f = "amd_iommu_close";

	if (instance < 0) {
		cmn_err(CE_WARN, "%s: invalid instance %d", f, instance);
		return (ENXIO);
	}

	if (!(flag & (FREAD|FWRITE))) {
		cmn_err(CE_WARN, "%s: invalid flags %d", f, flag);
		return (EINVAL);
	}

	if (otyp != OTYP_CHR) {
		cmn_err(CE_WARN, "%s: invalid otyp %d", f, otyp);
		return (EINVAL);
	}

	statep = ddi_get_soft_state(amd_iommu_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "%s: cannot get soft state: instance %d",
		    f, instance);
		return (ENXIO);
	}

	ASSERT(statep->aioms_instance == instance);
	return (0);

}

/*ARGSUSED*/
static int
amd_iommu_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int instance = AMD_IOMMU_MINOR2INST(getminor(dev));
	struct amd_iommu_state *statep;
	const char *f = "amd_iommu_ioctl";

	ASSERT(*rvalp);

	if (instance < 0) {
		cmn_err(CE_WARN, "%s: invalid instance %d", f, instance);
		return (ENXIO);
	}


	if (!(mode & (FREAD|FWRITE))) {
		cmn_err(CE_WARN, "%s: invalid mode %d", f, mode);
		return (EINVAL);
	}

	if (mode & FKIOCTL) {
		cmn_err(CE_WARN, "%s: FKIOCTL unsupported mode %d", f, mode);
		return (EINVAL);
	}

	statep = ddi_get_soft_state(amd_iommu_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "%s: cannot get soft state: instance %d",
		    f, instance);
		return (ENXIO);
	}

	ASSERT(statep->aioms_instance == instance);

	return (ENOTTY);
}
