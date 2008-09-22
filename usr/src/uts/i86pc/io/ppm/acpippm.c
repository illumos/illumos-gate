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
#include <sys/conf.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/epm.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/psm_types.h>

/*
 *	ACPI Power Management Driver
 *
 *	acpippm deals with those bits of ppm functionality that
 *	must be mediated by ACPI
 *
 *	The routines in this driver is referenced by Platform
 *	Power Management driver of X86 workstation systems.
 *	acpippm driver is loaded because it is listed as a platform driver
 *	It is initially configured as a pseudo driver.
 */
extern void pc_tod_set_rtc_offsets(FADT_DESCRIPTOR *);

/*
 * Configuration Function prototypes and data structures
 */
static int	appm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	appm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	appm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	appm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	appm_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	appm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Configuration data structures
 */
static struct cb_ops appm_cbops = {
	appm_open,		/* open */
	appm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	appm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP | D_NEW,		/* flag */
	CB_REV,			/* rev */
	nodev,			/* aread */
	nodev,			/* awrite */
};

static struct dev_ops appm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	appm_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	appm_attach,		/* attach */
	appm_detach,		/* detach */
	nodev,			/* reset */
	&appm_cbops,		/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"ACPI ppm driver",
	&appm_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Driver state structure
 */
typedef struct {
	dev_info_t		*dip;
	ddi_acc_handle_t	devid_hndl;
	ddi_acc_handle_t	estar_hndl;
	int			lyropen;		/* ref count */
} appm_unit;

/*
 * Driver global variables
 *
 * appm_lock synchronize the access of lyr handle to each appm
 * minor device, therefore write to tomatillo device is
 * sequentialized.  Lyr protocol requires pairing up lyr open
 * and close, so only a single reference is allowed per minor node.
 */
static void	*appm_statep;
static kmutex_t  appm_lock;

/*
 * S3 stuff:
 */
char _depends_on[] = "misc/acpica";

extern int acpi_enter_sleepstate(s3a_t *);
extern int acpi_exit_sleepstate(s3a_t *);


int
_init(void)
{
	int	error;

	if ((error = ddi_soft_state_init(&appm_statep,
	    sizeof (appm_unit), 0)) != DDI_SUCCESS) {
		return (error);
	}

	mutex_init(&appm_lock, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mutex_destroy(&appm_lock);
		ddi_soft_state_fini(&appm_statep);
		return (error);
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	if ((error = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		mutex_destroy(&appm_lock);
		ddi_soft_state_fini(&appm_statep);
	}

	return (error);

}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * Driver attach(9e) entry point
 */
static int
appm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char	*str = "appm_attach";
	int		instance;
	appm_unit	*unitp;
	FADT_DESCRIPTOR *fadt = NULL;
	int		rv = DDI_SUCCESS;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "%s: cmd %d unsupported.\n", str, cmd);
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	rv = ddi_soft_state_zalloc(appm_statep, instance);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: failed alloc for dev(%s@%s)",
		    str, ddi_binding_name(dip),
		    ddi_get_name_addr(dip) ? ddi_get_name_addr(dip) : " ");
		return (rv);
	}

	if ((unitp = ddi_get_soft_state(appm_statep, instance)) == NULL) {
		rv = DDI_FAILURE;
		goto doerrs;
	}

	/*
	 * Export "ddi-kernel-ioctl" property - prepared to support
	 * kernel ioctls (driver layering).
	 * XXX is this still needed?
	 * XXXX (RSF) Not that I am aware of.
	 */
	rv = ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);
	if (rv != DDI_PROP_SUCCESS)
		goto doerrs;

	ddi_report_dev(dip);
	unitp->dip = dip;

	/*
	 * XXX here we would do whatever we need to to determine if the
	 * XXX platform supports ACPI, and fail the attach if not.
	 * XXX If it does, we do whatever setup is needed to get access to
	 * XXX ACPI register space.
	 */

	unitp->lyropen = 0;

	/*
	 * create minor node for kernel_ioctl calls
	 */
	rv = ddi_create_minor_node(dip, "acpi-ppm", S_IFCHR, instance, 0, 0);
	if (rv != DDI_SUCCESS)
		goto doerrs;

	/* Get the FADT */
	if (AcpiGetFirmwareTable(FADT_SIG, 1, ACPI_LOGICAL_ADDRESSING,
	    (ACPI_TABLE_HEADER **)&fadt) != AE_OK)
		return (rv);

	/* Init the RTC offsets */
	if (fadt != NULL)
		pc_tod_set_rtc_offsets(fadt);

	return (rv);

doerrs:

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_NOTPROM, DDI_KERNEL_IOCTL))
		ddi_prop_remove_all(dip);

	ddi_soft_state_free(appm_statep, instance);

	return (rv);
}


/*
 * Driver getinfo(9e) entry routine
 */
/* ARGSUSED */
static int
appm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	appm_unit	*unitp;
	int		instance;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = getminor((dev_t)arg);
		unitp = ddi_get_soft_state(appm_statep, instance);
		if (unitp == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *) unitp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		instance = getminor((dev_t)arg);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/*
 * detach(9e)
 */
/* ARGSUSED */
static int
appm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	char *str = "appm_detach";

	switch (cmd) {
	case DDI_DETACH:
		return (DDI_FAILURE);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "%s: cmd %d unsupported", str, cmd);
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
appm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	appm_unit	*unitp;

	/* not intended to allow sysadmin level root process to open it */
	if (drv_priv(cred_p) != DDI_SUCCESS)
		return (EPERM);

	if ((unitp = ddi_get_soft_state(
	    appm_statep, getminor(*dev_p))) == NULL) {
		cmn_err(CE_WARN, "appm_open: failed to get soft state!");
		return (DDI_FAILURE);
	}

	mutex_enter(&appm_lock);
	if (unitp->lyropen != 0) {
		mutex_exit(&appm_lock);
		return (EBUSY);
	}
	unitp->lyropen++;
	mutex_exit(&appm_lock);

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
appm_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	appm_unit	*unitp;

	if ((unitp =
	    ddi_get_soft_state(appm_statep, getminor(dev))) == NULL)
		return (DDI_FAILURE);

	mutex_enter(&appm_lock);
	unitp->lyropen = 0;
	mutex_exit(&appm_lock);

	return (DDI_SUCCESS);
}


/*
 * must match ppm.conf
 */
#define	APPMIOC			('A' << 8)
#define	APPMIOC_ENTER_S3	(APPMIOC | 1)	/* arg *s3a_t */
#define	APPMIOC_EXIT_S3		(APPMIOC | 2)	/* arg *s3a_t */

/* ARGSUSED3 */
static int
appm_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p)
{
	static boolean_t	acpi_initted = B_FALSE;
	char			*str = "appm_ioctl";
	int			ret;
	s3a_t			*s3ap = (s3a_t *)arg;

	PMD(PMD_SX, ("%s: called with %x\n", str, cmd))

	if (drv_priv(cred_p) != 0) {
		PMD(PMD_SX, ("%s: EPERM\n", str))
		return (EPERM);
	}

	if (ddi_get_soft_state(appm_statep, getminor(dev)) == NULL) {
		PMD(PMD_SX, ("%s: no soft state: EIO\n", str))
		return (EIO);
	}

	if (!acpi_initted) {
		PMD(PMD_SX, ("%s: !acpi_initted\n", str))
		if (acpica_init() == 0) {
			acpi_initted = B_TRUE;
		} else {
			if (rval_p != NULL) {
				*rval_p = EINVAL;
			}
			PMD(PMD_SX, ("%s: EINVAL\n", str))
			return (EINVAL);
		}
	}

	PMD(PMD_SX, ("%s: looking for cmd %x\n", str, cmd))
	switch (cmd) {
	case APPMIOC_ENTER_S3:
		/*
		 * suspend to RAM (ie S3)
		 */
		PMD(PMD_SX, ("%s: cmd %x, arg %p\n", str, cmd, (void *)arg))
		ret = acpi_enter_sleepstate(s3ap);
		break;

	case APPMIOC_EXIT_S3:
		/*
		 * return from S3
		 */
		PMD(PMD_SX, ("%s: cmd %x, arg %p\n", str, cmd, (void *)arg))
		ret = acpi_exit_sleepstate(s3ap);
		break;

	default:
		PMD(PMD_SX, ("%s: cmd %x unrecognized: ENOTTY\n", str, cmd))
		return (ENOTTY);
	}

	/*
	 * upon failure return EINVAL
	 */
	if (ret != 0) {
		if (rval_p != NULL) {
			*rval_p = EINVAL;
		}
		return (EINVAL);
	}

	return (0);
}
