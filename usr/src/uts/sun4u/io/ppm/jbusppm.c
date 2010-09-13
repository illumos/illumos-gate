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
#include <sys/jbusppm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 *	JBus Power Management Driver
 *
 *	jbusppm driver initiates the JBus clock speed change
 *	as part of the protocol to adjust the clock speed on
 *	all JBus resident devices.
 *
 *	jbusppm driver is loaded because of the explicit dependency
 *	defined in PPM driver.
 */

/*
 * Configuration Function prototypes and data structures
 */
static int	jbppm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	jbppm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	jbppm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	jbppm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	jbppm_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	jbppm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Configuration data structures
 */
static struct cb_ops jbppm_cbops = {
	jbppm_open,		/* open */
	jbppm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	jbppm_ioctl,		/* ioctl */
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

static struct dev_ops jbppm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	jbppm_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	jbppm_attach,		/* attach */
	jbppm_detach,		/* detach */
	nodev,			/* reset */
	&jbppm_cbops,		/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"JBus ppm driver",
	&jbppm_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Local functions
 */
static void jbppm_next_speed(dev_info_t *, uint_t);
static int jbppm_start_next(dev_info_t *, int);

/*
 * Driver global variables
 *
 * jbppm_lock synchronize the access of lyr handle to each jbppm
 * minor device, therefore write to tomatillo device is
 * sequentialized.  Lyr protocol requires pairing up lyr open
 * and close, so only a single reference is allowed per minor node.
 */
static void	*jbppm_statep;
static kmutex_t  jbppm_lock;

/*
 * bit masks to scale the IO bridge clock in sync with and only with
 * scaling CPU clock.
 *
 * The array index indicates power level (from lowest to highest).
 */
static const uint64_t jbus_clock_masks[] = {
	JBUS_ESTAR_CNTL_32,
	JBUS_ESTAR_CNTL_2,
	JBUS_ESTAR_CNTL_1
};

int
_init(void)
{
	int	error;

	if ((error = ddi_soft_state_init(&jbppm_statep,
	    sizeof (jbppm_unit), 0)) != DDI_SUCCESS) {
		return (error);
	}

	mutex_init(&jbppm_lock, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != DDI_SUCCESS) {
		mutex_destroy(&jbppm_lock);
		ddi_soft_state_fini(&jbppm_statep);
		return (error);
	}

	return (error);
}

int
_fini(void)
{
	int	error;

	if ((error = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		mutex_destroy(&jbppm_lock);
		ddi_soft_state_fini(&jbppm_statep);
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
jbppm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char	*str = "jbppm_attach";
	int		instance;
	jbppm_unit	*unitp;
	uint64_t	data64;
	ddi_device_acc_attr_t	attr;
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
	rv = ddi_soft_state_zalloc(jbppm_statep, instance);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: failed alloc for dev(%s@%s)",
		    str, ddi_binding_name(dip),
		    ddi_get_name_addr(dip) ? ddi_get_name_addr(dip) : " ");
		return (rv);
	}

	if ((unitp = ddi_get_soft_state(jbppm_statep, instance)) == NULL) {
		rv = DDI_FAILURE;
		goto doerrs;
	}

	/*
	 * Export "ddi-kernel-ioctl" property - prepared to support
	 * kernel ioctls (driver layering).
	 */
	rv = ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);
	if (rv != DDI_PROP_SUCCESS)
		goto doerrs;

	ddi_report_dev(dip);
	unitp->dip = dip;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	rv = ddi_regs_map_setup(dip, 0, (caddr_t *)&unitp->devid_csr, 0, 8,
	    &attr, &unitp->devid_hndl);
	if (rv != DDI_SUCCESS)
		goto doerrs;

	rv = ddi_regs_map_setup(dip, 1, (caddr_t *)&unitp->estar_csr, 0, 16,
	    &attr, &unitp->estar_hndl);
	if (rv != DDI_SUCCESS)
		goto doerrs;
	unitp->j_chng_csr = (uint64_t *)((caddr_t)unitp->estar_csr +
	    J_CHNG_INITIATION_OFFSET);

	data64 = ddi_get64(unitp->devid_hndl, (uint64_t *)unitp->devid_csr);
	unitp->is_master = (data64 & MASTER_IOBRIDGE_BIT) ? 1 : 0;
	unitp->lyropen = 0;

	/*
	 * create minor node for kernel_ioctl calls
	 */
	rv = ddi_create_minor_node(dip, "jbus-ppm", S_IFCHR, instance, 0, 0);
	if (rv != DDI_SUCCESS)
		goto doerrs;

	return (rv);

doerrs:
	if (unitp->devid_hndl != NULL)
		ddi_regs_map_free(&unitp->devid_hndl);

	if (unitp->estar_csr != NULL)
		ddi_regs_map_free(&unitp->estar_hndl);

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_NOTPROM, DDI_KERNEL_IOCTL))
		ddi_prop_remove_all(dip);

	ddi_soft_state_free(jbppm_statep, instance);

	return (rv);
}


/*
 * Driver getinfo(9e) entry routine
 */
/* ARGSUSED */
static int
jbppm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	jbppm_unit	*unitp;
	int		instance;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = getminor((dev_t)arg);
		unitp = ddi_get_soft_state(jbppm_statep, instance);
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
jbppm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	char *str = "jbppm_detach";

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
jbppm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	jbppm_unit	*unitp;

	/* not intended to allow sysadmin level root process to open it */
	if (drv_priv(cred_p) != DDI_SUCCESS)
		return (EPERM);

	if ((unitp = ddi_get_soft_state(
	    jbppm_statep, getminor(*dev_p))) == NULL) {
		cmn_err(CE_WARN, "jbppm_open: failed to get soft state!");
		return (DDI_FAILURE);
	}

	mutex_enter(&jbppm_lock);
	if (unitp->lyropen != 0) {
		mutex_exit(&jbppm_lock);
		return (EBUSY);
	}
	unitp->lyropen++;
	mutex_exit(&jbppm_lock);

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
jbppm_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	jbppm_unit	*unitp;

	if ((unitp =
	    ddi_get_soft_state(jbppm_statep, getminor(dev))) == NULL)
		return (DDI_FAILURE);

	mutex_enter(&jbppm_lock);
	unitp->lyropen = 0;
	mutex_exit(&jbppm_lock);

	return (DDI_SUCCESS);
}


#define	JBPPMIOC		('j' << 8)
#define	JBPPMIOC_ISMASTER	(JBPPMIOC | 1)	/* no 'arg' */
#define	JBPPMIOC_NEXT		(JBPPMIOC | 2)	/* 'arg': next speed level */
#define	JBPPMIOC_GO		(JBPPMIOC | 3)	/* 'arg': jbus chng_delay */

/* ARGSUSED3 */
static int
jbppm_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p)
{
	jbppm_unit	*unitp;

	if (drv_priv(cred_p) != 0)
		return (EPERM);

	if ((unitp =
	    ddi_get_soft_state(jbppm_statep, getminor(dev))) == NULL)
		return (EIO);

	switch (cmd) {
	case JBPPMIOC_ISMASTER:
		if (unitp->is_master)
			return (0);
		else
			return (-1);

	case  JBPPMIOC_NEXT:
		jbppm_next_speed(unitp->dip, (uint_t)arg);
		return (0);

	case  JBPPMIOC_GO:
		if (!unitp->is_master)
			return (EINVAL);
		return (jbppm_start_next(unitp->dip, (int)arg));

	default:
		return (ENOTTY);
	}
}


/*
 * jbppm_next_speed - program a new speed into IO bridge device prior to
 * actual speed transition.
 */
static void
jbppm_next_speed(dev_info_t *dip, uint_t lvl_index)
{
	volatile uint64_t	data64;
	static jbppm_unit	*unitp;

	unitp = ddi_get_soft_state(jbppm_statep, ddi_get_instance(dip));
	ASSERT(unitp);

	mutex_enter(&jbppm_lock);
	data64 = ddi_get64(unitp->estar_hndl, unitp->estar_csr);
	data64 &= ~JBUS_ESTAR_CNTL_MASK;
	data64 |= jbus_clock_masks[lvl_index];

	ddi_put64(unitp->estar_hndl, (uint64_t *)unitp->estar_csr, data64);
	data64 = ddi_get64(unitp->estar_hndl, unitp->estar_csr);
	mutex_exit(&jbppm_lock);
}


/*
 * jbppm_start_next - Initiate JBus speed change on all JBus devices.
 * chng_delay indicates after master deassert j_chng signal the number of
 * jbus clock delay before all jbus device start to transit to the new
 * speed.
 * Trigger sequence:
 *      wait while j_chng[1:0] == 10
 *	write 00 to j_chng
 *	trigger by writing 10 to j_chng[1:0]
 *	wait while j_chng[1:0] == 10
 *	write 00 to j_chng[1:0]
 * Note: this sequence is not the same as Enchilada spec described, chiefly
 * because else where (e.g. flush E$ code) may have speed change code. If sw
 * wait upon j_chng[1:0] == 11 in both places, we'll have problem.  That spec
 * requires wait on 11 to ensure that trigger has completed. An alternative
 * way to ensure that is to check and wait upon 10. J_chng[1:0] stays as 10
 * for only a short period of time that is under HW control, unlike 11 signals
 * which has to be cleared by sw.
 */
/* ARGSUSED */
static int
jbppm_start_next(dev_info_t *dip, int chng_delay)
{
	volatile uint64_t	data64;
	static jbppm_unit	*unitp;

	unitp = ddi_get_soft_state(jbppm_statep, ddi_get_instance(dip));
	ASSERT(unitp && unitp->is_master);

	mutex_enter(&jbppm_lock);

	/* wait while trigger is incomplete */
	do {
		data64 = ddi_get64(unitp->estar_hndl, unitp->j_chng_csr);
	} while ((J_CHNG_INITIATION_MASK & data64) == J_CHNG_START);

	/* clear(reset) */
	data64 &= ~J_CHNG_INITIATION_MASK;
	ddi_put64(unitp->estar_hndl, (uint64_t *)unitp->j_chng_csr, data64);

	/* trigger */
	data64 &= ~J_CHNG_DELAY_MASK;
	data64 |= (J_CHNG_START | chng_delay);
	ddi_put64(unitp->estar_hndl, (uint64_t *)unitp->j_chng_csr, data64);

	/* wait while trigger is incomplete */
	do {
		data64 = ddi_get64(unitp->estar_hndl, unitp->j_chng_csr);
	} while ((J_CHNG_INITIATION_MASK & data64) == J_CHNG_START);

	/* clear(reset) */
	data64 &= ~J_CHNG_INITIATION_MASK;
	ddi_put64(unitp->estar_hndl, (uint64_t *)unitp->j_chng_csr, data64);
	(void) ddi_get64(unitp->estar_hndl, unitp->j_chng_csr);

	mutex_exit(&jbppm_lock);
	return (DDI_SUCCESS);
}
