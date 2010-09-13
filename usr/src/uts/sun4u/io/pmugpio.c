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
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/devops.h>

/*
 * The pmugpio driver supports ALOM GPIO bits for resetSC and
 * watchdog heartbeat on all relevant platforms.  Historically,
 * pmugpio is a leaf off the Chalupa pmubus.  In addition to
 * this support the pmugpio driver has been modified to support
 * Minneapolis/Boston Controller (MBC) FPGA GPIO and Seattle CPLD
 * GPIO.
 */

typedef enum {
	PMUGPIO_MBC,		/* Boston MBC FPGA GPIO - 8-bit */
	PMUGPIO_CPLD,		/* Seattle CPLD GPIO - 8-bit */
	PMUGPIO_OTHER		/* Chalupa - 8-bit */
} pmugpio_access_type_t;

/*
 * FWARC 2005/686: gpio device compatible property
 */
#define	PMUGPIO_DEVICE_TYPE "gpio-device-type"

/*
 * CPLD GPIO Register defines.
 */
#define	CPLD_RESET_SC		0x01	/* Reset SC */
#define	CPLD_WATCHDOG		0x02	/* Watchdog */

#define	CPLD_RESET_DELAY	3	/* microsecond delay */

/*
 * MBC FPGA CSR defines.
 */
#define	MBC_PPC_RESET		0x10	/* Reset ALOM */
#define	MBC_WATCHDOG		0x40	/* Watchdog heartbeat bit */

/*
 * Time periods, in nanoseconds
 */
#define	PMUGPIO_TWO_SEC		2000000000LL

static	dev_info_t	*pmugpio_dip;

typedef struct pmugpio_state {
	uint8_t			*pmugpio_reset_reg;
	ddi_acc_handle_t	pmugpio_reset_reg_handle;
	uint8_t			*pmugpio_watchdog_reg;
	ddi_acc_handle_t	pmugpio_watchdog_reg_handle;
	hrtime_t		hw_last_pat;
	pmugpio_access_type_t	access_type;
} pmugpio_state_t;

static void *pmugpio_statep;

static int pmugpio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pmugpio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pmugpio_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int pmugpio_map_regs(dev_info_t *, pmugpio_state_t *);

struct cb_ops pmugpio_cb_ops = {
	nulldev,	/* open  */
	nulldev,	/* close */
	nulldev,	/* strategy */
	nulldev,	/* print */
	nulldev,	/* dump */
	nulldev,	/* read */
	nulldev,	/* write */
	nulldev,	/* ioctl */
	nulldev,	/* devmap */
	nulldev,	/* mmap */
	nulldev,	/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,		/* streamtab  */
	D_MP | D_NEW
};

static struct dev_ops pmugpio_ops = {
	DEVO_REV,		/* Devo_rev */
	0,			/* Refcnt */
	pmugpio_info,		/* Info */
	nulldev,		/* Identify */
	nulldev,		/* Probe */
	pmugpio_attach,		/* Attach */
	pmugpio_detach,		/* Detach */
	nodev,			/* Reset */
	&pmugpio_cb_ops,		/* Driver operations */
	0,			/* Bus operations */
	NULL,			/* Power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, 		/* This one is a driver */
	"Pmugpio Driver", 		/* Name of the module. */
	&pmugpio_ops,			/* Driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&pmugpio_statep,
	    sizeof (pmugpio_state_t), 1)) != 0) {
		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pmugpio_statep);
	}
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
	if (error == 0) {
		/* Release per module resources */
		ddi_soft_state_fini(&pmugpio_statep);
	}
	return (error);
}

static int
pmugpio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	pmugpio_state_t	*pmugpio_ptr = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/* Get the instance and create soft state */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(pmugpio_statep, instance) != 0) {
		return (DDI_FAILURE);
	}
	pmugpio_ptr = ddi_get_soft_state(pmugpio_statep, instance);
	if (pmugpio_ptr == NULL) {
		return (DDI_FAILURE);
	}

	if (pmugpio_map_regs(dip, pmugpio_ptr) != DDI_SUCCESS) {
		ddi_soft_state_free(pmugpio_statep, instance);
		return (DDI_FAILURE);
	}

	/* Display information in the banner */
	ddi_report_dev(dip);

	/* Save the dip */
	pmugpio_dip = dip;

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
pmugpio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/* Pointer to soft state */
	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
pmugpio_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result)
{
	dev_t dev;
	int instance, error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)pmugpio_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

void
pmugpio_watchdog_pat(void)
{
	dev_info_t *dip = pmugpio_dip;
	int instance;
	pmugpio_state_t *pmugpio_ptr;
	hrtime_t now;
	uint8_t value;

	if (dip == NULL) {
		return;
	}
	instance = ddi_get_instance(dip);
	pmugpio_ptr = ddi_get_soft_state(pmugpio_statep, instance);
	if (pmugpio_ptr == NULL) {
		return;
	}
	/*
	 * The RMC can read interrupts either high to low OR low to high. As
	 * a result all that needs to happen is that when we hit the time to
	 * send an signal we simply need to change the state.
	 */
	now = gethrtime();
	if ((now - pmugpio_ptr->hw_last_pat) >= PMUGPIO_TWO_SEC) {
		/*
		 * fetch current reg value and invert it
		 */
		switch (pmugpio_ptr->access_type) {
		case PMUGPIO_CPLD:
			value = (CPLD_WATCHDOG ^
			    ddi_get8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg));

			ddi_put8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg, value);
			break;

		case PMUGPIO_MBC:
			value = (uint8_t)(MBC_WATCHDOG ^
			    ddi_get8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg));

			ddi_put8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg, value);
			break;

		case PMUGPIO_OTHER:
			value = (uint8_t)(0xff ^
			    ddi_get8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg));

			ddi_put8(pmugpio_ptr->pmugpio_watchdog_reg_handle,
			    pmugpio_ptr->pmugpio_watchdog_reg, value);
			break;

		default:
			cmn_err(CE_WARN, "pmugpio_watchdog_pat: Invalid type");
		}
		pmugpio_ptr->hw_last_pat = now;
	}
}

void
pmugpio_reset(void)
{
	dev_info_t *dip = pmugpio_dip;
	int instance;
	pmugpio_state_t *pmugpio_ptr;
	uint8_t value;

	if (dip == NULL) {
		return;
	}
	instance = ddi_get_instance(dip);
	pmugpio_ptr = ddi_get_soft_state(pmugpio_statep, instance);
	if (pmugpio_ptr == NULL) {
		return;
	}

	/*
	 * For Chalupa, turn all bits on then off again - pmubus nexus
	 * will ensure that only unmasked bit is affected.
	 * For CPLD and MBC, turn just reset bit on, then off.
	 */
	switch (pmugpio_ptr->access_type) {
	case PMUGPIO_CPLD:
		value = ddi_get8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg);
		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg, (value | CPLD_RESET_SC));

		drv_usecwait(CPLD_RESET_DELAY);

		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg, (value & ~CPLD_RESET_SC));
		break;

	case PMUGPIO_MBC:
		value = ddi_get8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg);
		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg,
		    (value | MBC_PPC_RESET));
		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg,
		    (value & ~MBC_PPC_RESET));
		break;

	case PMUGPIO_OTHER:
		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg, ~0);
		ddi_put8(pmugpio_ptr->pmugpio_reset_reg_handle,
		    pmugpio_ptr->pmugpio_reset_reg, 0);
		break;

	default:
		cmn_err(CE_WARN, "pmugpio_reset: Invalid type");
	}
}

static int
pmugpio_map_regs(dev_info_t *dip, pmugpio_state_t *pmugpio_ptr)
{
	ddi_device_acc_attr_t attr;
	char *pmugpio_type;

	/* The host controller will be little endian */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * Determine access type per FWARC 2005/686.
	 * For Boston and Seattle, the OBP gpio device contains a property
	 * named "gpio-device-type".
	 *
	 * Boston:  gpio-device-type = SUNW,mbc
	 * Seattle: gpio-device-type = SUNW,cpld
	 *
	 * If this property does not exist, we are a legacy Chalupa.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    PMUGPIO_DEVICE_TYPE, &pmugpio_type) == DDI_PROP_SUCCESS) {
		if (strcmp(pmugpio_type, "SUNW,mbc") == 0)
			pmugpio_ptr->access_type = PMUGPIO_MBC;
		else if (strcmp(pmugpio_type, "SUNW,cpld") == 0)
			pmugpio_ptr->access_type = PMUGPIO_CPLD;
		else {
			cmn_err(CE_WARN, "unexpected gpio-device-type: %s\n",
			    pmugpio_type);
			ddi_prop_free(pmugpio_type);
			return (DDI_FAILURE);
		}
		ddi_prop_free(pmugpio_type);
	}
	else
		pmugpio_ptr->access_type = PMUGPIO_OTHER;

	switch (pmugpio_ptr->access_type) {
	case PMUGPIO_CPLD:
	case PMUGPIO_MBC:
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&pmugpio_ptr->pmugpio_reset_reg, 0, 1, &attr,
		    &pmugpio_ptr->pmugpio_reset_reg_handle) != DDI_SUCCESS)
			return (DDI_FAILURE);
		/* MBC and CPLD have reset and watchdog bits in same reg. */
		pmugpio_ptr->pmugpio_watchdog_reg_handle =
		    pmugpio_ptr->pmugpio_reset_reg_handle;
		pmugpio_ptr->pmugpio_watchdog_reg =
		    pmugpio_ptr->pmugpio_reset_reg;
		break;

	case PMUGPIO_OTHER:
		if (ddi_regs_map_setup(dip, 1,
		    (caddr_t *)&pmugpio_ptr->pmugpio_watchdog_reg, 0, 1, &attr,
		    &pmugpio_ptr->pmugpio_watchdog_reg_handle) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		if (ddi_regs_map_setup(dip, 0,
		    (caddr_t *)&pmugpio_ptr->pmugpio_reset_reg, 0, 1, &attr,
		    &pmugpio_ptr->pmugpio_reset_reg_handle) != DDI_SUCCESS) {
			ddi_regs_map_free(
			    &pmugpio_ptr->pmugpio_watchdog_reg_handle);
			return (DDI_FAILURE);
		}
		break;

	default:
		cmn_err(CE_WARN, "pmugpio_map_regs: Invalid type");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
