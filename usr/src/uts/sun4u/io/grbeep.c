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
 * This is the Beep driver for SMBUS based beep mechanism.
 * The driver exports the interfaces to set frequency,
 * turn on beeper and turn off beeper to the generic beep
 * module. If a beep is in progress, the driver discards a
 * second beep. This driver uses the 8254 timer to program
 * the beeper ports.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/devops.h>
#include <sys/grbeep.h>
#include <sys/beep.h>


/* Pointer to the state structure */
static void *grbeep_statep;


/*
 * Debug stuff
 */
#ifdef DEBUG
int grbeep_debug = 0;
#define	GRBEEP_DEBUG(args)  if (grbeep_debug) cmn_err args
#define	GRBEEP_DEBUG1(args)  if (grbeep_debug > 1) cmn_err args
#else
#define	GRBEEP_DEBUG(args)
#define	GRBEEP_DEBUG1(args)
#endif


/*
 * Prototypes
 */
static int grbeep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int grbeep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int grbeep_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static void grbeep_freq(void *arg, int freq);
static void grbeep_on(void *arg);
static void grbeep_off(void *arg);
static void grbeep_cleanup(grbeep_state_t *);
static int grbeep_map_regs(dev_info_t *, grbeep_state_t *);
static grbeep_state_t *grbeep_obtain_state(dev_info_t *);


struct cb_ops grbeep_cb_ops = {
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


static struct dev_ops grbeep_ops = {
	DEVO_REV,		/* Devo_rev */
	0,			/* Refcnt */
	grbeep_info,		/* Info */
	nulldev,		/* Identify */
	nulldev,		/* Probe */
	grbeep_attach,		/* Attach */
	grbeep_detach,		/* Detach */
	nodev,			/* Reset */
	&grbeep_cb_ops,		/* Driver operations */
	0,			/* Bus operations */
	NULL,			/* Power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


static struct modldrv modldrv = {
	&mod_driverops, 		/* This one is a driver */
	"SMBUS Beep Driver", 		/* Name of the module. */
	&grbeep_ops,			/* Driver ops */
};


static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&grbeep_statep,
	    sizeof (grbeep_state_t), 1)) != 0) {

		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&grbeep_statep);
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
		ddi_soft_state_fini(&grbeep_statep);
	}

	return (error);
}


/*
 * Beep entry points
 */

/*
 * grbeep_attach:
 */
static int
grbeep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;

	/* Pointer to soft state */
	grbeep_state_t	*grbeeptr = NULL;

	GRBEEP_DEBUG1((CE_CONT, "grbeep_attach: Start"));

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

	if (ddi_soft_state_zalloc(grbeep_statep, instance) != 0) {

		return (DDI_FAILURE);
	}

	grbeeptr = ddi_get_soft_state(grbeep_statep, instance);

	if (grbeeptr == NULL) {

		return (DDI_FAILURE);
	}

	GRBEEP_DEBUG1((CE_CONT, "grbeeptr = 0x%p, instance %x",
	    (void *)grbeeptr, instance));

	/* Save the dip */
	grbeeptr->grbeep_dip = dip;

	/* Initialize beeper mode */
	grbeeptr->grbeep_mode = GRBEEP_OFF;

	/* Map the Beep Control and Beep counter Registers */
	if (grbeep_map_regs(dip, grbeeptr) != DDI_SUCCESS) {

		GRBEEP_DEBUG((CE_WARN,
		    "grbeep_attach: Mapping of beep registers failed."));

		grbeep_cleanup(grbeeptr);

		return (DDI_FAILURE);
	}

	(void) beep_init((void *)dip, grbeep_on, grbeep_off, grbeep_freq);

	/* Display information in the banner */
	ddi_report_dev(dip);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_attach: dip = 0x%p done",
	    (void *)dip));

	return (DDI_SUCCESS);
}


/*
 * grbeep_detach:
 */
static int
grbeep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/* Pointer to soft state */
	grbeep_state_t	*grbeeptr = NULL;

	GRBEEP_DEBUG1((CE_CONT, "grbeep_detach: Start"));

	switch (cmd) {
		case DDI_SUSPEND:
			grbeeptr = grbeep_obtain_state(dip);

			if (grbeeptr == NULL) {

				return (DDI_FAILURE);
			}

			/*
			 * If a beep is in progress; fail suspend
			 */
			if (grbeeptr->grbeep_mode == GRBEEP_OFF) {

				return (DDI_SUCCESS);
			} else {

				return (DDI_FAILURE);
			}
		default:

			return (DDI_FAILURE);
	}
}


/*
 * grbeep_info:
 */
/* ARGSUSED */
static int
grbeep_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result)
{
	dev_t dev;
	grbeep_state_t  *grbeeptr;
	int instance, error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = GRBEEP_UNIT(dev);

		if ((grbeeptr = ddi_get_soft_state(grbeep_statep,
		    instance)) == NULL) {

			return (DDI_FAILURE);
		}

		*result = (void *)grbeeptr->grbeep_dip;

		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = GRBEEP_UNIT(dev);

		*result = (void *)(uintptr_t)instance;

		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;

	}

	return (error);
}


/*
 * grbeep_freq() :
 * 	Set beep frequency
 */
static void
grbeep_freq(void *arg, int freq)
{
	dev_info_t *dip = (dev_info_t *)arg;
	grbeep_state_t *grbeeptr = grbeep_obtain_state(dip);
	int divisor = 0;

	ASSERT(freq != 0);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_freq: dip=0x%p freq=%d mode=%d",
	    (void *)dip, freq, grbeeptr->grbeep_mode));

	GRBEEP_WRITE_FREQ_CONTROL_REG(GRBEEP_CONTROL);

	divisor = GRBEEP_INPUT_FREQ / freq;

	if (divisor > GRBEEP_DIVISOR_MAX) {
		divisor = GRBEEP_DIVISOR_MAX;
	} else if (divisor < GRBEEP_DIVISOR_MIN) {
		divisor = GRBEEP_DIVISOR_MIN;
	}

	GRBEEP_DEBUG1((CE_CONT, "grbeep_freq: first=0x%x second=0x%x",
	    (divisor & 0xff), ((divisor & 0xff00) >> 8)));

	GRBEEP_WRITE_FREQ_DIVISOR_REG(divisor & 0xff);
	GRBEEP_WRITE_FREQ_DIVISOR_REG((divisor & 0xff00) >> 8);
}


/*
 * grbeep_on() :
 *	Turn the beeper on
 */
static void
grbeep_on(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	grbeep_state_t *grbeeptr = grbeep_obtain_state(dip);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_on: dip = 0x%p mode=%d",
	    (void *)dip, grbeeptr->grbeep_mode));

	if (grbeeptr->grbeep_mode == GRBEEP_OFF) {

		grbeeptr->grbeep_mode = GRBEEP_ON;
		GRBEEP_DEBUG1((CE_CONT, "grbeep_on: Starting beep"));
		GRBEEP_WRITE_START_STOP_REG(GRBEEP_START);

	}

	GRBEEP_DEBUG1((CE_CONT, "grbeep_on: dip = 0x%p done", (void *)dip));
}


/*
 * grbeep_off() :
 * 	Turn the beeper off
 */
static void
grbeep_off(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	grbeep_state_t *grbeeptr = grbeep_obtain_state(dip);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_off: dip = 0x%p mode=%d",
	    (void *)dip, grbeeptr->grbeep_mode));

	if (grbeeptr->grbeep_mode == GRBEEP_ON) {

		grbeeptr->grbeep_mode = GRBEEP_OFF;
		GRBEEP_DEBUG1((CE_CONT, "grbeep_off: Stopping beep"));
		GRBEEP_WRITE_START_STOP_REG(GRBEEP_STOP);

	}

	GRBEEP_DEBUG1((CE_CONT, "grbeep_off: dip = 0x%p done", (void *)dip));
}

/*
 * grbeep_map_regs() :
 *
 *	The write beep port register and spkr control register
 *	should be mapped into a non-cacheable portion of the  system
 *	addressable space.
 */
static int
grbeep_map_regs(dev_info_t *dip, grbeep_state_t *grbeeptr)
{
	ddi_device_acc_attr_t attr;

	GRBEEP_DEBUG1((CE_CONT, "grbeep_map_regs: Start"));

	/* The host controller will be little endian */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Map in operational registers */
	if (ddi_regs_map_setup(dip, 2,
	    (caddr_t *)&grbeeptr->grbeep_freq_regs,
	    0,
	    sizeof (grbeep_freq_regs_t),
	    &attr,
	    &grbeeptr->grbeep_freq_regs_handle)
	    != DDI_SUCCESS) {

		GRBEEP_DEBUG((CE_CONT, "grbeep_map_regs: Failed to map"));
		return (DDI_FAILURE);
	}

	/* Map in operational registers */
	if (ddi_regs_map_setup(dip, 3,
	    (caddr_t *)&grbeeptr->grbeep_start_stop_reg,
	    0,
	    1,
	    &attr,
	    &grbeeptr->grbeep_start_stop_reg_handle)
	    != DDI_SUCCESS) {

		GRBEEP_DEBUG((CE_CONT, "grbeep_map_regs: Failed to map"));
		ddi_regs_map_free((void *)&grbeeptr->grbeep_freq_regs_handle);

		return (DDI_FAILURE);
	}

	GRBEEP_DEBUG1((CE_CONT, "grbeep_map_regs: done"));

	return (DDI_SUCCESS);
}


/*
 * grbeep_obtain_state:
 */
static grbeep_state_t *
grbeep_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);

	grbeep_state_t *state = ddi_get_soft_state(grbeep_statep, instance);

	ASSERT(state != NULL);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_obtain_state: done"));

	return (state);
}


/*
 * grbeep_cleanup :
 *	Cleanup soft state
 */
static void
grbeep_cleanup(grbeep_state_t *grbeeptr)
{
	int instance = ddi_get_instance(grbeeptr->grbeep_dip);

	ddi_soft_state_free(grbeep_statep, instance);

	GRBEEP_DEBUG1((CE_CONT, "grbeep_cleanup: done"));
}
