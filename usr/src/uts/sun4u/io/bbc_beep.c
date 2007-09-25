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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is the Beep driver for bbc based beep mechanism.
 *
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/devops.h>
#include <sys/bbc_beep.h>
#include <sys/beep.h>


/* Pointer to the state structure */
static void *bbc_beep_statep;


/*
 * Debug stuff
 */
#ifdef DEBUG
int bbc_beep_debug = 0;
#define	BBC_BEEP_DEBUG(args)  if (bbc_beep_debug) cmn_err args
#define	BBC_BEEP_DEBUG1(args)  if (bbc_beep_debug > 1) cmn_err args
#else
#define	BBC_BEEP_DEBUG(args)
#define	BBC_BEEP_DEBUG1(args)
#endif


/*
 * Prototypes
 */
static int bbc_beep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int bbc_beep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int bbc_beep_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static void bbc_beep_freq(void *arg, int freq);
static void bbc_beep_on(void *arg);
static void bbc_beep_off(void *arg);
static void bbc_beep_cleanup(bbc_beep_state_t *);
static int bbc_beep_map_regs(dev_info_t *, bbc_beep_state_t *);
static bbc_beep_state_t *bbc_beep_obtain_state(dev_info_t *);
static unsigned long bbc_beep_hztocounter(int);


struct cb_ops bbc_beep_cb_ops = {
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
	D_64BIT | D_MP | D_NEW| D_HOTPLUG
};


static struct dev_ops bbc_beep_ops = {
	DEVO_REV,		/* Devo_rev */
	0,			/* Refcnt */
	bbc_beep_info,		/* Info */
	nulldev,		/* Identify */
	nulldev,		/* Probe */
	bbc_beep_attach,	/* Attach */
	bbc_beep_detach,	/* Detach */
	nodev,			/* Reset */
	&bbc_beep_cb_ops,	/* Driver operations */
	0,			/* Bus operations */
	ddi_power		/* Power */
};


static struct modldrv modldrv = {
	&mod_driverops, 		/* This one is a driver */
	"BBC Beep Driver %I%", 		/* Name of the module. */
	&bbc_beep_ops,			/* Driver ops */
};


static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&bbc_beep_statep,
	    sizeof (bbc_beep_state_t), 1)) != 0) {

		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&bbc_beep_statep);
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
		ddi_soft_state_fini(&bbc_beep_statep);
	}

	return (error);
}


/*
 * Beep entry points
 */

/*
 * bbc_beep_attach:
 */
static int
bbc_beep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;		/* Instance number */

	/* Pointer to soft state */
	bbc_beep_state_t	*bbc_beeptr = NULL;

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_attach: Start"));

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

	if (ddi_soft_state_zalloc(bbc_beep_statep, instance) != 0) {

		return (DDI_FAILURE);
	}

	bbc_beeptr = ddi_get_soft_state(bbc_beep_statep, instance);

	if (bbc_beeptr == NULL) {

		return (DDI_FAILURE);
	}

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beeptr = 0x%p, instance %x",
	    (void *)bbc_beeptr, instance));

	/* Save the dip */
	bbc_beeptr->bbc_beep_dip = dip;

	/* Initialize beeper mode */
	bbc_beeptr->bbc_beep_mode = BBC_BEEP_OFF;

	/* Map the Beep Control and Beep counter Registers */
	if (bbc_beep_map_regs(dip, bbc_beeptr) != DDI_SUCCESS) {

		BBC_BEEP_DEBUG((CE_WARN, \
		    "bbc_beep_attach: Mapping of bbc registers failed."));

		bbc_beep_cleanup(bbc_beeptr);

		return (DDI_FAILURE);
	}

	(void) beep_init((void *)dip, bbc_beep_on, bbc_beep_off, bbc_beep_freq);

	/* Display information in the banner */
	ddi_report_dev(dip);

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_attach: dip = 0x%p done",
	    (void *)dip));

	return (DDI_SUCCESS);
}


/*
 * bbc_beep_detach:
 */
static int
bbc_beep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/* Pointer to soft state */
	bbc_beep_state_t	*bbc_beeptr = NULL;

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_detach: Start"));

	switch (cmd) {
		case DDI_SUSPEND:
			bbc_beeptr = bbc_beep_obtain_state(dip);

			if (bbc_beeptr == NULL) {

				return (DDI_FAILURE);
			}

			/*
			 * If a beep is in progress; fail suspend
			 */
			if (bbc_beeptr->bbc_beep_mode == BBC_BEEP_OFF) {
				return (DDI_SUCCESS);
			} else {
				return (DDI_FAILURE);
			}
		default:

			return (DDI_FAILURE);
	}
}


/*
 * bbc_beep_info:
 */
/* ARGSUSED */
static int
bbc_beep_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result)
{
	dev_t dev;
	bbc_beep_state_t  *bbc_beeptr;
	int instance, error;

	switch (infocmd) {

	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = BEEP_UNIT(dev);

		if ((bbc_beeptr = ddi_get_soft_state(bbc_beep_statep,
		    instance)) == NULL) {

			return (DDI_FAILURE);
		}

		*result = (void *)bbc_beeptr->bbc_beep_dip;

		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = BEEP_UNIT(dev);

		*result = (void *)(uintptr_t)instance;

		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;

	}

	return (error);
}


/*
 * bbc_beep_freq() :
 *	Set the frequency
 */
static void
bbc_beep_freq(void *arg, int freq)
{
	dev_info_t *dip = (dev_info_t *)arg;
	unsigned long counter;
	int8_t beep_c2 = 0;
	int8_t beep_c3 = 0;

	bbc_beep_state_t *bbc_beeptr = bbc_beep_obtain_state(dip);

	/* Convert the frequency in hz to the bbc counter value */
	counter = bbc_beep_hztocounter(freq);

	/* Extract relevant second and third byte of counter value */
	beep_c2 = (counter & 0xff00) >> 8;
	beep_c3 = (counter & 0xff0000) >> 16;

	/*
	 * We need to write individual bytes instead of writing
	 * all of 32 bits to take care of allignment problem.
	 * Write 0 to LS 8 bits and MS 8 bits
	 * Write beep_c3 to bit 8..15 and beep_c2 to bit 16..24
	 * Little Endian format
	 */
	BEEP_WRITE_COUNTER_REG(0, 0);
	BEEP_WRITE_COUNTER_REG(1, beep_c3);
	BEEP_WRITE_COUNTER_REG(2, beep_c2);
	BEEP_WRITE_COUNTER_REG(3, 0);

	BBC_BEEP_DEBUG1((CE_CONT,
	    "bbc_beep_freq: dip = 0x%p, freq = %d, counter = 0x%x : Done",
	    (void *)dip, freq, (int)counter));
}


/*
 * bbc_beep_on() :
 *	Turn the beeper on
 */
static void
bbc_beep_on(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	bbc_beep_state_t *bbc_beeptr = bbc_beep_obtain_state(dip);

	BEEP_WRITE_CTRL_REG(BBC_BEEP_ON);

	bbc_beeptr->bbc_beep_mode = BBC_BEEP_ON;

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_on: dip = 0x%p done",
	    (void *)dip));
}


/*
 * bbc_beep_off() :
 * 	Turn the beeper off
 */
static void
bbc_beep_off(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	bbc_beep_state_t *bbc_beeptr = bbc_beep_obtain_state(dip);

	BEEP_WRITE_CTRL_REG(BBC_BEEP_OFF);

	bbc_beeptr->bbc_beep_mode = BBC_BEEP_OFF;

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_off: dip = 0x%p done",
	    (void *)dip));
}


/*
 * bbc_beep_map_regs() :
 *
 *	The Keyboard Beep Control Register and Keyboard Beep Counter Register
 *	should be mapped into a non-cacheable portion of the  system
 *	addressable space.
 */
static int
bbc_beep_map_regs(dev_info_t *dip, bbc_beep_state_t *bbc_beeptr)
{
	ddi_device_acc_attr_t attr;

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_map_regs: Start\n"));

	/* The host controller will be little endian */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Map in operational registers */
	if (ddi_regs_map_setup(dip, 0,
	    (caddr_t *)&bbc_beeptr->bbc_beep_regsp,
	    0,
	    sizeof (bbc_beep_regs_t),
	    &attr,
	    &bbc_beeptr->bbc_beep_regs_handle) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_map_regs: done\n"));

	return (DDI_SUCCESS);
}


/*
 * bbc_beep_obtain_state:
 */
static bbc_beep_state_t *
bbc_beep_obtain_state(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);

	bbc_beep_state_t *state = ddi_get_soft_state(bbc_beep_statep, instance);

	ASSERT(state != NULL);

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_obtain_state: done"));

	return (state);
}


/*
 * bbc_beep_cleanup :
 *	Cleanup soft state
 */
static void
bbc_beep_cleanup(bbc_beep_state_t *bbc_beeptr)
{
	int instance = ddi_get_instance(bbc_beeptr->bbc_beep_dip);

	ddi_soft_state_free(bbc_beep_statep, instance);

	BBC_BEEP_DEBUG1((CE_CONT, "bbc_beep_cleanup: done"));
}


/*
 * bbc_beep_hztocounter() :
 *	Given a frequency in hz, find out the value to
 *	be set in the Keyboard Beep Counter register
 *	BBC beeper uses the following formula to calculate
 * 	frequency. The formulae is :
 *	frequency generated = system freq /2^(n+2)
 *	Where n = position of the bit of counter register
 *	that is turned on and can range between 10 to 18.
 *	So in this function, the inputs are frequency generated
 *	and system frequency and we need to find out n, i.e, which
 *	bit to turn on.(Ref. to Section 4.2.22 of the BBC programming
 *	manual).
 */
unsigned long
bbc_beep_hztocounter(int freq)
{
	int 		i;
	unsigned long	counter;
	int 		newfreq, oldfreq;

	int		system_freq;

	/*
	 * Get system frequency for the root dev_info properties
	 */
	system_freq = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    0, "clock-frequency", 0);

	oldfreq = 0;

	/*
	 * Calculate frequency by turning on ith bit and
	 * matching it with the passed frequency and we do this
	 * in a loop for all the relevant bits
	 */
	for (i = BBC_BEEP_MIN_SHIFT, counter = 1 << BBC_BEEP_MSBIT;
	    i >= BBC_BEEP_MAX_SHIFT; i--, counter >>= 1) {

		/*
		 * Calculate the frequency by dividing the system
		 * frequency by 2^i
		 */
		newfreq = system_freq >> i;

		/*
		 * Check if we turn on the ith bit, the
		 * frequency matches exactly or not
		 */
		if (newfreq == freq) {
			/*
			 * Exact match of passed frequency with the
			 * counter value
			 */

			return (counter);
		}

		/*
		 * If calculated frequency is bigger
		 * return the passed frequency
		 */
		if (newfreq > freq) {

			if (i == BBC_BEEP_MIN_SHIFT) {
				/* Input freq is less than the possible min */

				return (counter);
			}

			/*
			 * Find out the nearest frequency to the passed
			 * frequency by comparing the difference between
			 * the calculated frequency and the passed frequency
			 */
			if ((freq - oldfreq) > (newfreq - freq)) {
				/* Return new counter corres. to newfreq */

				return (counter);
			}

			/* Return old counter corresponding to oldfreq */

			return (counter << 1);
		}

		oldfreq = newfreq;
	}

	/*
	 * Input freq is greater than the possible max;
	 * Back off the counter value and return max counter
	 * value possible in the register
	 */
	return (counter << 1);
}
