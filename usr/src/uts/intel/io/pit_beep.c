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
 * Simple beeper support for PC platform, using standard timer 2 beeper.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/beep.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/pit.h>
#include <sys/inttypes.h>

#define	PIT_BEEP_UNIT(dev)	(getminor((dev)))

typedef struct pit_beep_state {
	/* Dip of pit_beep device */
	dev_info_t	*dip;

} pit_beep_state_t;

#define	PIT_BEEP_ON	1
#define	PIT_BEEP_OFF	0

/* Pointer to the state structure */
static void *pit_beep_statep;

static int pit_beep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pit_beep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pit_beep_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static void pit_beep_freq(void *arg, int freq);
static void pit_beep_on(void *arg);
static void pit_beep_off(void *arg);

struct cb_ops pit_beep_cb_ops = {
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


static struct dev_ops pit_beep_ops = {
	DEVO_REV,		/* Devo_rev */
	0,			/* Refcnt */
	pit_beep_info,		/* Info */
	nulldev,		/* Identify */
	nulldev,		/* Probe */
	pit_beep_attach,	/* Attach */
	pit_beep_detach,	/* Detach */
	nodev,			/* Reset */
	&pit_beep_cb_ops,	/* Driver operations */
	0,			/* Bus operations */
	NULL			/* Power */
};


static struct modldrv modldrv = {
	&mod_driverops, 		/* This one is a driver */
	"Intel Pit_beep Driver %I%",    /* Name of the module. */
	&pit_beep_ops,			/* Driver ops */
};


static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};



int
_init(void)
{
	int error;

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&pit_beep_statep,
	    sizeof (pit_beep_state_t), 1)) != 0) {

		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pit_beep_statep);
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
		ddi_soft_state_fini(&pit_beep_statep);
	}

	return (error);
}

/*
 * pit_beep_attach:
 */
static int
pit_beep_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:

			return (DDI_SUCCESS);
		default:

			return (DDI_FAILURE);
	}

	pit_beep_off(dip);

	(void) beep_init((void *)dip, pit_beep_on, pit_beep_off,
	    pit_beep_freq);

	/* Display information in the banner */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}


/*
 * pit_beep_detach:
 */
/* ARGSUSED */
static int
pit_beep_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_SUSPEND:

			/*
			 * If a beep is in progress; fail suspend
			 */
			if (!beep_busy()) {

				return (DDI_SUCCESS);
			} else {

				return (DDI_FAILURE);
			}
		default:

			return (DDI_FAILURE);
	}
}


/*
 * pit_beep_info:
 */
/* ARGSUSED */
static int
pit_beep_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	dev_t dev;
	pit_beep_state_t  *statep;
	int instance, error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = PIT_BEEP_UNIT(dev);

		if ((statep = ddi_get_soft_state(pit_beep_statep,
		    instance)) == NULL) {

			return (DDI_FAILURE);
		}

		*result = (void *)statep->dip;

		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = PIT_BEEP_UNIT(dev);

		*result = (void *)(uintptr_t)instance;

		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;

	}

	return (error);
}


/* ARGSUSED */
static void
pit_beep_freq(void *arg, int freq)
{
	int counter;

	if (freq == 0)
		counter = 0;
	else {
		counter = PIT_HZ / freq;
		if (counter > UINT16_MAX)
			counter = UINT16_MAX;
		else if (counter < 1)
			counter = 1;
	}

	outb(PITCTL_PORT, PIT_C2 | PIT_READMODE | PIT_RATEMODE);
	outb(PITCTR2_PORT, counter & 0xff);
	outb(PITCTR2_PORT, counter >> 8);
}


/* ARGSUSED */
static void
pit_beep_on(void *arg)
{
	outb(PITAUX_PORT, inb(PITAUX_PORT) | (PITAUX_OUT2 | PITAUX_GATE2));
}


/* ARGSUSED */
static void
pit_beep_off(void *arg)
{
	outb(PITAUX_PORT, inb(PITAUX_PORT) & ~(PITAUX_OUT2 | PITAUX_GATE2));
}
