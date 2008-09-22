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
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>

#include <sys/fhc.h>
#include <sys/sram.h>
#include <sys/promif.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>

/*
 * Function protoypes
 */

static int sram_attach(dev_info_t *, ddi_attach_cmd_t);

static int sram_detach(dev_info_t *, ddi_detach_cmd_t);

static void sram_add_kstats(struct sram_soft_state *);

/*
 * Configuration data structures
 */
static struct cb_ops sram_cb_ops = {
	nulldev,			/* open */
	nulldev,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nodev,				/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	nulldev,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* cb_aread */
	nodev				/* cb_awrite */
};

static struct dev_ops sram_ops = {
	DEVO_REV,			/* rev */
	0,				/* refcnt  */
	ddi_no_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	sram_attach,			/* attach */
	sram_detach,			/* detach */
	nulldev,			/* reset */
	&sram_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};


/*
 * Driver globals
 */
void *sramp;			/* sram soft state hook */
static struct kstat *resetinfo_ksp = NULL;
static int reset_info_created = 0;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Sram Leaf",		/* name of module */
	&sram_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

#ifndef	lint
char _depends_on[] = "drv/fhc";
#endif	/* lint */

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&sramp,
	    sizeof (struct sram_soft_state), 1)) == 0 &&
	    (error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&sramp);
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&sramp);
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
sram_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	struct sram_soft_state *softsp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(sramp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(sramp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	/* get the board number from this devices parent. */
	softsp->pdip = ddi_get_parent(softsp->dip);
	if ((softsp->board = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->pdip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM, -1)) == -1) {
		cmn_err(CE_WARN, "sram%d: unable to retrieve %s property",
		    instance, OBP_BOARDNUM);
		goto bad;
	}

	DPRINTF(SRAM_ATTACH_DEBUG, ("sram%d: devi= 0x%p\n, "
	    " softsp=0x%p\n", instance, devi, softsp));

	/* map in the registers for this device. */
	if (ddi_map_regs(softsp->dip, 0,
	    (caddr_t *)&softsp->sram_base, 0, 0)) {
		cmn_err(CE_WARN, "sram%d: unable to map registers",
		    instance);
		goto bad;
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");

	/* create the kstats for this device. */
	sram_add_kstats(softsp);

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(sramp, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
sram_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct sram_soft_state *softsp;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(sramp, instance);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		(void) fhc_bdlist_lock(softsp->board);
		if (fhc_bd_detachable(softsp->board))
			break;
		else
			fhc_bdlist_unlock();
		/* FALLTHROUGH */

	default:
		return (DDI_FAILURE);
	}

	fhc_bdlist_unlock();

	/*
	 * We do not remove the kstat here. There is only one instance for
	 * the whole machine, and it must remain in existence while the
	 * system is running.
	 */


	/* unmap the registers */
	ddi_unmap_regs(softsp->dip, 0,
	    (caddr_t *)&softsp->sram_base, 0, 0);

	/* free the soft state structure */
	ddi_soft_state_free(sramp, instance);

	ddi_prop_remove_all(devi);

	return (DDI_SUCCESS);
}

/*
 * The Reset-info structure passed up by POST has it's own kstat.
 * It only needs to get created once. So the first sram instance
 * that gets created will check for the OBP property 'reset-info'
 * in the root node of the OBP device tree. If this property exists,
 * then the reset-info kstat will get created. Otherwise it will
 * not get created. This will inform users whether or not a fatal
 * hardware reset has recently occurred.
 */
static void
sram_add_kstats(struct sram_soft_state *softsp)
{
	int reset_size;		/* size of data collected by POST */
	char *ksptr;		/* memory pointer for byte copy */
	char *srptr;		/* pointer to sram for byte copy */
	int i;
	union  {
		char size[4];	/* copy in word byte-by-byte */
		uint_t len;
	} rst_size;

	/*
	 * only one reset_info kstat per system, so don't create it if
	 * it exists already.
	 */
	if (reset_info_created) {
		return;
	}

	/* mark that this code has been run. */
	reset_info_created = 1;

	/* does the root node have a 'fatal-reset-info' property? */
	if (prom_getprop(prom_rootnode(), "fatal-reset-info",
	    (caddr_t)&softsp->offset) == -1) {
		return;
	}

	/* XXX - workaround for OBP bug */
	softsp->reset_info = softsp->sram_base + softsp->offset;

	/*
	 * First read size. In case FW has not word aligned structure,
	 * copy the unsigned int into a 4 byte union, then read it out as
	 * an inteeger.
	 */
	for (i = 0, srptr = softsp->reset_info; i < 4; i++) {
		rst_size.size[i] = *srptr++;
	}
	reset_size = rst_size.len;

	/*
	 * If the reset size is zero, then POST did not
	 * record any info.
	 */
	if ((uint_t)reset_size == 0) {
		return;
	}

	/* Check for illegal size values. */
	if ((uint_t)reset_size > MX_RSTINFO_SZ) {
		cmn_err(CE_NOTE, "sram%d: illegal "
		    "reset_size: 0x%x",
		    ddi_get_instance(softsp->dip),
		    reset_size);
		return;
	}

	/* create the reset-info kstat */
	resetinfo_ksp = kstat_create("unix", 0,
	    RESETINFO_KSTAT_NAME, "misc", KSTAT_TYPE_RAW,
	    reset_size, KSTAT_FLAG_PERSISTENT);

	if (resetinfo_ksp == NULL) {
		cmn_err(CE_WARN, "sram%d: kstat_create failed",
		    ddi_get_instance(softsp->dip));
		return;
	}

	/*
	 * now copy the data into kstat. Don't use block
	 * copy, the local space sram does not support this.
	 */
	srptr = softsp->reset_info;

	ksptr = (char *)resetinfo_ksp->ks_data;

	for (i = 0; i < reset_size; i++) {
		*ksptr++ = *srptr++;
	}

	kstat_install(resetinfo_ksp);
}
