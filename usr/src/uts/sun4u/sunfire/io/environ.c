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
#include <sys/ivintr.h>
#include <sys/callb.h>
#include <sys/autoconf.h>
#include <sys/intreg.h>
#include <sys/modctl.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/fhc.h>
#include <sys/environ.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>

/*
 * Function prototypes
 */
static int environ_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);

static int environ_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

static int environ_init(struct environ_soft_state *softsp);

void environ_add_temp_kstats(struct environ_soft_state *softsp);

static void overtemp_wakeup(void *);

static void environ_overtemp_poll(void);

/*
 * Configuration data structures
 */
static struct cb_ops environ_cb_ops = {
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

static struct dev_ops environ_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* refcnt */
	ddi_no_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	environ_attach,			/* attach */
	environ_detach,			/* detach */
	nulldev,			/* reset */
	&environ_cb_ops,		/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

void *environp;			/* environ soft state hook */

/*
 * Mutex used to protect the soft state list and their data.
 */
static kmutex_t overtemp_mutex;

/* The CV is used to wakeup the thread when needed. */
static kcondvar_t overtemp_cv;

/* linked list of all environ soft states */
struct environ_soft_state *tempsp_list = NULL;

/* overtemp polling routine timeout delay */
static int overtemp_timeout_sec = OVERTEMP_TIMEOUT_SEC;

/* Should the environ_overtemp_poll thread be running? */
static int environ_do_overtemp_thread = 1;

/* Indicates whether or not the overtemp thread has been started */
static int environ_overtemp_thread_started = 0;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* module type, this one is a driver */
	"Environment Leaf",	/* name of module */
	&environ_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

#ifndef lint
char _depends_on[] = "drv/fhc";
#endif  /* lint */

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&environp,
	    sizeof (struct environ_soft_state), 1)) != 0)
		return (error);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ddi_soft_state_fini(&environp);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
environ_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct environ_soft_state *softsp;
	int instance;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(environp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(environp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	/*
	 * The DDI documentation on ddi_getprop() routine says that
	 * you should always use the real dev_t when calling it,
	 * but all calls found in uts use either DDI_DEV_T_ANY
	 * or DDI_DEV_T_NONE. No notes either on how to find the real
	 * dev_t. So we are doing it in two steps.
	 */
	softsp->pdip = ddi_get_parent(softsp->dip);

	if ((softsp->board = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->pdip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM, -1)) == -1) {
		cmn_err(CE_WARN, "environ%d: unable to retrieve %s property",
		    instance, OBP_BOARDNUM);
		goto bad;
	}

	DPRINTF(ENVIRON_ATTACH_DEBUG, ("environ: devi= 0x%p\n, softsp=0x%p,",
	    devi, softsp));

	/*
	 * Init the temperature device here. We start the overtemp
	 * polling thread here.
	 */
	if (environ_init(softsp) != DDI_SUCCESS)
		goto bad;

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");

	ddi_report_dev(devi);

	if (environ_overtemp_thread_started == 0) {
		/*
		 * set up the overtemp mutex and condition variable before
		 * starting the thread.
		 */
		mutex_init(&overtemp_mutex, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&overtemp_cv, NULL, CV_DRIVER, NULL);

		/* Start the overtemp polling thread now. */
		(void) thread_create(NULL, 0, (void (*)())environ_overtemp_poll,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
		environ_overtemp_thread_started++;
	}

	(void) fhc_bdlist_lock(softsp->board);
	fhc_bd_env_set(softsp->board, (void *)softsp);
	fhc_bdlist_unlock();

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(environp, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
environ_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct environ_soft_state *softsp;
	struct environ_soft_state **vect;	/* used in list deletion */
	struct environ_soft_state *temp;	/* used in list deletion */

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(environp, instance);

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

	fhc_bd_env_set(softsp->board, NULL);

	fhc_bdlist_unlock();

	/* remove the environmental kstats if they were allocated */
	if (softsp->environ_ksp)
		kstat_delete(softsp->environ_ksp);
	if (softsp->environ_oksp)
		kstat_delete(softsp->environ_oksp);

	/*
	 * remove from soft state pointer from the singly linked list of
	 * soft state pointers for temperature monitoring.
	 */
	mutex_enter(&overtemp_mutex);

	/*
	 * find the soft state for this instance in the soft state list
	 * and remove it from the list
	 */
	for (temp = tempsp_list, vect = &tempsp_list; temp != NULL;
	    vect = &temp->next, temp = temp->next) {
		if (temp == softsp) {
			*vect = temp->next;
			break;
		}
	}

	mutex_exit(&overtemp_mutex);

	/* unmap the registers (if they have been mapped) */
	if (softsp->temp_reg)
		ddi_unmap_regs(devi, 0, (caddr_t *)&softsp->temp_reg, 0, 0);

	/* deallocate the soft state instance */
	ddi_soft_state_free(environp, instance);

	ddi_prop_remove_all(devi);

	return (DDI_SUCCESS);
}

static int
environ_init(struct environ_soft_state *softsp)
{
	uchar_t tmp;

	/*
	 * If this environment node is on a CPU-less system board, i.e.,
	 * board type MEM_TYPE, then we do not want to map in, read
	 * the temperature register, create the polling entry for
	 * the overtemp polling thread, or create a kstat entry.
	 *
	 * The reason for this is that when no CPU modules are present
	 * on a CPU/Memory board, then the thermistors are not present,
	 * and the output of the A/D convertor is the max 8 bit value (0xFF)
	 */
	if (fhc_bd_type(softsp->board) == MEM_BOARD) {
		return (DDI_SUCCESS);
	}

	/*
	 * Map in the temperature register. Once the temperature register
	 * is mapped, the timeout thread can read the temperature and
	 * update the temperature in the softsp.
	 */
	if (ddi_map_regs(softsp->dip, 0,
	    (caddr_t *)&softsp->temp_reg, 0, 0)) {
		cmn_err(CE_WARN, "environ%d: unable to map temperature "
		    "register", ddi_get_instance(softsp->dip));
		return (DDI_FAILURE);
	}

	/* Initialize the temperature */
	init_temp_arrays(&softsp->tempstat);

	/*
	 * Do a priming read on the ADC, and throw away the first value
	 * read. This is a feature of the ADC hardware. After a power cycle
	 * it does not contains valid data until a read occurs.
	 */
	tmp = *(softsp->temp_reg);

	/* Wait 30 usec for ADC hardware to stabilize. */
	DELAY(30);

#ifdef lint
	tmp = tmp;
#endif

	/*
	 * Now add this soft state structure to the front of the linked list
	 * of soft state structures.
	 */
	mutex_enter(&overtemp_mutex);
	softsp->next = tempsp_list;
	tempsp_list = softsp;
	mutex_exit(&overtemp_mutex);

	/* Create kstats for this instance of the environ driver */
	environ_add_temp_kstats(softsp);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static void
overtemp_wakeup(void *arg)
{
	/*
	 * grab mutex to guarantee that our wakeup call
	 * arrives after we go to sleep -- so we can't sleep forever.
	 */
	mutex_enter(&overtemp_mutex);
	cv_signal(&overtemp_cv);
	mutex_exit(&overtemp_mutex);
}

/*
 * This function polls all the system board digital temperature registers
 * and stores them in the history buffers using the fhc driver support
 * routines.
 * The temperature detected must then be checked against our current
 * policy for what to do in the case of overtemperature situations. We
 * must also allow for manufacturing's use of a heat chamber.
 */
static void
environ_overtemp_poll(void)
{
	struct environ_soft_state *list;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &overtemp_mutex, callb_generic_cpr, "environ");

	/* The overtemp data strcutures are protected by a mutex. */
	mutex_enter(&overtemp_mutex);

	while (environ_do_overtemp_thread) {

		/*
		 * for each environment node that has been attached,
		 * read it and check for overtemp.
		 */
		for (list = tempsp_list; list != NULL; list = list->next) {
			if (list->temp_reg == NULL) {
				continue;
			}

			update_temp(list->pdip, &list->tempstat,
			    *(list->temp_reg));
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);

		/* now have this thread sleep for a while */
		(void) timeout(overtemp_wakeup, NULL, overtemp_timeout_sec*hz);

		cv_wait(&overtemp_cv, &overtemp_mutex);

		CALLB_CPR_SAFE_END(&cprinfo, &overtemp_mutex);
	}
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
	/* NOTREACHED */
}

void
environ_add_temp_kstats(struct environ_soft_state *softsp)
{
	struct  kstat   *tksp;
	struct  kstat   *ttsp;	/* environ temperature test kstat */

	/*
	 * Create the overtemp kstat required for the environment driver.
	 * The kstat instances are tagged with the physical board number
	 * instead of ddi instance number.
	 */
	if ((tksp = kstat_create("unix", softsp->board,
	    OVERTEMP_KSTAT_NAME, "misc", KSTAT_TYPE_RAW,
	    sizeof (struct temp_stats), KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "environ%d: temp kstat_create failed",
			ddi_get_instance(softsp->dip));
	} else {
		tksp->ks_update = overtemp_kstat_update;
		tksp->ks_private = (void *) &softsp->tempstat;
		softsp->environ_ksp = tksp;
		kstat_install(tksp);
	}

	/*
	 * Create the temperature override kstat, for testability.
	 * The kstat instances are tagged with the physical board number
	 * instead of ddi instance number.
	 */
	if ((ttsp = kstat_create("unix", softsp->board,
	    TEMP_OVERRIDE_KSTAT_NAME, "misc", KSTAT_TYPE_RAW, sizeof (short),
	    KSTAT_FLAG_PERSISTENT | KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "environ%d: temp override kstat_create failed",
		    ddi_get_instance(softsp->dip));
	} else {
		ttsp->ks_update = temp_override_kstat_update;
		ttsp->ks_private = (void *) &softsp->tempstat.override;
		softsp->environ_oksp = ttsp;
		kstat_install(ttsp);
	}
}
