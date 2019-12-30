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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Solaris x86 ACPI ThermalZone Monitor
 */


#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/uadmin.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/sdt.h>

#include "tzmon.h"


#define	TZMON_ENUM_TRIP_POINTS	1
#define	TZMON_ENUM_DEV_LISTS	2
#define	TZMON_ENUM_ALL		(TZMON_ENUM_TRIP_POINTS	| TZMON_ENUM_DEV_LISTS)

/*
 * TZ_TASKQ_NAME_LEN is precisely the length of the string "AcpiThermalMonitor"
 * plus a two-digit instance number plus a NULL.  If the taskq name is changed
 * (particularly if it is lengthened), then this value needs to change.
 */
#define	TZ_TASKQ_NAME_LEN	21

/*
 * Kelvin to Celsius conversion
 * The formula for converting degrees Kelvin to degrees Celsius is
 * C = K - 273.15 (we round to 273.2).  The unit for thermal zone
 * temperatures is tenths of a degree Kelvin.  Use tenth of a degree
 * to convert, then make a whole number out of it.
 */
#define	K_TO_C(temp)		(((temp) - 2732) / 10)


/* cb_ops or dev_ops forward declarations */
static	int	tzmon_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static	int	tzmon_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static	int	tzmon_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* other forward declarations */
static void tzmon_notify_zone(ACPI_HANDLE obj, UINT32 val, void *ctx);
static void tzmon_eval_int(ACPI_HANDLE obj, char *method, int *rv);
static thermal_zone_t *tzmon_alloc_zone();
static void tzmon_free_zone_list();
static void tzmon_discard_buffers(thermal_zone_t *tzp);
static void tzmon_enumerate_zone(ACPI_HANDLE obj, thermal_zone_t *tzp,
	int enum_flag);
static ACPI_STATUS tzmon_zone_callback(ACPI_HANDLE obj, UINT32 nest,
    void *ctx, void **rv);
static void tzmon_find_zones(void);
static void tzmon_monitor(void *ctx);
static void tzmon_set_power_device(ACPI_HANDLE dev, int on_off, char *tz_name);
static void tzmon_set_power(ACPI_BUFFER devlist, int on_off, char *tz_name);
static void tzmon_eval_zone(thermal_zone_t *tzp);
static void tzmon_do_shutdown(void);

extern void halt(char *);

static struct cb_ops	tzmon_cb_ops = {
	nodev,			/* no open routine	*/
	nodev,			/* no close routine	*/
	nodev,			/* not a block driver	*/
	nodev,			/* no print routine	*/
	nodev,			/* no dump routine	*/
	nodev,			/* no read routine	*/
	nodev,			/* no write routine	*/
	nodev,			/* no ioctl routine	*/
	nodev,			/* no devmap routine	*/
	nodev,			/* no mmap routine	*/
	nodev,			/* no segmap routine	*/
	nochpoll,		/* no chpoll routine	*/
	ddi_prop_op,
	0,			/* not a STREAMS driver	*/
	D_NEW | D_MP,		/* safe for multi-thread/multi-processor */
};

static struct dev_ops tzmon_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	tzmon_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	tzmon_attach,		/* devo_attach */
	tzmon_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&tzmon_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)0,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

extern	struct	mod_ops mod_driverops;

static	struct modldrv modldrv = {
	&mod_driverops,
	"ACPI Thermal Zone Monitor",
	&tzmon_ops,
};

static	struct modlinkage modlinkage = {
	MODREV_1,		/* MODREV_1 indicated by manual */
	(void *)&modldrv,
	NULL,			/* termination of list of linkage structures */
};

/* globals for this module */
static dev_info_t	*tzmon_dip;
static thermal_zone_t	*zone_list;
static int		zone_count;
static kmutex_t		zone_list_lock;
static kcondvar_t	zone_list_condvar;


/*
 * _init, _info, and _fini support loading and unloading the driver.
 */
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


static int
tzmon_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (tzmon_dip != NULL)
		return (DDI_FAILURE);

	/*
	 * Check to see if ACPI CA services are available
	 */
	if (AcpiSubsystemStatus() != AE_OK)
		return (DDI_FAILURE);

	mutex_init(&zone_list_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&zone_list_condvar, NULL, CV_DRIVER, NULL);

	tzmon_find_zones();
	mutex_enter(&zone_list_lock);
	if (zone_count < 1) {
		mutex_exit(&zone_list_lock);
		mutex_destroy(&zone_list_lock);
		cv_destroy(&zone_list_condvar);
		return (DDI_FAILURE);
	}
	mutex_exit(&zone_list_lock);

	if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		tzmon_free_zone_list();
		mutex_destroy(&zone_list_lock);
		cv_destroy(&zone_list_condvar);
		return (DDI_FAILURE);
	}

	tzmon_dip = dip;

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
tzmon_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = tzmon_dip;
		if (tzmon_dip == NULL)
			error = DDI_FAILURE;
		else
			error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		error = DDI_SUCCESS;
		break;
	default:
		*result = NULL;
		error = DDI_FAILURE;
	}

	return (error);
}


static int
tzmon_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	thermal_zone_t *tzp = zone_list;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/* free allocated thermal zone name(s) */
	while (tzp != NULL) {
		AcpiOsFree(tzp->zone_name);
		tzp = tzp->next;
	}

	/* discard zone list assets */
	tzmon_free_zone_list();

	ddi_remove_minor_node(dip, NULL);
	tzmon_dip = NULL;

	mutex_destroy(&zone_list_lock);
	cv_destroy(&zone_list_condvar);

	return (DDI_SUCCESS);
}


/*
 * tzmon_notify_zone
 * Thermal zone notification handler.
 */
static void
tzmon_notify_zone(ACPI_HANDLE obj, UINT32 val, void *ctx)
{
	thermal_zone_t *tzp = (thermal_zone_t *)ctx;

	switch (val) {
	case 0x80:	/* Thermal Zone status changed */
		tzmon_eval_zone(tzp);
		break;
	case 0x81:	/* Thermal Zone trip points changed */
		tzmon_enumerate_zone(obj, tzp, TZMON_ENUM_TRIP_POINTS);
		break;
	case 0x82:	/* Device Lists changed */
		tzmon_enumerate_zone(obj, tzp, TZMON_ENUM_DEV_LISTS);
		break;
	case 0x83:	/* Thermal Relationship Table changed */
		/* not handling _TRT objects, so not handling this event */
		DTRACE_PROBE1(trt__change, char *, (char *)tzp->zone_name);
		break;
	default:
		break;
	}
}


/*
 * tzmon_eval_int
 * Evaluate the object/method as an integer.
 */
static void
tzmon_eval_int(ACPI_HANDLE obj, char *method, int *rv)
{

	if (acpica_eval_int(obj, method, rv) != AE_OK)
		*rv = -1;
}


/*
 * tzmon_alloc_zone
 * Allocate memory for the zone structure and initialize it lock mutex.
 */
static thermal_zone_t *
tzmon_alloc_zone()
{
	thermal_zone_t *tzp;

	tzp = kmem_zalloc(sizeof (thermal_zone_t), KM_SLEEP);
	mutex_init(&tzp->lock, NULL, MUTEX_DRIVER, NULL);

	return (tzp);
}


/*
 * tzmon_free_zone_list
 * Free the zone list, either because attach failed or detach initiated.
 */
static void
tzmon_free_zone_list()
{
	thermal_zone_t *tzp = zone_list;

	while (tzp != NULL) {
		thermal_zone_t *next;

		mutex_enter(&tzp->lock);

		/*
		 * Remove the notify handler for the zone.  Not much to
		 * do if this fails (since we are on our way out), so
		 * just ignore failure.
		 */
		(void) AcpiRemoveNotifyHandler(tzp->obj, ACPI_DEVICE_NOTIFY,
		    tzmon_notify_zone);

		/* Shut down monitor thread, if running */
		if (tzp->taskq != NULL) {
			tzp->polling_period = 0;
			cv_broadcast(&zone_list_condvar);

			/* Drop mutex to allow the thread to run */
			mutex_exit(&tzp->lock);
			ddi_taskq_destroy(tzp->taskq);
			mutex_enter(&tzp->lock);
		}

		tzmon_discard_buffers(tzp);
		mutex_exit(&tzp->lock);
		mutex_destroy(&tzp->lock);

		next = tzp->next;
		kmem_free(tzp, sizeof (thermal_zone_t));
		tzp = next;
	}
}


static void
tzmon_discard_buffers(thermal_zone_t *tzp)
{
	int level;

	for (level = 0; level < TZ_NUM_LEVELS; level++) {
		if (tzp->al[level].Pointer != NULL)
			AcpiOsFree(tzp->al[level].Pointer);
	}

	if (tzp->psl.Pointer != NULL)
		AcpiOsFree(tzp->psl.Pointer);
}


/*
 * tzmon_enumerate_zone
 * Enumerates the contents of a thermal zone and updates passed-in
 * thermal_zone or creates a new one if tzp is NULL. Newly-created
 * zones are linked into the global zone_list.
 */
static void
tzmon_enumerate_zone(ACPI_HANDLE obj, thermal_zone_t *tzp, int enum_flag)
{
	ACPI_STATUS status;
	ACPI_BUFFER zone_name;
	int	level;
	int	instance = 0;
	char	abuf[5];

	/*
	 * Newly-created zones and existing zones both require
	 * some individual attention.
	 */
	if (tzp == NULL) {
		/* New zone required */
		tzp = tzmon_alloc_zone();
		mutex_enter(&zone_list_lock);
		tzp->next = zone_list;
		zone_list = tzp;

		/*
		 * It is exceedingly unlikely that instance will exceed 99.
		 * However, if it does, this will cause problems when
		 * creating the taskq for this thermal zone.
		 */
		instance = zone_count;
		zone_count++;
		mutex_exit(&zone_list_lock);
		mutex_enter(&tzp->lock);
		tzp->obj = obj;

		/*
		 * Set to a low level.  Will get set to the actual
		 * current power level when the thread monitor polls
		 * the current temperature.
		 */
		tzp->current_level = 0;

		/* Get the zone name in case we need to display it later */
		zone_name.Length = ACPI_ALLOCATE_BUFFER;
		zone_name.Pointer = NULL;

		status = AcpiGetName(obj, ACPI_FULL_PATHNAME, &zone_name);
		ASSERT(status == AE_OK);

		tzp->zone_name = zone_name.Pointer;

		status = AcpiInstallNotifyHandler(obj, ACPI_DEVICE_NOTIFY,
		    tzmon_notify_zone, (void *)tzp);
		ASSERT(status == AE_OK);
	} else {
		/* Existing zone - toss out allocated items */
		mutex_enter(&tzp->lock);
		ASSERT(tzp->obj == obj);

		if (enum_flag & TZMON_ENUM_DEV_LISTS)
			tzmon_discard_buffers(tzp);
	}

	if (enum_flag & TZMON_ENUM_TRIP_POINTS) {
		for (level = 0; level < TZ_NUM_LEVELS; level++) {
			(void) snprintf(abuf, 5, "_AC%d", level);
			tzmon_eval_int(obj, abuf, &tzp->ac[level]);

		}

		tzmon_eval_int(obj, "_CRT", &tzp->crt);
		tzmon_eval_int(obj, "_HOT", &tzp->hot);
		tzmon_eval_int(obj, "_PSV", &tzp->psv);
	}

	if (enum_flag & TZMON_ENUM_DEV_LISTS) {
		for (level = 0; level < TZ_NUM_LEVELS; level++) {
			if (tzp->ac[level] == -1) {
				tzp->al[level].Length = 0;
				tzp->al[level].Pointer = NULL;
			} else {
				(void) snprintf(abuf, 5, "_AL%d", level);
				tzp->al[level].Length = ACPI_ALLOCATE_BUFFER;
				tzp->al[level].Pointer = NULL;
				if (AcpiEvaluateObjectTyped(obj, abuf, NULL,
				    &tzp->al[level], ACPI_TYPE_PACKAGE) !=
				    AE_OK) {
					DTRACE_PROBE2(alx__missing, int, level,
					    char *, (char *)tzp->zone_name);

					tzp->al[level].Length = 0;
					tzp->al[level].Pointer = NULL;
				}
			}
		}

		tzp->psl.Length = ACPI_ALLOCATE_BUFFER;
		tzp->psl.Pointer = NULL;
		(void) AcpiEvaluateObjectTyped(obj, "_PSL", NULL, &tzp->psl,
		    ACPI_TYPE_PACKAGE);
	}

	tzmon_eval_int(obj, "_TC1", &tzp->tc1);
	tzmon_eval_int(obj, "_TC2", &tzp->tc2);
	tzmon_eval_int(obj, "_TSP", &tzp->tsp);
	tzmon_eval_int(obj, "_TZP", &tzp->tzp);

	if (tzp->tzp == 0) {
		tzp->polling_period = 0;
	} else {
		if (tzp->tzp < 0)
			tzp->polling_period = TZ_DEFAULT_PERIOD;
		else
			tzp->polling_period = tzp->tzp/10;

		/* start monitor thread if needed */
		if (tzp->taskq == NULL) {
			char taskq_name[TZ_TASKQ_NAME_LEN];

			(void) snprintf(taskq_name, TZ_TASKQ_NAME_LEN,
			    "AcpiThermalMonitor%02d", instance);
			tzp->taskq = ddi_taskq_create(tzmon_dip,
			    taskq_name, 1, TASKQ_DEFAULTPRI, 0);
			if (tzp->taskq == NULL) {
				tzp->polling_period = 0;
				cmn_err(CE_WARN, "tzmon: could not create "
				    "monitor thread for thermal zone %s - "
				    "monitor by notify only",
				    (char *)tzp->zone_name);
			} else {
				(void) ddi_taskq_dispatch(tzp->taskq,
				    tzmon_monitor, tzp, DDI_SLEEP);
			}
		}
	}

	mutex_exit(&tzp->lock);
}


/*
 * tzmon_zone_callback
 * Enumerate the thermal zone if it has a _TMP (current thermal zone
 * operating temperature) method.
 */
/*ARGSUSED*/
static ACPI_STATUS
tzmon_zone_callback(ACPI_HANDLE obj, UINT32 nest, void *ctx, void **rv)
{
	ACPI_HANDLE tmpobj;

	/*
	 * We get both ThermalZone() and Scope(\_TZ) objects here;
	 * look for _TMP (without which a zone is invalid) to pick
	 * between them (and ignore invalid zones)
	 */
	if (AcpiGetHandle(obj, "_TMP", &tmpobj) == AE_OK) {
		tzmon_enumerate_zone(obj, NULL, TZMON_ENUM_ALL);
	}

	return (AE_OK);
}


/*
 * tzmon_find_zones
 * Find all of the thermal zones by calling a ACPICA function that
 * walks the ACPI namespace and invokes a callback for each thermal
 * object found.
 */
static void
tzmon_find_zones()
{
	ACPI_STATUS status;
	int retval;

	status = AcpiWalkNamespace(ACPI_TYPE_THERMAL, ACPI_ROOT_OBJECT,
	    8, tzmon_zone_callback, NULL, NULL, (void **)&retval);

	ASSERT(status == AE_OK);
}


/*
 * tzmon_monitor
 * Run as a separate thread, this wakes according to polling period and
 * checks particular objects in the thermal zone.  One instance per
 * thermal zone.
 */
static void
tzmon_monitor(void *ctx)
{
	thermal_zone_t *tzp = (thermal_zone_t *)ctx;
	clock_t ticks;

	do {
		/* Check out the zone */
		tzmon_eval_zone(tzp);

		/* Go back to sleep */
		mutex_enter(&tzp->lock);
		ticks = drv_usectohz(tzp->polling_period * 1000000);
		if (ticks > 0)
			(void) cv_reltimedwait(&zone_list_condvar,
			    &tzp->lock, ticks, TR_CLOCK_TICK);
		mutex_exit(&tzp->lock);
	} while (ticks > 0);
}


/*
 * tzmon_set_power_device
 */
static void
tzmon_set_power_device(ACPI_HANDLE dev, int on_off, char *tz_name)
{
	ACPI_BUFFER rb;
	ACPI_OBJECT *pr0;
	ACPI_STATUS status;
	int i;

	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;
	status = AcpiEvaluateObjectTyped(dev, "_PR0", NULL, &rb,
	    ACPI_TYPE_PACKAGE);
	if (status != AE_OK) {
		DTRACE_PROBE2(alx__error, int, 2, char *, tz_name);
		return;
	}

	pr0 = ((ACPI_OBJECT *)rb.Pointer);
	for (i = 0; i < pr0->Package.Count; i++) {
		status = AcpiEvaluateObject(
		    pr0->Package.Elements[i].Reference.Handle,
		    on_off ? "_ON" : "_OFF", NULL, NULL);
		if (status != AE_OK) {
			DTRACE_PROBE2(alx__error, int, 4, char *, tz_name);
		}
	}

	AcpiOsFree(rb.Pointer);
}


/*
 * tzmon_set_power
 * Turn on or turn off all devices in the supplied list.
 */
static void
tzmon_set_power(ACPI_BUFFER devlist, int on_off, char *tz_name)
{
	ACPI_OBJECT *devs;
	int i;

	devs = ((ACPI_OBJECT *)devlist.Pointer);
	if (devs->Type != ACPI_TYPE_PACKAGE) {
		DTRACE_PROBE2(alx__error, int, 1, char *, tz_name);
		return;
	}

	for (i = 0; i < devs->Package.Count; i++)
		tzmon_set_power_device(
		    devs->Package.Elements[i].Reference.Handle, on_off,
		    tz_name);
}


/*
 * tzmon_eval_zone
 * Evaluate the current conditions within the thermal zone.
 */
static void
tzmon_eval_zone(thermal_zone_t *tzp)
{
	int tmp, new_level, level;

	mutex_enter(&tzp->lock);

	/* get the current temperature from ACPI */
	tzmon_eval_int(tzp->obj, "_TMP", &tmp);
	DTRACE_PROBE4(tz__temp, int, tmp, int, tzp->crt, int, tzp->hot,
	    char *, (char *)tzp->zone_name);

	/* _HOT handling */
	if (tzp->hot > 0 && tmp >= tzp->hot) {
		cmn_err(CE_WARN,
		    "tzmon: Thermal zone (%s) is too hot (%d C); "
		    "initiating shutdown\n",
		    (char *)tzp->zone_name, K_TO_C(tmp));

		tzmon_do_shutdown();
	}

	/* _CRT handling */
	if (tzp->crt > 0 && tmp >= tzp->crt) {
		cmn_err(CE_WARN,
		    "tzmon: Thermal zone (%s) is critically hot (%d C); "
		    "initiating rapid shutdown\n",
		    (char *)tzp->zone_name, K_TO_C(tmp));

		/* shut down (fairly) immediately */
		mdboot(A_REBOOT, AD_HALT, NULL, B_FALSE);
	}

	/*
	 * use the temperature to determine whether the thermal zone
	 * is at a new active cooling threshold level
	 */
	for (level = 0, new_level = -1; level < TZ_NUM_LEVELS; level++) {
		if (tzp->ac[level] >= 0 && (tmp >= tzp->ac[level])) {
			new_level = level;
			break;
		}
	}

	/*
	 * if the active cooling threshold has changed, turn off the
	 * devices associated with the old one and turn on the new one
	 */
	if (tzp->current_level != new_level) {
		if ((tzp->current_level >= 0) &&
		    (tzp->al[tzp->current_level].Length != 0))
			tzmon_set_power(tzp->al[tzp->current_level], 0,
			    (char *)tzp->zone_name);

		if ((new_level >= 0) &&
		    (tzp->al[new_level].Length != 0))
			tzmon_set_power(tzp->al[new_level], 1,
			    (char *)tzp->zone_name);

		tzp->current_level = new_level;
	}

	mutex_exit(&tzp->lock);
}


/*
 * tzmon_do_shutdown
 * Initiates shutdown by sending a SIGPWR signal to init.
 */
static void
tzmon_do_shutdown(void)
{
	proc_t *initpp;

	mutex_enter(&pidlock);
	initpp = prfind(P_INITPID);
	mutex_exit(&pidlock);

	/* if we can't find init, just halt */
	if (initpp == NULL) {
		mdboot(A_REBOOT, AD_HALT, NULL, B_FALSE);
	}

	/* graceful shutdown with inittab and all getting involved */
	psignal(initpp, SIGPWR);
}
