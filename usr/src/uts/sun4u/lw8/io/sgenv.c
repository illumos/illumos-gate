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
 * Serengeti Environmental Information driver (sgenv)
 *
 * This driver requests the environmental properties from the SC. These
 * request-response transactions are transferred through the SBBC mailbox,
 * between the Domain and the SC.
 *
 * All sensors have the same sort of properties: Low and high limits, warning
 * thresholds, last measured value, time of measurement, units (e.g., degrees
 * Celsius, volts, etc.), and so on.
 *
 * Each sensor is named by a unique Tag. The Tag identifies the geographical
 * location of the sensor in the Serengeti, and what it is the sensor measures.
 *
 * Requestable sensor properties are broken into two types:  Those which are
 * quasi-constant (infrequently change) - e.g., tolerance-defining low and high
 * limits; and those which are volatile (typically change) - e.g., the current
 * measurement.
 *
 * Unfortunately, property sets are too large to comprise a single mailbox
 * message, so the sets are further subdivided into notionally arbitrary
 * collections. NOTE: The SC-mailbox framework now supports fragmented messages
 * which could allow us to request the data in larger chunks in the future.
 *
 * Each collection is fetched by a separate transaction.
 *
 * Firstly there is a transaction to obtain a list of all collections. Each non-
 * zero key in this list is associated whith one of the collections of sensors.
 * (This sparse list of keys is then used as an index to obtain all the sensor
 * data for each collection).
 *
 * For each collection, there is one request-reply transaction to obtain a list
 * of all sensors in that collection and the limits that apply to each; and a
 * separate request-reply transaction to obtain the measurements from the
 * sensors in the collection.
 *
 * The sgenv driver assembles each property set from the constituent
 * collections, and caches the assembled property sets into the appropriate
 * cache (env_cache, board_cache). The caches are created at startup and are
 * updated on receipt of events from the SC. These events (which include DR
 * events and ENV events) notify sgenv of configuration changes and
 * environmental state changes (such as a sensor state change, Fan speed
 * change).
 *
 * The SC-APP maintains a pseudo-sensor in each collection "measuring" changes
 * to the quasi-constants in that collection. By monitoring these pseudo-sensor
 * measurements, the kstat driver avoids redundant or speculative re-fetches of
 * the quasi-constant properties.
 */

#include <sys/time.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/disp.h>

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/sgevents.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/domain.h>
#include <sys/sysevent/env.h>

#include <sys/serengeti.h>
#include <sys/sgfrutypes.h>

#include <sys/sgsbbc.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/sgsbbc_mailbox.h>

#include <sys/sbd_ioctl.h>	/* sbd header files needed for board support */
#include <sys/sbdp_priv.h>
#include <sys/sbd.h>

#include <sys/sgenv_impl.h>


/*
 * Global Variables - can be patched from Solaris
 * ==============================================
 */

/*
 * the maximum amount of time this driver is prepared to wait for the mailbox
 * to reply before it decides to timeout. The value is initially set in the
 * _init() routine to the global Serengeti variable <sbbc_mbox_default_timeout>
 * but could be tuned specifically for SGENV after booting up the system.
 */
int	sgenv_max_mbox_wait_time = 0;

#ifdef DEBUG
/*
 * This variable controls the level of debug output
 */
uint_t		sgenv_debug = SGENV_DEBUG_NONE;
#endif


/*
 * Module Variables
 * ================
 */

/*
 * Driver entry points
 */
static struct cb_ops sgenv_cb_ops = {
	nodev,		/* open() */
	nodev,		/* close() */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	nodev,		/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops sgenv_ops = {
	DEVO_REV,
	0,			/* ref count */
	ddi_getinfo_1to1,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	sgenv_attach,		/* attach() */
	sgenv_detach,		/* detach */
	nodev,			/* reset */
	&sgenv_cb_ops,		/* pointer to cb_ops structure */
	(struct bus_ops *)NULL,
	nulldev,		/* power() */
	ddi_quiesce_not_needed,		/* quiesce() */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. This is a driver */
	"Environmental Driver",		/* Name of the module */
	&sgenv_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* Opaque state structure pointer */
static void		*sgenv_statep;

/*
 * <env_cache> is a cache of all the sensor readings which is persistent
 * between kstat reads. It is created at init and gets updated upon receipt
 * of events from the SC.
 *
 * The kstat_update function takes a copy of the non-zero entries in this
 * cache and creates a temp buffer called env_cache_snapshot. The
 * kstat_snapshot function then bcopies the env_cache_snapshot into the
 * kstat buffer. This is done because there is no way to ensure that the
 * env_cache won't change between the kstat_update and the kstat_snapshot
 * which will cause problems as the update sets the ks_data_size.
 */
static env_sensor_t	*env_cache[SGENV_MAX_HPU_KEYS] = {NULL};
static void		*env_cache_snapshot = NULL;
static size_t		env_cache_snapshot_size = 0;

/*
 * This is set to TRUE the first time env data is stored in the cache
 * so that at least from then on, old data can be returned if a call to
 * the mailbox fails.
 */
static int		env_cache_updated = FALSE;

/*
 * This lock is needed by the variable-sized kstat which returns
 * environmental info. It prevents data-size races with kstat clients.
 */
static kmutex_t		env_kstat_lock;

/*
 * The <env_cache> can be accessed asynchronously by the polling function
 * and the kstat_read framework. This mutex ensures that access to the data
 * is controlled correctly.
 */
static kmutex_t		env_cache_lock;

/*
 * We need to store the last time we asked the SC for environmental information
 * so that we do not send too many requests in a short period of time.
 */
static hrtime_t		last_env_read_time = 0;

/*
 * Variables to coordinate between the handlers which are triggered when
 * the env cache needs to be updated and the thread which does the work.
 */
static volatile int	env_thread_run = 0;
static kthread_t	*env_thread = NULL;
static kt_did_t		env_thread_tid;

static kcondvar_t	env_flag_cond;
static kmutex_t		env_flag_lock;
static boolean_t	env_cache_updating = B_FALSE;
static boolean_t	env_cache_update_needed = B_TRUE;

/*
 * <board_cache> is a cache of all the board status info and it is persistent
 * between kstat reads.
 *
 * The kstat_update function takes a copy of the non-zero entries in this
 * cache and copies them into the board_cache_snapshot buffer. The
 * kstat_snapshot function then bcopies the board_cache_snapshot into the
 * kstat buffer. This is done because there is no way to ensure that the
 * board_cache won't change between the kstat_update and the kstat_snapshot
 * which will cause problems as the update sets the ks_data_size.
 */
static sg_board_info_t	board_cache[SG_MAX_BDS] = { 0 };
static sg_board_info_t	board_cache_snapshot[SG_MAX_BDS] = { 0 };
static int		board_cache_updated = FALSE;

/*
 * This mutex ensures the <board_cache> is not destroyed while the board data
 * is being collected.
 */
static kmutex_t		board_cache_lock;

/*
 * This lock is needed by the variable-sized kstat which returns
 * board status info. It prevents data-size races with kstat clients.
 */
static kmutex_t		board_kstat_lock;

/*
 * This is a count of the number of board readings were stored by
 * the kstat_update routine - this is needed by the kstat_snapshot routine.
 */
static int		board_count = 0;
static int		board_count_snapshot = 0;

/*
 * We need to store the last time we asked the SC for board information
 * so that we do not send too many requests in a short period of time.
 */
static hrtime_t		last_board_read_time = 0;

/*
 * Variables to coordinate between the handlers which are triggered when
 * the board cache needs to be updated and the thread which does the work.
 */
static volatile int	board_thread_run = 0;
static kthread_t	*board_thread = NULL;
static kt_did_t		board_thread_tid;
static kcondvar_t	board_flag_cond;

static kmutex_t		board_flag_lock;
static boolean_t	board_cache_updating = B_FALSE;
static boolean_t	board_cache_update_needed = B_TRUE;

/*
 * Used to keep track of the number of sensors associated with each key.
 * The sum of all the values in this array is used to set ks_data_size.
 */
static int		vol_sensor_count[SGENV_MAX_HPU_KEYS] = {0};

/*
 * This variable keeps a count of the number of errors that have occurred
 * when we make calls to the mailbox for Env or Board data.
 */
static int		sgenv_mbox_error_count = 0;

/*
 * mutex which protects the keyswitch interrupt handler.
 */
static kmutex_t		keysw_hdlr_lock;

/*
 * mutex which protects the env interrupt handler.
 */
static kmutex_t		env_hdlr_lock;

/*
 * mutex which protects the DR handler interrupt handler.
 */
static kmutex_t		dr_hdlr_lock;

/*
 * Payloads of the event handlers.
 */
static sg_event_key_position_t	keysw_payload;
static sbbc_msg_t		keysw_payload_msg;

static sg_event_env_changed_t	env_payload;
static sbbc_msg_t		env_payload_msg;

static sg_event_fan_status_t	fan_payload;
static sbbc_msg_t		fan_payload_msg;

static sg_system_fru_descriptor_t	dr_payload;
static sbbc_msg_t			dr_payload_msg;

/*
 * The following 3 arrays list all possible HPUs, Parts and Device types
 */

/*
 * ensure that all possible HPUs exported, as described in the main comment
 * in <sys/sensor_tag.h>, are accounted for here.
 */
static const hpu_value_t hpus[] = {
	HPU_ENTRY(SG_HPU_TYPE_UNKNOWN),
	HPU_ENTRY(SG_HPU_TYPE_CPU_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_PCI_IO_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_CPCI_IO_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_SP_CPCI_IO_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_REPEATER_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_L2_REPEATER_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_SYSTEM_CONTROLLER_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_SP_SYSTEM_CONTROLLER_BOARD),
	HPU_ENTRY(SG_HPU_TYPE_A123_POWER_SUPPLY),
	HPU_ENTRY(SG_HPU_TYPE_A138_POWER_SUPPLY),
	HPU_ENTRY(SG_HPU_TYPE_A145_POWER_SUPPLY),
	HPU_ENTRY(SG_HPU_TYPE_A152_POWER_SUPPLY),
	HPU_ENTRY(SG_HPU_TYPE_A153_POWER_SUPPLY),
	HPU_ENTRY(SG_HPU_TYPE_RACK_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_SP_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_MD_TOP_IO_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_MD_BOTTOM_IO_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_R12_THREE_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_K12_IO_ONE_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_K12_CPU_THREE_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_R24_IO_FOUR_FAN_TRAY),
	HPU_ENTRY(SG_HPU_TYPE_R24_CPU_SIX_FAN_TRAY),
	0,	(char *)NULL
};

static const struct part_value parts[] = {
	PART_VALUE(SG_SENSOR_PART_SBBC),
	PART_VALUE(SG_SENSOR_PART_SDC),
	PART_VALUE(SG_SENSOR_PART_AR),
	PART_VALUE(SG_SENSOR_PART_CBH),
	PART_VALUE(SG_SENSOR_PART_DX),
	PART_VALUE(SG_SENSOR_PART_CHEETAH),
	PART_VALUE(SG_SENSOR_PART_1_5_VDC),
	PART_VALUE(SG_SENSOR_PART_3_3_VDC),
	PART_VALUE(SG_SENSOR_PART_5_VDC),
	PART_VALUE(SG_SENSOR_PART_12_VDC),
	PART_VALUE(SG_SENSOR_PART_48_VDC),
	PART_VALUE(SG_SENSOR_PART_CURRENT),
	PART_VALUE(SG_SENSOR_PART_BOARD),
	PART_VALUE(SG_SENSOR_PART_SCAPP),
	PART_VALUE(SG_SENSOR_PART_SCHIZO),
	PART_VALUE(SG_SENSOR_PART_FAN),
	0,	(char *)NULL
};

static const struct type_value types[] = {
	TYPE_VALUE(SG_SENSOR_TYPE_CURRENT, SG_CURRENT_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_TEMPERATURE, SG_TEMPERATURE_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_1_5_VDC, SG_1_5_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_1_8_VDC, SG_1_8_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_3_3_VDC, SG_3_3_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_5_VDC, SG_5_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_12_VDC, SG_12_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_48_VDC, SG_48_VDC_SCALE),
	TYPE_VALUE(SG_SENSOR_TYPE_ENVDB, 1),
	TYPE_VALUE(SG_SENSOR_TYPE_COOLING, 1),
	0,	(char *)NULL
};

int
_init(void)
{
	int	error = 0;

	error = ddi_soft_state_init(&sgenv_statep,
	    sizeof (sgenv_soft_state_t), 1);

	if (error)
		return (error);

	error = mod_install(&modlinkage);
	if (error) {
		ddi_soft_state_fini(&sgenv_statep);
		return (error);
	}

	mutex_init(&env_kstat_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&env_cache_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&env_flag_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&env_flag_cond, NULL, CV_DEFAULT, NULL);

	mutex_init(&board_cache_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&board_kstat_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&board_flag_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&board_flag_cond, NULL, CV_DEFAULT, NULL);

	mutex_init(&keysw_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&env_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&dr_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);

	/* set the default timeout value */
	sgenv_max_mbox_wait_time = sbbc_mbox_default_timeout;

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
	int	error = 0;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	mutex_destroy(&env_kstat_lock);
	mutex_destroy(&env_cache_lock);

	mutex_destroy(&board_cache_lock);
	mutex_destroy(&board_kstat_lock);

	mutex_destroy(&keysw_hdlr_lock);
	mutex_destroy(&env_hdlr_lock);
	mutex_destroy(&dr_hdlr_lock);

	ddi_soft_state_fini(&sgenv_statep);

	return (error);
}


static int
sgenv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sgenv_soft_state_t	*softsp;

	int			instance;
	int			err;

	switch (cmd) {
	case DDI_ATTACH:

		instance = ddi_get_instance(dip);

		/* allocate a global sgenv_soft_state structure */
		err = ddi_soft_state_zalloc(sgenv_statep, instance);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "attach: could not allocate state "
			    "structure for inst %d.", instance);
			return (DDI_FAILURE);
		}

		softsp = ddi_get_soft_state(sgenv_statep, instance);
		if (softsp == NULL) {
			ddi_soft_state_free(sgenv_statep, instance);
			cmn_err(CE_WARN, "attach: could not get state "
			    "structure for inst %d.", instance);
			return (DDI_FAILURE);
		}

		softsp->dip = dip;
		softsp->instance = instance;

		err = sgenv_add_kstats(softsp);
		if (err != 0) {
			/*
			 * Some of the kstats may have been created before the
			 * error occurred in sgenv_add_kstats(), so we call
			 * sgenv_remove_kstats() which removes any kstats
			 * already created.
			 */
			sgenv_remove_kstats(softsp);
			ddi_soft_state_free(sgenv_statep, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Before we setup the framework to read the data from the SC
		 * we need to ensure the caches are initialized correctly.
		 */
		sgenv_init_board_cache();
		sgenv_init_env_cache();

		/*
		 * Add the threads which will update the env and board caches
		 * and post events to Sysevent Framework in the background
		 * when the interrupt handlers watching for ENV/DR events
		 * indicate to the threads that they need to do so.
		 */
		err = sgenv_create_cache_update_threads();
		if (err != DDI_SUCCESS) {
			sgenv_remove_kstats(softsp);
			ddi_soft_state_free(sgenv_statep, instance);
			return (DDI_FAILURE);
		}

		err = ddi_create_minor_node(dip, SGENV_DRV_NAME, S_IFCHR,
		    instance, DDI_PSEUDO, 0);
		if (err != DDI_SUCCESS) {
			sgenv_remove_kstats(softsp);
			(void) sgenv_remove_cache_update_threads();
			ddi_soft_state_free(sgenv_statep, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Add the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = sgenv_add_intr_handlers();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to add event handlers");
			(void) sgenv_remove_intr_handlers();
			sgenv_remove_kstats(softsp);
			(void) sgenv_remove_cache_update_threads();
			ddi_soft_state_free(sgenv_statep, instance);
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
sgenv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sgenv_soft_state_t	*softsp;

	int	instance;
	int	err;

	switch (cmd) {
	case DDI_DETACH:

		instance = ddi_get_instance(dip);

		softsp = ddi_get_soft_state(sgenv_statep, instance);
		if (softsp == NULL) {
			cmn_err(CE_WARN, "detach: could not get state "
			    "structure for inst %d.", instance);
			return (DDI_FAILURE);
		}

		err = sgenv_remove_cache_update_threads();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to remove update threads");
		}

		/*
		 * Remove the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = sgenv_remove_intr_handlers();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to remove event handlers");
		}

		sgenv_remove_kstats(softsp);

		ddi_soft_state_free(sgenv_statep, instance);

		ddi_remove_minor_node(dip, NULL);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


static int
sgenv_add_kstats(sgenv_soft_state_t *softsp)
{
	kstat_t		*ksp;
	kstat_named_t	*keyswitch_named_data;

	int		inst = softsp->instance;

	/*
	 * Create the 'keyswitch position' named kstat.
	 */
	ksp = kstat_create(SGENV_DRV_NAME, inst, SG_KEYSWITCH_KSTAT_NAME,
	    "misc", KSTAT_TYPE_NAMED, 1, 0);

	if (ksp != NULL) {
		/* initialize the named kstat */
		keyswitch_named_data = (struct kstat_named *)(ksp->ks_data);

		kstat_named_init(&keyswitch_named_data[0],
		    POSITION_KSTAT_NAME,
		    KSTAT_DATA_INT32);

		ksp->ks_update = sgenv_keyswitch_kstat_update;
		kstat_install(ksp);

		/* update the soft state */
		softsp->keyswitch_ksp = ksp;

	} else {
		cmn_err(CE_WARN, "Keyswitch: kstat_create failed");
		return (-1);
	}


	/*
	 * Environmental Information.
	 */
	ksp = kstat_create(SGENV_DRV_NAME, inst, SG_ENV_INFO_KSTAT_NAME,
	    "misc", KSTAT_TYPE_RAW, 0,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_VAR_SIZE);

	if (ksp != NULL) {
		ksp->ks_data = NULL;
		ksp->ks_data_size = 0;
		ksp->ks_snaptime = 0;
		ksp->ks_update = sgenv_env_info_kstat_update;
		ksp->ks_snapshot = sgenv_env_info_kstat_snapshot;
		ksp->ks_lock = &env_kstat_lock;
		kstat_install(ksp);

		/* update the soft state */
		softsp->env_info_ksp = ksp;

	} else {
		cmn_err(CE_WARN, "Environmental Info: kstat_create failed");
		return (-1);
	}


	/*
	 * Board Status Information.
	 */
	ksp = kstat_create(SGENV_DRV_NAME, inst, SG_BOARD_STATUS_KSTAT_NAME,
	    "misc", KSTAT_TYPE_RAW, 0,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_VAR_SIZE);

	if (ksp != NULL) {
		ksp->ks_data = NULL;
		ksp->ks_data_size = 0;
		ksp->ks_snaptime = 0;
		ksp->ks_update = sgenv_board_info_kstat_update;
		ksp->ks_snapshot = sgenv_board_info_kstat_snapshot;
		ksp->ks_lock = &board_kstat_lock;
		kstat_install(ksp);

		/* update the soft state */
		softsp->board_info_ksp = ksp;

	} else {
		cmn_err(CE_WARN, "Board Status Info: kstat_create failed");
		return (-1);
	}

	return (0);
}


static void
sgenv_remove_kstats(sgenv_soft_state_t *softsp)
{
	kstat_t	*ksp;

	ksp = softsp->keyswitch_ksp;
	if (ksp != NULL) {
		softsp->keyswitch_ksp = NULL;
		kstat_delete(ksp);
	}

	ksp = softsp->env_info_ksp;
	if (ksp != NULL) {
		sgenv_destroy_env_cache();
		softsp->env_info_ksp = NULL;
		ksp->ks_lock = NULL;
		kstat_delete(ksp);
	}

	ksp = softsp->board_info_ksp;
	if (ksp != NULL) {
		softsp->board_info_ksp = NULL;
		ksp->ks_lock = NULL;
		kstat_delete(ksp);
	}
}


/*
 * This function registers mailbox interrupt handlers to watch for certain
 * unsolicited mailbox messages, which indicate that some event has occurred.
 *
 * Currently only the following events are handled:
 *	MBOX_EVENT_KEY_SWITCH
 *	MBOX_EVENT_ENV
 *		- Thresholds/Limits Exceeded
 *		- Fan Status changed
 *
 * ERRORS:
 *	We return DDI_FAILURE if we fail to register any one of the
 *	interrupt handlers.
 */
static int
sgenv_add_intr_handlers(void)
{
	int	err;

	/*
	 * Register an interrupt handler with the sgsbbc driver for the
	 * MBOX_EVENT_KEY_SWITCH events.
	 *	- The virtual keyswitch has changed, we generate a sysevent.
	 */
	keysw_payload_msg.msg_buf = (caddr_t)&keysw_payload;
	keysw_payload_msg.msg_len = sizeof (keysw_payload);

	err = sbbc_mbox_reg_intr(MBOX_EVENT_KEY_SWITCH, sgenv_keyswitch_handler,
	    &keysw_payload_msg, NULL, &keysw_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_KEY_SWITCH "
		    "handler. Err=%d", err);
		return (DDI_FAILURE);
	}

	/*
	 * Register an interrupt handler with the sgsbbc driver for the
	 * MBOX_EVENT_ENV events.
	 *	- Thresholds/Limits Exceeded, we generate a sysevent
	 *	and we update our caches.
	 */
	env_payload_msg.msg_buf = (caddr_t)&env_payload;
	env_payload_msg.msg_len = sizeof (env_payload);

	err = sbbc_mbox_reg_intr(MBOX_EVENT_ENV, sgenv_env_data_handler,
	    &env_payload_msg, NULL, &env_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_ENV "
		    "(env) handler. Err=%d", err);
		return (DDI_FAILURE);
	}

	/*
	 * Register an interrupt handler with the sgsbbc driver for the
	 * MBOX_EVENT_ENV events.
	 *	- Fan Status changed, we generate a sysevent, and
	 *	we update the env cache only.
	 */
	fan_payload_msg.msg_buf = (caddr_t)&fan_payload;
	fan_payload_msg.msg_len = sizeof (fan_payload);

	err = sbbc_mbox_reg_intr(MBOX_EVENT_ENV, sgenv_fan_status_handler,
	    &fan_payload_msg, NULL, &env_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_ENV (fan)"
		    "handler. Err=%d", err);
		return (DDI_FAILURE);
	}

	/*
	 * Register an interrupt handler with the sgsbbc driver for the
	 * MBOX_EVENT_GENERIC events.
	 *	- DR state change, we update our caches.
	 */
	dr_payload_msg.msg_buf = (caddr_t)&dr_payload;
	dr_payload_msg.msg_len = sizeof (dr_payload);

	err = sbbc_mbox_reg_intr(MBOX_EVENT_GENERIC, sgenv_dr_event_handler,
	    &dr_payload_msg, NULL, &dr_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_GENERIC (DR)"
		    "handler. Err=%d", err);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * This function unregisters the mailbox interrupt handlers.
 *
 * ERRORS:
 *	We return DDI_FAILURE if we fail to register any one of the
 *	interrupt handlers.
 */
static int
sgenv_remove_intr_handlers(void)
{
	int	rv = DDI_SUCCESS;
	int	err;

	err = sbbc_mbox_unreg_intr(MBOX_EVENT_KEY_SWITCH,
	    sgenv_keyswitch_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_KEY_SWITCH "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}

	err = sbbc_mbox_unreg_intr(MBOX_EVENT_ENV, sgenv_env_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_ENV (env)"
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}

	err = sbbc_mbox_unreg_intr(MBOX_EVENT_ENV, sgenv_fan_status_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_ENV (fan)"
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}

	err = sbbc_mbox_unreg_intr(MBOX_EVENT_GENERIC, sgenv_dr_event_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_GENERIC (DR) "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}

	return (rv);
}


static int
sgenv_create_cache_update_threads(void)
{
	DCMN_ERR_S(f, "sgenv_create_cache_update_threads()");

	DCMN_ERR_THREAD(CE_NOTE, "Entering %s", f);

	/* Create thread to ensure env_cache is updated */
	env_thread_run = 1;

	env_thread = thread_create(NULL, 0, sgenv_update_env_cache,
	    NULL, 0, &p0, TS_RUN, minclsyspri);
	env_thread_tid = env_thread->t_did;

	/* Create thread to ensure board_cache is updated */
	board_thread_run = 1;

	board_thread = thread_create(NULL, 0, sgenv_update_board_cache,
	    NULL, 0, &p0, TS_RUN, minclsyspri);
	board_thread_tid = board_thread->t_did;

	DCMN_ERR_THREAD(CE_NOTE, "Exiting %s", f);

	return (DDI_SUCCESS);
}


static int
sgenv_remove_cache_update_threads(void)
{
	DCMN_ERR_S(f, "sgenv_remove_cache_update_threads()");

	DCMN_ERR_THREAD(CE_NOTE, "%s: Waiting for cache update threads", f);

	/* Cause the env_cache thread to terminate. */
	mutex_enter(&env_flag_lock);
	env_thread_run = 0;
	cv_signal(&env_flag_cond);
	mutex_exit(&env_flag_lock);

	thread_join(env_thread_tid);

	/* Cause the board_cache thread to terminate. */
	mutex_enter(&board_flag_lock);
	board_thread_run = 0;
	cv_signal(&board_flag_cond);
	mutex_exit(&board_flag_lock);

	thread_join(board_thread_tid);

	DCMN_ERR_THREAD(CE_NOTE, "%s: cache update threads finished", f);

	return (DDI_SUCCESS);
}


static int
sgenv_keyswitch_kstat_update(kstat_t *ksp, int rw)
{
	sg_keyswitch_kstat_t	*keysw_data;

	int8_t	posn;	/* keysw posn read from IO-SRAM */
	int	size;	/* size of IO-SRAM chunk */
	int	rv = 0;	/* return value of iosram_read() */

	keysw_data	= (sg_keyswitch_kstat_t *)ksp->ks_data;

	switch (rw) {
	case KSTAT_WRITE:
		/*
		 * Write not permitted
		 */
		return (EACCES);

	case KSTAT_READ:
		/*
		 * Get the size of the keyswitch IO-SRAM chunk.
		 * This should be one byte.
		 *
		 * If the size is not 1 byte we set the position to UNKNOWN
		 *
		 * Otherwise we read the keyswitch position from IO-SRAM.
		 * Then check that this is a valid keyswitch position.
		 * If it is not valid then something is corrupt and set
		 * the position to UNKNOWN.
		 */
		size = iosram_size(SBBC_KEYSWITCH_KEY);
		if (size != 1) {
			posn = SG_KEYSWITCH_POSN_UNKNOWN;
			rv = -1;

		} else if ((rv = iosram_read(SBBC_KEYSWITCH_KEY, 0,
		    (char *)&posn, size)) != 0) {
			posn = SG_KEYSWITCH_POSN_UNKNOWN;

		} else {
			/* Check posn is not corrupt */
			switch (posn) {
				case SG_KEYSWITCH_POSN_ON:
				case SG_KEYSWITCH_POSN_DIAG:
				case SG_KEYSWITCH_POSN_SECURE:
					/* value read from kstat is OK */
					break;

				default:
					/* value read from kstat is corrupt */
					posn = SG_KEYSWITCH_POSN_UNKNOWN;
					break;
			}
		}

		/* Write position to kstat. */
		keysw_data->keyswitch_position.value.i32 = posn;

		return (rv);

	default:
		return (EINVAL);
	}
}

static void
sgenv_init_env_cache(void)
{
	ASSERT(env_thread_run == 0);
	ASSERT(env_thread == NULL);
}


/*
 * This thread runs in the background and waits for an interrupt handler
 * registered to wait for ENV/DR events from the SC to signal/flag that we
 * need to update our Env Cache.
 */
static void
sgenv_update_env_cache(void)
{
	DCMN_ERR_S(f, "sgenv_update_env_cache()");

	mutex_enter(&env_flag_lock);

	while (env_thread_run == 1) {

		/*
		 * We check to see if the update needed flag is set.
		 * If it is then this means that:
		 *	1) This is the first time through the while loop
		 *	   and we need to initialize the cache.
		 *	2) An interrupt handler was triggered while we
		 *	   we were updating the env cache during the previous
		 *	   iteration of the while loop and we need to refresh
		 *	   the env data to ensure we are completely up to date.
		 *
		 * Otherwise we wait until we get a signal from one of the
		 * interrupt handlers.
		 */
		if (env_cache_update_needed) {
			DCMN_ERR_THREAD(CE_NOTE, "%s: update needed", f);

			env_cache_update_needed = B_FALSE;

		} else {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Waiting for signal", f);

			cv_wait(&env_flag_cond, &env_flag_lock);

			/* Check if we are being asked to terminate */
			if (env_thread_run == 0) {
				break;
			}

			env_cache_updating = B_TRUE;
		}

		mutex_exit(&env_flag_lock);
		(void) sgenv_get_env_info_data();

		(void) sgenv_check_sensor_thresholds();
		mutex_enter(&env_flag_lock);

		if (env_cache_update_needed == B_FALSE)
			env_cache_updating = B_FALSE;
	}

	mutex_exit(&env_flag_lock);

	DCMN_ERR_THREAD(CE_NOTE, "Exiting %s", f);

	env_thread_run = -1;
	thread_exit();
}


/*
 * We always return what is in the env_cache. It is up to the SC to ensure
 * that the env_cache is current by sending events to us when something
 * changes. The cache will then be updated by going to the SC to get the
 * new data. That way the kstat_update code can always be sure that it gets
 * current data without having to wait while the SC responds (slowly) to our
 * request for data.
 *
 * The way the update and snapshot code works, we cannot be guaranteed that
 * someone won't grab the env_cache_lock between the update and snapshot
 * calls so we use a temporary snapshot of the env_cache. We cannot hold
 * any locks across the calls from the update to the snapshot as we are
 * not guaranteed that the snapshot function will be called. So we create
 * the snapshot of the env_cache in the update routine and dump this to the
 * kstat user buffer in the snapshot routine. (There are error conditions in
 * which the snapshot will not be called by the kstat framework so we need
 * to handle these appropriately.)
 */
static int
sgenv_env_info_kstat_update(kstat_t *ksp, int rw)
{
	DCMN_ERR_S(f, "sgenv_env_info_kstat_update()");

	int		err = 0;
	int		key_posn;
	env_sensor_t	*ptr;

	switch (rw) {
	case KSTAT_WRITE:
		/*
		 * Write not permitted
		 */
		return (EACCES);

	case KSTAT_READ:

		mutex_enter(&env_cache_lock);
		/*
		 * We now need to ensure that there is enough room allocated
		 * by the kstat framework to return the data via ks_data.
		 * It is possible there may be no data in the cache but
		 * we still return zero sized kstats to ensure no client breaks
		 */
		sgenv_update_env_kstat_size(ksp);

		/*
		 * If the snapshot still has data (this could be because the
		 * kstat framework discovered an error and did not call the
		 * snapshot code which should have freed this buffer) we free
		 * it here.
		 */
		if ((env_cache_snapshot != NULL) &&
		    (env_cache_snapshot_size > 0)) {
			DCMN_ERR_CACHE(CE_NOTE, "%s freeing "
			    "env_cache_snapshot buf", f);
			kmem_free(env_cache_snapshot, env_cache_snapshot_size);
		}

		/*
		 * Create a new snapshot buffer based on ks_data_size
		 */
		env_cache_snapshot_size = ksp->ks_data_size;
		env_cache_snapshot = kmem_zalloc(
		    env_cache_snapshot_size, KM_SLEEP);

		/*
		 * We need to take a fresh snapshot of the env_cache here.
		 * For each sensor collection, we check to see if there is
		 * data in the cache (ie. != NULL). If there is, we copy it
		 * into the snapshot.
		 */
		ptr = env_cache_snapshot;
		for (key_posn = 0; key_posn < SGENV_MAX_HPU_KEYS; key_posn++) {
			if (vol_sensor_count[key_posn] <= 0)
				continue;

			ASSERT(vol_sensor_count[key_posn] <=
			    SGENV_MAX_SENSORS_PER_KEY);

			/*
			 * <env_cache> entry should have been allocated
			 * in the kstat_update function already.
			 *
			 * If this <env_cache> entry is NULL, then
			 * it has already been destroyed or cleared
			 * and the sensor readings have disappeared.
			 */
			if (env_cache[key_posn] == NULL) {
				DCMN_ERR(CE_NOTE, "!Cache entry %d has "
				    "disappeared", key_posn);
				vol_sensor_count[key_posn] = 0;
				continue;
			}

			bcopy(&env_cache[key_posn][0], ptr,
			    sizeof (env_sensor_t) *
			    vol_sensor_count[key_posn]);
			ptr += vol_sensor_count[key_posn];
		}
		mutex_exit(&env_cache_lock);

		return (err);

	default:
		return (EINVAL);
	}
}

static int
sgenv_env_info_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	DCMN_ERR_S(f, "sgenv_env_info_kstat_snapshot()");

	switch (rw) {
	case KSTAT_WRITE:
		/*
		 * Write not permitted
		 */
		return (EACCES);

	case KSTAT_READ:

		/*
		 * We have taken a snapshot of the env_cache in the
		 * update routine so we simply bcopy this into the
		 * kstat buf. No locks needed here.
		 */
		if (env_cache_snapshot_size > 0)
			bcopy(env_cache_snapshot, buf, env_cache_snapshot_size);

		ksp->ks_snaptime = last_env_read_time;

		/*
		 * Free the memory used by the snapshot. If for some reason
		 * the kstat framework does not call this snapshot routine,
		 * we also have a check in the update routine so the next
		 * time it is called it checks for this condition and frees
		 * the snapshot buffer there.
		 */
		DCMN_ERR_CACHE(CE_NOTE, "%s freeing env_cache_snapshot buf", f);
		kmem_free(env_cache_snapshot, env_cache_snapshot_size);
		env_cache_snapshot = NULL;
		env_cache_snapshot_size = 0;

		return (0);

	default:
		return (EINVAL);
	}
}

static void
sgenv_init_board_cache(void)
{
	int	i;

	ASSERT(board_thread_run == 0);
	ASSERT(board_thread == NULL);

	/*
	 * Init all node-ids to be -1.
	 */
	mutex_enter(&board_cache_lock);
	for (i = 0; i < SG_MAX_BDS; i++)
		board_cache[i].node_id = (-1);
	mutex_exit(&board_cache_lock);
}


/*
 * This thread runs in the background and waits for an interrupt handler
 * registered to wait for DR events from the SC to signal/flag that we
 * need to update our Board Cache.
 */
static void
sgenv_update_board_cache(void)
{
	DCMN_ERR_S(f, "sgenv_update_board_cache()");

	mutex_enter(&board_flag_lock);

	while (board_thread_run == 1) {

		/*
		 * We check to see if the update needed flag is set.
		 * If it is then this means that:
		 *	1) This is the first time through the while loop
		 *	   and we need to initialize the cache.
		 *	2) An interrupt handler was triggered while we
		 *	   we were updating the cache during the previous
		 *	   iteration of the while loop and we need to refresh
		 *	   the env data to ensure we are completely up to date.
		 *
		 * Otherwise we wait until we get a signal from one of the
		 * interrupt handlers.
		 */
		if (board_cache_update_needed) {
			DCMN_ERR_THREAD(CE_NOTE, "%s: update needed", f);
			board_cache_update_needed = B_FALSE;

		} else {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Waiting for signal", f);

			cv_wait(&board_flag_cond, &board_flag_lock);

			/* Check if we are being asked to terminate */
			if (board_thread_run == 0) {
				break;
			}

			board_cache_updating = B_TRUE;
		}

		mutex_exit(&board_flag_lock);
		(void) sgenv_get_board_info_data();
		mutex_enter(&board_flag_lock);

		if (board_cache_update_needed == B_FALSE)
			board_cache_updating = B_FALSE;
	}

	mutex_exit(&board_flag_lock);

	DCMN_ERR_THREAD(CE_NOTE, "Exiting %s", f);

	board_thread_run = -1;
	thread_exit();
}


/*
 * We always return what is in the board_cache. It is up to the SC to ensure
 * that the board_cache is current by sending events to us when something
 * changes. The cache will then be updated by going to the SC to get the
 * new data. That way the kstat_update code can always be sure that it gets
 * current data without having to wait while the SC responds (slowly) to our
 * request for data.
 *
 * The way the update and snapshot code works, we cannot be guaranteed that
 * someone won't grab the board_cache_lock between the update and snapshot
 * calls so we use a snapshot buffer of the board_cache. We cannot hold
 * any locks across the calls from the update to the snapshot as we are
 * not guaranteed that the snapshot function will be called. So we create
 * the snapshot of the board_cache in the update routine and dump this to the
 * kstat user buffer in the snapshot routine. (There are error conditions in
 * which the snapshot will not be called by the kstat framework so we need
 * to handle these appropriately.)
 */
static int
sgenv_board_info_kstat_update(kstat_t *ksp, int rw)
{
	int		i;

	switch (rw) {
	case KSTAT_WRITE:
		/*
		 * Write not permitted
		 */
		return (EACCES);

	case KSTAT_READ:
		/*
		 * The board_cache is created during startup, and so should be
		 * available before a user can log in and trigger a kstat read,
		 * but we check just in case.
		 */
		if (board_cache_updated == FALSE)
			return (ENXIO);

		mutex_enter(&board_cache_lock);

		/*
		 * Set <ks_data_size> to the new number of board readings so
		 * that the snapshot routine can allocate the correctly sized
		 * kstat.
		 */
		ksp->ks_data_size = board_count * sizeof (sg_board_info_t);

		board_count_snapshot = board_count;

		/*
		 * We are now guaranteed that that board_cache is not in flux
		 * (as we have the lock) so we take a copy of the board_cache
		 * into the board_cache_snapshot so that the snapshot routine
		 * can copy it from the board_cache_snapshot into the user kstat
		 * buffer.
		 */
		for (i = 0; i < SG_MAX_BDS; i++) {
			board_cache_snapshot[i] = board_cache[i];
		}

		mutex_exit(&board_cache_lock);

		return (0);

	default:
		return (EINVAL);
	}
}

static int
sgenv_board_info_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	DCMN_ERR_S(f, "sgenv_board_info_kstat_snapshot()");

	sg_board_info_t	*bdp;
	int		i, num_bds = 0;

	switch (rw) {
	case KSTAT_WRITE:
		/*
		 * Write not permitted
		 */
		return (EACCES);

	case KSTAT_READ:

		if (board_cache_updated == FALSE) {
			ksp->ks_data_size = 0;
			ksp->ks_data = NULL;
			return (ENOMEM);
		}

		/*
		 * Update the snap_time with the last time we got fresh data
		 * from the SC.
		 */
		ksp->ks_snaptime = last_board_read_time;

		ASSERT(board_count_snapshot <= SG_MAX_BDS);
		/*
		 * For each entry in the board_cache_snapshot we check to see
		 * if the node_id is != NULL before we copy it into
		 * the kstat buf.
		 */
		for (i = 0; i < SG_MAX_BDS; i++) {
			bdp = &board_cache_snapshot[i];
			DCMN_ERR_CACHE(CE_NOTE, "%s: looking at "
			    "cache_snapshot entry[%d], node=%d",
			    f, i, bdp->node_id);
			if (bdp->node_id >= 0) {
				/*
				 * Need a check to ensure that the buf
				 * is still within the allocated size.
				 * We check how many boards are already
				 * in the user buf before adding one.
				 */
				num_bds++;
				if (num_bds > board_count_snapshot) {
					ksp->ks_data_size = 0;
					ksp->ks_data = NULL;
					DCMN_ERR(CE_WARN, "%s: buf overflow."
					    " %d >= %d.",
					    f, num_bds, board_count_snapshot);
					return (EIO);
				}

				DCMN_ERR_CACHE(CE_NOTE, "%s: about to bcopy"
				    " cache_snapshot entry[%d], node=%d,"
				    " board=%d", f, i, bdp->node_id,
				    bdp->board_num);
				bcopy(bdp, buf, sizeof (sg_board_info_t));
				buf = ((sg_board_info_t *)buf) + 1;
			}
		}
		return (0);

	default:
		return (EINVAL);
	}
}


/*
 * This function coordinates reading the env data from the SC.
 *
 * ERROR:
 *	If an error occurs while making a call to the mailbox and we have data
 *	in the cache from a previous call to the SC, we return an error of 0.
 *	That way the kstat framework will return the old data instead of
 *	returning an error and an empty kstat.
 */
static int
sgenv_get_env_info_data(void)
{
	DCMN_ERR_S(f, "sgenv_get_env_info_data()");

	envresp_key_t	new_keys[SGENV_MAX_HPU_KEYS] = {0};
	envresp_key_t	old_key;
	envresp_key_t	key;

	int	i;

	int	err = 0;	/* return value of func's which get env data */
	int	status = 0;	/* reason why env data func returned an error */

	DCMN_ERR_EVENT(CE_NOTE, "%s: entered.", f);

	err = sgenv_get_hpu_keys(new_keys, &status);

	if (err != 0) {
		/*
		 * If we get an error getting the key values, then we return
		 * as we cannot proceed any farther. If there is old env data
		 * in the cache, then we return zero so that the kstat
		 * framework will export the old data.
		 */
		if (env_cache_updated == FALSE) {
			sgenv_mbox_error_msg("HPU Keys", err, status);
			return (err);
		} else {
			sgenv_mbox_error_msg("HPU Keys", err, status);
			return (0);
		}
	}


	for (i = 0; i < SGENV_MAX_HPU_KEYS; i++) {

		if (vol_sensor_count[i] == 0) {
			/* empty collection */
			old_key = 0;
		} else {
			/*
			 * populated collection:
			 * (assert size is OK, and 1st sensor is pseudo-sensor)
			 */
			ASSERT(env_cache[i] != NULL);
			ASSERT(env_cache[i][0].sd_id.id.sensor_part ==
			    SG_SENSOR_PART_SCAPP);
			ASSERT(env_cache[i][0].sd_id.id.sensor_type ==
			    SG_SENSOR_TYPE_ENVDB);
			ASSERT(SG_INFO_VALUESTATUS(env_cache[i][0].sd_infostamp)
			    == SG_INFO_VALUE_OK);

			old_key = env_cache[i][0].sd_value;
		}

		key = new_keys[i];

		/*
		 * No data is associated with this key position and there was
		 * no data on the previous read either so we simply continue
		 * to the next key position.
		 */
		if ((key == 0) && (old_key == 0)) {
			ASSERT(env_cache[i] == NULL);
			continue;
		}


		/*
		 * We need to grab this lock every time we are going to
		 * update a HPU. However, a kstat_read can grab
		 * the env_cache_lock when it wants to get a snapshot of
		 * the env_cache. This has the affect of stopping the
		 * active env_cache writer after they have updated the
		 * active HPU, allowing the kstat_read to get a dump of
		 * the env_cache, then the env_cache writer can resume
		 * updating the cache. For performance it is more important
		 * that the kstat_read completes quickly so we allow the
		 * kstat_read to interrupt the updating of the env_cache.
		 * The updating can take anything from a few seconds to
		 * several minutes to complete.
		 */
		mutex_enter(&env_cache_lock);

		/*
		 * If the key just read is zero, then the
		 * group of sensors have been removed by
		 * some means and we need to zero out
		 * the env_cache. (this ensures that data
		 * belonging to a removed board is not
		 * returned)
		 */
		if (key == 0) {
			ASSERT(old_key != 0);
			(void) sgenv_clear_env_cache_entry(i);
			mutex_exit(&env_cache_lock);
			continue;
		}

		/*
		 * Check to see if this key has changed since
		 * the last read.
		 *
		 * If it has changed, we need to update everything.
		 *
		 * If it hasn't we simply read the volatiles
		 * and check to see if the constants have changed.
		 */
		if (key != old_key) {
			/*
			 * If the key is non-zero, then a new HPU has
			 * been added to the system or it has changed
			 * somehow and we need to re-read everything.
			 * (we also need to zero out the env_cache as
			 * there may be less sensors returned now and
			 * the old ones may not be overwritten)
			 */

			/*
			 * If the <env_cache> has not already been
			 * allocated for this key position then we
			 * go ahead and allocate it.
			 */
			if (env_cache[i] == NULL) {
				err = sgenv_create_env_cache_entry(i);
				if (err == DDI_FAILURE) {
					mutex_exit(&env_cache_lock);
					continue;
				}
			}

			err = sgenv_get_env_data(new_keys[i], i,
			    SG_GET_ENV_CONSTANTS, &status);
			if (err) {
				err = sgenv_handle_env_data_error(err, status,
				    i, old_key, "Constant Data");
				mutex_exit(&env_cache_lock);
				if (err != DDI_FAILURE) {
					continue;
				} else if (env_cache_updated == TRUE) {
					return (0);
				} else {
					return (DDI_FAILURE);
				}
			}

			err = sgenv_get_env_data(new_keys[i], i,
			    SG_GET_ENV_THRESHOLDS, &status);
			if (err) {
				err = sgenv_handle_env_data_error(err, status,
				    i, old_key, "Threshold Data");
				mutex_exit(&env_cache_lock);
				if (err != DDI_FAILURE) {
					continue;
				} else if (env_cache_updated == TRUE) {
					return (0);
				} else {
					return (DDI_FAILURE);
				}
			}

			err = sgenv_get_env_data(new_keys[i], i,
			    SG_GET_ENV_VOLATILES, &status);
			if (err) {
				err = sgenv_handle_env_data_error(err, status,
				    i, old_key, "Volatile Data (fresh)");
				mutex_exit(&env_cache_lock);
				if (err != DDI_FAILURE) {
					continue;
				} else if (env_cache_updated == TRUE) {
					return (0);
				} else {
					return (DDI_FAILURE);
				}
			}

			/*
			 * As we have successfully got env data for a HPU,
			 * we ensure <env_cache_updated> is set to TRUE so that
			 * in the future, if an error occurs during the mailbox
			 * transfer, we know that there is old data for at
			 * least one HPU in the <env_cache> which could be
			 * returned instead of returning an error to the kstat
			 * framework indicating that we have no data to return.
			 */
			env_cache_updated = TRUE;
			last_env_read_time = gethrtime();

		} else {
			/*
			 * key == old_key
			 *
			 * Handle the case when the value of the old key and
			 * the new key are identical.
			 */
			ASSERT(env_cache[i] != NULL);

			/*
			 * If the keys are identical, then the quasi-constants
			 * should not have changed (and so don't need updating).
			 * Similarly for the threshold readings.
			 */

			/* Update the volatile data */
			err = sgenv_get_env_data(new_keys[i], i,
			    SG_GET_ENV_VOLATILES, &status);
			if (err) {
				err = sgenv_handle_env_data_error(err, status,
				    i, old_key, "Volatile Data (update)");
				mutex_exit(&env_cache_lock);
				if (err == DDI_FAILURE) {
					return (0);
				} else {
					continue;
				}
			}

		}
		mutex_exit(&env_cache_lock);
	}

	return (0);
}


static int
sgenv_get_board_info_data(void)
{
	/*
	 * This array keeps track of the valid nodes in a system. A call is
	 * made to OBP to get the "nodeid" property from all the ssm nodes,
	 * and for each nodeid found, that position in the array is set to
	 * TRUE. For a Serengeti only one position in the array will be TRUE.
	 */
	static uint_t node_present[SSM_MAX_INSTANCES] = {SGENV_NO_NODE_EXISTS};

	static fn_t	f = "sgenv_get_board_info_data()";
	static int	first_time = TRUE;

	sbbc_msg_t	req;
	sbbc_msg_t	resp;
	int		node;	/* loop index */
	int		board;	/* loop index */
	show_board_t	show_bd, *shbp = &show_bd;
	info_t		inform;
	int		status;	/* msg_status returned by response */
	int		rv = 0;	/* return value of call to mailbox */
	sg_board_info_t	*ptr;

	DCMN_ERR_EVENT(CE_NOTE, "%s: entered.", f);

	if (first_time) {
		sgenv_set_valid_node_positions(node_present);
		first_time = FALSE;
	}

	for (node = 0; node < SSM_MAX_INSTANCES; node++) {

		if (node_present[node] == SGENV_NO_NODE_EXISTS)
			continue;

		for (board = 0; board < SG_MAX_BDS; board++) {

			/*
			 * If we have discovered in a previous call to the SC
			 * that there is no board in this slot on this type of
			 * chassis then we don't waste resources asking the SC
			 * for nonexistent data.
			 */
			if ((node_present[node] & (1 << board)) == 0)
				continue;

			inform.board = board;
			inform.node = node;
			inform.revision = 0xdead;

			req.msg_type.type = DR_MBOX;
			req.msg_type.sub_type = DR_MBOX_SHOW_BOARD;
			req.msg_status = SG_MBOX_STATUS_SUCCESS;
			req.msg_len = sizeof (info_t);
			req.msg_bytes = sizeof (info_t);
			req.msg_buf = (caddr_t)&inform;

			bzero(shbp, sizeof (show_board_t));
			shbp->s_cond = -1;
			shbp->s_power = -1;
			shbp->s_assigned = -1;
			shbp->s_claimed = -1;
			shbp->s_present = -1;

			resp.msg_type.type = DR_MBOX;
			resp.msg_type.sub_type = DR_MBOX_SHOW_BOARD;
			resp.msg_bytes = sizeof (show_board_t);
			resp.msg_status = SG_MBOX_STATUS_SUCCESS;
			resp.msg_len = sizeof (show_board_t);
			resp.msg_buf = (caddr_t)shbp;


			/*
			 * We want to avoid the case where an invalid time
			 * is specified by a user (by patching the
			 * global variable <sgenv_max_mbox_wait_time>).
			 *
			 * Any incorrect values are reset to the default time.
			 */
			if (sgenv_max_mbox_wait_time <=
			    max(sbbc_mbox_min_timeout, 0))
				sgenv_max_mbox_wait_time =
				    sbbc_mbox_default_timeout;

			rv = sbbc_mbox_request_response(&req, &resp,
			    sgenv_max_mbox_wait_time);
			status = resp.msg_status;

			if ((rv) || (status != SG_MBOX_STATUS_SUCCESS)) {
				/*
				 * errors from Solaris sgsbbc driver
				 */
				if (status > SG_MBOX_STATUS_SUCCESS) {
					sgenv_mbox_error_msg("Board Info", rv,
					    resp.msg_status);
					return (rv);
				}

				/*
				 * errors from SCAPP
				 */
				if (status == SG_MBOX_STATUS_ILLEGAL_NODE) {
					sgenv_mbox_error_msg("Board Info", rv,
					    resp.msg_status);
					node_present[node] =
					    SGENV_NO_NODE_EXISTS;

					/*
					 * No point looping through the rest of
					 * the boards associated with this node.
					 */
					break;

				} else if (status ==
				    SG_MBOX_STATUS_ILLEGAL_SLOT) {

					/*
					 * We clear the bit representing <board>
					 * in <node> to indicate that this slot
					 * cannot exist on this chassis.
					 */
					node_present[node] &= (~(1 << board) &
					    SGENV_NODE_TYPE_DS);
					continue;

				} else if (status ==
				    SG_MBOX_STATUS_BOARD_ACCESS_DENIED) {
					/*
					 * We cannot access data for this slot,
					 * however we may be able to do so in
					 * the future. We do nothing.
					 */
					rv = rv;
				} else {
					char	err_msg[40];

					(void) sprintf(err_msg,
					    "Board data for "
					    "Node%d/Slot%d", node, board);
					sgenv_mbox_error_msg(err_msg, rv,
					    resp.msg_status);

					if (rv == 0)
						rv = status;

					continue;
				}
			}

			mutex_enter(&board_cache_lock);
			ptr = &board_cache[board];

			/*
			 * Check if the SC returns data for this board.
			 */
			if (shbp->s_assigned == -1) {
				/*
				 * If this cache entry used to have data and
				 * now doesn't we decrement the board_count
				 * clear the env_cache. The board must have
				 * been removed.
				 */
				if (ptr->node_id != -1) {
					board_count--;

					/*
					 * clear board_cache entry by
					 * setting node_id to -1;
					 */
					ptr->node_id = -1;
					DCMN_ERR_CACHE(CE_NOTE, "%s: "
					    "Clearing cache line %d [%p]",
					    f, board, (void *)ptr);
				}
			} else {
				/*
				 * If this cache entry was previously empty
				 * and we now have data for it we increment
				 * the board_count. A new board must have
				 * been added.
				 */
				if (ptr->node_id == -1)
					board_count++;
				/*
				 * update the board_cache entry
				 */
				DCMN_ERR_CACHE(CE_NOTE, "%s: "
				    "Writing data for bd=%d into "
				    " the board_cache at [%p]",
				    f, board, (void *)ptr);
				ptr->node_id = node;
				ptr->board_num = board;
				ptr->condition = shbp->s_cond;
				ptr->assigned = shbp->s_assigned;
				ptr->claimed = shbp->s_claimed;
				ptr->present = shbp->s_present;
				ptr->led.led_status =
				    shbp->s_ledstatus;
				last_board_read_time = gethrtime();
			}
			mutex_exit(&board_cache_lock);
		} /* board */
	} /* node */

	/*
	 * Indicate that have managed to store valid data in the <board_cache>
	 * at least once.
	 */
	if (board_count > 0)
		board_cache_updated = TRUE;


	return (rv);
}


static int
sgenv_get_hpu_keys(envresp_key_t *new, int *status)
{
	sbbc_msg_t	req;	/* request */
	sbbc_msg_t	resp;	/* response */

	int	rv;	/* return value from call to mbox */

	req.msg_type.type = SG_ENV;
	req.msg_type.sub_type = SG_GET_ENV_HPU_KEYS;
	req.msg_status = SG_MBOX_STATUS_SUCCESS;
	req.msg_len = 0;
	req.msg_bytes = 0;

	resp.msg_type.type = SG_ENV;
	resp.msg_type.sub_type = SG_GET_ENV_HPU_KEYS;
	resp.msg_status = SG_MBOX_STATUS_SUCCESS;
	resp.msg_len = sizeof (envresp_key_t) * SGENV_MAX_HPU_KEYS;
	resp.msg_bytes = 0;
	resp.msg_buf = (caddr_t)new;

	/*
	 * We want to avoid the case where an invalid time
	 * is specified by a user (by patching the
	 * global variable <sgenv_max_mbox_wait_time>).
	 *
	 * Any incorrect values are reset to the default time.
	 */
	if (sgenv_max_mbox_wait_time <= max(sbbc_mbox_min_timeout, 0))
		sgenv_max_mbox_wait_time = sbbc_mbox_default_timeout;

	rv = sbbc_mbox_request_response(&req, &resp, sgenv_max_mbox_wait_time);

	*status = resp.msg_status;

	return (rv);
}


static int
sgenv_get_env_data(envresp_key_t key, int key_posn, uint16_t flag, int *status)
{
	/*
	 * Only one of these buffers is ever going to be used in a call
	 * so to save kernel stack space we use a union.
	 */
	union {
		envresp_constants_t	con[SGENV_MAX_SENSORS_PER_KEY];
		envresp_volatiles_t	vol[SGENV_MAX_SENSORS_PER_KEY];
		envresp_thresholds_t	thr[SGENV_MAX_SENSORS_PER_KEY];
	} buf;

	sbbc_msg_t	req;	/* request */
	sbbc_msg_t	resp;	/* response */

	int	i;	/* loop variable for mbox msg_buf */
	int	rv;	/* return value from call to mbox */

	ASSERT(MUTEX_HELD(&env_cache_lock));
	ASSERT(env_cache[key_posn] != NULL);

	if (flag == SG_GET_ENV_CONSTANTS) {
		resp.msg_len = sizeof (buf.con);
		resp.msg_buf = (caddr_t)buf.con;

	} else if (flag == SG_GET_ENV_VOLATILES) {
		resp.msg_len = sizeof (buf.vol);
		resp.msg_buf = (caddr_t)buf.vol;

	} else if (flag == SG_GET_ENV_THRESHOLDS) {
		resp.msg_len = sizeof (buf.thr);
		resp.msg_buf = (caddr_t)buf.thr;

	} else {
		*status = EINVAL;
		return (-1);
	}

	req.msg_type.type = SG_ENV;
	req.msg_type.sub_type = flag;
	req.msg_status = SG_MBOX_STATUS_SUCCESS;
	req.msg_len = 0;
	req.msg_bytes = 0;
	req.msg_data[0] = key;

	resp.msg_type.type = SG_ENV;
	resp.msg_type.sub_type = flag;
	resp.msg_status = SG_MBOX_STATUS_SUCCESS;
	resp.msg_bytes = 0;

	/*
	 * We want to avoid the case where an invalid time
	 * is specified by a user (by patching the
	 * global variable <sgenv_max_mbox_wait_time>).
	 *
	 * Any incorrect values are reset to the default time.
	 */
	if (sgenv_max_mbox_wait_time <= max(sbbc_mbox_min_timeout, 0))
		sgenv_max_mbox_wait_time = sbbc_mbox_default_timeout;


	rv = sbbc_mbox_request_response(&req, &resp, sgenv_max_mbox_wait_time);

	*status = resp.msg_status;

	/*
	 * We now check that the data returned is valid.
	 */
	if (rv != 0) {
		/*
		 * The SBBC driver encountered an error.
		 */
		return (rv);

	} else {
		/*
		 * The SC encountered an error.
		 */
		switch (*status) {
		case SG_MBOX_STATUS_SUCCESS:
			/*
			 * No problems encountered - continue and return the
			 * new data.
			 */
			break;

		case ETIMEDOUT:
			/*
			 * For some reason the mailbox failed to return data
			 * and instead timed out so we return ETIMEDOUT
			 */
			return (ETIMEDOUT);

		case ENXIO:
			/*
			 * no sensors associated with this key, this may have
			 * changed since we read the keys.
			 */
			return (ENXIO);

		default:
			/*
			 * The contents of the mbox message contain corrupt
			 * data. Flag this as an error to be returned.
			 */
			SGENV_PRINT_MBOX_MSG((&resp), "Env info problem");
			return (EINVAL);
		}
	}

	/*
	 * Depending on the type of data returned, save the constant/volatile
	 * data returned in the mailbox message into the <env_cache>.
	 */
	for (i = 0; i < resp.msg_data[0]; i++) {

		if (flag == SG_GET_ENV_CONSTANTS) {
			env_cache[key_posn][i].sd_id.tag_id =
			    buf.con[i].id.tag_id;
			env_cache[key_posn][i].sd_lo =
			    buf.con[i].lo;
			env_cache[key_posn][i].sd_hi =
			    buf.con[i].hi;

		} else if (flag == SG_GET_ENV_VOLATILES) {
			env_cache[key_posn][i].sd_value =
			    buf.vol[i].value;
			env_cache[key_posn][i].sd_infostamp =
			    buf.vol[i].info;

			sgenv_set_sensor_status(&env_cache[key_posn][i]);

		} else if (flag == SG_GET_ENV_THRESHOLDS) {
			env_cache[key_posn][i].sd_lo_warn =
			    buf.thr[i].lo_warn;
			env_cache[key_posn][i].sd_hi_warn =
			    buf.thr[i].hi_warn;
		}
	}

	if (flag == SG_GET_ENV_VOLATILES)
		vol_sensor_count[key_posn] = resp.msg_data[0];

	return (rv);
}


/*
 * This function handles any errors received from the mailbox framework while
 * getting environmental data.
 *
 * INPUT PARAMETERS
 *	err	- return value from call to mailbox framework.
 *	status	- message status returned by mailbox framework.
 *	key	- key from previous (if any) reading of env data.
 *		  Needed to see if we have old data in the <env_cache>.
 *	str	- String indicating what type of env request failed.
 *
 * RETURN VALUES
 *	rv == DDI_FAILURE	- there is no point in continuing processing
 *				  the data, we should exit from the kstat
 *				  framework.
 *	rv != DDI_FAILURE	- error has been handled correctly, continue
 *				  processing the data returned from the SC.
 */
static int
sgenv_handle_env_data_error(int err, int status, int key_posn,
    envresp_key_t key, char *str)
{
	int	rv = DDI_SUCCESS;

	ASSERT(str != (char *)NULL);

	switch (err) {
	case ENXIO:
		/*
		 * The SC has changed the env data associated with this key
		 * since we started getting the data. We cannot tell if the
		 * data has disappeared due to the removal of the board from
		 * our Domain or just that the data has been updated. We
		 * simply return the last known data (if possible) and the
		 * next time we request the env data, the SC will have
		 * finished processing this board so we will receive the
		 * correct key values and we can get the correct data.
		 */
		DCMN_ERR_CACHE(CE_NOTE, "key @ posn %d has changed from %d"
		    " while %s", key_posn, key, str);
		rv = ENXIO;
		break;

	default:
		sgenv_mbox_error_msg(str, err, status);
		rv = DDI_FAILURE;
		break;
	}

	/*
	 * If there was no data in the <env_cache>, we need to clear the data
	 * just added as the <env_cache> will only be partially filled.
	 */
	if (key == 0)
		sgenv_clear_env_cache_entry(key_posn);

	return (rv);
}


/*
 * If the sensor readings for a particular collection of HPUs become invalid,
 * then we clear the cache by freeing up the memory.
 */
static void
sgenv_clear_env_cache_entry(int key_posn)
{
	ASSERT(MUTEX_HELD(&env_cache_lock));

	if (env_cache[key_posn] != NULL) {
		kmem_free(env_cache[key_posn], sizeof (env_sensor_t) *
		    SGENV_MAX_SENSORS_PER_KEY);
		env_cache[key_posn] = NULL;
		vol_sensor_count[key_posn] = 0;
	}
}


static void
sgenv_mbox_error_msg(char *str, int err, int status)
{
	/*
	 * We update the count of errors we have encountered during calls to
	 * the mailbox framework (unless we will cause a wraparound)
	 */
	if (sgenv_mbox_error_count < INT_MAX)
		sgenv_mbox_error_count++;

#ifdef DEBUG
	if ((sgenv_debug & SGENV_DEBUG_MSG) == 0)
		return;

	ASSERT(str != NULL);

	switch (err) {
	case ENOTSUP:
		DCMN_ERR(CE_WARN, "!This system configuration does not "
		"support SGENV");
		break;
	case ETIMEDOUT:
		DCMN_ERR(CE_WARN, "!Mailbox timed out while servicing "
		"SGENV request for %s", str);
		break;
	default:
		DCMN_ERR(CE_WARN, "!Error occurred reading %s, Errno=%d,"
		" Status=%d", str, err, status);
		break;
	}
#endif
}


/*
 * INPUT PARAMETERS
 *	key_posn -	The position in the env_cache for which we want to
 *			allocate space for a HPU's env data.
 *
 * ERROR VALUES
 *	DDI_FAILURE -	We failed to allocate memory for this cache entry.
 *			There is no point asking the SC for env data for this
 *			HPU as we will have nowhere to store it.
 */
static int
sgenv_create_env_cache_entry(int key_posn)
{
	int	i;	/* used to loop thru each sensor to set the status */

	ASSERT(key_posn < SGENV_MAX_HPU_KEYS);
	ASSERT(key_posn >= 0);

	env_cache[key_posn] = (env_sensor_t *)kmem_zalloc(
	    sizeof (env_sensor_t) * SGENV_MAX_SENSORS_PER_KEY, KM_NOSLEEP);
	if (env_cache[key_posn] == NULL) {
		cmn_err(CE_WARN, "Failed to allocate memory for env_cache[%d]",
		    key_posn);
		return (DDI_FAILURE);
	}

	for (i = 0; i < SGENV_MAX_SENSORS_PER_KEY; i++)
		env_cache[key_posn][i].sd_status = SG_SENSOR_STATUS_OK;

	return (DDI_SUCCESS);
}


static void
sgenv_destroy_env_cache(void)
{
	int i;

	ASSERT(MUTEX_HELD(&env_cache_lock) == FALSE);
	mutex_enter(&env_cache_lock);
	for (i = 0; i < SGENV_MAX_HPU_KEYS; i++) {
		if (env_cache[i] != NULL) {
			kmem_free(env_cache[i], sizeof (env_sensor_t) *
			    SGENV_MAX_SENSORS_PER_KEY);
			env_cache[i] = NULL;
			vol_sensor_count[i] = 0;
		}
	}
	env_cache_updated = FALSE;

	mutex_exit(&env_cache_lock);
}

static void
sgenv_update_env_kstat_size(kstat_t *ksp)
{
	int	i;

	ASSERT(MUTEX_HELD(&env_cache_lock));

	/* reinitialize this and recount number of sensors */
	ksp->ks_data_size = 0;

	for (i = 0; i < SGENV_MAX_HPU_KEYS; i++) {
		if (vol_sensor_count[i] <= 0)
			continue;

		ASSERT(vol_sensor_count[i] <= SGENV_MAX_SENSORS_PER_KEY);

		/*
		 * increment ksp->ks_data_size by the number of
		 * sensors in the collection <i>.
		 */
		ksp->ks_data_size += vol_sensor_count[i] *
		    sizeof (env_sensor_t);
	}
	ASSERT(ksp->ks_data_size >= 0);
}


/*
 * This function is triggered by the thread that updates the env_cache.
 * It checks for any sensors which have exceeded their limits/thresholds
 * and generates sysevents for the sensor values that have changed.
 */
/*ARGSUSED*/
static uint_t
sgenv_check_sensor_thresholds(void)
{
	DCMN_ERR_S(f, "sgenv_poll_env()");

	int	key;	/* loop through keys */
	int	i;	/* loops through each sensor for each <key> */

	env_sensor_t		sensor;
	env_sensor_status_t	status;

	DCMN_ERR_EVENT(CE_NOTE, "%s: just been triggered.", f);

	mutex_enter(&env_cache_lock);

	for (key = 0; key < SGENV_MAX_HPU_KEYS; key++) {

		if (vol_sensor_count[key] == 0)
			continue;

		for (i = 0; i < vol_sensor_count[key]; i++) {
			sensor = env_cache[key][i];
			status = sensor.sd_status;

			if (SG_GET_SENSOR_STATUS(status) ==
			    SG_GET_PREV_SENSOR_STATUS(status)) {
				continue;
			}

			/*
			 * This sensor has changed in status since the last
			 * time we polled - we need to inform the sysevent
			 * framework.
			 */
			switch (sensor.sd_id.id.sensor_type) {
			/*
			 * we don't care about the pseudo sensors and
			 * the Fan Status is notified by a separate
			 * unsolicited event so we simply get the next
			 * reading
			 */
			case SG_SENSOR_TYPE_ENVDB:
			case SG_SENSOR_TYPE_COOLING:
				continue;

			/*
			 * We have handled all the special cases by now.
			 */
			default:
				(void) sgenv_process_threshold_event(sensor);
				break;
			}

			SGENV_PRINT_POLL_INFO(sensor);
		}
	}
	mutex_exit(&env_cache_lock);

	return (DDI_SUCCESS);
}


/*
 * This function is passed in an array of length SSM_MAX_INSTANCES and
 * it searches OBP to for ssm nodes, and for each one if finds, it sets the
 * corresponding position in the array to TRUE.
 */
static void
sgenv_set_valid_node_positions(uint_t *node_present)
{
	dev_info_t	*rdip;		/* root dev info ptr */
	dev_info_t	*dip;

	ASSERT(node_present != NULL);

	rdip = ddi_root_node();

	for (dip = ddi_get_child(rdip); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (strncmp("ssm", ddi_node_name(dip), 3) == 0) {
			int	value;

			value = ddi_getprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "nodeid", 0);

			/*
			 * If we get a valid nodeID which has not already
			 * been found in a previous call to this function,
			 * then we set all 10 LSB bits to indicate there may
			 * be a board present in each slot.
			 *
			 * It is the job of sgenv_get_board_info_data() to weed
			 * out the invalid cases when we don't have a
			 * DS chassis.
			 *
			 * NOTE: We make the assumption that a chassis cannot
			 * be DR'ed out, which is true for a Serengeti.
			 * By the time WildCat need this functionality Solaris
			 * will be able to know what kind of a chassis is
			 * present and there will be no need to try and work
			 * this out from the msg_status from the mailbox.
			 */
			if ((value >= 0) &&
			    (value < SSM_MAX_INSTANCES) &&
			    (node_present[value] == SGENV_NO_NODE_EXISTS)) {
				node_present[value] = SGENV_NODE_TYPE_DS;
			}

		}
	}
}


static void
sgenv_set_sensor_status(env_sensor_t *sensor)
{
	env_sensor_status_t	*status;

	ASSERT(sensor != NULL);
	status = &sensor->sd_status;

	/*
	 * Save the previous status so we can compare them later
	 */
	SG_SET_PREV_SENSOR_STATUS(*status, *status);

	switch (sensor->sd_id.id.sensor_type) {
	case SG_SENSOR_TYPE_ENVDB:
		/*
		 * We want the status of this sensor to always be OK
		 * The concept of limits/thresholds do not exist for it.
		 */
		SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_OK);
		break;

	case SG_SENSOR_TYPE_COOLING:
		/*
		 * Fans have no concept of limits/thresholds, they have a state
		 * which we store in the <sd_status> field so that we can see
		 * when this state is changed.
		 */
		if (sensor->sd_value == SGENV_FAN_SPEED_HIGH) {
			SG_SET_SENSOR_STATUS(*status,
			    SG_SENSOR_STATUS_FAN_HIGH);

		} else if (sensor->sd_value == SGENV_FAN_SPEED_LOW) {
			SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_FAN_LOW);

		} else if (sensor->sd_value == SGENV_FAN_SPEED_OFF) {
			SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_FAN_OFF);

		} else {
			SG_SET_SENSOR_STATUS(*status,
			    SG_SENSOR_STATUS_FAN_FAIL);
		}

		/*
		 * If this is the first time this fan status has been read,
		 * then we need to initialize the previous reading to be the
		 * same as the current reading so that an event is not
		 * triggered.
		 *
		 * [ When the env_cache is being created, the status of the
		 *   sensors is set to SG_SENSOR_STATUS_OK, which is not a
		 *   valid Fan status ].
		 */
		if (SG_GET_PREV_SENSOR_STATUS(*status) == SG_SENSOR_STATUS_OK) {
			SG_SET_PREV_SENSOR_STATUS(*status, *status);
		}

		break;

	default:
		if (sensor->sd_value > sensor->sd_hi) {
			SG_SET_SENSOR_STATUS(*status,
			    SG_SENSOR_STATUS_HI_DANGER);

		} else if (sensor->sd_value > sensor->sd_hi_warn) {
			SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_HI_WARN);

		} else if (sensor->sd_value < sensor->sd_lo) {
			SG_SET_SENSOR_STATUS(*status,
			    SG_SENSOR_STATUS_LO_DANGER);

		} else if (sensor->sd_value < sensor->sd_lo_warn) {
			SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_LO_WARN);

		} else {
			SG_SET_SENSOR_STATUS(*status, SG_SENSOR_STATUS_OK);
		}
		break;
	}
}




/*
 * This function, when given an integer arg describing a HPU type,
 * returns the descriptive string associated with this HPU type.
 */
static const char *
sgenv_get_hpu_id_str(uint_t hpu_type)
{
	const hpu_value_t *hpu_list = hpus;

	while (hpu_list->name != (char *)NULL) {
		if (hpu_list->value == hpu_type)
			return (hpu_list->IDstr);
		else
			hpu_list++;
	}
	return ((char *)NULL);
}


/*
 * This function, when given an integer arg describing a sensor part,
 * returns the descriptive string associated with this sensor part.
 */
static const char *
sgenv_get_part_str(uint_t sensor_part)
{
	const part_value_t *part_list = parts;

	while (part_list->name != (char *)NULL) {
		if (part_list->value == sensor_part)
			return (part_list->name);
		else
			part_list++;
	}
	return ((char *)NULL);
}


/*
 * This function, when given an integer arg describing a sensor type,
 * returns the descriptive string associated with this sensor type.
 */
static const char *
sgenv_get_type_str(uint_t sensor_type)
{
	const type_value_t *type_list = types;

	while (type_list->name != (char *)NULL) {
		if (type_list->value == sensor_type)
			return (type_list->name);
		else
			type_list++;
	}
	return ((char *)NULL);
}


/*
 * This function takes a sensor TagID and generates a string describing
 * where in the system the sensor is.
 */
static void
sgenv_tagid_to_string(sensor_id_t id, char *str)
{
	const char	*hpu_str;
	const char	*part_str;
	const char	*type_str;

	ASSERT(str != NULL);

	hpu_str = sgenv_get_hpu_id_str(id.id.hpu_type);
	part_str = sgenv_get_part_str(id.id.sensor_part);
	type_str = sgenv_get_type_str(id.id.sensor_type);

	(void) sprintf(str,
	    "Sensor: Node=%d, Board=%s%d, Device=%s%d, Type=%s%d: reading has ",
	    id.id.node_id,
	    ((hpu_str != NULL) ? hpu_str : ""),
	    id.id.hpu_slot,
	    ((part_str != NULL) ? part_str : ""),
	    id.id.sensor_partnum,
	    ((type_str != NULL) ? type_str : ""),
	    id.id.sensor_typenum);

}


/*
 * This interrupt handler watches for unsolicited mailbox messages from the SC
 * telling it that the Keyswitch Position had changed. It then informs the
 * Sysevent Framework of this change.
 */
static uint_t
sgenv_keyswitch_handler(char *arg)
{
	DCMN_ERR_S(f, "sgenv_keyswitch_handler()");

	sysevent_t		*ev = NULL;
	sysevent_id_t		eid;
	sysevent_value_t	se_val;
	sysevent_attr_list_t	*ev_attr_list = NULL;
	sg_event_key_position_t	*payload = NULL;
	sbbc_msg_t		*msg = NULL;
	int			err;

	DCMN_ERR_EVENT(CE_NOTE, "%s called", f);

	if (arg == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;
	if (msg->msg_buf == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	payload = (sg_event_key_position_t *)msg->msg_buf;
	if (payload == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: payload == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	DCMN_ERR_EVENT(CE_NOTE, "Key posn = %d", (int)*payload);


	/*
	 * Allocate memory for sysevent buffer.
	 */
	ev = sysevent_alloc(EC_DOMAIN, ESC_DOMAIN_STATE_CHANGE,
	    EP_SGENV, SE_NOSLEEP);
	if (ev == NULL) {
		cmn_err(CE_WARN, "%s: Failed to alloc mem for %s/%s event",
		    f, EC_DOMAIN, ESC_DOMAIN_STATE_CHANGE);
		return (DDI_INTR_CLAIMED);
	}


	/*
	 * Set the DOMAIN_WHAT_CHANGED attribute.
	 */
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = DOMAIN_KEYSWITCH;
	err = sysevent_add_attr(&ev_attr_list, DOMAIN_WHAT_CHANGED,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    DOMAIN_WHAT_CHANGED, EC_DOMAIN,
		    ESC_DOMAIN_STATE_CHANGE);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}


	/*
	 * Log this event with sysevent framework.
	 */
	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		cmn_err(CE_WARN, "Failed to attach attr list for %s/%s event",
		    EC_DOMAIN, ESC_DOMAIN_STATE_CHANGE);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}
	err = log_sysevent(ev, SE_NOSLEEP, &eid);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event",
		    EC_DOMAIN, ESC_DOMAIN_STATE_CHANGE);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}

	/* clean up */
	sysevent_free(ev);

	return (DDI_INTR_CLAIMED);
}


/*
 * This interrupt handler watches for unsolicited mailbox messages from the SC
 * telling it that an environmental sensor has exceeded a threshold/limit level
 * or has returned to normal having previously exceeded a threshold/limit level.
 * It then informs the Sysevent Framework of this change and updates the
 * env_cache.
 */
static uint_t
sgenv_env_data_handler(char *arg)
{
	DCMN_ERR_S(f, "sgenv_env_data_handler()");

	sg_event_env_changed_t	*payload = NULL;
	sbbc_msg_t		*msg = NULL;

	DCMN_ERR_EVENT(CE_NOTE, "%s: just been triggered.", f);

	if (arg == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	if (msg->msg_buf == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	payload = (sg_event_env_changed_t *)msg->msg_buf;

	/*
	 * We check the first field of the msg_buf to see if the event_type
	 * is SC_EVENT_ENV, if it is then we handle the event.
	 */
	if (payload->event_type != SC_EVENT_ENV) {
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We now need to signal to the env background thread to ask the SC
	 * for env readings and discover which sensor caused the SC to send
	 * the ENV event before sending a sysevent to userland.
	 */
	sgenv_indicate_cache_update_needed(ENV_CACHE);

	return (DDI_INTR_CLAIMED);
}


/*
 * This interrupt handler watches for unsolicited mailbox messages from the SC
 * telling it that the status of a fan has changed. We register a sysevent
 * and trigger a softint to update the env cache.
 */
static uint_t
sgenv_fan_status_handler(char *arg)
{
	DCMN_ERR_S(f, "sgenv_fan_status_handler()");

	sysevent_t		*ev = NULL;
	sysevent_id_t		eid;
	sysevent_value_t	se_val;
	sysevent_attr_list_t	*ev_attr_list = NULL;
	sg_event_fan_status_t	*payload = NULL;
	sbbc_msg_t		*msg = NULL;
	char			fan_str[MAXNAMELEN];
	int			err;

	DCMN_ERR_EVENT(CE_NOTE, "%s: just been triggered.", f);

	if (arg == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	/*
	 * We check the first field of the msg_buf to see if the event_type
	 * is SC_EVENT_FAN
	 */
	if (msg->msg_buf == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	payload = (sg_event_fan_status_t *)msg->msg_buf;

	/*
	 * If another type of ENV Event triggered this handler then we simply
	 * return now.
	 */
	if (payload->event_type != SC_EVENT_FAN) {
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Allocate memory for sysevent buffer.
	 */
	ev = sysevent_alloc(EC_ENV, ESC_ENV_FAN, EP_SGENV, SE_NOSLEEP);
	if (ev == NULL) {
		cmn_err(CE_WARN, "%s: Failed to alloc mem for %s/%s event",
		    f, EC_ENV, ESC_ENV_FAN);
		return (DDI_INTR_CLAIMED);
	}


	/*
	 * Set the following attributes for this event:
	 *
	 *	ENV_FRU_ID
	 *	ENV_FRU_RESOURCE_ID
	 *	ENV_FRU_DEVICE
	 *	ENV_FRU_STATE
	 *	ENV_MSG
	 *
	 */
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_ID, &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_ID, EC_ENV, ESC_ENV_FAN);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_RESOURCE_ID,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_RESOURCE_ID, EC_ENV, ESC_ENV_FAN);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_DEVICE,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_DEVICE, EC_ENV, ESC_ENV_FAN);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Checks the fan to see if it has failed.
	 */
	se_val.value_type = SE_DATA_TYPE_INT32;
	switch (payload->fan_speed) {
	case SGENV_FAN_SPEED_OFF:
	case SGENV_FAN_SPEED_LOW:
	case SGENV_FAN_SPEED_HIGH:
		se_val.value.sv_int32 = ENV_OK;
		break;

	case SGENV_FAN_SPEED_UNKNOWN:
	default:
		se_val.value.sv_int32 = ENV_FAILED;
		break;
	}

	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_STATE,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_STATE, EC_ENV, ESC_ENV_FAN);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}


	/*
	 * Create the message to be sent to sysevent.
	 */
	(void) sprintf(fan_str,
	    "The status of the fan in Node%d/Slot%d is now ",
	    payload->node_id, payload->slot_number);
	switch (payload->fan_speed) {
	case SGENV_FAN_SPEED_OFF:
		(void) strcat(fan_str, SGENV_FAN_SPEED_OFF_STR);
		break;

	case SGENV_FAN_SPEED_LOW:
		(void) strcat(fan_str, SGENV_FAN_SPEED_LOW_STR);
		break;

	case SGENV_FAN_SPEED_HIGH:
		(void) strcat(fan_str, SGENV_FAN_SPEED_HIGH_STR);
		break;

	case SGENV_FAN_SPEED_UNKNOWN:
	default:
		(void) strcat(fan_str, SGENV_FAN_SPEED_UNKNOWN_STR);
		break;
	}

	DCMN_ERR_EVENT(CE_NOTE, "Fan: %s", fan_str);

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = fan_str;
	err = sysevent_add_attr(&ev_attr_list, ENV_MSG, &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_MSG, EC_ENV, ESC_ENV_FAN);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}


	/*
	 * Log this event with sysevent framework.
	 */
	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		cmn_err(CE_WARN, "Failed to attach attr list for %s/%s event",
		    EC_ENV, ESC_ENV_FAN);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}
	err = log_sysevent(ev, SE_NOSLEEP, &eid);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event",
		    EC_ENV, ESC_ENV_FAN);
		sysevent_free(ev);
		return (DDI_INTR_CLAIMED);
	}
	sysevent_free(ev);

	/*
	 * We now need to signal to the env background thread to ask the SC
	 * for env readings and discover which sensor caused the SC to send
	 * the ENV event before sending a sysevent to userland.
	 */
	sgenv_indicate_cache_update_needed(ENV_CACHE);

	return (DDI_INTR_CLAIMED);
}


/*
 * This function informs the Sysevent Framework that a temperature, voltage
 * or current reading for a sensor has exceeded its threshold/limit value or
 * that the reading has returned to a safe value having exceeded its
 * threshold/limit value previously.
 */
static int
sgenv_process_threshold_event(env_sensor_t sensor)
{
	DCMN_ERR_S(f, "sgenv_process_threshold_event()");

	sysevent_t		*ev = NULL;
	sysevent_id_t		eid;
	sysevent_value_t	se_val;
	sysevent_attr_list_t	*ev_attr_list = NULL;
	int			err;

	char	sensor_str[MAX_TAG_ID_STR_LEN];	/* holds the sensor TagID */

	/*
	 * This function handles the case when a temperature reading passes
	 * a threshold/limit level and also the case when there are power
	 * fluctuations (voltage/current readings pass a threshold/limit level)
	 * so we need to work out which case it is.
	 *
	 * if <temp_event_type> is TRUE, then need to handle an event
	 * of type ESC_ENV_TEMP.
	 */
	int	temp_event_type;

	switch (sensor.sd_id.id.sensor_type) {
	case SG_SENSOR_TYPE_TEMPERATURE:
		temp_event_type = TRUE;
		ev = sysevent_alloc(EC_ENV, ESC_ENV_TEMP, EP_SGENV, SE_NOSLEEP);
		if (ev == NULL) {
			cmn_err(CE_WARN, "Failed to allocate sysevent buffer "
			    "for %s/%s event", EC_ENV, ESC_ENV_TEMP);
			return (DDI_FAILURE);
		}
		break;

	default:
		temp_event_type = FALSE;
		ev = sysevent_alloc(EC_ENV, ESC_ENV_POWER,
		    EP_SGENV, SE_NOSLEEP);
		if (ev == NULL) {
			cmn_err(CE_WARN, "Failed to allocate sysevent buffer "
			    "for %s/%s event", EC_ENV, ESC_ENV_POWER);
			return (DDI_FAILURE);
		}
		break;
	}


	/*
	 * Set the following attributes for this event:
	 *
	 *	ENV_FRU_ID
	 *	ENV_FRU_RESOURCE_ID
	 *	ENV_FRU_DEVICE
	 *	ENV_FRU_STATE
	 *	ENV_MSG
	 *
	 */
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_ID, &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_ID, EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free(ev);
		return (DDI_FAILURE);
	}

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_RESOURCE_ID,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_RESOURCE_ID, EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_FAILURE);
	}

	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = ENV_RESERVED_ATTR;
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_DEVICE,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_DEVICE, EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_FAILURE);
	}


	/*
	 * We need to find out the status of the reading.
	 */
	se_val.value_type = SE_DATA_TYPE_INT32;
	switch (SG_GET_SENSOR_STATUS(sensor.sd_status)) {
	case SG_SENSOR_STATUS_OK:
		se_val.value.sv_int32 = ENV_OK;
		break;

	case SG_SENSOR_STATUS_LO_WARN:
	case SG_SENSOR_STATUS_HI_WARN:
		se_val.value.sv_int32 = ENV_WARNING;
		break;

	case SG_SENSOR_STATUS_LO_DANGER:
	case SG_SENSOR_STATUS_HI_DANGER:
	default:
		se_val.value.sv_int32 = ENV_FAILED;
		break;
	}

	/*
	 * Add ENV_FRU_STATE attribute.
	 */
	err = sysevent_add_attr(&ev_attr_list, ENV_FRU_STATE,
	    &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr[%s] for %s/%s event "
		    "(Err=%d)", ENV_FRU_STATE, EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP: ESC_ENV_POWER),
		    err);
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_FAILURE);
	}


	/*
	 * Save the sensor TagID as a string so that a meaningful message
	 * can be passed to as part of the ENV_MSG attribute.
	 */
	sgenv_tagid_to_string(sensor.sd_id, sensor_str);

	/*
	 * We need to add a string stating what type of event occurred.
	 */
	switch (SG_GET_SENSOR_STATUS(sensor.sd_status)) {
	case SG_SENSOR_STATUS_OK:
		(void) strcat(sensor_str, SGENV_EVENT_MSG_OK);
		break;

	case SG_SENSOR_STATUS_LO_WARN:
		(void) strcat(sensor_str, SGENV_EVENT_MSG_LO_WARN);
		break;

	case SG_SENSOR_STATUS_HI_WARN:
		(void) strcat(sensor_str, SGENV_EVENT_MSG_HI_WARN);
		break;

	case SG_SENSOR_STATUS_LO_DANGER:
		(void) strcat(sensor_str, SGENV_EVENT_MSG_LO_DANGER);
		break;

	case SG_SENSOR_STATUS_HI_DANGER:
		(void) strcat(sensor_str, SGENV_EVENT_MSG_HI_DANGER);
		break;

	default:
		DCMN_ERR_EVENT(CE_NOTE, "%s: Unknown sensor status", f);
		(void) strcat(sensor_str, SGENV_EVENT_MSG_UNKNOWN);
		break;
	}

	DCMN_ERR_EVENT(CE_NOTE, "Temp/Power: %s", sensor_str);

	/*
	 * Add ENV_MSG attribute.
	 */
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = sensor_str;
	err = sysevent_add_attr(&ev_attr_list, ENV_MSG, &se_val, SE_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_MSG, EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_FAILURE);
	}


	/*
	 * Log this event with sysevent framework.
	 */
	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		cmn_err(CE_WARN, "Failed to attach attr list for %s/%s event",
		    EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		return (DDI_FAILURE);
	}
	err = log_sysevent(ev, SE_NOSLEEP, &eid);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event", EC_ENV,
		    (temp_event_type ? ESC_ENV_TEMP : ESC_ENV_POWER));
		sysevent_free(ev);
		return (DDI_FAILURE);
	}
	sysevent_free(ev);

	return (DDI_SUCCESS);
}


/*
 * This function gets called when sgenv is notified of a DR event.
 * We need to update the board and env caches to ensure that they
 * now contain the latest system information..
 */
static uint_t
sgenv_dr_event_handler(char *arg)
{
	DCMN_ERR_S(f, "sgenv_dr_event_handler()");

	sg_system_fru_descriptor_t	*payload = NULL;
	sbbc_msg_t			*msg = NULL;

	DCMN_ERR_EVENT(CE_NOTE, "%s: just been triggered.", f);
	DCMN_ERR_EVENT(CE_NOTE, "%s: Start: %lld", f, gethrtime());


	if (arg == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	if (msg->msg_buf == NULL) {
		DCMN_ERR_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_CLAIMED);
	}

	payload = (sg_system_fru_descriptor_t *)msg->msg_buf;

	/*
	 * We check the event_details field of the msg_buf to see if
	 * we need to invalidate the caches
	 */
	switch (payload->event_details) {
	case SG_EVT_BOARD_ABSENT:
	case SG_EVT_BOARD_PRESENT:
	case SG_EVT_UNASSIGN:
	case SG_EVT_ASSIGN:
	case SG_EVT_UNAVAILABLE:
	case SG_EVT_AVAILABLE:
	case SG_EVT_POWER_OFF:
	case SG_EVT_POWER_ON:
	case SG_EVT_PASSED_TEST:
	case SG_EVT_FAILED_TEST:
		/*
		 * We now need to signal to the background threads to poll the
		 * SC for env readings and board info which may have changed
		 * as a result of the DR changes. This will cause the
		 * env_cache and the board_cache to be updated.
		 */
		DCMN_ERR_EVENT(CE_NOTE, "%s: about to signal to background "
		    "threads due to event %d.", f, payload->event_details);

		sgenv_indicate_cache_update_needed(ENV_CACHE);
		sgenv_indicate_cache_update_needed(BOARD_CACHE);

		break;

	default:
		DCMN_ERR_EVENT(CE_NOTE, "%s: Unknown DR event type.", f);
		break;
	}

	DCMN_ERR_EVENT(CE_NOTE, "%s: Finish: %lld", f, gethrtime());

	return (DDI_INTR_CLAIMED);
}


/*
 * This function is called by the interrupt handlers watching for ENV/DR events
 * from the SC. It indicates to the thread responsible for the cache specified
 * that it needs to update its data.
 */
static void
sgenv_indicate_cache_update_needed(int cache_type)
{
	DCMN_ERR_S(f, "sgenv_indicate_cache_update_needed()");

	/*
	 * If the cache is already being updated, we set a flag to
	 * inform the thread that it needs to reread the data when
	 * it is finished as we cannot be sure if the data was read
	 * before or after the time this handler was triggered.
	 *
	 * Otherwise the thread is waiting for us and we signal
	 * to it to start reading the data.
	 */
	switch (cache_type) {
	case ENV_CACHE:
		mutex_enter(&env_flag_lock);
		if (env_cache_updating) {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Thread already "
			    "updating env cache", f);
			env_cache_update_needed = B_TRUE;

		} else {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Sending signal "
			    "to env thread", f);
			cv_signal(&env_flag_cond);
		}
		mutex_exit(&env_flag_lock);
		break;

	case BOARD_CACHE:
		mutex_enter(&board_flag_lock);
		if (board_cache_updating) {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Thread already "
			    "updating board cache", f);
			board_cache_update_needed = B_TRUE;

		} else {
			DCMN_ERR_THREAD(CE_NOTE, "%s: Sending signal "
			    "to board thread", f);
			cv_signal(&board_flag_cond);
		}
		mutex_exit(&board_flag_lock);
		break;

	default:
		DCMN_ERR(CE_NOTE, "%s: Unknown cache type:0x%x", f, cache_type);
		break;
	}
}
