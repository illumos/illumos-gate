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


#include <sys/time.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/disp.h>
#include <sys/strlog.h>

#include <sys/sgevents.h>
#include <sys/serengeti.h>
#include <sys/sgsbbc.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/uadmin.h>
#include <sys/machsystm.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/file.h>
#include <sys/lw8.h>
#include <sys/lw8_impl.h>
#include <sys/plat_ecc_unum.h>

/*
 * Global Variables - can be patched from Solaris
 * ==============================================
 */

/*
 * Module Variables
 * ================
 */

/*
 * functions local to this driver.
 */
static int	lw8_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	lw8_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	lw8_add_intr_handlers(void);
static int	lw8_remove_intr_handlers(void);
static void lw8_wakeup_sleepers(void);
static uint_t	lw8_fast_shutdown(char *arg);
static uint_t	lw8_slow_shutdown(char *arg);
static uint_t	lw8_event_data_handler(char *);
static uint_t	lw8_dr_data_handler(char *);
static uint_t	lw8_env_data_handler(char *);
static uint_t	lw8_cap_ecc_msg_handler(char *);
static int	lw8_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	lw8_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	lw8_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);
static void	lw8_logger_start(void);
static void	lw8_logger_destroy(void);
static void	lw8_logger_wakeup(void);

/*
 * Driver entry points
 */
static struct cb_ops lw8_cb_ops = {
	lw8_open,	/* open */
	lw8_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	lw8_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops lw8_ops = {
	DEVO_REV,
	0,			/* ref count */
	ddi_getinfo_1to1,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	lw8_attach,		/* attach() */
	lw8_detach,		/* detach */
	nodev,			/* reset */
	&lw8_cb_ops,		/* pointer to cb_ops structure */
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
	"Netra-T12 control driver",	/* Name of the module */
	&lw8_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * messages
 */
#define	SHUTDOWN_EVENT_MSG		"lw8: system shutdown due to " \
					"SC request.\n"
#define	VOLTAGE_EVENT_MSG		"lw8: system shutdown due to " \
					"voltage out of range.\n"
#define	TEMPERATURE_EVENT_MSG		"lw8: system shutdown due to " \
					"temperature exceeding limits.\n"
#define	FANFAIL_EVENT_MSG		"lw8: system shutdown due to " \
					"too many fan failures.\n"
#define	NO_SCC_EVENT_MSG		"lw8: system shutdown due to " \
					"no system configuration card.\n"

/*
 * led table - the following provides a cache of the led state - needed
 * to avoid the overhead of readoing from the SC each time
 */

struct led_info {
	char	id[MAX_ID_LEN];
	int	position;
	int	status;
	char	color[MAX_COLOR_LEN];
};

static struct fru_led_info {
	char    location[MAX_LOCATION_LEN];
	struct led_info led_info[MAX_LEDS_PER_FRU];
} fru_led_table[MAX_FRUS] = {
	"SB0", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"PS0", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"predicted_fault", LOM_LED_POSITION_FRU, 0, "amber"},
	"SB2", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"PS1", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"predicted_fault", LOM_LED_POSITION_FRU, 0, "amber"},
	"SB4", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"PS2", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"predicted_fault", LOM_LED_POSITION_FRU, 0, "amber"},
	"IB6", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"PS3", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"predicted_fault", LOM_LED_POSITION_FRU, 0, "amber"},
	"FT0", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"FAN0", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN1", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN2", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN3", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN4", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN5", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN6", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN7", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN8", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"FAN9", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber"},
	"DISK0", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber",
		"power", LOM_LED_POSITION_LOCATION, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_LOCATION, 0, "blue"},
	"DISK1", {"fault", LOM_LED_POSITION_LOCATION, 0, "amber",
		"power", LOM_LED_POSITION_LOCATION, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_LOCATION, 0, "blue"},
	"RP0", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"RP2", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"ok_to_remove", LOM_LED_POSITION_FRU, 0, "amber"},
	"chassis", {"fault", LOM_LED_POSITION_FRU, 0, "amber",
		"power", LOM_LED_POSITION_FRU, 0, "green",
		"locator", LOM_LED_POSITION_FRU, 0, "white",
		"top_access", LOM_LED_POSITION_FRU, 0, "amber",
		"alarm1", LOM_LED_POSITION_FRU, 0, "amber",
		"alarm2", LOM_LED_POSITION_FRU, 0, "amber",
		"system", LOM_LED_POSITION_FRU, 0, "green",
		"supplyA", LOM_LED_POSITION_FRU, 0, "green",
		"supplyB", LOM_LED_POSITION_FRU, 0, "green"},
};

char    *fru_locn[MAX_LOCATION_LEN] = {
	"SB0",
	"PS0",
	"SB2",
	"PS1",
	"SB4",
	"PS2",
	"IB6",
	"PS3",
	"SCC",
	"SSC1",
};

/*
 * mutexes which protect the interrupt handlers.
 */
static kmutex_t		lw8_shutdown_hdlr_lock;
static kmutex_t		lw8_dr_hdlr_lock;
static kmutex_t		lw8_env_hdlr_lock;
static kmutex_t		lw8_event_mutex;
static kmutex_t		lw8_logger_lock;
static kmutex_t		lw8_cap_msg_hdlr_lock;
static kcondvar_t	lw8_event_cv;
static kcondvar_t	lw8_logger_sig_cv;

/*
 * state booleans
 */
static boolean_t	lw8_event_pending = B_FALSE;
static boolean_t	led_state_cached = B_FALSE;

/*
 * Payloads of the event handlers.
 */
static lw8_event_t	lw8_shutdown_payload;
static sbbc_msg_t	lw8_shutdown_payload_msg;
static sg_system_fru_descriptor_t	lw8_dr_payload;
static sbbc_msg_t	lw8_dr_payload_msg;
static sg_event_fan_status_t		lw8_env_payload;
static sbbc_msg_t	lw8_env_payload_msg;
static plat_capability_data_t	lw8_cap_payload;
static sbbc_msg_t	lw8_cap_payload_msg;

/*
 * The IDs of the soft interrupts
 */
static ddi_softintr_t   lw8_slow_shutdown_softint_id;
static ddi_softintr_t   lw8_fast_shutdown_softint_id;

/*
 * Logger commands..
 */
#define	LW8_LOGGER_EXITNOW	-1
#define	LW8_LOGGER_WAIT	0
#define	LW8_LOGGER_PROCESSNOW	1

/*
 * Logger thread state
 */
static int lw8_logger_sig = LW8_LOGGER_WAIT;
static kt_did_t lw8_logger_tid = 0;

extern pri_t maxclsyspri;

int
_init(void)
{
	int	error = 0;

	mutex_init(&lw8_shutdown_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&lw8_dr_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&lw8_env_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&lw8_cap_msg_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&lw8_event_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&lw8_logger_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&lw8_event_cv, NULL, CV_DRIVER, NULL);
	cv_init(&lw8_logger_sig_cv, NULL, CV_DRIVER, NULL);

	error = mod_install(&modlinkage);
	if (error) {
		cv_destroy(&lw8_logger_sig_cv);
		cv_destroy(&lw8_event_cv);
		mutex_destroy(&lw8_logger_lock);
		mutex_destroy(&lw8_event_mutex);
		mutex_destroy(&lw8_env_hdlr_lock);
		mutex_destroy(&lw8_cap_msg_hdlr_lock);
		mutex_destroy(&lw8_dr_hdlr_lock);
		mutex_destroy(&lw8_shutdown_hdlr_lock);
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
	int	error = 0;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);
	cv_destroy(&lw8_logger_sig_cv);
	cv_destroy(&lw8_event_cv);
	mutex_destroy(&lw8_logger_lock);
	mutex_destroy(&lw8_event_mutex);
	mutex_destroy(&lw8_env_hdlr_lock);
	mutex_destroy(&lw8_cap_msg_hdlr_lock);
	mutex_destroy(&lw8_dr_hdlr_lock);
	mutex_destroy(&lw8_shutdown_hdlr_lock);
	return (error);
}


static int
lw8_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			err;

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * only allow one instance
		 */
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		err = ddi_create_minor_node(dip, "lw8", S_IFCHR,
		    instance, DDI_PSEUDO, 0);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);

		err = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
		    &lw8_slow_shutdown_softint_id, NULL, NULL,
		    lw8_slow_shutdown, NULL);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to add polling softint"
			    "handler for lw8. Err=%d", err);
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		err = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
		    &lw8_fast_shutdown_softint_id, NULL, NULL,
		    lw8_fast_shutdown, NULL);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to add polling softint"
			    "handler for lw8. Err=%d", err);
			ddi_remove_softintr(lw8_slow_shutdown_softint_id);
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		lw8_logger_start();

		/*
		 * Add the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = lw8_add_intr_handlers();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to add event handlers");
			lw8_logger_destroy();
			ddi_remove_softintr(lw8_fast_shutdown_softint_id);
			ddi_remove_softintr(lw8_slow_shutdown_softint_id);
			ddi_remove_minor_node(dip, NULL);
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
lw8_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance;
	int	err;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		/*
		 * Remove the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = lw8_remove_intr_handlers();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to remove event handlers");
			return (DDI_FAILURE);
		}
		lw8_logger_destroy();
		ddi_remove_softintr(lw8_slow_shutdown_softint_id);
		ddi_remove_softintr(lw8_fast_shutdown_softint_id);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
lw8_add_intr_handlers()
{
	int	err;

	lw8_shutdown_payload_msg.msg_buf = (caddr_t)&lw8_shutdown_payload;
	lw8_shutdown_payload_msg.msg_len = sizeof (lw8_shutdown_payload);
	err = sbbc_mbox_reg_intr(MBOX_EVENT_LW8, lw8_event_data_handler,
	    &lw8_shutdown_payload_msg, NULL, &lw8_shutdown_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_LW8 "
		    " handler. Err=%d", err);
		return (DDI_FAILURE);
	}

	lw8_dr_payload_msg.msg_buf = (caddr_t)&lw8_dr_payload;
	lw8_dr_payload_msg.msg_len = sizeof (lw8_dr_payload);
	err = sbbc_mbox_reg_intr(MBOX_EVENT_GENERIC, lw8_dr_data_handler,
	    &lw8_dr_payload_msg, NULL, &lw8_dr_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_GENERIC "
		    " handler. Err=%d", err);
		(void) sbbc_mbox_unreg_intr(MBOX_EVENT_LW8,
		    lw8_event_data_handler);
		return (DDI_FAILURE);
	}

	lw8_env_payload_msg.msg_buf = (caddr_t)&lw8_env_payload;
	lw8_env_payload_msg.msg_len = sizeof (lw8_env_payload);
	err = sbbc_mbox_reg_intr(MBOX_EVENT_ENV, lw8_env_data_handler,
	    &lw8_env_payload_msg, NULL, &lw8_env_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register MBOX_EVENT_ENV "
		    " handler. Err=%d", err);
		(void) sbbc_mbox_unreg_intr(MBOX_EVENT_GENERIC,
		    lw8_dr_data_handler);
		(void) sbbc_mbox_unreg_intr(MBOX_EVENT_LW8,
		    lw8_event_data_handler);
		return (DDI_FAILURE);
	}

	lw8_cap_payload_msg.msg_buf = (caddr_t)&lw8_cap_payload;
	lw8_cap_payload_msg.msg_len = sizeof (lw8_cap_payload);
	err = sbbc_mbox_reg_intr(INFO_MBOX, lw8_cap_ecc_msg_handler,
	    &lw8_cap_payload_msg, NULL, &lw8_cap_msg_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register INFO_MBOX "
		    " handler. Err=%d", err);
		(void) sbbc_mbox_unreg_intr(MBOX_EVENT_GENERIC,
		    lw8_dr_data_handler);
		(void) sbbc_mbox_unreg_intr(MBOX_EVENT_LW8,
		    lw8_event_data_handler);
		(void) sbbc_mbox_unreg_intr(INFO_MBOX,
		    lw8_cap_ecc_msg_handler);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
lw8_remove_intr_handlers(void)
{
	int	rv = DDI_SUCCESS;
	int	err;

	err = sbbc_mbox_unreg_intr(MBOX_EVENT_LW8, lw8_event_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_LW8 "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}
	err = sbbc_mbox_unreg_intr(MBOX_EVENT_GENERIC, lw8_dr_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_GENERIC "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}
	err = sbbc_mbox_unreg_intr(MBOX_EVENT_ENV, lw8_env_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister MBOX_EVENT_ENV "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}
	err = sbbc_mbox_unreg_intr(INFO_MBOX, lw8_cap_ecc_msg_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister INFO_MBOX "
		    "handler. Err=%d", err);
		rv = DDI_FAILURE;
	}
	return (rv);
}

static uint_t
lw8_dr_data_handler(char *arg)
{
	sg_system_fru_descriptor_t	*payload;
	sbbc_msg_t			*msg;
	int				hint;
	sysevent_t			*ev;
	sysevent_id_t			eid;
	int				rv = 0;
	sysevent_value_t		evnt_val;
	sysevent_attr_list_t		*evnt_attr_list = NULL;
	char				attach_pnt[MAXPATHLEN];

	msg = (sbbc_msg_t *)arg;
	if (msg == NULL) {
		return (DDI_INTR_CLAIMED);
	}
	payload = (sg_system_fru_descriptor_t *)msg->msg_buf;
	if (payload == NULL) {
		return (DDI_INTR_CLAIMED);
	}
	if (payload->slot < 0 || payload->slot >= sizeof (fru_locn) /
	    sizeof (char *)) {
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * if not SB send sysevent (SBs send sysevent from ssm driver)
	 */
	if (strncmp(fru_locn[payload->slot], "SB", 2) != 0) {
		switch (payload->event_details) {
		case SG_EVT_BOARD_ABSENT:
			hint = SE_HINT_REMOVE;
			break;
		case SG_EVT_BOARD_PRESENT:
			hint = SE_HINT_INSERT;
			break;
		default:
			hint = SE_NO_HINT;
			break;
		}
		(void) snprintf(attach_pnt, sizeof (attach_pnt), "ssm0:N0.%s",
		    fru_locn[payload->slot]);
		ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE, EP_DDI,
		    KM_NOSLEEP);
		if (ev == NULL) {
			cmn_err(CE_WARN, "Failed to allocate %s event", EC_DR);
			return (DDI_INTR_CLAIMED);
		}
		evnt_val.value_type = SE_DATA_TYPE_STRING;
		evnt_val.value.sv_string = attach_pnt;
		rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val,
		    KM_NOSLEEP);
		if (rv != 0) {
			cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
			    DR_AP_ID, EC_DR);
			sysevent_free(ev);
			return (DDI_INTR_CLAIMED);
		}

		/*
		 * Add the hint
		 */
		evnt_val.value_type = SE_DATA_TYPE_STRING;
		evnt_val.value.sv_string = SE_HINT2STR(hint);
		rv = sysevent_add_attr(&evnt_attr_list, DR_HINT, &evnt_val,
		    KM_NOSLEEP);
		if (rv != 0) {
			cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
			    DR_HINT, EC_DR);
			sysevent_free_attr(evnt_attr_list);
			sysevent_free(ev);
			return (DDI_INTR_CLAIMED);
		}
		if (sysevent_attach_attributes(ev, evnt_attr_list) != 0) {
			cmn_err(CE_WARN, "Failed to attach attr list for %s "
			    "event", EC_DR);
			sysevent_free_attr(evnt_attr_list);
			sysevent_free(ev);
			return (DDI_INTR_CLAIMED);
		}
		rv = log_sysevent(ev, KM_NOSLEEP, &eid);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "lw8_dr_event_handler: failed to log event");
		}
		sysevent_free(ev);
	}
	lw8_wakeup_sleepers();
	return (DDI_INTR_CLAIMED);
}

static uint_t
lw8_cap_ecc_msg_handler(char *addr)
{
	sbbc_msg_t *msg = NULL;
	plat_capability_data_t *cap = NULL;

	msg = (sbbc_msg_t *)addr;
	if (msg == NULL || msg->msg_buf == NULL)
		return (DDI_INTR_CLAIMED);

	cap = (plat_capability_data_t *)msg->msg_buf;
	switch (cap->capd_msg_type) {
	case PLAT_ECC_CAPABILITY_MESSAGE:
		plat_ecc_capability_sc_set(cap->capd_capability);
		break;
	default:
		break;
	}

	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED*/
static uint_t
lw8_env_data_handler(char *arg)
{
	lw8_wakeup_sleepers();
	return (DDI_INTR_CLAIMED);
}

/*
 * wakeup sleepers + mark led cache for this fru as invalid
 */
static void
lw8_wakeup_sleepers()
{
	mutex_enter(&lw8_event_mutex);
	lw8_event_pending = B_TRUE;
	cv_broadcast(&lw8_event_cv);
	led_state_cached = B_FALSE;
	mutex_exit(&lw8_event_mutex);
}

/*
 * This function is triggered by a soft interrupt and it's purpose is to call
 * to kadmin() to shutdown the system.
 */
/*ARGSUSED*/
static uint_t
lw8_fast_shutdown(char *arg)
{
	(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);

	/*
	 * If kadmin fails for some reason then we bring the system down
	 * via power_down(), or failing that using halt().
	 */
	power_down("kadmin() failed, trying power_down()");

	halt("power_down() failed, trying halt()");

	/*
	 * We should never make it this far, so something must have gone
	 * horribly, horribly wrong.
	 */
	/*NOTREACHED*/
	return (DDI_INTR_UNCLAIMED);
}

/*
 * This function is triggered by a soft interrupt and it's purpose is to call
 * to do_shutdown() to shutdown the system.
 */
/*ARGSUSED*/
static uint_t
lw8_slow_shutdown(char *arg)
{
	do_shutdown();
	return (DDI_SUCCESS);
}

static uint_t
lw8_event_data_handler(char *arg)
{
	lw8_event_t	*payload;
	sbbc_msg_t	*msg;

	if (arg == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	msg = (sbbc_msg_t *)arg;
	if (msg->msg_buf == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	payload = (lw8_event_t *)msg->msg_buf;
	switch (payload->event_type) {
	case LW8_EVENT_REQUESTED_SHUTDOWN:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", SHUTDOWN_EVENT_MSG);
		ddi_trigger_softintr(lw8_slow_shutdown_softint_id);

		/*NOTREACHED*/
		break;

	case LW8_EVENT_VOLTAGE_SHUTDOWN:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", VOLTAGE_EVENT_MSG);
		ddi_trigger_softintr(lw8_fast_shutdown_softint_id);

		/*NOTREACHED*/
		break;

	case LW8_EVENT_TEMPERATURE_SHUTDOWN:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", TEMPERATURE_EVENT_MSG);
		ddi_trigger_softintr(lw8_fast_shutdown_softint_id);

		/*NOTREACHED*/
		break;

	case LW8_EVENT_FANFAIL_SHUTDOWN:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", FANFAIL_EVENT_MSG);
		ddi_trigger_softintr(lw8_fast_shutdown_softint_id);

		/*NOTREACHED*/
		break;

	case LW8_EVENT_NO_SCC_SHUTDOWN:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", NO_SCC_EVENT_MSG);
		ddi_trigger_softintr(lw8_fast_shutdown_softint_id);

		/*NOTREACHED*/
		break;

	case LW8_EVENT_NEW_LOG_MSG:

		/*
		 * Wake up the log retrieval thread.
		 */
		lw8_logger_wakeup();

		break;

	default:
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED*/
static int
lw8_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	int error = 0;
	int instance = getminor(*dev_p);
	static fn_t f = "lw8_open";

	if (instance != 0)
		return (ENXIO);

	if ((error = drv_priv(cred_p)) != 0) {
		cmn_err(CE_WARN, "lw8:%s: inst %d drv_priv failed",
		    f, instance);
		return (error);
	}
	return (error);
}

/*ARGSUSED*/
static int
lw8_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	return (DDI_SUCCESS);
}

static int
lw8_lomcmd(int cmd, intptr_t arg)
{
	sbbc_msg_t request, *reqp = &request;
	sbbc_msg_t response, *resp = &response;
	int rv = 0;
	lom_eventreq_t *eventreqp;

	bzero((caddr_t)&request, sizeof (request));
	reqp->msg_type.type = LW8_MBOX;
	reqp->msg_type.sub_type = cmd;
	bzero((caddr_t)&response, sizeof (response));
	resp->msg_type.type = LW8_MBOX;
	resp->msg_type.sub_type = cmd;

	switch (cmd) {
	case LW8_MBOX_GET_INFO:
		reqp->msg_len = 0;
		reqp->msg_buf = (caddr_t)NULL;
		resp->msg_len = sizeof (lom2_info_t);
		resp->msg_buf = (caddr_t)arg;
		break;
	case LW8_MBOX_SET_CTL:
		reqp->msg_len = sizeof (lom_ctl2_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = 0;
		resp->msg_buf = (caddr_t)NULL;
		break;
	case LW8_MBOX_UPDATE_FW:
		reqp->msg_len = sizeof (lom_prog_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = 0;
		resp->msg_buf = (caddr_t)NULL;
		break;
	case LW8_MBOX_GET_LED:
		reqp->msg_len = sizeof (lw8_get_led_payload_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = sizeof (lw8_get_led_payload_t);
		resp->msg_buf = (caddr_t)arg;
		break;
	case LW8_MBOX_SET_LED:
		reqp->msg_len = sizeof (lw8_set_led_payload_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = 0;
		resp->msg_buf = (caddr_t)NULL;
		break;
	case LW8_MBOX_GET_EVENTS:
		/*
		 * cast as lom_eventreq_t to minimise data traffic
		 */
		eventreqp = (lom_eventreq_t *)arg;
		reqp->msg_len = sizeof (lom_eventreq_t);
		reqp->msg_buf = (caddr_t)arg;
		resp->msg_len = sizeof (lom_eventreq_t) +
		    (eventreqp->num * MAX_EVENT_STR);
		resp->msg_buf = (caddr_t)arg;
		break;
	case LW8_MBOX_GET_NEXT_MSG:
		reqp->msg_len = 0;
		reqp->msg_buf = (caddr_t)NULL;
		resp->msg_len = sizeof (lw8_logmsg_t);
		resp->msg_buf = (caddr_t)arg;
		break;
	default:
		return (EINVAL);
	}

	rv = sbbc_mbox_request_response(reqp, resp,
	    LW8_DEFAULT_MAX_MBOX_WAIT_TIME);

	if ((rv) || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {

		/* errors from sgsbbc */
		if (resp->msg_status > 0) {
			return (resp->msg_status);
		}

		/* errors from SCAPP */
		switch (resp->msg_status) {

		case SG_MBOX_STATUS_COMMAND_FAILURE:
			/* internal SCAPP error */
			return (EINTR);

		case SG_MBOX_STATUS_HARDWARE_FAILURE:
			/* seprom read/write errors */
			return (EIO);

		case SG_MBOX_STATUS_ILLEGAL_PARAMETER:
			/* illegal ioctl parameter */
			return (EINVAL);

		case SG_MBOX_STATUS_BOARD_ACCESS_DENIED:
			/* board access denied */
			return (EACCES);

		case SG_MBOX_STATUS_STALE_CONTENTS:
			/* stale contents */
			return (ESTALE);

		case SG_MBOX_STATUS_STALE_OBJECT:
			/* stale handle */
			return (ENOENT);

		case SG_MBOX_STATUS_NO_SEPROM_SPACE:
			/* seprom lacks space */
			return (ENOSPC);

		case SG_MBOX_STATUS_NO_MEMORY:
			/* user prog. lacks space */
			return (ENOMEM);

		case SG_MBOX_STATUS_NOT_SUPPORTED:
			/* unsupported operation */
			return (ENOTSUP);

		default:
			return (EIO);
		}
	}
	return (0);
}

/*
 * set the requested led, and mark cache as empty
 */
static int
lw8_setled(lom_set_led_t *set_ledp)
{
	int retval;
	int i, j;
	struct led_info *lip;
	lw8_set_led_payload_t lw8_set_led;

	for (i = 0; i < MAX_FRUS; i++) {
		if (strncmp(set_ledp->location, fru_led_table[i].location,
		    MAX_LOCATION_LEN) != 0)
			continue;
		for (j = 0; j < MAX_LEDS_PER_FRU; j++) {
			lip = &fru_led_table[i].led_info[j];
			if (lip->id == NULL)
				continue;
			if (strncmp(set_ledp->id, lip->id, MAX_ID_LEN) != 0)
				continue;
			lw8_set_led.value = set_ledp->status;

			/*
			 * to minimise data transfer, the SC maintains
			 * just  3 values per fru - except for
			 * the chassis itself at the end which has
			 * MAX_LEDS_PER_FRU
			 */
			lw8_set_led.offset = (i * 3) + j;
			retval = lw8_lomcmd(LW8_MBOX_SET_LED,
			    (intptr_t)&lw8_set_led);
			if (retval != 0)
				return (retval);
			mutex_enter(&lw8_event_mutex);
			led_state_cached = B_FALSE;
			mutex_exit(&lw8_event_mutex);
			return (0);
		}
	}
	return (EINVAL);
}

/*
 * read led value from cache if possible, otherwise read from sc and
 * update the cache
 */
static int
lw8_getled(lom_get_led_t *get_ledp)
{
	int retval;
	int i, j, k;
	struct led_info *lip;
	lw8_get_led_payload_t lw8_get_led;

	for (i = 0; i < MAX_FRUS; i++) {
		if (strncmp(get_ledp->location, fru_led_table[i].location,
		    MAX_LOCATION_LEN) != 0)
			continue;
		if (get_ledp->id[0] == '\0') {
			(void) strncpy(get_ledp->next_id,
			    fru_led_table[i].led_info[0].id, MAX_ID_LEN);
			return (0);
		}
		for (j = 0; j < MAX_LEDS_PER_FRU; j++) {
			lip = &fru_led_table[i].led_info[j];
			if (lip->id == NULL)
				continue;
			if (strncmp(get_ledp->id, lip->id, MAX_ID_LEN) != 0)
				continue;
			mutex_enter(&lw8_event_mutex);
			if (!led_state_cached) {
				mutex_exit(&lw8_event_mutex);
				retval = lw8_lomcmd(LW8_MBOX_GET_LED,
				    (intptr_t)&lw8_get_led);
				if (retval != 0)
					return (retval);
				mutex_enter(&lw8_event_mutex);

				/*
				 * to minimise data transfer, the
				 * lw8_get_led_payload_t structure just has 3
				 * values per fru - except for the chassis
				 * itself at the end which has MAX_LEDS_PER_FRU
				 */
				for (k = 0; k < (MAX_FRUS - 1) * 3; k++) {
					fru_led_table[k / 3].led_info[k % 3].
					    status = lw8_get_led.value[k];
				}
				for (k = 0; k < MAX_LEDS_PER_FRU; k++) {
					fru_led_table[MAX_FRUS - 1].led_info[k].
					    status = lw8_get_led.value[k +
					    ((MAX_FRUS - 1) * 3)];
				}
				led_state_cached = B_TRUE;
			}
			get_ledp->status = lip->status;
			mutex_exit(&lw8_event_mutex);
			get_ledp->position = lip->position;
			(void) strncpy(get_ledp->color, lip->color,
			    MAX_COLOR_LEN);
			if (j == MAX_LEDS_PER_FRU - 1) {
				get_ledp->next_id[0] = '\0';
				return (0);
			}
			(void) strncpy(get_ledp->next_id,
			    fru_led_table[i].led_info[j + 1].id, MAX_ID_LEN);
			return (0);
		}
	}
	if (get_ledp->id[0] == '\0') {
		get_ledp->next_id[0] = '\0';
		return (0);
	}
	return (EINVAL);
}

/*ARGSUSED*/
static int
lw8_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	int instance = getminor(dev);
	lom2_info_t lw8_info2;
	lom_ctl_t lw8_ctl;
	lom_ctl2_t lw8_ctl2;
	lom_mprog_t lw8_mprog;
	lom_fled_info_t lw8_fled_info;
	lom_info_t lw8_info;
	lom_aldata_t lw8_aldata;
	lom_get_led_t lw8_get_led;
	lom_set_led_t lw8_set_led;
	lom_prog_t *lw8_progp;
	lom_eventlog2_t *lw8_eventlogp;
	lom_eventresp_t *lw8_eventresp;
	int retval = 0;
	int i, j;

	if (instance != 0)
		return (ENXIO);

	switch (cmd) {
	case LOMIOCWTMON:
		mutex_enter(&lw8_event_mutex);
		if (!lw8_event_pending) {
			if (cv_wait_sig(&lw8_event_cv, &lw8_event_mutex) == 0) {
				mutex_exit(&lw8_event_mutex);
				retval = EINTR;
				break;
			}
		}
		lw8_event_pending = B_FALSE;
		mutex_exit(&lw8_event_mutex);
		break;
	case LOMIOCMREAD:
		bzero((caddr_t)&lw8_mprog, sizeof (lw8_mprog));
		lw8_mprog.config = 4;
		if (ddi_copyout((caddr_t)&lw8_mprog, (caddr_t)arg,
		    sizeof (lw8_mprog), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCCTL2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_ctl2,
		    sizeof (lw8_ctl2), mode) != 0) {
			retval = EFAULT;
			break;
		}
		retval = lw8_lomcmd(LW8_MBOX_SET_CTL, (intptr_t)&lw8_ctl2);
		break;
	case LOMIOCPROG:
		lw8_progp = kmem_alloc(sizeof (*lw8_progp), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, (caddr_t)lw8_progp,
		    sizeof (*lw8_progp), mode) != 0) {
			kmem_free(lw8_progp, sizeof (*lw8_progp));
			retval = EFAULT;
			break;
		}
		retval = lw8_lomcmd(LW8_MBOX_UPDATE_FW, (intptr_t)lw8_progp);
		kmem_free(lw8_progp, sizeof (*lw8_progp));
		break;
	case LOMIOCINFO2:
		bzero((caddr_t)&lw8_info2, sizeof (lw8_info2));
		retval = lw8_lomcmd(LW8_MBOX_GET_INFO, (intptr_t)&lw8_info2);
		if (retval != 0)
			break;
		if (ddi_copyout((caddr_t)&lw8_info2, (caddr_t)arg,
		    sizeof (lw8_info2), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCINFO:
		bzero((caddr_t)&lw8_info2, sizeof (lw8_info2));
		retval = lw8_lomcmd(LW8_MBOX_GET_INFO, (intptr_t)&lw8_info2);
		if (retval != 0)
			break;
		bzero((caddr_t)&lw8_info, sizeof (lw8_info));
		lw8_info.ser_char = lw8_info2.escape_chars[0];
		lw8_info.fver = lw8_info2.fver;
		lw8_info.fchksum = lw8_info2.fchksum;
		lw8_info.prod_rev = lw8_info2.prod_rev;
		(void) strncpy(lw8_info.prod_id, lw8_info2.prod_id, MAX_ID_LEN);
		if (ddi_copyout((caddr_t)&lw8_info, (caddr_t)arg,
		    sizeof (lw8_info), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCFLEDSTATE:
		bzero((caddr_t)&lw8_get_led, sizeof (lw8_get_led));
		(void) strncpy(lw8_get_led.location, "chassis",
		    MAX_LOCATION_LEN);
		(void) strncpy(lw8_get_led.id, "fault", MAX_ID_LEN);
		retval = lw8_getled(&lw8_get_led);
		if (retval != 0)
			break;
		lw8_fled_info.on = lw8_get_led.status;
		if (ddi_copyout((caddr_t)&lw8_fled_info, (caddr_t)arg,
		    sizeof (lw8_fled_info), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCALSTATE:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_aldata,
		    sizeof (lw8_aldata), mode) != 0) {
			retval = EFAULT;
			break;
		}
		bzero((caddr_t)&lw8_get_led, sizeof (lw8_get_led));
		(void) strncpy(lw8_get_led.location, "chassis",
		    MAX_LOCATION_LEN);
		if (lw8_aldata.alarm_no == 3)
			(void) snprintf(lw8_get_led.id, MAX_ID_LEN, "system");
		else
			(void) snprintf(lw8_get_led.id, MAX_ID_LEN, "alarm%d",
			    lw8_aldata.alarm_no);
		retval = lw8_getled(&lw8_get_led);
		if (retval != 0)
			break;
		lw8_aldata.state = lw8_get_led.status;
		if (ddi_copyout((caddr_t)&lw8_aldata, (caddr_t)arg,
		    sizeof (lw8_aldata), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCGETLED:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_get_led,
		    sizeof (lw8_get_led), mode) != 0) {
			retval = EFAULT;
			break;
		}
		retval = lw8_getled(&lw8_get_led);
		if (retval != 0)
			break;
		if (ddi_copyout((caddr_t)&lw8_get_led, (caddr_t)arg,
		    sizeof (lw8_get_led), mode) != 0) {
			retval = EFAULT;
		}
		break;
	case LOMIOCEVENTLOG2:
		lw8_eventlogp = kmem_alloc(sizeof (*lw8_eventlogp), KM_SLEEP);
		lw8_eventresp = kmem_zalloc(sizeof (*lw8_eventresp), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, (caddr_t)lw8_eventlogp,
		    sizeof (*lw8_eventlogp), mode) != 0) {
			kmem_free(lw8_eventlogp, sizeof (*lw8_eventlogp));
			kmem_free(lw8_eventresp, sizeof (*lw8_eventresp));
			retval = EFAULT;
			break;
		}
		lw8_eventresp->num = lw8_eventlogp->num;
		lw8_eventresp->level = lw8_eventlogp->level;
		retval = lw8_lomcmd(LW8_MBOX_GET_EVENTS,
		    (intptr_t)lw8_eventresp);
		if (retval == 0) {
			lw8_eventlogp->num = lw8_eventresp->num;
			for (i = 0; i < lw8_eventresp->num; i++) {
				for (j = 0; j < MAX_EVENT_STR; j++) {
					lw8_eventlogp->string[i][j] =
					    lw8_eventresp->string[i][j];
				}
			}
			if (ddi_copyout((caddr_t)lw8_eventlogp, (caddr_t)arg,
			    sizeof (*lw8_eventlogp), mode) != 0) {
				retval = EFAULT;
			}
		}
		kmem_free(lw8_eventlogp, sizeof (*lw8_eventlogp));
		kmem_free(lw8_eventresp, sizeof (*lw8_eventresp));
		break;
	case LOMIOCALCTL:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_aldata,
		    sizeof (lw8_aldata), mode) != 0) {
			retval = EFAULT;
			break;
		}
		bzero((caddr_t)&lw8_set_led, sizeof (lw8_set_led));
		(void) strncpy(lw8_set_led.location, "chassis",
		    MAX_LOCATION_LEN);
		if (lw8_aldata.alarm_no == 3)
			(void) snprintf(lw8_set_led.id, MAX_ID_LEN, "system");
		else
			(void) snprintf(lw8_set_led.id, MAX_ID_LEN, "alarm%d",
			    lw8_aldata.alarm_no);
		lw8_set_led.status = lw8_aldata.state;
		retval = lw8_setled(&lw8_set_led);
		break;
	case LOMIOCSETLED:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_set_led,
		    sizeof (lw8_set_led), mode) != 0) {
			retval = EFAULT;
			break;
		}
		retval = lw8_setled(&lw8_set_led);
		break;
	case LOMIOCCTL:
		/*
		 * for this ioctl, as well as setting the fault led in the
		 * LOMIOCCTL case in lw8_lomcmd(), we also need to set the
		 * escape character. To do this we must use LW8_MBOX_SET_CTL,
		 * but this also needs the serial_event value which we have
		 * to get via LW8_MBOX_GET_INFO
		 */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lw8_ctl,
		    sizeof (lw8_ctl), mode) != 0) {
			retval = EFAULT;
			break;
		}
		bzero((caddr_t)&lw8_info2, sizeof (lw8_info2));
		retval = lw8_lomcmd(LW8_MBOX_GET_INFO, (intptr_t)&lw8_info2);
		if (retval != 0)
			break;
		bzero((caddr_t)&lw8_ctl2, sizeof (lw8_ctl2));
		lw8_ctl2.escape_chars[0] = lw8_ctl.ser_char;
		lw8_ctl2.serial_events = lw8_info2.serial_events;
		retval = lw8_lomcmd(LW8_MBOX_SET_CTL, (intptr_t)&lw8_ctl2);
		if (retval != 0)
			break;

		/*
		 * if fault_led != 0, then set the led
		 */
		if (lw8_ctl.fault_led == 0)
			break;
		bzero((caddr_t)&lw8_set_led, sizeof (lw8_set_led));
		(void) strncpy(lw8_set_led.location, "chassis",
		    MAX_LOCATION_LEN);
		(void) strncpy(lw8_set_led.id, "fault", MAX_ID_LEN);
		lw8_set_led.status = lw8_ctl.fault_led - 1;
		retval = lw8_setled(&lw8_set_led);
		break;
	default:
		retval = ENOTSUP;
		break;
	}
	return (retval);
}

/* ARGSUSED */
static void
lw8_logger(caddr_t arg)
{
	callb_cpr_t	cprinfo;
	lw8_logmsg_t	*lw8_logmsgp;
	boolean_t	more_waiting;
	char		level;
	int		retval;

	CALLB_CPR_INIT(&cprinfo, &lw8_logger_lock, callb_generic_cpr,
	    "lw8_logger");

	lw8_logmsgp = kmem_zalloc(sizeof (*lw8_logmsgp), KM_SLEEP);
	mutex_enter(&lw8_logger_lock);
	for (;;) {

		/*
		 * Wait for someone to tell me to continue.
		 */
		while (lw8_logger_sig == LW8_LOGGER_WAIT) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&lw8_logger_sig_cv, &lw8_logger_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &lw8_logger_lock);
		}

		/* LW8_LOGGER_EXITNOW implies signal by _detach(). */
		if (lw8_logger_sig == LW8_LOGGER_EXITNOW) {
			lw8_logger_sig = LW8_LOGGER_WAIT;

			kmem_free(lw8_logmsgp, sizeof (*lw8_logmsgp));

			/* lw8_logger_lock is held at this point! */
			CALLB_CPR_EXIT(&cprinfo);

			thread_exit();
			/* NOTREACHED */
		}

		ASSERT(lw8_logger_sig == LW8_LOGGER_PROCESSNOW);
		lw8_logger_sig = LW8_LOGGER_WAIT;

		mutex_exit(&lw8_logger_lock);

		/* Do lw8_event logging */

		/*
		 * Get one message per iteration. We do not sleep if
		 * there are more to process. This makes exit from the
		 * routine much more reliable.
		 */
		more_waiting = B_FALSE;

		retval = lw8_lomcmd(LW8_MBOX_GET_NEXT_MSG,
		    (intptr_t)lw8_logmsgp);
		if (retval == 0) {
			if (lw8_logmsgp->msg_valid) {

				switch (lw8_logmsgp->level) {
				case 0:	/* LOG_EMERG */
					level = SL_FATAL;
					break;
				case 1:	/* LOG_ALERT */
					level = SL_FATAL;
					break;
				case 2:	/* LOG_CRIT */
					level = SL_FATAL;
					break;
				case 3:	/* LOG_ERR */
					level = SL_ERROR;
					break;
				case 4:	/* LOG_WARNING */
					level = SL_WARN;
					break;
				case 5:	/* LOG_NOTICE */
					level = SL_NOTE;
					break;
				case 6:	/* LOG_INFO */
					level = SL_NOTE;
					break;
				case 7:	/* LOG_DEBUG */
					level = SL_TRACE;
					break;
				default:	/* unknown */
					level = SL_NOTE;
					break;
				}

				/* Ensure NUL termination */
				lw8_logmsgp->msg[
				    sizeof (lw8_logmsgp->msg) - 1] = '\0';
				(void) strlog(0, 0, 0, SL_CONSOLE | level,
				    lw8_logmsgp->msg);
			}

			if (lw8_logmsgp->num_remaining > 0)
				more_waiting = B_TRUE;
		}

		/*
		 * Re-enter the lock to prepare for another iteration.
		 * We must have the lock here to protect lw8_logger_sig.
		 */
		mutex_enter(&lw8_logger_lock);
		if ((lw8_logger_sig == LW8_LOGGER_WAIT) && more_waiting)
			/* We need to get more events */
			lw8_logger_sig = LW8_LOGGER_PROCESSNOW;
	}
}

static void
lw8_logger_start(void)
{
	kthread_t *tp;

	mutex_enter(&lw8_logger_lock);

	if (lw8_logger_tid == 0) {
		/* Force retrieval of any pending messages */
		lw8_logger_sig = LW8_LOGGER_PROCESSNOW;

		tp = thread_create(NULL, 0, lw8_logger, NULL, 0,
		    &p0, TS_RUN, maxclsyspri);
		lw8_logger_tid = tp->t_did;
	}

	mutex_exit(&lw8_logger_lock);
}

static void
lw8_logger_destroy(void)
{
	kt_did_t tid;

	mutex_enter(&lw8_logger_lock);
	tid = lw8_logger_tid;
	if (tid != 0) {
		lw8_logger_sig = LW8_LOGGER_EXITNOW;
		cv_signal(&lw8_logger_sig_cv);
		lw8_logger_tid = 0;
	}
	mutex_exit(&lw8_logger_lock);

	/*
	 * Wait for lw8_logger() to finish.
	 */
	if (tid != 0)
		thread_join(tid);
}

static void
lw8_logger_wakeup(void)
{
	mutex_enter(&lw8_logger_lock);

	if (lw8_logger_sig != LW8_LOGGER_EXITNOW)
		lw8_logger_sig = LW8_LOGGER_PROCESSNOW;
	cv_signal(&lw8_logger_sig_cv);

	mutex_exit(&lw8_logger_lock);
}
