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
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/callb.h>
#include <sys/strlog.h>
#include <sys/cyclic.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/rmc_comm.h>
#include <sys/machsystm.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/env.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/reboot.h>
#include <sys/envmon.h>
#include <sys/rmclomv_impl.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/ddi.h>
#include <sys/time.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>

#define	RMCRESBUFLEN	1024
#define	DATE_TIME_MSG_SIZE	78
#define	RMCLOMV_WATCHDOG_MODE	"rmclomv-watchdog-mode"
#define	DELAY_TIME	5000000	 /* 5 seconds, in microseconds */
#define	CPU_SIGNATURE_DELAY_TIME	5000000	 /* 5 secs, in microsecs */

extern void	pmugpio_watchdog_pat();

extern int	watchdog_activated;
static int	last_watchdog_msg = 1;
extern int	watchdog_enable;
extern int	boothowto;

int		rmclomv_watchdog_mode;

/*
 * functions local to this driver.
 */
static int	rmclomv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int	rmclomv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	rmclomv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static uint_t	rmclomv_break_intr(caddr_t arg);
static int	rmclomv_add_intr_handlers(void);
static int	rmclomv_remove_intr_handlers(void);
static uint_t	rmclomv_event_data_handler(char *);
static void	rmclomv_dr_data_handler(const char *, int);
static int	rmclomv_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	rmclomv_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	rmclomv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);
static void	rmclomv_checkrmc_start(void);
static void	rmclomv_checkrmc_destroy(void);
static void	rmclomv_checkrmc_wakeup(void *);
static void	rmclomv_refresh_start(void);
static void	rmclomv_refresh_destroy(void);
static void	rmclomv_refresh_wakeup(void);
static void	rmclomv_reset_cache(rmclomv_cache_section_t *new_chain,
    rmclomv_cache_section_t *new_subchain, dp_get_sysinfo_r_t *sysinfo);
static rmclomv_cache_section_t *rmclomv_find_section(
    rmclomv_cache_section_t *start, uint16_t sensor);
static rmclomv_cache_section_t *create_cache_section(int sensor_type, int num);
static int	get_sensor_by_name(const rmclomv_cache_section_t *section,
    const char *name, int *index);
static int	validate_section_entry(rmclomv_cache_section_t *section,
    int index);
static int	add_names_to_section(rmclomv_cache_section_t *section);
static void	free_section(rmclomv_cache_section_t *section);
static void	add_section(rmclomv_cache_section_t **head,
    rmclomv_cache_section_t *section);
static int	rmclomv_do_cmd(int req_cmd, int resp_cmd, int resp_len,
    intptr_t arg_req, intptr_t arg_res);
static void	refresh_name_cache(int force_fail);
static void	set_val_unav(envmon_sensor_t *sensor);
static void	set_fan_unav(envmon_fan_t *fan);
static int	do_psu_cmd(intptr_t arg, int mode, envmon_indicator_t *env_ind,
    dp_get_psu_status_t *rmc_psu, dp_get_psu_status_r_t *rmc_psu_r,
    int detector_type);
static uint_t rmc_set_watchdog_timer(uint_t timeoutval);
static uint_t rmc_clear_watchdog_timer(void);
static void send_watchdog_msg(int msg);
static void plat_timesync(void *arg);

static kmutex_t		timesync_lock;
static clock_t		timesync_interval = 0;
static timeout_id_t	timesync_tid = 0;

/*
 * Driver entry points
 */
static struct cb_ops rmclomv_cb_ops = {
	rmclomv_open,	/* open */
	rmclomv_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	rmclomv_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops rmclomv_ops = {
	DEVO_REV,
	0,			/* ref count */
	rmclomv_getinfo,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	rmclomv_attach,		/* attach() */
	rmclomv_detach,		/* detach */
	nodev,			/* reset */
	&rmclomv_cb_ops,		/* pointer to cb_ops structure */
	(struct bus_ops *)NULL,
	nulldev,		/* power() */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. This is a driver */
	"rmclomv control driver",	/* Name of the module */
	&rmclomv_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Device info
 */
static dev_info_t		*rmclomv_dip = NULL;
static int			rmclomv_break_requested = B_FALSE;
static ddi_softintr_t		rmclomv_softintr_id;
static ddi_iblock_cookie_t	rmclomv_soft_iblock_cookie;

extern void (*abort_seq_handler)();
/* key_position is effective key-position. Set to locked if unknown */
static rsci8 key_position = RMC_KEYSWITCH_POS_LOCKED;
/* real_key_position starts off as unknown and records value actually seen */
static rsci8 real_key_position = RMC_KEYSWITCH_POS_UNKNOWN;
static void rmclomv_abort_seq_handler(char *msg);

/*
 * mutexes which protect the interrupt handlers.
 */
static kmutex_t		rmclomv_event_hdlr_lock;
static kmutex_t		rmclomv_refresh_lock;
static kcondvar_t	rmclomv_refresh_sig_cv;
static kmutex_t		rmclomv_checkrmc_lock;
static kcondvar_t	rmclomv_checkrmc_sig_cv;

/*
 * mutex to protect the handle_name cache
 */
static kmutex_t		rmclomv_cache_lock;

/*
 * mutex to protect the RMC state
 */
static kmutex_t		rmclomv_state_lock;

/*
 * Payloads of the event handlers.
 */
static dp_event_notification_t	rmclomv_event_payload;
static rmc_comm_msg_t	rmclomv_event_payload_msg;

/*
 * Checkrmc commands..
 */
#define	RMCLOMV_CHECKRMC_EXITNOW	(-1)
#define	RMCLOMV_CHECKRMC_WAIT		0
#define	RMCLOMV_CHECKRMC_PROCESSNOW	1

/*
 * Checkrmc thread state
 */
static int rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_WAIT;
static kt_did_t rmclomv_checkrmc_tid = 0;

/*
 * RMC state data
 */
#define	RMCLOMV_RMCSTATE_UNKNOWN	0
#define	RMCLOMV_RMCSTATE_OK		1
#define	RMCLOMV_RMCSTATE_FAILED		2
#define	RMCLOMV_RMCSTATE_DOWNLOAD	3

/*
 * RMC error indicator values (status from last RMC command)
 */
#define	RMCLOMV_RMCERROR_NONE		0

/* fail RMC after 5 minutes without a good response */
#define	RMCLOMV_RMCFAILTHRESHOLD	5

/*
 * rmclomv_rmc_state is the state reported in OperationalStatus.
 * rmclomv_rmc_error reflects the result of the last RMC interaction.
 * rmclomv_rmcfailcount is used by the rmclomv_checkrmc thread to count
 * failures in its regular status polls. Once RMCLOMV_RMCFAILTHRESHOLD
 * is reached, rmclomv_rmc_state is marked as RMCLOMV_RMCSTATE_FAILED.
 */
static int	rmclomv_rmc_state = RMCLOMV_RMCSTATE_UNKNOWN;
static int	rmclomv_rmc_error = RMCLOMV_RMCERROR_NONE;
static int	rmclomv_rmcfailcount;

/*
 * Refresh commands..
 */
#define	RMCLOMV_REFRESH_EXITNOW		(-1)
#define	RMCLOMV_REFRESH_WAIT		0
#define	RMCLOMV_REFRESH_PROCESSNOW	1

/*
 * Refresh thread state
 */
static int rmclomv_refresh_sig = RMCLOMV_REFRESH_WAIT;
static kt_did_t rmclomv_refresh_tid = 0;

/*
 * timeout id
 */
static timeout_id_t	timer_id;

/*
 * Handle-name cache
 */
#define	LOCK_CACHE		mutex_enter(&rmclomv_cache_lock);
#define	RELEASE_CACHE		mutex_exit(&rmclomv_cache_lock);
static rmclomv_cache_section_t	*rmclomv_cache;		/* main handle-names */
static rmclomv_cache_section_t	*rmclomv_subcache;	/* derived names */
static dp_get_sysinfo_r_t	rmclomv_sysinfo_data;
static boolean_t		rmclomv_sysinfo_valid;
static int			rmclomv_cache_valid;

extern pri_t maxclsyspri;

/*
 * static strings
 */
static const char	str_percent[]		= "%";
static const char	str_rpm[]		= " rpm";
static const char	str_ip_volts_ind[]	= "P_PWR";
static const char	str_ip2_volts_ind[]	= "P_PWR2";
static const char	str_ff_pok_ind[]	= "FF_POK";
static const char	str_vlo_volts_ind[]	= "FF_UV";
static const char	str_vhi_volts_ind[]	= "FF_OV";
static const char	str_chi_amps_ind[]	= "FF_OC";
static const char	str_chi_nr_ind[]	= "FF_NR";
static const char	str_ot_tmpr_ind[]	= "FF_OT";
static const char	str_fan_ind[]		= "FF_FAN";
static const char	str_pdct_fan_ind[]	= "FF_PDCT_FAN";
static const char	str_sc[]		= "SC";

int
_init(void)
{
	int	error = 0;

	mutex_init(&rmclomv_event_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&rmclomv_checkrmc_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rmclomv_refresh_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rmclomv_cache_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rmclomv_state_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&timesync_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rmclomv_checkrmc_sig_cv, NULL, CV_DRIVER, NULL);
	cv_init(&rmclomv_refresh_sig_cv, NULL, CV_DRIVER, NULL);

	error = mod_install(&modlinkage);
	if (error) {
		cv_destroy(&rmclomv_refresh_sig_cv);
		cv_destroy(&rmclomv_checkrmc_sig_cv);
		mutex_destroy(&rmclomv_state_lock);
		mutex_destroy(&rmclomv_cache_lock);
		mutex_destroy(&rmclomv_refresh_lock);
		mutex_destroy(&rmclomv_checkrmc_lock);
		mutex_destroy(&rmclomv_event_hdlr_lock);
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
	cv_destroy(&rmclomv_refresh_sig_cv);
	cv_destroy(&rmclomv_checkrmc_sig_cv);
	mutex_destroy(&timesync_lock);
	mutex_destroy(&rmclomv_state_lock);
	mutex_destroy(&rmclomv_cache_lock);
	mutex_destroy(&rmclomv_refresh_lock);
	mutex_destroy(&rmclomv_checkrmc_lock);
	mutex_destroy(&rmclomv_event_hdlr_lock);
	return (error);
}


/* ARGSUSED */
static int
rmclomv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	minor_t m = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((m != 0) || (rmclomv_dip == NULL)) {
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = rmclomv_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)m;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


static int
rmclomv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			err;
	char			*wdog_state;
	int			attaching = 1;

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * only allow one instance
		 */
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		err = ddi_create_minor_node(dip, "rmclomv", S_IFCHR,
		    instance, DDI_PSEUDO, NULL);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);

		/*
		 * Register with rmc_comm to prevent it being detached
		 * (in the unlikely event that its attach succeeded on a
		 * platform whose platmod doesn't lock it down).
		 */
		err = rmc_comm_register();
		if (err != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		/* Remember the dev info */
		rmclomv_dip = dip;

		/*
		 * Add the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = rmclomv_add_intr_handlers();
		if (err != DDI_SUCCESS) {
			rmc_comm_unregister();
			ddi_remove_minor_node(dip, NULL);
			rmclomv_dip = NULL;
			return (DDI_FAILURE);
		}

		rmclomv_checkrmc_start();
		rmclomv_refresh_start();

		abort_seq_handler = rmclomv_abort_seq_handler;
		ddi_report_dev(dip);

		/*
		 * Check whether we have an application watchdog
		 */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, RMCLOMV_WATCHDOG_MODE,
		    &wdog_state) == DDI_PROP_SUCCESS) {
			if (strcmp(wdog_state, "app") == 0) {
				rmclomv_watchdog_mode = 1;
				watchdog_enable = 0;
			}
			else
				rmclomv_watchdog_mode = 0;
			ddi_prop_free(wdog_state);
		}

		tod_ops.tod_set_watchdog_timer = rmc_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = rmc_clear_watchdog_timer;

		/*
		 * Now is a good time to activate hardware watchdog
		 * (if one exists).
		 */
		mutex_enter(&tod_lock);
		if (watchdog_enable && tod_ops.tod_set_watchdog_timer != NULL)
			err = tod_ops.tod_set_watchdog_timer(0);
		mutex_exit(&tod_lock);
		if (err != 0)
			printf("Hardware watchdog enabled\n");

		/*
		 * Set time interval and start timesync routine.
		 * Also just this once set the Solaris clock
		 * to the RMC clock.
		 */
		timesync_interval = drv_usectohz(5*60 * MICROSEC);
		plat_timesync((void *) &attaching);

		return (DDI_SUCCESS);
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


static int
rmclomv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	timeout_id_t	tid;
	int		instance;
	int		err;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		/*
		 * Remove the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = rmclomv_remove_intr_handlers();
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to remove event handlers");
			return (DDI_FAILURE);
		}
		rmclomv_checkrmc_destroy();
		rmclomv_refresh_destroy();
		rmclomv_reset_cache(NULL, NULL, NULL);
		ddi_remove_minor_node(dip, NULL);

		mutex_enter(&timesync_lock);
		tid = timesync_tid;
		timesync_tid = 0;
		timesync_interval = 0;
		mutex_exit(&timesync_lock);
		(void) untimeout(tid);

		/* Forget the dev info */
		rmclomv_dip = NULL;
		rmc_comm_unregister();
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
rmclomv_add_intr_handlers()
{
	int	err;

	if (ddi_get_soft_iblock_cookie(rmclomv_dip, DDI_SOFTINT_HIGH,
	    &rmclomv_soft_iblock_cookie) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	err = ddi_add_softintr(rmclomv_dip, DDI_SOFTINT_HIGH,
	    &rmclomv_softintr_id, &rmclomv_soft_iblock_cookie, NULL,
	    rmclomv_break_intr, NULL);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);
	rmclomv_event_payload_msg.msg_buf = (caddr_t)&rmclomv_event_payload;
	rmclomv_event_payload_msg.msg_len = sizeof (rmclomv_event_payload);
	err = rmc_comm_reg_intr(DP_RMC_EVENTS, rmclomv_event_data_handler,
	    &rmclomv_event_payload_msg, NULL, &rmclomv_event_hdlr_lock);
	if (err != 0) {
		ddi_remove_softintr(rmclomv_softintr_id);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
rmclomv_remove_intr_handlers(void)
{
	int err = rmc_comm_unreg_intr(DP_RMC_EVENTS,
	    rmclomv_event_data_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister DP_RMC_EVENTS "
		    "handler. Err=%d", err);
		return (DDI_FAILURE);
	}
	ddi_remove_softintr(rmclomv_softintr_id);
	return (DDI_SUCCESS);
}

static void
rmclomv_abort_seq_handler(char *msg)
{
	if (key_position == RMC_KEYSWITCH_POS_LOCKED)
		cmn_err(CE_CONT, "KEY in LOCKED position, "
		    "ignoring debug enter sequence");
	else  {
		rmclomv_break_requested = B_TRUE;
		if (msg != NULL)
			prom_printf("%s\n", msg);

		ddi_trigger_softintr(rmclomv_softintr_id);
	}
}

/* ARGSUSED */
static uint_t
rmclomv_break_intr(caddr_t arg)
{
	if (rmclomv_break_requested) {
		rmclomv_break_requested = B_FALSE;
		debug_enter(NULL);
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_UNCLAIMED);
}

/*
 * Create a cache section structure
 */
static rmclomv_cache_section_t *
create_cache_section(int sensor_type, int num)
{
	size_t len = offsetof(rmclomv_cache_section_t, entry[0]) +
	    num * sizeof (rmclomv_cache_entry_t);
	rmclomv_cache_section_t *ptr = kmem_zalloc(len, KM_SLEEP);
	ptr->next_section = NULL;
	ptr->sensor_type = sensor_type;
	ptr->num_entries = num;
	ptr->section_len = len;
	return (ptr);
}

/*
 * Free a cache_section.
 */
static void
free_section(rmclomv_cache_section_t *section)
{
	size_t len = section->section_len;
	kmem_free(section, len);
}

/*
 * adds supplied section to end of cache chain
 * must be called with cache locked
 */
static void
add_section(rmclomv_cache_section_t **head, rmclomv_cache_section_t *section)
{
	section->next_section = *head;
	*head = section;
}

/*
 * This function releases all cache sections and exchanges the two
 * chain heads for new values.
 */
static void
rmclomv_reset_cache(rmclomv_cache_section_t *new_chain,
    rmclomv_cache_section_t *new_subchain, dp_get_sysinfo_r_t *sysinfo)
{
	rmclomv_cache_section_t	*first;
	rmclomv_cache_section_t	*sub_first;
	rmclomv_cache_section_t	*next;

	LOCK_CACHE

	rmclomv_cache_valid = (new_chain != NULL);
	first = rmclomv_cache;
	rmclomv_cache = new_chain;
	sub_first = rmclomv_subcache;
	rmclomv_subcache = new_subchain;

	if (sysinfo == NULL)
		bzero(&rmclomv_sysinfo_data, sizeof (rmclomv_sysinfo_data));
	else
		bcopy(sysinfo, &rmclomv_sysinfo_data,
		    sizeof (rmclomv_sysinfo_data));

	rmclomv_sysinfo_valid = (sysinfo != NULL);

	RELEASE_CACHE

	while (first != NULL) {
		next = first->next_section;
		free_section(first);
		first = next;
	}

	while (sub_first != NULL) {
		next = sub_first->next_section;
		free_section(sub_first);
		sub_first = next;
	}
}

/*
 * cache must be locked before calling rmclomv_find_section
 */
static rmclomv_cache_section_t *
rmclomv_find_section(rmclomv_cache_section_t *start, uint16_t sensor)
{
	rmclomv_cache_section_t	*next = start;

	while ((next != NULL) && (next->sensor_type != sensor))
		next = next->next_section;

	return (next);
}

/*
 * Return a string presenting the keyswitch position
 * For unknown values returns "Unknown"
 */
static char *
rmclomv_key_position(enum rmc_keyswitch_pos pos)
{
	switch (pos) {

	case RMC_KEYSWITCH_POS_NORMAL:
		return ("NORMAL");
	case RMC_KEYSWITCH_POS_DIAG:
		return ("DIAG");
	case RMC_KEYSWITCH_POS_LOCKED:
		return ("LOCKED");
	case RMC_KEYSWITCH_POS_OFF:
		return ("STBY");
	default:
		return ("UNKNOWN");
	}
}

/*
 * The sensor id name is sought in the supplied section and if found
 * its index within the section is written to *index.
 * Return value is zero for success, otherwise -1.
 * The cache must be locked before calling get_sensor_by_name
 */
static int
get_sensor_by_name(const rmclomv_cache_section_t *section,
    const char *name, int *index)
{
	int i;

	for (i = 0; i < section->num_entries; i++) {
		if (strcmp(name, section->entry[i].handle_name.name) == 0) {
			*index = i;
			return (0);
		}
	}

	*index = 0;
	return (-1);
}

/*
 * fills in the envmon_handle name
 * if it is unknown (not cached), the dp_handle_t is returned as a hex-digit
 * string
 */
static void
rmclomv_hdl_to_envhdl(dp_handle_t hdl, envmon_handle_t *envhdl)
{
	rmclomv_cache_section_t *next;
	int			i;

	LOCK_CACHE

	for (next = rmclomv_cache; next != NULL; next = next->next_section) {
		for (i = 0; i < next->num_entries; i++) {
			if (next->entry[i].handle == hdl) {
				*envhdl = next->entry[i].handle_name;
					RELEASE_CACHE
					return;
			}
		}
	}

	/*
	 * Sought handle not currently cached.
	 */
	RELEASE_CACHE

	(void) snprintf(envhdl->name, sizeof (envhdl->name),
	    "Unknown SC node 0x%x", hdl);
}

static void
rmclomv_dr_data_handler(const char *fru_name, int hint)
{
	int				err = 0;
	nvlist_t			*attr_list;
	char				attach_pnt[MAXPATHLEN];

	(void) snprintf(attach_pnt, sizeof (attach_pnt), "%s", fru_name);

	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN,
		    "Failed to allocate name-value list for %s event", EC_DR);
		return;
	}

	err = nvlist_add_string(attr_list, DR_AP_ID, attach_pnt);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
		    DR_AP_ID, EC_DR);
		nvlist_free(attr_list);
		return;
	}

	/*
	 * Add the hint
	 */
	err = nvlist_add_string(attr_list, DR_HINT, SE_HINT2STR(hint));
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s event",
		    DR_HINT, EC_DR);
		nvlist_free(attr_list);
		return;
	}

	err = ddi_log_sysevent(rmclomv_dip, DDI_VENDOR_SUNW, EC_DR,
	    ESC_DR_AP_STATE_CHANGE, attr_list, NULL, DDI_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event",
		    DR_AP_ID, EC_DR);
	}

	nvlist_free(attr_list);
}

static void
fan_sysevent(char *fru_name, char *sensor_name, int sub_event)
{
	nvlist_t		*attr_list;
	char			fan_str[MAXNAMELEN];
	int			err;

	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN,
		    "Failed to allocate name-value list for %s/%s event",
		    EC_ENV, ESC_ENV_FAN);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_ID, fru_name);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_ID, EC_ENV, ESC_ENV_FAN);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_RESOURCE_ID, sensor_name);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_RESOURCE_ID, EC_ENV, ESC_ENV_FAN);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_DEVICE, ENV_RESERVED_ATTR);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_DEVICE, EC_ENV, ESC_ENV_FAN);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_int32(attr_list, ENV_FRU_STATE,
	    (sub_event == RMC_ENV_FAULT_EVENT) ? ENV_FAILED : ENV_OK);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_STATE, EC_ENV, ESC_ENV_FAN);
		nvlist_free(attr_list);
		return;
	}

	if (sub_event == RMC_ENV_FAULT_EVENT) {
		(void) snprintf(fan_str, sizeof (fan_str),
		    "fan %s/%s is now failed", fru_name, sensor_name);
	} else {
		(void) snprintf(fan_str, sizeof (fan_str),
		    "fan %s/%s is now ok", fru_name, sensor_name);
	}
	err = nvlist_add_string(attr_list, ENV_MSG, fan_str);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_MSG, EC_ENV, ESC_ENV_FAN);
		nvlist_free(attr_list);
		return;
	}

	err = ddi_log_sysevent(rmclomv_dip, DDI_VENDOR_SUNW, EC_ENV,
	    ESC_ENV_FAN, attr_list, NULL, DDI_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event",
		    EC_ENV, ESC_ENV_FAN);
	}

	cmn_err(CE_NOTE, "%s", fan_str);
	nvlist_free(attr_list);
}

static void
threshold_sysevent(char *fru_name, char *sensor_name, int sub_event,
	char event_type)
{
	nvlist_t		*attr_list;
	int			err;
	char			*subclass;
	char			sensor_str[MAXNAMELEN];

	subclass = (event_type == 'T') ? ESC_ENV_TEMP : ESC_ENV_POWER;

	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, KM_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN,
		    "Failed to allocate name-value list for %s/%s event",
		    EC_ENV, subclass);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_ID, fru_name);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_ID, EC_ENV, subclass);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_RESOURCE_ID, sensor_name);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_RESOURCE_ID, EC_ENV, subclass);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, ENV_FRU_DEVICE, ENV_RESERVED_ATTR);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_DEVICE, EC_ENV, subclass);
		nvlist_free(attr_list);
		return;
	}

	switch (sub_event) {
	case RMC_ENV_OK_EVENT:
		err = nvlist_add_int32(attr_list, ENV_FRU_STATE, ENV_OK);
		break;
	case RMC_ENV_WARNING_THRESHOLD_EVENT:
		err = nvlist_add_int32(attr_list, ENV_FRU_STATE, ENV_WARNING);
		break;
	case RMC_ENV_SHUTDOWN_THRESHOLD_EVENT:
		err = nvlist_add_int32(attr_list, ENV_FRU_STATE, ENV_FAILED);
		break;
	}
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_FRU_STATE, EC_ENV, subclass);
		nvlist_free(attr_list);
		return;
	}

	switch (sub_event) {
	case RMC_ENV_OK_EVENT:
		(void) snprintf(sensor_str, sizeof (sensor_str),
		    "sensor %s/%s is now ok", fru_name,
		    sensor_name);
		break;
	case RMC_ENV_WARNING_THRESHOLD_EVENT:
		(void) snprintf(sensor_str, sizeof (sensor_str),
		    "sensor %s/%s is now outside warning thresholds", fru_name,
		    sensor_name);
		break;
	case RMC_ENV_SHUTDOWN_THRESHOLD_EVENT:
		(void) snprintf(sensor_str, sizeof (sensor_str),
		    "sensor %s/%s is now outside shutdown thresholds", fru_name,
		    sensor_name);
		break;
	}
	err = nvlist_add_string(attr_list, ENV_MSG, sensor_str);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to add attr [%s] for %s/%s event",
		    ENV_MSG, EC_ENV, subclass);
		nvlist_free(attr_list);
		return;
	}

	err = ddi_log_sysevent(rmclomv_dip, DDI_VENDOR_SUNW, EC_ENV,
	    subclass, attr_list, NULL, DDI_NOSLEEP);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to log %s/%s event",
		    EC_ENV, subclass);
	}

	cmn_err(CE_NOTE, "%s", sensor_str);
	nvlist_free(attr_list);
}

static uint_t
rmclomv_event_data_handler(char *arg)
{
	dp_event_notification_t	*payload;
	rmc_comm_msg_t	*msg;
	envmon_handle_t envhdl;
	int hint;
	char *ptr, *save_ptr;

	if (arg == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	msg = (rmc_comm_msg_t *)arg;
	if (msg->msg_buf == NULL) {
		return (DDI_INTR_CLAIMED);
	}

	payload = (dp_event_notification_t *)msg->msg_buf;
	switch (payload->event) {

	case RMC_KEYSWITCH_EVENT:
		real_key_position = payload->event_info.ev_keysw.key_position;
		cmn_err(CE_NOTE, "keyswitch change event - state = %s",
		    rmclomv_key_position(real_key_position));
		if ((real_key_position != RMC_KEYSWITCH_POS_UNKNOWN) &&
		    (real_key_position <= RMC_KEYSWITCH_POS_OFF)) {
			key_position = real_key_position;
		} else {
			/* treat unknown key position as locked */
			key_position = RMC_KEYSWITCH_POS_LOCKED;
		}
		break;

	case RMC_HPU_EVENT:
		/*
		 * send appropriate sysevent
		 */
		switch (payload->event_info.ev_hpunot.sub_event) {
		case RMC_HPU_REMOVE_EVENT:
			hint = SE_HINT_REMOVE;
			break;
		case RMC_HPU_INSERT_EVENT:
			hint = SE_HINT_INSERT;
			break;
		default:
			hint = SE_NO_HINT;
			break;
		}
		rmclomv_hdl_to_envhdl(payload->event_info.ev_hpunot.hpu_hdl,
		    &envhdl);
		rmclomv_dr_data_handler(envhdl.name, hint);
		break;

	case RMC_INIT_EVENT:
		/*
		 * Wake up the refresh thread.
		 */
		rmclomv_refresh_wakeup();

		/*
		 * Wake up the checkrmc thread for an early indication to PICL
		 */
		rmclomv_checkrmc_wakeup(NULL);
		break;

	case RMC_ENV_EVENT:
		rmclomv_hdl_to_envhdl(payload->event_info.ev_envnot.env_hdl,
		    &envhdl);

		/* split name into fru name and sensor name */
		ptr = strchr(envhdl.name, '.');

		/* must have at least one '.' */
		if (ptr == NULL)
			break;

		/* find last '.' - convert the others to '/' */
		for (;;) {
			save_ptr = ptr;
			ptr = strchr(ptr, '.');
			if (ptr == NULL) {
				ptr = save_ptr;
				break;
			}
			*save_ptr = '/';
		}
		*ptr = '\0';
		ptr++;
		/* is it a voltage or temperature sensor? */
		if ((*ptr == 'V' || *ptr == 'T') && *(ptr + 1) == '_') {
			switch (payload->event_info.ev_envnot.sub_event) {
			case RMC_ENV_WARNING_THRESHOLD_EVENT:
			case RMC_ENV_SHUTDOWN_THRESHOLD_EVENT:
			case RMC_ENV_OK_EVENT:
				threshold_sysevent(envhdl.name, ptr,
				    payload->event_info.ev_envnot.sub_event,
				    *ptr);
				break;
			default:
				break;
			}
		}

		/*
		 * is it a fan sensor?
		 * Fan sensor names end either in RS, F0 or F1
		 */
		if ((*ptr == 'R' && *(ptr + 1) == 'S' && *(ptr + 2) == '\0') ||
		    (*ptr == 'F' && *(ptr + 1) == '0' && *(ptr + 2) == '\0') ||
		    (*ptr == 'F' && *(ptr + 1) == '1' && *(ptr + 2) == '\0')) {
			switch (payload->event_info.ev_envnot.sub_event) {
			case RMC_ENV_FAULT_EVENT:
			case RMC_ENV_OK_EVENT:
				fan_sysevent(envhdl.name, ptr,
				    payload->event_info.ev_envnot.sub_event);
				break;
			default:
				break;
			}
		}
		break;

	case RMC_LOG_EVENT:
	{
		int level = 10;
		int flags = SL_NOTE | SL_CONSOLE;
		char *message =
		    (char *)payload->event_info.ev_rmclog.log_record;

		message[ payload->event_info.ev_rmclog.log_record_size] = '\0';

		/*
		 * Logs have a 10 character prefix - specifying the severity of
		 * the event being logged. Thus all the magic number 10s down
		 * here
		 */
		if (0 == strncmp("CRITICAL: ", message, 10)) {
			message += 10;
			level = 0;
			flags = SL_FATAL | SL_ERROR | SL_CONSOLE;
		} else if (0 == strncmp("MAJOR:    ", message, 10)) {
			message += 10;
			level = 5;
			flags = SL_WARN | SL_ERROR | SL_CONSOLE;
		} else if (0 == strncmp("MINOR:    ", message, 10)) {
			message += 10;
			level = 10;
			flags = SL_NOTE | SL_CONSOLE;
		}

		(void) strlog(0, 0, level, flags, message);
		break;
	}

	default:
		return (DDI_INTR_CLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED*/
static int
rmclomv_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	int error = 0;
	int instance = getminor(*dev_p);

	if (instance != 0)
		return (ENXIO);

	if ((flag & FWRITE) != 0 && (error = drv_priv(cred_p)) != 0)
		return (error);

	return (0);
}

/*ARGSUSED*/
static int
rmclomv_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	return (DDI_SUCCESS);
}

static int
rmclomv_do_cmd(int req_cmd, int resp_cmd, int resp_len, intptr_t arg_req,
    intptr_t arg_res)
{
	rmc_comm_msg_t request, *reqp = &request;
	rmc_comm_msg_t response, *resp = &response;
	int rv = 0;

	bzero((caddr_t)&request, sizeof (request));
	reqp->msg_type = req_cmd;
	reqp->msg_buf = (caddr_t)arg_req;
	bzero((caddr_t)&response, sizeof (response));
	resp->msg_type = resp_cmd;
	resp->msg_buf = (caddr_t)arg_res;
	resp->msg_len = resp_len;

	switch (req_cmd) {
	case DP_GET_SYSINFO:
		resp->msg_len = sizeof (dp_get_sysinfo_r_t);
		break;
	case DP_GET_EVENT_LOG:
		resp->msg_len = sizeof (dp_get_event_log_r_t);
		break;
	case DP_GET_VOLTS:
		reqp->msg_len = sizeof (dp_get_volts_t);
		break;
	case DP_GET_TEMPERATURES:
		reqp->msg_len = sizeof (dp_get_temperatures_t);
		break;
	case DP_GET_CIRCUIT_BRKS:
		reqp->msg_len = sizeof (dp_get_circuit_brks_t);
		break;
	case DP_GET_FAN_STATUS:
		reqp->msg_len = sizeof (dp_get_fan_status_t);
		break;
	case DP_GET_PSU_STATUS:
		reqp->msg_len = sizeof (dp_get_psu_status_t);
		break;
	case DP_GET_LED_STATE:
		reqp->msg_len = sizeof (dp_get_led_state_t);
		break;
	case DP_SET_LED_STATE:
		reqp->msg_len = sizeof (dp_set_led_state_t);
		break;
	case DP_GET_FRU_STATUS:
		reqp->msg_len = sizeof (dp_get_fru_status_t);
		break;
	case DP_GET_HANDLE_NAME:
		reqp->msg_len = sizeof (dp_get_handle_name_t);
		break;
	case DP_GET_ALARM_STATE:
		reqp->msg_len = sizeof (dp_get_alarm_state_t);
		break;
	case DP_SET_ALARM_STATE:
		reqp->msg_len = sizeof (dp_set_alarm_state_t);
		break;
	case DP_GET_SDP_VERSION:
		resp->msg_len = sizeof (dp_get_sdp_version_r_t);
		break;
	case DP_GET_CHASSIS_SERIALNUM:
		reqp->msg_len = 0;
		break;
	case DP_GET_DATE_TIME:
		reqp->msg_len = 0;
		break;
	default:
		return (EINVAL);
	}

	rv = rmc_comm_request_response(reqp, resp,
	    RMCLOMV_DEFAULT_MAX_MBOX_WAIT_TIME);

	if (rv != RCNOERR) {
		/*
		 * RMC returned an error or failed to respond.
		 * Where the RMC itself is implicated, rmclomv_rmc_error
		 * is set non-zero. It is cleared after an error free exchange.
		 * Two failure cases are distinguished:
		 * RMCLOMV_RMCSTATE_FAILED and RMCLOMV_RMCSTATE_DOWNLOAD.
		 */
		switch (rv) {
		case RCENOSOFTSTATE:
			/* invalid/NULL soft state structure */
			return (EIO);
		case RCENODATALINK:
			/*
			 * firmware download in progress,
			 * can you come back later?
			 */
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_DOWNLOAD;
			rmclomv_rmc_state = RMCLOMV_RMCSTATE_DOWNLOAD;
			return (EAGAIN);
		case RCENOMEM:
			/* memory problems */
			return (ENOMEM);
		case RCECANTRESEND:
			/* resend failed */
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_FAILED;
			return (EIO);
		case RCEMAXRETRIES:
			/* reply not received - retries exceeded */
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_FAILED;
			return (EINTR);
		case RCETIMEOUT:
			/* reply not received - command has timed out */
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_FAILED;
			return (EINTR);
		case RCEINVCMD:
			/* data protocol cmd not supported */
			return (ENOTSUP);
		case RCEINVARG:
			/* invalid argument(s) */
			return (ENOTSUP);
		case RCEGENERIC:
			/* generic error */
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_FAILED;
			return (EIO);
		default:
			rmclomv_rmc_error = RMCLOMV_RMCSTATE_FAILED;
			return (EIO);
		}
	}

	rmclomv_rmc_error = RMCLOMV_RMCERROR_NONE;
	return (0);
}

/*
 * validate_section_entry checks that the entry at the specified index
 * is valid and not duplicated by an entry above. If these tests fail
 * the entry is removed and B_FALSE returned. Otherwise returns B_TRUE.
 */
static int
validate_section_entry(rmclomv_cache_section_t *section, int index)
{
	int			i;
	rmclomv_cache_entry_t	*entry;

	for (i = index; i < section->num_entries; i++) {
		entry = &section->entry[i];
		if (entry->handle_name.name[0] == '\0') {
			cmn_err(CE_WARN,
			    "rmclomv: empty handle_name, handle 0x%x type %x",
			    entry->handle, section->sensor_type);
		} else if (entry->ind_mask != 0) {
			continue;	/* skip special entries */
		} else if (entry->handle == DP_NULL_HANDLE) {
			cmn_err(CE_WARN,
			    "rmclomv: null handle id for \"%s\" type %x",
			    entry->handle_name.name, section->sensor_type);
		} else if (i == index) {
			continue;
		} else if (section->entry[index].handle == entry->handle) {
			cmn_err(CE_WARN,
			    "rmclomv: duplicate handle 0x%x type %x",
			    entry->handle, section->sensor_type);
		} else if (strcmp(entry->handle_name.name,
		    section->entry[index].handle_name.name) == 0) {
			cmn_err(CE_WARN,
			    "rmclomv: duplicate handle_name \"%s\", "
			    "handle 0x%x type %x", entry->handle_name.name,
			    entry->handle, section->sensor_type);
		} else
			continue;

		/*
		 * need to remove the entry at index
		 */
		section->num_entries--;

		for (i = index; i < section->num_entries; i++) {
			section->entry[i] = section->entry[i + 1];
		}

		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Populate a section containing handles with corresponding names
 * The supplied section structure must not be publically visible and the
 * name cache must not be locked either (because RMC i/o is required).
 *
 * This is the place where a sanity check is applied. Entries containing
 * duplicate handles, duplicate names or empty names are removed and the
 * structure is compacted. As a result num_entries may be reduced.
 */
static int
add_names_to_section(rmclomv_cache_section_t *section)
{
	int			retval = 0;
	int			ditched = B_FALSE;
	int			index;
	dp_get_handle_name_r_t	handle_name_r;
	rmclomv_cache_entry_t	*entry;

	for (index = 0; index < section->num_entries; index++) {
		entry = &section->entry[index];
		if (entry->ind_mask != 0)
			continue;	/* skip special entries */
		handle_name_r.handle = entry->handle;
		retval = rmclomv_do_cmd(DP_GET_HANDLE_NAME,
		    DP_GET_HANDLE_NAME_R, sizeof (handle_name_r),
		    (intptr_t)&handle_name_r, (intptr_t)&handle_name_r);
		if (retval == 0)
			bcopy(handle_name_r.name,
			    entry->handle_name.name, DP_MAX_HANDLE_NAME);
	}

	/*
	 * now ditch invalid and duplicate entries
	 */
	for (index = 0; index < section->num_entries; index++) {
		while (validate_section_entry(section, index) == B_FALSE)
			ditched = B_TRUE;
	}

	if (ditched)
		cmn_err(CE_WARN, "Retaining %d nodes of type %d",
		    section->num_entries, section->sensor_type);

	return (retval);
}

/*
 * The supplied (PSU) cache section is traversed and entries are created
 * for the individual indicators belonging to a PSU. These entries are
 * placed in a private chain. The caller, subsequently acquires the
 * cache lock and copies the chain head to make it public.
 * The handle-names for PSU indicators are derived from the parent PSU
 * handle-name.
 * NOTE: add_names_to_section() may have reduced psu_section->num_entries
 *       so DON'T USE psu_resp->num_psus
 */
static void
make_psu_subsections(rmclomv_cache_section_t *psu_section,
    rmclomv_cache_section_t **chain_head, dp_get_psu_status_r_t *psu_resp)
{
	int			index;
	int			subindex = 0;
	rmclomv_cache_section_t	*subsection;
	rmclomv_cache_entry_t	*src_entry;
	rmclomv_cache_entry_t	*dst_entry;

	subsection = create_cache_section(RMCLOMV_VOLT_IND,
	    RMCLOMV_MAX_VI_PER_PSU * psu_section->num_entries);
	for (index = 0; index < psu_section->num_entries; index++) {
		src_entry = &psu_section->entry[index];
		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_INPUT_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_INPUT_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_ip_volts_ind);
		}

		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_SEC_INPUT_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_SEC_INPUT_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_ip2_volts_ind);
		}

		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_OUTPUT_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_OUTPUT_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_ff_pok_ind);
		}

		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_OUTPUT_VLO_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_OUTPUT_VLO_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_vlo_volts_ind);
		}

		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_OUTPUT_VHI_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_OUTPUT_VHI_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_vhi_volts_ind);
		}
	}
	/*
	 * Adjust number of entries value in cache section
	 * to match the facts.
	 */
	subsection->num_entries = subindex;
	add_section(chain_head, subsection);

	subsection = create_cache_section(RMCLOMV_AMP_IND,
	    RMCLOMV_MAX_CI_PER_PSU * psu_section->num_entries);
	subindex = 0;
	for (index = 0; index < psu_section->num_entries; index++) {
		int mask = psu_resp->psu_status[index].mask;
		src_entry = &psu_section->entry[index];
		if ((mask & DP_PSU_OUTPUT_AHI_STATUS) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_OUTPUT_AHI_STATUS;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_chi_amps_ind);
		}
		if ((mask & DP_PSU_NR_WARNING) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_NR_WARNING;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_chi_nr_ind);
		}
	}
	subsection->num_entries = subindex;
	add_section(chain_head, subsection);

	subsection = create_cache_section(RMCLOMV_TEMP_IND,
	    psu_section->num_entries);
	subindex = 0;
	for (index = 0; index < psu_section->num_entries; index++) {
		if ((psu_resp->psu_status[index].mask &
		    DP_PSU_OVERTEMP_FAULT) != 0) {
			src_entry = &psu_section->entry[index];
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_OVERTEMP_FAULT;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name,
			    str_ot_tmpr_ind);
		}
	}
	subsection->num_entries = subindex;
	add_section(chain_head, subsection);

	subsection = create_cache_section(RMCLOMV_FAN_IND,
	    RMCLOMV_MAX_FI_PER_PSU * psu_section->num_entries);
	subindex = 0;
	for (index = 0; index < psu_section->num_entries; index++) {
		int mask = psu_resp->psu_status[index].mask;
		src_entry = &psu_section->entry[index];
		if ((mask & DP_PSU_FAN_FAULT) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_FAN_FAULT;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name, str_fan_ind);
		}
		if ((mask & DP_PSU_PDCT_FAN) != 0) {
			dst_entry = &subsection->entry[subindex++];
			dst_entry->handle = src_entry->handle;
			dst_entry->ind_mask = DP_PSU_PDCT_FAN;
			(void) snprintf(dst_entry->handle_name.name,
			    ENVMON_MAXNAMELEN, "%s.%s",
			    src_entry->handle_name.name, str_pdct_fan_ind);
		}
	}
	subsection->num_entries = subindex;
	add_section(chain_head, subsection);
}

static void
refresh_name_cache(int force_fail)
{
	union {
		dp_get_volts_t		u_volts_cmd;
		dp_get_temperatures_t	u_temp_cmd;
		dp_get_circuit_brks_t	u_ampi_cmd;
		dp_get_fan_status_t	u_fan_cmd;
		dp_get_psu_status_t	u_psu_cmd;
		dp_get_fru_status_t	u_fru_cmd;
		dp_get_led_state_t	u_led_cmd;
		dp_set_led_state_t	u_setled_cmd;
		dp_get_alarm_state_t	u_alarm_cmd;
		dp_set_alarm_state_t	u_setalarm_cmd;
	} rmc_cmdbuf;

/* defines for accessing union fields */
#define	volts_cmd	rmc_cmdbuf.u_volts_cmd
#define	temp_cmd	rmc_cmdbuf.u_temp_cmd
#define	ampi_cmd	rmc_cmdbuf.u_ampi_cmd
#define	fan_cmd		rmc_cmdbuf.u_fan_cmd
#define	psu_cmd		rmc_cmdbuf.u_psu_cmd
#define	fru_cmd		rmc_cmdbuf.u_fru_cmd
#define	led_cmd		rmc_cmdbuf.u_led_cmd
#define	setled_cmd	rmc_cmdbuf.u_setled_cmd
#define	alarm_cmd	rmc_cmdbuf.u_alarm_cmd
#define	setalarm_cmd	rmc_cmdbuf.u_setalarm_cmd

	/*
	 * Data area to read sensor data into
	 */
	static union {
		char			reservation[RMCRESBUFLEN];
		dp_get_volts_r_t	u_volts_r;
		dp_get_temperatures_r_t	u_temp_r;
		dp_get_circuit_brks_r_t	u_ampi_r;
		dp_get_fan_status_r_t	u_fan_r;
		dp_get_psu_status_r_t	u_psu_r;
		dp_get_fru_status_r_t	u_fru_r;
		dp_get_led_state_r_t	u_led_r;
		dp_set_led_state_r_t	u_setled_r;
		dp_get_alarm_state_r_t	u_alarm_r;
		dp_set_alarm_state_r_t	u_setalarm_r;
	} rmc_sensbuf;

/* defines for accessing union fields */
#define	volts_r		rmc_sensbuf.u_volts_r
#define	temp_r		rmc_sensbuf.u_temp_r
#define	ampi_r		rmc_sensbuf.u_ampi_r
#define	fan_r		rmc_sensbuf.u_fan_r
#define	psu_r		rmc_sensbuf.u_psu_r
#define	fru_r		rmc_sensbuf.u_fru_r
#define	led_r		rmc_sensbuf.u_led_r
#define	setled_r	rmc_sensbuf.u_setled_r
#define	alarm_r		rmc_sensbuf.u_alarm_r
#define	setalarm_r	rmc_sensbuf.u_setalarm_r

	int			retval = force_fail;
	int			retval1 = retval;
	int			index;
	rmclomv_cache_section_t	*my_chain = NULL;
	rmclomv_cache_section_t	*derived_chain = NULL;
	rmclomv_cache_section_t	*section;
	rmclomv_cache_section_t	*psu_section;
	rmclomv_cache_section_t	*fru_section;
	dp_get_sysinfo_r_t	sysinfo;
	rmclomv_cache_entry_t	*entry;

	if (retval == 0) {
		retval = rmclomv_do_cmd(DP_GET_SYSINFO, DP_GET_SYSINFO_R,
		    sizeof (sysinfo), NULL, (intptr_t)&sysinfo);
	}
	if (retval == 0) {
		fru_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_FRU_STATUS, DP_GET_FRU_STATUS_R,
		    RMCRESBUFLEN, (intptr_t)&fru_cmd, (intptr_t)&fru_r);
	}
	if (retval != 0)
		fru_r.num_frus = 0;

	/*
	 * Reserve space for special additional entries in the FRU section
	 */
	fru_section = create_cache_section(RMCLOMV_HPU_IND,
	    RMCLOMV_NUM_SPECIAL_FRUS + fru_r.num_frus);

	/*
	 * add special entry for RMC itself
	 */
	entry = &fru_section->entry[0];
	(void) snprintf(entry->handle_name.name, sizeof (envmon_handle_t),
	    "SC");
	entry->handle = 0;
	entry->ind_mask = 1;	/* flag as a special entry */

	/*
	 * populate any other FRU entries
	 */
	for (index = 0; index < fru_r.num_frus; index++) {
		fru_section->entry[RMCLOMV_NUM_SPECIAL_FRUS + index].handle =
		    fru_r.fru_status[index].handle;
		fru_section->entry[RMCLOMV_NUM_SPECIAL_FRUS + index].ind_mask =
		    0;
	}

	my_chain = fru_section;

	if (retval == 0) {
		volts_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_VOLTS, DP_GET_VOLTS_R,
		    RMCRESBUFLEN, (intptr_t)&volts_cmd, (intptr_t)&volts_r);
	}
	if (retval == 0) {
		section = create_cache_section(RMCLOMV_VOLT_SENS,
		    volts_r.num_volts);
		for (index = 0; index < volts_r.num_volts; index++) {
			section->entry[index].handle =
			    volts_r.volt_status[index].handle;
		}
		add_section(&my_chain, section);
	}
	if (retval == 0) {
		temp_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_TEMPERATURES,
		    DP_GET_TEMPERATURES_R, RMCRESBUFLEN,
		    (intptr_t)&temp_cmd, (intptr_t)&temp_r);
	}
	if (retval == 0) {
		section = create_cache_section(RMCLOMV_TEMP_SENS,
		    temp_r.num_temps);
		for (index = 0; index < temp_r.num_temps; index++) {
			section->entry[index].handle =
			    temp_r.temp_status[index].handle;
		}
		add_section(&my_chain, section);
	}
	if (retval == 0) {
		fan_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_FAN_STATUS, DP_GET_FAN_STATUS_R,
		    RMCRESBUFLEN, (intptr_t)&fan_cmd, (intptr_t)&fan_r);
	}
	if (retval == 0) {
		section = create_cache_section(RMCLOMV_FAN_SENS,
		    fan_r.num_fans);
		for (index = 0; index < fan_r.num_fans; index++) {
			section->entry[index].handle =
			    fan_r.fan_status[index].handle;
		}
		add_section(&my_chain, section);
	}
	if (retval == 0) {
		ampi_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_CIRCUIT_BRKS,
		    DP_GET_CIRCUIT_BRKS_R, RMCRESBUFLEN,
		    (intptr_t)&ampi_cmd, (intptr_t)&ampi_r);
	}
	if (retval == 0) {
		section = create_cache_section(RMCLOMV_AMP_IND,
		    ampi_r.num_circuit_brks);
		for (index = 0; index < ampi_r.num_circuit_brks; index++) {
			section->entry[index].handle =
			    ampi_r.circuit_brk_status[index].handle;
		}
		add_section(&my_chain, section);
	}
	if (retval == 0) {
		led_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_LED_STATE, DP_GET_LED_STATE_R,
		    RMCRESBUFLEN, (intptr_t)&led_cmd, (intptr_t)&led_r);
	}
	if (retval == 0) {
		section = create_cache_section(RMCLOMV_LED_IND,
		    led_r.num_leds);
		for (index = 0; index < led_r.num_leds; index++) {
			section->entry[index].handle =
			    led_r.led_state[index].handle;
		}
		add_section(&my_chain, section);
	}
	/*
	 * The command DP_GET_ALARM_STATE may not be valid on
	 * some RMC versions, so we ignore the return value
	 * and proceed
	 */
	if (retval == 0) {
		alarm_cmd.handle = DP_NULL_HANDLE;
		retval1 = rmclomv_do_cmd(DP_GET_ALARM_STATE,
		    DP_GET_ALARM_STATE_R, RMCRESBUFLEN,
		    (intptr_t)&alarm_cmd, (intptr_t)&alarm_r);
		if ((retval1 == 0) && alarm_r.num_alarms) {
			section = create_cache_section(RMCLOMV_ALARM_IND,
			    alarm_r.num_alarms);
			for (index = 0; index < alarm_r.num_alarms; index++) {
				section->entry[index].handle =
				    alarm_r.alarm_state[index].handle;
			}
			add_section(&my_chain, section);
		}
	}
	if (retval == 0) {
		psu_cmd.handle = DP_NULL_HANDLE;
		retval = rmclomv_do_cmd(DP_GET_PSU_STATUS, DP_GET_PSU_STATUS_R,
		    RMCRESBUFLEN, (intptr_t)&psu_cmd, (intptr_t)&psu_r);
	}
	if (retval == 0) {
		/*
		 * WARNING:
		 * =======
		 * The PSUs must be probed last so that the response data
		 * (psu_r) is available for make_psu_subsections() below.
		 * Note that all the responses share the same data area
		 * which is declared as a union.
		 */
		psu_section = create_cache_section(RMCLOMV_PSU_IND,
		    psu_r.num_psus);
		for (index = 0; index < psu_r.num_psus; index++) {
			psu_section->entry[index].handle =
			    psu_r.psu_status[index].handle;
		}
		add_section(&my_chain, psu_section);
	}
	if (retval == 0) {
		for (section = my_chain;
		    section != NULL;
		    section = section->next_section) {
			retval = add_names_to_section(section);
			if (retval != 0) {
				break;
			}
		}
	}

	/*
	 * now add nodes derived from PSUs
	 */
	if (retval == 0) {
		make_psu_subsections(psu_section, &derived_chain, &psu_r);
		/*
		 * name cache sections all set, exchange new for old
		 */
		rmclomv_reset_cache(my_chain, derived_chain, &sysinfo);
	} else {
		/*
		 * RMC is not responding, ditch any existing cache
		 * and just leave the special SC FRU node
		 */
		rmclomv_reset_cache(my_chain, NULL, NULL);
	}
}

static void
set_val_unav(envmon_sensor_t *sensor)
{
	sensor->value = ENVMON_VAL_UNAVAILABLE;
	sensor->lowthresholds.warning = ENVMON_VAL_UNAVAILABLE;
	sensor->lowthresholds.shutdown = ENVMON_VAL_UNAVAILABLE;
	sensor->lowthresholds.poweroff = ENVMON_VAL_UNAVAILABLE;
	sensor->highthresholds.warning = ENVMON_VAL_UNAVAILABLE;
	sensor->highthresholds.shutdown = ENVMON_VAL_UNAVAILABLE;
	sensor->highthresholds.poweroff = ENVMON_VAL_UNAVAILABLE;
}

static void
set_fan_unav(envmon_fan_t *fan)
{
	fan->speed = ENVMON_VAL_UNAVAILABLE;
	fan->units[0] = '\0';
	fan->lowthresholds.warning = ENVMON_VAL_UNAVAILABLE;
	fan->lowthresholds.shutdown = ENVMON_VAL_UNAVAILABLE;
	fan->lowthresholds.poweroff = ENVMON_VAL_UNAVAILABLE;
}

static int
do_psu_cmd(intptr_t arg, int mode, envmon_indicator_t *env_ind,
    dp_get_psu_status_t *rmc_psu, dp_get_psu_status_r_t *rmc_psu_r,
    int detector_type)
{
	int			index;
	uint16_t		sensor_status;
	rmclomv_cache_section_t	*section;
	uint16_t		indicator_mask;

	if (ddi_copyin((caddr_t)arg, (caddr_t)env_ind,
	    sizeof (envmon_indicator_t), mode) != 0)
		return (EFAULT);

	/* ensure we've got PSU handles cached */
	LOCK_CACHE

	sensor_status = ENVMON_SENSOR_OK;
	section = rmclomv_find_section(rmclomv_subcache, detector_type);
	if (env_ind->id.name[0] == '\0') {
		/* request for first handle */
		if ((section == NULL) || (section->num_entries == 0))
			env_ind->next_id.name[0] = '\0';
		else
			env_ind->next_id = section->entry[0].handle_name;
		sensor_status = ENVMON_NOT_PRESENT;
	} else {
		/* ensure name is properly terminated */
		env_ind->id.name[ENVMON_MAXNAMELEN - 1] = '\0';
		if ((section == NULL) || (get_sensor_by_name(section,
		    env_ind->id.name, &index)) != 0) {
			env_ind->next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (index + 1 < section->num_entries)
			env_ind->next_id =
			    section->entry[index + 1].handle_name;
		else
			env_ind->next_id.name[0] = '\0';
	}
	if (sensor_status == ENVMON_SENSOR_OK) {
		/*
		 * user correctly identified a sensor, note its
		 * handle value and request the indicator status
		 */
		rmc_psu->handle = section->entry[index].handle;
		indicator_mask = section->entry[index].ind_mask;
	}

	RELEASE_CACHE

	if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
	    rmclomv_do_cmd(DP_GET_PSU_STATUS, DP_GET_PSU_STATUS_R,
	    sizeof (dp_get_psu_status_r_t), (intptr_t)rmc_psu,
	    (intptr_t)rmc_psu_r) != 0)) {
		sensor_status = ENVMON_INACCESSIBLE;
	}
	if ((env_ind->sensor_status = sensor_status) == ENVMON_SENSOR_OK) {
		/*
		 * copy results into buffer for user
		 */
		if ((rmc_psu_r->psu_status[0].flag & DP_PSU_PRESENCE) == 0)
			env_ind->sensor_status |= ENVMON_NOT_PRESENT;
		if (rmc_psu_r->psu_status[0].sensor_status !=
		    DP_SENSOR_DATA_AVAILABLE)
			env_ind->sensor_status |= ENVMON_INACCESSIBLE;
		env_ind->condition =
		    (rmc_psu_r->psu_status[0].flag & indicator_mask) == 0 ?
		    0 : 1;
	}

	if (rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE)
		env_ind->sensor_status = ENVMON_INACCESSIBLE;

	if (ddi_copyout((caddr_t)env_ind, (caddr_t)arg,
	    sizeof (envmon_indicator_t), mode) != 0)
		return (EFAULT);

	return (0);
}

/*ARGSUSED*/
static int
rmclomv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	int instance = getminor(dev);
	envmon_sysinfo_t lomv_sysinfo;
	union {
		envmon_sensor_t		u_env_sensor;
		envmon_indicator_t	u_env_ind;
		envmon_fan_t		u_env_fan;
		envmon_led_info_t	u_env_ledinfo;
		envmon_led_ctl_t	u_env_ledctl;
		envmon_hpu_t		u_env_hpu;
		envmon_alarm_info_t	u_env_alarminfo;
		envmon_alarm_ctl_t	u_env_alarmctl;
	} env_buf;
#define	env_sensor	env_buf.u_env_sensor
#define	env_ind		env_buf.u_env_ind
#define	env_fan		env_buf.u_env_fan
#define	env_ledinfo	env_buf.u_env_ledinfo
#define	env_ledctl	env_buf.u_env_ledctl
#define	env_hpu		env_buf.u_env_hpu
#define	env_alarminfo	env_buf.u_env_alarminfo
#define	env_alarmctl	env_buf.u_env_alarmctl

	union {
		dp_get_volts_t		u_rmc_volts;
		dp_get_temperatures_t	u_rmc_temp;
		dp_get_circuit_brks_t	u_rmc_ampi;
		dp_get_fan_status_t	u_rmc_fan;
		dp_get_psu_status_t	u_rmc_psu;
		dp_get_fru_status_t	u_rmc_fru;
		dp_get_led_state_t	u_rmc_led;
		dp_set_led_state_t	u_rmc_setled;
		dp_get_alarm_state_t	u_rmc_alarm;
		dp_set_alarm_state_t	u_rmc_setalarm;
	} rmc_reqbuf;
#define	rmc_volts	rmc_reqbuf.u_rmc_volts
#define	rmc_temp	rmc_reqbuf.u_rmc_temp
#define	rmc_ampi	rmc_reqbuf.u_rmc_ampi
#define	rmc_fan		rmc_reqbuf.u_rmc_fan
#define	rmc_psu		rmc_reqbuf.u_rmc_psu
#define	rmc_fru		rmc_reqbuf.u_rmc_fru
#define	rmc_led		rmc_reqbuf.u_rmc_led
#define	rmc_setled	rmc_reqbuf.u_rmc_setled
#define	rmc_alarm	rmc_reqbuf.u_rmc_alarm
#define	rmc_setalarm	rmc_reqbuf.u_rmc_setalarm

	union {
		dp_get_volts_r_t	u_rmc_volts_r;
		dp_get_temperatures_r_t	u_rmc_temp_r;
		dp_get_circuit_brks_r_t	u_rmc_ampi_r;
		dp_get_fan_status_r_t	u_rmc_fan_r;
		dp_get_psu_status_r_t	u_rmc_psu_r;
		dp_get_fru_status_r_t	u_rmc_fru_r;
		dp_get_led_state_r_t	u_rmc_led_r;
		dp_set_led_state_r_t	u_rmc_setled_r;
		dp_get_alarm_state_r_t	u_rmc_alarm_r;
		dp_set_alarm_state_r_t	u_rmc_setalarm_r;
		dp_get_sdp_version_r_t	u_rmc_sdpversion_r;
		dp_get_serialnum_r_t	u_rmc_serialnum_r;
	} rmc_resbuf;
#define	rmc_volts_r	rmc_resbuf.u_rmc_volts_r
#define	rmc_temp_r	rmc_resbuf.u_rmc_temp_r
#define	rmc_ampi_r	rmc_resbuf.u_rmc_ampi_r
#define	rmc_fan_r	rmc_resbuf.u_rmc_fan_r
#define	rmc_psu_r	rmc_resbuf.u_rmc_psu_r
#define	rmc_fru_r	rmc_resbuf.u_rmc_fru_r
#define	rmc_led_r	rmc_resbuf.u_rmc_led_r
#define	rmc_setled_r	rmc_resbuf.u_rmc_setled_r
#define	rmc_alarm_r	rmc_resbuf.u_rmc_alarm_r
#define	rmc_setalarm_r	rmc_resbuf.u_rmc_setalarm_r
#define	rmc_sdpver_r	rmc_resbuf.u_rmc_sdpversion_r
#define	rmc_serialnum_r	rmc_resbuf.u_rmc_serialnum_r

	int			retval = 0;
	int			special = 0;
	int			index;
	uint16_t		sensor_status;
	rmclomv_cache_section_t	*section;
	envmon_chassis_t chassis;

	if (instance != 0)
		return (ENXIO);

	switch (cmd) {
	case ENVMONIOCSYSINFO:

		LOCK_CACHE

		/*
		 * A number of OK/not_OK indicators are supported by PSUs
		 * (voltage, current, fan, temperature). So the maximum
		 * number of such indicators relates to the maximum number
		 * of power-supplies.
		 */
		if (rmclomv_sysinfo_valid) {
			lomv_sysinfo.maxVoltSens = rmclomv_sysinfo_data.maxVolt;
			lomv_sysinfo.maxVoltInd =
			    RMCLOMV_MAX_VI_PER_PSU *
			    rmclomv_sysinfo_data.maxPSU;
			/*
			 * the ALOM-Solaris interface does not include
			 * amp sensors, so we can hard code this value
			 */
			lomv_sysinfo.maxAmpSens = 0;
			lomv_sysinfo.maxAmpInd =
			    rmclomv_sysinfo_data.maxCircuitBrks +
			    (RMCLOMV_MAX_CI_PER_PSU *
			    rmclomv_sysinfo_data.maxPSU);
			lomv_sysinfo.maxTempSens = rmclomv_sysinfo_data.maxTemp;
			lomv_sysinfo.maxTempInd =
			    (RMCLOMV_MAX_TI_PER_PSU *
			    rmclomv_sysinfo_data.maxPSU);
			lomv_sysinfo.maxFanSens = rmclomv_sysinfo_data.maxFan;
			lomv_sysinfo.maxFanInd =
			    RMCLOMV_MAX_FI_PER_PSU *
			    rmclomv_sysinfo_data.maxPSU;
			lomv_sysinfo.maxLED = rmclomv_sysinfo_data.maxLED;
			lomv_sysinfo.maxHPU = RMCLOMV_NUM_SPECIAL_FRUS +
			    rmclomv_sysinfo_data.maxFRU;
		} else {
			bzero(&lomv_sysinfo, sizeof (lomv_sysinfo));
			lomv_sysinfo.maxHPU = 1;	/* just the SC node */
		}

		RELEASE_CACHE

		if (ddi_copyout((caddr_t)&lomv_sysinfo, (caddr_t)arg,
		    sizeof (lomv_sysinfo), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCVOLTSENSOR:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_sensor,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);

		/* see if we've got volts handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_VOLT_SENS)) == NULL)) {
			env_sensor.next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (env_sensor.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_sensor.next_id.name[0] = '\0';
			else
				env_sensor.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_sensor.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_sensor.id.name,
			    &index) != 0) {
				env_sensor.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_sensor.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_sensor.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified a sensor, note its
			 * handle value and request the sensor value
			 */
			rmc_volts.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_VOLTS, DP_GET_VOLTS_R,
		    sizeof (rmc_volts_r), (intptr_t)&rmc_volts,
		    (intptr_t)&rmc_volts_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmc_volts_r.volt_status[0].sensor_status ==
		    DP_SENSOR_NOT_PRESENT)) {
			sensor_status = ENVMON_NOT_PRESENT;
		}
		if ((env_sensor.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			/*
			 * copy results into buffer for user
			 */
			if (rmc_volts_r.volt_status[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_sensor.sensor_status = ENVMON_INACCESSIBLE;
			env_sensor.value =
			    rmc_volts_r.volt_status[0].reading;
			env_sensor.lowthresholds.warning =
			    rmc_volts_r.volt_status[0].low_warning;
			env_sensor.lowthresholds.shutdown =
			    rmc_volts_r.volt_status[0].low_soft_shutdown;
			env_sensor.lowthresholds.poweroff =
			    rmc_volts_r.volt_status[0].low_hard_shutdown;
			env_sensor.highthresholds.warning =
			    rmc_volts_r.volt_status[0].high_warning;
			env_sensor.highthresholds.shutdown =
			    rmc_volts_r.volt_status[0].high_soft_shutdown;
			env_sensor.highthresholds.poweroff =
			    rmc_volts_r.volt_status[0].high_hard_shutdown;
		}
		if (env_sensor.sensor_status != ENVMON_SENSOR_OK ||
		    rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE)
			set_val_unav(&env_sensor);

		if (ddi_copyout((caddr_t)&env_sensor, (caddr_t)arg,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCVOLTIND:
		return (do_psu_cmd(arg, mode, &env_ind, &rmc_psu, &rmc_psu_r,
		    RMCLOMV_VOLT_IND));

	case ENVMONIOCTEMPIND:
		return (do_psu_cmd(arg, mode, &env_ind, &rmc_psu, &rmc_psu_r,
		    RMCLOMV_TEMP_IND));

	case ENVMONIOCFANIND:
		return (do_psu_cmd(arg, mode, &env_ind, &rmc_psu, &rmc_psu_r,
		    RMCLOMV_FAN_IND));

	case ENVMONIOCAMPSENSOR:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_sensor,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);

		env_sensor.sensor_status = ENVMON_NOT_PRESENT;
		env_sensor.next_id.name[0] = '\0';

		if (ddi_copyout((caddr_t)&env_sensor, (caddr_t)arg,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCTEMPSENSOR:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_sensor,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);

		/* see if we've got temperature handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_TEMP_SENS)) == NULL)) {
			env_sensor.next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (env_sensor.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_sensor.next_id.name[0] = '\0';
			else
				env_sensor.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_sensor.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_sensor.id.name,
			    &index) != 0) {
				env_sensor.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_sensor.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_sensor.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified a sensor, note its
			 * handle value and request the sensor value
			 */
			rmc_temp.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_TEMPERATURES, DP_GET_TEMPERATURES_R,
		    sizeof (rmc_temp_r), (intptr_t)&rmc_temp,
		    (intptr_t)&rmc_temp_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmc_temp_r.temp_status[0].sensor_status ==
		    DP_SENSOR_NOT_PRESENT)) {
			sensor_status = ENVMON_NOT_PRESENT;
		}
		if ((env_sensor.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			/*
			 * copy results into buffer for user
			 */
			if (rmc_temp_r.temp_status[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_sensor.sensor_status = ENVMON_INACCESSIBLE;
			env_sensor.value =
			    rmc_temp_r.temp_status[0].value;
			env_sensor.lowthresholds.warning =
			    rmc_temp_r.temp_status[0].low_warning;
			env_sensor.lowthresholds.shutdown =
			    rmc_temp_r.temp_status[0].low_soft_shutdown;
			env_sensor.lowthresholds.poweroff =
			    rmc_temp_r.temp_status[0].low_hard_shutdown;
			env_sensor.highthresholds.warning =
			    rmc_temp_r.temp_status[0].high_warning;
			env_sensor.highthresholds.shutdown =
			    rmc_temp_r.temp_status[0].high_soft_shutdown;
			env_sensor.highthresholds.poweroff =
			    rmc_temp_r.temp_status[0].high_hard_shutdown;
		}
		if (env_sensor.sensor_status != ENVMON_SENSOR_OK ||
		    rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE)
			set_val_unav(&env_sensor);

		if (ddi_copyout((caddr_t)&env_sensor, (caddr_t)arg,
		    sizeof (envmon_sensor_t), mode) != 0)
			return (EFAULT);
		break;


	case ENVMONIOCFAN:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_fan,
		    sizeof (envmon_fan_t), mode) != 0)
			return (EFAULT);

		/* see if we've got fan handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_FAN_SENS)) == NULL)) {
			env_fan.next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (env_fan.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_fan.next_id.name[0] = '\0';
			else
				env_fan.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_fan.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_fan.id.name,
			    &index) != 0) {
				env_fan.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_fan.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_fan.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified a sensor, note its
			 * handle value and request the sensor value
			 */
			rmc_fan.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_FAN_STATUS, DP_GET_FAN_STATUS_R,
		    sizeof (rmc_fan_r), (intptr_t)&rmc_fan,
		    (intptr_t)&rmc_fan_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmc_fan_r.fan_status[0].sensor_status ==
		    DP_SENSOR_NOT_PRESENT)) {
			sensor_status = ENVMON_NOT_PRESENT;
		}
		if ((env_fan.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			if ((rmc_fan_r.fan_status[0].flag &
			    DP_FAN_PRESENCE) == 0)
				env_fan.sensor_status = ENVMON_NOT_PRESENT;
			if (rmc_fan_r.fan_status[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_fan.sensor_status |= ENVMON_INACCESSIBLE;
			if (env_fan.sensor_status == ENVMON_SENSOR_OK) {
				/*
				 * copy results into buffer for user
				 */
				env_fan.speed =
				    rmc_fan_r.fan_status[0].speed;
				env_fan.lowthresholds.warning =
				    rmc_fan_r.fan_status[0].minspeed;
				env_fan.lowthresholds.shutdown =
				    ENVMON_VAL_UNAVAILABLE;
				env_fan.lowthresholds.poweroff =
				    ENVMON_VAL_UNAVAILABLE;
				if ((rmc_fan_r.fan_status[0].flag &
				    DP_FAN_SPEED_VAL_UNIT) == 0)
					bcopy(str_rpm, env_fan.units,
					    sizeof (str_rpm));
				else
					bcopy(str_percent, env_fan.units,
					    sizeof (str_percent));
			}
		}
		if (env_fan.sensor_status != ENVMON_SENSOR_OK ||
		    rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE)
			set_fan_unav(&env_fan);

		if (ddi_copyout((caddr_t)&env_fan, (caddr_t)arg,
		    sizeof (envmon_fan_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCAMPIND:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_ind,
		    sizeof (envmon_indicator_t), mode) != 0)
			return (EFAULT);

		/* see if we've got amp indicator handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_AMP_IND)) == NULL)) {
			RELEASE_CACHE
			return (do_psu_cmd(arg, mode, &env_ind, &rmc_psu,
			    &rmc_psu_r, RMCLOMV_AMP_IND));
		} else if (env_ind.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0) {
				RELEASE_CACHE
				return (do_psu_cmd(arg, mode, &env_ind,
				    &rmc_psu, &rmc_psu_r, RMCLOMV_AMP_IND));
			}
			env_ind.next_id = section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_ind.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_ind.id.name,
			    &index) != 0) {
				RELEASE_CACHE
				return (do_psu_cmd(arg, mode, &env_ind,
				    &rmc_psu, &rmc_psu_r, RMCLOMV_AMP_IND));
			}
			if (index + 1 < section->num_entries) {
				env_ind.next_id =
				    section->entry[index + 1].handle_name;
			} else {
				rmclomv_cache_section_t	*sub_section =
				    rmclomv_find_section(rmclomv_subcache,
				    RMCLOMV_AMP_IND);
				if ((sub_section == NULL) ||
				    (sub_section->num_entries == 0))
					env_ind.next_id.name[0] = '\0';
				else
					env_ind.next_id =
					    sub_section->entry[0].handle_name;
			}
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified an indicator, note its
			 * handle value and request the indicator status
			 */
			rmc_ampi.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_CIRCUIT_BRKS, DP_GET_CIRCUIT_BRKS_R,
		    sizeof (rmc_ampi_r), (intptr_t)&rmc_ampi,
		    (intptr_t)&rmc_ampi_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmc_ampi_r.circuit_brk_status[0].sensor_status ==
		    DP_SENSOR_NOT_PRESENT)) {
			sensor_status = ENVMON_NOT_PRESENT;
		}
		if ((env_ind.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			/*
			 * copy results into buffer for user
			 */
			if (rmc_ampi_r.circuit_brk_status[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_ind.sensor_status = ENVMON_INACCESSIBLE;
			env_ind.condition =
			    rmc_ampi_r.circuit_brk_status[0].status;
		}

		/*
		 * If rmclomv_rmc_error is set there is no way
		 * that we read information from RSC. Just copy
		 * out an inaccessible evironmental.
		 */
		if (rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE) {
			env_ind.sensor_status = ENVMON_INACCESSIBLE;
			env_ind.condition = ENVMON_INACCESSIBLE;
		}

		if (ddi_copyout((caddr_t)&env_ind, (caddr_t)arg,
		    sizeof (envmon_indicator_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCHPU:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_hpu,
		    sizeof (envmon_hpu_t), mode) != 0)
			return (EFAULT);

		/* see if we've got hpu handles cached */
		LOCK_CACHE

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_HPU_IND)) == NULL)) {
			RELEASE_CACHE
			return (EAGAIN);
		}

		/*
		 * At this point the cache is locked and section points to
		 * the section relating to hpus.
		 */
		sensor_status = ENVMON_SENSOR_OK;
		if (env_hpu.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_hpu.next_id.name[0] = '\0';
			else
				env_hpu.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_hpu.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_hpu.id.name,
			    &index) != 0) {
				env_hpu.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_hpu.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_hpu.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified an hpu, note its
			 * handle value and request the hpu status
			 */
			rmc_fru.handle = section->entry[index].handle;
			special = section->entry[index].ind_mask;
		}
		RELEASE_CACHE
		if ((env_hpu.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			env_hpu.fru_status = ENVMON_FRU_PRESENT;

			if (special != 0) {
				/* this is the pseudo SC node */
				mutex_enter(&rmclomv_state_lock);
				switch (rmclomv_rmc_state) {
				case RMCLOMV_RMCSTATE_OK:
					break;
				case RMCLOMV_RMCSTATE_FAILED:
					env_hpu.fru_status = ENVMON_FRU_FAULT;
					break;
				case RMCLOMV_RMCSTATE_DOWNLOAD:
					env_hpu.fru_status =
					    ENVMON_FRU_DOWNLOAD;
					break;
				default:
					env_hpu.sensor_status =
					    ENVMON_INACCESSIBLE;
					break;
				}
				mutex_exit(&rmclomv_state_lock);
			} else if (rmclomv_rmc_error ||
			    rmclomv_do_cmd(DP_GET_FRU_STATUS,
			    DP_GET_FRU_STATUS_R, sizeof (rmc_fru_r),
			    (intptr_t)&rmc_fru, (intptr_t)&rmc_fru_r) != 0) {
				env_hpu.sensor_status = ENVMON_INACCESSIBLE;
			} else {
				/*
				 * copy results into buffer for user
				 */
				if (rmc_fru_r.fru_status[0].presence == 0) {
					env_hpu.sensor_status =
					    ENVMON_NOT_PRESENT;
					env_hpu.fru_status =
					    ENVMON_FRU_NOT_PRESENT;
				} else if (rmc_fru_r.fru_status[0].sensor_status
				    != DP_SENSOR_DATA_AVAILABLE) {
					env_hpu.sensor_status =
					    ENVMON_INACCESSIBLE;
				} else {
					uint8_t status =
					    rmc_fru_r.fru_status[0].status;
					if (status == DP_FRU_STATUS_UNKNOWN) {
						env_hpu.sensor_status =
						    ENVMON_INACCESSIBLE;
					} else if (status != DP_FRU_STATUS_OK) {
						env_hpu.fru_status =
						    ENVMON_FRU_FAULT;
					}
				}
			}
		}

		/*
		 * If rmclomv_rmc_error is set there is no way
		 * that we read information from RSC. Just copy
		 * out an inaccessible environmental.
		 */
		if (rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE) {
			env_hpu.sensor_status = ENVMON_INACCESSIBLE;
			env_hpu.fru_status = ENVMON_INACCESSIBLE;
		}

		if (ddi_copyout((caddr_t)&env_hpu, (caddr_t)arg,
		    sizeof (envmon_hpu_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCGETLED:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_ledinfo,
		    sizeof (envmon_led_info_t), mode) != 0)
			return (EFAULT);

		/* see if we've got LED handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_LED_IND)) == NULL)) {
			env_ledinfo.next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (env_ledinfo.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_ledinfo.next_id.name[0] = '\0';
			else
				env_ledinfo.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_ledinfo.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_ledinfo.id.name,
			    &index) != 0) {
				env_ledinfo.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_ledinfo.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_ledinfo.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified a LED, note its
			 * handle value and request the LED status
			 */
			rmc_led.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_LED_STATE, DP_GET_LED_STATE_R,
		    sizeof (rmc_led_r), (intptr_t)&rmc_led,
		    (intptr_t)&rmc_led_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmc_led_r.led_state[0].sensor_status ==
		    DP_SENSOR_NOT_PRESENT)) {
			sensor_status = ENVMON_NOT_PRESENT;
		}
		if ((env_ledinfo.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			/*
			 * copy results into buffer for user
			 * start with some defaults then override
			 */
			env_ledinfo.sensor_status = ENVMON_SENSOR_OK;
			env_ledinfo.led_state = ENVMON_LED_OFF;
			env_ledinfo.led_color = ENVMON_LED_CLR_NONE;

			if (rmc_led_r.led_state[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_ledinfo.sensor_status = ENVMON_INACCESSIBLE;
			else {
				dp_led_state_t ledState;
				ledState = rmc_led_r.led_state[0];
				env_ledinfo.led_color = (int8_t)ledState.colour;

				switch (ledState.state) {
				case (rsci8)DP_LED_OFF:
					break;
				case (rsci8)DP_LED_ON:
					env_ledinfo.led_state = ENVMON_LED_ON;
					break;
				case (rsci8)DP_LED_BLINKING:
					env_ledinfo.led_state =
					    ENVMON_LED_BLINKING;
					break;
				case (rsci8)DP_LED_FLASHING:
					env_ledinfo.led_state =
					    ENVMON_LED_FLASHING;
					break;
				default:
					break;
				}
			}
		}

		/*
		 * If rmclomv_rmc_error is set there is no way
		 * that we read information from RSC. Just copy
		 * out an inaccessible environmental.
		 */
		if (rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE) {
			env_ledinfo.sensor_status = ENVMON_INACCESSIBLE;
			env_ledinfo.led_state = ENVMON_INACCESSIBLE;
		}

		if (ddi_copyout((caddr_t)&env_ledinfo, (caddr_t)arg,
		    sizeof (envmon_led_info_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCSETLED:
		if ((mode & FWRITE) == 0)
			return (EACCES);
		if (drv_priv(cred_p) != 0)
			return (EPERM);
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_ledctl,
		    sizeof (envmon_led_ctl_t), mode) != 0)
			return (EFAULT);
		if (env_ledctl.led_state < RMCLOMV_MIN_LED_STATE ||
		    env_ledctl.led_state > RMCLOMV_MAX_LED_STATE)
			return (EINVAL);
		/*
		 * Ensure name is properly terminated.
		 */
		env_ledctl.id.name[ENVMON_MAXNAMELEN - 1] = '\0';

		/* see if we've got LED handles cached */
		LOCK_CACHE

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_LED_IND)) == NULL) ||
		    (get_sensor_by_name(section, env_ledctl.id.name,
		    &index) != 0)) {
			RELEASE_CACHE
			return (EINVAL);	/* no such LED */
		}
		/*
		 * user correctly identified a LED, note its handle value
		 */
		rmc_setled.handle = section->entry[index].handle;
		RELEASE_CACHE
		switch (env_ledctl.led_state) {
		case ENVMON_LED_ON:
			rmc_setled.state = DP_LED_ON;
			break;
		case ENVMON_LED_BLINKING:
			rmc_setled.state = DP_LED_BLINKING;
			break;
		case ENVMON_LED_FLASHING:
			rmc_setled.state = DP_LED_FLASHING;
			break;
		default:
			rmc_setled.state = DP_LED_OFF;
			break;
		}
		retval = rmclomv_do_cmd(DP_SET_LED_STATE, DP_SET_LED_STATE_R,
		    sizeof (rmc_setled_r), (intptr_t)&rmc_setled,
		    (intptr_t)&rmc_setled_r);

		if (retval != 0) {
			break;
		}

		if (rmc_setled_r.status != 0) {
			cmn_err(CE_WARN, "ENVMONIOCSETLED: \"%s\" status: 0x%x",
			    env_ledctl.id.name, rmc_setled_r.status);
			return (EIO);
		}
		break;

	case ENVMONIOCGETKEYSW:
	{
		enum rmc_keyswitch_pos	rmc_pos = real_key_position;
		envmon_keysw_pos_t	envmon_pos;

		/*
		 * Yes, I know this is ugly, but the V210 has no keyswitch,
		 * even though the ALOM returns a value for it
		 */
		if (strcmp(platform, "SUNW,Sun-Fire-V210") == 0) {
			return (ENOTSUP);
		}

		switch (rmc_pos) {

		case RMC_KEYSWITCH_POS_NORMAL:
			envmon_pos = ENVMON_KEYSW_POS_NORMAL;
			break;
		case RMC_KEYSWITCH_POS_DIAG:
			envmon_pos = ENVMON_KEYSW_POS_DIAG;
			break;
		case RMC_KEYSWITCH_POS_LOCKED:
			envmon_pos = ENVMON_KEYSW_POS_LOCKED;
			break;
		case RMC_KEYSWITCH_POS_OFF:
			envmon_pos = ENVMON_KEYSW_POS_OFF;
			break;
		default:
			envmon_pos = ENVMON_KEYSW_POS_UNKNOWN;
			break;
		}

		if (ddi_copyout((caddr_t)&envmon_pos, (caddr_t)arg,
		    sizeof (envmon_pos), mode) != 0)
			return (EFAULT);
		break;
	}

	case ENVMONIOCGETALARM:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_alarminfo,
		    sizeof (envmon_alarm_info_t), mode) != 0)
			return (EFAULT);

		/* see if we've got ALARM handles cached */
		LOCK_CACHE
		sensor_status = ENVMON_SENSOR_OK;

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_ALARM_IND)) == NULL)) {
			env_alarminfo.next_id.name[0] = '\0';
			sensor_status = ENVMON_NOT_PRESENT;
		} else if (env_alarminfo.id.name[0] == '\0') {
			/* request for first handle */
			if (section->num_entries == 0)
				env_alarminfo.next_id.name[0] = '\0';
			else
				env_alarminfo.next_id =
				    section->entry[0].handle_name;
			sensor_status = ENVMON_NOT_PRESENT;
		} else {
			/* ensure name is properly terminated */
			env_alarminfo.id.name[ENVMON_MAXNAMELEN - 1] = '\0';
			if (get_sensor_by_name(section, env_alarminfo.id.name,
			    &index) != 0) {
				env_alarminfo.next_id.name[0] = '\0';
				sensor_status = ENVMON_NOT_PRESENT;
			} else if (index + 1 < section->num_entries)
				env_alarminfo.next_id =
				    section->entry[index + 1].handle_name;
			else
				env_alarminfo.next_id.name[0] = '\0';
		}
		if (sensor_status == ENVMON_SENSOR_OK) {
			/*
			 * user correctly identified a ALARM, note its
			 * handle value and request the ALARM status
			 */
			rmc_alarm.handle = section->entry[index].handle;
		}
		RELEASE_CACHE
		if ((sensor_status == ENVMON_SENSOR_OK) &&
		    (rmclomv_rmc_error ||
		    rmclomv_do_cmd(DP_GET_ALARM_STATE, DP_GET_ALARM_STATE_R,
		    sizeof (rmc_alarm_r), (intptr_t)&rmc_alarm,
		    (intptr_t)&rmc_alarm_r) != 0)) {
			sensor_status = ENVMON_INACCESSIBLE;
		}
		if ((env_alarminfo.sensor_status = sensor_status) ==
		    ENVMON_SENSOR_OK) {
			/*
			 * copy results into buffer for user
			 * start with some defaults then override
			 */
			env_alarminfo.sensor_status = ENVMON_SENSOR_OK;
			env_alarminfo.alarm_state = ENVMON_ALARM_OFF;

			if (rmc_alarm_r.alarm_state[0].sensor_status !=
			    DP_SENSOR_DATA_AVAILABLE)
				env_alarminfo.sensor_status =
				    ENVMON_INACCESSIBLE;
			else {
				dp_alarm_state_t alarmState;
				alarmState = rmc_alarm_r.alarm_state[0];

				switch (alarmState.state) {
				case DP_ALARM_OFF:
					break;
				case DP_ALARM_ON:
					env_alarminfo.alarm_state =
					    ENVMON_ALARM_ON;
					break;
				default:
					break;
				}
			}
		}

		/*
		 * If rmclomv_rmc_error is set there is no way
		 * that we read information from RSC. Just copy
		 * out an inaccessible environmental.
		 */
		if (rmclomv_rmc_error != RMCLOMV_RMCERROR_NONE) {
			env_alarminfo.sensor_status = ENVMON_INACCESSIBLE;
			env_alarminfo.alarm_state = ENVMON_INACCESSIBLE;
		}

		if (ddi_copyout((caddr_t)&env_alarminfo, (caddr_t)arg,
		    sizeof (envmon_alarm_info_t), mode) != 0)
			return (EFAULT);
		break;

	case ENVMONIOCSETALARM:
		if ((mode & FWRITE) == 0)
			return (EACCES);
		if (drv_priv(cred_p) != 0)
			return (EPERM);
		if (ddi_copyin((caddr_t)arg, (caddr_t)&env_alarmctl,
		    sizeof (envmon_alarm_ctl_t), mode) != 0)
			return (EFAULT);
		if (env_alarmctl.alarm_state < RMCLOMV_MIN_ALARM_STATE ||
		    env_alarmctl.alarm_state > RMCLOMV_MAX_ALARM_STATE)
			return (EINVAL);
		/*
		 * Ensure name is properly terminated.
		 */
		env_alarmctl.id.name[ENVMON_MAXNAMELEN - 1] = '\0';

		/* see if we've got ALARM handles cached */
		LOCK_CACHE

		if ((rmclomv_cache_valid == B_FALSE) ||
		    ((section = rmclomv_find_section(rmclomv_cache,
		    RMCLOMV_ALARM_IND)) == NULL) ||
		    (get_sensor_by_name(section, env_alarmctl.id.name,
		    &index) != 0)) {
			RELEASE_CACHE
			return (EINVAL);	/* no such ALARM */
		}
		/*
		 * user correctly identified a ALARM, note its handle value
		 */
		rmc_setalarm.handle = section->entry[index].handle;
		RELEASE_CACHE
		rmc_setalarm.state = (rsci8)env_alarmctl.alarm_state;
		retval = rmclomv_do_cmd(DP_SET_ALARM_STATE,
		    DP_SET_ALARM_STATE_R,
		    sizeof (rmc_setalarm_r),
		    (intptr_t)&rmc_setalarm,
		    (intptr_t)&rmc_setalarm_r);

		if (retval != 0) {
			break;
		}

		if (rmc_setalarm_r.status != 0) {
			cmn_err(CE_WARN, "ENVMONIOCSETALARM: \"%s\" status: "
			    "0x%x", env_alarmctl.id.name,
			    rmc_setalarm_r.status);
			return (EIO);
		}
		break;

	case ENVMONIOCCHASSISSERIALNUM:
		retval = rmclomv_do_cmd(DP_GET_SDP_VERSION,
		    DP_GET_SDP_VERSION_R, sizeof (rmc_sdpver_r),
		    NULL, (intptr_t)&rmc_sdpver_r);

		if (retval != 0) {
			cmn_err(CE_WARN, "DP_GET_SDP_VERSION failed, ret=%d\n",
			    retval);
			break;
		} else if (rmc_sdpver_r.version < SDP_RESPONDS_TO_ALL_CMDS) {
			retval = ENOTSUP;
			break;
		}
		retval = rmclomv_do_cmd(DP_GET_CHASSIS_SERIALNUM,
		    DP_GET_CHASSIS_SERIALNUM_R, sizeof (rmc_serialnum_r),
		    NULL, (intptr_t)&rmc_serialnum_r);

		if (retval != 0) {
			break;
		}
		bcopy(rmc_serialnum_r.chassis_serial_number,
		    chassis.serial_number,
		    sizeof (rmc_serialnum_r.chassis_serial_number));

		if (ddi_copyout((caddr_t)&chassis, (caddr_t)arg,
		    sizeof (chassis), mode) != 0) {
			return (EFAULT);
		}
		sensor_status = ENVMON_SENSOR_OK;
		break;

	default:
		retval = ENOTSUP;
		break;
	}

	return (retval);
}

/* ARGSUSED */
static void
rmclomv_checkrmc(caddr_t arg)
{
	callb_cpr_t		cprinfo;
	int			err;
	int			retries;
	int			state;
	dp_get_sysinfo_r_t 	sysinfo;

	CALLB_CPR_INIT(&cprinfo, &rmclomv_checkrmc_lock, callb_generic_cpr,
	    "rmclomv_checkrmc");

	mutex_enter(&rmclomv_checkrmc_lock);
	for (;;) {
		/*
		 * Initial entry to this for loop is made with
		 * rmclomv_checkrmc_sig set to RMCLOMV_PROCESS_NOW. So the
		 * following while loop drops through the first time. A
		 * timeout call is made just before polling the RMC. Its
		 * interrupt routine sustains this loop by injecting additional
		 * state changes and cv events.
		 */
		/*
		 * Wait for someone to tell me to continue.
		 */
		while (rmclomv_checkrmc_sig == RMCLOMV_CHECKRMC_WAIT) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&rmclomv_checkrmc_sig_cv,
			    &rmclomv_checkrmc_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &rmclomv_checkrmc_lock);
		}

		mutex_exit(&rmclomv_checkrmc_lock);
		/*
		 * mustn't hold same lock as timeout called with
		 * when cancelling timer
		 */
		if (timer_id != 0) {
			(void) untimeout(timer_id);
			timer_id = 0;
		}
		mutex_enter(&rmclomv_checkrmc_lock);

		/* RMCLOMV_CHECKRMC_EXITNOW implies signal by _detach(). */
		if (rmclomv_checkrmc_sig == RMCLOMV_CHECKRMC_EXITNOW) {
			rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_WAIT;

			/* rmclomv_checkrmc_lock is held at this point! */
			CALLB_CPR_EXIT(&cprinfo);

			thread_exit();
			/* NOTREACHED */
		}

		rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_WAIT;

		/*
		 * If the RMC is not responding, rmclomv_do_cmd() takes a
		 * long time and eventually times out. We conclude that the
		 * RMC is broken if it doesn't respond to a number of polls
		 * made 60 secs apart. So that the rmclomv_do_cmd() time-out
		 * period isn't added to our 60 second timer, make the
		 * timeout() call before calling rmclomv_do_cmd().
		 */
		if (timer_id == 0) {
			timer_id = timeout(rmclomv_checkrmc_wakeup, NULL,
			    60 * drv_usectohz(1000000));
		}

		mutex_exit(&rmclomv_checkrmc_lock);

		err = rmclomv_do_cmd(DP_GET_SYSINFO, DP_GET_SYSINFO_R,
		    sizeof (sysinfo), NULL, (intptr_t)&sysinfo);
		if (err == 0) {
			mutex_enter(&rmclomv_state_lock);
			state = rmclomv_rmc_state;
			/* successful poll, reset fail count */
			rmclomv_rmcfailcount = 0;
			mutex_exit(&rmclomv_state_lock);

			if (state != RMCLOMV_RMCSTATE_OK) {
				rmclomv_refresh_wakeup();
			}
		}
		if ((err != 0) &&
		    (rmclomv_rmc_error != RMCLOMV_RMCSTATE_DOWNLOAD)) {
			/*
			 * Failed response or no response from RMC.
			 * Count the failure.
			 * If threshold exceeded, send a DR event.
			 */
			mutex_enter(&rmclomv_state_lock);
			retries = rmclomv_rmcfailcount;
			state = rmclomv_rmc_state;
			if (retries == RMCLOMV_RMCFAILTHRESHOLD)
				rmclomv_rmc_state = RMCLOMV_RMCSTATE_FAILED;
			if (rmclomv_rmcfailcount <= RMCLOMV_RMCFAILTHRESHOLD)
				rmclomv_rmcfailcount++;
			mutex_exit(&rmclomv_state_lock);

			if (retries == RMCLOMV_RMCFAILTHRESHOLD) {
				cmn_err(CE_WARN, "SC %s responding",
				    state == RMCLOMV_RMCSTATE_OK ?
				    "has stopped" : "is not");
				refresh_name_cache(B_TRUE);
				rmclomv_dr_data_handler(str_sc, SE_NO_HINT);
			}
		}

		/*
		 * Re-enter the lock to prepare for another iteration.
		 * We must have the lock here to protect rmclomv_checkrmc_sig.
		 */
		mutex_enter(&rmclomv_checkrmc_lock);
	}
}

static void
rmclomv_checkrmc_start(void)
{
	kthread_t *tp;

	mutex_enter(&rmclomv_checkrmc_lock);

	if (rmclomv_checkrmc_tid == 0) {
		rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_PROCESSNOW;

		tp = thread_create(NULL, 0, rmclomv_checkrmc, NULL, 0,
		    &p0, TS_RUN, maxclsyspri);
		rmclomv_checkrmc_tid = tp->t_did;
	}

	mutex_exit(&rmclomv_checkrmc_lock);
}

static void
rmclomv_checkrmc_destroy(void)
{
	kt_did_t tid;

	mutex_enter(&rmclomv_checkrmc_lock);
	tid = rmclomv_checkrmc_tid;
	if (tid != 0) {
		rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_EXITNOW;
		cv_signal(&rmclomv_checkrmc_sig_cv);
		rmclomv_checkrmc_tid = 0;
	}
	mutex_exit(&rmclomv_checkrmc_lock);

	/*
	 * Wait for rmclomv_checkrmc() to finish
	 */
	if (tid != 0)
		thread_join(tid);
}

/*ARGSUSED*/
static void
rmclomv_checkrmc_wakeup(void *arg)
{
	mutex_enter(&rmclomv_checkrmc_lock);

	if (rmclomv_checkrmc_sig != RMCLOMV_CHECKRMC_EXITNOW)
		rmclomv_checkrmc_sig = RMCLOMV_CHECKRMC_PROCESSNOW;
	cv_signal(&rmclomv_checkrmc_sig_cv);

	mutex_exit(&rmclomv_checkrmc_lock);
}

/* ARGSUSED */
static void
rmclomv_refresh(caddr_t arg)
{
	void			(*plat_nodename_set_fun)(void);
	sig_state_t		*current_sgn_p;
	callb_cpr_t		cprinfo;
	int			state;
	int			tmp_checkrmc_sig;

	CALLB_CPR_INIT(&cprinfo, &rmclomv_refresh_lock, callb_generic_cpr,
	    "rmclomv_refresh");

	/*
	 * Wait until the rmclomv_checkrmc() thread has had a chance to
	 * run its main loop.  This is done so that rmclomv_refresh will
	 * only run its main loop once at start of day; otherwise, it may
	 * run twice and generate warning messages when redundantly populating
	 * its internal cache.
	 */
	do {
		delay(drv_usectohz(DELAY_TIME));
		mutex_enter(&rmclomv_checkrmc_lock);
		tmp_checkrmc_sig = rmclomv_checkrmc_sig;
		mutex_exit(&rmclomv_checkrmc_lock);
	} while (tmp_checkrmc_sig != RMCLOMV_CHECKRMC_WAIT);

	mutex_enter(&rmclomv_refresh_lock);
	for (;;) {

		/*
		 * Wait for someone to tell me to continue.
		 */
		while (rmclomv_refresh_sig == RMCLOMV_REFRESH_WAIT) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&rmclomv_refresh_sig_cv, &rmclomv_refresh_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &rmclomv_refresh_lock);
		}

		/* RMCLOMV_REFRESH_EXITNOW implies signal by _detach(). */
		if (rmclomv_refresh_sig == RMCLOMV_REFRESH_EXITNOW) {
			rmclomv_refresh_sig = RMCLOMV_REFRESH_WAIT;

			/* rmclomv_refresh_lock is held at this point! */
			CALLB_CPR_EXIT(&cprinfo);

			thread_exit();
			/* NOTREACHED */
		}

		ASSERT(rmclomv_refresh_sig == RMCLOMV_REFRESH_PROCESSNOW);
		rmclomv_refresh_sig = RMCLOMV_REFRESH_WAIT;

		mutex_exit(&rmclomv_refresh_lock);

		refresh_name_cache(B_FALSE);

		/*
		 * We're not going to access rmclomv_sysinfo_data here,
		 * so there's no point in locking it before reading
		 * rmclomv_sysinfo_valid. Also this avoids holding two
		 * locks at once and the concommitant worry about deadlocks.
		 */
		if (rmclomv_sysinfo_valid) {
			/*
			 * We've just successfully read the RMC sysinfo
			 * so the RMC must be operational. Update its
			 * state and if it was previously not OK, refresh
			 * nodename, CPU signatures and watchdog settings.
			 */
			mutex_enter(&rmclomv_state_lock);
			rmclomv_rmcfailcount = 0;
			state = rmclomv_rmc_state;
			rmclomv_rmc_state = RMCLOMV_RMCSTATE_OK;
			mutex_exit(&rmclomv_state_lock);

			if (state != RMCLOMV_RMCSTATE_OK) {
				rmclomv_dr_data_handler(str_sc, SE_NO_HINT);
				if (state == RMCLOMV_RMCSTATE_FAILED) {
					cmn_err(CE_NOTE, "SC recovered");
				}
			}

			if (utsname.nodename[0] != 0) {
				plat_nodename_set_fun =
				    (void (*)(void))modgetsymvalue(
				    "plat_nodename_set", 0);
				if (plat_nodename_set_fun != NULL)
					plat_nodename_set_fun();
			}

			current_sgn_p = (sig_state_t *)modgetsymvalue(
			    "current_sgn", 0);

			/*
			 * Delay before calling CPU_SIGNATURE, to allow
			 * any pending asynchronous communications (i.e.
			 * plat_timesync()) to complete.  This helps to
			 * prevent the situation where the message associated
			 * with the CPU_SIGNATURE state cannot be sent to the
			 * system controller.
			 */
			if ((current_sgn_p != NULL) &&
			    (current_sgn_p->state_t.sig != 0)) {
				delay(drv_usectohz(CPU_SIGNATURE_DELAY_TIME));
				CPU_SIGNATURE(current_sgn_p->state_t.sig,
				    current_sgn_p->state_t.state,
				    current_sgn_p->state_t.sub_state, -1);

				if (!(boothowto & RB_DEBUG)) {
					/*
					 * Delay before calling
					 * send_watchdog_msg, to allow
					 * CPU_SIGNATURE() time to
					 * complete; this increases the
					 * chances of successfully sending
					 * the watchdog message to the
					 * system controller.
					 */
					delay(drv_usectohz(
					    CPU_SIGNATURE_DELAY_TIME));
					send_watchdog_msg(last_watchdog_msg);
				}
			}
		}

		/*
		 * update keyswitch value in case it changed while the
		 * RMC was out of action
		 */
		LOCK_CACHE
		if (rmclomv_sysinfo_valid) {
			real_key_position = rmclomv_sysinfo_data.keyswitch;
			if ((real_key_position != RMC_KEYSWITCH_POS_UNKNOWN) &&
			    (real_key_position <= RMC_KEYSWITCH_POS_OFF)) {
				key_position = real_key_position;
			} else {
				/* treat unknown key position as locked */
				key_position = RMC_KEYSWITCH_POS_LOCKED;
			}
		} else {
			/* treat unreadable key position as locked */
			key_position = RMC_KEYSWITCH_POS_LOCKED;
			real_key_position = RMC_KEYSWITCH_POS_UNKNOWN;
		}
		RELEASE_CACHE

		/*
		 * Re-enter the lock to prepare for another iteration.
		 * We must have the lock here to protect rmclomv_refresh_sig.
		 */
		mutex_enter(&rmclomv_refresh_lock);
	}
}

static void
rmclomv_refresh_start(void)
{
	kthread_t *tp;

	mutex_enter(&rmclomv_refresh_lock);

	if (rmclomv_refresh_tid == 0) {
		rmclomv_refresh_sig = RMCLOMV_REFRESH_PROCESSNOW;

		tp = thread_create(NULL, 0, rmclomv_refresh, NULL, 0,
		    &p0, TS_RUN, maxclsyspri);
		rmclomv_refresh_tid = tp->t_did;
	}

	mutex_exit(&rmclomv_refresh_lock);
}

static void
rmclomv_refresh_destroy(void)
{
	kt_did_t tid;

	mutex_enter(&rmclomv_refresh_lock);
	tid = rmclomv_refresh_tid;
	if (tid != 0) {
		rmclomv_refresh_sig = RMCLOMV_REFRESH_EXITNOW;
		cv_signal(&rmclomv_refresh_sig_cv);
		rmclomv_refresh_tid = 0;
	}
	mutex_exit(&rmclomv_refresh_lock);

	/*
	 * Wait for rmclomv_refresh() to finish
	 */
	if (tid != 0)
		thread_join(tid);
}

static void
rmclomv_refresh_wakeup(void)
{
	mutex_enter(&rmclomv_refresh_lock);

	if (rmclomv_refresh_sig != RMCLOMV_REFRESH_EXITNOW)
		rmclomv_refresh_sig = RMCLOMV_REFRESH_PROCESSNOW;
	cv_signal(&rmclomv_refresh_sig_cv);

	mutex_exit(&rmclomv_refresh_lock);
}

static void
send_watchdog_msg(int msg)
{
	rmc_comm_msg_t request;
	dp_set_host_watchdog_t watchdog_msg;

	if (rmclomv_watchdog_mode)
		return;

	watchdog_msg.enable = msg;
	request.msg_type = DP_SET_HOST_WATCHDOG;
	request.msg_len = sizeof (watchdog_msg);
	request.msg_buf = (caddr_t)&watchdog_msg;
	(void) rmc_comm_request_nowait(&request, (msg == 1) ?
	    RMC_COMM_DREQ_URGENT : 0);
}

/*ARGSUSED*/
static uint_t
rmc_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	if ((watchdog_enable == 0) || (watchdog_available == 0)) {
		return (0);
	}

	/*
	 * If boothowto has RB_DEBUG set we never want to set the watchdog
	 * support on.
	 */
	if (boothowto & RB_DEBUG) {
		return (0);
	}

	/*
	 * When the watchdog is shut off last_watchdog_msg goes from a
	 * 0 to a 1. So we must test to see that last_watchdog_msg is
	 * set to 1 indicating that watchdog was shut off and
	 * After which we set last_watchdog_msg back to 0 so that we do not
	 * run this code
	 * again.
	 */
	if (last_watchdog_msg == 1) {
		send_watchdog_msg(0);
		last_watchdog_msg = 0;
	}

	pmugpio_watchdog_pat();

	watchdog_activated = 1;

	return (1);
}

static uint_t
rmc_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	if ((watchdog_activated == 0) || (boothowto & RB_DEBUG))
		return (0);

	send_watchdog_msg(1);
	last_watchdog_msg = 1;
	watchdog_activated = 0;

	return (0);
}

static void
plat_timesync(void *arg)
{
	timestruc_t now;
	todinfo_t tod;
	rmc_comm_msg_t request;
	dp_set_date_time_t set_time_msg;
	int retval;
	timestruc_t ts;
	dp_get_date_time_r_t *date_and_time_info;
	int buffer[DATE_TIME_MSG_SIZE];

	/* Is the system coming up? */
	if (arg != NULL) {
		/* Request the time from the RMC clock. */
		retval = rmclomv_do_cmd(DP_GET_DATE_TIME, DP_GET_DATE_TIME_R,
		    DATE_TIME_MSG_SIZE, NULL, (intptr_t)&buffer);

		/*
		 * If we were able to get the time lets set the local clock.
		 * The time returned from RMC is in Unix time format.
		 *
		 * If we couldn't get the time we'll accept the drift so as not
		 * to cause congestion on the I2C bus or cause boot
		 * performance regressions.
		 */
		if (retval == RCNOERR) {
			date_and_time_info = (dp_get_date_time_r_t *)buffer;
			ts.tv_sec = date_and_time_info->current_datetime;
			ts.tv_nsec = 0;
			mutex_enter(&tod_lock);
			tod_set(ts);
			set_hrestime(&ts);
			mutex_exit(&tod_lock);
		}
	}

	gethrestime(&now);
	mutex_enter(&tod_lock);
	tod = utc_to_tod(now.tv_sec);
	mutex_exit(&tod_lock);

	set_time_msg.year	= tod.tod_year;
	set_time_msg.month	= tod.tod_month - 1;
	set_time_msg.day	= tod.tod_day;
	set_time_msg.hour	= tod.tod_hour;
	set_time_msg.minute	= tod.tod_min;
	set_time_msg.second	= tod.tod_sec;

	request.msg_type = DP_SET_DATE_TIME;
	request.msg_len = sizeof (set_time_msg);
	request.msg_buf = (caddr_t)&set_time_msg;

	(void) rmc_comm_request_nowait(&request, 0);

	mutex_enter(&timesync_lock);
	if (timesync_interval != 0)
		timesync_tid = timeout(plat_timesync, NULL, timesync_interval);
	mutex_exit(&timesync_lock);
}

/*
 * Interfaces to get/set alarm relays from outside
 */
int
rmclomv_alarm_get(int alarm_type, int *alarm_state)
{
	rmclomv_cache_section_t	*section;
	int			index;
	uint16_t		sensor_status;
	dp_get_alarm_state_t	u_rmc_alarm;
	dp_get_alarm_state_r_t	u_rmc_alarm_r;

	/* see if we've got ALARM handles cached */
	LOCK_CACHE
	sensor_status = ENVMON_SENSOR_OK;

	if ((rmclomv_cache_valid == B_FALSE) ||
	    ((section = rmclomv_find_section(rmclomv_cache,
	    RMCLOMV_ALARM_IND)) == NULL)) {
		sensor_status = ENVMON_NOT_PRESENT;
	}
	if (sensor_status == ENVMON_SENSOR_OK) {
		/*
		 * user correctly identified a ALARM, note its
		 * handle value and request the ALARM status
		 */
		index = alarm_type;
		if (index >= section->num_entries)
			sensor_status = ENVMON_INACCESSIBLE;
		else
			u_rmc_alarm.handle = section->entry[index].handle;
	}
	RELEASE_CACHE
	if ((sensor_status == ENVMON_SENSOR_OK) && (rmclomv_rmc_error ||
	    rmclomv_do_cmd(DP_GET_ALARM_STATE, DP_GET_ALARM_STATE_R,
	    sizeof (u_rmc_alarm_r), (intptr_t)&u_rmc_alarm,
	    (intptr_t)&u_rmc_alarm_r) != 0)) {
		sensor_status = ENVMON_INACCESSIBLE;
	}
	if (sensor_status == ENVMON_SENSOR_OK) {
		/*
		 * copy results into buffer for user
		 * start with some defaults then override
		 */
		*alarm_state = 0;

		if (u_rmc_alarm_r.alarm_state[0].sensor_status !=
		    DP_SENSOR_DATA_AVAILABLE)
			return (ENXIO);
		else {
			dp_alarm_state_t alarmState;
			alarmState = u_rmc_alarm_r.alarm_state[0];

			switch (alarmState.state) {
			case DP_ALARM_OFF:
				break;
			case DP_ALARM_ON:
				*alarm_state = 1;
				break;
			default:
				break;
			}
		}
	} else
		return (ENXIO);

	return (0);
}

int
rmclomv_alarm_set(int alarm_type, int new_state)
{
	rmclomv_cache_section_t	*section;
	int			index;
	uint16_t		sensor_status;
	dp_set_alarm_state_t	u_rmc_setalarm;
	dp_set_alarm_state_r_t	u_rmc_setalarm_r;

	/* see if we've got ALARM handles cached */
	LOCK_CACHE
	sensor_status = ENVMON_SENSOR_OK;

	if ((rmclomv_cache_valid == B_FALSE) ||
	    ((section = rmclomv_find_section(rmclomv_cache,
	    RMCLOMV_ALARM_IND)) == NULL)) {
		sensor_status = ENVMON_NOT_PRESENT;
	}
	if (sensor_status == ENVMON_SENSOR_OK) {
		/*
		 * user correctly identified a ALARM, note its
		 * handle value and request the ALARM status
		 */
		index = alarm_type;
		if (index >= section->num_entries)
			sensor_status = ENVMON_INACCESSIBLE;
		else {
			u_rmc_setalarm.handle = section->entry[index].handle;
			u_rmc_setalarm.state = new_state;
		}
	}
	RELEASE_CACHE
	if ((sensor_status == ENVMON_SENSOR_OK) &&
	    (rmclomv_rmc_error ||
	    rmclomv_do_cmd(DP_SET_ALARM_STATE, DP_SET_ALARM_STATE_R,
	    sizeof (u_rmc_setalarm_r), (intptr_t)&u_rmc_setalarm,
	    (intptr_t)&u_rmc_setalarm_r) != 0)) {
		sensor_status = ENVMON_INACCESSIBLE;
	}

	if (u_rmc_setalarm_r.status != DP_SET_ALARM_OK) {
		return (EIO);
	}

	if (sensor_status != ENVMON_SENSOR_OK) {
		return (ENXIO);
	}

	return (0);
}
