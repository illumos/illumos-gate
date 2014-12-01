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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/atomic.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>
#include <sys/cpu_event.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/synch.h>
#include <sys/sysmacros.h>
#include <sys/fipe.h>
#include <vm/hat.h>

/* Current PM policy, configurable through /etc/system and fipe.conf. */
fipe_pm_policy_t fipe_pm_policy = FIPE_PM_POLICY_BALANCE;
int fipe_pm_throttle_level = 1;

/* Enable kstat support. */
#define	FIPE_KSTAT_SUPPORT		1

/* Enable performance relative statistics. */
#define	FIPE_KSTAT_DETAIL		1

/* Enable builtin IOAT driver if no IOAT driver is available. */
#define	FIPE_IOAT_BUILTIN		0
#if defined(FIPE_IOAT_BUILTIN) && (FIPE_IOAT_BUILTIN == 0)
#undef	FIPE_IOAT_BUILTIN
#endif

#ifdef	FIPE_IOAT_BUILTIN
/* Use IOAT channel 3 to generate memory transactions. */
#define	FIPE_IOAT_CHAN_CTRL		0x200
#define	FIPE_IOAT_CHAN_STS_LO		0x204
#define	FIPE_IOAT_CHAN_STS_HI		0x208
#define	FIPE_IOAT_CHAN_ADDR_LO		0x20C
#define	FIPE_IOAT_CHAN_ADDR_HI		0x210
#define	FIPE_IOAT_CHAN_CMD		0x214
#define	FIPE_IOAT_CHAN_ERR		0x228
#else	/* FIPE_IOAT_BUILTIN */
#include <sys/dcopy.h>
#endif	/* FIPE_IOAT_BUILTIN */

/* Memory controller relative PCI configuration constants. */
#define	FIPE_MC_GBLACT			0x60
#define	FIPE_MC_THRTLOW			0x64
#define	FIPE_MC_THRTCTRL 		0x67
#define	FIPE_MC_THRTCTRL_HUNT		0x1

/* Hardware recommended values. */
#define	FIPE_MC_MEMORY_OFFSET		1024
#define	FIPE_MC_MEMORY_SIZE		128

/* Number of IOAT commands posted when entering idle. */
#define	FIPE_IOAT_CMD_NUM		2

/* Resource allocation retry interval in microsecond. */
#define	FIPE_IOAT_RETRY_INTERVAL	(15 * 1000 * 1000)

/* Statistics update interval in nanosecond. */
#define	FIPE_STAT_INTERVAL		(10 * 1000 * 1000)

/* Configuration profile support. */
#define	FIPE_PROFILE_FIELD(field)	(fipe_profile_curr->field)
#define	FIPE_PROF_IDLE_COUNT		FIPE_PROFILE_FIELD(idle_count)
#define	FIPE_PROF_BUSY_THRESHOLD	FIPE_PROFILE_FIELD(busy_threshold)
#define	FIPE_PROF_INTR_THRESHOLD	FIPE_PROFILE_FIELD(intr_threshold)
#define	FIPE_PROF_INTR_BUSY_THRESHOLD	FIPE_PROFILE_FIELD(intr_busy_threshold)
#define	FIPE_PROF_INTR_BUSY_THROTTLE	FIPE_PROFILE_FIELD(intr_busy_throttle)

/* Priority assigned to FIPE memory power management driver on x86. */
#define	CPU_IDLE_CB_PRIO_FIPE		(CPU_IDLE_CB_PRIO_LOW_BASE + 0x4000000)

/* Structure to support power management profile. */
#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_profiles)
static struct fipe_profile {
	uint32_t			idle_count;
	uint32_t			busy_threshold;
	uint32_t			intr_threshold;
	uint32_t			intr_busy_threshold;
	uint32_t			intr_busy_throttle;
} fipe_profiles[FIPE_PM_POLICY_MAX] = {
	{ 0,	0,	0,	0,	0 },
	{ 5,	30,	20,	50,	5 },
	{ 10,	40,	40,	75,	4 },
	{ 15,	50,	60,	100,	2 },
};

/* Structure to store memory controller relative data. */
#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_mc_ctrl)
static struct fipe_mc_ctrl {
	ddi_acc_handle_t		mc_pci_hdl;
	unsigned char			mc_thrtctrl;
	unsigned char			mc_thrtlow;
	unsigned char			mc_gblact;
	dev_info_t			*mc_dip;
	boolean_t			mc_initialized;
} fipe_mc_ctrl;

/* Structure to store IOAT relative information. */
#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_ioat_ctrl)
static struct fipe_ioat_control {
	kmutex_t			ioat_lock;
	boolean_t			ioat_ready;
#ifdef	FIPE_IOAT_BUILTIN
	boolean_t			ioat_reg_mapped;
	ddi_acc_handle_t		ioat_reg_handle;
	uint8_t				*ioat_reg_addr;
	uint64_t			ioat_cmd_physaddr;
#else	/* FIPE_IOAT_BUILTIN */
	dcopy_cmd_t			ioat_cmds[FIPE_IOAT_CMD_NUM + 1];
	dcopy_handle_t			ioat_handle;
#endif	/* FIPE_IOAT_BUILTIN */
	dev_info_t			*ioat_dev_info;
	uint64_t			ioat_buf_physaddr;
	char				*ioat_buf_virtaddr;
	char				*ioat_buf_start;
	size_t				ioat_buf_size;
	timeout_id_t			ioat_timerid;
	boolean_t			ioat_failed;
	boolean_t			ioat_cancel;
	boolean_t			ioat_try_alloc;
} fipe_ioat_ctrl;

#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_idle_ctrl)
static struct fipe_idle_ctrl {
	boolean_t			idle_ready;
	cpu_idle_callback_handle_t	cb_handle;
	cpu_idle_prop_handle_t		prop_enter;
	cpu_idle_prop_handle_t		prop_exit;
	cpu_idle_prop_handle_t		prop_busy;
	cpu_idle_prop_handle_t		prop_idle;
	cpu_idle_prop_handle_t		prop_intr;

	/* Put here for cache efficiency, it should be in fipe_global_ctrl. */
	hrtime_t			tick_interval;
} fipe_idle_ctrl;

/*
 * Global control structure.
 * Solaris idle thread has no reentrance issue, so it's enough to count CPUs
 * in idle state. Otherwise cpuset_t bitmap should be used to track idle CPUs.
 */
#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_gbl_ctrl)
static struct fipe_global_ctrl {
	kmutex_t			lock;
	boolean_t			pm_enabled;
	volatile boolean_t		pm_active;
	volatile uint32_t		cpu_count;
	volatile uint64_t		io_waiters;
	hrtime_t			enter_ts;
	hrtime_t			time_in_pm;
	size_t				state_size;
	char				*state_buf;
#ifdef	FIPE_KSTAT_SUPPORT
	kstat_t				*fipe_kstat;
#endif	/* FIPE_KSTAT_SUPPORT */
} fipe_gbl_ctrl;

#define	FIPE_CPU_STATE_PAD		(128 - \
	2 * sizeof (boolean_t) -  4 * sizeof (hrtime_t) - \
	2 * sizeof (uint64_t) - 2 * sizeof (uint32_t))

/* Per-CPU status. */
#pragma pack(1)
typedef struct fipe_cpu_state {
	boolean_t			cond_ready;
	boolean_t			state_ready;
	uint32_t			idle_count;
	uint32_t			throttle_cnt;
	hrtime_t			throttle_ts;
	hrtime_t			next_ts;
	hrtime_t			last_busy;
	hrtime_t			last_idle;
	uint64_t			last_intr;
	uint64_t			last_iowait;
	char				pad1[FIPE_CPU_STATE_PAD];
} fipe_cpu_state_t;
#pragma pack()

#ifdef	FIPE_KSTAT_SUPPORT
#pragma align CPU_CACHE_COHERENCE_SIZE(fipe_kstat)
static struct fipe_kstat_s {
	kstat_named_t		fipe_enabled;
	kstat_named_t		fipe_policy;
	kstat_named_t		fipe_pm_time;
#ifdef	FIPE_KSTAT_DETAIL
	kstat_named_t		ioat_ready;
	kstat_named_t		pm_tryenter_cnt;
	kstat_named_t		pm_success_cnt;
	kstat_named_t		pm_race_cnt;
	kstat_named_t		cpu_loop_cnt;
	kstat_named_t		cpu_busy_cnt;
	kstat_named_t		cpu_idle_cnt;
	kstat_named_t		cpu_intr_busy_cnt;
	kstat_named_t		cpu_intr_throttle_cnt;
	kstat_named_t		bio_busy_cnt;
	kstat_named_t		ioat_start_fail_cnt;
	kstat_named_t		ioat_stop_fail_cnt;
#endif	/* FIPE_KSTAT_DETAIL */
} fipe_kstat = {
	{ "fipe_enabled",	KSTAT_DATA_INT32 },
	{ "fipe_policy",	KSTAT_DATA_INT32 },
	{ "fipe_pm_time",	KSTAT_DATA_UINT64 },
#ifdef	FIPE_KSTAT_DETAIL
	{ "ioat_ready",		KSTAT_DATA_INT32 },
	{ "pm_tryenter_cnt",	KSTAT_DATA_UINT64 },
	{ "pm_success_cnt",	KSTAT_DATA_UINT64 },
	{ "pm_race_cnt",	KSTAT_DATA_UINT64 },
	{ "cpu_loop_cnt",	KSTAT_DATA_UINT64 },
	{ "cpu_busy_cnt",	KSTAT_DATA_UINT64 },
	{ "cpu_idle_cnt",	KSTAT_DATA_UINT64 },
	{ "cpu_intr_busy_cnt",	KSTAT_DATA_UINT64 },
	{ "cpu_intr_thrt_cnt",	KSTAT_DATA_UINT64 },
	{ "bio_busy_cnt",	KSTAT_DATA_UINT64 },
	{ "ioat_start_fail_cnt", KSTAT_DATA_UINT64 },
	{ "ioat_stop_fail_cnt",	KSTAT_DATA_UINT64 }
#endif	/* FIPE_KSTAT_DETAIL */
};

#define	FIPE_KSTAT_INC(v)		\
	atomic_inc_64(&fipe_kstat.v.value.ui64)
#ifdef	FIPE_KSTAT_DETAIL
#define	FIPE_KSTAT_DETAIL_INC(v)	\
	atomic_inc_64(&fipe_kstat.v.value.ui64)
#else	/* FIPE_KSTAT_DETAIL */
#define	FIPE_KSTAT_DETAIL_INC(v)
#endif	/* FIPE_KSTAT_DETAIL */

#else	/* FIPE_KSTAT_SUPPORT */

#define	FIPE_KSTAT_INC(v)
#define	FIPE_KSTAT_DETAIL_INC(v)

#endif	/* FIPE_KSTAT_SUPPORT */

/* Save current power management profile during suspend/resume. */
static fipe_pm_policy_t	fipe_pm_policy_saved = FIPE_PM_POLICY_BALANCE;
static fipe_cpu_state_t *fipe_cpu_states = NULL;

/*
 * There is no lock to protect fipe_profile_curr, so fipe_profile_curr
 * could change on threads in fipe_idle_enter.  This is not an issue,
 * as it always points to a valid profile, and though it might make
 * an incorrect choice for the new profile, it will still be a valid
 * selection, and would do the correct operation for the new profile on
 * next cpu_idle_enter cycle.  Since the selections would always be
 * valid for some profile, the overhead for the lock is not wasted.
 */
static struct fipe_profile *fipe_profile_curr = NULL;

static void fipe_idle_enter(void *arg, cpu_idle_callback_context_t ctx,
    cpu_idle_check_wakeup_t check_func, void* check_arg);
static void fipe_idle_exit(void* arg, cpu_idle_callback_context_t ctx,
    int flags);
static cpu_idle_callback_t fipe_idle_cb = {
	CPU_IDLE_CALLBACK_VER0,
	fipe_idle_enter,
	fipe_idle_exit,
};

/*
 * Configure memory controller into power saving mode:
 * 1) OLTT activation limit is set to unlimited
 * 2) MC works in S-CLTT mode
 */
static int
fipe_mc_change(int throttle)
{
	/* Enable OLTT/disable S-CLTT mode */
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTCTRL,
	    fipe_mc_ctrl.mc_thrtctrl & ~FIPE_MC_THRTCTRL_HUNT);
	/* Set OLTT activation limit to unlimited */
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_GBLACT, 0);
	/*
	 * Set S-CLTT low throttling to desired value. The lower value,
	 * the more power saving and the less available memory bandwidth.
	 */
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTLOW, throttle);
	/* Enable S-CLTT/disable OLTT mode */
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTCTRL,
	    fipe_mc_ctrl.mc_thrtctrl | FIPE_MC_THRTCTRL_HUNT);

	return (0);
}

/*
 * Restore memory controller's original configuration.
 */
static void
fipe_mc_restore(void)
{
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTCTRL,
	    fipe_mc_ctrl.mc_thrtctrl & ~FIPE_MC_THRTCTRL_HUNT);
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_GBLACT,
	    fipe_mc_ctrl.mc_gblact);
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTLOW,
	    fipe_mc_ctrl.mc_thrtlow);
	pci_config_put8(fipe_mc_ctrl.mc_pci_hdl, FIPE_MC_THRTCTRL,
	    fipe_mc_ctrl.mc_thrtctrl);
}

/*
 * Initialize memory controller's data structure and status.
 */
static int
fipe_mc_init(dev_info_t *dip)
{
	ddi_acc_handle_t handle;

	bzero(&fipe_mc_ctrl, sizeof (fipe_mc_ctrl));

	/* Hold one reference count and will be released in fipe_mc_fini. */
	ndi_hold_devi(dip);

	/* Setup pci configuration handler. */
	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!fipe: failed to setup pcicfg handler in mc_init.");
		ndi_rele_devi(dip);
		return (-1);
	}

	/* Save original configuration. */
	fipe_mc_ctrl.mc_thrtctrl = pci_config_get8(handle, FIPE_MC_THRTCTRL);
	fipe_mc_ctrl.mc_thrtlow = pci_config_get8(handle, FIPE_MC_THRTLOW);
	fipe_mc_ctrl.mc_gblact = pci_config_get8(handle, FIPE_MC_GBLACT);
	fipe_mc_ctrl.mc_dip = dip;
	fipe_mc_ctrl.mc_pci_hdl = handle;
	fipe_mc_ctrl.mc_initialized = B_TRUE;

	return (0);
}

/*
 * Restore memory controller's configuration and release resources.
 */
static void
fipe_mc_fini(void)
{
	if (fipe_mc_ctrl.mc_initialized) {
		fipe_mc_restore();
		pci_config_teardown(&fipe_mc_ctrl.mc_pci_hdl);
		ndi_rele_devi(fipe_mc_ctrl.mc_dip);
		fipe_mc_ctrl.mc_initialized = B_FALSE;
	}
	bzero(&fipe_mc_ctrl, sizeof (fipe_mc_ctrl));
}

/* Search device with specific pci ids. */
struct fipe_pci_ioat_id {
	uint16_t		venid;
	uint16_t		devid;
	uint16_t		subvenid;
	uint16_t		subsysid;
	char			*unitaddr;
};

static struct fipe_pci_ioat_id fipe_pci_ioat_ids[] = {
	{ 0x8086, 0x1a38, 0xffff, 0xffff, NULL },
	{ 0x8086, 0x360b, 0xffff, 0xffff, NULL },
};

/*ARGSUSED*/
static int
fipe_search_ioat_dev(dev_info_t *dip, void *arg)
{
	char *unit;
	struct fipe_pci_ioat_id *id;
	int i, max, venid, devid, subvenid, subsysid;

	/* Query PCI id properties. */
	venid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", 0xffffffff);
	if (venid == 0xffffffff) {
		return (DDI_WALK_CONTINUE);
	}
	devid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", 0xffffffff);
	if (devid == 0xffffffff) {
		return (DDI_WALK_CONTINUE);
	}
	subvenid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "subsystem-vendor-id", 0xffffffff);
	if (subvenid == 0xffffffff) {
		return (DDI_WALK_CONTINUE);
	}
	subsysid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "subsystem-id", 0xffffffff);
	if (subvenid == 0xffffffff) {
		return (DDI_WALK_CONTINUE);
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "unit-address", &unit) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	max = sizeof (fipe_pci_ioat_ids) / sizeof (fipe_pci_ioat_ids[0]);
	for (i = 0; i < max; i++) {
		id = &fipe_pci_ioat_ids[i];
		if ((id->venid == 0xffffu || id->venid == venid) &&
		    (id->devid == 0xffffu || id->devid == devid) &&
		    (id->subvenid == 0xffffu || id->subvenid == subvenid) &&
		    (id->subsysid == 0xffffu || id->subsysid == subsysid) &&
		    (id->unitaddr == NULL || strcmp(id->unitaddr, unit) == 0)) {
			break;
		}
	}
	ddi_prop_free(unit);
	if (i >= max) {
		return (DDI_WALK_CONTINUE);
	}

	/* Found IOAT device, hold one reference count. */
	ndi_hold_devi(dip);
	fipe_ioat_ctrl.ioat_dev_info = dip;

	return (DDI_WALK_TERMINATE);
}

/*
 * To enable FBDIMM idle power enhancement mechanism, IOAT will be used to
 * generate enough memory traffic to trigger memory controller thermal throttle
 * circuitry.
 * If dcopy/ioat is available, we will use dcopy interface to communicate
 * with IOAT. Otherwise the built-in driver will directly talk to IOAT
 * hardware.
 */
#ifdef	FIPE_IOAT_BUILTIN
static int
fipe_ioat_trigger(void)
{
	uint16_t ctrl;
	uint32_t err;
	uint8_t	*addr = fipe_ioat_ctrl.ioat_reg_addr;
	ddi_acc_handle_t handle = fipe_ioat_ctrl.ioat_reg_handle;

	/* Check channel in use flag. */
	ctrl = ddi_get16(handle, (uint16_t *)(addr + FIPE_IOAT_CHAN_CTRL));
	if (ctrl & 0x100) {
		/*
		 * Channel is in use by somebody else. IOAT driver may have
		 * been loaded, forbid fipe from accessing IOAT hardware
		 * anymore.
		 */
		fipe_ioat_ctrl.ioat_ready = B_FALSE;
		fipe_ioat_ctrl.ioat_failed = B_TRUE;
		FIPE_KSTAT_INC(ioat_start_fail_cnt);
		return (-1);
	} else {
		/* Set channel in use flag. */
		ddi_put16(handle,
		    (uint16_t *)(addr + FIPE_IOAT_CHAN_CTRL), 0x100);
	}

	/* Write command address. */
	ddi_put32(handle,
	    (uint32_t *)(addr + FIPE_IOAT_CHAN_ADDR_LO),
	    (uint32_t)fipe_ioat_ctrl.ioat_cmd_physaddr);
	ddi_put32(handle, (uint32_t *)(addr + FIPE_IOAT_CHAN_ADDR_HI),
	    (uint32_t)(fipe_ioat_ctrl.ioat_cmd_physaddr >> 32));

	/* Check and clear error flags. */
	err = ddi_get32(handle, (uint32_t *)(addr + FIPE_IOAT_CHAN_ERR));
	if (err != 0) {
		ddi_put32(handle, (uint32_t *)(addr + FIPE_IOAT_CHAN_ERR), err);
	}

	/* Start channel. */
	ddi_put8(handle, (uint8_t *)(addr + FIPE_IOAT_CHAN_CMD), 0x1);

	return (0);
}

static void
fipe_ioat_cancel(void)
{
	uint32_t status;
	uint8_t	*addr = fipe_ioat_ctrl.ioat_reg_addr;
	ddi_acc_handle_t handle = fipe_ioat_ctrl.ioat_reg_handle;

	/*
	 * Reset channel. Sometimes reset is not reliable,
	 * so check completion or abort status after reset.
	 */
	/* LINTED: constant in conditional context */
	while (1) {
		/* Issue reset channel command. */
		ddi_put8(handle, (uint8_t *)(addr + FIPE_IOAT_CHAN_CMD), 0x20);

		/* Query command status. */
		status = ddi_get32(handle,
		    (uint32_t *)(addr + FIPE_IOAT_CHAN_STS_LO));
		if (status & 0x1) {
			/* Reset channel completed. */
			break;
		} else {
			SMT_PAUSE();
		}
	}

	/* Put channel into "not in use" state. */
	ddi_put16(handle, (uint16_t *)(addr + FIPE_IOAT_CHAN_CTRL), 0);
}

/*ARGSUSED*/
static void
fipe_ioat_alloc(void *arg)
{
	int rc = 0, nregs;
	dev_info_t *dip;
	ddi_device_acc_attr_t attr;
	boolean_t fatal = B_FALSE;

	mutex_enter(&fipe_ioat_ctrl.ioat_lock);
	/*
	 * fipe_ioat_alloc() is called in DEVICE ATTACH context when loaded.
	 * In DEVICE ATTACH context, it can't call ddi_walk_devs(), so just
	 * schedule a timer and exit.
	 */
	if (fipe_ioat_ctrl.ioat_try_alloc == B_FALSE) {
		fipe_ioat_ctrl.ioat_try_alloc = B_TRUE;
		goto out_error;
	}

	/* Check whether has been initialized or encountered permanent error. */
	if (fipe_ioat_ctrl.ioat_ready || fipe_ioat_ctrl.ioat_failed ||
	    fipe_ioat_ctrl.ioat_cancel) {
		fipe_ioat_ctrl.ioat_timerid = 0;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		return;
	}

	if (fipe_ioat_ctrl.ioat_dev_info == NULL) {
		/* Find dev_info_t for IOAT engine. */
		ddi_walk_devs(ddi_root_node(), fipe_search_ioat_dev, NULL);
		if (fipe_ioat_ctrl.ioat_dev_info == NULL) {
			cmn_err(CE_NOTE,
			    "!fipe: no IOAT hardware found, disable pm.");
			fatal = B_TRUE;
			goto out_error;
		}
	}

	/* Map in IOAT control register window. */
	ASSERT(fipe_ioat_ctrl.ioat_dev_info != NULL);
	ASSERT(fipe_ioat_ctrl.ioat_reg_mapped == B_FALSE);
	dip = fipe_ioat_ctrl.ioat_dev_info;
	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS || nregs < 2) {
		cmn_err(CE_WARN, "!fipe: ioat has not enough register bars.");
		fatal = B_TRUE;
		goto out_error;
	}
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	rc = ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&fipe_ioat_ctrl.ioat_reg_addr,
	    0, 0, &attr, &fipe_ioat_ctrl.ioat_reg_handle);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!fipe: failed to map IOAT registeres.");
		fatal = B_TRUE;
		goto out_error;
	}

	/* Mark IOAT status. */
	fipe_ioat_ctrl.ioat_reg_mapped = B_TRUE;
	fipe_ioat_ctrl.ioat_ready = B_TRUE;
	fipe_ioat_ctrl.ioat_failed = B_FALSE;
	fipe_ioat_ctrl.ioat_timerid = 0;
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);

	return;

out_error:
	fipe_ioat_ctrl.ioat_timerid = 0;
	if (!fipe_ioat_ctrl.ioat_ready && !fipe_ioat_ctrl.ioat_cancel) {
		if (fatal) {
			/* Mark permanent error and give up. */
			fipe_ioat_ctrl.ioat_failed = B_TRUE;
			/* Release reference count hold by ddi_find_devinfo. */
			if (fipe_ioat_ctrl.ioat_dev_info != NULL) {
				ndi_rele_devi(fipe_ioat_ctrl.ioat_dev_info);
				fipe_ioat_ctrl.ioat_dev_info = NULL;
			}
		} else {
			/*
			 * Schedule another timer to keep on trying.
			 * timeout() should always succeed, no need to check
			 * return.
			 */
			fipe_ioat_ctrl.ioat_timerid = timeout(fipe_ioat_alloc,
			    NULL, drv_usectohz(FIPE_IOAT_RETRY_INTERVAL));
		}
	}
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);
}

static void
fipe_ioat_free(void)
{
	mutex_enter(&fipe_ioat_ctrl.ioat_lock);
	/* Cancel timeout to avoid race condition. */
	if (fipe_ioat_ctrl.ioat_timerid != 0) {
		fipe_ioat_ctrl.ioat_cancel = B_TRUE;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		(void) untimeout(fipe_ioat_ctrl.ioat_timerid);
		mutex_enter(&fipe_ioat_ctrl.ioat_lock);
		fipe_ioat_ctrl.ioat_timerid = 0;
		fipe_ioat_ctrl.ioat_cancel = B_FALSE;
	}

	if (fipe_ioat_ctrl.ioat_reg_mapped) {
		ddi_regs_map_free(&fipe_ioat_ctrl.ioat_reg_handle);
		fipe_ioat_ctrl.ioat_reg_mapped = B_FALSE;
	}

	fipe_ioat_ctrl.ioat_ready = B_FALSE;
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);
}

#else	/* FIPE_IOAT_BUILTIN */

/*
 * Trigger IOAT memory copy operation when entering power saving state.
 * A group of commands will be posted to IOAT driver and those commands
 * will be placed into an IOAT ring buffer.
 */
static int
fipe_ioat_trigger(void)
{
	int idx;
	dcopy_cmd_t *cmds = fipe_ioat_ctrl.ioat_cmds;

	for (idx = FIPE_IOAT_CMD_NUM; idx > 0; idx--) {
		if (dcopy_cmd_post(cmds[idx]) == DCOPY_SUCCESS) {
			continue;
		} else {
			/*
			 * Don't rollback on failure, it doesn't hurt much more
			 * than some small memory copy operations.
			 */
			FIPE_KSTAT_DETAIL_INC(ioat_start_fail_cnt);
			return (-1);
		}
	}

	return (0);
}

/*
 * Cancel the memory copy operations posted by fipe_ioat_trigger.
 * It's achieved by posting a new command which will break the ring
 * created by fipe_ioat_trigger. If it fails, the best way to recover
 * is to just let it go. IOAT will recover when posting next command
 * on the same channel.
 */
static void
fipe_ioat_cancel(void)
{
	if (dcopy_cmd_post(fipe_ioat_ctrl.ioat_cmds[0]) != DCOPY_SUCCESS) {
		FIPE_KSTAT_DETAIL_INC(ioat_stop_fail_cnt);
	}
}

/*
 * This function will be called from allocate IOAT resources.
 * Allocation may fail due to following reasons:
 * 1) IOAT driver hasn't been loaded yet. Keep on trying in this case.
 * 2) IOAT resources are temporarily unavailable.  Keep on trying in this case.
 * 3) Other no recoverable reasons. Disable power management function.
 */
/*ARGSUSED*/
static void
fipe_ioat_alloc(void *arg)
{
	int idx, flags, rc = 0;
	uint64_t physaddr;
	boolean_t fatal = B_FALSE;
	dcopy_query_t info;
	dcopy_handle_t handle;
	dcopy_cmd_t cmds[FIPE_IOAT_CMD_NUM + 1];

	mutex_enter(&fipe_ioat_ctrl.ioat_lock);
	/*
	 * fipe_ioat_alloc() is called in DEVICE ATTACH context when loaded.
	 * In DEVICE ATTACH context, it can't call ddi_walk_devs(), so just
	 * schedule a timer and exit.
	 */
	if (fipe_ioat_ctrl.ioat_try_alloc == B_FALSE) {
		fipe_ioat_ctrl.ioat_try_alloc = B_TRUE;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		goto out_error;
	}

	/*
	 * Check whether device has been initialized or if it encountered
	 * some permanent error.
	 */
	if (fipe_ioat_ctrl.ioat_ready || fipe_ioat_ctrl.ioat_failed ||
	    fipe_ioat_ctrl.ioat_cancel) {
		fipe_ioat_ctrl.ioat_timerid = 0;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		return;
	}

	if (fipe_ioat_ctrl.ioat_dev_info == NULL) {
		/* Find dev_info_t for IOAT engine. */
		ddi_walk_devs(ddi_root_node(), fipe_search_ioat_dev, NULL);
		if (fipe_ioat_ctrl.ioat_dev_info == NULL) {
			cmn_err(CE_NOTE,
			    "!fipe: no IOAT hardware found, disable pm.");
			mutex_exit(&fipe_ioat_ctrl.ioat_lock);
			fatal = B_TRUE;
			goto out_error;
		}
	}
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);

	/* Check, allocate and initialize IOAT resources with lock released. */
	dcopy_query(&info);
	if (info.dq_version < DCOPY_QUERY_V0) {
		/* Permanent error, give up. */
		cmn_err(CE_WARN, "!fipe: IOAT driver version mismatch.");
		fatal = B_TRUE;
		goto out_error;
	} else if (info.dq_num_channels == 0) {
		/* IOAT driver hasn't been loaded, keep trying. */
		goto out_error;
	}

	/* Allocate IOAT channel. */
	rc = dcopy_alloc(DCOPY_NOSLEEP, &handle);
	if (rc == DCOPY_NORESOURCES) {
		/* Resource temporarily not available, keep trying. */
		goto out_error;
	} else if (rc != DCOPY_SUCCESS) {
		/* Permanent error, give up. */
		cmn_err(CE_WARN, "!fipe: failed to allocate IOAT channel.");
		fatal = B_TRUE;
		goto out_error;
	}

	/*
	 * Allocate multiple IOAT commands and organize them into a ring to
	 * loop forever. Commands number is determined by IOAT descriptor size
	 * and memory interleave pattern.
	 * cmd[0] is used break the loop and disable IOAT operation.
	 * cmd[1, FIPE_IOAT_CMD_NUM] are grouped into a ring and cmd[1] is the
	 * list head.
	 */
	bzero(cmds, sizeof (cmds));
	physaddr = fipe_ioat_ctrl.ioat_buf_physaddr;
	for (idx = FIPE_IOAT_CMD_NUM; idx >= 0; idx--) {
		/* Allocate IOAT commands. */
		if (idx == 0 || idx == FIPE_IOAT_CMD_NUM) {
			flags = DCOPY_NOSLEEP;
		} else {
			/*
			 * To link commands into a list, the initial value of
			 * cmd need to be set to next cmd on list.
			 */
			flags = DCOPY_NOSLEEP | DCOPY_ALLOC_LINK;
			cmds[idx] = cmds[idx + 1];
		}
		rc = dcopy_cmd_alloc(handle, flags, &cmds[idx]);
		if (rc == DCOPY_NORESOURCES) {
			goto out_freecmd;
		} else if (rc != DCOPY_SUCCESS) {
			/* Permanent error, give up. */
			cmn_err(CE_WARN,
			    "!fipe: failed to allocate IOAT command.");
			fatal = B_TRUE;
			goto out_freecmd;
		}

		/* Disable src/dst snoop to improve CPU cache efficiency. */
		cmds[idx]->dp_flags = DCOPY_CMD_NOSRCSNP | DCOPY_CMD_NODSTSNP;
		/* Specially handle commands on the list. */
		if (idx != 0) {
			/* Disable IOAT status. */
			cmds[idx]->dp_flags |= DCOPY_CMD_NOSTAT;
			/* Disable waiting for resources. */
			cmds[idx]->dp_flags |= DCOPY_CMD_NOWAIT;
			if (idx == 1) {
				/* The list head, chain command into loop. */
				cmds[idx]->dp_flags |= DCOPY_CMD_LOOP;
			} else {
				/* Queue all other commands except head. */
				cmds[idx]->dp_flags |= DCOPY_CMD_QUEUE;
			}
		}
		cmds[idx]->dp_cmd = DCOPY_CMD_COPY;
		cmds[idx]->dp.copy.cc_source = physaddr;
		cmds[idx]->dp.copy.cc_dest = physaddr + FIPE_MC_MEMORY_OFFSET;
		if (idx == 0) {
			/*
			 * Command 0 is used to cancel memory copy by breaking
			 * the ring created in fipe_ioat_trigger().
			 * For efficiency, use the smallest memory copy size.
			 */
			cmds[idx]->dp.copy.cc_size = 1;
		} else {
			cmds[idx]->dp.copy.cc_size = FIPE_MC_MEMORY_SIZE;
		}
	}

	/* Update IOAT control status if it hasn't been initialized yet. */
	mutex_enter(&fipe_ioat_ctrl.ioat_lock);
	if (!fipe_ioat_ctrl.ioat_ready && !fipe_ioat_ctrl.ioat_cancel) {
		fipe_ioat_ctrl.ioat_handle = handle;
		for (idx = 0; idx <= FIPE_IOAT_CMD_NUM; idx++) {
			fipe_ioat_ctrl.ioat_cmds[idx] = cmds[idx];
		}
		fipe_ioat_ctrl.ioat_ready = B_TRUE;
		fipe_ioat_ctrl.ioat_failed = B_FALSE;
		fipe_ioat_ctrl.ioat_timerid = 0;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		return;
	}
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);
	/* Initialized by another thread, fall through to free resources. */

out_freecmd:
	if (cmds[0] != NULL) {
		dcopy_cmd_free(&cmds[0]);
	}
	/* Only need to free head, dcopy will free all commands on the list. */
	for (idx = 1; idx <= FIPE_IOAT_CMD_NUM; idx++) {
		if (cmds[idx] != NULL) {
			dcopy_cmd_free(&cmds[idx]);
			break;
		}
	}
	dcopy_free(&handle);

out_error:
	mutex_enter(&fipe_ioat_ctrl.ioat_lock);
	fipe_ioat_ctrl.ioat_timerid = 0;
	if (!fipe_ioat_ctrl.ioat_ready && !fipe_ioat_ctrl.ioat_cancel) {
		if (fatal) {
			/* Mark permanent error and give up. */
			fipe_ioat_ctrl.ioat_failed = B_TRUE;
			/* Release reference count hold by ddi_find_devinfo. */
			if (fipe_ioat_ctrl.ioat_dev_info != NULL) {
				ndi_rele_devi(fipe_ioat_ctrl.ioat_dev_info);
				fipe_ioat_ctrl.ioat_dev_info = NULL;
			}
		} else {
			/*
			 * Schedule another timer to keep on trying.
			 * timeout() should always success, no need to check.
			 */
			fipe_ioat_ctrl.ioat_timerid = timeout(fipe_ioat_alloc,
			    NULL, drv_usectohz(FIPE_IOAT_RETRY_INTERVAL));
		}
	}
	mutex_exit(&fipe_ioat_ctrl.ioat_lock);
}

/*
 * Free resources allocated in fipe_ioat_alloc.
 */
static void
fipe_ioat_free(void)
{
	int idx = 0;
	dcopy_cmd_t *cmds = fipe_ioat_ctrl.ioat_cmds;

	mutex_enter(&fipe_ioat_ctrl.ioat_lock);

	/* Cancel timeout to avoid race condition. */
	if (fipe_ioat_ctrl.ioat_timerid != 0) {
		fipe_ioat_ctrl.ioat_cancel = B_TRUE;
		mutex_exit(&fipe_ioat_ctrl.ioat_lock);
		(void) untimeout(fipe_ioat_ctrl.ioat_timerid);
		mutex_enter(&fipe_ioat_ctrl.ioat_lock);
		fipe_ioat_ctrl.ioat_timerid = 0;
		fipe_ioat_ctrl.ioat_cancel = B_FALSE;
	}

	/* Free ioat resources. */
	if (fipe_ioat_ctrl.ioat_ready) {
		if (cmds[0] != NULL) {
			dcopy_cmd_free(&cmds[0]);
		}
		for (idx = 1; idx <= FIPE_IOAT_CMD_NUM; idx++) {
			if (cmds[idx] != NULL) {
				dcopy_cmd_free(&cmds[idx]);
				break;
			}
		}
		bzero(fipe_ioat_ctrl.ioat_cmds,
		    sizeof (fipe_ioat_ctrl.ioat_cmds));
		dcopy_free(&fipe_ioat_ctrl.ioat_handle);
		fipe_ioat_ctrl.ioat_handle = NULL;
		fipe_ioat_ctrl.ioat_ready = B_FALSE;
	}

	/* Release reference count hold by ddi_find_devinfo. */
	if (fipe_ioat_ctrl.ioat_dev_info != NULL) {
		ndi_rele_devi(fipe_ioat_ctrl.ioat_dev_info);
		fipe_ioat_ctrl.ioat_dev_info = NULL;
	}

	mutex_exit(&fipe_ioat_ctrl.ioat_lock);
}
#endif	/* FIPE_IOAT_BUILTIN */

/*
 * Initialize IOAT relative resources.
 */
static int
fipe_ioat_init(void)
{
	char *buf;
	size_t size;

	bzero(&fipe_ioat_ctrl, sizeof (fipe_ioat_ctrl));
	mutex_init(&fipe_ioat_ctrl.ioat_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Allocate memory for IOAT memory copy operation.
	 * The allocated memory should be page aligned to achieve better power
	 * savings.
	 * Don't use ddi_dma_mem_alloc here to keep thing simple.  This also
	 * makes quiesce easier.
	 */
	size = PAGESIZE;
	buf = kmem_zalloc(size, KM_SLEEP);
	if ((intptr_t)buf & PAGEOFFSET) {
		kmem_free(buf, PAGESIZE);
		size <<= 1;
		buf = kmem_zalloc(size, KM_SLEEP);
	}
	fipe_ioat_ctrl.ioat_buf_size = size;
	fipe_ioat_ctrl.ioat_buf_start = buf;
	buf = (char *)P2ROUNDUP((intptr_t)buf, PAGESIZE);
	fipe_ioat_ctrl.ioat_buf_virtaddr = buf;
	fipe_ioat_ctrl.ioat_buf_physaddr = hat_getpfnum(kas.a_hat, buf);
	fipe_ioat_ctrl.ioat_buf_physaddr <<= PAGESHIFT;

#ifdef	FIPE_IOAT_BUILTIN
	{
		uint64_t bufpa;
		/* IOAT descriptor data structure copied from ioat.h. */
		struct fipe_ioat_cmd_desc {
			uint32_t	dd_size;
			uint32_t	dd_ctrl;
			uint64_t	dd_src_paddr;
			uint64_t	dd_dest_paddr;
			uint64_t	dd_next_desc;
			uint64_t	dd_res4;
			uint64_t	dd_res5;
			uint64_t	dd_res6;
			uint64_t	dd_res7;
		} *desc;

		/*
		 * Build two IOAT command descriptors and chain them into ring.
		 * Control flags as below:
		 *	0x2: disable source snoop
		 *	0x4: disable destination snoop
		 *	0x0 << 24: memory copy operation
		 * The layout for command descriptors and memory buffers are
		 * organized for power saving effect, please don't change it.
		 */
		buf = fipe_ioat_ctrl.ioat_buf_virtaddr;
		bufpa = fipe_ioat_ctrl.ioat_buf_physaddr;
		fipe_ioat_ctrl.ioat_cmd_physaddr = bufpa;

		/* First command descriptor. */
		desc = (struct fipe_ioat_cmd_desc *)(buf);
		desc->dd_size = 128;
		desc->dd_ctrl = 0x6;
		desc->dd_src_paddr = bufpa + 2048;
		desc->dd_dest_paddr = bufpa + 3072;
		/* Point to second descriptor. */
		desc->dd_next_desc = bufpa + 64;

		/* Second command descriptor. */
		desc = (struct fipe_ioat_cmd_desc *)(buf + 64);
		desc->dd_size = 128;
		desc->dd_ctrl = 0x6;
		desc->dd_src_paddr = bufpa + 2048;
		desc->dd_dest_paddr = bufpa + 3072;
		/* Point to first descriptor. */
		desc->dd_next_desc = bufpa;
	}
#endif	/* FIPE_IOAT_BUILTIN */

	return (0);
}

static void
fipe_ioat_fini(void)
{
	/* Release reference count hold by ddi_find_devinfo. */
	if (fipe_ioat_ctrl.ioat_dev_info != NULL) {
		ndi_rele_devi(fipe_ioat_ctrl.ioat_dev_info);
		fipe_ioat_ctrl.ioat_dev_info = NULL;
	}

	if (fipe_ioat_ctrl.ioat_buf_start != NULL) {
		ASSERT(fipe_ioat_ctrl.ioat_buf_size != 0);
		kmem_free(fipe_ioat_ctrl.ioat_buf_start,
		    fipe_ioat_ctrl.ioat_buf_size);
	}

	mutex_destroy(&fipe_ioat_ctrl.ioat_lock);
	bzero(&fipe_ioat_ctrl, sizeof (fipe_ioat_ctrl));
}

static int
fipe_idle_start(void)
{
	int rc;

	if (fipe_idle_ctrl.idle_ready) {
		return (0);
	}

	if (cpu_idle_prop_create_handle(CPU_IDLE_PROP_ENTER_TIMESTAMP,
	    &fipe_idle_ctrl.prop_enter) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to get enter_ts property.");
		return (-1);
	}
	if (cpu_idle_prop_create_handle(CPU_IDLE_PROP_EXIT_TIMESTAMP,
	    &fipe_idle_ctrl.prop_exit) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to get exit_ts property.");
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);
		return (-1);
	}
	if (cpu_idle_prop_create_handle(CPU_IDLE_PROP_TOTAL_IDLE_TIME,
	    &fipe_idle_ctrl.prop_idle) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to get idle_time property.");
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_exit);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);
		return (-1);
	}
	if (cpu_idle_prop_create_handle(CPU_IDLE_PROP_TOTAL_BUSY_TIME,
	    &fipe_idle_ctrl.prop_busy) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to get busy_time property.");
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_idle);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_exit);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);
		return (-1);
	}
	if (cpu_idle_prop_create_handle(CPU_IDLE_PROP_INTERRUPT_COUNT,
	    &fipe_idle_ctrl.prop_intr) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to get intr_count property.");
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_busy);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_idle);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_exit);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);
		return (-1);
	}

	/* Register idle state notification callback. */
	rc = cpu_idle_register_callback(CPU_IDLE_CB_PRIO_FIPE, &fipe_idle_cb,
	    NULL, &fipe_idle_ctrl.cb_handle);
	if (rc != 0) {
		cmn_err(CE_WARN, "!fipe: failed to register cpuidle callback.");
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_intr);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_busy);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_idle);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_exit);
		(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);
		return (-1);
	}

	fipe_idle_ctrl.idle_ready = B_TRUE;

	return (0);
}

static int
fipe_idle_stop(void)
{
	int rc;

	if (fipe_idle_ctrl.idle_ready == B_FALSE) {
		return (0);
	}

	rc = cpu_idle_unregister_callback(fipe_idle_ctrl.cb_handle);
	if (rc != 0) {
		cmn_err(CE_WARN,
		    "!fipe: failed to unregister cpuidle callback.");
		return (-1);
	}

	(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_intr);
	(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_busy);
	(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_idle);
	(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_exit);
	(void) cpu_idle_prop_destroy_handle(fipe_idle_ctrl.prop_enter);

	fipe_idle_ctrl.idle_ready = B_FALSE;

	return (0);
}

#ifdef	FIPE_KSTAT_SUPPORT
static int
fipe_kstat_update(kstat_t *ksp, int rw)
{
	struct fipe_kstat_s *sp;
	hrtime_t hrt;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	sp = ksp->ks_data;
	sp->fipe_enabled.value.i32 = fipe_gbl_ctrl.pm_enabled ? 1 : 0;
	sp->fipe_policy.value.i32 = fipe_pm_policy;

	hrt = fipe_gbl_ctrl.time_in_pm;
	scalehrtime(&hrt);
	sp->fipe_pm_time.value.ui64 = (uint64_t)hrt;

#ifdef	FIPE_KSTAT_DETAIL
	sp->ioat_ready.value.i32 = fipe_ioat_ctrl.ioat_ready ? 1 : 0;
#endif	/* FIPE_KSTAT_DETAIL */

	return (0);
}
#endif	/* FIPE_KSTAT_SUPPORT */

/*
 * Initialize memory power management subsystem.
 * Note: This function should only be called from ATTACH.
 * Note: caller must ensure exclusive access to all fipe_xxx interfaces.
 */
int
fipe_init(dev_info_t *dip)
{
	size_t nsize;
	hrtime_t hrt;

	/* Initialize global control structure. */
	bzero(&fipe_gbl_ctrl, sizeof (fipe_gbl_ctrl));
	mutex_init(&fipe_gbl_ctrl.lock, NULL, MUTEX_DRIVER, NULL);

	/* Query power management policy from device property. */
	fipe_pm_policy = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    FIPE_PROP_PM_POLICY, fipe_pm_policy);
	if (fipe_pm_policy < 0 || fipe_pm_policy >= FIPE_PM_POLICY_MAX) {
		cmn_err(CE_CONT,
		    "?fipe: invalid power management policy %d.\n",
		    fipe_pm_policy);
		fipe_pm_policy = FIPE_PM_POLICY_BALANCE;
	}
	fipe_profile_curr = &fipe_profiles[fipe_pm_policy];

	/*
	 * Compute unscaled hrtime value corresponding to FIPE_STAT_INTERVAL.
	 * (1 << 36) should be big enough here.
	 */
	hrt = 1ULL << 36;
	scalehrtime(&hrt);
	fipe_idle_ctrl.tick_interval = FIPE_STAT_INTERVAL * (1ULL << 36) / hrt;

	if (fipe_mc_init(dip) != 0) {
		cmn_err(CE_WARN, "!fipe: failed to initialize mc state.");
		goto out_mc_error;
	}
	if (fipe_ioat_init() != 0) {
		cmn_err(CE_NOTE, "!fipe: failed to initialize ioat state.");
		goto out_ioat_error;
	}

	/* Allocate per-CPU structure. */
	nsize = max_ncpus * sizeof (fipe_cpu_state_t);
	nsize += CPU_CACHE_COHERENCE_SIZE;
	fipe_gbl_ctrl.state_buf = kmem_zalloc(nsize, KM_SLEEP);
	fipe_gbl_ctrl.state_size = nsize;
	fipe_cpu_states = (fipe_cpu_state_t *)P2ROUNDUP(
	    (intptr_t)fipe_gbl_ctrl.state_buf, CPU_CACHE_COHERENCE_SIZE);

#ifdef	FIPE_KSTAT_SUPPORT
	fipe_gbl_ctrl.fipe_kstat = kstat_create("fipe", 0, "fipe-pm", "misc",
	    KSTAT_TYPE_NAMED, sizeof (fipe_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (fipe_gbl_ctrl.fipe_kstat == NULL) {
		cmn_err(CE_CONT, "?fipe: failed to create kstat object.\n");
	} else {
		fipe_gbl_ctrl.fipe_kstat->ks_lock = &fipe_gbl_ctrl.lock;
		fipe_gbl_ctrl.fipe_kstat->ks_data = &fipe_kstat;
		fipe_gbl_ctrl.fipe_kstat->ks_update = fipe_kstat_update;
		kstat_install(fipe_gbl_ctrl.fipe_kstat);
	}
#endif	/* FIPE_KSTAT_SUPPORT */

	return (0);

out_ioat_error:
	fipe_mc_fini();
out_mc_error:
	mutex_destroy(&fipe_gbl_ctrl.lock);
	bzero(&fipe_gbl_ctrl, sizeof (fipe_gbl_ctrl));

	return (-1);
}

/*
 * Destroy memory power management subsystem.
 * Note: This function should only be called from DETACH.
 * Note: caller must ensure exclusive access to all fipe_xxx interfaces.
 */
int
fipe_fini(void)
{
	if (fipe_gbl_ctrl.pm_enabled) {
		cmn_err(CE_NOTE, "!fipe: call fipe_fini without stopping PM.");
		return (EBUSY);
	}

	ASSERT(!fipe_gbl_ctrl.pm_active);
	fipe_ioat_fini();
	fipe_mc_fini();

#ifdef	FIPE_KSTAT_SUPPORT
	if (fipe_gbl_ctrl.fipe_kstat != NULL) {
		kstat_delete(fipe_gbl_ctrl.fipe_kstat);
		fipe_gbl_ctrl.fipe_kstat = NULL;
	}
#endif	/* FIPE_KSTAT_SUPPORT */

	if (fipe_gbl_ctrl.state_buf != NULL) {
		ASSERT(fipe_gbl_ctrl.state_size != 0);
		kmem_free(fipe_gbl_ctrl.state_buf, fipe_gbl_ctrl.state_size);
		fipe_cpu_states = NULL;
	}

	fipe_profile_curr = NULL;
	mutex_destroy(&fipe_gbl_ctrl.lock);
	bzero(&fipe_gbl_ctrl, sizeof (fipe_gbl_ctrl));

	return (0);
}

/*
 * Start memory power management subsystem.
 * Note: caller must ensure exclusive access to all fipe_xxx interfaces.
 */
int
fipe_start(void)
{
	if (fipe_gbl_ctrl.pm_enabled == B_TRUE) {
		return (0);
	}

	bzero(fipe_cpu_states, max_ncpus * sizeof (fipe_cpu_states[0]));
	fipe_ioat_alloc(NULL);
	if (fipe_idle_start() != 0) {
		cmn_err(CE_NOTE, "!fipe: failed to start PM subsystem.");
		fipe_ioat_free();
		return (-1);
	}

	fipe_gbl_ctrl.pm_enabled = B_TRUE;

	return (0);
}

/*
 * Stop memory power management subsystem.
 * Note: caller must ensure exclusive access to all fipe_xxx interfaces.
 */
int
fipe_stop(void)
{
	if (fipe_gbl_ctrl.pm_enabled) {
		if (fipe_idle_stop() != 0) {
			cmn_err(CE_NOTE,
			    "!fipe: failed to stop PM subsystem.");
			return (-1);
		}
		fipe_ioat_free();
		fipe_gbl_ctrl.pm_enabled = B_FALSE;
	}
	ASSERT(!fipe_gbl_ctrl.pm_active);

	return (0);
}

int
fipe_suspend(void)
{
	/* Save current power management policy. */
	fipe_pm_policy_saved = fipe_pm_policy;
	/* Disable PM by setting profile to FIPE_PM_POLICY_DISABLE. */
	fipe_pm_policy = FIPE_PM_POLICY_DISABLE;
	fipe_profile_curr = &fipe_profiles[fipe_pm_policy];

	return (0);
}

int
fipe_resume(void)
{
	/* Restore saved power management policy. */
	fipe_pm_policy = fipe_pm_policy_saved;
	fipe_profile_curr = &fipe_profiles[fipe_pm_policy];

	return (0);
}

fipe_pm_policy_t
fipe_get_pmpolicy(void)
{
	return (fipe_pm_policy);
}

int
fipe_set_pmpolicy(fipe_pm_policy_t policy)
{
	if (policy < 0 || policy >= FIPE_PM_POLICY_MAX) {
		return (EINVAL);
	}
	fipe_pm_policy = policy;
	fipe_profile_curr = &fipe_profiles[fipe_pm_policy];

	return (0);
}

/*
 * Check condition (fipe_gbl_ctrl.cpu_cnt == ncpus) to make sure that
 * there is other CPU trying to wake up system from memory power saving state.
 * If a CPU is waking up system, fipe_disable() will set
 * fipe_gbl_ctrl.pm_active to false as soon as possible and allow other CPU's
 * to continue, and it will take the responsibility to recover system from
 * memory power saving state.
 */
static void
fipe_enable(int throttle, cpu_idle_check_wakeup_t check_func, void* check_arg)
{
	extern void membar_sync(void);

	FIPE_KSTAT_DETAIL_INC(pm_tryenter_cnt);

	/*
	 * Check CPU wakeup events.
	 */
	if (check_func != NULL) {
		(*check_func)(check_arg);
	}

	/*
	 * Try to acquire mutex, which also implicitly has the same effect
	 * of calling membar_sync().
	 * If mutex_tryenter fails, that means other CPU is waking up.
	 */
	if (mutex_tryenter(&fipe_gbl_ctrl.lock) == 0) {
		FIPE_KSTAT_DETAIL_INC(pm_race_cnt);
	/*
	 * Handle a special race condition for the case that a CPU wakes
	 * and then enters into idle state within a short period.
	 * This case can't be reliably detected by cpu_count mechanism.
	 */
	} else if (fipe_gbl_ctrl.pm_active) {
		FIPE_KSTAT_DETAIL_INC(pm_race_cnt);
		mutex_exit(&fipe_gbl_ctrl.lock);
	} else {
		fipe_gbl_ctrl.pm_active = B_TRUE;
		membar_sync();
		if (fipe_gbl_ctrl.cpu_count != ncpus) {
			FIPE_KSTAT_DETAIL_INC(pm_race_cnt);
			fipe_gbl_ctrl.pm_active = B_FALSE;
		} else if (fipe_ioat_trigger() != 0) {
			fipe_gbl_ctrl.pm_active = B_FALSE;
		} else if (fipe_gbl_ctrl.cpu_count != ncpus ||
		    fipe_mc_change(throttle) != 0) {
			fipe_gbl_ctrl.pm_active = B_FALSE;
			fipe_ioat_cancel();
			if (fipe_gbl_ctrl.cpu_count != ncpus) {
				FIPE_KSTAT_DETAIL_INC(pm_race_cnt);
			}
		} else if (fipe_gbl_ctrl.cpu_count != ncpus) {
			fipe_gbl_ctrl.pm_active = B_FALSE;
			fipe_mc_restore();
			fipe_ioat_cancel();
			FIPE_KSTAT_DETAIL_INC(pm_race_cnt);
		} else {
			FIPE_KSTAT_DETAIL_INC(pm_success_cnt);
		}
		mutex_exit(&fipe_gbl_ctrl.lock);
	}
}

static void
fipe_disable(void)
{
	/*
	 * Try to acquire lock, which also implicitly has the same effect
	 * of calling membar_sync().
	 */
	while (mutex_tryenter(&fipe_gbl_ctrl.lock) == 0) {
		/*
		 * If power saving is inactive, just return and all dirty
		 * house-keeping work will be handled in fipe_enable().
		 */
		if (fipe_gbl_ctrl.pm_active == B_FALSE) {
			return;
		} else {
			(void) SMT_PAUSE();
		}
	}

	/* Disable power saving if it's active. */
	if (fipe_gbl_ctrl.pm_active) {
		/*
		 * Set pm_active to FALSE as soon as possible to prevent
		 * other CPUs from waiting on pm_active flag.
		 */
		fipe_gbl_ctrl.pm_active = B_FALSE;
		membar_producer();
		fipe_mc_restore();
		fipe_ioat_cancel();
	}

	mutex_exit(&fipe_gbl_ctrl.lock);
}

/*ARGSUSED*/
static boolean_t
fipe_check_cpu(struct fipe_cpu_state *sp, cpu_idle_callback_context_t ctx,
    hrtime_t ts)
{
	if (cpu_flagged_offline(CPU->cpu_flags)) {
		/* Treat CPU in offline state as ready. */
		sp->cond_ready = B_TRUE;
		return (B_TRUE);
	} else if (sp->next_ts <= ts) {
		uint64_t intr;
		hrtime_t idle, busy, diff;
		cpu_idle_prop_value_t val;

		/* Set default value. */
		sp->cond_ready = B_TRUE;
		sp->idle_count = 0;

		/* Calculate idle percent. */
		idle = sp->last_idle;
		sp->last_idle = cpu_idle_prop_get_hrtime(
		    fipe_idle_ctrl.prop_idle, ctx);
		idle = sp->last_idle - idle;
		busy = sp->last_busy;
		sp->last_busy = cpu_idle_prop_get_hrtime(
		    fipe_idle_ctrl.prop_busy, ctx);
		busy = sp->last_busy - busy;
		/* Check idle condition. */
		if (idle > 0 && busy > 0) {
			if (busy * (100 - FIPE_PROF_BUSY_THRESHOLD) >
			    idle * FIPE_PROF_BUSY_THRESHOLD) {
				FIPE_KSTAT_DETAIL_INC(cpu_busy_cnt);
				sp->cond_ready = B_FALSE;
			} else {
				FIPE_KSTAT_DETAIL_INC(cpu_idle_cnt);
			}
		} else {
			FIPE_KSTAT_DETAIL_INC(cpu_busy_cnt);
			sp->cond_ready = B_FALSE;
		}

		/* Calculate interrupt count. */
		diff = sp->next_ts;
		sp->next_ts = ts + fipe_idle_ctrl.tick_interval;
		diff = sp->next_ts - diff;
		intr = sp->last_intr;
		if (cpu_idle_prop_get_value(fipe_idle_ctrl.prop_intr, ctx,
		    &val) == 0) {
			sp->last_intr = val.cipv_uint64;
			intr = sp->last_intr - intr;
			if (diff != 0) {
				intr = intr * fipe_idle_ctrl.tick_interval;
				intr /= diff;
			} else {
				intr = FIPE_PROF_INTR_THRESHOLD;
			}
		} else {
			intr = FIPE_PROF_INTR_THRESHOLD;
		}

		/*
		 * System is busy with interrupts, so disable all PM
		 * status checks for INTR_BUSY_THROTTLE ticks.
		 * Interrupts are disabled when FIPE callbacks are called,
		 * so this optimization will help to reduce interrupt
		 * latency.
		 */
		if (intr >= FIPE_PROF_INTR_BUSY_THRESHOLD) {
			FIPE_KSTAT_DETAIL_INC(cpu_intr_busy_cnt);
			sp->throttle_ts = ts + FIPE_PROF_INTR_BUSY_THROTTLE *
			    fipe_idle_ctrl.tick_interval;
			sp->cond_ready = B_FALSE;
		} else if (intr >= FIPE_PROF_INTR_THRESHOLD) {
			FIPE_KSTAT_DETAIL_INC(cpu_intr_throttle_cnt);
			sp->cond_ready = B_FALSE;
		}
	} else if (++sp->idle_count >= FIPE_PROF_IDLE_COUNT) {
		/* Too many idle enter/exit in this tick. */
		FIPE_KSTAT_DETAIL_INC(cpu_loop_cnt);
		sp->throttle_ts = sp->next_ts + fipe_idle_ctrl.tick_interval;
		sp->idle_count = 0;
		sp->cond_ready = B_FALSE;
		return (B_FALSE);
	}

	return (sp->cond_ready);
}

/*ARGSUSED*/
static void
fipe_idle_enter(void *arg, cpu_idle_callback_context_t ctx,
    cpu_idle_check_wakeup_t check_func, void* check_arg)
{
	hrtime_t ts;
	uint32_t cnt;
	uint64_t iowait;
	cpu_t *cp = CPU;
	struct fipe_cpu_state *sp;

	sp = &fipe_cpu_states[cp->cpu_id];
	ts = cpu_idle_prop_get_hrtime(fipe_idle_ctrl.prop_enter, ctx);

	if (fipe_pm_policy != FIPE_PM_POLICY_DISABLE &&
	    fipe_ioat_ctrl.ioat_ready &&
	    sp->state_ready && sp->throttle_ts <= ts) {
		/* Adjust iowait count for local CPU. */
		iowait = CPU_STATS(cp, sys.iowait);
		if (iowait != sp->last_iowait) {
			atomic_add_64(&fipe_gbl_ctrl.io_waiters,
			    iowait - sp->last_iowait);
			sp->last_iowait = iowait;
		}

		/* Check current CPU status. */
		if (fipe_check_cpu(sp, ctx, ts)) {
			/* Increase count of CPU ready for power saving. */
			do {
				cnt = fipe_gbl_ctrl.cpu_count;
				ASSERT(cnt < ncpus);
			} while (atomic_cas_32(&fipe_gbl_ctrl.cpu_count,
			    cnt, cnt + 1) != cnt);

			/*
			 * Enable power saving if all CPUs are idle.
			 */
			if (cnt + 1 == ncpus) {
				if (fipe_gbl_ctrl.io_waiters == 0) {
					fipe_gbl_ctrl.enter_ts = ts;
					fipe_enable(fipe_pm_throttle_level,
					    check_func, check_arg);
				/* There are ongoing block io operations. */
				} else {
					FIPE_KSTAT_DETAIL_INC(bio_busy_cnt);
				}
			}
		}
	} else if (fipe_pm_policy == FIPE_PM_POLICY_DISABLE ||
	    fipe_ioat_ctrl.ioat_ready == B_FALSE) {
		if (sp->cond_ready == B_TRUE) {
			sp->cond_ready = B_FALSE;
		}
	} else if (sp->state_ready == B_FALSE) {
		sp->cond_ready = B_FALSE;
		sp->state_ready = B_TRUE;
		sp->throttle_ts = 0;
		sp->next_ts = ts + fipe_idle_ctrl.tick_interval;
		sp->last_busy = cpu_idle_prop_get_hrtime(
		    fipe_idle_ctrl.prop_busy, ctx);
		sp->last_idle = cpu_idle_prop_get_hrtime(
		    fipe_idle_ctrl.prop_idle, ctx);
		sp->last_intr = cpu_idle_prop_get_hrtime(
		    fipe_idle_ctrl.prop_intr, ctx);
		sp->idle_count = 0;
	}
}

/*ARGSUSED*/
static void
fipe_idle_exit(void* arg, cpu_idle_callback_context_t ctx, int flags)
{
	uint32_t cnt;
	hrtime_t ts;
	struct fipe_cpu_state *sp;

	sp = &fipe_cpu_states[CPU->cpu_id];
	if (sp->cond_ready) {
		do {
			cnt = fipe_gbl_ctrl.cpu_count;
			ASSERT(cnt > 0);
		} while (atomic_cas_32(&fipe_gbl_ctrl.cpu_count,
		    cnt, cnt - 1) != cnt);

		/*
		 * Try to disable power saving state.
		 * Only the first CPU waking from idle state will try to
		 * disable power saving state, all other CPUs will just go
		 * on and not try to wait for memory to recover from power
		 * saving state.
		 * So there are possible periods during which some CPUs are in
		 * active state but memory is in power saving state.
		 * This is OK, since it is an uncommon case, and it is
		 * better for performance to let them continue as their
		 * blocking latency is smaller than a mutex, and is only
		 * hit in the uncommon condition.
		 */
		if (cnt == ncpus) {
			fipe_disable();
			ts = cpu_idle_prop_get_hrtime(fipe_idle_ctrl.prop_exit,
			    ctx);
			fipe_gbl_ctrl.time_in_pm += ts - fipe_gbl_ctrl.enter_ts;
		}
	}
}
