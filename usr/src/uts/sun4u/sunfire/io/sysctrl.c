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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/ivintr.h>
#include <sys/autoconf.h>
#include <sys/intreg.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/callb.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/fhc.h>
#include <sys/sysctrl.h>
#include <sys/jtag.h>
#include <sys/ac.h>
#include <sys/simmstat.h>
#include <sys/clock.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/sunndi.h>
#include <sys/machsystm.h>

/* Useful debugging Stuff */
#ifdef DEBUG
int sysc_debug_info = 1;
int sysc_debug_print_level = 0;
#endif

/*
 * Function prototypes
 */
static int sysctrl_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);

static int sysctrl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);

static int sysctrl_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

static int sysctrl_open(dev_t *, int, int, cred_t *);

static int sysctrl_close(dev_t, int, int, cred_t *);

static int sysctrl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static uint_t system_high_handler(caddr_t arg);

static uint_t spur_delay(caddr_t arg);

static void spur_retry(void *);

static uint_t spur_reenable(caddr_t arg);

static void spur_long_timeout(void *);

static uint_t spur_clear_count(caddr_t arg);

static uint_t ac_fail_handler(caddr_t arg);

static void ac_fail_retry(void *);

static uint_t ac_fail_reenable(caddr_t arg);

static uint_t ps_fail_int_handler(caddr_t arg);

static uint_t ps_fail_poll_handler(caddr_t arg);

static uint_t ps_fail_handler(struct sysctrl_soft_state *softsp, int fromint);

enum power_state compute_power_state(struct sysctrl_soft_state *softsp,
					int plus_load);

static void ps_log_state_change(struct sysctrl_soft_state *softsp,
					int index, int present);

static void ps_log_pres_change(struct sysctrl_soft_state *softsp,
					int index, int present);

static void ps_fail_retry(void *);

static uint_t pps_fanfail_handler(caddr_t arg);

static void pps_fanfail_retry(void *);

static uint_t pps_fanfail_reenable(caddr_t arg);

static void pps_fan_poll(void *);

static void pps_fan_state_change(struct sysctrl_soft_state *softsp,
					int index, int fan_ok);

static uint_t bd_insert_handler(caddr_t arg);

static void bd_insert_timeout(void *);

static void bd_remove_timeout(void *);

static uint_t bd_insert_normal(caddr_t arg);

static void sysctrl_add_kstats(struct sysctrl_soft_state *softsp);

static int sysctrl_kstat_update(kstat_t *ksp, int rw);

static int psstat_kstat_update(kstat_t *, int);

static void init_remote_console_uart(struct sysctrl_soft_state *);

static void blink_led_timeout(void *);

static uint_t blink_led_handler(caddr_t arg);

static void sysctrl_thread_wakeup(void *type);

static void sysctrl_overtemp_poll(void);

static void sysctrl_keyswitch_poll(void);

static void update_key_state(struct sysctrl_soft_state *);

static void sysctrl_abort_seq_handler(char *msg);

static void nvram_update_powerfail(struct sysctrl_soft_state *softsp);

static void toggle_board_green_leds(int);

void bd_remove_poll(struct sysctrl_soft_state *);

static void sysc_slot_info(int nslots, int *start, int *limit, int *incr);

extern void sysc_board_connect_supported_init(void);

static void rcons_reinit(struct sysctrl_soft_state *softsp);

/*
 * Configuration data structures
 */
static struct cb_ops sysctrl_cb_ops = {
	sysctrl_open,		/* open */
	sysctrl_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nulldev,		/* read */
	nulldev,		/* write */
	sysctrl_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_MP|D_NEW,		/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops sysctrl_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	sysctrl_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sysctrl_attach,		/* attach */
	sysctrl_detach,		/* detach */
	nulldev,		/* reset */
	&sysctrl_cb_ops,	/* cb_ops */
	(struct bus_ops *)0,	/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

void *sysctrlp;				/* sysctrl soft state hook */

/* # of ticks to silence spurious interrupts */
static clock_t spur_timeout_hz;

/* # of ticks to count spurious interrupts to print message */
static clock_t spur_long_timeout_hz;

/* # of ticks between AC failure polling */
static clock_t ac_timeout_hz;

/* # of ticks between Power Supply Failure polling */
static clock_t ps_fail_timeout_hz;

/*
 * # of ticks between Peripheral Power Supply failure polling
 * (used both for interrupt retry timeout and polling function)
 */
static clock_t pps_fan_timeout_hz;

/* # of ticks delay after board insert interrupt */
static clock_t bd_insert_delay_hz;

/* # of secs to wait before restarting poll if we cannot clear interrupts */
static clock_t bd_insert_retry_hz;

/* # of secs between Board Removal polling */
static clock_t bd_remove_timeout_hz;

/* # of secs between toggle of OS LED */
static clock_t blink_led_timeout_hz;

/* overtemp polling routine timeout delay */
static clock_t overtemp_timeout_hz;

/* key switch polling routine timeout delay */
static clock_t keyswitch_timeout_hz;

/* Specify which system interrupt condition to monitor */
int enable_sys_interrupt = SYS_AC_PWR_FAIL_EN | SYS_PPS_FAN_FAIL_EN |
			SYS_PS_FAIL_EN | SYS_SBRD_PRES_EN;

/* Should the overtemp_poll thread be running? */
static int sysctrl_do_overtemp_thread = 1;

/* Should the keyswitch_poll thread be running? */
static int sysctrl_do_keyswitch_thread = 1;

/*
 * This timeout ID is for board remove polling routine. It is
 * protected by the fhc_bdlist mutex.
 * XXX - This will not work for wildfire. A different scheme must be
 * used since there will be multiple sysctrl nodes, each with its
 * own list of hotplugged boards to scan.
 */
static timeout_id_t bd_remove_to_id = 0;

/*
 * If this is set, the system will not shutdown when insufficient power
 * condition persists.
 */
int disable_insufficient_power_reboot = 0;

/*
 * Set this to enable suspend/resume
 */
int sysctrl_enable_detach_suspend = 0;

/*
 * Set this to reflect the OBP initialized HOTPLUG_DISABLED_PROPERTY and
 * during dynamic detection
 */
int sysctrl_hotplug_disabled = FALSE;

/* Indicates whether or not the overtemp thread has been started */
static int sysctrl_overtemp_thread_started = 0;

/* Indicates whether or not the key switch thread has been started */
static int sysctrl_keyswitch_thread_started = 0;

/* *Mutex used to protect the soft state list */
static kmutex_t sslist_mutex;

/* The CV is used to wakeup the overtemp thread when needed. */
static kcondvar_t overtemp_cv;

/* The CV is used to wakeup the key switch thread when needed. */
static kcondvar_t keyswitch_cv;

/* This mutex is used to protect the sysctrl_ddi_branch_init variable */
static kmutex_t sysctrl_branch_mutex;

/*
 * This variable is set after all existing branches in the system have
 * been discovered and held via e_ddi_branch_hold(). This happens on
 * first open() of any sysctrl minor node.
 */
static int sysctrl_ddi_branch_init;

/*
 * Linked list of all syctrl soft state structures.
 * Used for polling sysctrl state changes, i.e. temperature.
 */
struct sysctrl_soft_state *sys_list = NULL;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Clock Board",		/* name of module */
	&sysctrl_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&sysctrlp,
	    sizeof (struct sysctrl_soft_state), 1)) != 0)
		return (error);

	error = mod_install(&modlinkage);
	if (error != 0) {
		ddi_soft_state_fini(&sysctrlp);
		return (error);
	}

	mutex_init(&sysctrl_branch_mutex, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ddi_soft_state_fini(&sysctrlp);

	mutex_destroy(&sysctrl_branch_mutex);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
sysctrl_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = GETINSTANCE(dev);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
sysctrl_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct sysctrl_soft_state *softsp;
	int instance;
	uchar_t tmp_reg;
	dev_info_t *dip;
	char *propval;
	int proplen;
	int slot_num;
	int start;		/* start index for scan loop */
	int limit;		/* board number limit for scan loop */
	int incr;		/* amount to incr each pass thru loop */
	void set_clockbrd_info(void);


	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/* XXX see sysctrl:DDI_SUSPEND for special h/w treatment */
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(sysctrlp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = GETSOFTC(instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	/* Set up the parent dip */
	softsp->pdip = ddi_get_parent(softsp->dip);

	DPRINTF(SYSCTRL_ATTACH_DEBUG, ("sysctrl: devi= 0x%p\n, softsp=0x%p\n",
	    (void *)devi, (void *)softsp));

	/* First set all of the timeout values */
	spur_timeout_hz = drv_usectohz(SPUR_TIMEOUT_USEC);
	spur_long_timeout_hz = drv_usectohz(SPUR_LONG_TIMEOUT_USEC);
	ac_timeout_hz = drv_usectohz(AC_TIMEOUT_USEC);
	ps_fail_timeout_hz = drv_usectohz(PS_FAIL_TIMEOUT_USEC);
	pps_fan_timeout_hz = drv_usectohz(PPS_FAN_TIMEOUT_USEC);
	bd_insert_delay_hz = drv_usectohz(BRD_INSERT_DELAY_USEC);
	bd_insert_retry_hz = drv_usectohz(BRD_INSERT_RETRY_USEC);
	bd_remove_timeout_hz = drv_usectohz(BRD_REMOVE_TIMEOUT_USEC);
	blink_led_timeout_hz = drv_usectohz(BLINK_LED_TIMEOUT_USEC);
	overtemp_timeout_hz = drv_usectohz(OVERTEMP_TIMEOUT_SEC * MICROSEC);
	keyswitch_timeout_hz = drv_usectohz(KEYSWITCH_TIMEOUT_USEC);

	/*
	 * Map in the registers sets that OBP hands us. According
	 * to the sun4u device tree spec., the register sets are as
	 * follows:
	 *
	 *	0	Clock Frequency Registers (contains the bit
	 *		for enabling the remote console reset)
	 *	1	Misc (has all the registers that we need
	 *	2	Clock Version Register
	 */
	if (ddi_map_regs(softsp->dip, 0,
	    (caddr_t *)&softsp->clk_freq1, 0, 0)) {
		cmn_err(CE_WARN, "sysctrl%d: unable to map clock frequency "
		    "registers", instance);
		goto bad0;
	}

	if (ddi_map_regs(softsp->dip, 1,
	    (caddr_t *)&softsp->csr, 0, 0)) {
		cmn_err(CE_WARN, "sysctrl%d: unable to map internal"
		    "registers", instance);
		goto bad1;
	}

	/*
	 * There is a new register for newer vintage clock board nodes,
	 * OBP register set 2 in the clock board node.
	 *
	 */
	(void) ddi_map_regs(softsp->dip, 2, (caddr_t *)&softsp->clk_ver, 0, 0);

	/*
	 * Fill in the virtual addresses of the registers in the
	 * sysctrl_soft_state structure. We do not want to calculate
	 * them on the fly. This way we waste a little memory, but
	 * avoid bugs down the road.
	 */
	softsp->clk_freq2 = (uchar_t *)((caddr_t)softsp->clk_freq1 +
	    SYS_OFF_CLK_FREQ2);

	softsp->status1 = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_STAT1);

	softsp->status2 = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_STAT2);

	softsp->ps_stat = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_PSSTAT);

	softsp->ps_pres = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_PSPRES);

	softsp->pppsr = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_PPPSR);

	softsp->temp_reg = (uchar_t *)((caddr_t)softsp->csr +
	    SYS_OFF_TEMP);

	set_clockbrd_info();

	/*
	 * Enable the hardware watchdog gate on the clock board if
	 * map_wellknown has detected that watchdog timer is available
	 * and user wants it to be enabled.
	 */
	if (watchdog_available && watchdog_enable)
		*(softsp->clk_freq2) |= TOD_RESET_EN;
	else
		*(softsp->clk_freq2) &= ~TOD_RESET_EN;

	/* Check for inherited faults from the PROM. */
	if (*softsp->csr & SYS_LED_MID) {
		reg_fault(0, FT_PROM, FT_SYSTEM);
	}

	/*
	 * calculate and cache the number of slots on this system
	 */
	switch (SYS_TYPE(*softsp->status1)) {
	case SYS_16_SLOT:
		softsp->nslots = 16;
		break;

	case SYS_8_SLOT:
		softsp->nslots = 8;
		break;

	case SYS_4_SLOT:
		/* check the clk_version register - if the ptr is valid */
		if ((softsp->clk_ver != NULL) &&
		    (SYS_TYPE2(*softsp->clk_ver) == SYS_PLUS_SYSTEM)) {
			softsp->nslots = 5;
		} else {
			softsp->nslots = 4;
		}
		break;

	case SYS_TESTBED:
	default:
		softsp->nslots = 0;
		break;
	}


	/* create the fault list kstat */
	create_ft_kstats(instance);

	/*
	 * Do a priming read on the ADC, and throw away the first value
	 * read. This is a feature of the ADC hardware. After a power cycle
	 * it does not contains valid data until a read occurs.
	 */
	tmp_reg = *(softsp->temp_reg);

	/* Wait 30 usec for ADC hardware to stabilize. */
	DELAY(30);

	/* shut off all interrupt sources */
	*(softsp->csr) &= ~(SYS_PPS_FAN_FAIL_EN | SYS_PS_FAIL_EN |
	    SYS_AC_PWR_FAIL_EN | SYS_SBRD_PRES_EN);
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif

	/*
	 * Now register our high interrupt with the system.
	 */
	if (ddi_add_intr(devi, 0, &softsp->iblock,
	    &softsp->idevice, (uint_t (*)(caddr_t))nulldev, NULL) !=
	    DDI_SUCCESS)
		goto bad2;

	mutex_init(&softsp->csr_mutex, NULL, MUTEX_DRIVER,
	    (void *)softsp->iblock);

	ddi_remove_intr(devi, 0, softsp->iblock);

	if (ddi_add_intr(devi, 0, &softsp->iblock,
	    &softsp->idevice, system_high_handler, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad3;

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->spur_id,
	    &softsp->spur_int_c, NULL, spur_delay, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad4;

	mutex_init(&softsp->spur_int_lock, NULL, MUTEX_DRIVER,
	    (void *)softsp->spur_int_c);


	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->spur_high_id,
	    NULL, NULL, spur_reenable, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad5;

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->spur_long_to_id,
	    NULL, NULL, spur_clear_count, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad6;

	/*
	 * Now register low-level ac fail handler
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_HIGH, &softsp->ac_fail_id,
	    NULL, NULL, ac_fail_handler, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad7;

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->ac_fail_high_id,
	    NULL, NULL, ac_fail_reenable, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad8;

	/*
	 * Now register low-level ps fail handler
	 */

	if (ddi_add_softintr(devi, DDI_SOFTINT_HIGH, &softsp->ps_fail_int_id,
	    &softsp->ps_fail_c, NULL, ps_fail_int_handler, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad9;

	mutex_init(&softsp->ps_fail_lock, NULL, MUTEX_DRIVER,
	    (void *)softsp->ps_fail_c);

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->ps_fail_poll_id,
	    NULL, NULL, ps_fail_poll_handler, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad10;

	/*
	 * Now register low-level pps fan fail handler
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->pps_fan_id,
	    NULL, NULL, pps_fanfail_handler, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad11;

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->pps_fan_high_id,
	    NULL, NULL, pps_fanfail_reenable, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad12;

	/*
	 * Based upon a check for a current share backplane, advise
	 * that system does not support hot plug
	 *
	 */
	if ((*(softsp->pppsr) & SYS_NOT_CURRENT_S) != 0) {
		cmn_err(CE_NOTE, "Hot Plug not supported in this system");
		sysctrl_hotplug_disabled = TRUE;
	}

	/*
	 * If the trigger circuit is busted or the NOT_BRD_PRES line
	 * is stuck then OBP will publish this property stating that
	 * hot plug is not available.  If this happens we will complain
	 * to the console and register a system fault.  We will also
	 * not enable the board insert interrupt for this session.
	 */
	if (ddi_prop_op(DDI_DEV_T_ANY, softsp->dip, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, HOTPLUG_DISABLED_PROPERTY,
	    (caddr_t)&propval, &proplen) == DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "Hot Plug Unavailable [%s]", propval);
		reg_fault(0, FT_HOT_PLUG, FT_SYSTEM);
		sysctrl_hotplug_disabled = TRUE;
		enable_sys_interrupt &= ~SYS_SBRD_PRES_EN;
		kmem_free(propval, proplen);
	}

	sysc_board_connect_supported_init();

	fhc_bd_sc_register(sysc_policy_update, softsp);

	sysc_slot_info(softsp->nslots, &start, &limit, &incr);

	/* Prime the board list. */
	fhc_bdlist_prime(start, limit, incr);

	/*
	 * Set up a board remove timeout call.
	 */
	(void) fhc_bdlist_lock(-1);

	DPRINTF(SYSCTRL_ATTACH_DEBUG,
	    ("attach: start bd_remove_poll()..."));

	bd_remove_poll(softsp);
	fhc_bdlist_unlock();

	/*
	 * Now register low-level board insert handler
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->sbrd_pres_id,
	    NULL, NULL, bd_insert_handler, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad13;

	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->sbrd_gone_id,
	    NULL, NULL, bd_insert_normal, (caddr_t)softsp) != DDI_SUCCESS)
		goto bad14;

	/*
	 * Now register led blink handler (interrupt level)
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_LOW, &softsp->blink_led_id,
	    &softsp->sys_led_c, NULL, blink_led_handler, (caddr_t)softsp) !=
	    DDI_SUCCESS)
		goto bad15;
	mutex_init(&softsp->sys_led_lock, NULL, MUTEX_DRIVER,
	    (void *)softsp->sys_led_c);

	/* initialize the bit field for all pps fans to assumed good */
	softsp->pps_fan_saved = softsp->pps_fan_external_state =
	    SYS_AC_FAN_OK | SYS_KEYSW_FAN_OK;

	/* prime the power supply state machines */
	if (enable_sys_interrupt & SYS_PS_FAIL_EN)
		ddi_trigger_softintr(softsp->ps_fail_poll_id);


	/* kick off the OS led blinker */
	softsp->sys_led = FALSE;
	ddi_trigger_softintr(softsp->blink_led_id);

	/* Now enable selected interrupt sources */
	mutex_enter(&softsp->csr_mutex);
	*(softsp->csr) |= enable_sys_interrupt &
	    (SYS_AC_PWR_FAIL_EN | SYS_PS_FAIL_EN |
	    SYS_PPS_FAN_FAIL_EN | SYS_SBRD_PRES_EN);
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif
	mutex_exit(&softsp->csr_mutex);

	/* Initialize the temperature */
	init_temp_arrays(&softsp->tempstat);

	/*
	 * initialize key switch shadow state
	 */
	softsp->key_shadow = KEY_BOOT;

	/*
	 * Now add this soft state structure to the front of the linked list
	 * of soft state structures.
	 */
	if (sys_list == (struct sysctrl_soft_state *)NULL) {
		mutex_init(&sslist_mutex, NULL, MUTEX_DEFAULT, NULL);
	}
	mutex_enter(&sslist_mutex);
	softsp->next = sys_list;
	sys_list = softsp;
	mutex_exit(&sslist_mutex);

	/* Setup the kstats for this device */
	sysctrl_add_kstats(softsp);

	/* kick off the PPS fan poll routine */
	pps_fan_poll(softsp);

	if (sysctrl_overtemp_thread_started == 0) {
		/*
		 * set up the overtemp condition variable before
		 * starting the thread.
		 */
		cv_init(&overtemp_cv, NULL, CV_DRIVER, NULL);

		/*
		 * start up the overtemp polling thread
		 */
		(void) thread_create(NULL, 0, (void (*)())sysctrl_overtemp_poll,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
		sysctrl_overtemp_thread_started++;
	}

	if (sysctrl_keyswitch_thread_started == 0) {
		extern void (*abort_seq_handler)();

		/*
		 * interpose sysctrl's abort sequence handler
		 */
		abort_seq_handler = sysctrl_abort_seq_handler;

		/*
		 * set up the key switch condition variable before
		 * starting the thread
		 */
		cv_init(&keyswitch_cv, NULL, CV_DRIVER, NULL);

		/*
		 * start up the key switch polling thread
		 */
		(void) thread_create(NULL, 0,
		    (void (*)())sysctrl_keyswitch_poll, NULL, 0, &p0,
		    TS_RUN, minclsyspri);
		sysctrl_keyswitch_thread_started++;
	}

	/*
	 * perform initialization to allow setting of powerfail-time
	 */
	if ((dip = ddi_find_devinfo("options", -1, 0)) == NULL)
		softsp->options_nodeid = (pnode_t)0;
	else
		softsp->options_nodeid = (pnode_t)ddi_get_nodeid(dip);

	DPRINTF(SYSCTRL_ATTACH_DEBUG,
	    ("sysctrl: Creating devices start:%d, limit:%d, incr:%d\n",
	    start, limit, incr));

	/*
	 * Create minor node for each system attachment points
	 */
	for (slot_num = start; slot_num < limit; slot_num = slot_num + incr) {
		char name[30];
		(void) sprintf(name, "slot%d", slot_num);
		if (ddi_create_minor_node(devi, name, S_IFCHR,
		    (PUTINSTANCE(instance) | slot_num),
		    DDI_NT_ATTACHMENT_POINT, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "sysctrl%d: \"%s\" "
			    "ddi_create_minor_node failed",
			    instance, name);
			goto bad16;
		}
	}

	ddi_report_dev(devi);

	/*
	 * Remote console is inherited from POST
	 */
	if ((*(softsp->clk_freq2) & RCONS_UART_EN) == 0) {
		softsp->enable_rcons_atboot = FALSE;
		cmn_err(CE_WARN, "Remote console not active");
	} else
		softsp->enable_rcons_atboot = TRUE;

	return (DDI_SUCCESS);

bad16:
	cv_destroy(&keyswitch_cv);
	cv_destroy(&overtemp_cv);
	mutex_destroy(&sslist_mutex);
	mutex_destroy(&softsp->sys_led_lock);
	ddi_remove_softintr(softsp->blink_led_id);
bad15:
	ddi_remove_softintr(softsp->sbrd_gone_id);
bad14:
	ddi_remove_softintr(softsp->sbrd_pres_id);
bad13:
	ddi_remove_softintr(softsp->pps_fan_high_id);
bad12:
	ddi_remove_softintr(softsp->pps_fan_id);
bad11:
	ddi_remove_softintr(softsp->ps_fail_poll_id);
bad10:
	mutex_destroy(&softsp->ps_fail_lock);
	ddi_remove_softintr(softsp->ps_fail_int_id);
bad9:
	ddi_remove_softintr(softsp->ac_fail_high_id);
bad8:
	ddi_remove_softintr(softsp->ac_fail_id);
bad7:
	ddi_remove_softintr(softsp->spur_long_to_id);
bad6:
	ddi_remove_softintr(softsp->spur_high_id);
bad5:
	mutex_destroy(&softsp->spur_int_lock);
	ddi_remove_softintr(softsp->spur_id);
bad4:
	ddi_remove_intr(devi, 0, softsp->iblock);
bad3:
	mutex_destroy(&softsp->csr_mutex);
bad2:
	ddi_unmap_regs(softsp->dip, 1, (caddr_t *)&softsp->csr, 0, 0);
	if (softsp->clk_ver != NULL)
		ddi_unmap_regs(softsp->dip, 2, (caddr_t *)&softsp->clk_ver,
		    0, 0);
bad1:
	ddi_unmap_regs(softsp->dip, 0, (caddr_t *)&softsp->clk_freq1, 0, 0);

bad0:
	ddi_soft_state_free(sysctrlp, instance);
	ddi_remove_minor_node(dip, NULL);
	cmn_err(CE_WARN,
	    "sysctrl%d: Initialization failure. Some system level events,"
	    " {AC Fail, Fan Failure, PS Failure} not detected", instance);
	return (DDI_FAILURE);
}

struct sysc_hold {
	int start;
	int limit;
	int incr;
	int hold;
};

static int
sysctrl_hold_rele_branches(dev_info_t *dip, void *arg)
{
	int *rp, len, slot, i;
	struct sysc_hold *ap = (struct sysc_hold *)arg;

	/*
	 * For Sunfire, top nodes on board are always children of root dip
	 */
	ASSERT(ddi_get_parent(dip) == ddi_root_node());

	/*
	 * Skip non-PROM and "central" nodes
	 */
	if (!ndi_dev_is_prom_node(dip) ||
	    strcmp(ddi_node_name(dip), "central") == 0)
		return (DDI_WALK_PRUNECHILD);

	/*
	 * Extract board # from reg property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "reg", (caddr_t)&rp, &len)
	    != DDI_SUCCESS) {
		DPRINTF(SYSC_DEBUG, ("devinfo node %s(%p) has no reg"
		    " property\n", ddi_node_name(dip), (void *)dip));
		return (DDI_WALK_PRUNECHILD);
	}

	slot = (*rp - 0x1c0) >> 2;
	kmem_free(rp, len);

	ASSERT(ap->start >= 0 && ap->start < ap->limit);

	for (i = ap->start; i < ap->limit; i = i + ap->incr) {
		if (i == slot)
			break;
	}

	if (i >= ap->limit) {
		DPRINTF(SYSC_DEBUG, ("sysctrl_hold_rele: Invalid board # (%d)"
		    " for node %s(%p)\n", slot, ddi_node_name(dip),
		    (void *)dip));
		return (DDI_WALK_PRUNECHILD);
	}

	if (ap->hold) {
		ASSERT(!e_ddi_branch_held(dip));
		e_ddi_branch_hold(dip);
	} else {
		ASSERT(e_ddi_branch_held(dip));
		e_ddi_branch_rele(dip);
	}

	return (DDI_WALK_PRUNECHILD);
}

/* ARGSUSED */
static int
sysctrl_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
#ifdef	SYSCTRL_SUPPORTS_DETACH
	dev_info_t			*rdip;
	struct sysc_hold		arg = {0};
	struct sysctrl_soft_state	*softsp;
#endif	/* SYSCTRL_SUPPORTS_DETACH */

	if (sysctrl_enable_detach_suspend == FALSE)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_SUSPEND:
		/*
		 * XXX we don't presently save the state of the remote
		 * console because it is a constant function of POST.
		 * XXX we don't deal with the hardware watchdog here
		 * either.  It should be handled in hardclk.
		 */
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

#ifdef	SYSCTRL_SUPPORTS_DETACH

	/*
	 * XXX If sysctrl ever supports detach, this code should be enabled
	 * This is only the portion of the detach code dealing with
	 * the DDI branch routines. Other parts of detach will need
	 * to be added.
	 */

	/*
	 * Walk immediate children of root devinfo node, releasing holds
	 * on branches acquired in first sysctrl_open().
	 */

	instance = ddi_get_instance(dip);
	softsp = GETSOFTC(instance);

	if (softsp == NULL) {
		cmn_err(CE_WARN, "sysctrl%d device not attached", instance);
		return (DDI_FAILURE);
	}

	sysc_slot_info(softsp->nslots, &arg.start, &arg.limit, &arg.incr);

	arg.hold = 0;

	rdip = ddi_root_node();

	ndi_devi_enter(rdip, &circ);
	ddi_walk_devs(ddi_get_child(rdip), sysctrl_hold_rele_branches, &arg);
	ndi_devi_exit(rdip, circ);

	sysctrl_ddi_branch_init = 0;

	return (DDI_SUCCESS);
#endif	/* SYSCTRL_SUPPORTS_DETACH */

	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
sysctrl_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int		instance;
	int		slot;
	dev_t		dev;
	int		circ;
	dev_info_t	*rdip;
	struct sysc_hold arg = {0};
	struct sysctrl_soft_state *softsp;

	dev = *devp;

	/*
	 * We checked against the instance softstate structure since there
	 * will only be one instance of sysctrl (clock board) in UEXX00
	 *
	 * Since we only create minor devices for existing slots on a
	 * particular system, we don't need to worry about non-exist slot.
	 */

	instance = GETINSTANCE(dev);
	slot = GETSLOT(dev);

	/* Is the instance attached? */
	if ((softsp = GETSOFTC(instance)) == NULL) {
		cmn_err(CE_WARN, "sysctrl%d device not attached", instance);
		return (ENXIO);
	}

	/* verify that otyp is appropriate */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	if (!fhc_bd_valid(slot))
		return (ENXIO);

	/*
	 * On first open of a sysctrl minor walk immediate children of the
	 * devinfo root node and hold all branches of interest.
	 */
	mutex_enter(&sysctrl_branch_mutex);
	if (!sysctrl_ddi_branch_init) {

		sysctrl_ddi_branch_init = 1;

		sysc_slot_info(softsp->nslots, &arg.start, &arg.limit,
		    &arg.incr);
		arg.hold = 1;

		rdip = ddi_root_node();

		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), sysctrl_hold_rele_branches,
		    &arg);
		ndi_devi_exit(rdip, circ);
	}
	mutex_exit(&sysctrl_branch_mutex);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sysctrl_close(dev_t devp, int flag, int otyp, cred_t *credp)
{
	return (DDI_SUCCESS);
}

/*
 * This function will acquire the lock and set the in_transition
 * bit for the specified slot.  If the slot is being used,
 * we return FALSE; else set in_transition and return TRUE.
 */
static int
sysc_enter_transition(int slot)
{
	fhc_bd_t	*list;
	sysc_cfga_stat_t *sysc_stat_lk;
	fhc_bd_t	*glist;
	sysc_cfga_stat_t *sysc_stat_gk;

	/* mutex lock the structure */
	list = fhc_bdlist_lock(slot);
	if ((slot != -1) && (list == NULL)) {
		fhc_bdlist_unlock();
		return (FALSE);
	}

	glist = fhc_bd_clock();
	if (slot == -1)
		list = glist;

	/* change the in_transition bit */
	sysc_stat_lk = &list->sc;
	sysc_stat_gk = &glist->sc;
	if ((sysc_stat_lk->in_transition == TRUE) ||
	    (sysc_stat_gk->in_transition == TRUE)) {
		fhc_bdlist_unlock();
		return (FALSE);
	} else {
		sysc_stat_lk->in_transition = TRUE;
		return (TRUE);
	}
}

/*
 * This function will release the lock and clear the in_transition
 * bit for the specified slot.
 */
static void
sysc_exit_transition(int slot)
{
	fhc_bd_t	*list;
	sysc_cfga_stat_t *sysc_stat_lk;

	ASSERT(fhc_bdlist_locked());

	if (slot == -1)
		list = fhc_bd_clock();
	else
		list = fhc_bd(slot);
	sysc_stat_lk = &list->sc;
	ASSERT(sysc_stat_lk->in_transition == TRUE);
	sysc_stat_lk->in_transition = FALSE;
	fhc_bdlist_unlock();
}

static int
sysc_pkt_init(sysc_cfga_pkt_t *pkt, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {
		sysc_cfga_cmd32_t sysc_cmd32;

		if (ddi_copyin((void *)arg, &sysc_cmd32,
		    sizeof (sysc_cfga_cmd32_t), flag) != 0) {
			return (EFAULT);
		}
		pkt->cmd_cfga.force = sysc_cmd32.force;
		pkt->cmd_cfga.test = sysc_cmd32.test;
		pkt->cmd_cfga.arg = sysc_cmd32.arg;
		pkt->cmd_cfga.errtype = sysc_cmd32.errtype;
		pkt->cmd_cfga.outputstr =
		    (char *)(uintptr_t)sysc_cmd32.outputstr;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &(pkt->cmd_cfga),
	    sizeof (sysc_cfga_cmd_t), flag) != 0) {
		return (EFAULT);
	}
	pkt->errbuf = kmem_zalloc(SYSC_OUTPUT_LEN, KM_SLEEP);
	return (0);
}

static int
sysc_pkt_fini(sysc_cfga_pkt_t *pkt, intptr_t arg, int flag)
{
	int ret = TRUE;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {

		if (ddi_copyout(&(pkt->cmd_cfga.errtype),
		    (void *)&(((sysc_cfga_cmd32_t *)arg)->errtype),
		    sizeof (sysc_err_t), flag) != 0) {
			ret = FALSE;
		}
	} else
#endif
	if (ddi_copyout(&(pkt->cmd_cfga.errtype),
	    (void *)&(((sysc_cfga_cmd_t *)arg)->errtype),
	    sizeof (sysc_err_t), flag) != 0) {
		ret = FALSE;
	}

	if ((ret != FALSE) && ((pkt->cmd_cfga.outputstr != NULL) &&
	    (ddi_copyout(pkt->errbuf, pkt->cmd_cfga.outputstr,
	    SYSC_OUTPUT_LEN, flag) != 0))) {
			ret = FALSE;
	}

	kmem_free(pkt->errbuf, SYSC_OUTPUT_LEN);
	return (ret);
}

/* ARGSUSED */
static int
sysctrl_ioctl(dev_t devt, int cmd, intptr_t arg, int flag, cred_t *cred_p,
    int *rval_p)
{
	struct sysctrl_soft_state *softsp;
	sysc_cfga_pkt_t sysc_pkt;
	fhc_bd_t *fhc_list = NULL;
	sysc_cfga_stat_t *sc_list = NULL;
	fhc_bd_t *bdp;
	sysc_cfga_stat_t *sc = NULL;
	int instance;
	int slot;
	int retval = 0;
	int i;

	instance = GETINSTANCE(devt);
	softsp = GETSOFTC(instance);
	if (softsp == NULL) {
		cmn_err(CE_CONT,
		    "sysctrl_ioctl(%d): NULL softstate ptr!\n",
		    (int)GETSLOT(devt));
		return (ENXIO);
	}

	slot = GETSLOT(devt);

	/*
	 * First switch is to do correct locking and do ddi_copyin()
	 */
	switch (cmd) {
	case SYSC_CFGA_CMD_GETSTATUS:
		/* mutex lock the whole list */
		if (sysc_enter_transition(-1) != TRUE) {
			retval = EBUSY;
			goto cleanup_exit;
		}

		/* allocate the memory before acquiring mutex */
		fhc_list = kmem_zalloc(sizeof (fhc_bd_t) * fhc_max_boards(),
		    KM_SLEEP);

		sc_list = kmem_zalloc(sizeof (sysc_cfga_stat_t) *
		    fhc_max_boards(), KM_SLEEP);

		break;

	case SYSC_CFGA_CMD_EJECT:
	case SYSC_CFGA_CMD_INSERT:
		retval = ENOTSUP;
		goto cleanup_exit;

	case SYSC_CFGA_CMD_CONNECT:
	case SYSC_CFGA_CMD_DISCONNECT:
	case SYSC_CFGA_CMD_UNCONFIGURE:
	case SYSC_CFGA_CMD_CONFIGURE:
	case SYSC_CFGA_CMD_TEST:
	case SYSC_CFGA_CMD_TEST_SET_COND:
	case SYSC_CFGA_CMD_QUIESCE_TEST:

		/* ioctls allowed if caller has write permission */
		if (!(flag & FWRITE)) {
			retval = EPERM;
			goto cleanup_exit;
		}

		retval = sysc_pkt_init(&sysc_pkt, arg, flag);
		if (retval != 0)
			goto cleanup_exit;

		/* grasp lock and set in_transition bit */
		if (sysc_enter_transition(cmd == SYSC_CFGA_CMD_QUIESCE_TEST
		    ? -1 : slot) != TRUE) {
			retval = EBUSY;
			SYSC_ERR_SET(&sysc_pkt, SYSC_ERR_INTRANS);
			goto cleanup_copyout;
		}

		/* get the status structure for the slot */
		bdp = fhc_bd(slot);
		sc = &bdp->sc;
		break;

	/* POSIX definition: return ENOTTY if unsupported command */
	default:
		retval = ENOTTY;
		goto cleanup_exit;
	}

	/*
	 * Second switch is to call the underlayer workhorse.
	 */
	switch (cmd) {
	case SYSC_CFGA_CMD_GETSTATUS:
		for (i = 0; i < fhc_max_boards(); i++) {
			if (fhc_bd_valid(i)) {
				bdp = fhc_bd(i);
				if (fhc_bd_is_jtag_master(i))
					bdp->sc.no_detach = 1;
				else
					bdp->sc.no_detach = 0;
				bcopy((caddr_t)&bdp->sc,
				    &sc_list[i], sizeof (sysc_cfga_stat_t));
			} else {
				sc_list[i].board = -1;
				sc_list[i].rstate = SYSC_CFGA_RSTATE_EMPTY;
			}
		}

		sysc_exit_transition(-1);

		break;

	case SYSC_CFGA_CMD_EJECT:
	case SYSC_CFGA_CMD_INSERT:
		retval = ENOTSUP;
		goto cleanup_exit;

	case SYSC_CFGA_CMD_CONNECT:
		retval = sysc_policy_connect(softsp, &sysc_pkt, sc);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_DISCONNECT:
		retval = sysc_policy_disconnect(softsp, &sysc_pkt, sc);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_UNCONFIGURE:
		retval = sysc_policy_unconfigure(softsp, &sysc_pkt, sc);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_CONFIGURE:
		retval = sysc_policy_configure(softsp, &sysc_pkt, sc);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_TEST:
		retval = fhc_bd_test(slot, &sysc_pkt);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_TEST_SET_COND:
		retval = fhc_bd_test_set_cond(slot, &sysc_pkt);
		sysc_exit_transition(slot);
		break;

	case SYSC_CFGA_CMD_QUIESCE_TEST:
		sysctrl_suspend_prepare();
		fhc_bdlist_unlock();

		if (sysctrl_suspend(&sysc_pkt) == DDI_SUCCESS) {
			sysctrl_resume(&sysc_pkt);
		} else {
			retval = EBUSY;
		}

		(void) fhc_bdlist_lock(-1);
		sysc_exit_transition(-1);
		break;

	default:
		retval = ENOTTY;
		goto cleanup_exit;
	}

cleanup_copyout:
	/*
	 * 3rd switch is to do appropriate copyout and reset locks
	 */
	switch (cmd) {
	case SYSC_CFGA_CMD_GETSTATUS:
		if (ddi_copyout(sc_list, (void *)arg,
		    sizeof (sysc_cfga_stat_t) * fhc_max_boards(),
		    flag) != 0) {
			retval = EFAULT;
		}

		/* cleanup memory */
		kmem_free(fhc_list, sizeof (fhc_bd_t) * fhc_max_boards());
		kmem_free(sc_list, sizeof (sysc_cfga_stat_t) *
		    fhc_max_boards());
		break;

	case SYSC_CFGA_CMD_EJECT:
	case SYSC_CFGA_CMD_INSERT:
		retval = ENOTSUP;
		break;

	case SYSC_CFGA_CMD_CONNECT:
	case SYSC_CFGA_CMD_DISCONNECT:
	case SYSC_CFGA_CMD_UNCONFIGURE:
	case SYSC_CFGA_CMD_CONFIGURE:
	case SYSC_CFGA_CMD_TEST:
	case SYSC_CFGA_CMD_TEST_SET_COND:
	case SYSC_CFGA_CMD_QUIESCE_TEST:
		if (sysc_pkt_fini(&sysc_pkt, arg, flag) != TRUE)
			return (EFAULT);
		break;

	default:
		retval = ENOTTY;
		break;
	}

cleanup_exit:
	return (retval);
}

/*
 * system_high_handler()
 * This routine handles system interrupts.
 *
 * This routine goes through all the interrupt sources and masks
 * off the enable bit if interrupting.  Because of the special
 * nature of the pps fan source bits, we also cache the state
 * of the fan bits for that special case.
 *
 * The rest of the work is done in the low level handlers
 */
static uint_t
system_high_handler(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t csr;
	uchar_t status2;
	uchar_t tmp_reg;
	int serviced = 0;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);

	/* read in the hardware registers */
	csr = *(softsp->csr);
	status2 = *(softsp->status2);

	if (csr & SYS_AC_PWR_FAIL_EN) {
		if (status2 & SYS_AC_FAIL) {

			/* save the powerfail state in nvram */
			nvram_update_powerfail(softsp);

			/* disable this interrupt source */
			csr &= ~SYS_AC_PWR_FAIL_EN;

			ddi_trigger_softintr(softsp->ac_fail_id);
			serviced++;
		}
	}

	if (csr & SYS_PS_FAIL_EN) {
		if ((*(softsp->ps_stat) != 0xff) ||
		    ((~status2) & (SYS_PPS0_OK | SYS_CLK_33_OK |
		    SYS_CLK_50_OK)) ||
		    (~(*(softsp->pppsr)) & SYS_PPPSR_BITS)) {

			/* disable this interrupt source */
			csr &= ~SYS_PS_FAIL_EN;

			ddi_trigger_softintr(softsp->ps_fail_int_id);
			serviced++;
		}
	}

	if (csr & SYS_PPS_FAN_FAIL_EN) {
		if (status2 & SYS_RACK_FANFAIL ||
		    !(status2 & SYS_AC_FAN_OK) ||
		    !(status2 & SYS_KEYSW_FAN_OK)) {

			/*
			 * we must cache the fan status because it goes
			 * away when we disable interrupts !?!?!
			 */
			softsp->pps_fan_saved = status2;

			/* disable this interrupt source */
			csr &= ~SYS_PPS_FAN_FAIL_EN;

			ddi_trigger_softintr(softsp->pps_fan_id);
			serviced++;
		}
	}

	if (csr & SYS_SBRD_PRES_EN) {
		if (!(*(softsp->status1) & SYS_NOT_BRD_PRES)) {

			/* disable this interrupt source */
			csr &= ~SYS_SBRD_PRES_EN;

			ddi_trigger_softintr(softsp->sbrd_pres_id);
			serviced++;
		}
	}

	if (!serviced) {

		/*
		 * if we get here than it is likely that contact bounce
		 * is messing with us.  so, we need to shut this interrupt
		 * up for a while to let the contacts settle down.
		 * Then we will re-enable the interrupts that are enabled
		 * right now.  The trick is to disable the appropriate
		 * interrupts and then to re-enable them correctly, even
		 * though intervening handlers might have been working.
		 */

		/* remember all interrupts that could have caused it */
		softsp->saved_en_state |= csr &
		    (SYS_AC_PWR_FAIL_EN | SYS_PS_FAIL_EN |
		    SYS_PPS_FAN_FAIL_EN | SYS_SBRD_PRES_EN);

		/* and then turn them off */
		csr &= ~(SYS_AC_PWR_FAIL_EN | SYS_PS_FAIL_EN |
		    SYS_PPS_FAN_FAIL_EN | SYS_SBRD_PRES_EN);

		/* and then bump the counter */
		softsp->spur_count++;

		/* and kick off the timeout */
		ddi_trigger_softintr(softsp->spur_id);
	}

	/* update the real csr */
	*(softsp->csr) = csr;
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif
	mutex_exit(&softsp->csr_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * we've detected a spurious interrupt.
 * determine if we should log a message and if we need another timeout
 */
static uint_t
spur_delay(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;

	ASSERT(softsp);

	/* do we need to complain? */
	mutex_enter(&softsp->csr_mutex);

	/* NOTE: this is == because we want one message per long timeout */
	if (softsp->spur_count == MAX_SPUR_COUNT) {
		char buf[128];

		/* print out the candidates known at this time */
		/* XXX not perfect because of re-entrant nature but close */
		buf[0] = '\0';
		if (softsp->saved_en_state & SYS_AC_PWR_FAIL_EN)
			(void) strcat(buf, "AC FAIL");
		if (softsp->saved_en_state & SYS_PPS_FAN_FAIL_EN)
			(void) strcat(buf, buf[0] ? "|PPS FANS" : "PPS FANS");
		if (softsp->saved_en_state & SYS_PS_FAIL_EN)
			(void) strcat(buf, buf[0] ? "|PS FAIL" : "PS FAIL");
		if (softsp->saved_en_state & SYS_SBRD_PRES_EN)
			(void) strcat(buf,
			    buf[0] ? "|BOARD INSERT" : "BOARD INSERT");

		/*
		 * This is a high level mutex, therefore it needs to be
		 * dropped before calling cmn_err.
		 */
		mutex_exit(&softsp->csr_mutex);

		cmn_err(CE_WARN, "sysctrl%d: unserviced interrupt."
		    " possible sources [%s].",
		    ddi_get_instance(softsp->dip), buf);
	} else
		mutex_exit(&softsp->csr_mutex);

	mutex_enter(&softsp->spur_int_lock);

	/* do we need to start the short timeout? */
	if (softsp->spur_timeout_id == 0) {
		softsp->spur_timeout_id = timeout(spur_retry, softsp,
		    spur_timeout_hz);
	}

	/* do we need to start the long timeout? */
	if (softsp->spur_long_timeout_id == 0) {
		softsp->spur_long_timeout_id = timeout(spur_long_timeout,
		    softsp, spur_long_timeout_hz);
	}

	mutex_exit(&softsp->spur_int_lock);

	return (DDI_INTR_CLAIMED);
}

/*
 * spur_retry
 *
 * this routine simply triggers the interrupt which will re-enable
 * the interrupts disabled by the spurious int detection.
 */
static void
spur_retry(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;

	ASSERT(softsp);

	ddi_trigger_softintr(softsp->spur_high_id);

	mutex_enter(&softsp->spur_int_lock);
	softsp->spur_timeout_id = 0;
	mutex_exit(&softsp->spur_int_lock);
}

/*
 * spur_reenable
 *
 * OK, we've been slient for a while.   Go ahead and re-enable the
 * interrupts that were enabled at the time of the spurious detection.
 */
static uint_t
spur_reenable(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t tmp_reg;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);

	/* reenable those who were spurious candidates */
	*(softsp->csr) |= softsp->saved_en_state &
	    (SYS_AC_PWR_FAIL_EN | SYS_PS_FAIL_EN |
	    SYS_PPS_FAN_FAIL_EN | SYS_SBRD_PRES_EN);
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif

	/* clear out the saved state */
	softsp->saved_en_state = 0;

	mutex_exit(&softsp->csr_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * spur_long_timeout
 *
 * this routine merely resets the spurious interrupt counter thus ending
 * the interval of interest.  of course this is done by triggering a
 * softint because the counter is protected by an interrupt mutex.
 */
static void
spur_long_timeout(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;

	ASSERT(softsp);

	ddi_trigger_softintr(softsp->spur_long_to_id);

	mutex_enter(&softsp->spur_int_lock);
	softsp->spur_long_timeout_id = 0;
	mutex_exit(&softsp->spur_int_lock);
}

/*
 * spur_clear_count
 *
 * simply clear out the spurious interrupt counter.
 *
 * softint level only
 */
static uint_t
spur_clear_count(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);
	softsp->spur_count = 0;
	mutex_exit(&softsp->csr_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * ac_fail_handler
 *
 * This routine polls the AC power failure bit in the system status2
 * register.  If we get to this routine, then we sensed an ac fail
 * condition.  Note the fact and check again in a few.
 *
 * Called as softint from high interrupt.
 */
static uint_t
ac_fail_handler(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;

	ASSERT(softsp);

	cmn_err(CE_WARN, "%s failure detected", ft_str_table[FT_AC_PWR]);
	reg_fault(0, FT_AC_PWR, FT_SYSTEM);
	(void) timeout(ac_fail_retry, softsp, ac_timeout_hz);

	return (DDI_INTR_CLAIMED);
}

/*
 * The timeout from ac_fail_handler() that checks to see if the
 * condition persists.
 */
static void
ac_fail_retry(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;

	ASSERT(softsp);

	if (*softsp->status2 & SYS_AC_FAIL) {	/* still bad? */
		(void) timeout(ac_fail_retry, softsp, ac_timeout_hz);
	} else {
		cmn_err(CE_NOTE, "%s failure no longer detected",
		    ft_str_table[FT_AC_PWR]);
		clear_fault(0, FT_AC_PWR, FT_SYSTEM);
		ddi_trigger_softintr(softsp->ac_fail_high_id);
	}
}

/*
 * The interrupt routine that we use to re-enable the interrupt.
 * Called from ddi_trigger_softint() in the ac_fail_retry() when
 * the AC is better.
 */
static uint_t
ac_fail_reenable(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t tmp_reg;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);
	*(softsp->csr) |= SYS_AC_PWR_FAIL_EN;
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif
	mutex_exit(&softsp->csr_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * ps_fail_int_handler
 *
 * Handle power supply failure interrupt.
 *
 * This wrapper is called as softint from hardware interrupt routine.
 */
static uint_t
ps_fail_int_handler(caddr_t arg)
{
	return (ps_fail_handler((struct sysctrl_soft_state *)arg, 1));
}

/*
 * ps_fail_poll_handler
 *
 * Handle power supply failure interrupt.
 *
 * This wrapper is called as softint from power supply poll routine.
 */
static uint_t
ps_fail_poll_handler(caddr_t arg)
{
	return (ps_fail_handler((struct sysctrl_soft_state *)arg, 0));
}

/*
 * ps_fail_handler
 *
 * This routine checks all eight of the board power supplies that are
 * installed plus the Peripheral power supply and the two DC OK. Since the
 * hardware bits are not enough to indicate Power Supply failure
 * vs. being turned off via software, the driver must maintain a
 * shadow state for the Power Supply status and monitor all changes.
 *
 * Called as a softint only.
 */
static uint_t
ps_fail_handler(struct sysctrl_soft_state *softsp, int fromint)
{
	int i;
	struct ps_state *pstatp;
	int poll_needed = 0;
	uchar_t ps_stat, ps_pres, status1, status2, pppsr;
	uchar_t tmp_reg;
	enum power_state current_power_state;

	ASSERT(softsp);

	/* pre-read the hardware state */
	ps_stat = *softsp->ps_stat;
	ps_pres = *softsp->ps_pres;
	status1 = *softsp->status1;
	status2 = *softsp->status2;
	pppsr	= *softsp->pppsr;

	(void) fhc_bdlist_lock(-1);

	mutex_enter(&softsp->ps_fail_lock);

	for (i = 0, pstatp = &softsp->ps_stats[0]; i < SYS_PS_COUNT;
	    i++, pstatp++) {
		int	temp_psok;
		int	temp_pres;
		int	is_precharge = FALSE;
		int	is_fan_assy = FALSE;

		/*
		 * pre-compute the presence and ok bits for this
		 * power supply from the hardware registers.
		 * NOTE: 4-slot pps1 is the same as core ps 7...
		 */
		switch (i) {
		/* the core power supplies */
		case 0: case 1: case 2: case 3:
		case 4: case 5: case 6: case 7:
			temp_pres = !((ps_pres >> i) & 0x1);
			temp_psok = (ps_stat >> i) & 0x1;
			break;

		/* the first peripheral power supply */
		case SYS_PPS0_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = status2 & SYS_PPS0_OK;
			break;

		/* shared 3.3v clock power */
		case SYS_CLK_33_INDEX:
			temp_pres = TRUE;
			temp_psok = status2 & SYS_CLK_33_OK;
			break;

		/* shared 5.0v clock power */
		case SYS_CLK_50_INDEX:
			temp_pres = TRUE;
			temp_psok = status2 & SYS_CLK_50_OK;
			break;

		/* peripheral 5v */
		case SYS_V5_P_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES) ||
			    ((IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) &&
			    !(ps_pres & SYS_NOT_PPS1_PRES));
			temp_psok = pppsr & SYS_V5_P_OK;
			break;

		/* peripheral 12v */
		case SYS_V12_P_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES) ||
			    ((IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) &&
			    !(ps_pres & SYS_NOT_PPS1_PRES));
			temp_psok = pppsr & SYS_V12_P_OK;
			break;

		/* aux 5v */
		case SYS_V5_AUX_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = pppsr & SYS_V5_AUX_OK;
			break;

		/* peripheral 5v precharge */
		case SYS_V5_P_PCH_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = pppsr & SYS_V5_P_PCH_OK;
			is_precharge = TRUE;
			break;

		/* peripheral 12v precharge */
		case SYS_V12_P_PCH_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = pppsr & SYS_V12_P_PCH_OK;
			is_precharge = TRUE;
			break;

		/* 3.3v precharge */
		case SYS_V3_PCH_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = pppsr & SYS_V3_PCH_OK;
			is_precharge = TRUE;
			break;

		/* 5v precharge */
		case SYS_V5_PCH_INDEX:
			temp_pres = !(status1 & SYS_NOT_PPS0_PRES);
			temp_psok = pppsr & SYS_V5_PCH_OK;
			is_precharge = TRUE;
			break;

		/* peripheral fan assy */
		case SYS_P_FAN_INDEX:
			temp_pres = (IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) &&
			    !(status1 & SYS_NOT_P_FAN_PRES);
			temp_psok = softsp->pps_fan_saved &
			    SYS_AC_FAN_OK;
			is_fan_assy = TRUE;
			break;
		}

		/* *** Phase 1 -- power supply presence tests *** */

		/* do we know the presence status for this power supply? */
		if (pstatp->pshadow == PRES_UNKNOWN) {
			pstatp->pshadow = temp_pres ? PRES_IN : PRES_OUT;
			pstatp->dcshadow = temp_pres ? PS_BOOT : PS_OUT;
		} else {
			/* has the ps presence state changed? */
			if (!temp_pres ^ (pstatp->pshadow == PRES_IN)) {
				pstatp->pctr = 0;
			} else {
				/* a change! are we counting? */
				if (pstatp->pctr == 0) {
					pstatp->pctr = PS_PRES_CHANGE_TICKS;
				} else if (--pstatp->pctr == 0) {
					pstatp->pshadow = temp_pres ?
					    PRES_IN : PRES_OUT;
					pstatp->dcshadow = temp_pres ?
					    PS_UNKNOWN : PS_OUT;

					/*
					 * Now we know the state has
					 * changed, so we should log it.
					 */
					ps_log_pres_change(softsp,
					    i, temp_pres);
				}
			}
		}

		/* *** Phase 2 -- power supply status tests *** */

		/* check if the Power Supply is removed or same as before */
		if ((pstatp->dcshadow == PS_OUT) ||
		    ((pstatp->dcshadow == PS_OK) && temp_psok) ||
		    ((pstatp->dcshadow == PS_FAIL) && !temp_psok)) {
			pstatp->dcctr = 0;
		} else {

			/* OK, a change, do we start the timer? */
			if (pstatp->dcctr == 0) {
				switch (pstatp->dcshadow) {
				case PS_BOOT:
					pstatp->dcctr = PS_FROM_BOOT_TICKS;
					break;

				case PS_UNKNOWN:
					pstatp->dcctr = is_fan_assy ?
					    PS_P_FAN_FROM_UNKNOWN_TICKS :
					    PS_FROM_UNKNOWN_TICKS;
					break;

				case PS_OK:
					pstatp->dcctr = is_precharge ?
					    PS_PCH_FROM_OK_TICKS :
					    PS_FROM_OK_TICKS;
					break;

				case PS_FAIL:
					pstatp->dcctr = PS_FROM_FAIL_TICKS;
					break;

				default:
					panic("sysctrl%d: Unknown Power "
					    "Supply State %d", pstatp->dcshadow,
					    ddi_get_instance(softsp->dip));
				}
			}

			/* has the ticker expired? */
			if (--pstatp->dcctr == 0) {

				/* we'll skip OK messages during boot */
				if (!((pstatp->dcshadow == PS_BOOT) &&
				    temp_psok)) {
					ps_log_state_change(softsp,
					    i, temp_psok);
				}

				/*
				 * remote console interface has to be
				 * reinitialized on the rising edge V5_AUX
				 * when it is NOT boot. At the boot time an
				 * an error condition exists if it was not
				 * enabled before.
				 */
				if ((i == SYS_V5_AUX_INDEX) &&
				    (pstatp->dcshadow != PS_BOOT) &&
				    (softsp->enable_rcons_atboot)) {
					if (temp_psok)
						rcons_reinit(softsp);
					else
						/* disable rconsole */
						*(softsp->clk_freq2) &=
						    ~RCONS_UART_EN;
					tmp_reg = *(softsp->csr);
#ifdef lint
					tmp_reg = tmp_reg;
#endif

				}

				/* regardless, update the shadow state */
				pstatp->dcshadow = temp_psok ? PS_OK : PS_FAIL;

				/* always update board condition */
				sysc_policy_update(softsp, NULL,
				    SYSC_EVT_BD_PS_CHANGE);

			}
		}

		/*
		 * We will need to continue polling for three reasons:
		 * - a failing power supply is detected and we haven't yet
		 *   determined the power supplies existence.
		 * - the power supply is just installed and we're waiting
		 *   to give it a change to power up,
		 * - a failed power supply state is recognized
		 *
		 * NOTE: PS_FAIL shadow state is not the same as !temp_psok
		 * because of the persistence of PS_FAIL->PS_OK.
		 */
		if (!temp_psok ||
		    (pstatp->dcshadow == PS_UNKNOWN) ||
		    (pstatp->dcshadow == PS_FAIL)) {
			poll_needed++;
		}
	}

	/*
	 * Now, get the current power state for this instance.
	 * If the current state is different than what was known, complain.
	 */
	current_power_state = compute_power_state(softsp, 0);

	if (softsp->power_state != current_power_state) {
		switch (current_power_state) {
		case BELOW_MINIMUM:
			cmn_err(CE_WARN,
			    "Insufficient power available to system");
			if (!disable_insufficient_power_reboot) {
				cmn_err(CE_WARN, "System reboot in %d seconds",
				    PS_INSUFFICIENT_COUNTDOWN_SEC);
			}
			reg_fault(1, FT_INSUFFICIENT_POWER, FT_SYSTEM);
			softsp->power_countdown = PS_POWER_COUNTDOWN_TICKS;
			break;

		case MINIMUM:
			/* If we came from REDUNDANT, complain */
			if (softsp->power_state == REDUNDANT) {
				cmn_err(CE_WARN, "Redundant power lost");
			/* If we came from BELOW_MINIMUM, hurrah! */
			} else if (softsp->power_state == BELOW_MINIMUM) {
				cmn_err(CE_NOTE, "Minimum power available");
				clear_fault(1, FT_INSUFFICIENT_POWER,
				    FT_SYSTEM);
			}
			break;

		case REDUNDANT:
			/* If we aren't from boot, spread the good news */
			if (softsp->power_state != BOOT) {
				cmn_err(CE_NOTE, "Redundant power available");
				clear_fault(1, FT_INSUFFICIENT_POWER,
				    FT_SYSTEM);
			}
			break;

		default:
			break;
		}
		softsp->power_state = current_power_state;
		sysc_policy_update(softsp, NULL, SYSC_EVT_BD_PS_CHANGE);
	}

	mutex_exit(&softsp->ps_fail_lock);

	fhc_bdlist_unlock();

	/*
	 * Are we in insufficient powerstate?
	 * If so, is it time to take action?
	 */
	if (softsp->power_state == BELOW_MINIMUM &&
	    softsp->power_countdown > 0 && --(softsp->power_countdown) == 0 &&
	    !disable_insufficient_power_reboot) {
		cmn_err(CE_WARN,
		    "Insufficient power. System Reboot Started...");

		fhc_reboot();
	}

	/*
	 * If we don't have ps problems that need to be polled for, then
	 * enable interrupts.
	 */
	if (!poll_needed) {
		mutex_enter(&softsp->csr_mutex);
		*(softsp->csr) |= SYS_PS_FAIL_EN;
		tmp_reg = *(softsp->csr);
#ifdef lint
		tmp_reg = tmp_reg;
#endif
		mutex_exit(&softsp->csr_mutex);
	}

	/*
	 * Only the polling loop re-triggers the polling loop timeout
	 */
	if (!fromint) {
		(void) timeout(ps_fail_retry, softsp, ps_fail_timeout_hz);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Compute the current power configuration for this system.
 * Disk boards and Clock boards are not counted.
 *
 * This function must be called with the ps_fail_lock held.
 */
enum power_state
compute_power_state(struct sysctrl_soft_state *softsp, int plus_load)
{
	int i;
	int ok_supply_count = 0;
	int load_count = 0;
	int minimum_power_count;
	int pps_ok;
	fhc_bd_t *list;

	ASSERT(mutex_owned(&softsp->ps_fail_lock));

	/*
	 * Walk down the interesting power supplies and
	 * count the operational power units
	 */
	for (i = 0; i < 8; i++) {
		/*
		 * power supply id 7 on a 4 or 5 slot system is PPS1.
		 * don't include it in the redundant core power calculation.
		 */
		if (i == 7 &&
		    (IS4SLOT(softsp->nslots) || IS5SLOT(softsp->nslots)))
			continue;

		if (softsp->ps_stats[i].dcshadow == PS_OK)
			ok_supply_count++;
	}

	/* Note the state of the PPS... */
	pps_ok = (softsp->ps_stats[SYS_PPS0_INDEX].dcshadow == PS_OK);

	/*
	 * Dynamically compute the load count in the system.
	 * Don't count disk boards or boards in low power state.
	 */
	for (list = fhc_bd_first(); list; list = fhc_bd_next(list)) {
		ASSERT(list->sc.type != CLOCK_BOARD);
		if (list->sc.rstate == SYSC_CFGA_RSTATE_CONNECTED) {
			load_count++;
		}
	}

	load_count += plus_load;
	/*
	 * If we are 8 slot and we have 7 or 8 boards, then the PPS
	 * can count as a power supply...
	 */
	if (IS8SLOT(softsp->nslots) && load_count >= 7 && pps_ok)
		ok_supply_count++;

	/*
	 * This is to cover the corner case of a UE3500 having 5
	 * boards installed and still giving it N+1 power status.
	 */
	if (IS5SLOT(softsp->nslots) && (load_count >= 5))
		ok_supply_count++;

	/*
	 * Determine our power situation.  This is a simple step
	 * function right now:
	 *
	 * minimum power count = min(7, floor((board count + 1) / 2))
	 */
	minimum_power_count = (load_count + 1) / 2;
	if (minimum_power_count > 7)
		minimum_power_count = 7;

	if (ok_supply_count > minimum_power_count)
		return (REDUNDANT);
	else if (ok_supply_count == minimum_power_count)
		return (MINIMUM);
	else
		return (BELOW_MINIMUM);
}

/*
 * log the change of power supply presence
 */
static void
ps_log_pres_change(struct sysctrl_soft_state *softsp, int index, int present)
{
	char	*trans = present ? "Installed" : "Removed";

	switch (index) {
	/* the core power supplies (except for 7) */
	case 0: case 1: case 2: case 3:
	case 4: case 5: case 6:
		cmn_err(CE_NOTE, "%s %d %s", ft_str_table[FT_CORE_PS], index,
		    trans);
		if (!present) {
			clear_fault(index, FT_CORE_PS, FT_SYSTEM);
			sysc_policy_update(softsp, NULL, SYSC_EVT_BD_PS_CHANGE);
		}
		break;

	/* power supply 7 / pps 1 */
	case 7:
		if (IS4SLOT(softsp->nslots) || IS5SLOT(softsp->nslots)) {
			cmn_err(CE_NOTE, "%s 1 %s", ft_str_table[FT_PPS],
			    trans);
			if (!present) {
			clear_fault(1, FT_PPS, FT_SYSTEM);
			}
		} else {
			cmn_err(CE_NOTE, "%s %d %s", ft_str_table[FT_CORE_PS],
			    index, trans);
			if (!present) {
			clear_fault(7, FT_CORE_PS, FT_SYSTEM);
			sysc_policy_update(softsp, NULL, SYSC_EVT_BD_PS_CHANGE);
			}
		}
		break;

	/* the peripheral power supply 0 */
	case SYS_PPS0_INDEX:
		cmn_err(CE_NOTE, "%s 0 %s", ft_str_table[FT_PPS], trans);
		if (!present) {
			clear_fault(0, FT_PPS, FT_SYSTEM);
			sysc_policy_update(softsp, NULL, SYSC_EVT_BD_PS_CHANGE);
		}
		break;

	/* the peripheral rack fan assy */
	case SYS_P_FAN_INDEX:
		cmn_err(CE_NOTE, "%s %s", ft_str_table[FT_PPS_FAN], trans);
		if (!present) {
			clear_fault(0, FT_PPS_FAN, FT_SYSTEM);
		}
		break;

	/* we don't mention a change of presence state for any other power */
	}
}

/*
 * log the change of power supply status
 */
static void
ps_log_state_change(struct sysctrl_soft_state *softsp, int index, int ps_ok)
{
	int level = ps_ok ? CE_NOTE : CE_WARN;
	char *s = ps_ok ? "OK" : "Failing";

	switch (index) {
	/* the core power supplies (except 7) */
	case 0: case 1: case 2: case 3:
	case 4: case 5: case 6:
		cmn_err(level, "%s %d %s", ft_str_table[FT_CORE_PS], index, s);
		if (ps_ok) {
			clear_fault(index, FT_CORE_PS, FT_SYSTEM);
		} else {
			reg_fault(index, FT_CORE_PS, FT_SYSTEM);
		}
		break;

	/* power supply 7 / pps 1 */
	case 7:
		if (IS4SLOT(softsp->nslots) || IS5SLOT(softsp->nslots)) {
			cmn_err(level, "%s 1 %s", ft_str_table[FT_PPS], s);
			if (ps_ok) {
				clear_fault(1, FT_PPS, FT_SYSTEM);
			} else {
				reg_fault(1, FT_PPS, FT_SYSTEM);
			}
		} else {
			cmn_err(level, "%s %d %s", ft_str_table[FT_CORE_PS],
			    index, s);
			if (ps_ok) {
				clear_fault(index, FT_CORE_PS, FT_SYSTEM);
			} else {
				reg_fault(index, FT_CORE_PS, FT_SYSTEM);
			}
		}
		break;

	/* the peripheral power supply */
	case SYS_PPS0_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_PPS], s);
		if (ps_ok) {
			clear_fault(0, FT_PPS, FT_SYSTEM);
		} else {
			reg_fault(0, FT_PPS, FT_SYSTEM);
		}
		break;

	/* shared 3.3v clock power */
	case SYS_CLK_33_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_CLK_33], s);
		if (ps_ok) {
			clear_fault(0, FT_CLK_33, FT_SYSTEM);
		} else {
			reg_fault(0, FT_CLK_33, FT_SYSTEM);
		}
		break;

	/* shared 5.0v clock power */
	case SYS_CLK_50_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_CLK_50], s);
		if (ps_ok) {
			clear_fault(0, FT_CLK_50, FT_SYSTEM);
		} else {
			reg_fault(0, FT_CLK_50, FT_SYSTEM);
		}
		break;

	/* peripheral 5v */
	case SYS_V5_P_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V5_P], s);
		if (ps_ok) {
			clear_fault(0, FT_V5_P, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V5_P, FT_SYSTEM);
		}
		break;

	/* peripheral 12v */
	case SYS_V12_P_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V12_P], s);
		if (ps_ok) {
			clear_fault(0, FT_V12_P, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V12_P, FT_SYSTEM);
		}
		break;

	/* aux 5v */
	case SYS_V5_AUX_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V5_AUX], s);
		if (ps_ok) {
			clear_fault(0, FT_V5_AUX, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V5_AUX, FT_SYSTEM);
		}
		break;

	/* peripheral 5v precharge */
	case SYS_V5_P_PCH_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V5_P_PCH], s);
		if (ps_ok) {
			clear_fault(0, FT_V5_P_PCH, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V5_P_PCH, FT_SYSTEM);
		}
		break;

	/* peripheral 12v precharge */
	case SYS_V12_P_PCH_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V12_P_PCH], s);
		if (ps_ok) {
			clear_fault(0, FT_V12_P_PCH, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V12_P_PCH, FT_SYSTEM);
		}
		break;

	/* 3.3v precharge */
	case SYS_V3_PCH_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V3_PCH], s);
		if (ps_ok) {
			clear_fault(0, FT_V3_PCH, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V3_PCH, FT_SYSTEM);
		}
		break;

	/* 5v precharge */
	case SYS_V5_PCH_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_V5_PCH], s);
		if (ps_ok) {
			clear_fault(0, FT_V5_PCH, FT_SYSTEM);
		} else {
			reg_fault(0, FT_V5_PCH, FT_SYSTEM);
		}
		break;

	/* peripheral power supply fans */
	case SYS_P_FAN_INDEX:
		cmn_err(level, "%s %s", ft_str_table[FT_PPS_FAN], s);
		if (ps_ok) {
			clear_fault(0, FT_PPS_FAN, FT_SYSTEM);
		} else {
			reg_fault(0, FT_PPS_FAN, FT_SYSTEM);
		}
		break;
	}
}

/*
 * The timeout from ps_fail_handler() that simply re-triggers a check
 * of the ps condition.
 */
static void
ps_fail_retry(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;

	ASSERT(softsp);

	ddi_trigger_softintr(softsp->ps_fail_poll_id);
}

/*
 * pps_fanfail_handler
 *
 * This routine is called from the high level handler.
 */
static uint_t
pps_fanfail_handler(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;

	ASSERT(softsp);

	/* always check again in a bit by re-enabling the fan interrupt */
	(void) timeout(pps_fanfail_retry, softsp, pps_fan_timeout_hz);

	return (DDI_INTR_CLAIMED);
}

/*
 * After a bit of waiting, we simply re-enable the interrupt to
 * see if we get another one.  The softintr triggered routine does
 * the dirty work for us since it runs in the interrupt context.
 */
static void
pps_fanfail_retry(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;

	ASSERT(softsp);

	ddi_trigger_softintr(softsp->pps_fan_high_id);
}

/*
 * The other half of the retry handler run from the interrupt context
 */
static uint_t
pps_fanfail_reenable(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t tmp_reg;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);

	/*
	 * re-initialize the bit field for all pps fans to assumed good.
	 * If the fans are still bad, we're going to get an immediate system
	 * interrupt which will put the correct state back anyway.
	 *
	 * NOTE: the polling routines that use this state understand the
	 * pulse resulting from above...
	 */
	softsp->pps_fan_saved = SYS_AC_FAN_OK | SYS_KEYSW_FAN_OK;

	*(softsp->csr) |= SYS_PPS_FAN_FAIL_EN;
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif
	mutex_exit(&softsp->csr_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 *
 * Poll the hardware shadow state to determine the pps fan status.
 * The shadow state is maintained by the system_high handler and its
 * associated pps_* functions (above).
 *
 * There is a short time interval where the shadow state is pulsed to
 * the OK state even when the fans are bad.  However, this polling
 * routine has some built in hysteresis to filter out those _normal_
 * events.
 */
static void
pps_fan_poll(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;
	int i;

	ASSERT(softsp);

	for (i = 0; i < SYS_PPS_FAN_COUNT; i++) {
		int fanfail = FALSE;

		/* determine fan status */
		switch (i) {
		case RACK:
			fanfail = softsp->pps_fan_saved & SYS_RACK_FANFAIL;
			break;

		case AC:
			/*
			 * Don't bother polling the AC fan on 4 and 5 slot
			 * systems.
			 * Rather, it is handled by the power supply loop.
			 */
			fanfail = !(IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) &&
			    !(softsp->pps_fan_saved & SYS_AC_FAN_OK);
			break;

		case KEYSW:
			/*
			 * This signal is not usable if aux5v is missing
			 * so we will synthesize a failed fan when aux5v
			 * fails or when pps0 is out.
			 * The 4 and 5 slot systems behave the same.
			 */
			fanfail = (!(IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) &&
			    (softsp->ps_stats[SYS_V5_AUX_INDEX].dcshadow !=
			    PS_OK)) ||
			    !(softsp->pps_fan_saved & SYS_KEYSW_FAN_OK);
			break;

		}

		/* is the fan bad? */
		if (fanfail) {

			/* is this condition different than we know? */
			if (softsp->pps_fan_state_count[i] == 0) {

				/* log the change to failed */
				pps_fan_state_change(softsp, i, FALSE);
			}

			/* always restart the fan OK counter */
			softsp->pps_fan_state_count[i] = PPS_FROM_FAIL_TICKS;
		} else {

			/* do we currently know the fan is bad? */
			if (softsp->pps_fan_state_count[i]) {

				/* yes, but has it been stable? */
				if (--softsp->pps_fan_state_count[i] == 0) {

					/* log the change to OK */
					pps_fan_state_change(softsp, i, TRUE);
				}
			}
		}
	}

	/* always check again in a bit by re-enabling the fan interrupt */
	(void) timeout(pps_fan_poll, softsp, pps_fan_timeout_hz);
}

/*
 * pps_fan_state_change()
 *
 * Log the changed fan condition and update the external status.
 */
static void
pps_fan_state_change(struct sysctrl_soft_state *softsp, int index, int fan_ok)
{
	char *fan_type;
	char *state = fan_ok ? "fans OK" : "fan failure detected";

	switch (index) {
	case RACK:
		/* 4 and 5 slot systems behave the same */
		fan_type = (IS4SLOT(softsp->nslots) ||
		    IS5SLOT(softsp->nslots)) ?
		    "Disk Drive" : "Rack Exhaust";
		if (fan_ok) {
			softsp->pps_fan_external_state &= ~SYS_RACK_FANFAIL;
			clear_fault(0, (IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) ? FT_DSK_FAN :
			    FT_RACK_EXH, FT_SYSTEM);
		} else {
			softsp->pps_fan_external_state |= SYS_RACK_FANFAIL;
			reg_fault(0, (IS4SLOT(softsp->nslots) ||
			    IS5SLOT(softsp->nslots)) ? FT_DSK_FAN :
			    FT_RACK_EXH, FT_SYSTEM);
		}
		break;

	case AC:
		fan_type = "AC Box";
		if (fan_ok) {
			softsp->pps_fan_external_state |= SYS_AC_FAN_OK;
			clear_fault(0, FT_AC_FAN, FT_SYSTEM);
		} else {
			softsp->pps_fan_external_state &= ~SYS_AC_FAN_OK;
			reg_fault(0, FT_AC_FAN, FT_SYSTEM);
		}
		break;

	case KEYSW:
		fan_type = "Keyswitch";
		if (fan_ok) {
			softsp->pps_fan_external_state |= SYS_KEYSW_FAN_OK;
			clear_fault(0, FT_KEYSW_FAN, FT_SYSTEM);
		} else {
			softsp->pps_fan_external_state &= ~SYS_KEYSW_FAN_OK;
			reg_fault(0, FT_KEYSW_FAN, FT_SYSTEM);
		}
		break;
	default:
		fan_type = "[invalid fan id]";
		break;
	}

	/* now log the state change */
	cmn_err(fan_ok ? CE_NOTE : CE_WARN, "%s %s", fan_type, state);
}

static uint_t
bd_insert_handler(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;

	ASSERT(softsp);

	DPRINTF(SYSCTRL_ATTACH_DEBUG, ("bd_insert_handler()"));

	(void) timeout(bd_insert_timeout, softsp, bd_insert_delay_hz);

	return (DDI_INTR_CLAIMED);
}

void
bd_remove_poll(struct sysctrl_soft_state *softsp)
{
	ASSERT(fhc_bdlist_locked());

	if (!bd_remove_to_id) {
		bd_remove_to_id = timeout(bd_remove_timeout, softsp,
		    bd_remove_timeout_hz);
	} else {
		DPRINTF(SYSCTRL_ATTACH_DEBUG,
		    ("bd_remove_poll ignoring start request"));
	}
}

/*
 * bd_insert_timeout()
 *
 * This routine handles the board insert interrupt. It is called from a
 * timeout so that it does not run at interrupt level. The main job
 * of this routine is to find hotplugged boards and de-assert the
 * board insert interrupt coming from the board. For hotplug phase I,
 * the routine also powers down the board.
 * JTAG scan is used to find boards which have been inserted.
 * All other control of the boards is also done by JTAG scan.
 */
static void
bd_insert_timeout(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;
	int found;

	ASSERT(softsp);

	if (sysctrl_hotplug_disabled) {
		sysc_policy_update(softsp, NULL, SYSC_EVT_BD_HP_DISABLED);
	} else {
		/*
		 * Lock the board list mutex. Keep it locked until all work
		 * is done.
		 */
		(void) fhc_bdlist_lock(-1);

		found = fhc_bd_insert_scan();

		if (found) {
			DPRINTF(SYSCTRL_ATTACH_DEBUG,
			    ("bd_insert_timeout starting bd_remove_poll()"));
			bd_remove_poll(softsp);
		}

		fhc_bdlist_unlock();
	}

	/*
	 * Enable interrupts.
	 */
	ddi_trigger_softintr(softsp->sbrd_gone_id);
}

static void
bd_remove_timeout(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;
	int keep_polling;

	ASSERT(softsp);

	/*
	 * Lock the board list mutex. Keep it locked until all work
	 * is done.
	 */
	(void) fhc_bdlist_lock(-1);

	bd_remove_to_id = 0;	/* delete our timeout ID */

	keep_polling = fhc_bd_remove_scan();

	if (keep_polling) {
		bd_remove_poll(softsp);
	} else {
		DPRINTF(SYSCTRL_ATTACH_DEBUG, ("exiting bd_remove_poll."));
	}

	fhc_bdlist_unlock();
}

static uint_t
bd_insert_normal(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t tmp_reg;

	ASSERT(softsp);

	/* has the condition been removed? */
	/* XXX add deglitch state machine here */
	if (!(*(softsp->status1) & SYS_NOT_BRD_PRES)) {
		/* check again in a few */
		(void) timeout(bd_insert_timeout, softsp, bd_insert_retry_hz);
	} else {
		/* Turn on the enable bit for this interrupt */
		mutex_enter(&softsp->csr_mutex);
		*(softsp->csr) |= SYS_SBRD_PRES_EN;
		/* flush the hardware store buffer */
		tmp_reg = *(softsp->csr);
#ifdef lint
		tmp_reg = tmp_reg;
#endif
		mutex_exit(&softsp->csr_mutex);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * blink LED handler.
 *
 * The actual bit manipulation needs to occur at interrupt level
 * because we need access to the CSR with its CSR mutex
 */
static uint_t
blink_led_handler(caddr_t arg)
{
	struct sysctrl_soft_state *softsp = (struct sysctrl_soft_state *)arg;
	uchar_t tmp_reg;

	ASSERT(softsp);

	mutex_enter(&softsp->csr_mutex);

	/*
	 * XXX - The lock for the sys_led is not held here. If more
	 * complicated tasks are done with the System LED, then
	 * locking should be done here.
	 */

	/* read the hardware register. */
	tmp_reg = *(softsp->csr);

	/* Only turn on the OS System LED bit if the softsp state is on. */
	if (softsp->sys_led) {
		tmp_reg |= SYS_LED_RIGHT;
	} else {
		tmp_reg &= ~SYS_LED_RIGHT;
	}

	/* Turn on the yellow LED if system fault status is set. */
	if (softsp->sys_fault) {
		tmp_reg |= SYS_LED_MID;
	} else {
		tmp_reg &= ~SYS_LED_MID;
	}

	/* write to the hardware register */
	*(softsp->csr) = tmp_reg;

	/* flush the hardware store buffer */
	tmp_reg = *(softsp->csr);
#ifdef lint
	tmp_reg = tmp_reg;
#endif
	mutex_exit(&softsp->csr_mutex);

	(void) timeout(blink_led_timeout, softsp, blink_led_timeout_hz);

	return (DDI_INTR_CLAIMED);
}

/*
 * simply re-trigger the interrupt handler on led timeout
 */
static void
blink_led_timeout(void *arg)
{
	struct sysctrl_soft_state *softsp = arg;
	int led_state;

	ASSERT(softsp);

	/*
	 * Process the system fault list here. This is where the driver
	 * must decide what yellow LEDs to turn on if any. The fault
	 * list is walked and each fhc_list entry is updated with it's
	 * yellow LED status. This info is used later by the routine
	 * toggle_board_green_leds().
	 *
	 * The variable system_fault is non-zero if any non-
	 * suppressed faults are found in the system.
	 */
	softsp->sys_fault = process_fault_list();

	/* blink the system board OS LED */
	mutex_enter(&softsp->sys_led_lock);
	softsp->sys_led = !softsp->sys_led;
	led_state = softsp->sys_led;
	mutex_exit(&softsp->sys_led_lock);

	toggle_board_green_leds(led_state);

	ddi_trigger_softintr(softsp->blink_led_id);
}

void
toggle_board_green_leds(int led_state)
{
	fhc_bd_t *list;

	(void) fhc_bdlist_lock(-1);
	for (list = fhc_bd_first(); list; list = fhc_bd_next(list)) {
		uint_t value = 0;

		if (list->sc.in_transition ||
		    (list->sc.rstate != SYSC_CFGA_RSTATE_CONNECTED))
			continue;

		ASSERT(list->sc.type != CLOCK_BOARD);
		ASSERT(list->sc.type != DISK_BOARD);
		ASSERT(list->softsp);

		if ((list->sc.ostate == SYSC_CFGA_OSTATE_CONFIGURED) &&
		    led_state)
			value |= FHC_LED_RIGHT;

		if (list->fault)
			value |= FHC_LED_MID;
		else
			value &= ~FHC_LED_MID;

		update_board_leds(list, FHC_LED_RIGHT|FHC_LED_MID, value);
	}
	fhc_bdlist_unlock();
}

/*
 * timestamp an AC power failure in nvram
 */
static void
nvram_update_powerfail(struct sysctrl_soft_state *softsp)
{
	char buf[80];
	int len = 0;

	numtos(gethrestime_sec(), buf);

	if (softsp->options_nodeid) {
		len = prom_setprop(softsp->options_nodeid, "powerfail-time",
		    buf, strlen(buf)+1);
	}

	if (len <= 0) {
		cmn_err(CE_WARN, "sysctrl%d: failed to set powerfail-time "
		    "to %s\n", ddi_get_instance(softsp->dip), buf);
	}
}

void
sysctrl_add_kstats(struct sysctrl_soft_state *softsp)
{
	struct kstat	*ksp;		/* Generic sysctrl kstats */
	struct kstat	*pksp;		/* Power Supply kstat */
	struct kstat	*tksp;		/* Sysctrl temperatrure kstat */
	struct kstat	*ttsp;		/* Sysctrl temperature test kstat */

	if ((ksp = kstat_create("unix", ddi_get_instance(softsp->dip),
	    SYSCTRL_KSTAT_NAME, "misc", KSTAT_TYPE_NAMED,
	    sizeof (struct sysctrl_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "sysctrl%d: kstat_create failed",
		    ddi_get_instance(softsp->dip));
	} else {
		struct sysctrl_kstat *sysksp;

		sysksp = (struct sysctrl_kstat *)(ksp->ks_data);

		/* now init the named kstats */
		kstat_named_init(&sysksp->csr, CSR_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->status1, STAT1_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->status2, STAT2_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->clk_freq2, CLK_FREQ2_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->fan_status, FAN_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->key_status, KEY_KSTAT_NAMED,
		    KSTAT_DATA_CHAR);

		kstat_named_init(&sysksp->power_state, POWER_KSTAT_NAMED,
		    KSTAT_DATA_INT32);

		kstat_named_init(&sysksp->clk_ver, CLK_VER_KSTAT_NAME,
		    KSTAT_DATA_CHAR);

		ksp->ks_update = sysctrl_kstat_update;
		ksp->ks_private = (void *)softsp;
		kstat_install(ksp);
	}

	if ((tksp = kstat_create("unix", CLOCK_BOARD_INDEX,
	    OVERTEMP_KSTAT_NAME, "misc", KSTAT_TYPE_RAW,
	    sizeof (struct temp_stats), KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "sysctrl%d: kstat_create failed",
			ddi_get_instance(softsp->dip));
	} else {
		tksp->ks_update = overtemp_kstat_update;
		tksp->ks_private = (void *)&softsp->tempstat;
		kstat_install(tksp);
	}

	if ((ttsp = kstat_create("unix", CLOCK_BOARD_INDEX,
	    TEMP_OVERRIDE_KSTAT_NAME, "misc", KSTAT_TYPE_RAW, sizeof (short),
	    KSTAT_FLAG_PERSISTENT | KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "sysctrl%d: kstat_create failed",
		    ddi_get_instance(softsp->dip));
	} else {
		ttsp->ks_update = temp_override_kstat_update;
		ttsp->ks_private = (void *)&softsp->tempstat.override;
		kstat_install(ttsp);
	}

	if ((pksp = kstat_create("unix", ddi_get_instance(softsp->dip),
	    PSSHAD_KSTAT_NAME, "misc", KSTAT_TYPE_RAW,
	    SYS_PS_COUNT, KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "sysctrl%d: kstat_create failed",
		    ddi_get_instance(softsp->dip));
	} else {
		pksp->ks_update = psstat_kstat_update;
		pksp->ks_private = (void *)softsp;
		kstat_install(pksp);
	}
}

static int
sysctrl_kstat_update(kstat_t *ksp, int rw)
{
	struct sysctrl_kstat *sysksp;
	struct sysctrl_soft_state *softsp;

	sysksp = (struct sysctrl_kstat *)(ksp->ks_data);
	softsp = (struct sysctrl_soft_state *)(ksp->ks_private);

	/* this is a read-only kstat. Exit on a write */

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		/*
		 * copy the current state of the hardware into the
		 * kstat structure.
		 */
		sysksp->csr.value.c[0] = *(softsp->csr);
		sysksp->status1.value.c[0] = *(softsp->status1);
		sysksp->status2.value.c[0] = *(softsp->status2);
		sysksp->clk_freq2.value.c[0] = *(softsp->clk_freq2);

		sysksp->fan_status.value.c[0] = softsp->pps_fan_external_state;
		sysksp->key_status.value.c[0] = softsp->key_shadow;
		sysksp->power_state.value.i32 = softsp->power_state;

		/*
		 * non-existence of the clock version register returns the
		 * value 0xff when the hardware register location is read
		 */
		if (softsp->clk_ver != NULL)
			sysksp->clk_ver.value.c[0] = *(softsp->clk_ver);
		else
			sysksp->clk_ver.value.c[0] = (char)0xff;
	}
	return (0);
}

static int
psstat_kstat_update(kstat_t *ksp, int rw)
{
	struct sysctrl_soft_state *softsp;
	uchar_t *ptr = (uchar_t *)(ksp->ks_data);
	int ps;

	softsp = (struct sysctrl_soft_state *)(ksp->ks_private);

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		for (ps = 0; ps < SYS_PS_COUNT; ps++) {
			*ptr++ = softsp->ps_stats[ps].dcshadow;
		}
	}
	return (0);
}

static void
sysctrl_thread_wakeup(void *arg)
{
	int type = (int)(uintptr_t)arg;

	/*
	 * grab mutex to guarantee that our wakeup call
	 * arrives after we go to sleep -- so we can't sleep forever.
	 */
	mutex_enter(&sslist_mutex);
	switch (type) {
	case OVERTEMP_POLL:
		cv_signal(&overtemp_cv);
		break;
	case KEYSWITCH_POLL:
		cv_signal(&keyswitch_cv);
		break;
	default:
		cmn_err(CE_WARN, "sysctrl: invalid type %d to wakeup\n", type);
		break;
	}
	mutex_exit(&sslist_mutex);
}

static void
sysctrl_overtemp_poll(void)
{
	struct sysctrl_soft_state *list;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &sslist_mutex, callb_generic_cpr, "overtemp");

	/* The overtemp data structures are protected by a mutex. */
	mutex_enter(&sslist_mutex);

	while (sysctrl_do_overtemp_thread) {

		for (list = sys_list; list != NULL; list = list->next) {
			if (list->temp_reg != NULL) {
				update_temp(list->pdip, &list->tempstat,
				    *(list->temp_reg));
			}
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);

		/* now have this thread sleep for a while */
		(void) timeout(sysctrl_thread_wakeup, (void *)OVERTEMP_POLL,
		    overtemp_timeout_hz);

		cv_wait(&overtemp_cv, &sslist_mutex);

		CALLB_CPR_SAFE_END(&cprinfo, &sslist_mutex);
	}
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
	/* NOTREACHED */
}

static void
sysctrl_keyswitch_poll(void)
{
	struct sysctrl_soft_state *list;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &sslist_mutex, callb_generic_cpr, "keyswitch");

	/* The keyswitch data strcutures are protected by a mutex. */
	mutex_enter(&sslist_mutex);

	while (sysctrl_do_keyswitch_thread) {

		for (list = sys_list; list != NULL; list = list->next) {
			if (list->status1 != NULL)
				update_key_state(list);
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);

		/* now have this thread sleep for a while */
		(void) timeout(sysctrl_thread_wakeup, (void *)KEYSWITCH_POLL,
		    keyswitch_timeout_hz);

		cv_wait(&keyswitch_cv, &sslist_mutex);

		CALLB_CPR_SAFE_END(&cprinfo, &sslist_mutex);
	}
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
	/* NOTREACHED */
}

/*
 * check the key switch position for state changes
 */
static void
update_key_state(struct sysctrl_soft_state *list)
{
	enum keyswitch_state key;

	/*
	 * snapshot current hardware key position
	 */
	if (*(list->status1) & SYS_NOT_SECURE)
		key = KEY_NOT_SECURE;
	else
		key = KEY_SECURE;

	/*
	 * check for state transition
	 */
	if (key != list->key_shadow) {

		/*
		 * handle state transition
		 */
		switch (list->key_shadow) {
		case KEY_BOOT:
			cmn_err(CE_CONT, "?sysctrl%d: Key switch is%sin the "
			    "secure position\n", ddi_get_instance(list->dip),
			    (key == KEY_SECURE) ? " " : " not ");
			list->key_shadow = key;
			break;
		case KEY_SECURE:
		case KEY_NOT_SECURE:
			cmn_err(CE_NOTE, "sysctrl%d: Key switch has changed"
			    " to the %s position",
			    ddi_get_instance(list->dip),
			    (key == KEY_SECURE) ? "secure" : "not-secure");
			list->key_shadow = key;
			break;
		default:
			cmn_err(CE_CONT,
			    "?sysctrl%d: Key switch is in an unknown position,"
			    "treated as being in the %s position\n",
			    ddi_get_instance(list->dip),
			    (list->key_shadow == KEY_SECURE) ?
			    "secure" : "not-secure");
			break;
		}
	}
}

/*
 * consider key switch position when handling an abort sequence
 */
static void
sysctrl_abort_seq_handler(char *msg)
{
	struct sysctrl_soft_state *list;
	uint_t secure = 0;
	char buf[64], inst[4];


	/*
	 * if any of the key switch positions are secure,
	 * then disallow entry to the prom/debugger
	 */
	mutex_enter(&sslist_mutex);
	buf[0] = (char)0;
	for (list = sys_list; list != NULL; list = list->next) {
		if (!(*(list->status1) & SYS_NOT_SECURE)) {
			if (secure++)
				(void) strcat(buf, ",");
			/*
			 * XXX: later, replace instance number with nodeid
			 */
			(void) sprintf(inst, "%d", ddi_get_instance(list->dip));
			(void) strcat(buf, inst);
		}
	}
	mutex_exit(&sslist_mutex);

	if (secure) {
		cmn_err(CE_CONT,
		    "!sysctrl(%s): ignoring debug enter sequence\n", buf);
	} else {
		cmn_err(CE_CONT, "!sysctrl: allowing debug enter\n");
		debug_enter(msg);
	}
}

#define	TABLE_END	0xFF

struct uart_cmd {
	uchar_t reg;
	uchar_t data;
};

/*
 * Time constant defined by this formula:
 *	((4915200/32)/(baud) -2)
 */

struct uart_cmd uart_table[] = {
	{ 0x09, 0xc0 },	/* Force hardware reset */
	{ 0x04, 0x46 },	/* X16 clock mode, 1 stop bit/char, no parity */
	{ 0x03, 0xc0 },	/* Rx is 8 bits/char */
	{ 0x05, 0xe2 },	/* DTR, Tx is 8 bits/char, RTS */
	{ 0x09, 0x02 },	/* No vector returned on interrupt */
	{ 0x0b, 0x55 },	/* Rx Clock = Tx Clock = BR generator = ~TRxC OUT */
	{ 0x0c, 0x0e },	/* Time Constant = 0x000e for 9600 baud */
	{ 0x0d, 0x00 },	/* High byte of time constant */
	{ 0x0e, 0x02 },	/* BR generator comes from Z-SCC's PCLK input */
	{ 0x03, 0xc1 },	/* Rx is 8 bits/char, Rx is enabled */
	{ 0x05, 0xea },	/* DTR, Tx is 8 bits/char, Tx is enabled, RTS */
	{ 0x0e, 0x03 },	/* BR comes from PCLK, BR generator is enabled */
	{ 0x00, 0x30 },	/* Error reset */
	{ 0x00, 0x30 },	/* Error reset */
	{ 0x00, 0x10 },	/* external status reset */
	{ 0x03, 0xc1 },	/* Rx is 8 bits/char, Rx is enabled */
	{ TABLE_END, 0x0 }
};

static void
init_remote_console_uart(struct sysctrl_soft_state *softsp)
{
	int i = 0;

	/*
	 * Serial chip expects software to write to the control
	 * register first with the desired register number. Then
	 * write to the control register with the desired data.
	 * So walk thru table writing the register/data pairs to
	 * the serial port chip.
	 */
	while (uart_table[i].reg != TABLE_END) {
		*(softsp->rcons_ctl) = uart_table[i].reg;
		*(softsp->rcons_ctl) = uart_table[i].data;
		i++;
	}
}

/*
 * return the slot information of the system
 *
 * function take a sysctrl_soft_state, so it's ready for sunfire+
 * change which requires 2 registers to decide the system type.
 */
static void
sysc_slot_info(int nslots, int *start, int *limit, int *incr)
{
	switch (nslots) {
	case 8:
		*start = 0;
		*limit = 8;
		*incr = 1;
		break;
	case 5:
		*start = 1;
		*limit = 10;
		*incr = 2;
		break;
	case 4:
		*start = 1;
		*limit = 8;
		*incr = 2;
		break;
	case 0:
	case 16:
	default:
		*start = 0;
		*limit = 16;
		*incr = 1;
		break;
	}
}

/*
 * reinitialize the Remote Console on the clock board
 *
 * with V5_AUX power outage the Remote Console ends up in
 * unknown state and has to be reinitilized if it was enabled
 * initially.
 */
static void
rcons_reinit(struct sysctrl_soft_state *softsp)
{
	uchar_t tmp_reg;

	if (!(softsp->rcons_ctl))
		/*
		 * There is no OBP register set for the remote console UART,
		 * so offset from the last register set, the misc register
		 * set, in order to map in the remote console UART.
		 */
		if (ddi_map_regs(softsp->dip, 1, (caddr_t *)&softsp->rcons_ctl,
		    RMT_CONS_OFFSET, RMT_CONS_LEN)) {
			cmn_err(CE_WARN, "Unable to reinitialize "
			    "remote console.");
			return;
		}


	/* Disable the remote console reset control bits. */
	*(softsp->clk_freq2) &= ~RCONS_UART_EN;

	/* flush the hardware buffers */
	tmp_reg = *(softsp->csr);

	/*
	 * Program the UART to watch ttya console.
	 */
	init_remote_console_uart(softsp);

	/* Now enable the remote console reset control bits. */
	*(softsp->clk_freq2) |= RCONS_UART_EN;

	/* flush the hardware buffers */
	tmp_reg = *(softsp->csr);

	/* print some info for user to watch */
	cmn_err(CE_NOTE, "Remote console reinitialized");
#ifdef lint
	tmp_reg = tmp_reg;
#endif
}
