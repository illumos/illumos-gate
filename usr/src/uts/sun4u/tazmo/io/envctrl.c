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


/*
 * ENVCTRL_ Environment Monitoring driver for i2c
 *
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/termio.h>
#include <sys/termios.h>
#include <sys/cmn_err.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/eucioctl.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/kmem.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/obpdefs.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/stat.h>		/* ddi_create_minor_node S_IFCHR */
#include <sys/open.h>		/* for open params.	 */
#include <sys/uio.h>		/* for read/write */
#include <sys/envctrl.h>	/* Environment header */

/* driver entry point fn definitions */
static int	envctrl_open(queue_t *, dev_t *, int, int, cred_t *);
static int	envctrl_close(queue_t *, int, cred_t *);
static uint_t	envctrl_bus_isr(caddr_t);
static uint_t	envctrl_dev_isr(caddr_t);

/* configuration entry point fn definitions */
static int	envctrl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	envctrl_attach(dev_info_t *, ddi_attach_cmd_t);
static int	envctrl_detach(dev_info_t *, ddi_detach_cmd_t);

/* Driver private routines */
static void	envctrl_init_bus(struct envctrlunit *);
static int	envctrl_xmit(struct envctrlunit *, caddr_t *, int);
static void	envctrl_recv(struct envctrlunit *, caddr_t *, int);
static void	envctrl_get_sys_temperatures(struct envctrlunit *, uint8_t *);
static int	envctrl_get_lm75_temp(struct envctrlunit *);
static int	envctrl_get_ps_temp(struct envctrlunit *, uint8_t);
static int	envctrl_get_cpu_temp(struct envctrlunit *, int);
static void	envctrl_fan_fail_service(struct envctrlunit *);
static void	envctrl_PS_intr_service(struct envctrlunit *, uint8_t);
static void	envctrl_ps_probe(struct envctrlunit *);
static void	envctrl_tempr_poll(void *);
static void	envctrl_pshotplug_poll(void *);
static void	envctrl_led_blink(void *);
static void	envctrl_reset_dflop(struct envctrlunit *);
static void	envctrl_enable_devintrs(struct envctrlunit *);
static void	envctrl_stop_clock(struct envctrlunit *);
static void	envctrl_reset_watchdog(struct envctrlunit *, uint8_t *);
static void	envctrl_abort_seq_handler(char *msg);
static uint8_t	envctrl_get_fpm_status(struct envctrlunit *);
static void	envctrl_set_fsp(struct envctrlunit *, uint8_t *);
static int	envctrl_set_dskled(struct envctrlunit *,
				struct envctrl_pcf8574_chip *);
static int	envctrl_get_dskled(struct envctrlunit *,
				struct envctrl_pcf8574_chip *);
static void	envctrl_probe_cpus(struct envctrlunit *);
static int	envctrl_match_cpu(dev_info_t *, void *);
static int	envctrl_isother_fault_led(struct envctrlunit *,
		    uint8_t, uint8_t);

/* Kstat routines */
static void	envctrl_add_kstats(struct envctrlunit *);
static int	envctrl_ps_kstat_update(kstat_t *, int);
static int	envctrl_fanstat_kstat_update(kstat_t *, int);
static int	envctrl_encl_kstat_update(kstat_t *, int);
static void	envctrl_init_fan_kstats(struct envctrlunit *);
static void	envctrl_init_encl_kstats(struct envctrlunit *);
static void	envctrl_add_encl_kstats(struct envctrlunit *, int, int,
			uint8_t);
static void	envctrl_mod_encl_kstats(struct envctrlunit *, int, int,
			uint8_t);


/* Streams Routines */
static int	envctrl_wput(queue_t *, mblk_t *);

/* External routines */
extern void power_down(const char *);
extern int prom_getprop();
extern int prom_getproplen();
extern	void	prom_printf(const char *fmt, ...);
extern void (*abort_seq_handler)();

static void    *envctrlsoft_statep;

/* Local Variables */
/* Indicates whether or not the overtemp thread has been started */
static int	envctrl_debug_flags = 0;
static int	envctrl_afb_present = 0;
static int	envctrl_power_off_overide = 0;
static int	envctrl_max_retries = 100;
static int	envctrl_allow_detach = 0;
static int	envctrl_numcpus = 1;
static int	envctrl_p0_enclosure = 0; /* set to 1 if it is a P0 */
static int envctrl_handler = 1; /* 1 is the default */
static clock_t overtemp_timeout_hz;
static clock_t blink_timeout_hz;
static clock_t pshotplug_timeout_hz;
static int controller_present[] = {-1, -1, -1};
#ifdef MULTIFAN
static int	envctrl_fan_debug = 0;
#endif
static int	eHc_debug = 0;
static int	power_supply_previous_state[] = {-1, -1, -1};

extern void	pci_thermal_rem_intr(dev_info_t *, uint_t);

#define	LOOP_TIMEOUT 25
#define	INIT_FAN_VAL 35
#define	DCMNERR if (eHc_debug & 0x1) cmn_err
#define	DCMN2ERR if (eHc_debug & 0x2) cmn_err
#define	MAX_FAN_FAIL_RETRY 3

uint8_t backaddrs[] = {ENVCTRL_PCF8574_DEV0, ENVCTRL_PCF8574_DEV1,
    ENVCTRL_PCF8574_DEV2};

struct module_info envctrlinfo = {
	/* id, name, min pkt siz, max pkt siz, hi water, low water */
	42, "envctrl", 0, 2048, (1024 * 20), (1024 * 1)
};

static struct qinit envctrl_rinit = {
	putq, NULL, envctrl_open, envctrl_close, NULL, &envctrlinfo, NULL
};

static struct qinit envctrl_wint = {
	envctrl_wput, NULL, envctrl_open, envctrl_close,
	    NULL, &envctrlinfo, NULL
};

struct streamtab envctrl_str_info = {
	&envctrl_rinit, &envctrl_wint, NULL, NULL
};

static struct cb_ops envctrl_cb_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&envctrl_str_info,	/* cb_stream */
	D_MP			/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  envctrl_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	envctrl_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	envctrl_attach,		/* devo_attach */
	envctrl_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&envctrl_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv envctrlmodldrv = {
	&mod_driverops,		/* type of module - driver */
	"I2C ENVCTRL_driver",
	&envctrl_ops,
};

static struct modlinkage envctrlmodlinkage = {
	MODREV_1,
	&envctrlmodldrv,
	0
};

/*
 * The following defines are for the i2c protocol routines.
 * This section of defines should be removed once the envctrl_targets.c
 * file is included.
 */

#define	EHC_SUCCESS 0
#define	EHC_FAILURE (-1)
#define	EHC_NO_SLAVE_ACK 3

#define	EHC_MAX_WAIT 7 /* decimal */

#define	EHC_S1_PIN 0x80
#define	EHC_S1_ES1 0x20
#define	EHC_S1_ES0 0x40
#define	EHC_S1_NBB 0x01
#define	EHC_S1_ACK 0x01
#define	EHC_S1_STA 0x04
#define	EHC_S1_STO 0x02
#define	EHC_S1_LRB 0x08
#define	EHC_S1_BER 0x10
#define	EHC_S1_LAB 0x02

#define	EHC_S0_OWN 0x55
#define	EHC_S0_CLK 0x1c

#define	EHC_BYTE_READ 0x01

#define	EHC_LONGEST_MSG 1000 /* decimal */

/*
 * PCF8591 Chip Used for temperature sensors
 *
 * Addressing Register definition.
 * A0-A2 valid range is 0-7
 *
 *  7    6  5   4    3     2     1      0
 * ------------------------------------------------
 * | 1 | 0 | 0 | 1 | A2 | A1 | A0 | R/W |
 * ------------------------------------------------
 */


#define	EHC_PCF8591_MAX_DEVS	0x08

#define	EHC_DEV0	0x00
#define	EHC_DEV1	0x02
#define	EHC_DEV2	0x04
#define	EHC_DEV3	0x06
#define	EHC_DEV4	0x08
#define	EHC_DEV5	0x0A
#define	EHC_DEV6	0x0C
#define	EHC_DEV7	0x0E


/*
 *		CONTROL OF CHIP
 * PCF8591 Temp sensing control register definitions
 *
 *   7      6     5   4  3   2      1   0
 * ---------------------------------------------
 * | 0 | AOE | X | X | 0 | AIF | X | X |
 * ---------------------------------------------
 * AOE = Analog out enable.. not used on out implementation
 * 5 & 4 = Analog Input Programming.. see data sheet for bits..
 *
 * AIF = Auto increment flag
 * bits 1 & 0 are for the Chennel number.
 */

#define	EHC_PCF8591_ANALOG_OUTPUT_EN	0x40
#define	EHC_PCF8591_ANALOG_INPUT_EN	0x00
#define	EHC_PCF8591_READ_BIT		0x01


#define	EHC_PCF8591_AUTO_INCR 0x04
#define	EHC_PCF8591_OSCILATOR 0x40

#define	EHC_PCF8591_MAX_PORTS	0x04

#define	EHC_PCF8591_CH_0	0x00
#define	EHC_PCF8591_CH_1	0x01
#define	EHC_PCF8591_CH_2	0x02
#define	EHC_PCF8591_CH_3	0x03


/*
 * PCF8574 Fan Fail, Power Supply Fail Detector
 * This device is driven by interrupts. Each time it interrupts
 * you must look at the CSR to see which ports caused the interrupt
 * they are indicated by a 1.
 *
 * Address map of this chip
 *
 * -------------------------------------------
 * | 0 | 1 | 1 | 1 | A2 | A1 | A0 | 0 |
 * -------------------------------------------
 *
 */

#define	EHC_PCF8574_PORT0	0x01
#define	EHC_PCF8574_PORT1	0x02
#define	EHC_PCF8574_PORT2	0x04
#define	EHC_PCF8574_PORT3	0x08
#define	EHC_PCF8574_PORT4	0x10
#define	EHC_PCF8574_PORT5	0x20
#define	EHC_PCF8574_PORT6	0x40
#define	EHC_PCF8574_PORT7	0x80

/*
 * Defines for the PCF8583 Clock Calendar Chip.
 */
#define	EHC_PCF8583_READ_BIT	0x01
#define	ALARM_CTR_REG_MINS	0x03
#define	ALARM_REG_MINS		0x0B
#define	ALARM_TIMER_REG		0x0F

struct eHc_pcd8584_regs {
	uint8_t s0;		/* Own Address S0' */
	uint8_t s1;		/* Control Status register */
	uint8_t clock_s2;	/* Clock programming register */
};

struct eHc_envcunit {
	struct eHc_pcd8584_regs *bus_ctl_regs;
	ddi_acc_handle_t ctlr_handle;
	kmutex_t umutex;
};


/*
 * Prototypes for static routines
 */

static int eHc_write_tda8444(struct eHc_envcunit *, int, int, int, uint8_t *,
	int);
static int eHc_read_pcf8591(struct eHc_envcunit *, int, int, int, int, int,
	uint8_t *, int);
static int eHc_read_pcf8574a(struct eHc_envcunit *, int, uint8_t *, int);
static int eHc_write_pcf8574a(struct eHc_envcunit *, int, uint8_t *, int);
static int eHc_read_pcf8574(struct eHc_envcunit *, int, uint8_t *, int);
static int eHc_write_pcf8574(struct eHc_envcunit *, int, uint8_t *, int);
static int eHc_read_lm75(struct eHc_envcunit *, int, uint8_t *, int);
static int eHc_write_pcf8583(struct eHc_envcunit *, int, uint8_t *, int);

static int eHc_start_pcf8584(struct eHc_envcunit *, uint8_t);
static void eHc_stop_pcf8584(struct eHc_envcunit *);
static int eHc_read_pcf8584(struct eHc_envcunit *, uint8_t *);
static int eHc_write_pcf8584(struct eHc_envcunit *, uint8_t);
static int eHc_after_read_pcf8584(struct eHc_envcunit *, uint8_t *);

/*
 * End of i2c protocol definitions section
 */

int
_init(void)
{
	int    error;

	if ((error = mod_install(&envctrlmodlinkage)) == 0) {
		(void) ddi_soft_state_init(&envctrlsoft_statep,
		    sizeof (struct envctrlunit), 1);
	}

	return (error);
}

int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&envctrlmodlinkage)) == 0)
		ddi_soft_state_fini(&envctrlsoft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&envctrlmodlinkage, modinfop));
}

static int
envctrl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	instance;
	char		name[16];
	uint8_t fspval;
	struct	envctrlunit *unitp;
	struct ddi_device_acc_attr attr;
	int *reg_prop;
	uchar_t *creg_prop;
	uint_t len, tblsz;
	int i, cputemp, status;
	uint8_t buf[3];

	status = len = tblsz = 0;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		if (!(unitp = ddi_get_soft_state(envctrlsoft_statep, instance)))
			return (DDI_FAILURE);
		mutex_enter(&unitp->umutex);
		if (!unitp->suspended) {
			mutex_exit(&unitp->umutex);
			return (DDI_FAILURE);
		}
		unitp->suspended = 0;
		mutex_exit(&unitp->umutex);
		unitp->initting = B_TRUE;
		envctrl_init_bus(unitp);
		unitp->initting = B_FALSE;

		mutex_enter(&unitp->umutex);
		envctrl_ps_probe(unitp);
		envctrl_probe_cpus(unitp);
		mutex_exit(&unitp->umutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* Set up timer values */
	overtemp_timeout_hz = drv_usectohz(OVERTEMP_TIMEOUT_USEC);
	blink_timeout_hz = drv_usectohz(BLINK_TIMEOUT_USEC);
	pshotplug_timeout_hz = drv_usectohz(BLINK_TIMEOUT_USEC * 6);

	if (ddi_soft_state_zalloc(envctrlsoft_statep, instance) != 0) {
		cmn_err(CE_WARN, "envctrl failed to zalloc softstate\n");
		goto failed;
	}

	unitp = ddi_get_soft_state(envctrlsoft_statep, instance);

	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&unitp->bus_ctl_regs, 0,
	    sizeof (struct envctrl_pcd8584_regs), &attr,
	    &unitp->ctlr_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "I2c failed to map in bus_control regs\n");
		return (DDI_FAILURE);
	}

	/*
	 * If the PCI nexus has added a thermal interrupt, we first need
	 * to remove that interrupt handler.
	 *
	 * WARNING: Removing another driver's interrupt handler is not
	 * allowed. The pci_thermal_rem_intr() call below is needed to retain
	 * the legacy behavior on Tazmo systems.
	 */

	pci_thermal_rem_intr(dip, (uint_t)0);

	/* add interrupts */

	if (ddi_get_iblock_cookie(dip, 1,
	    &unitp->ic_trap_cookie) != DDI_SUCCESS)  {
		cmn_err(CE_WARN, "ddi_get_iblock_cookie FAILED \n");
		goto failed;
	}

	mutex_init(&unitp->umutex, NULL, MUTEX_DRIVER,
	    (void *)unitp->ic_trap_cookie);


	if (ddi_add_intr(dip, 0, &unitp->ic_trap_cookie, NULL, envctrl_bus_isr,
	    (caddr_t)unitp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "envctrl_attach failed to add hard intr %d\n",
		    instance);
		goto remlock;
	}


	if (ddi_add_intr(dip, 1, &unitp->ic_trap_cookie, NULL, envctrl_dev_isr,
	    (caddr_t)unitp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "envctrl_attach failed to add hard intr %d\n",
		    instance);
		goto remhardintr;
	}


	(void) sprintf(name, "envctrl%d", instance);

	if (ddi_create_minor_node(dip, name, S_IFCHR, instance, DDI_PSEUDO,
	    0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		goto remhardintr1;
	}

	mutex_enter(&unitp->umutex);
	switch (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    ENVCTRL_LED_BLINK, -1)) {
	case 1:
		unitp->activity_led_blink = B_TRUE;
		break;
	case 0:
	default:
		unitp->activity_led_blink = B_FALSE;
		break;
	}
	unitp->shutdown = B_FALSE;
	unitp->num_ps_present = unitp->num_encl_present = 0;
	unitp->num_fans_present = MIN_FAN_BANKS;
	unitp->num_fans_failed = ENVCTRL_CHAR_ZERO;
	unitp->AFB_present = B_TRUE;
	unitp->dip = dip;

#ifdef	DEBUG
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ENVCTRL_PANEL_LEDS_PR,
	    &reg_prop, &len) == DDI_PROP_SUCCESS)
		ddi_prop_free((void *)reg_prop);
	ASSERT(len != 0);

	len = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ENVCTRL_PANEL_LEDS_STA,
	    &reg_prop, &len) == DDI_PROP_SUCCESS)
		ddi_prop_free((void *)reg_prop);
	ASSERT(len != 0);

	len = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, ENVCTRL_DISK_LEDS_STA,
	    &reg_prop, &len) == DDI_PROP_SUCCESS)
		ddi_prop_free((void *)reg_prop);
	ASSERT(len != 0);
#endif	/* DEBUG */

	/*
	 * if we have prom fan tables, overide the static tables in
	 * header file.
	 */

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cpu-fan-speeds",
	    &creg_prop, &len) == DDI_PROP_SUCCESS) {

		tblsz = (sizeof (acme_cpu_fanspd) / sizeof (short));

		if (len <= tblsz) {
			for (i = 0; i < len; i++) {
				acme_cpu_fanspd[i] = creg_prop[i];
			}
		}
		ddi_prop_free((void *)creg_prop);
	}

	len = 0;

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "ps-fan-speeds",
	    &creg_prop, &len) == DDI_PROP_SUCCESS) {

		tblsz = (sizeof (acme_ps_fanspd) / sizeof (short));

		if (len <= tblsz) {
			for (i = 0; i < len; i++) {
				acme_ps_fanspd[i] = creg_prop[i];
			}
		}
		ddi_prop_free((void *)creg_prop);
	}

	switch (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "fan-override", -1)) {
	case 1:
	case 2:
		unitp->AFB_present = B_TRUE;
		break;
	case 0:
	default:
		unitp->AFB_present = B_FALSE;
		break;
	}

	/* For debug */
	if (envctrl_afb_present) {
		unitp->AFB_present = B_TRUE;
	}

	if (unitp->AFB_present == B_TRUE)
		unitp->num_fans_present++;

	/* initialize the envctrl bus controller */
	mutex_exit(&unitp->umutex);

	unitp->initting = B_TRUE;
	envctrl_init_bus(unitp);
	unitp->initting = B_FALSE;
	drv_usecwait(1000);

	mutex_enter(&unitp->umutex);

	/* Initialize the PCF8583 eggtimer registers */
	buf[0] = ALARM_CTR_REG_MINS;
	buf[1] = 0x0;
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "write to PCF8583 failed\n");

	buf[0] = ALARM_REG_MINS;
	buf[1] = 0x58;
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "write to PCF8583 failed\n");

	buf[0] = ALARM_TIMER_REG;
	buf[1] = 0x80;
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "write to PCF8583 failed\n");

	unitp->timeout_id = 0;
	unitp->blink_timeout_id = 0;

	if (envctrl_numcpus > 1) {
		unitp->num_cpus_present = envctrl_numcpus;
	}
	envctrl_probe_cpus(unitp);
	envctrl_ps_probe(unitp);
	/*
	 * clear the fan failures, if any before we do
	 * real work
	 */

	unitp->initting = B_TRUE;
	envctrl_fan_fail_service(unitp);
	unitp->initting = B_FALSE;

	/*
	 * we need to init the fan kstats before the tempr_poll
	 */
	envctrl_add_kstats(unitp);
	envctrl_init_fan_kstats(unitp);
	envctrl_init_encl_kstats(unitp);
	if (unitp->activity_led_blink == B_TRUE) {
		unitp->present_led_state = B_FALSE;
		mutex_exit(&unitp->umutex);
		envctrl_led_blink((void *)unitp);
		mutex_enter(&unitp->umutex);
	} else {
		fspval = ENVCTRL_FSP_ACTIVE;
		envctrl_set_fsp(unitp, &fspval);
	}

#ifndef TESTBED
	for (i = 0; i < ENVCTRL_MAX_CPUS; i++) {
		if (unitp->cpu_pr_location[i] == B_TRUE) {
			cputemp = envctrl_get_cpu_temp(unitp, i);
			envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_CPUTEMPR,
			    i, cputemp);
			if (cputemp >= MAX_CPU_TEMP) {
				if (!(envctrl_power_off_overide)) {
					cmn_err(CE_WARN,
					    "CPU %d OVERHEATING!!", i);
					unitp->shutdown = B_TRUE;
				} else {
					cmn_err(CE_WARN,
					    "CPU %d OVERHEATING!!", i);
				}
			}
		}
	}
#else
	cputemp = envctrl_get_cpu_temp(unitp, 0);
	envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_CPUTEMPR, INSTANCE_0,
	    cputemp);
#endif
	mutex_exit(&unitp->umutex);

	envctrl_tempr_poll((void *)unitp);

	/*
	 * interpose envctrl's abort sequence handler
	 */
	if (envctrl_handler) {
		abort_seq_handler = envctrl_abort_seq_handler;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

remhardintr1:
	ddi_remove_intr(dip, (uint_t)1, unitp->ic_trap_cookie);
remhardintr:
	ddi_remove_intr(dip, (uint_t)0, unitp->ic_trap_cookie);

remlock:
	mutex_destroy(&unitp->umutex);

failed:
	if (unitp->ctlr_handle)
		ddi_regs_map_free(&unitp->ctlr_handle);

	cmn_err(CE_WARN, "envctrl_attach:failed.\n");

	return (DDI_FAILURE);

}

static int
envctrl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	struct envctrlunit *unitp;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(envctrlsoft_statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		if (envctrl_allow_detach) {

			if (unitp->psksp != NULL) {
				kstat_delete(unitp->psksp);
			}
			if (unitp->fanksp != NULL) {
				kstat_delete(unitp->fanksp);
			}
			if (unitp->enclksp != NULL) {
				kstat_delete(unitp->enclksp);
			}

			if (unitp->timeout_id != 0) {
				(void) untimeout(unitp->timeout_id);
				unitp->timeout_id = 0;
			}
			if (unitp->blink_timeout_id != 0) {
				(void) untimeout(unitp->blink_timeout_id);
				unitp->blink_timeout_id = 0;
			}

			ddi_remove_minor_node(dip, NULL);

			ddi_remove_intr(dip, (uint_t)0, unitp->ic_trap_cookie);
			ddi_remove_intr(dip, (uint_t)1, unitp->ic_trap_cookie);

			ddi_regs_map_free(&unitp->ctlr_handle);

			mutex_destroy(&unitp->umutex);

			return (DDI_SUCCESS);
		} else {
			return (DDI_FAILURE);
		}

	case DDI_SUSPEND:
		if (!(unitp = ddi_get_soft_state(envctrlsoft_statep, instance)))
			return (DDI_FAILURE);
		mutex_enter(&unitp->umutex);
		if (unitp->suspended) {
			cmn_err(CE_WARN, "envctrl already suspended\n");
			mutex_exit(&unitp->umutex);
			return (DDI_FAILURE);
		}
		unitp->suspended = 1;
		mutex_exit(&unitp->umutex);
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_WARN, "envctrl suspend general fault\n");
		return (DDI_FAILURE);
	}


}

/* ARGSUSED */
int
envctrl_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t	dev = (dev_t)arg;
	struct envctrlunit *unitp;
	int	ret;
	minor_t instance = getminor(dev);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			if ((unitp = (struct envctrlunit *)
			    ddi_get_soft_state(envctrlsoft_statep,
			    instance)) != NULL) {
				*result = unitp->dip;
				ret = DDI_SUCCESS;
			} else {
				*result = NULL;
				ret = DDI_FAILURE;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			ret = DDI_SUCCESS;
			break;
		default:
			ret = DDI_FAILURE;
			break;
	}

	return (ret);
}

/* ARGSUSED */
static int
envctrl_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *credp)
{
	struct envctrlunit *unitp;
	int status = 0;
	int	instance;

	instance = getminor(*dev);
	if (instance < 0)
		return (ENXIO);
	unitp = (struct envctrlunit *)
	    ddi_get_soft_state(envctrlsoft_statep, instance);

	if (unitp == NULL)
		return (ENXIO);

	mutex_enter(&unitp->umutex);

	if (flag & FWRITE) {
		if ((unitp->oflag & FWRITE)) {
			mutex_exit(&unitp->umutex);
			return (EBUSY);
		} else {
			unitp->oflag |= FWRITE;
		}
	}

	q->q_ptr = WR(q)->q_ptr = (caddr_t)unitp;

	/*
	 * if device is open with O_NONBLOCK flag set, let read(2) return 0
	 * if no data waiting to be read.  Writes will block on flow control.
	 */

	/* enable the stream */
	qprocson(q);

	unitp->readq = RD(q);
	unitp->writeq = WR(q);
	unitp->msg = (mblk_t *)NULL;

	mutex_exit(&unitp->umutex);
	return (status);
}

/* ARGSUSED */
static int
envctrl_close(queue_t *q, int flag, cred_t *cred_p)
{
	struct envctrlunit *unitp;

	unitp = (struct envctrlunit *)q->q_ptr;

	mutex_enter(&unitp->umutex);

	unitp->oflag = B_FALSE;
	unitp->current_mode = ENVCTRL_NORMAL_MODE;

	/* disable the stream */
	q->q_ptr = WR(q)->q_ptr = NULL;
	qprocsoff(q);

	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

/*
 * standard put procedure for envctrl
 */
static int
envctrl_wput(queue_t *q, mblk_t *mp)
{
	struct msgb *mp1;
	struct envctrlunit *unitp;
	struct iocblk *iocp;
	struct copyresp *csp;
	struct envctrl_tda8444t_chip *fanspeed;
	struct envctrl_pcf8574_chip *ledchip;
	struct envctrl_pcf8591_chip *temp, *a_fanspeed;
	struct copyreq *cqp;
	int cmd;

	unitp = (struct envctrlunit *)q->q_ptr;

	switch (DB_TYPE(mp)) {

	case M_DATA:

		while (mp) {
			DB_TYPE(mp) = M_DATA;
			mp1 = unlinkb(mp);
			mp->b_cont = NULL;
			if ((mp->b_wptr - mp->b_rptr) <= 0) {
				freemsg(mp);
			} else {
				(void) putq(q, mp);
			}
			mp = mp1;
		}

		break;

	case M_IOCTL:
	{
		iocp = (struct iocblk *)(void *)mp->b_rptr;
		cmd = iocp->ioc_cmd;

		switch (cmd) {
		case ENVCTRL_IOC_SETMODE:
		case ENVCTRL_IOC_GETMODE:
			if (iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (uchar_t), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_RESETTMPR:
			/*
			 * For diags, cancel the current temp poll
			 * and reset it for a new one.
			 */
			if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
				if (unitp->timeout_id != 0) {
					(void) untimeout(unitp->timeout_id);
					unitp->timeout_id = 0;
				}
				envctrl_tempr_poll((void *)unitp);
				miocack(q, mp, 0, 0);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_GETTEMP:
			if (iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (struct envctrl_pcf8591_chip), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_SETTEMP:
			if (unitp->current_mode == ENVCTRL_DIAG_MODE &&
			    iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (uint8_t), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_SETWDT:
			if (unitp->current_mode == ENVCTRL_DIAG_MODE &&
			    iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (uint8_t), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_SETFAN:
			/*
			 * we must be in diag mode before we can
			 * set any fan speeds.
			 */
			if (unitp->current_mode == ENVCTRL_DIAG_MODE &&
			    iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (struct envctrl_tda8444t_chip),
				    NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_GETFAN:
			if (iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (struct envctrl_pcf8591_chip), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_SETFSP:
			if (iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (uint8_t), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		case ENVCTRL_IOC_SETDSKLED:
		case ENVCTRL_IOC_GETDSKLED:
			if (iocp->ioc_count == TRANSPARENT) {
				mcopyin(mp, *(caddr_t *)mp->b_cont->b_rptr,
				    sizeof (struct envctrl_pcf8574_chip), NULL);
				qreply(q, mp);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		default:
			miocnak(q, mp, 0, EINVAL);
			break;
		}

		break;

	}
	case M_IOCDATA:
	{
		uint8_t *tempr, *wdval;
		long state;

		csp = (struct copyresp *)(void *)mp->b_rptr;

		/*
		 * If copy request failed, quit now
		 */
		if (csp->cp_rval != 0) {
			miocnak(q, mp, 0, EINVAL);
			return (0);
		}

		cqp = (struct copyreq *)(void *)mp->b_rptr;

		cmd = csp->cp_cmd;
		state = (long)cqp->cq_private;

		switch (cmd) {
		case ENVCTRL_IOC_SETFAN:
			fanspeed = (struct envctrl_tda8444t_chip *)
			    (void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			if (envctrl_xmit(unitp, (caddr_t *)(void *)fanspeed,
			    fanspeed->type) == DDI_FAILURE) {
				/*
				 * Fix for a ADF bug
				 * move mutex to after fan fail call
				 * bugid 4016121
				 */
				envctrl_fan_fail_service(unitp);
				mutex_exit(&unitp->umutex);
				miocnak(q, mp, 0, EINVAL);
			} else {
				mutex_exit(&unitp->umutex);
				miocack(q, mp, 0, 0);
			}
			break;
		case ENVCTRL_IOC_SETFSP:
			wdval = (uint8_t *)(void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			/*
			 * If a user is in normal mode and they try
			 * to set anything other than a disk fault or
			 * a gen fault it is an invalid operation.
			 * in diag mode we allow everything to be
			 * twiddled.
			 */
			if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
				if (*wdval & ~ENVCTRL_FSP_USRMASK) {
					mutex_exit(&unitp->umutex);
					miocnak(q, mp, 0, EINVAL);
					break;
				}
			}
			envctrl_set_fsp(unitp, wdval);
			mutex_exit(&unitp->umutex);
			miocack(q, mp, 0, 0);
			break;
		case ENVCTRL_IOC_SETDSKLED:
			ledchip = (struct envctrl_pcf8574_chip *)
			    (void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			if (envctrl_set_dskled(unitp, ledchip)) {
				miocnak(q, mp, 0, EINVAL);
			} else {
				miocack(q, mp, 0, 0);
			}
			mutex_exit(&unitp->umutex);
			break;
		case ENVCTRL_IOC_GETDSKLED:
			if (state  == -1) {
				miocack(q, mp, 0, 0);
				break;
			}
			ledchip = (struct envctrl_pcf8574_chip *)
			    (void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			if (envctrl_get_dskled(unitp, ledchip)) {
				miocnak(q, mp, 0, EINVAL);
			} else {
				mcopyout(mp, (void *)-1,
				    sizeof (struct envctrl_pcf8574_chip),
				    csp->cp_private, NULL);
				qreply(q, mp);
			}
			mutex_exit(&unitp->umutex);
			break;
		case ENVCTRL_IOC_GETTEMP:
			/* Get the user buffer address */

			if (state  == -1) {
				miocack(q, mp, 0, 0);
				break;
			}
			temp = (struct envctrl_pcf8591_chip *)
			    (void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			envctrl_recv(unitp, (caddr_t *)(void *)temp, PCF8591);
			mutex_exit(&unitp->umutex);
			mcopyout(mp, (void *)-1,
			    sizeof (struct envctrl_pcf8591_chip),
			    csp->cp_private, NULL);
			qreply(q, mp);
			break;
		case ENVCTRL_IOC_GETFAN:
			/* Get the user buffer address */

			if (state == -1) {
				miocack(q, mp, 0, 0);
				break;
			}
			a_fanspeed = (struct envctrl_pcf8591_chip *)
			    (void *)mp->b_cont->b_rptr;
			mutex_enter(&unitp->umutex);
			envctrl_recv(unitp, (caddr_t *)(void *)a_fanspeed,
			    PCF8591);
			mutex_exit(&unitp->umutex);
			mcopyout(mp, (void *)-1,
			    sizeof (struct envctrl_pcf8591_chip),
			    csp->cp_private, NULL);
			qreply(q, mp);
			break;
		case ENVCTRL_IOC_SETTEMP:
			tempr = (uint8_t *)(void *)mp->b_cont->b_rptr;
			if (*tempr > MAX_DIAG_TEMPR) {
				miocnak(q, mp, 0, EINVAL);
			} else {
				mutex_enter(&unitp->umutex);
				envctrl_get_sys_temperatures(unitp, tempr);
				mutex_exit(&unitp->umutex);
				miocack(q, mp, 0, 0);
			}
			break;
		case ENVCTRL_IOC_SETWDT:
			/* reset watchdog timeout period */
			wdval = (uint8_t *)(void *)mp->b_cont->b_rptr;
			if (*wdval > MAX_CL_VAL) {
				miocnak(q, mp, 0, EINVAL);
			} else {
				mutex_enter(&unitp->umutex);
				envctrl_reset_watchdog(unitp, wdval);
				mutex_exit(&unitp->umutex);
				miocack(q, mp, 0, 0);
			}
			break;
		case ENVCTRL_IOC_GETMODE:
			/* Get the user buffer address */

			if (state == -1) {
				miocack(q, mp, 0, 0);
				break;
			}
			tempr = (uchar_t *)(void *)mp->b_cont->b_rptr;
			*tempr = unitp->current_mode;
			mcopyout(mp, (void *)-1, sizeof (uchar_t),
			    csp->cp_private, NULL);
			qreply(q, mp);
			break;
		case ENVCTRL_IOC_SETMODE:
			/* Set mode */
			wdval = (uint8_t *)(void *)mp->b_cont->b_rptr;
			if (*wdval == ENVCTRL_DIAG_MODE || *wdval ==
			    ENVCTRL_NORMAL_MODE) {
				mutex_enter(&unitp->umutex);
				unitp->current_mode = *wdval;
				if (unitp->timeout_id != 0 &&
				    *wdval == ENVCTRL_DIAG_MODE) {
					(void) untimeout(unitp->timeout_id);
					unitp->timeout_id =
					    (timeout(envctrl_tempr_poll,
					    (caddr_t)unitp,
					    overtemp_timeout_hz));

				}
				if (*wdval == ENVCTRL_NORMAL_MODE) {
					envctrl_get_sys_temperatures(unitp,
					    (uint8_t *)NULL);
					/*
					 * going to normal mode we
					 * need to go to diag mode
					 * just in case we have
					 * injected a fan fault. It
					 * may not be cleared and if
					 * we call fan_failsrvc it will
					 * power off the ystem if we are
					 * in NORMAL_MODE. Also we need
					 * to delay 1 bit of time here
					 * to  allow the fans to rotate
					 * back up and clear the intr
					 * after we get the sys temps.
					 */
					unitp->current_mode =
					    ENVCTRL_DIAG_MODE;
					envctrl_fan_fail_service(unitp);
					unitp->current_mode =
					    ENVCTRL_NORMAL_MODE;
				}
				mutex_exit(&unitp->umutex);
				miocack(q, mp, 0, 0);
			} else {
				miocnak(q, mp, 0, EINVAL);
			}
			break;
		default:
			freemsg(mp);
			break;
		}

		break;
	}

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;

	default:
		freemsg(mp);
		break;
	}

	return (0);
}

uint_t
envctrl_bus_isr(caddr_t arg)
{
	struct envctrlunit *unitp = (struct envctrlunit *)(void *)arg;
	int ic = DDI_INTR_UNCLAIMED;

	mutex_enter(&unitp->umutex);

	/*
	 * NOT USED
	 */

	mutex_exit(&unitp->umutex);
	return (ic);
}

uint_t
envctrl_dev_isr(caddr_t arg)
{
	struct envctrlunit *unitp = (struct envctrlunit *)(void *)arg;
	uint8_t recv_data;
	int ic;
	int retrys = 0;
	int status;

	ic = DDI_INTR_UNCLAIMED;

	mutex_enter(&unitp->umutex);

	/*
	 * First check to see if it is an interrupt for us by
	 * looking at the "ganged" interrrupt and vector
	 * according to the major type
	 * 0x70 is the addr of the ganged interrupt controller.
	 * Address map for the port byte read is as follows
	 * MSB
	 * -------------------------
	 * |  |  |  |  |  |  |  |  |
	 * -------------------------
	 *  P7 P6 P5 P4 P3 P2 P1 P0
	 * P0 = Power Supply 1 intr
	 * P1 = Power Supply 2 intr
	 * P2 = Power Supply 3 intr
	 * P3 = Dlfop enable for fan sped set
	 * P4 = ENVCTRL_ Fan Fail intr
	 * P5 =	Front Panel Interrupt
	 * P6 = Power Fail Detect Low.
	 * P7 = Enable Interrupts to system
	 */

retry:

	status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
	    PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV0, &recv_data, 1);

	/*
	 * This extra read is needed since the first read is discarded
	 * and the second read seems to return 0xFF.
	 */
	if (recv_data == 0xFF) {
		status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
		    PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV0, &recv_data, 1);
	}
	if (envctrl_debug_flags)
		cmn_err(CE_WARN, "envctrl_dev_isr: status= %d, data = %x\n",
		    status, recv_data);

	/*
	 * if the i2c bus is hung it is imperative that this
	 * be cleared on an interrupt or else it will
	 * hang the system with continuous interrupts
	 */

	if (status == DDI_FAILURE) {
		drv_usecwait(1000);
		if (retrys < envctrl_max_retries) {
			retrys++;
			goto retry;
		} else {
			if (envctrl_debug_flags)
				cmn_err(CE_WARN,
				    "DEVISR FAILED received 0x%x\n", recv_data);
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			envctrl_ps_probe(unitp);
			mutex_exit(&unitp->umutex);
			ic = DDI_INTR_CLAIMED;
			return (ic);
		}
	}

	/*
	 * Port 0 = PS1 interrupt
	 * Port 1 = PS2 Interrupt
	 * Port 2 = PS3 Interrupt
	 * Port 3 = SPARE
	 * Port 4 = Fan Fail Intr
	 * Port 5 = Front Panle Module intr
	 * Port 6 = Keyswitch Intr
	 * Port 7 = ESINTR ENABLE ???
	 */

	if (!(recv_data & ENVCTRL_PCF8574_PORT0)) {
		envctrl_PS_intr_service(unitp, PS1);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT1)) {
		envctrl_PS_intr_service(unitp, PS2);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT2)) {
		envctrl_PS_intr_service(unitp, PS3);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT3)) {
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT4)) {
		/*
		 * Check for a fan fail
		 * Single fan fail
		 * shutdown system
		 */
		envctrl_fan_fail_service(unitp);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT5)) {
		(void) envctrl_get_fpm_status(unitp);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT6)) {
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT7)) {
		ic = DDI_INTR_CLAIMED;
	}

	if ((recv_data == 0xFF)) {
		ic = DDI_INTR_CLAIMED;
	}

	mutex_exit(&unitp->umutex);
	return (ic);

}

static void
envctrl_init_bus(struct envctrlunit *unitp)
{

	int i;
	uint8_t noval = 0;
	struct envctrl_tda8444t_chip fan;
	int fans[] = {ENVCTRL_CPU_FANS, ENVCTRL_PS_FANS, ENVCTRL_AFB_FANS};

	mutex_enter(&unitp->umutex);
	/* Sets the Mode to 808x type bus */
	ddi_put8(unitp->ctlr_handle,
	    &unitp->bus_ctl_regs->s0, ENVCTRL_CHAR_ZERO);

	/* SET UP SLAVE ADDR XXX Required..send 0x80 */

	ddi_put8(unitp->ctlr_handle, &unitp->bus_ctl_regs->s1,
	    ENVCTRL_BUS_INIT0);
	(void) ddi_put8(unitp->ctlr_handle, &unitp->bus_ctl_regs->s0,
	    ENVCTRL_BUS_INIT1);

	/* Set the clock now */
	ddi_put8(unitp->ctlr_handle,
	    &unitp->bus_ctl_regs->s1, ENVCTRL_BUS_CLOCK0);

	/* S0 is now S2  necause of the previous write to S1 */
	/* clock= 12MHz, SCL=90KHz */
	ddi_put8(unitp->ctlr_handle,
	    &unitp->bus_ctl_regs->s0, ENVCTRL_BUS_CLOCK1);

	/* Enable serial interface */
	ddi_put8(unitp->ctlr_handle,
	    &unitp->bus_ctl_regs->s1, ENVCTRL_BUS_ESI);

	envctrl_stop_clock(unitp);

	/*
	 * This has been added here because the DAC is powered
	 * on at "0". When the reset_dflop routine is called
	 * this switched the  fans from blast to DAC control.
	 * if the DAC is at "0", then the fans momentarily lose
	 * power until the temp polling and fan set routine is
	 * first called. If the fans lose power, then there is
	 * a fan fault generated and the system will power off.
	 * We only want to do this IF the bus is first being
	 * initted. This will cause errors in Sunvts if we reset
	 * the fan speed under normal operation. Sometimes we need
	 * to be able to induce fan faults. Init bus is a common
	 * routine to unwedge the i2c bus in some cases.
	 */

	if (unitp->initting == B_TRUE) {
		fan.chip_num = ENVCTRL_TDA8444T_DEV7;
		fan.val = INIT_FAN_VAL;

		for (i = 0; i < sizeof (fans)/sizeof (int); i++) {
			fan.fan_num = fans[i];
			if ((fans[i] == ENVCTRL_AFB_FANS) &&
			    (unitp->AFB_present == B_FALSE))
				continue;
			(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fan,
			    TDA8444T);
		}
	}

	envctrl_reset_dflop(unitp);

	envctrl_enable_devintrs(unitp);

	unitp->current_mode = ENVCTRL_NORMAL_MODE;
	envctrl_reset_watchdog(unitp, &noval);

	mutex_exit(&unitp->umutex);
}

static int
envctrl_xmit(struct envctrlunit *unitp, caddr_t *data, int chip_type)
{

	struct envctrl_tda8444t_chip *fanspeed;
	struct envctrl_pcf8574_chip *ioport;
	uint8_t slave_addr;
	uint8_t buf[2];
	int retrys = 0;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	switch (chip_type) {
	case TDA8444T:

		fanspeed = (struct envctrl_tda8444t_chip *)data;

		if (fanspeed->chip_num > ENVCTRL_FAN_ADDR_MAX) {
			return (DDI_FAILURE);
		}

		if (fanspeed->fan_num > ENVCTRL_PORT7) {
			return (DDI_FAILURE);
		}

		if (fanspeed->val > MAX_FAN_VAL) {
			return (DDI_FAILURE);
		}

retry0:
		slave_addr = (TDA8444T_BASE_ADDR | fanspeed->chip_num);
		buf[0] = fanspeed->val;

		status = eHc_write_tda8444((struct eHc_envcunit *)unitp,
		    TDA8444T_BASE_ADDR | fanspeed->chip_num, 0xF,
		    fanspeed->fan_num, buf, 1);
		if (status != DDI_SUCCESS) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
				goto retry0;
			} else {
				mutex_exit(&unitp->umutex);
				envctrl_init_bus(unitp);
				mutex_enter(&unitp->umutex);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN,
					    "envctrl_xmit: Write to TDA8444 " \
					    "failed\n");
				return (DDI_FAILURE);
			}
		}

		/*
		 * Update the kstats.
		 */
		switch (fanspeed->fan_num) {
		case ENVCTRL_CPU_FANS:
			unitp->fan_kstats[ENVCTRL_FAN_TYPE_CPU].fanspeed =
			    fanspeed->val;
			break;
		case ENVCTRL_PS_FANS:
			unitp->fan_kstats[ENVCTRL_FAN_TYPE_PS].fanspeed =
			    fanspeed->val;
			break;
		case ENVCTRL_AFB_FANS:
			unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fanspeed =
			    fanspeed->val;
			break;
		default:
			break;
		}
		break;
	case PCF8574:
		ioport = (struct envctrl_pcf8574_chip *)data;
		buf[0] = ioport->val;
		if (ioport->chip_num > ENVCTRL_PCF8574_DEV7)
			return (DDI_FAILURE);

retry:
		if (ioport->type == PCF8574A) {
			slave_addr = (PCF8574A_BASE_ADDR | ioport->chip_num);
			status =
			    eHc_write_pcf8574a((struct eHc_envcunit *)unitp,
			    PCF8574A_BASE_ADDR | ioport->chip_num, buf, 1);
		} else {
			slave_addr = (PCF8574_BASE_ADDR | ioport->chip_num);
			status = eHc_write_pcf8574((struct eHc_envcunit *)unitp,
			    PCF8574_BASE_ADDR | ioport->chip_num, buf, 1);
		}

		if (status != DDI_SUCCESS) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
				goto retry;
			} else {
				mutex_exit(&unitp->umutex);
				envctrl_init_bus(unitp);
				mutex_enter(&unitp->umutex);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN, "Write to PCF8574 " \
					    "failed, addr = %X\n", slave_addr);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN, "envctrl_xmit: PCF8574\
						dev = %d, port = %d\n",
					    ioport->chip_num, ioport->type);
				return (DDI_FAILURE);
			}
		}
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
envctrl_recv(struct envctrlunit *unitp, caddr_t *data, int chip_type)
{

	struct envctrl_pcf8591_chip *temp;
	struct envctrl_pcf8574_chip *ioport;
	uint8_t slave_addr, recv_data;
	int retrys = 0;
	int status;
	uint8_t buf[1];

	ASSERT(MUTEX_HELD(&unitp->umutex));

	switch (chip_type) {
	case PCF8591:
		temp = (struct envctrl_pcf8591_chip *)data;
		slave_addr = (PCF8591_BASE_ADDR | temp->chip_num);

retry:
		status = eHc_read_pcf8591((struct eHc_envcunit *)unitp,
		    PCF8591_BASE_ADDR | temp->chip_num & 0xF,
		    temp->sensor_num, 0, 0, 1, &recv_data, 1);

		/*
		 * another place to catch the i2c bus hang on an 8591 read
		 * In this instance we will just return the data that is read
		 * after the max_retry because this could be a valid value.
		 */
		if (status != DDI_SUCCESS) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
				goto retry;
			} else {
				mutex_exit(&unitp->umutex);
				envctrl_init_bus(unitp);
				mutex_enter(&unitp->umutex);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN, "Read from PCF8591 " \
					    "failed, slave_addr = %x\n",
					    slave_addr);
			}
		}
		temp->temp_val = recv_data;
		break;
	case TDA8444T:
		printf("envctrl_recv: attempting to read TDA8444T\n");
		return;
	case PCF8574:
		ioport = (struct envctrl_pcf8574_chip *)data;

retry1:
		if (ioport->chip_num > ENVCTRL_PCF8574_DEV7)
			cmn_err(CE_WARN, "envctrl: dev out of range 0x%x\n",
			    ioport->chip_num);

		if (ioport->type == PCF8574A) {
			slave_addr = (PCF8574_READ_BIT | PCF8574A_BASE_ADDR |
			    ioport->chip_num);
			status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
			    PCF8574A_BASE_ADDR | ioport->chip_num, buf, 1);
		} else {
			slave_addr = (PCF8574_READ_BIT | PCF8574_BASE_ADDR |
			    ioport->chip_num);
			status = eHc_read_pcf8574((struct eHc_envcunit *)unitp,
			    PCF8574_BASE_ADDR | ioport->chip_num, buf, 1);
		}

		if (status != DDI_SUCCESS) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
				goto retry1;
			} else {
				mutex_exit(&unitp->umutex);
				envctrl_init_bus(unitp);
				mutex_enter(&unitp->umutex);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN, "Read from PCF8574 "\
					    "failed, addr = %X\n", slave_addr);
				if (envctrl_debug_flags)
					cmn_err(CE_WARN, "envctrl_recv: PCF8574\
						dev = %d, port = %d\n",
					    ioport->chip_num, ioport->type);
			}
		}
		ioport->val = buf[0];
		break;
	default:
		break;
	}
}

static int
envctrl_get_ps_temp(struct envctrlunit *unitp, uint8_t psaddr)
{
	uint8_t tempr;
	int i, retrys;
	int status;
	uint8_t buf[4];

	ASSERT(MUTEX_HELD(&unitp->umutex));

	tempr = 0;
	retrys = 0;

retry:
	status = eHc_read_pcf8591((struct eHc_envcunit *)unitp,
	    PCF8591_BASE_ADDR | psaddr & 0xF, 0, 1, 0, 1, buf, 4);

	tempr = 0;
	for (i = 0; i < PCF8591_MAX_PORTS; i++) {
		/*
		 * The pcf8591 will return 0xff if no port
		 * is there.. this is bogus for setting temps.
		 * so just ignore it!
		 */
		if (envctrl_debug_flags) {
			cmn_err(CE_WARN, "PS addr 0x%x recvd 0x%x on port %d\n",
			    psaddr, buf[i], i);
		}
		if (buf[i] > tempr && buf[i] < MAX_PS_ADVAL) {
			tempr = buf[i];
		}
	}

	/*
	 * This routine is a safeguard to make sure that if the
	 * powersupply temps cannot be read that we do something
	 * to make sure that the system will notify the user and
	 * it will stay running with the fans at 100%. The calling
	 * routine should take care of that.
	 */
	if (status != DDI_SUCCESS) {
		drv_usecwait(1000);
		if (retrys < envctrl_max_retries) {
			retrys++;
			goto retry;
		} else {
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			if (envctrl_debug_flags)
				cmn_err(CE_WARN,
				    "Cannot read Power Supply Temps addr = %X",
				    psaddr);
			return (PS_DEFAULT_VAL);
		}
	}

	return (ps_temps[tempr]);
}

static int
envctrl_get_cpu_temp(struct envctrlunit *unitp, int cpunum)
{
	uint8_t recv_data;
	int retrys;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/*
	 * This routine takes in the number of the port that
	 * we want to read in the 8591. This should be the
	 * location of the COU thermistor for one of the 4
	 * cpu's. It will return the temperature in degrees C
	 * to the caller.
	 */

	retrys = 0;

retry:
	status = eHc_read_pcf8591((struct eHc_envcunit *)unitp,
	    PCF8591_BASE_ADDR | PCF8591_DEV7, cpunum, 0, 0, 0,
	    &recv_data, 1);

	/*
	 * We need to take a sledge hammer to the bus if we get back
	 * value of the chip. This means that the i2c bus got wedged.
	 * On the 1.4 systems this happens sometimes while running
	 * sunvts. We will return the max cpu temp minus 10 to make
	 * the fans run at full speed so that we don;t cook the
	 * system.
	 * At this point this is a workaround for hardware glitch.
	 */
	if (status == DDI_FAILURE) {
		drv_usecwait(1000);
		if (retrys < envctrl_max_retries) {
			retrys++;
			goto retry;
		} else {
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			if (envctrl_debug_flags)
				cmn_err(CE_WARN, "envctrl CPU TEMP read " \
				    "failed\n");
			/* we don't want to power off the system */
			return (MAX_CPU_TEMP - 10);
		}
	}

	return (cpu_temps[recv_data]);
}

static int
envctrl_get_lm75_temp(struct envctrlunit *unitp)
{

	int k;
	ushort_t lmval;
	uint8_t tmp1;
	uint8_t tmp2;
	int status;
	uint8_t buf[2];


	ASSERT(MUTEX_HELD(&unitp->umutex));

	status = eHc_read_lm75((struct eHc_envcunit *)unitp,
	    LM75_BASE_ADDR | LM75_CONFIG_ADDRA, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "read of LM75 failed\n");

	tmp1 = buf[0];
	tmp2 = buf[1];

	/*
	 * Store the forst 8 bits in the upper nibble of the
	 * short, then store the lower 8 bits in the lower nibble
	 * of the short, shift 7 to the right to get the 9 bit value
	 * that the lm75 is really sending.
	 */
	lmval = tmp1 << 8;
	lmval = (lmval | tmp2);
	lmval = (lmval >> 7);
	/*
	 * Check the 9th bit to see if it is a negative
	 * temperature. If so change into 2's compliment
	 * and divide by 2 since each value is equal to a
	 * half degree strp in degrees C
	 */
	if (lmval & LM75_COMP_MASK) {
		tmp1 = (lmval & LM75_COMP_MASK_UPPER);
		tmp1 = -tmp1;
		tmp1 = tmp1/2;
		k = 0 - tmp1;
	} else {
		k = lmval /2;
	}
	return (k);
}


static void
envctrl_tempr_poll(void *arg)
{
	int diag_flag = 0;
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	mutex_enter(&unitp->umutex);

	if (unitp->shutdown == B_TRUE) {
		(void) power_down("Fatal System Environmental Control Error");
	}

	/*
	 * if we are in diag mode and the temp poll thread goes off,
	 * this means that the system is too heavily loaded and the 60 second
	 * window to execute the test is failing. We will change the fanspeed
	 * but will not check for a fanfault. This will cause a system shutdown
	 * if the system has had a fanfault injected.
	 */
	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		diag_flag++;
		if (envctrl_debug_flags) {
			cmn_err(CE_WARN,
			    "Tempr poll went off while in DIAG MODE");
		}
	}
	unitp->current_mode = ENVCTRL_NORMAL_MODE;
	envctrl_get_sys_temperatures(unitp, (uint8_t *)NULL);
	if (diag_flag == 0) {
		envctrl_fan_fail_service(unitp);
	}
	/* now have this thread sleep for a while */
	unitp->timeout_id = (timeout(envctrl_tempr_poll,
	    (caddr_t)unitp, overtemp_timeout_hz));

	mutex_exit(&unitp->umutex);
}

static void
envctrl_led_blink(void *arg)
{
	struct envctrl_pcf8574_chip fspchip;
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	mutex_enter(&unitp->umutex);

	fspchip.type = PCF8574A;
	fspchip.chip_num = ENVCTRL_PCF8574_DEV6; /* 0x01 port 1 */
	envctrl_recv(unitp, (caddr_t *)(void *)&fspchip, PCF8574);

	if (unitp->present_led_state == B_TRUE) {
		/*
		 * Now we need to "or" in fault bits of the FSP
		 * module for the mass storage fault led.
		 * and set it.
		 */
		fspchip.val = (fspchip.val & ~(ENVCTRL_PCF8574_PORT4) |
		    0xC0);
		unitp->present_led_state = B_FALSE;
	} else {
		fspchip.val = (fspchip.val | ENVCTRL_PCF8574_PORT4 | 0xC0);
		unitp->present_led_state = B_TRUE;
	}

	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fspchip, PCF8574);

	/* now have this thread sleep for a while */
	unitp->blink_timeout_id = (timeout(envctrl_led_blink,
	    (caddr_t)unitp, blink_timeout_hz));

	mutex_exit(&unitp->umutex);
}

/* called with mutex held */
static void
envctrl_get_sys_temperatures(struct envctrlunit *unitp, uint8_t *diag_tempr)
{
	int temperature, tmptemp, cputemp, hicputemp, ambtemp;
	int i;
	struct envctrl_tda8444t_chip fan;
	uint8_t psaddr[] = {PSTEMP3, PSTEMP2, PSTEMP1, PSTEMP0};
	uint8_t noval = 0;
	uint8_t fspval;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	fan.fan_num = ENVCTRL_CPU_FANS;
	fan.chip_num = ENVCTRL_TDA8444T_DEV7;

	tmptemp = 0;	/* Right init value ?? */

	/*
	 * THis routine is caled once every minute
	 * we wil re-se the watchdog timer each time
	 * we poll the temps. The watchdog timer is
	 * set up for 3 minutes. Should the kernel thread
	 * wedge, for some reason the watchdog will go off
	 * and blast the fans.
	 */

	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		unitp->current_mode = ENVCTRL_NORMAL_MODE;
		envctrl_reset_watchdog(unitp, &noval);
		unitp->current_mode = ENVCTRL_DIAG_MODE;
	} else {
		envctrl_reset_watchdog(unitp, &noval);
	}

	/*
	 * we need to reset the dflop to allow the fans to be
	 * set if the watchdog goes of and the kernel resumes
	 * resetting the dflop alos resets the device interrupts
	 * we need to reenable them also.
	 */
	envctrl_reset_dflop(unitp);

	envctrl_enable_devintrs(unitp);

	/*
	 * If we are in diag mode we allow the system to be
	 * faked out as to what the temperature is
	 * to see if the fans speed up.
	 */
	if (unitp->current_mode == ENVCTRL_DIAG_MODE && diag_tempr != NULL) {
		if (unitp->timeout_id != 0) {
			(void) untimeout(unitp->timeout_id);
		}

		ambtemp = *diag_tempr;
		unitp->timeout_id = (timeout(envctrl_tempr_poll,
		    (caddr_t)unitp, overtemp_timeout_hz));
	} else {
		ambtemp = envctrl_get_lm75_temp(unitp);
		/*
		 * Sometimes when we read the temp it comes back bogus
		 * to fix this we just need to reset the envctrl bus
		 */
		if (ambtemp == -100) {
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			ambtemp = envctrl_get_lm75_temp(unitp);
		}
	}

	envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_AMBTEMPR, INSTANCE_0,
	    ambtemp);

	fspval = envctrl_get_fpm_status(unitp);

	if (ambtemp > MAX_AMB_TEMP) {
		fspval |= (ENVCTRL_FSP_TEMP_ERR | ENVCTRL_FSP_GEN_ERR);
		if (!(envctrl_power_off_overide) &&
		    unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			unitp->shutdown = B_TRUE;
		}
		if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			cmn_err(CE_WARN,
			    "Ambient Temperature is %d C, shutdown now\n",
			    ambtemp);
		}
	} else {
		if (envctrl_isother_fault_led(unitp, fspval,
		    ENVCTRL_FSP_TEMP_ERR)) {
			fspval &= ~(ENVCTRL_FSP_TEMP_ERR);
		} else {
			fspval &= ~(ENVCTRL_FSP_TEMP_ERR | ENVCTRL_FSP_GEN_ERR);
		}
	}

	envctrl_set_fsp(unitp, &fspval);

	cputemp = hicputemp = 0;
#ifndef TESTBED
	for (i = 0; i < ENVCTRL_MAX_CPUS; i++) {
		if (unitp->cpu_pr_location[i] == B_TRUE) {
			cputemp = envctrl_get_cpu_temp(unitp, i);
			envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_CPUTEMPR,
			    i, cputemp);
			if (cputemp >= MAX_CPU_TEMP) {
				if (!(envctrl_power_off_overide)) {
					unitp->shutdown = B_TRUE;
				}
				cmn_err(CE_WARN,
				    "CPU %d OVERHEATING!!!", i);
			}

			if (cputemp > hicputemp) {
				hicputemp = cputemp;
			}
		}
	}
#else
	cputemp = envctrl_get_cpu_temp(unitp, 0);
	envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_CPUTEMPR, 0, cputemp);
#endif

	fspval = envctrl_get_fpm_status(unitp);

	/*
	 * We first look at the ambient temp. If the system is at idle
	 * the cpu temps will be approx 20 degrees above ambient.
	 * If the cpu's rise above 20, then the CPU fans are set
	 * according to the cpu temp minus 20 degrees C.
	 */
	if (unitp->current_mode == ENVCTRL_DIAG_MODE && diag_tempr != NULL) {
		temperature = ambtemp;
	} else {
		temperature = hicputemp - CPU_AMB_RISE;
	}

	if (temperature < 0) {
		fan.val = MAX_FAN_SPEED;	/* blast it is out of range */
	} else if (temperature > MAX_AMB_TEMP) {
		fan.val = MAX_FAN_SPEED;
		fspval |= (ENVCTRL_FSP_TEMP_ERR | ENVCTRL_FSP_GEN_ERR);

		if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			cmn_err(CE_WARN,
			    "CPU Fans set to MAX. CPU Temp is %d C\n",
			    hicputemp);
		}
	} else if (ambtemp < MAX_AMB_TEMP) {
		if (!envctrl_p0_enclosure) {
			fan.val = acme_cpu_fanspd[temperature];
		} else {
			fan.val = fan_speed[temperature];
		}
		if (envctrl_isother_fault_led(unitp, fspval,
		    ENVCTRL_FSP_TEMP_ERR)) {
			fspval &= ~(ENVCTRL_FSP_TEMP_ERR);
		} else {
			fspval &= ~(ENVCTRL_FSP_TEMP_ERR | ENVCTRL_FSP_GEN_ERR);
		}
	}

	envctrl_set_fsp(unitp, &fspval);

	/*
	 * Update temperature kstats. FSP kstats are updated in the
	 * set and get routine.
	 */

	unitp->fan_kstats[ENVCTRL_FAN_TYPE_CPU].fanspeed = fan.val;

	/* CPU FANS */
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fan, TDA8444T);

	/* The afb Fan is always at max */
	if (unitp->AFB_present == B_TRUE) {
		fan.val = AFB_MAX;
		/* AFB FANS */
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fanspeed = fan.val;
		fan.fan_num = ENVCTRL_AFB_FANS;
		(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fan, TDA8444T);
	}

	/*
	 * Now set the Powersupply fans
	 */

	tmptemp = temperature = 0;
	for (i = 0; i <= MAXPS; i++) {
		if (unitp->ps_present[i]) {
			tmptemp = envctrl_get_ps_temp(unitp, psaddr[i]);
			unitp->ps_kstats[i].ps_tempr = tmptemp & 0xFFFF;
			if (tmptemp > temperature) {
				temperature = tmptemp;
			}
			if (temperature >= MAX_PS_TEMP) {
				if (!(envctrl_power_off_overide)) {
					unitp->shutdown = B_TRUE;
				}
				cmn_err(CE_WARN,
				    "Power Supply %d OVERHEATING!!!\
				    Temp is %d C", i, temperature);
			}
		}
	}


	fan.fan_num = ENVCTRL_PS_FANS;
	if (temperature > PS_TEMP_WARN) {
		fspval = envctrl_get_fpm_status(unitp);
		fspval |= (ENVCTRL_FSP_TEMP_ERR | ENVCTRL_FSP_GEN_ERR);
		envctrl_set_fsp(unitp, &fspval);
		fan.val = MAX_FAN_SPEED;
		cmn_err(CE_WARN, "A Power Supply is close to  OVERHEATING!!!");
	} else {
		if (temperature - ambtemp > PS_AMB_RISE) {
			ambtemp = temperature - PS_AMB_RISE;
		}
		if (!envctrl_p0_enclosure) {
			fan.val = acme_ps_fanspd[ambtemp];
		} else {
			fan.val = ps_fans[ambtemp];
		}
	}

	/*
	 * XXX add in error condition for ps overtemp
	 */

	unitp->fan_kstats[ENVCTRL_FAN_TYPE_PS].fanspeed = fan.val;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fan, TDA8444T);
}

/* called with mutex held */
static void
envctrl_fan_fail_service(struct envctrlunit *unitp)
{
	uint8_t recv_data, fpmstat;
	int fantype;
	int psfanflt, cpufanflt, afbfanflt;
	int retries = 0, max_retry_count;
	int status;

	psfanflt = cpufanflt = afbfanflt = 0;
	/*
	 * The fan fail sensor is located at address 0x70
	 * on the envctrl bus.
	 */

	ASSERT(MUTEX_HELD(&unitp->umutex));

retry:
	status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
	    PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV4, &recv_data, 1);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "fan_fail_service: status = %d, data = %x\n",
		    status, recv_data);

	/*
	 * If all fan ports are high (0xff) then we don't have any
	 * fan faults. Reset the kstats
	 */
	if (recv_data == 0xff) {
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_PS].fans_ok = B_TRUE;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_CPU].fans_ok = B_TRUE;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fans_ok = B_TRUE;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_PS].fanflt_num = 0;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_CPU].fanflt_num = 0;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fanflt_num = 0;
		unitp->num_fans_failed = 0;
		fpmstat = envctrl_get_fpm_status(unitp);
		if (!(envctrl_isother_fault_led(unitp, fpmstat, 0))) {
			fpmstat &= ~(ENVCTRL_FSP_GEN_ERR);
		}
		if (unitp->shutdown != B_TRUE) {
			envctrl_set_fsp(unitp, &fpmstat);
		}
		return;
	}

	fantype = ENVCTRL_FAN_TYPE_PS;

	if (!(recv_data & ENVCTRL_PCF8574_PORT0)) {
		psfanflt = PS_FAN_3;
	}
	if (!(recv_data & ENVCTRL_PCF8574_PORT1)) {
		psfanflt = PS_FAN_2;
	}
	if (!(recv_data & ENVCTRL_PCF8574_PORT2)) {
		psfanflt = PS_FAN_1;
	}

	if (psfanflt != 0) {
		unitp->fan_kstats[fantype].fans_ok = B_FALSE;
		unitp->fan_kstats[fantype].fanflt_num = psfanflt - 1;
		if (retries == MAX_FAN_FAIL_RETRY && status == DDI_SUCCESS &&
		    unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			cmn_err(CE_WARN, "PS Fan Number %d Failed",
			    psfanflt - 1);
		}
	} else {
		unitp->fan_kstats[fantype].fans_ok = B_TRUE;
		unitp->fan_kstats[fantype].fanflt_num = 0;
	}

	fantype = ENVCTRL_FAN_TYPE_CPU;

	if (!(recv_data & ENVCTRL_PCF8574_PORT3)) {
		cpufanflt = CPU_FAN_1;
	}
	if (!(recv_data & ENVCTRL_PCF8574_PORT4)) {
		cpufanflt = CPU_FAN_2;
	}
	if (!(recv_data & ENVCTRL_PCF8574_PORT5)) {
		cpufanflt = CPU_FAN_3;
	}

	if (cpufanflt != 0) {
		unitp->fan_kstats[fantype].fans_ok = B_FALSE;
		unitp->fan_kstats[fantype].fanflt_num = cpufanflt - 1;
		if (retries == MAX_FAN_FAIL_RETRY && status == DDI_SUCCESS &&
		    unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			cmn_err(CE_WARN, "CPU Fan Number %d Failed",
			    cpufanflt - 1);
		}
	} else {
		unitp->fan_kstats[fantype].fans_ok = B_TRUE;
		unitp->fan_kstats[fantype].fanflt_num = 0;
	}

	if (!(recv_data & ENVCTRL_PCF8574_PORT6) &&
	    (unitp->AFB_present == B_TRUE)) {
		/*
		 * If the afb is present and the afb fan fails,
		 * we need to power off or else it will melt!
		 * If it isn't present just log the error.
		 * We make the decision off of the afbfanflt
		 * flag later on in an if statement.
		 */
		afbfanflt++;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fans_ok
		    = B_FALSE;
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].fanflt_num =
		    AFB_FAN_1;
		if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			cmn_err(CE_WARN, "AFB Fan Failed");
		}

	}

	/*
	 * If we have no Fan Faults Clear the LED's
	 * If we have fan faults set the Gen Fault LED.
	 */
	if (psfanflt == 0 && cpufanflt == 0 && afbfanflt == 0 &&
	    unitp->num_fans_failed != 0) {
		fpmstat = envctrl_get_fpm_status(unitp);
		if (!(envctrl_isother_fault_led(unitp,
		    fpmstat, 0))) {
			fpmstat &= ~(ENVCTRL_FSP_GEN_ERR);
		}
		envctrl_set_fsp(unitp, &fpmstat);
	} else if (psfanflt != 0 || cpufanflt != 0 || afbfanflt != 0) {
		fpmstat = envctrl_get_fpm_status(unitp);
		fpmstat |= ENVCTRL_FSP_GEN_ERR;
		envctrl_set_fsp(unitp, &fpmstat);
	}

	if (unitp->AFB_present == B_FALSE) {
		afbfanflt = 0;
	}

	if ((cpufanflt > 0 || psfanflt > 0 || afbfanflt > 0 ||
	    (status != DDI_SUCCESS)) && !unitp->initting &&
	    unitp->current_mode == ENVCTRL_NORMAL_MODE) {
		if (status != DDI_SUCCESS)
			max_retry_count = envctrl_max_retries;
		else
			max_retry_count = MAX_FAN_FAIL_RETRY;
		if (retries <= max_retry_count) {
			retries++;
			drv_usecwait(1000);
			if (retries == max_retry_count) {
				cmn_err(CE_WARN,
				    "Fan Fail is 0x%x, retries = %d\n",
				    recv_data, retries);
			}
			envctrl_get_sys_temperatures(unitp,
			    (uint8_t *)NULL);
			goto retry;
		}
		if (!(envctrl_power_off_overide)) {
			unitp->shutdown = B_TRUE;
		}
		cmn_err(CE_WARN, "Fan Failure(s), System Shutdown");
	}

	unitp->num_fans_failed = (psfanflt + cpufanflt + afbfanflt);

}

/*
 * Check for power supply insertion and failure.
 * This is a bit tricky, because a power supply insertion will
 * trigger a load share interrupt as well as PS present in the
 * new supply. if we detect an insertion clear
 * interrupts, disable interrupts, wait for a couple of seconds
 * come back and see if the PSOK bit is set, PS_PRESENT is set
 * and the share fail interrupts are gone. If not this is a
 * real load share fail event.
 * Called with mutex held
 */

static void
envctrl_PS_intr_service(struct envctrlunit *unitp, uint8_t psaddr)
{
	uint8_t recv_data;
	int status, retrys = 0;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		return;
	}

retry:
	status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
	    PCF8574A_BASE_ADDR | psaddr & 0xF, &recv_data, 1);
	if (status != DDI_SUCCESS) {
		drv_usecwait(1000);
		if (retrys < envctrl_max_retries) {
			retrys++;
			goto retry;
		} else {
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			if (envctrl_debug_flags)
				cmn_err(CE_WARN,
				    "PS_intr_service: Read from 8574A " \
				"failed\n");
		}
	}

	/*
	 * setup a timeout thread to poll the ps after a
	 * couple of seconds. This allows for the PS to settle
	 * and doesn't report false errors on a hotplug
	 */

	unitp->pshotplug_id = (timeout(envctrl_pshotplug_poll,
	    (caddr_t)unitp, pshotplug_timeout_hz));

}

/* called with mutex held */
static void
envctrl_reset_dflop(struct envctrlunit *unitp)
{
	struct envctrl_pcf8574_chip initval;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/*
	 * This initialization sequence allows a
	 * to change state to stop the fans from
	 * blastion upon poweron. If this isn't
	 * done the writes to the 8444 will not complete
	 * to the hardware because the dflop will
	 * be closed
	 */
	initval.chip_num = ENVCTRL_PCF8574_DEV0; /* 0x01 port 1 */
	initval.type = PCF8574A;

	initval.val = ENVCTRL_DFLOP_INIT0;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&initval, PCF8574);

	initval.val = ENVCTRL_DFLOP_INIT1;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&initval, PCF8574);
}

static void
envctrl_add_encl_kstats(struct envctrlunit *unitp, int type,
    int instance, uint8_t val)
{
	int i = 0;
	boolean_t inserted = B_FALSE;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	while (i < MAX_DEVS && inserted == B_FALSE) {
		if (unitp->encl_kstats[i].instance == I2C_NODEV) {
			unitp->encl_kstats[i].instance = instance;
			unitp->encl_kstats[i].type = type;
			unitp->encl_kstats[i].value = val;
			inserted = B_TRUE;
		}
		i++;
	}
	unitp->num_encl_present++;
}

/* called with mutex held */
static void
envctrl_enable_devintrs(struct envctrlunit *unitp)
{
	struct envctrl_pcf8574_chip initval;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/*
	 * This initialization sequence allows a
	 * to change state to stop the fans from
	 * blastion upon poweron. If this isn't
	 * done the writes to the 8444 will not complete
	 * to the hardware because the dflop will
	 * be closed
	 */
	initval.chip_num = ENVCTRL_PCF8574_DEV0; /* 0x01 port 1 */
	initval.type = PCF8574A;

	initval.val = ENVCTRL_DEVINTR_INTI0;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&initval, PCF8574);

	/*
	 * set lowerbits all high p0 = PS1, p1 = PS2
	 * p2 = PS3 p4 = envctrl intr_ctrl
	 */
	initval.val = ENVCTRL_DEVINTR_INTI1;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&initval, PCF8574);
}

/* called with mutex held */
static void
envctrl_stop_clock(struct envctrlunit *unitp)
{
	int status;
	uint8_t buf[2];

	/*
	 * This routine talks to the PCF8583 which
	 * is a clock calendar chip on the envctrl bus.
	 * We use this chip as a watchdog timer for the
	 * fan control. At reset this chip pulses the interrupt
	 * line every 1 second. We need to be able to shut
	 * this off.
	 */

	ASSERT(MUTEX_HELD(&unitp->umutex));

	buf[0] = CLOCK_CSR_REG;
	buf[1] = CLOCK_DISABLE;

	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "write to PCF8583 failed\n");
}

static void
envctrl_reset_watchdog(struct envctrlunit *unitp, uint8_t *wdval)
{

	uint8_t w, r;
	uint8_t res = 0;
	int status;
	uint8_t buf[3];

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/* the clock MUST be stopped before we re-set it */
	envctrl_stop_clock(unitp);

	/*
	 * Reset the minutes counter to 0.
	 */
	buf[0] = ALARM_CTR_REG_MINS;
	buf[1] = 0x0;
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "write to PCF8583 failed\n");

	/*
	 * set up the alarm timer for 3 minutes
	 * start by setting reg 8 ALARM_CTRL_REG
	 * If we are in diag mode, we set the timer in
	 * seconds. Valid values are 40-99. The timer
	 * counts up to 99. 40 would be 59 seconds
	 */
	buf[0] = CLOCK_ALARM_REG_A;
	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		if (unitp->timeout_id != 0) {
			(void) untimeout(unitp->timeout_id);
			unitp->timeout_id = 0;
			unitp->timeout_id = (timeout(envctrl_tempr_poll,
			    (caddr_t)unitp, overtemp_timeout_hz));
		}
		buf[1] = CLOCK_ENABLE_TIMER_S;
	} else {
		buf[1] = CLOCK_ENABLE_TIMER;
	}

	/* STEP 10: End Transmission */
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "Reset envctrl watchdog failed\n");

	/*
	 * Now set up the alarm timer register it
	 * counts from 0-99 with an intr triggered
	 * when it gets to overflow.. or 99. It will
	 * also count from a pre-set value which is
	 * where we are seting from. We want a 3 minute fail
	 * safe so our value is 99-3 or 96.
	 * we are programming register 7 in the 8583.
	 */

	buf[0] = ALARM_CTRL_REG;
	/*
	 * Allow the diagnostic to set the egg timer val.
	 * never allow it to be set greater than the default.
	 */
	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		if (*wdval > MAX_CL_VAL) {
			buf[1] = EGG_TIMER_VAL;
		} else {

			w = *wdval/10;
			r = *wdval%10;

			res = res | r;
			res = (0x99 - (res | (w << 4)));
			buf[1] = res;
		}
	} else {
		buf[1] = EGG_TIMER_VAL;
	}

	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "Reset envctrl watchdog failed\n");


	/*
	 * Now that we have set up.. it is time
	 * to re-start the clock in the CSR.
	 */

	buf[0] = CLOCK_CSR_REG;
	buf[1] = CLOCK_ENABLE;
	status = eHc_write_pcf8583((struct eHc_envcunit *)unitp,
	    PCF8583_BASE_ADDR | 0, buf, 2);
	if (status != DDI_SUCCESS)
		cmn_err(CE_WARN, "Reset envctrl watchdog failed\n");

}

/* Called with unip mutex held */
static void
envctrl_ps_probe(struct envctrlunit *unitp)
{

	uint8_t recv_data, fpmstat;
	uint8_t psaddr[] = {PS1, PS2, PS3, PSTEMP0};
	int i;
	int ps_error = 0, retrys = 0;
	int devaddr;
	int status;
	int twotimes = 0;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	unitp->num_ps_present = 0;

	for (i = 0; i <= MAXPS; i++) {
		unitp->ps_present[i] = B_FALSE;
		unitp->ps_kstats[i].ps_rating = 0;
		unitp->ps_kstats[i].ps_tempr = 0;

		switch (psaddr[i]) {
		case PS1:
			devaddr = ENVCTRL_PCF8574_DEV3;
			break;
		case PS2:
			devaddr = ENVCTRL_PCF8574_DEV2;
			break;
		case PS3:
			devaddr = ENVCTRL_PCF8574_DEV1;
			break;
		case PSTEMP0:
			devaddr = 0;
			break;
		}
		retrys = 0;
retry:
		status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
		    PCF8574A_BASE_ADDR | devaddr, &recv_data, 1);
		if (status != DDI_SUCCESS) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
				goto retry;
			} else {
				mutex_exit(&unitp->umutex);
				envctrl_init_bus(unitp);
				mutex_enter(&unitp->umutex);
				/*
				 * If we just reset the bus we need to reread
				 * the status.  If a second attempt still fails
				 * then report the read failure.
				 */
				if (twotimes == 0) {
					twotimes++;
					retrys = 0;
					goto retry;
				} else {
					cmn_err(CE_WARN,
					"PS_probe: Read from 8574A failed\n");
				}
			}
		}

		/*
		 * Port 0 = PS Present
		 * Port 1 = PS Type
		 * Port 2 = PS Type
		 * Port 3 = PS TYpe
		 * Port 4 = DC Status
		 * Port 5 = Current Limit
		 * Port 6 = Current Share
		 * Port 7 = SPARE
		 */

		/*
		 * Port 0 = PS Present
		 * Port is pulled LOW "0" to indicate
		 * present.
		 */

		if (!(recv_data & ENVCTRL_PCF8574_PORT0)) {
			unitp->ps_present[i] = B_TRUE;
			/* update unit kstat array */
			unitp->ps_kstats[i].instance = i;
			unitp->ps_kstats[i].ps_tempr = ENVCTRL_INIT_TEMPR;
			++unitp->num_ps_present;

			if (power_supply_previous_state[i] == 0) {
				cmn_err(CE_NOTE,
				    "Power Supply %d inserted\n", i);
			}
			power_supply_previous_state[i] = 1;

			if (!(recv_data & ENVCTRL_PCF8574_PORT1)) {
				unitp->ps_kstats[i].ps_rating = ENVCTRL_PS_550;
			}
			if (!(recv_data & ENVCTRL_PCF8574_PORT2)) {
				unitp->ps_kstats[i].ps_rating = ENVCTRL_PS_650;
			}
			if (!(recv_data & ENVCTRL_PCF8574_PORT3)) {
				cmn_err(CE_WARN,
				    "Power Supply %d NOT okay\n", i);
				unitp->ps_kstats[i].ps_ok = B_FALSE;
				ps_error++;
			} else {
				unitp->ps_kstats[i].ps_ok = B_TRUE;
			}
			if (!(recv_data & ENVCTRL_PCF8574_PORT4)) {
				cmn_err(CE_WARN,
				    "Power Supply %d Overloaded\n", i);
				unitp->ps_kstats[i].limit_ok = B_FALSE;
				ps_error++;
			} else {
				unitp->ps_kstats[i].limit_ok = B_TRUE;
			}
			if (!(recv_data & ENVCTRL_PCF8574_PORT5)) {
				cmn_err(CE_WARN,
				    "Power Supply %d load share err\n", i);
				unitp->ps_kstats[i].curr_share_ok = B_FALSE;
				ps_error++;
			} else {
				unitp->ps_kstats[i].curr_share_ok = B_TRUE;
			}

			if (!(recv_data & ENVCTRL_PCF8574_PORT6)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}

			if (!(recv_data & ENVCTRL_PCF8574_PORT7)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}
		} else {
			/* No power supply present */
			if (power_supply_previous_state[i] == 1) {
				cmn_err(CE_NOTE,
				    "Power Supply %d removed\n", i);
			}
			power_supply_previous_state[i] = 0;
		}
	}

	fpmstat = envctrl_get_fpm_status(unitp);
	if (ps_error) {
		fpmstat |= (ENVCTRL_FSP_PS_ERR | ENVCTRL_FSP_GEN_ERR);
	} else {
		if (envctrl_isother_fault_led(unitp, fpmstat,
		    ENVCTRL_FSP_PS_ERR)) {
			fpmstat &= ~(ENVCTRL_FSP_PS_ERR);
		} else {
			fpmstat &= ~(ENVCTRL_FSP_PS_ERR |
			    ENVCTRL_FSP_GEN_ERR);
		}

	}
	envctrl_set_fsp(unitp, &fpmstat);

	/*
	 * We need to reset all of the fans etc when a supply is
	 * interrupted and added, but we don't want to reset the
	 * fans if we are in DIAG mode. This will mess up SUNVTS.
	 */
	if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
		envctrl_get_sys_temperatures(unitp, (uint8_t *)NULL);
	}
}

/*
 * consider key switch position when handling an abort sequence
 */
static void
envctrl_abort_seq_handler(char *msg)
{
	struct envctrlunit *unitp;
	int i;
	uint8_t secure = 0;

	/*
	 * Find the instance of the device available on this host.
	 * Note that there may be only one, but the instance may
	 * not be zero.
	 */
	for (i = 0; i < MAX_DEVS; i++) {
		if (unitp = (struct envctrlunit *)
		    ddi_get_soft_state(envctrlsoft_statep, i))
			break;
	}

	ASSERT(unitp);

	for (i = 0; i < MAX_DEVS; i++) {
		if ((unitp->encl_kstats[i].type == ENVCTRL_ENCL_FSP) &&
		    (unitp->encl_kstats[i].instance != I2C_NODEV)) {
			secure = unitp->encl_kstats[i].value;
			break;
		}
	}

	/*
	 * take the logical not because we are in hardware mode only
	 */

	if ((secure & ENVCTRL_FSP_KEYMASK) == ENVCTRL_FSP_KEYLOCKED) {
			cmn_err(CE_CONT,
			    "!envctrl: ignoring debug enter sequence\n");
	} else {
		if (envctrl_debug_flags) {
			cmn_err(CE_CONT, "!envctrl: allowing debug enter\n");
		}
		debug_enter(msg);
	}
}

/*
 * get the front Panel module LED and keyswitch status.
 * this part is addressed at 0x7C on the i2c bus.
 * called with mutex held
 */
static uint8_t
envctrl_get_fpm_status(struct envctrlunit *unitp)
{
	uint8_t recv_data;
	int status, retrys = 0;

	ASSERT(MUTEX_HELD(&unitp->umutex));

retry:
	status = eHc_read_pcf8574a((struct eHc_envcunit *)unitp,
	    PCF8574A_BASE_ADDR | ENVCTRL_PCF8574_DEV6, &recv_data, 1);

	/*
	 * yet another place where a read can cause the
	 * the SDA line of the i2c bus to get stuck low.
	 * this funky sequence frees the SDA line.
	 */
	if (status != DDI_SUCCESS) {
		drv_usecwait(1000);
		if (retrys < envctrl_max_retries) {
			retrys++;
			goto retry;
		} else {
			mutex_exit(&unitp->umutex);
			envctrl_init_bus(unitp);
			mutex_enter(&unitp->umutex);
			if (envctrl_debug_flags)
				cmn_err(CE_WARN, "Read from PCF8574 (FPM) "\
				    "failed\n");
		}
	}
	recv_data = ~recv_data;
	envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_FSP,
	    INSTANCE_0, recv_data);

	return (recv_data);
}

static void
envctrl_set_fsp(struct envctrlunit *unitp, uint8_t *val)
{
	struct envctrl_pcf8574_chip chip;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	chip.val = ENVCTRL_FSP_OFF; /* init all values to off */
	chip.chip_num = ENVCTRL_PCF8574_DEV6; /* 0x01 port 1 */
	chip.type = PCF8574A;

	/*
	 * strip off bits that are R/O
	 */
	chip.val = (~(ENVCTRL_FSP_KEYMASK | ENVCTRL_FSP_POMASK) & (*val));

	chip.val = ~chip.val;
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&chip, PCF8574);

}

static int
envctrl_get_dskled(struct envctrlunit *unitp, struct envctrl_pcf8574_chip *chip)
{
	uint_t oldtype;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (chip->chip_num > ENVCTRL_PCF8574_DEV2 ||
	    chip->type != ENVCTRL_ENCL_BACKPLANE4 &&
	    chip->type != ENVCTRL_ENCL_BACKPLANE8) {
		return (DDI_FAILURE);
	}
	oldtype = chip->type;
	chip->type = PCF8574;
	envctrl_recv(unitp, (caddr_t *)(void *)chip, PCF8574);
	chip->type = oldtype;
	chip->val = ~chip->val;

	return (DDI_SUCCESS);
}
static int
envctrl_set_dskled(struct envctrlunit *unitp, struct envctrl_pcf8574_chip *chip)
{

	struct envctrl_pcf8574_chip fspchip;
	struct envctrl_pcf8574_chip backchip;
	int i, instance;
	int diskfault = 0;
	uint8_t controller_addr[] = {ENVCTRL_PCF8574_DEV0, ENVCTRL_PCF8574_DEV1,
	    ENVCTRL_PCF8574_DEV2};

	/*
	 * We need to check the type of disk led being set. If it
	 * is a 4 slot backplane then the upper 4 bits (7, 6, 5, 4) are
	 * invalid.
	 */
	ASSERT(MUTEX_HELD(&unitp->umutex));


	if (chip->chip_num > ENVCTRL_PCF8574_DEV2 ||
	    chip->val > ENVCTRL_DISK8LED_ALLOFF ||
	    chip->val < ENVCTRL_CHAR_ZERO) {
		return (DDI_FAILURE);
	}

	if (chip->type != ENVCTRL_ENCL_BACKPLANE4 &&
	    chip->type != ENVCTRL_ENCL_BACKPLANE8) {
		return (DDI_FAILURE);
	}

	/*
	 * Check all of the other controllwes LED states to make sure
	 * that there are no disk faults. If so then if the user is
	 * clearing the disk faults on this contoller, turn off
	 * the mass storage fault led.
	 */

	backchip.type = PCF8574;
	for (i = 0; i <= MAX_TAZ_CONTROLLERS; i++) {
		if (controller_present[i] == -1)
			continue;
		backchip.chip_num = controller_addr[i];
		envctrl_recv(unitp, (caddr_t *)(void *)&backchip, PCF8574);
		if (chip->chip_num == controller_addr[i]) {
			if (chip->val != ENVCTRL_CHAR_ZERO)
				diskfault++;
		} else if ((~backchip.val & 0xFF) != ENVCTRL_CHAR_ZERO) {
			diskfault++;
		}
	}

	fspchip.type = PCF8574A;
	fspchip.chip_num = ENVCTRL_PCF8574_DEV6; /* 0x01 port 1 */
	envctrl_recv(unitp, (caddr_t *)(void *)&fspchip, PCF8574);

	if (diskfault) {
		if (!(envctrl_isother_fault_led(unitp, fspchip.val & 0xFF,
		    ENVCTRL_FSP_DISK_ERR))) {
			fspchip.val &= ~(ENVCTRL_FSP_DISK_ERR);
		} else {
			fspchip.val &= ~(ENVCTRL_FSP_DISK_ERR |
			    ENVCTRL_FSP_GEN_ERR);
		}
		fspchip.val = (fspchip.val &
		    ~(ENVCTRL_FSP_DISK_ERR | ENVCTRL_FSP_GEN_ERR));
	} else {
		fspchip.val = (fspchip.val |
		    (ENVCTRL_FSP_DISK_ERR | ENVCTRL_FSP_GEN_ERR));
	}
	fspchip.type = PCF8574A;
	fspchip.chip_num = ENVCTRL_PCF8574_DEV6; /* 0x01 port 1 */
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)&fspchip, PCF8574);

	for (i = 0; i < (sizeof (backaddrs) / sizeof (uint8_t)); i++) {
		if (chip->chip_num == backaddrs[i]) {
			instance =  i;
		}
	}

	switch (chip->type) {
	case ENVCTRL_ENCL_BACKPLANE4:
		envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_BACKPLANE4,
		    instance, chip->val);
		break;
	case ENVCTRL_ENCL_BACKPLANE8:
		envctrl_mod_encl_kstats(unitp, ENVCTRL_ENCL_BACKPLANE8,
		    instance, chip->val);
		break;
	default:
		break;
	}
	chip->type = PCF8574;
	/*
	 * we take the ones compliment of the val passed in
	 * because the hardware thinks that a "low" or "0"
	 * is the way to indicate a fault. of course software
	 * knows that a 1 is a TRUE state or fault. ;-)
	 */
	chip->val = ~(chip->val);
	(void) envctrl_xmit(unitp, (caddr_t *)(void *)chip, PCF8574);
	return (DDI_SUCCESS);
}

void
envctrl_add_kstats(struct envctrlunit *unitp)
{

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if ((unitp->enclksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_ENCL, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->encl_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "envctrl%d: encl raw kstat_create failed",
		    unitp->instance);
		return;
	}

	unitp->enclksp->ks_update = envctrl_encl_kstat_update;
	unitp->enclksp->ks_private = (void *)unitp;
	kstat_install(unitp->enclksp);


	if ((unitp->fanksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_FANSTAT, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->fan_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "envctrl%d: fans kstat_create failed",
		    unitp->instance);
		return;
	}

	unitp->fanksp->ks_update = envctrl_fanstat_kstat_update;
	unitp->fanksp->ks_private = (void *)unitp;
	kstat_install(unitp->fanksp);

	if ((unitp->psksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_PSNAME, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->ps_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "envctrl%d: ps name kstat_create failed",
		    unitp->instance);
		return;
	}

	unitp->psksp->ks_update = envctrl_ps_kstat_update;
	unitp->psksp->ks_private = (void *)unitp;
	kstat_install(unitp->psksp);

}

int
envctrl_ps_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;



	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	kstatp = (char *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {

		unitp->psksp->ks_ndata = unitp->num_ps_present;
		bcopy(&unitp->ps_kstats, kstatp, sizeof (unitp->ps_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}
int
envctrl_fanstat_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;

	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		unitp->fanksp->ks_ndata = unitp->num_fans_present;
		bcopy(unitp->fan_kstats, kstatp, sizeof (unitp->fan_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

int
envctrl_encl_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;


	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {

		unitp->enclksp->ks_ndata = unitp->num_encl_present;
		(void) envctrl_get_fpm_status(unitp);
		/* XXX Need to ad disk updates too ??? */
		bcopy(unitp->encl_kstats, kstatp, sizeof (unitp->encl_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

/*
 * called with unitp lock held
 * type, fanspeed and fanflt will be set by the service routines
 */
static void
envctrl_init_fan_kstats(struct envctrlunit *unitp)
{
	int i;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	for (i = 0; i < unitp->num_fans_present; i++) {
		unitp->fan_kstats[i].instance = 0;
		unitp->fan_kstats[i].type = 0;
		unitp->fan_kstats[i].fans_ok = B_TRUE;
		unitp->fan_kstats[i].fanflt_num = B_FALSE;
		unitp->fan_kstats[i].fanspeed = B_FALSE;
	}

	unitp->fan_kstats[ENVCTRL_FAN_TYPE_PS].type = ENVCTRL_FAN_TYPE_PS;
	unitp->fan_kstats[ENVCTRL_FAN_TYPE_CPU].type = ENVCTRL_FAN_TYPE_CPU;
	if (unitp->AFB_present == B_TRUE)
		unitp->fan_kstats[ENVCTRL_FAN_TYPE_AFB].type =
		    ENVCTRL_FAN_TYPE_AFB;
}

static void
envctrl_init_encl_kstats(struct envctrlunit *unitp)
{

	int i;
	uint8_t val;
	struct envctrl_pcf8574_chip chip;
	int *reg_prop;
	uint_t len = 0;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	for (i = 0; i < MAX_DEVS; i++) {
		unitp->encl_kstats[i].instance = I2C_NODEV;
	}

	/*
	 * add in kstats now
	 * We ALWAYS HAVE THE FOLLOWING
	 * 1. FSP
	 * 2. AMB TEMPR
	 * 3. (1) CPU TEMPR
	 * 4. (1) 4 slot disk backplane
	 * OPTIONAL
	 * 8 slot backplane
	 * more cpu's
	 */

	chip.type = PCF8574A;
	chip.chip_num = ENVCTRL_PCF8574_DEV6; /* 0x01 port 1 */
	envctrl_recv(unitp, (caddr_t *)(void *)&chip, PCF8574);

	envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_FSP, INSTANCE_0,
	    chip.val & 0xFF);

	val = envctrl_get_lm75_temp(unitp) & 0xFF;
	envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_AMBTEMPR, INSTANCE_0, val);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, unitp->dip,
	    DDI_PROP_DONTPASS, ENVCTRL_DISK_LEDS_PR,
	    &reg_prop, &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "prop lookup of %s failed\n",
		    ENVCTRL_DISK_LEDS_PR);
		return;
	}

	ASSERT(len != 0);

	chip.type = PCF8574;

	for (i = 0; i < len; i++) {
		chip.chip_num = backaddrs[i];
		if (reg_prop[i] == ENVCTRL_4SLOT_BACKPLANE) {
			envctrl_recv(unitp, (caddr_t *)(void *)&chip, PCF8574);
			envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_BACKPLANE4,
			    i, ~chip.val);
			controller_present[i] = 1;
		}
		if (reg_prop[i] == ENVCTRL_8SLOT_BACKPLANE) {
			envctrl_recv(unitp, (caddr_t *)(void *)&chip, PCF8574);
			envctrl_add_encl_kstats(unitp, ENVCTRL_ENCL_BACKPLANE8,
			    i, ~chip.val);
			controller_present[i] = 1;
		}
	}
	ddi_prop_free((void *)reg_prop);

}

static void
envctrl_mod_encl_kstats(struct envctrlunit *unitp, int type,
    int instance, uint8_t val)
{
	int i = 0;
	boolean_t inserted = B_FALSE;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	while (i < MAX_DEVS && inserted == B_FALSE) {
		if (unitp->encl_kstats[i].instance == instance &&
		    unitp->encl_kstats[i].type == type) {
			unitp->encl_kstats[i].value = val;
			inserted = B_TRUE;
		}
		i++;
	}
}

static void
envctrl_probe_cpus(struct envctrlunit *unitp)
{
	int instance;

	/*
	 * The cpu search is as follows:
	 * If there is only 1 CPU module it is named as
	 * SUNW,UltraSPARC. If this is a match we still don't
	 * know what slot the cpu module is in therefore
	 * we need to check the "upa-portid" property.
	 * If we have more than 1 cpu, then they are appended by
	 * instance numbers and slot locations. e.g.
	 * SUNW,UltraSPARC@1,0 (slot 1). it would have been
	 * nice to have the naming consistent for one CPU e.g.
	 * SUNW,UltraSPARC@0,0...sigh
	 */

	for (instance = 0; instance < ENVCTRL_MAX_CPUS; instance++) {
		unitp->cpu_pr_location[instance] = B_FALSE;
	}

	ddi_walk_devs(ddi_root_node(), envctrl_match_cpu, unitp);
}

static int
envctrl_match_cpu(dev_info_t *dip, void *arg)
{

	int cpu_slot;
	char name[32];
	char name1[32];
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	(void) sprintf(name, "%s", ENVCTRL_TAZCPU_STRING);
	(void) sprintf(name1, "%s", ENVCTRL_TAZBLKBRDCPU_STRING);

	if ((strcmp(ddi_node_name(dip), name) == 0) ||
	    (strcmp(ddi_node_name(dip), name1) == 0)) {
		if ((cpu_slot = (int)ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "upa-portid", -1)) == -1) {
			cmn_err(CE_WARN, "envctrl no cpu upa-portid");
		} else {
			unitp->cpu_pr_location[cpu_slot] = B_TRUE;
			unitp->num_cpus_present++;
		}
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * This routine returns TRUE if some other error condition
 * has set the GEN_ERR FAULT LED. Tp further complicate this
 * LED panel we have overloaded the GEN_ERR LED to indicate
 * that a fan fault has occurred without having a fan fault
 * LED as does all other error conditions. So we just take the
 * software state and return true. The whole purpose of this functon
 * is to tell us wehther or not we can shut off the GEN_FAULT LED.
 * NOTE: this ledval is usually one of the following FSP vals
 * EXCEPT in the case of the fan fail.. we pass in a "0".
 */

static int
envctrl_isother_fault_led(struct envctrlunit *unitp, uint8_t fspval,
    uint8_t thisled)
{
	int status = B_FALSE;

	if (fspval != 0) {
		fspval = (fspval & ~(thisled));
	}
	if (unitp->num_fans_failed > 0 && thisled != 0) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_FSP_DISK_ERR) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_FSP_PS_ERR) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_FSP_TEMP_ERR) {
		status = B_TRUE;
	}
	return (status);
}

static void
envctrl_pshotplug_poll(void *arg)
{
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	mutex_enter(&unitp->umutex);

	envctrl_ps_probe(unitp);

	mutex_exit(&unitp->umutex);
}

/*
 * The following routines implement the i2c protocol.
 * They should be removed once the envctrl_targets.c file is included.
 */

/*
 * put host interface into master mode
 */
static int
eHc_start_pcf8584(struct eHc_envcunit *ehcp, uint8_t byteaddress)
{
	uint8_t poll_status;
	uint8_t discard;
	int i;

	/* wait if bus is busy */

	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while (((poll_status & EHC_S1_NBB) == 0) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_start_pcf8584: I2C bus busy");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN, "eHc_start_pcf8584: I2C bus error");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_start_pcf8584: Lost arbitration");
		return (EHC_FAILURE);
	}

	/* load the slave address */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, byteaddress);

	/* generate the "start condition" and clock out the slave address */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
	    EHC_S1_PIN | EHC_S1_ES0 | EHC_S1_STA | EHC_S1_ACK);

	/* wait for completion of transmission */
	i = 0;
	do {
		drv_usecwait(1000);
		poll_status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_start_pcf8584: I2C bus busy");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN, "eHc_start_pcf8584: I2C bus error");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_start_pcf8584: Lost arbitration");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LRB) {
		DCMNERR(CE_WARN, "eHc_start_pcf8584: No slave ACK");
		return (EHC_NO_SLAVE_ACK);
	}

	/*
	 * If this is a read we are setting up for (as indicated by
	 * the least significant byte being set), read
	 * and discard the first byte off the bus - this
	 * is the slave address.
	 */

	i = 0;
	if (byteaddress & EHC_BYTE_READ) {
		discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
		discard = discard;
#endif

		/* wait for completion of transmission */
		do {
			drv_usecwait(1000);
			poll_status = ddi_get8(ehcp->ctlr_handle,
			    &ehcp->bus_ctl_regs->s1);
			i++;
		} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

		if (i == EHC_MAX_WAIT) {
			DCMNERR(CE_WARN, "eHc_start_pcf8584: I2C bus busy");
			return (EHC_FAILURE);
		}

		if (poll_status & EHC_S1_BER) {
			DCMN2ERR(CE_WARN,
			    "eHc_start_pcf8584: I2C bus error");
			return (EHC_FAILURE);
		}

		if (poll_status & EHC_S1_LAB) {
			DCMN2ERR(CE_WARN,
			    "eHc_start_pcf8584: Lost arbitration");
			return (EHC_FAILURE);
		}
	}

	return (EHC_SUCCESS);
}

/*
 * put host interface into slave/receiver mode
 */
static void
eHc_stop_pcf8584(struct eHc_envcunit *ehcp)
{
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
	    EHC_S1_PIN | EHC_S1_ES0 | EHC_S1_STO | EHC_S1_ACK);
}

static int
eHc_read_pcf8584(struct eHc_envcunit *ehcp, uint8_t *data)
{
	uint8_t poll_status;
	int i = 0;

	/* Read the byte of interest */
	*data = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_read_pcf8584: I2C bus busy");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN, "eHc_read_pcf8584: I2C bus error");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_read_pcf8584: Lost arbitration");
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * host interface is in transmitter state, thus mode is master/transmitter
 * NOTE to Bill: this check the LRB bit (only done in transmit mode).
 */

static int
eHc_write_pcf8584(struct eHc_envcunit *ehcp, uint8_t data)
{
	uint8_t poll_status;
	int i = 0;

	/* send the data, EHC_S1_PIN should go to "1" immediately */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0, data);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_write_pcf8584: I2C bus busy");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN, "eHc_write_pcf8584: I2C bus error");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_write_pcf8584: Lost arbitration");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LRB) {
		DCMNERR(CE_WARN, "eHc_write_pcf8584: No slave ACK");
		return (EHC_NO_SLAVE_ACK);
	}

	return (EHC_SUCCESS);
}

static int
eHc_after_read_pcf8584(struct eHc_envcunit *ehcp, uint8_t *data)
{
	uint8_t discard;
	uint8_t poll_status;
	int i = 0;

	/* set ACK in register S1 to 0 */
	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1, EHC_S1_ES0);

	/*
	 * Read the "byte-before-the-last-byte" - sets PIN bit to '1'
	 */

	*data = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);

	/* wait for completion of transmission */
	do {
		drv_usecwait(1000);
		poll_status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((poll_status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_after_read_pcf8584: I2C bus busy");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN,
		    "eHc_after_read_pcf8584: I2C bus error");
		return (EHC_FAILURE);
	}

	if (poll_status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_after_read_pcf8584: Lost arbitration");
		return (EHC_FAILURE);
	}

	/*
	 * Generate the "stop" condition.
	 */
	eHc_stop_pcf8584(ehcp);

	/*
	 * Read the "last" byte.
	 */
	discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
	discard = discard;
#endif

	return (EHC_SUCCESS);
}

/*
 * Write to the TDA8444 chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_write_tda8444(struct eHc_envcunit *ehcp, int byteaddress, int instruction,
    int subaddress, uint8_t *buf, int size)
{
	uint8_t control;
	int i, status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(subaddress < 8);
	ASSERT(instruction == 0xf || instruction == 0x0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	control = (instruction << 4) | subaddress;

	if ((status = eHc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	if ((status = eHc_write_pcf8584(ehcp, control)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
		/*
		 * Send the "stop" condition.
		 */
		eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size; i++) {
		if ((status = eHc_write_pcf8584(ehcp, (buf[i] & 0x3f))) !=
		    EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				eHc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	eHc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from PCF8574A chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_read_pcf8574a(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = eHc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
	    EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard = ddi_get8(ehcp->ctlr_handle,
			    &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = eHc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
			return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read, including reading the last byte.
	 */

	if (eHc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8574A chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_write_pcf8574a(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition (write)
	 */
	if ((status = eHc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = eHc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				eHc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	eHc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the PCF8574 chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_read_pcf8574(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = eHc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
	    EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard = ddi_get8(ehcp->ctlr_handle,
			    &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = eHc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
		return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read.
	 */

	if (eHc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8574 chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_write_pcf8574(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition (write)
	 */
	if ((status = eHc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = eHc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				eHc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}
	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	eHc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the LM75
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_read_lm75(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Put the bus into the start condition
	 */
	if ((status = eHc_start_pcf8584(ehcp, EHC_BYTE_READ | byteaddress)) !=
	    EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the stop condition.
			 */
			eHc_stop_pcf8584(ehcp);
			/*
			 * Read the last byte - discard it.
			 */
			discard = ddi_get8(ehcp->ctlr_handle,
			    &ehcp->bus_ctl_regs->s0);
#ifdef lint
			discard = discard;
#endif
		}
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = eHc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
		return (EHC_FAILURE);
		}
	}

	/*
	 * Handle the part of the bus protocol which comes
	 * after a read.
	 */
	if (eHc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}

/*
 * Write to the PCF8583 chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_write_pcf8583(struct eHc_envcunit *ehcp, int byteaddress, uint8_t *buf,
    int size)
{
	int i;
	int status;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	if ((status = eHc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			/*
			 * Send the "stop" condition.
			 */
			eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	/*
	 * Send the data - poll as needed.
	 */
	for (i = 0; i < size; i++) {
		if ((status = eHc_write_pcf8584(ehcp, buf[i])) != EHC_SUCCESS) {
			if (status == EHC_NO_SLAVE_ACK)
				eHc_stop_pcf8584(ehcp);
			return (EHC_FAILURE);
		}
	}

	/*
	 * Transmission complete - generate stop condition and
	 * put device back into slave receiver mode.
	 */
	eHc_stop_pcf8584(ehcp);

	return (EHC_SUCCESS);
}

/*
 * Read from the PCF8581 chip.
 * byteaddress = chip type base address | chip offset address.
 */
static int
eHc_read_pcf8591(struct eHc_envcunit *ehcp, int byteaddress, int channel,
    int autoinc, int amode, int aenable, uint8_t *buf, int size)
{
	int i;
	int status;
	uint8_t control;
	uint8_t discard;

	ASSERT((byteaddress & 0x1) == 0);
	ASSERT(channel < 4);
	ASSERT(amode < 4);
	ASSERT(MUTEX_HELD(&ehcp->umutex));

	/*
	 * Write the control word to the PCF8591.
	 * Follow the control word with a repeated START byte
	 * rather than a STOP so that reads can follow without giving
	 * up the bus.
	 */

	control = ((aenable << 6) | (amode << 4) | (autoinc << 2) | channel);

	if ((status = eHc_start_pcf8584(ehcp, byteaddress)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK) {
			eHc_stop_pcf8584(ehcp);
		}
		return (EHC_FAILURE);
	}

	if ((status = eHc_write_pcf8584(ehcp, control)) != EHC_SUCCESS) {
		if (status == EHC_NO_SLAVE_ACK)
			eHc_stop_pcf8584(ehcp);
		return (EHC_FAILURE);
	}

	/*
	 * The following two operations, 0x45 to S1, and the byteaddress
	 * to S0, will result in a repeated START being sent out on the bus.
	 * Refer to Fig.8 of Philips Semiconductors PCF8584 product spec.
	 */

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1,
	    EHC_S1_ES0 | EHC_S1_STA | EHC_S1_ACK);

	ddi_put8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0,
	    EHC_BYTE_READ | byteaddress);

	i = 0;

	do {
		drv_usecwait(1000);
		status =
		    ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s1);
		i++;
	} while ((status & EHC_S1_PIN) && i < EHC_MAX_WAIT);

	if (i == EHC_MAX_WAIT) {
		DCMNERR(CE_WARN, "eHc_read_pcf8591(): read of S1 failed");
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_LRB) {
		DCMNERR(CE_WARN, "eHc_read_pcf8591(): No slave ACK");
		/*
		 * Send the stop condition.
		 */
		eHc_stop_pcf8584(ehcp);
		/*
		 * Read the last byte - discard it.
		 */
		discard = ddi_get8(ehcp->ctlr_handle, &ehcp->bus_ctl_regs->s0);
#ifdef lint
		discard = discard;
#endif
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_BER) {
		DCMN2ERR(CE_WARN, "eHc_read_pcf8591(): Bus error");
		return (EHC_FAILURE);
	}

	if (status & EHC_S1_LAB) {
		DCMN2ERR(CE_WARN, "eHc_read_pcf8591(): Lost Arbitration");
		return (EHC_FAILURE);
	}

	/*
	 * Discard first read as per PCF8584 master receiver protocol.
	 * This is normally done in the eHc_start_pcf8584() routine.
	 */
	if ((status = eHc_read_pcf8584(ehcp, &discard)) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	/* Discard second read as per PCF8591 protocol */
	if ((status = eHc_read_pcf8584(ehcp, &discard)) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	for (i = 0; i < size - 1; i++) {
		if ((status = eHc_read_pcf8584(ehcp, &buf[i])) != EHC_SUCCESS) {
			return (EHC_FAILURE);
		}
	}

	if (eHc_after_read_pcf8584(ehcp, &buf[i]) != EHC_SUCCESS) {
		return (EHC_FAILURE);
	}

	return (EHC_SUCCESS);
}
