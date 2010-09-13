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
 * ENVCTRLTWO_ Environment Monitoring driver for i2c on Javelin
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
#include <sys/envctrl_gen.h>	/* user level generic visible definitions */
#include <sys/envctrl_ue250.h>	/* user level UE250 visible definitions */
#include <javelin/sys/envctrltwo.h> /* definitions for Javelin */
#include <io/envctrl_targets.c>
#include <sys/priv_names.h>

/* driver entry point fn definitions */
static int 	envctrl_open(dev_t *, int, int, cred_t *);
static int	envctrl_close(dev_t, int, int, cred_t *);
static int	envctrl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static uint_t 	envctrl_bus_isr(caddr_t);
static uint_t 	envctrl_dev_isr(caddr_t);

/* configuration entry point fn definitions */
static int 	envctrl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	envctrl_attach(dev_info_t *, ddi_attach_cmd_t);
static int	envctrl_detach(dev_info_t *, ddi_detach_cmd_t);

/* Driver private routines */
#ifdef GET_CPU_TEMP
static int	envctrl_get_cpu_temp(struct envctrlunit *, int);
#endif
static void	envctrl_fan_fail_service(struct envctrlunit *);
static void	envctrl_PS_intr_service(struct envctrlunit *);
static void	envctrl_ps_probe(struct envctrlunit *);
static void	envctrl_tempr_poll(void *);
static void	envctrl_pshotplug_poll(void *);
static void	envctrl_led_blink(void *);
static void	envctrl_init_bus(struct envctrlunit *);
static void	envctrl_reset_dflop(struct envctrlunit *);
static void	envctrl_enable_devintrs(struct envctrlunit *);
static void	envctrl_intr_latch_clr(struct envctrlunit *);
static void	envctrl_abort_seq_handler(char *msg);
static int	envctrl_get_fpm_status(struct envctrlunit *, uint8_t *);
static int	envctrl_set_fsp(struct envctrlunit *, uint8_t *);
static int	envctrl_set_dskled(struct envctrlunit *,
				struct envctrl_chip *);
static int	envctrl_get_dskled(struct envctrlunit *,
				struct envctrl_chip *);
static int	envctrl_set_fanspeed(struct envctrlunit *,
			struct envctrl_chip *);
static void	envctrl_probe_cpus(struct envctrlunit *);
static int	envctrl_match_cpu(dev_info_t *, void *);
static int	envctrl_isother_fault_led(struct envctrlunit *,
		    uint8_t, uint8_t);
static int	envctrl_check_sys_temperatures(struct envctrlunit *);
static void	envctrl_check_disk_kstats(struct envctrlunit *);
static void	envctrl_update_disk_kstats(struct envctrlunit *,
			uint8_t, uint8_t);
static int	envctrl_read_chip(struct envctrlunit *, int, int, int,
			uint8_t *, int);
static int	envctrl_write_chip(struct envctrlunit *, int, int, int,
			uint8_t *, int);
static int	envctrl_check_tempr_levels(struct envctrlunit *,
		int, uint8_t *, int);
static void	envctrl_update_fanspeed(struct envctrlunit *);

/* Kstat routines */
static void	envctrl_add_kstats(struct envctrlunit *);
static int	envctrl_ps_kstat_update(kstat_t *, int);
static int	envctrl_fanstat_kstat_update(kstat_t *, int);
static int	envctrl_encl_kstat_update(kstat_t *, int);
static int	envctrl_temp_kstat_update(kstat_t *, int);
static int	envctrl_disk_kstat_update(kstat_t *, int);
static void	envctrl_init_encl_kstats(struct envctrlunit *);

extern void power_down(const char *);
extern int prom_getprop();
extern int prom_getproplen();
extern	void	prom_printf(const char *fmt, ...);
extern void (*abort_seq_handler)();

static void    *envctrlsoft_statep;

static char driver_name[] = "envctrltwo";
static uchar_t _cpu_temps[256];
static uchar_t _cpu_fan_speeds[256];
static int psok[2] = {-1, -1};
static int pspr[2] = {-1, -1};
static uint8_t idle_fanspeed;

static int power_flt_led_lit = 0;

extern void pci_thermal_rem_intr(dev_info_t *, uint_t);

/* Local Variables */
/* Indicates whether or not the overtemp thread has been started */
static int envctrl_debug_flags = 0;
static int envctrl_power_off_overide = 0;
static int envctrl_max_retries = 200;
static int envctrl_allow_detach = 0;
static int envctrl_numcpus = 1;
static int envctrl_handler = 1; /* 1 is the default */
static clock_t overtemp_timeout_hz;
static clock_t blink_timeout_hz;
static clock_t pshotplug_timeout_hz;
static clock_t warning_timeout_hz;
/*
 * Temperature levels :
 * green = OK  - no action needed
 * yellow = warning - display warning message and poll faster
 * red = critical - shutdown system
 */
enum levels {green, yellow, red};

#define	DPRINTF1 if (envctrl_debug_flags && (envctrl_debug_flags & 0x1)) printf
#define	DPRINTF2 if (envctrl_debug_flags && (envctrl_debug_flags & 0x2)) printf
#define	DPRINTF3 if (envctrl_debug_flags && (envctrl_debug_flags & 0x4)) printf

#define	JAV_FAN_SPEED_SF_NUM	107
#define	JAV_FAN_SPEED_SF_DEN	100
#define	JAV_MAX_TEMP_SENSORS	6
#define	JAV_FSP_MASK		0xC0
#define	FAN_DRIFT		25
#define	MAX_FAN_SPEED		255
#define	MAX_DEVS		16

#define	ENVCTRL_UE250_INTR_LATCH_INIT0 0xFE
#define	ENVCTRL_UE250_INTR_LATCH_INIT1 0xFF

static int t_scale_num[8];
static int t_scale_den[8];
static uint8_t t_addr[8];
static uint8_t t_port[8];
static int sensor_types[] = { ENVCTRL_UE250_CPU0_SENSOR,
			ENVCTRL_UE250_CPU1_SENSOR, ENVCTRL_UE250_MB0_SENSOR,
			ENVCTRL_UE250_MB1_SENSOR, ENVCTRL_UE250_PDB_SENSOR,
			ENVCTRL_UE250_SCSI_SENSOR };

static struct cb_ops envctrl_cb_ops = {
	envctrl_open,		/* cb_open */
	envctrl_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	envctrl_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_NEW | D_MP)	/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  envctrltwo_ops = {
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
	"I2C ENVCTRLTWO_driver",
	&envctrltwo_ops,
};

static struct modlinkage envctrlmodlinkage = {
	MODREV_1,
	&envctrlmodldrv,
	0
};

int
_init(void)
{
	register int    error;

	if ((error = mod_install(&envctrlmodlinkage)) == 0) {
		(void) ddi_soft_state_init(&envctrlsoft_statep,
		    sizeof (struct envctrlunit), 1);
	}

	return (error);
}

int
_fini(void)
{
	register int    error;

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
	register int	instance;
	char		name[16];
	uint8_t fspval;
	register struct	envctrlunit *unitp;
	struct ddi_device_acc_attr attr;
	uchar_t *creg_prop;
	uint_t len, tblsz;
	int i, j, k, status;
	uint8_t fanspeed;

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
		unitp->initting = B_TRUE;
		envctrl_init_bus(unitp);
		unitp->initting = B_FALSE;

		envctrl_ps_probe(unitp);
		envctrl_probe_cpus(unitp);
		mutex_exit(&unitp->umutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* Set up timer values */
	overtemp_timeout_hz = drv_usectohz(ENVCTRL_UE250_OVERTEMP_TIMEOUT_USEC);
	blink_timeout_hz = drv_usectohz(ENVCTRL_UE250_BLINK_TIMEOUT_USEC);
	pshotplug_timeout_hz =
	    drv_usectohz(ENVCTRL_UE250_BLINK_TIMEOUT_USEC * 2);
	/*
	 * On a cooling failure, either a fan failure or temperature
	 * exceeding a WARNING level, the temperature poll thread
	 * will run every 6 seconds.
	 */
	warning_timeout_hz =
	    drv_usectohz(ENVCTRL_UE250_OVERTEMP_TIMEOUT_USEC / 6);

	if (ddi_soft_state_zalloc(envctrlsoft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d: failed to zalloc softstate\n",
		    ddi_get_name(dip), instance);
		goto failed;
	}

	unitp = ddi_get_soft_state(envctrlsoft_statep, instance);

	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&unitp->bus_ctl_regs, 0,
	    sizeof (struct ehc_pcd8584_regs), &attr,
	    &unitp->ctlr_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to map in bus_control regs\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}

	/*
	 * If the PCI nexus has added a thermal interrupt, we first need
	 * to remove that interrupt handler.
	 *
	 * WARNING: Removing another driver's interrupt handler is not
	 * allowed. The pci_thermal_rem_intr() call below is needed to retain
	 * the legacy behavior on Javelin systems.
	 */

	pci_thermal_rem_intr(dip, (uint_t)0);

	/* add interrupts */

	if (ddi_get_iblock_cookie(dip, 1,
	    &unitp->ic_trap_cookie) != DDI_SUCCESS)  {
		cmn_err(CE_WARN, "%s%d: ddi_get_iblock_cookie FAILED \n",
		    ddi_get_name(dip), instance);
		goto failed;
	}

	mutex_init(&unitp->umutex, NULL, MUTEX_DRIVER,
	    (void *)unitp->ic_trap_cookie);


	if (ddi_add_intr(dip, 0, &unitp->ic_trap_cookie, NULL, envctrl_bus_isr,
	    (caddr_t)unitp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to add hard intr \n",
		    ddi_get_name(dip), instance);
		goto remlock;
	}


	if (ddi_add_intr(dip, 1, &unitp->ic_trap_cookie, NULL, envctrl_dev_isr,
	    (caddr_t)unitp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: failed to add hard intr \n",
		    ddi_get_name(dip), instance);
		goto remhardintr;
	}


	(void) sprintf(name, "envctrltwo%d", instance);

	if (ddi_create_priv_minor_node(dip, name, S_IFCHR, instance,
	    DDI_PSEUDO, 0, PRIV_SYS_CONFIG, PRIV_SYS_CONFIG, 0666) ==
	    DDI_FAILURE) {
		goto remhardintr1;
	}

	mutex_enter(&unitp->umutex);

	/*
	 * Javelin will not have a workstation configuration so activity
	 * LED will always blink.
	 */
	unitp->activity_led_blink = B_TRUE;
	unitp->shutdown = B_FALSE;
	unitp->num_ps_present = 0;
	unitp->num_encl_present = 1;
	unitp->current_mode = ENVCTRL_NORMAL_MODE;
	if (envctrl_numcpus > 1) {
		unitp->num_cpus_present = envctrl_numcpus;
	}
	envctrl_probe_cpus(unitp);
	if ((unitp->cpu_pr_location[ENVCTRL_CPU0] == B_FALSE) ||
	    (unitp->cpu_pr_location[ENVCTRL_CPU1] == B_FALSE))
		/* Only one CPU in the system */
		unitp->num_temps_present = 5;
	else
		unitp->num_temps_present = 6;
	unitp->num_fans_present = 1;
	unitp->dip = dip;

	mutex_exit(&unitp->umutex);

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cpu-temp-factors", &creg_prop, &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d: Unable to read cpu-temp-factors property",
		    ddi_get_name(dip), instance);
		return (DDI_NOT_WELL_FORMED);
	}
	tblsz = (sizeof (_cpu_temps) / sizeof (uchar_t));

	if (len <= tblsz && status == DDI_PROP_SUCCESS) {
		for (i = 0; i < len; i++) {
			_cpu_temps[i+2] = creg_prop[i];
		}
	}
	_cpu_temps[0] = _cpu_temps[1] = _cpu_temps[2];

	ddi_prop_free((void *)creg_prop);

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cpu-fan-speeds", &creg_prop, &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d: Unable to read cpu-fan-speeds property",
		    ddi_get_name(dip), instance);
		return (DDI_NOT_WELL_FORMED);
	}
	tblsz = (sizeof (_cpu_fan_speeds) / sizeof (uchar_t));

	if (len <= tblsz && status == DDI_PROP_SUCCESS) {
		for (i = 0; i < len; i++) {
			_cpu_fan_speeds[i+2] = creg_prop[i];
		}
	}
	_cpu_fan_speeds[0] = _cpu_fan_speeds[1] = _cpu_fan_speeds[2];

	ddi_prop_free((void *)creg_prop);

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "thermisters", &creg_prop, &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d: Unable to read thermisters property",
		    ddi_get_name(dip), instance);
		return (DDI_NOT_WELL_FORMED);
	}

	mutex_enter(&unitp->umutex);

	j = 0; k = 0;
	for (i = 0; i < JAV_MAX_TEMP_SENSORS; i++) {
		/* Type */
		unitp->temp_kstats[k].type = sensor_types[i];
		/* Address */
		t_addr[k] = creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Port */
		t_port[k] = creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Min */
		unitp->temp_kstats[k].min =
		    creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Warning threshold */
		unitp->temp_kstats[k].warning_threshold =
		    creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Shutdown threshold */
		unitp->temp_kstats[k].shutdown_threshold =
		    creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Numerator of scale factor */
		t_scale_num[k] = creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		/* Denominator of scale factor */
		t_scale_den[k] = creg_prop[j] << 24 | creg_prop[j+1] << 16 |
		    creg_prop[j+2] << 8 | creg_prop[j+3];
		j += 4;
		bcopy((caddr_t)&creg_prop[j], unitp->temp_kstats[k].label,
		    (size_t)sizeof (&creg_prop[j]));
		while (creg_prop[j] != '\0') j++;
		j++;
		if (t_addr[k] == ENVCTRL_UE250_CPU_TEMP_DEV) {
			if (((t_port[k] == ENVCTRL_UE250_CPU0_PORT) &&
			    (unitp->cpu_pr_location[ENVCTRL_CPU0] ==
			    B_FALSE)) ||
			    ((t_port[k] == ENVCTRL_UE250_CPU1_PORT) &&
			    (unitp->cpu_pr_location[ENVCTRL_CPU1] == B_FALSE)))
				/* Don't increment the kstat line count */
#ifdef lint
				k = k;
#else
				;
#endif
			else
				k++;
		} else
			k++;
	}

	ddi_prop_free((void *)creg_prop);

	/* initialize the envctrl bus controller */

	unitp->initting = B_TRUE;
	envctrl_init_bus(unitp);
	DPRINTF1("envctrl_attach(): Completed initialization of PCF8584");
	unitp->initting = B_FALSE;
	drv_usecwait(1000);

	unitp->timeout_id = 0;
	unitp->blink_timeout_id = 0;

	unitp->fan_failed = 0;
	unitp->fan_kstats.fans_ok = B_TRUE;
	unitp->tempr_warning = 0;

	envctrl_ps_probe(unitp);

	unitp->initting = B_TRUE;
	envctrl_fan_fail_service(unitp);
	unitp->initting = B_FALSE;

	/*
	 * Fans could be blasting, turn them down.
	 */
	fanspeed = 0x0;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8591, EHC_DEV2, 0,
	    &fanspeed, 1);
	if (status == DDI_FAILURE)
		cmn_err(CE_WARN, "%s%d: Write to PCF8591 (SETFAN) failed\n",
		    ddi_get_name(dip), instance);

	/*
	 * we need to init the fan kstats before the tempr_poll
	 */
	envctrl_add_kstats(unitp);
	envctrl_init_encl_kstats(unitp);
	envctrl_check_disk_kstats(unitp);

	envctrl_update_fanspeed(unitp);
	idle_fanspeed = unitp->fan_kstats.fanspeed;

	if (unitp->activity_led_blink == B_TRUE) {
		unitp->present_led_state = B_FALSE;
		mutex_exit(&unitp->umutex);
		envctrl_led_blink((void *)unitp);
		mutex_enter(&unitp->umutex);
	} else {
		fspval = ENVCTRL_UE250_FSP_ACTIVE;
		(void) envctrl_set_fsp(unitp, &fspval);
	}

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

	cmn_err(CE_WARN, "%s%d: attach failed\n", ddi_get_name(dip), instance);

	return (DDI_FAILURE);

}

static int
envctrl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	register struct envctrlunit *unitp;

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
			if (unitp->tempksp != NULL) {
				kstat_delete(unitp->tempksp);
			}
			if (unitp->diskksp != NULL) {
				kstat_delete(unitp->diskksp);
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
			cmn_err(CE_WARN, "%s%d: envctrltwo already suspended\n",
			    ddi_get_name(dip), instance);
			mutex_exit(&unitp->umutex);
			return (DDI_FAILURE);
		}
		unitp->suspended = 1;
		mutex_exit(&unitp->umutex);
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_WARN, "%s%d: suspend general fault\n",
		    ddi_get_name(dip), instance);
		return (DDI_FAILURE);
	}


}
int
envctrl_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t	dev = (dev_t)arg;
	struct envctrlunit *unitp;
	int	instance, ret;

	instance = getminor(dev);

#ifdef lint
	dip = dip;
#endif


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

/* ARGSUSED1 */
static int
envctrl_open(dev_t *dev, int flag, int otyp, cred_t *cred_p)
{
	struct envctrlunit *unitp;
	int status = 0;
	register int	instance;

	instance = getminor(*dev);
	if (instance < 0)
		return (ENXIO);
	unitp = (struct envctrlunit *)
	    ddi_get_soft_state(envctrlsoft_statep, instance);

	if (unitp == NULL)
		return (ENXIO);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&unitp->umutex);

	if (flag & FWRITE) {
		if ((unitp->oflag & FWRITE)) {
			mutex_exit(&unitp->umutex);
			return (EBUSY);
		} else {
			unitp->oflag |= FWRITE;
		}
	}

	mutex_exit(&unitp->umutex);
	return (status);
}

/*ARGSUSED1*/
static int
envctrl_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	struct envctrlunit *unitp;
	register int    instance;

	instance = getminor(dev);
	if (instance < 0)
		return (ENXIO);
	unitp = (struct envctrlunit *)
	    ddi_get_soft_state(envctrlsoft_statep, instance);
	if (unitp == NULL)
		return (ENXIO);

	mutex_enter(&unitp->umutex);

	unitp->oflag = B_FALSE;
	unitp->current_mode = ENVCTRL_NORMAL_MODE;

	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}


/*
 * standard put procedure for envctrl
 */
static int
envctrl_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
	int *rvalp)
{
	struct envctrlunit *unitp;
	register int	instance;
	uint8_t wdval, tempr;
	struct envctrl_chip fanspeed;
	struct envctrl_chip ledchip, envcchip;
	struct envctrl_chip temp, a_fanspeed;
	int rval = 0, status, tfanspeed;

#ifdef lint
	cred_p = cred_p;
	rvalp = rvalp;
#endif
	instance = getminor(dev);
	unitp = (struct envctrlunit *)
	    ddi_get_soft_state(envctrlsoft_statep, instance);

	if ((cmd == ENVCTRL_IOC_SETFAN2) ||
	    (cmd == ENVCTRL_IOC_GETFAN2) ||
	    (cmd == ENVCTRL_IOC_SETMODE) ||
	    (cmd == ENVCTRL_IOC_GETMODE) ||
	    (cmd == ENVCTRL_IOC_GETTEMP2) ||
	    (cmd == ENVCTRL_IOC_SETFSP2) ||
	    (cmd == ENVCTRL_IOC_GETFSP2) ||
	    (cmd == ENVCTRL_IOC_RESETTMPR) ||
	    (cmd == ENVCTRL_IOC_SETDSKLED2) ||
	    (cmd == ENVCTRL_IOC_GETDSKLED2))
		if ((caddr_t)arg == NULL)
			return (EFAULT);

	switch (cmd) {
	case ENVCTRL_IOC_SETMODE:
		/* Set mode */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&wdval, sizeof (uint8_t),
		    flag)) {
			rval = EFAULT;
			break;
		}
		if (wdval == ENVCTRL_DIAG_MODE ||
		    wdval == ENVCTRL_NORMAL_MODE) {
			mutex_enter(&unitp->umutex);
			unitp->current_mode = wdval;
			if (unitp->timeout_id != 0 &&
			    wdval == ENVCTRL_DIAG_MODE) {
				(void) untimeout(unitp->timeout_id);
				unitp->timeout_id =
				    (timeout(envctrl_tempr_poll,
				    (caddr_t)unitp, overtemp_timeout_hz));
			}
			if (wdval == ENVCTRL_NORMAL_MODE) {
				/*
				 * Fans could be blasting, turn them down.
				 */
				tempr = 0x0;
				status = envctrl_write_chip(unitp,
				    ENVCTRL_PCF8591, EHC_DEV2, 0,
				    &tempr, 1);
				if (status == DDI_FAILURE)
					cmn_err(CE_WARN,
					    "%s%d: Write to PCF8591 "
					    "(SETMODE) failed\n",
					    driver_name, unitp->instance);

				/*
				 * This delay allows the fans to time to
				 * change speed
				 */
				drv_usecwait(100000);
				(void) envctrl_check_sys_temperatures(unitp);
				unitp->current_mode = ENVCTRL_DIAG_MODE;
				envctrl_fan_fail_service(unitp);
				unitp->current_mode = ENVCTRL_NORMAL_MODE;
			}
			mutex_exit(&unitp->umutex);
		} else {
			rval = EINVAL;
		}
		break;
	case ENVCTRL_IOC_GETMODE:
		wdval = unitp->current_mode;
		if (ddi_copyout((caddr_t)&wdval, (caddr_t)arg,
		    sizeof (uint8_t), flag)) {
			rval = EFAULT;
		}
		break;
	case ENVCTRL_IOC_RESETTMPR:
		/*
		 * For diags, cancel the curent temp poll
		 * and reset it for a new one.
		 */
		if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
			if (unitp->timeout_id != 0) {
				(void) untimeout(unitp->timeout_id);
				unitp->timeout_id = 0;
			}
			envctrl_tempr_poll((void *)unitp);
		} else {
			rval = EINVAL;
		}
		break;
	case ENVCTRL_IOC_GETTEMP2:
		/* Get the user buffer address */

		if (ddi_copyin((caddr_t)arg, (caddr_t)&temp,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if (((temp.chip_num != ENVCTRL_DEV2) &&
		    (temp.chip_num != ENVCTRL_DEV7)) ||
		    (temp.index > EHC_PCF8591_CH_3)) {
			rval = EINVAL;
			break;
		}
		mutex_enter(&unitp->umutex);
		status = envctrl_read_chip(unitp, ENVCTRL_PCF8591,
		    temp.chip_num, temp.index, &temp.val, 1);
		mutex_exit(&unitp->umutex);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Read from PCF8591 (IOC_GETTEMP) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
			break;
		}
		if (ddi_copyout((caddr_t)&temp, (caddr_t)arg,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
		}
		break;
	case ENVCTRL_IOC_SETTEMP:
		rval = EINVAL;
		break;
	case ENVCTRL_IOC_SETWDT:
		rval = EINVAL;
		break;
	case ENVCTRL_IOC_SETFAN2:
		/* NOTE: need to sanity check values coming from userland */
		if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
			if (ddi_copyin((caddr_t)arg, (caddr_t)&fanspeed,
				sizeof (struct envctrl_chip), flag)) {
				rval = EFAULT;
				break;
			}
			if ((fanspeed.type != ENVCTRL_PCF8591) ||
			    (fanspeed.chip_num != ENVCTRL_DEV2) ||
			    (fanspeed.index > EHC_PCF8591_CH_3)) {
				rval = EINVAL;
				break;
			}
			mutex_enter(&unitp->umutex);
			status = envctrl_set_fanspeed(unitp, &fanspeed);
			if (status == DDI_FAILURE) {
				cmn_err(CE_WARN,
				    "%s%d: Write to PCF8591 "
				    "(IOC_SETFAN) failed",
				    driver_name, unitp->instance);
				rval = EINVAL;
			}
			mutex_exit(&unitp->umutex);
		} else {
			rval = EINVAL;
		}
		break;
	case ENVCTRL_IOC_GETFAN2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&a_fanspeed,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if ((a_fanspeed.type != ENVCTRL_PCF8591) ||
		    (a_fanspeed.chip_num != ENVCTRL_DEV2) ||
		    (a_fanspeed.index != EHC_PCF8591_CH_1)) {
			rval = EINVAL;
			break;
		}
		mutex_enter(&unitp->umutex);
		status = envctrl_read_chip(unitp, ENVCTRL_PCF8591,
		    a_fanspeed.chip_num, a_fanspeed.index,
		    &a_fanspeed.val, 1);
		mutex_exit(&unitp->umutex);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Read of PCF8591 (IOC_GETFAN) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
			break;
		}
		/*
		 * Due to hardware limitation, the actual fan speed
		 * is always a little less than what it was set to by
		 * software. Hence, we scale up the read fan speed value
		 * to more closely match the set value.
		 */
		if ((tfanspeed = ((int)a_fanspeed.val * JAV_FAN_SPEED_SF_NUM) /
		    JAV_FAN_SPEED_SF_DEN) > 255)
			a_fanspeed.val = 255;
		else
			a_fanspeed.val = tfanspeed & 0xFF;
		unitp->fan_kstats.fanspeed = a_fanspeed.val;
		if (ddi_copyout((caddr_t)&a_fanspeed, (caddr_t)arg,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
		}
		break;
	case ENVCTRL_IOC_SETFSP2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&envcchip,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if ((envcchip.type != ENVCTRL_PCF8574A) ||
		    (envcchip.chip_num != ENVCTRL_DEV6)) {
			rval = EINVAL;
			break;
		}
		wdval = envcchip.val;
		mutex_enter(&unitp->umutex);
		/*
		 * If a user is in normal mode and they try
		 * to set anything other than a disk fault or
		 * a gen fault it is an invalid operation.
		 * in diag mode we allow everything to be
		 * twiddled.
		 */
		if (unitp->current_mode == ENVCTRL_NORMAL_MODE) {
			if (wdval & ~ENVCTRL_UE250_FSP_USRMASK) {
				mutex_exit(&unitp->umutex);
				rval = EINVAL;
				break;
			}
		}
		if (wdval & ENVCTRL_UE250_FSP_PS_ERR)
			power_flt_led_lit = 1;
		status = envctrl_set_fsp(unitp, &wdval);
		mutex_exit(&unitp->umutex);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Read of PCF8574A (IOC_SETFSP) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
		}
		break;
	case ENVCTRL_IOC_GETFSP2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&envcchip,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if ((envcchip.type != ENVCTRL_PCF8574A) ||
		    (envcchip.chip_num != ENVCTRL_DEV6)) {
			rval = EINVAL;
			break;
		}
		mutex_enter(&unitp->umutex);
		status = envctrl_get_fpm_status(unitp, &wdval);
		mutex_exit(&unitp->umutex);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Read of PCF8574A (IOC_GETFSP) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
		} else {
			envcchip.val = wdval;
			if (ddi_copyout((caddr_t)&envcchip, (caddr_t)arg,
				sizeof (struct envctrl_chip), flag)) {
				rval = EFAULT;
			}
		}
		break;
	case ENVCTRL_IOC_SETDSKLED2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ledchip,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if ((ledchip.type != ENVCTRL_PCF8574A) ||
		    (ledchip.chip_num != ENVCTRL_DEV7)) {
			rval = EINVAL;
			break;
		}
		mutex_enter(&unitp->umutex);
		if (envctrl_set_dskled(unitp, &ledchip)) {
			rval = EINVAL;
		}
		mutex_exit(&unitp->umutex);
		break;
	case ENVCTRL_IOC_GETDSKLED2:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ledchip,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		if ((ledchip.type != ENVCTRL_PCF8574A) ||
		    (ledchip.chip_num != ENVCTRL_DEV7)) {
			rval = EINVAL;
			break;
		}
		mutex_enter(&unitp->umutex);
		if (envctrl_get_dskled(unitp, &ledchip)) {
			rval = EINVAL;
		} else {
			if (ddi_copyout((caddr_t)&ledchip, (caddr_t)arg,
				sizeof (struct envctrl_chip), flag)) {
				rval = EFAULT;
			}
		}
		mutex_exit(&unitp->umutex);
		break;
	case ENVCTRL_IOC_SETRAW:
		if (unitp->current_mode != ENVCTRL_DIAG_MODE) {
			rval = EINVAL;
			break;
		}
		if (ddi_copyin((caddr_t)arg, (caddr_t)&temp,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		mutex_enter(&unitp->umutex);
		status = envctrl_write_chip(unitp, temp.type, temp.chip_num,
		    temp.index, &temp.val, 1);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Write to chip (IOC_SETRAW) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
		}
		mutex_exit(&unitp->umutex);
		break;
	case ENVCTRL_IOC_GETRAW:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&temp,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
			break;
		}
		mutex_enter(&unitp->umutex);
		status = envctrl_read_chip(unitp, temp.type, temp.chip_num,
		    temp.index, &temp.val, 1);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Read of chip (IOC_GETRAW) failed",
			    driver_name, unitp->instance);
			rval = EINVAL;
		}
		mutex_exit(&unitp->umutex);
		if (ddi_copyout((caddr_t)&temp, (caddr_t)arg,
			sizeof (struct envctrl_chip), flag)) {
			rval = EFAULT;
		}
		break;
	default:
		rval = EINVAL;
	}

	return (rval);
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
	static int spurious_intr_count = 0;

	ic = DDI_INTR_UNCLAIMED;

	mutex_enter(&unitp->umutex);


	/*
	 * First check to see if it is an interrupt for us by
	 * looking at the "ganged" interrupt and vector
	 * according to the major type
	 * 0x70 is the addr of the ganged interrupt controller.
	 * Address map for the port byte read is as follows
	 * MSB
	 * -------------------------
	 * |  |  |  |  |  |  |  |  |
	 * -------------------------
	 *  P7 P6 P5 P4 P3 P2 P1 P0
	 * P0 = Spare
	 * P1 = Thermal Interrupt
	 * P2 = Disk Interrupt
	 * P3 = Interrupt clock enable
	 * P4 = Fan Fail Interrupt
	 * P5 =	Front Panel Interrupt
	 * P6 = Power Supply Interrupt
	 * P7 = Enable Interrupts
	 */

	do {
		status = ehc_read_pcf8574a((struct ehc_envcunit *)unitp,
		    ENVCTRL_UE250_PCF8574A_BASE_ADDR | EHC_DEV0,
		    &recv_data, 1);

		/*
		 * This extra read is needed since the first read is discarded
		 * and the second read seems to return 0xFF.
		 */
		if (recv_data == 0xFF) {
			status = ehc_read_pcf8574a((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574A_BASE_ADDR | EHC_DEV0,
			    &recv_data, 1);
		}

		/*
		 * if the i2c bus is hung it is imperative that this
		 * be cleared on an interrupt or else it will
		 * hang the system with continuous interrupts
		 */

		if (status == DDI_FAILURE) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
			} else {
				cmn_err(CE_WARN,
				    "%s%d: Read of PCF8574A (INT) failed\n",
				    driver_name, unitp->instance);
				ehc_init_pcf8584((struct ehc_envcunit *)unitp);
				mutex_exit(&unitp->umutex);
				ic = DDI_INTR_CLAIMED;
				return (ic);
			}
		}
	} while (status != DDI_SUCCESS);

	DPRINTF1("Interrupt routine called, interrupt = %X\n", recv_data);
	if (!(recv_data & EHC_PCF8574_PORT0)) {
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT1)) {
		DPRINTF1("Temperature interrupt detected\n");
		(void) envctrl_check_sys_temperatures(unitp);

		/*
		 * Clear the interrupt latches
		 */
		envctrl_intr_latch_clr(unitp);

		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT2)) {
		DPRINTF1("Disk interrupt detected\n");
		envctrl_check_disk_kstats(unitp);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT3)) {
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT4)) {
		/*
		 * Check for a fan fail
		 */
		DPRINTF1("Fan interrupt detected\n");
		envctrl_fan_fail_service(unitp);

		/*
		 * Clear the interrupt latches
		 */
		envctrl_intr_latch_clr(unitp);

		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT5)) {
		DPRINTF1("Keyswitch interrupt detected\n");
		(void) envctrl_get_fpm_status(unitp, (uint8_t *)NULL);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT6)) {
		DPRINTF1("Power supply interrupt detected\n");
		envctrl_PS_intr_service(unitp);
		ic = DDI_INTR_CLAIMED;
	}

	if (!(recv_data & EHC_PCF8574_PORT7)) {
		ic = DDI_INTR_CLAIMED;
	}

	/*
	 * The interrupt routine got called but the interrupt chip
	 * shows no interrupt present. If this happens more than 256
	 * times in a row, there is probably some hardware problem so
	 * send a warning message to the console.
	 */
	if ((recv_data == 0xFF)) {
		if (spurious_intr_count == 255)
			cmn_err(CE_WARN,
			    "%s%d: Received 256 spurious interrupts\n",
			    driver_name, unitp->instance);
		spurious_intr_count++;
		ic = DDI_INTR_CLAIMED;
	} else
		spurious_intr_count = 0;

	mutex_exit(&unitp->umutex);
	return (ic);

}


static int
envctrl_read_chip(struct envctrlunit *unitp, int type, int chip_num, int port,
	uint8_t *data, int num)
{
	int retrys = 0, autoincr = 0;
	int status;

	/*
	 * If more than one read is requested, set auto-increment bit
	 */
	if (num > 1)
		autoincr = 1;

	do {
		if (type == ENVCTRL_PCF8574A) {
			status = ehc_read_pcf8574a((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574A_BASE_ADDR | chip_num,
			    data, num);
		} else if (type == ENVCTRL_PCF8574) {
			status = ehc_read_pcf8574((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574_BASE_ADDR | chip_num,
			    data, num);
		} else if (type == ENVCTRL_PCF8591) {
			status = ehc_read_pcf8591((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8591_BASE_ADDR | chip_num,
			    port, autoincr, 0, 1, data, num);
		}
		/*
		 * If the bus hangs, attempt a recovery
		 */
		if (status == DDI_FAILURE) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
			} else {
				ehc_init_pcf8584((struct ehc_envcunit *)unitp);
				break;
			}
		}
	} while (status != DDI_SUCCESS);

	return (status);
}

static int
envctrl_write_chip(struct envctrlunit *unitp, int type, int chip_num, int port,
	uint8_t *data, int num)
{
	int retrys = 0, autoincr = 0;
	int status;

	/*
	 * Incase some applications mistakenly include the chips base addr
	 */
	chip_num = chip_num & 0xF;

	/*
	 * If more than one write is requested, set auto-increment bit
	 */
	if (num > 1)
		autoincr = 1;

	do {
		if (type == ENVCTRL_PCF8574A) {
			status = ehc_write_pcf8574a(
			    (struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574A_BASE_ADDR | chip_num,
			    data, num);
		} else if (type == ENVCTRL_PCF8574) {
			status = ehc_write_pcf8574((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574_BASE_ADDR | chip_num,
			    data, num);
		} else if (type == ENVCTRL_PCF8591) {
			status = ehc_write_pcf8591((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8591_BASE_ADDR | chip_num,
			    port, autoincr, 0, 1, data, num);
		}

		/*
		 * If the bus hangs, attempt a recovery
		 */
		if (status == DDI_FAILURE) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
			} else {
				ehc_init_pcf8584((struct ehc_envcunit *)unitp);
				break;
			}
		}
	} while (status != DDI_SUCCESS);

	return (status);
}

#ifdef GET_CPU_TEMP
static int
envctrl_get_cpu_temp(struct envctrlunit *unitp, int cpunum)
{
	uint8_t recv_data;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/*
	 * This routine takes in the number of the port that
	 * we want to read in the 8591. This should be the
	 * location of the CPU thermistor for one of the 2
	 * cpu's. It will return a normalized value
	 * to the caller.
	 */

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8591, EHC_DEV7, cpunum,
	    &recv_data, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: CPU TEMP read failed\n",
		    driver_name, unitp->instance);
		return (ENVCTRL_UE250_MAX_CPU_TEMP - 10);
	}

	return (_cpu_temps[recv_data]);
}
#endif

static void
envctrl_tempr_poll(void *arg)
{
	int diag_flag = 0, status;
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	mutex_enter(&unitp->umutex);

	if (unitp->shutdown == B_TRUE) {
		(void) power_down("Fatal System Environmental Control Error");
	}

	/*
	 * Clear the interrupt latches
	 */
	envctrl_intr_latch_clr(unitp);

	envctrl_reset_dflop(unitp);
	envctrl_enable_devintrs(unitp);
	/*
	 * if we are in diag mode and the temp poll thread goes off,
	 * this means that the system is too heavily loaded and the 60 second
	 * window to execute the test is failing.
	 */
	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		diag_flag++;
		if (envctrl_debug_flags) {
			cmn_err(CE_WARN, "%s%d: "
			    "Tempr poll went off while in DIAG MODE\n",
			    driver_name, unitp->instance);
		}
	}
	unitp->current_mode = ENVCTRL_NORMAL_MODE;
	DPRINTF1("envctrl_tempr_poll(): Checking system temps\n");
	status = envctrl_check_sys_temperatures(unitp);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN,
		    "%s%d: Failure detected during temperature poll",
		    driver_name, unitp->instance);
	}

	if (diag_flag == 0) {
		envctrl_fan_fail_service(unitp);
	}

	/* Turn of the power fault LED if ps_ok is asserted */
	envctrl_ps_probe(unitp);

	/* now have this thread sleep for a while */
	if ((unitp->fan_failed == B_TRUE) || (unitp->tempr_warning == B_TRUE)) {
		/*
		 * A thermal warning or fan failure condition exists.
		 * Temperature poll thread will run every 10 seconds.
		 */
		if (unitp->timeout_id != 0)
			(void) untimeout(unitp->timeout_id);
		unitp->timeout_id = (timeout(envctrl_tempr_poll,
		    (caddr_t)unitp, warning_timeout_hz));
	} else {
		/*
		 * No thermal warning or fan failure condition exists.
		 * This thread is set to run every 60 seconds.
		 */
		unitp->timeout_id = (timeout(envctrl_tempr_poll,
		    (caddr_t)unitp, overtemp_timeout_hz));
	}

	mutex_exit(&unitp->umutex);
}

static void
envctrl_led_blink(void *arg)
{
	uint8_t val, tmpval;
	int status;
	struct envctrlunit *unitp = (struct envctrlunit *)arg;

	mutex_enter(&unitp->umutex);

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
	    0, &val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Failed to read FSP LEDs",
		    driver_name, unitp->instance);
		/* now have this thread sleep for a while */
		unitp->blink_timeout_id = (timeout(envctrl_led_blink,
		    (caddr_t)unitp, blink_timeout_hz));
		mutex_exit(&unitp->umutex);
		return;
	}

	if (unitp->present_led_state == B_TRUE) {
		/*
		 * Now we need to "or" in fault bits of the FSP
		 * module for the mass storage fault led.
		 * and set it.
		 */
		val = (val & ~(EHC_PCF8574_PORT4) | JAV_FSP_MASK);
		unitp->present_led_state = B_FALSE;
	} else {
		val = (val | EHC_PCF8574_PORT4 | JAV_FSP_MASK);
		unitp->present_led_state = B_TRUE;
	}

	/*
	 * A static global variable, power_flt_led_lit, is used to keep
	 * track of periods when the software has lit the power fault LED.
	 * Whenever the power fault LED is lit and this variable is not set,
	 * then the power fault LED has been lit by hardware. In this case
	 * mask out the power fault LED in the byte. This is a fix for
	 * bug 4144872.
	 */
	tmpval = ~val;
	if (tmpval & ENVCTRL_UE250_FSP_PS_ERR) {
		if (power_flt_led_lit == 0) {
			/*
			 * Turn off power fault bit in the FSP byte.
			 */
			tmpval &= ~(ENVCTRL_UE250_FSP_PS_ERR);
		}
	}
	val = ~tmpval;

	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
	    0, &val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Failed to blink activity LED",
		    driver_name, unitp->instance);
		/* now have this thread sleep for a while */
		unitp->blink_timeout_id = (timeout(envctrl_led_blink,
		    (caddr_t)unitp, blink_timeout_hz));
		mutex_exit(&unitp->umutex);
		return;
	}

	/* now have this thread sleep for a while */
	unitp->blink_timeout_id = (timeout(envctrl_led_blink,
	    (caddr_t)unitp, blink_timeout_hz));

	mutex_exit(&unitp->umutex);
}

static int
envctrl_check_sys_temperatures(struct envctrlunit *unitp)
{
	uint8_t buf[8];
	enum levels warning_level, level;
	uint8_t fspval;
	int status, warning_count = 0;

retrytemp1:
	status = envctrl_read_chip(unitp, ENVCTRL_PCF8591, EHC_DEV2,
	    0, buf, 4);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Temperature read failed (PDB)",
		    driver_name, unitp->instance);
		return (status);
	}

	warning_level = envctrl_check_tempr_levels(unitp, EHC_DEV2,
	    buf, warning_count);
	level = warning_level;

	if (warning_level != green) {
		if (warning_count == 0) {
			warning_count++;
			drv_usecwait(1000);
			goto retrytemp1;
		}
		if (warning_level == yellow)
			unitp->tempr_warning = B_TRUE;
		else if (warning_level == red) {
				unitp->tempr_warning = B_TRUE;
				if (!envctrl_power_off_overide)
					unitp->shutdown = B_TRUE;
		}
	}

	warning_count = 0;
retrytemp2:
	status = envctrl_read_chip(unitp, ENVCTRL_PCF8591, EHC_DEV7,
	    0, buf+4, 4);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Temperature read failed (MBD)",
		    driver_name, unitp->instance);
		return (status);
	}

	warning_level = envctrl_check_tempr_levels(unitp, EHC_DEV7,
	    buf+4, warning_count);

	if (warning_level != green) {
		if (warning_count == 0) {
			warning_count++;
			drv_usecwait(1000);
			goto retrytemp2;
		}
		if ((warning_level == yellow) && (unitp->shutdown == B_FALSE))
			unitp->tempr_warning = B_TRUE;
		else if (warning_level == red) {
				unitp->tempr_warning = B_TRUE;
				if (!envctrl_power_off_overide)
					unitp->shutdown = B_TRUE;
		}
	} else if ((level == green) && (unitp->tempr_warning == B_TRUE)) {
		/*
		 * Current tempr. poll shows all levels normal.
		 * If the previous poll showed warning levels, we need
		 * to clear that status
		 */
		cmn_err(CE_NOTE,
		"TEMPERATURE NORMAL: all sensors back to normal readings");
		unitp->tempr_warning = B_FALSE;
	}

	status = envctrl_get_fpm_status(unitp, &fspval);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN,
		    "%s%d: Read of Front Status Panel LEDs failed",
		    driver_name, unitp->instance);
	}

	if ((unitp->tempr_warning == B_TRUE) || (unitp->shutdown == B_TRUE))
		fspval |= (ENVCTRL_UE250_FSP_TEMP_ERR |
		    ENVCTRL_UE250_FSP_GEN_ERR);
	else {
		if (envctrl_isother_fault_led(unitp, fspval,
		    ENVCTRL_UE250_FSP_TEMP_ERR)) {
			fspval &= ~(ENVCTRL_UE250_FSP_TEMP_ERR);
		} else {
			fspval &= ~(ENVCTRL_UE250_FSP_TEMP_ERR |
			    ENVCTRL_UE250_FSP_GEN_ERR);
		}
	}
	status = envctrl_set_fsp(unitp, &fspval);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN,
		    "%s%d: Setting of Front Status Panel LEDs failed",
		    driver_name, unitp->instance);
	}

	/*
	 * Have this thread run again in about 10 seconds
	 */
	if (unitp->tempr_warning == B_TRUE) {
		if (unitp->timeout_id != 0) {
			(void) untimeout(unitp->timeout_id);
			unitp->timeout_id = (timeout(envctrl_tempr_poll,
			    (caddr_t)unitp, warning_timeout_hz));
		}
	}

	return (status);
}

static int
envctrl_check_tempr_levels(struct envctrlunit *unitp, int chip_num,
	uint8_t *data, int count)
{
	uint_t temp_degree_c;
	uint8_t buf[8];
	enum levels warning_level = green;
	int i, j;
	int status;
	uint8_t fanspeed;
	int tval;

	for (i = 0; i < 4; i++) {
		if (chip_num == EHC_DEV2) {
			if (i == 1) {
				tval = ((int)data[i] * JAV_FAN_SPEED_SF_NUM) /
				    JAV_FAN_SPEED_SF_DEN;
				if (tval > 255)
					unitp->fan_kstats.fanspeed = 255;
				else
					unitp->fan_kstats.fanspeed = tval;
				DPRINTF1("device %X, fan = %d %d\n", chip_num,
				    unitp->fan_kstats.fanspeed, data[i]);
				continue;
			} else if (i == 2)
				continue;
		}
		if ((chip_num == EHC_DEV7) && ((i == ENVCTRL_UE250_CPU0_PORT) ||
		    (i == ENVCTRL_UE250_CPU1_PORT)))
			if (unitp->cpu_pr_location[i] == B_FALSE)
				continue;

		j = 0;
		while ((((t_addr[j] & 0xF) != chip_num) || (t_port[j] != i)) &&
		    (j < unitp->num_temps_present))
			j++;
		if ((chip_num == EHC_DEV7) && ((i == ENVCTRL_UE250_CPU0_PORT) ||
		    (i == ENVCTRL_UE250_CPU1_PORT)))
			temp_degree_c = _cpu_temps[data[i]];
		else
			temp_degree_c = ((int)data[i] * t_scale_num[j]) /
			    t_scale_den[j];

		/*
		 * Javelin hardware will not control fan speeds based on
		 * cpu temperature values because the voltages corresponding
		 * to the cpu temperatures are based on an inverted scale
		 * compared to the ambient temperatures and thus can be
		 * fed to the same fan control circuit. As a result, it
		 * has been decided that software will control fan speed
		 * if cpu temperatures rise.
		 */
		if ((chip_num == EHC_DEV7) && ((i == ENVCTRL_UE250_CPU0_PORT) ||
		    (i == ENVCTRL_UE250_CPU1_PORT)) &&
		    (unitp->current_mode == ENVCTRL_NORMAL_MODE)) {
			if (_cpu_fan_speeds[data[ENVCTRL_UE250_CPU0_PORT]] >
			    _cpu_fan_speeds[data[ENVCTRL_UE250_CPU1_PORT]])
				fanspeed =
				    _cpu_fan_speeds[
				    data[ENVCTRL_UE250_CPU0_PORT]];
			else
				fanspeed =
				    _cpu_fan_speeds[
				    data[ENVCTRL_UE250_CPU1_PORT]];
			status = envctrl_write_chip(unitp, ENVCTRL_PCF8591,
			    EHC_DEV2, 0, &fanspeed, 1);
			if (status == DDI_FAILURE)
				cmn_err(CE_WARN,
				    "%s%d: Write to PCF8591 (SETFAN) failed\n",
				    driver_name, unitp->instance);
			status = envctrl_read_chip(unitp, ENVCTRL_PCF8591,
			    EHC_DEV2, 0, buf, 4);
			if (status == DDI_FAILURE)
				cmn_err(CE_WARN,
				    "%s%d: Fan speed read failed (PDB)",
				    driver_name, unitp->instance);
			tval = ((int)buf[1] * JAV_FAN_SPEED_SF_NUM) /
			    JAV_FAN_SPEED_SF_DEN;
			if (tval > 255)
				unitp->fan_kstats.fanspeed = 255;
			else
				unitp->fan_kstats.fanspeed = tval;
		}

		DPRINTF1("device %X, temp = %d %d loc = %s\n", chip_num,
		    temp_degree_c, data[i], unitp->temp_kstats[j].label);

		unitp->temp_kstats[j].value = temp_degree_c;
		if ((temp_degree_c >=
		    unitp->temp_kstats[j].warning_threshold) ||
		    (temp_degree_c < unitp->temp_kstats[j].min)) {
			if (warning_level < yellow)
				warning_level = yellow;
			if (count != 0)
				cmn_err(CE_WARN,
				    "TEMPERATURE WARNING: %d degrees "
				    "celsius at location %s",
				    temp_degree_c, unitp->temp_kstats[j].label);
		}
		if (temp_degree_c >=
		    unitp->temp_kstats[j].shutdown_threshold) {
			if (warning_level < red)
				warning_level = red;
			if (count != 0) {
				cmn_err(CE_WARN,
				    "TEMPERATURE CRITICAL: %d "
				    "degrees celsius at location %s",
				    temp_degree_c, unitp->temp_kstats[j].label);
				if (!envctrl_power_off_overide)
					cmn_err(CE_WARN,
					    "System shutdown in "
					    "10 seconds ...");
			}
		}
	}
	return (warning_level);
}

static void
envctrl_update_fanspeed(struct envctrlunit *unitp)
{
	uint8_t buf[8];
	int tval;
	int status;

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8591, EHC_DEV2,
	    0, buf, 4);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Fan speed read failed ",
		    driver_name, unitp->instance);
	}

	tval = ((int)buf[ENVCTRL_PORT1] * JAV_FAN_SPEED_SF_NUM) /
	    JAV_FAN_SPEED_SF_DEN;
	if (tval > 255)
		unitp->fan_kstats.fanspeed = 255;
	else
		unitp->fan_kstats.fanspeed = tval;
}

/* called with mutex held */
static void
envctrl_fan_fail_service(struct envctrlunit *unitp)
{
	uint8_t recv_data, fpmstat;
	int retrys = 0;
	int status;

	/*
	 * The fan fail interrupt is read from address 0x70
	 * on the envctrl bus.
	 */

	ASSERT(MUTEX_HELD(&unitp->umutex));

	/*
	 * Clear the interrupt latches to handle spurious interrupts
	 */
	envctrl_intr_latch_clr(unitp);

	do {
		status = ehc_read_pcf8574a((struct ehc_envcunit *)unitp,
		    ENVCTRL_UE250_PCF8574A_BASE_ADDR | EHC_DEV0,
		    &recv_data, 1);
		/*
		 * This extra read is needed since the first read is discarded
		 * and the second read seems to return 0xFF.
		 */
		if (recv_data == 0xFF) {
			status = ehc_read_pcf8574a((struct ehc_envcunit *)unitp,
			    ENVCTRL_UE250_PCF8574A_BASE_ADDR | EHC_DEV0,
			    &recv_data, 1);
		}

		if (status == DDI_FAILURE) {
			drv_usecwait(1000);
			if (retrys < envctrl_max_retries) {
				retrys++;
			} else {
				cmn_err(CE_WARN,
				"%s%d: Read of PCF8574A (INTFAN) failed",
				    driver_name, unitp->instance);
				ehc_init_pcf8584((struct ehc_envcunit *)unitp);
				return;
			}
		}
	} while (status != DDI_SUCCESS);

	/* If the fan fail interrupt is now absent */
	if (recv_data & EHC_PCF8574_PORT4) {
		if (unitp->fan_failed == B_TRUE) {
			if (unitp->current_mode == ENVCTRL_NORMAL_MODE)
				cmn_err(CE_CONT,
				    "Fan failure has been cleared\n");
			unitp->fan_kstats.fans_ok = B_TRUE;
			/*
			 * Clear general fault LED if no other faults
			 */
			status = envctrl_get_fpm_status(unitp, &fpmstat);
			if (status == DDI_FAILURE) {
				cmn_err(CE_WARN,
				    "%s%d: Read of Front Status "
				    "Panel LEDs failed",
				    driver_name, unitp->instance);
			}
			if (!(envctrl_isother_fault_led(unitp, fpmstat, 0))) {
				fpmstat &= ~(ENVCTRL_UE250_FSP_GEN_ERR);
			}
			if (unitp->shutdown != B_TRUE) {
				status = envctrl_set_fsp(unitp, &fpmstat);
				if (status == DDI_FAILURE) {
					cmn_err(CE_WARN, "%s%d: "
					    "Setting of Front Status "
					    "Panel LEDs failed",
					    driver_name, unitp->instance);
				}
			}
			/*
			 * This should be set after envctrl_isother_fault_led()
			 * is called
			 */
			unitp->fan_failed = B_FALSE;
		}
	} else {
		if (unitp->fan_failed == B_FALSE) {
			if (unitp->current_mode == ENVCTRL_NORMAL_MODE)
				cmn_err(CE_WARN,
				    "Fan failure has been detected");
			unitp->fan_failed = B_TRUE;
			unitp->fan_kstats.fans_ok = B_FALSE;
			/*
			 * Set general fault LED
			 */
			status = envctrl_get_fpm_status(unitp, &fpmstat);
			if (status == DDI_FAILURE) {
				cmn_err(CE_WARN,
				    "%s%d: Read of Front Status "
				    "Panel LEDs failed",
				    driver_name, unitp->instance);
				return;
			}
			fpmstat |= ENVCTRL_UE250_FSP_GEN_ERR;
			status = envctrl_set_fsp(unitp, &fpmstat);
			if (status == DDI_FAILURE) {
				cmn_err(CE_WARN, "%s%d: "
				    "Setting of Front Status Panel LEDs failed",
				    driver_name, unitp->instance);
			}
			/*
			 * A fan failure condition exists.
			 * Temperature poll thread should run every 10 seconds.
			 */
			if (unitp->timeout_id != 0) {
				(void) untimeout(unitp->timeout_id);
				unitp->timeout_id =
				    (timeout(envctrl_tempr_poll,
				    (caddr_t)unitp, warning_timeout_hz));
			}
		}
	}
}

/*
 * Check for power supply insertion and failure.
 * This is a bit tricky, because a power supply insertion will
 * cause the ps_ok line to go active as well as PS present in the
 * new supply. If we detect an insertion clear
 * interrupts, disable interrupts, wait for a couple of seconds
 * come back and see if the PSOK bit is set, PS_PRESENT is set
 * and the share fail interrupts are gone. If not this is a
 * real load share fail event.
 * Called with mutex held
 */

static void
envctrl_PS_intr_service(struct envctrlunit *unitp)
{

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (unitp->current_mode == ENVCTRL_DIAG_MODE) {
		return;
	}

	/*
	 * setup a timeout thread to poll the ps after a
	 * couple of seconds. This allows for the PS to settle
	 * and doesn't report false errors on a hotplug
	 */

	unitp->pshotplug_id = (timeout(envctrl_pshotplug_poll,
	    (caddr_t)unitp, pshotplug_timeout_hz));

}

static void
envctrl_init_bus(struct envctrlunit *unitp)
{
	ehc_init_pcf8584((struct ehc_envcunit *)unitp);

	/*
	 * Clear the interrupt latches
	 */
	envctrl_intr_latch_clr(unitp);

	envctrl_reset_dflop(unitp);

	envctrl_enable_devintrs(unitp);
}

/* called with mutex held */
static void
envctrl_reset_dflop(struct envctrlunit *unitp)
{
	int status;
	uint8_t value;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	value = ENVCTRL_UE250_DFLOP_INIT0;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (DFLOP_INIT0) failed",
		    driver_name, unitp->instance);
	}

	value = ENVCTRL_UE250_DFLOP_INIT1;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (DFLOP_INIT1) failed",
		    driver_name, unitp->instance);
	}
}

/* called with mutex held */
static void
envctrl_enable_devintrs(struct envctrlunit *unitp)
{
	int status;
	uint8_t value;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	value = ENVCTRL_UE250_DEVINTR_INIT0;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (INTR_INIT0) failed",
		    driver_name, unitp->instance);
	}

	value = ENVCTRL_UE250_DEVINTR_INIT1;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (INTR_INIT1) failed",
		    driver_name, unitp->instance);
	}
}

static void
envctrl_intr_latch_clr(struct envctrlunit *unitp)
{
	int status;
	uint8_t value;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	value = ENVCTRL_UE250_INTR_LATCH_INIT0;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (INTR_LATCH0) failed",
		    driver_name, unitp->instance);
	}

	value = ENVCTRL_UE250_INTR_LATCH_INIT1;
	status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV0,
	    0, &value, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (INTR_LATCH1) failed",
		    driver_name, unitp->instance);
	}
}

/* Called with unitp mutex held */
static void
envctrl_ps_probe(struct envctrlunit *unitp)
{

	uint8_t recv_data, fpmstat;
	int i, j;
	int ps_error = 0, ps_present_port, power_ok_port;
	int status;


	ASSERT(MUTEX_HELD(&unitp->umutex));

	unitp->num_ps_present = 0;

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV1,
	    0, &recv_data, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574 (PS) failed",
		    driver_name, unitp->instance);
		return;
	}

	for (i = 0, j = 0; i < ENVCTRL_UE250_MAXPS; i++) {
		unitp->ps_kstats[i].slot = -1;

		/*
		 * Port 0 = PS0 Present
		 * Port 1 = PS1 Present
		 * Port 2 = SPARE
		 * Port 3 = SPARE
		 * Port 4 = PS0 OK
		 * Port 5 = PS1 OK
		 * Port 6 = SPARE
		 * Port 7 = SPARE
		 */

		/*
		 * Port 0 = PS Present
		 * Port is pulled LOW "0" to indicate
		 * present.
		 */

		switch (i) {
		case 0:
			ps_present_port = EHC_PCF8574_PORT0;
			power_ok_port = EHC_PCF8574_PORT4;
			break;
		case 1:
			ps_present_port = EHC_PCF8574_PORT1;
			power_ok_port = EHC_PCF8574_PORT5;
			break;
		}

		if (!(recv_data & ps_present_port)) {
			/* update unit kstat array */
			unitp->ps_kstats[j].slot = i;
			++unitp->num_ps_present;

			if (pspr[i] == 0) {
				cmn_err(CE_NOTE,
				    "Power Supply %d inserted\n", i);
			}
			pspr[i] = 1;

			if (!(recv_data & power_ok_port)) {
				cmn_err(CE_WARN,
				    "Power Supply %d NOT okay\n", i);
				unitp->ps_kstats[j].ps_ok = B_FALSE;
				ps_error++;
				psok[i] = 0;
			} else {
				unitp->ps_kstats[j].ps_ok = B_TRUE;
				if (psok[i] == 0)
					cmn_err(CE_NOTE,
					    "Power Supply %d okay\n", i);
				psok[i] = 1;
			}

			if (!(recv_data & EHC_PCF8574_PORT2)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}

			if (!(recv_data & EHC_PCF8574_PORT3)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}

			if (!(recv_data & EHC_PCF8574_PORT6)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}

			if (!(recv_data & EHC_PCF8574_PORT7)) {
				cmn_err(CE_WARN,
				    "PS %d Shouln't interrupt\n", i);
				ps_error++;
			}
			j++;
		} else {
			if (pspr[i] == 1) {
				cmn_err(CE_NOTE,
				    "Power Supply %d removed\n", i);
			}
			pspr[i] = 0;
		}
	}

	status = envctrl_get_fpm_status(unitp, &fpmstat);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of Front Status Panel LEDs failed",
		    driver_name, unitp->instance);
	}
	if (ps_error) {
		fpmstat |= (ENVCTRL_UE250_FSP_PS_ERR |
		    ENVCTRL_UE250_FSP_GEN_ERR);
	} else {
		if (envctrl_isother_fault_led(unitp, fpmstat,
		    ENVCTRL_UE250_FSP_PS_ERR)) {
			fpmstat &= ~(ENVCTRL_UE250_FSP_PS_ERR);
		} else {
			fpmstat &= ~(ENVCTRL_UE250_FSP_PS_ERR |
			    ENVCTRL_UE250_FSP_GEN_ERR);
		}
	}
	status = envctrl_set_fsp(unitp, &fpmstat);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN,
		    "%s%d: Setting of Front Status Panel LEDs failed",
		    driver_name, unitp->instance);
	}

	if (ps_error) {
		power_flt_led_lit = 1;
	} else {
		power_flt_led_lit = 0;
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

	secure = unitp->encl_kstats.value;

	if ((secure & ENVCTRL_UE250_FSP_KEYMASK) ==
	    ENVCTRL_UE250_FSP_KEYLOCKED) {
			cmn_err(CE_CONT,
			    "%s%d: ignoring debug enter sequence\n",
			    driver_name, unitp->instance);
	} else {
		if (envctrl_debug_flags) {
			cmn_err(CE_CONT, "%s%d: allowing debug enter\n",
			    driver_name, unitp->instance);
		}
		debug_enter(msg);
	}
}

/*
 * get the front Panel module LED and keyswitch status.
 * this part is addressed at 0x7C on the i2c bus.
 * called with mutex held
 */
static int
envctrl_get_fpm_status(struct envctrlunit *unitp, uint8_t *val)
{
	uint8_t recv_data;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
	    0, &recv_data, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read from PCF8574A (FSP) failed",
		    driver_name, unitp->instance);
		return (status);
	}

	recv_data = ~recv_data;
	if (val != (uint8_t *)NULL)
		*val = recv_data;

	/* Update kstats */
	unitp->encl_kstats.value = recv_data;

	return (status);
}

static int
envctrl_set_fsp(struct envctrlunit *unitp, uint8_t *val)
{
	uint8_t value;
	int status = DDI_SUCCESS;
	uint8_t confirm_val = 0, confirm_val_hold;
	int confirm_count = 0, confirm_max = 20;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	value = ENVCTRL_UE250_FSP_OFF; /* init all values to off */

	/*
	 * strip off bits that are R/O
	 */
	value = (~(ENVCTRL_UE250_FSP_KEYMASK | ENVCTRL_UE250_FSP_POMASK) &
	    (*val));

	confirm_val_hold = value;

	value = ~value;

	while (confirm_count < confirm_max) {
		status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
		    0, &value, 1);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s%d: Write to PCF8574A (FSP) failed",
			    driver_name, unitp->instance);
			break;
		} else {
			/*
			 * Sometimes the i2c hardware status is not
			 * completely dependable as far as reporting
			 * a condition where the set does not take
			 * place. So we read back the set value to
			 * confirm what we set.
			 */
			status = envctrl_get_fpm_status(unitp, &confirm_val);
			confirm_val = ~(ENVCTRL_UE250_FSP_KEYMASK |
			    ENVCTRL_UE250_FSP_POMASK) & confirm_val;
			if (status == DDI_FAILURE) {
				cmn_err(CE_WARN,
				"%s%d: Read of PCF8574A (FSP) failed",
				    driver_name, unitp->instance);
				break;
			} else if (confirm_val != confirm_val_hold) {
				confirm_count++;
				drv_usecwait(1000);
				continue;
			} else
				/*
				 * Set was confirmed.
				 */
				break;
		}
	}

	if (confirm_count == confirm_max)
		status = DDI_FAILURE;

	return (status);

}

static int
envctrl_get_dskled(struct envctrlunit *unitp, struct envctrl_chip *chip)
{
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (chip->chip_num != EHC_DEV7 ||
	    chip->type != ENVCTRL_PCF8574A) {
		return (DDI_FAILURE);
	}

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV7,
	    0, &chip->val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (DISKFL) failed",
		    driver_name, unitp->instance);
	}
	chip->val = ~chip->val;

	return (status);
}

static int
envctrl_set_dskled(struct envctrlunit *unitp, struct envctrl_chip *chip)
{
	uint8_t val;
	int status;
	struct envctrl_chip confirm_chip;
	uint8_t confirm_val_hold;
	int confirm_count = 0, confirm_max = 20;

	/*
	 * We need to check the type of disk led being set. If it
	 * is a 4 slot backplane then the upper 4 bits (7, 6, 5, 4) are
	 * invalid.
	 */
	ASSERT(MUTEX_HELD(&unitp->umutex));


	if (chip->chip_num != EHC_DEV7)
		return (DDI_FAILURE);

	if (chip->type != ENVCTRL_PCF8574A)
		return (DDI_FAILURE);

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
	    0, &val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (FSP) failed",
		    driver_name, unitp->instance);
		return (status);
	}

	val = ~val;
	if ((chip->val & 0x3F) == 0) {
		if (!(envctrl_isother_fault_led(unitp, val,
		    ENVCTRL_UE250_FSP_DISK_ERR))) {
			val &= ~(ENVCTRL_UE250_FSP_DISK_ERR);
		} else {
			val &= ~(ENVCTRL_UE250_FSP_DISK_ERR |
			    ENVCTRL_UE250_FSP_GEN_ERR);
		}
		val = (val & ~(ENVCTRL_UE250_FSP_DISK_ERR |
		    ENVCTRL_UE250_FSP_GEN_ERR));
	} else {
		val = (val | (ENVCTRL_UE250_FSP_DISK_ERR |
		    ENVCTRL_UE250_FSP_GEN_ERR));
	}

	status = envctrl_set_fsp(unitp, &val);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Write to PCF8574A (FSP) failed",
		    driver_name, unitp->instance);
		return (status);
	}


	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV5,
	    0, &val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (DISKFL) failed",
		    driver_name, unitp->instance);
		return (status);
	}

	envctrl_update_disk_kstats(unitp, val, ~(chip->val));

	/*
	 * we take the ones compliment of the val passed in
	 * because the hardware thinks that a "low" or "0"
	 * is the way to indicate a fault. of course software
	 * knows that a 1 is a TRUE state or fault. ;-)
	 */

	confirm_val_hold = chip->val;

	chip->val = ~(chip->val);

	while (confirm_count < confirm_max) {
		status = envctrl_write_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV7,
		    0, &chip->val, 1);
		if (status == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s%d: Write PCF8574A (DISKFL) failed",
			    driver_name, unitp->instance);
			return (status);
		} else {
			/*
			 * Sometimes the i2c hardware status is not
			 * completely dependable as far as reporting
			 * a condition where the set does not take
			 * place. So we read back the set value to
			 * confirm what we set.
			 */
			confirm_chip.type = chip->type;
			confirm_chip.chip_num = chip->chip_num;
			confirm_chip.index = chip->index;
			status = envctrl_get_dskled(unitp, &confirm_chip);
			if (status != DDI_SUCCESS) {
				return (status);
			} else if (confirm_chip.val != confirm_val_hold) {
				confirm_count++;
				drv_usecwait(1000);
				continue;
			} else
				/*
				 * Set was confirmed.
				 */
				break;
		}
	}

	if (confirm_count == confirm_max)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * After setting the fan speed, we read back the fan speed to confirm
 * that the new value is within an acceptable range, else we retry.
 * We do not confirm the fan speed if the set value is below the
 * hardware determined speed (based on system temeratures).
 */
static int
envctrl_set_fanspeed(struct envctrlunit *unitp, struct envctrl_chip *fanspeed)
{
	int readback_speed, max_speed;
	int status;
	int confirm_count = 0, confirm_max = 20;
	uint8_t fanspeed_hold;

	fanspeed_hold = fanspeed->val;
	while (confirm_count < confirm_max) {
		status = envctrl_write_chip(unitp, ENVCTRL_PCF8591,
		    EHC_DEV2, 0, &fanspeed->val, 1);
		if (status == DDI_FAILURE) {
			envctrl_fan_fail_service(unitp);
			cmn_err(CE_WARN,
			"%s%d: Set fanspeed failed", driver_name,
			    unitp->instance);
			return (status);
		} else {
			drv_usecwait(100000);
			envctrl_update_fanspeed(unitp);
			readback_speed = unitp->fan_kstats.fanspeed;
			if (fanspeed_hold > idle_fanspeed) {
				max_speed =
				    (fanspeed->val + FAN_DRIFT >
				    MAX_FAN_SPEED) ?  MAX_FAN_SPEED :
				    (fanspeed->val + FAN_DRIFT);
				if ((readback_speed < fanspeed->val -
				    FAN_DRIFT) ||
				    (readback_speed > max_speed)) {
					confirm_count++;
					drv_usecwait(1000);
					continue;
				}
			}
			break;
		}
	}

	if (confirm_count == confirm_max)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static void
envctrl_add_kstats(struct envctrlunit *unitp)
{

	ASSERT(MUTEX_HELD(&unitp->umutex));

	if ((unitp->enclksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_ENCL, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->encl_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "%s%d: encl raw kstat_create failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->enclksp->ks_update = envctrl_encl_kstat_update;
	unitp->enclksp->ks_private = (void *)unitp;
	kstat_install(unitp->enclksp);


	if ((unitp->fanksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_FANSTAT, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->fan_kstats),
	    KSTAT_FLAG_PERSISTENT | KSTAT_FLAG_WRITABLE)) == NULL) {
		cmn_err(CE_WARN, "%s%d: fans kstat_create failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->fanksp->ks_update = envctrl_fanstat_kstat_update;
	unitp->fanksp->ks_private = (void *)unitp;
	kstat_install(unitp->fanksp);

	if ((unitp->psksp = kstat_create(ENVCTRL_MODULE_NAME, unitp->instance,
	    ENVCTRL_KSTAT_PSNAME2, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->ps_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "%s%d: ps name kstat_create failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->psksp->ks_update = envctrl_ps_kstat_update;
	unitp->psksp->ks_private = (void *)unitp;
	kstat_install(unitp->psksp);

	if ((unitp->tempksp = kstat_create(ENVCTRL_MODULE_NAME,
	    unitp->instance, ENVCTRL_KSTAT_TEMPERATURE, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->temp_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "%s%d: temp name kstat_create failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->tempksp->ks_update = envctrl_temp_kstat_update;
	unitp->tempksp->ks_private = (void *)unitp;
	kstat_install(unitp->tempksp);

	if ((unitp->diskksp = kstat_create(ENVCTRL_MODULE_NAME,
	    unitp->instance, ENVCTRL_KSTAT_DISK, "misc", KSTAT_TYPE_RAW,
	    sizeof (unitp->disk_kstats),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "%s%d: disk name kstat_create failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->diskksp->ks_update = envctrl_disk_kstat_update;
	unitp->diskksp->ks_private = (void *)unitp;
	kstat_install(unitp->diskksp);

}

static int
envctrl_ps_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;



	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	kstatp = (char *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
		mutex_exit(&unitp->umutex);
		return (EACCES);
	} else {

		unitp->psksp->ks_ndata = unitp->num_ps_present;
		bcopy((caddr_t)&unitp->ps_kstats, kstatp,
		    sizeof (unitp->ps_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

static int
envctrl_fanstat_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;

	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		mutex_exit(&unitp->umutex);
		return (EACCES);
	} else {
		unitp->fanksp->ks_ndata = unitp->num_fans_present;
		bcopy((caddr_t)&unitp->fan_kstats, kstatp,
		    sizeof (unitp->fan_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

static int
envctrl_encl_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;
	int status;


	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		mutex_exit(&unitp->umutex);
		return (EACCES);
	} else {

		unitp->enclksp->ks_ndata = unitp->num_encl_present;
		status = envctrl_get_fpm_status(unitp, (uint8_t *)NULL);
		if (status == DDI_SUCCESS)
			bcopy((caddr_t)&unitp->encl_kstats, kstatp,
			    sizeof (unitp->encl_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

static int
envctrl_temp_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;

	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		mutex_exit(&unitp->umutex);
		return (EACCES);
	} else {
		unitp->tempksp->ks_ndata = unitp->num_temps_present;
		bcopy((caddr_t)unitp->temp_kstats, kstatp,
		    sizeof (unitp->temp_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

static int
envctrl_disk_kstat_update(kstat_t *ksp, int rw)
{
	struct envctrlunit *unitp;
	char *kstatp;

	kstatp = (char *)ksp->ks_data;
	unitp = (struct envctrlunit *)ksp->ks_private;

	mutex_enter(&unitp->umutex);
	ASSERT(MUTEX_HELD(&unitp->umutex));

	if (rw == KSTAT_WRITE) {
		mutex_exit(&unitp->umutex);
		return (EACCES);
	} else {
		unitp->diskksp->ks_ndata = unitp->num_disks_present;
		bcopy((caddr_t)unitp->disk_kstats, kstatp,
		    sizeof (unitp->disk_kstats));
	}
	mutex_exit(&unitp->umutex);
	return (DDI_SUCCESS);
}

static void
envctrl_init_encl_kstats(struct envctrlunit *unitp)
{
	uint8_t val;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV6,
	    0, &val, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (FSP) failed",
		    driver_name, unitp->instance);
		return;
	}

	unitp->encl_kstats.value = val;
}

static void
envctrl_check_disk_kstats(struct envctrlunit *unitp)
{
	uint8_t diskpr, diskfl;
	int status;

	ASSERT(MUTEX_HELD(&unitp->umutex));

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV5,
	    0, &diskpr, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (DISKPR) failed",
		    driver_name, unitp->instance);
	}

	status = envctrl_read_chip(unitp, ENVCTRL_PCF8574A, EHC_DEV7,
	    0, &diskfl, 1);
	if (status == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s%d: Read of PCF8574A (DISKFL) failed",
		    driver_name, unitp->instance);
	}

	envctrl_update_disk_kstats(unitp, diskpr, diskfl);

}

static void
envctrl_update_disk_kstats(struct envctrlunit *unitp, uint8_t diskpr,
	uint8_t diskfl)
{
	int i, j, count = 0;

	DPRINTF1("diskpr = %X, diskfl = %X\n", diskpr, diskfl);
	for (i = 0, j = 1; i < ENVCTRL_UE250_MAX_DISKS; i++, j = j << 1) {
		if (!(diskpr & j)) {
			if (!(diskfl & j))
				unitp->disk_kstats[count].disk_ok = 0;
			else
				unitp->disk_kstats[count].disk_ok = 1;
			unitp->disk_kstats[count].slot = i;
			count++;
		}
	}

	unitp->num_disks_present = count;
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

	(void) sprintf(name, "%s", ENVCTRL_ULTRA1CPU_STRING);
	(void) sprintf(name1, "%s", ENVCTRL_ULTRA2CPU_STRING);

	if ((strcmp(ddi_node_name(dip), name) == 0) ||
	    (strcmp(ddi_node_name(dip), name1) == 0)) {
		if ((cpu_slot = (int)ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "upa-portid",
		    -1)) == -1) {
			cmn_err(CE_WARN, "%s%d: no cpu upa-portid",
			    driver_name, unitp->instance);
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
	if ((unitp->fan_failed == B_TRUE) && thisled != 0) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_UE250_FSP_DISK_ERR) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_UE250_FSP_PS_ERR) {
		status = B_TRUE;
	} else if (fspval & ENVCTRL_UE250_FSP_TEMP_ERR) {
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
