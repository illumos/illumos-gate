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
 * Copyright 2015 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

/*
 * Driver for ACPI Battery, Lid, and Hotkey Control
 */
#include <sys/hotkey_drv.h>
#include <sys/sysevent/pwrctl.h>


#define	ACPI_DRV_MOD_STRING		"ACPI driver"

#define	ACPI_DRV_MAX_BAT_NUM		8
#define	ACPI_DRV_MAX_AC_NUM		10

#define	BST_FLAG_DISCHARGING		(0x1)
#define	BST_FLAG_CHARGING		(0x2)
#define	BST_FLAG_CRITICAL		(0x4)

/* Set if the battery is present */
#define	STA_FLAG_BATT_PRESENT		(0x10)

#define	ACPI_DEVNAME_CBAT		"PNP0C0A"
#define	ACPI_DEVNAME_AC			"ACPI0003"
#define	ACPI_DEVNAME_LID		"PNP0C0D"

#define	ACPI_DRV_EVENTS			(POLLIN | POLLRDNORM)

#ifdef DEBUG

#define	ACPI_DRV_PRINT_BUFFER_SIZE	512
static char acpi_drv_prt_buf[ACPI_DRV_PRINT_BUFFER_SIZE];
static kmutex_t acpi_drv_prt_mutex;

static int acpi_drv_debug = 0;
#define	ACPI_DRV_DBG(lev, devp, ...) \
	do { \
		if (acpi_drv_debug) acpi_drv_printf((devp), \
(lev), __VA_ARGS__); \
_NOTE(CONSTCOND) } while (0)
#define	ACPI_DRV_PRT_NOTIFY(hdl, val) \
	do { \
		if (acpi_drv_debug) acpi_drv_prt_notify((hdl), (val)); \
_NOTE(CONSTCOND) } while (0)

#else

#define	ACPI_DRV_DBG(lev, devp, ...)
#define	ACPI_DRV_PRT_NOTIFY(hdl, val)

#endif /* DEBUG */

/* ACPI notify types */
enum acpi_drv_notify {
	ACPI_DRV_NTF_UNKNOWN = -1,	/* No notifications seen, ever. */
	ACPI_DRV_NTF_CHANGED,
	ACPI_DRV_NTF_OK
};

static int acpi_drv_dev_present(struct acpi_drv_dev *);
#define	acpi_drv_ac_present(a)	(((a)->dev.type == ACPI_DRV_TYPE_AC) ? \
				acpi_drv_dev_present(&(a)->dev) : -1)
#define	acpi_drv_cbat_present(a)	(((a)->dev.type == ACPI_DRV_TYPE_CBAT) \
					? acpi_drv_dev_present(&(a)->dev) : -1)

static dev_info_t *acpi_drv_dip = NULL;
static kmutex_t acpi_drv_mutex;
static struct pollhead acpi_drv_pollhead;
static timeout_id_t acpi_drv_cbat_rescan_timeout;

/* Control Method Battery state */
struct acpi_drv_cbat_state {
	struct acpi_drv_dev dev;
	/* Caches of _BST and _BIF */
	enum acpi_drv_notify bat_bifok;
	acpi_bif_t bif_cache;
	enum acpi_drv_notify bat_bstok;
	acpi_bst_t bst_cache;

	uint32_t charge_warn;
	uint32_t charge_low;

	kstat_t *bat_bif_ksp;
	kstat_t *bat_bst_ksp;
} acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM];
static int nbat = 0;

/*
 * Synthesis battery state
 * When there are multiple batteries present, the battery subsystem
 * is not required to perform any synthesis of a composite battery
 * from the data of the separate batteries. In cases where the
 * battery subsystem does not synthesize a composite battery from
 * the separate battery's data, the OS must provide that synthesis.
 */
static uint32_t acpi_drv_syn_rem_cap;
static uint32_t acpi_drv_syn_last_cap;
static uint32_t acpi_drv_syn_oem_warn_cap;
static uint32_t acpi_drv_syn_oem_low_cap;

static int acpi_drv_warn_enabled;
static uint32_t acpi_drv_syn_warn_per;
static uint32_t acpi_drv_syn_low_per;
static uint32_t acpi_drv_syn_warn_cap;
static uint32_t acpi_drv_syn_low_cap;
/* Tracking boundery passing of _BST charge levels */
static uint32_t acpi_drv_syn_last_level;

/* AC state */
static struct acpi_drv_ac_state {
	struct acpi_drv_dev dev;
} acpi_drv_ac[ACPI_DRV_MAX_AC_NUM];
static int nac = 0;

/*
 * Current power source device
 * Note: assume only one device can be the power source device.
 */
static int acpi_drv_psr_type = ACPI_DRV_TYPE_UNKNOWN;
static struct acpi_drv_dev *acpi_drv_psr_devp = NULL;

struct obj_desc {
	char *name;
	int offset;
	int size;
	int type;
};

/* Object copy definitions */
#define	OFFSETOF(s, m)		((size_t)(&(((s *)0)->m)))
#define	SIZEOF(s, m)		(sizeof (((s *)0)->m))
#define	FIELD(n, s, m, t) \
	{ n, OFFSETOF(s, m), SIZEOF(s, m), t }
#define	FIELD_NULL		{ NULL, -1, 0, ACPI_TYPE_ANY }

static struct obj_desc bif_desc[] = {
	FIELD("bif_unit",	acpi_bif_t, bif_unit,	ACPI_TYPE_INTEGER),
	FIELD("bif_design_cap", acpi_bif_t, bif_design_cap, ACPI_TYPE_INTEGER),
	FIELD("bif_last_cap",	acpi_bif_t, bif_last_cap,   ACPI_TYPE_INTEGER),
	FIELD("bif_tech",	acpi_bif_t, bif_tech,	ACPI_TYPE_INTEGER),
	FIELD("bif_voltage",	acpi_bif_t, bif_voltage, ACPI_TYPE_INTEGER),
	FIELD("bif_warn_cap",	acpi_bif_t, bif_warn_cap, ACPI_TYPE_INTEGER),
	FIELD("bif_low_cap",	acpi_bif_t, bif_low_cap,  ACPI_TYPE_INTEGER),
	FIELD("bif_gran1_cap",	acpi_bif_t, bif_gran1_cap, ACPI_TYPE_INTEGER),
	FIELD("bif_gran2_cap",	acpi_bif_t, bif_gran2_cap, ACPI_TYPE_INTEGER),
	FIELD("bif_model",	acpi_bif_t, bif_model,	ACPI_TYPE_STRING),
	FIELD("bif_serial",	acpi_bif_t, bif_serial,	ACPI_TYPE_STRING),
	FIELD("bif_type",	acpi_bif_t, bif_type,	ACPI_TYPE_STRING),
	FIELD("bif_oem_info",	acpi_bif_t, bif_oem_info, ACPI_TYPE_STRING),
	FIELD_NULL
};

static struct obj_desc bst_desc[] = {
	FIELD("bst_state",   acpi_bst_t, bst_state,	ACPI_TYPE_INTEGER),
	FIELD("bst_rate",    acpi_bst_t, bst_rate,	ACPI_TYPE_INTEGER),
	FIELD("bst_rem_cap", acpi_bst_t, bst_rem_cap,	ACPI_TYPE_INTEGER),
	FIELD("bst_voltage", acpi_bst_t, bst_voltage,	ACPI_TYPE_INTEGER),
	FIELD_NULL
};

/* kstat definitions */
static kstat_t *acpi_drv_power_ksp;
static kstat_t *acpi_drv_warn_ksp;

acpi_drv_power_kstat_t acpi_drv_power_kstat = {
	{ SYSTEM_POWER,			KSTAT_DATA_STRING },
	{ SUPPORTED_BATTERY_COUNT,	KSTAT_DATA_UINT32 },
};

acpi_drv_warn_kstat_t acpi_drv_warn_kstat = {
	{ BW_ENABLED,			KSTAT_DATA_UINT32 },
	{ BW_POWEROFF_THRESHOLD,	KSTAT_DATA_UINT32 },
	{ BW_SHUTDOWN_THRESHOLD,	KSTAT_DATA_UINT32 },
};

/* BIF */
acpi_drv_bif_kstat_t acpi_drv_bif_kstat = {
	{ BIF_UNIT,		KSTAT_DATA_UINT32 },
	{ BIF_DESIGN_CAP,	KSTAT_DATA_UINT32 },
	{ BIF_LAST_CAP,		KSTAT_DATA_UINT32 },
	{ BIF_TECH,		KSTAT_DATA_UINT32 },
	{ BIF_VOLTAGE,		KSTAT_DATA_UINT32 },
	{ BIF_WARN_CAP,		KSTAT_DATA_UINT32 },
	{ BIF_LOW_CAP,		KSTAT_DATA_UINT32 },
	{ BIF_GRAN1_CAP,	KSTAT_DATA_UINT32 },
	{ BIF_GRAN2_CAP,	KSTAT_DATA_UINT32 },
	{ BIF_MODEL,		KSTAT_DATA_STRING },
	{ BIF_SERIAL,		KSTAT_DATA_STRING },
	{ BIF_TYPE,		KSTAT_DATA_STRING },
	{ BIF_OEM_INFO,		KSTAT_DATA_STRING },
};

/* BST */
acpi_drv_bst_kstat_t acpi_drv_bst_kstat = {
	{ BST_STATE,		KSTAT_DATA_UINT32 },
	{ BST_RATE,		KSTAT_DATA_UINT32 },
	{ BST_REM_CAP,		KSTAT_DATA_UINT32 },
	{ BST_VOLTAGE,		KSTAT_DATA_UINT32 },
};

struct acpi_drv_lid_state {
	struct acpi_drv_dev dev;
	enum acpi_drv_notify state_ok;
	int state;
} lid;
static int nlid = 0;

struct hotkey_drv acpi_hotkey;

static int acpi_drv_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int acpi_drv_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int acpi_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int acpi_drv_open(dev_t *devp, int flag, int otyp, cred_t *crp);
static int acpi_drv_close(dev_t dev, int flag, int otyp, cred_t *crp);
static int acpi_drv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
static int acpi_drv_chpoll(dev_t dev, short events, int anyyet,
    short *reventsp, struct pollhead **phpp);
static int acpi_drv_ac_ioctl(int index, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
static int acpi_drv_cbat_ioctl(int index, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
static int acpi_drv_lid_ioctl(int index, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
#ifdef DEBUG
static void acpi_drv_printf(struct acpi_drv_dev *devp, uint_t lev,
    const char *fmt, ...);
#endif

static int acpi_drv_update_bif(struct acpi_drv_cbat_state *bp);
static int acpi_drv_update_bst(struct acpi_drv_cbat_state *bp);
static int acpi_drv_update_lid(struct acpi_drv_dev *bp);
static int acpi_drv_set_warn(acpi_drv_warn_t *bwp);
static struct acpi_drv_cbat_state *acpi_drv_idx2cbat(int idx);
static struct acpi_drv_ac_state *acpi_drv_idx2ac(int idx);
static int acpi_drv_acpi_init(void);
static void acpi_drv_acpi_fini(void);
static int acpi_drv_kstat_init(void);
static void acpi_drv_kstat_fini(void);

static int acpi_drv_kstat_bif_update(kstat_t *, int);
static int acpi_drv_kstat_bst_update(kstat_t *, int);

static void acpi_drv_cbat_rescan(void *);

static struct cb_ops acpi_drv_cb_ops = {
	acpi_drv_open,		/* open */
	acpi_drv_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	acpi_drv_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	acpi_drv_chpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP,
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops acpi_drv_dev_ops = {
	DEVO_REV,
	0,			/* refcnt */
	acpi_drv_getinfo,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	acpi_drv_attach,	/* attach */
	acpi_drv_detach,	/* detach */
	nodev,			/* reset */
	&acpi_drv_cb_ops,
	NULL,			/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv1 = {
	&mod_driverops,
	ACPI_DRV_MOD_STRING,
	&acpi_drv_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv1,
	NULL,
};

int
_init(void)
{
	int ret;

	mutex_init(&acpi_drv_mutex, NULL, MUTEX_DRIVER, NULL);
#ifdef DEBUG
	mutex_init(&acpi_drv_prt_mutex, NULL, MUTEX_DRIVER, NULL);
#endif

	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&acpi_drv_mutex);
#ifdef DEBUG
		mutex_destroy(&acpi_drv_prt_mutex);
#endif
	}
	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
#ifdef DEBUG
		mutex_destroy(&acpi_drv_prt_mutex);
#endif
		mutex_destroy(&acpi_drv_mutex);
	}

	return (ret);
}

int
_info(struct modinfo *mp)
{
	return (mod_info(&modlinkage, mp));
}

static int
acpi_drv_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		/* Limit to one instance of driver */
		if (acpi_drv_dip) {
			return (DDI_FAILURE);
		}
		break;
	case DDI_RESUME:
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	acpi_drv_dip = devi;

	/* Init ACPI related stuff */
	if (acpi_drv_acpi_init() != ACPI_DRV_OK) {
		goto error;
	}

	/* Init kstat related stuff */
	if (acpi_drv_kstat_init() != ACPI_DRV_OK) {
		goto error;
	}

	acpi_drv_cbat_rescan_timeout = timeout(acpi_drv_cbat_rescan, NULL,
	    drv_usectohz(MICROSEC));

	return (DDI_SUCCESS);

error:
	ddi_remove_minor_node(devi, NULL);
	acpi_drv_kstat_fini();
	acpi_drv_acpi_fini();
	acpi_drv_dip = NULL;
	return (DDI_FAILURE);
}

static int
acpi_drv_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	timeout_id_t tmp_rescan_timeout;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Clear the timeout id to indicate that the handler should not
	 * reschedule itself.
	 */
	mutex_enter(&acpi_drv_mutex);
	tmp_rescan_timeout = acpi_drv_cbat_rescan_timeout;
	acpi_drv_cbat_rescan_timeout = 0;
	mutex_exit(&acpi_drv_mutex);

	(void) untimeout(tmp_rescan_timeout);

	mutex_enter(&acpi_drv_mutex);
	ddi_remove_minor_node(devi, NULL);

	acpi_drv_kstat_fini();
	acpi_drv_acpi_fini();
	mutex_exit(&acpi_drv_mutex);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
acpi_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = acpi_drv_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void*) 0;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
acpi_drv_open(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	if (acpi_drv_dip == NULL) {
		return (ENXIO);
	}

	return (0);
}

/*ARGSUSED*/
static int
acpi_drv_close(dev_t dev, int flag, int otyp, cred_t *crp)
{
	return (0);
}

/*ARGSUSED*/
static int
acpi_drv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int minor;
	int type, index;
	int res = 0;

	minor = getminor(dev);
	type = MINOR2TYPE(minor);
	index = MINOR2IDX(minor);

	mutex_enter(&acpi_drv_mutex);

	switch (type) {
	case ACPI_DRV_TYPE_CBAT:
		res = acpi_drv_cbat_ioctl(index, cmd, arg, mode, cr, rval);
		break;
	case ACPI_DRV_TYPE_AC:
		res = acpi_drv_ac_ioctl(index, cmd, arg, mode, cr, rval);
		break;
	case ACPI_DRV_TYPE_LID:
		res = acpi_drv_lid_ioctl(index, cmd, arg, mode, cr, rval);
		break;
	case ACPI_DRV_TYPE_HOTKEY:
		res = acpi_drv_hotkey_ioctl(cmd, arg, mode, cr, rval);
		break;
	default:
		res = EINVAL;
		break;
	}

	mutex_exit(&acpi_drv_mutex);
	return (res);
}

/*ARGSUSED*/
static int
acpi_drv_cbat_ioctl(int index, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int res = 0;
	acpi_drv_warn_t bwarn;
	struct acpi_drv_cbat_state *bp;

	ASSERT(mutex_owned(&acpi_drv_mutex));

	bp = acpi_drv_idx2cbat(index);
	if (!bp || bp->dev.valid != 1) {
		return (ENXIO);
	}

	switch (cmd) {
	/*
	 * Return _BIF(Battery Information) of battery[index],
	 * if battery plugged.
	 */
	case ACPI_DRV_IOC_INFO:
		if (bp->dev.present == 0) {
			res = ENXIO;
			break;
		}

		res = acpi_drv_update_bif(bp);
		if (res != ACPI_DRV_OK) {
			break;
		}
		if (copyout(&bp->bif_cache, (void *)arg,
		    sizeof (bp->bif_cache))) {
			res = EFAULT;
		}
		break;

	/*
	 * Return _BST(Battery Status) of battery[index],
	 * if battery plugged.
	 */
	case ACPI_DRV_IOC_STATUS:
		if (bp->dev.present == 0) {
			res = ENXIO;
			break;
		}

		res = acpi_drv_update_bst(bp);
		if (res != ACPI_DRV_OK) {
			break;
		}
		if (copyout(&bp->bst_cache, (void *)arg,
		    sizeof (bp->bst_cache))) {
			res = EFAULT;
		}
		break;

	/* Return the state of the battery bays in the system */
	case ACPI_DRV_IOC_BAY:
		{
			batt_bay_t bay;

			bay.bay_number = nbat;
			bay.battery_map = 0;
			for (bp = &acpi_drv_cbat[0];
			    bp < &acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM]; bp++) {
				if (bp->dev.valid) {
					if (bp->dev.present) {
						bay.battery_map |=
						    (1 << bp->dev.index);
					}
				}
			}
			if (copyout(&bay, (void *)arg, sizeof (bay))) {
				res = EFAULT;
				break;
			}
		}
		break;

	/*
	 * Return the current power source device if available:
	 * 0 -- battery supplying power
	 * 1 -- AC supplying power
	 */
	case ACPI_DRV_IOC_POWER_STATUS:
		{
			int val;

			/* State not available */
			if (acpi_drv_psr_type == ACPI_DRV_TYPE_UNKNOWN) {
				res = ENXIO;
				break;
			}
			val = (acpi_drv_psr_type == ACPI_DRV_TYPE_AC) ? 1 : 0;
			if (copyout(&val, (void *)arg, sizeof (val))) {
				res = EFAULT;
				break;
			}
		}
		break;

	/* Get charge-warn and charge-low levels for the whole system */
	case ACPI_DRV_IOC_GET_WARNING:
		bwarn.bw_enabled = acpi_drv_warn_enabled;
		bwarn.bw_charge_warn = acpi_drv_syn_warn_per;
		bwarn.bw_charge_low = acpi_drv_syn_low_per;
		if (copyout(&bwarn, (void *)arg, sizeof (&bwarn))) {
			res = EFAULT;
		}
		break;

	/* Set charge-warn and charge-low levels for the whole system */
	case ACPI_DRV_IOC_SET_WARNING:
		if (drv_priv(cr)) {
			res = EPERM;
			break;
		}
		if (copyin((void *)arg, &bwarn, sizeof (bwarn))) {
			res = EFAULT;
			break;
		}
		res = acpi_drv_set_warn(&bwarn);
		break;

	default:
		res = EINVAL;
		break;
	}

	return (res);
}

/*ARGSUSED*/
static int
acpi_drv_ac_ioctl(int index, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int res = 0;
	int ac_state;
	struct acpi_drv_ac_state *acp;

	ASSERT(mutex_owned(&acpi_drv_mutex));

	acp = acpi_drv_idx2ac(index);
	if (!acp || acp->dev.valid != 1) {
		return (ENXIO);
	}

	switch (cmd) {
	/* Return the number of AC adapters in the system */
	case ACPI_DRV_IOC_AC_COUNT:
		if (copyout(&nac, (void *)arg, sizeof (nac))) {
			res = EFAULT;
		}
		break;

	/*
	 * Return the state of AC[index] if available:
	 * 0 -- Off-line
	 * 1 -- On-line
	 */
	case ACPI_DRV_IOC_POWER_STATUS:
		if (!acp || acp->dev.valid != 1) {
			res = ENXIO;
			break;
		}
		/* State not available */
		if ((ac_state = acpi_drv_ac_present(acp)) == -1) {
			res = ENXIO;
			break;
		}
		if (copyout(&ac_state, (void *)arg, sizeof (ac_state))) {
			res = EFAULT;
		}
		break;

	default:
		res = EINVAL;
		break;
	}

	return (res);
}

/*ARGSUSED*/
static int
acpi_drv_lid_ioctl(int index, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int res = 0;

	/*
	 * lid.state 0 means lid is closed.
	 * lid.state non-zero means lid is open.
	 */
	switch (cmd) {
	case ACPI_DRV_IOC_LID_STATUS:
		if (lid.state_ok == ACPI_DRV_NTF_UNKNOWN) {
			/* State not available */
			res = acpi_drv_update_lid(&lid.dev);
			if (res != ACPI_DRV_OK) {
				res = ENXIO;
				break;
			}
		}
		if (copyout(&lid.state, (void *)arg, sizeof (lid.state))) {
			res = EFAULT;
		}
		break;
	case ACPI_DRV_IOC_LID_UPDATE:
		res = acpi_drv_update_lid(&lid.dev);
		if (res != ACPI_DRV_OK) {
			res = ENXIO;
			break;
		}
		if (copyout(&lid.state, (void *)arg, sizeof (lid.state))) {
			res = EFAULT;
		}
		break;

	default:
		res = EINVAL;
		break;
	}
	return (res);
}

/*ARGSUSED*/
static int
acpi_drv_chpoll(dev_t dev, short events, int anyyet,  short *reventsp,
	struct pollhead **phpp)
{
	if (!anyyet) {
		*phpp = &acpi_drv_pollhead;
	}
	*reventsp = 0;
	return (0);
}

#ifdef DEBUG
static void
acpi_drv_printf(struct acpi_drv_dev *devp, uint_t lev,
    const char *fmt, ...)
{
	va_list args;

	mutex_enter(&acpi_drv_prt_mutex);

	va_start(args, fmt);
	(void) vsprintf(acpi_drv_prt_buf, fmt, args);
	va_end(args);

	if (devp) {
		cmn_err(lev, "%s.%s: %s", devp->hid, devp->uid,
		    acpi_drv_prt_buf);
	} else {
		cmn_err(lev, "%s", acpi_drv_prt_buf);
	}
	mutex_exit(&acpi_drv_prt_mutex);
}

static void
acpi_drv_prt_notify(ACPI_HANDLE hdl, UINT32 val)
{
	ACPI_BUFFER buf;
	char str[1024];

	buf.Length = sizeof (str);
	buf.Pointer = str;
	(void) AcpiGetName(hdl, ACPI_FULL_PATHNAME, &buf);
	cmn_err(CE_NOTE, "AcpiNotify(%s, 0x%02x)", str, val);
}
#endif /* DEBUG */

void
acpi_drv_gen_sysevent(struct acpi_drv_dev *devp, char *ev, uint32_t val)
{
	nvlist_t *attr_list = NULL;
	int err;
	char pathname[MAXPATHLEN];

	/* Allocate and build sysevent attribute list */
	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, DDI_NOSLEEP);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "cannot allocate memory for sysevent attributes\n");
		return;
	}

	/* Add attributes */
	err = nvlist_add_string(attr_list, PWRCTL_DEV_HID, devp->hid);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    PWRCTL_DEV_HID, EC_PWRCTL, ev);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, PWRCTL_DEV_UID, devp->uid);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    PWRCTL_DEV_UID, EC_PWRCTL, ev);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_uint32(attr_list, PWRCTL_DEV_INDEX, devp->index);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    PWRCTL_DEV_INDEX, EC_PWRCTL, ev);
		nvlist_free(attr_list);
		return;
	}

	(void) ddi_pathname(acpi_drv_dip, pathname);
	err = nvlist_add_string(attr_list, PWRCTL_DEV_PHYS_PATH, pathname);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    PWRCTL_DEV_PHYS_PATH, EC_PWRCTL, ev);
		nvlist_free(attr_list);
		return;
	}

	if (strcmp(ev, ESC_PWRCTL_WARN) && strcmp(ev, ESC_PWRCTL_LOW)) {
		goto finish;
	}

	err = nvlist_add_uint32(attr_list, PWRCTL_CHARGE_LEVEL, val);
	if (err != 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    PWRCTL_CHARGE_LEVEL, EC_PWRCTL, ev);
		nvlist_free(attr_list);
		return;
	}

finish:
	ACPI_DRV_DBG(CE_NOTE, NULL, "SysEv(%s, %s.%s, %d)",
	    ev, devp->hid, devp->uid, val);
	/* Generate/log sysevent */
	err = ddi_log_sysevent(acpi_drv_dip, DDI_VENDOR_SUNW, EC_PWRCTL,
	    ev, attr_list, NULL, DDI_NOSLEEP);
#ifdef DEBUG
	if (err != DDI_SUCCESS) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "cannot log sysevent, err code %x\n", err);
	}
#endif

	nvlist_free(attr_list);
}

static int
acpi_drv_obj_copy(ACPI_OBJECT *op, char *bp, struct obj_desc *dp)
{
	ACPI_OBJECT *ep;
	char *fp;

	ep = &op->Package.Elements[0];
	for (; dp->offset != -1; dp++) {
		fp = bp + dp->offset;
		if (dp->type == ACPI_TYPE_INTEGER &&
		    ep->Type == dp->type) {
#ifdef DEBUG
			if (dp->size <= 4) {
				ACPI_DRV_DBG(CE_NOTE, NULL, "\t%s: %u",
				    dp->name,
				    (uint32_t)ep->Integer.Value);
			} else {
#ifdef _LP64
				ACPI_DRV_DBG(CE_NOTE, NULL, "\t%s: %lu",
				    dp->name, (uint64_t)ep->Integer.Value);
			}
#else
				ACPI_DRV_DBG(CE_NOTE, NULL, "\t%s: %llu",
				    dp->name, (uint64_t)ep->Integer.Value);
			}
#endif /* _LP64 */
#endif /* DEBUG */
			*(uint32_t *)fp = ep->Integer.Value;
		} else if (dp->type == ACPI_TYPE_STRING &&
		    ep->Type == dp->type) {
			ACPI_DRV_DBG(CE_NOTE, NULL, "\t%s: \"%s\"",
			    dp->name, ep->String.Pointer);
			(void) strlcpy(fp, ep->String.Pointer, dp->size);
		} else if (dp->type == ACPI_TYPE_STRING &&
		    ep->Type == ACPI_TYPE_BUFFER) {
#ifdef DEBUG
			int len;
			char buf[MAXNAMELEN + 1];

			len = (MAXNAMELEN < ep->Buffer.Length) ?
			    MAXNAMELEN : ep->Buffer.Length;
			bcopy(ep->Buffer.Pointer, buf, len);
			buf[len] = 0;
			ACPI_DRV_DBG(CE_NOTE, NULL, "\t%s: [%d] \"%s\"",
			    dp->name, len, buf);
#endif

			ASSERT(MAXNAMELEN >= ep->Buffer.Length);
			bcopy(ep->Buffer.Pointer, fp, ep->Buffer.Length);
		} else {
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "Bad field at offset %d: type %d",
			    dp->offset, ep->Type);
			if (dp->type != ACPI_TYPE_STRING) {
				return (ACPI_DRV_ERR);
			}
		}
		ep++;
	}

	return (ACPI_DRV_OK);
}

/*
 * Returns the current power source devices. Used for the AC adapter and is
 * located under the AC adapter object in name space. Used to determine if
 * system is running off the AC adapter. This will report that the system is
 * not running on the AC adapter if any of the batteries in the system is
 * being forced to discharge through _BMC.
 *
 * Return value:
 *	 0 -- Off-line, ie. battery supplying system power
 *	 1 -- On-line, ie. AC supplying system power
 *	-1 -- Unknown, some error ocurred.
 * Note: It will also update the driver ac state.
 */
static int
acpi_drv_get_psr(struct acpi_drv_ac_state *acp)
{
	struct acpi_drv_dev *devp = &acp->dev;
	int ac;

	if (!devp->valid) {
		ACPI_DRV_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	if (acpica_eval_int(devp->hdl, "_PSR", &ac) == AE_OK) {
		ACPI_DRV_DBG(CE_NOTE, devp, "_PSR = %d", ac);
		devp->present = ac;
	} else {
		ACPI_DRV_DBG(CE_WARN, NULL, "AcpiEval _PSR failed");
		devp->present = -1;
	}

	return (ac);
}

/*
 * For most systems, the _STA for this device will always
 * return a value with bits 0-3 set and will toggle bit 4
 * to indicate the actual presence of a battery.
 *
 * Return value:
 *	 0 -- battery not present
 *	 1 -- battery present
 *	-1 -- Unknown, some error ocurred.
 * Note: It will also update the driver cbat state.
 */
static int
acpi_drv_get_sta(struct acpi_drv_cbat_state *bp)
{
	struct acpi_drv_dev *devp = &bp->dev;
	int val;

	if (!devp->valid) {
		ACPI_DRV_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	if (acpica_eval_int(devp->hdl, "_STA", &val) == AE_OK) {
		ACPI_DRV_DBG(CE_NOTE, devp, "_STA = 0x%x", val);
		devp->present = ((val & STA_FLAG_BATT_PRESENT) != 0);
	} else {
		ACPI_DRV_DBG(CE_WARN, NULL, "AcpiEval _STA failed");
		devp->present = -1;
	}

	return (val);
}

static int
acpi_drv_update_bif(struct acpi_drv_cbat_state *bp)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT *objp;

	/* BIF is only available when battery plugged */
	ASSERT(bp->dev.present != 0);

	/* Update internal BIF cache */
	bp->bat_bifok = ACPI_DRV_NTF_UNKNOWN;

	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(bp->dev.hdl, "_BIF",
	    NULL, &buf, ACPI_TYPE_PACKAGE))) {
		ACPI_DRV_DBG(CE_WARN, NULL, "AcpiEval _BIF failed");
		return (ACPI_DRV_ERR);
	}

	objp = buf.Pointer;
	ACPI_DRV_DBG(CE_NOTE, &bp->dev, "get _BIF");
	if (acpi_drv_obj_copy(objp, (char *)&bp->bif_cache, bif_desc) ==
	    ACPI_DRV_ERR) {
		AcpiOsFree(objp);
		return (ACPI_DRV_ERR);
	}
	AcpiOsFree(objp);
	bp->bat_bifok = ACPI_DRV_NTF_OK;
	return (ACPI_DRV_OK);
}

static int
acpi_drv_update_bst(struct acpi_drv_cbat_state *bp)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT *objp;

	/* BST is only available when battery plugged */
	ASSERT(bp->dev.present != 0);

	/* Update internal BST cache */
	bp->bat_bstok = ACPI_DRV_NTF_UNKNOWN;

	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(bp->dev.hdl, "_BST",
	    NULL, &buf, ACPI_TYPE_PACKAGE))) {
		ACPI_DRV_DBG(CE_WARN, NULL, "AcpiEval _BST failed");
		return (ACPI_DRV_ERR);
	}

	objp = buf.Pointer;
	ACPI_DRV_DBG(CE_NOTE, &bp->dev, "get _BST");
	if (acpi_drv_obj_copy(objp, (char *)&bp->bst_cache, bst_desc) ==
	    ACPI_DRV_ERR) {
		AcpiOsFree(objp);
		return (ACPI_DRV_ERR);
	}
	AcpiOsFree(objp);

	if (bp->bst_cache.bst_rate == 0) {
		bp->bst_cache.bst_state &= ~(ACPI_DRV_BST_CHARGING |
		    ACPI_DRV_BST_DISCHARGING);
	}
	bp->bat_bstok = ACPI_DRV_NTF_OK;
	return (ACPI_DRV_OK);
}

/*
 * Return value:
 *	 1 -- device On-line
 *	 0 -- device Off-line
 *	-1 -- Unknown, some error ocurred.
 */
static int
acpi_drv_dev_present(struct acpi_drv_dev *devp)
{
	if (!devp->valid) {
		ACPI_DRV_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	ASSERT(devp->type != ACPI_DRV_TYPE_UNKNOWN);

	/* Update the device state */
	if (devp->present == -1) {
		if (devp->type == ACPI_DRV_TYPE_AC) {
			(void) acpi_drv_get_psr((struct acpi_drv_ac_state *)
			    devp);
		} else if (devp->type == ACPI_DRV_TYPE_CBAT) {
			(void) acpi_drv_get_sta((struct acpi_drv_cbat_state *)
			    devp);
		}
	}

	return (devp->present);
}

/*
 * Check if the device p existance state has changed.
 * Return value:
 *	 1 -- changed
 *	 0 -- no change
 *	-1 -- unknown
 */
static int
acpi_drv_update_present(struct acpi_drv_dev *p)
{
	int old_present = p->present;
	int new_present;

	ASSERT(p && p->valid);

	p->present = -1;
	new_present = acpi_drv_dev_present(p);
	if (new_present == -1) {
		return (-1);
	}
	if (new_present != old_present) {
		return (1);
	}
	return (0);
}

static void
acpi_drv_set_psr(struct acpi_drv_dev *p)
{
	acpi_drv_psr_devp = p;
	if (p != NULL) {
		ACPI_DRV_DBG(CE_NOTE, p, "psr = .");
		acpi_drv_psr_type = p->type;
	} else {
		ACPI_DRV_DBG(CE_NOTE, p, "psr = ?");
		acpi_drv_psr_type = ACPI_DRV_TYPE_UNKNOWN;
	}
}

/*
 * OSPM can determine independent warning and low battery
 * capacity values based on the OEM-designed levels, but
 * cannot set these values lower than the OEM-designed values.
 */
static int
acpi_drv_set_warn(acpi_drv_warn_t *bwp)
{
	uint32_t warn, low;

	warn = acpi_drv_syn_last_cap * bwp->bw_charge_warn / 100;
	low = acpi_drv_syn_last_cap * bwp->bw_charge_low / 100;

	/* Update internal state */
	if (bwp->bw_enabled) {
		if (low >= warn || warn < acpi_drv_syn_oem_warn_cap ||
		    low < acpi_drv_syn_oem_low_cap) {
			ACPI_DRV_DBG(CE_WARN, NULL, "charge level error");
			return (EINVAL);
		}

		ACPI_DRV_DBG(CE_NOTE, NULL, "set warn: warn=%d low=%d", warn,
		    low);

		acpi_drv_syn_warn_per = bwp->bw_charge_warn;
		acpi_drv_syn_low_per = bwp->bw_charge_low;
		acpi_drv_syn_warn_cap = warn;
		acpi_drv_syn_low_cap = low;
		acpi_drv_warn_enabled = 1;
	} else {
		acpi_drv_warn_enabled = 0;
	}

	return (0);
}

/*
 * Update information for the synthesis battery
 *
 * Note: Sometimes the value to be returned from _BST or _BIF will be
 * temporarily unknown. In this case, the method may return the value
 * 0xFFFFFFFF as a placeholder. When the value becomes known, the
 * appropriate notification (0x80 for _BST or 0x81 for BIF) should be
 * issued, in like manner to any other change in the data returned by
 * these methods. This will cause OSPM to re-evaluate the method obtaining
 * the correct data value.
 */
static void
acpi_drv_update_cap(int bif_changed)
{
	struct acpi_drv_cbat_state *bp;

	if (bif_changed != 0) {
		acpi_drv_syn_oem_warn_cap = 0xffffffff;
		acpi_drv_syn_oem_low_cap = 0xffffffff;
		acpi_drv_syn_last_cap = 0xffffffff;
	}
	acpi_drv_syn_last_level = acpi_drv_syn_rem_cap;
	acpi_drv_syn_rem_cap = 0xffffffff; /* initially unknown */

	for (bp = &acpi_drv_cbat[0]; bp < &acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM];
	    bp++) {
		if (bp->dev.valid) {
			/* Escape the empty bays */
			if (acpi_drv_cbat_present(bp) <= 0) {
				continue;
			}

			if (bif_changed != 0 &&
			    bp->bat_bifok == ACPI_DRV_NTF_OK) {
				acpi_bif_t *bif;

				bif = &bp->bif_cache;

				if (acpi_drv_syn_last_cap == 0xffffffff) {
					acpi_drv_syn_last_cap = 0;
				}
				acpi_drv_syn_last_cap += bif->bif_last_cap;

				if (bif->bif_warn_cap == 0xffffffff ||
				    bif->bif_low_cap == 0xffffffff) {
					ACPI_DRV_DBG(CE_WARN, &bp->dev,
					    "BIF value "
					    "invalid, warn_cap=0x%x "
					    "low_cap=0x%x", bif->bif_warn_cap,
					    bif->bif_low_cap);
					continue;
				}
				if (acpi_drv_syn_oem_warn_cap == 0xffffffff) {
					acpi_drv_syn_oem_warn_cap = 0;
				}
				if (acpi_drv_syn_oem_low_cap == 0xffffffff) {
					acpi_drv_syn_oem_low_cap = 0;
				}

				/*
				 * Use the highest level as the synthesis
				 * level.
				 */
				if (bif->bif_warn_cap >
				    acpi_drv_syn_oem_warn_cap) {
					acpi_drv_syn_oem_low_cap =
					    bif->bif_low_cap;
					acpi_drv_syn_oem_warn_cap =
					    bif->bif_warn_cap;
				}
			}
#ifdef DEBUG
			else if (bif_changed) {
				ACPI_DRV_DBG(CE_NOTE, &bp->dev,
				    "BIF not ready");
			}
#endif

			if (bp->bat_bstok == ACPI_DRV_NTF_OK) {
				acpi_bst_t *bst;

				bst = &bp->bst_cache;

				/*
				 * Batteries that are rechargeable and are in
				 * the discharging state are required to return
				 * a valid Battery Present Rate value.
				 * 0xFFFFFFFF - Unknown rate/capacity
				 */
				if (bst->bst_rem_cap == 0xffffffff) {
					ACPI_DRV_DBG(CE_WARN, &bp->dev,
					    "BST value invalid, "
					    "rate=0x%x cap=0x%x",
					    bst->bst_rate, bst->bst_rem_cap);
					continue;
				}

				if (acpi_drv_syn_rem_cap == 0xffffffff) {
					acpi_drv_syn_rem_cap = 0;
				}
				acpi_drv_syn_rem_cap += bst->bst_rem_cap;
				/* Check for overflow */
				ASSERT(acpi_drv_syn_rem_cap >=
				    bst->bst_rem_cap);
			}
#ifdef DEBUG
			else {
				ACPI_DRV_DBG(CE_NOTE, &bp->dev,
				    "BST not ready");
			}
#endif
		}
	}

	ACPI_DRV_DBG(CE_NOTE, NULL, "syn_cap: %d syn_oem_warn: %d "
	    "syn_oem_low: %d", acpi_drv_syn_rem_cap, acpi_drv_syn_oem_warn_cap,
	    acpi_drv_syn_oem_low_cap);
}

static struct acpi_drv_cbat_state *
acpi_drv_idx2cbat(int idx)
{
	if (idx >= ACPI_DRV_MAX_BAT_NUM) {
		return (NULL);
	}
	return (&acpi_drv_cbat[idx]);
}

static struct acpi_drv_ac_state *
acpi_drv_idx2ac(int idx)
{
	if (idx >= ACPI_DRV_MAX_AC_NUM) {
		return (NULL);
	}
	return (&acpi_drv_ac[idx]);
}

/*ARGSUSED*/
static void
acpi_drv_cbat_notify(ACPI_HANDLE hdl, UINT32 val, void *ctx)
{
	struct acpi_drv_cbat_state *bp = ctx;
	struct acpi_drv_dev *devp = &bp->dev;
	int bif_changed;
	uint32_t eval;
	char *ev;
	acpi_bst_t *bst;

	mutex_enter(&acpi_drv_mutex);
	ACPI_DRV_PRT_NOTIFY(hdl, val);

	switch (val) {
	/*
	 * BST has changed
	 * Whenever the Battery State value changes, the
	 * system will generate an SCI to notify the OS.
	 *
	 * Note: trip point is not used to implement the
	 * warning levels.
	 */
	case 0x80:
		/*
		 * We always get 0x80 and 0x81 at battery plug/unplug,
		 * but 0x80 may come first. In case that situation, we have
		 * to update battery present state here too to update bst
		 * correctly.
		 */
		bif_changed = acpi_drv_update_present(devp);

		if (devp->present == 0) {
			if (acpi_drv_psr_devp == devp) {
				acpi_drv_set_psr(NULL);
			}
			goto done;
		}

		if (acpi_drv_update_bst(bp) != ACPI_DRV_OK) {
			break;
		}
		acpi_drv_update_cap(bif_changed);

		bst = &bp->bst_cache;
		eval = bst->bst_rem_cap;

		if (bst->bst_state & BST_FLAG_DISCHARGING) {
			acpi_drv_set_psr(devp);
		}
		/*
		 * The Critical battery state indicates that all
		 * available batteries are discharged and do not
		 * appear to be able to supply power to run the
		 * system any longer. When this occurs, the OS
		 * should attempt to perform an emergency shutdown.
		 * Right now we do not shutdown.  This would
		 * need some discussion first since it could be
		 * controversial.
		 */
#ifdef DEBUG
		if (bst->bst_state & BST_FLAG_CRITICAL) {
			ACPI_DRV_DBG(CE_WARN, devp, "BST_FLAG_CRITICAL set");

			/*
			 * BST_FLAG_CRITICAL may set even with AC,
			 * plugged, when plug/unplug battery. Check
			 * to avoid erroneous shutdown.
			 */
			if (acpi_drv_psr_devp == devp &&
			    bst->bst_rem_cap != 0xffffffff) {
				ACPI_DRV_DBG(CE_WARN, NULL,
				    "Battery in critical state");
			}
		} else
#endif
		if (acpi_drv_warn_enabled &&
		    (bst->bst_state & BST_FLAG_DISCHARGING)) {
			/*
			 * This value is an estimation of the amount of
			 * energy or battery capacity required by the
			 * system to transition to any supported sleeping
			 * state. When the OS detects that the total
			 * available battery capacity is less than this
			 * value, it will transition the system to a user
			 * defined system state (S1-S5).
			 */
			if (acpi_drv_syn_last_level > acpi_drv_syn_low_cap &&
			    acpi_drv_syn_rem_cap <= acpi_drv_syn_low_cap) {
				acpi_drv_gen_sysevent(devp, ESC_PWRCTL_LOW,
				    eval);
			/*
			 * When the total available energy (mWh) or capacity
			 * (mAh) in the batteries falls below this level,
			 * the OS will notify the user through the UI.
			 */
			} else if (acpi_drv_syn_last_level >
			    acpi_drv_syn_warn_cap &&
			    acpi_drv_syn_rem_cap <= acpi_drv_syn_warn_cap) {
				acpi_drv_gen_sysevent(devp, ESC_PWRCTL_WARN,
				    eval);
			}
		}

done:
		acpi_drv_gen_sysevent(devp, ESC_PWRCTL_STATE_CHANGE, 0);
		pollwakeup(&acpi_drv_pollhead, ACPI_DRV_EVENTS);
		break;

	/* battery has been removed completely */
	case 0x03:
	/* BIF has changed */
	case 0x81:
		/*
		 * Note: Do not eliminate multiple ADD/REMOVE here,
		 * because they may corresponding to different batterys.
		 */
		(void) acpi_drv_update_present(devp);
		if (devp->present == 1) {
			if (acpi_drv_update_bif(bp) != ACPI_DRV_OK) {
				break;
			}
		}

		acpi_drv_update_cap(1);

		eval = devp->present;
		ev = eval ? ESC_PWRCTL_ADD : ESC_PWRCTL_REMOVE;
		acpi_drv_gen_sysevent(devp, ev, 0);
		pollwakeup(&acpi_drv_pollhead, ACPI_DRV_EVENTS);
		break;

	case 0x82:
	default:
		break;
	}

	mutex_exit(&acpi_drv_mutex);
}

static int
acpi_drv_update_lid(struct acpi_drv_dev *p)
{
	struct acpi_drv_lid_state *lp = (struct acpi_drv_lid_state *)p;

	if (acpica_eval_int(p->hdl, "_LID", &lp->state) == AE_OK) {
		lp->state_ok = ACPI_DRV_NTF_OK;
		return (ACPI_DRV_OK);
	}
	return (ACPI_DRV_ERR);
}

/*ARGSUSED*/
static void
acpi_drv_ac_notify(ACPI_HANDLE hdl, UINT32 val, void *ctx)
{
	struct acpi_drv_ac_state *acp = ctx;
	struct acpi_drv_dev *devp = &acp->dev;
	int old_present;
	char *ev;
	int eval;

	ACPI_DRV_PRT_NOTIFY(hdl, val);
	if (val != 0x80) {
		return;
	}

	mutex_enter(&acpi_drv_mutex);
	/*
	 * Note: if unplug and then quickly plug back, two ADD
	 * events will be generated.
	 */
	old_present = devp->present;
	eval = acpi_drv_get_psr(acp);

	/* Eliminate redundant events */
	if (eval != -1 && eval != old_present) {
		/* Keep tracking the current power source device */
		if (eval == 1) {
			ev = ESC_PWRCTL_ADD;
			acpi_drv_set_psr(devp);
		} else {
			ev = ESC_PWRCTL_REMOVE;
			/* If AC was supplying the power, it's not now */
			if (acpi_drv_psr_devp == devp) {
				acpi_drv_set_psr(NULL);
			}
		}

		acpi_drv_gen_sysevent(devp, ev, 0);
		pollwakeup(&acpi_drv_pollhead, ACPI_DRV_EVENTS);
	}

	mutex_exit(&acpi_drv_mutex);
}

static void
acpi_drv_lid_notify(ACPI_HANDLE hdl, UINT32 val, void *ctx)
{
	struct acpi_drv_lid_state *p = ctx;

	ACPI_DRV_PRT_NOTIFY(hdl, val);
	if (val == 0x80) {
		mutex_enter(&acpi_drv_mutex);
		if (acpi_drv_update_lid(&p->dev) == ACPI_DRV_OK) {
			acpi_drv_gen_sysevent(&p->dev, p->state ?
			    ESC_PWRCTL_ADD : ESC_PWRCTL_REMOVE, 0);
		}
		mutex_exit(&acpi_drv_mutex);
	}
}

static int
acpi_drv_obj_init(struct acpi_drv_dev *p)
{
	ACPI_DEVICE_INFO *info;
	ACPI_NOTIFY_HANDLER ntf_handler = NULL;
	ACPI_STATUS ret;
	char name[KSTAT_STRLEN];

	ASSERT(p != NULL && p->hdl != NULL);

	p->valid = 0;

	/* Info size is variable depending on existance of _CID */
	ret = AcpiGetObjectInfo(p->hdl, &info);
	if (ACPI_FAILURE(ret)) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo() fail: %d", (int32_t)ret);
		return (ACPI_DRV_ERR);
	}

	if ((info->Valid & ACPI_VALID_HID) == 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo(): _HID not available");
		p->hid[0] = 0;
	} else {
		(void) strlcpy(p->hid, info->HardwareId.String, ID_LEN);
	}

	/*
	 * This object is optional, but is required when the device
	 * has no other way to report a persistent unique device ID.
	 */
	if ((info->Valid & ACPI_VALID_UID) == 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo(): _UID not available");
		/* Use 0 as the default _UID */
		p->uid[0] = 0;
	} else {
		(void) strlcpy(p->uid, info->UniqueId.String, ID_LEN);
	}

	AcpiOsFree(info);
	p->valid = 1;

	if (strcmp(p->hid, ACPI_DEVNAME_CBAT) == 0) {
		struct acpi_drv_cbat_state *bp =
		    (struct acpi_drv_cbat_state *)p;
		kstat_t *ksp;

		p->type = ACPI_DRV_TYPE_CBAT;
		p->index = nbat - 1;

		/* Update device present state */
		(void) acpi_drv_update_present(p);
		if (p->present) {
			(void) acpi_drv_update_bif(bp);
			(void) acpi_drv_update_bst(bp);

			/* Init the current power source */
			if (bp->bst_cache.bst_state & BST_FLAG_DISCHARGING) {
				acpi_drv_set_psr(p);
			}
		}
		ntf_handler = acpi_drv_cbat_notify;
		ACPI_DRV_DBG(CE_NOTE, p, "battery %s",
		    (p->present ? "present" : "absent"));

		/* Create minor node for battery */
		(void) snprintf(name, sizeof (name), "battery%d", p->index);
		if (ddi_create_minor_node(acpi_drv_dip, name, S_IFCHR,
		    MINOR_BATT(p->index), DDI_PSEUDO, 0) == DDI_FAILURE)
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "%s: minor node create failed", name);

		/*
		 * Allocate, initialize and install BIF and BST kstat
		 */
		/* BIF kstat */
		(void) snprintf(name, KSTAT_STRLEN-1, "%s%d",
		    ACPI_DRV_BIF_KSTAT_NAME, bp->dev.index);
		ksp = kstat_create(ACPI_DRV_NAME, 0, name, "misc",
		    KSTAT_TYPE_NAMED,
		    sizeof (acpi_drv_bif_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
		if (ksp != NULL) {
			ACPI_DRV_DBG(CE_NOTE, NULL, "kstat_create(%s) ok",
			    name);

			bp->bat_bif_ksp = ksp;
			ksp->ks_data = &acpi_drv_bif_kstat;
			ksp->ks_update = acpi_drv_kstat_bif_update;
			ksp->ks_data_size += MAXNAMELEN * 4;
			ksp->ks_private = bp;

			kstat_install(ksp);
		} else {
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "kstat_create(%s) fail", name);
		}

		/* BST kstat */
		(void) snprintf(name, KSTAT_STRLEN-1, "%s%d",
		    ACPI_DRV_BST_KSTAT_NAME, bp->dev.index);
		ksp = kstat_create(ACPI_DRV_NAME, 0, name, "misc",
		    KSTAT_TYPE_NAMED,
		    sizeof (acpi_drv_bst_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);
		if (ksp != NULL) {
			ACPI_DRV_DBG(CE_NOTE, NULL, "kstat_create(%s) ok",
			    name);

			bp->bat_bst_ksp = ksp;
			ksp->ks_data = &acpi_drv_bst_kstat;
			ksp->ks_update = acpi_drv_kstat_bst_update;
			ksp->ks_data_size += MAXNAMELEN * 4;
			ksp->ks_private = bp;

			kstat_install(ksp);
		} else {
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "kstat_create(%s) fail", name);
		}
	} else if (strcmp(p->hid, ACPI_DEVNAME_AC) == 0) {
		p->type = ACPI_DRV_TYPE_AC;
		p->index = nac - 1;

		/* Update device present state */
		(void) acpi_drv_update_present(p);
		if (p->present) {
			/* Init the current power source */
			acpi_drv_set_psr(p);
		}
		ntf_handler = acpi_drv_ac_notify;
		ACPI_DRV_DBG(CE_NOTE, p, "AC %s",
		    (p->present ? "on-line" : "off-line"));

		/* Create minor node for AC */
		(void) snprintf(name, sizeof (name), "ac%d", p->index);
		if (ddi_create_minor_node(acpi_drv_dip, name, S_IFCHR,
		    MINOR_AC(p->index), DDI_PSEUDO, 0) == DDI_FAILURE)
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "%s: minor node create failed", name);
	} else if (strcmp(p->hid, ACPI_DEVNAME_LID) == 0) {
		p->type = ACPI_DRV_TYPE_LID;
		p->index = 0;
		lid.state_ok = ACPI_DRV_NTF_UNKNOWN;
		(void) acpi_drv_update_lid(p);
		ntf_handler = acpi_drv_lid_notify;
		ACPI_DRV_DBG(CE_NOTE, p, "added");

		/* Create minor node for lid. */
		if (ddi_create_minor_node(acpi_drv_dip, "lid", S_IFCHR,
		    MINOR_LID(p->index), DDI_PSEUDO, 0) == DDI_FAILURE)
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "lid: minor node create failed");
	} else {
		ACPI_DRV_DBG(CE_NOTE, p, "unknown device");
		p->valid = 0;
	}

	/* Register ACPI battery related events */
	if (ntf_handler != NULL) {
		if (ACPI_FAILURE(AcpiInstallNotifyHandler(p->hdl,
		    ACPI_ALL_NOTIFY, ntf_handler, p))) {
			ACPI_DRV_DBG(CE_NOTE, NULL,
			    "Notify handler for %s.%s install failed",
			    p->hid, p->uid);
			return (ACPI_DRV_ERR);
		}
	}

	return (ACPI_DRV_OK);
}

/*ARGSUSED*/
static ACPI_STATUS
acpi_drv_find_cb(ACPI_HANDLE ObjHandle, UINT32 NestingLevel, void *Context,
    void **ReturnValue)
{
	struct acpi_drv_dev *devp;
	int *type = (int *)Context;

	if (*type == ACPI_DRV_TYPE_CBAT) {
		struct acpi_drv_cbat_state *bp;

		for (bp = acpi_drv_cbat;
		    bp != &acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM];
		    bp++)
			if (bp->dev.hdl == ObjHandle)
				return (AE_OK);

		if (nbat == ACPI_DRV_MAX_BAT_NUM) {
			ACPI_DRV_DBG(CE_WARN, NULL,
			    "Need to support more batteries: "
			    "BATTERY_MAX = %d", ACPI_DRV_MAX_BAT_NUM);
			return (AE_LIMIT);
		}
		bp = &acpi_drv_cbat[nbat++];
		devp = (struct acpi_drv_dev *)bp;
	} else if (*type == ACPI_DRV_TYPE_AC) {
		struct acpi_drv_ac_state *ap;

		for (ap = acpi_drv_ac;
		    ap != &acpi_drv_ac[ACPI_DRV_MAX_AC_NUM];
		    ap++)
			if (ap->dev.hdl == ObjHandle)
				return (AE_OK);

		if (nac == ACPI_DRV_MAX_AC_NUM) {
			ACPI_DRV_DBG(CE_WARN, NULL, "Need to support more ACs: "
			    "AC_MAX = %d", ACPI_DRV_MAX_AC_NUM);
			return (AE_LIMIT);
		}
		ap = &acpi_drv_ac[nac++];
		devp = (struct acpi_drv_dev *)ap;
	} else if (*type == ACPI_DRV_TYPE_LID) {
		struct acpi_drv_lid_state *lp;

		lp = &lid;
		if (lp->dev.hdl == ObjHandle)
			return (AE_OK);

		nlid++;
		devp = (struct acpi_drv_dev *)lp;
	} else {
		ACPI_DRV_DBG(CE_WARN, NULL, "acpi_drv_find_cb(): "
		    "Unknown device");
		return (AE_ERROR);
	}

	devp->hdl = ObjHandle;

	/* Try to get as many working objs as possible */
	(void) acpi_drv_obj_init(devp);
	return (AE_OK);
}

/*ARGSUSED*/
static void
acpi_drv_cbat_rescan(void *arg)
{
	int *retp, type = ACPI_DRV_TYPE_CBAT;

	mutex_enter(&acpi_drv_mutex);

	/*
	 * The detach routine clears the timeout id to tell us not to
	 * reschedule ourselves. If thats the case there's also no point
	 * in looking for new ACPI battery devices, so just return.
	 */
	if (acpi_drv_cbat_rescan_timeout == 0) {
		mutex_exit(&acpi_drv_mutex);
		return;
	}

	(void) AcpiGetDevices(ACPI_DEVNAME_CBAT, acpi_drv_find_cb, &type,
	    (void *)&retp);

	acpi_drv_cbat_rescan_timeout = timeout(acpi_drv_cbat_rescan, NULL,
	    drv_usectohz(MICROSEC));
	mutex_exit(&acpi_drv_mutex);
}

static int
acpi_drv_acpi_init(void)
{
	int *retp, type;
	int status = ACPI_DRV_ERR;
	hotkey_drv_t *htkp;

	/* Check to see if ACPI CA services are available */
	if (AcpiSubsystemStatus() != AE_OK) {
		ACPI_DRV_DBG(CE_WARN, NULL, "ACPI CA not ready");
		return (status);
	}

	/* Init Control Method Batterys */
	type = ACPI_DRV_TYPE_CBAT;
	if (ACPI_SUCCESS(AcpiGetDevices(ACPI_DEVNAME_CBAT, acpi_drv_find_cb,
	    &type, (void *)&retp)) && nbat) {
		status = ACPI_DRV_OK;
	}

	/* Init AC */
	type = ACPI_DRV_TYPE_AC;
	if (ACPI_SUCCESS(AcpiGetDevices(ACPI_DEVNAME_AC, acpi_drv_find_cb,
	    &type, (void *)&retp)) && nac) {
		status = ACPI_DRV_OK;
	}

	/* Init LID */
	type = ACPI_DRV_TYPE_LID;
	if (ACPI_SUCCESS(AcpiGetDevices(ACPI_DEVNAME_LID, acpi_drv_find_cb,
	    &type, (void *)&retp)) && nlid) {
		status = ACPI_DRV_OK;
	}

	/* Init Hotkey Device */
	type = ACPI_DRV_TYPE_HOTKEY;
	htkp = &acpi_hotkey;
	bzero(htkp, sizeof (hotkey_drv_t));
	htkp->dip = acpi_drv_dip;
	htkp->hotkey_lock = &acpi_drv_mutex;
	if (hotkey_init(htkp) == ACPI_DRV_OK) {
		status = ACPI_DRV_OK;
	}

	acpi_drv_update_cap(1);

	return (status);
}

static void
acpi_drv_acpi_fini(void)
{
	int i;
	struct acpi_drv_cbat_state *bp;

	for (bp = &acpi_drv_cbat[0]; bp < &acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM];
	    bp++) {
		if (bp->dev.valid) {
			(void) AcpiRemoveNotifyHandler(bp->dev.hdl,
			    ACPI_DEVICE_NOTIFY, acpi_drv_cbat_notify);
		}
	}
	for (i = 0; i < nac; i++) {
		(void) AcpiRemoveNotifyHandler(acpi_drv_ac[i].dev.hdl,
		    ACPI_DEVICE_NOTIFY, acpi_drv_ac_notify);
	}
	(void) AcpiRemoveNotifyHandler(lid.dev.hdl, ACPI_DEVICE_NOTIFY,
	    acpi_drv_lid_notify);

	if (acpi_hotkey.hotkey_method != HOTKEY_METHOD_NONE)
		(void) hotkey_fini(&acpi_hotkey);
}

/*ARGSUSED*/
static int
acpi_drv_kstat_power_update(kstat_t *ksp, int flag)
{
	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	mutex_enter(&acpi_drv_mutex);
	if (acpi_drv_psr_type == ACPI_DRV_TYPE_UNKNOWN) {
		mutex_exit(&acpi_drv_mutex);
		return (EIO);
	}
	kstat_named_setstr(&acpi_drv_power_kstat.acpi_drv_power,
	    acpi_drv_psr_type == ACPI_DRV_TYPE_AC ? AC : BATTERY);
	acpi_drv_power_kstat.acpi_drv_supported_battery_count.value.ui32 =
	    (uint32_t)nbat;
	mutex_exit(&acpi_drv_mutex);

	return (0);
}

/*ARGSUSED*/
static int
acpi_drv_kstat_warn_update(kstat_t *ksp, int flag)
{
	if (flag == KSTAT_WRITE) {
		int ret = 0;
		acpi_drv_warn_t bw;
		acpi_drv_warn_kstat_t kbw;

		kbw = *(acpi_drv_warn_kstat_t *)acpi_drv_warn_ksp->ks_data;

		mutex_enter(&acpi_drv_mutex);
		bw.bw_enabled  = kbw.acpi_drv_bw_enabled.value.ui32;
		bw.bw_charge_warn = kbw.acpi_drv_bw_charge_warn.value.ui32;
		bw.bw_charge_low = kbw.acpi_drv_bw_charge_low.value.ui32;
		ret = acpi_drv_set_warn(&bw);
		mutex_exit(&acpi_drv_mutex);

		return (ret);
	} else {
		acpi_drv_warn_kstat_t *wp = &acpi_drv_warn_kstat;

		mutex_enter(&acpi_drv_mutex);
		wp->acpi_drv_bw_enabled.value.ui32 = acpi_drv_warn_enabled;
		wp->acpi_drv_bw_charge_warn.value.ui32 = acpi_drv_syn_warn_per;
		wp->acpi_drv_bw_charge_low.value.ui32 = acpi_drv_syn_low_per;
		mutex_exit(&acpi_drv_mutex);

		return (0);
	}
}

static int
acpi_drv_kstat_bif_update(kstat_t *ksp, int flag)
{
	struct acpi_drv_cbat_state *bp;
	acpi_bif_t *bif;
	acpi_drv_bif_kstat_t *kp;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	bp = (struct acpi_drv_cbat_state *)ksp->ks_private;
	mutex_enter(&acpi_drv_mutex);

	if (acpi_drv_cbat_present(bp) <= 0) {
		mutex_exit(&acpi_drv_mutex);
		return (ENXIO);
	}

	bzero(&bif, sizeof (bif));
	if (acpi_drv_update_bif(bp) != ACPI_DRV_OK) {
		mutex_exit(&acpi_drv_mutex);
		return (ENXIO);
	}

	bif = &bp->bif_cache;
	kp = &acpi_drv_bif_kstat;

	/* Update BIF */
	kp->acpi_drv_bif_unit.value.ui32 = bif->bif_unit;
	kp->acpi_drv_bif_design_cap.value.ui32 = bif->bif_design_cap;
	kp->acpi_drv_bif_last_cap.value.ui32 = bif->bif_last_cap;
	kp->acpi_drv_bif_tech.value.ui32 = bif->bif_tech;
	kp->acpi_drv_bif_voltage.value.ui32 = bif->bif_voltage;
	kp->acpi_drv_bif_warn_cap.value.ui32 = bif->bif_warn_cap;
	kp->acpi_drv_bif_low_cap.value.ui32 = bif->bif_low_cap;
	kp->acpi_drv_bif_gran1_cap.value.ui32 = bif->bif_gran1_cap;
	kp->acpi_drv_bif_gran2_cap.value.ui32 = bif->bif_gran2_cap;

	kstat_named_setstr(&kp->acpi_drv_bif_model, bif->bif_model);
	kstat_named_setstr(&kp->acpi_drv_bif_serial, bif->bif_serial);
	kstat_named_setstr(&kp->acpi_drv_bif_type, bif->bif_type);
	kstat_named_setstr(&kp->acpi_drv_bif_oem_info, bif->bif_oem_info);

	mutex_exit(&acpi_drv_mutex);
	return (0);
}

static int
acpi_drv_kstat_bst_update(kstat_t *ksp, int flag)
{
	struct acpi_drv_cbat_state *bp;
	acpi_bst_t *bst;
	acpi_drv_bst_kstat_t *kp;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	bp = (struct acpi_drv_cbat_state *)ksp->ks_private;
	mutex_enter(&acpi_drv_mutex);

	if (acpi_drv_cbat_present(bp) <= 0) {
		mutex_exit(&acpi_drv_mutex);
		return (ENXIO);
	}

	bzero(&bst, sizeof (bst));
	if (acpi_drv_update_bst(bp) != ACPI_DRV_OK) {
		mutex_exit(&acpi_drv_mutex);
		return (ENXIO);
	}

	bst = &bp->bst_cache;
	kp = &acpi_drv_bst_kstat;

	/* Update BST */
	kp->acpi_drv_bst_state.value.ui32 = bst->bst_state;
	kp->acpi_drv_bst_rate.value.ui32 = bst->bst_rate;
	kp->acpi_drv_bst_rem_cap.value.ui32 = bst->bst_rem_cap;
	kp->acpi_drv_bst_voltage.value.ui32 = bst->bst_voltage;

	mutex_exit(&acpi_drv_mutex);
	return (0);
}

static int
acpi_drv_kstat_init(void)
{
	/*
	 * Allocate, initialize and install powerstatus and
	 * supported_battery_count kstat.
	 */
	acpi_drv_power_ksp = kstat_create(ACPI_DRV_NAME, 0,
	    ACPI_DRV_POWER_KSTAT_NAME, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (acpi_drv_power_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (acpi_drv_power_ksp == NULL) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "kstat_create(%s) fail", ACPI_DRV_POWER_KSTAT_NAME);
		return (ACPI_DRV_ERR);
	}

	acpi_drv_power_ksp->ks_data = &acpi_drv_power_kstat;
	acpi_drv_power_ksp->ks_update = acpi_drv_kstat_power_update;
	acpi_drv_power_ksp->ks_data_size += MAXNAMELEN;
	kstat_install(acpi_drv_power_ksp);

	/*
	 * Allocate, initialize and install battery_capacity_warning kstat.
	 */
	acpi_drv_warn_ksp = kstat_create(ACPI_DRV_NAME, 0,
	    ACPI_DRV_BTWARN_KSTAT_NAME, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (acpi_drv_warn_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);
	if (acpi_drv_warn_ksp == NULL) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "kstat_create(%s) fail", ACPI_DRV_BTWARN_KSTAT_NAME);
		return (ACPI_DRV_ERR);
	}

	acpi_drv_warn_ksp->ks_data = &acpi_drv_warn_kstat;
	acpi_drv_warn_ksp->ks_update = acpi_drv_kstat_warn_update;
	kstat_install(acpi_drv_warn_ksp);

	return (ACPI_DRV_OK);
}

static void
acpi_drv_kstat_fini()
{
	struct acpi_drv_cbat_state *bp;

	if (acpi_drv_power_ksp != NULL) {
		kstat_delete(acpi_drv_power_ksp);
	}
	if (acpi_drv_warn_ksp != NULL) {
		kstat_delete(acpi_drv_warn_ksp);
	}
	for (bp = &acpi_drv_cbat[0]; bp < &acpi_drv_cbat[ACPI_DRV_MAX_BAT_NUM];
	    bp++) {
		if (bp->dev.valid) {
			if (bp->bat_bif_ksp != NULL) {
				kstat_delete(bp->bat_bif_ksp);
			}
			if (bp->bat_bst_ksp != NULL) {
				kstat_delete(bp->bat_bst_ksp);
			}
		}
	}
}

int
acpi_drv_set_int(ACPI_HANDLE dev, char *method, uint32_t aint)
{
	ACPI_OBJECT_LIST al;
	ACPI_OBJECT ao;

	al.Pointer = &ao;
	al.Count = 1;
	ao.Type = ACPI_TYPE_INTEGER;
	ao.Integer.Value = aint;
	return (AcpiEvaluateObject(dev, method, &al, NULL));
}

int
acpi_drv_dev_init(struct acpi_drv_dev *p)
{
	ACPI_DEVICE_INFO *info;
	ACPI_STATUS ret;

	ASSERT(p != NULL && p->hdl != NULL);

	p->valid = 0;

	/* Info size is variable depending on existance of _CID */
	ret = AcpiGetObjectInfo(p->hdl, &info);
	if (ACPI_FAILURE(ret)) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo() fail: %d", (int32_t)ret);
		return (ACPI_DRV_ERR);
	}

	if ((info->Valid & ACPI_VALID_HID) == 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "!AcpiGetObjectInfo(): _HID not available");
		p->hid[0] = 0;
	} else {
		(void) strlcpy(p->hid, info->HardwareId.String, ID_LEN);
	}

	/*
	 * This object is optional, but is required when the device
	 * has no other way to report a persistent unique device ID.
	 */
	if ((info->Valid & ACPI_VALID_UID) == 0) {
		ACPI_DRV_DBG(CE_WARN, NULL,
		    "!AcpiGetObjectInfo(): _UID not available");
		/* Use 0 as the default _UID */
		p->uid[0] = 0;
	} else {
		(void) strlcpy(p->uid, info->UniqueId.String, ID_LEN);
	}

	if (info->Valid & ACPI_VALID_ADR) {
		p->valid = 1;
		p->type = ACPI_DRV_TYPE_HOTKEY;
	}

	AcpiOsFree(info);

	return (ACPI_DRV_OK);
}
