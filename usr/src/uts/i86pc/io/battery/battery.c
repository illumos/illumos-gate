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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Solaris x86 ACPI Battery Monitor
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/acpiev.h>
#include <sys/reboot.h>
#include <sys/acpi/acpi.h>
#include <sys/note.h>
#include <sys/battery.h>


#define	BATT_MOD_STRING			"ACPI battery driver %I%"

#define	MINOR_SHIFT			8
#define	IDX_MASK			((1 << MINOR_SHIFT) - 1)
#define	MINOR_BATT(idx)			(BATT_TYPE_CBAT << MINOR_SHIFT | (idx))
#define	MINOR_AC(idx)			(BATT_TYPE_AC << MINOR_SHIFT | (idx))
#define	MINOR2IDX(minor)		((minor) & IDX_MASK)
#define	MINOR2TYPE(minor)		((minor) >> MINOR_SHIFT)

#define	BATT_OK				(0)
#define	BATT_ERR			(1)

#define	BATT_MAX_BAT_NUM		8
#define	BATT_MAX_AC_NUM			10

#define	BST_FLAG_DISCHARGING		(0x1)
#define	BST_FLAG_CHARGING		(0x2)
#define	BST_FLAG_CRITICAL		(0x4)

/* Set if the battery is present */
#define	STA_FLAG_BATT_PRESENT		(0x10)

#define	ACPI_DEVNAME_CBAT		"PNP0C0A"
#define	ACPI_DEVNAME_SBAT		"ACPI0002"
#define	ACPI_DEVNAME_AC			"ACPI0003"

#define	BATT_EVENTS			(POLLIN | POLLRDNORM)

#ifdef DEBUG

#define	BATT_PRINT_BUFFER_SIZE		512
static char batt_prt_buf[BATT_PRINT_BUFFER_SIZE];
static kmutex_t batt_prt_mutex;

static int batt_debug = 0;
#define	BATT_DBG(lev, devp, ...) \
	do { \
		if (batt_debug) batt_printf((devp), (lev), __VA_ARGS__); \
_NOTE(CONSTCOND) } while (0)
#define	BATT_PRT_NOTIFY(hdl, val) \
	do { \
		if (batt_debug) batt_prt_notify((hdl), (val)); \
_NOTE(CONSTCOND) } while (0)

#else

#define	BATT_DBG(lev, devp, ...)
#define	BATT_PRT_NOTIFY(hdl, val)

#endif /* DEBUG */

/* ACPI notify types */
enum batt_notify {
	BATT_NTF_UNKNOWN = -1,	/* No notifications seen, ever. */
	BATT_NTF_CHANGED,
	BATT_NTF_OK
};

/* Battery device types */
enum batt_type {
	BATT_TYPE_UNKNOWN = -1,
	BATT_TYPE_CBAT,
	BATT_TYPE_AC,
	BATT_TYPE_SBAT
};

struct batt_acpi_dev {
	ACPI_HANDLE hdl;
	char hid[9];	/* ACPI HardwareId */
	char uid[9];	/* ACPI UniqueId */
	int valid;	/* the device state is valid */

	/*
	 * Unlike most other devices, when a battery is inserted or
	 * removed from the system, the device itself(the battery bay)
	 * is still considered to be present in the system.
	 *
	 * Value:
	 *    0 -- On-line
	 *    1 -- Off-line
	 *   -1 -- Unknown
	 */
	int present;
	enum batt_type type;
	int index;	/* device index */
};

static int batt_dev_present(struct batt_acpi_dev *);
#define	batt_ac_present(a)	(((a)->dev.type == BATT_TYPE_AC) ? \
				batt_dev_present(&(a)->dev) : -1)
#define	batt_cbat_present(a)	(((a)->dev.type == BATT_TYPE_CBAT) ? \
				batt_dev_present(&(a)->dev) : -1)

static dev_info_t *batt_dip = NULL;
static kmutex_t batt_mutex;
static struct pollhead batt_pollhead;

/* Control Method Battery state */
struct batt_cbat_state {
	struct batt_acpi_dev dev;
/* Caches of _BST and _BIF */
	enum batt_notify bat_bifok;
	acpi_bif_t bif_cache;
	enum batt_notify bat_bstok;
	acpi_bst_t bst_cache;

	uint32_t charge_warn;
	uint32_t charge_low;

	kstat_t *bat_bif_ksp;
	kstat_t *bat_bst_ksp;
} batt_cbat[BATT_MAX_BAT_NUM];
static int nbat;

/*
 * Synthesis battery state
 * When there are multiple batteries present, the battery subsystem
 * is not required to perform any synthesis of a composite battery
 * from the data of the separate batteries. In cases where the
 * battery subsystem does not synthesize a composite battery from
 * the separate battery's data, the OS must provide that synthesis.
 */
static uint32_t batt_syn_rem_cap;
static uint32_t batt_syn_last_cap;
static uint32_t batt_syn_oem_warn_cap;
static uint32_t batt_syn_oem_low_cap;

static int batt_warn_enabled;
static uint32_t batt_syn_warn_per;
static uint32_t batt_syn_low_per;
static uint32_t batt_syn_warn_cap;
static uint32_t batt_syn_low_cap;
/* Tracking boundery passing of _BST charge levels */
static uint32_t batt_syn_last_level;

/* AC state */
static struct batt_ac_state {
	struct batt_acpi_dev dev;
} batt_ac[BATT_MAX_AC_NUM];
static int nac;

/*
 * Current power source device
 * Note: assume only one device can be the power source device.
 */
static int batt_psr_type = BATT_TYPE_UNKNOWN;
static struct batt_acpi_dev *batt_psr_devp = NULL;

/* Smart Battery state */
static struct batt_sbat_state {
	struct batt_acpi_dev dev;
} batt_sbat;

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
static kstat_t *batt_power_ksp;
static kstat_t *batt_warn_ksp;

batt_power_kstat_t batt_power_kstat = {
	{ SYSTEM_POWER,			KSTAT_DATA_STRING },
	{ SUPPORTED_BATTERY_COUNT,	KSTAT_DATA_UINT32 },
};

batt_warn_kstat_t batt_warn_kstat = {
	{ BW_ENABLED,			KSTAT_DATA_UINT32 },
	{ BW_POWEROFF_THRESHOLD,	KSTAT_DATA_UINT32 },
	{ BW_SHUTDOWN_THRESHOLD,	KSTAT_DATA_UINT32 },
};

/* BIF */
batt_bif_kstat_t batt_bif_kstat = {
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
batt_bst_kstat_t batt_bst_kstat = {
	{ BST_STATE,		KSTAT_DATA_UINT32 },
	{ BST_RATE,		KSTAT_DATA_UINT32 },
	{ BST_REM_CAP,		KSTAT_DATA_UINT32 },
	{ BST_VOLTAGE,		KSTAT_DATA_UINT32 },
};

static int batt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int batt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int batt_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int batt_open(dev_t *devp, int flag, int otyp, cred_t *crp);
static int batt_close(dev_t dev, int flag, int otyp, cred_t *crp);
static int batt_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval);
static int batt_chpoll(dev_t dev, short events, int anyyet,  short *reventsp,
    struct pollhead **phpp);
static int batt_ac_ioctl(int index, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
static int batt_cbat_ioctl(int index, int cmd, intptr_t arg, int mode,
    cred_t *cr, int *rval);
#ifdef DEBUG
static void batt_printf(struct batt_acpi_dev *devp, uint_t lev,
    const char *fmt, ...);
#endif
static int batt_get_bif(acpi_bif_t *bifp, struct batt_cbat_state *bp);
static int batt_get_bst(acpi_bst_t *bstp, struct batt_cbat_state *bp);
static int batt_set_warn(batt_warn_t *bwp);
static struct batt_cbat_state *batt_idx2cbat(int idx);
static struct batt_ac_state *batt_idx2ac(int idx);
static int batt_acpi_init(void);
static void batt_acpi_fini(void);
static int batt_kstat_init(void);
static void batt_kstat_fini(void);

static struct cb_ops batt_cb_ops = {
	batt_open,		/* open */
	batt_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	batt_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	batt_chpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP,
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops batt_dev_ops = {
	DEVO_REV,
	0,			/* refcnt */
	batt_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	batt_attach,		/* attach */
	batt_detach,		/* detach */
	nodev,			/* reset */
	&batt_cb_ops,
	NULL,			/* no bus operations */
	NULL			/* power */
};

static struct modldrv modldrv1 = {
	&mod_driverops,
	BATT_MOD_STRING,
	&batt_dev_ops
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

	mutex_init(&batt_mutex, NULL, MUTEX_DRIVER, NULL);
#ifdef DEBUG
	mutex_init(&batt_prt_mutex, NULL, MUTEX_DRIVER, NULL);
#endif

	if ((ret = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&batt_mutex);
#ifdef DEBUG
		mutex_destroy(&batt_prt_mutex);
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
		mutex_destroy(&batt_prt_mutex);
#endif
		mutex_destroy(&batt_mutex);
	}

	return (ret);
}

int
_info(struct modinfo *mp)
{
	return (mod_info(&modlinkage, mp));
}

static int
batt_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	char name[20];
	int i;
	struct batt_cbat_state *bp;

	switch (cmd) {
	case DDI_ATTACH:
		/* Limit to one instance of driver */
		if (batt_dip) {
			return (DDI_FAILURE);
		}
		break;
	case DDI_RESUME:
	case DDI_PM_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	batt_dip = devi;

	/* Init ACPI related stuff */
	if (batt_acpi_init() != BATT_OK) {
		goto error;
	}

	/* Init kstat related stuff */
	if (batt_kstat_init() != BATT_OK) {
		goto error;
	}

	/* Create minor node for each battery and ac */
	for (bp = &batt_cbat[0]; bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
		if (bp->dev.valid) {
			(void) snprintf(name, sizeof (name), "battery%d",
			    bp->dev.index);
			if (ddi_create_minor_node(devi, name, S_IFCHR,
			    MINOR_BATT(bp->dev.index), DDI_PSEUDO, 0) ==
			    DDI_FAILURE) {
				BATT_DBG(CE_WARN, NULL,
				    "%s: minor node create failed", name);
				goto error;
			}
		}
	}
	for (i = 0; i < nac; i++) {
		(void) snprintf(name, sizeof (name), "ac%d", i);
		if (ddi_create_minor_node(devi, name, S_IFCHR,
		    MINOR_AC(i), DDI_PSEUDO, 0) == DDI_FAILURE) {
			BATT_DBG(CE_WARN, NULL,
			    "%s: minor node create failed", name);
			goto error;
		}
	}

	return (DDI_SUCCESS);

error:
	ddi_remove_minor_node(devi, NULL);
	batt_kstat_fini();
	batt_acpi_fini();
	batt_dip = NULL;
	return (DDI_FAILURE);
}

static int
batt_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(devi, NULL);

	batt_kstat_fini();
	batt_acpi_fini();
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
batt_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = batt_dip;
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
batt_open(dev_t *devp, int flag, int otyp, cred_t *crp)
{
	if (batt_dip == NULL) {
		return (ENXIO);
	}

	return (0);
}

/*ARGSUSED*/
static int
batt_close(dev_t dev, int flag, int otyp, cred_t *crp)
{
	return (0);
}

/*ARGSUSED*/
static int
batt_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval)
{
	int minor;
	int type, index;
	int res = 0;

	minor = getminor(dev);
	type = MINOR2TYPE(minor);
	index = MINOR2IDX(minor);

	mutex_enter(&batt_mutex);

	if (type == BATT_TYPE_CBAT) {
		res = batt_cbat_ioctl(index, cmd, arg, mode, cr, rval);
	} else if (type == BATT_TYPE_AC) {
		res = batt_ac_ioctl(index, cmd, arg, mode, cr, rval);
	} else {
		res = EINVAL;
	}

	mutex_exit(&batt_mutex);
	return (res);
}

/*ARGSUSED*/
static int
batt_cbat_ioctl(int index, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int res = 0;
	acpi_bif_t bif;
	acpi_bst_t bst;
	batt_warn_t bwarn;
	struct batt_cbat_state *bp;

	ASSERT(mutex_owned(&batt_mutex));

	bp = batt_idx2cbat(index);
	if (!bp || bp->dev.valid != 1) {
		return (ENXIO);
	}

	switch (cmd) {
	/*
	 * Return _BIF(Battery Information) of battery[index],
	 * if battery plugged.
	 */
	case BATT_IOC_INFO:
		if (bp->dev.present == 0) {
			res = ENXIO;
			break;
		}

		(void) memset(&bif, 0, sizeof (bif));
		bp->bat_bifok = BATT_NTF_UNKNOWN;
		res = batt_get_bif(&bif, bp);
		if (res != BATT_OK) {
			break;
		}
		if (copyout(&bif, (void *)arg, sizeof (bif))) {
			res = EFAULT;
		}
		break;

	/*
	 * Return _BST(Battery Status) of battery[index],
	 * if battery plugged.
	 */
	case BATT_IOC_STATUS:
		if (bp->dev.present == 0) {
			res = ENXIO;
			break;
		}

		(void) memset(&bst, 0, sizeof (bst));
		bp->bat_bstok = BATT_NTF_UNKNOWN;
		res = batt_get_bst(&bst, bp);
		if (res != BATT_OK) {
			break;
		}
		if (copyout(&bst, (void *)arg, sizeof (bst))) {
			res = EFAULT;
		}
		break;

	/* Return the state of the battery bays in the system */
	case BATT_IOC_BAY:
		{
			batt_bay_t bay;

			bay.bay_number = nbat;
			bay.battery_map = 0;
			for (bp = &batt_cbat[0];
			    bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
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
	case BATT_IOC_POWER_STATUS:
		{
			int val;

			/* State not available */
			if (batt_psr_type == BATT_TYPE_UNKNOWN) {
				res = ENXIO;
				break;
			}
			val = (batt_psr_type == BATT_TYPE_AC) ? 1 : 0;
			if (copyout(&val, (void *)arg, sizeof (val))) {
				res = EFAULT;
				break;
			}
		}
		break;

	/* Get charge-warn and charge-low levels for the whole system */
	case BATT_IOC_GET_WARNING:
		bwarn.bw_enabled = batt_warn_enabled;
		bwarn.bw_charge_warn = batt_syn_warn_per;
		bwarn.bw_charge_low = batt_syn_low_per;
		if (copyout(&bwarn, (void *)arg, sizeof (&bwarn))) {
			res = EFAULT;
		}
		break;

	/* Set charge-warn and charge-low levels for the whole system */
	case BATT_IOC_SET_WARNING:
		if (drv_priv(cr)) {
			res = EPERM;
			break;
		}
		if (copyin((void *)arg, &bwarn, sizeof (&bwarn))) {
			res = EFAULT;
			break;
		}
		res = batt_set_warn(&bwarn);
		break;

	default:
		res = EINVAL;
		break;
	}

	return (res);
}

/*ARGSUSED*/
static int
batt_ac_ioctl(int index, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rval)
{
	int res = 0;
	int ac_state;
	struct batt_ac_state *acp;

	ASSERT(mutex_owned(&batt_mutex));

	acp = batt_idx2ac(index);
	if (!acp || acp->dev.valid != 1) {
		return (ENXIO);
	}

	switch (cmd) {
	/* Return the number of AC adapters in the system */
	case BATT_IOC_AC_COUNT:
		if (copyout(&nac, (void *)arg, sizeof (nac))) {
			res = EFAULT;
		}
		break;

	/*
	 * Return the state of AC[index] if available:
	 * 0 -- Off-line
	 * 1 -- On-line
	 */
	case BATT_IOC_POWER_STATUS:
		if (!acp || acp->dev.valid != 1) {
			res = ENXIO;
			break;
		}
		/* State not available */
		if ((ac_state = batt_ac_present(acp)) == -1) {
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
batt_chpoll(dev_t dev, short events, int anyyet,  short *reventsp,
	struct pollhead **phpp)
{
	if (!anyyet) {
		*phpp = &batt_pollhead;
	}
	*reventsp = 0;
	return (0);
}

#ifdef DEBUG
static void
batt_printf(struct batt_acpi_dev *devp, uint_t lev, const char *fmt, ...)
{
	va_list args;

	mutex_enter(&batt_prt_mutex);

	va_start(args, fmt);
	(void) vsprintf(batt_prt_buf, fmt, args);
	va_end(args);

	if (devp) {
		cmn_err(lev, "%s.%s: %s", devp->hid, devp->uid, batt_prt_buf);
	} else {
		cmn_err(lev, "%s", batt_prt_buf);
	}
	mutex_exit(&batt_prt_mutex);
}

static void
batt_prt_notify(ACPI_HANDLE hdl, UINT32 val)
{
	ACPI_BUFFER buf;
	char str[1024];

	buf.Length = sizeof (str);
	buf.Pointer = str;
	AcpiGetName(hdl, ACPI_FULL_PATHNAME, &buf);
	cmn_err(CE_NOTE, "AcpiNotify(%s, 0x%02x)", str, val);
}
#endif /* DEBUG */

static void
batt_gen_sysevent(struct batt_acpi_dev *devp, char *ev, uint32_t val)
{
	nvlist_t *attr_list = NULL;
	int err;
	char pathname[MAXPATHLEN];

	/* Allocate and build sysevent attribute list */
	err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE, DDI_NOSLEEP);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "cannot allocate memory for sysevent attributes\n");
		return;
	}

	/* Add attributes */
	err = nvlist_add_string(attr_list, ACPIEV_DEV_HID, devp->hid);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    ACPIEV_DEV_HID, EC_ACPIEV, ev);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_string(attr_list, ACPIEV_DEV_UID, devp->uid);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    ACPIEV_DEV_UID, EC_ACPIEV, ev);
		nvlist_free(attr_list);
		return;
	}

	err = nvlist_add_uint32(attr_list, ACPIEV_DEV_INDEX, devp->index);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    ACPIEV_DEV_INDEX, EC_ACPIEV, ev);
		nvlist_free(attr_list);
		return;
	}

	(void) ddi_pathname(batt_dip, pathname);
	err = nvlist_add_string(attr_list, ACPIEV_DEV_PHYS_PATH, pathname);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    ACPIEV_DEV_PHYS_PATH, EC_ACPIEV, ev);
		nvlist_free(attr_list);
		return;
	}

	if (strcmp(ev, ESC_ACPIEV_WARN) && strcmp(ev, ESC_ACPIEV_LOW)) {
		goto finish;
	}

	err = nvlist_add_uint32(attr_list, ACPIEV_CHARGE_LEVEL, val);
	if (err != 0) {
		BATT_DBG(CE_WARN, NULL,
		    "Failed to add attr [%s] for %s/%s event",
		    ACPIEV_CHARGE_LEVEL, EC_ACPIEV, ev);
		nvlist_free(attr_list);
		return;
	}

finish:
	BATT_DBG(CE_NOTE, NULL, "SysEv(%s, %s.%s, %d)",
	    ev, devp->hid, devp->uid, val);
	/* Generate/log sysevent */
	err = ddi_log_sysevent(batt_dip, DDI_VENDOR_SUNW, EC_ACPIEV,
	    ev, attr_list, NULL, DDI_NOSLEEP);
#ifdef DEBUG
	if (err != DDI_SUCCESS) {
		BATT_DBG(CE_WARN, NULL,
		    "cannot log sysevent, err code %x\n", err);
	}
#endif

	nvlist_free(attr_list);
}

static int
batt_obj_copy(ACPI_OBJECT *op, char *bp, struct obj_desc *dp)
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
				BATT_DBG(CE_NOTE, NULL, "\t%s: %u", dp->name,
				    (uint32_t)ep->Integer.Value);
			} else {
#ifdef _LP64
				BATT_DBG(CE_NOTE, NULL, "\t%s: %lu",
				    dp->name, (uint64_t)ep->Integer.Value);
			}
#else
				BATT_DBG(CE_NOTE, NULL, "\t%s: %llu",
				    dp->name, (uint64_t)ep->Integer.Value);
			}
#endif /* _LP64 */
#endif /* DEBUG */
			*(uint32_t *)fp = ep->Integer.Value;
		} else if (dp->type == ACPI_TYPE_STRING &&
		    ep->Type == dp->type) {
			BATT_DBG(CE_NOTE, NULL, "\t%s: \"%s\"",
			    dp->name, ep->String.Pointer);
			(void) strncpy(fp, ep->String.Pointer, dp->size);
		} else if (dp->type == ACPI_TYPE_STRING &&
		    ep->Type == ACPI_TYPE_BUFFER) {
#ifdef DEBUG
			int len;
			char buf[MAXNAMELEN + 1];

			len = (MAXNAMELEN < ep->Buffer.Length) ?
			    MAXNAMELEN : ep->Buffer.Length;
			bcopy(ep->Buffer.Pointer, buf, len);
			buf[len] = 0;
			BATT_DBG(CE_NOTE, NULL, "\t%s: [%d] \"%s\"",
			    dp->name, len, buf);
#endif

			ASSERT(MAXNAMELEN >= ep->Buffer.Length);
			bcopy(ep->Buffer.Pointer, fp, ep->Buffer.Length);
		} else {
			BATT_DBG(CE_WARN, NULL,
			    "Bad field at offset %d: type %d",
			    dp->offset, ep->Type);
			if (dp->type != ACPI_TYPE_STRING) {
				return (BATT_ERR);
			}
		}
		ep++;
	}

	return (BATT_OK);
}

static int
batt_eval_int(ACPI_HANDLE hdl, ACPI_STRING name, ACPI_OBJECT_LIST *parms,
    int *rval)
{
	ACPI_BUFFER buf;
	ACPI_OBJECT obj;

	buf.Length = sizeof (obj);
	buf.Pointer = &obj;

	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(hdl, name, parms, &buf,
	    ACPI_TYPE_INTEGER))) {
		return (BATT_ERR);
	}

	*rval = (int)obj.Integer.Value;
	return (BATT_OK);
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
batt_get_psr(struct batt_ac_state *acp)
{
	struct batt_acpi_dev *devp = &acp->dev;
	int ac;

	if (!devp->valid) {
		BATT_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	if (ACPI_FAILURE(batt_eval_int(devp->hdl, "_PSR", NULL, &ac))) {
		BATT_DBG(CE_WARN, NULL, "AcpiEval _PSR failed");
		devp->present = -1;
	} else {
		BATT_DBG(CE_NOTE, devp, "_PSR = %d", ac);
		devp->present = ac;
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
batt_get_sta(struct batt_cbat_state *bp)
{
	struct batt_acpi_dev *devp = &bp->dev;
	int val;

	if (!devp->valid) {
		BATT_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	if (batt_eval_int(devp->hdl, "_STA", NULL, &val) == BATT_ERR) {
		BATT_DBG(CE_WARN, NULL, "AcpiEval _STA failed");
		devp->present = -1;
	} else {
		BATT_DBG(CE_NOTE, devp, "_STA = 0x%x", val);
		devp->present = ((val & STA_FLAG_BATT_PRESENT) != 0);
	}

	return (val);
}

static int
batt_get_bif(acpi_bif_t *bifp, struct batt_cbat_state *bp)
{
	/* BIF is only available when battery plugged */
	ASSERT(bp->dev.present != 0);

	/* Update internal BIF cache */
	if (bp->bat_bifok != BATT_NTF_OK) {
		ACPI_BUFFER buf;
		ACPI_OBJECT *objp;

		buf.Length = ACPI_ALLOCATE_BUFFER;
		if (ACPI_FAILURE(AcpiEvaluateObjectTyped(bp->dev.hdl, "_BIF",
		    NULL, &buf, ACPI_TYPE_PACKAGE))) {
			BATT_DBG(CE_WARN, NULL, "AcpiEval _BIF failed");
			return (BATT_ERR);
		}

		objp = buf.Pointer;
		BATT_DBG(CE_NOTE, &bp->dev, "get _BIF");
		if (batt_obj_copy(objp, (char *)&bp->bif_cache, bif_desc) ==
		    BATT_ERR) {
			AcpiOsFree(objp);
			return (BATT_ERR);
		}
		AcpiOsFree(objp);

		bp->bat_bifok = BATT_NTF_OK;
	}

	/* Copy BIF back to user */
	if (bifp) {
		*bifp = bp->bif_cache;
	}
	return (BATT_OK);
}

static int
batt_get_bst(acpi_bst_t *bstp, struct batt_cbat_state *bp)
{
	/* BST is only available when battery plugged */
	ASSERT(bp->dev.present != 0);

	/* Update internal BST cache */
	if (bp->bat_bstok != BATT_NTF_OK) {
		ACPI_BUFFER buf;
		ACPI_OBJECT *objp;

		buf.Length = ACPI_ALLOCATE_BUFFER;
		if (ACPI_FAILURE(AcpiEvaluateObjectTyped(bp->dev.hdl, "_BST",
		    NULL, &buf, ACPI_TYPE_PACKAGE))) {
			BATT_DBG(CE_WARN, NULL, "AcpiEval _BST failed");
			return (BATT_ERR);
		}

		objp = buf.Pointer;
		BATT_DBG(CE_NOTE, &bp->dev, "get _BST");
		if (batt_obj_copy(objp, (char *)&bp->bst_cache, bst_desc) ==
		    BATT_ERR) {
			AcpiOsFree(objp);
			return (BATT_ERR);
		}
		AcpiOsFree(objp);

		if (bp->bst_cache.bst_rate == 0) {
			bp->bst_cache.bst_state &= ~(BATT_BST_CHARGING |
			    BATT_BST_DISCHARGING);
		}
		bp->bat_bstok = BATT_NTF_OK;
	}

	/* Copy BST back to user */
	if (bstp) {
		*bstp = bp->bst_cache;
	}
	return (BATT_OK);
}

static int
batt_update_bif(struct batt_cbat_state *bp)
{
	bp->bat_bifok = BATT_NTF_UNKNOWN;
	return (batt_get_bif(NULL, bp));
}

static int
batt_update_bst(struct batt_cbat_state *bp)
{
	bp->bat_bstok = BATT_NTF_UNKNOWN;
	return (batt_get_bst(NULL, bp));
}

/*
 * Return value:
 *	 1 -- device On-line
 *	 0 -- device Off-line
 *	-1 -- Unknown, some error ocurred.
 */
static int
batt_dev_present(struct batt_acpi_dev *devp)
{
	if (!devp->valid) {
		BATT_DBG(CE_WARN, NULL, "device not valid");
		return (-1);
	}

	ASSERT(devp->type != BATT_TYPE_UNKNOWN);

	/* Update the device state */
	if (devp->present == -1) {
		if (devp->type == BATT_TYPE_AC) {
			(void) batt_get_psr((struct batt_ac_state *)devp);
		} else if (devp->type == BATT_TYPE_CBAT) {
			(void) batt_get_sta((struct batt_cbat_state *)devp);
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
batt_update_present(struct batt_acpi_dev *p)
{
	int old_present = p->present;
	int new_present;

	ASSERT(p && p->valid);

	p->present = -1;
	new_present = batt_dev_present(p);
	if (new_present == -1) {
		return (-1);
	}
	if (new_present != old_present) {
		return (1);
	}
	return (0);
}

static void
batt_set_psr(struct batt_acpi_dev *p)
{
	batt_psr_devp = p;
	if (p != NULL) {
		BATT_DBG(CE_NOTE, p, "psr = .");
		batt_psr_type = p->type;
	} else {
		BATT_DBG(CE_NOTE, p, "psr = ?");
		batt_psr_type = BATT_TYPE_UNKNOWN;
	}
}

/*
 * OSPM can determine independent warning and low battery
 * capacity values based on the OEM-designed levels, but
 * cannot set these values lower than the OEM-designed values.
 */
static int
batt_set_warn(batt_warn_t *bwp)
{
	uint32_t warn, low;

	warn = batt_syn_last_cap * bwp->bw_charge_warn / 100;
	low = batt_syn_last_cap * bwp->bw_charge_low / 100;

	/* Update internal state */
	if (bwp->bw_enabled) {
		if (low >= warn || warn < batt_syn_oem_warn_cap ||
		    low < batt_syn_oem_low_cap) {
			BATT_DBG(CE_WARN, NULL, "charge level error");
			return (EINVAL);
		}

		BATT_DBG(CE_NOTE, NULL, "set warn: warn=%d low=%d", warn, low);

		batt_syn_warn_per = bwp->bw_charge_warn;
		batt_syn_low_per = bwp->bw_charge_low;
		batt_syn_warn_cap = warn;
		batt_syn_low_cap = low;
		batt_warn_enabled = 1;
	} else {
		batt_warn_enabled = 0;
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
batt_update_cap(int bif_changed)
{
	struct batt_cbat_state *bp;

	if (bif_changed != 0) {
		batt_syn_oem_warn_cap = 0xffffffff;
		batt_syn_oem_low_cap = 0xffffffff;
		batt_syn_last_cap = 0xffffffff;
	}
	batt_syn_last_level = batt_syn_rem_cap;
	batt_syn_rem_cap = 0xffffffff; /* initially unknown */

	for (bp = &batt_cbat[0]; bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
		if (bp->dev.valid) {
			/* Escape the empty bays */
			if (batt_cbat_present(bp) <= 0) {
				continue;
			}

			if (bif_changed != 0 && bp->bat_bifok == BATT_NTF_OK) {
				acpi_bif_t *bif;

				bif = &bp->bif_cache;

				if (batt_syn_last_cap == 0xffffffff) {
					batt_syn_last_cap = 0;
				}
				batt_syn_last_cap += bif->bif_last_cap;

				if (bif->bif_warn_cap == 0xffffffff ||
				    bif->bif_low_cap == 0xffffffff) {
					BATT_DBG(CE_WARN, &bp->dev, "BIF value "
					    "invalid, warn_cap=0x%x "
					    "low_cap=0x%x", bif->bif_warn_cap,
					    bif->bif_low_cap);
					continue;
				}
				if (batt_syn_oem_warn_cap == 0xffffffff) {
					batt_syn_oem_warn_cap = 0;
				}
				if (batt_syn_oem_low_cap == 0xffffffff) {
					batt_syn_oem_low_cap = 0;
				}

				/*
				 * Use the highest level as the synthesis
				 * level.
				 */
				if (bif->bif_warn_cap > batt_syn_oem_warn_cap) {
					batt_syn_oem_low_cap = bif->bif_low_cap;
					batt_syn_oem_warn_cap =
					    bif->bif_warn_cap;
				}
			}
#ifdef DEBUG
			else if (bif_changed) {
				BATT_DBG(CE_NOTE, &bp->dev, "BIF not ready");
			}
#endif

			if (bp->bat_bstok == BATT_NTF_OK) {
				acpi_bst_t *bst;

				bst = &bp->bst_cache;

				/*
				 * Batteries that are rechargeable and are in
				 * the discharging state are required to return
				 * a valid Battery Present Rate value.
				 * 0xFFFFFFFF - Unknown rate/capacity
				 */
				if (bst->bst_rem_cap == 0xffffffff) {
					BATT_DBG(CE_WARN, &bp->dev,
					    "BST value invalid, "
					    "rate=0x%x cap=0x%x",
					    bst->bst_rate, bst->bst_rem_cap);
					continue;
				}

				if (batt_syn_rem_cap == 0xffffffff) {
					batt_syn_rem_cap = 0;
				}
				batt_syn_rem_cap += bst->bst_rem_cap;
				/* Check for overflow */
				ASSERT(batt_syn_rem_cap >= bst->bst_rem_cap);
			}
#ifdef DEBUG
			else {
				BATT_DBG(CE_NOTE, &bp->dev, "BST not ready");
			}
#endif
		}
	}

	BATT_DBG(CE_NOTE, NULL, "syn_cap: %d syn_oem_warn: %d syn_oem_low: %d",
	    batt_syn_rem_cap, batt_syn_oem_warn_cap, batt_syn_oem_low_cap);
}

static struct batt_cbat_state *
batt_idx2cbat(int idx)
{
	if (idx >= BATT_MAX_BAT_NUM) {
		return (NULL);
	}
	return (&batt_cbat[idx]);
}

static struct batt_ac_state *
batt_idx2ac(int idx)
{
	if (idx >= BATT_MAX_AC_NUM) {
		return (NULL);
	}
	return (&batt_ac[idx]);
}

/*ARGSUSED*/
static void
batt_cbat_notify(ACPI_HANDLE hdl, UINT32 val, void *ctx)
{
	struct batt_cbat_state *bp = ctx;
	struct batt_acpi_dev *devp = &bp->dev;
	int bif_changed;
	uint32_t eval;
	char *ev;
	acpi_bst_t *bst;

	BATT_PRT_NOTIFY(hdl, val);
	mutex_enter(&batt_mutex);

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
		bif_changed = batt_update_present(devp);

		/* Omit events sent by empty battery slot */
		if (devp->present == 0) {
			break;
		}

		if (batt_update_bst(bp) != BATT_OK) {
			break;
		}
		batt_update_cap(bif_changed);

		bst = &bp->bst_cache;
		eval = bst->bst_rem_cap;

		/*
		 * Keep tracking the current power source device
		 *
		 * Note: Even no battery plugged, some system
		 * send out 0x80 ACPI event. So make sure the battery
		 * is present first.
		 */
		if (devp->present == 0) {
			if (batt_psr_devp == devp) {
				batt_set_psr(NULL);
			}
			break;
		}
		if (bst->bst_state & BST_FLAG_DISCHARGING) {
			batt_set_psr(devp);
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
			BATT_DBG(CE_WARN, devp, "BST_FLAG_CRITICAL set");

			/*
			 * BST_FLAG_CRITICAL may set even with AC,
			 * plugged, when plug/unplug battery. Check
			 * to avoid erroneous shutdown.
			 */
			if (batt_psr_devp == devp &&
			    bst->bst_rem_cap != 0xffffffff) {
				BATT_DBG(CE_WARN, NULL,
				    "Battery in critical state");
			}
		} else
#endif
		if (batt_warn_enabled &&
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
			if (batt_syn_last_level > batt_syn_low_cap &&
			    batt_syn_rem_cap <= batt_syn_low_cap) {
				batt_gen_sysevent(devp, ESC_ACPIEV_LOW, eval);
			/*
			 * When the total available energy (mWh) or capacity
			 * (mAh) in the batteries falls below this level,
			 * the OS will notify the user through the UI.
			 */
			} else if (batt_syn_last_level > batt_syn_warn_cap &&
			    batt_syn_rem_cap <= batt_syn_warn_cap) {
				batt_gen_sysevent(devp, ESC_ACPIEV_WARN, eval);
			}
		}

		batt_gen_sysevent(devp, ESC_ACPIEV_STATE_CHANGE, 0);
		pollwakeup(&batt_pollhead, BATT_EVENTS);
		break;

	/* BIF has changed */
	case 0x81:
		/*
		 * Note: Do not eliminate multiple ADD/REMOVE here,
		 * because they may corresponding to different batterys.
		 */
		(void) batt_update_present(devp);
		if (devp->present == 1) {
			if (batt_update_bif(bp) != BATT_OK) {
				break;
			}
		} else {
			bp->bat_bifok = BATT_NTF_UNKNOWN;
			bp->bat_bstok = BATT_NTF_UNKNOWN;
		}

		batt_update_cap(1);

		eval = devp->present;
		ev = eval ? ESC_ACPIEV_ADD : ESC_ACPIEV_REMOVE;
		batt_gen_sysevent(devp, ev, 0);
		pollwakeup(&batt_pollhead, BATT_EVENTS);
		break;

	case 0x82:
	default:
		break;
	}

	mutex_exit(&batt_mutex);
}

/*ARGSUSED*/
static void
batt_ac_notify(ACPI_HANDLE hdl, UINT32 val, void *ctx)
{
	struct batt_ac_state *acp = ctx;
	struct batt_acpi_dev *devp = &acp->dev;
	int old_present;
	char *ev;
	int eval;

	BATT_PRT_NOTIFY(hdl, val);
	if (val != 0x80) {
		return;
	}
	mutex_enter(&batt_mutex);

	/*
	 * Note: if unplug and then quickly plug back, two ADD
	 * events will be generated.
	 */
	old_present = devp->present;
	eval = batt_get_psr(acp);

	/* Eliminate redudant events */
	if (eval != -1 && eval != old_present) {
		/* Keep tracking the current power source device */
		if (eval == 1) {
			ev = ESC_ACPIEV_ADD;
			batt_set_psr(devp);
		} else {
			ev = ESC_ACPIEV_REMOVE;
			/* If AC was supplying the power, it's not now */
			if (batt_psr_devp == devp) {
				batt_set_psr(NULL);
			}
		}

		batt_gen_sysevent(devp, ev, 0);
		pollwakeup(&batt_pollhead, BATT_EVENTS);
	}

	mutex_exit(&batt_mutex);
}

static int
batt_obj_init(struct batt_acpi_dev *p)
{
	ACPI_DEVICE_INFO *info;
	ACPI_HANDLE hdl;
	ACPI_BUFFER buf;
	ACPI_NOTIFY_HANDLER ntf_handler = NULL;
	ACPI_STATUS ret;

	ASSERT(p != NULL && p->hdl != NULL);

	hdl = p->hdl;

	/* Info size is variable depending on existance of _CID */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	ret = AcpiGetObjectInfo(hdl, &buf);
	if (ACPI_FAILURE(ret)) {
		BATT_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo() fail: %d", (int32_t)ret);
		return (BATT_ERR);
	}

	info = buf.Pointer;

	if ((info->Valid & ACPI_VALID_HID) == 0) {
		BATT_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo(): _HID not available");
		AcpiOsFree(info);
		return (BATT_ERR);
	}
	(void) strncpy(p->hid, info->HardwareId.Value, 9);

	/*
	 * This object is optional, but is required when the device
	 * has no other way to report a persistent unique device ID.
	 */
	if ((info->Valid & ACPI_VALID_UID) == 0) {
		BATT_DBG(CE_WARN, NULL,
		    "AcpiGetObjectInfo(): _UID not available");
		/* Use 0 as the default _UID */
		(void) strncpy(p->uid, "0", 9);
	} else {
		(void) strncpy(p->uid, info->UniqueId.Value, 9);
	}

	p->valid = 1;
	p->type = BATT_TYPE_UNKNOWN;

	if (strcmp(p->hid, ACPI_DEVNAME_CBAT) == 0) {
		struct batt_cbat_state *bp = (struct batt_cbat_state *)p;

		p->type = BATT_TYPE_CBAT;
		p->index = nbat - 1;
		bp->bat_bifok = BATT_NTF_UNKNOWN;
		bp->bat_bstok = BATT_NTF_UNKNOWN;

		/* Update device present state */
		(void) batt_update_present(p);
		if (p->present) {
			(void) batt_update_bif(bp);
			(void) batt_update_bst(bp);

			/* Init the current power source */
			if (bp->bst_cache.bst_state & BST_FLAG_DISCHARGING) {
				batt_set_psr(p);
			}
		}
		ntf_handler = batt_cbat_notify;
		BATT_DBG(CE_NOTE, p, "battery %s",
		    (p->present ? "present" : "absent"));
	} else if (strcmp(p->hid, ACPI_DEVNAME_AC) == 0) {
		p->type = BATT_TYPE_AC;
		p->index = nac - 1;

		/* Update device present state */
		(void) batt_update_present(p);
		if (p->present) {
			/* Init the current power source */
			batt_set_psr(p);
		}
		ntf_handler = batt_ac_notify;
		BATT_DBG(CE_NOTE, p, "AC %s",
		    (p->present ? "on-line" : "off-line"));
	} else if (strcmp(p->hid, ACPI_DEVNAME_SBAT) == 0) {
		p->type = BATT_TYPE_SBAT;
		BATT_DBG(CE_NOTE, p, "added");
	} else {
		BATT_DBG(CE_NOTE, p, "unknown device");
		p->valid = 0;
	}

	/* Register ACPI battery related events */
	if (ntf_handler != NULL) {
		if (ACPI_FAILURE(AcpiInstallNotifyHandler(hdl,
		    ACPI_ALL_NOTIFY, ntf_handler, p))) {
			BATT_DBG(CE_NOTE, NULL,
			    "Notify handler for %s.%s install failed",
			    p->hid, p->uid);
			return (BATT_ERR);
		}
	}

out:
	AcpiOsFree(info);
	return (BATT_OK);
}

/*ARGSUSED*/
static ACPI_STATUS
batt_find_cb(ACPI_HANDLE ObjHandle, UINT32 NestingLevel, void *Context,
    void **ReturnValue)
{
	struct batt_acpi_dev *devp = (struct batt_acpi_dev *)Context;

	if (devp == &batt_cbat[0].dev) {
		struct batt_cbat_state *bp;

		if (nbat == BATT_MAX_BAT_NUM) {
			BATT_DBG(CE_WARN, NULL,
			    "Need to support more batteries: "
			    "BATTERY_MAX = %d", BATT_MAX_BAT_NUM);
			return (AE_LIMIT);
		}
		bp = &batt_cbat[nbat++];
		devp = (struct batt_acpi_dev *)bp;
	} else if (devp == &batt_ac[0].dev) {
		struct batt_ac_state *ap;

		if (nac == BATT_MAX_AC_NUM) {
			BATT_DBG(CE_WARN, NULL, "Need to support more ACs: "
			    "AC_MAX = %d", BATT_MAX_AC_NUM);
			return (AE_LIMIT);
		}
		ap = &batt_ac[nac++];
		devp = (struct batt_acpi_dev *)ap;
	}

	devp->hdl = ObjHandle;
	*ReturnValue = NULL;

	/* Try to get as many working objs as possible */
	(void) batt_obj_init(devp);
	return (0);
}

static int
batt_acpi_init()
{
	int *retp;

	/* Check to see if ACPI CA services are available */
	if (AcpiSubsystemStatus() != AE_OK) {
		BATT_DBG(CE_WARN, NULL, "ACPI CA not ready");
		return (BATT_ERR);
	}

	/* Init Control Method Batterys */
	if (ACPI_FAILURE(AcpiGetDevices(ACPI_DEVNAME_CBAT, batt_find_cb,
	    batt_cbat, (void *)&retp))) {
		return (BATT_ERR);
	}

	/* Init AC */
	if (ACPI_FAILURE(AcpiGetDevices(ACPI_DEVNAME_AC, batt_find_cb, batt_ac,
	    (void *)&retp))) {
		return (BATT_ERR);
	}

	/* Init Smart Battery */
	if (ACPI_FAILURE(AcpiGetDevices(ACPI_DEVNAME_SBAT, batt_find_cb,
	    &batt_sbat, (void *)&retp))) {
		return (BATT_ERR);
	}

	batt_update_cap(1);

	return (BATT_OK);
}

static void
batt_acpi_fini(void)
{
	int i;
	struct batt_cbat_state *bp;

	for (bp = &batt_cbat[0]; bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
		if (bp->dev.valid) {
			AcpiRemoveNotifyHandler(bp->dev.hdl, ACPI_DEVICE_NOTIFY,
			    batt_cbat_notify);
		}
	}
	for (i = 0; i < nac; i++) {
		AcpiRemoveNotifyHandler(batt_ac[i].dev.hdl, ACPI_DEVICE_NOTIFY,
		    batt_ac_notify);
	}
}

/*ARGSUSED*/
static int
batt_kstat_power_update(kstat_t *ksp, int flag)
{
	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	mutex_enter(&batt_mutex);
	if (batt_psr_type == BATT_TYPE_UNKNOWN) {
		mutex_exit(&batt_mutex);
		return (EIO);
	}
	kstat_named_setstr(&batt_power_kstat.batt_power,
	    batt_psr_type == BATT_TYPE_AC ? AC : BATTERY);
	batt_power_kstat.batt_supported_battery_count.value.ui32 =
	    (uint32_t)nbat;
	mutex_exit(&batt_mutex);

	return (0);
}

/*ARGSUSED*/
static int
batt_kstat_warn_update(kstat_t *ksp, int flag)
{
	if (flag == KSTAT_WRITE) {
		int ret = 0;
		batt_warn_t bw;
		batt_warn_kstat_t kbw;

		kbw = *(batt_warn_kstat_t *)batt_warn_ksp->ks_data;

		mutex_enter(&batt_mutex);
		bw.bw_enabled  = kbw.batt_bw_enabled.value.ui32;
		bw.bw_charge_warn = kbw.batt_bw_charge_warn.value.ui32;
		bw.bw_charge_low = kbw.batt_bw_charge_low.value.ui32;
		ret = batt_set_warn(&bw);
		mutex_exit(&batt_mutex);

		return (ret);
	} else {
		batt_warn_kstat_t *wp = &batt_warn_kstat;

		mutex_enter(&batt_mutex);
		wp->batt_bw_enabled.value.ui32 = batt_warn_enabled;
		wp->batt_bw_charge_warn.value.ui32 = batt_syn_warn_per;
		wp->batt_bw_charge_low.value.ui32 = batt_syn_low_per;
		mutex_exit(&batt_mutex);

		return (0);
	}
}

static int
batt_kstat_bif_update(kstat_t *ksp, int flag)
{
	struct batt_cbat_state *bp;
	acpi_bif_t bif;
	batt_bif_kstat_t *kp;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	bp = (struct batt_cbat_state *)ksp->ks_private;
	mutex_enter(&batt_mutex);

	if (batt_cbat_present(bp) <= 0) {
		mutex_exit(&batt_mutex);
		return (ENXIO);
	}

	bzero(&bif, sizeof (bif));
	bp->bat_bifok = BATT_NTF_UNKNOWN;
	if (batt_get_bif(&bif, bp) != BATT_OK) {
		mutex_exit(&batt_mutex);
		return (ENXIO);
	}

	kp = &batt_bif_kstat;

	/* Update BIF */
	kp->batt_bif_unit.value.ui32 = bif.bif_unit;
	kp->batt_bif_design_cap.value.ui32 = bif.bif_design_cap;
	kp->batt_bif_last_cap.value.ui32 = bif.bif_last_cap;
	kp->batt_bif_tech.value.ui32 = bif.bif_tech;
	kp->batt_bif_voltage.value.ui32 = bif.bif_voltage;
	kp->batt_bif_warn_cap.value.ui32 = bif.bif_warn_cap;
	kp->batt_bif_low_cap.value.ui32 = bif.bif_low_cap;
	kp->batt_bif_gran1_cap.value.ui32 = bif.bif_gran1_cap;
	kp->batt_bif_gran2_cap.value.ui32 = bif.bif_gran2_cap;

	kstat_named_setstr(&kp->batt_bif_model, bif.bif_model);
	kstat_named_setstr(&kp->batt_bif_serial, bif.bif_serial);
	kstat_named_setstr(&kp->batt_bif_type, bif.bif_type);
	kstat_named_setstr(&kp->batt_bif_oem_info, bif.bif_oem_info);

	mutex_exit(&batt_mutex);
	return (0);
}

static int
batt_kstat_bst_update(kstat_t *ksp, int flag)
{
	struct batt_cbat_state *bp;
	acpi_bst_t bst;
	batt_bst_kstat_t *kp;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	bp = (struct batt_cbat_state *)ksp->ks_private;
	mutex_enter(&batt_mutex);

	if (batt_cbat_present(bp) <= 0) {
		mutex_exit(&batt_mutex);
		return (ENXIO);
	}

	bzero(&bst, sizeof (bst));
	bp->bat_bstok = BATT_NTF_UNKNOWN;
	if (batt_get_bst(&bst, bp) != BATT_OK) {
		mutex_exit(&batt_mutex);
		return (ENXIO);
	}

	kp = &batt_bst_kstat;

	/* Update BST */
	kp->batt_bst_state.value.ui32 = bst.bst_state;
	kp->batt_bst_rate.value.ui32 = bst.bst_rate;
	kp->batt_bst_rem_cap.value.ui32 = bst.bst_rem_cap;
	kp->batt_bst_voltage.value.ui32 = bst.bst_voltage;

	mutex_exit(&batt_mutex);
	return (0);
}

static int
batt_kstat_init(void)
{
	char name[KSTAT_STRLEN];
	struct batt_cbat_state *bp;

	/*
	 * Allocate, initialize and install powerstatus and
	 * supported_battery_count kstat.
	 */
	batt_power_ksp = kstat_create(BATT_DRV_NAME, 0,
	    BATT_POWER_KSTAT_NAME, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (batt_power_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (batt_power_ksp == NULL) {
		BATT_DBG(CE_WARN, NULL,
		    "kstat_create(%s) fail", BATT_POWER_KSTAT_NAME);
		return (BATT_ERR);
	}

	batt_power_ksp->ks_data = &batt_power_kstat;
	batt_power_ksp->ks_update = batt_kstat_power_update;
	batt_power_ksp->ks_data_size += MAXNAMELEN;
	kstat_install(batt_power_ksp);

	/*
	 * Allocate, initialize and install battery_capacity_warning kstat.
	 */
	batt_warn_ksp = kstat_create(BATT_DRV_NAME, 0,
	    BATT_BTWARN_KSTAT_NAME, "misc",
	    KSTAT_TYPE_NAMED,
	    sizeof (batt_warn_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);
	if (batt_warn_ksp == NULL) {
		BATT_DBG(CE_WARN, NULL,
		    "kstat_create(%s) fail", BATT_BTWARN_KSTAT_NAME);
		return (BATT_ERR);
	}

	batt_warn_ksp->ks_data = &batt_warn_kstat;
	batt_warn_ksp->ks_update = batt_kstat_warn_update;
	kstat_install(batt_warn_ksp);

	/*
	 * Allocate, initialize and install BIF and BST kstat
	 * for each battery.
	 */
	for (bp = &batt_cbat[0]; bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
		if (bp->dev.valid) {
			kstat_t *ksp;

			/* BIF kstat */
			(void) snprintf(name, KSTAT_STRLEN-1, "%s%d",
			    BATT_BIF_KSTAT_NAME, bp->dev.index);
			ksp = kstat_create(BATT_DRV_NAME, 0,
			    name, "misc", KSTAT_TYPE_NAMED,
			    sizeof (batt_bif_kstat) / sizeof (kstat_named_t),
			    KSTAT_FLAG_VIRTUAL);
			if (ksp == NULL) {
				BATT_DBG(CE_WARN, NULL, "kstat_create(%s) fail",
				    name);
				return (BATT_ERR);
			}
			BATT_DBG(CE_NOTE, NULL, "kstat_create(%s) ok", name);

			bp->bat_bif_ksp = ksp;
			ksp->ks_data = &batt_bif_kstat;
			ksp->ks_update = batt_kstat_bif_update;
			ksp->ks_data_size += MAXNAMELEN * 4;
			ksp->ks_private = bp;

			kstat_install(ksp);

			/* BST kstat */
			(void) snprintf(name, KSTAT_STRLEN-1, "%s%d",
			    BATT_BST_KSTAT_NAME, bp->dev.index);
			ksp = kstat_create(BATT_DRV_NAME, 0, name, "misc",
			    KSTAT_TYPE_NAMED,
			    sizeof (batt_bst_kstat) / sizeof (kstat_named_t),
			    KSTAT_FLAG_VIRTUAL);
			if (ksp == NULL) {
				BATT_DBG(CE_WARN, NULL,
				    "kstat_create(%s) fail", name);
				return (BATT_ERR);
			}
			BATT_DBG(CE_NOTE, NULL, "kstat_create(%s) ok", name);

			bp->bat_bst_ksp = ksp;
			ksp->ks_data = &batt_bst_kstat;
			ksp->ks_update = batt_kstat_bst_update;
			ksp->ks_data_size += MAXNAMELEN * 4;
			ksp->ks_private = bp;

			kstat_install(ksp);
		}
	}

	return (BATT_OK);
}

static void
batt_kstat_fini()
{
	struct batt_cbat_state *bp;

	if (batt_power_ksp != NULL) {
		kstat_delete(batt_power_ksp);
	}
	if (batt_warn_ksp != NULL) {
		kstat_delete(batt_warn_ksp);
	}
	for (bp = &batt_cbat[0]; bp < &batt_cbat[BATT_MAX_BAT_NUM]; bp++) {
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
