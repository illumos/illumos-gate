/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Robert Mustacchi
 */

/*
 * AMD Northbridge CPU Temperature Driver
 *
 * The AMD northbridge CPU temperature driver supports the temperature sensor
 * that was found on the AMD northbridge on AMD CPUs from approximately AMD
 * Family 10h to Family 16h. For Zen and newer processors (Family 17h+) see the
 * 'amdf17nbdf' driver.
 *
 * The temperature is stored on the 'miscellaneous' device on the northbridge.
 * This is always found at PCI Device 18h, Function 3h. When there is more than
 * one 'node' (see cpuid.c for the AMD parlance), then the node id is added to
 * the device to create a unique device. This allows us to map the given PCI
 * device we find back to the corresponding CPU.
 *
 * While all family 10h, 11h, 12h, 14h, and 16h CPUs are supported, not all
 * family 15h CPUs are. Models 60h+ require the SMN interface, which this does
 * not know how to consume.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/pci.h>
#include <sys/stddef.h>
#include <sys/cpuvar.h>
#include <sys/x86_archext.h>
#include <sys/list.h>
#include <sys/bitset.h>
#include <sys/sensors.h>

/*
 * This register offset, in PCI config space, has the current temperature of the
 * device.
 */
#define	AMDNBTEMP_TEMPREG	0xa4
#define	AMDNBTEMP_TEMPREG_CURTMP(x)	BITX(x, 31, 21)
#define	AMDNBTEMP_TEMPREG_TJSEL(x)	BITX(x, 17, 16)

/*
 * Each bit in the temperature range represents 1/8th of a degree C.
 */
#define	AMDNBTEMP_GRANULARITY	8
#define	AMDNBTEMP_GSHIFT	3

/*
 * If the value of the current CurTmpTjSel is set to three, then the range that
 * the data is in is shifted by -49 degrees. In this mode, the bottom two bits
 * always read as zero.
 */
#define	AMDNBTEMP_TJSEL_ADJUST	0x3
#define	AMDNBTEMP_TEMP_ADJUST	(49 << AMDNBTEMP_GSHIFT)

/*
 * There are a variable number of northbridges that exist in the system. The AMD
 * BIOS and Kernel Developer's Guide (BKDG) says that for these families, the
 * first node has a device of 0x18. This means that node 7, the maximum, has a
 * device of 0x1f.
 */
#define	AMDNBTEMP_FIRST_DEV	0x18

typedef enum andnbtemp_state {
	AMDNBTEMP_S_CFGSPACE	= 1 << 0,
	AMDNBTEMP_S_MUTEX	= 1 << 1,
	AMDNBTEMP_S_MINOR	= 1 << 2,
	AMDNBTEMP_S_LIST	= 1 << 3
} amdnbtemp_state_t;

typedef struct amdnbtemp {
	amdnbtemp_state_t	at_state;
	list_node_t		at_link;
	dev_info_t		*at_dip;
	ddi_acc_handle_t	at_cfgspace;
	uint_t			at_bus;
	uint_t			at_dev;
	uint_t			at_func;
	minor_t			at_minor;
	boolean_t		at_tjsel;
	kmutex_t		at_mutex;
	uint32_t		at_raw;
	int64_t			at_temp;
} amdnbtemp_t;

static void *amdnbtemp_state;
static list_t amdnbtemp_list;
static kmutex_t amdnbtemp_mutex;

static amdnbtemp_t *
amdnbtemp_find_by_dev(dev_t dev)
{
	minor_t m = getminor(dev);
	amdnbtemp_t *at;

	mutex_enter(&amdnbtemp_mutex);
	for (at = list_head(&amdnbtemp_list); at != NULL;
	    at = list_next(&amdnbtemp_list, at)) {
		if (at->at_minor == m) {
			break;
		}
	}
	mutex_exit(&amdnbtemp_mutex);

	return (at);
}

static int
amdnbtemp_read(amdnbtemp_t *at)
{
	ASSERT(MUTEX_HELD(&at->at_mutex));

	at->at_raw = pci_config_get32(at->at_cfgspace, AMDNBTEMP_TEMPREG);
	if (at->at_raw == PCI_EINVAL32) {
		return (EIO);
	}

	at->at_temp = AMDNBTEMP_TEMPREG_CURTMP(at->at_raw);
	if (at->at_tjsel &&
	    AMDNBTEMP_TEMPREG_TJSEL(at->at_raw) == AMDNBTEMP_TJSEL_ADJUST) {
		at->at_temp -= AMDNBTEMP_TEMP_ADJUST;
	}

	return (0);
}

static int
amdnbtemp_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	amdnbtemp_t *at;

	if (crgetzoneid(credp) != GLOBAL_ZONEID || drv_priv(credp) != 0) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	at = amdnbtemp_find_by_dev(*devp);
	if (at == NULL) {
		return (ENXIO);
	}

	return (0);
}

static int
amdnbtemp_ioctl_kind(intptr_t arg, int mode)
{
	sensor_ioctl_kind_t kind;

	bzero(&kind, sizeof (kind));
	kind.sik_kind = SENSOR_KIND_TEMPERATURE;

	if (ddi_copyout(&kind, (void *)arg, sizeof (kind), mode & FKIOCTL) !=
	    0) {
		return (EFAULT);
	}

	return (0);
}

static int
amdnbtemp_ioctl_temp(amdnbtemp_t *at, intptr_t arg, int mode)
{
	int ret;
	sensor_ioctl_temperature_t temp;

	bzero(&temp, sizeof (temp));

	mutex_enter(&at->at_mutex);
	if ((ret = amdnbtemp_read(at)) != 0) {
		mutex_exit(&at->at_mutex);
		return (ret);
	}

	temp.sit_unit = SENSOR_UNIT_CELSIUS;
	temp.sit_gran = AMDNBTEMP_GRANULARITY;
	temp.sit_temp = at->at_temp;
	mutex_exit(&at->at_mutex);

	if (ddi_copyout(&temp, (void *)arg, sizeof (temp), mode & FKIOCTL) !=
	    0) {
		return (EFAULT);
	}

	return (0);
}

static int
amdnbtemp_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	amdnbtemp_t *at;

	at = amdnbtemp_find_by_dev(dev);
	if (at == NULL) {
		return (ENXIO);
	}

	if ((mode & FREAD) == 0) {
		return (EINVAL);
	}

	switch (cmd) {
	case SENSOR_IOCTL_TYPE:
		return (amdnbtemp_ioctl_kind(arg, mode));
	case SENSOR_IOCTL_TEMPERATURE:
		return (amdnbtemp_ioctl_temp(at, arg, mode));
	default:
		return (ENOTTY);
	}
}

static int
amdnbtemp_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static void
amdnbtemp_cleanup(amdnbtemp_t *at)
{
	int inst;
	inst = ddi_get_instance(at->at_dip);

	if ((at->at_state & AMDNBTEMP_S_LIST) != 0) {
		mutex_enter(&amdnbtemp_mutex);
		list_remove(&amdnbtemp_list, at);
		mutex_exit(&amdnbtemp_mutex);
		at->at_state &= ~AMDNBTEMP_S_LIST;
	}

	if ((at->at_state & AMDNBTEMP_S_MINOR) != 0) {
		ddi_remove_minor_node(at->at_dip, NULL);
		at->at_state &= ~AMDNBTEMP_S_MINOR;
	}

	if ((at->at_state & AMDNBTEMP_S_MUTEX) != 0) {
		mutex_destroy(&at->at_mutex);
		at->at_state &= ~AMDNBTEMP_S_MUTEX;
	}

	if ((at->at_state & AMDNBTEMP_S_CFGSPACE) != 0) {
		pci_config_teardown(&at->at_cfgspace);
		at->at_state &= ~AMDNBTEMP_S_CFGSPACE;
	}

	ASSERT0(at->at_state);
	ddi_soft_state_free(amdnbtemp_state, inst);
}

/*
 * For several family 10h processors, certain models have an erratum which says
 * that temperature information is unreliable. If we're on a platform that is
 * subject to this erratum, do not attach to the device.
 */
static boolean_t
amdnbtemp_erratum_319(void)
{
	uint32_t socket;

	if (cpuid_getfamily(CPU) != 0x10) {
		return (B_FALSE);
	}

	/*
	 * All Family 10h socket F parts are impacted. Socket AM2 parts are all
	 * impacted. The family 10h socket bits in cpuid share the same bit for
	 * socket AM2 and AM3. If you look at the erratum description, they use
	 * information about the memory controller to do DDR2/DDR3
	 * disambiguation to determine whether it's socket AM2 or AM3. Our cpuid
	 * subroutines already do the DDR2/DDR3 disambiguation so we can just
	 * check the socket type as the disambiguation has already been done.
	 */
	socket = cpuid_getsockettype(CPU);
	if (socket == X86_SOCKET_F1207 || socket == X86_SOCKET_AM2R2) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

static int
amdnbtemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst, *regs;
	amdnbtemp_t *at;
	uint_t nregs;
	char buf[128];

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(amdnbtemp_state, inst) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to allocate soft state entry %d",
		    inst);
		return (DDI_FAILURE);
	}

	at = ddi_get_soft_state(amdnbtemp_state, inst);
	if (at == NULL) {
		dev_err(dip, CE_WARN, "failed to retrieve soft state entry %d",
		    inst);
		return (DDI_FAILURE);
	}

	at->at_dip = dip;

	if (pci_config_setup(dip, &at->at_cfgspace) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to set up PCI config space");
		goto err;
	}
	at->at_state |= AMDNBTEMP_S_CFGSPACE;

	if (amdnbtemp_erratum_319()) {
		dev_err(dip, CE_WARN, "!device subject to AMD Erratum 319, "
		    "not attaching to unreliable sensor");
		goto err;
	}

	mutex_init(&at->at_mutex, NULL, MUTEX_DRIVER, NULL);
	at->at_state |= AMDNBTEMP_S_MUTEX;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, "reg",
	    &regs, &nregs) != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to get pci 'reg' property");
		goto err;
	}

	if (nregs < 1) {
		dev_err(dip, CE_WARN, "'reg' property missing PCI b/d/f");
		ddi_prop_free(regs);
		goto err;
	}

	at->at_bus = PCI_REG_BUS_G(regs[0]);
	at->at_dev = PCI_REG_DEV_G(regs[0]);
	at->at_func = PCI_REG_DEV_G(regs[0]);
	ddi_prop_free(regs);

	if (at->at_dev < AMDNBTEMP_FIRST_DEV) {
		dev_err(dip, CE_WARN, "Invalid pci b/d/f device, found 0x%x",
		    at->at_dev);
		goto err;
	}

	at->at_minor = at->at_dev - AMDNBTEMP_FIRST_DEV;
	if (snprintf(buf, sizeof (buf), "procnode.%u", at->at_minor) >=
	    sizeof (buf)) {
		dev_err(dip, CE_WARN, "unexpected buffer name overrun "
		    "constructing minor %u", at->at_minor);
		goto err;
	}

	if (ddi_create_minor_node(dip, buf, S_IFCHR, at->at_minor,
	    DDI_NT_SENSOR_TEMP_CPU, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to create minor node %s",
		    buf);
		goto err;
	}
	at->at_state |= AMDNBTEMP_S_MINOR;

	mutex_enter(&amdnbtemp_mutex);
	list_insert_tail(&amdnbtemp_list, at);
	mutex_exit(&amdnbtemp_mutex);
	at->at_state |= AMDNBTEMP_S_LIST;

	/*
	 * On families 15h and 16h the BKDG documents that the CurTmpTjSel bits
	 * of the temperature register dictate how the temperature reading
	 * should be interpreted. Capture that now.
	 */
	if (cpuid_getfamily(CPU) >= 0x15) {
		at->at_tjsel = B_TRUE;
	}

	mutex_enter(&at->at_mutex);
	(void) amdnbtemp_read(at);
	mutex_exit(&at->at_mutex);

	return (DDI_SUCCESS);

err:
	amdnbtemp_cleanup(at);
	return (DDI_FAILURE);
}

static int
amdnbtemp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	amdnbtemp_t *at;

	if (cmd != DDI_INFO_DEVT2DEVINFO && cmd != DDI_INFO_DEVT2INSTANCE) {
		return (DDI_FAILURE);
	}

	at = amdnbtemp_find_by_dev((dev_t)arg);
	if (at == NULL) {
		return (DDI_FAILURE);
	}

	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		*resultp = at->at_dip;
	} else {
		*resultp = (void *)(uintptr_t)ddi_get_instance(at->at_dip);
	}

	return (DDI_SUCCESS);
}

static int
amdnbtemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	amdnbtemp_t *at;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	inst = ddi_get_instance(dip);
	at = ddi_get_soft_state(amdnbtemp_state, inst);
	if (at == NULL) {
		dev_err(dip, CE_WARN, "asked to detach instance %d, but it is "
		    "missing from the soft state", inst);
		return (DDI_FAILURE);
	}

	amdnbtemp_cleanup(at);
	return (DDI_SUCCESS);
}

static struct cb_ops amdnbtemp_cb_ops = {
	.cb_open = amdnbtemp_open,
	.cb_close = amdnbtemp_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = amdnbtemp_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops amdnbtemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = amdnbtemp_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = amdnbtemp_attach,
	.devo_detach = amdnbtemp_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &amdnbtemp_cb_ops
};

static struct modldrv amdnbtemp_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD NB Temp Driver",
	.drv_dev_ops = &amdnbtemp_dev_ops
};

static struct modlinkage amdnbtemp_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &amdnbtemp_modldrv, NULL }
};

int
_init(void)
{
	int ret;

	if (ddi_soft_state_init(&amdnbtemp_state, sizeof (amdnbtemp_t), 2) !=
	    DDI_SUCCESS) {
		return (ENOMEM);
	}

	if ((ret = mod_install(&amdnbtemp_modlinkage)) != 0) {
		ddi_soft_state_fini(&amdnbtemp_state);
		return (ret);
	}

	list_create(&amdnbtemp_list, sizeof (amdnbtemp_t),
	    offsetof(amdnbtemp_t, at_link));
	mutex_init(&amdnbtemp_mutex, NULL, MUTEX_DRIVER, NULL);

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&amdnbtemp_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&amdnbtemp_modlinkage)) != 0) {
		return (ret);
	}

	mutex_destroy(&amdnbtemp_mutex);
	list_destroy(&amdnbtemp_list);
	ddi_soft_state_fini(&amdnbtemp_state);
	return (ret);
}
