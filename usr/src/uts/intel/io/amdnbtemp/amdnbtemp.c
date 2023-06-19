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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * AMD Northbridge CPU Temperature Driver
 *
 * The AMD northbridge CPU temperature driver supports the temperature sensor
 * that was found on the AMD northbridge on AMD CPUs from approximately AMD
 * Family 10h to Family 16h. For Zen and newer processors (Family 17h+) see the
 * 'smntemp' driver.
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
	AMDNBTMEP_S_KSENSOR	= 1 << 2
} amdnbtemp_state_t;

typedef struct amdnbtemp {
	amdnbtemp_state_t	at_state;
	dev_info_t		*at_dip;
	ddi_acc_handle_t	at_cfgspace;
	uint_t			at_bus;
	uint_t			at_dev;
	uint_t			at_func;
	id_t			at_ksensor;
	minor_t			at_minor;
	boolean_t		at_tjsel;
	kmutex_t		at_mutex;
	uint32_t		at_raw;
	int64_t			at_temp;
} amdnbtemp_t;

static void *amdnbtemp_state;

static int
amdnbtemp_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	amdnbtemp_t *at = arg;

	mutex_enter(&at->at_mutex);
	at->at_raw = pci_config_get32(at->at_cfgspace, AMDNBTEMP_TEMPREG);
	if (at->at_raw == PCI_EINVAL32) {
		mutex_exit(&at->at_mutex);
		return (EIO);
	}

	at->at_temp = AMDNBTEMP_TEMPREG_CURTMP(at->at_raw);
	if (at->at_tjsel &&
	    AMDNBTEMP_TEMPREG_TJSEL(at->at_raw) == AMDNBTEMP_TJSEL_ADJUST) {
		at->at_temp -= AMDNBTEMP_TEMP_ADJUST;
	}

	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_gran = AMDNBTEMP_GRANULARITY;
	scalar->sis_value = at->at_temp;
	mutex_exit(&at->at_mutex);

	return (0);
}

static const ksensor_ops_t amdnbtemp_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = amdnbtemp_read
};

static void
amdnbtemp_cleanup(amdnbtemp_t *at)
{
	int inst;
	inst = ddi_get_instance(at->at_dip);

	if ((at->at_state & AMDNBTMEP_S_KSENSOR) != 0) {
		(void) ksensor_remove(at->at_dip, KSENSOR_ALL_IDS);
		at->at_state &= ~AMDNBTMEP_S_KSENSOR;
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
	int inst, *regs, ret;
	amdnbtemp_t *at;
	uint_t nregs, id;
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

	id = at->at_dev - AMDNBTEMP_FIRST_DEV;
	if (snprintf(buf, sizeof (buf), "procnode.%u", id) >= sizeof (buf)) {
		dev_err(dip, CE_WARN, "unexpected buffer name overrun "
		    "constructing sensor %u", id);
		goto err;
	}

	/*
	 * On families 15h and 16h the BKDG documents that the CurTmpTjSel bits
	 * of the temperature register dictate how the temperature reading
	 * should be interpreted. Capture that now.
	 */
	if (cpuid_getfamily(CPU) >= 0x15) {
		at->at_tjsel = B_TRUE;
	}

	if ((ret = ksensor_create(dip, &amdnbtemp_temp_ops, at, buf,
	    DDI_NT_SENSOR_TEMP_CPU, &at->at_ksensor)) != 0) {
		dev_err(dip, CE_WARN, "failed to create ksensor for %s: %d",
		    buf, ret);
		goto err;
	}
	at->at_state |= AMDNBTMEP_S_KSENSOR;

	return (DDI_SUCCESS);

err:
	amdnbtemp_cleanup(at);
	return (DDI_FAILURE);
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

static struct dev_ops amdnbtemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = amdnbtemp_attach,
	.devo_detach = amdnbtemp_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
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

	ddi_soft_state_fini(&amdnbtemp_state);
	return (ret);
}
