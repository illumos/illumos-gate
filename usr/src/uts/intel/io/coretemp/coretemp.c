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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

/*
 * Intel CPU Thermal sensor driver
 *
 * These MSRs that were used were introduced with the 'Core' family processors
 * and have since spread beyond there, even to the Atom line. Currently,
 * temperature sensors exist on a per-core basis and optionally on a per-package
 * basis. The temperature sensor exposes a reading that's relative to the
 * processor's maximum junction temperature, often referred to as Tj. We
 * currently only support models where we can determine that junction
 * temperature programmatically. For older processors, we would need to track
 * down the datasheet. Unfortunately, the values here are often on a per-brand
 * string basis. As in two CPUs with the same model and stepping, but have
 * binned differently have different temperatures.
 *
 * The temperature is exposed through /dev and uses a semi-standard sensor
 * framework. We expose one minor node per CPU core and one minor node per CPU
 * package, if that is supported. Reads are rate-limited in the driver at 100ms
 * by default per the global variable coretemp_cache_ms.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/list.h>
#include <sys/stddef.h>
#include <sys/cmn_err.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module.h>
#include <sys/ontrap.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/sensors.h>

/*
 * The Intel SDM says that the measurements we get are always in degrees
 * Celsius.
 */
#define	CORETEMP_GRANULARITY	1

typedef enum coretemp_sensor_type {
	CORETEMP_S_CORE,
	CORETEMP_S_SOCKET
} coretemp_sensor_type_t;

typedef struct coretemp_sensor {
	list_node_t		cs_link;
	struct coretemp		*cs_coretemp;
	char			cs_name[128];
	id_t			cs_sensor;
	coretemp_sensor_type_t	cs_type;
	enum cmi_hdl_class	cs_class;
	uint_t			cs_chip;
	uint_t			cs_core;
	uint_t			cs_strand;
	uint_t			cs_tjmax;
	uint_t			cs_status_msr;
	uint_t			cs_intr_msr;
	hrtime_t		cs_last_read;
	uint64_t		cs_status;
	uint64_t		cs_intr;
	/* The following fields are derived from above */
	uint_t			cs_temperature;
	uint_t			cs_resolution;
} coretemp_sensor_t;

typedef struct coretemp {
	dev_info_t	*coretemp_dip;
	cpuset_t	*coretemp_cpuset;
	boolean_t	coretemp_pkg;
	kmutex_t	coretemp_mutex;
	list_t		coretemp_sensors;
} coretemp_t;

coretemp_t *coretemp;

/*
 * This indicates a number of milliseconds that we should wait between reads.
 * This is somewhat arbitrary, but the goal is to reduce cross call activity
 * and reflect that the sensor may not update all the time.
 */
uint_t coretemp_cache_ms = 100;

static int
coretemp_rdmsr_xc(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
{
	uint_t msr = (uint_t)arg1;
	uint64_t *valp = (uint64_t *)arg2;
	cmi_errno_t *errp = (cmi_errno_t *)arg3;

	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		if (checked_rdmsr(msr, valp) == 0) {
			*errp = CMI_SUCCESS;
		} else {
			*errp = CMIERR_NOTSUP;
		}
	} else {
		*errp = CMIERR_MSRGPF;
	}
	no_trap();

	return (0);
}

/*
 * This really should just be a call to the CMI handle to provide us the MSR.
 * However, that routine, cmi_hdl_rdmsr(), cannot be safely used until it is
 * fixed for use outside of a panic-like context.
 */
static int
coretemp_rdmsr(coretemp_t *ct, cmi_hdl_t hdl, uint_t msr, uint64_t *valp)
{
	id_t cpu = cmi_hdl_logical_id(hdl);
	int ret = CMI_SUCCESS;

	ASSERT(MUTEX_HELD(&ct->coretemp_mutex));
	kpreempt_disable();
	if (CPU->cpu_id == cpu) {
		(void) coretemp_rdmsr_xc((xc_arg_t)msr, (xc_arg_t)valp,
		    (xc_arg_t)&ret);
	} else {
		cpuset_only(ct->coretemp_cpuset, (uint_t)cpu);
		xc_call((xc_arg_t)msr, (xc_arg_t)valp, (xc_arg_t)&ret,
		    (ulong_t *)ct->coretemp_cpuset, coretemp_rdmsr_xc);
	}
	kpreempt_enable();

	return (ret);
}

static int
coretemp_cmi_errno(cmi_errno_t e)
{
	switch (e) {
	case CMIERR_NOTSUP:
		return (ENOTSUP);
	default:
		return (EIO);
	}
}

/*
 * Answer the question of whether or not the driver can support the CPU in
 * question. Right now we have the following constraints for supporting the CPU:
 *
 *   o The CPU is made by Intel
 *   o The CPU has the Digital Thermal Sensor
 *   o The CPU family is 6, which is usually implicit from the above
 *   o We can determine its junction temperature through an MSR
 *
 * If we can't determine the junction temperature programmatically, then we need
 * to set up tables of CPUs to do so. This can be fleshed out and improved.
 */
static boolean_t
coretemp_supported(void)
{
	uint_t model;

	if (cpuid_getvendor(CPU) != X86_VENDOR_Intel) {
		return (B_FALSE);
	}

	if (!is_x86_feature(x86_featureset, X86FSET_CORE_THERMAL)) {
		return (B_FALSE);
	}

	if (cpuid_getfamily(CPU) != 6) {
		return (B_FALSE);
	}

	model = cpuid_getmodel(CPU);
	if (model <= INTC_MODEL_PENRYN || model == INTC_MODEL_SILVERTHORNE ||
	    model == INTC_MODEL_LINCROFT || model == INTC_MODEL_PENWELL ||
	    model == INTC_MODEL_CLOVERVIEW || model == INTC_MODEL_CEDARVIEW) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * We need to determine the value of Tj Max as all temperature sensors are
 * derived from this value. The ease of this depends on how old the processor in
 * question is. The Core family processors after Penryn have support for an MSR
 * that tells us what to go for. In the Atom family, processors starting with
 * Silvermont have support for an MSR that documents this value. For older
 * processors, one needs to track down the datasheet for a specific processor.
 * Two processors in the same family/model may have different values of Tj Max.
 * At the moment, we only support this on processors that have that MSR.
 */
static int
coretemp_calculate_tjmax(coretemp_t *ct, cmi_hdl_t hdl, uint_t *tjmax)
{
	cmi_errno_t e;
	uint64_t val = 0;

	e = coretemp_rdmsr(ct, hdl, MSR_TEMPERATURE_TARGET, &val);
	if (e != CMI_SUCCESS) {
		return (coretemp_cmi_errno(e));
	} else if (val == 0) {
		return (EINVAL);
	}

	*tjmax = MSR_TEMPERATURE_TARGET_TARGET(val);
	return (0);
}

static int
coretemp_update(coretemp_t *ct, coretemp_sensor_t *sensor, cmi_hdl_t hdl)
{
	cmi_errno_t e;
	int err = 0;
	uint64_t intr, status;

	if ((e = coretemp_rdmsr(ct, hdl, sensor->cs_status_msr, &status)) !=
	    CMI_SUCCESS) {
		err = coretemp_cmi_errno(e);
		dev_err(ct->coretemp_dip, CE_WARN, "!failed to get thermal "
		    "status on %s: %d", sensor->cs_name, err);
		return (err);
	}

	if ((e = coretemp_rdmsr(ct, hdl, sensor->cs_intr_msr, &intr)) !=
	    CMI_SUCCESS) {
		err = coretemp_cmi_errno(e);
		dev_err(ct->coretemp_dip, CE_WARN, "!failed to get thermal "
		    "interrupt on %s: %d", sensor->cs_name, err);
		return (err);
	}

	sensor->cs_status = status;
	sensor->cs_intr = intr;
	sensor->cs_last_read = gethrtime();
	return (0);
}

static int
coretemp_read(void *arg, sensor_ioctl_temperature_t *sit)
{
	coretemp_sensor_t *sensor = arg;
	coretemp_t *ct = sensor->cs_coretemp;
	hrtime_t diff;
	uint_t reading, resolution;

	mutex_enter(&ct->coretemp_mutex);
	diff = NSEC2MSEC(gethrtime() - sensor->cs_last_read);
	if (diff > 0 && diff > (hrtime_t)coretemp_cache_ms) {
		int ret;
		cmi_hdl_t hdl;

		if ((hdl = cmi_hdl_lookup(sensor->cs_class, sensor->cs_chip,
		    sensor->cs_core, sensor->cs_strand)) == NULL) {
			mutex_exit(&ct->coretemp_mutex);
			return (ENXIO);
		}
		ret = coretemp_update(ct, sensor, hdl);
		cmi_hdl_rele(hdl);
		if (ret != 0) {
			mutex_exit(&ct->coretemp_mutex);
			return (ret);
		}
	}

	switch (sensor->cs_type) {
	case CORETEMP_S_CORE:
		if ((sensor->cs_status & IA32_THERM_STATUS_READ_VALID) == 0) {
			mutex_exit(&ct->coretemp_mutex);
			return (EIO);
		}
		reading = IA32_THERM_STATUS_READING(sensor->cs_status);
		resolution = IA32_THERM_STATUS_RESOLUTION(sensor->cs_status);
		break;
	case CORETEMP_S_SOCKET:
		reading = IA32_PKG_THERM_STATUS_READING(sensor->cs_status);
		resolution = 0;
		break;
	default:
		mutex_exit(&ct->coretemp_mutex);
		return (ENXIO);
	}
	if (reading >= sensor->cs_tjmax) {
		dev_err(ct->coretemp_dip, CE_WARN, "!found invalid temperature "
		    "on sensor %s: readout: %u, tjmax: %u, raw: 0x%"
		    PRIx64, sensor->cs_name, reading, sensor->cs_tjmax,
		    sensor->cs_status);
		mutex_exit(&ct->coretemp_mutex);
		return (EIO);
	}
	sensor->cs_temperature = sensor->cs_tjmax - reading;
	sensor->cs_resolution = resolution;

	sit->sit_unit = SENSOR_UNIT_CELSIUS;
	sit->sit_temp = sensor->cs_temperature;
	sit->sit_gran = CORETEMP_GRANULARITY;
	sit->sit_prec = sensor->cs_resolution;
	mutex_exit(&ct->coretemp_mutex);

	return (0);
}

static const ksensor_ops_t coretemp_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_temp = coretemp_read
};

static void
coretemp_destroy(coretemp_t *ct)
{
	coretemp_sensor_t *sensor;

	(void) ksensor_remove(ct->coretemp_dip, KSENSOR_ALL_IDS);
	while ((sensor = list_remove_head(&ct->coretemp_sensors)) != NULL) {
		kmem_free(sensor, sizeof (coretemp_sensor_t));
	}
	list_destroy(&ct->coretemp_sensors);

	if (ct->coretemp_cpuset != NULL) {
		cpuset_free(ct->coretemp_cpuset);
	}

	mutex_destroy(&ct->coretemp_mutex);
	kmem_free(ct, sizeof (coretemp_t));
}

static boolean_t
coretemp_create_sensor(coretemp_t *ct, cmi_hdl_t hdl, uint_t tjmax,
    coretemp_sensor_type_t type)
{
	int err;
	coretemp_sensor_t *sensor;

	sensor = kmem_zalloc(sizeof (coretemp_sensor_t), KM_SLEEP);
	sensor->cs_coretemp = ct;
	sensor->cs_type = type;
	sensor->cs_class = cmi_hdl_class(hdl);
	sensor->cs_chip = cmi_hdl_chipid(hdl);
	sensor->cs_core = cmi_hdl_coreid(hdl);
	sensor->cs_strand = 0;
	sensor->cs_tjmax = tjmax;

	switch (sensor->cs_type) {
	case CORETEMP_S_CORE:
		if (snprintf(sensor->cs_name, sizeof (sensor->cs_name),
		    "chip%u.core%u", sensor->cs_chip, sensor->cs_core) >=
		    sizeof (sensor->cs_name)) {
			goto err;
		}
		sensor->cs_status_msr = MSR_IA32_THERM_STATUS;
		sensor->cs_intr_msr = MSR_IA32_THERM_INTERRUPT;
		break;
	case CORETEMP_S_SOCKET:
		if (snprintf(sensor->cs_name, sizeof (sensor->cs_name),
		    "chip%u", sensor->cs_chip) >= sizeof (sensor->cs_name)) {
			goto err;
		}
		sensor->cs_status_msr = MSR_IA32_PACKAGE_THERM_STATUS;
		sensor->cs_intr_msr = MSR_IA32_PACKAGE_THERM_INTERRUPT;
		break;
	}

	if ((err = ksensor_create(ct->coretemp_dip, &coretemp_temp_ops, sensor,
	    sensor->cs_name, DDI_NT_SENSOR_TEMP_CPU, &sensor->cs_sensor)) !=
	    0) {
		dev_err(ct->coretemp_dip, CE_WARN, "failed to create ksensor "
		    "for %s: %d", sensor->cs_name, err);
	}

	return (B_TRUE);
err:
	kmem_free(sensor, sizeof (coretemp_sensor_t));
	return (B_FALSE);
}

static int
coretemp_walk(cmi_hdl_t hdl, void *arg1, void *arg2, void *arg3)
{
	coretemp_t *ct = arg1;
	boolean_t *walkerr = arg2;
	uint_t tjmax;
	int err;

	/*
	 * The temperature sensor only exists on a per-core basis. Therefore we
	 * ignore any non-zero strand.
	 */
	if (cmi_hdl_strandid(hdl) != 0) {
		return (CMI_HDL_WALK_NEXT);
	}

	if ((err = coretemp_calculate_tjmax(ct, hdl, &tjmax)) != 0) {
		dev_err(ct->coretemp_dip, CE_WARN,
		    "failed to read Tj Max on %u/%u: %d", cmi_hdl_chipid(hdl),
		    cmi_hdl_coreid(hdl), err);
		*walkerr = B_TRUE;
		return (CMI_HDL_WALK_DONE);
	}

	if (!coretemp_create_sensor(ct, hdl, tjmax, CORETEMP_S_CORE)) {
		*walkerr = B_TRUE;
		return (CMI_HDL_WALK_DONE);
	}

	if (ct->coretemp_pkg && cmi_hdl_coreid(hdl) == 0 &&
	    !coretemp_create_sensor(ct, hdl, tjmax, CORETEMP_S_SOCKET)) {
		*walkerr = B_TRUE;
		return (CMI_HDL_WALK_DONE);
	}

	return (CMI_HDL_WALK_NEXT);
}

static int
coretemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	boolean_t walkerr;
	coretemp_t *ct = NULL;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (coretemp != NULL) {
		return (DDI_FAILURE);
	}

	ct = kmem_zalloc(sizeof (coretemp_t), KM_SLEEP);
	ct->coretemp_dip = dip;
	ct->coretemp_pkg = is_x86_feature(x86_featureset, X86FSET_PKG_THERMAL);
	list_create(&ct->coretemp_sensors, sizeof (coretemp_sensor_t),
	    offsetof(coretemp_sensor_t, cs_link));
	mutex_init(&ct->coretemp_mutex, NULL, MUTEX_DRIVER, NULL);
	ct->coretemp_cpuset = cpuset_alloc(KM_SLEEP);

	mutex_enter(&ct->coretemp_mutex);
	walkerr = B_FALSE;
	cmi_hdl_walk(coretemp_walk, ct, &walkerr, NULL);

	if (walkerr) {
		mutex_exit(&ct->coretemp_mutex);
		goto fail;
	}

	coretemp = ct;
	mutex_exit(&ct->coretemp_mutex);
	return (DDI_SUCCESS);
fail:
	coretemp = NULL;
	coretemp_destroy(ct);
	return (DDI_FAILURE);

}

static int
coretemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (coretemp == NULL) {
		return (DDI_FAILURE);
	}

	coretemp_destroy(coretemp);
	coretemp = NULL;

	return (DDI_SUCCESS);
}

static struct dev_ops coretemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = coretemp_attach,
	.devo_detach = coretemp_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv coretemp_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Intel CPU/Package thermal sensor",
	.drv_dev_ops = &coretemp_dev_ops
};

static struct modlinkage coretemp_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &coretemp_modldrv, NULL }
};

int
_init(void)
{
	if (!coretemp_supported()) {
		return (ENOTSUP);
	}

	return (mod_install(&coretemp_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&coretemp_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&coretemp_modlinkage));
}
