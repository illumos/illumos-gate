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
 * temperature programatically. For older processors, we would need to track
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
#include <sys/id_space.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module.h>
#include <sys/ontrap.h>
#include <sys/cpuvar.h>
#include <sys/x_call.h>
#include <sys/sensors.h>

#define	CORETEMP_MINOR_MIN	1
#define	CORETEMP_MINOR_MAX	INT32_MAX

typedef struct coretemp_core {
	list_node_t		ctc_link;
	id_t			ctc_core_minor;
	id_t			ctc_pkg_minor;
	enum cmi_hdl_class	ctc_class;
	uint_t			ctc_chip;
	uint_t			ctc_core;
	uint_t			ctc_strand;
	uint_t			ctc_tjmax;
	hrtime_t		ctc_last_read;
	uint64_t		ctc_core_status;
	uint64_t		ctc_core_intr;
	uint64_t		ctc_pkg_status;
	uint64_t		ctc_pkg_intr;
	uint64_t		ctc_invalid_reads;
	/* The following fields are derived from above */
	uint_t			ctc_temperature;
	uint_t			ctc_resolution;
	uint_t			ctc_pkg_temperature;
} coretemp_core_t;

typedef struct coretemp {
	dev_info_t	*coretemp_dip;
	id_space_t	*coretemp_ids;
	cpuset_t	*coretemp_cpuset;
	boolean_t	coretemp_pkg;
	kmutex_t	coretemp_mutex;
	list_t		coretemp_cores;
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
 * If we can't determine the junction temperature programatically, then we need
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

static coretemp_core_t *
coretemp_lookup_core(coretemp_t *ct, minor_t minor)
{
	coretemp_core_t *ctc;

	ASSERT(MUTEX_HELD(&ct->coretemp_mutex));

	if (minor < CORETEMP_MINOR_MIN || minor > CORETEMP_MINOR_MAX) {
		return (NULL);
	}

	for (ctc = list_head(&ct->coretemp_cores); ctc != NULL;
	    ctc = list_next(&ct->coretemp_cores, ctc)) {
		if (ctc->ctc_core_minor == (id_t)minor ||
		    (ctc->ctc_pkg_minor >= CORETEMP_MINOR_MIN &&
		    ctc->ctc_pkg_minor == (id_t)minor)) {
			return (ctc);
		}
	}

	return (NULL);
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
coretemp_calculate_tjmax(coretemp_t *ct, coretemp_core_t *ctc, cmi_hdl_t hdl)
{
	cmi_errno_t e;
	int err = 0;
	uint64_t val = 0;

	e = coretemp_rdmsr(ct, hdl, MSR_TEMPERATURE_TARGET, &val);
	if (e == CMI_SUCCESS && val != 0) {
		ctc->ctc_tjmax = MSR_TEMPERATURE_TARGET_TARGET(val);
	} else if (val == 0) {
		err = EINVAL;
	} else {
		err = coretemp_cmi_errno(e);
	}

	return (err);
}

static int
coretemp_read(coretemp_t *ct, coretemp_core_t *ctc, cmi_hdl_t hdl)
{
	cmi_errno_t e;
	int err = 0;
	uint64_t val = 0;

	ctc->ctc_last_read = gethrtime();

	e = coretemp_rdmsr(ct, hdl, MSR_IA32_THERM_STATUS, &val);
	if (e == CMI_SUCCESS) {
		ctc->ctc_core_status = val;
	} else {
		err = coretemp_cmi_errno(e);
		dev_err(ct->coretemp_dip, CE_WARN, "!failed to get core "
		    "thermal status on %u/%u: %d", ctc->ctc_chip, ctc->ctc_core,
		    err);
		return (err);
	}

	e = coretemp_rdmsr(ct, hdl, MSR_IA32_THERM_INTERRUPT, &val);
	if (e == CMI_SUCCESS) {
		ctc->ctc_core_intr = val;
	} else {
		err = coretemp_cmi_errno(e);
		dev_err(ct->coretemp_dip, CE_WARN, "!failed to get core "
		    "thermal interrupt on %u/%u: %d", ctc->ctc_chip,
		    ctc->ctc_core, err);
		return (err);
	}

	/*
	 * If the last read wasn't valid, then we should keep the current state.
	 */
	if ((ctc->ctc_core_status & IA32_THERM_STATUS_READ_VALID) != 0) {
		uint_t diff;
		diff = IA32_THERM_STATUS_READING(ctc->ctc_core_status);

		if (diff >= ctc->ctc_tjmax) {
			dev_err(ct->coretemp_dip, CE_WARN, "!found invalid "
			    "core temperature on %u/%u: readout: %u, Tjmax: "
			    "%u, raw: 0x%" PRIx64, ctc->ctc_chip,
			    ctc->ctc_core, diff, ctc->ctc_tjmax,
			    ctc->ctc_core_status);
			ctc->ctc_invalid_reads++;
		} else {
			ctc->ctc_temperature = ctc->ctc_tjmax - diff;
		}
	} else {
		ctc->ctc_invalid_reads++;
	}

	ctc->ctc_resolution =
	    IA32_THERM_STATUS_RESOLUTION(ctc->ctc_core_status);

	/*
	 * If we have package support and this is core zero, then update the
	 * package data.
	 */
	if (ct->coretemp_pkg && ctc->ctc_core == 0) {
		uint_t diff;

		e = coretemp_rdmsr(ct, hdl, MSR_IA32_PACKAGE_THERM_STATUS,
		    &val);
		if (e == CMI_SUCCESS) {
			ctc->ctc_pkg_status = val;
		} else {
			err = coretemp_cmi_errno(e);
			dev_err(ct->coretemp_dip, CE_WARN, "!failed to get "
			    "package thermal status on %u: %d", ctc->ctc_chip,
			    err);
			return (err);
		}

		e = coretemp_rdmsr(ct, hdl, MSR_IA32_PACKAGE_THERM_INTERRUPT,
		    &val);
		if (e == CMI_SUCCESS) {
			ctc->ctc_pkg_intr = val;
		} else {
			err = coretemp_cmi_errno(e);
			dev_err(ct->coretemp_dip, CE_WARN, "!failed to get "
			    "package thermal interrupt on %u: %d",
			    ctc->ctc_chip, err);
			return (err);
		}

		diff = IA32_PKG_THERM_STATUS_READING(ctc->ctc_pkg_status);
		if (diff >= ctc->ctc_tjmax) {
			dev_err(ct->coretemp_dip, CE_WARN, "!found invalid "
			    "package temperature on %u: readout: %u, tjmax: "
			    "%u, raw: 0x%" PRIx64, ctc->ctc_chip, diff,
			    ctc->ctc_tjmax, ctc->ctc_pkg_status);
			ctc->ctc_invalid_reads++;

		} else {
			ctc->ctc_pkg_temperature = ctc->ctc_tjmax - diff;
		}
	}

	return (0);
}

static int
coretemp_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	coretemp_t *ct = coretemp;

	if (crgetzoneid(credp) != GLOBAL_ZONEID || drv_priv(credp)) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Sanity check the minor
	 */
	mutex_enter(&ct->coretemp_mutex);
	if (coretemp_lookup_core(ct, getminor(*devp)) == NULL) {
		mutex_exit(&ct->coretemp_mutex);
		return (ENXIO);
	}
	mutex_exit(&ct->coretemp_mutex);

	return (0);
}

static int
coretemp_ioctl_kind(intptr_t arg, int mode)
{
	sensor_ioctl_kind_t kind;

	bzero(&kind, sizeof (kind));
	kind.sik_kind = SENSOR_KIND_TEMPERATURE;

	if (ddi_copyout((void *)&kind, (void *)arg, sizeof (kind),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
coretemp_ioctl_temp(coretemp_t *ct, minor_t minor, intptr_t arg, int mode)
{
	coretemp_core_t *ctc;
	hrtime_t diff;
	sensor_ioctl_temperature_t temp;

	bzero(&temp, sizeof (temp));

	mutex_enter(&ct->coretemp_mutex);
	ctc = coretemp_lookup_core(ct, minor);
	if (ctc == NULL) {
		mutex_exit(&ct->coretemp_mutex);
		return (ENXIO);
	}

	diff = NSEC2MSEC(gethrtime() - ctc->ctc_last_read);
	if (diff > 0 && diff > (hrtime_t)coretemp_cache_ms) {
		int ret;
		cmi_hdl_t hdl;

		if ((hdl = cmi_hdl_lookup(ctc->ctc_class, ctc->ctc_chip,
		    ctc->ctc_core, ctc->ctc_strand)) == NULL) {
			mutex_exit(&ct->coretemp_mutex);
			return (ENXIO);
		}
		ret = coretemp_read(ct, ctc, hdl);
		cmi_hdl_rele(hdl);
		if (ret != 0) {
			mutex_exit(&ct->coretemp_mutex);
			return (ret);
		}
	}

	temp.sit_unit = SENSOR_UNIT_CELSIUS;
	if ((id_t)minor == ctc->ctc_core_minor) {
		temp.sit_temp = ctc->ctc_temperature;
	} else {
		temp.sit_temp = ctc->ctc_pkg_temperature;
	}

	/*
	 * The resolution field is in whole units of degrees Celsius.
	 */
	temp.sit_gran = ctc->ctc_resolution;
	if (ctc->ctc_resolution > 1) {
		temp.sit_gran *= -1;
	}
	mutex_exit(&ct->coretemp_mutex);

	if (ddi_copyout(&temp, (void *)arg, sizeof (temp),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
coretemp_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	coretemp_t *ct = coretemp;

	if ((mode & FREAD) == 0) {
		return (EINVAL);
	}

	switch (cmd) {
	case SENSOR_IOCTL_TYPE:
		return (coretemp_ioctl_kind(arg, mode));
	case SENSOR_IOCTL_TEMPERATURE:
		return (coretemp_ioctl_temp(ct, getminor(dev), arg, mode));
	default:
		return (ENOTTY);
	}
}

/*
 * We don't really do any state tracking on close, so for now, just allow it to
 * always succeed.
 */
static int
coretemp_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static void
coretemp_fini_core(coretemp_t *ct, coretemp_core_t *ctc)
{
	if (ctc->ctc_core_minor > 0)
		id_free(ct->coretemp_ids, ctc->ctc_core_minor);
	if (ctc->ctc_pkg_minor > 0)
		id_free(ct->coretemp_ids, ctc->ctc_pkg_minor);
	kmem_free(ctc, sizeof (coretemp_core_t));
}

static void
coretemp_destroy(coretemp_t *ct)
{
	coretemp_core_t *ctc;

	ddi_remove_minor_node(ct->coretemp_dip, NULL);

	while ((ctc = list_remove_head(&ct->coretemp_cores)) != NULL) {
		coretemp_fini_core(ct, ctc);
	}
	list_destroy(&ct->coretemp_cores);

	if (ct->coretemp_cpuset != NULL) {
		cpuset_free(ct->coretemp_cpuset);
	}

	if (ct->coretemp_ids != NULL) {
		id_space_destroy(ct->coretemp_ids);
	}

	mutex_destroy(&ct->coretemp_mutex);
	kmem_free(ct, sizeof (coretemp_t));
}

static int
coretemp_init_core(cmi_hdl_t hdl, void *arg1, void *arg2, void *arg3)
{
	coretemp_t *ct = arg1;
	boolean_t *walkerr = arg2;
	coretemp_core_t *ctc;
	uint_t chip, core;
	int err;

	chip = cmi_hdl_chipid(hdl);
	core = cmi_hdl_coreid(hdl);

	/*
	 * The temperature sensor only exists on a per-core basis. Therefore we
	 * ignore any non-zero strand.
	 */
	if (cmi_hdl_strandid(hdl) != 0) {
		return (CMI_HDL_WALK_NEXT);
	}

	ctc = kmem_zalloc(sizeof (coretemp_core_t), KM_SLEEP);
	ctc->ctc_class = cmi_hdl_class(hdl);
	ctc->ctc_chip = chip;
	ctc->ctc_core = core;
	ctc->ctc_strand = 0;
	ctc->ctc_core_minor = id_alloc(ct->coretemp_ids);
	if (ct->coretemp_pkg && ctc->ctc_core == 0) {
		ctc->ctc_pkg_minor = id_alloc(ct->coretemp_ids);
	}

	if ((err = coretemp_calculate_tjmax(ct, ctc, hdl)) != 0) {
		dev_err(ct->coretemp_dip, CE_WARN,
		    "failed to read Tj Max on %u/%u: %d", chip, core, err);
		*walkerr = B_TRUE;
		coretemp_fini_core(ct, ctc);
		return (CMI_HDL_WALK_DONE);
	}

	if ((err = coretemp_read(ct, ctc, hdl)) != 0) {
		dev_err(ct->coretemp_dip, CE_WARN,
		    "failed to take initial temperature reading on %u/%u: %d",
		    chip, core, err);
		*walkerr = B_TRUE;
		coretemp_fini_core(ct, ctc);
		return (CMI_HDL_WALK_DONE);
	}

	list_insert_tail(&ct->coretemp_cores, ctc);

	return (CMI_HDL_WALK_NEXT);
}

static boolean_t
coretemp_create_minors(coretemp_t *ct)
{
	coretemp_core_t *ctc;

	for (ctc = list_head(&ct->coretemp_cores); ctc != NULL;
	    ctc = list_next(&ct->coretemp_cores, ctc)) {
		int ret;
		char buf[128];

		if (snprintf(buf, sizeof (buf), "chip%u.core%u", ctc->ctc_chip,
		    ctc->ctc_core) >= sizeof (buf)) {
			return (B_FALSE);
		}
		ret = ddi_create_minor_node(ct->coretemp_dip, buf, S_IFCHR,
		    ctc->ctc_core_minor, DDI_NT_SENSOR_TEMP_CPU, 0);
		if (ret != DDI_SUCCESS) {
			dev_err(ct->coretemp_dip, CE_WARN, "!failed to create "
			    "minor node %s", buf);
			return (B_FALSE);
		}

		if (ctc->ctc_core != 0)
			continue;

		if (snprintf(buf, sizeof (buf), "chip%u", ctc->ctc_chip) >=
		    sizeof (buf)) {
			return (B_FALSE);
		}

		ret = ddi_create_minor_node(ct->coretemp_dip, buf, S_IFCHR,
		    ctc->ctc_pkg_minor, DDI_NT_SENSOR_TEMP_CPU, 0);
		if (ret != DDI_SUCCESS) {
			dev_err(ct->coretemp_dip, CE_WARN, "!failed to create "
			    "minor node %s", buf);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static int
coretemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	boolean_t walkerr;
	coretemp_t *ct = NULL;

	if (cmd == DDI_RESUME) {
		/*
		 * Currently suspend and resume for this driver are nops.
		 */
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (coretemp != NULL) {
		return (DDI_FAILURE);
	}

	ct = kmem_zalloc(sizeof (coretemp_t), KM_SLEEP);
	ct->coretemp_dip = dip;
	ct->coretemp_pkg = is_x86_feature(x86_featureset, X86FSET_PKG_THERMAL);
	list_create(&ct->coretemp_cores, sizeof (coretemp_core_t),
	    offsetof(coretemp_core_t, ctc_link));
	mutex_init(&ct->coretemp_mutex, NULL, MUTEX_DRIVER, NULL);
	ct->coretemp_cpuset = cpuset_alloc(KM_SLEEP);
	if ((ct->coretemp_ids = id_space_create("coretemp_minors", 1,
	    INT32_MAX)) == NULL) {
		goto fail;
	}

	mutex_enter(&ct->coretemp_mutex);
	walkerr = B_FALSE;
	cmi_hdl_walk(coretemp_init_core, ct, &walkerr, NULL);

	if (walkerr) {
		mutex_exit(&ct->coretemp_mutex);
		goto fail;
	}

	if (!coretemp_create_minors(ct)) {
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
coretemp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	int ret;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = coretemp->coretemp_dip;
		ret = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)0;
		ret = DDI_SUCCESS;
		break;
	default:
		ret = DDI_FAILURE;
		break;
	}

	return (ret);
}

static int
coretemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	coretemp_t *ct;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (coretemp == NULL) {
		return (DDI_FAILURE);
	}

	ct = coretemp;
	coretemp = NULL;
	coretemp_destroy(ct);

	return (DDI_SUCCESS);
}

static struct cb_ops coretemp_cb_ops = {
	.cb_open = coretemp_open,
	.cb_close = coretemp_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = coretemp_ioctl,
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

static struct dev_ops coretemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = coretemp_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = coretemp_attach,
	.devo_detach = coretemp_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &coretemp_cb_ops
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
