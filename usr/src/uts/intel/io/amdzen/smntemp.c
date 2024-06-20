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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This implements a temperature sensor for AMD Zen family products that rely
 * upon the SMN framework for getting temperature information.
 *
 * ----------
 * Background
 * ----------
 *
 * When we think of temperature sensors, we generally think of an external or
 * embedded diode that measures a value in Celsius or Fahrenheit with some
 * accuracy and resolution. The most common forms of these are called Tj and
 * Tcase for the junction and case temperature. The junction temperature is the
 * one that comes up most inside of devices like a CPU as it looks at the
 * temperature of the actual transistors inside the part. On AMD, these Tj
 * sensors are often called Tdie, because they represent the temperature of a
 * particular die.
 *
 * While this is represented as a single number, there are often numerous diodes
 * that have some amount of post-processing applied to them from different
 * sources that are used to combine and make up this number.
 *
 * While AMD has various Tdie sensors (we'll get back to them later), the
 * primary thing that the CPU exposes and is used for overall health is quite
 * different and called Tctl, the control temperature. Unlike normal sensors
 * Tctl is not a measure of temperature in a traditional sense and is instead
 * used as part of the processor's control loop and is a unitless quantity that
 * ranges between 0 and 100. There are two notable thresholds:
 *
 * 1) At a value of 95, the CPU will begin internal thermal throttling.
 * 2) At a value of 100, after some period of time the CPU will shutdown. This
 * likely involves asserting the THERMTRIP_L signal, which is a dedicated pin on
 * the CPU socket.
 *
 * It's notable that this value is calculated and has various slew rates
 * applied. While for a few Zen 1 ThreadRipper CPUs, there was a suggestion from
 * the Ryzen Master software that there was a straightforward relationship
 * between Tctl and Tdie, we've found that this isn't quite true in practice and
 * that it's not helpful to try to convert Tctl to Tdie. There is no simple way
 * to do so. As such, we don't pretend to do so anymore, though we did in an
 * earlier life of this driver. The addition of the various CCD-specific sensors
 * is an aid here.
 *
 * -------------------------------------
 * System Management Network and Sensors
 * -------------------------------------
 *
 * The SMN (system management network) exists on a per-die basis. That is there
 * is one for each I/O die and connected devices in the system. In the context
 * of Zen 2+, there is usually only a single SMN network per socket. In Zen 1,
 * there was one for each Zepplin die, which combined both the core complexes
 * and I/O. See uts/intel/os/cpuid.c for more background here.
 *
 * As a result of this split there are two different groups of sensors that
 * exist within a single die:
 *
 * 1) SMU::THM::THM_TCON_CUR_TMP provides Tctl for the overall I/O die and
 * connected components. This is the unitless measurement mentioned above. The
 * aforementioned register is a shadow of whatever the die actually maintains
 * and is read-only for all intents and purposes for us due to its nature as a
 * shadow, despite what the PPR says.
 *
 * 2) SMU::THM::THM_DIEx_TEMP provides Tdie for a single die. Unlike Tctl, this
 * is a valid measurement in degrees Celsius. Notably, this is also a shadow
 * register that is updated by the SMU, while each die has its own underlying
 * diodes and control temperature calculations that are performed. There are
 * generally a fixed number of these die sensors at given offsets on the CPU.
 * These are sourced by the thermal monitor and have a valid bit. The general
 * assumption is that there is a 1:1 mapping on CPUs and APUs to CCDs.
 *
 * -------------------
 * Sensor Organization
 * -------------------
 *
 * The driver uses DDI_NT_SENSOR_TEMP_CPU, which will put us in the
 * /dev/sensors/cpu directory. Each DF maps to the cpuid.c procnode concept. The
 * Tctl sensor is named 'procnode.%u'. The Tdie sensors are named
 * 'procnode.%u:die.%u'. This allows us to have them exist on a per-DF basis.
 * The expectation is that consumers who care will make the assumption that
 * these are CCD-specific sensors rather than this driver itself.
 *
 * To represent this, the driver, which is rooted in the smntemp_t structure,
 * the smntemp_data global, contains a number of smntemp_df_t structures. One
 * for each df that exists. Each DF contains one smntemp_temp_t structure that
 * represents Tctl and a variable number of Tdie sensors based on how many the
 * SoC supports.
 *
 * Because of our desire not to assume that these are specifically CCD sensors
 * here (though they realistically speaking are), we don't try iterating the
 * CCDs as a way to scope which Tdie sensors exist and instead leverage the
 * valid bit that they have to determine which ksensors to create.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/stdbool.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>
#include <sys/sensors.h>
#include <sys/sysmacros.h>
#include <sys/amdzen/smn.h>
#include <sys/amdzen/thm.h>
#include <amdzen_client.h>

typedef enum {
	SMNTEMP_F_MUTEX	= 1 << 0,
	SMNTEMP_F_VALID = 1 << 1
} smntemp_flags_t;

typedef enum {
	SMNTEMP_K_TCTL = 1,
	SMNTEMP_K_TDIE
} smntemp_kind_t;

typedef struct smntemp_temp smntemp_temp_t;
typedef struct smntemp_df smntemp_df_t;
typedef struct smntemp smntemp_t;

/*
 * This represents the per-temperature data that we keep around per exposed
 * ksensor.
 */
struct smntemp_temp {
	smntemp_kind_t stt_kind;
	smntemp_df_t *stt_df;
	smn_reg_t stt_reg;
	smntemp_flags_t stt_flags;
	id_t stt_ksensor;
	kmutex_t stt_mutex;
	hrtime_t stt_last_read;
	uint32_t stt_raw;
	int64_t stt_temp;
};

/*
 * This represents a single DF in the system and contains all of the temperature
 * sensors for it, both its Tctl and however many Tdie exist.
 */
struct smntemp_df {
	uint32_t sd_dfno;
	smntemp_temp_t sd_tctl;
	uint32_t sd_nccd;
	uint32_t sd_nccd_valid;
	smntemp_temp_t *sd_tdie;
};

/*
 * Primary driver state structure.
 */
struct smntemp {
	dev_info_t *smn_dip;
	x86_processor_family_t smn_fam;
	uint_t smn_ndf;
	smntemp_df_t *smn_df;
};

static smntemp_t smntemp_data;

/*
 * Determine if the "temperature" requires adjustment in some form. Tdie is
 * always adjusted. Tctl may in two different circumstances:
 *
 * (1) If the range bit, 'THM_CURTEMP_GET_RANGE' is set.
 * (2) if the mode is set to r/w. While the former is made much more explicit,
 * the latter is something that AMD has suggested, but hasn't been formally
 * documented in the PPR. However, experimentally this has proven to hold.
 */
static int64_t
smntemp_temp_adjust(smntemp_temp_t *stt)
{
	if (stt->stt_kind == SMNTEMP_K_TDIE) {
		return (THM_CURTEMP_RANGE_ADJ);
	}

	if (THM_CURTEMP_GET_RANGE(stt->stt_raw) == THM_CURTEMP_RANGE_N49_206 ||
	    THM_CURTEMP_GET_TJ_SEL(stt->stt_raw) == THM_CURTEMP_TJ_SEL_RW) {
		return (THM_CURTEMP_RANGE_ADJ);
	}

	return (0);
}

static int
smntemp_temp_update(smntemp_temp_t *stt)
{
	int ret;
	uint32_t reg;
	int64_t raw, decimal;

	ASSERT(MUTEX_HELD((&stt->stt_mutex)));

	if ((ret = amdzen_c_smn_read(stt->stt_df->sd_dfno, stt->stt_reg,
	    &reg)) != 0) {
		return (ret);
	}

	stt->stt_last_read = gethrtime();
	stt->stt_raw = reg;
	if (stt->stt_kind == SMNTEMP_K_TCTL) {
		raw = THM_CURTEMP_GET_TEMP(reg);
	} else {
		raw = THM_DIE_GET_TEMP(reg);
	}

	decimal = raw & THM_CURTEMP_TEMP_DEC_MASK;
	raw = raw >> THM_CURTEMP_TEMP_DEC_BITS;
	raw += smntemp_temp_adjust(stt);

	stt->stt_temp = raw << THM_CURTEMP_TEMP_DEC_BITS;
	stt->stt_temp += decimal;

	return (0);
}

static uint32_t
smntemp_temp_unit(smntemp_temp_t *stt)
{
	ASSERT(MUTEX_HELD(&stt->stt_mutex));

	if (stt->stt_kind == SMNTEMP_K_TDIE) {
		return (SENSOR_UNIT_CELSIUS);
	} else if (THM_CURTEMP_GET_TJ_SEL(stt->stt_raw) ==
	    THM_CURTEMP_TJ_SEL_TJ) {
		return (SENSOR_UNIT_CELSIUS);
	} else {
		return (SENSOR_UNIT_NONE);
	}
}

static int
smntemp_temp_read(void *arg, sensor_ioctl_scalar_t *temp)
{
	int ret;
	smntemp_temp_t *stt = arg;

	mutex_enter(&stt->stt_mutex);
	if ((ret = smntemp_temp_update(stt)) != 0) {
		mutex_exit(&stt->stt_mutex);
		return (ret);
	}

	temp->sis_unit = smntemp_temp_unit(stt);
	temp->sis_value = stt->stt_temp;
	/* This is the same between Tctl and Tdie */
	temp->sis_gran = THM_CURTEMP_TEMP_DEC_GRAN;
	mutex_exit(&stt->stt_mutex);

	return (0);
}

/*
 * Because Tctl is usually a control temperature, but isn't guaranteed, we
 * cannot use a stock ksensor function and must implement this ourselves.
 */
static int
smntemp_temp_kind(void *arg, sensor_ioctl_kind_t *kind)
{
	smntemp_temp_t *stt = arg;

	if (stt->stt_kind == SMNTEMP_K_TDIE) {
		kind->sik_kind = SENSOR_KIND_TEMPERATURE;
		return (0);
	}

	mutex_enter(&stt->stt_mutex);
	if (stt->stt_raw == 0) {
		int ret = smntemp_temp_update(stt);
		if (ret != 0) {
			mutex_exit(&stt->stt_mutex);
			return (ret);
		}
	}

	if (THM_CURTEMP_GET_TJ_SEL(stt->stt_raw) == THM_CURTEMP_TJ_SEL_TJ) {
		kind->sik_kind = SENSOR_KIND_TEMPERATURE;
	} else {
		kind->sik_kind = SENSOR_KIND_SYNTHETIC;
		kind->sik_derive = SENSOR_KIND_TEMPERATURE;
	}

	mutex_exit(&stt->stt_mutex);
	return (0);
}

static const ksensor_ops_t smntemp_temp_ops = {
	.kso_kind = smntemp_temp_kind,
	.kso_scalar = smntemp_temp_read
};

static bool
smntemp_create_tdie(smntemp_t *smn, smntemp_df_t *df, smntemp_temp_t *temp,
    uint32_t ccdno)
{
	int ret;
	uint32_t val;
	char buf[128];

	temp->stt_kind = SMNTEMP_K_TDIE;
	temp->stt_df = df;
	temp->stt_reg = THM_DIE(ccdno, smn->smn_fam);
	mutex_init(&temp->stt_mutex, NULL, MUTEX_DRIVER, NULL);
	temp->stt_flags = SMNTEMP_F_MUTEX;

	/*
	 * Tdie sensors have a valid bit that we need to check before we
	 * register with the ksensor framework.
	 */
	if (snprintf(buf, sizeof (buf), "procnode.%u.die.%u", df->sd_dfno,
	    ccdno) >= sizeof (buf)) {
		dev_err(smn->smn_dip, CE_WARN, "!unexpected buffer name "
		    "overrun assembling DF/CCD %u/%u Tdie", df->sd_dfno,
		    ccdno);
		return (false);
	}

	if ((ret = amdzen_c_smn_read(temp->stt_df->sd_dfno, temp->stt_reg,
	    &val)) != 0) {
		dev_err(smn->smn_dip, CE_WARN, "!unexpected SMN read failure "
		    "reading DF/CCD %u/%u Tdie: %d", df->sd_dfno, ccdno, ret);
		return (false);
	}

	/*
	 * Tdie sensors have a valid bit in them. We more or less assume that
	 * this valid bit is set by the SMU early in life and remains valid
	 * throughout a given system boot.
	 */
	if (THM_DIE_GET_VALID(val) == 0) {
		return (true);
	}

	df->sd_nccd_valid++;
	temp->stt_flags |= SMNTEMP_F_VALID;

	if ((ret = ksensor_create(smn->smn_dip, &smntemp_temp_ops, temp, buf,
	    DDI_NT_SENSOR_TEMP_CPU, &temp->stt_ksensor)) != 0) {
		dev_err(smn->smn_dip, CE_WARN, "!failed to create sensor %s: "
		    "%d", buf, ret);
		return (false);
	}

	return (true);
}

static bool
smntemp_create_tctl(smntemp_t *smn, smntemp_df_t *df, smntemp_temp_t *temp)
{
	int ret;
	char buf[128];

	temp->stt_kind = SMNTEMP_K_TCTL;
	temp->stt_df = df;
	temp->stt_reg = THM_CURTEMP;
	mutex_init(&temp->stt_mutex, NULL, MUTEX_DRIVER, NULL);
	temp->stt_flags = SMNTEMP_F_VALID | SMNTEMP_F_MUTEX;

	if (snprintf(buf, sizeof (buf), "procnode.%u", df->sd_dfno) >=
	    sizeof (buf)) {
		dev_err(smn->smn_dip, CE_WARN, "!unexpected buffer name "
		    "overrun assembling DF %u Tctl", df->sd_dfno);
		return (false);
	}

	if ((ret = ksensor_create(smn->smn_dip, &smntemp_temp_ops, temp, buf,
	    DDI_NT_SENSOR_TEMP_CPU, &temp->stt_ksensor)) != 0) {
		dev_err(smn->smn_dip, CE_WARN, "!failed to create sensor %s: "
		    "%d", buf, ret);
		return (false);
	}

	return (true);
}

static void
smntemp_cleanup_temp(smntemp_temp_t *temp)
{
	temp->stt_flags &= ~SMNTEMP_F_VALID;
	if ((temp->stt_flags & SMNTEMP_F_MUTEX) != 0) {
		mutex_destroy(&temp->stt_mutex);
		temp->stt_flags &= ~SMNTEMP_F_MUTEX;
	}
	ASSERT0(temp->stt_flags);
}

static void
smntemp_cleanup(smntemp_t *smn)
{
	(void) ksensor_remove(smn->smn_dip, KSENSOR_ALL_IDS);

	for (uint32_t dfno = 0; dfno < smn->smn_ndf; dfno++) {
		smntemp_df_t *df = &smn->smn_df[dfno];
		smntemp_cleanup_temp(&df->sd_tctl);
		for (uint32_t ccdno = 0; ccdno < df->sd_nccd; ccdno++) {
			smntemp_cleanup_temp(&df->sd_tdie[ccdno]);
		}

		if (df->sd_nccd > 0) {
			kmem_free(df->sd_tdie, df->sd_nccd *
			    sizeof (smntemp_temp_t));
			df->sd_nccd = 0;
			df->sd_tdie = NULL;
		}
	}
	if (smn->smn_ndf > 0) {
		kmem_free(smn->smn_df, sizeof (smntemp_df_t) * smn->smn_ndf);
		smn->smn_ndf = 0;
		smn->smn_df = NULL;
	}

	if (smn->smn_dip != NULL) {
		ddi_remove_minor_node(smn->smn_dip, NULL);
		ddi_set_driver_private(smn->smn_dip, NULL);
		smn->smn_dip = NULL;
	}
}

static int
smntemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	smntemp_t *smntemp = &smntemp_data;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (smntemp->smn_dip != NULL) {
		dev_err(dip, CE_WARN, "!smntemp already attached");
		return (DDI_FAILURE);
	}
	smntemp->smn_dip = dip;
	smntemp->smn_fam = chiprev_family(cpuid_getchiprev(CPU));

	/*
	 * First account for each actual DF instance. Then determine the number
	 * of CCD entries we need to care about per SoC.
	 */
	smntemp->smn_ndf = amdzen_c_df_count();
	if (smntemp->smn_ndf == 0) {
		dev_err(dip, CE_WARN, "!found zero DFs, can't attach smntemp");
		goto err;
	}
	smntemp->smn_df = kmem_zalloc(sizeof (smntemp_df_t) * smntemp->smn_ndf,
	    KM_SLEEP);
	for (uint32_t dfno = 0; dfno < smntemp->smn_ndf; dfno++) {
		smntemp_df_t *df = &smntemp->smn_df[dfno];
		df->sd_dfno = dfno;
		df->sd_nccd = THM_DIE_MAX_UNITS(smntemp->smn_fam);

		if (!smntemp_create_tctl(smntemp, df, &df->sd_tctl)) {
			goto err;
		}

		if (df->sd_nccd > 0) {
			df->sd_tdie = kmem_zalloc(sizeof (smntemp_temp_t) *
			    df->sd_nccd, KM_SLEEP);
		}

		for (uint32_t i = 0; i < df->sd_nccd; i++) {
			if (!smntemp_create_tdie(smntemp, df,
			    &df->sd_tdie[i], i)) {
				goto err;
			}
		}
	}

	ddi_set_driver_private(dip, smntemp);
	return (DDI_SUCCESS);

err:
	smntemp_cleanup(smntemp);
	return (DDI_FAILURE);
}

static int
smntemp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	smntemp_t *smntemp = &smntemp_data;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (smntemp->smn_dip == NULL) {
		dev_err(smntemp->smn_dip, CE_WARN, "!asked to detach smn "
		    "instance %d that was never attached",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	smntemp_cleanup(smntemp);
	return (DDI_SUCCESS);
}

static struct dev_ops smntemp_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nodev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = smntemp_attach,
	.devo_detach = smntemp_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
};

static struct modldrv smntemp_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD SMN Temperature Driver",
	.drv_dev_ops = &smntemp_dev_ops
};

static struct modlinkage smntemp_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &smntemp_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&smntemp_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&smntemp_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&smntemp_modlinkage));
}
