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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This implements a temperature sensor for AMD Zen family products that rely
 * upon the SMN framework for getting temperature information.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>
#include <sys/sensors.h>
#include <sys/sysmacros.h>
#include <sys/amdzen/smn.h>
#include <amdzen_client.h>

/*
 * The following are register offsets and the meaning of their bits related to
 * temperature. These addresses reside in the System Management Network which is
 * accessed through the northbridge. They are not addresses in PCI configuration
 * space.
 */
#define	SMN_SMU_THERMAL_CURTEMP			SMN_MAKE_REG(0x00059800)
#define	SMN_SMU_THERMAL_CURTEMP_TEMPERATURE(x)	((x) >> 21)
#define	SMN_SMU_THERMAL_CURTEMP_RANGE_SEL		(1 << 19)

#define	SMN_SMU_THERMAL_CURTEMP_RANGE_ADJ		(-49)
#define	SMN_SMU_THERMAL_CURTEMP_DECIMAL_BITS		3
#define	SMN_SMU_THERMAL_CURTEMP_BITS_MASK		0x7

/*
 * The temperature sensor in Family 17 is measured in terms of 0.125 C steps.
 */
#define	SMN_THERMAL_GRANULARITY	8

typedef enum {
	SMNTEMP_F_MUTEX	= 1 << 0
} smntemp_flags_t;

typedef struct {
	uint_t stt_dfno;
	id_t stt_ksensor;
	struct smntemp *stt_smn;
	smntemp_flags_t stt_flags;
	kmutex_t stt_mutex;
	hrtime_t stt_last_read;
	uint32_t stt_reg;
	int64_t stt_temp;
} smntemp_temp_t;

typedef struct smntemp {
	dev_info_t *smn_dip;
	uint_t smn_ntemps;
	int smn_offset;
	smntemp_temp_t *smn_temps;
} smntemp_t;

static smntemp_t smntemp_data;

/*
 * AMD processors report a control temperature (called Tctl) which may be
 * different from the junction temperature, which is the value that is actually
 * measured from the die (sometimes called Tdie or Tjct). This is done so that
 * socket-based environmental monitoring can be consistent from a platform
 * perspective, but doesn't help us. Unfortunately, these values aren't in
 * datasheets that we can find, but have been documented partially in a series
 * of blog posts by AMD when discussing their 'Ryzen Master' monitoring software
 * for Windows.
 *
 * The brand strings below may contain partial matches such in the Threadripper
 * cases so we can match the entire family of processors. The offset value is
 * the quantity in degrees that we should adjust Tctl to reach Tdie.
 */
typedef struct {
	const char	*sto_brand;
	uint_t		sto_family;
	int		sto_off;
} smntemp_offset_t;

static const smntemp_offset_t smntemp_offsets[] = {
	{ "AMD Ryzen 5 1600X", 0x17, -20 },
	{ "AMD Ryzen 7 1700X", 0x17, -20 },
	{ "AMD Ryzen 7 1800X", 0x17, -20 },
	{ "AMD Ryzen 7 2700X", 0x17, -10 },
	{ "AMD Ryzen Threadripper 19", 0x17, -27 },
	{ "AMD Ryzen Threadripper 29", 0x17, -27 },
	{ NULL }
};

static int
smntemp_temp_update(smntemp_t *smn, smntemp_temp_t *stt)
{
	int ret;
	uint32_t reg;
	int64_t raw, decimal;

	ASSERT(MUTEX_HELD((&stt->stt_mutex)));

	if ((ret = amdzen_c_smn_read32(stt->stt_dfno, SMN_SMU_THERMAL_CURTEMP,
	    &reg)) != 0) {
		return (ret);
	}

	stt->stt_last_read = gethrtime();
	stt->stt_reg = reg;
	raw = SMN_SMU_THERMAL_CURTEMP_TEMPERATURE(reg) >>
	    SMN_SMU_THERMAL_CURTEMP_DECIMAL_BITS;
	decimal = SMN_SMU_THERMAL_CURTEMP_TEMPERATURE(reg) &
	    SMN_SMU_THERMAL_CURTEMP_BITS_MASK;
	if ((reg & SMN_SMU_THERMAL_CURTEMP_RANGE_SEL) != 0) {
		raw += SMN_SMU_THERMAL_CURTEMP_RANGE_ADJ;
	}
	raw += smn->smn_offset;
	stt->stt_temp = raw << SMN_SMU_THERMAL_CURTEMP_DECIMAL_BITS;
	stt->stt_temp += decimal;

	return (0);
}

static int
smntemp_temp_read(void *arg, sensor_ioctl_scalar_t *temp)
{
	int ret;
	smntemp_temp_t *stt = arg;
	smntemp_t *smn = stt->stt_smn;

	mutex_enter(&stt->stt_mutex);
	if ((ret = smntemp_temp_update(smn, stt)) != 0) {
		mutex_exit(&stt->stt_mutex);
		return (ret);
	}

	temp->sis_unit = SENSOR_UNIT_CELSIUS;
	temp->sis_value = stt->stt_temp;
	temp->sis_gran = SMN_THERMAL_GRANULARITY;
	mutex_exit(&stt->stt_mutex);

	return (0);
}

static const ksensor_ops_t smntemp_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = smntemp_temp_read
};

static void
smntemp_cleanup(smntemp_t *smn)
{
	if (smn->smn_temps != NULL) {
		uint_t i;

		(void) ksensor_remove(smn->smn_dip, KSENSOR_ALL_IDS);
		for (i = 0; i < smn->smn_ntemps; i++) {
			if ((smn->smn_temps[i].stt_flags & SMNTEMP_F_MUTEX) !=
			    0) {
				mutex_destroy(&smn->smn_temps[i].stt_mutex);
				smn->smn_temps[i].stt_flags &= ~SMNTEMP_F_MUTEX;
			}
		}
		kmem_free(smn->smn_temps, sizeof (smntemp_temp_t) *
		    smn->smn_ntemps);
		smn->smn_temps = NULL;
		smn->smn_ntemps = 0;
	}

	if (smn->smn_dip != NULL) {
		ddi_remove_minor_node(smn->smn_dip, NULL);
		ddi_set_driver_private(smn->smn_dip, NULL);
		smn->smn_dip = NULL;
	}
}

static boolean_t
smntemp_find_offset(smntemp_t *smn)
{
	uint_t i, family;
	char buf[256];

	if (cpuid_getbrandstr(CPU, buf, sizeof (buf)) >= sizeof (buf)) {
		dev_err(smn->smn_dip, CE_WARN, "!failed to read processor "
		    "brand string, brand larger than internal buffer");
		return (B_FALSE);
	}

	family = cpuid_getfamily(CPU);

	for (i = 0; i < ARRAY_SIZE(smntemp_offsets); i++) {
		if (family != smntemp_offsets[i].sto_family)
			continue;
		if (strncmp(buf, smntemp_offsets[i].sto_brand,
		    strlen(smntemp_offsets[i].sto_brand)) == 0) {
			smn->smn_offset = smntemp_offsets[i].sto_off;
			break;
		}
	}

	return (B_TRUE);
}

static int
smntemp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint_t i;
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
	ddi_set_driver_private(dip, smntemp);

	if (!smntemp_find_offset(smntemp)) {
		goto err;
	}

	smntemp->smn_ntemps = amdzen_c_df_count();
	if (smntemp->smn_ntemps == 0) {
		dev_err(dip, CE_WARN, "!found zero DFs, can't attach smntemp");
		goto err;
	}
	smntemp->smn_temps = kmem_zalloc(sizeof (smntemp_temp_t) *
	    smntemp->smn_ntemps, KM_SLEEP);
	for (i = 0; i < smntemp->smn_ntemps; i++) {
		int ret;
		char buf[128];

		smntemp->smn_temps[i].stt_smn = smntemp;
		smntemp->smn_temps[i].stt_dfno = i;
		mutex_init(&smntemp->smn_temps[i].stt_mutex, NULL, MUTEX_DRIVER,
		    NULL);
		smntemp->smn_temps[i].stt_flags |= SMNTEMP_F_MUTEX;

		if (snprintf(buf, sizeof (buf), "procnode.%u", i) >=
		    sizeof (buf)) {
			dev_err(dip, CE_WARN, "!unexpected buffer name overrun "
			    "assembling temperature minor %u", i);
			goto err;
		}

		if ((ret = ksensor_create(dip, &smntemp_temp_ops,
		    &smntemp->smn_temps[i], buf, DDI_NT_SENSOR_TEMP_CPU,
		    &smntemp->smn_temps[i].stt_ksensor)) != 0) {
			dev_err(dip, CE_WARN, "!failed to create sensor %s: %d",
			    buf, ret);
			goto err;
		}
	}

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
