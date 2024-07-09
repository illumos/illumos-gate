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
 * Copyright 2024 Oxide Computer Company
 */

#include "nvme_reg.h"
#include "nvme_var.h"

static void
nvme_stat_device_cleanup(nvme_t *nvme)
{
	if (nvme->n_device_kstat != NULL) {
		kstat_delete(nvme->n_device_kstat);
		nvme->n_device_kstat = NULL;
	}
}

static boolean_t
nvme_stat_device_init(nvme_t *nvme)
{
	kstat_t *ksp = kstat_create(NVME_MODULE_NAME,
	    ddi_get_instance(nvme->n_dip), "device", "controller",
	    KSTAT_TYPE_NAMED,
	    sizeof (nvme_device_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	nvme_device_stat_t *nds = &nvme->n_device_stat;

	if (ksp == NULL) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to create device kstats");
		return (false);
	}

	nvme->n_device_kstat = ksp;
	ksp->ks_data = nds;

#define	STAT_INIT(stat) \
	kstat_named_init(&nds->nds_ ## stat, #stat, KSTAT_DATA_UINT64)

	/* Errors detected by driver */
	STAT_INIT(dma_bind_err);
	STAT_INIT(abort_timeout);
	STAT_INIT(abort_failed);
	STAT_INIT(abort_successful);
	STAT_INIT(abort_unsuccessful);
	STAT_INIT(cmd_timeout);
	STAT_INIT(wrong_logpage);
	STAT_INIT(unknown_logpage);
	STAT_INIT(too_many_cookies);
	STAT_INIT(unknown_cid);

	/* Errors detected by hardware */
	STAT_INIT(inv_cmd_err);
	STAT_INIT(inv_field_err);
	STAT_INIT(inv_nsfmt_err);
	STAT_INIT(data_xfr_err);
	STAT_INIT(internal_err);
	STAT_INIT(abort_rq_err);
	STAT_INIT(abort_pwrloss_err);
	STAT_INIT(abort_sq_del);
	STAT_INIT(nvm_cap_exc);
	STAT_INIT(nvm_ns_notrdy);
	STAT_INIT(nvm_ns_formatting);
	STAT_INIT(inv_cq_err);
	STAT_INIT(inv_qid_err);
	STAT_INIT(max_qsz_exc);
	STAT_INIT(inv_int_vect);
	STAT_INIT(inv_log_page);
	STAT_INIT(inv_format);
	STAT_INIT(inv_q_del);
	STAT_INIT(cnfl_attr);
	STAT_INIT(inv_prot);
	STAT_INIT(readonly);
	STAT_INIT(inv_fwslot);
	STAT_INIT(inv_fwimg);
	STAT_INIT(fwact_creset);
	STAT_INIT(fwact_nssr);
	STAT_INIT(fwact_reset);
	STAT_INIT(fwact_mtfa);
	STAT_INIT(fwact_prohibited);
	STAT_INIT(fw_overlap);

	/* Errors reported by asynchronous events */
	STAT_INIT(diagfail_event);
	STAT_INIT(persistent_event);
	STAT_INIT(transient_event);
	STAT_INIT(fw_load_event);
	STAT_INIT(reliability_event);
	STAT_INIT(temperature_event);
	STAT_INIT(spare_event);
	STAT_INIT(vendor_event);
	STAT_INIT(notice_event);
	STAT_INIT(unknown_event);

#undef STAT_INIT

	kstat_install(nvme->n_device_kstat);
	return (true);
}

static void
nvme_stat_admin_cleanup(nvme_t *nvme)
{
	if (nvme->n_admin_kstat != NULL) {
		kstat_delete(nvme->n_admin_kstat);
		nvme->n_admin_kstat = NULL;
		mutex_destroy(&nvme->n_admin_stat_mutex);
	}
}

static boolean_t
nvme_stat_admin_init(nvme_t *nvme)
{
	kstat_t *ksp = kstat_create(NVME_MODULE_NAME,
	    ddi_get_instance(nvme->n_dip), "admin", "controller",
	    KSTAT_TYPE_NAMED,
	    sizeof (nvme_admin_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	nvme_admin_stat_t *nas = &nvme->n_admin_stat;

	if (ksp == NULL) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to create admin kstats");
		return (false);
	}

	nvme->n_admin_kstat = ksp;
	ksp->ks_data = nas;
	mutex_init(&nvme->n_admin_stat_mutex, NULL, MUTEX_DRIVER, NULL);

#define	STAT_INIT_ONE(stat, index, postfix) \
	kstat_named_init(&nas->nas_ ## stat[index], #stat postfix, \
	KSTAT_DATA_UINT64)

#define	STAT_INIT(stat) \
	do { \
		STAT_INIT_ONE(stat, NAS_CNT, "_cnt"); \
		STAT_INIT_ONE(stat, NAS_AVG, "_avg"); \
		STAT_INIT_ONE(stat, NAS_MAX, "_max"); \
	} while (0)

	STAT_INIT(getlogpage);
	STAT_INIT(identify);
	STAT_INIT(abort);
	STAT_INIT(fwactivate);
	STAT_INIT(fwimgload);
	STAT_INIT(nsformat);
	STAT_INIT(vendor);
	STAT_INIT(other);

#undef STAT_INIT
#undef STAT_INIT_ONE

	kstat_install(nvme->n_admin_kstat);
	return (true);
}

void
nvme_stat_cleanup(nvme_t *nvme)
{
	nvme_stat_device_cleanup(nvme);
	nvme_stat_admin_cleanup(nvme);
}

boolean_t
nvme_stat_init(nvme_t *nvme)
{
	if (!nvme_stat_device_init(nvme) || !nvme_stat_admin_init(nvme)) {
		nvme_stat_cleanup(nvme);
		return (B_FALSE);
	}
	return (B_TRUE);
}

void
nvme_admin_stat_cmd(nvme_t *nvme, nvme_cmd_t *cmd)
{
	hrtime_t t;
	uint64_t cnt, avg;
	kstat_named_t *data, *cntd, *avgd, *maxd;

	switch (cmd->nc_sqe.sqe_opc) {
	case NVME_OPC_DELETE_SQUEUE:
	case NVME_OPC_CREATE_SQUEUE:
	case NVME_OPC_DELETE_CQUEUE:
	case NVME_OPC_CREATE_CQUEUE:
		/* No statistics are kept for these opcodes */
		return;
	case NVME_OPC_GET_LOG_PAGE:
		data = nvme->n_admin_stat.nas_getlogpage;
		break;
	case NVME_OPC_IDENTIFY:
		data = nvme->n_admin_stat.nas_identify;
		break;
	case NVME_OPC_ABORT:
		data = nvme->n_admin_stat.nas_abort;
		break;
	case NVME_OPC_FW_ACTIVATE:
		data = nvme->n_admin_stat.nas_fwactivate;
		break;
	case NVME_OPC_FW_IMAGE_LOAD:
		data = nvme->n_admin_stat.nas_fwimgload;
		break;
	case NVME_OPC_NVM_FORMAT:
		data = nvme->n_admin_stat.nas_nsformat;
		break;
	case NVME_OPC_VENDOR_LOW ... NVME_OPC_VENDOR_HIGH:
		data = nvme->n_admin_stat.nas_vendor;
		break;
	default:
		data = nvme->n_admin_stat.nas_other;
		break;
	}

	t = gethrtime() - cmd->nc_submit_ts;

	cntd = &data[NAS_CNT];
	avgd = &data[NAS_AVG];
	maxd = &data[NAS_MAX];

	mutex_enter(&nvme->n_admin_stat_mutex);
	cnt = cntd->value.ui64;
	avg = avgd->value.ui64;

	/*
	 * Update the cumulative rolling average.
	 * Since `t` and `avg` are orders of magnitude greater than `cnt` it
	 * is sufficient to directly adjust the current average towards the
	 * new value.
	 */
	if (t > avg)
		avg += (t - avg) / (cnt + 1);
	else
		avg -= (avg - t) / (cnt + 1);
	cntd->value.ui64++;
	avgd->value.ui64 = avg;
	if (t > maxd->value.ui64)
		maxd->value.ui64 = t;
	mutex_exit(&nvme->n_admin_stat_mutex);
}
