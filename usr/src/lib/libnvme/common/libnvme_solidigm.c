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

/*
 * libnvme logic specific to Solidigm (nee Intel) device families. This
 * currently supports the Intel P5510, Intel/Solidigm P5[56]20, and the Solidigm
 * PS10[13]0.
 *
 * The Intel/Solidigm 5000 series controllers all used the same PCI device ID.
 * To determine the specific device in question that we should be targeting we
 * must use the subsystem ID. The P5[56]20 was branded under both Solidigm and
 * Intel and therefore may use both vendor IDs. For the PS10[13]0 series we opt
 * to break out all the subsystems again here because of the above experience.
 */

#include <string.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/nvme/solidigm.h>

#include "libnvme_impl.h"

CTASSERT(SOLIDIGM_P5XXX_LOG_SMART == SOLIDIGM_P5XXX_LOG_SMART);

static bool
nvme_solidigm_outlier_var_len(uint64_t *outp, const void *data, size_t len)
{
	solidigm_vul_p5xxx_lat_outlier_t hdr;

	if (len < sizeof (solidigm_vul_p5xxx_lat_outlier_t)) {
		return (false);
	}

	(void) memcpy(&hdr, data, sizeof (hdr));
	*outp = (uint64_t)hdr.lao_nents * sizeof (soligm_vul_lat_ent_t);
	return (true);
}

static const nvme_log_page_info_t solidigm_log_read_lat = {
	.nlpi_short = "solidigm/rlat",
	.nlpi_human = "Read Latency",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_READ_LAT,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5xxx_lat_t)
};

static const nvme_log_page_info_t solidigm_log_write_lat = {
	.nlpi_short = "solidigm/wlat",
	.nlpi_human = "Write Latency",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_WRITE_LAT,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5xxx_lat_t)
};

/*
 * While the P5000 series and the PS10x0 series use the same structure for this
 * log, they show up at different log addresses due to the OCP support in the
 * latter.
 */
static const nvme_log_page_info_t solidigm_p5xxx_log_temp = {
	.nlpi_short = "solidigm/temp",
	.nlpi_human = "Temperature Statistics",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_TEMP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_temp_t)
};

static const nvme_log_page_info_t solidigm_ps10x0_log_temp = {
	.nlpi_short = "solidigm/temp",
	.nlpi_human = "Temperature Statistics",
	.nlpi_lid = SOLIDIGM_PS10x0_LOG_TEMP,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_temp_t)
};

/*
 * The SMART log page is shared across all devices that we support currently.
 */
static const nvme_log_page_info_t solidigm_log_smart = {
	.nlpi_short = "solidigm/smart",
	.nlpi_human = "SMART",
	.nlpi_lid = SOLIDIGM_PS10x0_LOG_SMART,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_smart_log_t)
};

static const nvme_log_page_info_t solidigm_log_io_queue = {
	.nlpi_short = "solidigm/ioqueue",
	.nlpi_human = "I/O Queue Metrics",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_IO_QUEUE,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5xxx_ioq_t)
};

static const nvme_log_page_info_t solidigm_log_name = {
	.nlpi_short = "solidigm/name",
	.nlpi_human = "Drive Marketing Name",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_MARK_DESC,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = SOLIDIGM_VUC_MARK_NAME_LEN
};

static const nvme_log_page_info_t solidigm_log_power = {
	.nlpi_short = "solidigm/power",
	.nlpi_human = "Power Usage",
	.nlpi_lid = SOLIDIGM_P5X20_LOG_POWER,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5x2x_power_t)
};

static const nvme_log_page_info_t solidigm_log_gc = {
	.nlpi_short = "solidigm/gc",
	.nlpi_human = "Garbage Collection",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_GC,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5xxx_gc_t)
};

static const nvme_log_page_info_t solidigm_log_outlier = {
	.nlpi_short = "solidigm/outlier",
	.nlpi_human = "Latency Outlier",
	.nlpi_lid = SOLIDIGM_P5XXX_LOG_OUTLIER,
	.nlpi_csi = NVME_CSI_NVM,
	.nlpi_kind = NVME_LOG_ID_VENDOR_SPECIFIC,
	.nlpi_source = NVME_LOG_DISC_S_DB,
	.nlpi_scope = NVME_LOG_SCOPE_CTRL,
	.nlpi_len = sizeof (solidigm_vul_p5xxx_lat_outlier_t),
	.nlpi_var_func = nvme_solidigm_outlier_var_len
};

static const nvme_log_page_info_t *intel_p5510_log_pages[] = {
	&solidigm_log_read_lat, &solidigm_log_write_lat,
	&solidigm_p5xxx_log_temp, &solidigm_log_smart, &solidigm_log_io_queue,
	&solidigm_log_name, &solidigm_log_gc, &solidigm_log_outlier
};

static const nvme_vsd_ident_t intel_p5510_idents[] = {
	{
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5510_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5510"
	}
};

const nvme_vsd_t intel_p5510 = {
	.nvd_ident = intel_p5510_idents,
	.nvd_nident = ARRAY_SIZE(intel_p5510_idents),
	.nvd_logs = intel_p5510_log_pages,
	.nvd_nlogs = ARRAY_SIZE(intel_p5510_log_pages)
};

static const nvme_log_page_info_t *solidigm_p5x20_log_pages[] = {
	&ocp_log_smart, &solidigm_log_read_lat, &solidigm_log_write_lat,
	&solidigm_p5xxx_log_temp, &solidigm_log_smart, &solidigm_log_io_queue,
	&solidigm_log_name, &solidigm_log_power, &solidigm_log_gc,
	&solidigm_log_outlier

};

static const nvme_vsd_ident_t intel_p5x20_idents[] = {
	{
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5520 U.2"
	}, {
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1S_9P5MM_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5520 E1.S 9.5mm"
	}, {
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1S_15MM_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5520 E1.S 15mm"
	}, {
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1L_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5520 E1.L 15mm"
	}, {
		.nvdi_vid = INTEL_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = INTEL_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5620_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Intel P5620 U.2"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm P5520 U.2"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1S_9P5MM_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm P5520 E1.S 9.5mm"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1S_15MM_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm P5520 E1.S 15mm"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5520_E1L_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm P5520 E1.L 15mm"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_P5XXX_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_P5620_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm P5620 U.2"
	}
};

const nvme_vsd_t solidigm_p5x20 = {
	.nvd_ident = intel_p5x20_idents,
	.nvd_nident = ARRAY_SIZE(intel_p5x20_idents),
	.nvd_logs = solidigm_p5x20_log_pages,
	.nvd_nlogs = ARRAY_SIZE(solidigm_p5x20_log_pages)
};


static const nvme_log_page_info_t *solidigm_ps10x0_log_pages[] = {
	&ocp_log_smart, &ocp_log_errrec, &ocp_log_fwact, &ocp_log_lat,
	&ocp_log_devcap, &ocp_log_unsup, &solidigm_log_smart,
	&solidigm_ps10x0_log_temp
};

static const nvme_vsd_ident_t solidigm_ps10x0_idents[] = {
	{
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_PS10X0_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_PS1010_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm PS1010 U.2"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_PS10X0_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_PS1010_E3_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm PS1010 E3.S"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_PS10X0_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_PS1030_U2_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm PS1030 U.2"
	}, {
		.nvdi_vid = SOLIDIGM_PCI_VID,
		.nvdi_did = SOLIDIGM_PS10X0_DID,
		.nvdi_svid = SOLIDIGM_PCI_VID,
		.nvdi_sdid = SOLIDIGM_PS1010_E3_SDID,
		.nvdi_subsys = true,
		.nvdi_human = "Solidigm PS1030 E3.S"
	}
};

const nvme_vsd_t solidigm_ps10x0 = {
	.nvd_ident = solidigm_ps10x0_idents,
	.nvd_nident = ARRAY_SIZE(solidigm_ps10x0_idents),
	.nvd_logs = solidigm_ps10x0_log_pages,
	.nvd_nlogs = ARRAY_SIZE(solidigm_ps10x0_log_pages)
};
