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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>
#include <sys/acpidev_dr.h>
#include <sys/acpidev_impl.h>

static ACPI_STATUS acpidev_pci_probe(acpidev_walk_info_t *infop);

/*
 * Default class driver for PCI/PCIEX Host Bridge devices.
 */
acpidev_class_t acpidev_class_pci = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_PCI,		/* adc_class_id */
	"PCI/PCIex Host Bridge",	/* adc_class_name */
	ACPIDEV_TYPE_PCI,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_pci_probe,		/* adc_probe */
	NULL,				/* adc_filter */
	NULL,				/* adc_init */
	NULL,				/* adc_fini */
};

static char *acpidev_pci_device_ids[] = {
	ACPIDEV_HID_PCIEX_HOSTBRIDGE,
	ACPIDEV_HID_PCI_HOSTBRIDGE,
};

static char *acpidev_pciex_device_ids[] = {
	ACPIDEV_HID_PCIEX_HOSTBRIDGE,
};

static void
acpidev_pci_update_status(acpidev_walk_info_t *infop)
{
	int status;
	dev_info_t *dip = NULL;
	acpidev_data_handle_t dhdl;

	dhdl = infop->awi_data;
	ASSERT((dhdl->aod_iflag & ACPIDEV_ODF_DEVINFO_CREATED) == 0);
	ASSERT((dhdl->aod_iflag & ACPIDEV_ODF_DEVINFO_TAGGED) == 0);
	if ((dhdl->aod_iflag & ACPIDEV_ODF_STATUS_VALID) == 0) {
		status = acpidev_query_device_status(infop->awi_hdl);
		dhdl->aod_status = status;
		dhdl->aod_iflag |= ACPIDEV_ODF_STATUS_VALID;
	} else {
		status = dhdl->aod_status;
	}
	dhdl->aod_level = infop->awi_level;
	dhdl->aod_hdl = infop->awi_hdl;
	dhdl->aod_class = NULL;
	dhdl->aod_class_list = NULL;
	if (acpidev_match_device_id(infop->awi_info,
	    ACPIDEV_ARRAY_PARAM(acpidev_pciex_device_ids))) {
		dhdl->aod_class_id = ACPIDEV_CLASS_ID_PCIEX;
	} else {
		dhdl->aod_class_id = ACPIDEV_CLASS_ID_PCI;
	}

	if (ACPI_FAILURE(acpica_get_devinfo(infop->awi_hdl, &dip))) {
		dip = NULL;
	} else {
		ASSERT(dip != NULL);
	}
	if (acpidev_check_device_enabled(status)) {
		/*
		 * Mark the device as DISABLE if no device node created.
		 * BIOS may hide some special PCI/PCIex buses from OS.
		 */
		if (dip == NULL) {
			dhdl->aod_dip = NULL;
			dhdl->aod_status &= ~ACPI_STA_DEVICE_ENABLED;
		} else {
			dhdl->aod_dip = dip;
			dhdl->aod_iflag |= ACPIDEV_ODF_DEVINFO_CREATED;
		}
	} else {
		ASSERT(dip == NULL);
		dhdl->aod_dip = NULL;
		dhdl->aod_status &= ~ACPI_STA_DEVICE_ENABLED;
	}
}

static ACPI_STATUS
acpidev_pci_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);
	if (infop->awi_info->Type != ACPI_TYPE_DEVICE ||
	    acpidev_match_device_id(infop->awi_info,
	    ACPIDEV_ARRAY_PARAM(acpidev_pci_device_ids)) == B_FALSE) {
		return (AE_OK);
	}

	if (acpica_get_devcfg_feature(ACPI_DEVCFG_PCI) == 0) {
		return (AE_OK);
	}

	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE) {
		/*
		 * Check hotplug capability on the first pass.
		 */
		acpidev_dr_check(infop);
	} else if (infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE) {
		/*
		 * Check whether the PCI device enumerator has created device
		 * nodes for PCI/PCIEX host bridges.
		 */
		acpidev_pci_update_status(infop);
	} else if (infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		/*
		 * No support of PCI/PCIEX host bridge hotplug yet.
		 * It will come in next phase.
		 */
		cmn_err(CE_WARN,
		    "!acpidev: no support of PCI/PCIEX host bridge hotplug.");
		/*
		 * Don't block the hot-adding process, just skip it.
		 */
		rc = AE_OK;
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_pci_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_CONT, "?acpidev: failed to process PCI/PCIEX host "
		    "bridge object %s.\n", infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}
