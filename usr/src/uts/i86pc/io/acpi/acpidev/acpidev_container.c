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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * There are three types of container objects defined in the ACPI Spec as below.
 * PNP0A05: Generic Container Device
 *   A device whose settings are totally controlled by its ACPI resource
 *   information, and otherwise needs no device or bus-specific driver support.
 *   This was originally known as Generic ISA Bus Device.
 *   This ID should only be used for containers that do not produce resources
 *   for consumption by child devices. Any system resources claimed by a PNP0A05
 *   device's _CRS object must be consumed by the container itself.
 * PNP0A06: Generic Container Device
 *   This device behaves exactly the same as the PNP0A05 device.
 *   This was originally known as Extended I/O Bus.
 *   This ID should only be used for containers that do not produce resources
 *   for consumption by child devices. Any system resources claimed by a PNP0A06
 *   device's _CRS object must be consumed by the container itself.
 * ACPI0004: Module Device.
 *   This device is a container object that acts as a bus node in a namespace.
 *   A Module Device without any of the _CRS, _PRS and _SRS methods behaves
 *   the same way as the Generic Container Devices (PNP0A05 or PNP0A06).
 *   If the Module Device contains a _CRS method, only the resources
 *   described in the _CRS are available for consumption by its child devices.
 *   Also, the Module Device can support _PRS and _SRS methods if _CRS is
 *   supported.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/note.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_dr.h>
#include <sys/acpidev_impl.h>

static ACPI_STATUS acpidev_container_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_container_filter(
    acpidev_walk_info_t *infop, char *devname, int maxlen);
static ACPI_STATUS acpidev_container_init(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_container_filter_func(
    acpidev_walk_info_t *infop, ACPI_HANDLE hdl, acpidev_filter_rule_t *rulep,
    char *devname, int devnamelen);

/*
 * Default class driver for ACPI container objects.
 */
acpidev_class_t acpidev_class_container = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_CONTAINER,	/* adc_class_id */
	"ACPI Container",		/* adc_class_name */
	ACPIDEV_TYPE_CONTAINER,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_container_probe,	/* adc_probe */
	acpidev_container_filter,	/* adc_filter */
	acpidev_container_init,		/* adc_init */
	NULL,				/* adc_fini */
};

static char *acpidev_container_device_ids[] = {
	ACPIDEV_HID_MODULE,
	ACPIDEV_HID_CONTAINER1,
	ACPIDEV_HID_CONTAINER2,
};

static char *acpidev_container_uid_formats[] = {
	"CPUSCK%x",
};

/* Filter rule table for container objects. */
static acpidev_filter_rule_t acpidev_container_filters[] = {
	{	/* Ignore all container objects under ACPI root object */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		1,
		NULL,
		NULL,
	},
	{	/* Create node and scan child for all other container objects */
		acpidev_container_filter_func,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		ACPIDEV_NODE_NAME_CONTAINER,
	}
};

static ACPI_STATUS
acpidev_container_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE ||
	    acpidev_match_device_id(infop->awi_info,
	    ACPIDEV_ARRAY_PARAM(acpidev_container_device_ids)) == 0) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
		if (acpica_get_devcfg_feature(ACPI_DEVCFG_CONTAINER)) {
			flags |= ACPIDEV_PROCESS_FLAG_CREATE;
			acpidev_dr_check(infop);
		}
		break;

	case ACPIDEV_OP_BOOT_REPROBE:
		break;

	case ACPIDEV_OP_HOTPLUG_PROBE:
		if (acpica_get_devcfg_feature(ACPI_DEVCFG_CONTAINER)) {
			flags |= ACPIDEV_PROCESS_FLAG_CREATE |
			    ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
			    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		}
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u in "
		    "acpidev_container_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
		break;
	}

	if (rc == AE_OK) {
		rc = acpidev_process_object(infop, flags);
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process container object %s.",
		    infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}

static ACPI_STATUS
acpidev_container_search_dev(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	_NOTE(ARGUNUSED(hdl, retval));

	int *fp = (int *)ctx;

	*fp = lvl;

	return (AE_CTRL_TERMINATE);
}

static acpidev_filter_result_t
acpidev_container_filter_func(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *rulep, char *devname, int devnamelen)
{
	ACPI_BUFFER buf;
	void *retval;
	int proc_lvl, cpu_lvl, module_lvl;
	acpidev_filter_result_t res;
	static char *cpu_hids[] = {
		ACPIDEV_HID_CPU,
	};
	static char *module_hids[] = {
		ACPIDEV_HID_MODULE,
	};

	res = acpidev_filter_default(infop, hdl, rulep, devname, devnamelen);
	/* Return if we don't need to generate a device name. */
	if (devname == NULL || res == ACPIDEV_FILTER_FAILED ||
	    res == ACPIDEV_FILTER_SKIP) {
		return (res);
	}

	/* Try to figure out the most specific device name for the object. */
	retval = NULL;
	proc_lvl = INT_MAX;
	cpu_lvl = INT_MAX;
	module_lvl = INT_MAX;

	/* Search for ACPI Processor object. */
	(void) AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, hdl, 2,
	    acpidev_container_search_dev, NULL, &proc_lvl, &retval);

	/* Search for CPU Device object. */
	(void) acpidev_get_device_by_id(hdl, ACPIDEV_ARRAY_PARAM(cpu_hids), 2,
	    B_FALSE, acpidev_container_search_dev, &cpu_lvl, &retval);

	/* Search for Module Device object. */
	(void) acpidev_get_device_by_id(hdl, ACPIDEV_ARRAY_PARAM(module_hids),
	    2, B_FALSE, acpidev_container_search_dev, &module_lvl, &retval);

	buf.Pointer = devname;
	buf.Length = devnamelen;
	if (cpu_lvl > proc_lvl) {
		cpu_lvl = proc_lvl;
	}
	if (cpu_lvl == 1) {
		/* CPU as child, most likely a physical CPU. */
		(void) strlcpy(devname, ACPIDEV_NODE_NAME_MODULE_CPU,
		    devnamelen);
	} else if (cpu_lvl == 2 && module_lvl == 1) {
		/* CPU as grandchild, most likely a system board. */
		(void) strlcpy(devname, ACPIDEV_NODE_NAME_MODULE_SBD,
		    devnamelen);
	} else if (ACPI_FAILURE(AcpiGetName(infop->awi_hdl,
	    ACPI_SINGLE_NAME, &buf))) {
		/*
		 * Failed to get ACPI object name; use ACPI object name
		 * as the default name.
		 */
		(void) strlcpy(devname, ACPIDEV_NODE_NAME_CONTAINER,
		    devnamelen);
	}

	return (res);
}

static acpidev_filter_result_t
acpidev_container_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_container_filters),
		    devname, maxlen);
	} else {
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_container_init(acpidev_walk_info_t *infop)
{
	static char *compatible[] = {
		ACPIDEV_TYPE_CONTAINER,
		ACPIDEV_HID_VIRTNEX,
		ACPIDEV_TYPE_VIRTNEX,
	};

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_dip != NULL);

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}
	if (ACPI_FAILURE(acpidev_set_unitaddr(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_container_uid_formats), NULL))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
