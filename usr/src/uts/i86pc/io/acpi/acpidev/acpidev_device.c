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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_impl.h>

static ACPI_STATUS acpidev_device_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_device_filter(acpidev_walk_info_t *infop,
    char *devname, int maxlen);
static ACPI_STATUS acpidev_device_init(acpidev_walk_info_t *infop);

static uint32_t acpidev_device_unitaddr = 0;

/*
 * Default class driver for ACPI DEVICE objects.
 * The default policy for DEVICE objects is to scan child objects without
 * creating device nodes. But some special DEVICE objects will have device
 * nodes created for them.
 */
acpidev_class_t acpidev_class_device = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_DEVICE,	/* adc_class_id */
	"ACPI Device",			/* adc_class_name */
	ACPIDEV_TYPE_DEVICE,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_device_probe,		/* adc_probe */
	acpidev_device_filter,		/* adc_filter */
	acpidev_device_init,		/* adc_init */
	NULL,				/* adc_fini */
};

/*
 * List of class drivers which will be called in order when handling
 * children of ACPI DEVICE objects.
 */
acpidev_class_list_t *acpidev_class_list_device = NULL;

/* Filter rule table for boot. */
static acpidev_filter_rule_t acpidev_device_filters[] = {
	{	/* _SB_ object type is hardcoded to DEVICE by acpica */
		NULL,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		1,
		1,
		ACPIDEV_OBJECT_NAME_SB,
		ACPIDEV_NODE_NAME_MODULE_SBD,
	},
	{	/* Ignore other device objects under ACPI root object */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		1,
		NULL,
		NULL,
	},
	{	/* Scan other device objects not directly under ACPI root */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		NULL,
	}
};

static ACPI_STATUS
acpidev_device_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE) {
		return (AE_OK);
	}

	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE) {
		flags = ACPIDEV_PROCESS_FLAG_SCAN | ACPIDEV_PROCESS_FLAG_CREATE;
		rc = acpidev_process_object(infop, flags);
	} else if (infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE) {
		flags = ACPIDEV_PROCESS_FLAG_SCAN;
		rc = acpidev_process_object(infop, flags);
	} else if (infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		flags = ACPIDEV_PROCESS_FLAG_SCAN | ACPIDEV_PROCESS_FLAG_CREATE;
		rc = acpidev_process_object(infop, flags);
	} else {
		ACPIDEV_DEBUG(CE_WARN,
		    "acpidev: unknown operation type %u in "
		    "acpi_device_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process device object %s.",
		    infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}

static acpidev_filter_result_t
acpidev_device_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_device_filters),
		    devname, maxlen);
	} else {
		ACPIDEV_DEBUG(CE_WARN, "acpidev: unknown operation type %u "
		    "in acpidev_device_filter().", infop->awi_op_type);
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

/*ARGSUSED*/
static ACPI_STATUS
acpidev_device_init(acpidev_walk_info_t *infop)
{
	char unitaddr[32];
	char *compatible[] = {
		ACPIDEV_TYPE_DEVICE,
		ACPIDEV_HID_VIRTNEX,
		ACPIDEV_TYPE_VIRTNEX,
	};

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}
	(void) snprintf(unitaddr, sizeof (unitaddr), "%u",
	    atomic_inc_32_nv(&acpidev_device_unitaddr) - 1);
	if (ACPI_FAILURE(acpidev_set_unitaddr(infop, NULL, 0, unitaddr))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
