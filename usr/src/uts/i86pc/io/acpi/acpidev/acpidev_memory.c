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
 * Copyright (c) 2009-2010, Intel Corporation.
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

static ACPI_STATUS acpidev_memory_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_memory_filter(
    acpidev_walk_info_t *infop, char *devname, int maxlen);
static ACPI_STATUS acpidev_memory_init(acpidev_walk_info_t *infop);

/*
 * Default class driver for ACPI memory objects.
 */
acpidev_class_t acpidev_class_memory = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_MEMORY,	/* adc_class_id */
	"ACPI memory",			/* adc_class_name */
	ACPIDEV_TYPE_MEMORY,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_memory_probe,		/* adc_probe */
	acpidev_memory_filter,		/* adc_filter */
	acpidev_memory_init,		/* adc_init */
	NULL,				/* adc_fini */
};

/*
 * List of class drivers which will be called in order when handling
 * children of ACPI memory objects.
 */
acpidev_class_list_t *acpidev_class_list_memory = NULL;

static char *acpidev_memory_device_ids[] = {
	ACPIDEV_HID_MEMORY,
};

static char *acpidev_memory_uid_formats[] = {
	"MEM%x-%x",
};

/* Filter rule table for memory objects. */
static acpidev_filter_rule_t acpidev_memory_filters[] = {
	{	/* Ignore all memory objects under the ACPI root object */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		1,
		NULL,
		NULL,
	},
	{	/* Create node and scan child for all other memory objects */
		NULL,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		2,
		INT_MAX,
		NULL,
		ACPIDEV_NODE_NAME_MEMORY,
	}
};

static ACPI_STATUS
acpidev_memory_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);
	if (infop->awi_info->Type != ACPI_TYPE_DEVICE ||
	    acpidev_match_device_id(infop->awi_info,
	    ACPIDEV_ARRAY_PARAM(acpidev_memory_device_ids)) == 0) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
		if (acpica_get_devcfg_feature(ACPI_DEVCFG_MEMORY)) {
			flags |= ACPIDEV_PROCESS_FLAG_CREATE;
			acpidev_dr_check(infop);
		}
		break;

	case ACPIDEV_OP_BOOT_REPROBE:
		break;

	case ACPIDEV_OP_HOTPLUG_PROBE:
		if (acpica_get_devcfg_feature(ACPI_DEVCFG_MEMORY)) {
			flags |= ACPIDEV_PROCESS_FLAG_CREATE |
			    ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
			    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		}
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_memory_probe.", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
		break;
	}

	if (rc == AE_OK) {
		rc = acpidev_process_object(infop, flags);
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process memory object %s.",
		    infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}

static acpidev_filter_result_t
acpidev_memory_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_memory_filters),
		    devname, maxlen);
	} else {
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_memory_init(acpidev_walk_info_t *infop)
{
	char *compatible[] = {
		ACPIDEV_TYPE_MEMORY,
		"mem"
	};

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_dip != NULL);
	if (ACPI_FAILURE(acpidev_resource_process(infop, B_TRUE))) {
		cmn_err(CE_WARN, "!acpidev: failed to process resources of "
		    "memory device %s.", infop->awi_name);
		return (AE_ERROR);
	}

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}

	if (ACPI_FAILURE(acpidev_set_unitaddr(infop,
	    ACPIDEV_ARRAY_PARAM(acpidev_memory_uid_formats), NULL))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
