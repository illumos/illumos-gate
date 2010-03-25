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
#include <sys/acpidev_impl.h>

static ACPI_STATUS acpidev_scope_probe(acpidev_walk_info_t *infop);
static acpidev_filter_result_t acpidev_scope_filter(acpidev_walk_info_t *infop,
    char *devname, int maxlen);
static ACPI_STATUS acpidev_scope_init(acpidev_walk_info_t *infop);

/*
 * Default class driver for ACPI scope objects.
 * This class driver is used to handle predefined ACPI SCOPE objects
 * under the ACPI root object, such as _PR_, _SB_ and _TZ_ etc.
 * The default policy for ACPI SCOPE objects is SKIP.
 */
acpidev_class_t acpidev_class_scope = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_SCOPE,		/* adc_class_id */
	"ACPI Scope",			/* adc_class_name */
	ACPIDEV_TYPE_SCOPE,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_scope_probe,		/* adc_probe */
	acpidev_scope_filter,		/* adc_filter */
	acpidev_scope_init,		/* adc_init */
	NULL,				/* adc_fini */
};

acpidev_class_list_t *acpidev_class_list_scope = NULL;

/*
 * All SCOPE objects share a global pseudo unit address space across the system.
 */
static uint32_t acpidev_scope_unitaddr = 0;

/* Filter rule table for ACPI SCOPE objects. */
static acpidev_filter_rule_t acpidev_scope_filters[] = {
	{	/* For safety, _SB_ is hardcoded as DEVICE by acpica */
		NULL,
		0,
		ACPIDEV_FILTER_DEFAULT,
		&acpidev_class_list_device,
		1,
		1,
		ACPIDEV_OBJECT_NAME_SB,
		ACPIDEV_NODE_NAME_MODULE_SBD,
	},
	{	/* Handle _PR_ object. */
		NULL,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_scope,
		1,
		1,
		ACPIDEV_OBJECT_NAME_PR,
		ACPIDEV_NODE_NAME_PROCESSOR,
	},
	{	/* Ignore all other scope objects. */
		NULL,
		0,
		ACPIDEV_FILTER_SKIP,
		NULL,
		1,
		INT_MAX,
		NULL,
		NULL,
	}
};

static ACPI_STATUS
acpidev_scope_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS rc = AE_OK;
	int flags;

	ASSERT(infop != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);
	if (infop->awi_info->Type != ACPI_TYPE_LOCAL_SCOPE) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE;
		break;

	case ACPIDEV_OP_BOOT_REPROBE:
		break;

	case ACPIDEV_OP_HOTPLUG_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
		    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		break;

	default:
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_scope_probe().", infop->awi_op_type);
		rc = AE_BAD_PARAMETER;
		break;
	}

	if (rc == AE_OK) {
		rc = acpidev_process_object(infop, flags);
	}
	if (ACPI_FAILURE(rc) && rc != AE_NOT_EXIST && rc != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to process scope object %s.",
		    infop->awi_name);
	} else {
		rc = AE_OK;
	}

	return (rc);
}

static acpidev_filter_result_t
acpidev_scope_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_scope_filters),
		    devname, maxlen);
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_scope_filter().", infop->awi_op_type);
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_scope_init(acpidev_walk_info_t *infop)
{
	char unitaddr[32];
	char *compatible[] = {
		ACPIDEV_HID_SCOPE,
		ACPIDEV_TYPE_SCOPE,
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
	(void) snprintf(unitaddr, sizeof (unitaddr), "%u",
	    atomic_inc_32_nv(&acpidev_scope_unitaddr) - 1);
	if (ACPI_FAILURE(acpidev_set_unitaddr(infop, NULL, 0, unitaddr))) {
		return (AE_ERROR);
	}

	return (AE_OK);
}
