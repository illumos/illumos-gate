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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * ACPI driver that enumerates and creates USB nodes.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_impl.h>

/*
 * List of class drivers which will be called in order when handling
 * children of ACPI USB objects.
 */
acpidev_class_list_t *acpidev_class_list_usbport = NULL;

static acpidev_filter_result_t acpidev_usbport_filter_cb(acpidev_walk_info_t *,
    ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);

static acpidev_filter_rule_t acpidev_usbport_filters[] = {
	{
		acpidev_usbport_filter_cb,
		0,
		ACPIDEV_FILTER_SCAN,
		&acpidev_class_list_usbport,
		3,
		INT_MAX,
		NULL,
		NULL
	}
};

/*
 * We've been passed something by the general device scanner. This means that we
 * were able to determine that the parent was a valid PCI device with a USB
 * class code.
 */
static ACPI_STATUS
acpidev_usbport_probe(acpidev_walk_info_t *infop)
{
	ACPI_STATUS ret;
	int flags;

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE) {
		return (AE_OK);
	}

	flags = ACPIDEV_PROCESS_FLAG_SCAN;
	switch (infop->awi_op_type) {
	case ACPIDEV_OP_BOOT_PROBE:
	case ACPIDEV_OP_BOOT_REPROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE;
		break;
	case ACPIDEV_OP_HOTPLUG_PROBE:
		flags |= ACPIDEV_PROCESS_FLAG_CREATE |
		    ACPIDEV_PROCESS_FLAG_SYNCSTATUS |
		    ACPIDEV_PROCESS_FLAG_HOLDBRANCH;
		break;
	default:
		return (AE_BAD_PARAMETER);
	}

	if (infop->awi_parent == NULL) {
		return (AE_BAD_PARAMETER);
	}

	/*
	 * Inherit our parents value.
	 */
	if (infop->awi_parent->awi_scratchpad[AWI_SCRATCH_USBPORT] != 0) {
		infop->awi_scratchpad[AWI_SCRATCH_USBPORT] =
		    infop->awi_parent->awi_scratchpad[AWI_SCRATCH_USBPORT];
	} else {
		infop->awi_scratchpad[AWI_SCRATCH_USBPORT] = infop->awi_level;
	}

	ret = acpidev_process_object(infop, flags);
	if (ACPI_FAILURE(ret) && ret != AE_NOT_EXIST &&
	    ret != AE_ALREADY_EXISTS) {
		cmn_err(CE_WARN, "!failed to process USB object %s: %d",
		    infop->awi_name, ret);
	} else {
		ret = AE_OK;
	}

	return (ret);
}

static acpidev_filter_result_t
acpidev_usbport_filter_cb(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	ACPI_BUFFER buf;

	if (infop->awi_info->Type != ACPI_TYPE_DEVICE) {
		return (ACPIDEV_FILTER_SKIP);
	}

	/*
	 * Make sure we can get the _ADR method for this as a reasonable case of
	 * determining whether or not this is something that we care about.
	 */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_FAILURE(AcpiEvaluateObject(hdl, "_ADR", NULL, &buf))) {
		return (ACPIDEV_FILTER_SKIP);
	}
	AcpiOsFree(buf.Pointer);

	if (infop->awi_level == infop->awi_scratchpad[AWI_SCRATCH_USBPORT]) {
		(void) snprintf(devname, len, "usbroothub");
	} else {
		(void) snprintf(devname, len, "port");
	}

	return (ACPIDEV_FILTER_DEFAULT);
}

static acpidev_filter_result_t
acpidev_usbport_filter(acpidev_walk_info_t *infop, char *devname, int maxlen)
{
	acpidev_filter_result_t res;

	ASSERT(infop != NULL);
	if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE ||
	    infop->awi_op_type == ACPIDEV_OP_BOOT_REPROBE ||
	    infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE) {
		res = acpidev_filter_device(infop, infop->awi_hdl,
		    ACPIDEV_ARRAY_PARAM(acpidev_usbport_filters),
		    devname, maxlen);
	} else {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: unknown operation type %u "
		    "in acpidev_device_filter().", infop->awi_op_type);
		res = ACPIDEV_FILTER_FAILED;
	}

	return (res);
}

static ACPI_STATUS
acpidev_usbport_init(acpidev_walk_info_t *infop)
{
	char *name;
	ACPI_BUFFER buf;
	char acpi_strbuf[128];

	char *compatible[] = {
		ACPIDEV_TYPE_USBPORT,
		ACPIDEV_TYPE_VIRTNEX
	};

	if (ACPI_FAILURE(acpidev_set_compatible(infop,
	    ACPIDEV_ARRAY_PARAM(compatible)))) {
		return (AE_ERROR);
	}

	/*
	 * Set the port's unit address to the last component of the ACPI path
	 * for it. This needs to be unique for a given set of parents and
	 * children. Because the hubs all usually have names that aren't unique
	 * we end up using the name of the parent for the top level device.
	 *
	 * For children, just use their acpi port address.
	 */
	if (infop->awi_parent->awi_scratchpad[AWI_SCRATCH_USBPORT] == 0) {
		name = strrchr(infop->awi_parent->awi_name, '.');
		if (name != NULL)
			name = name + 1;

		/*
		 * Also, add the parents name as a property so when user land is
		 * trying to marry up USB devices with the root controller, it
		 * can.
		 */
		if (ndi_prop_update_string(DDI_DEV_T_NONE, infop->awi_dip,
		    "acpi-controller-name", infop->awi_parent->awi_name) !=
		    DDI_PROP_SUCCESS) {
			return (AE_ERROR);
		}
	} else {
		ACPI_OBJECT *obj;
		buf.Length = ACPI_ALLOCATE_BUFFER;
		if (ACPI_FAILURE(AcpiEvaluateObject(infop->awi_hdl, "_ADR",
		    NULL, &buf))) {
			return (AE_ERROR);
		}

		obj = (ACPI_OBJECT *)buf.Pointer;
		if (obj->Type != ACPI_TYPE_INTEGER) {
			AcpiOsFree(buf.Pointer);
			return (AE_ERROR);
		}
		if (ndi_prop_update_int64(DDI_DEV_T_NONE, infop->awi_dip,
		    "acpi-address", (int64_t)obj->Integer.Value) !=
		    DDI_PROP_SUCCESS) {
			AcpiOsFree(buf.Pointer);
			return (AE_ERROR);
		}
		(void) snprintf(acpi_strbuf, sizeof (acpi_strbuf), "%lu",
		    obj->Integer.Value);
		name = acpi_strbuf;
		AcpiOsFree(buf.Pointer);
	}


	if (ACPI_FAILURE(acpidev_set_unitaddr(infop, NULL, 0,
	    name))) {
		return (AE_ERROR);
	}

	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_SUCCESS(AcpiEvaluateObject(infop->awi_hdl, "_PLD", NULL,
	    &buf))) {
		ACPI_OBJECT *obj = (ACPI_OBJECT *)buf.Pointer;

		if (obj->Type == ACPI_TYPE_PACKAGE && obj->Package.Count >= 1 &&
		    obj->Package.Elements[0].Type == ACPI_TYPE_BUFFER &&
		    obj->Package.Elements[0].Buffer.Length >=
		    ACPI_PLD_REV1_BUFFER_SIZE) {
			(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE,
			    infop->awi_dip, "acpi-physical-location",
			    obj->Package.Elements[0].Buffer.Pointer,
			    obj->Package.Elements[0].Buffer.Length);
		}
		AcpiOsFree(buf.Pointer);
	}

	buf.Length = ACPI_ALLOCATE_BUFFER;
	if (ACPI_SUCCESS(AcpiEvaluateObject(infop->awi_hdl, "_UPC", NULL,
	    &buf))) {
		ACPI_OBJECT *obj = (ACPI_OBJECT *)buf.Pointer;

		if (obj->Type == ACPI_TYPE_PACKAGE && obj->Package.Count >= 4 &&
		    obj->Package.Elements[0].Type == ACPI_TYPE_INTEGER &&
		    obj->Package.Elements[1].Type == ACPI_TYPE_INTEGER) {
			if (obj->Package.Elements[0].Integer.Value != 0) {
				(void) ndi_prop_create_boolean(DDI_DEV_T_NONE,
				    infop->awi_dip, "usb-port-connectable");
			}

			(void) ndi_prop_update_int(DDI_DEV_T_NONE,
			    infop->awi_dip, "usb-port-type",
			    (int)obj->Package.Elements[1].Integer.Value);
		}
		AcpiOsFree(buf.Pointer);
	}

	return (AE_OK);
}

acpidev_class_t acpidev_class_usbport = {
	0,				/* adc_refcnt */
	ACPIDEV_CLASS_REV1,		/* adc_version */
	ACPIDEV_CLASS_ID_USB,		/* adc_class_id */
	"ACPI USBPORT",			/* adc_class_name */
	ACPIDEV_TYPE_USBPORT,		/* adc_dev_type */
	NULL,				/* adc_private */
	NULL,				/* adc_pre_probe */
	NULL,				/* adc_post_probe */
	acpidev_usbport_probe,		/* adc_probe */
	acpidev_usbport_filter,		/* adc_filter */
	acpidev_usbport_init,		/* adc_init */
	NULL,				/* adc_fini */
};
