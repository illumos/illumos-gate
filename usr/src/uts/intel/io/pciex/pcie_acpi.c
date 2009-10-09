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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/promif.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/pcie_acpi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

ACPI_STATUS pcie_acpi_eval_osc(dev_info_t *dip, ACPI_HANDLE osc_hdl,
	uint32_t *osc_flags);
static ACPI_STATUS pcie_acpi_find_osc(ACPI_HANDLE busobj,
	ACPI_HANDLE *osc_hdlp);

#ifdef DEBUG
static void pcie_dump_acpi_obj(ACPI_HANDLE pcibus_obj);
static ACPI_STATUS pcie_walk_obj_namespace(ACPI_HANDLE hdl, uint32_t nl,
	void *context, void **ret);
static ACPI_STATUS pcie_print_acpi_name(ACPI_HANDLE hdl, uint32_t nl,
	void *context, void **ret);
#endif /* DEBUG */

int
pcie_acpi_osc(dev_info_t *dip, uint32_t *osc_flags)
{
	ACPI_HANDLE pcibus_obj;
	int status = AE_ERROR;
	ACPI_HANDLE osc_hdl;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	pcie_x86_priv_t *osc_p = (pcie_x86_priv_t *)bus_p->bus_plat_private;

	/* Mark this so we know _OSC has been called for this device */
	osc_p->bus_osc = B_TRUE;

	/*
	 * (1)  Find the ACPI device node for this bus node.
	 */
	status = acpica_get_handle(dip, &pcibus_obj);
	if (status != AE_OK) {
		PCIE_DBG("No ACPI device found (dip %p)\n", (void *)dip);
		return (DDI_FAILURE);
	}

	/*
	 * (2)	Check if _OSC method is present.
	 */
	if (pcie_acpi_find_osc(pcibus_obj, &osc_hdl) != AE_OK) {
		/* no _OSC method present */
		PCIE_DBG("no _OSC method present for dip %p\n",
		    (void *)dip);
		return (DDI_FAILURE);
	}

	/*
	 * (3)	_OSC method exists; evaluate _OSC.
	 */
	if (pcie_acpi_eval_osc(dip, osc_hdl, osc_flags) != AE_OK) {
		PCIE_DBG("Failed to evaluate _OSC method for dip 0x%p\n",
		    (void *)dip);
		return (DDI_FAILURE);
	}

	osc_p->bus_osc_hp = (*osc_flags & OSC_CONTROL_PCIE_NAT_HP) ?
	    B_TRUE : B_FALSE;
	osc_p->bus_osc_aer = (*osc_flags & OSC_CONTROL_PCIE_ADV_ERR) ?
	    B_TRUE : B_FALSE;

#ifdef DEBUG
	if (pcie_debug_flags > 1)
		pcie_dump_acpi_obj(pcibus_obj);
#endif /* DEBUG */

	return (DDI_SUCCESS);
}

static ACPI_STATUS
pcie_acpi_find_osc(ACPI_HANDLE busobj, ACPI_HANDLE *osc_hdlp)
{
	ACPI_HANDLE parentobj = busobj;
	ACPI_STATUS status = AE_NOT_FOUND;

	*osc_hdlp = NULL;

	/*
	 * Walk up the ACPI device tree looking for _OSC method.
	 */
	do {
		busobj = parentobj;
		if ((status = AcpiGetHandle(busobj, "_OSC", osc_hdlp)) == AE_OK)
			break;
	} while (AcpiGetParent(busobj, &parentobj) == AE_OK);

	if (*osc_hdlp == NULL)
		status = AE_NOT_FOUND;

	return (status);
}

/* UUID for for PCI/PCI-X/PCI-Exp hierarchy as defined in PCI fw ver 3.0 */
static uint8_t pcie_uuid[16] =
	{0x5b, 0x4d, 0xdb, 0x33, 0xf7, 0x1f, 0x1c, 0x40,
	0x96, 0x57, 0x74, 0x41, 0xc0, 0x3d, 0xd7, 0x66};

/*
 * Evaluate _OSC method.
 */
ACPI_STATUS
pcie_acpi_eval_osc(dev_info_t *dip, ACPI_HANDLE osc_hdl, uint32_t *osc_flags)
{
	ACPI_STATUS		status;
	ACPI_OBJECT_LIST	arglist;
	ACPI_OBJECT		args[4];
	UINT32			caps_buffer[3];
	ACPI_BUFFER		rb;
	UINT32			*rbuf;
	UINT32			tmp_ctrl;

	/* construct argument list */
	arglist.Count = 4;
	arglist.Pointer = args;

	/* arg0 - UUID */
	args[0].Type = ACPI_TYPE_BUFFER;
	args[0].Buffer.Length = 16; /* size of UUID string */
	args[0].Buffer.Pointer = pcie_uuid;

	/* arg1 - Revision ID */
	args[1].Type = ACPI_TYPE_INTEGER;
	args[1].Integer.Value = PCIE_OSC_REVISION_ID;

	/* arg2 - Count */
	args[2].Type = ACPI_TYPE_INTEGER;
	args[2].Integer.Value = 3; /* no. of DWORDS in caps_buffer */

	/* arg3 - Capabilities Buffer */
	args[3].Type = ACPI_TYPE_BUFFER;
	args[3].Buffer.Length = 12;
	args[3].Buffer.Pointer = (void *)caps_buffer;

	/* Initialize Capabilities Buffer */

	/* DWORD1: no query flag set */
	caps_buffer[0] = 0;
	/* DWORD2: Support Field */
	caps_buffer[1] = OSC_SUPPORT_FIELD_INIT;
	/* DWORD3: Control Field */
	caps_buffer[2] = OSC_CONTROL_FIELD_INIT;

	/* If hotplug is supported add the corresponding control fields */
	if (*osc_flags & OSC_CONTROL_PCIE_NAT_HP)
		caps_buffer[2] |= (OSC_CONTROL_PCIE_NAT_HP |
		    OSC_CONTROL_PCIE_NAT_PM);

	tmp_ctrl = caps_buffer[2];
	rb.Length = ACPI_ALLOCATE_BUFFER;
	rb.Pointer = NULL;

	status = AcpiEvaluateObjectTyped(osc_hdl, NULL, &arglist, &rb,
	    ACPI_TYPE_BUFFER);
	if (status != AE_OK) {
		PCIE_DBG("Failed to execute _OSC method (status %d)\n",
		    status);
		return (status);
	}

	/* LINTED pointer alignment */
	rbuf = (UINT32 *)((ACPI_OBJECT *)rb.Pointer)->Buffer.Pointer;

	/* check the STATUS word in the capability buffer */
	if (rbuf[0] & OSC_STATUS_ERRORS) {
		PCIE_DBG("_OSC method failed (STATUS %d)\n", rbuf[0]);
		AcpiOsFree(rb.Pointer);
		return (AE_ERROR);
	}

	*osc_flags = rbuf[2];

	PCIE_DBG("_OSC method evaluation completed for 0x%p: "
	    "STATUS 0x%x SUPPORT 0x%x CONTROL req 0x%x, CONTROL ret 0x%x\n",
	    (void *)dip, rbuf[0], rbuf[1], tmp_ctrl, rbuf[2]);

	AcpiOsFree(rb.Pointer);

	return (AE_OK);
}

/*
 * Checks if _OSC method has been called for this device.
 */
boolean_t
pcie_is_osc(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);
	pcie_x86_priv_t *osc_p = (pcie_x86_priv_t *)bus_p->bus_plat_private;
	return (osc_p->bus_osc);
}

#ifdef DEBUG
static void
pcie_dump_acpi_obj(ACPI_HANDLE pcibus_obj)
{
	int status;
	ACPI_BUFFER retbuf;

	if (pcibus_obj == NULL)
		return;

	/* print the full path name */
	retbuf.Pointer = NULL;
	retbuf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(pcibus_obj, ACPI_FULL_PATHNAME, &retbuf);
	if (status != AE_OK)
		return;
	PCIE_DBG("PCIE BUS PATHNAME: %s\n", (char *)retbuf.Pointer);
	AcpiOsFree(retbuf.Pointer);

	/* dump all the methods for this bus node */
	PCIE_DBG("  METHODS: \n");
	status = AcpiWalkNamespace(ACPI_TYPE_METHOD, pcibus_obj, 1,
	    pcie_print_acpi_name, "  ", NULL);
	/* dump all the child devices */
	status = AcpiWalkNamespace(ACPI_TYPE_DEVICE, pcibus_obj, 1,
	    pcie_walk_obj_namespace, NULL, NULL);
}

/*ARGSUSED*/
static ACPI_STATUS
pcie_walk_obj_namespace(ACPI_HANDLE hdl, uint32_t nl, void *context,
	void **ret)
{
	int status;
	ACPI_BUFFER retbuf;
	char buf[32];

	/* print the full path name */
	retbuf.Pointer = NULL;
	retbuf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiGetName(hdl, ACPI_FULL_PATHNAME, &retbuf);
	if (status != AE_OK)
		return (status);
	buf[0] = 0;
	while (nl--)
		(void) strcat(buf, "  ");
	PCIE_DBG("%sDEVICE: %s\n", buf, (char *)retbuf.Pointer);
	AcpiOsFree(retbuf.Pointer);

	/* dump all the methods for this device */
	PCIE_DBG("%s  METHODS: \n", buf);
	status = AcpiWalkNamespace(ACPI_TYPE_METHOD, hdl, 1,
	    pcie_print_acpi_name, (void *)buf, NULL);
	return (status);
}

/*ARGSUSED*/
static ACPI_STATUS
pcie_print_acpi_name(ACPI_HANDLE hdl, uint32_t nl, void *context, void **ret)
{
	int status;
	ACPI_BUFFER retbuf;
	char name[16];

	retbuf.Pointer = name;
	retbuf.Length = 16;
	status = AcpiGetName(hdl, ACPI_SINGLE_NAME, &retbuf);
	if (status == AE_OK)
		PCIE_DBG("%s    %s \n", (char *)context, name);
	return (AE_OK);
}
#endif /* DEBUG */
