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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Platform specific device enumerator for ACPI specific devices.
 * "x86 system devices" refers to the suite of hardware components which are
 * common to the x86 platform and play important roles in the system
 * architecture but can't be enumerated/discovered through industry-standard
 * bus specifications. Examples of these x86 system devices include:
 *   * Logical processor/CPU
 *   * Memory device
 *   * Non-PCI discoverable IOMMU or DMA Remapping Engine
 *   * Non-PCI discoverable IOxAPIC
 *   * Non-PCI discoverable HPET (High Precision Event Timer)
 *   * ACPI defined devices, including power button, sleep button, battery etc.
 *
 * X86 system devices may be discovered through BIOS/Firmware interfaces, such
 * as SMBIOS tables, MPS tables and ACPI tables since their discovery isn't
 * covered by any industry-standard bus specifications.
 *
 * In order to aid Solaris in flexibly managing x86 system devices,
 * x86 system devices are placed into a specific firmware device
 * subtree whose device path is '/devices/fw'.
 *
 * This driver populates the firmware device subtree with ACPI-discoverable
 * system devices if possible. To achieve that, the ACPI object
 * namespace is abstracted as ACPI virtual buses which host system devices.
 * Another nexus driver for the ACPI virtual bus will manage all devices
 * connected to it.
 *
 * For more detailed information, please refer to PSARC/2009/104.
 */

#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/ddi_subrdefs.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/mutex.h>
#include <sys/note.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_dr.h>
#include <sys/acpidev_impl.h>

/* Patchable through /etc/system */
int acpidev_options = 0;
int acpidev_debug = 0;

krwlock_t acpidev_class_lock;
acpidev_class_list_t *acpidev_class_list_root = NULL;
ulong_t acpidev_object_type_mask[BT_BITOUL(ACPI_TYPE_NS_NODE_MAX + 1)];

/* ACPI device autoconfig global status */
typedef enum acpidev_status {
	ACPIDEV_STATUS_FAILED = -2,	/* ACPI device autoconfig failed */
	ACPIDEV_STATUS_DISABLED = -1,	/* ACPI device autoconfig disabled */
	ACPIDEV_STATUS_UNKNOWN = 0,	/* initial status */
	ACPIDEV_STATUS_INITIALIZED,	/* ACPI device autoconfig initialized */
	ACPIDEV_STATUS_FIRST_PASS,	/* first probing finished */
	ACPIDEV_STATUS_READY		/* second probing finished */
} acpidev_status_t;

static acpidev_status_t acpidev_status = ACPIDEV_STATUS_UNKNOWN;
static kmutex_t	acpidev_drv_lock;
static dev_info_t *acpidev_root_dip = NULL;

/* Boot time ACPI device enumerator. */
static void acpidev_boot_probe(int type);

/* DDI module auto configuration interface */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"ACPI device enumerator"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

int
_init(void)
{
	int err;

	if ((err = mod_install(&modlinkage)) == 0) {
		bzero(acpidev_object_type_mask,
		    sizeof (acpidev_object_type_mask));
		mutex_init(&acpidev_drv_lock, NULL, MUTEX_DRIVER, NULL);
		rw_init(&acpidev_class_lock, NULL, RW_DEFAULT, NULL);
		acpidev_dr_init();
		impl_bus_add_probe(acpidev_boot_probe);
	} else {
		cmn_err(CE_WARN, "!acpidev: failed to install driver.");
	}

	return (err);
}

int
_fini(void)
{
	/* No support for module unload. */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* Check blacklists and load platform specific driver modules. */
static ACPI_STATUS
acpidev_load_plat_modules(void)
{
	return (AE_OK);
}

/* Unload platform specific driver modules. */
static void
acpidev_unload_plat_modules(void)
{
}

/* Unregister all device class drivers from the device driver lists. */
static void
acpidev_class_list_fini(void)
{
	acpidev_unload_plat_modules();

	(void) acpidev_unregister_class(&acpidev_class_list_usbport,
	    &acpidev_class_usbport);

	if ((acpidev_options & ACPIDEV_OUSER_NO_PCI) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_scope,
		    &acpidev_class_pci);
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_pci);
	}

	if ((acpidev_options & ACPIDEV_OUSER_NO_MEM) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_memory);
	}

	if (acpidev_options & ACPIDEV_OUSER_NO_CPU) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_cpu);
		(void) acpidev_unregister_class(&acpidev_class_list_scope,
		    &acpidev_class_cpu);
		(void) acpidev_unregister_class(&acpidev_class_list_root,
		    &acpidev_class_cpu);
	}

	if ((acpidev_options & ACPIDEV_OUSER_NO_CONTAINER) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_container);
	}

	(void) acpidev_unregister_class(&acpidev_class_list_device,
	    &acpidev_class_device);
	(void) acpidev_unregister_class(&acpidev_class_list_root,
	    &acpidev_class_device);

	(void) acpidev_unregister_class(&acpidev_class_list_root,
	    &acpidev_class_scope);
}

/* Register all device class drivers onto the driver lists. */
static ACPI_STATUS
acpidev_class_list_init(uint64_t *fp)
{
	ACPI_STATUS rc = AE_OK;

	/* Set bit in mask for supported object types. */
	BT_SET(acpidev_object_type_mask, ACPI_TYPE_LOCAL_SCOPE);
	BT_SET(acpidev_object_type_mask, ACPI_TYPE_DEVICE);

	/*
	 * Register the ACPI scope class driver onto the class driver lists.
	 * Currently only ACPI scope objects under ACPI root node, such as _PR,
	 * _SB, _TZ etc, need to be handled, so only register the scope class
	 * driver onto the root list.
	 */
	if (ACPI_FAILURE(acpidev_register_class(&acpidev_class_list_root,
	    &acpidev_class_scope, B_FALSE))) {
		goto error_out;
	}

	/*
	 * Register the ACPI device class driver onto the class driver lists.
	 * The ACPI device class driver should be registered at the tail to
	 * handle all device objects which haven't been handled by other
	 * HID/CID specific device class drivers.
	 */
	if (ACPI_FAILURE(acpidev_register_class(&acpidev_class_list_root,
	    &acpidev_class_device, B_TRUE))) {
		goto error_root_device;
	}
	if (ACPI_FAILURE(acpidev_register_class(&acpidev_class_list_device,
	    &acpidev_class_device, B_TRUE))) {
		goto error_device_device;
	}

	/* Check and register support for ACPI container device. */
	if ((acpidev_options & ACPIDEV_OUSER_NO_CONTAINER) == 0) {
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_device, &acpidev_class_container,
		    B_FALSE))) {
			goto error_device_container;
		}
		*fp |= ACPI_DEVCFG_CONTAINER;
	}

	/* Check and register support for ACPI CPU device. */
	if ((acpidev_options & ACPIDEV_OUSER_NO_CPU) == 0) {
		/* Handle ACPI CPU Device */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_device, &acpidev_class_cpu, B_FALSE))) {
			goto error_device_cpu;
		}
		/* Handle ACPI Processor under _PR */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_scope, &acpidev_class_cpu, B_FALSE))) {
			goto error_scope_cpu;
		}
		/* House-keeping for CPU scan */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_root, &acpidev_class_cpu, B_FALSE))) {
			goto error_root_cpu;
		}
		BT_SET(acpidev_object_type_mask, ACPI_TYPE_PROCESSOR);
		*fp |= ACPI_DEVCFG_CPU;
	}

	/* Check support of ACPI memory devices. */
	if ((acpidev_options & ACPIDEV_OUSER_NO_MEM) == 0) {
		/*
		 * Register the ACPI memory class driver onto the
		 * acpidev_class_list_device list because ACPI module
		 * class driver uses that list.
		 */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_device, &acpidev_class_memory,
		    B_FALSE))) {
			goto error_device_memory;
		}
		*fp |= ACPI_DEVCFG_MEMORY;
	}

	/* Check support of PCI/PCIex Host Bridge devices. */
	if ((acpidev_options & ACPIDEV_OUSER_NO_PCI) == 0) {
		/*
		 * Register pci/pciex class drivers onto
		 * the acpidev_class_list_device class list because ACPI
		 * module class driver uses that list.
		 */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_device, &acpidev_class_pci,
		    B_FALSE))) {
			goto error_device_pci;
		}

		/*
		 * Register pci/pciex class drivers onto the
		 * acpidev_class_list_scope class list.
		 */
		if (ACPI_FAILURE(acpidev_register_class(
		    &acpidev_class_list_scope, &acpidev_class_pci,
		    B_FALSE))) {
			goto error_scope_pci;
		}

		*fp |= ACPI_DEVCFG_PCI;
	}

	/* Check support of USB port enumeration */
	if (ACPI_FAILURE(acpidev_register_class(&acpidev_class_list_usbport,
	    &acpidev_class_usbport, B_TRUE))) {
		goto error_usbport;
	}


	/* Check blacklist and load platform specific modules. */
	rc = acpidev_load_plat_modules();
	if (ACPI_FAILURE(rc)) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to check blacklist "
		    "or load pratform modules.");
		goto error_plat;
	}

	return (AE_OK);

error_plat:
	if ((acpidev_options & ACPIDEV_OUSER_NO_PCI) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_scope,
		    &acpidev_class_pci);
	}

error_usbport:
	(void) acpidev_unregister_class(&acpidev_class_list_usbport,
	    &acpidev_class_usbport);

error_scope_pci:
	if ((acpidev_options & ACPIDEV_OUSER_NO_PCI) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_pci);
	}
error_device_pci:
	if ((acpidev_options & ACPIDEV_OUSER_NO_MEM) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_memory);
	}
error_device_memory:
	if (acpidev_options & ACPIDEV_OUSER_NO_CPU) {
		(void) acpidev_unregister_class(&acpidev_class_list_root,
		    &acpidev_class_cpu);
	}
error_root_cpu:
	if (acpidev_options & ACPIDEV_OUSER_NO_CPU) {
		(void) acpidev_unregister_class(&acpidev_class_list_scope,
		    &acpidev_class_cpu);
	}
error_scope_cpu:
	if (acpidev_options & ACPIDEV_OUSER_NO_CPU) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_cpu);
	}
error_device_cpu:
	if ((acpidev_options & ACPIDEV_OUSER_NO_CONTAINER) == 0) {
		(void) acpidev_unregister_class(&acpidev_class_list_device,
		    &acpidev_class_container);
	}
error_device_container:
	(void) acpidev_unregister_class(&acpidev_class_list_device,
	    &acpidev_class_device);
error_device_device:
	(void) acpidev_unregister_class(&acpidev_class_list_root,
	    &acpidev_class_device);
error_root_device:
	(void) acpidev_unregister_class(&acpidev_class_list_root,
	    &acpidev_class_scope);
error_out:
	ACPIDEV_DEBUG(CE_WARN,
	    "!acpidev: failed to register built-in class drivers.");
	*fp = 0;

	return (AE_ERROR);
}

/*
 * Called in single threaded context during boot, no protection for
 * reentrance.
 */
static ACPI_STATUS
acpidev_create_root_node(void)
{
	int circ, rv = AE_OK;
	dev_info_t *dip = NULL;
	acpidev_data_handle_t objhdl;
	char *compatibles[] = {
		ACPIDEV_HID_ROOTNEX,
		ACPIDEV_TYPE_ROOTNEX,
		ACPIDEV_HID_VIRTNEX,
		ACPIDEV_TYPE_VIRTNEX,
	};

	ndi_devi_enter(ddi_root_node(), &circ);
	ASSERT(acpidev_root_dip == NULL);

	/* Query whether device node already exists. */
	dip = ddi_find_devinfo(ACPIDEV_NODE_NAME_ROOT, -1, 0);
	if (dip != NULL && ddi_get_parent(dip) == ddi_root_node()) {
		ndi_devi_exit(ddi_root_node(), circ);
		cmn_err(CE_WARN, "!acpidev: node /devices/%s already exists, "
		    "disable driver.", ACPIDEV_NODE_NAME_ROOT);
		return (AE_ALREADY_EXISTS);
	}

	/* Create the device node if it doesn't exist. */
	rv = ndi_devi_alloc(ddi_root_node(), ACPIDEV_NODE_NAME_ROOT,
	    (pnode_t)DEVI_SID_NODEID, &dip);
	if (rv != NDI_SUCCESS) {
		ndi_devi_exit(ddi_root_node(), circ);
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to create device node "
		    "for ACPI root with errcode %d.", rv);
		return (AE_ERROR);
	}

	/* Build cross reference between dip and ACPI object. */
	if (ACPI_FAILURE(acpica_tag_devinfo(dip, ACPI_ROOT_OBJECT))) {
		(void) ddi_remove_child(dip, 0);
		ndi_devi_exit(ddi_root_node(), circ);
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to tag object %s.",
		    ACPIDEV_OBJECT_NAME_SB);
		return (AE_ERROR);
	}

	/* Set device properties. */
	rv = ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    OBP_COMPATIBLE, ACPIDEV_ARRAY_PARAM(compatibles));
	if (rv == NDI_SUCCESS) {
		rv = ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    OBP_DEVICETYPE, ACPIDEV_TYPE_ROOTNEX);
	}
	if (rv != DDI_SUCCESS) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to set device property for /devices/%s.",
		    ACPIDEV_NODE_NAME_ROOT);
		goto error_out;
	}

	/* Manually create an object handle for the root node */
	objhdl = acpidev_data_create_handle(ACPI_ROOT_OBJECT);
	if (objhdl == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to create object "
		    "handle for the root node.");
		goto error_out;
	}
	objhdl->aod_level = 0;
	objhdl->aod_hdl = ACPI_ROOT_OBJECT;
	objhdl->aod_dip = dip;
	objhdl->aod_class = &acpidev_class_scope;
	objhdl->aod_status = acpidev_query_device_status(ACPI_ROOT_OBJECT);
	objhdl->aod_iflag = ACPIDEV_ODF_STATUS_VALID |
	    ACPIDEV_ODF_DEVINFO_CREATED | ACPIDEV_ODF_DEVINFO_TAGGED;

	/* Bind device driver. */
	(void) ndi_devi_bind_driver(dip, 0);

	acpidev_root_dip = dip;
	ndi_devi_exit(ddi_root_node(), circ);

	return (AE_OK);

error_out:
	(void) acpica_untag_devinfo(dip, ACPI_ROOT_OBJECT);
	(void) ddi_remove_child(dip, 0);
	ndi_devi_exit(ddi_root_node(), circ);
	return (AE_ERROR);
}

static void
acpidev_initialize(void)
{
	int rc;
	char *str = NULL;
	uint64_t features = 0;

	/* Check whether it has already been initialized. */
	if (acpidev_status == ACPIDEV_STATUS_DISABLED) {
		cmn_err(CE_CONT, "?acpidev: ACPI device autoconfig "
		    "disabled by user.\n");
		return;
	} else if (acpidev_status != ACPIDEV_STATUS_UNKNOWN) {
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: initialization called more than once.");
		return;
	}

	/* Check whether ACPI device autoconfig has been disabled by user. */
	rc = ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpidev-autoconfig", &str);
	if (rc == DDI_SUCCESS) {
		if (strcasecmp(str, "off") == 0 || strcasecmp(str, "no") == 0) {
			cmn_err(CE_CONT, "?acpidev: ACPI device autoconfig "
			    "disabled by user.\n");
			ddi_prop_free(str);
			acpidev_status = ACPIDEV_STATUS_DISABLED;
			return;
		}
		ddi_prop_free(str);
	}

	/* Initialize acpica subsystem. */
	if (ACPI_FAILURE(acpica_init())) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to initialize acpica subsystem.");
		acpidev_status = ACPIDEV_STATUS_FAILED;
		return;
	}

	/* Check ACPICA subsystem status. */
	if (!acpica_get_core_feature(ACPI_FEATURE_FULL_INIT)) {
		cmn_err(CE_WARN, "!acpidev: ACPICA hasn't been fully "
		    "initialized, ACPI device autoconfig will be disabled.");
		acpidev_status = ACPIDEV_STATUS_DISABLED;
		return;
	}

	/* Converts acpidev-options from type string to int, if any */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpidev-options", &str) == DDI_PROP_SUCCESS) {
		long data;
		rc = ddi_strtol(str, NULL, 0, &data);
		if (rc == 0) {
			(void) e_ddi_prop_remove(DDI_DEV_T_NONE,
			    ddi_root_node(), "acpidev-options");
			(void) e_ddi_prop_update_int(DDI_DEV_T_NONE,
			    ddi_root_node(), "acpidev-options", data);
		}
		ddi_prop_free(str);
	}
	/* Get acpidev_options user options. */
	acpidev_options = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpidev-options", acpidev_options);

	/* Check whether ACPI based DR has been disabled by user. */
	rc = ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpidev-dr", &str);
	if (rc == DDI_SUCCESS) {
		if (strcasecmp(str, "off") == 0 || strcasecmp(str, "no") == 0) {
			cmn_err(CE_CONT, "?acpidev: ACPI based DR has been "
			    "disabled by user.\n");
			acpidev_dr_enable = 0;
		}
		ddi_prop_free(str);
	}

	/* Register all device class drivers. */
	if (ACPI_FAILURE(acpidev_class_list_init(&features))) {
		cmn_err(CE_WARN,
		    "!acpidev: failed to initalize class driver lists.");
		acpidev_status = ACPIDEV_STATUS_FAILED;
		return;
	}

	/* Create root node for ACPI/firmware device subtree. */
	if (ACPI_FAILURE(acpidev_create_root_node())) {
		cmn_err(CE_WARN, "!acpidev: failed to create root node "
		    "for acpi device tree.");
		acpidev_class_list_fini();
		acpidev_status = ACPIDEV_STATUS_FAILED;
		return;
	}

	/* Notify acpica to enable ACPI device auto configuration. */
	acpica_set_core_feature(ACPI_FEATURE_DEVCFG);
	acpica_set_devcfg_feature(features);

	ACPIDEV_DEBUG(CE_NOTE, "!acpidev: ACPI device autoconfig initialized.");
	acpidev_status = ACPIDEV_STATUS_INITIALIZED;
}

/*
 * Probe devices in ACPI namespace which can't be enumerated by other methods
 * at boot time.
 */
static ACPI_STATUS
acpidev_boot_probe_device(acpidev_op_type_t op_type)
{
	ACPI_STATUS rc = AE_OK;
	acpidev_walk_info_t *infop;

	ASSERT(acpidev_root_dip != NULL);
	ASSERT(op_type == ACPIDEV_OP_BOOT_PROBE ||
	    op_type == ACPIDEV_OP_BOOT_REPROBE);

	infop = acpidev_alloc_walk_info(op_type, 0, ACPI_ROOT_OBJECT,
	    &acpidev_class_list_root, NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to allocate walk info "
		    "object in acpi_boot_probe_device().");
		return (AE_ERROR);
	}
	/* Enumerate ACPI devices. */
	rc = acpidev_probe_child(infop);
	if (ACPI_FAILURE(rc)) {
		cmn_err(CE_WARN, "!acpidev: failed to probe child object "
		    "under ACPI root node.");
	}
	acpidev_free_walk_info(infop);

	return (rc);
}

/*
 * Platform specific device prober for ACPI virtual bus.
 * It will be called in single-threaded environment to enumerate devices in
 * ACPI namespace at boot time.
 */
static void
acpidev_boot_probe(int type)
{
	ACPI_STATUS rc;

	/* Initialize subsystem on first pass. */
	mutex_enter(&acpidev_drv_lock);
	if (type == 0) {
		acpidev_initialize();
		if (acpidev_status != ACPIDEV_STATUS_INITIALIZED &&
		    acpidev_status != ACPIDEV_STATUS_DISABLED) {
			cmn_err(CE_WARN, "!acpidev: driver disabled due to "
			    "initalization failure.");
		}
	}

	/* Probe ACPI devices */
	if (type == 0 && acpidev_status == ACPIDEV_STATUS_INITIALIZED) {
		rc = acpidev_boot_probe_device(ACPIDEV_OP_BOOT_PROBE);
		if (ACPI_SUCCESS(rc)) {
			/*
			 * Support of DR operations will be disabled
			 * if failed to initialize DR subsystem.
			 */
			rc = acpidev_dr_initialize(acpidev_root_dip);
			if (ACPI_FAILURE(rc) && rc != AE_SUPPORT) {
				cmn_err(CE_CONT, "?acpidev: failed to "
				    "initialize DR subsystem.");
			}
			acpidev_status = ACPIDEV_STATUS_FIRST_PASS;
		} else {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to probe ACPI "
			    "devices during boot.");
			acpidev_status = ACPIDEV_STATUS_FAILED;
		}
	} else if (type != 0 && acpidev_status == ACPIDEV_STATUS_FIRST_PASS) {
		rc = acpidev_boot_probe_device(ACPIDEV_OP_BOOT_REPROBE);
		if (ACPI_SUCCESS(rc)) {
			acpidev_status = ACPIDEV_STATUS_READY;
		} else {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to reprobe "
			    "ACPI devices during boot.");
			acpidev_status = ACPIDEV_STATUS_FAILED;
		}
	} else if (acpidev_status != ACPIDEV_STATUS_FAILED &&
	    acpidev_status != ACPIDEV_STATUS_DISABLED &&
	    acpidev_status != ACPIDEV_STATUS_READY) {
		cmn_err(CE_WARN,
		    "!acpidev: invalid ACPI device autoconfig global status.");
	}
	mutex_exit(&acpidev_drv_lock);
}

ACPI_STATUS
acpidev_probe_child(acpidev_walk_info_t *infop)
{
	int circ;
	dev_info_t *pdip;
	ACPI_STATUS res, rc = AE_OK;
	ACPI_HANDLE child;
	ACPI_OBJECT_TYPE type;
	acpidev_class_list_t *it;
	acpidev_walk_info_t *cinfop;
	acpidev_data_handle_t datap;

	/* Validate parameter first. */
	ASSERT(infop != NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: infop is NULL in acpidev_probe_child().");
		return (AE_BAD_PARAMETER);
	}
	ASSERT(infop->awi_level < ACPIDEV_MAX_ENUM_LEVELS - 1);
	if (infop->awi_level >= ACPIDEV_MAX_ENUM_LEVELS - 1) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: recursive level is too deep "
		    "in acpidev_probe_child().");
		return (AE_BAD_PARAMETER);
	}
	ASSERT(infop->awi_class_list != NULL);
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);
	ASSERT(infop->awi_name != NULL);
	ASSERT(infop->awi_data != NULL);
	if (infop->awi_class_list == NULL || infop->awi_hdl == NULL ||
	    infop->awi_info == NULL || infop->awi_name == NULL ||
	    infop->awi_data == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: infop has NULL fields in "
		    "acpidev_probe_child().");
		return (AE_BAD_PARAMETER);
	}
	pdip = acpidev_walk_info_get_pdip(infop);
	if (pdip == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: pdip is NULL in acpidev_probe_child().");
		return (AE_BAD_PARAMETER);
	}

	ndi_devi_enter(pdip, &circ);
	rw_enter(&acpidev_class_lock, RW_READER);

	/* Call pre-probe callback functions. */
	for (it = *(infop->awi_class_list); it != NULL; it = it->acl_next) {
		if (it->acl_class->adc_pre_probe == NULL) {
			continue;
		}
		infop->awi_class_curr = it->acl_class;
		if (ACPI_FAILURE(it->acl_class->adc_pre_probe(infop))) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to pre-probe "
			    "device of type %s under %s.",
			    it->acl_class->adc_class_name, infop->awi_name);
		}
	}

	/* Walk child objects. */
	child = NULL;
	while (ACPI_SUCCESS(AcpiGetNextObject(ACPI_TYPE_ANY,
	    infop->awi_hdl, child, &child))) {
		/* Skip object if we're not interested in it. */
		if (ACPI_FAILURE(AcpiGetType(child, &type)) ||
		    type > ACPI_TYPE_NS_NODE_MAX ||
		    BT_TEST(acpidev_object_type_mask, type) == 0) {
			continue;
		}

		/* It's another hotplug-capable board, skip it. */
		if (infop->awi_op_type == ACPIDEV_OP_HOTPLUG_PROBE &&
		    acpidev_dr_device_is_board(child)) {
			continue;
		}

		/* Allocate the walk info structure. */
		cinfop = acpidev_alloc_walk_info(infop->awi_op_type,
		    infop->awi_level + 1, child, NULL, infop);
		if (cinfop == NULL) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to allocate "
			    "walk info child object of %s.",
			    infop->awi_name);
			/* Mark error and continue to handle next child. */
			rc = AE_ERROR;
			continue;
		}

		/*
		 * Remember the class list used to handle this object.
		 * It should be the same list for different passes of scans.
		 */
		ASSERT(cinfop->awi_data != NULL);
		datap = cinfop->awi_data;
		if (cinfop->awi_op_type == ACPIDEV_OP_BOOT_PROBE) {
			datap->aod_class_list = infop->awi_class_list;
		}

		/* Call registered process callbacks. */
		for (it = *(infop->awi_class_list); it != NULL;
		    it = it->acl_next) {
			if (it->acl_class->adc_probe == NULL) {
				continue;
			}
			cinfop->awi_class_curr = it->acl_class;
			res = it->acl_class->adc_probe(cinfop);
			if (ACPI_FAILURE(res)) {
				rc = res;
				ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to "
				    "process object of type %s under %s.",
				    it->acl_class->adc_class_name,
				    infop->awi_name);
			}
		}

		/* Free resources. */
		acpidev_free_walk_info(cinfop);
	}

	/* Call post-probe callback functions. */
	for (it = *(infop->awi_class_list); it != NULL; it = it->acl_next) {
		if (it->acl_class->adc_post_probe == NULL) {
			continue;
		}
		infop->awi_class_curr = it->acl_class;
		if (ACPI_FAILURE(it->acl_class->adc_post_probe(infop))) {
			ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to post-probe "
			    "device of type %s under %s.",
			    it->acl_class->adc_class_name, infop->awi_name);
		}
	}

	rw_exit(&acpidev_class_lock);
	ndi_devi_exit(pdip, circ);

	return (rc);
}

ACPI_STATUS
acpidev_process_object(acpidev_walk_info_t *infop, int flags)
{
	ACPI_STATUS rc = AE_OK;
	char *devname;
	dev_info_t *dip, *pdip;
	ACPI_HANDLE hdl;
	ACPI_DEVICE_INFO *adip;
	acpidev_class_t *clsp;
	acpidev_data_handle_t datap;
	acpidev_filter_result_t res;

	/* Validate parameters first. */
	ASSERT(infop != NULL);
	if (infop == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: infop is NULL in acpidev_process_object().");
		return (AE_BAD_PARAMETER);
	}
	ASSERT(infop->awi_hdl != NULL);
	ASSERT(infop->awi_info != NULL);
	ASSERT(infop->awi_data != NULL);
	ASSERT(infop->awi_class_curr != NULL);
	ASSERT(infop->awi_class_curr->adc_filter != NULL);
	hdl = infop->awi_hdl;
	adip = infop->awi_info;
	datap = infop->awi_data;
	clsp = infop->awi_class_curr;
	if (hdl == NULL || datap == NULL || adip == NULL || clsp == NULL ||
	    clsp->adc_filter == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: infop has NULL pointer in "
		    "acpidev_process_object().");
		return (AE_BAD_PARAMETER);
	}
	pdip = acpidev_walk_info_get_pdip(infop);
	if (pdip == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: failed to get pdip for %s "
		    "in acpidev_process_object().", infop->awi_name);
		return (AE_BAD_PARAMETER);
	}

	/*
	 * Check whether the object has already been handled.
	 * Tag and child dip pointer are used to indicate the object has been
	 * handled by the ACPI auto configure driver. It has the
	 * following usages:
	 * 1) Prevent creating dip for objects which already have a dip
	 *    when reloading the ACPI auto configure driver.
	 * 2) Prevent creating multiple dips for ACPI objects with ACPI
	 *    aliases. Currently ACPICA framework has no way to tell whether
	 *    an object is an alias or not for some types of object. So tag
	 *    is used to indicate that the object has been handled.
	 * 3) Prevent multiple class drivers from creating multiple devices for
	 *    the same ACPI object.
	 */
	if ((flags & ACPIDEV_PROCESS_FLAG_CREATE) &&
	    (flags & ACPIDEV_PROCESS_FLAG_CHECK) &&
	    !(infop->awi_flags & ACPIDEV_WI_DISABLE_CREATE) &&
	    (infop->awi_flags & ACPIDEV_WI_DEVICE_CREATED)) {
		ASSERT(infop->awi_dip != NULL);
		ACPIDEV_DEBUG(CE_NOTE,
		    "!acpidev: device has already been created for object %s.",
		    infop->awi_name);
		return (AE_ALREADY_EXISTS);
	}

	/*
	 * Determine action according to following rules based on device
	 * status returned by _STA method. Please refer to ACPI3.0b section
	 * 6.3.1 and 6.5.1.
	 * present functioning enabled	Action
	 *	0	0	x	Do nothing
	 *	1	x	0	Do nothing
	 *	1	x	1	Create node and scan child
	 *	x	1	0	Do nothing
	 *	x	1	1	Create node and scan child
	 */
	if ((datap->aod_iflag & ACPIDEV_ODF_STATUS_VALID) == 0 ||
	    (flags & ACPIDEV_PROCESS_FLAG_SYNCSTATUS)) {
		datap->aod_status = acpidev_query_device_status(hdl);
		datap->aod_iflag |= ACPIDEV_ODF_STATUS_VALID;
	}
	if (!acpidev_check_device_enabled(datap->aod_status)) {
		ACPIDEV_DEBUG(CE_NOTE, "!acpidev: object %s doesn't exist.",
		    infop->awi_name);
		/*
		 * Need to scan for hotplug-capable boards even if object
		 * doesn't exist or has been disabled during the first pass.
		 * So just disable creating device node and keep on scanning.
		 */
		if (infop->awi_op_type == ACPIDEV_OP_BOOT_PROBE) {
			flags &= ~ACPIDEV_PROCESS_FLAG_CREATE;
		} else {
			return (AE_NOT_EXIST);
		}
	}

	ASSERT(infop->awi_data != NULL);
	ASSERT(infop->awi_parent != NULL);
	ASSERT(infop->awi_parent->awi_data != NULL);
	if (flags & ACPIDEV_PROCESS_FLAG_CREATE) {
		mutex_enter(&(DEVI(pdip)->devi_lock));
		/*
		 * Put the device into offline state if its parent is in
		 * offline state.
		 */
		if (DEVI_IS_DEVICE_OFFLINE(pdip)) {
			flags |= ACPIDEV_PROCESS_FLAG_OFFLINE;
		}
		mutex_exit(&(DEVI(pdip)->devi_lock));
	}

	/* Evaluate filtering rules and generate device name. */
	devname = kmem_zalloc(ACPIDEV_MAX_NAMELEN + 1, KM_SLEEP);
	(void) memcpy(devname, (char *)&adip->Name, sizeof (adip->Name));
	if (flags & ACPIDEV_PROCESS_FLAG_CREATE) {
		res = clsp->adc_filter(infop, devname, ACPIDEV_MAX_NAMELEN);
	} else {
		res = clsp->adc_filter(infop, NULL, 0);
	}

	/* Create device if requested. */
	if ((flags & ACPIDEV_PROCESS_FLAG_CREATE) &&
	    !(infop->awi_flags & ACPIDEV_WI_DISABLE_CREATE) &&
	    !(infop->awi_flags & ACPIDEV_WI_DEVICE_CREATED) &&
	    (res == ACPIDEV_FILTER_DEFAULT || res == ACPIDEV_FILTER_CREATE)) {
		int ret;

		/*
		 * Allocate dip and set default properties.
		 * Properties can be overriden in class specific init routines.
		 */
		ASSERT(infop->awi_dip == NULL);
		ndi_devi_alloc_sleep(pdip, devname, (pnode_t)DEVI_SID_NODEID,
		    &dip);
		infop->awi_dip = dip;
		ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    OBP_DEVICETYPE, clsp->adc_dev_type);
		if (ret != NDI_SUCCESS) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to set device property for %s.",
			    infop->awi_name);
			(void) ddi_remove_child(dip, 0);
			infop->awi_dip = NULL;
			kmem_free(devname, ACPIDEV_MAX_NAMELEN + 1);
			return (AE_ERROR);
		}

		/* Build cross reference between dip and ACPI object. */
		if ((flags & ACPIDEV_PROCESS_FLAG_NOTAG) == 0 &&
		    ACPI_FAILURE(acpica_tag_devinfo(dip, hdl))) {
			cmn_err(CE_WARN,
			    "!acpidev: failed to tag object %s.",
			    infop->awi_name);
			(void) ddi_remove_child(dip, 0);
			infop->awi_dip = NULL;
			kmem_free(devname, ACPIDEV_MAX_NAMELEN + 1);
			return (AE_ERROR);
		}

		/* Call class specific initialization callback. */
		if (clsp->adc_init != NULL &&
		    ACPI_FAILURE(clsp->adc_init(infop))) {
			ACPIDEV_DEBUG(CE_WARN,
			    "!acpidev: failed to initialize device %s.",
			    infop->awi_name);
			if ((flags & ACPIDEV_PROCESS_FLAG_NOTAG) == 0) {
				(void) acpica_untag_devinfo(dip, hdl);
			}
			(void) ddi_remove_child(dip, 0);
			infop->awi_dip = NULL;
			kmem_free(devname, ACPIDEV_MAX_NAMELEN + 1);
			return (AE_ERROR);
		}

		/* Set device into offline state if requested. */
		if (flags & ACPIDEV_PROCESS_FLAG_OFFLINE) {
			mutex_enter(&(DEVI(dip)->devi_lock));
			DEVI_SET_DEVICE_OFFLINE(dip);
			mutex_exit(&(DEVI(dip)->devi_lock));
		}

		/* Mark status */
		infop->awi_flags |= ACPIDEV_WI_DEVICE_CREATED;
		datap->aod_iflag |= ACPIDEV_ODF_DEVINFO_CREATED;
		datap->aod_dip = dip;
		datap->aod_class = clsp;
		/* Hold reference count on class driver. */
		atomic_inc_32(&clsp->adc_refcnt);
		if ((flags & ACPIDEV_PROCESS_FLAG_NOTAG) == 0) {
			datap->aod_iflag |= ACPIDEV_ODF_DEVINFO_TAGGED;
		}

		/* Bind device driver. */
		if ((flags & ACPIDEV_PROCESS_FLAG_NOBIND) != 0) {
			mutex_enter(&(DEVI(dip)->devi_lock));
			DEVI(dip)->devi_flags |= DEVI_NO_BIND;
			mutex_exit(&(DEVI(dip)->devi_lock));
		} else {
			(void) ndi_devi_bind_driver(dip, 0);
		}

		/* Hold reference on branch when hot-adding devices. */
		if (flags & ACPIDEV_PROCESS_FLAG_HOLDBRANCH) {
			e_ddi_branch_hold(dip);
		}
	}

	/* Free resources */
	kmem_free(devname, ACPIDEV_MAX_NAMELEN + 1);
	rc = AE_OK;

	/* Recursively scan child objects if requested. */
	switch (res) {
	case ACPIDEV_FILTER_DEFAULT:
		/* FALLTHROUGH */
	case ACPIDEV_FILTER_SCAN:
		/* Check if we need to scan child. */
		if ((flags & ACPIDEV_PROCESS_FLAG_SCAN) &&
		    !(infop->awi_flags & ACPIDEV_WI_DISABLE_SCAN) &&
		    !(infop->awi_flags & ACPIDEV_WI_CHILD_SCANNED)) {
			/* probe child object. */
			rc = acpidev_probe_child(infop);
			if (ACPI_FAILURE(rc)) {
				ACPIDEV_DEBUG(CE_WARN,
				    "!acpidev: failed to probe subtree of %s.",
				    infop->awi_name);
				rc = AE_ERROR;
			}
			/* Mark object as scanned. */
			infop->awi_flags |= ACPIDEV_WI_CHILD_SCANNED;
		}
		break;

	case ACPIDEV_FILTER_CREATE:
		/* FALLTHROUGH */
	case ACPIDEV_FILTER_CONTINUE:
		/* FALLTHROUGH */
	case ACPIDEV_FILTER_SKIP:
		break;

	case ACPIDEV_FILTER_FAILED:
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: failed to probe device for %s.",
		    infop->awi_name);
		rc = AE_ERROR;
		break;

	default:
		cmn_err(CE_WARN,
		    "!acpidev: unknown filter result code %d.", res);
		rc = AE_ERROR;
		break;
	}

	return (rc);
}

acpidev_filter_result_t
acpidev_filter_default(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, char *devname, int len)
{
	_NOTE(ARGUNUSED(hdl));

	ASSERT(afrp != NULL);
	ASSERT(devname == NULL || len >= ACPIDEV_MAX_NAMELEN);
	if (infop->awi_level < afrp->adf_minlvl ||
	    infop->awi_level > afrp->adf_maxlvl) {
		return (ACPIDEV_FILTER_CONTINUE);
	} else if (afrp->adf_pattern != NULL &&
	    strncmp(afrp->adf_pattern,
	    (char *)&infop->awi_info->Name,
	    sizeof (infop->awi_info->Name))) {
		return (ACPIDEV_FILTER_CONTINUE);
	}
	if (afrp->adf_replace != NULL && devname != NULL) {
		(void) strlcpy(devname, afrp->adf_replace, len);
	}

	return (afrp->adf_retcode);
}

acpidev_filter_result_t
acpidev_filter_device(acpidev_walk_info_t *infop, ACPI_HANDLE hdl,
    acpidev_filter_rule_t *afrp, int entries, char *devname, int len)
{
	acpidev_filter_result_t res;

	res = ACPIDEV_FILTER_FAILED;
	/* Evaluate filtering rules. */
	for (; entries > 0; entries--, afrp++) {
		if (afrp->adf_filter_func != NULL) {
			res = afrp->adf_filter_func(infop, hdl, afrp,
			    devname, len);
		} else {
			res = acpidev_filter_default(infop, hdl, afrp,
			    devname, len);
		}
		if (res == ACPIDEV_FILTER_DEFAULT ||
		    res == ACPIDEV_FILTER_SCAN) {
			infop->awi_class_list = afrp->adf_class_list;
			break;
		}
	}

	return (res);
}

dev_info_t *
acpidev_root_node(void)
{
	return (acpidev_root_dip);
}

ACPI_STATUS
acpidev_register_class(acpidev_class_list_t **listpp, acpidev_class_t *clsp,
    boolean_t tail)
{
	ACPI_STATUS rc;
	acpidev_class_list_t *item;
	acpidev_class_list_t *temp;

	ASSERT(clsp != NULL);
	ASSERT(listpp != NULL);
	if (listpp == NULL || clsp == NULL) {
		ACPIDEV_DEBUG(CE_WARN,
		    "!acpidev: invalid parameter in acpidev_register_class().");
		return (AE_BAD_PARAMETER);
	} else if (clsp->adc_version != ACPIDEV_CLASS_REV) {
		cmn_err(CE_WARN,
		    "!acpidev: class driver %s version mismatch.",
		    clsp->adc_class_name);
		return (AE_BAD_DATA);
	}

	rc = AE_OK;
	item = kmem_zalloc(sizeof (*item), KM_SLEEP);
	item->acl_class = clsp;
	rw_enter(&acpidev_class_lock, RW_WRITER);
	/* Check for duplicated item. */
	for (temp = *listpp; temp != NULL; temp = temp->acl_next) {
		if (temp->acl_class == clsp) {
			cmn_err(CE_WARN,
			    "!acpidev: register duplicate class driver %s.",
			    clsp->adc_class_name);
			rc = AE_ALREADY_EXISTS;
			break;
		}
	}
	if (ACPI_SUCCESS(rc)) {
		if (tail) {
			while (*listpp) {
				listpp = &(*listpp)->acl_next;
			}
		}
		item->acl_next = *listpp;
		*listpp = item;
	}
	rw_exit(&acpidev_class_lock);
	if (ACPI_FAILURE(rc)) {
		kmem_free(item, sizeof (*item));
	}

	return (rc);
}

ACPI_STATUS
acpidev_unregister_class(acpidev_class_list_t **listpp,
    acpidev_class_t *clsp)
{
	ACPI_STATUS rc = AE_NOT_FOUND;
	acpidev_class_list_t *temp;

	ASSERT(clsp != NULL);
	ASSERT(listpp != NULL);
	if (listpp == NULL || clsp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: invalid parameter "
		    "in acpidev_unregister_class().");
		return (AE_BAD_PARAMETER);
	}

	rw_enter(&acpidev_class_lock, RW_WRITER);
	for (temp = NULL; *listpp; listpp = &(*listpp)->acl_next) {
		if ((*listpp)->acl_class == clsp) {
			temp = *listpp;
			*listpp = (*listpp)->acl_next;
			break;
		}
	}
	if (temp == NULL) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: class %p(%s) doesn't exist "
		    "in acpidev_unregister_class().",
		    (void *)clsp, clsp->adc_class_name);
		rc = AE_NOT_FOUND;
	} else if (temp->acl_class->adc_refcnt != 0) {
		ACPIDEV_DEBUG(CE_WARN, "!acpidev: class %p(%s) is still in use "
		    "in acpidev_unregister_class()..",
		    (void *)clsp, clsp->adc_class_name);
		rc = AE_ERROR;
	} else {
		kmem_free(temp, sizeof (*temp));
		rc = AE_OK;
	}
	rw_exit(&acpidev_class_lock);

	return (rc);
}
