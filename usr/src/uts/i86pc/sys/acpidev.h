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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_ACPIDEV_H
#define	_SYS_ACPIDEV_H
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#ifdef	_KERNEL
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum recursion levels when enumerating objects in ACPI namespace. */
#define	ACPIDEV_MAX_ENUM_LEVELS		32

/* Maximum length of device name for ACPI object. */
#define	ACPIDEV_MAX_NAMELEN		OBP_MAXDRVNAME

/* Pseudo ACPI device HID for ACPI root object. */
#define	ACPIDEV_HID_ROOTNEX		"SOLA0001"
/* Pseudo ACPI device HID for ACPI virtual bus. */
#define	ACPIDEV_HID_VIRTNEX		"SOLA0002"
#define	ACPIDEV_HID_SCOPE		"SOLA0003"
#define	ACPIDEV_HID_PROCESSOR		"SOLA0004"

/* ACPI device HIDs/CIDs defined by ACPI specification. */
#define	ACPIDEV_HID_CONTAINER1		"PNP0A05"
#define	ACPIDEV_HID_CONTAINER2		"PNP0A06"
#define	ACPIDEV_HID_MODULE		"ACPI0004"
#define	ACPIDEV_HID_CPU			"ACPI0007"
#define	ACPIDEV_HID_PCI_HOSTBRIDGE	"PNP0A03"
#define	ACPIDEV_HID_PCIE_HOSTBRIDGE	"PNP0A08"
#define	ACPIDEV_HID_PCIEX_HOSTBRIDGE	"PNP0A08"
#define	ACPIDEV_HID_MEMORY		"PNP0C80"

/* Device names for ACPI objects. */
#define	ACPIDEV_NODE_NAME_ROOT		"fw"
#define	ACPIDEV_NODE_NAME_ACPIDR	"acpidr"
#define	ACPIDEV_NODE_NAME_CONTAINER	"container"
#define	ACPIDEV_NODE_NAME_MODULE_SBD	"sb"
#define	ACPIDEV_NODE_NAME_MODULE_CPU	"socket"
#define	ACPIDEV_NODE_NAME_CPU		"cpu"
#define	ACPIDEV_NODE_NAME_PROCESSOR	"cpus"
#define	ACPIDEV_NODE_NAME_MEMORY	"mem"
#define	ACPIDEV_NODE_NAME_PCI		"pci"

/* Device types for ACPI objects. */
#define	ACPIDEV_TYPE_ROOTNEX		"acpirootnex"
#define	ACPIDEV_TYPE_VIRTNEX		"acpivirtnex"
#define	ACPIDEV_TYPE_SCOPE		"acpiscope"
#define	ACPIDEV_TYPE_DEVICE		"acpidevice"
#define	ACPIDEV_TYPE_CONTAINER		"acpicontainer"
#define	ACPIDEV_TYPE_CPU		"acpicpu"
#define	ACPIDEV_TYPE_MEMORY		"acpimemory"
#define	ACPIDEV_TYPE_PCI		"pci"
#define	ACPIDEV_TYPE_PCIEX		"pciex"

/* Device property names for ACPI objects. */
#define	ACPIDEV_PROP_NAME_UNIT_ADDR	"unit-address"
#define	ACPIDEV_PROP_NAME_ACPI_UID	"acpi-uid"
#define	ACPIDEV_PROP_NAME_PROCESSOR_ID	"acpi-processor-id"
#define	ACPIDEV_PROP_NAME_LOCALAPIC_ID	"apic-id"
#define	ACPIDEV_PROP_NAME_PROXIMITY_ID	"proximity-id"

#define	ACPIDEV_PROP_NAME_UID_FORMAT	"acpidev-uid-format"

/* Miscellaneous strings. */
#define	ACPIDEV_CMD_OST_PREFIX		"acpi-update-status"
#define	ACPIDEV_CMD_OST_INPROGRESS	"acpi-update-status=inprogress"
#define	ACPIDEV_CMD_OST_SUCCESS		"acpi-update-status=success"
#define	ACPIDEV_CMD_OST_FAILURE		"acpi-update-status=failure"
#define	ACPIDEV_CMD_OST_NOOP		"acpi-update-status=noop"

#define	ACPIDEV_EVENT_TYPE_ATTR_NAME	"acpi-event-type"
#define	ACPIDEV_EVENT_TYPE_BUS_CHECK	"bus_check"
#define	ACPIDEV_EVENT_TYPE_DEVICE_CHECK	"device_check"
#define	ACPIDEV_EVENT_TYPE_DEVICE_CHECK_LIGHT	"device_check_light"
#define	ACPIDEV_EVENT_TYPE_EJECT_REQUEST	"eject_request"

/* ACPI device class Id. */
typedef enum acpidev_class_id {
	ACPIDEV_CLASS_ID_INVALID = 0,
	ACPIDEV_CLASS_ID_ROOTNEX = 1,
	ACPIDEV_CLASS_ID_SCOPE = 2,
	ACPIDEV_CLASS_ID_DEVICE = 3,
	ACPIDEV_CLASS_ID_CONTAINER = 4,
	ACPIDEV_CLASS_ID_CPU = 5,
	ACPIDEV_CLASS_ID_MEMORY = 6,
	ACPIDEV_CLASS_ID_PCI = 7,
	ACPIDEV_CLASS_ID_PCIEX = 8,
	ACPIDEV_CLASS_ID_MAX
} acpidev_class_id_t;

/* Flags for acpidev_options boot options. */
#define	ACPIDEV_OUSER_NO_CPU		0x1
#define	ACPIDEV_OUSER_NO_MEM		0x2
#define	ACPIDEV_OUSER_NO_CONTAINER	0x4
#define	ACPIDEV_OUSER_NO_PCI		0x8
#define	ACPIDEV_OUSER_NO_CACHE		0x10000

#ifdef	_KERNEL

/* Common ACPI object names. */
#define	ACPIDEV_OBJECT_NAME_SB		METHOD_NAME__SB_
#define	ACPIDEV_OBJECT_NAME_PR		"_PR_"

/* Common ACPI method names. */
#define	ACPIDEV_METHOD_NAME_MAT		"_MAT"
#define	ACPIDEV_METHOD_NAME_EJ0		"_EJ0"
#define	ACPIDEV_METHOD_NAME_EDL		"_EDL"
#define	ACPIDEV_METHOD_NAME_EJD		"_EJD"
#define	ACPIDEV_METHOD_NAME_OST		"_OST"
#define	ACPIDEV_METHOD_NAME_PXM		"_PXM"
#define	ACPIDEV_METHOD_NAME_SLI		"_SLI"

/* Source event code for _OST. */
#define	ACPI_OST_EVENT_EJECTING		0x103
#define	ACPI_OST_EVENT_INSERTING	0x200

/* Status code for _OST. */
#define	ACPI_OST_STA_SUCCESS		0x0

/* Non-specific failure. */
#define	ACPI_OST_STA_FAILURE		0x1

/* Unrecognized Notify Code. */
#define	ACPI_OST_STA_NOT_SUPPORT	0x2

/* Device ejection not supported by OSPM. */
#define	ACPI_OST_STA_EJECT_NOT_SUPPORT	0x80

/* Device in use by application. */
#define	ACPI_OST_STA_EJECT_IN_USE	0x81

/* Device Busy. */
#define	ACPI_OST_STA_EJECT_BUSY		0x82

/* Ejection dependency is busy or not supported for ejection by OSPM. */
#define	ACPI_OST_STA_EJECT_DEPENDENCY	0x83

/* Ejection is in progress (pending). */
#define	ACPI_OST_STA_EJECT_IN_PROGRESS	0x84

/* Device insertion in progress (pending). */
#define	ACPI_OST_STA_INSERT_IN_PROGRESS	0x80

/* Device driver load failure. */
#define	ACPI_OST_STA_INSERT_DRIVER	0x81

/* Device insertion not supported by OSPM. */
#define	ACPI_OST_STA_INSERT_NOT_SUPPORT	0x82

/*
 * Insertion failure
 * Resources Unavailable as described by the following bit encodings:
 * Bit[3] Bus Numbers
 * Bit[2] Interrupts
 * Bit[1] I/O
 * Bit[0] Memory
 */
#define	ACPI_OST_STA_INSERT_NO_RESOURCE	0x90
#define	ACPI_OST_STA_INSERT_NO_BUS	0x8
#define	ACPI_OST_STA_INSERT_NO_INTR	0x4
#define	ACPI_OST_STA_INSERT_NO_IO	0x2
#define	ACPI_OST_STA_INSERT_NO_MEM	0x1

/*
 * According to the ACPI specification, self latency (entry[n][n]) in the
 * SLIT table should be 10.
 */
#define	ACPI_SLIT_SELF_LATENCY		10

/*
 * The DR driver assigns a unique device id for each hot-added memory device.
 * ACPI_MEMNODE_DEVID_BOOT is assigned to memory devices present at boot,
 * which is distinguished from device ids assigned by the DR driver.
 */
#define	ACPI_MEMNODE_DEVID_BOOT		UINT32_MAX

/* Forward declaration */
typedef	struct acpidev_data_impl	*acpidev_data_handle_t;
typedef struct acpidev_walk_info	acpidev_walk_info_t;
typedef struct acpidev_filter_rule	acpidev_filter_rule_t;
typedef struct acpidev_class		acpidev_class_t;
typedef struct acpidev_class_list	acpidev_class_list_t;

/* Type of ACPI device enumerating operation. */
typedef enum acpidev_op_type {
	ACPIDEV_OP_BOOT_PROBE = 0,	/* First pass probing at boot time. */
	ACPIDEV_OP_BOOT_REPROBE,	/* Second pass probing at boot time. */
	ACPIDEV_OP_HOTPLUG_PROBE	/* Probing for hotplug at runtime. */
} acpidev_op_type_t;

/*
 * Structure to pass arguments when enumerating ACPI namespace.
 */
struct acpidev_walk_info {
	/* Always valid for all callbacks. */
	acpidev_op_type_t		awi_op_type;
	int				awi_level;
	acpidev_walk_info_t		*awi_parent;
	acpidev_class_t			*awi_class_curr;

	/* Valid for all callbacks except pre_probe and post_probe. */
	int				awi_flags;
	ACPI_HANDLE			awi_hdl;
	ACPI_DEVICE_INFO		*awi_info;
	char				*awi_name;
	acpidev_data_handle_t		awi_data;

	/* Need to validate it before access. */
	dev_info_t			*awi_dip;
	acpidev_class_list_t		**awi_class_list;

	/* Used by class to store data temporarily. */
	intptr_t			awi_scratchpad[4];
};

/* Disable creating device nodes for ACPI objects. */
#define	ACPIDEV_WI_DISABLE_CREATE	0x1
/* Device node has already been created for an ACPI object. */
#define	ACPIDEV_WI_DEVICE_CREATED	0x2
/* Disable enumerating children of ACPI objects. */
#define	ACPIDEV_WI_DISABLE_SCAN		0x10
/* Children of ACPI objects have already been enumerated. */
#define	ACPIDEV_WI_CHILD_SCANNED	0x20

/*
 * Device filtering result code.
 * Device filtering logic will be applied to determine how to handle ACPI
 * objects according to the filtering result code when enumerating ACPI objects.
 */
typedef enum acpidev_filter_result {
	ACPIDEV_FILTER_FAILED = -1,	/* operation failed */
	ACPIDEV_FILTER_CONTINUE = 0,	/* continue to evaluate filter rules */
	ACPIDEV_FILTER_DEFAULT,		/* create node and scan child */
	ACPIDEV_FILTER_SCAN,		/* scan child of current node only */
	ACPIDEV_FILTER_CREATE,		/* create device node only */
	ACPIDEV_FILTER_SKIP,		/* skip current node */
} acpidev_filter_result_t;

typedef acpidev_filter_result_t (* acpidev_filter_func_t)(acpidev_walk_info_t *,
    ACPI_HANDLE, acpidev_filter_rule_t *, char *, int);

/*
 * Device filter rule data structure.
 * User provided callback will be called if adf_filter_func is not NULL,
 * otherwise default filtering algorithm will be applied.
 */
struct acpidev_filter_rule {
	acpidev_filter_func_t		adf_filter_func;
	intptr_t			adf_filter_arg;
	acpidev_filter_result_t		adf_retcode;
	acpidev_class_list_t		**adf_class_list;
	intptr_t			adf_minlvl;
	intptr_t			adf_maxlvl;
	char				*adf_pattern;
	char				*adf_replace;
};

/* Callback function prototypes for ACPI device class driver. */
typedef ACPI_STATUS (* acpidev_pre_probe_t)(acpidev_walk_info_t *);
typedef ACPI_STATUS (* acpidev_post_probe_t)(acpidev_walk_info_t *);
typedef ACPI_STATUS (* acpidev_probe_t)(acpidev_walk_info_t *);
typedef acpidev_filter_result_t (* acpidev_filter_t)(acpidev_walk_info_t *,
    char *, int);
typedef ACPI_STATUS (* acpidev_init_t)(acpidev_walk_info_t *);
typedef void (* acpidev_fini_t)(ACPI_HANDLE, acpidev_data_handle_t,
    acpidev_class_t *);

/* Device class driver interface. */
struct acpidev_class {
	volatile uint32_t		adc_refcnt;
	int				adc_version;
	acpidev_class_id_t		adc_class_id;
	/* Name of device class, used in log messages. */
	char				*adc_class_name;
	/* Used as "device_type" property. */
	char				*adc_dev_type;
	/* Private storage for device driver. */
	void				*adc_private;
	/* Callback to setup environment before probing child objects. */
	acpidev_pre_probe_t		adc_pre_probe;
	/* Callback to clean environment after probing child objects. */
	acpidev_post_probe_t		adc_post_probe;
	/* Callback to probe child objects. */
	acpidev_probe_t			adc_probe;
	/* Callback to figure out policy to handle objects. */
	acpidev_filter_t		adc_filter;
	/* Callback to set device class specific device properties. */
	acpidev_init_t			adc_init;
	/* Callback to clean up resources when destroying device nodes. */
	acpidev_fini_t			adc_fini;
};

/* Versions of the ACPI device class driver data structure. */
#define	ACPIDEV_CLASS_REV1		1
#define	ACPIDEV_CLASS_REV		ACPIDEV_CLASS_REV1

/*
 * Class drivers.
 */
extern acpidev_class_t			acpidev_class_scope;
extern acpidev_class_t			acpidev_class_device;
extern acpidev_class_t			acpidev_class_container;
extern acpidev_class_t			acpidev_class_cpu;
extern acpidev_class_t			acpidev_class_memory;
extern acpidev_class_t			acpidev_class_pci;

/*
 * Class driver lists.
 */
extern acpidev_class_list_t		*acpidev_class_list_root;
extern acpidev_class_list_t		*acpidev_class_list_scope;
extern acpidev_class_list_t		*acpidev_class_list_device;
extern acpidev_class_list_t		*acpidev_class_list_cpu;
extern acpidev_class_list_t		*acpidev_class_list_memory;

/*
 * Register a device class driver onto a driver list. All class drivers on the
 * same list will be called in order when processing an ACPI object.
 * This interface can be used to support machine/platform specific object
 * handling by registering special plug-in class drivers to override system
 * default behaviors.
 * listpp:	pointer to driver list header
 * clsp:	device class driver to register
 * tail:	insert at tail of list if true
 * Return values:
 *	AE_OK: success
 *	AE_BAD_PARAMETER: invalid parameter
 *	AE_BAD_DATA: driver version mismatch
 *	AE_ALREADY_EXISTS: class driver already exists on the list
 */
extern ACPI_STATUS acpidev_register_class(acpidev_class_list_t **listpp,
    acpidev_class_t *clsp, boolean_t tail);

/*
 * Unregister a device class driver from a driver list.
 * listpp: pointer to driver list header
 * clsp: device class driver to unregister
 * Return values:
 *	AE_OK: success
 *	AE_BAD_PARAMETER: invalid parameter
 *	AE_NOT_FOUND: class driver doesn't exist in list
 *	AE_ERROR: class driver is still in use.
 */
extern ACPI_STATUS acpidev_unregister_class(acpidev_class_list_t **listpp,
    acpidev_class_t *clsp);

/*
 * Recursively enumerate child objects of an ACPI object.
 * It does following things in turn:
 * 1) Call pre_probe callback for each registered handler
 * 2) Enumerate child objects and call probe callbacks for each object
 * 3) Call post_probe callback for each registered handler
 * Return AE_OK on success and error code on failure.
 */
extern ACPI_STATUS acpidev_probe_child(acpidev_walk_info_t *infop);

/*
 * Default handler to process ACPI objects.
 * It creates a device node for an ACPI object and scans all child objects on
 * demand.
 * Return values:
 * AE_OK: on success
 * AE_NOT_EXIST: device doesn't exist according to _STA value.
 * AE_ALREADY_EXISTS: object already handled by other handler.
 * AE_ERROR: on other failure
 */
extern ACPI_STATUS acpidev_process_object(acpidev_walk_info_t *infop,
    int flags);

/* Flags for acpidev_process_device() */
#define	ACPIDEV_PROCESS_FLAG_CREATE	0x1	/* Create device */
#define	ACPIDEV_PROCESS_FLAG_SCAN	0x2	/* Scan child objects */
#define	ACPIDEV_PROCESS_FLAG_CHECK	0x100	/* Check status */
#define	ACPIDEV_PROCESS_FLAG_NOBIND	0x200	/* Skip binding driver */
#define	ACPIDEV_PROCESS_FLAG_OFFLINE	0x400	/* Put device into offline. */
#define	ACPIDEV_PROCESS_FLAG_NOTAG	0x800	/* Skip tag dip with object. */
#define	ACPIDEV_PROCESS_FLAG_SYNCSTATUS	0x1000	/* Sync object status. */
#define	ACPIDEV_PROCESS_FLAG_HOLDBRANCH	0x10000	/* Hold device branch. */

/*
 * Filter ACPI objects according to filter rules, generate devname if needed.
 * infop:	pointer to walker information structure
 * hdl:		handle of ACPI object in question
 * afrp:	pointer to filter rule array
 * entries:	number of filter rules in array
 * devname:	buffer to store generated device name
 * len:		sizeof devname buffer
 */
extern acpidev_filter_result_t acpidev_filter_device(acpidev_walk_info_t *infop,
    ACPI_HANDLE hdl, acpidev_filter_rule_t *afrp, int entries,
    char *devname, int len);

/* Default object filtering algorithm. */
extern acpidev_filter_result_t acpidev_filter_default(
    acpidev_walk_info_t *infop, ACPI_HANDLE hdl, acpidev_filter_rule_t *afrp,
    char *devname, int len);

/* Utility routines */
extern dev_info_t *acpidev_root_node(void);
extern char *acpidev_get_object_name(ACPI_HANDLE hdl);
extern void acpidev_free_object_name(char *objname);

extern acpidev_walk_info_t *acpidev_alloc_walk_info(acpidev_op_type_t op_type,
    int lvl, ACPI_HANDLE hdl, acpidev_class_list_t **listpp,
    acpidev_walk_info_t *pinfop);
extern void acpidev_free_walk_info(acpidev_walk_info_t *infop);
extern dev_info_t *acpidev_walk_info_get_pdip(acpidev_walk_info_t *infop);

/* Interfaces to access data associated with ACPI object. */
extern acpidev_data_handle_t acpidev_data_get_handle(ACPI_HANDLE hdl);
extern acpidev_data_handle_t acpidev_data_create_handle(ACPI_HANDLE hdl);
extern void acpidev_data_destroy_handle(ACPI_HANDLE hdl);
extern ACPI_HANDLE acpidev_data_get_object(acpidev_data_handle_t hdl);
extern dev_info_t *acpidev_data_get_devinfo(acpidev_data_handle_t hdl);
extern int acpidev_data_get_status(acpidev_data_handle_t hdl);
extern boolean_t acpidev_data_dr_capable(acpidev_data_handle_t hdl);
extern boolean_t acpidev_data_dr_ready(acpidev_data_handle_t hdl);
extern boolean_t acpidev_data_dr_failed(acpidev_data_handle_t hdl);
extern void acpidev_data_set_flag(acpidev_data_handle_t hdl, uint32_t flag);
extern void acpidev_data_clear_flag(acpidev_data_handle_t hdl, uint32_t flag);
extern uint32_t acpidev_data_get_flag(acpidev_data_handle_t hdl, uint32_t flag);

/* ACPI system event handler has been registered. */
#define	ACPIDEV_DATA_HANDLER_READY	0x1

/*
 * Try to generate meaningful device unit address from uid.
 * Return buf on success and NULL on failure.
 */
extern char *acpidev_generate_unitaddr(char *uid, char **fmts, size_t nfmt,
    char *buf, size_t len);

/*
 * Set device unit address property if _UID is available or unitaddr is valid.
 * Return AE_OK on success and error code on failure.
 * N.B.: it returns AE_OK if _UID is unavailable and unitaddr is NULL.
 */
extern ACPI_STATUS acpidev_set_unitaddr(acpidev_walk_info_t *infop,
    char **fmts, size_t nfmt, char *unitaddr);

/*
 * Generate the device 'compatible' property list for a device based on:
 *	* Device HID if available
 *	* Device CIDs if available
 *	* property array passed in
 * infop:	pointer to walk information structure
 * compat:	pointer to property array
 * acount:	entries in property array
 * Return AE_OK on success and error code on failure.
 */
extern ACPI_STATUS acpidev_set_compatible(acpidev_walk_info_t *infop,
    char **compat, int acount);

/*
 * Query ACPI device status.
 * N.B.: it returns with all status bits set if _STA is not available.
 */
extern int acpidev_query_device_status(ACPI_HANDLE hdl);

/*
 * Check whether device exists.
 * Return false if device doesn't exist.
 */
extern boolean_t acpidev_check_device_present(int status);

/*
 * Check whether device is enabled.
 * Return false if device doesn't exist or hasn't been enabled.
 */
extern boolean_t acpidev_check_device_enabled(int status);

/*
 * Match device ids with ACPI object's _HID and _CIDs.
 * infop: ACPI object information structure
 * ids: array of ACPI HIDs and CIDs
 * count: entries in array
 * Return TRUE if one item matches or num is zero, else FALSE.
 */
extern boolean_t acpidev_match_device_id(ACPI_DEVICE_INFO *infop,
    char **ids, int count);

/*
 * Implement almost the same function as AcpiGetDevices() with the following
 * changes/enhancements:
 * 1) Support limiting recursive levels.
 * 2) Support matching multiple ids instead of one.
 * 3) Report device without ACPI_STA_DEVICE_PRESENT flag which will be ignored
 *    by AcpiGetDevices().
 */
extern ACPI_STATUS acpidev_get_device_by_id(ACPI_HANDLE hdl,
    char **ids, int count, int maxdepth, boolean_t skip_non_exist,
    ACPI_WALK_CALLBACK userfunc, void *userarg, void** retval);

/* Callback for APIC entry walker. */
typedef ACPI_STATUS (* acpidev_apic_walker_t)(ACPI_SUBTABLE_HEADER *, void *);

/*
 * Walk ACPI APIC entries from the first source available in following order:
 * 1) ACPI buffer passed in if bufp isn't NULL.
 * 2) Buffer returned by evaluating method if it isn't NULL.
 * 3) MADT table as last resort.
 */
extern ACPI_STATUS acpidev_walk_apic(ACPI_BUFFER *bufp, ACPI_HANDLE hdl,
    char *method, acpidev_apic_walker_t func, void *context);

/*
 * Evaluate _OST method under object, which is used to support hotplug event.
 * hdl: object handle
 * code: _OST source event code
 * stauts: _OST result status code
 * bufp and len: optional third parameter for _OST.
 */
extern ACPI_STATUS acpidev_eval_ost(ACPI_HANDLE hdl, uint32_t code,
    uint32_t status, char *bufp, size_t len);

/*
 * Evaluate _EJ0 method under object.
 */
extern ACPI_STATUS acpidev_eval_ej0(ACPI_HANDLE hdl);

/*
 * Evaluate _PXM method under object.
 */
extern ACPI_STATUS acpidev_eval_pxm(ACPI_HANDLE hdl, uint32_t *idp);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIDEV_H */
