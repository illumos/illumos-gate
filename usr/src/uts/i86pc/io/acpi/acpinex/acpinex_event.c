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
#include <sys/bitmap.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/sunndi.h>
#include <sys/fastboot_impl.h>
#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_dr.h>
#include <sys/acpinex.h>

int acpinex_event_support_remove = 0;

static volatile uint_t acpinex_dr_event_cnt = 0;
static ulong_t acpinex_object_type_mask[BT_BITOUL(ACPI_TYPE_NS_NODE_MAX + 1)];

/*
 * Generate DR_REQ event to syseventd.
 * Please refer to sys/sysevent/dr.h for message definition.
 */
static int
acpinex_event_generate_event(dev_info_t *dip, ACPI_HANDLE hdl, int req,
    int event, char *objname)
{
	int rv = 0;
	sysevent_id_t eid;
	sysevent_value_t evnt_val;
	sysevent_attr_list_t *evnt_attr_list = NULL;
	char *attach_pnt;
	char event_type[32];

	/* Add "attachment point" attribute. */
	attach_pnt = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (ACPI_FAILURE(acpidev_dr_get_attachment_point(hdl,
	    attach_pnt, MAXPATHLEN))) {
		cmn_err(CE_WARN,
		    "!acpinex: failed to generate AP name for %s.", objname);
		kmem_free(attach_pnt, MAXPATHLEN);
		return (-1);
	}
	ASSERT(attach_pnt[0] != '\0');
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;
	rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID, &evnt_val, KM_SLEEP);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "!acpinex: failed to add attr [%s] for %s event.",
		    DR_AP_ID, EC_DR);
		kmem_free(attach_pnt, MAXPATHLEN);
		return (rv);
	}

	/* Add "request type" attribute. */
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = SE_REQ2STR(req);
	rv = sysevent_add_attr(&evnt_attr_list, DR_REQ_TYPE, &evnt_val,
	    KM_SLEEP);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "!acpinex: failed to add attr [%s] for %s event.",
		    DR_REQ_TYPE, EC_DR);
		sysevent_free_attr(evnt_attr_list);
		kmem_free(attach_pnt, MAXPATHLEN);
		return (rv);
	}

	/* Add "acpi-event-type" attribute. */
	switch (event) {
	case ACPI_NOTIFY_BUS_CHECK:
		(void) snprintf(event_type, sizeof (event_type),
		    ACPIDEV_EVENT_TYPE_BUS_CHECK);
		break;
	case ACPI_NOTIFY_DEVICE_CHECK:
		(void) snprintf(event_type, sizeof (event_type),
		    ACPIDEV_EVENT_TYPE_DEVICE_CHECK);
		break;
	case ACPI_NOTIFY_DEVICE_CHECK_LIGHT:
		(void) snprintf(event_type, sizeof (event_type),
		    ACPIDEV_EVENT_TYPE_DEVICE_CHECK_LIGHT);
		break;
	case ACPI_NOTIFY_EJECT_REQUEST:
		(void) snprintf(event_type, sizeof (event_type),
		    ACPIDEV_EVENT_TYPE_EJECT_REQUEST);
		break;
	default:
		cmn_err(CE_WARN,
		    "!acpinex: unknown ACPI event type %d.", event);
		sysevent_free_attr(evnt_attr_list);
		kmem_free(attach_pnt, MAXPATHLEN);
		return (-1);
	}
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = event_type;
	rv = sysevent_add_attr(&evnt_attr_list, ACPIDEV_EVENT_TYPE_ATTR_NAME,
	    &evnt_val, KM_SLEEP);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "!acpinex: failed to add attr [%s] for %s event.",
		    ACPIDEV_EVENT_TYPE_ATTR_NAME, EC_DR);
		sysevent_free_attr(evnt_attr_list);
		kmem_free(attach_pnt, MAXPATHLEN);
		return (rv);
	}

	rv = ddi_log_sysevent(dip, DDI_VENDOR_SUNW, EC_DR, ESC_DR_REQ,
	    evnt_attr_list, &eid, KM_SLEEP);
	if (rv != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "!acpinex: failed to log DR_REQ event for %s.", objname);
		rv = -1;
	}

	nvlist_free(evnt_attr_list);
	kmem_free(attach_pnt, MAXPATHLEN);

	return (rv);
}

/*
 * Event handler for ACPI EJECT_REQUEST notifications.
 * EJECT_REQUEST notifications should be generated on the device to be ejected,
 * so no need to scan subtree of it.
 * It also invokes ACPI _OST method to update event status if call_ost is true.
 */
static void
acpinex_event_handle_eject_request(ACPI_HANDLE hdl, acpinex_softstate_t *sp,
    boolean_t call_ost)
{
	int code;
	char *objname;

	ASSERT(hdl != NULL);
	objname = acpidev_get_object_name(hdl);

	ASSERT(sp != NULL);
	ASSERT(sp->ans_dip != NULL && sp->ans_hdl != NULL);
	if (sp == NULL || sp->ans_dip == NULL || sp->ans_hdl == NULL) {
		if (call_ost) {
			(void) acpidev_eval_ost(hdl, ACPI_NOTIFY_EJECT_REQUEST,
			    ACPI_OST_STA_FAILURE, NULL, 0);
		}
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: softstate data structure is invalid.");
		cmn_err(CE_WARN,
		    "!acpinex: failed to handle EJECT_REQUEST event from %s.",
		    objname);
		acpidev_free_object_name(objname);
		return;
	}

	if (acpinex_event_support_remove == 0) {
		cmn_err(CE_WARN,
		    "!acpinex: hot-removing of device %s is unsupported.",
		    objname);
		code = ACPI_OST_STA_EJECT_NOT_SUPPORT;
	} else if (acpinex_event_generate_event(sp->ans_dip, hdl,
	    SE_OUTGOING_RES, ACPI_NOTIFY_EJECT_REQUEST, objname) != 0) {
		cmn_err(CE_WARN, "!acpinex: failed to generate ESC_DR_REQ "
		    "event for device eject request from %s.", objname);
		code = ACPI_OST_STA_FAILURE;
	} else {
		cmn_err(CE_NOTE, "!acpinex: generate ESC_DR_REQ event for "
		    "device eject request from %s.", objname);
		code = ACPI_OST_STA_EJECT_IN_PROGRESS;
	}
	if (call_ost) {
		(void) acpidev_eval_ost(hdl, ACPI_NOTIFY_EJECT_REQUEST,
		    code, NULL, 0);
	}

	acpidev_free_object_name(objname);
}

struct acpinex_event_check_arg {
	acpinex_softstate_t	*softstatep;
	int			event_type;
	uint32_t		device_insert;
	uint32_t		device_remove;
	uint32_t		device_fail;
};

static ACPI_STATUS
acpinex_event_handle_check_one(ACPI_HANDLE hdl, UINT32 lvl, void *ctx,
    void **retval)
{
	_NOTE(ARGUNUSED(lvl, retval));

	char *objname;
	int status, psta, csta;
	acpidev_data_handle_t dhdl;
	struct acpinex_event_check_arg *argp;

	ASSERT(hdl != NULL);
	ASSERT(ctx != NULL);
	argp = (struct acpinex_event_check_arg *)ctx;

	dhdl = acpidev_data_get_handle(hdl);
	if (dhdl == NULL) {
		/* Skip subtree if failed to get the data handle. */
		ACPINEX_DEBUG(CE_NOTE,
		    "!acpinex: failed to get data associated with %p.", hdl);
		return (AE_CTRL_DEPTH);
	} else if (!acpidev_data_dr_capable(dhdl)) {
		return (AE_OK);
	}

	objname = acpidev_get_object_name(hdl);

	status = 0;
	/* Query previous device status. */
	psta = acpidev_data_get_status(dhdl);
	if (acpidev_check_device_enabled(psta)) {
		status |= 0x1;
	}
	/* Query current device status. */
	csta = acpidev_query_device_status(hdl);
	if (acpidev_check_device_enabled(csta)) {
		status |= 0x2;
	}

	switch (status) {
	case 0x0:
		/*FALLTHROUGH*/
	case 0x3:
		/* No status changes, keep on walking. */
		acpidev_free_object_name(objname);
		return (AE_OK);

	case 0x1:
		/* Surprising removal. */
		cmn_err(CE_WARN,
		    "!acpinex: device %s has been surprisingly removed.",
		    objname);
		if (argp->event_type == ACPI_NOTIFY_BUS_CHECK) {
			/*
			 * According to ACPI spec, BUS_CHECK notification
			 * should be triggered for hot-adding events only.
			 */
			ACPINEX_DEBUG(CE_WARN,
			    "!acpinex: device %s has been surprisingly removed "
			    "when handling BUS_CHECK event.", objname);
		}
		acpidev_free_object_name(objname);
		argp->device_remove++;
		return (AE_CTRL_DEPTH);

	case 0x2:
		/* Hot-adding. */
		ACPINEX_DEBUG(CE_NOTE,
		    "!acpinex: device %s has been inserted.", objname);
		argp->device_insert++;
		if (acpinex_event_generate_event(argp->softstatep->ans_dip, hdl,
		    SE_INCOMING_RES, argp->event_type, objname) != 0) {
			cmn_err(CE_WARN,
			    "!acpinex: failed to generate ESC_DR_REQ event for "
			    "device insert request from %s.", objname);
			argp->device_fail++;
		} else {
			cmn_err(CE_NOTE, "!acpinex: generate ESC_DR_REQ event "
			    "for device insert request from %s.", objname);
		}
		acpidev_free_object_name(objname);
		return (AE_OK);

	default:
		ASSERT(0);
		break;
	}

	return (AE_ERROR);
}

/*
 * Event handler for BUS_CHECK/DEVICE_CHECK/DEVICE_CHECK_LIGHT notifications.
 * These events may be signaled on parent/ancestor of devices to be hot-added,
 * so need to scan ACPI namespace to figure out devices in question.
 * It also invokes ACPI _OST method to update event status if call_ost is true.
 */
static void
acpinex_event_handle_check_request(int event, ACPI_HANDLE hdl,
    acpinex_softstate_t *sp, boolean_t call_ost)
{
	ACPI_STATUS rv;
	int code;
	char *objname;
	struct acpinex_event_check_arg arg;

	ASSERT(hdl != NULL);
	objname = acpidev_get_object_name(hdl);

	ASSERT(sp != NULL);
	ASSERT(sp->ans_dip != NULL && sp->ans_hdl != NULL);
	if (sp == NULL || sp->ans_dip == NULL || sp->ans_hdl == NULL) {
		if (call_ost) {
			(void) acpidev_eval_ost(hdl, event,
			    ACPI_OST_STA_FAILURE, NULL, 0);
		}
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: softstate data structure is invalid.");
		cmn_err(CE_WARN, "!acpinex: failed to handle "
		    "BUS/DEVICE_CHECK event from %s.", objname);
		acpidev_free_object_name(objname);
		return;
	}

	bzero(&arg, sizeof (arg));
	arg.event_type = event;
	arg.softstatep = sp;
	rv = acpinex_event_handle_check_one(hdl, 0, &arg, NULL);
	if (ACPI_SUCCESS(rv)) {
		rv = AcpiWalkNamespace(ACPI_TYPE_DEVICE, hdl,
		    ACPIDEV_MAX_ENUM_LEVELS,
		    &acpinex_event_handle_check_one, NULL, &arg, NULL);
	}

	if (ACPI_FAILURE(rv)) {
		/* Failed to scan the ACPI namespace. */
		cmn_err(CE_WARN, "!acpinex: failed to handle event %d from %s.",
		    event, objname);
		code = ACPI_OST_STA_FAILURE;
	} else if (arg.device_remove != 0) {
		/* Surprising removal happened. */
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: some devices have been surprisingly removed.");
		code = ACPI_OST_STA_NOT_SUPPORT;
	} else if (arg.device_fail != 0) {
		/* Failed to handle some devices. */
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: failed to check status of some devices.");
		code = ACPI_OST_STA_FAILURE;
	} else if (arg.device_insert == 0) {
		/* No hot-added devices found. */
		cmn_err(CE_WARN,
		    "!acpinex: no hot-added devices under %s found.", objname);
		code = ACPI_OST_STA_FAILURE;
	} else {
		code = ACPI_OST_STA_INSERT_IN_PROGRESS;
	}
	if (call_ost) {
		(void) acpidev_eval_ost(hdl, event, code, NULL, 0);
	}

	acpidev_free_object_name(objname);
}

static void
acpinex_event_system_handler(ACPI_HANDLE hdl, UINT32 type, void *arg)
{
	acpinex_softstate_t *sp;

	ASSERT(hdl != NULL);
	ASSERT(arg != NULL);
	sp = (acpinex_softstate_t *)arg;

	acpidev_dr_lock_all();
	mutex_enter(&sp->ans_lock);

	switch (type) {
	case ACPI_NOTIFY_BUS_CHECK:
		/*
		 * Bus Check. This notification is performed on a device object
		 * to indicate to OSPM that it needs to perform the Plug and
		 * Play re-enumeration operation on the device tree starting
		 * from the point where it has been notified. OSPM will only
		 * perform this operation at boot, and when notified. It is
		 * the responsibility of the ACPI AML code to notify OSPM at
		 * any other times that this operation is required. The more
		 * accurately and closer to the actual device tree change the
		 * notification can be done, the more efficient the operating
		 * system response will be; however, it can also be an issue
		 * when a device change cannot be confirmed. For example, if
		 * the hardware cannot notice a device change for a particular
		 * location during a system sleeping state, it issues a Bus
		 * Check notification on wake to inform OSPM that it needs to
		 * check the configuration for a device change.
		 */
		/*FALLTHROUGH*/
	case ACPI_NOTIFY_DEVICE_CHECK:
		/*
		 * Device Check. Used to notify OSPM that the device either
		 * appeared or disappeared. If the device has appeared, OSPM
		 * will re-enumerate from the parent. If the device has
		 * disappeared, OSPM will invalidate the state of the device.
		 * OSPM may optimize out re-enumeration. If _DCK is present,
		 * then Notify(object,1) is assumed to indicate an undock
		 * request.
		 */
		/*FALLTHROUGH*/
	case ACPI_NOTIFY_DEVICE_CHECK_LIGHT:
		/*
		 * Device Check Light. Used to notify OSPM that the device
		 * either appeared or disappeared. If the device has appeared,
		 * OSPM will re-enumerate from the device itself, not the
		 * parent. If the device has disappeared, OSPM will invalidate
		 * the state of the device.
		 */
		atomic_inc_uint(&acpinex_dr_event_cnt);
		acpinex_event_handle_check_request(type, hdl, sp, B_TRUE);
		break;

	case ACPI_NOTIFY_EJECT_REQUEST:
		/*
		 * Eject Request. Used to notify OSPM that the device should
		 * be ejected, and that OSPM needs to perform the Plug and Play
		 * ejection operation. OSPM will run the _EJx method.
		 */
		atomic_inc_uint(&acpinex_dr_event_cnt);
		acpinex_event_handle_eject_request(hdl, sp, B_TRUE);
		break;

	default:
		ACPINEX_DEBUG(CE_NOTE,
		    "!acpinex: unhandled event(%d) on hdl %p under %s.",
		    type, hdl, sp->ans_path);
		(void) acpidev_eval_ost(hdl, type, ACPI_OST_STA_NOT_SUPPORT,
		    NULL, 0);
		break;
	}

	if (acpinex_dr_event_cnt != 0) {
		/*
		 * Disable fast reboot if a CPU/MEM/IOH hotplug event happens.
		 * Note: this is a temporary solution and will be revised when
		 * fast reboot can support CPU/MEM/IOH DR operations in the
		 * future.
		 *
		 * ACPI BIOS generates some static ACPI tables, such as MADT,
		 * SRAT and SLIT, to describe the system hardware configuration
		 * on power-on. When a CPU/MEM/IOH hotplug event happens, those
		 * static tables won't be updated and will become stale.
		 *
		 * If we reset the system by fast reboot, BIOS will have no
		 * chance to regenerate those staled static tables. Fast reboot
		 * can't tolerate such inconsistency between staled ACPI tables
		 * and real hardware configuration yet.
		 *
		 * A temporary solution is introduced to disable fast reboot if
		 * CPU/MEM/IOH hotplug event happens. This solution should be
		 * revised when fast reboot is enhanced to support CPU/MEM/IOH
		 * DR operations.
		 */
		fastreboot_disable(FBNS_HOTPLUG);
	}

	mutex_exit(&sp->ans_lock);
	acpidev_dr_unlock_all();
}

/*
 * Install event handler for ACPI system events.
 * Acpinex driver handles ACPI system events for its children,
 * device specific events will be handled by device drivers.
 * Return DDI_SUCCESS on success, and DDI_FAILURE on failure.
 */
static int
acpinex_event_install_handler(ACPI_HANDLE hdl, void *arg,
    ACPI_DEVICE_INFO *infop, acpidev_data_handle_t dhdl)
{
	int rc = DDI_SUCCESS;

	ASSERT(hdl != NULL);
	ASSERT(dhdl != NULL);
	ASSERT(infop != NULL);

	/*
	 * Check whether the event handler has already been installed on the
	 * device object. With the introduction of ACPI Alias objects, which are
	 * similar to symlinks in file systems, there may be multiple name
	 * objects in the ACPI namespace pointing to the same underlying device
	 * object. Those Alias objects need to be filtered out, otherwise
	 * it will attempt to install the event handler multiple times on the
	 * same device object which will fail.
	 */
	if (acpidev_data_get_flag(dhdl, ACPIDEV_DATA_HANDLER_READY)) {
		return (DDI_SUCCESS);
	}
	if (ACPI_SUCCESS(AcpiInstallNotifyHandler(hdl, ACPI_SYSTEM_NOTIFY,
	    acpinex_event_system_handler, arg))) {
		acpidev_data_set_flag(dhdl, ACPIDEV_DATA_HANDLER_READY);
	} else {
		char *objname;

		objname = acpidev_get_object_name(hdl);
		cmn_err(CE_WARN,
		    "!acpinex: failed to install system event handler for %s.",
		    objname);
		acpidev_free_object_name(objname);
		rc = DDI_FAILURE;
	}

	return (rc);
}

/*
 * Uninstall event handler for ACPI system events.
 * Return DDI_SUCCESS on success, and DDI_FAILURE on failure.
 */
static int
acpinex_event_uninstall_handler(ACPI_HANDLE hdl, ACPI_DEVICE_INFO *infop,
    acpidev_data_handle_t dhdl)
{
	ASSERT(hdl != NULL);
	ASSERT(dhdl != NULL);
	ASSERT(infop != NULL);

	if (!acpidev_data_get_flag(dhdl, ACPIDEV_DATA_HANDLER_READY)) {
		return (DDI_SUCCESS);
	}
	if (ACPI_SUCCESS(AcpiRemoveNotifyHandler(hdl, ACPI_SYSTEM_NOTIFY,
	    acpinex_event_system_handler))) {
		acpidev_data_clear_flag(dhdl, ACPIDEV_DATA_HANDLER_READY);
	} else {
		char *objname;

		objname = acpidev_get_object_name(hdl);
		cmn_err(CE_WARN, "!acpinex: failed to uninstall system event "
		    "handler for %s.", objname);
		acpidev_free_object_name(objname);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Install/uninstall ACPI system event handler for child objects of hdl.
 * Return DDI_SUCCESS on success, and DDI_FAILURE on failure.
 */
static int
acpinex_event_walk(boolean_t init, acpinex_softstate_t *sp, ACPI_HANDLE hdl)
{
	int rc;
	int retval = DDI_SUCCESS;
	dev_info_t *dip;
	ACPI_HANDLE child = NULL;
	ACPI_OBJECT_TYPE type;
	ACPI_DEVICE_INFO *infop;
	acpidev_data_handle_t dhdl;

	/* Walk all child objects. */
	ASSERT(hdl != NULL);
	while (ACPI_SUCCESS(AcpiGetNextObject(ACPI_TYPE_ANY, hdl, child,
	    &child))) {
		/* Skip unwanted object types. */
		if (ACPI_FAILURE(AcpiGetType(child, &type)) ||
		    type > ACPI_TYPE_NS_NODE_MAX ||
		    BT_TEST(acpinex_object_type_mask, type) == 0) {
			continue;
		}

		/* Get data associated with the object. Skip it if fails. */
		dhdl = acpidev_data_get_handle(child);
		if (dhdl == NULL) {
			ACPINEX_DEBUG(CE_NOTE, "!acpinex: failed to get data "
			    "associated with %p, skip.", child);
			continue;
		}

		/* Query ACPI object info for the object. */
		if (ACPI_FAILURE(AcpiGetObjectInfo(child, &infop))) {
			cmn_err(CE_WARN,
			    "!acpidnex: failed to get object info for %p.",
			    child);
			continue;
		}

		if (init) {
			rc = acpinex_event_install_handler(child, sp, infop,
			    dhdl);
			if (rc != DDI_SUCCESS) {
				ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to "
				    "install handler for child %p of %s.",
				    child, sp->ans_path);
				retval = DDI_FAILURE;
			/*
			 * Try to handle descendants if both of the
			 * following two conditions are true:
			 * 1) Device corresponding to the current object is
			 *    enabled. If the device is absent/disabled,
			 *    no notification should be generated from
			 *    descendant objects of it.
			 * 2) No Solaris device node has been created for the
			 *    current object yet. If the device node has been
			 *    created for the current object, notification
			 *    events from child objects should be handled by
			 *    the corresponding driver.
			 */
			} else if (acpidev_check_device_enabled(
			    acpidev_data_get_status(dhdl)) &&
			    ACPI_FAILURE(acpica_get_devinfo(child, &dip))) {
				rc = acpinex_event_walk(B_TRUE, sp, child);
				if (rc != DDI_SUCCESS) {
					ACPINEX_DEBUG(CE_WARN,
					    "!acpinex: failed to install "
					    "handler for descendants of %s.",
					    sp->ans_path);
					retval = DDI_FAILURE;
				}
			}
		} else {
			rc = DDI_SUCCESS;
			/* Uninstall handler for descendants if needed. */
			if (ACPI_FAILURE(acpica_get_devinfo(child, &dip))) {
				rc = acpinex_event_walk(B_FALSE, sp, child);
			}
			if (rc == DDI_SUCCESS) {
				rc = acpinex_event_uninstall_handler(child,
				    infop, dhdl);
			}
			/* Undo will be done by caller in case of failure. */
			if (rc != DDI_SUCCESS) {
				ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to "
				    "uninstall handler for descendants of %s.",
				    sp->ans_path);
				AcpiOsFree(infop);
				retval = DDI_FAILURE;
				break;
			}
		}

		/* Release cached resources. */
		AcpiOsFree(infop);
	}

	return (retval);
}

int
acpinex_event_scan(acpinex_softstate_t *sp, boolean_t init)
{
	int rc;

	ASSERT(sp != NULL);
	ASSERT(sp->ans_hdl != NULL);
	ASSERT(sp->ans_dip != NULL);
	if (sp == NULL || sp->ans_hdl == NULL || sp->ans_dip == NULL) {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: invalid parameter to acpinex_event_scan().");
		return (DDI_FAILURE);
	}

	/* Lock current device node and walk all child device nodes of it. */
	mutex_enter(&sp->ans_lock);

	rc = acpinex_event_walk(init, sp, sp->ans_hdl);
	if (rc != DDI_SUCCESS) {
		if (init) {
			ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to "
			    "configure child objects of %s.", sp->ans_path);
			rc = DDI_FAILURE;
		} else {
			ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to "
			    "unconfigure child objects of %s.", sp->ans_path);
			/* Undo in case of errors */
			(void) acpinex_event_walk(B_TRUE, sp, sp->ans_hdl);
			rc = DDI_FAILURE;
		}
	}

	mutex_exit(&sp->ans_lock);

	return (rc);
}

void
acpinex_event_init(void)
{
	/*
	 * According to ACPI specifications, notification is only supported on
	 * Device, Processor and ThermalZone. Currently we only need to handle
	 * Device and Processor objects.
	 */
	BT_SET(acpinex_object_type_mask, ACPI_TYPE_PROCESSOR);
	BT_SET(acpinex_object_type_mask, ACPI_TYPE_DEVICE);
}

void
acpinex_event_fini(void)
{
	bzero(acpinex_object_type_mask, sizeof (acpinex_object_type_mask));
}
