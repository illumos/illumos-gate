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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <config_admin.h>
#include <strings.h>
#include <syslog.h>
#include <libsysevent.h>
#include <libdevinfo.h>
#include <libnvpair.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/sbd_ioctl.h>
#include <sys/acpidev.h>

#define	PMCONFIG_PATH			"/usr/sbin/pmconfig"

#define	CFGADM_CMD_ASSIGN		"assign"
#define	CFGADM_CMD_POWERON		"poweron"
#define	CFGADM_CMD_PASSTHRU		"passthru"

#define	STATUS_INPROGRESS		0
#define	STATUS_SUCCESS			1
#define	STATUS_FAILURE			2
#define	STATUS_NOOP			3

static char *s_status_array[] = {
	ACPIDEV_CMD_OST_INPROGRESS,
	ACPIDEV_CMD_OST_SUCCESS,
	ACPIDEV_CMD_OST_FAILURE,
	ACPIDEV_CMD_OST_NOOP
};

extern void debug_print(int, const char *, ...);

/*ARGSUSED*/
static int
confirm_no(void *appdata_ptr, const char *message)
{
	return (0);
}

/*ARGSUSED*/
static int
message_output(void *appdata_ptr, const char *message)
{
	debug_print(2, "cfgadm message: %s", message);
	return (CFGA_OK);
}

static char *
plat_opt_str_alloc(int cmd, char *acpi_event_type, int status)
{
	char *opt;
	size_t len;

	if (cmd == SBD_CMD_PASSTHRU) {
		len = strlen(s_status_array[status]) +
		    strlen(ACPIDEV_EVENT_TYPE_ATTR_NAME) +
		    strlen(acpi_event_type) + 10;
		if ((opt = malloc(len)) != NULL) {
			(void) snprintf(opt, len, "%s %s=%s",
			    s_status_array[status],
			    ACPIDEV_EVENT_TYPE_ATTR_NAME,
			    acpi_event_type);
			debug_print(2, "plat_opt_str_alloc = '%s'", opt);
		}
	} else {
		len = strlen("platform=''") +
		    strlen(s_status_array[status]) +
		    strlen(ACPIDEV_EVENT_TYPE_ATTR_NAME) +
		    strlen(acpi_event_type) + 10;
		if ((opt = malloc(len)) != NULL) {
			(void) snprintf(opt, len, "platform='%s %s=%s'",
			    s_status_array[status],
			    ACPIDEV_EVENT_TYPE_ATTR_NAME,
			    acpi_event_type);
			debug_print(2, "plat_opt_str_alloc = '%s'", opt);
		}
	}

	return (opt);
}

static int
cfgadm_cmd_wrapper(int cmd, int apid_num, char **apids,
	char *acpi_event_type, int status,
	struct cfga_confirm *confirm, struct cfga_msg *message)
{
	cfga_err_t ret;
	char *plat_opts;
	char *estrp = NULL;

	assert(apid_num == 1);
	assert(apids != NULL);

	plat_opts = plat_opt_str_alloc(cmd, acpi_event_type, status);
	if (plat_opts == NULL) {
		debug_print(0,
		    "failed to generate platform option string for cfgadm");
		return (-1);
	}

	switch (cmd) {
	case SBD_CMD_CONNECT:
		ret = config_change_state(CFGA_CMD_CONNECT, apid_num, apids,
		    plat_opts, confirm, message, &estrp, 0);
		if (ret != CFGA_OK) {
			debug_print(0, "cfgadm('connect', '%s') failed, "
			    "ret = %d, errstr = '%s'", apids[0], ret, estrp);
		}
		break;

	case SBD_CMD_CONFIGURE:
		ret = config_change_state(CFGA_CMD_CONFIGURE, apid_num, apids,
		    plat_opts, confirm, message, &estrp, 0);
		if (ret != CFGA_OK) {
			debug_print(0, "cfgadm('configure', '%s') failed, "
			    "ret = %d, errstr = '%s'", apids[0], ret, estrp);
		}
		break;

	case SBD_CMD_ASSIGN:
		ret = config_private_func(CFGADM_CMD_ASSIGN, apid_num, apids,
		    plat_opts, confirm, message, &estrp, 0);
		if (ret != CFGA_OK) {
			debug_print(0, "cfgadm('assign', '%s') failed, "
			    "ret = %d, errstr = '%s'", apids[0], ret, estrp);
		}
		break;

	case SBD_CMD_POWERON:
		ret = config_private_func(CFGADM_CMD_POWERON, apid_num, apids,
		    plat_opts, confirm, message, &estrp, 0);
		if (ret != CFGA_OK) {
			debug_print(0, "cfgadm('poweron', '%s') failed, "
			    "ret = %d, errstr = '%s'", apids[0], ret, estrp);
		}
		break;

	case SBD_CMD_PASSTHRU:
		ret = config_private_func(CFGADM_CMD_PASSTHRU, apid_num, apids,
		    plat_opts, confirm, message, &estrp, 0);
		if (ret != CFGA_OK) {
			debug_print(0, "cfgadm('passthru', '%s') failed, "
			    "ret = %d, errstr = '%s'", apids[0], ret, estrp);
		}
		break;

	default:
		debug_print(2, "unknown command (%d) to cfgadm_cmd_wrapper()");
		ret = CFGA_ERROR;
		break;
	}

	if (plat_opts != NULL)
		free(plat_opts);

	return (ret == CFGA_OK ? 0 : -1);
}

static int
event_process(char *ap_id, char *req, char *acpi_event_type)
{
	char *apids[1];
	struct cfga_msg message;
	struct cfga_confirm confirm;

	if (strcmp(req, DR_REQ_INCOMING_RES) != 0) {
		debug_print(2,
		    "Event is not supported (ap_id = %s, req = %s)",
		    ap_id, req);
		return (-1);
	}

	apids[0] = ap_id;
	(void) memset(&confirm, 0, sizeof (confirm));
	confirm.confirm = confirm_no;
	(void) memset(&message, 0, sizeof (message));
	message.message_routine = message_output;

	if (cfgadm_cmd_wrapper(SBD_CMD_ASSIGN, 1, apids,
	    acpi_event_type, STATUS_NOOP, &confirm, &message) != 0) {
		goto L_ERR;
	}
	syslog(LOG_NOTICE,
	    "board '%s' has been assigned successfully", ap_id);
	(void) cfgadm_cmd_wrapper(SBD_CMD_PASSTHRU, 1, apids,
	    acpi_event_type, STATUS_INPROGRESS, &confirm, &message);

	if (cfgadm_cmd_wrapper(SBD_CMD_POWERON, 1, apids,
	    acpi_event_type, STATUS_NOOP, &confirm, &message) != 0) {
		goto L_ERR_SIG;
	}
	syslog(LOG_NOTICE,
	    "board '%s' has been powered on successfully", ap_id);
	(void) cfgadm_cmd_wrapper(SBD_CMD_PASSTHRU, 1, apids,
	    acpi_event_type, STATUS_INPROGRESS, &confirm, &message);

	if (cfgadm_cmd_wrapper(SBD_CMD_CONNECT, 1, apids,
	    acpi_event_type, STATUS_INPROGRESS, &confirm, &message) != 0) {
		goto L_ERR_SIG;
	}
	syslog(LOG_NOTICE,
	    "board '%s' has been connected successfully", ap_id);
	(void) cfgadm_cmd_wrapper(SBD_CMD_PASSTHRU, 1, apids,
	    acpi_event_type, STATUS_INPROGRESS, &confirm, &message);

	if (cfgadm_cmd_wrapper(SBD_CMD_CONFIGURE, 1, apids,
	    acpi_event_type, STATUS_INPROGRESS, &confirm, &message) != 0) {
		goto L_ERR_SIG;
	}
	syslog(LOG_NOTICE,
	    "board '%s' has been configured successfully", ap_id);
	(void) cfgadm_cmd_wrapper(SBD_CMD_PASSTHRU, 1, apids,
	    acpi_event_type, STATUS_SUCCESS, &confirm, &message);

	(void) system(PMCONFIG_PATH);
	syslog(LOG_NOTICE,
	    "board '%s' has been added into system successfully", ap_id);

	return (0);

L_ERR_SIG:
	(void) cfgadm_cmd_wrapper(SBD_CMD_PASSTHRU, 1, apids,
	    acpi_event_type, STATUS_FAILURE, &confirm, &message);
L_ERR:
	syslog(LOG_ERR, "failed to add board '%s' into system", ap_id);

	return (-1);
}

void
notify_hotplug(sysevent_t *ev)
{
	char *vendor = NULL;
	nvlist_t *attr_list = NULL;
	char *class, *subclass;
	char *ap_id, *req, *acpi_event_type;

	vendor = sysevent_get_vendor_name(ev);
	debug_print(2, "message_vendor = '%s'", vendor ? vendor : "unknown");
	if (vendor == NULL || strcmp(vendor, SUNW_VENDOR) != 0) {
		debug_print(2,
		    "vendor id of message is not '%s'", SUNW_VENDOR);
		goto L_EXIT;
	}

	class = sysevent_get_class_name(ev);
	debug_print(2, "message_class = '%s'", class ? class : "unknown");
	if (class == NULL || strcmp(class, EC_DR) != 0) {
		debug_print(2, "class of message is not '%s'", EC_DR);
		goto L_EXIT;
	}

	subclass = sysevent_get_subclass_name(ev);
	debug_print(2,
	    "message_subclass = '%s'", subclass ? subclass : "unknown");
	if (subclass == NULL || strcmp(subclass, ESC_DR_REQ) != 0) {
		debug_print(2,
		    "subclass of message is not '%s'", ESC_DR_REQ);
		goto L_EXIT;
	}

	if (sysevent_get_attr_list(ev, &attr_list) != 0) {
		debug_print(2,
		    "can't retrieve attribute list from DR message");
		goto L_EXIT;
	}

	if (nvlist_lookup_string(attr_list, DR_AP_ID, &ap_id) != 0) {
		debug_print(2,
		    "can't retrieve '%s' property from attribute list",
		    DR_AP_ID);
		goto L_EXIT;
	}
	debug_print(2, "%s = '%s'", DR_AP_ID, ap_id ? ap_id : "<null>");
	if ((ap_id == NULL) || (strlen(ap_id) == 0)) {
		debug_print(2, "'%s' property in message is NULL", DR_AP_ID);
		goto L_EXIT;
	}

	if (nvlist_lookup_string(attr_list, DR_REQ_TYPE, &req) != 0) {
		debug_print(2,
		    "can't retrieve '%s' property from attribute list",
		    DR_REQ_TYPE);
		goto L_EXIT;
	}
	debug_print(2, "%s = '%s'", DR_REQ_TYPE, req ? req : "<null>");
	if ((req == NULL) || (strlen(req) == 0)) {
		debug_print(2, "'%s' property in message is NULL", DR_REQ_TYPE);
		goto L_EXIT;
	}

	if (nvlist_lookup_string(attr_list, ACPIDEV_EVENT_TYPE_ATTR_NAME,
	    &acpi_event_type) != 0) {
		debug_print(2,
		    "can't retrieve '%s' property from attribute list",
		    ACPIDEV_EVENT_TYPE_ATTR_NAME);
		goto L_EXIT;
	}
	debug_print(2, "%s = '%s'", ACPIDEV_EVENT_TYPE_ATTR_NAME,
	    acpi_event_type ? acpi_event_type : "<null>");
	if ((acpi_event_type == NULL) || (strlen(acpi_event_type) == 0)) {
		debug_print(2, "'%s' property in message is NULL",
		    ACPIDEV_EVENT_TYPE_ATTR_NAME);
		goto L_EXIT;
	}

	(void) event_process(ap_id, req, acpi_event_type);

L_EXIT:
	if (vendor != NULL) {
		free(vendor);
	}

	if (attr_list != NULL) {
		nvlist_free(attr_list);
	}

	/* No need to free class & subclass. */
}
