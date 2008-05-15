/***************************************************************************
 *
 * adt_data.c : Provides Audit functionalities
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 ***************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include "../hald/logger.h"
#include "adt_data.h"

adt_export_data_t *
get_audit_export_data(DBusConnection *bus, const char *invoked_by_syscon_name, size_t *data_size)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, subiter;
	DBusError error;
	int count, bufsize;
	uchar_t *buf;
	uchar_t value;

	message = dbus_message_new_method_call ("org.freedesktop.DBus",
						"/org/freedesktop/DBus",
						"org.freedesktop.DBus",
						"GetAuditSessionData");
	if (message == NULL) {
		HAL_INFO (("cannot get GetAuditSessionData message\n"));
		return NULL;
	}

	if (!dbus_message_append_args(message, DBUS_TYPE_STRING, &invoked_by_syscon_name,
	    DBUS_TYPE_INVALID)) {
		dbus_message_unref(message);
		return NULL;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (bus,
							   message, -1,
							   &error);
	if (dbus_error_is_set (&error)) {
		HAL_INFO (("send failed %s\n", error.message));
		dbus_error_free (&error);
		dbus_message_unref (message);
		return NULL;
	}
	if (reply == NULL) {
		dbus_message_unref (message);
		return NULL;
	}

	dbus_message_iter_init (reply, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY  ||
	    dbus_message_iter_get_element_type (&iter) != DBUS_TYPE_BYTE) {
		HAL_INFO (("expecting an array of byte entries\n"));
		dbus_message_unref (message);
		dbus_message_unref (reply);
		return NULL;
	}
	dbus_message_iter_recurse (&iter, &subiter);

	count = 0;
	bufsize = 256;
	buf = (uchar_t *)malloc (bufsize);

	while (dbus_message_iter_get_arg_type (&subiter) == DBUS_TYPE_BYTE) {
		if (count == bufsize) {
			bufsize += 256;
			buf = realloc (buf, bufsize);
			if (buf == NULL) {
				dbus_message_unref (message);
				dbus_message_unref (reply);
				return NULL;
			}
		}
		
		dbus_message_iter_get_basic (&subiter, &value);
		buf[count++] = value;
		dbus_message_iter_next(&subiter);
	}

	dbus_message_unref (message);
	dbus_message_unref (reply);

	*data_size = count;
	if (count == 0) {
		free (buf);
		buf = NULL;
	}

	return (adt_export_data_t *)buf;
}
