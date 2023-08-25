/***************************************************************************
 * CVSID: $Id$
 *
 * main.c - Main dbus interface of the hald runner
 *
 * Copyright (C) 2006 Sjoerd Simons, <sjoerd@luon.net>
 * Copyright (C) 2007 Codethink Ltd. Author Rob Taylor <rob.taylor@codethink.co.uk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib-lowlevel.h>

#include <glib.h>
#include "utils.h"
#include "runner.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

static gboolean
parse_udi (run_request *r, DBusMessage *msg, DBusMessageIter *iter)
{
	char *tmpstr;

	/* Should be the device UDI */
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING)
		goto malformed;
	dbus_message_iter_get_basic(iter, &tmpstr);
	r->udi = g_strdup(tmpstr);

	if (!dbus_message_iter_next(iter))
		goto malformed;

	return TRUE;

malformed:
	return FALSE;
}

static gboolean
parse_environment(run_request *r, DBusMessage *msg, DBusMessageIter *iter)
{
	DBusMessageIter sub_iter;
	char *tmpstr;

	/* The environment array */
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		goto malformed;
	dbus_message_iter_recurse(iter, &sub_iter);
	/* Add default path for the programs we start */
#if defined(__FreeBSD__)
	tmpstr = g_strdup_printf("PATH=/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/X11R6/sbin:/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin:%s", getenv("PATH"));
#else
	tmpstr = g_strdup_printf("PATH=/sbin:/usr/sbin:/bin:/usr/bin:%s", getenv("PATH"));
#endif
	r->environment = get_string_array(&sub_iter, tmpstr);

	/* Then argv */
	if (!dbus_message_iter_next(iter) || dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		goto malformed;
	dbus_message_iter_recurse(iter, &sub_iter);
	r->argv = get_string_array(&sub_iter, NULL);

	return TRUE;

malformed:
	return FALSE;
}

static void
handle_run(DBusConnection *con, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	run_request *r;
	char *tmpstr;

	r = new_run_request();
	g_assert(dbus_message_iter_init(msg, &iter));

	if (!parse_udi(r, msg, &iter))
		goto malformed;

	if (!parse_environment(r, msg, &iter))
		goto malformed;

	/* Next a string of what should be written to stdin */
	if (!dbus_message_iter_next(&iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto malformed;
	dbus_message_iter_get_basic(&iter, &tmpstr);
	r->input = g_strdup(tmpstr);

	/* Then an bool to indicate if we should grab stderr */
	if (!dbus_message_iter_next(&iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN)
		goto malformed;
	dbus_message_iter_get_basic(&iter, &(r->error_on_stderr));

	/* Then an uint32 timeout for it */
	if (!dbus_message_iter_next(&iter) || dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
		goto malformed;
	dbus_message_iter_get_basic(&iter, &(r->timeout));

	/* let run_request_run handle the reply */
	run_request_run(r, con, msg, NULL);
	return;

malformed:
	del_run_request(r);
	reply = dbus_message_new_error(msg, "org.freedesktop.HalRunner.Malformed",
				       "Malformed run request");
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
}

static void
handle_start(DBusConnection *con, DBusMessage *msg, gboolean is_singleton)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	run_request *r;
	GPid pid;

	r = new_run_request();
	r->is_singleton = is_singleton;

	g_assert(dbus_message_iter_init(msg, &iter));

	if (!dbus_message_iter_init(msg, &iter))
		goto malformed;

	if (!is_singleton && !parse_udi(r, msg, &iter)) {
		fprintf(stderr, "error parsing udi");
		goto malformed;
	}

	if (!parse_environment(r, msg, &iter)) {
		fprintf(stderr, "error parsing environment");
		goto malformed;
	}

	if (run_request_run(r, con, NULL, &pid)) {
		gint64 ppid = pid;
		reply = dbus_message_new_method_return(msg);
		dbus_message_append_args (reply,
					  DBUS_TYPE_INT64, &ppid,
					  DBUS_TYPE_INVALID);

	} else {
		reply = dbus_message_new_error(msg, "org.freedesktop.HalRunner.Failed",
					       "Start request failed");
	}
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
	return ;
malformed:
	del_run_request(r);
	reply = dbus_message_new_error(msg, "org.freedesktop.HalRunner.Malformed",
				       "Malformed start request");
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
}

static void
handle_kill(DBusConnection *con, DBusMessage *msg)
{
	DBusError error;
	DBusMessage *reply = NULL;
	char *udi;

	dbus_error_init (&error);
	if (!dbus_message_get_args(msg, &error,
				   DBUS_TYPE_STRING, &udi,
				   DBUS_TYPE_INVALID)) {
		reply = dbus_message_new_error (msg, "org.freedesktop.HalRunner.Malformed",
						"Malformed kill message");
		g_assert(reply);
		dbus_connection_send (con, reply, NULL);
		dbus_message_unref(reply);
		return;
	}
	run_kill_udi(udi);

	/* always successfull */
	reply = dbus_message_new_method_return(msg);
	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
}

static DBusHandlerResult
filter(DBusConnection *con, DBusMessage *msg, void *user_data)
{
	DBusMessage *reply;

	if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "Run")) {
		handle_run(con, msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "Start")) {
		handle_start(con, msg, FALSE);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "StartSingleton")) {
		handle_start(con, msg, TRUE);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "Kill")) {
		handle_kill(con, msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "Shutdown")) {
		run_kill_all ();
		exit (0);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_method_call(msg, "org.freedesktop.HalRunner", "KillAll")) {
		run_kill_all();
		/* alwasy successfull */
		reply = dbus_message_new_method_return(msg);
		dbus_connection_send(con, reply, NULL);
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int
main(int argc, char **argv)
{
	DBusConnection *c;
	DBusError error;
	GMainLoop *loop;
	char *dbus_address;

	run_init();
	dbus_error_init(&error);
	dbus_address = getenv("HALD_RUNNER_DBUS_ADDRESS");
	g_assert(dbus_address != NULL);

	fprintf(stderr, "Runner started - allowed paths are '%s'\n", getenv("PATH"));

	c = dbus_connection_open(dbus_address, &error);
	if (c == NULL)
		goto error;

	loop = g_main_loop_new(NULL, FALSE);

	dbus_connection_setup_with_g_main(c, NULL);
	dbus_connection_set_exit_on_disconnect(c, TRUE);
	dbus_connection_add_filter(c, filter, NULL, NULL);

	g_main_loop_run(loop);

error:
	fprintf(stderr,"An error has occured: %s\n", error.message);
	return -1;
}
