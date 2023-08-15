/***************************************************************************
 * CVSID: $Id$
 *
 * utils.c - Some utils for the hald runner
 *
 * Copyright (C) 2006 Sjoerd Simons, <sjoerd@luon.net>
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

char **
get_string_array(DBusMessageIter *iter, char *extra)
{
	GArray *array;
	char **result;
	array = g_array_new(TRUE, FALSE, sizeof(char *));

	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		const char *value;
		char *t;
		dbus_message_iter_get_basic(iter, &value);
		t = g_strdup(value);
		g_array_append_vals(array, &t, 1);
		dbus_message_iter_next(iter);
	}
	if (extra != NULL)
		g_array_append_vals(array, &extra, 1);
	result = (char **) array->data;
	g_array_free(array, FALSE);
	return result;
}

char **
get_string_array_from_fd(int fd)
{
	GArray *array;
	char **result;
	GString *str;
	gsize pos;
	GIOChannel *io;
	int i = 0;

	array = g_array_new(TRUE, FALSE, sizeof(char *));
	str = g_string_new("");
	io = g_io_channel_unix_new(fd);
	while (g_io_channel_read_line_string(io, str, &pos, NULL) == G_IO_STATUS_NORMAL && (i++ < 128)) {
		char *t;

		/* Remove the terminting char aka \n */
		g_string_erase(str, pos, 1);
		t = g_strdup(str->str);
		g_array_append_vals(array, &t, 1);
	}
	g_string_free(str, TRUE);
	g_io_channel_unref(io);
	result = (char **) array->data;
	g_array_free(array, FALSE);
	return result;
}

void
free_string_array(char **array)
{
	char **p;

	for (p = array; p != NULL && *p != NULL; p++)
		g_free(*p);
	g_free(array);
}
