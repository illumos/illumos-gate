/***************************************************************************
 * CVSID: $Id$
 *
 * runner.h - Process running interface
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
#ifndef RUNNER_H
#define RUNNER_H

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib-lowlevel.h>

#include <glib.h>

typedef struct {
	gchar *udi;
	gchar **environment;
	gchar **argv;
	gchar *input;
	gboolean error_on_stderr;
	gboolean is_singleton;
	guint32 timeout;
} run_request;

run_request *new_run_request(void);
void del_run_request(run_request *r);

/* Run the given request and reply it's result on msg */
gboolean run_request_run(run_request *r, DBusConnection *con, DBusMessage *msg, GPid *out_pid);

/* Kill all running request for a udi */
void run_kill_udi(gchar *udi);

/* Kill all running request*/
void run_kill_all(void);

/* initialise the actual runner data */
void run_init(void);

#endif /*  RUNNER_H */
