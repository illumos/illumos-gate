/***************************************************************************
 * CVSID: $Id$
 *
 * runner.c - Process running code
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
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib-lowlevel.h>

#include <glib.h>
#include "utils.h"
#include "runner.h"

/* Successful run of the program */
#define HALD_RUN_SUCCESS 0x0
/* Process was killed because of running too long */
#define  HALD_RUN_TIMEOUT 0x1
/* Failed to start for some reason */
#define HALD_RUN_FAILED 0x2
/* Killed on purpose, e.g. hal_util_kill_device_helpers */
#define HALD_RUN_KILLED 0x4

GHashTable *udi_hash = NULL;
GList *singletons = NULL;

typedef struct {
	run_request *r;
	DBusMessage *msg;
	DBusConnection *con;
	GPid pid;
	gint stderr_v;
	guint watch;
	guint timeout;
	gboolean sent_kill;
	gboolean emit_pid_exited;
} run_data;

static void
del_run_data(run_data *rd)
{
	if (rd == NULL)
		return;

	del_run_request(rd->r);
	if (rd->msg)
		dbus_message_unref(rd->msg);

	g_spawn_close_pid(rd->pid);

	if (rd->stderr_v >= 0)
		close(rd->stderr_v);

	if (rd->timeout != 0)
		g_source_remove(rd->timeout);

	g_free(rd);
}

run_request *
new_run_request(void)
{
	run_request *result;
	result = g_new0(run_request, 1);
	g_assert(result != NULL);
	return result;
}

void
del_run_request(run_request *r)
{
	if (r == NULL)
		return;
	g_free(r->udi);
	free_string_array(r->environment);
	free_string_array(r->argv);
	g_free(r->input);
	g_free(r);
}

static void
send_reply(DBusConnection *con, DBusMessage *msg, guint32 exit_type, gint32 return_code, gchar **error)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	int i;

	if (con == NULL || msg == NULL)
		return;

	reply = dbus_message_new_method_return(msg);
	g_assert(reply != NULL);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &exit_type);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &return_code);
	if (error != NULL) for (i = 0; error[i] != NULL; i++) {
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &error[i]);
	}

	dbus_connection_send(con, reply, NULL);
	dbus_message_unref(reply);
}

static void
remove_run_data(run_data *rd)
{
	GList *list;

	if (rd->r->is_singleton) {
		singletons = g_list_remove(singletons, rd);
	} else {
		/* Remove to the hashtable */
		list = (GList *)g_hash_table_lookup(udi_hash, rd->r->udi);
		list = g_list_remove(list, rd);
		/* The hash table will take care to not leak the dupped string */
		g_hash_table_insert(udi_hash, g_strdup(rd->r->udi), list);
	}
}

static void
run_exited(GPid pid, gint status, gpointer data)
{
	run_data *rd = (run_data *)data;
	char **error = NULL;

	printf("pid %d: rc=%d signaled=%d: %s\n",
               pid, WEXITSTATUS(status), WIFSIGNALED(status), rd->r->argv[0]);
	rd->watch = 0;
	if (rd->sent_kill == TRUE) {
		/* We send it a kill, so ignore */
		del_run_data(rd);
		return;
	}
	/* Check if it was a normal exit */
	if (!WIFEXITED(status)) {
		/* No not normal termination ? crash ? */
		send_reply(rd->con, rd->msg, HALD_RUN_FAILED, 0, NULL);
		goto out;
	}
	/* normal exit */
	if (rd->stderr_v >= 0) {
		/* Need to read stderr */
		error = get_string_array_from_fd(rd->stderr_v);
		close(rd->stderr_v);
		rd->stderr_v = -1;
	}
	if (rd->msg != NULL)
		send_reply(rd->con, rd->msg, HALD_RUN_SUCCESS, WEXITSTATUS(status), error);
	free_string_array(error);

out:
	remove_run_data (rd);

	/* emit a signal that this PID exited */
	if(rd->con != NULL && rd->emit_pid_exited) {
		DBusMessage *signal;
		gint64 ppid = rd->pid;
		signal = dbus_message_new_signal ("/org/freedesktop/HalRunner",
						  "org.freedesktop.HalRunner",
						  "StartedProcessExited");
		dbus_message_append_args (signal,
					  DBUS_TYPE_INT64, &(ppid),
					  DBUS_TYPE_INVALID);
		dbus_connection_send(rd->con, signal, NULL);
	}

	del_run_data(rd);
}

static gboolean
run_timedout(gpointer data) {
	run_data *rd = (run_data *)data;
	/* Time is up, kill the process, send reply that it was killed!
	 * Don't wait for exit, because it could hang in state D
	 */
	kill(rd->pid, SIGTERM);
	/* Ensure the timeout is not removed in the delete */
	rd->timeout = 0;
	/* So the exit watch will know it's killed  in case it runs*/
	rd->sent_kill = TRUE;

	send_reply(rd->con, rd->msg, HALD_RUN_TIMEOUT, 0, NULL);
	remove_run_data (rd);
	return FALSE;
}

static gboolean
find_program(char **argv)
{
	/* Search for the program in the dirs where it's allowed to be */
	char *program;
	char *path = NULL;

	if (argv[0] == NULL)
		return FALSE;

	program = g_path_get_basename(argv[0]);

	/* first search $PATH to make e.g. run-hald.sh work */
	path = g_find_program_in_path (program);
	g_free(program);
	if (path == NULL)
		return FALSE;
	else {
		/* Replace program in argv[0] with the full path */
		g_free(argv[0]);
		argv[0] = path;
	}
	return TRUE;
}

/* Run the given request and reply it's result on msg */
gboolean
run_request_run (run_request *r, DBusConnection *con, DBusMessage *msg, GPid *out_pid)
{
	GPid pid;
	GError *error = NULL;
	gint *stdin_p = NULL;
	gint *stderr_p = NULL;
	gint stdin_v;
	gint stderr_v = -1;
	run_data *rd = NULL;
	gboolean program_exists = FALSE;
	char *program_dir = NULL;
	GList *list;

	printf("Run started %s (%u) (%d) \n!", r->argv[0], r->timeout,
		r->error_on_stderr);
	if (r->input != NULL) {
		stdin_p = &stdin_v;
	}
	if (r->error_on_stderr) {
		stderr_p = &stderr_v;
	}

	program_exists = find_program(r->argv);

	if (program_exists) {
		program_dir = g_path_get_dirname (r->argv[0]);
		printf("  full path is '%s', program_dir is '%s'\n", r->argv[0], program_dir);
	}

	if (!program_exists ||
		!g_spawn_async_with_pipes(program_dir, r->argv, r->environment,
		                          G_SPAWN_DO_NOT_REAP_CHILD,
		                          NULL, NULL, &pid,
		                          stdin_p, NULL, stderr_p, &error)) {
		g_free (program_dir);
		del_run_request(r);
		if (con && msg)
			send_reply(con, msg, HALD_RUN_FAILED, 0, NULL);
		return FALSE;
	}
	g_free (program_dir);

	if (r->input) {
		if (write(stdin_v, r->input, strlen(r->input)) != (ssize_t) strlen(r->input))
			printf("Warning: Error while writing r->input (%s) to stdin_v.\n", r->input);
		close(stdin_v);
	}

	rd = g_new0(run_data,1);
	g_assert(rd != NULL);
	rd->r = r;
	rd->msg = msg;
	if (msg != NULL)
		dbus_message_ref(msg);

	rd->con = con;
	rd->pid = pid;
	rd->stderr_v = stderr_v;
	rd->sent_kill = FALSE;

	/* Add watch for exit of the program */
	rd->watch = g_child_watch_add(pid, run_exited, rd);

	/* Add timeout if needed */
	if (r->timeout > 0)
		rd->timeout = g_timeout_add(r->timeout, run_timedout, rd);
	else
		rd->timeout = 0;

	if (r->is_singleton) {
		singletons = g_list_prepend(singletons, rd);
	} else {
		/* Add to the hashtable */
		list = (GList *)g_hash_table_lookup(udi_hash, r->udi);
		list = g_list_prepend(list, rd);

		/* The hash table will take care to not leak the dupped string */
		g_hash_table_insert(udi_hash, g_strdup(r->udi), list);
	}

	/* send back PID if requested.. and only emit StartedProcessExited in this case */
	if (out_pid != NULL) {
		*out_pid = pid;
		rd->emit_pid_exited = TRUE;
	}
	return TRUE;
}

static void
kill_rd(gpointer data, gpointer user_data)
{
	run_data *rd = (run_data *)data;

	kill(rd->pid, SIGTERM);
	printf("Sent kill to %d\n", rd->pid);
	if (rd->timeout != 0) {
		/* Remove the timeout watch */
		g_source_remove(rd->timeout);
		rd->timeout = 0;
	}

	/* So the exit watch will know it's killed  in case it runs */
	rd->sent_kill = TRUE;

	if (rd->msg != NULL)
		send_reply(rd->con, rd->msg, HALD_RUN_KILLED, 0, NULL);
}

static void
do_kill_udi(gchar *udi)
{
	GList *list;
	list = (GList *)g_hash_table_lookup(udi_hash, udi);
	g_list_foreach(list, kill_rd, NULL);
	g_list_free(list);
}

/* Kill all running request for a udi */
void
run_kill_udi(gchar *udi)
{
	do_kill_udi(udi);
	g_hash_table_remove(udi_hash, udi);
}

static gboolean
hash_kill_udi(gpointer key, gpointer value, gpointer user_data) {
	do_kill_udi(key);
	return TRUE;
}

/* Kill all running request*/
void
run_kill_all()
{
	g_hash_table_foreach_remove(udi_hash, hash_kill_udi, NULL);
	g_list_foreach(singletons, kill_rd, NULL);
}

void
run_init()
{
	udi_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}
