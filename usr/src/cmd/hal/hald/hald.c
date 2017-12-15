/***************************************************************************
 * CVSID: $Id$
 *
 * hald.c : main startup for HAL daemon
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2005 Danny Kukawka, <danny.kukawka@web.de>
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <grp.h>
#include <syslog.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

/*#include "master_slave.h"*/

#include "logger.h"
#include "hald.h"
#include "device_store.h"
#include "device_info.h"
#include "osspec.h"
#include "hald_dbus.h"
#include "util.h"
#include "hald_runner.h"
#include "util_helper.h"

static void delete_pid(void)
{
	unlink(HALD_PID_FILE);
}

/**
 * @defgroup HalDaemon HAL daemon
 * @brief The HAL daemon manages persistent device objects available through
 *        a D-BUS network API
 */

static HalDeviceStore *global_device_list = NULL;

static HalDeviceStore *temporary_device_list = NULL;


static void
addon_terminated (HalDevice *device, guint32 exit_type, 
		  gint return_code, gchar **error,
		  gpointer data1, gpointer data2)
{
	HAL_INFO (("in addon_terminated for udi=%s", device->udi));

	/* TODO: log to syslog - addons shouldn't just terminate, this is a bug with the addon */

	/* however, the world can stop, mark this addon as ready 
	 * (TODO: potential bug if the addon crashed after calling libhal_device_addon_is_ready())
	 */
	if (hal_device_inc_num_ready_addons (device)) {
		if (hal_device_are_all_addons_ready (device)) {
			manager_send_signal_device_added (device);
		}
	}
}




static void
gdl_store_changed (HalDeviceStore *store, HalDevice *device,
		   gboolean is_added, gpointer user_data)
{
	if (is_added) {
		GSList *addons;

		HAL_INFO (("Added device to GDL; udi=%s", hal_device_get_udi(device)));

		if ((addons = hal_device_property_get_strlist (device, "info.addons")) != NULL) {
			GSList *i;

			for (i = addons; i != NULL; i = g_slist_next (i)) {
				const gchar *command_line;
				gchar *extra_env[2] = {"HALD_ACTION=addon", NULL};

				command_line = (const gchar *) i->data;
				if (hald_runner_start(device, command_line, extra_env, addon_terminated, NULL, NULL)) {
					HAL_INFO (("Started addon %s for udi %s", 
						   command_line, hal_device_get_udi(device)));
					hal_device_inc_num_addons (device);
				} else {
					HAL_ERROR (("Cannot start addon %s for udi %s", 
						    command_line, hal_device_get_udi(device)));
				}
			}
		}
	} else {
		HAL_INFO (("Removed device from GDL; udi=%s", hal_device_get_udi(device)));
		hald_runner_kill_device(device);
	}

	/*hal_device_print (device);*/

	if (is_added) {
		if (hal_device_are_all_addons_ready (device)) {
			manager_send_signal_device_added (device);
		}
	} else {
		if (hal_device_are_all_addons_ready (device)) {
			manager_send_signal_device_removed (device);
		}
	}
}

static void
gdl_property_changed (HalDeviceStore *store, HalDevice *device,
		      const char *key, gboolean added, gboolean removed,
		      gpointer user_data)
{
	if (hal_device_are_all_addons_ready (device)) {
		device_send_signal_property_modified (device, key, removed, added);
	}

	/* only execute the callouts if the property _changed_ */
	if (added == FALSE && removed == FALSE)
		/*hal_callout_property (device, key)*/;
}

static void
gdl_capability_added (HalDeviceStore *store, HalDevice *device,
		      const char *capability, gpointer user_data)
{
	if (hal_device_are_all_addons_ready (device)) {
		manager_send_signal_new_capability (device, capability);
	}
	/*hal_callout_capability (device, capability, TRUE)*/;
}

HalDeviceStore *
hald_get_gdl (void)
{
	if (global_device_list == NULL) {
		global_device_list = hal_device_store_new ();
		
		g_signal_connect (global_device_list,
				  "store_changed",
				  G_CALLBACK (gdl_store_changed), NULL);
		g_signal_connect (global_device_list,
				  "device_property_changed",
				  G_CALLBACK (gdl_property_changed), NULL);
		g_signal_connect (global_device_list,
				  "device_capability_added",
				  G_CALLBACK (gdl_capability_added), NULL);
	}

	return global_device_list;
}

HalDeviceStore *
hald_get_tdl (void)
{
	if (temporary_device_list == NULL) {
		temporary_device_list = hal_device_store_new ();
		
	}

	return temporary_device_list;
}

/**
 * @defgroup MainDaemon Basic functions
 * @ingroup HalDaemon
 * @brief Basic functions in the HAL daemon
 * @{
 */

/** Print out program usage.
 *
 */
static void
usage ()
{
	fprintf (stderr, "\n" "usage : hald [--daemon=yes|no] [--verbose=yes|no] [--help]\n");
	fprintf (stderr,
		 "\n"
		 "        --daemon=yes|no      Become a daemon\n"
		 "        --verbose=yes|no     Print out debug (overrides HALD_VERBOSE)\n"
 		 "        --use-syslog         Print out debug messages to syslog instead of stderr.\n"
		 "                             Use this option to get debug messages if HAL runs as\n"
		 "                             daemon.\n"
		 "        --help               Show this information and exit\n"
		 "        --version            Output version information and exit"
		 "\n"
		 "The HAL daemon detects devices present in the system and provides the\n"
		 "org.freedesktop.Hal service through the system-wide message bus provided\n"
		 "by D-BUS.\n"
		 "\n"
		 "For more information visit http://freedesktop.org/Software/hal\n"
		 "\n");
}

/** If #TRUE, we will daemonize */
static dbus_bool_t opt_become_daemon = TRUE;

/** If #TRUE, we will spew out debug */
dbus_bool_t hald_is_verbose = FALSE;
dbus_bool_t hald_use_syslog = FALSE;

static int sigterm_unix_signal_pipe_fds[2];
static GIOChannel *sigterm_iochn;

static void 
handle_sigterm (int value)
{
	static char marker[1] = {'S'};

	/* write a 'S' character to the other end to tell about
	 * the signal. Note that 'the other end' is a GIOChannel thingy
	 * that is only called from the mainloop - thus this is how we
	 * defer this since UNIX signal handlers are evil
	 *
	 * Oh, and write(2) is indeed reentrant */
	(void) write (sigterm_unix_signal_pipe_fds[1], marker, 1);
}

static gboolean
sigterm_iochn_data (GIOChannel *source, 
		    GIOCondition condition, 
		    gpointer user_data)
{
	GError *err = NULL;
	gchar data[1];
	gsize bytes_read;

	/* Empty the pipe */
	if (G_IO_STATUS_NORMAL != 
	    g_io_channel_read_chars (source, data, 1, &bytes_read, &err)) {
		HAL_ERROR (("Error emptying sigterm pipe: %s",
				   err->message));
		g_error_free (err);
		goto out;
	}

	HAL_INFO (("Caught SIGTERM, initiating shutdown"));
	hald_runner_kill_all();
	exit (0);

out:
	return TRUE;
}


/** This is set to #TRUE if we are probing and #FALSE otherwise */
dbus_bool_t hald_is_initialising;

static int startup_daemonize_pipe[2];


/*--------------------------------------------------------------------------------------------------*/

static gboolean child_died = FALSE;

static void 
handle_sigchld (int value)
{
	child_died = TRUE;
}

static int 
parent_wait_for_child (int child_fd, pid_t child_pid)
{
	fd_set rfds;
	fd_set efds;
	struct timeval tv;
	int retval;
	int ret;

	signal(SIGCHLD, handle_sigchld);

	/* wait for either
	 *
	 * o Child writes something to the child_fd; means that device
	 *   probing is completed and the parent should exit with success
	 *
	 * o Child is killed (segfault etc.); means that parent should exit
	 *   with failure
	 *
	 * o Timeout; means that we should kill the child and exit with
	 *   failure
	 *
	 */

	FD_ZERO(&rfds);
	FD_SET(child_fd, &rfds);
	FD_ZERO(&efds);
	FD_SET(child_fd, &efds);
	/* Wait up to 250 seconds for device probing */
	tv.tv_sec = 250;
	tv.tv_usec = 0;

	retval = select (child_fd + 1, &rfds, NULL, &efds, &tv);

	if (child_died) {
		/* written from handle_sigchld */
		ret = 1;
		goto out;
	}

	if (retval > 0) {
		/* means child wrote to socket or closed it; all good */
		ret = 0;
		goto out;
	}

	/* assume timeout; kill child */
	kill (child_pid, SIGTERM);
	ret = 2;

out:
	return ret;
}

/*--------------------------------------------------------------------------------------------------*/

/** Entry point for HAL daemon
 *
 *  @param  argc                Number of arguments
 *  @param  argv                Array of arguments
 *  @return                     Exit code
 */
int
main (int argc, char *argv[])
{
	GMainLoop *loop;
	char *path;
	char newpath[512];

	openlog ("hald", LOG_PID, LOG_DAEMON);
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	if (getenv ("HALD_VERBOSE"))
		hald_is_verbose = TRUE;
	else
		hald_is_verbose = FALSE;

	/* our helpers are installed into libexec, so adjust out $PATH
	 * to include this at the end (since we want to overide in
	 * run-hald.sh and friends)
	 */
	path = getenv ("PATH");
	if (path != NULL) {
		g_strlcpy (newpath, path, sizeof (newpath));
		g_strlcat (newpath, ":", sizeof (newpath));
	} else {
		/* No PATH was set */
		newpath[0] = '\0';
	} 

	g_strlcat (newpath, PACKAGE_LIBEXEC_DIR, sizeof (newpath));
	g_strlcat (newpath, ":", sizeof (newpath));
	g_strlcat (newpath, PACKAGE_SCRIPT_DIR, sizeof (newpath));

	setenv ("PATH", newpath, TRUE);

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"daemon", 1, NULL, 0},
			{"verbose", 1, NULL, 0},
			{"use-syslog", 0, NULL, 0},
			{"help", 0, NULL, 0},
			{"version", 0, NULL, 0},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc, argv, "",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			opt = long_options[option_index].name;

			if (strcmp (opt, "help") == 0) {
				usage ();
				return 0;
			} else if (strcmp (opt, "version") == 0) {
				fprintf (stderr, "HAL package version: " PACKAGE_VERSION "\n");
				return 0;
			} else if (strcmp (opt, "daemon") == 0) {
				if (strcmp ("yes", optarg) == 0) {
					opt_become_daemon = TRUE;
				} else if (strcmp ("no", optarg) == 0) {
					opt_become_daemon = FALSE;
				} else {
					usage ();
					return 1;
				}
			} else if (strcmp (opt, "verbose") == 0) {
				if (strcmp ("yes", optarg) == 0) {
					hald_is_verbose = TRUE;
				} else if (strcmp ("no", optarg) == 0) {
					hald_is_verbose = FALSE;
				} else {
					usage ();
					return 1;
				}
			} else if (strcmp (opt, "use-syslog") == 0) {
                                hald_use_syslog = TRUE;
			}

			break;

		default:
			usage ();
			return 1;
			break;
		}
	}

	if (hald_is_verbose)
		logger_enable ();
	else
		logger_disable ();

	if (hald_use_syslog)
		logger_enable_syslog ();
	else
		logger_disable_syslog ();

	/* will fork into two; only the child will return here if we are successful */
	/*master_slave_setup ();
	  sleep (100000000);*/

	loop = g_main_loop_new (NULL, FALSE);

	HAL_INFO ((PACKAGE_STRING));

	if (opt_become_daemon) {
		int child_pid;
		int dev_null_fd;
		int pf;
		char pid[9];
		
		HAL_INFO (("Will daemonize"));
		HAL_INFO (("Becoming a daemon"));

		if (pipe (startup_daemonize_pipe) != 0) {
			fprintf (stderr, "Could not setup pipe: %s\n", strerror(errno));
			exit (1);
		}


		if (chdir ("/") < 0) {
			fprintf (stderr, "Could not chdir to /: %s\n", strerror(errno));
			exit (1);
		}

		child_pid = fork ();
		switch (child_pid) {
		case -1:
			fprintf (stderr, "Cannot fork(): %s\n", strerror(errno));
			break;

		case 0:
			/* child */

			dev_null_fd = open ("/dev/null", O_RDWR);
			/* ignore if we can't open /dev/null */
			if (dev_null_fd >= 0) {
				/* attach /dev/null to stdout, stdin, stderr */
				dup2 (dev_null_fd, 0);
				dup2 (dev_null_fd, 1);
				dup2 (dev_null_fd, 2);
				close (dev_null_fd);
			}

			umask (022);
			break;

		default:
			/* parent, block until child writes */
			exit (parent_wait_for_child (startup_daemonize_pipe[0], child_pid));
			break;
		}

		/* Create session */
		setsid ();

		/* remove old pid file */
		unlink (HALD_PID_FILE);

		/* Make a new one */
		if ((pf= open (HALD_PID_FILE, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) > 0) {
			snprintf (pid, sizeof(pid), "%lu\n", (long unsigned) getpid ());
			(void) write (pf, pid, strlen(pid));
			close (pf);
			atexit (delete_pid);
		}
	} else {
		HAL_INFO (("Will not daemonize"));
	}


	/* we need to do stuff when we are expected to terminate, thus
	 * this involves looking for SIGTERM; UNIX signal handlers are
	 * evil though, so set up a pipe to transmit the signal.
	 */

	/* create pipe */
	if (pipe (sigterm_unix_signal_pipe_fds) != 0) {
		DIE (("Could not setup pipe, errno=%d", errno));
	}
	
	/* setup glib handler - 0 is for reading, 1 is for writing */
	sigterm_iochn = g_io_channel_unix_new (sigterm_unix_signal_pipe_fds[0]);
	if (sigterm_iochn == NULL)
		DIE (("Could not create GIOChannel"));
	
	/* get callback when there is data to read */
	(void) g_io_add_watch (
		sigterm_iochn, G_IO_IN, sigterm_iochn_data, NULL);
	
	/* Finally, setup unix signal handler for TERM */
	signal (SIGTERM, handle_sigterm);

	/* set up the local dbus server */
	if (!hald_dbus_local_server_init ())
		return 1;
	/* Start the runner helper daemon */
	if (!hald_runner_start_runner ()) {
		return 1;
	}

	drop_privileges(0);

	/* initialize operating system specific parts */
	osspec_init ();

	hald_is_initialising = TRUE;

	/* detect devices */
	osspec_probe ();

	/* run the main loop and serve clients */
	g_main_loop_run (loop);

	return 0;
}

#ifdef HALD_MEMLEAK_DBG
extern int dbg_hal_device_object_delta;

/* useful for valgrinding; see below */
static gboolean
my_shutdown (gpointer data)
{
	HalDeviceStore *gdl;
	
	printf ("Num devices in TDL: %d\n", g_slist_length ((hald_get_tdl ())->devices));
	printf ("Num devices in GDL: %d\n", g_slist_length ((hald_get_gdl ())->devices));
	
	gdl = hald_get_gdl ();
next:
	if (g_slist_length (gdl->devices) > 0) {
		HalDevice *d = HAL_DEVICE(gdl->devices->data);
		hal_device_store_remove (gdl, d);
		g_object_unref (d);
		goto next;
	}
	
	printf ("hal_device_object_delta = %d (should be zero)\n", dbg_hal_device_object_delta);
	exit (1);
}
#endif

void 
osspec_probe_done (void)
{
	char buf[1] = {0};

	HAL_INFO (("Device probing completed"));

	if (!hald_dbus_init ()) {
		hald_runner_kill_all();
		exit (1);
	}

	/* tell parent to exit */
	(void) write (startup_daemonize_pipe[1], buf, sizeof (buf));
	close (startup_daemonize_pipe[0]);
	close (startup_daemonize_pipe[1]);

	hald_is_initialising = FALSE;

#ifdef HALD_MEMLEAK_DBG
	g_timeout_add ((HALD_MEMLEAK_DBG) * 1000,
		       my_shutdown,
		       NULL);
#endif
}


/** @} */
