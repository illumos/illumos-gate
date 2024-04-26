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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * rmvolmgr daemon
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>
#include <libintl.h>
#include <sys/syscall.h>
#include <libscf.h>
#include <priv_utils.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <libhal.h>

#include "rmm_common.h"

char *progname = "rmvolmgr";

#define	RMVOLMGR_FMRI	"svc:/system/filesystem/rmvolmgr:default"

typedef struct managed_volume {
	char			*udi;
	boolean_t		my;
	struct action_arg	aa;
} managed_volume_t;

static GSList		*managed_volumes;

static GMainLoop	*mainloop;
static LibHalContext	*hal_ctx;
static int		sigexit_pipe[2];
static GIOChannel	*sigexit_ioch;

static boolean_t	opt_c;	/* disable CDE compatibility */
static boolean_t	opt_n;	/* disable legacy mountpoint symlinks */
static boolean_t	opt_s;	/* system instance */

/* SMF property "eject_button" */
static boolean_t	rmm_prop_eject_button = B_TRUE;

static void	get_smf_properties();
static void	rmm_device_added(LibHalContext *ctx, const char *udi);
static void	rmm_device_removed(LibHalContext *ctx, const char *udi);
static void	rmm_property_modified(LibHalContext *ctx, const char *udi,
		const char *key, dbus_bool_t is_removed, dbus_bool_t is_added);
static void	rmm_device_condition(LibHalContext *ctx, const char *udi,
		const char *name, const char *detail);
static void	rmm_mount_all();
static void	rmm_unmount_all();
static void	sigexit(int signo);
static gboolean	sigexit_ioch_func(GIOChannel *source, GIOCondition condition,
		gpointer user_data);

static void
usage()
{
	(void) fprintf(stderr, gettext("\nusage: rmvolmgr [-v]\n"));
}

static int
rmvolmgr(int argc, char **argv)
{
	const char	*opts = "chnsv";
	DBusError	error;
	boolean_t	daemonize;
	rmm_error_t	rmm_error;
	int		c;

	while ((c = getopt(argc, argv, opts)) != EOF) {
		switch (c) {
		case 'c':
			opt_c = B_TRUE;
			break;
		case 'n':
			opt_n = B_TRUE;
			break;
		case 's':
			opt_s = B_TRUE;
			break;
		case 'v':
			rmm_debug = 1;
			break;
		case '?':
		case 'h':
			usage();
			return (0);
		default:
			usage();
			return (1);
		}
	}

	if (opt_s) {
		if (geteuid() != 0) {
			(void) fprintf(stderr,
			    gettext("system instance must have euid 0\n"));
			return (1);
		}

		get_smf_properties();

		if (opt_c) {
			rmm_vold_actions_enabled = B_FALSE;
		}
		if (opt_n) {
			rmm_vold_mountpoints_enabled = B_FALSE;
		}


		/*
		 * Drop unused privileges. Remain root for HAL interaction
		 * and to create legacy symlinks.
		 *
		 * Need PRIV_FILE_DAC_WRITE to write to users'
		 * /tmp/.removable/notify* files.
		 */
		if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
		    0, 0,
		    rmm_vold_actions_enabled ? PRIV_FILE_DAC_WRITE : NULL,
		    NULL) == -1) {
			(void) fprintf(stderr,
			    gettext("failed to drop privileges"));
			return (1);
		}
		/* basic privileges we don't need */
		(void) priv_set(PRIV_OFF, PRIV_PERMITTED, PRIV_PROC_EXEC,
		    PRIV_PROC_INFO, PRIV_FILE_LINK_ANY, PRIV_PROC_SESSION,
		    NULL);

	} else {
		if (opt_c) {
			rmm_vold_actions_enabled = B_FALSE;
		}
		if (opt_n) {
			rmm_vold_mountpoints_enabled = B_FALSE;
		}
	}

	daemonize = (getenv("RMVOLMGR_NODAEMON") == NULL);

	if (daemonize && daemon(0, 0) < 0) {
		dbgprintf("daemonizing failed: %s", strerror(errno));
		return (1);
	}

	if (opt_s) {
		__fini_daemon_priv(PRIV_PROC_FORK, NULL);
	}

	/*
	 * signal mainloop integration using pipes
	 */
	if (pipe(sigexit_pipe) != 0) {
		dbgprintf("pipe failed %s\n", strerror(errno));
		return (1);
	}
	sigexit_ioch = g_io_channel_unix_new(sigexit_pipe[0]);
	if (sigexit_ioch == NULL) {
		dbgprintf("g_io_channel_unix_new failed\n");
		return (1);
	}
	g_io_add_watch(sigexit_ioch, G_IO_IN, sigexit_ioch_func, NULL);
	signal(SIGTERM, sigexit);
	signal(SIGINT, sigexit);
	signal(SIGHUP, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	if ((hal_ctx = rmm_hal_init(rmm_device_added, rmm_device_removed,
	    rmm_property_modified, rmm_device_condition,
	    &error, &rmm_error)) == NULL) {
		dbus_error_free(&error);
		return (1);
	}

	/* user instance should claim devices */
	if (!opt_s) {
		if (!rmm_hal_claim_branch(hal_ctx, HAL_BRANCH_LOCAL)) {
			(void) fprintf(stderr,
			    gettext("cannot claim branch\n"));
			return (1);
		}
	}

	rmm_mount_all();

	if ((mainloop = g_main_loop_new(NULL, B_FALSE)) == NULL) {
		dbgprintf("Cannot create main loop\n");
		return (1);
	}

	g_main_loop_run(mainloop);

	return (0);
}

static void
get_smf_properties()
{
	scf_simple_prop_t *prop;
	uint8_t *val;

	if ((prop = scf_simple_prop_get(NULL, RMVOLMGR_FMRI,
	    "rmvolmgr", "legacy_mountpoints")) != NULL) {
		if ((val = scf_simple_prop_next_boolean(prop)) != NULL) {
			rmm_vold_mountpoints_enabled = (*val != 0);
		}
		scf_simple_prop_free(prop);
	}

	if ((prop = scf_simple_prop_get(NULL, RMVOLMGR_FMRI,
	    "rmvolmgr", "cde_compatible")) != NULL) {
		if ((val = scf_simple_prop_next_boolean(prop)) != NULL) {
			rmm_vold_actions_enabled = (*val != 0);
		}
		scf_simple_prop_free(prop);
	}

	if ((prop = scf_simple_prop_get(NULL, RMVOLMGR_FMRI,
	    "rmvolmgr", "eject_button")) != NULL) {
		if ((val = scf_simple_prop_next_boolean(prop)) != NULL) {
			rmm_prop_eject_button = (*val != 0);
		}
		scf_simple_prop_free(prop);
	}
}

/* ARGSUSED */
static void
sigexit(int signo)
{
	dbgprintf("signal to exit %d\n", signo);

	write(sigexit_pipe[1], "s", 1);
}

/* ARGSUSED */
static gboolean
sigexit_ioch_func(GIOChannel *source, GIOCondition condition,
    gpointer user_data)
{
	gchar	buf[1];
	gsize	bytes_read;
	GError	*error = NULL;

	if (g_io_channel_read_chars(source, buf, 1, &bytes_read, &error) !=
	    G_IO_STATUS_NORMAL) {
		dbgprintf("g_io_channel_read_chars failed %s", error->message);
		g_error_free(error);
		return (TRUE);
	}

	dbgprintf("signal to exit\n");

	rmm_unmount_all();

	g_main_loop_quit(mainloop);

	return (TRUE);
}

static managed_volume_t *
rmm_managed_alloc(LibHalContext *ctx, const char *udi)
{
	managed_volume_t *v;

	if ((v = calloc(1, sizeof (managed_volume_t))) == NULL) {
		return (NULL);
	}
	if ((v->udi = strdup(udi)) == NULL) {
		free(v);
		return (NULL);
	}
	if (!rmm_volume_aa_from_prop(ctx, udi, NULL, &v->aa)) {
		free(v->udi);
		free(v);
		return (NULL);
	}

	return (v);
}

static void
rmm_managed_free(managed_volume_t *v)
{
	rmm_volume_aa_free(&v->aa);
	free(v->udi);
	free(v);
}

static gint
rmm_managed_compare_udi(gconstpointer a, gconstpointer b)
{
	const managed_volume_t *va = a;
	const char *udi = b;

	return (strcmp(va->udi, udi));
}

static boolean_t
volume_should_mount(const char *udi)
{
	char	*storage_device = NULL;
	int	ret = B_FALSE;

	if (libhal_device_get_property_bool(hal_ctx, udi,
	    "volume.ignore", NULL)) {
		goto out;
	}

	/* get the backing storage device */
	if (!(storage_device = libhal_device_get_property_string(hal_ctx, udi,
	    "block.storage_device", NULL))) {
		dbgprintf("cannot get block.storage_device\n");
		goto out;
	}

	/* we handle either removable or hotpluggable */
	if (!libhal_device_get_property_bool(hal_ctx, storage_device,
	    "storage.removable", NULL) &&
	    !libhal_device_get_property_bool(hal_ctx, storage_device,
	    "storage.hotpluggable", NULL)) {
		goto out;
	}

	/* ignore if claimed by another volume manager */
	if (libhal_device_get_property_bool(hal_ctx, storage_device,
	    "info.claimed", NULL)) {
		goto out;
	}

	ret = B_TRUE;

out:
	libhal_free_string(storage_device);
	return (ret);
}

static void
volume_added(const char *udi)
{
	GSList		*l;
	managed_volume_t *v;

	dbgprintf("volume added %s\n", udi);

	l = g_slist_find_custom(managed_volumes, udi, rmm_managed_compare_udi);
	v = (l != NULL) ? l->data : NULL;

	if (v != NULL) {
		dbgprintf("already managed %s\n", udi);
		return;
	}
	if (!volume_should_mount(udi)) {
		dbgprintf("should not mount %s\n", udi);
		return;
	}
	if ((v = rmm_managed_alloc(hal_ctx, udi)) == NULL) {
		return;
	}
	if (rmm_action(hal_ctx, udi, INSERT, &v->aa, 0, 0, 0)) {
		v->my = B_TRUE;
		managed_volumes = g_slist_prepend(managed_volumes, v);
	} else {
		dbgprintf("rmm_action failed %s\n", udi);
		rmm_managed_free(v);
	}
}

static void
volume_removed(const char *udi)
{
	GSList		*l;
	managed_volume_t *v;

	dbgprintf("volume removed %s\n", udi);

	l = g_slist_find_custom(managed_volumes, udi, rmm_managed_compare_udi);
	v = (l != NULL) ? l->data : NULL;
	if (v == NULL) {
		return;
	}

	/* HAL will unmount, just do the vold legacy stuff */
	v->aa.aa_action = EJECT;
	(void) vold_postprocess(hal_ctx, udi, &v->aa);

	rmm_managed_free(v);
	managed_volumes = g_slist_delete_link(managed_volumes, l);
}

/* ARGSUSED */
static void
rmm_device_added(LibHalContext *ctx, const char *udi)
{
	if (libhal_device_query_capability(hal_ctx, udi, "volume", NULL)) {
		volume_added(udi);
	}
}

/* ARGSUSED */
static void
rmm_device_removed(LibHalContext *ctx, const char *udi)
{
	if (libhal_device_query_capability(hal_ctx, udi, "volume", NULL)) {
		volume_removed(udi);
	}
}

/* ARGSUSED */
static void
rmm_property_modified(LibHalContext *ctx, const char *udi, const char *key,
    dbus_bool_t is_removed, dbus_bool_t is_added)
{
	DBusError		error;
	GSList			*l;
	managed_volume_t	*v;
	boolean_t		is_mounted;

	if (strcmp(key, "volume.is_mounted") != 0) {
		return;
	}
	is_mounted = libhal_device_get_property_bool(hal_ctx, udi, key, NULL);

	l = g_slist_find_custom(managed_volumes, udi, rmm_managed_compare_udi);
	v = (l != NULL) ? l->data : NULL;

	if (is_mounted) {
		dbgprintf("Mounted: %s\n", udi);

		if (v != NULL) {
			/* volume mounted by us is already taken care of */
			if (v->my) {
				return;
			}
		} else {
			if ((v = rmm_managed_alloc(ctx, udi)) == NULL) {
				return;
			}
			managed_volumes = g_slist_prepend(managed_volumes, v);
		}

		v->aa.aa_action = INSERT;
		(void) vold_postprocess(hal_ctx, udi, &v->aa);

	} else {
		dbgprintf("Unmounted: %s\n", udi);

		if (v == NULL) {
			return;
		}

		v->aa.aa_action = EJECT;
		(void) vold_postprocess(hal_ctx, udi, &v->aa);

		rmm_managed_free(v);
		managed_volumes = g_slist_delete_link(managed_volumes, l);
	}
}

static void
storage_eject_pressed(const char *udi)
{
	DBusError	error;

	/* ignore if disabled via SMF or claimed by another volume manager */
	if (!rmm_prop_eject_button ||
	    libhal_device_get_property_bool(hal_ctx, udi, "info.claimed",
	    NULL)) {
		return;
	}

	dbus_error_init(&error);
	(void) rmm_hal_eject(hal_ctx, udi, &error);
	rmm_dbus_error_free(&error);
}

/* ARGSUSED */
static void
rmm_device_condition(LibHalContext *ctx, const char *udi,
    const char *name, const char *detail)
{
	if ((strcmp(name, "EjectPressed") == 0) &&
	    libhal_device_query_capability(hal_ctx, udi, "storage", NULL)) {
		storage_eject_pressed(udi);
	}
}

/*
 * Mount all mountable volumes
 */
static void
rmm_mount_all()
{
	DBusError	error;
	char		**udis = NULL;
	int		num_udis;
	int		i;
	managed_volume_t *v;

	dbus_error_init(&error);

	/* get all volumes */
	if ((udis = libhal_find_device_by_capability(hal_ctx, "volume",
	    &num_udis, &error)) == NULL) {
		dbgprintf("mount_all: no volumes found\n");
		goto out;
	}

	for (i = 0; i < num_udis; i++) {
		/* skip if already mounted */
		if (libhal_device_get_property_bool(hal_ctx, udis[i],
		    "volume.is_mounted", NULL)) {
			dbgprintf("mount_all: %s already mounted\n", udis[i]);
			continue;
		}
		if (!volume_should_mount(udis[i])) {
			continue;
		}
		if ((v = rmm_managed_alloc(hal_ctx, udis[i])) == NULL) {
			continue;
		}
		if (rmm_action(hal_ctx, udis[i], INSERT, &v->aa, 0, 0, 0)) {
			v->my = B_TRUE;
			managed_volumes = g_slist_prepend(managed_volumes, v);
		} else {
			rmm_managed_free(v);
		}
	}

out:
	if (udis != NULL) {
		libhal_free_string_array(udis);
	}
	rmm_dbus_error_free(&error);
}

/*
 * Mount all volumes mounted by this program
 */
static void
rmm_unmount_all()
{
	GSList		*i;
	managed_volume_t *v;

	for (i = managed_volumes; i != NULL; i = managed_volumes) {
		v = (managed_volume_t *)i->data;

		if (v->my && libhal_device_get_property_bool(hal_ctx, v->udi,
		    "volume.is_mounted", NULL)) {
			(void) rmm_action(hal_ctx, v->udi, UNMOUNT,
			    &v->aa, 0, 0, 0);
		}

		managed_volumes = g_slist_remove(managed_volumes, v);
		rmm_managed_free(v);
	}
}

int
main(int argc, char **argv)
{
	vold_init(argc, argv);

	return (rmvolmgr(argc, argv));
}
