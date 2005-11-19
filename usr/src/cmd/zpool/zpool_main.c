/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libintl.h>
#include <libuutil.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <priv.h>

#include <sys/stat.h>

#include <libzfs.h>

#include "zpool_util.h"

static int zpool_do_create(int, char **);
static int zpool_do_destroy(int, char **);

static int zpool_do_add(int, char **);

static int zpool_do_list(int, char **);
static int zpool_do_iostat(int, char **);
static int zpool_do_status(int, char **);

static int zpool_do_online(int, char **);
static int zpool_do_offline(int, char **);

static int zpool_do_attach(int, char **);
static int zpool_do_detach(int, char **);
static int zpool_do_replace(int, char **);

static int zpool_do_scrub(int, char **);

static int zpool_do_import(int, char **);
static int zpool_do_export(int, char **);

/*
 * These libumem hooks provide a reasonable set of defaults for the allocator's
 * debugging facilities.
 */
const char *
_umem_debug_init()
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}

typedef struct zpool_command {
	const char	*name;
	int		(*func)(int, char **);
	const char	*usage;
} zpool_command_t;

/*
 * Master command table.  Each ZFS command has a name, associated function, and
 * usage message.  These commands are organized according to how they are
 * displayed in the usage message.  An empty command (one with a NULL name)
 * indicates an empty line in the generic usage message.
 */
static zpool_command_t command_table[] = {
	{ "create",	zpool_do_create,
	    "\tcreate  [-fn] [-R root] [-m mountpoint] <pool> <vdev> ...\n" },
	{ "destroy",	zpool_do_destroy,
	    "\tdestroy [-f] <pool>\n"					},


	{ NULL },

	{ "add",	zpool_do_add,
	    "\tadd [-fn] <pool> <vdev> ...\n"				},

	{ NULL },

	{ "list",	zpool_do_list,
	    "\tlist [-H] [-o field[,field]*] [pool] ...\n"		},
	{ "iostat",	zpool_do_iostat,
	    "\tiostat [-v] [pool] ... [interval [count]]\n"		},
	{ "status",	zpool_do_status,
	    "\tstatus [-vx] [pool] ...\n"				},

	{ NULL },

	{ "online",	zpool_do_online,
	    "\tonline <pool> <device>\n"				},
	{ "offline",	zpool_do_offline,
	    "\toffline <pool> <device>\n"				},

	{ NULL },

	{ "attach",	zpool_do_attach,
	    "\tattach [-f] <pool> <device> <new_device>\n"		},
	{ "detach",	zpool_do_detach,
	    "\tdetach <pool> <device>\n"				},
	{ "replace",	zpool_do_replace,
	    "\treplace [-f] <pool> <device> [new_device]\n"		},

	{ NULL },

	{ "scrub",	zpool_do_scrub,
	    "\tscrub [-s] <pool> ...\n"					},

	{ NULL },

	{ "import",	zpool_do_import,
	    "\timport [-d dir]\n"
	    "\timport [-d dir] [-f] [-o opts] [-R root] -a\n"
	    "\timport [-d dir] [-f] [-o opts] [-R root ]<pool | id> "
	    "[newpool]\n"						},
	{ "export",	zpool_do_export,
	    "\texport [-f] <pool> ...\n"				},

	{ NULL }
};

#define	NCOMMAND	(sizeof (command_table) / sizeof (command_table[0]))

zpool_command_t *current_command;

/*
 * Fields available for 'zpool list'.
 */
typedef enum {
	ZPOOL_FIELD_NAME,
	ZPOOL_FIELD_SIZE,
	ZPOOL_FIELD_USED,
	ZPOOL_FIELD_AVAILABLE,
	ZPOOL_FIELD_CAPACITY,
	ZPOOL_FIELD_HEALTH,
	ZPOOL_FIELD_ROOT
} zpool_field_t;

#define	MAX_FIELDS	10

typedef struct column_def {
	const char	*cd_title;
	size_t		cd_width;
	enum {
		left_justify,
		right_justify
	}		cd_justify;
} column_def_t;

static column_def_t column_table[] = {
	{ "NAME",	20,	left_justify	},
	{ "SIZE",	6,	right_justify	},
	{ "USED",	6,	right_justify	},
	{ "AVAIL",	6,	right_justify	},
	{ "CAP",	5,	right_justify	},
	{ "HEALTH",	9,	left_justify	},
	{ "ALTROOT",	15,	left_justify	}
};

static char *column_subopts[] = {
	"name",
	"size",
	"used",
	"available",
	"capacity",
	"health",
	"root",
	NULL
};

/*
 * Display usage message.  If we're inside a command, display only the usage for
 * that command.  Otherwise, iterate over the entire command table and display
 * a complete usage message.
 */
void
usage(int requested)
{
	int i;
	FILE *fp = requested ? stdout : stderr;

	if (current_command == NULL) {
		int i;

		(void) fprintf(fp, gettext("usage: zpool command args ...\n"));
		(void) fprintf(fp,
		    gettext("where 'command' is one of the following:\n\n"));

		for (i = 0; i < NCOMMAND; i++) {
			if (command_table[i].name == NULL)
				(void) fprintf(fp, "\n");
			else
				(void) fprintf(fp, "%s",
				    command_table[i].usage);
		}
	} else {
		(void) fprintf(fp, gettext("usage:\n"));
		(void) fprintf(fp, current_command->usage);

		if (strcmp(current_command->name, "list") == 0) {
			(void) fprintf(fp, gettext("\nwhere 'field' is one "
			    "of the following:\n\n"));

			for (i = 0; column_subopts[i] != NULL; i++)
				(void) fprintf(fp, "\t%s\n", column_subopts[i]);
		}
	}

	exit(requested ? 0 : 2);
}

const char *
state_to_name(int state)
{
	switch (state) {
	case VDEV_STATE_CLOSED:
	case VDEV_STATE_CANT_OPEN:
		return (gettext("FAULTED"));
	case VDEV_STATE_OFFLINE:
		return (gettext("OFFLINE"));
	case VDEV_STATE_DEGRADED:
		return (gettext("DEGRADED"));
	case VDEV_STATE_HEALTHY:
		return (gettext("ONLINE"));
	}

	return (gettext("UNKNOWN"));
}

void
print_vdev_tree(const char *name, nvlist_t *nv, int indent)
{
	nvlist_t **child;
	uint_t c, children;

	if (name != NULL)
		(void) printf("\t%*s%s\n", indent, "", name);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return;

	for (c = 0; c < children; c++)
		print_vdev_tree(vdev_get_name(child[c]), child[c], indent + 2);
}

/*
 * zpool add [-fn] <pool> <vdev> ...
 *
 *	-f	Force addition of devices, even if they appear in use
 *	-n	Do not add the devices, but display the resulting layout if
 *		they were to be added.
 *
 * Adds the given vdevs to 'pool'.  As with create, the bulk of this work is
 * handled by get_vdev_spec(), which constructs the nvlist needed to pass to
 * libzfs.
 */
int
zpool_do_add(int argc, char **argv)
{
	int force = FALSE;
	int dryrun = FALSE;
	int c;
	nvlist_t *nvroot;
	char *poolname;
	int ret;
	zpool_handle_t *zhp;
	nvlist_t *config;

	/* check options */
	while ((c = getopt(argc, argv, "fn")) != -1) {
		switch (c) {
		case 'f':
			force = TRUE;
			break;
		case 'n':
			dryrun = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name argument\n"));
		usage(FALSE);
	}
	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing vdev specification\n"));
		usage(FALSE);
	}

	poolname = argv[0];

	argc--;
	argv++;

	if ((zhp = zpool_open(poolname)) == NULL)
		return (1);

	if ((config = zpool_get_config(zhp, NULL)) == NULL) {
		(void) fprintf(stderr, gettext("pool '%s' is unavailable\n"),
		    poolname);
		zpool_close(zhp);
		return (1);
	}

	/* pass off to get_vdev_spec for processing */
	nvroot = make_root_vdev(config, force, !force, argc, argv);
	if (nvroot == NULL) {
		zpool_close(zhp);
		return (1);
	}

	if (dryrun) {
		nvlist_t *poolnvroot;

		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &poolnvroot) == 0);

		(void) printf(gettext("would update '%s' to the following "
		    "configuration:\n"), zpool_get_name(zhp));

		print_vdev_tree(poolname, poolnvroot, 0);
		print_vdev_tree(NULL, nvroot, 0);

		ret = 0;
	} else {
		ret = (zpool_add(zhp, nvroot) != 0);
	}

	return (ret);
}

/*
 * zpool create [-fn] [-R root] [-m mountpoint] <pool> <dev> ...
 *
 *	-f	Force creation, even if devices appear in use
 *	-n	Do not create the pool, but display the resulting layout if it
 *		were to be created.
 *      -R	Create a pool under an alternate root
 *      -m	Set default mountpoint for the root dataset.  By default it's
 *      	'/<pool>'
 *
 * Creates the the named pool according to the given vdev specification.  The
 * bulk of the vdev processing is done in get_vdev_spec() in zpool_vdev.c.  Once
 * we get the nvlist back from get_vdev_spec(), we either print out the contents
 * (if '-n' was specified), or pass it to libzfs to do the creation.
 */
int
zpool_do_create(int argc, char **argv)
{
	int force = FALSE;
	int dryrun = FALSE;
	int c;
	nvlist_t *nvroot;
	char *poolname;
	int ret;
	char *altroot = NULL;
	char *mountpoint = NULL;

	/* check options */
	while ((c = getopt(argc, argv, ":fnR:m:")) != -1) {
		switch (c) {
		case 'f':
			force = TRUE;
			break;
		case 'n':
			dryrun = TRUE;
			break;
		case 'R':
			altroot = optarg;
			break;
		case 'm':
			mountpoint = optarg;
			break;
		case ':':
			(void) fprintf(stderr, gettext("missing argument for "
			    "'%c' option\n"), optopt);
			usage(FALSE);
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name argument\n"));
		usage(FALSE);
	}
	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing vdev specification\n"));
		usage(FALSE);
	}

	poolname = argv[0];

	/*
	 * As a special case, check for use of '/' in the name, and direct the
	 * user to use 'zfs create' instead.
	 */
	if (strchr(poolname, '/') != NULL) {
		(void) fprintf(stderr, gettext("cannot create '%s': invalid "
		    "character '/' in pool name\n"), poolname);
		(void) fprintf(stderr, gettext("use 'zfs create' to "
		    "create a dataset\n"));
		return (1);
	}

	/* pass off to get_vdev_spec for bulk processing */
	nvroot = make_root_vdev(NULL, force, !force, argc - 1, argv + 1);
	if (nvroot == NULL)
		return (1);

	if (altroot != NULL && altroot[0] != '/') {
		(void) fprintf(stderr, gettext("invalid alternate root '%s': "
		    "must be an absolute path\n"));
		return (1);
	}

	/*
	 * Check the validity of the mountpoint and direct the user to use the
	 * '-m' mountpoint option if it looks like its in use.
	 */
	if (mountpoint == NULL ||
	    (strcmp(mountpoint, ZFS_MOUNTPOINT_LEGACY) != 0 &&
	    strcmp(mountpoint, ZFS_MOUNTPOINT_NONE) != 0)) {
		char buf[MAXPATHLEN];
		struct stat64 statbuf;

		if (mountpoint && mountpoint[0] != '/') {
			(void) fprintf(stderr, gettext("invalid mountpoint "
			    "'%s': must be an absolute path, 'legacy', or "
			    "'none'\n"), mountpoint);
			return (1);
		}

		if (mountpoint == NULL) {
			if (altroot != NULL)
				(void) snprintf(buf, sizeof (buf), "%s/%s",
				    altroot, poolname);
			else
				(void) snprintf(buf, sizeof (buf), "/%s",
				    poolname);
		} else {
			if (altroot != NULL)
				(void) snprintf(buf, sizeof (buf), "%s%s",
				    altroot, mountpoint);
			else
				(void) snprintf(buf, sizeof (buf), "%s",
				    mountpoint);
		}

		if (stat64(buf, &statbuf) == 0 &&
		    statbuf.st_nlink != 2) {
			if (mountpoint == NULL)
				(void) fprintf(stderr, gettext("default "
				    "mountpoint '%s' exists and is not "
				    "empty\n"), buf);
			else
				(void) fprintf(stderr, gettext("mountpoint "
				    "'%s' exists and is not empty\n"), buf);
			(void) fprintf(stderr, gettext("use '-m' "
			    "option to provide a different default\n"));
			return (1);
		}
	}


	if (dryrun) {
		/*
		 * For a dry run invocation, print out a basic message and run
		 * through all the vdevs in the list and print out in an
		 * appropriate hierarchy.
		 *
		 * XXZFS find out of we can create the pool?
		 */
		(void) printf(gettext("would create '%s' with the "
		    "following layout:\n\n"), poolname);

		print_vdev_tree(poolname, nvroot, 0);

		ret = 0;
	} else {
		ret = 1;
		/*
		 * Hand off to libzfs.
		 */
		if (zpool_create(poolname, nvroot, altroot) == 0) {
			zfs_handle_t *pool = zfs_open(poolname,
			    ZFS_TYPE_FILESYSTEM);
			if (pool != NULL) {
				if (mountpoint != NULL)
					verify(zfs_prop_set(pool,
					    ZFS_PROP_MOUNTPOINT,
					    mountpoint) == 0);
				if (zfs_mount(pool, NULL, 0) == 0)
					ret = zfs_share(pool);
				zfs_close(pool);
			}
		}

	}

	nvlist_free(nvroot);

	return (ret);
}

/*
 * zpool destroy <pool>
 *
 * 	-f	Forcefully unmount any datasets
 *
 * Destroy the given pool.  Automatically unmounts any datasets in the pool.
 */
int
zpool_do_destroy(int argc, char **argv)
{
	int force = FALSE;
	int c;
	char *pool;
	zpool_handle_t *zhp;
	int ret;

	/* check options */
	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			force = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* check arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool argument\n"));
		usage(FALSE);
	}
	if (argc > 1) {
		(void) fprintf(stderr, gettext("too many arguments\n"));
		usage(FALSE);
	}

	pool = argv[0];

	if ((zhp = zpool_open_canfail(pool)) == NULL) {
		/*
		 * As a special case, check for use of '/' in the name, and
		 * direct the user to use 'zfs destroy' instead.
		 */
		if (strchr(pool, '/') != NULL)
			(void) fprintf(stderr, gettext("use 'zfs destroy' to "
			    "destroy a dataset\n"));
		return (1);
	}

	if (unmount_datasets(zhp, force) != 0) {
		(void) fprintf(stderr, gettext("could not destroy '%s': "
		    "could not unmount datasets\n"), zpool_get_name(zhp));
		return (1);
	}

	ret = (zpool_destroy(zhp) != 0);

	zpool_close(zhp);

	return (ret);
}

/*
 * zpool export [-f] <pool> ...
 *
 *	-f	Forcefully unmount datasets
 *
 * Export the the given pools.  By default, the command will attempt to cleanly
 * unmount any active datasets within the pool.  If the '-f' flag is specified,
 * then the datasets will be forcefully unmounted.
 */
int
zpool_do_export(int argc, char **argv)
{
	int force = FALSE;
	int c;
	zpool_handle_t *zhp;
	int ret;
	int i;

	/* check options */
	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			force = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* check arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool argument\n"));
		usage(FALSE);
	}

	ret = 0;
	for (i = 0; i < argc; i++) {
		if ((zhp = zpool_open_canfail(argv[i])) == NULL) {
			ret = 1;
			continue;
		}

		if (unmount_datasets(zhp, force) != 0) {
			ret = 1;
			zpool_close(zhp);
			continue;
		}

		if (zpool_export(zhp) != 0)
			ret = 1;

		zpool_close(zhp);
	}

	return (ret);
}

/*
 * Given a vdev configuration, determine the maximum width needed for the device
 * name column.
 */
static int
max_width(nvlist_t *nv, int depth, int max)
{
	const char *name = vdev_get_name(nv);
	nvlist_t **child;
	uint_t c, children;
	int ret;

	if (strlen(name) + depth > max)
		max = strlen(name) + depth;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return (max);

	for (c = 0; c < children; c++)
		if ((ret = max_width(child[c], depth + 2, max)) > max)
			max = ret;

	return (max);
}


/*
 * Print the configuration of an exported pool.  Iterate over all vdevs in the
 * pool, printing out the name and status for each one.
 */
void
print_import_config(const char *name, nvlist_t *nv, int namewidth, int depth)
{
	nvlist_t **child;
	uint_t c, children;
	vdev_stat_t *vs;
	char *type;

	verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_TYPE, &type) == 0);
	if (strcmp(type, VDEV_TYPE_MISSING) == 0)
		return;

	verify(nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &c) == 0);

	(void) printf("\t%*s%-*s", depth, "", namewidth - depth, name);

	if (vs->vs_aux != 0) {
		(void) printf("  %-8s  ", state_to_name(vs->vs_state));

		switch (vs->vs_aux) {
		case VDEV_AUX_OPEN_FAILED:
			(void) printf(gettext("cannot open"));
			break;

		case VDEV_AUX_BAD_GUID_SUM:
			(void) printf(gettext("missing device"));
			break;

		case VDEV_AUX_NO_REPLICAS:
			(void) printf(gettext("insufficient replicas"));
			break;

		default:
			(void) printf(gettext("corrupted data"));
			break;
		}
	} else {
		(void) printf("  %s", state_to_name(vs->vs_state));
	}
	(void) printf("\n");

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		return;

	for (c = 0; c < children; c++)
		print_import_config(vdev_get_name(child[c]), child[c],
		    namewidth, depth + 2);
}

/*
 * Display the status for the given pool.
 */
static void
show_import(nvlist_t *config)
{
	uint64_t pool_state;
	vdev_stat_t *vs;
	char *name;
	uint64_t guid;
	char *msgid;
	nvlist_t *nvroot;
	int reason;
	char *health;
	uint_t vsc;
	int namewidth;

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
	    &guid) == 0);
	verify(nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
	    &pool_state) == 0);
	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_HEALTH,
	    &health) == 0);
	verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
	    &nvroot) == 0);

	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &vsc) == 0);

	reason = zpool_import_status(config, &msgid);

	(void) printf("  pool: %s\n", name);
	(void) printf("    id: %llu\n", guid);
	(void) printf(" state: %s\n", health);

	switch (reason) {
	case ZPOOL_STATUS_MISSING_DEV_R:
	case ZPOOL_STATUS_MISSING_DEV_NR:
	case ZPOOL_STATUS_BAD_GUID_SUM:
		(void) printf(gettext("status: One or more devices are missing "
		    "from the system.\n"));
		break;

	case ZPOOL_STATUS_CORRUPT_LABEL_R:
	case ZPOOL_STATUS_CORRUPT_LABEL_NR:
		(void) printf(gettext("status: One or more devices contains "
		    "corrupted data.\n"));
		break;

	case ZPOOL_STATUS_CORRUPT_DATA:
		(void) printf(gettext("status: The pool data is corrupted.\n"));
		break;

	default:
		/*
		 * No other status can be seen when importing pools.
		 */
		assert(reason == ZPOOL_STATUS_OK);
	}

	/*
	 * Print out an action according to the overall state of the pool.
	 */
	if (strcmp(health, gettext("ONLINE")) == 0) {
		(void) printf(gettext("action: The pool can be imported"
		    " using its name or numeric identifier."));
		if (pool_state != POOL_STATE_EXPORTED)
			(void) printf(gettext("  The\n\tpool may be active on "
			    "on another system, but can be imported using\n\t"
			    "the '-f' flag.\n"));
		else
			(void) printf("\n");
	} else if (strcmp(health, gettext("DEGRADED")) == 0) {
		(void) printf(gettext("action: The pool can be imported "
		    "despite missing or damaged devices.  The\n\tfault "
		    "tolerance of the pool may be compromised if imported."));
		if (pool_state != POOL_STATE_EXPORTED)
			(void) printf(gettext("  The\n\tpool may be active on "
			    "on another system, but can be imported using\n\t"
			    "the '-f' flag.\n"));
		else
			(void) printf("\n");
	} else {
		if (reason == ZPOOL_STATUS_MISSING_DEV_R ||
		    reason == ZPOOL_STATUS_MISSING_DEV_NR ||
		    reason == ZPOOL_STATUS_BAD_GUID_SUM)
			(void) printf(gettext("action: The pool cannot be "
			    "imported. Attach the missing\n\tdevices and try "
			    "again.\n"));
		else
			(void) printf(gettext("action: The pool cannot be "
			    "imported due to damaged devices or data.\n"));
	}

	if (msgid != NULL)
		(void) printf(gettext("   see: http://www.sun.com/msg/%s\n"),
		    msgid);

	(void) printf(gettext("config:\n\n"));

	namewidth = max_width(nvroot, 0, 0);
	if (namewidth < 10)
		namewidth = 10;
	print_import_config(name, nvroot, namewidth, 0);

	if (reason == ZPOOL_STATUS_BAD_GUID_SUM) {
		(void) printf("\n\tAdditional devices are known to "
		    "be part of this pool, though their\n\texact "
		    "configuration cannot be determined.\n");
	}
}

/*
 * Perform the import for the given configuration.  This passes the heavy
 * lifting off to zpool_import(), and then mounts the datasets contained within
 * the pool.
 */
static int
do_import(nvlist_t *config, const char *newname, const char *mntopts,
    const char *altroot, int force)
{
	zpool_handle_t *zhp;
	char *name;
	uint64_t state;

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
	    &name) == 0);

	verify(nvlist_lookup_uint64(config,
	    ZPOOL_CONFIG_POOL_STATE, &state) == 0);
	if (state != POOL_STATE_EXPORTED && !force) {
		(void) fprintf(stderr, gettext("cannot import '%s': pool "
		    "may be in use from other system\n"), name);
		(void) fprintf(stderr, gettext("use '-f' to import anyway\n"));
		return (1);
	}

	if (zpool_import(config, newname, altroot) != 0)
		return (1);

	if (newname != NULL)
		name = (char *)newname;

	verify((zhp = zpool_open(name)) != NULL);

	if (mount_share_datasets(zhp, mntopts) != 0) {
		zpool_close(zhp);
		return (1);
	}

	zpool_close(zhp);
	return (0);
}

/*
 * zpool import [-d dir]
 *       import [-R root] [-d dir] [-f] -a
 *       import [-R root] [-d dir] [-f] <pool | id> [newpool]
 *
 *       -d	Scan in a specific directory, other than /dev/dsk.  More than
 *		one directory can be specified using multiple '-d' options.
 *
 *       -R	Temporarily import the pool, with all mountpoints relative to
 *		the given root.  The pool will remain exported when the machine
 *		is rebooted.
 *
 *       -f	Force import, even if it appears that the pool is active.
 *
 *       -a	Import all pools found.
 *
 * The import command scans for pools to import, and import pools based on pool
 * name and GUID.  The pool can also be renamed as part of the import process.
 */
int
zpool_do_import(int argc, char **argv)
{
	char **searchdirs = NULL;
	int nsearch = 0;
	int c;
	int err;
	nvlist_t *pools;
	int do_all = FALSE;
	char *altroot = NULL;
	char *mntopts = NULL;
	int do_force = FALSE;
	nvpair_t *elem;
	nvlist_t *config;
	uint64_t searchguid;
	char *searchname;
	nvlist_t *found_config;
	int first;

	/* check options */
	while ((c = getopt(argc, argv, ":fd:R:ao:")) != -1) {
		switch (c) {
		case 'a':
			do_all = TRUE;
			break;
		case 'd':
			if (searchdirs == NULL) {
				searchdirs = safe_malloc(sizeof (char *));
			} else {
				char **tmp = safe_malloc((nsearch + 1) *
				    sizeof (char *));
				bcopy(searchdirs, tmp, nsearch *
				    sizeof (char *));
				free(searchdirs);
				searchdirs = tmp;
			}
			searchdirs[nsearch++] = optarg;
			break;
		case 'f':
			do_force = TRUE;
			break;
		case 'o':
			mntopts = optarg;
			break;
		case 'R':
			altroot = optarg;
			break;
		case ':':
			(void) fprintf(stderr, gettext("missing argument for "
			    "'%c' option\n"), optopt);
			usage(FALSE);
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	if (searchdirs == NULL) {
		searchdirs = safe_malloc(sizeof (char *));
		searchdirs[0] = "/dev/dsk";
		nsearch = 1;
	}

	/* check argument count */
	if (do_all) {
		if (argc != 0) {
			(void) fprintf(stderr, gettext("too many arguments\n"));
			usage(FALSE);
		}
	} else {
		if (argc > 2) {
			(void) fprintf(stderr, gettext("too many arguments\n"));
			usage(FALSE);
		}

		/*
		 * Check for the SYS_CONFIG privilege.  We do this explicitly
		 * here because otherwise any attempt to discover pools will
		 * silently fail.
		 */
		if (argc == 0 && !priv_ineffect(PRIV_SYS_CONFIG)) {
			(void) fprintf(stderr, gettext("cannot "
			    "discover pools: permission denied\n"));
			return (1);
		}
	}

	if ((pools = zpool_find_import(nsearch, searchdirs)) == NULL)
		return (1);

	/*
	 * We now have a list of all available pools in the given directories.
	 * Depending on the arguments given, we do one of the following:
	 *
	 *	<none>	Iterate through all pools and display information about
	 *		each one.
	 *
	 *	-a	Iterate through all pools and try to import each one.
	 *
	 *	<id>	Find the pool that corresponds to the given GUID/pool
	 *		name and import that one.
	 */
	if (argc != 0) {
		char *endptr;

		errno = 0;
		searchguid = strtoull(argv[0], &endptr, 10);
		if (errno != 0 || *endptr != '\0')
			searchname = argv[0];
		else
			searchname = NULL;
		found_config = NULL;
	}

	err = 0;
	elem = NULL;
	first = TRUE;
	while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {

		verify(nvpair_value_nvlist(elem, &config) == 0);

		if (argc == 0) {
			if (first)
				first = FALSE;
			else
				(void) printf("\n");

			if (do_all)
				err |= do_import(config, NULL, mntopts,
				    altroot, do_force);
			else
				show_import(config);
		} else if (searchname != NULL) {
			char *name;

			/*
			 * We are searching for a pool based on name.
			 */
			verify(nvlist_lookup_string(config,
			    ZPOOL_CONFIG_POOL_NAME, &name) == 0);

			if (strcmp(name, searchname) == 0) {
				if (found_config != NULL) {
					(void) fprintf(stderr, gettext(
					    "cannot import '%s': more than "
					    "one matching pool\n"), searchname);
					(void) fprintf(stderr, gettext(
					    "import by numeric ID instead\n"));
					err = TRUE;
				}
				found_config = config;
			}
		} else {
			uint64_t guid;

			/*
			 * Search for a pool by guid.
			 */
			verify(nvlist_lookup_uint64(config,
			    ZPOOL_CONFIG_POOL_GUID, &guid) == 0);

			if (guid == searchguid)
				found_config = config;
		}
	}

	/*
	 * If we were searching for a specific pool, verify that we found a
	 * pool, and then do the import.
	 */
	if (argc != 0 && err == 0) {
		if (found_config == NULL) {
			(void) fprintf(stderr, gettext("cannot import '%s': "
			    "no such pool available\n"), argv[0]);
			err = TRUE;
		} else {
			err |= do_import(found_config, argc == 1 ? NULL :
			    argv[1], mntopts, altroot, do_force);
		}
	}

	/*
	 * If we were just looking for pools, report an error if none were
	 * found.
	 */
	if (argc == 0 && first)
		(void) fprintf(stderr,
		    gettext("no pools available to import\n"));

	nvlist_free(pools);

	return (err ? 1 : 0);
}

typedef struct iostat_cbdata {
	zpool_list_t *cb_list;
	int cb_verbose;
	int cb_iteration;
	int cb_namewidth;
} iostat_cbdata_t;

static void
print_iostat_separator(iostat_cbdata_t *cb)
{
	int i = 0;

	for (i = 0; i < cb->cb_namewidth; i++)
		(void) printf("-");
	(void) printf("  -----  -----  -----  -----  -----  -----\n");
}

static void
print_iostat_header(iostat_cbdata_t *cb)
{
	(void) printf("%*s     capacity     operations    bandwidth\n",
	    cb->cb_namewidth, "");
	(void) printf("%-*s   used  avail   read  write   read  write\n",
	    cb->cb_namewidth, "pool");
	print_iostat_separator(cb);
}

/*
 * Display a single statistic.
 */
void
print_one_stat(uint64_t value)
{
	char buf[64];

	zfs_nicenum(value, buf, sizeof (buf));
	(void) printf("  %5s", buf);
}

/*
 * Print out all the statistics for the given vdev.  This can either be the
 * toplevel configuration, or called recursively.  If 'name' is NULL, then this
 * is a verbose output, and we don't want to display the toplevel pool stats.
 */
void
print_vdev_stats(const char *name, nvlist_t *oldnv, nvlist_t *newnv,
	iostat_cbdata_t *cb, int depth)
{
	nvlist_t **oldchild, **newchild;
	uint_t c, children;
	vdev_stat_t *oldvs, *newvs;
	vdev_stat_t zerovs = { 0 };
	uint64_t tdelta;
	double scale;

	if (oldnv != NULL) {
		verify(nvlist_lookup_uint64_array(oldnv, ZPOOL_CONFIG_STATS,
		    (uint64_t **)&oldvs, &c) == 0);
	} else {
		oldvs = &zerovs;
	}

	verify(nvlist_lookup_uint64_array(newnv, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&newvs, &c) == 0);

	if (strlen(name) + depth > cb->cb_namewidth)
		(void) printf("%*s%s", depth, "", name);
	else
		(void) printf("%*s%s%*s", depth, "", name,
		    (int)(cb->cb_namewidth - strlen(name) - depth), "");

	tdelta = newvs->vs_timestamp - oldvs->vs_timestamp;

	if (tdelta == 0)
		scale = 1.0;
	else
		scale = (double)NANOSEC / tdelta;

	/* only toplevel vdevs have capacity stats */
	if (newvs->vs_space == 0) {
		(void) printf("      -      -");
	} else {
		print_one_stat(newvs->vs_alloc);
		print_one_stat(newvs->vs_space - newvs->vs_alloc);
	}

	print_one_stat((uint64_t)(scale * (newvs->vs_ops[ZIO_TYPE_READ] -
	    oldvs->vs_ops[ZIO_TYPE_READ])));

	print_one_stat((uint64_t)(scale * (newvs->vs_ops[ZIO_TYPE_WRITE] -
	    oldvs->vs_ops[ZIO_TYPE_WRITE])));

	print_one_stat((uint64_t)(scale * (newvs->vs_bytes[ZIO_TYPE_READ] -
	    oldvs->vs_bytes[ZIO_TYPE_READ])));

	print_one_stat((uint64_t)(scale * (newvs->vs_bytes[ZIO_TYPE_WRITE] -
	    oldvs->vs_bytes[ZIO_TYPE_WRITE])));

	(void) printf("\n");

	if (!cb->cb_verbose)
		return;

	if (nvlist_lookup_nvlist_array(newnv, ZPOOL_CONFIG_CHILDREN,
	    &newchild, &children) != 0)
		return;

	if (oldnv && nvlist_lookup_nvlist_array(oldnv, ZPOOL_CONFIG_CHILDREN,
	    &oldchild, &c) != 0)
		return;

	for (c = 0; c < children; c++)
		print_vdev_stats(vdev_get_name(newchild[c]),
		    oldnv ? oldchild[c] : NULL, newchild[c], cb, depth + 2);
}

static int
refresh_iostat(zpool_handle_t *zhp, void *data)
{
	iostat_cbdata_t *cb = data;

	/*
	 * If the pool has disappeared, remove it from the list and continue.
	 */
	if (zpool_refresh_stats(zhp) != 0)
		pool_list_remove(cb->cb_list, zhp);

	return (0);
}

/*
 * Callback to print out the iostats for the given pool.
 */
int
print_iostat(zpool_handle_t *zhp, void *data)
{
	iostat_cbdata_t *cb = data;
	nvlist_t *oldconfig, *newconfig;
	nvlist_t *oldnvroot, *newnvroot;

	newconfig = zpool_get_config(zhp, &oldconfig);

	if (cb->cb_iteration == 1)
		oldconfig = NULL;

	verify(nvlist_lookup_nvlist(newconfig, ZPOOL_CONFIG_VDEV_TREE,
	    &newnvroot) == 0);

	if (oldconfig == NULL)
		oldnvroot = NULL;
	else
		verify(nvlist_lookup_nvlist(oldconfig, ZPOOL_CONFIG_VDEV_TREE,
		    &oldnvroot) == 0);

	/*
	 * Print out the statistics for the pool.
	 */
	print_vdev_stats(zpool_get_name(zhp), oldnvroot, newnvroot, cb, 0);

	if (cb->cb_verbose)
		print_iostat_separator(cb);

	return (0);
}

int
get_namewidth(zpool_handle_t *zhp, void *data)
{
	iostat_cbdata_t *cb = data;
	nvlist_t *config, *nvroot;

	if ((config = zpool_get_config(zhp, NULL)) != NULL) {
		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) == 0);
		if (!cb->cb_verbose)
			cb->cb_namewidth = strlen(zpool_get_name(zhp));
		else
			cb->cb_namewidth = max_width(nvroot, 0, 0);
	}

	/*
	 * The width must fall into the range [10,38].  The upper limit is the
	 * maximum we can have and still fit in 80 columns.
	 */
	if (cb->cb_namewidth < 10)
		cb->cb_namewidth = 10;
	if (cb->cb_namewidth > 38)
		cb->cb_namewidth = 38;

	return (0);
}

/*
 * zpool iostat [-v] [pool] ... [interval [count]]
 *
 *	-v	Display statistics for individual vdevs
 *
 * This command can be tricky because we want to be able to deal with pool
 * creation/destruction as well as vdev configuration changes.  The bulk of this
 * processing is handled by the pool_list_* routines in zpool_iter.c.  We rely
 * on pool_list_update() to detect the addition of new pools.  Configuration
 * changes are all handled within libzfs.
 */
int
zpool_do_iostat(int argc, char **argv)
{
	int c;
	int ret;
	int npools;
	unsigned long interval = 0, count = 0;
	zpool_list_t *list;
	int verbose = FALSE;
	iostat_cbdata_t cb;

	/* check options */
	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/*
	 * Determine if the last argument is an integer or a pool name
	 */
	if (argc > 0 && isdigit(argv[argc - 1][0])) {
		char *end;

		errno = 0;
		interval = strtoul(argv[argc - 1], &end, 10);

		if (*end == '\0' && errno == 0) {
			if (interval == 0) {
				(void) fprintf(stderr, gettext("interval "
				    "cannot be zero\n"));
				usage(FALSE);
			}

			/*
			 * Ignore the last parameter
			 */
			argc--;
		} else {
			/*
			 * If this is not a valid number, just plow on.  The
			 * user will get a more informative error message later
			 * on.
			 */
			interval = 0;
		}
	}

	/*
	 * If the last argument is also an integer, then we have both a count
	 * and an integer.
	 */
	if (argc > 0 && isdigit(argv[argc - 1][0])) {
		char *end;

		errno = 0;
		count = interval;
		interval = strtoul(argv[argc - 1], &end, 10);

		if (*end == '\0' && errno == 0) {
			if (interval == 0) {
				(void) fprintf(stderr, gettext("interval "
				    "cannot be zero\n"));
				usage(FALSE);
			}

			/*
			 * Ignore the last parameter
			 */
			argc--;
		} else {
			interval = 0;
		}
	}

	/*
	 * Construct the list of all interesting pools.
	 */
	ret = 0;
	if ((list = pool_list_get(argc, argv, &ret)) == NULL)
		return (1);

	if (pool_list_count(list) == 0 && argc != 0)
		return (1);

	if (pool_list_count(list) == 0 && interval == 0) {
		(void) fprintf(stderr, gettext("no pools available\n"));
		return (1);
	}

	/*
	 * Enter the main iostat loop.
	 */
	cb.cb_list = list;
	cb.cb_verbose = verbose;
	cb.cb_iteration = 0;
	cb.cb_namewidth = 0;

	for (;;) {
		pool_list_update(list);

		if ((npools = pool_list_count(list)) == 0)
			break;

		/*
		 * Refresh all statistics.  This is done as an explicit step
		 * before calculating the maximum name width, so that any
		 * configuration changes are properly accounted for.
		 */
		(void) pool_list_iter(list, FALSE, refresh_iostat, &cb);

		/*
		 * Iterate over all pools to determine the maximum width
		 * for the pool / device name column across all pools.
		 */
		cb.cb_namewidth = 0;
		(void) pool_list_iter(list, FALSE, get_namewidth, &cb);

		/*
		 * If it's the first time, or verbose mode, print the header.
		 */
		if (++cb.cb_iteration == 1 || verbose)
			print_iostat_header(&cb);

		(void) pool_list_iter(list, FALSE, print_iostat, &cb);

		/*
		 * If there's more than one pool, and we're not in verbose mode
		 * (which prints a separator for us), then print a separator.
		 */
		if (npools > 1 && !verbose)
			print_iostat_separator(&cb);

		if (verbose)
			(void) printf("\n");

		if (interval == 0)
			break;

		if (count != 0 && --count == 0)
			break;

		(void) sleep(interval);
	}

	pool_list_free(list);

	return (ret);
}

typedef struct list_cbdata {
	int	cb_scripted;
	int	cb_first;
	int	cb_fields[MAX_FIELDS];
	int	cb_fieldcount;
} list_cbdata_t;

/*
 * Given a list of columns to display, output appropriate headers for each one.
 */
void
print_header(int *fields, size_t count)
{
	int i;
	column_def_t *col;
	const char *fmt;

	for (i = 0; i < count; i++) {
		col = &column_table[fields[i]];
		if (i != 0)
			(void) printf("  ");
		if (col->cd_justify == left_justify)
			fmt = "%-*s";
		else
			fmt = "%*s";

		(void) printf(fmt, i == count - 1 ? strlen(col->cd_title) :
		    col->cd_width, col->cd_title);
	}

	(void) printf("\n");
}

int
list_callback(zpool_handle_t *zhp, void *data)
{
	list_cbdata_t *cbp = data;
	nvlist_t *config;
	int i;
	char buf[ZPOOL_MAXNAMELEN];
	uint64_t total;
	uint64_t used;
	const char *fmt;
	column_def_t *col;

	if (cbp->cb_first) {
		if (!cbp->cb_scripted)
			print_header(cbp->cb_fields, cbp->cb_fieldcount);
		cbp->cb_first = FALSE;
	}

	if (zpool_get_state(zhp) == POOL_STATE_UNAVAIL) {
		config = NULL;
	} else {
		config = zpool_get_config(zhp, NULL);
		total = zpool_get_space_total(zhp);
		used = zpool_get_space_used(zhp);
	}

	for (i = 0; i < cbp->cb_fieldcount; i++) {
		if (i != 0) {
			if (cbp->cb_scripted)
				(void) printf("\t");
			else
				(void) printf("  ");
		}

		col = &column_table[cbp->cb_fields[i]];

		switch (cbp->cb_fields[i]) {
		case ZPOOL_FIELD_NAME:
			(void) strlcpy(buf, zpool_get_name(zhp), sizeof (buf));
			break;

		case ZPOOL_FIELD_SIZE:
			if (config == NULL)
				(void) strlcpy(buf, "-", sizeof (buf));
			else
				zfs_nicenum(total, buf, sizeof (buf));
			break;

		case ZPOOL_FIELD_USED:
			if (config == NULL)
				(void) strlcpy(buf, "-", sizeof (buf));
			else
				zfs_nicenum(used, buf, sizeof (buf));
			break;

		case ZPOOL_FIELD_AVAILABLE:
			if (config == NULL)
				(void) strlcpy(buf, "-", sizeof (buf));
			else
				zfs_nicenum(total - used, buf, sizeof (buf));
			break;

		case ZPOOL_FIELD_CAPACITY:
			if (config == NULL) {
				(void) strlcpy(buf, "-", sizeof (buf));
			} else {
				uint64_t capacity = (total == 0 ? 0 :
				    (used * 100 / total));
				(void) snprintf(buf, sizeof (buf), "%llu%%",
				    capacity);
			}
			break;

		case ZPOOL_FIELD_HEALTH:
			if (config == NULL) {
				(void) strlcpy(buf, "FAULTED", sizeof (buf));
			} else {
				nvlist_t *nvroot;
				vdev_stat_t *vs;
				uint_t vsc;

				verify(nvlist_lookup_nvlist(config,
				    ZPOOL_CONFIG_VDEV_TREE, &nvroot) == 0);
				verify(nvlist_lookup_uint64_array(nvroot,
				    ZPOOL_CONFIG_STATS, (uint64_t **)&vs,
				    &vsc) == 0);
				(void) strlcpy(buf, state_to_name(vs->vs_state),
				    sizeof (buf));
			}
			break;

		case ZPOOL_FIELD_ROOT:
			if (config == NULL)
				(void) strlcpy(buf, "-", sizeof (buf));
			else if (zpool_get_root(zhp, buf, sizeof (buf)) != 0)
				(void) strlcpy(buf, "-", sizeof (buf));
			break;
		}

		if (cbp->cb_scripted)
			(void) printf("%s", buf);
		else {
			if (col->cd_justify == left_justify)
				fmt = "%-*s";
			else
				fmt = "%*s";

			(void) printf(fmt, i == cbp->cb_fieldcount - 1 ?
			    strlen(buf) : col->cd_width, buf);
		}
	}

	(void) printf("\n");

	return (0);
}

/*
 * zpool list [-H] [-o field[,field]*] [pool] ...
 *
 *	-H	Scripted mode.  Don't display headers, and separate fields by
 *		a single tab.
 *	-o	List of fields to display.  Defaults to all fields, or
 *		"name,size,used,available,capacity,health,root"
 *
 * List all pools in the system, whether or not they're healthy.  Output space
 * statistics for each one, as well as health status summary.
 */
int
zpool_do_list(int argc, char **argv)
{
	int c;
	int ret;
	list_cbdata_t cb = { 0 };
	static char default_fields[] =
	    "name,size,used,available,capacity,health,root";
	char *fields = default_fields;
	char *value;

	/* check options */
	while ((c = getopt(argc, argv, ":Ho:")) != -1) {
		switch (c) {
		case 'H':
			cb.cb_scripted = TRUE;
			break;
		case 'o':
			fields = optarg;
			break;
		case ':':
			(void) fprintf(stderr, gettext("missing argument for "
			    "'%c' option\n"), optopt);
			usage(FALSE);
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	while (*fields != '\0') {
		if (cb.cb_fieldcount == MAX_FIELDS) {
			(void) fprintf(stderr, gettext("too many "
			    "properties given to -o option\n"));
			usage(FALSE);
		}

		if ((cb.cb_fields[cb.cb_fieldcount] = getsubopt(&fields,
		    column_subopts, &value)) == -1) {
			(void) fprintf(stderr, gettext("invalid property "
			    "'%s'\n"), value);
			usage(FALSE);
		}

		cb.cb_fieldcount++;
	}


	cb.cb_first = TRUE;

	ret = for_each_pool(argc, argv, TRUE, list_callback, &cb);

	if (argc == 0 && cb.cb_first) {
		(void) printf(gettext("no pools available\n"));
		return (0);
	}

	return (ret);
}

static nvlist_t *
zpool_get_vdev_by_name(nvlist_t *nv, char *name)
{
	nvlist_t **child;
	uint_t c, children;
	nvlist_t *match;
	char *path;

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0) {
		verify(nvlist_lookup_string(nv, ZPOOL_CONFIG_PATH, &path) == 0);
		if (strncmp(name, "/dev/dsk/", 9) == 0)
			name += 9;
		if (strncmp(path, "/dev/dsk/", 9) == 0)
			path += 9;
		if (strcmp(name, path) == 0)
			return (nv);
		return (NULL);
	}

	for (c = 0; c < children; c++)
		if ((match = zpool_get_vdev_by_name(child[c], name)) != NULL)
			return (match);

	return (NULL);
}

static int
zpool_do_attach_or_replace(int argc, char **argv, int replacing)
{
	int force = FALSE;
	int c;
	nvlist_t *nvroot;
	char *poolname, *old_disk, *new_disk;
	zpool_handle_t *zhp;
	nvlist_t *config;

	/* check options */
	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			force = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name argument\n"));
		usage(FALSE);
	}

	poolname = argv[0];

	if (argc < 2) {
		(void) fprintf(stderr,
		    gettext("missing <device> specification\n"));
		usage(FALSE);
	}

	old_disk = argv[1];

	if (argc < 3) {
		if (!replacing) {
			(void) fprintf(stderr,
			    gettext("missing <new_device> specification\n"));
			usage(FALSE);
		}
		new_disk = old_disk;
		argc -= 1;
		argv += 1;
	} else {
		new_disk = argv[2];
		argc -= 2;
		argv += 2;
	}

	if (argc > 1) {
		(void) fprintf(stderr, gettext("too many arguments\n"));
		usage(FALSE);
	}

	if ((zhp = zpool_open(poolname)) == NULL)
		return (1);

	if ((config = zpool_get_config(zhp, NULL)) == NULL) {
		(void) fprintf(stderr, gettext("pool '%s' is unavailable\n"),
		    poolname);
		zpool_close(zhp);
		return (1);
	}

	nvroot = make_root_vdev(config, force, B_FALSE, argc, argv);
	if (nvroot == NULL) {
		zpool_close(zhp);
		return (1);
	}

	return (zpool_vdev_attach(zhp, old_disk, new_disk, nvroot, replacing));
}

/*
 * zpool replace [-f] <pool> <device> <new_device>
 *
 *	-f	Force attach, even if <new_device> appears to be in use.
 *
 * Replace <device> with <new_device>.
 */
/* ARGSUSED */
int
zpool_do_replace(int argc, char **argv)
{
	return (zpool_do_attach_or_replace(argc, argv, B_TRUE));
}

/*
 * zpool attach [-f] <pool> <device> <new_device>
 *
 *	-f	Force attach, even if <new_device> appears to be in use.
 *
 * Attach <new_device> to the mirror containing <device>.  If <device> is not
 * part of a mirror, then <device> will be transformed into a mirror of
 * <device> and <new_device>.  In either case, <new_device> will begin life
 * with a DTL of [0, now], and will immediately begin to resilver itself.
 */
int
zpool_do_attach(int argc, char **argv)
{
	return (zpool_do_attach_or_replace(argc, argv, B_FALSE));
}

/*
 * zpool detach [-f] <pool> <device>
 *
 *	-f	Force detach of <device>, even if DTLs argue against it
 *		(not supported yet)
 *
 * Detach a device from a mirror.  The operation will be refused if <device>
 * is the last device in the mirror, or if the DTLs indicate that this device
 * has the only valid copy of some data.
 */
/* ARGSUSED */
int
zpool_do_detach(int argc, char **argv)
{
	int c;
	char *poolname, *path;
	zpool_handle_t *zhp;

	/* check options */
	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name argument\n"));
		usage(FALSE);
	}

	if (argc < 2) {
		(void) fprintf(stderr,
		    gettext("missing <device> specification\n"));
		usage(FALSE);
	}

	poolname = argv[0];
	path = argv[1];

	if ((zhp = zpool_open(poolname)) == NULL)
		return (1);

	return (zpool_vdev_detach(zhp, path));
}

/*
 * zpool online [-t] <pool> <device>
 *
 *	-t	Only bring the device on-line temporarily.  The online
 *		state will not be persistent across reboots.
 */
/* ARGSUSED */
int
zpool_do_online(int argc, char **argv)
{
	int c, i;
	char *poolname;
	zpool_handle_t *zhp;
	int ret = 0;

	/* check options */
	while ((c = getopt(argc, argv, "t")) != -1) {
		switch (c) {
		case 't':
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name\n"));
		usage(FALSE);
	}
	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing device name\n"));
		usage(FALSE);
	}

	poolname = argv[0];

	if ((zhp = zpool_open(poolname)) == NULL)
		return (1);

	for (i = 1; i < argc; i++)
		if (zpool_vdev_online(zhp, argv[i]) == 0)
			(void) printf(gettext("Bringing device %s online\n"),
			    argv[i]);
		else
			ret = 1;

	return (ret);
}

/*
 * zpool offline [-ft] <pool> <device>
 *
 *	-f	Force the device into the offline state, even if doing
 *		so would appear to compromise pool availability.
 *		(not supported yet)
 *
 *	-t	Only take the device off-line temporarily.  The offline
 *		state will not be persistent across reboots.
 *		(not supported yet)
 */
/* ARGSUSED */
int
zpool_do_offline(int argc, char **argv)
{
	int c, i;
	char *poolname;
	zpool_handle_t *zhp;
	int ret = 0;

	/* check options */
	while ((c = getopt(argc, argv, "ft")) != -1) {
		switch (c) {
		case 'f':
		case 't':
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	/* get pool name and check number of arguments */
	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name\n"));
		usage(FALSE);
	}
	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing device name\n"));
		usage(FALSE);
	}

	poolname = argv[0];

	if ((zhp = zpool_open(poolname)) == NULL)
		return (1);

	for (i = 1; i < argc; i++)
		if (zpool_vdev_offline(zhp, argv[i]) == 0)
			(void) printf(gettext("Bringing device %s offline\n"),
			    argv[i]);
		else
			ret = 1;

	return (ret);
}

typedef struct scrub_cbdata {
	int	cb_type;
} scrub_cbdata_t;

int
scrub_callback(zpool_handle_t *zhp, void *data)
{
	scrub_cbdata_t *cb = data;

	return (zpool_scrub(zhp, cb->cb_type) != 0);
}

/*
 * zpool scrub [-s] <pool> ...
 *
 *	-s	Stop.  Stops any in-progress scrub.
 */
int
zpool_do_scrub(int argc, char **argv)
{
	int c;
	scrub_cbdata_t cb;

	cb.cb_type = POOL_SCRUB_EVERYTHING;

	/* check options */
	while ((c = getopt(argc, argv, "s")) != -1) {
		switch (c) {
		case 's':
			cb.cb_type = POOL_SCRUB_NONE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		(void) fprintf(stderr, gettext("missing pool name argument\n"));
		usage(FALSE);
	}

	return (for_each_pool(argc, argv, TRUE, scrub_callback, &cb));
}

typedef struct status_cbdata {
	int	cb_verbose;
	int	cb_explain;
	int	cb_count;
	int	cb_first;
} status_cbdata_t;

/*
 * Print out detailed scrub status.
 */
void
print_scrub_status(nvlist_t *nvroot)
{
	vdev_stat_t *vs;
	uint_t vsc;
	time_t start, end, now;
	double fraction_done;
	uint64_t examined, total, minutes_left;
	char *scrub_type;

	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &vsc) == 0);

	/*
	 * If there's never been a scrub, there's not much to say.
	 */
	if (vs->vs_scrub_end == 0 && vs->vs_scrub_type == POOL_SCRUB_NONE) {
		(void) printf(gettext("none requested\n"));
		return;
	}

	scrub_type = (vs->vs_scrub_type == POOL_SCRUB_RESILVER) ?
	    "resilver" : "scrub";

	start = vs->vs_scrub_start;
	end = vs->vs_scrub_end;
	now = time(NULL);
	examined = vs->vs_scrub_examined;
	total = vs->vs_alloc;

	if (end != 0) {
		(void) printf(gettext("%s %s with %llu errors on %s"),
		    scrub_type, vs->vs_scrub_complete ? "completed" : "stopped",
		    (u_longlong_t)vs->vs_scrub_errors, ctime(&end));
		return;
	}

	if (examined == 0)
		examined = 1;
	if (examined > total)
		total = examined;

	fraction_done = (double)examined / total;
	minutes_left = (uint64_t)((now - start) *
	    (1 - fraction_done) / fraction_done / 60);

	(void) printf(gettext("%s in progress, %.2f%% done, %lluh%um to go\n"),
	    scrub_type, 100 * fraction_done,
	    (u_longlong_t)(minutes_left / 60), (uint_t)(minutes_left % 60));
}

/*
 * Print out configuration state as requested by status_callback.
 */
void
print_status_config(const char *name, nvlist_t *nv, int namewidth, int depth)
{
	nvlist_t **child;
	uint_t c, children;
	vdev_stat_t *vs;
	char rbuf[6], wbuf[6], cbuf[6], repaired[6];

	verify(nvlist_lookup_uint64_array(nv, ZPOOL_CONFIG_STATS,
	    (uint64_t **)&vs, &c) == 0);

	if (nvlist_lookup_nvlist_array(nv, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) != 0)
		children = 0;

	(void) printf("\t%*s%-*s  %-8s", depth, "", namewidth - depth,
	    name, state_to_name(vs->vs_state));

	zfs_nicenum(vs->vs_read_errors, rbuf, sizeof (rbuf));
	zfs_nicenum(vs->vs_write_errors, wbuf, sizeof (wbuf));
	zfs_nicenum(vs->vs_checksum_errors, cbuf, sizeof (cbuf));
	(void) printf(" %5s %5s %5s", rbuf, wbuf, cbuf);

	if (vs->vs_aux != 0) {
		(void) printf("  ");

		switch (vs->vs_aux) {
		case VDEV_AUX_OPEN_FAILED:
			(void) printf(gettext("cannot open"));
			break;

		case VDEV_AUX_BAD_GUID_SUM:
			(void) printf(gettext("missing device"));
			break;

		case VDEV_AUX_NO_REPLICAS:
			(void) printf(gettext("insufficient replicas"));
			break;

		default:
			(void) printf(gettext("corrupted data"));
			break;
		}
	} else if (vs->vs_scrub_repaired != 0 && children == 0) {
		/*
		 * Report bytes resilvered/repaired on leaf devices.
		 */
		zfs_nicenum(vs->vs_scrub_repaired, repaired, sizeof (repaired));
		(void) printf(gettext("  %s %s"), repaired,
		    (vs->vs_scrub_type == POOL_SCRUB_RESILVER) ?
		    "resilvered" : "repaired");
	}

	(void) printf("\n");

	for (c = 0; c < children; c++)
		print_status_config(vdev_get_name(child[c]), child[c],
		    namewidth, depth + 2);
}

/*
 * Display a summary of pool status.  Displays a summary such as:
 *
 *        pool: tank
 *	status: DEGRADED
 *	reason: One or more devices ...
 *         see: http://www.sun.com/msg/ZFS-xxxx-01
 *	config:
 *		mirror		DEGRADED
 *                c1t0d0	OK
 *                c2t0d0	FAULTED
 *
 * When given the '-v' option, we print out the complete config.  If the '-e'
 * option is specified, then we print out error rate information as well.
 */
int
status_callback(zpool_handle_t *zhp, void *data)
{
	status_cbdata_t *cbp = data;
	nvlist_t *config, *nvroot;
	char *msgid;
	int reason;
	char *health;

	config = zpool_get_config(zhp, NULL);
	reason = zpool_get_status(zhp, &msgid);

	cbp->cb_count++;

	/*
	 * If we were given 'zpool status -x', only report those pools with
	 * problems.
	 */
	if (reason == ZPOOL_STATUS_OK && cbp->cb_explain)
		return (0);

	if (cbp->cb_first)
		cbp->cb_first = FALSE;
	else
		(void) printf("\n");

	verify(nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_HEALTH,
	    &health) == 0);

	(void) printf(gettext("  pool: %s\n"), zpool_get_name(zhp));
	(void) printf(gettext(" state: %s\n"), health);

	switch (reason) {
	case ZPOOL_STATUS_MISSING_DEV_R:
		(void) printf(gettext("status: One or more devices could not "
		    "be opened.  Sufficient replicas exist for\n\tthe pool to "
		    "continue functioning in a degraded state.\n"));
		(void) printf(gettext("action: Attach the missing device and "
		    "online it using 'zpool online'.\n"));
		break;

	case ZPOOL_STATUS_MISSING_DEV_NR:
		(void) printf(gettext("status: One or more devices could not "
		    "be opened.  There are insufficient\n\treplicas for the "
		    "pool to continue functioning.\n"));
		(void) printf(gettext("action: Attach the missing device and "
		    "online it using 'zpool online'.\n"));
		break;

	case ZPOOL_STATUS_CORRUPT_LABEL_R:
		(void) printf(gettext("status: One or more devices could not "
		    "be used because the label is missing or\n\tinvalid.  "
		    "Sufficient replicas exist for the pool to continue\n\t"
		    "functioning in a degraded state.\n"));
		(void) printf(gettext("action: Replace the device using "
		    "'zpool replace'.\n"));
		break;

	case ZPOOL_STATUS_CORRUPT_LABEL_NR:
		(void) printf(gettext("status: One or more devices could not "
		    "be used because the the label is missing \n\tor invalid.  "
		    "There are insufficient replicas for the pool to "
		    "continue\n\tfunctioning.\n"));
		(void) printf(gettext("action: Destroy and re-create the pool "
		    "from a backup source.\n"));
		break;

	case ZPOOL_STATUS_FAILING_DEV:
		(void) printf(gettext("status: One or more devices has "
		    "experienced an unrecoverable error.  An\n\tattempt was "
		    "made to correct the error.  Applications are "
		    "unaffected.\n"));
		(void) printf(gettext("action: Determine if the device needs "
		    "to be replaced, and clear the errors\n\tusing "
		    "'zpool online' or replace the device with 'zpool "
		    "replace'.\n"));
		break;

	case ZPOOL_STATUS_OFFLINE_DEV:
		(void) printf(gettext("status: One or more devices has "
		    "been taken offline by the adminstrator.\n\tSufficient "
		    "replicas exist for the pool to continue functioning in "
		    "a\n\tdegraded state.\n"));
		(void) printf(gettext("action: Online the device using "
		    "'zpool online' or replace the device with\n\t'zpool "
		    "replace'.\n"));
		break;

	case ZPOOL_STATUS_RESILVERING:
		(void) printf(gettext("status: One or more devices is "
		    "currently being resilvered.  The pool will\n\tcontinue "
		    "to function, possibly in a degraded state.\n"));
		(void) printf(gettext("action: Wait for the resilver to "
		    "complete.\n"));
		break;

	default:
		/*
		 * The remaining errors can't actually be generated, yet.
		 */
		assert(reason == ZPOOL_STATUS_OK);
	}

	if (msgid != NULL)
		(void) printf(gettext("   see: http://www.sun.com/msg/%s\n"),
		    msgid);

	if (config != NULL) {
		int namewidth;

		verify(nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
		    &nvroot) == 0);

		(void) printf(gettext(" scrub: "));
		print_scrub_status(nvroot);

		namewidth = max_width(nvroot, 0, 0);
		if (namewidth < 10)
			namewidth = 10;

		(void) printf(gettext("config:\n\n"));
		(void) printf(gettext("\t%-*s  %-8s %5s %5s %5s\n"), namewidth,
		    "NAME", "STATE", "READ", "WRITE", "CKSUM");
		print_status_config(zpool_get_name(zhp), nvroot, namewidth, 0);
	} else {
		(void) printf(gettext("config: The configuration cannot be "
		    "determined.\n"));
	}

	return (0);
}

/*
 * zpool status [-vx] [pool] ...
 *
 *	-v	Display complete error logs
 *	-x	Display only pools with potential problems
 *
 * Describes the health status of all pools or some subset.
 */
int
zpool_do_status(int argc, char **argv)
{
	int c;
	int ret;
	status_cbdata_t cb = { 0 };

	/* check options */
	while ((c = getopt(argc, argv, "vx")) != -1) {
		switch (c) {
		case 'v':
			cb.cb_verbose = TRUE;
			break;
		case 'x':
			cb.cb_explain = TRUE;
			break;
		case '?':
			(void) fprintf(stderr, gettext("invalid option '%c'\n"),
			    optopt);
			usage(FALSE);
		}
	}

	argc -= optind;
	argv += optind;

	cb.cb_first = TRUE;

	ret = for_each_pool(argc, argv, TRUE, status_callback, &cb);

	if (argc == 0 && cb.cb_count == 0)
		(void) printf(gettext("no pools available\n"));
	else if (cb.cb_explain && cb.cb_first) {
		if (argc == 0) {
			(void) printf(gettext("all pools are healthy\n"));
		} else {
			int i;
			for (i = 0; i < argc; i++)
				(void) printf(gettext("pool '%s' is healthy\n"),
				    argv[i]);
		}
	}

	return (ret);
}

int
main(int argc, char **argv)
{
	int ret;
	int i;
	char *cmdname;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;

	/*
	 * Make sure the user has specified some command.
	 */
	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing command\n"));
		usage(FALSE);
	}

	cmdname = argv[1];

	/*
	 * Special case '-?'
	 */
	if (strcmp(cmdname, "-?") == 0)
		usage(TRUE);

	/*
	 * Run the appropriate command.
	 */
	for (i = 0; i < NCOMMAND; i++) {
		if (command_table[i].name == NULL)
			continue;

		if (strcmp(cmdname, command_table[i].name) == 0) {
			current_command = &command_table[i];
			ret = command_table[i].func(argc - 1, argv + 1);
			break;
		}
	}

	/*
	 * 'freeze' is a vile debugging abomination, so we treat it as such.
	 */
	if (strcmp(cmdname, "freeze") == 0 && argc == 3) {
		char buf[8192];
		int fd = open("/dev/zpoolctl", O_RDWR);
		(void) strcpy((void *)buf, argv[2]);
		return (!!ioctl(fd, ZFS_IOC_POOL_FREEZE, buf));
	}

	if (i == NCOMMAND) {
		(void) fprintf(stderr, gettext("unrecognized "
		    "command '%s'\n"), cmdname);
		usage(FALSE);
	}

	/*
	 * The 'ZFS_ABORT' environment variable causes us to dump core on exit
	 * for the purposes of running ::findleaks.
	 */
	if (getenv("ZFS_ABORT") != NULL) {
		(void) printf("dumping core by request\n");
		abort();
	}

	return (ret);
}
