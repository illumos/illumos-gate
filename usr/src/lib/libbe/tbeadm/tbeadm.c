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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * System includes
 */

#include <stdio.h>
#include <strings.h>
#include <libzfs.h>

#include "libbe.h"

static int be_do_create(int argc, char **argv);
static int be_do_destroy(int argc, char **argv);
static int be_do_list(int argc, char **argv);
static int be_do_mount(int argc, char **argv);
static int be_do_unmount(int argc, char **argv);
static int be_do_rename(int argc, char **argv);
static int be_do_activate(int argc, char **argv);
static int be_do_create_snapshot(int argc, char **argv);
static int be_do_destroy_snapshot(int argc, char **argv);
static int be_do_rollback(int argc, char **argv);
static void usage(void);

typedef struct be_command {
	const char	*name;
	int		(*func)(int argc, char **argv);
} be_command_t;

static be_command_t command_table[] = {
	{ "create", be_do_create },
	{ "destroy", be_do_destroy },
	{ "list", be_do_list },
	{ "mount", be_do_mount },
	{ "unmount", be_do_unmount },
	{ "rename", be_do_rename },
	{ "activate", be_do_activate },
	{ "create_snap", be_do_create_snapshot },
	{ "destroy_snap", be_do_destroy_snapshot },
};

static int fs_num = 2;
static int shared_fs_num = 2;
static char *fs_names[2] = {"/", "/opt"};
static char *shared_fs_names[4] = {"/export", "/export/home"};

static void
usage(void)
{
	(void) printf("usage:\n"
	    "\ttbeadm\n"
	    "\ttbeadm create [-d BE_desc] [-e nonActiveBe | -i] \n"
	    "\t\t[-o property=value] ... [-p zpool] [beName]\n"
	    "\ttbeadm destroy [-fs] beName\n"
	    "\ttbeadm create_snap [-p policy] beName [snapshot]\n"
	    "\ttbeadm destroy_snap beName snapshot\n"
	    "\ttbeadm list [-s] [beName]\n"
	    "\ttbeadm mount [-s ro|rw] beName mountpoint\n"
	    "\ttbeadm unmount [-f] beName\n"
	    "\ttbeadm rename origBeName newBeName\n"
	    "\ttbeadm activate beName\n"
	    "\ttbeadm rollback beName snapshot\n");
}

int
main(int argc, char **argv) {

	if (argc < 2) {
		usage();
		return (1);
	}

	/* Turn error printing on */
	libbe_print_errors(B_TRUE);

	if (strcmp(argv[1], "create") == 0) {
		return (be_do_create(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "destroy") == 0) {
		return (be_do_destroy(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "list") == 0) {
		return (be_do_list(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "mount") == 0) {
		return (be_do_mount(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "unmount") == 0) {
		return (be_do_unmount(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "rename") == 0) {
		return (be_do_rename(argc - 2, argv + 2));
	} else if (strcmp(argv[1], "activate") == 0) {
		return (be_do_activate(argc - 2, argv + 2));
	} else if (strcmp(argv[1], "create_snap") == 0) {
		return (be_do_create_snapshot(argc - 1, argv + 1));
	} else if (strcmp(argv[1], "destroy_snap") == 0) {
		return (be_do_destroy_snapshot(argc - 2, argv + 2));
	} else if (strcmp(argv[1], "rollback") == 0) {
		return (be_do_rollback(argc - 2, argv + 2));
	} else {
		usage();
		return (1);
	}

	/* NOTREACHED */
}

static int
be_do_create(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name = NULL;
	char		*snap_name = NULL;
	char		*nbe_zpool = NULL;
	char		*nbe_name = NULL;
	char		*nbe_desc = NULL;
	nvlist_t	*zfs_props = NULL;
	char		*propname = NULL;
	char		*propval = NULL;
	char		*strval = NULL;
	boolean_t	init = B_FALSE;
	int		c;
	int		ret = BE_SUCCESS;

	if (nvlist_alloc(&zfs_props, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	while ((c = getopt(argc, argv, "d:e:io:p:")) != -1) {
		switch (c) {
		case 'd':
			nbe_desc = optarg;
			break;
		case 'e':
			obe_name = optarg;
			break;
		case 'i':
			/* Special option to test be_init() function */
			init = B_TRUE;
			break;
		case 'o':
			if (zfs_props == NULL) {
				if (nvlist_alloc(&zfs_props, NV_UNIQUE_NAME,
				    0) != 0) {
					printf("nvlist_alloc failed.\n");
					return (1);
				}
			}

			propname = optarg;
			if ((propval = strchr(propname, '=')) == NULL) {
				(void) fprintf(stderr, "missing "
				    "'=' for -o option\n");
				return (1);
			}
			*propval = '\0';
			propval++;
			if (nvlist_lookup_string(zfs_props, propname,
			    &strval) == 0) {
				(void) fprintf(stderr, "property '%s' "
				    "specified multiple times\n", propname);
				return (1);
			}
			if (nvlist_add_string(zfs_props, propname, propval)
			    != 0) {
				(void) fprintf(stderr, "internal "
				    "error: out of memory\n");
				return (1);
			}
			break;
		case 'p':
			nbe_zpool = optarg;
			break;
		default:
			usage();
			return (1);
		}
	}

	if (init && obe_name) {
		printf("ERROR: -e and -i are exclusive options\n");
		usage();
		return (1);
	}

	argc -= optind;
	argv += optind;

	if (argc == 1) {
		nbe_name = argv[0];
	} else if (argc > 1) {
		usage();
		return (1);
	}

	if (obe_name) {
		/*
		 * Check if obe_name is really a snapshot name.
		 * If so, split it out.
		 */
		char *cp = NULL;

		cp = strrchr(obe_name, '@');
		if (cp != NULL) {
			cp[0] = '\0';
			if (cp[1] != NULL && cp[1] != '\0') {
				snap_name = cp+1;
			}
		}
	}

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (zfs_props) {
		if (nvlist_add_nvlist(be_attrs, BE_ATTR_ZFS_PROPERTIES,
		    zfs_props) != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_ZFS_PROPERTES (%s).\n", zfs_props);
			return (1);
		}
	}

	if (obe_name != NULL) {
		if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
			return (1);
		}
	}

	if (snap_name != NULL) {
		if (nvlist_add_string(be_attrs, BE_ATTR_SNAP_NAME, snap_name)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_SNAP_NANE (%s).\n", snap_name);
			return (1);
		}
	}

	if (nbe_zpool != NULL) {
		if (nvlist_add_string(be_attrs, BE_ATTR_NEW_BE_POOL, nbe_zpool)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_NEW_BE_POOL (%s).\n", nbe_zpool);
			return (1);
		}
	}

	if (nbe_name) {
		if (nvlist_add_string(be_attrs, BE_ATTR_NEW_BE_NAME, nbe_name)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_NEW_BE_NAME (%s).\n", nbe_name);
			return (1);
		}
	}

	if (nbe_desc) {
		if (nvlist_add_string(be_attrs, BE_ATTR_NEW_BE_DESC, nbe_desc)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_NEW_BE_DESC (%s)\n", nbe_desc);
			return (1);
		}
	}

	if (init) {
		/*
		 * Add the default file system test values to test
		 * creating an initial BE.
		 */
		if (nvlist_add_uint16(be_attrs, BE_ATTR_FS_NUM, fs_num) != 0) {
			printf("nvlist_add_uint16 failed for BE_ATTR_FS_NUM "
			    "(%d).\n", fs_num);
			return (1);
		}

		if (nvlist_add_string_array(be_attrs, BE_ATTR_FS_NAMES,
		    fs_names, fs_num) != 0) {
			printf("nvlist_add_string_array failed for "
			    "BE_ATTR_FS_NAMES\n");
			return (1);
		}

		if (nvlist_add_uint16(be_attrs, BE_ATTR_SHARED_FS_NUM,
		    shared_fs_num) != 0) {
			printf("nvlist_add_uint16 failed for "
			    "BE_ATTR_SHARED_FS_NUM (%d).\n", shared_fs_num);
			return (1);
		}

		if (nvlist_add_string_array(be_attrs, BE_ATTR_SHARED_FS_NAMES,
		    shared_fs_names, shared_fs_num) != 0) {
			printf("nvlist_add_string_array failed for "
			    "BE_ATTR_SHARED_FS_NAMES\n");
			return (1);
		}

		return (be_init(be_attrs));
	}

	ret = be_copy(be_attrs);

	if (!nbe_name & ret == BE_SUCCESS) {
		/*
		 * We requested an auto named BE; find out the
		 * name of the BE that was created for us and
		 * the auto snapshot created from the original BE.
		 */
		if (nvlist_lookup_string(be_attrs, BE_ATTR_NEW_BE_NAME,
		    &nbe_name) != 0) {
			printf("failed to get BE_ATTR_NEW_BE_NAME attribute\n");
			ret = 1;
		} else {
			printf("Auto named BE: %s\n", nbe_name);
		}

		if (nvlist_lookup_string(be_attrs, BE_ATTR_SNAP_NAME,
		    &snap_name) != 0) {
			printf("failed to get BE_ATTR_SNAP_NAME attribute\n");
			ret = 1;
		} else {
			printf("Auto named snapshot: %s\n", snap_name);
		}
	}

	return (ret);
}

static int
be_do_destroy(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	int		c;
	int		destroy_flags = 0;
	char		*be_name;

	while ((c = getopt(argc, argv, "fs")) != -1) {
		switch (c) {
		case 'f':
			destroy_flags |= BE_DESTROY_FLAG_FORCE_UNMOUNT;
			break;
		case 's':
			destroy_flags |= BE_DESTROY_FLAG_SNAPSHOTS;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		return (1);
	}

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, argv[0]) != 0) {
		printf("nvlist_add_string failed for BE_ATTR_NEW_BE_NAME "
		    "(%s).\n", argv[0]);
		return (1);
	}

	if (nvlist_add_uint16(be_attrs, BE_ATTR_DESTROY_FLAGS, destroy_flags)
	    != 0) {
		printf("nvlist_add_uint16 failed for "
		    "BE_ATTR_DESTROY_FLAGS.\n");
		return (1);
	}

	return (be_destroy(be_attrs));
}

static int
be_do_list(int argc, char **argv)
{
	int		err = BE_SUCCESS;
	be_node_list_t	*be_nodes;
	be_node_list_t	*cur_be;
	boolean_t	snaps = B_FALSE;
	int		c = 0;

	while ((c = getopt(argc, argv, "s")) != -1) {
		switch (c) {
		case 's':
			snaps = B_TRUE;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;


	if (argc == 1) {
		err = be_list(argv[0], &be_nodes);
	} else {
		err = be_list(NULL, &be_nodes);
	}

	if (err == BE_SUCCESS) {

		printf(
		    "BE name\t\tActive\tActive \tDataset\t\t\tPolicy\tUUID\n");
		printf(
		    "       \t\t      \ton boot\t       \t\t\t      \t    \n");
		printf(
		    "-------\t\t------\t-------\t-------\t\t\t------\t----\n");

		for (cur_be = be_nodes; cur_be != NULL;
		    cur_be = cur_be->be_next_node) {

			int name_len = strlen(cur_be->be_node_name);
			int ds_len = strlen(cur_be->be_root_ds);

			printf("%s%s%s\t%s\t%s%s%s\t%s\n",
			    cur_be->be_node_name,
			    name_len < 8 ? "\t\t" : "\t",
			    cur_be->be_active ? "yes" : "no",
			    cur_be->be_active_on_boot ? "yes" : "no",
			    cur_be->be_root_ds,
			    ds_len < 8 ? "\t\t\t" :
			    (ds_len < 16 ? "\t\t" : "\t"),
			    cur_be->be_policy_type,
			    cur_be->be_uuid_str ? cur_be->be_uuid_str : "-");
			if (snaps) {
				be_snapshot_list_t *snapshots = NULL;
				printf("Snapshot Name\n");
				printf("--------------\n");
				for (snapshots = cur_be->be_node_snapshots;
				    snapshots != NULL; snapshots =
				    snapshots->be_next_snapshot) {
					printf("%s\n",
					    snapshots->be_snapshot_name);
				}
			}
		}
	}

	be_free_list(be_nodes);
	return (err);
}

static int
be_do_rename(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	char		*nbe_name;

	if (argc < 1 || argc > 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];
	nbe_name = argv[1];

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_NEW_BE_NAME, nbe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_NEW_BE_NAME (%s).\n", nbe_name);
		return (1);
	}

	return (be_rename(be_attrs));

}

static int
be_do_create_snapshot(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name = NULL;
	char		*snap_name = NULL;
	char		*policy = NULL;
	int		c;
	int		ret = BE_SUCCESS;

	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
		case 'p':
			policy = optarg;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1 || argc > 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];

	if (argc > 1) {
		/* Snapshot name provided */
		snap_name = argv[1];
	}

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (policy) {
		if (nvlist_add_string(be_attrs, BE_ATTR_POLICY, policy) != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_POLICY (%s).\n", policy);
			return (1);
		}
	}

	if (snap_name) {
		if (nvlist_add_string(be_attrs, BE_ATTR_SNAP_NAME, snap_name)
		    != 0) {
			printf("nvlist_add_string failed for "
			    "BE_ATTR_SNAP_NAME (%s).\n", snap_name);
			return (1);
		}
	}

	ret = be_create_snapshot(be_attrs);

	if (!snap_name && ret == BE_SUCCESS) {
		/*
		 * We requested an auto named snapshot; find out
		 * the snapshot name that was created for us.
		 */
		if (nvlist_lookup_string(be_attrs, BE_ATTR_SNAP_NAME,
		    &snap_name) != 0) {
			printf("failed to get BE_ATTR_SNAP_NAME attribute\n");
			ret = 1;
		} else {
			printf("Auto named snapshot: %s\n", snap_name);
		}
	}

	return (ret);
}

static int
be_do_destroy_snapshot(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	char		*snap_name;

	if (argc != 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];
	snap_name = argv[1];

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_SNAP_NAME, snap_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_SNAP_NAME (%s).\n", snap_name);
		return (1);
	}

	return (be_destroy_snapshot(be_attrs));
}

static int
be_do_rollback(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	char		*snap_name;

	if (argc < 1 || argc > 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];
	snap_name = argv[1];

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_SNAP_NAME, snap_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_SNAP_NAME (%s).\n", snap_name);
		return (1);
	}

	return (be_rollback(be_attrs));
}

static int
be_do_activate(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;

	if (argc < 1 || argc > 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	return (be_activate(be_attrs));
}

static int
be_do_mount(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	int		c;
	boolean_t	shared_fs = B_FALSE;
	int		mount_flags = 0;
	char		*obe_name;
	char		*mountpoint;

	while ((c = getopt(argc, argv, "s:")) != -1) {
		switch (c) {
		case 's':
			shared_fs = B_TRUE;

			mount_flags |= BE_MOUNT_FLAG_SHARED_FS;

			if (strcmp(optarg, "rw") == 0) {
				mount_flags |= BE_MOUNT_FLAG_SHARED_RW;
			} else if (strcmp(optarg, "ro") != 0) {
				printf("The -s flag requires an argument "
				    "[ rw | ro ]\n");
				usage();
				return (1);
			}

			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1 || argc > 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];

	if (argc == 2) {
		mountpoint = argv[1];
	} else {
		/*
		 * XXX - Need to generate a random mountpoint here;
		 * right now we're just exitting if one isn't supplied.
		 */
		usage();
		return (1);
	}

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_MOUNTPOINT, mountpoint)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_MOUNTPOINT (%s).\n", mountpoint);
		return (1);
	}

	if (shared_fs) {
		if (nvlist_add_uint16(be_attrs, BE_ATTR_MOUNT_FLAGS,
		    mount_flags) != 0) {
			printf("nvlist_add_uint16 failed for "
			    "BE_ATTR_MOUNT_FLAGS (%d).\n", mount_flags);
			return (1);
		}
	}

	return (be_mount(be_attrs));
}


static int
be_do_unmount(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	int		c;
	int		unmount_flags = 0;
	char		*obe_name;

	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			unmount_flags |= BE_UNMOUNT_FLAG_FORCE;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		return (1);
	}

	obe_name = argv[0];

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		printf("nvlist_alloc failed.\n");
		return (1);
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name)
	    != 0) {
		printf("nvlist_add_string failed for "
		    "BE_ATTR_ORIG_BE_NAME (%s).\n", obe_name);
		return (1);
	}

	if (nvlist_add_uint16(be_attrs, BE_ATTR_UNMOUNT_FLAGS, unmount_flags)
	    != 0) {
		printf("nvlist_add_uint16 failed for "
		    "BE_ATTR_UNMOUNT_FLAGS\n");
		return (1);
	}

	return (be_unmount(be_attrs));
}
