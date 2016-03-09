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
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 * Copyright 2015 Gary Mills
 */

/*
 * System includes
 */

#include <assert.h>
#include <stdio.h>
#include <strings.h>
#include <libzfs.h>
#include <locale.h>
#include <langinfo.h>
#include <stdlib.h>
#include <wchar.h>
#include <sys/types.h>

#include "libbe.h"

#ifndef lint
#define	_(x) gettext(x)
#else
#define	_(x) (x)
#endif

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#define	DT_BUF_LEN (128)
#define	NUM_COLS (6)

static int be_do_activate(int argc, char **argv);
static int be_do_create(int argc, char **argv);
static int be_do_destroy(int argc, char **argv);
static int be_do_list(int argc, char **argv);
static int be_do_mount(int argc, char **argv);
static int be_do_unmount(int argc, char **argv);
static int be_do_rename(int argc, char **argv);
static int be_do_rollback(int argc, char **argv);
static void usage(void);

/*
 * single column name/width output format description
 */
struct col_info {
	const char *col_name;
	size_t width;
};

/*
 * all columns output format
 */
struct hdr_info {
	struct col_info cols[NUM_COLS];
};

/*
 * type of possible output formats
 */
enum be_fmt {
	BE_FMT_DEFAULT,
	BE_FMT_DATASET,
	BE_FMT_SNAPSHOT,
	BE_FMT_ALL
};

/*
 * command handler description
 */
typedef struct be_command {
	const char	*name;
	int		(*func)(int argc, char **argv);
} be_command_t;

/*
 * sorted list of be commands
 */
static const be_command_t be_command_tbl[] = {
	{ "activate",		be_do_activate },
	{ "create",		be_do_create },
	{ "destroy",		be_do_destroy },
	{ "list",		be_do_list },
	{ "mount",		be_do_mount },
	{ "unmount",		be_do_unmount },
	{ "umount",		be_do_unmount }, /* unmount alias */
	{ "rename",		be_do_rename },
	{ "rollback",		be_do_rollback },
	{ NULL,			NULL },
};

static void
usage(void)
{
	(void) fprintf(stderr, _("usage:\n"
	    "\tbeadm subcommand cmd_options\n"
	    "\n"
	    "\tsubcommands:\n"
	    "\n"
	    "\tbeadm activate [-v] beName\n"
	    "\tbeadm create [-a] [-d BE_desc]\n"
	    "\t\t[-o property=value] ... [-p zpool] \n"
	    "\t\t[-e nonActiveBe | beName@snapshot] [-v] beName\n"
	    "\tbeadm create [-d BE_desc]\n"
	    "\t\t[-o property=value] ... [-p zpool] [-v] beName@snapshot\n"
	    "\tbeadm destroy [-Ffsv] beName \n"
	    "\tbeadm destroy [-Fv] beName@snapshot \n"
	    "\tbeadm list [[-a] | [-d] [-s]] [-H]\n"
	    "\t\t[-k|-K date | name | space] [-v] [beName]\n"
	    "\tbeadm mount [-s ro|rw] [-v] beName [mountpoint]\n"
	    "\tbeadm unmount [-fv] beName | mountpoint\n"
	    "\tbeadm umount [-fv] beName | mountpoint\n"
	    "\tbeadm rename [-v] origBeName newBeName\n"
	    "\tbeadm rollback [-v] beName snapshot\n"
	    "\tbeadm rollback [-v] beName@snapshot\n"));
}

static int
run_be_cmd(const char *cmdname, int argc, char **argv)
{
	const be_command_t *command;

	for (command = &be_command_tbl[0]; command->name != NULL; command++)
		if (strcmp(command->name, cmdname) == 0)
			return (command->func(argc, argv));

	(void) fprintf(stderr, _("Invalid command: %s\n"), cmdname);
	usage();
	return (1);
}

int
main(int argc, char **argv)
{
	const char *cmdname;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2) {
		usage();
		return (1);
	}

	cmdname = argv[1];

	/* Turn error printing off */
	libbe_print_errors(B_FALSE);

	return (run_be_cmd(cmdname, --argc, ++argv));
}

static void
print_hdr(struct hdr_info *hdr_info)
{
	boolean_t first = B_TRUE;
	size_t i;
	for (i = 0; i < NUM_COLS; i++) {
		struct col_info *col_info = &hdr_info->cols[i];
		const char *name = col_info->col_name;
		size_t width = col_info->width;
		if (name == NULL)
			continue;

		if (first) {
			(void) printf("%-*s", width, name);
			first = B_FALSE;
		} else
			(void) printf(" %-*s", width, name);
	}
	(void) putchar('\n');
}

static void
init_hdr_cols(enum be_fmt be_fmt, struct hdr_info *hdr)
{
	struct col_info *col = hdr->cols;
	size_t i;

	col[1].col_name = _("Active");
	col[2].col_name = _("Mountpoint");
	col[3].col_name = _("Space");
	col[4].col_name = _("Policy");
	col[5].col_name = _("Created");
	col[6].col_name = NULL;

	switch (be_fmt) {
	case BE_FMT_ALL:
		col[0].col_name = _("BE/Dataset/Snapshot");
		break;
	case BE_FMT_DATASET:
		col[0].col_name = _("BE/Dataset");
		break;
	case BE_FMT_SNAPSHOT:
		col[0].col_name = _("BE/Snapshot");
		col[1].col_name = NULL;
		col[2].col_name = NULL;
		break;
	case BE_FMT_DEFAULT:
	default:
		col[0].col_name = _("BE");
	}

	for (i = 0; i < NUM_COLS; i++) {
		const char *name = col[i].col_name;
		col[i].width = 0;

		if (name != NULL) {
			wchar_t wname[128];
			size_t sz = mbstowcs(wname, name, sizeof (wname) /
			    sizeof (wchar_t));
			if (sz > 0) {
				int wcsw = wcswidth(wname, sz);
				if (wcsw > 0)
					col[i].width = wcsw;
				else
					col[i].width = sz;
			} else {
				col[i].width = strlen(name);
			}
		}
	}
}

static void
nicenum(uint64_t num, char *buf, size_t buflen)
{
	uint64_t n = num;
	int index = 0;
	char u;

	while (n >= 1024) {
		n /= 1024;
		index++;
	}

	u = " KMGTPE"[index];

	if (index == 0) {
		(void) snprintf(buf, buflen, "%llu", n);
	} else {
		int i;
		for (i = 2; i >= 0; i--) {
			if (snprintf(buf, buflen, "%.*f%c", i,
			    (double)num / (1ULL << 10 * index), u) <= 5)
				break;
		}
	}
}

static void
count_widths(enum be_fmt be_fmt, struct hdr_info *hdr, be_node_list_t *be_nodes)
{
	size_t len[NUM_COLS];
	char buf[DT_BUF_LEN];
	int i;
	be_node_list_t *cur_be;

	for (i = 0; i < NUM_COLS; i++)
		len[i] = hdr->cols[i].width;

	for (cur_be = be_nodes; cur_be != NULL; cur_be = cur_be->be_next_node) {
		char name[ZFS_MAXNAMELEN+1];
		const char *be_name = cur_be->be_node_name;
		const char *root_ds = cur_be->be_root_ds;
		char *pos;
		size_t node_name_len = strlen(cur_be->be_node_name);
		size_t root_ds_len = strlen(cur_be->be_root_ds);
		size_t mntpt_len = 0;
		size_t policy_len = 0;
		size_t used_len;
		uint64_t used = cur_be->be_space_used;
		be_snapshot_list_t *snap = NULL;

		if (cur_be->be_mntpt != NULL)
			mntpt_len = strlen(cur_be->be_mntpt);
		if (cur_be->be_policy_type != NULL)
			policy_len = strlen(cur_be->be_policy_type);

		(void) strlcpy(name, root_ds, sizeof (name));
		pos = strstr(name, be_name);

		if (be_fmt == BE_FMT_DEFAULT) {
			if (node_name_len > len[0])
				len[0] = node_name_len;
		} else {
			if (root_ds_len + 3 > len[0])
				len[0] = root_ds_len + 3;
		}

		if (mntpt_len > len[2])
			len[2] = mntpt_len;
		if (policy_len > len[4])
			len[4] = policy_len;

		for (snap = cur_be->be_node_snapshots; snap != NULL;
		    snap = snap->be_next_snapshot) {
			uint64_t snap_used = snap->be_snapshot_space_used;
			const char *snap_name = snap->be_snapshot_name;
			(void) strcpy(pos, snap_name);

			if (be_fmt == BE_FMT_DEFAULT)
				used += snap_used;
			else if (be_fmt & BE_FMT_SNAPSHOT) {
				int snap_len = strlen(name) + 3;
				if (be_fmt == BE_FMT_SNAPSHOT)
					snap_len -= pos - name;
				if (snap_len > len[0])
					len[0] = snap_len;
				nicenum(snap_used, buf, sizeof (buf));
				used_len = strlen(buf);
				if (used_len > len[3])
					len[3] = used_len;
			}
		}

		if (be_fmt == BE_FMT_DEFAULT) {
			int used_len;
			nicenum(used, buf, sizeof (buf));
			used_len = strlen(buf);
			if (used_len > len[3])
				len[3] = used_len;
		}

		nicenum(used, buf, sizeof (buf));
	}

	for (i = 0; i < NUM_COLS; i++)
		hdr->cols[i].width = len[i];
}

static void
print_be_nodes(const char *be_name, boolean_t parsable, struct hdr_info *hdr,
    be_node_list_t *nodes)
{
	char buf[64];
	char datetime[DT_BUF_LEN];
	be_node_list_t	*cur_be;

	for (cur_be = nodes; cur_be != NULL; cur_be = cur_be->be_next_node) {
		char active[3] = "-\0";
		int ai = 0;
		const char *datetime_fmt = "%F %R";
		const char *name = cur_be->be_node_name;
		const char *mntpt = cur_be->be_mntpt;
		be_snapshot_list_t *snap = NULL;
		uint64_t used = cur_be->be_space_used;
		time_t creation = cur_be->be_node_creation;
		struct tm *tm;

		if (be_name != NULL && strcmp(be_name, name) != 0)
			continue;

		if (parsable)
			active[0] = '\0';

		tm = localtime(&creation);
		(void) strftime(datetime, DT_BUF_LEN, datetime_fmt, tm);

		for (snap = cur_be->be_node_snapshots; snap != NULL;
		    snap = snap->be_next_snapshot)
			used += snap->be_snapshot_space_used;

		if (!cur_be->be_global_active)
			active[ai++] = 'x';

		if (cur_be->be_active)
			active[ai++] = 'N';
		if (cur_be->be_active_on_boot) {
			if (!cur_be->be_global_active)
				active[ai] = 'b';
			else
				active[ai] = 'R';
		}

		nicenum(used, buf, sizeof (buf));
		if (parsable)
			(void) printf("%s;%s;%s;%s;%llu;%s;%ld\n",
			    name,
			    cur_be->be_uuid_str,
			    active,
			    (cur_be->be_mounted ? mntpt: ""),
			    used,
			    cur_be->be_policy_type,
			    creation);
		else
			(void) printf("%-*s %-*s %-*s %-*s %-*s %-*s\n",
			    hdr->cols[0].width, name,
			    hdr->cols[1].width, active,
			    hdr->cols[2].width, (cur_be->be_mounted ? mntpt:
			    "-"),
			    hdr->cols[3].width, buf,
			    hdr->cols[4].width, cur_be->be_policy_type,
			    hdr->cols[5].width, datetime);
	}
}

static void
print_be_snapshots(be_node_list_t *be, struct hdr_info *hdr, boolean_t parsable)
{
	char buf[64];
	char datetime[DT_BUF_LEN];
	be_snapshot_list_t *snap = NULL;

	for (snap = be->be_node_snapshots; snap != NULL;
	    snap = snap->be_next_snapshot) {
		char name[ZFS_MAXNAMELEN+1];
		const char *datetime_fmt = "%F %R";
		const char *be_name = be->be_node_name;
		const char *root_ds = be->be_root_ds;
		const char *snap_name = snap->be_snapshot_name;
		char *pos;
		uint64_t used = snap->be_snapshot_space_used;
		time_t creation = snap->be_snapshot_creation;
		struct tm *tm = localtime(&creation);

		(void) strncpy(name, root_ds, sizeof (name));
		pos = strstr(name, be_name);
		(void) strcpy(pos, snap_name);

		(void) strftime(datetime, DT_BUF_LEN, datetime_fmt, tm);
		nicenum(used, buf, sizeof (buf));

		if (parsable)
			if (hdr->cols[1].width != 0)
				(void) printf("%s;%s;%s;%s;%llu;%s;%ld\n",
				    be_name,
				    snap_name,
				    "",
				    "",
				    used,
				    be->be_policy_type,
				    creation);
			else
				(void) printf("%s;%s;%llu;%s;%ld\n",
				    be_name,
				    snap_name,
				    used,
				    be->be_policy_type,
				    creation);
		else
			if (hdr->cols[1].width != 0)
				(void) printf("   %-*s %-*s %-*s %-*s %-*s "
				    "%-*s\n",
				    hdr->cols[0].width-3, name,
				    hdr->cols[1].width, "-",
				    hdr->cols[2].width, "-",
				    hdr->cols[3].width, buf,
				    hdr->cols[4].width, be->be_policy_type,
				    hdr->cols[5].width, datetime);
			else
				(void) printf("   %-*s %-*s %-*s %-*s\n",
				    hdr->cols[0].width-3, snap_name,
				    hdr->cols[3].width, buf,
				    hdr->cols[4].width, be->be_policy_type,
				    hdr->cols[5].width, datetime);
	}
}

static void
print_fmt_nodes(const char *be_name, enum be_fmt be_fmt, boolean_t parsable,
    struct hdr_info *hdr, be_node_list_t *nodes)
{
	char buf[64];
	char datetime[DT_BUF_LEN];
	be_node_list_t	*cur_be;

	for (cur_be = nodes; cur_be != NULL; cur_be = cur_be->be_next_node) {
		char active[3] = "-\0";
		int ai = 0;
		const char *datetime_fmt = "%F %R";
		const char *name = cur_be->be_node_name;
		const char *mntpt = cur_be->be_mntpt;
		uint64_t used = cur_be->be_space_used;
		time_t creation = cur_be->be_node_creation;
		struct tm *tm;

		if (be_name != NULL && strcmp(be_name, name) != 0)
			continue;

		if (!parsable)
			(void) printf("%-s\n", name);
		else
			active[0] = '\0';

		tm = localtime(&creation);
		(void) strftime(datetime, DT_BUF_LEN, datetime_fmt, tm);

		if (cur_be->be_active)
			active[ai++] = 'N';
		if (cur_be->be_active_on_boot)
			active[ai] = 'R';

		nicenum(used, buf, sizeof (buf));
		if (be_fmt & BE_FMT_DATASET)
			if (parsable)
				(void) printf("%s;%s;%s;%s;%llu;%s;%ld\n",
				    cur_be->be_node_name,
				    cur_be->be_root_ds,
				    active,
				    (cur_be->be_mounted ? mntpt: ""),
				    used,
				    cur_be->be_policy_type,
				    creation);
			else
				(void) printf("   %-*s %-*s %-*s %-*s %-*s "
				    "%-*s\n",
				    hdr->cols[0].width-3, cur_be->be_root_ds,
				    hdr->cols[1].width, active,
				    hdr->cols[2].width, (cur_be->be_mounted ?
				    mntpt: "-"),
				    hdr->cols[3].width, buf,
				    hdr->cols[4].width, cur_be->be_policy_type,
				    hdr->cols[5].width, datetime);

		if (be_fmt & BE_FMT_SNAPSHOT)
			print_be_snapshots(cur_be, hdr, parsable);
	}
}

static void
print_nodes(const char *be_name, boolean_t dsets, boolean_t snaps,
    boolean_t parsable, be_node_list_t *be_nodes)
{
	struct hdr_info hdr;
	enum be_fmt be_fmt  = BE_FMT_DEFAULT;

	if (dsets)
		be_fmt |= BE_FMT_DATASET;
	if (snaps)
		be_fmt |= BE_FMT_SNAPSHOT;

	if (!parsable) {
		init_hdr_cols(be_fmt, &hdr);
		count_widths(be_fmt, &hdr, be_nodes);
		print_hdr(&hdr);
	}

	if (be_fmt == BE_FMT_DEFAULT)
		print_be_nodes(be_name, parsable, &hdr, be_nodes);
	else
		print_fmt_nodes(be_name, be_fmt, parsable, &hdr, be_nodes);
}

static boolean_t
confirm_destroy(const char *name)
{
	boolean_t res = B_FALSE;
	const char *yesre = nl_langinfo(YESEXPR);
	const char *nore = nl_langinfo(NOEXPR);
	regex_t yes_re;
	regex_t no_re;
	char buf[128];
	char *answer;
	int cflags = REG_EXTENDED;

	if (regcomp(&yes_re, yesre, cflags) != 0) {
		/* should not happen */
		(void) fprintf(stderr, _("Failed to compile 'yes' regexp\n"));
		return (res);
	}
	if (regcomp(&no_re, nore, cflags) != 0) {
		/* should not happen */
		(void) fprintf(stderr, _("Failed to compile 'no' regexp\n"));
		regfree(&yes_re);
		return (res);
	}

	(void) printf(_("Are you sure you want to destroy %s?\n"
	    "This action cannot be undone (y/[n]): "), name);

	answer = fgets(buf, sizeof (buf), stdin);
	if (answer == NULL || *answer == '\0' || *answer == 10)
		goto out;

	if (regexec(&yes_re, answer, 0, NULL, 0) == 0) {
		res = B_TRUE;
	} else if (regexec(&no_re, answer, 0, NULL, 0) != 0) {
		(void) fprintf(stderr, _("Invalid response. "
		    "Please enter 'y' or 'n'.\n"));
	}

out:
	regfree(&yes_re);
	regfree(&no_re);
	return (res);
}

static int
be_nvl_alloc(nvlist_t **nvlp)
{
	assert(nvlp != NULL);

	if (nvlist_alloc(nvlp, NV_UNIQUE_NAME, 0) != 0) {
		(void) perror(_("nvlist_alloc failed.\n"));
		return (1);
	}

	return (0);
}

static int
be_nvl_add_string(nvlist_t *nvl, const char *name, const char *val)
{
	assert(nvl != NULL);

	if (nvlist_add_string(nvl, name, val) != 0) {
		(void) fprintf(stderr, _("nvlist_add_string failed for "
		    "%s (%s).\n"), name, val);
		return (1);
	}

	return (0);
}

static int
be_nvl_add_nvlist(nvlist_t *nvl, const char *name, nvlist_t *val)
{
	assert(nvl != NULL);

	if (nvlist_add_nvlist(nvl, name, val) != 0) {
		(void) fprintf(stderr, _("nvlist_add_nvlist failed for %s.\n"),
		    name);
		return (1);
	}

	return (0);
}

static int
be_nvl_add_uint16(nvlist_t *nvl, const char *name, uint16_t val)
{
	assert(nvl != NULL);

	if (nvlist_add_uint16(nvl, name, val) != 0) {
		(void) fprintf(stderr, _("nvlist_add_uint16 failed for "
		    "%s (%hu).\n"), name, val);
		return (1);
	}

	return (0);
}

static int
be_do_activate(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	int		err = 1;
	int		c;
	char		*obe_name;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			libbe_print_errors(B_TRUE);
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

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);

	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	err = be_activate(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Activated successfully\n"));
		break;
	case BE_ERR_BE_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid BE.\nPlease check that the name of "
		    "the BE provided is correct.\n"), obe_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Unable to activate %s.\n"), obe_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	case BE_ERR_ACTIVATE_CURR:
	default:
		(void) fprintf(stderr, _("Unable to activate %s.\n"), obe_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
	return (err);
}

static int
be_do_create(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	nvlist_t	*zfs_props = NULL;
	boolean_t	activate = B_FALSE;
	boolean_t	is_snap = B_FALSE;
	int		c;
	int		err = 1;
	char		*obe_name = NULL;
	char		*snap_name = NULL;
	char		*nbe_zpool = NULL;
	char		*nbe_name = NULL;
	char		*nbe_desc = NULL;
	char		*propname = NULL;
	char		*propval = NULL;
	char		*strval = NULL;

	while ((c = getopt(argc, argv, "ad:e:io:p:v")) != -1) {
		switch (c) {
		case 'a':
			activate = B_TRUE;
			break;
		case 'd':
			nbe_desc = optarg;
			break;
		case 'e':
			obe_name = optarg;
			break;
		case 'o':
			if (zfs_props == NULL && be_nvl_alloc(&zfs_props) != 0)
				return (1);

			propname = optarg;
			if ((propval = strchr(propname, '=')) == NULL) {
				(void) fprintf(stderr, _("missing "
				    "'=' for -o option\n"));
				goto out2;
			}
			*propval = '\0';
			propval++;
			if (nvlist_lookup_string(zfs_props, propname,
			    &strval) == 0) {
				(void) fprintf(stderr, _("property '%s' "
				    "specified multiple times\n"), propname);
				goto out2;

			}
			if (be_nvl_add_string(zfs_props, propname, propval)
			    != 0)
				goto out2;

			break;
		case 'p':
			nbe_zpool = optarg;
			break;
		case 'v':
			libbe_print_errors(B_TRUE);
			break;
		default:
			usage();
			goto out2;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		goto out2;
	}

	nbe_name = argv[0];

	if ((snap_name = strrchr(nbe_name, '@')) != NULL) {
		if (snap_name[1] == '\0') {
			usage();
			goto out2;
		}

		snap_name[0] = '\0';
		snap_name++;
		is_snap = B_TRUE;
	}

	if (obe_name) {
		if (is_snap) {
			usage();
			goto out2;
		}

		/*
		 * Check if obe_name is really a snapshot name.
		 * If so, split it out.
		 */
		if ((snap_name = strrchr(obe_name, '@')) != NULL) {
			if (snap_name[1] == '\0') {
				usage();
				goto out2;
			}

			snap_name[0] = '\0';
			snap_name++;
		}
	} else if (is_snap) {
		obe_name = nbe_name;
		nbe_name = NULL;
	}

	if (be_nvl_alloc(&be_attrs) != 0)
		goto out2;


	if (zfs_props != NULL && be_nvl_add_nvlist(be_attrs,
	    BE_ATTR_ORIG_BE_NAME, zfs_props) != 0)
		goto out;

	if (obe_name != NULL && be_nvl_add_string(be_attrs,
	    BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	if (snap_name != NULL && be_nvl_add_string(be_attrs,
	    BE_ATTR_SNAP_NAME, snap_name) != 0)
		goto out;

	if (nbe_zpool != NULL && be_nvl_add_string(be_attrs,
	    BE_ATTR_NEW_BE_POOL, nbe_zpool) != 0)
		goto out;

	if (nbe_name != NULL && be_nvl_add_string(be_attrs,
	    BE_ATTR_NEW_BE_NAME, nbe_name) != 0)
		goto out;

	if (nbe_desc != NULL && be_nvl_add_string(be_attrs,
	    BE_ATTR_NEW_BE_DESC, nbe_desc) != 0)
		goto out;

	if (is_snap)
		err = be_create_snapshot(be_attrs);
	else
		err = be_copy(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		if (!is_snap && !nbe_name) {
			/*
			 * We requested an auto named BE; find out the
			 * name of the BE that was created for us and
			 * the auto snapshot created from the original BE.
			 */
			if (nvlist_lookup_string(be_attrs, BE_ATTR_NEW_BE_NAME,
			    &nbe_name) != 0) {
				(void) fprintf(stderr, _("failed to get %s "
				    "attribute\n"), BE_ATTR_NEW_BE_NAME);
				break;
			} else
				(void) printf(_("Auto named BE: %s\n"),
				    nbe_name);

			if (nvlist_lookup_string(be_attrs, BE_ATTR_SNAP_NAME,
			    &snap_name) != 0) {
				(void) fprintf(stderr, _("failed to get %s "
				    "attribute\n"), BE_ATTR_SNAP_NAME);
				break;
			} else
				(void) printf(_("Auto named snapshot: %s\n"),
				    snap_name);
		}

		if (!is_snap && activate) {
			char *args[] = { "activate", "", NULL };
			args[1] = nbe_name;
			optind = 1;

			err = be_do_activate(2, args);
			goto out;
		}

		(void) printf(_("Created successfully\n"));
		break;
	case BE_ERR_BE_EXISTS:
		(void) fprintf(stderr, _("BE %s already exists\n."
		    "Please choose a different BE name.\n"), nbe_name);
		break;
	case BE_ERR_SS_EXISTS:
		(void) fprintf(stderr, _("BE %s snapshot %s already exists.\n"
		    "Please choose a different snapshot name.\n"), obe_name,
		    snap_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		if (is_snap)
			(void) fprintf(stderr, _("Unable to create snapshot "
			    "%s.\n"), snap_name);
		else
			(void) fprintf(stderr, _("Unable to create %s.\n"),
			    nbe_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	default:
		if (is_snap)
			(void) fprintf(stderr, _("Unable to create snapshot "
			    "%s.\n"), snap_name);
		else
			(void) fprintf(stderr, _("Unable to create %s.\n"),
			    nbe_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
out2:
	nvlist_free(zfs_props);

	return (err);
}

static int
be_do_destroy(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	boolean_t	is_snap = B_FALSE;
	boolean_t	suppress_prompt = B_FALSE;
	int		err = 1;
	int		c;
	int		destroy_flags = 0;
	char		*snap_name;
	char		*be_name;

	while ((c = getopt(argc, argv, "fFsv")) != -1) {
		switch (c) {
		case 'f':
			destroy_flags |= BE_DESTROY_FLAG_FORCE_UNMOUNT;
			break;
		case 's':
			destroy_flags |= BE_DESTROY_FLAG_SNAPSHOTS;
			break;
		case 'v':
			libbe_print_errors(B_TRUE);
			break;
		case 'F':
			suppress_prompt = B_TRUE;
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

	be_name = argv[0];
	if (!suppress_prompt && !confirm_destroy(be_name)) {
		(void) printf(_("%s has not been destroyed.\n"), be_name);
		return (0);
	}

	if ((snap_name = strrchr(be_name, '@')) != NULL) {
		if (snap_name[1] == '\0') {
			usage();
			return (1);
		}

		is_snap = B_TRUE;
		*snap_name = '\0';
		snap_name++;
	}

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);


	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, be_name) != 0)
		goto out;

	if (is_snap) {
		if (be_nvl_add_string(be_attrs, BE_ATTR_SNAP_NAME,
		    snap_name) != 0)
			goto out;

		err = be_destroy_snapshot(be_attrs);
	} else {
		if (be_nvl_add_uint16(be_attrs, BE_ATTR_DESTROY_FLAGS,
		    destroy_flags) != 0)
			goto out;

		err = be_destroy(be_attrs);
	}

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Destroyed successfully\n"));
		break;
	case BE_ERR_MOUNTED:
		(void) fprintf(stderr, _("Unable to destroy %s.\n"), be_name);
		(void) fprintf(stderr, _("It is currently mounted and must be "
		    "unmounted before it can be destroyed.\n" "Use 'beadm "
		    "unmount %s' to unmount the BE before destroying\nit or "
		    "'beadm destroy -f %s'.\n"), be_name, be_name);
		break;
	case BE_ERR_DESTROY_CURR_BE:
		(void) fprintf(stderr, _("%s is the currently active BE and "
		    "cannot be destroyed.\nYou must boot from another BE in "
		    "order to destroy %s.\n"), be_name, be_name);
		break;
	case BE_ERR_ZONES_UNMOUNT:
		(void) fprintf(stderr, _("Unable to destroy one of " "%s's "
		    "zone BE's.\nUse 'beadm destroy -f %s' or "
		    "'zfs -f destroy <dataset>'.\n"), be_name, be_name);
		break;
	case BE_ERR_SS_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid snapshot.\nPlease check that the name of "
		    "the snapshot provided is correct.\n"), snap_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Unable to destroy %s.\n"), be_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	case BE_ERR_SS_EXISTS:
		(void) fprintf(stderr, _("Unable to destroy %s: "
		    "BE has snapshots.\nUse 'beadm destroy -s %s' or "
		    "'zfs -r destroy <dataset>'.\n"), be_name, be_name);
		break;
	default:
		(void) fprintf(stderr, _("Unable to destroy %s.\n"), be_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
	return (err);
}

static int
be_do_list(int argc, char **argv)
{
	be_node_list_t	*be_nodes = NULL;
	boolean_t	all = B_FALSE;
	boolean_t	dsets = B_FALSE;
	boolean_t	snaps = B_FALSE;
	boolean_t	parsable = B_FALSE;
	int		err = 1;
	int		c = 0;
	char		*be_name = NULL;
	be_sort_t	order = BE_SORT_UNSPECIFIED;

	while ((c = getopt(argc, argv, "adk:svHK:")) != -1) {
		switch (c) {
		case 'a':
			all = B_TRUE;
			break;
		case 'd':
			dsets = B_TRUE;
			break;
		case 'k':
		case 'K':
			if (order != BE_SORT_UNSPECIFIED) {
				(void) fprintf(stderr, _("Sort key can be "
				    "specified only once.\n"));
				usage();
				return (1);
			}
			if (strcmp(optarg, "date") == 0) {
				if (c == 'k')
					order = BE_SORT_DATE;
				else
					order = BE_SORT_DATE_REV;
				break;
			}
			if (strcmp(optarg, "name") == 0) {
				if (c == 'k')
					order = BE_SORT_NAME;
				else
					order = BE_SORT_NAME_REV;
				break;
			}
			if (strcmp(optarg, "space") == 0) {
				if (c == 'k')
					order = BE_SORT_SPACE;
				else
					order = BE_SORT_SPACE_REV;
				break;
			}
			(void) fprintf(stderr, _("Unknown sort key: %s\n"),
			    optarg);
			usage();
			return (1);
		case 's':
			snaps = B_TRUE;
			break;
		case 'v':
			libbe_print_errors(B_TRUE);
			break;
		case 'H':
			parsable = B_TRUE;
			break;
		default:
			usage();
			return (1);
		}
	}

	if (all) {
		if (dsets) {
			(void) fprintf(stderr, _("Invalid options: -a and %s "
			    "are mutually exclusive.\n"), "-d");
			usage();
			return (1);
		}
		if (snaps) {
			(void) fprintf(stderr, _("Invalid options: -a and %s "
			    "are mutually exclusive.\n"), "-s");
			usage();
			return (1);
		}

		dsets = B_TRUE;
		snaps = B_TRUE;
	}

	argc -= optind;
	argv += optind;


	if (argc == 1)
		be_name = argv[0];

	err = be_list(be_name, &be_nodes);

	switch (err) {
	case BE_SUCCESS:
		/* the default sort is ascending date, no need to sort twice */
		if (order == BE_SORT_UNSPECIFIED)
			order = BE_SORT_DATE;

		if (order != BE_SORT_DATE) {
			err = be_sort(&be_nodes, order);
			if (err != BE_SUCCESS) {
				(void) fprintf(stderr, _("Unable to sort Boot "
				    "Environment\n"));
				(void) fprintf(stderr, "%s\n",
				    be_err_to_str(err));
				break;
			}
		}

		print_nodes(be_name, dsets, snaps, parsable, be_nodes);
		break;
	case BE_ERR_BE_NOENT:
		if (be_name == NULL)
			(void) fprintf(stderr, _("No boot environments found "
			    "on this system.\n"));
		else {
			(void) fprintf(stderr, _("%s does not exist or appear "
			    "to be a valid BE.\nPlease check that the name of "
			    "the BE provided is correct.\n"), be_name);
		}
		break;
	default:
		(void) fprintf(stderr, _("Unable to display Boot "
		    "Environment\n"));
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

	if (be_nodes != NULL)
		be_free_list(be_nodes);
	return (err);
}

static int
be_do_mount(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	boolean_t	shared_fs = B_FALSE;
	int		err = 1;
	int		c;
	int		mount_flags = 0;
	char		*obe_name;
	char		*mountpoint;
	char		*tmp_mp = NULL;

	while ((c = getopt(argc, argv, "s:v")) != -1) {
		switch (c) {
		case 's':
			shared_fs = B_TRUE;

			mount_flags |= BE_MOUNT_FLAG_SHARED_FS;

			if (strcmp(optarg, "rw") == 0) {
				mount_flags |= BE_MOUNT_FLAG_SHARED_RW;
			} else if (strcmp(optarg, "ro") != 0) {
				(void) fprintf(stderr, _("The -s flag "
				    "requires an argument [ rw | ro ]\n"));
				usage();
				return (1);
			}

			break;
		case 'v':
			libbe_print_errors(B_TRUE);
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
		if (mountpoint[0] != '/') {
			(void) fprintf(stderr, _("Invalid mount point %s. "
			    "Mount point must start with a /.\n"), mountpoint);
			return (1);
		}
	} else {
		const char *tmpdir = getenv("TMPDIR");
		const char *tmpname = "tmp.XXXXXX";
		int sz;

		if (tmpdir == NULL)
			tmpdir = "/tmp";

		sz = asprintf(&tmp_mp, "%s/%s", tmpdir, tmpname);
		if (sz < 0) {
			(void) fprintf(stderr, _("internal error: "
			    "out of memory\n"));
			return (1);
		}

		mountpoint = mkdtemp(tmp_mp);
	}

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);

	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	if (be_nvl_add_string(be_attrs, BE_ATTR_MOUNTPOINT, mountpoint) != 0)
		goto out;

	if (shared_fs && be_nvl_add_uint16(be_attrs, BE_ATTR_MOUNT_FLAGS,
	    mount_flags) != 0)
		goto out;

	err = be_mount(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Mounted successfully on: '%s'\n"), mountpoint);
		break;
	case BE_ERR_BE_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid BE.\nPlease check that the name of "
		    "the BE provided is correct.\n"), obe_name);
		break;
	case BE_ERR_MOUNTED:
		(void) fprintf(stderr, _("%s is already mounted.\n"
		    "Please unmount the BE before mounting it again.\n"),
		    obe_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Unable to mount %s.\n"), obe_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	case BE_ERR_NO_MOUNTED_ZONE:
		(void) fprintf(stderr, _("Mounted on '%s'.\nUnable to mount "
		    "one of %s's zone BE's.\n"), mountpoint, obe_name);
		break;
	default:
		(void) fprintf(stderr, _("Unable to mount %s.\n"), obe_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	if (tmp_mp != NULL)
		free(tmp_mp);
	nvlist_free(be_attrs);
	return (err);
}

static int
be_do_unmount(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	int		err = 1;
	int		c;
	int		unmount_flags = 0;

	while ((c = getopt(argc, argv, "fv")) != -1) {
		switch (c) {
		case 'f':
			unmount_flags |= BE_UNMOUNT_FLAG_FORCE;
			break;
		case 'v':
			libbe_print_errors(B_TRUE);
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

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);


	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	if (be_nvl_add_uint16(be_attrs, BE_ATTR_UNMOUNT_FLAGS,
	    unmount_flags) != 0)
		goto out;

	err = be_unmount(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Unmounted successfully\n"));
		break;
	case BE_ERR_BE_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid BE.\nPlease check that the name of "
		    "the BE provided is correct.\n"), obe_name);
		break;
	case BE_ERR_UMOUNT_CURR_BE:
		(void) fprintf(stderr, _("%s is the currently active BE.\n"
		    "It cannot be unmounted unless another BE is the "
		    "currently active BE.\n"), obe_name);
		break;
	case BE_ERR_UMOUNT_SHARED:
		(void) fprintf(stderr, _("%s is a shared file system and it "
		    "cannot be unmounted.\n"), obe_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Unable to unmount %s.\n"), obe_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	default:
		(void) fprintf(stderr, _("Unable to unmount %s.\n"), obe_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
	return (err);
}

static int
be_do_rename(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	char		*nbe_name;
	int err = 1;
	int c;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			libbe_print_errors(B_TRUE);
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		usage();
		return (1);
	}

	obe_name = argv[0];
	nbe_name = argv[1];

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);

	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	if (be_nvl_add_string(be_attrs, BE_ATTR_NEW_BE_NAME, nbe_name) != 0)
		goto out;

	err = be_rename(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Renamed successfully\n"));
		break;
	case BE_ERR_BE_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid BE.\nPlease check that the name of "
		    "the BE provided is correct.\n"), obe_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Rename of BE %s failed.\n"),
		    obe_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	default:
		(void) fprintf(stderr, _("Rename of BE %s failed.\n"),
		    obe_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
	return (err);
}

static int
be_do_rollback(int argc, char **argv)
{
	nvlist_t	*be_attrs;
	char		*obe_name;
	char		*snap_name;
	int		err = 1;
	int		c;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			libbe_print_errors(B_TRUE);
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
	if (argc == 2)
		snap_name = argv[1];
	else { /* argc == 1 */
		if ((snap_name = strrchr(obe_name, '@')) != NULL) {
			if (snap_name[1] == '\0') {
				usage();
				return (1);
			}

			snap_name[0] = '\0';
			snap_name++;
		} else {
			usage();
			return (1);
		}
	}

	if (be_nvl_alloc(&be_attrs) != 0)
		return (1);

	if (be_nvl_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, obe_name) != 0)
		goto out;

	if (be_nvl_add_string(be_attrs, BE_ATTR_SNAP_NAME, snap_name) != 0)
		goto out;

	err = be_rollback(be_attrs);

	switch (err) {
	case BE_SUCCESS:
		(void) printf(_("Rolled back successfully\n"));
		break;
	case BE_ERR_BE_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid BE.\nPlease check that the name of "
		    "the BE provided is correct.\n"), obe_name);
		break;
	case BE_ERR_SS_NOENT:
		(void) fprintf(stderr, _("%s does not exist or appear "
		    "to be a valid snapshot.\nPlease check that the name of "
		    "the snapshot provided is correct.\n"), snap_name);
		break;
	case BE_ERR_PERM:
	case BE_ERR_ACCESS:
		(void) fprintf(stderr, _("Rollback of BE %s snapshot %s "
		    "failed.\n"), obe_name, snap_name);
		(void) fprintf(stderr, _("You have insufficient privileges to "
		    "execute this command.\n"));
		break;
	default:
		(void) fprintf(stderr, _("Rollback of BE %s snapshot %s "
		    "failed.\n"), obe_name, snap_name);
		(void) fprintf(stderr, "%s\n", be_err_to_str(err));
	}

out:
	nvlist_free(be_attrs);
	return (err);
}
