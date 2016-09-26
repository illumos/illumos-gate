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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * Loader menu management.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <libbe.h>
#include <ficl.h>
#include <ficlplatform/emu.h>

#include "bootadm.h"

extern int bam_rootlen;
extern int bam_alt_root;
extern char *rootbuf;
extern char *bam_root;

#define	BOOT_DIR	"/boot"
#define	CONF_DIR	BOOT_DIR "/conf.d"
#define	MENU		BOOT_DIR "/menu.lst"
#define	TRANSIENT	BOOT_DIR "/transient.conf"
#define	XEN_CONFIG	CONF_DIR "/xen"

struct menu_entry {
	int entry;
	char *title;
	char *bootfs;
	STAILQ_ENTRY(menu_entry) next;
};
STAILQ_HEAD(menu_lst, menu_entry);

static error_t set_option(struct menu_lst *, char *, char *);
static error_t list_entry(struct menu_lst *, char *, char *);
static error_t update_entry(struct menu_lst *, char *, char *);
static error_t update_temp(struct menu_lst *, char *, char *);
static error_t list_setting(struct menu_lst *menu, char *, char *);
static error_t disable_hyper(struct menu_lst *, char *, char *);
static error_t enable_hyper(struct menu_lst *, char *, char *);

/* Menu related sub commands */
static subcmd_defn_t menu_subcmds[] = {
	"set_option",		OPT_ABSENT,	set_option, 0,	/* PUB */
	"list_entry",		OPT_OPTIONAL,	list_entry, 1,	/* PUB */
	"update_entry",		OPT_REQ,	update_entry, 0, /* menu */
	"update_temp",		OPT_OPTIONAL,	update_temp, 0,	/* reboot */
	"list_setting",		OPT_OPTIONAL,	list_setting, 1, /* menu */
	"disable_hypervisor",	OPT_ABSENT,	disable_hyper, 0, /* menu */
	"enable_hypervisor",	OPT_ABSENT,	enable_hyper, 0, /* menu */
	NULL,			0,		NULL, 0 /* must be last */
};

#define	NUM_COLS	(4)
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
init_hdr_cols(struct hdr_info *hdr)
{
	struct col_info *col = hdr->cols;
	size_t i;

	col[0].col_name = _("Index");
	col[1].col_name = _("Default");
	col[2].col_name = _("Dataset");
	col[3].col_name = _("Menu");
	col[4].col_name = NULL;

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
count_widths(struct hdr_info *hdr, struct menu_lst *menu)
{
	size_t len[NUM_COLS];
	struct menu_entry *entry;
	int i;

	for (i = 0; i < NUM_COLS; i++)
		len[i] = hdr->cols[i].width + 1;

	STAILQ_FOREACH(entry, menu, next) {
		size_t bootfs_len = strlen(entry->bootfs);
		if (bootfs_len > len[2])
			len[2] = bootfs_len + 1;
	}

	for (i = 0; i < NUM_COLS; i++)
		hdr->cols[i].width = len[i];
}

static void
print_menu_nodes(boolean_t parsable, struct hdr_info *hdr,
    struct menu_lst *menu)
{
	struct menu_entry  *entry;
	int i = -1;
	int rv;
	be_node_list_t *be_nodes, *be_node;

	rv = be_list(NULL, &be_nodes);
	if (rv != BE_SUCCESS)
		return;

	STAILQ_FOREACH(entry, menu, next) {
		i++;
		for (be_node = be_nodes; be_node;
		    be_node = be_node->be_next_node)
			if (strcmp(be_node->be_root_ds, entry->bootfs) == 0)
				break;

		if (parsable)
			(void) printf("%d;%s;%s;%s\n", i,
			    be_node->be_active_on_boot == B_TRUE? "*" : "-",
			    entry->bootfs, entry->title);
		else
			(void) printf("%-*d %-*s %-*s %-*s\n",
			    hdr->cols[0].width, i,
			    hdr->cols[1].width,
			    be_node->be_active_on_boot == B_TRUE? "*" : "-",
			    hdr->cols[2].width, entry->bootfs,
			    hdr->cols[3].width, entry->title);
	}
	be_free_list(be_nodes);
}

static void
print_nodes(boolean_t parsable, struct menu_lst *menu)
{
	struct hdr_info hdr;

	if (!parsable) {
		init_hdr_cols(&hdr);
		count_widths(&hdr, menu);
		print_hdr(&hdr);
	}

	print_menu_nodes(parsable, &hdr, menu);
}

error_t
menu_read(struct menu_lst *menu, char *menu_path)
{
	FILE *fp;
	struct menu_entry *mp;
	char buf[PATH_MAX];
	char *title;
	char *bootfs;
	char *ptr;
	int i = 0;
	int ret = BAM_SUCCESS;

	fp = fopen(menu_path, "r");
	if (fp == NULL)
		return (BAM_ERROR);

	/*
	 * menu.lst entry is on two lines, one for title, one for bootfs
	 * so we process both lines in succession.
	 */
	do {
		if (fgets(buf, PATH_MAX, fp) == NULL) {
			if (!feof(fp))
				ret = BAM_ERROR;
			(void) fclose(fp);
			return (ret);
		}
		ptr = strchr(buf, '\n');
		if (ptr != NULL)
			*ptr = '\0';

		ptr = strchr(buf, ' ');
		if (ptr == NULL) {
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		*ptr++ = '\0';
		if (strcmp(buf, "title") != 0) {
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		if ((title = strdup(ptr)) == NULL) {
			(void) fclose(fp);
			return (BAM_ERROR);
		}

		if (fgets(buf, PATH_MAX, fp) == NULL) {
			free(title);
			(void) fclose(fp);
			return (BAM_ERROR);
		}

		ptr = strchr(buf, '\n');
		if (ptr != NULL)
			*ptr = '\0';

		ptr = strchr(buf, ' ');
		if (ptr == NULL) {
			free(title);
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		*ptr++ = '\0';
		if (strcmp(buf, "bootfs") != 0) {
			free(title);
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		if ((bootfs = strdup(ptr)) == NULL) {
			free(title);
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		if ((mp = malloc(sizeof (struct menu_entry))) == NULL) {
			free(title);
			free(bootfs);
			(void) fclose(fp);
			return (BAM_ERROR);
		}
		mp->entry = i++;
		mp->title = title;
		mp->bootfs = bootfs;
		STAILQ_INSERT_TAIL(menu, mp, next);
	} while (feof(fp) == 0);

	(void) fclose(fp);
	return (ret);
}

void
menu_free(struct menu_lst *menu)
{
	struct menu_entry *entry;
	STAILQ_FOREACH(entry, menu, next) {
		STAILQ_REMOVE_HEAD(menu, next);
		free(entry->title);
		free(entry->bootfs);
		free(entry);
	}
}

error_t
bam_loader_menu(char *subcmd, char *opt, int largc, char *largv[])
{
	error_t		ret;
	char		menu_path[PATH_MAX];
	char		clean_menu_root[PATH_MAX];
	char		menu_root[PATH_MAX];
	struct stat	sb;
	error_t		(*f)(struct menu_lst *, char *, char *);
	char		*special;
	char		*pool = NULL;
	zfs_mnted_t	zmnted;
	char		*zmntpt;
	char		*osdev;
	char		*osroot;
	const char	*fcn = "bam_loader_menu()";
	struct menu_lst	menu = {0};

	STAILQ_INIT(&menu);

	/*
	 * Check arguments
	 */
	ret = check_subcmd_and_options(subcmd, opt, menu_subcmds, &f);
	if (ret == BAM_ERROR) {
		return (BAM_ERROR);
	}

	assert(bam_root);

	(void) strlcpy(menu_root, bam_root, sizeof (menu_root));
	osdev = osroot = NULL;

	if (strcmp(subcmd, "update_entry") == 0) {
		assert(opt);

		osdev = strtok(opt, ",");
		assert(osdev);
		osroot = strtok(NULL, ",");
		if (osroot) {
			/* fixup bam_root so that it points at osroot */
			if (realpath(osroot, rootbuf) == NULL) {
				bam_error(_("cannot resolve path %s: %s\n"),
				    osroot, strerror(errno));
				return (BAM_ERROR);
			}
			bam_alt_root = 1;
			bam_root  = rootbuf;
			bam_rootlen = strlen(rootbuf);
		}
	}

	if (stat(menu_root, &sb) == -1) {
		bam_error(_("cannot find menu\n"));
		return (BAM_ERROR);
	}

	if (!is_zfs(menu_root)) {
		bam_error(_("only ZFS root is supported\n"));
		return (BAM_ERROR);
	}

	assert(strcmp(menu_root, bam_root) == 0);
	special = get_special(menu_root);
	INJECT_ERROR1("Z_MENU_GET_SPECIAL", special = NULL);
	if (special == NULL) {
		bam_error(_("cant find special file for mount-point %s\n"),
		    menu_root);
		return (BAM_ERROR);
	}
	pool = strtok(special, "/");
	INJECT_ERROR1("Z_MENU_GET_POOL", pool = NULL);
	if (pool == NULL) {
		free(special);
		bam_error(_("cant find pool for mount-point %s\n"), menu_root);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: derived pool=%s from special\n", fcn, pool));

	zmntpt = mount_top_dataset(pool, &zmnted);
	INJECT_ERROR1("Z_MENU_MOUNT_TOP_DATASET", zmntpt = NULL);
	if (zmntpt == NULL) {
		bam_error(_("cannot mount pool dataset for pool: %s\n"), pool);
		free(special);
		return (BAM_ERROR);
	}
	BAM_DPRINTF(("%s: top dataset mountpoint=%s\n", fcn, zmntpt));

	(void) strlcpy(menu_root, zmntpt, sizeof (menu_root));
	BAM_DPRINTF(("%s: zfs menu_root=%s\n", fcn, menu_root));

	elide_trailing_slash(menu_root, clean_menu_root,
	    sizeof (clean_menu_root));

	BAM_DPRINTF(("%s: cleaned menu root is <%s>\n", fcn, clean_menu_root));

	(void) strlcpy(menu_path, clean_menu_root, sizeof (menu_path));
	(void) strlcat(menu_path, MENU, sizeof (menu_path));

	BAM_DPRINTF(("%s: menu path is: %s\n", fcn, menu_path));

	/*
	 * update_entry is special case, its used by installer
	 * and needs to create menu.lst file for loader
	 */
	if (menu_read(&menu, menu_path) == BAM_ERROR &&
	    strcmp(subcmd, "update_entry") != 0) {
		bam_error(_("cannot find menu file: %s\n"), menu_path);
		if (special != NULL)
			free(special);
		return (BAM_ERROR);
	}

	/*
	 * If listing the menu, display the menu location
	 */
	if (strcmp(subcmd, "list_entry") == 0)
		bam_print(_("the location for the active menu is: %s\n"),
		    menu_path);

	/*
	 * We already checked the following case in
	 * check_subcmd_and_suboptions() above. Complete the
	 * final step now.
	 */
	if (strcmp(subcmd, "set_option") == 0) {
		assert(largc == 1 && largv[0] && largv[1] == NULL);
		opt = largv[0];
	} else if ((strcmp(subcmd, "enable_hypervisor") != 0) &&
	    (strcmp(subcmd, "list_setting") != 0)) {
		assert(largc == 0 && largv == NULL);
	}

	/*
	 * Once the sub-cmd handler has run
	 * only the line field is guaranteed to have valid values
	 */
	if (strcmp(subcmd, "update_entry") == 0) {
		ret = f(&menu, menu_root, osdev);
	} else if (strcmp(subcmd, "upgrade") == 0) {
		ret = f(&menu, bam_root, menu_root);
	} else if (strcmp(subcmd, "list_entry") == 0) {
		ret = f(&menu, menu_path, opt);
	} else if (strcmp(subcmd, "list_setting") == 0) {
		ret = f(&menu, ((largc > 0) ? largv[0] : ""),
		    ((largc > 1) ? largv[1] : ""));
	} else if (strcmp(subcmd, "disable_hypervisor") == 0) {
		if (is_sparc()) {
			bam_error(_("%s operation unsupported on SPARC "
			    "machines\n"), subcmd);
			ret = BAM_ERROR;
		} else {
			ret = f(&menu, bam_root, NULL);
		}
	} else if (strcmp(subcmd, "enable_hypervisor") == 0) {
		if (is_sparc()) {
			bam_error(_("%s operation unsupported on SPARC "
			    "machines\n"), subcmd);
			ret = BAM_ERROR;
		} else {
			char *extra_args = NULL;

			/*
			 * Compress all arguments passed in the largv[] array
			 * into one string that can then be appended to the
			 * end of the kernel$ string the routine to enable the
			 * hypervisor will build.
			 *
			 * This allows the caller to supply arbitrary unparsed
			 * arguments, such as dom0 memory settings or APIC
			 * options.
			 *
			 * This concatenation will be done without ANY syntax
			 * checking whatsoever, so it's the responsibility of
			 * the caller to make sure the arguments are valid and
			 * do not duplicate arguments the conversion routines
			 * may create.
			 */
			if (largc > 0) {
				int extra_len, i;

				for (extra_len = 0, i = 0; i < largc; i++)
					extra_len += strlen(largv[i]);

				/*
				 * Allocate space for argument strings,
				 * intervening spaces and terminating NULL.
				 */
				extra_args = alloca(extra_len + largc);

				(void) strcpy(extra_args, largv[0]);

				for (i = 1; i < largc; i++) {
					(void) strcat(extra_args, " ");
					(void) strcat(extra_args, largv[i]);
				}
			}

			ret = f(&menu, bam_root, extra_args);
		}
	} else
		ret = f(&menu, NULL, opt);

	if (ret == BAM_WRITE) {
		BAM_DPRINTF(("%s: writing menu to clean-menu-root: <%s>\n",
		    fcn, clean_menu_root));
		/* ret = menu_write(clean_menu_root, menu); */
	}

	INJECT_ERROR1("POOL_SET", pool = "/pooldata");
	assert((is_zfs(menu_root)) ^ (pool == NULL));
	if (pool) {
		(void) umount_top_dataset(pool, zmnted, zmntpt);
		free(special);
	}

	menu_free(&menu);
	return (ret);
}

/*
 * To suppress output from ficl. We do not want to see messages
 * from interpreting loader config.
 */

/*ARGSUSED*/
static void
ficlTextOutSilent(ficlCallback *cb, char *text)
{
}

/*ARGSUSED*/
static error_t
set_option(struct menu_lst *menu, char *dummy, char *opt)
{
	char path[PATH_MAX];
	char *val;
	char *rest;
	int optval;
	struct menu_entry *entry;
	nvlist_t *be_attrs;
	FILE *fp;
	int rv, ret = BAM_SUCCESS;

	assert(menu);
	assert(opt);
	assert(dummy == NULL);

	val = strchr(opt, '=');
	if (val != NULL) {
		*val++ = '\0';
	}

	if (strcmp(opt, "default") == 0) {
		errno = 0;
		optval = strtol(val, &rest, 10);
		if (errno != 0 || *rest != '\0') {
			bam_error(_("invalid boot entry number: %s\n"), val);
			return (BAM_ERROR);
		}
		STAILQ_FOREACH(entry, menu, next) {
			if (entry->entry == optval)
				break;
		}
		if (entry == NULL) {
			bam_error(_("invalid boot entry number: %s\n"), val);
			return (BAM_ERROR);
		}
		if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
			bam_error(_("out of memory\n"));
			return (BAM_ERROR);
		}
		if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME,
		    entry->title) != 0) {
			bam_error(_("out of memory\n"));
			nvlist_free(be_attrs);
			return (BAM_ERROR);
		}
		ret = be_activate(be_attrs);
		nvlist_free(be_attrs);
		if (ret != 0)
			ret = BAM_ERROR;
		return (ret);
	} else if (strcmp(opt, "timeout") == 0) {
		errno = 0;
		optval = strtol(val, &rest, 10);
		if (errno != 0 || *rest != '\0') {
			bam_error(_("invalid timeout: %s\n"), val);
			return (BAM_ERROR);
		}

		(void) snprintf(path, PATH_MAX, "%s" CONF_DIR "/timeout",
		    bam_root);

		fp = fopen(path, "w");
		if (fp == NULL) {
			bam_error(_("failed to open file: %s: %s\n"),
			    path, strerror(errno));
			return (BAM_ERROR);
		}
		/*
		 * timeout=-1 is to disable auto boot in illumos, but
		 * loader needs "NO" to disable auto boot.
		 */
		if (optval == -1)
			rv = fprintf(fp, "autoboot_delay=\"NO\"\n");
		else
			rv = fprintf(fp, "autoboot_delay=\"%d\"\n", optval);

		if (rv < 0) {
			bam_error(_("write to file failed: %s: %s\n"),
			    path, strerror(errno));
			(void) fclose(fp);
			ret = BAM_ERROR;
		} else
			rv = fclose(fp);

		if (rv < 0) {
			bam_error(_("failed to close file: %s: %s\n"),
			    path, strerror(errno));
			ret = BAM_ERROR;
		}
		if (ret == BAM_ERROR)
			(void) unlink(path);

		return (BAM_SUCCESS);
	}

	bam_error(_("invalid option: %s\n"), opt);
	return (BAM_ERROR);
}

static int
bam_mount_be(struct menu_entry *entry, char **dir)
{
	nvlist_t *be_attrs = NULL;
	const char *tmpdir = getenv("TMPDIR");
	const char *tmpname = "bam.XXXXXX";
	be_node_list_t *be_node, *be_nodes = NULL;
	int ret;

	*dir = NULL;
	if (tmpdir == NULL)
		tmpdir = "/tmp";

	ret = asprintf(dir, "%s/%s", tmpdir, tmpname);
	if (ret < 0) {
		return (BE_ERR_NOMEM);
	}
	*dir = mkdtemp(*dir);

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0) {
		ret = BE_ERR_NOMEM;
		goto out;
	}

	ret = be_list(NULL, &be_nodes);
	if (ret != BE_SUCCESS) {
		goto out;
	}

	for (be_node = be_nodes; be_node;
	    be_node = be_node->be_next_node)
		if (strcmp(be_node->be_root_ds, entry->bootfs) == 0)
			break;

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME,
	    be_node->be_node_name) != 0) {
		ret = BE_ERR_NOMEM;
		goto out;
	}

	if (nvlist_add_string(be_attrs, BE_ATTR_MOUNTPOINT, *dir) != 0) {
		ret = BE_ERR_NOMEM;
		goto out;
	}

	ret = be_mount(be_attrs);
	if (ret == BE_ERR_MOUNTED) {
		/*
		 * if BE is mounted, dir does not point to correct directory
		 */
		(void) rmdir(*dir);
		free(*dir);
		*dir = NULL;
	}
out:
	if (be_nodes != NULL)
		be_free_list(be_nodes);
	nvlist_free(be_attrs);
	return (ret);
}

static int
bam_umount_be(char *dir)
{
	nvlist_t *be_attrs;
	int ret;

	if (dir == NULL)		/* nothing to do */
		return (BE_SUCCESS);

	if (nvlist_alloc(&be_attrs, NV_UNIQUE_NAME, 0) != 0)
		return (BE_ERR_NOMEM);

	if (nvlist_add_string(be_attrs, BE_ATTR_ORIG_BE_NAME, dir) != 0) {
		ret = BE_ERR_NOMEM;
		goto out;
	}

	ret = be_unmount(be_attrs);
out:
	nvlist_free(be_attrs);
	return (ret);
}

/*
 * display details of menu entry or single property
 */
static error_t
list_menu_entry(struct menu_entry *entry, char *setting)
{
	int ret = BAM_SUCCESS;
	char *ptr, *dir;
	char buf[MAX_INPUT];
	ficlVm *vm;
	int mounted;

	mounted = bam_mount_be(entry, &dir);
	if (mounted != BE_SUCCESS && mounted != BE_ERR_MOUNTED) {
		if (dir != NULL) {
			(void) rmdir(dir);
			free(dir);
		}
		bam_error(_("%s is not mounted\n"), entry->title);
		return (BAM_ERROR);
	}

	vm = bf_init("", ficlTextOutSilent);
	if (vm == NULL) {
		bam_error(_("error setting up forth interpreter\n"));
		ret = BAM_ERROR;
		goto done;
	}

	/* should only get FICL_VM_STATUS_OUT_OF_TEXT */
	(void) snprintf(buf, MAX_INPUT, "set currdev=zfs:%s:",
	    entry->bootfs);
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("error interpreting boot config\n"));
		ret = BAM_ERROR;
		goto done;
	}
	(void) snprintf(buf, MAX_INPUT, "include /boot/forth/loader.4th");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("error interpreting boot config\n"));
		ret = BAM_ERROR;
		goto done;
	}
	(void) snprintf(buf, MAX_INPUT, "start");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("error interpreting boot config\n"));
		ret = BAM_ERROR;
		goto done;
	}
	(void) snprintf(buf, MAX_INPUT, "boot");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("error interpreting boot config\n"));
		ret = BAM_ERROR;
		goto done;
	}

	ret = BAM_SUCCESS;
	if (*setting == '\0')
		(void) printf("\nTitle:       %s\n", entry->title);
	else if (strcasecmp(setting, "title") == 0) {
		(void) printf("%s\n", entry->title);
		goto done;
	}

	ptr = getenv("autoboot_delay");
	if (ptr != NULL) {
		char *timeout = "-1";

		if (strcasecmp(ptr, "NO") != 0)
			timeout = ptr;

		if (*setting == '\0')
			(void) printf("Timeout:     %s\n", timeout);
		else if (strcasecmp(setting, "timeout") == 0) {
			(void) printf("%s\n", timeout);
			goto done;
		}

	}
	ptr = getenv("console");
	if (ptr != NULL) {
		if (*setting == '\0')
			(void) printf("Console:     %s\n", ptr);
		else if (strcasecmp(setting, "console") == 0) {
			(void) printf("%s\n", ptr);
			goto done;
		}
	}

	if (*setting == '\0')
		(void) printf("Bootfs:      %s\n", entry->bootfs);
	else if (strcasecmp(setting, "bootfs") == 0) {
		(void) printf("%s\n", entry->bootfs);
		goto done;
	}

	ptr = getenv("xen_kernel");
	if (ptr != NULL) {
			if (*setting == '\0') {
				(void) printf("Xen kernel:  %s\n", ptr);
			} else if (strcasecmp(setting, "xen_kernel") == 0) {
				(void) printf("%s\n", ptr);
				goto done;
			}

			if (*setting == '\0') {
				(void) printf("Xen args:    \"%s\"\n",
				    getenv("xen_cmdline"));
			} else if (strcasecmp(setting, "xen_cmdline") == 0) {
				(void) printf("%s\n", getenv("xen_cmdline"));
				goto done;
			}

			if (*setting == '\0') {
				(void) printf("Kernel:      %s\n",
				    getenv("bootfile"));
			} if (strcasecmp(setting, "kernel") == 0) {
				(void) printf("%s\n", getenv("bootfile"));
				goto done;
			}
	} else {
		ptr = getenv("kernelname");
		if (ptr != NULL) {
			if (*setting == '\0') {
				(void) printf("Kernel:      %s\n", ptr);
			} else if (strcasecmp(setting, "kernel") == 0) {
				(void) printf("%s\n", ptr);
				goto done;
			}
		}
	}

	ptr = getenv("boot-args");
	if (ptr != NULL) {
		if (*setting == '\0') {
			(void) printf("Boot-args:   \"%s\"\n", ptr);
		} else if (strcasecmp(setting, "boot-args") == 0) {
			(void) printf("%s\n", ptr);
			goto done;
		}
	}

	if (*setting == '\0' || strcasecmp(setting, "modules") == 0) {
		(void) printf("\nModules:\n");
		ficlVmSetTextOut(vm, ficlCallbackDefaultTextOut);
		(void) snprintf(buf, MAX_INPUT, "show-module-options");
		ret = ficlVmEvaluate(vm, buf);
		if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
			bam_error(_("error interpreting boot config\n"));
			ret = BAM_ERROR;
			goto done;
		}
		ret = BAM_SUCCESS;
		goto done;
	}

	/* if we got here with setting string, its unknown property */
	if (*setting != '\0') {
		bam_error(_("unknown property: %s\n"), setting);
		ret = BAM_ERROR;
	} else
		ret = BAM_SUCCESS;
done:
	bf_fini();
	if (mounted != BE_ERR_MOUNTED) {
		(void) bam_umount_be(dir);
	}

	if (dir != NULL) {
		(void) rmdir(dir);
		free(dir);
	}

	return (ret);
}

/*ARGSUSED*/
static error_t
list_entry(struct menu_lst *menu, char *menu_root, char *opt)
{
	error_t ret = BAM_SUCCESS;
	struct menu_entry *entry;
	char *ptr, *title = NULL;
	int i, e = -1;

	if (opt == NULL) {
		print_nodes(B_FALSE, menu);
		return (ret);
	}

	if ((ptr = strchr(opt, '=')) == NULL) {
		bam_error(_("invalid option: %s\n"), opt);
		return (BAM_ERROR);
	}

	i = ptr - opt;
	if (strncmp(opt, "entry", i) == 0) {
		e = atoi(ptr+1);
	} else if (strncmp(opt, "title", i) == 0) {
		title = ptr+1;
	} else {
		bam_error(_("invalid option: %s\n"), opt);
		return (BAM_ERROR);
	}

	STAILQ_FOREACH(entry, menu, next) {
		if (title != NULL) {
			if (strcmp(title, entry->title) == 0)
				break;
		} else if (entry->entry == e)
			break;
	}

	if (entry == NULL) {
		bam_error(_("no matching entry found\n"));
		return (BAM_ERROR);
	}

	return (list_menu_entry(entry, ""));
}

/*
 * For now this is just stub entry to support grub interface, the
 * known consumer is installer ict.py code, calling as:
 * bootadm update-menu -R /a -Z -o rdisk
 * Later this can be converted to do something useful.
 */
/*ARGSUSED*/
static error_t
update_entry(struct menu_lst *menu, char *menu_root, char *osdev)
{
	char path[PATH_MAX];
	char *pool = menu_root + 1;
	be_node_list_t *be_nodes, *be_node;
	int rv;
	FILE *fp;

	(void) snprintf(path, PATH_MAX, "%s%s", menu_root, MENU);
	rv = be_list(NULL, &be_nodes);

	if (rv != BE_SUCCESS)
		return (BAM_ERROR);

	fp = fopen(path, "w");
	if (fp == NULL) {
		be_free_list(be_nodes);
		return (BAM_ERROR);
	}

	for (be_node = be_nodes; be_node; be_node = be_node->be_next_node) {
		if (strcmp(be_node->be_rpool, pool) == 0) {
			(void) fprintf(fp, "title %s\n", be_node->be_node_name);
			(void) fprintf(fp, "bootfs %s\n", be_node->be_root_ds);
		}
	}

	be_free_list(be_nodes);
	(void) fclose(fp);
	return (BAM_SUCCESS);
}

/*ARGSUSED*/
static error_t
update_temp(struct menu_lst *menu, char *dummy, char *opt)
{
	error_t ret = BAM_ERROR;
	char path[PATH_MAX];
	char buf[MAX_INPUT];
	struct mnttab mpref = { 0 };
	struct mnttab mp = { 0 };
	ficlVm *vm;
	char *env, *o;
	FILE *fp;

	(void) snprintf(path, PATH_MAX, "%s" TRANSIENT, bam_root);
	/*
	 * if opt == NULL, remove transient config
	 */
	if (opt == NULL) {
		(void) unlink(path);
		return (BAM_SUCCESS);
	}

	fp = fopen(MNTTAB, "r");
	if (fp == NULL)
		return (BAM_ERROR);

	mpref.mnt_mountp = "/";
	if (getmntany(fp, &mp, &mpref) != 0) {
		(void) fclose(fp);
		return (BAM_ERROR);
	}
	(void) fclose(fp);

	vm = bf_init("", ficlTextOutSilent);
	if (vm == NULL) {
		bam_error(_("Error setting up forth interpreter\n"));
		return (ret);
	}

	/*
	 * need to check current boot config, so fire up the ficl
	 * if its xen setup, we add option to boot-args list, not replacing it.
	 */
	(void) snprintf(buf, MAX_INPUT, "set currdev=zfs:%s:", mp.mnt_special);
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "include /boot/forth/loader.4th");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "start");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "boot");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	bf_fini();

	if (opt[0] == '-') {
		env = getenv("xen_kernel");
		fp = fopen(path, "w");
		if (fp == NULL)
			return (BAM_ERROR);

		if (env != NULL) {
			env = getenv("boot-args");
			(void) fprintf(fp, "boot-args=\"%s %s\"\n", env, opt);
		} else
			(void) fprintf(fp, "boot-args=\"%s\"\n", opt);
		(void) fclose(fp);
		return (BAM_SUCCESS);
	}

	/*
	 * it should be the case with "kernel args"
	 * so, we split the opt at first space
	 * and store bootfile= and boot-args=
	 */
	env = getenv("xen_kernel");

	o = strchr(opt, ' ');
	if (o == NULL) {
		fp = fopen(path, "w");
		if (fp == NULL)
			return (BAM_ERROR);
		(void) fprintf(fp, "bootfile=\"%s\"\n", opt);
		(void) fclose(fp);
		return (BAM_SUCCESS);
	}
	*o++ = '\0';
	fp = fopen(path, "w");
	if (fp == NULL)
		return (BAM_ERROR);
	(void) fprintf(fp, "bootfile=\"%s\"\n", opt);

	if (env != NULL) {
		env = getenv("boot-args");
		(void) fprintf(fp, "boot-args=\"%s %s\"\n", env, opt);
	} else
		(void) fprintf(fp, "boot-args=\"%s\"\n", o);

	(void) fflush(fp);
	(void) fclose(fp);
	return (ret);
}

static error_t
list_setting(struct menu_lst *menu, char *which, char *setting)
{
	int entry = -1;
	struct menu_entry *m;
	be_node_list_t *be_nodes, *be_node = NULL;
	int ret;

	assert(which);
	assert(setting);

	/*
	 * which can be:
	 * "" - list default entry
	 * number - use for entry number
	 * property name
	 */
	if (*which != '\0') {
		if (isdigit(*which)) {
			char *rest;
			errno = 0;
			entry = strtol(which, &rest, 10);
			if (errno != 0 || *rest != '\0') {
				bam_error(_("invalid boot entry number: %s\n"),
				    which);
				return (BAM_ERROR);
			}
		} else
			setting = which;
	}

	/* find default entry */
	if (entry == -1) {
		ret = be_list(NULL, &be_nodes);
		if (ret != BE_SUCCESS) {
			bam_error(_("No BE's found\n"));
			return (BAM_ERROR);
		}
		STAILQ_FOREACH(m, menu, next) {
			entry++;
			for (be_node = be_nodes; be_node;
			    be_node = be_node->be_next_node)
				if (strcmp(be_node->be_root_ds, m->bootfs) == 0)
					break;
			if (be_node->be_active_on_boot == B_TRUE)
				break; /* found active node */
		}
		be_free_list(be_nodes);
		if (be_node == NULL) {
			bam_error(_("None of BE nodes is marked active\n"));
			return (BAM_ERROR);
		}
	} else {
		STAILQ_FOREACH(m, menu, next)
			if (m->entry == entry)
				break;

		if (m == NULL) {
			bam_error(_("no matching entry found\n"));
			return (BAM_ERROR);
		}
	}

	return (list_menu_entry(m, setting));
}

/*ARGSUSED*/
static error_t
disable_hyper(struct menu_lst *menu, char *osroot, char *opt)
{
	char path[PATH_MAX];

	(void) snprintf(path, PATH_MAX, "%s" XEN_CONFIG, bam_root);
	(void) unlink(path);
	return (BAM_SUCCESS);
}

/*ARGSUSED*/
static error_t
enable_hyper(struct menu_lst *menu, char *osroot, char *opt)
{
	ficlVm *vm;
	char path[PATH_MAX];
	char buf[MAX_INPUT];
	char *env;
	FILE *fp;
	struct mnttab mpref = { 0 };
	struct mnttab mp = { 0 };
	int ret;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL)
		return (BAM_ERROR);

	mpref.mnt_mountp = "/";
	if (getmntany(fp, &mp, &mpref) != 0) {
		(void) fclose(fp);
		return (BAM_ERROR);
	}
	(void) fclose(fp);

	vm = bf_init("", ficlTextOutSilent);
	if (vm == NULL) {
		bam_error(_("Error setting up forth interpreter\n"));
		return (BAM_ERROR);
	}

	/*
	 * need to check current boot config, so fire up the ficl
	 * if its xen setup, we add option to boot-args list, not replacing it.
	 */
	(void) snprintf(buf, MAX_INPUT, "set currdev=zfs:%s:", mp.mnt_special);
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "include /boot/forth/loader.4th");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "start");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	(void) snprintf(buf, MAX_INPUT, "boot");
	ret = ficlVmEvaluate(vm, buf);
	if (ret != FICL_VM_STATUS_OUT_OF_TEXT) {
		bam_error(_("Error interpreting boot config\n"));
		bf_fini();
		return (BAM_ERROR);
	}
	bf_fini();

	(void) mkdir(CONF_DIR, 0755);
	(void) snprintf(path, PATH_MAX, "%s" XEN_CONFIG, bam_root);
	fp = fopen(path, "w");
	if (fp == NULL) {
		return (BAM_ERROR);	/* error, cant write config */
	}

	errno = 0;
	/*
	 * on write error, remove file to ensure we have bootable config.
	 * note we dont mind if config exists, it will get updated
	 */
	(void) fprintf(fp, "xen_kernel=\"/boot/${ISADIR}/xen\"\n");
	if (errno != 0)
		goto error;

	/*
	 * really simple and stupid console conversion.
	 * it really has to be gone, it belongs to milestone/xvm properties.
	 */
	env = getenv("console");
	if (env != NULL) {
		if (strcmp(env, "ttya") == 0)
			(void) fprintf(fp, "xen_cmdline=\"console=com1 %s\"\n",
			    opt);
		else if (strcmp(env, "ttyb") == 0)
			(void) fprintf(fp, "xen_cmdline=\"console=com2 %s\"\n",
			    opt);
		else
			(void) fprintf(fp, "xen_cmdline=\"console=vga %s\"\n",
			    opt);
	} else
		(void) fprintf(fp, "xen_cmdline=\"%s\"\n", opt);
	if (errno != 0)
		goto error;

	(void) fprintf(fp,
	    "bootfile=\"/platform/i86xpv/kernel/${ISADIR}/unix\"\n");
	if (errno != 0)
		goto error;

	(void) fprintf(fp,
	    "boot-args=\"/platform/i86xpv/kernel/${ISADIR}/unix\"\n");
	if (errno != 0)
		goto error;

	(void) fclose(fp);
	if (errno != 0) {
		(void) unlink(path);
		return (BAM_ERROR);
	}
	return (BAM_SUCCESS);
error:
	(void) fclose(fp);
	(void) unlink(path);
	return (BAM_ERROR);
}
